"""`scripts/_session_mint.py`：验收工具唯一的本地 mint 入口（3c-1B ticket 01，spec §11.8.4）。

先于实现写下并跑红。它读 `[SessionKeys]`、按 family/role 取 SSM 值、调用**生产** `session.mint_token`
（legacy role 调用旧 mint，用于 L3/退役之前预存负向探针 token）。路径只来自 config；`--save` 只许写进
`.scratch/`。2A 把这个模块换成夹具签发器，六处调用方不动。
"""
import base64
import json
import sys
import textwrap
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "auth"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import _session_mint as sm  # noqa: E402  —— import 期不得碰 AWS
import session as sess  # noqa: E402

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.test
    routing_table = site-routes

    [SessionKeys]
    site_current = site-hs-v1
    site_previous =
    console_current = console-hs-v1
    console_previous =
    legacy_param = /site-builder/jwt-secret
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/site-hs-v1

    [SessionKey:console-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/console-hs-v1
""")
CFG_WITH_PREVIOUS = (CFG.replace("site_previous =", "site_previous = site-hs-v0")
                     .replace("console_previous =", "console_previous = console-hs-v0")
                     + textwrap.dedent("""
    [SessionKey:site-hs-v0]
    alg = HS256
    ssm_param = /site-builder/session-keys/site-hs-v0

    [SessionKey:console-hs-v0]
    alg = HS256
    ssm_param = /site-builder/session-keys/console-hs-v0
"""))
ROUTER = textwrap.dedent("""
    [SiteBuilder]
    trusted_idps = Feishu-Test, Other   # 第一个是 Edge 信任的
    require_idp_claim = true
""")
SECRETS = {"/site-builder/session-keys/site-hs-v1": "site-v1-secret",
           "/site-builder/session-keys/console-hs-v1": "console-v1-secret",
           "/site-builder/session-keys/site-hs-v0": "site-v0-secret",
           "/site-builder/session-keys/console-hs-v0": "console-v0-secret",
           "/site-builder/jwt-secret": "legacy-secret"}


def _files(tmp_path, cfg=CFG):
    c = tmp_path / "config.ini"; c.write_text(cfg)
    r = tmp_path / "router.ini"; r.write_text(ROUTER)
    return c, r


def _ssm_with_secrets():
    ssm = boto3.client("ssm", region_name="us-east-1")
    for k, v in SECRETS.items():
        ssm.put_parameter(Name=k, Value=v, Type="SecureString")
    return ssm


def _header(tok):
    h = tok.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def _payload(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def _minter(tmp_path, cfg=CFG):
    c, r = _files(tmp_path, cfg)
    return sm.Minter.from_config(c, r, ssm=_ssm_with_secrets())


def test_import_has_no_side_effects_and_exposes_the_api():
    assert callable(sm.Minter.from_config) and callable(sm.main) and callable(sm.save_token)


def test_default_role_is_current_and_token_is_kid_form(aws, tmp_path):
    m = _minter(tmp_path)
    tok = m.mint("site-session", "v@example.test", ttl_seconds=600)
    assert _header(tok) == {"alg": "HS256", "typ": "JWT", "kid": "site-hs-v1"}
    claims, outcome = sess.verify_token(
        tok, allowlist={"site-hs-v1": {"alg": "HS256", "secret": "site-v1-secret", "role": "current"}},
        token_use="site-session")
    assert outcome == "accepted_current" and claims["email"] == "v@example.test"
    # Edge 的 REQUIRE_IDP_CLAIM：idp 取 router 配置 trusted_idps 的第一个，auth_via 是托管登录值
    assert claims["idp"] == "Feishu-Test" and claims["auth_via"] == "TokenGeneration_HostedAuth"
    assert claims["name"] == "v"      # 默认 name = 邮箱本地部分（与今天六处调用方一致）


def test_console_family_tokens_use_console_current_kid(aws, tmp_path):
    m = _minter(tmp_path)
    code = m.mint("console-upgrade", "v@example.test", ttl_seconds=600)
    cookie = m.mint("console-session", "v@example.test", ttl_seconds=600)
    assert _header(code)["kid"] == "console-hs-v1" and _header(cookie)["kid"] == "console-hs-v1"
    allow = {"console-hs-v1": {"alg": "HS256", "secret": "console-v1-secret", "role": "current"}}
    c1, o1 = sess.verify_token(code, allowlist=allow, token_use="console-upgrade")
    c2, o2 = sess.verify_token(cookie, allowlist=allow, token_use="console-session")
    assert o1 == o2 == "accepted_current" and c1["jti"]
    assert _payload(code)["exp"] - _payload(code)["iat"] <= 60      # 升级码 TTL 钳到 60


def test_previous_role_uses_the_previous_kid(aws, tmp_path):
    m = _minter(tmp_path, CFG_WITH_PREVIOUS)
    tok = m.mint("site-session", "v@example.test", role="previous", ttl_seconds=600)
    assert _header(tok)["kid"] == "site-hs-v0"
    _, outcome = sess.verify_token(
        tok, allowlist={"site-hs-v1": {"alg": "HS256", "secret": "site-v1-secret", "role": "current"},
                        "site-hs-v0": {"alg": "HS256", "secret": "site-v0-secret", "role": "previous"}},
        token_use="site-session")
    assert outcome == "accepted_previous"


def test_previous_role_fails_loudly_when_previous_is_empty(aws, tmp_path):
    m = _minter(tmp_path)
    with pytest.raises(SystemExit, match="previous"):
        m.mint("site-session", "v@example.test", role="previous", ttl_seconds=600)


def test_legacy_role_mints_the_old_kid_less_form(aws, tmp_path):
    m = _minter(tmp_path)
    site = m.mint("site-session", "v@example.test", role="legacy", ttl_seconds=600)
    console = m.mint("console-session", "v@example.test", role="legacy", ttl_seconds=600)
    code = m.mint("console-upgrade", "v@example.test", role="legacy", ttl_seconds=600)
    for t in (site, console, code):
        assert "kid" not in _header(t)
    assert sess.verify_session_jwt(site, "legacy-secret", expected_typ="session")["email"] == "v@example.test"
    assert "scope" not in _payload(site)
    assert _payload(console)["scope"] == "console"
    assert sess.verify_upgrade_code(code, "legacy-secret")["jti"]


def test_unknown_role_is_rejected(aws, tmp_path):
    with pytest.raises(SystemExit, match="role"):
        _minter(tmp_path).mint("site-session", "v@example.test", role="next", ttl_seconds=600)


def test_each_ssm_parameter_is_read_once(aws, tmp_path):
    c, r = _files(tmp_path)
    real = _ssm_with_secrets()
    calls = []

    class Counting:
        def get_parameter(self, **kw):
            calls.append(kw["Name"])
            return real.get_parameter(**kw)

    m = sm.Minter.from_config(c, r, ssm=Counting())
    for _ in range(3):
        m.mint("site-session", "a@example.test", ttl_seconds=60)
        m.mint("console-session", "a@example.test", ttl_seconds=60)
    assert sorted(calls) == ["/site-builder/session-keys/console-hs-v1", "/site-builder/session-keys/site-hs-v1"]


def test_empty_secret_value_is_fatal_not_an_empty_key(aws, tmp_path):
    c, r = _files(tmp_path)
    ssm = _ssm_with_secrets()

    class Blank:
        def get_parameter(self, **kw):
            return {"Parameter": {"Value": ""}}

    with pytest.raises(SystemExit, match="取不到"):
        sm.Minter.from_config(c, r, ssm=Blank()).mint("site-session", "a@example.test", ttl_seconds=60)


def test_trusted_idp_is_the_first_entry_and_missing_is_fatal(tmp_path):
    c, r = _files(tmp_path)
    assert sm.trusted_idp(r) == "Feishu-Test"
    (tmp_path / "empty.ini").write_text("[SiteBuilder]\ntrusted_idps =\n")
    with pytest.raises(SystemExit, match="trusted_idps"):
        sm.trusted_idp(tmp_path / "empty.ini")


def test_save_token_writes_json_record_only_under_scratch(tmp_path):
    scratch = tmp_path / ".scratch"
    scratch.mkdir()
    rec = {"token_use": "site-session", "role": "previous", "kid": "site-hs-v0",
           "email": "v@example.test", "token": "a.b.c"}
    out = sm.save_token(scratch / "3c-1b" / "v0.json", rec, scratch_root=scratch)
    assert json.loads(out.read_text()) == rec
    with pytest.raises(SystemExit, match="scratch"):
        sm.save_token(tmp_path / "elsewhere.json", rec, scratch_root=scratch)
    with pytest.raises(SystemExit, match="scratch"):
        sm.save_token(scratch / ".." / "escape.json", rec, scratch_root=scratch)


def test_load_saved_token_round_trips_and_rejects_garbage(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"token_use": "console-session", "role": "legacy", "kid": None,
                             "email": "v@example.test", "token": "x.y.z"}))
    assert sm.load_saved_token(p) == ("console-session", "x.y.z")
    (tmp_path / "bad.json").write_text('{"token": "x.y.z"}')
    with pytest.raises(SystemExit, match="token_use"):
        sm.load_saved_token(tmp_path / "bad.json")


def test_cli_mints_and_saves_with_role_and_prints_no_token(aws, tmp_path, capsys, monkeypatch):
    c, r = _files(tmp_path, CFG_WITH_PREVIOUS)
    _ssm_with_secrets()
    scratch = tmp_path / ".scratch"; scratch.mkdir()
    monkeypatch.setattr(sm, "CONFIG_PATH", c)
    monkeypatch.setattr(sm, "ROUTER_CONFIG", r)
    monkeypatch.setattr(sm, "SCRATCH_ROOT", scratch)
    out_file = scratch / "3c-1b" / "site-v0.json"
    rc = sm.main(["--token-use", "site-session", "--email", "v@example.test", "--role", "previous",
                  "--ttl", "600", "--save", str(out_file)])
    assert rc == 0
    rec = json.loads(out_file.read_text())
    assert rec["kid"] == "site-hs-v0" and rec["role"] == "previous" and _header(rec["token"])["kid"] == "site-hs-v0"
    printed = capsys.readouterr().out
    assert rec["token"] not in printed and "site-hs-v0" in printed


# ---- 探针目标发现（kid 探针与语义闸门共用；今天冒充真实 owner 是 2A 之前的过渡）----

def _routes(items):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    ddb.create_table(TableName="site-routes",
                     KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                     BillingMode="PAY_PER_REQUEST")
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-routes")
    for it in items:
        t.put_item(Item=it)


def test_live_target_picks_a_require_auth_site_that_is_not_platform(aws, tmp_path):
    c, _ = _files(tmp_path)
    _routes([{"subdomain": "console", "owner": "platform", "require_auth": True},
             {"subdomain": "app-open", "owner": "o@example.test", "require_auth": False},
             {"subdomain": "app-x", "owner": "owner@example.test", "require_auth": True}])
    t = sm.live_target(c)
    assert t.owner == "owner@example.test"
    assert t.site_url == "https://app-x.example.test/"
    assert t.auth_host == "auth.example.test" and t.console_host == "console.example.test"


def test_live_target_is_fatal_when_no_site_qualifies(aws, tmp_path):
    c, _ = _files(tmp_path)
    _routes([{"subdomain": "console", "owner": "platform", "require_auth": True}])
    with pytest.raises(SystemExit, match="require_auth"):
        sm.live_target(c)
