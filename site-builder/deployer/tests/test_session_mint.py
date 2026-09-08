"""`scripts/_session_mint.py`：夹具签发器的客户端（3c-final；ADR 0002）。**import 期不得碰 AWS。**

本模块不再持有任何密钥：站点会话来自 `sts.assume_role(site-builder-verifier)` + SigV4 `POST`
auth 的 `/fixture-session`；升级码与面板会话走**真实**换取链路。`family=` 覆盖已删——KMS 之后
没有任何组件能带外签 console family，跨 family 反例改由 auth / Edge 单测给（plan D3）。
"""
import base64
import json
import os
import sys
import textwrap
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "auth", "deployer/functions"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import _session_mint as sm  # noqa: E402

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.test
    account_id = 111111111111
    routing_table = site-routes

    [Verification]
    fixture_issuer = true
    verifier_trusted_principals = arn:aws:iam::111111111111:user/kent
""")
CFG_OFF = CFG.replace("fixture_issuer = true", "fixture_issuer = false")
URL = "https://abc.lambda-url.us-east-1.on.aws/"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6InByb2JlQGUyZS5pbnZhbGlkIn0.c2ln"
CODE = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJ4In0.c2ln"
CONSOLE = "eyJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl91c2UiOiJjb25zb2xlLXNlc3Npb24ifQ.c2ln"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# 带 kid 的 header（真机形态）：CLI 的记录字段 `kid` 是从 header 解出来的，
# 上面那枚 TOKEN 的 header 里没有 kid，证不出"解对了"。两枚 kid 不同，`role=previous`
# 拿到的必须是 v0 那枚——否则"记录里的 role 与实际那把 key 一致"这条断言是空话。
KID_TOKEN = (_b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "site-rs-v1"}).encode())
             + ".eyJlbWFpbCI6InByb2JlQGUyZS5pbnZhbGlkIn0.c2ln")
KID_TOKEN_PREV = (_b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "site-rs-v0"}).encode())
                  + ".eyJlbWFpbCI6InByb2JlQGUyZS5pbnZhbGlkIn0.c2ln")


class FakeSession:
    """boto3.Session 替身：sts.assume_role 与 lambda.get_function_url_config。"""
    def __init__(self):
        self.calls = []

    def client(self, svc, region_name=None):
        outer = self

        class C:
            def assume_role(self, **kw):
                outer.calls.append(("assume_role", kw))
                return {"Credentials": {"AccessKeyId": "AKIA" + "X" * 16, "SecretAccessKey": "s", "SessionToken": "t"}}

            def get_function_url_config(self, FunctionName):
                outer.calls.append(("get_function_url_config", FunctionName))
                return {"FunctionUrl": URL, "AuthType": "AWS_IAM"}
        return C()


class FakeHttp:
    """记录每个请求；按 URL 路径给出理想应答（auth 的 /fixture-session、/console-session、panel 的 callback）。

    `token_previous` 给 `role=previous` 的应答换一枚**header 里 kid 不同**的 token：签发器真机上就是
    这样（两个槽位两把 key），而"记录里的 kid 是从 header 解出来的"只有在两枚不同时才证得出来。
    """
    def __init__(self, *, fixture_status=200, token=TOKEN, token_previous=None):
        self.requests = []
        self.fixture_status = fixture_status
        self.token = token
        self.token_previous = token_previous

    def __call__(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        path = urlparse(url).path
        if path.endswith("/fixture-session"):
            b = json.loads(body)
            previous = b.get("role", "current") == "previous"
            return self.fixture_status, {"content-type": "application/json"}, json.dumps(
                {"token": self.token_previous if (previous and self.token_previous) else self.token,
                 "kid": "site-rs-v0" if previous else "site-rs-v1",
                 "ttl_seconds": b.get("ttl_seconds", 1800)})
        if path == "/console-session":
            return 302, {"location": f"https://console.example.test/api/session-callback?code={CODE}"}, ""
        if path == "/api/session-callback":
            return 302, {"location": "https://console.example.test/",
                         "set-cookie": [f"__Host-sb_console={CONSOLE}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=14400"]}, ""
        raise AssertionError(f"unexpected {method} {url}")


def _cfg(tmp_path, text=CFG):
    p = tmp_path / "config.ini"; p.write_text(text); return p


def _minter(tmp_path, http=None, text=CFG):
    return sm.Minter.from_config(_cfg(tmp_path, text), session=FakeSession(), http=http or FakeHttp())


def test_import_has_no_side_effects_and_exposes_the_api():
    for name in ("Minter", "live_target", "save_token", "load_saved_token", "PROBE_EMAIL", "FIXTURE_SITE_ID"):
        assert hasattr(sm, name), name
    assert sm.PROBE_EMAIL == "probe@e2e.invalid" and sm.FIXTURE_SITE_ID == "e2e-probe"


def test_from_config_only_finds_the_auth_url_and_each_mint_assumes_the_role_afresh(tmp_path):
    fs = FakeSession()
    m = sm.Minter.from_config(_cfg(tmp_path), session=fs, http=FakeHttp())
    assert [c[0] for c in fs.calls] == ["get_function_url_config"] and fs.calls[0][1] == "site-auth-service"
    m.site_session("probe@e2e.invalid")
    m.site_session("probe@e2e.invalid")
    # D11：验收角色会话上限 3600 s、E2E 约 37 min——构造时只 assume 一次会贴着上限，过期症状是 Function URL 403、
    # 读起来像授权配错。每次 mint 一次 AssumeRole（900 s 是 STS 允许的最小值），没有到期刷新那套时钟逻辑。
    assert [c[0] for c in fs.calls] == ["get_function_url_config", "assume_role", "assume_role"]
    kw = fs.calls[1][1]
    assert kw["RoleArn"] == "arn:aws:iam::111111111111:role/site-builder-verifier" and kw["DurationSeconds"] == 900
    assert kw["RoleSessionName"].startswith("verify-")


def test_from_config_refuses_when_the_component_is_off(tmp_path):
    with pytest.raises(SystemExit, match="fixture_issuer"):
        sm.Minter.from_config(_cfg(tmp_path, CFG_OFF), session=FakeSession(), http=FakeHttp())


def test_from_config_refuses_an_empty_config(tmp_path):
    """configparser 对缺失文件是静默的——不硬失败就会拿空值往下拼出假结论。"""
    with pytest.raises(SystemExit, match="读空了"):
        sm.Minter.from_config(tmp_path / "missing.ini", session=FakeSession(), http=FakeHttp())


def test_site_session_posts_a_sigv4_signed_request_with_the_contract_body(tmp_path):
    http = FakeHttp()
    tok = _minter(tmp_path, http).site_session("probe@e2e.invalid", ttl_seconds=600, name="Probe")
    assert tok == TOKEN
    method, url, headers, body = http.requests[0]
    assert (method, url) == ("POST", URL + "fixture-session")
    assert json.loads(body) == {"email": "probe@e2e.invalid", "ttl_seconds": 600, "name": "Probe", "role": "current"}
    h = {k.lower(): v for k, v in headers.items()}
    assert h["authorization"].startswith("AWS4-HMAC-SHA256") and "x-amz-security-token" in h and "x-amz-date" in h
    assert h["content-type"] == "application/json"


def test_role_previous_is_passed_through(tmp_path):
    http = FakeHttp()
    _minter(tmp_path, http).site_session("probe@e2e.invalid", role="previous")
    assert json.loads(http.requests[0][3])["role"] == "previous"


def test_an_unknown_role_is_refused_before_any_request(tmp_path):
    http = FakeHttp()
    with pytest.raises(SystemExit, match="role"):
        _minter(tmp_path, http).site_session("probe@e2e.invalid", role="legacy")
    assert http.requests == []


@pytest.mark.parametrize("email", ["a@example.com", "a@e2e.invalid.x", "", "a@E2E.INVALID"])
def test_non_fixture_emails_are_refused_client_side_before_any_request(tmp_path, email):
    http = FakeHttp()
    with pytest.raises(SystemExit, match="e2e.invalid"):
        _minter(tmp_path, http).site_session(email)
    assert http.requests == []


def test_non_200_from_the_issuer_is_fatal_and_names_the_status(tmp_path):
    with pytest.raises(SystemExit, match="403"):
        _minter(tmp_path, FakeHttp(fixture_status=403)).site_session("probe@e2e.invalid")


def test_upgrade_code_and_console_session_walk_the_real_exchange_chain(tmp_path):
    http = FakeHttp()
    m = _minter(tmp_path, http)
    assert m.upgrade_code("probe@e2e.invalid") == CODE
    http.requests.clear()
    assert m.console_session("probe@e2e.invalid") == CONSOLE
    paths = [(r[0], urlparse(r[1]).netloc, urlparse(r[1]).path) for r in http.requests]
    assert paths == [("POST", urlparse(URL).netloc, "/fixture-session"),
                     ("GET", "auth.example.test", "/console-session"),
                     ("GET", "console.example.test", "/api/session-callback")]
    assert http.requests[1][2]["cookie"] == f"sb_session={TOKEN}"
    assert parse_qs(urlparse(http.requests[2][1]).query)["code"] == [CODE]


def test_console_session_reuses_the_given_site_session_instead_of_minting_again(tmp_path):
    """一枚会话走完整条链路：多签一枚不是错，但那让"这枚会话被 auth 与 panel 都接受了"证不成立。"""
    http = FakeHttp()
    m = _minter(tmp_path, http)
    assert m.console_session("probe@e2e.invalid", site_session="GIVEN.a.b") == CONSOLE
    assert [urlparse(r[1]).path for r in http.requests] == ["/console-session", "/api/session-callback"]
    assert all(r[2]["cookie"] == "sb_session=GIVEN.a.b" for r in http.requests)


def test_a_chain_step_that_does_not_hand_back_a_cookie_is_fatal(tmp_path):
    """panel 不下发 `__Host-sb_console` 时必须响亮失败——静默返回空串会让调用方拿空 cookie 继续。"""
    def http(method, url, headers, body):
        if url.endswith("/console-session"):
            return 302, {"location": f"https://console.example.test/api/session-callback?code={CODE}"}, ""
        return 401, {}, "no"

    with pytest.raises(SystemExit, match="session-callback"):
        _minter(tmp_path, http).console_session("probe@e2e.invalid", site_session="GIVEN.a.b")


@pytest.mark.parametrize("token_use", ["console-upgrade", "console-session"])
def test_console_uses_refuse_a_non_current_role_before_any_request(tmp_path, token_use):
    """`role=previous` 配 console 用途必须**响亮拒绝**，不是静默按 current 走。

    静默忽略的后果：`save_token` 记下 `role: previous`，而链路里那枚升级码永远是 auth 用
    console current key 签的 ⇒ DEPLOY.md 退役前预存的那条负向探针（退役后期望 panel 401）
    会**因为码过期**而变绿，而它要证明的是"旧 kid 不再被接受"。下一步就是不可逆的删参数。
    """
    http = FakeHttp()
    with pytest.raises(SystemExit, match="role"):
        _minter(tmp_path, http).mint(token_use, "probe@e2e.invalid", role="previous")
    assert http.requests == [], "拒绝必须发生在任何一次 HTTP 之前"


def test_site_session_still_accepts_previous_as_a_positive_control(tmp_path):
    """正对照：同一个入口下 site-session + previous 必须照旧可用（上面那条拒的是 console 用途，不是 previous）。"""
    http = FakeHttp(token=KID_TOKEN, token_previous=KID_TOKEN_PREV)
    assert _minter(tmp_path, http).mint("site-session", "probe@e2e.invalid", role="previous") == KID_TOKEN_PREV
    assert json.loads(http.requests[0][3])["role"] == "previous"


def test_mint_dispatches_by_token_use_and_has_no_family_override(tmp_path):
    m = _minter(tmp_path)
    assert m.mint("site-session", "p@e2e.invalid") == TOKEN
    assert m.mint("console-upgrade", "p@e2e.invalid") == CODE
    assert m.mint("console-session", "p@e2e.invalid") == CONSOLE
    with pytest.raises(TypeError):
        m.mint("site-session", "p@e2e.invalid", family="console")
    with pytest.raises(SystemExit):
        m.mint("legacy", "p@e2e.invalid")


def test_live_target_picks_only_the_resident_fixture_site(aws, tmp_path):
    import boto3
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    t = ddb.create_table(TableName="site-routes", KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
    t.put_item(Item={"subdomain": "app-real", "require_auth": True, "owner": "real@example.test"})
    with pytest.raises(SystemExit, match="ensure_fixture_site"):
        sm.live_target(_cfg(tmp_path), ddb=ddb)
    t.put_item(Item={"subdomain": "app-e2e-probe", "require_auth": True, "owner": sm.PROBE_EMAIL})
    tgt = sm.live_target(_cfg(tmp_path), ddb=ddb)
    assert (tgt.subdomain, tgt.owner, tgt.base) == ("app-e2e-probe", sm.PROBE_EMAIL, "example.test")


def test_live_target_pages_through_the_whole_routing_table(tmp_path):
    """夹具站点在第二页 —— 不翻页就会以"没有夹具站点"失败（3c-1B-G A5），而报文指向路由表内容，真因是分页。"""
    pages = [{"Items": [{"subdomain": "console", "owner": "platform", "require_auth": True},
                        {"subdomain": "app-open", "owner": "o@x.test", "require_auth": False}],
              "LastEvaluatedKey": {"subdomain": "app-open"}},
             {"Items": [{"subdomain": "app-e2e-probe", "owner": sm.PROBE_EMAIL, "require_auth": True}]}]
    seen = []

    class _T:
        def scan(self, **kw):
            seen.append(kw.get("ExclusiveStartKey"))
            return pages[len(seen) - 1]

    class _DDB:
        def Table(self, name):
            return _T()

    t = sm.live_target(_cfg(tmp_path), ddb=_DDB())
    assert t.subdomain == "app-e2e-probe" and t.owner == sm.PROBE_EMAIL
    assert seen == [None, {"subdomain": "app-open"}], seen
    assert (t.site_url, t.auth_host, t.console_host) == (
        "https://app-e2e-probe.example.test/", "auth.example.test", "console.example.test")


def test_org_target_finds_a_real_org_site_and_is_none_when_the_account_has_none(aws, tmp_path):
    """ADR 0002 的边界判据要一条**真实** org 站点（夹具会话投过去必须 302）。

    没有这样的站点时返回 None（闸门据此报 skip，不是失败）；夹具站点自己即使 `allowed_users="org"`
    也不算——拿它当目标那条判据就变成了"夹具会话能进夹具站点"，与正对照重复。
    """
    import boto3
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    t = ddb.create_table(TableName="site-routes", KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
    t.put_item(Item={"subdomain": "app-e2e-probe", "owner": sm.PROBE_EMAIL, "require_auth": True,
                     "allowed_users": "org"})
    t.put_item(Item={"subdomain": "app-open", "owner": "real@example.test", "require_auth": False,
                     "allowed_users": "org"})
    t.put_item(Item={"subdomain": "app-listed", "owner": "real@example.test", "require_auth": True,
                     "allowed_users": ["real@example.test"]})
    assert sm.org_target(_cfg(tmp_path), ddb=ddb) is None
    t.put_item(Item={"subdomain": "app-org", "owner": "real@example.test", "require_auth": True,
                     "allowed_users": "org"})
    tgt = sm.org_target(_cfg(tmp_path), ddb=ddb)
    assert tgt is not None and (tgt.subdomain, tgt.owner) == ("app-org", "real@example.test")


# ---- 预存 / 读回（负向探针用）：不碰签发，原样保留 -------------------------------------------

def test_save_token_writes_json_record_only_under_scratch(tmp_path):
    scratch = tmp_path / ".scratch"
    scratch.mkdir()
    rec = {"token_use": "site-session", "role": "previous", "kid": "site-rs-v0",
           "email": sm.PROBE_EMAIL, "token": "a.b.c"}
    out = sm.save_token(scratch / "rotation" / "v0.json", rec, scratch_root=scratch)
    assert json.loads(out.read_text()) == rec
    with pytest.raises(SystemExit, match="scratch"):
        sm.save_token(tmp_path / "elsewhere.json", rec, scratch_root=scratch)
    with pytest.raises(SystemExit, match="scratch"):
        sm.save_token(scratch / ".." / "escape.json", rec, scratch_root=scratch)


def test_load_saved_token_round_trips_and_rejects_garbage(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"token_use": "console-upgrade", "role": "previous", "kid": "console-rs-v1",
                             "email": sm.PROBE_EMAIL, "token": "x.y.z"}))
    assert sm.load_saved_token(p) == ("console-upgrade", "x.y.z")
    (tmp_path / "bad.json").write_text('{"token": "x.y.z"}')
    with pytest.raises(SystemExit, match="token_use"):
        sm.load_saved_token(tmp_path / "bad.json")


def test_cli_mints_and_saves_with_role_and_prints_no_token(tmp_path, capsys, monkeypatch):
    """`--role previous` 写出的记录必须自洽：`role` 与 token **header 里的 kid** 指同一把 key。

    从前这条断言的是 `role=previous` + `kid=site-rs-v1`（current 那把），自相矛盾——而"记录里的
    role 与实际签名的 key 一致"正是退役前负向探针唯一的依据。
    """
    http = FakeHttp(token=KID_TOKEN, token_previous=KID_TOKEN_PREV)
    m = _minter(tmp_path, http)
    scratch = tmp_path / ".scratch"; scratch.mkdir()
    monkeypatch.setattr(sm.Minter, "from_config", classmethod(lambda cls, *a, **kw: m))
    monkeypatch.setattr(sm, "SCRATCH_ROOT", scratch)
    out_file = scratch / "rotation" / "site-previous.json"
    rc = sm.main(["--token-use", "site-session", "--email", sm.PROBE_EMAIL, "--role", "previous",
                  "--ttl", "600", "--save", str(out_file)])
    assert rc == 0
    rec = json.loads(out_file.read_text())
    assert set(rec) == {"token_use", "role", "kid", "email", "minted_at", "ttl_seconds", "token"}
    assert (rec["token_use"], rec["role"], rec["kid"], rec["email"]) == (
        "site-session", "previous", "site-rs-v0", sm.PROBE_EMAIL)
    assert rec["token"] == KID_TOKEN_PREV and json.loads(http.requests[0][3])["role"] == "previous"
    printed = capsys.readouterr().out
    assert rec["token"] not in printed and "site-rs-v0" in printed


def test_cli_refuses_a_non_current_role_for_console_upgrade(tmp_path, monkeypatch):
    """argparse 层就拒（exit 2），且什么都不写：记录里 `role=previous` 而实际是 current key 签的
    升级码，会让退役前那条负向探针因为"码过期"而假绿。"""
    m = _minter(tmp_path, FakeHttp())
    scratch = tmp_path / ".scratch"; scratch.mkdir()
    monkeypatch.setattr(sm.Minter, "from_config", classmethod(lambda cls, *a, **kw: m))
    monkeypatch.setattr(sm, "SCRATCH_ROOT", scratch)
    out_file = scratch / "code.json"
    with pytest.raises(SystemExit) as exc:
        sm.main(["--token-use", "console-upgrade", "--role", "previous", "--save", str(out_file)])
    assert exc.value.code == 2
    assert not out_file.exists()


def test_cli_defaults_to_the_probe_identity_and_refuses_a_console_session_record(tmp_path, capsys, monkeypatch):
    """面板会话记录不接受：panel 只在写请求上验它，而探针只发 GET（预存那种记录读回时才炸）。"""
    m = _minter(tmp_path, FakeHttp())
    scratch = tmp_path / ".scratch"; scratch.mkdir()
    monkeypatch.setattr(sm.Minter, "from_config", classmethod(lambda cls, *a, **kw: m))
    monkeypatch.setattr(sm, "SCRATCH_ROOT", scratch)
    with pytest.raises(SystemExit):
        sm.main(["--token-use", "console-session", "--save", str(scratch / "x.json")])
    assert sm.main(["--token-use", "console-upgrade", "--save", str(scratch / "code.json")]) == 0
    assert json.loads((scratch / "code.json").read_text())["email"] == sm.PROBE_EMAIL


# ---- ticket 17 第 6、13 条（/code-review 2026-09-04）------------------------------------------
#
# 6：`--save` 的相对路径按 `.scratch/` 解析，于是模块 docstring 自己的例子
#    `--save .scratch/rotation/x.json` 会落进 `.scratch/.scratch/rotation/`——命令**成功**，
#    到用 `--retired-token` 读回（按 cwd 解析）时才以"不是 --save 写出的记录"失败。
# 13：token 是活凭证，却按默认 umask 落成 0644、目录 0755。

def test_save_token_accepts_a_leading_scratch_prefix_instead_of_nesting_it(tmp_path):
    """写 `.scratch/a/b.json` 与写 `a/b.json` 必须落在同一个文件上。

    两种写法都出现在仓库文档里（模块 docstring 用前者、runbook 用后者），而"多出一层
    `.scratch/.scratch/`"是静默的——只有读回那一步才炸。
    """
    scratch = tmp_path / ".scratch"
    rec = {"token_use": "site-session", "token": "t.t.t"}
    a = sm.save_token(".scratch/rotation/v1.json", rec, scratch_root=scratch)
    b = sm.save_token("rotation/v1.json", rec, scratch_root=scratch)
    assert a == b == (scratch / "rotation" / "v1.json").resolve()
    assert not (scratch / ".scratch").exists(), "又嵌了一层 .scratch/"
    # 读回那一步（探针按 cwd 解析）必须能拿到它
    assert sm.load_saved_token(a) == ("site-session", "t.t.t")


def test_save_token_still_refuses_paths_outside_scratch(tmp_path):
    """回归：吃掉 `.scratch/` 前缀不能变成"逃逸检查放水"，也不能变成**前缀模糊匹配**。"""
    scratch = tmp_path / ".scratch"
    rec = {"token_use": "site-session", "token": "t.t.t"}
    # 逃逸仍然硬拒——检查在吃掉前缀**之后**做
    for bad in ("../escape.json", ".scratch/../escape.json", ".scratch/../../escape.json"):
        with pytest.raises(SystemExit):
            sm.save_token(bad, rec, scratch_root=scratch)
    # 只吃**恰好等于**根目录名的第一段：`.scratchy` 是 scratch 里一个普通子目录，不许被当成前缀削掉
    out = sm.save_token(".scratchy/x.json", rec, scratch_root=scratch)
    assert out == (scratch / ".scratchy" / "x.json").resolve()


def test_save_token_writes_a_live_credential_with_owner_only_permissions(tmp_path):
    """0644 的活凭证同机任何账号可读、可重放成夹具身份的会话。"""
    scratch = tmp_path / ".scratch"
    out = sm.save_token("rotation/v1.json", {"token_use": "site-session", "token": "t.t.t"},
                        scratch_root=scratch)
    assert oct(out.stat().st_mode)[-3:] == "600", oct(out.stat().st_mode)
    assert oct(out.parent.stat().st_mode)[-3:] == "700", oct(out.parent.stat().st_mode)


def test_module_docstring_save_example_is_a_form_that_round_trips(tmp_path):
    """docstring 里的例子必须是能用的形态——它就是操作者会照抄的那一行。"""
    import re
    m = re.search(r"--save (\S*/\S*)", sm.__doc__)   # 取带路径分隔符的那个真例子，不是 `--save FILE` 那行占位
    assert m, "docstring 里没有带路径的 --save 例子了"
    scratch = tmp_path / ".scratch"
    out = sm.save_token(m.group(1), {"token_use": "site-session", "token": "t.t.t"}, scratch_root=scratch)
    assert out.is_relative_to(scratch) and not (scratch / ".scratch").exists()


# ---- 3c-1B-G A5：目录权限、target==root -----------------------------------------------------

def test_save_token_refuses_the_scratch_root_itself(tmp_path):
    """`--save .scratch` 会被前缀吃成空路径 ⇒ 曾经抛裸 IsADirectoryError。"""
    root = tmp_path / ".scratch"
    root.mkdir()
    for bad in (".scratch", ".", ""):
        with pytest.raises(SystemExit, match="文件路径"):
            sm.save_token(Path(bad), {"token_use": "site-session", "token": "a.b.c"}, scratch_root=root)


def test_save_token_tightens_directories_that_already_exist(tmp_path):
    """复审低优先级 2：`.scratch/` 与子目录已经以 0755 存在时也要收到 0700——否则"目录 0700"
    只对新克隆成立。范围到 scratch 根为止：它的父目录不动。"""
    root = tmp_path / ".scratch"
    (root / "rotation").mkdir(parents=True)
    os.chmod(root, 0o755); os.chmod(root / "rotation", 0o755)
    parent_mode = oct(tmp_path.stat().st_mode)[-3:]
    sm.save_token(Path("rotation/v1.json"), {"token_use": "site-session", "token": "a.b.c"},
                  scratch_root=root)
    assert oct(root.stat().st_mode)[-3:] == "700"
    assert oct((root / "rotation").stat().st_mode)[-3:] == "700"
    assert oct(tmp_path.stat().st_mode)[-3:] == parent_mode, "scratch 根以上的目录不该被动"


def test_save_token_does_not_follow_a_symlink_out_of_scratch(tmp_path):
    """复审三轮 P2 的同一个洞在 token 文件上（内容是一枚可重放的 cookie）。这里比 write_dump 更强：
    `save_token` 先 `resolve()` 再做逃逸检查 ⇒ 指向 .scratch **外**的 symlink 被**拒绝**而不是被跟随，
    victim 一个字节不动。（.scratch 内部的 symlink 会解析到真实文件——那仍在 0700 目录里，是有意的。）"""
    root = tmp_path / ".scratch"; (root / "rotation").mkdir(parents=True)
    victim = tmp_path / "victim"; victim.write_text("keep me"); os.chmod(victim, 0o644)
    link = root / "rotation" / "v1.json"; link.symlink_to(victim)
    with pytest.raises(SystemExit, match="只许写进"):
        sm.save_token(Path("rotation/v1.json"), {"token_use": "site-session", "token": "a.b.c"}, scratch_root=root)
    assert victim.read_text() == "keep me" and oct(victim.stat().st_mode)[-3:] == "644"
    assert link.is_symlink(), "拒绝时不该动那个链接"


def test_save_token_writes_a_fresh_0600_inode_over_an_existing_0644_file(tmp_path):
    """覆盖已有 0644 文件：不能在旧 inode 上原地截断（写入期间仍 0644、已打开的读者会读到新 cookie）。"""
    root = tmp_path / ".scratch"; (root / "rotation").mkdir(parents=True)
    out = root / "rotation" / "v1.json"; out.write_text("old"); os.chmod(out, 0o644)
    old_ino = out.stat().st_ino
    with open(out) as reader:
        sm.save_token(Path("rotation/v1.json"), {"token_use": "site-session", "token": "a.b.c"}, scratch_root=root)
        assert reader.read() == "old"
    assert out.stat().st_ino != old_ino and oct(out.stat().st_mode)[-3:] == "600"
    assert sm.load_saved_token(out) == ("site-session", "a.b.c")


def test_save_token_locks_down_the_scratch_root_it_creates(tmp_path):
    """`mkdir(mode=…)` 不作用于顺带创建的父目录 ⇒ 新克隆上 `.scratch/` 会是 0755。"""
    root = tmp_path / ".scratch"          # 故意**不**预先创建
    sm.save_token(Path("rotation/v1.json"), {"token_use": "site-session", "token": "a.b.c"},
                  scratch_root=root)
    assert oct(root.stat().st_mode)[-3:] == "700", oct(root.stat().st_mode)
    assert oct((root / "rotation").stat().st_mode)[-3:] == "700"
