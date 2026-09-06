"""`scripts/_session_mint.py`：验收工具唯一的本地 mint 入口（3c-1B ticket 01，spec §11.8.4）。

先于实现写下并跑红。它读 `[SessionKeys]`、按 family/role 取 SSM 值、调用**生产** `session.mint_token`
（legacy role 调用旧 mint，用于 L3/退役之前预存负向探针 token）。路径只来自 config；`--save` 只许写进
`.scratch/`。2A 把这个模块换成夹具签发器，六处调用方不动。
"""
import base64
import json
import os
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
    signer = legacy
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


# ---- ticket 17 第 6、13 条（/code-review 2026-09-04）------------------------------------------
#
# 6：`--save` 的相对路径按 `.scratch/` 解析，于是模块 docstring 自己的例子
#    `--save .scratch/3c-1b/x.json` 会落进 `.scratch/.scratch/3c-1b/`——命令**成功**，
#    到 ⑤/⑩ 用 `--retired-token` 读回（按 cwd 解析）时才以"不是 --save 写出的记录"失败，
#    而那时配置已改、三个组件已重部，且 ⑩ 的 previous 已从 config 删掉、token 无法重签。
# 13：token 是活凭证，却按默认 umask 落成 0644、目录 0755。

def test_save_token_accepts_a_leading_scratch_prefix_instead_of_nesting_it(tmp_path):
    """写 `.scratch/a/b.json` 与写 `a/b.json` 必须落在同一个文件上。

    两种写法都出现在仓库文档里（模块 docstring 用前者、runbook 用后者），而"多出一层
    `.scratch/.scratch/`"是静默的——只有读回那一步才炸。
    """
    scratch = tmp_path / ".scratch"
    rec = {"token_use": "site-session", "token": "t.t.t"}
    a = sm.save_token(".scratch/3c-1b/v1.json", rec, scratch_root=scratch)
    b = sm.save_token("3c-1b/v1.json", rec, scratch_root=scratch)
    assert a == b == (scratch / "3c-1b" / "v1.json").resolve()
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
    """0644 的活凭证同机任何账号可读、可重放成目标站点 owner 的会话。"""
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


# ---- 3c-1B-G A1：跨 family 同形态 token（family separation 闸门的隔离变量）------------------
#
# `mint()` 原先只由 `token_use` 推导 family（`FAMILY_OF`），于是**造不出**"console kid +
# token_use=site-session"这一种形态——而那正是唯一能单独证明"console kid 不在 site
# allowlist"的 token。缺了它，探针同时改了两个变量（kid family 与 token_use），
# 它的 302 可以来自任一条，闸门因此在 allowlist 真的失守时照旧全绿（见下面 Edge 侧那条）。

def test_family_override_mints_a_cross_family_same_shape_token(aws, tmp_path):
    """`family=` 显式覆盖 ⇒ console kid 签的 **site-session** token（只改 kid family 一个变量）。"""
    m = _minter(tmp_path)
    tok = m.mint("site-session", "v@example.test", ttl_seconds=600, family="console")
    assert _header(tok)["kid"] == "console-hs-v1", _header(tok)
    p = _payload(tok)
    assert p["token_use"] == "site-session" and p["aud"] == "site-edge", p
    # 对照：不给 family 时仍是 site kid（默认行为不变）
    assert _header(m.mint("site-session", "v@example.test", ttl_seconds=600))["kid"] == "site-hs-v1"


def test_family_override_is_validated_not_silently_ignored(aws, tmp_path):
    m = _minter(tmp_path)
    with pytest.raises(SystemExit, match="family"):
        m.mint("site-session", "v@example.test", ttl_seconds=600, family="nope")


# ---- 3c-1B-G A5：分页、目录权限、target==root -----------------------------------------------

def test_live_target_pages_through_the_whole_routing_table(tmp_path):
    """首页只有公开站点/平台行时，合格站点在第二页 —— 不翻页就会以"没有目标"失败。"""
    pages = [{"Items": [{"subdomain": "console", "owner": "platform", "require_auth": True},
                        {"subdomain": "app-open", "owner": "o@x.test", "require_auth": False}],
              "LastEvaluatedKey": {"subdomain": "app-open"}},
             {"Items": [{"subdomain": "app-deep", "owner": "deep@x.test", "require_auth": True}]}]
    seen = []

    class _T:
        def scan(self, **kw):
            seen.append(kw.get("ExclusiveStartKey"))
            return pages[len(seen) - 1]

    class _DDB:
        def Table(self, name):
            return _T()

    _files(tmp_path)
    t = sm.live_target(tmp_path / "config.ini", ddb=_DDB())
    assert t.subdomain == "app-deep" and t.owner == "deep@x.test"
    assert seen == [None, {"subdomain": "app-open"}], seen


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
    (root / "3c-1b").mkdir(parents=True)
    os.chmod(root, 0o755); os.chmod(root / "3c-1b", 0o755)
    parent_mode = oct(tmp_path.stat().st_mode)[-3:]
    sm.save_token(Path("3c-1b/v1.json"), {"token_use": "site-session", "token": "a.b.c"},
                  scratch_root=root)
    assert oct(root.stat().st_mode)[-3:] == "700"
    assert oct((root / "3c-1b").stat().st_mode)[-3:] == "700"
    assert oct(tmp_path.stat().st_mode)[-3:] == parent_mode, "scratch 根以上的目录不该被动"


def test_save_token_does_not_follow_a_symlink_out_of_scratch(tmp_path):
    """复审三轮 P2 的同一个洞在 token 文件上（内容是一枚可重放的 cookie）。这里比 write_dump 更强：
    `save_token` 先 `resolve()` 再做逃逸检查 ⇒ 指向 .scratch **外**的 symlink 被**拒绝**而不是被跟随，
    victim 一个字节不动。（.scratch 内部的 symlink 会解析到真实文件——那仍在 0700 目录里，是有意的。）"""
    root = tmp_path / ".scratch"; (root / "3c-1b").mkdir(parents=True)
    victim = tmp_path / "victim"; victim.write_text("keep me"); os.chmod(victim, 0o644)
    link = root / "3c-1b" / "v1.json"; link.symlink_to(victim)
    with pytest.raises(SystemExit, match="只许写进"):
        sm.save_token(Path("3c-1b/v1.json"), {"token_use": "site-session", "token": "a.b.c"}, scratch_root=root)
    assert victim.read_text() == "keep me" and oct(victim.stat().st_mode)[-3:] == "644"
    assert link.is_symlink(), "拒绝时不该动那个链接"


def test_save_token_writes_a_fresh_0600_inode_over_an_existing_0644_file(tmp_path):
    """覆盖已有 0644 文件：不能在旧 inode 上原地截断（写入期间仍 0644、已打开的读者会读到新 cookie）。"""
    root = tmp_path / ".scratch"; (root / "3c-1b").mkdir(parents=True)
    out = root / "3c-1b" / "v1.json"; out.write_text("old"); os.chmod(out, 0o644)
    old_ino = out.stat().st_ino
    with open(out) as reader:
        sm.save_token(Path("3c-1b/v1.json"), {"token_use": "site-session", "token": "a.b.c"}, scratch_root=root)
        assert reader.read() == "old"
    assert out.stat().st_ino != old_ino and oct(out.stat().st_mode)[-3:] == "600"
    assert sm.load_saved_token(out) == ("site-session", "a.b.c")


def test_save_token_locks_down_the_scratch_root_it_creates(tmp_path):
    """`mkdir(mode=…)` 不作用于顺带创建的父目录 ⇒ 新克隆上 `.scratch/` 会是 0755。"""
    root = tmp_path / ".scratch"          # 故意**不**预先创建
    sm.save_token(Path("3c-1b/v1.json"), {"token_use": "site-session", "token": "a.b.c"},
                  scratch_root=root)
    assert oct(root.stat().st_mode)[-3:] == "700", oct(root.stat().st_mode)
    assert oct((root / "3c-1b").stat().st_mode)[-3:] == "700"
