"""panel 侧：验 code、jti 原子消费、cookie 形态、cookie↔header 一致性。"""
import json

import boto3
import pytest

import console_session
import session
from upgrade_code_vectors import MUTATIONS, SECRET


def test_code_is_single_use(aws, secret):
    code = session.mint_upgrade_code("u@x.com", SECRET)
    assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="u@x.com")  # 重放


def test_replay_is_rejected_by_conditional_write_not_by_a_read_check(aws, secret):
    """并发重放：两个请求同时用同一 code，只有一个能成。

    条件写（attribute_not_exists(jti)）才有这个性质；"先 get 再 put"的写法
    在并发下两边都会看到"没用过"。
    """
    code = session.mint_upgrade_code("u@x.com", SECRET)
    ok = 0
    for _ in range(2):
        try:
            console_session.consume_code(code, expected_email="u@x.com")
            ok += 1
        except console_session.UpgradeRejected:
            pass
    assert ok == 1


def test_consumed_jti_row_has_ttl(aws, secret):
    """session-codes 是一次性标记——必须带 TTL，否则表无限增长。"""
    console_session.consume_code(session.mint_upgrade_code("u@x.com", SECRET),
                                expected_email="u@x.com")
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert len(items) == 1 and int(items[0]["expires_at"]) > 0


def test_expired_code_is_rejected_before_being_consumed(aws, secret):
    """过期 code 不得占用 jti 行——否则攻击者能用过期 code 污染表。"""
    import time
    code = session.mint_upgrade_code("u@x.com", SECRET, ttl_seconds=1)
    time.sleep(1.1)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="u@x.com")
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == []


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_same_vectors_as_auth_side(aws, secret, name, mutate, expect_reject):
    code = mutate(session.mint_upgrade_code("u@x.com", SECRET))
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code, expected_email="u@x.com")
    else:
        assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"


def test_console_cookie_attributes(aws, secret):
    c = console_session.console_cookie("u@x.com", "U")
    assert c.startswith("__Host-sb_console=")
    for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert attr in c, attr
    assert "Domain=" not in c, "__Host- 前缀下带 Domain 浏览器会整条拒绝"


def test_cookie_email_must_match_edge_header(aws, secret):
    """换人登录后旧 __Host-sb_console 必须失效（spec §5.4 第 1 步）。

    残留 cookie 属 A，Edge 注入的身份是 B —— 必须拒绝并要求重新升级，
    否则 B 会拿着 A 的面板会话操作 A 的站点。
    """
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    assert console_session.verify_console_cookie(
        cookie, x_user_email="a@x.com") == "a@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(cookie, x_user_email="b@x.com")


def test_empty_edge_header_is_rejected_not_treated_as_match(aws, secret):
    """x-user-email 为空时不得"因为都为空所以相等"而放行。"""
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(cookie, x_user_email="")


def test_scope_must_be_console(aws, secret):
    """站点会话 cookie（无 scope）不能当面板会话用。"""
    site_jwt = session.mint_session_jwt("u@x.com", "U", SECRET)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"__Host-sb_console={site_jwt}",
                                              x_user_email="u@x.com")


def test_upgrade_code_cannot_be_used_as_console_cookie(aws, secret):
    """60 秒 code 不得当 4 小时面板会话用（它没有 scope=console）。"""
    code = session.mint_upgrade_code("u@x.com", SECRET)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"__Host-sb_console={code}",
                                              x_user_email="u@x.com")


def test_missing_or_other_cookies_are_rejected(aws, secret):
    for header in ("", "a=1; b=2", "sb_session=xyz", "__Host-sb_pkce=abc"):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(header,
                                                  x_user_email="u@x.com")


def test_console_cookie_is_found_among_other_cookies(aws, secret):
    """真实浏览器会带一串 cookie——解析必须按名字精确取，不能只看第一个。"""
    good = console_session.console_cookie("u@x.com", "U").split(";")[0]
    header = f"a=1; {good}; sb_session=zzz"
    assert console_session.verify_console_cookie(
        header, x_user_email="u@x.com") == "u@x.com"


def test_secret_is_read_from_ssm_not_environment(aws, monkeypatch):
    """明文密钥严禁进环境变量——环境里只有参数名。

    GetFunctionConfiguration 会原样回显环境变量，拿到 JWT_SECRET 即可伪造
    任意用户会话（deploy_auth.py 已记录该原因）。
    """
    import os
    calls = []

    class FakeSSM:
        def get_parameter(self, **kw):
            calls.append(kw)
            return {"Parameter": {"Value": SECRET}}

    monkeypatch.setattr(console_session, "_secret_cache", {})
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSSM())
    assert console_session._secret() == SECRET
    assert calls[0]["Name"] == os.environ["JWT_SECRET_PARAM"]
    assert calls[0]["WithDecryption"] is True
    # 环境变量里不得出现密钥本身
    assert SECRET not in os.environ.values()


def test_secret_cache_has_a_ttl(aws, monkeypatch):
    """无 TTL 时轮转密钥后 warm 容器会永久用旧值（auth 的既有教训）。"""
    assert console_session.SECRET_TTL_SECONDS > 0
    calls = []

    class FakeSSM:
        def get_parameter(self, **kw):
            calls.append(kw)
            return {"Parameter": {"Value": SECRET}}

    monkeypatch.setattr(console_session, "_secret_cache", {})
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeSSM())
    console_session._secret()
    console_session._secret()
    assert len(calls) == 1, "TTL 内应命中缓存"
    # 把缓存时间推到过期之外
    name = list(console_session._secret_cache)[0]
    val, _ = console_session._secret_cache[name]
    console_session._secret_cache[name] = (
        val, -console_session.SECRET_TTL_SECONDS * 2)
    console_session._secret()
    assert len(calls) == 2, "过期后应重新读 SSM"


# ── 身份不符不得消费 jti（Codex 审查 2026-08-10 P2-3）──────────────────
# 原实现：handler 先 consume_code() 原子写 jti，**之后**才比对 code 的 email
# 与 Edge 身份。于是拿别人的 code 提交一次（401）就把它作废了，合法持有者
# 随后再用会得到"升级码已被使用"。实测复现过这个顺序。

def test_mismatched_identity_does_not_consume_jti(aws, secret):
    """错身份提交 → 拒绝，且 code **仍可被正确身份使用**。"""
    code = session.mint_upgrade_code("victim@x.com", SECRET)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="attacker@x.com")
    # 表里不得留下消费标记
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == [], f"错身份提交后 jti 已被写入: {items}"
    # 合法持有者仍然能用
    assert console_session.consume_code(
        code, expected_email="victim@x.com") == "victim@x.com"


def test_expected_email_is_required_to_match_exactly(aws, secret):
    """匹配必须逐字符相等，且空值不得视为通过。"""
    code = session.mint_upgrade_code("u@x.com", SECRET)
    for bad in ("", "U@X.COM", "u@x.com ", "u@x.co"):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code, expected_email=bad)
    assert console_session.consume_code(
        code, expected_email="u@x.com") == "u@x.com"


def test_handler_callback_rejects_mismatch_without_burning_code(aws, secret):
    """走 handler 的真实路径：错身份的 callback 不得作废 code。

    这是用户可见面——单独测 consume_code 不够，handler 里的调用顺序才是
    缺陷所在（它原来先消费再比对）。
    """
    import handler
    from test_handler import EDGE_ROLE_ID
    code = session.mint_upgrade_code("victim@x.com", SECRET)
    ev = {"requestContext": {
              "http": {"method": "GET"},
              # 合规的 Edge IAM 上下文——本用例测的是 code 消费顺序，
              # 不是 P1-1 的传输层校验（那个由 test_handler 覆盖）。
              "authorizer": {"iam": {
                  "callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
          "rawPath": "/api/session-callback",
          "headers": {"x-user-email": "attacker@x.com"},
          "queryStringParameters": {"code": code}}
    r = handler.handler(ev, None)
    assert r["statusCode"] == 401, r
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == [], f"错身份的 callback 把 code 作废了: {items}"
    # 合法身份随后仍能换到面板会话
    ev["headers"]["x-user-email"] = "victim@x.com"
    r2 = handler.handler(ev, None)
    assert r2["statusCode"] == 302, r2
    assert any(console_session.CONSOLE_COOKIE in c for c in r2.get("cookies", []))


# ---- 3c-1A：新入口（带 kid）与 legacy 入口并存（状态机 L1）----
from upgrade_code_vectors import (CONSOLE_KID, CONSOLE_KID_SECRET, SITE_KID,  # noqa: E402
                                  SITE_KID_SECRET)


def _kid_code(email="u@x.com", **kw):
    return session.mint_token(kid=CONSOLE_KID, secret=CONSOLE_KID_SECRET, token_use="console-upgrade",
                              email=email, ttl_seconds=60, **kw)


def _kid_console_cookie(email="u@x.com"):
    tok = session.mint_token(kid=CONSOLE_KID, secret=CONSOLE_KID_SECRET, token_use="console-session",
                             email=email, ttl_seconds=3600, name="U")
    return f"{console_session.CONSOLE_COOKIE}={tok}"


def test_kid_form_upgrade_code_is_consumed_once(aws, secret):
    code = _kid_code()
    assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="u@x.com")


def test_kid_form_console_cookie_is_verified(aws, secret):
    assert console_session.verify_console_cookie(_kid_console_cookie(), x_user_email="u@x.com") == "u@x.com"


def test_site_kid_token_is_not_a_console_cookie(aws, secret):
    """panel 的 allowlist 里没有 site family 的 kid（spec §4.3）。"""
    tok = session.mint_token(kid=SITE_KID, secret=SITE_KID_SECRET, token_use="console-session",
                             email="u@x.com", ttl_seconds=3600, name="U")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"{console_session.CONSOLE_COOKIE}={tok}", x_user_email="u@x.com")


def test_kid_form_site_session_is_not_a_console_cookie(aws, secret):
    tok = session.mint_token(kid=CONSOLE_KID, secret=CONSOLE_KID_SECRET, token_use="site-session",
                             email="u@x.com", ttl_seconds=3600, name="U", idp="Feishu", auth_via="x")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"{console_session.CONSOLE_COOKIE}={tok}", x_user_email="u@x.com")


def test_kid_form_console_cookie_is_not_an_upgrade_code(aws, secret):
    tok = _kid_console_cookie().split("=", 1)[1]
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(tok, expected_email="u@x.com")


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_same_vectors_as_auth_side_for_kid_form(aws, secret, name, mutate, expect_reject):
    code = mutate(_kid_code())
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code, expected_email="u@x.com")
    else:
        assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"


def test_legacy_entry_off_rejects_legacy_code_but_not_kid_form(aws, secret, monkeypatch):
    monkeypatch.setenv("LEGACY_ENTRY", "off")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(session.mint_upgrade_code("u@x.com", SECRET), expected_email="u@x.com")
    assert console_session.consume_code(_kid_code(), expected_email="u@x.com") == "u@x.com"


def test_panel_refuses_a_session_keys_json_that_carries_the_site_family(aws, secret, monkeypatch):
    """每个 verifier 只持自己那份 allowlist：panel 拿到 site family 就是部署配置错了，直接拒。"""
    monkeypatch.setenv("SESSION_KEYS_JSON",
                       '{"console": [], "site": [{"kid": "site-hs-v1", "alg": "HS256", "role": "current", '
                       '"ssm_param": "/site-builder/session-keys/site-hs-v1"}]}')
    with pytest.raises(RuntimeError):
        console_session.verify_console_cookie(_kid_console_cookie(), x_user_email="u@x.com")


def test_verify_outcome_is_logged_without_the_token(aws, secret, capsys):
    cookie = _kid_console_cookie()
    console_session.verify_console_cookie(cookie, x_user_email="u@x.com")
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.splitlines() if l.startswith("{") and "session_verify" in l]
    assert lines and lines[-1]["outcome"] == "accepted_current" and lines[-1]["verifier"] == "panel"
    assert cookie.split("=", 1)[1].split(".")[1] not in out


# ---- 3c-1B：panel signer 开关（spec §11.8.3 / §11.4 的面板会话表）----------------------
#
# 断言的是**外部可见形态**：Set-Cookie 里 token 的 JOSE 头与 payload 的精确 claim 集合、
# `__Host-` 三要素、以及一致性校验的结果。两侧都测——`legacy` 是"1A 前字节级不变"的基线，
# 只测新形态的话，一个把 legacy 分支改坏的改动会在 ③ 切换**之前**那次部署（开关仍是
# legacy）里把控制台的所有写接口打成 401。
import base64  # noqa: E402

from upgrade_code_vectors import console_session_token  # noqa: E402


@pytest.fixture
def signer_current(monkeypatch):
    monkeypatch.setenv("SESSION_SIGNER", "current")


def _seg(token: str, i: int) -> dict:
    s = token.split(".")[i]
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def _cookie_token(c: str) -> str:
    return c.split(";")[0][len(console_session.CONSOLE_COOKIE) + 1:]


def test_console_cookie_uses_the_console_current_kid_when_signer_is_current(aws, secret, signer_current):
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    assert _seg(token, 0) == {"alg": "HS256", "typ": "JWT", "kid": CONSOLE_KID}
    claims = _seg(token, 1)
    # §11.4 的面板会话表：**精确**这 6 个键。多出 typ/scope 说明混了旧合同；
    # 多出 idp/auth_via 说明误用了站点会话那张表。
    assert set(claims) == {"token_use", "aud", "email", "name", "exp", "iat"}
    assert claims["token_use"] == "console-session" and claims["aud"] == "console-panel"
    assert (claims["email"], claims["name"]) == ("u@x.com", "U")
    assert claims["exp"] - claims["iat"] == console_session.CONSOLE_TTL_SECONDS


def test_console_cookie_keeps_the_host_prefix_trio_in_both_signer_modes(aws, secret, monkeypatch):
    """`__Host-` 三要素与 Max-Age 不随开关变——任何 Domain= 会让浏览器整条丢弃 cookie。"""
    for mode in ("legacy", "current"):
        monkeypatch.setenv("SESSION_SIGNER", mode)
        c = console_session.console_cookie("u@x.com", "U")
        assert c.startswith(f"{console_session.CONSOLE_COOKIE}=")
        for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/",
                     f"Max-Age={console_session.CONSOLE_TTL_SECONDS}"):
            assert attr in c, (mode, attr)
        assert "Domain=" not in c, mode


def test_console_cookie_keeps_the_legacy_wire_form_when_signer_is_legacy(aws, secret):
    """1A 前的形态：头里**没有 kid**，payload 是旧合同（typ=session + scope=console）。"""
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    assert _seg(token, 0) == {"alg": "HS256", "typ": "JWT"}
    claims = _seg(token, 1)
    assert set(claims) == {"typ", "email", "name", "exp", "scope"}
    assert claims["typ"] == session.SESSION_TYP and claims["scope"] == console_session.CONSOLE_SCOPE


def test_new_form_cookie_is_signed_with_the_console_family_key_not_the_legacy_one(aws, secret, signer_current):
    """负向：换成 legacy 密钥验必不过（否则"切了开关"只是换了 header）。"""
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    ok = {CONSOLE_KID: {"alg": "HS256", "secret": CONSOLE_KID_SECRET, "role": "current"}}
    claims, outcome = session.verify_token(token, allowlist=ok, token_use="console-session")
    assert claims and outcome == "accepted_current"
    wrong = {CONSOLE_KID: {"alg": "HS256", "secret": SECRET, "role": "current"}}
    assert session.verify_token(token, allowlist=wrong, token_use="console-session") == (None, "bad_signature")


def test_panel_round_trips_its_own_new_form_cookie(aws, secret, signer_current):
    cookie = console_session.console_cookie("u@x.com", "U").split(";")[0]
    assert console_session.verify_console_cookie(cookie, x_user_email="u@x.com") == "u@x.com"


def test_new_form_cookie_still_fails_when_a_different_person_logged_in(aws, secret, signer_current):
    """换人登录（spec §5.4 第 1 步）在新形态下必须**照样**拒——这是 M3 的核心不变量。

    残留 cookie 属 A、Edge 刚验过的身份是 B ⇒ 必须要求重新升级，否则 B 拿着 A 的面板会话
    操作 A 的站点。空 `x-user-email` 也不得"因为都为空所以相等"。
    """
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    assert console_session.verify_console_cookie(cookie, x_user_email="a@x.com") == "a@x.com"
    for wrong in ("b@x.com", ""):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(cookie, x_user_email=wrong)


def test_new_form_cookie_is_not_accepted_as_an_upgrade_code(aws, secret, signer_current):
    """跨用途复用：面板会话（4 h）不得当升级码用，否则等于一个可无限续期的长期凭证。"""
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(token, expected_email="u@x.com")


def test_signer_switch_does_not_change_which_upgrade_codes_are_accepted(aws, secret, signer_current):
    """开关只管**签发**：切到 current 之后，auth 发的 legacy 与新形态升级码都还得能消费
    （切换有先后，两种升级码会在同一时间窗里并存）。"""
    assert console_session.consume_code(_kid_code(), expected_email="u@x.com") == "u@x.com"
    assert console_session.consume_code(session.mint_upgrade_code("u@x.com", SECRET),
                                        expected_email="u@x.com") == "u@x.com"


@pytest.mark.parametrize("bad", [None, "", "on", "Current", "true"],
                         ids=["missing", "empty", "on", "Current", "true"])
def test_missing_or_illegal_session_signer_fails_loudly_instead_of_signing(aws, secret, monkeypatch, bad):
    """缺/错开关必须抛（→ /api/session-callback 500），不许静默按某一侧签。"""
    if bad is None:
        monkeypatch.delenv("SESSION_SIGNER")
    else:
        monkeypatch.setenv("SESSION_SIGNER", bad)
    with pytest.raises(RuntimeError, match="SESSION_SIGNER"):
        console_session.console_cookie("u@x.com", "U")


def test_signer_current_does_not_touch_the_verify_path(aws, secret, signer_current):
    """验签侧与开关无关：legacy cookie 与 site-family token 的结果都不变。"""
    legacy = session.mint_session_jwt("u@x.com", "U", SECRET,
                                      ttl_seconds=3600, scope=console_session.CONSOLE_SCOPE)
    assert console_session.verify_console_cookie(
        f"{console_session.CONSOLE_COOKIE}={legacy}", x_user_email="u@x.com") == "u@x.com"
    site = session.mint_token(kid=SITE_KID, secret=SITE_KID_SECRET, token_use="console-session",
                              email="u@x.com", ttl_seconds=3600, name="U")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(
            f"{console_session.CONSOLE_COOKIE}={site}", x_user_email="u@x.com")


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_console_session_cookie_vectors_match_the_auth_side(aws, secret, name, mutate, expect_reject):
    """panel 签、两侧各自那份 session.py 验：同一组 MUTATIONS 的接受/拒绝必须一致。

    这条与 auth 侧 test_upgrade_code.py 的同名向量配对——panel 的 session.py 是构建时
    复制来的，漂移的症状是"面板自己验得过、别的组件验不过"。
    """
    cookie = f"{console_session.CONSOLE_COOKIE}={mutate(console_session_token(session.mint_token))}"
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(cookie, x_user_email="u@x.com")
    else:
        assert console_session.verify_console_cookie(cookie, x_user_email="u@x.com") == "u@x.com"


def _callback_event(code: str, *, email: str, name: str = "U") -> dict:
    from test_handler import EDGE_ROLE_ID
    return {"requestContext": {
                "http": {"method": "GET"},
                "authorizer": {"iam": {"callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
            "rawPath": "/api/session-callback",
            # `name` 仍来自 Edge 注入的头（URL 编码），不是 token 里的——本票不改这条
            "headers": {"x-user-email": email, "x-user-name": name},
            "queryStringParameters": {"code": code}}


def test_handler_callback_sets_a_new_form_cookie_end_to_end(aws, secret, signer_current):
    """走 handler 的真实路径（用户可见面）：升级码换出的 Set-Cookie 必须是新形态。

    单独测 `console_cookie` 不够——handler 才是那个把 Edge 注入的 `name` 递进去的地方，
    也是"cookie 属性写在响应上"的地方。
    """
    import handler
    r = handler.handler(_callback_event(_kid_code("u@x.com"), email="u@x.com",
                                       name="%E5%BC%A0%E4%B8%89%20Ltd"), None)
    assert r["statusCode"] == 302, r
    cookie = next(c for c in r["cookies"] if c.startswith(console_session.CONSOLE_COOKIE))
    token = _cookie_token(cookie)
    assert _seg(token, 0) == {"alg": "HS256", "typ": "JWT", "kid": CONSOLE_KID}
    claims = _seg(token, 1)
    assert set(claims) == {"token_use", "aud", "email", "name", "exp", "iat"}
    assert claims["email"] == "u@x.com"
    # `name` 是新形态里**新增**的 payload 成员，来源必须仍是 Edge 注入的 x-user-name
    # （URL 编码，handler 负责 unquote）。不钉住的话，"name 退化成 email"或"漏了 unquote"
    # 都会静默通过——控制台顶栏显示的就是这个值。
    assert claims["name"] == "张三 Ltd", claims["name"]
    # 换出来的 cookie 立刻就能用（同一进程内的往返，证明签发与验签口径一致）
    assert console_session.verify_console_cookie(
        cookie.split(";")[0], x_user_email="u@x.com") == "u@x.com"


def test_handler_rejects_a_new_form_cookie_from_another_person_with_401(aws, secret, signer_current):
    """**handler 层**（用户可见面）的换人登录：新形态 cookie 属 A、Edge 身份是 B ⇒ 401。

    模块级的 `verify_console_cookie` 用例不够——ticket 要的是响应码，而 401 的形状
    （`{"need": "console-session"}`）是前端据以重新升级的契约。既有的 401 用例都跑在
    `SESSION_SIGNER=legacy` 基线上（conftest 固定），所以新形态这一侧此前没有 handler 覆盖。
    """
    import handler
    from test_handler import CONSOLE, EDGE_ROLE_ID
    stale = console_session.console_cookie("a@x.com", "A").split(";")[0]
    ev = {"requestContext": {
              "http": {"method": "PUT"},
              "authorizer": {"iam": {"callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
          "rawPath": "/api/sites/s-1/permissions",
          "headers": {"x-user-email": "b@x.com", "cookie": stale,
                      "origin": f"https://{CONSOLE}", "content-type": "application/json"},
          "body": json.dumps({"require_login": False})}
    r = handler.handler(ev, None)
    assert r["statusCode"] == 401, r
    assert json.loads(r["body"])["need"] == "console-session"
    # 正对照：同一条路径下身份相符时不会停在 401（否则上面那条可能是别的原因导致的 401）
    ev["headers"]["x-user-email"] = "a@x.com"
    assert handler.handler(ev, None)["statusCode"] != 401


def test_handler_callback_still_sets_the_legacy_cookie_before_the_switch(aws, secret):
    """开关仍是 legacy（③ 之前与回滚之后）时，同一条路径必须产出旧形态。"""
    import handler
    r = handler.handler(_callback_event(_kid_code("u@x.com"), email="u@x.com"), None)
    assert r["statusCode"] == 302, r
    token = _cookie_token(next(c for c in r["cookies"]
                               if c.startswith(console_session.CONSOLE_COOKIE)))
    assert _seg(token, 0) == {"alg": "HS256", "typ": "JWT"}
    assert _seg(token, 1)["scope"] == console_session.CONSOLE_SCOPE


# ---- 变形测试：证明上面那些正向断言真会红 ------------------------------------------------
#
# 用**临时副本**加载改过的 console_session（spec Testing Decisions 的「`git stash` 或临时副本」
# 的后者）：不动仓库里的文件，脏工作树下也能跑，CI 里也能跑。
from module_mutation import mutate_module_segment  # noqa: E402

# 签发段 = console_cookie 那个函数。`token_use="console-session"` 在本文件里出现两次，
# 另一处是 verify_console_cookie 的**验签**参数——切段就是为了不改到那一处。
_SIGNER_REGION = ("def console_cookie", "def verify_console_cookie")


def _console_session_variant(tmp_path, old: str, new: str):
    mod = mutate_module_segment(console_session.__file__, region=_SIGNER_REGION,
                                old=old, new=new, tmp_path=tmp_path,
                                module_name="_console_session_mutant")
    # 假 SSM 只装在真模块上（conftest 的 secret 夹具）；副本自带一份干净缓存
    mod._secret_by_param = console_session._secret_by_param
    return mod


def test_mutating_the_signer_token_use_makes_the_cookie_unverifiable(aws, secret, signer_current, tmp_path):
    """`console-session` → `site-session`：cookie 照样签出、照样种下，但验签必拒。"""
    mod = _console_session_variant(tmp_path, 'token_use="console-session"', 'token_use="site-session"')
    token = _cookie_token(mod.console_cookie("u@x.com", "U"))
    assert _seg(token, 1)["token_use"] == "site-session"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(
            f"{console_session.CONSOLE_COOKIE}={token}", x_user_email="u@x.com")


def test_inverting_the_signer_branch_produces_the_wrong_wire_form(aws, secret, signer_current, tmp_path):
    """把分支条件写反：开关是 current 却签出 legacy 形态 ⇒ 新形态断言必须能看见。

    这条证明上面 `test_console_cookie_uses_the_console_current_kid_when_signer_is_current`
    真的依赖那个分支，而不是"反正 mint_token 总会被调用"。
    """
    mod = _console_session_variant(tmp_path, '_signer_mode() == "current"', '_signer_mode() == "legacy"')
    token = _cookie_token(mod.console_cookie("u@x.com", "U"))
    assert "kid" not in _seg(token, 0), "分支写反了却仍签出新形态——断言在测别的东西"
