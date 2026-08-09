"""panel 侧：验 code、jti 原子消费、cookie 形态、cookie↔header 一致性。"""
import boto3
import pytest

import console_session
import session
from upgrade_code_vectors import MUTATIONS, SECRET


def test_code_is_single_use(aws, secret):
    code = session.mint_upgrade_code("u@x.com", SECRET)
    assert console_session.consume_code(code) == "u@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code)      # 重放


def test_replay_is_rejected_by_conditional_write_not_by_a_read_check(aws, secret):
    """并发重放：两个请求同时用同一 code，只有一个能成。

    条件写（attribute_not_exists(jti)）才有这个性质；"先 get 再 put"的写法
    在并发下两边都会看到"没用过"。
    """
    code = session.mint_upgrade_code("u@x.com", SECRET)
    ok = 0
    for _ in range(2):
        try:
            console_session.consume_code(code)
            ok += 1
        except console_session.UpgradeRejected:
            pass
    assert ok == 1


def test_consumed_jti_row_has_ttl(aws, secret):
    """session-codes 是一次性标记——必须带 TTL，否则表无限增长。"""
    console_session.consume_code(session.mint_upgrade_code("u@x.com", SECRET))
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert len(items) == 1 and int(items[0]["expires_at"]) > 0


def test_expired_code_is_rejected_before_being_consumed(aws, secret):
    """过期 code 不得占用 jti 行——否则攻击者能用过期 code 污染表。"""
    import time
    code = session.mint_upgrade_code("u@x.com", SECRET, ttl_seconds=1)
    time.sleep(1.1)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code)
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == []


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_same_vectors_as_auth_side(aws, secret, name, mutate, expect_reject):
    code = mutate(session.mint_upgrade_code("u@x.com", SECRET))
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code)
    else:
        assert console_session.consume_code(code) == "u@x.com"


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
