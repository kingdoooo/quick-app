import json
from unittest.mock import patch
import login_handler as lh

ENV = {"JWT_SECRET": "s3cret", "COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test"}


def _event(path, qs=None, cookies=None):
    return {"rawPath": path, "queryStringParameters": qs or {},
            "cookies": cookies or [], "requestContext": {"http": {"method": "GET"}}}


@patch.dict(lh.os.environ, ENV)
def test_login_redirects_to_hosted_ui():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith(ENV["COGNITO_DOMAIN"] + "/oauth2/authorize")
    assert "client_id=cid" in loc and "state=" in loc


@patch.dict(lh.os.environ, ENV)
def test_login_rejects_foreign_redirect():
    r = lh.handler(_event("/login", {"redirect": "https://evil.com/"}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
@patch.object(lh, "_exchange_code", return_value={"email": "a@x.com", "name": "Alice",
                                                  "idp": "Feishu"})
def test_callback_sets_cookie_and_redirects(mock_ex):
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/page?tab=2"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "https://app-x.example.com/page?tab=2"
    cookie = next(c for c in r["cookies"] if c.startswith("sb_session="))
    assert "Domain=.example.com" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_tampered_state():
    state = lh._encode_state("https://app-x.example.com/")
    body, _, sig = state.rpartition(".")
    import base64, json as _json
    payload = _json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["r"] = "https://evil.com/"
    forged = base64.urlsafe_b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
    # 补一个有效的 PKCE cookie：确保 400 是 state 验签失败导致的，而非缺 cookie
    pkce = lh._pkce_cookie("v", "n").split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": f"{forged}.{sig}"},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_expired_state():
    import time
    with patch.object(lh.time, "time", return_value=time.time() - 600):
        state = lh._encode_state("https://app-x.example.com/")
    # 同上：补有效 cookie，锁定 400 的原因是 state 过期
    pkce = lh._pkce_cookie("v", "n").split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_logout_clears_cookie():
    r = lh.handler(_event("/logout"), None)
    assert any("Max-Age=0" in c for c in r["cookies"])


# ---- M3: /console-session（面板会话升级入口）----

@patch.dict(lh.os.environ, ENV)
def test_console_session_issues_code_and_redirects_to_console():
    """有效顶域会话 → 302 带 code 到 console callback。"""
    import session
    token = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session",
                          cookies=[f"sb_session={token}"]), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith("https://console.example.com/api/session-callback?code=")
    import urllib.parse
    code = urllib.parse.unquote(loc.split("code=", 1)[1])
    claims = session.verify_upgrade_code(code, ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_without_session_goes_to_login_with_redirect_back():
    r = lh.handler(_event("/console-session"), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith("https://auth.example.com/login?redirect=")
    # 登录完必须回到 /console-session：指回 console 首页的话，用户登录后
    # 仍然没有面板会话，面板还是 401（死循环的用户体验）
    assert "console-session" in loc


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_tampered_session_cookie():
    """签名不过的 sb_session 不得换出 code（否则等于伪造任意身份）。"""
    import session
    bad = session.mint_session_jwt("u@x.com", "U", "wrong-secret")
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={bad}"]), None)
    assert r["statusCode"] == 302
    assert "/login" in r["headers"]["Location"], "篡改的会话竟然换出了 code"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_expired_session_cookie():
    import session
    old = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"],
                                   ttl_seconds=-10)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={old}"]), None)
    assert "/login" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_console_session_does_not_set_cookies_or_body():
    """code 只出现在 Location，不进 Set-Cookie / body（缩小泄漏面）。"""
    import session
    token = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session",
                          cookies=[f"sb_session={token}"]), None)
    assert not r.get("cookies"), "升级码流程不该设任何 cookie"
    assert not r.get("body")
    assert r["headers"].get("cache-control") == "no-store"


@patch.dict(lh.os.environ, ENV)
def test_console_session_login_redirect_passes_its_own_safety_check():
    """构造出的 redirect 必须能通过 _is_safe_redirect，否则用户拿到 400。"""
    r = lh.handler(_event("/console-session"), None)
    import urllib.parse
    target = urllib.parse.unquote(
        r["headers"]["Location"].split("redirect=", 1)[1])
    assert lh._is_safe_redirect(target), f"{target} 会被 /login 判为非法"


@patch.dict(lh.os.environ, ENV)
def test_console_session_refuses_an_upgrade_code_as_the_cookie():
    """把升级码当 sb_session 递进 /console-session 不得换出新码。

    这是链式续期的修复点（M05）：`/console-session` 用的就是通用 verifier，
    不查 typ 时递一个升级码进去即可换出**新的** 60s 升级码，无限续期
    ——「60 秒 + 一次性」两个属性同时失效。已实测连续续期成功 3 轮。

    注意这一半**与 `require_idp_claim` 无关**：`auth` 子域注册为
    `require_auth=False`，Edge 根本不 gate 这个端点，是 auth 服务自己验 cookie。

    密钥必须用 ENV["JWT_SECRET"]：换个密钥的话签名检查就先拦下了，
    这条用例即便在缺陷仍在时也会绿——那是假绿，证明不了 typ 检查生效。
    """
    import session
    code = session.mint_upgrade_code("v@example.test", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={code}"]), None)
    assert r["statusCode"] == 302
    assert "/login?redirect=" in r["headers"]["Location"], (
        "应被当成无有效会话、引导去登录，而不是换出新的升级码")


# ---- M06 的 auth 侧一半：同名 sb_session 遮蔽（/console-session）----
#
# Edge 的 `_get_cookies` 逐个验，但 `auth` 子域注册为 `require_auth=False`，
# Edge 根本不 gate `/console-session`——那一侧的修复覆盖不到这里。
# 缺陷形态：站点 JS 写 `sb_session=garbage; domain=.{base}; path=/console-session`
# 新建第二条 cookie（HttpOnly 只护住同 path 的那条），RFC 6265 §5.4.2 让它先发。
# 只取第一条 ⇒ 控制台写操作持久 302 登录循环（重新登录只重写 Path=/ 那条）。

SHADOW = "garbage.garbage.garbage"


def _console_session(cookies):
    return lh.handler(_event("/console-session", cookies=cookies), None)


def _issued_code(r) -> str:
    """→ Location 里的升级码；不是"换出了 code"的响应则返回 ""。"""
    loc = r["headers"]["Location"]
    if "/api/session-callback?code=" not in loc:
        return ""
    import urllib.parse
    return urllib.parse.unquote(loc.split("code=", 1)[1])


@patch.dict(lh.os.environ, ENV)
def test_console_session_survives_a_shadowing_cookie_sent_first():
    """垃圾值排在合法会话**之前**时仍须换出 code（M06 回归）。

    这是本用例组的核心：修复前 handler 取到第一条就 break，于是 302 去登录，
    而登录回调只重写 `Path=/` 的那条 ⇒ 回到本入口继续失败，死循环。
    """
    import session
    good = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={SHADOW}", f"sb_session={good}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com", (
        "遮蔽 cookie 排在前面就换不出 code —— 控制台写操作会陷入登录循环")


@patch.dict(lh.os.environ, ENV)
def test_console_session_still_works_when_shadow_is_sent_last():
    """正序（合法在前）的正对照：证明上一条不是靠"顺序反了"才绿的。"""
    import session
    good = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={good}", f"sb_session={SHADOW}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_when_every_candidate_is_invalid():
    """负对照：逐个验不等于放宽——全部无效时仍须去登录。

    没有这一条，"把所有候选都当通过"的实现也会让上面两条绿。
    """
    import session
    wrong_secret = session.mint_session_jwt("u@x.com", "U", "wrong-secret")
    r = _console_session([f"sb_session={SHADOW}",
                          f"sb_session={wrong_secret}",
                          "sb_session="])
    assert r["statusCode"] == 302
    assert "/login?redirect=" in r["headers"]["Location"]
    assert not _issued_code(r)


@patch.dict(lh.os.environ, ENV)
def test_console_session_shadowed_by_an_upgrade_code_picks_the_real_session():
    """M05 + M06 合起来：遮蔽项是**验签通过的升级码**时，胜出者必须是真会话。

    升级码与会话用同一密钥、同一线格式，所以它是"签名合法但 typ 不对"的候选。
    逐个验的判据若写成"第一个验签通过的"（漏了 typ），这里会拿升级码的身份
    换出新码 —— 正是 M05 那条无限续期。
    """
    import session
    good = session.mint_session_jwt("owner@x.com", "O", ENV["JWT_SECRET"])
    code = session.mint_upgrade_code("attacker@x.com", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={code}", f"sb_session={good}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "owner@x.com", (
        "升级码被当成会话了 —— typ 检查没生效")


@patch.dict(lh.os.environ, ENV)
def test_session_cookie_candidates_returns_every_same_name_value():
    """机制层断言：helper 必须返回**全部**同名值，且保持 header 顺序。

    调用方的正确性依赖"拿到的是全集"；只断言端点行为的话，一个"取最后一条"
    的实现也能让上面几条绿，而按位置挑仍然是把缺陷换个方向。
    """
    ev = _event("/console-session",
                cookies=[f"sb_session={SHADOW}", "other=x",
                         "sb_session=second", " sb_session=third"])
    assert lh._session_cookie_candidates(ev) == [SHADOW, "second", "third"]
    assert lh._session_cookie_candidates(_event("/console-session")) == []
