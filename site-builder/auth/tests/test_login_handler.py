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
