"""PKCE（S256）+ nonce：防授权码注入与 id_token 重放。"""
import base64
import hashlib
from unittest.mock import patch

import pytest

import login_handler as lh

ENV = {"JWT_SECRET": "s3cret",
       "COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test"}


def _event(path, qs=None, cookies=None):
    return {"rawPath": path, "queryStringParameters": qs or {},
            "cookies": cookies or [],
            "requestContext": {"http": {"method": "GET"}}}


def test_pkce_pair_challenge_is_s256_of_verifier():
    verifier, challenge = lh._pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


def test_pkce_verifier_length_within_rfc7636():
    verifier, _ = lh._pkce_pair()
    assert 43 <= len(verifier) <= 128


def test_pkce_pair_is_random():
    assert lh._pkce_pair()[0] != lh._pkce_pair()[0]


@patch.dict(lh.os.environ, ENV)
def test_login_includes_code_challenge_and_nonce():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    loc = r["headers"]["Location"]
    assert "code_challenge=" in loc
    assert "code_challenge_method=S256" in loc
    assert "nonce=" in loc


@patch.dict(lh.os.environ, ENV)
def test_state_carries_only_redirect():
    """verifier/nonce 绝不能进 state（会经 URL/Referer/日志/历史泄漏）。"""
    import base64 as b64mod
    import json as jsonmod
    state = lh._encode_state("https://app-x.example.com/")
    assert lh._decode_state(state) == "https://app-x.example.com/"
    body = state.rpartition(".")[0]
    payload = jsonmod.loads(b64mod.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert set(payload) == {"r", "exp"}


@patch.dict(lh.os.environ, ENV)
def test_tampered_state_rejected():
    state = lh._encode_state("https://app-x.example.com/")
    body, _, sig = state.rpartition(".")
    assert lh._decode_state(f"{body}x.{sig}") is None


@patch.dict(lh.os.environ, ENV)
def test_login_sets_host_only_pkce_cookie():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    cookie = next(c for c in r["cookies"] if c.startswith(lh.PKCE_COOKIE))
    assert "Domain=" not in cookie          # __Host- 要求无 Domain
    assert "Secure" in cookie and "HttpOnly" in cookie
    assert "Path=/" in cookie and "Max-Age=300" in cookie
    # authorize URL 里不得出现 verifier
    assert "code_challenge=" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_callback_takes_verifier_from_cookie():
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    state = [q.split("state=")[1] for q in [r_login["headers"]["Location"]]
             if "state=" in q][0]
    import urllib.parse as up
    state = up.unquote(state.split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A",
                                    "idp": "Feishu"}) as ex:
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce_cookie]), None)
    assert r["statusCode"] == 302
    # verifier 来自 cookie，不是 state
    args = ex.call_args[0]
    assert args[0] == "abc" and args[1] and args[2]


@patch.dict(lh.os.environ, ENV)
def test_callback_without_pkce_cookie_is_rejected():
    """cookie 丢失时必须让用户重登，不能静默降级成无 PKCE 交换。"""
    state = lh._encode_state("https://app-x.example.com/")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_forged_pkce_cookie():
    state = lh._encode_state("https://app-x.example.com/")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[f"{lh.PKCE_COOKIE}=forged.sig"]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_pkce_cookie_with_valid_sig_but_no_verifier_is_rejected():
    """state 与 pkce cookie 共用 _state_sig、线格式相同——一个合法 state 值就是
    "签名合法"的 pkce cookie。它解不出 v/n，若不拦就会带空 verifier 去换 token
    （静默降级成无 PKCE 交换，只剩 Cognito 兜着）。"""
    forged = lh._encode_state("https://app-x.example.com/")   # 合法签名，但没有 v/n
    assert lh._read_pkce_cookie({"cookies": [f"{lh.PKCE_COOKIE}={forged}"]}) is None
    r = lh.handler(_event("/callback", {"code": "abc", "state": forged},
                          cookies=[f"{lh.PKCE_COOKIE}={forged}"]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_pkce_cookie_with_non_ascii_does_not_crash():
    """cookie 值全由客户端控制：hmac.compare_digest 遇非 ASCII 会抛 TypeError。
    整段包 try 才能给出约定的 400，而不是 500 + 堆栈。"""
    state = lh._encode_state("https://app-x.example.com/")
    assert lh._read_pkce_cookie({"cookies": [f"{lh.PKCE_COOKIE}=YWJj.ü"]}) is None
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[f"{lh.PKCE_COOKIE}=YWJj.ü"]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_without_code_returns_400():
    """IdP 带 ?error=access_denied 回调时没有 code——不能让 KeyError 冒成 500。"""
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    r = lh.handler(_event("/callback", {"state": state, "error": "access_denied"},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_nonce_mismatch_returns_400_not_500():
    """nonce 不匹配（两个登录标签页并发时第二个覆盖了单一 cookie）是可预期的
    用户侧失败——_exchange_code 抛的 ValueError 必须被翻成 400。"""
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      side_effect=ValueError("id_token nonce 与本次登录不匹配")):
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_clears_pkce_cookie():
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A", "idp": "Okta"}):
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce_cookie]), None)
    assert any(c.startswith(lh.PKCE_COOKIE) and "Max-Age=0" in c
               for c in r["cookies"])


@patch.dict(lh.os.environ, ENV)
def test_callback_passes_idp_into_session():
    """idp 必须进会话 JWT，否则 Edge 的校验会把合法用户全拦住。"""
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A",
                                    "idp": "Feishu"}), \
         patch.object(lh, "mint_session_jwt", return_value="tok") as mint:
        lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce_cookie]), None)
    assert mint.call_args.kwargs.get("idp") == "Feishu"


@patch.dict(lh.os.environ, ENV)
def test_exchange_code_rejects_nonce_mismatch():
    """id_token 的 nonce 与 state 里的不一致 → 拒绝（防 id_token 重放）。"""
    fake_tokens = {"id_token": "header.payload.sig"}

    class _Key:
        key = "k"

    with patch.object(lh, "_post_token", return_value=fake_tokens), \
         patch.object(lh, "_get_jwks_client") as jwks, \
         patch.object(lh.pyjwt, "decode",
                      return_value={"token_use": "id", "email": "a@x.com",
                                    "nonce": "WRONG"}):
        jwks.return_value.get_signing_key_from_jwt.return_value = _Key()
        with pytest.raises(ValueError, match="nonce"):
            lh._exchange_code("code", "ver123", "expected-nonce")


@patch.dict(lh.os.environ, ENV)
def test_exchange_code_accepts_matching_nonce():
    fake_tokens = {"id_token": "header.payload.sig"}

    class _Key:
        key = "k"

    with patch.object(lh, "_post_token", return_value=fake_tokens), \
         patch.object(lh, "_get_jwks_client") as jwks, \
         patch.object(lh.pyjwt, "decode",
                      return_value={"token_use": "id", "email": "a@x.com",
                                    "name": "Alice", "nonce": "good-nonce"}):
        jwks.return_value.get_signing_key_from_jwt.return_value = _Key()
        out = lh._exchange_code("code", "ver123", "good-nonce")
    # idp/auth_via 由 pre-token 注入 id_token；此处 decode 被 patch 掉，
    # 未提供这两个 claim，故回落空串。
    assert out == {"email": "a@x.com", "name": "Alice", "idp": "", "auth_via": ""}


@patch.dict(lh.os.environ, ENV)
def test_exchange_code_returns_idp_and_auth_via():
    """两个 claim 都要透出来——mint_session_jwt 要把它们写进会话。"""
    class _Key:
        key = "k"

    with patch.object(lh, "_post_token", return_value={"id_token": "h.p.s"}), \
         patch.object(lh, "_get_jwks_client") as jwks, \
         patch.object(lh.pyjwt, "decode",
                      return_value={"token_use": "id", "email": "a@x.com",
                                    "name": "Alice", "nonce": "n",
                                    "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth"}):
        jwks.return_value.get_signing_key_from_jwt.return_value = _Key()
        out = lh._exchange_code("code", "v", "n")
    assert out["idp"] == "Feishu"
    assert out["auth_via"] == "TokenGeneration_HostedAuth"


@patch.dict(lh.os.environ, ENV)
def test_post_token_body_includes_code_verifier():
    captured = {}

    def _fake_urlopen(req, timeout=None):
        captured["body"] = req.data.decode()

        class _R:
            def read(self):
                return b'{"id_token":"x"}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return _R()

    with patch.object(lh.urllib.request, "urlopen", _fake_urlopen):
        lh._post_token("thecode", "theverifier")
    assert "code_verifier=theverifier" in captured["body"]
    assert "grant_type=authorization_code" in captured["body"]


# --- token 端点失败的分流（Codex review P2，已实测复现） ---
# 复现过的现象：_post_token 的 urlopen 对 4xx 抛 urllib.error.HTTPError，
# 而 HTTPError 不是 ValueError 的子类（URLError→OSError 那条谱系），
# callback 原先只 except ValueError，于是无效/过期/重放的 code 冒成 502。

def _login_state_and_cookie():
    import urllib.parse as up
    r_login = lh.handler(
        _event("/login", {"redirect": "https://app-x.example.com/"}), None)
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    return state, pkce


@patch.dict(lh.os.environ, ENV)
def test_callback_token_endpoint_4xx_returns_400_not_500():
    """无效/过期/重放的 code：Cognito 给 400，用户必须看到 400 而不是 502。

    **必须打 urlopen 而不是 _post_token**：4xx→400 的翻译就发生在 _post_token
    内部，打掉它等于跳过被测代码（本测试第一版正是这样写的，改对实现后仍红）。
    """
    import urllib.error
    state, pkce = _login_state_and_cookie()
    err = urllib.error.HTTPError("https://sso/oauth2/token", 400,
                                 "Bad Request", {}, None)
    with patch.object(lh.urllib.request, "urlopen", side_effect=err):
        r = lh.handler(_event("/callback", {"code": "replayed", "state": state},
                              cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_token_endpoint_5xx_still_raises():
    """上游故障必须保持 5xx——伪装成"请重新登录"会让真实故障不告警、无重试统计。"""
    import urllib.error
    state, pkce = _login_state_and_cookie()
    err = urllib.error.HTTPError("https://sso/oauth2/token", 503,
                                 "Service Unavailable", {}, None)
    with patch.object(lh.urllib.request, "urlopen", side_effect=err):
        with pytest.raises(urllib.error.HTTPError):
            lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce]), None)


@patch.dict(lh.os.environ, ENV)
def test_callback_upstream_timeout_still_raises():
    """超时不是用户错误：TimeoutError 必须冒成 5xx，不能被当成"请重新登录"。"""
    state, pkce = _login_state_and_cookie()
    with patch.object(lh.urllib.request, "urlopen", side_effect=TimeoutError()):
        with pytest.raises(TimeoutError):
            lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce]), None)


@patch.dict(lh.os.environ, ENV)
def test_callback_expired_id_token_returns_400_not_500():
    """pyjwt 的异常基类是 PyJWTError，**不继承 ValueError**——过期 id_token
    同样会冒成 500，所以 except 子句必须显式含 InvalidTokenError。"""
    import jwt as pyjwt
    state, pkce = _login_state_and_cookie()
    with patch.object(lh, "_exchange_code",
                      side_effect=pyjwt.ExpiredSignatureError("Signature has expired")):
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce]), None)
    assert r["statusCode"] == 400


# --- 登出必须结束 Cognito 托管登录会话（Codex review P2 / 继承风险） ---
# 只清本地 sb_session 时，Cognito 侧会话仍活着：共享设备上"退出"后再访问
# 任何站点会被静默自动重新登录。Cognito 的 /logout 不登出上游 IdP，
# 所以文案不能承诺"已完全退出"。

@patch.dict(lh.os.environ, ENV)
def test_logout_redirects_to_cognito_logout_and_clears_cookie():
    r = lh.handler(_event("/logout"), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith(ENV["COGNITO_DOMAIN"] + "/logout?")
    assert "client_id=cid" in loc
    # 平台会话必须同时被清掉（不能只依赖 Cognito 那一跳）
    assert any(c.startswith("sb_session=;") and "Max-Age=0" in c
               for c in r["cookies"])


@patch.dict(lh.os.environ, ENV)
def test_logout_uri_is_not_logout_itself():
    """logout_uri 指回 /logout 会被 Cognito 打回本分支 → 无限重定向。"""
    import urllib.parse as up
    r = lh.handler(_event("/logout"), None)
    qs = up.parse_qs(up.urlparse(r["headers"]["Location"]).query)
    logout_uri = qs["logout_uri"][0]
    assert logout_uri == f"https://auth.{ENV['BASE_DOMAIN']}/logged-out"
    assert not logout_uri.endswith("/logout")


@patch.dict(lh.os.environ, ENV)
def test_logged_out_page_does_not_claim_full_signout():
    """Cognito /logout 不登出上游 IdP——文案必须提示还需退出 IdP。"""
    r = lh.handler(_event("/logged-out"), None)
    assert r["statusCode"] == 200
    assert "已退出登录" in r["body"]
    assert "身份提供方" in r["body"]      # 明确告知效力边界
    assert any(c.startswith("sb_session=;") for c in r["cookies"])
