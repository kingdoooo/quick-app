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
