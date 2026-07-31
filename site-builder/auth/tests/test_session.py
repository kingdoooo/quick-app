import time
import session
from session import mint_session_jwt, verify_session_jwt

SECRET = "test-secret-0123456789abcdef"


def test_roundtrip():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    claims = verify_session_jwt(tok, SECRET)
    assert claims["email"] == "a@x.com" and claims["name"] == "Alice"


def test_wrong_secret_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    assert verify_session_jwt(tok, "other-secret") is None


def test_expired_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET, ttl_seconds=10)
    assert verify_session_jwt(tok, SECRET, now=int(time.time()) + 11) is None


def test_tampered_payload_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    h, p, s = tok.split(".")
    assert verify_session_jwt(f"{h}.{p}x.{s}", SECRET) is None


def test_garbage_rejected():
    assert verify_session_jwt("not-a-jwt", SECRET) is None
    assert verify_session_jwt("", SECRET) is None


def test_mint_includes_idp_when_given():
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret", idp="Feishu")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert payload["idp"] == "Feishu"
    assert payload["email"] == "a@x.com"


def test_mint_omits_idp_when_empty():
    """空值不写入：保持与一期 token 的字节形态兼容。"""
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert "idp" not in payload
    assert "scope" not in payload


def test_mint_includes_scope_for_console_session():
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret",
                                   ttl_seconds=14400, scope="console")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert payload["scope"] == "console"


def test_verify_still_accepts_token_with_extra_claims():
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret", idp="Okta")
    claims = session.verify_session_jwt(tok, "s3cret")
    assert claims["idp"] == "Okta"
