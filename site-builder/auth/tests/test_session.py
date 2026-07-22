import time
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
