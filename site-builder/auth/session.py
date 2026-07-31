"""站点会话 JWT（HS256）——纯标准库实现。
路由层 Edge 函数（infrastructure/lambda/origin_request.py）内嵌同一算法验签，
两处必须字节等价——改动此处务必同步那边。"""
import base64
import hashlib
import hmac
import json
import time


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(msg: bytes, secret: str) -> str:
    return _b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())


def mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400,
                     idp: str = "", scope: str = "", auth_via: str = "") -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"email": email, "name": name, "exp": int(time.time()) + ttl_seconds}
    # 只在非空时写入：保持与一期已签发 token 的形态兼容，Edge 侧无需改验签。
    if idp:
        claims["idp"] = idp        # spec §3.5：Edge 据此确认身份来自企业 IdP
    if scope:
        claims["scope"] = scope    # M3 面板会话用（Edge 不校验 scope）
    if auth_via:
        claims["auth_via"] = auth_via   # spec §3.5：本次 token 的来源
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_session_jwt(token: str, secret: str, now: int | None = None) -> dict | None:
    try:
        header_b64, payload_b64, sig = token.split(".")
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), secret)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if int(claims.get("exp", 0)) <= (now if now is not None else int(time.time())):
            return None
        return claims
    except Exception:
        return None
