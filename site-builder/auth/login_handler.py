"""站点登录端点（Lambda Function URL）。
/login → Cognito Hosted UI（后接飞书 OIDC）；/callback → 验 state、验 id_token、
种顶域会话 cookie；/logout。
安全：state HMAC 签名 + 5 分钟过期（防 login CSRF/redirect 篡改）；
id_token 走 Cognito JWKS 验签 + iss/aud/exp/token_use 校验。"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request

import jwt as pyjwt
from jwt import PyJWKClient

from session import mint_session_jwt

_jwks_client = None  # 模块级缓存，Lambda 容器复用


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            f"https://cognito-idp.us-east-1.amazonaws.com/"
            f"{os.environ['USER_POOL_ID']}/.well-known/jwks.json")
    return _jwks_client


def _state_sig(body: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(
        os.environ["JWT_SECRET"].encode(), body.encode(),
        hashlib.sha256).digest()).rstrip(b"=").decode()


def _encode_state(redirect: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps(
        {"r": redirect, "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
    return f"{body}.{_state_sig(body)}"


def _decode_state(state: str) -> str | None:
    """验签 + 验期，失败返回 None。"""
    try:
        body, _, sig = state.rpartition(".")
        if not hmac.compare_digest(sig, _state_sig(body)):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return payload["r"]
    except Exception:
        return None


def _is_safe_redirect(url: str) -> bool:
    """回跳白名单：仅 https 且 host 属于 BASE_DOMAIN。

    反斜杠必须显式拒绝：Python urlparse 把 "https://evil.com\\.dsir.cc/" 的 host
    解析为 "evil.com\\.dsir.cc"（后缀匹配通过），而浏览器按 WHATWG 规范把 \\ 当
    /，实际导航到 evil.com——登录成功后会把已认证用户送到攻击者站点。
    """
    if not isinstance(url, str) or "\\" in url:
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return False
    host = parsed.hostname or ""
    base = os.environ["BASE_DOMAIN"]
    return host == base or host.endswith("." + base)


def _exchange_code(code: str) -> dict:
    """code → Cognito token → JWKS 验签 → {email, name}"""
    domain = os.environ["COGNITO_DOMAIN"]
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": os.environ["CLIENT_ID"],
        "redirect_uri": f"https://auth.{os.environ['BASE_DOMAIN']}/callback",
    }).encode()
    basic = base64.b64encode(
        f"{os.environ['CLIENT_ID']}:{os.environ['CLIENT_SECRET']}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token", data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        tokens = json.loads(resp.read())
    signing_key = _get_jwks_client().get_signing_key_from_jwt(tokens["id_token"])
    claims = pyjwt.decode(
        tokens["id_token"], signing_key.key, algorithms=["RS256"],
        audience=os.environ["CLIENT_ID"],
        issuer=f"https://cognito-idp.us-east-1.amazonaws.com/{os.environ['USER_POOL_ID']}")
    if claims.get("token_use") != "id":
        raise ValueError("token_use != id")
    return {"email": claims["email"], "name": claims.get("name", claims["email"])}


def handler(event, context):
    path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}
    base = os.environ["BASE_DOMAIN"]

    if path == "/login":
        redirect = qs.get("redirect", f"https://{base}/")
        if not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid redirect"}
        auth_url = (f"{os.environ['COGNITO_DOMAIN']}/oauth2/authorize?"
                    + urllib.parse.urlencode({
                        "response_type": "code", "client_id": os.environ["CLIENT_ID"],
                        "redirect_uri": f"https://auth.{base}/callback",
                        "scope": "openid email profile",
                        "state": _encode_state(redirect)}))
        return {"statusCode": 302, "headers": {"Location": auth_url}, "body": ""}

    if path == "/callback":
        redirect = _decode_state(qs.get("state", ""))
        if redirect is None or not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid or expired state"}
        user = _exchange_code(qs["code"])
        token = mint_session_jwt(user["email"], user["name"], os.environ["JWT_SECRET"])
        cookie = (f"sb_session={token}; Domain=.{base}; Path=/; Max-Age=86400; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 302, "headers": {"Location": redirect},
                "cookies": [cookie], "body": ""}

    if path == "/logout":
        cookie = (f"sb_session=; Domain=.{base}; Path=/; Max-Age=0; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 200, "cookies": [cookie],
                "headers": {"Content-Type": "text/html"},
                "body": "<h1>已退出登录</h1>"}

    return {"statusCode": 404, "body": "not found"}
