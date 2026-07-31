"""站点登录端点（Lambda Function URL）。
/login → Cognito Hosted UI（后接飞书 OIDC）；/callback → 验 state、验 PKCE、
验 id_token、种顶域会话 cookie；/logout。
安全：OAuth 授权码 + PKCE(S256) + nonce；state HMAC 签名 + 5 分钟过期
（防 login CSRF/redirect 篡改）；id_token 走 Cognito JWKS 验签 +
iss/aud/exp/token_use 校验，并核对 nonce（防 id_token 重放）。
**code_verifier 与 nonce 放 `__Host-sb_pkce` host-only cookie，不放 state**
——state 随 authorize URL 明文传输（只有签名、没有加密），把 verifier 放进去
既会经地址栏/Referer/IdP 日志/浏览器历史泄漏，也不再与浏览器绑定
（攻击者可把自带 verifier 的 callback URL 发给受害者做 login CSRF）。
见 _encode_state / _pkce_cookie 的 docstring 与 spec §7.2。"""
import base64
import hashlib
import hmac
import json
import os
import secrets
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


PKCE_COOKIE = "__Host-sb_pkce"


def _encode_state(redirect: str) -> str:
    """state 只放 redirect 与过期时间，**不放 code_verifier / nonce**。

    RFC 7636 的分工是授权请求只发 code_challenge、令牌请求才发 code_verifier。
    把明文 verifier 放进随 authorize URL 传输的 state（state 有 HMAC 签名，
    但内容是 base64 明文）会让它经浏览器地址栏、Referer、IdP 侧日志与浏览器
    历史各暴露一遍，PKCE 本应提供的"授权码被截获也换不到 token"的独立防护
    就没了；更要紧的是它不再绑定浏览器——攻击者把自己登录产生的 callback URL
    发给受害者，verifier 跟在 URL 里，后端就能替受害者完成交换并种下攻击者
    账户的会话（login CSRF / account confusion）。verifier 放 host-only
    cookie 才与浏览器绑定。见 spec §7.2。
    """
    body = base64.urlsafe_b64encode(json.dumps(
        {"r": redirect, "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
    return f"{body}.{_state_sig(body)}"


def _decode_state(state: str) -> str | None:
    """验签 + 验期，失败返回 None；成功返回 redirect。"""
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


def _pkce_cookie(verifier: str, nonce: str) -> str:
    """把 verifier/nonce 装进 auth 子域的 host-only 短期 cookie。

    __Host- 前缀是浏览器强制的：必须 Secure、必须 Path=/、**必须无 Domain**，
    因此它只回发给签发它的那台主机（/login 与 /callback 同在 auth.{base}，
    读得到）。5 分钟过期，用完即清。

    **不要给本函数加 base/domain 参数**：`__Host-` 前缀下任何 `Domain=` 都会让
    浏览器直接丢弃该 cookie，于是每次登录都走 callback 的 400 分支。
    `"t": "pkce"` 是类型标记——state 与本 cookie 共用 `_state_sig`，没有它
    一个合法 state 值就能充当"签名合法"的 pkce cookie（见 _read_pkce_cookie）。
    """
    payload = base64.urlsafe_b64encode(
        json.dumps({"t": "pkce", "v": verifier, "n": nonce}).encode()).decode().rstrip("=")
    sig = _state_sig(payload)
    return (f"{PKCE_COOKIE}={payload}.{sig}; Path=/; Max-Age=300; "
            f"Secure; HttpOnly; SameSite=Lax")


def _read_pkce_cookie(event) -> dict | None:
    """从 callback 请求里取回 verifier/nonce；验签失败、缺失或内容不完整返回 None。

    **整段包在 try 里**（不只包 json.loads）：`hmac.compare_digest` 对含非 ASCII
    的字符串会抛 `TypeError`，而 cookie 值完全由客户端控制——只包 json.loads
    时一个 `__Host-sb_pkce=YWJj.ü` 就能让 handler 抛出 500 + 堆栈，而不是约定的
    400。`_decode_state` 本来就是整段包的，这里必须一致。

    **v/n 必须非空**：`_state_sig` 同时给 state 与本 cookie 签名、且线格式相同，
    所以一个合法 state 值就是一个"签名合法"的 pkce cookie——它解出来
    `{"v": "", "n": ""}`，若不检查就会带着空 verifier 去 `_post_token`，
    正是"静默降级成无 PKCE 交换"（现在只靠 Cognito 拒空 verifier 兜着，
    不是本地约束）。同时给 payload 打类型标记，彻底断开两种上下文的签名复用。
    """
    for raw in (event.get("cookies") or []):
        name, _, value = raw.partition("=")
        if name.strip() != PKCE_COOKIE:
            continue
        try:
            body, _, sig = value.rpartition(".")
            if not hmac.compare_digest(sig, _state_sig(body)):
                return None
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if data.get("t") != "pkce":      # state 值不能当 pkce cookie 用
                return None
            verifier, nonce = data.get("v", ""), data.get("n", "")
            if not verifier or not nonce:
                return None
            return {"v": verifier, "n": nonce}
        except Exception:
            return None
    return None


def _pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256：返回 (code_verifier, code_challenge)。"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _is_safe_redirect(url: str) -> bool:
    """回跳白名单：仅 https 且 host 属于 BASE_DOMAIN。

    反斜杠必须显式拒绝：Python urlparse 把 "https://evil.com\\.example.com/" 的 host
    解析为 "evil.com\\.example.com"（后缀匹配通过），而浏览器按 WHATWG 规范把 \\ 当
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


def _post_token(code: str, verifier: str) -> dict:
    domain = os.environ["COGNITO_DOMAIN"]
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": os.environ["CLIENT_ID"],
        "redirect_uri": f"https://auth.{os.environ['BASE_DOMAIN']}/callback",
        "code_verifier": verifier,
    }).encode()
    basic = base64.b64encode(
        f"{os.environ['CLIENT_ID']}:{os.environ['CLIENT_SECRET']}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token", data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _exchange_code(code: str, verifier: str, nonce: str) -> dict:
    """code → Cognito token → JWKS 验签 + nonce 校验 → {email, name}"""
    tokens = _post_token(code, verifier)
    signing_key = _get_jwks_client().get_signing_key_from_jwt(tokens["id_token"])
    claims = pyjwt.decode(
        tokens["id_token"], signing_key.key, algorithms=["RS256"],
        audience=os.environ["CLIENT_ID"],
        issuer=f"https://cognito-idp.us-east-1.amazonaws.com/{os.environ['USER_POOL_ID']}")
    if claims.get("token_use") != "id":
        raise ValueError("token_use != id")
    # nonce 绑定本次 /login：缺失或不匹配都拒绝，防他人的 id_token 被重放进
    # 这个 callback（PKCE 保护授权码，nonce 保护 id_token）。
    if claims.get("nonce") != nonce:
        raise ValueError("id_token nonce 与本次登录不匹配")
    # idp 由 pre-token 触发器注入 id token（两个容器都写，见 Task 14 Step 4b）。
    # 本地用户没有它——会话里就不会有，Edge 据此拦截（spec §3.5）。
    return {"email": claims["email"], "name": claims.get("name", claims["email"]),
            "idp": claims.get("idp", ""),
            "auth_via": claims.get("auth_via", "")}


def handler(event, context):
    path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}
    base = os.environ["BASE_DOMAIN"]

    if path == "/login":
        redirect = qs.get("redirect", f"https://{base}/")
        if not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid redirect"}
        verifier, challenge = _pkce_pair()
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
        auth_url = (f"{os.environ['COGNITO_DOMAIN']}/oauth2/authorize?"
                    + urllib.parse.urlencode({
                        "response_type": "code", "client_id": os.environ["CLIENT_ID"],
                        "redirect_uri": f"https://auth.{base}/callback",
                        "scope": "openid email profile",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "nonce": nonce,
                        "state": _encode_state(redirect)}))
        # verifier/nonce 走 host-only cookie（与浏览器绑定），不进 URL
        return {"statusCode": 302, "headers": {"Location": auth_url},
                "cookies": [_pkce_cookie(verifier, nonce)], "body": ""}

    if path == "/callback":
        redirect = _decode_state(qs.get("state", ""))
        if redirect is None or not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid or expired state"}
        pkce = _read_pkce_cookie(event)
        if pkce is None:
            # cookie 丢失/被篡改/内容不完整（换了浏览器、被清、超过 5 分钟、
            # 或拿 state 值来冒充）——比静默降级到无 PKCE 安全：重走一次登录。
            return {"statusCode": 400,
                    "body": "登录状态已过期，请重新登录"}
        # IdP 也可能带着 ?error=access_denied 回调（没有 code），或 code 被重放、
        # nonce 不匹配（两个登录标签页并发时第二个会覆盖单一 cookie）。
        # 这些都是可预期的用户侧失败，必须给 400 而不是让异常冒成 500 +堆栈。
        code = qs.get("code", "")
        if not code:
            return {"statusCode": 400,
                    "body": "授权失败或被取消，请重新登录"}
        try:
            user = _exchange_code(code, pkce["v"], pkce["n"])
        except ValueError:
            return {"statusCode": 400, "body": "登录校验失败，请重新登录"}
        token = mint_session_jwt(user["email"], user["name"],
                                 os.environ["JWT_SECRET"], idp=user.get("idp", ""),
                                 auth_via=user.get("auth_via", ""))
        cookie = (f"sb_session={token}; Domain=.{base}; Path=/; Max-Age=86400; "
                  f"Secure; HttpOnly; SameSite=Lax")
        clear_pkce = f"{PKCE_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        return {"statusCode": 302, "headers": {"Location": redirect},
                "cookies": [cookie, clear_pkce], "body": ""}

    if path == "/logout":
        cookie = (f"sb_session=; Domain=.{base}; Path=/; Max-Age=0; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 200, "cookies": [cookie],
                "headers": {"Content-Type": "text/html"},
                "body": "<h1>已退出登录</h1>"}

    return {"statusCode": 404, "body": "not found"}
