"""站点会话 JWT（HS256）——纯标准库实现。
路由层 Edge 函数（infrastructure/lambda/origin_request.py）内嵌同一算法验签，
两处必须字节等价——改动此处务必同步那边。"""
import base64
import hashlib
import hmac
import json
import secrets
import time


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(msg: bytes, secret: str) -> str:
    return _b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())


SESSION_TYP = "session"


def mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400,
                     idp: str = "", scope: str = "", auth_via: str = "") -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    # 载荷里的 `typ` 与 JOSE 头里的 `typ: JWT` 是两回事：前者是**用途**标记，
    # 用来断开会话 token 与 console 一次性升级码之间的跨上下文复用
    # （两者同密钥、同线格式，见 verify_session_jwt）。
    claims = {"typ": SESSION_TYP, "email": email, "name": name,
              "exp": int(time.time()) + ttl_seconds}
    # （下面三个可选 claim）只在非空时写入：保持与一期已签发 token 的形态兼容，
    # Edge 侧无需改验签。**这句只管这三个**——上面的 typ 是无条件写入的，
    # 且 Edge 侧正要为它加检查（Task 8）。
    if idp:
        claims["idp"] = idp        # spec §3.5：Edge 据此确认身份来自企业 IdP
    if scope:
        claims["scope"] = scope    # M3 面板会话用（Edge 不校验 scope）
    if auth_via:
        claims["auth_via"] = auth_via   # spec §3.5：本次 token 的来源
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_session_jwt(token: str, secret: str, now: int | None = None, *,
                       expected_typ: str) -> dict | None:
    """→ claims 或 None。`expected_typ` 是**必填关键字参数**。

    为什么必填而不给默认值 `SESSION_TYP`：给默认值等于允许调用方忘记传，
    而"忘记传"恰好退化成本次修复之前的行为（不查 typ）——那时一个 60s 的
    console 升级码就是一个有效会话，且能在 `/console-session` 无限续期（M05）。

    **改这里必须同步 `router/infrastructure/lambda/origin_request.py` 的
    `_verify_session_jwt`**：两处算法必须字节等价。
    """
    # 必填只挡住"忘记传"，挡不住"显式传假值"：`claims.get("typ")` 对缺失
    # typ 的旧 token 返回 None，于是 expected_typ=None 会让下面的比较写成
    # `None != None` 为假、直接放行——正好退回修复前的行为。
    # 放在 try **之外**：这是对可信入参的前置条件检查，不是解析不可信输入；
    # 混进 try 会与下面的 `except Exception` 纠缠，让形态在克隆到 Edge 时走样。
    if not expected_typ or not isinstance(expected_typ, str):
        return None
    try:
        header_b64, payload_b64, sig = token.split(".")
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), secret)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        # typ 先查：这是"不能跨上下文复用"的唯一技术保证
        if claims.get("typ") != expected_typ:
            return None
        if int(claims.get("exp", 0)) <= (now if now is not None else int(time.time())):
            return None
        return claims
    except Exception:
        return None


# ---- console-session 的一次性 upgrade code（M3）----
#
# **单一实现**：panel 构建时复制本文件（同 common.py / permissions.py 模式），
# 不得在 panel 里手写第二份编解码。两侧测试跑同一组向量（
# panel/tests/upgrade_code_vectors.py）防复制品漂移——本文件与 Edge 的 HS256
# 就是靠这种同步测试盯住的。
#
# 与会话 JWT 的三个区别（都不是可选项）：
#   · typ="console-upgrade" —— 上下文标记。没有它，login state / PKCE cookie /
#     会话 JWT 可以跨上下文冒充（spec §5.4）。verify 端**先查 typ**。
#   · exp ≤ 60s —— code 只在 302 跳转的那一瞬间有效。**上限而非默认值**：
#     调用方传更大的值也会被压到 60，否则等于多出一个长期凭证。
#   · jti —— 由调用方原子消费一次（panel 对 session-codes 表条件写）。
#     签发端**不记状态**：谁消费谁负责；签发端记状态会变成第二个真源。
UPGRADE_TYP = "console-upgrade"
UPGRADE_MAX_TTL = 60


def mint_upgrade_code(email: str, secret: str,
                      ttl_seconds: int = UPGRADE_MAX_TTL) -> str:
    ttl = min(int(ttl_seconds), UPGRADE_MAX_TTL)
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                                separators=(",", ":")).encode())
    claims = {"typ": UPGRADE_TYP, "email": email,
              "jti": _b64url(secrets.token_bytes(16)),
              "exp": int(time.time()) + ttl}
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_upgrade_code(code: str, secret: str, now: int | None = None) -> dict | None:
    """→ claims 或 None。**任何异常都归为 None**（fail-closed）。

    返回 None 而不是抛异常：调用方是 Lambda handler，它要的是"拒绝"，
    抛异常会变成 500 + 堆栈。
    """
    try:
        header_b64, payload_b64, sig = code.split(".")
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), secret)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        # typ 必须先查：这是"不能跨上下文复用"的唯一技术保证
        if claims.get("typ") != UPGRADE_TYP:
            return None
        if not claims.get("email") or not claims.get("jti"):
            return None
        if int(claims.get("exp", 0)) <= (now if now is not None else int(time.time())):
            return None
        return claims
    except Exception:
        return None
