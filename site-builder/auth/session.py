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


# ---- 3c：kid allowlist 验签核心（spec §5 / §9 / §11.4；plan 3c-1A Task 2）----
#
# **每个 verifier 只认自己那份 allowlist**（kid -> {"alg", "secret", "role"}），Edge 内嵌
# 字节等价的副本（router/infrastructure/lambda/origin_request.py），改这里必须同步那边。
# 顺序按 spec §5：kid ∈ allowlist → alg 与绑定值精确一致 → 验签 → token_use → aud → exp
# → 身份字段。**先验签再信 payload。** `kid` 是攻击者控制的输入：只拿它查表，不拼资源。
#
# 3c-1A 里 `mint_token` 没有 handler 调用（tests/test_signer_untouched_in_1a.py 锁死），
# 它在这里是为了让测试与跨组件向量用**生产 mint**而不是测试专用副本；3c-1B 把 handler 切过来。
TOKEN_USES = {"site-session": "site-edge",
              "console-upgrade": "console-exchange",
              "console-session": "console-panel"}
OUTCOMES = ("accepted_current", "accepted_previous", "accepted_legacy",
            "unknown_kid", "alg_mismatch", "wrong_audience",
            "wrong_token_use", "bad_signature", "expired")
NAME_MAX = 256
SIGNING_INPUT_MAX = 4096      # spec §11.5：kms:Sign RAW 的上限，HS 阶段就按它守


def _strict_json(raw: bytes) -> dict:
    """拒绝重复键：Python 默认取最后一个，攻击者可放两个 kid 让不同实现看到不同值。"""
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d
    obj = json.loads(raw, object_pairs_hook=no_dupes)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def _aud_matches(got, want: str) -> bool:
    """字符串**精确相等**。数组形态的 aud 一律不匹配（RFC 7519 允许数组，本平台不允许）。
    单独成函数是为了让 tests 里的 meta 用例能证明"aud 数组被拒"钉在这一行。"""
    return isinstance(got, str) and got == want


def _has_kid(header: dict) -> bool:
    """legacy 入口的进入条件是 header **根本没有 kid 键**（状态机第 5 条）。
    不是"kid 不在 allowlist"——那样一个乱写的 kid 就能把验证降级到旧合同。
    单独成函数是给 meta 用例钉行用的（用例把它换成"kid 在 allowlist 里"的错误语义）。"""
    return "kid" in header


def mint_token(*, kid: str, secret: str, token_use: str, email: str,
               ttl_seconds: int, name: str = "", idp: str = "",
               auth_via: str = "", now: int | None = None) -> str:
    """claim 集合按 spec §11.4 的三类表；不写 typ（payload）与 scope。"""
    aud = TOKEN_USES[token_use]
    t = int(time.time()) if now is None else now
    claims = {"token_use": token_use, "aud": aud, "email": email,
              "exp": t + int(ttl_seconds), "iat": t}
    if token_use == "site-session":
        claims.update(name=name[:NAME_MAX], idp=idp, auth_via=auth_via)
    elif token_use == "console-upgrade":
        claims["jti"] = _b64url(secrets.token_bytes(16))
        claims["exp"] = t + min(int(ttl_seconds), UPGRADE_MAX_TTL)
    else:
        claims["name"] = name[:NAME_MAX]
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid},
                                separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    if len(signing_input) > SIGNING_INPUT_MAX:
        raise ValueError("signing input 超过 4096 字节，拒签")
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_token(token: str, *, allowlist: dict, token_use: str,
                 now: int | None = None) -> tuple[dict | None, str]:
    """→ (claims 或 None, outcome ∈ OUTCOMES)。任何异常都归为拒绝（fail-closed）。"""
    try:
        header_b64, payload_b64, sig = token.split(".")
        header = _strict_json(_b64url_decode(header_b64))
    except Exception:
        return None, "bad_signature"
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in allowlist:
        return None, "unknown_kid"
    entry = allowlist[kid]
    if header.get("alg") != entry["alg"]:
        return None, "alg_mismatch"
    try:
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), entry["secret"])
        if not hmac.compare_digest(sig, expected):
            return None, "bad_signature"
        claims = _strict_json(_b64url_decode(payload_b64))
    except Exception:
        return None, "bad_signature"
    if claims.get("token_use") != token_use:
        return None, "wrong_token_use"
    if not _aud_matches(claims.get("aud"), TOKEN_USES[token_use]):
        return None, "wrong_audience"
    t = int(time.time()) if now is None else now
    try:
        if int(claims.get("exp", 0)) <= t:
            return None, "expired"
    except Exception:
        return None, "bad_signature"
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        return None, "bad_signature"
    if token_use == "console-upgrade" and not claims.get("jti"):
        return None, "bad_signature"
    return claims, f"accepted_{entry['role']}"


def verify_with_legacy(token: str, *, allowlist: dict, token_use: str,
                       legacy_secret: str | None, now: int | None = None
                       ) -> tuple[dict | None, str]:
    """L1/L2 的「2 + 1」入口，handler 调的是它。

    header 有 kid（或 legacy 入口已删：legacy_secret=None）⇒ 走 verify_token，**不回落**；
    没有 kid ⇒ legacy 入口，按旧合同验：site = typ=session 且无 scope；console-session =
    typ=session + scope=console；upgrade = typ=console-upgrade + jti。
    旧合同的 typ 不符在 verify_session_jwt 内部归为 None，这里只能报 bad_signature；
    scope 规则不符能分辨，报 wrong_token_use。
    """
    try:
        header = _strict_json(_b64url_decode(token.split(".")[0]))
    except Exception:
        return None, "bad_signature"
    if _has_kid(header) or legacy_secret is None:
        return verify_token(token, allowlist=allowlist, token_use=token_use, now=now)
    if token_use == "console-upgrade":
        claims = verify_upgrade_code(token, legacy_secret, now)
        return (claims, "accepted_legacy") if claims else (None, "bad_signature")
    claims = verify_session_jwt(token, legacy_secret, now, expected_typ=SESSION_TYP)
    if not claims:
        return None, "bad_signature"
    if (token_use == "console-session") != (claims.get("scope") == "console"):
        return None, "wrong_token_use"
    return claims, "accepted_legacy"
