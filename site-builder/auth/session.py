"""平台 token 的 JOSE 合同（RS256，3c-final）。

**签发**由调用方注入 `sign(signing_input: bytes) -> bytes`（生产：`session_kms.KmsSigner`，
测试与夹具单测：`local_signer(private_key)`）；**验签**在本模块用 `cryptography` 本地完成。
Edge（router/infrastructure/lambda/origin_request.py）内嵌一份**字节等价**的验签核心
（`_b64url_decode_strict` / `_strict_json` / `load_public_key_der` / `_rsa_verify` / `verify_token` 的判定段），
改这里必须同步那边（CLAUDE.md 不变量；router 的 test_edge_kid_allowlist.py 逐段比对）。
panel 构建时复制本文件（deploy_panel.COPY_FILES）。

顺序按 spec §5：kid ∈ allowlist → alg 与绑定值精确一致 → 验签 → token_use → aud → exp → 身份字段。
**先验签再信 payload。** `kid` 是攻击者控制的输入：只拿它查表，不拼资源。

JOSE 层（spec §5，与用哪个 RSA 实现无关，一律必须）：base64url 规范形式（拒 `=`、拒标准字母表、
拒非规范尾比特）；拒 `crit` 头；`alg` 只与 allowlist 比对、不用来分派实现；签名长度**严格等于**模长；
公钥侧 SPKI 必须是 rsaEncryption、DER 最小形式、模长 ∈ {2048, 3072, 4096}、指数 65537。
RSA 原语层交给 cryptography（ADR 0003）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALG = "RS256"
TOKEN_USES = {"site-session": "site-edge",
              "console-upgrade": "console-exchange",
              "console-session": "console-panel"}
OUTCOMES = ("accepted_current", "accepted_previous",
            "unknown_kid", "alg_mismatch", "wrong_audience",
            "wrong_token_use", "bad_signature", "expired")
NAME_MAX = 256
SIGNING_INPUT_MAX = 4096      # spec §11.5：kms:Sign RAW 的 Message 上限；超过在调 sign 之前拒
UPGRADE_MAX_TTL = 60          # 升级码只在 302 跳转那一瞬间有效：上限，不是默认值
RSA_MODULUS_BITS = (2048, 3072, 4096)
RSA_PUBLIC_EXPONENT = 65537

# 夹具身份（spec §11.7 / ADR 0002）。**授权边界要进 git review，所以是常量不是配置。**
# Edge 内嵌同一组字面量（它拿不到本模块；router 单测钉住等值），panel 经 COPY_FILES 拿到本文件，
# deployer/functions/permissions.py 另有一份 FIXTURE_DOMAIN（auth 单测钉住等值）。
FIXTURE_DOMAIN = "e2e.invalid"
FIXTURE_IDP = "fixture"
FIXTURE_AUTH_VIA = "fixture-issuer"
FIXTURE_MAX_TTL = 1800

_PAD = padding.PKCS1v15()
_HASH = hashes.SHA256()
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode_strict(s: str) -> bytes:
    """规范 base64url：字母表只许 A-Za-z0-9-_（拒 `=` 填充与标准字母表的 + /），且重编码必须逐字符
    相等（拒非规范尾比特——同一串字节的第二种编码是"同一签名两种写法"的入口）。"""
    if not isinstance(s, str) or not _B64URL_RE.fullmatch(s):
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64url(raw) != s:
        raise ValueError("non-canonical base64url")
    return raw


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


def spki_sha256(der: bytes) -> str:
    """`[SessionKey:<kid>] spki_sha256` 的定义：SHA-256(DER SPKI) 的 64 位 hex。"""
    return hashlib.sha256(der).hexdigest()


def load_public_key_der(der: bytes):
    """DER SPKI → RSAPublicKey，公钥侧四项（spec §5）：rsaEncryption、指数 65537、模长 ∈ RSA_MODULUS_BITS、
    DER 最小形式（重新序列化逐字节相等）。任一不符抛 ValueError；调用方（部署脚本 / verifier 冷启动）
    把它当硬失败，不回落。"""
    key = serialization.load_der_public_key(der)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("SPKI 不是 rsaEncryption")
    if key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("RSA 公钥指数不是 65537")
    if key.key_size not in RSA_MODULUS_BITS:
        raise ValueError(f"RSA 模长 {key.key_size} 不在 {RSA_MODULUS_BITS}")
    canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if canonical != der:
        raise ValueError("SPKI DER 不是最小形式")
    return key


def _rsa_verify(public_key, signing_input: bytes, sig: bytes) -> bool:
    """签名长度必须**严格等于**模长（spec §5）——不许交给 RSA 层去"补零"；其余交给 PKCS1 v1.5 验签。"""
    if len(sig) != public_key.key_size // 8:
        return False
    try:
        public_key.verify(sig, signing_input, _PAD, _HASH)
        return True
    except InvalidSignature:
        return False


def local_signer(private_key):
    """测试 / 夹具单测用的 `sign`：本地私钥 PKCS1 v1.5 + SHA-256。生产 signer 是 session_kms.KmsSigner，
    两者对同一 signing input 产出**同一个**签名（PKCS1 v1.5 是确定性签名，spec §11.5）。"""
    return lambda signing_input: private_key.sign(signing_input, _PAD, _HASH)


def _aud_matches(got, want: str) -> bool:
    """字符串**精确相等**。数组形态的 aud 一律不匹配（RFC 7519 允许数组，本平台不允许）。"""
    return isinstance(got, str) and got == want


def mint_token(*, kid: str, sign, token_use: str, email: str,
               ttl_seconds: int, name: str = "", idp: str = "",
               auth_via: str = "", now: int | None = None) -> str:
    """claim 集合按 spec §11.4 的三类表；header 是 {alg, typ, kid}；不写 typ（payload）与 scope。

    `sign(signing_input: bytes) -> bytes` 返回**原始签名字节**（KMS `Sign` 响应的 `Signature`，或本地私钥），
    本函数负责 base64url。signing input 超过 4096 字节在调 `sign` **之前**拒（spec §11.5）。"""
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
    header = _b64url(json.dumps({"alg": ALG, "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    if len(signing_input) > SIGNING_INPUT_MAX:
        raise ValueError("signing input 超过 4096 字节，拒签")
    return f"{header}.{payload}.{_b64url(sign(signing_input))}"


def verify_token(token: str, *, allowlist: dict, token_use: str,
                 now: int | None = None) -> tuple[dict | None, str]:
    """→ (claims 或 None, outcome ∈ OUTCOMES)。任何异常都归为拒绝（fail-closed）。

    allowlist: kid -> {"alg": "RS256", "public_key": RSAPublicKey, "role": "current" | "previous"}。
    **下面从 `try` 到 `return claims` 这一段与 Edge 的 `_verify_site_session` 字节等价**（router 单测逐段比对）。"""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = _strict_json(_b64url_decode_strict(header_b64))
    except Exception:
        return None, "bad_signature"
    if "crit" in header:                      # RFC 7515 §4.1.11：本平台不认任何 critical 扩展
        return None, "bad_signature"
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in allowlist:
        return None, "unknown_kid"
    entry = allowlist[kid]
    if header.get("alg") != entry["alg"]:
        return None, "alg_mismatch"
    try:
        sig = _b64url_decode_strict(sig_b64)
        if not _rsa_verify(entry["public_key"], f"{header_b64}.{payload_b64}".encode(), sig):
            return None, "bad_signature"
        claims = _strict_json(_b64url_decode_strict(payload_b64))
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


# 黄金三元组（spec §11.5）：一次性本地私钥签出的 (SPKI, signing input, signature)。**公钥与签名都不是秘密。**
# 用途：① Edge 在 import 期用它做一次预热验签（spec §11.1 的冷启动判据建立在"库初始化 + 首次验签发生在
# Init 阶段"上）；② 三处 verifier 的单测用同一组字节证明 RSA 层一致。**不要用它签任何 token**：私钥已丢弃。
# 生成方式见 docs/superpowers/plans/2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover.md Task 1 Step 6。
RS256_GOLDEN = {
    "spki_b64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx2eNvs12AANfSjqTYb85HR0pX6TUwA5kQpmCWGDJwEOl1ckHHzAHdWPDBNCHwaiZyC7fnvzqy3a41abvxvX5gzLZdfdRYkGJNx05/T3u6t5d2F87TtYIIvRkpJKEFKWlkrfIk00iOV/fjF04CFy0j6GXIHEKJ3Yg6SYFreqdCwg4Uh1xLKuK+NL7UyP15gOzEhXjG4yKR2FTZ9VEsxFe06sgG9+i3gS5kLIIJ+C7IJZhO8e9qNXGK6lAwX0ua/Oznq2dXGUfE4Nf9mrNimwtFjAw5Zx6Ro4nX7LxUifFeMmTjIgEywaiv9bzruWH9lNAYr23YznWwSgHWQc4bVi43QIDAQAB",
    "signing_input": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdvbGRlbi1ycy12MCJ9.eyJ0b2tlbl91c2UiOiJzaXRlLXNlc3Npb24iLCJhdWQiOiJzaXRlLWVkZ2UiLCJlbWFpbCI6ImdvbGRlbkBlMmUuaW52YWxpZCIsImV4cCI6MCwiaWF0IjowfQ",
    "signature_b64": "P92df6Bjg13TN86Skcbup/uscO+/6JVap6jETiXYvCxLuiT7xQogdljNqPdRxAblz3qn+jlKwovcAUg+MBu5nhtjkxYdn/jbvI3Kj3ua02rNIKSIPxtDshWMWbEsH/XttCLmHuzVqKVA7b6YN0R9rk7KO076DkSgeAkY7/UZ0YvRWPQWOm8zAzEYGif0CfPpveqwssulc1WOTHlflEjj58oOKRx9QHImsYR/1FDIB2nbLJhkQ6GIfws+e8BIb6TJboK8f9V3UvXYiIp4AhZCNQp/aq+fxqeDo+foYvNfycFXxs8HVQS+3uYo8+qdiMG6/5LdNqN36qBUfDGjHig0lA==",
}
