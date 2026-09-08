"""三个套件（auth / panel / router）共用的 RS256 测试密钥与契约向量（3c-final）。

为什么共用一份：panel 构建时**复制** session.py，Edge 内嵌一份字节等价的验签核心——两份副本
各自漂移是本项目已知的风险类型。同一组密钥、同一组变形向量在三侧都跑，漂移当场暴露。

密钥在 **import 期生成**（三把 RSA-2048 约 0.2 s），**不落 PEM 进仓库**：`scan_staged_secrets.sh`
拦 `BEGIN … PRIVATE KEY`，而测试也不需要跨进程稳定的密钥——只需要同一进程里三侧看到同一把。
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SITE_KID, SITE_PREV_KID, CONSOLE_KID = "site-rs-v1", "site-rs-v0", "console-rs-v1"
SITE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SITE_PREV_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CONSOLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# 与生产同形的假 ARN（账号 111111111111，仓库红线）；kid → key ARN 一一对应
KEY_ARN = {SITE_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000001",
           SITE_PREV_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000000",
           CONSOLE_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000002"}
PRIVATE = {SITE_KID: SITE_KEY, SITE_PREV_KID: SITE_PREV_KEY, CONSOLE_KID: CONSOLE_KEY}
SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"


def spki_der(private_key) -> bytes:
    return private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_b64(private_key) -> str:
    return base64.b64encode(spki_der(private_key)).decode()


def spki_hex(private_key) -> str:
    return hashlib.sha256(spki_der(private_key)).hexdigest()


def public_entry(private_key, role: str) -> dict:
    """verifier allowlist 的一行（session.verify_token 消费的形态）。"""
    return {"alg": "RS256", "public_key": private_key.public_key(), "role": role}


def signer(private_key):
    return lambda data: private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


SITE_ALLOWLIST = {SITE_KID: public_entry(SITE_KEY, "current")}
CONSOLE_ALLOWLIST = {CONSOLE_KID: public_entry(CONSOLE_KEY, "current")}


def session_keys_json(*rows: tuple[str, str]) -> str:
    """`SESSION_KEYS_JSON` 的形态（与 session_keys.env_json 一致）：rows 是 (kid, role)。"""
    out: dict = {}
    for kid, role in rows:
        fam = kid.split("-")[0]
        out.setdefault(fam, []).append({"kid": kid, "alg": "RS256", "role": role,
                                        "key_arn": KEY_ARN[kid], "spki_sha256": spki_hex(PRIVATE[kid])})
    return json.dumps(out, separators=(",", ":"))


class FakeKms:
    """KMS 替身：DescribeKey / GetPublicKey / Sign 按本模块的私钥回答，并**记录每次调用**。

    `wrong_key_id_for`：让 Sign 的响应 KeyId 指向别的 ARN（测 signer 的 KeyId 断言）；
    `tamper_public_key_for`：让 GetPublicKey 返回另一把的 SPKI（测指纹自检）；
    `describe_overrides`：覆盖 KeyMetadata 字段（测部署前四项校验的每一项）。
    """

    def __init__(self, arns: dict | None = None):
        self.arns = dict(arns or {v: k for k, v in KEY_ARN.items()})   # arn -> kid
        self.calls: list = []
        self.wrong_key_id_for: dict = {}
        self.tamper_public_key_for: dict = {}
        self.describe_overrides: dict = {}

    def _key(self, arn: str):
        if arn not in self.arns:
            raise RuntimeError(f"FakeKms: 未知 KeyId {arn!r}（测试意外碰了配置外的 key）")
        return PRIVATE[self.arns[arn]]

    def describe_key(self, KeyId):
        self.calls.append(("describe_key", KeyId))
        self._key(KeyId)
        meta = {"Arn": KeyId, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled",
                "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384",
                                      "RSASSA_PSS_SHA_256"]}
        meta.update(self.describe_overrides.get(KeyId, {}))
        return {"KeyMetadata": meta}

    def get_public_key(self, KeyId):
        self.calls.append(("get_public_key", KeyId))
        key = self._key(KeyId)
        der = spki_der(self.tamper_public_key_for.get(KeyId, key))
        return {"KeyId": KeyId, "PublicKey": der, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append(("sign", KeyId, MessageType, SigningAlgorithm, len(Message)))
        assert MessageType == "RAW" and SigningAlgorithm == SIGNING_ALGORITHM, "合同（spec §11.5）"
        sig = self._key(KeyId).sign(Message, padding.PKCS1v15(), hashes.SHA256())
        return {"KeyId": self.wrong_key_id_for.get(KeyId, KeyId), "Signature": sig,
                "SigningAlgorithm": SigningAlgorithm}


# ---- 变形向量：auth 侧签、panel 侧验，两个包各跑一遍 -------------------------------------

def _tamper_payload(code: str) -> str:
    h, _, rest = code.partition(".")
    _, _, sig = rest.partition(".")
    return f"{h}.eyJhIjoxfQ.{sig}"


def _drop_sig(code: str) -> str:
    h, p, _ = code.split(".")
    return f"{h}.{p}."


def _pad_sig(code: str) -> str:
    """签名段带上 `=` 填充：同一签名的第二种编码，规范 base64url 必须拒。"""
    h, p, s = code.split(".")
    return f"{h}.{p}.{s}{'=' * (-len(s) % 4) or '='}"


def _std_alphabet_sig(code: str) -> str:
    """签名段换成标准字母表（+ /）。这枚签名的 base64 里恰好没有 + / 时（概率约 2e-5）退化成带 = 填充的
    形态——两种都是"同一签名的第二种编码"，规范 base64url 都必须拒。"""
    h, p, s = code.split(".")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    std = base64.b64encode(raw).decode().rstrip("=")
    return f"{h}.{p}.{std}" if std != s else _pad_sig(code)


def _crit_header(code: str) -> str:
    """header 加 crit：RFC 7515 要求不认识的 critical 扩展必须拒，本平台不认任何一个。"""
    h, p, s = code.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    hdr["crit"] = ["exp"]
    h2 = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{h2}.{p}.{s}"


def _alg_none(code: str) -> str:
    h, p, s = code.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    hdr["alg"] = "none"
    h2 = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{h2}.{p}."


def _short_sig(code: str) -> str:
    """签名少一个字节：长度不等于模长必须拒，不许交给 RSA 层"补零"。"""
    h, p, s = code.split(".")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))[:-1]
    return f"{h}.{p}.{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}"


# (名字, 变换函数, 期望被拒)
MUTATIONS = [
    ("完好", lambda c: c, False),
    ("签名被截断", lambda c: c[:-4], True),
    ("签名整段删除", _drop_sig, True),
    ("篡改 payload 保留旧签名", _tamper_payload, True),
    ("整段替换成 login state 形态", lambda c: "abc.def.ghi", True),
    ("段数不足", lambda c: c.rsplit(".", 1)[0], True),
    ("空串", lambda c: "", True),
]
RS_MUTATIONS = MUTATIONS + [
    ("签名带 = 填充", _pad_sig, True),
    ("签名用标准字母表", _std_alphabet_sig, True),
    ("header 带 crit", _crit_header, True),
    ("alg=none", _alg_none, True),
    ("签名少一字节", _short_sig, True),
]
CONSOLE_SESSION_TTL = 4 * 3600


def console_session_token(mint_token, *, email="u@x.com", name="U", kid=CONSOLE_KID,
                          key=CONSOLE_KEY, **kw) -> str:
    """新形态面板会话 token。`mint_token` 由调用方传入**自己那份** session.py 的实现。"""
    return mint_token(kid=kid, sign=signer(key), token_use="console-session", email=email,
                      ttl_seconds=CONSOLE_SESSION_TTL, name=name, **kw)
