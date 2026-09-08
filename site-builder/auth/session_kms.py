"""KMS 边界的**唯一实现**（spec §11.2 / §11.5 / §11.6；3c-final）。

三个使用面、一份代码：
- **部署前**（spec §11.6 第 1 层）：`precheck_keys` 对每个 RS kid 做 DescribeKey + GetPublicKey 四项校验
  （KeySpec=RSA_2048、KeyUsage=SIGN_VERIFY、SigningAlgorithms 含 RSASSA_PKCS1_V1_5_SHA_256、
  SHA-256(SPKI) == 配置的 spki_sha256），任一不符**拒绝部署**。deploy_auth / deploy_panel / router 栈都调它。
- **verifier 冷启动**：`public_key_loader` 按 key_arn 取公钥、与 spki_sha256 核对后才装进 allowlist
  （fail closed；`verifier_env.load_allowlist` 的 get_public_key 参数）。
- **signer**（spec §11.6 第 2 层）：`KmsSigner` 首次调用做一次 GetPublicKey 指纹自检，每次 Sign 断言
  响应 KeyId == 配置的 key_arn；`MessageType=RAW`，任何地方不做本地哈希（spec §11.5）。

本模块**不 import boto3、不读配置、不读环境变量**：client 由调用方传入（deploy 脚本、login_handler、
console_session、stack.py 各自缓存自己的），与 function_url_policy.py 同一纪律。
auth 拥有本文件；panel 打包时复制（deploy_panel.COPY_FILES）；login_handler import 它 ⇒ 它在
`deploy_auth.AUTH_PACKAGE_MODULES` 里（test_deploy_auth_package.py 按 import 闭包核对）。
"""
from __future__ import annotations

import base64

import session

SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
KEY_SPEC = "RSA_2048"
KEY_USAGE = "SIGN_VERIFY"
MESSAGE_TYPE = "RAW"


class KeyMaterialMismatch(RuntimeError):
    """KMS 里的 key 与配置声明的不是同一把、或不是合同要求的形态。调用方不得捕获后继续。"""


def _describe_checks(meta: dict, key_arn: str) -> list:
    problems = []
    if meta.get("Arn") != key_arn:
        problems.append(f"DescribeKey 返回的 Arn {meta.get('Arn')!r} != 配置的 {key_arn!r}")
    if meta.get("KeySpec") != KEY_SPEC:
        problems.append(f"KeySpec={meta.get('KeySpec')!r}，要 {KEY_SPEC}")
    if meta.get("KeyUsage") != KEY_USAGE:
        problems.append(f"KeyUsage={meta.get('KeyUsage')!r}，要 {KEY_USAGE}")
    if SIGNING_ALGORITHM not in (meta.get("SigningAlgorithms") or []):
        problems.append(f"SigningAlgorithms={meta.get('SigningAlgorithms')!r} 不含 {SIGNING_ALGORITHM}")
    if meta.get("KeyState") != "Enabled":
        problems.append(f"KeyState={meta.get('KeyState')!r}，要 Enabled")
    return problems


def describe_public_key(kms, key_arn: str) -> tuple[bytes, str]:
    """→ (DER SPKI, spki_sha256)。做 DescribeKey 的形态检查与公钥侧四项（session.load_public_key_der），
    **不**与任何配置值比对——`scripts/session_key_fingerprint.py` 靠它算出要回填的指纹。"""
    meta = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    problems = _describe_checks(meta, key_arn)
    if problems:
        raise KeyMaterialMismatch(f"{key_arn}: " + "；".join(problems))
    der = kms.get_public_key(KeyId=key_arn)["PublicKey"]
    try:
        session.load_public_key_der(der)
    except ValueError as exc:
        raise KeyMaterialMismatch(f"{key_arn}: 公钥 SPKI 不合合同（{exc}）") from exc
    return der, session.spki_sha256(der)


def fetch_verified_public_key_der(kms, ref) -> bytes:
    """spec §11.6 第 1 层：DescribeKey 三项 + 公钥侧四项 + 指纹等值。**汇总**该 key 的所有不符项后
    以 `ref.kid` 为前缀抛一个 KeyMaterialMismatch——precheck 直接把它 str 进汇总（"lists every mismatch"），
    调用方一次就能看清哪把 key、错在哪几项。任一不符即拒。"""
    meta = kms.describe_key(KeyId=ref.key_arn)["KeyMetadata"]
    problems = _describe_checks(meta, ref.key_arn)
    der = kms.get_public_key(KeyId=ref.key_arn)["PublicKey"]
    try:
        session.load_public_key_der(der)
    except ValueError as exc:
        problems.append(f"公钥 SPKI 不合合同（{exc}）")
    fp = session.spki_sha256(der)
    if fp != ref.spki_sha256:
        problems.append(
            f"KMS 公钥的 spki_sha256={fp} != 配置的 {ref.spki_sha256}——"
            "config.ini 指的不是这把 key（或 key 被换过）")
    if problems:
        raise KeyMaterialMismatch(f"{ref.kid}: " + "；".join(problems))
    return der


def precheck_keys(kms, refs) -> None:
    """部署脚本在**第一次写之前**调：对每个 RS kid 做四项校验，汇总全部不符项后 SystemExit（与
    secrets_util.precheck_parameters 同形）。只读，不打印任何密钥材料（公钥不是秘密，但也不需要打）。"""
    problems = []
    for ref in refs:
        try:
            fetch_verified_public_key_der(kms, ref)
        except KeyMaterialMismatch as exc:
            problems.append(str(exc))
        except Exception as exc:  # noqa: BLE001  AccessDenied / NotFound 同样是"部署出去会 500"
            problems.append(f"{ref.kid}: {type(exc).__name__}: {exc}")
    if problems:
        raise SystemExit("部署前核对失败：这些会话签名 key 与 [SessionKeys] 声明不符，拒绝部署（任何写都未发生）：\n  "
                         + "\n  ".join(problems)
                         + "\n先部 deployer 栈拿到 key ARN，用 scripts/session_key_fingerprint.py 算指纹回填 config.ini。")


def public_key_loader(kms):
    """→ `get_public_key(key_arn, spki_sha256) -> RSAPublicKey`，容器内按 ARN 缓存。
    指纹不符抛 KeyMaterialMismatch：verifier 宁可 500 也不装一把来历不明的公钥进 allowlist。"""
    cache: dict = {}

    def get_public_key(key_arn: str, spki_sha256: str):
        hit = cache.get(key_arn)
        if hit is not None:
            return hit
        der = kms.get_public_key(KeyId=key_arn)["PublicKey"]
        fp = session.spki_sha256(der)
        if fp != spki_sha256:
            raise KeyMaterialMismatch(f"{key_arn}: 公钥指纹 {fp} != 配置的 {spki_sha256}——拒绝装进 allowlist")
        pub = session.load_public_key_der(der)
        cache[key_arn] = pub
        return pub
    return get_public_key


class KmsSigner:
    """`session.mint_token(sign=…)` 的生产实现。首次调用先做一次 GetPublicKey 指纹自检（spec §11.6 第 2 层：
    不符则拒签，fail closed）；每次 Sign 断言响应 KeyId == key_arn；`MessageType=RAW`（spec §11.5）。"""

    def __init__(self, kms, key_arn: str, spki_sha256: str):
        self._kms = kms
        self.key_arn = key_arn
        self.spki_sha256 = spki_sha256
        self._checked = False

    def self_check(self) -> None:
        """一次 GetPublicKey + 指纹比对。login_handler 在烧掉一次性授权码之前调它（ticket 20 的同一理由）。"""
        if self._checked:
            return
        der = self._kms.get_public_key(KeyId=self.key_arn)["PublicKey"]
        fp = session.spki_sha256(der)
        if fp != self.spki_sha256:
            raise KeyMaterialMismatch(f"{self.key_arn}: 公钥指纹 {fp} != 配置的 {self.spki_sha256}——拒签")
        self._checked = True

    def __call__(self, signing_input: bytes) -> bytes:
        if len(signing_input) > session.SIGNING_INPUT_MAX:
            raise ValueError(f"signing input {len(signing_input)} 字节超过 {session.SIGNING_INPUT_MAX}，拒签")
        self.self_check()
        resp = self._kms.sign(KeyId=self.key_arn, Message=signing_input, MessageType=MESSAGE_TYPE,
                              SigningAlgorithm=SIGNING_ALGORITHM)
        if resp.get("KeyId") != self.key_arn:
            raise KeyMaterialMismatch(f"Sign 响应的 KeyId {resp.get('KeyId')!r} != 配置的 {self.key_arn!r}")
        return resp["Signature"]


def spki_b64(der: bytes) -> str:
    """Edge 注入用的形态（stack.py）：base64（标准字母表，无换行）。JSON 里没有反斜杠、没有换行。"""
    return base64.b64encode(der).decode()
