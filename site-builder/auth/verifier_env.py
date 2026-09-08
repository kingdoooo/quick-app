"""auth 与 panel 共用的 verifier / signer 运行时装配（3c-final，RS-only）。

原先两处各手写一份（login_handler / console_session），复制品漂移正是本仓库最怕的风险类型，所以收成一份：
auth 拥有本文件，panel 打包时复制（deploy_panel.py 的 COPY_FILES）。
- load_allowlist：SESSION_KEYS_JSON（kid / alg / role / key_arn / spki_sha256，**没有密钥材料**）→ 本 verifier
  那份 kid allowlist，公钥按 key_arn 经 `get_public_key(key_arn, spki_sha256)` 取（session_kms.public_key_loader：
  GetPublicKey + 指纹核对，不符抛）。**出现本 verifier 不该持有的 family 直接拒**（spec §4.3：panel 只持 console）；
  缺配置直接抛，不静默成空 allowlist（空 allowlist 会把全部会话拒掉而看起来像"用户没登录"）。
- signing_ref：同一份 JSON 里 role=current（或显式 previous）的 (kid, key_arn, spki_sha256)。**故意复用 _rows**：
  签发用的 kid 必须是本 verifier 自己也接受的那把，共用一条解析路径就不可能分叉。它不调 KMS——签名器
  （session_kms.KmsSigner）由调用方用返回值构造并缓存。
- log_verify：spec §8 的固定低基数词表，**不记 token**，异常一律吞掉。
"""
from __future__ import annotations

import json

ROLES = ("current", "previous")


def _rows(env_json: str | None, family: str, allowed_families: tuple) -> list:
    if env_json is None:
        raise RuntimeError("SESSION_KEYS_JSON 缺失——部署脚本没下发")
    try:
        keys = json.loads(env_json)
    except ValueError as exc:
        raise RuntimeError("SESSION_KEYS_JSON 不是 JSON——部署脚本坏了") from exc
    if not isinstance(keys, dict) or not set(keys) <= set(allowed_families):
        raise RuntimeError(f"SESSION_KEYS_JSON 含本 verifier 不该持有的 family：{sorted(keys) if isinstance(keys, dict) else keys!r}")
    if family not in keys:
        raise RuntimeError(f"SESSION_KEYS_JSON 没有 {family} family——部署脚本没下发")
    return keys[family]


def load_allowlist(env_json: str | None, family: str, get_public_key, *, allowed_families: tuple) -> dict:
    """验签用的 allowlist：**每一行都取公钥**（current 与 previous 都要能验签）。"""
    return {r["kid"]: {"alg": r["alg"], "public_key": get_public_key(r["key_arn"], r["spki_sha256"]),
                       "role": r["role"]}
            for r in _rows(env_json, family, allowed_families)}


def signing_ref(env_json: str | None, family: str, *, allowed_families: tuple,
                role: str = "current") -> tuple[str, str, str]:
    """→ (kid, key_arn, spki_sha256)：该 family 里指定 role 的那把。签发用，**只有 signer 侧调用**。

    `role="previous"` 只给 auth 的 /fixture-session（就位期正向探针，spec §11.8.8）；生产签发一律 current。
    current 不唯一（0 个或 2 个）时硬失败——env_json 只会给出一个，出现别的数量说明下发的 JSON 被手改过。
    """
    if role not in ROLES:
        raise RuntimeError(f"role 必须是 {ROLES} 之一，得到 {role!r}")
    rows = _rows(env_json, family, allowed_families)
    current = [r for r in rows if r.get("role") == "current"]
    if len(current) != 1:
        raise RuntimeError(f"SESSION_KEYS_JSON 的 {family} family 有 {len(current)} 个 role=current 的 kid，"
                           "必须恰好 1 个——部署脚本坏了")
    picked = current if role == "current" else [r for r in rows if r.get("role") == "previous"]
    if not picked:
        raise RuntimeError(f"SESSION_KEYS_JSON 的 {family} family 没有 previous 行——就位之前没有 previous key 可签")
    row = picked[0]
    return row["kid"], row["key_arn"], row["spki_sha256"]


def log_verify(verifier: str, outcome) -> None:
    try:
        print(json.dumps({"event": "session_verify", "verifier": verifier, "outcome": outcome}))
    except Exception:
        pass
