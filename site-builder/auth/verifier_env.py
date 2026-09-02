"""auth 与 panel 共用的 verifier 运行时装配（3c-1A）。

三件事，原先两处各手写一份（login_handler / console_session），复制品漂移正是本仓库最怕的
风险类型，所以收成一份：auth 拥有本文件，panel 打包时复制（deploy_panel.py 的 COPY_FILES）。
- load_allowlist：SESSION_KEYS_JSON（只有参数名）→ 本 verifier 那份 kid allowlist，值按参数名取；
  **出现本 verifier 不该持有的 family 直接拒**（spec §4.3：panel 只持 console）；缺配置直接抛，
  不静默成空 allowlist（空 allowlist 会把新形态会话全拒而看起来像"用户没登录"）。
- legacy_secret：LEGACY_ENTRY on/off → legacy 入口密钥或 None（None = 入口已删，3c-3）。
- log_verify：spec §8 的固定低基数词表，**不记 token**，异常一律吞掉。
"""
from __future__ import annotations

import json


def load_allowlist(env_json: str | None, family: str, get_secret, *, allowed_families: tuple) -> dict:
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
    return {r["kid"]: {"alg": r["alg"], "secret": get_secret(r["ssm_param"]), "role": r["role"]}
            for r in keys[family]}


def legacy_secret(flag: str | None, get_legacy):
    if flag not in ("on", "off"):
        raise RuntimeError("LEGACY_ENTRY 必须是 on/off——部署脚本没下发")
    return get_legacy() if flag == "on" else None


def log_verify(verifier: str, outcome) -> None:
    try:
        print(json.dumps({"event": "session_verify", "verifier": verifier, "outcome": outcome}))
    except Exception:
        pass
