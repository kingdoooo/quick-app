"""auth 与 panel 共用的 verifier 运行时装配（3c-1A）。

三件事，原先两处各手写一份（login_handler / console_session），复制品漂移正是本仓库最怕的
风险类型，所以收成一份：auth 拥有本文件，panel 打包时复制（deploy_panel.py 的 COPY_FILES）。
- load_allowlist：SESSION_KEYS_JSON（只有参数名）→ 本 verifier 那份 kid allowlist，值按参数名取；
  **出现本 verifier 不该持有的 family 直接拒**（spec §4.3：panel 只持 console）；缺配置直接抛，
  不静默成空 allowlist（空 allowlist 会把新形态会话全拒而看起来像"用户没登录"）。
- legacy_secret：LEGACY_ENTRY on/off → legacy 入口密钥或 None（None = 入口已删，3c-3）。
- log_verify：spec §8 的固定低基数词表，**不记 token**，异常一律吞掉。

3c-1B 起本文件也装配 **signer** 侧的两件事（spec §11.8.3 明写"加在 verifier_env.py，**不改文件名**"
——改名要同时动 auth 的 AUTH_PACKAGE_MODULES 与 panel 的 COPY_FILES，两处任一漏改就是
`Runtime.ImportModuleError` ⇒ 整个组件 502，那是 2026-09-02 真踩过的事故）：
- signing_key：从同一份 SESSION_KEYS_JSON 取 role=current 的 (kid, secret)。**故意复用
  load_allowlist**：签发用的 kid 必须是本 verifier 自己也接受的那把，共用一条解析路径就不可能分叉。
- signer_mode：SESSION_SIGNER legacy/current，缺失或别的值硬失败（与 legacy_secret 同款
  "部署脚本没下发"）。**不默认任何值**：默认 legacy 会让漏下发变成"切换看起来做了但没生效"，
  默认 current 会让漏下发变成"legacy_param 还在但已按新形态签"，两种都是静默的。
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


def signing_key(env_json: str | None, family: str, get_secret, *,
                allowed_families: tuple) -> tuple[str, str]:
    """→ (kid, secret)：该 family 里 role=current 的那把。签发用，**只有 signer 侧调用**。

    走 load_allowlist 而不是自己解一遍 JSON：那样"签发的 kid 一定在本 verifier 的 allowlist 里"
    是结构保证而不是巧合；代价是顺带解析 previous 行（值走同一套 TTL 缓存，多一次 SSM 调用）。
    current 不唯一（0 个或 2 个）时硬失败——env_json 只会给出一个，出现别的数量说明下发的
    JSON 被手改过，静默取第一个会让"签哪把"变成字典序的副产品。
    """
    allowlist = load_allowlist(env_json, family, get_secret, allowed_families=allowed_families)
    current = [(kid, entry) for kid, entry in allowlist.items() if entry["role"] == "current"]
    if len(current) != 1:
        raise RuntimeError(
            f"SESSION_KEYS_JSON 的 {family} family 有 {len(current)} 个 role=current 的 kid，"
            "必须恰好 1 个——部署脚本坏了")
    kid, entry = current[0]
    return kid, entry["secret"]


def signer_mode(flag: str | None) -> str:
    """→ "legacy" | "current"。缺失或别的值硬失败（不默认任何值，见模块 docstring）。"""
    if flag not in ("legacy", "current"):
        raise RuntimeError("SESSION_SIGNER 必须是 legacy/current——部署脚本没下发")
    return flag


def legacy_secret(flag: str | None, get_legacy):
    if flag not in ("on", "off"):
        raise RuntimeError("LEGACY_ENTRY 必须是 on/off——部署脚本没下发")
    return get_legacy() if flag == "on" else None


def log_verify(verifier: str, outcome) -> None:
    try:
        print(json.dumps({"event": "session_verify", "verifier": verifier, "outcome": outcome}))
    except Exception:
        pass
