"""`[SessionKeys]` 的唯一定义：加载 + 校验，**不读 SSM**。

auth 拥有本文件；panel 打包时复制（deploy_panel.py 的 COPY_FILES）；router 栈 synth 时
从 site-builder/auth import；闸门与脚本同样只经它读 kid 清单。取 secret 是调用方的事：
本模块只把 config 变成结构，并把每一种"配置写错了但程序照常跑"的形态变成响亮的
SessionKeysError（configparser 对缺失是静默的，本仓库的既定做法是读不到就硬失败）。

schema 见 spec §11.6，HS 与 RS 两阶段共用：

    [SessionKeys]
    site_current = site-hs-v1        console_current = console-hs-v1
    site_previous =                  console_previous =
    signer = legacy | current
    legacy_param = /site-builder/jwt-secret
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:<kid>]   alg = HS256 + ssm_param=/site-builder/session-keys/<kid>
                         或 alg = RS256 + key_arn（带 :key/）+ spki_sha256（64 位 hex）

kid 格式 `{family}-{hs|rs}-v{n}`：family 前缀必须与所属 family 一致，算法段必须与 alg
一致。verifier 把 kid 当不透明字符串查表，**这里的解析只用于校验配置，不用于运行时分派**。

`login_flow_secret_param`（3c-1B，spec §11.3 / §11.8.6）是第三种参数：auth 私有的 HMAC 密钥，
只签 OAuth state 与 `__Host-sb_pkce` cookie，**不属于任何 family、没有 kid、不签发也不验证会话**。
所以它不进 `allowlist()`、不进 `env_json()`，只在 `ssm_parameter_names(login_flow=True)` 时出现
——那个开关只有 deploy_auth 打开，panel 与 Edge 永不持有它。它不许落在 session-keys 前缀下
（长得像一把 family 密钥会误导闸门与读代码的人），也不许与 legacy / 任何 HS 行同一参数：
拿会话密钥签登录流程数据正是 1B 要消灭的那条耦合。

`signer`（3c-1B，spec §11.8.3）决定 **签发**形态：`legacy` = 拆 family 之前那把共享密钥 + 旧
合同；`current` = 各 family 的 role=current 那把 + `mint_token` 新合同。它下发为 auth 与 panel 的
`SESSION_SIGNER` 环境变量（**panel 侧随 3c-1B 的 05 号任务落地**；在那之前 deploy_panel 不下发它、
panel 无条件签 legacy 形态），**回滚就是改这一行重跑两个部署脚本**（不回退代码，免得连带回滚同批的
其它改动）。验签侧与它无关：verifier 全程双接受，所以切换与回滚都不需要动 Edge。
缺键或写别的值是配置错，硬失败——给默认值等于让"没写 signer"静默变成某一种签发形态。
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

KID_RE = re.compile(r"^(site|console)-(hs|rs)-v(\d+)$")
SIGNER_MODES = ("legacy", "current")
HS_PARAM_PREFIX = "/site-builder/session-keys/"
ALGS = {"hs": "HS256", "rs": "RS256"}
FAMILIES = ("site", "console")


class SessionKeysError(ValueError):
    """配置缺失或自相矛盾。调用方不得捕获后回落默认值。"""


@dataclass(frozen=True)
class KeyRef:
    kid: str
    family: str
    alg: str
    role: str                     # "current" | "previous"
    ssm_param: str | None = None  # HS
    key_arn: str | None = None    # RS（3c-2B 起）
    spki_sha256: str | None = None


@dataclass(frozen=True)
class SessionKeys:
    families: dict            # family -> {"current": KeyRef, "previous": KeyRef | None}
    legacy_param: str
    login_flow_secret_param: str   # auth 私有；不是 kid、不属于任何 family（见模块 docstring）
    signer: str                    # "legacy" | "current"（见模块 docstring）

    def allowlist(self, family: str) -> tuple[KeyRef, ...]:
        """该 family 的接受集合，current 在前。**不含 legacy**：legacy 是 family 外的第三入口。"""
        fam = self.families[family]
        return tuple(k for k in (fam["current"], fam["previous"]) if k is not None)


def _strip(v: str) -> str:
    # configparser 默认把行内注释并进值（CLAUDE.md 记过的坑），这里统一剥掉
    return v.split("#")[0].strip()


def _key_ref(cfg: configparser.ConfigParser, kid: str, family: str, role: str) -> KeyRef:
    m = KID_RE.match(kid)
    if not m or m.group(1) != family:
        raise SessionKeysError(f"[SessionKeys] {family}_{role}={kid!r} 不是本 family 的合法 kid")
    sect = f"SessionKey:{kid}"
    if not cfg.has_section(sect):
        raise SessionKeysError(f"缺 [{sect}] 小节")
    alg = _strip(cfg.get(sect, "alg", fallback=""))
    if alg != ALGS[m.group(2)]:
        raise SessionKeysError(f"[{sect}] alg={alg!r} 与 kid 里的算法段不一致")
    ssm_param = _strip(cfg.get(sect, "ssm_param", fallback=""))
    key_arn = _strip(cfg.get(sect, "key_arn", fallback=""))
    spki = _strip(cfg.get(sect, "spki_sha256", fallback=""))
    if alg == "HS256":
        if not ssm_param.startswith(HS_PARAM_PREFIX) or key_arn or spki:
            raise SessionKeysError(
                f"[{sect}] HS 行必须只有 ssm_param（{HS_PARAM_PREFIX}…），不得带 key_arn/spki_sha256")
        return KeyRef(kid, family, alg, role, ssm_param=ssm_param)
    if ":key/" not in key_arn or not re.fullmatch(r"[0-9a-f]{64}", spki) or ssm_param:
        raise SessionKeysError(
            f"[{sect}] RS 行必须有带 :key/ 的 key_arn（不接受 alias）与 64 位 hex spki_sha256，"
            "且不得带 ssm_param")
    return KeyRef(kid, family, alg, role, key_arn=key_arn, spki_sha256=spki)


def load_session_keys(config_path: Path) -> SessionKeys:
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        found = cfg.read(config_path)
    except configparser.Error as exc:            # 重复键 / 坏语法：同样是配置错，不许静默
        raise SessionKeysError(f"{config_path} 解析失败：{exc}") from exc
    if not found or not cfg.has_section("SessionKeys"):
        raise SessionKeysError(f"{config_path} 缺 [SessionKeys] 段（或文件不存在）")
    families: dict = {}
    seen: set[str] = set()
    for fam in FAMILIES:
        cur = _strip(cfg.get("SessionKeys", f"{fam}_current", fallback=""))
        prev = _strip(cfg.get("SessionKeys", f"{fam}_previous", fallback=""))
        if not cur:
            raise SessionKeysError(f"[SessionKeys] 缺 {fam}_current")
        if prev == cur:
            raise SessionKeysError(f"[SessionKeys] {fam}_previous 与 current 相同")
        refs = {"current": _key_ref(cfg, cur, fam, "current"),
                "previous": _key_ref(cfg, prev, fam, "previous") if prev else None}
        for r in refs.values():
            if r is not None:
                if r.kid in seen:
                    raise SessionKeysError(f"kid {r.kid} 出现在两个 family")
                seen.add(r.kid)
        families[fam] = refs
    signer = _strip(cfg.get("SessionKeys", "signer", fallback=""))
    if signer not in SIGNER_MODES:
        raise SessionKeysError(
            f"[SessionKeys] signer={signer!r} 必须是 {' 或 '.join(SIGNER_MODES)}（3c-1B 起必填）"
            "——缺键也是配置错，不给默认值：默认哪一侧都会让「忘了写」静默变成一种签发形态")
    legacy = _strip(cfg.get("SessionKeys", "legacy_param", fallback=""))
    if signer == "legacy" and not legacy:
        raise SessionKeysError(
            "[SessionKeys] signer=legacy 要求 legacy_param 非空——legacy 入口关闭后再签 legacy 形态"
            "等于签一批没人接受的 token（全员登录循环）")
    if not legacy:
        # 3c-1B 的 07 号任务把这条放开为「legacy_param 为空即要求 signer=current」（L3）；
        # 在那之前清空它会让 Edge/panel 的 legacy 入口与角色 SSM 清单一起变，属于另一票的范围。
        raise SessionKeysError("[SessionKeys] 缺 legacy_param（3c-3 之前必填）")
    login_flow = _strip(cfg.get("SessionKeys", "login_flow_secret_param", fallback=""))
    if not login_flow:
        raise SessionKeysError(
            "[SessionKeys] 缺 login_flow_secret_param（3c-1B 起必填；spec §11.3 的字面路径是 "
            "/site-builder/login-flow-secret）")
    if not login_flow.startswith("/"):
        raise SessionKeysError(
            f"[SessionKeys] login_flow_secret_param={login_flow!r} 不是绝对 SSM 路径")
    if login_flow.startswith(HS_PARAM_PREFIX):
        raise SessionKeysError(
            f"[SessionKeys] login_flow_secret_param={login_flow!r} 落在 {HS_PARAM_PREFIX} 下"
            "——它不是 kid，不许长得像一把 family 密钥")
    hs_params = {r.ssm_param for fam in families.values() for r in fam.values()
                 if r is not None and r.ssm_param}
    if login_flow == legacy or login_flow in hs_params:
        raise SessionKeysError(
            f"[SessionKeys] login_flow_secret_param={login_flow!r} 与一把会话密钥同一参数"
            "——登录流程的 HMAC 不得复用会话密钥（spec §11.3）")
    return SessionKeys(families=families, legacy_param=legacy,
                       login_flow_secret_param=login_flow, signer=signer)


def env_json(keys: SessionKeys, families: tuple) -> str:
    """给 Lambda 下发的 SESSION_KEYS_JSON：**只有参数名，没有值**；只含调用方要的 family
    （auth 两个都要，panel 只要 console；Edge 不用它，Edge 由 stack.py 直接注入 allowlist）。"""
    import json
    out = {}
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
        out[fam] = [{"kid": r.kid, "alg": r.alg, "role": r.role, "ssm_param": r.ssm_param}
                    for r in keys.allowlist(fam)]
    return json.dumps(out, separators=(",", ":"))


def legacy_entry(keys: SessionKeys) -> str:
    """legacy 入口开关的下发值：legacy_param 非空即 "on"（3c-3 清空它即 "off"）。"""
    return "on" if keys.legacy_param else "off"


def ssm_parameter_names(keys: SessionKeys, families: tuple, *, login_flow: bool = False,
                        extra: tuple = ()) -> list:
    """某个执行角色要读的 SSM 参数**名**的精确清单（legacy → login-flow（仅 auth）→ extra →
    各 family 的 HS 行；去重保序）。role 的 ARN 清单（ssm_parameter_arns）与部署前核对
    （secrets_util.precheck_parameters）都从它推导，两处不会分叉。

    `login_flow=True` **只有 deploy_auth 传**：那把密钥是 auth 私有的（spec §11.3），
    panel 与 Edge 永不持有它。默认关，漏传的后果是 auth 运行时 AccessDenied（响亮），
    而误传的后果是把一把密钥交给不需要它的组件（静默扩权）——所以默认取安全的那一侧。"""
    params = [keys.legacy_param]
    if login_flow:
        params.append(keys.login_flow_secret_param)
    params += list(extra)
    for fam in families:
        params += [r.ssm_param for r in keys.allowlist(fam) if r.alg == "HS256"]
    return list(dict.fromkeys(p for p in params if p))


def ssm_parameter_arns(keys: SessionKeys, families: tuple, *, region: str, account: str,
                       login_flow: bool = False, extra: tuple = ()) -> list:
    """某个执行角色能读的 SSM 参数**精确 ARN 清单**。deploy_auth / deploy_panel 共用，不各拼一份；
    前缀通配 `parameter/site-builder/*` 会把 session-keys 下未来的一切一并交出去。"""
    return [f"arn:aws:ssm:{region}:{account}:parameter{p}"
            for p in ssm_parameter_names(keys, families, login_flow=login_flow, extra=extra)]


# stack.py 在 SSM 读不到时注入它：**合法 JSON**（Edge import 不炸）、带 SYNTH-ONLY 标记
# （verify_deployed_edge.sh 的"无 SYNTH-ONLY-PLACEHOLDER"那条会抓）、kid 不合 KID_RE（永不匹配任何 token）。
# 空 `{}` 不行：它看起来合法，synth 与全部部署前测试都过，只有部署后才发现。
SYNTH_PLACEHOLDER_ALLOWLIST_JSON = (
    '{"SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY": {"alg": "HS256", '
    '"secret": "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY", "role": "current"}}')
