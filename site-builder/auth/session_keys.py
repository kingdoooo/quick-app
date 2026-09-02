"""`[SessionKeys]` 的唯一定义：加载 + 校验，**不读 SSM**。

auth 拥有本文件；panel 打包时复制（deploy_panel.py 的 COPY_FILES）；router 栈 synth 时
从 site-builder/auth import；闸门与脚本同样只经它读 kid 清单。取 secret 是调用方的事：
本模块只把 config 变成结构，并把每一种"配置写错了但程序照常跑"的形态变成响亮的
SessionKeysError（configparser 对缺失是静默的，本仓库的既定做法是读不到就硬失败）。

schema 见 spec §11.6，HS 与 RS 两阶段共用：

    [SessionKeys]
    site_current = site-hs-v1        console_current = console-hs-v1
    site_previous =                  console_previous =
    legacy_param = /site-builder/jwt-secret

    [SessionKey:<kid>]   alg = HS256 + ssm_param=/site-builder/session-keys/<kid>
                         或 alg = RS256 + key_arn（带 :key/）+ spki_sha256（64 位 hex）

kid 格式 `{family}-{hs|rs}-v{n}`：family 前缀必须与所属 family 一致，算法段必须与 alg
一致。verifier 把 kid 当不透明字符串查表，**这里的解析只用于校验配置，不用于运行时分派**。
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

KID_RE = re.compile(r"^(site|console)-(hs|rs)-v(\d+)$")
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
    legacy = _strip(cfg.get("SessionKeys", "legacy_param", fallback=""))
    if not legacy:
        raise SessionKeysError("[SessionKeys] 缺 legacy_param（3c-3 之前必填）")
    return SessionKeys(families=families, legacy_param=legacy)


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
