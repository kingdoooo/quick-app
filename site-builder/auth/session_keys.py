"""`[SessionKeys]` 的唯一定义：加载 + 校验，**不读 SSM、不调 KMS**。

auth 拥有本文件；panel 打包时复制（deploy_panel.py 的 COPY_FILES）；router 栈 synth 时从 site-builder/auth
import；闸门与脚本同样只经它读 kid 清单。取公钥 / 签名是调用方的事（session_kms.py）：本模块只把 config
变成结构，并把每一种"配置写错了但程序照常跑"的形态变成响亮的 SessionKeysError（configparser 对缺失是
静默的，本仓库的既定做法是读不到就硬失败）。

schema 见 spec §11.6（3c-final 起只有 RS 行）：

    [SessionKeys]
    site_current = site-rs-v1        console_current = console-rs-v1
    site_previous =                  console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:<kid>]   alg = RS256 + key_arn（带 :key/ 的完整 ARN，永不写 alias）+ spki_sha256（64 位 hex）

kid 格式 `{family}-rs-v{n}`：family 前缀必须与所属 family 一致。verifier 把 kid 当不透明字符串查表，
**这里的解析只用于校验配置，不用于运行时分派**。

槽位语义（CONTEXT.md「Key family」）：`current` = 签发用的那把；`previous` = 另一把被接受的 key
——要么是排空中的旧 key，要么是就位中的新 key。新 key 一律经 previous 就位（DEPLOY.md「轮转会话密钥」）。

`login_flow_secret_param`（spec §11.3）是唯一的 SSM 参数：auth 私有的 HMAC 密钥，只签 OAuth state 与
`__Host-sb_pkce` cookie，**不属于任何 family、没有 kid、不签发也不验证会话**。它不进 `allowlist()`、
不进 `env_json()`，只在 `ssm_parameter_names(login_flow=True)` 时出现——那个开关只有 deploy_auth 打开，
panel 与 Edge 永不持有它。

**没有 `signer`、没有 `legacy_param`**（3c-final 删）：签发形态只有一种，legacy 入口不存在。这两个键若出现在
config 里就是配置错（多半是从旧环境抄来的），硬失败——让"以为还能切回 HS"的人在 synth / 部署前就知道。
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

KID_RE = re.compile(r"^(site|console)-rs-v(\d+)$")
ALG = "RS256"
FAMILIES = ("site", "console")
REMOVED_KEYS = ("signer", "legacy_param")     # 3c-final 删掉的键：出现即拒


class SessionKeysError(ValueError):
    """配置缺失或自相矛盾。调用方不得捕获后回落默认值。"""


@dataclass(frozen=True)
class KeyRef:
    kid: str
    family: str
    alg: str
    role: str                     # "current" | "previous"
    key_arn: str
    spki_sha256: str


@dataclass(frozen=True)
class SessionKeys:
    families: dict            # family -> {"current": KeyRef, "previous": KeyRef | None}
    login_flow_secret_param: str

    def allowlist(self, family: str) -> tuple[KeyRef, ...]:
        """该 family 的接受集合，current 在前。"""
        fam = self.families[family]
        return tuple(k for k in (fam["current"], fam["previous"]) if k is not None)


def _strip(v: str) -> str:
    # configparser 默认把行内注释并进值（CLAUDE.md 记过的坑），这里统一剥掉
    return v.split("#")[0].strip()


def _key_ref(cfg: configparser.ConfigParser, kid: str, family: str, role: str) -> KeyRef:
    m = KID_RE.match(kid)
    if not m or m.group(1) != family:
        raise SessionKeysError(f"[SessionKeys] {family}_{role}={kid!r} 不是本 family 的合法 kid（形态 {family}-rs-v<n>）")
    sect = f"SessionKey:{kid}"
    if not cfg.has_section(sect):
        raise SessionKeysError(f"缺 [{sect}] 小节")
    alg = _strip(cfg.get(sect, "alg", fallback=""))
    if alg != ALG:
        raise SessionKeysError(f"[{sect}] alg={alg!r}，3c-final 起只有 {ALG}")
    if cfg.has_option(sect, "ssm_param"):
        raise SessionKeysError(f"[{sect}] 带 ssm_param——RS 行没有 SSM 密钥；这是 HS 时代的键，删掉")
    key_arn = _strip(cfg.get(sect, "key_arn", fallback=""))
    spki = _strip(cfg.get(sect, "spki_sha256", fallback=""))
    if not re.fullmatch(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}", key_arn):
        raise SessionKeysError(
            f"[{sect}] key_arn 必须是带 :key/<uuid> 的完整 KMS key ARN（不接受 alias），当前 {key_arn!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", spki):
        raise SessionKeysError(f"[{sect}] spki_sha256 必须是 64 位小写 hex（scripts/session_key_fingerprint.py 算），当前 {spki!r}")
    return KeyRef(kid, family, alg, role, key_arn=key_arn, spki_sha256=spki)


def load_session_keys(config_path: Path) -> SessionKeys:
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        found = cfg.read(config_path)
    except configparser.Error as exc:            # 重复键 / 坏语法：同样是配置错，不许静默
        raise SessionKeysError(f"{config_path} 解析失败：{exc}") from exc
    if not found or not cfg.has_section("SessionKeys"):
        raise SessionKeysError(f"{config_path} 缺 [SessionKeys] 段（或文件不存在）")
    for removed in REMOVED_KEYS:
        if cfg.has_option("SessionKeys", removed):
            raise SessionKeysError(
                f"[SessionKeys] 含 {removed}——3c-final 起没有 HS/legacy 形态，这个键已删除；"
                "把它从 config.ini 去掉（参照 config.ini.example）")
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
    login_flow = _strip(cfg.get("SessionKeys", "login_flow_secret_param", fallback=""))
    if not login_flow:
        raise SessionKeysError(
            "[SessionKeys] 缺 login_flow_secret_param（spec §11.3 的字面路径是 /site-builder/login-flow-secret）")
    if not login_flow.startswith("/"):
        raise SessionKeysError(f"[SessionKeys] login_flow_secret_param={login_flow!r} 不是绝对 SSM 路径")
    # **任何两把 key material 都不许指向同一处**：同一把 CMK 或同一个公钥指纹出现两次就不是两把 key，
    # family 隔离与轮转都会失效。
    rows = [r for fam in families.values() for r in fam.values() if r is not None]
    for attr, what in (("key_arn", "KMS key"), ("spki_sha256", "公钥指纹")):
        vals = [getattr(r, attr) for r in rows]
        if len(vals) != len(set(vals)):
            raise SessionKeysError(f"[SessionKeys] 两个 kid 指向同一个 {what}（{sorted(vals)}）——那不是两把 key")
    return SessionKeys(families=families, login_flow_secret_param=login_flow)


def key_refs(keys: SessionKeys, families: tuple) -> list:
    """调用方要的 family 的全部 KeyRef（current 在前，去重保序）。deploy 脚本的部署前四项校验按它逐把做。"""
    out: list = []
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
        out += list(keys.allowlist(fam))
    return list(dict.fromkeys(out))


def kms_key_arns(keys: SessionKeys, families: tuple) -> list:
    """某个执行角色要 `kms:Sign` / `kms:GetPublicKey` 的 key ARN **精确清单**（auth 两个 family、panel 只 console）。
    deploy_auth / deploy_panel 共用，不各拼一份。"""
    return [r.key_arn for r in key_refs(keys, families)]


def env_json(keys: SessionKeys, families: tuple) -> str:
    """给 Lambda 下发的 SESSION_KEYS_JSON：kid / alg / role / key_arn / spki_sha256，**没有任何密钥材料**
    （公钥运行时按 key_arn 取，再与 spki_sha256 核对——verifier_env.load_allowlist）。只含调用方要的 family
    （auth 两个都要，panel 只要 console；Edge 不用它，Edge 由 stack.py 直接注入公钥）。"""
    import json
    out = {}
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
        out[fam] = [{"kid": r.kid, "alg": r.alg, "role": r.role, "key_arn": r.key_arn,
                     "spki_sha256": r.spki_sha256} for r in keys.allowlist(fam)]
    return json.dumps(out, separators=(",", ":"))


def ssm_parameter_names(keys: SessionKeys, families: tuple, *, login_flow: bool = False,
                        extra: tuple = ()) -> list:
    """某个执行角色要读的 SSM 参数**名**（login-flow（仅 auth）→ extra；去重保序）。

    3c-final 起会话密钥不在 SSM 里，所以 `families` 对结果没有影响——参数保留是为了让两个部署脚本的
    调用点不用改形，也让"某天有人给 family 加回 SSM 行"在这里被一眼看见。`login_flow=True` **只有
    deploy_auth 传**：那把密钥是 auth 私有的（spec §11.3），panel 与 Edge 永不持有它。"""
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
    params = [keys.login_flow_secret_param] if login_flow else []
    params += list(extra)
    return list(dict.fromkeys(p for p in params if p))


def ssm_parameter_arns(keys: SessionKeys, families: tuple, *, region: str, account: str,
                       login_flow: bool = False, extra: tuple = ()) -> list:
    return [f"arn:aws:ssm:{region}:{account}:parameter{p}"
            for p in ssm_parameter_names(keys, families, login_flow=login_flow, extra=extra)]


# stack.py 在 KMS 读不到且显式 APP_SYNTH_OFFLINE=1 时注入它：**合法 JSON**、带 SYNTH-ONLY 标记
# （verify_deployed_edge.sh 的"无 SYNTH-ONLY-PLACEHOLDER"那条会抓）、kid 不合 KID_RE（永不匹配任何 token）、
# spki_b64 是标记串的 base64（解不出合法 SPKI ⇒ Edge 首次用到时响亮失败，而不是静默放行）。
SYNTH_PLACEHOLDER_ALLOWLIST_JSON = (
    '{"SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY": {"alg": "RS256", '
    '"spki_b64": "U1lOVEgtT05MWS1QTEFDRUhPTERFUi1ETy1OT1QtREVQTE9Z", "role": "current"}}')
