#!/usr/bin/env python3
"""验收工具唯一的本地 mint 入口（3c-1B ticket 01；spec §11.8.4、§11.8.11）。

四个 `verify_*`、`verify_kid_entry_live.py` 与 E2E 的会话 cookie fixture 都从这里拿 token，
不再各自读 SSM 明文调用旧 mint。它做三件事：
- 读 `[SessionKeys]`（`auth/session_keys.py` 校验，路径只来自 config，不接受命令行路径），按
  family 与 role（`current` 默认 / `previous` / `legacy`）取 SSM 值，值按参数名缓存；
- `current` / `previous` 调用**生产** `session.mint_token`（带 kid 的新形态）；`legacy` 调用旧的
  `mint_session_jwt` / `mint_upgrade_code`（无 kid），只用于 L3 与退役**之前**预存负向探针 token；
- `--save FILE` 把 token 连同元数据写成 JSON，**只许写进 `.scratch/`**（gitignored）。

身份：`idp` 取 `router/config.ini` 的 `trusted_idps` 第一项，`auth_via` 是托管登录值——Edge 开了
`require_idp_claim` 之后缺这两个 claim 的会话会被 302，后面的断言都在"根本没到站点"的前提下通过/失败。
邮箱仍由调用方给（今天冒充目标站点 owner / `e2e@test.com`），3c-2A 按 ADR-0002 把本模块换成夹具签发器，
调用方不动。用不带路径的 python3 跑（CLAUDE.md）。

    python3 site-builder/scripts/_session_mint.py --token-use site-session --email <owner> \
        --role legacy --ttl 600 --save .scratch/3c-1b/legacy-site.json
"""
from __future__ import annotations

import argparse
import configparser
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import session as sess  # noqa: E402
from session_keys import SessionKeys, load_session_keys  # noqa: E402

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
ROUTER_CONFIG = ROOT / "router" / "config.ini"
SCRATCH_ROOT = ROOT / ".scratch"
ROLES = ("current", "previous", "legacy")
FAMILY_OF = {"site-session": "site", "console-upgrade": "console", "console-session": "console"}
AUTH_VIA = "TokenGeneration_HostedAuth"   # Edge 的 TRUSTED_AUTH_SOURCES 之一，与真机 Cognito 签出的一致


def _strip(v: str) -> str:
    return v.split("#")[0].split(";")[0].strip()


def trusted_idp(router_config: Path = ROUTER_CONFIG) -> str:
    """Edge 实际信任的 idp（`trusted_idps` 第一项）。写死 "Feishu" 会让脚本在换 IdP 的环境上全红。"""
    rc = configparser.ConfigParser(interpolation=None)
    rc.read(router_config)
    for sec in rc.sections():
        if rc.has_option(sec, "trusted_idps"):
            first = _strip(rc.get(sec, "trusted_idps")).split(",")[0].strip()
            if first:
                return first
    raise SystemExit(f"{router_config} 里取不到 trusted_idps——签出来的会话 Edge 不认，验收不可信")


class Minter:
    def __init__(self, keys: SessionKeys, get_param, *, idp: str):
        self._keys = keys
        self._get_param = get_param
        self._idp = idp
        self._cache: dict[str, str] = {}

    @classmethod
    def from_config(cls, config_path: Path = CONFIG_PATH, router_config: Path = ROUTER_CONFIG, *,
                    ssm=None) -> "Minter":
        keys = load_session_keys(config_path)
        if ssm is None:
            import boto3
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read(config_path)
            region = _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1"
            ssm = boto3.client("ssm", region_name=region)
        return cls(keys, lambda name: ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"],
                   idp=trusted_idp(router_config))

    @property
    def keys(self) -> SessionKeys:
        return self._keys

    def _secret(self, param: str) -> str:
        if param not in self._cache:
            value = self._get_param(param)
            if not value:
                raise SystemExit(f"取不到 {param} 的值——无法签发会话，验收不可信")
            self._cache[param] = value
        return self._cache[param]

    def key(self, family: str, role: str) -> tuple[str | None, str]:
        """→ (kid 或 None（legacy）, secret)。previous 为空 / legacy 已清空都响亮失败，不回落。"""
        if role not in ROLES:
            raise SystemExit(f"role 必须是 {ROLES} 之一，得到 {role!r}")
        if role == "legacy":
            if not self._keys.legacy_param:
                raise SystemExit("[SessionKeys] legacy_param 为空（legacy 入口已关闭）——不能再 mint legacy 形态")
            return None, self._secret(self._keys.legacy_param)
        ref = self._keys.families[family][role]
        if ref is None:
            raise SystemExit(f"[SessionKeys] {family}_previous 为空——没有 previous key 可用于 mint")
        if ref.alg != "HS256":
            raise SystemExit(f"{ref.kid} 是 {ref.alg}，本模块只会 HS256 本地 mint（RS 是 3c-2A 的夹具签发器）")
        return ref.kid, self._secret(ref.ssm_param)

    def mint(self, token_use: str, email: str, *, role: str = "current", ttl_seconds: int,
             name: str | None = None, auth_via: str = AUTH_VIA) -> str:
        if token_use not in FAMILY_OF:
            raise SystemExit(f"token_use 必须是 {tuple(FAMILY_OF)} 之一，得到 {token_use!r}")
        name = email.split("@")[0] if name is None else name
        kid, secret = self.key(FAMILY_OF[token_use], role)
        if kid is None:                                   # legacy：旧形态、旧合同
            if token_use == "console-upgrade":
                return sess.mint_upgrade_code(email, secret, ttl_seconds=ttl_seconds)
            return sess.mint_session_jwt(email, name, secret, ttl_seconds=ttl_seconds, idp=self._idp,
                                         scope="console" if token_use == "console-session" else "",
                                         auth_via=auth_via)
        return sess.mint_token(kid=kid, secret=secret, token_use=token_use, email=email,
                               ttl_seconds=ttl_seconds, name=name, idp=self._idp, auth_via=auth_via)


# ---- 探针目标（kid 探针与语义闸门共用）-------------------------------------------------------

from dataclasses import dataclass  # noqa: E402


@dataclass(frozen=True)
class Target:
    subdomain: str
    owner: str
    base: str
    region: str

    @property
    def site_url(self) -> str:
        return f"https://{self.subdomain}.{self.base}/"

    @property
    def auth_host(self) -> str:
        return f"auth.{self.base}"

    @property
    def console_host(self) -> str:
        return f"console.{self.base}"


def live_target(config_path: Path = CONFIG_PATH, *, ddb=None) -> Target:
    """路由表里第一个 `require_auth=True` 且 owner 不是 platform 的站点（只读 scan）。

    探针冒充它的**真实 owner**——这是 3c-2A 常驻夹具站点（ADR-0002）就位前的过渡做法；2A 之后
    本函数改成返回夹具站点，调用方不动。"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    base = _strip(cfg["Platform"]["base_domain"])
    region = _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1"
    table = _strip(cfg["Platform"]["routing_table"])
    if ddb is None:
        import boto3
        ddb = boto3.resource("dynamodb", region_name=region)
    for it in ddb.Table(table).scan()["Items"]:
        if it.get("require_auth") is True and it.get("owner") != "platform":
            return Target(subdomain=str(it["subdomain"]), owner=str(it["owner"]), base=base, region=region)
    raise SystemExit(f"路由表 {table} 里找不到 require_auth=True 的非平台站点——探针没有目标")


# ---- 预存 / 读回（负向探针用）--------------------------------------------------------------

def save_token(path: Path, record: dict, *, scratch_root: Path = SCRATCH_ROOT) -> Path:
    """只许写进 `.scratch/`（gitignored）：token 是活凭证，不能落进任何可能被跟踪的位置。"""
    path = Path(path)
    root = Path(scratch_root).resolve()
    target = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if root != target and root not in target.parents:
        raise SystemExit(f"--save 只许写进 {root}（scratch，gitignored），拒绝 {path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, ensure_ascii=False, indent=1))
    return target


def load_saved_token(path: Path) -> tuple[str, str]:
    """→ (token_use, token)。"""
    try:
        rec = json.loads(Path(path).read_text())
        return rec["token_use"], rec["token"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"{path} 不是 --save 写出的记录（缺 token_use/token）：{exc}") from exc


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--token-use", required=True, choices=tuple(FAMILY_OF))
    ap.add_argument("--email", required=True)
    ap.add_argument("--role", default="current", choices=ROLES)
    ap.add_argument("--ttl", type=int, default=600, help="秒；升级码会被钳到 60")
    ap.add_argument("--save", required=True, metavar="FILE", help="写 JSON 记录（只许 .scratch/ 下）；不在终端打印 token")
    args = ap.parse_args(argv)
    m = Minter.from_config(CONFIG_PATH, ROUTER_CONFIG)
    kid, _ = m.key(FAMILY_OF[args.token_use], args.role)
    token = m.mint(args.token_use, args.email, role=args.role, ttl_seconds=args.ttl)
    out = save_token(Path(args.save), {"token_use": args.token_use, "role": args.role, "kid": kid,
                                       "email": args.email, "minted_at": int(time.time()),
                                       "ttl_seconds": args.ttl, "token": token},
                     scratch_root=SCRATCH_ROOT)
    print(f"已写 {out}：{args.token_use} role={args.role} kid={kid or 'legacy(无 kid)'}（token 不打印）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
