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
        --role legacy --ttl 600 --save 3c-1b/legacy-site.json   # 相对 .scratch/；写成 .scratch/3c-1b/… 也一样
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
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
             name: str | None = None, auth_via: str = AUTH_VIA, family: str | None = None) -> str:
        """按 `token_use` 签一枚 token；`family` 可**显式覆盖**签名用的 key family。

        缺省（`family=None`）走 `FAMILY_OF[token_use]`，与全部既有调用方一致。

        **`family` 是给 family-separation 探针用的，不是给生产用的**（3c-1B-G A1）：
        只有"console kid 签的 `token_use=site-session`"这一种**跨 family 同形态** token
        能单独证明"console kid 不在 site allowlist"。不给这个覆盖的话，探针只能造出
        "console kid + console-session"，它同时改了 kid family 与 token_use 两个变量
        ⇒ Edge 的 302 可能来自任一条 ⇒ allowlist 真的失守时闸门照旧全绿
        （`test_edge_accepts_the_cross_family_token_once_the_console_kid_leaks_in` 是那条反例）。
        """
        if token_use not in FAMILY_OF:
            raise SystemExit(f"token_use 必须是 {tuple(FAMILY_OF)} 之一，得到 {token_use!r}")
        if family is not None and family not in self._keys.families:
            raise SystemExit(f"family 必须是 {tuple(self._keys.families)} 之一，得到 {family!r}")
        name = email.split("@")[0] if name is None else name
        kid, secret = self.key(FAMILY_OF[token_use] if family is None else family, role)
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
    # **必须翻页**（3c-1B-G A5）：`scan()` 单次最多返回 1 MB，丢掉 `LastEvaluatedKey` 就等于
    # 只看第一页。路由表每部署一个站点多一行，一旦超过一页而首页恰好只有公开站点与平台行，
    # 本函数就会以"探针没有目标"失败——报文指向路由表内容，而真因是分页，排查方向全错。
    t = ddb.Table(table)
    kwargs: dict = {}
    while True:
        page = t.scan(**kwargs)
        for it in page.get("Items", []):
            if it.get("require_auth") is True and it.get("owner") != "platform":
                return Target(subdomain=str(it["subdomain"]), owner=str(it["owner"]),
                              base=base, region=region)
        last = page.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last
    raise SystemExit(f"路由表 {table} 里找不到 require_auth=True 的非平台站点——探针没有目标"
                     "（已翻完所有页）")


# ---- 预存 / 读回（负向探针用）--------------------------------------------------------------

def save_token(path: Path, record: dict, *, scratch_root: Path = SCRATCH_ROOT) -> Path:
    """只许写进 `.scratch/`（gitignored）：token 是活凭证，不能落进任何可能被跟踪的位置。

    **相对路径按 `scratch_root` 解析，但开头写不写 `.scratch/` 都一样**（3c-1B ticket 17 第 6 条）：
    仓库文档里两种写法都出现过（本模块 docstring 用 `.scratch/…`、runbook 用 `rotation/…`），
    而"多嵌一层 `.scratch/.scratch/`"是**静默**的——命令照样成功，只有 ⑤/⑩ 用 `--retired-token`
    读回（那个旗标按 cwd 解析）时才以"不是 --save 写出的记录"失败；到那一刻配置已改、三处已重部，
    ⑩ 更是已经把 previous 从 config 删掉、token 无法重签。所以这里把前缀吃掉，而不是让它嵌套。
    逃逸检查在**吃掉前缀之后**做，`.scratch/../x` 仍然被拒。

    **权限 0600 / 目录 0700**（第 13 条）：记录里是一枚可直接重放的会话 cookie，
    默认 umask 会落成 0644 ⇒ 同机任何账号都能读它、以目标站点 owner 的身份访问站点。
    """
    root = Path(scratch_root).resolve()
    path = Path(path)
    if not path.is_absolute() and path.parts and path.parts[0] == root.name:
        path = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
    target = (root / path).resolve() if not path.is_absolute() else path.resolve()
    # `--save .scratch` 会把前缀吃成空路径 ⇒ target == root ⇒ 逃逸检查放行，然后
    # `os.open` 对着目录抛裸 `IsADirectoryError`（3c-1B-G A5）。显式拒绝，给一句能读的话。
    if target == root or target.is_dir():
        raise SystemExit(f"--save 要给一个文件路径（相对 {root}），不能是目录：{path}")
    if root not in target.parents:
        raise SystemExit(f"--save 只许写进 {root}（scratch，gitignored），拒绝 {path}")
    # `mkdir(mode=…)` **不作用于它顺带创建的父目录**（CPython 明确：父目录按默认权限建），
    # 所以新克隆上第一次用会留下 0755 的 `.scratch/`，而 docstring 承诺的是 0700。
    # 逐层建 + 逐层收权限（3c-1B-G A5）。
    missing = [d for d in (target.parent, *target.parent.parents) if not d.exists()]
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for d in missing:
        if root == d or root in d.parents or d == root:
            os.chmod(d, 0o700)
    # 先建后改：write_text 不接受 mode，而"先写再 chmod"有一个短暂的 0644 窗口 ⇒ 用 os.open 定死
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, indent=1))
    os.chmod(target, 0o600)      # 文件已存在时 O_CREAT 的 mode 不生效，显式收一次
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
