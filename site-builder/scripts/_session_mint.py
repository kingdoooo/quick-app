#!/usr/bin/env python3
"""验收工具唯一的登录态入口（3c-final；spec §11.7 / ADR 0002）：**夹具签发器的客户端**。

四个 `verify_*`、`verify_kid_entry_live.py` 与 E2E 的会话 cookie fixture 都从这里拿 token；本模块**不持有
任何密钥**（KMS 之后本地也拿不到）。三条路：
- 站点会话：`sts.assume_role(site-builder-verifier)`（只有 `[Verification] verifier_trusted_principals` 里列的
  principal 能 assume）→ SigV4 `POST` auth 的 Function URL `/fixture-session` → 只给夹具域 `@e2e.invalid`、
  TTL ≤ 30 min、`role=current|previous`（就位期探针用 previous）。
- 升级码：拿夹具站点会话走**真实**的 `GET https://auth.{base}/console-session`，从 302 Location 里取 code。
- 面板会话：再 `GET https://console.{base}/api/session-callback?code=…`（经 CloudFront → Edge → panel），
  从 Set-Cookie 里取 `__Host-sb_console`。**这一步会消费那枚一次性升级码**（session-codes 表多一行，1 h TTL）。
所以带外签发的只有一种 token、一个域（ADR 0002）；`family=` 覆盖已删——KMS 之后没有任何组件能带外签 console
family，"console kid 签 site-session"这类跨 family 反例改由单测 + 产物公钥对账证明（plan D3）。

调用方接口沿用 `Minter.mint(token_use, email, ttl_seconds=, role=, name=)`。`--save FILE` 只许写进 `.scratch/`。
用不带路径的 python3 跑（CLAUDE.md）。

    python3 site-builder/scripts/_session_mint.py --token-use site-session --email probe@e2e.invalid \
        --role previous --ttl 600 --save rotation/site-previous.json
"""
from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))
from permissions import FIXTURE_DOMAIN, is_fixture_email  # noqa: E402  夹具域的唯一定义（与 auth/session.py 等值）
if str(Path(__file__).resolve().parent) not in sys.path:      # 被 tests / E2E 以别的 cwd import 时
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from _secure_write import write_private_text  # noqa: E402

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
SCRATCH_ROOT = ROOT / ".scratch"
ROLES = ("current", "previous")
TOKEN_USES = ("site-session", "console-upgrade", "console-session")
VERIFIER_ROLE_NAME = "site-builder-verifier"
AUTH_FN = "site-auth-service"
PROBE_EMAIL = f"probe@{FIXTURE_DOMAIN}"
FIXTURE_SITE_ID = "e2e-probe"
FIXTURE_MAX_TTL = 1800


def _strip(v: str) -> str:
    return v.split("#")[0].split(";")[0].strip()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _urllib_http(method: str, url: str, headers: dict, body: str | None):
    """→ (status, headers（http.client.HTTPMessage，支持 get_all）, text)。不跟随 302——Location 就是要读的东西。"""
    req = urllib.request.Request(url, method=method, headers=headers, data=body.encode() if body else None)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.headers, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode(errors="replace")


def _hdr(headers, name: str):
    """大小写不敏感取头；`set-cookie` 取全部（urllib 的 HTTPMessage 与测试替身的 dict 都支持）。"""
    if hasattr(headers, "get_all"):
        vals = headers.get_all(name) or []
        return vals if name.lower() == "set-cookie" else (vals[0] if vals else "")
    for k, v in headers.items():
        if k.lower() == name.lower():
            if name.lower() != "set-cookie":
                return v
            return v if isinstance(v, list) else [v]
    return [] if name.lower() == "set-cookie" else ""


def _require_fixture_email(email) -> None:
    if not is_fixture_email(email):
        raise SystemExit(f"验收身份必须是 <local>@{FIXTURE_DOMAIN}（ADR 0002），得到 {email!r}——签发器也会拒，这里提前停")


class Minter:
    """夹具签发器客户端。`http(method, url, headers, body) -> (status, headers, text)` 可替换（测试）。"""

    def __init__(self, *, base_domain: str, region: str, account_id: str, function_url: str, session, http=None):
        self.base = base_domain
        self.region = region
        self.account_id = account_id
        self.function_url = function_url if function_url.endswith("/") else function_url + "/"
        self._session = session          # boto3.Session（或测试替身）；凭据不缓存，每次 mint 现 assume（D11）
        self._http = http or _urllib_http

    @classmethod
    def from_config(cls, config_path: Path = CONFIG_PATH, *, session=None, http=None) -> "Minter":
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(config_path)
        if not cfg.sections():
            raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")
        if _strip(cfg.get("Verification", "fixture_issuer", fallback="false")).lower() != "true":
            raise SystemExit("config.ini [Verification] fixture_issuer 不是 true——验收工具的登录态来自 auth 的 /fixture-session"
                             "（ADR 0002），先开它并重部 auth（deploy_auth.py 会建 site-builder-verifier 角色）")
        base = _strip(cfg["Platform"]["base_domain"])
        region = _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1"
        account = _strip(cfg["Platform"]["account_id"])
        if session is None:
            import boto3
            session = boto3.Session()
        url = session.client("lambda", region_name=region).get_function_url_config(FunctionName=AUTH_FN)["FunctionUrl"]
        return cls(base_domain=base, region=region, account_id=account, function_url=url, session=session, http=http)

    def _verifier_credentials(self) -> dict:
        """每次 mint 现 assume（D11）：角色会话上限 3600 s 而 E2E 约 37 min，缓存一份会贴着上限过期，症状是
        Function URL 403、读起来像授权配错。900 s 是 STS 允许的最小 DurationSeconds，一枚凭据只签一个请求。"""
        return self._session.client("sts", region_name=self.region).assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{VERIFIER_ROLE_NAME}",
            RoleSessionName=f"verify-{os.getpid()}-{int(time.time())}", DurationSeconds=900)["Credentials"]

    # ---- 站点会话：带外签发的唯一一种 token ----

    def site_session(self, email: str, *, ttl_seconds: int = FIXTURE_MAX_TTL, name: str | None = None,
                     role: str = "current") -> str:
        _require_fixture_email(email)
        if role not in ROLES:
            raise SystemExit(f"role 必须是 {ROLES} 之一，得到 {role!r}")
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        body = json.dumps({"email": email, "ttl_seconds": int(ttl_seconds),
                           "name": name or email.split("@")[0], "role": role})
        url = self.function_url + "fixture-session"
        req = AWSRequest(method="POST", url=url, data=body,
                         headers={"content-type": "application/json", "host": urllib.parse.urlparse(url).netloc})
        creds = self._verifier_credentials()
        SigV4Auth(Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]),
                  "lambda", self.region).add_auth(req)
        status, _, text = self._http("POST", url, dict(req.headers), body)
        if status != 200:
            # **不 JSON 解析非 200 的 body**：签发器的错误体是纯文本（没有 content-type），
            # 解析它会把"403 forbidden"变成一个 JSONDecodeError，报文与真因无关。
            raise SystemExit(f"/fixture-session 返回 {status}：{text[:200]}——"
                             "403 = 调用者不是 site-builder-verifier（本机凭据不在 verifier_trusted_principals 里？）；"
                             "404 = auth 没开 FIXTURE_ISSUER（重部 auth）")
        return json.loads(text)["token"]

    # ---- 升级码与面板会话：真实换取链路 ----

    def upgrade_code(self, email: str, *, site_session: str | None = None) -> str:
        tok = site_session or self.site_session(email)
        status, headers, _ = self._http("GET", f"https://auth.{self.base}/console-session",
                                        {"cookie": f"sb_session={tok}"}, None)
        loc = _hdr(headers, "location")
        if status != 302 or "/api/session-callback?code=" not in loc:
            raise SystemExit(f"/console-session 没有换出升级码：{status} {loc[:120]}——夹具站点会话没被 auth 接受？")
        return urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]

    def console_session(self, email: str, *, site_session: str | None = None) -> str:
        tok = site_session or self.site_session(email)
        code = self.upgrade_code(email, site_session=tok)
        status, headers, text = self._http(
            "GET", f"https://console.{self.base}/api/session-callback?code={urllib.parse.quote(code, safe='')}",
            {"cookie": f"sb_session={tok}"}, None)
        for c in _hdr(headers, "set-cookie"):
            name, _, rest = c.partition("=")
            if name.strip() == "__Host-sb_console":
                return rest.split(";")[0]
        raise SystemExit(f"/api/session-callback 没有下发面板会话：{status} {text[:120]}——panel 拒了升级码（夹具身份被 Edge 302？）")

    def mint(self, token_use: str, email: str, *, ttl_seconds: int = FIXTURE_MAX_TTL, role: str = "current",
             name: str | None = None) -> str:
        """六处调用方的兼容入口。`console-*` 两种 token 不接受 role/ttl（真实链路决定）。"""
        if token_use == "site-session":
            return self.site_session(email, ttl_seconds=ttl_seconds, name=name, role=role)
        if token_use == "console-upgrade":
            return self.upgrade_code(email)
        if token_use == "console-session":
            return self.console_session(email)
        raise SystemExit(f"token_use 必须是 {TOKEN_USES} 之一，得到 {token_use!r}")


# ---- 探针目标：常驻夹具站点 ---------------------------------------------------------------

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


def _platform_bits(config_path: Path) -> tuple[str, str, str]:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    if not cfg.sections():
        raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")
    return (_strip(cfg["Platform"]["base_domain"]),
            _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1",
            _strip(cfg["Platform"]["routing_table"]))


def _scan_routes(table: str, region: str, ddb):
    """路由表全表只读扫描（**必须翻页**，3c-1B-G A5）。

    `scan()` 单次最多返回 1 MB，丢掉 `LastEvaluatedKey` 就等于只看第一页。路由表每部署一个站点
    多一行，一旦超过一页而首页恰好没有目标行，调用方就会以"没有目标"失败——报文指向路由表内容，
    而真因是分页，排查方向全错。
    """
    if ddb is None:
        import boto3
        ddb = boto3.resource("dynamodb", region_name=region)
    t = ddb.Table(table)
    kwargs: dict = {}
    while True:
        page = t.scan(**kwargs)
        yield from page.get("Items", [])
        last = page.get("LastEvaluatedKey")
        if not last:
            return
        kwargs["ExclusiveStartKey"] = last


def live_target(config_path: Path = CONFIG_PATH, *, ddb=None) -> Target:
    """路由表里 owner == PROBE_EMAIL 且 require_auth=True 的那条（常驻夹具站点，ensure_fixture_site.py 建）。
    不再冒充任何真实 owner（ADR 0002）。"""
    base, region, table = _platform_bits(config_path)
    for it in _scan_routes(table, region, ddb):
        if it.get("require_auth") is True and it.get("owner") == PROBE_EMAIL:
            return Target(subdomain=str(it["subdomain"]), owner=PROBE_EMAIL, base=base, region=region)
    raise SystemExit(f"路由表 {table} 里没有 owner={PROBE_EMAIL} 的常驻夹具站点——先跑 "
                     "python3 site-builder/scripts/ensure_fixture_site.py（已翻完所有页）")


def org_target(config_path: Path = CONFIG_PATH, *, ddb=None) -> Target | None:
    """一条**真实**的 org 站点路由（`allowed_users == "org"`、owner 不是夹具域、require_auth=True），没有则 None。

    ADR 0002 的边界判据要打它：`allowed_users="org"` 的站点会放行任何可信来源的邮箱，所以"夹具会话投给
    真实 org 站点必 302"才是那条边界的真机证据。夹具站点自己即使是 org 也不算——那条判据会退化成正对照。
    账号里没有这种站点时返回 None，闸门据此报 skip 而不是失败（干净账号上本来就没有）。
    """
    base, region, table = _platform_bits(config_path)
    for it in _scan_routes(table, region, ddb):
        owner = it.get("owner")
        if (it.get("require_auth") is True and it.get("allowed_users") == "org"
                and isinstance(owner, str) and not is_fixture_email(owner) and owner != "platform"):
            return Target(subdomain=str(it["subdomain"]), owner=owner, base=base, region=region)
    return None


# ---- 预存 / 读回（负向探针用）--------------------------------------------------------------

def save_token(path: Path, record: dict, *, scratch_root: Path = SCRATCH_ROOT) -> Path:
    """只许写进 `.scratch/`（gitignored）：token 是活凭证，不能落进任何可能被跟踪的位置。

    **相对路径按 `scratch_root` 解析，但开头写不写 `.scratch/` 都一样**（3c-1B ticket 17 第 6 条）：
    仓库文档里两种写法都出现过（本模块 docstring 用 `.scratch/…`、runbook 用 `rotation/…`），
    而"多嵌一层 `.scratch/.scratch/`"是**静默**的——命令照样成功，只有用 `--retired-token`
    读回（那个旗标按 cwd 解析）时才以"不是 --save 写出的记录"失败；到那一刻配置已改、三处已重部，
    退役那一步更是已经把 previous 从 config 删掉、token 无法重签。所以这里把前缀吃掉，而不是让它嵌套。
    逃逸检查在**吃掉前缀之后**做，`.scratch/../x` 仍然被拒。

    **权限 0600 / 目录 0700**（第 13 条）：记录里是一枚可直接重放的会话 cookie，
    默认 umask 会落成 0644 ⇒ 同机任何账号都能读它、以夹具身份访问夹具站点。
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
    # **已存在的目录同样收到 0700**（复审低优先级 2）：只改新建的那几层，等于承诺"目录 0700"
    # 只对新克隆成立——本仓库的 `.scratch/` 与子目录实测就是 0755。范围只到
    # scratch 根为止（`root in d.parents or d == root`），不碰仓库根以上的任何目录。
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for d in (target.parent, *target.parent.parents):
        if d == root or root in d.parents:
            os.chmod(d, 0o700)
    # 同目录 0600 临时文件 + os.replace（`_secure_write`）：`write_text` 有 0644 窗口；此前的
    # `os.open(..., 0o600)` 对已有文件不生效、且会跟随 symlink 去改写别的文件（复审三轮）。
    return write_private_text(target, json.dumps(record, ensure_ascii=False, indent=1))


def load_saved_token(path: Path) -> tuple[str, str]:
    """→ (token_use, token)。"""
    try:
        rec = json.loads(Path(path).read_text())
        return rec["token_use"], rec["token"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"{path} 不是 --save 写出的记录（缺 token_use/token）：{exc}") from exc


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--token-use", required=True, choices=("site-session", "console-upgrade"),
                    help="面板会话记录不接受：panel 只在写请求上验它，探针只发 GET")
    ap.add_argument("--email", default=PROBE_EMAIL)
    ap.add_argument("--role", default="current", choices=ROLES)
    ap.add_argument("--ttl", type=int, default=600, help="秒（≤ 1800）；升级码由链路决定 60 s")
    ap.add_argument("--save", required=True, metavar="FILE", help="写 JSON 记录（只许 .scratch/ 下）；不在终端打印 token")
    args = ap.parse_args(argv)
    m = Minter.from_config(CONFIG_PATH)
    token = m.mint(args.token_use, args.email, role=args.role, ttl_seconds=args.ttl)
    head = token.split(".")[0]
    kid = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))).get("kid")
    out = save_token(Path(args.save), {"token_use": args.token_use, "role": args.role, "kid": kid,
                                       "email": args.email, "minted_at": int(time.time()),
                                       "ttl_seconds": args.ttl, "token": token}, scratch_root=SCRATCH_ROOT)
    print(f"已写 {out}：{args.token_use} role={args.role} kid={kid}（token 不打印）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
