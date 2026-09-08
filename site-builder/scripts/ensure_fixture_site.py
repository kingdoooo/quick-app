#!/usr/bin/env python3
"""幂等创建**常驻夹具站点**（spec §11.7 / ADR 0002）：`site_id = e2e-probe`、owner `probe@e2e.invalid`、
static 站点（fixtures/static-hello）、`require_login=True`、`allowed_users = [probe@e2e.invalid]`。

它是部署验收的一步（DEPLOY.md）：`verify_session_token_semantics.py` / `verify_kid_entry_live.py` 只打这个站点，
不再冒充任何真实 owner。绕过 MCP 直接起状态机（deploy_fixture.py 那条路，含 per-site 部署租约），
所以 owner 可以是夹具域——MCP 建站的 owner 是 OAuth 身份，夹具域没有 OAuth 身份。

四种起点都处理：
- sites 行不存在 / `DELETED` 墓碑 ⇒ 部署；
- **路由行不存在** ⇒ 同样按"没部署过"处理（只有部署路径会建路由行：`write_permissions` 的投影带
  `attribute_exists(subdomain)`，它纠正投影、不补建路由）；
- sites 行或路由行的权限漂了 ⇒ 只收敛权限（经 `permissions.set_access_policy`，真源 + 投影原子写）；
- sites 行存在但 owner 不是夹具域 ⇒ 拒绝（有人占了这个 site_id，不覆盖别人的站点）。

**返回前一定读回路由行核对**（`require_auth is True` 且 `owner == PROBE_EMAIL`，也就是
`_session_mint.live_target` 找目标用的那两个条件）：不核对的话存在一种最坏形态——本脚本打印
`deployed=False permissions_changed=False`（看起来一切正常），而闸门继续以"先跑 ensure_fixture_site.py"
失败，把操作者指回一个刚说"没问题"的脚本。事务在路由行缺失时会返回 `route_synced=False`
（真源写了、投影没写），那正是这种形态。

**取值只认 config.ini**：六个环境变量在本函数执行期间被**无条件覆盖**成 config 的值、退出时还原。
`setdefault` 是错的——一个陈旧的 `AWS_DEFAULT_REGION` export 会让本脚本去另一个区读 sites 表，
而 `deploy_fixture` 按 config 部署 ⇒ 每次都判成"不存在"并重新部署（幂等性没了），或者把权限写进错误的区。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import configparser
import contextlib
import os
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402  子域格式的唯一定义（路由行的 key）
import permissions  # noqa: E402
# 两个字面量与**闸门找目标那段逻辑**的唯一定义。读回核对直接调 `live_target`，不在这里复述它的判据
# （复述就会漂，而漂的症状正是本脚本要消灭的那种：脚本说完成、闸门说没有目标）。
from _session_mint import FIXTURE_SITE_ID, PROBE_EMAIL, live_target  # noqa: E402

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
FIXTURE = "static-hello"
# permissions.py 与 common.py 按环境变量找表（它们本来是 Lambda 里的模块）。
# 值全部来自 config.ini，**不接受环境变量覆盖**——见模块 docstring 最后一段。
_ENV_FROM_CONFIG = (("SITES_TABLE", "Deployer", "sites_table", "site-sites"),
                    ("ADMINS_TABLE", "Deployer", "admins_table", "site-admins"),
                    ("OPS_LOG_TABLE", "Panel", "ops_log_table", "site-ops-log"),
                    ("ROUTING_TABLE", "Platform", "routing_table", None),
                    ("BASE_DOMAIN", "Platform", "base_domain", None),
                    ("AWS_DEFAULT_REGION", "Platform", "region", "us-east-1"))


@contextlib.contextmanager
def _config_env(config_path: Path):
    """把 config.ini 的表名/域名/区域**无条件**导成环境变量，退出时还原（同 E2E 的 `_platform_env`）。

    还原是因为本函数是可被 import 调用的（单测、将来的验收编排）：留下六个进程级副作用会污染
    同一进程里的其它调用方，而那种污染的症状是"另一个模块忽然去错的表读数"。
    """
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    if not cfg.sections():
        raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")
    want = {}
    for key, section, option, default in _ENV_FROM_CONFIG:
        raw = cfg.get(section, option, fallback=default) or ""
        want[key] = raw.split("#")[0].strip() or (default or "")
    missing = sorted(k for k, v in want.items() if not v)
    if missing:
        raise SystemExit(f"{config_path} 里这些取值是空的：{missing}——回填后再跑"
                         "（config.ini 是唯一取值来源，本脚本不从环境变量兜底）")
    saved = {k: os.environ.get(k) for k in want}
    os.environ.update(want)
    try:
        yield want
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _deploy_default(fixture: str, owner: str, *, site_id=None, marker=None):
    """`deploy_fixture.main` 轮询到终态后 **`sys.exit(0/1)`**（它是给 CLI 写的）——成功的 exit 0 要吞掉，
    否则本函数还没来得及收敛权限就把进程带走了；非 0 原样上抛（部署失败不是本脚本能修的）。"""
    import deploy_fixture
    try:
        deploy_fixture.main(str(ROOT / "site-builder" / "fixtures" / fixture), owner, site_id=site_id, marker=marker)
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def _site_row(ddb) -> dict:
    return ddb.get_item(TableName=os.environ["SITES_TABLE"], Key={"site_id": {"S": FIXTURE_SITE_ID}},
                        ConsistentRead=True).get("Item") or {}


def _route_row(ddb) -> dict:
    return ddb.get_item(TableName=os.environ["ROUTING_TABLE"],
                        Key={"subdomain": {"S": common.subdomain_for(FIXTURE_SITE_ID)}},
                        ConsistentRead=True).get("Item") or {}


def _wanted_users() -> list:
    return [PROBE_EMAIL]


def _site_needs_convergence(site: dict) -> bool:
    """static fixture 的 site.json 是 `require_login: false` + `allowed_users: "org"`，所以首次部署之后
    **必须**收敛一次：探针要的是"只有夹具身份能进"的私有站点。名单多一个人同样算漂移。"""
    if site.get("require_login", {}).get("BOOL") is not True:
        return True
    if "L" not in site.get("allowed_users", {}):
        return True
    return sorted(x.get("S", "") for x in site["allowed_users"]["L"]) != _wanted_users()


def _gate_target(config_path: Path):
    """闸门（`_session_mint.live_target`）在**当前**路由表里找得到的目标，找不到返回 None。

    **判据不在这里复述**：闸门筛的是"这条路由需要登录、且 owner 是探针身份"，本脚本若自己再写一份
    同义条件，两边一旦漂开就会出现"脚本说完成、闸门说先跑脚本"的死循环——那正是要消灭的形态。

    它自己建 resource 级客户端（Table API），与本模块用的 client 是两个对象但同一份配置；
    `SystemExit` 在这里只可能来自"没有夹具站点"——配置本身已经由 `_config_env` 校验过非空。
    """
    try:
        return live_target(config_path)
    except SystemExit:
        return None


def _route_users_drifted(route: dict) -> bool:
    """路由投影上的名单漂了没有（`live_target` 不看名单，所以这一条要自己判）。"""
    if "L" not in route.get("allowed_users", {}):
        return True
    return sorted(x.get("S", "") for x in route["allowed_users"]["L"]) != _wanted_users()


def ensure(config_path: Path = CONFIG_PATH, *, deploy=_deploy_default, ddb=None) -> dict:
    with _config_env(config_path) as env:
        ddb = ddb or boto3.client("dynamodb", region_name=env["AWS_DEFAULT_REGION"])
        site = _site_row(ddb)
        if site and site.get("status", {}).get("S") != "DELETED":
            owner = site.get("owner", {}).get("S", "")
            if not permissions.is_fixture_email(owner):
                raise SystemExit(f"site_id {FIXTURE_SITE_ID} 已被 owner={owner!r} 占用，不是夹具域 "
                                 f"@{permissions.FIXTURE_DOMAIN}——不覆盖别人的站点；"
                                 "换 FIXTURE_SITE_ID 或先处理那个站点")
            live = True
        else:
            live = False
        route = _route_row(ddb)
        deployed = False
        if not live or not route:
            why = "sites 行缺失或已是墓碑" if not live else "路由行缺失（只有部署路径会建它）"
            print(f"  部署常驻夹具站点 {FIXTURE_SITE_ID}（{FIXTURE}，owner {PROBE_EMAIL}）：{why}…")
            deploy(FIXTURE, PROBE_EMAIL, site_id=FIXTURE_SITE_ID)
            deployed = True
            site, route = _site_row(ddb), _route_row(ddb)
        changed = False
        if _site_needs_convergence(site) or _route_users_drifted(route) or _gate_target(config_path) is None:
            permissions.set_access_policy(FIXTURE_SITE_ID, actor=PROBE_EMAIL, require_login=True,
                                          allowed_users=_wanted_users())
            changed = True
        # 读回核对（见模块 docstring）：**用闸门自己那段查找**，不核对就会出现
        # "本脚本说没问题、闸门说先跑本脚本"的死循环。
        if _gate_target(config_path) is None:
            route = _route_row(ddb)
            # 整行打出来（夹具站点的行里没有敏感值），不在这里逐个点名字段：闸门的判据只有它自己
            # 那一份定义，本脚本复述任何一个字段名都会变成第二份判据。
            raise SystemExit(
                f"收敛之后闸门在路由表里仍然找不到 {common.subdomain_for(FIXTURE_SITE_ID)}"
                f"（当前那行：{route or '不存在'}）——"
                "常见原因是权限事务的投影那一半没写成（返回 route_synced=False，真源已写、路由没写）。"
                "先看这条路由行是否存在、是否被别的写入方踩过，再重跑本脚本")
        print(f"  夹具站点 {FIXTURE_SITE_ID}：deployed={deployed} permissions_changed={changed} "
              f"→ https://{common.subdomain_for(FIXTURE_SITE_ID)}.{env['BASE_DOMAIN']}/"
              f"（只有 {PROBE_EMAIL} 能进）")
        return {"deployed": deployed, "permissions_changed": changed}


def main() -> int:
    ensure()
    return 0


if __name__ == "__main__":
    sys.exit(main())
