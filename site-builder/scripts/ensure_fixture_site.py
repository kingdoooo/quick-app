#!/usr/bin/env python3
"""幂等创建**常驻夹具站点**（spec §11.7 / ADR 0002）：`site_id = e2e-probe`、owner `probe@e2e.invalid`、
static 站点（fixtures/static-hello）、`require_login=True`、`allowed_users = [probe@e2e.invalid]`。

它是部署验收的一步（DEPLOY.md）：`verify_session_token_semantics.py` / `verify_kid_entry_live.py` 只打这个站点，
不再冒充任何真实 owner。绕过 MCP 直接起状态机（deploy_fixture.py 那条路，含 per-site 部署租约），
所以 owner 可以是夹具域——MCP 建站的 owner 是 OAuth 身份，夹具域没有 OAuth 身份。

三种起点都处理：不存在 / DELETED 墓碑 ⇒ 部署；存在但权限漂了 ⇒ 只收敛权限（经 permissions.set_access_policy，
真源 + 投影原子写）；存在但 owner 不是夹具域 ⇒ 拒绝（有人占了这个 site_id，不覆盖别人的站点）。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import configparser
import os
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import permissions  # noqa: E402
from _session_mint import FIXTURE_SITE_ID, PROBE_EMAIL  # noqa: E402  两个字面量的唯一定义

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
FIXTURE = "static-hello"


def _env_from_config(config_path: Path) -> None:
    """permissions.py 按环境变量找表（与 E2E 的 _platform_env 同一批键）。

    `setdefault` 而不是覆盖：单测在夹具里已经把这批键指向 moto 的表，覆盖会让它们去打真表名。
    """
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    if not cfg.sections():
        raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")

    def s(sec, key, default=None):
        return (cfg.get(sec, key, fallback=default) or "").split("#")[0].strip()

    os.environ.setdefault("SITES_TABLE", s("Deployer", "sites_table", "site-sites"))
    os.environ.setdefault("ADMINS_TABLE", s("Deployer", "admins_table", "site-admins"))
    os.environ.setdefault("OPS_LOG_TABLE", s("Panel", "ops_log_table", "site-ops-log"))
    os.environ.setdefault("ROUTING_TABLE", s("Platform", "routing_table"))
    os.environ.setdefault("BASE_DOMAIN", s("Platform", "base_domain"))
    os.environ.setdefault("AWS_DEFAULT_REGION", s("Platform", "region", "us-east-1") or "us-east-1")


def _deploy_default(fixture: str, owner: str, *, site_id=None, marker=None):
    """`deploy_fixture.main` 轮询到终态后 **`sys.exit(0/1)`**（它是给 CLI 写的）——成功的 exit 0 要吞掉，
    否则本函数还没来得及收敛权限就把进程带走了；非 0 原样上抛（部署失败不是本脚本能修的）。"""
    import deploy_fixture
    try:
        deploy_fixture.main(str(ROOT / "site-builder" / "fixtures" / fixture), owner, site_id=site_id, marker=marker)
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def ensure(config_path: Path = CONFIG_PATH, *, deploy=_deploy_default, ddb=None) -> dict:
    _env_from_config(config_path)
    ddb = ddb or boto3.client("dynamodb", region_name=os.environ["AWS_DEFAULT_REGION"])
    item = ddb.get_item(TableName=os.environ["SITES_TABLE"], Key={"site_id": {"S": FIXTURE_SITE_ID}},
                        ConsistentRead=True).get("Item") or {}
    owner = item.get("owner", {}).get("S", "")
    status = item.get("status", {}).get("S", "")
    deployed = False
    if item and status != "DELETED":
        if not permissions.is_fixture_email(owner):
            raise SystemExit(f"site_id {FIXTURE_SITE_ID} 已被 owner={owner!r} 占用，不是夹具域 @{permissions.FIXTURE_DOMAIN}"
                             "——不覆盖别人的站点；换 FIXTURE_SITE_ID 或先处理那个站点")
    else:
        print(f"  部署常驻夹具站点 {FIXTURE_SITE_ID}（{FIXTURE}，owner {PROBE_EMAIL}）…")
        deploy(FIXTURE, PROBE_EMAIL, site_id=FIXTURE_SITE_ID)
        deployed = True
        item = ddb.get_item(TableName=os.environ["SITES_TABLE"], Key={"site_id": {"S": FIXTURE_SITE_ID}},
                            ConsistentRead=True).get("Item") or {}
    # static fixture 的 site.json 是 `require_login: false` + `allowed_users: "org"`，所以首次部署之后
    # **必须**收敛一次：探针要的是"只有夹具身份能进"的私有站点。名单多一个人同样算漂移。
    want_users = [PROBE_EMAIL]
    have_login = item.get("require_login", {}).get("BOOL")
    have_users = ([x.get("S", "") for x in item["allowed_users"]["L"]]
                  if "L" in item.get("allowed_users", {}) else item.get("allowed_users", {}).get("S", ""))
    changed_needed = (have_login is not True or not isinstance(have_users, list)
                      or sorted(have_users) != want_users)
    changed = False
    if changed_needed:
        permissions.set_access_policy(FIXTURE_SITE_ID, actor=PROBE_EMAIL, require_login=True, allowed_users=want_users)
        changed = True
    print(f"  夹具站点 {FIXTURE_SITE_ID}：deployed={deployed} permissions_changed={changed} "
          f"→ https://app-{FIXTURE_SITE_ID}.{os.environ['BASE_DOMAIN']}/（只有 {PROBE_EMAIL} 能进）")
    return {"deployed": deployed, "permissions_changed": changed}


def main() -> int:
    ensure()
    return 0


if __name__ == "__main__":
    sys.exit(main())
