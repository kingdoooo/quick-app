#!/usr/bin/env python3
"""一次性迁移：把路由表里的权限现值回填到 sites 表（二期权限真源）。

背景：一期权限存在两处（site.json 每次部署携带 + 路由表 Edge 读），
sites 表没有权限字段。二期让 sites 表成为唯一真源，存量站点需要回填。

安全性：默认 dry-run 只报告；已有 require_login 字段的站点一律跳过
（那是二期之后写入的真源，不能被路由表旧值覆盖）。迁移期间 Edge 行为
不变（仍读路由表现值），无中断窗口。

用法：
    python3 site-builder/scripts/migrate_permissions.py           # dry-run
    python3 site-builder/scripts/migrate_permissions.py --apply   # 实际写入
"""
import argparse
import configparser
import json
import os
import sys
from pathlib import Path

import boto3

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))


def _load_config() -> None:
    """从 config.ini 填好 common/permissions 需要的环境变量。"""
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    os.environ.setdefault("SITES_TABLE", cfg["Deployer"]["sites_table"])
    os.environ.setdefault("JOBS_TABLE", cfg["Deployer"]["jobs_table"])
    os.environ.setdefault("ADMINS_TABLE", cfg["Deployer"]["admins_table"])
    os.environ.setdefault("AWS_DEFAULT_REGION", cfg["Platform"]["region"])


class UnparsableAllowlist(ValueError):
    pass


def _parse_allowed(raw) -> str | list[str]:
    """路由表的 allowed_users 现状：S 里存 "org" 或 JSON 数组字符串。

    **无法解析必须抛错，绝不降级为 "org"**：Edge 现行为是 JSON 解析失败即用
    空名单（仅 owner 可访问，fail-closed，origin_request.py:308-315）。若迁移
    把它写成 "org"，下一次部署会把这个值投影到路由表，权限从"仅 owner"扩大成
    "全体登录用户"——一次数据修复动作变成扩权。见 spec §3.4。
    """
    if "L" in raw:                       # 已是二期形态
        return [e["S"] for e in raw["L"]]
    value = raw.get("S", "org")
    if value == "org":
        return "org"
    try:
        parsed = json.loads(value)
    except Exception as e:
        raise UnparsableAllowlist(f"allowed_users 不是合法 JSON: {value!r}") from e
    if not isinstance(parsed, list):
        raise UnparsableAllowlist(f"allowed_users 解析后不是数组: {parsed!r}")
    return parsed


def migrate(routing_table: str, *, dry_run: bool = True) -> dict:
    import common
    import permissions

    ddb = boto3.client("dynamodb")
    report = {"scanned": 0, "migrated": [], "skipped": [], "errors": []}
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=routing_table):
        for item in page.get("Items", []):
            report["scanned"] += 1
            owner = item.get("owner", {}).get("S", "")
            if owner == "platform":      # auth-service / 控制台等平台路由无站点记录
                continue
            site_id = item.get("site_id", {}).get("S", "")
            site = common.get_site(site_id)
            if not site:
                report["errors"].append(
                    f"路由 {item['subdomain']['S']} 指向的站点 {site_id} 无 sites 记录")
                continue
            if "require_login" in site:
                report["skipped"].append(site_id)
                continue
            try:
                allowed = permissions.normalize_allowed_users(
                    _parse_allowed(item.get("allowed_users", {})))
            except ValueError as e:
                # UnparsableAllowlist 也是 ValueError 的子类，一并落在这里：
                # 报告并跳过，由人工判断原意后手工修——不自动放宽。
                report["errors"].append(f"{site_id}: allowed_users 无法规范化（{e}）")
                continue
            report["migrated"].append(site_id)
            if dry_run:
                continue
            common.upsert_site(
                site_id,
                require_login=bool(item.get("require_auth", {}).get("BOOL", True)),
                allowed_users=allowed,
                collaborators=list(site.get("collaborators") or []),
                permissions_updated_at=permissions.now_iso(),
                permissions_updated_by="migration")
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写入（默认只报告）")
    args = ap.parse_args()
    _load_config()
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    report = migrate(cfg["Platform"]["routing_table"], dry_run=not args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] 扫描 {report['scanned']} 条路由")
    print(f"  迁移: {len(report['migrated'])} {report['migrated']}")
    print(f"  跳过（已有真源）: {len(report['skipped'])} {report['skipped']}")
    if report["errors"]:
        print(f"  问题: {len(report['errors'])}")
        for e in report["errors"]:
            print(f"    - {e}")
    if not args.apply and report["migrated"]:
        print("\n确认无误后加 --apply 实际写入")


if __name__ == "__main__":
    main()
