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
    """从 config.ini 填好 common/permissions 需要的环境变量。

    **直接赋值，不用 setdefault**：config.ini 是部署脚本的唯一取值来源
    （CLAUDE.md），setdefault 会让 shell 里残留的旧 SITES_TABLE 静默改写
    写入目标。config.ini 缺失时立刻报错，不留到 KeyError('Deployer')。
    """
    path = HERE.parent / "config.ini"
    if not path.exists():
        raise SystemExit(f"找不到 {path}——从 config.ini.example 复制并填好再跑")
    cfg = configparser.ConfigParser()
    cfg.read(path)
    # 一期建的 config.ini 没有 admins_table / routing_table 这些二期键：
    # 裸 KeyError 不告诉操作者补哪一行，这里换成可执行的提示。
    try:
        os.environ["SITES_TABLE"] = cfg["Deployer"]["sites_table"]
        os.environ["ADMINS_TABLE"] = cfg["Deployer"]["admins_table"]
        os.environ["AWS_DEFAULT_REGION"] = cfg["Platform"]["region"]
    except KeyError as e:
        raise SystemExit(
            f"config.ini 缺少 {e}——二期新增的键，一期建的 config.ini 里没有。"
            "\n对照 config.ini.example 补齐 [Deployer] admins_table"
            "（默认 site-admins）。") from e


class UnparsableAllowlist(ValueError):
    pass


def _parse_allowed(raw) -> str | list[str]:
    """路由表的 allowed_users 现状：S 里存 "org" 或 JSON 数组字符串。

    **无法解析必须抛错，绝不降级为 "org"**：Edge 现行为是 JSON 解析失败即用
    空名单（仅 owner 可访问，fail-closed，origin_request.py:308-315）。若迁移
    把它写成 "org"，下一次部署会把这个值投影到路由表，权限从"仅 owner"扩大成
    "全体登录用户"——一次数据修复动作变成扩权。见 spec §3.4。

    **未知 AttributeValue 类型同样必须抛错**：不能写 raw.get("S", "org")——
    SS/NULL/N/BOOL 会双双错过 S 和 L 分支、静默落成 "org"（moto 探针实锤过）。
    这不是理论场景：spec §3.4 的救济流程就是"人工判断原意后手工修"，而人在
    DynamoDB 控制台给字符串列表选的类型就是 String Set——修完一重跑，owner-only
    变全组织放行。只有"属性整体缺失"才回落 "org"（Edge 的默认正是如此：
    route.get("allowed_users", "org")）。
    """
    if "L" in raw:                       # 已是二期形态
        members = raw["L"]
        if not all(isinstance(e, dict) and "S" in e for e in members):
            raise UnparsableAllowlist(
                f"allowed_users 的 L 含非字符串成员: {members!r}")
        return [e["S"] for e in members]
    if not raw:                          # 属性缺失：与 Edge 的默认一致
        return "org"
    if "S" not in raw:
        raise UnparsableAllowlist(
            f"allowed_users 类型不支持（应为 S/L）: {sorted(raw)}")
    value = raw["S"]
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
    import botocore.exceptions
    import common
    import permissions

    ddb = boto3.client("dynamodb")
    report = {"scanned": 0, "migrated": [], "skipped": [], "errors": [],
              "planned": {}}
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=routing_table):
        for item in page.get("Items", []):
            report["scanned"] += 1
            # 整个单条处理都在 try 里：一条畸形路由（缺 site_id、L 里混 NULL、
            # 空字符串键……）**不能中止整个扫描**——apply 模式下中止意味着
            # 半套迁移 + 没有报告，操作者不知道停在哪。逐条収进 errors 继续。
            try:
                owner = item.get("owner", {}).get("S", "")
                if owner == "platform":  # auth-service / 控制台等平台路由无站点记录
                    continue
                site_id = item.get("site_id", {}).get("S", "")
                if not site_id:
                    report["errors"].append(
                        f"路由 {item.get('subdomain', {}).get('S', '?')} 缺 site_id")
                    continue
                site = common.get_site(site_id)
                if not site:
                    report["errors"].append(
                        f"路由 {item['subdomain']['S']} 指向的站点 {site_id} 无 sites 记录")
                    continue
                # **两个字段都在才算"已有真源"**。不能只看 require_login：
                # 在线接口只持久化调用方传入的字段，所以"只改过 allowed_users"
                # 的站点 require_login 缺失，单看它会判成"未迁移"，然后用路由表
                # 旧值（很可能是 "org"）盖掉在线设的私有名单——一次数据修复动作
                # 变成静默扩权，且报告里显示为 migrated 成功（moto 实证）。
                # 与 register_route._seed_permissions_if_absent 同构。
                if "require_login" in site and "allowed_users" in site:
                    report["skipped"].append(site_id)
                    continue
                try:
                    allowed = permissions.normalize_allowed_users(
                        _parse_allowed(item.get("allowed_users", {})))
                except ValueError as e:
                    # UnparsableAllowlist 也是 ValueError 的子类，一并落在这里：
                    # 报告并跳过，由人工判断原意后手工修——不自动放宽。
                    report["errors"].append(
                        f"{site_id}: allowed_users 无法规范化（{e}）")
                    continue
                require_login = bool(item.get("require_auth", {}).get("BOOL", True))
                report["migrated"].append(site_id)
                # planned：给 dry-run 报告看"将写什么值"。没有它，SS→org 这类
                # 静默扩权在唯一的人工审查关口（dry-run 输出）上是不可见的。
                # **只列真正会被写入的字段**：稀疏行上另一个字段是 if_not_exists
                # 保留在线值，若照抄路由表的值会让报告谎报一次覆盖，人在唯一的
                # 审查关口看到的就不是实际行为。
                planned = {}
                if "require_login" not in site:
                    planned["require_login"] = require_login
                if "allowed_users" not in site:
                    planned["allowed_users"] = allowed
                planned["kept_from_online"] = sorted(
                    f for f in ("require_login", "allowed_users") if f in site)
                report["planned"][site_id] = planned
                if dry_run:
                    continue
                # 条件写 + rev=1，与 register_route 的 seed **同源但条件更窄**：
                # 那边的 ConditionExpression 还包含
                # `attribute_not_exists(permissions_rev)`（部署路径必须保证 rev
                # 存在，否则快照守卫会把合法部署卡死）；本脚本刻意不加那一项。
                # 理由：两个 auth 字段都在时上面的 skip 判定已经**不碰这行**，
                # 而这种"有 auth 字段、缺 rev"的稀疏行不会被卡住——首次在线权限
                # 写入的 SET 子句里就有 `permissions_rev = :nrev`，会把它补成 1
                # （已用 moto 实测：owner 与 collaborator 都能正常写入，外人仍被
                # 拒）。在这里额外补 rev 要重新取路由表的值，反而多一次扩权风险。
                # ① attribute_not_exists(require_login)——迁移读快照与写入之间
                #    若有部署把权限 seed 进来了，绝不能用路由表旧值（可能是
                #    "org"）盖掉刚 seed 的更紧策略（upsert_site 无条件写做不到
                #    这一点）；条件失败按 skipped 处理。
                # ② permissions_rev 推到 1——两个 organic seeder 都写 1，缺失
                #    会让 register_route 的 ConditionCheck 察觉不到迁移这次
                #    初始化（它的注释里写明了这个坑）。
                try:
                    boto3.resource("dynamodb").Table(
                        os.environ["SITES_TABLE"]).update_item(
                        Key={"site_id": site_id},
                        UpdateExpression=(
                            # 逐字段 if_not_exists：只补缺的，已有的在线值一律
                            # 保留。无条件 SET 会让"部署前只改过一个字段"的稀疏
                            # 行被路由表旧值覆盖（扩权）。
                            "SET require_login = if_not_exists(require_login, :rl), "
                            "allowed_users = if_not_exists(allowed_users, :au), "
                            "collaborators = if_not_exists(collaborators, :co), "
                            # spec §3.4 列了 owner：sites 行缺 owner 时从路由表
                            # 回填（一期 mark_job 每次部署都写 owner，缺失是
                            # 异常数据；不回填的话 role_of 对所有人 ROLE_NONE，
                            # 真 owner 失去自己站点的访问权）。已有则不动。
                            "#o = if_not_exists(#o, :own), "
                            "permissions_updated_at = :t, "
                            "permissions_updated_by = :by, "
                            "permissions_rev = if_not_exists(permissions_rev, :one)"),
                        # 与上面的 skip 判定同构：两个字段都在时不该走到这里，
                        # 走到了（读快照与写之间有部署 seed 进来）就让条件挡下。
                        ConditionExpression=("attribute_not_exists(require_login) OR "
                                             "attribute_not_exists(allowed_users)"),
                        ExpressionAttributeNames={"#o": "owner"},
                        ExpressionAttributeValues={
                            ":rl": require_login, ":au": allowed, ":co": [],
                            ":own": owner, ":t": permissions.now_iso(),
                            ":by": "migration", ":one": 1})
                except botocore.exceptions.ClientError as e:
                    if (e.response["Error"]["Code"]
                            != "ConditionalCheckFailedException"):
                        raise
                    # 期间有部署 seed 了真源：它的值更新鲜，让位
                    report["migrated"].pop()
                    report["planned"].pop(site_id, None)
                    report["skipped"].append(site_id)
            except Exception as e:                        # noqa: BLE001
                report["errors"].append(
                    f"{item.get('site_id', {}).get('S', '?')}: "
                    f"{type(e).__name__}: {e}")
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
    # 逐条打印"将写什么值"——dry-run 是唯一的人工审查关口，只列 site_id 的话
    # 任何解析歧义造成的扩权在这里都看不见
    print(f"  迁移: {len(report['migrated'])}")
    for sid in report["migrated"]:
        p = dict(report["planned"][sid])
        kept = p.pop("kept_from_online", [])
        # 稀疏行只补缺字段，所以这里不能假定两个键都在（假定会 KeyError）
        writes = " ".join(f"{k}={v!r}" for k, v in sorted(p.items())) or "（无）"
        line = f"    - {sid} → 写入 {writes}"
        if kept:
            line += f"；保留在线值 {','.join(kept)}"
        print(line)
    print(f"  跳过（已有真源）: {len(report['skipped'])} {report['skipped']}")
    if report["errors"]:
        print(f"  问题: {len(report['errors'])}")
        for e in report["errors"]:
            print(f"    - {e}")
    if not args.apply and report["migrated"]:
        print("\n确认无误后加 --apply 实际写入")


if __name__ == "__main__":
    main()
