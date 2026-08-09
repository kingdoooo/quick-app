#!/usr/bin/env python3
"""一次性幂等回填 sites.created_at（控制台要显示创建时间）。

缺口：upsert_site 全链路从不写 created_at，只有 jobs 表有。存量站点因此没有
这个字段。从该站点**最早一条 job** 的 created_at 推导。

**无 job 的站点不猜**：写 now() 会是个错的日期，且看不出是猜的。这类记录进
报告由人工判断。同 migrate_permissions.py 的"损坏数据报错跳过，不降级"取向。

用法：
    ./backfill_site_created_at.py            # dry-run（默认，只报告）
    ./backfill_site_created_at.py --apply    # 真写
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/deployer/functions"))
CFG_PATH = HERE.parent / "config.ini"


def _read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


def run(*, apply: bool) -> dict:
    import boto3
    from boto3.dynamodb.conditions import Key
    import common

    ddb = boto3.resource("dynamodb",
                         region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    sites_tbl = ddb.Table(os.environ["SITES_TABLE"])
    jobs_tbl = ddb.Table(os.environ["JOBS_TABLE"])
    stats = {"total": 0, "updated": 0, "would_update": 0,
             "skipped_existing": 0, "no_jobs": 0}
    reports: list[str] = []

    sites = common._paginate(sites_tbl.scan,
                             ProjectionExpression="site_id, created_at")
    for site in sites:
        stats["total"] += 1
        site_id = site["site_id"]
        if site.get("created_at"):
            stats["skipped_existing"] += 1
            continue
        # 最早一条 job：site-index 正序取第一条
        resp = jobs_tbl.query(IndexName="site-index",
                              KeyConditionExpression=Key("site_id").eq(site_id),
                              ScanIndexForward=True, Limit=1)
        items = resp.get("Items", [])
        if not items or not items[0].get("created_at"):
            stats["no_jobs"] += 1
            reports.append(f"  跳过 {site_id}：没有可推导创建时间的 job（不猜）")
            continue
        ts = items[0]["created_at"]
        if not apply:
            stats["would_update"] += 1
            reports.append(f"  将回填 {site_id} → {ts}")
            continue
        try:
            sites_tbl.update_item(
                Key={"site_id": site_id},
                UpdateExpression="SET created_at = :t",
                ConditionExpression="attribute_not_exists(created_at)",
                ExpressionAttributeValues={":t": ts})
            stats["updated"] += 1
        except Exception as e:      # 条件失败=并发写入了，属正常
            if "ConditionalCheckFailed" not in str(type(e).__name__) + str(e):
                raise
            stats["skipped_existing"] += 1
    for line in reports:
        print(line)
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="真写（默认 dry-run 只报告）")
    args = ap.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", _read_cfg("Platform", "region"))
    os.environ["SITES_TABLE"] = _read_cfg("Deployer", "sites_table")
    os.environ["JOBS_TABLE"] = _read_cfg("Deployer", "jobs_table")
    stats = run(apply=args.apply)
    print(f"\n站点总数 {stats['total']}｜"
          f"{'已回填' if args.apply else '待回填'} "
          f"{stats['updated'] or stats['would_update']}｜"
          f"已有值跳过 {stats['skipped_existing']}｜无 job 跳过 {stats['no_jobs']}")
    if stats["no_jobs"]:
        print("⚠️  有站点无法推导创建时间——控制台会显示为空，需人工确认后手工补")
    return 0


if __name__ == "__main__":
    sys.exit(main())
