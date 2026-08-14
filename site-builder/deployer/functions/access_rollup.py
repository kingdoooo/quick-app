"""M5 每日聚合：把明细行封口成 site-access-daily 的一行。

**幂等靠覆盖写，不靠水位线**：真源是耐久的明细行（90 天 TTL），每轮重算过去
LOOKBACK_DAYS 个完整日并 PutItem 覆盖。所以 rollup 坏 89 天，重跑即全部恢复
——这正是 spec §0.1 用来否掉"日志侧聚合"的那条差别（那边的真源是会过期的
日志，聚合器坏一个月即永久丢数）。

**只封口完整的 UTC 日**：今天的数由读路径实时算（panel/analytics.py）。
封口今天会把半天的数字固化成"全天"。
"""
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

LOOKBACK_DAYS = 7      # 一轮失败无需人工补跑的余量
TTL_DAYS = 400         # 与 ops_log.TTL_DAYS 对齐（13 个月，够看同月同比）

_ddb = None


def _client():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def target_days() -> list[str]:
    """要封口的日期：过去 LOOKBACK_DAYS 个**完整**日，不含今天。"""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=n)).isoformat()
            for n in range(1, LOOKBACK_DAYS + 1)]


def all_site_ids() -> list[str]:
    """DynamoDB 无法枚举分区键，所以站点清单只能来自 sites 表。

    **DELETED 也要枚举**：下线站点的历史趋势仍该被聚合（它只是不再产生新行，
    于是 rollup_day 返回 None 而不写）。
    """
    table = os.environ["SITES_TABLE"]
    out, kwargs = [], {"TableName": table, "ProjectionExpression": "site_id"}
    while True:
        resp = _client().scan(**kwargs)
        out.extend(i["site_id"]["S"] for i in resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return out
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def day_stats(rows: list[dict]) -> dict:
    """一天的明细行 → {pv, uv, pv_denied}。

    **唯一定义**：panel 的读取层 import 本函数算"今天"，不另写一份
    （两处算法漂移的症状是"面板今天的数与历史曲线口径不同"，没人会立刻发现）。

    · pv/uv 只数 allow——被拒不进 PV 曲线；
    · 空 email 不是一个访客（公开站点与未登录被拒都是空串），写哨兵值会污染
      distinct 计数，所以明细那边存的就是空串。
    """
    pv = uv = 0
    visitors, denied = set(), 0
    for r in rows:
        if r.get("decision", {}).get("S") != "allow":
            denied += 1
            continue
        pv += 1
        email = r.get("email", {}).get("S", "")
        if email:
            visitors.add(email)
    uv = len(visitors)
    return {"pv": pv, "uv": uv, "pv_denied": denied}


def _query_day(site_id: str, day: str) -> list[dict]:
    rows, kwargs = [], {
        "TableName": os.environ["ACCESS_EVENTS_TABLE"],
        "KeyConditionExpression": "site_date = :sd",
        "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
        "ProjectionExpression": "email, decision"}
    while True:
        resp = _client().query(**kwargs)
        rows.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def rollup_day(site_id: str, day: str) -> dict | None:
    """封口一天。**无明细行则返回 None 且不写**——否则 23 个 DELETED 站点
    会每天各得一行 0。"""
    rows = _query_day(site_id, day)
    if not rows:
        return None
    stats = day_stats(rows)
    _client().put_item(
        TableName=os.environ["ACCESS_DAILY_TABLE"],
        Item={"site_id": {"S": site_id}, "date": {"S": day},
              "pv": {"N": str(stats["pv"])}, "uv": {"N": str(stats["uv"])},
              "pv_denied": {"N": str(stats["pv_denied"])},
              "expires_at": {"N": str(int(time.time()) + TTL_DAYS * 86400)}})
    return stats


def handler(event, context) -> dict:
    """EventBridge 每日触发。`event` 里可给 `days` / `sites` 覆盖（供闸门定向重算）。"""
    days = (event or {}).get("days") or target_days()
    sites = (event or {}).get("sites") or all_site_ids()
    written = 0
    for site_id in sites:
        for day in days:
            if rollup_day(site_id, day) is not None:
                written += 1
    logger.info("rollup 完成 sites=%d days=%d 写入=%d",
                len(sites), len(days), written)
    return {"sites": len(sites), "days": len(days), "written": written}
