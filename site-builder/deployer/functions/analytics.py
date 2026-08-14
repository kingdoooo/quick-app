"""访问统计的**唯一**读取层，panel 与 MCP 共用（api.py / server.py 都不出现表名）。

**位置是 `deployer/functions/` 不是 `panel/`**：那是共享模块的既有位置，也是
MCP 传递闭包守卫唯一会扫的目录——放在 panel 下会让守卫静默放过，而容器里
`import analytics` 直接 ModuleNotFoundError（Codex 审查 2026-08-14 P1-2）。

两条契约要点：
  · 今天的数从明细实时算，`date < today` 读聚合表——今天实时、历史耐久；
  · **PV 可相加，UV 不能**。日 UV 永远精确（聚合行里存着，活 400 天）；
    周/月 UV 只在区间**完整落在 90 天明细窗口内**时精确，否则 `uv=None` +
    `uv_exact=False`，由前端显式标注"超出明细留存窗口"。
    不显示一个站不住的数字。
"""
import base64
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone

import boto3

# 口径唯一：pv/uv 的定义只有 access_rollup.day_stats 一份。
# 同目录，所以 panel 的 COPY_FILES 与 MCP 的三份清单都要带上这两个文件。
from access_rollup import day_stats

logger = logging.getLogger(__name__)

DETAIL_DAYS = 90        # = 明细表 TTL，UV 精确窗口的上界
MAX_VISITOR_DAYS = 90
MAX_VISITOR_LIMIT = 100
_ddb = None


def _client():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _day_rows(site_id: str, day: str) -> list[dict]:
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


def _daily_rows(site_id: str, since: str) -> dict:
    out, kwargs = {}, {
        "TableName": os.environ["ACCESS_DAILY_TABLE"],
        "KeyConditionExpression": "site_id = :s AND #d >= :since",
        "ExpressionAttributeNames": {"#d": "date"},
        "ExpressionAttributeValues": {":s": {"S": site_id}, ":since": {"S": since}}}
    while True:
        resp = _client().query(**kwargs)
        for it in resp.get("Items", []):
            out[it["date"]["S"]] = {
                "pv": int(it.get("pv", {}).get("N", 0)),
                "uv": int(it.get("uv", {}).get("N", 0)),
                "pv_denied": int(it.get("pv_denied", {}).get("N", 0))}
        if "LastEvaluatedKey" not in resp:
            return out
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _bucket_of(day: str, period: str) -> str:
    if period == "day":
        return day
    if period == "month":
        return day[:7]
    d = datetime.strptime(day, "%Y-%m-%d").date()
    year, week, _ = d.isocalendar()
    return f"{year}-W{week:02d}"


def _bucket_keys(period: str, n: int, today: date) -> list[str]:
    """最近 n 个**日历桶**的键，升序，长度恒为 n。

    **不能用 `n×7` / `n×31` 天回溯再分桶**（Codex 审查 2026-08-14 P2-2，
    已实测）：那样会返回 **n+1 个残缺桶**——固定 2026-08-14：`month n=1` 得
    `['2026-07','2026-08']`、`n=2` 得 3 个、`week n=4` 得 5 个，**五种参数全错**，
    而边界桶只是部分区间却没有任何标注，用户会当成完整周/月读。
    这里从**当前桶**往回数 n 个，最后一个桶必然是进行中的当前桶
    （"本月至今"），这是统计产品的通行语义。
    """
    if period == "day":
        return [(today - timedelta(days=i)).isoformat()
                for i in range(n - 1, -1, -1)][:n]
    if period == "week":
        monday = today - timedelta(days=today.weekday())
        out = []
        for i in range(n - 1, -1, -1):
            d = monday - timedelta(weeks=i)
            y, w, _ = d.isocalendar()
            out.append(f"{y}-W{w:02d}")
        return out
    out = []
    for i in range(n - 1, -1, -1):
        total = today.year * 12 + (today.month - 1) - i
        out.append(f"{total // 12:04d}-{total % 12 + 1:02d}")
    return out


def _bucket_first_day(period: str, key: str) -> date:
    """桶键 → 它的第一天（用来定 Query 的下界）。"""
    if period == "day":
        return date.fromisoformat(key)
    if period == "month":
        y, m = key.split("-")
        return date(int(y), int(m), 1)
    y, w = key.split("-W")
    return date.fromisocalendar(int(y), int(w), 1)


def series(site_id: str, period: str = "day", n: int = 30) -> list[dict]:
    """时间序列。`period` ∈ day|week|month，`n` = 桶数。"""
    if period not in ("day", "week", "month"):
        raise ValueError(f"period 必须是 day/week/month，收到 {period!r}")
    if not 1 <= n <= 400:
        raise ValueError(f"n 必须在 1..400，收到 {n}")
    today = datetime.now(timezone.utc).date()
    keys = _bucket_keys(period, n, today)      # 恰好 n 个，日历对齐
    start = _bucket_first_day(period, keys[0])
    daily = _daily_rows(site_id, start.isoformat())
    # 今天没被封口（rollup 只处理完整日）→ 实时算
    live = day_stats(_day_rows(site_id, _today()))
    if live["pv"] or live["pv_denied"]:
        daily[_today()] = live

    detail_floor = today - timedelta(days=DETAIL_DAYS - 1)
    # **零填充恰好 n 个桶**：契约是"最近 n 个日历桶"，没有数据的桶要给 0 而不是
    # 消失（前端 sparkline 与 pv7 都依赖长度固定）。
    buckets: dict[str, dict] = {
        k: {"bucket": k, "pv": 0, "uv": 0, "pv_denied": 0, "_days": [],
            "uv_exact": True} for k in keys}
    for day, st in sorted(daily.items()):
        key = _bucket_of(day, period)
        if key not in buckets:
            continue          # 落在区间外（Query 下界是桶首日，可能多带几天）
        b = buckets[key]
        b["pv"] += st["pv"]
        b["pv_denied"] += st["pv_denied"]
        b["_days"].append(day)
        if period == "day":
            b["uv"] = st["uv"]              # 日 UV 直接取，永远精确

    for key, b in buckets.items():
        if period == "day":
            b.pop("_days")
            continue
        days = b.pop("_days")
        # **判据是桶的日历边界，不是桶内恰好有哪些数据行**（Codex 复审
        # 2026-08-14 P2-2）：零填充之后，一个 200 天前、没有任何聚合行的月份
        # 其 `days` 是空列表 → `any(...)` 为 False → 会被标成 `uv_exact=True`
        # 且 `uv=0`，与 spec §1.4「超出窗口就 null」直接冲突。
        # 用桶自己的首日判定，与桶里有没有数据无关。
        if _bucket_first_day(period, key) < detail_floor:
            b["uv"], b["uv_exact"] = None, False
            continue
        # **UV 不能相加去重**：跨天去重必须回明细。
        visitors = set()
        for d in days:
            for r in _day_rows(site_id, d):
                if r.get("decision", {}).get("S") != "allow":
                    continue
                email = r.get("email", {}).get("S", "")
                if email:
                    visitors.add(email)
        b["uv"] = len(visitors)
    return [buckets[k] for k in keys]      # 恒为 n 个，升序


def _encode(key: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


def _decode(cursor: str) -> dict:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except Exception:
        raise ValueError("cursor 不是本接口发出的游标")


def visitors(site_id: str, days: int = 7, limit: int = 50,
             cursor: str | None = None) -> dict:
    """访问明细（最新在前）。含被拒记录。"""
    if not 1 <= days <= MAX_VISITOR_DAYS:
        raise ValueError(f"days 必须在 1..{MAX_VISITOR_DAYS}（= 明细留存），收到 {days}")
    if not 1 <= limit <= MAX_VISITOR_LIMIT:
        raise ValueError(f"limit 必须在 1..{MAX_VISITOR_LIMIT}，收到 {limit}")
    today = datetime.now(timezone.utc).date()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days)]
    state = _decode(cursor) if cursor else {}
    start_at = state.get("day", day_list[0])
    rows: list[dict] = []
    nxt = None
    for day in day_list:
        if day > start_at:
            continue
        kwargs = {"TableName": os.environ["ACCESS_EVENTS_TABLE"],
                  "KeyConditionExpression": "site_date = :sd",
                  "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
                  "ScanIndexForward": False,
                  "Limit": limit - len(rows)}
        if day == start_at and state.get("key"):
            kwargs["ExclusiveStartKey"] = state["key"]
        resp = _client().query(**kwargs)
        for it in resp.get("Items", []):
            rows.append({"ts": it["ts_id"]["S"].split("#")[0],
                         "email": it.get("email", {}).get("S", ""),
                         "path": it.get("path", {}).get("S", ""),
                         "decision": it.get("decision", {}).get("S", "")})
        if len(rows) >= limit:
            if "LastEvaluatedKey" in resp:
                nxt = _encode({"day": day, "key": resp["LastEvaluatedKey"]})
            else:
                remaining = [d for d in day_list if d < day]
                nxt = _encode({"day": remaining[0]}) if remaining else None
            break
    return {"rows": rows, "next": nxt}
