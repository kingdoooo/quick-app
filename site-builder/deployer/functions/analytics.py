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

**两个面的成本上界刻意不同**（Codex 审查 2026-08-14 P1）：

  · `pv7()` —— 控制台**首页**的迷你趋势，站点数 × 每站一遍，所以它的读取
    **必须有硬上界**：聚合表那次由 `BETWEEN` 的键条件封住（每天最多一行），
    今天那次由 `Limit` 封住（`PV7_LIVE_ROW_CAP`），超出即返回 `[]` = 未知。
    理由不是"省钱"：Edge 给**每一个页面级请求**都记一行明细，**包括未登录的
    302 redirect_login**，而 CloudFront 全站禁缓存（鉴权正确性的前提）让每个
    请求都真的到 Edge —— 于是"今天有多少行"是一个**匿名方可控的输入**。
    首页同时是改权限、下线这些恢复手段的入口，它不能被行数拖到 30s 超时
    （超时**接不住**：进程被杀，没有异常可 catch）。
  · `series()` / `visitors()` —— 单站、刻意打开的统计页，今天照旧全量分页、
    照旧精确。它可以比列表贵，因为它是一次一站、由用户主动发起的。
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
# 首页迷你趋势读"今天"的**硬上界**（行数，非字节）。取 1000：当前全平台日均
# 124 行（M5-FINDINGS §4.26），单站 1000 行留了近一个数量级余量，而最坏情况
# 站点数 × 1000 行小对象仍是秒级。**这个数不是安全边界的来源**——上界本身是，
# 它由 Query 的 Limit 落实；这个数只决定"多大的站还能看到趋势线"。
# 某个**真实**站点长期超过它时，正确的动作是让 rollup 也写一行"今天至此"的
# 部分聚合，而不是把这个数改大（改大等于把上界还给攻击者）。
PV7_LIVE_ROW_CAP = 1000
_ddb = None


class ReadTooLarge(Exception):
    """要读的明细超出调用方给的上界。

    **只由 `pv7()` 触发并被它接住**（它给了 `live_row_cap`）；`series()` /
    `visitors()` 不传上界，所以这个异常不会从那两条路上冒出来，`handler.py`
    也就不需要为它加映射。
    """


def _client():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _day_rows(site_id: str, day: str, max_rows: int | None = None) -> list[dict]:
    """某一天的明细行。

    `max_rows=None`（统计页 / 周月 UV 去重）——全量分页，数字精确。
    `max_rows=N`（首页的迷你趋势）——**一次 Query、`Limit=N+1`、多一行就 raise**。

    上界由 Query 自己带（服务端截断），不是"拉回整页再在客户端 break"：行数是
    匿名请求可控的输入，客户端 break 仍会把最多 1MB 拉回来反序列化，而"翻几页"
    这件事本身还是跟着行数走。`N+1` 是为了区分「刚好 N 行」（照常给真数）与
    「还有更多」（给不出，raise）——**绝不返回截断的结果**：一个偏小的 PV 与
    真实的 PV 在 sparkline 上完全一样，是一张看着像真数据的错图。
    """
    kwargs = {
        "TableName": os.environ["ACCESS_EVENTS_TABLE"],
        "KeyConditionExpression": "site_date = :sd",
        "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
        "ProjectionExpression": "email, decision"}
    if max_rows is not None:
        kwargs["Limit"] = max_rows + 1
        resp = _client().query(**kwargs)
        rows = resp.get("Items", [])
        if len(rows) > max_rows or "LastEvaluatedKey" in resp:
            raise ReadTooLarge(
                f"{site_id} 在 {day} 的明细超过 {max_rows} 行，不在本次读取的上界内")
        return rows
    rows = []
    while True:
        resp = _client().query(**kwargs)
        rows.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _daily_rows(site_id: str, since: str, until: str) -> dict:
    """聚合表上 `since..until`（含两端）的行，day → {pv,uv,pv_denied}。

    **两端都给**：`date` 是排序键且每天最多一行，所以带上界之后"返回多少条"
    由键条件本身封住（= 区间天数），不跟表里存了多少天走。首页那条迷你趋势的
    上界有一半落在这里。
    """
    out, kwargs = {}, {
        "TableName": os.environ["ACCESS_DAILY_TABLE"],
        "KeyConditionExpression": "site_id = :s AND #d BETWEEN :since AND :until",
        "ExpressionAttributeNames": {"#d": "date"},
        "ExpressionAttributeValues": {":s": {"S": site_id},
                                      ":since": {"S": since},
                                      ":until": {"S": until}}}
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


def series(site_id: str, period: str = "day", n: int = 30,
           live_row_cap: int | None = None) -> list[dict]:
    """时间序列。`period` ∈ day|week|month，`n` = 桶数。

    `live_row_cap` 只由 `pv7()`（首页）传：给今天那次明细读加硬上界，超出则
    `raise ReadTooLarge`。统计页与 MCP 都不传 → 行为与加这个参数之前逐字一致
    （两侧"字段完全相同"的闸门断言因此不受影响）。
    """
    if period not in ("day", "week", "month"):
        raise ValueError(f"period 必须是 day/week/month，收到 {period!r}")
    if not 1 <= n <= 400:
        raise ValueError(f"n 必须在 1..400，收到 {n}")
    today = datetime.now(timezone.utc).date()
    keys = _bucket_keys(period, n, today)      # 恰好 n 个，日历对齐
    start = _bucket_first_day(period, keys[0])
    # 上界钉在今天：未来日期的行只可能来自时钟异常，落进"本月至今"会污染当前桶。
    daily = _daily_rows(site_id, start.isoformat(), today.isoformat())
    # 今天没被封口（rollup 只处理完整日）→ 实时算
    live = day_stats(_day_rows(site_id, _today(), max_rows=live_row_cap))
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


def pv7(site_id: str) -> list[int]:
    """近 7 天的日 PV，升序，**长度恒为 7**（缺失日为 0）；读不完整时给 `[]`。

    给站点列表画 sparkline 用（母 spec §11-clarify 的 M5 项）。仍然复用
    `series()`（零填充、日历对齐、pv 的口径都在那边），这里只多给一个上界。

    **`[]` = 未知**，与 `api._pv7_or_unknown()` 的降级值、与 `uv_exact=False`
    同一个口径：前端那条"恰好 7 个有限数字"的守卫据此什么都不画。返回一个偏小的
    真数字是更坏的选择——错图没有任何视觉标记。

    触发条件只有一个：**今天**那个明细分区超过 `PV7_LIVE_ROW_CAP` 行。此时
    改用统计页（`series()` 不带上界）看这个站点的精确数字。
    """
    try:
        return [b["pv"] for b in series(site_id, "day", 7,
                                        live_row_cap=PV7_LIVE_ROW_CAP)]
    except ReadTooLarge as e:
        # warning 不是可选的：这条是"某个站点今天的行数异常多"的唯一信号，
        # 而那既可能是站点真的火了，也可能是有人在灌明细。
        logger.warning("站点 %s 今天的明细超出首页读取上界（%d 行），本次趋势"
                       "按未知返回（统计页仍给精确数）: %s",
                       site_id, PV7_LIVE_ROW_CAP, e)
        return []


def _encode(key: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


_CURSOR_FIELDS = {"day", "key"}
_EVENTS_KEY_FIELDS = {"site_date", "ts_id"}      # = 明细表的主键形态，一字不差


def _decode(cursor: str, site_id: str, day_window: list[str]) -> dict:
    """游标 → `{day, key}`，**形状不对一律 ValueError（→ 400）**。

    上一版只判"能不能 base64+JSON 解出来"。于是一批语法合法、形状不对的游标会
    在业务代码里炸出别的异常，而 `handler.py` 只把 `ValueError` 映射成 400：
      · `[]` / `"x"` / `3` / `null` → `state.get()` 抛 `AttributeError` → **500**；
      · `{"day": 123}` → 后面 `day > start_at` 抛 `TypeError` → **500**；
      · `key` 里塞非键属性或错类型 → botocore `ParamValidationError` / 真机
        `ValidationException` → **500**（M5-FINDINGS §4.21 实测的那个 wart）。
    全都是**调用方能自己纠正**的入参错误，一个都不该表述成服务故障。

    `key` 额外**绑定到 (site_id, day)**：`site_date` 是明细表的分区键，它就在
    游标里，所以"把 A 站的游标投到 B 站"这件事在**业务代码之前**就被拒。
    不另加签名/HMAC：这里没有任何需要保密或防篡改的东西——绑定之后，篡改的唯一
    结果是 400，而能被合法构造出来的游标只能指向调用方自己已经通过授权的分区
    （授权在 `api.do_get_visitors` 里、在本函数之前）。多一个密钥要多一处轮换。
    """
    try:
        state = json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except Exception:
        raise ValueError("cursor 不是本接口发出的游标")
    if not isinstance(state, dict) or set(state) - _CURSOR_FIELDS:
        raise ValueError("cursor 不是本接口发出的游标")
    day = state.get("day")
    if day is not None and day not in day_window:
        # **一句成员判定同时管住类型、格式、范围**：`day_window` 的每一项都是
        # `date.isoformat()` 生成的字符串，所以"不是 str"、"不是 ISO 日期"、
        # "不在本次 days 覆盖的范围内"三种输入都在这里被拒。
        # **刻意不再叠 `isinstance` + `date.fromisoformat` 两层**：逐条打掉守卫
        # 实测过，那两层**没有任何输入能让它们单独变红**（都会落到这一句上），
        # 即死守卫——而死守卫会让下一个人以为这里有三层保护、改动时只看其中一层。
        # `day` 合法性的真源只有 `day_window` 一处。
        # 典型成因：换了 days 参数、或跨过 UTC 零点后重放旧游标。
        raise ValueError("cursor 指向的日期不在本次查询的天数范围内，请重新翻页")
    if "key" in state:
        key = state["key"]
        if day is None:
            raise ValueError("cursor 不是本接口发出的游标")
        if not isinstance(key, dict) or set(key) != _EVENTS_KEY_FIELDS:
            raise ValueError("cursor 不是本接口发出的游标")
        for v in key.values():
            if not isinstance(v, dict) or list(v) != ["S"] \
                    or not isinstance(v["S"], str):
                raise ValueError("cursor 不是本接口发出的游标")
        if key["site_date"]["S"] != f"{site_id}#{day}":
            raise ValueError("cursor 与本次查询的站点/日期不一致，请重新翻页")
    return state


def visitors(site_id: str, days: int = 7, limit: int = 50,
             cursor: str | None = None) -> dict:
    """访问明细（最新在前）。含被拒记录。"""
    if not 1 <= days <= MAX_VISITOR_DAYS:
        raise ValueError(f"days 必须在 1..{MAX_VISITOR_DAYS}（= 明细留存），收到 {days}")
    if not 1 <= limit <= MAX_VISITOR_LIMIT:
        raise ValueError(f"limit 必须在 1..{MAX_VISITOR_LIMIT}，收到 {limit}")
    today = datetime.now(timezone.utc).date()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days)]
    state = _decode(cursor, site_id, day_list) if cursor else {}
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
