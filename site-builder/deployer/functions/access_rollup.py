"""M5 每日聚合：把明细行封口成 site-access-daily 的一行。

**幂等靠覆盖写，不靠水位线**：真源是耐久的明细行（DETAIL_TTL_DAYS 天 TTL），每轮
重算过去 LOOKBACK_DAYS 个完整日并 PutItem 覆盖——重算出什么就写什么，**包括重算
出 0**（明细被更正/删干净的那种情况，见 `rollup_day`）。这正是 spec §0.1 用来否掉
"日志侧聚合"的那条差别：那边的真源是会过期的日志，聚合器坏一个月即永久丢数；
这边只要明细还在，数就还能算回来。

**但"数还能恢复"与"会自动恢复"是两件事**：自动重算只覆盖最近 LOOKBACK_DAYS 天
（`target_days()` 只给这么多，而每日那次触发不带 `days`）。所以中断超过
LOOKBACK_DAYS 天，最老的那几天不会自己回来，得显式补一次：
`{"days": ["2026-08-01", ...]}`（可选带 `sites`）。数据本身在明细 TTL 到期前一直
补得回来——DETAIL_TTL_DAYS 天说的是这个，不是自动窗口有那么长。

**但补跑别贴着明细 TTL 的边界**：明细的 TTL 是**逐行**从各自写入时刻算的，所以越
接近 DETAIL_TTL_DAYS 的那一天，越可能只剩当天晚些时候写的那部分行——重算出来是个
偏小的数，而它会**覆盖掉本来正确的聚合行**。要补就补明显还在窗口里的天。
（例行调用只碰最近 LOOKBACK_DAYS 天，碰不到这个边界；这句是给显式补跑的人看的。）

自动窗口取 7 天够不够，取决于"坏了多久会被发现"：一次调用失败会经 EventBridge
重试 2 次后进 `site-deployer-reconcile-dlq`，**没有告警盯那个队列**，但有一条
`m5-rollup-no-successful-invocation-24h`（`Invocations - Errors < 1`）盯"这个函数
24 小时内一次都没成功"，所以多日中断约 24~48 小时内会被发现，7 天窗口有余量。
见 DEPLOY.md「两条埋点可观测性告警」。

**只封口完整的 UTC 日**：今天的数由读路径实时算（panel/analytics.py）。
封口今天会把半天的数字固化成"全天"。

**顺带做一件与聚合无关的事**：扫全部已启用区的 Lambda@Edge 日志，把埋点失败条数
发成**一个**跨区聚合指标（见下半部分「跨区 Edge 埋点失败聚合」）。搭在这一轮里是
因为它需要的正是同一个每日节奏与同一个 us-east-1 落点，且零新增基础设施。
"""
import logging
import os
import threading
import time
from concurrent import futures
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

LOOKBACK_DAYS = 7      # 一轮失败无需人工补跑的余量
TTL_DAYS = 400         # 与 ops_log.TTL_DAYS 对齐（13 个月，够看同月同比）

# 明细行的 TTL。**真源是写入方**：必须等于 `origin_request.ACCESS_TTL_DAYS`
# （`router/infrastructure/lambda/`）。两边是各自独立的部署单元，而本模块只许
# stdlib+boto3（要被复制进 panel/MCP 产物），没法 import 同一个常量——所以这份
# 重复由 `test_access_rollup.py::test_the_reconcile_window_tracks_the_edge_writers_ttl`
# 逐字钉住：谁单独改了一侧，那条立刻红。
# 它在这里的用途只有一个：判断"这天查不到明细"是**真的没有访问**，还是**明细
# 过期了**（见 `_details_are_authoritative`）。
DETAIL_TTL_DAYS = 90

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


def _details_are_authoritative(day: str) -> bool:
    """"这天查不到明细"能不能当成"这天真的没有访问"。

    Edge 写明细时 `expires_at = 写入时刻 + DETAIL_TTL_DAYS 天`，所以 day 那天的行
    最早也要到 day+DETAIL_TTL_DAYS 那一天才开始到期（TTL 的实际删除还能再滞后
    48h，那只会让行活得更久）。于是：

    · age ≤ DETAIL_TTL_DAYS-1 ⇒ 空结果只可能是真的没有行，可以据此对账；
    · age ≥ DETAIL_TTL_DAYS   ⇒ 空结果可能只是明细过期了，什么都不能推断。
    """
    try:
        target = datetime.strptime(day, "%Y-%m-%d").date()
    except ValueError:
        return False        # 手写 days 里的怪字符串：算不出年龄就不动任何行
    return 0 <= (datetime.now(timezone.utc).date() - target).days < DETAIL_TTL_DAYS


def _put_daily(site_id: str, day: str, stats: dict, *,
               only_if_exists: bool = False) -> bool:
    """写一行聚合行；`only_if_exists` 时该行不存在就什么都不做。返回是否写了。

    **条件写只需要 `dynamodb:PutItem`**——条件由 PutItem 自己求值（另需
    `dynamodb:ConditionCheckItem` 的是事务里的 ConditionCheck 项，M4 踩过那个）。
    所以下面的对账不给 rollup 角色加任何新权限。换成 DeleteItem 就得动
    `infra/app.py` 的策略，而 moto 不校验 IAM ⇒ 漏给时单测全绿、真机 AccessDenied。
    """
    kwargs = {"TableName": os.environ["ACCESS_DAILY_TABLE"],
              "Item": {"site_id": {"S": site_id}, "date": {"S": day},
                       "pv": {"N": str(stats["pv"])},
                       "uv": {"N": str(stats["uv"])},
                       "pv_denied": {"N": str(stats["pv_denied"])},
                       "expires_at": {"N": str(int(time.time())
                                               + TTL_DAYS * 86400)}}}
    if only_if_exists:
        kwargs["ConditionExpression"] = "attribute_exists(site_id)"
    try:
        _client().put_item(**kwargs)
    except _client().exceptions.ConditionalCheckFailedException:
        return False
    return True


def rollup_day(site_id: str, day: str) -> dict | None:
    """封口一天，返回**写下去的**那组数；什么都没写则 None。

    查不到明细行时分两种情况，差别只有明细那 DETAIL_TTL_DAYS 天 TTL：

    · day 还在明细保留期内 ⇒ "查不到"就是真相，已存在的聚合行必须被改成 0。
      少了这一步，「重算即修复」在**归零**这一支上是假的：明细被更正/删干净之后
      聚合行永久停在旧数字，而那条属性正是 spec §0.1 用来否掉日志侧聚合的理由。
      但**只改已经存在的行、绝不新建**——30 来个 DELETED 站点不该每天各得一行 0。
      这个不对称交给条件写（`attribute_exists`）由 DynamoDB 自己保证，不做
      "先读再写"（两次调用之间那行可能刚被写出来）。
    · day 已经超出明细保留期 ⇒ "查不到"什么也不证明（明细过期了，而聚合行本就
      要活 TTL_DAYS 天）。这时**原样不动**：否则每天的例行 rollup 会把
      DETAIL_TTL_DAYS～TTL_DAYS 那段历史逐日抹平，而两张表 TTL 不同的全部意义
      就是留下这段。
    """
    rows = _query_day(site_id, day)
    if not rows:
        if not _details_are_authoritative(day):
            return None
        zero = {"pv": 0, "uv": 0, "pv_denied": 0}
        if not _put_daily(site_id, day, zero, only_if_exists=True):
            return None     # 本来就没有这一行——保持它不存在
        logger.warning("对账：%s %s 的明细已归零，聚合行改写为 0/0/0",
                       site_id, day)
        return zero
    stats = day_stats(rows)
    _put_daily(site_id, day, stats)
    return stats


# ══════════════════════════════════════════════════════════════════════
# 跨区 Edge 埋点失败聚合
#
# **问题**：Lambda@Edge 在 POP 所在区执行，日志就落在那个区。CloudWatch 告警
# 不能跨区（只读同区指标、只通知同区 topic），所以一条 us-east-1 的告警只盯得住
# 落在 us-east-1 的那部分流量（本账号实测 3.5%，87.8% 在 ap-southeast-1）。
#
# **为什么不按区建 metric filter + 告警**：别的部署不知道自己的 POP 会落在哪些区
# （随 CloudFront 选路与 AWS 新开区变化）。所以这里**零按区资源**：每天扫一遍
# 全部已启用区，发一个聚合指标，一条告警覆盖所有 POP，含将来才出现的区。
# 同理不用 metric filter——那也是按区建的资源，新部署不会有。
# ══════════════════════════════════════════════════════════════════════

# Lambda@Edge 的日志组在**每个执行区**都叫 `/aws/lambda/{归属区}.{函数名}`
# ——前缀里的区是函数的**归属区**（Edge 函数只能建在 us-east-1，平台硬约束），
# 与执行区无关。所以这个前缀是与部署无关的**形状**，可以拿来发现日志组；
# 而 Edge 函数名是 `{stack_name}-{origin_request_function_name}`，两段都来自
# `router/config.ini`，**每个部署可以不一样**，绝不能写死在这里。
EDGE_LOG_GROUP_PREFIX = "/aws/lambda/us-east-1."

# Edge 侧那两条「一行埋点丢了」的 WARN（`origin_request.py` 的
# `_record_access` / `_maybe_record` except 分支）。埋点按设计吞掉一切异常
# （统计不是安全控制），**所以日志是这类丢数的唯一痕迹**。
# 两条都要盯：前者是写失败，后者是判定失败，结果一样是少了一行、且没人知道。
EDGE_FAILURE_TERMS = ("[WARN] 访问埋点失败", "[WARN] 埋点判定失败")
# `?A ?B` 是 CloudWatch 的 **OR**；空格分隔的裸短语是 AND（写错方向的症状是
# 一条都匹配不到，而两侧单测照样绿）。已对真日志组实测过这个形态，含非 ASCII。
EDGE_FAILURE_PATTERN = " ".join(f'?"{t}"' for t in EDGE_FAILURE_TERMS)

METRIC_NAMESPACE = "SiteBuilder/M5"
METRIC_NAME = "EdgeAnalyticsFailedGlobal"
SCAN_HOURS = 24        # 与每日一轮的节奏对齐
SCAN_WORKERS = 8       # 18 个已启用区串行扫会顶到 Lambda 的 300s。**同时也是内存
                       # 上界的那个乘数**（每线程一个 Session，见 _logs_client）
                       # ——调大它必须同时调大函数内存，由 CDK 断言
                       # `test_rollup_memory_is_sized_for_its_scan_threads` 钉住。
MAX_EVENT_PAGES = 40   # 见 _count_matches

# 扫描自己的时限。**扫描绝不许把封口那次调用拖挂**：区数（AWS 开新区）与日志组数
# （别人往本账号部署 Edge 函数，前缀发现会一起扫到）都不是我们的输入，一路吃到
# Lambda 的 300s 超时就是「观测把耐久工作标记成失败」——EventBridge 重试 + DLQ +
# 把 `m5-rollup-no-successful-invocation-24h` 一起拖响。真正的上界取两者小值：
# 这个固定预算（CDK 断言钉住它落在 Timeout 的一半以内）与**本次调用剩余时间**减
# 收尾余量（见 `_scan_budget`）。超预算 ⇒ 抛，绝不返回部分和。
SCAN_BUDGET_SECONDS = 120
SCAN_TIME_MARGIN_SECONDS = 30   # 留给 put_metric_data + 收尾日志

# 扫描是纯观测，**要重试**（与埋点写入刻意 max_attempts=0 相反）：偶发限流让
# 整轮扫描失败 ⇒ 指标缺数据 ⇒ 告警响一次假的，而偶发变红的告警的代价是下一个人
# 学会忽略它（M5-FINDINGS §4.20）。
_SCAN_CFG = Config(retries={"mode": "standard", "max_attempts": 4},
                   connect_timeout=5, read_timeout=30)


class ScanIncomplete(RuntimeError):
    """这一轮**没读完**。与「读到了 0」是两件事，所以必须是异常而不是返回值：
    调用方（`handler`）据此不发任何数据点，让「指标缺数据」成为唯一的信号。"""


# 每**线程**一个 Session，跨区复用。
_thread_state = threading.local()


def _logs_client(region: str):
    """建一个 logs client。

    两条约束都要满足，而 2026-08-15 之前只满足了第一条：

    · **不能用模块级共享的 session/client**：扫描是多线程的，而 boto3 的默认
      session 不是线程安全的建 client 入口（同一个 session 并发建 client 会撞上
      共享的 loader 缓存）。
    · **也不能每次新建 Session**：每个 Session 各自加载一份 botocore 的
      endpoints/服务模型（实测 ≈12MB/个），"每区一个"在 18 个已启用区上就是
      200MB+ 活内存 —— 那正是线上一半调用挂 `Runtime.OutOfMemory` 的原因，
      而**区数是 AWS 说了算的输入**，光调大内存等于把旋钮留在那儿。

    每线程一个 Session 两头都占：建 client 的入口是线程私有的（`threading.local`，
    从不被并发访问），而活着的 Session 数被 `SCAN_WORKERS` 钉住，不随区数增长。
    同一线程内跨区复用的是 Session（那份服务模型），client 仍按区建——client 上带
    着区，共用不了。
    """
    session = getattr(_thread_state, "session", None)
    if session is None:
        session = _thread_state.session = boto3.session.Session()
    return session.client("logs", region_name=region, config=_SCAN_CFG)


def _cloudwatch_client():
    """不指定区：指标要落在**本函数所在区**（= 平台区 us-east-1），也正是告警
    所在的区。写死 us-east-1 会让"换平台区"这件事多一个隐蔽的失败点。"""
    return boto3.client("cloudwatch")


def enabled_regions() -> list[str]:
    """本账号**已启用**的区，运行时问 AWS。

    不硬编码区列表就是这次改动的可移植性要求本身。`describe_regions` 默认只返回
    已启用的区（未 opt-in 的不返回），而 Lambda@Edge 也只会在能用的区落日志。
    """
    resp = boto3.client("ec2").describe_regions()
    return sorted(r["RegionName"] for r in resp["Regions"])


def _scan_budget(context=None) -> float:
    """这一轮允许扫多久（秒）。

    两个上界取小：`SCAN_BUDGET_SECONDS`，以及**本次调用真正剩下的时间**减去收尾
    余量。后者才是真源——封口在前，慢的那天剩下多少时间只有运行时知道；固定预算
    是给"没有 context"的路径（本地/单测）与"部署期可断言"用的。
    """
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return float(SCAN_BUDGET_SECONDS)
    return min(float(SCAN_BUDGET_SECONDS),
               remaining() / 1000.0 - SCAN_TIME_MARGIN_SECONDS)


def _check_budget(deadline: float, where: str) -> None:
    """预算用完就抛。**在每次翻页前查**：一个区里的组数 × 每组页数全在一次
    `_scan_region` 里，只在入口查一次等于没有上界。

    消息里不写具体秒数：本轮的有效预算可能是 `SCAN_BUDGET_SECONDS`，也可能是
    被剩余时间压小后的值（`_scan_budget`），写死一个会误导排查的人。
    """
    if time.monotonic() > deadline:
        raise ScanIncomplete(f"扫描用尽了本轮时间预算（停在 {where}）——本轮不报数")


def _count_matches(logs, group: str, start_ms: int, end_ms: int,
                   deadline: float) -> int:
    """一个日志组在窗口内的匹配条数。

    **空页也可能带 nextToken**——真机实测：同一次查询先返回两页 0 事件、第三页
    才有 17 条。所以终止条件只能是「没有 nextToken」，见到空页就停会漏数。

    `MAX_EVENT_PAGES` 是单组的页数上限：真撞到它说明这一轮的失败条数是十万量级，
    早已远超任何告警阈值，截断不影响结论。它管不了"组很多"，那由 `deadline` 管。
    """
    total, token, pages = 0, None, 0
    while True:
        _check_budget(deadline, f"{group} 第 {pages + 1} 页事件")
        kwargs = {"logGroupName": group, "startTime": start_ms,
                  "endTime": end_ms, "filterPattern": EDGE_FAILURE_PATTERN}
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        total += len(resp.get("events", []))
        token, pages = resp.get("nextToken"), pages + 1
        if not token or pages >= MAX_EVENT_PAGES:
            return total


def _scan_region(region: str, start_ms: int, end_ms: int,
                 deadline: float) -> int:
    """一个区里全部 Edge 日志组的匹配条数之和。

    **按前缀发现，不拼组名**：拼出来的名字在没有 Edge 日志的区会
    `ResourceNotFoundException`，而那是**正常态**（多数区没有 POP 落过），于是
    实现被迫吞掉一类真异常。发现式在空区自然得 0，不需要那个兜底。
    代价是会连账号里别人的 Edge 函数一起扫（本账号有一个 `us-east-1.redirectEdge`）
    ——它们不会打这两条中文 WARN，多几次调用换掉一个不可移植的假设。
    """
    logs = _logs_client(region)
    groups, token = [], None
    while True:
        _check_budget(deadline, f"{region} 的日志组清单")
        kwargs = {"logGroupNamePrefix": EDGE_LOG_GROUP_PREFIX}
        if token:
            kwargs["nextToken"] = token
        resp = logs.describe_log_groups(**kwargs)
        groups.extend(g["logGroupName"] for g in resp.get("logGroups", []))
        token = resp.get("nextToken")
        if not token:
            break
    return sum(_count_matches(logs, g, start_ms, end_ms, deadline)
               for g in groups)


def scan_edge_analytics_failures(end: datetime | None = None,
                                 budget_seconds: float | None = None) -> int:
    """全部已启用区、过去 SCAN_HOURS 小时的埋点失败条数。

    **任何一个区扫不动就整体抛出，绝不返回部分和**：部分和会被下游当成
    「就这么多」= 健康，而真相是「有一段没读到」。「读不到」必须与「没有」
    可区分（Task 14 定下的同一条纪律，M5-FINDINGS §4.20）。**预算耗尽走的是
    同一条路**（`ScanIncomplete`）——它同样是「没读完」，不是一个数。
    """
    end = end or datetime.now(timezone.utc)
    start_ms = int((end - timedelta(hours=SCAN_HOURS)).timestamp() * 1000)
    end_ms = int(end.timestamp() * 1000)
    budget = SCAN_BUDGET_SECONDS if budget_seconds is None else budget_seconds
    if budget <= 0:
        raise ScanIncomplete(
            f"本次调用剩余时间不够扫描（预算 {budget:.1f}s）——本轮不报数")
    deadline = time.monotonic() + budget
    regions = enabled_regions()
    if not regions:
        raise ScanIncomplete("枚举不到任何已启用区——扫描结果不可信，不发指标")
    total = 0
    with futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        jobs = [pool.submit(_scan_region, r, start_ms, end_ms, deadline)
                for r in regions]
        for job in jobs:
            total += job.result()       # 任一区抛出即整体抛出
    return total


def publish_failure_count(count: int, when: datetime | None = None) -> None:
    """发**一个**聚合数据点。

    **0 也要发**：只在有失败时才发的话，「健康」与「扫描器瞎了」在指标上是同一个
    形态（都没有数据点），告警分不开这两件事。发了显式 0 之后，缺数据只剩一个
    含义——本轮没扫成——交给告警的 `TreatMissingData=breaching`。这是承重点。

    **不带任何维度**：一个告警要覆盖所有 POP，加了区维度就又回到按区建告警。
    """
    _cloudwatch_client().put_metric_data(
        Namespace=METRIC_NAMESPACE,
        MetricData=[{"MetricName": METRIC_NAME,
                     "Value": float(count),
                     "Unit": "Count",
                     "Timestamp": when or datetime.now(timezone.utc)}])


def handler(event, context) -> dict:
    """EventBridge 每日触发。`event` 里可给 `days` / `sites` 覆盖（供闸门定向重算），
    以及 `scan_end_offset_hours` 把日志扫描窗口整体往前推（补发某个已过去的窗口，
    比如扫描器停过一段之后回填；日志保留 90 天，超出就什么都扫不到）。"""
    days = (event or {}).get("days") or target_days()
    sites = (event or {}).get("sites") or all_site_ids()
    written = 0
    for site_id in sites:
        for day in days:
            if rollup_day(site_id, day) is not None:
                written += 1
    logger.info("rollup 完成 sites=%d days=%d 写入=%d",
                len(sites), len(days), written)
    out = {"sites": len(sites), "days": len(days), "written": written}

    # **封口之后才扫日志**：封口是耐久工作（真源写入），扫日志只是观测。异常在这里
    # 收住而不外抛，是为了不让观测把耐久工作的那次调用也标记成失败（那会触发
    # EventBridge 重试与 DLQ，还会连带把 rollup 的成功调用告警拖响）。
    # 但**不是静默**：既不发 0（坏掉的扫描器会长期伪装成健康），也不 `except: pass`。
    end = datetime.now(timezone.utc) - timedelta(
        hours=float((event or {}).get("scan_end_offset_hours") or 0))
    try:
        count = scan_edge_analytics_failures(end, _scan_budget(context))
    except Exception as e:      # noqa: BLE001
        logger.warning("Edge 埋点失败扫描未完成，本轮**不发指标**"
                       "（指标缺数据即告警条件）: %s: %s", type(e).__name__, e)
        out["edge_failures"] = None
    else:
        publish_failure_count(count, end)
        logger.info("Edge 埋点失败扫描完成 count=%d 窗口=%dh 截止=%s",
                    count, SCAN_HOURS, end.isoformat())
        out["edge_failures"] = count
    return out
