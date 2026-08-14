"""rollup 单测。用 moto 建两张表。

**moto 不校验 IAM**——本文件全绿不代表线上角色有对应权限；IAM 由 Task 6 的
CDK 断言 + Task 13 的真机闸门各自盯（M4 踩过：事务里的 ConditionCheck 漏给
权限时单测全绿、真机 500）。
"""
import ast
import configparser
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

EVENTS = "site-access-events"
DAILY = "site-access-daily"

REPO = Path(__file__).resolve().parents[3]
EDGE_SRC = REPO / "router" / "infrastructure" / "lambda" / "origin_request.py"
ROLLUP_SRC = Path(__file__).resolve().parents[1] / "functions" / "access_rollup.py"
ROUTER_CFG_EXAMPLE = REPO / "router" / "config.ini.example"


def _no_scan_stub():
    raise RuntimeError("本用例没有装跨区扫描桩（用 `scan` 夹具）")


@pytest.fixture
def tables(monkeypatch):
    monkeypatch.setenv("ACCESS_EVENTS_TABLE", EVENTS)
    monkeypatch.setenv("ACCESS_DAILY_TABLE", DAILY)
    monkeypatch.setenv("SITES_TABLE", "site-sites")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        d = boto3.client("dynamodb", region_name="us-east-1")
        d.create_table(TableName=EVENTS,
                       KeySchema=[{"AttributeName": "site_date", "KeyType": "HASH"},
                                  {"AttributeName": "ts_id", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_date", "AttributeType": "S"},
                           {"AttributeName": "ts_id", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        d.create_table(TableName=DAILY,
                       KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"},
                                  {"AttributeName": "date", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_id", "AttributeType": "S"},
                           {"AttributeName": "date", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        d.create_table(TableName="site-sites",
                       KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_id", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        # **护栏**（M5-FINDINGS §4.2 的同一类）：`handler` 现在顺带跨区扫日志，
        # 而本文件里好几条**只关心封口**的老用例走的正是 handler。不给默认桩的话
        # 它们会去 moto 的 ec2/logs 里绕 18~30 个区（实测本文件从 5s 涨到 49s），
        # 而万一哪天 `mock_aws` 没覆盖到，那就是**真的**跨区调用（§4.2 就是这么
        # 让单测往生产表写了行）。没显式装桩的用例一律让扫描直接抛——handler 会
        # 记 warning 且不发指标，与"扫不成"同构，不影响它们要断言的封口行为。
        import access_rollup as ar
        monkeypatch.setattr(ar, "enabled_regions", _no_scan_stub)
        yield d


def _ev(d, site, day, email, decision="allow", i=0):
    d.put_item(TableName=EVENTS, Item={
        "site_date": {"S": f"{site}#{day}"},
        "ts_id": {"S": f"{day}T00:00:0{i}+00:00#aa{i:02d}"},
        "site_id": {"S": site}, "email": {"S": email},
        "path": {"S": "/"}, "decision": {"S": decision},
        "expires_at": {"N": "9999999999"}})


def test_pv_counts_rows_and_uv_counts_distinct_emails(tables):
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=0)
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=1)
    _ev(tables, "s1", "2026-08-10", "b@x.co", i=2)
    out = ar.rollup_day("s1", "2026-08-10")
    assert out == {"pv": 3, "uv": 2, "pv_denied": 0}


def test_denied_rows_do_not_enter_pv_or_uv(tables):
    """被拒不进 PV 曲线，但要可查。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=0)
    _ev(tables, "s1", "2026-08-10", "out@x.co", decision="denied_403", i=1)
    _ev(tables, "s1", "2026-08-10", "", decision="redirect_login", i=2)
    assert ar.rollup_day("s1", "2026-08-10") == {"pv": 1, "uv": 1, "pv_denied": 2}


def test_empty_email_is_not_a_unique_visitor(tables):
    """公开站点/未登录的空串不能算成一个访客。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "", i=0)
    _ev(tables, "s1", "2026-08-10", "", i=1)
    assert ar.rollup_day("s1", "2026-08-10") == {"pv": 2, "uv": 0, "pv_denied": 0}


def test_no_rows_writes_no_aggregate_row(tables):
    """23 个 DELETED 站点不该每天各得一行 0。"""
    import access_rollup as ar
    assert ar.rollup_day("gone", "2026-08-10") is None
    got = tables.query(TableName=DAILY,
                       KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "gone"}})
    assert got["Count"] == 0


def test_rerun_is_idempotent(tables):
    """覆盖写 ⇒ 连续几天失败无需人工补跑。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY,
                       KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    assert got["Count"] == 1
    assert got["Items"][0]["pv"]["N"] == "1"


def test_rerun_recomputes_instead_of_keeping_the_first_number(tables):
    """重算即修复：封口后又到的明细行必须体现在重跑结果里。

    **与上面那条 test_rerun_is_idempotent 不重复，别删任何一条**：
    「重跑不产生重复行」是 daily 表的键结构（site_id + date）本身保证的，
    与实现是不是覆盖写无关——所以上面那条对「写一次就再也不覆盖」的实现
    （PutItem 带 attribute_not_exists 条件 + 吞掉冲突）照样全绿，实测过。
    本条钉的是另一半、也是真正承重的那半：重跑必须用**重新算出的**数盖掉旧行。
    spec §0.1 就是用「重算即修复」否掉日志侧聚合的（那边真源会过期，
    聚合器坏一个月即永久丢数；这边明细耐久，所以重跑能全恢复）。
    """
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=0)
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    _ev(tables, "s1", "2026-08-10", "b@x.co", i=1)      # 迟到 / 上轮只跑了半天
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    assert got["Count"] == 1
    assert got["Items"][0]["pv"]["N"] == "2"            # 不是 "1"
    assert got["Items"][0]["uv"]["N"] == "2"


def test_today_is_never_sealed(tables):
    """今天的数由读路径实时算；封口今天会把半天的数字固化成"全天"。"""
    import access_rollup as ar
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert today not in ar.target_days()
    assert len(ar.target_days()) == ar.LOOKBACK_DAYS
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    assert yesterday in ar.target_days()


def test_aggregate_row_carries_a_400_day_ttl(tables):
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    ttl = int(got["Items"][0]["expires_at"]["N"])
    now = int(datetime.now(timezone.utc).timestamp())
    assert 399 * 86400 < ttl - now <= 401 * 86400, "TTL 不是 400 天"


def test_sites_are_enumerated_from_the_sites_table(tables):
    """DynamoDB 无法枚举分区键，所以 site_id 只能来自 sites 表。"""
    import access_rollup as ar
    tables.put_item(TableName="site-sites",
                    Item={"site_id": {"S": "s1"}, "status": {"S": "ACTIVE"}})
    tables.put_item(TableName="site-sites",
                    Item={"site_id": {"S": "s2"}, "status": {"S": "DELETED"}})
    # DELETED 也要枚举——它的历史趋势仍该被聚合；无行时自然不写（上面那条）
    assert set(ar.all_site_ids()) == {"s1", "s2"}


# ══════════════════════════════════════════════════════════════════════
# 「重算即修复」的**归零**那一支（2026-08-15 补）
#
# 原实现 `if not rows: return None` 从不碰已存在的聚合行，于是明细被更正/删干净
# 之后，聚合行永久停在旧数字——spec §0.1 用来否掉日志侧聚合的那条承重属性在这
# 一支上是假的。旧用例只删了两行里的一行（还剩非零结果），刚好绕过边界。
#
# 修的时候真正难的不是归零，是**别把 90～400 天那段历史一起抹平**：明细只活 90
# 天，聚合行活 400 天，所以"查不到明细"在窗口外什么也不证明。下面的用例都按
# "距今多少天"算日期，不写死——窗口是相对今天的，写死的日期几个月后会换一种走法。
# ══════════════════════════════════════════════════════════════════════


def _day(age: int) -> str:
    """距今 age 天的那个 UTC 日。"""
    return (datetime.now(timezone.utc).date() - timedelta(days=age)).isoformat()


def _seal(d, site, day, pv="1", uv="1", denied="0", expires="1800000000"):
    """直接摆一行聚合行（不经 rollup），构造"这天早就封口过"的现场。"""
    d.put_item(TableName=DAILY, Item={
        "site_id": {"S": site}, "date": {"S": day},
        "pv": {"N": pv}, "uv": {"N": uv}, "pv_denied": {"N": denied},
        "expires_at": {"N": expires}})


def _daily(d, site, day) -> dict | None:
    got = d.get_item(TableName=DAILY, ConsistentRead=True,
                     Key={"site_id": {"S": site}, "date": {"S": day}})
    return got.get("Item")


def _triple(row) -> tuple:
    return (row["pv"]["N"], row["uv"]["N"], row["pv_denied"]["N"])


def _wipe_details(d, site, day) -> int:
    """删掉那天全部明细，返回删了几行。

    **每次都断言返回值**：现场没构造出来（一行都没删）时，下面那些用例会因为
    一个完全无关的原因绿。
    """
    got = d.query(TableName=EVENTS, KeyConditionExpression="site_date = :sd",
                  ExpressionAttributeValues={":sd": {"S": f"{site}#{day}"}})
    for it in got["Items"]:
        d.delete_item(TableName=EVENTS,
                      Key={"site_date": it["site_date"], "ts_id": it["ts_id"]})
    return len(got["Items"])


def _module_int(src: Path, name: str) -> int:
    """从源码文本里取模块级整数常量。

    不 import：Edge 那份代码不在本包的 sys.path 上，而且 import 它会带上
    `origin_request` 的整套模块级副作用。
    """
    for node in ast.parse(src.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{src} 里没有模块级 {name} = <整数>")


def test_recompute_to_zero_corrects_an_aggregate_row_whose_details_are_all_gone(
        tables):
    """明细被删干净后重算 → 聚合行必须降到 0，不能永久停在 pv=1。

    这是「重算即修复」的边界：删掉两行里的一行会降（`test_rerun_recomputes_...`
    测的是这个），删掉**最后**一行原实现反而不降。
    """
    import access_rollup as ar
    day = _day(3)
    _ev(tables, "s1", day, "a@x.co")
    assert ar.rollup_day("s1", day) == {"pv": 1, "uv": 1, "pv_denied": 0}
    assert _wipe_details(tables, "s1", day) == 1
    assert ar.rollup_day("s1", day) == {"pv": 0, "uv": 0, "pv_denied": 0}
    row = _daily(tables, "s1", day)
    assert _triple(row) == ("0", "0", "0")
    # 改写出来的行要和正常封口的行同规矩（少写 expires_at 就是永久留存）
    ttl = int(row["expires_at"]["N"]) - int(datetime.now(timezone.utc).timestamp())
    assert 399 * 86400 < ttl <= 401 * 86400, "对账写出来的行 TTL 不是 400 天"


def test_a_day_past_the_detail_ttl_is_left_untouched(tables):
    """窗口**外**的聚合行必须原样不动——它的明细早被 TTL 吃了。

    这条是"归零"的护栏：不看窗口的话，每天的例行 rollup 会把 90～400 天那段
    历史逐日抹平，而两张表 TTL 不同（90 / 400）的全部意义就是留下这段。
    """
    import access_rollup as ar
    old = _day(ar.DETAIL_TTL_DAYS + 10)
    _seal(tables, "s1", old, pv="7", uv="5", denied="2")
    before = _daily(tables, "s1", old)
    assert ar.rollup_day("s1", old) is None
    # 整行逐字比，含 expires_at：刷新 TTL 也算动过它
    assert _daily(tables, "s1", old) == before


def test_the_reconcile_window_ends_exactly_at_the_detail_ttl(tables):
    """边界本身：age = DETAIL_TTL_DAYS-1 要对账，age = DETAIL_TTL_DAYS 不动。

    day 那天写的明细 expires_at = 写入时刻 + DETAIL_TTL_DAYS 天，所以最早也要到
    day+DETAIL_TTL_DAYS 那一天才开始到期（TTL 实际删除还能再滞后 48h，只会让行
    活得更久）。把这个比较写反、放宽成 `<=`、或换成别的天数，这一条都会红。
    """
    import access_rollup as ar
    inside, outside = _day(ar.DETAIL_TTL_DAYS - 1), _day(ar.DETAIL_TTL_DAYS)
    _seal(tables, "s1", inside, pv="4", uv="3", denied="1")
    _seal(tables, "s1", outside, pv="4", uv="3", denied="1")
    assert ar.rollup_day("s1", inside) == {"pv": 0, "uv": 0, "pv_denied": 0}
    assert _triple(_daily(tables, "s1", inside)) == ("0", "0", "0")
    assert ar.rollup_day("s1", outside) is None
    assert _triple(_daily(tables, "s1", outside)) == ("4", "3", "1")


def test_a_site_with_no_details_never_gets_an_aggregate_row_created(tables):
    """窗口**内**也不许凭空造行——30 来个 DELETED 站点不该每天各得一行 0。

    这就是"对账"与"每天写一行 0"的分界：只改**已经存在**、且被明细否证的那行。
    与 `test_no_rows_writes_no_aggregate_row` 不重复：那条写死了日期，几个月后
    会落到窗口外，于是变成在测窗口护栏；本条把窗口**内**这一支永久钉住。
    """
    import access_rollup as ar
    day = _day(3)
    assert ar.rollup_day("gone", day) is None
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "gone"}})
    assert got["Count"] == 0


def test_the_scheduled_run_reconciles_inside_its_window_and_invents_nothing(tables):
    """线上那条路径（不带 days 的例行调用）也要对账，且只动该动的那一行。

    只测 `rollup_day` 不够：`written` 是闸门读的数，而"顺带多写了 13 行 0"这种
    回归只有走 handler 才看得见。
    """
    import access_rollup as ar
    day = _day(2)
    _seal(tables, "s1", day, pv="9", uv="9", denied="9")
    out = ar.handler({"sites": ["s1", "gone"]}, None)
    assert _triple(_daily(tables, "s1", day)) == ("0", "0", "0")
    # 2 站 × 7 天 = 14 对，只有那一对有已存在的行
    assert out["written"] == 1
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "gone"}})
    assert got["Count"] == 0


def test_the_reconcile_window_tracks_the_edge_writers_ttl():
    """对账窗口的真源是**写入方**的 TTL：`origin_request.ACCESS_TTL_DAYS`。

    两侧不能共享常量（Edge 是独立部署单元；本模块还要被复制进 panel/MCP 产物，
    只许 stdlib+boto3），所以 90 在两个文件里各有一份字面量。这条断言就是那份
    耦合的可执行约束：谁单独改了一侧，这里立刻红。
    """
    import access_rollup as ar
    assert ar.DETAIL_TTL_DAYS == _module_int(EDGE_SRC, "ACCESS_TTL_DAYS")


# ══════════════════════════════════════════════════════════════════════
# 跨区 Edge 埋点失败聚合（2026-08-15）
#
# **为什么在 rollup 里做**：Lambda@Edge 在 POP 所在区落日志（本账号实测 8 个区
# 执行过，ap-southeast-1 占 87.8%、us-east-1 只占 3.5%），而 CloudWatch 告警
# **不能跨区**（只读同区指标、只通知同区 topic）。按区建 metric filter + 告警
# 不可移植——别的部署不知道自己的 POP 会落在哪些区。所以这一轮顺带扫全部**已启用
# 区**，把条数发成 us-east-1 的**一个**指标，一条告警覆盖所有 POP（含将来才出现的）。
#
# 这些用例都用假 client：真 CloudWatch 的 filter pattern 语义（尤其 `?A ?B` 是
# OR、以及非 ASCII 短语能不能匹配）**假 client 证明不了**，那部分由部署后的真机
# 读回负责（往真日志组注一行合成 WARN 再看指标）。这里钉的是聚合/失败/发布语义。
# ══════════════════════════════════════════════════════════════════════

class _FakeLogs:
    """假 logs client。

    `spec` 形态：
      `groups`  —— `[(名字列表, nextToken), ...]`，最后一页 token 给 None
      `events`  —— `{组名: [每页事件数, ...]}`，除最后一页外都带 nextToken
      `boom`    —— `"describe"` / `"filter"` 时抛异常（模拟某个区扫不动）
    """

    def __init__(self, region, spec, rec):
        self.region, self.spec, self.rec = region, spec, rec

    def describe_log_groups(self, **kw):
        self.rec["described"].append((self.region, kw))
        if self.spec.get("boom") == "describe":
            raise RuntimeError(f"{self.region} 的 describe 挂了")
        pages = self.spec.get("groups", [([], None)])
        idx = 0 if "nextToken" not in kw else int(kw["nextToken"].split("-")[-1])
        names, token = pages[idx]
        out = {"logGroups": [{"logGroupName": n} for n in names]}
        if token:
            out["nextToken"] = token
        return out

    def filter_log_events(self, **kw):
        self.rec["filtered"].append((self.region, kw))
        if self.spec.get("boom") == "filter":
            raise RuntimeError(f"{self.region} 的 filter 挂了")
        pages = self.spec.get("events", {}).get(kw["logGroupName"], [0])
        idx = 0 if "nextToken" not in kw else int(kw["nextToken"].split("-")[-1])
        out = {"events": [{"message": "x"} for _ in range(pages[idx])]}
        if idx + 1 < len(pages):
            out["nextToken"] = f"ev-{idx + 1}"
        return out


@pytest.fixture
def scan(monkeypatch):
    """接住 `enabled_regions` 与 `_logs_client`，返回 (装配函数, 记录本)。"""
    import access_rollup as ar
    rec = {"described": [], "filtered": [], "regions": 0}

    def install(specs: dict):
        monkeypatch.setattr(ar, "enabled_regions", lambda: list(specs))
        monkeypatch.setattr(
            ar, "_logs_client",
            lambda region: _FakeLogs(region, specs[region], rec))
        return rec

    return install, rec


@pytest.fixture
def cw(monkeypatch):
    """接住 CloudWatch client，记录每次 put_metric_data 的入参。"""
    import access_rollup as ar
    calls = []

    class _FakeCw:
        def put_metric_data(self, **kw):
            calls.append(kw)

    monkeypatch.setattr(ar, "_cloudwatch_client", lambda: _FakeCw())
    return calls


def _one_group(count, name="/aws/lambda/us-east-1.Edge"):
    return {"groups": [([name], None)], "events": {name: [count]}}


def test_scan_sums_matches_from_every_enabled_region(scan):
    """聚合值 = 所有区之和；而且每个区都真的被访问过。"""
    import access_rollup as ar
    install, rec = scan
    specs = {"ap-southeast-1": _one_group(3),
             "us-east-1": _one_group(1),
             "eu-west-1": {"groups": [([], None)]}}   # 该区没有 Edge 日志组
    install(specs)
    assert ar.scan_edge_analytics_failures() == 4
    # **先断非空再逐项**（M5-FINDINGS §4.5）：集合空时"每个区都访问过"恒真
    visited = {r for r, _ in rec["described"]}
    assert len(visited) == len(specs) == 3, f"漏扫了区：{visited}"
    for region in specs:
        assert region in visited, f"{region} 没被扫到"


def test_a_region_without_edge_log_groups_contributes_zero_without_error(scan):
    """大多数区根本没有 Edge 日志组——这是**正常态**，不能算失败。

    这条正是"按前缀发现"而不是"拼出组名再吞 ResourceNotFoundException"的理由：
    发现式在空区自然得 0，不需要把一类真异常也吞掉。
    """
    import access_rollup as ar
    install, rec = scan
    install({"sa-east-1": {"groups": [([], None)]}})
    assert ar.scan_edge_analytics_failures() == 0
    assert rec["filtered"] == [], "没有日志组时不该发 filter 调用"


def test_one_region_failing_makes_the_whole_scan_fail(scan):
    """**绝不返回部分和**。

    部分和会被下游当成「就这么多」= 健康，而真相是「有一段没读到」。
    「读不到」必须与「没有」可区分（Task 14 的同一条纪律，M5-FINDINGS §4.20）。
    """
    import access_rollup as ar
    install, _ = scan
    install({"ap-southeast-1": _one_group(5),
             "ap-northeast-1": {"boom": "filter",
                                "groups": [(["/aws/lambda/us-east-1.Edge"], None)],
                                "events": {}}})
    with pytest.raises(Exception) as ei:
        ar.scan_edge_analytics_failures()
    assert "ap-northeast-1" in str(ei.value), str(ei.value)


def test_scan_window_is_the_last_24_hours(scan):
    """窗口 = 过去 24 小时（与每日一轮的节奏对齐）。"""
    import access_rollup as ar
    install, rec = scan
    install({"us-east-1": _one_group(0)})
    end = datetime(2026, 8, 15, 3, 0, tzinfo=timezone.utc)
    ar.scan_edge_analytics_failures(end)
    assert rec["filtered"], "一次 filter 都没发出——本条空转"
    for _, kw in rec["filtered"]:
        assert kw["endTime"] == int(end.timestamp() * 1000)
        assert kw["startTime"] == int((end - timedelta(hours=24)).timestamp() * 1000)


def test_event_pagination_follows_next_token_across_empty_pages(scan):
    """**空页也可能带 nextToken**——见到空页就停会漏数。

    真机实测（`aws logs filter-log-events` 自动分页）：同一次查询先返回两页
    0 事件、第三页才有 17 条。所以循环的终止条件只能是「没有 nextToken」。
    """
    import access_rollup as ar
    install, rec = scan
    name = "/aws/lambda/us-east-1.Edge"
    install({"us-east-1": {"groups": [([name], None)],
                           "events": {name: [0, 0, 2, 0]}}})
    assert ar.scan_edge_analytics_failures() == 2
    assert len(rec["filtered"]) == 4, "没有走完全部分页"


def test_log_group_pagination_is_followed(scan):
    """日志组清单本身也要翻页，否则区里组多时会漏组。"""
    import access_rollup as ar
    install, rec = scan
    a, b = "/aws/lambda/us-east-1.A", "/aws/lambda/us-east-1.B"
    install({"us-east-1": {"groups": [([a], "lg-1"), ([b], None)],
                           "events": {a: [1], b: [2]}}})
    assert ar.scan_edge_analytics_failures() == 3
    assert len(rec["described"]) == 2, "没有翻第二页日志组"


def test_regions_come_from_the_api_not_a_hardcoded_list(monkeypatch):
    """区清单必须**运行时问 AWS**。

    硬编码区列表就是不可移植：别的部署不知道自己的 POP 会落在哪些区，而
    Lambda@Edge 的执行区随 CloudFront 的 POP 走、还会随 AWS 新开区变化。
    """
    import access_rollup as ar

    class _FakeEc2:
        def describe_regions(self):
            return {"Regions": [{"RegionName": "zz-fake-2"},
                                {"RegionName": "aa-fake-1"}]}

    monkeypatch.setattr(ar.boto3, "client",
                        lambda service, **kw: _FakeEc2() if service == "ec2"
                        else pytest.fail(f"不该建 {service} client"))
    assert ar.enabled_regions() == ["aa-fake-1", "zz-fake-2"]


def test_scan_refuses_to_report_a_number_when_no_region_could_be_listed(scan, monkeypatch):
    """枚举不到任何区 ⇒ 结果不可信 ⇒ 抛，而不是返回 0。

    返回 0 就是「全世界都没失败」这个最像健康的谎。
    """
    import access_rollup as ar
    install, _ = scan
    install({})
    with pytest.raises(Exception):
        ar.scan_edge_analytics_failures()


def test_scan_pattern_covers_exactly_the_lines_edge_prints():
    """**从 Edge 源码派生**，不猜：两侧漂了就红。

    逐条配对（M5-FINDINGS §4.8：`assert X in 整个文件` 只能证明"某处提到过"）：
    Edge 里每一条埋点 except 分支打出的 `[WARN] …` 都必须被某个 term 覆盖，
    反过来每个 term 也必须真有一条 print 对应（否则是死 term）。
    """
    import access_rollup as ar
    tree = ast.parse(EDGE_SRC.read_text(encoding="utf-8"))
    targets = {"_record_access", "_maybe_record"}    # 埋点的两条 except 分支
    printed = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name in targets):
            continue
        for h in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]:
            for call in [n for n in ast.walk(h) if isinstance(n, ast.Call)]:
                if getattr(call.func, "id", None) != "print" or not call.args:
                    continue
                arg = call.args[0]
                parts = arg.values if isinstance(arg, ast.JoinedStr) else [arg]
                head = next((p.value for p in parts
                             if isinstance(p, ast.Constant)
                             and isinstance(p.value, str)), "")
                if head.startswith("[WARN]"):
                    printed.append(head)
    assert len(printed) == len(targets) == 2, (
        f"没在 Edge 的埋点 except 分支里找到预期数量的 WARN print：{printed}")
    for head in printed:                     # 每一条都要被覆盖
        assert any(head.startswith(t) for t in ar.EDGE_FAILURE_TERMS), (
            f"Edge 打的 {head!r} 不在扫描 term 里 ⇒ 这类失败无人监控")
    for term in ar.EDGE_FAILURE_TERMS:       # 反过来不许有死 term
        assert any(h.startswith(term) for h in printed), (
            f"term {term!r} 在 Edge 源码里没有对应的 print ⇒ 死 term")


def test_scan_pattern_is_an_or_of_quoted_phrases():
    """`?A ?B` 才是 OR；空格分隔的裸短语在 CloudWatch 里是 **AND**。

    写错方向的症状是「一条都匹配不到」而两侧单测照样绿，所以这里按字面钉住。
    形态已对真日志组实测（`?"[INFO] m5-region" ?"[WARN] 埋点判定失败"` 命中
    17 条，只留后一项命中 0 条）。
    """
    import access_rollup as ar
    assert ar.EDGE_FAILURE_PATTERN == " ".join(
        f'?"{t}"' for t in ar.EDGE_FAILURE_TERMS)
    assert ar.EDGE_FAILURE_PATTERN.count("?") == len(ar.EDGE_FAILURE_TERMS) >= 2


def test_log_group_discovery_does_not_hardcode_this_deployment_s_stack_name():
    """路由层栈名是**每个部署可以不一样**的（`router/config.ini` 的
    `[CDK] stack_name` + `[LambdaEdge] origin_request_function_name` 拼出 Edge
    函数名），所以扫描只能按 Lambda@Edge 日志组的**形状**发现：
    `/aws/lambda/{函数归属区}.{函数名}` —— 前缀里的区是**归属区**（Edge 函数只能
    建在 us-east-1），在每个执行区都一样，与执行区无关。
    """
    import access_rollup as ar
    cfg = configparser.ConfigParser()
    cfg.read(ROUTER_CFG_EXAMPLE, encoding="utf-8")
    stack_name = cfg.get("CDK", "stack_name")
    assert stack_name, "读不到示例配置里的栈名——本条空转"
    src = ROLLUP_SRC.read_text(encoding="utf-8")
    assert stack_name not in src, (
        f"{stack_name!r} 被写进了 access_rollup.py ⇒ 换个部署就扫不到日志组")
    assert ar.EDGE_LOG_GROUP_PREFIX == "/aws/lambda/us-east-1."


def test_zero_failures_are_published_explicitly(tables, scan, cw):
    """**扫成功且为 0 时必须发一个显式 0**。

    只在有失败时才发的话，「健康」与「扫描器瞎了」在指标上是同一个形态
    （都没有数据点），告警无法区分。发了显式 0 之后，缺数据只剩一个含义
    ——本轮没扫成——由告警的 TreatMissingData=breaching 接住。这是整个设计的承重点。
    """
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(0)})
    out = ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    assert len(cw) == 1, f"应当发**恰好一个**数据点：{cw}"
    datum = cw[0]["MetricData"][0]
    assert datum["Value"] == 0
    assert out["edge_failures"] == 0


def test_failures_are_published_as_the_measured_count(tables, scan, cw):
    import access_rollup as ar
    install, _ = scan
    install({"ap-southeast-1": _one_group(2), "us-east-1": _one_group(1)})
    out = ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    assert len(cw) == 1
    assert cw[0]["MetricData"][0]["Value"] == 3
    assert out["edge_failures"] == 3


def test_the_metric_has_no_dimensions_so_one_alarm_covers_every_pop(tables, scan, cw):
    """加了区维度就又回到「按区建告警」——那正是这次要拆掉的东西。"""
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(0)})
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    assert len(cw) == 1
    datum = cw[0]["MetricData"][0]
    assert datum.get("Dimensions", []) == [], datum
    assert cw[0]["Namespace"] == ar.METRIC_NAMESPACE
    assert datum["MetricName"] == ar.METRIC_NAME


def test_scan_failure_publishes_nothing_and_still_seals_the_day(tables, cw, caplog,
                                                                monkeypatch):
    """扫描炸了也**不能**影响封口——封口是耐久工作，扫日志只是观测。

    而且失败**不许静默**：既不发 0（那会让坏掉的扫描器长期伪装成健康），
    也不能只 `except: pass`（M5-FINDINGS §4.2/§4.20）。留一条 warning 供排查，
    真正的信号是「指标缺数据」。
    """
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co")

    def _boom(*a, **k):
        raise RuntimeError("扫描挂了")

    monkeypatch.setattr(ar, "scan_edge_analytics_failures", _boom)
    with caplog.at_level("WARNING"):
        out = ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    assert got["Count"] == 1 and got["Items"][0]["pv"]["N"] == "1", "封口被带崩了"
    assert cw == [], "扫描失败时**不能**发任何数据点（发 0 = 伪装成健康）"
    assert out["edge_failures"] is None
    warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warned, "失败没有留下任何 warning ⇒ 纯静默失败"
    assert any("扫描" in m and "不发指标" in m for m in warned), warned


def test_the_scan_runs_after_the_sealing(tables, scan, cw, monkeypatch):
    """顺序有意义：耐久工作先做完，观测工作放最后。"""
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(0)})
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    order, real = [], ar.rollup_day

    def _seal(site_id, day):
        order.append("seal")
        return real(site_id, day)

    real_scan = ar.scan_edge_analytics_failures

    def _scan(*a, **k):
        order.append("scan")
        return real_scan(*a, **k)

    monkeypatch.setattr(ar, "rollup_day", _seal)
    monkeypatch.setattr(ar, "scan_edge_analytics_failures", _scan)
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    assert order, "一次都没调到——本条空转"
    assert order[-1] == "scan" and "seal" in order, order


def test_backfill_stamps_the_datapoint_at_the_end_of_the_scanned_window(
        tables, scan, cw):
    """`scan_end_offset_hours` 用来补发已过去的窗口（扫描器停过一段之后回填）。

    数据点必须打在**被扫窗口的结束时刻**，否则补发的值会落在今天，把两天的
    结论混成一天。
    """
    import access_rollup as ar
    install, rec = scan
    install({"us-east-1": _one_group(0)})
    before = datetime.now(timezone.utc) - timedelta(hours=30)
    ar.handler({"days": [], "sites": [], "scan_end_offset_hours": 30}, None)
    assert len(cw) == 1
    stamped = cw[0]["MetricData"][0]["Timestamp"]
    assert abs((stamped - before).total_seconds()) < 60, stamped
    assert rec["filtered"], "没有真的扫"
    end_ms = rec["filtered"][0][1]["endTime"]
    assert abs(end_ms / 1000 - before.timestamp()) < 60


# ══════════════════════════════════════════════════════════════════════
# 扫描的资源上界（2026-08-15 线上回归：`Runtime.OutOfMemory`）
#
# 上线后约一半调用挂在 `Runtime.OutOfMemory`（256MB 的函数，六次 REPORT 全部
# used=255~256/256MB）。根因不是扫描逻辑——是 `_logs_client` **每区新建一个
# boto3 Session**：每个 Session 各自加载一份 botocore 的 endpoints/服务模型
# （本机实测 ≈12.3MB/个），18 个已启用区 × 并发 8 就是 200MB+ 的活内存。
#
# 而**区数与日志组数都不是我们的输入**：AWS 会开新区，别的团队会往本账号部署
# Edge 函数（前缀发现会一起扫到）。所以光调大内存不够——下面两条钉的是"上界由
# 我们控制的量决定"：活着的 Session 数由**线程数**钉住，扫描时长由**预算**钉住。
# 两条都必须保住原有的两条纪律：① 建 client 的入口线程私有（不许退回模块级
# 共享 Session/client）；② 读不到就抛，绝不返回部分和（部分和 = 伪装成健康）。
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def sessions(monkeypatch):
    """接住 **Session 工厂**而不接管 `_logs_client`——要测的正是后者的生命周期。

    返回 `install(specs) -> (made, used, rec)`：
      `made` —— `[(session id, 建它的线程 id), ...]`
      `used` —— `[(session id, 用它建 client 的线程 id, region), ...]`
    """
    import access_rollup as ar
    rec, made, used, box = {"described": [], "filtered": []}, [], [], {}

    class _FakeSession:
        def __init__(self):
            made.append((id(self), threading.get_ident()))

        def client(self, service, **kw):
            region = kw.get("region_name")
            used.append((id(self), threading.get_ident(), region))
            assert service == "logs", f"扫描只该建 logs client：{service}"
            return _FakeLogs(region, box["specs"][region], rec)

    def install(specs: dict):
        box["specs"] = specs
        monkeypatch.setattr(ar, "enabled_regions", lambda: list(specs))
        monkeypatch.setattr(ar.boto3.session, "Session", _FakeSession)
        # 线程本地状态是模块级的，主线程那份会跨用例残留。`raising=False`：
        # 这个属性还不存在时（= 修复前）不许把断言的红变成夹具的错。
        monkeypatch.setattr(ar, "_thread_state", threading.local(), raising=False)
        return made, used, rec

    return install


def test_live_sessions_are_bounded_by_worker_count_not_region_count(sessions):
    """活着的 boto3 Session 数由 `SCAN_WORKERS` 钉住，**不随区数增长**。

    这就是 2026-08-15 那次 OOM 的那颗旋钮：每区一个 Session ⇒ 内存随 AWS 开新区
    线性上涨，而开区不是我们说了算的。每**线程**一个 Session 之后上界是
    `SCAN_WORKERS`（≤8 份 botocore 数据），与区数无关。
    """
    import access_rollup as ar
    specs = {f"r-{i}": _one_group(1) for i in range(18)}
    assert len(specs) > ar.SCAN_WORKERS, "区数没超过线程数 ⇒ 本条空转"
    made, _, _ = sessions(specs)
    assert ar.scan_edge_analytics_failures() == 18       # 一区不落
    assert made, "一个 Session 都没建 ⇒ 本条空转（工厂没被接住）"
    assert len(made) <= ar.SCAN_WORKERS, (
        f"建了 {len(made)} 个 Session 扫 {len(specs)} 个区——上界应当是线程数 "
        f"{ar.SCAN_WORKERS}，否则内存随区数涨")


def test_no_session_is_shared_across_threads(sessions):
    """线程安全那一半不许丢：每个 Session 只许被**建它的那个线程**使用。

    boto3 的默认 session 不是线程安全的建 client 入口（并发建 client 会撞上共享的
    loader 缓存），所以"省内存"的正确方向是每线程一个，**不是**退回模块级共享。
    这条在修复前后都该绿——它是防止修复方向跑偏的那道反向闸门。
    """
    import access_rollup as ar
    made, used, _ = sessions({f"r-{i}": _one_group(1) for i in range(18)})
    ar.scan_edge_analytics_failures()
    owner = dict(made)
    assert used, "没有任何 client 被建出来 ⇒ 本条空转"
    assert len({tid for _, tid, _ in used}) > 1, "只跑了一个线程 ⇒ 本条空转"
    for sid, tid, region in used:
        assert sid in owner, f"{region} 用的 Session 不是本次扫描建的"
        assert owner[sid] == tid, (
            f"{region} 在线程 {tid} 里用了属于线程 {owner[sid]} 的 Session "
            f"⇒ 建 client 的入口被并发共享")


def test_the_scan_gives_up_on_its_own_budget_instead_of_eating_the_timeout(
        scan, monkeypatch):
    """预算耗尽 ⇒ **抛**，不返回已经数到的那部分。

    日志组数同样不是我们的输入（别的团队往本账号部署 Edge 函数，前缀发现会一起
    扫到），所以扫描要有自己的时限——不然它会一路吃到 Lambda 的 300s 超时，把
    **封口那次调用**也标记成失败（EventBridge 重试 + DLQ + 拖响存活告警）。
    """
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(3)})
    monkeypatch.setattr(ar, "SCAN_BUDGET_SECONDS", 0)
    with pytest.raises(ar.ScanIncomplete):
        ar.scan_edge_analytics_failures()


def test_the_budget_is_checked_between_pages_not_only_before_the_first_call(
        scan, monkeypatch):
    """预算要在**翻页之间**查。

    一个区里的组数 × 每组的页数全在一次 `_scan_region` 里，只在入口查一次等于没有
    上界。这里的假时钟在**第一页事件返回之后**才跳过预算：那之后必须停手（第二页
    不再发出），而不是把这一组翻完。
    """
    import access_rollup as ar
    install, rec = scan
    name = "/aws/lambda/us-east-1.Edge"
    install({"us-east-1": {"groups": [([name], None)],
                           "events": {name: [1, 1]}}})
    monkeypatch.setattr(ar.time, "monotonic",
                        lambda: 1000.0 if rec["filtered"] else 0.0)
    with pytest.raises(ar.ScanIncomplete):
        ar.scan_edge_analytics_failures()
    assert len(rec["described"]) == 1, rec["described"]
    assert len(rec["filtered"]) == 1, (
        f"预算超了之后还在翻页（发了 {len(rec['filtered'])} 次 filter）"
        "⇒ 检查点不在循环里")


def test_the_budget_shrinks_to_what_this_invocation_has_left(tables, scan, cw,
                                                             monkeypatch):
    """真源是**本次调用剩下的时间**：封口在前，慢的那天剩余时间才是真上界。

    固定预算只是上限的另一半（部署期由 CDK 断言钉在 Timeout 之内），两者取小。
    """
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(0)})
    seen = []
    real = ar.scan_edge_analytics_failures

    def _spy(end=None, budget_seconds=None):
        seen.append(budget_seconds)
        return real(end, budget_seconds)

    monkeypatch.setattr(ar, "scan_edge_analytics_failures", _spy)

    class _Ctx:
        def get_remaining_time_in_millis(self):
            return 40_000

    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, _Ctx())
    assert seen and seen[0] is not None, "handler 没有把预算传下去"
    assert seen[0] < ar.SCAN_BUDGET_SECONDS, (
        f"剩 40s 时的预算还是固定的 {ar.SCAN_BUDGET_SECONDS}s ⇒ 会吃穿超时")
    assert seen[0] <= 40 - ar.SCAN_TIME_MARGIN_SECONDS + 0.5, seen


def test_a_budget_stop_is_not_reported_as_zero_failures(tables, scan, cw, caplog,
                                                        monkeypatch):
    """预算停手是「读不到」，**不是「没有失败」**——一个数据点都不许发。

    与已有的 `test_scan_failure_publishes_nothing_and_still_seals_the_day` 的区别：
    那条把 `scan_edge_analytics_failures` 整个替成抛异常的桩，走不到新加的这条
    真实路径。这条驱动的是**真的预算守卫**，并且顺带钉住封口不受影响。
    """
    import access_rollup as ar
    install, _ = scan
    install({"us-east-1": _one_group(7)})
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    monkeypatch.setattr(ar, "SCAN_BUDGET_SECONDS", 0)
    with caplog.at_level("WARNING"):
        out = ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    assert cw == [], "预算停手时发了数据点 ⇒ 「读不到」被伪装成了一个数字"
    assert out["edge_failures"] is None
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    assert got["Count"] == 1 and got["Items"][0]["pv"]["N"] == "1", "封口被带崩了"
    assert any("不发指标" in r.getMessage() for r in caplog.records
               if r.levelname == "WARNING"), "预算停手没留下 warning ⇒ 纯静默"


def test_no_remaining_time_means_no_number_at_all(tables, scan, cw):
    """剩余时间已经不够收尾 ⇒ 连扫都不开始，照样不发 0。"""
    import access_rollup as ar
    install, rec = scan
    install({"us-east-1": _one_group(7)})

    class _Ctx:
        def get_remaining_time_in_millis(self):
            return 1_000

    out = ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, _Ctx())
    assert out["edge_failures"] is None
    assert cw == []
    assert rec["filtered"] == [], "没有预算却还是发了 filter 调用"


def test_access_rollup_stays_pure_stdlib_plus_boto3():
    """本模块被复制进 panel 与 MCP 的产物，多一个依赖就是三处部署的事。"""
    tree = ast.parse(ROLLUP_SRC.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots, "一个 import 都没解析出来——本条空转"
    allowed = {"boto3", "botocore", "concurrent", "datetime", "logging", "os",
               "threading", "time"}
    assert roots <= allowed, f"引入了不该有的依赖：{sorted(roots - allowed)}"
