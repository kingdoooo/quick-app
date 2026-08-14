"""panel 读取层单测。

`uv_exact` 是**契约的一部分**，不是可选字段：周/月 UV 只在区间完整落在 90 天
明细窗口内才精确（日 UV 永远精确，聚合行里就存着）。不显示一个站不住的数字。
"""
import base64
import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

EVENTS, DAILY = "site-access-events", "site-access-daily"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ACCESS_EVENTS_TABLE", EVENTS)
    monkeypatch.setenv("ACCESS_DAILY_TABLE", DAILY)
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
        yield d


def _daily(d, site, day, pv, uv, denied=0):
    d.put_item(TableName=DAILY, Item={
        "site_id": {"S": site}, "date": {"S": day},
        "pv": {"N": str(pv)}, "uv": {"N": str(uv)},
        "pv_denied": {"N": str(denied)}, "expires_at": {"N": "9999999999"}})


def _event(d, site, day, email, decision="allow", i=0, path="/"):
    d.put_item(TableName=EVENTS, Item={
        "site_date": {"S": f"{site}#{day}"},
        "ts_id": {"S": f"{day}T01:02:0{i}+00:00#bb{i:02d}"},
        "site_id": {"S": site}, "email": {"S": email},
        "path": {"S": path}, "decision": {"S": decision},
        "expires_at": {"N": "9999999999"}})


def test_daily_series_reads_the_aggregate_table(env):
    import analytics
    y = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    _daily(env, "s1", y, pv=5, uv=2, denied=1)
    out = {b["bucket"]: b for b in analytics.series("s1", "day", 3)}
    assert out[y]["pv"] == 5 and out[y]["uv"] == 2 and out[y]["pv_denied"] == 1
    assert out[y]["uv_exact"] is True, "日 UV 永远精确"


def test_today_is_computed_live_from_details(env):
    """今天还没被封口，必须从明细实时算——否则今天永远显示 0。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _event(env, "s1", today, "a@x.co", i=0)
    _event(env, "s1", today, "a@x.co", i=1)
    _event(env, "s1", today, "b@x.co", i=2)
    out = {b["bucket"]: b for b in analytics.series("s1", "day", 1)}
    assert out[today]["pv"] == 3 and out[today]["uv"] == 2


def test_day_series_uses_the_same_stats_definition_as_rollup():
    """口径唯一：读取层 import rollup 的 day_stats，不另写一份。"""
    import analytics
    import access_rollup
    assert analytics.day_stats is access_rollup.day_stats


def test_month_uv_is_null_and_flagged_outside_the_detail_window(env):
    """超出 90 天明细窗口的月份：PV 可加总，UV 给 null + uv_exact=False。"""
    import analytics
    old = (datetime.now(timezone.utc) - timedelta(days=200))
    _daily(env, "s1", old.strftime("%Y-%m-%d"), pv=9, uv=3)
    buckets = {b["bucket"]: b for b in analytics.series("s1", "month", 8)}
    b = buckets[old.strftime("%Y-%m")]
    assert b["pv"] == 9
    assert b["uv"] is None and b["uv_exact"] is False


def test_empty_bucket_outside_the_window_is_also_flagged(env):
    """P2-2 的回归：零填充之后，**没有任何数据**的旧月份同样要标 uv_exact=False。

    上一版按"桶里有哪些天有数据"判定 → 空桶的 days=[] → any() 为 False →
    被标成 uv_exact=True 且 uv=0，等于对一个查不到的区间宣称"0 个独立访客"。
    """
    import analytics
    out = {b["bucket"]: b for b in analytics.series("never-visited", "month", 8)}
    oldest = sorted(out)[0]
    assert out[oldest]["uv"] is None, out[oldest]
    assert out[oldest]["uv_exact"] is False, out[oldest]
    # 正对照：当前月份（在窗口内）必须给精确的 0，而不是 null
    newest = sorted(out)[-1]
    assert out[newest]["uv"] == 0 and out[newest]["uv_exact"] is True, out[newest]


def test_month_uv_is_exact_inside_the_detail_window(env):
    """正对照：窗口内的月份必须给出精确 UV（跨天去重，不是日 UV 相加）。"""
    import analytics
    now = datetime.now(timezone.utc)
    d1 = (now - timedelta(days=2)).strftime("%Y-%m-%d")
    d2 = (now - timedelta(days=3)).strftime("%Y-%m-%d")
    if d1[:7] != d2[:7]:
        pytest.skip("跨月边界，本条不适用")     # 每月仅约 1/15 的日子会跳过
    _event(env, "s1", d1, "a@x.co", i=0)
    _event(env, "s1", d2, "a@x.co", i=1)
    _daily(env, "s1", d1, pv=1, uv=1)
    _daily(env, "s1", d2, pv=1, uv=1)
    b = {x["bucket"]: x for x in analytics.series("s1", "month", 2)}[d1[:7]]
    assert b["pv"] == 2
    assert b["uv"] == 1, "同一个人跨两天被算成了两个访客（日 UV 不能相加）"
    assert b["uv_exact"] is True


@pytest.mark.parametrize("period,n", [("day", 7), ("week", 1), ("week", 4),
                                      ("month", 1), ("month", 2), ("month", 3)])
def test_series_returns_exactly_n_calendar_aligned_buckets(env, period, n):
    """P2-2 的回归：n 是桶数。上一版用 n×7 / n×31 天回溯，**五种参数全错**
    （month n=1 给 2 个、n=2 给 3 个、week n=4 给 5 个）。"""
    import analytics
    out = analytics.series("s1", period, n)
    assert len(out) == n, f"{period} n={n} 给了 {len(out)} 个桶: {[b['bucket'] for b in out]}"
    keys = [b["bucket"] for b in out]
    assert keys == sorted(keys), "桶没有升序"
    assert len(set(keys)) == n, f"桶键重复: {keys}"


def test_last_bucket_is_the_current_in_progress_one(env):
    """最后一个桶必然是"至今"的当前桶——这是契约，前端据此不给它画完整周期。"""
    import analytics
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).date()
    assert analytics.series("s1", "month", 3)[-1]["bucket"] == today.strftime("%Y-%m")
    assert analytics.series("s1", "day", 3)[-1]["bucket"] == today.isoformat()


def test_pv7_is_always_seven_numbers_oldest_first(env):
    """长度恒为 7 且零填充——前端 sparkline 依赖固定长度，缺失日给 0 不是给空。"""
    import analytics
    from datetime import datetime, timedelta, timezone
    y = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    _daily(env, "s1", y, pv=5, uv=2)
    out = analytics.pv7("s1")
    assert isinstance(out, list) and len(out) == 7, out
    assert all(isinstance(x, int) for x in out), out
    assert out[-2] == 5, f"倒数第二个应是昨天的 5: {out}"
    assert out[-1] == 0, f"最后一个是今天（本轮无数据）: {out}"


def test_pv7_of_a_site_without_data_is_seven_zeros(env):
    import analytics
    assert analytics.pv7("never-visited") == [0] * 7


# ── 首页那条迷你趋势的读取**必须有上界** ───────────────────────────────────
#
# Edge 给**每一个页面级请求**都记一行明细，**包括未登录的 302 redirect_login**
# （`origin_request.py`）。所以任何匿名方只要对一个已知站点反复请求扩展名为空的
# 路径，就能把今天那个明细分区撑到任意大（CloudFront 全站禁缓存是鉴权正确性的
# 前提，每个请求都真的到 Edge）。
#
# 而 `/api/sites` 是控制台**首页**接口：它给每个站点算 pv7，串行。上一版 pv7 走
# `series()`，`series()` 对今天恒走 `_day_rows()` 的 `while True` 全量分页
# —— 于是"今天的行数"这个**攻击者可控的输入**直接决定首页的耗时，31 个站点里
# 只要有一个被灌爆，首页就会撞 panel 的 30s 超时。`_pv7_or_unknown()` 接的是
# `ClientError`/`BotoCoreError`/`KeyError`，**接不住超时**（进程被杀，没有异常），
# 所以 Task 9b 那层降级防的是"错"不防"慢"，而恢复手段（改权限、下线）就在这个
# 首页里。M5-FINDINGS §4.26 记的「当前日均 124」不是安全上界，它是一个可被改写
# 的观测值。
#
# 断言盯的一律是**做了多少活**（打了几次 Query、Query 自己带没带上界），不是
# 墙上时间：耗时断言在系统健康时会偶发变红（§4.20），而且它证明不了"没翻页"。


class _SpyClient:
    """包一层真 client，记下每次 Query 的入参；可选地把明细表伪装成无限分页。

    `events_page_cap` 给了值时：明细表的每次 Query 都返回"还有下一页"，翻到第
    `cap+1` 页就抛错。**这是本组用例的红/绿判据**——无上界的读法会一路翻到抛错
    （红），有上界的读法只打一次（绿）。用抛错而不是真的无限循环，是为了让红是
    一条明确的失败信息而不是挂住。
    """

    def __init__(self, real, events_page_cap=None):
        self._real, self._cap, self.kw = real, events_page_cap, []

    def query(self, **kw):
        self.kw.append(kw)
        if self._cap is not None and kw["TableName"] == EVENTS:
            n = self.tables.count(EVENTS)
            if n > self._cap:
                raise RuntimeError(
                    f"今天的明细被翻了 {n} 页——首页的读取没有上界，"
                    f"行数由匿名请求决定")
            return {"Items": [{"email": {"S": "a@x.co"},
                               "decision": {"S": "allow"}}],
                    "LastEvaluatedKey": {"site_date": {"S": "x#y"},
                                         "ts_id": {"S": f"p{n}"}}}
        return self._real.query(**kw)

    @property
    def tables(self):
        return [k["TableName"] for k in self.kw]

    def of(self, table):
        return [k for k in self.kw if k["TableName"] == table]


def _spy(monkeypatch, analytics, events_page_cap=None):
    spy = _SpyClient(analytics._client(), events_page_cap)
    monkeypatch.setattr(analytics, "_client", lambda: spy)
    return spy


def test_pv7_does_not_paginate_todays_detail_rows(env, monkeypatch):
    """P1 回归：今天的明细再多，首页也只打一次明细 Query，且给出「未知」。

    上一版会一路翻页（本用例会红在 `_SpyClient` 的 RuntimeError 上）。
    """
    import analytics
    spy = _spy(monkeypatch, analytics, events_page_cap=20)
    out = analytics.pv7("s1")
    assert spy.tables.count(EVENTS) <= 1, (
        f"明细表被打了 {spy.tables.count(EVENTS)} 次——首页仍在跟着行数翻页")
    assert out == [], (
        f"今天读不完整时必须给「未知」（`[]`，前端什么都不画），"
        f"不是一个截断出来的、看着像真数据的数: {out}")


def test_pv7_puts_the_bound_in_the_query_itself(env, monkeypatch):
    """上界必须由**读取**落实（Limit / BETWEEN），不是"指望数据不多"。

    只在客户端 `break` 的写法在真机上仍会把整页（最多 1MB）拉回来并反序列化，
    而聚合表那次若只给下界，返回条数就跟着表里有多少天走。
    """
    import analytics
    spy = _spy(monkeypatch, analytics)
    analytics.pv7("s1")
    assert spy.tables == [DAILY, EVENTS], (
        f"pv7 的取数不是「聚合表一次 + 今天一次」: {spy.tables}")
    ev = spy.of(EVENTS)[0]
    assert ev.get("Limit") == analytics.PV7_LIVE_ROW_CAP + 1, (
        f"今天那次 Query 没带服务端上界（Limit=cap+1 才能区分"
        f"「刚好到上界」与「还有更多」）: {ev.get('Limit')}")
    assert "ExclusiveStartKey" not in ev, "首页不该翻页"
    # 聚合表那次必须**两端都有界**（每天最多一行 → 条数 = 区间天数）。断言的是
    # "键条件里引用了一个上界值、且那个值是今天"，不是某个写法（BETWEEN 与
    # `#d <= :until` 等价，钉字面量会让等价改写变成假红）。
    dk = spy.of(DAILY)[0]
    assert ":until" in dk["KeyConditionExpression"], (
        f"聚合表那次只有下界，返回条数跟着表里存了多少天走: "
        f"{dk['KeyConditionExpression']!r}")
    assert dk["ExpressionAttributeValues"][":until"]["S"] == \
        datetime.now(timezone.utc).strftime("%Y-%m-%d"), dk


def test_pv7_is_unknown_instead_of_truncated_beyond_the_cap(env, monkeypatch):
    """真表（moto）上过一遍 Limit 语义：超上界 → `[]`；上界之内 → 真数。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(3):
        _event(env, "s1", today, "a@x.co", i=i)
    monkeypatch.setattr(analytics, "PV7_LIVE_ROW_CAP", 3)
    assert analytics.pv7("s1")[-1] == 3, "**刚好到上界**必须照常给真数（差一错）"
    _event(env, "s1", today, "a@x.co", i=4)
    assert analytics.pv7("s1") == [], "超出上界必须是「未知」"
    monkeypatch.setattr(analytics, "PV7_LIVE_ROW_CAP", 50)
    assert analytics.pv7("s1")[-1] == 4, "放宽上界后要能重新给出真数"


def test_the_analytics_page_still_counts_every_row_today(env, monkeypatch):
    """**明确不动的那一面**：单站统计页是刻意打开的视图，今天照旧精确、照旧分页。

    首页的上界不得漏进 `series()`——否则为了修首页把统计页的准确性一起改了。
    """
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(5):
        _event(env, "s1", today, f"u{i}@x.co", i=i)
    monkeypatch.setattr(analytics, "PV7_LIVE_ROW_CAP", 2)
    spy = _spy(monkeypatch, analytics)
    out = {b["bucket"]: b for b in analytics.series("s1", "day", 1)}
    assert out[today]["pv"] == 5, f"统计页的今天被首页的上界截断了: {out[today]}"
    assert "Limit" not in spy.of(EVENTS)[0], (
        "首页的 Limit 漏进了 series()——统计页会静默少数")


def test_visitors_returns_rows_with_decision_and_paginates(env):
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(3):
        _event(env, "s1", today, f"u{i}@x.co", i=i, path=f"/p{i}")
    page = analytics.visitors("s1", days=1, limit=2, cursor=None)
    assert len(page["rows"]) == 2 and page["next"]
    assert set(page["rows"][0]) == {"ts", "email", "path", "decision"}
    page2 = analytics.visitors("s1", days=1, limit=2, cursor=page["next"])
    assert len(page2["rows"]) == 1 and page2["next"] is None


def test_visitors_includes_denied_attempts(env):
    """被拒记录是本轮明确要的能力。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _event(env, "s1", today, "out@x.co", decision="denied_403", i=0)
    rows = analytics.visitors("s1", days=1, limit=10, cursor=None)["rows"]
    assert [r["decision"] for r in rows] == ["denied_403"]


@pytest.mark.parametrize("days,limit", [(91, 10), (1, 101), (0, 10), (1, 0)])
def test_visitors_rejects_out_of_range_parameters(env, days, limit):
    """days ≤ 90（= 明细留存），limit ≤ 100。越界报 ValueError → 400。"""
    import analytics
    with pytest.raises(ValueError):
        analytics.visitors("s1", days=days, limit=limit, cursor=None)


# ── 游标：**每一种可纠正的错都必须是稳定的 400** ─────────────────────────────
#
# 上一版 `_decode()` 只判"能不能 base64+JSON 解出来"，不判解出来的**形状**。
# 于是一批语法合法、形状不对的游标会在业务代码里炸出 `AttributeError` /
# `TypeError`（`handler.py` 只把 `ValueError` 映射成 400）→ 调用方拿到 500，
# 一个纯入参问题被表述成"服务故障"。逐条列在下面的 `why` 里。

def _cur(state) -> str:
    return base64.urlsafe_b64encode(json.dumps(state).encode()).decode()


def _key(site, day, ts="2026-01-01T00:00:00+00:00#abc"):
    return {"site_date": {"S": f"{site}#{day}"}, "ts_id": {"S": ts}}


BAD_CURSORS = [
    (lambda s, d: [], "JSON 数组——`state.get()` 抛 AttributeError → 500"),
    (lambda s, d: "x", "JSON 字符串——同上"),
    (lambda s, d: 3, "JSON 数字"),
    (lambda s, d: None, "JSON null"),
    (lambda s, d: {"day": 123}, "day 是数字——后面 str/int 比较抛 TypeError → 500"),
    (lambda s, d: {"day": "2026-8-1"}, "day 不是 ISO 日期"),
    (lambda s, d: {"day": "9999-01-01"}, "day 在未来"),
    (lambda s, d: {"day": "1999-01-01"}, "day 早于本次 days 覆盖的窗口"),
    (lambda s, d: {"day": d, "extra": 1}, "多出本接口从不发的字段"),
    (lambda s, d: {"key": _key(s, d)}, "有 key 没有 day（无法判定它属于哪一天）"),
    # 这一条是"有 key 必须有 day"那个守卫**唯一**能单独变红的输入：day 缺失时
    # 绑定判据退化成 `f"{site_id}#None"`，于是一个字面写着 `站点#None` 的分区键
    # 会**通过**绑定判定，然后被拿去当另一天分区的 ExclusiveStartKey——真机
    # ValidationException → 500。moto 不校验这个（M5-FINDINGS §4.6），所以没有
    # 这条用例时，那个守卫在单测里是不可观测的。
    (lambda s, d: {"key": _key(s, "None")}, "site_date 里写着字面量 None"),
    (lambda s, d: {"day": d, "key": []}, "key 不是字典"),
    (lambda s, d: {"day": d, "key": {"site_date": {"S": f"{s}#{d}"}}}, "key 缺 ts_id"),
    (lambda s, d: {"day": d, "key": {**_key(s, d), "email": {"S": "a@x.co"}}},
     "key 多带非键属性（真机 ValidationException → 500）"),
    (lambda s, d: {"day": d, "key": {"site_date": {"S": f"{s}#{d}"},
                                     "ts_id": {"N": "1"}}}, "ts_id 的类型不是 S"),
    (lambda s, d: {"day": d, "key": {"site_date": "x", "ts_id": "y"}},
     "键值不是 DynamoDB AttributeValue"),
    (lambda s, d: {"day": d, "key": _key("other-site", d)},
     "分区键被改成别的站点（真机 ValidationException → 500，M5-FINDINGS §4.21）"),
    (lambda s, d: {"day": d, "key": _key(s, "1999-01-01")},
     "分区键里的日期与 day 不一致"),
]


@pytest.mark.parametrize("make,why", BAD_CURSORS,
                         ids=[str(i) for i in range(len(BAD_CURSORS))])
def test_visitors_rejects_cursors_of_the_wrong_shape(env, make, why):
    """形状不对的游标一律 ValueError（→ 400），一个都不许漏成 500。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with pytest.raises(ValueError):
        analytics.visitors("s1", days=1, limit=5,
                           cursor=_cur(make("s1", today)))
    # 反向：同一个游标不能只是"抛了别的异常"就算过——上面那句用 ValueError
    # 精确匹配，AttributeError / TypeError / ClientError 都会让本条红。


def test_a_cursor_cannot_be_replayed_against_another_site(env):
    """游标**绑站点**：s1 的游标拿到 s2 上必须 400，而不是去读 s2 的分区。

    形态上它本来就读不到 s1 的数据（分区键在游标里），但"把别人的游标原样投进
    另一个上下文"是一个不该有清晰失败信息的入口——绑定让它在**业务代码之前**
    就被拒，也顺手把 §4.21 那条实测出来的 500 变成 400。
    """
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(3):
        _event(env, "s1", today, f"u{i}@x.co", i=i)
    nxt = analytics.visitors("s1", days=1, limit=1)["next"]
    assert nxt, "前置条件不成立：没拿到游标"
    assert analytics.visitors("s1", days=1, limit=1, cursor=nxt)["rows"], \
        "正对照：原站点上这个游标必须照常能翻页"
    with pytest.raises(ValueError):
        analytics.visitors("s2", days=1, limit=1, cursor=nxt)


def test_a_valid_cursor_survives_a_wider_window(env):
    """正对照：合法游标在**更宽**的窗口里照常可用（校验不是"只准原样重放"）。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(3):
        _event(env, "s1", today, f"u{i}@x.co", i=i)
    nxt = analytics.visitors("s1", days=1, limit=1)["next"]
    page = analytics.visitors("s1", days=7, limit=1, cursor=nxt)
    assert len(page["rows"]) == 1, page
