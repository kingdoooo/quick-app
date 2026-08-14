"""panel 读取层单测。

`uv_exact` 是**契约的一部分**，不是可选字段：周/月 UV 只在区间完整落在 90 天
明细窗口内才精确（日 UV 永远精确，聚合行里就存着）。不显示一个站不住的数字。
"""
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
