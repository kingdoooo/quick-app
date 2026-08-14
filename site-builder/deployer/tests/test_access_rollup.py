"""rollup 单测。用 moto 建两张表。

**moto 不校验 IAM**——本文件全绿不代表线上角色有对应权限；IAM 由 Task 6 的
CDK 断言 + Task 13 的真机闸门各自盯（M4 踩过：事务里的 ConditionCheck 漏给
权限时单测全绿、真机 500）。
"""
import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

EVENTS = "site-access-events"
DAILY = "site-access-daily"


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
