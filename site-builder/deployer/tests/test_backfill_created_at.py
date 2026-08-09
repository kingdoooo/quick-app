"""sites.created_at 回填：控制台要显示创建时间，但 upsert_site 全链路从不写它。

只有 jobs 表有 created_at——从该站点最早一条 job 推导。
"""
import sys
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))


def _put_site(site_id, **extra):
    boto3.resource("dynamodb", region_name="us-east-1").Table("site-sites").put_item(
        Item={"site_id": site_id, "owner": "u@x.com", "status": "ACTIVE", **extra})


def _put_job(job_id, site_id, created_at):
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "u@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": created_at, "updated_at": created_at})


def _site(site_id):
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-sites").get_item(Key={"site_id": site_id}).get("Item")


def test_backfills_from_earliest_job(aws):
    import backfill_site_created_at as bf
    _put_site("s1")
    _put_job("job-b", "s1", "2026-07-20T10:00:00+00:00")
    _put_job("job-a", "s1", "2026-06-18T09:41:00+00:00")   # 更早
    out = bf.run(apply=True)
    assert out["updated"] == 1
    assert _site("s1")["created_at"] == "2026-06-18T09:41:00+00:00"


def test_existing_value_is_not_overwritten(aws):
    import backfill_site_created_at as bf
    _put_site("s2", created_at="2026-01-01T00:00:00+00:00")
    _put_job("job-c", "s2", "2026-07-20T10:00:00+00:00")
    out = bf.run(apply=True)
    assert out["skipped_existing"] == 1 and out["updated"] == 0
    assert _site("s2")["created_at"] == "2026-01-01T00:00:00+00:00"


def test_site_without_jobs_is_reported_not_guessed(aws):
    """无 job 的站点**不能猜**创建时间（写 now 会是错的）——报告后跳过。"""
    import backfill_site_created_at as bf
    _put_site("s3")
    out = bf.run(apply=True)
    assert out["no_jobs"] == 1 and out["updated"] == 0
    assert "created_at" not in (_site("s3") or {})


def test_concurrent_writer_between_scan_and_update_is_not_overwritten(aws,
                                                                      monkeypatch):
    """并发写入者在 scan 之后、update 之前落地 created_at —— 不得被覆盖。

    为什么需要这条：`test_existing_value_is_not_overwritten` 被**扫描时的
    `if site.get("created_at"): continue`** 满足，删掉 update 的
    `ConditionExpression` 它照样绿（实测）。两道防护对那条用例互为冗余，
    于是"条件写"这个真正的并发防护没有任何用例盯着。

    脚本先扫全表再逐个写，中间这段窗口才是 ConditionExpression 存在的理由。
    在 jobs 查询（发生在存在性检查之后、update_item 之前）里注入并发写，
    正好命中那一刻。
    """
    import backfill_site_created_at as bf
    _put_site("s5")
    _put_job("job-e", "s5", "2026-05-01T00:00:00+00:00")

    real_resource = boto3.resource

    class _JobsProxy:
        def __init__(self, inner):
            self._inner = inner

        def query(self, **kw):
            # 中间时刻：另一个写入者刚把 created_at 写进去了
            _put_site("s5", created_at="2026-09-09T00:00:00+00:00")
            return self._inner.query(**kw)

        def __getattr__(self, item):
            return getattr(self._inner, item)

    class _ResProxy:
        def __init__(self, inner):
            self._inner = inner

        def Table(self, name):
            t = self._inner.Table(name)
            return _JobsProxy(t) if name == "site-deploy-jobs" else t

    monkeypatch.setattr(
        boto3, "resource",
        lambda *a, **kw: _ResProxy(real_resource(*a, **kw)))

    out = bf.run(apply=True)
    assert out["updated"] == 0, "并发写入的值被回填覆盖了"
    assert out["skipped_existing"] == 1
    assert _site("s5")["created_at"] == "2026-09-09T00:00:00+00:00"


def test_dry_run_writes_nothing(aws):
    import backfill_site_created_at as bf
    _put_site("s4")
    _put_job("job-d", "s4", "2026-05-01T00:00:00+00:00")
    out = bf.run(apply=False)
    assert out["would_update"] == 1
    assert "created_at" not in _site("s4")
