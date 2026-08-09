import re
import common


def test_job_lifecycle(aws):
    jid = common.create_job("a@x.com", "demo-abc123")
    job = common.get_job(jid)
    assert job["status"] == "PENDING" and job["owner"] == "a@x.com"
    common.update_job(jid, status="RUNNING", phase="validate")
    assert common.get_job(jid)["phase"] == "validate"
    common.update_job(jid, status="FAILED", error="boom")
    j = common.get_job(jid)
    assert j["status"] == "FAILED" and j["error"] == "boom"


def test_update_job_with_no_fields_only_touches_updated_at(aws):
    jid = common.create_job("a@x.com", "demo-abc123")
    before = common.get_job(jid)
    common.update_job(jid)  # 不传任何可选字段：不应崩溃
    after = common.get_job(jid)
    assert after["status"] == "PENDING"
    assert after["updated_at"] >= before["updated_at"]


def test_list_jobs_by_owner(aws):
    a = common.create_job("a@x.com", "s1")
    common.create_job("b@x.com", "s2")
    mine = common.list_jobs_by_owner("a@x.com")
    assert [j["job_id"] for j in mine] == [a]


def test_site_upsert_and_get(aws):
    common.upsert_site("demo-abc123", owner="a@x.com", tier="static",
                       subdomain="app-demo-abc123", status="ACTIVE")
    s = common.get_site("demo-abc123")
    assert s["tier"] == "static"
    common.upsert_site("demo-abc123", status="DELETED")
    assert common.get_site("demo-abc123")["status"] == "DELETED"
    assert common.get_site("demo-abc123")["owner"] == "a@x.com"  # 未覆盖字段保留


def test_id_helpers():
    # 合同允许最长 30 字符；site_id 取前 20 字符 + 6 位随机后缀
    sid = common.new_site_id("my-long-project-name-abcdefg")
    assert re.match(r"^[a-z][a-z0-9-]{0,19}-[a-z0-9]{6}$", sid)
    assert common.subdomain_for("x-1a2b3c") == "app-x-1a2b3c"
    assert common.dsql_schema_for("x-1a2b3c") == "site_x1a2b3c"


def test_site_name_rejects_sql_and_resource_name_hazards():
    """site_name 会成为 DSQL 标识符与 IAM/Lambda 资源名，必须在入口拦下。"""
    import pytest
    for bad in ['x" ; CREATE ROLE attacker WITH LOGIN SUPERUSER; --',
                "MySite With Spaces!", "UPPER", "-lead", "has_underscore",
                "a", "x" * 31, "", "sql'inject"]:
        with pytest.raises(common.InvalidSiteName):
            common.new_site_id(bad)
    # 合法名照常通过
    for good in ("expense-tracker", "notes", "a1", "x" * 30):
        assert common.new_site_id(good)


def test_list_sites_by_owner_uses_gsi(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", name="one")
    common.upsert_site("s-2", owner="o@x.com", name="two")
    common.upsert_site("s-3", owner="other@x.com", name="three")
    got = {s["site_id"] for s in common.list_sites_by_owner("o@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_by_owner_empty(aws):
    import common
    assert common.list_sites_by_owner("nobody@x.com") == []


def test_list_sites_for_user_includes_collaborations(aws):
    import common
    common.upsert_site("s-1", owner="me@x.com", collaborators=[])
    common.upsert_site("s-2", owner="other@x.com", collaborators=["me@x.com"])
    common.upsert_site("s-3", owner="other@x.com", collaborators=["nope@x.com"])
    got = {s["site_id"] for s in common.list_sites_for_user("me@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_for_user_dedups(aws):
    import common
    # 理论上 owner 不该同时在 collaborators 里（permissions 层会拦），
    # 但历史数据可能有——不能返回重复项
    common.upsert_site("s-1", owner="me@x.com", collaborators=["me@x.com"])
    got = [s["site_id"] for s in common.list_sites_for_user("me@x.com")]
    assert got == ["s-1"]


def test_list_jobs_by_site_returns_newest_first(aws):
    for jid, ts in [("job-1", "2026-06-01T00:00:00+00:00"),
                    ("job-2", "2026-07-01T00:00:00+00:00"),
                    ("job-3", "2026-05-01T00:00:00+00:00")]:
        common._table("JOBS_TABLE").put_item(Item={
            "job_id": jid, "site_id": "sx", "owner": "u@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": ts, "updated_at": ts})
    # 另一个站点的 job 不得混入
    common._table("JOBS_TABLE").put_item(Item={
        "job_id": "job-other", "site_id": "sy", "owner": "u@x.com",
        "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
        "created_at": "2026-08-01T00:00:00+00:00",
        "updated_at": "2026-08-01T00:00:00+00:00"})
    jobs = common.list_jobs_by_site("sx")
    assert [j["job_id"] for j in jobs] == ["job-2", "job-1", "job-3"]


def test_create_site_record_collision_raises_and_writes_nothing(aws):
    """碰撞必须抛 SiteIdCollision，且已有站点的**每个字段**原样不动。"""
    import pytest
    common._table("SITES_TABLE").put_item(Item={
        "site_id": "victim-abc123", "owner": "victim@x.com",
        "name": "victim", "status": "ACTIVE",
        "created_at": "2026-01-01T00:00:00+00:00"})
    with pytest.raises(common.SiteIdCollision):
        common.create_site_record("victim-abc123",
                                  owner="attacker@x.com", name="attacker")
    site = common.get_site("victim-abc123")
    assert site["owner"] == "victim@x.com"      # 不只 created_at——
    assert site["name"] == "victim"             # owner/name/status 全部
    assert site["status"] == "ACTIVE"           # 必须原样（假绿教训）
    assert site["created_at"] == "2026-01-01T00:00:00+00:00"


def test_create_site_record_writes_full_record_once(aws):
    common.create_site_record("s-new", owner="u@x.com", name="fresh")
    site = common.get_site("s-new")
    assert site["owner"] == "u@x.com" and site["status"] == "DEPLOYING"
    assert site["created_at"]
