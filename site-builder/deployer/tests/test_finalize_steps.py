import boto3
from unittest.mock import MagicMock, patch
import pytest

MANIFEST = {"name": "hello", "tier": "static", "database": {"engine": "none"},
            "auth": {"require_login": True, "allowed_users": ["v@x.com"]}}
EVENT = {"job_id": "job-1", "site_id": "hello-x1", "manifest": MANIFEST}


def test_upload_frontend_versioned_prefix_keeps_old_version(aws):
    import upload_frontend, common
    common.create_job("a@x.com", "hello-x1")
    s3 = boto3.client("s3")
    s3.put_object(Bucket="site-artifacts-1", Key="extracted/job-1/frontend/index.html",
                  Body=b"<h1>hi</h1>")
    # 旧版本（上一个 job 的前缀）——发布期间线上流量仍在用，不得删除
    s3.put_object(Bucket="site-frontend-1", Key="sites/hello-x1/job-0/index.html",
                  Body=b"old")
    upload_frontend.handler(dict(EVENT), None)
    obj = s3.get_object(Bucket="site-frontend-1",
                        Key="sites/hello-x1/job-1/index.html")
    assert obj["ContentType"] == "text/html"
    old = s3.get_object(Bucket="site-frontend-1", Key="sites/hello-x1/job-0/index.html")
    assert old["Body"].read() == b"old"  # 旧版本原样保留


def test_register_route_atomic_switch(aws):
    import register_route, common
    common.create_job("a@x.com", "hello-x1")
    common.upsert_site("hello-x1", owner="a@x.com")
    ddb = boto3.client("dynamodb")
    # 模拟已有旧路由（指向旧 job 前缀）
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-hello-x1"}, "site_id": {"S": "hello-x1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/hello-x1/job-0"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "owner": {"S": "a@x.com"}})
    out = register_route.handler(dict(EVENT), None)
    assert out["url"] == "https://app-hello-x1.example.com"
    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-hello-x1"}})["Item"]
    assert item["static_prefix"]["S"] == "sites/hello-x1/job-1"  # 原子切到新版本
    assert item["route_mode"]["S"] == "split"
    assert item["require_auth"]["BOOL"] is True
    # 二期：allowed_users 投影为 L（原 JSON 字符串写法已废弃；Edge 的 _deser
    # 支持 L 后才能部署本改动）。本站点无权限字段 → 首次部署由 manifest 初始化。
    assert item["allowed_users"]["L"] == [{"S": "v@x.com"}]
    assert item["owner"]["S"] == "a@x.com"


def test_smoke_auth_site_expects_302_to_login(aws):
    import smoke_test
    # require_auth 站点：302 到登录端点 = 健康；200 = 鉴权失效，必须失败
    with patch.object(smoke_test, "_head",
                      return_value=(302, "https://auth.example.com/login?redirect=x")):
        smoke_test.handler({**EVENT, "url": "https://app-hello-x1.example.com"}, None)
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        with pytest.raises(smoke_test.SmokeFailure):
            smoke_test.handler({**EVENT, "url": "https://app-hello-x1.example.com"}, None)


def test_smoke_public_site_expects_200(aws):
    import smoke_test
    ev = {**EVENT, "manifest": {**MANIFEST, "auth": {"require_login": False,
                                                     "allowed_users": "org"}},
          "url": "https://app-hello-x1.example.com"}
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        smoke_test.handler(ev, None)
    with patch.object(smoke_test, "_head", return_value=(500, "")):
        with pytest.raises(smoke_test.SmokeFailure):
            smoke_test.handler(ev, None)


def test_mark_job_success_and_failure(aws):
    import mark_job, common
    j1 = common.create_job("a@x.com", "hello-x1")
    mark_job.handler({"job_id": j1, "site_id": "hello-x1", "manifest": MANIFEST,
                      "url": "https://app-hello-x1.example.com"}, None)
    assert common.get_job(j1)["status"] == "SUCCEEDED"
    assert common.get_site("hello-x1")["status"] == "ACTIVE"
    j2 = common.create_job("a@x.com", "hello-x1")
    mark_job.handler({"job_id": j2, "site_id": "hello-x1",
                      "error_info": {"Cause": "boom"}}, None)
    job = common.get_job(j2)
    assert job["status"] == "FAILED" and "boom" in job["error"]


def test_register_route_seeds_permissions_from_manifest_on_first_deploy(aws):
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", name="one")  # 无权限字段
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True,
                                   "allowed_users": ["a@x.com"]}}}
    register_route.handler(event, None)

    site = common.get_site("s-1")
    assert site["require_login"] is True
    assert site["allowed_users"] == ["a@x.com"]

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is True
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]


def test_register_route_prefers_sites_table_over_manifest(aws):
    """在线改过权限后重部署：manifest 的旧值必须被忽略。"""
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users=["online@x.com"], collaborators=["c@x.com"])
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}}
    register_route.handler(event, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is False           # 线上值，不是 manifest 的 True
    assert item["allowed_users"]["L"] == [{"S": "online@x.com"}]
    assert item["collaborators"]["L"] == [{"S": "c@x.com"}]
    # sites 表不被 manifest 覆盖
    assert common.get_site("s-1")["require_login"] is False


def test_register_route_refuses_stale_snapshot(aws, monkeypatch):
    """并发交错：读到"公开"后，别人把权限改成私有 → 本次不得把路由写回公开。

    模拟 spec §3.2 描述的那条交错：在 register_route 读完 sites、写路由之前，
    在线改权限的事务已经把 sites 与路由都改成私有（rev 也推进了）。
    条件事务必须拒绝这次写入，重读后用新策略成稿。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    job_id = common.create_job("o@x.com", "s-1")

    real_get_site = common.get_site_consistent
    calls = {"n": 0}

    def _racing_get_site(site_id):
        site = real_get_site(site_id)   # real_get_site = common.get_site_consistent
        calls["n"] += 1
        if calls["n"] == 1:
            # 第一次读之后、写路由之前，别人把权限收紧了（rev 推进）
            common.upsert_site(site_id, require_login=True,
                               allowed_users=["vip@x.com"], permissions_rev=1)
        return site

    # 实现用的是 get_site_consistent（强一致），patch 它才能注入竞态；
    # patch get_site 的话回调根本不会执行，测试变成空跑。
    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        _racing_get_site)
    register_route.handler({"job_id": job_id, "site_id": "s-1", "api_target": "",
                            "manifest": {"auth": {"require_login": False,
                                                  "allowed_users": "org"}}}, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    # 最终必须是收紧后的策略，而不是第一次读到的"公开"
    assert item["require_auth"]["BOOL"] is True
    assert item["allowed_users"]["L"] == [{"S": "vip@x.com"}]
    assert int(item["permissions_rev"]["N"]) == 1


def test_register_route_seed_does_not_overwrite_concurrent_online_change(aws):
    """首次部署的初始化必须条件写：不能覆盖并发的首次在线权限修改。"""
    import common
    import register_route
    # 用户在首次部署跑到这一步之前就用控制台设了策略
    common.upsert_site("s-2", owner="o@x.com", require_login=False,
                       allowed_users=["early@x.com"], collaborators=[],
                       permissions_rev=1)
    job_id = common.create_job("o@x.com", "s-2")
    register_route.handler({"job_id": job_id, "site_id": "s-2", "api_target": "",
                            "manifest": {"auth": {"require_login": True,
                                                  "allowed_users": "org"}}}, None)
    site = common.get_site("s-2")
    assert site["require_login"] is False               # 在线值保留
    assert site["allowed_users"] == ["early@x.com"]     # 不被 manifest 覆盖


def test_register_route_uses_consistent_read_after_seed(aws, monkeypatch):
    """seed 刚写完就用最终一致读 → 可能读不到，名单被放大成 org。

    moto 的读默认就是强一致，所以无法真的制造出"副本滞后"。这里换一个
    **不会让正确实现失败**的等价断言：把最终一致的 get_site 打成陷阱
    （一调用即 fail），强一致的 get_site_consistent 保持真实。
    若实现退回 get_site，测试立刻失败；用 get_site_consistent 则读到 seed
    后的真值，名单不会回落成 org。

    **不要**把 get_site_consistent 本身 patch 成陈旧快照：seed 已经把真实
    行的 permissions_rev 写成 1，而陈旧快照算出的 rev=0 会让
    ConditionCheck 每轮都失败，三轮耗尽后实现抛 RuntimeError——正确实现
    也永远到不了下面的断言（已用 moto 实测：3/3 轮 ConditionalCheckFailed）。
    """
    import boto3
    import common
    import register_route

    common.upsert_site("s-1", owner="o@x.com")      # 无权限字段（首次部署）
    job_id = common.create_job("o@x.com", "s-1")

    def _trap(site_id):
        raise AssertionError(
            "register_route 必须用 get_site_consistent（最终一致读会在 seed "
            "之后拿到旧值，_route_item 回落 allowed_users=\"org\"，"
            "把指定名单放大成全体可信 IdP 用户）")

    # 只打陷阱，不动 get_site_consistent——让它照常读到 seed 后的真值。
    # 用 AssertionError 而不是 pytest.fail：pytest.fail 抛的 Failed 继承自
    # BaseException，实现里任何 `except Exception` 都拦不住它，看起来"有效"，
    # 但若实现改成 except BaseException 就会被静默吞掉；AssertionError 是
    # Exception 子类，被吞掉时反而会让断言阶段失败，不会假通过。
    monkeypatch.setattr(register_route.common, "get_site", _trap)

    register_route.handler(
        {"job_id": job_id, "site_id": "s-1", "api_target": "",
         "manifest": {"auth": {"require_login": True,
                               "allowed_users": ["a@x.com"]}}}, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    # 必须是 manifest 指定的名单，不能回落成 org
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]
    assert item["allowed_users"].get("S") is None
    assert int(item["permissions_rev"]["N"]) == 1


def test_seed_advances_rev_to_one(aws):
    """初始化把 rev 从"缺失"推进到 1，与未初始化状态可区分。"""
    import common
    import register_route
    common.upsert_site("s-2", owner="o@x.com")
    job_id = common.create_job("o@x.com", "s-2")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-2", "api_target": "",
         "manifest": {"auth": {"require_login": False, "allowed_users": "org"}}},
        None)
    assert int(common.get_site("s-2")["permissions_rev"]) == 1


def test_register_route_emits_effective_auth_for_smoke_test(aws):
    """smoke_test 读 event["effective_auth"]，不读 manifest（spec §3.3.2）。"""
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users=["online@x.com"], collaborators=[])
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}}
    out = register_route.handler(event, None)
    assert out["effective_auth"] == {"require_login": False,
                                     "allowed_users": ["online@x.com"]}


def test_register_route_writes_org_as_string(aws):
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    job_id = common.create_job("o@x.com", "s-1")
    register_route.handler({"job_id": job_id, "site_id": "s-1", "api_target": "",
                            "manifest": {"auth": {"require_login": True,
                                                  "allowed_users": "org"}}}, None)
    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["allowed_users"] == {"S": "org"}
    assert item["collaborators"] == {"L": []}
