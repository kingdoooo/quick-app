import json
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
    tx_attempts = {"n": 0}

    def _racing_get_site(site_id):
        site = real_get_site(site_id)   # real_get_site = common.get_site_consistent
        calls["n"] += 1
        if calls["n"] == 2:
            # **必须在第 2 次读（循环内的读）之后注入**。第 1 次读是 handler
            # 顶部 seed 前的预读——在那儿注入的话，循环读到的已经是收紧后的
            # 新值，第一笔事务直接成功，重试路径从未执行：把 ConditionCheck
            # 整个删掉、MAX_ROUTE_ATTEMPTS 改 1，测试照样全绿（moto 实测，
            # 上一版正是这么假绿的）。在循环读之后注入，循环拿到的才是
            # 陈旧快照，事务被 rev 条件取消，才走到重读重试。
            common.upsert_site(site_id, require_login=True,
                               allowed_users=["vip@x.com"], permissions_rev=1)
        return site

    # 实现用的是 get_site_consistent（强一致），patch 它才能注入竞态；
    # patch get_site 的话回调根本不会执行，测试变成空跑。
    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        _racing_get_site)

    # 数事务次数：只断言最终路由状态无法区分"条件事务重试后成稿"与
    # "根本没有条件保护、一把裸写"。>=2 才证明第一笔被取消、重试发生过。
    real_client = boto3.client

    def _counting_client(*args, **kwargs):
        client = real_client(*args, **kwargs)
        if args and args[0] == "dynamodb":
            real_tx = client.transact_write_items

            def _wrapped(**kw):
                tx_attempts["n"] += 1
                return real_tx(**kw)

            client.transact_write_items = _wrapped
        return client

    monkeypatch.setattr(register_route.boto3, "client", _counting_client)
    out = register_route.handler(
        {"job_id": job_id, "site_id": "s-1", "api_target": "",
         "manifest": {"auth": {"require_login": False,
                               "allowed_users": "org"}}}, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    # 最终必须是收紧后的策略，而不是循环第一次读到的"公开"
    assert item["require_auth"]["BOOL"] is True
    assert item["allowed_users"]["L"] == [{"S": "vip@x.com"}]
    assert int(item["permissions_rev"]["N"]) == 1
    assert tx_attempts["n"] >= 2        # 第一笔被 rev 条件取消 → 真的重试了
    # effective_auth 必须来自最终成稿的那次快照（不是重试前的旧快照）——
    # 它喂给 smoke_test，取错快照会把成功部署判成 FAILED（Task 5b）。
    assert out["effective_auth"] == {"require_login": True,
                                     "allowed_users": ["vip@x.com"]}


def test_register_route_gives_up_after_max_attempts(aws, monkeypatch):
    """重试耗尽必须让部署 FAILED——绝不用旧快照把路由写回公开。

    每次循环读之后都推进 rev（持续冲突），三次全被取消后应抛 RuntimeError，
    且路由表里没有 item（宁可失败也不留下陈旧的公开状态）。
    MAX_ROUTE_ATTEMPTS 改 1 或删掉 ConditionCheck 都会让本测试失败。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    job_id = common.create_job("o@x.com", "s-1")
    real = common.get_site_consistent
    state = {"rev": 0, "reads": 0}

    def _always_racing(site_id):
        site = real(site_id)
        state["reads"] += 1
        if state["reads"] >= 2:                 # 循环内的每次读之后都被人抢先
            state["rev"] += 1
            common.upsert_site(site_id, permissions_rev=state["rev"] + 100)
        return site

    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        _always_racing)
    with pytest.raises(RuntimeError, match="并发修改"):
        register_route.handler(
            {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": False,
                                   "allowed_users": "org"}}}, None)
    assert "Item" not in boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})


def test_seed_reraises_non_conditional_errors(aws, monkeypatch):
    """seed 的 except 只放过 ConditionalCheckFailed；其余错误必须如实上抛。

    把这个分支放宽成裸 pass 的后果：seed 静默失败 → site 行没有权限字段 →
    _route_item 回落 allowed_users="org"——指定名单被放大成全体可信 IdP 用户
    （fail-open）。本测试锁死"其他 ClientError 不被吞"。
    """
    import botocore.exceptions
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com")
    job_id = common.create_job("o@x.com", "s-1")

    class _BoomTable:
        def update_item(self, **kw):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException",
                           "Message": "throttled"}}, "UpdateItem")

    class _BoomResource:
        def Table(self, name):
            return _BoomTable()

    monkeypatch.setattr(register_route.boto3, "resource",
                        lambda *a, **kw: _BoomResource())
    with pytest.raises(botocore.exceptions.ClientError):
        register_route.handler(
            {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True,
                                   "allowed_users": ["a@x.com"]}}}, None)


def test_missing_require_login_defaults_closed(aws, monkeypatch):
    """sites 快照意外缺 require_login 时按"需要登录"投影（fail-closed）。

    这一行默认值是数据异常与"站点全公开"之间唯一的闸门——把
    site.get("require_login", True) 的默认改成 False，本测试必须失败。
    正常路径下 seed 会补齐该字段、moto 强一致读立即可见，默认分支跑不到，
    所以直接注入"缺字段的快照"（模拟真实 DynamoDB 的异常数据/延迟形态）。
    **快照必须带 permissions_rev=1**：seed 在真实行上执行并把 rev 推到 1，
    快照 rev 与之不符会让 ConditionCheck 三连败抛 RuntimeError，测试测不到
    目标（moto 实测：rev 缺失/0 都 RuntimeError，rev=1 才走到投影）。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com")
    job_id = common.create_job("o@x.com", "s-1")
    anomalous = {"site_id": "s-1", "owner": "o@x.com", "permissions_rev": 1,
                 "allowed_users": ["a@x.com"], "collaborators": []}
    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        lambda sid: dict(anomalous))
    out = register_route.handler(
        {"job_id": job_id, "site_id": "s-1", "api_target": "",
         "manifest": {"auth": {"require_login": False,   # 故意给 False：
                               "allowed_users": ["a@x.com"]}}}, None)
    # manifest 是 False 而快照缺字段——默认必须压过 manifest 的诱导，投影 True
    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is True
    assert out["effective_auth"]["require_login"] is True


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


def test_mark_success_does_not_change_site_owner(aws):
    """collaborator 发起的部署成功后，站点 owner 必须不变（spec §3.3.1）。"""
    import common
    import mark_job
    common.upsert_site("s-1", owner="alice@x.com", collaborators=["bob@x.com"],
                       require_login=True, allowed_users="org")
    job_id = common.create_job("bob@x.com", "s-1")      # 发起者是协作者
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "url": "https://app-s-1.example.com",
                      "manifest": {"tier": "static", "name": "one"}}, None)

    site = common.get_site("s-1")
    assert site["owner"] == "alice@x.com"               # 不是 bob
    assert site["status"] == "ACTIVE"                   # 其余收尾照常
    assert site["last_job_id"] == job_id
    assert site["tier"] == "static"


def test_mark_success_still_sets_owner_absent_field(aws):
    """sites 表缺 owner（异常数据）时不因为不写 owner 而永久缺字段——
    首次部署路径由 do_deploy_site 写入 owner，这里只断言不会崩。"""
    import common
    import mark_job
    common.upsert_site("s-2", name="two")               # 无 owner
    job_id = common.create_job("carol@x.com", "s-2")
    mark_job.handler({"job_id": job_id, "site_id": "s-2",
                      "url": "https://app-s-2.example.com",
                      "manifest": {"tier": "static", "name": "two"}}, None)
    assert common.get_site("s-2")["status"] == "ACTIVE"


def test_smoke_test_uses_effective_auth_not_manifest(aws, monkeypatch):
    """线上已改成公开、manifest 仍是 true：smoke 必须按公开断言（期待 200）。"""
    import common
    import smoke_test
    job_id = common.create_job("o@x.com", "s-1")
    calls = []

    def _fake_check(url, require_auth, login_prefix, what):
        calls.append((url, require_auth))

    monkeypatch.setattr(smoke_test, "_check", _fake_check)
    smoke_test.handler({"job_id": job_id, "site_id": "s-1",
                        "url": "https://app-s-1.example.com",
                        "manifest": {"auth": {"require_login": True}},
                        "effective_auth": {"require_login": False,
                                           "allowed_users": "org"}}, None)
    assert calls and all(require_auth is False for _, require_auth in calls)


def test_smoke_test_falls_back_to_manifest_when_effective_absent(aws, monkeypatch):
    """兼容：老 execution 的 event 里没有 effective_auth（部署过程中升级）。"""
    import common
    import smoke_test
    job_id = common.create_job("o@x.com", "s-1")
    calls = []
    monkeypatch.setattr(smoke_test, "_check",
                        lambda url, ra, lp, what: calls.append(ra))
    smoke_test.handler({"job_id": job_id, "site_id": "s-1",
                        "url": "https://app-s-1.example.com",
                        "manifest": {"auth": {"require_login": True}}}, None)
    assert calls == [True]


def test_register_route_refuses_when_site_row_absent(aws):
    """sites 行不存在时必须拒绝写路由，且**不得凭空创建 sites 行**。

    这是快照守卫的后门（独立审查 2026-08-08 P1，已实测）：DynamoDB 的
    update_item 在 item 不存在时会创建它，所以没有 attribute_exists(site_id) 时
    一个陈旧/恶意 job 能用自己的 manifest 建出 sites 行、写 permissions_rev=1 与
    require_login=false，随后守卫读到 had_rev=True 且 rev 相符——守卫校验的是这个
    job 刚刚自己伪造的快照，结果是站点公开且托管旧 owner 的产物。
    """
    import boto3
    import common
    import register_route
    job_id = common.create_job("attacker@x.com", "gone-abc123")
    with pytest.raises(RuntimeError, match="不存在"):
        register_route.handler(
            {"job_id": job_id, "site_id": "gone-abc123", "api_target": "",
             "manifest": {"auth": {"require_login": False,
                                   "allowed_users": "org"}}}, None)
    assert common.get_site("gone-abc123") is None, "sites 行被凭空创建了"
    assert "Item" not in boto3.client("dynamodb").get_item(
        TableName="routing",
        Key={"subdomain": {"S": "app-gone-abc123"}}), "路由被写入了"


def test_register_route_seed_fills_rev_and_collaborators(aws):
    """seed 的条件必须覆盖它要写的每个字段。

    rev 缺失会让守卫（要求 rev 存在，fail-closed）把合法部署卡死；
    collaborators 缺失是潜在的同类洞（将来给它加守卫子句就会继承）。
    """
    import common
    import register_route
    # ① 缺 rev（守卫会因此卡死合法部署）
    common.upsert_site("sparse-abc123", owner="o@x.com", require_login=True,
                       allowed_users="org")
    job_id = common.create_job("o@x.com", "sparse-abc123")
    register_route.handler(
        {"job_id": job_id, "site_id": "sparse-abc123", "api_target": "",
         "manifest": {"auth": {"require_login": True,
                               "allowed_users": "org"}}}, None)
    assert int(common.get_site("sparse-abc123")["permissions_rev"]) >= 1, \
        "seed 没补上 rev → 守卫（要求 rev 存在）会把合法部署卡死"

    # ② 只缺 collaborators：其余三个条件字段都在，条件若不覆盖它就会整体跳过。
    #    目前是潜在洞（rev 在，守卫仍工作），但将来给 collaborators 加守卫子句
    #    就会继承——所以这里单独钉一遍。
    common.upsert_site("nocollab-abc123", owner="o@x.com", require_login=True,
                       allowed_users="org", permissions_rev=3)
    job2 = common.create_job("o@x.com", "nocollab-abc123")
    register_route.handler(
        {"job_id": job2, "site_id": "nocollab-abc123", "api_target": "",
         "manifest": {"auth": {"require_login": True,
                               "allowed_users": "org"}}}, None)
    assert common.get_site("nocollab-abc123").get("collaborators") == [], \
        "seed 的条件没覆盖 collaborators —— 它在 SET 子句里，条件必须覆盖所写的每个字段"


# ---------------------------------------------------------------------------
# M7 B3：register_route 是**唯一提交点** + 切换前的整值路由快照
#
# 提交点之后只剩 smoke_test（它必须打公网 URL，只能排在切路由之后——这是不可
# 消除的顺序）。所以补偿机制是"切换前的整值快照 + 失败时原样写回"，快照由本
# 步骤留在 event["previous_route"] 里，mark_job 的失败分支消费它。
# ---------------------------------------------------------------------------

# 只读操作白名单。判"写"用的是它的**补集**：将来出现任何没见过的操作名都会被
# 算成写，于是"提交点只有一个"这条断言宁可弄红也不会放过第二次写（fail-closed
# 方向）。反之若用写操作白名单，漏列一个新操作就是静默放行。
_DDB_READ_OPS = {"GetItem", "BatchGetItem", "Query", "Scan", "DescribeTable",
                 "DescribeTimeToLive", "ListTables", "DescribeEndpoints"}


def _spy_dynamodb(monkeypatch, on_call=None):
    """在 botocore 的**唯一出口**上录下所有 DynamoDB 调用。

    不逐个包装 client 上的方法名（`put_item` / `transact_write_items` …）：
    那样只能看住我列举的那几个，将来改用 `batch_write_item` /
    `execute_statement` 写路由就悄悄漏掉——而"提交点只有一个"这条断言的全部
    价值就在于挡住多出来的那次写。`_make_api_call` 是所有 API 调用必经的
    单一出口，从这里录不可能被绕过。

    on_call: 可选钩子 `(operation_name, api_params) -> None`，抛异常即注入故障。
    """
    import botocore.client
    real = botocore.client.BaseClient._make_api_call
    calls = []

    def _spy(self, operation_name, api_params):
        if self.meta.service_model.service_name == "dynamodb":
            calls.append((operation_name, api_params))
            if on_call is not None:
                on_call(operation_name, api_params)
        return real(self, operation_name, api_params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _spy)
    return calls


def _routing_writes(calls, table="routing"):
    """`calls` 里所有可能改动路由表的调用。

    表名按 `"TableName": "<table>"` 的序列化形态匹配，所以顶层参数
    （put_item / update_item）与嵌在 TransactItems 里的都能命中，且不会被
    某个恰好等于表名的属性值误伤。事务里对路由表只做 ConditionCheck 也会被
    算成写——同样是 fail-closed 方向的过计数。
    """
    needle = json.dumps({"TableName": table})[1:-1]
    return [(op, p) for op, p in calls
            if op not in _DDB_READ_OPS
            and needle in json.dumps(p, default=str)]


def _b3_event(job_id, site_id, api_target="https://g.lambda-url.us-east-1.on.aws"):
    return {"job_id": job_id, "site_id": site_id, "owner": "a@x.com",
            "api_target": api_target, "deploy_color": "green",
            "manifest": {"name": "n", "tier": "fullstack-nosql",
                         "auth": {"require_login": True, "allowed_users": "org"}}}


def _old_route(site_id, *, api_target="https://b.lambda-url.us-east-1.on.aws",
               static_prefix=None, require_auth=True, allowed_users=None, rev="4"):
    """上一版路由 item（DynamoDB 形态）。

    `legacy_marker` 是实现方**没有理由知道**的字段：逐字段挑选的"快照"会把它
    丢掉，整值快照不会。它是"整值"这条断言的着力点。
    """
    return {"subdomain": {"S": f"app-{site_id}"}, "site_id": {"S": site_id},
            "route_mode": {"S": "split"}, "api_target": {"S": api_target},
            "static_prefix": {"S": static_prefix or f"sites/{site_id}/job-old"},
            "require_auth": {"BOOL": require_auth},
            "allowed_users": {"L": allowed_users or [{"S": "v@x.com"}]},
            "collaborators": {"L": []}, "owner": {"S": "a@x.com"},
            "permissions_rev": {"N": rev}, "legacy_marker": {"S": "keep-me"}}


def test_register_route_snapshots_previous_item_for_compensation(aws):
    """切换前的整个 route item 必须原样留在 event 里，不是挑几个字段。

    mark_job 的失败分支要把路由**原样写回**。挑字段的快照写回后会静默丢掉
    没挑的那些（route_mode / require_auth / allowed_users / collaborators /
    permissions_rev …）——恢复出来的是一条残缺的路由，Edge 按缺失字段回落
    默认值，等于一次静默的策略变更。所以断言是整值相等，不是逐字段。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="a@x.com", require_login=True,
                       allowed_users="org", collaborators=[], permissions_rev=4)
    job_id = common.create_job("a@x.com", "s-1")
    ddb = boto3.client("dynamodb")
    old = _old_route("s-1")
    ddb.put_item(TableName="routing", Item=old)

    out = register_route.handler(_b3_event(job_id, "s-1"), None)

    assert out["previous_route"] == old, "快照必须是切换前的整个 item"
    # 快照是"切换前"的：新路由确实已经切过去了（否则快照相等只是因为没切）
    now = ddb.get_item(TableName="routing",
                       Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert now["api_target"]["S"] == "https://g.lambda-url.us-east-1.on.aws"
    assert now["static_prefix"]["S"] == f"sites/s-1/{job_id}"


def test_register_route_switches_backend_and_frontend_in_one_write(aws, monkeypatch):
    """一次写同时切 api_target 与 static_prefix——那一次写就是提交点。

    分成两次写（先切后端再切前端）会在两次之间留出一个"新后端 + 旧前端"的
    窗口：旧前端的 JS 打新后端的接口。而且那个窗口里失败，补偿要还原**两条**
    半提交状态。所以路由表在本步骤里**只能被写一次**。
    """
    import common
    import register_route
    common.upsert_site("s-2", owner="a@x.com")
    job_id = common.create_job("a@x.com", "s-2")

    calls = _spy_dynamodb(monkeypatch)
    register_route.handler(_b3_event(job_id, "s-2"), None)

    writes = _routing_writes(calls)
    assert len(writes) == 1, \
        f"路由表被写了 {len(writes)} 次：{[op for op, _ in writes]}"
    blob = json.dumps(writes[0][1], default=str)
    assert "https://g.lambda-url.us-east-1.on.aws" in blob, "后端没在这次写里切"
    assert f"sites/s-2/{job_id}" in blob, "前端不在同一次写里 → 提交点不止一个"


def test_register_route_marks_first_deploy_with_explicit_none(aws):
    """首次部署没有上一版路由：键必须**在**、值为 None。

    写成 `if prev: event["previous_route"] = prev` 会让键整个缺席，于是
    mark_job 的失败分支分不清两件事：① register_route 还没提交（路由不该动）；
    ② 提交过、但这是首次部署（该把刚写的路由删掉，别让一个冒烟失败的新站点
    留在线上）。两者都表现为"键不存在"，键缺席就把这个区分永久丢掉了。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-3", owner="a@x.com")
    job_id = common.create_job("a@x.com", "s-3")
    assert "Item" not in boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-3"}})

    out = register_route.handler(_b3_event(job_id, "s-3"), None)

    assert "previous_route" in out, "首次部署也必须留下快照位（None = 之前没有路由）"
    assert out["previous_route"] is None


def test_register_route_resnapshots_route_before_each_commit_attempt(aws, monkeypatch):
    """快照必须在**每次提交尝试之前**重读，不能在重试循环外读一次。

    交错（与 test_register_route_refuses_stale_snapshot 同一条，但看的是快照）：
    我们读完 sites（公开）→ 别人在线把权限收紧（sites 与路由同一事务，rev 推进）
    → 我们的事务被 rev 条件取消 → 重读重试。若快照是循环外读的那一份，它记的是
    **收紧之前**的公开路由；mark_job 的失败分支照它写回，就把刚被收紧的站点还原
    成公开（fail-open 扩权）。循环内重读拿到的才是收紧后的那一版。
    """
    import boto3
    import common
    import register_route
    ddb = boto3.client("dynamodb")
    common.upsert_site("s-1", owner="a@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    job_id = common.create_job("a@x.com", "s-1")
    public = _old_route("s-1", require_auth=False,
                        allowed_users=[{"S": "org"}], rev="0")
    ddb.put_item(TableName="routing", Item=public)
    tightened = _old_route("s-1", require_auth=True,
                           allowed_users=[{"S": "vip@x.com"}], rev="1")

    real_get_site = common.get_site_consistent
    reads = {"n": 0}

    def _racing_get_site(site_id):
        site = real_get_site(site_id)
        reads["n"] += 1
        if reads["n"] == 2:
            # 必须在**循环内**那次读之后注入（第 1 次读是 seed 前的预读）：在
            # 预读后注入的话循环第一笔事务就成功，重试路径从未执行。
            # 在线改权限是"sites + 路由"同一事务，所以两张表一起改。
            common.upsert_site(site_id, require_login=True,
                               allowed_users=["vip@x.com"], permissions_rev=1)
            ddb.put_item(TableName="routing", Item=tightened)
        return site

    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        _racing_get_site)
    calls = _spy_dynamodb(monkeypatch)
    out = register_route.handler(_b3_event(job_id, "s-1"), None)

    # 独立于快照断言的旁证：第一笔事务真的被 rev 条件取消、真的重试过。
    # 没有它，下面那条断言可能只是"从没进过重试路径"的假绿。
    assert len([op for op, _ in calls if op == "TransactWriteItems"]) >= 2
    assert out["previous_route"] == tightened, \
        "快照是循环外读的那一份（收紧之前的公开路由）→ 失败恢复会把站点还原成公开"


def test_register_route_does_not_commit_when_snapshot_read_fails(aws, monkeypatch):
    """快照读失败必须让本步骤失败在**提交之前**——不许"读不到就算了"。

    把这次 get_item 包进 `try/except: pass` 的后果：路由照切，但
    previous_route 缺席 → 冒烟失败时 mark_job 无从还原 → 线上停在新版本上。
    提交点之前失败对线上零影响，所以"抛出去"就是正确行为。

    注入的错误码用 AccessDenied 不是随便挑的：exec_role 若少了路由表的
    GetItem，真机就是这个形态，而 moto 不校验 IAM（单测永远绿）。
    """
    import boto3
    import botocore.exceptions
    import common
    import register_route
    common.upsert_site("s-1", owner="a@x.com", require_login=True,
                       allowed_users="org", collaborators=[], permissions_rev=4)
    job_id = common.create_job("a@x.com", "s-1")
    ddb = boto3.client("dynamodb")
    old = _old_route("s-1")
    ddb.put_item(TableName="routing", Item=old)

    fired = {"n": 0}

    def _fail_first_routing_get(op, params):
        # 只炸第一次（handler 那次）：否则本用例末尾自己的核对读也会被炸掉。
        # 「只响一次」同时是旁证——它证明注入确实作用在 handler 的那次读上。
        if op == "GetItem" and params.get("TableName") == "routing":
            fired["n"] += 1
            if fired["n"] == 1:
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDeniedException",
                               "Message": "snapshot-read-boom"}}, "GetItem")

    _spy_dynamodb(monkeypatch, on_call=_fail_first_routing_get)
    # match= 钉住是**哪一条**失败：只断言 ClientError 的话，任何一次 DynamoDB
    # 报错都能让用例过绿，而快照这根轴其实没人看着（Ruling 54）。
    with pytest.raises(botocore.exceptions.ClientError, match="snapshot-read-boom"):
        register_route.handler(_b3_event(job_id, "s-1"), None)

    assert fired["n"] == 1, "handler 根本没读路由表 → 这次注入什么都没测到"
    # 独立于异常的旁证：路由**没被切**（提交点之前失败 = 线上零影响）。
    # 快照读挪到事务之后也会抛同样的异常，只有这条断言能抓住它。
    assert ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"] == old, \
        "快照读失败了，但路由已经被切走了"


# ── B4: 失败恢复路由（三态）+ 版本清理 ───────────────────────────────────
#
# **`previous_route` 是三态契约，不是"有/没有"**（register_route 那段注释写了，
# 这里按它测）：
#   · 键**不在**      = register_route 还没提交 ⇒ 线上从未变过，动它才是制造故障；
#   · 键在、值 None   = 提交过，但切换前没有路由（首次部署）⇒ 该把刚写的那条删掉；
#   · 键在、值是 item = 提交过且有上一版 ⇒ 整值写回。
# 写成 `if not prev: return` 会把前两态合并 —— 首次部署失败时那条指向失败站点的
# 路由会**留在线上**，子域名被一个 FAILED 的部署占住。

def _routing_item(site_id="s-1"):
    import os

    import boto3
    return boto3.client("dynamodb").get_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": f"app-{site_id}"}}).get("Item")


def _put_routing(item):
    import os

    import boto3
    boto3.client("dynamodb").put_item(
        TableName=os.environ["ROUTING_TABLE"], Item=item)


def _lam_versions_mock(versions, aliases, *, alias_error=None):
    """lambda 替身：`list_versions_by_function` 返回 `versions`，两个颜色的
    alias 指向 `aliases`（缺的颜色抛 ResourceNotFoundException）。

    `alias_error`: 给 get_alias 注入一个**别的**异常类型，用来验"查不到 alias
    的原因不是'该色不存在'时，清理必须整体放弃"——不放弃就可能删掉线上正在用的
    那个版本。
    """
    lam = MagicMock()
    lam.exceptions.ResourceNotFoundException = type(
        "ResourceNotFoundException", (Exception,), {})
    lam.get_paginator.return_value.paginate.return_value = [
        {"Versions": [{"Version": v} for v in versions]}]

    def _get_alias(FunctionName, Name):
        if alias_error is not None:
            raise alias_error
        if Name in aliases:
            return {"FunctionVersion": aliases[Name]}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_alias.side_effect = _get_alias
    return lam


def _deleted_qualifiers(lam):
    return [c.kwargs.get("Qualifier") for c in lam.delete_function.call_args_list]


def test_failed_job_restores_the_previous_route_item(aws):
    """提交点之后失败（如 smoke 红）⇒ 路由**整值**写回切换前。

    断言整值相等而不是逐字段：`_old_route` 里的 `legacy_marker` 是恢复方没有理由
    知道的字段，逐字段写回会把它丢掉，而 Edge 对缺失字段是按默认值回落 = 一次
    静默的策略变更。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1")
    # 线上当前是这次部署刚切过去的那条（green + 新前缀）
    _put_routing({"subdomain": {"S": "app-s-1"},
                  "api_target": {"S": "https://g.lambda-url.us-east-1.on.aws"},
                  "static_prefix": {"S": f"sites/s-1/{job_id}"}})
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "previous_route": prev,
                      "error_info": {"Cause": "smoke failed"}}, None)
    assert _routing_item("s-1") == prev


def test_failed_job_without_snapshot_does_not_touch_route(aws, monkeypatch):
    """健康门在切路由之前失败 ⇒ 快照那个**键根本不在** ⇒ 一次路由写都不许有。

    断言"没有写"而不是"值没变"：值没变也可能是写了一条一模一样的回去，而那在真机
    上会推进 Edge 的缓存与 DynamoDB 的写指标，也会让"提交点只有一次写"不再成立。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    live = {"subdomain": {"S": "app-s-1"},
            "api_target": {"S": "https://b.lambda-url.us-east-1.on.aws"}}
    _put_routing(live)
    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "error_info": {"Cause": "BackendUnhealthy"}}, None)
    assert _routing_writes(calls) == []
    assert _routing_item("s-1") == live


def test_failed_first_deploy_removes_the_route_it_just_created(aws):
    """键在、值是 None = 提交过但切换前没有路由（首次部署）⇒ 删掉刚写的那条。

    这一态 brief 漏了，而它正是 `if not prev: return` 会吃掉的那个：合并成"没快照
    就什么都不做"的话，一个 FAILED 的首次部署会把子域名留在线上指向自己——用户拿到
    的 URL 打开是一个部署失败的站点，而不是 404。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    _put_routing({"subdomain": {"S": "app-s-1"},
                  "api_target": {"S": "https://b.lambda-url.us-east-1.on.aws"},
                  "static_prefix": {"S": f"sites/s-1/{job_id}"}})
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "previous_route": None,
                      "error_info": {"Cause": "smoke failed"}}, None)
    assert _routing_item("s-1") is None, \
        "首次部署失败后那条路由还在——子域名被一个 FAILED 的部署占着"


def test_cleanup_keeps_alias_referenced_and_recent_versions(aws):
    """健康门失败留下的版本不许永久堆积；两个 alias 引用的版本必须留。"""
    import mark_job
    lam = _lam_versions_mock(["$LATEST", "1", "2", "3", "4", "5"],
                             {"blue": "5", "green": "2"})
    with patch.object(mark_job, "_lambda", return_value=lam):
        mark_job._cleanup_versions("s-1")
    deleted = set(_deleted_qualifiers(lam))
    assert "5" not in deleted and "2" not in deleted and "$LATEST" not in deleted
    assert "1" in deleted
    # 最近 N 个也要留：3/4 虽然没人引用，但它们是回滚的落点
    assert {"3", "4"} & deleted == set()


def test_cleanup_treats_a_missing_color_as_nothing_to_keep(aws):
    """只建了一个颜色的站点（迁移中）：另一色的 get_alias 抛
    ResourceNotFoundException，那条 except **必须真的被执行到**（Ruling 58），
    且清理照常进行。"""
    import mark_job
    lam = _lam_versions_mock(["$LATEST", "1", "2", "3", "4", "5"],
                             {"blue": "5"})            # green 不存在
    with patch.object(mark_job, "_lambda", return_value=lam):
        mark_job._cleanup_versions("s-1")
    assert lam.get_alias.call_count == 2, "两个颜色都要查——少查一个就等于少留一个"
    deleted = set(_deleted_qualifiers(lam))
    assert "5" not in deleted                       # blue 引用
    assert {"1", "2"} <= deleted                    # green 不存在 ⇒ 2 不再被引用
    assert {"3", "4"} & deleted == set()


def test_cleanup_aborts_when_an_alias_lookup_fails_for_any_other_reason(aws):
    """**查不到 alias 的原因不是"该色不存在"时，整体放弃清理。**

    这是删除类操作唯一安全的方向：一次限流/超时会让 keep 集合少一个版本，而那个
    版本可能正是**线上 alias 指着的**那个——删掉它，正在服务的站点立刻 500。
    宽 `except Exception: pass` 恰好把这两种原因混成一种（brief 里就是这么写的）。
    """
    import mark_job
    lam = _lam_versions_mock(["$LATEST", "1", "2", "3", "4", "5"],
                             {"blue": "5", "green": "2"},
                             alias_error=RuntimeError("Throttling"))
    with patch.object(mark_job, "_lambda", return_value=lam):
        mark_job._cleanup_versions("s-1")           # 只告警，不抛
    lam.delete_function.assert_not_called()


def test_cleanup_never_deletes_the_function_itself(aws):
    """`delete_function` **不带 Qualifier 就是删整个函数**——站点当场消失。

    所以每一次调用都必须带一个纯数字的 Qualifier。版本号来自 API，理论上就是数字，
    但这条断言的代价接近零，而它挡住的是本仓库里破坏性最强的一次误操作。
    """
    import mark_job
    lam = _lam_versions_mock(["$LATEST", "1", "2", "3", "4", "5", "bogus"],
                             {"blue": "5", "green": "2"})
    with patch.object(mark_job, "_lambda", return_value=lam):
        mark_job._cleanup_versions("s-1")
    quals = _deleted_qualifiers(lam)
    assert quals, "一个版本都没删——本条已空转"
    for q in quals:
        assert q is not None and str(q).isdigit(), \
            f"delete_function 的 Qualifier 是 {q!r}——不带/非版本号会删掉整个函数"


def test_cleanup_keeps_the_version_this_job_just_deployed(aws):
    """B2 产出的 `deploy_version` 在这里被消费：**无论 alias 怎么读，刚部署的那个
    版本都不删**。

    为什么需要它：alias 的读与"刚把 alias 指过去"之间有一个瞬间，读到旧值时 keep
    里就没有本次的版本号，而它恰好可能落在"没人引用且不在最近 N 个"里 ⇒ 被删。
    传进来的这一个是不依赖读一致性的兜底。
    """
    import mark_job
    lam = _lam_versions_mock(["$LATEST", "1", "2", "3", "4", "5", "6"],
                             {"blue": "6", "green": "2"})
    with patch.object(mark_job, "_lambda", return_value=lam):
        mark_job._cleanup_versions("s-1", keep_extra=("3",))
    deleted = set(_deleted_qualifiers(lam))
    assert "3" not in deleted, "刚部署的版本被删了"
    assert "1" in deleted, "本条已空转——没有任何版本被删，说明 keep 把全部吃掉了"


def test_success_path_cleans_versions_with_the_deployed_version_kept(aws):
    """handler 成功分支真的会调清理，且把 deploy_version 传下去——否则上一条
    只测了一个没人调用的函数。"""
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    ev = {"job_id": job_id, "site_id": "s-1", "url": "https://app-s-1.example.com",
          "deploy_color": "green", "deploy_version": "7",
          "manifest": {"name": "n", "tier": "static"}}
    with patch.object(mark_job, "_cleanup_versions") as cv:
        mark_job.handler(ev, None)
    cv.assert_called_once()
    assert cv.call_args.args[0] == "s-1"
    assert "7" in tuple(cv.call_args.kwargs.get("keep_extra", ()))


def test_route_snapshot_read_is_strongly_consistent(aws, monkeypatch):
    """快照那次 GetItem 必须**真的把 `ConsistentRead=True` 传给 API**。

    为什么要单独一条：这根轴在 moto 下**行为上造不出差异**（moto 的读本来就是
    强一致），所以任何"跑一遍看结果"的用例都抓不到它——把 `ConsistentRead=True`
    删掉，本文件照样全绿（实测）。它只能在**真实 API 边界上按参数**断言：
    "源码里写着" ≠ "真的传给了 API"。

    为什么这根轴值钱：最终一致读可能拿不到"刚刚在线收紧权限"那次写（在线改权限
    是"sites 推 rev + 改路由"同一事务），快照就记成收紧**之前**的公开路由；
    mark_job 的失败分支照它整值写回，等于把刚被收紧的站点还原成公开——
    fail-open 扩权，而且是静默的。

    断言写成 `is True` 而不是"有没有 ConsistentRead 这个键"：`ConsistentRead=False`
    同样有键，而它恰好就是要防的那个值。

    **别和 test_register_route_uses_consistent_read_after_seed 搞混**：那条管的是
    **sites 表**的权限读（`get_site` vs `get_site_consistent`），与这里的**路由表
    快照读**是两个不同的对象。两条名字几乎一样，曾因此造成"已被覆盖"的假象。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-4", owner="a@x.com", require_login=True,
                       allowed_users="org", collaborators=[], permissions_rev=4)
    job_id = common.create_job("a@x.com", "s-4")
    boto3.client("dynamodb").put_item(TableName="routing", Item=_old_route("s-4"))

    calls = _spy_dynamodb(monkeypatch)
    register_route.handler(_b3_event(job_id, "s-4"), None)

    reads = [p for op, p in calls
             if op == "GetItem" and p.get("TableName") == "routing"]
    # 先证明守卫不是空转：真的有那么一次读，而且只有一次（提交点前每次尝试重读，
    # 本用例不制造冲突 ⇒ 恰好一次）。没有这条的话，快照读被整个删掉时下面那句
    # 会 IndexError——红是红，但读起来像守卫自己坏了。
    assert len(reads) == 1, \
        f"路由表的快照读发生了 {len(reads)} 次，期望恰好 1 次"
    assert reads[0].get("ConsistentRead") is True, \
        "快照读不是强一致 ⇒ 可能读到「在线收紧权限」之前的公开路由，失败恢复会扩权"
