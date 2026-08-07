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
