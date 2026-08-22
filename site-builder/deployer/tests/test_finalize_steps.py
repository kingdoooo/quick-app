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


def test_missing_require_login_is_refused_not_defaulted(aws, monkeypatch):
    """sites 快照缺 require_login 时**拒绝部署**，不再按 True 兜底（M02）。

    **这条用例是反过来的**：旧版本断言"缺字段 ⇒ 投影 True"，理由是那行默认值
    是数据异常与"站点全公开"之间唯一的闸门。M02 换掉了那道闸门——按 True 兜底
    仍然是在猜（缺失读不出 True 还是 False），现在由 `effective_policy` 直接拒绝，
    比猜一个方向更强。所以断言从"投影了什么"变成"拒绝且**一个字都没写进路由**"
    （spec §6.1 第 2 条：断言拒绝且路由未被写）。

    正常路径下 seed 会补齐该字段、moto 强一致读立即可见，所以这个形态只能靠
    注入"缺字段的快照"来造（模拟真实 DynamoDB 的异常数据/延迟形态）。
    **快照仍要带 permissions_rev=1**：与旧版同理，rev 不符会让 ConditionCheck
    三连败抛 RuntimeError，测不到目标。这里它还保证拒绝**不是**被 rev 挡下的。
    """
    import boto3
    import permissions
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com")
    job_id = common.create_job("o@x.com", "s-1")
    anomalous = {"site_id": "s-1", "owner": "o@x.com", "permissions_rev": 1,
                 "allowed_users": ["a@x.com"], "collaborators": []}
    monkeypatch.setattr(register_route.common, "get_site_consistent",
                        lambda sid: dict(anomalous))
    with pytest.raises(permissions.PolicyDataInvalid, match="require_login"):
        register_route.handler(
            {"job_id": job_id, "site_id": "s-1", "api_target": "",
             # manifest 给 False：拒绝必须压过 manifest 的诱导，而不是投影它
             "manifest": {"auth": {"require_login": False,
                                   "allowed_users": ["a@x.com"]}}}, None)
    # 拒绝发生在提交点之前 ⇒ 路由表里根本不该出现这条 item（线上零影响）
    assert "Item" not in boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})


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
    # 线上当前是这次部署刚切过去的那条（green + 新前缀）。
    # **必须带上 `register_route._route_item` 必写的那些字段**（这里是 `site_id`
    # 与 `permissions_rev`）：本用例的前提是"register_route 已经提交过"，而它写出来的
    # item 一定有这两个（`permissions.py` 的在线改权限与自愈投影是 update，不会去掉
    # 它们；undeploy 是整行删除）。所以"提交过、但线上这条缺这些字段"是**不可达**状态。
    # 留着一条不可达的 fixture 的代价不是测试红，而是**逼恢复的条件守卫放宽**才能过
    # ——而放宽的那两种形态各自都有真洞：`attribute_not_exists(permissions_rev)` 的
    # 析取会在 item 被 undeploy 删掉时成立（把已下线站点复活，见
    # test_restore_does_not_resurrect_a_route_deleted_during_smoke），去掉
    # `attribute_exists(site_id)` 则丢掉同一层保护。
    # rev 取 4 = register_route 写进去的那个（`committed_permissions_rev`），
    # static_prefix 取本次 job 的：这两项就是补偿的条件锚点，"世界没变过"即两者
    # 都还在线上。
    _put_routing({"subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
                  "api_target": {"S": "https://g.lambda-url.us-east-1.on.aws"},
                  "static_prefix": {"S": common.static_prefix_for("s-1", job_id)},
                  "permissions_rev": {"N": "4"}})
    mark_job.handler(_fail_event(job_id, prev), None)
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
    # 线上 = 这次首次部署刚写进去的那条。**必须带 permissions_rev**：
    # register_route 必写它，而删除现在也按提交端锚点（static_prefix + rev）
    # 设条件——留一条缺 rev 的 fixture 只会逼那道条件放宽。
    _put_routing(_committed_route("s-1", job_id, rev="1",
                                  api_target="https://b.lambda-url.us-east-1.on.aws"))
    mark_job.handler(_fail_event(job_id, None, committed_rev=1), None)
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


# ---------------------------------------------------------------------------
# B4 fix：恢复路由必须带条件——补偿只在"世界还是我离开时的样子"才允许落地
# ---------------------------------------------------------------------------

def _fail_event(job_id, prev, site_id="s-1", committed_rev=4):
    """提交点之后失败的 event。

    `committed_permissions_rev` 是 register_route 提交成功后写进 event 的**提交端
    锚点**（= 它写进路由 item 的那个 rev）。补偿的条件锚在这一端而不是快照端，
    理由见 `permissions.committed_route_condition`。默认 4 = `_old_route` 的默认
    rev，即"期间没人改过权限"。传 None 模拟升级窗口里老代码起的 execution。
    """
    ev = {"job_id": job_id, "site_id": site_id, "previous_route": prev,
          "error_info": {"Cause": "smoke failed"}}
    if committed_rev is not None:
        ev["committed_permissions_rev"] = committed_rev
    return ev


def _committed_route(site_id, job_id, *, rev="4", **kw):
    """register_route 提交之后线上那条路由（= 本次部署的新目标）。

    `static_prefix` 必须是 `common.static_prefix_for(site_id, job_id)`：补偿的
    条件就是按它比的，随手写个别的值会让"条件通过"的用例永远走不到。
    """
    import common
    kw.setdefault("api_target", "https://g.lambda-url.us-east-1.on.aws")
    return _old_route(site_id, rev=rev,
                      static_prefix=common.static_prefix_for(site_id, job_id),
                      **kw)


def test_abandons_restore_when_permissions_changed_during_smoke(aws, monkeypatch):
    """提交之后、smoke 期间有人在线收紧权限 ⇒ **放弃恢复**，不许把权限写回去。

    交错：register_route 提交（快照 rev=4）→ 有人在线改权限（"sites 推 rev +
    改路由"同一事务，路由 rev 变 5、名单收紧）→ smoke 失败 → 恢复。
    无条件整值写回会把 allowed_users 一起写回收紧**之前**的样子 = fail-open 扩权，
    而且是静默的（恢复本来就只 warning）。

    **Ruling 54：这条和"根本没提交所以没恢复"是两条不同的分支**，不能只断言
    "路由没变"——那两条分支的路由都没变。区分点是**有没有尝试过写**：
    没提交那条一次写都没有（B4 的
    test_failed_job_without_snapshot_does_not_touch_route 断言 == []），
    而这一条必须**尝试了一次并被条件拒掉**。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")                       # 快照：rev 4，公开名单
    # 线上 = 本次提交的那条（static_prefix 是本 job 的）**再被在线收紧过一次**：
    # `write_permissions` 只改权限字段并把 rev 推到 5，**不动 static_prefix**。
    # 所以这里唯一与提交端不同的就是 rev —— 本用例验的正是"只靠 static_prefix
    # 不够、rev 那一项必须在"。
    tightened = _committed_route("s-1", job_id, rev="5", require_auth=True,
                                 allowed_users=[{"S": "vip@x.com"}])
    _put_routing(tightened)                                 # 线上：已被收紧过

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(job_id, prev), None)

    # ① 分支身份：确实**尝试**了一次恢复（不是"没提交所以没动"那条分支）
    writes = _routing_writes(calls)
    assert len(writes) == 1 and writes[0][0] == "PutItem", \
        f"没有发生恢复尝试，落到了别的分支：{[op for op, _ in calls]}"
    # ② 结果：被条件拒掉，收紧后的权限原样留着
    assert _routing_item("s-1") == tightened, "恢复把收紧前的权限写回去了（扩权）"
    # ③ 如实告知：错误信息里要能看出"路由留在新目标上、需要人工介入"
    err = common.get_job(job_id)["error"]
    assert "smoke failed" in err, "原始错因被盖掉了"
    assert "人工" in err and "权限" in err, \
        f"补偿被放弃却没写进 job 错误信息，只有 CloudWatch 里有：{err!r}"


def test_restore_does_not_resurrect_a_route_deleted_during_smoke(aws, monkeypatch):
    """smoke 期间站点被下线（undeploy 删掉了路由）⇒ 恢复**不许把它复活**。

    这条是"条件写成 `attribute_not_exists(permissions_rev) OR rev = :snap` 那种
    宽松析取"会漏掉的那根轴：item 不存在时 `attribute_not_exists(...)` **成立**，
    于是一个已被下线的站点的子域名又变回可路由——比扩权更糟，它把"已删除"撤销了。
    现在的条件全是属性**相等**比较（`static_prefix` + `permissions_rev`），
    item 缺失时一律为假，恢复自动放弃，不需要另加 `attribute_exists`。

    `undeploy.py` 确实会删这一行，且 smoke 有几十秒窗口，所以这是可达的交错，
    不是纸面问题。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")
    assert _routing_item("s-1") is None                     # 线上已被 undeploy 删掉

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(job_id, prev), None)

    assert len(_routing_writes(calls)) == 1                 # 尝试过（分支身份）
    assert _routing_item("s-1") is None, \
        "把一个已被下线的站点的路由复活了——恢复必须精确匹配 rev，不能用宽松析取"
    assert "人工" in common.get_job(job_id)["error"]


def test_restores_a_legacy_snapshot_that_has_no_rev(aws, monkeypatch):
    """快照里没有 permissions_rev（M3 之前写入的存量路由）**照样能回滚**。

    这是 Codex 2026-08-17 P1-4：实测生产 6 条站点路由里有 5 条没有 rev
    （只有 app-notes-01d147 有）。旧实现把条件锚在**快照端**，于是"快照里没有 rev
    可比"只能放弃恢复——那 5 个站点第一次更新若 smoke 失败就回滚不了，路由留在
    失败的新目标上。

    锚**提交端**之后这一态不再特殊：`register_route` 总会写 rev，所以"我写出去的
    那份"永远有 rev 可比；条件成立即证明期间无人改动，rev-less 的快照可以原样
    整值写回（写回后这条路由仍然没有 rev —— 它就是切换前的样子，而 Edge 不读
    这个字段）。

    红的条件：恢复被放弃（回到 P1-4）、或写回的不是整值。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1")
    del prev["permissions_rev"]                             # 存量：快照没有 rev
    # 线上 = 本次提交的那条。**它有 rev**（register_route 必写），所以提交端锚点
    # 齐全 —— 这正是"快照缺 rev 不影响回滚"的机理。
    _put_routing(_committed_route("s-1", job_id, rev="4"))

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(job_id, prev), None)

    assert len(_routing_writes(calls)) == 1, "一次恢复写都没有发出去"
    assert _routing_item("s-1") == prev, (
        "存量（无 rev）路由没能整值回滚——生产上 5/6 条站点路由是这个形状")
    assert "人工" not in (common.get_job(job_id).get("error") or ""), \
        "恢复成功了却还在提示需要人工介入"


def test_gives_up_when_the_commit_anchor_is_absent(aws, monkeypatch):
    """event 里没有 `committed_permissions_rev`（升级窗口里老代码起的 execution）
    ⇒ 放弃恢复并如实告知，**不退回快照 rev 那套守卫**。

    退回去才是错的：快照端那套恰是被本次改动认定不可靠的一套（认不出并发部署、
    存量无 rev 时又必然放弃），在最不该的时候用一个已知有洞的守卫没有任何好处。

    **一次写请求都不该发**：没有可锚的提交端时任何条件都只能是猜。

    分支身份靠"有没有那条提示"区分，不靠写次数：本分支与"快照键根本不在"
    （test_failed_job_without_snapshot_does_not_touch_route）都是零次写，区别是
    那条**不该**有提示（线上从未变过），而这条**必须**有（路由停在新目标上了）。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")
    live = _committed_route("s-1", job_id, rev="4")
    _put_routing(live)

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(job_id, prev, committed_rev=None), None)

    assert _routing_writes(calls) == [], \
        "发了一次只能靠猜的恢复写——没有提交端锚点时应当直接放弃"
    assert _routing_item("s-1") == live
    assert "人工" in common.get_job(job_id)["error"]


def test_refuses_to_overwrite_a_newer_deploys_committed_route(aws, monkeypatch):
    """同一站点另一次**更晚**的部署已经提交 ⇒ 旧 job 的补偿必须放弃，不许覆盖。

    这是 Codex 2026-08-17 P1-2。可达性：`do_confirm_upload` 的条件只管它自己那条
    job 的 PENDING→RUNNING；部署租约（后补的）挡的是新执行的**创建**，
    存量在跑的执行仍可能交错，所以本守卫独立必要、不因租约而冗余。

    交错：旧 job 提交路由（rev=4）→ 新 job 提交路由（rev 仍是 4，因为期间没人改
    权限）→ 旧 job 的 smoke 失败 → 旧 job 补偿。

    锚快照 rev 时这里会**通过**：两个 job 看到的 rev 相同，"线上 rev 还等于我的
    快照 rev"对旧 job 同样成立 ⇒ 新 job 刚提交成功的路由被整条覆盖回更早的版本，
    而新 job 的成功分支已经在清理前缀了，覆盖出来的那条可能指向一个不存在的前缀。
    锚提交端时 `static_prefix` 带 job_id ⇒ 天然唯一 ⇒ 条件必然失败。

    红的条件：新 job 的路由被改动。
    """
    import common
    import mark_job
    old_job = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")                    # 旧 job 切换前的快照
    newer = _committed_route("s-1", "job-newer", rev="4")   # 线上：更晚那次的路由
    _put_routing(newer)

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(old_job, prev), None)

    assert len(_routing_writes(calls)) == 1, "没有发生恢复尝试，落到了别的分支"
    assert _routing_item("s-1") == newer, \
        "旧 job 的补偿覆盖了更晚那次成功部署的路由"
    assert "人工" in common.get_job(old_job)["error"]


def test_restore_api_failure_is_reported_in_the_job(aws, monkeypatch):
    """恢复的写请求本身失败（AWS 报错）⇒ job 错误信息里必须说出来。

    这是 Codex 2026-08-17 P2：宽 except 只 `logger.error` 然后返回 None，于是
    handler 拿不到 note，job 记录只写"smoke failed"。看到 job 的人会以为部署只是
    失败了，不知道那条失败的新路由还在线上服务。CloudWatch 里那行他们不看。

    文案必须与"条件判定为不该回滚"分开：那是一个正确的决定，这是一次故障。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    common.update_job(job_id, status="RUNNING")   # MarkFailed 被调时 job 必然 RUNNING
    prev = _old_route("s-1", rev="4")
    live = _committed_route("s-1", job_id, rev="4")
    _put_routing(live)

    armed = {"on": True}      # 第二次调用前解除注入 = 模拟 SFN 的下一次 attempt

    def _boom(op, params):
        # 只打路由表的 PutItem：update_job 也走 DynamoDB，一律炸掉的话连
        # "错因已落账"这个前提都没了，验的就不是本分支。
        if armed["on"] and op == "PutItem" and params.get("TableName") == "routing":
            raise RuntimeError("ddb unavailable")

    _spy_dynamodb(monkeypatch, on_call=_boom)
    # 恢复的 AWS 调用失败 ⇒ **抛出而不是写 FAILED**（Codex 2026-08-18 R4 P1-1
    # 的子项）：写 FAILED 就是放开租约让新部署在未回滚的路由上开跑。抛出让 SFN
    # 重试（补偿幂等）；job 保持 RUNNING，租约继续挡着。
    with pytest.raises(RuntimeError, match="回滚请求失败"):
        mark_job.handler(_fail_event(job_id, prev), None)

    job = common.get_job(job_id)
    assert job["status"] == "RUNNING", \
        f"恢复失败却写了终态 {job['status']}——租约被提前放开"
    assert "smoke failed" in job["error"], "原始错因没有先落账"
    # 重试成功那一侧：去掉注入后重跑 = SFN 的下一次 attempt
    armed["on"] = False
    mark_job.handler(_fail_event(job_id, prev), None)
    assert _routing_item("s-1") == prev
    assert common.get_job(job_id)["status"] == "FAILED"


def test_first_deploy_route_removal_failure_is_reported_in_the_job(aws, monkeypatch):
    """首次部署失败时"删掉刚写的那条路由"也可能失败 ⇒ 同样要写进 job。

    这一态的后果比一般恢复失败更直接：子域名被一个 FAILED 的首次部署占着，
    用户拿到的 URL 打开是一个坏站点。静默 = 没人会去处置它。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    common.update_job(job_id, status="RUNNING")   # MarkFailed 被调时 job 必然 RUNNING
    live = {"subdomain": {"S": "app-s-1"},
            "static_prefix": {"S": common.static_prefix_for("s-1", job_id)}}
    _put_routing(live)

    def _boom(op, params):
        if op == "DeleteItem" and params.get("TableName") == "routing":
            raise RuntimeError("ddb unavailable")

    _spy_dynamodb(monkeypatch, on_call=_boom)
    with pytest.raises(RuntimeError, match="回滚请求失败"):
        mark_job.handler(_fail_event(job_id, None), None)

    assert _routing_item("s-1") == live                  # 没删掉（注入的故障）
    assert common.get_job(job_id)["status"] == "RUNNING", \
        "删除失败却写了终态——租约被提前放开"


def test_long_error_cause_does_not_truncate_the_manual_intervention_note(aws):
    """原因很长时，截断要砍**原因**而不是砍那条提示。

    job 的 error 字段有 500 字上限，而"路由没回滚、需人工介入"是里面唯一**可操作**
    的部分。先拼后截会正好把它切掉——症状是"长错误的那些部署看不到提示"，短错误的
    却看得到，很难联想到截断。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")
    _put_routing(_old_route("s-1", rev="5"))        # rev 不匹配 ⇒ 放弃恢复
    ev = _fail_event(job_id, prev)
    ev["error_info"] = {"Cause": "X" * 5000}
    mark_job.handler(ev, None)

    err = common.get_job(job_id)["error"]
    assert mark_job.ROUTE_NOT_ROLLED_BACK in err, "提示被截断切掉了"
    assert len(err) <= 500, f"error 字段超了 500：{len(err)}"
    assert "X" in err, "原因被整段丢掉了——应该是截断，不是丢弃"


# ---------------------------------------------------------------------------
# 前端版本前缀的清理：删早了就是线上 403（Codex 2026-08-17 P1-1）
# ---------------------------------------------------------------------------

def _put_frontend(*prefixes):
    """在前端桶里给每个前缀放一个 index.html。返回 s3 client。"""
    import boto3
    s3 = boto3.client("s3")
    for p in prefixes:
        s3.put_object(Bucket="site-frontend-1", Key=f"{p.rstrip('/')}/index.html",
                      Body=b"<html>")
    return s3


def _frontend_prefixes():
    """桶里现存的版本前缀集合（不带尾斜杠，与路由表的 static_prefix 同形）。"""
    import boto3
    resp = boto3.client("s3").list_objects_v2(Bucket="site-frontend-1",
                                             Prefix="sites/")
    return {o["Key"].rsplit("/", 1)[0] for o in resp.get("Contents", [])}


def _age_out(monkeypatch):
    """把 mark_job 眼里的"现在"推到 KEEP_PREFIX_MINUTES 之后，让桶里已有的对象
    全部变成"陈旧"。moto 不允许指定 LastModified，年龄分支只能从这一端注入。"""
    from datetime import datetime, timedelta, timezone
    import mark_job
    monkeypatch.setattr(mark_job, "_utcnow", lambda: (
        datetime.now(timezone.utc)
        + timedelta(minutes=mark_job.KEEP_PREFIX_MINUTES + 1)))


def test_cleanup_keeps_the_previous_live_prefix_for_the_edge_cache_window(
        aws, monkeypatch):
    """上一版正在服务的前缀**不许在成功之后立刻删掉**。

    这是 Codex 2026-08-17 P1-1，M7"原子切换"的必要条件：切路由是一次 put_item，
    但 Edge 每个实例把整条路由 item 缓存 60s（origin_request.ROUTE_CACHE_TTL），
    提交之后仍有 warm 实例按**旧** static_prefix 改写请求。旧前缀被立刻删掉 ⇒
    那些实例打到一个不存在的对象上，而前端桶是私有的 ⇒ 浏览器拿到 **403 而不是
    404**，最长约 60s。

    红的条件：上一版前缀被删（旧实现必红——它删掉除当前 job 外的一切）。
    用例把"现在"推到 KEEP_PREFIX_MINUTES 之后，所以保留**不是**靠年龄那一条侥幸
    成立的，而是靠 previous_route 这个显式锚点。
    """
    import mark_job
    _put_frontend("sites/s-1/job-prev", "sites/s-1/job-new", "sites/s-1/job-ancient")
    _age_out(monkeypatch)

    mark_job._cleanup_old_versions("s-1", "job-new",
                                   previous_prefix="sites/s-1/job-prev")

    left = _frontend_prefixes()
    assert "sites/s-1/job-new" in left, "把线上正在服务的那一份删了"
    assert "sites/s-1/job-prev" in left, (
        "上一版前缀被立刻删掉——仍持有旧路由缓存的 Edge 实例会 403，最长约 60s")
    assert "sites/s-1/job-ancient" not in left, "更早的版本没被清理，存储会无限累积"


def test_cleanup_keeps_a_concurrent_deploys_fresh_upload(aws, monkeypatch):
    """同一站点另一次**正在跑**的部署刚上传完的前缀不许删。

    可达性：`do_confirm_upload` 的条件只管它自己那条 job 的 PENDING→RUNNING，
    部署租约只挡新执行的创建，存量在跑的执行仍可能交错。删掉之后那次部署随后提交的路由会
    指向一个空前缀 ⇒ 整站 403。

    这里**不推时钟**：新上传的对象年龄接近 0，本用例验的就是年龄那一条闸门。
    """
    import mark_job
    _put_frontend("sites/s-1/job-new", "sites/s-1/job-concurrent")

    mark_job._cleanup_old_versions("s-1", "job-new", previous_prefix=None)

    assert "sites/s-1/job-concurrent" in _frontend_prefixes(), (
        "把另一次正在跑的部署刚上传的前端删了——那次部署提交后会整站 403")


def test_cleanup_does_not_touch_other_sites(aws, monkeypatch):
    """只清理本站点。前端桶是所有站点共用的，前缀算错一段就是删别人的站。"""
    import mark_job
    _put_frontend("sites/s-1/job-old", "sites/s-2/job-old")
    _age_out(monkeypatch)

    mark_job._cleanup_old_versions("s-1", "job-new", previous_prefix=None)

    left = _frontend_prefixes()
    assert "sites/s-2/job-old" in left, "删到别的站点了"
    assert "sites/s-1/job-old" not in left


def test_cleanup_keeps_the_previous_prefix_even_when_the_route_value_has_no_slash(
        aws, monkeypatch):
    """路由表里的 static_prefix **不带**尾斜杠，而清理是按分组键（带尾斜杠）比相等。

    两个都要挡住，本用例的 fixture 同时覆盖：
      · 忘了补尾斜杠 ⇒ `p in keep` 永远为假 ⇒ 每次都删掉要保的那个上一版；
      · 用 `startswith` 判归属 ⇒ `sites/s-1/job-1` 会命中 `sites/s-1/job-11/...`
        的对象，删除范围随 job_id 的字面前缀关系漂移（"偶尔删错，换个 job_id 就好"）。
    同一类尾斜杠错误在 Edge 的静态改写上造成过整站 403。
    """
    import mark_job
    _put_frontend("sites/s-1/job-1", "sites/s-1/job-11")
    _age_out(monkeypatch)

    mark_job._cleanup_old_versions("s-1", "job-11", previous_prefix="sites/s-1/job-1")

    assert _frontend_prefixes() == {"sites/s-1/job-1", "sites/s-1/job-11"}


def test_success_path_passes_the_previous_prefix_to_the_cleanup(aws, monkeypatch):
    """成功分支必须把 `previous_route` 里那个前缀传给清理。

    单测 `_cleanup_old_versions` 本身全绿、而 handler 忘了传 —— 那正是这条 P1 的
    真实形态（旧实现的 handler 只传了 site_id 与 job_id）。所以这里按 handler
    的实际调用断言，不是再测一遍那个函数。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    seen = {}
    monkeypatch.setattr(mark_job, "_cleanup_old_versions",
                        lambda *a, **kw: seen.update(args=a, kwargs=kw))
    monkeypatch.setattr(mark_job, "_cleanup_versions", lambda *a, **kw: None)

    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "url": "https://app-s-1.example.com",
                      "previous_route": _old_route("s-1"),
                      "manifest": {"name": "n", "tier": "fullstack-nosql"}}, None)

    assert seen["kwargs"].get("previous_prefix") == "sites/s-1/job-old", (
        "成功分支没把上一版前缀传给清理——那一版会被立刻删掉（Edge 缓存 403）")


def test_success_path_survives_a_first_deploy_without_a_previous_route(aws,
                                                                      monkeypatch):
    """首次部署时 `previous_route` 是 None ⇒ 不许因此抛异常。

    站点此刻已经上线了，清理是最后一步；这里抛异常会把一次成功的部署报成 FAILED。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    _put_frontend("sites/s-1/job-new")
    monkeypatch.setattr(mark_job, "_cleanup_versions", lambda *a, **kw: None)

    out = mark_job.handler({"job_id": job_id, "site_id": "s-1",
                            "url": "https://app-s-1.example.com",
                            "previous_route": None,
                            "manifest": {"name": "n", "tier": "fullstack-nosql"}},
                           None)

    assert out["status"] == "SUCCEEDED"


def test_register_route_records_the_rev_it_committed(aws):
    """提交成功后必须把**写进路由的那个 rev** 留在 event 里。

    这是 mark_job 补偿的提交端锚点。忘了写的后果不是报错而是**恢复静默停摆**：
    mark_job 拿不到 `committed_permissions_rev` ⇒ 一律放弃回滚（fail-closed），
    每次 smoke 失败都只留一条"需人工介入"。所以按 event 断言，不是只看路由表。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=6)
    job_id = common.create_job("o@x.com", "s-1")

    out = register_route.handler(_b3_event(job_id, "s-1"), None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert out["committed_permissions_rev"] == int(item["permissions_rev"]["N"]), (
        "event 里记的 rev 与真正写进路由的那个不一致——补偿会锚一份从未落地的状态")
    assert out["committed_permissions_rev"] == 6


def test_register_route_does_not_record_a_rev_it_never_committed(aws, monkeypatch):
    """事务失败（提交没发生）⇒ event 里**不许**出现 `committed_permissions_rev`。

    留一个下来就等于告诉 mark_job "我提交过"，而路由其实一个字没改。那会让
    `previous_route` 三态契约的第一态（键不在 ⇒ 线上从未变过 ⇒ 别动）失去意义：
    补偿会拿着一个凭空的锚点去写路由。
    """
    import botocore.exceptions
    import pytest

    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=1)
    job_id = common.create_job("o@x.com", "s-1")
    ev = _b3_event(job_id, "s-1")

    def _always_cancelled(**kw):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TransactionCanceledException"}},
            "TransactWriteItems")

    real_client = boto3.client

    def _patched(*a, **kw):
        c = real_client(*a, **kw)
        if a and a[0] == "dynamodb":
            c.transact_write_items = _always_cancelled
        return c

    monkeypatch.setattr(register_route.boto3, "client", _patched)
    with pytest.raises(RuntimeError, match="并发修改"):
        register_route.handler(ev, None)

    assert "committed_permissions_rev" not in ev, \
        "提交从未成功却留下了提交端锚点"


# ---------------------------------------------------------------------------
# Step Functions 的 Task 自动重试（每个 Task 都有 MaxAttempts=6，四种错误都属于
# "函数可能已经执行完，只是响应没回来"）。Codex 2026-08-17 P1-1 / P2。
# 复现方式统一为：**用同一份原始输入把 handler 调第二次**——SFN 重试就是这样，
# 它不会带上第一次丢失的输出。
# ---------------------------------------------------------------------------

def test_register_route_retry_keeps_the_first_snapshot(aws):
    """RegisterRoute 被重试时，快照必须仍是**第一次**拍下的那条旧路由。

    这是 P1-1。旧实现把 `previous_route` 只放在返回值里：重试用原始输入 ⇒ 第一次的
    快照丢失 ⇒ 第二次拍到的是自己刚写进去的**新**路由 ⇒ 后续 smoke 失败时"回滚"成
    写回新路由的 no-op，而日志照样说"已恢复到切换前"。

    红的条件：第二次返回的 previous_route 变成了新路由（= 快照丢了）。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=3)
    job_id = common.create_job("o@x.com", "s-1")
    old = _old_route("s-1", rev="3")
    boto3.client("dynamodb").put_item(TableName="routing", Item=old)
    ev = _b3_event(job_id, "s-1")

    first = register_route.handler(dict(ev), None)
    assert first["previous_route"] == old, "前提不成立：第一次就没拍到旧路由"

    # ---- SFN 重试：同一份**原始**输入再调一次 ----
    second = register_route.handler(dict(ev), None)
    assert second["previous_route"] == old, (
        "重试把自己刚写的新路由当成了『切换前快照』——补偿会变成 no-op，"
        f"而日志会说已恢复：{second['previous_route']}")
    assert second["committed_permissions_rev"] == first["committed_permissions_rev"]
    assert second["effective_auth"] == first["effective_auth"]


def test_register_route_retry_does_not_write_the_route_again(aws, monkeypatch):
    """重试必须**一次路由写都不发**：提交点只能发生一次。

    再写一遍即使内容相同也不是无害的：它会覆盖掉这期间任何更晚的成功部署，
    并且推进 Edge 缓存与写指标，让"提交点只有一次写"这条不再成立。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=3)
    job_id = common.create_job("o@x.com", "s-1")
    boto3.client("dynamodb").put_item(TableName="routing",
                                      Item=_old_route("s-1", rev="3"))
    ev = _b3_event(job_id, "s-1")
    register_route.handler(dict(ev), None)

    calls = _spy_dynamodb(monkeypatch)
    register_route.handler(dict(ev), None)
    assert _routing_writes(calls) == [], \
        f"重试又写了一次路由：{[op for op, _ in calls]}"


def test_register_route_retry_after_a_lost_response_is_still_recoverable(aws):
    """第一次提交成功但**响应丢失**（event 上的字段没传下去）⇒ 重试后仍能完整回滚。

    这条把 P1-1 的两端接起来：重试拿回快照 → mark_job 据它把路由整值写回。
    旧实现在这里会"恢复"成新路由（no-op）并报成功。
    """
    import boto3
    import common
    import mark_job
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=3)
    job_id = common.create_job("o@x.com", "s-1")
    old = _old_route("s-1", rev="3")
    boto3.client("dynamodb").put_item(TableName="routing", Item=old)
    ev = _b3_event(job_id, "s-1")

    register_route.handler(dict(ev), None)          # 第一次：提交了，响应"丢失"
    retried = register_route.handler(dict(ev), None)  # SFN 用原始输入重试
    retried["error_info"] = {"Cause": "smoke failed"}
    mark_job.handler(retried, None)

    assert _routing_item("s-1") == old, "重试之后回滚不再有效——快照在重试里丢了"
    assert "人工" not in (common.get_job(job_id).get("error") or "")


def test_mark_failed_retry_does_not_claim_the_route_was_not_rolled_back(aws):
    """MarkFailed 被重试时不许谎报"路由未回滚、需人工介入"。

    这是 P2。第一次已经把路由写回旧值 ⇒ 第二次的提交端条件必然不成立（线上已经
    不是我提交的那份）。把这一态报成"需人工介入"是**谎报**：路由其实好着，而这条
    提示会让人去处置一个不存在的问题，等真出问题时也就不再被当真。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")
    _put_routing(_committed_route("s-1", job_id, rev="4"))
    ev = _fail_event(job_id, prev)

    mark_job.handler(dict(ev), None)
    assert _routing_item("s-1") == prev, "前提不成立：第一次就没恢复成功"

    mark_job.handler(dict(ev), None)                # SFN 重试
    assert _routing_item("s-1") == prev, "第二次把路由改坏了"
    err = common.get_job(job_id)["error"]
    assert mark_job.ROUTE_NOT_ROLLED_BACK not in err, \
        f"重试谎报了『路由未回滚』，而路由其实已经恢复好了：{err!r}"
    assert mark_job.ROUTE_RESTORE_FAILED not in err


def test_mark_failed_retry_of_a_first_deploy_deletion_is_idempotent(aws):
    """首次部署那一态（previous_route=None ⇒ 删掉）被重试时同样不许谎报。"""
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    _put_routing(_committed_route("s-1", job_id, rev="1"))
    ev = _fail_event(job_id, None, committed_rev=1)

    mark_job.handler(dict(ev), None)
    assert _routing_item("s-1") is None, "前提不成立：第一次就没删掉"

    mark_job.handler(dict(ev), None)                # SFN 重试
    assert _routing_item("s-1") is None
    err = common.get_job(job_id)["error"]
    assert mark_job.ROUTE_NOT_ROLLED_BACK not in err, \
        f"重试谎报了『路由未回滚』，而那条路由已经撤掉了：{err!r}"


def test_first_deploy_deletion_refuses_to_remove_a_newer_deploys_route(aws,
                                                                      monkeypatch):
    """失败的**首次部署**不许删掉一次更晚的成功部署写下的路由。

    这是 Codex 2026-08-17 P1-2：`previous_route is None` 那一态原先是**无条件**
    delete_item，于是这个交错会让整条路由消失——比"停在旧目标"更糟，子域名直接
    不解析。

    交错：首次部署 A 提交（切换前无路由 ⇒ 快照 None）→ 更新 B 成功提交 →
    A 的 smoke 失败 → A 补偿。
    """
    import common
    import mark_job
    job_a = common.create_job("a@x.com", "s-1")
    newer = _committed_route("s-1", "job-newer", rev="1")
    _put_routing(newer)

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler(_fail_event(job_a, None, committed_rev=1), None)

    assert _routing_item("s-1") == newer, \
        "失败的首次部署删掉了更晚那次成功部署的路由——子域名直接不解析了"
    assert len(_routing_writes(calls)) == 1, "分支身份：应当尝试过一次条件删除"
    assert "人工" in common.get_job(job_a)["error"]


def test_missing_snapshot_but_route_already_switched_is_reported(aws):
    """`previous_route` 键缺席、而线上前缀已经是本 job 的 ⇒ 必须如实告知。

    键缺席**通常**意味着 register_route 还没提交（那时一个字都不该动）。但重试
    交错下"提交过、快照却没传到"是可达的，此刻静默什么都不做等于把"路由停在失败
    的新目标上"藏起来。判据是线上前缀是不是我写的——那是只有提交过才可能出现的。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    _put_routing(_committed_route("s-1", job_id, rev="4"))

    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "error_info": {"Cause": "smoke failed"}}, None)

    assert mark_job.ROUTE_SNAPSHOT_LOST in common.get_job(job_id)["error"], \
        "路由已切而快照缺席，却什么都没说"


def test_missing_snapshot_with_an_unrelated_route_stays_silent(aws, monkeypatch):
    """键缺席且线上前缀不是本 job 的 ⇒ 这是"没提交过"，必须**一个字都不说、
    一次写都不发**。

    与上一条是同一个判据的两侧。报成"需人工介入"会让每一次健康门失败都带上一条
    假警报——而健康门失败是最常见的失败。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    live = _old_route("s-1", rev="4")
    _put_routing(live)

    calls = _spy_dynamodb(monkeypatch)
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "error_info": {"Cause": "BackendUnhealthy"}}, None)

    assert _routing_writes(calls) == []
    assert _routing_item("s-1") == live
    err = common.get_job(job_id)["error"]
    assert "人工" not in err, f"健康门失败被加上了假警报：{err!r}"


def test_upload_frontend_refuses_an_empty_frontend(aws):
    """前端产物为空 ⇒ 在**提交点之前** fail closed（Codex 2026-08-17 P1-5）。

    空前缀意味着提交之后每个非 /api 请求都 403（桶是私有的，"没这个对象"就是 403
    而不是 404），而这一点没有任何下游能发现：register_route 照样把 static_prefix
    切过去，require_auth 站点的 smoke 只断言"302 到登录端点"、根本不碰 S3，
    于是这样的部署会被标成 SUCCEEDED，等 Edge 缓存过期之后才整站坏掉。

    红的条件：不抛（旧行为——静默上传 0 个对象然后继续）。
    """
    import pytest

    import common
    import upload_frontend
    common.create_job("a@x.com", "hello-x1")
    # extracted/job-1/frontend/ 下什么都没有（zip 里没有 frontend 目录）
    with pytest.raises(RuntimeError, match="前端产物为空"):
        upload_frontend.handler(dict(EVENT), None)


def test_upload_frontend_accepts_a_non_index_frontend(aws):
    """有对象就放行，**不**额外要求 index.html。

    index.html 的要求**存在，但住在合同层**（`contract/redlines.py`，
    Codex 2026-08-18 P1-5B 之后）：validate 步骤在部署链最早、还没动任何资源时
    就把缺 index.html 的包拦下。上传步骤只守"非空"这一条兜底——在这里再查一遍
    index.html 就是同一条合同要求的第二份手抄，两份漂移时错的那份决定行为。
    本条钉住这个分层。
    """
    import boto3
    import common
    import upload_frontend
    common.create_job("a@x.com", "hello-x1")
    boto3.client("s3").put_object(
        Bucket="site-artifacts-1",
        Key="extracted/job-1/frontend/app.js", Body=b"console.log(1)")
    out = upload_frontend.handler(dict(EVENT), None)
    assert out["job_id"] == "job-1"


def test_restore_falls_back_to_the_persisted_route_commit(aws):
    """事件里两个补偿字段都缺、但 job 里有 route_commit ⇒ **完整回滚**，
    不是报"需人工介入"（独立评审 2026-08-18 Important-2）。

    可达路径：SFN 的 add_catch 把错误并进**失败那个 Task 的输入**。RegisterRoute
    提交成功后若全部重试仍失败（transact 落地后进程被杀、每次重试都栽在回放读上），
    MarkFailed 拿到的是 upload_frontend 的输出——没有 previous_route 也没有
    committed_permissions_rev。而 job 里有与提交同一笔事务落库的 route_commit，
    系统完全有能力自动回滚；只报 SNAPSHOT_LOST 是把能自动做的事推给人工。

    红的条件：路由没被写回、或 job 错误里出现"人工"。
    """
    import boto3 as b3
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    prev = _old_route("s-1", rev="4")
    committed = _committed_route("s-1", job_id, rev="4")
    _put_routing(committed)                       # 线上：本次提交的新目标
    # job 里有与提交同一笔落库的 route_commit（register_route 的产物形态）
    b3.client("dynamodb").update_item(
        TableName="site-deploy-jobs", Key={"job_id": {"S": job_id}},
        UpdateExpression="SET route_commit = :rc",
        ExpressionAttributeValues={":rc": {"M": {
            "previous_route": {"M": prev},
            "committed_route": {"M": committed}}}})

    # MarkFailed 收到的是 RegisterRoute 的**输入**：两个补偿字段都不在
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "error_info": {"Cause": "States.TaskFailed"}}, None)

    assert _routing_item("s-1") == prev, \
        "job 里有 route_commit 却没回滚——把系统能自动做的事推给了人工"
    err = common.get_job(job_id)["error"]
    assert "人工" not in err, f"回滚成功却还在喊需人工介入：{err!r}"


def test_restore_falls_back_for_a_first_deploy_commit_too(aws):
    """同一回落对首次部署（previous_route=NULL）也成立：删掉刚写的那条。"""
    import boto3 as b3
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    committed = _committed_route("s-1", job_id, rev="1")
    _put_routing(committed)
    b3.client("dynamodb").update_item(
        TableName="site-deploy-jobs", Key={"job_id": {"S": job_id}},
        UpdateExpression="SET route_commit = :rc",
        ExpressionAttributeValues={":rc": {"M": {
            "previous_route": {"NULL": True},
            "committed_route": {"M": committed}}}})

    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "error_info": {"Cause": "States.TaskFailed"}}, None)

    assert _routing_item("s-1") is None, \
        "首次部署的 route_commit 回落没删掉刚写的路由——子域名被 FAILED 部署占着"


def test_job_stays_running_until_the_compensation_finishes(aws, monkeypatch):
    """MarkFailed 必须**先补偿、后写 FAILED**（Codex 2026-08-18 R4 P1-1）。

    部署租约判"忙"看的是 holder 的 RUNNING：status 先写成 FAILED 的话，租约在
    补偿完成前就可被抢——新部署 B 在"已提交但未回滚"的路由上算 live/idle 色，
    随后本 job 的补偿把路由写回 B 正在改的那个色，B 还没过健康门的版本就这样
    接上了线上流量。这与 undeploy 那条 Critical（先清租约后 purge）是同一类。

    断言的是**进入补偿那一刻的 status**——只看最终状态的用例对顺序缺陷全盲。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    common.update_job(job_id, status="RUNNING")
    prev = _old_route("s-1", rev="4")
    _put_routing(_committed_route("s-1", job_id, rev="4"))

    seen = {}
    real = mark_job._restore_route

    def _spy(event):
        seen["status_at_restore"] = common.get_job(job_id, consistent=True)["status"]
        return real(event)

    monkeypatch.setattr(mark_job, "_restore_route", _spy)
    mark_job.handler(_fail_event(job_id, prev), None)

    assert seen["status_at_restore"] == "RUNNING", (
        f"进入补偿时 job 已是 {seen['status_at_restore']}——租约此刻已可被抢，"
        "新部署会与补偿交错")
    assert common.get_job(job_id)["status"] == "FAILED"   # 终态照写，只是在后
    assert _routing_item("s-1") == prev                    # 补偿本身照常生效


def test_a_failed_route_commit_read_keeps_the_job_running(aws, monkeypatch):
    """读 route_commit 失败（暂时性超时）⇒ MarkFailed **抛出并保持 RUNNING**，
    不许写 FAILED（Codex 2026-08-18 R5 P1）。

    此刻系统不知道路由是否提交过、要不要恢复。把读失败折叠成"无需补偿"会让
    job 进终态、租约被抢，新部署在一条**状态未知**的路由上开跑——与"补偿动作
    尚未确定完成时锁不能变得可抢"是同一条纪律。抛出让 SFN 重试这次读。
    """
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    common.update_job(job_id, status="RUNNING")
    live = _committed_route("s-1", job_id, rev="4")
    _put_routing(live)

    armed = {"on": True}

    def _boom(op, params):
        if (armed["on"] and op == "GetItem"
                and params.get("TableName") == "site-deploy-jobs"):
            raise RuntimeError("jobs 读超时（注入）")

    _spy_dynamodb(monkeypatch, on_call=_boom)
    # 事件缺两个补偿字段（Task 重试的原始输入形态）⇒ 必须读 route_commit 才知道
    # 有没有提交过——而这次读失败了。
    with pytest.raises(RuntimeError, match="回滚请求失败"):
        mark_job.handler({"job_id": job_id, "site_id": "s-1",
                          "error_info": {"Cause": "smoke failed"}}, None)

    armed["on"] = False          # 断言自己也要读 jobs 表
    assert common.get_job(job_id)["status"] == "RUNNING", \
        "补偿状态读失败却写了终态——租约被放给了新部署"
    assert _routing_item("s-1") == live, "状态未知时不许动路由"


def test_a_failed_live_route_read_keeps_the_job_running(aws, monkeypatch):
    """route_commit 为空后、判定"提交过没有"的**线上路由读**失败 ⇒ 同样抛出保持
    RUNNING。这次读是最后的判定依据，读失败 = 状态未知 ≠ 无需补偿。"""
    import common
    import mark_job
    job_id = common.create_job("a@x.com", "s-1")
    common.update_job(job_id, status="RUNNING")

    def _boom(op, params):
        if op == "GetItem" and params.get("TableName") == "routing":
            raise RuntimeError("路由读超时（注入）")

    _spy_dynamodb(monkeypatch, on_call=_boom)
    with pytest.raises(RuntimeError, match="回滚请求失败"):
        mark_job.handler({"job_id": job_id, "site_id": "s-1",
                          "error_info": {"Cause": "BackendUnhealthy"}}, None)
    assert common.get_job(job_id)["status"] == "RUNNING"
