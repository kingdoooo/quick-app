import boto3
from unittest.mock import MagicMock, patch
import pytest


def test_deploy_site_new_returns_upload_url(aws):
    import server
    out = server.do_deploy_site("a@x.com", "expense-tracker")
    assert out["job_id"].startswith("job-")
    assert out["site_id"].startswith("expense-tracker-")
    assert "uploads/" + out["job_id"] in out["upload_url"]


def test_deploy_site_update_checks_owner(aws):
    import server, common
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    out = server.do_deploy_site("a@x.com", "demo", site_id="demo-abc123")
    assert out["site_id"] == "demo-abc123"
    with pytest.raises(server.NotOwner):
        server.do_deploy_site("intruder@x.com", "demo", site_id="demo-abc123")


def test_confirm_upload_starts_sfn_with_jobid_name(aws, monkeypatch):
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:1:stateMachine:sm")
    # 权限判定的真源是 sites 表（job 只提供 site_id）——真实流程里
    # create_job 之前站点记录必然已存在，fixture 也要如实建出来
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=b"zip")
    sfn = MagicMock()
    with patch.object(server, "_sfn", return_value=sfn):
        out = server.do_confirm_upload("a@x.com", jid)
    assert out["status"] == "RUNNING"
    assert sfn.start_execution.call_args.kwargs["name"] == jid  # 幂等 execution name


def test_confirm_upload_double_call_rejected(aws, monkeypatch):
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=b"zip")
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)
        with pytest.raises(server.AlreadyStarted):  # 条件更新拦住第二次
            server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_checks_owner(aws):
    import server, common
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    with pytest.raises(server.NotOwner):
        server.do_confirm_upload("b@x.com", jid)


def test_confirm_upload_missing_zip_errors(aws):
    import server, common
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    with pytest.raises(server.UploadMissing):
        server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_oversize_zip_rejected(aws, monkeypatch):
    import server, common
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    head = MagicMock()
    head.head_object.return_value = {"ContentLength": 51 * 1024 * 1024}
    head.exceptions = boto3.client("s3").exceptions
    with patch.object(server, "_s3", return_value=head):
        with pytest.raises(server.UploadTooLarge):
            server.do_confirm_upload("a@x.com", jid)


def test_get_status_scoped_to_owner(aws):
    import server, common
    common.upsert_site("s1", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "s1")
    assert server.do_get_status("a@x.com", jid)["status"] == "PENDING"
    with pytest.raises(server.NotOwner):
        server.do_get_status("b@x.com", jid)


def test_list_sites_only_mine(aws):
    import server, common
    common.upsert_site("s1-aaaaaa", owner="a@x.com", name="s1", status="ACTIVE",
                       tier="static", subdomain="app-s1-aaaaaa")
    common.upsert_site("s2-bbbbbb", owner="b@x.com", name="s2", status="ACTIVE",
                       tier="static", subdomain="app-s2-bbbbbb")
    mine = server.do_list_sites("a@x.com")
    assert [s["site_id"] for s in mine] == ["s1-aaaaaa"]
    assert mine[0]["url"] == "https://app-s1-aaaaaa.example.com"


def test_undeploy_checks_owner_and_invokes(aws):
    import server, common
    common.upsert_site("s1-aaaaaa", owner="a@x.com", status="ACTIVE")
    lam = MagicMock()
    with patch.object(server, "_lambda", return_value=lam):
        out = server.do_undeploy("a@x.com", "s1-aaaaaa")
    assert out["job_id"]
    assert lam.invoke.call_args.kwargs["FunctionName"] == "site-deployer-undeploy"
    with pytest.raises(server.NotOwner):
        server.do_undeploy("b@x.com", "s1-aaaaaa")


def test_collaborator_can_deploy_update(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"],
                       require_login=True, allowed_users="org")
    out = server.do_deploy_site("c@x.com", "app", "app-abc123")
    assert out["site_id"] == "app-abc123"


def test_outsider_cannot_deploy_update(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    with pytest.raises(server.NotOwner):
        server.do_deploy_site("x@x.com", "app", "app-abc123")


def test_collaborator_cannot_undeploy(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_undeploy("c@x.com", "app-abc123")


def test_owner_can_undeploy(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    # moto 没有 site-deployer-undeploy 这个函数，实调必 ResourceNotFound；
    # 本用例断言的是权限判定，与既有 test_undeploy_checks_owner_and_invokes 同样打桩
    with patch.object(server, "_lambda", return_value=MagicMock()):
        out = server.do_undeploy("o@x.com", "app-abc123")
    assert out["job_id"]


def test_admin_can_undeploy_others_site(aws):
    import common
    import permissions
    import server
    permissions.add_admin("adm@x.com", added_by="seed")
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    with patch.object(server, "_lambda", return_value=MagicMock()):
        out = server.do_undeploy("adm@x.com", "app-abc123")
    assert out["job_id"]


def test_collaborator_deploy_does_not_change_owner(aws):
    """与 Task 5a 配套的回归：collaborator 走部署入口后 owner 不变。

    完整 SFN 后的断言在 Task 12 的真机 E2E；这里锁住 MCP 侧入口不会自己
    改 owner。
    """
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    server.do_deploy_site("c@x.com", "app", "app-abc123")
    assert common.get_site("app-abc123")["owner"] == "o@x.com"


def test_collaborator_can_read_status(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    job_id = common.create_job("o@x.com", "app-abc123")
    out = server.do_get_status("c@x.com", job_id)
    assert "status" in out


def test_outsider_cannot_read_status(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    job_id = common.create_job("o@x.com", "app-abc123")
    with pytest.raises(server.NotOwner):
        server.do_get_status("x@x.com", job_id)


def test_list_sites_includes_collaborations_with_role(aws):
    import common
    import server
    common.upsert_site("mine-abc123", owner="me@x.com", name="mine",
                       status="ACTIVE", tier="static", collaborators=[])
    common.upsert_site("theirs-abc123", owner="o@x.com", name="theirs",
                       status="ACTIVE", tier="static", collaborators=["me@x.com"])
    common.upsert_site("hidden-abc123", owner="o@x.com", name="hidden",
                       status="ACTIVE", tier="static", collaborators=[])
    got = {s["site_id"]: s["role"] for s in server.do_list_sites("me@x.com")}
    assert got == {"mine-abc123": "owner", "theirs-abc123": "collaborator"}


SITE_ID = "demo-abc123"


def _route_item(site_id=SITE_ID):
    import boto3
    import common
    return boto3.client("dynamodb").get_item(
        TableName="routing",
        Key={"subdomain": {"S": common.subdomain_for(site_id)}}).get("Item")


def _seed_site_and_route(site_id=SITE_ID, owner="o@x.com", collaborators=None):
    import boto3
    import common
    common.upsert_site(site_id, owner=owner, name="demo", status="ACTIVE",
                       tier="static", require_login=True, allowed_users="org",
                       collaborators=collaborators or [])
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": common.subdomain_for(site_id)},
        "site_id": {"S": site_id}, "route_mode": {"S": "split"},
        "static_prefix": {"S": f"sites/{site_id}/j"}, "api_target": {"S": ""},
        "require_auth": {"BOOL": True}, "allowed_users": {"S": "org"},
        "collaborators": {"L": []}, "owner": {"S": owner}})


def test_update_permissions_writes_both_tables(aws):
    import common
    import server
    _seed_site_and_route()
    out = server.do_update_permissions("o@x.com", SITE_ID,
                                       require_login=False,
                                       allowed_users=["a@x.com"])
    assert out["require_login"] is False
    assert out["allowed_users"] == ["a@x.com"]
    assert common.get_site(SITE_ID)["allowed_users"] == ["a@x.com"]
    item = _route_item()
    assert item["require_auth"]["BOOL"] is False
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]


def test_update_permissions_allows_collaborator(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    out = server.do_update_permissions("c@x.com", SITE_ID, require_login=False)
    assert out["require_login"] is False


def test_update_permissions_rejects_outsider(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(server.NotOwner):
        server.do_update_permissions("x@x.com", SITE_ID, require_login=False)


def test_update_permissions_rejects_bad_allowlist(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(ValueError):
        server.do_update_permissions("o@x.com", SITE_ID,
                                     allowed_users=["not-an-email"])


def test_manage_collaborators_add_syncs_route(aws):
    import server
    _seed_site_and_route()
    out = server.do_manage_collaborators("o@x.com", SITE_ID, add=["c@x.com"])
    assert out["collaborators"] == ["c@x.com"]
    assert _route_item()["collaborators"]["L"] == [{"S": "c@x.com"}]


def test_manage_collaborators_rejects_collaborator_caller(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_manage_collaborators("c@x.com", SITE_ID, add=["d@x.com"])


def test_transfer_owner_syncs_route(aws):
    import server
    _seed_site_and_route()
    out = server.do_manage_collaborators("o@x.com", SITE_ID,
                                         transfer_owner="new@x.com")
    assert out["owner"] == "new@x.com"
    assert out["collaborators"] == ["o@x.com"]
    item = _route_item()
    assert item["owner"]["S"] == "new@x.com"
    assert item["collaborators"]["L"] == [{"S": "o@x.com"}]


def test_transfer_owner_rejected_for_collaborator(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_manage_collaborators("c@x.com", SITE_ID,
                                       transfer_owner="c@x.com")


def test_transfer_owner_and_add_are_mutually_exclusive(aws):
    """docstring 承诺互斥就必须真互斥——静默丢弃 add 是半执行陷阱。"""
    import common
    import server
    _seed_site_and_route()
    with pytest.raises(ValueError, match="互斥"):
        server.do_manage_collaborators("o@x.com", SITE_ID,
                                       add=["keep@x.com"],
                                       transfer_owner="new@x.com")
    # 站点纹丝不动：owner 没转，协作者也没加
    site = common.get_site(SITE_ID)
    assert site["owner"] == "o@x.com"
    assert "keep@x.com" not in (site.get("collaborators") or [])


def test_get_permissions_returns_current_state(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    out = server.do_get_permissions("c@x.com", SITE_ID)
    assert out["require_login"] is True
    assert out["allowed_users"] == "org"
    assert out["collaborators"] == ["c@x.com"]
    assert out["owner"] == "o@x.com"
    assert out["my_role"] == "collaborator"


def test_get_permissions_rejects_outsider(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(server.NotOwner):
        server.do_get_permissions("x@x.com", SITE_ID)


def test_update_permissions_surfaces_conflict(aws, monkeypatch):
    """permissions 层的并发冲突必须被转成 MCP 侧的可读异常，不能漏成 500。"""
    import permissions
    import server
    _seed_site_and_route()

    def _boom(*a, **kw):
        raise permissions.PermissionConflict("站点权限已被其他人修改，请刷新后重试")

    monkeypatch.setattr(permissions, "set_access_policy", _boom)
    with pytest.raises(server.PermissionConflict):
        server.do_update_permissions("o@x.com", SITE_ID, require_login=False)


def test_update_permissions_works_before_first_deploy(aws):
    """站点还没部署成功（无路由 item）时改权限不能炸——只更新真源即可。"""
    import common
    import server
    common.upsert_site("nodeploy-abc123", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = server.do_update_permissions("o@x.com", "nodeploy-abc123",
                                       require_login=False)
    assert out["require_login"] is False


# ---- 鉴权→动作之间的撤权窗口（Codex 复审 2026-08-07 P1）----
#
# 这三个用例的价值全在**交错时机**上：必须在 _assert_permission 已经通过之后、
# 最终动作提交之前撤权。在别处撤权测的是另一回事（前者是 _assert_permission
# 本来就拦得住的普通拒绝，后者是"已经落地了再撤"，无从阻止）。
# 所以用 patch 在中间那一刻注入撤权，而不是先改数据再调用。

def _revoke_collaborator(site_id, email):
    """把 email 从协作者名单里去掉，并推进 permissions_rev（与真实撤权同形）。"""
    import common
    site = common.get_site(site_id) or {}
    common.upsert_site(
        site_id,
        collaborators=[c for c in (site.get("collaborators") or []) if c != email],
        permissions_rev=int(site.get("permissions_rev", 0)) + 1)


def test_confirm_upload_rejected_if_revoked_after_authz(aws, monkeypatch):
    """协作者鉴权通过后被撤权 → 这次部署必须落不了地。

    没有 rev 条件时：job 被置 RUNNING、SFN 被启动，已撤权的人提交的代码
    覆盖生产站点。
    """
    import boto3 as _b3
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       collaborators=["c@x.com"], permissions_rev=3)
    jid = common.create_job("c@x.com", "demo-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")

    # HeadObject 成功之后、事务提交之前撤权
    real_s3 = server._s3

    def _s3_then_revoke():
        client = real_s3()
        orig_head = client.head_object

        def head(**kw):
            out = orig_head(**kw)
            _revoke_collaborator("demo-abc123", "c@x.com")
            return out

        client.head_object = head
        return client

    sfn = MagicMock()
    monkeypatch.setattr(server, "_s3", _s3_then_revoke)
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(server.NotOwner):
            server.do_confirm_upload("c@x.com", jid)
    # 两条硬断言：SFN 没被启动，job 也没被置 RUNNING
    sfn.start_execution.assert_not_called()
    assert common.get_job(jid)["status"] == "PENDING"


def test_undeploy_rejected_if_ownership_transferred_after_authz(aws, monkeypatch):
    """鉴权后所有权被转移 → 旧 owner 的下线请求必须落不了地。

    没有 rev 条件时：undeploy Lambda 被异步调用，purge_data=True 会删掉
    **新 owner** 的站点数据，不可恢复。
    """
    import common
    import server
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=2)

    real_assert = server._assert_permission

    def _assert_then_transfer(*a, **kw):
        out = real_assert(*a, **kw)
        # 鉴权已完成，此刻站点被转给别人（rev 前进）
        common.upsert_site("demo-abc123", owner="new@x.com",
                           permissions_rev=3)
        return out

    monkeypatch.setattr(server, "_assert_permission", _assert_then_transfer)
    lam = MagicMock()
    with patch.object(server, "_lambda", return_value=lam):
        with pytest.raises(server.NotOwner):
            server.do_undeploy("o@x.com", "demo-abc123", purge_data=True)
    lam.invoke.assert_not_called()


def test_undeploy_still_works_when_rev_unchanged(aws):
    """正向对照：权限没变时前面那道条件不能误拦（否则下线功能直接坏掉）。"""
    import common
    import server
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=7)
    lam = MagicMock()
    with patch.object(server, "_lambda", return_value=lam):
        out = server.do_undeploy("o@x.com", "demo-abc123")
    assert out["job_id"]
    lam.invoke.assert_called_once()


def test_undeploy_works_on_site_without_rev_attribute(aws):
    """一期存量站点没有 permissions_rev 属性——条件必须用
    attribute_not_exists 兜住，否则老站点全部无法下线。"""
    import common
    import server
    common.upsert_site("legacy-abc123", owner="o@x.com", status="ACTIVE")
    lam = MagicMock()
    with patch.object(server, "_lambda", return_value=lam):
        out = server.do_undeploy("o@x.com", "legacy-abc123")
    assert out["job_id"]
    lam.invoke.assert_called_once()


# ---- 守卫的两个漏洞（Codex 复审 2026-08-07 第二轮，均已实测复现）----

def test_confirm_upload_rejected_if_site_deleted_and_recreated(aws, monkeypatch):
    """站点被删除并用同 site_id 重建（新 owner、无 rev）→ 旧 owner 必须被拒。

    `attribute_not_exists(permissions_rev)` 那个兼容分支在 item 被重建且没写
    rev 时同样成立，于是旧 owner 的部署会覆盖新 owner 的站点。
    """
    import boto3 as _b3
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=7)
    jid = common.create_job("o@x.com", "demo-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    ddb = _b3.client("dynamodb")
    real_s3 = server._s3

    def _s3_then_recreate():
        client = real_s3()
        orig_head = client.head_object

        def head(**kw):
            out = orig_head(**kw)
            # 鉴权已完成；此刻站点被删除并以同 site_id 重建（无 permissions_rev）
            ddb.delete_item(TableName="site-sites",
                            Key={"site_id": {"S": "demo-abc123"}})
            ddb.put_item(TableName="site-sites", Item={
                "site_id": {"S": "demo-abc123"},
                "owner": {"S": "new@x.com"}, "status": {"S": "ACTIVE"}})
            return out

        client.head_object = head
        return client

    sfn = MagicMock()
    monkeypatch.setattr(server, "_s3", _s3_then_recreate)
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(server.NotOwner):
            server.do_confirm_upload("o@x.com", jid)
    sfn.start_execution.assert_not_called()
    assert common.get_job(jid)["status"] == "PENDING"
    assert common.get_site("demo-abc123")["owner"] == "new@x.com"


def test_undeploy_rejected_if_legacy_site_recreated_by_other_owner(aws):
    """一期存量站点（无 rev）被重建成别人的 → 旧 owner 的下线必须被拒。

    无 rev 时守卫退回按角色事实判定（owner 仍是我 / 我仍在 collaborators），
    所以"重建后 owner 变成别人"照样拦得住。
    """
    import boto3 as _b3
    import common
    import server
    common.upsert_site("legacy-abc123", owner="o@x.com", status="ACTIVE")
    ddb = _b3.client("dynamodb")
    real_assert = server._assert_permission

    def _assert_then_recreate(*a, **kw):
        out = real_assert(*a, **kw)
        ddb.put_item(TableName="site-sites", Item={
            "site_id": {"S": "legacy-abc123"},
            "owner": {"S": "new@x.com"}, "status": {"S": "ACTIVE"}})
        return out

    with patch.object(server, "_assert_permission", _assert_then_recreate):
        lam = MagicMock()
        with patch.object(server, "_lambda", return_value=lam):
            with pytest.raises(server.NotOwner):
                server.do_undeploy("o@x.com", "legacy-abc123", purge_data=True)
        lam.invoke.assert_not_called()


def test_legacy_collaborator_can_still_deploy(aws, monkeypatch):
    """正向对照：无 rev 的存量站点，协作者仍要能部署（守卫不能误伤）。"""
    import boto3 as _b3
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("legacy-abc123", owner="o@x.com",
                       collaborators=["c@x.com"], status="ACTIVE")
    jid = common.create_job("c@x.com", "legacy-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    sfn = MagicMock()
    with patch.object(server, "_sfn", return_value=sfn):
        out = server.do_confirm_upload("c@x.com", jid)
    assert out["status"] == "RUNNING"
    sfn.start_execution.assert_called_once()


def test_confirm_upload_rolls_back_when_start_execution_fails(aws, monkeypatch):
    """StartExecution **被服务端确定拒绝**（ClientError）→ job 退回 PENDING，可重试。

    只有确定拒绝才允许回滚：ClientError 意味着 SFN 收到并拒绝了请求，执行确定
    没起来。（网络类错误走另一条：见 test_uncertain_start_error_keeps_running。）
    不回滚的话 job 永久停在 RUNNING 而没有 execution 在跑，重试被判
    AlreadyStarted，用户只能轮询一个永不推进的任务。
    """
    import boto3 as _b3
    import botocore.exceptions
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=1)
    jid = common.create_job("o@x.com", "demo-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    boom = MagicMock()
    boom.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionLimitExceeded"}}, "StartExecution")
    with patch.object(server, "_sfn", return_value=boom):
        with pytest.raises(botocore.exceptions.ClientError):
            server.do_confirm_upload("o@x.com", jid)
    assert common.get_job(jid)["status"] == "PENDING", "没回滚 → 永久卡死"
    # 重试必须能真正跑通（这才是回滚的目的）
    ok = MagicMock()
    with patch.object(server, "_sfn", return_value=ok):
        assert server.do_confirm_upload("o@x.com", jid)["status"] == "RUNNING"
    ok.start_execution.assert_called_once()


def test_confirm_upload_fails_job_when_execution_already_closed(aws, monkeypatch):
    """ExecutionAlreadyExists 表示同名执行**已关闭**（官方契约），不是"仍在跑"。

    同 name + 同 input 且在运行时 StartExecution 是**成功**的；只有已关闭或
    input 不同才报这个错。本函数的 input 对同一 job 恒定，所以收到它就证明
    execution 已关闭，而该 name 90 天内不可复用 → 这个 job 永远推不动了。
    因此必须置 FAILED，既不能报成功（用户永远轮询）也不能回滚成 PENDING
    （重试只会再撞同一个错）。
    """
    import boto3 as _b3
    import botocore.exceptions
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=1)
    jid = common.create_job("o@x.com", "demo-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    dup = MagicMock()
    dup.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionAlreadyExists", "Message": "exists"}},
        "StartExecution")
    with patch.object(server, "_sfn", return_value=dup):
        with pytest.raises(server.AlreadyStarted):
            server.do_confirm_upload("o@x.com", jid)
    job = common.get_job(jid)
    assert job["status"] == "FAILED", "必须如实失败，不能谎报成功或卡在 RUNNING"
    assert job["error"], "要给出可操作的原因"


def test_rollback_does_not_touch_advanced_job(aws):
    """回滚条件必须只匹配"刚置 RUNNING/queued"：已推进的任务不能被踩回 PENDING。"""
    import common
    import server
    jid = common.create_job("o@x.com", "demo-abc123")
    common.update_job(jid, status="RUNNING", phase="validate")   # SFN 已在跑
    server._rollback_job_to_pending(jid)
    job = common.get_job(jid)
    assert job["status"] == "RUNNING" and job["phase"] == "validate"


def test_legacy_undeploy_rejected_after_owner_downgraded_to_collaborator(aws):
    """存量站点(无 rev)：旧 owner 鉴权后发生**合法的** transfer_owner，
    他被自动降级为 collaborator → undeploy 必须被拒。

    CAPABILITIES 里 undeploy 不含 collaborator。守卫若把 owner 与 collaborator
    合并成"二者之一即可"，旧 owner 就能 purge 掉新 owner 的数据（不可恢复）。
    这是"守卫的角色判定必须与 CAPABILITIES 同源"的回归用例。
    """
    import boto3 as _b3
    import common
    import permissions
    import server
    # **不给 permissions_rev**——本用例要的正是"存量无 rev"那条守卫分支。
    # 但 require_login / allowed_users 要给：M02 起写路径（这里是 setup 用的
    # transfer_owner）走 effective_policy 严格解析，缺这两个字段的行会被拒绝，
    # 用例就走不到它真正要证明的角色判定上。"有 auth 字段、缺 rev"是真实的
    # 存量形态（见 migrate_permissions.py 对这类稀疏行的说明）。
    common.upsert_site("legacy-abc123", owner="old@x.com", status="ACTIVE",
                       collaborators=[], tier="fullstack-sql",
                       require_login=True, allowed_users="org")
    _b3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-legacy-abc123"},
        "site_id": {"S": "legacy-abc123"}, "owner": {"S": "old@x.com"}})
    real = server._assert_permission

    def _assert_then_transfer(*a, **kw):
        out = real(*a, **kw)
        # 鉴权已过；此刻发生正常的所有权转移（旧 owner 降级为 collaborator）
        permissions.transfer_owner("legacy-abc123", actor="old@x.com",
                                   new_owner="new@x.com")
        return out

    with patch.object(server, "_assert_permission", _assert_then_transfer):
        lam = MagicMock()
        with patch.object(server, "_lambda", return_value=lam):
            with pytest.raises(server.NotOwner):
                server.do_undeploy("old@x.com", "legacy-abc123", purge_data=True)
        lam.invoke.assert_not_called()
    site = common.get_site("legacy-abc123")
    # 前置事实自检：确认这个场景真的把旧 owner 变成了 collaborator，
    # 且该角色确实无权 undeploy（否则用例证明的不是我想证明的东西）
    assert site["owner"] == "new@x.com"
    assert "old@x.com" in site["collaborators"]
    assert not permissions.can(permissions.role_of("old@x.com", site), "undeploy")


def test_legacy_collaborator_deploy_still_allowed_after_downgrade(aws, monkeypatch):
    """对照：deploy **含** collaborator，所以降级后仍应放行——
    守卫必须按 action 区分，不能一律收紧成"只有 owner"。"""
    import boto3 as _b3
    import common
    import permissions
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    # 同上一条用例：留住"无 rev"，补齐两个 auth 字段
    common.upsert_site("legacy-abc123", owner="old@x.com", status="ACTIVE",
                       collaborators=[], require_login=True,
                       allowed_users="org")
    jid = common.create_job("old@x.com", "legacy-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    real_s3 = server._s3

    def _s3_then_transfer():
        c = real_s3()
        orig = c.head_object

        def head(**kw):
            out = orig(**kw)
            permissions.transfer_owner("legacy-abc123", actor="old@x.com",
                                       new_owner="new@x.com")
            return out

        c.head_object = head
        return c

    sfn = MagicMock()
    monkeypatch.setattr(server, "_s3", _s3_then_transfer)
    with patch.object(server, "_sfn", return_value=sfn):
        out = server.do_confirm_upload("old@x.com", jid)
    assert out["status"] == "RUNNING"
    sfn.start_execution.assert_called_once()
    site = common.get_site("legacy-abc123")
    assert permissions.can(permissions.role_of("old@x.com", site), "deploy")


def test_execution_already_exists_does_not_clobber_succeeded_job(aws, monkeypatch):
    """已经成功的 job 不能被 ExecutionAlreadyExists 改写成 FAILED。

    可达序列：首次 StartExecution 响应丢失 → 回滚成 PENDING → 那条 execution
    其实跑完了、mark_job 写入 SUCCEEDED + url → 用户重试 → 事务把 job 置回
    RUNNING/queued → StartExecution 报 ExecutionAlreadyExists。此时若无条件写
    FAILED，用户看到"失败"而站点其实已更新好。
    """
    import boto3 as _b3
    import botocore.exceptions
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                       permissions_rev=1)
    jid = common.create_job("o@x.com", "demo-abc123")
    _b3.client("s3").put_object(Bucket="site-artifacts-1",
                                Key=f"uploads/{jid}.zip", Body=b"zip")
    # 那条 execution 已经跑完并回写了成功状态
    common.update_job(jid, status="SUCCEEDED", phase="done",
                      url="https://app-demo-abc123.example.com")
    # 用户重试：条件迁移要求 PENDING，所以这里会先被 AlreadyStarted 拦住；
    # 直接调到 start_execution 那段的形态用 PENDING + url 已填来构造
    common.update_job(jid, status="PENDING", phase="submitted")
    dup = MagicMock()
    dup.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionAlreadyExists", "Message": "exists"}},
        "StartExecution")
    with patch.object(server, "_sfn", return_value=dup):
        with pytest.raises(server.AlreadyStarted):
            server.do_confirm_upload("o@x.com", jid)
    job = common.get_job(jid)
    assert job["url"] == "https://app-demo-abc123.example.com", "成功的 url 丢了"
    assert job["status"] != "FAILED", (
        f"已成功的部署被改写成 {job['status']}——用户会以为失败而站点其实已更新")


def test_deploy_site_regenerates_id_on_collision(aws, monkeypatch):
    """建站分支撞 ID 时重新生成，不得对已有行做任何写。"""
    import common
    import server
    common._table("SITES_TABLE").put_item(Item={
        "site_id": "notes-aaaaaa", "owner": "victim@x.com",
        "name": "notes", "status": "ACTIVE",
        "created_at": "2026-01-01T00:00:00+00:00"})
    ids = iter(["notes-aaaaaa", "notes-bbbbbb"])   # 第一次碰撞，第二次成功
    monkeypatch.setattr(common, "new_site_id", lambda name: next(ids))
    out = server.do_deploy_site("caller@x.com", "notes")
    assert out["site_id"] == "notes-bbbbbb"
    victim = common.get_site("notes-aaaaaa")
    assert victim["owner"] == "victim@x.com" and victim["status"] == "ACTIVE"


def test_undeploy_invoke_failure_does_not_leave_pending_job(aws):
    """MCP 侧同样：invoke 失败不得留下永久 PENDING 的 job。

    与 panel 的 test_undeploy_invoke_failure_does_not_leave_pending_job 同一个
    缺陷类（Codex 审查 2026-08-10 P1-4）——两个 writer 都要收敛，
    照 M3-FINDINGS「别打地鼠，修那一类」的要求清点全部调用点。
    """
    import server, common
    server.common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                              tier="fullstack-nosql")
    import botocore.exceptions
    lam = MagicMock()
    # **确定拒绝**（ClientError）才就地收敛成 FAILED；网络类错误保持 RUNNING
    # 交给 sweeper（见 test_uncertain_undeploy_invoke_error_keeps_running）。
    lam.invoke.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "Invoke")
    with patch.object(server, "_lambda", return_value=lam):
        with pytest.raises(botocore.exceptions.ClientError):
            server.do_undeploy("o@x.com", "demo-abc123")
    jobs = common.list_jobs_by_site("demo-abc123")
    assert jobs, "没有 job 记录"
    assert jobs[0]["status"] == "FAILED", (
        f"job 停在 {jobs[0]['status']}——确定被拒时应立即放开租约")


# ================= on-behalf 信任规则（二期 M4，spec §5.3）=================
#
# `_caller_email()` 从此有两条信任路径，而**第二条决定"这个请求以谁的身份行事"**
# ——写错就是"任何 OAuth 用户加一个头即可冒充任意人"。所以这一组里负测比正路径
# 重要得多，顺序也按危险程度排。
#
# 规则（实现里同一份注释）：
#   token 有 email claim → 既有 OAuth 路径，一字不改（idp / auth_via /
#                          email_verified 三重校验照旧）
#   token 无 email claim → 只有在 ① MACHINE_CLIENT_ID 非空、② token 的
#                          client_id 与它 compare_digest 相等、③ 头值过
#                          permissions.EMAIL_RE.fullmatch 时，才信 on-behalf 头
#   其余                 → NotOwner（文案一字不改）

MACHINE_CLIENT = "machine1234567890abcdef"
MCP_CLIENT = "mcpclient1234567890abcd"


def _machine_token(**over):
    """机器 token 的真实 claim 形态：**没有** email / idp / auth_via /
    email_verified 任何一项（spike 实测 client_credentials token 的 10 个
    claim 里一个都不是）——这正是它必须走第二条路径的原因。"""
    from conftest import make_token
    claims = {"sub": MACHINE_CLIENT, "client_id": MACHINE_CLIENT,
              "token_use": "access", "scope": "site-builder-mcp/invoke",
              "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_x"}
    claims.update(over)
    return make_token(claims)


def _on_behalf(email: str) -> dict:
    import server
    return {server.ON_BEHALF_HEADER: email}


def test_ordinary_oauth_user_cannot_impersonate_with_the_header(monkeypatch):
    """**只看头 = 任何 OAuth 用户加个头就能冒充别人。**

    这条是 M4 最重要的负测。构造：一个**合法的** OAuth 用户 token（有 email
    claim、idp/auth_via 齐全、能正常调工具），额外带上
    X-SB-On-Behalf-Of: victim@x.com。必须解析成**他自己**，绝不是受害者。
    """
    import server
    from conftest import make_token, with_auth
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, make_token({
        "email": "caller@x.com", "idp": "Feishu",
        "auth_via": "TokenGeneration_HostedAuth", "email_verified": True,
        "client_id": MCP_CLIENT}), **_on_behalf("victim@x.com"))
    assert server._caller_email() == "caller@x.com"


def test_oauth_user_token_with_machine_client_id_still_uses_its_own_email(monkeypatch):
    """纵深防御：即使 token 的 client_id 恰好等于 machine client，只要它带
    email claim 就走第一条路径。on-behalf 头**只对无 email claim 的 token 生效**
    ——否则"拿到一个 machine client 签出的用户 token"就能冒充。"""
    import server
    from conftest import make_token, with_auth
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, make_token({
        "email": "caller@x.com", "idp": "Feishu",
        "auth_via": "TokenGeneration_HostedAuth", "email_verified": True,
        "client_id": MACHINE_CLIENT}), **_on_behalf("victim@x.com"))
    assert server._caller_email() == "caller@x.com"


def test_untrusted_oauth_token_cannot_fall_through_to_on_behalf(monkeypatch):
    """三重校验拒掉的 token 不得"退而"走 on-behalf 路径。

    有 email claim 但 idp 不受信 → 必须直接 NotOwner。若实现把三重校验的拒绝
    改成"继续往下试 on-behalf"，一个来源不受信的 token 配上 machine client_id
    就能拿到任意身份。
    """
    import server
    from conftest import make_token, with_auth
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, make_token({
        "email": "evil@x.com", "idp": "EvilCorp",
        "auth_via": "TokenGeneration_HostedAuth", "email_verified": True,
        "client_id": MACHINE_CLIENT}), **_on_behalf("victim@x.com"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_machine_token_without_header_is_rejected(monkeypatch):
    """spike 已实证改造前的行为（"无法识别调用者身份"）；改造后仍必须拒。

    机器 token 自己不代表任何人——身份完全来自 on-behalf 头。没有头就没有身份，
    不得回退成任何默认值（空 owner / machine client 名 / 第一个管理员）。
    """
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token())
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_machine_token_with_header_resolves_to_header_value(monkeypatch):
    """正路径：machine client 的 token + 合法头 → 头里那个 email。"""
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(), **_on_behalf("owner@x.com"))
    assert server._caller_email() == "owner@x.com"


def test_on_behalf_path_is_the_only_one_allowed_to_skip_claim_checks(monkeypatch):
    """机器 token 天生没有 idp/auth_via/email_verified，所以这条路径**必须**跳过
    三重校验——把它锁住，免得将来有人"顺手补齐"而让全部 Key 调用当场失效。

    可信性来自**创建时**：Key 只能在控制台创建，而控制台身份是 Edge 注入的
    x-user-email，那条路径已过 REQUIRE_IDP_CLAIM 校验（决定 8）。
    """
    import server
    from conftest import with_auth
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")          # 严格模式也要通
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFIED", "true")
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(), **_on_behalf("owner@x.com"))
    assert server._caller_email() == "owner@x.com"


def test_wrong_client_id_with_header_is_rejected(monkeypatch):
    """client_id 不是 machine client 的 token 带头 → 拒。

    注意构造：**不能**用 mcp client 的 token 做这条（它有 email claim，会走
    第一条路径）。这里是"无 email claim 且 client_id 是别的值"。
    """
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(client_id="someothelient00000000"),
              **_on_behalf("victim@x.com"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_user_token_without_email_claim_cannot_use_the_header(monkeypatch):
    """真实会发生的形态：pre-token 触发器没挂/挂错时，mcp client 的 access token
    **没有 email claim**。此时带上 on-behalf 头必须拒——否则任何登录用户都能在
    那段时间里冒充任意人。"""
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(client_id=MCP_CLIENT),
              **_on_behalf("victim@x.com"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


@pytest.mark.parametrize("claim", [None, "", 123, ["m"], {"c": 1}])
def test_token_without_usable_client_id_cannot_use_the_header(monkeypatch, claim):
    """client_id 缺失或不是字符串 → 拒。

    实现刻意不写"client_id 为空就拒"那句（那会挡住空环境变量的闸门、让它无法被
    测试证明，见 _on_behalf_email 的注释），所以类型/缺失这条路必须单独钉住。
    """
    import server
    from conftest import make_token, with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    claims = {"sub": MACHINE_CLIENT, "token_use": "access"}
    if claim is not None:
        claims["client_id"] = claim
    with_auth(monkeypatch, make_token(claims), **_on_behalf("victim@x.com"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


@pytest.mark.parametrize("env", ["", "   ", None])
def test_missing_machine_client_env_rejects_all_on_behalf(monkeypatch, env):
    """**配置缺失不得退化成"不比对"**。

    没配 MACHINE_CLIENT_ID 就是"本平台没启用 API Key"，此时任何 on-behalf 头都
    必须拒。若实现让空值走进 compare_digest，`"" == ""` 会让**任何**无 email
    claim 的 token（含 client_id 缺失的）拿到任意身份——本仓库记过的
    "默认值恰好意味着放行"那一类。
    """
    import server
    from conftest import with_auth
    if env is None:
        monkeypatch.delenv(server.MACHINE_CLIENT_ID_ENV, raising=False)
    else:
        monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, env)
    # 两种 token 都要拒：client_id 与环境值"相同"的空串形态最危险
    for token in (_machine_token(), _machine_token(client_id=""),
                  _machine_token(client_id="   ")):
        with_auth(monkeypatch, token, **_on_behalf("victim@x.com"))
        with pytest.raises(server.NotOwner):
            server._caller_email()


@pytest.mark.parametrize("bad", ["", "   ", "notanemail", "a@b",
                                 "a@b.c,d@e.f",
                                 "a@b.com\nX-Injected: 1"])
def test_malformed_on_behalf_header_is_rejected(monkeypatch, bad):
    """头值必须过 permissions.EMAIL_RE.fullmatch。

    最后一条（含换行）尤其重要：邮箱形态校验顺带挡住头注入。倒数第二条
    （逗号分隔）锁的是 fullmatch 而不是 match——`match` 会让这两条都通过，
    而通过之后那个字符串会被当成授权主键去查 owner/collaborators。
    """
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(), **_on_behalf(bad))
    with pytest.raises(server.NotOwner):
        server._caller_email()


# `<script>@x.com` **过** permissions.EMAIL_RE（`[^@\s]+` 允许 < >），所以它
# 不在上面的拒绝清单里——这是**有意的**：头值的形态闸门必须与平台其它入口
# （控制台加协作者、site.json 的 allowed_users）**完全同一个判定**。在这里单独
# 加严会造成"控制台能加的协作者，用 Key 却调不了"，而它换不来安全收益：这个头
# 只在机器 token 后面才被读，而 key-proxy 每次都用 Key 记录里的 email 覆写它。
# 所以下面锁的是**等价性**，不是某个具体清单——将来 EMAIL_RE 收严，这里自动跟上。
@pytest.mark.parametrize("value", [
    "owner@x.com", "a.b+tag@sub.example.com", "A@B.COM", "<script>@x.com",
    "", "   ", "notanemail", "a@b", "a@b.c,d@e.f", "a@b.com\nX-Injected: 1",
    "a@b.com ", " a@b.com", "a@b.com,", "\ta@b.com"])
def test_on_behalf_shape_gate_is_exactly_permissions_email_re(monkeypatch, value):
    import permissions
    import server
    from conftest import with_auth
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    with_auth(monkeypatch, _machine_token(), **_on_behalf(value))
    accepted = bool(permissions.EMAIL_RE.fullmatch(value))
    if accepted:
        assert server._caller_email() == value
    else:
        with pytest.raises(server.NotOwner):
            server._caller_email()


def test_machine_client_id_is_read_per_call_not_module_level(monkeypatch):
    """照 _trusted_idps 的既有形态：固化成模块级常量会让拒绝类用例假通过。

    做法：server 在本文件更早的用例里已被导入（那时 env 未设），现在 setenv
    必须能被看到——看不到就说明值在 import 时被固化了。
    """
    import server
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    assert server._machine_client_id() == MACHINE_CLIENT
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, "another-machine-client")
    assert server._machine_client_id() == "another-machine-client"
    monkeypatch.delenv(server.MACHINE_CLIENT_ID_ENV, raising=False)
    assert server._machine_client_id() == ""


def test_on_behalf_header_is_read_case_insensitively(monkeypatch):
    """starlette 给的头名全小写，实现必须按小写取。

    这条防的是"实现按 `X-SB-On-Behalf-Of` 原样取值"——那样线上永远取不到头，
    症状是所有 Key 调用都报"无法识别调用者身份"，而单测若也用大写键构造请求
    就会一起瞎掉（conftest.with_auth 因此强制小写化）。
    """
    import server
    monkeypatch.setenv(server.MACHINE_CLIENT_ID_ENV, MACHINE_CLIENT)
    assert server.ON_BEHALF_HEADER == server.ON_BEHALF_HEADER.lower()


def _job_item(job_id: str) -> dict:
    return boto3.client("dynamodb", region_name="us-east-1").get_item(
        TableName="site-deploy-jobs", Key={"job_id": {"S": job_id}})["Item"]


def test_confirm_upload_pins_the_etag_it_head_checked(aws, monkeypatch):
    """把 ETag 写进 job 记录的那一步必须**在同一笔事务里**、且用**那一次 HEAD** 的
    ETag：为取 etag 再 HEAD 一次会重新打开 TOCTOU（第二次 HEAD 可能看到另一个对象，
    于是钉住的是"第二次看到的字节"而 50MB 是对第一次查的）。

    validate 用这个 etag 做 `IfMatch`（deployer 侧
    test_upload_is_pinned_to_the_bytes_confirm_upload_checked），所以"钉的是哪一次
    HEAD"不是风格问题：钉错一次，被校验的字节与被查过 50MB 的字节就不是同一个对象。
    """
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    body = b"zip-bytes-of-a-known-length"
    put = boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                        Key=f"uploads/{jid}.zip", Body=body)
    real = boto3.client("s3", region_name="us-east-1")
    heads = []

    class _Spy:
        """只记 head_object 的次数，其余一律透传给真客户端。"""

        exceptions = real.exceptions

        def head_object(self, **kw):
            heads.append(kw["Key"])
            return real.head_object(**kw)

        def __getattr__(self, name):
            return getattr(real, name)

    with patch.object(server, "_s3", return_value=_Spy()), \
         patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)

    item = _job_item(jid)
    assert item["upload_etag"]["S"] == put["ETag"]
    assert item["upload_bytes"]["N"] == str(len(body))
    assert heads == [f"uploads/{jid}.zip"], (
        f"head_object 被调用 {len(heads)} 次——为取 etag 再 HEAD 一次就重新打开了"
        "那个 TOCTOU（钉住的字节与查过 50MB 的字节可以是两个对象）")


def test_double_confirm_does_not_repin(aws, monkeypatch):
    """etag 与 PENDING→RUNNING 在同一笔事务 ⇒ 第二次点击（AlreadyStarted）既不推进
    状态也不许改 etag。否则重放能把已经开跑的 job 钉到新字节上。"""
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    jid = common.create_job("a@x.com", "demo-abc123")
    s3 = boto3.client("s3")
    first = s3.put_object(Bucket="site-artifacts-1", Key=f"uploads/{jid}.zip",
                          Body=b"first-bytes")["ETag"]
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)
        assert _job_item(jid)["upload_etag"]["S"] == first
        # 预签名 URL 还活着：把对象换成另一份字节再点一次确认
        second = s3.put_object(Bucket="site-artifacts-1", Key=f"uploads/{jid}.zip",
                               Body=b"second-bytes-are-different")["ETag"]
        assert second != first, "前提：两次上传的 ETag 必须不同，否则本例测不到东西"
        with pytest.raises(server.AlreadyStarted):
            server.do_confirm_upload("a@x.com", jid)
    assert _job_item(jid)["upload_etag"]["S"] == first, (
        "第二次确认改掉了 etag——重放能把已经开跑的 job 钉到新字节上")


# ---------------------------------------------------------------------------
# per-site 部署租约（M7 加固，Codex 2026-08-17 P1-3）
# ---------------------------------------------------------------------------

def _ready_job(owner="a@x.com", site_id="demo-abc123"):
    """建站点 + job + 上传对象，返回 job_id。confirm_upload 的前置条件。"""
    import boto3 as b3
    import common
    common.upsert_site(site_id, owner=owner, status="ACTIVE")
    jid = common.create_job(owner, site_id)
    b3.client("s3").put_object(Bucket="site-artifacts-1",
                              Key=f"uploads/{jid}.zip", Body=b"zip")
    return jid


def test_second_concurrent_deploy_of_the_same_site_is_rejected(aws, monkeypatch):
    """同一站点第二次并发部署必须被拒。

    这是 Codex 2026-08-17 P1-3。不拒的话两次部署会**算出同一个空闲色**，各自把那个
    alias 指向自己的版本、各自过健康门，线上可能变成"前端来自 A、后端来自 B"——
    M7 的"前后端在同一个提交点切换"这条不变量被破坏，而两个 job 都不会触发补偿
    （一个成功、一个在提交点之前就失败）。

    红的条件：第二次也拿到了 RUNNING（旧行为）。
    """
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    first, second = _ready_job(), _ready_job()
    with patch.object(server, "_sfn", return_value=MagicMock()):
        assert server.do_confirm_upload("a@x.com", first)["status"] == "RUNNING"
        with pytest.raises(server.AlreadyStarted, match="另一次部署|正在进行"):
            server.do_confirm_upload("a@x.com", second)


def test_lease_is_released_when_the_holder_reaches_a_terminal_state(aws,
                                                                   monkeypatch):
    """持有者一旦终态，下一次部署就能拿到租约。

    **租约没有显式释放路径**，判据是推导出来的（"忙 ⟺ 持有者非终态"），所以这条
    用例同时是那个设计的验收：把持有者置成 SUCCEEDED 就够了，不需要任何人去"释放"。
    红的条件：站点在一次成功部署之后再也部署不了（那才是加锁最危险的失败模式）。
    """
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    first, second = _ready_job(), _ready_job()
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", first)
        common.update_job(first, status="SUCCEEDED")          # mark_job 干的事
        assert server.do_confirm_upload("a@x.com", second)["status"] == "RUNNING"


def test_lease_does_not_block_a_different_site(aws, monkeypatch):
    """租约是 per-site 的，不许把别的站点一起挡住。"""
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    a = _ready_job(site_id="demo-abc123")
    b = _ready_job(site_id="other-def456")
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", a)
        assert server.do_confirm_upload("a@x.com", b)["status"] == "RUNNING"


def test_lease_row_stays_out_of_both_job_indexes(aws, monkeypatch):
    """租约行**不许**带 site_id / owner / status。

    带 site_id 或 owner 就会进 jobs 表的两个 GSI（稀疏索引），于是控制台的
    "部署历史"（site-index 的 Query）与 list_jobs_by_owner 里会多出一条不是 job
    的东西；带 status 就会被 reconcile 的 sweeper 按 `#s = :running` 捞去当成
    一条卡住的 job 反复收敛。
    """
    import boto3 as b3
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    jid = _ready_job()
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)

    row = b3.client("dynamodb").get_item(
        TableName="site-deploy-jobs",
        Key={"job_id": {"S": common.deploy_lease_key("demo-abc123")}})["Item"]
    assert row["holder_job_id"]["S"] == jid
    for forbidden in ("site_id", "owner", "status", "created_at"):
        assert forbidden not in row, (
            f"租约行带了 {forbidden}——它会进 GSI/被 sweeper 当成 job")
    # 控制台的部署历史查的是 site-index：那里不该出现租约行
    hist = b3.resource("dynamodb").Table("site-deploy-jobs").query(
        IndexName="site-index",
        KeyConditionExpression=b3.dynamodb.conditions.Key("site_id").eq(
            "demo-abc123"))
    assert [i["job_id"] for i in hist["Items"]] == [jid]


def test_lease_does_not_lock_the_site_when_start_execution_failed(aws, monkeypatch):
    """`start_execution` 失败 ⇒ job 退回 PENDING ⇒ 租约必须**不再**挡住这个站点。

    这是我给租约设计自己挖的坑，必须钉住：`_rollback_job_to_pending` 把 job 退回
    PENDING 是为了让用户重试，而 PENDING 既不是终态、也不会被 reconcile 的 sweeper
    收敛（它只扫 RUNNING）。如果租约的判据写成"非终态即忙"，这个 job 就会**永远**
    持有租约 ⇒ 该站点再也无法部署。

    所以判据是"持有者还是 RUNNING 吗"。红的条件：换回按终态判之后这条必红。
    """
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    doomed, retry = _ready_job(), _ready_job()

    import botocore.exceptions
    sfn = MagicMock()
    sfn.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionLimitExceeded"}}, "StartExecution")
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(botocore.exceptions.ClientError):
            server.do_confirm_upload("a@x.com", doomed)
    assert common.get_job(doomed)["status"] == "PENDING", "前提不成立：没退回 PENDING"

    # 换一个 job 重新部署这个站点：不该被那份陈旧租约挡住
    with patch.object(server, "_sfn", return_value=MagicMock()):
        assert server.do_confirm_upload("a@x.com", retry)["status"] == "RUNNING"


def test_same_job_can_retry_confirm_after_a_failed_start(aws, monkeypatch):
    """同一个 job 重试 confirm_upload 时，自己那份租约不能挡住自己。"""
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    import botocore.exceptions
    jid = _ready_job()
    sfn = MagicMock()
    sfn.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionLimitExceeded"}}, "StartExecution")
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(botocore.exceptions.ClientError):
            server.do_confirm_upload("a@x.com", jid)
    with patch.object(server, "_sfn", return_value=MagicMock()):
        assert server.do_confirm_upload("a@x.com", jid)["status"] == "RUNNING"


def test_takeover_plan_is_rejected_if_the_holder_becomes_running(aws, monkeypatch):
    """"我读到持有者是陈旧的"必须**进最终事务**，读一下是不够的。

    这是 Codex 2026-08-18 P1-1（check-then-act TOCTOU，实测复现）：
    contender B 读到持有者 H 是 PENDING、判它陈旧；在 B 提交之前 H 重试成功
    （自己变回 RUNNING 并续上租约）。只按 `holder_job_id = H` 判的顶替此刻照样
    成立——从一个**已经 RUNNING** 的持有者手里把租约抢走，两次部署并行。

    修法是顶替时附一条对 H 的 ConditionCheck（`#s <> RUNNING`），与租约切换
    同一笔提交。本用例按同一交错执行：B 的计划先生成、H 后变 RUNNING、
    B 再提交 ⇒ 必须被取消。
    """
    import boto3 as b3
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    h, b = _ready_job(), _ready_job()

    # H 拿到租约后 start_execution 失败 ⇒ 回滚到 PENDING（持有租约的陈旧持有者）
    import botocore.exceptions
    sfn = MagicMock()
    # 确定拒绝（ClientError）才会回滚成 PENDING——本用例要的就是 PENDING 持有者
    sfn.start_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionLimitExceeded"}}, "StartExecution")
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(botocore.exceptions.ClientError):
            server.do_confirm_upload("a@x.com", h)
    assert common.get_job(h)["status"] == "PENDING"

    # B 读租约并生成计划：此刻 H 是 PENDING ⇒ 被判为陈旧持有者
    plan_b = common.plan_deploy_lease("demo-abc123", b)
    assert len(plan_b) == 2, "顶替陈旧持有者时必须附持有者状态的 ConditionCheck"

    # H 在 B 提交之前重试成功：自己变回 RUNNING 并续上租约
    with patch.object(server, "_sfn", return_value=MagicMock()):
        assert server.do_confirm_upload("a@x.com", h)["status"] == "RUNNING"
    assert common.read_deploy_lease("demo-abc123") == h

    # B 现在才提交它早已生成的计划 ⇒ 必须被取消，租约仍归 H
    ddb = b3.client("dynamodb")
    with pytest.raises(Exception) as ei:
        ddb.transact_write_items(TransactItems=plan_b)
    assert "TransactionCanceled" in str(type(ei.value)) + str(ei.value)
    assert common.read_deploy_lease("demo-abc123") == h, \
        "从一个已经 RUNNING 的持有者手里把租约抢走了——两次部署会并行"


def test_undeploy_is_rejected_while_a_deploy_is_running(aws, monkeypatch):
    """部署 RUNNING 期间下线必须被拒（Codex 2026-08-18 P1-2）。

    不拒的话：undeploy 删掉路由/函数/前端并清掉租约，而那次部署的状态机还在跑，
    后续步骤会把刚下线的站点**重新建出来**（复活）——且租约一清，第三次部署也能
    开跑。
    """
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    jid = _ready_job()
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)          # 部署 RUNNING，持有租约

    with pytest.raises(server.AlreadyStarted, match="正在进行|刚刚开始"):
        server.do_undeploy("a@x.com", "demo-abc123")


def test_deploy_is_rejected_while_an_undeploy_is_running(aws, monkeypatch):
    """反方向同样成立：下线进行中，新部署必须被拒。"""
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    with patch.object(server, "_lambda", return_value=MagicMock()):
        out = server.do_undeploy("a@x.com", "demo-abc123")
    jid = _ready_job()
    with pytest.raises(server.AlreadyStarted, match="正在进行"):
        with patch.object(server, "_sfn", return_value=MagicMock()):
            server.do_confirm_upload("a@x.com", jid)
    # 下线 job 终态后（undeploy Lambda 写 DELETED），部署恢复可用
    import common
    common.update_job(out["job_id"], status="DELETED")
    with patch.object(server, "_sfn", return_value=MagicMock()):
        assert server.do_confirm_upload("a@x.com", jid)["status"] == "RUNNING"


def test_undeploy_job_is_running_with_kind_from_creation(aws, monkeypatch):
    """undeploy 的 job 必须以 RUNNING + kind=undeploy **落库**，不是等 Lambda 运行时补。

    RUNNING：租约判"持有者还在跑吗"看的是它——建成 PENDING 就留出一个租约形同
    虚设的窗口。kind：异步 invoke 的事件被丢弃时 Lambda 根本没跑，job 没有 kind
    ⇒ sweeper 把它当 deploy 去 DescribeExecution ⇒ 永远 orphan、永远不收敛。
    """
    import common
    import server
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    with patch.object(server, "_lambda", return_value=MagicMock()):
        out = server.do_undeploy("a@x.com", "demo-abc123")
    job = common.get_job(out["job_id"])
    assert job["status"] == "RUNNING"
    assert job.get("kind") == "undeploy"
    assert common.read_deploy_lease("demo-abc123") == out["job_id"], \
        "undeploy 没有持有租约——它与部署的互斥就不存在"


def test_uncertain_start_error_keeps_running_and_holds_the_lease(aws, monkeypatch):
    """StartExecution **网络错误（结果不确定）** ⇒ 不回滚、保持 RUNNING、租约继续
    挡住第二次部署（Codex 2026-08-18 R4 P1-2）。

    "不确定"的含义：请求可能已到 SFN、执行在跑、只是响应丢了。此时回滚成
    PENDING，租约会把持有者当陈旧放行 ⇒ 第二次部署与那条**可能活着**的执行并行
    ——正是租约要消灭的交错。收敛交给 sweeper：按确定性 name 查证
    ExecutionDoesNotExist 后判 FAILED（≤45 分钟），届时租约自动放开。

    红的条件：job 被回滚成 PENDING、或第二次部署被放行。
    """
    import common
    import server
    monkeypatch.setenv("STATE_MACHINE_ARN",
                       "arn:aws:states:us-east-1:1:stateMachine:sm")
    first, second = _ready_job(), _ready_job()
    sfn = MagicMock()
    sfn.start_execution.side_effect = ConnectionError("网络中断（注入）")
    with patch.object(server, "_sfn", return_value=sfn):
        with pytest.raises(RuntimeError, match="结果不确定"):
            server.do_confirm_upload("a@x.com", first)

    assert common.get_job(first)["status"] == "RUNNING", \
        "结果不确定却回滚了——执行可能活着，租约不该放"
    with pytest.raises(server.AlreadyStarted, match="正在进行"):
        with patch.object(server, "_sfn", return_value=MagicMock()):
            server.do_confirm_upload("a@x.com", second)


def test_uncertain_undeploy_invoke_error_keeps_running(aws):
    """异步 undeploy invoke 网络错误（结果不确定）⇒ 不写 FAILED、租约不放。

    事件可能已被 Lambda 受理、后台正在删路由/函数/数据；此刻写 FAILED 就是把
    租约放给新部署，让它与一场进行中的下线并行。sweeper 的 20 分钟 undeploy
    阈值负责"确实没起来"那一侧的收敛（kind 建库时已写，收敛必达）。
    """
    import common
    import server
    server.common.upsert_site("demo-abc123", owner="o@x.com", status="ACTIVE",
                              tier="fullstack-nosql")
    lam = MagicMock()
    lam.invoke.side_effect = ConnectionError("网络中断（注入）")
    with patch.object(server, "_lambda", return_value=lam):
        with pytest.raises(RuntimeError, match="结果不确定"):
            server.do_undeploy("o@x.com", "demo-abc123")
    jobs = common.list_jobs_by_site("demo-abc123")
    assert jobs and jobs[0]["status"] == "RUNNING", (
        f"job 是 {jobs[0]['status'] if jobs else '缺失'}——不确定时写终态"
        "就是把租约放给新部署，与进行中的下线并行")
    assert common.read_deploy_lease("demo-abc123") == jobs[0]["job_id"]
