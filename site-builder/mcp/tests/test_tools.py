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
    """StartExecution 失败 → job 必须退回 PENDING，用户可重试。

    不回滚的话 job 永久停在 RUNNING 而没有 execution 在跑，重试被判
    AlreadyStarted，用户只能轮询一个永不推进的任务。
    """
    import boto3 as _b3
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
    boom.start_execution.side_effect = RuntimeError("SFN 挂了")
    with patch.object(server, "_sfn", return_value=boom):
        with pytest.raises(RuntimeError):
            server.do_confirm_upload("o@x.com", jid)
    assert common.get_job(jid)["status"] == "PENDING", "没回滚 → 永久卡死"
    # 重试必须能真正跑通（这才是回滚的目的）
    ok = MagicMock()
    with patch.object(server, "_sfn", return_value=ok):
        assert server.do_confirm_upload("o@x.com", jid)["status"] == "RUNNING"
    ok.start_execution.assert_called_once()


def test_confirm_upload_treats_existing_execution_as_success(aws, monkeypatch):
    """ExecutionAlreadyExists 说明上次其实起成功了：按成功返回且**不**回滚。

    同 name + 同 input 就是同一次部署（STANDARD 工作流幂等）。若这里误回滚，
    会把一个真在跑的部署改回 PENDING。
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
        assert server.do_confirm_upload("o@x.com", jid)["status"] == "RUNNING"
    # 关键：状态留在 RUNNING（真在跑），没有被回滚成 PENDING
    assert common.get_job(jid)["status"] == "RUNNING"


def test_rollback_does_not_touch_advanced_job(aws):
    """回滚条件必须只匹配"刚置 RUNNING/queued"：已推进的任务不能被踩回 PENDING。"""
    import common
    import server
    jid = common.create_job("o@x.com", "demo-abc123")
    common.update_job(jid, status="RUNNING", phase="validate")   # SFN 已在跑
    server._rollback_job_to_pending(jid)
    job = common.get_job(jid)
    assert job["status"] == "RUNNING" and job["phase"] == "validate"
