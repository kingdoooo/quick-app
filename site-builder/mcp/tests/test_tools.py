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
