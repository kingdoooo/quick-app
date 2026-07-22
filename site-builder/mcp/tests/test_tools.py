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
    jid = common.create_job("a@x.com", "demo-abc123")
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=b"zip")
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)
        with pytest.raises(server.AlreadyStarted):  # 条件更新拦住第二次
            server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_checks_owner(aws):
    import server, common
    jid = common.create_job("a@x.com", "demo-abc123")
    with pytest.raises(server.NotOwner):
        server.do_confirm_upload("b@x.com", jid)


def test_confirm_upload_missing_zip_errors(aws):
    import server, common
    jid = common.create_job("a@x.com", "demo-abc123")
    with pytest.raises(server.UploadMissing):
        server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_oversize_zip_rejected(aws, monkeypatch):
    import server, common
    jid = common.create_job("a@x.com", "demo-abc123")
    head = MagicMock()
    head.head_object.return_value = {"ContentLength": 51 * 1024 * 1024}
    head.exceptions = boto3.client("s3").exceptions
    with patch.object(server, "_s3", return_value=head):
        with pytest.raises(server.UploadTooLarge):
            server.do_confirm_upload("a@x.com", jid)


def test_get_status_scoped_to_owner(aws):
    import server, common
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
