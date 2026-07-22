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
    assert '"v@x.com"' in item["allowed_users"]["S"]
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
