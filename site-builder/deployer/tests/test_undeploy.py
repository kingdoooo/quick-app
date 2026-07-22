import boto3
from unittest.mock import MagicMock, patch


def test_undeploy_cleans_route_frontend_lambda(aws):
    import undeploy, common
    jid = common.create_job("a@x.com", "hello-x1")
    common.upsert_site("hello-x1", owner="a@x.com", status="ACTIVE")
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-hello-x1"}, "site_id": {"S": "hello-x1"},
        "static_prefix": {"S": "sites/hello-x1"}, "api_target": {"S": ""},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "a@x.com"}})
    boto3.client("s3").put_object(Bucket="site-frontend-1",
                                  Key="sites/hello-x1/index.html", Body=b"x")
    lam = MagicMock()
    lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
    with patch.object(undeploy, "_lambda", return_value=lam):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert "Item" not in ddb.get_item(TableName="routing",
                                      Key={"subdomain": {"S": "app-hello-x1"}})
    assert boto3.client("s3").list_objects_v2(
        Bucket="site-frontend-1", Prefix="sites/hello-x1/")["KeyCount"] == 0
    lam.delete_function.assert_called_once_with(FunctionName="site-hello-x1")
    assert common.get_site("hello-x1")["status"] == "DELETED"
