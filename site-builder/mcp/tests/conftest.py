import json
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "deployer" / "functions"))

ENV = {"JOBS_TABLE": "site-deploy-jobs", "SITES_TABLE": "site-sites",
       "ARTIFACTS_BUCKET": "site-artifacts-1", "FRONTEND_BUCKET": "site-frontend-1",
       "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
       "RUNTIME_BOUNDARY_ARN": "arn:aws:iam::1:policy/site-runtime-boundary",
       "ACCOUNT_ID": "1",
       "ADMINS_TABLE": "site-admins",
       "OPS_LOG_TABLE": "site-ops-log",
       "PACKAGE_PROJECT": "site-package", "DSQL_ENDPOINT": "x.dsql.us-east-1.on.aws",
       "AWS_DEFAULT_REGION": "us-east-1",
       "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}


def make_token(claims: dict) -> str:
    """伪造一个 JWT（只有 payload 有意义）。

    网关已验过签名，`server._caller_email()` 只解 payload——所以单测不需要
    真签名，但**必须是三段**（实现按 `.` 切成 3 段才解析）。
    """
    import base64
    import json as _json

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return (b64(_json.dumps({"alg": "RS256"}).encode()) + "." +
            b64(_json.dumps(claims).encode()) + ".sig")


def with_auth(monkeypatch, token: str, **extra_headers: str):
    """伪造 FastMCP 的请求上下文。

    `extra_headers` 的键按 starlette 的行为**小写化**：真实请求里
    `dict(request.headers)` 拿到的键全是小写，测试若给大写键，实现用小写取值
    就会永远取不到——那会让"带头也拒"的用例以假通过的方式变绿。
    """
    import server

    headers = {"authorization": f"Bearer {token}"}
    headers.update({k.lower(): v for k, v in extra_headers.items()})

    class _Req:
        pass

    _Req.headers = headers

    class _Ctx:
        class request_context:
            request = _Req()

    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx())


@pytest.fixture
def aws(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(TableName="site-deploy-jobs",
                         KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[
                             {"AttributeName": "job_id", "AttributeType": "S"},
                             {"AttributeName": "owner", "AttributeType": "S"},
                             {"AttributeName": "site_id", "AttributeType": "S"},
                             {"AttributeName": "created_at", "AttributeType": "S"}],
                         GlobalSecondaryIndexes=[{
                             "IndexName": "owner-index",
                             "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"},
                                           {"AttributeName": "created_at", "KeyType": "RANGE"}],
                             "Projection": {"ProjectionType": "ALL"}}, {
                             "IndexName": "site-index",
                             "KeySchema": [{"AttributeName": "site_id", "KeyType": "HASH"},
                                           {"AttributeName": "created_at", "KeyType": "RANGE"}],
                             "Projection": {"ProjectionType": "ALL"}}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-sites",
                         KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[
                             {"AttributeName": "site_id", "AttributeType": "S"},
                             {"AttributeName": "owner", "AttributeType": "S"}],
                         GlobalSecondaryIndexes=[{
                             "IndexName": "owner-index",
                             "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
                             "Projection": {"ProjectionType": "ALL"}}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="routing",
                         KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-admins",
                         KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "email",
                                                "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        # Task 8 的 ops-log 落点在 permissions.py，MCP 的权限工具会走到它
        ddb.create_table(TableName="site-ops-log",
                         KeySchema=[{"AttributeName": "target", "KeyType": "HASH"},
                                    {"AttributeName": "ts_actor", "KeyType": "RANGE"}],
                         AttributeDefinitions=[
                             {"AttributeName": "target", "AttributeType": "S"},
                             {"AttributeName": "ts_actor", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        s3c = boto3.client("s3", region_name="us-east-1")
        for b in ("site-artifacts-1", "site-frontend-1"):
            s3c.create_bucket(Bucket=b)
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="site-runtime-boundary",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
        yield
