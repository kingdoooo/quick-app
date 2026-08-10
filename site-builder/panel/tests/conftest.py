import json
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

PANEL = Path(__file__).parent.parent
sys.path.insert(0, str(PANEL))
sys.path.insert(0, str(PANEL.parent / "deployer" / "functions"))
# 测试期直接 import session（部署时由 deploy_panel.py 复制进包）。
# **能 import 不等于部署产物里有它**——复制清单由 Task 10 的 contract test 盯。
sys.path.insert(0, str(PANEL.parent / "auth"))

ENV = {"JOBS_TABLE": "site-deploy-jobs", "SITES_TABLE": "site-sites",
       "ARTIFACTS_BUCKET": "site-artifacts-1", "FRONTEND_BUCKET": "site-frontend-1",
       "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
       "RUNTIME_BOUNDARY_ARN": "arn:aws:iam::1:policy/site-runtime-boundary",
       "ACCOUNT_ID": "1",
       "ADMINS_TABLE": "site-admins",
       "OPS_LOG_TABLE": "site-ops-log",
       "SESSION_CODES_TABLE": "site-session-codes",
       "JWT_SECRET_PARAM": "/site-builder/jwt-secret",
       "CONSOLE_HOST": "console.example.com",
       # Edge 执行角色的 RoleId：handler 用它确认调用者真是 Edge（P1-1）。
       # 与 test_handler.EDGE_ROLE_ID 必须一致。
       "EDGE_ROLE_ID": "AROAEDGEROLEIDXXXXXX",
       "UNDEPLOY_FN": "site-deployer-undeploy",
       "PACKAGE_PROJECT": "site-package", "DSQL_ENDPOINT": "x.dsql.us-east-1.on.aws",
       "AWS_DEFAULT_REGION": "us-east-1",
       "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}


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
                         AttributeDefinitions=[{"AttributeName": "subdomain",
                                                "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-admins",
                         KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "email",
                                                "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-ops-log",
                         KeySchema=[{"AttributeName": "target", "KeyType": "HASH"},
                                    {"AttributeName": "ts_actor", "KeyType": "RANGE"}],
                         AttributeDefinitions=[
                             {"AttributeName": "target", "AttributeType": "S"},
                             {"AttributeName": "ts_actor", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-session-codes",
                         KeySchema=[{"AttributeName": "jti", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "jti",
                                                "AttributeType": "S"}],
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


@pytest.fixture
def secret(monkeypatch):
    """把 panel 的密钥读取指向测试向量的固定密钥。

    直接 patch `console_session._secret`（而不是往环境变量里塞明文）：
    生产路径就是"环境变量只有参数名、运行时从 SSM 读"，把明文放进环境
    会让测试与生产形态不一致，也违反本项目"明文不进环境变量"的约束。
    _secret 自身的行为（读 SSM、TTL 缓存）另有专门用例覆盖。
    """
    import console_session
    from upgrade_code_vectors import SECRET
    monkeypatch.setattr(console_session, "_secret", lambda: SECRET)
    return SECRET
