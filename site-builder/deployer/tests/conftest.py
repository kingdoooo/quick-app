import json
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "functions"))

ENV = {"JOBS_TABLE": "site-deploy-jobs", "SITES_TABLE": "site-sites",
       "ARTIFACTS_BUCKET": "site-artifacts-1", "FRONTEND_BUCKET": "site-frontend-1",
       "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
       "RUNTIME_BOUNDARY_ARN": "arn:aws:iam::1:policy/site-runtime-boundary",
       "ACCOUNT_ID": "1",
       "ADMINS_TABLE": "site-admins",
       "OPS_LOG_TABLE": "site-ops-log",
       "SESSION_CODES_TABLE": "site-session-codes",
       "API_KEYS_TABLE": "site-api-keys",
       "PACKAGE_PROJECT": "site-package", "DSQL_ENDPOINT": "x.dsql.us-east-1.on.aws",
       "STATE_MACHINE_ARN": "arn:aws:states:us-east-1:1:stateMachine:site-deploy",
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
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
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
        # 二期 M4：API Key。形态与 infra/app.py 的 ApiKeys 表、以及
        # key-proxy/tests/conftest.py 的同名表**必须一致**（PK key_hash +
        # 两个 GSI）——keystore 是这张表的唯一访问层，两个包各跑自己的用例，
        # 夹具形态漂移会让一侧绿另一侧红，而真机只有一张表。
        ddb.create_table(TableName="site-api-keys",
                         KeySchema=[{"AttributeName": "key_hash", "KeyType": "HASH"}],
                         AttributeDefinitions=[
                             {"AttributeName": "key_hash", "AttributeType": "S"},
                             {"AttributeName": "email", "AttributeType": "S"},
                             {"AttributeName": "key_id", "AttributeType": "S"}],
                         GlobalSecondaryIndexes=[{
                             "IndexName": "email-index",
                             "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}],
                             "Projection": {"ProjectionType": "ALL"}}, {
                             "IndexName": "keyid-index",
                             "KeySchema": [{"AttributeName": "key_id", "KeyType": "HASH"}],
                             "Projection": {"ProjectionType": "ALL"}}],
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
