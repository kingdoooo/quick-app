import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

KEY_PROXY = Path(__file__).parent.parent
sys.path.insert(0, str(KEY_PROXY))
# keygen / edge_caller / ops_log 的物理落点是 deployer/functions（deployer 的
# Lambda 打包整个目录，panel 与 key-proxy 各自在构建时复制单个文件出来）。
# **能 import 不等于部署产物里有它**——复制清单由 Task 10 的 contract test 盯。
sys.path.insert(0, str(KEY_PROXY.parent / "deployer" / "functions"))

ENV = {"API_KEYS_TABLE": "site-api-keys",
       "ROUTING_TABLE": "routing",
       "AGENTCORE_ENDPOINT": "https://agentcore.example.com/mcp",
       "COGNITO_DOMAIN": "auth.example.com",
       "MACHINE_CLIENT_ID": "machineclientid",
       # 环境里只放**参数名**，明文密钥运行时从 SSM 读（与 panel 同约定）。
       "MACHINE_SECRET_PARAM": "/site-builder/machine-client-secret",
       # client_credentials 必须显式带 scope（Codex P1-2a）：Cognito 在缺 scope
       # 时发的 token 不含所需 scope，网关侧 403 而非 400，排查方向会被带偏。
       "MACHINE_SCOPE": "site-builder/invoke",
       # Edge 执行角色的 RoleId：handler 用它确认调用者真是 Edge（P1-1）。
       "EDGE_ROLE_ID": "AROA" + "KEYPROXYROLEIDXXXX",
       "AWS_DEFAULT_REGION": "us-east-1",
       "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}


@pytest.fixture
def aws(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        # PK 是 key_hash（不是 key_id）：库被读走时攻击者只拿到哈希。
        # 两个 GSI 都要建——email-index 给"按人列 Key"，keyid-index 给吊销
        # （DELETE 拿到的是 key_id，而 PK 是 key_hash）。
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
        ddb.create_table(TableName="routing",
                         KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain",
                                                "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        yield
