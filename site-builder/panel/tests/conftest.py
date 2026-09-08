import json
import sys
import textwrap
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

import upgrade_code_vectors as v  # noqa: E402  （本文件所在目录已在 sys.path）

# RS 形态的 `[SessionKeys]`（spec §11.6）：两个 family 各一把 current，previous 留空。
#
# **两个 deploy 用例文件一律按这份判，不读真 config.ini**：3c-final 的 RS 形态里那一段是
# KMS key ARN + 公钥指纹，只有部署过 deployer 栈的账号才有，而且是真实账号值（不许进 tracked
# 文件、也不许进断言）。这份用 upgrade_code_vectors 的三把测试密钥现算，所以断言能逐字比对
# ARN 与指纹，且在任何机器上、config 处于任何状态时都成立。
# site 那一节留着是为了让"panel 不许碰 site 的 key"这条断言有东西可以对照——
# 配置里有它、角色清单里必须没有。
RS_SESSION_KEYS = textwrap.dedent(f"""
    [SessionKeys]
    site_current = {v.SITE_KID}
    site_previous =
    console_current = {v.CONSOLE_KID}
    console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:{v.SITE_KID}]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_KEY)}

    [SessionKey:{v.CONSOLE_KID}]
    alg = RS256
    key_arn = {v.KEY_ARN[v.CONSOLE_KID]}
    spki_sha256 = {v.spki_hex(v.CONSOLE_KEY)}
""")


@pytest.fixture
def rs_config(tmp_path, monkeypatch):
    """把 `deploy_panel` 读 `[SessionKeys]` 的那个路径指到临时 RS config 上。

    只换 `CFG_PATH`（`load_session_keys` 的实参），**不换 `HERE`**：`HERE` 还决定复制清单的
    源目录、`frontend/` 的位置与 `REQUIREMENTS`，整体挪过去会让打包/前端那批用例去读一个空目录。

    **不 autouse**：两个 deploy 用例文件各自声明一个 autouse 包装器显式打开它（见那两个文件顶部），
    别在这里 autouse——那会让每条 panel 用例都 import deploy_panel（顺带改 sys.path）。
    """
    import deploy_panel as dp
    p = tmp_path / "config.ini"
    p.write_text(RS_SESSION_KEYS)
    monkeypatch.setattr(dp, "CFG_PATH", p)
    return p

ENV = {"JOBS_TABLE": "site-deploy-jobs", "SITES_TABLE": "site-sites",
       "ARTIFACTS_BUCKET": "site-artifacts-1", "FRONTEND_BUCKET": "site-frontend-1",
       "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
       "RUNTIME_BOUNDARY_ARN": "arn:aws:iam::1:policy/site-runtime-boundary",
       "ACCOUNT_ID": "1",
       "ADMINS_TABLE": "site-admins",
       "OPS_LOG_TABLE": "site-ops-log",
       "SESSION_CODES_TABLE": "site-session-codes",
       # 二期 M4：keystore 读它（api.py 经 keystore 访问这张表）。
       # 名字与 deploy_panel.lambda_environment() 必须一致，由
       # test_deploy_panel_contract 的推导式断言交叉核对。
       "API_KEYS_TABLE": "site-api-keys",
       # 二期 M5：访问明细与每日聚合。analytics.py 读它们（api.py 经 analytics
       # 访问这两张表），名字同样必须与下发给 Lambda 的环境变量一致。
       "ACCESS_EVENTS_TABLE": "site-access-events",
       "ACCESS_DAILY_TABLE": "site-access-daily",
       # 3c-final：console family 的 kid 清单（kid / alg / role / key_arn / spki_sha256，
       # **没有任何密钥材料**——公钥运行时经 kms:GetPublicKey 取、与指纹核对后才用）。
       # 形态与 deploy_panel.lambda_environment() 一致；**不含 site family**（panel 不得持它）。
       "SESSION_KEYS_JSON": v.session_keys_json((v.CONSOLE_KID, "current")),
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
        # 二期 M4：API Key。形态与 `deployer/infra/app.py` 的 ApiKeys 表、
        # `deployer/tests/conftest.py`、`key-proxy/tests/conftest.py` 的同名表
        # **必须一致**（PK key_hash + email-index + keyid-index）——真机只有
        # 一张表，夹具形态漂移会让一侧绿另一侧红。
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
        # 二期 M5：形态与 `deployer/infra/app.py` 的两张访问表、以及
        # `deployer/tests/test_analytics.py` 的同名夹具**必须一致**
        # （events: site_date + ts_id；daily: site_id + date）——真机只有一套表，
        # 夹具形态漂移会让一侧绿另一侧红。
        ddb.create_table(TableName="site-access-events",
                         KeySchema=[{"AttributeName": "site_date", "KeyType": "HASH"},
                                    {"AttributeName": "ts_id", "KeyType": "RANGE"}],
                         AttributeDefinitions=[
                             {"AttributeName": "site_date", "AttributeType": "S"},
                             {"AttributeName": "ts_id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-access-daily",
                         KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"},
                                    {"AttributeName": "date", "KeyType": "RANGE"}],
                         AttributeDefinitions=[
                             {"AttributeName": "site_id", "AttributeType": "S"},
                             {"AttributeName": "date", "AttributeType": "S"}],
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
def keys(monkeypatch):
    """把 panel 的 KMS 边界换成 vectors 的替身：公钥与签名都由 CONSOLE_KEY 算。返回 FakeKms 供用例看调用。

    patch 的是 `_kms()`（而不是往环境变量里塞密钥材料）：生产路径就是"环境变量只有 kid /
    key_arn / spki_sha256，公钥运行时取、指纹核对后才用"，3c-final 起 panel 连一处 SSM
    读取都没有。`_reset_signing()` 前后各一次——容器级缓存（公钥加载器与 KmsSigner）
    不清掉的话，上一条用例的替身会漏到下一条。
    """
    import console_session
    kms = v.FakeKms()
    console_session._reset_signing()
    monkeypatch.setattr(console_session, "_kms", lambda: kms)
    yield kms
    console_session._reset_signing()
