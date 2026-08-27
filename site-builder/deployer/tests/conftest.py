import json
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "functions"))


# ---- 扫全仓库的"唯一定义"守卫共用的一条豁免：部署窗口里的逐字节副本 ----
#
# panel / mcp / key-proxy 的部署脚本会把 `deployer/functions/` 下的共享模块
# （`common.py` / `permissions.py` / `ops_log.py` …；panel 另从 `auth/` 取
# `session.py`）**复制进自己的包目录**，打完包在 finally 里删掉
# （deploy_panel.py `_build_zip` / deploy_key_proxy.py / deploy_agentcore.py）。
# MCP 那一次的窗口覆盖整个 buildx + push，是分钟级的。
# 那期间，任何扫描整个 `site-builder/` 的守卫都会把副本报成"第四份手抄"。
#
# **必须按内容豁免，不能按路径豁免。** 一条 `panel/common.py 不算` 的路径豁免会把
# 一份**真的**手抄一起放过——而"手抄不会再回来"正是这些守卫存在的全部理由，
# 给它们加路径豁免等于把洞开在守卫自己身上。逐字节相同的副本里不可能藏着第二个
# 实现；有人动它一个字节（手抄的意义就在于要改），守卫立刻恢复。
#
# 如实记下残留缺口：一份**从未改动**的副本被提交进仓库时，本豁免看不见它——
# 它与部署窗口里的临时文件在文件系统上完全不可区分。它一旦被改动就会被咬住，
# 而产物层面另有 `verify_deployed_components.py` 逐字节比对已部署的那一份。
_COPY_SOURCE_DIRS = (Path(__file__).parents[1] / "functions",
                     Path(__file__).parents[2] / "auth")


def is_transient_deploy_copy(path, *, sources=_COPY_SOURCE_DIRS) -> bool:
    """`path` 是不是某个共享模块**逐字节相同**的副本（部署脚本的临时产物）。

    真源自己返回 False：它们不是副本，而"唯一定义在哪"必须由各守卫按路径点名，
    不能靠这条内容比较悄悄替代掉。
    """
    path = Path(path)
    if path.parent.resolve() in {d.resolve() for d in sources if d.exists()}:
        return False
    for d in sources:
        src = d / path.name
        if src.exists() and src.read_bytes() == path.read_bytes():
            return True
    return False


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


# ---------------------------------------------------------------------------
# 把**过滤之前**的完整收集清单留一份给守卫用。
#
# `-k` / `-m` 的 deselect 就发生在 `pytest_collection_modifyitems` 里（pytest 自己的实现
# 就地删 `items`），所以 `request.session.items` 拿到的是**过滤之后**的列表——实测：
# 一个 3 条用例的文件带 `-k alpha` 跑，`session.items` 只剩 1 条。
# （**别用文件名里含关键词的文件去验这件事**：`-k` 也匹配模块名，那样三条会全被选中，
#   看起来像"没被过滤"。我就是这么误判过一次。）
#
# 有守卫要断言"pytest 到底会不会收集某几条用例"（见
# `test_verify_account_trust_boundary.py::test_blind_spot_tests_exist_and_will_actually_run`），
# 而变形 harness 每条变形都用 `-k` 跑。没有这份完整清单，那道守卫在带 `-k` 时必然假红。
# `tryfirst=True` 是必须的：要抢在 pytest 自己那个删元素的实现之前。
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    session._unfiltered_collected_items = list(items)
