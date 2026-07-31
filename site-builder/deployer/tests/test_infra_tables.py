"""CDK 模板断言：二期新增的表与索引必须存在，且 step Lambda 拿到 ADMINS_TABLE。

**opt-in（默认 skip）**：本文件要 synth 整个 stack，而 step Lambda 用
Code.from_asset(bundling=...) —— synth 阶段就会起 Docker 装 psycopg。
所以默认不跑，需要时显式开：

    # aws_cdk 只装在 infra/.venv（deployer/.venv 只有 boto3/pytest/moto）；不带
    # PYTHONPATH 桥接时"依赖缺失"会被静默变成 skip——看起来绿了其实什么都没断言。
    PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" \
      SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q

日常回归靠"部署后 describe-table 真机核对"（见本任务 Step 5 与 Task 9）。
"""
import os
import sys
from pathlib import Path

import pytest

INFRA = Path(__file__).parents[1] / "infra"
CONFIG = Path(__file__).parents[2] / "config.ini"

pytestmark = [
    pytest.mark.skipif(os.environ.get("SB_CDK_TESTS") != "1",
                       reason="需 SB_CDK_TESTS=1（synth 会起 Docker 做 bundling）"),
    pytest.mark.skipif(not CONFIG.exists(),
                       reason="需要 site-builder/config.ini"),
]


@pytest.fixture(scope="module")
def template():
    # 显式 opt-in 了就不许再静默 skip：importorskip 会把"aws_cdk 装错 venv"
    # 伪装成 skip，和默认不跑长得一样，等于这次运行白跑。上面的 pytestmark
    # 已经管了 SB_CDK_TESTS 未设的情况，所以这里只会在故意开跑时触发。
    try:
        import aws_cdk
        from aws_cdk import assertions
    except ImportError:
        pytest.fail("SB_CDK_TESTS=1 但 aws_cdk 不可用——用 docstring 里的 "
                    "PYTHONPATH 桥接命令跑，否则这次运行什么都没验证")
    sys.path.insert(0, str(INFRA))
    import importlib
    mod = importlib.import_module("app")
    app = aws_cdk.App()
    stack = mod.SiteDeployerStack(app, "TestStack")
    return assertions.Template.from_stack(stack)


def test_sites_table_has_owner_index(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "TableName": "site-sites",
        "GlobalSecondaryIndexes": [{
            "IndexName": "owner-index",
            "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"}}]})


def test_admins_table_exists(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "TableName": "site-admins",
        "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}]})


def test_admins_table_is_retained(template):
    # RETAIN 是本表唯一有意为之、且运维上要命的属性（名单误删 = 平台失去管理
    # 入口）。DeletionPolicy 是 resource 级字段，has_resource_properties 看不到
    # ——必须用 has_resource，否则日后有人改成 DESTROY 全部测试照样绿。
    template.has_resource("AWS::DynamoDB::Table", {
        "DeletionPolicy": "Retain",
        "Properties": {"TableName": "site-admins"}})


def test_step_lambdas_get_admins_table_env(template):
    # table_name 在模板里是 {"Ref": <Admins 逻辑 ID>}（CFN 部署时才解析成
    # site-admins 字面量），和既有 JOBS_TABLE/SITES_TABLE 同形——所以先按
    # TableName 反查逻辑 ID，再断言 env 指向它，别断言字面量。
    admins_lid = next(lid for lid, res in
                      template.find_resources("AWS::DynamoDB::Table").items()
                      if res["Properties"]["TableName"] == "site-admins")
    template.has_resource_properties("AWS::Lambda::Function", {
        "FunctionName": "site-deployer-register_route",
        "Environment": {"Variables": {"ADMINS_TABLE": {"Ref": admins_lid}}}})
