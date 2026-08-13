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


def test_ops_log_and_session_codes_tables(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    by_name = {t["Properties"]["TableName"]: t
               for t in tables.values()
               if isinstance(t["Properties"].get("TableName"), str)}
    ops = by_name["site-ops-log"]
    # 审计表误删会丢合规证据——与 site-admins 同为 RETAIN
    assert ops["DeletionPolicy"] == "Retain"
    assert ops["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
    codes = by_name["site-session-codes"]
    assert codes["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"


def test_api_keys_table_pk_is_key_hash_with_both_gsis(template):
    """二期 M4：PK 必须是 key_hash，且两个 GSI 都在。

    PK 不是 key_id 是安全属性（spec §5.1）：库被读走时攻击者只拿到哈希。
    keyid-index 不是"优化"而是**吊销路径的前提**——DELETE 拿到的是 key_id，
    没有它就只能全表 Scan，而吊销必须先查到该行 email 与调用者比对。
    """
    tables = template.find_resources("AWS::DynamoDB::Table")
    keys_tbl = next(t for t in tables.values()
                    if t["Properties"].get("TableName") == "site-api-keys")
    assert keys_tbl["Properties"]["KeySchema"] == [
        {"AttributeName": "key_hash", "KeyType": "HASH"}], \
        "PK 必须是 key_hash——换成 key_id 等于把可用凭证的标识符当主键"
    idx = {g["IndexName"]: g
           for g in keys_tbl["Properties"]["GlobalSecondaryIndexes"]}
    assert set(idx) == {"email-index", "keyid-index"}, idx
    assert idx["email-index"]["KeySchema"] == [
        {"AttributeName": "email", "KeyType": "HASH"}]
    assert idx["keyid-index"]["KeySchema"] == [
        {"AttributeName": "key_id", "KeyType": "HASH"}]


def test_api_keys_table_is_retained(template):
    # 凭证表误删 = 全体 Key 用户断服，且**无法恢复**（服务端不存明文，用户
    # 手里的 Key 再也对不上任何行）。DeletionPolicy 是 resource 级字段，
    # has_resource_properties 看不到——必须用 has_resource，否则日后有人改成
    # DESTROY 全部测试照样绿（与 test_admins_table_is_retained 同理）。
    template.has_resource("AWS::DynamoDB::Table", {
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "Properties": {"TableName": "site-api-keys"}})


def test_every_retained_table_has_deletion_protection(template):
    """**不变量（按类断言，不列表名）**：设了 `DeletionPolicy: Retain` 的表，
    必须同时有 `DeletionProtectionEnabled`。

    两者防的不是同一件事：RETAIN 只在**删栈/替换资源**时起作用，对"有人拿着
    `dynamodb:DeleteTable` 直接删表"一点保护都没有。而给一张表设 RETAIN 本身就
    等于声明了"这份数据不能丢"——那个声明不该只在删栈这一条路径上成立。

    **为什么按 DeletionPolicy 推导、而不是写死三个表名**：写死表名的话，下一个人
    加一张新的 RETAIN 表时这条照样绿，于是同一个洞再开一个。本项目已经反复栽在
    "手抄的清单就是下一个漂移源"上（M3-FINDINGS §2.18、M4-FINDINGS §3.9）。
    这条断言的覆盖面**跟着 RETAIN 的声明自动长**。

    反过来不断言：DESTROY 语义的表（jobs / sites / session-codes）**不该**加保护
    ——`site-session-codes` 是 60 秒 TTL 的一次性标记，给它加保护会让
    `cdk destroy` 卡在一张按设计可丢的表上。
    """
    tables = template.find_resources("AWS::DynamoDB::Table")
    retained = {t["Properties"].get("TableName"): t for t in tables.values()
                if t.get("DeletionPolicy") == "Retain"}
    assert retained, "模板里一张 RETAIN 表都没有——本用例的前提已失效，先查 app.py"
    missing = sorted(name for name, t in retained.items()
                     if t["Properties"].get("DeletionProtectionEnabled") is not True)
    assert not missing, (
        f"这些表设了 RETAIN 却没开 DeletionProtection: {missing}。"
        "RETAIN 只挡删栈，挡不住一条 aws dynamodb delete-table——而 RETAIN 本身"
        "就是在声明这份数据不能丢。")


def test_jobs_has_site_index(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    jobs = [t for t in tables.values()
            if t["Properties"].get("TableName") == "site-deploy-jobs"][0]
    idx = {g["IndexName"]: g for g in jobs["Properties"]["GlobalSecondaryIndexes"]}
    assert "site-index" in idx, "控制台部署历史需要按 site_id 查"
    keys = {k["KeyType"]: k["AttributeName"] for k in idx["site-index"]["KeySchema"]}
    assert keys == {"HASH": "site_id", "RANGE": "created_at"}


def test_undeploy_has_async_failure_destination(template):
    """undeploy 的异步调用失败必须有去处（Codex 审查 2026-08-10 P1-4）。

    它由 MCP/panel 以 InvocationType=Event 调用，不进状态机——add_catch 与
    SFN 的收敛都覆盖不到。**线上实测过**：没有 EventInvokeConfig 也没有
    DeadLetterConfig，Lambda 重试后静默丢弃，站点部分删除却无人知晓。

    按 FunctionName 反查逻辑 ID 再断言（同 test_step_lambdas 的理由：模板里
    是 Ref 不是字面量）。
    """
    undeploy_lid = next(
        lid for lid, res in
        template.find_resources("AWS::Lambda::Function").items()
        if res["Properties"].get("FunctionName") == "site-deployer-undeploy")
    configs = template.find_resources("AWS::Lambda::EventInvokeConfig")
    mine = [c for c in configs.values()
            if c["Properties"].get("FunctionName", {}).get("Ref") == undeploy_lid]
    assert mine, "site-deployer-undeploy 没有 EventInvokeConfig（失败即静默丢弃）"
    props = mine[0]["Properties"]
    assert "OnFailure" in props.get("DestinationConfig", {}), props
    # 删除类动作不自动重试：部分删除后重跑会撞"资源已不存在"，掩盖真实根因
    assert props.get("MaximumRetryAttempts") == 0, props
