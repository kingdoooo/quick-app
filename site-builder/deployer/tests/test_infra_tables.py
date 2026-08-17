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
import ast
import json
import os
import re
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
    # **必须传 env**：TableV2 的 replicas 在 region-agnostic 栈里会抛
    # ReplicaTablesNotSupportedInRegionAgnosticStack（2026-08-14 实测），
    # fixture 一抛异常会让本文件所有用例连带失效（含 RETAIN 不变量那条）。
    # 顺带的好处：带 env 后 self.account/region 渲染成字面量而不是
    # Fn::Join + Ref(AWS::AccountId)，模板断言可以直接比字符串。
    stack = mod.SiteDeployerStack(
        app, "TestStack",
        env=aws_cdk.Environment(account=mod.ACCOUNT, region=mod.REGION))
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


def test_access_events_table_is_a_three_region_global_table(template):
    """明细表必须是 3 区 Global Table（spec §0.4）。

    漏一个副本区 = 那个区的埋点跨区回落（正确但慢）；而 IAM 少给一个副本 ARN
    = 那个区静默零数据（Task 4 锁 IAM，这里只锁表）。
    """
    tables = template.find_resources("AWS::DynamoDB::GlobalTable")
    hit = [t for t in tables.values()
           if t["Properties"].get("TableName") == "site-access-events"]
    assert len(hit) == 1, f"site-access-events 不是 GlobalTable：{list(tables)}"
    props = hit[0]["Properties"]
    regions = {r["Region"] for r in props["Replicas"]}
    assert regions == {"us-east-1", "ap-southeast-1", "ap-northeast-1"}, (
        f"副本区集合不对: {sorted(regions)}")
    keys = {k["AttributeName"]: k["KeyType"] for k in props["KeySchema"]}
    assert keys == {"site_date": "HASH", "ts_id": "RANGE"}, keys
    assert props["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
    assert props["TimeToLiveSpecification"]["Enabled"] is True


def test_access_daily_table_is_retained_and_protected(template):
    """聚合表 400 天趋势丢了不可重建（明细 90 天就没了）→ RETAIN + 保护。

    RETAIN 那半由 test_every_retained_table_has_deletion_protection 从模板推导，
    本条只钉键与 TTL 属性名——键名错了下游全部 Query 失败。
    """
    for res in template.find_resources("AWS::DynamoDB::Table").values():
        if res["Properties"].get("TableName") != "site-access-daily":
            continue
        keys = {k["AttributeName"]: k["KeyType"] for k in res["Properties"]["KeySchema"]}
        assert keys == {"site_id": "HASH", "date": "RANGE"}, keys
        assert res["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
        assert res["DeletionPolicy"] == "Retain"
        return
    raise AssertionError("模板里找不到 site-access-daily")


def test_rollup_role_can_only_query_events_and_put_daily(template):
    """rollup 是唯一能写聚合表的身份，且对明细表只读。

    给它 PutItem 到明细表 = 聚合器能伪造访问历史；给它 Scan 明细表 = 不必要的
    全表能力（它只按分区 Query）。
    """
    # **不能按 "site-access" 字面量筛策略**（Codex 审查 2026-08-14 P2-4）：
    # `table_arn` 渲染成 {"Fn::GetAtt": ["AccessEvents832F10D1", "Arn"]}（实测），
    # policy 文本里根本没有表名字面量，那样筛会把目标策略全筛掉 → 用例空转。
    # 改成按**逻辑 ID** 对应：先从模板里查出两张表的逻辑 ID，再看语句引用了谁。
    def _logical_id(res_type: str, table_name: str) -> str:
        for lid, res in template.find_resources(res_type).items():
            if res["Properties"].get("TableName") == table_name:
                return lid
        raise AssertionError(f"模板里找不到 {table_name}")

    ev_lid = _logical_id("AWS::DynamoDB::GlobalTable", "site-access-events")
    da_lid = _logical_id("AWS::DynamoDB::Table", "site-access-daily")

    def _refs(resource) -> set[str]:
        """语句 Resource 里引用到的逻辑 ID 集合（Fn::GetAtt / Ref 都算）。"""
        out = set()
        for r in (resource if isinstance(resource, list) else [resource]):
            if isinstance(r, dict):
                for k, v in r.items():
                    if k in ("Fn::GetAtt", "Ref"):
                        out.add(v[0] if isinstance(v, list) else v)
        return out

    events_actions, daily_actions = set(), set()
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for st in pol["Properties"]["PolicyDocument"]["Statement"]:
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            acts = {str(a) for a in acts if str(a).startswith("dynamodb:")}
            if not acts:
                continue
            refs = _refs(st["Resource"])
            if ev_lid in refs:
                events_actions |= acts
            if da_lid in refs:
                daily_actions |= acts
    # **两个都要非空**，否则本用例在筛不到语句时会静默通过（上一版就是这样）
    assert events_actions, "没有任何语句引用明细表——筛选逻辑坏了，本条空转"
    assert daily_actions, "没有任何语句引用聚合表——筛选逻辑坏了，本条空转"
    assert events_actions == {"dynamodb:Query"}, (
        f"明细表的动作集合必须恰好是 Query（给 PutItem = 聚合器能伪造历史）: "
        f"{sorted(events_actions)}")
    assert daily_actions == {"dynamodb:PutItem"}, (
        f"聚合表的动作集合不对: {sorted(daily_actions)}")


def _rollup_statements(template):
    """rollup 角色**自己那些** inline 语句。

    不按动作字面量在全模板里筛——那样会把别的角色（step Lambda、panel）的同名
    动作也捞进来，于是"最小权限"这个结论其实是在别人身上验的。改成从函数
    `site-access-rollup` → `Role` 引用的逻辑 ID → 挂在该角色上的 Policy。
    """
    role_lid = None
    for fn in template.find_resources("AWS::Lambda::Function").values():
        if fn["Properties"].get("FunctionName") == "site-access-rollup":
            role_lid = fn["Properties"]["Role"]["Fn::GetAtt"][0]
    assert role_lid, "模板里找不到 site-access-rollup 函数——本条空转"
    stmts = []
    for pol in template.find_resources("AWS::IAM::Policy").values():
        roles = [r.get("Ref") for r in pol["Properties"].get("Roles", [])
                 if isinstance(r, dict)]
        if role_lid in roles:
            stmts.extend(pol["Properties"]["PolicyDocument"]["Statement"])
    assert stmts, f"{role_lid} 名下没有任何 inline 策略语句——本条空转"
    return stmts


def test_rollup_role_can_scan_cross_region_logs_and_publish_one_metric(template):
    """跨区扫 Edge 日志 + 发一个聚合指标所需的**全部**权限，一条不多。

    资源上的 region 段只能是 `*`（要扫的区在部署期未知——这正是可移植性要求
    本身），但**服务、账号、日志组前缀都收窄**：给 `logs:FilterLogEvents` 一个
    裸 `*` 等于让聚合器能读 auth / panel / 站点的全部日志（里面有邮箱）。
    """
    stmts = _rollup_statements(template)
    by_prefix = {}
    for st in stmts:
        acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
        for a in acts:
            by_prefix.setdefault(str(a).split(":")[0], set()).add(str(a))
    assert by_prefix, "解析不出任何动作——本条空转"
    assert by_prefix.get("logs") == {"logs:DescribeLogGroups",
                                     "logs:FilterLogEvents"}, by_prefix.get("logs")
    assert by_prefix.get("ec2") == {"ec2:DescribeRegions"}, by_prefix.get("ec2")
    assert by_prefix.get("cloudwatch") == {"cloudwatch:PutMetricData"}, \
        by_prefix.get("cloudwatch")
    # PutMetricData 没有资源级权限，唯一的收窄手段是 namespace 条件；
    # 不带条件时这个角色能往**任何** namespace 写，包括伪造别的告警的输入指标。
    # 两个字面量都**从运行时模块派生**，不在测试里抄第二份（抄了就只能证明
    # "模板等于测试里的那份抄写"，模块改了照样绿）
    import access_rollup as ar
    cw = [st for st in stmts if "cloudwatch:PutMetricData" in (
        st["Action"] if isinstance(st["Action"], list) else [st["Action"]])]
    assert len(cw) == 1, cw
    assert cw[0]["Condition"] == {
        "StringEquals": {"cloudwatch:namespace": ar.METRIC_NAMESPACE}}, cw[0]
    # FilterLogEvents 的资源要按 Lambda@Edge 日志组前缀收窄（区段是 `*`）
    fle = [st for st in stmts if "logs:FilterLogEvents" in (
        st["Action"] if isinstance(st["Action"], list) else [st["Action"]])]
    assert len(fle) == 1, fle
    res = fle[0]["Resource"]
    res = res if isinstance(res, list) else [res]
    assert res, "FilterLogEvents 语句没有资源——本条空转"
    for r in res:
        assert isinstance(r, str) and r != "*", f"资源是裸通配：{r}"
        assert f":log-group:{ar.EDGE_LOG_GROUP_PREFIX}" in r, r


def test_rollup_role_has_no_over_broad_actions(template):
    """反向：**不许**出现服务级通配或第二张表的写权限。

    与上面那条不重复——上面钉"该有的恰好有"，这条钉"不该有的一个都没有"，
    而通配动作（`logs:*`）恰好能同时满足上面那条的补集之外的一切。
    """
    stmts = _rollup_statements(template)
    seen = set()
    for st in stmts:
        acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
        seen |= {str(a) for a in acts}
    assert seen, "解析不出任何动作——本条空转"
    for a in seen:
        assert a != "*" and not a.endswith(":*"), f"服务级通配动作：{a}"
    # 聚合器对 DynamoDB 的能力**不许**随本次改动扩大（它只该 Query 明细、
    # PutItem 聚合、Scan sites）
    assert {a for a in seen if a.startswith("dynamodb:")} == {
        "dynamodb:Query", "dynamodb:PutItem", "dynamodb:Scan"}, sorted(seen)


def test_every_retained_table_has_pitr(template):
    """**不变量（按类断言，不列表名）**：设了 `DeletionPolicy: Retain` 的表，
    必须同时开 PITR（连续备份）。

    与 `test_every_retained_table_has_deletion_protection` 防的**不是一个方向**：
    RETAIN 与 `DeletionProtectionEnabled` 都只挡"整张表被删"，而丢数据最常见的
    形态是**写坏**——一次错的覆盖写、一段错的批量删除、一次跑歪的补跑脚本。
    给一张表设 RETAIN 本身就等于声明"这份数据不能丢"，那个声明不该只在
    "删表"这一条路径上成立。

    `site-access-daily` 是这个形态的靶心：rollup 的设计**就是**每天反复覆盖同一批
    行（`rollup_day` 连"归零"都会覆盖已存在的行），而它的 400 天历史在明细 90 天
    TTL 到期后**不可重建**（`infra/app.py` 自己就是这么写的）。写坏之后没有 PITR
    就只剩"接受错的数字"。

    **为什么按 DeletionPolicy 推导、而不是点名两张分析表**：写死表名的话，下一个人
    加一张新的 RETAIN 表时这条照样绿，同一个洞再开一个（M3-FINDINGS §2.18、
    M4-FINDINGS §3.9 的同一课）。覆盖面跟着 RETAIN 的声明自动长。
    """
    tables = template.find_resources("AWS::DynamoDB::Table")
    retained = {t["Properties"].get("TableName"): t for t in tables.values()
                if t.get("DeletionPolicy") == "Retain"}
    assert retained, "模板里一张 RETAIN 表都没有——本用例的前提已失效，先查 app.py"
    missing = sorted(
        name for name, t in retained.items()
        if (t["Properties"].get("PointInTimeRecoverySpecification") or {}
            ).get("PointInTimeRecoveryEnabled") is not True)
    assert not missing, (
        f"这些表设了 RETAIN 却没开 PITR: {missing}。RETAIN 与 DeletionProtection "
        "都只挡删表，挡不住一次写坏——而 RETAIN 本身就是在声明这份数据不能丢。")


def test_every_global_table_replica_has_pitr(template):
    """**不变量（按资源类型推导，不列表名）**：每张 `AWS::DynamoDB::GlobalTable`
    的**每个副本**都要开 PITR。

    **属性形状与普通表不同，必须读渲染后的模板**：`AWS::DynamoDB::Table` 的
    `PointInTimeRecoverySpecification` 在顶层，而 GlobalTable 的在**每个 replica
    里各一份**（CDK 的表级 prop 会分发到含主副本在内的每个 replica）。拿 Table
    那个形状去断言 GlobalTable 会永远查不到那个键 → 用例空转，而两侧都"绿"。
    这也是为什么上面那条（只扫 `AWS::DynamoDB::Table`）看不见它：**不是重复用例，
    是另一种资源类型**。

    **按资源类型推导而不是点名 `site-access-events`**：将来再加多区表会自动被
    要求，与 `test_every_retained_table_has_deletion_protection` 同一条纪律
    （手抄的清单就是下一个漂移源）。

    唯一那张多区表按设计是 DESTROY（90 天滚动明细），所以它**不在**上面那条
    RETAIN 不变量的范围里，只能由本条覆盖。它值得 PITR 的理由与聚合表不同：
    它是**其它一切数字的来源**（rollup / 面板 / MCP 都从它算），而"只要明细还在，
    数就还能算回来"（spec §0.1 用来否掉日志侧聚合的正是这条属性）只在明细自己
    没被写坏时成立。PITR 又是**按副本**计费与恢复的，所以要求逐个副本都有：
    只在一个区开，另外两个区被写坏时没有可回溯的点。
    """
    gts = template.find_resources("AWS::DynamoDB::GlobalTable")
    assert gts, "模板里没有 GlobalTable——本条前提已失效（多区表换回 Table 了？）"
    for res in gts.values():
        props = res["Properties"]
        replicas = props.get("Replicas") or []
        assert replicas, f"{props.get('TableName')} 一个副本都没渲染出来——本条会空转"
        missing = sorted(r["Region"] for r in replicas
                         if (r.get("PointInTimeRecoverySpecification") or {}
                             ).get("PointInTimeRecoveryEnabled") is not True)
        assert not missing, (
            f"{props.get('TableName')} 这些副本没开 PITR: {missing}。明细是聚合表的"
            "重建来源，写坏之后「重算即修复」就不成立了；GlobalTable 的 PITR "
            "是按副本设的，漏一个就是那个区没有时点恢复能力。")


def _alarm(template, alarm_name: str) -> dict:
    """按 AlarmName 取**恰好一条**告警的 Properties。

    要求恰好一条：CloudWatch 的告警名在区内唯一，模板里出现两条同名的会在部署时
    互相覆盖（后写的赢），而两条各自的断言都能绿。
    """
    hit = [a["Properties"] for a in
           template.find_resources("AWS::CloudWatch::Alarm").values()
           if a["Properties"].get("AlarmName") == alarm_name]
    assert len(hit) == 1, (
        f"{alarm_name} 在模板里不是恰好一条（找到 {len(hit)} 条）。"
        "手工建的告警不算——那正是本次要消灭的状态。")
    return hit[0]


def _flat_arn(value) -> str:
    """把模板里 `Fn::Join` 形态的 ARN 拉平成字符串（`Ref: AWS::Partition` → `aws`）。

    imported topic 的 ARN 在模板里不是字面量，直接 `==` 比字符串永远不等
    ——那种断言写出来就是死的（§4.8 同一形态）。
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(_flat_arn(p) for p in parts)
    if isinstance(value, dict) and value.get("Ref") == "AWS::Partition":
        return "aws"        # 本平台钉死商业区（us-east-1 是硬约束）
    raise AssertionError(f"无法拉平的 ARN 形态：{value}")


EDGE_ALARM = "m5-edge-analytics-failed-global"
ROLLUP_ALARM = "m5-rollup-no-successful-invocation-24h"


def test_edge_analytics_alarm_watches_the_metric_the_rollup_publishes(template):
    """跨区 Edge 埋点失败告警：**指标坐标从运行时模块派生**，参数逐个钉死。

    namespace 与指标名不在这里抄第二份——抄了就只能证明"模板等于测试里的抄写"，
    `access_rollup.py` 改了名字照样绿，而线上表现是告警盯着一个再也没有数据点的
    指标（`breaching` 下每天响一次假警报，然后下一个人学会忽略它）。

    每个参数都有实测理由（见 `infra/app.py` 的长注释与 DEPLOY.md），这里只钉值：
    改任何一个都必须先改那两处的理由。
    """
    import access_rollup as ar
    props = _alarm(template, EDGE_ALARM)
    assert props["Namespace"] == ar.METRIC_NAMESPACE, props
    assert props["MetricName"] == ar.METRIC_NAME, props
    # Maximum 而不是 Sum：手工重跑 rollup 会在同一窗口里多打一个数据点
    assert props["Statistic"] == "Maximum", props
    assert props["Period"] == 86400, props
    # 阈值 3（配 GreaterThanThreshold ⇒ 一天 ≥4 条失败、连续两天才响）。
    # **这个数字挂在一个未测量的量上**（埋点的正常失败底噪）：现网实测流量
    # ≈134 次写入/天，而失败样本只有"18 次里 0 次失败"，按 rule of three 只能
    # 把失败率上界压到 ≈17% —— 也就是说底噪是 0 还是 20 次/天，现有数据分不出。
    # 所以 3 是**假设**（"底噪 < 3/天"）不是结论，理由、可证伪的观测、以及
    # 一周后的复查触发条件全写在 app.py 与 DEPLOY.md，改这里必须一起改。
    assert props["Threshold"] == 3, props
    assert props["ComparisonOperator"] == "GreaterThanThreshold", props
    # 2/2：period=86400 的告警评估**滚动** 24h 窗口，1/1 时健康也会响
    assert props["EvaluationPeriods"] == 2, props
    assert props["DatapointsToAlarm"] == 2, props
    # breaching：扫成功时会发显式 0，所以缺数据只剩"本轮没扫成"一个含义
    assert props["TreatMissingData"] == "breaching", props
    # 指标本身不带维度；告警加了维度就只盯得住某一个区（= 又回到按区建告警）
    assert "Dimensions" not in props, props


def test_rollup_liveness_alarm_is_invocations_minus_errors(template):
    """聚合器活性告警：`Invocations - Errors < 1` 连续两天。

    **为什么不是 `Errors > 0`**：要抓的头号形态是"根本没被触发"（EventBridge rule
    被删/禁用、触发权限丢了），那时 Errors **不产生任何数据点**，`Errors > 0` 永远
    不会响。所以必须用 metric math 把"成功次数"算出来，再配 `breaching`。

    表达式里的两个 id 从 MetricStat 反推（不比字面量），维度按逻辑 ID 对应到
    `site-access-rollup` 函数——比字面函数名的话，模板里那是 `Ref` 不是字面量。
    """
    props = _alarm(template, ROLLUP_ALARM)
    # metric math 告警不许同时带静态指标坐标（那是另一种告警形态，两者混写时
    # CloudWatch 只认一种，读模板的人却以为盯的是另一种）
    assert "MetricName" not in props and "Namespace" not in props, props
    exprs = [m for m in props["Metrics"] if "Expression" in m]
    subs = {m["Id"]: m["MetricStat"] for m in props["Metrics"] if "MetricStat" in m}
    assert len(exprs) == 1, props["Metrics"]
    assert len(subs) == 2, subs
    by_metric = {st["Metric"]["MetricName"]: (mid, st) for mid, st in subs.items()}
    assert set(by_metric) == {"Invocations", "Errors"}, sorted(by_metric)
    fn_lid = next(lid for lid, res in
                  template.find_resources("AWS::Lambda::Function").items()
                  if res["Properties"].get("FunctionName") == "site-access-rollup")
    for name, (mid, st) in by_metric.items():
        assert st["Metric"]["Namespace"] == "AWS/Lambda", (name, st)
        assert st["Stat"] == "Sum", (name, st)
        assert st["Period"] == 86400, (name, st)
        assert st["Metric"]["Dimensions"] == [
            {"Name": "FunctionName", "Value": {"Ref": fn_lid}}], (name, st)
    inv, err = by_metric["Invocations"][0], by_metric["Errors"][0]
    assert " ".join(exprs[0]["Expression"].split()) == f"{inv} - {err}", exprs[0]
    assert props["Threshold"] == 1, props
    assert props["ComparisonOperator"] == "LessThanThreshold", props
    # 2/2 与另一条同理：**这条原本手工建成 1/1**，实测每天产生一对 ALARM→OK
    assert props["EvaluationPeriods"] == 2, props
    assert props["DatapointsToAlarm"] == 2, props
    assert props["TreatMissingData"] == "breaching", props


def test_the_rollup_module_docstring_cites_an_alarm_that_exists(template):
    """`access_rollup.py` 的模块 docstring 告诉运维"多日中断约 24~48 小时内会被
    发现"，依据就是这条告警。把它改名或删掉之后那句话变成谎话，而 docstring
    自己不会红——这条把两者绑在一起。

    只检查"引用的名字确实是模板里的一条告警"，不检查那段描述是否句句准确
    （后者做不到；参数的准确性由上面那条钉）。
    """
    import access_rollup as ar
    _alarm(template, ROLLUP_ALARM)      # 恰好一条，由 _alarm 保证
    assert ROLLUP_ALARM in (ar.__doc__ or ""), (
        f"access_rollup 的模块 docstring 不再引用 {ROLLUP_ALARM}——两处必须同时改")


def test_both_m5_alarms_notify_the_platform_topic(template):
    """两条告警的 ALARM 与 OK 都必须发到平台那一个 SNS topic。

    **OK actions 不是可选的**：本项目统一把 OK 称作"告警解除"并同样通知
    （与 auth 那条登录失败告警同一套用词，见 DEPLOY.md）。只发 ALARM 时，
    收件人无法区分"还在坏"与"已恢复"。

    **本栈不许自己建 topic**：已确认的邮件订阅挂在 `deploy_auth.py` 建的那一个
    上；另建一个的症状是告警照样进 ALARM 而没有任何人收到通知——正是这套告警
    要防的盲区本身。
    """
    import app as infra_app
    # 先断这条：本栈自己建 topic 时下面的 ARN 会渲染成 `Ref`，`_flat_arn` 会抛出
    # 一个看不出所以然的错。先在这里失败，报错文案才说得清是哪种缺陷。
    assert not template.find_resources("AWS::SNS::Topic"), (
        "本栈不该自己建 SNS topic——已确认的邮件订阅挂在 deploy_auth.py 建的"
        "那个上，另建一个等于把告警发到没人订阅的地方")
    expect = (f"arn:aws:sns:{infra_app.REGION}:{infra_app.ACCOUNT}:"
              f"{infra_app.ALARM_TOPIC_NAME}")
    for name in (EDGE_ALARM, ROLLUP_ALARM):
        props = _alarm(template, name)
        for key in ("AlarmActions", "OKActions"):
            got = [_flat_arn(v) for v in props.get(key) or []]
            assert got == [expect], (name, key, got)


def test_alarm_topic_name_matches_the_script_that_creates_it(template):
    """topic 的**建者**是 `auth/deploy_auth.py`（幂等 boto3 收敛，不是 CDK），
    本栈只按名字引用。两侧字面量必须一致。

    为什么值得一条跨文件断言：CloudWatch **不校验 action 指向的 topic 是否存在**，
    所以任一侧改名之后告警照样建得出来、照样进 ALARM，只是通知发进虚空。这类
    "配置对不上而两侧单测都绿"是本项目反复栽的形态（CLAUDE.md 高频坑）。
    """
    import app as infra_app
    src = (Path(__file__).parents[2] / "auth" / "deploy_auth.py").read_text(
        encoding="utf-8")
    names = {kw.value.value
             for node in ast.walk(ast.parse(src)) if isinstance(node, ast.Call)
             for kw in node.keywords
             if kw.arg == "topic_name" and isinstance(kw.value, ast.Constant)}
    assert names, "deploy_auth.py 里找不到 topic_name= 字面量——本条已空转，先查那边"
    assert names == {infra_app.ALARM_TOPIC_NAME}, (
        f"topic 名两侧不一致：deploy_auth.py={sorted(names)}，"
        f"infra/app.py={infra_app.ALARM_TOPIC_NAME}")


def _rollup_fn(template) -> dict:
    hit = [res["Properties"] for res in
           template.find_resources("AWS::Lambda::Function").values()
           if res["Properties"].get("FunctionName") == "site-access-rollup"]
    assert len(hit) == 1, f"模板里没有唯一的 site-access-rollup：{len(hit)}"
    return hit[0]


def test_rollup_memory_is_sized_for_its_scan_threads(template):
    """内存不许再回到 256MB，且**必须随扫描线程数走**。

    2026-08-15 线上回归：跨区扫描上线后约一半调用挂 `Runtime.OutOfMemory`
    （256MB 的函数，六次 REPORT 全部 used≈255~256/256MB）。根因是每区新建一个
    boto3 Session（各自一份 botocore endpoints/服务模型），18 个已启用区 × 并发 8
    ⇒ 200MB+ 活内存。运行时那侧已改成**每线程一个 Session**，于是活内存的乘数从
    "区数"（AWS 说了算）变成 `SCAN_WORKERS`（我们说了算）。

    这条钉的就是那条式子：
      · `MemorySize` 逐字等于 `infra/app.py` 的 `ROLLUP_MEMORY_MB`（防"悄悄改回
        256"）；
      · 而 `ROLLUP_MEMORY_MB` 必须 ≥ (基线 + 每线程 × 线程数) × 余量倍数
        ——**调大 `SCAN_WORKERS` 而不调内存 ⇒ 这条红**，那正是上一次那个"新开一个区
        就悄悄坏掉"的旋钮；
      · 线程数从 `functions/access_rollup.py` 的源码读（单一真源，不手抄）。
    """
    import app as infra_app
    workers = infra_app.ROLLUP_SCAN_WORKERS
    assert workers >= 1, workers
    floor = ((infra_app.ROLLUP_MEM_BASE_MB
              + infra_app.ROLLUP_MEM_PER_WORKER_MB * workers)
             * infra_app.ROLLUP_MEM_HEADROOM)
    props = _rollup_fn(template)
    assert props["MemorySize"] == infra_app.ROLLUP_MEMORY_MB, props["MemorySize"]
    assert props["MemorySize"] >= floor, (
        f"MemorySize={props['MemorySize']}MB 撑不住 {workers} 个扫描线程"
        f"（下界 {floor}MB = (基线 {infra_app.ROLLUP_MEM_BASE_MB} + 每线程 "
        f"{infra_app.ROLLUP_MEM_PER_WORKER_MB} × {workers}) × "
        f"{infra_app.ROLLUP_MEM_HEADROOM}）")
    assert props["MemorySize"] > 256, "256MB 就是 2026-08-15 那次 OOM 的尺寸"


def test_the_scan_budget_leaves_room_inside_the_rollup_timeout(template):
    """扫描的自限预算必须**明显小于**函数超时。

    扫描是观测，封口是耐久工作，两者在同一次调用里（封口在前）。预算的全部意义
    是"扫不完就放手"，而不是"扫到超时"——超时会把封口那次调用一起标记成失败
    （EventBridge 重试 + DLQ + 拖响 `m5-rollup-no-successful-invocation-24h`）。
    所以留一半给封口与收尾：预算 × 2 ≤ 超时。
    """
    import app as infra_app
    props = _rollup_fn(template)
    assert props["Timeout"] == infra_app.ROLLUP_TIMEOUT_SECONDS, props["Timeout"]
    budget = infra_app.ROLLUP_SCAN_BUDGET_SECONDS
    assert budget > 0, budget
    assert budget * 2 <= props["Timeout"], (
        f"扫描预算 {budget}s 在 {props['Timeout']}s 超时里没留出封口余量")


def test_validate_disk_covers_the_unpacked_size_limit(template):
    """磁盘下界由**合同的解包上界**决定：`extractall` 把整棵树写进 `/tmp`
    （`TemporaryDirectory()` 在 Lambda 上就落那里）。改上界不同时改磁盘 ⇒ 本条红。

    **2 倍是两项之和**：/tmp 上同时有 `extractall` 解出来的整棵树，与
    `_pack_build_input` 重新打包出来的工件（run.sh + backend/ 子集，最坏情况几乎
    与树同量级——已压缩过的资产再压不动）。二者各 ≤ 上界 ⇒ 下界 = 上界 × 2。
    顺带的余量也用得上：那道上界预检查的是 zip 中央目录里**声明的** `file_size`，
    而真正落盘的是实际写出的字节，两者不必相等（CRC 不符要等写完才发现）；磁盘
    刚好卡在声明值上时，症状会从 `ContractViolation`（说得清是用户包太大）退化成
    ENOSPC（读起来像平台故障）。

    **本条只绑磁盘这一条轴。** 内存那条轴（下载下来的上传包 + extracted/ 循环里
    当下那个文件）没有任何常量绑着，是 M7 的遗留项，另有跟进任务。
    """
    import app as appmod
    limit_mb = appmod._validate_const("MAX_UNPACKED_BYTES", int) // (1024 * 1024)
    assert limit_mb > 0, limit_mb
    assert appmod.VALIDATE_EPHEMERAL_MB >= limit_mb * 2, (
        f"解包上界 {limit_mb}MB 需要至少 {limit_mb * 2}MB 磁盘，"
        f"当前 {appmod.VALIDATE_EPHEMERAL_MB}MB")
    template.has_resource_properties("AWS::Lambda::Function", {
        "Handler": "validate.handler",
        "EphemeralStorage": {"Size": appmod.VALIDATE_EPHEMERAL_MB}})


def _role_lid_by_name(template, role_name: str) -> str:
    role_lid = next(
        (lid for lid, res in template.find_resources("AWS::IAM::Role").items()
         if res["Properties"].get("RoleName") == role_name), None)
    assert role_lid, f"模板里找不到 {role_name}——本条空转"
    return role_lid


def _statements_by_role(template) -> dict[str, list[dict]]:
    """角色逻辑 ID → 挂在它名下的**全部**策略语句（独立 Policy + 内联 Policies）。

    两种承载形态都要收：`add_to_policy` 渲染成独立的 `AWS::IAM::Policy`，而
    `iam.Role(policies=...)` 会内联在角色里。只看一种的守卫会把另一种形态写出来的
    权限当成不存在——那正是"遍历所有语句"这句话最容易空转的地方。
    """
    out: dict[str, list[dict]] = {}
    for lid, res in template.find_resources("AWS::IAM::Role").items():
        for pol in res["Properties"].get("Policies") or []:
            out.setdefault(lid, []).extend(pol["PolicyDocument"]["Statement"])
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for r in pol["Properties"].get("Roles") or []:
            if isinstance(r, dict) and r.get("Ref"):
                out.setdefault(r["Ref"], []).extend(
                    pol["Properties"]["PolicyDocument"]["Statement"])
    return out


def _exec_role_statements(template):
    """`site-deployer-exec-role` **自己那些** inline 策略语句。

    与 `_rollup_statements` 同一条纪律：不在全模板里按 Effect/动作筛——那样别的
    角色上的一条 Deny 就足以让"exec_role 有 Deny"这个结论成立，而 exec_role 自己
    一条都没有。先从 RoleName 反查逻辑 ID，再取挂在它名下的 policy。
    """
    role_lid = _role_lid_by_name(template, "site-deployer-exec-role")
    stmts = _statements_by_role(template).get(role_lid, [])
    assert stmts, f"{role_lid} 名下没有任何策略语句——本条空转"
    return stmts


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def test_deployer_cannot_touch_platform_functions(template):
    """**存量过度授权**：exec_role 一直持有 UpdateFunctionCode on site-*，而
    site-* 同时匹配 site-panel / site-key-proxy / site-auth-service。部署器能
    覆写控制面的代码，这比 M7 要加的 InvokeFunction 严重得多（M7-SPEC §2.1）。
    用显式 Deny 兜（Deny 胜过 Allow），资源写**精确名**——通配不可判定。

    这条断言的三根自由度都要锁住：Effect、Resource、**Action**。只锁前两根是
    Codex P2-d 实测过的假绿——把 `actions=["lambda:*"]` 改成 `["lambda:GetFunction"]`
    时旧版本 2 passed，而那一步等于把 UpdateFunctionCode/DeleteFunction 重新放行。
    Action 的期望值**从模板里 exec_role 自己的 Allow 语句推导**（不是手抄一份危险动作
    表——那会过时）：部署器被允许对 site-* 做的每个 lambda 动作，都必须在平台 ARN 上
    被**同一条** Deny 挡住。并集式判定同样堵掉：覆盖 ARN 的那条语句必须自己就管住动作。
    """
    import app as appmod
    stmts = _exec_role_statements(template)

    # 部署器实际被授予的 lambda 动作（真源 = 模板里的 Allow 语句）
    allowed = {a for st in stmts if st.get("Effect", "Allow") == "Allow"
               for a in _as_list(st.get("Action", []))
               if isinstance(a, str) and (a == "*" or a.startswith("lambda:"))}
    assert allowed, "抽不到 exec_role 的 lambda Allow 动作——本条已空转，先查那些语句"
    if "*" in allowed or "lambda:*" in allowed:
        allowed = {"lambda:*"}   # 全给了就只需 Deny 全量

    denies = [st for st in stmts if st.get("Effect") == "Deny"]
    assert denies, "exec_role 没有任何 Deny 语句"

    def _covers(st, arn: str) -> bool:
        if arn not in set(_as_list(st.get("Resource", []))):
            return False
        acts = set(_as_list(st.get("Action", [])))
        return "*" in acts or "lambda:*" in acts or allowed <= acts

    # **按整串比，不按子串**，且两种形态都要：不带限定符的 ARN 管住 UpdateFunctionCode
    # 这类不指版本的调用，`:*` 管住指到别名/版本上的调用。子串式断言会漏掉最省事的
    # 那种退化——只保留 `:*` 一份（此时 "function:site-panel" 仍是
    # "function:site-panel:*" 的子串，断言照样绿，而不带限定符的调用已重新放行）。
    for fn in appmod.PLATFORM_FUNCTION_NAMES:
        for suffix in ("", ":*"):
            arn = (f"arn:aws:lambda:{appmod.REGION}:{appmod.ACCOUNT}"
                   f":function:{fn}{suffix}")
            assert any(_covers(st, arn) for st in denies), (
                f"没有**单独一条** Deny 同时覆盖 {arn} 与动作 {sorted(allowed)}"
                "——分散在两条语句里不算，Resource 取并集会把这种退化判绿")
    # Resource 未必是字符串：`f"{bucket.bucket_arn}/x/*"` 渲染成 `Fn::Join`（F7 起
    # exec_role 的 S3 Deny 就是这种形态）。序列化之后再查子串——直接进 set 会
    # `TypeError: unhashable type: 'dict'`，只取 isinstance(str) 则会把藏在 token
    # 里的通配静默漏掉。
    covered = [r if isinstance(r, str) else json.dumps(r, sort_keys=True)
               for st in denies for r in _as_list(st.get("Resource", []))]
    wild = sorted(r for r in covered if "function:site-*" in r)
    assert not wild, f"Deny 用了通配——会误伤真实站点：{wild}"


# ── B0: exec_role 的 lambda 动作要覆盖 functions/ 实际调用的每个 API ──────
# boto3 方法名 → IAM 动作的**已知命名不规则**（其余按 snake_case → PascalCase 机械
# 映射）。这张表不是偷懒，每条都有依据：
#   · `invoke`     → InvokeFunction（方法名与动作名不同）
#   · `get_waiter("function_updated"/"function_active")` 实际轮询的是
#     GetFunctionConfiguration（**不是** GetFunction）——app.py 那条既有注释记着这个
#     实测教训：缺它每次部署都 AccessDenied
#   · `get_paginator("x")` → 按它的字符串参数解（`list_versions_by_function` 这种）
#   · `exceptions` 是属性访问，不是 API
LAMBDA_CALL_TO_ACTION = {
    "invoke": "lambda:InvokeFunction",
    "get_waiter": "lambda:GetFunctionConfiguration",
    "get_paginator": None,
    "exceptions": None,
}

# Phase B（blue/green）会用到、但**调用还没写进 functions/** 的动作。真源是
# B1-B6 的 brief，不是代码——所以这张表是手抄的，且必须手抄：上面那条采集式守卫
# 只看得见"已经写下来的调用"，而这六个动作要**先于**代码进 IAM，否则 B1-B6 全绿地
# 做完再在真机上 AccessDenied（moto 不校验 IAM）。等 B1-B6 的调用落地后，采集式
# 守卫会自动接管这六项，本表就退化成一条冗余的双保险。
PHASE_B_BLUE_GREEN_ACTIONS = {
    "lambda:GetAlias",                  # B1:77-81 / B4:58 / B5:39 判当前颜色
    "lambda:PublishVersion",            # B1:90 / B5:47 发版
    "lambda:CreateAlias",               # B2 首次建两个固定 alias
    "lambda:UpdateAlias",               # B2 切色、B4 回滚
    "lambda:InvokeFunction",            # B1:174 健康门直调（带 Qualifier）
    "lambda:ListVersionsByFunction",    # B4:108 旧版本清理前的列举
}


def _pascal(snake: str) -> str:
    return "".join(part.title() for part in snake.split("_"))


def _is_lambda_client_call(node) -> bool:
    """`boto3.client("lambda")`。"""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "client"
            and getattr(node.func.value, "id", None) == "boto3"
            and bool(node.args) and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "lambda")


def _lambda_client_names(tree) -> tuple[set[str], set[str]]:
    """这个模块里 lambda 客户端的两种拿法 → (变量名集合, 工厂函数名集合)。

    **名字不写死**（本仓库当下是 `def _lambda(): return boto3.client("lambda")` 再
    `lam = _lambda()`，但那是可以改的）：先找出返回 lambda 客户端的工厂函数，再收集
    直接赋值与"赋值 = 调用那个工厂"两种绑定。写死 `lam` 的话，改个变量名就会让这条
    守卫静默退化成恒真。

    工厂名也一并返回：`_lambda().get_function(...)` 这种不落变量的写法同样要算进来
    ——只认变量名的话，把调用改成直接链在工厂上就能绕过整条守卫，而那正是最自然的
    重构之一。
    """
    factories = {node.name for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and any(_is_lambda_client_call(n.value)
                         for n in ast.walk(node) if isinstance(n, ast.Return))}
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        v = node.value
        if _is_lambda_client_call(v) or (
                isinstance(v, ast.Call)
                and getattr(v.func, "id", None) in factories):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names, factories


def _receiver_is_lambda_client(value, clients: set[str], factories: set[str]) -> bool:
    """`<recv>.method(...)` 里的 `<recv>` 是不是 lambda 客户端。

    三种形态：变量（`lam`）、直接工厂调用（`_lambda()`）、就地 boto3 调用
    （`boto3.client("lambda")`）。
    """
    if isinstance(value, ast.Name):
        return value.id in clients
    if isinstance(value, ast.Call):
        return (getattr(value.func, "id", None) in factories
                or _is_lambda_client_call(value))
    return False


def _lambda_actions_called_in(src: str) -> set[str]:
    """一个 `functions/*.py` 里对 lambda 客户端发起的调用 → 需要的 IAM 动作集合。"""
    tree = ast.parse(src)
    clients, factories = _lambda_client_names(tree)
    out: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and _receiver_is_lambda_client(node.func.value, clients, factories)):
            continue
        method = node.func.attr
        if method in LAMBDA_CALL_TO_ACTION:
            mapped = LAMBDA_CALL_TO_ACTION[method]
            if mapped:
                out.add(mapped)
            elif method == "get_paginator" and node.args \
                    and isinstance(node.args[0], ast.Constant):
                out.add(f"lambda:{_pascal(node.args[0].value)}")
            continue
        out.add(f"lambda:{_pascal(method)}")
    return out


def _exec_role_lambda_allows(template) -> set[str]:
    """模板里 exec_role 被 Allow 的 lambda 动作集（`lambda:*`/`*` 原样留着）。"""
    return {a for st in _exec_role_statements(template)
            if st.get("Effect", "Allow") == "Allow"
            for a in _as_list(st.get("Action", []))
            if isinstance(a, str) and (a == "*" or a.startswith("lambda:"))}


def test_exec_role_can_do_every_lambda_call_the_functions_actually_make(template):
    """**期望值从 `functions/*.py` 实际调用的 API 推导**，不是手抄一份动作清单。

    这条守卫挡的是本仓库记过的那一整类："moto 不校验 IAM ⇒ 漏给权限时单测全绿、
    真机 500"。单测直接调 handler、moto 不看角色，所以"这个调用有没有权限"在整个
    单测层面**没有任何东西在看**——只有从调用点反推、再跟模板对账才看得见。

    抓得到：给 deployer 新增任何一个 lambda API 调用而没同步 exec_role。
    抓不到：调用名是变量拼出来的（`getattr(lam, op)`）——那种写法本仓库没有，
    出现时这条会漏，所以**不许**那样写。

    **本条今天是绿的，而且这就是对的**：blue/green 那六个调用还没写进 functions/
    （B1-B6 才落地），所以今天的 needed 全都已经被授予。它的价值在 B1-B6：那时新
    调用一进来，没同步 IAM 就会红。它有牙这件事由注入验证（临时加一句
    `put_function_concurrency` ⇒ 报缺 PutFunctionConcurrency），不是由"今天就红"。
    """
    fn_dir = Path(__file__).parents[1] / "functions"
    per_file = {p.name: _lambda_actions_called_in(p.read_text(encoding="utf-8"))
                for p in sorted(fn_dir.glob("*.py"))}
    needed = set().union(*per_file.values())
    # 空转防护：采集器坏掉（变量名换了、客户端换了拿法）时 needed 会变空，而
    # 空集是任何东西的子集 ⇒ 断言恒真。所以先要求它非空，再要求它被覆盖。
    assert needed, ("从 functions/*.py 抽不到任何 lambda 调用——采集器坏了（本条已"
                    "退化成恒真）。先查 _lambda_client_names 认不认现在的拿法")
    assert len(needed) >= 5, f"只抽到 {sorted(needed)}——太少，像是采集只命中了一处"

    granted = _exec_role_lambda_allows(template)
    if "*" in granted or "lambda:*" in granted:
        return          # 全给了（本仓库不这么做，但别在这里误报）
    missing = needed - granted
    assert not missing, (
        f"functions/ 里调了这些 lambda API 而 exec_role 没授权：{sorted(missing)}"
        f"\n调用出处：{ {k: sorted(v & missing) for k, v in per_file.items() if v & missing} }"
        "\nmoto 不校验 IAM ⇒ 单测会全绿，真机 AccessDenied")


def test_exec_role_has_the_lambda_actions_phase_b_blue_green_will_need(template):
    """六个 blue/green 动作**先于代码**进 IAM，所以要单独钉一次（Ruling 39）。

    上面那条采集式守卫看不见它们：`get_alias` / `publish_version` / `create_alias` /
    `update_alias` / `invoke(Qualifier=…)` / `list_versions_by_function` 的调用点在
    B1-B6 才写进 `functions/`，今天 needed 里没有 ⇒ 今天删掉其中任何一个动作，所有
    测试照绿，而 B1-B6 依然会做完再在 C1 真机上 AccessDenied。这条把那个窗口关上。

    真源是 B1-B6 的 brief（`PHASE_B_BLUE_GREEN_ACTIONS` 上方逐条注了出处），不是
    `app.py`——所以它不与被测代码同源。等那六个调用落地后本条变成冗余双保险，
    采集式守卫会自动接管。
    """
    granted = _exec_role_lambda_allows(template)
    if "*" in granted or "lambda:*" in granted:
        return
    missing = PHASE_B_BLUE_GREEN_ACTIONS - granted
    assert not missing, (
        f"exec_role 缺 blue/green 要用的动作：{sorted(missing)}——Phase B 的任务会在"
        "单测里全绿（moto 不校验 IAM），然后在真机上 AccessDenied")


PLATFORM_FN_RE = re.compile(r"site-[a-z0-9-]+")

# 平台 Lambda 的**创建方**（= 名字的真源）里，本栈之外的那三个部署脚本。
EXTERNAL_FN_SCRIPTS = ("panel/deploy_panel.py", "key-proxy/deploy_key_proxy.py",
                       "auth/deploy_auth.py")


def _fn_names_declared_in(script: Path) -> set[str]:
    """从一个部署脚本里抽出**它创建的 Lambda 函数名**字面量。

    只认挂在"名字里含 fn 的模块级常量或形参默认值"上的 `site-*` 字面量
    （`FN_NAME` / `FN` / `fn_name=`）——所以 `ROLE_NAME = "site-panel-role"`
    这类同前缀的角色名不会混进来。抽不到就让调用处红：常量改名时本条会**自报
    空转**，而不是静默把覆盖面缩到零（同 test_alarm_topic_name_... 的处理）。
    """
    out: set[str] = set()

    def _take(target: str, value) -> None:
        if ("fn" in target.lower() and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and PLATFORM_FN_RE.fullmatch(value.value)):
            out.add(value.value)

    for node in ast.walk(ast.parse(script.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    _take(t.id, node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            pos = a.posonlyargs + a.args
            for arg, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
                _take(arg.arg, d)
            for arg, d in zip(a.kwonlyargs, a.kw_defaults):
                if d is not None:
                    _take(arg.arg, d)
    return out


def test_platform_function_name_list_matches_what_creates_them(template):
    """名单漏一个就等于给部署器留一个可覆写的控制面函数，所以**期望值必须来自
    别处**：本栈创建的从**模板**里数，另外四个从**创建它们的部署脚本**里 AST 抽。

    这条的形状是有意的。若期望值也读 `PLATFORM_FUNCTION_NAMES`（本任务 brief 里
    最初就是那样），从名单里摘掉一项时策略与期望**一起**变小 ⇒ 断言恒真
    ——实测过：摘掉 `site-panel` 后三条 platform 断言全绿（plan Global Constraints
    点名的 v1 `copied_files_not_in_map()` 是同一个错）。

    抓得到的两种退化：本栈新增/改名一个平台函数而没进名单；panel / key-proxy /
    auth 那侧改了函数名而这边没跟。抓不到的：**新写一个部署脚本**创建新的平台
    函数——没有便宜办法发现，所以 EXTERNAL_FN_SCRIPTS 是手工清单，加脚本时要加。
    """
    import app as appmod
    listed = set(appmod.PLATFORM_FUNCTION_NAMES)

    created = {p["Properties"]["FunctionName"]
               for p in template.find_resources("AWS::Lambda::Function").values()
               if isinstance(p.get("Properties", {}).get("FunctionName"), str)}
    assert created, "模板里一个具名 Lambda 都没有——本条空转"
    assert created - listed == set(), \
        f"这些本栈创建的函数没进 Deny 名单：{sorted(created - listed)}"

    root = Path(__file__).parents[2]
    for rel in EXTERNAL_FN_SCRIPTS:
        names = _fn_names_declared_in(root / rel)
        assert names, (f"{rel} 里抽不出 site-* 函数名字面量——本条已空转，"
                       "先查那边的常量名（FN_NAME / FN / fn_name=）")
        assert names - listed == set(), (
            f"{rel} 创建的这些平台函数没进 Deny 名单：{sorted(names - listed)}"
            "——部署器现在能覆写它们的代码")


# ── F7: validate 的独立角色 + validated/ 只有它能写 ──────────────────────
VALIDATE_ROLE_NAME = "site-deployer-validate-role"
EXEC_ROLE_NAME = "site-deployer-exec-role"

# `service-role/AWSLambdaBasicExecutionRole` 在模板里的渲染形态（partition 是 Ref）。
# **按结构比，不按 json.dumps 子串**：子串式断言连 `NotAction` 里出现这串都算命中。
BASIC_EXEC_MANAGED_POLICY = {"Fn::Join": ["", [
    "arn:", {"Ref": "AWS::Partition"},
    ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]]}


def _fn_role_lid(fn_res: dict) -> str:
    """Lambda 资源的 `Role` 属性 → 角色逻辑 ID（`Fn::GetAtt[lid, "Arn"]`）。"""
    role = fn_res["Properties"]["Role"]
    assert isinstance(role, dict) and isinstance(role.get("Fn::GetAtt"), list), \
        f"Role 不是 Fn::GetAtt 形态，本条无法判定：{role}"
    return role["Fn::GetAtt"][0]


def _fn_lid_by_handler(template, handler: str) -> str:
    hit = [lid for lid, res in template.find_resources("AWS::Lambda::Function").items()
           if res["Properties"].get("Handler") == handler]
    assert len(hit) == 1, f"按 Handler={handler} 找到 {len(hit)} 个函数：{hit}"
    return hit[0]


def _state_machine_step_fn_lids(template) -> set[str]:
    """状态机里被当成 Task Resource 的 Lambda 逻辑 ID 集合。

    "别的 step 是谁"**不手抄**（会随状态机改）：CDK 把每个 `LambdaInvoke` 的 ARN
    渲染成 `DefinitionString` 那个 `Fn::Join` 里的一个
    `Fn::GetAtt[<函数逻辑 ID>, "Arn"]` 片段，从那里取。
    """
    sms = template.find_resources("AWS::StepFunctions::StateMachine")
    assert sms, "模板里没有状态机——本条空转"
    fn_lids = set(template.find_resources("AWS::Lambda::Function"))
    out: set[str] = set()
    for sm in sms.values():
        parts = sm["Properties"]["DefinitionString"]["Fn::Join"][1]
        for p in parts:
            ga = p.get("Fn::GetAtt") if isinstance(p, dict) else None
            if isinstance(ga, list) and len(ga) == 2 and ga[1] == "Arn" \
                    and ga[0] in fn_lids:
                out.add(ga[0])
    assert len(out) >= 5, f"状态机定义里只抽到 {len(out)} 个 Lambda——本条近乎空转"
    return out


def _resolve_arn(template, val):
    """把模板里的一个 Resource 值解析成**具体字符串**（可能带 `*` 通配）。

    返回 `None` = 解析不了。**调用处必须把 None 判成红**：本文件那条"遍历所有语句
    找 validated/ 的写方"的守卫，一旦把解析不了的 Resource 静默当成"匹配不上"，
    就正好把最需要发现的那种形态（`f"{bucket.bucket_arn}/artifacts/*"` 渲染成
    `Fn::Join`）漏掉——那是本仓库里真实存在的写法（package_project 的两条）。
    """
    if isinstance(val, str):
        return val
    if not isinstance(val, dict) or len(val) != 1:
        return None
    key, arg = next(iter(val.items()))
    if key == "Ref":
        if arg == "AWS::Partition":
            return "aws"
        props = template.find_resources("AWS::S3::Bucket").get(arg, {}).get("Properties")
        return props.get("BucketName") if props else None
    if key == "Fn::GetAtt" and isinstance(arg, list) and len(arg) == 2 and arg[1] == "Arn":
        props = template.find_resources("AWS::S3::Bucket").get(arg[0], {}).get("Properties")
        name = props.get("BucketName") if props else None
        return f"arn:aws:s3:::{name}" if isinstance(name, str) else None
    if key == "Fn::Join" and isinstance(arg, list) and len(arg) == 2 and arg[0] == "":
        parts = [_resolve_arn(template, p) for p in arg[1]]
        return None if any(p is None for p in parts) else "".join(parts)
    return None


def _iam_glob_matches(pattern: str, concrete: str) -> bool:
    """IAM 的 `*`/`?` 通配匹配（整串锚定，不是子串）。"""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                 for c in pattern)
    return re.fullmatch(rx, concrete) is not None


def _grants(template, stmts: list[dict], action: str, probe: str) -> bool:
    """`stmts` 里是否有一条 Allow 同时命中 `action` 与具体资源 `probe`。"""
    for st in stmts:
        if st.get("Effect", "Allow") != "Allow" or "NotAction" in st:
            continue
        if not any(_iam_glob_matches(a, action)
                   for a in _as_list(st.get("Action", [])) if isinstance(a, str)):
            continue
        for r in _as_list(st.get("Resource", [])):
            resolved = _resolve_arn(template, r)
            assert resolved is not None, (
                f"解析不出这个 Resource，本条会把它静默当成'匹配不上' ⇒ 空转：{r}")
            if _iam_glob_matches(resolved, probe):
                return True
    return False


def _denies(template, stmts: list[dict], action: str, probe: str) -> bool:
    """`stmts` 里是否有一条**无条件** Deny 同时盖住 `action` 与具体资源 `probe`。

    带 `Condition` 的 Deny 不算：它只在条件成立时生效，不能作为"谁都写不了"的依据。
    """
    for st in stmts:
        if st.get("Effect") != "Deny" or "Condition" in st or "NotResource" in st:
            continue
        if not any(_iam_glob_matches(a, action)
                   for a in _as_list(st.get("Action", [])) if isinstance(a, str)):
            continue
        for r in _as_list(st.get("Resource", [])):
            resolved = _resolve_arn(template, r)
            assert resolved is not None, (
                f"解析不出这个 Deny 的 Resource，本条会把它当成'没盖住' ⇒ 假红：{r}")
            if _iam_glob_matches(resolved, probe):
                return True
    return False


@pytest.fixture(scope="module")
def artifacts_probes(template):
    """artifacts 桶下三个前缀的**具体** key ARN（不是通配式），用来探策略。

    桶名与前缀都不手抄：桶名从 validate 函数的 `ARTIFACTS_BUCKET` 环境变量指到的
    桶资源取，`validated/` 从 `functions/validate.py` 的 `VALIDATED_PREFIX` 取
    （运行时代码是那个前缀的真源——改名时 IAM 与本守卫一起跟着走）。
    """
    import app as appmod
    env = template.find_resources("AWS::Lambda::Function")[
        _fn_lid_by_handler(template, "validate.handler")]["Properties"][
            "Environment"]["Variables"]
    bucket_lid = env["ARTIFACTS_BUCKET"]["Ref"]
    bucket = template.find_resources("AWS::S3::Bucket")[bucket_lid][
        "Properties"]["BucketName"]
    assert isinstance(bucket, str) and bucket, bucket
    validated = appmod._validate_const("VALIDATED_PREFIX", str)
    assert validated, "validate.py 里 VALIDATED_PREFIX 是空的"
    return {"bucket_arn": f"arn:aws:s3:::{bucket}",
            "validated_prefix": validated,
            "uploads": f"arn:aws:s3:::{bucket}/uploads/job-abc123.zip",
            "extracted": f"arn:aws:s3:::{bucket}/extracted/job-abc123/site.json",
            "validated": (f"arn:aws:s3:::{bucket}/{validated}"
                          "/job-abc123/backend-src.zip")}


def test_validate_runs_under_its_own_role_not_the_shared_exec_role(template):
    """所有 step Lambda 共用 `exec_role` 时，"只有 validate 能写 validated/"在 IAM 上
    不成立（Codex 复审 P1-a）。从模板里按 Handler 取 Role 判两半：

    · validate 的角色**不是** exec_role 那个逻辑 ID；
    · 状态机里**别的** step 仍是 exec_role。

    只断言前半句的话，"把所有 step 都换成新角色"这种退化（新角色于是又变成共用的
    宽角色）会照样绿。后半句的 step 集合从状态机的 `DefinitionString` 取，不手抄。
    """
    exec_lid = _role_lid_by_name(template, EXEC_ROLE_NAME)
    validate_role_lid = _role_lid_by_name(template, VALIDATE_ROLE_NAME)
    assert validate_role_lid != exec_lid

    fns = template.find_resources("AWS::Lambda::Function")
    validate_lid = _fn_lid_by_handler(template, "validate.handler")
    assert _fn_role_lid(fns[validate_lid]) == validate_role_lid, (
        f"validate 挂的是 {_fn_role_lid(fns[validate_lid])}，不是 {VALIDATE_ROLE_NAME}"
        "——它与兄弟步骤共用角色时，'只有它能写 validated/'在 IAM 上不成立")

    steps = _state_machine_step_fn_lids(template)
    assert validate_lid in steps, "validate 不在状态机里？后半句的比较对象不对"
    siblings = steps - {validate_lid}
    assert siblings, "状态机里除 validate 之外没有别的 step——后半句已空转"
    wrong = {lid: _fn_role_lid(fns[lid]) for lid in siblings
             if _fn_role_lid(fns[lid]) != exec_lid}
    assert not wrong, (
        f"这些兄弟步骤没在 {EXEC_ROLE_NAME} 上：{wrong}——若它们也换到了 validate "
        "的角色，那个角色就又是共用的宽角色，本项等于只改了个名字")


def test_validate_role_grants_exactly_the_four_things_it_needs(
        template, artifacts_probes):
    """新角色的语句集要**精确**，否则"独立角色"只是换了个名字。

    validate 的全部 AWS 调用面（`functions/validate.py`）：`update_job` +
    `get_job(consistent=True)`（F1 起要读 `upload_etag`）⇒ jobs 表
    UpdateItem/GetItem；`get_object` on `uploads/{job_id}.zip`；`put_object` on
    `extracted/{job_id}/*` 与 `validated/{job_id}/backend-src.zip`。就这四件事。

    锁四根轴：① 动作集**恰好**等于那四个（`s3:*`/`dynamodb:*`/`*` 都会红）；
    ② 每个 s3 资源都必须落在 `uploads|extracted|validated` 某个前缀下——桶级 ARN
    与整桶 `/*` 都不行（`ListBucket` 需要桶级 ARN，所以这一条同时把它挡在门外）；
    ③ ddb 资源恰好是 jobs 表的 ARN（不是 `table/site-*`）；
    ④ `AWSLambdaBasicExecutionRole` 挂着——**自带 `role=` 时 CDK 不会替你加**，
    漏了就静默丢日志（部署不报错，出事时没有 CloudWatch 可看）。
    """
    role_lid = _role_lid_by_name(template, VALIDATE_ROLE_NAME)
    stmts = _statements_by_role(template).get(role_lid, [])
    assert stmts, f"{VALIDATE_ROLE_NAME} 名下没有任何策略语句——本条空转"

    grants: dict[str, set[str]] = {}
    for st in stmts:
        assert st.get("Effect", "Allow") == "Allow", f"新角色不该有 Deny：{st}"
        assert "NotAction" not in st and "NotResource" not in st, st
        assert "Condition" not in st, f"条件式授权在本条里不可判定：{st}"
        for a in _as_list(st["Action"]):
            # s3 的资源在这里解析成具体串；非 s3（ddb 表是 `Fn::GetAtt`，解不出来是
            # 预期的）只登记动作名，资源在下面按原始结构比。
            hits = grants.setdefault(a, set())
            if not a.startswith("s3:"):
                continue
            resolved = {_resolve_arn(template, r) for r in _as_list(st["Resource"])}
            assert None not in resolved, f"解析不出 Resource ⇒ 无法判定：{st}"
            hits.update(resolved)

    art, validated = artifacts_probes["bucket_arn"], artifacts_probes["validated_prefix"]
    assert set(grants) == {"s3:GetObject", "s3:PutObject",
                           "dynamodb:GetItem", "dynamodb:UpdateItem"}, (
        f"动作集不精确：{sorted(grants)}")
    assert grants["s3:GetObject"] == {f"{art}/uploads/*"}, grants["s3:GetObject"]
    assert grants["s3:PutObject"] == {f"{art}/extracted/*",
                                      f"{art}/{validated}/*"}, grants["s3:PutObject"]

    # ddb：`_resolve_arn` 只解 S3，表的 `Fn::GetAtt` 解不出来是预期的，所以这两项按
    # **原始结构**比——期望值里的逻辑 ID 来自环境变量那一侧，不是策略这一侧。
    jobs_lid = template.find_resources("AWS::Lambda::Function")[
        _fn_lid_by_handler(template, "validate.handler")]["Properties"][
            "Environment"]["Variables"]["JOBS_TABLE"]["Ref"]
    want_ddb = {"Fn::GetAtt": [jobs_lid, "Arn"]}
    for st in stmts:
        for a in _as_list(st["Action"]):
            if a.startswith("dynamodb:"):
                assert _as_list(st["Resource"]) == [want_ddb], (
                    f"{a} 的资源不是 jobs 表本身：{st['Resource']}")

    props = template.find_resources("AWS::IAM::Role")[role_lid]["Properties"]
    assert BASIC_EXEC_MANAGED_POLICY in (props.get("ManagedPolicyArns") or []), (
        f"{VALIDATE_ROLE_NAME} 没挂 AWSLambdaBasicExecutionRole——自带 role= 时 CDK "
        f"不会替你加：{props.get('ManagedPolicyArns')}")


def test_nobody_but_validate_can_write_the_validated_prefix(
        template, artifacts_probes):
    """本项的交付物就是这句话，所以按模板判它，而不是靠注释声明。

    遍历**每个角色名下的全部**策略语句（独立 `AWS::IAM::Policy` + 角色内联
    `Policies`，见 `_statements_by_role`），拿一个**具体的** validated/ key ARN 当
    探针去匹配（通配式资源如 `…-{ACCOUNT}/*` 会命中，正是要抓的那种）。任何 Allow
    了 `s3:PutObject` 的角色，除 validate 自己之外，都必须在**同一个角色**上另有一
    条无条件 Deny 盖住 validated/ 的 Put 与 Delete。

    exec_role 就是那种情况：它对整个 artifacts 桶的 Allow **保留**给别的步骤
    （`deploy_lambda_site` 读 artifacts/*、`upload_frontend` 与 `provision_dsql` 读
    extracted/*、`mark_job`/`undeploy` 删前端桶），靠 Deny 精确挖掉两个前缀。

    **`extracted/` 与 `validated/` 都要判**（Ruling 26 的同一课，实测过）：exec_role
    的那条 Deny 的 `resources` 是一个**两元素列表**，那就是两根独立的自由度。此前只拿
    validated/ 探针判，于是把 Deny 收窄成 `[validated/*]` 一项时 **33 passed**——而那
    一步等于让每个兄弟步骤重新能覆写 `extracted/`（validate 已校验的那棵树），
    `provision_dsql` 按前缀列举 migrations、`upload_frontend` 按前缀发布前端，都会读到
    被改过的字节。两个前缀同为 validate 的输出，判据必须逐个前缀各走一遍。

    **本条只管身份策略。** 资源策略那侧另判一次：artifacts 桶的 bucket policy 不许
    给任何主体 `s3:PutObject`（CDK 的 `auto_delete_objects` 会在那里留一条
    `s3:DeleteObject*` 给它自己的清理角色——那是删桶时的 teardown 授权，只删不写，
    故意不在本条的作用面内）。
    """
    validate_role_lid = _role_lid_by_name(template, VALIDATE_ROLE_NAME)
    by_role = _statements_by_role(template)
    assert by_role, "模板里一条角色策略语句都抽不到——本条空转"
    roles = template.find_resources("AWS::IAM::Role")

    for prefix in ("validated", "extracted"):
        probe = artifacts_probes[prefix]
        writers = {lid for lid, stmts in by_role.items()
                   if _grants(template, stmts, "s3:PutObject", probe)}
        assert writers, (f"没有任何角色能写 {prefix}/——连 validate 自己都不能？"
                         "本条已空转，先查 _grants 与探针")
        assert validate_role_lid in writers, \
            f"{VALIDATE_ROLE_NAME} 自己都写不了 {prefix}/"

        for lid in writers - {validate_role_lid}:
            name = roles.get(lid, {}).get("Properties", {}).get("RoleName") or lid
            for act in ("s3:PutObject", "s3:DeleteObject"):
                assert _denies(template, by_role[lid], act, probe), (
                    f"{name} 的 Allow 能命中 {probe} 而它没有一条无条件 Deny 盖住 "
                    f"{act}——'只有 validate 能写 {prefix}/'在 IAM 上不成立")

        for pol in template.find_resources("AWS::S3::BucketPolicy").values():
            for st in pol["Properties"]["PolicyDocument"]["Statement"]:
                assert not _grants(template, [st], "s3:PutObject", probe), (
                    f"桶策略把 {prefix}/ 的写授给了 {st.get('Principal')}——"
                    f"身份策略那侧收紧了也没用：{st.get('Action')}")


def test_rollup_runs_daily_and_has_a_dlq(template):
    rules = template.find_resources("AWS::Events::Rule")
    hit = [r for r in rules.values()
           if r["Properties"].get("Name") == "site-access-rollup-daily"]
    assert len(hit) == 1, f"找不到 site-access-rollup-daily：{list(rules)}"
    props = hit[0]["Properties"]
    assert props["ScheduleExpression"] == "cron(20 0 * * ? *)", props["ScheduleExpression"]
    assert props["State"] == "ENABLED"
    target = props["Targets"][0]
    assert "DeadLetterConfig" in target, "rollup 的 target 没有 DLQ"
