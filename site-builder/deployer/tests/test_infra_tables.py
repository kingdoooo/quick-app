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


def test_access_events_replicas_all_have_pitr(template):
    """明细表（`TableV2` → `AWS::DynamoDB::GlobalTable`）**每个副本**都要开 PITR。

    **属性形状与普通表不同，必须读渲染后的模板**：`AWS::DynamoDB::Table` 的
    `PointInTimeRecoverySpecification` 在顶层，而 GlobalTable 的在**每个 replica
    里各一份**（CDK 的表级 prop 会分发到含主副本在内的每个 replica）。拿 Table
    那个形状去断言 GlobalTable 会永远查不到那个键 → 用例空转，而两侧都"绿"。

    本表按设计是 DESTROY（90 天滚动明细），所以它**不在**上面那条 RETAIN 不变量
    的范围里——这里显式点名，理由是它是聚合表的**重建来源**："只要明细还在，数就
    还能算回来"（模块 docstring 与 spec §0.1 用来否掉日志侧聚合的正是这条属性）
    只在明细自己没被写坏时成立。PITR 又是**按副本**计费与恢复的，所以要求每个副本
    都有：只在一个区开，另外两个区被写坏时没有可回溯的点。
    """
    gts = [t for t in template.find_resources("AWS::DynamoDB::GlobalTable").values()
           if t["Properties"].get("TableName") == "site-access-events"]
    assert len(gts) == 1, f"site-access-events 不是恰好一张 GlobalTable：{gts}"
    replicas = gts[0]["Properties"]["Replicas"]
    assert len(replicas) == 3, replicas      # 少一个副本另有 test 管，这里防空转
    missing = sorted(r["Region"] for r in replicas
                     if (r.get("PointInTimeRecoverySpecification") or {}
                         ).get("PointInTimeRecoveryEnabled") is not True)
    assert not missing, (
        f"这些副本没开 PITR: {missing}。明细是聚合表的重建来源，写坏之后"
        "「重算即修复」就不成立了；GlobalTable 的 PITR 是按副本设的。")


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
    # 阈值 0 = 一天内 ≥1 条失败即计入（实测全区合计 ≈2.6 次写入/天，
    # 起步值 10 那类阈值连 100% 失败都凑不满）
    assert props["Threshold"] == 0, props
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
