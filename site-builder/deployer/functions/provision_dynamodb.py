"""SFN 步骤 2a：按 manifest 声明创建站点 DynamoDB 表（幂等）。

**两阶段：先全量预检（零写入），再逐张创建。** 不是为了整洁，是两条实测缺陷：

① `ResourceInUseException` 曾被 `pass` 掉，等于把"表已经存在"当成"这是我上次建的"。
   在表名可跨站点碰撞的年代（见 `common.site_table_name`），这一步会把**别人的表**
   接管进本站的 `data_tables` 与 per-site IAM 策略，随后 `purge_data` 还会删掉它。
   现在撞到已有表必须过 `common.assert_table_owned_by_site`（tag + schema）。

② 逐表循环 + 循环末尾才写 `data_tables` ⇒ 第 1 张建成、第 2 张失败时，第 1 张成了
   **未托管的孤儿表**：sites 行里没有它，`purge_data` 也找不到它。这与碰撞无关，
   在干净环境里同样可达（限流、waiter 超时、自家旧表 schema 不符）。所以把所有
   "可能失败的判断"提到任何 `CreateTable` 之前。

**残留（不假装已闭环）**：阶段二**中途**失败仍可能留下本轮已建的表——那需要补偿删除，
是独立的设计面。此时异常信息会列出本轮已建的表名，供人工处置。
"""
import re

import boto3

import common

# Lambda 环境变量键的合法形态。表名会派生出 `TABLE_<NAME>`，而 Lambda 不接受 `-`。
# 合同侧的 `TABLE_NAME_RE` 已经禁掉 `-`，这里是 fail-fast 兜底：让它在**建表之前**
# 失败，而不是等到 `deploy_lambda_site` 写 Lambda 配置时（那时表已经建出来了）。
_ENV_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def _env_key(logical: str) -> str:
    key = f"TABLE_{logical.upper()}"
    if not _ENV_KEY_RE.fullmatch(key):
        raise common.InvalidTableName(
            f"逻辑表名 {logical!r} 会派生出非法的 Lambda 环境变量键 {key!r}"
            "（只允许字母、数字、下划线，且以字母开头）")
    return key


def _wait_active(ddb, table_name: str) -> None:
    """有界地等一张**已存在**的表到 ACTIVE。等不到就抛（fail-closed）。

    上限约 2 分钟/表：本步骤的 Lambda 超时是 300s（infra/app.py 的 step_fn），
    正常路径（表早已 ACTIVE）首次 describe 即返回，只有 CREATING/DELETING
    这类罕见形态才会真的等。
    """
    ddb.get_waiter("table_exists").wait(
        TableName=table_name, WaiterConfig={"Delay": 5, "MaxAttempts": 24})


def handler(event, context):
    common.update_job(event["job_id"], phase="provision-db")
    ddb = boto3.client("dynamodb")
    site_id = event["site_id"]
    specs = event["manifest"]["database"].get("tables", [])

    # ── 阶段一：全量预检，零写入 ────────────────────────────────────────
    plan = []          # [(logical, 物理名, 环境变量键, 是否需要创建, key_schema, attr_defs)]
    for spec in specs:
        logical = spec["name"]
        # site_table_name 会拒掉含 `-` 的 logical（跨站点碰撞的必要条件）
        table_name = common.site_table_name(site_id, logical)
        env_key = _env_key(logical)
        key_schema = [{"AttributeName": spec["pk"], "KeyType": "HASH"}]
        attr_defs = [{"AttributeName": spec["pk"], "AttributeType": "S"}]
        try:
            ddb.describe_table(TableName=table_name)
        except ddb.exceptions.ResourceNotFoundException:
            plan.append((logical, table_name, env_key, True, key_schema, attr_defs))
            continue
        # 已存在：必须确认是本站的、且 schema 与本次声明一致，否则中止。
        # 抛出的 TableOwnershipUnconfirmed 会让整个 provision 步骤失败，
        # 于是**既不写 data_tables、也走不到 ensure_site_role**。
        common.assert_table_owned_by_site(
            ddb, site_id, logical,
            expect_key_schema=key_schema,
            expect_attribute_definitions=attr_defs)
        # 归属正确 ≠ 就绪：上一次运行可能在 create 成功后、waiter 处中断，重试
        # 看到的是 CREATING 的表；不等就会把它当完成、直落 data_tables 并进
        # Lambda 部署（存量缺口，非 8f8b0c6 回归——旧代码撞 ResourceInUse 时
        # 同样不跑 waiter）。DELETING 的表则在这里有界超时、fail-closed。
        # waiter 仍是只读，不破坏"阶段一零写入"。
        _wait_active(ddb, table_name)
        plan.append((logical, table_name, env_key, False, key_schema, attr_defs))

    # ── 阶段二：预检全过，才开始建表 ────────────────────────────────────
    created = []
    for logical, table_name, _env_key_, need_create, key_schema, attr_defs in plan:
        if not need_create:
            continue
        try:
            ddb.create_table(
                TableName=table_name,
                KeySchema=key_schema,
                AttributeDefinitions=attr_defs,
                BillingMode="PAY_PER_REQUEST",
                Tags=[{"Key": "project", "Value": common.SITE_TAG_PROJECT},
                      {"Key": "site_id", "Value": site_id}])
            ddb.get_waiter("table_exists").wait(TableName=table_name)
            created.append(table_name)
        except ddb.exceptions.ResourceInUseException:
            # 预检时它还不存在，现在存在了 ⇒ 与另一次并发部署撞上。仍要核归属，
            # 不能 pass：并发的另一方也可能是**别的站点**。
            common.assert_table_owned_by_site(
                ddb, site_id, logical,
                expect_key_schema=key_schema,
                expect_attribute_definitions=attr_defs)
            # 并发方的表同样要等到 ACTIVE（与阶段一的已存在路径同一条理由）
            _wait_active(ddb, table_name)
        except Exception as exc:              # noqa: BLE001 中途失败要报出已建的表
            raise RuntimeError(
                f"建表 {table_name} 失败（{type(exc).__name__}: {exc}）。"
                f"本轮**已经建出**这些表且尚未记入 data_tables，需人工处置："
                f"{created or '无'}") from exc

    env_vars = event.get("env_vars", {})
    for logical, table_name, env_key, *_ in plan:
        env_vars[env_key] = table_name
    event["env_vars"] = env_vars
    # 记下已建表的逻辑名，供 undeploy --purge_data 精确删除。
    # 不能靠 ListTables 反查：该动作不支持资源级限定，授权它等于放开全账号表枚举。
    names = [logical for logical, *_ in plan]
    if names:
        common.upsert_site(site_id, data_tables=names)
    return event
