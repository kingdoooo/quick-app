#!/usr/bin/env python3
"""Deployer 基础设施：任务/站点表、产物桶、CodeBuild 打包项目、执行角色。
状态机定义在 Task 17 追加到本 stack。"""
import ast
import configparser
from pathlib import Path

from aws_cdk import (App, CfnOutput, Duration, Environment, RemovalPolicy, Size,
                     Stack,
                     aws_cloudwatch as cw,
                     aws_cloudwatch_actions as cw_actions,
                     aws_codebuild as cb, aws_dynamodb as ddb,
                     aws_events as events, aws_events_targets as targets,
                     aws_iam as iam, aws_lambda as lam_,
                     aws_lambda_destinations as destinations, aws_s3 as s3,
                     aws_sns as sns, aws_sqs as sqs, aws_stepfunctions as sfn,
                     aws_stepfunctions_tasks as tasks)
from constructs import Construct

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parents[2] / "config.ini")
ACCOUNT = CFG["Platform"]["account_id"]
REGION = CFG["Platform"]["region"]


def _rollup_const(name: str, kind: type = str):
    """从 `functions/access_rollup.py` 里读一个模块级常量，**不 import**
    （import 需要 boto3，而 `infra/.venv` 只有 CDK 依赖）。

    IAM 里的日志组前缀与指标 namespace 必须与运行时用的是**同一个字面量**：
    手抄第二份就是下一次「两侧单测都绿、线上 AccessDenied」。同理内存/超时要与
    运行时的线程数、扫描预算对得上（`kind=int` 的那几个）。
    """
    src = (Path(__file__).parents[1] / "functions" / "access_rollup.py").read_text(
        encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == name
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, kind)):
            return node.value.value
    raise RuntimeError(f"access_rollup.py 里找不到 {kind.__name__} 常量 {name}")


def _validate_const(name: str, kind=str):
    """从 functions/validate.py 取常量——磁盘尺寸的单一真源（同 _rollup_const）。"""
    src = (Path(__file__).parents[1] / "functions" / "validate.py").read_text(
        encoding="utf-8")
    for node in ast.parse(src).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == name):
            # 允许字面量与 `200 * 1024 * 1024` 这样的常量表达式
            return kind(eval(compile(ast.Expression(node.value), "<c>", "eval")))
    raise RuntimeError(f"validate.py 里找不到常量 {name}")


# validate 的 /tmp 尺寸。**下界是合同的解包上界**（`MAX_UNPACKED_BYTES`）：
# `extractall` 把整棵树写进 TemporaryDirectory = Lambda 的 /tmp。上界与磁盘绑在
# 一条式子上，调大上界不同时调大磁盘 ⇒ CDK 断言红
# （test_validate_disk_covers_the_unpacked_size_limit），同 rollup 的
# SCAN_WORKERS ↔ 内存那条。
# **2 倍是两项之和**，不是拍出来的余量：/tmp 上同时有解包出来的整棵树，以及
# `_pack_build_input` 重新打包出来的工件（run.sh + backend/ 子集，最坏情况几乎
# 与树同量级——已压缩过的资产再压不动）。二者各 ≤ 上界 ⇒ 下界 = 上界 × 2。
# 顺带的余量也用得上：那道上界预检查看的是 zip 里**声明的** file_size，落盘的却是
# 实际写出的字节，刚好卡在声明值上时症状会从 ContractViolation（说得清是用户包
# 太大）退化成 ENOSPC（读起来像平台故障）。
# 内存那条轴**本常量管不到**，但它已经不是全无上界了：下载下来的上传包由
# `validate.MAX_UPLOAD_BYTES` 在 `read()` **之前**按 ContentLength 兜住（Task F1；
# 在那之前它无常量可绑）。仍无上界的只剩 extracted/ 上传循环里**当下那一个文件**的
# 字节——单文件最坏只被 `MAX_UNPACKED_BYTES` 那道（按 zip 声明值算的）总量预检查间接
# 兜着，而 step_fn 给的是 memory_size=512。这一条仍是 M7 遗留项，另有跟进任务。
VALIDATE_EPHEMERAL_MB = 1024

# CodeBuild 的唯一输入前缀，**真源是运行时代码**（`validate.VALIDATED_PREFIX`）。
# 下面三处都用它：validate 自己那个窄角色的 PutObject、exec_role 上把这个前缀挖掉
# 的 Deny、以及 package_project 的 GetObject。手抄成字面量的话，改前缀就会得到
# "代码写 A、IAM 管 B"——那种错在部署前不报，出事时表现为运行期 AccessDenied 或
# （更糟）Deny 落空而没人知道。绑在一个常量上让这一类错在**结构上**不成立。
VALIDATED_PREFIX = _validate_const("VALIDATED_PREFIX")

EDGE_LOG_GROUP_PREFIX = _rollup_const("EDGE_LOG_GROUP_PREFIX")
ROLLUP_METRIC_NAMESPACE = _rollup_const("METRIC_NAMESPACE")
ROLLUP_METRIC_NAME = _rollup_const("METRIC_NAME")

# ── rollup 的内存与时限 ────────────────────────────────────────────────
# **内存下界由扫描线程数决定，不由区数决定**：跨区扫描每个线程持一个 boto3
# Session（各自一份 botocore endpoints/服务模型），见 `access_rollup._logs_client`。
# 2026-08-15 的线上回归就是这条没成立时的样子——那时是"每区一个 Session"，18 个
# 已启用区把 256MB 顶穿（六次 REPORT 全部 used≈256/256MB，约一半调用
# `Runtime.OutOfMemory`）。所以这里的两个常量都从**实测**来，且与运行时的
# `SCAN_WORKERS` 绑在一条式子上：调大线程数不同时调大内存 ⇒ CDK 断言红
# （`test_rollup_memory_is_sized_for_its_scan_threads`）。
ROLLUP_SCAN_WORKERS = _rollup_const("SCAN_WORKERS", int)
ROLLUP_SCAN_BUDGET_SECONDS = _rollup_const("SCAN_BUDGET_SECONDS", int)
ROLLUP_TIMEOUT_SECONDS = 300
# 下面三个数**全部来自真机 REPORT 的 Max Memory Used**（2026-08-15，先按 1024MB
# 探测再定尺寸，不猜）：
#   · 冷容器第一次调用峰值 202MB；
#   · 同一个热容器连打 21 次，峰值单调涨到 434MB 后**收平**（最后四次都是 434）
#     ——`Max Memory Used` 是容器生命周期的高水位，每轮新建 8 个线程/Session、
#     反复分配再释放，让高水位收敛在这里；不是泄漏（泄漏会按每轮 +100MB 线性涨）。
#     线上每天只跑一次（容器必然是冷的），但闸门脚本与手工重跑会连打，所以
#     **按 434MB 定尺寸**。
# 拆成"基线 + 每线程"是为了让式子随 `SCAN_WORKERS` 走：
ROLLUP_MEM_BASE_MB = 110        # 202 − 8 个 Session（各实测 ≈12MB）≈ 103，取整 110
ROLLUP_MEM_PER_WORKER_MB = 40   # (434 热态收平 − 110) / 8 ≈ 40.5
ROLLUP_MEM_HEADROOM = 2         # 建模峰值之上的余量倍数
ROLLUP_MEMORY_MB = 1024         # = 实测热态峰值 434MB 的 2.36 倍

# 告警通知的 SNS topic。**建者不是本栈**——它由 `auth/deploy_auth.py`
# （`alarm_pipeline.py`）幂等收敛，连带那个必须由收件人手工确认的邮件订阅。
# 本栈**只按名字引用**：两个创建方就是两个真源，症状是告警照样进 ALARM 而
# 没有任何人收到通知（已确认的订阅挂在另一个 topic 上）。
# 两侧字面量由 test_alarm_topic_name_matches_the_script_that_creates_it 跨文件钉住。
ALARM_TOPIC_NAME = "site-builder-alarms"

# **PITR 只防"写坏"这一类**，与 RETAIN / deletion_protection / TTL 都不重叠：
#   · RETAIN 只在删栈/替换资源时起作用；
#   · deletion_protection 挡直接 `DeleteTable`；
#   · 三者对"一次错的覆盖写"毫无作用。
# 而 rollup 的设计**就是**反复覆盖同一批行，`site-access-daily` 的 400 天历史在
# 明细 90 天 TTL 到期后不可重建 ⇒ 写坏之后没有 PITR 就只剩"接受错的数字"。
# 凡 RETAIN 的表都加（= 已经声明过"这份数据不能丢"），由
# test_every_retained_table_has_pitr 按 DeletionPolicy 推导校验，新增 RETAIN 表
# 自动被要求。明细表虽然是 DESTROY 也加：它是聚合表的重建来源。
_PITR = ddb.PointInTimeRecoverySpecification(point_in_time_recovery_enabled=True)

# 平台自己的 Lambda。**精确名，不用通配**：`site-auth-*` 会命中用户站点
# site-auth-tool-x1y2z3（站点名保留前缀由 common.RESERVED_SITE_NAME_PREFIXES 兜，
# 但策略侧不该依赖那条校验的历史生效时间）。
# 本栈创建的那 13 个由 test_platform_function_name_list_matches_what_creates_them
# 按模板核对；另 4 个由别的部署脚本创建（panel / key-proxy / auth），同一条断言从
# 那三个脚本的源码里 AST 抽函数名核对——任一侧改名都红，名单不会静默变陈旧。
PLATFORM_FUNCTION_NAMES = (
    "site-panel", "site-key-proxy", "site-auth-service", "site-auth-pre-token",
    "site-access-rollup",
    "site-deployer-validate", "site-deployer-package_backend",
    "site-deployer-deploy_lambda_site", "site-deployer-register_route",
    "site-deployer-upload_frontend", "site-deployer-smoke_test",
    "site-deployer-mark_job", "site-deployer-provision_dsql",
    "site-deployer-provision_dynamodb", "site-deployer-undeploy",
    "site-deployer-reconcile-job", "site-deployer-sweep-jobs",
)


class SiteDeployerStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw):
        super().__init__(scope, cid, **kw)

        jobs = ddb.Table(self, "Jobs", table_name="site-deploy-jobs",
                         partition_key=ddb.Attribute(name="job_id", type=ddb.AttributeType.STRING),
                         billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                         removal_policy=RemovalPolicy.DESTROY)
        jobs.add_global_secondary_index(
            index_name="owner-index",
            partition_key=ddb.Attribute(name="owner", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="created_at", type=ddb.AttributeType.STRING))
        # 二期 M3：控制台的"部署历史"按 site_id 查。owner-index 是**发起者**
        # 维度（jobs.owner = requested_by），查不出"这个站点的所有部署"——
        # 协作者发起的部署 owner 是协作者。
        jobs.add_global_secondary_index(
            index_name="site-index",
            partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="created_at", type=ddb.AttributeType.STRING))
        sites = ddb.Table(self, "Sites", table_name="site-sites",
                          partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                          removal_policy=RemovalPolicy.DESTROY)
        # 二期：list_my_sites / 控制台按 owner 查（替掉全表 Scan）。
        # 无 sort key——站点数量级小，按 owner 一次 query 即可。
        sites.add_global_secondary_index(
            index_name="owner-index",
            partition_key=ddb.Attribute(name="owner", type=ddb.AttributeType.STRING))

        # 二期：平台管理员名单。首个管理员由 deploy 脚本从 config.ini
        # [Platform] admin_seed 幂等注入；之后由控制台增删（不走重部署）。
        # RETAIN 是有意为之：名单误删会让平台失去管理入口，与 jobs/sites 的
        # DESTROY 语义不同——删栈时保留此表。
        # `deletion_protection` 与 RETAIN 是两道不同的保护，见 api_keys 处的
        # 长注释。**不变量**：凡是设了 RETAIN 的表（= 我们已经判定"这份数据不能
        # 丢"），都要一并挡住直接 `DeleteTable`——否则 RETAIN 只是挡了删栈，一条
        # aws CLI 照样能删掉它。由 test_every_retained_table_has_deletion_protection
        # 按模板里的 DeletionPolicy 推导校验，新增 RETAIN 表时会自动要求这一条。
        admins = ddb.Table(self, "Admins", table_name="site-admins",
                           partition_key=ddb.Attribute(name="email",
                                                       type=ddb.AttributeType.STRING),
                           billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                           deletion_protection=True,
                           point_in_time_recovery_specification=_PITR,
                           removal_policy=RemovalPolicy.RETAIN)

        # 二期 M3：操作审计（append-only）。写入方只被授予 PutItem。
        # RETAIN 与 admins 同理：审计记录误删会丢失合规证据。
        ops_log = ddb.Table(
            self, "OpsLog", table_name="site-ops-log",
            partition_key=ddb.Attribute(name="target", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="ts_actor", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            deletion_protection=True,        # 同上：RETAIN 挡不住 DeleteTable
            point_in_time_recovery_specification=_PITR,
            removal_policy=RemovalPolicy.RETAIN)

        # 二期 M3：面板会话升级的一次性 code 消费标记（jti）。
        # DESTROY（不同于 ops_log）：60 秒 TTL 的一次性标记，删栈丢掉无害。
        session_codes = ddb.Table(
            self, "SessionCodes", table_name="site-session-codes",
            partition_key=ddb.Attribute(name="jti", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            removal_policy=RemovalPolicy.DESTROY)

        # 二期 M4：API Key。PK 是 **key_hash**（SHA-256(明文)）而不是 key_id
        # ——库被读走时攻击者只拿到哈希，反推不出可用的 Key（spec §5.1）。
        # RETAIN 与 admins/ops_log 同理：这是凭证表，误删等于全体 Key 用户断服，
        # 而且**无法恢复**（服务端不存明文，用户手里的 Key 再也对不上任何行）。
        # **`deletion_protection` 与 `RemovalPolicy.RETAIN` 防的不是同一件事**，
        # 两个都要（2026-08-13 补）：
        #   · RETAIN 只在**删栈/替换资源**时起作用——CloudFormation 不删这张表；
        #   · deletion_protection 挡的是**直接调 `DeleteTable`**：控制台点删除、
        #     一条 aws CLI、任何拿到 `dynamodb:DeleteTable` 的脚本或自动化。
        #     开了之后必须先显式关掉保护才能删，多一道人工确认。
        # 对这张表值得多花这一道：它是凭证表，误删**无法恢复**——服务端不存明文，
        # 用户手里的 Key 再也对不上任何行，而且症状是"全体 Key 用户同时断服"。
        # 代价：`cdk destroy` 会在这张表上失败，要先手工关保护。这是有意的取舍。
        api_keys = ddb.Table(
            self, "ApiKeys", table_name="site-api-keys",
            partition_key=ddb.Attribute(name="key_hash",
                                        type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            deletion_protection=True,
            point_in_time_recovery_specification=_PITR,
            removal_policy=RemovalPolicy.RETAIN)
        # 控制台按人列 Key。
        api_keys.add_global_secondary_index(
            index_name="email-index",
            partition_key=ddb.Attribute(name="email",
                                        type=ddb.AttributeType.STRING))
        # **吊销必须靠它**（计划级补充 A）：POST /api/keys/revoke 拿到的是 key_id，
        # 而 PK 是 key_hash。没有这个 GSI 就只能全表 Scan，而吊销路径必须先
        # 查到该行的 email 与调用者比对（"只能吊销自己的"）——Scan 在这条
        # 路径上既慢又容易写成"扫到就删"。
        api_keys.add_global_secondary_index(
            index_name="keyid-index",
            partition_key=ddb.Attribute(name="key_id",
                                        type=ddb.AttributeType.STRING))

        # 二期 M5：访问明细。**Global Table（3 区）**——Edge 写它执行区的本地
        # 副本。实测跨区写 229ms / 同区 6ms（spec §0.1、§0.4），97% 的代价是
        # 那条跨太平洋的腿，不是"同步写"本身。副本区集合与
        # router/config.ini 的 access_replica_regions 必须一致，由
        # test_stack_edge_iam.py 从同一份清单推导锁死（漏一个 = 该区静默零数据）。
        #
        # 用 TableV2 而不是给 Table 配 replication_regions：后者是自定义资源。
        # 本表是仓库里唯一的多区表，引入第二种构造类型是有意的局部选择。
        #
        # DESTROY（不同于 daily）：90 天滚动明细，删栈丢掉可接受。所以它**不进**
        # RETAIN⇒deletion_protection 那条不变量的范围。
        access_events = ddb.TableV2(
            self, "AccessEvents", table_name="site-access-events",
            partition_key=ddb.Attribute(name="site_date",
                                        type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="ts_id", type=ddb.AttributeType.STRING),
            billing=ddb.Billing.on_demand(),
            time_to_live_attribute="expires_at",
            replicas=[ddb.ReplicaTableProps(region="ap-southeast-1"),
                      ddb.ReplicaTableProps(region="ap-northeast-1")],
            # TableV2 的表级 PITR 会分发到**含主副本在内的每个** replica
            # （GlobalTable 的 PITR 是逐副本属性，只在一个区开等于另两个区没有
            # 可回溯的点）。由 test_every_global_table_replica_has_pitr 逐副本钉
            # ——**逐个**副本，不是"有一个开了就算"（反向验证里单独注入过：只把
            # ap-southeast-1 那个副本关掉，那条断言要能只点出这一个区）。
            point_in_time_recovery_specification=_PITR,
            removal_policy=RemovalPolicy.DESTROY)

        # 二期 M5：日聚合。RETAIN + deletion_protection 与 ops_log/admins 同理
        # ——400 天趋势**一旦丢不可重建**（明细只活 90 天）。写入方只有 rollup。
        access_daily = ddb.Table(
            self, "AccessDaily", table_name="site-access-daily",
            partition_key=ddb.Attribute(name="site_id",
                                        type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="date", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            deletion_protection=True,
            point_in_time_recovery_specification=_PITR,
            removal_policy=RemovalPolicy.RETAIN)

        artifacts = s3.Bucket(self, "Artifacts", bucket_name=f"site-artifacts-{ACCOUNT}",
                              block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                              removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True,
                              lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(30))])

        # 站点运行时权限边界：per-site 角色（site-rt-*，Task 15 动态创建）的能力上限。
        # 站点代码不可信——boundary 限制其最坏情况能力面；精确资源由各角色 inline policy 再收窄。
        runtime_boundary = iam.ManagedPolicy(
            self, "SiteRuntimeBoundary", managed_policy_name="site-runtime-boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                             "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
                    resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-data-*"]),
                iam.PolicyStatement(actions=["dsql:DbConnect"], resources=["*"]),
                iam.PolicyStatement(
                    actions=["logs:CreateLogGroup", "logs:CreateLogStream",
                             "logs:PutLogEvents"],
                    resources=[f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/site-*"]),
            ])

        package_project = cb.Project(
            self, "PackageProject", project_name="site-package",
            build_spec=cb.BuildSpec.from_asset(
                str(Path(__file__).parents[1] / "buildspec-package.yml")),
            environment=cb.BuildEnvironment(
                build_image=cb.LinuxBuildImage.STANDARD_7_0,
                compute_type=cb.ComputeType.SMALL),
            timeout=Duration.minutes(15))
        # 构建容器跑的是不可信站点的依赖安装：只读 validated/*（validate 产出的
        # 不可变工件）、只写 artifacts/*，且不给 ListBucket 与 DeleteObject。
        # **不能改成"从 extracted/ 递归拷贝"**：aws s3 cp --recursive 必须
        # ListObjectsV2 = 要 ListBucket = 让构建容器能枚举所有 job。
        package_project.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[f"{artifacts.bucket_arn}/{VALIDATED_PREFIX}/*"]))
        package_project.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{artifacts.bucket_arn}/artifacts/*"]))

        exec_role = iam.Role(self, "DeployerExecRole", role_name="site-deployer-exec-role",
                             assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                             managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                 "service-role/AWSLambdaBasicExecutionRole")])
        for stmt in [
            iam.PolicyStatement(  # 站点 Lambda 的创建/更新，限 site- 前缀
                # GetFunctionConfiguration 是 function_updated/function_active waiter
                # 实际轮询的 API（不是 GetFunction）——缺它每次部署都 AccessDenied。
                actions=["lambda:CreateFunction", "lambda:UpdateFunctionCode",
                         "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
                         "lambda:GetFunctionConfiguration",
                         "lambda:CreateFunctionUrlConfig", "lambda:GetFunctionUrlConfig",
                         "lambda:AddPermission", "lambda:RemovePermission",
                         "lambda:DeleteFunction",
                         "lambda:DeleteFunctionUrlConfig", "lambda:GetLayerVersion",
                         "lambda:TagResource"],
                resources=[f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:site-*",
                           "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"]),
            iam.PolicyStatement(  # 仅 CreateRole 强制 boundary：iam:PermissionsBoundary 这个
                # condition key 只在 CreateRole/PutRolePermissionsBoundary 请求上下文存在，
                # 其他 iam 动作带此条件会因 key 缺失被 StringEquals 判 false 而拒绝。
                actions=["iam:CreateRole"],
                resources=[f"arn:aws:iam::{ACCOUNT}:role/site-rt-*"],
                conditions={"StringEquals": {
                    "iam:PermissionsBoundary": runtime_boundary.managed_policy_arn}}),
            iam.PolicyStatement(  # 其余角色管理动作无条件——角色创建时已被 boundary 封顶，
                # PutRolePolicy 授的权也超不出 boundary 交集，无条件是安全的。
                actions=["iam:GetRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                         "iam:AttachRolePolicy", "iam:DeleteRole", "iam:PassRole",
                         "iam:TagRole", "iam:ListRolePolicies"],
                resources=[f"arn:aws:iam::{ACCOUNT}:role/site-rt-*"]),
            iam.PolicyStatement(  # 站点数据表 + 任务/站点/路由表
                actions=["dynamodb:*"],
                resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-*",
                           f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-*/index/*",
                           f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{CFG['Platform']['routing_table']}"]),
            iam.PolicyStatement(actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                         "s3:ListBucket"],
                                resources=[f"arn:aws:s3:::site-artifacts-{ACCOUNT}",
                                           f"arn:aws:s3:::site-artifacts-{ACCOUNT}/*",
                                           f"arn:aws:s3:::site-frontend-{ACCOUNT}",
                                           f"arn:aws:s3:::site-frontend-{ACCOUNT}/*"]),
            iam.PolicyStatement(actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                                resources=[package_project.project_arn]),
            # DbConnectAdmin 仅用于引导 schema/role；DbConnect 用于以 per-site
            # migrator role 执行站点提交的 SQL（不可信 SQL 不碰 admin 身份）。
            iam.PolicyStatement(actions=["dsql:DbConnectAdmin", "dsql:DbConnect"],
                                resources=["*"]),
            iam.PolicyStatement(  # 站点日志组生命周期：建站预建+设保留期，下线删除。
                # 限 /aws/lambda/site-* 前缀；DeleteLogGroup 只能删站点自己的组。
                actions=["logs:CreateLogGroup", "logs:PutRetentionPolicy",
                         "logs:DeleteLogGroup"],
                resources=[f"arn:aws:logs:{REGION}:{ACCOUNT}:"
                           "log-group:/aws/lambda/site-*"]),
            iam.PolicyStatement(  # **存量过度授权的兜底**：site-* 同时匹配平台自己的
                # 17 个函数，于是部署器一直能覆写 site-panel / site-auth-service
                # 的代码。Deny 胜过 Allow，所以这一条把上面那些 site-* 的 Allow
                # 精确挖掉平台部分，用户站点不受影响。
                effect=iam.Effect.DENY,
                actions=["lambda:*"],
                resources=[f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{n}"
                           for n in PLATFORM_FUNCTION_NAMES]
                          + [f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{n}:*"
                             for n in PLATFORM_FUNCTION_NAMES]),
            iam.PolicyStatement(  # **validate 产物的写入面收口**（Codex 复审 P1-a）：
                # 上面那条整桶 Allow 让**每个** step Lambda 都能写 validated/ 与
                # extracted/，于是 validate.py 里"本前缀由 validate 独占"这句话在
                # IAM 上不成立。validate 现在走自己的窄角色（下面的 validate_role），
                # exec_role 这一侧用 Deny 把两个前缀挖掉。
                #
                # **为什么是 Deny 而不是重新推导那条整桶 Allow**：整桶 Allow 还养着
                # 别的步骤（deploy_lambda_site 读 artifacts/*、upload_frontend 与
                # provision_dsql 读 extracted/*、mark_job 与 undeploy 删前端桶），
                # 重推容易把其中一个弄断，而那种断法要跑真机部署才看得见。Deny 的
                # 作用面窄且可证：artifacts 桶下的**写方**只有 validate（这两个前缀）
                # 与 CodeBuild（自有角色，只写 artifacts/*）——逐函数枚举过
                # `put_object`/`delete_object` 的全部调用点，mark_job:25 与
                # undeploy:161 打的都是 FRONTEND_BUCKET，upload_frontend:26 的
                # 目的桶同样是前端桶。所以这条 Deny 不误伤任何现有步骤。
                #
                # 读权限故意不动：兄弟步骤要读 extracted/（上面已枚举），Deny 只列写。
                effect=iam.Effect.DENY,
                actions=["s3:PutObject", "s3:DeleteObject"],
                resources=[f"{artifacts.bucket_arn}/{VALIDATED_PREFIX}/*",
                           f"{artifacts.bucket_arn}/extracted/*"]),
        ]:
            exec_role.add_to_policy(stmt)

        # validate 的**独立窄角色**（同 recon_role / rollup_role 的 idiom）。它是
        # validated/ 与 extracted/ 的唯一写方，所以不能和兄弟步骤共用 exec_role
        # ——共用时 exec_role 的 dynamodb:* on site-* / iam:* on site-rt-* / Lambda
        # 建删权限也一并落到这个"只解压和校验用户上传包"的函数上。
        #
        # **必须自己显式挂 AWSLambdaBasicExecutionRole**：CDK 只在它替你创建执行
        # 角色时才加这条 managed policy，自带 `role=` 时不会。漏了不报错——函数照样
        # 部署、照样运行，只是没有 logs:CreateLogStream/PutLogEvents，于是**静默
        # 没有日志**，出事时无从查起。
        validate_role = iam.Role(
            self, "ValidateRole", role_name="site-deployer-validate-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        # 权限恰好是 validate.handler 的全部 AWS 调用面，一条不多：
        #   · get_object on uploads/{job_id}.zip（owner 预签名 PUT 上来的那份）
        #   · put_object on extracted/{job_id}/* 与 validated/{job_id}/backend-src.zip
        #   · jobs 表 UpdateItem（update_job 写 phase/status）+ GetItem
        #     （F1 起 get_job(consistent=True) 读 upload_etag——漏了它 validate 必挂）
        # **不给整桶通配、不给 ListBucket（要桶级 ARN）、不给 DeleteObject**：这个
        # 函数处理的是不可信上传包，它自己也没有任何删除或枚举的调用点。
        validate_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[f"{artifacts.bucket_arn}/uploads/*"]))
        validate_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{artifacts.bucket_arn}/extracted/*",
                       f"{artifacts.bucket_arn}/{VALIDATED_PREFIX}/*"]))
        validate_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:UpdateItem"],
            resources=[jobs.table_arn]))

        for k, v in {"JobsTable": jobs.table_name, "SitesTable": sites.table_name,
                     "AdminsTable": admins.table_name,
                     "OpsLogTable": ops_log.table_name,
                     "SessionCodesTable": session_codes.table_name,
                     "ArtifactsBucket": artifacts.bucket_name,
                     "PackageProjectName": package_project.project_name,
                     "ExecRoleArn": exec_role.role_arn,
                     "RuntimeBoundaryArn": runtime_boundary.managed_policy_arn}.items():
            CfnOutput(self, k, value=v)

        # ---- Task 17: Lambda 函数群 + site-deploy 状态机 ----
        fn_dir = str(Path(__file__).parents[1] / "functions")
        contract_dir = str(Path(__file__).parents[2] / "contract" / "src")
        # bundling 的锁定清单放在本目录，**必须显式挂进容器**：/asset-input 挂的是
        # functions/，它在容器里的父目录是 `/` 而不是宿主的 infra/——写
        # /asset-input/../infra/bundling-requirements.txt 会在容器里指向 /infra/…，
        # 那个路径不存在，pip 直接找不到清单。
        locks_dir = str(Path(__file__).parent)
        common_env = {
            "JOBS_TABLE": jobs.table_name, "SITES_TABLE": sites.table_name,
            "ADMINS_TABLE": admins.table_name,
            "OPS_LOG_TABLE": ops_log.table_name,
            "ARTIFACTS_BUCKET": artifacts.bucket_name,
            "FRONTEND_BUCKET": f"site-frontend-{ACCOUNT}",
            "ROUTING_TABLE": CFG["Platform"]["routing_table"],
            "BASE_DOMAIN": CFG["Platform"]["base_domain"],
            "RUNTIME_BOUNDARY_ARN": runtime_boundary.managed_policy_arn,
            # 路由层栈 CfnOutput 回填；deploy 前需在 config.ini [Deployer] 填入
            # edge_role_arn（synth 阶段允许空字符串）
            "EDGE_ROLE_ARN": CFG["Deployer"]["edge_role_arn"],
            "PACKAGE_PROJECT": package_project.project_name,
            "DSQL_ENDPOINT": CFG["DSQL"]["cluster_endpoint"],
            "ACCOUNT_ID": ACCOUNT,
        }

        def step_fn(name: str, handler: str, timeout_s: int = 120,
                    ephemeral_mb: int | None = None,
                    role: iam.IRole | None = None) -> lam_.Function:
            # 打包 functions/ + contract 包；psycopg 由 bundling pip 装入
            return lam_.Function(
                self, name, function_name=f"site-deployer-{handler}",
                runtime=lam_.Runtime.PYTHON_3_13,
                handler=f"{handler}.handler",
                code=lam_.Code.from_asset(fn_dir, bundling={
                    "image": lam_.Runtime.PYTHON_3_13.bundling_image,
                    # 钉死 amd64：Lambda 默认 x86_64，Apple Silicon 上不钉平台
                    # 会装出 aarch64 的 psycopg 二进制导致运行时 import 失败
                    "platform": "linux/amd64",
                    # --require-hashes 装锁定清单，不再裸装 'psycopg[binary]' sqlparse：
                    # 这些函数建 per-site IAM 角色、写路由表、连 DSQL admin，是执行器
                    # 的 TCB；范围声明意味着每次 deploy 都可能装到不同版本。清单里有
                    # hash 但装时不校验等于什么都没做，所以开关和清单必须一起改。
                    #
                    # **合同包用 cp 而不是 pip**（Codex 复审 P1-b）：contract 是 PEP 517
                    # 项目（`requires = ["setuptools>=68"]` + setuptools.build_meta），
                    # `pip install /asset-contract` 在默认 build isolation 下会**联网
                    # 下载并执行**一个未锁版本、未锁 hash 的 setuptools，而它的输出进的
                    # 是全部 site-deployer-* 产物。只锁上面那条 install、放开构建后端，
                    # 等于闭包根本没闭（实测：加 `--no-index` 后它直接报
                    # "Could not find a version that satisfies the requirement
                    # setuptools>=68"，证明那一步真的在向外拿东西）。
                    # **cp 安全的依据**：site-contract 是本仓库自己的纯 Python 包、
                    # `dependencies = []`，且没有任何代码读它的 dist 元数据（grep 过
                    # functions/、contract/src/、mcp/：无 importlib.metadata /
                    # pkg_resources 消费方）⇒ 装出来的 site-packages 与直接拷包目录
                    # 对 import 完全等价，少一整条构建工具链。
                    # 顺带清掉宿主机的 `__pycache__`：pip 是从源码建 wheel（不带
                    # pycache），cp 会把开发机上用别的 Python 版本编出来的 .pyc 一起
                    # 塞进产物——它们在 Lambda 上只会被忽略，但让同一份源码产出的
                    # 工件随开发机状态变化。
                    #
                    # **挂载卷的内容不进 CDK asset hash**（ledger 实测：两份不同的
                    # lockfile 算出同一个 asset.14ea085b…）——asset hash 只看
                    # /asset-input 那个源目录（functions/）。所以改 contract/ 或改锁定
                    # 清单之后**必须 `rm -rf cdk.out`**，否则 CDK 复用旧 asset，
                    # 部署出去的还是上一次的字节。
                    "command": ["bash", "-c",
                                "pip install --require-hashes -r "
                                "/asset-locks/bundling-requirements.txt "
                                "-t /asset-output -q && "
                                f"cp -r /asset-input/. /asset-output/ && "
                                "cp -r /asset-contract/contract /asset-output/ && "
                                "find /asset-output/contract -name __pycache__ "
                                "-type d -prune -exec rm -rf {} +"],
                    # 挂 contract/src（= contract_dir）而不是它的父目录：父目录是整个
                    # `contract/`，把 `contract/.venv`、build/、tests/ 一并暴露给构建
                    # 容器，而容器里真正需要的只有 `src/contract` 这一个包目录。
                    "volumes": [{"hostPath": contract_dir,
                                 "containerPath": "/asset-contract"},
                                {"hostPath": locks_dir,
                                 "containerPath": "/asset-locks"}]}),
                # 默认共用 exec_role；只有 validate 传自己的窄角色（见上）。
                role=role or exec_role, timeout=Duration.seconds(timeout_s),
                memory_size=512, environment=common_env,
                # None ⇒ 不渲染 EphemeralStorage，沿用 Lambda 默认 512MB。
                # 只有真的往 /tmp 写东西的步骤才显式给（当下只有 validate）。
                ephemeral_storage_size=(Size.mebibytes(ephemeral_mb)
                                        if ephemeral_mb else None))

        f_validate = step_fn("FnValidate", "validate",
                             ephemeral_mb=VALIDATE_EPHEMERAL_MB,
                             role=validate_role)
        f_ddb = step_fn("FnProvDdb", "provision_dynamodb", 300)
        f_dsql = step_fn("FnProvDsql", "provision_dsql", 300)
        f_pkg = step_fn("FnPackage", "package_backend", 900)
        f_deploy = step_fn("FnDeployLambda", "deploy_lambda_site", 300)
        f_upload = step_fn("FnUpload", "upload_frontend", 300)
        f_route = step_fn("FnRoute", "register_route")
        f_smoke = step_fn("FnSmoke", "smoke_test", 60)
        f_mark = step_fn("FnMark", "mark_job")
        f_undeploy = step_fn("FnUndeploy", "undeploy", 300)  # MCP/panel 直调，不进状态机

        mark_failed = tasks.LambdaInvoke(self, "MarkFailed", lambda_function=f_mark,
                                         payload_response_only=True)
        mark_failed.next(sfn.Fail(self, "Failed"))

        _tracked: list = []

        def t(name: str, fn) -> tasks.LambdaInvoke:
            node = tasks.LambdaInvoke(self, name, lambda_function=fn,
                                      payload_response_only=True)
            node.add_catch(mark_failed, errors=["States.ALL"],
                           result_path="$.error_info")
            _tracked.append(node)
            return node

        # 汇合点用 Pass 节点——同一后续链只被 next 一次，Choice 分支都指向它
        join_upload = sfn.Pass(self, "JoinUpload")
        join_upload.next(t("UploadFrontend", f_upload)
                         .next(t("RegisterRoute", f_route))
                         .next(t("SmokeTest", f_smoke))
                         .next(t("MarkSuccess", f_mark))
                         .next(sfn.Succeed(self, "Done")))

        join_backend = sfn.Pass(self, "JoinBackend")
        join_backend.next(
            sfn.Choice(self, "HasBackend?")
            .when(sfn.Condition.string_equals("$.manifest.tier", "static"),
                  join_upload)
            .otherwise(t("PackageBackend", f_pkg)
                       .next(t("DeployLambdaSite", f_deploy))
                       .next(join_upload)))

        choice_db = (sfn.Choice(self, "WhichDB?")
                     .when(sfn.Condition.string_equals("$.manifest.database.engine",
                                                       "dynamodb"),
                           t("ProvisionDynamoDB", f_ddb).next(join_backend))
                     .when(sfn.Condition.string_equals("$.manifest.database.engine",
                                                       "dsql"),
                           t("ProvisionDSQL", f_dsql).next(join_backend))
                     .otherwise(join_backend))
        definition = t("Validate", f_validate).next(choice_db)

        sm = sfn.StateMachine(self, "DeploySM", state_machine_name="site-deploy",
                              definition_body=sfn.DefinitionBody.from_chainable(definition),
                              timeout=Duration.minutes(30))
        CfnOutput(self, "StateMachineArn", value=sm.state_machine_arn)
        CfnOutput(self, "UndeployFnArn",
                  value=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:site-deployer-undeploy")

        # ---- M3 前置 B1：SFN 终态两层收敛 ----
        # 缺口：状态机级 TimeoutSeconds 到点（TIMED_OUT）与人工 StopExecution
        # （ABORTED）**不执行任何 State**——add_catch 只覆盖步骤内失败，于是
        # mark_job 不被调用、job 永久停在 RUNNING，而 confirm_upload 只接受
        # PENDING，用户既看不到结果也无法重试。
        #
        # 为什么两层：Step Functions 的状态变化事件是 **best-effort**（AWS 不
        # 保证投递），只挂一条 EventBridge rule 不算闭合。sweeper 定时用
        # DescribeExecution 兜底。
        #
        # **独立窄角色，不用 exec_role**：exec_role 有 dynamodb:* on site-*、
        # iam:* on site-rt-*、Lambda 建删权限。reconciler 由外部事件触发，
        # 只需要 jobs 表条件更新 + DescribeExecution + 自身日志。
        recon_role = iam.Role(
            self, "ReconcilerRole", role_name="site-deployer-reconciler-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        recon_role.add_to_policy(iam.PolicyStatement(
            # 只读 + 条件更新 jobs 表。**不给 PutItem/DeleteItem**：收敛只改
            # 已存在行的 status/error/updated_at，给 PutItem 就等于允许凭空建行。
            actions=["dynamodb:GetItem", "dynamodb:UpdateItem",
                     "dynamodb:Scan"],
            resources=[jobs.table_arn]))
        recon_role.add_to_policy(iam.PolicyStatement(
            actions=["states:DescribeExecution"],
            resources=[f"arn:aws:states:{REGION}:{ACCOUNT}:execution:"
                       f"{sm.state_machine_name}:*"]))

        recon_env = {"JOBS_TABLE": jobs.table_name,
                     "STATE_MACHINE_ARN": sm.state_machine_arn}

        def recon_fn(cid: str, fn_name: str, handler: str) -> lam_.Function:
            # 与 step_fn 不同：不需要 psycopg/contract，纯标准库 + boto3。
            # 用 from_asset 直接打包 functions/ 目录（reconcile_job 只 import
            # common，同目录）。
            return lam_.Function(
                self, cid, function_name=fn_name,
                runtime=lam_.Runtime.PYTHON_3_13, handler=handler,
                code=lam_.Code.from_asset(fn_dir),
                role=recon_role, timeout=Duration.seconds(60),
                memory_size=256, environment=recon_env)

        f_recon = recon_fn("FnReconcile", "site-deployer-reconcile-job",
                           "reconcile_job.handler")
        f_sweep = recon_fn("FnSweepJobs", "site-deployer-sweep-jobs",
                           "reconcile_job.sweeper_handler")

        dlq = sqs.Queue(self, "ReconcileDlq",
                        queue_name="site-deployer-reconcile-dlq",
                        retention_period=Duration.days(14))

        # undeploy 的**异步调用失败去处**（Codex 审查 2026-08-10 P1-4）。
        # 它由 MCP/panel 以 InvocationType=Event 调用，不进状态机，所以
        # add_catch 与 SFN 的任何收敛都覆盖不到它。没有 destination 时，
        # Lambda 重试两次后**静默丢弃**——线上实测确认过它既没有
        # EventInvokeConfig 也没有 DeadLetterConfig。
        # 站点已部分删除却无人知晓，是这条链上最后一个静默失败点。
        # 注意 job 的终态由 undeploy.handler 自己写（DLQ 只保证事件不丢、
        # 有告警面）——两者都要，不可互相替代。
        f_undeploy.configure_async_invoke(
            retry_attempts=0,       # 删除类动作不自动重试：部分删除后重跑
                                    # 会撞上"资源已不存在"，掩盖真实根因
            max_event_age=Duration.hours(1),
            on_failure=destinations.SqsDestination(dlq))

        # M5 每日聚合。**独立角色**：它是唯一能写聚合表的身份，而对明细表只读。
        # 给它明细表的 PutItem 就等于让聚合器能伪造访问历史；给它 Scan 也不必要
        # （只按分区 Query）。sites 表只读（枚举 site_id，DynamoDB 无法枚举分区键）。
        rollup_role = iam.Role(
            self, "AccessRollupRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"], resources=[access_events.table_arn]))
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem"], resources=[access_daily.table_arn]))
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Scan"], resources=[sites.table_arn]))

        # 跨区扫 Lambda@Edge 日志 → 发**一个**聚合指标（access_rollup 下半部分）。
        # Lambda@Edge 在 POP 所在区落日志，而 CloudWatch 告警不能跨区，所以按区
        # 建告警的方案在别的部署上不可移植（不知道 POP 会落在哪些区）。
        #
        # 资源里的 **region 段只能是 `*`**——要扫哪些区在部署期未知，这正是可移植性
        # 要求本身。但其余各段都收窄：
        #  · FilterLogEvents 限定在 Lambda@Edge 日志组的前缀上。裸 `*` 等于让聚合器
        #    能读 auth / panel / 站点的**全部**日志（里面有邮箱），那是白拿的权限；
        #  · DescribeLogGroups 拿不到更细的粒度（列举操作按整个 log-group 命名空间
        #    鉴权），至少限定到本账号本服务。
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["logs:DescribeLogGroups"],
            resources=[f"arn:aws:logs:*:{self.account}:log-group:*"]))
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["logs:FilterLogEvents"],
            resources=[
                f"arn:aws:logs:*:{self.account}:log-group:"
                f"{EDGE_LOG_GROUP_PREFIX}*",
                f"arn:aws:logs:*:{self.account}:log-group:"
                f"{EDGE_LOG_GROUP_PREFIX}*:log-stream:*"]))
        # 区清单运行时问 AWS（不硬编码）。
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["ec2:DescribeRegions"], resources=["*"]))
        # PutMetricData **没有资源级权限**，唯一的收窄手段是 namespace 条件；
        # 不带它这个角色能往任何 namespace 写，包括伪造别的告警的输入指标。
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"], resources=["*"],
            conditions={"StringEquals": {
                "cloudwatch:namespace": ROLLUP_METRIC_NAMESPACE}}))

        f_rollup = lam_.Function(
            self, "FnAccessRollup", function_name="site-access-rollup",
            runtime=lam_.Runtime.PYTHON_3_13,
            handler="access_rollup.handler",
            code=lam_.Code.from_asset(fn_dir),
            role=rollup_role,
            timeout=Duration.seconds(ROLLUP_TIMEOUT_SECONDS),
            memory_size=ROLLUP_MEMORY_MB,
            environment={"ACCESS_EVENTS_TABLE": access_events.table_name,
                         "ACCESS_DAILY_TABLE": access_daily.table_name,
                         "SITES_TABLE": sites.table_name})

        # 每天 00:20 UTC。**只封口完整日**，所以不需要更高频率；一轮失败由
        # 下一轮的 7 天回溯窗口自动补上（access_rollup.LOOKBACK_DAYS）。
        events.Rule(
            self, "AccessRollupRule", rule_name="site-access-rollup-daily",
            schedule=events.Schedule.cron(minute="20", hour="0"),
            targets=[targets.LambdaFunction(
                f_rollup, dead_letter_queue=dlq, retry_attempts=2)])

        # ── M5 的两条埋点可观测性告警 ────────────────────────────────────
        # **必须在 CDK 里声明，不能手工建**：手工建的告警新部署拿不到、被人删掉
        # 也不会被发现——那就不是可复现的交付物。这与保留期那一轮写进 DEPLOY.md 的
        # 「真源是代码不是控制台」是同一条纪律（这两条此前正是手工建的，已作废）。
        #
        # 两条**互为对方的守卫**，别删任何一条：
        #   · liveness 抓「聚合器自己停了」——它一停，下面那条只会表现成指标缺数据，
        #     而缺数据要连续两天才够条件；
        #   · edge-analytics 抓「某个 POP 所在区在静默丢埋点行」——rollup 调用成功
        #     并不意味着它扫出来的数是对的。
        alarm_topic = sns.Topic.from_topic_arn(
            self, "AlarmTopic",
            self.format_arn(service="sns", resource=ALARM_TOPIC_NAME))

        def _wire(alarm: cw.Alarm) -> cw.Alarm:
            """ALARM 与 OK 都通知。**OK 不是可选的**：本项目统一把 OK 称作
            「告警解除」并同样发通知（与 auth 那条登录失败告警同一套用词），
            只发 ALARM 时收件人无法区分「还在坏」与「已恢复」。"""
            action = cw_actions.SnsAction(alarm_topic)
            alarm.add_alarm_action(action)
            alarm.add_ok_action(action)
            return alarm

        # ① 跨区聚合的 Edge 埋点失败。指标由 access_rollup 每轮发**一个**无维度值。
        #
        # 阈值/周期的实测依据（改任何一个数字前先读 DEPLOY.md 那一节）：
        #  · **threshold=3**（配 GreaterThanThreshold ⇒ 一天 ≥4 条、连续两天才响）。
        #    分母是实测流量 **≈134 次写入/天**（≈5.6 次/小时）：18 条 `[INFO] m5-region`
        #    落在 **3.2 小时**里，而不是 7 天——那行探针是 `8a8fb20` 才随路由层上线的，
        #    比它更早的日志里根本没有它。`analytics.py` 旁边独立写着的「全平台日均
        #    124 行」（M5-FINDINGS §4.26）对得上这个量级。
        #    于是 4/134 ≈ **3%**：这条告警说的是"一天丢了 3% 以上的访问行，两天连着"。
        #    旧的「> 10 条/小时」仍然作废（5.6/小时的 100% 失败也凑不满 10），那是
        #    本次改动的出发点，没有变。
        #  · **底噪没有测过，所以 3 是假设不是结论**：失败样本是"18 次里 0 次失败"，
        #    按 rule of three（3/n）只能把失败率上界压到 ≈17% —— 底噪是 0 还是
        #    20 次/天，现有数据分不出。埋点写入**不重试**（origin_request 那边刻意
        #    max_attempts=0）、跨区回落实测 719ms 冷启动对 2s 读超时，所以偶发超时
        #    是可能的。取 3 是在两种错法之间选：threshold=0 在底噪只有 1%（≈1.3/天）
        #    时就会长期误报（Poisson：P(X≥1)≈73%，连着两天≈53%），而 threshold=3
        #    在同一底噪下约 1.4 年才误报一次（P(X≥4)≈4.6%，成对≈0.2%）。
        #    **可证伪的观测**：部署后手工调一次 rollup 发出来的那个数就是底噪的第一个
        #    24h 真样本——它 >0 就说明底噪不是 0，本注释的假设当场被推翻。
        #    **复查触发条件**：上线第一周内若在没有真故障时响过 ⇒ 底噪高于 0，
        #    抬阈值或改成比率（分母用同法扫 `[INFO] m5-region`，见 DEPLOY.md）。
        #  · **能抓到多大的故障**（按各区流量占比换算）：全平台全坏 ≈134/天、
        #    ap-southeast-1 全坏 ≈118/天、ap-northeast-1 全坏 ≈7/天 —— 都远超阈值；
        #    us-east-1 全坏 ≈4.7/天，要几天才凑够连续两天；**单个小区（<1/天）
        #    抓不到**，那一格仍然靠 verify_analytics_e2e.py 的确定性核对。
        #  · **2/2**：周期 86400 的告警评估的是**滚动** 24h 窗口（实测线上
        #    StateReasonData 的 startDate = queryDate - 24h）。每日那一轮的落点会
        #    抖动（EventBridge 调度延迟 + 封口耗时），只要今天比昨天晚一点，窗口里
        #    就会有几分钟一个数据点都没有 ⇒ 1/1 下**系统健康时也会响**（§4.20：
        #    偶发变红的告警的代价是下一个人学会忽略它）。
        #  · **Maximum 而不是 Sum**：手工重跑 rollup 会在同一窗口里多打一个数据点，
        #    Sum 会把它们加起来、凭空越过阈值。
        #  · **breaching**：这是「扫成功也要发显式 0」那条设计的另一半——发了 0 之后
        #    缺数据只剩一个含义（本轮没扫成），于是"瞎了"与"健康"可区分。
        _wire(cw.Metric(
            namespace=ROLLUP_METRIC_NAMESPACE, metric_name=ROLLUP_METRIC_NAME,
            statistic="Maximum", period=Duration.days(1)).create_alarm(
                self, "EdgeAnalyticsFailedAlarm",
                alarm_name="m5-edge-analytics-failed-global",
                alarm_description=(
                    "全部 POP 所在区的 Edge 埋点失败条数（由 site-access-rollup 每日"
                    "跨区扫日志聚合成一个指标）。埋点异常按设计被吞掉，所以这是唯一能"
                    "发现「某个区在静默丢访问数据」的信号。触发条件：连续 2 个 24 小时"
                    "窗口，每个窗口的最大值 > 3（≈ 当前 134 次写入/天 的 3%）。"
                    "指标**缺数据**同样是告警条件——那表示扫描器本轮没扫成，即我们瞎了。"
                    "阈值 3 是按「正常失败底噪低于 3/天」这个**未经测量的假设**取的："
                    "若上线第一周在没有真故障时响过，说明底噪高于 0，应抬阈值或改成"
                    "比率告警（失败数 ÷ 当天写入尝试数）。OK=告警解除（仅表示指标不再"
                    "满足条件，不代表已确认修复）。"),
                threshold=3, comparison_operator=(
                    cw.ComparisonOperator.GREATER_THAN_THRESHOLD),
                evaluation_periods=2, datapoints_to_alarm=2,
                treat_missing_data=cw.TreatMissingData.BREACHING))

        # ② 聚合器活性。**用 `Invocations - Errors` 而不是 `Errors > 0`**：要抓的头号
        # 形态是「根本没被触发」（rule 被删/禁用、触发权限丢了），那时 Errors 不产生
        # 任何数据点，`Errors > 0` 永远不会响。配 breaching 才能把"没有数据"变成信号。
        _lambda_day = {"period": Duration.days(1), "statistic": "Sum"}
        _wire(cw.MathExpression(
            expression="inv - err", label="成功调用数", period=Duration.days(1),
            using_metrics={"inv": f_rollup.metric_invocations(**_lambda_day),
                           "err": f_rollup.metric_errors(**_lambda_day)}
            ).create_alarm(
                self, "RollupLivenessAlarm",
                alarm_name="m5-rollup-no-successful-invocation-24h",
                alarm_description=(
                    "site-access-rollup 连续 2 天没有成功调用（Invocations-Errors<1）。"
                    "它停了没人会发现：今天的数字仍由读路径实时算，历史曲线只会静默"
                    "停在最后一次封口那天。需要 2 个周期的理由与另一条告警相同——"
                    "周期 86400 评估的是滚动 24h 窗口，而定时任务在 00:20 的落点会"
                    "抖动，1/1 会让健康的系统每天误报一次。恢复后 7 天内的空洞由"
                    "LOOKBACK_DAYS 自动补齐，更久的中断要显式补跑。"),
                threshold=1,
                comparison_operator=cw.ComparisonOperator.LESS_THAN_THRESHOLD,
                evaluation_periods=2, datapoints_to_alarm=2,
                treat_missing_data=cw.TreatMissingData.BREACHING))

        # rule 只匹配**本状态机**的 TIMED_OUT / ABORTED。
        # 不匹配 FAILED：那条路径已由每个 Task 的 add_catch → MarkFailed 覆盖，
        # 重复收敛会把 mark_job 写入的真实错因覆盖成通用文案。
        events.Rule(
            self, "TerminalStatusRule", rule_name="site-deploy-terminal-status",
            event_pattern=events.EventPattern(
                source=["aws.states"],
                detail_type=["Step Functions Execution Status Change"],
                detail={"status": ["TIMED_OUT", "ABORTED"],
                        "stateMachineArn": [sm.state_machine_arn]}),
            targets=[targets.LambdaFunction(
                f_recon, dead_letter_queue=dlq,
                retry_attempts=2,
                max_event_age=Duration.hours(2))])

        # 兜底层：30 分钟一轮（超龄阈值 45 分钟 = 状态机 30 分钟上限 + 余量，
        # 见 reconcile_job.STALE_MINUTES）。
        events.Rule(
            self, "JobSweepRule", rule_name="site-deploy-job-sweep",
            schedule=events.Schedule.rate(Duration.minutes(30)),
            targets=[targets.LambdaFunction(
                f_sweep, dead_letter_queue=dlq, retry_attempts=2)])

        CfnOutput(self, "ReconcileDlqUrl", value=dlq.queue_url)


app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
