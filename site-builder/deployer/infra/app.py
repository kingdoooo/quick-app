#!/usr/bin/env python3
"""Deployer 基础设施：任务/站点表、产物桶、CodeBuild 打包项目、执行角色。
状态机定义在 Task 17 追加到本 stack。"""
import configparser
from pathlib import Path

from aws_cdk import (App, CfnOutput, Duration, Environment, RemovalPolicy, Stack,
                     aws_codebuild as cb, aws_dynamodb as ddb,
                     aws_events as events, aws_events_targets as targets,
                     aws_iam as iam, aws_lambda as lam_,
                     aws_lambda_destinations as destinations, aws_s3 as s3,
                     aws_sqs as sqs, aws_stepfunctions as sfn,
                     aws_stepfunctions_tasks as tasks)
from constructs import Construct

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parents[2] / "config.ini")
ACCOUNT = CFG["Platform"]["account_id"]
REGION = CFG["Platform"]["region"]


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
        admins = ddb.Table(self, "Admins", table_name="site-admins",
                           partition_key=ddb.Attribute(name="email",
                                                       type=ddb.AttributeType.STRING),
                           billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                           removal_policy=RemovalPolicy.RETAIN)

        # 二期 M3：操作审计（append-only）。写入方只被授予 PutItem。
        # RETAIN 与 admins 同理：审计记录误删会丢失合规证据。
        ops_log = ddb.Table(
            self, "OpsLog", table_name="site-ops-log",
            partition_key=ddb.Attribute(name="target", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="ts_actor", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            removal_policy=RemovalPolicy.RETAIN)

        # 二期 M3：面板会话升级的一次性 code 消费标记（jti）。
        # DESTROY（不同于 ops_log）：60 秒 TTL 的一次性标记，删栈丢掉无害。
        session_codes = ddb.Table(
            self, "SessionCodes", table_name="site-session-codes",
            partition_key=ddb.Attribute(name="jti", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            removal_policy=RemovalPolicy.DESTROY)

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
        # 构建容器跑的是不可信站点的依赖安装：即使 --ignore-scripts，也不给它
        # 整桶读写（否则可读/删他人上传包与产物、枚举所有 job）。
        # 只读 uploads/*、只写 artifacts/*，且不给 ListBucket 与 DeleteObject。
        package_project.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[f"{artifacts.bucket_arn}/uploads/*"]))
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
        ]:
            exec_role.add_to_policy(stmt)

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

        def step_fn(name: str, handler: str, timeout_s: int = 120) -> lam_.Function:
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
                    "command": ["bash", "-c",
                                "pip install 'psycopg[binary]' sqlparse -t /asset-output -q && "
                                f"cp -r /asset-input/. /asset-output/ && "
                                "pip install /asset-contract -t /asset-output -q"],
                    "volumes": [{"hostPath": contract_dir + "/..",
                                 "containerPath": "/asset-contract"}]}),
                role=exec_role, timeout=Duration.seconds(timeout_s),
                memory_size=512, environment=common_env)

        f_validate = step_fn("FnValidate", "validate")
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
