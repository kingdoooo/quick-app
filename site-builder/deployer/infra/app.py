#!/usr/bin/env python3
"""Deployer 基础设施：任务/站点表、产物桶、CodeBuild 打包项目、执行角色。
状态机定义在 Task 17 追加到本 stack。"""
import configparser
from pathlib import Path

from aws_cdk import (App, CfnOutput, Duration, Environment, RemovalPolicy, Stack,
                     aws_codebuild as cb, aws_dynamodb as ddb, aws_iam as iam,
                     aws_lambda as lam_, aws_s3 as s3, aws_stepfunctions as sfn,
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
        sites = ddb.Table(self, "Sites", table_name="site-sites",
                          partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
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
        step_fn("FnUndeploy", "undeploy", 300)  # MCP 直调，不进状态机

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


app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
