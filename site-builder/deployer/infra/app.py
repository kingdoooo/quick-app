#!/usr/bin/env python3
"""Deployer 基础设施：任务/站点表、产物桶、CodeBuild 打包项目、执行角色。
状态机定义在 Task 17 追加到本 stack。"""
import configparser
from pathlib import Path

from aws_cdk import (App, CfnOutput, Duration, Environment, RemovalPolicy, Stack,
                     aws_codebuild as cb, aws_dynamodb as ddb, aws_iam as iam,
                     aws_s3 as s3)
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
        artifacts.grant_read_write(package_project)

        exec_role = iam.Role(self, "DeployerExecRole", role_name="site-deployer-exec-role",
                             assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                             managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                 "service-role/AWSLambdaBasicExecutionRole")])
        for stmt in [
            iam.PolicyStatement(  # 站点 Lambda 的创建/更新，限 site- 前缀
                actions=["lambda:CreateFunction", "lambda:UpdateFunctionCode",
                         "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
                         "lambda:CreateFunctionUrlConfig", "lambda:GetFunctionUrlConfig",
                         "lambda:AddPermission", "lambda:DeleteFunction",
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
            iam.PolicyStatement(actions=["dsql:DbConnectAdmin"], resources=["*"]),
        ]:
            exec_role.add_to_policy(stmt)

        for k, v in {"JobsTable": jobs.table_name, "SitesTable": sites.table_name,
                     "ArtifactsBucket": artifacts.bucket_name,
                     "PackageProjectName": package_project.project_name,
                     "ExecRoleArn": exec_role.role_arn,
                     "RuntimeBoundaryArn": runtime_boundary.managed_policy_arn}.items():
            CfnOutput(self, k, value=v)


app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
