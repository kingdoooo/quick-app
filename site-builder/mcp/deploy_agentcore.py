#!/usr/bin/env python3
"""部署部署 MCP 到 Bedrock AgentCore Runtime。幂等可重跑。

流程：cp common.py → buildx 构 ARM64 镜像 → 推 ECR → 建/更新 runtime IAM 角色
→ create/update_agent_runtime（MCP 协议 + Cognito customJWTAuthorizer +
requestHeaderAllowlist=["Authorization"]）→ 打印 endpoint 与冒烟指引。

关键约束（均来自 AWS 官方文档，改动前先核实）：
- 容器必须 ARM64（Graviton）；x86 镜像运行时 exec format error。
- 容器监听 0.0.0.0:8000，POST /mcp，stateless streamable-http。
- Authorization 头要透传给容器，必须显式加进 requestHeaderAllowlist，
  且 runtime 必须配 customJWTAuthorizer——否则该头被平台拦掉，
  server.py 的 _caller_email() 取不到 email，所有工具报"无法识别调用者身份"。

用法：
    python3 deploy_agentcore.py            # 构建 + 推送 + 部署
    python3 deploy_agentcore.py --skip-build   # 只更新 runtime 配置
"""
import argparse
import base64
import configparser
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import boto3

HERE = Path(__file__).parent
CFG = configparser.ConfigParser()
CFG.read(HERE.parent / "config.ini")

ACCOUNT = CFG["Platform"]["account_id"]
REGION = CFG["Platform"]["region"]
BASE_DOMAIN = CFG["Platform"]["base_domain"]

REPO = "site-builder-mcp"
RUNTIME_NAME = "site_builder_deploy"  # 只允许 [a-zA-Z][a-zA-Z0-9_]{0,47}
ROLE_NAME = "site-mcp-runtime-role"
IMAGE_TAG = "latest"

ecr = boto3.client("ecr", region_name=REGION)
iam = boto3.client("iam")
acc = boto3.client("bedrock-agentcore-control", region_name=REGION)


def _run(cmd: list[str], **kw) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kw)


def ensure_repo() -> str:
    try:
        uri = ecr.describe_repositories(repositoryNames=[REPO])["repositories"][0][
            "repositoryUri"]
    except ecr.exceptions.RepositoryNotFoundException:
        uri = ecr.create_repository(
            repositoryName=REPO,
            imageScanningConfiguration={"scanOnPush": True},
            tags=[{"Key": "project", "Value": "site-builder"}],
        )["repository"]["repositoryUri"]
    return uri


def build_and_push(image_uri: str) -> None:
    # common.py / permissions.py 必须进构建上下文：server.py 按同目录解析它们
    copied = []
    for name in ("common.py", "permissions.py"):
        shutil.copyfile(HERE.parent / "deployer" / "functions" / name, HERE / name)
        copied.append(HERE / name)
    try:
        token = ecr.get_authorization_token()["authorizationData"][0]
        user, pwd = base64.b64decode(token["authorizationToken"]).decode().split(":", 1)
        _run(["docker", "login", "--username", user, "--password-stdin",
              token["proxyEndpoint"]], input=pwd.encode())
        # --platform linux/arm64：AgentCore 只接受 ARM64（Graviton）。
        # --provenance=false 必需：buildx 默认往 manifest list 里加一条
        # os=unknown/arch=unknown 的 attestation manifest，CreateAgentRuntime
        # 校验镜像时会失败，且报错文案误导为
        # "Access denied while validating ECR URI ... requires permissions for
        #  ecr:GetAuthorizationToken, ecr:BatchGetImage, ..."
        # ——实际与 IAM 权限无关（权限齐全时同样报这个）。
        _run(["docker", "buildx", "build", "--platform", "linux/arm64",
              "--provenance=false",
              "-t", image_uri, "--push", str(HERE)])
    finally:
        for p in copied:
            p.unlink(missing_ok=True)


def ensure_role() -> str:
    """Runtime 执行角色：起 SFN、读写 jobs/sites、发 presigned URL、调 undeploy。"""
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "AssumeRolePolicy",
        "Effect": "Allow",
        "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
        "Action": "sts:AssumeRole",
        # SourceAccount + SourceArn 双条件（官方 runtime-permissions 文档要求），
        # 防跨账号混淆代理
        "Condition": {
            "StringEquals": {"aws:SourceAccount": ACCOUNT},
            "ArnLike": {"aws:SourceArn":
                        f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:*"}},
    }]})
    try:
        arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=ROLE_NAME, PolicyDocument=trust)
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=ROLE_NAME, AssumeRolePolicyDocument=trust,
            Tags=[{"Key": "project", "Value": "site-builder"}])["Role"]["Arn"]
        time.sleep(10)  # IAM 传播

    policy = {"Version": "2012-10-17", "Statement": [
        # 拉自建镜像：缺这两个动作 runtime 起不来（镜像在本账号私有 ECR）
        {"Sid": "ECRImageAccess", "Effect": "Allow",
         "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
         "Resource": f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}"},
        {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken",
         "Resource": "*"},  # 该动作不支持资源级限定
        # jobs + sites：MCP 的读写主路径（含 owner-index GSI）。
        # ConditionCheckItem 是 register_route / write_permissions 的事务需要的
        # ——IAM 里没有 dynamodb:TransactWriteItems 这个 action，事务内
        # Put/Update/Delete/Get 的权限由底层同名 action 决定，只有
        # ConditionCheck 需要它（见 Task 11 Step 7 的官方链接）。
        {"Sid": "JobsAndSites", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                    "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:ConditionCheckItem"],
         "Resource": [
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-deploy-jobs",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-deploy-jobs/index/*",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites/index/*"]},
        # admins 表：**只读 + 事务条件检查**。
        # is_admin() 要 GetItem、list_admins() 要 Scan、write_permissions() 的
        # admin 代管路径要对 admins 做 ConditionCheck（缺 ConditionCheckItem
        # 时管理员改任意站点权限会直接 AccessDenied）。
        # 故意**不给** PutItem/UpdateItem/DeleteItem：增删管理员不走 MCP
        # runtime 角色（M2 由部署时的种子脚本做，M3 由 panel 自己的角色做）。
        {"Sid": "AdminsReadOnly", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:Scan",
                    "dynamodb:ConditionCheckItem"],
         "Resource": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-admins"},
        # presigned PUT 由调用者上传，MCP 侧只需 HeadObject 校验大小
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": f"arn:aws:s3:::site-artifacts-{ACCOUNT}/uploads/*"},
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:site-deploy"},
        {"Effect": "Allow", "Action": "lambda:InvokeFunction",
         "Resource": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:site-deployer-undeploy"},
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                    "logs:DescribeLogStreams"],
         "Resource": [
             f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/bedrock-agentcore/*",
             f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/bedrock-agentcore/*:*"]},
    ]}
    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName="mcp-scope",
                        PolicyDocument=json.dumps(policy))
    return arn


def _discovery_url() -> str:
    pool = CFG["Cognito"]["user_pool_id"]
    if not pool:
        sys.exit("config.ini [Cognito] user_pool_id 为空——先完成 DEPLOY.md ① 身份层")
    return (f"https://cognito-idp.{REGION}.amazonaws.com/{pool}"
            f"/.well-known/openid-configuration")


def _find_runtime() -> str | None:
    paginator_token = None
    while True:
        kw = {"nextToken": paginator_token} if paginator_token else {}
        resp = acc.list_agent_runtimes(**kw)
        for rt in resp.get("agentRuntimes", []):
            if rt.get("agentRuntimeName") == RUNTIME_NAME:
                return rt["agentRuntimeId"]
        paginator_token = resp.get("nextToken")
        if not paginator_token:
            return None


def deploy_runtime(image_uri: str, role_arn: str) -> dict:
    client_id = CFG["Cognito"]["mcp_client_id"]
    if not client_id:
        sys.exit("config.ini [Cognito] mcp_client_id 为空——先完成 DEPLOY.md ①")
    sm_arn = CFG["Deployer"]["state_machine_arn"]
    if not sm_arn:
        sys.exit("config.ini [Deployer] state_machine_arn 为空——先完成 DEPLOY.md ④")

    common = dict(
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": image_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        protocolConfiguration={"serverProtocol": "MCP"},
        # allowedClients 对应 access token 的 client_id。真机已钉死（2026-07-29）：
        # MCP 客户端发的就是 access token，id_token 会被网关 401
        # （"Claim 'client_id' value mismatch"）——不要改 allowedAudience。
        # email 靠 pre-token-generation Lambda 注入 access token
        # （auth/pre_token_email.py，见 AGENTCORE-SPIKE.md §7）。
        authorizerConfiguration={"customJWTAuthorizer": {
            "discoveryUrl": _discovery_url(),
            "allowedClients": [client_id]}},
        # Authorization 头不在 allowlist 里就不会到达容器，_caller_email() 必失败
        requestHeaderConfiguration={"requestHeaderAllowlist": ["Authorization"]},
        environmentVariables={
            "JOBS_TABLE": CFG["Deployer"]["jobs_table"],
            "SITES_TABLE": CFG["Deployer"]["sites_table"],
            "ADMINS_TABLE": CFG["Deployer"]["admins_table"],
            "TRUSTED_IDPS": CFG["IdP"]["provider_name"] if CFG.has_section("IdP") else "",
            "ARTIFACTS_BUCKET": f"site-artifacts-{ACCOUNT}",
            "STATE_MACHINE_ARN": sm_arn,
            "BASE_DOMAIN": BASE_DOMAIN,
            "ACCOUNT_ID": ACCOUNT,
            "AWS_DEFAULT_REGION": REGION,
        },
    )

    existing = _find_runtime()
    if existing:
        print(f"  更新已有 runtime {existing}（update 是全量 PUT）")
        return acc.update_agent_runtime(agentRuntimeId=existing, **common)
    print("  创建新 runtime")
    return acc.create_agent_runtime(agentRuntimeName=RUNTIME_NAME,
                                    description="Site Builder 部署 MCP（owner 绑飞书账号）",
                                    **common)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true",
                    help="不重新构镜像，只更新 runtime 配置")
    args = ap.parse_args()

    print("① ECR 仓库")
    repo_uri = ensure_repo()
    image_uri = f"{repo_uri}:{IMAGE_TAG}"
    print(f"   {image_uri}")

    if args.skip_build:
        print("② 跳过构建（--skip-build）")
    else:
        print("② 构建并推送 ARM64 镜像")
        build_and_push(image_uri)

    print("③ Runtime 执行角色")
    role_arn = ensure_role()
    print(f"   {role_arn}")

    print("④ AgentCore Runtime")
    out = deploy_runtime(image_uri, role_arn)
    arn = out.get("agentRuntimeArn", "")
    print(f"   arn: {arn}")
    print(f"   status: {out.get('status', '?')}")

    # MCP 客户端连接用的 URL（InvokeAgentRuntime 的 MCP 直连形态）
    if arn:
        encoded = arn.replace(":", "%3A").replace("/", "%2F")
        endpoint = (f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
                    f"{encoded}/invocations?qualifier=DEFAULT")
        print(f"\n回填 config.ini [MCP] endpoint_url =\n  {endpoint}")

    print("\n冒烟（需要一个真实 Cognito token）：")
    print("  npx @modelcontextprotocol/inspector  # 连上面 endpoint，带 Bearer token")
    print("  检查：5 个工具列出 / 无 token 返回 401 /")
    print("       list_my_sites 的 owner == 登录的飞书邮箱（验证 email claim 透传）")


if __name__ == "__main__":
    main()
