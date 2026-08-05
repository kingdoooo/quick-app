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


# MCP runtime 允许在路由表上读写的属性白名单（dynamodb:Attributes 条件键）。
#
# **必须与 permissions.write_permissions 的 route_update 逐字段对齐**：
# 少一个 → 在线改权限被 AccessDenied（不是事务取消，报错形态完全不同，
# 排查时容易误判成条件冲突）；多一个 → 那个字段就成了可被 runtime 改写的
# 攻击面。当前对应关系（permissions.py 的 route_update）：
#   subdomain      —— 分区键 + attribute_exists() 条件都要用（官方要求主键必列）
#   require_auth   —— SET :a
#   allowed_users  —— SET :u
#   collaborators  —— SET :c
#   owner          —— SET #ro（真实名，非别名 #ro）
#   permissions_rev—— SET :rv
# **不含** static_prefix / api_target / route_mode / site_id：这四个是部署链
# register_route 整条 put_item 的字段，用 deployer 的 exec role 写；
# 把它们放进白名单等于把"改路由指向"的能力交给 MCP runtime。
ROUTE_PROJECTION_ATTRIBUTES = ("subdomain", "require_auth", "allowed_users",
                               "collaborators", "owner", "permissions_rev")

# MCP runtime 允许在 sites 表上写的属性白名单。
#
# 只覆盖**从 MCP 工具真正可达**的写路径：
#   site_id                     —— 分区键（官方要求主键必列）
#   owner / name / status       —— do_deploy_site 创建站点时写
#   require_login / allowed_users / collaborators / permissions_rev /
#   permissions_updated_at / permissions_updated_by
#                               —— write_permissions（改权限、协作者、转移所有权）
#
# **不含**部署链自己的字段：status 之外的 data_tables / migrations_applied /
# last_job_id / dsql_schema 等由 SFN 的各步骤用 deployer exec role 写，
# MCP 不该碰。放进来等于让被攻破的 runtime 能篡改部署状态
# （例：改 data_tables 让后续步骤对别的表动手）。
# status 必须留：do_deploy_site 写 DEPLOYING。
#
# 新增 MCP 侧写字段时同步这里，否则线上 AccessDenied；
# 由 test_agentcore_contract 从实现源码解析比对，不手抄第二份清单。
SITE_WRITABLE_ATTRIBUTES = ("site_id", "owner", "name", "status",
                            "require_login", "allowed_users", "collaborators",
                            "permissions_rev", "permissions_updated_at",
                            "permissions_updated_by")


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
        # jobs：MCP 唯一需要**整条写**的表（common.create_job 是 put_item）。
        # ConditionCheckItem 是 register_route / write_permissions 的事务需要的
        # ——IAM 里没有 dynamodb:TransactWriteItems 这个 action，事务内
        # Put/Update/Delete/Get 的权限由底层同名 action 决定，只有
        # ConditionCheck 需要它（见 Task 11 Step 7 的官方链接）。
        {"Sid": "Jobs", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                    "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:ConditionCheckItem"],
         "Resource": [
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-deploy-jobs",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-deploy-jobs/index/*"]},
        # sites 读：**不能加 dynamodb:Attributes 条件**。
        # Query/Scan 不带 ProjectionExpression 时请求上下文里没有
        # dynamodb:Attributes，而写侧那条加了 Null 检查——两者合在一个
        # statement 里会让 list_my_sites 的 Query 直接 AccessDenied。
        # 读全字段本身不是问题：调用方能读的站点由应用层 owner 判定收口。
        {"Sid": "SitesRead", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:ConditionCheckItem"],
         "Resource": [
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites/index/*"]},
        # sites 写：**故意不给 PutItem，且按属性白名单收窄 UpdateItem**。
        # 不给 PutItem 只挡住"整条覆盖"，挡不住 UpdateItem 改任意属性
        # （UpdateItem 能编辑任意属性，item 不存在时甚至会创建）——所以必须
        # 同时上属性闸门，否则 runtime 被攻破可改 status/data_tables/
        # migrations_applied 这些**部署链自己的字段**：把 DELETED 站点改回
        # ACTIVE、篡改 data_tables 让后续步骤误操作别的表。
        #
        # ⚠️ **效力边界（务必按字面理解，不要外推）**：本条约束的是"可写哪些
        # 字段"，**不是**"可写哪些站点的行"。owner 必须留在白名单里（建站写
        # owner、transfer_owner 改 owner 都是 MCP 的正常功能），因此
        # **被攻破的 runtime 仍可把任意站点的 owner 改成攻击者，进而以新 owner
        # 的身份走正常接口做任何事**。这条路径 IAM 关不掉：
        #   · dynamodb:LeadingKeys 只能把主体限制在"由其身份推出的分区键"
        #     （多租户 ${...:user_id} 模式），而本 runtime 服务全部用户、
        #     合法地需要访问任意 site_id；
        #   · 真正的授权规则（owner/collaborators）**存在行里**，是数据驱动的，
        #     而 IAM 策略是静态的、读不到行内容。
        # 所以站点归属的最终裁决者是**应用层代码 + runtime 角色本身的完整性**：
        # MCP runtime 对"站点管理操作"而言属于 TCB（可信计算基）。同理它还持有
        # jobs PutItem、states:StartExecution 与 undeploy Lambda 调用权限。
        # 若要让 IAM 真正兜住站点归属，必须把建站/transfer_owner/权限写入拆成
        # 独立角色的窄接口（各自做服务端授权），那是架构改动，不在本轮范围。
        # 见 DEPLOY.md「MCP runtime 的信任边界」一节。
        #
        # 本条仍然值得有：它把可写面收敛到 MCP 真正需要的字段，挡住对**部署链
        # 字段**（data_tables / migrations_applied / last_job_id …）的篡改——
        # 那些是纵深防御里独立的一层，与 owner 那条路径无关。
        {"Sid": "SitesWrite", "Effect": "Allow",
         "Action": "dynamodb:UpdateItem",
         "Resource": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites",
         "Condition": {
             "ForAllValues:StringEquals": {
                 "dynamodb:Attributes": list(SITE_WRITABLE_ATTRIBUTES)},
             "Null": {"dynamodb:Attributes": "false"},
             "StringEqualsIfExists": {
                 "dynamodb:ReturnValues": ["NONE", "UPDATED_OLD", "UPDATED_NEW"]}}},
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
        # 路由表：只做权限投影 + 事务条件检查。
        #
        # **不给 PutItem/DeleteItem 是必要条件，但远远不够**：DynamoDB 的
        # UpdateItem 本身就能改任意属性，所以"没有 PutItem 就动不了
        # static_prefix / api_target"是错的（Codex review P1 指出，官方
        # specifying-conditions 文档确认）。真正的字段级闸门是
        # dynamodb:Attributes 条件键——不加它，runtime 被攻破后可以：
        #   · 改 api_target / static_prefix → 把任意站点的流量指向攻击者后端；
        #   · 把 owner 改成 "platform" → Edge 的 _is_platform_route 成立，
        #     顶域 sb_session 不再被剥除，共享会话 cookie 被转发给用户控制的
        #     origin（origin_request.py 的 RESERVED_COOKIES 剥除逻辑）。
        #
        # 官方契约（写这段前逐条核实过，改动前请复核）：
        #   · dynamodb:Attributes 收的是**请求参数里出现的全部顶层属性**，
        #     不只是 UpdateExpression 写的那些——Key 与 ConditionExpression
        #     引用的属性同样计入。故 subdomain（分区键 + attribute_exists
        #     条件）必须在白名单里，官方 Important 明示"必须列出全部主键属性"。
        #   · 名单里放**解析后的真实属性名**（owner），不是
        #     ExpressionAttributeNames 的别名（#ro）。
        #   · ForAllValues 在请求上下文缺键或空集时返回 **true**（真空真值），
        #     官方对 ForAllValues+Allow 的建议是必须配 Null 检查兜底，
        #     否则这条闸门在"键缺失"时静默失效。
        #   · UpdateItem 会做隐式读，ReturnValues=ALL_OLD/ALL_NEW 能带回完整
        #     item（绕过属性限制读到未授权字段），故一并收窄；事务路径对应的是
        #     ReturnValuesOnConditionCheckFailure，同一条件键管辖。
        #     不传时默认 NONE，在白名单内，所以 IfExists 不会拦住现有调用。
        #   · **不要**给 ConditionCheckItem 加 dynamodb:EnclosingOperation 条件：
        #     该 action 的支持条件键里没有 EnclosingOperation，而 ForAnyValue
        #     在键缺失时返回 false → 每次 ConditionCheck 都被拒。
        #   · 不列 dynamodb:Select（UpdateItem / ConditionCheck 不用该参数）。
        # 不含 GetItem：MCP 侧没有任何读路由表的代码（权限真源是 sites 表，
        # 路由表只是投影）。留着它反而是隐患——GetItem 不带 ProjectionExpression
        # 时请求上下文没有 dynamodb:Attributes，会被同 statement 的 Null 检查拒，
        # 于是"某天有人加了读路由的代码"会以 AccessDenied 的形态出现在生产。
        {"Sid": "RoutingProjection", "Effect": "Allow",
         "Action": ["dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"],
         "Resource": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/"
                     + CFG["Platform"]["routing_table"],
         "Condition": {
             "ForAllValues:StringEquals": {
                 "dynamodb:Attributes": list(ROUTE_PROJECTION_ATTRIBUTES)},
             # 真空真值兜底：缺键时 ForAllValues 为 true，等于没有这道闸门
             "Null": {"dynamodb:Attributes": "false"},
             "StringEqualsIfExists": {
                 "dynamodb:ReturnValues": ["NONE", "UPDATED_OLD", "UPDATED_NEW"]}}},
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


def _require_email_verified_cfg() -> str:
    """config.ini [IdP] require_email_verified → runtime 环境变量字符串。

    与 auth/deploy_auth.py 的同名函数保持一致：默认 "true"，只有显式
    写成 false 才关闭（拼错一律当 true——安全开关不做静默降级）。
    """
    raw = CFG["IdP"].get("require_email_verified", "") if CFG.has_section("IdP") else ""
    head = raw.split("#")[0].split(";")[0].strip().lower()
    return "false" if head == "false" else "true"


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
            # 权限投影的目标表（permissions.write_permissions 的第二个事务项）
            "ROUTING_TABLE": CFG["Platform"]["routing_table"],
            "TRUSTED_IDPS": CFG["IdP"]["provider_name"] if CFG.has_section("IdP") else "",
            # 与 auth 服务同一个开关（两处语义必须一致）：email 是授权主键，
            # 而联邦 email 默认 unverified。默认 "true"，只有接入不发该 claim
            # 的 IdP 时才在 config.ini 设 false。
            "REQUIRE_EMAIL_VERIFIED": _require_email_verified_cfg(),
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
    print("  检查：8 个工具列出 / 无 token 返回 401 /")
    print("       list_my_sites 的 owner == 登录的飞书邮箱（验证 email claim 透传）")


if __name__ == "__main__":
    main()
