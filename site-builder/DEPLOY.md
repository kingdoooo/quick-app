# Quick 自动化建站方案 — 部署 Runbook

本文档是把本方案部署到**你自己的 AWS 账号**的操作手册。所有代码 + 154 个单元测试
已完成；本手册覆盖的是**需要真实 AWS 资源、DNS、飞书凭证**的部署门禁，无法自动化。

- **区域**：`us-east-1`（Lambda@Edge、ACM、Quick Desktop 身份区域共同强制）
- 下文 `{account_id}`、`{base_domain}` 等**花括号占位符需手工替换成你的实际值**
  （与 config.ini 中对应字段一致）。注意与 `config.ini` 里的
  `frontend_bucket = site-frontend-{account_id}` 区分——那处是脚本读取时自动插值的，
  不需要手改；本文档里的命令是给你复制粘贴执行的，必须先替换
- **中心配置**：`site-builder/config.ini` 与 `router/config.ini`（都从同目录
`.example` 复制，gitignored；部署过程中逐段回填）
- 设计文档 `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`，实施计划 `docs/superpowers/plans/2026-07-21-quick-site-builder.md`

---

## 0. 前置要求（全部备齐才开始）

### AWS 账号与区域

任意 AWS 账号，需有创建 IAM 角色 / Lambda / CloudFront / DynamoDB / S3 /
Step Functions / CodeBuild / Aurora DSQL 的权限。

区域**必须 `us-east-1`**：Lambda@Edge 函数与 CloudFront 用的 ACM 证书强制在
us-east-1，Quick Desktop 身份区域当前也要求 us-east-1。这不是偏好而是硬约束——
换区需要改代码（见文末 Minor 里 region 硬编码的两处）。

### 域名与通配符证书

需要一个你能改 DNS 的域名（记为 `{base_domain}`），以及**签发在 us-east-1 的
`*.{base_domain}` 通配符证书**。站点 URL 形如
`https://app-{site_id}.{base_domain}`，登录端点固定 `auth.{base_domain}`——
所以必须通配符，单域名证书不够。

```bash
# 申请通配符证书（DNS 验证）
aws acm request-certificate --region us-east-1 \
  --domain-name "*.{base_domain}" --validation-method DNS
# 按输出的 CNAME 完成验证，等状态变 ISSUED：
aws acm describe-certificate --region us-east-1 \
  --certificate-arn {cert_arn} --query 'Certificate.Status'
```

证书 ARN 填 `router/config.ini` 的 `[CloudFront] certificate_arn`。

> **建议用专用域名或子域**（如 `apps.example.com`）：会话 cookie 下发在
> `.{base_domain}`，所有 `app-*.{base_domain}` 站点共享一次登录。用承载其他
> 业务的主域会让会话作用域覆盖无关系统。

### 飞书企业自建应用

站点登录与部署权限都绑飞书账号，需要一个企业自建应用：App ID / App Secret
（① 阶段部署 SSO 时作为参数输入），**必需权限：获取用户 userid、获取用户邮箱**。
重定向 URI 由 ① 阶段产出的 Cognito Hosted UI 决定，建完 Cognito 后回飞书后台补填。

邮箱权限不可省：`owner`（谁部署的、谁能改/删站点）与访问名单 `allowed_users`
都以飞书邮箱为标识，拿不到邮箱则整个权限模型不成立。

### SSM 参数


| 参数名                                | 何时创建               | 用途                                   |
| ---------------------------------- | ------------------ | ------------------------------------ |
| `/site-builder/jwt-secret`         | **部署 ② 之前手工创建**    | 站点会话 JWT 的 HS256 签名密钥，Edge 函数与登录服务共用 |
| `/site-builder/site-client-secret` | ① 阶段建完 Cognito 后写入 | 站点登录 App Client 的 secret             |


```bash
aws ssm put-parameter --region us-east-1 \
  --name /site-builder/jwt-secret --type SecureString \
  --value "$(openssl rand -hex 32)"
```

`jwt-secret` 必须早于 ② 存在：② 的栈部署时从 SSM 读它并字符串替换注入 Edge
函数（Lambda@Edge 不支持环境变量）。读取失败时会打印
`SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY` 警告，此时**不要继续**——否则每个会话
token 都验签失败，表现为无限登录跳转。

### 本机工具链


| 工具      | 要求                                                                 |
| ------- | ------------------------------------------------------------------ |
| AWS CLI | 已配置指向目标账号（`aws sts get-caller-identity` 确认）                        |
| CDK CLI | 用 `npx -y aws-cdk@latest`（部分环境全局 CDK 过旧）                           |
| Docker  | ④ 执行器栈需要（bundling 装 psycopg，拉 x86_64 镜像）；⑤ MCP 需 buildx 构 ARM64 镜像 |
| Python  | 3.12+                                                              |
| Node.js | 仅 `npx`（CDK 与 MCP Inspector）                                       |


### 成本预期（PoC 量级）


| 项                                              | 估算/月          |
| ---------------------------------------------- | ------------- |
| 路由层（CloudFront + Lambda@Edge + DynamoDB，1M 请求） | ~$2-5         |
| 站点 Lambda + S3（数十站点低流量）                        | ~$5-20        |
| Aurora DSQL 共享 cluster（低用量，按请求计费）              | ~$0-10        |
| AgentCore MCP + Step Functions + CodeBuild     | ~$5-15        |
| Cognito（月活 &lt;50）                             | 免费额度内         |
| **合计**                                         | **~$15-50/月** |


CloudFront 全站禁缓存是鉴权正确性的前提（origin-request 事件只在 cache miss
时执行），PoC 流量下成本影响可忽略；高流量场景需评估精细缓存（二期）。

## 部署顺序总览

组件间有依赖，必须按序：

```
①身份层(SSO)  →  ②路由层  →  ③DSQL  →  ④执行器  →  ⑤部署MCP  →  ⑥客户端接入  →  ⑦端到端彩排
   Cognito        CloudFront    cluster    SFN+Lambda   AgentCore     Skill+MCP      RUN_E2E
   (Task 3)       (Task 8)      (Task 13)  (Task 17)    (Task 20)     (Task 22)      (Task 23)
```

依赖关系：②需要①产出的 JWT_SECRET（已在 SSM）与 edge role；④需要①的 boundary、②的 edge_role_arn、③的 DSQL endpoint；⑤需要④的 state_machine_arn 与①的 Cognito。

开始前的就绪清单（详见上面 §0）：

- [ ] AWS 凭证指向目标账号 / us-east-1（`aws sts get-caller-identity`）
- [ ] `*.{base_domain}` ACM 证书 ISSUED（us-east-1）
- [ ] `{base_domain}` DNS 可修改（Route53 hosted zone 或等价）
- [ ] SSM `/site-builder/jwt-secret` 已创建（SecureString）
- [ ] 飞书企业自建应用（App ID/Secret，含用户 userid + 邮箱权限）
- [ ] Docker 运行中；`npx` 可用
- [ ] `site-builder/config.ini` 与 `router/config.ini` 已从 `.example` 复制并填好

---

## ① 身份层 — feishu-quick-sso（Task 3）

**产出**：Cognito User Pool + 飞书 OIDC 适配器；回填 `config.ini [Cognito]` 全部 4 项。

1. 克隆并按其 README 部署上游方案（Serverless 路线）：
  ```bash
   git clone https://github.com/aws-samples/sample-for-amazon-quick-sso-with-feishu /tmp/feishu-sso
   cd /tmp/feishu-sso && cat README.md
   # 按 README 部署，飞书 App ID/Secret 作为参数输入
  ```
2. 取 **User Pool ID**。上游栈的 CfnOutput 里有（`UserPoolId`），也可以直接查：
  ```bash
   aws cognito-idp list-user-pools --max-results 20 --region us-east-1 \
     --query "UserPools[?contains(Name,'Feishu')].{Id:Id,Name:Name}"
  ```
   回填 `config.ini [Cognito] user_pool_id`。

3. 取 **Hosted UI 域名**。⚠️ **上游栈的 CfnOutput 里没有这一项**（它输出的
   `DesktopAuthEndpoint` 等是 Quick Desktop SSO 的 API Gateway 代理端点，与站点
   登录无关），必须单独查 user pool 上的 domain 前缀：
  ```bash
   aws cognito-idp describe-user-pool --user-pool-id {user_pool_id} \
     --region us-east-1 --query 'UserPool.Domain' --output text
   # 输出形如：feishu-quick-sso-{account_id}-us-east-1
  ```
   拼成完整 URL 回填 `config.ini [Cognito] domain`：

   ```
   https://{上一行输出}.auth.us-east-1.amazoncognito.com
   ```

   **格式要求**：必须带 `https://` 前缀、末尾不带斜杠。`login_handler.py` 是直接
   拼接使用的（`f"{COGNITO_DOMAIN}/oauth2/authorize"`），写成裸域名会拼出无 scheme
   的地址导致登录跳转失败。

   > **这个 domain 不是你自己的域名**。它是 AWS 自动生成的 Cognito Hosted UI 地址
   > （承载登录页与 `/oauth2/authorize`、`/oauth2/token`）。你自己的域名填在
   > `[Platform] base_domain`，两者用途不同，别混。
   > 若用了 Cognito 自定义域名（`CustomDomain` 非空），则填那个自定义域名。

   验证域名可用（返回 302 说明端点正常；若 DNS 失败或 404 说明域名没建成）：
  ```bash
   curl -s -o /dev/null -w '%{http_code}\n' \
     "https://{domain_prefix}.auth.us-east-1.amazoncognito.com/oauth2/authorize"
  ```

4. 确认上游栈创建的 IdP 名称（下一步 `--supported-identity-providers` 要用，
   通常是 `Feishu`）：
  ```bash
   aws cognito-idp list-identity-providers --user-pool-id {user_pool_id} \
     --region us-east-1 --query 'Providers[].{Name:ProviderName,Type:ProviderType}'
  ```
5. 建两个 App Client（**不要复用上游已有的 Desktop/Web client**，那两个是给 Quick
   登录用的）：

   **回调 URL 用你自己的域名 `https://auth.{base_domain}/callback`**，不是 Cognito
   的 Hosted UI 域名。`login_handler.py` 在 /login 与 /callback 两处都发送
   `f"https://auth.{BASE_DOMAIN}/callback"` 作为 `redirect_uri`，Cognito 侧登记的
   值必须与它逐字符相同，否则换 token 时报 `redirect_mismatch`。

  ```bash
   # 站点登录 client（confidential，带 secret）
   aws cognito-idp create-user-pool-client --region us-east-1 \
     --user-pool-id {user_pool_id} --client-name site-auth \
     --generate-secret \
     --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
     --allowed-o-auth-flows-user-pool-client \
     --supported-identity-providers {idp_name} \
     --callback-urls https://auth.{base_domain}/callback \
     --logout-urls https://auth.{base_domain}/logout \
     --query 'UserPoolClient.ClientId' --output text
   # → 输出的 ClientId 回填 [Cognito] site_client_id
   # （--logout-urls 当前代码用不到：/logout 只清本地 cookie 不跳 Cognito 全局登出；
   #   先登记好，二期接全局登出时免改配置）

   # MCP client（AgentCore 用，public client 不加 --generate-secret）
   aws cognito-idp create-user-pool-client --region us-east-1 \
     --user-pool-id {user_pool_id} --client-name deploy-mcp \
     --allowed-o-auth-flows code --allowed-o-auth-scopes openid email \
     --allowed-o-auth-flows-user-pool-client \
     --supported-identity-providers {idp_name} \
     --callback-urls https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback \
     --query 'UserPoolClient.ClientId' --output text
   # → 输出的 ClientId 回填 [Cognito] mcp_client_id
  ```

   > 建完后可核对回调是否登记正确：
   > ```bash
   > aws cognito-idp describe-user-pool-client --user-pool-id {user_pool_id} \
   >   --client-id {site_client_id} --region us-east-1 \
   >   --query 'UserPoolClient.{Callbacks:CallbackURLs,Scopes:AllowedOAuthScopes,IdPs:SupportedIdentityProviders}'
   > ```
6. 把站点 client 的 secret 存 SSM（Task 5 的 auth-service 部署要读）：
  ```bash
   aws cognito-idp describe-user-pool-client --user-pool-id {user_pool_id} \
     --client-id {site_client_id} --region us-east-1 --query 'UserPoolClient.ClientSecret' --output text
   aws ssm put-parameter --name /site-builder/site-client-secret \
     --type SecureString --value {上一行输出的 secret} --region us-east-1
  ```
7. **验证点（人工门禁）**：在 Quick Web/Desktop 配置该 IdP，用飞书账号登录成功。Desktop 身份区域须 us-east-1。

**⚠️ 注意**：Task 20 spike 可能改变 MCP client 的 scope 需求（若 AgentCore 只透传 access token，email 需从 id_token 或额外 scope 取）——步骤 5 的第二个 client 配置以 spike 报告 `task-20-spike-report.md` 结论为准，可能需回来调整。

---

## ② 路由 + 鉴权层 — WebRouterStack（Task 8）

**产出**：CloudFront 分发（`*.{base_domain}`）+ 扩展路由表 + 前端桶；回填 `config.ini [Deployer] edge_role_arn`。

**前置**（来自 ①，缺任一项本阶段会失败）：
- `site-builder/config.ini [Cognito]` 四项已填（步骤 5 的 auth-service 要读
  `site_client_id`）
- SSM `/site-builder/site-client-secret` 已写入（① 步骤 6）
- SSM `/site-builder/jwt-secret` 已存在（§0；栈部署时注入 Edge 函数）

确认 `router/config.ini` 已填好：account_id / domain_name / certificate_arn /
frontend_bucket / base_domain（从 `router/config.ini.example` 复制）。

1. 建私有前端桶（若不存在）。**注意此桶不由 CDK 管理**，需手工建并配好
   public-access-block 与生命周期规则：
  ```bash
   # us-east-1 不要带 --create-bucket-configuration LocationConstraint
   aws s3api create-bucket --bucket site-frontend-{account_id} --region us-east-1
   aws s3api put-public-access-block --bucket site-frontend-{account_id} \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   # 旧版本前端清理：upload_frontend 只写新前缀不删旧的（发布期间线上仍用旧前缀），
   # mark_job 成功后清理当前站点旧版本；这条规则是兜底，防残留无限累积。
   aws s3api put-bucket-lifecycle-configuration --bucket site-frontend-{account_id} \
     --lifecycle-configuration '{"Rules":[{"ID":"expire-old-site-versions","Status":"Enabled","Filter":{"Prefix":"sites/"},"Expiration":{"Days":30}}]}'
  ```
   桶必须保持私有：Edge 函数用 SigV4 签名读它（见 `_add_s3_sigv4_auth`），
   不依赖公开访问。
2. 部署栈（首次需先 bootstrap）：
  ```bash
   cd router/infrastructure
   # --clear：首次创建与已存在时重建都适用。venv 的 shebang 是绝对路径，
   # 仓库被移动或改名后旧 venv 会报 "bad interpreter"，而不带 --clear 的
   # python3 -m venv 对已存在目录不会重写 shebang（重跑也修不了）
   python3 -m venv --clear .venv
   .venv/bin/pip install -r requirements.txt -q
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest bootstrap aws://{account_id}/us-east-1   # 首次
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
  ```

   stack.py 部署时会从 SSM 读真实 JWT_SECRET 注入 Edge 函数（`load_jwt_secret`）；若打印
   `SYNTH-ONLY-PLACEHOLDER` 警告说明 SSM 读取失败，**不要继续**——检查凭证与 SSM 参数。
3. 记录 CfnOutput 的 **EdgeRoleArn**，回填 `site-builder/config.ini [Deployer] edge_role_arn`（Task 17 执行器需要它给站点 Function URL 授权）。记录 **DistributionDomainName**。
4. DNS：在 `{base_domain}` 加通配符 CNAME 或 A-alias 指向 CloudFront 域名：
  ```
   *.{base_domain}  →  {distribution_domain_name}  (如 d1234abcd.cloudfront.net)
  ```
5. **部署 auth-service Lambda**（Task 5 的登录端点，依赖①的 Cognito + 本步骤的路由表）：
  ```bash
   cd ../../site-builder/auth && python3 deploy_auth.py
   # 它会：打 zip（含 pyjwt）→ 建/更新 Lambda site-auth-service → Function URL(NONE)
   #      → 生成/复用 SSM /site-builder/jwt-secret → 路由表注册 subdomain=auth (route_mode=api-only)
  ```
6. **冒烟**（CloudFront 传播需 15-30 分钟后再跑）：
  ```bash
   cd {仓库根} && bash site-builder/scripts/smoke_router.sh
  ```

   预期 6 行 PASS：static route / no cross-site cache / auth 302 / auth subdomain api-only routing / unknown 404 / route update visible。

---

## ③ Aurora DSQL cluster（Task 13）

**产出**：共享 DSQL cluster；回填 `config.ini [DSQL] cluster_endpoint`。

```bash
aws dsql create-cluster --region us-east-1 \
  --tags Key=project,Value=site-builder \
  --no-deletion-protection-enabled
aws dsql list-clusters --region us-east-1
# 取 endpoint（形如 {cluster_id}.dsql.us-east-1.on.aws），回填 [DSQL] cluster_endpoint
```

站点数据隔离由执行器在部署 SQL 站点时创建 per-site schema + per-site PG role +
`AWS IAM GRANT` 到该站点执行角色（provision_dsql.py）。此处只需 cluster 存在。

---

## ④ 异步执行器 — SiteDeployerStack（Task 17）

**产出**：jobs/sites 表、artifacts 桶、CodeBuild、状态机 `site-deploy`、10 个 step Lambda、undeploy Lambda、runtime boundary、exec role；回填 `config.ini [Deployer] state_machine_arn`。

**前置**：`[Deployer] edge_role_arn`（来自②）、`[DSQL] cluster_endpoint`（来自③）必须已回填，否则站点 Function URL 授权与 DSQL 连接会失败。

```bash
cd site-builder/deployer/infra
python3 -m venv --clear .venv                  # 见 ② 的说明：venv 不可跨路径复用
.venv/bin/pip install -r requirements.txt -q
# 部署（bundling 会用 Docker 拉 x86_64 镜像装 psycopg[binary]+sqlparse+contract 包）
PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

记录 CfnOutput 的 **StateMachineArn**，回填 `site-builder/config.ini [Deployer] state_machine_arn`。

**冒烟（手工触发一次 static 部署，验证执行器全链路）**：

```bash
cd {仓库根}
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_e2e_fixtures.py::test_static_site_public_200 -q
# 或用 deploy_fixture.py 直接跑：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/static-hello
```

预期：SFN execution SUCCEEDED，`curl https://app-{site_id}.{base_domain}/` 返回 fixture 首页。

**⚠️ Docker 拉镜像 403**：若 `public.ecr.aws` 凭证过期，先 `docker logout public.ecr.aws`
再重试（bundling 用匿名拉取）。

---

## ⑤ 部署 MCP — AgentCore Runtime（Task 20）

**代码已就绪并在本地真实容器里验证过**（ARM64 镜像构建 → 起容器 → 完整 MCP
握手 → Bearer token 的 email claim 被 `_caller_email()` 正确解出 → 平台注入的
`Mcp-Session-Id` 被容忍）。`get_http_headers` 问题早已按 spike 结论修掉，
详见 `site-builder/mcp/AGENTCORE-SPIKE.md`。

**前置**：④ 的 `state_machine_arn`、① 的 `mcp_client_id` / `user_pool_id` 必须已回填。

```bash
cd site-builder/mcp
python3 deploy_agentcore.py        # 建 ECR → buildx ARM64 → 推送 → 建角色 → 建/更新 runtime
# 只改配置不重建镜像：python3 deploy_agentcore.py --skip-build
```

脚本做的事（全部幂等）：ECR 仓库 → cp `deployer/functions/common.py` 进构建上下文 →
`docker buildx --platform linux/arm64` 构建推送 → runtime 执行角色
（jobs/sites 表、`uploads/*` presign、`states:StartExecution`、undeploy `lambda:InvokeFunction`）→
`create_agent_runtime`（`serverProtocol=MCP`、Cognito `customJWTAuthorizer`、
`requestHeaderAllowlist=["Authorization"]`）。运行结束会打印要回填的
`[MCP] endpoint_url`。

**三个契约要点**（违反的症状都是"部署完才发现连不上"，已由 `tests/test_agentcore_contract.py` 锁定）：

- 容器必须 **ARM64**，监听 **0.0.0.0:8000**、暴露 **POST /mcp**、**stateless** streamable-http；
- `Authorization` 必须显式进 `requestHeaderAllowlist`，否则平台不透传该头，
所有工具报"无法识别调用者身份"；而透传 `Authorization` 又要求配 `customJWTAuthorizer`；
- `agentRuntimeName` 只允许 `[a-zA-Z][a-zA-Z0-9_]{0,47}`（连字符会被 API 拒）。

**冒烟**：`npx @modelcontextprotocol/inspector` 连 endpoint（带 Cognito Bearer token），
确认列出 5 工具、无 token 返回 401、`list_my_sites` 的 owner == 登录用户飞书邮箱。

**⚠️ 唯一待真机确认项**：AgentCore 透传的是 id_token 还是 access token。Cognito
access token 默认**不含 email**——若 owner 取不到，改用
`allowedAudience=[mcp_client_id]`（id_token 用 `aud`）或加 pre-token-generation
Lambda 注入 email。处置办法见 `site-builder/docs/client-setup.md`。

---

## ⑥ 客户端接入（Task 22）

**Claude Code（先做，自动化程度高）**：

```bash
mkdir -p ~/.claude/skills && cp -r site-builder/skills/site-builder ~/.claude/skills/
claude mcp add --transport http site-builder-deploy {mcp_endpoint_url}
```

新会话提示："用 site-builder 技能给我做一个团队读书清单站点，能加书标记读完，全组织可看，做完部署" → 应走完 Skill 工作流 → MCP 部署 → 返回 URL → 浏览器飞书登录 + 加书验证。

**Quick Desktop（人工，核心演示通道）**：导入 site-builder Skill + Capabilities→MCP 添加 endpoint（OAuth 走飞书登录）。

完整步骤、逐客户端冒烟清单与 email claim 排查办法见 [**docs/client-setup.md**](docs/client-setup.md)。

---

## ⑦ 端到端彩排（Task 23）

```bash
# 前一天跑：全链路 E2E（用 JWT_SECRET mint 测试会话 cookie，自动化 CRUD，无需人工扫码）
cd {仓库根}
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q
```

预期 4 passed：static 200、notes 未登录 302 + 登录后 CRUD + author=飞书邮箱、expenses DSQL CRUD、undeploy 后 404。

演示叙事（10 分钟）与故障预案见 plan Task 23。

---

## 部署后回填检查清单

`site-builder/config.ini` 全部字段应非空：


| 段          | 字段                                                     | 来源                          |
| ---------- | ------------------------------------------------------ | --------------------------- |
| [Cognito]  | user_pool_id / domain / site_client_id / mcp_client_id | ①                           |
| [DSQL]     | cluster_endpoint                                       | ③                           |
| [Deployer] | edge_role_arn                                          | ② CfnOutput EdgeRoleArn     |
| [Deployer] | state_machine_arn                                      | ④ CfnOutput StateMachineArn |
| [MCP]      | endpoint_url                                           | ⑤                           |


SSM 参数：`/site-builder/jwt-secret`（已存在）、`/site-builder/site-client-secret`（① 步骤 5 写入）。

## 已知限制与延后项（向客户声明）

- Quick Desktop 为 preview、身份区域须 us-east-1
- 顶域 cookie 使所有 `app-*.{base_domain}` 站点共享一次登录（PoC 可接受，产品化需按站点隔离会话）
- PoC 仅 Node.js 后端（Python 3.13 延后）；MCP 仅 OAuth（API Key fallback 延后）
- CloudFront 全站禁缓存（正确性优先；精细缓存延后）
- 详见设计文档 §8 风险 / §9 范围外

## 2026-07-27 独立审查后的修复（已实证验证，部署前必读）

两轮独立审查（本机 + Codex）确认的 P0 已修复并用真实 AWS API 验证：


| 问题                                                        | 修复                                                                                            | 验证方式                                                           |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Edge S3 签名缺 `x-amz-content-sha256`，所有静态页 400              | 改用 `S3SigV4Auth`                                                                              | 真实 us-east-1 桶探针：修前 400 InvalidRequest，修后 404 NoSuchKey（签名被接受） |
| 顶域 `sb_session` 被转发给不可信站点后端，可跨站重放                         | Edge 验签后按 origin 剥除；新增 origin-response 剥除站点写的平台 cookie                                        | 4 个场景单测（站点剥除/站点自有 cookie 保留/auth 子域保留/伪造标记被剥）                  |
| Function URL 缺 2025-10 起要求的第二个权限                          | 三处各加 `lambda:InvokeFunction` + `InvokedViaFunctionUrl`                                        | AWS 官方文档 urls-auth 明确要求两者                                      |
| exec role 缺 `lambda:GetFunctionConfiguration`（waiter 轮询它） | 补该 action                                                                                     | `aws iam simulate-custom-policy`：修前 implicitDeny，修后 allowed    |
| `site_name` 未校验 → DSQL admin SQL 注入 + IAM/Lambda 命名炸裂     | `common.validate_site_name` 入口卡 `^[a-z][a-z0-9-]{1,29}$`                                      | 单测覆盖注入串/空格/大写等 9 种非法输入                                         |
| `npm install` 执行站点 preinstall 脚本（CodeBuild 内任意代码执行）       | `--ignore-scripts` + 删 `.npmrc` + 红线拦生命周期脚本 + CodeBuild 角色收窄到 `uploads/*` 只读、`artifacts/*` 只写 | 红线单测 + synth 确认无整桶读写                                           |
| 站点 SQL 以 DSQL admin 执行，可跨 schema 读写/销毁                    | 拆两个连接：admin 只引导 schema/role；站点提交的 SQL 以 per-site migrator role 执行                             | 单测断言站点 DDL 绝不出现在 admin 连接；bootstrap SQL 过 DSQL linter          |
| `CREATE ROLE`/`AWS IAM GRANT` 裸 `except: pass` 吞真实错误      | 只容忍 duplicate（SQLSTATE 42710/42P06），其余抛出                                                      | 单测覆盖 42601 语法错/42501 权限不足必抛                                    |
| 回跳白名单可被 `https://evil.com\.{base_domain}/` 绕过             | 拒反斜杠 + 强制 https                                                                               | 8 组用例；Python urlparse 与 Node WHATWG 解析差异实测                     |


**仍需真机验证**：`AWS IAM GRANT` 对真实 DSQL 的语法与幂等 sqlstate（③ 冒烟覆盖）；
migrator role 的 `ALTER DEFAULT PRIVILEGES FOR ROLE` 是否被接受（失败无损，末尾有显式 GRANT 兜底）。

## 待部署时验证的 Minor（来自各任务审查，记录在 .superpowers/sdd/progress.md）

- `_add_s3_sigv4_auth` 用 `quote(uri)` 签名但转发原样 URI：非 ASCII 文件名（中文/空格）可能 SignatureDoesNotMatch。PoC 生成的资产路径均 ASCII，不受影响；若客户站点用非 ASCII 静态文件名需修。
- `_site_policy` 与 Edge S3 签名 region 硬编码 us-east-1（与部署区一致，换区需改）。
- `provision_dsql` 的 `migrations/*.sql` 不经红线扫描（只扫 schema.sql）；migration 里的禁用 DDL 会在 provision-db 阶段才失败（可读报错，非静默）。
- 跑测试的 venv：`site-builder/auth` 无自己的 venv，用 `site-builder/contract/.venv/bin/pytest tests`（含 pyjwt）；`site-builder/deployer` 必须 `pytest tests`（裸 `pytest -q` 会误收集 `infra/cdk.out` 里的 asset 副本）。

