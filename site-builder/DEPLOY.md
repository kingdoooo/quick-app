# Quick 自动化建站方案 — 部署 Runbook

本文档是把 `site-builder` 分支已实现的代码部署到真实 AWS 的操作手册。所有代码 +
单元测试（133 个）已完成并提交；本手册覆盖的是**需要真实 AWS 资源、DNS、飞书凭证**
的部署门禁，无法自动化。

- **目标账号**：`{account_id}` / `us-east-1`（Lambda@Edge、ACM、Quick Desktop 身份区域共同强制）
- **域名**：`dsir.cc`（通配符 ACM 证书已就绪：`arn:aws:acm:us-east-1:{account_id}:certificate/2fc6413a-892c-4654-917e-78132db2ad10`，状态 ISSUED）
- **中心配置**：`site-builder/config.ini`（gitignored，含真实值；部署过程中逐段回填）
- 设计文档 `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`，实施计划 `docs/superpowers/plans/2026-07-21-quick-site-builder.md`

## 部署顺序总览

组件间有依赖，必须按序：

```
①身份层(SSO)  →  ②路由层  →  ③DSQL  →  ④执行器  →  ⑤部署MCP  →  ⑥客户端接入  →  ⑦端到端彩排
   Cognito        CloudFront    cluster    SFN+Lambda   AgentCore     Skill+MCP      RUN_E2E
   (Task 3)       (Task 8)      (Task 13)  (Task 17)    (Task 20)     (Task 22)      (Task 23)
```

依赖关系：②需要①产出的 JWT_SECRET（已在 SSM）与 edge role；④需要①的 boundary、②的 edge_role_arn、③的 DSQL endpoint；⑤需要④的 state_machine_arn 与①的 Cognito。

前置检查（全部满足才开始）：
- [x] AWS 凭证指向 {account_id} / us-east-1（`aws sts get-caller-identity`）
- [x] `*.dsir.cc` ACM 证书 ISSUED
- [x] SSM `/site-builder/jwt-secret` 已存在（SecureString）
- [x] `dsir.cc` Route53 hosted zone 存在
- [ ] 飞书企业自建应用（App ID/Secret，权限：获取用户 userid、获取用户邮箱）
- [ ] 本机 CDK CLI 用 `npx -y aws-cdk@latest`（全局 CLI 2.1100.1 过旧）
- [ ] Docker 运行中（Task 17 执行器 Lambda 用 bundling 装 psycopg，需拉 x86_64 镜像）

---

## ① 身份层 — feishu-quick-sso（Task 3）

**产出**：Cognito User Pool + 飞书 OIDC 适配器；回填 `config.ini [Cognito]` 全部 4 项。

1. 克隆并按其 README 部署上游方案（Serverless 路线）：
   ```bash
   git clone https://github.com/aws-samples/sample-for-amazon-quick-sso-with-feishu /tmp/feishu-sso
   cd /tmp/feishu-sso && cat README.md
   # 按 README 部署，飞书 App ID/Secret 作为参数输入
   ```
2. 记录产出的 **User Pool ID** 和 **Hosted UI 域名**，回填 `config.ini [Cognito]` 的 `user_pool_id`、`domain`。
3. 先确认上游栈创建的 IdP 名称（下一步 `--supported-identity-providers` 要用）：
   ```bash
   aws cognito-idp list-identity-providers --user-pool-id <USER_POOL_ID> --region us-east-1
   ```
4. 建两个 App Client（站点登录用带 secret，MCP 用）：
   ```bash
   # 站点登录 client（confidential，带 secret）
   aws cognito-idp create-user-pool-client --region us-east-1 \
     --user-pool-id <USER_POOL_ID> --client-name site-auth \
     --generate-secret \
     --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
     --allowed-o-auth-flows-user-pool-client \
     --supported-identity-providers <IdP名> \
     --callback-urls https://auth.dsir.cc/callback
   # → 记录 ClientId 回填 [Cognito] site_client_id

   # MCP client（AgentCore 用；回调 URL 见 Task 20 spike 结论）
   aws cognito-idp create-user-pool-client --region us-east-1 \
     --user-pool-id <USER_POOL_ID> --client-name deploy-mcp \
     --allowed-o-auth-flows code --allowed-o-auth-scopes openid email \
     --allowed-o-auth-flows-user-pool-client \
     --supported-identity-providers <IdP名> \
     --callback-urls https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback
   # → 记录 ClientId 回填 [Cognito] mcp_client_id
   ```
5. 把站点 client 的 secret 存 SSM（Task 5 的 auth-service 部署要读）：
   ```bash
   aws cognito-idp describe-user-pool-client --user-pool-id <USER_POOL_ID> \
     --client-id <site_client_id> --region us-east-1 --query 'UserPoolClient.ClientSecret' --output text
   aws ssm put-parameter --name /site-builder/site-client-secret \
     --type SecureString --value <上一行输出的 secret> --region us-east-1
   ```
6. **验证点（人工门禁）**：在 Quick Web/Desktop 配置该 IdP，用飞书账号登录成功。Desktop 身份区域须 us-east-1。

**⚠️ 注意**：Task 20 spike 可能改变 MCP client 的 scope 需求（若 AgentCore 只透传 access token，email 需从 id_token 或额外 scope 取）——步骤 4 的第二个 client 配置以 spike 报告 `task-20-spike-report.md` 结论为准，可能需回来调整。

---

## ② 路由 + 鉴权层 — manus WebRouterStack（Task 8）

**产出**：CloudFront 分发（`*.dsir.cc`）+ 扩展路由表 + 前端桶；回填 `config.ini [Deployer] edge_role_arn`。

`manus-web-application-main/config.ini` 已配好真实值（account/domain/cert/frontend_bucket/base_domain）。

1. 建私有前端桶（若不存在）：
   ```bash
   aws s3api create-bucket --bucket site-frontend-{account_id} --region us-east-1
   aws s3api put-public-access-block --bucket site-frontend-{account_id} \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```
2. 部署栈（首次需先 bootstrap）：
   ```bash
   cd manus-web-application-main/infrastructure
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -q
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest bootstrap aws://{account_id}/us-east-1   # 首次
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
   ```
   stack.py 部署时会从 SSM 读真实 JWT_SECRET 注入 Edge 函数（`load_jwt_secret`）；若打印
   `SYNTH-ONLY-PLACEHOLDER` 警告说明 SSM 读取失败，**不要继续**——检查凭证与 SSM 参数。
3. 记录 CfnOutput 的 **EdgeRoleArn**，回填 `site-builder/config.ini [Deployer] edge_role_arn`（Task 17 执行器需要它给站点 Function URL 授权）。记录 **DistributionDomainName**。
4. DNS：在 Route53 `dsir.cc` 加通配符 CNAME 或 A-alias 指向 CloudFront 域名：
   ```
   *.dsir.cc  →  <DistributionDomainName>  (如 d1234abcd.cloudfront.net)
   ```
5. **部署 auth-service Lambda**（Task 5 的登录端点，依赖①的 Cognito + 本步骤的路由表）：
   ```bash
   cd ../../site-builder/auth && python3 deploy_auth.py
   # 它会：打 zip（含 pyjwt）→ 建/更新 Lambda site-auth-service → Function URL(NONE)
   #      → 生成/复用 SSM /site-builder/jwt-secret → 路由表注册 subdomain=auth (route_mode=api-only)
   ```
6. **冒烟**（CloudFront 传播需 15-30 分钟后再跑）：
   ```bash
   cd /Users/kentpeng/projects/quick-app && bash site-builder/scripts/smoke_router.sh
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
# 取 endpoint（形如 <id>.dsql.us-east-1.on.aws），回填 [DSQL] cluster_endpoint
```

站点数据隔离由执行器在部署 SQL 站点时创建 per-site schema + per-site PG role +
`AWS IAM GRANT` 到该站点执行角色（provision_dsql.py）。此处只需 cluster 存在。

---

## ④ 异步执行器 — SiteDeployerStack（Task 17）

**产出**：jobs/sites 表、artifacts 桶、CodeBuild、状态机 `site-deploy`、10 个 step Lambda、undeploy Lambda、runtime boundary、exec role；回填 `config.ini [Deployer] state_machine_arn`。

**前置**：`[Deployer] edge_role_arn`（来自②）、`[DSQL] cluster_endpoint`（来自③）必须已回填，否则站点 Function URL 授权与 DSQL 连接会失败。

```bash
cd site-builder/deployer/infra
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -q
# 部署（bundling 会用 Docker 拉 x86_64 镜像装 psycopg[binary]+sqlparse+contract 包）
PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

记录 CfnOutput 的 **StateMachineArn**，回填 `site-builder/config.ini [Deployer] state_machine_arn`。

**冒烟（手工触发一次 static 部署，验证执行器全链路）**：
```bash
cd /Users/kentpeng/projects/quick-app
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_e2e_fixtures.py::test_static_site_public_200 -q
# 或用 deploy_fixture.py 直接跑：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/static-hello
```
预期：SFN execution SUCCEEDED，`curl https://app-<siteid>.dsir.cc/` 返回 fixture 首页。

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
claude mcp add --transport http site-builder-deploy <MCP_ENDPOINT_URL>
```
新会话提示："用 site-builder 技能给我做一个团队读书清单站点，能加书标记读完，全组织可看，做完部署" → 应走完 Skill 工作流 → MCP 部署 → 返回 URL → 浏览器飞书登录 + 加书验证。

**Quick Desktop（人工，核心演示通道）**：导入 site-builder Skill + Capabilities→MCP 添加 endpoint（OAuth 走飞书登录）。

完整步骤、逐客户端冒烟清单与 email claim 排查办法见 **[docs/client-setup.md](docs/client-setup.md)**。

---

## ⑦ 端到端彩排（Task 23）

```bash
# 前一天跑：全链路 E2E（用 JWT_SECRET mint 测试会话 cookie，自动化 CRUD，无需人工扫码）
cd /Users/kentpeng/projects/quick-app
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q
```
预期 4 passed：static 200、notes 未登录 302 + 登录后 CRUD + author=飞书邮箱、expenses DSQL CRUD、undeploy 后 404。

演示叙事（10 分钟）与故障预案见 plan Task 23。

---

## 部署后回填检查清单

`site-builder/config.ini` 全部字段应非空：

| 段 | 字段 | 来源 |
|---|---|---|
| [Cognito] | user_pool_id / domain / site_client_id / mcp_client_id | ① |
| [DSQL] | cluster_endpoint | ③ |
| [Deployer] | edge_role_arn | ② CfnOutput EdgeRoleArn |
| [Deployer] | state_machine_arn | ④ CfnOutput StateMachineArn |
| [MCP] | endpoint_url | ⑤ |

SSM 参数：`/site-builder/jwt-secret`（已存在）、`/site-builder/site-client-secret`（① 步骤 5 写入）。

## 已知限制与延后项（向客户声明）

- Quick Desktop 为 preview、身份区域须 us-east-1
- 顶域 cookie 使所有 `app-*.dsir.cc` 站点共享一次登录（PoC 可接受，产品化需按站点隔离会话）
- PoC 仅 Node.js 后端（Python 3.13 延后）；MCP 仅 OAuth（API Key fallback 延后）
- CloudFront 全站禁缓存（正确性优先；精细缓存延后）
- 详见设计文档 §8 风险 / §9 范围外

## 2026-07-27 独立审查后的修复（已实证验证，部署前必读）

两轮独立审查（本机 + Codex）确认的 P0 已修复并用真实 AWS API 验证：

| 问题 | 修复 | 验证方式 |
|---|---|---|
| Edge S3 签名缺 `x-amz-content-sha256`，所有静态页 400 | 改用 `S3SigV4Auth` | 真实 us-east-1 桶探针：修前 400 InvalidRequest，修后 404 NoSuchKey（签名被接受） |
| 顶域 `sb_session` 被转发给不可信站点后端，可跨站重放 | Edge 验签后按 origin 剥除；新增 origin-response 剥除站点写的平台 cookie | 4 个场景单测（站点剥除/站点自有 cookie 保留/auth 子域保留/伪造标记被剥） |
| Function URL 缺 2025-10 起要求的第二个权限 | 三处各加 `lambda:InvokeFunction` + `InvokedViaFunctionUrl` | AWS 官方文档 urls-auth 明确要求两者 |
| exec role 缺 `lambda:GetFunctionConfiguration`（waiter 轮询它） | 补该 action | `aws iam simulate-custom-policy`：修前 implicitDeny，修后 allowed |
| `site_name` 未校验 → DSQL admin SQL 注入 + IAM/Lambda 命名炸裂 | `common.validate_site_name` 入口卡 `^[a-z][a-z0-9-]{1,29}$` | 单测覆盖注入串/空格/大写等 9 种非法输入 |
| `npm install` 执行站点 preinstall 脚本（CodeBuild 内任意代码执行） | `--ignore-scripts` + 删 `.npmrc` + 红线拦生命周期脚本 + CodeBuild 角色收窄到 `uploads/*` 只读、`artifacts/*` 只写 | 红线单测 + synth 确认无整桶读写 |
| 站点 SQL 以 DSQL admin 执行，可跨 schema 读写/销毁 | 拆两个连接：admin 只引导 schema/role；站点提交的 SQL 以 per-site migrator role 执行 | 单测断言站点 DDL 绝不出现在 admin 连接；bootstrap SQL 过 DSQL linter |
| `CREATE ROLE`/`AWS IAM GRANT` 裸 `except: pass` 吞真实错误 | 只容忍 duplicate（SQLSTATE 42710/42P06），其余抛出 | 单测覆盖 42601 语法错/42501 权限不足必抛 |
| 回跳白名单可被 `https://evil.com\.dsir.cc/` 绕过 | 拒反斜杠 + 强制 https | 8 组用例；Python urlparse 与 Node WHATWG 解析差异实测 |

**仍需真机验证**：`AWS IAM GRANT` 对真实 DSQL 的语法与幂等 sqlstate（③ 冒烟覆盖）；
migrator role 的 `ALTER DEFAULT PRIVILEGES FOR ROLE` 是否被接受（失败无损，末尾有显式 GRANT 兜底）。

## 待部署时验证的 Minor（来自各任务审查，记录在 .superpowers/sdd/progress.md）

- `_add_s3_sigv4_auth` 用 `quote(uri)` 签名但转发原样 URI：非 ASCII 文件名（中文/空格）可能 SignatureDoesNotMatch。PoC 生成的资产路径均 ASCII，不受影响；若客户站点用非 ASCII 静态文件名需修。
- `_site_policy` 与 Edge S3 签名 region 硬编码 us-east-1（与部署区一致，换区需改）。
- `provision_dsql` 的 `migrations/*.sql` 不经红线扫描（只扫 schema.sql）；migration 里的禁用 DDL 会在 provision-db 阶段才失败（可读报错，非静默）。
- 跑测试的 venv：`site-builder/auth` 无自己的 venv，用 `site-builder/contract/.venv/bin/pytest tests`（含 pyjwt）；`site-builder/deployer` 必须 `pytest tests`（裸 `pytest -q` 会误收集 `infra/cdk.out` 里的 asset 副本）。
