# Quick 自动化建站方案（Site Builder）设计文档

- **日期**：2026-07-21
- **状态**：设计已确认（brainstorming 完成），待实施计划
- **交付形态**：客户 PoC / 参考方案——业务人员在 Amazon Quick Desktop（或其他 Agent 客户端）里开发简易全栈站点后，一键部署到客户自己的 AWS 账号，站点登录与管理权限绑定飞书账号

## 1. 背景与目标

客户业务人员使用 Amazon Quick Desktop（飞书 SSO 登录）开发带 Web 前端 + 数据库后端的简易站点，不希望用 EC2/RDS 等重资产部署。目标是提供类似 manus 的体验：开发完成后一键部署，拿到可分享的子域名 URL，站点访问和管理权限与飞书账号结合。

**成功标准（端到端演示链路）**：业务人员在 Quick Desktop（飞书 SSO 登录）里用自然语言开发一个带数据库的小站点 → 说"部署" → 拿到 `https://app-xxx.<域名>` → 用飞书账号登录该站点 → 增删改查数据——全程不碰 AWS 控制台。

**参考资料**：
- 飞书文档《AI Coding Agent 建站平台：三大基础设施模式深度拆解》（YDkddDkyHovVv2xJkU6c6BxcnJd）
- 飞书文档《Coding Agent 建站平台 — 技术路径拆解》（RmVPd8X71oh0pvxXo0Wc2HHSnUb，Solution 1/2 拼合方案）
- 本地项目 `manus-web-application-main`（CloudFront + Lambda@Edge + DynamoDB 子域名路由，即 Solution 1）
- [aws/aws-lambda-web-adapter](https://github.com/aws/aws-lambda-web-adapter)
- 飞书 × Quick 集成调研笔记 `~/learning/topics/004-amazon-quick-feishu-integration/README.md`（含 SSO 两条路线、MCP 三方案）

## 2. 总体架构

选定方案：**异步部署 + 边缘统一鉴权**。

```
┌─────────────────────────────────────────────────────────────┐
│ ① 建站 Skill（Agent Skills 开放标准，"部署合同"）             │
│    Quick Desktop / Claude Code / Kiro / Qoder 等通用          │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP 调用（OAuth 携带飞书身份）
┌──────────────────────────▼──────────────────────────────────┐
│ ② 部署 MCP（AgentCore Runtime，薄壳）                        │
│    deploy_site / get_deploy_status / list_my_sites /         │
│    undeploy_site —— 只提交任务和查状态，秒级返回              │
└──────────────────────────┬──────────────────────────────────┘
                           │ 写部署任务表 + 启动执行
┌──────────────────────────▼──────────────────────────────────┐
│ ③ 异步部署执行器（Step Functions + Lambda + CodeBuild）      │
│    校验合同 → 开数据库 → 打包建 Lambda → 上传 S3 → 注册路由   │
└──────────────────────────┬──────────────────────────────────┘
                           │ 写路由表（subdomain → targets + auth 策略）
┌──────────────────────────▼──────────────────────────────────┐
│ ④ 路由 + 鉴权层（manus-web-application 复用改造）             │
│    CloudFront(*.域名) → Lambda@Edge：查路由 + 验飞书会话      │
└──────────────────────────┬──────────────────────────────────┘
                           │ 未登录跳转
┌──────────────────────────▼──────────────────────────────────┐
│ ⑤ 飞书身份层（feishu-quick-sso 复用扩展）                    │
│    Cognito User Pool + 飞书 OIDC 适配器 Lambda                │
│    一套身份三处消费：Quick SSO / 站点访问 / 部署权限          │
└─────────────────────────────────────────────────────────────┘
```

### 关键设计决策

1. **不做代码生成**。代码生成由 Quick Desktop（或 Quick 集成的 Claude Code / Kiro）完成——这是 Quick 的价值所在。本方案只做 Quick 做不了的"部署到 AWS"一段。参考项目 Solution 2 的 Strands Agent / Code Interpreter / Model Router 整体不引入。
2. **manus Solution 1（子域名路由）复用改造**：Lambda@Edge 查路由后增加 auth 策略检查（路由表加 `require_auth` / `allowed_users` / `owner` / `route_mode` 字段）。**CloudFront 全站禁用缓存（CACHING_DISABLED）**——origin-request 事件只在 cache miss 时执行，任何缓存都会绕过鉴权并可能跨子域串内容；PoC 流量下无缓存的成本影响可忽略，精细缓存（viewer-request 鉴权 + cache key 分区）记为二期。
3. **后端部署走 zip + Lambda Web Adapter Layer，不用容器镜像**。manus README 记录的 LWA 失败全部是 Docker 镜像模式（`exec format error` 为镜像架构问题）；参考文档 Solution 2 实测 zip + 公开 Layer ARN（`arn:aws:lambda:<region>:753240598075:layer:LambdaAdapterLayerX86:28`）路线可行，且免去 ECR/Docker 构建链。
4. **部署异步化**规避 Quick MCP 60 秒工具调用超时（HTTP 424）：`deploy_site` 提交即返回 jobId，Skill 轮询 `get_deploy_status`。
5. **站点代码零 auth 逻辑**：鉴权统一在边缘做，生成代码越少越不容易错，最符合业务人员场景。
6. **一套 Cognito 三个消费方**：飞书身份贯穿全链路——部署时知道"谁部署的"，访问时知道"谁在访问"。

### 候选方案与否决理由

- **B：MCP 同步直执行 + 站点内嵌鉴权**——组件最少，但建库/建函数极易撞 60s 超时；每个站点的 auth 代码靠 AI 生成，错误面大。否决。
- **C：GitOps（CodeBuild/Pipeline 全链路）**——可审计可回滚、最接近生产形态，但 PoC 阶段建设量过大。否决（其构建环节以单次 CodeBuild 任务的形式被方案 A 吸收）。

## 3. 组件设计

### 3.1 建站 Skill 与部署合同

**部署合同（Deployment Contract）是方案锚点**：纯文件约定，与生成代码的 agent 无关，部署执行器只认合同。

产物目录结构：

```
my-site/
├── site.json              # 部署清单（合同核心）
├── frontend/              # 静态前端（必须）
│   ├── index.html
│   └── assets/...
└── backend/               # 后端（可选，按 tier 出现）
    ├── server.js          # 或 app.py
    ├── package.json       # 或 requirements.txt
    └── schema.sql         # 仅 fullstack-sql
```

`site.json` 字段：

```json
{
  "name": "expense-tracker",
  "tier": "fullstack-sql",
  "backend": {
    "runtime": "nodejs22.x",
    "entrypoint": "node server.js",
    "port": 8080
  },
  "database": {
    "engine": "dsql",
    "tables": []
  },
  "auth": {
    "require_login": true,
    "allowed_users": "org"
  }
}
```

- `tier`: `static` | `fullstack-nosql` | `fullstack-sql`
- `backend.runtime`: PoC 仅支持 `nodejs22.x`（Express）；Python 支持记为二期（需补 db.py 模板、Python fixture 与 E2E 后才宣称支持）
- `database.engine`: `none` | `dynamodb` | `dsql`；dynamodb 时 `tables` 列表名 + 主键定义（表名/主键须匹配 `[a-z][a-z0-9_-]*`，至多 10 张，不得重复）；dsql 时 schema 在 `schema.sql`
- `auth.allowed_users`: `"org"`（全组织飞书用户）或邮箱数组

三档 tier 的生成约束：

| tier | 前端 | 后端 | 数据库 | 典型场景 |
|---|---|---|---|---|
| `static` | 纯 HTML/JS/CSS | 无 | 无 | 展示页、报表页 |
| `fullstack-nosql` | 静态 + fetch `/api/*` | Express/FastAPI | DynamoDB，环境变量 `TABLE_<NAME>` 注入表名 | 记录型小工具 |
| `fullstack-sql` | 静态 + fetch `/api/*` | Express/FastAPI | Aurora DSQL，环境变量 `DATABASE_URL` 注入连接串 | 关系型业务 |

**代码红线**（写进 Skill，防 AI 生成不可部署代码）：

1. 前端 API 调用一律相对路径 `/api/*`，禁止 localhost、禁止硬编码域名。前后端同域名部署（路由层按 `/api/*` 分流），消除参考方案里"两步部署 + `{{BACKEND_URL}}` 占位符注入"的复杂度。
2. 站点代码不写任何登录逻辑。需要当前用户时读请求头 `x-user-email` / `x-user-name`（Edge 鉴权通过后注入），后端直接信任。
3. DSQL 访问只通过 Skill 提供的固定模板文件 `db.js`（原样复制进 backend/，内部用站点专属 PG role 的非 admin IAM token 现签连接并 SET search_path）；schema 全部写在 `schema.sql`（执行器负责执行）；Skill 中写明 DSQL 不支持的 PG 特性（外键约束、SERIAL、JSONB 列、触发器/PLpgSQL、临时表等）要求生成时规避（UUID 主键、TEXT 存 JSON 等替代）。DynamoDB 只用 SDK 基础 CRUD。
4. 无本地文件写入、无后台常驻任务（Lambda 约束）；监听端口读 `PORT` 环境变量；API 请求/响应体 ≤1MB（Edge 转发上限）。
5. 前端渲染用户输入时用 `textContent` 或转义，禁止把输入直接拼进 `innerHTML`（防存储型 XSS——站点在组织内共享会话，XSS 危害被顶域 cookie 放大）。

**Skill 工作流**：需求澄清 → 按 tier 生成代码 → 本地预览确认 → 用户说"部署" → 打包 zip → 调 MCP `deploy_site`（拿 presigned URL 上传产物）→ 轮询 `get_deploy_status` → 返回站点 URL。业务人员全程自然语言对话。

**客户端兼容性**：规则载体统一采用 Agent Skills 开放标准（SKILL.md + 资源文件），一份 `site-builder` Skill 同时服务 Quick Desktop、Claude Code、Kiro、Qoder 等主流 Agent 客户端，不做每客户端派生。规范文档为 single source of truth。

### 3.2 部署 MCP（AgentCore Runtime）

标准 Streamable HTTP MCP Server，部署在 Bedrock AgentCore Runtime（复用飞书集成调研中方案 3 的部署形态，但工具面只有 4 个，无需 Tier1/Tier2 分层）：

| 工具 | 行为 | 返回 |
|---|---|---|
| `deploy_site` | 新站点分配 siteId（更新则校验 owner）→ 生成 jobId + 产物上传 presigned URL（15 分钟有效，限制大小） | jobId、siteId、upload_url |
| `confirm_upload` | HeadObject 确认 zip 已上传 → jobs 表条件迁移 PENDING→RUNNING（防重复提交）→ 以 jobId 为 execution name 启动 Step Functions（天然幂等） | status |
| `get_deploy_status` | 查任务表（owner 校验） | status/phase/error/url |
| `list_my_sites` | 按 owner 查站点表 | 站点列表 |
| `undeploy_site` | 校验 owner → 提交下线任务 | jobId |

`deploy_site`/`confirm_upload` 两段式源于 presigned-URL 上传模式：客户端上传完产物后显式确认，MCP 才启动执行。

- **认证**：MCP OAuth 对接 Cognito（同一 User Pool），token 里的飞书邮箱即 `owner`。客户端不支持 OAuth 时降级为个人 API Key（Cognito 侧签发，仍映射飞书身份）——**记为二期，PoC 仅支持 OAuth**。
- **前置 Spike**：AgentCore Runtime 对 JWT claims（email）向容器的透传机制需真实环境验证后才能锁定 `_caller_email` 实现（读网关注入头 vs 自行解码 Bearer JWT）。
- **产物通道**：MCP 不直接传文件（不可靠 + AgentCore 容器无文件落地能力），走 S3 presigned URL 由客户端直接 PUT `site.zip`。
- **所有工具秒级返回**，无 60s 超时风险。

### 3.3 异步部署执行器（Step Functions 标准工作流）

选 Step Functions 而非单 Lambda 的理由：每步独立重试、失败停留在明确状态、执行历史即部署日志（演示可视化）。

```
提交 → 校验合同（site.json schema 校验 + 代码红线静态扫描）
  → [tier 分支]
     static:          跳过
     fullstack-nosql: 确保 DynamoDB 表（幂等，命名 site-{siteId}-{table}）
     fullstack-sql:   确保共享 DSQL cluster 内建独立 database → 执行 schema.sql
  → [有 backend] CodeBuild 装依赖打 zip → 创建/更新 Lambda
                 （zip + LWA Layer + Function URL, AuthType=AWS_IAM）
  → 上传 frontend 到 S3（每站点前缀隔离）
  → 写路由表（subdomain、static_target、api_target、auth 策略、owner）
  → 冒烟测试（curl 首页；有 backend 时另测 /api/health，Skill 红线要求后端必须实现该端点）
  → 任务表置 SUCCEEDED + url
任一步失败 → 任务表置 FAILED + phase + 人类可读错误（Skill 转述给用户）
```

关键细节：

- **依赖安装在 CodeBuild**：`npm install` / `pip install` 不在 Lambda 里跑（磁盘/可靠性问题），CodeBuild 是无 Docker 依赖的托管构建点；产物 zip 存 artifacts bucket。
- **DSQL 策略**：共享 cluster、每站点独立 **schema**（DSQL 不支持 `CREATE DATABASE`，每 cluster 仅一个 `postgres` 库；schema 秒级创建，PoC 一个 cluster 足够）。schema.sql 执行时逐条 DDL（DSQL 限制：每事务一条 DDL），语句拆分用 `sqlparse`（不能裸 `split(";")`——会破坏含分号的字符串与注释）。
- **站点运行时隔离（站点代码是不可信代码）**：站点由 AI 生成、owner 可任意改，必须按不可信代码对待。**每站点独立 Lambda 执行角色** `site-rt-{site_id}`：
  - DynamoDB 站点：仅允许访问 `site-data-{site_id}-*` 表；
  - DSQL 站点：执行器以 admin 建 per-site PG role `site_{id}_app`（`GRANT USAGE/ALL ON SCHEMA site_{id}`，无其他 schema 权限），`AWS IAM GRANT` 映射到该站点执行角色，仅授 `dsql:DbConnect`（非 admin）；站点代码模板 `db.js` 用普通 `getDbConnectAuthToken` + 对应 PG role 连接；
  - 执行器角色持 `dsql:DbConnectAdmin` 仅用于建 schema/role/migration——平台身份与站点身份严格分离。
- **幂等与更新**：同一 siteId 重复 `deploy_site` = 更新部署。Step Functions execution name = jobId（同一 job 重复启动被 SFN 拒绝），confirm_upload 前置 jobs 表条件更新 PENDING→RUNNING（重复确认直接报错）。schema 演进约定：首次部署执行 `schema.sql`；后续变更写在 `migrations/NNN_*.sql`，执行器按序号执行未跑过的文件，**每执行完一个文件立即记录**（中途失败不重复执行已完成的）。前端发布走版本化前缀 + 路由原子切换（见 §3.4）。subdomain 不变，站点 URL 稳定。
- **任务表**（DynamoDB `deploy-jobs`）：`jobId, siteId, owner(飞书email), status, phase, error, url, timestamps`。
- **产物防护**：confirm_upload 时 HeadObject 校验 zip 本体 ≤50MB；validate 步骤校验解压后总大小（≤200MB）、文件数（≤2000）、压缩比（≤100:1，防 zip bomb）。（presigned PUT 不支持 content-length-range 条件——那是 presigned POST 的能力，故校验后置。）
- **权限模型**：执行器角色是全系统权限最大者，所有创建的资源强制 `site-*` 命名前缀 + 项目标签，IAM policy 按前缀限定（沿用 manus 项目 `*WebRouterStack*` 最小权限模式）。S3 批量操作一律走 paginator + 每批 ≤1000 对象。

### 3.4 路由 + 鉴权层（manus 复用改造）

路由表（DynamoDB）在 manus 原表基础上扩展：

```
subdomain (PK) | route_mode ("split" | "api-only") | static_prefix (S3 版本化前缀)
| api_target (Lambda Function URL) | require_auth (bool)
| allowed_users ("org" 或 ["a@x.com", ...]) | owner (飞书 email)
```

- `route_mode=split`：站点默认——`/api/*` 走 api_target，其余走 S3 静态前缀。
- `route_mode=api-only`：全路径走 api_target——**auth 子域必须用此模式**（其端点是 `/login` `/callback` `/logout`，不匹配 `/api/*`）。
- `static_prefix` 为版本化前缀 `sites/{site_id}/{job_id}`：新部署先传新前缀，再原子更新路由 item 切流，旧版本由 S3 生命周期清理——更新即时生效且无半发布状态。

Lambda@Edge（origin-request）判定顺序：

```
请求 app-xxx.<域名>/path
  → 查路由表（函数内缓存 60s，减少 Edge→DynamoDB 往返）
  → require_auth?
      否 → 直接路由
      是 → 读 cookie 中的会话 JWT
            无/过期 → 302 到登录端点（带回跳地址，含原 query string）
            有效 → 本地验签 + allowed_users 名单检查
                 → 注入 x-user-email / x-user-name 头 → 路由
  → 路由：route_mode=api-only → 全路径 api_target
          split: /api/* → api_target（SigV4 签名，Function URL 为 AWS_IAM）
                 其余   → S3 static_prefix
  → 任何未捕获异常 → 返回 500（fail-closed，绝不透传原请求到默认 origin）
```

**带 body 请求的签名**：Edge Lambda 关联必须设 `include_body=True`；SigV4 签名用 base64 解码后的真实 body 计算 payload hash（否则 Function URL 校验必败）。Lambda@Edge origin-request body 上限 1MB、超限时 CloudFront 置 `inputTruncated` 标志——Edge 检测到截断即返回 413，"API 请求体 ≤1MB" 写入部署合同红线。

技术要点：

- **Edge 内 JWT 验证**：不引入 JWT 库，用 Python 标准库 `hmac`/`hashlib` 验 HS256（manus 的 Edge 函数为 Python 3.11）；签名密钥在部署时字符串替换注入（manus 已有该机制，Lambda@Edge 不支持环境变量）。纯本地验签、零网络往返，1MB 代码限制内可行。
- **`allowed_users: "org"`**：仅要求"能通过本飞书组织 OAuth 的有效用户"，不查名单；名单模式逐邮箱比对；owner 隐式在名单内。
- 客户端注入的 `x-user-email` / `x-user-name` 头在 Edge 层无条件剥除后再注入，防伪造。

### 3.5 飞书身份层（feishu-quick-sso 复用扩展）

基座：`aws-samples/sample-for-amazon-quick-sso-with-feishu`（Cognito User Pool + 飞书 OIDC 适配器 Lambda，全 Serverless）。其架构本质是**用 Cognito 替代 Keycloak 作为 OIDC 中间层**——Cognito 满足 Quick Desktop 的全部 OIDC 要求（Public Client/PKCE/Discovery），Web/Desktop 共用 Cognito 会话，无需 EC2+ALB 自建 Keycloak。

一套 Cognito 三个消费方：

1. **登录 Quick（Web + Desktop）**——GitHub 路线原生能力；
2. **站点访问者登录**——站点登录端点走同一 Cognito Hosted UI + 飞书适配器；
3. **部署 MCP OAuth**——同一 User Pool 签发。

站点登录流：

1. Edge 发现未登录 → 302 `auth.<域名>/login?redirect=原URL（含 query string）`
2. 登录端点（Lambda）→ Cognito Hosted UI → 飞书 OIDC 适配器 → 飞书扫码/免密授权
3. 回调后登录端点校验并换取 token，生成站点会话 JWT（HS256 自签，含 email/name/exp），种 `.<域名>` 顶域 cookie → 302 回站点
4. 顶域 cookie 使所有 `app-*.<域名>` 站点共享一次登录；且与 Quick 共享 Cognito 会话——登录过 Quick 的浏览器打开站点通常静默通过。

OAuth 回调安全要求：

- `state` 参数 HMAC-SHA256 签名（密钥即 JWT_SECRET）+ 5 分钟过期时间戳，回调时验签验期——防 login CSRF 与 redirect 篡改；
- Cognito `id_token` 必须验签：JWKS（`/.well-known/jwks.json`，Lambda 内存缓存）验 RS256 签名 + 校验 `iss`/`aud`/`exp`/`token_use=id`；
- redirect 白名单校验（仅 `*.<BASE_DOMAIN>`）在 /login 与 /callback 两端都执行。
- PKCE/nonce：confidential client + 签名 state 已覆盖 PoC 威胁模型，记为二期增强。

**与 Blog 路线（SAML + Keycloak）的适配关系**：若客户已按 Blog 路线部署 Quick SSO，本方案的站点鉴权层与"Quick 怎么登录"解耦——独立部署自己的 Cognito + 飞书适配器服务站点与 MCP。飞书账号单一身份仍成立（锚定同一飞书企业应用），只是 Quick 会话与站点会话不共享，站点首次访问多一次飞书授权跳转（浏览器有飞书会话时通常静默）。Keycloak 无需任何改动。

**管理权限落地**：部署凭证全在服务端；MCP OAuth 携带的飞书身份写入任务表 `owner`；`deploy_site`（更新已有站点）与 `undeploy_site` 校验调用者 == owner。站点转移/协作者管理记为二期。

## 4. 数据流（端到端时序）

1. 业务人员在 Quick Desktop（飞书 SSO 登录）中通过 site-builder Skill 用自然语言开发站点，Skill 按部署合同约束产物。
2. 用户确认部署 → Skill 打包 `site.zip` → 调 `deploy_site` → 拿 presigned URL 上传 → MCP 写任务表（owner=飞书邮箱）、启动 Step Functions。
3. 执行器：校验合同 → 建库（DynamoDB 表 / DSQL database+schema）→ CodeBuild 打包 → 建/更新 Lambda（LWA Layer）→ 上传 S3 → 写路由表 → 冒烟测试 → SUCCEEDED。
4. Skill 轮询到成功，向用户报告 `https://app-xxx.<域名>`。
5. 访问者打开 URL → CloudFront → Lambda@Edge 查路由 + 鉴权（未登录跳飞书 OAuth）→ 注入用户头 → 静态走 S3、`/api/*` 走 Lambda → 后端凭 `DATABASE_URL`（IAM token）读写 DSQL。

## 5. 错误处理

| 故障点 | 处理 |
|---|---|
| 产物不符合合同 | 校验步失败，FAILED + 具体违规项（如"前端硬编码了 localhost"），Skill 转述并引导修复重部署 |
| CodeBuild 依赖安装失败 | FAILED + 构建日志摘要 |
| schema.sql 执行失败 | FAILED + SQL 错误行；DSQL 不兼容语法在 Skill 红线中前置规避 |
| 冒烟测试失败 | FAILED（资源保留供排查），提示用户描述症状让 agent 修复后重部署 |
| Step Functions 中途异常 | 每步幂等设计，重跑安全；FAILED 状态含 phase 定位 |
| Edge 鉴权异常（路由表无记录） | 404 页；JWT 异常按未登录处理（302 登录） |
| MCP 调用者非 owner | 拒绝并返回明确错误 |

## 6. 测试策略

- **合同校验单测**：site.json schema、代码红线扫描器（localhost 检测、auth 代码检测）的正反用例。
- **执行器集成测试**：三个 tier 各一个样例站点（fixture），跑真实 Step Functions 到 SUCCEEDED。
- **鉴权与数据端到端（自动化，用 JWT_SECRET 直接 mint 测试会话 cookie，无需人工扫码）**：
  1. 未登录请求返回 302 且 Location 指向 `auth.<域名>/login`（禁跟随重定向断言）；
  2. 带有效 cookie：GET 200 → POST 创建 → read-back 验证 → DELETE；
  3. 名单外用户 403；伪造 `x-user-email` 头被剥除（后端回显的是会话身份）；
  4. 带 body 的 POST 经全链路（CloudFront→Edge SigV4→Function URL）成功；
  5. 两个不同子域相同路径内容不串（缓存禁用验证）；
  6. 更新部署后新内容立即可见；undeploy 后立即 404。
- **更新幂等**：同一 siteId 二次部署内容更新且 URL 不变；同一 jobId 重复 confirm_upload 被拒。
- **演示彩排**：完整成功标准链路（Quick Desktop → 部署 → 飞书登录站点 → CRUD）。

## 7. 成本估算（PoC 量级）

| 项 | 估算/月 |
|---|---|
| 路由层（CloudFront + Lambda@Edge + CF Function + DynamoDB，1M 请求） | ~$2-5 |
| 站点 Lambda + S3（数十站点低流量） | ~$5-20 |
| DSQL 共享 cluster（低用量，按请求计费） | ~$0-10 |
| AgentCore MCP + Step Functions + CodeBuild | ~$5-15 |
| Cognito（月活 <50） | 免费额度内 |
| **合计** | **~$15-50/月** |

## 8. 风险与已知限制

1. **Quick Desktop 为 preview、身份区域须 us-east-1**——本方案全栈锚 us-east-1（Lambda@Edge/ACM 本就强制），一致；但 preview 状态需向客户声明。
2. **DSQL PG 兼容性子集**（无外键约束、无 SERIAL 等）——靠 Skill 红线规避；生成代码若触碰会在 schema 执行阶段显式失败，错误可读。
3. **LWA zip+Layer 路线**已被参考项目实测可行，但 manus README 的容器路线失败记录提示：不要退回 Docker 镜像模式。
4. **顶域 cookie 共享登录**意味着任意 `app-*` 站点共享会话——PoC 可接受（同一组织内部），产品化需评估按站点隔离会话。
5. **Edge 函数 1MB 限制**——JWT 验签用内置 crypto 可控；后续功能膨胀需警惕。
6. **MCP OAuth 依赖客户端支持**——Quick/主流客户端支持；不支持时降级 API Key。
7. **一次性前置准备**：通配符域名 + us-east-1 ACM 证书 + DNS CNAME + 飞书企业应用（redirect URI 配置）。
8. **单 AWS 账号单组织假设**——多租户/多组织隔离超出 PoC 范围。

## 9. 范围外（记为后续阶段）

- 站点协作者/转移、组织管理面板（站点列表 UI）
- 自定义域名绑定、按站点会话隔离
- GitOps 化（版本回滚、部署历史审计）
- ECS Fargate 有状态站点档位
- 计费/配额、多租户隔离
- Python 3.13 站点 runtime（db.py 模板、Python fixture、E2E）
- MCP 个人 API Key 认证（不支持 OAuth 的客户端）
- CloudFront 精细缓存（viewer-request 鉴权 + cache key 按站点/登录态分区）
- OAuth PKCE + nonce 增强

## 10. 实施模块划分（供 writing-plans 参考）

| 模块 | 内容 | 依赖 |
|---|---|---|
| M1 身份层 | 部署 feishu-quick-sso（Cognito + 飞书适配器），验证 Quick Web/Desktop 登录 | 飞书企业应用 |
| M2 路由层 | manus CDK 栈部署 + Edge 鉴权改造 + 路由表扩展 | ACM/DNS、M1（JWT 密钥/登录端点） |
| M3 执行器 | Step Functions + 校验器 + CodeBuild + DSQL/DynamoDB 开通 + 三个 fixture 站点 | 无（可并行先行） |
| M4 部署 MCP | AgentCore Runtime 四工具 + Cognito OAuth | M1、M3 |
| M5 建站 Skill | site-builder Skill（合同 + 红线 + 工作流），三客户端冒烟 | M4 |
| M6 端到端 | 成功标准链路彩排 + 演示脚本 | 全部 |
