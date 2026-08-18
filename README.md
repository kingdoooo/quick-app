# Quick 自动化建站方案（Site Builder）

业务人员在**任意支持 Skill + MCP 的 Agent 客户端**（Claude Code / Codex /
Amazon Quick / Kiro …）里用自然语言开发简易全栈站点，说一句"部署"即获得
`https://app-xxx.<你的域名>` 的可分享 URL；站点访问与管理权限绑定**飞书账号**
（或任意能提供 email claim 的企业 OIDC/SAML IdP 身份）。
全程不接触 AWS 控制台，无 EC2/RDS 重资产。

> **与 Agent 客户端的账号体系无关**：Claude Code / Codex / Quick 各自怎么登录是
> 客户端自己的事，本方案不做任何假设。客户端只需要两件事——能加载 Skill、能连
> MCP；对**本方案**的认证（部署权限、站点访问、控制台）全部走方案自带的
> Cognito，联邦到你在部署时接入的飞书或标准 IdP。

> **当前状态**：已在真实 AWS 账号完整部署并端到端验证——自助管理控制台、
> API Key 交换层、访问统计聚合、以及站点更新的 blue/green 原子切换都已上线并通过
> 真机闸门（含真实用户经 Claude Code OAuth 接入部署、飞书登录 + 鉴权四态实测）。
>
> **本段不写测试数量与日期**：那种数字每一轮都会变假，而这里是外部读者看到的第一段话。
> 想知道当下的确切状态就**自己跑一遍**——各包的测试命令与真机闸门脚本都列在
> [CLAUDE.md](CLAUDE.md) 的「测试命令」小节里，跑出来的数字就是答案。
>
> 部署中踩到的所有坑（ECR manifest、Function URL 权限、飞书回调/邮箱、token 形态、
> 预签名上传、部署顺序等）均已回写
> **[site-builder/DEPLOY.md](site-builder/DEPLOY.md)** 与
> [docs/client-setup.md](site-builder/docs/client-setup.md)，换账号重部署照手册执行即可。
> 更细的逐任务进度与实测发现记在仓库内的 `docs/design/`，那些文件**不随仓库分发**
> （含真实账号与资源值，git-ignored）——所以本文件与 DEPLOY.md 才是对外的口径真源。

## 架构

<!-- tool-list:begin  ② 那格的工具面由 site-builder/mcp/tests/test_doc_tool_surface.py
     对着 MCP 实时注册表校验（漏一个、或留着已删除的都会变红）。本图里除工具名外
     不要出现别的 snake_case 标识符，否则会被当成"多出来的工具"。 -->

```
┌─────────────────────────────────────────────────────────────┐
│ ① 建站 Skill（Agent Skills 开放标准，"部署合同"）             │  site-builder/skills/
│    Claude Code / Codex / Amazon Quick / Kiro 等通用           │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP 调用（OAuth 携带平台身份）
┌──────────────────────────▼──────────────────────────────────┐
│ ② 部署 MCP（AgentCore Runtime，薄壳，工具全部秒级返回）       │  site-builder/mcp/
│    deploy_site / confirm_upload / get_deploy_status /         │
│    list_my_sites / undeploy_site / get_site_analytics /       │
│    update_site_permissions / manage_collaborators /           │
│    get_site_permissions                                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ 条件迁移 PENDING→RUNNING + SFN 启动
┌──────────────────────────▼──────────────────────────────────┐
│ ③ 异步部署执行器（Step Functions + Lambda + CodeBuild）       │  site-builder/deployer/
│    合同校验(zip bomb防护) → 建库(DynamoDB表/DSQL schema+role)  │
│    → CodeBuild 装依赖 → 站点 Lambda(zip+LWA Layer)            │
│    → 前端传 S3 版本化前缀 → 路由原子切流 → 冒烟                │
└──────────────────────────┬──────────────────────────────────┘
                           │ 路由表（subdomain → 目标 + auth 策略）
┌──────────────────────────▼──────────────────────────────────┐
│ ④ 路由 + 鉴权层（CloudFront *.<域名> + Lambda@Edge）           │  router/
│    查路由 → 验会话 JWT → 注入 x-user-email →                  │
│    /api/*→站点Lambda(SigV4) / 其余→S3（全站禁缓存）           │
└──────────────────────────┬──────────────────────────────────┘
                           │ 未登录 302 → auth.<域名>/login
┌──────────────────────────▼──────────────────────────────────┐
│ ⑤ 身份层（Cognito 联邦到飞书适配器或任意 OIDC/SAML IdP）      │  site-builder/auth/
│    一套 Cognito 三处消费：站点访问 / 控制台 / MCP 部署权限     │
└─────────────────────────────────────────────────────────────┘
```

<!-- tool-list:end -->

### 关键设计决策

- **不做代码生成**——那是 Agent 客户端的事；本方案只做客户端做不了的"部署到 AWS"。
- **部署合同**（`site.json` + 目录约定 + 代码红线）是锚点：哪个 agent 生成的代码都行，
  执行器只认合同。校验器 + 红线扫描器把不合规产物在部署前拦下。
- **站点代码按不可信代码对待**：每站点独立 IAM 角色（PermissionsBoundary 封顶）、
  DSQL per-site schema + 非 admin PG role、DynamoDB 表按站点前缀隔离。
- **鉴权统一在边缘**：站点代码零 auth 逻辑，Lambda@Edge 验 HS256 会话 cookie、
  按名单放行、注入 `x-user-email`；CloudFront **全站禁缓存**（origin-request 鉴权
  在 cache hit 时会被绕过——禁缓存是正确性前提）。
- **三档 tier**：`static`（纯前端）/ `fullstack-nosql`（Express+DynamoDB）/
  `fullstack-sql`（Express+Aurora DSQL）。选 DSQL 因为：免 VPC、闲置零成本、
  IAM 认证免密码、PG 线协议兼容 AI 生成代码。
- **后端 zip + Lambda Web Adapter Layer**（禁容器镜像——参考项目实测镜像模式踩坑）。

## 目录导览

| 路径 | 内容 |
|---|---|
| `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md` | **一期**设计文档（已实现快照，勿改）——二期的控制台/API Key/统计/blue-green 都不在其中 |
| `docs/superpowers/plans/2026-07-21-quick-site-builder.md` | **一期**实施计划（23 任务；同为快照）。当前架构口径见本文件与 `CLAUDE.md` |
| `site-builder/DEPLOY.md` | **部署手册：§0 前置要求 + 七阶段操作（下一步从这里开始）** |
| `site-builder/contract/` | 部署合同库：site.json 校验器 + 红线扫描器 |
| `site-builder/auth/` | 会话 JWT + 站点登录服务 |
| `site-builder/deployer/` | 执行器：7 个 SFN 步骤 + 状态机 CDK + undeploy |
| `site-builder/mcp/` | 部署 MCP server + Dockerfile/部署脚本 + AgentCore spike 报告 |
| `site-builder/skills/site-builder/` | 建站 Skill 包（SKILL.md + 合同/红线文档 + 模板） |
| `site-builder/fixtures/` | 三档黄金样例站点（全部通过合同校验，兼演示素材） |
| `site-builder/scripts/` | smoke_router.sh（路由层冒烟）、deploy_fixture.py |
| `router/` | 路由层：CloudFront + Lambda@Edge 分流/鉴权/禁缓存 |

## 测试与质量

- **七个包各有单元测试**（contract / auth / router edge / deployer / mcp / panel /
  key-proxy），另有一组 E2E 在 `RUN_E2E=1` + 真实部署后运行，含自动化登录 CRUD
  ——用平台 JWT_SECRET 直接 mint 测试会话 cookie，无需人工飞书扫码。
  **这里不写各包的测试数量**：那些数字每加一个用例就变假。要当下的确切数字，
  照 [CLAUDE.md](CLAUDE.md) 的「测试命令」小节跑一遍，输出就是答案。
- 每个任务经独立子代理实现 + 审查/裁决 + 修复闭环；开发过程中修复的典型问题：
  CloudFront 缓存绕过鉴权（CRITICAL）、auth 子域路由错位、POST body SigV4 签名、
  DSQL 权限模型、红线扫描器多轮防绕过加固、IAM PermissionsBoundary 条件门 bug。
- 跑测试：多数包用各自目录下 `.venv/bin/pytest -q`；两个例外——
  `site-builder/auth` 无自己的 venv，用 `site-builder/contract/.venv/bin/pytest tests`（含 pyjwt）；
  `site-builder/deployer` 须 `pytest tests`（裸 `pytest -q` 会误收集 `infra/cdk.out` 的 asset 副本）。
- venv 里的 shebang 是绝对路径：若克隆到别的路径或移动过目录，用
  `python3 -m venv --clear .venv` 重建（不带 `--clear` 时对已存在目录不会重写
  shebang，会一直报 bad interpreter）。

## 部署前置要求

本方案面向**在你自己的 AWS 账号里从零部署**。需要先准备：**us-east-1 区域**
（Lambda@Edge 与 CloudFront 用的 ACM 证书强制）、一个可改 DNS 的域名 + 该域名的
`*.<域名>` ACM 通配符证书、一个身份源——飞书企业自建应用（需用户邮箱权限）**或**
任意能提供 email claim 的标准 OIDC/SAML IdP——以及 SSM 里的会话签名密钥、本机
Docker。

逐项要求与命令见 **[site-builder/DEPLOY.md](site-builder/DEPLOY.md) §0 前置要求**
（含就绪检查清单与成本预期）。

账号 ID、域名、证书 ARN 等环境相关值全部走配置文件
（`site-builder/config.ini` 与 `router/config.ini`，均从同目录 `.example`
复制，gitignored），代码与文档中不硬编码。

## 如何继续

1. **备齐前置**：照 [site-builder/DEPLOY.md](site-builder/DEPLOY.md) §0 的就绪清单
   逐项确认，并从两份 `config.ini.example` 复制出自己的配置。
2. **部署**：照同文档七个阶段执行
   （①身份层 → ②路由 → ③DSQL → ④执行器 → ⑤MCP → ⑥客户端 → ⑦彩排）；
   每阶段产出的 ARN/ID 按手册回填 `site-builder/config.ini`。
3. **演示**：⑦ 的 E2E 通过后，演示叙事见实施计划 Task 23。
4. **仍未交付的候选**：Python 站点 runtime（当前仅 Node.js 后端）、精细缓存
   （当前 CloudFront 全站禁缓存，那是鉴权正确性的前提）。
   原清单里的 MCP API-Key、站点协作者、管理面板、PKCE/nonce **都已在二期交付**
   （分别是 `site-builder/key-proxy/`、panel 的协作者接口、`console.<域名>`
   控制台、`auth/login_handler.py` 的 PKCE S256 + nonce 校验）。
