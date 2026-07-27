# Quick 自动化建站方案（Site Builder）

业务人员在 **Amazon Quick Desktop**（或 Claude Code / Kiro 等任意支持 Skill + MCP 的
Agent 客户端）里用自然语言开发简易全栈站点，说一句"部署"即获得
`https://app-xxx.<你的域名>` 的可分享 URL；站点访问与管理权限绑定**飞书账号**。
全程不接触 AWS 控制台，无 EC2/RDS 重资产。

> **当前状态**：代码已完成并通过两轮独立审查（154 个单元测试全绿，2 个 CDK 栈 synth 通过），
> 尚未部署到真实 AWS。部署操作手册见 **[site-builder/DEPLOY.md](site-builder/DEPLOY.md)**。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│ ① 建站 Skill（Agent Skills 开放标准，"部署合同"）             │  site-builder/skills/
│    Quick Desktop / Claude Code / Kiro 通用                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP 调用（OAuth 携带飞书身份）
┌──────────────────────────▼──────────────────────────────────┐
│ ② 部署 MCP（AgentCore Runtime，薄壳，5 工具秒级返回）         │  site-builder/mcp/
│    deploy_site / confirm_upload / get_deploy_status /         │
│    list_my_sites / undeploy_site                              │
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
│    查路由 → 验飞书会话 JWT → 注入 x-user-email →              │
│    /api/*→站点Lambda(SigV4) / 其余→S3（全站禁缓存）           │
└──────────────────────────┬──────────────────────────────────┘
                           │ 未登录 302 → auth.<域名>/login
┌──────────────────────────▼──────────────────────────────────┐
│ ⑤ 飞书身份层（Cognito + 飞书 OIDC 适配器，复用官方样例）       │  site-builder/auth/
│    一套 Cognito 三处消费：Quick SSO / 站点访问 / MCP 部署权限   │
└─────────────────────────────────────────────────────────────┘
```

### 关键设计决策

- **不做代码生成**——那是 Quick 的价值；本方案只做 Quick 做不了的"部署到 AWS"。
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
| `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md` | 设计文档（经对抗性 review 修订） |
| `docs/superpowers/plans/2026-07-21-quick-site-builder.md` | 实施计划（23 任务，含完整代码） |
| `site-builder/DEPLOY.md` | **部署手册：§0 前置要求 + 七阶段操作（下一步从这里开始）** |
| `site-builder/contract/` | 部署合同库：site.json 校验器 + 红线扫描器（67 测试） |
| `site-builder/auth/` | 会话 JWT + 站点登录服务（11 测试） |
| `site-builder/deployer/` | 执行器：7 个 SFN 步骤 + 状态机 CDK + undeploy（30 测试） |
| `site-builder/mcp/` | 部署 MCP server（23 测试）+ Dockerfile/部署脚本 + AgentCore spike 报告 |
| `site-builder/skills/site-builder/` | 建站 Skill 包（SKILL.md + 合同/红线文档 + 模板） |
| `site-builder/fixtures/` | 三档黄金样例站点（全部通过合同校验，兼演示素材） |
| `site-builder/scripts/` | smoke_router.sh（路由层冒烟）、deploy_fixture.py |
| `router/` | 路由层：CloudFront + Lambda@Edge 分流/鉴权/禁缓存（23 测试） |

## 测试与质量

- **154 个单元测试**：contract 67 / auth 11 / router edge 23 / deployer 30 / mcp 23
  （另 4 个 E2E 在 `RUN_E2E=1` + 真实部署后运行，含自动化登录 CRUD——用平台
  JWT_SECRET 直接 mint 测试会话 cookie，无需人工飞书扫码）。
- 每个任务经独立子代理实现 + 审查/裁决 + 修复闭环；开发过程中修复的典型问题：
  CloudFront 缓存绕过鉴权（CRITICAL）、auth 子域路由错位、POST body SigV4 签名、
  DSQL 权限模型、红线扫描器多轮防绕过加固、IAM PermissionsBoundary 条件门 bug。
- 跑测试：多数包用各自目录下 `.venv/bin/pytest -q`；两个例外——
  `site-builder/auth` 无自己的 venv，用 `site-builder/contract/.venv/bin/pytest tests`（含 pyjwt）；
  `site-builder/deployer` 须 `pytest tests`（裸 `pytest -q` 会误收集 `infra/cdk.out` 的 asset 副本）。

## 部署前置要求

部署到你自己的 AWS 账号需要先准备：**us-east-1 区域**（Lambda@Edge/ACM/Quick
身份区域共同强制）、一个可改 DNS 的域名 + 该域名的 `*.<域名>` ACM 通配符证书、
飞书企业自建应用（需用户邮箱权限）、SSM 里的会话签名密钥、本机 Docker。

逐项要求与命令见 **[site-builder/DEPLOY.md](site-builder/DEPLOY.md) §0 前置要求**
（含就绪检查清单与成本预期）。

账号 ID、域名、证书 ARN 等环境相关值全部走配置文件
（`site-builder/config.ini` 与 `router/config.ini`，均从同目录 `.example`
复制，gitignored），代码与文档中不硬编码。

## 如何继续

1. **备齐前置**：照 [site-builder/DEPLOY.md](site-builder/DEPLOY.md) §0 的就绪清单
   逐项确认，并从两份 `config.ini.example` 复制出自己的配置。
2. **部署**：照同文档七个阶段执行
   （①SSO → ②路由 → ③DSQL → ④执行器 → ⑤MCP → ⑥客户端 → ⑦彩排）；
   每阶段产出的 ARN/ID 按手册回填 `site-builder/config.ini`。
3. **演示**：⑦ 的 E2E 通过后，演示叙事见实施计划 Task 23。
4. **二期候选**（设计文档 §9）：Python 站点 runtime、MCP API-Key、精细缓存、
   PKCE/nonce、站点协作者、管理面板。
