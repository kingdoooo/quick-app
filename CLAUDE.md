# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目是什么

Quick 自动化建站平台（Site Builder）：业务人员在任意支持 Skill+MCP 的 Agent 客户端
（Claude Code / Quick Desktop）用自然语言开发简易全栈站点，一句"部署"得到
`https://app-{site_id}.{base_domain}` 的可分享 URL。站点访问与管理权限绑定飞书账号
（身份源可换成任意能给 email claim 的 Cognito 联邦 IdP）。

**当前状态**：一期已在真实 AWS 全量部署并端到端验证（两条客户端通道都走通）。
二期需求清单在 `docs/phase2-requirements.md`。部署手册 `site-builder/DEPLOY.md`
含全部实测坑；一期实现的任务级审查记录在 `.superpowers/sdd/progress.md`。

## 测试命令（有坑，别猜）

每个包的 venv 归属不同，照抄下面的组合（三个例外都验证过）：

```bash
cd site-builder/contract && .venv/bin/pytest tests -q        # 67 tests
cd site-builder/auth     && ../contract/.venv/bin/pytest tests -q   # 11 tests；auth 无自己的 venv，借 contract 的（含 pyjwt）
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q  # 23 tests；router 的 .venv 只有 CDK 依赖没有 pytest，借 deployer 的（含 boto3）
cd site-builder/deployer && .venv/bin/pytest tests -q        # 必须指定 tests/——裸 pytest 会误收集 infra/cdk.out 里的 asset 副本
cd site-builder/mcp      && python3 -m pytest tests -q       # 23 tests
```

单测跑法：`.venv/bin/pytest tests/test_xxx.py::test_name -q`。

venv 的 shebang 是绝对路径：仓库被移动/克隆到新路径后必须
`python3 -m venv --clear .venv` 重建（不带 `--clear` 不会重写 shebang，一直报
bad interpreter）。

E2E（需要真实 AWS 部署 + config.ini 已回填）：

```bash
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q   # 4 个 fixture，约 6 分钟
bash site-builder/scripts/smoke_router.sh    # 路由层冒烟（会写测试数据，跑完清理）
```

## 部署/重部署命令

```bash
# 路由层（改过 config.ini 必须先 rm -rf cdk.out，否则用陈旧 asset）
cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never

# 执行器（bundling 需要 Docker）
cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never

# auth 服务（Lambda + Function URL + pre-token 触发器，幂等）
cd site-builder/auth && python3 deploy_auth.py

# MCP（buildx ARM64 → ECR → AgentCore runtime；--skip-build 只改配置）
cd site-builder/mcp && python3 deploy_agentcore.py

# 生成含真实值的用户接入指引（产物 gitignored）
python3 site-builder/scripts/gen_onboarding.py
```

配置全在 `site-builder/config.ini` 与 `router/config.ini`（gitignored，从同目录
`.example` 复制）。**config.ini 是各部署脚本与 CDK 栈的唯一取值来源**，代码不硬编码
账号/域名。git 历史已清洗过真实账号 ID——不要把真实账号值写进任何被跟踪的文件。

## 架构（五层，读代码前先建这张图）

```
① 建站 Skill (site-builder/skills/)  ← Agent 客户端加载的"部署合同"说明书
        ↓ MCP 调用（OAuth 带飞书身份）
② 部署 MCP (site-builder/mcp/)       ← AgentCore Runtime，5 工具全部秒级返回
        ↓ 条件迁移 PENDING→RUNNING + 启动 SFN
③ 异步执行器 (site-builder/deployer/) ← Step Functions 10 步：validate → provision-db
        ↓ 写路由表                       → CodeBuild 打包 → 站点 Lambda → 前端 S3 → 路由 → 冒烟
④ 路由+鉴权层 (router/)              ← CloudFront *.{domain} + Lambda@Edge
        ↓ 未登录 302                     查路由表 → 验会话 JWT → 注入 x-user-email → 分流
⑤ 身份层 (site-builder/auth/)        ← Cognito(联邦到飞书) + 登录服务 + pre-token 触发器
```

理解整个系统的关键抽象：

- **部署合同是锚点**：`site.json` schema + 目录约定 + 代码红线
  （`site-builder/contract/`）。哪个 Agent 生成的代码都行，执行器只认合同；
  validate 步骤把不合规产物在部署前拦下。改合同要同步三处：
  `contract/src/contract/`（校验器）、`skills/site-builder/references/`
  （给 Agent 的文档）、`fixtures/`（黄金样例，模板与 fixture 字节一致）。
- **站点代码按不可信对待**：per-site IAM 角色带 PermissionsBoundary
  （`site-runtime-boundary`）、DSQL per-site schema + 非 admin PG role、
  DynamoDB 表按 `site-data-{site_id}-` 前缀隔离、CodeBuild 装依赖
  `--ignore-scripts`。任何给执行器/站点加权限的改动都要维持这个模型。
- **鉴权全部在边缘**：站点代码零 auth 逻辑。Edge 验 HS256 会话 cookie
  （与 `auth/session.py` 同算法，**两处必须字节级同步**，见
  `router/infrastructure/lambda/origin_request.py` 注释）、按 allowed_users
  放行、注入 `x-user-email` / `x-user-name`（后者 URL 编码，站点须
  decodeURIComponent）。**CloudFront 全站禁缓存是鉴权正确性前提**
  （origin-request 只在 cache miss 执行）——别加缓存策略。
- **身份即邮箱**：owner / allowed_users / 会话 claim 全以 email 为键，对 IdP
  无感。Cognito access token 默认不含 email，靠 pre-token V2 触发器
  （`auth/pre_token_email.py`）注入——MCP 网关只收 access token
  （id_token 会 401，不要把 authorizer 改成 allowedAudience）。
- **Lambda@Edge 不支持环境变量**：Edge 函数的配置（表名、JWT 密钥）由 CDK
  部署时字符串替换注入（`{{PLACEHOLDER}}` 形态）。看到
  `SYNTH-ONLY-PLACEHOLDER` 警告说明 SSM 读取失败，此时部署出去所有会话验签失败。

## 高频坑（都是真机踩过的）

- Function URL 一律 `AuthType=AWS_IAM` + 只授权 edge role，且 2025-10 起需要
  `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl) 两条语句，缺一即 403。
  `AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（删光 resource policy）。
- AgentCore 镜像构建必须 `--provenance=false`（buildx 默认加 attestation
  manifest，CreateAgentRuntime 校验失败但报成 IAM 权限错误文案）。
- S3 预签名 PUT 不能带 Content-Type 头（签名按无该头计算，加了必 403）。
- MCP 客户端 OAuth：Cognito 无 dynamic client registration，必须
  `--client-id` + `--callback-port 18765`（8765/8766 被 Quick Desktop 常驻占用）。
  Quick Desktop Remote MCP 不支持 OAuth，走 `site-builder/clients/quick-desktop-proxy/`。
- deployer 的 CDK bundling 钉死 `platform: linux/amd64`——Apple Silicon 上去掉会装出
  aarch64 psycopg，Lambda 运行时 import 失败。
- DSQL：API 不返回 endpoint（自拼 `{id}.dsql.{region}.on.aws`）；清理顺序必须先
  `AWS IAM REVOKE` 再 `DROP ROLE`（否则 2BP01）。
- git push 用 `--no-verify`（用户全局约定）；us-east-1 是硬约束
  （Lambda@Edge/ACM/Quick 身份区域），换区要改代码。

## 文档地图

| 要做什么 | 看哪里 |
|---|---|
| 部署到新账号 / 排查部署问题 | `site-builder/DEPLOY.md`（七阶段 + 全部实测坑） |
| 客户端接入（人/Agent） | `site-builder/docs/client-setup.md`；含真实值版本跑 `gen_onboarding.py` |
| 合同细节（给站点生成方） | `site-builder/skills/site-builder/references/{contract,redlines}.md` |
| 一期设计决策与范围 | `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`（已实现快照，勿改） |
| 二期需求 | `docs/phase2-requirements.md` |
| 任务级实现/审查历史 | `.superpowers/sdd/progress.md` |
