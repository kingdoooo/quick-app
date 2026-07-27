# 客户端接入（Skill + 部署 MCP）

把 `site-builder` Skill 与部署 MCP 接到各 Agent 客户端。Skill 是同一份
（Agent Skills 开放标准），不做每客户端派生；差异只在 MCP 的挂载方式。

**前置**：DEPLOY.md ①–⑤ 全部完成，`config.ini [MCP] endpoint_url` 已回填。

MCP endpoint 形如：

```
https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/<url-encoded-runtime-arn>/invocations?qualifier=DEFAULT
```

## 通用前提：拿一个 Cognito token

所有客户端都用 OAuth 携带飞书身份。runtime 配的是 `customJWTAuthorizer`
（`allowedClients=[mcp_client_id]`），调用必须带 `Authorization: Bearer <token>`。

**token 里必须有 `email` claim**——`owner`（谁部署的、谁能改）就取自它。
Cognito access token 默认不含 email；若冒烟发现 owner 取不到，两个选择：

1. 让 AgentCore 收到 id_token：authorizer 改用 `allowedAudience=[mcp_client_id]`
   （id_token 用 `aud` 而非 `client_id`），改 `deploy_agentcore.py` 里那一段；
2. 保留 access token，加 Cognito pre-token-generation Lambda 把 email 注入 claim。

判定方法见下面每个客户端的冒烟步骤。

## Claude Code（自动化程度最高，先在这里验证）

```bash
mkdir -p ~/.claude/skills
cp -r site-builder/skills/site-builder ~/.claude/skills/

# MCP（HTTP transport，OAuth 走浏览器授权）
claude mcp add --transport http site-builder-deploy "<MCP_ENDPOINT_URL>"
```

新会话里提示：

> 用 site-builder 技能给我做一个团队读书清单站点，能加书、标记读完，全组织可看，做完部署

预期：Skill 走完澄清 → 生成代码 → 本地预览 → `deploy_site` → PUT zip →
`confirm_upload` → 轮询 `get_deploy_status` 播报 phase → 返回
`https://app-xxx.<BASE_DOMAIN>`。浏览器打开该 URL 应跳飞书登录，登录后可加书。

## Quick Desktop（核心演示通道，人工配置）

1. **导入 Skill**：把 `site-builder/skills/site-builder/` 整个目录按 Quick Desktop
   当期的 Skill 导入入口加载（SKILL.md + references/ + templates/ 一并带上，
   references 与 templates 是合同的一部分，缺了会生成不合规产物）。
2. **添加 MCP**：Capabilities → MCP → 添加 endpoint，认证选 OAuth，
   走飞书登录授权。
3. **身份区域必须 us-east-1**（Quick Desktop preview 限制，与本方案全栈一致）。

## 冒烟检查清单（每个客户端各跑一遍）

用 MCP Inspector 先验协议层，再验业务层：

```bash
npx @modelcontextprotocol/inspector
# 连 endpoint，带 Bearer token
```

| 检查 | 预期 | 失败含义 |
|---|---|---|
| 列出工具 | 5 个：deploy_site / confirm_upload / get_deploy_status / list_my_sites / undeploy_site | 容器未起或协议不匹配（应为 stateless streamable-http，0.0.0.0:8000/mcp） |
| 不带 token 调用 | 401 | authorizer 未生效——任何人可部署 |
| `list_my_sites` 的 owner | == 你的飞书邮箱 | email claim 没透传：检查 `requestHeaderAllowlist` 含 `Authorization`，再按上文选 id_token 或 pre-token Lambda |
| 换另一个账号调 `get_deploy_status(别人的 job)` | 报"你不是…所有者" | owner 校验被绕过 |
| 完整部署一次 | 拿到 URL 且浏览器能飞书登录访问 | 见 DEPLOY.md 各阶段排查 |

## 已知客户端差异

（真机验证后补：Skill 导入路径、OAuth 授权弹窗行为、工具超时表现。
Quick MCP 工具调用 60 秒超时是本方案异步化的原因——所有工具秒级返回，
长任务在 Step Functions 里跑，不受此限。）
