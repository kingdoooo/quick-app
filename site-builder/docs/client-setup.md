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
这一点已真机钉死（2026-07-29）：网关只接受 **access token**（id_token 会被
401 拒，"Claim 'client_id' value mismatch"），而 Cognito access token 默认
不含 email，所以平台已部署 **pre-token-generation V2 Lambda**
（`auth/pre_token_email.py` → 函数 `site-auth-pre-token`，挂在用户池上）把
email 注入 access token。客户端无需任何额外配置；若 owner 取不到，先确认该
触发器还挂在用户池 `LambdaConfig.PreTokenGenerationConfig`（V2_0）上。
**不要**把 authorizer 改成 `allowedAudience`——那会反过来拒掉 access token。

## Claude Code（自动化程度最高，先在这里验证）

```bash
mkdir -p ~/.claude/skills
cp -r site-builder/skills/site-builder ~/.claude/skills/

# MCP（HTTP transport，OAuth 走浏览器授权）。
# 必须带 --client-id 与固定回调端口：Cognito 不支持 RFC 7591 dynamic client
# registration，裸 add 会报 "Incompatible auth server: does not support
# dynamic client registration"（2026-07-29 实测）。
# 端口用 18765：8765/8766 被 Quick Desktop 的 quickwork-agent 常驻占用
# （演示机上必装 Quick Desktop，冲突必现）。
claude mcp add --transport http site-builder-deploy "{mcp_endpoint_url}" \
  --client-id {mcp_client_id} --callback-port 18765
```

还要在 deploy-mcp app client 的 CallbackURLs 里**预注册**
`http://localhost:18765/callback`（与 AgentCore 的 identities 回调并存）：

```bash
aws cognito-idp update-user-pool-client --region us-east-1 \
  --user-pool-id {user_pool_id} --client-id {mcp_client_id} \
  --client-name deploy-mcp --refresh-token-validity 30 \
  --supported-identity-providers Feishu \
  --callback-urls "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback" \
                  "http://localhost:18765/callback" \
  --allowed-o-auth-flows code --allowed-o-auth-scopes openid email \
  --allowed-o-auth-flows-user-pool-client --enable-token-revocation \
  --auth-session-validity 3 \
  --explicit-auth-flows ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH
```

配好后 `claude mcp list` 显示 `! Needs authentication`，在 Claude Code 会话里
`/mcp` → 选 site-builder-deploy → Authenticate，浏览器走飞书登录完成授权。

新会话里提示：

> 用 site-builder 技能给我做一个团队读书清单站点，能加书、标记读完，全组织可看，做完部署

预期：Skill 走完澄清 → 生成代码 → 本地预览 → `deploy_site` → PUT zip →
`confirm_upload` → 轮询 `get_deploy_status` 播报 phase → 返回
`https://app-xxx.{base_domain}`。浏览器打开该 URL 应跳飞书登录，登录后可加书。

## Quick Desktop（核心演示通道，人工配置；2026-07-29 已真机走通）

1. **导入 Skill**：把 `site-builder/skills/site-builder/` 整个目录按 Quick Desktop
   当期的 Skill 导入入口加载（SKILL.md + references/ + templates/ 一并带上，
   references 与 templates 是合同的一部分，缺了会生成不合规产物）。
2. **添加 MCP——必须走本地 stdio 代理**。Quick Desktop 的 Remote MCP 只支持
   静态 Headers，**不支持 OAuth 授权码流程**（实测直接填 endpoint 报 401）。
   用 `site-builder/clients/quick-desktop-proxy/`（纯 Node 内置模块，免 install）：
   ```bash
   cd site-builder/clients/quick-desktop-proxy
   node auth.js "{mcp_endpoint_url}" "{mcp_client_id}"   # 浏览器飞书登录，token 落盘
   ```
   然后 Settings → Capabilities → MCP → Add：Connection type=**Local**，
   Command=`node`，Args=`/绝对路径/quick-desktop-proxy/index.js {mcp_endpoint_url} {mcp_client_id}`
   （UI 字段里**不要加引号**，不是 shell；URL 无空格无需引号。若 Args 不接受
   多参数，Args 只填脚本路径 + Env 设 `SITE_BUILDER_MCP_ENDPOINT` /
   `SITE_BUILDER_MCP_CLIENT_ID`，代理两种都认）。
   代理自动注入并续期 Bearer token；坑清单见该目录 README。
3. **身份区域必须 us-east-1**（Quick Desktop preview 限制，与本方案全栈一致）。
4. **与 Quick 的登录方式无关**：Quick 本体用什么登录（飞书/企业 internal/Okta）
   不影响本步骤——MCP 的身份走上面的独立 OAuth。

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

## 已知客户端差异（2026-07-29 两通道均真机验证）

| | Claude Code | Quick Desktop |
|---|---|---|
| MCP 接入 | 原生 HTTP transport | Local stdio 代理（Remote MCP 不支持 OAuth） |
| OAuth | 内置（`--client-id` + `--callback-port`） | 代理的 auth.js（RFC 9728 发现 + PKCE） |
| token 管理 | 客户端自动 | 代理落盘 `~/.site-builder-deploy-token.json` + 自动续期 |
| Skill 导入 | `cp -r` 到 `~/.claude/skills/` | profile 的 skills 目录（如 `~/.quickwork/profiles/{profile}/skills/`） |

Quick MCP 工具调用 60 秒超时是本方案异步化的原因——所有工具秒级返回，
长任务在 Step Functions 里跑，不受此限（真机部署实测未触发超时）。
