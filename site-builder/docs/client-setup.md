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
```

**MCP 必须走 stdio 代理，不能用 HTTP transport 直连**（2026-08-06 实测）。
原因：Claude Code 按 MCP 新版规范在 OAuth 请求里带 RFC 8707 的 `resource`
参数（Resource Indicator），而 **Cognito 不支持它**——授权页能走完、拿到
授权码，但换 token 时返回 `invalid_grant`，客户端日志里是
`Error during auth completion`，状态卡在 `! Needs authentication`。

> 三次对照实验定位（带 scope 无 resource → 成功；无 scope 无 resource → 成功；
> 带 resource → 失败）。**scope 缺失不是原因**，`resource` 才是。这与本平台
> 的配置无关，任何用 Cognito 当 authorization server 的 MCP 部署都会遇到。

代理（`site-builder/clients/quick-desktop-proxy/`，纯 Node 18+ 内置模块，
免 npm install）自己实现 OAuth 且**不发 `resource`**，正好绕过：

```bash
# ① 先授权一次，token 落盘到 ~/.site-builder-deploy-token.json
node site-builder/clients/quick-desktop-proxy/auth.js \
  "{mcp_endpoint_url}" "{mcp_client_id}"

# ② 以 stdio 形态加入（Claude Code 不参与 OAuth，token 由代理注入并刷新）
claude mcp add site-builder-deploy -- \
  node /绝对路径/site-builder/clients/quick-desktop-proxy/index.js \
  "{mcp_endpoint_url}" "{mcp_client_id}"
```

⚠️ **URL 与 client_id 必须是两个独立参数**。实测踩过：在 `--` 之后用引号包
URL 时 shell 可能吞掉参数间的空格，两个值粘成一个，代理因缺 client_id 直接
退出。加完用这条确认存了 **3 个** args：

```bash
python3 -c "import json;d=json.load(open('$HOME/.claude.json'));\
print(d['projects']['$PWD']['mcpServers']['site-builder-deploy']['args'])"
```

**加完必须重启 Claude Code**（stdio server 在启动时加载），然后 `/mcp` 应显示
<!-- tool-count:begin -->9<!-- tool-count:end --> 个工具（清单见下面
「冒烟检查清单」一节）、无需再授权。

代理需要 `http://localhost:18765/callback` 已在 mcp client 的 CallbackURLs 里
（`deploy_pool.py` 默认就注册了；端口选 18765 是因为 8765/8766 被 Quick Desktop
的 quickwork-agent 常驻占用）。**不要用 `aws cognito-idp update-user-pool-client`
手工改这个 client**——该 API 是整体替换语义，漏掉任一字段就会把二期收紧的边界
打回默认（原生认证 flow 被重开、refresh TTL 回到 30 天）。要改就重跑
`deploy_pool.py`。

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
   然后注册为 Local MCP。推荐直接编辑
   `~/.quickwork/profiles/{profile}/mcp_config.json`（重启生效；args 是 JSON
   数组，零歧义）：
   ```json
   "site-builder-deploy": {
     "command": "node",
     "args": ["/绝对路径/quick-desktop-proxy/index.js",
              "{mcp_endpoint_url}", "{mcp_client_id}"],
     "env": {}
   }
   ```
   或走 UI（Settings → Capabilities → MCP → Add）：Connection type=**Local**，
   Command=`node`，Args 一行填 `脚本路径 endpoint client_id`——Args 按类 shell
   规则解析（空格拆分、引号剥除，已向 Quick 源码求证），URL 无空格带不带引号
   均可；UI 亦有 env 区域，可改用 `SITE_BUILDER_MCP_ENDPOINT` /
   `SITE_BUILDER_MCP_CLIENT_ID`（代理 argv 与 env 都认）。
   代理自动注入并续期 Bearer token；坑清单见该目录 README。
3. **身份区域必须 us-east-1**（Quick Desktop preview 限制，与本方案全栈一致）。
4. **与 Quick 的登录方式无关**：Quick 本体用什么登录（飞书/企业 internal/Okta）
   不影响本步骤——MCP 的身份走上面的独立 OAuth。

## Quick Desktop Remote MCP + API Key（二期 M4，**仅在平台启用了该组件时可用**）

上面那条 stdio 代理是**兼容方案**——它存在的唯一原因是 Remote MCP 不支持 OAuth。
平台配了 `[ApiKey]` 段之后，Quick Desktop 可以直接用 Remote MCP：

1. 在 `https://console.{base_domain}/` 的 **API Key** 页面点"创建"，
   **明文只显示这一次**（服务端不留明文，抄漏了只能吊销重发）。
2. Quick Desktop → Settings → Capabilities → MCP → Add，
   Connection type = **Remote**：
   - URL：`https://mcp.{base_domain}/`
   - Headers：`X-API-Key: sk-…`
3. 不需要 `auth.js`、不需要 Node、不需要本机进程常驻。

**它与 OAuth 是两条平行的认证路径，身份语义完全一致**：Key 绑定创建它的人的
邮箱，所以经它部署的站点 owner 就是那个人。交换层不接受客户端自带的
`X-SB-On-Behalf-Of`（那个头只有交换层自己能设），所以持 Key 者无法冒充别人。

**吊销与关闸**：控制台可以单把吊销（**立即**生效，交换层每次现读不缓存）；
管理员还有一个全局总开关，关掉之后**所有** Key 一律 401。开关变更有审计。

**已知取舍**：Key 绑的是邮箱字符串，不联动 IdP 账号状态——用户离职后旧 Key
仍然有效，离职流程里要显式吊销（控制台按 owner 列得出来）。OAuth 那条路径不受
影响（IdP 账号一撤销就登不进来）。

## 冒烟检查清单（每个客户端各跑一遍）

用 MCP Inspector 先验协议层，再验业务层：

```bash
npx @modelcontextprotocol/inspector
# 连 endpoint，带 Bearer token
```

| 检查 | 预期 | 失败含义 |
|---|---|---|
| 列出工具 | <!-- tool-count:begin -->9<!-- tool-count:end --> 个（清单见下） | 容器未起或协议不匹配（应为 stateless streamable-http，0.0.0.0:8000/mcp） |
| 不带 token 调用 | 401 | authorizer 未生效——任何人可部署 |
| `list_my_sites` 的 owner | == 你的飞书邮箱 | email claim 没透传：检查 `requestHeaderAllowlist` 含 `Authorization`，再按上文选 id_token 或 pre-token Lambda |
| 换另一个账号调 `get_deploy_status(别人的 job)` | 报"你不是…所有者" | owner 校验被绕过 |
| 完整部署一次 | 拿到 URL 且浏览器能飞书登录访问 | 见 DEPLOY.md 各阶段排查 |

上表第一行应当列出的工具面（工具面的真源是 `mcp/server.py` 的装饰器，
由 `mcp/tests/test_agentcore_contract.py` 与 `test_doc_tool_surface.py` 两侧锁定）：

<!-- tool-list:begin  本区域由 site-builder/mcp/tests/test_doc_tool_surface.py 对着
     MCP 实时注册表校验；区域内只写工具名，别的标识符写到区域外。 -->

- 部署：`deploy_site` → `confirm_upload` → `get_deploy_status`
- 管理：`list_my_sites` / `get_site_permissions` / `update_site_permissions` /
  `manage_collaborators` / `undeploy_site`
- 统计：`get_site_analytics`（二期 M5）

<!-- tool-list:end -->

## 已知客户端差异（2026-08-06 复核）

**两条通道现在都走同一个 stdio 代理**——原本只有 Quick Desktop 需要它
（Remote MCP 不支持 OAuth），2026-08-06 发现 Claude Code 也必须用
（它发的 `resource` 参数 Cognito 不认，见上面 Claude Code 一节）。

| | Claude Code | Quick Desktop |
|---|---|---|
| MCP 接入 | Local stdio 代理 | Local stdio 代理 |
| 不能直连的原因 | 发 RFC 8707 `resource`，Cognito 返回 `invalid_grant` | Remote MCP 只支持静态 Headers，不支持 OAuth |
| OAuth | 代理的 auth.js（RFC 9728 发现 + PKCE，不发 resource） | 同左 |
| token 管理 | 代理落盘 `~/.site-builder-deploy-token.json` + 自动续期 | 同左 |
| Skill 导入 | `cp -r` 到 `~/.claude/skills/` | profile 的 skills 目录（如 `~/.quickwork/profiles/{profile}/skills/`） |
| 免代理方案 | 无（`resource` 参数问题绕不开） | **Remote MCP + `X-API-Key`**（需平台启用 `[ApiKey]` 组件，见上一节） |

Quick MCP 工具调用 60 秒超时是本方案异步化的原因——所有工具秒级返回，
长任务在 Step Functions 里跑，不受此限（真机部署实测未触发超时）。
