# 部署 MCP 的本地 stdio 代理（OAuth 登录与续期）

这个代理替 Agent 客户端完成对部署 MCP 的 OAuth 登录，并自动续期 token。
两类客户端默认都靠它接入：

- **Claude Code**：它在 OAuth 请求里带 RFC 8707 的 `resource` 参数，在本平台的 Cognito
  配置下换 token 会报 `invalid_grant`（单账号实测，证据等级与排查口径见
  `site-builder/docs/client-setup.md`）。代理自己实现 OAuth、不发这个参数。
- **Amazon Quick Desktop**：它的 Remote MCP 只支持静态 Headers，不支持 OAuth 授权码流程
  （实测直接填 AgentCore endpoint 报 401）。平台启用了可选的 API Key 组件时，
  Quick Desktop 也可以改走 Remote MCP + `X-API-Key`，见 `site-builder/docs/client-setup.md`。

```
┌───────────────┐  stdio   ┌──────────────┐  HTTPS + Bearer  ┌───────────────────┐
│  Agent 客户端  │ ◀──────▶ │  index.js    │ ───────────────▶ │ Bedrock AgentCore │
└───────────────┘          └──────────────┘                  └───────────────────┘
                                  │
                          ~/.site-builder-deploy-token.json
```

仅用 Node 18+ 内置模块，**无需 npm install**。

## 使用

```bash
# 1) 首次 OAuth（浏览器走 IdP 登录，token 落盘，之后代理自动续期）
node auth.js "<endpoint_url>" "<client_id>"

# 2) 注册为 Local MCP（以 Quick Desktop 为例；Claude Code 的注册命令见 client-setup.md）。推荐直接编辑
#    ~/.quickwork/profiles/{profile}/mcp_config.json（重启生效）：
#      "site-builder-deploy": {
#        "command": "node",
#        "args": ["/绝对路径/index.js", "<endpoint_url>", "<client_id>"]
#      }
#    或 UI：Settings → Capabilities → MCP → Add，Connection type=Local，
#    Command=node，Args 一行填 `路径 endpoint client_id`。
#    Args 按类 shell 规则解析（空格拆分、引号剥除，源码求证过 parseShellArgs）；
#    URL 无空格，带不带引号均可。也可用 env：
#    SITE_BUILDER_MCP_ENDPOINT / SITE_BUILDER_MCP_CLIENT_ID（代理两种都认）。
```

`<endpoint_url>` / `<client_id>` 的真实值见部署者生成的 ONBOARDING.md
（`config.ini` 的 `[MCP] endpoint_url` 与 `[Cognito] mcp_client_id`）。

## 实测坑（改代码前先读）

- AgentCore 的 `WWW-Authenticate` 是 `Bearer resource_metadata="..."` 形态，
  Bearer 后可能无空格——正则要宽松。
- scope 只能请求 `openid email`（client 就配了这两个，多要 profile/phone
  报 invalid_scope）。
- 回调端口必须 18765（Cognito 预注册；8765/8766 被 Quick Desktop 自身占用）。
- 本代理对任何"OAuth 保护的 Remote MCP × 只支持静态头的客户端"通用，
  换 endpoint/client_id 参数即可复用。
