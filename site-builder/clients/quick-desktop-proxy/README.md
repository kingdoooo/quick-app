# Quick Desktop MCP stdio 代理

Quick Desktop 的 Remote MCP 只支持静态 Headers，不支持 OAuth 授权码流程
（2026-07-29 实测，直接填 AgentCore endpoint 报 401）。本目录提供 Local MCP
（stdio）代理作为 workaround：

```
┌───────────────┐  stdio   ┌──────────────┐  HTTPS + Bearer  ┌───────────────────┐
│ Quick Desktop │ ◀──────▶ │  index.js    │ ───────────────▶ │ Bedrock AgentCore │
└───────────────┘          └──────────────┘                  └───────────────────┘
                                  │
                          ~/.site-builder-deploy-token.json
```

仅用 Node 18+ 内置模块，**无需 npm install**。

## 使用

```bash
# 1) 首次 OAuth（浏览器飞书登录，token 落盘，之后代理自动续期）
node auth.js "<endpoint_url>" "<client_id>"

# 2) Quick Desktop → Settings → Capabilities → MCP → Add
#    Connection type: Local
#    Command:         node
#    Args:            /绝对路径/index.js <endpoint_url> <client_id>
#    （UI 字段不是 shell：不要加引号，会成为参数的一部分。
#      Args 不接受多参数时：Args 只填脚本路径，Env 设
#      SITE_BUILDER_MCP_ENDPOINT / SITE_BUILDER_MCP_CLIENT_ID）
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
