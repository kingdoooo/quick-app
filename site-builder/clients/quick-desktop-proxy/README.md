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

# 2) 注册为 Local MCP。推荐直接编辑
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
