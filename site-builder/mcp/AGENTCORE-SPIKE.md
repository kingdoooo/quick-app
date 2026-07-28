# Task 20 Spike 报告：AgentCore MCP 的 email claim 透传

**结论（一句话）**：AgentCore Runtime 的 customJWTAuthorizer 验签后**原样透传 `Authorization: Bearer <JWT>` 头**给容器内的 MCP server；用官方 `mcp` SDK 的 `FastMCP.get_context().request_context.request.headers` 读该头、解 JWT payload 取 `email` claim 即可。原计划的 `get_http_headers`（fastmcp 2.x API）在官方 SDK 中不存在，已用验证过的写法替换并提交。

## 1. 问题确认

- `from mcp.server.fastmcp import get_http_headers` 在官方 `mcp` SDK 1.28.1 中 **不存在**（实测 `hasattr(mcp.server.fastmcp, "get_http_headers") == False`）。它是 jlowin/fastmcp 2.x 的 API。原 server.py 一旦被真实 HTTP 调用就会 ImportError。

## 2. claim 透传机制（AgentCore Runtime，官方文档）

- AgentCore 支持 inbound OAuth / `customJWTAuthorizer`：网关验证入站 JWT（discoveryUrl + allowedClients），验签通过后**把 Authorization 头连同请求透传到容器**。官方 Developer Guide 明确 "Authorization header will be propagated automatically"（MCP server 作为 OAuth 2.0 resource server）。
- 出处：Amazon Bedrock AgentCore Developer Guide（bedrock-agentcore-dg），MCP interceptor / header propagation 章节；MCP client 用 `streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"})` 连接。

## 3. 读请求头的正确 API（官方 mcp SDK）

- 官方 SDK 无 `get_http_headers`。正确路径：`FastMCP` 实例 → `mcp.get_context()` → `.request_context.request`（一个 starlette `Request`）→ `dict(request.headers)`。
- `RequestContext.request` 字段自 mcp **1.10.0** 引入（1.9.0 无，1.10.0+ 有；当前锁 1.28.1 满足）。
- **本地端到端 smoke 已验证通过**：起一个 `FastMCP(stateless_http=True)` streamable-http server，工具内 `mcp.get_context().request_context.request.headers` 读到客户端发的 `Authorization: Bearer <fake-jwt>`，解出 `email=kent@example.com`，exit 0。同步工具（本项目工具都是同步 def）也能拿到 context——tool 在请求处理协程内被调用。

## 4. `_caller_email()` 确切实现（已应用到 server.py）

```python
def _caller_email() -> str:
    import base64, json as _json
    try:
        request = mcp.get_context().request_context.request
        auth = dict(request.headers).get("authorization", "") if request else ""
    except Exception:
        auth = ""
    token = auth[7:] if auth[:7].lower() == "bearer " else auth
    parts = token.split(".")
    if len(parts) == 3:
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload))
            email = claims.get("email", "")
            if email:
                return email
        except Exception:
            pass
    raise NotOwner("无法识别调用者身份（缺少 OAuth email claim）")
```

不重复验签（AgentCore 网关已验），只解 payload 取 email。

## 5. requirements 变更

**无需换成 fastmcp 2.x**，保持官方 `mcp>=1.10`（当前 1.28.1）。starlette 是 mcp 的传递依赖，无需显式加。10 个单测保持全绿（`_caller_email` 走 context，单测不触达该路径）。

## 6. 对 Task 3 Cognito 配置的连带影响（重要）

- email 必须在到达容器的那个 token 里。两种情形：
  - 若 AgentCore 透传的是 **id_token**：Cognito id_token 默认含 `email`（前提 app client 请求了 `openid email` scope，且用户池 email 属性存在）。
  - 若透传的是 **access token**：Cognito access token **默认不含 email**。此时需要：① app client 配 `email` scope；② 依赖 AgentCore/Cognito 是否把 email 放进 access token（Cognito 需自定义 scope 或 pre-token-generation Lambda 注入）——这是**唯一需真机确认**的点。
- **建议**：Task 3 的 MCP app client 保留 `openid email` scope（DEPLOY.md 已如此写）。真机冒烟时用 MCP Inspector 打一个真实 Cognito token，让 `list_my_sites` 回显 owner，确认它 == 登录飞书邮箱。若 access token 不含 email，则在 AgentCore authorizer 配置里改用 id_token，或加 Cognito pre-token-generation Lambda 把 email 注入 access token 的 claim。

## 7. 真机验证结论（2026-07-29，全部钉死）

1. **id_token vs access token**：AgentCore 网关不"选择"token——它验证客户端发来的
   任何 Bearer token。配 `allowedClients` 时**只有 access token 能过**（id_token
   被 401 拒，报文 `Claim 'client_id' value mismatch with configuration.`——
   id_token 用 `aud` 而非 `client_id`）。而 MCP 客户端按 OAuth 规范发的就是
   access token，所以正确做法**不是**改 `allowedAudience`（那会反过来拒掉
   access token），而是 §6 的方案②：**pre-token-generation V2 Lambda 把 email
   注入 access token**。已部署 `site-auth-pre-token`（源码
   `auth/pre_token_email.py`，V2_0，要求用户池 Essentials/Plus tier）。
2. `customJWTAuthorizer` 语法与本文一致（discoveryUrl + allowedClients），真机可用。
3. `get_context()` 在 AgentCore 托管运行时下可用：真机 `list_my_sites` 正确解出
   caller email，owner 归属与跨账号拒绝（"你不是…所有者"）都实测通过。
4. 无 token / 坏 token 网关直接 401，不触达容器。

## 8. 部署时其余步骤（不变，见 DEPLOY.md ⑤）

Dockerfile（ARM64）+ deploy_agentcore.py（cp common.py → buildx arm64 → ECR → create_agent_runtime，protocolConfiguration MCP + customJWTAuthorizer）+ Inspector 冒烟（5 工具 / 401 / owner==飞书邮箱）。
