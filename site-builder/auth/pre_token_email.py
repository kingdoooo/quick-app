"""Cognito pre-token-generation V2 触发器：把用户的 email 属性注入 access token。

为什么需要：Cognito access token 默认不含 email，而部署 MCP 的
customJWTAuthorizer 配 allowedClients（只认 access token 的 client_id claim，
id_token 会被 "Claim 'client_id' value mismatch" 拒掉），MCP 客户端按 OAuth
规范发的也是 access token——所以 email 必须注入 access token，否则
_caller_email() 拿不到 owner（真机冒烟实证，见 AGENTCORE-SPIKE.md §6）。

要求用户池 Essentials/Plus tier（access token 定制），LambdaVersion=V2_0。
"""


def handler(event, context):
    email = event["request"]["userAttributes"].get("email", "")
    if email:
        event["response"]["claimsAndScopeOverrideDetails"] = {
            "accessTokenGeneration": {"claimsToAddOrOverride": {"email": email}}}
    return event
