"""Cognito pre-token-generation V2 触发器：把用户的 email / idp / auth_via
注入 token。

为什么需要 email：Cognito access token 默认不含 email，而部署 MCP 的
customJWTAuthorizer 配 allowedClients（只认 access token 的 client_id claim，
id_token 会被 "Claim 'client_id' value mismatch" 拒掉），MCP 客户端按 OAuth
规范发的也是 access token——所以 email 必须注入 access token，否则
_caller_email() 拿不到 owner（真机冒烟实证，见 AGENTCORE-SPIKE.md §6）。

为什么需要 idp / auth_via：`allowed_users="org"` 的主防线要求 Edge 能判断
会话来自哪个 IdP、以及本次 token 是怎么来的（spec §3.5）。

要求用户池 Essentials/Plus tier（access token 定制），LambdaVersion=V2_0。
"""

# 只有这两个来源能证明"本次 token 出自托管登录页（必经 IdP）或它换出的
# refresh token"。TokenGeneration_Authentication 是原生 InitiateAuth 流程
# 完成后触发的——linked 本地用户与设过密码的联邦用户走的就是它，
# 而它们的 identities 里仍有可信 provider，靠 idp claim 分辨不出来。
TRUSTED_AUTH_SOURCES = ("TokenGeneration_HostedAuth",
                        "TokenGeneration_RefreshTokens")


def handler(event, context):
    attrs = event["request"]["userAttributes"]
    claims = {}
    email = attrs.get("email", "")
    if email:
        claims["email"] = email
    # email_verified 必须进 **access token**：Cognito 默认只把它放 id_token，
    # 而 MCP 网关只收 access token（见上面 email 的同一个理由）。不注入的话
    # MCP 侧永远看不到验证状态，那道检查等于不存在。
    # 字符串化：Cognito 的 userAttributes 全是字符串（"true"/"false"），
    # 这里保持原样透出，由消费方统一按 _is_verified 判定，避免两处对
    # "true" / True / "1" 的理解不一致。
    claims["email_verified"] = str(attrs.get("email_verified", "")).lower()
    # idp 来自用户档案的**静态**属性：只证明"这个账号关联过某个 IdP"，
    # 不证明本次登录由它验证（spec §3.5 的效力边界）。
    idp = _provider_name(attrs.get("identities", ""))
    if idp:
        claims["idp"] = idp
    # auth_via 才是"本次 token 的来源"：把 triggerSource 透出去，
    # 让 Edge / MCP 能拒掉原生认证路径。
    claims["auth_via"] = event.get("triggerSource", "")
    if claims:
        # idTokenGeneration 与 accessTokenGeneration 是**两个独立容器**，
        # 只写一个不会同步到另一个（官方文档明示）。两处都要写：
        #   - id token：auth 服务 /callback 验签后从它取 email/idp 签会话
        #   - access token：MCP 网关只收 access token，owner 识别靠它
        # 少写 id token 那份 → 会话 JWT 永远没有 idp → Edge 开关一开
        # 全部合法用户被 302 拦死。
        # 各建一份**独立**的 claims dict：外层 dict(...) 是浅拷贝，只复制外壳，
        # 两个容器仍会共享同一个 claims 对象——改一处会静默影响另一处，而两者
        # 的消费方不同（auth 服务 / MCP 网关），这种耦合出问题极难定位。
        # 所以内层也要复制。
        event["response"]["claimsAndScopeOverrideDetails"] = {
            "idTokenGeneration": {"claimsToAddOrOverride": dict(claims)},
            "accessTokenGeneration": {"claimsToAddOrOverride": dict(claims)}}
    return event


def _provider_name(identities) -> str:
    """从 identities 属性取 providerName。形态在真机 spike 确认（Task 15）。"""
    import json
    if not identities:
        return ""
    try:
        parsed = json.loads(identities) if isinstance(identities, str) else identities
    except Exception:
        return ""
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        if isinstance(first, dict):
            return str(first.get("providerName", ""))
    return ""
