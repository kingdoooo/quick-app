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
    #
    # **必须写 JSON 布尔，不能写字符串**：email_verified 是 OIDC Core 的标准
    # claim，类型定义为 boolean。之前这里 str(...).lower() 会把 id_token 里
    # 原本的 true 覆盖成 "true"——本项目的 _is_verified() 特意兼容了字符串，
    # 所以自家测试发现不了，但严格的 OIDC consumer 可能拒绝或误解该 token。
    # userAttributes 侧一律是字符串（"true"/"false"），故在此转换类型。
    verified = _attr_true(attrs.get("email_verified"))
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
        id_claims = dict(claims)
        access_claims = dict(claims)
        # **id_token：只在能证明为真时才写**。Cognito 本来就会把
        # email_verified 放进 id_token，属性缺失/为假时我们不去覆盖它——
        # 覆盖既无收益，又会把一个标准 claim 的来源变成"我们的触发器"，
        # 出问题时多一层排查。为真时显式写布尔，与 Cognito 自己的类型一致。
        if verified:
            id_claims["email_verified"] = True
        # **access token：始终显式写布尔**。这里 Cognito 不会自己放该 claim，
        # 而 MCP 的检查是 fail-closed——不写就等于永远拒绝。写 False 也有意义：
        # 让"确实未验证"与"触发器没跑"在下游可区分（后者是 claim 缺失）。
        access_claims["email_verified"] = bool(verified)
        event["response"]["claimsAndScopeOverrideDetails"] = {
            "idTokenGeneration": {"claimsToAddOrOverride": id_claims},
            "accessTokenGeneration": {"claimsToAddOrOverride": access_claims}}
    return event


def _attr_true(value) -> bool:
    """userAttributes 里的布尔属性判定。只认真值，其余一律 False。

    Cognito 的 userAttributes 全是字符串；联邦用户未映射该属性时可能整个缺失。
    与 login_handler._is_verified / server._is_verified 同语义（三处必须一致）。
    """
    return value is True or str(value).strip().lower() == "true"


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
