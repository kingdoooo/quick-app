#!/usr/bin/env python3
"""部署平台专用 Cognito user pool（与上游 Quick SSO 的 pool 解耦）。幂等可重跑。

为什么要专用 pool：一期平台复用了 feishu-quick-sso 的 pool，平台侧配置
（pre-token 触发器、app client、token 形态）与 Quick SSO 相互牵制。二期
把平台身份独立出来，之后改平台配置不再影响别的消费方。

**IdP 无关**：本脚本只建 pool + 两个 app client（site/mcp）+ branding + pre-token 触发器。
联邦哪个 IdP 由 config.ini [IdP] 段决定——飞书适配器（feishu-quick-sso 的
OIDC 适配器）与标准 IdP（Okta、Azure AD 等）走同一条 OIDC provider 路径，
平台其余部分只消费 email/name claim。

两个 app client（machine 随 M4 的 resource server 一起建——
client_credentials 不能用空 scope 创建，否则脚本会在建 client 这步中止）：
- site：auth 服务用（confidential，authorization_code）
- mcp：MCP 客户端 OAuth 用（public，需预注册回调——Cognito 无 dynamic
  client registration）
- machine：key-proxy 用（client_credentials；**本脚本 M1 不建**——M4 建
  resource server 时经 `include_machine=True` 一并创建）

用法：
    python3 site-builder/scripts/deploy_pool.py
    python3 site-builder/scripts/deploy_pool.py --domain-prefix my-site-builder
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent

# "有没有 [ApiKey] 段"的判定只有一处：deployer/functions/api_key_config.py。
# 本脚本、deploy_agentcore.py、deploy_key_proxy.py 共用它——各写一次
# has_section 就是三个判定点，漏改一处即"部分部署"（最危险的状态）。
# 落 functions/ 而不是本目录：另两个脚本从 mcp/ 与 key-proxy/ 执行，
# 那两个目录看不到 scripts/（Codex 审查 2026-08-11 P1-3 已实测）。
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
from api_key_config import (api_key_enabled, machine_scope,  # noqa: E402
                            resource_server_id, scope_name)

POOL_NAME = "site-builder-users"
MCP_LOCALHOST_CALLBACK = "http://localhost:18765/callback"

# spec §3.5 第 4 条：org 边界 = app client 不开任何原生认证 flow。
# 只留 refresh（正常会话续期需要）。加入下面任何一项即打破边界：
#   ALLOW_USER_PASSWORD_AUTH / ALLOW_USER_SRP_AUTH / ALLOW_CUSTOM_AUTH /
#   ALLOW_USER_AUTH / ALLOW_ADMIN_USER_PASSWORD_AUTH
NATIVE_AUTH_DISABLED = ["ALLOW_REFRESH_TOKEN_AUTH"]
# **必须覆盖 ExplicitAuthFlows 的全部非 refresh 枚举值，legacy 三个也要列**：
# botocore 1.43.53 实测该枚举是 9 个值——除 5 个 ALLOW_* 外还有 3 个 legacy
# 值 ADMIN_NO_SRP_AUTH / CUSTOM_AUTH_FLOW_ONLY / USER_PASSWORD_AUTH
# （注意最后一个没有 ALLOW_ 前缀，与 ALLOW_USER_PASSWORD_AUTH 是两个不同值）。
# 漏掉它们的后果实测过：ExplicitAuthFlows=["USER_PASSWORD_AUTH"] 能同时通过
# _assert_no_native_flows 与 _verify_no_native_flows，而原生密码认证是全开的
# ——两道闸门一起瞎掉，等于边界不存在。
NATIVE_AUTH_FLOWS = ("ALLOW_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH",
                     "ALLOW_CUSTOM_AUTH", "ALLOW_USER_AUTH",
                     "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                     # legacy（无 ALLOW_ 前缀）——AWS 不允许与 ALLOW_* 混用，
                     # 但手工建的 client 或调试期改动可能只用它们
                     "ADMIN_NO_SRP_AUTH", "CUSTOM_AUTH_FLOW_ONLY",
                     "USER_PASSWORD_AUTH")


def _clean(value: str) -> str:
    """config.ini 的取值清洗：切掉行内注释再 strip，**不改大小写**。

    裸 ConfigParser 不剥行内注释（本仓库刻意保持这个语义，见
    deployer/tests/test_example_config_consistency.py），所以每个自己判分支的键
    都要先过这里。大小写必须原样保留——Cognito 的 provider 名校验区分大小写
    （实测：`Google` 被拒而 `google` 接受）。
    """
    return str(value).split("#")[0].split(";")[0].strip()


def _truthy(value: str) -> bool:
    """config.ini 的布尔解析。行内注释会被 configparser 并进值，故先过 _clean。

    只认明确的真值词；写错（yes/1/on 之外的拼写）一律当 False，与
    router/stack.py 对 require_idp_claim 的严格态度一致。
    """
    return _clean(value).lower() in ("true", "yes", "1", "on")


# ---- [IdP] 模式（ADR 0006 / 工单 07）-------------------------------------
#
# external-oidc：采用者已有 OIDC IdP（Okta / Entra / Google / 飞书适配器…），
#                issuer / client_id / client_secret 由他给出。**默认值**，
#                也是 mode 键缺失时的回落——存量 config.ini 里没有这个键。
# cognito-admin：资产自己再建第二个 Cognito 池当 OIDC IdP（LITE、只许管理员
#                建户、email 在 schema 层 Mutable=False），三个联邦字段由部署
#                过程派生。决策见 docs/adr/0006-*.md。
#
# **名字不叫 cognito-managed**（ADR 早期用过）：LITE 档恰恰**不支持** managed
# login v2，那个名字会把读者引到反面。
IDP_MODE_EXTERNAL = "external-oidc"
IDP_MODE_COGNITO = "cognito-admin"
IDP_MODES = (IDP_MODE_EXTERNAL, IDP_MODE_COGNITO)

# cognito-admin 独有的键（缺一不可：少了池名无法幂等找回那个池，少了域名前缀
# 就没有 authorization/token/userinfo 端点）
_COGNITO_MODE_KEYS = ("cognito_user_pool_name", "cognito_domain_prefix")
# external-oidc 独有的键；cognito-admin 下由部署过程派生，**非空即冲突**
_EXTERNAL_MODE_KEYS = ("issuer", "client_id", "client_secret")

# provider_name 的保留名（**逐个实测，区分大小写**，工单 06 腿 1）。
# 只有四个**社交类型名**会被 Cognito 拒（`Provider X cannot be of type OIDC`）；
# `SAML` 与小写 `google` 都被接受，所以不许往这张表里凭印象加名字——多拒一个
# 就是用一句假话挡住采用者。`COGNITO` 是本仓库自己的规则，理由见值。
RESERVED_PROVIDER_NAMES = {
    "Google": "Cognito 把它保留给原生 social provider 类型（ProviderType=Google），"
              "与本平台一律走的 ProviderType=OIDC 冲突。接 Google 用 GoogleOIDC。",
    "Facebook": "同上（原生 social provider 类型名）。",
    "LoginWithAmazon": "同上（原生 social provider 类型名）。",
    "SignInWithApple": "同上（原生 social provider 类型名）。",
    "COGNITO": "Cognito 的 API 接受它，但 app client 的 SupportedIdentityProviders "
               "用这个字面量表示「池内建用户目录」——同名会让配置语义无法分辨。",
}


def idp_mode(idp: dict) -> str:
    """[IdP] mode 的唯一解析点。键缺失 / 为空 → external-oidc（向后兼容）。

    未知值**响亮失败**：静默回落会让写错模式名的采用者建出一个「没有 IdP 池、
    client 只列 COGNITO」的平台池，而脚本输出看起来一切正常。
    """
    raw = _clean(idp.get("mode", ""))
    if not raw:
        return IDP_MODE_EXTERNAL
    if raw not in IDP_MODES:
        raise SystemExit(
            f"[IdP] mode = {raw!r} 不认识。只能是 {IDP_MODE_EXTERNAL}（已有 OIDC "
            f"IdP，默认）或 {IDP_MODE_COGNITO}（资产内置第二个 Cognito 池当 IdP）。"
            "键缺失时按 external-oidc。")
    return raw


def assert_provider_name_allowed(name: str) -> None:
    """provider_name 的保留名校验。**纯本地、零 API 调用，前移到任何 AWS 写之前。**

    不前移的代价实测过（工单 06 腿 1）：Cognito 要到 create_identity_provider
    才报 `Provider Google cannot be of type OIDC`，而那一步在建池与建托管域名
    **之后**，脚本停在中途。文档挡不住手滑。
    """
    why = RESERVED_PROVIDER_NAMES.get(name)
    if why:
        raise SystemExit(f"[IdP] provider_name = {name!r} 不能用：{why}")


def check_idp_section(idp: dict, mode: str) -> None:
    """[IdP] 段的本地一致性校验（零 AWS 调用）。

    三类判据：
      ① provider_name 非空时不许是保留名（两种模式都查）；
      ② 模式所需键齐备（cognito-admin 才有必填项——external-oidc 下"全空 =
         跳过联邦"是支持的首次部署状态，见 main() ③ 的告警分支）；
      ③ 两套模式的字段不许混填（静默忽略比报错难查得多：采用者以为自己指定了
         issuer，实际生效的是另一个池的）。
    """
    name = _clean(idp.get("provider_name", ""))
    if name:
        assert_provider_name_allowed(name)

    cognito_filled = [k for k in _COGNITO_MODE_KEYS if _clean(idp.get(k, ""))]
    # client_secret 不过 _clean：secret 里的 `#` 不是注释（Cognito 的 secret 是
    # [\w+]+，但别让清洗逻辑成为一条能改写凭证的路径）
    external_filled = [k for k in _EXTERNAL_MODE_KEYS if str(idp.get(k, "")).strip()]

    if mode == IDP_MODE_COGNITO:
        if not name:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 必须给 provider_name（Cognito 里那个"
                " provider 名，自取）。同一个值还要逐字符写进 router/config.ini 的"
                " [SiteBuilder] trusted_idps，否则 require_idp_claim=true 下这个 IdP"
                "的用户全部被 Edge 302——那一对没有任何自动闸门。")
        missing = [k for k in _COGNITO_MODE_KEYS if k not in cognito_filled]
        if missing:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 缺 {', '.join(missing)}。"
                "这两个键与 mode 是一组、缺一不可：没有池名就无法幂等找回那个 IdP 池，"
                "没有托管域名前缀就没有 authorize/token/userinfo 端点"
                "（issuer 的 discovery 文档全指向托管域名）。")
        if external_filled:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 下 {', '.join(external_filled)} 必须留空"
                "——它们由本次部署从新建的 IdP 池派生。填了值说明这份 config 混了两套"
                "模式的字段，静默忽略会让你以为生效的是自己填的那个 issuer。")
    elif cognito_filled:
        raise SystemExit(
            f"[IdP] mode = {IDP_MODE_EXTERNAL}（或未给 mode）时 {', '.join(cognito_filled)}"
            f" 必须留空——那是 {IDP_MODE_COGNITO} 模式的键。要用内置 IdP 池请显式写"
            f" mode = {IDP_MODE_COGNITO}。")


def resolve_idp_pool_names(*, pool_name: str, idp_pool_name: str | None,
                           idp_domain_prefix: str | None,
                           idp: dict) -> tuple[str, str]:
    """内置 IdP 池的池名与托管域名前缀：命令行旗标优先于 config。

    **隔离守卫**：`--pool-name` 不是生产池时，两个旗标必须都显式给出。
    `--pool-name` 只隔离了三样东西（平台池名、pre-token 函数名、SSM 前缀），
    **IdP 池的名字来自 config** ⇒「隔离平台池 + 生产 IdP 池」这个组合会对生产
    IdP 池的 app client 做 read-modify-write（改 SupportedIdentityProviders /
    ExplicitAuthFlows / CallbackURLs）。这里在任何 AWS 写之前拒掉它。
    """
    if pool_name != POOL_NAME and not (idp_pool_name and idp_domain_prefix):
        raise SystemExit(
            f"--pool-name {pool_name!r} 不是生产池，但没有同时给 --idp-pool-name 与"
            " --idp-domain-prefix。内置 IdP 池的名字来自 config.ini，`--pool-name`"
            "隔离不到它——照这样跑会对**生产 IdP 池**的 app client 做写操作。"
            "两个旗标都显式给出后再跑。")
    return (idp_pool_name or _clean(idp.get("cognito_user_pool_name", "")),
            idp_domain_prefix or _clean(idp.get("cognito_domain_prefix", "")))


def pool_config(base_domain: str) -> dict:
    """CreateUserPool 参数。

    UserPoolTier=ESSENTIALS 是硬要求：pre-token-generation V2（往 access
    token 注入 email）只在 Essentials+ 可用，而 MCP 网关只收 access token
    ——LITE 档会让 owner 识别整条链断掉（一期实测）。
    """
    return {
        "PoolName": POOL_NAME,
        "UserPoolTier": "ESSENTIALS",
        "AutoVerifiedAttributes": ["email"],
        "UsernameAttributes": ["email"],
        "Schema": [{"Name": "email", "AttributeDataType": "String",
                    "Required": True, "Mutable": True}],
        # AllowAdminCreateUserOnly=True 关闭自注册。这是 allowed_users="org"
        # 的安全前提：Edge 对 org 的判定只是"持有有效平台会话"，不查邮箱域，
        # 所以 pool 里绝不能有非企业身份（spec §3.5）。
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "UserPoolTags": {"project": "site-builder", "managed_by": "deploy_pool.py"},
    }


def client_configs(base_domain: str, extra_mcp_callbacks: list[str],
                   idp_name: str | None = None, *,
                   include_machine: bool = False,
                   machine_scopes: tuple[str, ...] = ()) -> dict:
    """app client 参数（默认只含 site/mcp）。

    idp_name 给出时，site/mcp 的 SupportedIdentityProviders **只列该 IdP**，
    不含 COGNITO——否则托管登录页仍暴露本地用户登录/注册入口，
    allowed_users="org" 的语义就被击穿（spec §3.5）。未给出时回落
    ["COGNITO"]（首次部署、联邦还没接），main() 会显式告警。

    **那个 ["COGNITO"] 回落只对"新建"成立**：已存在的 client 走
    update_user_pool_client（整体替换），把回落值盖上去等于把线上的联邦
    provider 摘掉。所以 _ensure_clients 在 update 路径上会把这个键整个删掉，
    让 read-modify-write 保留线上现值——详见 _idp_derived_client_keys。
    """
    # 每个 client 一份独立副本：共享同一个 list 对象时，任何一处 append
    # 会静默改掉另一个 client 的 provider 名单——而这正是 org 边界字段
    # （实测：往 site 的名单 append "COGNITO"，mcp 的也变成 [Okta, COGNITO]）。
    # M4 走 include_machine=True 时最可能第一次踩到。
    _providers = [idp_name] if idp_name else ["COGNITO"]
    site = {
        "ClientName": "site-builder-site",
        "GenerateSecret": True,
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": [f"https://auth.{base_domain}/callback"],
        # **/logged-out，不是 /logout**：auth 服务的 /logout 会重定向到 Cognito
        # 的 /logout?logout_uri=…，而 Cognito 只接受已登记的 sign-out URL。
        # 若这里登记 /logout，Cognito 登出后又打回 /logout → 无限重定向。
        # 保留 /logout 以兼容历史登记值（多一个已登记 URL 无害，少一个会报错）。
        "LogoutURLs": [f"https://auth.{base_domain}/logged-out",
                       f"https://auth.{base_domain}/logout"],
        "SupportedIdentityProviders": list(_providers),
        # refresh token 有效期收到 1 天（默认 30 天）。理由：refresh token
        # 一旦签发，在有效期内可持续换新 token，而新 token 的 auth_via 是
        # 受信的 TokenGeneration_RefreshTokens——万一原生 flow 曾被误开，
        # 关掉它并不能使已签发的 token 失效，只能靠有效期到期或显式吊销。
        # 站点会话 cookie 本就是 24h，节奏一致。
        #
        # access token 也必须显式收：默认 60 分钟，而**吊销 refresh token 不能
        # 立刻废掉已经换出去的 access token**。AWS 对 AdminUserGlobalSignOut
        # 明说"Other requests might be valid until your user's token expires"，
        # 且 token-revocation 文档说被吊销的 token"仍然有效，如果用任何只验
        # 签名与过期时间的 JWT 库校验"——AgentCore 的 inbound authorizer 正是
        # 这种（只按 discovery/公钥/exp/allowedClients 验，不回查 Cognito 撤销
        # 状态）。所以真实暴露窗口 = refresh 有效期 + access 有效期。
        # 收到 15 分钟：把吊销后的残留窗口从 1 小时压到 15 分钟。
        "AccessTokenValidity": 15,
        "IdTokenValidity": 15,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes",
                               "RefreshToken": "days"},
        # spec §3.5 第 4 条 —— **这是 org 边界本体**，不是可调项。
        # 只留 refresh：不含 ALLOW_USER_PASSWORD_AUTH / ALLOW_USER_SRP_AUTH /
        # ALLOW_CUSTOM_AUTH / ALLOW_USER_AUTH / ALLOW_ADMIN_USER_PASSWORD_AUTH，
        # 因此 InitiateAuth / AdminInitiateAuth 对本 client 直接失败——
        # linked 用户与设过密码的联邦用户都无从发起原生登录，也就不存在
        # 可被 refresh 洗白的原生 token（claim 校验挡不住那条路）。
        "ExplicitAuthFlows": list(NATIVE_AUTH_DISABLED),
    }
    mcp = {
        "ClientName": "site-builder-mcp",
        "GenerateSecret": False,   # Claude Code 等客户端无法安全保存 secret
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": [MCP_LOCALHOST_CALLBACK] + list(extra_mcp_callbacks),
        "SupportedIdentityProviders": list(_providers),
        # 同 site：refresh 1 天 + access/id 15 分钟。mcp client 这条更要紧——
        # AgentCore authorizer 不回查 Cognito 撤销状态，吊销后残留的 access
        # token 在过期前仍能调 MCP（部署/改权限/下线）。
        "AccessTokenValidity": 15,
        "IdTokenValidity": 15,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes",
                               "RefreshToken": "days"},
        "ExplicitAuthFlows": list(NATIVE_AUTH_DISABLED),   # 同上，边界
    }
    # machine client（key-proxy 用）**不在 M1 创建**：client_credentials 授权
    # 只能授 resource server 的 custom scope，而 AllowedOAuthScopes 为空的
    # client_credentials client 会被 Cognito 的跨字段校验拒绝——脚本会在创建
    # app client 这一步中止，后面的 branding、pre-token 触发器都跑不到。
    # resource server + custom scope 属于 M4 的范围，届时连同 machine client
    # 一起建（M4 调 client_configs 时传 include_machine=True）。
    out = {"site": site, "mcp": mcp}
    if include_machine:
        if not machine_scopes:
            raise ValueError(
                "machine client 需要至少一个 resource server custom scope——"
                "client_credentials 不能用空 scope 创建（先建 resource server）")
        out["machine"] = {
            "ClientName": "site-builder-machine",
            "GenerateSecret": True,
            "AllowedOAuthFlows": ["client_credentials"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": list(machine_scopes),
            "CallbackURLs": [],
            # machine 走 client_credentials，与用户身份无关
            "SupportedIdentityProviders": ["COGNITO"],
            # 不开任何原生认证 flow（与 site/mcp 同一条边界）。
            # **必须是显式的 ["ALLOW_REFRESH_TOKEN_AUTH"]，不能是 []**：空数组被
            # Cognito 当成"未指定"，而未指定的默认值含 ALLOW_USER_SRP_AUTH +
            # ALLOW_CUSTOM_AUTH（工单 06 实测：[] 时 USER_SRP_AUTH 调 InitiateAuth
            # 成功返回挑战）。client_credentials 与 ExplicitAuthFlows 正交，
            # 收紧它不影响 key-proxy 换 token。
            "ExplicitAuthFlows": list(NATIVE_AUTH_DISABLED),
        }
    return out


def _cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    return cfg


def _find_pool(cog, name: str) -> str | None:
    """按名字找 pool。name 由调用方传入（默认 POOL_NAME）——标准 IdP spike
    要在独立的临时 pool 上做，不能改生产 pool 的 client 配置（Task 15 Step 7）。"""
    token = None
    while True:
        kw = {"NextToken": token} if token else {}
        resp = cog.list_user_pools(MaxResults=60, **kw)
        for p in resp.get("UserPools", []):
            if p["Name"] == name:
                return p["Id"]
        token = resp.get("NextToken")
        if not token:
            return None


def pool_update_params(cog, pool: dict) -> dict:
    """describe_user_pool 结果 → update_user_pool 的完整参数。

    实现在 auth/deploy_auth.py（那边挂 pre-token 触发器时也要用同一套语义）。
    **两边各留一份手抄白名单正是这个坑上一次的形态**，所以这里只做转发，
    不要复制实现。详见 deploy_auth.pool_update_params 的 docstring。
    """
    sys.path.insert(0, str(HERE.parent / "auth"))
    import deploy_auth
    return deploy_auth.pool_update_params(cog, pool)


def _ensure_pool(cog, base_domain: str, pool_name: str = POOL_NAME) -> str:
    """幂等：已有 pool 也要把关键配置纠正回来，不能直接 return。

    否则"幂等重跑"修不了已经建错的 pool——尤其
    AllowAdminCreateUserOnly（自注册开着就等于全部 org 站点对公网开放，
    spec §3.5）。

    pool_name 可覆盖：标准 IdP spike 用独立临时 pool，避免把生产 client 的
    SupportedIdentityProviders 改成另一个 IdP（会切断线上登录，见 Task 15
    Step 7）。
    """
    existing = _find_pool(cog, pool_name)
    if not existing:
        cfg = pool_config(base_domain)
        cfg["PoolName"] = pool_name
        pool_id = cog.create_user_pool(**cfg)["UserPool"]["Id"]
        print(f"  新建 pool {pool_id}")
        return pool_id

    print(f"  已存在 pool {existing}，核对关键配置")
    pool = cog.describe_user_pool(UserPoolId=existing)["UserPool"]
    # 回填全部可保留字段（不是手工白名单——见 pool_update_params 的注释），
    # 再把本脚本真正要纠正的两项盖上去
    kwargs = pool_update_params(cog, pool)
    desired = pool_config(base_domain)
    kwargs["AdminCreateUserConfig"] = desired["AdminCreateUserConfig"]
    kwargs["UserPoolTier"] = desired["UserPoolTier"]
    cog.update_user_pool(UserPoolId=existing, **kwargs)

    # 复验：update 是整体替换，静默漂移过一次就够致命，必须读回确认
    after = cog.describe_user_pool(UserPoolId=existing)["UserPool"]
    only_admin = after.get("AdminCreateUserConfig", {}).get(
        "AllowAdminCreateUserOnly")
    if only_admin is not True:
        raise SystemExit(
            f"pool {existing} 的 AllowAdminCreateUserOnly={only_admin!r}，"
            "自注册未关闭——allowed_users=\"org\" 会对公网开放，中止")
    if after.get("UserPoolTier") != "ESSENTIALS":
        raise SystemExit(
            f"pool {existing} 的 tier={after.get('UserPoolTier')!r}，"
            "pre-token V2 需要 ESSENTIALS+，中止")
    print("  ✓ 自注册已关闭、tier=ESSENTIALS")
    return existing


MANAGED_LOGIN_V2 = 2


def _ensure_domain(cog, pool_id: str, prefix: str) -> str:
    """建/纠正托管域名。

    **`ManagedLoginVersion` 属于 domain API，不是 client API**：
    `CreateUserPoolClient` / `UpdateUserPoolClient` 没有这个参数，传进去会
    `ParamValidationError: Unknown parameter`（已用仓库当前 botocore 的
    service model 实测：client 两个 False、domain 两个 True）。
    不显式指定时 domain 默认 classic hosted UI（version 1），而
    `CreateManagedLoginBranding` 给的是 managed login 的 style——两者不匹配
    时登录页仍不可用。
    """
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    existing = pool.get("Domain")
    if not existing:
        cog.create_user_pool_domain(Domain=prefix, UserPoolId=pool_id,
                                    ManagedLoginVersion=MANAGED_LOGIN_V2)
        print(f"  域名前缀 {prefix}（managed login v{MANAGED_LOGIN_V2}）")
        return prefix

    # 已存在：核对版本，漂移了就纠回来（幂等重跑要能修配错的 domain）
    desc = cog.describe_user_pool_domain(Domain=existing)
    version = desc.get("DomainDescription", {}).get("ManagedLoginVersion")
    if version != MANAGED_LOGIN_V2:
        cog.update_user_pool_domain(Domain=existing, UserPoolId=pool_id,
                                    ManagedLoginVersion=MANAGED_LOGIN_V2)
        print(f"  域名 {existing}: managed login v{version} → v{MANAGED_LOGIN_V2}")
    else:
        print(f"  域名 {existing}（managed login v{version}）")
    return existing


SCOPE_DESCRIPTION = "Invoke the site-builder deploy MCP"


def ensure_resource_server(cog, pool_id: str, *, identifier: str,
                           scope: str) -> str:
    """幂等建 resource server + custom scope；返回 `{identifier}/{scope}`。

    machine client 的存在前提：`client_credentials` 只能授 resource server 的
    custom scope，空 scope 会被 Cognito 的跨字段校验拒绝。

    **UpdateResourceServer 与 UpdateUserPoolClient 一样是整体替换**：补 scope
    时必须把已有的 scope 一起回填。只发新 scope 会把别的 scope 从 resource
    server 上抹掉，而那些 scope 可能已经授给了别的 client——症状是那个 client
    换 token 报 invalid_scope，与本次改动看不出关系。
    """
    want = {"ScopeName": scope, "ScopeDescription": SCOPE_DESCRIPTION}
    try:
        current = cog.describe_resource_server(
            UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    except cog.exceptions.ResourceNotFoundException:
        cog.create_resource_server(UserPoolId=pool_id, Identifier=identifier,
                                   Name=identifier, Scopes=[want])
        print(f"  新建 resource server {identifier}，scope {scope}")
        return f"{identifier}/{scope}"

    scopes = list(current.get("Scopes") or [])
    if any(s.get("ScopeName") == scope for s in scopes):
        print(f"  resource server {identifier} 已有 scope {scope}")
        return f"{identifier}/{scope}"
    cog.update_resource_server(
        UserPoolId=pool_id, Identifier=identifier,
        Name=current.get("Name") or identifier, Scopes=scopes + [want])
    print(f"  resource server {identifier}: 补上 scope {scope}"
          f"（保留原有 {[s.get('ScopeName') for s in scopes]}）")
    return f"{identifier}/{scope}"


# 探针 provider 名：**只在本进程内做比对，绝不下发给 AWS**。
# 取一个不可能是真实 provider 名的值（Cognito 的 provider 名不含下划线包裹的
# 这种形态，且真值来自 config.ini 的 [IdP] provider_name）。
_PROBE_IDP = "__idp_probe__"


def _idp_derived_client_keys(base_domain: str, extra_mcp_callbacks: list[str],
                             *, include_machine: bool,
                             machine_scopes: tuple[str, ...]) -> frozenset:
    """哪些 client 的 SupportedIdentityProviders 是"跟着 [IdP] 段走"的。

    用探针 IdP 名跑一遍 client_configs 再比对，**不手抄一份
    {"site", "mcp"} 名单**：手抄的那份会在加第四个联邦 client 时腐烂，而腐烂
    的症状恰好就是本次要修的那个缺陷（新 client 的线上 provider 名单在无
    [IdP] 重跑时被清空）。唯一定义仍在 client_configs 里。

    machine client 探不到，这是对的：它的 ["COGNITO"] 是写死的正确值
    （client_credentials 与用户身份无关），不随 [IdP] 变，所以它照常被下发。
    反过来若有人手工往 machine 上加了联邦 provider，重跑会纠回 COGNITO
    ——方向是收紧，不是放开。
    """
    probe = client_configs(base_domain, extra_mcp_callbacks, _PROBE_IDP,
                           include_machine=include_machine,
                           machine_scopes=machine_scopes)
    return frozenset(k for k, v in probe.items()
                     if v.get("SupportedIdentityProviders") == [_PROBE_IDP])


def _ensure_clients(cog, pool_id: str, base_domain: str,
                    extra_mcp_callbacks: list[str],
                    idp_name: str | None = None, *,
                    include_machine: bool = False,
                    machine_scopes: tuple[str, ...] = ()) -> dict:
    """建/更新 app client。

    include_machine / machine_scopes **原样透传**给 client_configs：那两个参数
    在 M1 落地时没有任何调用方（machine client 属于 M4），所以这里漏加就是
    main() 一传参数就 TypeError，而 client_configs 自己的用例照样全绿。

    **create 与 update 对"没有 [IdP] 段"的处理必须不同**（2026-08-12 修）：
    client_configs 在无 IdP 时回落 ["COGNITO"]，而 update 是 read-modify-write
    ——盖上去就把线上的联邦 provider（如 Feishu）从生产 client 上摘掉：
      · 全部用户当场登不进（托管登录页不再有 IdP 入口）；
      · 同时把 Cognito 本地登录/注册重新暴露出来，allowed_users="org" 的边界
        （spec §3.5、§11）随之失效。
    "配置缺失"在这里绝不能被当成"删掉联邦"。本仓库的一贯方向是缺/读不出配置
    就取最严解释，而这里最严的解释是**一个字节都不动线上的 provider 名单**：
    所以 update 路径把这个键整个删掉，让 _client_update_params 的回填保留现值。
    create 路径没有"现值"可保留，仍用 ["COGNITO"]（main() 已为该情形告警）。
    """
    existing = {}
    token = None
    while True:
        kw = {"NextToken": token} if token else {}
        resp = cog.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60, **kw)
        for c in resp.get("UserPoolClients", []):
            existing[c["ClientName"]] = c["ClientId"]
        token = resp.get("NextToken")
        if not token:
            break

    federated = _idp_derived_client_keys(base_domain, extra_mcp_callbacks,
                                         include_machine=include_machine,
                                         machine_scopes=machine_scopes)
    out = {}
    for key, params in client_configs(base_domain, extra_mcp_callbacks,
                                      idp_name,
                                      include_machine=include_machine,
                                      machine_scopes=machine_scopes).items():
        _assert_no_native_flows(key, params)
        name = params["ClientName"]
        if name in existing:
            client_id = existing[name]
            desired = params
            if not idp_name and key in federated:
                # 无 [IdP] 段 → 不声明这个字段，交给 read-modify-write 保留现值
                desired = {k: v for k, v in params.items()
                           if k != "SupportedIdentityProviders"}
            update = _client_update_params(cog, pool_id, existing[name], desired)
            if desired is not params:
                live = update.get("SupportedIdentityProviders")
                print(f"  {name}: 无 [IdP] 段 → 保留线上 IdP 名单 "
                      f"{live if live else '（线上未显式设置，同样不动）'}")
            cog.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id,
                                        **update)
            print(f"  更新 client {name} = {client_id}")
        else:
            client_id = cog.create_user_pool_client(
                UserPoolId=pool_id, **params)["UserPoolClient"]["ClientId"]
            print(f"  新建 client {name} = {client_id}")
        out[key] = client_id
    return out


# 本脚本**有意不回填**的字段（与 service model 无关的业务/调用约定）。
#
# GenerateSecret：只在 create 有效，update 不接受。
# UserPoolId / ClientId：**两个 shape 里都有**，所以动态求差不会剔掉它们，
# 而调用方是 update_user_pool_client(UserPoolId=..., ClientId=..., **merged)
# ——留在 merged 里会 TypeError（同一关键字传了两次）。必须显式排除。
#
# **ClientName 不在此列**（曾经在，是错的）：update_user_pool_client 接受它，
# 而 AWS 的契约是"未提供的属性恢复默认值"，跳过它没有依据。原先的理由是
# "更新名称会导致下次按名称找不到"——但这里是 read-modify-write，回填的就是
# 当前名称，而 desired["ClientName"] 正是用来查到这个 client 的同一个值，
# 两者相等，正常回填不可能产生重命名。
_CLIENT_SKIP_KEYS = frozenset({"GenerateSecret", "UserPoolId", "ClientId"})


def _client_describe_only_keys(cog) -> frozenset:
    """describe_user_pool_client 回传但 update 不接受的字段（回填即报错）。

    **按 service model 动态求差，不硬编码。** 硬编码那份"对当前 pinned 版本
    正确"的清单在本仓库不可复现——requirements 里 boto3 是不钉版本的，
    换台机器装到新版就可能多出字段。动态求差没有这个问题。
    """
    sm = cog.meta.service_model
    describe_members = set(sm.operation_model(
        "DescribeUserPoolClient").output_shape.members["UserPoolClient"].members)
    update_members = set(sm.operation_model(
        "UpdateUserPoolClient").input_shape.members)
    return frozenset(describe_members - update_members)

# app client 必须能读写的属性。
#   email          —— IdP 映射目标 + 授权主键
#   email_verified —— IdP 映射目标（_ensure_oidc_idp 默认映射它）
#   name           —— IdP 映射目标（会话里的显示名）
# 缺任一项的后果见 _client_update_params 的注释。
_REQUIRED_CLIENT_ATTRIBUTES = frozenset({"email", "email_verified", "name"})


def _client_update_params(cog, pool_id: str, client_id: str,
                          desired: dict) -> dict:
    """read-modify-write：先 Describe，再把本脚本声明的字段盖上去。

    **UpdateUserPoolClient 是整体替换**，官方明示"If you don't provide a value
    for an attribute, Amazon Cognito sets it to its default value"，并建议
    "construct this API request to pass the existing configuration of your app
    client, modified to include the changes that you want to make"。
    只发本脚本声明的字段（旧实现）会把脚本没管的配置静默打回默认值，其中至少
    两项是安全相关的：
      · PreventUserExistenceErrors —— **API 创建/更新的默认值是 LEGACY（关闭）**，
        而控制台默认是 ENABLED。运营同学在控制台开了它，脚本一重跑就被关掉，
        用户枚举防护消失，且没有任何输出提示。
      · EnableTokenRevocation —— 关掉后 refresh token 无法吊销，而
        AgentCore 的 authorizer 不回查撤销状态，等于延长了被盗 token 的寿命。
    其余如 ReadAttributes / WriteAttributes / AnalyticsConfiguration 同理。

    ClientName **照常回填当前值**（曾经有一版跳过它，是错的）：update 接受该
    字段，契约是"未提供即恢复默认值"，跳过没有依据。回填不会造成重命名——
    这是 read-modify-write，回填的就是线上现值，而 desired["ClientName"] 正是
    用来查到这个 client 的同一个值。跳过它的字段见 _CLIENT_SKIP_KEYS。
    """
    current = cog.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    drop = _client_describe_only_keys(cog) | _CLIENT_SKIP_KEYS
    merged = {k: v for k, v in current.items() if k not in drop}
    merged.update({k: v for k, v in desired.items() if k not in drop})
    # Read/WriteAttributes 必须涵盖全部 IdP 映射属性与 scope 必需属性，
    # **不能只是沿用线上值**（前一版就是这样，属于半个修复）：线上值是
    # email_verified 映射之前配的，缺这一项时
    #   · WriteAttributes 缺 → 联邦登录写不进该属性（官方 API 参考说抛错、
    #     开发者指南说静默跳过——两种说法都意味着必须包含）；
    #   · ReadAttributes 缺而请求了 email scope → token 端点 invalid_grant。
    # 两者都表现为"部署与 Stubber 测试全绿、真机一登录就失败"。
    #
    # 语义合并（并集）而不是 fail-fast：这两个字段本就允许运营侧扩展
    # （加自定义属性），报错中止会把可自愈的配置漂移变成部署阻塞。
    # 空/缺失保持空——Cognito 的语义是"未指定即全部标准属性可读写"，
    # 显式塞一份名单反而把它从"全部"收窄成"这几个"。
    for field in ("ReadAttributes", "WriteAttributes"):
        existing = merged.get(field)
        if not existing:
            continue        # 未指定 = 全部标准属性，已覆盖，不要画蛇添足
        merged[field] = sorted(set(existing) | _REQUIRED_CLIENT_ATTRIBUTES)
    return merged


def _assert_no_native_flows(key: str, params: dict) -> None:
    """边界自检：client 参数里不得出现任何原生认证 flow（spec §3.5 第 4 条）。

    放在下发之前——配置漂移（有人为了调试加回 USER_PASSWORD_AUTH）会让
    allowed_users="org" 的边界失效，而 claim 校验拦不住"原生认证 → refresh
    洗白"这条路径。

    **空 / 缺席同样是缺陷**（工单 06 实测）：Cognito 把它当成"未指定"，默认值是
    ALLOW_REFRESH_TOKEN_AUTH + ALLOW_USER_SRP_AUTH + ALLOW_CUSTOM_AUTH ⇒ 能力面
    是开着的，而与 NATIVE_AUTH_FLOWS 求交集恰好为空 ⇒ 两道闸门一起瞎掉。
    """
    flows = set(params.get("ExplicitAuthFlows") or [])
    if not flows:
        raise SystemExit(
            f"client {key} 的 ExplicitAuthFlows 为空 / 未给——Cognito 会把它当成"
            "「未指定」并套用默认值（含 ALLOW_USER_SRP_AUTH + ALLOW_CUSTOM_AUTH），"
            f"等于原生认证全开。必须显式给 {NATIVE_AUTH_DISABLED}。")
    bad = flows & set(NATIVE_AUTH_FLOWS)
    if bad:
        raise SystemExit(
            f"client {key} 开了原生认证 flow {sorted(bad)}——这会打破 org 边界"
            "（spec §3.5 第 4 条）。要支持原生登录必须先重新设计该边界。")


def _verify_no_native_flows(cog, pool_id: str, clients: dict) -> None:
    """下发后读回复验：update_user_pool_client 是整体替换，漏传即被清空/改写。

    **读回 [] / None 也要红**：那是"未指定" ⇒ 线上能力面含 SRP + CUSTOM
    （工单 06 实测），而旧判据会为它打印一行 ✓。
    """
    for key, client_id in clients.items():
        desc = cog.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
        flows = set(desc.get("ExplicitAuthFlows") or [])
        if not flows:
            raise SystemExit(
                f"client {key}({client_id}) 线上的 ExplicitAuthFlows 是空 / 未设——"
                "Cognito 按「未指定」套默认值（含 SRP + CUSTOM），原生认证实际开着，"
                f"中止。期望恰好是 {NATIVE_AUTH_DISABLED}（spec §3.5 第 4 条）")
        bad = flows & set(NATIVE_AUTH_FLOWS)
        if bad:
            raise SystemExit(
                f"client {key}({client_id}) 线上仍开着 {sorted(bad)}——"
                "org 边界失效，中止（spec §3.5 第 4 条）")
    print("  ✓ 所有 client 均未开启原生认证 flow（org 边界成立）")


def _ensure_branding(cog, pool_id: str, clients: dict) -> None:
    """给 API 创建的 app client 套 branding style。

    AWS 明确：经 CreateUserPoolClient 建的 client **不会**自动获得 branding
    style，套上之前 managed login 与 classic hosted UI 页面都不可用
    （控制台建的会自动有，所以这个坑只在脚本化部署时出现）。不做这步，
    后面所有登录验证会在 /oauth2/authorize 第一步就失败。
    用 Cognito 默认样式（UseCognitoProvidedValues=True），不做定制。
    前提是 domain 已是 managed login v2（见 _ensure_domain）——style 与
    domain 版本不匹配时登录页依然不可用。
    """
    for key in ("site", "mcp"):
        try:
            cog.create_managed_login_branding(
                UserPoolId=pool_id, ClientId=clients[key],
                UseCognitoProvidedValues=True)
            print(f"  {key}: 已套默认 branding")
        except cog.exceptions.ManagedLoginBrandingExistsException:
            print(f"  {key}: branding 已存在")


def _ensure_oidc_idp(cog, pool_id: str, idp: dict) -> None:
    """联邦一个 OIDC IdP。飞书适配器与标准 IdP（Okta 等）走同一条路径。

    **email 的可信度是整个授权模型的地基**：owner / collaborators /
    allowed_users / 会话 claim 全以 email 为键。而联邦映射进 Cognito 的 email
    **默认是 unverified**（官方："By default, mapped email addresses are
    unverified… Instead, map an attribute from your IdP to get the verification
    status"）。若 IdP 允许用户自行设置未验证邮箱，攻击者把自己的 email 改成
    某站点 owner 的地址即可继承其权限。

    因此在有 email_verified 的 IdP 上必须映射它。映射本身是安全的：官方明示
    "Amazon Cognito will map incoming claims to user pool attributes only if
    the claims exist in the incoming token"——IdP 不发这个 claim 时是 no-op，
    **不会导致登录失败**。所以默认就映射上（config.ini 可关）。

    注意映射的效力边界（别把它当成完整防线）：
      · 该属性是**粘性**的——官方说源 claim 消失时 Cognito 不会删除或改写已有
        值，所以"某次登录带了 true，之后不带"不会退回 false。
      · 它证明"IdP 声明该邮箱已验证"，不证明"邮箱不可被用户自改"。真正的
        强约束是企业 IdP 侧保证邮箱唯一且用户不可自改。
      · 长期正解是把授权主键换成 issuer+subject，email 只作展示（spec 未来项）。
    """
    name = idp["provider_name"]
    # secret 优先从环境变量取：config.ini 虽 gitignored，但落成磁盘明文仍会
    # 进备份 / 编辑器缓存 / 误 cat 的终端回滚。用
    #   asm-exec -- env SB_IDP_CLIENT_SECRET={{resolve:secretsmanager:…}} \
    #     python3 deploy_pool.py
    # 可让明文只存在于子进程。显式注入优先于 config 值。
    secret = os.environ.get("SB_IDP_CLIENT_SECRET", "").strip() \
        or idp.get("client_secret", "").strip()
    if not secret:
        sys.exit(f"IdP {name} 缺 client_secret：填 config.ini [IdP] client_secret，"
                 "或用环境变量 SB_IDP_CLIENT_SECRET 注入。\n"
                 "空值建出的 provider 会在**用户登录时**才失败"
                 "（回调报 invalid_client），比部署时报错难查得多。")
    details = {
        "client_id": idp["client_id"],
        "client_secret": secret,
        "attributes_request_method": "GET",
        "oidc_issuer": idp["issuer"],
        "authorize_scopes": idp.get("scopes", "openid email profile"),
    }
    mapping = {"email": "email", "name": "name"}
    # 默认映射 email_verified；IdP 确实不提供且不想留空属性时可显式关掉。
    if _truthy(idp.get("map_email_verified", "true")):
        mapping["email_verified"] = "email_verified"
    try:
        cog.describe_identity_provider(UserPoolId=pool_id, ProviderName=name)
        cog.update_identity_provider(UserPoolId=pool_id, ProviderName=name,
                                     ProviderDetails=details,
                                     AttributeMapping=mapping)
        print(f"  更新 IdP {name}")
    except cog.exceptions.ResourceNotFoundException:
        cog.create_identity_provider(UserPoolId=pool_id, ProviderName=name,
                                     ProviderType="OIDC",
                                     ProviderDetails=details,
                                     AttributeMapping=mapping)
        print(f"  新建 IdP {name}")


def _store_client_secrets(cog, pool_id: str, clients: dict, region: str,
                          param_prefix: str = "/site-builder", *, ssm=None) -> None:
    """client secret 直接写 SSM SecureString，**不打印明文**。

    不要改成打印 `aws ssm put-parameter --value '<secret>'` 让人手敲：
    那会把凭证留在 shell history、终端回滚缓冲与 agent transcript 里，
    执行时还会出现在进程参数（ps 可见）。

    param_prefix 随 pool 隔离：隔离 spike（`--pool-name`）**绝不能**把临时
    pool 的 secret 写进生产参数名——那会覆盖 auth 服务正在用的 site client
    secret，线上换 token 立刻失败（比"改了生产 client"更隐蔽，因为 Cognito
    侧看不出任何变化）。见 Task 15 Step 7。

    ssm 可注入：boto3.client() 每次返回新对象，函数内部自建 client 时
    botocore Stubber **拦不住**——测试里那次 put_parameter 会真的打到当前
    凭证的账号（本仓库实测发生过，误写了一个真实参数）。所以把 client 做成
    可注入的参数，让测试能钉住它。
    """
    if ssm is None:
        import boto3
        ssm = boto3.client("ssm", region_name=region)
    # **按 clients 里实际存在的 client 取**，不写死清单：machine client 只在
    # 启用 API Key 组件时才建，硬编码"两个都写"会在这一步 KeyError 中止，
    # 而前面七步已经改过线上资源（部署脚本停在中途最难收拾）。
    # 反过来漏了 machine 则 key-proxy 永远换不到 token（secret 只在这里落 SSM）。
    for key, param in ((k, f"{param_prefix}/{name}") for k, name in
                       (("site", "site-client-secret"),
                        ("machine", "machine-client-secret"))
                       if k in clients):
        secret = cog.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=clients[key])["UserPoolClient"].get(
                "ClientSecret", "")
        if not secret:
            print(f"  {param}: 该 client 无 secret（public client），跳过")
            continue
        ssm.put_parameter(Name=param, Value=secret, Type="SecureString",
                          Overwrite=True)
        print(f"  {param}: 已写入（长度 {len(secret)}）")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain-prefix", default="site-builder-auth",
                    help="Cognito 托管域名前缀（全局唯一）")
    ap.add_argument("--mcp-callback", action="append", default=[],
                    help="额外的 MCP 回调 URL（如 AgentCore identities 回调），可重复")
    # 标准 IdP spike 用独立临时 pool：在生产 pool 上换 [IdP] 重跑会把飞书从
    # 生产 client 的 SupportedIdentityProviders 里移除，线上登录立即中断
    # （Task 15 Step 7）。默认仍是生产 pool 名。
    ap.add_argument("--pool-name", default=POOL_NAME,
                    help=f"user pool 名（默认 {POOL_NAME}；仅隔离 spike 时改）")
    args = ap.parse_args()

    import boto3
    cfg = _cfg()
    region = cfg["Platform"]["region"]
    base_domain = cfg["Platform"]["base_domain"]
    cog = boto3.client("cognito-idp", region_name=region)

    print(f"① user pool（禁自注册）: {args.pool_name}")
    pool_id = _ensure_pool(cog, base_domain, args.pool_name)

    print("② 托管域名")
    domain_prefix = _ensure_domain(cog, pool_id, args.domain_prefix)

    # IdP 必须先建：client 的 SupportedIdentityProviders 要引用它的名字，
    # 且生产 client 不放 COGNITO（spec §3.5）——顺序颠倒会因 provider
    # 不存在而 InvalidParameterException。
    idp_name = None
    if cfg.has_section("IdP") and cfg["IdP"].get("provider_name"):
        print("③ OIDC IdP 联邦")
        idp = dict(cfg["IdP"])
        _ensure_oidc_idp(cog, pool_id, idp)
        idp_name = idp["provider_name"]
    else:
        print("③ 跳过 IdP 联邦（config.ini 无 [IdP] 段）")
        print("   ⚠️  未接企业 IdP：**新建**的 site/mcp client 只能用 COGNITO 本地用户。")
        print("      此状态下 allowed_users=\"org\" 不代表\"全组织\"——")
        print("      接上 IdP 后重跑本脚本，client 会切成仅该 IdP。")
        # 已存在的 client 不受影响：④ 会保留线上现有的 provider 名单
        # （缺配置 ≠ 删联邦，见 _ensure_clients 的 docstring）。
        print("      已存在的 client 保持线上现有 IdP 名单不变（见 ④ 的输出）。")

    # ④a 组件门禁（spec §5.1.1）：没配 [ApiKey] 段 = 平台只允许 OAuth 一条路径，
    # 此时**不建** resource server、也不建 machine client。这是"API Key 是可选
    # 组件"的 pool 侧实现——建了它们，deploy_agentcore 那边的 allowedClients
    # 门禁就还有东西可放行了。
    machine_scopes = ()
    if api_key_enabled(cfg):
        print("④a resource server + custom scope（API Key 组件已启用）")
        scope = ensure_resource_server(cog, pool_id,
                                       identifier=resource_server_id(cfg),
                                       scope=scope_name(cfg))
        # 建出来的 scope 必须与 key-proxy 换 token 时请求的那一串逐字符相同
        # （machine_scope 是那个拼接的唯一实现）。不等就说明两处读配置的方式漂了
        # ——那时的症状是换 token 报 invalid_scope，而文案指向 client 配置。
        if scope != machine_scope(cfg):
            raise SystemExit(
                f"scope 拼接不一致：本脚本建的是 {scope!r}，而 key-proxy 会请求 "
                f"{machine_scope(cfg)!r}——两处必须同源（api_key_config）")
        machine_scopes = (scope,)
    else:
        print("④a 跳过 resource server / machine client"
              "（config.ini 无 [ApiKey] 段 = OAuth-only，spec §5.1.1 组件门禁）")

    print("④ app clients")
    clients = _ensure_clients(cog, pool_id, base_domain, args.mcp_callback,
                              idp_name, include_machine=bool(machine_scopes),
                              machine_scopes=machine_scopes)

    print("⑤ 边界复验：client 不得开原生认证 flow")
    _verify_no_native_flows(cog, pool_id, clients)

    print("⑥ managed login branding（API 建的 client 必须显式套）")
    _ensure_branding(cog, pool_id, clients)

    print("⑦ pre-token 触发器（注入 email + idp/auth_via claim）")
    sys.path.insert(0, str(HERE.parent / "auth"))
    import deploy_auth
    role_arn = deploy_auth.ensure_lambda_role()
    # 非生产 pool 用独立函数名：生产 pool 正在调用 site-auth-pre-token，而
    # ensure_pre_token_trigger 对已存在的函数走 update_function_code——沿用
    # 默认名会把 spike 的代码推到生产在用的函数上，静默改掉线上 token 形态。
    fn_name = ("site-auth-pre-token" if args.pool_name == POOL_NAME
               else f"site-auth-pre-token-spike-{args.pool_name}"[:64])
    if fn_name != "site-auth-pre-token":
        print(f"   （隔离 pool：触发器部署为 {fn_name}，不动生产函数）")
    deploy_auth.ensure_pre_token_trigger(role_arn, pool_id=pool_id,
                                        fn_name=fn_name)

    print("⑧ client secret → SSM")
    # 非生产 pool 走独立参数前缀，避免覆盖 auth 服务在用的生产 secret
    prefix = ("/site-builder" if args.pool_name == POOL_NAME
              else f"/site-builder-spike/{args.pool_name}")
    if prefix != "/site-builder":
        print(f"   （隔离 pool：secret 写入 {prefix}，不动生产参数）")
    _store_client_secrets(cog, pool_id, clients, region, prefix)

    print("\n回填 site-builder/config.ini：")
    print(f"  [Cognito] user_pool_id = {pool_id}")
    print(f"  [Cognito] domain = https://{domain_prefix}.auth.{region}.amazoncognito.com")
    print(f"  [Cognito] site_client_id = {clients['site']}")
    print(f"  [Cognito] mcp_client_id = {clients['mcp']}")
    if "machine" in clients:
        print(f"  [Cognito] machine_client_id = {clients['machine']}")
        print("  ⚠️  回填后必须重跑 deploy_agentcore.py：machine client 要同时进"
              "网关的 allowedClients 与容器的 MACHINE_CLIENT_ID，"
              "否则 Key 调用会以「网关放行、容器拒绝」的形态失败。")
    else:
        print("  [Cognito] machine_client_id = （无 [ApiKey] 段：OAuth-only，"
              "不需要）")
    if idp_name:
        print(f"\n在 IdP（{idp_name}）侧把这个回调加进白名单：")
        print(f"  https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse")


if __name__ == "__main__":
    main()
