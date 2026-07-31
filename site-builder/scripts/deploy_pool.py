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
import sys
from pathlib import Path

HERE = Path(__file__).parent

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
        "LogoutURLs": [f"https://auth.{base_domain}/logout"],
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
            # 不开任何原生认证 flow（与 site/mcp 同一条边界）
            "ExplicitAuthFlows": [],
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


# update_user_pool 是整体替换语义（一期实测坑）：只回传已知可变字段，
# 避免误清其他配置。与 deploy_auth.py 的 _POOL_MUTABLE 同源。
_POOL_MUTABLE = ("Policies", "DeletionProtection", "AutoVerifiedAttributes",
                 "MfaConfiguration", "EmailConfiguration", "AdminCreateUserConfig",
                 "AccountRecoverySetting", "UserAttributeUpdateSettings",
                 "VerificationMessageTemplate", "UserPoolTier", "LambdaConfig")


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
    kwargs = {k: pool[k] for k in _POOL_MUTABLE if k in pool}
    # describe 回传的废弃字段，与 PasswordPolicy.TemporaryPasswordValidityDays
    # 同传会被 update-user-pool 拒绝（一期实测）
    kwargs.get("AdminCreateUserConfig", {}).pop("UnusedAccountValidityDays", None)
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


def _ensure_clients(cog, pool_id: str, base_domain: str,
                    extra_mcp_callbacks: list[str],
                    idp_name: str | None = None) -> dict:
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

    out = {}
    for key, params in client_configs(base_domain, extra_mcp_callbacks,
                                      idp_name).items():
        _assert_no_native_flows(key, params)
        name = params["ClientName"]
        if name in existing:
            client_id = existing[name]
            update = {k: v for k, v in params.items() if k != "GenerateSecret"}
            cog.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id,
                                        **update)
            print(f"  更新 client {name} = {client_id}")
        else:
            client_id = cog.create_user_pool_client(
                UserPoolId=pool_id, **params)["UserPoolClient"]["ClientId"]
            print(f"  新建 client {name} = {client_id}")
        out[key] = client_id
    return out


def _assert_no_native_flows(key: str, params: dict) -> None:
    """边界自检：client 参数里不得出现任何原生认证 flow（spec §3.5 第 4 条）。

    放在下发之前——配置漂移（有人为了调试加回 USER_PASSWORD_AUTH）会让
    allowed_users="org" 的边界失效，而 claim 校验拦不住"原生认证 → refresh
    洗白"这条路径。
    """
    flows = set(params.get("ExplicitAuthFlows") or [])
    bad = flows & set(NATIVE_AUTH_FLOWS)
    if bad:
        raise SystemExit(
            f"client {key} 开了原生认证 flow {sorted(bad)}——这会打破 org 边界"
            "（spec §3.5 第 4 条）。要支持原生登录必须先重新设计该边界。")


def _verify_no_native_flows(cog, pool_id: str, clients: dict) -> None:
    """下发后读回复验：update_user_pool_client 是整体替换，漏传即被清空/改写。"""
    for key, client_id in clients.items():
        desc = cog.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
        flows = set(desc.get("ExplicitAuthFlows") or [])
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
    """联邦一个 OIDC IdP。飞书适配器与标准 IdP（Okta 等）走同一条路径。"""
    name = idp["provider_name"]
    details = {
        "client_id": idp["client_id"],
        "client_secret": idp["client_secret"],
        "attributes_request_method": "GET",
        "oidc_issuer": idp["issuer"],
        "authorize_scopes": idp.get("scopes", "openid email profile"),
    }
    mapping = {"email": "email", "name": "name"}
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
    for key, param in (("site", f"{param_prefix}/site-client-secret"),):
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
        print("   ⚠️  未接企业 IdP：site/mcp client 暂时只能用 COGNITO 本地用户。")
        print("      此状态下 allowed_users=\"org\" 不代表\"全组织\"——")
        print("      接上 IdP 后重跑本脚本，client 会切成仅该 IdP。")

    print("④ app clients")
    clients = _ensure_clients(cog, pool_id, base_domain, args.mcp_callback, idp_name)

    print("⑤ 边界复验：client 不得开原生认证 flow")
    _verify_no_native_flows(cog, pool_id, clients)

    print("⑥ managed login branding（API 建的 client 必须显式套）")
    _ensure_branding(cog, pool_id, clients)

    print("⑦ pre-token 触发器（注入 email + idp/auth_via claim）")
    sys.path.insert(0, str(HERE.parent / "auth"))
    import deploy_auth
    role_arn = deploy_auth.ensure_lambda_role()
    deploy_auth.ensure_pre_token_trigger(role_arn, pool_id=pool_id)

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
    print("  [Cognito] machine_client_id = （M4 建 resource server 时再填）")
    if idp_name:
        print(f"\n在 IdP（{idp_name}）侧把这个回调加进白名单：")
        print(f"  https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse")


if __name__ == "__main__":
    main()
