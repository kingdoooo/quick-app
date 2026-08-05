"""平台专用 user pool 的配置生成（纯逻辑，不连 AWS）。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

import deploy_pool as dp


@pytest.fixture(autouse=True)
def _no_real_credentials(monkeypatch):
    """把凭证钉成假值：**改变漏出调用的失败模式，不是网络屏障**。

    实测教训（2026-07-31）：本文件早期版本里 `_store_client_secrets` 的测试
    只 stub 了测试自己建的 ssm client，而实现内部另建一个 client——Stubber
    拦不住，那次 put_parameter **真的写进了开发者当前凭证的账号**。

    这个 fixture 的真实效力边界，别当成更强的东西：
    - 泄漏的调用**仍会发出网络请求**，只是以鉴权失败告终，而不是改动真实资源。
    - 若 `boto3.DEFAULT_SESSION` 已缓存过凭证，本 pin 对之后新建的 client
      **完全无效**（本仓库当前无此路径：没有测试在 moto 之外用默认 session）。

    真正的防线是把 client 做成可注入的参数（见 `_store_client_secrets` 的
    `ssm=` 参数），让 Stubber 能确实拦住它。
    """
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def test_pool_config_requires_essentials_tier():
    # pre-token V2（access token 定制）要求 Essentials+
    assert dp.pool_config("example.com")["UserPoolTier"] == "ESSENTIALS"


def test_pool_config_has_email_attribute():
    cfg = dp.pool_config("example.com")
    assert "email" in cfg["AutoVerifiedAttributes"]


def test_spike_pool_secrets_go_to_isolated_ssm_prefix():
    """隔离 spike 不能覆盖生产的 site client secret。

    `_store_client_secrets` 默认写 /site-builder/site-client-secret —— auth
    服务运行时就读这个。若 --pool-name 指向临时 pool 时仍写同一个参数名，
    临时 client 的 secret 会顶掉生产的，线上换 token 立刻失败，而 Cognito
    侧完全看不出异常（比误改 client 更难查）。

    注：ssm client 必须显式注入。boto3.client() 每次返回新对象，Stubber
    只能拦住传进去的那一个——实现内部自建 client 时会直接打到真实账号
    （实测踩过，见 _no_real_credentials）。
    """
    import boto3
    from botocore.stub import Stubber

    # ClientSecret 的 service model 约束是 min 24 / max 64 / [\w+]+ —— Stubber
    # 连**响应**也按 shape 校验，短假值（如 "s3cret"）会以
    # ParamValidationError 失败，看起来像实现的错。用 30 字符的假值。
    fake_secret = "FAKEclientsecretFAKEclientsec1"
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    ssm = boto3.client("ssm", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as cstub, Stubber(ssm) as sstub:
        cstub.add_response("describe_user_pool_client",
                           {"UserPoolClient": {"ClientSecret": fake_secret}},
                           {"UserPoolId": "us-east-1_spike", "ClientId": "c1"})
        # 关键断言：参数名带隔离前缀，不是 /site-builder/site-client-secret
        sstub.add_response("put_parameter", {},
                           {"Name": "/site-builder-spike/tmp-pool/site-client-secret",
                            "Value": fake_secret, "Type": "SecureString",
                            "Overwrite": True})
        dp._store_client_secrets(cog, "us-east-1_spike", {"site": "c1"},
                                 "us-east-1",
                                 "/site-builder-spike/tmp-pool", ssm=ssm)
        sstub.assert_no_pending_responses()


def test_default_pool_name_is_production_pool():
    """--pool-name 的默认值必须仍是生产 pool。

    该参数只为标准 IdP spike 的隔离而存在（Task 15 Step 7）：在生产 pool 上
    换 [IdP] 重跑会把飞书从生产 client 的 SupportedIdentityProviders 移除，
    线上登录立即中断。默认值漂了就等于每次部署都建新 pool。
    """
    assert dp.POOL_NAME == "site-builder-users"
    assert dp.pool_config("example.com")["PoolName"] == dp.POOL_NAME


def test_pool_config_disables_self_signup():
    """P0：允许自注册会让 allowed_users="org" 失去"组织"语义。

    Edge 对 org 的判定只是"持有有效平台会话"，不查邮箱域；若任何人能自注册，
    就等于所有 org 站点对整个互联网开放（spec §3.5）。
    """
    cfg = dp.pool_config("example.com")
    assert cfg["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True


def test_production_clients_exclude_local_cognito_users(idp_name="Okta"):
    """生产 client 不能放 COGNITO——否则托管登录仍暴露本地登录/注册入口。"""
    clients = dp.client_configs("example.com", [], idp_name=idp_name)
    for key in ("site", "mcp"):
        assert clients[key]["SupportedIdentityProviders"] == [idp_name]
        assert "COGNITO" not in clients[key]["SupportedIdentityProviders"]


def test_clients_fall_back_to_cognito_only_without_idp():
    """未配 IdP 时（首次部署、联邦还没接）允许 COGNITO，但脚本要显式告警。"""
    clients = dp.client_configs("example.com", [], idp_name=None)
    assert clients["site"]["SupportedIdentityProviders"] == ["COGNITO"]


def test_site_client_callback_is_auth_subdomain():
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    assert clients["site"]["CallbackURLs"] == ["https://auth.example.com/callback"]


def test_site_client_is_confidential():
    clients = dp.client_configs("example.com", [])
    assert clients["site"]["GenerateSecret"] is True


def test_site_client_flows():
    site = dp.client_configs("example.com", [], idp_name="Okta")["site"]
    assert site["AllowedOAuthFlows"] == ["code"]
    assert set(site["AllowedOAuthScopes"]) == {"openid", "email", "profile"}


def test_mcp_client_includes_localhost_callback():
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    # 18765：8765/8766 被 Quick Desktop 常驻占用（一期实测）
    assert "http://localhost:18765/callback" in clients["mcp"]["CallbackURLs"]


def test_mcp_client_accepts_extra_callbacks():
    clients = dp.client_configs("example.com",
                                ["https://agentcore.example/identities/cb"],
                                idp_name="Okta")
    assert "https://agentcore.example/identities/cb" in clients["mcp"]["CallbackURLs"]


def test_mcp_client_is_public():
    # MCP 客户端（Claude Code 等）无法安全保存 secret
    assert dp.client_configs("example.com", [], idp_name="Okta")["mcp"]["GenerateSecret"] is False


def test_machine_client_not_created_in_m1():
    """M1 不建 machine client：client_credentials 只能授 resource server 的
    custom scope，空 scope 会被 Cognito 跨字段校验拒绝——脚本会在建 client
    这一步中止，后面的 branding / pre-token 触发器都跑不到。M4 再建。"""
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    assert set(clients) == {"site", "mcp"}


def test_machine_client_requires_scopes_when_requested():
    with pytest.raises(ValueError, match="scope"):
        dp.client_configs("example.com", [], idp_name="Okta",
                          include_machine=True, machine_scopes=())


def test_machine_client_with_scopes_is_client_credentials_only():
    machine = dp.client_configs(
        "example.com", [], idp_name="Okta", include_machine=True,
        machine_scopes=("site-builder/deploy",))["machine"]
    assert machine["AllowedOAuthFlows"] == ["client_credentials"]
    assert machine["AllowedOAuthScopes"] == ["site-builder/deploy"]
    assert machine["GenerateSecret"] is True
    assert machine["CallbackURLs"] == []
    assert machine["ExplicitAuthFlows"] == []


@pytest.mark.parametrize("key", ["site", "mcp"])
def test_clients_disable_all_native_auth_flows(key):
    """spec §3.5 第 4 条：这是 org 边界本体。

    只要开了任一原生 flow，linked 用户 / 设过密码的联邦用户就能原生登录，
    再用 refresh 刷一次就把 auth_via 洗成可信值——claim 校验拦不住那条路。
    """
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    flows = set(clients[key]["ExplicitAuthFlows"])
    assert flows == {"ALLOW_REFRESH_TOKEN_AUTH"}
    assert not (flows & set(dp.NATIVE_AUTH_FLOWS))


@pytest.mark.parametrize("key", ["site", "mcp"])
def test_refresh_token_validity_is_capped(key):
    """默认 30 天太长：原生 flow 若曾被误开，已签发的 refresh token 在有效期内
    仍能换出 auth_via=RefreshTokens 的可信 token，关配置也拦不住。"""
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    assert clients[key]["RefreshTokenValidity"] == 1
    assert clients[key]["TokenValidityUnits"]["RefreshToken"] == "days"


@pytest.mark.parametrize("key", ["site", "mcp"])
def test_access_token_validity_is_capped(key):
    """access token 也必须显式收（默认 60 分钟）。

    吊销 refresh token **不会**让已经换出去的 access token 立即失效：AWS 对
    AdminUserGlobalSignOut 明说"Other requests might be valid until your
    user's token expires"，且被吊销的 token 对"只验签名与过期时间的 JWT 库"
    仍然有效——AgentCore 的 inbound authorizer 就是这种。所以漂移/泄露后的
    真实暴露窗口 = refresh 有效期 + access 有效期，两个都要收。
    """
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    assert clients[key]["AccessTokenValidity"] == 15
    assert clients[key]["IdTokenValidity"] == 15
    units = clients[key]["TokenValidityUnits"]
    assert units["AccessToken"] == "minutes"
    assert units["IdToken"] == "minutes"


def test_assert_no_native_flows_rejects_drift():
    with pytest.raises(SystemExit, match="原生认证"):
        dp._assert_no_native_flows("site", {
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH",
                                  "ALLOW_USER_PASSWORD_AUTH"]})


def test_native_auth_flows_covers_entire_enum_except_refresh():
    """denylist 必须等于 ExplicitAuthFlows 枚举减去 refresh——按真实 service
    model 比对，而不是照着记忆列。

    漏项的后果不是"少拦一种"，而是两道闸门一起瞎掉：漏掉的值既过
    _assert_no_native_flows 也过 _verify_no_native_flows，而它开的是真的原生认证。
    botocore 1.43.53 实测该枚举有 9 个值，legacy 三个（ADMIN_NO_SRP_AUTH /
    CUSTOM_AUTH_FLOW_ONLY / USER_PASSWORD_AUTH）没有 ALLOW_ 前缀，最易漏。
    """
    import botocore.session
    model = botocore.session.get_session().get_service_model("cognito-idp")
    enum = set(model.operation_model("CreateUserPoolClient").input_shape
               .members["ExplicitAuthFlows"].member.enum)
    assert enum - {"ALLOW_REFRESH_TOKEN_AUTH"} == set(dp.NATIVE_AUTH_FLOWS)


@pytest.mark.parametrize("legacy", ["ADMIN_NO_SRP_AUTH", "CUSTOM_AUTH_FLOW_ONLY",
                                    "USER_PASSWORD_AUTH"])
def test_assert_rejects_legacy_native_flow_values(legacy):
    """legacy 值（无 ALLOW_ 前缀）同样开原生认证，必须被拦。

    注意 USER_PASSWORD_AUTH 与 ALLOW_USER_PASSWORD_AUTH 是枚举里两个不同的值。
    """
    with pytest.raises(SystemExit, match="原生认证"):
        dp._assert_no_native_flows("site", {"ExplicitAuthFlows": [legacy]})


def test_each_client_gets_its_own_provider_list():
    """两个 client 不能共享同一个 SupportedIdentityProviders 对象。

    共享时任何一处 append 会静默改掉另一个 client 的 provider 名单——而这正是
    org 边界字段（实测：往 site 的名单 append "COGNITO"，mcp 的也变成
    [Okta, COGNITO]）。M4 传 include_machine=True 做 per-client 调整时最可能踩到。
    """
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    site_p = clients["site"]["SupportedIdentityProviders"]
    mcp_p = clients["mcp"]["SupportedIdentityProviders"]
    assert site_p == mcp_p == ["Okta"]
    assert site_p is not mcp_p
    site_p.append("COGNITO")                      # 污染其中一个
    assert mcp_p == ["Okta"]                      # 另一个必须毫发无损


def test_verify_no_native_flows_reads_back_from_aws():
    """下发后必须读回复验：update 是整体替换，漂移只能靠 describe 发现。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ExplicitAuthFlows":
                                              ["ALLOW_USER_PASSWORD_AUTH"]}},
                          {"UserPoolId": "us-east-1_test", "ClientId": "c1"})
        with pytest.raises(SystemExit, match="org 边界失效"):
            dp._verify_no_native_flows(cog, "us-east-1_test", {"site": "c1"})


def test_client_configs_have_no_managed_login_version():
    """ManagedLoginVersion 属于 domain API，混进 client 参数会 ParamValidationError。

    断言 dict 不够——必须让 botocore 真正校验参数名（见下一个测试）。
    """
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    for key in ("site", "mcp"):
        assert "ManagedLoginVersion" not in clients[key]


def test_client_configs_pass_botocore_param_validation():
    """用 Stubber 让 botocore 按真实 service model 校验参数名与类型。

    纯 dict 断言抓不到"参数放错 API"这类错误——本计划上一版就把
    ManagedLoginVersion 放进了 client 参数，dict 测试全绿，真实调用必失败。
    """
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    with Stubber(cog) as stub:
        for key in ("site", "mcp"):
            params = {"UserPoolId": "us-east-1_test", **clients[key]}
            stub.add_response("create_user_pool_client",
                              {"UserPoolClient": {"ClientId": "c"}}, params)
            cog.create_user_pool_client(**params)   # 参数非法会在此抛


def test_domain_creation_requests_managed_login_v2():
    """domain 必须显式带 ManagedLoginVersion=2，否则默认 classic hosted UI。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {}},
                          {"UserPoolId": "us-east-1_test"})
        stub.add_response("create_user_pool_domain", {},
                          {"Domain": "pfx", "UserPoolId": "us-east-1_test",
                           "ManagedLoginVersion": 2})
        assert dp._ensure_domain(cog, "us-east-1_test", "pfx") == "pfx"


def test_existing_domain_with_v1_is_upgraded():
    """已存在但停在 v1 的 domain 要被纠正——幂等重跑得能修配错的资源。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {"Domain": "old"}},
                          {"UserPoolId": "us-east-1_test"})
        stub.add_response("describe_user_pool_domain",
                          {"DomainDescription": {"ManagedLoginVersion": 1}},
                          {"Domain": "old"})
        stub.add_response("update_user_pool_domain", {},
                          {"Domain": "old", "UserPoolId": "us-east-1_test",
                           "ManagedLoginVersion": 2})
        assert dp._ensure_domain(cog, "us-east-1_test", "pfx") == "old"


# --- 幂等重跑不得重置线上配置（Codex review P2） ---
# UpdateUserPoolClient 是整体替换语义：官方明示未提供的参数会被设回默认值。
# 只发脚本声明的字段会把运营/安全加固静默打回默认，其中
# PreventUserExistenceErrors 经 API 的默认是 LEGACY（关闭）——控制台默认却是
# ENABLED，所以"控制台开了、脚本重跑关掉"是完全现实的路径。

def _client_stub_response(**overrides) -> dict:
    """describe_user_pool_client 的线上现状（含脚本不管的加固项）。"""
    base = {
        "UserPoolId": "us-east-1_x", "ClientId": "c1",
        "ClientName": "site-builder-site",
        "PreventUserExistenceErrors": "ENABLED",
        "EnableTokenRevocation": True,
        "ReadAttributes": ["email", "name"],
        "WriteAttributes": ["email", "name"],
        "AllowedOAuthFlows": ["code"],
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
    }
    base.update(overrides)
    return base


def test_client_update_preserves_unmanaged_hardening():
    """脚本不声明的加固项必须原样回填，不能被重置为默认值。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": _client_stub_response()},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        desired = dp.client_configs("example.com", [], "Okta")["site"]
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)

    # 线上加固项被保留
    assert merged["PreventUserExistenceErrors"] == "ENABLED"
    assert merged["EnableTokenRevocation"] is True
    assert merged["ReadAttributes"] == ["email", "name"]
    # 脚本声明的字段仍然生效（本脚本管的就是这些）
    assert merged["SupportedIdentityProviders"] == ["Okta"]
    assert merged["ExplicitAuthFlows"] == dp.NATIVE_AUTH_DISABLED
    assert merged["AccessTokenValidity"] == 15


def test_client_update_params_strip_create_only_keys():
    """ClientId/ClientSecret/GenerateSecret 等不能进 update 请求。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": _client_stub_response(
                              ClientSecret="FAKEclientsecretFAKEclientsec1")},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        desired = dp.client_configs("example.com", [], "Okta")["site"]
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)

    for k in ("ClientId", "ClientSecret", "GenerateSecret", "UserPoolId",
              "CreationDate", "LastModifiedDate"):
        assert k not in merged, f"{k} 不能出现在 update 请求里"


def test_client_update_request_passes_service_model_validation():
    """合并结果必须能通过 botocore 的 UpdateUserPoolClient 参数校验。

    Stubber 按真实 service model 校验请求参数——回填一个 update 不接受的键
    （比如 ClientSecret）会在这里以 ParamValidationError 失败，而不是等到真机。
    """
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    desired = dp.client_configs("example.com", [], "Okta")["site"]
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": _client_stub_response()},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)
        stub.add_response("update_user_pool_client", {"UserPoolClient": {}},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1",
                           **merged})
        cog.update_user_pool_client(UserPoolId="us-east-1_x", ClientId="c1",
                                    **merged)
        stub.assert_no_pending_responses()


# --- 联邦 email 的可信度（Codex review P1） ---
# 授权主键是 email，而联邦映射进 Cognito 的 email 默认 unverified。
# 官方：源 claim 不存在时映射是 no-op（不会导致登录失败），所以默认就映射上。

def _idp(**over):
    base = {"provider_name": "Okta", "client_id": "cid",
            "client_secret": "csec", "issuer": "https://idp.example.com"}
    base.update(over)
    return base


def _captured_mapping(idp: dict) -> dict:
    """跑 _ensure_oidc_idp 的 create 分支，抓它下发的 AttributeMapping。"""
    seen = {}

    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_identity_provider(self, **kw):
            raise self.exceptions.ResourceNotFoundException()

        def create_identity_provider(self, **kw):
            seen.update(kw)

        def update_identity_provider(self, **kw):
            seen.update(kw)

    dp._ensure_oidc_idp(_Cog(), "us-east-1_x", idp)
    return seen["AttributeMapping"]


def test_idp_maps_email_verified_by_default():
    """不映射 email_verified 时，联邦 email 恒为 unverified——
    允许自设邮箱的 IdP 上等于可冒充任意 owner/collaborator。"""
    mapping = _captured_mapping(_idp())
    assert mapping["email_verified"] == "email_verified"
    assert mapping["email"] == "email"


def test_idp_email_verified_mapping_can_be_disabled():
    """IdP 确实不提供该 claim 时可显式关掉（映射本身是 no-op，但允许留白）。"""
    mapping = _captured_mapping(_idp(map_email_verified="false"))
    assert "email_verified" not in mapping


def test_idp_mapping_applies_on_update_path_too():
    """已存在的 IdP 走 update 分支——映射不能只在新建时加上。"""
    seen = {}

    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_identity_provider(self, **kw):
            return {"IdentityProvider": {}}

        def update_identity_provider(self, **kw):
            seen.update(kw)

    dp._ensure_oidc_idp(_Cog(), "us-east-1_x", _idp())
    assert seen["AttributeMapping"]["email_verified"] == "email_verified"


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("True", True), ("yes", True), ("1", True), ("on", True),
    ("false", False), ("no", False), ("", False), ("maybe", False),
    # configparser 保留行内注释——切掉后仍要判对（router/stack.py 同款坑）
    ("true   # 默认开", True), ("false  ; 关掉", False),
])
def test_truthy_parsing(raw, expected):
    assert dp._truthy(raw) is expected
