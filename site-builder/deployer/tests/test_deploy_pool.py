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


def test_spike_pool_does_not_overwrite_production_pre_token_lambda():
    """隔离 spike 不能改动生产在用的 pre-token 函数。

    `ensure_pre_token_trigger` 里函数名硬编码为 `site-auth-pre-token`，且对
    已存在的函数走 `update_function_code`。--pool-name 指向临时 pool 时若仍
    用这个名字，spike 会把新版代码推到**生产 pool 正在调用的同一个函数上**：
    实测线上那版只往 access token 注入 email，新版往 id/access 两个容器注入
    email/email_verified/idp/auth_via 四个 claim——等于在只想"试一下登录体验"
    的时候改掉了生产的 token 形态，而 Cognito 侧毫无异常显示。

    与 SSM 前缀隔离（见上一个测试）是同一类漏项：凡是 spike 与生产共享的
    命名，都必须随 pool_name 一起隔离。
    """
    sys.path.insert(0, str(Path(__file__).parents[2] / "auth"))
    import deploy_auth

    import inspect
    src = inspect.getsource(deploy_auth.ensure_pre_token_trigger)
    assert "fn_name" in src or "function_name" in src, \
        "函数名必须可参数化，否则 spike 会覆盖生产在用的 Lambda 代码"
    sig = inspect.signature(deploy_auth.ensure_pre_token_trigger)
    assert "fn_name" in sig.parameters, "需要显式的函数名参数供 spike 传隔离值"
    assert sig.parameters["fn_name"].default == "site-auth-pre-token", \
        "默认值必须仍是生产函数名"
    # deploy_pool 侧：非生产 pool 必须传隔离后的函数名
    dp_src = inspect.getsource(dp.main)
    assert "fn_name=" in dp_src, "deploy_pool 必须按 pool 传隔离的函数名"


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
    assert machine["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]


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


# --- 托管域名前缀撞车：AWS 原文误导，必须翻译（工单 14 实测） ---
# 前缀是**跨全部 AWS 账号**的全局命名空间，而出厂默认值被参考部署占着 ⇒ 每个采用者
# 裸跑 deploy_pool.py 都会撞上。AWS 的原文 "Domain already associated with another
# user pool" 读起来像"**你自己的**池已经有域名了"（那条其实走 existing 分支、到不了
# 这里），于是操作者会去查自己的池而不是换前缀。本账号看不见别人的池 ⇒
# _pool_id_for_domain 的 preflight 结构上查不出这一条，只能在写失败时翻译。


class _FakeDomainTaken:
    """describe_user_pool 说"池还没有域名"，create_user_pool_domain 抛前缀撞车。"""

    class exceptions:
        class InvalidParameterException(Exception):
            pass

    def __init__(self, message):
        self._message = message

    def describe_user_pool(self, **_):
        return {"UserPool": {}}

    def create_user_pool_domain(self, **_):
        raise self.exceptions.InvalidParameterException(self._message)


_AWS_TAKEN_MESSAGE = (
    "An error occurred (InvalidParameterException) when calling the "
    "CreateUserPoolDomain operation: Domain already associated with another user pool.")


def test_domain_prefix_taken_by_another_account_is_translated():
    """撞车必须变成 SystemExit，且文案要点出"全局命名空间 / 别的账号 / 换前缀重跑"。"""
    cog = _FakeDomainTaken(_AWS_TAKEN_MESSAGE)
    with pytest.raises(SystemExit) as ei:
        dp._ensure_domain(cog, "us-east-1_test", "acme-auth")
    msg = str(ei.value)
    assert "acme-auth" in msg
    assert "全局命名空间" in msg, msg
    assert "别的账号" in msg, msg
    # 可行动的那半句：池已经建好了，换前缀重跑即可（幂等），不需要清理
    assert "重跑" in msg, msg
    assert "us-east-1_test" in msg, msg


def test_domain_prefix_taken_names_the_shipped_default():
    """撞的是出厂默认值时要额外点名它——那是"每个采用者必然踩一次"的那条。"""
    cog = _FakeDomainTaken(_AWS_TAKEN_MESSAGE)
    with pytest.raises(SystemExit) as ei:
        dp._ensure_domain(cog, "us-east-1_test", dp.DEFAULT_DOMAIN_PREFIX)
    assert "出厂默认值" in str(ei.value), str(ei.value)
    # 反面：换了前缀就不该再提默认值那句，否则文案在正常撞车时是噪音
    cog2 = _FakeDomainTaken(_AWS_TAKEN_MESSAGE)
    with pytest.raises(SystemExit) as ei2:
        dp._ensure_domain(cog2, "us-east-1_test", "acme-auth")
    assert "出厂默认值" not in str(ei2.value), str(ei2.value)


def test_default_domain_prefix_matches_argparse_default():
    """`DEFAULT_DOMAIN_PREFIX` 是钉住的字面量。它与 `--domain-prefix` 的 default 一漂移，
    上面那条"点名出厂默认值"的文案就会挂在错误的前缀上（或永不触发）。"""
    import pathlib
    import re as _re

    src = pathlib.Path(dp.__file__).read_text(encoding="utf-8")
    m = _re.search(r'"--domain-prefix",\s*default="([^"]+)"', src)
    assert m, "找不到 --domain-prefix 的 default（argparse 那行改过了？）"
    assert m.group(1) == dp.DEFAULT_DOMAIN_PREFIX, (
        f"argparse default={m.group(1)!r} 与 DEFAULT_DOMAIN_PREFIX="
        f"{dp.DEFAULT_DOMAIN_PREFIX!r} 漂移了")


def test_unrelated_invalid_parameter_still_propagates():
    """正面对照（mutation guard）：不是撞车的 InvalidParameterException 必须原样抛出，
    否则这段翻译会把任意配置错误都伪装成"换个前缀就好"。"""
    cog = _FakeDomainTaken("InvalidParameterException: 1 validation error detected: "
                           "Value at 'domain' failed to satisfy constraint")
    with pytest.raises(_FakeDomainTaken.exceptions.InvalidParameterException):
        dp._ensure_domain(cog, "us-east-1_test", "Bad_Prefix")


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
    # 线上原有属性保留，但必须并上 IdP 映射目标（见下面 email_verified 的用例）
    assert set(merged["ReadAttributes"]) >= {"email", "name"}
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
    # ClientName 反而**必须**回填：update 接受它，漏传按契约会恢复默认值
    assert merged["ClientName"] == "site-builder-site"
    # 动态求差必须真的覆盖 service model 的全部 describe-only 字段
    assert not (dp._client_describe_only_keys(cog) & set(merged))


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


def _captured_idp_call(idp: dict, *, mode: str = dp.IDP_MODE_EXTERNAL) -> dict:
    """跑 _ensure_oidc_idp 的 create 分支，抓它下发的**全部**参数。

    工单 07 让这个函数变成模式感知的（secret 的来源随模式不同），所以既要能看
    AttributeMapping 也要能看 ProviderDetails —— 两处各写一份 Stubber 样板就是
    第二份真源，所以 `_captured_mapping` 改成薄封装。
    """
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

    dp._ensure_oidc_idp(_Cog(), "us-east-1_x", idp, mode=mode)
    return seen


def _captured_mapping(idp: dict) -> dict:
    """跑 _ensure_oidc_idp 的 create 分支，抓它下发的 AttributeMapping。"""
    return _captured_idp_call(idp)["AttributeMapping"]


def test_idp_client_secret_can_come_from_env(monkeypatch):
    """IdP client_secret 必须能从环境变量注入，不必写进 config.ini。

    config.ini 虽然 gitignored，但把联邦 secret 落成磁盘明文仍是不必要的暴露
    面（会进备份、编辑器缓存、误 cat 的终端回滚）。有了这条通道就能用
    `asm-exec -- env SB_IDP_CLIENT_SECRET={{resolve:secretsmanager:…}} \
     python3 deploy_pool.py` 让明文只存在于子进程。
    环境变量优先于 config 值：两者都在时以显式注入的为准。
    """
    seen = {}

    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_identity_provider(self, **kw):
            raise self.exceptions.ResourceNotFoundException()

        def create_identity_provider(self, **kw):
            seen.update(kw)

    monkeypatch.setenv("SB_IDP_CLIENT_SECRET", "from-env-secret")
    dp._ensure_oidc_idp(_Cog(), "us-east-1_x", _idp(client_secret=""))
    assert seen["ProviderDetails"]["client_secret"] == "from-env-secret"


def test_idp_missing_client_secret_fails_loudly():
    """config 与环境变量都没有 secret 时必须明确报错。

    Cognito 对空 client_secret 的 OIDC provider 会在**用户登录时**才失败
    （换 token 阶段 invalid_client），那时症状是"登录页正常、回调报错"，
    比部署时报错难查得多。
    """
    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_identity_provider(self, **kw):
            raise self.exceptions.ResourceNotFoundException()

        def create_identity_provider(self, **kw):
            raise AssertionError("空 secret 不该走到建 IdP")

    with pytest.raises(SystemExit, match="client_secret"):
        dp._ensure_oidc_idp(_Cog(), "us-east-1_x", _idp(client_secret=""))


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


# --- Read/WriteAttributes 必须覆盖 IdP 映射目标（Codex re-review P1） ---
# 上一版只"保留线上值"，而线上值是 email_verified 映射之前配的：
# WriteAttributes 缺它 → 联邦登录写不进该属性；ReadAttributes 缺它而请求了
# email scope → token 端点 invalid_grant。两者都是"部署全绿、真机登录才失败"。

def test_merge_adds_idp_mapping_targets_to_attribute_permissions():
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": _client_stub_response(
                              ReadAttributes=["email", "name"],
                              WriteAttributes=["email", "name"])},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        desired = dp.client_configs("example.com", [], "Okta")["site"]
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)

    for field in ("ReadAttributes", "WriteAttributes"):
        assert "email_verified" in merged[field], field
        assert "email" in merged[field] and "name" in merged[field]


def test_merge_preserves_operator_added_custom_attributes():
    """并集而非替换：运营加的自定义属性不能被脚本抹掉。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": _client_stub_response(
                              ReadAttributes=["email", "custom:dept"],
                              WriteAttributes=["email", "custom:dept"])},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        desired = dp.client_configs("example.com", [], "Okta")["site"]
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)

    assert "custom:dept" in merged["ReadAttributes"]
    assert "email_verified" in merged["ReadAttributes"]


def test_merge_keeps_unset_attributes_unset():
    """未指定 = Cognito 允许全部标准属性。塞一份名单反而把"全部"收窄。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    current = _client_stub_response()
    current.pop("ReadAttributes", None)
    current.pop("WriteAttributes", None)
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": current},
                          {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        desired = dp.client_configs("example.com", [], "Okta")["site"]
        merged = dp._client_update_params(cog, "us-east-1_x", "c1", desired)

    assert "ReadAttributes" not in merged
    assert "WriteAttributes" not in merged


def test_required_attributes_cover_every_idp_mapping_target():
    """白名单必须覆盖 _ensure_oidc_idp 实际下发的全部映射目标。

    从实现抓 mapping，而不是手抄——将来加映射（如 given_name）时这里会红，
    而不是等真机登录失败。
    """
    mapping = _captured_mapping(_idp())
    targets = set(mapping)          # AttributeMapping 的键是 user pool 属性名
    assert targets <= dp._REQUIRED_CLIENT_ATTRIBUTES, (
        f"IdP 映射目标未进必需属性白名单: "
        f"{sorted(targets - dp._REQUIRED_CLIENT_ATTRIBUTES)}")


# --- update_user_pool 必须回填全部可保留字段（Codex re-review P1） ---
# 手抄可变字段白名单必然随 AWS 加字段而腐烂：实测旧名单漏了 10 项，
# 其中 UserPoolAddOns 是威胁防护、SmsConfiguration 是短信通道。

def _cog():
    import boto3
    return boto3.client("cognito-idp", region_name="us-east-1",
                        aws_access_key_id="t", aws_secret_access_key="t")


def test_pool_update_params_preserves_everything_updatable():
    """凡是 describe 返回且 update 接受的字段，都必须出现在回填结果里。"""
    cog = _cog()
    sm = cog.meta.service_model
    describe_members = set(sm.operation_model(
        "DescribeUserPool").output_shape.members["UserPool"].members)
    update_members = set(sm.operation_model(
        "UpdateUserPool").input_shape.members)
    preservable = describe_members & update_members

    # 构造一个"每个可保留字段都有值"的 describe 结果
    pool = {k: {} if k not in ("MfaConfiguration", "DeletionProtection")
            else "OFF" for k in preservable}
    pool.update({"Id": "us-east-1_x", "Name": "p", "Arn": "arn:x"})  # describe-only
    kwargs = dp.pool_update_params(cog, pool)

    assert set(kwargs) == preservable, (
        f"漏回填: {sorted(preservable - set(kwargs))}；"
        f"多回填: {sorted(set(kwargs) - preservable)}")


def test_pool_update_params_drops_describe_only_fields():
    """describe 独有字段回填即 ParamValidationError。"""
    cog = _cog()
    pool = {"Id": "us-east-1_x", "Name": "p", "Arn": "arn:x",
            "Status": "Enabled", "CreationDate": "d", "LastModifiedDate": "d",
            "SchemaAttributes": [], "EstimatedNumberOfUsers": 1,
            "MfaConfiguration": "OFF"}
    kwargs = dp.pool_update_params(cog, pool)
    for k in ("Id", "Name", "Arn", "Status", "SchemaAttributes",
              "EstimatedNumberOfUsers", "CreationDate", "LastModifiedDate"):
        assert k not in kwargs, k
    assert kwargs["MfaConfiguration"] == "OFF"


def test_pool_update_params_preserves_threat_protection_and_sms():
    """旧手抄名单漏掉的关键项：重跑不得关掉威胁防护/设备/短信配置。"""
    cog = _cog()
    pool = {"Id": "us-east-1_x",
            "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"},
            "DeviceConfiguration": {"ChallengeRequiredOnNewDevice": True},
            "SmsConfiguration": {"SnsCallerArn": "arn:sns"},
            "UserPoolTags": {"project": "site-builder"}}
    kwargs = dp.pool_update_params(cog, pool)
    assert kwargs["UserPoolAddOns"]["AdvancedSecurityMode"] == "ENFORCED"
    assert kwargs["DeviceConfiguration"]["ChallengeRequiredOnNewDevice"] is True
    assert kwargs["SmsConfiguration"]["SnsCallerArn"] == "arn:sns"
    assert kwargs["UserPoolTags"] == {"project": "site-builder"}


def test_pool_update_params_strips_deprecated_validity_field():
    """UnusedAccountValidityDays 与 TemporaryPasswordValidityDays 同传会被拒。"""
    cog = _cog()
    kwargs = dp.pool_update_params(cog, {
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True,
                                  "UnusedAccountValidityDays": 7}})
    assert "UnusedAccountValidityDays" not in kwargs["AdminCreateUserConfig"]
    assert kwargs["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True


def test_pool_update_params_result_passes_service_model_validation():
    """回填结果必须能通过 botocore 的 UpdateUserPool 参数校验。"""
    from botocore.stub import Stubber
    cog = _cog()
    pool = {"Id": "us-east-1_x", "MfaConfiguration": "OFF",
            "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"},
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            "UserPoolTags": {"project": "site-builder"}}
    kwargs = dp.pool_update_params(cog, pool)
    with Stubber(cog) as stub:
        stub.add_response("update_user_pool", {},
                          {"UserPoolId": "us-east-1_x", **kwargs})
        cog.update_user_pool(UserPoolId="us-east-1_x", **kwargs)
        stub.assert_no_pending_responses()


def test_deploy_auth_and_deploy_pool_share_one_implementation():
    """两边各留一份手抄名单正是这个坑的上一次形态——必须是同一实现。"""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parents[2] / "auth"))
    import deploy_auth
    src = (Path(__file__).parents[2] / "auth" / "deploy_auth.py").read_text()
    assert "_POOL_MUTABLE" not in src, "deploy_auth 仍留着手抄白名单"
    pool_src = (Path(__file__).parents[2] / "scripts" / "deploy_pool.py").read_text()
    assert "_POOL_MUTABLE" not in pool_src, "deploy_pool 仍留着手抄白名单"
    assert hasattr(deploy_auth, "pool_update_params")


def test_client_describe_only_keys_derived_not_hardcoded():
    """describe-only 字段按 service model 动态求差。

    硬编码"对 pinned 版本正确"的清单在本仓库不可复现——requirements 里
    boto3 不钉版本，换机器装到新版就可能多出字段。
    """
    cog = _cog()
    derived = dp._client_describe_only_keys(cog)
    # 当前 service model 的已知成员（回归锚点，不是实现来源）
    assert {"ClientSecret", "CreationDate", "LastModifiedDate"} <= derived
    # ClientName 被 update 接受，所以它**不属于** describe-only，
    # 也不该被业务规则跳过——必须原样回填
    assert "ClientName" not in derived
    assert "ClientName" not in dp._CLIENT_SKIP_KEYS


def test_client_name_is_backfilled_unchanged():
    """ClientName 必须回填当前值，且不会造成重命名。

    update_user_pool_client 接受 ClientName，AWS 契约是"未提供的属性恢复
    默认值"，所以跳过它没有依据。回填是安全的：查找该 client 用的就是这个
    名字，desired 与线上值相等。
    """
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

    assert merged["ClientName"] == desired["ClientName"]   # 未改名
    assert merged["ClientName"] == "site-builder-site"


# --- M4：resource server + machine client（组件门禁的 pool 侧）---
# 判定"有没有 [ApiKey] 段"的唯一实现在 deployer/functions/api_key_config.py，
# 本脚本只消费它（mcp/tests/test_component_gate.py 有 AST 守卫盯着这点）。


def _resource_server_cog():
    import boto3
    return boto3.client("cognito-idp", region_name="us-east-1",
                        aws_access_key_id="t", aws_secret_access_key="t")


def test_ensure_resource_server_creates_and_returns_full_scope():
    """新建路径：返回值必须是 `{identifier}/{scope}`（换 token 用的完整 scope）。"""
    from botocore.stub import Stubber
    cog = _resource_server_cog()
    with Stubber(cog) as stub:
        stub.add_client_error("describe_resource_server",
                              service_error_code="ResourceNotFoundException")
        stub.add_response("create_resource_server", {"ResourceServer": {}}, {
            "UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp",
            "Name": "site-builder-mcp",
            "Scopes": [{"ScopeName": "invoke",
                        "ScopeDescription": "Invoke the site-builder deploy MCP"}]})
        scope = dp.ensure_resource_server(cog, "us-east-1_x",
                                          identifier="site-builder-mcp",
                                          scope="invoke")
        assert scope == "site-builder-mcp/invoke"
        stub.assert_no_pending_responses()


def test_ensure_resource_server_is_idempotent_when_scope_present():
    """已有且 scope 齐全 → 不再 create/update（重跑不得白改线上资源）。"""
    from botocore.stub import Stubber
    cog = _resource_server_cog()
    with Stubber(cog) as stub:
        stub.add_response("describe_resource_server", {"ResourceServer": {
            "UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp",
            "Name": "site-builder-mcp",
            "Scopes": [{"ScopeName": "invoke", "ScopeDescription": "d"}]}},
            {"UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp"})
        assert dp.ensure_resource_server(
            cog, "us-east-1_x", identifier="site-builder-mcp",
            scope="invoke") == "site-builder-mcp/invoke"
        stub.assert_no_pending_responses()   # 多一次调用就会在这里红


def test_ensure_resource_server_adds_missing_scope_preserving_others():
    """UpdateResourceServer 是整体替换：补 scope 时必须把已有的 scope 回填。

    只发新 scope 会把别的 scope 从 resource server 上抹掉，而那些 scope 可能
    已经授给了别的 client——症状是那个 client 换 token 报 invalid_scope，
    与本次改动看不出关系（同 UpdateUserPoolClient 的整体替换教训）。
    """
    from botocore.stub import Stubber
    cog = _resource_server_cog()
    with Stubber(cog) as stub:
        stub.add_response("describe_resource_server", {"ResourceServer": {
            "UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp",
            "Name": "site-builder-mcp",
            "Scopes": [{"ScopeName": "legacy", "ScopeDescription": "别人在用"}]}},
            {"UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp"})
        stub.add_response("update_resource_server", {"ResourceServer": {}}, {
            "UserPoolId": "us-east-1_x", "Identifier": "site-builder-mcp",
            "Name": "site-builder-mcp",
            "Scopes": [{"ScopeName": "legacy", "ScopeDescription": "别人在用"},
                       {"ScopeName": "invoke",
                        "ScopeDescription": "Invoke the site-builder deploy MCP"}]})
        assert dp.ensure_resource_server(
            cog, "us-east-1_x", identifier="site-builder-mcp",
            scope="invoke") == "site-builder-mcp/invoke"
        stub.assert_no_pending_responses()


def test_machine_client_explicitly_disables_native_flows_not_empty_list():
    """machine client 的 ExplicitAuthFlows 必须是**显式的** ["ALLOW_REFRESH_TOKEN_AUTH"]。

    **这条用例取代了原先那条锁死"`[]` 必须放行"的用例**，因为它的前提被实测推翻了
    （工单 06）：Cognito 把空数组当成**未指定**，而未指定的默认值是
    ALLOW_REFRESH_TOKEN_AUTH + **ALLOW_USER_SRP_AUTH** + **ALLOW_CUSTOM_AUTH**。
    实测（对一个 ExplicitAuthFlows=[] 的 client 带正确 SECRET_HASH 调 InitiateAuth）：
    `USER_SRP_AUTH` **成功返回挑战**，`CUSTOM_AUTH` 只因没配 lambda 而失败 ⇒ 两个
    flow 都是开的。改成显式那一项后三者全部 `not enabled`。

    所以"读回来是空"与"能力面是空"是两件事，中间差一次**行为**验证——这也是
    NATIVE_AUTH_DISABLED 一开始就写成 ["ALLOW_REFRESH_TOKEN_AUTH"] 而不是 [] 的原因。
    """
    from botocore.stub import Stubber
    machine = dp.client_configs("example.com", [], idp_name="Okta",
                                include_machine=True,
                                machine_scopes=("site-builder-mcp/invoke",))["machine"]
    assert machine["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    dp._assert_no_native_flows("machine", machine)          # 不得抛

    cog = _resource_server_cog()
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ExplicitAuthFlows":
                                              ["ALLOW_REFRESH_TOKEN_AUTH"]}},
                          {"UserPoolId": "us-east-1_x", "ClientId": "m1"})
        dp._verify_no_native_flows(cog, "us-east-1_x", {"machine": "m1"})


@pytest.mark.parametrize("flows", [[], None])
def test_assert_no_native_flows_rejects_unspecified(flows):
    """空 / 缺席同样要被拦：它等于"未指定" ⇒ Cognito 的默认值把 SRP 与 CUSTOM 打开。

    这条判据不能只写在 machine client 的用例里——闸门本身必须会红，否则下一个
    手抄一份 client 参数的人照样能把 `[]` 递进去。
    """
    params = {} if flows is None else {"ExplicitAuthFlows": flows}
    with pytest.raises(SystemExit, match="未指定|显式"):
        dp._assert_no_native_flows("probe", params)


@pytest.mark.parametrize("flows", [[], None])
def test_verify_no_native_flows_rejects_unspecified_readback(flows):
    """读回复验同样要拦空值：线上读回 [] / None 时能力面是**开着**的
    （SRP + CUSTOM），而旧判据会把它当成"边界成立"打印一行 ✓。"""
    import boto3
    from botocore.stub import Stubber
    live = {} if flows is None else {"ExplicitAuthFlows": flows}
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client", {"UserPoolClient": live},
                          {"UserPoolId": "us-east-1_test", "ClientId": "c1"})
        with pytest.raises(SystemExit, match="未指定|显式"):
            dp._verify_no_native_flows(cog, "us-east-1_test", {"site": "c1"})


def test_store_client_secrets_writes_machine_secret_when_it_exists():
    """machine client 的 secret 必须落 SSM（key-proxy 靠它换 token）。"""
    import boto3
    from botocore.stub import Stubber
    fake_site = "FAKEclientsecretFAKEclientsec1"
    fake_machine = "FAKEmachinesecretFAKEmachine2"
    cog = _resource_server_cog()
    ssm = boto3.client("ssm", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as cstub, Stubber(ssm) as sstub:
        cstub.add_response("describe_user_pool_client",
                           {"UserPoolClient": {"ClientSecret": fake_site}},
                           {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        sstub.add_response("put_parameter", {},
                           {"Name": "/site-builder/site-client-secret",
                            "Value": fake_site, "Type": "SecureString",
                            "Overwrite": True})
        cstub.add_response("describe_user_pool_client",
                           {"UserPoolClient": {"ClientSecret": fake_machine}},
                           {"UserPoolId": "us-east-1_x", "ClientId": "m1"})
        sstub.add_response("put_parameter", {},
                           {"Name": "/site-builder/machine-client-secret",
                            "Value": fake_machine, "Type": "SecureString",
                            "Overwrite": True})
        dp._store_client_secrets(cog, "us-east-1_x",
                                 {"site": "c1", "mcp": "p1", "machine": "m1"},
                                 "us-east-1", ssm=ssm)
        sstub.assert_no_pending_responses()
        cstub.assert_no_pending_responses()


def test_store_client_secrets_skips_machine_when_component_disabled():
    """没建 machine client 时不得去写那个参数（`clients` 里没有这个键）。

    硬编码成"两个都写"会 KeyError 中止在 ⑧ 步——而前面七步已经改过线上资源。
    """
    import boto3
    from botocore.stub import Stubber
    fake_site = "FAKEclientsecretFAKEclientsec1"
    cog = _resource_server_cog()
    ssm = boto3.client("ssm", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as cstub, Stubber(ssm) as sstub:
        cstub.add_response("describe_user_pool_client",
                           {"UserPoolClient": {"ClientSecret": fake_site}},
                           {"UserPoolId": "us-east-1_x", "ClientId": "c1"})
        sstub.add_response("put_parameter", {},
                           {"Name": "/site-builder/site-client-secret",
                            "Value": fake_site, "Type": "SecureString",
                            "Overwrite": True})
        dp._store_client_secrets(cog, "us-east-1_x", {"site": "c1", "mcp": "p1"},
                                 "us-east-1", ssm=ssm)
        sstub.assert_no_pending_responses()


def test_machine_secret_also_honours_the_isolated_prefix():
    """隔离 spike 的 machine secret 同样不得覆盖生产参数（见 site 那条的教训）。"""
    import boto3
    from botocore.stub import Stubber
    fake_machine = "FAKEmachinesecretFAKEmachine2"
    cog = _resource_server_cog()
    ssm = boto3.client("ssm", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as cstub, Stubber(ssm) as sstub:
        cstub.add_response("describe_user_pool_client",
                           {"UserPoolClient": {"ClientSecret": fake_machine}},
                           {"UserPoolId": "us-east-1_spike", "ClientId": "m1"})
        sstub.add_response("put_parameter", {},
                           {"Name": "/site-builder-spike/tmp-pool/machine-client-secret",
                            "Value": fake_machine, "Type": "SecureString",
                            "Overwrite": True})
        dp._store_client_secrets(cog, "us-east-1_spike", {"machine": "m1"},
                                 "us-east-1", "/site-builder-spike/tmp-pool",
                                 ssm=ssm)
        sstub.assert_no_pending_responses()


def test_ensure_clients_passes_machine_flags_through():
    """`_ensure_clients` 必须把 include_machine/machine_scopes 透传给 client_configs。

    签名不改的话 main() 传这两个参数会 TypeError——而 client_configs 的
    include_machine 分支在 M1 之后一直没有调用方，漏改不会被别的用例发现。
    """
    import inspect
    sig = inspect.signature(dp._ensure_clients)
    assert sig.parameters["include_machine"].default is False
    assert sig.parameters["machine_scopes"].default == ()

    seen = {}

    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": []}

        def create_user_pool_client(self, **kw):
            seen[kw["ClientName"]] = kw
            return {"UserPoolClient": {"ClientId": "id-" + kw["ClientName"]}}

    out = dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [], "Okta",
                             include_machine=True,
                             machine_scopes=("site-builder-mcp/invoke",))
    assert set(out) == {"site", "mcp", "machine"}
    assert seen["site-builder-machine"]["AllowedOAuthScopes"] == \
        ["site-builder-mcp/invoke"]


def test_ensure_clients_defaults_to_no_machine_client():
    """不传参数时行为与 M1 完全一致（没配 [ApiKey] 段就不该有 machine client）。"""
    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": []}

        def create_user_pool_client(self, **kw):
            return {"UserPoolClient": {"ClientId": "id"}}

    assert set(dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [],
                                  "Okta")) == {"site", "mcp"}


def test_deploy_pool_uses_the_shared_gate_not_its_own_judgement():
    """判定必须来自 api_key_config（`deployer/functions/`），不是本脚本自己写。"""
    src = (Path(__file__).parents[2] / "scripts" / "deploy_pool.py").read_text()
    assert "from api_key_config import" in src
    assert 'has_section("ApiKey")' not in src
    assert hasattr(dp, "api_key_enabled")


# --- 无 [IdP] 段时不得清掉线上的 IdP 名单（2026-08-12）---
# client_configs 在无 IdP 时回落 ["COGNITO"]，而已存在的 client 走
# update_user_pool_client（read-modify-write，整体替换）——把回落值盖上去就是
# 把 Feishu 从生产 client 的 SupportedIdentityProviders 里摘掉：
#   · 全部用户当场登不进（托管登录页不再有 IdP 入口）；
#   · Cognito 本地登录/注册重新暴露，allowed_users="org" 的边界失效
#     （spec §3.5、§11——§11 明写了"换 IdP 重跑会移除原 IdP、切断线上登录"）。
# 已部署平台的 config.ini **确实没有 [IdP] 段**，所以这是"一条命令之外"的事故。
# 修的方向：缺配置 = 不动线上（最严解释），而不是 = 恢复默认。

def _live_client(name: str, client_id: str, providers: list[str]) -> dict:
    """线上现状（describe_user_pool_client 的回包），带 provider 名单。"""
    return _client_stub_response(ClientName=name, ClientId=client_id,
                                 SupportedIdentityProviders=providers)


def _two_existing_clients() -> list[dict]:
    return [{"ClientName": "site-builder-site", "ClientId": "c-site"},
            {"ClientName": "site-builder-mcp", "ClientId": "c-mcp"}]


def _capture_update_params(cog) -> list:
    """抓真正发给 UpdateUserPoolClient 的参数。

    Stubber 只校验参数、不把它回传，所以挂 botocore 的 provide-client-params
    事件（注册在前缀上，匹配该事件的全部操作，再按 model.name 过滤）。
    这样**既拿到参数又仍然经过真实 service model 校验**——序列化发生在这个
    事件之后，非法参数照样以 ParamValidationError 失败。
    """
    seen = []

    def _grab(params, model, **kw):
        if model.name == "UpdateUserPoolClient":
            seen.append(dict(params))

    cog.meta.events.register("provide-client-params", _grab)
    return seen


def test_update_without_idp_config_preserves_live_federation():
    """回归：无 [IdP] 段重跑，线上的 Feishu 必须还在，且不得被换成 COGNITO。

    这就是已部署平台今天的真实状态：config.ini 无 [IdP] 段，而 site/mcp 两个
    生产 client 的 SupportedIdentityProviders 都是 ['Feishu']。旧实现在这里
    下发 ['COGNITO']——登录全断 + 本地注册入口重开。
    """
    from botocore.stub import Stubber

    cog = _cog()
    seen = _capture_update_params(cog)
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients",
                          {"UserPoolClients": _two_existing_clients()},
                          {"UserPoolId": "us-east-1_x", "MaxResults": 60})
        for name, cid in (("site-builder-site", "c-site"),
                          ("site-builder-mcp", "c-mcp")):
            stub.add_response(
                "describe_user_pool_client",
                {"UserPoolClient": _live_client(name, cid, ["Feishu"])},
                {"UserPoolId": "us-east-1_x", "ClientId": cid})
            # 参数不预期死值——用事件抓下来断言（见 _capture_update_params）
            stub.add_response("update_user_pool_client", {"UserPoolClient": {}})
        dp._ensure_clients(cog, "us-east-1_x", "example.com", [], None)
        stub.assert_no_pending_responses()

    assert len(seen) == 2, "两个 client 都要走 update"
    for params in seen:
        who = params["ClientName"]
        assert params["SupportedIdentityProviders"] == ["Feishu"], who
        assert "COGNITO" not in params["SupportedIdentityProviders"], who


def test_update_path_omits_provider_key_entirely_without_idp(monkeypatch):
    """fail-closed 的**形状**本身：无 [IdP] 时 desired 里不许有这个键。

    只断言"结果里有 Feishu"不够——那也能用"先读一遍线上再塞回 desired"实现，
    而那种实现一旦读取失败或走了空值兜底，就又把名单清掉了（本仓库的
    "假值兜底鉴权是陷阱"同一类）。唯一稳的形状是这个键压根不出现在 desired
    里，由 _client_update_params 的回填保留现值。
    """
    captured = {}

    def _spy(cog, pool_id, client_id, desired):
        captured[desired["ClientName"]] = desired
        return {"ClientName": desired["ClientName"]}

    monkeypatch.setattr(dp, "_client_update_params", _spy)

    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": _two_existing_clients()}

        def update_user_pool_client(self, **kw):
            return {"UserPoolClient": {}}

    dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [], None)
    assert set(captured) == {"site-builder-site", "site-builder-mcp"}
    for name, desired in captured.items():
        assert "SupportedIdentityProviders" not in desired, name
    # 只摘这一个键，别的照常声明（不是"整个 desired 都不发了"）
    site = captured["site-builder-site"]
    assert site["ExplicitAuthFlows"] == dp.NATIVE_AUTH_DISABLED
    assert site["AccessTokenValidity"] == 15


def test_create_without_idp_config_still_uses_cognito_only():
    """create 路径没有"现值"可保留，仍下发 ["COGNITO"]（main() 已为此告警）。"""
    seen = {}

    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": []}

        def create_user_pool_client(self, **kw):
            seen[kw["ClientName"]] = kw
            return {"UserPoolClient": {"ClientId": "id-" + kw["ClientName"]}}

    dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [], None)
    for name in ("site-builder-site", "site-builder-mcp"):
        assert seen[name]["SupportedIdentityProviders"] == ["COGNITO"], name
        # 探针 IdP 名只用于本进程内比对，绝不能出现在下发参数里
        assert dp._PROBE_IDP not in seen[name]["SupportedIdentityProviders"]


def test_create_with_idp_config_lists_only_that_idp():
    """配了 IdP 的 create 路径行为不变：只列该 IdP，不含 COGNITO。"""
    seen = {}

    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": []}

        def create_user_pool_client(self, **kw):
            seen[kw["ClientName"]] = kw
            return {"UserPoolClient": {"ClientId": "id"}}

    dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [], "Okta")
    for name in ("site-builder-site", "site-builder-mcp"):
        assert seen[name]["SupportedIdentityProviders"] == ["Okta"], name
        assert "COGNITO" not in seen[name]["SupportedIdentityProviders"], name


def test_update_with_idp_config_still_replaces_provider_list():
    """配了 IdP 时 update 路径必须照旧下发 [provider_name]。

    这条盯的是"修过头"：把这个键在 update 路径上一律摘掉，就再也没法用本脚本
    把 client 切到新 IdP（也就修不了配错的线上名单）。省略只在**缺配置**时成立。
    """
    from botocore.stub import Stubber

    cog = _cog()
    seen = _capture_update_params(cog)
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients",
                          {"UserPoolClients": _two_existing_clients()},
                          {"UserPoolId": "us-east-1_x", "MaxResults": 60})
        for name, cid in (("site-builder-site", "c-site"),
                          ("site-builder-mcp", "c-mcp")):
            stub.add_response(
                "describe_user_pool_client",
                {"UserPoolClient": _live_client(name, cid, ["Feishu"])},
                {"UserPoolId": "us-east-1_x", "ClientId": cid})
            stub.add_response("update_user_pool_client", {"UserPoolClient": {}})
        dp._ensure_clients(cog, "us-east-1_x", "example.com", [], "Okta")
        stub.assert_no_pending_responses()

    assert len(seen) == 2
    for params in seen:
        assert params["SupportedIdentityProviders"] == ["Okta"], params["ClientName"]
        assert "COGNITO" not in params["SupportedIdentityProviders"]


def test_machine_client_keeps_cognito_on_update_without_idp(monkeypatch):
    """machine 的 ["COGNITO"] 是写死的正确值，不是 IdP 回落——不能一起被摘掉。

    它走 client_credentials，与用户身份无关；把这个键从它的 desired 里摘掉就
    等于放弃纠正（有人手工给它加了联邦 provider 时再也改不回来）。
    """
    captured = {}

    def _spy(cog, pool_id, client_id, desired):
        captured[desired["ClientName"]] = desired
        return {"ClientName": desired["ClientName"]}

    monkeypatch.setattr(dp, "_client_update_params", _spy)

    class _Cog:
        def list_user_pool_clients(self, **kw):
            return {"UserPoolClients": _two_existing_clients() + [
                {"ClientName": "site-builder-machine", "ClientId": "c-machine"}]}

        def update_user_pool_client(self, **kw):
            return {"UserPoolClient": {}}

    dp._ensure_clients(_Cog(), "us-east-1_x", "example.com", [], None,
                       include_machine=True,
                       machine_scopes=("site-builder-mcp/invoke",))
    assert captured["site-builder-machine"]["SupportedIdentityProviders"] == \
        ["COGNITO"]
    # 联邦的那两个仍然一个键都不声明
    for name in ("site-builder-site", "site-builder-mcp"):
        assert "SupportedIdentityProviders" not in captured[name], name


def test_idp_derived_keys_are_probed_from_client_configs():
    """"哪些 client 跟着 [IdP] 走"必须从 client_configs 探出来，不能手抄名单。

    手抄的 {"site","mcp"} 会在加第四个联邦 client 时腐烂，而腐烂的症状正是
    本次修的这个缺陷（新 client 的线上名单在无 [IdP] 重跑时被清成 COGNITO）。
    这里直接拿 client_configs 的真实输出反推，两者必须一致。
    """
    scopes = ("site-builder-mcp/invoke",)
    keys = dp._idp_derived_client_keys("example.com", [], include_machine=True,
                                       machine_scopes=scopes)
    clients = dp.client_configs("example.com", [], "Okta", include_machine=True,
                                machine_scopes=scopes)
    assert keys == {k for k, v in clients.items()
                    if v["SupportedIdentityProviders"] == ["Okta"]}
    assert keys == {"site", "mcp"}          # 当前形态的回归锚点
    # machine 不在其中：它的 COGNITO 与 [IdP] 无关
    assert "machine" not in keys


# ---------------------------------------------------------------------------
# 工单 07：[IdP] mode —— 纯本地 preflight（零 AWS 调用）
# ---------------------------------------------------------------------------
#
# **为什么这些用例必须存在**：`test_config_example_keys_are_read.py` 把"整段读取"
# （`dict(cfg["IdP"])`，deploy_pool 正是这样读的）算成"读了该段每个键"，所以往
# `[IdP]` 里加任何键，那个守卫都恒真——它证明不了新键影响行为。本节是新键的
# **唯一**行为证据。

def _idp_cognito(**over) -> dict:
    """cognito-admin 模式的最小合法 [IdP]（issuer/client_id/client_secret 必须缺席）。"""
    base = {"mode": "cognito-admin", "provider_name": "CognitoSource",
            "cognito_user_pool_name": "site-builder-idp",
            "cognito_domain_prefix": "acme-idp-2026"}
    base.update(over)
    return base


def test_idp_mode_defaults_to_external_when_key_absent():
    """键缺失 ⇒ external-oidc。这是向后兼容的支点：存量 config.ini 里没有 mode。"""
    assert dp.idp_mode({}) == dp.IDP_MODE_EXTERNAL
    assert dp.idp_mode({"provider_name": "Feishu"}) == dp.IDP_MODE_EXTERNAL
    assert dp.idp_mode({"mode": ""}) == dp.IDP_MODE_EXTERNAL


def test_idp_mode_tolerates_inline_comments():
    """裸 ConfigParser 会把行内注释并进值。mode 是本脚本自己判分支用的，
    所以它必须先切掉 `#` / `;`——否则 `mode = cognito-admin  # 内置` 会被判成未知模式。"""
    assert dp.idp_mode({"mode": "cognito-admin  # 内置池"}) == dp.IDP_MODE_COGNITO
    assert dp.idp_mode({"mode": "external-oidc ; 已有 IdP"}) == dp.IDP_MODE_EXTERNAL


def test_idp_mode_rejects_unknown_value():
    """未知模式必须响亮失败：静默回落成 external-oidc 会让写错模式名的采用者
    建出一个"没有 IdP 池、client 只列 COGNITO"的池，而输出看起来一切正常。"""
    with pytest.raises(SystemExit, match="cognito-admin"):
        dp.idp_mode({"mode": "cognito-managed"})     # ADR 早期用过的名字，不是最终值


@pytest.mark.parametrize("name", ["Google", "Facebook", "LoginWithAmazon",
                                  "SignInWithApple", "COGNITO"])
def test_reserved_provider_names_are_rejected_locally(name):
    """保留名校验必须**在任何 AWS 调用之前**：Cognito 要到 create_identity_provider
    才报 `Provider Google cannot be of type OIDC`，而那时池与托管域名都已建好，
    脚本停在中途（工单 06 腿 1 实测踩过）。前四个是 Cognito 拒的社交类型名；
    COGNITO 是本仓库自己的规则——API 接受它，但 app client 的
    SupportedIdentityProviders 用这个字面量表示"池内建用户目录"，同名无法分辨。"""
    with pytest.raises(SystemExit) as e:
        dp.assert_provider_name_allowed(name)
    assert name in str(e.value)


@pytest.mark.parametrize("name", ["GoogleOIDC", "SAML", "google", "CognitoSource",
                                  "Feishu"])
def test_non_reserved_provider_names_are_accepted(name):
    """校验**区分大小写且只拒实测被拒的那些**，不许自己发明规则。

    逐个实测过：`SAML` 与 `google`（小写）Cognito 都接受。多拒一个名字的代价是
    采用者被一条不存在的限制挡住，而错误文案会告诉他"Cognito 保留了这个名字"
    ——一句假话。`google` 能用但不该依赖（大小写差一个字母就变成被拒的那个），
    这条提醒写在 config.ini.example 的注释里，不写成硬失败。
    """
    dp.assert_provider_name_allowed(name)      # 不得抛


def test_reserved_name_check_sees_through_inline_comments():
    """`provider_name = Google  # 我们的 IdP` 同样要被拦住。"""
    with pytest.raises(SystemExit, match="Google"):
        dp.check_idp_section({"provider_name": "Google  # 我们的 IdP"},
                             dp.IDP_MODE_EXTERNAL)


def test_external_mode_with_empty_provider_name_is_not_an_error():
    """**回归钉子（裁定 1）**：`[IdP]` 段存在但全空 ⇒ 不报错。

    `.example` 出厂就是空值，而 main() 对这种情形的既有行为是打印告警并跳过联邦
    （"首次部署、联邦还没接"那条路）。把它改成硬失败会改掉生产在用的那条代码路径。
    """
    dp.check_idp_section({}, dp.IDP_MODE_EXTERNAL)                       # 不得抛
    dp.check_idp_section({"provider_name": "", "issuer": ""},
                         dp.IDP_MODE_EXTERNAL)                            # 不得抛


def test_cognito_mode_requires_provider_name():
    """cognito-admin 下必定要建 provider ⇒ 名字必填，且它还要逐字符进 router 的
    trusted_idps（那一对没有任何自动闸门）。"""
    with pytest.raises(SystemExit, match="provider_name"):
        dp.check_idp_section(_idp_cognito(provider_name=""), dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("missing", ["cognito_user_pool_name", "cognito_domain_prefix"])
def test_cognito_mode_requires_both_of_its_own_keys(missing):
    """两个键缺一不可：少了池名就无法幂等找回那个池，少了域名前缀就没有
    authorization/token/userinfo 端点（issuer 的 discovery 全指向托管域名）。"""
    idp = _idp_cognito(**{missing: ""})
    with pytest.raises(SystemExit, match=missing):
        dp.check_idp_section(idp, dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("field", ["issuer", "client_id", "client_secret"])
def test_cognito_mode_rejects_externally_supplied_federation_fields(field):
    """三个字段在内置模式下由部署过程从新建的池派生 ⇒ **非空即报冲突**，不静默忽略。

    静默忽略的症状最难查：采用者以为自己指定了 issuer，实际生效的是另一个池的
    issuer，而两者的 discovery 文档都合法、登录页都能开，只有 claim 里的 `idp`
    与预期不同。
    """
    with pytest.raises(SystemExit, match=field):
        dp.check_idp_section(_idp_cognito(**{field: "x"}), dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("field", ["cognito_user_pool_name", "cognito_domain_prefix"])
def test_external_mode_rejects_cognito_mode_keys(field):
    """反向混填同样拒：填了内置模式的键却没切模式 ⇒ 采用者以为会建第二个池，
    而实际什么都没建（.example 出厂两键为空，所以只有"填了"才触发）。"""
    idp = {"provider_name": "Okta", "issuer": "https://okta.example/",
           "client_id": "c", "client_secret": "s", field: "acme-idp"}
    with pytest.raises(SystemExit, match=field):
        dp.check_idp_section(idp, dp.IDP_MODE_EXTERNAL)


def test_cognito_mode_minimal_config_passes():
    dp.check_idp_section(_idp_cognito(), dp.IDP_MODE_COGNITO)      # 不得抛


def test_idp_pool_names_prefer_flags_over_config():
    """生产运行取 config；隔离运行（连平台池一起隔离）取旗标。

    **旗标只在非生产 `--pool-name` 下合法**——反向组合会把生产平台池的 provider
    指向 spike IdP 池，见 test_isolation_flags_require_a_non_production_platform_pool。
    """
    assert _resolve() == ("site-builder-idp", "acme-idp-2026")
    assert _resolve(pool_name="sb-idp-spike", platform_domain_prefix="sb-idp-spike-2026",
                    idp_pool_name="spike-idp",
                    idp_domain_prefix="spike-idp-2026") == ("spike-idp", "spike-idp-2026")


@pytest.mark.parametrize("flags", [(None, None), ("spike-idp", None),
                                   (None, "spike-idp-2026")])
def test_isolated_platform_pool_requires_both_idp_isolation_flags(flags):
    """**裁定 2**：`--pool-name` 的三层隔离（池名 / pre-token 函数名 / SSM 前缀）
    **覆盖不到 IdP 池**——它的名字来自 config。所以"隔离平台池 + 生产 IdP 池"
    这个组合会对**生产 IdP 池的 app client** 做 read-modify-write
    （`SupportedIdentityProviders` / `ExplicitAuthFlows` / `CallbackURLs`）。
    在任何 AWS 写之前拒掉它，而不是靠人记得同时改 config。
    """
    name, prefix = flags
    with pytest.raises(SystemExit, match="--idp-pool-name"):
        dp.resolve_idp_pool_names(pool_name="sb-idp-spike",
                                  platform_domain_prefix="sb-idp-spike-2026",
                                  idp_pool_name=name, idp_domain_prefix=prefix,
                                  idp=_idp_cognito())


# ---------------------------------------------------------------------------
# 工单 07：内置 IdP 池的参数生成（纯函数）
# ---------------------------------------------------------------------------

def test_idp_pool_is_lite_tier():
    """LITE 够用：平台池要 ESSENTIALS 是为了 pre-token V2，而这个池不挂任何触发器
    （实测 access token 里 email/idp/auth_via 都由**平台池**那个触发器注入）。
    LITE 还明确拒 managed login v2 ⇒ 只有 classic hosted UI，也不需要 branding。
    采用者的月成本因此只加 LITE 一档。"""
    assert dp.idp_pool_config("acme-idp")["UserPoolTier"] == "LITE"


def test_idp_pool_email_is_required_and_immutable():
    """**这是"邮箱由身份源控制"的唯一实现点。**

    实测复验：Mutable=False 下 admin_update_user_attributes 改 email 报
    `InvalidParameterException: user.email: Attribute cannot be updated.`
    ——连管理员都改不了。代价是建错邮箱只能删号重建（写进 DEPLOY.md）。
    """
    schema = dp.idp_pool_config("acme-idp")["Schema"]
    email = [a for a in schema if a["Name"] == "email"]
    assert email == [{"Name": "email", "AttributeDataType": "String",
                      "Required": True, "Mutable": False}]


def test_idp_pool_disables_self_signup():
    """开着自注册 = 任何人都能自己造一个邮箱身份，整条路的地基就没了
    （也是 palisade.udd.cognito.pool.open 扫的那一条）。"""
    cfg = dp.idp_pool_config("acme-idp")
    assert cfg["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert cfg["PoolName"] == "acme-idp"
    assert cfg["UsernameAttributes"] == ["email"]
    assert cfg["AutoVerifiedAttributes"] == ["email"]


def test_idp_client_omits_write_attributes_entirely():
    """**WriteAttributes 这个键必须整个不给**，而不是给一份不含 email 的名单。

    实测（工单 06 Q3）：显式给出的 WriteAttributes 必须包含全部 Required=True 属性
    ——`["name"]` 被 `InvalidParameterException: Invalid write attributes specified
    while creating a client` 拒，而 `["email","name"]` 反而**被接受**（哪怕 email 是
    Mutable=False）。所以它**不是防线**；不给这个键时读回是 None，语义是"全部
    **可变**标准属性可写"，而 email 在 schema 层不可变 ⇒ 自动被排除。
    """
    assert "WriteAttributes" not in dp.idp_client_config("https://x/oauth2/idpresponse")


def test_idp_client_reads_the_three_mapping_targets():
    """ReadAttributes 缺 email 而请求了 email scope ⇒ token 端点 invalid_grant。"""
    cfg = dp.idp_client_config("https://x/oauth2/idpresponse")
    assert set(cfg["ReadAttributes"]) == {"email", "email_verified", "name"}


def test_idp_client_is_confidential_code_flow_with_platform_callback():
    cfg = dp.idp_client_config(
        "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse")
    assert cfg["GenerateSecret"] is True    # Cognito 作 OIDC RP 时要 client_secret
    assert cfg["AllowedOAuthFlows"] == ["code"]
    assert cfg["AllowedOAuthFlowsUserPoolClient"] is True
    assert set(cfg["AllowedOAuthScopes"]) == {"openid", "email", "profile"}
    assert cfg["CallbackURLs"] == [
        "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"]
    # IdP 池自己就是身份源：它的 client 只列 COGNITO（与平台池刻意不列 COGNITO 相反）
    assert cfg["SupportedIdentityProviders"] == ["COGNITO"]
    assert cfg["ClientName"] == dp.IDP_CLIENT_NAME


def test_idp_client_passes_the_native_flow_gate():
    """身份源池上原生认证全开 = 可以绕过 hosted UI 直接用 API 认证
    （工单 06 的 Q4 更正）。这个池今天没有 CDK / 控制台替它复验，闸门就是这条。"""
    cfg = dp.idp_client_config("https://x/oauth2/idpresponse")
    assert cfg["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    dp._assert_no_native_flows("idp-federation", cfg)      # 不得抛


def test_idp_pool_and_client_pass_botocore_param_validation():
    """参数形态按 service model 校验：拼错键名 / 类型的症状否则是真机上
    ParamValidationError，而那时平台池已经建好了。"""
    import botocore.session
    from botocore.validate import validate_parameters
    model = botocore.session.get_session().get_service_model("cognito-idp")
    validate_parameters(dp.idp_pool_config("acme-idp"),
                        model.operation_model("CreateUserPool").input_shape)
    params = dict(dp.idp_client_config("https://x/oauth2/idpresponse"),
                  UserPoolId="us-east-1_abc")
    validate_parameters(params,
                        model.operation_model("CreateUserPoolClient").input_shape)


# ---------------------------------------------------------------------------
# 工单 07：内置 IdP 池的只读 preflight（第 4/5 条分叉 fail closed）
# ---------------------------------------------------------------------------

class _ReadOnlyCog:
    """只实现 preflight 需要的三个**读** API 的假 client。

    "preflight 不写"因此是**结构性**的：任何 create_* / update_* 调用会
    AttributeError，而不是靠人读代码确认。比 Stubber 更强的一点是它记录调用顺序，
    可以断言"读了哪几个、没读别的"。
    """

    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self, pools: dict, domains: dict):
        self._pools = pools            # {pool_name: {"Id":…, "Domain":…}}
        self._domains = domains        # {domain_prefix: pool_id}
        self.calls: list = []

    def list_user_pools(self, **kw):
        self.calls.append(("list_user_pools", kw))
        return {"UserPools": [{"Id": p["Id"], "Name": n}
                              for n, p in self._pools.items()]}

    def describe_user_pool(self, UserPoolId):
        self.calls.append(("describe_user_pool", UserPoolId))
        for p in self._pools.values():
            if p["Id"] == UserPoolId:
                return {"UserPool": dict(p)}
        raise self.exceptions.ResourceNotFoundException(UserPoolId)

    def describe_user_pool_domain(self, Domain):
        self.calls.append(("describe_user_pool_domain", Domain))
        pool_id = self._domains.get(Domain)
        # **实测形态**：不存在的前缀返回空的 DomainDescription，不抛异常
        return {"DomainDescription": {"UserPoolId": pool_id} if pool_id else {}}


def test_preflight_returns_none_when_nothing_exists_and_only_reads():
    cog = _ReadOnlyCog(pools={}, domains={})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") is None
    assert {c[0] for c in cog.calls} <= {"list_user_pools", "describe_user_pool",
                                         "describe_user_pool_domain"}


def test_preflight_returns_existing_pool_when_name_and_domain_agree():
    cog = _ReadOnlyCog(
        pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "acme-idp-2026"}},
        domains={"acme-idp-2026": "us-east-1_a"})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") == "us-east-1_a"


def test_preflight_fails_closed_when_domain_belongs_to_another_pool():
    """判据 4：按名字与按域名前缀找到的**不是同一个池** ⇒ 停。

    继续往下跑的后果是把这个域名前缀当成"还没建"，于是 create_user_pool_domain
    对着别的池的前缀失败（或更糟：那个池是另一个环境的 IdP 池，而我们正准备把
    平台池的回调写到它的 client 上）。
    """
    cog = _ReadOnlyCog(
        pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "other-prefix"}},
        domains={"acme-idp-2026": "us-east-1_b", "other-prefix": "us-east-1_a"})
    with pytest.raises(SystemExit, match="us-east-1_b"):
        dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026")


def test_preflight_fails_closed_when_named_pool_has_a_different_domain():
    """判据 5：按名字找到的池存在，但它的托管域名 ≠ 配置里的前缀 ⇒ 停。

    `_ensure_domain` 在池已有域名时**沿用现值、忽略配置前缀**，所以放它过去会得到
    "config 说 A、线上用 B"的静默漂移，而最后一跳的症状是 redirect_uri_mismatch
    （工单 06 的第 4 条 code-review 结论）。
    """
    cog = _ReadOnlyCog(
        pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "legacy-prefix"}},
        domains={"legacy-prefix": "us-east-1_a"})
    with pytest.raises(SystemExit, match="legacy-prefix"):
        dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026")


def test_preflight_allows_existing_pool_without_a_domain_yet():
    """池建好了但域名没建（上一次跑到一半中断）⇒ 这是可收敛的状态，不该拒。"""
    cog = _ReadOnlyCog(pools={"acme-idp": {"Id": "us-east-1_a"}}, domains={})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") == "us-east-1_a"


def test_domain_lookup_treats_missing_and_not_found_alike():
    """两种"没有"都要当成 None：空 DomainDescription（实测形态）与
    ResourceNotFoundException（防御性，AWS 若改行为不至于把 preflight 打成崩溃）。"""
    cog = _ReadOnlyCog(pools={}, domains={})
    assert dp._pool_id_for_domain(cog, "nope") is None

    class _Raising(_ReadOnlyCog):
        def describe_user_pool_domain(self, Domain):
            raise self.exceptions.ResourceNotFoundException(Domain)

    assert dp._pool_id_for_domain(_Raising(pools={}, domains={}), "nope") is None


# ---------------------------------------------------------------------------
# 工单 07：IdP 池收敛（建池 → 托管域名 → 联邦 client → 读回复验）
# ---------------------------------------------------------------------------

def test_idp_domain_is_created_without_managed_login_version():
    """LITE 池只有 classic hosted UI：传 ManagedLoginVersion=2 会
    `FeatureUnavailableInTierException`（实测）。所以内置 IdP 池这条路必须
    **不带**这个参数——Stubber 按精确参数匹配，多传一个键就不匹配。"""
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {"Id": "us-east-1_a"}},
                          {"UserPoolId": "us-east-1_a"})
        stub.add_response("create_user_pool_domain", {},
                          {"Domain": "acme-idp-2026", "UserPoolId": "us-east-1_a"})
        assert dp._ensure_domain(cog, "us-east-1_a", "acme-idp-2026",
                                 managed_login_version=None) == "acme-idp-2026"
        stub.assert_no_pending_responses()


def test_platform_domain_still_requests_managed_login_v2_by_default():
    """回归钉子：平台池那条路（默认参数）**必须**仍然传 v2。
    平台池是 managed login v2 + 必须套 branding，混成一条就是登录页不可用。"""
    import inspect
    sig = inspect.signature(dp._ensure_domain)
    assert sig.parameters["managed_login_version"].default == dp.MANAGED_LOGIN_V2


def test_ensure_idp_pool_creates_and_verifies_both_boundaries():
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("create_user_pool", {"UserPool": {"Id": "us-east-1_new"}},
                          dp.idp_pool_config("acme-idp"))
        stub.add_response("describe_user_pool", {"UserPool": {
            "Id": "us-east-1_new",
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            "SchemaAttributes": [{"Name": "email", "Mutable": False},
                                 {"Name": "name", "Mutable": True}]}},
                          {"UserPoolId": "us-east-1_new"})
        assert dp._ensure_idp_pool(cog, "acme-idp", None) == "us-east-1_new"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("live,match", [
    ({"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
      "SchemaAttributes": [{"Name": "email", "Mutable": False}]}, "自注册"),
    ({"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
      "SchemaAttributes": [{"Name": "email", "Mutable": True}]}, "重建"),
])
def test_idp_pool_boundaries_fail_closed(live, match):
    """两条边界各自都要红。

    email 可变那条**不可自愈**（schema 建后不能改），所以文案必须说"删池重建"
    ——否则采用者会以为幂等重跑能修好它，反复跑一个永远不满足前提的部署。
    """
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool",
                          {"UserPool": dict(live, Id="us-east-1_a")},
                          {"UserPoolId": "us-east-1_a"})
        with pytest.raises(SystemExit, match=match):
            dp._verify_idp_pool_boundaries(cog, "us-east-1_a")


def test_ensure_idp_pool_client_creates_with_secret():
    import boto3
    from botocore.stub import Stubber
    fake_secret = "FAKEidpclientsecretFAKEidpcs1"
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    idpresponse = "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients", {"UserPoolClients": []},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("create_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientSecret": fake_secret}},
                          dict(dp.idp_client_config(idpresponse),
                               UserPoolId="us-east-1_a"))
        assert dp._ensure_idp_pool_client(cog, "us-east-1_a", idpresponse) == \
            ("idpc1", fake_secret)
        stub.assert_no_pending_responses()


def test_ensure_idp_pool_client_unions_callbacks_on_update():
    """**回调取并集，绝不替换**（裁定 2 的第二半）。

    UpdateUserPoolClient 是整体替换，直接下发我们这一条会摘掉线上已登记的回调
    ——若那是另一个平台池的 idpresponse，那个环境的登录当场全断。沿用本仓库
    既有的先例（LogoutURLs 的注释：多一个已登记 URL 无害，少一个会报错）。
    """
    import boto3
    from botocore.stub import Stubber
    fake_secret = "FAKEidpclientsecretFAKEidpcs1"
    other = "https://other.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    mine = "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    captured = _capture_update_params(cog)
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients",
                          {"UserPoolClients": [{"ClientName": dp.IDP_CLIENT_NAME,
                                                "ClientId": "idpc1"}]},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientName": dp.IDP_CLIENT_NAME,
                                              "CallbackURLs": [other],
                                              "ExplicitAuthFlows":
                                                  ["ALLOW_REFRESH_TOKEN_AUTH"]}},
                          {"UserPoolId": "us-east-1_a", "ClientId": "idpc1"})
        stub.add_response("update_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientSecret": fake_secret}}, None)
        assert dp._ensure_idp_pool_client(cog, "us-east-1_a", mine) == \
            ("idpc1", fake_secret)
    assert sorted(captured[0]["CallbackURLs"]) == sorted([other, mine])
    # WriteAttributes 在 update 路径上同样不许被塞进来（线上没设 ⇒ 保持未设）
    assert "WriteAttributes" not in captured[0]


def test_ensure_idp_pool_client_fails_loudly_without_a_secret():
    """没 secret 的 provider 只在**用户登录**那一刻报 invalid_client，
    比部署期报错难查得多——所以这里硬失败。"""
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    idpresponse = "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients", {"UserPoolClients": []},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("create_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1"}},
                          dict(dp.idp_client_config(idpresponse),
                               UserPoolId="us-east-1_a"))
        with pytest.raises(SystemExit, match="client_secret"):
            dp._ensure_idp_pool_client(cog, "us-east-1_a", idpresponse)


# ---------------------------------------------------------------------------
# 工单 07：_ensure_oidc_idp 模式感知 + 派生 issuer / client_id / secret
# ---------------------------------------------------------------------------

def test_cognito_mode_idp_derives_issuer_from_the_new_pool():
    """issuer 是池的 discovery 地址（不是托管域名）——托管域名只出现在 discovery
    文档里的三个端点上。写错这一条的症状是 create_identity_provider 就失败。"""
    src = _idp_cognito()
    out = dp.cognito_mode_idp(src, region="us-east-1", idp_pool_id="us-east-1_abc",
                              client_id="c1", client_secret="s1")
    assert out["issuer"] == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc"
    assert out["client_id"] == "c1"
    assert out["client_secret"] == "s1"
    assert out["provider_name"] == "CognitoSource"     # config 的值原样带过
    assert "issuer" not in src                          # 不得改动入参


def test_cognito_mode_ignores_sb_idp_client_secret_env(monkeypatch):
    """**环境变量不许覆盖派生出来的 secret。**

    `SB_IDP_CLIENT_SECRET` 是 external-oidc 那条路的注入通道（让明文只活在子进程
    里）。内置模式下 secret 是本次运行刚从新建的 client 上读到的，如果环境里恰好
    留着上一条路的值，覆盖的后果是 provider 带着一个错的 secret 建成功、
    **到用户登录换 token 那一刻才报 invalid_client**。
    """
    monkeypatch.setenv("SB_IDP_CLIENT_SECRET", "STALEsecretfromanotherIdP0001")
    idp = dp.cognito_mode_idp(_idp_cognito(), region="us-east-1",
                              idp_pool_id="us-east-1_abc", client_id="c1",
                              client_secret="DERIVEDsecretFROMnewPOOL0001")
    seen = _captured_idp_call(idp, mode=dp.IDP_MODE_COGNITO)
    assert seen["ProviderDetails"]["client_secret"] == "DERIVEDsecretFROMnewPOOL0001"
    assert seen["ProviderType"] == "OIDC"
    assert seen["ProviderName"] == "CognitoSource"


def test_external_mode_still_prefers_the_env_secret(monkeypatch):
    """回归钉子：external-oidc 那条路的注入通道不能被改坏
    （既有用例 test_idp_client_secret_can_come_from_env 也覆盖，这条锁"模式参数
    不影响它"）。"""
    monkeypatch.setenv("SB_IDP_CLIENT_SECRET", "ENVsecret0001")
    seen = _captured_idp_call(_idp(client_secret="cfg"),
                              mode=dp.IDP_MODE_EXTERNAL)
    assert seen["ProviderDetails"]["client_secret"] == "ENVsecret0001"


def test_cognito_mode_still_maps_email_verified():
    """内置池发 email_verified（建户时置 true），映射必须照常配上——
    平台侧 require_email_verified 默认 true，缺映射时该池所有登录都会被拒。"""
    idp = dp.cognito_mode_idp(_idp_cognito(), region="us-east-1",
                              idp_pool_id="us-east-1_abc", client_id="c1",
                              client_secret="s1")
    seen = _captured_idp_call(idp, mode=dp.IDP_MODE_COGNITO)
    assert seen["AttributeMapping"] == {"email": "email", "name": "name",
                                        "email_verified": "email_verified"}


def test_cognito_mode_without_a_derived_secret_is_an_internal_invariant():
    """内置模式下 secret 为空 = main() 的接线坏了，不是配置问题。
    文案必须说清这一点，否则采用者会去 config.ini 里找一个本该留空的键。"""
    idp = dict(_idp_cognito(), client_secret="")
    with pytest.raises(SystemExit, match="内部不变量"):
        _captured_idp_call(idp, mode=dp.IDP_MODE_COGNITO)


# ---------------------------------------------------------------------------
# 工单 07：main() 的次序（preflight → 第一次写 → ②b → ③）
# ---------------------------------------------------------------------------

def _main_call_order() -> list:
    """main() 里按源码位置排列的被调用函数名。

    用 AST 而不是 `in source`：后者对"函数被调用了"成立，对"在写之前被调用"
    无话可说——而次序正是这条路的全部安全性所在。
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(dp.main))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    calls.sort(key=lambda n: (n.lineno, n.col_offset))
    return [getattr(n.func, "id", getattr(n.func, "attr", "")) for n in calls]


def test_main_runs_local_preflight_before_the_first_aws_write():
    """**次序是这条路的全部安全性所在**：本地 preflight → 只读 preflight → 第一次写。

    工单 06 那个坑正是"池和域名都建好之后才炸"（provider_name 填了保留名）。
    """
    called = _main_call_order()
    assert "_ensure_pool" in called, "main() 没调用 _ensure_pool（本条空转）"
    first_write = called.index("_ensure_pool")
    for name in ("idp_mode", "check_idp_section", "resolve_idp_pool_names",
                 "preflight_idp_pool"):
        assert name in called, f"main() 没调用 {name}"
        assert called.index(name) < first_write, \
            f"{name} 排在 _ensure_pool（第一次 AWS 写）之后——preflight 失去意义"


def test_main_creates_the_idp_pool_after_the_platform_domain():
    """②b 必须在 ②（平台池托管域名）之后：IdP client 的回调要平台池托管域名的
    **真实现值**，而 _ensure_domain 在池已有域名时沿用现值、忽略配置前缀
    （拼错的症状是最后一跳 redirect_uri_mismatch）。
    同时它必须在 ③（建 provider）之前：provider 要 IdP 池的 issuer + secret。"""
    called = _main_call_order()
    assert called.index("_ensure_domain") < called.index("_ensure_idp_pool")
    assert called.index("_ensure_idp_pool") < called.index("_ensure_oidc_idp")
    assert called.index("_ensure_idp_pool_client") < called.index("_ensure_oidc_idp")
    # IdP 池那个 client 也要过读回复验（工单 06 Q4：手工建的池没有这道闸门）
    assert "_verify_no_native_flows" in called


def test_main_has_the_two_idp_isolation_flags():
    """隔离旗标必须在 CLI 上（裁定 2）。默认 None ⇒ 生产运行时取 config 值。"""
    import inspect
    src = inspect.getsource(dp.main)
    for flag in ("--idp-pool-name", "--idp-domain-prefix"):
        assert flag in src, f"main() 缺旗标 {flag}"


def test_main_prints_the_two_admin_create_user_commands():
    """内置模式下脚本必须把建户那两条命令打出来（含真实 pool id）。

    少第二条（admin-set-user-password --permanent）的后果实测过：用户停在
    FORCE_CHANGE_PASSWORD，hosted UI 首登多一屏强制改密。裁定 3 决定建户不进
    脚本，那么"把命令递到手上"就是这条路唯一的降门槛手段。
    """
    import inspect
    src = inspect.getsource(dp.main)
    assert "admin-create-user" in src
    assert "admin-set-user-password" in src and "--permanent" in src
    assert "email_verified,Value=true" in src        # require_email_verified 的前提
    assert "SUPPRESS" in src


# ---------------------------------------------------------------------------
# 工单 07：出厂 config.ini.example 必须过自己的 preflight
# ---------------------------------------------------------------------------

def _example_idp() -> dict:
    """出厂 `.example` 的 [IdP] 段，**裸 ConfigParser**（与生产同款：行内注释留在值里）。"""
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).resolve().parents[3] / "site-builder" / "config.ini.example")
    assert cfg.sections(), ".example 读空了——本条空转"
    return dict(cfg["IdP"])


def test_shipped_example_declares_the_three_mode_keys():
    idp = _example_idp()
    for key in ("mode", "cognito_user_pool_name", "cognito_domain_prefix"):
        assert key in idp, f".example 的 [IdP] 缺 {key}"


def test_shipped_example_passes_its_own_preflight():
    """**出厂模板必须过自己的 preflight。**

    这条比它看起来重要：`cognito_user_pool_name` 若出厂就带一个推荐值
    （`site-builder-idp`），而 mode 是 external-oidc ⇒ 判据③（两套字段混填）当场
    把每个采用者的第一次部署打红。所以两个 cognito_* 键出厂**必须为空**，
    推荐值只写在注释里。
    """
    idp = _example_idp()
    mode = dp.idp_mode(idp)
    assert mode == dp.IDP_MODE_EXTERNAL, ".example 的出厂模式必须是 external-oidc"
    dp.check_idp_section(idp, mode)          # 不得抛


def test_example_switched_to_cognito_admin_passes_preflight():
    """采用者按注释填完之后也必须过：把 mode 换成 cognito-admin、补两个键、
    清空三个派生字段——这就是 DEPLOY.md 第 3 条路要他做的全部编辑。"""
    idp = dict(_example_idp(), mode="cognito-admin", provider_name="CognitoSource",
               cognito_user_pool_name="site-builder-idp",
               cognito_domain_prefix="acme-idp-2026",
               issuer="", client_id="", client_secret="")
    assert dp.idp_mode(idp) == dp.IDP_MODE_COGNITO
    dp.check_idp_section(idp, dp.IDP_MODE_COGNITO)      # 不得抛


def test_example_mode_keys_have_no_inline_comments():
    """行内注释会被裸 ConfigParser 并进值 ⇒ `mode = cognito-admin  # 内置` 虽然被
    `_clean` 兜住了，但 cognito_user_pool_name 带注释就会拼出一个带空格与井号的
    池名。注释一律写在**上一行**（与 test_example_config_consistency 同一条纪律）。"""
    idp = _example_idp()
    for key in ("mode", "cognito_user_pool_name", "cognito_domain_prefix"):
        assert "#" not in idp[key] and ";" not in idp[key], f"{key} = {idp[key]!r}"


# ---------------------------------------------------------------------------
# 工单 07 的 /code-review findings（#2 / #3 / #4 / #6）——都落在本地 preflight
# ---------------------------------------------------------------------------

def test_isolation_flags_require_a_non_production_platform_pool():
    """**finding #2（最危险的一条）**：守卫原先只做了一个方向。

    反向组合无人拦：默认 `--pool-name`（= 生产平台池）+ 两个 --idp-* 旗标 ⇒
    脚本会建出 spike IdP 池、派生它的 issuer/client，然后对**生产平台池**跑
    `update_identity_provider`，把线上那个 OIDC provider 指向一个**没有任何用户**
    的池 —— 全部生产用户的登录当场断，与 `--pool-name` docstring 早就警告过的
    是同一类事故，只是从新开的这道门进来。
    """
    with pytest.raises(SystemExit, match="--pool-name"):
        _resolve(idp_pool_name="spike-idp", idp_domain_prefix="spike-2026")
    # 单给一个旗标同样拒（否则"只给池名"会静默走 config 的域名前缀）
    with pytest.raises(SystemExit, match="--pool-name"):
        _resolve(idp_pool_name="spike-idp")


def test_production_run_without_flags_still_works():
    """正对照：生产运行（默认 pool-name、不给旗标）必须照常从 config 取值。
    上一条守卫收紧后最容易误伤的就是它。"""
    assert _resolve() == ("site-builder-idp", "acme-idp-2026")


def _resolve(**over):
    """resolve_idp_pool_names 的默认合法调用（生产运行形态），按需覆盖。"""
    kw = {"pool_name": dp.POOL_NAME, "platform_domain_prefix": "site-builder-auth",
          "idp_pool_name": None, "idp_domain_prefix": None, "idp": _idp_cognito()}
    kw.update(over)
    return dp.resolve_idp_pool_names(**kw)


@pytest.mark.parametrize("key,value", [
    ("cognito_user_pool_name", "site-builder-users"),
    ("cognito_domain_prefix", "site-builder-auth"),
])
def test_built_in_idp_pool_must_not_be_the_platform_pool(key, value):
    """**finding #4**：没人比较过"内置 IdP 池"与"平台池"是不是同一个。

    `cognito_user_pool_name = site-builder-users` 时 preflight 全过（按名字与按
    域名前缀都解析到同一个池——平台池），`_ensure_idp_pool` 于是对**平台池**跑
    `update_user_pool`，接着 `_verify_idp_pool_boundaries` 因平台池的 email 是
    `Mutable: True` 而中止，**而那条错误文案写着"只能删掉这个池重建"**——照做
    就是删掉生产池与它全部的联邦用户。一行本地不等式就消灭整个场景。
    """
    with pytest.raises(SystemExit, match="平台池"):
        _resolve(idp=_idp_cognito(**{key: value}))


@pytest.mark.parametrize("flag,value,match", [
    ("idp_pool_name", "site-builder-users", "平台池"),
    ("idp_pool_name", "sb-spike", "平台池"),          # 本次运行的平台池
    ("idp_domain_prefix", "sb-spike-2026", "前缀同值"),   # 本次运行的平台前缀
])
def test_flags_cannot_bypass_the_platform_pool_check(flag, value, match):
    """**第二轮 /code-review finding #1**：判据放错层，旗标正好绕过它。

    上一轮把"内置池 ≠ 平台池"判在 config 值上，而部署用的是
    `resolve_idp_pool_names` 的**返回值**——旗标胜过 config ⇒
    `--pool-name sb-spike --idp-pool-name site-builder-users` 时 config 的
    `site-builder-idp` 与 `sb-spike` 不同、判据放行，然后 `_ensure_idp_pool` 照旧
    对**生产平台池**跑 `update_user_pool`，读回复验再抛出那句"只能删掉这个池重建"
    ——finding #4 声称消灭的灾难场景原地复活。所以判据必须判解析后的值。
    """
    kw = {"pool_name": "sb-spike", "platform_domain_prefix": "sb-spike-2026",
          "idp_pool_name": "spike-idp", "idp_domain_prefix": "spike-2026"}
    kw[flag] = value                     # 把生产名字粘进隔离旗标里
    with pytest.raises(SystemExit, match=match):
        _resolve(**kw)


def test_a_prefix_owned_by_another_pool_is_caught_by_the_read_only_preflight():
    """本地判据只能比"本次运行的平台前缀"——隔离运行**合法地**覆盖了 --domain-prefix，
    所以"生产平台池的前缀"在本地无从得知（采用者的生产前缀是他自己配的）。

    那一种由 `preflight_idp_pool` 的判据 ④ 兜住：按前缀反查到的池 ≠ 按名字找到的池
    ⇒ fail closed（见 test_preflight_fails_closed_when_domain_belongs_to_another_pool）。
    它是一次 AWS **读**，仍在第一次写之前。这条用例把这个分工写下来，免得将来有人
    以为本地判据漏了一种情形而去加一个用错误常量比较的检查。
    """
    assert _resolve(pool_name="sb-spike", platform_domain_prefix="sb-spike-2026",
                    idp_pool_name="spike-idp",
                    idp_domain_prefix="site-builder-auth") == \
        ("spike-idp", "site-builder-auth")


def test_resolved_idp_pool_name_cannot_be_the_production_pool_even_when_isolated():
    """即使平台池已隔离，把内置 IdP 池指到**生产**平台池名上同样要拒
    （那是 finding #1 举的那条具体命令）。"""
    with pytest.raises(SystemExit, match="生产平台池|平台池"):
        _resolve(pool_name="sb-spike", platform_domain_prefix="sb-spike-2026",
                 idp_pool_name=dp.POOL_NAME, idp_domain_prefix="spike-2026")


@pytest.mark.parametrize("field", ["provider_name", "issuer", "client_id", "scopes"])
def test_inline_comments_on_aws_bound_keys_are_rejected(field):
    """**finding #3**：判据过 `_clean`、下发用原值 ⇒ 判据看到的和 AWS 看到的不是同一个串。

    `provider_name = GoogleOIDC  # 也写进 trusted_idps` 会过 ⓿（cleaned 值不是保留名），
    然后平台池、托管域名、整个内置 IdP 池与 client 都建完，最后在
    `create_identity_provider(ProviderName="GoogleOIDC  # 也写进 trusted_idps")`
    因名字正则失败 —— **正是把保留名校验前移要防的那个"停在中途"**。

    修法取"拒"而不是"替他剥掉"：与 `router/infrastructure/stack.py` 对
    `require_idp_claim` / `trusted_idps` 的既有态度一致（那边也是直接拒行内注释）。
    `mode` 不在此列——它只在本进程内判分支、从不下发给 AWS，见下一条。
    """
    idp = {"provider_name": "Okta", "issuer": "https://okta.example/",
           "client_id": "c", "client_secret": "s", "scopes": "openid email profile"}
    idp[field] = idp[field] + "  # 顺手写个注释"
    with pytest.raises(SystemExit, match=field):
        dp.check_idp_section(idp, dp.IDP_MODE_EXTERNAL)


def test_mode_still_tolerates_inline_comments_because_it_never_reaches_aws():
    """`mode` 的行内注释仍然容忍（既有用例 test_idp_mode_tolerates_inline_comments
    钉着）：它只用来判分支，不会变成任何 AWS 参数。上一条的判据必须不误伤它。"""
    dp.check_idp_section({"mode": "external-oidc  # 已有 IdP", "provider_name": "Okta",
                          "issuer": "https://okta.example/", "client_id": "c",
                          "client_secret": "s"}, dp.IDP_MODE_EXTERNAL)   # 不得抛


@pytest.mark.parametrize("prefix", ["Acme-IdP", "acme_idp", "-acme", "acme-",
                                    "a" * 64, "acme.idp"])
def test_malformed_domain_prefix_fails_locally_not_with_a_traceback(prefix):
    """**finding #6**：畸形前缀让只读 preflight 以 botocore traceback 收场。

    Cognito 的 prefix domain 只允许小写字母 / 数字 / 连字符，首尾不能是连字符，
    ≤63 字符。`describe_user_pool_domain(Domain="Acme-IdP")` 抛
    `InvalidParameterException`，而 `_pool_id_for_domain` 只捕
    `ResourceNotFoundException` ⇒ 那一步的全部意义（"在第一次 AWS 写之前带着可读
    文案 fail closed"）落空。格式判断是纯本地的，前移到 ⓿ 与其它判据同处。
    """
    with pytest.raises(SystemExit, match="cognito_domain_prefix"):
        _resolve(idp=_idp_cognito(cognito_domain_prefix=prefix))


@pytest.mark.parametrize("prefix", ["acme-idp-2026", "a", "site-builder-idp",
                                    "x" * 63, "abc123"])
def test_valid_domain_prefixes_are_accepted(prefix):
    """负对照：合法前缀不许被误拒——多拒一个就是用一条不存在的限制挡住采用者。"""
    assert _resolve(idp=_idp_cognito(cognito_domain_prefix=prefix))[1] == prefix


# ---------------------------------------------------------------------------
# 工单 07 的 /code-review finding #1：托管域名是异步的，provider 不能抢在它前面建
# ---------------------------------------------------------------------------

def test_wait_for_domain_polls_until_active():
    """**finding #1**：prefix domain 是异步创建的（`Status: CREATING`）。

    Cognito 建 OIDC provider 时按 `oidc_issuer` 去取
    `/.well-known/openid-configuration` 解析 authorize / token / userInfo 端点，
    而那份文档里的这三个端点**只有池有了域名之后才存在**。②b 建完域名到 ③ 建
    provider 只隔几个 API 调用 —— 手工路径有人工停顿，脚本没有。撞上的后果是
    静默的：脚本退 0，第一次真实登录才在 /oauth2/authorize 那一跳炸。

    **本票的真机运行不能作为"没有这个竞态"的证据**：那次的时序是建域名 → 建
    provider → 读回 → **幂等复跑（update_identity_provider）** → 登录，而那次
    update 会重新解析端点 ⇒ 即使首次创建拿到空端点也被盖好了。
    """
    calls = []

    class _Cog:
        def describe_user_pool_domain(self, Domain):
            calls.append(Domain)
            status = "CREATING" if len(calls) < 3 else "ACTIVE"
            return {"DomainDescription": {"Status": status}}

    dp._wait_for_domain_active(_Cog(), "acme-idp-2026", sleep=lambda _s: None)
    assert len(calls) == 3, f"应当轮询到 ACTIVE 才返回，实际 {len(calls)} 次"


def test_wait_for_domain_gives_up_loudly_instead_of_racing_on():
    """超时必须**响亮失败**而不是"算了继续建 provider"：继续走的结果正是那个
    静默坏配置（provider 建成功、端点是空的）。"""
    class _Cog:
        def describe_user_pool_domain(self, Domain):
            return {"DomainDescription": {"Status": "CREATING"}}

    with pytest.raises(SystemExit, match="ACTIVE"):
        dp._wait_for_domain_active(_Cog(), "acme-idp-2026", attempts=3,
                                   sleep=lambda _s: None)


def test_wait_for_domain_tolerates_a_missing_status_field():
    """Cognito 不返回 Status 的形态（老 API 行为 / 空 DomainDescription）不该把部署
    卡死在轮询里——查不到状态时按"未就绪"计入重试，用尽后仍是响亮失败。"""
    class _Cog:
        def describe_user_pool_domain(self, Domain):
            return {"DomainDescription": {}}

    with pytest.raises(SystemExit, match="ACTIVE"):
        dp._wait_for_domain_active(_Cog(), "acme-idp-2026", attempts=2,
                                   sleep=lambda _s: None)


def test_main_waits_for_the_idp_domain_before_building_the_provider():
    """次序守卫：`_wait_for_domain_active` 必须排在 `_ensure_oidc_idp` 之前
    （否则这个修复只是"函数存在"，竞态照旧）。"""
    called = _main_call_order()
    assert "_wait_for_domain_active" in called, "main() 没等域名 ACTIVE"
    assert called.index("_wait_for_domain_active") < called.index("_ensure_oidc_idp")


def test_the_two_branding_docstrings_state_their_scope():
    """**finding #5**：两处 docstring 对"classic hosted UI 要不要 branding"给出过
    相反的**实测**结论，读者无从判断哪条管事。

    真相是它们说的不是同一件事：`_ensure_branding` 那条实测于 **managed login v2**
    （平台池），`_ensure_domain` 那条实测于 **LITE + classic hosted UI**（内置 IdP
    池，`/login` 200 带密码表单）。若旧那条其实才对，第三条接入路径就会带着一个
    打不开的登录页发货 —— 而那种失败只在浏览器里看得见，任何测试与闸门都抓不到。
    所以两条都必须自报作用域。
    """
    import inspect
    branding = inspect.getdoc(dp._ensure_branding)
    domain = inspect.getdoc(dp._ensure_domain)
    assert "managed login v2" in branding, "_ensure_branding 没写清它只管 v2"
    assert "classic hosted UI" in branding and "相反" in branding, \
        "_ensure_branding 没点出 classic hosted UI 是相反的情形"
    assert "classic hosted UI" in domain and "不需要" in domain, \
        "_ensure_domain 没写清 classic hosted UI 不需要 branding"
    # 且内置 IdP 池确实不进 _ensure_branding（"刻意不是漏了"要有代码背书）
    src = inspect.getsource(dp.main)
    assert src.count("_ensure_branding(") == 1, \
        "_ensure_branding 被调了多于一次——内置 IdP 池不该进去"


@pytest.mark.parametrize("prefix", ["acme-cognito-idp", "aws-corp-idp",
                                    "amazon-idp", "myaws"])
def test_domain_prefix_reserved_words_are_rejected_locally(prefix):
    """**第二轮 finding #2**：Cognito 的托管域名前缀里不许出现 `aws` / `amazon` /
    `cognito`（AWS 文档）。`acme-cognito-idp` 是很自然会被写出来的取名，它过了
    字符集/长度校验，到 ②b 建域名才失败——而那时平台池、平台域名与 IdP 池都建好了，
    脚本停在中途。纯本地一行判断就挡掉。"""
    with pytest.raises(SystemExit, match="保留词"):
        _resolve(idp=_idp_cognito(cognito_domain_prefix=prefix))


def test_wait_for_domain_fails_fast_on_terminal_failed_status():
    """**第二轮 finding #3**：`FAILED` 是终态，再轮询 200 秒也不会变。
    早退并把真实原因（前缀被占 / 含保留词 / 配额）指出来，而不是让操作者等完超时
    再看到一句"仍未 ACTIVE"。"""
    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_user_pool_domain(self, Domain):
            return {"DomainDescription": {"Status": "FAILED"}}

    with pytest.raises(SystemExit, match="FAILED"):
        dp._wait_for_domain_active(_Cog(), "acme-idp-2026", sleep=lambda _s: None)


def test_wait_for_domain_survives_resource_not_found():
    """紧跟 create_user_pool_domain 之后可能还查不到（与 _pool_id_for_domain 同一条
    防御）。裸 traceback 会让这一步失去"响亮而可读地失败"的全部意义。"""
    calls = []

    class _Cog:
        class exceptions:
            class ResourceNotFoundException(Exception):
                pass

        def describe_user_pool_domain(self, Domain):
            calls.append(Domain)
            if len(calls) < 2:
                raise self.exceptions.ResourceNotFoundException(Domain)
            return {"DomainDescription": {"Status": "ACTIVE"}}

    dp._wait_for_domain_active(_Cog(), "acme-idp-2026", sleep=lambda _s: None)
    assert len(calls) == 2


def test_idp_flag_help_says_isolation_only():
    """**第二轮 finding #4**：反向守卫加上之后，"默认取 config"这句 help 会把操作者
    引向一个 SystemExit（比如配置的前缀被全局占用、想只覆盖前缀重跑一次）。
    help 必须自己说清"仅隔离运行可用"。"""
    import inspect
    src = inspect.getsource(dp.main)
    assert src.count("仅隔离运行可用") == 2, "两个旗标的 help 都要写明"
