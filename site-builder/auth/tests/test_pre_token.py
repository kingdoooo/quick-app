import pre_token_email as pt


def _event(attrs, trigger="TokenGeneration_HostedAuth"):
    return {"request": {"userAttributes": attrs}, "response": {},
            "triggerSource": trigger}


import pytest


def _claims(ev, container):
    return ev["response"]["claimsAndScopeOverrideDetails"][container][
        "claimsToAddOrOverride"]


def test_auth_via_carries_trigger_source():
    """auth_via 必须反映本次 triggerSource——idp 分辨不出原生认证。"""
    ev = pt.handler({"request": {"userAttributes": {
        "email": "a@x.com",
        "identities": '[{"providerName":"Feishu","userId":"u1"}]'}},
        "response": {},
        "triggerSource": "TokenGeneration_Authentication"}, None)
    for c in ("idTokenGeneration", "accessTokenGeneration"):
        assert _claims(ev, c)["auth_via"] == "TokenGeneration_Authentication"
        assert _claims(ev, c)["idp"] == "Feishu"   # 静态属性仍在，正是问题所在


def test_hosted_auth_is_a_trusted_source():
    ev = pt.handler({"request": {"userAttributes": {"email": "a@x.com"}},
                     "response": {},
                     "triggerSource": "TokenGeneration_HostedAuth"}, None)
    assert (_claims(ev, "idTokenGeneration")["auth_via"]
            in pt.TRUSTED_AUTH_SOURCES)


@pytest.mark.parametrize("container", ["idTokenGeneration",
                                       "accessTokenGeneration"])
def test_injects_email_and_idp_into_both_containers(container):
    """两个容器都要写：id token 供 auth 签会话，access token 供 MCP 网关。

    只写 accessTokenGeneration 会让会话 JWT 永远没有 idp——Edge 的
    REQUIRE_IDP_CLAIM 一开，全部合法用户被 302 拦死（spec §3.5）。
    """
    ev = pt.handler(_event({
        "email": "a@x.com",
        "identities": '[{"providerName":"Feishu","userId":"u1"}]'}), None)
    assert _claims(ev, container) == {
        "email": "a@x.com", "idp": "Feishu",
        "auth_via": "TokenGeneration_HostedAuth",
        # 属性缺失 → 空串 → 消费方按未验证处理（fail-closed）
        "email_verified": ""}


def test_local_user_gets_no_idp_claim():
    """本地用户没有 idp claim——这正是 Edge 要拦的信号（spec §3.5）。

    auth_via 仍会写入（它记录的是本次 token 怎么来的，与账号是否联邦无关）。
    """
    ev = pt.handler(_event({"email": "local@x.com"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        claims = _claims(ev, container)
        assert claims == {"email": "local@x.com",
                          "auth_via": "TokenGeneration_HostedAuth",
                          "email_verified": ""}
        assert "idp" not in claims


def test_malformed_identities_does_not_raise():
    ev = pt.handler(_event({"email": "a@x.com", "identities": "{not json"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        assert _claims(ev, container) == {
            "email": "a@x.com", "auth_via": "TokenGeneration_HostedAuth",
            "email_verified": ""}


def test_no_attributes_still_records_auth_via():
    """没有任何用户属性时也要写 auth_via——Edge 靠它判断来源，缺了就拦不住。

    （实现是"claims 非空就写"，而 auth_via 总会被填上，所以 response
    一定会被改写；不要断言 response 原样不变。）
    """
    ev = pt.handler(_event({}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        claims = _claims(ev, container)
        assert claims == {"auth_via": "TokenGeneration_HostedAuth",
                          "email_verified": ""}
        assert "email" not in claims


def test_missing_trigger_source_yields_empty_auth_via():
    """triggerSource 缺失（异常事件形态）→ auth_via 为空串 → 下游按不可信处理。"""
    ev = pt.handler({"request": {"userAttributes": {"email": "a@x.com"}},
                     "response": {}}, None)
    assert _claims(ev, "idTokenGeneration")["auth_via"] == ""


def test_token_containers_are_independent_objects():
    """两个容器不能共享同一个 dict。

    共享时任何下游（或未来的本函数改动）改一个容器的 claims 会静默改到另一个，
    而 id token 与 access token 的消费方不同（auth 服务 / MCP 网关）——
    这种耦合出问题时极难定位。实现里用 dict(override) 各建一份。
    """
    ev = pt.handler(_event({"email": "a@x.com"}), None)
    details = ev["response"]["claimsAndScopeOverrideDetails"]
    assert (details["idTokenGeneration"]
            is not details["accessTokenGeneration"])
    details["idTokenGeneration"]["claimsToAddOrOverride"]["probe"] = 1
    assert "probe" not in details["accessTokenGeneration"]["claimsToAddOrOverride"]


# --- email_verified 必须注入 access token（Codex re-review P1） ---
# Cognito 默认只把它放 id_token，而 MCP 网关只收 access token——不注入的话
# MCP 侧那道 email_verified 检查永远看不到值，等于不存在。

@pytest.mark.parametrize("container", ["idTokenGeneration",
                                       "accessTokenGeneration"])
def test_email_verified_injected_into_both_containers(container):
    ev = pt.handler(_event({"email": "a@x.com", "email_verified": "true"}), None)
    assert _claims(ev, container)["email_verified"] == "true"


@pytest.mark.parametrize("raw,expected", [
    ("true", "true"), ("True", "true"), ("false", "false"), ("", ""),
])
def test_email_verified_normalized_to_lowercase(raw, expected):
    """统一小写字符串：消费方（auth / MCP）只需一套判定，避免两处理解不一致。"""
    ev = pt.handler(_event({"email": "a@x.com", "email_verified": raw}), None)
    assert _claims(ev, "accessTokenGeneration")["email_verified"] == expected
