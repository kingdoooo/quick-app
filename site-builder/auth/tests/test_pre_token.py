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
    expected = {"email": "a@x.com", "idp": "Feishu",
                "auth_via": "TokenGeneration_HostedAuth"}
    if container == "accessTokenGeneration":
        # access token 始终显式写布尔（Cognito 不会自己放该 claim）
        expected["email_verified"] = False
    # id_token 侧属性缺失时不覆盖 Cognito 自己的值
    assert _claims(ev, container) == expected


def test_local_user_gets_no_idp_claim():
    """本地用户没有 idp claim——这正是 Edge 要拦的信号（spec §3.5）。

    auth_via 仍会写入（它记录的是本次 token 怎么来的，与账号是否联邦无关）。
    """
    ev = pt.handler(_event({"email": "local@x.com"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        claims = _claims(ev, container)
        expected = {"email": "local@x.com",
                    "auth_via": "TokenGeneration_HostedAuth"}
        if container == "accessTokenGeneration":
            expected["email_verified"] = False
        assert claims == expected
        assert "idp" not in claims


def test_malformed_identities_does_not_raise():
    ev = pt.handler(_event({"email": "a@x.com", "identities": "{not json"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        expected = {"email": "a@x.com",
                    "auth_via": "TokenGeneration_HostedAuth"}
        if container == "accessTokenGeneration":
            expected["email_verified"] = False
        assert _claims(ev, container) == expected


def test_no_attributes_still_records_auth_via():
    """没有任何用户属性时也要写 auth_via——Edge 靠它判断来源，缺了就拦不住。

    （实现是"claims 非空就写"，而 auth_via 总会被填上，所以 response
    一定会被改写；不要断言 response 原样不变。）
    """
    ev = pt.handler(_event({}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        claims = _claims(ev, container)
        expected = {"auth_via": "TokenGeneration_HostedAuth"}
        if container == "accessTokenGeneration":
            expected["email_verified"] = False
        assert claims == expected
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


# --- email_verified 的类型与容器差异（Codex re-review P2） ---
# email_verified 是 OIDC Core 标准 claim，类型是 **boolean**。
# 之前这里写字符串 "true"，会把 id_token 里 Cognito 原本的布尔覆盖成字符串
# ——本项目 _is_verified() 兼容字符串所以自家测试全绿，但严格的 OIDC
# consumer 可能拒绝或误解。这些用例断言 **JSON 类型**，不只是值。

def test_email_verified_is_json_boolean_not_string():
    ev = pt.handler(_event({"email": "a@x.com", "email_verified": "true"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        v = _claims(ev, container)["email_verified"]
        assert v is True, f"{container}: {v!r}"
        assert not isinstance(v, str), f"{container} 写成了字符串"


def test_access_token_always_carries_boolean_even_when_false():
    """access token 侧必须始终显式写：Cognito 不会自己放该 claim，
    而 MCP 的检查是 fail-closed——不写等于永远拒绝。
    写 False 也让"确实未验证"与"触发器没跑"（claim 缺失）可区分。"""
    ev = pt.handler(_event({"email": "a@x.com", "email_verified": "false"}), None)
    v = _claims(ev, "accessTokenGeneration")["email_verified"]
    assert v is False and not isinstance(v, str)


def test_id_token_not_overridden_when_attribute_absent_or_false():
    """id_token 侧不覆盖 Cognito 自己的 email_verified。

    覆盖没有收益，还会把标准 claim 的来源变成我们的触发器，多一层排查。
    """
    for attrs in ({"email": "a@x.com"},
                  {"email": "a@x.com", "email_verified": "false"}):
        ev = pt.handler(_event(attrs), None)
        assert "email_verified" not in _claims(ev, "idTokenGeneration")


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("True", True), (" true ", True), (True, True),
    ("false", False), ("", False), ("1", False), ("yes", False), (None, False),
])
def test_attr_true_is_fail_closed(raw, expected):
    """只认真值。与 login_handler._is_verified / server._is_verified 同语义。"""
    assert pt._attr_true(raw) is expected


def test_containers_do_not_share_claims_object():
    """两个容器的 dict 必须独立——共享对象时改一处会静默影响另一处。"""
    ev = pt.handler(_event({"email": "a@x.com", "email_verified": "true"}), None)
    d = ev["response"]["claimsAndScopeOverrideDetails"]
    assert (d["idTokenGeneration"]["claimsToAddOrOverride"]
            is not d["accessTokenGeneration"]["claimsToAddOrOverride"])


def test_all_three_verification_predicates_stay_identical():
    """pre_token / login_handler / MCP server 三处判定必须字节级一致。

    它们分属三个部署单元（触发器 / auth Lambda / AgentCore 容器），无法共享
    模块，只能靠这个测试防漂移。任一处放宽（比如接受 "1"）都会让另两处的
    fail-closed 变成纸面约定：token 在一处被认作已验证、在另一处被拒。
    """
    import re
    from pathlib import Path

    root = Path(__file__).parents[2]
    targets = [("auth/pre_token_email.py", "_attr_true"),
               ("auth/login_handler.py", "_is_verified"),
               ("mcp/server.py", "_is_verified")]
    exprs = set()
    for rel, fn in targets:
        src = (root / rel).read_text()
        m = re.search(rf"def {fn}\(value\)[^\n]*\n(?:.*?\n)*?    return ([^\n]+)\n",
                      src)
        assert m, f"{rel} 里找不到 {fn} 的 return"
        exprs.add(m.group(1).strip())
    assert len(exprs) == 1, f"三处判定已漂移: {exprs}"
