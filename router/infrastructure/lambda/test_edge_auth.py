import base64, hashlib, hmac, json, time
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
_SRC = (Path(__file__).parent / "origin_request.py").read_text()
for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
             "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
             "{{JWT_SECRET}}": "test-secret", "{{BASE_DOMAIN}}": "example.com",
             "{{REQUIRE_IDP_CLAIM}}": "true",
             "{{TRUSTED_IDPS}}": "Feishu,Okta"}.items():
    _SRC = _SRC.replace(k, v)
(Path(__file__).parent / "_edge_auth_testable.py").write_text(_SRC)
import _edge_auth_testable as orq


def _jwt(email="a@x.com", name="Alice", exp_delta=3600, secret="test-secret",
         idp="Feishu", auth_via="TokenGeneration_HostedAuth"):
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"name": name, "exp": int(time.time()) + exp_delta}
    if email is not None:  # email=None -> payload 完全省略 email 字段
        payload["email"] = email
    if idp:
        payload["idp"] = idp
    if auth_via:
        payload["auth_via"] = auth_via
    p = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


ROUTE_AUTH = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x",
              "api_target": "", "require_auth": True, "allowed_users": "org",
              "owner": "o@x.com"}


def _req(uri="/", cookie=None, extra_headers=None):
    headers = {"host": [{"key": "Host", "value": "app-x.example.com"}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    headers.update(extra_headers or {})
    return {"uri": uri, "querystring": "", "method": "GET", "headers": headers}


def test_no_cookie_redirects_to_login():
    resp = orq._check_auth(_req(), dict(ROUTE_AUTH), "app-x.example.com")
    assert resp["status"] == "302"
    loc = resp["headers"]["location"][0]["value"]
    assert loc.startswith("https://auth.example.com/login?redirect=")


def test_redirect_preserves_querystring():
    r = _req(uri="/page")
    r["querystring"] = "tab=2&q=x"
    resp = orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    loc = resp["headers"]["location"][0]["value"]
    import urllib.parse as up
    target = up.unquote(loc.split("redirect=")[1])
    assert target == "https://app-x.example.com/page?tab=2&q=x"


def test_valid_cookie_passes_and_injects_headers():
    r = _req(cookie=f"sb_session={_jwt()}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None
    assert r["headers"]["x-user-email"][0]["value"] == "a@x.com"


def test_expired_cookie_redirects():
    r = _req(cookie=f"sb_session={_jwt(exp_delta=-10)}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")["status"] == "302"


def test_wrong_signature_redirects():
    r = _req(cookie=f"sb_session={_jwt(secret='other')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")["status"] == "302"


def test_allowlist_rejects_outsider():
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    r = _req(cookie=f"sb_session={_jwt(email='a@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_allowlist_admits_member_and_owner():
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    assert orq._check_auth(_req(cookie=f"sb_session={_jwt(email='vip@x.com')}"),
                           route, "app-x.example.com") is None
    assert orq._check_auth(_req(cookie=f"sb_session={_jwt(email='o@x.com')}"),
                           route, "app-x.example.com") is None


def test_spoofed_user_header_stripped():
    r = _req(cookie=f"sb_session={_jwt()}",
             extra_headers={"x-user-email": [{"key": "x-user-email", "value": "fake@x.com"}]})
    orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    assert r["headers"]["x-user-email"][0]["value"] == "a@x.com"


def test_token_missing_email_treated_as_unauthenticated():
    # 签名正确但 payload 无 email：应当 302 当作未登录，而非 KeyError / 注入 None
    r = _req(cookie=f"sb_session={_jwt(email=None)}")
    resp = orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    assert resp["status"] == "302"
    assert "x-user-email" not in r["headers"]

    # 名单分支同样不应抛 KeyError
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    r2 = _req(cookie=f"sb_session={_jwt(email=None)}")
    assert orq._check_auth(r2, route, "app-x.example.com")["status"] == "302"


def test_no_auth_route_strips_spoofed_headers_too():
    route = {**ROUTE_AUTH, "require_auth": False}
    r = _req(extra_headers={"x-user-email": [{"key": "x-user-email", "value": "fake@x.com"}]})
    assert orq._check_auth(r, route, "app-x.example.com") is None
    assert "x-user-email" not in r["headers"]


# ---- 平台会话 cookie 不得下发给不可信站点 origin ----

SITE_ROUTE = {**ROUTE_AUTH, "route_mode": "split",
              "api_target": "https://a.lambda-url.us-east-1.on.aws"}
PLATFORM_ROUTE = {"subdomain": "auth", "site_id": "auth-service",
                  "route_mode": "api-only", "static_prefix": "",
                  "api_target": "https://p.lambda-url.us-east-1.on.aws",
                  "require_auth": False, "allowed_users": "org", "owner": "platform"}


def _route(request, route):
    with patch.object(orq, "_add_sigv4_auth"), patch.object(orq, "_add_s3_sigv4_auth"):
        return orq._route_request(request, dict(route))


def test_session_cookie_not_forwarded_to_site_origin():
    """站点代码可读到会话 JWT 即可重放到其他站点（顶域 cookie 共享登录）。"""
    r = _req(uri="/api/x", cookie=f"sb_session={_jwt()}")
    assert orq._check_auth(r, dict(SITE_ROUTE), "app-x.example.com") is None
    _route(r, SITE_ROUTE)
    assert "cookie" not in r["headers"]
    # 身份仍通过注入头传递给站点
    assert r["headers"]["x-user-email"][0]["value"] == "a@x.com"


def test_site_own_cookies_survive_reserved_strip():
    r = _req(uri="/api/x", cookie=f"theme=dark; sb_session={_jwt()}; cart=7")
    orq._check_auth(r, dict(SITE_ROUTE), "app-x.example.com")
    _route(r, SITE_ROUTE)
    forwarded = r["headers"]["cookie"][0]["value"]
    assert "sb_session" not in forwarded
    assert "theme=dark" in forwarded and "cart=7" in forwarded


def test_platform_route_keeps_session_cookie_and_gets_mark():
    """auth-service 需要读 cookie（/logout）并被允许签发平台 cookie。

    平台判定由 lambda_handler 按请求 host 算出（见 _is_platform_route），
    所以这里必须把那个键带上——直接调 _route_request 时它不会自己出现。
    这正是防线所在：路由 item 里写什么都不影响判定。
    """
    r = _req(uri="/logout", cookie=f"sb_session={_jwt()}")
    orq._check_auth(r, dict(PLATFORM_ROUTE), "auth.example.com")
    _route(r, {**PLATFORM_ROUTE, orq._PLATFORM_KEY: True})
    assert "sb_session" in r["headers"]["cookie"][0]["value"]
    assert orq.PLATFORM_MARK in r["headers"]


def test_spoofed_platform_mark_stripped_on_site_route():
    """客户端伪造平台标记不得让站点获得签发平台 cookie 的资格。"""
    r = _req(uri="/api/x", cookie=f"sb_session={_jwt()}",
             extra_headers={orq.PLATFORM_MARK: [{"key": orq.PLATFORM_MARK, "value": "1"}]})
    orq._check_auth(r, dict(SITE_ROUTE), "app-x.example.com")
    _route(r, SITE_ROUTE)
    assert orq.PLATFORM_MARK not in r["headers"]


def test_s3_signing_includes_content_sha256():
    """S3 要求 x-amz-content-sha256；通用 SigV4Auth 不生成该头会 400 InvalidRequest。"""
    from botocore.credentials import Credentials
    orq.credentials = Credentials("AK", "SK", "TOKEN")
    request = {"uri": "/sites/x/job/index.html", "headers": {}}
    orq._add_s3_sigv4_auth(request, "b.s3.us-east-1.amazonaws.com", request["uri"])
    assert "x-amz-content-sha256" in request["headers"]
    signed = request["headers"]["authorization"][0]["value"]
    assert "x-amz-content-sha256" in signed  # 且参与签名，不只是附带


def test_deser_handles_list_of_strings():
    out = orq._deser({"allowed_users": {"L": [{"S": "a@x.com"}, {"S": "b@x.com"}]},
                      "require_auth": {"BOOL": True},
                      "owner": {"S": "o@x.com"}})
    assert out["allowed_users"] == ["a@x.com", "b@x.com"]
    assert out["require_auth"] is True
    assert out["owner"] == "o@x.com"


def test_deser_handles_empty_list():
    assert orq._deser({"collaborators": {"L": []}})["collaborators"] == []


def test_deser_handles_number():
    assert orq._deser({"n": {"N": "42"}})["n"] == 42


def test_native_list_allowlist_admits_member():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='vip@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_native_list_allowlist_rejects_outsider():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='nope@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_collaborator_admitted_by_named_allowlist():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"],
             "collaborators": ["c@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='c@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None
    assert r["headers"]["x-user-email"][0]["value"] == "c@x.com"


def test_non_collaborator_still_rejected():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"],
             "collaborators": ["c@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='stranger@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_legacy_json_string_allowlist_still_works():
    """迁移期间路由表里可能还是一期的 JSON 字符串形态。"""
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    r = _req(cookie=f"sb_session={_jwt(email='vip@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_unparsable_allowlist_is_fail_closed():
    route = {**ROUTE_AUTH, "allowed_users": "{not json"}
    r = _req(cookie=f"sb_session={_jwt(email='a@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_org_route_admits_any_email_from_trusted_idp():
    """org 的语义是"来自可信 IdP 的任何人"，不是"任何有效会话"。"""
    r = _req(cookie=f"sb_session={_jwt(email='anyone@x.com')}")   # 带 idp
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


# ---- Task 8b: idp / auth_via 校验（org 语义的执行点，spec §3.5） ----


def _jwt_idp(email="a@x.com", idp="Feishu", exp_delta=3600, secret="test-secret",
             auth_via="TokenGeneration_HostedAuth"):
    """带 idp + auth_via 的会话 JWT（Task 13 起 auth 服务签的就是这种）。"""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"email": email, "name": "Alice",
               "exp": int(time.time()) + exp_delta}
    if idp:
        payload["idp"] = idp
    if auth_via:
        payload["auth_via"] = auth_via
    p = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_trusted_idp_session_is_admitted():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='Feishu')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


def test_second_trusted_idp_also_admitted():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='Okta')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


def test_session_without_idp_is_rejected_when_required():
    """本地用户（SDK 直接认证 user pool）签出的会话没有 idp——必须拦住。

    这是 spec §3.5 的核心：移除 COGNITO 不阻止 SDK 认证本地用户，
    只有这条校验能把"身份必须来自企业 IdP"落到请求路径上。
    """
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    resp = orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    assert resp["status"] == "302"          # 按未登录处理，不是 403


def test_untrusted_idp_is_rejected():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='EvilCorp')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH),
                           "app-x.example.com")["status"] == "302"


def test_native_auth_source_is_rejected_even_with_trusted_idp():
    """linked 本地用户 / 设过密码的联邦用户：idp 合法但走原生 InitiateAuth。

    这是 idp claim 单独拦不住的那一类（spec §3.5 的效力边界）——
    它们的 identities 里确实有可信 provider，只有 auth_via 能分辨。
    """
    r = _req(cookie=f"sb_session={_jwt_idp(idp='Feishu', auth_via='TokenGeneration_Authentication')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH),
                           "app-x.example.com")["status"] == "302"


def test_refresh_token_source_is_admitted():
    """托管登录换出的 refresh token 续期属正常路径，不能拦。"""
    r = _req(cookie=f"sb_session={_jwt_idp(auth_via='TokenGeneration_RefreshTokens')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


def test_missing_auth_via_is_rejected():
    """旧会话（升级前签发）没有 auth_via——开关开启后按未登录处理。"""
    r = _req(cookie=f"sb_session={_jwt_idp(auth_via=None)}")
    assert orq._check_auth(r, dict(ROUTE_AUTH),
                           "app-x.example.com")["status"] == "302"


def test_idp_check_applies_to_named_allowlist_too():
    """名单站点同样要过 idp 校验——不能因为在名单里就跳过来源检查。"""
    route = {**ROUTE_AUTH, "allowed_users": ["a@x.com"]}
    r = _req(cookie=f"sb_session={_jwt_idp(email='a@x.com', idp=None)}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "302"


def test_public_route_skips_idp_check():
    """公开站点（require_auth=False）根本不验会话，自然也不验 idp。"""
    route = {**ROUTE_AUTH, "require_auth": False}
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_idp_check_disabled_by_switch():
    """开关为 false 时放行无 idp 的会话——迁移宽限期的行为。

    用独立的 testable 副本验证：把占位符替换成 false 后重新加载模块。
    """
    import importlib
    import sys
    src = (Path(__file__).parent / "origin_request.py").read_text()
    for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
                 "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
                 "{{JWT_SECRET}}": "test-secret", "{{BASE_DOMAIN}}": "example.com",
                 "{{REQUIRE_IDP_CLAIM}}": "false",
                 "{{TRUSTED_IDPS}}": "Feishu"}.items():
        src = src.replace(k, v)
    (Path(__file__).parent / "_edge_noidp_testable.py").write_text(src)
    sys.path.insert(0, str(Path(__file__).parent))
    mod = importlib.import_module("_edge_noidp_testable")
    importlib.reload(mod)
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    assert mod._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


# ---- 平台身份不得从可写字段推导（Codex re-review P0） ----
# 这些用例必须走完整 lambda_handler：平台判定发生在那里（按请求 host），
# 只调 _route_request 会绕过它，等于不测真正的防线。

def _full_event(host, uri="/", cookie=None):
    headers = {"host": [{"key": "Host", "value": host}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    return {"Records": [{"cf": {"request": {
        "uri": uri, "querystring": "", "method": "GET", "headers": headers}}}]}


# owner 是权限投影字段：能写权限投影的角色（MCP runtime）可把任意用户站点的
# owner 改成 "platform"。若 Edge 据此授予平台待遇，那条站点就能读到顶域
# sb_session（可重放到该用户的其他站点），并被 origin_response 放行写平台 cookie。

def test_forged_platform_owner_on_site_route_gets_no_platform_treatment():
    """把站点路由的 owner 改成 platform 不得换来平台待遇（核心攻击链）。"""
    hijacked = {**SITE_ROUTE, "owner": "platform"}
    r = _req(uri="/api/x", cookie=f"sb_session={_jwt()}")
    # 走完整 handler：平台判定只能由请求 host 决定
    with patch.object(orq, "_lookup_route", return_value=dict(hijacked)), \
         patch.object(orq, "_add_sigv4_auth"), patch.object(orq, "_add_s3_sigv4_auth"):
        out = orq.lambda_handler(
            _full_event("app-x.example.com", "/api/x", f"sb_session={_jwt()}"), None)
    # 会话 cookie 必须仍被剥除
    assert "cookie" not in out["headers"] or \
        "sb_session" not in out["headers"]["cookie"][0]["value"]
    # 也不得拿到允许签发平台 cookie 的标记
    assert orq.PLATFORM_MARK not in out["headers"]


def test_forged_platform_key_in_route_item_is_overridden():
    """连 _platform_origin 这个键本身被写进路由 item 也不管用——
    lambda_handler 用真实 host 的判定结果覆盖它。"""
    hijacked = {**SITE_ROUTE, orq._PLATFORM_KEY: True, "owner": "platform"}
    with patch.object(orq, "_lookup_route", return_value=dict(hijacked)), \
         patch.object(orq, "_add_sigv4_auth"), patch.object(orq, "_add_s3_sigv4_auth"):
        out = orq.lambda_handler(
            _full_event("app-x.example.com", "/api/x", f"sb_session={_jwt()}"), None)
    assert orq.PLATFORM_MARK not in out["headers"]


def test_real_platform_subdomain_still_works():
    """auth 子域名仍须拿到平台待遇（否则 /logout 读不到 cookie）。"""
    with patch.object(orq, "_lookup_route", return_value=dict(PLATFORM_ROUTE)), \
         patch.object(orq, "_add_sigv4_auth"), patch.object(orq, "_add_s3_sigv4_auth"):
        out = orq.lambda_handler(
            _full_event("auth.example.com", "/logout", f"sb_session={_jwt()}"), None)
    assert "sb_session" in out["headers"]["cookie"][0]["value"]
    assert orq.PLATFORM_MARK in out["headers"]


def test_platform_treatment_survives_owner_removal_on_auth_route():
    """反过来：auth 路由即使 owner 字段被清掉也仍是平台（判定不依赖它）。"""
    stripped = {k: v for k, v in PLATFORM_ROUTE.items() if k != "owner"}
    with patch.object(orq, "_lookup_route", return_value=stripped), \
         patch.object(orq, "_add_sigv4_auth"), patch.object(orq, "_add_s3_sigv4_auth"):
        out = orq.lambda_handler(
            _full_event("auth.example.com", "/logout", f"sb_session={_jwt()}"), None)
    assert orq.PLATFORM_MARK in out["headers"]


# --- fail-closed：require_auth / allowed_users 的缺失与错型 ---
# Codex 审查 2026-08-06 P1：_deser 把 N=0 / 空 L / NULL / 未知类型落到假值，
# 而判定是 `if not route.get("require_auth"): 放行`——四种形态全部让站点变全公开。
# 代码注释早就预言了这个后果（"require_auth 变 False 才是灾难"）却没有防住。
# 实测复现过：missing / N=0 / empty L / NULL 四种都无 cookie 放行。

import pytest


@pytest.mark.parametrize("bad", [
    pytest.param({}, id="require_auth-缺失"),
    pytest.param({"require_auth": {"N": "0"}}, id="require_auth-N0"),
    pytest.param({"require_auth": {"L": []}}, id="require_auth-空L"),
    pytest.param({"require_auth": {"NULL": True}}, id="require_auth-NULL"),
    pytest.param({"require_auth": {"S": "false"}}, id="require_auth-字符串"),
    pytest.param({"require_auth": {"M": {}}}, id="require_auth-未知类型M"),
])
def test_non_boolean_require_auth_is_fail_closed(bad):
    """只有**显式 BOOL 值**才能决定公开与否；缺失和错型一律要求登录。

    这些行不是假想：迁移脚本、人工修复、新 writer 都可能写出缺字段或错型的行。
    fail-open 的后果是私有站点静默全公开，且没有任何告警。
    """
    route = {"subdomain": {"S": "app-x"}, "site_id": {"S": "x"},
             "route_mode": {"S": "api-only"}, "api_target": {"S": "https://x.example"}}
    route.update(bad)
    resp = orq._check_auth(_req(), orq._deser(route), "app-x.example.com")
    assert resp is not None and resp["status"] == "302", \
        f"{bad} 让未登录请求被放行 —— 站点变全公开"


def test_explicit_bool_false_still_makes_site_public():
    """显式 require_auth=false 必须仍然公开——这是合法的产品能力，别一起改坏。"""
    route = orq._deser({"subdomain": {"S": "app-x"}, "site_id": {"S": "x"},
                        "require_auth": {"BOOL": False},
                        "route_mode": {"S": "api-only"},
                        "api_target": {"S": "https://x.example"}})
    assert orq._check_auth(_req(), route, "app-x.example.com") is None


def test_missing_allowed_users_does_not_default_to_org():
    """allowed_users 缺失时不能默认 'org'（= 全组织可见）。

    缺字段说明写入方没有表达意图，默认放宽等于把"未声明"当成"最宽"。
    正确的默认是最窄：只有 owner/协作者可访问。
    """
    route = orq._deser({"subdomain": {"S": "app-x"}, "site_id": {"S": "x"},
                        "require_auth": {"BOOL": True},
                        "owner": {"S": "owner@x.com"},
                        "route_mode": {"S": "api-only"},
                        "api_target": {"S": "https://x.example"}})
    # 合法会话但既不是 owner 也不在名单里 → 必须 403
    r = _req(cookie=f"sb_session={_jwt(email='outsider@x.com')}")
    resp = orq._check_auth(r, route, "app-x.example.com")
    assert resp is not None and resp["status"] == "403", \
        "allowed_users 缺失时默认成了 org，外人被放行"
