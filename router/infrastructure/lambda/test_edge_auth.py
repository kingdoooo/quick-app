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
    payload = {"typ": "session", "name": name, "exp": int(time.time()) + exp_delta}
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
    payload = {"typ": "session", "email": email, "name": "Alice",
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


# ---- M3: console 平台子域 + 平台保留 cookie ----
# 注意本文件的既有机制：origin_request.py 被读进来做 {{PLACEHOLDER}} 替换后
# 写成 _edge_auth_testable.py 再 import 成 `orq`（文件头 1-15 行）。
# 新用例**一律用 orq**，不要 `import origin_request`——直连原文件会带着未替换
# 的占位符。origin_response.py 无占位符，可直接 import。

def test_console_subdomain_is_platform():
    """console 必须被当平台路由（放行平台 cookie、不注入站点身份头）。"""
    assert "console" in orq.PLATFORM_SUBDOMAINS


def test_platform_identity_comes_only_from_host_not_route_owner():
    """伪造 route.owner=platform 不得获得平台待遇。

    owner 是**可写投影字段**——能改权限的角色就能写它。平台身份只能由
    host 解析出的 hardcoded 白名单判定（spec §5.2）。

    平台标记在 lambda_handler 里内联完成（`route = {**route, _PLATFORM_KEY:
    subdomain in PLATFORM_SUBDOMAINS}`），没有独立的 _mark_platform 函数——
    所以这里断言判定函数 _is_platform_route 的行为。
    """
    evil = {"site_id": "evil-abc123", "owner": "platform",
            "require_auth": False, "route_mode": "split"}
    assert orq._is_platform_route(evil) is False, (
        "route.owner 被当成了平台身份判据——这是可写字段")
    # 连"真值但不是 True"也不能翻盘（必须是 `is True` 严格判定）
    assert orq._is_platform_route({**evil, "_platform_origin": "true"}) is False
    marked = {**evil, orq._PLATFORM_KEY: True}
    assert orq._is_platform_route(marked) is True


def test_reserved_cookies_cover_both_platform_cookies():
    import origin_response as ors
    for name in ("__Host-sb_console", "__Host-sb_pkce", "sb_session"):
        assert name in orq.RESERVED_COOKIES, name
    assert tuple(orq.RESERVED_COOKIES) == tuple(ors.RESERVED_COOKIES), (
        "两份保留 cookie 清单漂移了——会出现'请求里剥了、响应里没剥'")


def test_site_route_strips_platform_cookies():
    """普通站点请求里的平台 cookie 必须被剥掉（不转发给不可信站点代码）。

    `_strip_reserved_cookies(request)` **原地改 request**、返回 None——
    不要按"返回新字符串"写断言，那样的用例永远绿。
    """
    request = {"headers": {"cookie": [
        {"key": "Cookie",
         "value": "a=1; __Host-sb_console=secret; sb_session=xyz; b=2"}]}}
    assert orq._strip_reserved_cookies(request) is None
    kept = request["headers"]["cookie"][0]["value"]
    assert "__Host-sb_console" not in kept and "sb_session" not in kept
    assert "a=1" in kept and "b=2" in kept


def test_pkce_cookie_is_also_stripped_from_site_requests():
    """__Host-sb_pkce 是 M1 就有但漏登记的——站点也不该看到它。"""
    request = {"headers": {"cookie": [
        {"key": "Cookie", "value": "__Host-sb_pkce=verifier; keep=1"}]}}
    orq._strip_reserved_cookies(request)
    kept = request["headers"]["cookie"][0]["value"]
    assert "__Host-sb_pkce" not in kept and "keep=1" in kept


# ---- S1/M05: Edge 内嵌 verifier 必须查 typ ----
# 会话 token 与 console 一次性升级码用**同一个密钥**签名、线格式也相同，
# 唯一的区别是载荷里的 typ。Edge 不查 typ 时，一个 60s 的升级码就是一个
# 有效站点会话（而它还能在 auth 的 /console-session 无限续期）。
#
# 下面两条"不带 typ"的用例**故意不用 `_jwt`**：那个辅助已经带上了 typ
# （Step 4），用它就测不到"缺 typ"这件事本身。手搓是为了让用例不会因为
# 别人改辅助而静默失效。

# auth 包（site-builder/auth）不在 Edge 的运行时路径里，只有测试期为了跑
# 跨组件向量才需要它。按 __file__ 定位而不是相对 cwd——本文件顶部就是这个
# 约定（`Path(__file__).parent`），且 cwd 漂移导致的静默读空在本仓库有先例。
_AUTH_PKG = str(Path(__file__).resolve().parents[3] / "site-builder" / "auth")


def test_edge_rejects_a_token_without_typ():
    """缺 typ 的旧会话被拒（走 302，不是 403）。

    302 而非 403 的理由与既有的 idp/auth_via 检查一致：引导用户去登录，
    而不是让他以为"没权限"去找站点 owner 加名单。
    这一条也是"全员重登一次"的技术表现。
    """
    claims = {"email": "v@example.test", "name": "V",
              "exp": int(time.time()) + 600}          # 故意不带 typ
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64(hmac.new(b"test-secret", f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    assert orq._verify_session_jwt(f"{header}.{payload}.{sig}") is None


def test_edge_rejects_a_console_upgrade_code_as_a_site_session():
    """console 升级码不得当站点会话用（M05 在 Edge 侧的那一半）。"""
    sys.path.insert(0, _AUTH_PKG)
    from session import mint_upgrade_code
    code = mint_upgrade_code("v@example.test", "test-secret")
    assert orq._verify_session_jwt(code) is None


def test_check_auth_redirects_a_typeless_token_to_login():
    """缺 typ 走到 `_check_auth` 是 **302 到登录端点**，不是 403。

    口径与既有的 idp / auth_via 检查一致：引导用户去登录，
    而不是让他以为"没权限"去找站点 owner 加名单。

    手搓 token 而不用 `_jwt`：那个辅助现在会带 typ，用它这条用例就变成
    "带 typ 的合法会话被 302"——恒绿且测的是别的东西。
    """
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = b64(json.dumps(
        {"email": "v@example.test", "name": "V", "idp": "Feishu",
         "auth_via": "TokenGeneration_HostedAuth",
         "exp": int(time.time()) + 600},              # 故意不带 typ
        separators=(",", ":")).encode())
    sig = b64(hmac.new(b"test-secret", f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    token = f"{header}.{payload}.{sig}"
    request = _req(cookie=f"sb_session={token}")
    denied = orq._check_auth(request, ROUTE_AUTH, "app-x.example.test")
    assert denied is not None and denied["status"] == "302"
    assert "/login?redirect=" in denied["headers"]["location"][0]["value"]


def test_a_real_auth_token_verifies_at_the_edge():
    """**跨组件正向向量**：auth 真签出来的 token 必须能过 Edge 的 verifier。

    这是唯一能发现 `auth/session.py` 的 `SESSION_TYP` 与 Edge 里硬编码的
    `"session"` 漂移的东西——两处按设计必须字节等价，但 Edge 拿不到那个常量
    （Lambda@Edge 不能 import auth 包）。只有负向用例的话，把 auth 改成
    `typ="sess"` 而 Edge 仍查 `"session"`，全部负向用例照样绿，
    而线上所有会话失效。
    """
    sys.path.insert(0, _AUTH_PKG)
    from session import mint_session_jwt
    token = mint_session_jwt("v@example.test", "V", "test-secret",
                             idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    claims = orq._verify_session_jwt(token)
    assert claims is not None, "auth 签的 token 在 Edge 侧被拒——两处 typ 漂移了"
    assert claims["email"] == "v@example.test"


def test_edge_expected_typ_is_not_caller_supplied():
    """期望的 typ 是**硬编码字面量**，不是入参——钉住这个形状本身。

    auth 侧的 `verify_session_jwt(..., expected_typ=...)` 有一个假值洞：
    显式传 `expected_typ=None` 时，缺 typ 的旧 token 走到 `None != None` ——
    为假，于是**被接受**，正好退回 M05 要消灭的那个行为。Edge 这份不收这个参数，
    所以那个洞在这里不可达（没有任何调用方能影响期望值），因此这里**不加**
    "假值一律拒"的守卫——那道守卫在本形状下守不住任何东西。

    这条用例是那个判断的保险：谁把 Edge 改成收 `expected_typ`（例如为了向
    auth/session.py 的签名靠拢），本用例立刻红，提醒他这一刻必须把
    `if not expected_typ or not isinstance(expected_typ, str): return None`
    一起抄过来。
    """
    import inspect
    params = list(inspect.signature(orq._verify_session_jwt).parameters)
    assert params == ["token"], (
        f"_verify_session_jwt 现在收 {params}——期望 typ 一旦可由调用方传入，"
        "就必须同时加上'缺失/非字符串一律拒'的守卫，否则 expected_typ=None "
        "会让缺 typ 的旧 token 通过")


@pytest.mark.parametrize("bad_typ", [
    pytest.param(None, id="typ-null"),
    pytest.param("", id="typ-空串"),
    pytest.param(0, id="typ-0"),
    pytest.param(False, id="typ-false"),
    pytest.param([], id="typ-空数组"),
])
def test_edge_rejects_falsy_typ_claims(bad_typ):
    """载荷侧的假值同样一律拒——"假值兜底"在鉴权路径上是本仓库的记录在案的陷阱。

    这是上面那个洞在**claim 方向**的镜像：判据一旦被写成
    `if claims.get("typ") and claims.get("typ") != "session"`（看起来像"给存量
    会话留个兼容"的软化），这五种形态连同"完全没有 typ"就全部通过了。
    现在的 `!= "session"` 对它们都成立，本用例把这件事钉住。
    """
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = b64(json.dumps(
        {"typ": bad_typ, "email": "v@example.test", "name": "V",
         "exp": int(time.time()) + 600}, separators=(",", ":")).encode())
    sig = b64(hmac.new(b"test-secret", f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    assert orq._verify_session_jwt(f"{header}.{payload}.{sig}") is None, (
        f"typ={bad_typ!r} 被当成有效会话——假值不等于'不用查'")


# ---- S1/M06: 同名 cookie 全取并逐个验签 ----


def test_a_garbage_cookie_in_front_does_not_lock_the_user_out():
    """两条同名 sb_session、第一条是垃圾 ⇒ 仍放行。

    M06：`sb_session` 是顶域 cookie（`Domain=.{base}`），而 HttpOnly 只阻止
    `document.cookie` 覆盖**同 (name, domain, path)** 的那一条。站点页面 JS 写
    `sb_session=garbage; domain=.{base}; path=/api` 是**新建第二条**，浏览器不拦；
    RFC 6265 §5.4.2 规定路径更长的先发 ⇒ 垃圾值先被取到 ⇒ 全平台 /api/* 持久 302，
    且重新登录（写 path=/）不会清掉遮蔽项。已本地复现。
    """
    good = _jwt(email="v@example.test")
    request = _req(cookie=f"sb_session=garbage; sb_session={good}")
    assert orq._get_cookies(request, "sb_session") == ["garbage", good]
    # 放行 = _check_auth 返回 None，并注入了真身份
    assert orq._check_auth(request, ROUTE_AUTH, "app-x.example.test") is None
    assert request["headers"]["x-user-email"][0]["value"] == "v@example.test"


def test_candidate_count_is_not_capped_at_any_depth():
    """候选条数**不设上限**：真 token 排在多深都必须被尝试。

    这条取代了原来的 `test_only_the_first_candidates_are_tried`（它断言第
    cap+1 条**不**被尝试）。那条用例把残留面写成了需求：可遮蔽条数的上界是
    `4n − 2`，n 是请求路径的段数，而站点的 URL 空间由站点作者决定、平台不约束
    ⇒ n 无界 ⇒ **不存在"设在任何可达值之外"的有限上限**。上限设成 C，站点作者
    写出 `n ≥ (C + 2) / 4` 段的路径，M06 就在那些路径上原样复活。

    **写死 300 而不是从常量派生**：常量已经删了，而这条用例要防的正是"有人又
    加回一个上限"。派生自常量的用例对任何有限上限都是绿的（那是它原本的语义），
    所以这里必须是一个硬编码的、比任何"看起来够用"的值都大的数——它同时也
    远超旧上限 64。
    """
    good = _jwt(email="v@example.test")
    shadow = "; ".join(f"sb_session=x{i}" for i in range(300))
    # 300 条 ≈ 17 段以上的站点路径能造出来的量级，用 uri 一并把场景写实
    request = _req(uri="/" + "/".join(f"seg{i}" for i in range(20)),
                   cookie=f"{shadow}; sb_session={good}")
    assert len(orq._get_cookies(request, "sb_session")) == 301
    assert orq._check_auth(request, ROUTE_AUTH, "app-x.example.test") is None, \
        "第 301 条候选没被尝试——有人重新引入了条数上限，M06 在深路径上复活了"
    assert request["headers"]["x-user-email"][0]["value"] == "v@example.test"


def test_no_candidate_count_cap_constant_is_reintroduced():
    """结构断言：模块里不得再出现"候选条数上限"这类常量。

    上一条是行为断言，但它只证明"上限不小于 300"。有人加一个 500 的上限时它
    仍然绿，而 M06 在 n ≥ 126 段的路径上就回来了。这条从结构上钉死：真正的界
    是 Cookie 头体积（由传输层强制、与路径深度无关），要限就限体积，不限条数。
    """
    import inspect

    # **必须先剥掉注释再断言**：解释"为什么删掉这个上限"的那段注释里就写着常量名，
    # 裸 `in src` 会被自己的文档绊倒（本仓库反复栽过的"断言的字样只活在注释里"，
    # 这次是同一个坑的反方向：字样活在注释里就让守卫**假红**）。
    code = "\n".join(line for line in inspect.getsource(orq).splitlines()
                     if not line.lstrip().startswith("#"))
    assert "MAX_SESSION_COOKIE_CANDIDATES" not in code, (
        "候选条数上限被加回来了——任何有限条数上限都会按路径深度让 M06 复活，"
        "见 _get_cookies 上方那段推导")
    # 切片 / islice 式截断同样是上限，只是换个写法
    assert '_get_cookies(request, "sb_session")[' not in code, (
        "_get_cookies 的结果被切片了——那就是一个匿名的条数上限")
    assert "islice" not in code, "用 islice 截断候选同样是条数上限"


def test_a_real_world_shadowing_burst_still_authenticates():
    """14 条遮蔽候选压在合法会话前面仍须放行——**M06 真正关闭的判据**。

    14 不是随手取的数（fix 轮 1 把上限从 8 提到 64 的理由，已独立复算）：
    RFC 6265 §5.1.4 让请求路径的**每个 `/` 边界前缀**都是合法 cookie-path，
    §5.4.2 又让路径长的先发。对 console 的 `/api/sites/{id}/analytics`，
    比 `/` 更长的可设路径正好 7 条（`/api`、`/api/`、`/api/sites`、
    `/api/sites/`、`/api/sites/{id}`、`/api/sites/{id}/`、
    `/api/sites/{id}/analytics`）；站点 JS 能给**两个**父域设 cookie，
    两者都会送到 console 这个兄弟 host ⇒ 7 × 2 = 14 条，全部排在 `Path=/`
    的真会话前面，真 token 落在**第 15 位**。

    上限为 8 时它压根不被尝试，受害者拿到的正是 M06 描述的持久 302——而失效的
    恰好是 site-detail / permissions / collaborators / owner / undeploy /
    analytics / visitors 这些他**用来排查和自救**的 console 接口（都是 4 段路径）。
    所以"上限 8"下 M06 只是被收窄、没有被关掉。
    """
    good = _jwt(email="v@example.test")
    # 14 个各不相同的值：现实里它们来自 14 个不同的 (domain, path) scope
    shadow = "; ".join(f"sb_session=shadow{i}" for i in range(14))
    request = _req(uri="/api/sites/abc/analytics",
                   cookie=f"{shadow}; sb_session={good}")
    assert len(orq._get_cookies(request, "sb_session")) == 15
    assert orq._check_auth(request, ROUTE_AUTH, "app-x.example.test") is None, \
        "14 条遮蔽 cookie 仍能锁死用户——上限太小，M06 只被收窄而没关掉"
    # 放行时用的必须是**真身份**，不是任何遮蔽项
    assert request["headers"]["x-user-email"][0]["value"] == "v@example.test"
    assert request["headers"]["x-user-name"][0]["value"] == "Alice"


def test_reserved_cookies_are_still_stripped_in_full():
    """回归：改 _get_cookies 时不要顺手动坏"剥掉全部同名保留 cookie"。"""
    request = _req(cookie="sb_session=a; sb_session=b; site_own=keep")
    orq._strip_reserved_cookies(request)
    assert request["headers"]["cookie"][0]["value"] == "site_own=keep"
