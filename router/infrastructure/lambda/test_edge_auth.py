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
    """auth-service 需要读 cookie（/logout）并被允许签发平台 cookie。"""
    r = _req(uri="/logout", cookie=f"sb_session={_jwt()}")
    orq._check_auth(r, dict(PLATFORM_ROUTE), "auth.example.com")
    _route(r, PLATFORM_ROUTE)
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
