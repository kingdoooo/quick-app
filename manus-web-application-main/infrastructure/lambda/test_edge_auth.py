import base64, hashlib, hmac, json, time
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
_SRC = (Path(__file__).parent / "origin_request.py").read_text()
for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
             "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
             "{{JWT_SECRET}}": "test-secret", "{{BASE_DOMAIN}}": "example.com"}.items():
    _SRC = _SRC.replace(k, v)
(Path(__file__).parent / "_edge_auth_testable.py").write_text(_SRC)
import _edge_auth_testable as orq


def _jwt(email="a@x.com", name="Alice", exp_delta=3600, secret="test-secret"):
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"name": name, "exp": int(time.time()) + exp_delta}
    if email is not None:  # email=None -> payload 完全省略 email 字段
        payload["email"] = email
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
