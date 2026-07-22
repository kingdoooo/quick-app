"""Edge 路由单测——DynamoDB 与签名 mock 掉，测分流与改写逻辑。"""
import importlib
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

# 占位符在测试中先替换再 import
_SRC = (Path(__file__).parent / "origin_request.py").read_text()
_SRC = (_SRC.replace("{{DYNAMODB_TABLE_NAME}}", "test-table")
            .replace("{{DYNAMODB_REGION}}", "us-east-1")
            .replace("{{FRONTEND_BUCKET_DOMAIN}}", "site-frontend-123.s3.us-east-1.amazonaws.com")
            .replace("{{JWT_SECRET}}", "test-secret"))
_mod_path = Path(__file__).parent / "_origin_request_testable.py"
_mod_path.write_text(_SRC)
import _origin_request_testable as orq


ROUTE = {"subdomain": "app-demo1", "site_id": "demo1", "route_mode": "split",
         "static_prefix": "sites/demo1/job-aaa",
         "api_target": "https://abc.lambda-url.us-east-1.on.aws",
         "require_auth": False, "allowed_users": "org", "owner": "a@x.com"}


def _event(host="app-demo1.example.com", uri="/", method="GET", cookie=None, body=None):
    headers = {"host": [{"key": "Host", "value": host}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    req = {"uri": uri, "querystring": "", "method": method, "headers": headers}
    if body is not None:
        req["body"] = body
    return {"Records": [{"cf": {"request": req}}]}


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_sigv4_auth")
def test_api_path_routes_to_lambda(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/api/items"), None)
    assert req["origin"]["custom"]["domainName"] == "abc.lambda-url.us-east-1.on.aws"
    mock_sig.assert_called_once()


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_s3_sigv4_auth")
def test_static_path_routes_to_s3_with_versioned_prefix(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/assets/app.js"), None)
    assert req["origin"]["custom"]["domainName"] == "site-frontend-123.s3.us-east-1.amazonaws.com"
    assert req["uri"] == "/sites/demo1/job-aaa/assets/app.js"


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_s3_sigv4_auth")
def test_extensionless_uri_maps_to_index(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/"), None)
    assert req["uri"] == "/sites/demo1/job-aaa/index.html"
    req2 = orq.lambda_handler(_event(uri="/detail"), None)
    assert req2["uri"] == "/sites/demo1/job-aaa/index.html"


@patch.object(orq, "_lookup_route",
              return_value={"subdomain": "auth", "site_id": "auth-service",
                            "route_mode": "api-only", "static_prefix": "",
                            "api_target": "https://xyz.lambda-url.us-east-1.on.aws",
                            "require_auth": False, "allowed_users": "org",
                            "owner": "platform"})
@patch.object(orq, "_add_sigv4_auth")
def test_api_only_mode_routes_all_paths_to_lambda(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(host="auth.example.com", uri="/login"), None)
    assert req["origin"]["custom"]["domainName"] == "xyz.lambda-url.us-east-1.on.aws"
    assert req["uri"] == "/login"


@patch.object(orq, "_lookup_route", return_value=None)
def test_unknown_subdomain_404(mock_lookup):
    resp = orq.lambda_handler(_event(host="nope.example.com"), None)
    assert resp["status"] == "404"


@patch.object(orq, "_lookup_route",
              return_value={**ROUTE, "api_target": ""})
def test_api_on_static_only_site_404(mock_lookup):
    resp = orq.lambda_handler(_event(uri="/api/items"), None)
    assert resp["status"] == "404"


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
def test_truncated_body_returns_413(mock_lookup):
    resp = orq.lambda_handler(_event(uri="/api/items", method="POST",
                                     body={"inputTruncated": True, "data": "",
                                           "encoding": "base64"}), None)
    assert resp["status"] == "413"


@patch.object(orq, "_lookup_route", side_effect=RuntimeError("boom"))
def test_edge_fails_closed_on_exception(mock_lookup):
    resp = orq.lambda_handler(_event(), None)
    assert resp["status"] == "500"  # 绝不透传原请求
