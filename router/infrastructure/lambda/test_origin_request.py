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


def _event(host="app-demo1.example.com", uri="/", method="GET", cookie=None, body=None,
           querystring=""):
    headers = {"host": [{"key": "Host", "value": host}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    req = {"uri": uri, "querystring": querystring, "method": method,
           "headers": headers}
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


# ── query string 脱敏（Codex 审查 2026-08-10 P2-3）─────────────────────
# 真机证据：Edge 日志里已经存着明文 Cognito OAuth code
#   ap-northeast-1 2026-08-03  "Fixed querystring: code=ab27...&state=eyJ..."
# 认证材料（OAuth code / console upgrade code）绝不能整值进长期日志。

def test_redact_querystring_keeps_names_drops_values():
    """脱敏后：参数名可见、值不可见（只留长度）。"""
    out = orq._redact_querystring(
        "code=ab279620-f66e-4091-8bd9-ba09e54774b2&state=eyJyIjoiaHR0cHMifQ")
    assert "ab279620" not in out and "f66e" not in out
    assert "eyJyIjoiaHR0cHMifQ" not in out
    assert "code" in out and "state" in out


def test_redact_querystring_handles_empty_and_valueless():
    assert orq._redact_querystring("") == ""
    assert "flag" in orq._redact_querystring("flag")


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_sigv4_auth")
def test_no_log_line_contains_raw_query_value(mock_sig, mock_lookup, caplog):
    """**整条 query 值不得出现在任何日志行里**（两个 INFO 点都覆盖）。

    按整行断言而非逐字段：换个 f-string 写法就能绕过字段级断言。
    """
    secret = "ab279620-f66e-4091-8bd9-ba09e54774b2"
    import logging as _l
    with caplog.at_level(_l.INFO):
        orq.lambda_handler(_event(uri="/api/session-callback",
                                  querystring=f"code={secret}"), None)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert secret not in joined, f"认证材料整值进了日志:\n{joined}"
