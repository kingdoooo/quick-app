"""Edge 路由单测——DynamoDB 与签名 mock 掉，测分流与改写逻辑。"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import edge_substitutions as es          # 替换表的唯一定义（ticket 22）

# 占位符在测试中先替换再 import
orq = es.load_edge_module("_origin_request_testable", write_to=HERE,
                          DYNAMODB_TABLE_NAME="test-table",
                          FRONTEND_BUCKET_DOMAIN="site-frontend-123.s3.us-east-1.amazonaws.com",
                          ACCESS_REPLICA_REGIONS="us-east-1,ap-southeast-1,ap-northeast-1")


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


# 本用例走完整 handler 且 `/` 与 `/detail` 都是页面级请求，于是会触发 M5 埋点。
# 这是一条**路由**用例，不关心埋点，所以显式 patch 掉 `_record_access` 表明
# "我不写"。不 patch 的话会真的向生产表发 PutItem——conftest.py 的护栏会把它
# 变成 teardown 断言失败（加护栏之前它是静默出网的，实测两次真实调用）。
@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_s3_sigv4_auth")
@patch.object(orq, "_record_access")
def test_extensionless_uri_maps_to_index(mock_record, mock_sig, mock_lookup):
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


# ---------- M04：静态资源的 SigV4 路径（2026-09-27 真机判别实验）----------
# 原来签的是 `quote(uri)`，而 CloudFront 交给 Edge 的 uri 是 viewer 发来的**已编码**形态
# ⇒ `%20` 被编成 `%2520`，S3 回 403 SignatureDoesNotMatch。下表是真机结果（专用一次性路由 +
# 同名对象，浏览器形态的请求路径；只有 plain 与裸括号是 200）。
M04_REAL_MACHINE = [
    # (Edge 收到的 uri, 真机旧代码下 S3 是否接受)
    ("/plain.png", True),
    ("/a%20b.png", False),
    ("/logo(1).png", True),
    ("/%E6%88%91.png", False),
    ("/100%25.png", False),
    ("/a%2520b.png", False),
    ("/logo%281%29.png", False),
]
_UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def _s3_side_canonical(received_path: str) -> str:
    """**S3 侧**的 CanonicalURI：把收到的路径解码成对象键，再按 SigV4 规范逐字节编码
    （unreserved 与 `/` 原样，其余 `%XX` 大写）。刻意手写、不用 urllib.quote——
    与被测代码用同一个函数就成了自证。"""
    raw, i, b = bytearray(), 0, received_path.encode()
    while i < len(b):
        if b[i] == ord("%") and i + 2 < len(b):
            raw.append(int(b[i + 1:i + 3], 16))
            i += 3
        else:
            raw.append(b[i])
            i += 1
    return "".join(chr(c) if c in _UNRESERVED or c == ord("/") else f"%{c:02X}" for c in raw)


class _RecordingS3Auth:
    """顶替 S3SigV4Auth：记下被签的 URL 路径（S3SigV4Auth 不规范化路径，签的就是它）。"""
    paths: list = []

    def __init__(self, *a, **k):
        pass

    def add_auth(self, aws_request):
        from urllib.parse import urlsplit
        _RecordingS3Auth.paths.append(urlsplit(aws_request.url).path)


def _signed_vs_expected(uri: str):
    _RecordingS3Auth.paths = []
    with patch.object(orq, "_lookup_route", return_value=dict(ROUTE)), \
            patch.object(orq, "S3SigV4Auth", _RecordingS3Auth):
        req = orq.lambda_handler(_event(uri=uri), None)
    assert req["origin"]["custom"]["domainName"].startswith("site-frontend-")
    (signed,) = _RecordingS3Auth.paths
    return signed, _s3_side_canonical(req["uri"])


def test_m04_s3_side_model_reproduces_the_real_machine_table():
    """正向控制：模拟器配**旧公式** `quote(uri)` 必须复现真机表——否则下一条的绿不代表 S3 会接受。"""
    import urllib.parse
    for uri, accepted in M04_REAL_MACHINE:
        forwarded = f"/{ROUTE['static_prefix']}{uri}"
        old_signed = urllib.parse.quote(forwarded)
        assert (old_signed == _s3_side_canonical(forwarded)) is accepted, uri


def test_m04_signed_path_is_what_s3_computes_for_every_real_machine_case():
    bad = [(uri, s, e) for uri, _ in M04_REAL_MACHINE for s, e in [_signed_vs_expected(uri)]
           if s != e]
    assert not bad, f"签名路径 != S3 侧 CanonicalURI（S3 会回 SignatureDoesNotMatch）: {bad}"


def test_m04_forwarded_uri_is_not_re_encoded():
    """写回 request["uri"] 的仍是 viewer 的原样编码：S3 按它解码出对象键。"""
    with patch.object(orq, "_lookup_route", return_value=dict(ROUTE)), \
            patch.object(orq, "S3SigV4Auth", _RecordingS3Auth):
        req = orq.lambda_handler(_event(uri="/%E6%88%91.png"), None)
    assert req["uri"] == "/sites/demo1/job-aaa/%E6%88%91.png"


def test_m04_decodes_bytes_not_utf8_text():
    """单元级（非真机）：按字符串 unquote 会把非 UTF-8 序列换成 U+FFFD，签出来就不是 S3 解出的键。"""
    signed, expected = _signed_vs_expected("/%FF.png")
    assert signed == expected == "/sites/demo1/job-aaa/%FF.png"
