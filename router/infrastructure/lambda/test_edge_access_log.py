"""M5 埋点单测。机制同 test_edge_auth.py：把 origin_request.py 读进来做
占位符替换后写成一个 testable 副本再 import（所以改 origin_request.py 会自动
流进本文件，不存在"两份代码漂移"）。
"""
import importlib
import json
from pathlib import Path

import pytest

_SRC = (Path(__file__).parents[0] / "origin_request.py").read_text()
_SUBS = {
    "{{DYNAMODB_TABLE_NAME}}": "test-table",
    "{{DYNAMODB_REGION}}": "us-east-1",
    "{{FRONTEND_BUCKET_DOMAIN}}": "site-frontend-123.s3.us-east-1.amazonaws.com",
    "{{JWT_SECRET}}": "test-secret",
    "{{BASE_DOMAIN}}": "example.test",
    "{{REQUIRE_IDP_CLAIM}}": "false",
    "{{TRUSTED_IDPS}}": "Feishu",
    "{{ACCESS_TABLE}}": "site-access-events",
    "{{ACCESS_REPLICA_REGIONS}}": "us-east-1,ap-southeast-1,ap-northeast-1",
}
for _k, _v in _SUBS.items():
    _SRC = _SRC.replace(_k, _v)
(Path(__file__).parent / "_edge_access_testable.py").write_text(_SRC)
import _edge_access_testable as orq          # noqa: E402


class Ctx:
    def __init__(self, arn=""):
        self.invoked_function_arn = arn


# ── 区域解析与回落（spec §2.3 规矩 5）────────────────────────────────

def test_region_comes_from_env_when_it_is_a_replica(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    assert orq._access_region(Ctx()) == "ap-southeast-1"


def test_region_falls_back_to_arn_when_env_missing(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    ctx = Ctx("arn:aws:lambda:ap-northeast-1:111111111111:function:x")
    assert orq._access_region(ctx) == "ap-northeast-1"


def test_unresolvable_region_falls_back_to_primary(monkeypatch):
    """解析不出区域 → 回落 us-east-1 = 正确但慢，**永不丢数据**。"""
    monkeypatch.delenv("AWS_REGION", raising=False)
    assert orq._access_region(Ctx("")) == "us-east-1"


def test_region_without_a_replica_falls_back_to_primary(monkeypatch):
    """解析出一个没有副本的区 → 也必须回落，不能对着不存在的副本发请求。"""
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert orq._access_region(Ctx()) == "us-east-1"


# ── 页面级判定必须与静态改写用同一个条件（spec §2.2）────────────────

# oracle **必须来自真实的 _route_request**，不能复刻它的条件。
# 初版就是复刻的，于是漏了 /api/ 前置分支还全绿（P1-1）。
# 另注：oracle 也不能写成"进了静态桶"——`.css` 也进桶。判据是**被改写成
# index.html**（我第一次写这个 oracle 时就选错了，表格看着对、结论是错的）。
_ROUTE = {"route_mode": "split", "static_prefix": "sites/x",
          "api_target": "https://f.lambda-url.us-east-1.on.aws/"}
_URIS = ["/", "/notes", "/a/b", "/.well-known/x", "/app.css", "/x/main.js",
         "/favicon.ico", "/api/data", "/api/sites/x/jobs", "/api/x.json"]
_METHODS = ["GET", "HEAD", "POST", "PUT", "OPTIONS", "DELETE"]


def _observed_kind(uri, method):
    """从**真实 _route_request** 观察它到底怎么处理了这个请求。

    oracle 必须是观察出来的，不能是复刻的条件——复刻已经错过两轮。
    也不能写成"进了静态桶"：`.css` 也进桶，判据是**改写成 index.html**。
    """
    req = {"uri": uri, "method": method, "querystring": "", "headers": {}}
    out = orq._route_request(req, dict(_ROUTE))
    if out.get("status") == "404":
        return "reject"
    u = str(out.get("uri", ""))
    if u.endswith("/index.html"):
        return "page"
    if u.startswith("/sites/"):
        return "asset"
    return "lambda"


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("uri", _URIS)
def test_route_kind_matches_what_route_request_actually_does(uri, method):
    """**60 组组合逐个比对**：_route_kind 是唯一定义，它说的必须就是真实发生的。

    第二轮审查（2026-08-14）实测：只看 uri 不看 method 时，POST/PUT/OPTIONS/
    DELETE 打到无扩展名路径会被记成 allow PV，而真实是 404——4 条不一致。
    method 维度不进参数化就抓不到。
    """
    assert orq._route_kind(_ROUTE, uri, method) == _observed_kind(uri, method), (
        f"_route_kind 与真实处理不一致: {method} {uri}")


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("uri", _URIS)
def test_only_real_page_views_are_recorded(uri, method):
    assert orq._is_page_request(_ROUTE, uri, method) is (
        _observed_kind(uri, method) == "page")


def test_api_only_sites_record_every_request_including_writes():
    route = {"route_mode": "api-only",
             "api_target": "https://f.lambda-url.us-east-1.on.aws/"}
    for m in _METHODS:
        assert orq._is_page_request(route, "/x.css", m) is True, m


# ── _route_kind 的**内容**必须被字面量钉住 ──────────────────────────
# Step 5 注入④⑤实测暴露的缺口：上面那 60 组一致性用例的 oracle
# (`_observed_kind`) 是从真实 `_route_request` 观察出来的，而重构后
# `_route_request` 自己就调 `_route_kind`——比较的两边同源、同步移动。于是那组
# 用例对 `_route_kind` 的**内容**是恒真的：它只能抓"两份判定漂移"（注入⑦），
# 抓不到"判定内容写错了"。实测两次：
#   · 删掉 `/api/` 分支 → 那 60 组全绿，靠既有 test_origin_request.py 才红；
#   · 删掉 method 检查 → **整个包 205 项全绿**，一个闸门都没有。
# 后者正是 P1-1 第二轮那个缺陷本身，也就是说它当时并没有真的被测着。
# 所以这里把每个分支的期望值**写成字面量**，不与任何 oracle 比较——oracle 会
# 跟着实现一起变，字面量不会。
_EXPECTED_KIND = {
    # /api/ 前缀一律走后端，与方法无关
    ("/api/data", "GET"): "lambda",
    ("/api/data", "POST"): "lambda",
    ("/api/x.json", "DELETE"): "lambda",
    # 读方法 + 无扩展名 = 页面（会被改写成 index.html）
    ("/", "GET"): "page",
    ("/notes", "GET"): "page",
    ("/a/b", "HEAD"): "page",
    # 读方法 + 有扩展名 = 静态资源
    ("/app.css", "GET"): "asset",
    ("/x/main.js", "HEAD"): "asset",
    ("/favicon.ico", "GET"): "asset",
    # 非读方法打到静态桶 = 404，**绝不能算页面**（P1-1 第二轮）
    ("/notes", "POST"): "reject",
    ("/notes", "PUT"): "reject",
    ("/notes", "OPTIONS"): "reject",
    ("/notes", "DELETE"): "reject",
    ("/app.css", "POST"): "reject",
}


@pytest.mark.parametrize("key,expected", sorted(_EXPECTED_KIND.items()))
def test_route_kind_content_is_pinned_by_literals(key, expected):
    uri, method = key
    assert orq._route_kind(_ROUTE, uri, method) == expected, f"{method} {uri}"


def test_api_only_mode_is_lambda_for_every_path_and_method():
    route = {"route_mode": "api-only"}
    for uri in ["/", "/notes", "/app.css", "/api/data"]:
        for m in _METHODS:
            assert orq._route_kind(route, uri, m) == "lambda", f"{m} {uri}"


# ── 只记 app- 前缀（spec §2.1）─────────────────────────────────────

@pytest.mark.parametrize("sub,recorded", [
    ("app-notes-abc123", True), ("auth", False),
    ("console", False), ("mcp", False),
])
def test_only_app_prefixed_subdomains_are_recorded(monkeypatch, sub, recorded):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda *a, **k: seen.append(a))
    orq._maybe_record(Ctx(), sub, "/", "GET", {"route_mode": "split"}, None, {})
    assert bool(seen) is recorded


def test_site_id_is_the_subdomain_minus_the_app_prefix(monkeypatch):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda ctx, site_id, uri, decision, email:
                        seen.append((site_id, decision, email)))
    orq._maybe_record(Ctx(), "app-notes-01d147", "/", "GET",
                      {"route_mode": "split"}, None, {"email": "a@b.co"})
    assert seen == [("notes-01d147", "allow", "a@b.co")]


# ── 三种 decision ────────────────────────────────────────────────

@pytest.mark.parametrize("denied,decision", [
    (None, "allow"),
    ({"status": "403"}, "denied_403"),
    ({"status": "302"}, "redirect_login"),
])
def test_decision_covers_allow_and_both_denials(monkeypatch, denied, decision):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda ctx, site_id, uri, d, email: seen.append(d))
    orq._maybe_record(Ctx(), "app-x-abc123", "/", "GET",
                      {"route_mode": "split"}, denied, {"email": "a@b.co"})
    assert seen == [decision]


# ── 埋点绝不能影响路由/鉴权（spec §2.3 规矩 3）──────────────────────

def test_a_throwing_write_does_not_change_the_returned_request(monkeypatch):
    """写穿抛任何异常都不许改变返回值——统计不是安全控制，这里 fail-open。"""
    def boom(*a, **k):
        raise RuntimeError("DynamoDB 挂了")
    monkeypatch.setattr(orq, "_access_client", boom)
    monkeypatch.setattr(orq, "_lookup_route", lambda sub: {
        "require_auth": False, "route_mode": "api-only",
        "api_target": "https://f.lambda-url.us-east-1.on.aws/"})
    event = {"Records": [{"cf": {"request": {
        "uri": "/", "method": "GET", "querystring": "",
        "headers": {"host": [{"key": "Host", "value": "app-x-abc123.example.test"}]}}}}]}
    out = orq.lambda_handler(event, Ctx())
    assert "origin" in out, "埋点异常把请求变成了错误响应"


def test_client_construction_failure_is_also_swallowed(monkeypatch):
    """兜底必须覆盖 client 取用本身，不能只包住 put_item 调用。"""
    monkeypatch.setattr(orq, "_access_region",
                        lambda ctx: (_ for _ in ()).throw(RuntimeError("x")))
    orq._maybe_record(Ctx(), "app-x-abc123", "/", "GET",
                      {"route_mode": "split"}, None, {"email": "a@b.co"})   # 不抛即通过


def test_record_access_swallows_on_its_own_not_via_the_outer_guard(monkeypatch):
    """内层兜底必须**独立**成立——这条是 Step 5 注入②实测补出来的。

    brief 预期"删掉 `_record_access` 的 try/except → 上面那条 handler 用例变红"，
    实测**没有变红**：`_maybe_record` 外面还有一层 except 把异常吞了，所以那条
    用例只证明"两层里至少有一层在"，删掉内层照样全绿。两层都在是有意的
    （防御纵深，两个函数各自的 docstring 都写了），但没有任何用例单独盯住内层。
    这里**直接调 `_record_access`**，绕开外层，把内层单独钉死。
    """
    def boom(*a, **k):
        raise RuntimeError("DynamoDB 挂了")
    monkeypatch.setattr(orq, "_access_client", boom)
    orq._record_access(Ctx(), "x-abc123", "/", "allow", "a@b.co")   # 不抛即通过


# ── 不许往返回的 request 对象加自定义键（spec §2.3 规矩 1）───────────

def test_returned_request_has_no_custom_keys(monkeypatch):
    """CloudFront 会校验 request 对象的形状；多一个键就是 500。

    身份靠独立的 sink dict 带出，不挂在 request 上。
    """
    monkeypatch.setattr(orq, "_record_access", lambda *a, **k: None)
    monkeypatch.setattr(orq, "_lookup_route", lambda sub: {
        "require_auth": False, "route_mode": "api-only",
        "api_target": "https://f.lambda-url.us-east-1.on.aws/"})
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x-abc123.example.test"}]}}
    out = orq.lambda_handler({"Records": [{"cf": {"request": req}}]}, Ctx())
    allowed = {"uri", "method", "querystring", "headers", "origin", "body",
               "clientIp"}
    assert set(out) <= allowed, f"request 对象多了键: {set(out) - allowed}"


# ── 写入形态 ────────────────────────────────────────────────────

def test_written_item_shape(monkeypatch):
    captured = {}

    class FakeClient:
        def put_item(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(orq, "_access_client", lambda rg: FakeClient())
    orq._record_access(Ctx(), "notes-01d147", "/x", "allow", "a@b.co")
    assert captured["TableName"] == "site-access-events"
    item = captured["Item"]
    assert item["site_date"]["S"].startswith("notes-01d147#")
    assert len(item["site_date"]["S"].split("#")[1]) == 10       # YYYY-MM-DD
    assert "#" in item["ts_id"]["S"]
    assert item["email"]["S"] == "a@b.co"
    assert item["decision"]["S"] == "allow"
    # path 原本漏了断言（Step 5 注入③实测发现）——少了它，"记的是哪个路径"
    # 这件事根本没被任何用例看着。
    assert item["path"]["S"] == "/x"
    assert int(item["expires_at"]["N"]) > 0


def test_recorded_path_is_the_user_visible_one_not_the_bucket_key(monkeypatch):
    """走**完整 handler** 确认记的是用户看到的路径，不是改写后的桶内 key。

    Step 5 注入③实测补出来的。brief 预期这条由 `test_written_item_shape` 兜住，
    实测**没兜住**：那条用例(a)当时根本没断言 `path`，(b)直接调 `_record_access`、
    不经 `lambda_handler`，所以结构上看不见"什么时候取 uri"这个缺陷。
    把 `_maybe_record` 挪到 `_route_request` 之后（或改用 `request["uri"]`）就会
    记成 `/sites/x/index.html`——统计页上每个站点只剩一条路径，PV 分布全废。
    """
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda ctx, site_id, uri, decision, email: seen.append(uri))
    monkeypatch.setattr(orq, "_add_s3_sigv4_auth", lambda *a, **k: None)
    monkeypatch.setattr(orq, "_lookup_route", lambda sub: {
        "require_auth": False, "route_mode": "split", "static_prefix": "sites/x"})
    event = {"Records": [{"cf": {"request": {
        "uri": "/notes", "method": "GET", "querystring": "",
        "headers": {"host": [{"key": "Host", "value": "app-x-abc123.example.test"}]}}}}]}
    out = orq.lambda_handler(event, Ctx())
    # 先钉住前提，否则改写没发生时本用例会空转通过
    assert out["uri"] == "/sites/x/index.html", "前提不成立：_route_request 没改写 uri"
    assert seen == ["/notes"], f"记成了改写后的桶内 key: {seen}"


def test_unauthenticated_denial_writes_an_empty_email(monkeypatch):
    """302（未登录）没有身份可言 → 空串。DynamoDB 允许**非键**属性为空串。"""
    captured = {}

    class FakeClient:
        def put_item(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(orq, "_access_client", lambda rg: FakeClient())
    orq._record_access(Ctx(), "x-abc123", "/", "redirect_login", "")
    assert captured["Item"]["email"]["S"] == ""


# ── sink：403 也要拿到已验签邮箱 ─────────────────────────────────

def test_sink_carries_email_even_when_access_is_forbidden():
    """被拒记录的价值在于"谁被拒了"，所以 403 分支也要有邮箱。"""
    import base64, hashlib, hmac, time
    payload = base64.urlsafe_b64encode(json.dumps(
        {"email": "out@b.co", "exp": int(time.time()) + 600}).encode()).rstrip(b"=").decode()
    head = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(
        b"test-secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token = f"{head}.{payload}.{sig}"
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x.example.test"}],
                       "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}
    sink = {}
    denied = orq._check_auth(req, {"require_auth": True, "allowed_users": [],
                                   "owner": "someone@else.co"}, "app-x.example.test",
                             sink)
    assert denied and denied["status"] == "403"
    assert sink["email"] == "out@b.co"


def test_untrusted_idp_session_yields_302_without_an_email():
    """P2-1 的回归：签名有效但 idp/auth_via 不可信 → 302 且 sink 里**没有**邮箱。

    这条与上一条是一对：403 必须有邮箱（"谁被拒了"），302 必须没有
    （契约说 redirect_login 的 email 是空串）。只写其中一条都会漏掉 P2-1。
    需要 REQUIRE_IDP_CLAIM=true 的副本，机制照 test_edge_auth.py 的
    `_edge_noidp_testable` 形态：把占位符替换成 true 后重新加载模块。
    """
    import importlib
    src = (Path(__file__).parents[0] / "origin_request.py").read_text()
    subs = dict(_SUBS, **{"{{REQUIRE_IDP_CLAIM}}": "true"})
    for k, v in subs.items():
        src = src.replace(k, v)
    (Path(__file__).parent / "_edge_access_idp_testable.py").write_text(src)
    mod = importlib.import_module("_edge_access_idp_testable")
    import base64, hashlib, hmac, time
    head = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"email": "linked@b.co", "exp": int(time.time()) + 600,
         "idp": "Cognito",
         "auth_via": "TokenGeneration_Authentication"}).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(
        b"test-secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x.example.test"}],
                       "cookie": [{"key": "Cookie",
                                   "value": f"sb_session={head}.{payload}.{sig}"}]}}
    sink = {}
    denied = mod._check_auth(req, {"require_auth": True, "allowed_users": "org"},
                             "app-x.example.test", sink)
    assert denied and denied["status"] == "302"
    assert sink.get("email", "") == "", (
        f"302 却带了邮箱: {sink}——违反 spec §1.1 的 redirect_login 契约")
