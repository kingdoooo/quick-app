"""handler 层：路由、错误码、以及**副作用前置顺序**。"""
import json
from unittest.mock import patch

import boto3
import pytest

import api
import handler
import permissions
import session
from test_authz import _seed
from upgrade_code_vectors import SECRET

CONSOLE = "console.example.com"


def _ev(method, path, *, email="owner@x.com", cookie=None, origin=None,
        body=None, ctype="application/json", qs=None):
    headers = {"x-user-email": email, "x-user-name": "Owner"}
    if cookie:
        headers["cookie"] = cookie
    if origin is not None:
        headers["origin"] = origin
    if ctype:
        headers["content-type"] = ctype
    return {"rawPath": path,
            "requestContext": {"http": {"method": method}},
            "headers": headers,
            "queryStringParameters": qs or {},
            "body": json.dumps(body) if body is not None else None}


def _cookie(email="owner@x.com"):
    import console_session
    return console_session.console_cookie(email, "Owner").split(";")[0]


def _write_ev(path, **kw):
    """一个"除了被测那一项之外样样合规"的写请求。"""
    kw.setdefault("cookie", _cookie(kw.get("email", "owner@x.com")))
    kw.setdefault("origin", f"https://{CONSOLE}")
    return _ev(kw.pop("method", "PUT"), path, **kw)


def test_missing_edge_identity_is_401_not_500(aws, secret):
    """没有 x-user-email 说明请求没经过 Edge——必须拒绝，且不是 500。"""
    ev = _ev("GET", "/api/me")
    del ev["headers"]["x-user-email"]
    assert handler.handler(ev, None)["statusCode"] == 401


def test_read_without_console_session_is_allowed(aws, secret):
    """读接口只要 Edge 身份即可（面板会话是写操作的前置）。"""
    r = handler.handler(_ev("GET", "/api/me"), None)
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["email"] == "owner@x.com"


def test_write_without_console_session_is_401_with_need_hint(aws, secret):
    _seed()
    r = handler.handler(_ev("PUT", "/api/sites/s-1/permissions",
                            origin=f"https://{CONSOLE}",
                            body={"require_login": False}), None)
    assert r["statusCode"] == 401
    assert json.loads(r["body"])["need"] == "console-session"


def test_csrf_failure_performs_zero_writes(aws, secret):
    """**副作用前置断言**：CSRF 不合法时不得有任何 DynamoDB 写调用。

    spec §5.4：不得出现"先更新 DynamoDB，再发现 CSRF 不合法"。
    在 boto3 层装间谍：任何写路径都会经过它，比断言业务结果更严
    （业务结果没变也可能是写了又被改回）。
    """
    _seed()
    seen = []
    real_resource = boto3.resource
    real_client = boto3.client

    class TableSpy:
        def __init__(self, inner, name):
            self._i, self._n = inner, name

        def __getattr__(self, k):
            if k in ("put_item", "update_item", "delete_item"):
                seen.append((self._n, k))
            return getattr(self._i, k)

    class ResSpy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def Table(self, n):
            return TableSpy(self._i.Table(n), n)

    class ClientSpy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            if k in ("put_item", "update_item", "delete_item",
                     "transact_write_items"):
                seen.append(("client", k))
            return getattr(self._i, k)

    with patch.object(boto3, "resource",
                      lambda *a, **k: ResSpy(real_resource(*a, **k))), \
         patch.object(boto3, "client",
                      lambda *a, **k: ClientSpy(real_client(*a, **k))):
        r = handler.handler(_ev("PUT", "/api/sites/s-1/permissions",
                                cookie=_cookie(),
                                origin="https://evil.example.com",
                                body={"require_login": False}), None)
    assert r["statusCode"] == 403
    assert seen == [], f"CSRF 失败却发生了写调用: {seen}"


def test_bad_console_session_performs_zero_writes(aws, secret):
    """同上，但失败点是面板会话（顺序里的第 ③ 步）。"""
    _seed()
    seen = []
    real_resource = boto3.resource

    class ResSpy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def Table(self, n):
            inner = self._i.Table(n)

            class T:
                def __getattr__(s, k):
                    if k in ("put_item", "update_item", "delete_item"):
                        seen.append((n, k))
                    return getattr(inner, k)
            return T()

    with patch.object(boto3, "resource",
                      lambda *a, **k: ResSpy(real_resource(*a, **k))):
        # 拿别人的面板会话（email 不匹配 Edge 身份）
        r = handler.handler(_ev("PUT", "/api/sites/s-1/permissions",
                                cookie=_cookie("someone@x.com"),
                                origin=f"https://{CONSOLE}",
                                body={"require_login": False}), None)
    assert r["statusCode"] == 401
    assert seen == [], f"会话校验失败却发生了写调用: {seen}"


def test_permission_denied_is_403(aws, secret):
    _seed()
    r = handler.handler(_write_ev("/api/sites/s-1/permissions",
                                  email="nobody@x.com",
                                  body={"require_login": False}), None)
    assert r["statusCode"] == 403


def test_permission_conflict_is_409(aws, secret):
    _seed()
    with patch.object(permissions, "set_access_policy",
                      side_effect=permissions.PermissionConflict("并发")):
        r = handler.handler(_write_ev("/api/sites/s-1/permissions",
                                      body={"require_login": False}), None)
    assert r["statusCode"] == 409


def test_value_error_is_400(aws, secret):
    """非法邮箱这类入口校验错误是用户可纠正的，不该是 500。"""
    _seed()
    r = handler.handler(_write_ev("/api/sites/s-1/collaborators",
                                  body={"add": ["not-an-email"]}), None)
    assert r["statusCode"] == 400


def test_unknown_route_is_404(aws, secret):
    assert handler.handler(_ev("GET", "/api/nope"), None)["statusCode"] == 404


def test_unknown_route_does_not_require_console_session(aws, secret):
    """404 不该先要求面板会话——否则探测者拿到的是 401，路由表被间接泄漏。"""
    r = handler.handler(_ev("POST", "/api/nope", origin=f"https://{CONSOLE}"),
                        None)
    assert r["statusCode"] == 404


def test_wrong_method_on_known_path_is_404(aws, secret):
    assert handler.handler(_ev("DELETE", "/api/me"), None)["statusCode"] == 404


def test_malformed_json_body_is_400_not_500(aws, secret):
    ev = _write_ev("/api/sites/s-1/permissions")
    ev["body"] = "{not json"
    assert handler.handler(ev, None)["statusCode"] == 400


def test_non_object_json_body_is_400(aws, secret):
    ev = _write_ev("/api/sites/s-1/permissions")
    ev["body"] = "[1,2,3]"
    assert handler.handler(ev, None)["statusCode"] == 400


def test_unexpected_exception_is_500_without_leaking_internals(aws, secret):
    """500 的 body 不得含堆栈/ARN/表名——那是内部结构泄漏。"""
    with patch.object(api, "do_me", side_effect=RuntimeError(
            "arn:aws:dynamodb:us-east-1:000000000000:table/site-sites 挂了")):
        r = handler.handler(_ev("GET", "/api/me"), None)
    assert r["statusCode"] == 500
    for bad in ("arn:aws", "site-sites", "Traceback", "RuntimeError"):
        assert bad not in r["body"], f"500 响应泄漏了 {bad}"


def test_responses_are_no_store(aws, secret):
    """面板响应随权限变化，绝不能被缓存。"""
    r = handler.handler(_ev("GET", "/api/me"), None)
    assert r["headers"]["cache-control"] == "no-store"


def test_user_name_is_url_decoded(aws, secret):
    """Edge 注入的 x-user-name 是 URL 编码的（含中文/空格）。"""
    ev = _ev("GET", "/api/me")
    ev["headers"]["x-user-name"] = "%E5%BC%A0%20%E4%B8%89"
    assert json.loads(handler.handler(ev, None)["body"])["name"] == "张 三"


def test_session_callback_sets_console_cookie_and_redirects(aws, secret):
    code = session.mint_upgrade_code("owner@x.com", SECRET)
    r = handler.handler(_ev("GET", "/api/session-callback",
                            qs={"code": code}), None)
    assert r["statusCode"] == 302
    assert any("__Host-sb_console=" in c for c in r.get("cookies", []))


def test_session_callback_rejects_replayed_code(aws, secret):
    code = session.mint_upgrade_code("owner@x.com", SECRET)
    ev = _ev("GET", "/api/session-callback", qs={"code": code})
    assert handler.handler(ev, None)["statusCode"] == 302
    assert handler.handler(ev, None)["statusCode"] == 401


def test_callback_code_email_must_match_edge_identity(aws, secret):
    """拿别人的 code 到自己的会话里换 cookie —— 必须拒绝。"""
    code = session.mint_upgrade_code("victim@x.com", SECRET)
    r = handler.handler(_ev("GET", "/api/session-callback",
                            email="attacker@x.com", qs={"code": code}), None)
    assert r["statusCode"] == 401
    assert not r.get("cookies"), "拒绝路径不该设 cookie"


def test_callback_without_code_is_401(aws, secret):
    assert handler.handler(_ev("GET", "/api/session-callback"),
                           None)["statusCode"] == 401


def test_full_write_roundtrip_succeeds(aws, secret):
    """五步全部合规时写操作要真的成功（防"全都拒绝"式假安全）。"""
    _seed()
    r = handler.handler(_write_ev("/api/sites/s-1/permissions",
                                  body={"require_login": False}), None)
    assert r["statusCode"] == 200
    import common
    assert common.get_site("s-1")["require_login"] is False


def test_admin_routes_dispatch(aws, secret):
    permissions.add_admin("boss@x.com", "seed")
    r = handler.handler(_ev("GET", "/api/admins", email="boss@x.com"), None)
    assert r["statusCode"] == 200
    assert "boss@x.com" in json.loads(r["body"])["admins"]
    r = handler.handler(_write_ev("/api/admins", email="boss@x.com",
                                  body={"email": "new@x.com"}), None)
    assert r["statusCode"] == 200
    assert "new@x.com" in json.loads(r["body"])["admins"]


def test_jobs_and_get_site_dispatch(aws, secret):
    _seed()
    assert handler.handler(_ev("GET", "/api/sites/s-1"),
                           None)["statusCode"] == 200
    assert handler.handler(_ev("GET", "/api/sites/s-1/jobs"),
                           None)["statusCode"] == 200


def test_list_sites_all_flag_reaches_api(aws, secret):
    _seed()
    r = handler.handler(_ev("GET", "/api/sites", qs={"all": "1"}), None)
    assert r["statusCode"] == 403       # 非 admin
    permissions.add_admin("boss@x.com", "seed")
    r = handler.handler(_ev("GET", "/api/sites", email="boss@x.com",
                            qs={"all": "1"}), None)
    assert r["statusCode"] == 200


def test_resync_route_dispatch(aws, secret):
    _seed()
    permissions.add_admin("boss@x.com", "seed")
    r = handler.handler(_write_ev("/api/admin/resync/s-1", method="POST",
                                  email="boss@x.com", body={}), None)
    assert r["statusCode"] == 200


def test_undeploy_dispatch_is_async_and_returns_job(aws, secret, monkeypatch):
    _seed()
    invoked = []
    real_client = boto3.client

    class Spy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def invoke(self, **kw):
            invoked.append(kw)
            return {"StatusCode": 202}

    monkeypatch.setattr(boto3, "client",
                        lambda *a, **k: Spy(real_client(*a, **k))
                        if a and a[0] == "lambda" else real_client(*a, **k))
    r = handler.handler(_write_ev("/api/sites/s-1/undeploy", method="POST",
                                  body={"purge_data": False}), None)
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["job_id"].startswith("job-")
    assert invoked and invoked[0]["InvocationType"] == "Event"
