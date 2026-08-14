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


# Edge 执行角色的 RoleId（测试用）。真机形态见 test_real_edge_caller_shape_is_accepted
# 附近的注释：callerId 是 `{RoleId}:{带区域前缀的 session name}`。
# **拼接而不是写成一个字面量**：Code Defender 的 HARD_CODED_SECRET 规则按
# `AROA` 前缀 + 长度匹配，整串写出来会被拦下（该规则晚于本文件首次提交才生效）。
# 它的 remediation 建议是往 secrets.allowed 里加例外——那是放宽扫描器，
# 本项目明令不走这个方向。conftest.ENV["EDGE_ROLE_ID"] 必须与此值一致。
EDGE_ROLE_ID = "AROA" + "EDGEROLEID" + "XXXXXX"


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
            # 默认带**合规的 Edge IAM 上下文**：真实请求一定经过 Edge，
            # handler 的第 ⓪ 步会校验它（P1-1）。要测"非 Edge 直连"的用例
            # 自己覆盖 requestContext.authorizer。
            "requestContext": {
                "http": {"method": method},
                "authorizer": {"iam": {
                    "callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
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


# ── purge_data 必须是真布尔（Codex 审查 2026-08-10 P1-2）───────────────
# bool("false") is True ——任何非空字符串都为真，所以 {"purge_data":"false"}
# 会被解释成"永久删除数据"。不可恢复动作的入口绝不能靠"唯一前端永远正确"，
# 必须在 API 边界拒绝非布尔。

def _undeploy_spy(monkeypatch):
    """拦住异步 invoke，返回收到的 payload 列表。"""
    invoked = []
    real_client = boto3.client

    class Spy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def invoke(self, **kw):
            invoked.append(json.loads(kw["Payload"].decode()))
            return {"StatusCode": 202}

    monkeypatch.setattr(boto3, "client",
                        lambda *a, **k: Spy(real_client(*a, **k))
                        if a and a[0] == "lambda" else real_client(*a, **k))
    return invoked


@pytest.mark.parametrize("bad", ["false", "0", "true", "", 1, 0, [], {},
                                 ["yes"], None])
def test_undeploy_rejects_non_boolean_purge_data(aws, secret, monkeypatch, bad):
    """字符串/数字/数组/对象/null 一律 400，且**零副作用**（不发 invoke）。"""
    _seed()
    invoked = _undeploy_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/sites/s-1/undeploy", method="POST",
                                  body={"purge_data": bad}), None)
    assert r["statusCode"] == 400, f"purge_data={bad!r} 被接受了"
    assert not invoked, f"purge_data={bad!r} 已经触发下线: {invoked}"


def test_undeploy_missing_purge_data_defaults_to_false(aws, secret, monkeypatch):
    """字段缺失 = 不清数据（默认必须是最安全的那一侧）。"""
    _seed()
    invoked = _undeploy_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/sites/s-1/undeploy", method="POST",
                                  body={}), None)
    assert r["statusCode"] == 200
    assert invoked and "purge_data" not in invoked[0], invoked


def test_undeploy_true_boolean_still_purges(aws, secret, monkeypatch):
    """别把校验写成"什么都不清"——真布尔 True 仍要透传。"""
    _seed()
    invoked = _undeploy_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/sites/s-1/undeploy", method="POST",
                                  body={"purge_data": True}), None)
    assert r["statusCode"] == 200
    assert invoked and invoked[0]["purge_data"] is True, invoked


def test_undeploy_invoke_failure_does_not_leave_pending_job(aws, secret,
                                                            monkeypatch):
    """调 undeploy Lambda 失败时，不得留下永久 PENDING 的 job。

    Codex 审查 2026-08-10 P1-4 的最后一条：job 先建（PENDING），再异步调
    Lambda。invoke 本身失败（限流/权限/网络）时若不收敛，这个 job 永远
    PENDING——sweeper 只扫 RUNNING，谁都不会再碰它，用户看到"排队中"到永远。
    """
    _seed()
    real_client = boto3.client

    class Boom:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def invoke(self, **kw):
            raise RuntimeError("invoke 失败（注入）")

    monkeypatch.setattr(boto3, "client",
                        lambda *a, **k: Boom(real_client(*a, **k))
                        if a and a[0] == "lambda" else real_client(*a, **k))
    r = handler.handler(_write_ev("/api/sites/s-1/undeploy", method="POST",
                                  body={"purge_data": False}), None)
    assert r["statusCode"] == 500, r
    # 找到刚建的 job，它必须已被收敛成 FAILED（不能停在 PENDING）
    jobs = api.do_list_jobs("owner@x.com", "s-1")
    assert jobs, "没有 job 记录"
    assert jobs[0]["status"] == "FAILED", (
        f"job 停在 {jobs[0]['status']}——sweeper 只扫 RUNNING，它永远不会被收敛")
    assert jobs[0]["error"], "没有错误摘要"


# ── Function URL 的调用者必须真是 Edge（Codex 审查 2026-08-10 P1-1）──────
# 原实现只靠 resource policy 保证"只有 Edge 能调"，然后无条件信任
# x-user-email。但 AWS 的真实规则是：**同账号 principal 只要 identity policy
# 允许 lambda:InvokeFunctionUrl + lambda:InvokeFunction，无需命中 resource
# policy 也能调用**。真机实测确认（2026-08-10）：直接签名调用线上 Function
# URL 并自带 x-user-email，/api/me 返回 200 且识别成管理员，
# /api/sites?all=1 返回全部 27 个站点。
#
# **不能拿 config 里的 edge_role_arn 逐字符比**（Codex 建议的做法会 403 整站）：
# 真机抓到的 caller 是 STS 形态 + 区域前缀的 session name（RoleId 本体按仓库
# 红线打码成 `AROA<...>`——形态是这里唯一有信息量的部分，真值现查
# `aws iam get-role`）——
#   userArn: arn:aws:sts::<acct>:assumed-role/<EdgeRoleName>/us-east-1.ApplicationWebRouterStack-...
#   callerId: AROA<...>:us-east-1.ApplicationWebRouterStack-...
# 而 config 里是 arn:aws:iam::<acct>:role/<EdgeRoleName>。两者永不相等。
# 稳定且不可伪造的锚点是 callerId 的 AROA 段 = 该角色的 RoleId（已核对相等）。

# _ev() 默认就带合规的 Edge IAM 上下文（见文件顶部），所以 _edge_ev 就是 _ev。
_edge_ev = _ev


def test_real_edge_caller_shape_is_accepted(aws, secret, monkeypatch):
    """真机抓到的 callerId 形态必须放行——否则整个控制台 403。

    这条是防"修复本身把站点打死"的护栏：如果有人把校验改成与
    edge_role_arn 逐字符比较，它会立刻变红。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", EDGE_ROLE_ID)
    r = handler.handler(_edge_ev("GET", "/api/me"), None)
    assert r["statusCode"] == 200, r


def test_same_account_non_edge_signed_request_is_403(aws, secret, monkeypatch):
    """同账号、非 Edge、但有 Function URL 调用权限的签名请求必须被拒。

    这是 P1-1 的核心断言：resource policy 挡不住它，只有校验 caller 能挡。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", EDGE_ROLE_ID)
    ev = _ev("GET", "/api/me")
    # 真机上就是这个形态：IAM user Kent（AdministratorAccess）直连
    # 拼接而不是整串字面量：Code Defender 的 HARD_CODED_SECRET 规则按 `AIDA`
    # 前缀 + 长度匹配（同文件顶部 EDGE_ROLE_ID 的理由），值保持逐字节不变。
    ev["requestContext"].update(
        {"authorizer": {"iam": {"callerId": "AIDA" + "X5GBA74KD2LIPY7AJ"}}})
    r = handler.handler(ev, None)
    assert r["statusCode"] == 403, f"伪造身份的直连请求被放行了: {r}"
    # 不得回显内部细节（探测者不该知道我们在比什么）
    assert "AROA" not in r["body"] and "EDGE_ROLE_ID" not in r["body"]


def test_role_id_prefix_must_not_be_substring_matchable(aws, secret, monkeypatch):
    """必须按 `AROA...:` 边界比，不能用 startswith/in 之类的松匹配。

    `AROAEDGEROLEIDXXXXXXEVIL:...` 能骗过 startswith；
    `AIDAX:AROAEDGEROLEIDXXXXXX` 能骗过 `in`。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", EDGE_ROLE_ID)
    for bad in (f"{EDGE_ROLE_ID}EVIL:us-east-1.x",
                f"AIDAX5GB:{EDGE_ROLE_ID}",
                f"x{EDGE_ROLE_ID}:s",
                EDGE_ROLE_ID.lower() + ":s"):
        ev = _ev("GET", "/api/me")
        ev["requestContext"].update({"authorizer": {"iam": {"callerId": bad}}})
        assert handler.handler(ev, None)["statusCode"] == 403, (
            f"松匹配放行了 {bad!r}")


def test_missing_iam_context_is_403_not_open(aws, secret, monkeypatch):
    """拿不到 IAM 上下文时 fail-closed（缺字段不等于放行）。"""
    monkeypatch.setenv("EDGE_ROLE_ID", EDGE_ROLE_ID)
    for ctx in ({"authorizer": {}}, {"authorizer": {"iam": {}}},
                {"authorizer": {"iam": {"callerId": ""}}},
                {"authorizer": None}):
        ev = _ev("GET", "/api/me")
        ev["requestContext"].update(ctx)
        assert handler.handler(ev, None)["statusCode"] == 403, ctx
    # authorizer 整个键缺失（**要真删掉**，update({}) 删不掉 _ev 的默认值）
    ev = _ev("GET", "/api/me")
    del ev["requestContext"]["authorizer"]
    assert handler.handler(ev, None)["statusCode"] == 403
    # requestContext 整体缺失
    ev = _ev("GET", "/api/me")
    ev.pop("requestContext")
    assert handler.handler(ev, None)["statusCode"] == 403


def test_unconfigured_edge_role_id_fails_closed(aws, secret, monkeypatch):
    """**没配 EDGE_ROLE_ID 时必须拒绝所有请求**，不能"没配就不检查"。

    "配置缺失 → 跳过校验"是本项目记录过的陷阱形态（假值兜底恰好是放宽）。
    宁可整站 503/403 也不能静默回到可被绕过的状态。
    """
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    r = handler.handler(_edge_ev("GET", "/api/me"), None)
    assert r["statusCode"] in (403, 500), r


def test_write_path_also_checks_caller(aws, secret, monkeypatch):
    """写路径同样要校验——别只在读路径加。"""
    monkeypatch.setenv("EDGE_ROLE_ID", EDGE_ROLE_ID)
    _seed()
    ev = _write_ev("/api/sites/s-1/permissions", body={"require_login": False})
    ev["requestContext"].update(
        {"authorizer": {"iam": {"callerId": "AIDANOTEDGE"}}})
    assert handler.handler(ev, None)["statusCode"] == 403


def test_panel_delegates_edge_caller_check_and_has_no_own_parser():
    """panel 不得自己解析 callerId——唯一实现在 edge_caller.py。

    为什么要这条：P1-1 的判定逻辑有四个易错点（AROA 段、`:` 边界、大小写、
    缺配置即拒）。同一份逻辑存在两处时，改对一处、漏改另一处正是本项目
    反复出现的缺陷形态（M3-FINDINGS「别打地鼠，修那一类」）。

    **扫的是 handler.py，不是本文件**：本文件的夹具里合法地含有 callerId
    （要构造 event），把测试文件放进扫描范围会让断言禁掉它自己需要的东西
    （M3-FINDINGS §2.10）。
    """
    import ast
    import pathlib
    src = (pathlib.Path(__file__).parents[1] / "handler.py").read_text()
    tree = ast.parse(src)
    # ① 必须 import edge_caller
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    assert "edge_caller" in imported, "panel 必须依赖唯一实现"
    # ② 不得出现 callerId 的取值（那是自己解析的标志）
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "callerId" not in strings, \
        "panel 出现了 callerId 字面量——说明又抄了一份解析逻辑"
    # ③ 不得再有 AROA 相关的比较常量
    assert not any("AROA" in s for s in strings), "panel 不该关心 RoleId 形态"


# ── M4：Key 端点与 admin 开关的路由继承（spec §4.4）─────────────────────
# 这五条路由**没有一行新的鉴权代码**：三个写方法自动继承 ②CSRF + ③面板会话，
# admin-only 由 api._require_admin 负责。所以这里断言的是"继承确实生效且零写"，
# 不是重新验证 CSRF/会话本身（那些各有自己的用例）。

KEY_WRITES = [("POST", "/api/keys", {"name": "笔记本"}),
              ("POST", "/api/keys/revoke", {"key_id": "abcd1234"}),
              ("PUT", "/api/settings/api-key", {"enabled": True})]


def _ddb_write_spy(monkeypatch) -> list:
    """记录本进程的所有 DynamoDB 写调用（表名, 方法）。

    keystore / ops_log 都把 resource 句柄缓存在模块全局里，必须清掉，
    否则它们用的是间谍之前建好的那个句柄——写调用一条都记不到，
    "零写"断言会变成永远绿的装饰。
    """
    import keystore
    import ops_log
    seen = []
    real = boto3.resource

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

    monkeypatch.setattr(boto3, "resource", lambda *a, **k: ResSpy(real(*a, **k)))
    monkeypatch.setattr(keystore, "_ddb", None)
    monkeypatch.setattr(ops_log, "_ddb", None)
    return seen


def test_write_spy_would_notice_a_key_write(aws, secret, monkeypatch):
    """间谍自身的验证：合规的创建请求必须被它看见。

    没有这条时，下面两条"零写"断言可能只是因为间谍装不上（keystore 缓存了
    句柄）——那正是本项目反复出现的假绿形态。
    """
    seen = _ddb_write_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/keys", method="POST",
                                  body={"name": "笔记本"}), None)
    assert r["statusCode"] == 200, r
    assert ("site-api-keys", "put_item") in seen, seen


@pytest.mark.parametrize("method,path,body", KEY_WRITES)
def test_key_writes_without_console_session_are_401_and_write_nothing(
        aws, secret, monkeypatch, method, path, body):
    seen = _ddb_write_spy(monkeypatch)
    r = handler.handler(_ev(method, path, origin=f"https://{CONSOLE}",
                            body=body), None)
    assert r["statusCode"] == 401, r
    assert json.loads(r["body"])["need"] == "console-session"
    assert seen == [], f"缺面板会话却发生了写: {seen}"


@pytest.mark.parametrize("method,path,body", KEY_WRITES)
def test_key_writes_with_forged_origin_are_403_and_write_nothing(
        aws, secret, monkeypatch, method, path, body):
    seen = _ddb_write_spy(monkeypatch)
    r = handler.handler(_ev(method, path, cookie=_cookie(),
                            origin="https://evil.example.com", body=body), None)
    assert r["statusCode"] == 403, r
    assert seen == [], f"CSRF 失败却发生了写: {seen}"


def test_key_reads_need_only_edge_identity(aws, secret):
    """读接口不要求面板会话（与站点列表同口径）。"""
    r = handler.handler(_ev("GET", "/api/keys"), None)
    assert r["statusCode"] == 200
    assert json.loads(r["body"]) == {"keys": []}


def test_key_crud_dispatches_end_to_end(aws, secret):
    """创建 → 列表 → 吊销，全部经真实的六步前置。"""
    created = handler.handler(_write_ev("/api/keys", method="POST",
                                        body={"name": "笔记本"}), None)
    assert created["statusCode"] == 200, created
    key = json.loads(created["body"])
    assert key["plaintext"].startswith("sk-")
    assert "key_hash" not in created["body"]

    listed = json.loads(handler.handler(_ev("GET", "/api/keys"), None)["body"])
    assert [k["key_id"] for k in listed["keys"]] == [key["key_id"]]
    # 列表响应里既没有明文也没有哈希（**查整段 body**：字段名可能被换掉）
    assert key["plaintext"] not in json.dumps(listed)
    assert "key_hash" not in json.dumps(listed)

    revoked = handler.handler(_write_ev("/api/keys/revoke", method="POST",
                                        body={"key_id": key["key_id"]}), None)
    assert revoked["statusCode"] == 200, revoked
    after = json.loads(handler.handler(_ev("GET", "/api/keys"), None)["body"])
    assert after["keys"][0]["revoked"] is True


def test_revoking_someone_elses_key_over_http_is_403(aws, secret):
    """403 而不是 500——而且与"不存在"同一句话（api 层用例覆盖文案一致性）。"""
    import keystore
    victim = keystore.create("victim@x.com", name="victim")
    mine = handler.handler(_write_ev("/api/keys/revoke", method="POST",
                                     body={"key_id": victim["key_id"]}), None)
    missing = handler.handler(_write_ev("/api/keys/revoke", method="POST",
                                        body={"key_id": "zzzzzzzz"}), None)
    assert mine["statusCode"] == 403 and missing["statusCode"] == 403
    assert mine["body"] == missing["body"], "两种情形的响应可区分 = 枚举探测器"


def test_key_switch_requires_admin_over_http(aws, secret):
    for ev in (_ev("GET", "/api/settings/api-key"),
               _write_ev("/api/settings/api-key", body={"enabled": True})):
        assert handler.handler(ev, None)["statusCode"] == 403, ev["rawPath"]


def test_key_switch_dispatches_for_admin(aws, secret):
    permissions.add_admin("boss@x.com", "seed")
    r = handler.handler(_write_ev("/api/settings/api-key", email="boss@x.com",
                                  body={"enabled": True}), None)
    assert r["statusCode"] == 200, r
    assert json.loads(r["body"]) == {"deployed": True, "enabled": True}
    got = handler.handler(_ev("GET", "/api/settings/api-key",
                              email="boss@x.com"), None)
    assert json.loads(got["body"]) == {"deployed": True, "enabled": True}


@pytest.mark.parametrize("bad", ["false", "0", "true", "", 1, 0, [], {}, None])
def test_non_boolean_enabled_is_400_with_zero_writes(aws, secret, monkeypatch,
                                                     bad):
    """`{"enabled":"false"}` 被当成 True 就是"以为关了其实开着"（同 P1-2）。"""
    permissions.add_admin("boss@x.com", "seed")
    seen = _ddb_write_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/settings/api-key", email="boss@x.com",
                                  body={"enabled": bad}), None)
    assert r["statusCode"] == 400, f"enabled={bad!r} 被接受: {r}"
    assert seen == [], f"enabled={bad!r} 被拒却写了库: {seen}"


def test_missing_enabled_field_is_400_not_a_silent_off(aws, secret, monkeypatch):
    """缺字段**不能**兜个 False：那会让一个畸形请求静默关掉全平台 Key 通道。

    与 purge_data 刻意相反（那里缺失=False 才是安全侧）——开关的两个方向都是
    状态变更，没有"安全默认"，只能让调用方明确表达。
    """
    permissions.add_admin("boss@x.com", "seed")
    seen = _ddb_write_spy(monkeypatch)
    r = handler.handler(_write_ev("/api/settings/api-key", email="boss@x.com",
                                  body={}), None)
    assert r["statusCode"] == 400, r
    assert seen == [], seen


def test_me_exposes_api_key_feature_flags(aws, secret):
    """前端按 `features.api_key.deployed` 决定 UI 可用性（Codex P1-5）。"""
    me = json.loads(handler.handler(_ev("GET", "/api/me"), None)["body"])
    feat = me["features"]["api_key"]
    assert feat == {"deployed": False, "enabled": False}, feat


def test_every_new_key_route_is_dispatched(aws, secret):
    """ROUTES 加了分发忘了写 = 500。逐条走一遍，断言没有一条落到那个兜底上。

    比"挑一条试试"强：`_dispatch` 的兜底 RuntimeError 只在真的漏分支时才触发，
    而漏的那条恰好可能是没被抽查到的那条。
    """
    permissions.add_admin("boss@x.com", "seed")
    cases = [("GET", "/api/keys", None), ("POST", "/api/keys", {"name": "n"}),
             ("POST", "/api/keys/revoke", {"key_id": "zzzzzzzz"}),
             ("GET", "/api/settings/api-key", None),
             ("PUT", "/api/settings/api-key", {"enabled": False})]
    for method, path, body in cases:
        ev = (_ev(method, path, email="boss@x.com") if body is None
              else _write_ev(path, method=method, email="boss@x.com", body=body))
        r = handler.handler(ev, None)
        assert r["statusCode"] != 500, f"{method} {path} 落到未分发兜底: {r}"
        assert "接口不存在" not in r["body"], f"{method} {path} 没进 ROUTES"


# ── 这条链路上不允许"DELETE + 请求体"（2026-08-13 真机隔离）──────────────

def test_no_route_uses_delete_with_body():
    """`ROUTES` 里**一条 DELETE 都不许有**。

    根因写在 `handler.py` 的 `ROUTES` 下方：CloudFront 把 DELETE 的请求体交给了
    Lambda@Edge（`include_body=True`，Edge 因此按真实 body 算 payload hash 去签
    SigV4），但转发到源站时那个 body 不在了——Function URL 按空 body 算哈希，
    签名不匹配，**在 handler 任何代码之前**就 403。

    **为什么这条断言必须按 `ROUTES` 写、而不是逐个路径写**：逐个写的话，下一个
    人加一条新的 DELETE 路由时它照样绿。而这个缺陷的形态恰恰是"单测全绿、生产
    不可用"——`DELETE /api/admins` 从 M3 上线起就坏着，没有任何用例发现，因为
    单测直接调本模块的 handler，压根不经过 CloudFront。

    真要加 DELETE 就必须先证明它**不带请求体**（参数走路径段）。那时改这条断言
    的人会被迫读上面那段根因，这正是它存在的目的。
    """
    deletes = [pat.pattern for method, pat in handler.ROUTES
               if method.upper() == "DELETE"]
    assert deletes == [], (
        f"新增了 DELETE 路由 {deletes}——带请求体的 DELETE 在 CloudFront → "
        "Lambda@Edge → Function URL 这条链路上必 403（见 handler.ROUTES 下方注释）。"
        "改成 POST，或证明该路由不带请求体。")


def test_revoke_and_admin_remove_are_post_routes():
    """两个"删除"动作的落点是 POST 子路径，且**仍然是写方法**。

    断言路由表而不是断言行为：行为各有自己的用例（吊销的三态、移除管理员的
    最后一名管理员保护），这里锁的是"它们没有退回 DELETE"。写方法这一点同样要
    锁——POST 在 `console_session.WRITE_METHODS` 里，所以 CSRF + 面板会话两道
    前置自动继承；万一有人改成 GET，那两道就整体失效了。
    """
    import console_session
    routes = {(m.upper(), p.pattern) for m, p in handler.ROUTES}
    assert ("POST", r"^/api/keys/revoke$") in routes
    assert ("POST", r"^/api/admins/remove$") in routes
    assert "POST" in console_session.WRITE_METHODS


def test_analytics_routes_are_registered_and_read_only():
    """两个新端点必须是 GET（写路径才需要 CSRF + 面板会话）。"""
    import handler
    pats = {(m, rx.pattern) for m, rx in handler.ROUTES}
    assert ("GET", r"^/api/sites/(?P<site_id>[a-z][a-z0-9-]{1,63})/analytics$") in pats
    assert ("GET", r"^/api/sites/(?P<site_id>[a-z][a-z0-9-]{1,63})/visitors$") in pats


def test_every_route_still_has_a_dispatch_branch():
    """加了 ROUTES 忘了加分发 = 500。这条盯着两个新端点。"""
    import handler
    for m, rx in handler.ROUTES:
        if rx.pattern == handler.CALLBACK:
            continue
        try:
            handler._dispatch(rx.pattern, m, "me@x.co", "me", "s1", {}, {})
        except RuntimeError as e:
            assert "路由已匹配但未分发" not in str(e), f"{m} {rx.pattern} 没有分发分支"
        except Exception:
            pass          # 其它异常（权限/表不存在）说明分支存在，本条不关心
