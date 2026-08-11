"""panel Lambda 入口：六步前置校验 + 路由分发 + 错误码。

**顺序是安全边界，不是风格**（spec §5.4）：
  ⓪ 传输层：**IAM 调用者必须是 Edge 执行角色**
     （`edge_caller.caller_is_edge`——**唯一实现**，panel 与 key-proxy 共用，
     本文件不自己解析 callerId；判定形态与真机证据见那个模块）。
     resource policy 单独不够——同账号 principal 只要 identity policy 给了
     lambda:InvokeFunctionUrl + InvokeFunction，就能绕开 resource policy 直连
     并自带伪造的 x-user-email（Codex 审查 2026-08-10 P1-1，真机验证过：
     `/api/me` 返回 200 且 is_admin=true、`/api/sites?all=1` 返回全部站点）。
  ① 身份：x-user-email 必须存在。它由 Edge **先剥除再注入**，所以在 ⓪ 已经
     确认调用者是 Edge 的前提下，它存在就等于"请求确实经过 CloudFront +
     Lambda@Edge"。⓪ 与 Function URL 的 AWS_IAM + exact edge role resource
     policy 是这个推论的前提（见 deploy_panel.py）——缺任一层，本文件的整套
     身份假设就失效。
  ② 写方法：CSRF（Origin 精确匹配 / Content-Type / 方法白名单）；
  ③ 写方法：__Host-sb_console 验签 + scope==console + email 与 ① 一致；
  ④ 路由分发；
  ⑤ 业务副作用（权限判定在 permissions 内部与写入同快照，不在这里预判）。

②③ 必须在 ④⑤ 之前：不得出现"先更新 DynamoDB，再发现 CSRF 不合法"。
test_csrf_failure_performs_zero_writes 在 boto3 层装写调用间谍锁定这一点。

路由匹配在 ②③ **之前**：404 不该要求面板会话，否则未知路径返回 401，
探测者能据此区分"路径存在但没会话"与"路径不存在"。
"""
import json
import logging
import os
import re
import urllib.parse

import api
import console_session
import edge_caller
import permissions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

READ_ONLY = ("GET",)
_SITE = r"(?P<site_id>[a-z][a-z0-9-]{1,63})"

# (method, 编译后的 pattern)。pattern 字符串同时用作 _dispatch 的分支键。
ROUTES = [
    ("GET", re.compile(r"^/api/me$")),
    ("GET", re.compile(r"^/api/sites$")),
    ("GET", re.compile(rf"^/api/sites/{_SITE}$")),
    ("GET", re.compile(rf"^/api/sites/{_SITE}/jobs$")),
    ("PUT", re.compile(rf"^/api/sites/{_SITE}/permissions$")),
    ("PUT", re.compile(rf"^/api/sites/{_SITE}/collaborators$")),
    ("PUT", re.compile(rf"^/api/sites/{_SITE}/owner$")),
    ("POST", re.compile(rf"^/api/sites/{_SITE}/undeploy$")),
    ("GET", re.compile(r"^/api/admins$")),
    ("PUT", re.compile(r"^/api/admins$")),
    ("DELETE", re.compile(r"^/api/admins$")),
    ("POST", re.compile(rf"^/api/admin/resync/{_SITE}$")),
    ("GET", re.compile(r"^/api/session-callback$")),
]
CALLBACK = r"^/api/session-callback$"


def _json(status: int, payload, cookies=None) -> dict:
    out = {"statusCode": status,
           "headers": {"content-type": "application/json",
                       # 面板响应一律不缓存：内容随权限变化
                       "cache-control": "no-store"},
           "body": json.dumps(payload, ensure_ascii=False)}
    if cookies:
        out["cookies"] = cookies
    return out


def handler(event, context):
    method = (event.get("requestContext", {}).get("http", {})
              .get("method", "GET")).upper()
    path = event.get("rawPath", "/")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    qs = event.get("queryStringParameters") or {}

    # ⓪ 传输层：调用者必须真是 Edge 的执行角色。
    #    ① 的整套推论（"x-user-email 存在 ⇒ 请求经过 Edge"）依赖它——
    #    同账号 IAM 身份可以绕开 resource policy 直连 Function URL 并自带
    #    伪造的 x-user-email（真机验证过，判定形态见 edge_caller）。
    #    **不在这里重写判定**：唯一实现在 edge_caller.py，panel 与 key-proxy
    #    共用一份（同一逻辑存在两处时"改对一处、漏改另一处"是本项目反复
    #    出现的缺陷形态）。test_panel_delegates_edge_caller_check_* 盯着这点。
    #    与 ① 同样不回显原因：探测者不该知道我们在比什么。
    if not edge_caller.caller_is_edge(event):
        return _json(403, {"error": "禁止访问"})

    # ① 身份。**不给假值兜底**：鉴权字段的"默认值"往往正好是"放宽"
    #    （本项目已记录过这个陷阱）。也不回显原因——直连 Function URL 的
    #    探测不该拿到任何信息。
    email = headers.get("x-user-email", "")
    if not email:
        return _json(401, {"error": "未认证"})
    # x-user-name 由 Edge URL 编码后注入（可能含中文/空格）
    name = urllib.parse.unquote(headers.get("x-user-name", "") or email)

    # 路由匹配（先匹配再做写前置，见模块 docstring）
    matched = None
    for m, rx in ROUTES:
        hit = rx.match(path)
        if hit and m == method:
            matched = (rx.pattern, hit.groupdict())
            break
    if matched is None:
        return _json(404, {"error": "接口不存在"})
    pattern, params = matched
    site_id = params.get("site_id", "")

    # session-callback 是升级入口本身，不能要求"已有面板会话"
    if pattern == CALLBACK:
        try:
            # 身份比对在 consume_code **内部**、且在原子消费 jti **之前**
            # （Codex 审查 2026-08-10 P2-3）。原来是"先消费再在这里比对"，
            # 于是拿别人的 code 提交一次就把它提前作废了。
            console_session.consume_code(qs.get("code", ""),
                                         expected_email=email)
        except console_session.UpgradeRejected as e:
            return _json(401, {"need": "console-session", "error": str(e)})
        return {"statusCode": 302,
                "headers": {"Location": f"https://{os.environ['CONSOLE_HOST']}/",
                            "cache-control": "no-store"},
                "cookies": [console_session.console_cookie(email, name)],
                "body": ""}

    body = {}
    if method not in READ_ONLY:
        # ② CSRF —— 在任何业务调用之前
        try:
            console_session.check_csrf(method, headers)
        except console_session.CsrfRejected as e:
            return _json(403, {"error": str(e)})
        # ③ 面板会话
        try:
            console_session.verify_console_cookie(headers.get("cookie", ""),
                                                  x_user_email=email)
        except console_session.UpgradeRejected as e:
            return _json(401, {"need": "console-session", "error": str(e)})
        if event.get("body"):
            try:
                body = json.loads(event["body"])
            except Exception:
                return _json(400, {"error": "请求体不是合法 JSON"})
            if not isinstance(body, dict):
                return _json(400, {"error": "请求体必须是 JSON 对象"})

    # ④⑤ 分发与副作用
    try:
        return _json(200, _dispatch(pattern, method, email, name, site_id,
                                    qs, body))
    except permissions.PermissionDenied as e:
        return _json(403, {"error": str(e)})
    except permissions.PermissionConflict as e:
        return _json(409, {"error": str(e)})
    except ValueError as e:
        # 入口校验类（非法邮箱、owner 不能同时是协作者、allowed_users 形态
        # 不对等）——用户可以纠正，不是服务故障
        return _json(400, {"error": str(e)})
    except Exception:
        # **不回显内部错误**：ARN / 表名 / 堆栈都是内部结构。日志里留全量。
        logger.exception("panel 未预期异常 path=%s", path)
        return _json(500, {"error": "服务内部错误，请稍后重试"})


def _strict_bool(body: dict, field: str) -> bool:
    """取一个**必须是真布尔**的字段；缺失 = False。非布尔抛 ValueError（→400）。

    不用 `bool(body.get(field))`（Codex 审查 2026-08-10 P1-2）：Python 里任何
    非空字符串都为真，于是 `{"purge_data": "false"}` 会被解释成"永久删除数据"
    ——一个**不可恢复**的动作。JSON 有真正的布尔类型，客户端没理由发别的；
    API 边界不能依赖"唯一前端永远正确"，第二个客户端（脚本/curl/其他 Agent）
    随时会出现。

    注意 `isinstance(True, int)` 也成立，所以必须先查 bool 再谈数字——
    反过来写会把 1/0 放进来。

    **显式 `null` 也拒**（不等同于缺失）：字段不在 body 里说明调用方没表达
    意图，取安全默认；而显式写了 `null` 说明它表达了一个不是布尔的东西，
    通常是客户端 bug（把 undefined 变量序列化进去）。两种情形的安全方向
    相同，但报 400 能让 bug 当场暴露，而不是静默按 False 跑过去。
    """
    if field not in body:
        return False
    value = body[field]
    if not isinstance(value, bool):
        raise ValueError(f"{field} 必须是布尔值 true/false，"
                         f"收到 {type(value).__name__}")
    return value


def _dispatch(pattern, method, email, name, site_id, qs, body):
    if pattern == r"^/api/me$":
        return api.do_me(email, name)
    if pattern == r"^/api/sites$":
        return {"sites": api.do_list_sites(email, all_sites=qs.get("all") == "1")}
    if pattern.endswith(r"/jobs$"):
        return {"jobs": api.do_list_jobs(email, site_id)}
    if pattern == rf"^/api/sites/{_SITE}$":
        return api.do_get_site(email, site_id)
    if pattern.endswith(r"/permissions$"):
        return api.do_set_access(email, site_id,
                                 require_login=body.get("require_login"),
                                 allowed_users=body.get("allowed_users"))
    if pattern.endswith(r"/collaborators$"):
        return api.do_set_collaborators(email, site_id, add=body.get("add"),
                                        remove=body.get("remove"))
    if pattern.endswith(r"/owner$"):
        return api.do_transfer_owner(email, site_id,
                                     new_owner=body.get("new_owner", ""))
    if pattern.endswith(r"/undeploy$"):
        return api.do_undeploy(email, site_id,
                               purge_data=_strict_bool(body, "purge_data"))
    if pattern == r"^/api/admins$":
        if method == "GET":
            return api.do_list_admins(email)
        target = body.get("email", "")
        return (api.do_add_admin(email, target) if method == "PUT"
                else api.do_remove_admin(email, target))
    if pattern.startswith(r"^/api/admin/resync/"):
        return api.do_resync(email, site_id)
    # 路由已匹配却没有分支 = 加了 ROUTES 忘了加分发。抛出让 500 + 日志暴露它，
    # 而不是静默返回空对象（那会让前端拿到 200 和空数据，极难查）。
    raise RuntimeError(f"路由已匹配但未分发: {pattern}")
