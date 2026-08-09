"""panel Lambda 入口：五步前置校验 + 路由分发 + 错误码。

**顺序是安全边界，不是风格**（spec §5.4）：
  ① 身份：x-user-email 必须存在。它由 Edge **先剥除再注入**，所以它存在就
     等于"请求确实经过 CloudFront + Lambda@Edge"。Function URL 的 AWS_IAM +
     exact edge role resource policy 是这个推论的前提（见 deploy_panel.py）
     ——两者缺一，本文件的整套身份假设就失效。
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
            code_email = console_session.consume_code(qs.get("code", ""))
            if code_email != email:
                # 拿别人的 code 换自己的 cookie
                raise console_session.UpgradeRejected("升级码与当前身份不符")
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
                               purge_data=bool(body.get("purge_data")))
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
