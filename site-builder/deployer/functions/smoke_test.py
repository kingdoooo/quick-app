"""SFN 步骤 7：冒烟。禁跟随重定向——require_auth 站点的健康态是
"302 且 Location 指向登录端点"；跟随到登录页的 200 会掩盖后端故障，
而鉴权站点直接 200 意味着鉴权失效，同样必须失败。"""
import os
import urllib.error
import urllib.request

import common


class SmokeFailure(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _head(url: str) -> tuple[int, str]:
    """返回 (status, location)。不跟随重定向。"""
    req = urllib.request.Request(url, method="GET")
    try:
        with _opener.open(req, timeout=10) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def _check(url: str, require_auth: bool, login_prefix: str, what: str):
    code, location = _head(url)
    if require_auth:
        if code != 302 or not location.startswith(login_prefix):
            raise SmokeFailure(
                f"{what} 期待 302→登录端点，实际 {code} Location={location!r}"
                + ("（鉴权未生效！）" if code == 200 else ""))
    else:
        if code != 200:
            raise SmokeFailure(f"{what} 返回 {code}")


def handler(event, context):
    common.update_job(event["job_id"], phase="smoke-test")
    # 按本次实际写入路由的策略断言，不按 manifest：用户可能在线改过
    # require_login，manifest 里是生成代码时的旧值（spec §3.3.2）。
    # effective_auth 由 register_route 写入；缺失时回落 manifest，
    # 兼容升级窗口里已在运行的 execution。
    effective = event.get("effective_auth") or {}
    require_auth = bool(effective.get("require_login",
                                      event["manifest"]["auth"]["require_login"]))
    login_prefix = f"https://auth.{os.environ['BASE_DOMAIN']}/login"
    _check(event["url"] + "/", require_auth, login_prefix, "首页")
    if event["manifest"].get("backend"):
        _check(event["url"] + "/api/health", require_auth, login_prefix, "/api/health")
    return event
