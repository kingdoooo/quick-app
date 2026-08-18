"""SFN 步骤 7：冒烟。禁跟随重定向——require_auth 站点的健康态是
"302 且 Location 指向登录端点"；跟随到登录页的 200 会掩盖后端故障，
而鉴权站点直接 200 意味着鉴权失效，同样必须失败。

**本步骤证明不了"公网已经在服务新版本"，别把它当那个用**（Codex 2026-08-17 P1-5）。
它排在提交点之后、而 Edge 每个实例把整条路由缓存 60s
（`origin_request.ROUTE_CACHE_TTL`），所以这次请求**可能命中一个还拿着旧路由的
Edge 实例**，于是对**旧**目标返回 200/302 而通过。实测探针确认过：缓存命中时
这条路径一次 DynamoDB 都不读。

为什么没有为此在提交后等 65s 再冒烟：
  · 那给**每一次**部署都加 65s，而它要防的是一个 ≤60s 就自愈的状态——路由的真源
    （DynamoDB）已经提交，Edge 只是还没读到；
  · 且那 60s 里旧实例服务的是**上一版能用的站点**，不是错误页：旧色的
    alias/URL/版本由 `mark_job._cleanup_versions` 按 alias 引用保留，上一版前端
    前缀由 `_cleanup_old_versions` 显式保留一轮。所以"还没收敛"≠"坏了"。
  · 真正**不会自愈**的两件事已经在提交点**之前**各自 fail-closed 了，不依赖冒烟：
    候选色的 Function URL 授权（`deploy_lambda_site` 改成冲突即替换，
    不再"同名就当对"）与新前缀下有没有可服务对象（`upload_frontend` 空产物即拒）。

也就是说：本步骤的定位是"Edge 这条链路对**某一版**是通的、且鉴权语义正确"，
不是"新版本已上线"。真机上"新版本已上线"由 E2E 在等待缓存收敛之后断言。
"""
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
