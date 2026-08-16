"""SFN 步骤 4：per-site 执行角色 + 站点 Lambda——zip + LWA Layer（禁止镜像模式）。
站点代码不可信：角色带 PermissionsBoundary，inline policy 精确到本站点资源。"""
import json
import os
import time

import boto3

import common

LWA_LAYER = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"

# ── blue/green（M7）────────────────────────────────────────────────────
# 两个固定 alias，各带一个固定 Function URL。部署总是打到**空闲色**，健康门过了
# 也仍不上线——上线只发生在 register_route 那一次 put_item（唯一提交点）。
COLORS = ("blue", "green")
HEALTH_PATH = "/api/health"
# 新发布的版本/alias 有一段就绪窗口，这两个常量只管**那一段**的重试。
VERSION_READY_ATTEMPTS = 6
VERSION_READY_SLEEP = 5


class BackendUnhealthy(Exception):
    """候选版本没能服务 /api/health。**路由从未切换**，线上仍在旧色。"""


class UnmigratedSite(Exception):
    """这个站点还没进 blue/green 模型。**不做隐式半迁移**——先跑
    scripts/migrate_sites_to_blue_green.py。理由见 M7-SPEC §4.3：
    半套迁移会让首次更新仍然把未经健康门的代码暴露在 $LATEST 上。"""


def _lambda():
    return boto3.client("lambda")


def _color_urls(lam, fn: str) -> dict:
    """两个颜色各自**已存在**的 Function URL（不存在的键就不出现）。

    键的有无就是"这个站点迁到哪一步了"：两个都没有 = 还没迁移。所以这里不给缺失的
    颜色填占位值——填了会让上层的未迁移判定走错分支。
    """
    out = {}
    for c in COLORS:
        try:
            out[c] = lam.get_function_url_config(
                FunctionName=fn, Qualifier=c)["FunctionUrl"].rstrip("/")
        except lam.exceptions.ResourceNotFoundException:
            pass
    return out


def _live_color(route_api_target: str, urls: dict) -> str | None:
    """当前对外服务的是哪个颜色。**从路由表的 api_target 推导**，不另存一份
    live_color——两份状态必然漂移，而漂移的后果是往正在服务的颜色上部署。

    认不出来（旧的函数级 URL、或路由里还没有 api_target）就返回 None = 未迁移。
    """
    target = (route_api_target or "").rstrip("/")
    for c, u in urls.items():
        if u.rstrip("/") == target:
            return c
    return None


def _idle_color(live: str | None) -> str:
    """要部署到的那个颜色。live 为 None（首次）时用 COLORS[0]。"""
    return COLORS[0] if live is None else COLORS[1 if live == COLORS[0] else 0]


def _health_event() -> dict:
    """合成 Function URL payload v2.0 事件。形态已用一次性探针对线上真实站点验证
    （2026-08-15：手搓 v2.0 事件直调，真实 LWA 返回完整 Express 200 响应）。
    带一个保留邮箱：站点代码可能无条件读 x-user-email。"""
    return {
        "version": "2.0", "rawPath": HEALTH_PATH, "rawQueryString": "",
        "headers": {"x-user-email": f"deploy-healthcheck@{os.environ['BASE_DOMAIN']}",
                    "user-agent": "site-builder-deploy-healthcheck"},
        "requestContext": {
            "http": {"method": "GET", "path": HEALTH_PATH, "protocol": "HTTP/1.1",
                     "sourceIp": "127.0.0.1",
                     "userAgent": "site-builder-deploy-healthcheck"},
            "requestId": "deploy-healthcheck", "routeKey": "$default",
            "stage": "$default", "timeEpoch": 0},
        "isBase64Encoded": False}


def _health_check(lam, fn: str, qualifier: str) -> None:
    """确认候选（空闲色 / 某个版本）真的能服务 /api/health。

    调 Qualifier 会拉起**新执行环境** ⇒ 真冷启测试。过去 smoke 对 require_auth
    站点只断言 Edge 的 302，请求根本到不了站点 Lambda，于是"新后端启动即崩"能
    一路绿到 SUCCEEDED（Codex 2026-08-15 P1-2）。

    **fail-closed 的四种形态**：FunctionError、非 JSON、JSON 但不是 HTTP 响应
    形态（缺 statusCode，例如站点直接返回 `"pong"`）、statusCode 非 200。中间那
    两种最容易被写成"取不到就当通过"，而那正好等于健康门不存在。
    """
    payload = json.dumps(_health_event()).encode()
    for attempt in range(VERSION_READY_ATTEMPTS):
        try:
            resp = lam.invoke(FunctionName=fn, Qualifier=qualifier, Payload=payload)
            break
        except lam.exceptions.ResourceConflictException:
            # 只有"版本/alias 尚未就绪"重试。**业务失败绝不重试**——重试会把
            # "这个后端起不来"掩盖成"偶发抖动"，然后照样上线。
            if attempt == VERSION_READY_ATTEMPTS - 1:
                raise
            time.sleep(VERSION_READY_SLEEP)
    if resp.get("FunctionError"):
        detail = resp["Payload"].read()[:400].decode(errors="replace")
        raise BackendUnhealthy(
            f"{fn}:{qualifier} FunctionError={resp['FunctionError']} {detail}")
    raw = resp["Payload"].read()
    try:
        body = json.loads(raw)
    except ValueError:
        raise BackendUnhealthy(f"{fn}:{qualifier} 返回非 JSON：{raw[:200]!r}")
    if not isinstance(body, dict) or "statusCode" not in body:
        raise BackendUnhealthy(
            f"{fn}:{qualifier} 返回的不是 HTTP 响应形态：{str(body)[:200]}")
    if int(body["statusCode"]) != 200:
        raise BackendUnhealthy(
            f"{fn}:{qualifier} 的 {HEALTH_PATH} 返回 {body['statusCode']}")


# 角色创建/授权逻辑集中在 common：provision_dsql 也要用它（AWS IAM GRANT 要求
# IAM 角色先存在），两处各写一份必然漂移。
_ensure_site_role = common.ensure_site_role


def _ensure_log_group(fn: str) -> None:
    """预建站点日志组并设保留期。Lambda 首次执行会自动建组但不设 retention
    （永久保留）；这里先建好，站点日志 90 天自动过期（2026-08-15 用户决定的
    全平台统一值，取代原 30 天）。undeploy 时整组删除。

    这里是**新建站点保留期的唯一真源**：手工改存量日志组不影响新站点，
    下次部署仍按这个值写回。"""
    logs = boto3.client("logs")
    name = f"/aws/lambda/{fn}"
    try:
        logs.create_log_group(logGroupName=name)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName=name, retentionInDays=90)


def handler(event, context):
    common.update_job(event["job_id"], phase="deploy-backend")
    edge_role_arn = os.environ["EDGE_ROLE_ARN"]  # 缺失即 KeyError——不允许 * fallback
    lam = _lambda()
    fn = f"site-{event['site_id']}"
    _ensure_log_group(fn)
    engine = event["manifest"].get("database", {}).get("engine", "none")
    role_arn = _ensure_site_role(event["site_id"], engine)
    env = {"AWS_LAMBDA_EXEC_WRAPPER": "/opt/bootstrap", "PORT": "8080",
           "AWS_LWA_INVOKE_MODE": "BUFFERED", **event.get("env_vars", {})}
    code = {"S3Bucket": os.environ["ARTIFACTS_BUCKET"], "S3Key": event["backend_zip_key"]}
    runtime = event["manifest"]["backend"]["runtime"]

    try:
        lam.get_function(FunctionName=fn)
        lam.update_function_code(FunctionName=fn, **code)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
        lam.update_function_configuration(
            FunctionName=fn, Runtime=runtime, Handler="run.sh", Role=role_arn,
            Layers=[LWA_LAYER], Environment={"Variables": env},
            MemorySize=512, Timeout=30)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):  # 新建 IAM 角色传播延迟
            try:
                lam.create_function(
                    FunctionName=fn, Runtime=runtime, Handler="run.sh",
                    Role=role_arn, Code=code,
                    Layers=[LWA_LAYER], Environment={"Variables": env},
                    MemorySize=512, Timeout=30,
                    Tags={"project": "site-builder", "site_id": event["site_id"]})
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 5:
                    raise
                time.sleep(5)
        lam.get_waiter("function_active").wait(FunctionName=fn)

    try:
        url = lam.create_function_url_config(FunctionName=fn,
                                             AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
    # 2025-10 起新建 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两个权限
    # （AWS 官方文档 urls-auth）；只给前者会让 Edge 调用返回 403。
    # InvokedViaFunctionUrl 把 InvokeFunction 限定为仅经 Function URL 调用。
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke",
                           Action="lambda:InvokeFunctionUrl",
                           Principal=edge_role_arn,
                           FunctionUrlAuthType="AWS_IAM")
    except lam.exceptions.ResourceConflictException:
        pass
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke-function",
                           Action="lambda:InvokeFunction",
                           Principal=edge_role_arn,
                           InvokedViaFunctionUrl=True)
    except lam.exceptions.ResourceConflictException:
        pass

    event["api_target"] = url.rstrip("/")
    return event
