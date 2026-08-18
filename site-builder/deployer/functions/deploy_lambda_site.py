"""SFN 步骤 4：per-site 执行角色 + 站点 Lambda——zip + LWA Layer（禁止镜像模式）。
站点代码不可信：角色带 PermissionsBoundary，inline policy 精确到本站点资源。"""
import json
import logging
import os
import time

import boto3

import common

logger = logging.getLogger()

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
    else:
        # 只有 VERSION_READY_ATTEMPTS <= 0 才走到这里（循环体一次没进）。那是配置
        # 错，不是运行时状况——但不写这条 else，`resp` 就可能未绑定，症状会是
        # UnboundLocalError 而不是"这个常量配错了"。
        raise RuntimeError(
            f"VERSION_READY_ATTEMPTS={VERSION_READY_ATTEMPTS} 不合法（须 ≥ 1）")
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
        exists = True
    except lam.exceptions.ResourceNotFoundException:
        exists = False

    if exists:
        # **先判颜色，后动任何字节**：未迁移的站点必须在 update_function_code
        # 之前就被拒掉。反过来（先推 $LATEST 再检查）就是 v1 的 P1-1——那会把
        # 未经健康门的代码留在 $LATEST 上，而未迁移站点的 Function URL 正挂在
        # $LATEST，等于当场上线。
        urls = _color_urls(lam, fn)
        target = common.route_api_target(event["site_id"])
        live = _live_color(target, urls)
        # **判据是"路由指着的东西认不认得"，不是"有没有颜色 URL"。**
        #
        # 原来写的是 `live is None and not urls`，那个 AND 漏掉了**半迁移**状态：
        # 迁移脚本的健康门失败时（migrate_sites_to_blue_green 的
        # `skipped:unhealthy` 分支）会留下 blue alias + blue URL 而**故意不切
        # 路由**，于是 `urls` 非空、`live` 仍是 None ⇒ 闸门放行 ⇒ 下面
        # `update_function_code` 推 $LATEST，而路由此刻正指着无 qualifier 的
        # URL（= $LATEST）⇒ 未经健康门的新代码当场上线。那正是本闸门要挡的事
        # （M7-SPEC §4.3，v1 被驳回的 P1-1 同一形态；Codex 2026-08-17 P1-3
        # 复现）。
        #
        # **不能收成 `if live is None: raise`**：那会把一个合法状态也拒死——
        # 首次部署在 deploy_lambda_site 之后、register_route 提交之前失败时，
        # 函数与 blue alias/URL 都已存在而路由**根本不存在**，此时 target 是
        # `""`、live 是 None，但线上没有任何入口指向 $LATEST（M7 建的站点从不给
        # $LATEST 挂 URL），重试是安全且必要的。收成那样这个站点将永远无法再
        # 部署，且报的是"去跑迁移脚本"——一条根本不适用的指引。
        #
        # 所以条件是"**有**路由、但它指向的不是任何一个颜色"：既盖住未迁移
        # （指向 $LATEST 的 URL）、半迁移（同上，只是多了个 blue URL），也盖住
        # 认不出的第三方 target；而"没有路由"落在首次部署那一支。
        if live is None and target:
            raise UnmigratedSite(
                f"{fn} 的路由指向 {target}，它不是 blue/green 任何一色的 Function "
                "URL（未迁移，或上次迁移只做了一半：alias/URL 已建但路由还在 "
                "$LATEST）。先跑 scripts/migrate_sites_to_blue_green.py 把路由切到"
                "某个颜色，再重试部署。")
        color = _idle_color(live)
        lam.update_function_code(FunctionName=fn, **code)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
        lam.update_function_configuration(
            FunctionName=fn, Runtime=runtime, Handler="run.sh", Role=role_arn,
            Layers=[LWA_LAYER], Environment={"Variables": env},
            MemorySize=512, Timeout=30)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
    else:
        color = COLORS[0]
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

    # 不可变版本 → 指给**空闲色** → 健康门。线上那一色全程没被碰过。
    # **顺序是 alias 先动、健康门后跑**：颜色的 Function URL 挂在 alias 这个
    # qualifier 上，所以只有 invoke 那个 alias 才是在验"真正会服务流量的东西"。
    # 先健康门再移 alias 的话，验的是版本号那个 qualifier，而移 alias 本身就成了
    # 没被验证的动作。空闲色不在路由上 ⇒ 先移它对线上零影响。
    version = lam.publish_version(FunctionName=fn)["Version"]
    try:
        lam.update_alias(FunctionName=fn, Name=color, FunctionVersion=version)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_alias(FunctionName=fn, Name=color, FunctionVersion=version)
    _health_check(lam, fn, color)      # 不过则抛：路由从未切换

    # 挂 URL 与授权都在健康门**之后**：这两步是让这一色可被外部调用，候选没通过
    # 健康门就不该具备被调用的条件。
    try:
        url = lam.create_function_url_config(FunctionName=fn, Qualifier=color,
                                             AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        cfg = lam.get_function_url_config(FunctionName=fn, Qualifier=color)
        url = cfg["FunctionUrl"]
        # **AuthType 必须读回核对，不能"存在即当对"**（Codex 2026-08-18 P1-5A）：
        # 已有 URL 被漂移成 NONE 时，create 报 Conflict、get 照样给出 URL，
        # 下面的语句替换又只管我们自己那两条 sid——于是一个**公开可达**的候选色
        # 会被原样提交，新后端绕过 Edge 的全部鉴权直接暴露公网。健康门是
        # `lambda:invoke` 直调，发现不了；smoke 打的是 Edge 域名，也发现不了。
        # 改回来而不是抛错：AWS_IAM 就是本平台的唯一合法值，自愈是安全方向。
        if cfg.get("AuthType") != "AWS_IAM":
            logger.warning(f"{fn}:{color} 的 Function URL AuthType 是 "
                           f"{cfg.get('AuthType')!r}（漂移），改回 AWS_IAM")
            lam.update_function_url_config(FunctionName=fn, Qualifier=color,
                                           AuthType="AWS_IAM")

    # **清掉这一色 resource policy 里所有非预期语句**（同一条 P1-5A 的另一半）：
    # 我们只维护两条 sid，但漂移/篡改可以用**别的** sid 塞进 Principal:* 之类的
    # 额外授权，只替换自己那两条清不掉它们。候选色此刻不在路由上（挂 URL 与授权
    # 都在健康门之后、提交点之前），删语句对线上零影响；删失败让它抛——
    # 这是提交点之前，fail-closed 是安全方向。
    _EXPECTED_SIDS = ("edge-invoke", "edge-invoke-function")
    try:
        policy = json.loads(lam.get_policy(FunctionName=fn,
                                           Qualifier=color)["Policy"])
        # 只收**有 Sid** 的语句：Lambda 的 add_permission 必然写 Sid，所以
        # Sid 缺失今天不可达；但真出现时 remove_permission(StatementId=None)
        # 是一个难读的 ParamValidationError，而不是这段 fail-closed 的本意。
        stray = [s["Sid"] for s in policy.get("Statement", [])
                 if s.get("Sid") and s["Sid"] not in _EXPECTED_SIDS]
    except lam.exceptions.ResourceNotFoundException:
        stray = []          # 还没有任何 policy（URL 是刚建的）
    for sid in stray:
        logger.warning(f"{fn}:{color} 的 resource policy 有非预期语句 {sid!r}"
                       "（漂移/篡改），删除")
        lam.remove_permission(FunctionName=fn, Qualifier=color, StatementId=sid)
    # 2025-10 起新建 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两个权限
    # （AWS 官方文档 urls-auth）；只给前者会让 Edge 调用返回 403。
    # InvokedViaFunctionUrl 把 InvokeFunction 限定为仅经 Function URL 调用。
    # **权限也要带 Qualifier**：不带就授在函数上，与"URL 只挂在颜色上"不一致。
    # **冲突时替换，不是忽略**（Codex 2026-08-17 P1-5）：同名 StatementId 已存在只
    # 说明"有一条语句叫这个名字"，不说明**它的内容是对的**。一条内容错误的同名语句
    # （principal 不对、少了 Qualifier、少了 InvokedViaFunctionUrl）会让 Edge 调用
    # 403，而这条路径上没有任何东西能发现它：健康门是 `lambda:invoke` 直调，压根
    # 不经过 Function URL 的授权；提交点之后的 smoke 又可能命中 Edge 的旧路由缓存
    # 而对**旧**目标返回 200。于是缓存过期之后整站才开始 403。
    # remove→add 期间这一色还没有任何路由指向它（挂 URL 与授权都在健康门之后、
    # 提交点之前），所以那个瞬间对线上零影响。
    for sid, action, extra in (
            ("edge-invoke", "lambda:InvokeFunctionUrl",
             {"FunctionUrlAuthType": "AWS_IAM"}),
            ("edge-invoke-function", "lambda:InvokeFunction",
             {"InvokedViaFunctionUrl": True})):
        for attempt in range(2):
            try:
                lam.add_permission(FunctionName=fn, Qualifier=color,
                                   StatementId=sid, Action=action,
                                   Principal=edge_role_arn, **extra)
                break
            except lam.exceptions.ResourceConflictException:
                # **最后一轮还冲突就抛出去**，不要让循环自然结束：自然结束等于把
                # "授权可能是错的"静默咽下，而那正是本改动要消除的形态。
                if attempt == 1:
                    raise
                # 删掉那条同名语句再重加一次。
                lam.remove_permission(FunctionName=fn, Qualifier=color,
                                      StatementId=sid)

    # **只是候选**：真正上线由 register_route 那一次 put_item 完成（唯一提交点）。
    # 本步骤到此为止没有写过路由表——失败对线上零影响就是靠这条。
    event["api_target"] = url.rstrip("/")
    event["deploy_color"] = color
    event["deploy_version"] = version
    return event
