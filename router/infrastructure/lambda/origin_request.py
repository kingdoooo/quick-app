"""
Lambda@Edge Origin Request处理器

根据DynamoDB中存储的subdomain路由表，将CloudFront请求分流到后端
Lambda Function URL（SigV4）或共享前端S3桶（SigV4 GET）。
支持 route_mode：split（/api/ 走后端，其余走S3静态）与 api-only（全路径走后端）。
"""
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib.parse


# 配置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 配置常量（Lambda@Edge不支持环境变量，由CDK部署时注入）
DYNAMODB_TABLE_NAME = "{{DYNAMODB_TABLE_NAME}}"
DYNAMODB_REGION = "{{DYNAMODB_REGION}}"
FRONTEND_BUCKET_DOMAIN = "{{FRONTEND_BUCKET_DOMAIN}}"
JWT_SECRET = "{{JWT_SECRET}}"  # Task 7 使用
_ROUTE_CACHE: dict = {}  # subdomain -> (expires_epoch, item)
ROUTE_CACHE_TTL = 60
DEFAULT_PROTOCOL = "https"
DEFAULT_PORT = 443
DEFAULT_SSL_PROTOCOLS = ["TLSv1.2"]
DEFAULT_READ_TIMEOUT = 30
DEFAULT_KEEPALIVE_TIMEOUT = 5

# 初始化DynamoDB客户端
dynamodb = boto3.client("dynamodb", region_name=DYNAMODB_REGION)

# ── 访问埋点（M5）──────────────────────────────────────────────────
# 只记**页面级**请求，且只记 app- 前缀的用户站点。写本区副本（Global Table）。
ACCESS_TABLE = "{{ACCESS_TABLE}}"
ACCESS_REPLICA_REGIONS = tuple(
    x.strip() for x in "{{ACCESS_REPLICA_REGIONS}}".split(",") if x.strip())
ACCESS_TTL_DAYS = 90
_ACCESS_CLIENTS: dict = {}

# 超时预算经过两次修正，**别收紧**（spec §2.3 规矩 4）：
#   · 初版 0.3/0.5 被实测否掉——跨区冷连接首次 PutItem 要 719ms，于是每个冷
#     容器的首次埋点必然超时并被下面的 except 吞掉 = 静默丢行；
#   · 正常路径是同区副本（实测冷 58ms / 暖 6ms），离这个预算差两个数量级；
#   · 预算的**下限由回落路径**（跨区 719ms）决定，不是由同区 58ms 决定。
#     收紧到"够本区用"就等于让回落路径静默丢行。
# 不给重试：埋点重试的价值低于它带来的延迟方差。
_ACCESS_CFG = Config(connect_timeout=1.0, read_timeout=2.0,
                     retries={"max_attempts": 0})


def _access_region(context) -> str:
    """写哪个副本。

    **解析不出、或解析出一个没有副本的区，都回落主区**——回落 = 跨区写 =
    正确但慢，**永不丢数据**。这条是"加副本"这个优化不会变成故障的唯一保证。
    `AWS_REGION` 在 Lambda@Edge 里是否可用由部署时的日志实测确定（spec §0.4
    第 1 步）；拿不到就退到 ARN 解析，两者都拿不到就回落。
    """
    region = os.environ.get("AWS_REGION") or ""
    if region not in ACCESS_REPLICA_REGIONS:
        arn = getattr(context, "invoked_function_arn", "") or ""
        parts = arn.split(":")
        region = parts[3] if len(parts) > 3 else ""
    if region not in ACCESS_REPLICA_REGIONS:
        region = DYNAMODB_REGION
    # spec §0.4 第 1 步的线上探测。**读完保留**：Lambda@Edge 拿不到自定义环境
    # 变量，所以"副本路径在用、还是一直在跨区回落"这件事，线上只有这一行能证明
    # （回落是正确但慢的，不报错——没有它就永远分不清两者）。三个值都不敏感。
    print(f"[INFO] m5-region env={os.environ.get('AWS_REGION')!r} "
          f"arn={getattr(context, 'invoked_function_arn', '')!r} -> {region}")
    return region


def _access_client(region: str):
    """按区缓存的 client。**不复用模块级 `dynamodb`**——那个钉在主区，
    而这里要写本区副本，两者不是同一个连接池（spec §2.3 规矩 4 第二版被推翻的
    正是"复用就能蹭到暖连接"这个推论）。"""
    if region not in _ACCESS_CLIENTS:
        _ACCESS_CLIENTS[region] = boto3.client("dynamodb", region_name=region,
                                               config=_ACCESS_CFG)
    return _ACCESS_CLIENTS[region]


def _route_kind(route: dict, uri: str, method: str) -> str:
    """这个请求会被怎么处理：`"lambda" | "page" | "asset" | "reject"`。

    **唯一定义**——`_route_request` 与埋点判定都调它，谁也不许再写第二份。
    这条设计是被两次同类缺陷逼出来的（Codex 审查 2026-08-14 两轮，都实测）：
      · 第一版只抄了"有没有扩展名"，漏掉 `/api/` 前置分支 → split 站点的
        `/api/data` 被记成页面，一次 SPA 打开 + 5 个接口 = **PV 放大 6 倍**；
      · 第二版补了 `/api/`，仍漏掉**方法检查** → `POST /notes` 真实是 404
        （分发是 ALLOW_ALL，非 GET/HEAD 的静态请求被 `_not_found` 拒），
        却被记成一条 `allow` PV。实测 4 条不一致（POST/PUT/OPTIONS/DELETE
        × 无扩展名路径）。
    两次都是"镜像一份判定"这个做法本身的问题——所以改成**一处判定、两处引用**。
    往这里加分支时，`_route_request` 自动跟着变，不存在漂移。
    """
    if route.get("route_mode") == "api-only":
        return "lambda"
    if uri.startswith("/api/"):
        return "lambda"
    if method not in ("GET", "HEAD"):
        return "reject"        # 静态桶只接受读方法，其余 404
    return "asset" if "." in uri.rsplit("/", 1)[-1] else "page"


def _is_page_request(route: dict, uri: str, method: str) -> bool:
    """要不要记这一条。**从 `_route_kind` 派生，不自己判。**

    api-only 站点没有"页面 vs 资源"之分，全记；其余只记会被改写成
    `/index.html` 的那些。`reject`（方法不允许 → 404）与 `asset` 都不记。
    """
    kind = _route_kind(route, uri, method)
    if route.get("route_mode") == "api-only":
        return kind == "lambda"
    return kind == "page"


def _record_access(context, site_id: str, uri: str, decision: str,
                   email: str) -> None:
    """写一行访问明细。**任何异常都吞掉**——统计不是安全控制，这里 fail-open
    是对的（与本文件其它 fail-closed 判定的区别是有意的，别"统一"掉）。
    兜底覆盖 client 取用本身，不只包住 put_item。
    """
    try:
        now = datetime.now(timezone.utc)
        _access_client(_access_region(context)).put_item(
            TableName=ACCESS_TABLE,
            Item={"site_date": {"S": f"{site_id}#{now.strftime('%Y-%m-%d')}"},
                  # ts 在最前面：读取方式是按分区 Query 再按 SK 排时间线。
                  # 随机后缀不可省——同一微秒两条请求会撞同一主键，第二条
                  # 静默覆盖第一条（ops_log.record 的 docstring 记过实测）。
                  "ts_id": {"S": f"{now.isoformat()}#{secrets.token_hex(3)}"},
                  "site_id": {"S": site_id},
                  # 空串合法（DynamoDB 只禁**键**属性为空）：302 未登录时确实
                  # 没有身份可言，写 "-" 之类的哨兵会污染 distinct email 的计数。
                  "email": {"S": email},
                  "path": {"S": uri[:512]},
                  "decision": {"S": decision},
                  "expires_at": {"N": str(int(now.timestamp())
                                          + ACCESS_TTL_DAYS * 86400)}})
    except Exception as e:      # noqa: BLE001
        print(f"[WARN] 访问埋点失败 site={site_id} decision={decision}: "
              f"{type(e).__name__}: {e}")


def _maybe_record(context, subdomain: str, uri: str, method: str, route: dict,
                  denied, sink: dict) -> None:
    """记不记、记什么。

    **判定用分区键前缀**（`app-`），不用 `owner`/`_is_platform_route()`：
      · `owner` 是权限投影字段，能写权限的角色可控（见 PLATFORM_SUBDOMAINS 上方
        那段长注释否掉的同一种推导）；
      · `mcp` 子域**故意**不在 PLATFORM_SUBDOMAINS 里，用它会把 key-proxy 的
        每次调用记成一个"站点"，还给每次调用加一次跨区写。
    `subdomain` 是路由表分区键、由真实 Host 解析，不可伪造。
    """
    try:
        if not subdomain.startswith("app-"):
            return
        if not _is_page_request(route, uri, method):
            return
        if denied is None:
            decision = "allow"
        elif str(denied.get("status")) == "403":
            decision = "denied_403"
        else:
            decision = "redirect_login"
        _record_access(context, subdomain[4:], uri, decision,
                       sink.get("email", ""))
    except Exception as e:      # noqa: BLE001
        print(f"[WARN] 埋点判定失败 sub={subdomain}: {type(e).__name__}: {e}")


# 初始化 boto3 session 用于签名
session = boto3.Session()
credentials = session.get_credentials()


def _server_error() -> dict:
    return {"status": "500", "statusDescription": "Internal Server Error",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/plain"}]},
            "body": "服务暂时不可用"}


def lambda_handler(event, context):
    try:
        request = event["Records"][0]["cf"]["request"]
        original_host = _get_original_host(request)
        if not original_host:
            return _server_error()
        subdomain = _extract_subdomain(original_host)
        route = _lookup_route(subdomain)
        if not route:
            return _not_found(f'Subdomain "{subdomain}" not configured.')
        # 平台身份取自**请求 host 解析出的 subdomain**，不是路由 item 里的字段。
        # 这一步之后 _route_request 只看这个键，见 _is_platform_route。
        route = {**route, _PLATFORM_KEY: subdomain in PLATFORM_SUBDOMAINS}
        # **在 _route_request 之前抓 uri**：那个函数会把静态请求的 uri 改写成
        # 桶内 key（f"/{static_prefix}{path}"），埋点要记的是用户看到的路径。
        original_uri = request.get("uri", "/")
        original_method = request.get("method", "GET")
        sink: dict = {}
        denied = _check_auth(request, route, original_host, sink)
        result = denied if denied else _route_request(request, route)
        _maybe_record(context, subdomain, original_uri, original_method,
                      route, denied, sink)
        return result
    except Exception as e:
        logger.error(f"处理请求时出错: {e}", exc_info=True)
        return _server_error()


def _redact_querystring(querystring: str) -> str:
    """query string 的**可日志形态**：只留参数名与值长度，绝不留值本身。

    为什么必需（Codex 审查 2026-08-10 P2-3）：query 里会出现认证材料——
    Cognito 的 OAuth authorization code（`/callback?code=...`）与面板升级码
    （`/api/session-callback?code=...`）。**真机证据**：本函数加进来之前，
    ap-northeast-1 的 Edge 日志里已经存着一条明文 OAuth code
    （2026-08-03T09:57:48Z，`code=ab27...&state=eyJ...`）。CloudWatch 日志是
    长期留存且多区域分布的，认证材料进去就等于凭证落盘。

    只打名字不打值：排查路由问题需要知道"带了哪些参数"，从不需要值本身。
    """
    if not querystring:
        return ""
    try:
        out = []
        for pair in querystring.split("&"):
            if not pair:
                continue
            name, sep, value = pair.partition("=")
            out.append(f"{name}=<{len(value)}b>" if sep else name)
        return "&".join(out)
    except Exception:
        # 脱敏自身绝不能把原值当兜底返回——那正是要避免的事
        return "<unparseable>"


def _fix_querystring_encoding(querystring: str) -> str:
    """
    修复查询字符串中的编码问题，特别是Base64字符串中的等号

    参数:
        querystring: 原始查询字符串

    返回:
        修复后的查询字符串
    """
    if not querystring:
        return querystring

    try:
        # 解析查询参数
        params = urllib.parse.parse_qs(querystring, keep_blank_values=True)

        # 重新构建查询字符串，确保正确编码
        fixed_params = []
        for key, values in params.items():
            for value in values:
                # 对参数值进行URL编码，特别处理Base64字符串
                encoded_value = urllib.parse.quote(value, safe='')
                fixed_params.append(f"{key}={encoded_value}")

        result = "&".join(fixed_params)
        # **脱敏后再打**：query 里可能是 OAuth code / 面板升级码（见
        # _redact_querystring 的 docstring，含真机泄漏证据）
        logger.info(f"Fixed querystring: {_redact_querystring(querystring)} "
                    f"-> {_redact_querystring(result)}")
        return result

    except Exception as e:
        logger.warning(f"Failed to fix querystring encoding: {e}")
        return querystring


def _get_original_host(request: Dict[str, Any]) -> Optional[str]:
    """
    从 Host 或 X-Original-Host header 中提取原始 host

    参数:
        request: CloudFront请求对象

    返回:
        原始host值，如果不存在则返回None
    """
    headers = request.get("headers", {})

    # 优先使用 Host header
    if "host" in headers:
        host = headers["host"][0]["value"]
        logger.info(f"Found Host header: {host}")
        return host

    # 回退到 X-Original-Host
    if "x-original-host" in headers:
        host = headers["x-original-host"][0]["value"]
        logger.info(f"Found X-Original-Host header: {host}")
        return host

    logger.warning("No Host or X-Original-Host header found")
    return None


def _extract_subdomain(host: str) -> str:
    """
    从hostname中提取subdomain

    参数:
        host: 完整的hostname（例如："api.example.com"）

    返回:
        subdomain（例如："api"）
    """
    return host.split(".")[0]


class _Unknown:
    """未识别 AttributeValue 类型的哨兵。

    **不要用 None/False/"" 之类的常规假值**：鉴权判定里"假值"往往正好是
    "放宽"的意思（require_auth 为 False = 公开），用假值兜底会让坏数据被当成
    合法的宽松配置。这个对象不是 bool、不等于任何字面量，下游的类型检查一定
    会认出它。repr 里带提示，方便在日志里定位坏数据。
    """
    def __repr__(self):
        return "<未识别的 DynamoDB 类型>"

    def __bool__(self):
        # 真值取 True：万一有分支漏了类型检查而直接 if 判断，也倒向"更严"
        # （require_auth 为真 = 要求登录），而不是倒向公开。
        return True


_UNKNOWN = _Unknown()


def _deser(item: dict) -> dict:
    """DynamoDB AttributeValue -> plain dict（本表用到的类型：S / BOOL / L / N）。

    未识别类型落到 **`_UNKNOWN` 而不是 False**。原来兜底成 False 是个陷阱：
    `require_auth` 的公开判定恰好是"值为 False"，于是 `{"NULL":true}` 或任何
    新类型都会被当成"站主显式声明了公开"，鉴权整段关闭（实测 2026-08-06）。
    换成一个既不等于 False、也不是布尔的哨兵值，让下游的
    `isinstance(x, bool)` 检查能把它认成坏数据并 fail-closed。
    加字段前仍要在此登记类型——哨兵只保证失败方向安全，不代表可以不登记。
    """
    out = {}
    for k, v in item.items():
        if "S" in v:
            out[k] = v["S"]
        elif "BOOL" in v:
            out[k] = v["BOOL"]
        elif "L" in v:
            out[k] = [e.get("S", "") for e in v["L"]]
        elif "N" in v:
            out[k] = int(v["N"])
        else:
            out[k] = _UNKNOWN
    return out


def _lookup_route(subdomain: str):
    import time as _t
    hit = _ROUTE_CACHE.get(subdomain)
    if hit and hit[0] > _t.time():
        return hit[1]
    try:
        resp = dynamodb.get_item(TableName=DYNAMODB_TABLE_NAME,
                                 Key={"subdomain": {"S": subdomain}},
                                 ConsistentRead=False)
        item = _deser(resp["Item"]) if "Item" in resp else None
    except ClientError as e:
        logger.error(f"DynamoDB错误: {e}")
        return None
    _ROUTE_CACHE[subdomain] = (_t.time() + ROUTE_CACHE_TTL, item)
    return item


def _not_found(msg: str) -> dict:
    return {"status": "404", "statusDescription": "Not Found",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/html"}]},
            "body": f"<html><body><h1>404 Not Found</h1><p>{msg}</p></body></html>"}


def _get_request_body(request):
    """include_body=True 时 CloudFront 提供 base64 body；截断返回哨兵。"""
    body = request.get("body") or {}
    if body.get("inputTruncated"):
        return None  # 调用方返回 413
    data = body.get("data", "")
    if not data:
        return b""
    if body.get("encoding") == "base64":
        import base64
        return base64.b64decode(data)
    return data.encode()


def _payload_too_large() -> dict:
    return {"status": "413", "statusDescription": "Payload Too Large",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/plain"}]},
            "body": "请求体超过 1MB 上限"}


def _route_to_lambda(request, route, uri, qs):
    target = route.get("api_target") or ""
    if not target:
        return _not_found("此站点无后端")
    body = _get_request_body(request)
    if body is None:
        return _payload_too_large()
    domain = urllib.parse.urlparse(target).netloc
    if ".lambda-url." in domain and ".on.aws" in domain:
        _add_sigv4_auth(request, domain, uri, qs, body)
    request["origin"] = _custom_origin(domain)
    request["headers"]["host"] = [{"key": "Host", "value": domain}]
    return request


BASE_DOMAIN = "{{BASE_DOMAIN}}"

# spec §3.5：org 语义的执行点。移除 COGNITO 不阻止 SDK 认证本地用户，
# 只有这里能把"身份必须来自企业 IdP"落到请求路径上。
# 迁移宽限期用开关控制（存量会话没有 idp claim）——切 pool 且全员重新登录后
# 置 true，这是 M1 的完成条件。
REQUIRE_IDP_CLAIM = "{{REQUIRE_IDP_CLAIM}}".strip().lower() == "true"
TRUSTED_IDPS = tuple(x.strip() for x in "{{TRUSTED_IDPS}}".split(",") if x.strip())
# 只放行托管登录页与它换出的 refresh token。原生 InitiateAuth 完成后触发的
# TokenGeneration_Authentication 一律拒——linked 本地用户与设过密码的联邦
# 用户走的就是它，而它们的 idp claim 看起来完全合法（spec §3.5）。
TRUSTED_AUTH_SOURCES = ("TokenGeneration_HostedAuth",
                        "TokenGeneration_RefreshTokens")


def _b64url_decode(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_session_jwt(token: str) -> dict | None:
    """与 site-builder/auth/session.py 同算法（HS256），改动须两处同步。"""
    import base64, hashlib, hmac as _hmac, time as _t
    try:
        h, p, sig = token.split(".")
        expected = base64.urlsafe_b64encode(
            _hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(p))
        if int(claims.get("exp", 0)) <= int(_t.time()):
            return None
        email = claims.get("email")
        if not isinstance(email, str) or not email:
            return None  # 缺 email 的 token 视为无效，_check_auth 依赖 claims["email"]
        return claims
    except Exception:
        return None


def _get_cookie(request, name: str) -> str | None:
    for header in request.get("headers", {}).get("cookie", []):
        for part in header["value"].split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
    return None


# 平台保留 cookie：只有 auth-service 能签发，绝不能到达站点代码。
# 站点 origin 若能读到会话 JWT，即可重放到其他站点（顶域 cookie 共享登录）——
# 站点代码是不可信代码，因此转发前必须剥除；auth-service（owner=platform）例外。
# 平台 cookie 不转发给站点（站点代码按不可信对待）；平台路由放行。
# **与 origin_response.py 的同名常量必须逐字一致**——两份漂移会出现
# "请求里剥了、响应里没剥"这类只在真机复现的怪问题，由用例断言两者相等。
# __Host-sb_pkce 是 M1 就实现但漏登记的（M3 一并补上）。
RESERVED_COOKIES = ("sb_session", "__Host-sb_console", "__Host-sb_pkce")
# origin_response 靠此头判断"本响应来自平台自己的 origin，允许写平台 cookie"。
# 客户端可伪造，故与 x-user-* 一样先无条件剥除再按路由注入。
PLATFORM_MARK = "x-sb-platform-origin"


# 平台自有子域名白名单。**平台身份必须由这里判定，不能从路由 item 的字段推导。**
#
# 为什么不用 owner == "platform"（原实现）：owner 同时是权限投影字段，
# 在线改权限那条路径要写它（permissions.write_permissions 的 route_update），
# 所以任何能写权限投影的角色（MCP runtime）都能把某条路由的 owner 改成
# "platform"。那一刻这条用户站点就被 Edge 当成平台 origin：
#   · 顶域 sb_session 不再被剥除 → 用户控制的 origin 直接读到共享会话 JWT，
#     可重放到该用户能访问的任何站点；
#   · origin_response 的 PLATFORM_MARK 分支放行它写 sb_session →
#     可做会话固定/强制登出。
# 即"信任标记"与"可写数据"是同一个字段，这是权限提升的直接通路。
#
# subdomain 是路由表的分区键：它是 Key，不是可 SET 的属性，改它等于写另一条
# item（需要 PutItem，MCP runtime 没有），且新 item 的 subdomain 必须真的
# 匹配请求 host 才会被查到。因此按分区键白名单判定是不可伪造的。
#
# 与 auth/deploy_auth.py 注册的平台路由保持一致（当前只有 auth）。
# 新增平台自有子域名（如 M3 控制台）时必须同步这里，否则它拿不到平台待遇。
# console 加入平台白名单（M3）。**平台身份只认这里**——不得根据
# route.owner == "platform" 或任何 route item 可写字段推导（那些字段对能写
# 权限投影的角色是可控的，见 _is_platform_route 的注释）。
PLATFORM_SUBDOMAINS = ("auth", "console")

# lambda_handler 用请求 host 解析出的 subdomain 算好后放进这个键。
# 名字带前缀且不是路由表里的属性名：即便有人往路由 item 里写同名字段，
# lambda_handler 也会用真实 host 的判定结果覆盖它（{**route, ...} 在后）。
_PLATFORM_KEY = "_platform_origin"


def _is_platform_route(route: dict) -> bool:
    """是否平台自有 origin。

    **只读 lambda_handler 按请求 host 算出的 _PLATFORM_KEY，缺省 False。**
    绝不要改回读 route["owner"]/route["subdomain"] 这类存储字段——见上面
    PLATFORM_SUBDOMAINS 的注释：那些字段对能写权限投影的角色是可控的。
    缺键即 False 是有意的 fail-closed：判不出平台身份时按不可信站点处理
    （剥 cookie、不给 mark），最坏结果是 auth-service 功能异常，
    而不是把会话 JWT 泄漏给站点代码。
    """
    return route.get(_PLATFORM_KEY) is True


def _strip_reserved_cookies(request) -> None:
    """从转发给不可信 origin 的请求里删除平台保留 cookie，保留站点自己的 cookie。"""
    headers = request.get("headers", {})
    if "cookie" not in headers:
        return
    kept_headers = []
    for header in headers["cookie"]:
        kept = [p.strip() for p in header["value"].split(";")
                if p.strip() and p.strip().partition("=")[0] not in RESERVED_COOKIES]
        if kept:
            kept_headers.append({"key": header.get("key", "Cookie"),
                                 "value": "; ".join(kept)})
    if kept_headers:
        headers["cookie"] = kept_headers
    else:
        headers.pop("cookie", None)


def _redirect_login(host: str, uri: str, querystring: str = "") -> dict:
    full = f"https://{host}{uri}" + (f"?{querystring}" if querystring else "")
    target = urllib.parse.quote(full, safe="")
    return {"status": "302", "statusDescription": "Found",
            "headers": {"location": [{"key": "Location",
                        "value": f"https://auth.{BASE_DOMAIN}/login?redirect={target}"}]}}


def _forbidden() -> dict:
    return {"status": "403", "statusDescription": "Forbidden",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/html"}]},
            "body": "<html><body><h1>403</h1><p>你不在此站点的访问名单内。</p></body></html>"}


def _check_auth(request, route, host, sink=None):
    """返回 None=放行（用户头已注入）；返回 dict=302/403 响应。

    `sink` 是**可选的 out-param**：验签成功后把邮箱放进去，供埋点使用
    （403 分支也要有——"谁被拒了"是被拒记录的全部价值）。
    **用 out-param 而不是改成返回二元组**：M4-FINDINGS §3.3——因审查从单值改
    多值的函数，调用方最容易按旧签名继续用。也**不往 request 上挂键**：
    CloudFront 会校验 request 对象的形状。
    """
    # 无条件剥除客户端可伪造的用户头与平台 origin 标记
    request["headers"].pop("x-user-email", None)
    request["headers"].pop("x-user-name", None)
    request["headers"].pop(PLATFORM_MARK, None)

    # **只有显式布尔 False 才公开**（fail-closed）。
    # 原来写的是 `if not route.get("require_auth")`，于是缺字段（None）、
    # `{"N":"0"}`（0）、`{"L":[]}`（[]）、`{"NULL":true}` 与任何未识别类型
    # （_deser 落到 False）全部走进"放行"分支——私有站点静默全公开，无告警。
    # 迁移脚本、人工修复、新 writer 任一写出这样的行就会触发（实测四种形态
    # 都能放行，2026-08-06）。缺字段说明写入方没表达意图，此时必须取最严。
    require_auth = route.get("require_auth")
    if require_auth is False:
        return None
    if not isinstance(require_auth, bool):
        # 错型/缺失：当作需要登录，并留一行日志便于定位坏数据来源
        print(f"[WARN] route {route.get('subdomain')!r} 的 require_auth 不是布尔"
              f"（{type(require_auth).__name__}={require_auth!r}），按需要登录处理")

    token = _get_cookie(request, "sb_session")
    claims = _verify_session_jwt(token) if token else None
    if not claims:
        return _redirect_login(host, request.get("uri", "/"),
                               request.get("querystring", ""))

    if REQUIRE_IDP_CLAIM:
        # 按未登录处理（302）而非 403：本地用户/旧会话应被引导去正规登录，
        # 403 会让用户以为"没权限"而去找站点 owner 加名单。
        # 两个 claim 都要过：
        #   idp      —— 账号关联过可信 IdP（拦纯本地用户）
        #   auth_via —— 本次 token 出自托管登录或其 refresh（拦 linked 用户
        #               与设过密码的联邦用户走的原生 InitiateAuth 路径；
        #               它们的 idp 是合法的，只有来源能分辨）
        if (claims.get("idp") not in TRUSTED_IDPS
                or claims.get("auth_via") not in TRUSTED_AUTH_SOURCES):
            return _redirect_login(host, request.get("uri", "/"),
                                   request.get("querystring", ""))

    # 契约（spec §1.1）：403 有邮箱、302 无邮箱。
    # **位置不能提前到验签成功处**（Codex 审查 2026-08-14 P2-1，已实测）：
    # 验签成功与 IdP 来源可信是两道检查，中间那段返回 302。提前赋值会让一个
    # 签名有效但 idp/auth_via 不可信的会话（linked 本地用户、旧会话）产出
    # `decision=redirect_login` 且 email 非空——实测 status=302、
    # sink={'email': ...}，违反契约且扩大 PII 落盘。
    if sink is not None:
        sink["email"] = claims["email"]

    # 缺失时**不能默认 "org"**（= 全组织可见）：缺字段说明写入方没有表达意图，
    # 把"未声明"当成"最宽"是 fail-open。默认取最窄——空名单，于是只有
    # owner/协作者（下面的 insiders 例外）能进。
    allowed = route.get("allowed_users") if "allowed_users" in route else []
    if allowed != "org":
        if isinstance(allowed, list):
            allowlist = allowed
        else:
            # 迁移期兼容：一期把名单存成 JSON 字符串。解析失败按空名单处理
            # （fail-closed：宁可全员 403 也不能全员放行）。
            try:
                allowlist = json.loads(allowed)
            except Exception:
                allowlist = []
            if not isinstance(allowlist, list):
                allowlist = []
        email = claims["email"]
        # owner 与 collaborator 隐式在名单内：他们能改这个名单，
        # 要求他们把自己也写进去只会制造"把自己锁在门外"的工单。
        insiders = [route.get("owner", "")] + list(route.get("collaborators") or [])
        if email not in allowlist and email not in insiders:
            return _forbidden()

    request["headers"]["x-user-email"] = [{"key": "x-user-email", "value": claims["email"]}]
    request["headers"]["x-user-name"] = [{"key": "x-user-name",
                                          "value": urllib.parse.quote(claims.get("name", ""))}]
    return None


def _route_request(request, route):
    uri = request.get("uri", "/")
    qs = _fix_querystring_encoding(request.get("querystring", ""))
    request["querystring"] = qs

    # 平台会话 cookie 不下发给站点代码（不可信）；auth-service 需要它做登出等操作
    if _is_platform_route(route):
        request["headers"][PLATFORM_MARK] = [{"key": PLATFORM_MARK, "value": "1"}]
    else:
        _strip_reserved_cookies(request)

    kind = _route_kind(route, uri, request.get("method", "GET"))
    if kind == "lambda":
        return _route_to_lambda(request, route, uri, qs)
    if kind == "reject":
        # 静态桶只接受读方法。**这条判定原来写在本函数里**，M5 把它连同
        # api-only / /api/ / 扩展名一起收进 _route_kind——因为埋点也要用同一份
        # 判定，而"镜像一份"已经错过两次（见 _route_kind 的 docstring）。
        return _not_found("方法不允许")
    path = "/index.html" if kind == "page" else uri
    request["uri"] = f"/{route['static_prefix']}{path}"
    _add_s3_sigv4_auth(request, FRONTEND_BUCKET_DOMAIN, request["uri"])
    request["origin"] = _custom_origin(FRONTEND_BUCKET_DOMAIN)
    request["headers"]["host"] = [{"key": "Host", "value": FRONTEND_BUCKET_DOMAIN}]
    return request


def _custom_origin(domain: str) -> dict:
    return {"custom": {"domainName": domain, "port": DEFAULT_PORT,
                       "protocol": DEFAULT_PROTOCOL, "path": "",
                       "sslProtocols": DEFAULT_SSL_PROTOCOLS,
                       "readTimeout": DEFAULT_READ_TIMEOUT,
                       "keepaliveTimeout": DEFAULT_KEEPALIVE_TIMEOUT,
                       "customHeaders": {}}}


def _add_s3_sigv4_auth(request, domain: str, uri: str) -> None:
    """S3 GET 的 SigV4（Edge 执行角色需有该桶前缀的 s3:GetObject）。

    必须用 S3SigV4Auth 而非通用 SigV4Auth：S3 要求请求带 x-amz-content-sha256，
    通用 SigV4Auth 不生成该头，S3 会返回
    400 InvalidRequest "Missing required header for this request: x-amz-content-sha256"。
    """
    url = f"https://{domain}{urllib.parse.quote(uri)}"
    aws_request = AWSRequest(method="GET", url=url)
    S3SigV4Auth(credentials, "s3", "us-east-1").add_auth(aws_request)
    for h, v in aws_request.headers.items():
        if h.lower() in ("authorization", "x-amz-date", "x-amz-security-token",
                         "x-amz-content-sha256"):
            request["headers"][h.lower()] = [{"key": h, "value": v}]


def _add_sigv4_auth(request: Dict[str, Any], domain: str, uri: str = "/",
                    querystring: str = "", body: bytes = b"") -> None:
    """
    为请求添加 AWS Signature Version 4 认证头

    参数:
        request: CloudFront请求对象
        domain: Lambda Function URL 域名
        uri: 请求URI
        querystring: 查询字符串（已修复编码）
        body: 解码后的请求体（真实 bytes，参与 payload hash 计算）
    """
    # 提取区域
    region = domain.split(".lambda-url.")[1].split(".")[0]

    # 构建请求 URL（使用修复后的查询字符串）
    url = f"https://{domain}{uri}"
    if querystring:
        url += f"?{querystring}"

    # 获取请求方法
    method = request.get("method", "GET")

    # 创建 AWS 请求对象（用解码后的真实 body 计算 payload hash）
    aws_request = AWSRequest(method=method, url=url, data=body)

    # 添加签名
    SigV4Auth(credentials, "lambda", region).add_auth(aws_request)

    # 将签名头添加到 CloudFront 请求
    for header_name, header_value in aws_request.headers.items():
        if header_name.lower() in ['authorization', 'x-amz-date', 'x-amz-security-token']:
            request["headers"][header_name.lower()] = [{
                "key": header_name,
                "value": header_value
            }]

    # 同样脱敏：这一行也会打到带 code= 的请求（见 _redact_querystring）
    logger.info(f"Added SigV4 auth for Lambda URL in region {region} "
                f"with querystring: {_redact_querystring(querystring)}")
