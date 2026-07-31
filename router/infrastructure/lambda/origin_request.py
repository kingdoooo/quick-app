"""
Lambda@Edge Origin Request处理器

根据DynamoDB中存储的subdomain路由表，将CloudFront请求分流到后端
Lambda Function URL（SigV4）或共享前端S3桶（SigV4 GET）。
支持 route_mode：split（/api/ 走后端，其余走S3静态）与 api-only（全路径走后端）。
"""
import json
import logging
from typing import Dict, Any, Optional
import boto3
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
        denied = _check_auth(request, route, original_host)
        if denied:
            return denied
        return _route_request(request, route)
    except Exception as e:
        logger.error(f"处理请求时出错: {e}", exc_info=True)
        return _server_error()


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
        logger.info(f"Fixed querystring: {querystring} -> {result}")
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


def _deser(item: dict) -> dict:
    """DynamoDB AttributeValue -> plain dict（本表用到的类型：S / BOOL / L / N）。

    新增类型必须在此登记：未识别的类型会落到 False。落点不同后果不同——
    allowed_users 变 False 是 fail-closed（json.loads(False) 抛异常 → 空名单
    → 仅 owner/协作者可访问，名单成员全 403 = 宕机）；**require_auth 变 False
    才是灾难**（`if not route.get("require_auth")` 直接放行 = 鉴权整段关闭，
    站点全公开）。加字段前先加解析，尤其是任何会投影到 require_auth 的类型。
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
            out[k] = False
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
RESERVED_COOKIES = ("sb_session",)
# origin_response 靠此头判断"本响应来自平台自己的 origin，允许写平台 cookie"。
# 客户端可伪造，故与 x-user-* 一样先无条件剥除再按路由注入。
PLATFORM_MARK = "x-sb-platform-origin"


def _is_platform_route(route: dict) -> bool:
    return route.get("owner") == "platform"


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


def _check_auth(request, route, host):
    """返回 None=放行（用户头已注入）；返回 dict=302/403 响应。"""
    # 无条件剥除客户端可伪造的用户头与平台 origin 标记
    request["headers"].pop("x-user-email", None)
    request["headers"].pop("x-user-name", None)
    request["headers"].pop(PLATFORM_MARK, None)

    if not route.get("require_auth"):
        return None

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

    allowed = route.get("allowed_users", "org")
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

    if route.get("route_mode") == "api-only":
        return _route_to_lambda(request, route, uri, qs)

    if uri.startswith("/api/"):
        return _route_to_lambda(request, route, uri, qs)

    # 静态资源 → 共享前端桶（私有，SigV4 GET）
    if request.get("method") not in ("GET", "HEAD"):
        return _not_found("方法不允许")
    path = uri if ("." in uri.rsplit("/", 1)[-1]) else "/index.html"
    request["uri"] = f"/{route['static_prefix']}{path}" if path != uri else f"/{route['static_prefix']}{uri}"
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

    logger.info(f"Added SigV4 auth for Lambda URL in region {region} with querystring: {querystring}")
