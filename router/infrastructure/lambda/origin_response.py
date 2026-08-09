"""Lambda@Edge Origin Response 处理器

站点代码是不可信代码：它若能对顶域写 `sb_session`，就能做会话固定
（把访问者塞进攻击者的会话）或强制登出（写garbage 触发无限登录跳转）。
本函数从站点 origin 的响应里剥除平台保留 cookie 的 Set-Cookie；
auth-service 自己需要签发该 cookie，由 CloudFront 转发时带的标记放行。

与 origin_request.py 的 RESERVED_COOKIES 必须保持一致。
"""
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RESERVED_COOKIES = ("sb_session", "__Host-sb_console", "__Host-sb_pkce")
# origin_request 对平台路由（auth-service）注入此头，允许其签发平台 cookie
PLATFORM_MARK = "x-sb-platform-origin"


def _cookie_name(set_cookie_value: str) -> str:
    return set_cookie_value.split("=", 1)[0].strip()


def lambda_handler(event, context):
    try:
        rec = event["Records"][0]["cf"]
        response = rec["response"]
        request = rec.get("request", {})

        # 平台自己的 origin（auth-service）允许写平台 cookie
        if PLATFORM_MARK in request.get("headers", {}):
            return response

        headers = response.get("headers", {})
        if "set-cookie" not in headers:
            return response

        kept = [h for h in headers["set-cookie"]
                if _cookie_name(h.get("value", "")) not in RESERVED_COOKIES]
        if len(kept) != len(headers["set-cookie"]):
            logger.warning("站点 origin 试图写平台保留 cookie，已剥除")
        if kept:
            headers["set-cookie"] = kept
        else:
            headers.pop("set-cookie", None)
        return response
    except Exception as e:
        # 响应阶段 fail-open 到原响应：此处异常若吞掉整个响应会让站点全挂，
        # 而保留 cookie 的最坏情况（会话固定）严重性低于全站不可用。
        logger.error(f"origin-response 处理出错: {e}", exc_info=True)
        return event["Records"][0]["cf"]["response"]
