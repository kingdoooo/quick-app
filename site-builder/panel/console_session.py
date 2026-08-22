"""面板会话：一次性 code 消费 → __Host-sb_console cookie，以及 CSRF 前置。

**本模块不实现 code 的编解码**——单一实现在 auth/session.py，deploy_panel.py
打包时复制过来（同 common.py / permissions.py 模式）。这里只做三件事：
① 用 verify_upgrade_code 验签后**原子消费 jti**（条件写 session-codes）；
② 构造/校验 __Host-sb_console（scope=console 的会话 JWT，TTL 4h）；
③ CSRF 校验，且必须**前置于**一切业务副作用（spec §5.4，顺序在 handler.py）。

密钥：环境变量只有参数名 JWT_SECRET_PARAM，运行时从 SSM SecureString 读 +
TTL 缓存（照抄 auth 的 _secret 模式）。**明文严禁进环境变量**——
GetFunctionConfiguration 会原样回显，拿到 JWT_SECRET 即可伪造任意用户会话。
"""
import os
import time
from datetime import datetime, timezone

import boto3

import session

CONSOLE_COOKIE = "__Host-sb_console"
CONSOLE_SCOPE = "console"
CONSOLE_TTL_SECONDS = 4 * 3600
# 消费标记留存时长：code 本身 60 秒过期，但标记要留得久一点才能挡住
# "过期后重放"的探测，也便于排查。TTL 到点由 DynamoDB 自动清。
CONSUMED_TTL_SECONDS = 3600
SECRET_TTL_SECONDS = 300
WRITE_METHODS = ("PUT", "POST", "DELETE")

_secret_cache: dict[str, tuple[str, float]] = {}


class UpgradeRejected(Exception):
    """code/cookie 不可信。handler 转 401 + {"need": "console-session"}。"""


class CsrfRejected(Exception):
    """前置校验未过。handler 转 403，且**此时尚未发生任何副作用**。"""


def _secret() -> str:
    """从 SSM 读 JWT 密钥，带 TTL 缓存。

    TTL 不可省：无 TTL 时轮转密钥后 warm 容器会永久用旧值，表现为
    "部分请求验签失败"这种极难查的间歇故障（auth 的既有教训）。
    """
    name = os.environ["JWT_SECRET_PARAM"]
    hit = _secret_cache.get(name)
    if hit is not None and time.monotonic() - hit[1] < SECRET_TTL_SECONDS:
        return hit[0]
    value = boto3.client("ssm", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).get_parameter(
            Name=name, WithDecryption=True)["Parameter"]["Value"]
    _secret_cache[name] = (value, time.monotonic())
    return value


def _codes_table():
    return boto3.resource("dynamodb", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).Table(
            os.environ["SESSION_CODES_TABLE"])


def consume_code(code: str, *, expected_email: str) -> str:
    """验 code 并**原子消费** jti → email。任何不可信情形抛 UpgradeRejected。

    条件写而不是"先查再写"：并发重放下后者两边都会看到"没用过"，两个请求
    都能换到面板会话。

    **三步顺序不可调换**（每一步都在挡一类攻击）：
      ① 验签 —— 否则伪造的 code 也能往表里写一行（垃圾数据 + 探测 jti 空间）；
      ② 比对 expected_email —— **必须在消费之前**（Codex 审查 2026-08-10
         P2-3）。原来是"先消费再由 handler 比对"，于是拿别人的 code 提交一次
         （得到 401）就把它作废了，合法持有者随后只会看到"升级码已被使用"。
         实测复现过。这一步放在条件写之前，错身份就不会留下任何痕迹；
      ③ 原子消费 jti。

    `expected_email` 是**必填关键字参数**：给默认值等于允许调用方忘记传，
    而"忘记传"恰好退化成原来那个缺陷。
    """
    import botocore.exceptions
    claims = session.verify_upgrade_code(code or "", _secret())
    if not claims:
        raise UpgradeRejected("升级码无效或已过期")
    # **空值不得视为相等**（同 verify_console_cookie 的理由）：两边都空时
    # `==` 成立，等于放行一个无身份的请求。
    if not expected_email or claims.get("email") != expected_email:
        raise UpgradeRejected("升级码与当前身份不符")
    try:
        _codes_table().put_item(
            Item={"jti": claims["jti"], "email": claims["email"],
                  "consumed_at": datetime.now(timezone.utc).isoformat(),
                  "expires_at": int(time.time()) + CONSUMED_TTL_SECONDS},
            ConditionExpression="attribute_not_exists(jti)")
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise UpgradeRejected("升级码已被使用") from e
        raise
    return claims["email"]


def console_cookie(email: str, name: str) -> str:
    """__Host-sb_console 的 Set-Cookie 值。

    __Host- 前缀是浏览器强制的：必须 Secure、必须 Path=/、**必须无 Domain**。
    不要给本函数加 domain 参数——任何 Domain= 都会让浏览器整条丢弃 cookie，
    表现为"登录成功但面板一直 401"（auth 的 PKCE cookie 有同样的注释）。
    """
    token = session.mint_session_jwt(email, name, _secret(),
                                     ttl_seconds=CONSOLE_TTL_SECONDS,
                                     scope=CONSOLE_SCOPE)
    return (f"{CONSOLE_COOKIE}={token}; Secure; HttpOnly; "
            f"SameSite=Lax; Path=/; Max-Age={CONSOLE_TTL_SECONDS}")


def verify_console_cookie(cookie_header: str, *, x_user_email: str) -> str:
    """→ email。验签 + 未过期 + scope==console + **与 Edge 身份一致**。

    最后一条不能省：换人登录后浏览器里可能还留着前一个人的
    __Host-sb_console（4h TTL），而 x-user-email 是 Edge 刚验过的真身份。
    不一致就必须重新升级，否则 B 拿着 A 的面板会话操作 A 的站点。
    """
    token = ""
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == CONSOLE_COOKIE:
            token = v
            break
    if not token:
        raise UpgradeRejected("缺少面板会话")
    claims = session.verify_session_jwt(token, _secret(),
                                        expected_typ=session.SESSION_TYP)
    if not claims:
        raise UpgradeRejected("面板会话无效或已过期")
    if claims.get("scope") != CONSOLE_SCOPE:
        # 只有站点会话（typ=session 但无 scope）会落在这里；upgrade code
        # 早在上面的 typ 检查就被拒了（M05 之前它是靠这一行兜住的）。
        raise UpgradeRejected("该会话不是面板会话")
    # **空值不得视为相等**：两边都空时 `==` 成立，等于放行一个无身份请求
    if not x_user_email or claims.get("email") != x_user_email:
        raise UpgradeRejected("面板会话与当前登录身份不一致")
    return claims["email"]


def check_csrf(method: str, headers: dict) -> None:
    """spec §5.4 的方法白名单 / Origin / Content-Type 三项。

    **缺 Origin 直接拒绝，不回退 Referer**：Referer 会被代理与隐私设置改写，
    拿它当同源证据就是一条绕过路径。

    Origin 用**逐字符相等**而不是 startswith/endswith：
    `https://console.example.com.evil.com` 与 `https://evil.console.example.com`
    都能骗过前缀/后缀匹配。
    """
    if (method or "").upper() not in WRITE_METHODS:
        raise CsrfRejected(f"方法 {method!r} 不允许用于写操作")
    expected = f"https://{os.environ['CONSOLE_HOST']}"
    origin = (headers or {}).get("origin", "")
    if not origin:
        raise CsrfRejected("缺少 Origin 头")
    if origin != expected:
        raise CsrfRejected("Origin 不匹配")
    ctype = (headers or {}).get("content-type", "")
    # 浏览器常发 application/json;charset=UTF-8——按前缀判断 media type
    if not ctype.split(";")[0].strip().lower() == "application/json":
        raise CsrfRejected("Content-Type 必须是 application/json")
