"""机器 token：key-proxy 向 AgentCore 证明「我是 key-proxy」的凭证。

**本模块是 M4 里唯一允许缓存的模块**，与 `keystore` 的「绝不缓存」并不矛盾——
两者缓存的东西性质完全不同：

  · keystore 读的是**授权判定**（这把 Key 是谁的、平台闸门开没开）。缓存它
    「即时吊销」就不成立，而即时吊销是那套设计存在的全部理由。
  · 本模块拿的是**本组件自身的凭证**。它的作用域是整个 key-proxy，与「哪个
    用户在调」无关：吊销某个用户的 Key 不需要换 token（用户身份走
    `X-SB-On-Behalf-Of` 头，每请求现查）。不缓存会让每次 MCP 调用多一次
    Cognito 往返，并撞 token 端点的频率限制。

所以这里**不得缓存任何与用户相关的东西**——缓存键只由「域 + client_id +
scope」构成，里面出现 email / key_id / key_hash 就说明写错了模块。
`key-proxy/tests/test_no_module_level_cache.py` 有一条反向用例盯着本文件
**确实有缓存**，防止有人为了让那两条结构守卫变绿而把缓存删掉。

**提前 REFRESH_MARGIN_SECONDS 换新，不等 401**：spec §8 的「token 被拒 →
重取一次再转发」是**兜底**，不是主路径。等 401 才换会让每个 token 生命周期
末尾的请求多一次往返 + 一条失败日志（噪音会掩盖真实故障）。

**secret 不进环境变量**：环境里只有 `MACHINE_SECRET_PARAM`（SSM 参数名）。
`lambda:GetFunctionConfiguration` 会原样回显环境变量，而那是个很常见的只读
权限（`44aef8d` 之前的 auth 就踩过明文密钥进环境变量，部署时实测确认）。

**secret 与 token 都是凭证：两者都不得进日志、异常文案或 repr。** 本模块的
日志只出现状态码、收口后的 OAuth error 词汇和有效期秒数。
"""
import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

logger = logging.getLogger(__name__)

# 提前多久换新。300 秒足够覆盖一次 SSM 读 + 一次 token 交换 + 一次 MCP 转发，
# 不会出现「拿到 token 时它还有效、转发到网关时已过期」。
REFRESH_MARGIN_SECONDS = 300
# secret 缓存的 TTL。**不可省**：无 TTL 时轮转密钥后 warm 容器会永久用旧值
# （Lambda 执行环境可复用数小时），表现为「部分请求 invalid_client」这种极难
# 查的间歇故障（auth 的既有教训）。300 秒 = 每 5 分钟最多一次 SSM 读。
SECRET_TTL_SECONDS = 300
# token 端点的超时。**必须显式给**：默认无超时时 Cognito 挂住会把整个 Lambda
# 拖到它自己的超时，客户端看到的是 504 而不是一条可归因的 502。
# 比 auth 的 10 秒短，因为换到 token 之后还要跑一次 MCP 转发。
HTTP_TIMEOUT_SECONDS = 5

# (域, client_id, scope) → (access_token, 绝对过期时刻)。见模块 docstring：
# 键里**只有组件自身的身份**，任何用户维度的东西都不该出现在这里。
_token_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
# 参数名 → (明文, 读取时刻)
_secret_cache: dict[str, tuple[str, float]] = {}
_ssm_client = None

# RFC 6749 §5.2 + Cognito token 端点实际会返回的 error code 全集。
# **日志只允许出现这里面的值或 "other"**：`error` 字段来自上游 JSON，
# 「规范上它不该含请求值」不是实现保证（网关/代理/未来版本都可能塞别的东西
# 进去）。auth 侧的探针实证过整串异常值会进日志，这里照同一口径收口。
_KNOWN_OAUTH_ERRORS = frozenset({
    "invalid_request", "invalid_client", "invalid_grant",
    "unauthorized_client", "unsupported_grant_type", "invalid_scope",
    "slow_down", "access_denied", "server_error", "temporarily_unavailable",
})


class TokenUnavailable(Exception):
    """换不到机器 token。handler 转 502。

    **所有失败都收敛到这一个异常**（4xx、5xx、超时、DNS、响应体没有
    access_token）：调用方对它们的处置完全相同——不转发、回 502、留日志。
    分类信息不丢，它进的是日志（状态码 + 收口后的 error 词汇）而不是异常类型。

    文案里**只允许出现状态码与收口后的 error 词汇**，绝不含 secret 或 token。
    """


def _ssm():
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = boto3.client("ssm", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"))
    return _ssm_client


def _now() -> float:
    """单调时钟。**函数而不是内联 `time.monotonic()`**：单测要能控制时间去覆盖
    「提前换新」与「过期换新」两条分支，内联就只能靠 `sleep`（慢且不稳）。"""
    return time.monotonic()


def _env(name: str) -> str:
    """必需的环境变量，空白视同缺失。

    缺配置一律 `TokenUnavailable` 而不是 `KeyError`：后者会冒成未捕获异常
    （Function URL 502 + 一条堆栈），与「上游故障」在监控上无法区分；而这里
    每一项缺失都是部署脚本的问题，必须能从日志一眼看出是哪一项。
    """
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise TokenUnavailable(f"{name} 未配置——拒绝换取机器 token")
    return value


def _token_endpoint() -> str:
    """`{COGNITO_DOMAIN}/oauth2/token`，并强制 https。

    **两种形态都要接**：auth 侧的 `COGNITO_DOMAIN` 带 scheme
    （`https://sso.auth.<region>.amazoncognito.com`），而 key-proxy 的
    既有夹具只给裸域名。缺 scheme 时补 https 而不是报错——它是同一个配置项的
    两种既有写法，在这里挑一种去炸只会让部署卡在一个与功能无关的地方。

    **明文 http 一律拒**：这个请求体里带的是 Basic 凭证（client secret），
    响应里带的是 access token。降级到 http 等于把两个凭证都放到线上明文里，
    而症状（一切正常）不会有任何人察觉。
    """
    domain = _env("COGNITO_DOMAIN").rstrip("/")
    if "://" not in domain:
        domain = "https://" + domain
    if not domain.startswith("https://"):
        raise TokenUnavailable("COGNITO_DOMAIN 必须是 https——"
                               "明文会把 client secret 与 token 一起泄漏")
    return f"{domain}/oauth2/token"


def _config() -> tuple[str, str, str]:
    """(token 端点, client_id, scope)。**任何一项不合法时此处就抛**——
    调用点在发出任何 SSM / HTTP 请求之前，所以配置错误不会变成一次对 Cognito
    的无效请求。

    `MACHINE_SCOPE` 是**部署脚本拼好的完整串**（`{resource_server_id}/{scope}`，
    Codex 审查 2026-08-11 P1-2a）。这里只读、不再拼、不给默认值：
      · 硬编码 `site-builder-mcp/invoke` 会绕开「config.ini 是唯一取值来源」，
        而 config 允许自定义 resource server 与 scope 名；
      · 拼接逻辑只应存在于 `deploy_key_proxy.py` 一处（少一处能写错的地方）；
      · 缺失时**绝不能拿空 scope 去换**——Cognito 会拒，但错误文案指向
        client 配置，排查方向会被整个带偏。
    """
    return _token_endpoint(), _env("MACHINE_CLIENT_ID"), _env("MACHINE_SCOPE")


def _secret() -> str:
    """从 SSM SecureString 读 machine client secret，带 TTL 缓存。

    形态照 `panel/console_session._secret()`：环境里只有参数名。
    **返回值绝不进日志**，调用方只把它塞进 Basic 头。
    """
    name = _env("MACHINE_SECRET_PARAM")
    hit = _secret_cache.get(name)
    if hit is not None and _now() - hit[1] < SECRET_TTL_SECONDS:
        return hit[0]
    try:
        value = _ssm().get_parameter(Name=name, WithDecryption=True)[
            "Parameter"]["Value"]
    except Exception as e:
        # 读不到密钥就换不到 token。**不回退到环境变量、不回退到空串**：
        # 空 secret 换来的只会是一个 invalid_client，而日志会指向 Cognito
        # 配置而不是这次 SSM 失败。
        logger.warning("machine client secret 读取失败 %s", type(e).__name__)
        raise TokenUnavailable(
            f"无法读取 machine client secret: {type(e).__name__}") from e
    if not isinstance(value, str) or not value:
        raise TokenUnavailable("machine client secret 为空")
    _secret_cache[name] = (value, _now())
    return value


def _oauth_error(err: urllib.error.HTTPError) -> str:
    """错误响应体里的 `error`，收口到 `_KNOWN_OAUTH_ERRORS` 或 "other"。

    读 body 会消耗流且只读一次。取不到返回空串——分类不出来时不猜。
    这一个词是排查的关键分叉：`invalid_client` = secret 写坏/轮转过，
    `invalid_scope` = `MACHINE_SCOPE` 与 resource server 不一致，
    `unauthorized_client` = client 没开 client_credentials。
    """
    try:
        payload = json.loads(err.read().decode("utf-8", "replace"))
        raw = payload.get("error", "") if isinstance(payload, dict) else ""
    except Exception:
        return ""
    return raw if raw in _KNOWN_OAUTH_ERRORS else ("other" if raw else "")


def _expires_at(payload: dict) -> float | None:
    """`expires_in` → 绝对过期时刻；不可用时返回 None（调用方按「不缓存」处理）。

    非数字 / ≤0 都算不可用。**不给默认有效期**：猜一个偏长的值会让缓存把
    已经失效的 token 一直发出去（症状是间歇 401，且看不出与时间有关）。
    """
    try:
        seconds = float(payload.get("expires_in"))
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return _now() + seconds


def _exchange(url: str, client_id: str, scope: str) -> tuple[str, float | None]:
    """`client_credentials` 换一次 token。→ (access_token, 绝对过期时刻|None)。

    凭证走 **Basic 头**而不是请求体里的 `client_secret`：两者 Cognito 都收，
    但请求体更容易被沿途的日志/抓包完整记录。

    **任何失败都抛 `TokenUnavailable`，绝不返回空串**：空串会变成
    `Authorization: Bearer ` 打到网关，得到的是一个与本地故障毫无关系的 401，
    排查时会一路查到网关配置上去。
    """
    body = urllib.parse.urlencode({"grant_type": "client_credentials",
                                   "scope": scope}).encode()
    basic = base64.b64encode(f"{client_id}:{_secret()}".encode()).decode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # 4xx 与 5xx **不分流**：对调用方而言两者都是「这次换不到」。分类进
        # 日志（见 _oauth_error 的 docstring），不进异常类型。
        error = _oauth_error(e)
        logger.warning("机器 token 交换被拒 status=%s error=%s", e.code, error)
        raise TokenUnavailable(
            f"token 端点拒绝了交换 status={e.code} error={error}") from e
    except Exception as e:
        # 超时 / DNS / 连接重置 / 响应体不是 JSON 都落这里。只记类型名——
        # 有些异常的 str() 会带上完整 URL 与请求信息。
        logger.warning("机器 token 交换失败 %s", type(e).__name__)
        raise TokenUnavailable(f"token 端点不可用: {type(e).__name__}") from e
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        logger.error("token 端点未返回 access_token")
        raise TokenUnavailable("token 端点未返回 access_token")
    return token, _expires_at(payload)


def get_token() -> str:
    """有效的机器 access token。缓存至**过期前 REFRESH_MARGIN_SECONDS 秒**。

    **失败绝不缓存**：只有成功路径会写 `_token_cache`，所以一次故障之后下一次
    调用会重新尝试（把失败结果缓存住会让一次抖动变成 300 秒的全量不可用）。

    **刷新失败时不回退到「还没真过期」的旧 token**（它可能还剩 299 秒）：
    刷新失败的典型原因是 Cognito 不可达或 secret 被轮转，回退只能把同一个故障
    往后推不到 5 分钟，代价是多一条「用着一个已经没法确认还授不授权的凭证」
    的路径。宁可现在 502。
    """
    url, client_id, scope = _config()
    key = (url, client_id, scope)
    hit = _token_cache.get(key)
    if hit is not None and hit[1] - _now() > REFRESH_MARGIN_SECONDS:
        return hit[0]
    token, expires_at = _exchange(url, client_id, scope)
    if expires_at is None or expires_at - _now() <= REFRESH_MARGIN_SECONDS:
        # 有效期缺失或短于 margin：**这一次照用，但不进缓存**。
        # 不抛错——token 本身是可用的，为一个 RFC 里只是 RECOMMENDED 的字段
        # 让整条通道不可用是过度反应；也不缓存——那等于自己发明一个有效期。
        # 代价是每次调用一次往返，所以留一条 warning 让它可被发现。
        logger.warning("token 剩余有效期不足以缓存（expires_in 缺失或过短）"
                       "——本次不缓存，每次调用都会重新换取")
        return token
    _token_cache[key] = (token, expires_at)
    return token


def invalidate() -> None:
    """丢弃缓存。供转发拿到 401/403 时重取一次（spec §8 的兜底路径）。

    **secret 一并丢**：401 是「我这边的凭证被拒了」这条路上唯一的信号，而
    secret 的 300 秒 TTL 会让一次轮转把 warm 容器卡在旧值上（那段时间全部
    502）。多一次 SSM 读换掉这个窗口是划算的——401 重试全局只发生一次
    （Task 5 只重发一次），不构成放大。
    """
    _token_cache.clear()
    _secret_cache.clear()
