"""站点登录端点（Lambda Function URL）。
/login → Cognito Hosted UI（后接飞书 OIDC）；/callback → 验 state、验 PKCE、
验 id_token、种顶域会话 cookie；/logout。
安全：OAuth 授权码 + PKCE(S256) + nonce；state HMAC 签名 + 5 分钟过期
（防 login CSRF/redirect 篡改）；id_token 走 Cognito JWKS 验签 +
iss/aud/exp/token_use 校验，并核对 nonce（防 id_token 重放）。
**code_verifier 与 nonce 放 `__Host-sb_pkce` host-only cookie，不放 state**
——state 随 authorize URL 明文传输（只有签名、没有加密），把 verifier 放进去
既会经地址栏/Referer/IdP 日志/浏览器历史泄漏，也不再与浏览器绑定
（攻击者可把自带 verifier 的 callback URL 发给受害者做 login CSRF）。
见 _encode_state / _pkce_cookie 的 docstring 与 spec §7.2。"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt as pyjwt
from jwt import PyJWKClient

from session import SESSION_TYP, mint_session_jwt, mint_upgrade_code, verify_session_jwt

_jwks_client = None  # 模块级缓存，Lambda 容器复用
# (值, 读取时刻) —— 带 TTL，见 _secret 的说明
_secret_cache: dict[str, tuple[str, float]] = {}
_ssm_client = None
# 缓存有效期。Lambda 执行环境可复用数小时，**无 TTL 的缓存会让密钥轮转后
# warm 容器永久用旧值**，而新容器用新值——登录请求随机落到两类容器，一部分
# 成功一部分 invalid_client，且没有任何配置变更能触发刷新。
# 300 秒是延迟与新鲜度的折中：每 5 分钟最多一次 SSM 调用（不会撞节流），
# 轮转后最长 5 分钟收敛。
SECRET_TTL_SECONDS = 300


def _ssm():
    global _ssm_client
    if _ssm_client is None:
        import boto3
        _ssm_client = boto3.client("ssm", region_name="us-east-1")
    return _ssm_client


def _secret(name: str) -> str:
    """从 SSM SecureString 读密钥，容器内缓存。

    **不从环境变量下发生产密钥**：`lambda:GetFunctionConfiguration` 会原样
    回显环境变量明文，而那是个很常见的只读权限（部署时实测确认过）。
    JWT_SECRET 的后果尤重——Edge 只验 HS256 签名，拿到它即可伪造任意用户的
    会话 cookie，等于绕过 owner / allowed_users / collaborators 全部判定。

    仍认环境变量直给的值：单测与本地调试依赖它，且生产部署只下发 `*_PARAM`
    参数名（见 deploy_auth 的 lambda_env），所以明文不会回到线上配置。
    两个来源都没有时抛错——空密钥签出的 HS256 任何人都能伪造，静默降级
    在这里等于关掉鉴权。

    缓存带 `SECRET_TTL_SECONDS` 的 TTL：无 TTL 时轮转密钥后 warm 容器会永久
    用旧值（Lambda 执行环境可复用数小时），表现为部分请求成功、部分
    invalid_client，且改配置也不触发刷新。

    ⚠️ **JWT_SECRET 的轮转不能只靠这个 TTL**：Edge 那份是 CDK 部署时字符串
    替换注入的（Lambda@Edge 不支持环境变量），改一次要 10-20 分钟全球复制。
    auth 侧读到新值时 Edge 可能还在用旧值验签 → 这期间新签发的会话全部验签
    失败，用户登录后立刻被踢回登录页（症状极难定位到密钥版本）。轮转它需要
    版本化/双密钥或"先让 Edge 同时接受新旧值、复制完成后再切签发"的协调顺序，
    不在当前实现范围内。
    **动手前先读 DEPLOY.md「轮转 jwt-secret：当前实现下不能就地改值」**——
    那里写了为什么不能就地改、双密钥要改哪两处，以及密钥已泄漏时那条
    "可用性换安全性"的应急步骤（含"处置期间不要回滚 Edge"）。
    """
    hit = _secret_cache.get(name)
    if hit is not None and time.monotonic() - hit[1] < SECRET_TTL_SECONDS:
        return hit[0]
    direct = os.environ.get(name)
    if direct:
        _secret_cache[name] = (direct, time.monotonic())
        return direct
    param = os.environ.get(f"{name}_PARAM")
    if not param:
        raise RuntimeError(
            f"{name} 无来源：既没有环境变量 {name}，也没有 {name}_PARAM 指向 "
            "SSM 参数。拒绝继续——空密钥签出的会话任何人都能伪造。")
    value = _ssm().get_parameter(Name=param, WithDecryption=True)[
        "Parameter"]["Value"]
    _secret_cache[name] = (value, time.monotonic())
    return value


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            f"https://cognito-idp.us-east-1.amazonaws.com/"
            f"{os.environ['USER_POOL_ID']}/.well-known/jwks.json")
    return _jwks_client


def _state_sig(body: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(
        _secret("JWT_SECRET").encode(), body.encode(),
        hashlib.sha256).digest()).rstrip(b"=").decode()


PKCE_COOKIE = "__Host-sb_pkce"


def _encode_state(redirect: str) -> str:
    """state 只放 redirect 与过期时间，**不放 code_verifier / nonce**。

    RFC 7636 的分工是授权请求只发 code_challenge、令牌请求才发 code_verifier。
    把明文 verifier 放进随 authorize URL 传输的 state（state 有 HMAC 签名，
    但内容是 base64 明文）会让它经浏览器地址栏、Referer、IdP 侧日志与浏览器
    历史各暴露一遍，PKCE 本应提供的"授权码被截获也换不到 token"的独立防护
    就没了；更要紧的是它不再绑定浏览器——攻击者把自己登录产生的 callback URL
    发给受害者，verifier 跟在 URL 里，后端就能替受害者完成交换并种下攻击者
    账户的会话（login CSRF / account confusion）。verifier 放 host-only
    cookie 才与浏览器绑定。见 spec §7.2。
    """
    body = base64.urlsafe_b64encode(json.dumps(
        {"r": redirect, "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
    return f"{body}.{_state_sig(body)}"


def _decode_state(state: str) -> str | None:
    """验签 + 验期，失败返回 None；成功返回 redirect。"""
    try:
        body, _, sig = state.rpartition(".")
        if not hmac.compare_digest(sig, _state_sig(body)):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return payload["r"]
    except Exception:
        return None


def _pkce_cookie(verifier: str, nonce: str) -> str:
    """把 verifier/nonce 装进 auth 子域的 host-only 短期 cookie。

    __Host- 前缀是浏览器强制的：必须 Secure、必须 Path=/、**必须无 Domain**，
    因此它只回发给签发它的那台主机（/login 与 /callback 同在 auth.{base}，
    读得到）。5 分钟过期，用完即清。

    **不要给本函数加 base/domain 参数**：`__Host-` 前缀下任何 `Domain=` 都会让
    浏览器直接丢弃该 cookie，于是每次登录都走 callback 的 400 分支。
    `"t": "pkce"` 是类型标记——state 与本 cookie 共用 `_state_sig`，没有它
    一个合法 state 值就能充当"签名合法"的 pkce cookie（见 _read_pkce_cookie）。
    """
    payload = base64.urlsafe_b64encode(
        json.dumps({"t": "pkce", "v": verifier, "n": nonce}).encode()).decode().rstrip("=")
    sig = _state_sig(payload)
    return (f"{PKCE_COOKIE}={payload}.{sig}; Path=/; Max-Age=300; "
            f"Secure; HttpOnly; SameSite=Lax")


def _read_pkce_cookie(event) -> dict | None:
    """从 callback 请求里取回 verifier/nonce；验签失败、缺失或内容不完整返回 None。

    **整段包在 try 里**（不只包 json.loads）：`hmac.compare_digest` 对含非 ASCII
    的字符串会抛 `TypeError`，而 cookie 值完全由客户端控制——只包 json.loads
    时一个 `__Host-sb_pkce=YWJj.ü` 就能让 handler 抛出 500 + 堆栈，而不是约定的
    400。`_decode_state` 本来就是整段包的，这里必须一致。

    **v/n 必须非空**：`_state_sig` 同时给 state 与本 cookie 签名、且线格式相同，
    所以一个合法 state 值就是一个"签名合法"的 pkce cookie——它解出来
    `{"v": "", "n": ""}`，若不检查就会带着空 verifier 去 `_post_token`，
    正是"静默降级成无 PKCE 交换"（现在只靠 Cognito 拒空 verifier 兜着，
    不是本地约束）。同时给 payload 打类型标记，彻底断开两种上下文的签名复用。
    """
    for raw in (event.get("cookies") or []):
        name, _, value = raw.partition("=")
        if name.strip() != PKCE_COOKIE:
            continue
        try:
            body, _, sig = value.rpartition(".")
            if not hmac.compare_digest(sig, _state_sig(body)):
                return None
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if data.get("t") != "pkce":      # state 值不能当 pkce cookie 用
                return None
            verifier, nonce = data.get("v", ""), data.get("n", "")
            if not verifier or not nonce:
                return None
            return {"v": verifier, "n": nonce}
        except Exception:
            return None
    return None


def _pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256：返回 (code_verifier, code_challenge)。"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _is_safe_redirect(url: str) -> bool:
    """回跳白名单：仅 https 且 host 属于 BASE_DOMAIN。

    反斜杠必须显式拒绝：Python urlparse 把 "https://evil.com\\.example.com/" 的 host
    解析为 "evil.com\\.example.com"（后缀匹配通过），而浏览器按 WHATWG 规范把 \\ 当
    /，实际导航到 evil.com——登录成功后会把已认证用户送到攻击者站点。
    """
    if not isinstance(url, str) or "\\" in url:
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return False
    host = parsed.hostname or ""
    base = os.environ["BASE_DOMAIN"]
    return host == base or host.endswith("." + base)


# 是否要求 email 已被 IdP 验证。默认 **开**——这是 email 作为授权主键的前提。
# 只有接入不提供 email_verified claim 的 IdP 时才设 "false"，代价是这道
# 技术防线消失、退回纯选型约束（见 config.ini.example [IdP] 的说明）。
REQUIRE_EMAIL_VERIFIED = os.environ.get(
    "REQUIRE_EMAIL_VERIFIED", "true").strip().lower() != "false"


def _is_verified(value) -> bool:
    """email_verified 的判定。**只认真值，其他一律 False（fail-closed）。**

    形态在两条链路上不一致：id_token 里是 JSON 布尔 true，而 pre-token
    触发器从 userAttributes 拿到的是字符串 "true"。两种都要认；缺失、
    "false"、None、空串一律不通过。
    """
    return value is True or str(value).strip().lower() == "true"


class TokenExchangeRejected(Exception):
    """Cognito 的 token 端点用 4xx 拒了本次交换（无效/过期/已用过的 code）。

    与"上游故障"（5xx、超时、DNS）分开：前者是可预期的用户侧失败，必须给 400；
    后者是平台故障，应让异常冒出去以便告警与重试统计。混在一起会让真实故障
    被静默成"请重新登录"。
    """


def _post_token(code: str, verifier: str) -> dict:
    domain = os.environ["COGNITO_DOMAIN"]
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": os.environ["CLIENT_ID"],
        "redirect_uri": f"https://auth.{os.environ['BASE_DOMAIN']}/callback",
        "code_verifier": verifier,
    }).encode()
    basic = base64.b64encode(
        f"{os.environ['CLIENT_ID']}:{_secret('CLIENT_SECRET')}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token", data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # HTTPError **不是** ValueError 的子类（它走 URLError→OSError 这条），
        # 所以 callback 的 `except ValueError` 接不住它：无效/过期/重放的 code
        # 会让整个 handler 抛异常 → Function URL 502 + CloudWatch 堆栈，
        # 而不是注释里承诺的 400。已实测复现（HTTP Error 400: Bad Request）。
        #
        # **按 OAuth error code 分流，不能按 HTTP 状态码一刀切**：Cognito 的
        # token 端点用 400 表达的远不只"这个 code 不能用"——invalid_client
        # （secret 被轮换/写坏）、unauthorized_client（client 没开 code grant）、
        # invalid_request（我们自己拼错请求）都是 400，而 429 是限流。
        # 把它们全翻成"请重新登录"会让配置事故与限流伪装成用户错误：
        # 用户反复重登都失败，而 Lambda 返回成功的 400，不触发任何 5xx 告警。
        # 只有 invalid_grant 才真正属于"本次授权码不可用"。
        err, desc = _oauth_error(e)
        if err == "invalid_grant":
            # **invalid_grant 不等于"用户的 code 有问题"**：官方把
            # "app client 缺少 scope 所需的属性读取权限（如请求 email scope
            # 却读不到 email_verified）"也归到这个 code 下。那是**全员登录失败**
            # 的配置事故，与"某个用户重放了 code"混在同一个 400 里。
            # 响应体不足以可靠细分（error_description 不是稳定契约），所以
            # 不猜：仍返回用户可读的 400，但**必须留下结构化日志**，让
            # "invalid_grant 突然高频"这条曲线可被告警发现。
            # 单个用户重放 = 偶发几条；配置写坏 = 每次登录一条，形态完全不同。
            _log_auth_failure("token_exchange_invalid_grant",
                              error=_safe_error(err),
                              hint=_describe_hint(desc), status=e.code)
            raise TokenExchangeRejected(
                f"授权码不可用（{err}）: {e.code}") from e
        # 其余 4xx 与全部 5xx 一律上抛成平台故障：宁可 502 告警，
        # 也不要把"secret 过期了"显示成"请重新登录"。
        _log_auth_failure("token_exchange_upstream_error",
                          error=_safe_error(err),
                          hint=_describe_hint(desc), status=e.code)
        raise


# RFC 6749 §5.2 + Cognito token 端点实际会返回的 error code 全集。
# **日志只允许出现这里面的值或 "other"**：`error` 字段同样来自上游 JSON，
# 上一版只把 error_description 收口了，却把 error 原样记录——探针实证
# `{"error": "custom_AUTH_CODE_LEAKS_VIA_ERROR_FIELD"}` 会整串进日志，
# 违反 _log_auth_failure 自己的约定。规范上 error 不该含请求值，但"规范上
# 不该"不是实现保证：网关/代理/未来版本都可能塞别的东西进去。
_KNOWN_OAUTH_ERRORS = frozenset({
    "invalid_request", "invalid_client", "invalid_grant",
    "unauthorized_client", "unsupported_grant_type", "invalid_scope",
    "slow_down", "access_denied", "server_error",
    "temporarily_unavailable",
})


def _safe_error(error: str) -> str:
    """把上游 error 收口到已知词汇；未知值一律压成 "other"。

    分类信息不丢：告警按 event + error 聚合，而 Cognito 正常只会返回
    _KNOWN_OAUTH_ERRORS 里的值。真出现 "other" 本身就是值得查的信号
    （上游返回了非规范 error code），此时去看它对应的 HTTP status。
    """
    return error if error in _KNOWN_OAUTH_ERRORS else ("other" if error else "")


# error_description 里出现这些子串时，归成一个**固定词汇**的分类值。
# 只用于把"配置写坏"与"用户重放"分开，不承载上游原文。
_HINT_PATTERNS = (
    ("attribute_read_permission", ("email_verified", "read attribute",
                                   "not authorized to read")),
    ("client_config", ("client", "grant type", "unauthorized_client")),
    ("redirect_uri", ("redirect",)),
    ("code_state", ("code", "expired", "consumed", "already")),
)


def _describe_hint(description: str) -> str:
    """把上游 error_description 压成固定词汇的分类，**绝不回传原文**。

    为什么不能记原文（实测踩过）：Cognito 会在 error_description 里回显请求值，
    探针里出现过 `bad code <授权码> for user <邮箱>`——授权码与邮箱一起进了
    CloudWatch，而日志保留期远长于授权码寿命。error_description 还可能带
    redirect URI、client 信息等。而告警**只依赖频率**，原文对它没有价值。
    分类值取自上面的固定表，未命中一律 "other"：即便上游改文案，
    进日志的也只有这几个常量之一。
    """
    low = (description or "").lower()
    for label, needles in _HINT_PATTERNS:
        if any(n in low for n in needles):
            return label
    return "other" if low else ""


def _log_auth_failure(event_type: str, **fields) -> None:
    """一行 JSON 打进 CloudWatch Logs，供 metric filter / Logs Insights 聚合。

    为什么是结构化而不是 print 文本：这条日志的用途是**发现配置事故**——
    对 `event="token_exchange_invalid_grant"` 建 metric filter + 阈值告警，
    高频即代表 app client 属性权限被写坏（而非用户重放）。文本日志做不到
    可靠聚合。

    **只允许放固定词汇/枚举值，绝不放上游原文或任何请求值**：
    code / token / cookie / 邮箱 / redirect URI 都不行。上游回显是真实存在的
    泄漏渠道（见 _describe_hint）。新增字段前先问"这个值的取值集合是否有限"。
    """
    try:
        print(json.dumps({"event": event_type, **fields}, ensure_ascii=False))
    except Exception:
        pass        # 日志失败绝不能影响请求处理路径


def _oauth_error(err: urllib.error.HTTPError) -> tuple[str, str]:
    """取 OAuth 错误响应体的 (error, error_description)；取不到返回 ("", "")。

    读 body 会消耗流，且只读一次——调用方之后不要再读它。
    body 不是 JSON / 没有 error 字段 / 读失败时一律返回空，
    走"当成平台故障上抛"的保守分支（分类不出来时不要替用户下结论）。
    """
    try:
        payload = json.loads(err.read().decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            return "", ""
        return payload.get("error", ""), payload.get("error_description", "")
    except Exception:
        return "", ""


def _exchange_code(code: str, verifier: str, nonce: str) -> dict:
    """code → Cognito token → JWKS 验签 + nonce 校验 → {email, name}"""
    tokens = _post_token(code, verifier)
    signing_key = _get_jwks_client().get_signing_key_from_jwt(tokens["id_token"])
    claims = pyjwt.decode(
        tokens["id_token"], signing_key.key, algorithms=["RS256"],
        audience=os.environ["CLIENT_ID"],
        issuer=f"https://cognito-idp.us-east-1.amazonaws.com/{os.environ['USER_POOL_ID']}")
    if claims.get("token_use") != "id":
        raise ValueError("token_use != id")
    # nonce 绑定本次 /login：缺失或不匹配都拒绝，防他人的 id_token 被重放进
    # 这个 callback（PKCE 保护授权码，nonce 保护 id_token）。
    if claims.get("nonce") != nonce:
        raise ValueError("id_token nonce 与本次登录不匹配")
    # **email 是授权主键**（owner / collaborators / allowed_users 全用它），
    # 而联邦映射进 Cognito 的 email 默认 unverified。只映射不校验等于没有
    # 技术防线：允许自设邮箱的 IdP 上，改个 email 就能继承他人站点权限。
    # 开关默认开（当前飞书适配器确实发 email_verified=true）；接入不发该
    # claim 的 IdP 时才关，且关掉意味着回到"只靠 IdP 选型兜底"。
    if REQUIRE_EMAIL_VERIFIED and not _is_verified(claims.get("email_verified")):
        raise ValueError("邮箱未经身份提供方验证，拒绝签发会话")
    # idp 由 pre-token 触发器注入 id token（两个容器都写，见 Task 14 Step 4b）。
    # 本地用户没有它——会话里就不会有，Edge 据此拦截（spec §3.5）。
    return {"email": claims["email"], "name": claims.get("name", claims["email"]),
            "idp": claims.get("idp", ""),
            "auth_via": claims.get("auth_via", "")}


def handler(event, context):
    path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}
    base = os.environ["BASE_DOMAIN"]

    if path == "/login":
        redirect = qs.get("redirect", f"https://{base}/")
        if not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid redirect"}
        verifier, challenge = _pkce_pair()
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
        auth_url = (f"{os.environ['COGNITO_DOMAIN']}/oauth2/authorize?"
                    + urllib.parse.urlencode({
                        "response_type": "code", "client_id": os.environ["CLIENT_ID"],
                        "redirect_uri": f"https://auth.{base}/callback",
                        "scope": "openid email profile",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "nonce": nonce,
                        "state": _encode_state(redirect)}))
        # verifier/nonce 走 host-only cookie（与浏览器绑定），不进 URL
        return {"statusCode": 302, "headers": {"Location": auth_url},
                "cookies": [_pkce_cookie(verifier, nonce)], "body": ""}

    if path == "/callback":
        redirect = _decode_state(qs.get("state", ""))
        if redirect is None or not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid or expired state"}
        pkce = _read_pkce_cookie(event)
        if pkce is None:
            # cookie 丢失/被篡改/内容不完整（换了浏览器、被清、超过 5 分钟、
            # 或拿 state 值来冒充）——比静默降级到无 PKCE 安全：重走一次登录。
            return {"statusCode": 400,
                    "body": "登录状态已过期，请重新登录"}
        # IdP 也可能带着 ?error=access_denied 回调（没有 code），或 code 被重放、
        # nonce 不匹配（两个登录标签页并发时第二个会覆盖单一 cookie）。
        # 这些都是可预期的用户侧失败，必须给 400 而不是让异常冒成 500 +堆栈。
        code = qs.get("code", "")
        if not code:
            return {"statusCode": 400,
                    "body": "授权失败或被取消，请重新登录"}
        try:
            user = _exchange_code(code, pkce["v"], pkce["n"])
        except (ValueError, TokenExchangeRejected, pyjwt.InvalidTokenError):
            # 三类都是可预期的用户侧失败，都给 400：
            #   ValueError            —— nonce/token_use 不匹配、claims 缺失
            #   TokenExchangeRejected —— code 无效/过期/被重放（token 端点 4xx）
            #   InvalidTokenError     —— id_token 验签/exp/aud/iss 不过
            # pyjwt 的异常**不继承 ValueError**（基类是 PyJWTError→Exception），
            # 过期的 id_token 同样会冒成 500，所以必须显式列出。
            # 上游 5xx / 超时 / JWKS 拉取失败不在此列，照原样上抛成 5xx——
            # 平台故障不能伪装成"请重新登录"。
            return {"statusCode": 400, "body": "登录校验失败，请重新登录"}
        token = mint_session_jwt(user["email"], user["name"],
                                 _secret("JWT_SECRET"), idp=user.get("idp", ""),
                                 auth_via=user.get("auth_via", ""))
        cookie = (f"sb_session={token}; Domain=.{base}; Path=/; Max-Age=86400; "
                  f"Secure; HttpOnly; SameSite=Lax")
        clear_pkce = f"{PKCE_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        return {"statusCode": 302, "headers": {"Location": redirect},
                "cookies": [cookie, clear_pkce], "body": ""}

    if path == "/console-session":
        # 面板会话升级入口：顶域 sb_session（站点/平台通用）→ 一次性 code。
        #
        # **为什么要多这一跳**：面板会话必须是 console 域的 host-only
        # `__Host-sb_console`，而本函数跑在 auth.{base} 上，跨域设不了那个
        # cookie（`__Host-` 前缀禁止 Domain=）。所以走"auth 发 code → 302 到
        # console → console 自己 Set-Cookie"（spec §5.4）。
        #
        # code 只出现在 Location：不设 cookie、不进 body，且 no-store。
        # 它 60 秒过期且由 panel 侧原子消费一次（session-codes 表条件写）。
        session_token = ""
        for raw in (event.get("cookies") or []):
            name_, _, value_ = raw.partition("=")
            if name_.strip() == "sb_session":
                session_token = value_
                break
        claims = verify_session_jwt(session_token, _secret("JWT_SECRET"),
                                    expected_typ=SESSION_TYP)
        if not claims:
            # 无有效会话（缺失/过期/签名不过）：走完整登录，登录后**回到本
            # 入口**再换 code。redirect 指回 console 首页是错的——那样用户
            # 登录完了却仍没有面板会话，面板继续 401。
            back = urllib.parse.quote(f"https://auth.{base}/console-session",
                                      safe="")
            return {"statusCode": 302,
                    "headers": {"Location": f"https://auth.{base}/login?redirect={back}",
                                "cache-control": "no-store"},
                    "body": ""}
        code = mint_upgrade_code(claims["email"], _secret("JWT_SECRET"))
        target = (f"https://console.{base}/api/session-callback"
                  f"?code={urllib.parse.quote(code, safe='')}")
        return {"statusCode": 302,
                "headers": {"Location": target, "cache-control": "no-store"},
                "body": ""}

    if path == "/logout":
        # 清平台会话，然后**把用户送去 Cognito 的 /logout 结束托管登录会话**。
        # 只清本地 cookie 是不够的：Cognito 侧的会话 cookie 还活着，共享设备上
        # 退出后再访问任何站点会被静默自动重新登录（看起来像"登出没生效"）。
        #
        # 效力边界，别当成完整登出：Cognito 的 /logout **不会**登出上游 IdP
        # （官方明示"The logout endpoint doesn't sign users out of OIDC or
        # social identity providers"）。飞书侧会话仍在，只是下次登录会重新
        # 经过一次 IdP 授权而不是直接复用 Cognito 会话。真正的全局登出要把
        # 用户再导向 IdP 自己的登出页，那属于 IdP 特定配置（保持 IdP 无关，
        # 故不做），因此登出提示文案不能承诺"已完全退出"。
        cookie = (f"sb_session=; Domain=.{base}; Path=/; Max-Age=0; "
                  f"Secure; HttpOnly; SameSite=Lax")
        done = f"https://auth.{base}/logged-out"
        # logout_uri 必须是该 client 已登记的 sign-out URL，否则 Cognito 报错。
        # **不能指向 /logout 本身**——那会打回本分支，无限重定向。
        target = (f"{os.environ['COGNITO_DOMAIN']}/logout?"
                  + urllib.parse.urlencode({
                      "client_id": os.environ["CLIENT_ID"],
                      "logout_uri": done}))
        return {"statusCode": 302, "headers": {"Location": target},
                "cookies": [cookie], "body": ""}

    if path == "/logged-out":
        # Cognito 登出后的落地页。这里已经没有平台会话了；再清一次是幂等兜底
        # （用户可能直接访问本路径）。
        cookie = (f"sb_session=; Domain=.{base}; Path=/; Max-Age=0; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 200, "cookies": [cookie],
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body": "<h1>已退出登录</h1>"
                        "<p>如需彻底结束企业账号会话，请同时退出企业身份提供方。</p>"}

    return {"statusCode": 404, "body": "not found"}
