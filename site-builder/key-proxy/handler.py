"""key-proxy Lambda 入口：六步前置 + **不懂 MCP 协议**的透明转发（二期 M4，spec §5.2）。

只能配静态 Header 的 MCP 客户端（如 Quick Desktop 的 Remote MCP）把
`X-API-Key: sk-…` 打到 `mcp.{base_domain}`：CloudFront → Lambda@Edge → 本函数的
Function URL。本函数验 Key、换机器 token，然后把**原封不动**的 MCP 请求转给
AgentCore runtime，只多一个 `X-SB-On-Behalf-Of: {email}` 告诉 MCP server
"以谁的身份行事"（server 侧的信任规则见 spec §5.3）。

**六步顺序是安全边界，不是风格**（plan Task 5）。每一步失败时后续步骤必须
**零副作用**：⓪①② 失败不得产生任何 DynamoDB 读，③ 失败不得换 token、不得转发、
不得写 last_used。`tests/test_handler.py` 的顺序组在 boto3 层装间谍锁定这一点，
并有一条正对照证明间谍装得上（断言"某件事没发生"的用例假通过时没有任何症状）。

  ⓪ 传输层：IAM 调用者必须是 Edge 执行角色（`edge_caller`，**唯一实现**）
  ① 只接受 POST
  ② `X-API-Key` 存在
  ③ `keystore.lookup`（开关 + Key，**每次现读不缓存**）→ email
  ④ `machine_token.get_token`（组件**自身**的凭证，可以缓存）
  ⑤ 透明转发 + 节流写 last_used

**⓪ 为什么 key-proxy 也要**：同账号 principal 只要 identity policy 允许
`lambda:InvokeFunctionUrl` + `InvokeFunction` 就能绕开 resource policy 直连
（44aef8d 的 P1-1 真机实证）。绕过 Edge 对本组件不等于绕过认证（攻击者还得有一把
有效 Key），但 **Edge 是可观测性与限流的唯一位置**——绕过它意味着 Key 暴力尝试
不留任何可告警痕迹。**本文件不解析调用者身份、也不认识 RoleId 的形态**：判定的
唯一实现在 `edge_caller.py`（panel 与 key-proxy 共用），有一条 AST 守卫盯着这点
（它按字面量扫描，所以本文件连"那个前缀"都不该出现）。

**"透明"的具体含义**（plan 决定 7）：
  · 请求 body 是 **bytes 原样**。不 `json.loads`——非法 JSON 与 JSON-RPC batch
    都必须原样到上游，由上游按协议回错（我们不是 MCP 实现，猜不对）；重新序列化
    还会改字节（紧凑分隔符、`ensure_ascii` 转义）。
  · 出站请求头由**白名单从零构建**，不是"复制入站再覆盖"。后者只要漏掉一个名字
    就等于把客户端自带的 `X-SB-On-Behalf-Of` 交给上游，于是任意持 Key 者能冒充
    任意人——这是本文件最坏的失效模式，所以它的形态必须是"只有列出来的能过"。
  · 响应体**整体缓冲后逐字节回传**（SSE 也一样）。Lambda 的响应不能流式经过
    Lambda@Edge，所以缓冲不是"暂不支持流式"而是这条链路上唯一的选项；既然要
    缓冲，就绝不能顺手"按 `data:` 行重组"——那会丢掉 event/id/注释行并改掉 CRLF。
  · 响应头只回 `content-type` 与 `mcp-session-id`，其余全丢（上游的 `set-cookie`
    尤其不能落到 `{base_domain}` 上——那是平台会话 cookie 的作用域）。

**cookie 一个字节都不读**（plan 决定 9）：`mcp` 子域**故意不在** Edge 的
`PLATFORM_SUBDOMAINS` 里，因此 Edge 会剥掉保留 cookie。但"上游剥了"不是本文件
可以依赖的前提（那个白名单随时会被改，而改它的人不会想到 key-proxy）。

**明文 Key 与机器 token 都不进日志、不进异常文案、不进任何响应体。** 日志里只有
`key_id`（非秘密，控制台里就列着它）、`Verdict.reason`（我们自己的词汇）与状态码。
"""
import base64
import json
import logging
import os
import urllib.error
import urllib.request

import edge_caller
import keygen
import keystore
import machine_token

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AgentCore invocations 端点的环境变量名。**常量在这里定义一次**供
# deploy_key_proxy.py 引用，两侧不各写字符串字面量——手抄的第二份真源会漂移
# （下发了 A、代码读 B，两侧单测都绿而线上全 502），同 edge_caller.EDGE_ROLE_ID_ENV。
AGENTCORE_ENDPOINT_ENV = "AGENTCORE_ENDPOINT"

# 出站请求头白名单。**tuple 而不是 set**：模块级可变容器是跨请求缓存的入口，
# test_no_module_level_cache.py 会拦下 set/dict/list 字面量（它刻意放过
# tuple/frozenset——不可变常量正是白名单该有的形态）。
REQUEST_HEADER_ALLOWLIST = ("content-type", "accept", "mcp-session-id",
                            "mcp-protocol-version")
# 回给客户端的响应头白名单。
RESPONSE_HEADER_ALLOWLIST = ("content-type", "mcp-session-id")

# 转发超时。Lambda 侧给 30s，这里留余量：不显式给超时的话上游挂住会把整个 Lambda
# 拖到它自己的超时，客户端看到的是空响应而不是一条可归因的 504。
HTTP_TIMEOUT_SECONDS = 25

# 上游拒绝**我们自己**的凭证的状态码：只有这两个触发 invalidate + 重取 + 重发
# 一次（spec §8）。别把 400/404/500 加进来——那是 MCP 协议层的回答，重发只会把
# 一次无效请求放大成两次，而客户端还会丢掉真正的 JSON-RPC 错误信息。
TOKEN_REJECTED_STATUSES = (401, 403)

# 无效 / 吊销 / 关闸 / 未知 Key / 压根没带 Key：**同一状态码、同一份字节**
# （spec §8）。调用方不得能区分"这把 Key 不存在"与"被吊销了"与"平台关闸了"，
# 否则这就是一个免费的 Key 状态探测器。分类信息只进日志。
# "没带 Key"也收进这一份：调用方本来就知道自己有没有带头，所以它不是信息隐藏的
# 必要项——但让 401 只有一种形态，能杜绝"某天有人给其中一条加句更友好的文案"
# 顺手把四种原因也拆开。排查靠日志里的 reason=missing-api-key。
REJECT_STATUS = 401
REJECT_BODY = json.dumps({"error": "API Key 无效或已被吊销"}, ensure_ascii=False)


class UpstreamTimeout(Exception):
    """上游在超时预算内没有回话 → 504。"""


class UpstreamUnavailable(Exception):
    """连不上 / 连接被重置 / 响应读不出来 → 502。

    与 UpstreamTimeout 分开是有意的：两者的运维处置完全不同（前者看上游负载与
    我们的超时预算，后者看网络与端点配置）。合成一个状态码会让排查从第一步就
    分不清方向。
    """


class EndpointMisconfigured(Exception):
    """`AGENTCORE_ENDPOINT` 缺失或不是 https → 502，且**不发出任何请求**。"""


def _our_response(status: int, body: str) -> dict:
    """**我们自己**产生的响应（拒绝与故障）。`body` 是已序列化的字符串。

    与透传响应刻意分成两个函数：透传响应不许加头（那会破坏透明性），而我们自己的
    响应必须带 `no-store`——一个被缓存的 401 会在管理员开闸之后继续拒绝，且没人
    看得出为什么。
    """
    return {"statusCode": status,
            "headers": {"content-type": "application/json",
                        "cache-control": "no-store"},
            "body": body}


def _reject() -> dict:
    """五种拒绝原因共用的**那一份**响应（见 REJECT_BODY 的理由）。"""
    return _our_response(REJECT_STATUS, REJECT_BODY)


def _error(status: int, message: str) -> dict:
    """故障响应。`message` 必须是**写死在本文件里的常量文案**。

    绝不拼接异常：`str(e)` 会带上 ARN / 表名 / 端点 URL / OAuth error 词汇，
    而 502 的响应体是给公网看的。分类信息进日志。
    """
    return _our_response(status, json.dumps({"error": message},
                                            ensure_ascii=False))


def _endpoint() -> str:
    """AgentCore invocations URL。形态见 `mcp/deploy_agentcore.py`：
    `https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{URL 编码的 ARN}/
    invocations?qualifier=DEFAULT`。

    它**只认 Bearer JWT，不走 SigV4**，所以 key-proxy 的 role 不需要任何 bedrock
    权限（Task 8 的最小权限断言据此收窄）。

    **必须是 https**：这个请求带着机器 token。降级到明文会把凭证放到线上，而症状
    是"一切正常"——不会有任何人察觉。同 machine_token 对 COGNITO_DOMAIN 的处理。
    """
    url = (os.environ.get(AGENTCORE_ENDPOINT_ENV) or "").strip()
    if not url:
        logger.error("%s 未配置——无法转发", AGENTCORE_ENDPOINT_ENV)
        raise EndpointMisconfigured("endpoint-missing")
    if not url.startswith("https://"):
        logger.error("%s 必须是 https——拒绝用明文转发机器 token",
                     AGENTCORE_ENDPOINT_ENV)
        raise EndpointMisconfigured("endpoint-not-https")
    return url


def _request_body(event: dict) -> bytes:
    """Function URL 的请求体 → bytes。**只解码，不解析。**

    `isBase64Encoded` 是 Function URL 对二进制载荷的表示，判据只能是这个标志本身
    ——按 content-type 猜会在客户端发了预期之外的类型时解错，而"解错"在这里等于
    把请求体改掉。
    """
    raw = event.get("body")
    if not raw:
        return b""
    if event.get("isBase64Encoded"):
        return base64.b64decode(raw)
    return raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)


def _outbound_headers(headers: dict, token: str, email: str) -> dict:
    """出站请求头：**从零按白名单构建**，绝不"复制入站再覆盖"。

    刻意不透传：`authorization`（换成我们的机器 token）、`x-api-key`（不能泄给
    下游）、`cookie`（决定 9）、`host`（urllib 按 URL 自己填）、
    `x-sb-on-behalf-of`（**客户端说什么都不算**——见模块 docstring 的冒充路径）。

    **不给 `accept` 之类补默认值**：客户端没声明就是没声明。替它声明"我接受 SSE"
    会让上游发回一个它读不懂的流，而透明代理的职责是不发明语义。
    """
    out = {}
    for name in REQUEST_HEADER_ALLOWLIST:
        value = headers.get(name)
        if isinstance(value, str) and value != "":
            out[name] = value
    # 我们**加**的两个头，与上面的"只读入站"那一段分开写：混在一个循环里就会
    # 演变成"复制入站再覆盖"，而那是本文件最坏失效模式的形态。
    out["authorization"] = f"Bearer {token}"
    out["x-sb-on-behalf-of"] = email
    return out


def _is_timeout(e: BaseException) -> bool:
    """超时与"连不上"必须分开。

    urllib 把 socket 超时**有时**直接抛出、**有时**包在 `URLError.reason` 里
    （connect 阶段与 read 阶段不同），所以两层都要看。只看一层的后果是一半的
    超时被记成 502。
    """
    if isinstance(e, TimeoutError):
        return True
    return isinstance(getattr(e, "reason", None), TimeoutError)


def _post(url: str, body: bytes, out_headers: dict):
    """一次转发 → `(status, headers, body_bytes)`。

    **出站头由调用方传进来**（而不是在这里现拼）：重发那一次必须换成**新** token，
    调用点显式传新头能让"重发用了新 token、但仍是同一份 body"这件事在代码上一眼
    可读——反过来在这里现拼，两次调用看起来完全一样，改错了也看不出。

    **4xx/5xx 也是"返回"而不是"异常"**：urllib 对非 2xx 抛 `HTTPError`，但对调用方
    而言上游的 400/500 是协议层的回答，必须原样透传（MCP 的错误就在那些响应体
    里）。当成异常处理会让客户端拿到我们编的 502，真正的 JSON-RPC 错误则丢失。

    `HTTPError` 本身就是一个响应对象（`.code` / `.headers` / `.read()`），且它的
    `.headers` 与 `urlopen()` 的一样是 `HTTPMessage`（大小写不敏感）——所以下游
    按小写名取头是安全的（上游发的是 `Content-Type`）。
    """
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers=out_headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    except Exception as e:
        # 只记类型名：有些异常的 str() 会带上完整 URL 与请求信息。
        if _is_timeout(e):
            raise UpstreamTimeout(type(e).__name__) from e
        raise UpstreamUnavailable(type(e).__name__) from e


def _passthrough(status: int, up_headers, body: bytes) -> dict:
    """上游响应 → Function URL 响应。**字节级原样。**

    UTF-8 能解就以文本回，不能解则 base64 + `isBase64Encoded`。两条路都是**无损**
    的：JSON 与 SSE 都是 UTF-8 文本，走第一条；真出现二进制载荷时走第二条也不改
    一个字节。不能只走第一条（`errors="replace"` 会静默改字节），也不必只走第二条
    （那会让日常响应多 33% 体积）。
    """
    out = {"statusCode": status, "headers": {}}
    for name in RESPONSE_HEADER_ALLOWLIST:
        value = up_headers.get(name)
        if value:
            out["headers"][name] = value
    try:
        out["body"] = body.decode("utf-8")
    except UnicodeDecodeError:
        out["body"] = base64.b64encode(body).decode("ascii")
        out["isBase64Encoded"] = True
    return out


def handler(event, context):
    """入口。**只做一件事**：把未预期异常收敛成 500，不让堆栈冒到 Function URL。"""
    try:
        return _handle(event)
    except Exception:
        # 不回显内部错误（ARN / 表名 / 堆栈都是内部结构），日志里留全量。
        logger.exception("key-proxy 未预期异常")
        return _error(500, "服务内部错误，请稍后重试")


def _handle(event: dict) -> dict:
    # ⓪ 传输层。**不在这里重写判定**：唯一实现在 edge_caller.py。
    #    与下面各步一样不回显原因——探测者不该知道我们在比什么。
    if not edge_caller.caller_is_edge(event):
        return _error(403, "禁止访问")

    # ① 只接受 POST。streamable-http 的 GET（服务端推流）与 DELETE（关会话）在
    #    这条链路上不存在：Lambda 的响应不能流式经过 Lambda@Edge，而既有的 stdio
    #    代理（clients/quick-desktop-proxy）实测也只发 POST。method 缺失同样落
    #    405（fail-closed，不默认成 POST）。
    method = ((event.get("requestContext") or {}).get("http") or {}).get("method")
    if (method or "").upper() != "POST":
        out = _error(405, "只接受 POST")
        out["headers"]["allow"] = "POST"
        return out

    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    # ② Key 存在。**不给假值兜底**：鉴权字段的"默认值"往往正好是"放宽"。
    #    这一步在 ③ 之前是为了不给出一条免费的存在性探测通道（也不让暴力尝试
    #    的成本落在我们的读容量上）。
    plaintext = headers.get("x-api-key") or ""
    if not plaintext:
        logger.warning("请求未携带 X-API-Key reason=missing-api-key")
        return _reject()

    # ③ 开关 + Key。**每次现读、不缓存**——即时吊销是这套设计存在的全部理由。
    verdict = keystore.lookup(plaintext)
    if not verdict.ok:
        # reason 与 key_id 都只进日志（前者是分类信息，后者是非秘密标识符）。
        # 明文与 key_hash 都不在 Verdict 里，因此也进不了这条日志。
        logger.warning("Key 校验未通过 reason=%s key_id=%s",
                       verdict.reason, verdict.key_id or "-")
        return _reject()

    # 端点配置在换 token **之前**校验：配置错时不该额外向 Cognito 发一次注定要
    # 作废的请求（也让"配置错"与"上游拒了我们"在日志里天然可分）。
    try:
        endpoint = _endpoint()
    except EndpointMisconfigured:
        return _error(502, "上游未正确配置，请联系管理员")

    # ④ 组件自身的凭证。get_token 失败时**抛**而不是返回空串（machine_token 的
    #    保证）——空串会变成 `Bearer ` 打到网关，得到一个与本地故障毫无关系的 401。
    try:
        token = machine_token.get_token()
    except machine_token.TokenUnavailable:
        # 异常文案里只有状态码与收口后的 OAuth 词汇，但那仍是内部信息：只进日志。
        logger.exception("换取机器 token 失败 key_id=%s", verdict.key_id)
        return _error(502, "上游认证暂时不可用，请稍后重试")

    # ⑤ 转发。body 取一次、两次尝试共用同一份 bytes（见下）。
    body = _request_body(event)
    try:
        status, up_headers, up_body = _post(
            endpoint, body, _outbound_headers(headers, token, verdict.email))
        if status in TOKEN_REJECTED_STATUSES:
            # 上游拒的是**我们的**凭证（客户端的 Key 已经在 ③ 验过了）。典型原因
            # 是 token 在这几十毫秒里过期，或 machine client secret 被轮转。
            # invalidate + 重取 + 重发一次（spec §8）；**重发用同一份 body**——
            # 重新从 event 取在别的实现里会拿到已消费的流（空体），而空体会换回
            # 一个与真实原因毫无关系的 400，排查方向被整个带偏。
            logger.warning("上游拒绝机器 token status=%s——重取后重发一次", status)
            machine_token.invalidate()
            token = machine_token.get_token()
            status, up_headers, up_body = _post(
                endpoint, body,
                _outbound_headers(headers, token, verdict.email))
            if status in TOKEN_REJECTED_STATUSES:
                # **只重试一次**：第二次仍被拒说明不是"刚过期"，而是配置/授权问题
                # （machine client 不在 allowedClients、scope 不对）。继续重试
                # 只会把一次故障放大，且掩盖真正的原因。
                logger.error("重取 token 后仍被上游拒绝 status=%s key_id=%s",
                             status, verdict.key_id)
                return _error(502, "上游认证暂时不可用，请稍后重试")
    except machine_token.TokenUnavailable:
        logger.exception("重取机器 token 失败 key_id=%s", verdict.key_id)
        return _error(502, "上游认证暂时不可用，请稍后重试")
    except UpstreamTimeout:
        logger.warning("上游在 %ss 内未响应 key_id=%s", HTTP_TIMEOUT_SECONDS,
                       verdict.key_id)
        return _error(504, "上游响应超时，请稍后重试")
    except UpstreamUnavailable as e:
        logger.warning("上游不可达 key_id=%s cause=%s", verdict.key_id, e)
        return _error(502, "上游暂时不可用，请稍后重试")

    # 遥测放在最后，且只在**真的把请求送到上游并拿到回答**之后——转发失败时写
    # last_used 会给出"这把 Key 刚用过"的假象。touch_last_used 自己吞掉所有异常
    # （它是遥测不是授权），所以这里不需要 try：把"最后使用时间没记上"升级成
    # "这次 MCP 调用失败"是明显更坏的交换。
    # key_hash 不在 Verdict 里（刻意——它不该进日志），所以现算一次。
    keystore.touch_last_used(keygen.hash_key(plaintext), verdict.key_id)
    logger.info("转发完成 key_id=%s status=%s", verdict.key_id, status)
    return _passthrough(status, up_headers, up_body)
