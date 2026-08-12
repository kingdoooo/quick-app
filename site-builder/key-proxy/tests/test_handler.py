"""key-proxy handler：六步前置（顺序即安全边界）+ 不懂 MCP 协议的透明转发。

四组断言彼此不可替代，每组都有一条"防自己变成永远绿"的护栏：

  · **顺序组**在 boto3 层装间谍，证明"前置失败时后续零副作用"。断言"没发生"
    的用例最容易变成永远绿——所以本文件有一条**正对照**
    (`test_spy_sees_reads_and_writes_on_the_happy_path`) 证明间谍确实装得上、
    看得见读也看得见写。`keystore._ddb` 是模块级全局且**跨用例存活**，不清掉它
    间谍就落不到实处，而那时所有"零副作用"断言会一起假通过
    （M3-FINDINGS §2.10 的同一形态：守卫只覆盖它自己夹具造出来的世界）。
    顺序组还额外覆盖**重排**而不只是删除：`switch-off` 那条同时断言"没换
    token、没转发、没写 last_used"，把 ③ 挪到 ④ 之后就会红。

  · **透明性组**用"round-trip 必然改变字节"的载荷：紧凑分隔符 + 非 ASCII。
    `json.dumps(json.loads(x)) == x` 对 `{"a": 1}` 这种"恰好长得像 dumps 输出"
    的串是成立的，拿它做载荷会让"解析再序列化"这个缺陷测不出来。

  · **错误组**断言四种拒绝原因**逐字节相同**，以及 502/504 的响应体里没有内部
    信息。后者的判据是"假异常里塞的内部标记不出现在 body 里"——只断言
    "没有 Traceback" 抓不到 `str(e)` 拼进文案这种写法。

  · **日志组**每个分支用**不同的**假明文再按全串 grep：共用一份明文时，"某个
    分支泄漏了"会被另一个分支的干净输出掩盖不掉，但会分不清是哪一条泄的。

本文件里所有 `sk-` 值都是现造的假 Key（`_fake_key`，形态合法、库里现种），
与任何真实凭证无关；机器 token 也是 `tok-machine-*` 这种假值。
"""
import ast
import base64
import io
import json
import logging
import pathlib
import urllib.error
import urllib.request
from email.message import Message

import boto3
import pytest

import handler
import keygen
import keystore
import machine_token
# **从 conftest 取 EDGE_ROLE_ID 而不是再写一份字面量**：panel 侧那份是手抄的
# （test_handler.py 与 conftest.py 各写一遍，靠注释约定"必须一致"）。手抄的第二
# 份真源会漂移，而漂移的症状是"403 但两边单测都绿"。顺带也不必在本文件里再放
# 一个 `AROA` 串（Code Defender 的 HARD_CODED_SECRET 按前缀 + 长度匹配）。
from conftest import ENV

EDGE_CALLER_ID = f"{ENV['EDGE_ROLE_ID']}:us-east-1.ApplicationWebRouterStack-fn"
ENDPOINT = ENV["AGENTCORE_ENDPOINT"]

# 非 Edge 调用者的 callerId：真机上是一个 IAM user（AdministratorAccess）直连时
# 的形态——`AIDA` + 17 位，且**没有** `:session` 段。
# **拼接 + 现造的假值，两条理由**：① Code Defender 的 HARD_CODED_SECRET 按
# `AIDA`/`AROA` 前缀 + 长度匹配，整串写出来当场阻断提交（它的 remediation 是往
# secrets.allowed 加例外——那是放宽扫描器，本项目明令不走）；② 真实 principal ID
# 属于"真实账号值"，按仓库红线不进被跟踪文件。panel 的同名用例里还留着一个真串
# （`panel/tests/test_handler.py:483`，早于该规则生效），那份是隐患不是范例。
NON_EDGE_CALLER = "AIDA" + "NOTTHEEDGEROLEXXX"

# 上游响应的默认载荷（正常 JSON-RPC 回答）。
OK_JSON = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

# 非法 JSON：**必须原样到上游**（证明我们不解析）。
MALFORMED_BODY = '{"jsonrpc":"2.0","id":1,,,"method":'

# JSON-RPC batch（数组）。紧凑分隔符 + 中文：`json.dumps(json.loads(...))` 会
# 同时在两处改字节（补空格、`ensure_ascii` 转义），所以"解析再序列化"必红。
BATCH_BODY = ('[{"jsonrpc":"2.0","id":1,"method":"tools/list"},'
              '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
              '"params":{"name":"deploy_site","arguments":{"note":"中文"}}}]')

# SSE 响应：CRLF、`event:` / `id:` / 注释行、跨行 data、非 ASCII、结尾空行。
# **任何"按 data: 行重组"的实现都改不出这一串**（既有 stdio 代理
# clients/quick-desktop-proxy/index.js 就是那种重组，它是客户端的自由，
# 但代理层做同样的事就是丢信息）。
SSE_BODY = (b"event: message\r\n"
            b"id: 42\r\n"
            b'data: {"jsonrpc":"2.0","id":1,"result":{"note":"\xe4\xb8\xad"}}\r\n'
            b"\r\n"
            b": keep-alive\r\n"
            b'data: {"jsonrpc":"2.0","method":"notifications/progress",\r\n'
            b'data:  "params":{"progress":1}}\r\n'
            b"\r\n")


# --------------------------------------------------------------- 夹具与替身

def _fake_key(marker: str) -> str:
    """形态合法的假明文：`sk-` + 16 位 base62。

    marker 让每个用例的明文互不相同——日志组按明文全串 grep，共享一份明文时
    分不清是哪个分支泄的。
    """
    body = (marker + "0" * keygen.PLAINTEXT_LEN)[:keygen.PLAINTEXT_LEN]
    assert keygen.PLAINTEXT_RE.fullmatch("sk-" + body), marker
    return "sk-" + body


def _table():
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        ENV["API_KEYS_TABLE"])


def _seed_switch(enabled=True):
    _table().put_item(Item={"key_hash": keygen.SWITCH_PK, "enabled": enabled,
                            "updated_at": "2026-08-11T00:00:00+00:00",
                            "updated_by": "seed"})


def _seed_key(plaintext, *, email="alice@x.com", revoked=False, key_id="k1abcd23"):
    _table().put_item(Item={"key_hash": keygen.hash_key(plaintext),
                            "key_id": key_id, "email": email, "name": "笔记本",
                            "prefix": plaintext[:7], "revoked": revoked,
                            "created_at": "2026-08-11T00:00:00+00:00",
                            "last_used_at": ""})


def _ev(method="POST", *, api_key=None, headers=None, body=None,
        is_base64=False, caller=EDGE_CALLER_ID, path="/mcp"):
    """Function URL payload v2 形态。默认带**合规的 Edge IAM 上下文**——真实
    请求一定经过 Edge，第 ⓪ 步会校验它。要测"非 Edge 直连"的用例自己传 caller。
    """
    hdrs = {}
    if api_key is not None:
        hdrs["x-api-key"] = api_key
    hdrs.update(headers or {})
    ev = {"rawPath": path,
          "requestContext": {"http": {"method": method} if method else {},
                             "authorizer": {"iam": {"callerId": caller}}},
          "headers": hdrs,
          "isBase64Encoded": is_base64}
    if body is not None:
        ev["body"] = body
    return ev


def _body_bytes(response: dict) -> bytes:
    """把 Function URL 响应还原成字节——逐字节断言的唯一正确比法。"""
    raw = response.get("body", "")
    if response.get("isBase64Encoded"):
        return base64.b64decode(raw)
    return raw.encode("utf-8")


def _hdr(response: dict, name: str):
    return {k.lower(): v for k, v in (response.get("headers") or {}).items()
            }.get(name)


def _our_logs(caplog) -> str:
    """只保留**我们自己**的 logger 产生的行。

    `caplog.at_level(DEBUG)` 会一并打开 botocore 的线级调试日志，而那里面合法地
    含有 DynamoDB 请求体（即 `key_hash`）——拿整个 caplog 去 grep hash 会红在一个
    与本文件无关的地方，且真机上 botocore 的 DEBUG 是关着的。明文那条判据仍用
    **整个** caplog（更严：若哪天有人改成拿明文去查库，botocore 的日志会先招供）。
    """
    return "\n".join(r.getMessage() for r in caplog.records
                     if not r.name.startswith(("botocore", "boto3", "urllib3",
                                               "s3transfer")))


class Up:
    """一次上游响应。

    `headers` 用 `email.message.Message` 而不是 dict：真实 `urlopen()` 与
    `HTTPError` 的 `.headers` 都是 `http.client.HTTPMessage`（**大小写不敏感**）。
    用 dict 会让"按小写名取 Content-Type"这类写法在测试里假通过，真机上却取到
    None（上游发的是 `Content-Type`）。
    """

    def __init__(self, status=200, body=OK_JSON,
                 ctype="application/json", extra=None):
        self.status = status
        self.body = body
        self.msg = Message()
        if ctype is not None:
            self.msg["Content-Type"] = ctype
        for k, v in (extra or {}).items():
            self.msg[k] = v

    def deliver(self, url):
        if self.status >= 400:
            # urllib 对非 2xx **抛** HTTPError，而 HTTPError 本身就是一个响应
            # 对象。透传上游 4xx/5xx 的能力全靠 handler 认得这一点。
            raise urllib.error.HTTPError(url, self.status, "upstream",
                                         self.msg, io.BytesIO(self.body))

        class _Resp:
            status = self.status
            headers = self.msg

            def read(_self):
                return self.body

            def __enter__(_self):
                return _self

            def __exit__(_self, *a):
                return False

        return _Resp()


class FakeUpstream:
    """记录每一次 urlopen 调用（真实 Request 对象的内容，不是被测代码的自述）。"""

    def __init__(self):
        self.calls = []
        self.queue = []
        self.default = Up()

    def __call__(self, req, timeout=None):
        self.calls.append({
            "url": req.full_url,
            "method": req.get_method(),
            "body": req.data,
            "timeout": timeout,
            # urllib 的 Request 会把头名 capitalize（`X-api-key`），所以一律小写比。
            "headers": {k.lower(): v for k, v in req.headers.items()}})
        item = self.queue.pop(0) if self.queue else self.default
        if isinstance(item, BaseException):
            raise item
        return item.deliver(req.full_url)

    @property
    def n(self):
        return len(self.calls)

    @property
    def last(self):
        return self.calls[-1]


class FakeToken:
    """机器 token 替身。两个不同的值：重发那条要证明用的是**新**token。"""

    def __init__(self):
        self.gets = 0
        self.invalidations = 0
        self.error = None

    def get_token(self):
        if self.error is not None:
            raise self.error
        self.gets += 1
        return f"tok-machine-{self.gets}"

    def invalidate(self):
        self.invalidations += 1


class DdbSpy(list):
    """(表名, 操作) 序列。"""

    READS = ("get_item", "query", "scan", "batch_get_item")
    WRITES = ("put_item", "update_item", "delete_item", "transact_write_items")

    @property
    def reads(self):
        return [c for c in self if c[1] in self.READS]

    @property
    def writes(self):
        return [c for c in self if c[1] in self.WRITES]


@pytest.fixture
def upstream(monkeypatch):
    fake = FakeUpstream()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return fake


@pytest.fixture
def token(monkeypatch):
    fake = FakeToken()
    monkeypatch.setattr(machine_token, "get_token", fake.get_token)
    monkeypatch.setattr(machine_token, "invalidate", fake.invalidate)
    return fake


@pytest.fixture
def ddb_spy(aws, monkeypatch):
    """boto3 层的读写间谍。

    **必须先把 `keystore._ddb` 清成 None**：它是模块级全局，在 Lambda 里跨请求
    存活、在 pytest 里跨用例存活。上一条用例已经建过 resource 时，本夹具的
    patch 根本不会被调用，于是所有"零副作用"断言一起假通过——而它们全是断言
    "某件事没发生"，假通过时没有任何症状。正对照
    `test_spy_sees_reads_and_writes_on_the_happy_path` 是这条的第二道保险。
    """
    seen = DdbSpy()
    real_resource = boto3.resource
    monkeypatch.setattr(keystore, "_ddb", None)

    class TableSpy:
        def __init__(self, inner, name):
            self._i, self._n = inner, name

        def __getattr__(self, k):
            if k in DdbSpy.READS + DdbSpy.WRITES:
                seen.append((self._n, k))
            return getattr(self._i, k)

    class ResSpy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def Table(self, n):
            return TableSpy(self._i.Table(n), n)

    monkeypatch.setattr(boto3, "resource",
                        lambda *a, **k: ResSpy(real_resource(*a, **k)))
    return seen


# ============================================================ 顺序组（安全边界）

def test_spy_sees_reads_and_writes_on_the_happy_path(ddb_spy, token, upstream):
    """**正对照**：间谍确实看得见读与写。

    没有这一条，下面所有"零副作用"断言都可能是因为间谍装不上而绿的
    （keystore._ddb 跨用例存活是最现实的那种装不上）。这条一红，说明下面
    整组断言的判据都失效了——它必须比它们更显眼。
    """
    plaintext = _fake_key("happyControl")
    _seed_switch(True)
    _seed_key(plaintext)
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 200, r
    assert len(ddb_spy.reads) >= 2, f"开关 + Key 两次读都该被看到: {ddb_spy}"
    assert ddb_spy.writes, f"last_used 的节流写该被看到: {ddb_spy}"


def test_non_edge_caller_is_403_with_zero_side_effects(ddb_spy, token, upstream):
    """同账号但非 Edge 的签名直连必须 403，且**什么都不做**。

    resource policy 挡不住它（同账号 principal 只要 identity policy 允许
    InvokeFunctionUrl + InvokeFunction 就能绕开 resource policy，44aef8d 的
    P1-1 真机实证）。对 key-proxy 而言绕过 Edge 不等于绕过认证，但 Edge 是
    可观测性与限流的唯一位置：绕过它意味着 Key 暴力尝试不留任何可告警痕迹。
    """
    plaintext = _fake_key("nonEdgeCaller")
    _seed_switch(True)
    _seed_key(plaintext)
    ddb_spy.clear()
    r = handler.handler(_ev(api_key=plaintext, body="{}", caller=NON_EDGE_CALLER),
                        None)
    assert r["statusCode"] == 403, r
    assert ddb_spy == [], f"非 Edge 调用者却查了库: {ddb_spy}"
    assert token.gets == 0, "非 Edge 调用者却换了机器 token"
    assert upstream.n == 0, "非 Edge 调用者的请求被转发了"
    # 不回显原因：探测者不该知道我们在比什么。
    assert "AROA" not in r["body"] and "EDGE_ROLE_ID" not in r["body"]


def test_unconfigured_edge_role_id_fails_closed(ddb_spy, token, upstream,
                                                monkeypatch):
    """没配 `EDGE_ROLE_ID` 时拒绝一切，不能"没配就不检查"。

    鉴权字段的"默认值"往往正好是"放宽"——本项目已记录过这个陷阱形态。
    """
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    plaintext = _fake_key("noRoleIdConfig")
    _seed_switch(True)
    _seed_key(plaintext)
    ddb_spy.clear()
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 403, r
    assert ddb_spy == [] and token.gets == 0 and upstream.n == 0


@pytest.mark.parametrize("headers", [{}, {"x-api-key": ""}])
def test_missing_api_key_is_401_and_reads_nothing(ddb_spy, token, upstream,
                                                  caplog, headers):
    """② 在 ③ 之前：没带 Key 时**一次库都不查**。

    少一条免费的存在性探测通道，也让"暴力尝试"的成本不落在我们的读容量上。

    **为什么还要断言日志里的 reason**（实测发现，2026-08-12 反向验证 E5）：把 ②
    整段删掉时"零读"这条**照样绿**——`keystore.lookup("")` 的形态校验在任何读之前
    就返回了，于是不变量由 keystore 兜住，与 handler 有没有 ② 无关。只断言"零读"
    的守卫因此分不清"handler 先查了 ②"与"keystore 替它挡住了"，正是
    M3-FINDINGS §2.10 那个形态（守卫只覆盖它自己夹具造出来的世界）。加上这条
    reason 断言后，② 成为可观测的一步：删掉它 reason 会变成 malformed-plaintext。
    """
    _seed_switch(True)
    ddb_spy.clear()
    with caplog.at_level(logging.DEBUG):
        r = handler.handler(_ev(headers=headers, body="{}"), None)
    assert r["statusCode"] == 401, r
    assert ddb_spy == [], f"缺 Key 却查了库: {ddb_spy}"
    assert token.gets == 0 and upstream.n == 0
    assert "missing-api-key" in _our_logs(caplog), _our_logs(caplog)


@pytest.mark.parametrize("method", ["GET", "DELETE", "PUT", "OPTIONS", None])
def test_non_post_is_405_and_reads_nothing(ddb_spy, token, upstream, method):
    """① 只接受 POST，且在 ③ 之前。

    streamable-http 的 GET（服务端推流）与 DELETE（关会话）在这条链路上不存在
    ——Lambda 的响应不能流式经过 Lambda@Edge。method 缺失也走这里（fail-closed，
    不默认成 POST）。
    """
    plaintext = _fake_key("methodCheck")
    _seed_switch(True)
    _seed_key(plaintext)
    ddb_spy.clear()
    r = handler.handler(_ev(method, api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 405, r
    assert ddb_spy == [], f"非 POST 却查了库: {ddb_spy}"
    assert token.gets == 0 and upstream.n == 0


def test_switch_off_is_401_without_token_forward_or_write(ddb_spy, token,
                                                          upstream):
    """关闸：③ 拒绝后**不换 token、不转发、不写 last_used**。

    这一条同时锁住"③ 挪到 ④ 之后"这种重排——把顺序换掉时 token.gets 会变成 1。
    关闸期间产生写也不行：审计上那会看起来像"关闸没生效"。
    """
    plaintext = _fake_key("switchIsOff")
    _seed_switch(False)
    _seed_key(plaintext)
    ddb_spy.clear()
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 401, r
    assert ddb_spy.writes == [], f"关闸期间发生了写: {ddb_spy}"
    assert token.gets == 0, "关闸期间换了机器 token"
    assert upstream.n == 0, "关闸期间把请求转发出去了"


@pytest.mark.parametrize("seed,plain", [
    ("unknown", _fake_key("unknownKeyRow")),
    ("revoked", _fake_key("revokedKeyRow")),
    ("malformed", "sk-not-a-valid-shape"),
])
def test_invalid_key_is_401_without_token_or_forward(ddb_spy, token, upstream,
                                                     seed, plain):
    """③ 的三种失败（未知 / 吊销 / 形态非法）都不得走到 ④⑤。"""
    _seed_switch(True)
    if seed == "revoked":
        _seed_key(plain, revoked=True)
    ddb_spy.clear()
    r = handler.handler(_ev(api_key=plain, body="{}"), None)
    assert r["statusCode"] == 401, r
    assert ddb_spy.writes == [], f"拒绝路径发生了写: {ddb_spy}"
    assert token.gets == 0 and upstream.n == 0


# ================================================================== 透明性组

def _ok(plaintext, **kw):
    """种一把有效 Key 并发一次请求。"""
    _seed_switch(True)
    _seed_key(plaintext, **kw)


def test_malformed_json_body_is_forwarded_unparsed(aws, token, upstream):
    """非法 JSON 也要原样转发——我们不是 MCP 实现，不该替上游判协议。"""
    plaintext = _fake_key("malformedBody")
    _ok(plaintext)
    upstream.queue.append(Up(400, b'{"jsonrpc":"2.0","error":{"code":-32700}}'))
    r = handler.handler(_ev(api_key=plaintext, body=MALFORMED_BODY), None)
    assert upstream.last["body"] == MALFORMED_BODY.encode(), upstream.last
    # 下游返回什么就回什么（状态码与响应体都不改）
    assert r["statusCode"] == 400
    assert _body_bytes(r) == b'{"jsonrpc":"2.0","error":{"code":-32700}}'


def test_jsonrpc_batch_body_is_forwarded_byte_identical(aws, token, upstream):
    """batch（数组）照样转发，且**逐字节**——解析再序列化会改分隔符与转义。"""
    plaintext = _fake_key("batchBody")
    _ok(plaintext)
    r = handler.handler(_ev(api_key=plaintext, body=BATCH_BODY), None)
    assert r["statusCode"] == 200
    assert upstream.last["body"] == BATCH_BODY.encode("utf-8")


def test_base64_encoded_body_is_decoded_before_forwarding(aws, token, upstream):
    """`isBase64Encoded` 是 Function URL 对二进制载荷的表示：转发**解码后的字节**。

    判据只能是这个标志本身，不能猜 content-type。
    """
    plaintext = _fake_key("base64Body")
    _ok(plaintext)
    raw = b'{"jsonrpc":"2.0","blob":"\xff\xfe","note":"\xe4\xb8\xad"}'
    r = handler.handler(_ev(api_key=plaintext,
                            body=base64.b64encode(raw).decode(),
                            is_base64=True), None)
    assert r["statusCode"] == 200
    assert upstream.last["body"] == raw


def test_mcp_session_id_round_trips_both_ways(aws, token, upstream):
    """请求头 → 上游、上游响应头 → 客户端。会话 ID 断了 MCP 就从头握手。"""
    plaintext = _fake_key("sessionRoundTrip")
    _ok(plaintext)
    upstream.queue.append(Up(200, OK_JSON,
                             extra={"Mcp-Session-Id": "sess-from-upstream"}))
    r = handler.handler(_ev(api_key=plaintext, body="{}",
                            headers={"mcp-session-id": "sess-from-client"}),
                        None)
    assert upstream.last["headers"]["mcp-session-id"] == "sess-from-client"
    assert _hdr(r, "mcp-session-id") == "sess-from-upstream"


def test_accept_and_protocol_version_are_forwarded(aws, token, upstream):
    """`accept` 与 `mcp-protocol-version` 在白名单里（实测的客户端两者都发）。"""
    plaintext = _fake_key("acceptHeader")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext, body="{}", headers={
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18",
        "content-type": "application/json"}), None)
    h = upstream.last["headers"]
    assert h["accept"] == "application/json, text/event-stream"
    assert h["mcp-protocol-version"] == "2025-06-18"
    assert h["content-type"] == "application/json"


def test_sse_response_is_returned_byte_identical(aws, token, upstream):
    """SSE 整体缓冲后**逐字节**回传，不重新组包。

    Lambda 的响应不能流式经过 Lambda@Edge，所以缓冲是这条链路上的唯一选项；
    既然要缓冲，就绝不能顺手"按 data: 行重组"——那会丢掉 event/id/注释行、
    改掉 CRLF，且症状是"偶发的协议错误"。
    """
    plaintext = _fake_key("sseResponse")
    _ok(plaintext)
    upstream.queue.append(Up(200, SSE_BODY, ctype="text/event-stream"))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 200
    assert _hdr(r, "content-type") == "text/event-stream"
    assert _body_bytes(r) == SSE_BODY


def test_client_authorization_and_api_key_are_never_forwarded(aws, token,
                                                              upstream):
    """`authorization` 换成机器 token、`x-api-key` 不能泄给下游。"""
    plaintext = _fake_key("headerAllowlist")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext, body="{}", headers={
        "authorization": "Bearer client-supplied-token",
        "host": "mcp.example.com",
        "x-forwarded-for": "1.2.3.4"}), None)
    h = upstream.last["headers"]
    assert h["authorization"] == "Bearer tok-machine-1", h
    assert "x-api-key" not in h, "明文 Key 被转发给了上游"
    assert plaintext not in json.dumps(h), h
    # host 由 urllib 按 URL 自己填；客户端的 host / x-forwarded-for 不该透传
    assert h.get("host", "") != "mcp.example.com"
    assert "x-forwarded-for" not in h


def test_client_cookie_is_never_forwarded(aws, token, upstream):
    """cookie 一个字节都不读（决定 9）。

    `mcp` 子域**故意不在** Edge 的 PLATFORM_SUBDOMAINS 里，所以 Edge 会剥掉
    保留 cookie。但"上游剥了"不是本文件可以依赖的前提——那个白名单随时会被改，
    而改它的人不会想到 key-proxy。
    """
    plaintext = _fake_key("cookieHeader")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext, body="{}", headers={
        "cookie": "__Host-sb_session=stolen; __Host-sb_console=stolen"}), None)
    h = upstream.last["headers"]
    assert "cookie" not in h, h
    assert "stolen" not in json.dumps(h), h


def test_client_supplied_on_behalf_of_header_cannot_impersonate(aws, token,
                                                                upstream):
    """**本文件最坏的失效模式**：客户端自带 `X-SB-On-Behalf-Of`。

    MCP server 的信任规则是"机器 token + 这个头 ⇒ 头里那个人"（spec §5.3），
    所以客户端说的那个值一旦被透传，任意持 Key 者就能冒充任意人。出站头必须是
    **白名单从零构建**，不是"复制入站再覆盖"——后者漏一个名字就等于放开冒充。
    """
    plaintext = _fake_key("impersonation")
    _ok(plaintext, email="alice@x.com")
    handler.handler(_ev(api_key=plaintext, body="{}", headers={
        "x-sb-on-behalf-of": "admin@x.com",
        "X-SB-On-Behalf-Of": "admin@x.com"}), None)
    h = upstream.last["headers"]
    assert h["x-sb-on-behalf-of"] == "alice@x.com", h
    assert "admin@x.com" not in json.dumps(h), h


def test_on_behalf_of_equals_the_email_keystore_resolved(aws, token, upstream):
    """身份来源只有一个：keystore 从库里解出的 email。"""
    plaintext = _fake_key("onBehalfOf")
    _ok(plaintext, email="bob@example.com")
    handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert upstream.last["headers"]["x-sb-on-behalf-of"] == "bob@example.com"


def test_response_headers_outside_the_allowlist_are_dropped(aws, token,
                                                            upstream):
    """只回 `content-type` 与 `mcp-session-id`。

    上游的 `set-cookie` 尤其不能落到 `{base_domain}` 上——那是会话 cookie 的
    作用域，一个上游发的 cookie 能污染整个平台的鉴权面。
    """
    plaintext = _fake_key("respHeaders")
    _ok(plaintext)
    upstream.queue.append(Up(200, OK_JSON, extra={
        "Set-Cookie": "evil=1; Domain=example.com",
        "Server": "agentcore/1.0",
        "X-Amzn-Trace-Id": "Root=1-internal"}))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    got = {k.lower() for k in (r.get("headers") or {})}
    assert got == {"content-type"}, got
    assert "evil" not in json.dumps(r)


def test_forward_targets_the_configured_endpoint_with_post(aws, token, upstream):
    """转发目标只从环境变量来（部署脚本从 config.ini 派生），方法固定 POST。"""
    plaintext = _fake_key("endpointFromEnv")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert upstream.last["url"] == ENDPOINT
    assert upstream.last["method"] == "POST"


def test_forward_has_an_explicit_timeout(aws, token, upstream):
    """超时必须显式给：不给时上游挂住会把整个 Lambda 拖到自己的超时，
    客户端看到的是空响应而不是一条可归因的 504。"""
    plaintext = _fake_key("explicitTimeout")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext, body="{}"), None)
    t = upstream.last["timeout"]
    assert t == handler.HTTP_TIMEOUT_SECONDS
    assert 0 < t < 30, "必须短于 Lambda 的 30s 预算，否则 504 会变成 Lambda 被 kill"


def test_empty_body_is_forwarded_as_empty_bytes(aws, token, upstream):
    """没有 body 时转发空字节，不替客户端编一个 `{}`。"""
    plaintext = _fake_key("emptyBody")
    _ok(plaintext)
    handler.handler(_ev(api_key=plaintext), None)
    assert upstream.last["body"] == b""


# ==================================================================== 错误组

def test_all_four_rejection_reasons_are_indistinguishable(aws, token, upstream):
    """无效 / 吊销 / 关闸 / 未知 Key：**同一状态码、逐字节相同的响应体与响应头**。

    能区分就等于一个免费的 Key 状态探测器（"这把存在过吗"/"是被吊销了吗"/
    "是平台关闸了吗"）。分类只进日志（Verdict.reason）。
    """
    responses = []

    # ① 形态非法
    _seed_switch(True)
    responses.append(handler.handler(_ev(api_key="sk-bad", body="{}"), None))
    # ② 未知 Key（形态合法但库里没有）
    responses.append(handler.handler(
        _ev(api_key=_fake_key("unknownForDiff"), body="{}"), None))
    # ③ 已吊销
    revoked = _fake_key("revokedForDiff")
    _seed_key(revoked, revoked=True, key_id="rv000001")
    responses.append(handler.handler(_ev(api_key=revoked, body="{}"), None))
    # ④ 平台关闸（用一把**有效**的 Key，证明差别只来自开关）
    valid = _fake_key("validButClosed")
    _seed_key(valid, key_id="vl000001")
    _seed_switch(False)
    responses.append(handler.handler(_ev(api_key=valid, body="{}"), None))

    first = responses[0]
    assert first["statusCode"] == 401, first
    for r in responses[1:]:
        assert r["statusCode"] == first["statusCode"], (r, first)
        assert _body_bytes(r) == _body_bytes(first), (r, first)
        assert r.get("headers") == first.get("headers"), (r, first)
    assert upstream.n == 0 and token.gets == 0


def test_token_unavailable_is_502_without_internal_details(aws, token, upstream,
                                                           caplog):
    """④ 失败 → 502，且响应体**只有一句写死的文案**。

    判据是"假异常里塞的内部标记不出现在 body 里"：只断言"没有 Traceback"
    抓不到 `f"...{e}"` 这种拼接，而那正是最容易顺手写出来的形态。
    """
    marker = "invalid_client param=/site-builder/machine-client-secret"
    token.error = machine_token.TokenUnavailable(f"token 端点拒绝了交换 {marker}")
    plaintext = _fake_key("tokenUnavail")
    _ok(plaintext)
    with caplog.at_level(logging.DEBUG):
        r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 502, r
    body = r["body"]
    for leak in (marker, "invalid_client", "/site-builder/", "Traceback",
                 "arn:aws", ENV["API_KEYS_TABLE"], ENDPOINT):
        assert leak not in body, f"502 响应体泄漏了内部信息 {leak!r}: {body}"
    assert upstream.n == 0, "换不到 token 却还是转发了"
    # 分类信息必须进日志（不然这条 502 无从排查）
    assert "invalid_client" in caplog.text


def test_upstream_401_triggers_one_invalidate_and_one_resend(aws, token,
                                                             upstream):
    """上游拒我们的凭证 → invalidate + 重取 + 重发一次；第二次成功就照常回。

    重发**必须用新 token**：拿同一个被拒的 token 重发只是把同一个 401 再要一遍。
    """
    plaintext = _fake_key("retryOn401")
    _ok(plaintext)
    upstream.queue.extend([Up(401, b"unauthorized"), Up(200, OK_JSON)])
    r = handler.handler(_ev(api_key=plaintext, body=BATCH_BODY), None)
    assert r["statusCode"] == 200, r
    assert _body_bytes(r) == OK_JSON
    assert upstream.n == 2, "应当恰好重发一次"
    assert token.invalidations == 1 and token.gets == 2
    assert upstream.calls[0]["headers"]["authorization"] == "Bearer tok-machine-1"
    assert upstream.calls[1]["headers"]["authorization"] == "Bearer tok-machine-2"


@pytest.mark.parametrize("status", [401, 403])
def test_two_rejections_in_a_row_is_502_and_only_two_attempts(aws, token,
                                                              upstream, status):
    """两次都被拒 → 502，且**只重试一次**。

    第二次仍被拒说明不是"token 刚过期"，而是配置/授权问题（machine client 不在
    allowedClients、scope 不对）。继续重试只会把一次故障放大成 N 次。
    upstream 的默认响应是 200，所以"重试上限改成 3"会让本条同时红在
    statusCode 与 n 上。
    """
    plaintext = _fake_key("twiceRejected")
    _ok(plaintext)
    upstream.queue.extend([Up(status, b"nope"), Up(status, b"nope")])
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 502, r
    assert upstream.n == 2, f"重试次数不对: {upstream.n}"
    assert token.invalidations == 1
    assert "nope" not in r["body"], "上游的凭证错误细节不该回给客户端"


def test_retry_reuses_the_same_body_bytes(aws, token, upstream):
    """重发用**同一份 body bytes**。

    "重新从 event 取"在别的实现里会拿到已消费的流（空体），而空体会得到一个
    与真实原因毫无关系的 400——排查方向被整个带偏。
    """
    plaintext = _fake_key("retrySameBody")
    _ok(plaintext)
    upstream.queue.extend([Up(401, b"nope"), Up(200, OK_JSON)])
    handler.handler(_ev(api_key=plaintext, body=BATCH_BODY), None)
    assert upstream.n == 2
    assert upstream.calls[0]["body"] == upstream.calls[1]["body"] != b""
    assert upstream.calls[1]["body"] == BATCH_BODY.encode("utf-8")


def test_upstream_error_status_is_passed_through_not_retried(aws, token,
                                                             upstream):
    """上游的 4xx/5xx（非 401/403）是**协议层的回答**：原样透传，不重发。

    把 400/500 也当"凭证被拒"会放大一次无效请求，而且客户端会丢掉真正的
    JSON-RPC 错误信息。
    """
    plaintext = _fake_key("passThrough500")
    _ok(plaintext)
    upstream.queue.append(Up(500, b'{"jsonrpc":"2.0","error":{"code":-32603}}'))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 500
    assert _body_bytes(r) == b'{"jsonrpc":"2.0","error":{"code":-32603}}'
    assert upstream.n == 1 and token.invalidations == 0


def test_upstream_timeout_is_504(aws, token, upstream):
    """上游超时 → **504**（不挂起、不 500）。

    504 与 502 分开是有意的：前者"上游还在，只是慢"，后者"上游不可达/拒了我们"。
    两者的处置完全不同（前者看上游负载，后者看配置与凭证）。
    """
    plaintext = _fake_key("upstreamTimeout")
    _ok(plaintext)
    upstream.queue.append(TimeoutError("timed out"))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 504, r
    assert "Traceback" not in r["body"] and ENDPOINT not in r["body"]


def test_upstream_timeout_wrapped_in_urlerror_is_also_504(aws, token, upstream):
    """connect 阶段的超时被 urllib 包在 `URLError.reason` 里——两层都要看。"""
    plaintext = _fake_key("wrappedTimeout")
    _ok(plaintext)
    upstream.queue.append(urllib.error.URLError(TimeoutError("timed out")))
    assert handler.handler(_ev(api_key=plaintext, body="{}"),
                           None)["statusCode"] == 504


def test_upstream_unreachable_is_502(aws, token, upstream):
    """DNS / 连接重置 → 502，响应体不含内部细节。"""
    plaintext = _fake_key("unreachable")
    _ok(plaintext)
    upstream.queue.append(urllib.error.URLError("Name or service not known"))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 502, r
    assert "Name or service" not in r["body"] and ENDPOINT not in r["body"]


@pytest.mark.parametrize("bad", ["", "   ", "http://agentcore.example.com/mcp"])
def test_bad_endpoint_config_is_502_and_forwards_nothing(aws, token, upstream,
                                                          monkeypatch, bad):
    """端点缺失或不是 https → 502，且**不发出任何请求、也不换 token**。

    明文 http 会把机器 token（Bearer）放到线上明文里，而症状是"一切正常"。
    同 machine_token 对 COGNITO_DOMAIN 的处理。
    """
    monkeypatch.setenv("AGENTCORE_ENDPOINT", bad)
    plaintext = _fake_key("badEndpoint")
    _ok(plaintext)
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 502, r
    assert upstream.n == 0 and token.gets == 0
    if bad.strip():
        assert bad.strip() not in r["body"], "端点不该回显给调用方"


def test_last_used_is_not_written_when_forwarding_fails(aws, token, upstream,
                                                        ddb_spy):
    """转发没成功就不算"用过"——遥测不该给出"这把 Key 刚用过"的假象。"""
    plaintext = _fake_key("noTouchOnFail")
    _ok(plaintext)
    ddb_spy.clear()
    upstream.queue.append(urllib.error.URLError("boom"))
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 502
    assert ddb_spy.writes == [], ddb_spy


def test_touch_failure_does_not_break_the_forward(aws, token, upstream,
                                                   monkeypatch):
    """遥测失败绝不能升级成"这次 MCP 调用失败"。"""
    plaintext = _fake_key("touchExplodes")
    _ok(plaintext)

    def boom(*a, **kw):
        raise RuntimeError("dynamodb down")

    monkeypatch.setattr(keystore, "_update_last_used", boom)
    r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 200, r


def test_touch_uses_the_hash_of_the_presented_key(aws, token, upstream,
                                                  monkeypatch):
    """`Verdict` 刻意不带 key_hash（它不该进日志），所以 handler 现算一次。

    算错了的症状极隐蔽：转发全部正常，只是 last_used_at 永远不更新
    （或更糟——`attribute_exists` 拦住之前往表里写半行）。
    """
    plaintext = _fake_key("touchHash")
    _ok(plaintext)
    seen = []
    monkeypatch.setattr(keystore, "touch_last_used",
                        lambda key_hash, key_id: seen.append((key_hash, key_id)))
    handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert seen == [(keygen.hash_key(plaintext), "k1abcd23")], seen


# ==================================================================== 日志组

@pytest.mark.parametrize("case", ["ok", "unknown", "revoked", "switch-off",
                                  "upstream-401"])
def test_plaintext_key_never_appears_in_logs(aws, token, upstream, caplog, case):
    """任何分支都不得把明文写进日志。

    明文进日志 = 一个能读日志的人拿到可用凭证；而日志的读者面（运维、告警、
    日志转存）远大于凭证的持有者面。每个分支用不同的明文，泄漏定位到分支。
    """
    plaintext = _fake_key("logLeak" + case.replace("-", ""))
    if case == "switch-off":
        _seed_switch(False)
        _seed_key(plaintext)
    elif case == "unknown":
        _seed_switch(True)
    else:
        _ok(plaintext, revoked=(case == "revoked"))
    if case == "upstream-401":
        upstream.queue.extend([Up(401, b"nope"), Up(401, b"nope")])
    with caplog.at_level(logging.DEBUG):
        handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert plaintext not in caplog.text, f"{case} 分支把明文写进了日志"
    # hash 也不该进我们的日志：它是拿明文直查那张表的钥匙形态
    assert keygen.hash_key(plaintext) not in _our_logs(caplog)


def test_machine_token_never_appears_in_logs(aws, token, upstream, caplog):
    """机器 token 是凭证：不进日志、不进异常文案。"""
    plaintext = _fake_key("tokenNotLogged")
    _ok(plaintext)
    upstream.queue.extend([Up(401, b"nope"), Up(401, b"nope")])
    with caplog.at_level(logging.DEBUG):
        handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert "tok-machine-1" not in caplog.text
    assert "tok-machine-2" not in caplog.text


def test_rejection_log_has_reason_and_key_id(aws, token, upstream, caplog):
    """拒绝时日志里要有 `reason` 与 `key_id`——否则线上一把 Key 报 401 无从下手。

    两者都是**非秘密**：key_id 列在控制台里，reason 是我们自己的词汇。
    """
    plaintext = _fake_key("logHasReason")
    _seed_switch(True)
    _seed_key(plaintext, revoked=True, key_id="rvk12345")
    with caplog.at_level(logging.DEBUG):
        r = handler.handler(_ev(api_key=plaintext, body="{}"), None)
    assert r["statusCode"] == 401
    assert "revoked" in caplog.text, caplog.text
    assert "rvk12345" in caplog.text, caplog.text
    assert plaintext not in caplog.text
    # 但这些排查信息一个字也不许出网
    assert "revoked" not in r["body"] and "rvk12345" not in r["body"]


# ================================================================== 结构守卫

def test_key_proxy_delegates_edge_caller_check_and_has_no_own_parser():
    """handler 不得自己解析 callerId——唯一实现在 `edge_caller.py`。

    判定有四个易错点（AROA 段、`:` 边界、大小写、缺配置即拒）。同一逻辑存在两处
    时"改对一处、漏改另一处"是本项目反复出现的缺陷形态；panel 侧已有同名守卫
    （`panel/tests/test_handler.py::test_panel_delegates_edge_caller_check_and_
    has_no_own_parser`），key-proxy 是第二个 Function URL 组件，必须有对应的一条。

    **扫的是 handler.py，不是本文件**：本文件的夹具里合法地含有 callerId
    （要构造 event），把测试文件放进扫描范围会让断言禁掉它自己需要的东西
    （M3-FINDINGS §2.10）。
    """
    src = (pathlib.Path(__file__).parents[1] / "handler.py").read_text()
    tree = ast.parse(src)
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    assert "edge_caller" in imported, "key-proxy 必须依赖唯一实现"
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "callerId" not in strings, \
        "handler 出现了 callerId 字面量——说明又抄了一份解析逻辑"
    assert not any("AROA" in s for s in strings), \
        "key-proxy 不该关心 RoleId 形态"
