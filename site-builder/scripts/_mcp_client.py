#!/usr/bin/env python3
"""MCP over streamable-http 的**唯一**客户端实现，三个真机闸门共用。

  · `verify_api_key_e2e.py`（M4）——静态 Header 打 `mcp.{base_domain}`；
  · `verify_oauth_and_impersonation.py`（M4 N1）——真实用户 OAuth token；
  · `verify_analytics_e2e.py`（M5）——真实用户 OAuth token 读访问统计。

**为什么必须是一份**：本文件的内容原来分散在前两个闸门里（`Mcp`/`http`/
`sse_json` 在 verify_api_key_e2e，token 获取在 verify_oauth_and_impersonation，
后者还得用 `importlib` 按路径去加载前者才能拿到 `Mcp`）。第三个闸门要用同样的
东西，抄第三份的结果是"三个脚本走的其实不是同一个协议路径"——而那正是负测最
不能有的性质（本项目已因"手抄第二份"栽过多次，见 origin_request._route_kind 的
docstring）。

**不是包**：`scripts/` 下没有 `__init__.py`，所以调用方靠"脚本自己的目录在
sys.path[0]"来 import 它。被当模块 import（而不是直接跑）的调用方要自己
`sys.path.insert(0, <scripts 目录>)`。

**token 一个字节都不打印**（连前缀都不打）——见 `load_user_token`。
"""
import configparser
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CFG_PATH = HERE.parent / "config.ini"
TOKEN_PATH = Path.home() / ".site-builder-deploy-token.json"

_CFG: configparser.ConfigParser | None = None


def _cfg_value(section: str, key: str) -> str:
    """config.ini 取值。**读空当场炸**，不返回空串。

    `ConfigParser.read()` 对不存在的路径是静默的，之后任何取值都会给出一个
    看起来言之有理的错误结论（本项目 2026-08-13 因 cwd 漂移发过一次假警报）。
    """
    global _CFG
    if _CFG is None:
        c = configparser.ConfigParser(interpolation=None)
        c.read(CFG_PATH)
        if not c.sections():
            sys.exit(f"{CFG_PATH} 读不到任何段——请从仓库根用绝对路径跑")
        _CFG = c
    try:
        return _CFG[section][key].split("#")[0].split(";")[0].strip()
    except KeyError:
        sys.exit(f"config.ini 缺 [{section}] {key}")


def mcp_endpoint() -> str:
    """AgentCore runtime 的 MCP endpoint（`[MCP] endpoint_url`）。"""
    return _cfg_value("MCP", "endpoint_url")


def http(method: str, url: str, *, headers=None, body=None, raw: bytes | None = None,
         timeout: int = 60) -> tuple[int, dict, str]:
    """→ (status, headers, text)。**不跟随重定向**（302 本身可能是断言对象）。"""
    data = raw if raw is not None else (
        json.dumps(body).encode() if body is not None else None)
    h = dict(headers or {})
    if body is not None:
        h.setdefault("content-type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=h)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


def sse_json(text: str) -> dict:
    """streamable-http 的响应体是 SSE（`event: message` + `data: {...}`）。

    只取 `data:` 行拼起来解析。**不按行重组语义**——我们只是要那一个 JSON-RPC
    响应，而 FastMCP 每个响应就是一个 data 块。
    """
    payload = "".join(ln[len("data:"):].strip()
                      for ln in text.splitlines() if ln.startswith("data:"))
    if not payload:
        # 非 SSE（例如我们自己的 401/502 JSON）时按普通 JSON 解
        payload = text
    try:
        return json.loads(payload)
    except ValueError:
        return {}


def claims(access_token: str) -> dict:
    """access token 的 claims（**只解 payload，不验签**）。

    不验签是有意的：这里不是授权判定，只是要读出 `email` 好知道"应该解析成谁"。
    真正的验签在网关（`customJWTAuthorizer`）——如果 token 是伪造的，下面每一次
    调用都会 401，而不是靠这里挡。
    """
    import base64
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def load_user_token(client_id: str = "") -> str:
    """有效的用户 access token。过期就用 refresh_token 续；续不动则明确要求人登录。

    **续到的新 token 写回文件**（与 proxy 同一个落点、同一份格式）：不写回的话
    下一次跑本脚本又要续一次，而 refresh 每次都会让 Cognito 轮转 refresh token，
    白丢一次可用期。

    `client_id` 省略时取 `[Cognito] mcp_client_id`——refresh 必须用**同一个**
    public client，换一个会被 Cognito 拒。
    """
    client_id = client_id or _cfg_value("Cognito", "mcp_client_id")
    if not TOKEN_PATH.exists():
        sys.exit(f"没有 {TOKEN_PATH} —— 先在浏览器里登录一次：\n"
                 f"  node {ROOT}/site-builder/clients/quick-desktop-proxy/auth.js "
                 f'"<endpoint_url>" "<mcp_client_id>"')
    data = json.loads(TOKEN_PATH.read_text())
    token = data.get("access_token") or ""
    # **余量必须覆盖整场跑完的时间，不是"还没过期就行"。**
    # access token 只有 15 分钟（M1 收紧的边界）。第一版留 60s，结果注入验证那
    # 一跑真的踩到了：① 段拿到 12 个站点后，token 在中途过期，后面几条全变成
    # HTTP 401，而错误文案是"身份被头改写了"——**一条假的安全告警**，比不报还糟。
    # 本脚本会连发 ~8 次 MCP 调用，300s 余量足够，且离 15 分钟上限还很远。
    if token and claims(token).get("exp", 0) - time.time() > 300:
        return token

    refresh = data.get("refresh_token")
    endpoint = data.get("token_endpoint")
    if not (refresh and endpoint):
        sys.exit("access token 已过期且没有 refresh_token —— 请重新登录（见 --help）")
    body = urllib.parse.urlencode({"grant_type": "refresh_token",
                                   "client_id": client_id,
                                   "refresh_token": refresh}).encode()
    st, _, text = http("POST", endpoint, raw=body,
                       headers={"content-type": "application/x-www-form-urlencoded"})
    if st != 200:
        # 二期把 refresh TTL 收到 1 天（M1 的边界决定），所以"几天没用就要重登"
        # 是**预期行为**，不是故障。文案必须说清，否则会被当成缺陷去查。
        err = ""
        try:
            err = json.loads(text).get("error", "")
        except ValueError:
            err = text[:80]
        sys.exit(f"refresh 失败（HTTP {st} {err}）——二期把 refresh 有效期收紧到 "
                 "1 天，超过就必须重新登录。请在浏览器里跑一次：\n"
                 f"  node {ROOT}/site-builder/clients/quick-desktop-proxy/auth.js "
                 f'"<endpoint_url>" "<mcp_client_id>"')
    fresh = json.loads(text)
    data["access_token"] = fresh["access_token"]
    data["expires_at"] = int(time.time()) + int(fresh.get("expires_in", 900))
    if fresh.get("refresh_token"):
        data["refresh_token"] = fresh["refresh_token"]
    TOKEN_PATH.write_text(json.dumps(data, indent=2))
    print("  （access token 已用 refresh_token 自动续期并写回）")
    return data["access_token"]


class Mcp:
    """一个 MCP streamable-http 会话。**认证方式由 `headers` 决定**：

    · 场景 ①-⑥ 走 `X-API-Key` 打到 `mcp.{base_domain}`（即真实客户端的形态）；
    · N2 走 `Authorization: Bearer {机器 token}` 直连 AgentCore（绕过 key-proxy）；
    · M4 的 N1 与 M5 的统计闸门走 `Authorization: Bearer {用户 OAuth token}`。

    三者的协议部分完全一样，所以共用这个类——分成多份实现就会出现"负测走的其实
    不是同一个协议路径"。

    `client_name` 只进 initialize 的 `clientInfo`（服务端仅用于日志），默认值
    保持提取前的取值不变。
    """

    def __init__(self, url: str, auth: dict, client_name: str = "verify-api-key-e2e"):
        self.url = url
        self.auth = dict(auth)
        self.client_name = client_name
        self.session_id = ""
        self._id = 0

    def _post(self, payload: dict) -> tuple[int, dict, str]:
        h = dict(self.auth)
        h["accept"] = "application/json, text/event-stream"
        if self.session_id:
            h["mcp-session-id"] = self.session_id
        return http("POST", self.url, headers=h, body=payload, timeout=120)

    def initialize(self) -> tuple[int, dict]:
        self._id += 1
        st, hd, text = self._post({
            "jsonrpc": "2.0", "id": self._id, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": self.client_name,
                                      "version": "1"}}})
        for k, v in hd.items():
            if k.lower() == "mcp-session-id":
                self.session_id = v
        if st == 200:
            # 协议要求：initialize 之后发一条 initialized 通知，否则后续请求
            # 会被服务端按"未完成握手"拒掉。
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return st, sse_json(text)

    def rpc(self, method: str, params: dict | None = None) -> tuple[int, dict]:
        self._id += 1
        st, _, text = self._post({"jsonrpc": "2.0", "id": self._id,
                                  "method": method, "params": params or {}})
        return st, sse_json(text)

    def raw_body(self, payload: dict) -> tuple[int, str]:
        """不解析、原样返回响应体——⑥ 的逐字节比对要的就是原始 bytes 语义。"""
        st, _, text = self._post(payload)
        return st, text

    def call_tool(self, name: str, args: dict | None = None, *,
                  expect: str = "dict"):
        """→ (ok, payload_or_error_text)。`expect` 是 `"dict"` 或 `"list"`。

        工具抛异常时 `result.isError` 为真、文案在 content 里；成功时结果可能在
        `result.structuredContent`，**也可能只有 content 文本块**。

        **为什么必须由调用方声明 `expect`，不能自动猜**（2026-08-13 实测）：
        线上这台 MCP server **根本不发 `structuredContent`**，而返回列表的工具
        （`list_my_sites`）会被序列化成**每个元素一个 text 块**——实测 12 个站点
        = 12 个块。于是"取 content[0] 解析"这种写法会**静默只返回第一个元素**，
        断言看起来在比对却少了 11 条数据。反过来，"有多个块就当列表"也不行：
        只有一个站点时列表会退化成 1 个块，与"返回单个 dict 的工具"在形态上
        完全一样。两种猜法各有一半的情况是错的，而错的那一半**不报错、只是
        数据少了**——所以这里改成调用方声明期望形态，不猜。
        """
        st, resp = self.rpc("tools/call", {"name": name,
                                           "arguments": args or {}})
        if st != 200:
            return False, f"HTTP {st}"
        result = resp.get("result") or {}
        texts = [c.get("text", "") for c in result.get("content", [])
                 if isinstance(c, dict)]
        if result.get("isError"):
            return False, " ".join(texts) or json.dumps(resp)[:200]
        if expect not in ("dict", "list"):
            raise ValueError(f"expect 只能是 dict / list，收到 {expect!r}")
        if "structuredContent" in result:
            # 别的 FastMCP 版本会发它。**非 dict** 返回值被裹成 `{"result": ...}`；
            # 判据是"只有这一个键"，不是"有这个键"——工具自己返回的 dict 里恰好有
            # `result` 字段时，后者会把整个载荷替换成那个字段的值，而症状是
            # "少了几个字段"，排查方向会指向服务端。
            inner = result["structuredContent"]
            if isinstance(inner, dict) and set(inner) == {"result"}:
                inner = inner["result"]
            return True, inner
        parsed = []
        for t in texts:
            try:
                parsed.append(json.loads(t))
            except ValueError:
                return False, f"content 块不是合法 JSON: {t[:120]}"
        if expect == "list":
            # 空列表 → `content: []` → 这里如实返回 []（实测过：返回空列表的工具
            # 既没有 content 块也没有 structuredContent）
            return True, parsed
        if len(parsed) != 1:
            return False, (f"expect=dict 但拿到 {len(parsed)} 个 content 块"
                           "——这个工具返回的是列表？调用方的 expect 写错了")
        return True, parsed[0]
