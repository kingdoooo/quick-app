#!/usr/bin/env python3
"""API Key 通道的**真机**端到端验收（二期 M4，plan Task 11）。

六个场景 + 四条负测，每一条都是真机 HTTP，没有一处 moto：

  ① 控制台创建 Key：响应含明文一次；列表接口**不含**明文与 hash
  ② 静态 Header 直连 `mcp.{base_domain}` 完成一次**真实部署**
     （MCP initialize → tools/list → deploy_site → 预签名 PUT → confirm_upload
      → 轮询到 SUCCEEDED → 站点 URL 可访问，且站点 owner == Key 持有者）
  ③ 吊销后**立即** 401（吊销与下一次调用之间不等待——这是"不缓存"的真机证据）
  ④ 关闸 → **另一把有效 Key** 也 401（证明是全局关闸，不是单 Key 失效）
  ⑤ 开闸 → 恢复
  ⑥ 五种拒绝原因的响应体**逐字节相同**（无效 / 吊销 / 关闸 / 未知 / 没带）
  N2 机器 token 直连 AgentCore、不带 on-behalf 头 → 拒（fail-closed）
  N3 非 Edge 的签名直连 key-proxy Function URL → 403
  N4 明文 Key **不在任何日志里**（key-proxy 与 panel 两个日志组）

**N1（冒充负测）不在本脚本里**：它要一个**真实用户的 OAuth access token**
（真实用户 token + 伪造 `X-SB-On-Behalf-Of` → 必须仍解析成自己），而拿到那个
token 必须走交互式飞书登录，headless 做不到。照 `verify_console_e2e.py` 对
"真浏览器那两项"的既有处理：脚本末尾把它打印成人工待办，**不计入通过数**。
它已有单测 + 注入复验覆盖（precedence flip → 2 条红），未覆盖的只是真机那一次。

## 两条容易写错的地方（都写在这里，别在别处再想一遍）

**预签名 PUT 不能带 `Content-Type`**（签名按无该头计算，带了必 403）。而
`urllib.request` 在 `data` 非空时会**自动补** `Content-Type:
application/x-www-form-urlencoded`——用 urllib 上传必 403，且错误文案指向签名，
排查方向会被带向 IAM。所以这一步走 `http.client` 手工发，只带 `Content-Length`。

**N4 不能用服务端 filter**：`FilterLogEvents` 的 `filterPattern` 会把明文 Key
写进 API 调用参数（可能进 CloudTrail），等于为了检查泄漏而制造一次泄漏。做法是
把时间窗内的事件**拉回本地再 grep**。别"优化"成服务端过滤。

## 纪律
- 一次性后缀资源（Key 备注名、站点名都带随机后缀）；
- `finally` 里逐个删除并**读回核对**，清理失败即验收失败（不是打印警告）；
- **开关状态在 `finally` 里恢复成进入时的值**——脚本跑一半崩掉不能把生产开关
  留在关闸状态（那时所有 Key 都 401，而现场会以为是组件坏了）；
- 脚本自身**从不打印明文 Key**，只打前 6 位；
- `MIN_CHECKS` 下限 + 非零退出。

**开关为什么不经控制台的 admin HTTP 接口翻**（`PUT /api/settings/api-key`）：
那条路径要一个**管理员**的面板会话，而本脚本能造出的只有"用真实 JWT_SECRET 签一个
任意 email 的会话"。拿真实管理员的邮箱去签，等于在 `ops_log` 里留下一条
"某位管理员关掉了全平台 Key 通道"的假审计——审计可信度的代价远大于多覆盖一条
HTTP 路径。这里直接调 `keystore.set_switch`（**同一个写入实现**）并把 `actor`
标成本脚本名（沿用 `deploy_key_proxy.py` 写哨兵行时的既有约定），再断言
`ops_log` 里确实落了对应的审计行——审计路径同样被验到，且署名是诚实的。
场景 ④ 要断言的对象本来就是 **key-proxy 在关闸时的行为**，不是 panel 的开关接口
（后者有单测覆盖）。

用法（**从仓库根跑**）：
    python3 site-builder/scripts/verify_api_key_e2e.py
    python3 site-builder/scripts/verify_api_key_e2e.py --keep-on-failure
"""
import argparse
import configparser
import io
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from http.client import HTTPSConnection
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key as DdbKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CFG_PATH = HERE.parent / "config.ini"
FIXTURE = HERE.parent / "fixtures" / "static-hello"

sys.path.insert(0, str(HERE.parent / "auth"))
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
sys.path.insert(0, str(HERE.parent / "key-proxy"))

CHECKS = 0
FAILURES = 0
# 全绿时的实际断言条数。低于它说明脚本中途退出或某个分支被跳过，而
# "跑了 3 项全过"读起来跟"30 项全过"一样像成功（M3-FINDINGS §2.3）。
MIN_CHECKS = 34

# 哨兵行与审计里的署名。**不是某个人**——见模块 docstring 里"开关为什么不经
# 控制台 admin 接口翻"那一段。
ACTOR = "verify_api_key_e2e.py"


def check(ok: bool, desc: str, detail: str = "") -> bool:
    global CHECKS, FAILURES
    CHECKS += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES += 1
    return ok


def _cfg_obj(path: Path) -> configparser.ConfigParser:
    """读 config.ini 并**断言真读到了**。

    `ConfigParser.read()` 对不存在的路径静默返回空配置，之后任何取值/判段都会
    给出一个看起来言之有理的错误结论（本项目 2026-08-13 因此发过一次假警报）。
    """
    c = configparser.ConfigParser(interpolation=None)
    c.read(path)
    if not c.sections():
        sys.exit(f"{path} 读不到任何段——请从仓库根用绝对路径跑本脚本")
    return c


def cfg(c, section: str, key: str, default: str | None = None) -> str:
    try:
        return c[section][key].split("#")[0].split(";")[0].strip()
    except KeyError:
        if default is not None:
            return default
        sys.exit(f"config.ini 缺 [{section}] {key}")


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


def presigned_put(url: str, blob: bytes) -> int:
    """预签名 PUT。**只带 Content-Length，绝不带 Content-Type**（见模块 docstring）。

    走 `http.client` 而不是 urllib 就是为了这一件事：urllib 会在 `data` 非空时
    自动补 `Content-Type`，而预签名 URL 的签名是按"没有该头"算的，带上必 403。
    """
    u = urllib.parse.urlsplit(url)
    conn = HTTPSConnection(u.netloc, timeout=180)
    try:
        path = u.path + (f"?{u.query}" if u.query else "")
        conn.putrequest("PUT", path, skip_accept_encoding=True)
        conn.putheader("Content-Length", str(len(blob)))
        conn.endheaders()
        conn.send(blob)
        return conn.getresponse().status
    finally:
        conn.close()


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


class Mcp:
    """一个 MCP streamable-http 会话。**认证方式由 `headers` 决定**：

    · 场景 ①-⑥ 走 `X-API-Key` 打到 `mcp.{base_domain}`（即真实客户端的形态）；
    · N2 走 `Authorization: Bearer {机器 token}` 直连 AgentCore（绕过 key-proxy）。

    两者的协议部分完全一样，所以共用这个类——分成两份实现就会出现"负测走的其实
    不是同一个协议路径"。
    """

    def __init__(self, url: str, auth: dict):
        self.url = url
        self.auth = dict(auth)
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
                       "clientInfo": {"name": "verify-api-key-e2e",
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-on-failure", action="store_true",
                    help="失败时保留 Key 与站点便于排查（开关仍会恢复）")
    args = ap.parse_args()

    c = _cfg_obj(CFG_PATH)
    region = cfg(c, "Platform", "region")
    base = cfg(c, "Platform", "base_domain")
    account = cfg(c, "Platform", "account_id")
    routing_table = cfg(c, "Platform", "routing_table")
    sites_table = cfg(c, "Deployer", "sites_table")
    console_origin = f"https://console.{base}"

    # keystore / ops_log 的表名都靠环境变量（它们本来跑在 Lambda 里）。
    # **在 import 之前设好**：模块级不建客户端，但第一次调用就会读它们。
    os.environ.setdefault("AWS_DEFAULT_REGION", region)
    os.environ.setdefault("API_KEYS_TABLE", "site-api-keys")
    os.environ.setdefault("OPS_LOG_TABLE", "site-ops-log")

    import api_key_config
    import keygen
    import keystore
    import session as sess

    if not api_key_config.api_key_enabled(c):
        sys.exit("config.ini 无 [ApiKey] 段 = API Key 组件未启用，本验收无对象。"
                 "先按 config.ini.example 配置该段并跑完四步部署。")

    mcp_url = f"https://{api_key_config.mcp_subdomain(c)}.{base}/"

    ddb = boto3.resource("dynamodb", region_name=region)
    keys_tbl = ddb.Table("site-api-keys")
    secret = boto3.client("ssm", region_name=region).get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    if not secret:
        sys.exit("取不到 JWT_SECRET —— 无法签发控制台会话，验收不可信")

    # Edge 实际信任的 idp 值（router 那侧的配置注入了 Edge 的 TRUSTED_IDPS）。
    # 在这里写死 "Feishu" 会让脚本在换 IdP 的环境上全红，而红的原因与被测代码无关。
    rcfg = _cfg_obj(ROOT / "router" / "config.ini")
    trusted_idp = ""
    for sec in rcfg.sections():
        if rcfg.has_option(sec, "trusted_idps"):
            trusted_idp = rcfg.get(sec, "trusted_idps").split("#")[0].split(",")[0].strip()
            if trusted_idp:
                break
    if not trusted_idp:
        sys.exit("router/config.ini 里找不到 trusted_idps —— 签出来的会话 Edge 不认")

    suf = secrets.token_hex(4)
    owner = f"apikeye2e-{suf}@example.com"
    started_at = datetime.now(timezone.utc)

    def mint(scope: str = "") -> str:
        return sess.mint_session_jwt(
            owner, owner.split("@")[0], secret, ttl_seconds=1800,
            idp=trusted_idp, scope=scope, auth_via="TokenGeneration_HostedAuth")

    console_ck = f"sb_session={mint()}; __Host-sb_console={mint('console')}"
    console_headers = {"cookie": console_ck, "origin": console_origin}

    # ---- 进入时的开关状态：finally 必须恢复成它 ----
    entry_deployed, entry_switch = keystore.switch_state()
    if not entry_deployed:
        sys.exit("哨兵行不存在 = 组件没跑过 deploy_key_proxy.py，本验收无对象")
    print(f"进入时的 API Key 总开关：{'开' if entry_switch else '关'}"
          f"（finally 会恢复成这个值）")
    if not entry_switch:
        sys.exit("进入时开关是**关**的：场景 ②③ 需要通道是开的。"
                 "请先在控制台（管理员）打开开关再跑本脚本。")

    created_hashes: list[tuple[str, str]] = []      # (key_hash, 用途标签)
    site_id = ""
    k1 = k2 = ""
    reject_bodies: dict[str, str] = {}
    rc = 1
    try:
        # ─────────────────────────── ① 控制台创建 Key ───────────────────────
        print("\n── ① 控制台创建 Key（明文只出现这一次）──────────────")
        st, _, text = http("POST", console_origin + "/api/keys",
                           headers=console_headers,
                           body={"name": f"e2e-primary-{suf}"})
        body = json.loads(text) if st == 200 else {}
        k1 = body.get("plaintext", "")
        check(st == 200 and bool(k1), "POST /api/keys → 200 且响应含明文",
              f"HTTP {st}，明文前缀 {k1[:6]}…" if k1 else f"HTTP {st} {text[:120]}")
        if not k1:
            raise RuntimeError("拿不到明文 Key，后续场景无从进行")
        created_hashes.append((keygen.hash_key(k1), "primary"))
        check(bool(keygen.PLAINTEXT_RE.fullmatch(k1)),
              "明文形态符合 keygen.PLAINTEXT_RE", f"{k1[:6]}… 长度 {len(k1)}")
        k1_id = body.get("key_id", "")
        check(bool(k1_id) and "key_hash" not in text,
              "创建响应含 key_id 且**不含** key_hash", f"key_id={k1_id}")

        st, _, text = http("GET", console_origin + "/api/keys",
                           headers={"cookie": console_ck})
        listed = (json.loads(text) if st == 200 else {}).get("keys", [])
        check(st == 200 and any(r.get("key_id") == k1_id for r in listed),
              "GET /api/keys 列出这把 Key", f"{len(listed)} 条")
        # **列表接口一个字节的明文/哈希都不能出**：明文在服务端只应在创建响应里
        # 出现一次。按整个响应文本断言，而不是逐字段——逐字段会漏掉"换了个字段名
        # 但还是同一个值"。
        check(k1 not in text and "plaintext" not in text and "key_hash" not in text,
              "列表响应里没有明文、没有 plaintext / key_hash 字段",
              "出现了明文或哈希——列表接口存在泄漏路径"
              if (k1 in text or "plaintext" in text) else "三者都不在")

        st, _, text = http("POST", console_origin + "/api/keys",
                           headers=console_headers,
                           body={"name": f"e2e-second-{suf}"})
        k2 = (json.loads(text) if st == 200 else {}).get("plaintext", "")
        check(st == 200 and bool(k2), "再创建第二把 Key（④ 用它验全局关闸）",
              f"HTTP {st}，前缀 {k2[:6]}…" if k2 else f"HTTP {st} {text[:120]}")
        if not k2:
            raise RuntimeError("拿不到第二把 Key，场景 ④ 无从进行")
        created_hashes.append((keygen.hash_key(k2), "second"))

        # ─────────────────── ② 静态 Header 直连 → 真实部署 ──────────────────
        print("\n── ② 静态 Header 直连 mcp 子域完成一次真实部署 ───────")
        m = Mcp(mcp_url, {"x-api-key": k1})
        st, resp = m.initialize()
        check(st == 200 and bool(m.session_id),
              "initialize → 200 且拿到 mcp-session-id",
              f"HTTP {st} session={m.session_id[:8]}…" if m.session_id
              else f"HTTP {st} {json.dumps(resp)[:120]}")
        st, resp = m.rpc("tools/list")
        names = {t.get("name") for t in (resp.get("result") or {}).get("tools", [])}
        need = {"deploy_site", "confirm_upload", "get_deploy_status",
                "undeploy_site", "list_my_sites"}
        check(need <= names, "tools/list 含部署链全部工具",
              f"缺 {sorted(need - names)}" if need - names else f"{len(names)} 个工具")

        ok, out = m.call_tool("deploy_site", {"site_name": f"e2ekey{suf}"})
        job_id = (out or {}).get("job_id", "") if isinstance(out, dict) else ""
        upload_url = (out or {}).get("upload_url", "") if isinstance(out, dict) else ""
        site_id = (out or {}).get("site_id", "") if isinstance(out, dict) else ""
        check(ok and bool(job_id) and bool(upload_url) and bool(site_id),
              "deploy_site → 返回 job_id / site_id / upload_url",
              f"site_id={site_id} job={job_id}" if ok else str(out)[:160])
        if not (job_id and upload_url):
            raise RuntimeError("deploy_site 没给出上传入口，部署链无从进行")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(FIXTURE.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(FIXTURE))
        put_status = presigned_put(upload_url, buf.getvalue())
        check(put_status in (200, 204),
              "预签名 PUT 上传 site.zip（不带 Content-Type）",
              f"HTTP {put_status}"
              + ("" if put_status in (200, 204)
                 else " —— 带了 Content-Type 必 403，见 presigned_put 的注释"))

        ok, out = m.call_tool("confirm_upload", {"job_id": job_id})
        check(ok, "confirm_upload → 启动异步部署", str(out)[:120])

        deadline = time.time() + 420
        status, url, last = "", "", {}
        while time.time() < deadline:
            ok, last = m.call_tool("get_deploy_status", {"job_id": job_id})
            if isinstance(last, dict):
                status, url = last.get("status", ""), last.get("url", "")
                if status in ("SUCCEEDED", "FAILED"):
                    break
            time.sleep(10)
        check(status == "SUCCEEDED" and bool(url),
              "轮询到 SUCCEEDED 且返回站点 URL",
              f"status={status} url={url}" if status == "SUCCEEDED"
              else f"status={status} {json.dumps(last, ensure_ascii=False)[:200]}")

        if url:
            st, _, page = http("GET", url)
            check(st == 200 and "html" in page.lower(),
                  "站点 URL 可访问（fixture 是公开站点）",
                  f"HTTP {st}，{len(page)} 字节")

        # **身份真的传下去了**：站点 owner 必须是 Key 的持有者，而不是别人。
        # 这一条是整条 on-behalf 链路的落点——网关放行、容器采信、权限层落库。
        row = ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True).get("Item") or {}
        check(row.get("owner") == owner,
              "sites 表里的 owner == Key 持有者（on-behalf 身份真的落地了）",
              f"owner={row.get('owner')} 期望={owner}")

        # **`last_used_at` 必须真的写进去了**（Codex 审查 2026-08-13 P1-1 的连带）：
        # key-proxy 的 UpdateItem 权限已按字段收窄（只允许 key_hash +
        # last_used_at），而 `touch_last_used` **吞掉所有异常**——万一收窄写错了，
        # 真机表现是遥测悄悄停摆、只有一条 warning 日志，功能测试全绿。
        # 所以这条断言的对象不是"遥测有用"，而是"那条 IAM 收窄没把自己挡死"。
        krow = keys_tbl.get_item(Key={"key_hash": keygen.hash_key(k1)},
                                 ConsistentRead=True).get("Item") or {}
        check(bool(krow.get("last_used_at")),
              "转发后 last_used_at 已写入（证明收窄后的 UpdateItem 权限仍够用）",
              str(krow.get("last_used_at"))[:25] if krow.get("last_used_at")
              else "**没写进去**——IAM 收窄把遥测挡掉了，而它是静默失败的")

        # ─────────────────────── ③ 吊销后立即 401 ──────────────────────────
        print("\n── ③ 吊销后**立即** 401（不等待，证明不缓存）──────────")
        # 吊销走 **`POST /api/keys/revoke`**，不是 `DELETE /api/keys`。
        # 本脚本首跑（2026-08-13）用的是 DELETE，红了，而且**红得对**：
        # CloudFront 把 DELETE 的请求体交给了 Lambda@Edge（`include_body=True`，
        # 所以 Edge 按真实 body 算 payload hash 去签名），但转发到源站时那个 body
        # 不在了——Function URL 按空 body 算哈希，SigV4 不匹配，**在 panel 任何
        # 代码之前**就 403。四组对照隔离：DELETE 带 body → 403 签名不匹配；
        # DELETE 不带 body → 到达 panel；POST 带 body → 200；
        # `DELETE /api/admins` 带 body → 同样 403（所以这**不是 M4 引入的**，
        # `DELETE /api/admins` 从 M3 上线起就坏着，只是没有任何闸门发过带 body 的
        # DELETE——单测直接调 handler，不经 CloudFront）。
        # 根因与"为什么不搬进查询串"写在 `panel/handler.py` 的 ROUTES 下方，
        # 并由 `test_no_route_uses_delete_with_body` 按路由表锁住。
        st, _, text = http("POST", console_origin + "/api/keys/revoke",
                           headers=console_headers, body={"key_id": k1_id})
        check(st == 200, "POST /api/keys/revoke 吊销第一把",
              f"HTTP {st} {text[:100]}")
        # 中间**一秒都不等**：有缓存的实现会在这里仍然放行。
        revoked = Mcp(mcp_url, {"x-api-key": k1})
        st, revoked_body = revoked.raw_body(
            {"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}})
        check(st == 401, "吊销后下一次调用立刻 401（零等待）", f"HTTP {st}")
        reject_bodies["吊销"] = revoked_body

        # ─────────────────────── ④ 关闸 → 全部 Key 401 ─────────────────────
        print("\n── ④ 关闸 → 另一把有效 Key 也 401（全局关闸）─────────")
        alive = Mcp(mcp_url, {"x-api-key": k2})
        st, _ = alive.initialize()
        check(st == 200, "关闸前第二把 Key 可用（前置）", f"HTTP {st}")

        keystore.set_switch(False, actor=ACTOR)
        off = Mcp(mcp_url, {"x-api-key": k2})
        st, off_body = off.raw_body(
            {"jsonrpc": "2.0", "id": 98, "method": "tools/list", "params": {}})
        check(st == 401, "关闸后有效 Key 也 401（不是单 Key 失效）", f"HTTP {st}")
        reject_bodies["关闸"] = off_body

        # 关闸窗口里顺便取另外三种拒绝的响应体：都在同一时刻取，排除"不同时间
        # 的响应体差异"这种干扰。
        reject_bodies["未知但形态合法"] = Mcp(
            mcp_url, {"x-api-key": keygen.new_key().plaintext}).raw_body(
                {"jsonrpc": "2.0", "id": 97, "method": "tools/list"})[1]

        audits = ddb.Table("site-ops-log").query(
            KeyConditionExpression=DdbKey("target").eq("apikey:switch"),
            ScanIndexForward=False, Limit=5).get("Items", [])
        check(any(a.get("action") == "disable_api_key_switch"
                  and a.get("actor") == ACTOR for a in audits),
              "关闸落了 ops_log 审计行且署名是本脚本",
              f"最近 {len(audits)} 条里找不到" if not audits else f"actor={ACTOR}")

        # ─────────────────────────── ⑤ 开闸 → 恢复 ─────────────────────────
        print("\n── ⑤ 开闸 → 立即恢复 ───────────────────────────────")
        keystore.set_switch(True, actor=ACTOR)
        back = Mcp(mcp_url, {"x-api-key": k2})
        st, _ = back.initialize()
        check(st == 200, "开闸后第二把 Key 立刻恢复可用（零等待）", f"HTTP {st}")
        audits = ddb.Table("site-ops-log").query(
            KeyConditionExpression=DdbKey("target").eq("apikey:switch"),
            ScanIndexForward=False, Limit=5).get("Items", [])
        check(any(a.get("action") == "enable_api_key_switch"
                  and a.get("actor") == ACTOR for a in audits),
              "开闸也落了 ops_log 审计行", f"最近 {len(audits)} 条")

        # ──────────────────── ⑥ 五种拒绝**逐字节相同** ─────────────────────
        print("\n── ⑥ 五种拒绝原因的响应体逐字节相同 ─────────────────")
        # 剩下两种在开闸状态下取（"无效形态"与"没带 Key"与开关无关）
        reject_bodies["形态无效"] = Mcp(
            mcp_url, {"x-api-key": "sk-not-a-real-key"}).raw_body(
                {"jsonrpc": "2.0", "id": 96, "method": "tools/list"})[1]
        reject_bodies["没带 Key"] = Mcp(mcp_url, {}).raw_body(
            {"jsonrpc": "2.0", "id": 95, "method": "tools/list"})[1]
        distinct = {v for v in reject_bodies.values()}
        check(len(distinct) == 1,
              f"{len(reject_bodies)} 种拒绝原因的响应体逐字节相同",
              f"出现了 {len(distinct)} 种不同响应体："
              f"{ {k: v[:40] for k, v in reject_bodies.items()} }"
              if len(distinct) != 1 else repr(next(iter(distinct))[:60]))
        check(all(v for v in reject_bodies.values()),
              "五种拒绝都真的拿到了响应体（不是空串蒙混过关）",
              f"空的: {[k for k, v in reject_bodies.items() if not v]}")

        # ───────────────── N2 机器 token 直连 AgentCore 不带头 ──────────────
        print("\n── N2 机器 token 绕过 key-proxy、不带 on-behalf 头 ────")
        os.environ["COGNITO_DOMAIN"] = cfg(c, "Cognito", "domain")
        os.environ["MACHINE_CLIENT_ID"] = cfg(c, "Cognito", "machine_client_id")
        os.environ["MACHINE_SCOPE"] = api_key_config.machine_scope(c)
        os.environ["MACHINE_SECRET_PARAM"] = "/site-builder/machine-client-secret"
        import machine_token          # 换 token 的**唯一实现**，不在这里重写
        token = machine_token.get_token()
        check(bool(token), "换到机器 token（client_credentials）",
              f"长度 {len(token)}")
        direct = Mcp(cfg(c, "MCP", "endpoint_url"),
                     {"authorization": f"Bearer {token}"})
        st, _ = direct.initialize()
        check(st == 200, "机器 token 过网关（allowedClients 含它）", f"HTTP {st}")
        ok, out = direct.call_tool("list_my_sites", expect="list")
        check(not ok and "无法识别调用者身份" in str(out),
              "不带 on-behalf 头调工具 → 容器 fail-closed 拒绝",
              str(out)[:120] if not ok else f"**放行了**，返回 {str(out)[:80]}")

        # ─────────────── N3 非 Edge 直连 key-proxy Function URL ─────────────
        print("\n── N3 非 Edge 的签名直连 key-proxy → 403 ──────────────")
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        lam = boto3.client("lambda", region_name=region)
        fn_url = lam.get_function_url_config(
            FunctionName="site-key-proxy")["FunctionUrl"]
        creds = boto3.Session().get_credentials().get_frozen_credentials()
        areq = AWSRequest(method="POST", url=fn_url,
                          data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                          headers={"x-api-key": k2})
        SigV4Auth(creds, "lambda", region).add_auth(areq)
        st, _, text = http("POST", fn_url, headers=dict(areq.headers),
                           raw=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
        # 403 且响应体是 handler 自己的 {"error":…}——IAM 的 403 是
        # {"Message":"Forbidden"}，只看状态码分不出"handler 拒的"与"IAM 拒的"。
        parsed = {}
        try:
            parsed = json.loads(text)
        except ValueError:
            pass
        check(st == 403 and "error" in parsed,
              "非 Edge 直连被 handler 的 ⓪ 步拒（带有效 Key 也不行）",
              f"HTTP {st} {text[:100]}")

        # ────────────────────── N4 明文不在任何日志里 ───────────────────────
        print("\n── N4 明文 Key 不在 key-proxy / panel 的日志里 ────────")
        # **拉回本地再 grep**：用明文做服务端 filterPattern 会把它写进 API 调用
        # 参数（可能进 CloudTrail），为了查泄漏而制造一次泄漏。别"优化"回去。
        logs = boto3.client("logs", region_name=region)
        since = int((started_at - timedelta(minutes=1)).timestamp() * 1000)
        for group in ("/aws/lambda/site-key-proxy", "/aws/lambda/site-panel"):
            hay, scanned = [], 0
            try:
                tok = None
                while True:
                    kw = {"logGroupName": group, "startTime": since, "limit": 10000}
                    if tok:
                        kw["nextToken"] = tok
                    page = logs.filter_log_events(**kw)
                    evs = page.get("events", [])
                    scanned += len(evs)
                    hay += [e.get("message", "") for e in evs]
                    tok = page.get("nextToken")
                    if not tok or scanned >= 50000:
                        break
            except logs.exceptions.ResourceNotFoundException:
                check(False, f"{group} 存在", "日志组不存在——组件没跑过？")
                continue
            leaked = [msg[:80] for msg in hay if k1 in msg or k2 in msg]
            check(not leaked, f"{group} 里明文 Key 零命中",
                  f"扫了 {scanned} 条事件"
                  if not leaked else f"**命中 {len(leaked)} 条**: {leaked[:2]}")

        rc = 0 if FAILURES == 0 else 1
    finally:
        print("\n── 清理（开关先恢复，再删资源）────────────────────")
        # **开关最先恢复**：后面的清理即便失败，也不能把生产留在关闸状态。
        try:
            keystore.set_switch(entry_switch, actor=ACTOR)
            _, now = keystore.switch_state()
            check(now == entry_switch,
                  f"开关已恢复成进入时的值（{'开' if entry_switch else '关'}）",
                  f"现在是 {'开' if now else '关'}")
        except Exception as exc:                # noqa: BLE001 恢复失败必须显式红
            check(False, "开关已恢复成进入时的值", f"恢复失败: {exc}")

        keep = args.keep_on_failure and FAILURES
        if keep:
            print(f"  --keep-on-failure 且有失败：保留 Key 与站点 {site_id}")
        else:
            # **顺序是硬约束：先下线站点，再删 Key 行。**
            # 反过来写过一次（2026-08-13 首跑）：Key 行删掉之后再拿那把 Key 调
            # undeploy_site，key-proxy 当然 401，于是**生产上留下了一个真站点**，
            # 而脚本只报"清理失败"。下线要经 MCP（与创建同一条路径、同一个身份），
            # 而那条路径的前提就是 Key 还活着。
            if site_id:
                _cleanup_site(ddb, sites_table, routing_table, site_id,
                              mcp_url, k2)
            for kh, label in created_hashes:
                try:
                    keys_tbl.delete_item(Key={"key_hash": kh})
                    left = keys_tbl.get_item(Key={"key_hash": kh},
                                             ConsistentRead=True).get("Item")
                    check(left is None, f"已删除并读回确认 Key 行（{label}）",
                          "已不存在" if left is None else "**仍存在**")
                except Exception as exc:        # noqa: BLE001
                    check(False, f"已删除并读回确认 Key 行（{label}）", str(exc)[:120])

        print()
        if CHECKS < MIN_CHECKS:
            print(f"❌ 只跑了 {CHECKS} 项（下限 {MIN_CHECKS}）——脚本中途退出，"
                  "结果不可信")
            rc = 1
        elif FAILURES:
            print(f"❌ {CHECKS - FAILURES}/{CHECKS} 项通过，{FAILURES} 项未达预期")
            rc = 1
        else:
            print(f"✅ {CHECKS}/{CHECKS} 项通过")
        print("\n人工待办（headless 做不到，需交互式飞书登录）：")
        print("  N1 冒充负测：用真实用户的 OAuth access token 调 MCP，同时带一个"
              "伪造的\n     X-SB-On-Behalf-Of: 别人@域名 —— 必须仍解析成**自己**。"
              "\n     （已有单测 + 注入复验覆盖，缺的只是真机那一次）")
    return rc


def _cleanup_site(ddb, sites_table: str, routing_table: str, site_id: str,
                  mcp_url: str, key: str) -> None:
    """下线 fixture 站点并**读回核对**。

    走 MCP 的 `undeploy_site`（与创建同一条路径、同一个身份），而不是直接删表：
    直接删表会留下 Lambda / S3 对象 / IAM 角色这些真资源。undeploy 是**异步**的
    （Event 方式调 site-deployer-undeploy），所以要轮询到路由行消失 +
    sites 行 status=DELETED 才算清理完成。
    """
    if not key:
        check(False, f"站点 {site_id} 已清理", "没有可用的 Key 来调 undeploy")
        return
    ok, out = Mcp(mcp_url, {"x-api-key": key}).call_tool(
        "undeploy_site", {"site_id": site_id})
    if not ok:
        check(False, f"站点 {site_id} 已下线", f"undeploy_site 拒绝: {str(out)[:120]}")
        return
    deadline = time.time() + 300
    route_gone = status = None
    while time.time() < deadline:
        route_gone = ddb.Table(routing_table).get_item(
            Key={"subdomain": f"app-{site_id}"},
            ConsistentRead=True).get("Item") is None
        status = (ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True).get("Item")
            or {}).get("status")
        if route_gone and status == "DELETED":
            break
        time.sleep(10)
    check(bool(route_gone) and status == "DELETED",
          f"站点 {site_id} 已下线并读回确认（路由行消失 + status=DELETED）",
          f"route_gone={route_gone} status={status}")


if __name__ == "__main__":
    sys.exit(main())
