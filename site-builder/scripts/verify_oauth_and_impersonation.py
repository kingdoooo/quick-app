#!/usr/bin/env python3
"""真实用户 OAuth token 的两项真机验收（M4 的最后两项，plan Task 11 的 N1）。

  ① **既有 OAuth 路径回归**：生产 MCP 镜像在 Task 10 被换过（digest
     f0ce7f4698d4d → 1d6e0ef10a25c031a），而 M4 动的正是 `_caller_email()`
     这条身份解析路径。所以"普通用户用 OAuth 调 MCP 一切照旧"必须真机确认一次。
  ② **N1 冒充负测**：真实用户 token **+ 伪造的 `X-SB-On-Behalf-Of`** →
     必须仍解析成**自己**，不是头里那个人。

**为什么这两项不能进 verify_api_key_e2e.py**：它们要一个真实用户的 OAuth access
token，而拿到它必须走交互式飞书登录。本脚本把"人只需在浏览器里点一次"之外的部分
全自动化：token 从 `~/.site-builder-deploy-token.json` 读（`quick-desktop-proxy`
的既有落点），过期时用 refresh_token 自动续；续不动才要求人重跑 auth.js。

**token 一个字节都不打印**（连前缀都不打）。它比 API Key 更敏感：mcp client 是
public client，拿到 refresh token 只需公开的 client ID 就能持续以受害者身份部署、
改权限、下线站点（`quick-desktop-proxy/auth.js` 的注释里记着这一点）。

## ② 的判定为什么是"两次调用返回同一批站点"

MCP 没有 whoami 工具，"解析成了谁"只能从**副作用**观察。`list_my_sites` 返回的
是调用者自己的站点，所以：带伪造头与不带伪造头两次调用**返回同一批 site_id**
⇒ 身份没被头改写。

但这条断言**只有在前置成立时才有意义**，所以前置也各写成一条 check：
  · 自己的站点集合**非空**——空集时"两次都空"会让断言永远绿；
  · 伪造的 email **不等于**自己——否则测的是"自己冒充自己"；
  · 变体 b 的基线（不带头时）必须先是 owner/admin——否则"两次一致"可能只是
    "两次都被拒"。
三条里任一不成立就报 FAIL，绝不让它静默变成一条装饰。

两个伪造变体缺一不可：
  · a) 形态合法但**不存在**的 email：冒充成功的表现是返回空集；
  · b) 换一个**完全不同的观察量**：对自己的站点查权限。`_assert_permission`
       对无权访问者是**抛异常**，所以"冒充成功"的表现是调用直接失败，而不是
       "返回的数据少了几条"。一个看数据、一个看鉴权决策，覆盖两种失效方式。

本脚本**不需要 AWS 凭证**，只需要那个用户 token——它验的就是"以普通用户身份
调 MCP"这条路径，带上 AWS 管理员权限反而会让它偏离被验的场景。

用法（**从仓库根跑**）：
    # 若 token 已过期且 refresh 也失效，先在浏览器里登录一次（只需这一步）：
    node site-builder/clients/quick-desktop-proxy/auth.js "<endpoint>" "<client_id>"
    python3 site-builder/scripts/verify_oauth_and_impersonation.py
"""
import argparse
import configparser
import importlib.util
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CFG_PATH = HERE.parent / "config.ini"
TOKEN_PATH = Path.home() / ".site-builder-deploy-token.json"

# 正对照要换机器 token，复用 key-proxy 的 machine_token（换 token 的唯一实现）
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
sys.path.insert(0, str(HERE.parent / "key-proxy"))

CHECKS = 0
FAILURES = 0
MIN_CHECKS = 11

# MCP over streamable-http 的客户端**只有一份实现**：verify_api_key_e2e.py 的
# `Mcp`。在这里再写一遍就会出现"两个脚本走的其实不是同一个协议路径"，而那正是
# 负测最不能有的性质（本项目已因"手抄第二份"栽过多次）。按路径加载而不是包
# 导入，是因为 scripts/ 不是包。
_spec = importlib.util.spec_from_file_location(
    "_vake", HERE / "verify_api_key_e2e.py")
assert _spec and _spec.loader
_vake = importlib.util.module_from_spec(_spec)
sys.modules["_vake"] = _vake
_spec.loader.exec_module(_vake)
Mcp, http = _vake.Mcp, _vake.http


def check(ok: bool, desc: str, detail: str = "") -> bool:
    global CHECKS, FAILURES
    CHECKS += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES += 1
    return ok


def _claims(access_token: str) -> dict:
    """access token 的 claims（**只解 payload，不验签**）。

    不验签是有意的：这里不是授权判定，只是要读出 `email` 好知道"应该解析成谁"。
    真正的验签在网关（`customJWTAuthorizer`）——如果 token 是伪造的，下面每一次
    调用都会 401，而不是靠这里挡。
    """
    import base64
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _load_token(client_id: str) -> str:
    """有效的用户 access token。过期就用 refresh_token 续；续不动则明确要求人登录。

    **续到的新 token 写回文件**（与 proxy 同一个落点、同一份格式）：不写回的话
    下一次跑本脚本又要续一次，而 refresh 每次都会让 Cognito 轮转 refresh token，
    白丢一次可用期。
    """
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
    if token and _claims(token).get("exp", 0) - time.time() > 300:
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


def _site_ids(payload) -> set | None:
    """`list_my_sites` 的返回 → site_id 集合。形态不对时返回 None（调用方报红）。"""
    if not isinstance(payload, list):
        return None
    return {s.get("site_id") for s in payload if isinstance(s, dict)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()

    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    if not c.sections():
        sys.exit(f"{CFG_PATH} 读不到任何段——请从仓库根用绝对路径跑")

    def cfg(sec, key):
        return c[sec][key].split("#")[0].split(";")[0].strip()

    endpoint = cfg("MCP", "endpoint_url")
    client_id = cfg("Cognito", "mcp_client_id")

    token = _load_token(client_id)
    claims = _claims(token)
    me = claims.get("email", "")

    print("\n── ① 既有 OAuth 路径回归（镜像换过之后）──────────────")
    check(bool(me), "access token 里有 email claim（owner 的取值来源）",
          "缺它则 pre-token 触发器掉了" if not me else f"caller={me}")
    check(claims.get("client_id") == client_id,
          "token 的 client_id == config 里的 mcp_client_id",
          "不是同一个 client——网关会 401")

    m = Mcp(endpoint, {"authorization": f"Bearer {token}"})
    st, _ = m.initialize()
    check(st == 200, "用户 OAuth token 过网关并完成 MCP initialize", f"HTTP {st}")
    st, resp = m.rpc("tools/list")
    names = {t.get("name") for t in (resp.get("result") or {}).get("tools", [])}
    check(len(names) >= 8, "tools/list 返回全部工具", f"{len(names)} 个")

    ok, payload = m.call_tool("list_my_sites", expect="list")
    mine = _site_ids(payload) if ok else None
    check(ok and mine is not None,
          "list_my_sites 成功（OAuth 身份解析正常）",
          f"{len(mine)} 个站点" if mine is not None else str(payload)[:140])
    if mine is None:
        return 1

    print("\n── ② N1 冒充负测：伪造 X-SB-On-Behalf-Of 必须无效 ─────")
    # 前置①：自己的站点集合非空。空集时"两次都空"会让下面的断言永远绿。
    if not check(len(mine) > 0,
                 "前置：调用者自己有站点（否则冒充断言会永远绿）",
                 f"{len(mine)} 个"):
        return 1

    fake = "impersonation-probe@notreal.invalid"
    # 前置②：伪造的 email 不等于自己，否则测的是"自己冒充自己"
    check(fake != me, "前置：伪造的 email 与调用者不同", fake)

    m2 = Mcp(endpoint, {"authorization": f"Bearer {token}",
                        "x-sb-on-behalf-of": fake})
    st, _ = m2.initialize()
    ok, payload = m2.call_tool("list_my_sites", expect="list")
    got = _site_ids(payload) if ok else None
    check(ok and got == mine,
          "变体 a：伪造一个不存在的 email → 仍解析成自己",
          f"返回 {len(got) if got is not None else '?'} 个站点，"
          f"与自己的 {len(mine)} 个"
          + ("一致" if got == mine else "**不一致——身份被头改写了**"))

    # 变体 b：换一个**完全不同的观察量**——权限判定，而不是列表内容。
    # 对自己的一个站点查权限：`do_get_permissions` 里的 `_assert_permission`
    # 对无权访问者是**抛异常**（isError），所以"冒充成功"的表现是这次调用直接
    # 失败，而不是"返回的数据少了几条"。两个变体一个看数据、一个看鉴权决策，
    # 覆盖的是两种不同的失效方式。
    #
    # **为什么不用"伪造成另一个真实 owner 再比对他的站点"**：本环境里调用者拥有
    # 全部 ACTIVE 站点，构造不出那个变体（第一版实现试过，永远 SKIP）。而永久
    # SKIP 的检查是死重量——它看起来覆盖了什么，实际上一次都没跑过。
    probe_site = sorted(mine)[0]
    ok, base = m.call_tool("get_site_permissions", {"site_id": probe_site})
    base_role = base.get("my_role") if isinstance(base, dict) else None
    check(ok and base_role in ("owner", "admin"),
          "前置：不带伪造头查自己站点的权限 → owner/admin",
          f"my_role={base_role}" if ok else str(base)[:120])

    m4 = Mcp(endpoint, {"authorization": f"Bearer {token}",
                        "x-sb-on-behalf-of": fake})
    m4.initialize()
    ok, got = m4.call_tool("get_site_permissions", {"site_id": probe_site})
    got_role = got.get("my_role") if isinstance(got, dict) else None
    check(ok and got_role == base_role,
          "变体 b：带伪造头查同一站点 → 权限判定仍按自己算",
          f"my_role={got_role}（与不带头时一致）" if ok and got_role == base_role
          else f"**{str(got)[:110]}** —— 身份被头改写，鉴权按别人算了")

    # ── 正对照：证明这个头**真的到达了服务端** ───────────────────────────
    # 没有这一条，上面两个变体是**空转的**：如果网关的 requestHeaderAllowlist
    # 把 `X-SB-On-Behalf-Of` 丢掉了，头压根到不了容器，那么"身份没被改写"就会
    # 因为一个完全无关的原因成立——负测全绿而冒充防线其实从未被测到。
    # 机器 token 是这条链路上**唯一被允许**用这个头指定身份的调用者，所以拿它
    # 带上"我自己"的邮箱：能返回我的站点 ⇒ 头确实到达且被采信。
    try:
        os.environ.setdefault("AWS_DEFAULT_REGION",
                              cfg("Platform", "region"))
        os.environ["COGNITO_DOMAIN"] = cfg("Cognito", "domain")
        os.environ["MACHINE_CLIENT_ID"] = cfg("Cognito", "machine_client_id")
        import api_key_config
        os.environ["MACHINE_SCOPE"] = api_key_config.machine_scope(c)
        os.environ["MACHINE_SECRET_PARAM"] = "/site-builder/machine-client-secret"
        import machine_token
        mt = machine_token.get_token()
    except Exception as exc:                # noqa: BLE001
        # **正对照不是可选项**（Codex 审查 2026-08-13 P2-1）。原来这里 SKIP，而
        # MIN_CHECKS 恰好等于正对照之前的 check 数——于是"拿不到机器 token"会
        # 输出 ✅ 10/10 并返回 0，而此时两个负测**可能全是空转的**
        # （头没到达服务端 ⇒ "身份没被改写"因一个完全无关的原因成立）。
        # 一个可能空转的负测报成功，比报"未验证"糟得多：它会被当成"防冒充已验证"
        # 写进交付结论。所以这里落一条 FAIL。
        check(False, "正对照：机器 token + on-behalf=自己 → 返回自己的站点",
              f"拿不到机器 token（{type(exc).__name__}）——本条需要 AWS 凭证，"
              "且**不能跳过**：没有它，上面两个负测证明不了任何事")
    else:
        m5 = Mcp(endpoint, {"authorization": f"Bearer {mt}",
                            "x-sb-on-behalf-of": me})
        m5.initialize()
        ok, got = m5.call_tool("list_my_sites", expect="list")
        got_ids = _site_ids(got) if ok else None
        check(ok and got_ids == mine,
              "正对照：机器 token + on-behalf=自己 → 返回自己的站点"
              "（证明头真的到达服务端，上面两个负测不是空转）",
              f"返回 {len(got_ids) if got_ids is not None else '?'} 个，"
              f"自己 {len(mine)} 个"
              + ("" if got_ids == mine
                 else " —— 头没被采信，那么负测的「没被改写」说明不了任何事"))

    print()
    if CHECKS < MIN_CHECKS:
        print(f"❌ 只跑了 {CHECKS} 项（下限 {MIN_CHECKS}）——中途退出，结果不可信")
        return 1
    if FAILURES:
        print(f"❌ {CHECKS - FAILURES}/{CHECKS} 项通过，{FAILURES} 项未达预期")
        return 1
    print(f"✅ {CHECKS}/{CHECKS} 项通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
