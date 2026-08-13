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
  · 变体 b 里那个真实 owner 的站点集合**与自己的不同**——相同的话，即便冒充
    成功也看不出差别。
三条里任一不成立就报 SKIP 或 FAIL，绝不让它静默变成一条装饰。

两个伪造变体缺一不可：
  · a) 形态合法但**不存在**的 email：冒充成功的表现是返回空集；
  · b) **真实存在的另一个 owner**（从 sites 表现查）：冒充成功的表现是返回
       那个人的站点。只做 a) 时，"把身份解析成一个查不到站点的用户"与
       "正确地解析成自己但恰好返回空"在结果上分不开。

用法（**从仓库根跑**）：
    # 若 token 已过期且 refresh 也失效，先在浏览器里登录一次（只需这一步）：
    node site-builder/clients/quick-desktop-proxy/auth.js "<endpoint>" "<client_id>"
    python3 site-builder/scripts/verify_oauth_and_impersonation.py
"""
import argparse
import configparser
import importlib.util
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import boto3

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CFG_PATH = HERE.parent / "config.ini"
TOKEN_PATH = Path.home() / ".site-builder-deploy-token.json"

CHECKS = 0
FAILURES = 0
MIN_CHECKS = 8

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
    # 留 60s 余量：正好在过期边缘的 token 会让后面某一次调用莫名 401
    if token and _claims(token).get("exp", 0) - time.time() > 60:
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


def _other_owner_with_sites(region: str, sites_table: str, me: str,
                            my_ids: set) -> tuple[str, set] | tuple[None, None]:
    """现查一个**真实存在**的其他 owner，且其站点集合与我的不同（变体 b 用）。

    只读 sites 表。挑的是 ACTIVE 站点的 owner——已下线的 owner 会返回空集，
    那样变体 b 就退化成变体 a 了。
    """
    tbl = boto3.resource("dynamodb", region_name=region).Table(sites_table)
    owners: dict = {}
    kw = {"ProjectionExpression": "site_id,#o,#s",
          "ExpressionAttributeNames": {"#o": "owner", "#s": "status"}}
    while True:
        page = tbl.scan(**kw)
        for it in page.get("Items", []):
            owner = str(it.get("owner", ""))
            if owner and owner != me and it.get("status") == "ACTIVE":
                owners.setdefault(owner, set()).add(it.get("site_id"))
        if "LastEvaluatedKey" not in page:
            break
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    for owner, ids in sorted(owners.items()):
        if ids and ids != my_ids:
            return owner, ids
    return None, None


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

    region = cfg("Platform", "region")
    endpoint = cfg("MCP", "endpoint_url")
    client_id = cfg("Cognito", "mcp_client_id")
    sites_table = cfg("Deployer", "sites_table")

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

    ok, payload = m.call_tool("list_my_sites")
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
    ok, payload = m2.call_tool("list_my_sites")
    got = _site_ids(payload) if ok else None
    check(ok and got == mine,
          "变体 a：伪造一个不存在的 email → 仍解析成自己",
          f"返回 {len(got) if got is not None else '?'} 个站点，"
          f"与自己的 {len(mine)} 个"
          + ("一致" if got == mine else "**不一致——身份被头改写了**"))

    other, other_ids = _other_owner_with_sites(region, sites_table, me, mine)
    if not other:
        print("  SKIP  变体 b（sites 表里找不到另一个「有 ACTIVE 站点且集合与自己"
              "不同」的 owner——本环境构造不出这个更强的变体）")
    else:
        # 前置③：那个人的站点集合与我的不同，否则冒充成功也看不出差别
        check(other_ids != mine,
              "前置：被冒充者的站点集合与自己不同（否则看不出差别）",
              f"对方 {len(other_ids)} 个 vs 自己 {len(mine)} 个")
        m3 = Mcp(endpoint, {"authorization": f"Bearer {token}",
                            "x-sb-on-behalf-of": other})
        st, _ = m3.initialize()
        ok, payload = m3.call_tool("list_my_sites")
        got = _site_ids(payload) if ok else None
        check(ok and got == mine,
              "变体 b：伪造一个**真实存在**的其他 owner → 仍解析成自己",
              "返回的是自己的站点"
              if got == mine else
              f"**返回了 {len(got) if got is not None else '?'} 个站点，"
              f"不是自己的 {len(mine)} 个——可越权读取他人站点**")

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
