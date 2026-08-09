#!/usr/bin/env python3
"""控制台（M3 panel）真机端到端验收——spec §7 的 13 项。

**为什么不是浏览器脚本**：13 项里只有"飞书同意页"与"cookie 落盘"必须真浏览器，
其余全是 HTTP 层可判定的行为（302 / 403 / 401 / 404 / 200 + 响应形态 + 线上
数据是否真被改）。用 HTTP 层做可以无人值守、可重复、失败点精确。真浏览器那两项
在本脚本末尾列出来交给人工（同 `verify_auth_alarm.sh` 的 ② 段既有设计）。

**会话怎么来**：用 SSM 里的真实 `JWT_SECRET` 签一个与托管登录**同形态**的
会话 JWT（含 idp/auth_via，Edge 的 REQUIRE_IDP_CLAIM 要求它们）。这不是绕过
鉴权——签名密钥就是唯一的信任根，Edge 验的就是这个。它验证的是 Edge→panel
的完整链路：CloudFront → origin-request 验签 → 注入 x-user-email →
Function URL(AWS_IAM) → handler 五步前置。

**纪律（照 smoke_router.sh 的三条）**：
  ① 断言失败必须让脚本非零退出（不能只打印不通过）；
  ② 只碰本次创建的资源：随机后缀 fixture 站点，逐个指名删除，**禁止**按
     owner 批量删（试点环境里有长期存在的真站点）；
  ③ 清理要读回核对，且 finally 覆盖异常路径。

用法：
    python3 site-builder/scripts/verify_console_e2e.py
    python3 site-builder/scripts/verify_console_e2e.py --keep-on-failure
"""
import argparse
import configparser
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import boto3

HERE = Path(__file__).resolve().parent
CFG_PATH = HERE.parent / "config.ini"
sys.path.insert(0, str(HERE.parent / "auth"))
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))

import session as sess          # noqa: E402  (auth/session.py，签发算法单一实现)

CHECKS = 0
FAILURES = 0
# 全绿时的实际断言条数下限。**不是估的**：低于它说明脚本中途崩了或分支被跳过，
# 而"跑了 3 项全过"读起来跟"30 项全过"一样像成功（M3-FINDINGS §2.3 的教训）。
MIN_CHECKS = 55


def cfg(section: str, key: str, default: str | None = None) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    try:
        return c[section][key].split("#")[0].split(";")[0].strip()
    except KeyError:
        if default is not None:
            return default
        sys.exit(f"config.ini 缺 [{section}] {key}")


def check(ok: bool, desc: str, detail: str = "") -> bool:
    global CHECKS, FAILURES
    CHECKS += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES += 1
    return ok


class Headers(dict):
    """响应头字典，**取值大小写不敏感**（HTTP 头本来就是）。

    为什么需要它：`dict(resp.headers)` 会丢掉 email.message.Message 的大小写
    不敏感特性。auth 服务返回的是小写 `location`（Lambda 里手写的字典），而
    panel/Edge 返回的是 `Location`——按 `hd["Location"]` 取就会在 auth 那边拿到
    None，表现为"302 了但没有 Location"这种**根本不可能的产品行为**。
    本脚本第一版就是这样误报了 3 项（/console-session 三条全红），差点让人去
    查一个不存在的缺陷。
    """

    def get(self, key, default=None):        # type: ignore[override]
        lowered = str(key).lower()
        for k, v in self.items():
            if str(k).lower() == lowered:
                return v
        return default


def request(method: str, url: str, *, cookies: dict | None = None,
            body: dict | None = None, headers: dict | None = None,
            follow: bool = False) -> tuple[int, Headers, str]:
    """→ (status, headers, body_text)。**不跟随重定向**（302 本身是断言对象）。"""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("content-type", "application/json")
    if cookies:
        hdrs["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = (urllib.request.build_opener()
              if follow else urllib.request.build_opener(NoRedirect))
    try:
        with opener.open(req, timeout=30) as resp:
            return resp.status, Headers(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, Headers(e.headers), e.read().decode(errors="replace")


def as_json(text: str) -> dict:
    """响应体必须是合法 JSON。

    非法 JSON 一律返回空 dict 而不是抛——但调用方随后的字段断言就会失败，
    于是"接口返回了 HTML 错误页"这种情况会**红**，不会被静默当成通过。
    """
    try:
        out = json.loads(text)
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-on-failure", action="store_true")
    args = ap.parse_args()

    region = cfg("Platform", "region")
    base = cfg("Platform", "base_domain")
    console = f"console.{base}"
    origin = f"https://{console}"
    sites_table = "site-sites"
    routing_table = cfg("Platform", "routing_table")

    ddb = boto3.resource("dynamodb", region_name=region)
    secret = boto3.client("ssm", region_name=region).get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    if not secret:
        sys.exit("取不到 JWT_SECRET —— 无法签发会话，验收不可信")

    # ── fixture：本次专用的站点 + 两个探针身份 ──────────────────────────
    suf = secrets.token_hex(4)
    site_id = f"conse2e-{suf}"
    owner = f"conse2e-owner-{suf}@example.com"
    outsider = f"conse2e-outsider-{suf}@example.com"
    collaborator = f"conse2e-collab-{suf}@example.com"
    created: list[tuple[str, dict]] = []

    # idp 必须取 **Edge 实际信任的那个值**（router/config.ini 的 trusted_idps，
    # CDK synth 时注入 Edge 的 TRUSTED_IDPS）。在这里写死 "Feishu" 会让脚本在
    # 换 IdP 的环境上全红，而红的原因与被测代码无关。
    router_cfg = configparser.ConfigParser(interpolation=None)
    router_cfg.read(HERE.parents[1] / "router" / "config.ini")
    trusted_idp = (router_cfg.get("Edge", "trusted_idps", fallback="")
                   or router_cfg.get("CloudFront", "trusted_idps", fallback=""))
    if not trusted_idp:
        # 段名可能不同，退化成全文件扫这一个键
        for sec in router_cfg.sections():
            if router_cfg.has_option(sec, "trusted_idps"):
                trusted_idp = router_cfg.get(sec, "trusted_idps")
                break
    trusted_idp = trusted_idp.split("#")[0].split(",")[0].strip()
    if not trusted_idp:
        sys.exit("router/config.ini 里找不到 trusted_idps —— "
                 "签出来的会话 Edge 不会认，验收结果不可信")

    def mint(email: str, *, scope: str = "") -> str:
        """与托管登录同形态的会话 JWT（Edge 的 REQUIRE_IDP_CLAIM 要 idp+auth_via）。"""
        return sess.mint_session_jwt(
            email, email.split("@")[0], secret, ttl_seconds=1800,
            idp=trusted_idp, scope=scope,
            auth_via="TokenGeneration_HostedAuth")

    def cookies_for(email: str, *, console_session: bool) -> dict:
        out = {"sb_session": mint(email)}
        if console_session:
            # 面板会话：scope=console 的会话 JWT，与 console_session.py 同形态
            out["__Host-sb_console"] = mint(email, scope="console")
        return out

    try:
        print("── ① 未登录一律 fail-closed ────────────────────────")
        for path, what in (("/", "首页"), ("/api/me", "API"),
                           ("/app.js", "静态 JS"), ("/app.css", "静态 CSS")):
            st, hd, _ = request("GET", origin + path)
            loc = hd.get("Location", "")
            check(st == 302 and f"auth.{base}/login" in loc,
                  f"未登录访问{what} → 302 到登录页", f"{st} {loc[:48]}")

        print("\n── ② 直连 Function URL 必须 403（身份假设的前提）──────")
        route = ddb.Table(routing_table).get_item(
            Key={"subdomain": "console"}, ConsistentRead=True).get("Item") or {}
        fn_url = str(route.get("api_target", ""))
        check(bool(fn_url), "取到 console 的 Function URL")
        if fn_url:
            st, _, _ = request("GET", fn_url.rstrip("/") + "/api/me",
                               headers={"x-user-email": owner})
            # 关键：**即使伪造 x-user-email 也必须 403**——AuthType=AWS_IAM 在
            # 请求到达代码之前就拒了。这条是 handler"x-user-email 存在即来自
            # Edge"这个推论的唯一支撑；它一旦坏掉，整套鉴权失效。
            check(st == 403,
                  "unsigned 直连 Function URL（且伪造 x-user-email）→ 403",
                  f"实际 {st}")

        print("\n── ③ 前端真的能加载（Task 14 的核心）────────────────")
        ck = cookies_for(owner, console_session=False)
        st, hd, page = request("GET", origin + "/", cookies=ck)
        check(st == 200, "带会话访问首页 → 200（不再 403/404）", f"实际 {st}")
        check("<title>Site Builder Console" in page,
              "首页返回的是控制台 HTML", page[:60].replace("\n", " "))
        check('src="/app.js"' in page, "首页引用 /app.js")
        for asset, marker in (("/app.js", "window.addEventListener"),
                              ("/app.css", "--accent")):
            st, hd, text = request("GET", origin + asset, cookies=ck)
            check(st == 200 and marker in text,
                  f"静态资源 {asset} → 200 且内容正确",
                  f"{st}, {len(text)} 字节")
        # 前端产物里不得出现真实账号值（部署产物层面再核一次，不只本地文件）
        st, _, js = request("GET", origin + "/app.js", cookies=ck)
        acct = cfg("Platform", "account_id")
        check(acct not in js and ".lambda-url." not in js,
              "线上前端产物里没有账号 ID / Function URL")

        print("\n── ④ 读接口：站点会话即可 ───────────────────────────")
        st, _, text = request("GET", origin + "/api/me", cookies=ck)
        me = as_json(text)
        check(st == 200 and me.get("email") == owner,
              "GET /api/me → 200 且 email 为当前身份", f"{st} {me.get('email','')[:24]}")
        check(me.get("is_admin") is False,
              "探针身份不是管理员（fail-closed 默认）", str(me.get("is_admin")))

        st, _, text = request("GET", origin + "/api/sites", cookies=ck)
        listing = as_json(text)
        check(st == 200 and isinstance(listing.get("sites"), list),
              "GET /api/sites → 200 且 sites 是数组", f"{st}")
        check(listing.get("sites") == [],
              "新身份看不到任何站点（不是「看到全部」）",
              f"{len(listing.get('sites') or [])} 个")

        print("\n── ⑤ 建 fixture 站点（只此一个，指名清理）──────────")
        ddb.Table(sites_table).put_item(Item={
            "site_id": site_id, "name": f"conse2e-{suf}", "owner": owner,
            "status": "ACTIVE", "require_login": True, "allowed_users": "org",
            "collaborators": [], "created_at": "2026-08-10T00:00:00+00:00",
            "permissions_rev": 0})
        created.append((sites_table, {"site_id": site_id}))
        got = ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True).get("Item")
        check(bool(got), "fixture 站点已建立并强一致读回", site_id)

        st, _, text = request("GET", origin + "/api/sites", cookies=ck)
        mine = as_json(text).get("sites") or []
        check(st == 200 and any(s["site_id"] == site_id for s in mine),
              "owner 能在 /api/sites 里看到自己的站点", f"{len(mine)} 个")
        shaped = next((s for s in mine if s["site_id"] == site_id), {})
        check(shaped.get("role") == "owner", "role 判定为 owner",
              str(shaped.get("role")))
        check(set(shaped) >= {"site_id", "name", "status", "url", "owner",
                              "created_at", "require_login", "allowed_users",
                              "collaborators", "role", "ever_live"},
              "站点形态含全部对外字段（含 ever_live）", f"{len(shaped)} 个字段")
        # ever_live 是"有没有成功上线过"的派生：fixture 站点没有 last_job_id，
        # 所以必须是 False。它决定控制台把 DEPLOYING 显示成"部署中"还是"未上线"。
        check(shaped.get("ever_live") is False,
              "没有 last_job_id 的站点 ever_live=False（控制台据此显示「未上线」）",
              str(shaped.get("ever_live")))

        print("\n── ⑥ 越权：outsider 读不到、也改不了 ────────────────")
        ck_out = cookies_for(outsider, console_session=True)
        st, _, _ = request("GET", origin + f"/api/sites/{site_id}", cookies=ck_out)
        check(st == 403, "非 owner 读该站点 → 403", f"实际 {st}")
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                              cookies=ck_out, body={"require_login": False},
                              headers={"origin": origin})
        check(st == 403, "非 owner 改访问策略 → 403", f"实际 {st}")
        after = ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True)["Item"]
        check(after.get("require_login") is True,
              "越权被拒后线上数据**零改动**", f"require_login={after.get('require_login')}")

        print("\n── ⑦ 写接口必须有面板会话 ───────────────────────────")
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                              cookies=cookies_for(owner, console_session=False),
                              body={"require_login": False},
                              headers={"origin": origin})
        payload = as_json(text)
        check(st == 401 and payload.get("need") == "console-session",
              "无面板会话的写请求 → 401 {need: console-session}",
              f"{st} {payload.get('need')}")

        print("\n── ⑧ CSRF 三形态全拒，且零副作用 ───────────────────")
        ck_w = cookies_for(owner, console_session=True)
        for desc, hdrs in (
                ("Origin 错", {"origin": "https://evil.example.com"}),
                ("缺 Origin", {}),
                ("Origin 是子串前缀", {"origin": f"https://{console}.evil.com"})):
            st, _, _ = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                               cookies=ck_w, body={"require_login": False},
                               headers=hdrs)
            check(st == 403, f"CSRF：{desc} → 403", f"实际 {st}")
        # Content-Type 不对：手工构造，不让 request() 自动补 json
        st, _, _ = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                           cookies=ck_w,
                           headers={"origin": origin,
                                    "content-type": "text/plain"})
        check(st == 403, "CSRF：Content-Type 不是 json → 403", f"实际 {st}")
        after = ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True)["Item"]
        check(after.get("require_login") is True and
              int(after.get("permissions_rev", 0)) == 0,
              "四次 CSRF 被拒后线上数据零改动（rev 未推进）",
              f"rev={after.get('permissions_rev')}")

        print("\n── ⑨ 合法写：改策略 / 协作者 / 转移所有权 ───────────")
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                              cookies=ck_w,
                              body={"require_login": True,
                                    "allowed_users": [owner, collaborator]},
                              headers={"origin": origin})
        check(st == 200, "合法改访问策略 → 200", f"{st} {text[:80]}")
        row = ddb.Table(sites_table).get_item(
            Key={"site_id": site_id}, ConsistentRead=True)["Item"]
        check(sorted(row.get("allowed_users") or []) == sorted([owner, collaborator]),
              "allowed_users 真的写进了 sites 表",
              f"{len(row.get('allowed_users') or [])} 人")
        check(int(row.get("permissions_rev", 0)) == 1, "permissions_rev 推进到 1",
              str(row.get("permissions_rev")))
        rt = ddb.Table(routing_table).get_item(
            Key={"subdomain": f"app-{site_id}"}, ConsistentRead=True).get("Item")
        check(rt is None or int(rt.get("rev", -1)) == 1,
              "路由投影与 sites 表的 rev 一致（或该站点无 route）",
              f"route={'无' if rt is None else rt.get('rev')}")

        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/collaborators",
                              cookies=ck_w, body={"add": [collaborator]},
                              headers={"origin": origin})
        got = as_json(text).get("collaborators") or []
        check(st == 200 and collaborator in got, "增加协作者 → 200 且返回新名单",
              f"{st} {len(got)} 人")
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/collaborators",
                              cookies=ck_w, body={"remove": [collaborator]},
                              headers={"origin": origin})
        check(st == 200 and collaborator not in (as_json(text).get("collaborators") or []),
              "移除协作者 → 200 且名单里没有他了", f"{st}")

        # 转移所有权：转给 collaborator，原 owner 自动降级为协作者
        request("PUT", origin + f"/api/sites/{site_id}/collaborators",
                cookies=ck_w, body={"add": [collaborator]},
                headers={"origin": origin})
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/owner",
                              cookies=ck_w, body={"new_owner": collaborator},
                              headers={"origin": origin})
        out = as_json(text)
        check(st == 200 and out.get("owner") == collaborator,
              "转移所有权 → 200 且 owner 已变", f"{st} {out.get('owner','')[:28]}")
        check(owner in (out.get("collaborators") or []),
              "原 owner 自动降级为协作者（防转错人即失联）")
        # 转移后原 owner 不能再转移（CAPABILITIES 里 collaborator 无此权）
        st, _, _ = request("PUT", origin + f"/api/sites/{site_id}/owner",
                           cookies=ck_w, body={"new_owner": owner},
                           headers={"origin": origin})
        check(st == 403, "降级后的原 owner 不能再转移所有权 → 403", f"实际 {st}")

        print("\n── ⑩ 部署历史 / 未知路由 / admin 名单 ──────────────")
        ck_new = cookies_for(collaborator, console_session=True)
        st, _, text = request("GET", origin + f"/api/sites/{site_id}/jobs",
                              cookies=ck_new)
        check(st == 200 and isinstance(as_json(text).get("jobs"), list),
              "GET jobs → 200 且 jobs 是数组（无部署记录时为空）", f"{st}")

        st, _, text = request("GET", origin + "/api/nonexistent-route",
                              cookies=ck_new)
        check(st == 404, "未知路由（带合法会话）→ 404 而不是 401（不泄漏路由表）",
              f"实际 {st}")

        st, _, text = request("GET", origin + "/api/admins", cookies=ck_new)
        check(st == 403, "非管理员读 admin 名单 → 403", f"实际 {st}")
        st, _, text = request("PUT", origin + "/api/admins", cookies=ck_new,
                              body={"email": outsider}, headers={"origin": origin})
        check(st == 403, "非管理员加管理员 → 403", f"实际 {st}")
        cnt = ddb.Table("site-admins").get_item(
            Key={"email": "__count__"}, ConsistentRead=True).get("Item") or {}
        check(int(cnt.get("n", -1)) == 1,
              "管理员名单未被越权请求改动（__count__ 仍为 1）", f"n={cnt.get('n')}")

        print("\n── ⑪ M4/M5 的接口确实不存在 ────────────────────────")
        for path in ("/api/keys", "/api/analytics", "/api/visitors"):
            st, _, _ = request("GET", origin + path, cookies=ck_new)
            check(st == 404, f"{path} → 404（M4/M5 未实现，前端也不请求它）",
                  f"实际 {st}")

        print("\n── ⑫ 面板会话的边界 ────────────────────────────────")
        # 拿 A 的面板会话配 B 的站点会话：必须拒（换人登录后的残留 cookie）
        mixed = {"sb_session": mint(collaborator),
                 "__Host-sb_console": mint(outsider, scope="console")}
        st, _, text = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                              cookies=mixed, body={"require_login": True},
                              headers={"origin": origin})
        check(st == 401 and as_json(text).get("need") == "console-session",
              "面板会话与站点会话身份不一致 → 401（不是放行）", f"实际 {st}")
        # 站点会话（无 scope）冒充面板会话
        fake = {"sb_session": mint(collaborator),
                "__Host-sb_console": mint(collaborator)}     # 无 scope
        st, _, _ = request("PUT", origin + f"/api/sites/{site_id}/permissions",
                           cookies=fake, body={"require_login": True},
                           headers={"origin": origin})
        check(st == 401, "无 scope 的会话冒充面板会话 → 401", f"实际 {st}")

        print("\n── ⑬ 正常双表事务路径（站点**有** route item）──────")
        # 上面的 fixture 站点没有 route item，走的是 write_permissions 的**降级**
        # 路径。正常路径（sites + routing 双表原子事务）必须单独覆盖：真机上这两
        # 条路径要的 IAM 权限不同（降级路径需要路由表的 ConditionCheckItem，
        # 正是 Task 14 Step 3 实测发现 panel role 漏掉的那条），只测一条会漏。
        rt_site = f"{site_id}-rt"
        rt_sub = f"app-{rt_site}"
        ddb.Table(sites_table).put_item(Item={
            "site_id": rt_site, "name": rt_site, "owner": owner,
            "status": "ACTIVE", "require_login": True, "allowed_users": "org",
            "collaborators": [], "created_at": "2026-08-10T00:00:00+00:00",
            "permissions_rev": 0})
        created.append((sites_table, {"site_id": rt_site}))
        ddb.Table(routing_table).put_item(Item={
            "subdomain": rt_sub, "site_id": rt_site, "route_mode": "api-only",
            "static_prefix": "", "api_target": "https://placeholder.invalid",
            "require_auth": True, "allowed_users": "org", "owner": owner,
            "collaborators": [], "permissions_rev": 0})
        created.append((routing_table, {"subdomain": rt_sub}))

        ck_rt = cookies_for(owner, console_session=True)
        st, _, text = request("PUT", origin + f"/api/sites/{rt_site}/permissions",
                              cookies=ck_rt,
                              body={"require_login": True,
                                    "allowed_users": [owner]},
                              headers={"origin": origin})
        check(st == 200, "有 route 的站点改策略 → 200（正常双表事务）",
              f"{st} {text[:60]}")
        rt_row = ddb.Table(routing_table).get_item(
            Key={"subdomain": rt_sub}, ConsistentRead=True).get("Item") or {}
        check(int(rt_row.get("permissions_rev", -1)) == 1,
              "路由投影同步更新到 rev=1（Edge 读得到新策略）",
              str(rt_row.get("permissions_rev")))
        check(list(rt_row.get("allowed_users") or []) == [owner],
              "路由投影的 allowed_users 已同步",
              str(rt_row.get("allowed_users"))[:40])
        # register_route 是整条 put_item（原子切流），write_permissions 只能
        # update 权限字段——踩掉 api_target 会让站点立刻 502
        check(rt_row.get("api_target") == "https://placeholder.invalid",
              "路由的 api_target 未被踩掉（只 update 权限字段）",
              str(rt_row.get("api_target")))

        print("\n── ⑭ /console-session 升级入口 ─────────────────────")
        st, hd, _ = request("GET", f"https://auth.{base}/console-session",
                            cookies={"sb_session": mint(owner)})
        loc = hd.get("Location", "")
        check(st == 302 and f"console.{base}/api/session-callback?code=" in loc,
              "带会话访问 /console-session → 302 到 callback 且带 code",
              f"{st} {loc.split('?')[0][-40:]}")
        code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
        check(bool(code), "拿到一次性升级 code", f"{len(code)} 字符")
        if code:
            cb = origin + "/api/session-callback?code=" + urllib.parse.quote(code)
            st, hd, _ = request("GET", cb, cookies={"sb_session": mint(owner)})
            setc = hd.get("Set-Cookie", "")
            check(st == 302 and "__Host-sb_console=" in setc,
                  "消费 code → 302 且 Set-Cookie __Host-sb_console", f"{st}")
            check("HttpOnly" in setc and "Secure" in setc and "Domain=" not in setc,
                  "面板 cookie 是 HttpOnly+Secure 且无 Domain（__Host- 前缀要求）")
            st, _, text = request("GET", cb, cookies={"sb_session": mint(owner)})
            check(st == 401, "同一个 code 重放 → 401（jti 已原子消费）", f"实际 {st}")
        st, hd, _ = request("GET", f"https://auth.{base}/console-session")
        check(st == 302 and "/login?redirect=" in hd.get("Location", "")
              and "console-session" in urllib.parse.unquote(hd.get("Location", "")),
              "无会话访问 /console-session → 先登录且**回到本入口**",
              hd.get("Location", "")[:56])

    finally:
        keep = args.keep_on_failure and FAILURES > 0
        print("\n── 清理 fixture ────────────────────────────────────")
        if keep:
            print(f"  --keep-on-failure 且有失败：保留 {site_id}（记得手工删）")
        else:
            for table, key in created:
                ddb.Table(table).delete_item(Key=key)
                # delete-item 返回 0 不等于真删掉了 —— 强一致读回核对
                still = ddb.Table(table).get_item(
                    Key=key, ConsistentRead=True).get("Item")
                check(still is None, f"已删除并读回确认 {table} {list(key.values())[0]}",
                      "已不存在" if still is None else "**仍存在**")

    print()
    if CHECKS < MIN_CHECKS:
        print(f"❌ 只跑了 {CHECKS} 项（下限 {MIN_CHECKS}）——脚本中途退出，"
              f"结果不可信")
        return 1
    print(f"结果：{CHECKS - FAILURES}/{CHECKS} 项通过")
    if FAILURES:
        return 1
    print("\n仍需人工在真浏览器里确认的两项（本脚本无法覆盖）：")
    print(f"  · 完整登录流：无痕窗口开 {origin}/ → 飞书同意页 → 回到控制台首页")
    print("  · 浏览器真的接受了 __Host-sb_console（DevTools > Application > Cookies）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
