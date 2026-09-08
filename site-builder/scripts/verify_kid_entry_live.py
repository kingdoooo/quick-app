#!/usr/bin/env python3
"""kid 入口与 key 轮转的**真机**正向/负向证据（默认只发 GET，不写任何数据）。

三种模式，判定逻辑都是纯函数、`--self-test` 不碰 AWS（deployer/tests/test_verify_kid_entry_live.py 也跑）：

- 默认（三条判据 + 一条负对照）：夹具会话打**常驻夹具站点**必须 **200**（不是"非 302"——403/500/502
  也非 302，那分不清放行与站点故障）；未知 kid 必须 302 且不回落；auth 的 `/console-session` 对夹具
  会话必须换出升级码。
- `--role current|previous`（就位/切换/回滚演练）：该 role 的站点会话必须 200；再拿它走**真实**换取
  链路（auth `/console-session` → panel `/api/session-callback`）必须换出 `__Host-sb_console`。
  **这一条会消费一枚升级码**（session-codes 表多一行，1 h TTL 自动清）——是本脚本唯一的写副作用，
  只在给了 --role 时发生。
- `--retired-token FILE`（可重复；退役旧 kid 之后）：用 `_session_mint --save` 预存的 token 必须被
  明确拒绝：站点会话 → Edge 302 到登录且 auth `/console-session` 302 到登录；升级码 → panel 401。
  500 不算被拒。§5 合同里 kid 先于 exp，所以过期与否不影响结论。面板会话（console-session）记录
  **不接受**：panel 只在写请求上验它，本脚本不发写请求，请预存 console-upgrade 记录。

**跨 family 与用途混用不在这里**（plan D3）：3c-final 之后没有任何组件能带外签 console family 的
token，那两种反例造不出来了。它们的证据是 `site-builder/auth/tests/test_verifier_allowlist.py` 的
token_use 矩阵与 `router/infrastructure/lambda/test_edge_kid_allowlist.py::test_console_kid_is_not_in_the_edge_allowlist`，
加上 `verify_deployed_edge.sh` 对线上 Edge 里公钥的精确对账。

登录态一律经 `_session_mint`（夹具签发器客户端，ADR 0002）：本脚本不持有任何密钥。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
import _session_mint as sm  # noqa: E402

# 未知 kid：**不许**与 config.ini 里任何 [SessionKey:*] 小节同名，否则这条判据会变成
# "已配置的 key 被拒"（那是另一回事，且会假红）。verify_session_token_semantics.py 里有同形态的
# 一份——两处都是**故意无效**的 token，不放进 _session_mint（那个模块的契约是"取真凭据的唯一入口"）。
UNKNOWN_KID = "site-rs-v9"


@dataclass(frozen=True)
class Tokens:
    site_kid: str          # 夹具签发器给的站点会话（site current kid；新入口正向）
    unknown_kid: str       # header 带未知 kid（本地造，不需要任何密钥）


@dataclass(frozen=True)
class RoleTokens:
    role: str
    site: str                    # 该 role 的站点会话
    console_cookie: str | None   # 真实换取链路换出的面板会话（None = 没换出来，见上面打印的原因）


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _is_login_302(st, hd, auth_host=None) -> bool:
    loc = hd.get("location", "")
    return st == 302 and ("/login" in loc) and (auth_host is None or auth_host in loc)


def run_checks(get, tokens: Tokens, *, site_url: str, auth_host: str) -> list:
    """get(url, cookie_header) -> (status, lowercase_headers)。纯函数，无 AWS。"""
    out = []

    def add(name, ok, detail):
        out.append(Check(name, ok, detail))

    st, hd = get(site_url, "")
    add("负对照：无 cookie 302 到登录（fail-closed）", _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.site_kid}")
    add("新入口：夹具会话进夹具站点放行（必须 200，非 302 不算）", st == 200, f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.unknown_kid}")
    add("新入口：未知 kid 不回落（kid 查表先于验签 ⇒ 只错 kid 这一个变量）",
        _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tokens.site_kid}")
    add("auth：夹具会话换出升级码", st == 302 and "session-callback?code=" in hd.get("location", ""), f"{st}")
    return out


def run_role_checks(get, rt: RoleTokens, *, site_url: str) -> list:
    """就位/切换/回滚：该 role 的会话必须**可用**——站点 200，且能走完真实换取链路。500 不算可用。

    面板会话那条由 `_session_mint.console_session` 走真实链路换取（auth → panel），
    换不出来时调用方把 `console_cookie` 置 None 并已打印原因，这里只负责把它记成一条判据
    ——不能让它以裸 SystemExit 结束，那样报告里既没有 FAIL 行也没有"N 项失败"的总结。
    """
    out = []
    st, hd = get(site_url, f"sb_session={rt.site}")
    out.append(Check(f"role={rt.role}：站点会话放行（必须 200）", st == 200, f"{st}"))
    out.append(Check(f"role={rt.role}：真实换取链路换出面板会话（__Host-sb_console）",
                     bool(rt.console_cookie), "已换出" if rt.console_cookie else "没换出来"))
    return out


def run_retired_checks(get, retired: list, *, site_current: str, site_url: str, auth_host: str,
                       console_host: str) -> list:
    """退役后：预存 token 必须被**明确**拒绝（302 到登录 / 401），200 与 500 都红。"""
    for use, _ in retired:
        if use not in ("site-session", "console-upgrade"):
            raise SystemExit(f"退役探针只接受 site-session / console-upgrade 记录，得到 {use!r}——"
                             "panel 只在写请求上验面板会话，本脚本只发 GET，请预存 console-upgrade 记录")
    out = []
    st, hd = get(site_url, f"sb_session={site_current}")
    out.append(Check("正对照：current 站点会话 200（否则下面的拒绝证明不了任何东西）", st == 200, f"{st}"))
    for use, tok in retired:
        if use == "site-session":
            st, hd = get(site_url, f"sb_session={tok}")
            out.append(Check("退役 key 的站点会话被 Edge 拒（302 到登录）", _is_login_302(st, hd, auth_host), f"{st}"))
            st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tok}")
            out.append(Check("退役 key 的站点会话在 auth 换不出升级码（302 到登录）", _is_login_302(st, hd), f"{st}"))
        else:
            cb = f"https://{console_host}/api/session-callback?code={urllib.parse.quote(tok, safe='')}"
            st, hd = get(cb, f"sb_session={site_current}")
            out.append(Check("退役 key 的升级码被 panel 拒（401）", st == 401, f"{st}"))
    return out


def render(checks: list) -> int:
    for c in checks:
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.name}   [{c.detail}]")
    failed = sum(1 for c in checks if not c.ok)
    print(f"\n结果：{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


def _unknown_kid_token(email: str) -> str:
    """header 带未知 kid 的 token。**本地造，不需要任何密钥**：verifier 的 kid 查表在验签之前，
    所以签名段只要是合法 base64url 就够（256 字节 = RSA-2048 签名的长度）。"""
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    h = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": UNKNOWN_KID}).encode())
    p = b64(json.dumps({"token_use": "site-session", "aud": "site-edge", "email": email,
                        "name": email.split("@")[0], "iat": now, "exp": now + 600}).encode())
    return f"{h}.{p}.{b64(os.urandom(256))}"


# ---- 自测：理想应答器 / 坏掉的路径 ------------------------------------------------------------

def _ideal_responder(*, break_allow_path: bool = False, break_unknown_kid: bool = False,
                     break_role_path: bool = False, break_retired_path: bool = False):
    """理想应答器 + 四条可单独打断的路径。

    `break_allow_path` 覆盖"合法 current 会话可用"那一族（站点 200 + auth 换出升级码）；
    `break_unknown_kid` 覆盖唯一的负向断言——`UNKNOWN` 在理想应答器里**永远**落到 `302, login`，
    没有它那条断言在自测里不可能红，而"未知 kid 不回落"正是新 kid 入口区别于旧代码的性质
    （元用例 `test_every_default_assertion_has_some_break_path_that_makes_it_red` 抓这个）；
    另两条覆盖 `--role` 与 `--retired-token` 两种模式。
    """
    login = {"location": "https://auth.example.test/login?redirect=x"}

    def cookies(header):
        return {k.strip(): v for k, _, v in (p.partition("=") for p in header.split(";") if "=" in p)}

    def get(url, cookie_header):
        ck = cookies(cookie_header)
        host = url.split("//")[1].split("/")[0]
        if host.startswith("console.") and "session-callback" in url:
            code = urllib.parse.unquote(url.split("code=")[1])
            if not ck.get("sb_session", "").startswith(("SITE", "PREVS")):
                return 302, login
            if code.startswith("RETIRED"):
                return (302, {"set-cookie": "__Host-sb_console=x"}) if break_retired_path else (401, {})
            return 401, {}
        token = ck.get("sb_session", "")
        if url.endswith("/console-session"):
            # break_allow_path 也覆盖这条**正向**断言（合法夹具会话必须能换出升级码）：
            # 否则它在自测里没有任何坏路径能让它红。
            if break_allow_path and token.startswith("SITE"):
                return 302, login
            if token.startswith(("SITE", "PREVS")):
                return 302, {"location": "https://console.example.test/api/session-callback?code=x"}
            return 302, login
        if token.startswith("RETIRED"):
            return (200, {}) if break_retired_path else (302, login)
        if token.startswith("PREVS"):
            return (500, {}) if break_role_path else (200, {})
        if token.startswith("SITE"):
            return (500, {}) if break_allow_path else (200, {})
        # break_unknown_kid：verifier 对未知 kid 回落 ⇒ 本该被拒的那一枚被放行
        if break_unknown_kid and token.startswith("UNKNOWN"):
            return 200, {}
        return 302, login
    return get


def self_test(*, break_allow_path: bool = False, break_unknown_kid: bool = False,
              break_role_path: bool = False, break_retired_path: bool = False) -> int:
    get = _ideal_responder(break_allow_path=break_allow_path, break_unknown_kid=break_unknown_kid,
                           break_role_path=break_role_path, break_retired_path=break_retired_path)
    site, auth, console = "https://app-e2e-probe.example.test/", "auth.example.test", "console.example.test"
    checks = run_checks(get, Tokens(site_kid="SITE.x.y", unknown_kid="UNKNOWN.x.y"),
                        site_url=site, auth_host=auth)
    checks += run_role_checks(get, RoleTokens(role="previous", site="PREVS.x.y",
                                              console_cookie=None if break_role_path else "COOKIE.x.y"),
                              site_url=site)
    checks += run_retired_checks(get, [("site-session", "RETIRED-S.x.y"), ("console-upgrade", "RETIRED-C.x.y")],
                                 site_current="SITE.x.y", site_url=site, auth_host=auth, console_host=console)
    return 1 if any(not c.ok for c in checks) else 0


# ---- 真机 ------------------------------------------------------------------------------------

def _http_get(url: str, cookie_header: str):
    req = urllib.request.Request(url, method="GET", headers={"cookie": cookie_header})

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    def headers(h):
        out = {k.lower(): v for k, v in h.items()}
        out["set-cookie"] = "; ".join(h.get_all("Set-Cookie") or [])   # 多个 Set-Cookie 不能只留最后一个
        return out

    try:
        with urllib.request.build_opener(NoRedir).open(req, timeout=30) as r:
            return r.status, headers(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, headers(e.headers)


def _live(role: str | None, retired_files: list):
    minter = sm.Minter.from_config()
    target = sm.live_target()
    site_cur = minter.site_session(sm.PROBE_EMAIL)
    print(f"探针目标：常驻夹具站点 {target.subdomain}.{target.base}（需登录，owner={sm.PROBE_EMAIL}）")
    checks = run_checks(_http_get, Tokens(site_kid=site_cur,
                                          unknown_kid=_unknown_kid_token(sm.PROBE_EMAIL)),
                        site_url=target.site_url, auth_host=target.auth_host)
    if role:
        print(f"（--role {role}：面板会话那一条会消费一枚升级码，session-codes 表多一行，1 h TTL）")
        role_site = minter.site_session(sm.PROBE_EMAIL, role=role)
        try:
            # 真实换取链路：auth /console-session → panel /api/session-callback（都用这枚 role 会话）
            console_cookie = minter.console_session(sm.PROBE_EMAIL, site_session=role_site)
        except SystemExit as exc:      # 换不出来是**判据失败**，不是脚本崩溃：记成一条 FAIL 继续
            print(f"  （面板会话没换出来：{exc}）")
            console_cookie = None
        checks += run_role_checks(_http_get, RoleTokens(role=role, site=role_site,
                                                       console_cookie=console_cookie),
                                  site_url=target.site_url)
    if retired_files:
        retired = [sm.load_saved_token(Path(f)) for f in retired_files]
        checks += run_retired_checks(_http_get, retired, site_current=site_cur, site_url=target.site_url,
                                     auth_host=target.auth_host, console_host=target.console_host)
    return checks


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="不碰 AWS：理想应答器全绿、**四**种坏路径各自必红")
    ap.add_argument("--role", choices=("current", "previous"),
                    help="就位/切换/回滚：该 role 的站点会话必须 200、并能走真实链路换出面板会话（会消费一枚升级码）")
    ap.add_argument("--retired-token", action="append", default=[], metavar="FILE",
                    help="_session_mint --save 写出的记录；退役后必须被明确拒绝（可重复）")
    args = ap.parse_args(argv)
    if args.self_test:
        ok = (self_test() == 0 and self_test(break_allow_path=True) != 0
              and self_test(break_unknown_kid=True) != 0 and self_test(break_role_path=True) != 0
              and self_test(break_retired_path=True) != 0)
        print("self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    return render(_live(args.role, args.retired_token))


if __name__ == "__main__":
    sys.exit(main())
