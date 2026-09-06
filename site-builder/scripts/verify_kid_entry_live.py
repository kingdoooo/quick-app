#!/usr/bin/env python3
"""kid 入口与 key 轮转的**真机**正向/负向证据（默认只发 GET，不写任何数据）。

三种模式，判定逻辑都是纯函数、`--self-test` 不碰 AWS（deployer/tests/test_verify_kid_entry_live.py 也跑）：

- 默认：新入口在真机上通。用 site family 的 current key 本地 mint 一枚带 kid 的站点会话打一个
  require_auth=True 的站点必须 **200**（不是"非 302"——403/500/502 也非 302，那分不清放行与站点故障）；
  console kid 的同形态 token 必须 302；未知 kid 必须 302 且不回落；auth 的 /console-session 对 kid 形态
  会话必须换出升级码。legacy 入口还开着时另有一条 legacy 正对照（关闭后该条不出现）。
- `--role current|previous`（3c-1B 演练的就位/切换/回滚步骤）：该 role 的站点会话必须 200；该 role 的
  升级码走 panel 的 /api/session-callback 必须换出面板 cookie。**这一条会消费一枚自签升级码**
  （session-codes 表多一行，1 h TTL 自动清）——是本脚本唯一的写副作用，只在给了 --role 时发生。
- `--retired-token FILE`（可重复；关闭 legacy / 退役 v1 之后）：用 `_session_mint --save` 预存的
  token 必须被明确拒绝：站点会话 → Edge 302 到登录且 auth /console-session 302 到登录；升级码 →
  panel 401。500 不算被拒。§5 合同里 kid 先于 exp，所以过期与否不影响结论。面板会话（console-session）
  记录**不接受**：panel 只在写请求上验它，本脚本不发写请求，请预存 console-upgrade 记录。

token 由 `_session_mint` 统一签发（今天冒充目标站点真实 owner，2A 换夹具身份）。用不带路径的
python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import _session_mint as sm  # noqa: E402


@dataclass(frozen=True)
class Tokens:
    legacy: str | None     # 今天的形态（正对照）；legacy 入口关闭后为 None，该条不出现
    site_kid: str          # site current 签的站点会话（新入口正向）
    # 下面两枚**各自只改一个变量**，这是它们能证明东西的全部原因（3c-1B-G A1）：
    console_kid: str       # console kid + token_use=**site-session** ⇒ 只改 kid family
    unknown_kid: str       # header 带未知 kid（不回落）
    wrong_use: str         # site kid + token_use=console-session ⇒ 只改 token_use


@dataclass(frozen=True)
class RoleTokens:
    role: str
    site: str              # 该 role 的站点会话
    upgrade: str           # 该 role 的升级码（走 panel 链路）
    site_current: str      # 过 Edge 到 console 主机用的当前站点会话


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

    if tokens.legacy is not None:
        st, hd = get(site_url, f"sb_session={tokens.legacy}")
        add("正对照：legacy 会话仍 200 放行（L1/L2：存量形态零影响）", st == 200, f"{st}")
    st, hd = get(site_url, "")
    add("负对照：无 cookie 302 到登录（fail-closed）", _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.site_kid}")
    add("新入口：site kid 签的站点会话放行（必须 200，非 302 不算）", st == 200, f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.console_kid}")
    add("新入口：console kid 签的**站点会话形态** token 被 Edge 拒（证明 site allowlist 无 console）",
        _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.unknown_kid}")
    add("新入口：未知 kid 不回落 legacy", _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.wrong_use}")
    add("新入口：site kid 签的 token_use=console-session 被 Edge 拒（证明 token_use 比较）",
        _is_login_302(st, hd, auth_host), f"{st}")
    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tokens.site_kid}")
    add("auth：kid 形态会话换出升级码", st == 302 and "session-callback?code=" in hd.get("location", ""), f"{st}")
    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tokens.console_kid}")
    add("auth：console kid 的 token 换不出升级码", _is_login_302(st, hd), f"{st}")
    return out


def run_role_checks(get, rt: RoleTokens, *, site_url: str, console_host: str) -> list:
    """就位/切换/回滚：该 role 的两个 family 都必须**可用**（200 / 换出面板 cookie），500 不算。"""
    out = []
    st, hd = get(site_url, f"sb_session={rt.site}")
    out.append(Check(f"role={rt.role}：站点会话放行（必须 200）", st == 200, f"{st}"))
    cb = f"https://{console_host}/api/session-callback?code={urllib.parse.quote(rt.upgrade, safe='')}"
    st, hd = get(cb, f"sb_session={rt.site_current}")
    out.append(Check(f"role={rt.role}：升级码经 panel 换出面板 cookie（302 + __Host-sb_console）",
                     st == 302 and "__Host-sb_console=" in hd.get("set-cookie", ""), f"{st}"))
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


# ---- 自测：理想应答器 / 坏掉的路径 ------------------------------------------------------------

def _ideal_responder(*, break_allow_path: bool = False, break_role_path: bool = False,
                     break_retired_path: bool = False, break_family: bool = False):
    """理想应答器 + 四条可单独打断的路径。

    `break_allow_path` 覆盖"合法 current 会话可用"那一族（站点 200 + auth 换出升级码）；
    `break_family` 是 3c-1B ticket 17 第 14 条补的：其余三个旗标都动不了 `CONSOLE` / `UNKNOWN` /
    `WRONG` 三种 token（它们一律落到最后那个 `302, login`），于是四条**负向**断言在自测里不可能红
    ——而"console kid 不进 site allowlist""未知 kid 不回落 legacy""token_use 不能混用"正是新入口
    区别于 3c-1A 之前那份代码的全部性质。这个旗标模拟"verifier 对 family/kid/用途都不挑"，
    让那四条能被证明真的会红。
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
            if code.startswith("PREVC"):
                return (500, {}) if break_role_path else (302, {"set-cookie": "__Host-sb_console=x; Secure"})
            return 401, {}
        token = ck.get("sb_session", "")
        if url.endswith("/console-session"):
            # break_allow_path 也覆盖这条**正向**断言（合法 site kid 会话必须能换出升级码）：
            # 否则它在自测里没有任何坏路径能让它红（元用例
            # test_every_default_assertion_has_some_break_path_that_makes_it_red 抓到过）。
            if break_allow_path and token.startswith("SITE"):
                return 302, login
            # break_family：auth 也不挑 family ⇒ console kid 的会话照样换出升级码
            if token.startswith(("SITE", "PREVS")) or (break_family and token.startswith("CONSOLE")):
                return 302, {"location": "https://console.example.test/api/session-callback?code=x"}
            return 302, login
        if token.startswith("RETIRED"):
            return (200, {}) if break_retired_path else (302, login)
        if token.startswith("PREVS"):
            return (500, {}) if break_role_path else (200, {})
        if token.startswith(("LEGACY", "SITE")):
            return (500, {}) if (break_allow_path and token.startswith("SITE")) else (200, {})
        # break_family：Edge 对 family/未知 kid/用途都不挑 ⇒ 三种本该被拒的 token 全被放行
        if break_family and token.startswith(("CONSOLE", "UNKNOWN", "WRONG")):
            return 200, {}
        return 302, login
    return get


def self_test(*, break_allow_path: bool = False, break_role_path: bool = False,
              break_retired_path: bool = False, break_family: bool = False) -> int:
    get = _ideal_responder(break_allow_path=break_allow_path, break_role_path=break_role_path,
                           break_retired_path=break_retired_path, break_family=break_family)
    site, auth, console = "https://app-x.example.test/", "auth.example.test", "console.example.test"
    checks = run_checks(get, Tokens(legacy="LEGACY.x.y", site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                                    unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y"),
                        site_url=site, auth_host=auth)
    checks += run_role_checks(get, RoleTokens(role="previous", site="PREVS.x.y", upgrade="PREVC.x.y",
                                              site_current="SITE.x.y"), site_url=site, console_host=console)
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


def _unknown_kid_token(minter: sm.Minter, owner: str, idp: str) -> str:
    """header 带未知 kid 的 token。签名用哪把 key 都不该被认（kid 查表在验签之前）；有 legacy 时用
    legacy 密钥签，证明"不回落"；legacy 关闭后用 site current 签。"""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "site-hs-v99"}).encode())
    p = b64(json.dumps({"typ": "session", "email": owner, "exp": int(time.time()) + 600,
                        "idp": idp, "auth_via": sm.AUTH_VIA}).encode())
    _, secret = minter.key("site", "legacy" if minter.keys.legacy_param else "current")
    return f"{h}.{p}." + b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


def _live(role: str | None, retired_files: list):
    minter = sm.Minter.from_config()
    target = sm.live_target()
    owner = target.owner
    mint = lambda use, r="current", fam=None: minter.mint(use, owner, role=r, ttl_seconds=600,
                                                          family=fam)
    site_cur = mint("site-session")
    print(f"探针目标：站点 {target.subdomain}.{target.base}（需登录），owner={owner.split('@')[0]}@…；"
          f"site current={minter.keys.families['site']['current'].kid}")
    checks = run_checks(_http_get, Tokens(
        legacy=mint("site-session", "legacy") if minter.keys.legacy_param else None,
        # **跨 family 同形态**：console kid 签的 site-session。只改 kid family 这一个变量，
        # 所以它的 302 只能来自 allowlist（见 `Tokens` 上的注释与 A1 的 Edge 侧反例用例）。
        site_kid=site_cur, console_kid=mint("site-session", fam="console"),
        unknown_kid=_unknown_kid_token(minter, owner, sm.trusted_idp()),
        wrong_use=_wrong_use_token(minter, owner)),
        site_url=target.site_url, auth_host=target.auth_host)
    if role:
        print(f"（--role {role}：console 那一条会消费一枚自签升级码，session-codes 表多一行，1 h TTL）")
        checks += run_role_checks(_http_get, RoleTokens(role=role, site=mint("site-session", role),
                                                        upgrade=mint("console-upgrade", role), site_current=site_cur),
                                  site_url=target.site_url, console_host=target.console_host)
    if retired_files:
        retired = [sm.load_saved_token(Path(f)) for f in retired_files]
        checks += run_retired_checks(_http_get, retired, site_current=site_cur, site_url=target.site_url,
                                     auth_host=target.auth_host, console_host=target.console_host)
    return checks


def _wrong_use_token(minter: sm.Minter, owner: str) -> str:
    """site kid 签的 token_use=console-session（Edge 必拒 wrong_token_use）。"""
    import session as sess
    kid, secret = minter.key("site", "current")
    return sess.mint_token(kid=kid, secret=secret, token_use="console-session", email=owner,
                           ttl_seconds=600, name=owner.split("@")[0])


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="不碰 AWS：理想应答器全绿、**四**种坏路径各自必红")
    ap.add_argument("--role", choices=("current", "previous"),
                    help="就位/切换/回滚：该 role 的站点会话必须 200、升级码经 panel 换出面板 cookie（会消费一枚升级码）")
    ap.add_argument("--retired-token", action="append", default=[], metavar="FILE",
                    help="_session_mint --save 写出的记录；退役后必须被明确拒绝（可重复）")
    args = ap.parse_args(argv)
    if args.self_test:
        ok = (self_test() == 0 and self_test(break_allow_path=True) != 0
              and self_test(break_role_path=True) != 0 and self_test(break_retired_path=True) != 0
              and self_test(break_family=True) != 0)
        print("self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    return render(_live(args.role, args.retired_token))


if __name__ == "__main__":
    sys.exit(main())
