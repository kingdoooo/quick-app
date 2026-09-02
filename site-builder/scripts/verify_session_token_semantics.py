#!/usr/bin/env python3
"""会话 token 语义的**真机行为**闸门（token 用途混用 + 同名 cookie 遮蔽）。

**只发 GET，不写任何数据**，所以可以随时对生产跑；目标站点从路由表里现取一个
`require_auth=True` 的行，不新建夹具（`_session_mint.live_target`）。

为什么需要它：其余闸门对这两条只有**静态**证据。`verify_deployed_edge.sh` 证明
"线上产物 == 这份源码"，单测证明"这份源码行为正确"，两者相乘是很强的链条，但没有
任何一条真机请求走过那两个分支。而它们恰好是"旧版 Edge 也会让正常探针通过"的那种
缺陷，所以业务验收在结构上分辨不出新旧。这个脚本发的是**只有新版才会答对**的请求。

判据（七条，含正负对照；3c-1B ticket 01 起全部按新形态——token 由 `_session_mint`
用 current key 签出、带 kid）：
  · 遮蔽 cookie 排在合法会话**之前**时，`/console-session` 仍须换出升级码；
  · 同上，Edge 侧站点请求仍须放行（必须 200，非 302 不算：403/500 也非 302）；14 条遮蔽亦然；
  · console kid 的升级码当站点会话递给 Edge，必须被拒（Edge 的 allowlist 里没有 console family）；
  · console kid 的面板会话当站点会话递给 Edge，必须被拒（同上；用途混用的另一半）；
  · 正对照：单枚合法会话必须能进（否则上面几条 302 证明不了任何东西）；
  · 负对照：无 cookie 必须 302（确认 fail-closed 没被这些改动弄坏）。

**HTTP 头按小写取**：CloudFront 会把 `Location` 规范成小写，而 Edge 自己生成的
302 保留大写——写死大小写会让一半用例假红（实测踩过）。
判定逻辑是纯函数（run_checks），`--self-test` 不碰 AWS。用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import _session_mint as sm  # noqa: E402

GARBAGE = "garbage.garbage.garbage"


@dataclass(frozen=True)
class Tokens:
    good: str              # current site kid 的站点会话
    upgrade: str           # current console kid 的升级码
    console_session: str   # current console kid 的面板会话


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _login_302(st, hd, auth_host) -> bool:
    return st == 302 and f"{auth_host}/login" in hd.get("location", "")


def run_checks(get, tokens: Tokens, *, site_url: str, auth_host: str) -> list:
    """get(url, cookie_header) -> (status, lowercase_headers)。纯函数，无 AWS。"""
    out = []

    def add(name, ok, detail=""):
        out.append(Check(name, ok, detail))

    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={GARBAGE}; sb_session={tokens.good}")
    add("M06 auth：遮蔽 cookie 在前仍换出升级 code（修复前这里 302 去 /login）",
        st == 302 and "session-callback?code=" in hd.get("location", ""), f"{st}")
    st, hd = get(site_url, f"sb_session={GARBAGE}; sb_session={tokens.good}")
    add("M06 Edge：遮蔽 cookie 在前仍放行（必须 200）", st == 200, f"{st}")
    burst = "; ".join(f"sb_session=shadow{i}" for i in range(14))
    st, hd = get(site_url, f"{burst}; sb_session={tokens.good}")
    add("M06 Edge：14 条遮蔽 cookie 压在前面仍放行（console 4 段路径的真实量级）", st == 200, f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.upgrade}")
    add("M05 Edge：console kid 的升级码当站点会话被拒（allowlist 无 console）", _login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.console_session}")
    add("M05 Edge：console kid 的面板会话当站点会话被拒（allowlist 无 console）", _login_302(st, hd, auth_host), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.good}")
    add("正对照：单枚合法会话正常放行（200）", st == 200, f"{st}")
    st, hd = get(site_url, "")
    add("负对照：无 cookie 302 到登录（fail-closed 仍在）", _login_302(st, hd, auth_host), f"{st}")
    return out


def render(checks: list) -> int:
    for c in checks:
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.name}   [{c.detail}]")
    failed = sum(1 for c in checks if not c.ok)
    print(f"\n结果：{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


# ---- 自测 -------------------------------------------------------------------------------------

def _ideal_responder(*, break_shadow: bool = False, break_mixuse: bool = False):
    """理想 verifier：只认 GOOD；`break_shadow` 模拟修复前"只取第一条 cookie"；`break_mixuse` 模拟
    Edge 不分 family（console kid 也放行）。"""
    login = {"location": "https://auth.example.test/login?redirect=x"}

    def get(url, cookie_header):
        vals = [p.partition("=")[2] for p in cookie_header.split(";") if p.strip().startswith("sb_session=")]
        candidates = vals[:1] if break_shadow else vals
        accepted = any(v == "GOOD" or (break_mixuse and v in ("UPG", "CONS")) for v in candidates)
        if url.endswith("/console-session"):
            return (302, {"location": "https://console.example.test/api/session-callback?code=x"}) if accepted \
                else (302, login)
        return (200, {}) if accepted else (302, login)
    return get


def self_test(**flags) -> int:
    checks = run_checks(_ideal_responder(**flags), Tokens(good="GOOD", upgrade="UPG", console_session="CONS"),
                        site_url="https://app-x.example.test/", auth_host="auth.example.test")
    return 1 if any(not c.ok for c in checks) else 0


# ---- 真机 -------------------------------------------------------------------------------------

def _http_get(url: str, cookie_header: str):
    req = urllib.request.Request(url, method="GET", headers={"cookie": cookie_header})

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    try:
        with urllib.request.build_opener(NoRedir).open(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="不碰 AWS：理想应答器全绿、遮蔽/混用两种坏路径各自必红")
    args = ap.parse_args(argv)
    if args.self_test:
        ok = self_test() == 0 and self_test(break_shadow=True) != 0 and self_test(break_mixuse=True) != 0
        print("self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    minter = sm.Minter.from_config()
    target = sm.live_target()
    owner = target.owner
    tokens = Tokens(good=minter.mint("site-session", owner, ttl_seconds=600),
                    upgrade=minter.mint("console-upgrade", owner, ttl_seconds=60),
                    console_session=minter.mint("console-session", owner, ttl_seconds=600))
    print(f"探针目标：站点 {target.subdomain}.{target.base}（需登录），owner={owner.split('@')[0]}@…；"
          f"kid={minter.keys.families['site']['current'].kid}/{minter.keys.families['console']['current'].kid}")
    return render(run_checks(_http_get, tokens, site_url=target.site_url, auth_host=target.auth_host))


if __name__ == "__main__":
    sys.exit(main())
