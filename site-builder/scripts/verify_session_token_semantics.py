#!/usr/bin/env python3
"""会话 token 语义的**真机行为**闸门（同名 cookie 遮蔽 + kid 入口 + 夹具身份边界）。

**只发 GET，不写任何数据**，所以可以随时对生产跑；打的是**常驻夹具站点**
（`_session_mint.live_target`，由 `ensure_fixture_site.py` 建），不再冒充任何真实 owner（ADR 0002）。

为什么需要它：其余闸门对这几条只有**静态**证据。`verify_deployed_edge.sh` 证明
"线上产物 == 这份源码"，单测证明"这份源码行为正确"，两者相乘是很强的链条，但没有
任何一条真机请求走过那些分支。而它们恰好是"旧版 Edge 也会让正常探针通过"的那种
缺陷，所以业务验收在结构上分辨不出新旧。这个脚本发的是**只有新版才会答对**的请求。

判据（六条，含正负对照；3c-final 起签发走 auth 的 `/fixture-session`，token 是 RS256、带 kid）：
  · 遮蔽 cookie 排在合法会话**之前**时，`/console-session` 仍须换出升级码；
  · 同上，Edge 侧站点请求仍须放行（必须 200，非 302 不算：403/500 也非 302）；14 条遮蔽亦然；
  · **未知 kid** 的 token（本地造，不需要任何密钥）必须被 Edge 拒，且不回落；
  · **夹具会话投给真实 org 站点必被拒**（ADR 0002 的边界：`allowed_users="org"` 的站点会放行
    任何可信来源的邮箱，所以这条才是"夹具身份的危害上限是夹具站点"的真机证据）。账号里没有
    org 站点时该条报 `skip: 账号里没有 org 站点`，**不算失败**；
  · 正对照：单枚合法夹具会话必须能进（否则上面几条 302 证明不了任何东西）；
  · 负对照：无 cookie 必须 302（确认 fail-closed 没被这些改动弄坏）。

**用途混用与跨 family 三条改由静态证据给**（plan D3）：KMS 之后没有任何组件能带外签 console
family 的 token，所以那三种反例造不出来了。它们的证据是
`site-builder/auth/tests/test_verifier_allowlist.py`（token_use 矩阵的非对角线全拒）与
`router/infrastructure/lambda/test_edge_kid_allowlist.py::test_console_kid_is_not_in_the_edge_allowlist`
（console kid 不在 Edge 的 allowlist 里），加上 `verify_deployed_edge.sh` 对已部署 Edge 里
公钥的精确对账（证明线上那份 allowlist 就是这两条测的那份）。

**HTTP 头按小写取**：CloudFront 会把 `Location` 规范成小写，而 Edge 自己生成的
302 保留大写——写死大小写会让一半用例假红（实测踩过）。
判定逻辑是纯函数（run_checks），`--self-test` 不碰 AWS。用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
import _session_mint as sm  # noqa: E402

GARBAGE = "garbage.garbage.garbage"
UNKNOWN_KID = "site-rs-v9"


@dataclass(frozen=True)
class Tokens:
    good: str              # 夹具签发器给的站点会话（current kid）
    # kid 查表在验签**之前**，所以这一枚不需要任何密钥就能造，且它的被拒只可能来自 allowlist。
    unknown_kid: str       # header 带未知 kid


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _login_302(st, hd, auth_host) -> bool:
    return st == 302 and f"{auth_host}/login" in hd.get("location", "")


def run_checks(get, tokens: Tokens, *, site_url: str, auth_host: str,
               org_site_url: str | None = None) -> list:
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
    st, hd = get(site_url, f"sb_session={tokens.unknown_kid}")
    add("新入口 Edge：未知 kid 被拒且不回落（kid 查表在验签之前 ⇒ 只错 kid 这一个变量）",
        _login_302(st, hd, auth_host), f"{st}")
    if org_site_url:
        st, hd = get(org_site_url, f"sb_session={tokens.good}")
        add("ADR 0002 边界：夹具会话投给真实 org 站点被拒（302；org 站点对任何可信邮箱都开门）",
            _login_302(st, hd, auth_host), f"{st}")
    else:
        # **不是失败**：干净账号里本来就没有 `allowed_users="org"` 的真实站点，
        # 而拿夹具站点当目标会把这条判据退化成正对照（它 owner 就是夹具域）。
        add("ADR 0002 边界：夹具会话投给真实 org 站点被拒（302；org 站点对任何可信邮箱都开门）",
            True, "skip: 账号里没有 org 站点")
    st, hd = get(site_url, f"sb_session={tokens.good}")
    add("正对照：单枚合法夹具会话正常放行（200）", st == 200, f"{st}")
    st, hd = get(site_url, "")
    add("负对照：无 cookie 302 到登录（fail-closed 仍在）", _login_302(st, hd, auth_host), f"{st}")
    return out


def render(checks: list) -> int:
    for c in checks:
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.name}   [{c.detail}]")
    failed = sum(1 for c in checks if not c.ok)
    print(f"\n结果：{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


def _unknown_kid_token(email: str) -> str:
    """header 带未知 kid 的 token。**本地造，不需要任何密钥**：verifier 的 kid 查表在验签之前，
    所以签名段只要是合法 base64url 就够（256 字节随机 = RSA-2048 签名的长度）。"""
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    h = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": UNKNOWN_KID}).encode())
    p = b64(json.dumps({"token_use": "site-session", "aud": "site-edge", "email": email,
                        "name": email.split("@")[0], "iat": now, "exp": now + 600}).encode())
    return f"{h}.{p}.{b64(os.urandom(256))}"


# ---- 自测 -------------------------------------------------------------------------------------

def _ideal_responder(*, break_shadow: bool = False, break_unknown_kid: bool = False,
                     break_fixture_boundary: bool = False):
    """理想 verifier：只认 GOOD，且 GOOD 只在夹具站点上算数。三个坏路径各覆盖一条判据：

    - `break_shadow`          —— 修复前"只取第一条 cookie"（M06）；
    - `break_unknown_kid`     —— verifier 对未知 kid 回落（allowlist 形同不存在）；
    - `break_fixture_boundary`—— Edge 不做夹具边界判定（夹具会话成了全组织的钥匙，ADR 0002）。

    三条必须分开：合成一个旗标的话，报告里分不出坏的是哪一条，而它们的修法与后果完全不同。
    """
    login = {"location": "https://auth.example.test/login?redirect=x"}

    def get(url, cookie_header):
        vals = [p.partition("=")[2] for p in cookie_header.split(";") if p.strip().startswith("sb_session=")]
        candidates = vals[:1] if break_shadow else vals
        accepted = any(v == "GOOD" or (break_unknown_kid and v == "UNKNOWN") for v in candidates)
        if url.endswith("/console-session"):
            return (302, {"location": "https://console.example.test/api/session-callback?code=x"}) if accepted \
                else (302, login)
        if "app-org." in url:                     # 真实 org 站点：夹具会话在这里必须被拒
            return (200, {}) if (accepted and break_fixture_boundary) else (302, login)
        return (200, {}) if accepted else (302, login)
    return get


def self_test(**flags) -> int:
    checks = run_checks(_ideal_responder(**flags), Tokens(good="GOOD", unknown_kid="UNKNOWN"),
                        site_url="https://app-e2e-probe.example.test/", auth_host="auth.example.test",
                        org_site_url="https://app-org.example.test/")
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
    ap.add_argument("--self-test", action="store_true",
                    help="不碰 AWS：理想应答器全绿，遮蔽 / 未知 kid / 夹具边界三种坏路径各自必红")
    args = ap.parse_args(argv)
    if args.self_test:
        ok = (self_test() == 0 and self_test(break_shadow=True) != 0
              and self_test(break_unknown_kid=True) != 0 and self_test(break_fixture_boundary=True) != 0)
        print("self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    minter = sm.Minter.from_config()
    target = sm.live_target()
    org = sm.org_target()
    tokens = Tokens(good=minter.mint("site-session", sm.PROBE_EMAIL, ttl_seconds=600),
                    unknown_kid=_unknown_kid_token(sm.PROBE_EMAIL))
    print(f"探针目标：常驻夹具站点 {target.subdomain}.{target.base}（需登录，owner={sm.PROBE_EMAIL}）；"
          f"org 边界目标：{org.subdomain if org else '无（该条 skip）'}")
    return render(run_checks(_http_get, tokens, site_url=target.site_url, auth_host=target.auth_host,
                             org_site_url=org.site_url if org else None))


if __name__ == "__main__":
    sys.exit(main())
