#!/usr/bin/env python3
"""3c-1A 新入口的**真机**正向/负向证据（只发 GET，不写任何数据）。

L1 之后线上 token 仍全是 legacy 形态，其它 verify 脚本走的都是 legacy 入口；本脚本专门证明
**新入口在真机上也通**：用 site-hs-v1 本地 mint 一枚带 kid 的站点会话（操作者身份读 SSM），
打一个 require_auth=True 的站点必须 **200**（不是"非 302"——403/500/502 也非 302，那分不清放行与
站点故障）；console-hs-v1 签的同形态 token 必须 302；未知 kid（哪怕用 legacy 密钥签）必须 302 且不回落；
auth 的 /console-session 对 kid 形态会话必须换出升级码。正/负对照各一条。

判定逻辑是纯函数（run_checks），`--self-test` 不碰 AWS：对理想应答器全绿、对"放行路径返回 500"
的应答器必红（deployer/tests/test_verify_kid_entry_live.py 也跑这两条）。import 期无副作用。

目标站点从路由表现取，会话冒充该站点的**真实 owner**——这是 3c-2A 常驻夹具站点（ADR-0002）
就位前的过渡做法，与 verify_session_token_semantics.py 相同；2A 之后改打夹具站点。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import session as sess  # noqa: E402
from session_keys import load_session_keys  # noqa: E402


@dataclass(frozen=True)
class Tokens:
    legacy: str        # 今天的形态（正对照）
    site_kid: str      # site-hs-v1 签的站点会话（新入口正向）
    console_kid: str   # console-hs-v1 签的同形态 token（Edge allowlist 无 console）
    unknown_kid: str   # legacy 密钥签、旧合同 payload、header 带未知 kid（不回落）
    wrong_use: str     # site kid 签的 token_use=console-session


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def run_checks(get, tokens: Tokens, *, site_url: str, auth_host: str) -> list:
    """get(url, cookie_header) -> (status, lowercase_headers)。纯函数，无 AWS。"""
    login = f"{auth_host}/login"
    out = []

    def add(name, ok, detail):
        out.append(Check(name, ok, detail))

    st, hd = get(site_url, f"sb_session={tokens.legacy}")
    add("正对照：legacy 会话仍 200 放行（L1：存量形态零影响）", st == 200, f"{st}")
    st, hd = get(site_url, "")
    add("负对照：无 cookie 302 到登录（fail-closed）", st == 302 and login in hd.get("location", ""), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.site_kid}")
    add("新入口：site kid 签的站点会话放行（必须 200，非 302 不算）", st == 200, f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.console_kid}")
    add("新入口：console kid 的同形态 token 被 Edge 拒（allowlist 无 console）",
        st == 302 and login in hd.get("location", ""), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.unknown_kid}")
    add("新入口：未知 kid 不回落 legacy（哪怕签名用的是 legacy 密钥）",
        st == 302 and login in hd.get("location", ""), f"{st}")
    st, hd = get(site_url, f"sb_session={tokens.wrong_use}")
    add("新入口：token_use=console-session 的 token 被 Edge 拒", st == 302, f"{st}")
    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tokens.site_kid}")
    add("auth：kid 形态会话换出升级码", st == 302 and "session-callback?code=" in hd.get("location", ""), f"{st}")
    st, hd = get(f"https://{auth_host}/console-session", f"sb_session={tokens.console_kid}")
    add("auth：console kid 的 token 换不出升级码", st == 302 and "/login" in hd.get("location", ""), f"{st}")
    return out


def render(checks: list) -> int:
    for c in checks:
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.name}   [{c.detail}]")
    failed = sum(1 for c in checks if not c.ok)
    print(f"\n结果：{'全部通过' if failed == 0 else f'{failed} 项失败'}")
    return 1 if failed else 0


# ---- 自测：理想应答器 / 坏掉的放行路径 -------------------------------------------------

def _ideal_responder(*, break_allow_path: bool = False):
    def get(url, cookie_header):
        token = cookie_header.split("=", 1)[1] if "=" in cookie_header else ""
        if url.endswith("/console-session"):
            if token.startswith("SITE"):
                return 302, {"location": "https://console.example.test/api/session-callback?code=x"}
            return 302, {"location": "https://auth.example.test/login?redirect=x"}
        if token.startswith(("LEGACY", "SITE")):
            return (500, {}) if (break_allow_path and token.startswith("SITE")) else (200, {})
        return 302, {"location": "https://auth.example.test/login?redirect=x"}
    return get


def self_test(*, break_allow_path: bool = False) -> int:
    tokens = Tokens(legacy="LEGACY.x.y", site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                    unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y")
    checks = run_checks(_ideal_responder(break_allow_path=break_allow_path), tokens,
                        site_url="https://app-x.example.test/", auth_host="auth.example.test")
    return 1 if any(not c.ok for c in checks) else 0


# ---- 真机 ------------------------------------------------------------------------------

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


def _live_tokens_and_target():
    import boto3
    sb = configparser.ConfigParser(interpolation=None)
    sb.read(ROOT / "site-builder" / "config.ini")
    rt = configparser.ConfigParser(interpolation=None)
    rt.read(ROOT / "router" / "config.ini")
    base = sb["Platform"]["base_domain"].split("#")[0].strip()
    region = sb["Platform"]["region"].split("#")[0].strip()
    keys = load_session_keys(ROOT / "site-builder" / "config.ini")
    ssm = boto3.client("ssm", region_name=region)

    def param(name):
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]

    site_cur, console_cur = keys.families["site"]["current"], keys.families["console"]["current"]
    site_secret, console_secret, legacy = param(site_cur.ssm_param), param(console_cur.ssm_param), param(keys.legacy_param)
    trusted = next((rt.get(s, "trusted_idps").split("#")[0].split(",")[0].strip()
                    for s in rt.sections() if rt.has_option(s, "trusted_idps")), "")
    if not trusted:
        raise SystemExit("router/config.ini 取不到 trusted_idps")
    ddb = boto3.resource("dynamodb", region_name=region)
    route_t = sb["Platform"]["routing_table"].split("#")[0].strip()
    target = next((it for it in ddb.Table(route_t).scan()["Items"]
                   if it.get("require_auth") is True and it.get("owner") != "platform"), None)
    if not target:
        raise SystemExit("找不到 require_auth=True 的站点路由")
    owner = target["owner"]

    def mint(kid, secret, token_use="site-session"):
        return sess.mint_token(kid=kid, secret=secret, token_use=token_use, email=owner, ttl_seconds=600,
                               name=owner.split("@")[0], idp=trusted, auth_via="TokenGeneration_HostedAuth")

    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "site-hs-v99"}).encode())
    p = b64(json.dumps({"typ": "session", "email": owner, "exp": int(time.time()) + 600,
                        "idp": trusted, "auth_via": "TokenGeneration_HostedAuth"}).encode())
    unknown = f"{h}.{p}." + b64(hmac.new(legacy.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    tokens = Tokens(legacy=sess.mint_session_jwt(owner, owner.split("@")[0], legacy, idp=trusted,
                                                 auth_via="TokenGeneration_HostedAuth"),
                    site_kid=mint(site_cur.kid, site_secret),
                    console_kid=mint(console_cur.kid, console_secret),
                    unknown_kid=unknown,
                    wrong_use=mint(site_cur.kid, site_secret, token_use="console-session"))
    print(f"探针目标：站点 {target['subdomain']}.{base}（require_auth=True），owner={owner.split('@')[0]}@…；kid={site_cur.kid}")
    return tokens, f"https://{target['subdomain']}.{base}/", f"auth.{base}"


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="不碰 AWS：理想应答器全绿、坏掉的放行路径必红")
    args = ap.parse_args(argv)
    if args.self_test:
        ok = self_test() == 0 and self_test(break_allow_path=True) != 0
        print("self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    tokens, site_url, auth_host = _live_tokens_and_target()
    return render(run_checks(_http_get, tokens, site_url=site_url, auth_host=auth_host))


if __name__ == "__main__":
    sys.exit(main())
