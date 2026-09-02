#!/usr/bin/env python3
"""3c-1A 新入口的**真机**正向/负向证据（只发 GET，不写任何数据）。

L1 之后线上 token 仍全是 legacy 形态，所以其它 verify 脚本走的都是 legacy 入口；本脚本专门
证明**新入口在真机上也通**：用 site-hs-v1 本地 mint 一枚带 kid 的站点会话（操作者身份读 SSM），
打一个 require_auth=True 的站点必须放行；用 console-hs-v1 签的同形态 token 打 Edge 必须 302；
未知 kid（哪怕用 legacy 密钥签）必须 302 且不回落；auth 的 /console-session 对 kid 形态会话
必须换出升级码。正/负对照各一条。

目标站点从路由表现取（同 verify_session_token_semantics.py，3c-2A 的常驻夹具站点就位后改打它）。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import base64
import configparser
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import session as sess  # noqa: E402
from session_keys import load_session_keys  # noqa: E402

sb = configparser.ConfigParser(interpolation=None)
sb.read(ROOT / "site-builder" / "config.ini")
rt = configparser.ConfigParser(interpolation=None)
rt.read(ROOT / "router" / "config.ini")
base = sb["Platform"]["base_domain"].split("#")[0].strip()
region = sb["Platform"]["region"].split("#")[0].strip()
keys = load_session_keys(ROOT / "site-builder" / "config.ini")
ssm = boto3.client("ssm", region_name=region)


def param(name: str) -> str:
    return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]


site_cur = keys.families["site"]["current"]
console_cur = keys.families["console"]["current"]
SITE_KID, SITE_SECRET = site_cur.kid, param(site_cur.ssm_param)
CONSOLE_KID, CONSOLE_SECRET = console_cur.kid, param(console_cur.ssm_param)
LEGACY = param(keys.legacy_param)

trusted = ""
for s in rt.sections():
    if rt.has_option(s, "trusted_idps"):
        trusted = rt.get(s, "trusted_idps").split("#")[0].split(",")[0].strip()
        break
assert trusted, "取不到 trusted_idps"

ddb = boto3.resource("dynamodb", region_name=region)
route_t = sb["Platform"]["routing_table"].split("#")[0].strip()
target = next((it for it in ddb.Table(route_t).scan()["Items"]
               if it.get("require_auth") is True and it.get("owner") != "platform"), None)
assert target, "找不到 require_auth=True 的站点路由"
site_sub, owner = target["subdomain"], target["owner"]


def mint(kid: str, secret: str, token_use: str = "site-session") -> str:
    return sess.mint_token(kid=kid, secret=secret, token_use=token_use, email=owner, ttl_seconds=600,
                           name=owner.split("@")[0], idp=trusted, auth_via="TokenGeneration_HostedAuth")


def unknown_kid_token() -> str:
    """legacy 密钥签、旧合同 payload、但 header 带未知 kid：不回落就必须 302。"""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "site-hs-v99"}).encode())
    p = b64(json.dumps({"typ": "session", "email": owner, "exp": int(time.time()) + 600,
                        "idp": trusted, "auth_via": "TokenGeneration_HostedAuth"}).encode())
    sig = b64(hmac.new(LEGACY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def get(url: str, cookie_header: str):
    req = urllib.request.Request(url, method="GET", headers={"cookie": cookie_header})

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    try:
        with urllib.request.build_opener(NoRedir).open(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


FAIL = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global FAIL
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    FAIL += (not ok)


site_url = f"https://{site_sub}.{base}/"
login = f"auth.{base}/login"
print(f"探针目标：站点 {site_sub}.{base}（require_auth=True），owner={owner.split('@')[0]}@…；kid={SITE_KID}")

print("\n── 正对照 ──")
st, hd = get(site_url, f"sb_session={sess.mint_session_jwt(owner, owner.split('@')[0], LEGACY, idp=trusted, auth_via='TokenGeneration_HostedAuth')}")
check(st != 302, "legacy 会话仍放行（L1：存量形态零影响）", f"{st}")
st, hd = get(site_url, "")
check(st == 302 and login in hd.get("location", ""), "无 cookie 仍 302（fail-closed）", f"{st}")

print("\n── 新入口（Edge）──")
st, hd = get(site_url, f"sb_session={mint(SITE_KID, SITE_SECRET)}")
check(st != 302, f"{SITE_KID} 签的站点会话放行", f"{st}")
st, hd = get(site_url, f"sb_session={mint(CONSOLE_KID, CONSOLE_SECRET)}")
check(st == 302 and login in hd.get("location", ""), f"{CONSOLE_KID} 签的同形态 token 被 Edge 拒（allowlist 无 console）", f"{st}")
st, hd = get(site_url, f"sb_session={unknown_kid_token()}")
check(st == 302 and login in hd.get("location", ""), "未知 kid 不回落 legacy（哪怕签名用的是 legacy 密钥）", f"{st}")
st, hd = get(site_url, f"sb_session={mint(SITE_KID, SITE_SECRET, token_use='console-session')}")
check(st == 302, "token_use=console-session 的 token 被 Edge 拒", f"{st}")

print("\n── 新入口（auth /console-session）──")
st, hd = get(f"https://auth.{base}/console-session", f"sb_session={mint(SITE_KID, SITE_SECRET)}")
check(st == 302 and "session-callback?code=" in hd.get("location", ""), "kid 形态会话换出升级码", f"{st}")
st, hd = get(f"https://auth.{base}/console-session", f"sb_session={mint(CONSOLE_KID, CONSOLE_SECRET)}")
check(st == 302 and "/login" in hd.get("location", ""), "console kid 的 token 换不出升级码", f"{st}")

print(f"\n结果：{'全部通过' if FAIL == 0 else f'{FAIL} 项失败'}")
sys.exit(1 if FAIL else 0)
