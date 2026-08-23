"""会话 token 语义的**真机行为**闸门（token 用途混用 + 同名 cookie 遮蔽）。

**只发 GET，不写任何数据**，所以可以随时对生产跑；目标站点从路由表里现取一个
`require_auth=True` 的行，不新建夹具。

为什么需要它：其余闸门对这两条只有**静态**证据。`verify_deployed_edge.sh` 证明
"线上产物 == 这份源码"，单测证明"这份源码行为正确"，两者相乘是很强的链条，但没有
任何一条真机请求走过那两个分支。而它们恰好是"旧版 Edge 也会让正常探针通过"的那种
缺陷（多带的 `typ` claim 旧 Edge 只是忽略；单枚正常 cookie 两版都放行），所以业务
验收在结构上分辨不出新旧。这个脚本发的是**只有新版才会答对**的请求。

判据（六条，含正负对照）：
  · 遮蔽 cookie 排在合法会话**之前**时，`/console-session` 仍须换出升级码；
  · 同上，Edge 侧站点请求仍须放行；14 条遮蔽（console 4 段路径的真实量级）亦然；
  · 把 console 升级码当站点会话递给 Edge，必须被拒（`typ != session`）；
  · 正对照：单枚合法会话必须能进（否则上面几条 302 证明不了任何东西）；
  · 负对照：无 cookie 必须 302（确认 fail-closed 没被这些改动弄坏）。

**HTTP 头按小写取**：CloudFront 会把 `Location` 规范成小写，而 Edge 自己生成的
302 保留大写——写死大小写会让一半用例假红（实测踩过）。
"""
import configparser
import sys
import urllib.error
import urllib.request
from pathlib import Path

# 从 __file__ 推导，不写死本机路径：家目录路径属于 scan_staged_secrets.sh 的
# "本机信息"类命中（推送前 range scan 抓到的正是硬编码版本），且换机器即坏。
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import boto3
import session as sess

sb = configparser.ConfigParser(interpolation=None)
sb.read(ROOT / "site-builder" / "config.ini")
rt = configparser.ConfigParser(interpolation=None)
rt.read(ROOT / "router" / "config.ini")
base = sb["Platform"]["base_domain"].split("#")[0].strip()
region = sb["Platform"]["region"].split("#")[0].strip()

secret = boto3.client("ssm", region_name=region).get_parameter(
    Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]

trusted = ""
for s in rt.sections():
    if rt.has_option(s, "trusted_idps"):
        trusted = rt.get(s, "trusted_idps").split("#")[0].split(",")[0].strip()
        break
assert trusted, "取不到 trusted_idps"

# 找一个 ACTIVE 且 require_auth=True 的站点做探针目标（只读）
ddb = boto3.resource("dynamodb", region_name=region)
route_t = sb["Platform"]["routing_table"].split("#")[0].strip()
target = None
for it in ddb.Table(route_t).scan()["Items"]:
    if it.get("require_auth") is True and it.get("owner") != "platform":
        target = it
        break
assert target, "找不到 require_auth=True 的站点路由"
site_sub = target["subdomain"]
owner = target["owner"]


def mint_session(email):
    return sess.mint_session_jwt(email, email.split("@")[0], secret,
                                 ttl_seconds=600, idp=trusted,
                                 auth_via="TokenGeneration_HostedAuth")


def get(url, cookie_header):
    req = urllib.request.Request(url, method="GET",
                                 headers={"cookie": cookie_header})

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    try:
        with urllib.request.build_opener(NoRedir).open(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


FAIL = 0


def check(ok, name, detail=""):
    global FAIL
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    FAIL += (not ok)


good = mint_session(owner)
code = sess.mint_upgrade_code(owner, secret)
GARBAGE = "garbage.garbage.garbage"

print(f"探针目标：站点 {site_sub}.{base}（require_auth=True），owner={owner.split('@')[0]}@…")
print("\n── M06 · auth 侧 /console-session：垃圾值排在合法会话之前 ──")
st, hd = get(f"https://auth.{base}/console-session",
             f"sb_session={GARBAGE}; sb_session={good}")
loc = hd.get("location", "")
check(st == 302 and "session-callback?code=" in loc,
      "遮蔽 cookie 在前仍换出升级 code（修复前这里 302 去 /login）",
      f"{st} {loc.split('?')[0][-34:]}")

print("\n── M06 · Edge 侧站点请求：垃圾值排在合法会话之前 ──")
st, hd = get(f"https://{site_sub}.{base}/", f"sb_session={GARBAGE}; sb_session={good}")
check(st != 302, "遮蔽 cookie 在前仍放行（修复前这里 302 登录循环）",
      f"{st}{' → ' + hd.get('Location', '')[:40] if st == 302 else ''}")

print("\n── M06 · 深路径 14 条遮蔽（console 4 段路径的真实量级）──")
burst = "; ".join(f"sb_session=shadow{i}" for i in range(14))
st, hd = get(f"https://{site_sub}.{base}/", f"{burst}; sb_session={good}")
check(st != 302, "14 条遮蔽 cookie 压在前面仍放行", f"{st}")

print("\n── M05 · 把 console 升级码当站点会话递给 Edge ──")
st, hd = get(f"https://{site_sub}.{base}/", f"sb_session={code}")
check(st == 302 and f"auth.{base}/login" in hd.get("location", ""),
      "升级码被 Edge 拒绝（typ != session）", f"{st}")

print("\n── 正对照：合法会话必须能进（否则上面的 302 都没意义）──")
st, hd = get(f"https://{site_sub}.{base}/", f"sb_session={good}")
check(st != 302, "单枚合法会话正常放行", f"{st}")

print("\n── 负对照：无 cookie 必须 302（fail-closed 仍在）──")
st, hd = get(f"https://{site_sub}.{base}/", "")
check(st == 302 and f"auth.{base}/login" in hd.get("location", ""),
      "未登录仍 302 到登录端点", f"{st}")

print(f"\n结果：{'全部通过' if FAIL == 0 else f'{FAIL} 项失败'}")
sys.exit(1 if FAIL else 0)
