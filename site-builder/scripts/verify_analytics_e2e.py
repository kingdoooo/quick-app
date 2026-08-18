#!/usr/bin/env python3
"""M5 访问统计的真机端到端闸门：一次真实 HTTP 请求 → Edge 埋点 → rollup 封口
→ 面板与 MCP 读回同一组数字。

**用法（从仓库根跑）**：

    python3 site-builder/scripts/verify_analytics_e2e.py
    python3 site-builder/scripts/verify_analytics_e2e.py --keep-on-failure

用**系统 `python3`**，不要用 `deployer/.venv/bin/python3`：那个解释器的 CA
信任库是空的（2026-08-14 实测 `cert_store_stats()` 全 0），urllib 的每一次
HTTPS 都会 CERTIFICATE_VERIFY_FAILED——而本闸门几乎全是 HTTPS。

## 为什么需要它

到 M5 为止，埋点/聚合/读取三层的验证全部靠 moto。moto **不校验 IAM**（漏给
`dynamodb:Scan` 时单测全绿、真机 500），而且与真实 DynamoDB 至少有一处实测
差异（伪造游标：真机 ValidationException → 500，moto 下是 400）。整条链路
在真 AWS 上究竟通不通，只有本脚本能回答。

## 设计要点（每一条都是被具体缺陷逼出来的）

**① fixture 是本闸门自己的站点，不是别人的生产站点。**
`site_id` 带一次性随机后缀，只有本进程知道那个子域，所以「这个站点今天有
几行明细」是**可以精确断言**的（`pv` 恰好 2、`uv` 恰好 1、`pv_denied` 恰好
2），而不是只能写 `>= 2`。`>=` 型断言抓不住「资源请求也被记成 PV」这类
**虚增**缺陷——M5 已经因为镜像判定漏 `/api/` 与漏方法检查各错过一次
（见 `origin_request._route_kind` 的 docstring，一次实测 PV 放大 6 倍）。
顺带：不往真实用户的站点里灌探针流量，也就不会在别人的控制台里留下垃圾。

**② 「没数据」与「读不到数据」必须分开。**两者都长得像一片 0。所以：
  · 今天的期望值是**非零精确值**，全 0 一定红；
  · 昨天的桶在封口前先断言是 0、封口后再断言变成 `2/1/1`——**同一个桶的
    前后对比**才能证明面板真的在读聚合表，而不是「恰好也返回 0」。

**③ 每条负测都配一个「Edge 确实处理了这一条」的正证据。**
只断言「不该记的没记」时，「埋点压根没部署」会让负测全绿（§3.5）。做法是
把负测请求的**响应本身**当证据：静态资源请求返回 200 + 探针 CSS 内容（走完
了 asset 分支）、非 GET 请求返回 Edge 自己的 404、console 子域返回 302；
再在三条负测**之后**发一次页面请求并等到它的明细行——证明埋点在负测发生的
时刻是活的。

**④ 从真实行派生合成 fixture。**⑨ 段要一个**完整 UTC 日**（rollup 按设计
永不封口今天），而今天之前的明细只能由脚本自己写。那些合成行的形态**从 ②
段那行真实 Edge 写入拷贝**而来（只换分区键/时间/邮箱/判定）：手写一份形态
就有「合成行的形状与线上不同 ⇒ rollup 测过了但生产还是坏的」这个风险。

**⑤ 等待都是有上限的轮询，不是 sleep 一个大数。**理由见下面各常量的注释。
发完请求立刻断言 = 做出一个 flaky 闸门，而 flaky 闸门的代价是下一个人学会
忽略它。

## 清理

路由 → S3 对象 → 明细行（今天+昨天）→ 聚合行 → 站点行，逐个指名删除后
**强一致读回核对**，残留即验收失败（不是打印警告）。先删路由是为了在删数据
之前掐掉「还能产生新行」的入口。
`--keep-on-failure` 只在失败时保留，并打印完整的手工清理清单。

**⑨ 段有一次「不给 sites」的 invoke，它会按生产的方式重算全部站点的昨天**：
那与每日 EventBridge 跑的是同一件事、幂等、且只覆盖完整日，所以不需要
（也不应该）回滚别的站点那些行。
"""
import argparse
import base64
import configparser
import json
import re
import secrets
import sys
import time
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CFG_PATH = HERE.parent / "config.ini"
ROUTER_CFG_PATH = ROOT / "router" / "config.ini"

sys.path.insert(0, str(HERE.parent / "auth"))   # session.py：签发算法唯一实现
sys.path.insert(0, str(HERE))                   # _mcp_client.py（scripts/ 不是包）
# common.py：前端版本前缀格式的唯一定义（尾斜杠是实测红线）。这个闸门要造一条
# 真路由，手抄一份格式就等于让闸门用一份可能已经漂移的路径去验生产。
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))

import common as sb_common                      # noqa: E402
import session as sess                          # noqa: E402
from _mcp_client import (Mcp, claims as token_claims,  # noqa: E402
                         http, load_user_token, mcp_endpoint)

# 两张表与 rollup 函数的名字由 deployer 栈钉死（`infra/app.py`），不是配置项。
# 明细表名另外从 router/config.ini 读一遍（那是 Edge 的取值来源），⓿ 段还会
# 把 rollup 函数的环境变量与它们比一次——「大家读的不是同一张表」这种缺陷会
# 让全场绿灯而线上零数据。
DAILY_TABLE = "site-access-daily"
ROLLUP_FN = "site-access-rollup"

# 路由在 Edge 生效的上限。两个来源叠加：① 路由表 `get_item` 用的是**最终
# 一致**读（`origin_request._lookup_route` 里 ConsistentRead=False）；
# ② Edge 把查询结果（**包括未命中**）缓存 60s（`ROUTE_CACHE_TTL`）。所以最坏
# 情况是「第一次探测赶在写入可见之前 → 未命中被缓存 60s」，90s 覆盖它并留余量。
# 这也是本脚本**不照抄 smoke_router.sh 那个无条件 `sleep 65`** 的原因：改成
# 有上限的轮询，正常情况下一次就过，并把真实等待时间打出来。
ROUTE_READY_TIMEOUT = 90
ROUTE_READY_POLL = 5

# 明细行出现的上限。明细表是 3 区 Global Table，Edge 写的是**它执行区的副本**，
# 而本脚本读主区——复制是异步的且**没有 SLA**（实测跨区冷写 719ms、同区暖写
# 6ms）。30s ≈ 已实测最坏值的 40 倍。轮询间隔 1s。
ROW_TIMEOUT = 30
ROW_POLL = 1.0

# 断言「负测没产生明细行」之前的额外余量。正对照的行已经到达，但**复制不保证
# 保序**——晚发的请求先到是可能的。在正对照到达之后再多给 5s，负测的结论才
# 不是在赌复制延迟。
NEG_GRACE = 5

# 距 UTC 零点的最小余量。明细的分区键、聚合行的 date、面板的桶键全是 UTC 日；
# 跨日会让所有精确比对失去意义（而且是**红**，不是黄）——这种红只会浪费一次
# 排查。宁可拒绝开跑。
MIDNIGHT_MARGIN = 15 * 60

# 全绿时的实际断言条数。**不是估的**：低于它说明脚本中途退出或某个分支被跳过，
# 而「跑了 3 项全过」读起来跟「70 项全过」一样像成功（M3-FINDINGS §2.3）。
# 推导：全文有 70 处 `check(` 调用点，全绿路径会走进每一个 `if check(...)` 的
# 真分支，其中
#   · 2 处**只在失败时**执行（⑧ 段拿不到 token 的兜底、⑨ 段无真实行可派生的
#     兜底），全绿时不跑；
#   · 1 处在 `for` 里跑 3 次（⑦ 段三条探针路径），多算 2 条。
# 68 + 2 = 70。改动检查项后重新数一遍，别拍脑袋改这个数——它偏大就会让全绿的
# 一次运行被报成「未完成」，偏小就会让中途退出被报成成功。
MIN_CHECKS = 70

results: list[tuple[bool, str, str]] = []


class Abort(Exception):
    """前置条件不成立，验收无法开始。

    **不用 `sys.exit("话")`**：`__main__` 的 finally 里还会 `sys.exit(rc)`，
    后者会顶掉前者，于是那句解释**永远不会被打印**（只剩一个裸的 exit 1）。
    """


def check(ok, name: str, detail: str = "") -> bool:
    ok = bool(ok)
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    return ok


def cfg_obj(path: Path) -> configparser.ConfigParser:
    """读 config.ini 并**断言真读到了**。

    `ConfigParser.read()` 对不存在的路径是**静默**的，之后任何取值/判定都会
    给出一个看起来言之有理的错误结论（本项目 2026-08-13 因 cwd 漂移据此伪造
    出一个「生产隐患」）。读空必须当场炸。
    """
    c = configparser.ConfigParser(interpolation=None)
    c.read(path)
    if not c.sections():
        raise Abort(f"{path} 读不到任何段——请从仓库根跑，别在子目录跑")
    return c


def val(c: configparser.ConfigParser, section: str, key: str) -> str:
    try:
        return c[section][key].split("#")[0].split(";")[0].strip()
    except KeyError:
        raise Abort(f"配置缺 [{section}] {key}")


def hdr(headers: dict, name: str) -> str:
    """响应头取值，**大小写不敏感**（HTTP 头本来就是）。

    `dict(resp.headers)` 会丢掉 `email.message.Message` 的大小写不敏感特性。
    Edge 返回的是 `Location`、auth 服务返回的是小写 `location`——按固定大小写
    取就会在其中一侧拿到 None，表现为「302 了但没有 Location」这种**根本不
    可能的产品行为**（verify_console_e2e.py 第一版因此误报 3 项）。
    """
    for k, v in (headers or {}).items():
        if str(k).lower() == name.lower():
            return str(v)
    return ""


def as_json(text: str) -> dict:
    """响应体必须是合法 JSON 对象；否则返回空 dict。

    不抛：调用方随后的字段断言会失败，于是「接口返回了 HTML 错误页」会**红**，
    而不是被静默当成通过。
    """
    try:
        out = json.loads(text)
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


def b64_cursor(state: dict) -> str:
    """按 `analytics._encode` 的形态造一个游标（伪造负测用）。"""
    return base64.urlsafe_b64encode(json.dumps(state).encode()).decode()


def query_rows(ddb, table: str, site_id: str, day: str,
               consistent: bool = False) -> list[dict]:
    """某站点某天的**全部**明细行（翻页到底）。

    默认最终一致读：这是 Global Table，跨副本的强一致读并不存在（强一致只在
    单区内成立），花两倍读容量换不到任何保证。
    """
    rows, kwargs = [], {
        "TableName": table,
        "KeyConditionExpression": "site_date = :sd",
        "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
        "ConsistentRead": consistent}
    while True:
        resp = ddb.query(**kwargs)
        rows.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def wait_for_row(ddb, table: str, site_id: str, day: str,
                 want_path: str) -> tuple[dict | None, float]:
    """轮询等那一行出现 → (item | None, 等了几秒)。见 ROW_TIMEOUT 的注释。"""
    started = time.time()
    while True:
        for it in query_rows(ddb, table, site_id, day):
            if it.get("path", {}).get("S") == want_path:
                return it, round(time.time() - started, 1)
        if time.time() - started >= ROW_TIMEOUT:
            return None, round(time.time() - started, 1)
        time.sleep(ROW_POLL)


def get_daily(ddb, site_id: str, date_s: str) -> dict | None:
    return ddb.get_item(TableName=DAILY_TABLE,
                        Key={"site_id": {"S": site_id}, "date": {"S": date_s}},
                        ConsistentRead=True).get("Item")


def daily_triple(item: dict | None) -> tuple | None:
    if not item:
        return None
    try:
        return (int(item["pv"]["N"]), int(item["uv"]["N"]),
                int(item["pv_denied"]["N"]))
    except (KeyError, ValueError):
        return ("字段缺失/错型", sorted(item))


def invoke_rollup(lam, payload: dict) -> tuple[bool, dict]:
    """同步调一次 rollup → (成功?, 返回体)。`FunctionError` 必须一起看：
    Lambda 抛异常时 StatusCode 仍是 200，只有这个字段能分辨。"""
    resp = lam.invoke(FunctionName=ROLLUP_FN,
                      Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read().decode(errors="replace")
    out = as_json(raw) or {"_raw": raw[:200]}
    ok = resp.get("FunctionError") is None and resp.get("StatusCode") == 200
    return ok, out


def main() -> int:                                      # noqa: C901
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep-on-failure", action="store_true",
                    help="失败时保留 fixture（站点/路由/对象/明细/聚合行）便于排查")
    args = ap.parse_args()

    c = cfg_obj(CFG_PATH)
    rc = cfg_obj(ROUTER_CFG_PATH)
    region = val(c, "Platform", "region")
    base = val(c, "Platform", "base_domain")
    account = val(c, "Platform", "account_id")
    routing_table = val(c, "Platform", "routing_table")
    sites_table = val(c, "Deployer", "sites_table")
    bucket = val(c, "Deployer", "frontend_bucket").replace("{account_id}", account)
    events_table = val(rc, "SiteBuilder", "access_table")

    now = datetime.now(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    yday = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    to_midnight = 86400 - (now.hour * 3600 + now.minute * 60 + now.second)
    if to_midnight < MIDNIGHT_MARGIN:
        raise Abort(f"距 UTC 零点只剩 {to_midnight}s。本闸门全程按同一个 UTC 日"
                    "比对（明细分区键 / 聚合行 date / 面板桶键都是 UTC 日），"
                    "跨日会得出一堆与被测代码无关的红。等过了零点再跑。")

    ddb = boto3.client("dynamodb", region_name=region)
    # rollup 的函数超时是 300s，而 botocore 默认 read_timeout 是 60s：⑨ 段有一次
    # 「不给 sites」的 invoke 会遍历全部站点，站点多起来时默认超时会让**闸门自己**
    # 抛 ReadTimeout（一次与被测代码无关的中断）。给到函数超时之上。
    lam = boto3.client("lambda", region_name=region,
                       config=BotoConfig(read_timeout=310, retries={"max_attempts": 0}))
    s3 = boto3.client("s3", region_name=region)
    secret = boto3.client("ssm", region_name=region).get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    if not secret:
        raise Abort("取不到 JWT_SECRET —— 无法签发会话，验收不可信")

    # idp 必须取 **Edge 实际信任的那个值**（router/config.ini 的 trusted_idps，
    # CDK synth 时注入 Edge 的 TRUSTED_IDPS）。写死 "Feishu" 会让脚本在换 IdP
    # 的环境上全红，而红的原因与被测代码无关。
    trusted_idp = ""
    for sec in rc.sections():
        if rc.has_option(sec, "trusted_idps"):
            trusted_idp = rc.get(sec, "trusted_idps").split("#")[0].split(",")[0].strip()
            if trusted_idp:
                break
    require_idp = val(rc, "SiteBuilder", "require_idp_claim").lower() == "true"
    if require_idp and not trusted_idp:
        raise Abort("router/config.ini 里 require_idp_claim=true 却没有 "
                    "trusted_idps —— 签出来的会话 Edge 一律不认，结果不可信")

    # ── fixture 身份与命名（一次性后缀）────────────────────────────────
    suf = secrets.token_hex(4)
    site_id = f"m5e2e-{suf}"          # panel 的 _SITE 正则要求首字符是小写字母
    subdomain = f"app-{site_id}"
    # 格式走 common 的唯一定义（**不带尾斜杠**：Edge 拼的是
    # f"/{static_prefix}{path}"，带尾斜杠会拼出双斜杠、与上传的 key 不是同一个
    # 对象，整站 403 —— CLAUDE.md 高频坑）。这里的"job_id"位置放的是固定串
    # `m5e2e`，因为这条 fixture 路由不是由某次真实部署写出来的。
    static_prefix = sb_common.static_prefix_for(site_id, "m5e2e")
    owner = f"m5e2e-owner-{suf}@example.com"
    visitor = f"m5e2e-visitor-{suf}@example.com"
    visitor2 = f"m5e2e-visitor2-{suf}@example.com"
    outsider = f"m5e2e-outsider-{suf}@example.com"
    page_mark = f"m5e2e-page-{suf}"
    css_mark = f"m5e2e-asset-{suf}"

    def mint(email: str, scope: str = "") -> str:
        return sess.mint_session_jwt(email, email.split("@")[0], secret,
                                     ttl_seconds=3600, idp=trusted_idp,
                                     scope=scope,
                                     auth_via="TokenGeneration_HostedAuth")

    def ck(email: str) -> dict:
        return {"cookie": f"sb_session={mint(email)}"}

    def site_url(path: str) -> str:
        return f"https://{subdomain}.{base}{path}"

    api = f"https://console.{base}/api/sites/{site_id}"

    # MCP 调用者的身份要在建 fixture **之前**拿到：它得作为协作者写进站点行，
    # 否则 ⑧ 段会因为「无权访问」而红——那不是被测的事。
    # **token 一个字节都不打印**，调用者的邮箱也不打印（它是真人的地址）。
    mcp_caller, mcp_token, mcp_note = "", "", ""
    try:
        mcp_token = load_user_token()
        mcp_caller = token_claims(mcp_token).get("email", "")
    except (Exception, SystemExit) as exc:      # noqa: BLE001
        # load_user_token 拿不到就 sys.exit（SystemExit 不是 Exception 的子类，
        # 必须显式列出，否则它会穿过这里直接把脚本带走）
        mcp_note = f"{type(exc).__name__}: {str(exc)[:160]}"

    made = {"route": False, "site": False, "objects": [],
            "detail_days": set(), "daily_dates": set(),
            # ⑤ 段若真在 console/ole 分区里发现了本次探针的行（= 缺陷），
            # 那行垃圾也要由本闸门收走：(分区键前缀, ts_id 的 AttributeValue)
            "stray": []}

    try:
        print("\n── ⓿ 前置：两张表在线，且各方读的是同一张表 ─────────")
        try:
            ev = ddb.describe_table(TableName=events_table)["Table"]
            da = ddb.describe_table(TableName=DAILY_TABLE)["Table"]
            fn_env = (lam.get_function_configuration(FunctionName=ROLLUP_FN)
                      .get("Environment", {}).get("Variables", {}))
        except ClientError as exc:
            raise Abort(f"M5 的表/函数还不在线（{exc.response['Error']['Code']}）"
                        "—— 先部署（Task 15 的 deployer 栈那一步），再跑本闸门")
        check(ev["TableStatus"] == "ACTIVE", f"明细表 {events_table} ACTIVE",
              ev["TableStatus"])
        check(da["TableStatus"] == "ACTIVE", f"聚合表 {DAILY_TABLE} ACTIVE",
              da["TableStatus"])
        # 表名漂移是最阴的一类缺陷：写入方与读取方各自都「工作正常」，线上却是
        # 零数据。这两条把 rollup 的取值与本闸门的取值对齐（Edge 那侧的取值由
        # verify_deployed_components ⑨ 段按同一份清单锁死）。
        check(fn_env.get("ACCESS_EVENTS_TABLE") == events_table,
              "rollup 读的明细表 == 本闸门读的明细表",
              f"rollup={fn_env.get('ACCESS_EVENTS_TABLE')} 闸门={events_table}")
        check(fn_env.get("ACCESS_DAILY_TABLE") == DAILY_TABLE,
              "rollup 写的聚合表 == 本闸门读的聚合表",
              f"rollup={fn_env.get('ACCESS_DAILY_TABLE')} 闸门={DAILY_TABLE}")

        print("\n── ① fixture：一个只有本闸门碰的站点 ────────────────")
        s3.put_object(Bucket=bucket, Key=f"{static_prefix}/index.html",
                      Body=(f"<!doctype html><title>{page_mark}</title>"
                            f"<p>{page_mark}</p>\n").encode())
        made["objects"].append(f"{static_prefix}/index.html")
        s3.put_object(Bucket=bucket, Key=f"{static_prefix}/probe.css",
                      Body=f"/* {css_mark} */\n".encode())
        made["objects"].append(f"{static_prefix}/probe.css")

        # **条件写**：随机后缀撞上一个真实站点的概率极低，但 PutItem 是覆盖写，
        # 万一撞上就是把别人的站点行/路由行整行替换掉。用 attribute_not_exists
        # 让这种情况变成一次响亮的前置失败，而不是一次静默的数据损坏。
        try:
            ddb.put_item(
                TableName=sites_table,
                ConditionExpression="attribute_not_exists(site_id)",
                Item={
                    "site_id": {"S": site_id}, "name": {"S": site_id},
                    "owner": {"S": owner}, "status": {"S": "ACTIVE"},
                    "require_login": {"BOOL": True},
                    "allowed_users": {"L": [{"S": visitor}]},
                    # MCP 调用者以**协作者**身份读统计：view_analytics 的名单是
                    # owner/collaborator/admin，这样 ⑧ 段顺带验到协作者那条路径。
                    "collaborators": {"L": [{"S": e} for e in
                                            ([mcp_caller] if mcp_caller else [])]},
                    "created_at": {"S": now.isoformat()},
                    "permissions_rev": {"N": "0"}})
            made["site"] = True
            ddb.put_item(
                TableName=routing_table,
                ConditionExpression="attribute_not_exists(subdomain)",
                Item={
                    "subdomain": {"S": subdomain}, "site_id": {"S": site_id},
                    "route_mode": {"S": "split"},
                    "static_prefix": {"S": static_prefix},
                    "api_target": {"S": ""}, "require_auth": {"BOOL": True},
                    "allowed_users": {"L": [{"S": visitor}]},
                    "owner": {"S": owner}})
            made["route"] = True
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            raise Abort(f"一次性后缀 {suf} 撞上了已存在的行（site_id={site_id} 或 "
                        f"subdomain={subdomain}）—— 本闸门**不覆盖**任何已有行，"
                        "重跑一次换个后缀即可")
        check(bool(ddb.get_item(TableName=sites_table,
                                Key={"site_id": {"S": site_id}},
                                ConsistentRead=True).get("Item")),
              "fixture 站点已建立并强一致读回", site_id)
        check(bool(ddb.get_item(TableName=routing_table,
                                Key={"subdomain": {"S": subdomain}},
                                ConsistentRead=True).get("Item")),
              "fixture 路由已建立并强一致读回", subdomain)

        # 基线为零是后面每个精确数字的前提，所以它是一条检查而不是一句注释。
        check(not query_rows(ddb, events_table, site_id, day, consistent=True),
              "明细表里这个站点今天一行都没有（精确计数的前提）", "")

        # 路由生效探测用**带扩展名的路径且不带 cookie**：资源请求不产生明细行，
        # 所以这一步不会污染后面的计数；302 说明路由已被查到（没查到是 Edge
        # 自己的 404）。
        waited, st_ready = 0.0, 0
        started = time.time()
        while True:
            st_ready, _, _ = http("GET", site_url(f"/m5ready-{suf}.css"))
            waited = round(time.time() - started, 1)
            if st_ready == 302 or waited >= ROUTE_READY_TIMEOUT:
                break
            time.sleep(ROUTE_READY_POLL)
        check(st_ready == 302,
              f"路由在 Edge 生效（轮询 ≤{ROUTE_READY_TIMEOUT}s，实际 {waited}s）",
              f"HTTP {st_ready}")

        print("\n── ② 一次真实页面请求 → 一行 allow 明细 ──────────────")
        p_allow = f"/m5-allow-{suf}"
        st, _, body = http("GET", site_url(p_allow), headers=ck(visitor))
        check(st == 200 and page_mark in body,
              "名单内身份的页面请求 → 200，且返回的是本闸门上传的探针页",
              f"HTTP {st} {len(body)}B")
        row, waited = wait_for_row(ddb, events_table, site_id, day, p_allow)
        if check(row is not None,
                 f"明细行出现（轮询 ≤{ROW_TIMEOUT}s，实际 {waited}s）",
                 "超时未出现：Edge 把写入异常吞掉了（_record_access 是 fail-open），"
                 "去它的日志里找 [WARN] 访问埋点失败" if row is None else ""):
            check(row["decision"]["S"] == "allow", "decision == allow",
                  row["decision"]["S"])
            # **逐字相等**，不是「含 @」：`"@" in email` 这种断言连「写的是别人
            # 的邮箱」都抓不住（§4.8 的形态）。
            check(row["email"]["S"] == visitor,
                  "email 是 Edge 验签后的那个邮箱（逐字相等）",
                  row["email"]["S"])
            check(row["path"]["S"] == p_allow,
                  "path 是用户看到的路径，不是桶内 key（Edge 在改写 uri 之前抓的）",
                  row["path"]["S"])
            check(row["site_id"]["S"] == site_id,
                  "site_id 属性与分区键前缀一致", row["site_id"]["S"])
            check(re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.+\-]+#[0-9a-f]{6}",
                               row["ts_id"]["S"]) is not None,
                  "ts_id = ISO8601#6位hex（前缀可排序 + 同微秒两条不互相覆盖）",
                  row["ts_id"]["S"])
            ttl_days = (int(row["expires_at"]["N"]) - int(now.timestamp())) / 86400
            check(89 < ttl_days <= 90.1, "明细行 TTL ≈ 90 天",
                  f"{ttl_days:.2f} 天")
            # 属性集合钉死：多一个字段就是有人往明细里加了东西，而这张表会被
            # owner 在控制台里逐行看到——PII 面变了必须有人知道。
            check(set(row) == {"site_date", "ts_id", "site_id", "email",
                               "path", "decision", "expires_at"},
                  "明细行的属性集合恰好是契约的 7 个", str(sorted(row)))

        print("\n── ③ 未登录 → redirect_login（email 必须是空串）──────")
        p_anon = f"/m5-anon-{suf}"
        st, h, _ = http("GET", site_url(p_anon))
        loc = hdr(h, "location")
        check(st == 302 and f"auth.{base}/login" in loc,
              "未登录的页面请求 → 302 到登录页", f"HTTP {st} {loc[:40]}")
        row3, waited = wait_for_row(ddb, events_table, site_id, day, p_anon)
        if check(row3 is not None,
                 f"未登录请求的明细行出现（实际 {waited}s）", ""):
            check(row3["decision"]["S"] == "redirect_login",
                  "decision == redirect_login", row3["decision"]["S"])
            check(row3["email"]["S"] == "",
                  "未登录时 email 是空串，不是 - 之类的哨兵（哨兵会污染 UV 去重）",
                  repr(row3["email"]["S"]))

        print("\n── ④ 名单外 → denied_403（必须带已验签的邮箱）────────")
        p_403 = f"/m5-denied-{suf}"
        st, _, _ = http("GET", site_url(p_403), headers=ck(outsider))
        check(st == 403, "有会话但不在名单里的页面请求 → 403", f"HTTP {st}")
        row4, waited = wait_for_row(ddb, events_table, site_id, day, p_403)
        if check(row4 is not None,
                 f"denied_403 的明细行出现（实际 {waited}s）", ""):
            check(row4["decision"]["S"] == "denied_403",
                  "decision == denied_403", row4["decision"]["S"])
            check(row4["email"]["S"] == outsider,
                  "被拒记录带的是被拒者的邮箱（「谁被拒了」是这条记录的全部价值）",
                  row4["email"]["S"])

        print("\n── ⑤ 三条负测，每条都先证明 Edge 处理过它 ───────────")
        st, _, css_body = http("GET", site_url("/probe.css"), headers=ck(visitor))
        check(st == 200 and css_mark in css_body,
              "静态资源请求 → 200 且内容是探针 CSS（Edge 走完了 asset 分支）",
              f"HTTP {st}")
        p_post = f"/m5-post-{suf}"
        st_post, _, _ = http("POST", site_url(p_post), headers=ck(visitor), raw=b"")
        check(st_post == 404,
              "非 GET/HEAD 的无扩展名请求 → 404（静态桶只接读方法，Edge 自己拒的）",
              f"HTTP {st_post}")
        p_con = f"/m5-console-{suf}"
        st_con, _, _ = http("GET", f"https://console.{base}{p_con}")
        check(st_con == 302,
              "平台子域 console 的请求 → 302（Edge 确实处理了这一条）",
              f"HTTP {st_con}")

        # 正对照**排在三条负测之后**：它证明埋点在负测发生的那一刻是活的。
        # 只验「不该记的没记」时，「埋点压根没部署」会让负测全绿（§3.5）。
        p_ctrl = f"/m5-ctrl-{suf}"
        st, _, body = http("GET", site_url(p_ctrl), headers=ck(visitor))
        check(st == 200 and page_mark in body,
              "正对照：三条负测之后再发一次页面请求 → 200", f"HTTP {st}")
        ctrl, waited = wait_for_row(ddb, events_table, site_id, day, p_ctrl)
        check(ctrl is not None,
              f"正对照的明细行出现（实际 {waited}s）⇒ 上面三条负测不是空转",
              "" if ctrl is not None else "超时未出现，则三条负测什么都证明不了")
        time.sleep(NEG_GRACE)       # 见 NEG_GRACE 的注释

        rows_today = query_rows(ddb, events_table, site_id, day)
        paths_today = {r.get("path", {}).get("S", "") for r in rows_today}
        # detail 里带上「今天一共有哪些路径」：**在 PASS 时也打印**，这样
        # 「因为整张分区是空的所以负测通过」这种情形一眼可见（否则一条空转的
        # 负测和一条真的负测在输出里长得一模一样）。
        seen = f"今天共 {len(rows_today)} 行：{sorted(paths_today)}"
        check("/probe.css" not in paths_today,
              "带扩展名的资源请求**没有**明细行（否则一次 SPA 打开就把 PV 放大数倍）",
              seen)
        check(p_post not in paths_today,
              "非 GET/HEAD 请求**没有**明细行（它真实是 404，记成 allow 就是虚增 PV）",
              seen)
        # console 的记录会落在哪里？两种手滑各查一次：整条 subdomain 当 site_id
        # （去掉了 app- 前缀判定），或仍做 `subdomain[4:]` 切片（"console" → "ole"）。
        con_hits = []
        for part in ("console", "ole"):
            for r in query_rows(ddb, events_table, part, day):
                if r.get("path", {}).get("S") == p_con:
                    con_hits.append(part)
                    # 真被记了就是缺陷，但那行垃圾也得由本闸门收走
                    made["stray"].append((part, r["ts_id"]))
        check(not con_hits,
              "console 子域的请求**没有**明细行（判定用 app- 前缀，不是 owner 字段）",
              f"却在 {con_hits} 分区里找到了")

        print("\n── ⑥ 口径：记下的恰好是本闸门做过的事 ──────────────")
        counts: dict[str, int] = {}
        for r in rows_today:
            d = r.get("decision", {}).get("S", "?")
            counts[d] = counts.get(d, 0) + 1
        check(counts == {"allow": 2, "redirect_login": 1, "denied_403": 1},
              "今天这个站点的明细恰好 {allow:2, redirect_login:1, denied_403:1}"
              "（一行不多、一行不少）", str(counts))
        allow_rows = [r for r in rows_today
                      if r.get("decision", {}).get("S") == "allow"]
        exp_pv = len(allow_rows)
        exp_uv = len({r["email"]["S"] for r in allow_rows if r["email"]["S"]})
        exp_denied = len(rows_today) - exp_pv
        check(exp_uv == 1,
              "两次 allow 来自同一个访客 ⇒ UV 去重后是 1（不是 2）",
              f"pv={exp_pv} uv={exp_uv} pv_denied={exp_denied}")

        print("\n── ⑦ 面板读回：非零精确值，且「读不到」不算「没数据」──")
        st, _, text = http("GET", f"{api}/analytics?period=day&n=2",
                           headers=ck(owner))
        series = as_json(text).get("series") or []
        check(st == 200, "GET /analytics?period=day&n=2 → 200（不是 403/500）",
              f"HTTP {st} {text[:80]}")
        buckets = [b.get("bucket") for b in series]
        if check(buckets == [yday, day],
                 "恰好 2 个桶且日历对齐 [昨天, 今天]", str(buckets)):
            today_b, yday_b = series[1], series[0]
            panel_today = (today_b.get("pv"), today_b.get("uv"),
                           today_b.get("pv_denied"))
            # `exp_pv > 0` 不是多余的：没有它，「明细是空的 + 面板也返回 0」
            # 会让这条断言通过——而那正是「读不到数据」与「没有数据」被混为
            # 一谈的样子。期望值必须先是非零的，比对才有意义。
            check(exp_pv > 0 and panel_today == (exp_pv, exp_uv, exp_denied),
                  f"今天的桶 == 明细实测 {exp_pv}/{exp_uv}/{exp_denied} 且非零"
                  "（全 0 意味着读路径坏了，不是站点闲着）", str(panel_today))
            check(today_b.get("uv_exact") is True,
                  "period=day 的桶 uv_exact 恒为 true（日 UV 存在聚合行里，永远精确）",
                  str(today_b.get("uv_exact")))
            # 这条与 ⑨ 段最后一条是**一对**：现在必须是 0（还没封口），封口后
            # 必须变成 2/1/1。单看任何一条都可能「因为恰好也返回 0」而绿。
            check((yday_b.get("pv"), yday_b.get("pv_denied")) == (0, 0),
                  "昨天的桶此刻是 0（还没封口）—— 与 ⑨ 段末尾那条配对使用",
                  f"{yday_b.get('pv')}/{yday_b.get('pv_denied')}")

        st, _, text = http("GET", f"{api}/visitors?days=1&limit=50",
                           headers=ck(owner))
        vrows = as_json(text).get("rows") or []
        # 同上：先要求非空。`len(vrows) == len(rows_today)` 在两边都是 0 时也成立。
        check(st == 200 and len(rows_today) > 0 and len(vrows) == len(rows_today),
              f"GET /visitors → 200 且恰好 {len(rows_today)} 条（非空且不多不少）",
              f"HTTP {st} 返回 {len(vrows)} 条 / 明细 {len(rows_today)} 行")
        by_path = {r.get("path"): r for r in vrows}
        for p, dec, mail in ((p_allow, "allow", visitor),
                             (p_anon, "redirect_login", ""),
                             (p_403, "denied_403", outsider)):
            hit = by_path.get(p) or {}
            check(hit.get("decision") == dec and hit.get("email") == mail,
                  f"访问明细里有 {dec} 那条，且 decision/email 与明细表逐字一致",
                  f"{hit.get('decision')} / {hit.get('email')!r}")

        st, _, text = http("GET", f"{api}/visitors?days=1&limit=1",
                           headers=ck(owner))
        page1 = as_json(text)
        p1rows = page1.get("rows") or []
        if check(st == 200 and len(p1rows) == 1 and bool(page1.get("next")),
                 "limit=1 → 恰好 1 条 + 非空 next 游标",
                 f"HTTP {st} {len(p1rows)} 条 next={'有' if page1.get('next') else '无'}"):
            cur = urllib.parse.quote(str(page1["next"]), safe="")
            st, _, text = http("GET", f"{api}/visitors?days=1&limit=1&cursor={cur}",
                               headers=ck(owner))
            p2rows = as_json(text).get("rows") or []
            ts1 = p1rows[0].get("ts", "")
            ts2 = p2rows[0].get("ts", "") if p2rows else ""
            check(st == 200 and ts2 and ts2 < ts1,
                  "跟着 next 拿到的是**更早的另一条**（不是把第一页又发一遍）",
                  f"HTTP {st} {ts1} → {ts2}")

        st, _, text = http("GET", f"{api}/visitors?days=1&cursor=not-a-cursor",
                           headers=ck(owner))
        check(st == 400, "不是本接口发出的游标 → 400（入参错误，不是 500）",
              f"HTTP {st} {text[:60]}")
        # 把游标里的**分区键**改成另一个站点：真实 DynamoDB 会 ValidationException
        # （starting key outside query boundaries）→ panel 兜底成 500。
        # **moto 下这里是 400**，所以单测看不到这个差异（M5-FINDINGS §4.6）。
        # 断言的是「不返回任何数据」——游标不能变成跨站点读别人明细的入口。
        forged = b64_cursor({"day": day,
                             "key": {"site_date": {"S": f"m5e2e-nosuch-{suf}#{day}"},
                                     "ts_id": {"S": "1970-01-01T00:00:00+00:00#000000"}}})
        st, _, text = http("GET", f"{api}/visitors?days=1&limit=5"
                                  f"&cursor={urllib.parse.quote(forged, safe='')}",
                           headers=ck(owner))
        check(st >= 400 and '"rows"' not in text,
              "游标里的分区键被改成别的站点 → 不返回任何数据（实测 500）",
              f"HTTP {st} {text[:60]}")

        print("\n── ⑧ MCP 读回：与面板同一组数字 ────────────────────")
        if mcp_caller:
            m = Mcp(mcp_endpoint(), {"authorization": f"Bearer {mcp_token}"},
                    client_name="verify-analytics-e2e")
            st_i, _ = m.initialize()
            check(st_i == 200,
                  "MCP initialize（真实用户 OAuth token 过网关并完成握手）",
                  f"HTTP {st_i}")
            ok, payload = m.call_tool("get_site_analytics",
                                      {"site_id": site_id, "period": "day",
                                       "days": 2}, expect="dict")
            check(ok, "get_site_analytics 调用成功（协作者身份即有 view_analytics）",
                  "" if ok else str(payload)[:160])
            if ok and isinstance(payload, dict):
                check(set(payload) == {"series", "recent_visitors"},
                      "返回单个 dict，字段是 series + recent_visitors"
                      "（裸列表会被拆成多个 text 块并被调用方静默截断）",
                      str(sorted(payload)))
                mbuckets = [b.get("bucket") for b in payload.get("series") or []]
                check(mbuckets == [yday, day], "MCP 的桶与面板同样日历对齐",
                      str(mbuckets))
                # 逐字段比整个 series，不只比 pv：桶键 / uv / pv_denied /
                # uv_exact 任一处漂移都必须红（两条代码路径、同一个读取层）。
                check(payload.get("series") == series,
                      "MCP 与面板的 series **逐字段完全相同**",
                      f"MCP {payload.get('series')} vs 面板 {series}")
                vpaths = {r.get("path") for r in payload.get("recent_visitors") or []}
                check(p_allow in vpaths,
                      "MCP 的 recent_visitors 里有 allow 那条探针",
                      f"{len(vpaths)} 条")
        else:
            # **不 SKIP**：MCP 不可用正是要抓的东西，永久 SKIP 是死重量（§3.6）。
            check(False, "MCP get_site_analytics 可调用",
                  f"拿不到用户 OAuth token，本段未验证：{mcp_note}")

        print("\n── ⑨ rollup：封口完整日、幂等、重算即修复、绝不封今天 ─")
        if row is None:
            check(False, "昨天的合成明细已写入（形态从真实 Edge 行派生）",
                  "② 段没有真实行可派生 ⇒ ⑨ 段整段未验证")
        else:
            # 合成行**从真实行拷贝**，只换分区键/时间/邮箱/判定/路径。手写一份
            # 形态就有「合成的与线上不同 ⇒ rollup 测过了但生产还是坏的」的风险。
            seeds = [(visitor, "allow"), (visitor, "allow"),
                     (visitor2, "allow"), (outsider, "denied_403")]
            unique_sk = ""
            for i, (mail, dec) in enumerate(seeds):
                item = dict(row)
                item["site_date"] = {"S": f"{site_id}#{yday}"}
                item["ts_id"] = {"S": f"{yday}T0{i}:00:00+00:00#{secrets.token_hex(3)}"}
                item["email"] = {"S": mail}
                item["decision"] = {"S": dec}
                item["path"] = {"S": f"/m5-seed{i}-{suf}"}
                ddb.put_item(TableName=events_table, Item=item)
                if mail == visitor2:
                    unique_sk = item["ts_id"]["S"]
            made["detail_days"].add(yday)
            seeded = query_rows(ddb, events_table, site_id, yday, consistent=True)
            check(len(seeded) == len(seeds),
                  f"昨天的合成明细已写入（{len(seeds)} 行，形态从 ② 段那行真实"
                  "Edge 写入派生）", f"{len(seeded)} 行")

            # 清理清单先记上：崩在下面任何一步都要能把这两行删掉
            made["daily_dates"].update({yday, day})
            ok, out = invoke_rollup(lam, {"days": [yday], "sites": [site_id]})
            check(ok and out.get("written") == 1,
                  "定向 invoke（带 days+sites）成功且写了 1 行", str(out)[:100])
            agg = get_daily(ddb, site_id, yday)
            if check(agg is not None, "昨天的聚合行出现", ""):
                check(daily_triple(agg) == (3, 2, 1),
                      "聚合行 == 合成明细的精确口径 pv/uv/pv_denied = 3/2/1"
                      "（uv 去重后是 2；被拒的那条只进 pv_denied）",
                      str(daily_triple(agg)))
                ttl = (int(agg["expires_at"]["N"]) - int(time.time())) / 86400
                check(399 < ttl <= 400.1,
                      "聚合行 TTL ≈ 400 天（明细只活 90 天，趋势全靠它）",
                      f"{ttl:.2f} 天")

            # `ok` 必须一起断言：第二次 invoke 若**根本没跑成**，数字当然也不变
            # ——那会让这条幂等断言因为一个完全无关的原因绿（§4.16 的形态）。
            ok, _ = invoke_rollup(lam, {"days": [yday], "sites": [site_id]})
            check(ok and daily_triple(get_daily(ddb, site_id, yday)) == (3, 2, 1),
                  "再 invoke 一次 → 调用成功且数字不变（幂等覆盖写，不是累加）",
                  f"ok={ok} {daily_triple(get_daily(ddb, site_id, yday))}")

            # 「重算即修复」：删掉唯一带 visitor2 的那条 allow，pv 与 uv 都该降。
            # **只有覆盖写的实现会降**——「聚合行已存在就跳过」会停在 3/2/1，
            # 而那正是 M5 单测第一版测不出来的那个实现（d10b4d1 补的钉）。
            ddb.delete_item(TableName=events_table,
                            Key={"site_date": {"S": f"{site_id}#{yday}"},
                                 "ts_id": {"S": unique_sk}})
            ok, _ = invoke_rollup(lam, {"days": [yday], "sites": [site_id]})
            check(ok and daily_triple(get_daily(ddb, site_id, yday)) == (2, 1, 1),
                  "删掉一条 allow 明细后重算 → 2/1/1（覆盖写；「存在就跳过」会停在 3/2/1）",
                  f"ok={ok} {daily_triple(get_daily(ddb, site_id, yday))}")

            # 默认站点枚举走 sites 表 Scan。漏给 dynamodb:Scan 时**单测全绿、
            # 真机 500**（moto 不校验 IAM），只有真机能发现。
            ddb.delete_item(TableName=DAILY_TABLE,
                            Key={"site_id": {"S": site_id}, "date": {"S": yday}})
            ok, out = invoke_rollup(lam, {"days": [yday]})
            check(ok and out.get("sites", 0) >= 1,
                  "不带 sites 的 invoke 成功（站点清单来自 sites 表 Scan）",
                  str(out)[:100])
            check(daily_triple(get_daily(ddb, site_id, yday)) == (2, 1, 1),
                  "聚合行被**默认枚举**重建 ⇒ Scan 真的覆盖到这个站点、"
                  "角色真有 dynamodb:Scan",
                  str(daily_triple(get_daily(ddb, site_id, yday))))

            # 「绝不封今天」：同一次 invoke 里既有正对照（昨天被写了）又有负测
            # （今天没有行）。少了正对照，「今天没有行」也可能只是它压根没跑。
            ddb.delete_item(TableName=DAILY_TABLE,
                            Key={"site_id": {"S": site_id}, "date": {"S": yday}})
            ok, out = invoke_rollup(lam, {"sites": [site_id]})
            check(ok, "不带 days 的 invoke 成功（回溯窗口由 target_days 算）",
                  str(out)[:100])
            check(get_daily(ddb, site_id, yday) is not None,
                  "正对照：这一次 invoke 确实给昨天写了行", "")
            check(get_daily(ddb, site_id, day) is None,
                  "**今天没有**聚合行（只封口完整日；封今天会把半天固化成全天）",
                  "")

            st, _, text = http("GET", f"{api}/analytics?period=day&n=2",
                               headers=ck(owner))
            s2 = as_json(text).get("series") or []
            y2 = s2[0] if len(s2) == 2 else {}
            check((y2.get("pv"), y2.get("uv"), y2.get("pv_denied")) == (2, 1, 1),
                  "封口后面板昨天的桶 == 聚合行 2/1/1（⑦ 段那时是 0）"
                  "⇒ 历史读的是聚合表，且那个 0 不是伪造的",
                  f"HTTP {st} 面板给 {y2.get('pv')}/{y2.get('uv')}/{y2.get('pv_denied')}")

        print("\n── ⑩ 基准是否稳定（上面每个精确数字的前提）──────────")
        final_rows = query_rows(ddb, events_table, site_id, day)
        check(len(rows_today) > 0 and len(final_rows) == len(rows_today),
              "整场比对期间这个站点今天没有多出明细行（基准稳定，不是撞上了竞态）",
              f"{len(rows_today)} → {len(final_rows)} 行")
        check(datetime.now(timezone.utc).strftime("%Y-%m-%d") == day,
              "整场跑完仍在同一个 UTC 日（跨日则分区键与桶键都换了，数字不可比）",
              day)
        return 0

    finally:
        failed_now = any(not ok for ok, _, _ in results)
        if args.keep_on_failure and failed_now:
            print("\n⚠️  --keep-on-failure：保留本次 fixture 以便排查")
            print(f"    站点行     {sites_table} / site_id={site_id}")
            print(f"    路由行     {routing_table} / subdomain={subdomain}")
            print(f"    对象       s3://{bucket}/{static_prefix}/"
                  "{index.html,probe.css}")
            print(f"    明细分区   {events_table} / {site_id}#{{{day},{yday}}}")
            print(f"    聚合行     {DAILY_TABLE} / {site_id} / {{{day},{yday}}}")
        elif not (made["site"] or made["route"] or made["objects"]
                  or made["detail_days"] or made["daily_dates"] or made["stray"]):
            # 前置就没过（例如表还没部署）时一件资源都没建，跑清理只会用一堆
            # ResourceNotFoundException **顶掉真正的错因**——这次真机试跑就是这么
            # 发现的：Abort 的那句「M5 还没部署」被清理时的异常埋在三层
            # traceback 中间。
            print("\n（没有创建任何资源，无需清理）")
        else:
            print("\n── 清理（只删本次后缀 "
                  f"{suf} 的资源，逐个指名 + 读回核对）──")
            try:
                leftovers = _cleanup(ddb, s3, made, bucket, sites_table,
                                     routing_table, events_table, site_id,
                                     subdomain, day)
            except Exception as exc:            # noqa: BLE001
                # **清理自身出错绝不能顶掉主流程的异常**：那会把「断言失败」
                # 变成「清理时报了个别的错」，排查方向整个偏掉。
                leftovers = [f"清理过程本身出错：{type(exc).__name__}: {exc}"]
            check(not leftovers, "清理完成并强一致读回核对（0 残留）",
                  f"残留：{leftovers}" if leftovers else "")


def _cleanup(ddb, s3, made, bucket, sites_table, routing_table,
             events_table, site_id, subdomain, day) -> list[str]:
    """按依赖顺序删本次资源，返回残留清单（空 = 干净）。

    **先删路由**：它是「还能产生新明细行」的唯一入口，先掐掉它再删数据，
    否则一次晚到的请求会在清理之后又写一行。
    `delete_item` 返回 200 不等于真删掉了，所以每一类都强一致读回。
    """
    leftovers: list[str] = []

    def swallow(fn):
        """删除动作报错只打印，判定交给下面的读回核对（删不掉 = 残留 = 失败）。"""
        try:
            fn()
        except Exception as exc:            # noqa: BLE001
            print(f"    （删除时报错，留给读回核对判定：{type(exc).__name__}: {exc}）")

    def probe(what: str, fn):
        """读回一项。**核对不了也算残留**——「查不到就当干净」正是清理最不能有的
        默认（那会把一次没删干净读成一次干净的收尾）。"""
        try:
            if fn():
                leftovers.append(what)
        except Exception as exc:            # noqa: BLE001
            leftovers.append(f"{what}（无法核对：{type(exc).__name__}）")

    if made["route"]:
        swallow(lambda: ddb.delete_item(
            TableName=routing_table, Key={"subdomain": {"S": subdomain}}))
    for key in made["objects"]:
        swallow(lambda k=key: s3.delete_object(Bucket=bucket, Key=k))
    for d in {day} | set(made["detail_days"]):
        try:
            doomed = query_rows(ddb, events_table, site_id, d, consistent=True)
        except Exception as exc:            # noqa: BLE001
            print(f"    （列举 {site_id}#{d} 的明细行失败：{type(exc).__name__}）")
            doomed = []
        for r in doomed:
            swallow(lambda r=r, d=d: ddb.delete_item(
                TableName=events_table,
                Key={"site_date": {"S": f"{site_id}#{d}"},
                     "ts_id": r["ts_id"]}))
    for part, ts in made["stray"]:
        swallow(lambda p=part, t=ts: ddb.delete_item(
            TableName=events_table,
            Key={"site_date": {"S": f"{p}#{day}"}, "ts_id": t}))
    for d in set(made["daily_dates"]):
        swallow(lambda d=d: ddb.delete_item(
            TableName=DAILY_TABLE,
            Key={"site_id": {"S": site_id}, "date": {"S": d}}))
    if made["site"]:
        swallow(lambda: ddb.delete_item(
            TableName=sites_table, Key={"site_id": {"S": site_id}}))

    if made["route"]:
        probe(f"路由 {subdomain}", lambda: ddb.get_item(
            TableName=routing_table, Key={"subdomain": {"S": subdomain}},
            ConsistentRead=True).get("Item"))
    if made["site"]:
        probe(f"站点 {site_id}", lambda: ddb.get_item(
            TableName=sites_table, Key={"site_id": {"S": site_id}},
            ConsistentRead=True).get("Item"))
    for key in made["objects"]:
        def _obj_left(k=key):
            try:
                s3.head_object(Bucket=bucket, Key=k)
                return True
            except ClientError:
                return False        # 404 = 真删了
        probe(f"对象 {key}", _obj_left)
    for d in {day} | set(made["detail_days"]):
        probe(f"明细 {site_id}#{d}",
              lambda d=d: len(query_rows(ddb, events_table, site_id, d,
                                         consistent=True)) or False)
    for d in set(made["daily_dates"]):
        probe(f"聚合 {site_id}/{d}", lambda d=d: get_daily(ddb, site_id, d))
    for part, ts in made["stray"]:
        probe(f"越界明细 {part}#{day}", lambda p=part, t=ts: ddb.get_item(
            TableName=events_table,
            Key={"site_date": {"S": f"{p}#{day}"}, "ts_id": t},
            ConsistentRead=True).get("Item"))
    print("    " + ("干净" if not leftovers else f"残留 {leftovers}"))
    return leftovers


if __name__ == "__main__":
    # 行缓冲：重定向到文件时 stdout 默认按块缓冲，而 traceback 走 stderr（无缓冲）
    # ——于是 `> log 2>&1` 里段落标题会跑到错误后面，证据日志读起来像另一次运行。
    sys.stdout.reconfigure(line_buffering=True)
    rc, crashed = 1, ""
    try:
        rc = main()
    except Abort as exc:
        print(f"\n前置条件不满足：{exc}")
        crashed = f"Abort: {exc}"
    except Exception as exc:                # noqa: BLE001
        traceback.print_exc()
        # **必须记在 finally 之外**：只置 rc=1 会被下面按「项数够了」重算成 0
        # （verify_deployed_components 踩过，2026-08-08 独立审查复现）。
        crashed = f"{type(exc).__name__}: {exc}"
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        print()
        if crashed:
            print(f"结果：执行中断（{crashed}）—— 验收**未完成**，状态不可信")
            rc = 1
        elif len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）"
                  "—— 验收**未完成**，状态不可信")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else ""))
            rc = 1 if failed else 0
    sys.exit(rc)
