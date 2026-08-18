#!/usr/bin/env python3
"""一次性迁移：把存量站点从「Function URL 挂在 `$LATEST`」迁到 blue/green 双 alias。

背景（M7 spec §4.3）：存量站点的路由 `api_target` 指向**无 qualifier** 的 Function
URL，也就是指向 `$LATEST`。于是任何 `update_function_code` 都当场上线——未经健康门的
代码没有暂存区。blue/green 要求路由指向**某个颜色的 alias URL**，`$LATEST` 退化成纯
暂存区并且**永不挂 URL**。

`deploy_lambda_site.handler` 对未迁移站点 fail-closed（抛 `UnmigratedSite`），所以本
脚本产出的状态就是「让它不再抛」的那个状态。判据必须与它对得上：它判的是
**「路由存在、但它指向的不是任何一个颜色的 URL」**（`_live_color(...) is None and
target`）。所以本脚本的完成判据是**路由的 api_target 等于某个颜色的 URL，且无
qualifier 的 URL 已删除**——只把 alias/URL 建出来是不够的。

那条闸门的判据曾经写成 `live is None and **not urls**`（AND），于是本脚本第 4 步
健康门失败留下的**半迁移**状态（blue alias + blue URL 已建、路由仍在 `$LATEST`）
恰好被放行：`urls` 非空 ⇒ 不抛 ⇒ `update_function_code` 推 `$LATEST` ⇒ 未经健康门的
代码当场对外服务，正是 v1 被驳回的 P1-1 同一形态（Codex 2026-08-17 P1-3 复现）。
现在改成按**路由**判，所以本脚本留下半套状态是安全的（下次部署会被拦住并指回这里），
但**不要把闸门改回按 `urls` 判**。

每个站点七步（顺序是死的）：

    1. publish_version（当前线上代码）        → 不可变版本 P
    2. blue alias → P                        （已存在则 update）
    3. 建 blue 的 Function URL + 两条 add_permission（Qualifier=blue）
    4. 健康门：直调 blue 的 /api/health       ← 不过就跳过该站并报告，**不改路由**
    5. 路由 update_item **只改 api_target** → blue URL   ← 提交点
    6. sleep 65s（Edge ROUTE_CACHE_TTL=60）后从公网复查
    7. 删除无 qualifier 的 Function URL       ← 此后 `$LATEST` 无入口

为什么第 3 步在健康门**之前**（与 `deploy_lambda_site` 里"挂 URL 在健康门之后"相反）：
迁移时版本 P 与**正在服务公网**的 `$LATEST` 字节相同（publish 就是给它拍快照），所以
建 blue URL 不新增任何暴露；而第 6 步要打公网，必须先有 URL 与授权。日常部署里候选是
**新代码**，那里的顺序不能照抄这里。

用法：

    python3 site-builder/scripts/migrate_sites_to_blue_green.py            # dry-run
    python3 site-builder/scripts/migrate_sites_to_blue_green.py --apply    # 实际迁移
    python3 site-builder/scripts/migrate_sites_to_blue_green.py --apply --site-id s-1

**默认 dry-run**：本脚本改生产站点的路由，且第 7 步不可逆。dry-run 一个写调用都不发
（用例按 mock 的写方法 `assert_not_called` 锁死，不是只看打印）。
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

import boto3

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))

import common                    # noqa: E402
import deploy_lambda_site        # noqa: E402
import smoke_test                # noqa: E402

# 颜色定义、live 颜色推导、健康门**都从部署侧引用，不在这里抄第二份**：迁移与部署对
# "什么算已迁移"必须逐字同义，抄两份的下一步就是两份漂移（本轮的元教训）。
COLORS = deploy_lambda_site.COLORS

# Edge 的路由缓存 TTL 是 60s（router/infrastructure/lambda/origin_request.py 的
# ROUTE_CACHE_TTL = 60）。删旧 URL 之前必须等到所有 Edge 实例的缓存过期——早删就是
# 让还拿着旧 api_target 的实例把请求打到一个已经不存在的端点上（当场 404）。
ROUTE_CACHE_SECONDS = 65

# `skipped:<tag> …` 里这两个 tag 表示"这个站点本来就不该迁"，不计入问题；其余 skip
# （unhealthy / unknown-target / no-route）都要人工处理，会让退出码非 0。
NOT_APPLICABLE = ("static", "no-function")


def _sleep(seconds: int) -> None:
    """模块级，好让用例 patch 掉——否则每条用例真等 65 秒。"""
    import time
    time.sleep(seconds)


def _load_config() -> None:
    """从 config.ini 填好需要的环境变量。

    **直接赋值，不用 setdefault**：config.ini 是唯一取值来源（CLAUDE.md），
    setdefault 会让 shell 里残留的旧 ROUTING_TABLE 静默改写写入目标。
    """
    path = HERE.parent / "config.ini"
    if not path.exists():
        raise SystemExit(f"找不到 {path}——从 config.ini.example 复制并填好再跑")
    cfg = configparser.ConfigParser()
    cfg.read(path)
    try:
        os.environ["ROUTING_TABLE"] = cfg["Platform"]["routing_table"]
        os.environ["BASE_DOMAIN"] = cfg["Platform"]["base_domain"]
        os.environ["AWS_DEFAULT_REGION"] = cfg["Platform"]["region"]
        os.environ["EDGE_ROLE_ARN"] = cfg["Deployer"]["edge_role_arn"]
    except KeyError as e:
        raise SystemExit(f"config.ini 缺少 {e}——对照 config.ini.example 补齐") from e
    if not os.environ["EDGE_ROLE_ARN"]:
        # 空串会让 add_permission 报一句难读的校验错，而真正的问题是配置没回填。
        # 更糟的是：授权若失败而后面的步骤照走，公网复查会 403，站点在提交点之后坏掉。
        raise SystemExit("config.ini 的 [Deployer] edge_role_arn 是空的——"
                         "先回填（部署 router 栈后可从栈输出取）")


def _public_check(subdomain: str, require_auth: bool) -> str:
    """从公网确认这一色真的在服务。返回 `""` = 通过，否则返回失败原因。

    判据复用 `smoke_test._check`（**不手抄第二份 302/200 规则**）：require_auth 站点的
    健康态是"302 且 Location 指向登录端点"，直接 200 意味着鉴权失效。

    这一步是本脚本唯一能发现「health gate 过了但公网仍不通」的地方——最典型的成因是
    `add_permission` 没带 Qualifier 或只给了一条语句（2025-10 起需要两条），此时直调
    alias 完全正常而 Edge 调用 403。
    """
    base = os.environ["BASE_DOMAIN"]
    url = f"https://{subdomain}.{base}{deploy_lambda_site.HEALTH_PATH}"
    try:
        smoke_test._check(url, require_auth, f"https://auth.{base}/login", "公网复查")
    except smoke_test.SmokeFailure as e:
        return str(e)
    return ""


def _unqualified_url(lam, fn: str) -> str | None:
    """挂在 `$LATEST` 上的那个 Function URL（没有则 None）。

    它的有无就是"迁移的最后一步做完了吗"：还在 = `$LATEST` 仍有公网入口。
    """
    try:
        return lam.get_function_url_config(
            FunctionName=fn)["FunctionUrl"].rstrip("/")
    except lam.exceptions.ResourceNotFoundException:
        return None


def _other_route_on(ddb, subdomain: str, url: str) -> str | None:
    """还有**别的**路由指着 `url` 吗？返回第一条这样的 subdomain，没有则 None。

    第 7 步删无 qualifier 的 URL 是**不可逆**的，而 `migrate_one` 只会切
    `subdomain_for(site_id)` 那一条路由。真实生产数据里就有一个站点带两条路由
    （`app-smk431d776a` 与 `app-smkauth431d776a`，site_id 相同，smoke_router.sh 的
    残留）——那种情形下删掉旧 URL 会让没被切换的那条路由当场 404。所以在**动任何
    东西之前**先问这一句，而不是切完路由才发现。

    代价是每个站点一次 scan（路由表是个位数条目，可忽略）；换来的是这条闸门对
    `--site-id` 单站点跑法同样生效，而不是只在批量枚举那一层拦。
    """
    target = (url or "").rstrip("/")
    for page in ddb.get_paginator("scan").paginate(
            TableName=os.environ["ROUTING_TABLE"]):
        for item in page.get("Items", []):
            other = item.get("subdomain", {}).get("S", "")
            if other == subdomain:
                continue
            if item.get("api_target", {}).get("S", "").rstrip("/") == target:
                return other
    return None


def _color_urls(lam, fn: str, aliases: set) -> dict:
    """存在的颜色各自的 Function URL。

    只对**确实存在的 alias** 取 URL：`deploy_lambda_site._color_urls` 逐色试 URL，
    未迁移站点每次连吃两个 404；批量跑 6 个存量站点时先 `list_aliases` 列一次就能
    把绝大多数站点在一次调用里判掉（Ruling 59-3）。
    """
    out = {}
    for c in COLORS:
        if c not in aliases:
            continue
        try:
            out[c] = lam.get_function_url_config(
                FunctionName=fn, Qualifier=c)["FunctionUrl"].rstrip("/")
        except lam.exceptions.ResourceNotFoundException:
            pass          # alias 有、URL 没建（上次迁移半途失败）⇒ 这一色不算就绪
    return out


def _grant_edge(lam, fn: str, color: str) -> None:
    """让 Edge role 能调这一色的 Function URL。

    2025-10 起需要 `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl)
    两条语句，缺一即 403；**两条都要带 Qualifier**，不带就授在函数上，与"URL 只挂在
    颜色上"不一致。与 `deploy_lambda_site` 里那段同形（那里是新建色，这里是迁移）。
    """
    for sid, action, extra in (
            ("edge-invoke", "lambda:InvokeFunctionUrl",
             {"FunctionUrlAuthType": "AWS_IAM"}),
            ("edge-invoke-function", "lambda:InvokeFunction",
             {"InvokedViaFunctionUrl": True})):
        try:
            lam.add_permission(FunctionName=fn, Qualifier=color, StatementId=sid,
                               Action=action,
                               Principal=os.environ["EDGE_ROLE_ARN"], **extra)
        except lam.exceptions.ResourceConflictException:
            pass          # 上次跑到这里就中断了：语句已在，幂等继续


def migrate_one(lam, ddb, site_id: str, *, dry_run: bool = True) -> str:
    """迁一个站点。返回 `"migrated"` / `"already"` / `"skipped:<tag> 原因"` /
    `"switched-unverified:原因"`。

    `dry_run` 是**关键字参数且默认 True**：位置传参写错一个布尔就会在生产上开写。
    """
    fn = f"site-{site_id}"
    subdomain = common.subdomain_for(site_id)
    route = ddb.get_item(TableName=os.environ["ROUTING_TABLE"],
                         Key={"subdomain": {"S": subdomain}},
                         ConsistentRead=True).get("Item")
    if not route:
        return f"skipped:no-route 路由表里没有 {subdomain} 这条路由"
    api_target = route.get("api_target", {}).get("S", "").rstrip("/")
    if not api_target:
        # static 站点：CDK 的 HasBackend? Choice 在 tier == "static" 时直接跳过
        # DeployLambdaSite，所以它们**没有** Lambda / alias / api_target。
        # 报成 skipped 而不是静默略过：静默的"无"和"确实不用迁"长得一样，而 C1 要
        # 拿真站点跑这个脚本，看不见的跳过等于看不见的漏迁。
        return ("skipped:static 路由没有 api_target（static 站点没有后端 Lambda，"
                "blue/green 不适用）")
    try:
        aliases = {a["Name"] for a in lam.list_aliases(FunctionName=fn)["Aliases"]}
    except lam.exceptions.ResourceNotFoundException:
        return (f"skipped:no-function 找不到 Lambda 函数 {fn}"
                "（static 站点或函数已被删除）")

    urls = _color_urls(lam, fn, aliases)
    live = deploy_lambda_site._live_color(api_target, urls)
    old_url = _unqualified_url(lam, fn)

    if old_url is not None:
        # 下面**两条**路径最后都会删掉这个 URL（迁移的第 7 步、续做的补做），所以闸门
        # 放在分叉之前问一次；dry_run 也要问，否则 dry-run 报 migrated 而 apply 拒绝
        # ——人工审查关口读到的就是假话。
        other = _other_route_on(ddb, subdomain, old_url)
        if other:
            return (f"skipped:shared-backend 路由 {other} 也指向 {old_url}，而迁移的"
                    "最后一步要删掉它（那条路由会当场 404）。请先人工处理那条路由")

    if live is not None:
        # 路由已经指着某个颜色。剩下的唯一可能欠账是第 7 步没做完。
        if old_url is None:
            return "already"
        # **不重新 publish**：这次跑的 `$LATEST` 未必还是当初上线的那份代码
        # （可能被一次失败的部署污染过），而 live 色的版本已经是被验证过的。
        if dry_run:
            _plan(f"{fn}: 路由已在 {live}，仅删除 $LATEST 上的旧 URL {old_url}")
            return "migrated"
        lam.delete_function_url_config(FunctionName=fn)
        return "migrated"

    if old_url is None:
        return ("skipped:unknown-target 认不出线上在服务什么——api_target "
                f"{api_target} 既不是 blue/green 的 URL，也没有无 qualifier 的 "
                "Function URL。请人工核对后再迁")

    color = COLORS[0]
    if dry_run:
        _plan(f"{fn}: {old_url}($LATEST) → {color} alias URL；"
              f"路由 {subdomain}.api_target 将从 {api_target} 改为新建的 {color} URL；"
              f"健康门通过后等 {ROUTE_CACHE_SECONDS}s 再删旧 URL")
        return "migrated"

    version = lam.publish_version(FunctionName=fn)["Version"]
    try:
        lam.create_alias(FunctionName=fn, Name=color, FunctionVersion=version)
    except lam.exceptions.ResourceConflictException:
        lam.update_alias(FunctionName=fn, Name=color, FunctionVersion=version)
    try:
        url = lam.create_function_url_config(
            FunctionName=fn, Qualifier=color, AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(
            FunctionName=fn, Qualifier=color)["FunctionUrl"]
    _grant_edge(lam, fn, color)
    try:
        # 与部署路径**同一个**健康门：直调 alias ⇒ 新执行环境 ⇒ 真冷启测试。
        deploy_lambda_site._health_check(lam, fn, color)
    except deploy_lambda_site.BackendUnhealthy as e:
        # 路由一个字都没动 ⇒ 线上仍在 `$LATEST`，零影响。留下的版本与 alias 无害
        # （没有路由指向它们），下次重跑会 update 到新版本。
        return f"skipped:unhealthy 健康门未通过，路由未切换（线上仍在 $LATEST）：{e}"

    # ── 提交点：只改 api_target ────────────────────────────────────────
    # **不能整条 put_item**：脚本手里的快照会盖掉 require_auth / allowed_users /
    # static_prefix / permissions_rev——一次数据修复动作变成静默的策略变更。
    # 条件 attribute_exists(subdomain)：站点若在扫描与切换之间被下线，无条件
    # update_item 会**凭空建出**一条只有 subdomain + api_target 的路由（DynamoDB 的
    # upsert 语义），Edge 读到它会按缺失字段回落默认值。
    ddb.update_item(TableName=os.environ["ROUTING_TABLE"],
                    Key={"subdomain": {"S": subdomain}},
                    UpdateExpression="SET api_target = :t",
                    ConditionExpression="attribute_exists(subdomain)",
                    ExpressionAttributeValues={":t": {"S": url.rstrip("/")}})

    _sleep(ROUTE_CACHE_SECONDS)
    reason = _public_check(subdomain,
                           bool(route.get("require_auth", {}).get("BOOL", True)))
    if reason:
        # 提交点之后失败：**不删旧 URL**。留着它，把 api_target 指回 old_url 就是
        # 一步回滚。状态既不是 migrated 也不是 skipped——路由确实已经切了，报成
        # 那两者任何一个都会让操作者在唯一的报告里读到假话。
        return (f"switched-unverified:路由已切到 {color}（{url}），但公网复查失败；"
                f"旧 URL {old_url} 已保留，回滚 = 把 api_target 改回它。原因：{reason}")

    lam.delete_function_url_config(FunctionName=fn)   # 此后 $LATEST 无入口
    return "migrated"


def _plan(msg: str) -> None:
    """dry-run 的计划行。走**同一条决策路径**打印，所以报告不会与实际行为分叉。"""
    print(f"    计划 {msg}")


def _needs_attention(status: str) -> bool:
    """这个状态需要人去处理吗？

    分类是操作者唯一的抓手，所以"确实不用迁"（static / 没有函数）与"没迁成"
    （健康门、认不出、共用后端、提交后未验证、异常）必须落在不同的桶里——混在
    一起就等于让健康门失败躲在 static 站点后面。
    """
    if status in ("migrated", "already"):
        return False
    return status.split(" ")[0].removeprefix("skipped:") not in NOT_APPLICABLE


def _app_routes(ddb) -> tuple[list, list]:
    """扫路由表，返回 (站点 site_id 列表, 畸形路由的说明列表)。

    只取站点路由：平台路由（console / auth / mcp …）不带 `app-` 前缀。缺 site_id 的
    `app-` 路由**报出来而不是丢掉**——一条看不见的漏迁就是一个仍挂在 `$LATEST` 上的站点。
    """
    prefix = common.subdomain_for("")        # "app-"；前缀的唯一真源在 common
    seen, problems = {}, []
    for page in ddb.get_paginator("scan").paginate(
            TableName=os.environ["ROUTING_TABLE"]):
        for item in page.get("Items", []):
            sub = item.get("subdomain", {}).get("S", "")
            if not sub.startswith(prefix):
                continue
            site_id = item.get("site_id", {}).get("S", "")
            if not site_id:
                problems.append(f"路由 {sub} 缺 site_id，无法定位函数——请人工核对")
                continue
            seen.setdefault(site_id, []).append(sub)
    site_ids = []
    for site_id, subs in sorted(seen.items()):
        if len(subs) > 1:
            # 一个 site_id 挂两条路由（实测有：smoke_router.sh 的残留）。migrate_one
            # 只切 subdomain_for(site_id) 那一条，另一条会留在旧 URL 上而旧 URL 会被
            # 删除 ⇒ 排除出批量并报出来，**不猜哪条才是正主**。
            problems.append(f"站点 {site_id} 有 {len(subs)} 条路由 "
                            f"{sorted(subs)}——已排除，请先人工清理多余的那条")
            continue
        site_ids.append(site_id)
    return site_ids, problems


def main() -> int:
    ap = argparse.ArgumentParser(
        description="存量站点迁移到 blue/green（默认 dry-run）")
    ap.add_argument("--apply", action="store_true", help="实际迁移（默认只报告）")
    ap.add_argument("--dry-run", action="store_true",
                    help="显式只报告（默认行为；与 --apply 互斥）")
    ap.add_argument("--site-id", help="只处理这一个站点（默认全部 app- 路由）")
    args = ap.parse_args()
    if args.apply and args.dry_run:
        # 两个都给了就是意图不明；按哪个走都可能不是操作者要的，所以拒绝执行。
        raise SystemExit("--apply 与 --dry-run 互斥，请只给一个")
    dry_run = not args.apply

    _load_config()
    lam = boto3.client("lambda")
    ddb = boto3.client("dynamodb")
    if args.site_id:
        site_ids, problems = [args.site_id], []
    else:
        site_ids, problems = _app_routes(ddb)

    print(f"[{'DRY-RUN' if dry_run else 'APPLY'}] 站点 {len(site_ids)} 个")
    results = {}
    for site_id in sorted(site_ids):
        try:
            results[site_id] = migrate_one(lam, ddb, site_id, dry_run=dry_run)
        except Exception as e:                                    # noqa: BLE001
            # 一个站点炸掉不能中止整批：apply 模式下中止 = 半套迁移 + 没有报告，
            # 操作者不知道停在哪（migrate_permissions 同一处置）。
            results[site_id] = f"error:{type(e).__name__}: {e}"
        print(f"  - {site_id}: {results[site_id]}")

    attention = {s: r for s, r in results.items() if _needs_attention(r)}
    n = {"migrated": 0, "already": 0, "不适用": 0}
    for site_id, r in results.items():
        n[r if r in ("migrated", "already")
          else "不适用"] += 0 if site_id in attention else 1
    for p in problems:
        print(f"  ! {p}")
    print(f"\n迁移 {n['migrated']} · 已是 blue/green {n['already']} · "
          f"不适用 {n['不适用']} · 需人工 {len(attention)}"
          f"{'（含未处理的路由问题 %d 条）' % len(problems) if problems else ''}")
    for site_id, r in attention.items():
        print(f"  ! {site_id}: {r}")
    if dry_run and site_ids:
        print("\n确认无误后加 --apply 实际迁移")
    return 1 if (attention or problems) else 0


if __name__ == "__main__":
    sys.exit(main())
