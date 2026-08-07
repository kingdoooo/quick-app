"""SFN 步骤 6：注册子域名路由（含 auth 策略与 owner）。

put_item 覆盖整个 item = 原子切流：static_prefix 指向本次 job 的版本化前缀，
写入瞬间所有新请求走新版本（Edge 路由缓存最多再滞后 60s）。

权限字段（require_auth / allowed_users / collaborators / owner）的**真源是
sites 表**，不是 manifest——用户可能在控制台在线改过，manifest 里带的是
生成代码时的旧值。仅首次部署（sites 表尚无 require_login 字段）用 manifest
的 auth 段初始化真源。改这段逻辑前先读
docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md §3。
"""
import os

import boto3

import common
import permissions


MAX_ROUTE_ATTEMPTS = 3


def _seed_permissions_if_absent(site_id: str, manifest_auth: dict,
                                owner: str) -> None:
    """首次部署：把 manifest 的 auth 用来**补齐真源里缺失的权限字段**。

    **逐字段 if_not_exists，不要拿任何单个字段当"整套已初始化"的 sentinel。**
    早先的实现条件写 attribute_not_exists(require_login) 却同时覆盖
    require_login + allowed_users，这在稀疏行上是静默扩权（moto 实证）：
    在线接口只持久化调用方显式传入的字段（permissions.write_permissions），
    所以"部署前只改过 allowed_users"会留下 require_login 缺失的行 →
    sentinel 判定"未初始化" → seed 用 manifest 的值把指定邮箱名单盖回
    "org"，私有站点变成全组织可见。

    反向稀疏同样有坑：只改过 require_login 的行 sentinel 存在 → 整个 seed
    被跳过 → allowed_users 一直缺失 → _route_item 回落 "org"，也是扩权。

    因此：每个字段独立 if_not_exists 补缺；只要有一个字段缺就写一次
    （条件表达式保证两个都在时是真正的 no-op，不白推进 updated_at）。
    """
    import botocore.exceptions
    allowed = permissions.normalize_allowed_users(manifest_auth["allowed_users"])
    try:
        boto3.resource("dynamodb", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1")).Table(
            os.environ["SITES_TABLE"]).update_item(
            Key={"site_id": site_id},
            UpdateExpression=(
                "SET require_login = if_not_exists(require_login, :rl), "
                "allowed_users = if_not_exists(allowed_users, :au), "
                "collaborators = if_not_exists(collaborators, :co), "
                "permissions_rev = if_not_exists(permissions_rev, :one), "
                "permissions_updated_at = :t, "
                "permissions_updated_by = :by"),
            # 缺任一个受管字段 → 只补那一个，已有的由 if_not_exists 原样保留
            # （在线值永不被 manifest 覆盖）；三个都在 → 条件失败 = 真正的 no-op。
            #
            # **permissions_rev 必须进这个条件**：稀疏行可能两个 auth 字段都在、
            # 而 rev 缺失（upsert_site 建站只写 owner/name/status，在线写也只
            # 持久化调用方显式传的字段）。漏掉它的话 seed 整体被跳过 → rev 永远
            # 补不上 → 下面的快照守卫（要求 rev 存在，fail-closed）每轮都失败，
            # 把一次**合法**部署卡成"权限被并发修改"。本函数是 rev 存在性的
            # 唯一保证点，条件必须覆盖它要写的每个字段。
            ConditionExpression=("attribute_not_exists(require_login) OR "
                                 "attribute_not_exists(allowed_users) OR "
                                 "attribute_not_exists(permissions_rev)"),
            ExpressionAttributeValues={
                ":rl": bool(manifest_auth["require_login"]),
                ":au": allowed,
                ":co": [],
                ":t": permissions.now_iso(),
                ":by": owner,
                # rev 至少推到 1：让"未初始化"(缺字段或 0) 与"已初始化"在条件
                # 表达式里可区分。若这里留 0，seed 前后的 rev 都是 0，后续
                # ConditionCheck 察觉不到中间发生过初始化。已有 rev（在线写
                # 已推进过）时用 if_not_exists 保留，不回退也不虚增。
                ":one": 1})
    except botocore.exceptions.ClientError as e:
        # ConditionalCheckFailed = 两个字段都已存在：完全用真源的值（幂等吞掉）。
        # 其余错误（限流、校验……）必须如实上抛——放宽成裸 pass 会让 seed
        # 静默失败，_route_item 回落 allowed_users="org"（fail-open 扩权）。
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise


def _route_item(event, site: dict, owner: str, subdomain: str) -> dict:
    allowed = site.get("allowed_users", "org")
    return {"subdomain": {"S": subdomain},
            "site_id": {"S": event["site_id"]},
            "route_mode": {"S": "split"},
            "static_prefix": {"S": f"sites/{event['site_id']}/{event['job_id']}"},
            "api_target": {"S": event.get("api_target", "")},
            "require_auth": {"BOOL": bool(site.get("require_login", True))},
            "allowed_users": permissions.allowed_users_av(allowed),
            "collaborators": {"L": [{"S": e} for e in
                                    (site.get("collaborators") or [])]},
            "owner": {"S": owner},
            "permissions_rev": {"N": str(int(site.get("permissions_rev", 0)))}}


def handler(event, context):
    """写路由（原子切流）。权限值取自 sites 表真源，并用条件事务防并发覆盖。

    为什么必须是事务：本步骤是"读 sites → 写整条路由"。若中间有人在线收紧
    权限（那边是两表事务，sites 与路由都已改成私有），这里再用旧快照
    put_item 整条，就把路由写回公开——sites=私有 / Edge=公开，正是在线改权限
    的事务本该消除的安全状态错误。DynamoDB 事务只保证事务内原子，不会把事务
    之前的普通读与之后的普通写合成一个业务事务。见 spec §3.2。

    做法：对 sites 表做 ConditionCheck（permissions_rev 仍是我读到的值）+
    对路由表 Put 整条，同一事务提交。冲突则重读重试（≤3 次）；仍冲突就让
    本步骤失败——部署 FAILED 比留下错误的公开状态好。
    """
    import botocore.exceptions

    common.update_job(event["job_id"], phase="register-route")
    subdomain = common.subdomain_for(event["site_id"])
    ddb = boto3.client("dynamodb")

    site = common.get_site_consistent(event["site_id"]) or {}
    owner = site.get("owner") or common.get_job(event["job_id"])["owner"]
    _seed_permissions_if_absent(event["site_id"], event["manifest"]["auth"], owner)

    for attempt in range(MAX_ROUTE_ATTEMPTS):
        # **必须强一致读**：紧接在 _seed_permissions_if_absent 之后，
        # 最终一致读可能拿不到刚写入的权限，_route_item 就会回落默认值
        # （require_login=True / allowed_users="org"）——把指定邮箱名单
        # 错误地放大成"全体可信 IdP 用户"。且 seed 把 rev 明确写成 1，
        # 与"未初始化"的 0 区分开，否则条件检查察觉不到这次状态变更。
        site = common.get_site_consistent(event["site_id"]) or {}
        owner = site.get("owner") or owner
        rev = int(site.get("permissions_rev", 0))
        try:
            # 守卫走 permissions.sites_snapshot_guard（全仓库唯一定义）。
            # **had_rev 传 site 里的真实情况**，不要写死 True：
            # _seed_permissions_if_absent 刚把 rev 补成 1，所以正常路径必然
            # had_rev=True 走精确匹配；真的读不到 rev 说明 seed 没生效或记录
            # 被替换，此时精确匹配会失败 → 走重试重读（fail-closed），
            # 而不是被 attribute_not_exists 静默放行。
            #
            # 原来手抄的 `attribute_not_exists(permissions_rev) OR rev = :rev`
            # 在"站点被同 site_id 重建且无 rev"时成立：旧 job 会把新站点的路由
            # 覆盖成旧 static_prefix / 旧 owner / 旧权限（实测复现，
            # Codex 复审 2026-08-08 P1）。
            ddb.transact_write_items(TransactItems=[
                permissions.sites_snapshot_guard(
                    event["site_id"], rev=rev,
                    had_rev=("permissions_rev" in site)),
                {"Put": {"TableName": os.environ["ROUTING_TABLE"],
                         "Item": _route_item(event, site, owner, subdomain)}}])
            break
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            if attempt == MAX_ROUTE_ATTEMPTS - 1:
                raise RuntimeError(
                    "写路由时站点权限被并发修改，已重试 "
                    f"{MAX_ROUTE_ATTEMPTS} 次仍冲突——本次部署失败，请重新部署"
                ) from e
            # 重读循环顶部会拿到新 rev 与新策略

    # smoke_test 必须按本次实际写入路由的策略断言，不能按 manifest
    # （在线翻转过 require_login 时两者不一致，会把成功的部署判成 FAILED，
    #  而路由切换已经发生）。见 spec §3.3.2。
    event["effective_auth"] = {"require_login": bool(site.get("require_login", True)),
                               "allowed_users": site.get("allowed_users", "org")}
    event["url"] = f"https://{subdomain}.{os.environ['BASE_DOMAIN']}"
    return event
