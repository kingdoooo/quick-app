"""SFN 步骤 6：注册子域名路由（含 auth 策略与 owner）。

**这一次写就是整个部署的提交点**（M7）：一次覆盖整个 item，同时切
`api_target`（本次部署的那个颜色的 Function URL）与 `static_prefix`（本次 job
的版本化前缀），写入瞬间所有新请求走新版本（Edge 路由缓存最多再滞后 60s）。
分成两次写会留出"新后端 + 旧前端"的窗口，也会让补偿要还原两条半提交状态——
所以路由表在本步骤里只能被写一次。这之前失败对线上零影响；这之后只剩
smoke_test，靠 `event["previous_route"]` 这份整值快照补偿（见 handler 内注释）。

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
                                owner: str, site_exists: bool = True) -> None:
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
            # **`attribute_exists(site_id)` 必须在最外层**，否则本函数会成为
            # 快照守卫的后门（Codex 之后的独立审查发现，已实测）：
            # DynamoDB 的 update_item 在 item 不存在时会**创建**它，于是一个
            # 陈旧/恶意的 job 可以凭自己的 manifest 无中生有地建出 sites 行、
            # 写入 `permissions_rev = 1` 与 `require_login = false`，随后下面的
            # 守卫读到 had_rev=True 且 rev 相符——守卫校验的是这个 job 刚刚
            # **自己伪造**的快照，于是新 owner 的站点变成公开、并托管旧 owner
            # 的产物。这比原缺陷更糟（原缺陷还要求行已存在且缺 rev）。
            # 站点行由 do_deploy_site / deploy_fixture 在部署前创建，所以这里
            # "行不存在"只可能是异常或攻击，一律不该继续。
            #
            # 括号不可省：AND 比 OR 结合更紧，不加括号会变成
            # `(exists AND not_exists(require_login)) OR not_exists(allowed_users) OR ...`
            # ——后两个析取项完全不受存在性约束，等于没加这道闸门。
            #
            # 三个受管字段各自的 attribute_not_exists 是"缺哪个补哪个"：
            # 稀疏行可能两个 auth 字段都在而 rev 缺失（upsert_site 建站只写
            # owner/name/status，在线写也只持久化调用方显式传的字段）。漏掉 rev
            # 那一项会让 seed 整体跳过 → 守卫（要求 rev 存在，fail-closed）每轮
            # 失败 → 把一次**合法**部署卡成"权限被并发修改"。
            # collaborators 也要列：它同在 SET 子句里，条件必须覆盖所写的每个
            # 字段，否则"三个条件字段都在、collaborators 缺失"的行会跳过 seed，
            # 将来给 collaborators 加守卫子句就会继承这个洞。
            ConditionExpression=("attribute_exists(site_id) AND ("
                                 "attribute_not_exists(require_login) OR "
                                 "attribute_not_exists(allowed_users) OR "
                                 "attribute_not_exists(collaborators) OR "
                                 "attribute_not_exists(permissions_rev))"),
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
        # ConditionalCheckFailed 现在有**两种**来源，必须分开（加了
        # attribute_exists(site_id) 之后）：
        #   · 站点行确实存在、受管字段都齐 → 幂等 no-op，用真源的值，正常继续；
        #   · 站点行**不存在** → 不能继续。它不是"已经初始化好了"，而是异常或
        #     攻击（陈旧 job 想给一个已删除的 site_id 建路由）。吞掉的话下面的
        #     守卫会以 had_rev=False 走系统写入者分支、连续失败三次，最后报
        #     "写路由时站点权限被并发修改"——把"站点不存在"说成并发冲突，排查时
        #     会往完全错误的方向查。所以显式判定并给出准确原因。
        # 其余错误（限流、校验……）一律如实上抛——放宽成裸 pass 会让 seed
        # 静默失败，_route_item 回落 allowed_users="org"（fail-open 扩权）。
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        if not site_exists:
            raise RuntimeError(
                f"站点 {site_id} 在 sites 表里不存在，拒绝写路由——"
                "部署前应已创建站点记录（do_deploy_site / deploy_fixture）。"
                "若站点已被下线，请重新发起部署而不是复用旧任务。") from e


def _route_item(event, site: dict, owner: str, subdomain: str) -> dict:
    allowed = site.get("allowed_users", "org")
    return {"subdomain": {"S": subdomain},
            "site_id": {"S": event["site_id"]},
            "route_mode": {"S": "split"},
            # 格式的唯一定义在 common（尾斜杠是一条实测红线，见该函数 docstring）。
            # mark_job 的补偿要按**同一个**值做条件，两处各手写一份就没有任何东西
            # 保证它们同义。
            "static_prefix": {"S": common.static_prefix_for(event["site_id"],
                                                           event["job_id"])},
            "api_target": {"S": event.get("api_target", "")},
            "require_auth": {"BOOL": bool(site.get("require_login", True))},
            "allowed_users": permissions.allowed_users_av(allowed),
            "collaborators": {"L": [{"S": e} for e in
                                    (site.get("collaborators") or [])]},
            "owner": {"S": owner},
            "permissions_rev": {"N": str(int(site.get("permissions_rev", 0)))}}


def _finish(event, committed_route: dict, previous_route, subdomain: str) -> dict:
    """把"提交之后"的那几个 event 字段填好。

    **提交路径与重放路径共用这一个函数**：两条路径各填一份的话，重试时 smoke 的
    判据（`effective_auth`）就可能与真正写进路由的那条不一致——而那正是
    spec §3.3.2 要消除的"按 manifest 断言"的同一类错误。
    所以这里的值一律**从 `committed_route` 这个 item 反推**，不从 sites 表再读一次：
    重试发生在提交之后，此刻 sites 表可能已经被在线改权限动过，再读一次就会用
    新策略去断言一条按旧策略写下的路由。
    """
    event["previous_route"] = previous_route
    event["committed_permissions_rev"] = int(
        committed_route["permissions_rev"]["N"])
    allowed = committed_route["allowed_users"]
    event["effective_auth"] = {
        "require_login": bool(committed_route["require_auth"]["BOOL"]),
        "allowed_users": (allowed["S"] if "S" in allowed
                          else [e["S"] for e in allowed["L"]])}
    event["url"] = f"https://{subdomain}.{os.environ['BASE_DOMAIN']}"
    return event


def handler(event, context):
    """写路由（原子切流）。权限值取自 sites 表真源，并用条件事务防并发覆盖。

    为什么必须是事务：本步骤是"读 sites → 写整条路由"。若中间有人在线收紧
    权限（那边是两表事务，sites 与路由都已改成私有），这里再用旧快照
    put_item 整条，就把路由写回公开——sites=私有 / Edge=公开，正是在线改权限
    的事务本该消除的安全状态错误。DynamoDB 事务只保证事务内原子，不会把事务
    之前的普通读与之后的普通写合成一个业务事务。见 spec §3.2。

    做法：对 sites 表做 ConditionCheck（permissions_rev 仍是我读到的值）+
    对路由表 Put 整条 + 把补偿状态写进 job 记录，同一事务提交。冲突则重读重试
    （≤3 次）；仍冲突就让本步骤失败——部署 FAILED 比留下错误的公开状态好。

    **本步骤对 Task 重试必须幂等**（Codex 2026-08-17 P1-1）。Step Functions 给每个
    Task 都配了默认重试，四种触发错误都属于"函数可能已经执行完，只是响应没回来"，
    而重试用的是**原始输入** ⇒ 第一次放进返回值里的 `previous_route` 就此丢失，
    第二次拍到的"切换前快照"其实是自己刚写进去的新路由。于是补偿变成 no-op
    却日志报"已恢复"，并且 mark_job 会把真正的上一版前缀当成当前前缀删掉。
    所以补偿状态与路由提交**同一笔事务**落进 job 记录（`route_commit`），
    重试时认出"我已经提交过"，回放那份记录、**一次路由写都不再发**。
    """
    import botocore.exceptions

    common.update_job(event["job_id"], phase="register-route")
    subdomain = common.subdomain_for(event["site_id"])
    ddb = boto3.client("dynamodb")

    # ---- 幂等入口：这条 job 已经提交过路由了吗 ----
    # 放在**任何写之前**。重试时再走一遍 seed / 事务不只是浪费：seed 之后的
    # 强一致读会拿到"提交后"的世界，快照就成了自己写的那条新路由。
    replay = common.read_route_commit(event["job_id"])
    if replay is not None:
        prev = (None if "NULL" in replay["previous_route"]
                else replay["previous_route"]["M"])
        return _finish(event, replay["committed_route"]["M"], prev, subdomain)

    site = common.get_site_consistent(event["site_id"]) or {}
    owner = site.get("owner") or common.get_job(event["job_id"])["owner"]
    # site_exists 用**上面这次读**的结果，不再额外读一次：多一次读会改变
    # 调用序列，而并发交错的用例正是按"第几次读"注入竞态的。
    _seed_permissions_if_absent(event["site_id"], event["manifest"]["auth"],
                                owner, site_exists=bool(site))

    for attempt in range(MAX_ROUTE_ATTEMPTS):
        # **必须强一致读**：紧接在 _seed_permissions_if_absent 之后，
        # 最终一致读可能拿不到刚写入的权限，_route_item 就会回落默认值
        # （require_login=True / allowed_users="org"）——把指定邮箱名单
        # 错误地放大成"全体可信 IdP 用户"。且 seed 把 rev 明确写成 1，
        # 与"未初始化"的 0 区分开，否则条件检查察觉不到这次状态变更。
        site = common.get_site_consistent(event["site_id"]) or {}
        owner = site.get("owner") or owner
        rev = int(site.get("permissions_rev", 0))
        # ---- 切换前的整值快照（mark_job 的失败分支据此原样写回）----
        # 提交点之后只剩 smoke_test（它必须打公网 URL，所以只能排在切路由之后
        # ——这是不可消除的顺序）。所以在这里留一份快照来补偿。三个要点：
        #
        # ① **整值**，不是挑几个字段：恢复要写回的是"切换前的那条路由"，挑字段
        #    会静默丢掉没挑的（route_mode / require_auth / allowed_users /
        #    collaborators / permissions_rev …），恢复出一条残缺的 item，Edge
        #    按缺失字段回落默认值 = 一次静默的策略变更。
        # ② **强一致读**：最终一致读可能拿不到"刚刚在线收紧权限"那次写，快照就
        #    记成收紧之前的公开状态；失败恢复照它写回 = fail-open 扩权。
        # ③ **在重试循环内**，紧贴事务之前：循环外读一次的话，被 rev 条件取消
        #    后重试成稿，快照仍是第一次读到的旧版本（同样是把收紧前的公开路由
        #    当成"上一版"）。快照与提交之间仍有一个瞬间，但那个窗口被下面的
        #    permissions_rev ConditionCheck 关掉了：在线改权限是"sites 推 rev +
        #    改路由"同一事务，任何插在中间的路由改动都会让本次事务被取消 → 带着
        #    新快照重试。
        #
        # 值为 None = 切换前没有路由（首次部署）。**键一定在**：mark_job 靠
        # "键在不在"区分"register_route 还没提交（路由不该动）"与"提交过、但这是
        # 首次部署（该把刚写的路由删掉）"，写成 `if prev:` 会把这个区分丢掉。
        #
        # 这次读失败一律上抛：失败在提交之前，对线上零影响；吞掉的话路由照切而
        # 快照缺席，冒烟失败时无从还原。恢复完备还要求旧色 alias、旧色 URL、旧
        # 前端前缀都还在，所以清理只在成功分支做（见 mark_job 的版本清理）。
        previous_route = ddb.get_item(
            TableName=os.environ["ROUTING_TABLE"],
            Key={"subdomain": {"S": subdomain}},
            ConsistentRead=True).get("Item")
        route_item = _route_item(event, site, owner, subdomain)
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
            # 第三条：把补偿状态与路由提交绑成**同一笔**。分开写就有一个窗口，
            # 窗口里挂掉 = 路由已切而补偿状态缺席（就是 P1-1 的形态）。
            #
            # **route_commit 的下标由构造处算出，不写死字面量**（与 mcp/panel 的
            # _WHY 同一条纪律）：往这个列表中间插一项时，硬编码的下标会把"这是
            # 重放"误读成"权限被并发修改"——重试 3 次后 raise，一次**已经提交**的
            # 部署被报成 FAILED，且 MarkFailed 收到的输入里没有 previous_route。
            tx_items = [
                permissions.sites_snapshot_guard(
                    event["site_id"], rev=rev,
                    had_rev=("permissions_rev" in site)),
                {"Put": {"TableName": os.environ["ROUTING_TABLE"],
                         "Item": route_item}},
                common.route_commit_item(event["job_id"], previous_route,
                                         route_item)]
            commit_idx = len(tx_items) - 1
            ddb.transact_write_items(TransactItems=tx_items)
            # ---- 提交端的锚点（mark_job 的补偿按它做条件）----
            # 从**刚写进去的那个 item** 反推，与重放路径共用 `_finish`：
            # 两条路径各填一份的话，重试时 smoke 的判据会与真正写进路由的那条不一致。
            #
            # **不要在 mark_job 那边改成"读一次现在的路由再比"**：那是 read →
            # conditional-write 的 TOCTOU，而且读到的就是要判定的对象本身，
            # 条件永远成立，等于没有条件。
            return _finish(event, route_item, previous_route, subdomain)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            # **先分辨是哪一项被取消**：第三项（route_commit 的
            # attribute_not_exists）失败意味着"这条 job 已经提交过路由了"——
            # 也就是上面那个幂等入口的读没看到、但事务看到了（重试与第一次调用
            # 几乎同时发生时可达）。这不是冲突，是重放，必须走幂等路径而不是
            # 被下面当成"权限被并发修改"最终把一次成功的部署报成 FAILED。
            reasons = [r.get("Code", "") for r in
                       e.response.get("CancellationReasons", [])]
            if (len(reasons) > commit_idx
                    and reasons[commit_idx] == "ConditionalCheckFailed"):
                replay = common.read_route_commit(event["job_id"])
                if replay is not None:
                    prev = (None if "NULL" in replay["previous_route"]
                            else replay["previous_route"]["M"])
                    return _finish(event, replay["committed_route"]["M"], prev,
                                   subdomain)
            if attempt == MAX_ROUTE_ATTEMPTS - 1:
                raise RuntimeError(
                    "写路由时站点权限被并发修改，已重试 "
                    f"{MAX_ROUTE_ATTEMPTS} 次仍冲突——本次部署失败，请重新部署"
                ) from e
            # 重读循环顶部会拿到新 rev 与新策略

    # 循环的每条出路都是 return 或 raise（成功即 `_finish`，见 spec §3.3.2：
    # smoke 的判据必须来自**实际写入路由的那条 item**，不是 manifest 也不是
    # 事后再读一次 sites 表）。只有 MAX_ROUTE_ATTEMPTS <= 0 才会落到这里，
    # 那是配置错——响亮失败，否则症状会是"路由没写但部署报成功"。
    raise RuntimeError(
        f"MAX_ROUTE_ATTEMPTS={MAX_ROUTE_ATTEMPTS} 不合法（须 ≥ 1）")
