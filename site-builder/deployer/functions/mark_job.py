"""SFN 终态：成功/失败落账 + 站点记录维护 + 前端旧版本与 Lambda 旧版本清理。

提交点之后（register_route 那一次 put_item 之后）只剩 smoke_test，所以本文件的
失败分支承担**补偿**：把路由按 `event["previous_route"]` 还原。
"""
import logging
import os

import boto3

import common
import permissions
# blue/green 的颜色词表**只有一处定义**（deploy_lambda_site.COLORS）。这里 import
# 而不是再抄一份 ("blue", "green")：抄第二份之后，加第三个颜色或改名时清理逻辑会
# 静默地只看旧的两个 —— 而"漏看一个颜色"在这里的后果是删掉它正在用的版本。
from deploy_lambda_site import COLORS

logger = logging.getLogger()

# 除 alias 引用的版本之外，再留最近这么多个：回滚要有落点。
KEEP_RECENT_VERSIONS = 3


def _lambda():
    return boto3.client("lambda")


# 补偿被放弃时写进 **job 错误信息**的说明。只 logger.error 不够：看到部署失败的人
# 看的是 job 记录，CloudWatch 里那行他们看不到，而"路由没回滚"是需要人去处置的。
ROUTE_NOT_ROLLED_BACK = (
    "路由未回滚，仍停在本次部署的新目标上：切换前的快照与线上现状已不匹配"
    "（冒烟期间有人改过站点权限、站点被下线，或快照来自没有 permissions_rev 的"
    "存量数据）。强行回滚会把旧权限写回、或让已下线的站点复活，因此放弃——需人工介入。")


def _restore_route(event) -> str | None:
    """把路由还原到本次部署切换之前。**`previous_route` 是三态契约**，
    见 `register_route` 里那段注释：

    · 键**不在**       = register_route 还没提交 ⇒ 线上从未变过，动它才是制造故障；
    · 键在、值 `None`  = 提交过，但切换前没有路由（首次部署）⇒ 删掉刚写的那条；
    · 键在、值是 item  = 提交过且有上一版 ⇒ **整值**写回。

    写成 `if not prev: return` 会把前两态合并，于是首次部署失败后那条指向失败站点
    的路由会留在线上——用户拿到的 URL 打开是一个部署失败的站点而不是 404。

    整值写回而不是挑字段：挑字段会丢掉 route_mode / require_auth / allowed_users /
    collaborators / permissions_rev……而 Edge 对缺失字段按默认值回落 = 一次静默的
    策略变更（可能是扩权）。

    失败仅告警：此刻已经在失败分支里，抛异常只会用"恢复也失败了"盖掉原始错误。

    **写回必须带条件**：快照是提交那一刻拍的，而 smoke 有几十秒。这段时间里线上
    可能已经变了，两条都可达：
      · 有人在线收紧权限（`permissions.py` 是"sites 推 rev + 改路由"同一事务）
        ⇒ 无条件整值写回会把 allowed_users 一起写回收紧**之前**的样子，
        fail-open 扩权，而且只 warning ⇒ 静默；
      · 站点被下线（`undeploy.py` 删掉这一行）⇒ 写回等于让一个已删除的站点的
        子域名重新可路由，把"已删除"撤销了。
    所以条件是"线上的 permissions_rev 还是我快照里那个"，**精确匹配**。

    条件失败 = 世界变过了 ⇒ **放弃**，不重试、不挑字段合并（挑字段会丢掉
    route_mode / require_auth / collaborators……而 Edge 对缺失字段按默认值回落，
    等于一次静默的策略变更）。返回一句说明由 handler 写进 job 错误信息。

    **精确匹配，不用 `attribute_not_exists(permissions_rev) OR rev = :snap`**：
    那种宽松析取在 **item 不存在**时前半成立 ⇒ 恰好把上面第二条（站点已下线）
    放行，路由被复活。同一形态在 `register_route` 里也是被删掉的手抄版本，
    见 `permissions.snapshot_condition` 的 docstring（"这类兼容分支会静默成立，
    旧主体的写入照样落地"，实测复现过）。这里的语义与该函数 `had_rev` 的两条分支
    一致，但**没有复用它**：它的表达式钉在 sites 表的属性名上
    （`attribute_exists(site_id)`），而路由 item 的存在性键是 subdomain。

    快照里没有 rev（M3 之前的存量路由）⇒ 条件退化成"线上也还没有 rev"，
    而 `register_route` 总会写 rev ⇒ 实际上必然失败 ⇒ 放弃。这是**故意的**：
    没有可比的 rev 就无法证明期间没人改过，放弃的代价只是可用性（路由留在这次
    失败的部署上，而它的权限是按**当前**真源算的，并没有扩权），放行的代价是
    可能把旧权限写回去。两边不对等。

    **值为 `None` 那一态（首次部署 ⇒ 删掉）不带条件，这个不对称是有意的**：
    删除不写回任何权限值，它比任何权限状态都更"关"（子域名直接不解析）；被丢掉的
    只是权限的**投影**，而真源在 sites 表里还在（`permissions.py` 本来就有
    `_ALLOW_ROUTE_ABSENT` 这条"站点还没首次部署成功"的路径，下次部署会重新投影）。
    反过来给删除加条件的代价是实打实的：条件一失败，一个 FAILED 的首次部署就把
    子域名继续占着、指向一个坏站点——那正是这一态存在的理由。
    """
    if "previous_route" not in event:
        return None
    prev = event["previous_route"]
    subdomain = common.subdomain_for(event["site_id"])
    try:
        ddb = boto3.client("dynamodb")
        if prev is None:
            ddb.delete_item(TableName=os.environ["ROUTING_TABLE"],
                            Key={"subdomain": {"S": subdomain}})
            logger.warning(f"首次部署失败，已撤掉 {subdomain} 的路由")
            return None
        snap_rev = prev.get("permissions_rev")
        if snap_rev is None:
            # 快照里没有 rev ⇒ 没有可比的 rev 就无法证明期间没人改过 ⇒ 放弃，
            # 而且**一次写请求都不发**：任何条件在这一态都注定被拒，发出去只是
            # 消耗配额、并在 CloudWatch 里留一条会被误读成"恢复失败"的噪声。
            logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
            return ROUTE_NOT_ROLLED_BACK
        # **条件表达式走 permissions.snapshot_condition（全仓库唯一定义），不在这里
        # 手写**。`tests/test_permissions.py::
        # test_no_handwritten_rev_guard_outside_permissions_module` 按 AST 扫源码
        # 钉死这一点，而它存在的理由正是本函数上面讲的那个坑的另一面：手抄第二份
        # 之后，"兼容分支静默成立"的形态会在第二处复活（仓库里两个 P1 都是这么来的）。
        #
        # `had_rev=True` 给出的是 "attribute_exists(site_id) AND permissions_rev = :rev"：
        #   · `permissions_rev = :rev` —— 精确匹配，正是这里要的；
        #   · `attribute_exists(site_id)` —— 多一层 anti-resurrection。路由 item 被
        #     undeploy 删掉后该条件为假，恢复自动放弃，不会把已下线站点的子域名
        #     复活。路由 item 一定带 site_id（`register_route._route_item` 必写，
        #     在线改权限与自愈投影都是 update 不动它）。
        # **不用 had_rev=False**：那条分支是给带重试循环的调用方设计的（条件必然
        # 失败 → 重读重试），mark_job 只有一次机会，语义不对。
        expr, values, names = permissions.snapshot_condition(
            rev=int(snap_rev["N"]), had_rev=True)
        kwargs = {"ExpressionAttributeValues": values} if values else {}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        try:
            ddb.put_item(TableName=os.environ["ROUTING_TABLE"], Item=prev,
                         ConditionExpression=expr, **kwargs)
        except ddb.exceptions.ConditionalCheckFailedException:
            logger.error(f"{subdomain}: {ROUTE_NOT_ROLLED_BACK}")
            return ROUTE_NOT_ROLLED_BACK
        logger.warning(f"已把 {subdomain} 的路由整值恢复到切换前")
        return None
    except Exception as e:      # noqa: BLE001
        logger.error(f"路由恢复失败（需人工介入）: {e}")
        return None


def _cleanup_versions(site_id: str, *, keep_extra=()) -> None:
    """删掉没人引用的旧 Lambda 版本。保留：两个 alias 当前引用的 + 最近
    `KEEP_RECENT_VERSIONS` 个 + `keep_extra`（本次刚部署的那个）。

    健康门失败留下的版本会被这里收走（否则永久占账号的代码存储配额）。

    **`keep_extra` 不是冗余**：alias 的读与"刚把 alias 指过去"之间有一个瞬间，读到
    旧值时 keep 里就没有本次的版本号，而它可能恰好落在"没人引用且不在最近 N 个"里
    ⇒ 被删。传进来的这一个不依赖读一致性。

    **失败一律整体放弃，不做部分清理**：站点已上线，残留版本只是配额；而 keep 集合
    只要少一个版本就可能删掉**线上 alias 正指着的**那个 —— 那是站点当场 500。所以
    只有"该色不存在"（`ResourceNotFoundException`）算作"这一色没有要保留的版本"，
    其余任何原因（限流、超时、权限）都让整个清理放弃。宽 `except Exception: pass`
    恰好把这两种原因混成一种。
    """
    fn = f"site-{site_id}"
    lam = _lambda()
    try:
        keep = {str(v) for v in keep_extra if v}
        for c in COLORS:
            try:
                keep.add(lam.get_alias(FunctionName=fn, Name=c)["FunctionVersion"])
            except lam.exceptions.ResourceNotFoundException:
                pass        # 该色还不存在（迁移中的站点只有一个颜色）
        # **只收纯数字的版本号**：`$LATEST` 必须排除（删它 = 删函数配置里的当前
        # 代码），而任何非版本号字符串既会让 sort(key=int) 抛错、又会变成
        # delete_function 的一个危险 Qualifier。
        nums = []
        for page in lam.get_paginator("list_versions_by_function").paginate(
                FunctionName=fn):
            nums += [v["Version"] for v in page["Versions"]
                     if str(v["Version"]).isdigit()]
        nums.sort(key=int)
        # 注意 `nums[-0:]` 是**整个列表**而不是空：把 KEEP_RECENT_VERSIONS 设成 0
        # 的效果是"全部保留"（清理停摆），不是"一个都不留"。这个方向是安全的
        # （宁可多留也不误删），所以不去"修"它——但别照字面读成"保留 0 个"。
        keep |= set(nums[-KEEP_RECENT_VERSIONS:])
        for v in nums:
            if v not in keep:
                # Qualifier 必须带且必须是版本号：**不带 Qualifier 就是删整个
                # 函数**，站点当场消失。
                lam.delete_function(FunctionName=fn, Qualifier=v)
    except Exception as e:      # noqa: BLE001
        logger.warning(f"旧版本清理失败（不影响部署结果）: {e}")


def _cleanup_old_versions(site_id: str, current_job_id: str):
    """删除 sites/{site_id}/ 下除当前 job 外的旧版本前缀。
    失败仅告警——站点已上线，残留旧版本只是存储成本。"""
    try:
        s3 = boto3.client("s3")
        bucket = os.environ["FRONTEND_BUCKET"]
        keep = f"sites/{site_id}/{current_job_id}/"
        paginator = s3.get_paginator("list_objects_v2")
        stale = []
        for page in paginator.paginate(Bucket=bucket, Prefix=f"sites/{site_id}/"):
            stale += [{"Key": o["Key"]} for o in page.get("Contents", [])
                      if not o["Key"].startswith(keep)]
        for i in range(0, len(stale), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": stale[i:i + 1000]})
    except Exception as e:
        logger.warning(f"旧版本清理失败（不影响部署结果）: {e}")


def handler(event, context):
    job_id = event["job_id"]
    if "error_info" in event:
        cause = str(event["error_info"].get("Cause", "未知错误"))[:500]
        # 先落账再补偿：恢复自己吞掉所有异常，所以顺序对结果没影响，但"失败已被
        # 记录"是排查的前提——万一恢复那步在真机上卡住，job 也不该停在 RUNNING。
        common.update_job(job_id, status="FAILED", error=cause)
        note = _restore_route(event)
        if note:
            # 补偿被放弃是**可操作**信息，必须落到用户看得见的地方（job 记录）。
            # 截断时砍**原因**、不砍这条提示：提示被截掉就等于没写。
            cause = f"{cause[:max(0, 500 - len(note) - 3)]} | {note}"
            common.update_job(job_id, error=cause)
        return {"job_id": job_id, "status": "FAILED", "error": cause}

    common.update_job(job_id, status="SUCCEEDED", url=event["url"])
    # 不写 owner：jobs 表的 owner 字段是**发起者**（requested_by 语义），
    # 而站点 owner 只由 permissions.transfer_owner 与首次部署的
    # do_deploy_site 写。二期放开 collaborator 部署后，把发起者写回站点
    # owner 会让协作者部署一次就夺取所有权（spec §3.3.1）。
    common.upsert_site(event["site_id"], status="ACTIVE", last_job_id=job_id,
                       tier=event["manifest"]["tier"],
                       name=event["manifest"]["name"],
                       subdomain=common.subdomain_for(event["site_id"]))
    _cleanup_old_versions(event["site_id"], job_id)
    # 清理**只在成功分支**做：失败分支要靠旧色 alias、旧色 URL、旧前端前缀都还在
    # 才能完整恢复（register_route 那段注释里的同一条理由）。
    _cleanup_versions(event["site_id"],
                      keep_extra=(event.get("deploy_version"),))
    return {"job_id": job_id, "status": "SUCCEEDED", "url": event["url"]}
