"""SFN 终态：成功/失败落账 + 站点记录维护 + 前端旧版本与 Lambda 旧版本清理。

提交点之后（register_route 那一次 put_item 之后）只剩 smoke_test，所以本文件的
失败分支承担**补偿**：把路由按 `event["previous_route"]` 还原。
"""
import logging
import os

import boto3

import common
# blue/green 的颜色词表**只有一处定义**（deploy_lambda_site.COLORS）。这里 import
# 而不是再抄一份 ("blue", "green")：抄第二份之后，加第三个颜色或改名时清理逻辑会
# 静默地只看旧的两个 —— 而"漏看一个颜色"在这里的后果是删掉它正在用的版本。
from deploy_lambda_site import COLORS

logger = logging.getLogger()

# 除 alias 引用的版本之外，再留最近这么多个：回滚要有落点。
KEEP_RECENT_VERSIONS = 3


def _lambda():
    return boto3.client("lambda")


def _restore_route(event) -> None:
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
    """
    if "previous_route" not in event:
        return
    prev = event["previous_route"]
    subdomain = common.subdomain_for(event["site_id"])
    try:
        ddb = boto3.client("dynamodb")
        if prev is None:
            ddb.delete_item(TableName=os.environ["ROUTING_TABLE"],
                            Key={"subdomain": {"S": subdomain}})
            logger.warning(f"首次部署失败，已撤掉 {subdomain} 的路由")
        else:
            ddb.put_item(TableName=os.environ["ROUTING_TABLE"], Item=prev)
            logger.warning(f"已把 {subdomain} 的路由整值恢复到切换前")
    except Exception as e:      # noqa: BLE001
        logger.error(f"路由恢复失败（需人工介入）: {e}")


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
        _restore_route(event)
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
