"""panel 各端点的纯函数层（do_* 模式，无 HTTP 形态）。

**入参 email 已经是 Edge 验证过的身份**（`x-user-email`，只有请求确实经过
CloudFront + Lambda@Edge 才会存在——Function URL 的 AWS_IAM + exact edge role
resource policy 是这个前提的保证，见 deploy_panel.py）。本层不做任何身份
解析，也不碰 cookie / Origin / CSRF —— 那些在 handler.py，且必须**前置于**
本层的任何调用（spec §5.4：不得出现"先写 DynamoDB 再发现 CSRF 不合法"）。

授权 100% 走 permissions.py 的高层函数：本文件不出现任何手写的
DynamoDB 表达式、角色判定、权限 rev 守卫，也不直写 sites/admins/routing 表。
tests/test_no_handwritten_guards.py 用 AST 锁定这一点。
"""
import json
import os
from datetime import datetime

import boto3

import common
import permissions


def _base() -> str:
    return os.environ["BASE_DOMAIN"]


def _site_url(site: dict) -> str:
    sub = site.get("subdomain") or common.subdomain_for(site["site_id"])
    return f"https://{sub}.{_base()}"


def _require_admin(email: str) -> None:
    """admin 专属端点的守卫。

    用 permissions.is_admin（强一致读）而不是缓存或调用方传入的标志：
    撤权必须立刻生效，最终一致读会留下代管窗口。
    """
    if not permissions.is_admin(email):
        raise permissions.PermissionDenied("仅平台管理员可执行此操作")


def do_me(email: str, name: str) -> dict:
    return {"email": email, "name": name,
            "is_admin": permissions.is_admin(email)}


def _shape_site(site: dict, viewer: str, *, viewer_is_admin: bool) -> dict:
    """站点的对外形态。

    created_at 可能是空串：Task 5 的回填对"没有 job 可推导"的站点**不猜**
    （写 now() 会是个错日期且看不出是猜的）。前端按空值处理，不要在这里
    编一个默认时间。

    `ever_live`：这个站点**有没有成功上线过**。
    为什么需要它：`status` 只有三个写入点——建站写 `DEPLOYING`（初始值）、
    `mark_job` 成功写 `ACTIVE`、`undeploy` 写 `DELETED`，**没有任何地方把它从
    DEPLOYING 改回去**。所以 `DEPLOYING` 同时covers"正在部署"与"首次部署失败后
    再没成功过"两种情况，仅凭 sites 表的 status 分不出来，而两者对用户的含义
    完全相反（后者的 URL 是 404、没有 route）。
    判据用 `last_job_id` 的**存在性**：它只由 `mark_job` 的成功分支写
    （`upsert_site(status="ACTIVE", last_job_id=...)`）。真机核对过全部站点：
    `DEPLOYING` 且无 `last_job_id` ⟺ 从未成功过，且没有 ACTIVE 站点缺这个字段。
    列表接口没有 job 数据，所以这个派生必须在后端做——前端拿不到依据就只能猜。
    """
    return {"site_id": site["site_id"], "name": site.get("name", ""),
            "status": site.get("status", ""), "url": _site_url(site),
            "owner": site.get("owner", ""),
            "created_at": site.get("created_at", ""),
            "require_login": bool(site.get("require_login", True)),
            "allowed_users": site.get("allowed_users", "org"),
            "collaborators": list(site.get("collaborators") or []),
            "ever_live": bool(site.get("last_job_id")),
            "role": permissions.role_of(viewer, site, viewer_is_admin)}


def do_list_sites(email: str, *, all_sites: bool = False) -> list[dict]:
    """mine（owner ∪ collaborator）或 admin 的全量列表，按创建时间倒序。"""
    is_adm = permissions.is_admin(email)
    if all_sites:
        _require_admin(email)
        sites = common._paginate(common._table("SITES_TABLE").scan)
    else:
        sites = common.list_sites_for_user(email)
    return [_shape_site(s, email, viewer_is_admin=is_adm)
            for s in sorted(sites, key=lambda s: s.get("created_at", ""),
                            reverse=True)]


def do_get_site(email: str, site_id: str) -> dict:
    site = common.get_site_consistent(site_id)
    is_adm = permissions.is_admin(email)
    # site 可能是 None——assert_can 对 None 返回 ROLE_NONE 并抛"无权访问
    # （或该站点不存在）"，与"存在但无权"**同一句话**。不要在这里提前返回
    # 404：能区分存在性就是站点枚举探测器（site_id 形如 {name}-{6位}，可猜）。
    permissions.assert_can(email, site, "read", is_admin=is_adm,
                           what=f"站点 {site_id}")
    out = _shape_site(site, email, viewer_is_admin=is_adm)
    out["subdomain"] = site.get("subdomain") or common.subdomain_for(site_id)
    return out


def _duration_s(job: dict) -> int:
    """updated_at - created_at 派生，不给 jobs 表加新字段（spec §4 第 8 行）。

    脏数据不得让整页挂掉：解析失败返回 0（展示层显示"—"）。
    """
    try:
        a = datetime.fromisoformat(job["created_at"])
        b = datetime.fromisoformat(job["updated_at"])
        return max(0, int((b - a).total_seconds()))
    except Exception:
        return 0


def do_list_jobs(email: str, site_id: str) -> list[dict]:
    """部署历史（最新在前）。字段按 Task 5 真机确认的 9 个投影字段派生。"""
    site = common.get_site_consistent(site_id)
    permissions.assert_can(email, site, "read",
                           is_admin=permissions.is_admin(email),
                           what=f"站点 {site_id}")
    return [{"job_id": j["job_id"], "status": j.get("status", ""),
             "phase": j.get("phase", ""), "error": j.get("error", ""),
             "url": j.get("url", ""),
             "created_at": j.get("created_at", ""),
             # jobs.owner 是**发起者**（requested_by 语义），不参与授权判定
             "by": j.get("owner", ""),
             "duration_s": _duration_s(j)}
            for j in common.list_jobs_by_site(site_id)]


def do_set_access(email: str, site_id: str, *, require_login=None,
                  allowed_users=None) -> dict:
    return permissions.set_access_policy(site_id, actor=email,
                                         require_login=require_login,
                                         allowed_users=allowed_users)


def do_set_collaborators(email: str, site_id: str, *, add=None,
                         remove=None) -> dict:
    return {"collaborators": permissions.set_collaborators(
        site_id, actor=email, add=add, remove=remove)}


def do_transfer_owner(email: str, site_id: str, *, new_owner: str) -> dict:
    return permissions.transfer_owner(site_id, actor=email,
                                      new_owner=new_owner)


def do_undeploy(email: str, site_id: str, *, purge_data: bool = False) -> dict:
    """下线（异步）。建 job 与"权限快照未变"**同一笔事务**提交。

    与 MCP 的 do_undeploy 同路径同语义（不是重新发明——这是 M2 三轮审查的
    结论）：鉴权之后被转移所有权/撤权的旧请求不能再落地，因为
    purge_data=True 不可恢复。条件表达式**不在这里定义**，来自
    permissions.sites_snapshot_guard（全仓库唯一定义）。
    """
    import botocore.exceptions
    site = common.get_site_consistent(site_id)
    is_adm = permissions.is_admin(email)
    role = permissions.assert_can(email, site, "undeploy", is_admin=is_adm,
                                  what=f"站点 {site_id}")
    site = site or {}
    # sites_snapshot_guard **已经返回** {"ConditionCheck": {...}}——不要再包
    # 一层（permissions.py 的最后一行就是 return {"ConditionCheck": out}）。
    # 双层包裹得到的是 ValidationException，而不是一个能读懂的错误。
    guards = [permissions.sites_snapshot_guard(
        site_id, rev=int(site.get("permissions_rev", 0)),
        had_rev="permissions_rev" in site, actor=email,
        action="undeploy", role=role)]
    if is_adm:
        # admin 代管路径还要断言"我的管理员身份此刻仍有效"（同 MCP 的
        # _admin_condition_check）：撤权后在途请求不得落地。
        guards.append({"ConditionCheck": {
            "TableName": os.environ["ADMINS_TABLE"],
            "Key": {"email": {"S": email}},
            "ConditionExpression": "attribute_exists(email)"}})
    try:
        job_id = common.create_job(email, site_id, guard_items=guards)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        # CancellationReasons 与 TransactItems 同序：[0] 建 job 的 Put、
        # [1] 权限快照守卫、[2] admin 守卫（若有）。**按下标分辨**而不是笼统
        # 报一句：管理员权限被撤销与站点权限被改动是两种处置。
        reasons = [r.get("Code", "") for r in
                   e.response.get("CancellationReasons", [])]
        if len(reasons) > 2 and reasons[2] == "ConditionalCheckFailed":
            raise permissions.PermissionDenied("你的管理员权限已被撤销") from e
        if len(reasons) > 1 and reasons[1] == "ConditionalCheckFailed":
            raise permissions.PermissionConflict(
                "站点权限在你提交期间被修改（协作者/所有权变更），本次下线已取消"
                "——请重新确认权限后再试") from e
        raise
    payload = {"job_id": job_id, "site_id": site_id}
    if purge_data:
        payload["purge_data"] = True
    boto3.client("lambda", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).invoke(
            FunctionName=os.environ["UNDEPLOY_FN"],
            InvocationType="Event", Payload=json.dumps(payload).encode())
    return {"job_id": job_id, "status": "PENDING",
            "note": "下线已提交，请轮询该站点的部署历史查看进度"}


def do_list_admins(email: str) -> dict:
    _require_admin(email)
    return {"admins": permissions.list_admins()}


def do_add_admin(email: str, target: str) -> dict:
    _require_admin(email)
    permissions.add_admin(target, email)
    return {"admins": permissions.list_admins()}


def do_remove_admin(email: str, target: str) -> dict:
    _require_admin(email)
    # 传 removed_by：审计要记"谁摘掉了谁的管理员"，缺它审计行的 actor 是空
    permissions.remove_admin(target, removed_by=email)
    return {"admins": permissions.list_admins()}


def do_resync(email: str, site_id: str) -> dict:
    return permissions.resync_route(site_id, actor=email)
