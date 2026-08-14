"""panel 各端点的纯函数层（do_* 模式，无 HTTP 形态）。

**入参 email 已经是 Edge 验证过的身份**（`x-user-email`，只有请求确实经过
CloudFront + Lambda@Edge 才会存在——Function URL 的 AWS_IAM + exact edge role
resource policy 是这个前提的保证，见 deploy_panel.py）。本层不做任何身份
解析，也不碰 cookie / Origin / CSRF —— 那些在 handler.py，且必须**前置于**
本层的任何调用（spec §5.4：不得出现"先写 DynamoDB 再发现 CSRF 不合法"）。

授权 100% 走 permissions.py 的高层函数：本文件不出现任何手写的
DynamoDB 表达式、角色判定、权限 rev 守卫，也不直写 sites/admins/routing 表。
tests/test_no_handwritten_guards.py 用 AST 锁定这一点。

二期 M4 的 `site-api-keys` 表同理，唯一访问层是 keystore.py（本文件既不碰那张
表也不调 keygen），由 tests/test_keys_api.py 的结构组锁定。
"""
import json
import logging
import os
from datetime import datetime

import boto3

import analytics
import common
import keystore
import permissions

logger = logging.getLogger(__name__)


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


def _api_key_feature() -> dict:
    """`features.api_key` 的派生。**只影响 UI 展示，不是门禁**（真门禁在网关层）。

    **两个字段而不是一个布尔**（Codex 审查 2026-08-11 P1-5）：首次部署强制把
    哨兵行建成 `enabled=false`，若只有一个布尔、前端据它 disabled 且零请求，
    管理员就**无处点开闸**——部署流程自锁。所以 `deployed` 决定 UI 可用性，
    `enabled` 只驱动状态提示与开关初值。

    读失败一律 `(False, False)`：表不存在 / 哨兵行不存在 / AccessDenied 都算
    "没部署"。**这与 keystore.switch_state 的"读失败就抛"不矛盾**——两个调用点
    的代价完全不同：
      · 这里是 `/api/me`，控制台的**启动请求**。让它 500 等于 M4 一没部署好，
        整个控制台（连站点管理）都打不开——把一个功能开关的故障放大成全站故障；
      · `do_get_key_switch` 是 admin 专属端点，那里**故意不接**这个异常：读失败
        照 keystore 的口径变成 500，管理员看到的是"读不出来"而不是"未部署"
        （后者会让他以为平台没这功能，正是自锁的那一步）。
    """
    try:
        deployed, enabled = keystore.switch_state()
    except Exception:
        logger.warning("API Key 开关状态读取失败——按未部署展示", exc_info=True)
        return {"deployed": False, "enabled": False}
    return {"deployed": deployed, "enabled": enabled}


def do_me(email: str, name: str) -> dict:
    return {"email": email, "name": name,
            "is_admin": permissions.is_admin(email),
            "features": {"api_key": _api_key_feature()}}


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
    try:
        boto3.client("lambda", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1")).invoke(
                FunctionName=os.environ["UNDEPLOY_FN"],
                InvocationType="Event", Payload=json.dumps(payload).encode())
    except Exception as e:
        # **job 已经建好了（PENDING），invoke 失败必须就地收敛**
        # （Codex 审查 2026-08-10 P1-4）：sweeper 只扫 RUNNING，一个停在
        # PENDING 的 job 谁都不会再碰，用户看到"排队中"到永远。
        # 收敛失败也不能盖掉原始异常（那才是根因）。
        try:
            common.update_job(job_id, status="FAILED",
                              error="下线任务提交失败（未开始执行），站点未做任何"
                                    "改动。请重新发起下线。")
        except Exception:
            pass
        raise e
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


# ------------------------------------------------------------------ API Key
# 表访问 100% 经 keystore（同本文件对 sites 表"只走 permissions.py 高层函数"的
# 既有约束）：`site-api-keys` 只能有一个访问层，否则"哨兵行 enabled 必须是布尔
# True"这条不变量就会被抄成两份（keystore.py 的模块 docstring 有完整理由）。
# panel 也**不直接调 keygen**——明文/哈希的生成只在 keystore.create 里发生一次。
# tests/test_keys_api.py 的 AST 断言锁定这两点。

def _shape_key(row: dict) -> dict:
    """Key 的对外形态。**唯一出口**——绝不返回 key_hash。

    为什么必须收口到一个函数：key_hash 是这张表最值得保护的字段
    （spec §5.1：库被读走时攻击者只拿到哈希）。把它挡在一个地方，
    比在三个端点各写一次 `del row["key_hash"]` 可靠——后者漏一处即泄漏，
    而"漏一处"正是本项目反复出现的缺陷形态。

    形态是**白名单**而不是"复制 row 再删几个键"：白名单下将来给表加字段
    （比如 `revoked_by`、内部标记）默认不出网；黑名单下默认出网，得靠人记得
    每次加字段都回来改这里。
    tests/test_keys_api.py 用 AST 锁定所有返回路径都经过本函数。
    """
    return {"key_id": row.get("key_id", ""), "name": row.get("name", ""),
            "prefix": row.get("prefix", ""),
            "created_at": row.get("created_at", ""),
            "last_used_at": row.get("last_used_at", ""),
            "revoked": bool(row.get("revoked"))}


def do_list_keys(email: str) -> dict:
    """我的全部 Key（含已吊销的——控制台要显示吊销状态）。

    只按 `email-index` 查自己那一批：哪个人能看到哪些 Key 由**分区键**决定，
    不是查回来再过滤（后者一旦漏掉过滤条件就是全表泄漏）。哨兵行没有 email
    属性，天然不进这个 GSI，所以它不会出现在任何人的列表里。
    """
    return {"keys": [_shape_key(row) for row in keystore.list_for(email)]}


def do_create_key(email: str, *, name: str) -> dict:
    """发一把新 Key。响应里的 `plaintext` 是明文在服务端**唯一一次**出场。

    name / 邮箱形态的校验在 keystore.create 里，**不在这里再抄一份**：两份校验
    迟早分叉，而分叉方向通常是"这一侧更松"。
    """
    row = keystore.create(email, name=name)
    out = _shape_key(row)
    # 明文**不放进 _shape_key**：那个形态是列表与创建共用的，让它有能力输出
    # 明文就等于给列表接口留了一条泄漏路径。整个服务端只有这一行贴明文。
    out["plaintext"] = row["plaintext"]
    return out


def do_revoke_key(email: str, *, key_id: str) -> dict:
    """吊销我的一把 Key（置 `revoked`，不删行——删了就没有审计痕迹）。

    "不存在"与"是别人的"由 keystore 抛**同一个异常同一句文案**，这里只做状态码
    转换、**绝不按情形分支**：能区分两者就是 key_id 枚举探测器（8 位 base62）。
    转成 PermissionDenied（403）而不是让 KeystoreError 落到 500，口径同
    `do_get_site` 对"站点不存在/无权访问"的既有处理。
    """
    try:
        return keystore.revoke(key_id, actor=email)
    except keystore.KeyNotFound as e:
        raise permissions.PermissionDenied(str(e)) from e


def do_get_key_switch(email: str) -> dict:
    """开关状态（admin-only）。

    **不接 keystore 的读异常**（与 `_api_key_feature` 刻意相反，见那里的理由）：
    管理员必须能区分"没部署"与"读不出来"，把后者显示成前者会让他以为平台没有
    这个功能。
    """
    _require_admin(email)
    deployed, enabled = keystore.switch_state()
    return {"deployed": deployed, "enabled": enabled}


def do_set_key_switch(email: str, *, enabled: bool) -> dict:
    """改开关（admin-only，落 ops_log）。

    **`enabled` 必须是真布尔，判定在 keystore.set_switch**（`"false"` / `"0"` /
    `0` / `1` / `None` / `[]` 全部 ValueError → 400）。不在这里再写一次
    `isinstance`：写入侧的收紧只能有一个定义，两份迟早有一份变松，而这个陷阱
    的症状是"以为关了其实开着"（同 `44aef8d` 的 `bool("false") is True`）。
    审计也由 keystore 落（`{enable,disable}_api_key_switch`）。

    返回的 `deployed` 直接是 True：`set_switch` 的 PutItem 成功就意味着哨兵行
    此刻存在，这是**从写入结果推出来的**而不是猜的。刻意不回读一次——回读失败
    会把一次已经成功的开关变更报成 500，管理员会以为没生效而重复操作。
    """
    _require_admin(email)
    keystore.set_switch(enabled, actor=email)
    return {"deployed": True, "enabled": enabled}


# ----------------------------------------------------------------- 访问统计
# 表访问 100% 经 analytics.py（同上面两节对 sites 表与 api-keys 表的既有约束）：
# 本文件不出现 site-access-events / site-access-daily 的表名，也不自己分桶——
# pv/uv 的口径只有 access_rollup.day_stats 一份，analytics.py import 它。

def do_get_analytics(email: str, site_id: str, *, period: str = "day",
                     n: int = 30) -> dict:
    """PV/UV 时间序列。`uv_exact=False` 的桶其 `uv` 为 null（analytics 模块的
    契约），前端要显式标注而不是显示 0。"""
    site = common.get_site_consistent(site_id)
    permissions.assert_can(email, site, "view_analytics",
                           is_admin=permissions.is_admin(email),
                           what=f"站点 {site_id} 的访问统计")
    return {"period": period, "series": analytics.series(site_id, period, n)}


def do_get_visitors(email: str, site_id: str, *, days: int = 7,
                    limit: int = 50, cursor: str | None = None) -> dict:
    """访问明细/审计（含被拒记录）。"""
    site = common.get_site_consistent(site_id)
    permissions.assert_can(email, site, "view_analytics",
                           is_admin=permissions.is_admin(email),
                           what=f"站点 {site_id} 的访问明细")
    return analytics.visitors(site_id, days=days, limit=limit, cursor=cursor)
