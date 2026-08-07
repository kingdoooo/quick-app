"""部署 MCP——薄壳：4 工具全部秒级返回，重活交给 Step Functions。
运行于 AgentCore Runtime；调用者飞书 email 由网关经 JWT claims 传入。"""
import json
import os
import re
import sys
from pathlib import Path
from typing import NamedTuple

import boto3
from mcp.server.fastmcp import FastMCP

# common.py 来自 deployer/functions/：容器构建时 cp 到本目录（见 Dockerfile），
# 本地开发/单测则从源码树取。两条路径都显式加进 sys.path，避免"单测能过、
# 容器里 ModuleNotFoundError"。
sys.path.insert(0, str(Path(__file__).parent))
_DEV_COMMON = Path(__file__).parents[1] / "deployer" / "functions"
if not (Path(__file__).parent / "common.py").exists() and _DEV_COMMON.is_dir():
    sys.path.insert(0, str(_DEV_COMMON))

import common  # noqa: E402  deployer/functions/common.py
import permissions  # noqa: E402  deployer/functions/permissions.py（同 common 的解析路径）

# 平台生成的 site_id 形态：<name(≤20)>-<6 位随机小写数字>
SITE_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,19}-[a-z0-9]{6}")


# spec §3.5：身份必须来自企业 IdP。Edge 管住站点访问，这里管住管理面
# （AgentCore authorizer 只验 issuer/client_id，不看 idp）。
# 空值 = 迁移宽限期放行，与 Edge 的 REQUIRE_IDP_CLAIM 开关对齐；
# 切完 pool、全员重新登录后必须配上。
#
# **每次调用时读环境变量，不在模块导入时固化**：固化成模块级常量后，
# 测试里的 monkeypatch.setenv 不再生效（server 早已被别的用例导入过），
# 拒绝类用例会永远看到空 tuple 而假通过。
def _trusted_idps() -> tuple[str, ...]:
    return tuple(x.strip() for x in
                 os.environ.get("TRUSTED_IDPS", "").split(",") if x.strip())


# 与 Edge 的 TRUSTED_AUTH_SOURCES 同义：只放行托管登录与其 refresh。
# 原生 InitiateAuth（TokenGeneration_Authentication）的 token 拒掉——
# linked 本地用户的 idp claim 看起来合法，只有来源能分辨（spec §3.5）。
TRUSTED_AUTH_SOURCES = ("TokenGeneration_HostedAuth",
                        "TokenGeneration_RefreshTokens")


# 与 auth/login_handler.py 的 REQUIRE_EMAIL_VERIFIED 同义、必须同步。
# 默认开：email 是授权主键，而联邦 email 默认 unverified。
# 同样每次调用时读（理由见 _trusted_idps 的注释）。
def _require_email_verified() -> bool:
    return os.environ.get(
        "REQUIRE_EMAIL_VERIFIED", "true").strip().lower() != "false"


def _is_verified(value) -> bool:
    """只认真值，其余（缺失/false/None）一律 False——fail-closed。

    access token 里该 claim 由 pre-token 触发器注入成字符串 "true"/"false"；
    直接来自 id_token 时是 JSON 布尔。两种形态都要认。
    """
    return value is True or str(value).strip().lower() == "true"


class NotOwner(Exception):
    pass


class UploadMissing(Exception):
    pass


class UploadTooLarge(Exception):
    pass


class AlreadyStarted(Exception):
    pass


MAX_ZIP_BYTES = 50 * 1024 * 1024


def _s3():
    return boto3.client("s3", region_name="us-east-1")


def _sfn():
    return boto3.client("stepfunctions", region_name="us-east-1")


def _lambda():
    return boto3.client("lambda", region_name="us-east-1")


class Authz(NamedTuple):
    """一次鉴权判定的结果快照。

    `rev` 是判定所依据的 permissions_rev——把它带到最终动作的事务条件里，
    就能保证"判定之后权限没被改过"（见 _rev_condition_check）。
    `had_rev` 区分"rev 确实是 0"与"这条记录没有 rev 属性"（一期存量）：
    后者不能用 rev 相等来守卫，只能退回到按角色事实守卫。
    """
    site: dict
    role: str
    rev: int
    had_rev: bool
    actor: str


def _assert_permission(email: str, site_id: str, action: str,
                       what: str) -> Authz:
    """按二期角色模型判定（owner / collaborator / admin）。

    权限真源是 sites 表，判定逻辑全在 permissions.py——控制台与 MCP 共用
    同一模块，两边语义不会漂移。

    **返回值里带 role 与 rev**：调用方若要落地一个有副作用的动作，必须把它们
    绑进最终动作（见 _rev_condition_check / do_undeploy），否则鉴权与动作之间
    的撤权窗口里旧请求仍会生效。
    """
    # 强一致读：撤权/转移必须立刻生效。最终一致读会留下"权限已撤销但旧请求
    # 仍读到旧名单"的窗口。写路径不用本函数（授权在事务内做，见下方注释）。
    site = common.get_site_consistent(site_id)
    try:
        role = permissions.assert_can(
            email, site, action, is_admin=permissions.is_admin(email), what=what)
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e))
    site = site or {}
    return Authz(site, role, int(site.get("permissions_rev", 0)),
                 "permissions_rev" in site, email)


# 判定与动作之间的撤权窗口：把"权限快照仍是我鉴权时那份"作为事务条件。
#
# permissions.write_permissions 每次成功写入都会推进 sites 表的
# permissions_rev（撤协作者、改名单、转移所有权都算），所以"rev 未变"等价于
# "我读到的那套授权数据仍然有效"。这正是 write_permissions 自己用的机制——
# 那里授权与写入在同一事务，本函数把同一不变量带到 MCP 的两条副作用路径上
# （Codex 复审 2026-08-07 P1）。
#
# ⚠️ **效力边界，按字面理解**：线性化点是**本事务提交成功的那一刻**——提交成功
# 即视为请求已被接受。所以它保证的是"撤权完成后，旧主体的请求不再被接受"，
# 而**不是**"SFN 启动前都还能拦住"：事务提交后、start_execution 之前发生的撤权
# 拦不住（那已在接受点之后），SFN 一旦开跑（约 90 秒到上线）更不会被回收。
# 要覆盖接受点之后的部分，得在 SFN 步骤里复查 rev 并支持中止，属独立改动。
# 写运维文档时按"提交即接受"表述，别写成"部署开始前都能撤回"
# （Codex 复审 2026-08-07 第二轮对边界表述的再修正）。
def _rev_condition_check(authz: "Authz", site_id: str) -> dict:
    """把"鉴权所依据的授权事实此刻仍然成立"作为事务条件。

    **不能只写 `attribute_not_exists(permissions_rev) OR permissions_rev = :rev`**。
    那个写法本意是兼容一期存量（没有 rev 属性），但 attribute_not_exists 在
    **整个 item 不存在、或 item 被删除后用同 site_id 重建且没写 rev** 时同样
    成立——于是：
        旧 owner 读到 rev=7 → 站点被删除并重建（新 owner，无 rev）→
        条件通过 → 旧 owner 的代码覆盖新 owner 的站点。
    已实测复现（Codex 复审 2026-08-07 P1）。undeploy.py 会 delete 路由 item 并
    把 sites 置 DELETED，而 do_deploy_site 的 upsert 只写 owner/name/status
    （不写 rev），"同 site_id 重新建站"这条路径是真实可达的。

    所以分两种情况，都要求 **item 必须存在**：
      · 鉴权快照带 rev  → 只接受精确相等（重建后无 rev 也会被拒）；
      · 快照没有 rev（一期存量）→ 退回到按**角色事实**守卫：owner 必须还是我，
        或 collaborators 里还有我。这样即便记录被重建，新记录的 owner 不是我
        就会被拒。
    admin 代管路径由独立的 admins ConditionCheck 负责（见 _admin_condition_check）。
    """
    if authz.had_rev:
        return {"ConditionCheck": {
            "TableName": os.environ["SITES_TABLE"],
            "Key": {"site_id": {"S": site_id}},
            # attribute_exists 不可省：item 被删掉时 permissions_rev = :rev
            # 本身就不成立，但显式写出来意图更清楚，也挡住"重建且无 rev"。
            "ConditionExpression": ("attribute_exists(site_id) "
                                    "AND permissions_rev = :rev"),
            "ExpressionAttributeValues": {":rev": {"N": str(authz.rev)}}}}
    # 一期存量：没有 rev 可比，只能断言"我此刻仍是 owner 或 collaborator"。
    # admin 走这条时角色事实可能两条都不成立，交给 admins ConditionCheck。
    if authz.role == permissions.ROLE_ADMIN:
        return {"ConditionCheck": {
            "TableName": os.environ["SITES_TABLE"],
            "Key": {"site_id": {"S": site_id}},
            "ConditionExpression": "attribute_exists(site_id)"}}
    return {"ConditionCheck": {
        "TableName": os.environ["SITES_TABLE"],
        "Key": {"site_id": {"S": site_id}},
        "ConditionExpression": ("attribute_exists(site_id) AND "
                                "(#o = :me OR contains(collaborators, :me))"),
        "ExpressionAttributeNames": {"#o": "owner"},
        "ExpressionAttributeValues": {":me": {"S": authz.actor}}}}


def _admin_condition_check(email: str) -> dict:
    """admin 代管路径：把"此刻仍在管理员名单里"也绑进同一事务。

    admin 被移出名单不会推进任何站点的 permissions_rev，所以 rev 条件管不到
    这条路径，必须单独加（与 write_permissions 的 admin ConditionCheck 同理）。
    """
    return {"ConditionCheck": {
        "TableName": os.environ["ADMINS_TABLE"],
        "Key": {"email": {"S": email}},
        "ConditionExpression": "attribute_exists(email)"}}


# ---------- 纯函数层（单测目标） ----------

def do_deploy_site(owner: str, site_name: str, site_id: str | None = None) -> dict:
    if site_id:
        # site_id 同样进入资源名/SQL 标识符；只接受本平台生成的形态
        if not SITE_ID_RE.fullmatch(site_id or ""):
            raise common.InvalidSiteName(f"site_id 格式非法: {site_id!r}")
        _assert_permission(owner, site_id, "deploy", f"站点 {site_id}")
    else:
        site_id = common.new_site_id(common.validate_site_name(site_name))
        common.upsert_site(site_id, owner=owner, name=site_name, status="DEPLOYING")
    job_id = common.create_job(owner, site_id)
    url = _s3().generate_presigned_url(
        "put_object",
        Params={"Bucket": os.environ["ARTIFACTS_BUCKET"],
                "Key": f"uploads/{job_id}.zip"},
        ExpiresIn=900)
    return {"job_id": job_id, "site_id": site_id, "upload_url": url,
            "next_step": "将 site.zip PUT 到 upload_url（不要带 Content-Type 头，"
                         "否则预签名校验 403），然后调用 confirm_upload"}


def do_confirm_upload(owner: str, job_id: str) -> dict:
    job = common.get_job(job_id)
    if not job:
        raise NotOwner(f"任务 {job_id} 不存在")
    # "deploy" 而非 "read"：确认上传会启动部署
    authz = _assert_permission(owner, job["site_id"], "deploy", f"任务 {job_id}")
    s3 = _s3()
    try:
        head = s3.head_object(Bucket=os.environ["ARTIFACTS_BUCKET"],
                              Key=f"uploads/{job_id}.zip")
    except s3.exceptions.ClientError:
        raise UploadMissing("未检测到上传的 site.zip，请先 PUT 到 upload_url")
    if head["ContentLength"] > MAX_ZIP_BYTES:
        raise UploadTooLarge(f"site.zip {head['ContentLength']} 字节超过 50MB 上限")

    # 条件迁移 PENDING→RUNNING：双击/重放在此被拦，SFN 同名执行是第二道闸。
    #
    # **走事务而不是裸 update_item**：同一笔里带上"权限快照未变"（+ admin 路径
    # 的"仍是管理员"）的 ConditionCheck。否则鉴权通过后、启动部署前的窗口里
    # owner 若移除了协作者，这个旧请求仍会把 job 置 RUNNING 并起 SFN，
    # 已撤权的人提交的代码照样覆盖生产站点（Codex 复审 2026-08-07 P1）。
    import botocore.exceptions
    items = [
        {"Update": {
            "TableName": os.environ["JOBS_TABLE"],
            "Key": {"job_id": {"S": job_id}},
            "UpdateExpression": "SET #s = :running, phase = :q",
            "ConditionExpression": "#s = :pending",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": {"S": "RUNNING"},
                                          ":pending": {"S": "PENDING"},
                                          ":q": {"S": "queued"}}}},
        _rev_condition_check(authz, job["site_id"]),
    ]
    if authz.role == permissions.ROLE_ADMIN:
        items.append(_admin_condition_check(owner))
    try:
        boto3.client("dynamodb", region_name="us-east-1").transact_write_items(
            TransactItems=items)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        # 逐项分辨取消原因：整个异常当"已启动过"会把撤权报成重复点击
        reasons = [r.get("Code", "") for r in
                   e.response.get("CancellationReasons", [])]
        if reasons and reasons[0] == "ConditionalCheckFailed":
            raise AlreadyStarted(
                f"任务 {job_id} 已启动过，请用 get_deploy_status 查询进度") from e
        if len(reasons) > 1 and reasons[1] == "ConditionalCheckFailed":
            raise NotOwner(
                "站点权限在你提交期间被修改（协作者/所有权变更），本次部署已取消"
                "——请重新确认权限后再试") from e
        if len(reasons) > 2 and reasons[2] == "ConditionalCheckFailed":
            raise NotOwner("你的管理员权限已被撤销") from e
        raise
    # 事务已提交（= 请求已被接受），但 SFN 还没起。这两步之间失败的话，
    # job 会永久停在 RUNNING 而没有任何 execution 在跑：重试因 status 已非
    # PENDING 被判成 AlreadyStarted，用户只能一直轮询一个永不推进的任务
    # ——ExecutionLimitExceeded / 节流 / KMS / 状态机被删都会走到这里
    # （Codex 复审 2026-08-07 P1，已实测复现）。
    #
    # 处置：条件回滚到 PENDING，把重试权还给用户。
    # 回滚是安全的——StartExecution 对 STANDARD 工作流**幂等**（同 name + 同
    # input 返回同一个 execution），而本函数的 input 完全由 job_id/site_id 决定，
    # 所以"其实已经起成功了、只是响应丢了"这种情况下重试也不会起出第二条。
    sfn_input = json.dumps({"job_id": job_id, "site_id": job["site_id"]})
    try:
        _sfn().start_execution(
            stateMachineArn=os.environ["STATE_MACHINE_ARN"],
            name=job_id,  # 同名执行被 SFN 拒绝 = 幂等
            input=sfn_input)
    except botocore.exceptions.ClientError as start_err:
        # 按**错误码**判别，不用异常类名：botocore 的异常类是按服务模型动态生成的，
        # 类名比错误码更容易随 SDK 版本变化。
        if (start_err.response.get("Error", {}).get("Code")
                == "ExecutionAlreadyExists"):
            # 上一次其实起成功了（响应丢了或并发重试）。同 name + 同 input
            # 就是同一次部署，按成功返回，**不要**回滚。
            return {"status": "RUNNING"}
        _rollback_job_to_pending(job_id)
        raise
    except Exception:
        # 非 ClientError（网络中断、连接超时等）同样要回滚——这类失败最可能
        # 根本没到达 SFN，不回滚就是永久卡死。
        _rollback_job_to_pending(job_id)
        raise

    return {"status": "RUNNING"}


def _rollback_job_to_pending(job_id: str) -> None:
    """SFN 未起成功时把 job 退回 PENDING，让 confirm_upload 可以重试。

    **条件必须同时匹配 status=RUNNING 且 phase=queued**——也就是"正是本函数刚
    写进去、还没有任何 SFN 步骤动过"的那个状态。若 execution 其实已经起来并推进
    到 validate（phase 会变），回滚就会把一个真在跑的任务改回 PENDING，用户重试
    时又起一条同名 execution（被拒）或误判状态。宁可回滚失败留下 RUNNING，
    也不能踩掉真在跑的部署。

    回滚本身失败不再抛出：此时要让调用方看到的是 start_execution 的**原始**错误
    （那才是根因）。回滚失败的后果退化成本函数修的那个老问题，不会更糟。
    """
    import botocore.exceptions
    try:
        boto3.client("dynamodb", region_name="us-east-1").update_item(
            TableName=os.environ["JOBS_TABLE"],
            Key={"job_id": {"S": job_id}},
            UpdateExpression="SET #s = :pending, phase = :p",
            ConditionExpression="#s = :running AND phase = :queued",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":pending": {"S": "PENDING"}, ":p": {"S": "submitted"},
                ":running": {"S": "RUNNING"}, ":queued": {"S": "queued"}})
    except botocore.exceptions.ClientError:
        pass    # 见 docstring：原始错误更重要，且回滚失败不会让状态更坏


def do_get_status(owner: str, job_id: str) -> dict:
    job = common.get_job(job_id)
    if not job:
        raise NotOwner(f"任务 {job_id} 不存在")
    _assert_permission(owner, job["site_id"], "read", f"任务 {job_id}")
    return {k: job.get(k, "") for k in ("status", "phase", "error", "url")}


def do_list_sites(owner: str) -> list[dict]:
    """我 owner 的 ∪ 我是 collaborator 的站点。"""
    base = os.environ["BASE_DOMAIN"]
    out = []
    for s in common.list_sites_for_user(owner):
        role = permissions.role_of(owner, s)
        out.append({"site_id": s["site_id"], "name": s.get("name", ""),
                    "url": f"https://{s.get('subdomain', 'app-' + s['site_id'])}.{base}",
                    "status": s.get("status", ""), "tier": s.get("tier", ""),
                    "role": role})
    return out


def do_undeploy(owner: str, site_id: str, purge_data: bool = False) -> dict:
    authz = _assert_permission(owner, site_id, "undeploy", f"站点 {site_id}")
    site = authz.site
    # **建 job 与"权限快照未变"同一笔提交**：下线（尤其 purge_data=True）不可
    # 恢复，鉴权之后被转移所有权/撤权的旧请求不能再落地
    # （Codex 复审 2026-08-07 P1）。建 job 失败 → 不调 undeploy Lambda。
    import botocore.exceptions
    guards = [_rev_condition_check(authz, site_id)]
    if authz.role == permissions.ROLE_ADMIN:
        guards.append(_admin_condition_check(owner))
    try:
        job_id = common.create_job(owner, site_id, guard_items=guards)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        reasons = [r.get("Code", "") for r in
                   e.response.get("CancellationReasons", [])]
        if len(reasons) > 2 and reasons[2] == "ConditionalCheckFailed":
            raise NotOwner("你的管理员权限已被撤销") from e
        if len(reasons) > 1 and reasons[1] == "ConditionalCheckFailed":
            raise NotOwner(
                "站点权限在你提交期间被修改（协作者/所有权变更），本次下线已取消"
                "——请重新确认权限后再试") from e
        raise
    payload = {"job_id": job_id, "site_id": site_id}
    if purge_data:
        payload["purge_data"] = True
        # tier 决定该清 DynamoDB 表还是 DSQL schema/role
        payload["engine"] = ("dsql" if (site or {}).get("tier") == "fullstack-sql"
                            else "dynamodb")
        tables = list((site or {}).get("data_tables", []))
        if tables:
            payload["data_tables"] = tables
    _lambda().invoke(FunctionName="site-deployer-undeploy",
                     InvocationType="Event",
                     Payload=json.dumps(payload))
    return {"job_id": job_id, "purge_data": bool(purge_data)}


class PermissionConflict(Exception):
    """并发修改。MCP 工具把它转成可读文案让 Agent 提示用户重试。"""


# 写路径**不在这里预先鉴权**：授权判定在 permissions.write_permissions 内
# 与 rev 同源完成（分开做会有 TOCTOU——鉴权通过后权限被撤销，写入仍成功）。
# 这里只负责把 permissions 层的异常翻译成 MCP 的错误类型。

def do_update_permissions(caller: str, site_id: str, require_login=None,
                          allowed_users=None) -> dict:
    try:
        out = permissions.set_access_policy(site_id, actor=caller,
                                            require_login=require_login,
                                            allowed_users=allowed_users)
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e)) from e
    except permissions.PermissionConflict as e:
        raise PermissionConflict(str(e)) from e
    out["note"] = "已生效，边缘缓存最多 1 分钟后全网一致"
    return out


def do_manage_collaborators(caller: str, site_id: str, add=None, remove=None,
                            transfer_owner=None) -> dict:
    try:
        if transfer_owner:
            # 工具 docstring 承诺"与 add/remove 互斥"——必须真的互斥，不能静默
            # 丢弃：用户说"加 Bob 并把站点交给 Alice"，Agent 拿到成功响应但
            # Bob 根本没被加上，这类静默半执行比报错难查得多。
            if add or remove:
                raise ValueError(
                    "transfer_owner 与 add/remove 互斥——请分两次调用"
                    "（先加/删协作者，再转移所有权）")
            return permissions.transfer_owner(site_id, actor=caller,
                                              new_owner=transfer_owner)
        if not add and not remove:
            raise ValueError("需要指定 add / remove / transfer_owner 之一")
        collaborators = permissions.set_collaborators(site_id, actor=caller,
                                                      add=add, remove=remove)
        site = common.get_site_consistent(site_id) or {}
        return {"owner": site.get("owner", ""), "collaborators": collaborators}
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e)) from e
    except permissions.PermissionConflict as e:
        raise PermissionConflict(str(e)) from e


def do_get_permissions(caller: str, site_id: str) -> dict:
    site = _assert_permission(caller, site_id, "read", f"站点 {site_id}").site
    return {"site_id": site_id,
            "owner": site.get("owner", ""),
            "collaborators": list(site.get("collaborators") or []),
            "require_login": bool(site.get("require_login", True)),
            "allowed_users": site.get("allowed_users", "org"),
            "my_role": permissions.role_of(caller, site,
                                           permissions.is_admin(caller))}


# ---------- MCP 壳 ----------

# AgentCore Runtime 契约：容器必须监听 0.0.0.0:8000 并暴露 POST /mcp，
# 且用 stateless streamable-http（平台为每个请求注入 Mcp-Session-Id 做会话隔离）。
# FastMCP 默认绑 127.0.0.1，在容器里平台探测不到。
mcp = FastMCP("site-builder-deploy", stateless_http=True,
              host="0.0.0.0", port=8000)


def _caller_email() -> str:
    """从入站请求的 Authorization: Bearer <JWT> 里取 email claim。

    AgentCore Runtime 的 customJWTAuthorizer 验签后，把原始 Authorization 头
    透传给容器内的 MCP server（官方 SDK 无 get_http_headers；用 FastMCP 的
    request_context 拿 starlette Request）。JWT 已被 AgentCore 验过签名，此处
    只解 payload 取 email，不重复验签。Task 20 spike 已本地验证此路径可用。
    """
    import base64
    import json as _json

    try:
        request = mcp.get_context().request_context.request
        auth = dict(request.headers).get("authorization", "") if request else ""
    except Exception:
        auth = ""
    token = auth[7:] if auth[:7].lower() == "bearer " else auth
    parts = token.split(".")
    if len(parts) == 3:
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload))
            email = claims.get("email", "")
            if email:
                trusted = _trusted_idps()
                if trusted:
                    if claims.get("idp") not in trusted:
                        raise NotOwner(
                            "身份来源不被信任（缺少或非法的 idp claim）——"
                            "请用企业账号重新登录")
                    if claims.get("auth_via") not in TRUSTED_AUTH_SOURCES:
                        raise NotOwner(
                            "本次登录方式不被信任（非托管登录来源）——"
                            "请用企业账号重新登录")
                # email 是授权主键（owner/collaborators/allowed_users 全用它），
                # 而联邦 email 默认 unverified——只映射不校验等于没有防线。
                # 与 auth/login_handler.py 的同名开关语义一致，两处必须同步。
                # 注入靠 pre-token 触发器（access token 默认不含该 claim）。
                if _require_email_verified() and not _is_verified(
                        claims.get("email_verified")):
                    raise NotOwner(
                        "邮箱未经身份提供方验证，拒绝授权——请用企业账号登录")
                return email
        except NotOwner:
            raise
        except Exception:
            pass
    raise NotOwner("无法识别调用者身份（缺少 OAuth email claim）")


@mcp.tool()
def deploy_site(site_name: str, site_id: str = "") -> dict:
    """部署（或更新）一个站点。返回 upload_url，把 site.zip PUT 上去后调 confirm_upload。
    site_name: 站点名（小写字母数字连字符）；site_id: 更新已有站点时传。"""
    return do_deploy_site(_caller_email(), site_name, site_id or None)


@mcp.tool()
def confirm_upload(job_id: str) -> dict:
    """确认 site.zip 已上传，启动异步部署。之后轮询 get_deploy_status。"""
    return do_confirm_upload(_caller_email(), job_id)


@mcp.tool()
def get_deploy_status(job_id: str) -> dict:
    """查询部署任务状态。status=SUCCEEDED 时 url 即站点地址；FAILED 时 error 为原因。"""
    return do_get_status(_caller_email(), job_id)


@mcp.tool()
def list_my_sites() -> list:
    """列出我部署的所有站点。"""
    return do_list_sites(_caller_email())


@mcp.tool()
def undeploy_site(site_id: str, purge_data: bool = False) -> dict:
    """下线站点：删路由/Lambda/前端。仅站点所有者可操作。

    purge_data=False（默认）：数据库数据保留，可留待排查或后续恢复。
    purge_data=True：额外永久删除该站点的 DynamoDB 表 / DSQL schema 与角色。
      不可恢复——必须先向用户明确确认再传 true。"""
    return do_undeploy(_caller_email(), site_id, purge_data)


@mcp.tool()
def update_site_permissions(site_id: str, require_login: bool | None = None,
                            allowed_users: list | str | None = None) -> dict:
    """在线修改站点访问策略——不需要重新部署，约 1 分钟内全网生效。

    require_login: true 需登录后访问，false 公开；不传表示不改。
    allowed_users: "org"（全组织可访问）或邮箱数组；不传表示不改。
    站点 owner 与协作者均可调用。site.json 里的 auth 字段不再生效。"""
    return do_update_permissions(_caller_email(), site_id, require_login,
                                 allowed_users)


@mcp.tool()
def manage_collaborators(site_id: str, add: list | None = None,
                         remove: list | None = None,
                         transfer_owner: str = "") -> dict:
    """管理站点协作者或转移所有权。仅 owner（或平台管理员）可调用。

    add/remove: 协作者邮箱数组。协作者可部署更新、改访问策略、查状态，
      但不能下线站点、不能增删协作者。
    transfer_owner: 新 owner 邮箱。转移后原 owner 自动降级为协作者
      （防转错人失去访问）。此参数与 add/remove 互斥。"""
    return do_manage_collaborators(_caller_email(), site_id, add, remove,
                                   transfer_owner or None)


@mcp.tool()
def get_site_permissions(site_id: str) -> dict:
    """查询站点当前的访问策略、owner、协作者，以及我对它的角色。"""
    return do_get_permissions(_caller_email(), site_id)


if __name__ == "__main__":
    # streamable-http 挂在 /mcp（FastMCP 默认 streamable_http_path）
    mcp.run(transport="streamable-http")
