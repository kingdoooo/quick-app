"""部署 MCP——薄壳：工具全部秒级返回，重活交给 Step Functions。

工具数**刻意不写在这里**：真源是本文件下半部分的 `@mcp.tool()` 装饰器，
在同一个文件里再抄一个数字只会像 M6 之前那样漂掉（当时这行还写着 4）。
运行于 AgentCore Runtime；调用者飞书 email 由网关经 JWT claims 传入。"""
import hmac
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


# ---------- API Key 的 on-behalf 路径（二期 M4，spec §5.3）----------
#
# 交换层（key-proxy）用 machine client 的 client_credentials token 调本服务，
# 并带一个 `X-SB-On-Behalf-Of: {email}` 说明"以谁的身份行事"。
#
# **头名与环境变量名的真源是 `deployer/functions/api_key_config.py`**
# （那里还给网关的 requestHeaderAllowlist 与部署脚本用）。本模块留一份小写镜像
# 而不是 import 它：容器只 COPY server.py / common.py / permissions.py /
# ops_log.py，多一个模块就要同步 Dockerfile、构建输入指纹与复制清单。两处由
# `mcp/tests/test_component_gate.py` 的 real-value 断言绑定，漂了当场红。
#
# 小写是**必须**的：starlette 的 `dict(request.headers)` 键全小写，按原样
# 大小写取值会永远取不到——症状是所有 Key 调用都报"无法识别调用者身份"。
ON_BEHALF_HEADER = "x-sb-on-behalf-of"
MACHINE_CLIENT_ID_ENV = "MACHINE_CLIENT_ID"


# **每次调用时读环境变量**（同 _trusted_idps 的理由，那条教训在本文件更上面）。
# 空值 = 本平台没启用 API Key 组件 → 拒绝全部 on-behalf 请求，与网关侧
# "machine client 不在 allowedClients"同向 fail-closed。
def _machine_client_id() -> str:
    return os.environ.get(MACHINE_CLIENT_ID_ENV, "").strip()


def _on_behalf_email(claims: dict, headers: dict) -> str:
    """机器 token + on-behalf 头 → 被代理的用户 email；不成立时返回 ""。

    三个条件全过才认（缺一即返回空，由调用方按"识别不出身份"拒绝）：
      ① `_machine_client_id()` 非空——**没配置绝不能退化成"不比对"**，
         那正是 fail-open：`"" == ""` 会让任何 token 拿到任意身份；
      ② token 的 `client_id` 与它 `compare_digest` 相等（机器 token 只能由
         持有 machine client secret 的组件换到，而那个 secret 只在 SSM 里、
         只有 key-proxy 读）；
      ③ 头值过 `permissions.EMAIL_RE.fullmatch`——**复用平台唯一的邮箱形态
         判定**，不写第二个正则。`fullmatch` 而非 `match`：`match` 会放过
         "a@b.com\\nX-Injected: 1" 与逗号分隔的多值，于是形态校验顺带丢掉了
         挡头注入的作用。

    **为什么这条路径可以跳过 idp / auth_via / email_verified 三重校验**
    （全仓库只有这一条能跳，别照抄到别处）：机器 token 天生没有这三个 claim
    （spike 实测 client_credentials token 的 claim 里一个都不是），补齐它们做不到
    ——这不是"漏了校验"，而是那三个 claim 在这条链路上不存在。email 的可信性来自
    **创建时**：Key 只能在控制台创建，控制台身份是 Edge 注入的 `x-user-email`，
    那条路径已经过了 `REQUIRE_IDP_CLAIM` 校验（决定 8）。已知取舍：用户离职后旧
    Key 仍有效，靠审计 + 吊销处理（哨兵行可一键全禁）。
    """
    machine = _machine_client_id()
    if not machine:
        return ""
    client_id = claims.get("client_id")
    # **这里刻意不写 `or not client_id`**（反向验证 2026-08-12 的发现）：
    # 那个多余的判断会把上面那条空值闸门挡在身后——`client_id == ""` 先被它拒掉，
    # 于是"把 `if not machine: return ""` 删掉"这种注入**没有任何测试会变红**，
    # 空值闸门看起来有、实际上无法证明它在起作用（本仓库记过的
    # 「加固测试必须先会红」）。现在 `"" == ""` 这条路只由上面那一处闸门挡着，
    # 删掉它 test_missing_machine_client_env_rejects_all_on_behalf 立刻变红。
    # 安全性不变：machine 非空时 compare_digest("", machine) 恒为假。
    if not isinstance(client_id, str):
        return ""
    # bytes 比对：compare_digest 对含非 ASCII 的 str 会 TypeError，
    # 而 client_id 来自入站 token（不受我们控制）。
    if not hmac.compare_digest(client_id.encode("utf-8"),
                               machine.encode("utf-8")):
        return ""
    value = headers.get(ON_BEHALF_HEADER, "")
    if not isinstance(value, str) or not permissions.EMAIL_RE.fullmatch(value):
        return ""
    return value


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
def _rev_condition_check(authz: "Authz", site_id: str, action: str) -> dict:
    """把"鉴权所依据的授权事实此刻仍然成立"作为事务条件。

    条件表达式本身**不在这里定义**——统一由 permissions.snapshot_condition 生成
    （全仓库唯一定义）。这个模块曾经手抄过一份，代价是两个 P1：
      · `attribute_not_exists(permissions_rev)` 兼容分支在"站点被同 site_id
        重建且无 rev"时静默成立（旧 owner 覆盖新 owner 的站点）；
      · 手写的角色子句把 owner 与 collaborator 合并成"二者之一"，而
        CAPABILITIES 里 undeploy **不给** collaborator——transfer_owner 把旧
        owner 降级为 collaborator 后，他仍能 purge 掉新 owner 的数据。
    两者都实测复现过。所以**必须把 action 传进来**：允许哪些角色由
    CAPABILITIES[action] 决定，与 assert_can 同源，不可能再漂移。
    """
    return permissions.sites_snapshot_guard(
        site_id, rev=authz.rev, had_rev=authz.had_rev,
        actor=authz.actor, action=action, role=authz.role)


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
        # create_site_record 而非 upsert_site：整条记录 attribute_not_exists
        # 单次条件写。upsert 语义下随机 ID 碰撞会把已有站点的 owner/name/
        # status 覆盖成本次调用者（误接管）；碰撞重新生成 ID 重试。
        # 36^6 ≈ 21.8 亿的后缀空间里 3 次连撞视为异常（大概率是环境/代码问题），
        # 响亮失败而不是无限重试。
        for _ in range(3):
            site_id = common.new_site_id(common.validate_site_name(site_name))
            try:
                common.create_site_record(site_id, owner=owner, name=site_name)
                break
            except common.SiteIdCollision:
                continue
        else:
            raise common.InvalidSiteName(
                "站点 ID 连续碰撞，请重试；若持续出现请联系平台管理员")
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
    #
    # 同一笔里还把**上面那一次 HEAD** 的 ETag 与字节数钉进 job 记录：
    #   · 钉的必须是**那一次** HEAD 的返回，不许为取 etag 再 HEAD 一次——上面的
    #     50MB 是对第一次看到的那个对象查的，第二次 HEAD 可能已经是另一个对象
    #     （预签名 PUT URL 还活 900s，谁都没有机制作废它），于是"被钉住的字节"
    #     与"被查过大小的字节"就不是同一份了（test_confirm_upload_pins_the_etag_
    #     it_head_checked 按 head_object 的**次数**锁死）；
    #   · validate 用它做 `IfMatch` 读同一份字节（deployer/functions/validate.py
    #     的 MAX_UPLOAD_BYTES 那段）。SFN 对每个步骤都有 MaxAttempts:6 的
    #     service-exception 重试，不钉的话两次 attempt 可以读到不同的包；
    #   · `upload_bytes` 是**审计字段，不是控制点**——别看到"记录里有个字节数"就以为
    #     大小校验在这里。真正的校验有两处：本函数上面那次 HEAD 的 50MB，以及 validate
    #     对 `get_object` 返回的 `ContentLength` 与 `MAX_UPLOAD_BYTES` 那一次比较
    #     （`IfMatch` 已经比字节数强，所以没人读它）。留着它是为了真机排障时不必再
    #     HEAD 一次就知道当时那个包多大；
    #   · 与 PENDING→RUNNING **同一笔**：第二次点击（AlreadyStarted）因此既不推进
    #     状态也改不到 etag，否则重放能把已经开跑的 job 钉到新字节上。
    import botocore.exceptions
    items = [
        {"Update": {
            "TableName": os.environ["JOBS_TABLE"],
            "Key": {"job_id": {"S": job_id}},
            "UpdateExpression": ("SET #s = :running, phase = :q, "
                                 "upload_etag = :etag, upload_bytes = :len"),
            "ConditionExpression": "#s = :pending",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": {"S": "RUNNING"},
                                          ":pending": {"S": "PENDING"},
                                          ":q": {"S": "queued"},
                                          ":etag": {"S": head["ETag"]},
                                          ":len": {"N": str(head["ContentLength"])}}}},
        _rev_condition_check(authz, job["site_id"], "deploy"),
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
    #
    # 回滚安全性依据的是 StartExecution 的**确切**契约（官方原文，不要凭印象）：
    #   "对 STANDARD 工作流，若用**同 name 同 input** 调用一个**正在运行**的
    #    execution，调用**成功**并返回与原请求相同的响应。若该 execution 已
    #    **关闭**、或 input 不同，则返回 400 ExecutionAlreadyExists。
    #    name 在 90 天后才可复用。"
    # 由此得到两条推论，本函数完全建立在它们之上：
    #   ① 本函数的 input 完全由 job_id/site_id 决定（对同一 job 恒定），所以
    #      "input 不同"不可能发生；
    #   ② 于是收到 ExecutionAlreadyExists **恰好证明该 execution 已关闭**，
    #      而不是"正在跑"。上一轮把它当成"仍在运行"按成功返回，是把契约读反了
    #      （Codex 复审 2026-08-08 P1）：真实后果是 job 永久停在 RUNNING，且这个
    #      name 90 天内不能再用，等于该 job 永久无法推进——正是想修的那个病。
    #      顺带：正因为①②，判"是否仍在运行"**不需要** DescribeExecution
    #      （runtime 角色也没有该权限），错误码本身已经给出答案。
    sfn_input = json.dumps({"job_id": job_id, "site_id": job["site_id"]})
    try:
        _sfn().start_execution(
            stateMachineArn=os.environ["STATE_MACHINE_ARN"],
            name=job_id,   # 同 name 同 input 且在运行 = 幂等成功（见上）
            input=sfn_input)
    except botocore.exceptions.ClientError as start_err:
        # 按**错误码**判别，不用异常类名：botocore 的异常类是按服务模型动态生成的，
        # 类名比错误码更容易随 SDK 版本变化。
        if (start_err.response.get("Error", {}).get("Code")
                == "ExecutionAlreadyExists"):
            # 该 name 的 execution 已存在且**已关闭**（见上面的推论②）。
            # 这个 job 再也起不起来了（name 90 天内不可复用），所以既不能报成功
            # （用户会一直轮询一个永不推进的任务），也不该回滚成 PENDING
            # （重试只会再撞一次同样的错）。如实置 FAILED 并告诉用户重新部署——
            # 重新部署会拿到新 job_id，也就是新的 execution name。
            # **条件写**：只在 job 仍是"我刚写进去、SFN 没碰过"的
            # RUNNING/queued 时才标 FAILED。无条件写会把一个**已经成功**的
            # 部署改成 FAILED——序列是：首次调用响应丢失 → 回滚成 PENDING →
            # 那条 execution 其实跑完了、mark_job 写了 SUCCEEDED → 用户重试 →
            # 事务把 job 又置回 RUNNING/queued → StartExecution 报
            # ExecutionAlreadyExists。此时若无条件写 FAILED，用户看到的是
            # "失败"而站点其实已经更新好了（独立审查发现，clobber 已实测）。
            # 条件失败说明 job 已被别的写入者推进过，那份状态更可信，不要覆盖。
            import botocore.exceptions as _be
            try:
                boto3.client("dynamodb", region_name="us-east-1").update_item(
                    TableName=os.environ["JOBS_TABLE"],
                    Key={"job_id": {"S": job_id}},
                    UpdateExpression="SET #s = :failed, #e = :err",
                    ConditionExpression=("#s = :running AND phase = :queued "
                                         "AND (attribute_not_exists(#u) OR #u = :empty)"),
                    ExpressionAttributeNames={"#s": "status", "#e": "error",
                                              "#u": "url"},
                    ExpressionAttributeValues={
                        ":failed": {"S": "FAILED"},
                        ":running": {"S": "RUNNING"},
                        ":queued": {"S": "queued"},
                        ":empty": {"S": ""},
                        ":err": {"S":
                                 "该任务的部署执行已结束但未能回写状态（同名执行"
                                 "已存在且已关闭，其名称 90 天内不可复用）。请重新"
                                 "发起一次部署（会生成新任务）；若站点已更新成功，"
                                 "也可直接查看站点确认。"}})
            except _be.ClientError:
                pass    # 已被推进（含已 SUCCEEDED）：保留那份状态，别覆盖
            raise AlreadyStarted(
                f"任务 {job_id} 的执行已结束且无法重启，已标记为 FAILED——"
                "请重新发起部署（会生成新任务）") from start_err
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
    # action="undeploy"：CAPABILITIES 里它**不含** collaborator，所以无-rev
    # 存量站点的守卫只会断言 "owner 仍是我"——旧 owner 被 transfer_owner 降级为
    # collaborator 后，这条会正确拒绝（Codex 复审 2026-08-08 P1）。
    guards = [_rev_condition_check(authz, site_id, "undeploy")]
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
    try:
        _lambda().invoke(FunctionName="site-deployer-undeploy",
                         InvocationType="Event",
                         Payload=json.dumps(payload))
    except Exception:
        # **job 已建好（PENDING），invoke 失败必须就地收敛**
        # （Codex 审查 2026-08-10 P1-4）：sweeper 只扫 RUNNING，停在 PENDING
        # 的 job 谁都不会再碰。panel 的 api.do_undeploy 有同样的处理——
        # 两个 writer 都要，不能只修一处（M3-FINDINGS「别打地鼠，修那一类」）。
        try:
            common.update_job(job_id, status="FAILED",
                              error="下线任务提交失败（未开始执行），站点未做任何"
                                    "改动。请重新发起下线。")
        except Exception:
            pass
        raise
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


def _analytics_payload(site_id: str, period: str, days: int) -> dict:
    """读取层。与 panel **共用同一个** deployer/functions/analytics.py。

    该模块必须进镜像（Dockerfile COPY + build_and_push 复制元组 +
    _BUILD_INPUTS 三处，见 Task 11）——容器里只有四个 .py 时这行会
    ModuleNotFoundError，而部署会显示成功（Codex 审查 P1-2 实测）。
    """
    import analytics
    return {"series": analytics.series(site_id, period, days),
            "recent_visitors": analytics.visitors(site_id, days=min(days, 7),
                                                  limit=50)["rows"]}


def do_get_analytics(caller: str, site_id: str, period: str, days: int) -> dict:
    if period not in ("day", "week", "month"):
        raise ValueError(f"period 必须是 day/week/month，收到 {period!r}")
    _assert_permission(caller, site_id, "view_analytics",
                       what=f"站点 {site_id} 的访问统计")
    return _analytics_payload(site_id, period, days)


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

    **两条信任路径，顺序不可换**（二期 M4）：
      · token 有 email claim → 既有 OAuth 路径，三重 claim 校验一字不改。
        这条**必须在前**：否则一个合法用户只要额外带个 on-behalf 头就能冒充
        别人（M4 最重要的负测盯的就是这一点）。
      · token 无 email claim → 才看 on-behalf 头（`_on_behalf_email`，那里写了
        为什么它可以跳过三重校验）。
    两条都不成立 → 下面那句 NotOwner（文案与 M4 之前一致）。
    """
    import base64
    import json as _json

    try:
        request = mcp.get_context().request_context.request
        headers = dict(request.headers) if request else {}
    except Exception:
        headers = {}
    auth = headers.get("authorization", "")
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
            # 无 email claim：唯一的另一条路径是 API Key 的交换层。
            # 注意这里**不是** else 兜底——上面的 `if email:` 分支只以 return
            # 或 raise 结束，所以带 email 的 token 永远到不了这行。
            on_behalf = _on_behalf_email(claims, headers)
            if on_behalf:
                return on_behalf
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


@mcp.tool()
def get_site_analytics(site_id: str, period: str = "day",
                       days: int = 30) -> dict:
    """查询站点的访问统计（PV / 独立访客 / 被拒次数）与最近的访问明细。

    period: day|week|month。**返回单个对象**，`series` 与 `recent_visitors`
    是它的字段——不返回裸列表（列表会被拆成多个 text 块并被调用方静默截断）。
    `uv_exact=false` 的桶其 `uv` 为 null：该区间超出 90 天明细留存窗口，
    独立访客数无法精确去重。
    """
    return do_get_analytics(_caller_email(), site_id, period, days)


if __name__ == "__main__":
    # streamable-http 挂在 /mcp（FastMCP 默认 streamable_http_path）
    mcp.run(transport="streamable-http")
