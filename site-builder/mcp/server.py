"""部署 MCP——薄壳：4 工具全部秒级返回，重活交给 Step Functions。
运行于 AgentCore Runtime；调用者飞书 email 由网关经 JWT claims 传入。"""
import json
import os
import re
import sys
from pathlib import Path

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


def _assert_permission(email: str, site_id: str, action: str, what: str) -> dict:
    """按二期角色模型判定（owner / collaborator / admin）。

    权限真源是 sites 表，判定逻辑全在 permissions.py——控制台与 MCP 共用
    同一模块，两边语义不会漂移。
    """
    # 强一致读：撤权/转移必须立刻生效。最终一致读会留下"权限已撤销但旧请求
    # 仍读到旧名单"的窗口。写路径不用本函数（授权在事务内做，见下方注释）。
    site = common.get_site_consistent(site_id)
    try:
        permissions.assert_can(email, site, action,
                               is_admin=permissions.is_admin(email), what=what)
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e))
    return site or {}


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
    _assert_permission(owner, job["site_id"], "deploy", f"任务 {job_id}")
    s3 = _s3()
    try:
        head = s3.head_object(Bucket=os.environ["ARTIFACTS_BUCKET"],
                              Key=f"uploads/{job_id}.zip")
    except s3.exceptions.ClientError:
        raise UploadMissing("未检测到上传的 site.zip，请先 PUT 到 upload_url")
    if head["ContentLength"] > MAX_ZIP_BYTES:
        raise UploadTooLarge(f"site.zip {head['ContentLength']} 字节超过 50MB 上限")

    # 条件迁移 PENDING→RUNNING：双击/重放在此被拦，SFN 同名执行是第二道闸
    import botocore.exceptions
    try:
        boto3.resource("dynamodb", region_name="us-east-1").Table(
            os.environ["JOBS_TABLE"]).update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :running, phase = :q",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":running": "RUNNING", ":pending": "PENDING",
                                       ":q": "queued"})
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise AlreadyStarted(f"任务 {job_id} 已启动过，请用 get_deploy_status 查询进度")
        raise
    _sfn().start_execution(
        stateMachineArn=os.environ["STATE_MACHINE_ARN"],
        name=job_id,  # 同名执行被 SFN 拒绝 = 幂等
        input=json.dumps({"job_id": job_id, "site_id": job["site_id"]}))
    return {"status": "RUNNING"}


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
    site = _assert_permission(owner, site_id, "undeploy", f"站点 {site_id}")
    job_id = common.create_job(owner, site_id)
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
    site = _assert_permission(caller, site_id, "read", f"站点 {site_id}")
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
