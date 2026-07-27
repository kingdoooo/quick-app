"""部署 MCP——薄壳：4 工具全部秒级返回，重活交给 Step Functions。
运行于 AgentCore Runtime；调用者飞书 email 由网关经 JWT claims 传入。"""
import json
import os
import re

import boto3
from mcp.server.fastmcp import FastMCP

import common  # deployer/functions/common.py，部署包中同目录

# 平台生成的 site_id 形态：<name(≤20)>-<6 位随机小写数字>
SITE_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,19}-[a-z0-9]{6}")


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


def _assert_owner(owner: str, record: dict | None, what: str):
    if not record:
        raise NotOwner(f"{what} 不存在")
    if record.get("owner") != owner:
        raise NotOwner(f"你不是 {what} 的所有者，无权操作")


# ---------- 纯函数层（单测目标） ----------

def do_deploy_site(owner: str, site_name: str, site_id: str | None = None) -> dict:
    if site_id:
        # site_id 同样进入资源名/SQL 标识符；只接受本平台生成的形态
        if not SITE_ID_RE.fullmatch(site_id or ""):
            raise common.InvalidSiteName(f"site_id 格式非法: {site_id!r}")
        _assert_owner(owner, common.get_site(site_id), f"站点 {site_id}")
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
            "next_step": "将 site.zip PUT 到 upload_url，然后调用 confirm_upload"}


def do_confirm_upload(owner: str, job_id: str) -> dict:
    job = common.get_job(job_id)
    _assert_owner(owner, job, f"任务 {job_id}")
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
    _assert_owner(owner, job, f"任务 {job_id}")
    return {k: job.get(k, "") for k in ("status", "phase", "error", "url")}


def do_list_sites(owner: str) -> list[dict]:
    import boto3.dynamodb.conditions as cond
    table = boto3.resource("dynamodb", region_name="us-east-1").Table(
        os.environ["SITES_TABLE"])
    items = table.scan(FilterExpression=cond.Attr("owner").eq(owner)).get("Items", [])
    base = os.environ["BASE_DOMAIN"]
    return [{"site_id": s["site_id"], "name": s.get("name", ""),
             "url": f"https://{s.get('subdomain', 'app-' + s['site_id'])}.{base}",
             "status": s.get("status", ""), "tier": s.get("tier", "")}
            for s in items]


def do_undeploy(owner: str, site_id: str) -> dict:
    _assert_owner(owner, common.get_site(site_id), f"站点 {site_id}")
    job_id = common.create_job(owner, site_id)
    _lambda().invoke(FunctionName="site-deployer-undeploy",
                     InvocationType="Event",
                     Payload=json.dumps({"job_id": job_id, "site_id": site_id}))
    return {"job_id": job_id}


# ---------- MCP 壳 ----------

mcp = FastMCP("site-builder-deploy", stateless_http=True)


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
                return email
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
def undeploy_site(site_id: str) -> dict:
    """下线站点（删路由/Lambda/前端；数据库数据保留）。仅站点所有者可操作。"""
    return do_undeploy(_caller_email(), site_id)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
