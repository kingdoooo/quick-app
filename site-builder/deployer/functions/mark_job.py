"""SFN 终态：成功/失败落账 + 站点记录维护 + 旧版本前端清理。"""
import logging
import os

import boto3

import common

logger = logging.getLogger()


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
        common.update_job(job_id, status="FAILED", error=cause)
        return {"job_id": job_id, "status": "FAILED", "error": cause}

    job = common.get_job(job_id)
    common.update_job(job_id, status="SUCCEEDED", url=event["url"])
    common.upsert_site(event["site_id"], status="ACTIVE", last_job_id=job_id,
                       owner=job["owner"], tier=event["manifest"]["tier"],
                       name=event["manifest"]["name"],
                       subdomain=common.subdomain_for(event["site_id"]))
    _cleanup_old_versions(event["site_id"], job_id)
    return {"job_id": job_id, "status": "SUCCEEDED", "url": event["url"]}
