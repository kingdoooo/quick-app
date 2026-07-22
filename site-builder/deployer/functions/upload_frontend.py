"""SFN 步骤 5：前端静态文件 → 版本化前缀 sites/{site_id}/{job_id}/。
不删旧版本——线上流量仍指旧前缀，切换由 register_route 原子完成；
旧版本由前端桶生命周期规则（30 天）清理。"""
import mimetypes
import os

import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="upload-frontend")
    s3 = boto3.client("s3")
    src_bucket = os.environ["ARTIFACTS_BUCKET"]
    dst_bucket = os.environ["FRONTEND_BUCKET"]
    src_prefix = f"extracted/{event['job_id']}/frontend/"
    dst_prefix = f"sites/{event['site_id']}/{event['job_id']}/"

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=src_bucket, Prefix=src_prefix):
        for obj in page.get("Contents", []):
            rel = obj["Key"][len(src_prefix):]
            body = s3.get_object(Bucket=src_bucket, Key=obj["Key"])["Body"].read()
            ctype = mimetypes.guess_type(rel)[0] or "application/octet-stream"
            s3.put_object(Bucket=dst_bucket, Key=dst_prefix + rel,
                          Body=body, ContentType=ctype)
    return event
