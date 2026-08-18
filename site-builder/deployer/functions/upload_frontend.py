"""SFN 步骤 5：前端静态文件 → 版本化前缀 sites/{site_id}/{job_id}/。
不删旧版本——线上流量仍指旧前缀，切换由 register_route 原子完成；
旧版本由 `mark_job._cleanup_old_versions` 在**成功之后**清理。

**不要再把清理说成"由前端桶的生命周期规则兜底"**：那条规则（`sites/` 前缀
30 天过期）在这个模型下是错的——线上那一份也住在 `sites/` 下、写一次之后
永不重写，于是任何 30 天没重新部署过的站点会被它删掉前端（桶未开版本控制，
删了就没了）。规则已从 DEPLOY.md 与生产桶上移除，存储上界由 mark_job 的
清理提供。"""
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
    # 前缀格式的唯一定义在 common（这里要**带**尾斜杠：它在拼 key）。
    dst_prefix = common.static_prefix_for(event["site_id"], event["job_id"]) + "/"

    paginator = s3.get_paginator("list_objects_v2")
    uploaded = 0
    for page in paginator.paginate(Bucket=src_bucket, Prefix=src_prefix):
        for obj in page.get("Contents", []):
            rel = obj["Key"][len(src_prefix):]
            body = s3.get_object(Bucket=src_bucket, Key=obj["Key"])["Body"].read()
            ctype = mimetypes.guess_type(rel)[0] or "application/octet-stream"
            s3.put_object(Bucket=dst_bucket, Key=dst_prefix + rel,
                          Body=body, ContentType=ctype)
            uploaded += 1
    # **一个对象都没上传 ⇒ fail closed**（Codex 2026-08-17 P1-5）。
    # 空前缀意味着提交之后每个非 /api 请求都 403（桶是私有的，"没这个对象"就是
    # 403 而不是 404），而这一点**没有任何下游能发现**：register_route 照样把
    # static_prefix 切过去，require_auth 站点的 smoke 只断言"302 到登录端点"、
    # 根本不碰 S3，于是这样的部署会被标成 SUCCEEDED。
    # 在提交点**之前**失败，线上零影响；提交之后才暴露的话，还要等 Edge 缓存过期。
    if not uploaded:
        raise RuntimeError(
            f"前端产物为空（{src_prefix} 下没有任何对象），拒绝提交这次部署——"
            "否则站点除 /api 之外的所有路径都会 403。请确认 site.zip 里有 "
            "frontend/ 目录且包含 index.html。")
    return event
