"""站点下线：删路由 → 删 Lambda → 删 per-site 角色 → 清前端（paginator 分批）。
DB 数据保留（PoC 防误删）。"""
import os

import boto3

import common


def _lambda():
    return boto3.client("lambda")


def _delete_prefix(s3, bucket: str, prefix: str):
    """paginator + 每批 ≤1000 对象（delete_objects 上限）。"""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        for i in range(0, len(objs), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000]})


def handler(event, context):
    site_id = event["site_id"]
    common.update_job(event["job_id"], status="RUNNING", phase="undeploy")

    boto3.client("dynamodb").delete_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": common.subdomain_for(site_id)}})

    lam = _lambda()
    try:
        lam.delete_function(FunctionName=f"site-{site_id}")
    except lam.exceptions.ResourceNotFoundException:
        pass

    iam = boto3.client("iam")
    role = f"site-rt-{site_id}"
    try:
        for pol in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=pol)
        iam.delete_role(RoleName=role)
    except iam.exceptions.NoSuchEntityException:
        pass

    _delete_prefix(boto3.client("s3"), os.environ["FRONTEND_BUCKET"],
                   f"sites/{site_id}/")

    common.upsert_site(site_id, status="DELETED")
    common.update_job(event["job_id"], status="DELETED")
    return {"job_id": event["job_id"], "status": "DELETED"}
