"""deployer 各步骤 Lambda 的公共层：配置、jobs/sites 表访问、ID 生成。"""
import os
import secrets
import string
from datetime import datetime, timezone

import boto3

_ddb = None


def _table(name_env: str):
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_DEFAULT_REGION",
                                                                     "us-east-1"))
    return _ddb.Table(os.environ[name_env])


def get_config() -> dict:
    keys = ["JOBS_TABLE", "SITES_TABLE", "ARTIFACTS_BUCKET", "FRONTEND_BUCKET",
            "ROUTING_TABLE", "BASE_DOMAIN", "RUNTIME_BOUNDARY_ARN", "PACKAGE_PROJECT",
            "DSQL_ENDPOINT"]
    return {k.lower(): os.environ[k] for k in keys}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_job(owner: str, site_id: str) -> str:
    job_id = "job-" + secrets.token_hex(8)
    _table("JOBS_TABLE").put_item(Item={
        "job_id": job_id, "site_id": site_id, "owner": owner,
        "status": "PENDING", "phase": "submitted", "error": "", "url": "",
        "created_at": _now(), "updated_at": _now()})
    return job_id


def update_job(job_id: str, *, status=None, phase=None, error=None, url=None) -> None:
    updates, values = ["updated_at = :t"], {":t": _now()}
    names = {}
    for field, val in (("status", status), ("phase", phase), ("error", error), ("url", url)):
        if val is not None:
            names[f"#{field}"] = field
            updates.append(f"#{field} = :{field}")
            values[f":{field}"] = val
    _table("JOBS_TABLE").update_item(
        Key={"job_id": job_id},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeNames=names or None,
        ExpressionAttributeValues=values)


def get_job(job_id: str) -> dict | None:
    return _table("JOBS_TABLE").get_item(Key={"job_id": job_id}).get("Item")


def list_jobs_by_owner(owner: str) -> list[dict]:
    resp = _table("JOBS_TABLE").query(
        IndexName="owner-index",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("owner").eq(owner))
    return resp.get("Items", [])


def upsert_site(site_id: str, **attrs) -> None:
    if not attrs:
        return
    names = {f"#{k}": k for k in attrs}
    _table("SITES_TABLE").update_item(
        Key={"site_id": site_id},
        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in attrs),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={f":{k}": v for k, v in attrs.items()})


def get_site(site_id: str) -> dict | None:
    return _table("SITES_TABLE").get_item(Key={"site_id": site_id}).get("Item")


def new_site_id(name: str) -> str:
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{name[:20].rstrip('-')}-{suffix}"


def subdomain_for(site_id: str) -> str:
    return f"app-{site_id}"


def dsql_schema_for(site_id: str) -> str:
    return "site_" + site_id.replace("-", "")
