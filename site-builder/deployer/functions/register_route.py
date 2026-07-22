"""SFN 步骤 6：注册子域名路由（含 auth 策略与 owner）。
put_item 覆盖整个 item = 原子切流：static_prefix 指向本次 job 的版本化前缀，
写入瞬间所有新请求走新版本（Edge 路由缓存最多再滞后 60s）。"""
import json
import os

import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="register-route")
    site = common.get_site(event["site_id"]) or {}
    owner = site.get("owner") or common.get_job(event["job_id"])["owner"]
    auth = event["manifest"]["auth"]
    allowed = auth["allowed_users"]
    subdomain = common.subdomain_for(event["site_id"])

    boto3.client("dynamodb").put_item(
        TableName=os.environ["ROUTING_TABLE"],
        Item={"subdomain": {"S": subdomain},
              "site_id": {"S": event["site_id"]},
              "route_mode": {"S": "split"},
              "static_prefix": {"S": f"sites/{event['site_id']}/{event['job_id']}"},
              "api_target": {"S": event.get("api_target", "")},
              "require_auth": {"BOOL": bool(auth["require_login"])},
              "allowed_users": {"S": allowed if allowed == "org" else json.dumps(allowed)},
              "owner": {"S": owner}})
    event["url"] = f"https://{subdomain}.{os.environ['BASE_DOMAIN']}"
    return event
