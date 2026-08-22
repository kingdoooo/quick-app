"""SFN 步骤 2a：按 manifest 声明创建站点 DynamoDB 表（幂等）。"""
import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="provision-db")
    ddb = boto3.client("dynamodb")
    env_vars = event.get("env_vars", {})
    for spec in event["manifest"]["database"].get("tables", []):
        table_name = common.site_table_name(event["site_id"], spec["name"])
        try:
            ddb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": spec["pk"], "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": spec["pk"], "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
                Tags=[{"Key": "project", "Value": "site-builder"},
                      {"Key": "site_id", "Value": event["site_id"]}])
            ddb.get_waiter("table_exists").wait(TableName=table_name)
        except ddb.exceptions.ResourceInUseException:
            pass
        env_vars[f"TABLE_{spec['name'].upper()}"] = table_name
    event["env_vars"] = env_vars
    # 记下已建表的逻辑名，供 undeploy --purge_data 精确删除。
    # 不能靠 ListTables 反查：该动作不支持资源级限定，授权它等于放开全账号表枚举。
    names = [s["name"] for s in event["manifest"]["database"].get("tables", [])]
    if names:
        common.upsert_site(event["site_id"], data_tables=names)
    return event
