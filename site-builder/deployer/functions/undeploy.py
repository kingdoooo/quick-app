"""站点下线：删路由 → 删 Lambda → 删 per-site 角色 → 清前端（paginator 分批）。

数据库默认保留（防误删）；event 传 purge_data=True 时额外清理：
DynamoDB 的 site-data-{site_id}-* 表、DSQL 的 per-site schema / role / IAM 映射。
清理只能在这里做——站点运行时角色既无 DeleteTable 也无 DbConnectAdmin，
Skill 与站点代码都没有这个能力。
"""
import logging
import os

import boto3

import common

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _lambda():
    return boto3.client("lambda")


def _delete_prefix(s3, bucket: str, prefix: str):
    """paginator + 每批 ≤1000 对象（delete_objects 上限）。"""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        for i in range(0, len(objs), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000]})


def _purge_dynamodb(site_id: str, tables: list[str]) -> list[str]:
    """删除本站点声明过的 site-data-{site_id}-{name} 表。返回已删表名。

    表名由 manifest 的 database.tables 推导，不用 ListTables 枚举——
    ListTables 不支持资源级限定，给它权限等于允许列举账号内所有表，
    而执行器角色的其他 DynamoDB 权限都严格限定在 site-* 前缀内。
    """
    ddb = boto3.client("dynamodb")
    deleted = []
    for t in tables:
        name = f"site-data-{site_id}-{t}"
        try:
            ddb.delete_table(TableName=name)
            deleted.append(name)
        except ddb.exceptions.ResourceNotFoundException:
            pass
    return deleted


def _purge_dsql(site_id: str) -> str:
    """删除本站点的 DSQL schema、两个 per-site role 及其 IAM 映射。

    顺序关键：必须先 AWS IAM REVOKE 再 DROP ROLE，否则 DROP ROLE 报 2BP01
    （有对象依赖）。不做这步会在 sys.iam_pg_role_mappings 里留下指向已删 IAM
    角色的孤儿映射。
    """
    import psycopg

    endpoint = os.environ["DSQL_ENDPOINT"]
    if not endpoint:
        return "skipped: DSQL_ENDPOINT 未配置"
    schema = common.dsql_schema_for(site_id)
    token = boto3.client("dsql").generate_db_connect_admin_auth_token(Hostname=endpoint)
    conn = psycopg.connect(host=endpoint, dbname="postgres", user="admin",
                           password=token, sslmode="require", autocommit=True)
    try:
        cur = conn.cursor()
        # **精确匹配这两个角色，不要用 LIKE 前缀**。
        # dsql_schema_for 把连字符删掉（site_id.replace("-","")），所以不同
        # site_id 会产生有前缀关系的 schema 名：
        #   `aa-abc123`       → site_aaabc123
        #   `aaabc123-def456` → site_aaabc123def456
        # 用 LIKE 'site_aaabc123%' 会连后者的 _app/_mig 一起撤销——那个站点的
        # 数据还在，但运行时与迁移器失去角色映射，立刻断连、后续部署也失败。
        # site_id 的 name 段用户可控，可被刻意构造（Codex 审查 2026-08-06 P1）。
        cur.execute("SELECT arn, pg_role_name FROM sys.iam_pg_role_mappings "
                    "WHERE pg_role_name IN (%s, %s)",
                    (f"{schema}_app", f"{schema}_mig"))
        # 纵深防御：**不信任查询结果**，逐行再核一次角色名。
        # REVOKE 的 role 是字符串拼进 SQL 的（DSQL 的 AWS IAM REVOKE 不支持
        # 参数化），而"撤错角色"的后果是另一个站点静默断连——这类不可逆操作
        # 值得在执行前再确认一次目标，哪怕上面的查询已经收窄。
        expected_roles = {f"{schema}_app", f"{schema}_mig"}
        for arn, role in cur.fetchall():
            if role not in expected_roles:
                logger.error(f"跳过不属于本站点的角色映射: {role}（预期 "
                             f"{sorted(expected_roles)}）——查询条件可能被改坏")
                continue
            try:
                cur.execute(f"AWS IAM REVOKE {role} FROM '{arn}'")
            except Exception as e:
                logger.warning(f"REVOKE {role} <- {arn} 失败: {e}")
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        for role in (f"{schema}_app", f"{schema}_mig"):
            try:
                cur.execute(f"DROP ROLE IF EXISTS {role}")
            except Exception as e:
                logger.warning(f"DROP ROLE {role} 失败: {e}")
        return f"purged schema {schema} + roles"
    finally:
        conn.close()


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

    # 日志组随站点走（不属于"数据"，不受 purge_data 开关控制）：
    # 留着既是成本泄漏也把已下线站点的运行痕迹无限期保留。
    logs = boto3.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/site-{site_id}")
    except logs.exceptions.ResourceNotFoundException:
        pass

    # 数据清理默认关闭：站点下线通常只是停止对外服务，数据误删不可恢复。
    # 清理失败不改变下线结果（路由/Lambda 已删，站点确实已下线）。
    purged: dict = {}
    if event.get("purge_data"):
        site = common.get_site(site_id) or {}
        engine = (event.get("engine")
                  or ("dsql" if site.get("tier") == "fullstack-sql" else "dynamodb"))
        # 表名取自 provision_dynamodb 写入 sites 表的 data_tables；
        # 允许 event 覆盖，便于清理历史站点（该字段是本次新增的）
        tables = event.get("data_tables") or list(site.get("data_tables", []))
        try:
            purged["dynamodb"] = _purge_dynamodb(site_id, tables)
        except Exception as e:
            logger.warning(f"DynamoDB 清理失败: {e}")
            purged["dynamodb_error"] = str(e)[:200]
        if engine == "dsql":
            try:
                purged["dsql"] = _purge_dsql(site_id)
            except Exception as e:
                logger.warning(f"DSQL 清理失败: {e}")
                purged["dsql_error"] = str(e)[:200]

    common.upsert_site(site_id, status="DELETED")
    common.update_job(event["job_id"], status="DELETED")
    result = {"job_id": event["job_id"], "status": "DELETED"}
    if purged:
        result["purged"] = purged
    return result
