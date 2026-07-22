"""SFN 步骤 2b：共享 DSQL cluster 内为站点建独立 schema + per-site PG role 并执行 DDL。
DSQL 约束：无 CREATE DATABASE；每事务一条 DDL → 逐条 execute（autocommit）。
身份分离：本步骤用 admin（平台身份）；站点 Lambda 用 per-site role（非 admin），
只被 GRANT 自己的 schema——站点代码是不可信代码。"""
import os
import re
from pathlib import PurePosixPath

import boto3
import sqlparse

import common

# psycopg 仅在 Lambda 打包时可用；测试 mock _connect 不触达
def _connect():
    """返回 autocommit connection。执行角色需 dsql:DbConnectAdmin。"""
    import psycopg
    endpoint = os.environ["DSQL_ENDPOINT"]
    token = boto3.client("dsql", region_name="us-east-1").generate_db_connect_admin_auth_token(
        Hostname=endpoint)
    return psycopg.connect(host=endpoint, dbname="postgres", user="admin",
                           password=token, sslmode="require", autocommit=True)


def _statements(sql: str) -> list[str]:
    # sqlparse.split 会把前导注释附着在下一条语句上，用 strip_comments 剥离
    # （裸 startswith("--") 过滤会误删整条语句）
    stmts = (sqlparse.format(s, strip_comments=True).strip()
             for s in sqlparse.split(sql))
    return [s for s in stmts if s]


def handler(event, context):
    common.update_job(event["job_id"], phase="provision-db")
    site_id, job_id = event["site_id"], event["job_id"]
    schema = common.dsql_schema_for(site_id)
    pg_role = f"{schema}_app"
    rt_role_arn = (f"arn:aws:iam::{os.environ['ACCOUNT_ID']}:role/site-rt-{site_id}")
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    site = common.get_site(site_id) or {}
    applied = list(site.get("migrations_applied", []))

    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        cur.execute(f'SET search_path = "{schema}"')

        # per-site PG role + IAM 映射（幂等：已存在则容忍）
        try:
            cur.execute(f'CREATE ROLE {pg_role} WITH LOGIN')
        except Exception:
            pass  # duplicate role
        try:
            cur.execute(f"AWS IAM GRANT {pg_role} TO '{rt_role_arn}'")
        except Exception:
            pass  # 已映射
        cur.execute(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO {pg_role}')
        cur.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" '
                    f'GRANT ALL ON TABLES TO {pg_role}')

        def run_file(key: str, marker: str):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
            for stmt in _statements(body):
                cur.execute(stmt)
            applied.append(marker)
            common.upsert_site(site_id, migrations_applied=applied)  # 逐文件立即记录

        if "schema.sql" not in applied:
            run_file(f"extracted/{job_id}/backend/schema.sql", "schema.sql")

        resp = s3.list_objects_v2(Bucket=bucket,
                                  Prefix=f"extracted/{job_id}/backend/migrations/")
        for obj in sorted(resp.get("Contents", []), key=lambda o: o["Key"]):
            fname = PurePosixPath(obj["Key"]).name
            if re.match(r"^\d{3}_.+\.sql$", fname) and fname not in applied:
                run_file(obj["Key"], fname)

        # 覆盖 schema.sql/migrations 新建的表（DEFAULT PRIVILEGES 只对未来生效一次性补齐）
        cur.execute(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema}" TO {pg_role}')
    finally:
        conn.close()

    env_vars = event.get("env_vars", {})
    env_vars["DSQL_ENDPOINT"] = os.environ["DSQL_ENDPOINT"]
    env_vars["DSQL_SCHEMA"] = schema
    env_vars["DSQL_USER"] = pg_role
    event["env_vars"] = env_vars
    return event
