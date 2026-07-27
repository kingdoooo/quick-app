"""SFN 步骤 2b：共享 DSQL cluster 内为站点建独立 schema + per-site PG role 并执行 DDL。
DSQL 约束：无 CREATE DATABASE；每事务一条 DDL → 逐条 execute（autocommit）。
身份分离：本步骤用 admin（平台身份）；站点 Lambda 用 per-site role（非 admin），
只被 GRANT 自己的 schema——站点代码是不可信代码。"""
import logging
import os
import re
from pathlib import PurePosixPath

import boto3
import sqlparse

import common

logger = logging.getLogger()

# psycopg 仅在 Lambda 打包时可用；测试 mock _connect 不触达
def _connect():
    """admin 连接（仅用于引导 schema/role）。执行角色需 dsql:DbConnectAdmin。"""
    import psycopg
    endpoint = os.environ["DSQL_ENDPOINT"]
    token = boto3.client("dsql", region_name="us-east-1").generate_db_connect_admin_auth_token(
        Hostname=endpoint)
    return psycopg.connect(host=endpoint, dbname="postgres", user="admin",
                           password=token, sslmode="require", autocommit=True)


def _connect_as(pg_role: str):
    """以非 admin 的 per-site role 连接——站点提交的 SQL 只在此连接上执行。

    用普通 DbConnect token（非 admin），身份即该 PG role，权限只有本站点 schema。
    """
    import psycopg
    endpoint = os.environ["DSQL_ENDPOINT"]
    token = boto3.client("dsql", region_name="us-east-1").generate_db_connect_auth_token(
        Hostname=endpoint)
    return psycopg.connect(host=endpoint, dbname="postgres", user=pg_role,
                           password=token, sslmode="require", autocommit=True)


# PostgreSQL SQLSTATE：42710 duplicate_object、42P06 duplicate_schema
_DUPLICATE_SQLSTATES = {"42710", "42P06"}


def _exec_ignoring_duplicate(cur, sql: str) -> None:
    """只容忍"对象已存在"，其余错误必须抛出。

    原实现用裸 except: pass —— AWS IAM GRANT 语法错误或权限不足会被静默吞掉，
    结果是部署报成功而站点永远连不上库，且数据隔离映射根本没建立。
    """
    try:
        cur.execute(sql)
    except Exception as e:
        sqlstate = getattr(e, "sqlstate", None) or getattr(e, "pgcode", None)
        if sqlstate in _DUPLICATE_SQLSTATES:
            return
        # DSQL 对 AWS IAM GRANT 重复映射的报错未在真实环境验证过 sqlstate，
        # 按消息兜底识别；其余一律抛出。
        msg = str(e).lower()
        if "already exists" in msg or "already granted" in msg:
            return
        raise


def _exec_best_effort(cur, sql: str) -> None:
    """执行纯优化性语句：失败只记日志。仅用于有显式兜底的语句。"""
    try:
        cur.execute(sql)
    except Exception as e:
        logger.warning(f"可选语句失败（已有兜底，不影响正确性）: {sql!r} -> {e}")


def _exec_role_arn() -> str:
    """本执行器 Lambda 自身的角色 ARN——migrator PG role 映射到它。

    sts:GetCallerIdentity 返回的是 assumed-role ARN，需还原成 role ARN 形态。
    """
    arn = boto3.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/")[1].split("/")[0]
        acct = arn.split(":")[4]
        return f"arn:aws:iam::{acct}:role/{role_name}"
    return arn


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
    pg_role = f"{schema}_app"      # 站点运行时身份（只读写本 schema 的表）
    mig_role = f"{schema}_mig"     # 迁移身份（可在本 schema 建对象，不能碰其他 schema）
    rt_role_arn = common.site_role_arn(site_id)
    exec_role_arn = _exec_role_arn()
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    site = common.get_site(site_id) or {}
    applied = list(site.get("migrations_applied", []))

    # AWS IAM GRANT 要求 IAM 角色已存在（官方流程：IAM role → DB role → GRANT）
    common.ensure_site_role(site_id, "dsql")

    # 阶段一：admin 身份只做引导——建 schema、建两个 per-site role、授权。
    # 不在此连接上执行任何站点提交的 SQL。
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')

        # runtime role（站点 Lambda 用，无 CREATE）与 migrator role（跑 DDL，仅本 schema）
        for role in (pg_role, mig_role):
            _exec_ignoring_duplicate(cur, f'CREATE ROLE {role} WITH LOGIN')
        _exec_ignoring_duplicate(
            cur, f"AWS IAM GRANT {pg_role} TO '{rt_role_arn}'")
        _exec_ignoring_duplicate(
            cur, f"AWS IAM GRANT {mig_role} TO '{exec_role_arn}'")

        # 站点运行时：只用不建；migrator：可建对象但仅限本 schema
        cur.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO {pg_role}')
        cur.execute(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO {mig_role}')
        # migrator 新建的表自动授权给运行时 role。纯优化：DSQL 2026-04 起支持
        # ALTER DEFAULT PRIVILEGES，但 FOR ROLE 需调用者是该 role 成员，可能被拒。
        # 失败无损——每轮建库结尾都会对全部已存在表显式 GRANT（见阶段二末尾）。
        _exec_best_effort(cur, f'ALTER DEFAULT PRIVILEGES FOR ROLE {mig_role} '
                               f'IN SCHEMA "{schema}" GRANT SELECT, INSERT, UPDATE, '
                               f'DELETE ON TABLES TO {pg_role}')
    finally:
        conn.close()

    # 阶段二：站点提交的 SQL 以 migrator 身份执行——它对其他站点 schema 无任何权限，
    # 也不能建角色/改 IAM 映射。即使 schema.sql 含 DROP SCHEMA site_other CASCADE
    # 或 GRANT ... TO 自己，也会因权限不足失败而非成功越权。
    mig_conn = _connect_as(mig_role)
    try:
        cur = mig_conn.cursor()
        cur.execute(f'SET search_path = "{schema}"')

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

        # 补齐已存在表的授权（DEFAULT PRIVILEGES 只作用于此后新建的表）
        cur.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES '
                    f'IN SCHEMA "{schema}" TO {pg_role}')
    finally:
        mig_conn.close()

    env_vars = event.get("env_vars", {})
    env_vars["DSQL_ENDPOINT"] = os.environ["DSQL_ENDPOINT"]
    env_vars["DSQL_SCHEMA"] = schema
    env_vars["DSQL_USER"] = pg_role
    event["env_vars"] = env_vars
    return event
