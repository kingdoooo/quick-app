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
import ops_log

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

    # **强一致读**：marker 是正确性不变量（下面的 catalog 守卫与 undeploy 的 purge
    # 都按它判断"这个文件跑过没有"）。最终一致读会把那些窗口重新打开一次——一个
    # marker 刚被 purge 清空的站点可能仍读到旧的非空值 ⇒ 跳过 schema.sql ⇒ 空 schema。
    site = common.get_site_consistent(site_id) or {}
    applied = list(site.get("migrations_applied", []))

    # AWS IAM GRANT 要求 IAM 角色已存在（官方流程：IAM role → DB role → GRANT）
    common.ensure_site_role(site_id, "dsql", tables=[])

    # 阶段一：admin 身份只做引导——建 schema、建两个 per-site role、授权。
    # 不在此连接上执行任何站点提交的 SQL。
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')  # nosemgrep: sqlalchemy-execute-raw-query —— 标识符来自已校验的 site_id；DSQL 的 DDL 与 AWS IAM GRANT/REVOKE 不能参数化

        # ---- catalog 守卫：marker 非空却查到 schema 是空的 = **已证明的失配** ----
        # undeploy 的 purge 路径只覆盖 5 条让 marker 失效的路径里的 1 条，另外 4 条是：
        #   ① DEPLOY.md 自己教的孤儿清理 `DROP SCHEMA "site_xxx" CASCADE`（预期会被用）；
        #   ② DSQL cluster 重建 / endpoint 重指——sites 行里**不记任何 DSQL 身份**，
        #      换 cluster 会让每个 fullstack-sql 站点的 marker 一次性全部失效，无人察觉；
        #   ③ 站点自己的 SQL `DROP TABLE`；④ purge 时 tier 未知会跳过 DSQL 清理。
        # 失配的后果是**静默**的：跳过 schema.sql ⇒ 站点起来但一张表都没有。
        #
        # **自愈而不是 fail closed**：判据是"schema 已证明为空"，空 schema 上重跑不可能
        # 覆盖数据；而 fail closed 会把一个可自动修复的状态变成人工工单，且手册自己教的
        # 手工 DROP SCHEMA 之后必然撞上它。审计行让「平台替你重跑了建库 SQL」留痕。
        #
        # **效力边界**：schema 空 + marker 非空 = 已证明的失配；schema **非空**则什么都
        # 证明不了（不告诉你哪些文件跑过），此时不动。
        # **查 `pg_tables` 而不是 `information_schema.tables`**：后者按 PostgreSQL 的定义
        # 是**按权限过滤**的（只列"当前用户有权访问的表"），而站点的表是 `{schema}_mig`
        # 建的、这里用的是 admin 连接，且 DSQL 的 admin 是引导角色而非 superuser ⇒ 很可能
        # 一张都看不见 ⇒ count=0 ⇒ **每次重部都误判成失配**。`pg_tables` 走 pg_class +
        # pg_namespace、不按权限过滤，且 DSQL 的系统表文档明确列它为支持
        # （`information_schema` 不在那份清单里）。SELECT 不受"一事务一条 DDL"约束，可参数化。
        #
        # **失败方向是刻意的：查不出来就什么都不做。** 这个守卫的前提（admin 能看见
        # mig role 建的表）在真机上没有验证过。前提若不成立：把"查不出来"当成"空"会在
        # 每次重部清掉 marker 并重跑全部迁移；让异常冒出去会让每一个存量 fullstack-sql
        # 站点的重部直接失败。两者都比"守卫不生效"糟糕得多——它是**加固**，不是部署的
        # 必要条件，所以只在**读到了一个确定为 0 的计数**时才动手。
        if applied:
            table_count = None
            try:
                cur.execute("SELECT count(*) FROM pg_tables WHERE schemaname = %s",
                            (schema,))
                row = cur.fetchone()
                if row and isinstance(row[0], int) and not isinstance(row[0], bool):
                    table_count = row[0]
                else:
                    logger.warning("catalog 守卫：读回的计数不可用（%r），跳过", row)
            except Exception as e:
                # 不 re-raise、也不当成空：见上面那段的失败方向说明
                logger.warning("catalog 守卫：pg_tables 查询失败，跳过本次检查: %s", e)
            if table_count == 0:
                stale = list(applied)
                applied = []
                common.upsert_site(site_id, migrations_applied=applied)
                job = common.get_job(job_id) or {}
                ops_log.record(actor=job.get("owner", ""),
                               action="dsql-marker-self-heal",
                               target=f"site:{site_id}", result="ok",
                               detail={"schema": schema, "cleared_marker": stale,
                                       "reason": "schema 已证明为空而已应用标记非空——"
                                                 "重置标记以重跑建库 SQL"})
                logger.warning("catalog 守卫自愈 site=%s schema=%s 清空 marker=%s",
                               site_id, schema, stale)

        # runtime role（站点 Lambda 用，无 CREATE）与 migrator role（跑 DDL，仅本 schema）
        for role in (pg_role, mig_role):
            _exec_ignoring_duplicate(cur, f'CREATE ROLE {role} WITH LOGIN')
        _exec_ignoring_duplicate(
            cur, f"AWS IAM GRANT {pg_role} TO '{rt_role_arn}'")
        _exec_ignoring_duplicate(
            cur, f"AWS IAM GRANT {mig_role} TO '{exec_role_arn}'")

        # 站点运行时：只用不建；migrator：可建对象但仅限本 schema
        cur.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO {pg_role}')  # nosemgrep: sqlalchemy-execute-raw-query —— 标识符来自已校验的 site_id；DSQL 的 DDL 与 AWS IAM GRANT/REVOKE 不能参数化
        cur.execute(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO {mig_role}')  # nosemgrep: sqlalchemy-execute-raw-query —— 标识符来自已校验的 site_id；DSQL 的 DDL 与 AWS IAM GRANT/REVOKE 不能参数化
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
        cur.execute(f'SET search_path = "{schema}"')  # nosemgrep: sqlalchemy-execute-raw-query —— 标识符来自已校验的 site_id；DSQL 的 DDL 与 AWS IAM GRANT/REVOKE 不能参数化

        def run_file(key: str, marker: str):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
            stmts = _statements(body)
            for idx, stmt in enumerate(stmts, start=1):
                try:
                    cur.execute(stmt)
                except Exception as e:
                    # 富失败信息（M03 处方第 4 条）：文件名、第几条语句、SQLSTATE、
                    # **已知已提交的条数**，并直接给出补救办法。原来抛的是 psycopg
                    # 的原始异常，只有一句 "column already exists"——看不出是哪个
                    # 文件的第几条，也看不出前面几条已经不可回滚地提交了。
                    sqlstate = getattr(e, "sqlstate", None) or getattr(e, "pgcode", None)
                    # **先说能行动的，再说解释性的**：这条消息唯一到得了用户眼前的
                    # 通道是 job.error，而 mark_job 会把 SFN 的 Cause（一个 JSON 信封）
                    # 截到 500 字符 ⇒ 排在后面的补救办法与出错语句会被切掉。
                    # 措辞对**两种**失败都成立：不可重放的语句，以及瞬时错误
                    # （超时 / OCC 中止 / 连接重置）——后者的 SQL 可能本来就是合规的，
                    # 断言"你的 SQL 不可重放"是错的建议。原异常挂在 __cause__ 上，
                    # sqlstate 仍可被程序取到。
                    raise RuntimeError(
                        f"{marker} 第 {idx}/{len(stmts)} 条失败"
                        f"（SQLSTATE={sqlstate}）：{stmt[:120]}"
                        f" ← {str(e)[:160]}"
                        f"｜本文件前 {idx - 1} 条已提交且不可回滚（每条语句 autocommit），"
                        f"标记未写入 ⇒ 下次部署整文件重跑。"
                        f"若该语句不是可重放形态，改成 IF NOT EXISTS / "
                        f"ON CONFLICT DO NOTHING 之类（合同层红线 9 会在 validate 拦它）；"
                        f"若是瞬时错误（超时/冲突），直接重新部署即可。"
                    ) from e
            applied.append(marker)
            common.upsert_site(site_id, migrations_applied=applied)  # 逐文件立即记录

        if "schema.sql" not in applied:
            run_file(f"extracted/{job_id}/backend/schema.sql", "schema.sql")

        # Delimiter="/"：只列 migrations/ **直下层**，子目录落进 CommonPrefixes 被忽略。
        # 与校验器 `_dsql_sql_files` 的非递归 glob 口径一致（校验器已在 validate 拒掉
        # 带子目录的站点）。从前递归列举 + 取 basename ⇒ 子目录里的 SQL 会被执行却
        # 不被红线扫描（M16），而那正是禁用 DDL 推迟到执行期才炸的成因。
        # paginator：单次 list_objects_v2 只回 1000 条且**静默截断**，迁移文件多了会漏跑。
        paginator = s3.get_paginator("list_objects_v2")
        objs = []
        for page in paginator.paginate(
                Bucket=bucket,
                Prefix=f"extracted/{job_id}/backend/migrations/",
                Delimiter="/"):
            objs.extend(page.get("Contents", []))
        for obj in sorted(objs, key=lambda o: o["Key"]):
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
