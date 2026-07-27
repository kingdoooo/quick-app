import boto3
from unittest.mock import MagicMock, patch


def _event(job_id="job-1", site_id="exp-a1b2c3"):
    return {"job_id": job_id, "site_id": site_id,
            "manifest": {"name": "exp", "tier": "fullstack-sql",
                         "database": {"engine": "dsql"},
                         "backend": {"runtime": "nodejs22.x",
                                     "entrypoint": "node server.js", "port": 8080},
                         "auth": {"require_login": True, "allowed_users": "org"}}}


def _put(job_id, key, body):
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"extracted/{job_id}/{key}", Body=body)


def _mock_conn():
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def _run(event=None, admin=None, mig=None):
    """跑 handler，返回 (out, admin_sqls, mig_sqls, admin_conn, mig_conn)。

    admin 连接只做引导；站点提交的 SQL 必须只出现在 migrator 连接上。
    """
    import provision_dsql
    admin_conn, admin_cur = admin or _mock_conn()
    mig_conn, mig_cur = mig or _mock_conn()
    with patch.object(provision_dsql, "_connect", return_value=admin_conn), \
         patch.object(provision_dsql, "_connect_as", return_value=mig_conn), \
         patch.object(provision_dsql, "_exec_role_arn",
                      return_value="arn:aws:iam::1:role/site-deployer-exec-role"):
        out = provision_dsql.handler(event or _event(), None)
    return (out,
            [c.args[0] for c in admin_cur.execute.call_args_list],
            [c.args[0] for c in mig_cur.execute.call_args_list],
            admin_conn, mig_conn)


def test_first_deploy_bootstraps_roles_and_runs_schema_as_migrator(aws):
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\nCREATE TABLE b (id UUID PRIMARY KEY);")
    out, admin_sqls, mig_sqls, admin_conn, mig_conn = _run()

    # admin 只引导：建 schema、建两个 role、做 IAM 映射与授权
    assert 'CREATE SCHEMA IF NOT EXISTS "site_expa1b2c3"' in admin_sqls[0]
    assert any("CREATE ROLE site_expa1b2c3_app" in s for s in admin_sqls)
    assert any("CREATE ROLE site_expa1b2c3_mig" in s for s in admin_sqls)
    assert any("AWS IAM GRANT site_expa1b2c3_app" in s
               and "role/site-rt-exp-a1b2c3" in s for s in admin_sqls)
    assert any("AWS IAM GRANT site_expa1b2c3_mig" in s
               and "site-deployer-exec-role" in s for s in admin_sqls)

    # 核心隔离断言：站点提交的 DDL 绝不在 admin(DbConnectAdmin) 连接上执行
    assert not any("CREATE TABLE" in s for s in admin_sqls)
    assert sum("CREATE TABLE" in s for s in mig_sqls) == 2

    # 运行时 role 不得有 CREATE（只有 migrator 有）
    assert any("GRANT USAGE ON SCHEMA" in s and s.endswith("site_expa1b2c3_app")
               for s in admin_sqls)
    assert any("GRANT USAGE, CREATE ON SCHEMA" in s and "site_expa1b2c3_mig" in s
               for s in admin_sqls)

    assert out["env_vars"]["DSQL_SCHEMA"] == "site_expa1b2c3"
    assert out["env_vars"]["DSQL_USER"] == "site_expa1b2c3_app"  # 站点用运行时 role
    admin_conn.close.assert_called_once()
    mig_conn.close.assert_called_once()


def test_site_iam_role_exists_before_iam_grant(aws):
    """AWS IAM GRANT 要求 IAM 角色已存在（官方顺序：IAM role → DB role → GRANT）。"""
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql", b"CREATE TABLE a (id UUID PRIMARY KEY);")
    _run()
    role = boto3.client("iam").get_role(RoleName="site-rt-exp-a1b2c3")["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"].endswith(
        "policy/site-runtime-boundary")


def test_statement_split_respects_semicolon_in_string(aws):
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY, note TEXT DEFAULT 'a;b');\n"
         b"-- comment; with semicolon\nCREATE TABLE b (id UUID PRIMARY KEY);")
    _, _, mig_sqls, _, _ = _run()
    creates = [s for s in mig_sqls if "CREATE TABLE" in s]
    assert len(creates) == 2 and "'a;b'" in creates[0]  # sqlparse 不在字符串内断句


def test_redeploy_skips_schema_applies_new_migration_incrementally(aws):
    import common
    import pytest
    common.create_job("a@x.com", "exp-a1b2c3")
    common.upsert_site("exp-a1b2c3", migrations_applied=["schema.sql", "001_add.sql"])
    _put("job-1", "backend/schema.sql", b"CREATE TABLE a (id UUID PRIMARY KEY);")
    _put("job-1", "backend/migrations/001_add.sql", b"ALTER TABLE a ADD COLUMN x TEXT;")
    _put("job-1", "backend/migrations/002_more.sql", b"ALTER TABLE a ADD COLUMN y TEXT;")
    _put("job-1", "backend/migrations/003_fail.sql", b"ALTER TABLE a ADD COLUMN z TEXT;")

    mig_conn, mig_cur = _mock_conn()

    def _explode(sql, *a):  # 003 执行时抛错——验证 002 已被记录（逐文件回写）
        if "COLUMN z" in sql:
            raise RuntimeError("boom")
    mig_cur.execute.side_effect = _explode

    with pytest.raises(RuntimeError):
        _run(mig=(mig_conn, mig_cur))
    applied = common.get_site("exp-a1b2c3")["migrations_applied"]
    assert "002_more.sql" in applied and "003_fail.sql" not in applied
    mig_conn.close.assert_called_once()  # try/finally 关闭


# ---- 裸 except 收窄：只容忍"已存在"，其余必须抛 ----

def test_duplicate_object_tolerated_but_real_errors_raised():
    import provision_dsql
    import pytest

    cur = MagicMock()
    provision_dsql._exec_ignoring_duplicate(cur, "CREATE ROLE r")  # 正常路径不抛

    class DupErr(Exception):
        sqlstate = "42710"  # duplicate_object
    cur.execute.side_effect = DupErr("role already exists")
    provision_dsql._exec_ignoring_duplicate(cur, "CREATE ROLE r")  # 重复被容忍

    # AWS IAM GRANT 语法不被支持 / 权限不足：绝不能像原裸 except 那样被吞掉，
    # 否则部署报成功而站点永远连不上库、数据隔离映射根本没建立。
    for sqlstate, msg in (("42601", "syntax error at or near AWS"),
                          ("42501", "permission denied for schema")):
        err = type("E", (Exception,), {"sqlstate": sqlstate})
        cur.execute.side_effect = err(msg)
        with pytest.raises(Exception) as ei:
            provision_dsql._exec_ignoring_duplicate(cur, "AWS IAM GRANT r TO 'arn'")
        assert getattr(ei.value, "sqlstate", None) == sqlstate
