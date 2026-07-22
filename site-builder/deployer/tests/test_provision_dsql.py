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


def test_first_deploy_runs_schema_and_grants(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\nCREATE TABLE b (id UUID PRIMARY KEY);")
    conn, cur = _mock_conn()
    with patch.object(provision_dsql, "_connect", return_value=conn):
        out = provision_dsql.handler(_event(), None)
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    assert 'CREATE SCHEMA IF NOT EXISTS "site_expa1b2c3"' in sqls[0]
    assert sum("CREATE TABLE" in s for s in sqls) == 2
    assert any("AWS IAM GRANT site_expa1b2c3_app" in s
               and "role/site-rt-exp-a1b2c3" in s for s in sqls)  # 站点 IAM 角色映射
    assert any(s.startswith("GRANT USAGE") for s in sqls)
    assert out["env_vars"]["DSQL_SCHEMA"] == "site_expa1b2c3"
    assert out["env_vars"]["DSQL_USER"] == "site_expa1b2c3_app"
    conn.close.assert_called_once()  # try/finally 关闭


def test_statement_split_respects_semicolon_in_string(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY, note TEXT DEFAULT 'a;b');\n"
         b"-- comment; with semicolon\nCREATE TABLE b (id UUID PRIMARY KEY);")
    conn, cur = _mock_conn()
    with patch.object(provision_dsql, "_connect", return_value=conn):
        provision_dsql.handler(_event(), None)
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    creates = [s for s in sqls if "CREATE TABLE" in s]
    assert len(creates) == 2 and "'a;b'" in creates[0]  # sqlparse 不在字符串内断句


def test_redeploy_skips_schema_applies_new_migration_incrementally(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    common.upsert_site("exp-a1b2c3", migrations_applied=["schema.sql", "001_add.sql"])
    _put("job-1", "backend/schema.sql", b"CREATE TABLE a (id UUID PRIMARY KEY);")
    _put("job-1", "backend/migrations/001_add.sql", b"ALTER TABLE a ADD COLUMN x TEXT;")
    _put("job-1", "backend/migrations/002_more.sql", b"ALTER TABLE a ADD COLUMN y TEXT;")
    _put("job-1", "backend/migrations/003_fail.sql", b"ALTER TABLE a ADD COLUMN z TEXT;")
    conn, cur = _mock_conn()
    # 003 执行时抛错——验证 002 已被记录（逐文件回写）
    def _explode(sql, *a):
        if "COLUMN z" in sql:
            raise RuntimeError("boom")
    cur.execute.side_effect = _explode
    with patch.object(provision_dsql, "_connect", return_value=conn):
        import pytest as _pt
        with _pt.raises(RuntimeError):
            provision_dsql.handler(_event(), None)
    applied = common.get_site("exp-a1b2c3")["migrations_applied"]
    assert "002_more.sql" in applied and "003_fail.sql" not in applied
    conn.close.assert_called_once()
