import boto3
import re
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


# ---- M16 执行器半边：只列 migrations/ 直下层 ----

def test_migrations_in_subdirectory_are_not_executed(aws):
    """执行器列举带 Delimiter="/"，子目录里的 SQL 不再被执行。

    与校验器口径一致（校验器已在 validate 拒掉带子目录的站点）：从前执行器递归看到
    子目录、`PurePosixPath(key).name` 把 `nested/002_bad.sql` 取成 `002_bad.sql` 就跑，
    而红线扫描只看直下层 ⇒ 「执行器扫的 ⊋ 校验器扫的」，禁用 DDL 因此推迟到执行期才炸。
    """
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    _put("job-1", "backend/migrations/001_ok.sql",
         b"ALTER TABLE IF EXISTS a ADD COLUMN IF NOT EXISTS x TEXT;")
    _put("job-1", "backend/migrations/nested/002_bad.sql",
         b"ALTER TABLE IF EXISTS a ADD COLUMN IF NOT EXISTS y TEXT;")
    _, _, mig_sqls, _, _ = _run()
    applied = common.get_site("exp-a1b2c3")["migrations_applied"]
    assert applied == ["schema.sql", "001_ok.sql"], applied
    assert not any("COLUMN y" in s for s in mig_sqls), mig_sqls


# ---- 裁定 6：marker 是正确性不变量，读它必须强一致 ----

def test_marker_read_uses_consistent_read(aws, monkeypatch):
    """marker 一旦成为正确性不变量（catalog 守卫 + purge 清 marker 都依赖它），
    最终一致读会把刚关上的窗口重新打开一次：一个 marker 刚被 purge 清空的站点，
    最终一致读可能仍读到旧的非空 marker ⇒ 跳过 schema.sql ⇒ 建出空 schema。

    按行为断言（不数调用次数）：把**最终一致**读改成返回空行，强一致读走真实数据。
    若代码读的是最终一致，schema.sql 会被重跑；读强一致则跳过。
    """
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    common.upsert_site("exp-a1b2c3", migrations_applied=["schema.sql"])
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    monkeypatch.setattr(common, "get_site", lambda site_id: {})   # 陈旧的最终一致读
    admin_conn, admin_cur = _mock_conn()
    admin_cur.fetchone.return_value = (3,)      # schema 非空：catalog 守卫不该动它
    _, _, mig_sqls, _, _ = _run(admin=(admin_conn, admin_cur))
    assert not any("CREATE TABLE" in s for s in mig_sqls), (
        f"读到了陈旧的最终一致值，schema.sql 被重跑: {mig_sqls}")


# ---- M03 反例：用**真能记住状态**的 fake，而不是 mock 掉 execute ----

class _StatefulCur:
    """记得住已建对象的 fake cursor。

    merged review 对 M03 的回归要求原文：「用真能记住状态的 fake（不是 mock 掉
    execute），让第 3 条抛错，再重跑一次，断言第二次**不是** duplicate_table 失败」。
    mock 掉 execute 的用例永远看不见这个缺陷——"一个记得住第 2 条语句的数据库"
    从未被重放过。
    """

    def __init__(self, tables=None):
        self.tables = set(tables or ())
        self.executed = []
        self.fail_once = None       # 命中该子串的语句第一次执行时抛（模拟 typo/超时）
        self.table_count = None     # catalog 守卫的 SELECT count(*) 返回值
        # 包成 MagicMock 才能让 _run 的 `execute.call_args_list` 照常取到发出的 SQL，
        # 同时 side_effect 保留"记得住已建对象"这个本用例的全部价值。
        self.execute = MagicMock(side_effect=self._execute)

    def _execute(self, sql, params=None):
        self.executed.append(sql)
        norm = " ".join(sql.split())
        if self.fail_once and self.fail_once in norm:
            self.fail_once = None
            raise RuntimeError("transient boom")     # 无 sqlstate ⇒ 不是 duplicate
        m = re.match(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", norm, re.I)
        if m:
            name = m.group(1)
            if name in self.tables:
                if "IF NOT EXISTS" in norm.upper():
                    return                            # 幂等：无害
                err = type("DupTable", (Exception,), {"sqlstate": "42P07"})
                raise err(f'relation "{name}" already exists')
            self.tables.add(name)

    def fetchone(self):
        return (len(self.tables) if self.table_count is None else self.table_count,)

    def fetchall(self):
        return []


def _stateful(tables=None):
    conn = MagicMock()
    cur = _StatefulCur(tables)
    conn.cursor.return_value = cur
    return conn, cur


def test_m03_non_replayable_schema_bricks_on_retry(aws):
    """今天的失败形态：第 3 条失败 ⇒ 无 marker ⇒ 重试重跑第 1 条 ⇒ 42P07 ⇒ 永久失败。

    这是**红线 9 存在的理由**：执行层修不了它（DSQL 与 DynamoDB 无原子事务，语句级
    marker 也只能让窗口变窄），只能在合同层强制可重放形式把它拦在 validate。
    """
    import common
    import pytest
    common.create_job("a@x.com", "exp-brick")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE c (id UUID PRIMARY KEY);")
    admin1, admin_cur1 = _stateful()
    mig1_conn, mig1 = _stateful()
    mig1.fail_once = "CREATE TABLE c"
    with pytest.raises(Exception):
        _run(event=_event(job_id="job-1", site_id="exp-brick"),
             admin=(admin1, admin_cur1), mig=(mig1_conn, mig1))
    # 文件没跑完 ⇒ marker 未写；但 a、b 两条**已提交**（autocommit，无回滚）
    assert (common.get_site_consistent("exp-brick") or {}).get("migrations_applied", []) == []
    assert mig1.tables == {"a", "b"}

    # 重试 = 再调一次 deploy_site ⇒ **新 job_id、新 extracted/ 前缀**，site_id 不变，
    # migrations_applied 是按 site 存的。同一份产物重新上传到新前缀。
    _put("job-2", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE c (id UUID PRIMARY KEY);")
    admin2, admin_cur2 = _stateful(mig1.tables)
    mig2_conn, mig2 = _stateful(mig1.tables)
    admin_cur2.table_count = 2          # schema 非空，catalog 守卫不该介入
    with pytest.raises(Exception) as ei:
        _run(event=_event(job_id="job-2", site_id="exp-brick"),
             admin=(admin2, admin_cur2), mig=(mig2_conn, mig2))
    assert "42P07" in str(ei.value) or "already exists" in str(ei.value), str(ei.value)


def test_replayable_schema_recovers_on_retry(aws):
    """同样的三张表带 IF NOT EXISTS：半途失败后重试**不再**是 duplicate 失败，而是成功。"""
    import common
    import pytest
    common.create_job("a@x.com", "exp-recover")
    _put("job-3", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS c (id UUID PRIMARY KEY);")
    admin3, admin_cur3 = _stateful()
    mig3_conn, mig3 = _stateful()
    mig3.fail_once = "CREATE TABLE IF NOT EXISTS c"
    with pytest.raises(Exception):
        _run(event=_event(job_id="job-3", site_id="exp-recover"),
             admin=(admin3, admin_cur3), mig=(mig3_conn, mig3))
    assert (common.get_site_consistent("exp-recover") or {}).get("migrations_applied", []) == []

    _put("job-4", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS c (id UUID PRIMARY KEY);")
    admin4, admin_cur4 = _stateful(mig3.tables)
    mig4_conn, mig4 = _stateful(mig3.tables)
    admin_cur4.table_count = 2
    _run(event=_event(job_id="job-4", site_id="exp-recover"),
         admin=(admin4, admin_cur4), mig=(mig4_conn, mig4))       # 不抛
    assert common.get_site_consistent("exp-recover")["migrations_applied"] == ["schema.sql"]
    assert mig4.tables == {"a", "b", "c"}


# ---- 裁定 3④：富失败信息（文件名、第几条、SQLSTATE、已提交条数、补救办法）----

def test_run_file_failure_reports_file_stmt_sqlstate_and_remedy(aws):
    """失败信息必须能让人**不看日志上下文**就知道要改哪里、怎么改。

    从前抛的是 psycopg 的原始异常：只有一句 `column "z" already exists`，既不知道是
    哪个文件的第几条，也不知道前面有几条已经提交（不可回滚），更没有补救办法。
    """
    import common
    import pytest
    common.create_job("a@x.com", "exp-rich")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"
         b"ALTER TABLE a ADD COLUMN z TEXT;")
    mig_conn, mig_cur = _mock_conn()

    def _boom(sql, *a, **kw):
        if "COLUMN z" in sql:
            err = type("DupColumn", (Exception,), {"sqlstate": "42701"})
            raise err('column "z" of relation "a" already exists')
    mig_cur.execute.side_effect = _boom

    with pytest.raises(RuntimeError) as ei:
        _run(event=_event(job_id="job-1", site_id="exp-rich"), mig=(mig_conn, mig_cur))
    msg = str(ei.value)
    assert "schema.sql" in msg, msg                 # 哪个文件
    assert "第 2/2 条" in msg, msg                   # 第几条语句
    assert "42701" in msg, msg                      # SQLSTATE
    assert "1 条已提交" in msg, msg                  # 已知已提交的对象
    assert "可重放" in msg, msg                      # 补救办法
    assert "COLUMN z" in msg, msg                   # 出错的语句本体
