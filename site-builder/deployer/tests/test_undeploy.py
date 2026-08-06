import boto3
from unittest.mock import MagicMock, patch


def test_undeploy_cleans_route_frontend_lambda(aws):
    import undeploy, common
    jid = common.create_job("a@x.com", "hello-x1")
    common.upsert_site("hello-x1", owner="a@x.com", status="ACTIVE")
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-hello-x1"}, "site_id": {"S": "hello-x1"},
        "static_prefix": {"S": "sites/hello-x1"}, "api_target": {"S": ""},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "a@x.com"}})
    boto3.client("s3").put_object(Bucket="site-frontend-1",
                                  Key="sites/hello-x1/index.html", Body=b"x")
    lam = MagicMock()
    lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
    with patch.object(undeploy, "_lambda", return_value=lam):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert "Item" not in ddb.get_item(TableName="routing",
                                      Key={"subdomain": {"S": "app-hello-x1"}})
    assert boto3.client("s3").list_objects_v2(
        Bucket="site-frontend-1", Prefix="sites/hello-x1/")["KeyCount"] == 0
    lam.delete_function.assert_called_once_with(FunctionName="site-hello-x1")
    assert common.get_site("hello-x1")["status"] == "DELETED"


def _seed(common, boto3_, site_id="hello-x1", tier="fullstack-nosql"):
    jid = common.create_job("a@x.com", site_id)
    common.upsert_site(site_id, owner="a@x.com", status="ACTIVE", tier=tier)
    return jid


def _lam_mock():
    lam = MagicMock()
    lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
    return lam


def test_data_preserved_by_default(aws):
    """默认不删数据——误删不可恢复，必须显式 opt-in。"""
    import undeploy, common
    ddb = boto3.client("dynamodb")
    ddb.create_table(TableName="site-data-hello-x1-notes",
                     KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                     BillingMode="PAY_PER_REQUEST")
    jid = _seed(common, boto3)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert "purged" not in out
    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"]


def test_purge_data_deletes_only_this_site_tables(aws):
    """purge_data=True 删本站点表，不得碰其他站点的。"""
    import undeploy, common
    ddb = boto3.client("dynamodb")
    for t in ("site-data-hello-x1-notes", "site-data-other-x2-notes"):
        ddb.create_table(TableName=t,
                         KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
    jid = _seed(common, boto3)
    common.upsert_site("hello-x1", data_tables=["notes"])
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)
    names = ddb.list_tables()["TableNames"]
    assert "site-data-hello-x1-notes" not in names
    assert "site-data-other-x2-notes" in names      # 跨站点隔离
    assert out["purged"]["dynamodb"] == ["site-data-hello-x1-notes"]


def test_purge_dsql_revokes_before_drop_role(aws):
    """DSQL 清理顺序：REVOKE 必须早于 DROP ROLE，否则 DROP ROLE 报 2BP01。"""
    import undeploy, common
    jid = _seed(common, boto3, site_id="exp-a1", tier="fullstack-sql")
    conn, cur = MagicMock(), MagicMock()
    conn.cursor.return_value = cur
    cur.fetchall.return_value = [
        ("arn:aws:iam::1:role/site-rt-exp-a1", "site_expa1_app"),
        ("arn:aws:iam::1:role/site-deployer-exec-role", "site_expa1_mig"),
    ]
    # psycopg 只在 Lambda 打包时存在，测试环境注入假模块
    import sys, types
    fake = types.ModuleType("psycopg")
    fake.connect = lambda **kw: conn
    with patch.dict(sys.modules, {"psycopg": fake}), \
         patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy.boto3, "client") as bc:
        bc.return_value.generate_db_connect_admin_auth_token.return_value = "tok"
        undeploy._purge_dsql("exp-a1")
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    revokes = [i for i, s in enumerate(sqls) if "AWS IAM REVOKE" in s]
    drops = [i for i, s in enumerate(sqls) if s.startswith("DROP ROLE")]
    assert revokes and drops, sqls
    assert max(revokes) < min(drops), f"REVOKE 必须早于 DROP ROLE: {sqls}"
    assert any('DROP SCHEMA IF EXISTS "site_expa1" CASCADE' in s for s in sqls)


def test_purge_dsql_selects_roles_exactly_not_by_prefix(aws):
    """撤销必须**精确匹配**本站点的两个角色，不能用 LIKE 前缀。

    Codex 审查 2026-08-06 P1，已复现可达路径：dsql_schema_for 把连字符删掉
    （`site_id.replace("-","")`），于是不同 site_id 会产生有前缀关系的 schema 名：
        站点 A `aa-abc123`        → schema `site_aaabc123`
        站点 B `aaabc123-def456`  → schema `site_aaabc123def456`
    A 下线时 `LIKE 'site_aaabc123%'` 会命中 B 的 `_app` / `_mig` 角色并对它们
    执行 AWS IAM REVOKE —— B 的数据还在，但运行时与迁移器失去数据库角色映射，
    现有站点开始连接失败、后续部署也失败。site_id 的 name 段用户可控，
    所以这甚至可能被刻意构造。
    """
    import undeploy, common
    _seed(common, boto3, site_id="aa-abc123", tier="fullstack-sql")
    conn, cur = MagicMock(), MagicMock()
    conn.cursor.return_value = cur
    # 模拟表里同时存在 A 与 B 的映射（B 的名字带 A 的前缀）
    cur.fetchall.return_value = [
        ("arn:aws:iam::1:role/site-rt-aa-abc123", "site_aaabc123_app"),
        ("arn:aws:iam::1:role/site-deployer-exec-role", "site_aaabc123_mig"),
        ("arn:aws:iam::1:role/site-rt-aaabc123-def456", "site_aaabc123def456_app"),
        ("arn:aws:iam::1:role/site-deployer-exec-role", "site_aaabc123def456_mig"),
    ]
    import sys, types
    fake = types.ModuleType("psycopg")
    fake.connect = lambda **kw: conn
    with patch.dict(sys.modules, {"psycopg": fake}), \
         patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy.boto3, "client") as bc:
        bc.return_value.generate_db_connect_admin_auth_token.return_value = "tok"
        undeploy._purge_dsql("aa-abc123")

    sqls = [c.args[0] for c in cur.execute.call_args_list]
    # ① 查询本身不能用 LIKE 前缀（那样连别站点的行都会取回来）
    selects = [s for s in sqls if "iam_pg_role_mappings" in s]
    assert selects, sqls
    assert not any("LIKE" in s.upper() for s in selects), \
        f"仍在用 LIKE 前缀选角色，会命中同前缀的其他站点: {selects}"
    # ② 无论查询怎么写，绝不能对别站点的角色发 REVOKE
    revokes = [s for s in sqls if "AWS IAM REVOKE" in s]
    assert not any("def456" in s for s in revokes), \
        f"撤销了另一个站点的角色映射: {revokes}"
    # ③ 本站点的两个角色仍要被撤销（别改成什么都不撤）
    assert any("site_aaabc123_app" in s for s in revokes), revokes
    assert any("site_aaabc123_mig" in s for s in revokes), revokes


def test_purge_failure_does_not_fail_undeploy(aws):
    """清理失败不改变下线结果——路由/Lambda 已删，站点确实已下线。"""
    import undeploy, common
    jid = _seed(common, boto3)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dynamodb", side_effect=RuntimeError("boom")):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)
    assert out["status"] == "DELETED"
    assert "boom" in out["purged"]["dynamodb_error"]
