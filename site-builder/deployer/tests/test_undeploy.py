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
