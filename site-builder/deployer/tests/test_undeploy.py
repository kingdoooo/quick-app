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


def _make_site_table(ddb, name: str, site_id: str, *, tags: bool = True):
    """按 provision_dynamodb 的真实形态建一张站点数据表（**含 tag**）。

    夹具从前不打 tag，而 `provision_dynamodb` 建表时一直是打的
    （`project` + `site_id`）。归属核验开始回读 tag 之后，不打 tag 的夹具会让
    自家表被判成"归属未确认"——那是夹具与生产不一致，不是被测行为变了。
    `tags=False` 用来**故意**造出无 tag 的表，验证 fail-closed。
    """
    kw = dict(TableName=name,
              KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
              AttributeDefinitions=[{"AttributeName": "id",
                                     "AttributeType": "S"}],
              BillingMode="PAY_PER_REQUEST")
    if tags:
        kw["Tags"] = [{"Key": "project", "Value": "site-builder"},
                      {"Key": "site_id", "Value": site_id}]
    ddb.create_table(**kw)


def test_data_preserved_by_default(aws):
    """默认不删数据——误删不可恢复，必须显式 opt-in。"""
    import undeploy, common
    ddb = boto3.client("dynamodb")
    _make_site_table(ddb, "site-data-hello-x1-notes", "hello-x1")
    jid = _seed(common, boto3)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert "purged" not in out
    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"]


def test_purge_data_deletes_only_this_site_tables(aws):
    """purge_data=True 删本站点表，不得碰其他站点的。"""
    import undeploy, common
    ddb = boto3.client("dynamodb")
    _make_site_table(ddb, "site-data-hello-x1-notes", "hello-x1")
    _make_site_table(ddb, "site-data-other-x2-notes", "other-x2")
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


def test_purge_failure_keeps_site_deleted_but_job_reports_purge_failed(aws):
    """站点确实已下线（路由/Lambda 已删），但**数据没清掉不能报成功**。

    改自旧的 `test_purge_failure_does_not_fail_undeploy`（Codex 审查
    2026-08-10 P1-3）：那条把"purge 失败仍写 DELETED"当成正确契约锁住了。
    "站点已下线"与"数据已清除"是两件事，必须分别汇报——undeploy 是异步调用，
    返回值里的 dynamodb_error 没人看得到，用户在控制台看到的是"删除成功"。

    job 用 PURGE_FAILED 而不是 FAILED：站点真的下线了，报 FAILED 会让前端
    显示"下线失败"，那是另一个方向的谎。
    """
    import undeploy, common
    jid = _seed(common, boto3)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dynamodb", side_effect=RuntimeError("boom")):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)
    # 站点侧：确实已下线
    assert common.get_site("hello-x1")["status"] == "DELETED"
    # 任务侧：必须能看出"数据没清干净"
    job = common.get_job(jid)
    assert job["status"] == "PURGE_FAILED", job
    assert "boom" in out["purged"]["dynamodb_error"]
    # 错误摘要要落到 job 上（异步调用的返回值用户看不到）
    assert job.get("error"), "purge 失败摘要没写进 job，用户无从得知"
    assert "dynamodb" in job["error"].lower(), job["error"]


def test_purge_success_reports_deleted(aws):
    """别把上面那条写成"purge 一律 PURGE_FAILED"——全成功仍要是 DELETED。"""
    import undeploy, common
    jid = _seed(common, boto3, tier="fullstack-nosql")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                          "purge_data": True}, None)
    assert common.get_job(jid)["status"] == "DELETED"


def test_dsql_purge_failure_also_reports_purge_failed(aws):
    """DSQL 侧失败同样不得报成功（两条清理路径都要覆盖）。"""
    import undeploy, common
    jid = _seed(common, boto3, tier="fullstack-sql")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dsql", side_effect=RuntimeError("pgboom")):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                          "purge_data": True}, None)
    job = common.get_job(jid)
    assert job["status"] == "PURGE_FAILED", job
    assert "dsql" in job["error"].lower(), job["error"]


def test_unknown_tier_skips_dsql_purge_instead_of_failing_the_undeploy(aws):
    """tier 认不出来时：**跳过** DSQL 清理，不许把整次下线打成 FAILED。

    `common.tier_engine` 抛错是对的（不许猜——猜成 dynamodb 会让 backfill 丢掉
    `dsql:DbConnect`），但这个抛错必须在**调用点**接住：走到这一段时路由
    （:142）、Lambda（:146）、per-site 角色（:152）、日志组都已经删了，站点
    **确实已经完全下线**。让 ValueError 冒到 handler 的顶层 try 就会写
    `job=FAILED, error="下线中途失败，站点可能处于部分删除状态"` 并重抛去触发
    OnFailure 告警——为一次**可选**的数据清理没能定型，把一个干净成功的下线
    报成"可能部分删除"。本段开头的注释写的正是相反的契约：
    「清理失败不改变下线结果」，两个 sibling（dynamodb / dsql 清理）都各自
    try/except 守住了它。

    汇报口径跟 sibling 一致（`test_purge_failure_keeps_site_deleted_but_job_reports_purge_failed`）：
    站点 DELETED，job 报 PURGE_FAILED 且摘要落到 `job.error`。**不能报 DELETED**
    ——DSQL 清理被跳过了，如果它本来是个 DSQL 站点，数据还在，而用户刚勾的是
    "永久删除数据"；异步调用的返回值（`out["purged"]`）没有任何人看得到。
    """
    import undeploy, common
    jid = _seed(common, boto3, site_id="odd-x9", tier="fullstack-graph")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dsql") as purge_dsql:
        out = undeploy.handler({"job_id": jid, "site_id": "odd-x9",
                                "purge_data": True}, None)
    # 跳过，而不是猜一个 engine 然后照着清
    purge_dsql.assert_not_called()
    # 站点侧：下线本身完整成功
    assert common.get_site("odd-x9")["status"] == "DELETED"
    job = common.get_job(jid)
    assert job["status"] != "FAILED", (
        f"未知 tier 把整次下线打成了 FAILED：{job.get('error')}")
    assert job["status"] == "PURGE_FAILED", job
    # 异常必须留痕：只落在返回值里等于没落（异步调用没人读返回值）
    msg = out["purged"]["engine_unknown_error"]
    assert "无法判定数据引擎" in msg, msg
    assert "未尝试 DSQL 清理" in msg, msg
    # **只说知道的事**：判不出引擎 ⇒ 有没有残留数据我们不知道，不许断言"数据还在"
    assert "是否有残留数据未知" in msg, msg
    assert msg in job["error"], job["error"]


def test_empty_tier_is_an_anomaly_not_a_static_site(aws):
    """`tier` 是空串/None（键**在**但值是假值）：算异常并留痕，不许悄悄回落。

    这里曾经写成 `site.get("tier") or "static"`——把"这行没有可用的 tier"猜成
    "这是个静态站点"，而这正是 M02 那类"把坏数据洗成合法值"。

    **本用例先前的 docstring 断言过一条假事实**（"真正的静态站点由
    `create_site_record` 写着 tier=static"），已核实并纠正：
    `create_site_record` 只写 owner/name/status/created_at（`common.py:194-199`），
    `tier` 的**唯一** writer 是 `mark_job.py:441`，且只在**成功**路径上
    （紧随 `update_job(status="SUCCEEDED")`，第 10/10 步）。没有任何地方删 sites 行
    （三处 `delete_item` 打的是 JOBS_TABLE 的租约行与 ROUTING_TABLE）。
    所以"没有 tier 的行"= **首次部署没走到最后一步的站点**（外加存量老行），
    是正常可达且永久留存的一类，不是"坏数据"。

    这让猜**更**危险而不是更安全：`data_tables`（`provision_dynamodb.py:30`，第 2 步）
    与 DSQL schema（`provision_dsql.py:116`）都在 `tier` **之前**落盘，所以一个失败的
    fullstack-sql 部署完全可能已经有真实的 DSQL schema 却没有 tier。猜成 static ⇒
    静默跳过那个真实存在的 schema，而用户勾的是"永久删除数据"。
    问题在"静默"，不在"跳过"。

    注：`site.get("tier", "static")` 那个写法连这一步都到不了——它只在**键不存在**
    时给默认值，空串/NULL 的行会取到 `""` / `None` 然后直接把整次下线打成 FAILED。
    """
    import undeploy, common
    jid = common.create_job("a@x.com", "blank-x8")
    common.upsert_site("blank-x8", owner="a@x.com", status="ACTIVE", tier="")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dsql") as purge_dsql:
        out = undeploy.handler({"job_id": jid, "site_id": "blank-x8",
                                "purge_data": True}, None)
    purge_dsql.assert_not_called()
    assert common.get_site("blank-x8")["status"] == "DELETED"
    job = common.get_job(jid)
    assert job["status"] != "FAILED", (
        f"空 tier 把整次下线打成了 FAILED：{job.get('error')}")
    # 断言在**记下来的键**上，而不是日志上——日志不是断言
    assert out["purged"]["engine_unknown_error"], out
    assert job["status"] == "PURGE_FAILED", job


def test_missing_tier_key_is_an_anomaly_too(aws):
    """`tier` 键**完全不存在**的行（= 首次部署没成功过的站点）：同样留痕并跳过。

    与 sibling 的区别是这条走的是 `get` 返回 None 的分支（那条走假值分支），
    两条都必须落到同一个出口——把它们合成一条就分不出"默认值生效了"
    和"值是假值"这两种情况。真实账号里这一类**不罕见**：`tier` 只在
    `mark_job.py:441`（成功路径末步）才写，而 sites 行永不删除。

    这条**按整句钉死文案**（sibling 只查关键短语）：文案本身是这次修正的产物，
    "判不出引擎"必须不能读成"数据还在"——一个失败过的 static 部署本来就没有数据，
    对它警告残留数据是虚假警报。写成字面量而不是从被测代码拼出来，
    否则改坏文案时期望值跟着一起变、用例照绿。
    """
    import undeploy, common
    jid = common.create_job("a@x.com", "sparse-x7")
    # 注意：不传 tier，模拟 tier 这一列压根没写过的存量行
    common.upsert_site("sparse-x7", owner="a@x.com", status="ACTIVE")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dsql") as purge_dsql:
        out = undeploy.handler({"job_id": jid, "site_id": "sparse-x7",
                                "purge_data": True}, None)
    purge_dsql.assert_not_called()
    assert common.get_site("sparse-x7")["status"] == "DELETED"
    job = common.get_job(jid)
    assert job["status"] != "FAILED", (
        f"缺 tier 键把整次下线打成了 FAILED：{job.get('error')}")
    assert out["purged"]["engine_unknown_error"] == (
        "无法判定数据引擎（sites 行的 tier=None 不是已知取值），因此未尝试 "
        "DSQL 清理；是否有残留数据未知。DynamoDB 侧仍按 data_tables=[] 处理"), out
    assert job["status"] == "PURGE_FAILED", job


def test_real_static_site_purges_cleanly_without_an_anomaly(aws):
    """对照组：**真正的** static 站点（tier 写着 "static"）一切正常，不留异常。

    删掉 `or "static"` 兜底的回归风险全在这条上——判据若写歪，全部静态站点的
    下线都会报 PURGE_FAILED。static → engine="none"，不清 DSQL 是**正常**结果，
    不是异常（与上面两条"值不可用"区分开）。
    """
    import undeploy, common
    jid = _seed(common, boto3, site_id="flat-x6", tier="static")
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(undeploy, "_purge_dsql") as purge_dsql:
        out = undeploy.handler({"job_id": jid, "site_id": "flat-x6",
                                "purge_data": True}, None)
    purge_dsql.assert_not_called()
    assert common.get_job(jid)["status"] == "DELETED", "真 static 站点不该算异常"
    assert "engine_unknown_error" not in out.get("purged", {}), out


# ── 中途失败必须收敛到终态（Codex 审查 2026-08-10 P1-4）────────────────
# 实测复现过：注入 IAM 永久失败后
#   job_status=RUNNING / job_phase=undeploy / route=已删除 / site=ACTIVE
# 即"站点已经打不开了，控制台却显示 ACTIVE、任务永远转圈"。
# sweeper 也救不了它：undeploy 是独立异步 Lambda，没有 SFN execution，
# reconcile_job 的 sweeper 只会记一条 job_running_without_execution。

def test_midway_failure_writes_terminal_state_and_reraises(aws):
    """删 IAM 角色炸了：job 必须是 FAILED，且异常仍要抛出（触发 DLQ/告警）。"""
    import undeploy, common
    jid = _seed(common, boto3)
    real_client = boto3.client

    def fake(name, *a, **k):
        c = real_client(name, *a, **k)
        if name == "iam":
            m = MagicMock()
            m.exceptions.NoSuchEntityException = c.exceptions.NoSuchEntityException
            m.list_role_policies.side_effect = RuntimeError("IAM 永久失败（注入）")
            return m
        return c

    with patch.object(undeploy, "_lambda", return_value=_lam_mock()), \
         patch.object(boto3, "client", fake):
        try:
            undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
            raised = False
        except RuntimeError:
            raised = True
    assert raised, "异常被吞了——异步调用失败必须冒出去才会进 DLQ/告警"
    job = common.get_job(jid)
    assert job["status"] == "FAILED", f"job 停在 {job['status']}，永远转圈"
    assert job.get("error"), "没有错误摘要，用户不知道发生了什么"
    # 中途失败**不得**把站点写成 DELETED（它没删干净）
    assert common.get_site("hello-x1")["status"] != "DELETED"


def test_job_marked_undeploy_kind_for_sweeper(aws):
    """job 要能被认出是 undeploy（sweeper 的收敛规则不同于 deploy）。"""
    import undeploy, common
    jid = _seed(common, boto3)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert common.get_job(jid).get("kind") == "undeploy"


def test_lease_is_cleared_only_after_the_job_reaches_a_terminal_state(aws,
                                                                     monkeypatch):
    """租约行只能在 job 写完**终态**之后收走（独立评审 2026-08-18 Critical-1）。

    提前清（比如在删完路由/函数那一步）会打开这样的窗口：一个手里还有 PENDING
    job 的用户立刻 confirm_upload 开始新部署，而本函数下面还在 purge 数据、写
    site=DELETED——那次部署刚建出来的表/schema 会被当场删掉（purge_data=True 时
    窗口有几十秒），最后 mark_job 把一个数据已被清空的站点标成 ACTIVE。

    按**调用顺序**断言，不是只断言"最终清掉了"：顺序错误时终态照样都发生，
    只看终值的用例对这个缺陷完全不敏感。
    """
    import undeploy, common
    jid = _seed(common, boto3)
    order = []
    real_update = common.update_job
    real_clear = common.clear_deploy_lease

    def _spy_update(job_id, **kw):
        if kw.get("status") in ("DELETED", "PURGE_FAILED", "FAILED"):
            order.append(("terminal", kw["status"]))
        return real_update(job_id, **kw)

    def _spy_clear(site_id, holder):
        order.append(("clear_lease", holder))
        return real_clear(site_id, holder)

    monkeypatch.setattr(undeploy.common, "update_job", _spy_update)
    monkeypatch.setattr(undeploy.common, "clear_deploy_lease", _spy_clear)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)

    kinds = [k for k, _ in order]
    assert "clear_lease" in kinds and "terminal" in kinds
    assert kinds.index("terminal") < kinds.index("clear_lease"), (
        f"租约在 job 终态之前就被清了——purge 窗口里新部署能开跑：{order}")


def test_lease_clear_is_conditional_on_the_holder(aws):
    """清租约必须带"持有者还是本 job"的条件——别人的租约不许动。"""
    import common
    boto3.client("dynamodb").transact_write_items(
        TransactItems=common.plan_deploy_lease("hello-x1", "job-someone-else"))
    common.clear_deploy_lease("hello-x1", "job-mine")     # 不是持有者
    assert common.read_deploy_lease("hello-x1") == "job-someone-else", \
        "把别人正持有的租约清掉了"


# ── purge 前核归属：算出名字就删的年代结束了 ─────────────────────────────────
#
# `tables` 有两个来源（sites 行的 `data_tables`，以及 event 覆盖值——MCP 会传、
# panel 不传），任何一条被污染都会让一次下线删掉**别人的**数据表。表在创建时就打了
# `site_id` tag，从前只是从不回读。

def _spy_dynamodb(monkeypatch):
    """记下所有 DynamoDB API 调用。断言"压根没发出 DeleteTable"用它。

    patch 在 `botocore.client.BaseClient._make_api_call`——所有 client 的唯一出口，
    所以不管代码用哪个 client 实例、怎么拿到它，都逃不掉（与
    test_finalize_steps.py 的同名 helper 同法）。
    """
    import botocore.client
    calls = []
    orig = botocore.client.BaseClient._make_api_call

    def _spy(self, operation_name, api_params):
        if self.meta.service_model.service_name == "dynamodb":
            calls.append((operation_name, api_params))
        return orig(self, operation_name, api_params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _spy)
    return calls


def test_purge_refuses_to_delete_a_table_tagged_for_another_site(aws, monkeypatch):
    """`data_tables` 指向一张 tag 属于别站的表 ⇒ **不删**，job 落 PURGE_FAILED。

    这是碰撞被利用时的删表那一半：A 的 data_tables 里记着一个能指到 B 的表名。
    """
    import undeploy, common
    ddb = boto3.client("dynamodb")
    # 表名算作 hello-x1 的，但 tag 上写着别的站点
    _make_site_table(ddb, "site-data-hello-x1-notes", "somebody-else-x9")
    jid = _seed(common, boto3)
    common.upsert_site("hello-x1", data_tables=["notes"])

    calls = _spy_dynamodb(monkeypatch)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)

    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"], \
        "外站 tag 的表被删了"
    assert not [c for c in calls if c[0] == "DeleteTable"], \
        f"压根不该发出 DeleteTable，实际发了：{[c[1] for c in calls if c[0] == 'DeleteTable']}"
    assert "dynamodb_error" in out["purged"], f"错误没上报：{out['purged']}"
    job = common.get_job(jid)
    assert job["status"] == "PURGE_FAILED", \
        f"下线被报成了 {job['status']}——残留数据无人知晓"
    assert common.get_site("hello-x1")["status"] == "DELETED", \
        "站点确实已下线，这一半不该被清理失败带偏"


def test_purge_refuses_a_table_without_ownership_tags(aws, monkeypatch):
    """没有 tag ⇒ 归属未确认 ⇒ 不删。**不许降级成"那就当它是我的"**。"""
    import undeploy, common
    ddb = boto3.client("dynamodb")
    _make_site_table(ddb, "site-data-hello-x1-notes", "hello-x1", tags=False)
    jid = _seed(common, boto3)
    common.upsert_site("hello-x1", data_tables=["notes"])

    calls = _spy_dynamodb(monkeypatch)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)
    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"]
    assert not [c for c in calls if c[0] == "DeleteTable"]
    assert common.get_job(jid)["status"] == "PURGE_FAILED"


def test_purge_checks_ownership_for_event_supplied_table_names_too(aws, monkeypatch):
    """event 覆盖的 `data_tables` 走**同一条**核验。

    `undeploy` 的表名来源是 `event.get("data_tables") or site.data_tables`，
    event 优先（MCP 会传）。只在 sites 行那条路上核归属等于留了一半的门。
    """
    import undeploy, common
    ddb = boto3.client("dynamodb")
    _make_site_table(ddb, "site-data-hello-x1-notes", "somebody-else-x9")
    jid = _seed(common, boto3)
    # sites 行里**没有** data_tables，名字完全由 event 提供
    calls = _spy_dynamodb(monkeypatch)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True,
                                "data_tables": ["notes"]}, None)
    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"]
    assert not [c for c in calls if c[0] == "DeleteTable"]
    assert common.get_job(jid)["status"] == "PURGE_FAILED"


def test_purge_refuses_a_hyphenated_table_name_from_a_poisoned_row(aws, monkeypatch):
    """`data_tables` 里若留着含连字符的历史值 ⇒ fail-closed，不删任何东西。

    那种值正是跨站点碰撞的载体。`site_table_name` 在唯一定义处就拒掉它，所以
    这条路径连"算出名字"都做不到——而不是算出来再去比对。
    """
    import undeploy, common
    ddb = boto3.client("dynamodb")
    _make_site_table(ddb, "site-data-hello-x1-notes", "hello-x1")
    jid = _seed(common, boto3)
    common.upsert_site("hello-x1", data_tables=["b-654321-notes"])

    calls = _spy_dynamodb(monkeypatch)
    with patch.object(undeploy, "_lambda", return_value=_lam_mock()):
        out = undeploy.handler({"job_id": jid, "site_id": "hello-x1",
                                "purge_data": True}, None)
    assert not [c for c in calls if c[0] == "DeleteTable"]
    assert common.get_job(jid)["status"] == "PURGE_FAILED"
    assert "site-data-hello-x1-notes" in ddb.list_tables()["TableNames"]
