import boto3


EVENT = {"job_id": "job-1", "site_id": "notes-a1b2c3",
         "manifest": {"name": "notes", "tier": "fullstack-nosql",
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "notes", "pk": "id"}]},
                      "backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080},
                      "auth": {"require_login": True, "allowed_users": "org"}}}


def test_creates_table_and_env(aws):
    import provision_dynamodb, common
    common.create_job("a@x.com", "notes-a1b2c3")
    out = provision_dynamodb.handler(dict(EVENT), None)
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"
    desc = boto3.client("dynamodb").describe_table(
        TableName="site-data-notes-a1b2c3-notes")
    assert desc["Table"]["KeySchema"][0]["AttributeName"] == "id"


def test_idempotent_rerun(aws):
    import provision_dynamodb
    provision_dynamodb.handler(dict(EVENT), None)
    out = provision_dynamodb.handler(dict(EVENT), None)  # 不抛 ResourceInUse
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"


# ── 两阶段：预检零写入，且"表已存在"不等于"这是我的表" ──────────────────────
#
# 两条实测缺陷（见 provision_dynamodb 的模块 docstring）：
#   ① `ResourceInUseException` 曾被 `pass` 掉 ⇒ 把别人的表接管进本站的 data_tables
#      与 IAM 策略，随后 purge_data 还会删掉它；
#   ② 逐表循环 + 末尾才写 data_tables ⇒ 第 1 张建成、第 2 张失败时留下**未托管的
#      孤儿表**（sites 行里没有它，purge_data 也找不到它）。

import copy

import pytest


def _copy_event(tables):
    ev = copy.deepcopy(EVENT)
    ev["manifest"]["database"]["tables"] = tables
    return ev


def _foreign_table(ddb, name, owner_site):
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "project", "Value": "site-builder"},
              {"Key": "site_id", "Value": owner_site}])


def test_existing_table_owned_by_another_site_is_refused(aws, monkeypatch):
    """外站 tag 的已有表 ⇒ 抛错，且**不写 data_tables、不碰 role**。

    "表已经存在"从前被当成"这是我上次建的"。在表名可跨站点碰撞的年代，那一步会把
    别人的表接管进本站。
    """
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")
    _foreign_table(ddb, "site-data-notes-a1b2c3-notes", "somebody-else-x1")

    # role 侧用 spy：provision 本身不调 ensure_site_role，但它抛错就走不到
    # DeployLambdaSite——这条 spy 锁住"抛错之后没有任何 IAM 写入"
    calls = []
    monkeypatch.setattr(common, "ensure_site_role",
                        lambda *a, **k: calls.append((a, k)))

    with pytest.raises(common.TableOwnershipUnconfirmed, match="另一个站点"):
        provision_dynamodb.handler(dict(EVENT), None)

    assert calls == [], "抛错后仍动了 role policy"
    assert "data_tables" not in (common.get_site("notes-a1b2c3") or {}), \
        "抛错后仍把外站表名写进了 data_tables"


def test_precheck_creates_nothing_when_a_later_table_is_foreign(aws):
    """**两阶段的要害**：第 1 张可合法新建、第 2 张是外站表 ⇒ 第 1 张压根没被创建。

    逐表循环的版本会先把第 1 张建出来，再在第 2 张抛错——而 data_tables 还没写，
    于是第 1 张成了未托管的孤儿表：sites 行里没有它，purge_data 也找不到它。
    """
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")
    _foreign_table(ddb, "site-data-notes-a1b2c3-second", "somebody-else-x1")

    ev = _copy_event([{"name": "first", "pk": "id"},
                      {"name": "second", "pk": "id"}])
    with pytest.raises(common.TableOwnershipUnconfirmed):
        provision_dynamodb.handler(ev, None)

    names = ddb.list_tables()["TableNames"]
    assert "site-data-notes-a1b2c3-first" not in names, \
        "第 1 张表在预检失败前就被建出来了 —— 孤儿表"
    assert "data_tables" not in (common.get_site("notes-a1b2c3") or {})


def test_hyphenated_table_name_is_refused_before_anything_is_created(aws):
    """带连字符的表名在**建表之前**就失败。

    它有两个后果，都在这里挡住：跨站点物理表名碰撞（`site_table_name` 拒），以及
    派生出非法的 Lambda 环境变量键 `TABLE_MY-NOTES`（Lambda 的键不接受 `-`）。
    从前后者要等到 `deploy_lambda_site` 写配置时才炸——那时表已经建出来了。
    """
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")

    ev = _copy_event([{"name": "my-notes", "pk": "id"}])
    with pytest.raises(common.InvalidTableName, match="连字符"):
        provision_dynamodb.handler(ev, None)
    assert not [t for t in ddb.list_tables()["TableNames"]
                if t.startswith("site-data-notes-a1b2c3")]


def test_env_key_guard_catches_names_that_would_break_lambda(aws):
    """环境变量键守卫本身的反向验证。

    它管的是**非法字符**，不是"字母开头"——`TABLE_` 前缀已经保证了后者
    （第一版拿 `0starts_with_digit` 当反例，`TABLE_0STARTS…` 其实是合法键、当场不红）。
    它与 `site_table_name` 的 `-` 检查**不重复**：后者只看 `-`，而 `.`/空格/`!`
    这类字符在一个被污染的 event 直接进到 provision 时只有这条能挡。
    """
    import common
    import provision_dynamodb
    for bad in ("my-notes", "my.notes", "my notes", "my!notes"):
        with pytest.raises(common.InvalidTableName, match="环境变量键"):
            provision_dynamodb._env_key(bad)
    # 正对照：合法名不许被误伤
    assert provision_dynamodb._env_key("my_notes") == "TABLE_MY_NOTES"


# ── 已存在的表还要**就绪**（TableStatus=ACTIVE），归属正确不等于可以进 Lambda 部署 ──
#
# Codex 复审 8f8b0c6 的 P3-2（存量缺口，不是该提交引入的回归——旧代码的 waiter 在
# try 内，create 抛 ResourceInUseException 时同样不执行）：上一次运行在 create 成功后、
# waiter 处中断 ⇒ 重试看到的是 CREATING 的表；把它当完成会直落 data_tables 并进
# Lambda 部署，站点上线即报错。DELETING 的表则该经有界 waiter 超时 fail-closed。


def _never_ready(monkeypatch):
    """把 table_exists waiter 钉死为"永远等不到 ACTIVE"。

    botocore 动态生成的 waiter 子类把 wait 委托给 `Waiter.wait`，patch 基类即可。
    """
    import botocore.exceptions
    import botocore.waiter

    def _raise(self, **kw):
        raise botocore.exceptions.WaiterError(
            name="TableExists", reason="Max attempts exceeded",
            last_response={})

    monkeypatch.setattr(botocore.waiter.Waiter, "wait", _raise)


def test_an_existing_table_still_creating_is_not_treated_as_done(aws, monkeypatch):
    """阶段一：本站的表已存在（tag/schema 都对）但还是 CREATING ⇒ 不许当完成。"""
    import botocore.client
    import botocore.exceptions
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")
    _foreign_table(ddb, "site-data-notes-a1b2c3-notes", "notes-a1b2c3")  # 本站 tag

    orig = botocore.client.BaseClient._make_api_call

    def _still_creating(self, op, params):
        out = orig(self, op, params)
        if op == "DescribeTable":
            out["Table"]["TableStatus"] = "CREATING"
        return out

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call",
                        _still_creating)
    _never_ready(monkeypatch)

    with pytest.raises(botocore.exceptions.WaiterError):
        provision_dynamodb.handler(dict(EVENT), None)
    assert "data_tables" not in (common.get_site("notes-a1b2c3") or {}), \
        "CREATING 的表被当成完成写进了 data_tables"


def test_a_concurrently_created_table_must_also_reach_active(aws, monkeypatch):
    """阶段二：create 与并发方相撞、归属核验通过 ⇒ 仍要等它 ACTIVE。"""
    import botocore.client
    import botocore.exceptions
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")
    # 并发方已建出本站的表；预检时把它藏起来（第一次 DescribeTable 报不存在），
    # 于是本方走 create → 撞 ResourceInUseException → 归属核验通过
    _foreign_table(ddb, "site-data-notes-a1b2c3-notes", "notes-a1b2c3")

    orig = botocore.client.BaseClient._make_api_call
    hidden = {"done": False}

    def _hide_once(self, op, params):
        if (op == "DescribeTable"
                and params.get("TableName") == "site-data-notes-a1b2c3-notes"
                and not hidden["done"]):
            hidden["done"] = True
            raise ddb.exceptions.ResourceNotFoundException(
                {"Error": {"Code": "ResourceNotFoundException",
                           "Message": "gone"}}, "DescribeTable")
        return orig(self, op, params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call",
                        _hide_once)
    _never_ready(monkeypatch)

    with pytest.raises((botocore.exceptions.WaiterError, RuntimeError)):
        provision_dynamodb.handler(dict(EVENT), None)
    assert "data_tables" not in (common.get_site("notes-a1b2c3") or {})


def test_concurrent_create_racing_with_a_foreign_table_is_refused(aws, monkeypatch):
    """预检时不存在 → create 时撞外站表 ⇒ 拒（Codex 复审点名必补的竞态分支）。

    这是原 P1 在"预检与创建之间"的竞态版本：现有的阶段一外站用例只盖 describe
    分支，把 `except ResourceInUseException` 改回 `pass` 时它仍然绿——只有这条
    能咬住那个回退。
    """
    import botocore.client
    import common
    import provision_dynamodb
    ddb = boto3.client("dynamodb")
    common.create_job("a@x.com", "notes-a1b2c3")
    _foreign_table(ddb, "site-data-notes-a1b2c3-notes", "somebody-else-x1")

    orig = botocore.client.BaseClient._make_api_call
    hidden = {"done": False}

    def _hide_once(self, op, params):
        if (op == "DescribeTable"
                and params.get("TableName") == "site-data-notes-a1b2c3-notes"
                and not hidden["done"]):
            hidden["done"] = True
            raise ddb.exceptions.ResourceNotFoundException(
                {"Error": {"Code": "ResourceNotFoundException",
                           "Message": "gone"}}, "DescribeTable")
        return orig(self, op, params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call",
                        _hide_once)

    with pytest.raises(common.TableOwnershipUnconfirmed, match="另一个站点"):
        provision_dynamodb.handler(dict(EVENT), None)
    assert "data_tables" not in (common.get_site("notes-a1b2c3") or {}), \
        "竞态撞上外站表后仍把表名写进了 data_tables"
    assert [t for t in ddb.list_tables()["TableNames"]
            if t.startswith("site-data-notes-a1b2c3")] == \
        ["site-data-notes-a1b2c3-notes"], "不该有任何新表被建出来"


def test_tables_are_created_with_ownership_tags(aws):
    """建表必须打 tag——归属核验全靠它，而从前没有任何用例断言过 tag 存在。"""
    import provision_dynamodb, common
    common.create_job("a@x.com", "notes-a1b2c3")
    provision_dynamodb.handler(dict(EVENT), None)
    ddb = boto3.client("dynamodb")
    arn = ddb.describe_table(
        TableName="site-data-notes-a1b2c3-notes")["Table"]["TableArn"]
    tags = {t["Key"]: t["Value"] for t in
            ddb.list_tags_of_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("project") == "site-builder"
    assert tags.get("site_id") == "notes-a1b2c3"
