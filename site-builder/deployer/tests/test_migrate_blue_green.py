"""存量站点 blue/green 迁移脚本的守卫。

前四条来自 B5 brief（顺序、健康门、幂等、dry-run），其余是本轮硬性纪律要求的：

- **Ruling 58**：写了 `try/except <AWS 异常>` 的分支，必须有用例让替身**真的抛**
  那个异常——否则那条 `except` 是死代码，而本脚本通篇都是"首次/迁移/续做"这类
  最少走到、最需要对的路径。
- **Ruling 54**：多个 fail-closed 分支只断言"返回了 skipped" = 只断言了"至少还有
  一条分支在"。**分支身份是断言的一部分**，所以每条 skip 都按它**独有的原因串**断言。
- 控制器裁决：`tier: static` 站点没有 Lambda / alias / api_target，blue/green 对
  它们不适用，**必须显式报 skipped 并说明原因**（静默的"无"和"确实不用迁"长得一样）。

`_sleep` 与 `_public_check` 必须是**模块级函数**：否则用例要真等 65 秒、真发 HTTPS。
"""
import io
import json
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

REPO = Path(__file__).parents[3]

OLD_URL = "https://old.lambda-url.us-east-1.on.aws/"
BLUE_URL = "https://blue1.lambda-url.us-east-1.on.aws/"
EDGE_ROLE = "arn:aws:iam::000000000000:role/ApplicationWebRouterStack-EdgeRole"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """脚本读的三个环境变量（真机由 _load_config 从 config.ini 填）。

    用 autouse fixture 而不是模块级 os.environ 赋值：后者会泄漏到同一进程里
    其它测试文件，把"这个变量该缺失"的用例悄悄弄绿。
    """
    monkeypatch.setenv("ROUTING_TABLE", "routing")
    monkeypatch.setenv("BASE_DOMAIN", "example.com")
    monkeypatch.setenv("EDGE_ROLE_ARN", EDGE_ROLE)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _legacy_lam(healthy=True, aliases=()):
    """无 alias、有无 qualifier Function URL 的旧式站点。"""
    lam = MagicMock()
    for n in ("ResourceNotFoundException", "ResourceConflictException"):
        setattr(lam.exceptions, n, type(n, (Exception,), {}))
    # **显式桩 list_aliases**：裸 MagicMock 的 `["Aliases"]` 会返回一个可迭代成
    # 空序列的 MagicMock，于是"没有 alias"这个结论是替身白送的，不是脚本判出来的
    # （Ruling 58 那族：替身太宽容 ⇒ 分支从未被真的走过）。
    lam.list_aliases.return_value = {"Aliases": [{"Name": n} for n in aliases]}

    def _get_url(FunctionName, Qualifier=None):
        if Qualifier is None:
            return {"FunctionUrl": OLD_URL}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_function_url_config.side_effect = _get_url
    lam.create_function_url_config.return_value = {"FunctionUrl": BLUE_URL}
    lam.publish_version.return_value = {"Version": "9"}
    status = 200 if healthy else 500
    lam.invoke.return_value = {"Payload": io.BytesIO(
        json.dumps({"statusCode": status}).encode())}
    return lam


def _ddb_with_route(api_target=OLD_URL, others=(), **fields):
    ddb = MagicMock()
    item = {"subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
            "api_target": {"S": api_target}, "require_auth": {"BOOL": True}}
    item.update(fields)
    ddb.get_item.return_value = {"Item": item}
    ddb.get_paginator.return_value.paginate.return_value = [
        {"Items": [item, *others]}]
    return ddb


@contextmanager
def _no_wait(m, public=""):
    """挡住两件在用例里不能真做的事：等 65 秒、对公网发 HTTPS。"""
    with patch.object(m, "_sleep") as slept, \
            patch.object(m, "_public_check", return_value=public) as pub:
        yield slept, pub


# ── brief 的四条 ────────────────────────────────────────────────────────

def test_migration_switches_route_before_deleting_old_url():
    """顺序是死的：建 blue URL → 健康门 → 切路由 → 等缓存 → 才删旧 URL。
    删早了 = 路由还指着它 = 立刻 404。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m) as (slept, _):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    lam_names = [c[0] for c in lam.method_calls]
    assert lam_names.index("create_function_url_config") < lam_names.index("invoke")
    assert lam_names.index("invoke") < lam_names.index("delete_function_url_config")
    assert ddb.update_item.called, "没有切路由"
    # 切完路由要等 Edge 的路由缓存收敛，之后才删旧端点
    assert slept.called, "删旧 URL 之前没等路由缓存"
    switched = ddb.update_item.call_args.kwargs
    assert BLUE_URL.rstrip("/") in json.dumps(switched)


def test_migration_skips_and_reports_when_health_check_fails():
    """健康门不过 ⇒ 不切路由、不删旧 URL、报告跳过。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(healthy=False), _ddb_with_route()
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "健康门" in out, "跳过原因没点出是健康门——分支身份也是断言的一部分"
    ddb.update_item.assert_not_called()
    lam.delete_function_url_config.assert_not_called()


def test_migration_is_idempotent():
    """已迁移（路由已指 blue URL）再跑一次 ⇒ already，且不发写调用。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam(aliases=("blue",))
    ddb = _ddb_with_route(api_target=BLUE_URL)

    def _get_url(FunctionName, Qualifier=None):
        if Qualifier == "blue":
            return {"FunctionUrl": BLUE_URL}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_function_url_config.side_effect = _get_url
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "already"
    ddb.update_item.assert_not_called()
    lam.publish_version.assert_not_called()
    lam.delete_function_url_config.assert_not_called()


def test_dry_run_makes_no_write_calls():
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=True) == "migrated"
    for meth in ("publish_version", "create_alias", "update_alias",
                 "create_function_url_config", "add_permission",
                 "delete_function_url_config"):
        getattr(lam, meth).assert_not_called()
    ddb.update_item.assert_not_called()


def test_dry_run_calls_only_read_only_apis():
    """**白名单而不是黑名单**：逐个点名"这些写方法没被调"挡不住将来新加的第七个写
    调用，而这个 dry-run 要拿去对真实生产站点跑。所以断言"只允许出现这些只读 API"。
    """
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=True) == "migrated"
    assert {c[0] for c in lam.method_calls} <= {
        "list_aliases", "get_function", "get_alias", "get_function_url_config",
        "get_policy", "list_versions_by_function"}
    assert {c[0] for c in ddb.method_calls} <= {"get_item", "query", "scan",
                                               "get_paginator"}


def test_dry_run_does_not_even_invoke_the_health_gate():
    """dry-run 一个写调用都不许发；`invoke` 会拉起执行环境（有副作用、要计费），
    所以它也不该在只读试跑里发生。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m) as (slept, pub):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=True) == "migrated"
    lam.invoke.assert_not_called()
    slept.assert_not_called()
    pub.assert_not_called()


# ── static / 畸形路由：每条 skip 按**自己的原因串**断言（Ruling 54）──────────

def test_static_site_is_reported_as_skipped_with_a_reason():
    """`tier: static` 没有 Lambda、没有 alias、没有 api_target ⇒ 不适用 blue/green。
    **必须显式报 skipped 并说明原因**：静默略过时，"没迁"和"不用迁"长得一样。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route(api_target="")
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "static" in out and "api_target" in out
    lam.publish_version.assert_not_called()
    ddb.update_item.assert_not_called()


def test_site_without_lambda_function_is_reported_as_skipped():
    """函数不存在（static 站点 / 函数已被删）：`list_aliases` 真的抛
    ResourceNotFoundException，那条 except 必须被走到（Ruling 58）。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    lam.list_aliases.side_effect = lam.exceptions.ResourceNotFoundException()
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "site-s-1" in out and "Lambda" in out
    lam.publish_version.assert_not_called()
    ddb.update_item.assert_not_called()


def test_route_missing_from_table_is_reported_as_skipped():
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    ddb.get_item.return_value = {}
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "app-s-1" in out and "路由" in out
    lam.publish_version.assert_not_called()


def test_unrecognisable_api_target_is_skipped_not_guessed():
    """api_target 既不是任何颜色的 URL、也没有无 qualifier 的 URL ⇒ 认不出线上在
    服务什么，**不猜**。猜错的后果是把 $LATEST 覆盖成新版本却仍无入口，或反之。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam()
    lam.get_function_url_config.side_effect = \
        lam.exceptions.ResourceNotFoundException()
    ddb = _ddb_with_route(api_target="https://who-knows.example.com/")
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "认不出" in out
    lam.publish_version.assert_not_called()
    ddb.update_item.assert_not_called()


# ── 提交点之后：公网复查与续做 ────────────────────────────────────────────

def test_public_check_failure_keeps_the_old_url():
    """切路由是提交点，之后公网复查失败**不能删旧 URL**——留着它，把 api_target
    指回去就能一步回滚。状态也不能报成 migrated 或 skipped：路由确实已经切了。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m, public="/api/health 返回 403"):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert not out.startswith(("migrated", "already", "skipped")), out
    assert "403" in out
    assert ddb.update_item.called, "路由确实切了，报告不能把它说成没切"
    lam.delete_function_url_config.assert_not_called()


def test_resumes_when_route_is_on_a_color_but_old_url_still_exists():
    """半套状态（路由已在 blue，$LATEST 还挂着 URL）：只补最后一步删旧 URL，
    **不重新 publish**——重新 publish 会把这次跑的 $LATEST 当成"线上代码"。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam(aliases=("blue",))
    ddb = _ddb_with_route(api_target=BLUE_URL)

    def _get_url(FunctionName, Qualifier=None):
        return {"FunctionUrl": BLUE_URL if Qualifier == "blue" else OLD_URL}
    lam.get_function_url_config.side_effect = _get_url
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    lam.delete_function_url_config.assert_called_once()
    assert "Qualifier" not in lam.delete_function_url_config.call_args.kwargs
    lam.publish_version.assert_not_called()
    ddb.update_item.assert_not_called()


# ── 每条 except <AWS 异常> 都要被真的走到（Ruling 58）─────────────────────

def test_existing_color_alias_is_updated_instead_of_recreated():
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    lam.create_alias.side_effect = lam.exceptions.ResourceConflictException()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    assert lam.update_alias.call_args.kwargs == {
        "FunctionName": "site-s-1", "Name": "blue", "FunctionVersion": "9"}


def test_existing_color_url_is_reused_instead_of_recreated():
    """blue 的 URL 已存在（上一次迁移半途失败）：拿现有的用，别把整站判失败。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(aliases=("blue",)), _ddb_with_route()
    lam.create_function_url_config.side_effect = \
        lam.exceptions.ResourceConflictException()

    def _get_url(FunctionName, Qualifier=None):
        return {"FunctionUrl": BLUE_URL if Qualifier == "blue" else OLD_URL}
    lam.get_function_url_config.side_effect = _get_url
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    assert BLUE_URL.rstrip("/") in json.dumps(ddb.update_item.call_args.kwargs)


def test_add_permission_conflict_is_tolerated():
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    lam.add_permission.side_effect = lam.exceptions.ResourceConflictException()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"


def test_edge_gets_both_statements_on_the_color_qualifier():
    """2025-10 起 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两条，缺一
    即 403；且**必须带 Qualifier**，否则授在函数上，与"URL 只挂在颜色上"不一致。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    calls = [c.kwargs for c in lam.add_permission.call_args_list]
    assert {c["Action"] for c in calls} == {"lambda:InvokeFunctionUrl",
                                           "lambda:InvokeFunction"}
    assert all(c["Qualifier"] == "blue" for c in calls), calls
    assert all(c["Principal"] == EDGE_ROLE for c in calls), calls
    by_action = {c["Action"]: c for c in calls}
    assert by_action["lambda:InvokeFunctionUrl"]["FunctionUrlAuthType"] == "AWS_IAM"
    assert by_action["lambda:InvokeFunction"]["InvokedViaFunctionUrl"] is True


def test_color_function_url_is_iam_authed():
    """AuthType=NONE 会被安全扫描自动处置（删光 resource policy），且那一刻站点
    对全世界开放。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        m.migrate_one(lam, ddb, "s-1", dry_run=False)
    kw = lam.create_function_url_config.call_args.kwargs
    assert kw["AuthType"] == "AWS_IAM" and kw["Qualifier"] == "blue"


# ── 切路由只碰 api_target ────────────────────────────────────────────────

def test_route_switch_touches_only_api_target():
    """spec §4.3 第 5 步：**只改 api_target，不动其它字段**。整条 put_item 会用
    脚本手里的旧快照盖掉 require_auth / allowed_users / static_prefix——一次数据
    修复动作变成静默的策略变更。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        m.migrate_one(lam, ddb, "s-1", dry_run=False)
    ddb.put_item.assert_not_called()
    expr = ddb.update_item.call_args.kwargs["UpdateExpression"]
    # 独立于实现地数一遍"这条表达式改了几个属性"：SET 子句里的赋值个数
    assigned = [seg.split("=")[0].strip()
                for seg in expr[len("SET "):].split(",")]
    assert expr.startswith("SET ") and assigned == ["api_target"], expr


def test_route_switch_requires_the_route_to_still_exist():
    """站点在扫描与切换之间被下线：无条件 update_item 会**凭空建出**一条只有
    subdomain + api_target 的路由（DynamoDB 的 upsert 语义），Edge 读到它会按
    缺失字段回落默认值。"""
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        m.migrate_one(lam, ddb, "s-1", dry_run=False)
    cond = ddb.update_item.call_args.kwargs.get("ConditionExpression", "")
    assert "attribute_exists(subdomain)" in cond.replace(" ", "")


# ── 与 deploy_lambda_site 的对接：产出的状态必须让 handler 不再抛 ───────────

def test_post_migration_state_satisfies_the_deploy_handler():
    """迁移"完成"的判据必须与 handler 的未迁移判定对得上。handler 判的是
    `_live_color(...) is None and not _color_urls(...)`；本用例拿**迁移实际写出的
    api_target** 回放那两个函数，确认它认出了颜色（不是只满足"urls 非空"那半——
    那种半套状态下路由还指着 $LATEST 的旧 URL，正是 v1 的 P1-1）。"""
    import deploy_lambda_site as dls
    import migrate_sites_to_blue_green as m
    lam, ddb = _legacy_lam(), _ddb_with_route()
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=False) == "migrated"
    written = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
    new_target = next(v["S"] for v in written.values() if "S" in v)

    after = _legacy_lam(aliases=("blue",))          # 迁移后的线上状态
    after.get_function_url_config.side_effect = lambda FunctionName, Qualifier=None: (
        {"FunctionUrl": BLUE_URL} if Qualifier == "blue"
        else (_ for _ in ()).throw(after.exceptions.ResourceNotFoundException()))
    urls = dls._color_urls(after, "site-s-1")
    live = dls._live_color(new_target, urls)
    assert live == "blue", (new_target, urls)
    assert not (live is None and not urls), "handler 仍会抛 UnmigratedSite"
    assert dls._idle_color(live) == "green", "下一次部署该打到 green"


def test_sleep_covers_the_edge_route_cache_ttl():
    """等待必须严格长于 Edge 的路由缓存 TTL——否则删旧 URL 时还有 Edge 实例
    拿着旧 api_target，那些请求当场 404。期望值从 **router 的源文件**独立读取，
    不从脚本自己的常量推导。"""
    import migrate_sites_to_blue_green as m
    src = (REPO / "router/infrastructure/lambda/origin_request.py").read_text()
    ttl = int(re.search(r"^ROUTE_CACHE_TTL\s*=\s*(\d+)", src, re.M).group(1))
    assert m.ROUTE_CACHE_SECONDS > ttl, (m.ROUTE_CACHE_SECONDS, ttl)


# ── 公网复查的判据（复用 smoke_test._check，别手抄第二份 302/200 规则）──────

def test_public_check_requires_302_to_login_for_authed_sites():
    import migrate_sites_to_blue_green as m
    import smoke_test
    with patch.object(smoke_test, "_head",
                      return_value=(302, "https://auth.example.com/login?x=1")):
        assert m._public_check("app-s-1", True) == ""
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        assert "鉴权未生效" in m._public_check("app-s-1", True)


def test_public_check_requires_200_for_open_sites():
    import migrate_sites_to_blue_green as m
    import smoke_test
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        assert m._public_check("app-s-1", False) == ""
    with patch.object(smoke_test, "_head", return_value=(403, "")):
        assert "403" in m._public_check("app-s-1", False)


# ── 批量枚举：只碰 app- 路由，畸形的要报出来 ──────────────────────────────

def test_status_classification_separates_not_applicable_from_needs_attention():
    """报告的分类是操作者唯一的抓手：把"确实不用迁"和"没迁成"混进同一个数字，等于
    让健康门失败躲在 static 站点后面。**每个状态必须落在恰好一个桶里。**"""
    import migrate_sites_to_blue_green as m
    fine = ("migrated", "already",
            "skipped:static 路由没有 api_target（…）",
            "skipped:no-function 找不到 Lambda 函数 site-x（…）")
    bad = ("skipped:unhealthy 健康门未通过（…）",
           "skipped:unknown-target 认不出线上在服务什么（…）",
           "skipped:no-route 路由表里没有 app-x 这条路由",
           "skipped:shared-backend 路由 app-y 也指向（…）",
           "switched-unverified:路由已切到 blue，但公网复查失败",
           "error:ClientError: boom")
    assert [s for s in fine if m._needs_attention(s)] == []
    assert [s for s in bad if not m._needs_attention(s)] == []
    # 分区性：不适用 = 既不是成功也不需人工
    assert [s for s in fine + bad
            if m._needs_attention(s) and s in ("migrated", "already")] == []


def test_app_routes_lists_only_site_routes(aws):
    import migrate_sites_to_blue_green as m
    ddb = boto3.client("dynamodb")
    for sub, extra in (("app-s-1", {"site_id": {"S": "s-1"}}),
                       ("app-s-2", {"site_id": {"S": "s-2"}}),
                       ("console", {"owner": {"S": "platform"}}),
                       ("auth", {"owner": {"S": "platform"}}),
                       ("mcp", {"owner": {"S": "platform"}})):
        ddb.put_item(TableName="routing",
                     Item={"subdomain": {"S": sub}, **extra})
    site_ids, problems = m._app_routes(ddb)
    assert sorted(site_ids) == ["s-1", "s-2"]
    assert problems == []


def test_two_routes_on_one_site_id_are_reported_and_excluded(aws):
    """实测的生产数据：`app-smkauth431d776a` 与 `app-smk431d776a` 的 site_id 相同
    （smoke_router.sh 的残留）。`migrate_one` 只按 subdomain_for(site_id) 那一条路由
    切换，另一条会留在旧 URL 上——而第 7 步把那个 URL 删了 ⇒ 那条路由当场 404。
    所以这种站点**排除出批量**并报出来，不是"顺带迁一下"。"""
    import migrate_sites_to_blue_green as m
    ddb = boto3.client("dynamodb")
    for sub, sid in (("app-s-1", "s-1"), ("app-alias-of-s-1", "s-1"),
                     ("app-s-2", "s-2")):
        ddb.put_item(TableName="routing", Item={"subdomain": {"S": sub},
                                                "site_id": {"S": sid}})
    site_ids, problems = m._app_routes(ddb)
    assert site_ids == ["s-2"], site_ids
    assert any("s-1" in p and "app-alias-of-s-1" in p for p in problems), problems


def test_refuses_to_delete_an_old_url_another_route_still_uses():
    """删无 qualifier 的 URL 是**不可逆**的，而它可能被第二条路由引用着。
    在动任何东西**之前**就拒绝，不是切完路由才发现。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam()
    ddb = _ddb_with_route(others=[{"subdomain": {"S": "app-other"},
                                   "site_id": {"S": "s-9"},
                                   "api_target": {"S": OLD_URL}}])
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:")
    assert "app-other" in out, out
    lam.publish_version.assert_not_called()
    ddb.update_item.assert_not_called()
    lam.delete_function_url_config.assert_not_called()


def test_shared_old_url_also_blocks_the_resume_path():
    """续做路径（路由已在 blue、旧 URL 还在）删的是同一个 URL ⇒ 同一道闸门。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam(aliases=("blue",))
    lam.get_function_url_config.side_effect = (
        lambda FunctionName, Qualifier=None:
        {"FunctionUrl": BLUE_URL if Qualifier == "blue" else OLD_URL})
    ddb = _ddb_with_route(api_target=BLUE_URL,
                          others=[{"subdomain": {"S": "app-other"},
                                   "api_target": {"S": OLD_URL}}])
    with _no_wait(m):
        out = m.migrate_one(lam, ddb, "s-1", dry_run=False)
    assert out.startswith("skipped:") and "app-other" in out
    lam.delete_function_url_config.assert_not_called()


def test_dry_run_reports_the_shared_url_refusal_too():
    """dry-run 是唯一的人工审查关口：它说 migrated 而 apply 时拒绝 = 报告在说谎。"""
    import migrate_sites_to_blue_green as m
    lam = _legacy_lam()
    ddb = _ddb_with_route(others=[{"subdomain": {"S": "app-other"},
                                   "api_target": {"S": OLD_URL}}])
    with _no_wait(m):
        assert m.migrate_one(lam, ddb, "s-1", dry_run=True).startswith("skipped:")


def test_app_route_without_site_id_is_reported_not_dropped(aws):
    import migrate_sites_to_blue_green as m
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={"subdomain": {"S": "app-broken"}})
    site_ids, problems = m._app_routes(ddb)
    assert site_ids == []
    assert any("app-broken" in p for p in problems)
