import io
import json
from unittest.mock import MagicMock, patch

LWA_ARN = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"

def _route_item(api_target):
    """路由表里放一条这个站点的现状（`api_target` 就是"当前哪个颜色在服务"的真源）。"""
    import os

    import boto3
    boto3.client("dynamodb").put_item(
        TableName=os.environ["ROUTING_TABLE"],
        Item={"subdomain": {"S": "app-s-1"}, "api_target": {"S": api_target}})


def _route_target():
    import os

    import boto3
    item = boto3.client("dynamodb").get_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": "app-s-1"}}).get("Item") or {}
    return item.get("api_target", {}).get("S")

EVENT = {"job_id": "job-1", "site_id": "s-1",
         "manifest": {"backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080},
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "notes", "pk": "id"}]}},
         "env_vars": {"TABLE_NOTES": "site-data-s-1-notes"},
         "backend_zip_key": "artifacts/job-1/backend.zip"}


def _color_url(color: str) -> str:
    """按颜色首字母造一个可辨认的 Function URL（blue → b…, green → g…）。"""
    return f"https://{color[0]}.lambda-url.us-east-1.on.aws/"


def _lam_mock(exists: bool, colors=()):
    """lambda 客户端替身（B1/B2 共用）。

    `colors`：**已经存在** alias 与对应 Function URL 的颜色集合。不在集合里的颜色
    按真实 API 的行为抛 `ResourceNotFoundException`——"这个颜色还没建"与"建了"是
    blue/green 判定的全部输入，替身必须把两者区分开，否则 `_color_urls` 拿到的永远
    是"两个颜色都在"，未迁移站点那条路径就测不到。

    三个异常类型**一律**挂上（不按 `exists` 分叉）：`except lam.exceptions.X` 在
    X 是 MagicMock 时会 TypeError，而那种炸法只在真的抛异常时才显形，读起来像被测
    代码的错。
    """
    lam = MagicMock()
    for name in ("ResourceNotFoundException", "ResourceConflictException",
                 "InvalidParameterValueException"):
        setattr(lam.exceptions, name, type(name, (Exception,), {}))
    if not exists:
        lam.get_function.side_effect = lam.exceptions.ResourceNotFoundException()

    def _get_alias(FunctionName, Name):
        if Name in colors:
            return {"FunctionVersion": "5", "Name": Name}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_alias.side_effect = _get_alias

    # **update_alias 对不存在的 alias 要抛**（真实 API 如此）。不抛的话
    # `except ResourceNotFoundException: create_alias(...)` 那条分支在任何用例里
    # 都走不到——首次部署建 alias 的代码就成了从没被执行过的死路。
    def _update_alias(FunctionName, Name, FunctionVersion):
        if Name in colors:
            return {"Name": Name, "FunctionVersion": FunctionVersion}
        raise lam.exceptions.ResourceNotFoundException()
    lam.update_alias.side_effect = _update_alias
    lam.create_alias.side_effect = lambda **kw: {
        "Name": kw["Name"], "FunctionVersion": kw["FunctionVersion"]}

    # **B2 之后每个 Function URL 调用都必须带 Qualifier**：函数级 URL（挂在
    # $LATEST 上）就是"未迁移"的那个形态，迁移后永不再挂。所以这里不给
    # Qualifier=None 留后路，而是让它显式炸——handler 若退回函数级 URL，
    # 会得到一条指名道姓的失败，而不是一个能让断言照绿的旧 URL。
    def _require_qualifier(where, q):
        assert q is not None, (
            f"{where} 没带 Qualifier——B2 之后 URL 只挂在颜色 alias 上，"
            "函数级 URL 等于回到未迁移状态")

    def _get_url(FunctionName, Qualifier=None):
        _require_qualifier("get_function_url_config", Qualifier)
        if Qualifier in colors:
            # AuthType 默认给对的值：验"漂移成 NONE 要被改回"的用例自己覆写。
            return {"FunctionUrl": _color_url(Qualifier), "AuthType": "AWS_IAM"}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_function_url_config.side_effect = _get_url

    # resource policy 默认不存在（URL 是刚建的）；验"额外语句要被清掉"的用例覆写。
    lam.get_policy.side_effect = lam.exceptions.ResourceNotFoundException()

    def _create_url(**kw):
        _require_qualifier("create_function_url_config", kw.get("Qualifier"))
        return {"FunctionUrl": _color_url(kw["Qualifier"])}
    lam.create_function_url_config.side_effect = _create_url

    lam.publish_version.return_value = {"Version": "7"}
    lam.invoke.return_value = _ok_payload(200)
    return lam


def _ok_payload(status=200):
    """一次 invoke 的返回。**每次新造 BytesIO**：`Payload.read()` 是一次性的，
    复用同一个句柄会让第二次读到空 bytes ⇒ 断言变成在测 mock 的状态。"""
    return {"Payload": io.BytesIO(json.dumps({"statusCode": status}).encode())}


def test_creates_per_site_role_and_function(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        out = deploy_lambda_site.handler(dict(EVENT), None)
    # B2 起 URL 挂在颜色 alias 上，首次部署是 blue ⇒ 期望值跟着**被测行为**变
    assert out["api_target"] == "https://b.lambda-url.us-east-1.on.aws"

    # per-site 角色（moto IAM 真建）：boundary + 只授本站点表
    import boto3, json
    iam = boto3.client("iam")
    role = iam.get_role(RoleName="site-rt-s-1")["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"].endswith(
        "policy/site-runtime-boundary")
    pol = iam.get_role_policy(RoleName="site-rt-s-1", PolicyName="site-scope")
    doc = json.dumps(pol["PolicyDocument"])
    assert "site-data-s-1-" in doc and "site-data-s-2" not in doc

    kw = lam.create_function.call_args.kwargs
    assert kw["FunctionName"] == "site-s-1"
    assert kw["Role"].endswith("role/site-rt-s-1")
    assert kw["Layers"] == [LWA_ARN]
    assert kw["Handler"] == "run.sh"
    env = kw["Environment"]["Variables"]
    assert env["AWS_LAMBDA_EXEC_WRAPPER"] == "/opt/bootstrap"
    assert env["PORT"] == "8080"
    assert env["TABLE_NOTES"] == "site-data-s-1-notes"
    # Function URL 权限精确到 Edge role，无 * fallback
    perm = lam.add_permission.call_args.kwargs
    assert perm["Principal"] == "arn:aws:iam::1:role/edge-role"


def test_missing_edge_role_arn_fails_closed(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.delenv("EDGE_ROLE_ARN", raising=False)
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    import pytest as _pt
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        with _pt.raises(KeyError):
            deploy_lambda_site.handler(dict(EVENT), None)


def test_site_log_group_retention_is_ninety_days(aws, monkeypatch):
    """站点日志组保留期钉在 90 天（2026-08-15 用户决定的全平台统一值）。

    这行代码管的是**将来每一个新建站点**——手工把存量日志组改成 90 天不会
    影响新站点，下次部署又按代码里的值写回去。所以数字必须由用例锁住。
    """
    import deploy_lambda_site, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        deploy_lambda_site.handler(dict(EVENT), None)
    import boto3
    groups = boto3.client("logs", region_name="us-east-1").describe_log_groups(
        logGroupNamePrefix="/aws/lambda/site-s-1")["logGroups"]
    assert [(g["logGroupName"], g.get("retentionInDays")) for g in groups] == [
        ("/aws/lambda/site-s-1", 90)]


def test_existing_function_updated(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    # B2 起"已存在的函数"还必须**已迁移**（两个颜色 + 路由指着其中一个），
    # 否则走的是 UnmigratedSite 那条路而不是更新路。
    _route_item("https://b.lambda-url.us-east-1.on.aws")
    lam = _lam_mock(exists=True, colors=("blue", "green"))
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        deploy_lambda_site.handler(dict(EVENT), None)
    lam.update_function_code.assert_called_once()
    lam.create_function.assert_not_called()


# ── B1: 颜色判定 + 健康门 ────────────────────────────────────────────────

def test_live_color_is_derived_from_the_route_not_stored_separately(aws):
    """**不另存 live_color**：第二份状态必然漂移，而漂移的后果是往正在服务的颜色上
    部署（= 用户当场看到半成品）。颜色从路由表的 api_target 反推。"""
    import deploy_lambda_site as d
    urls = {"blue": "https://b.lambda-url.us-east-1.on.aws",
            "green": "https://g.lambda-url.us-east-1.on.aws"}
    assert d._live_color("https://b.lambda-url.us-east-1.on.aws", urls) == "blue"
    assert d._live_color("https://g.lambda-url.us-east-1.on.aws/", urls) == "green"
    # 无 qualifier 的旧 URL ⇒ 认不出颜色 ⇒ 未迁移
    assert d._live_color("https://old.lambda-url.us-east-1.on.aws", urls) is None
    assert d._idle_color("blue") == "green" and d._idle_color("green") == "blue"
    # 一个颜色都没有时，第一次部署去 COLORS[0]
    assert d._idle_color(None) == d.COLORS[0]


def test_color_urls_only_reports_colors_that_actually_exist(aws):
    """`_color_urls` 是"这个站点迁移到哪一步了"的唯一观测口。

    只建了一个颜色时**不能**假装两个都在——B2 靠"两个颜色都不匹配 api_target"判
    未迁移，而"键存在但值是空/占位"会让那个判断静默走错分支。顺带锁掉尾斜杠：
    api_target 存的是不带尾斜杠的形态，两边不一致就永远匹配不上。
    """
    import deploy_lambda_site as d
    lam = _lam_mock(exists=True, colors=("blue",))
    assert d._color_urls(lam, "site-s-1") == {
        "blue": "https://b.lambda-url.us-east-1.on.aws"}      # 已 rstrip("/")
    assert d._color_urls(lam, "site-s-1")["blue"][-1] != "/"

    both = _lam_mock(exists=True, colors=("blue", "green"))
    assert set(d._color_urls(both, "site-s-1")) == set(d.COLORS)
    none = _lam_mock(exists=True, colors=())
    assert d._color_urls(none, "site-s-1") == {}


def test_health_check_asserts_200_and_no_function_error(aws):
    import deploy_lambda_site as d, pytest
    lam = _lam_mock(exists=True)
    lam.invoke.return_value = _ok_payload(200)
    d._health_check(lam, "site-s-1", "green")
    assert lam.invoke.call_args.kwargs["Qualifier"] == "green"
    ev = json.loads(lam.invoke.call_args.kwargs["Payload"])
    assert ev["rawPath"] == "/api/health"
    assert ev["headers"]["x-user-email"] == "deploy-healthcheck@example.com"
    # LWA 只认 payload v2.0；形态错了真实站点会 502 而这里却绿
    assert ev["version"] == "2.0"
    assert ev["requestContext"]["http"]["method"] == "GET"

    # 四种 fail-closed 形态，**每种都断言是哪一条分支拒的**（`match=`）。
    # 只断言"抛了 BackendUnhealthy"不够：实测过——把 FunctionError 那条检查整段
    # 删掉，本条依然全绿，因为 {"errorMessage":"boom"} 会掉到下面的"不是 HTTP
    # 响应形态"分支上，于是异常照抛、断言照过，而 FunctionError 这根轴其实没被
    # 任何东西看着。分支身份是这条断言的一部分。
    for bad, why in (
            ({"FunctionError": "Unhandled",
              "Payload": io.BytesIO(b'{"errorMessage":"boom"}')}, "FunctionError"),
            (_ok_payload(502), "502"),
            ({"Payload": io.BytesIO(b'"pong"')}, "不是 HTTP 响应形态"),
            ({"Payload": io.BytesIO(b'not json at all')}, "返回非 JSON")):
        lam.invoke.return_value = bad
        with pytest.raises(d.BackendUnhealthy, match=why):
            d._health_check(lam, "site-s-1", "green")


def test_health_check_does_not_retry_business_failures(aws):
    """起不来的后端不许被重试掩盖成偶发。"""
    import deploy_lambda_site as d, pytest
    lam = _lam_mock(exists=True)
    lam.invoke.return_value = _ok_payload(500)
    with pytest.raises(d.BackendUnhealthy):
        d._health_check(lam, "site-s-1", "green")
    assert lam.invoke.call_count == 1


def test_health_check_retries_only_while_the_version_is_not_ready(aws):
    """新发布的版本/alias 有就绪窗口，那一段**要**重试；别的一律不重试。

    两半都要测：`ResourceConflictException` 连着抛几次之后成功 ⇒ 总调用次数是
    "失败次数 + 1"（证明它真在重试，而不是碰巧第一次就成）；一直抛 ⇒ 到上限后把
    原异常抛出来、且**恰好**试了 VERSION_READY_ATTEMPTS 次（证明上限真的生效，
    不是无限重试）。sleep 打掉，否则本条要跑 VERSION_READY_SLEEP × N 秒。
    """
    import deploy_lambda_site as d, pytest
    conflict = _lam_mock(exists=True).exceptions.ResourceConflictException

    lam = _lam_mock(exists=True)
    lam.exceptions.ResourceConflictException = conflict
    lam.invoke.side_effect = [conflict(), conflict(), _ok_payload(200)]
    with patch.object(d.time, "sleep") as slept:
        d._health_check(lam, "site-s-1", "green")
    assert lam.invoke.call_count == 3
    assert slept.call_count == 2
    assert slept.call_args.args == (d.VERSION_READY_SLEEP,)

    lam2 = _lam_mock(exists=True)
    lam2.exceptions.ResourceConflictException = conflict
    lam2.invoke.side_effect = conflict()
    with patch.object(d.time, "sleep"):
        with pytest.raises(conflict):
            d._health_check(lam2, "site-s-1", "green")
    assert lam2.invoke.call_count == d.VERSION_READY_ATTEMPTS


# ── B2: 部署到空闲色，不切换；未迁移 fail-closed ─────────────────────────

def test_deploys_to_idle_color_and_never_touches_live(aws, monkeypatch):
    """线上是 blue ⇒ 只能动 green。**不许**对 blue 调 update_alias。

    顺带锁死本步骤**根本不写路由表**：提交点在 register_route（B3），本步骤
    产出的 api_target 只是"候选"。handler 自己碰一下路由就等于把提交点搬了家，
    而那种搬家在单测里只看返回值是发现不了的。
    """
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://b.lambda-url.us-east-1.on.aws")
    lam = _lam_mock(exists=True, colors=("blue", "green"))
    with patch.object(d, "_lambda", return_value=lam):
        out = d.handler(dict(EVENT), None)
    assert out["deploy_color"] == "green"
    assert out["deploy_version"] == "7"
    assert out["api_target"] == "https://g.lambda-url.us-east-1.on.aws"
    assert lam.update_alias.call_args.kwargs["Name"] == "green"
    assert all(c.kwargs.get("Name") != "blue"
               for c in lam.update_alias.call_args_list)
    # 线上那一色的 URL/权限也不许被动
    for c in lam.create_function_url_config.call_args_list:
        assert c.kwargs.get("Qualifier") != "blue"
    for c in lam.add_permission.call_args_list:
        assert c.kwargs.get("Qualifier") != "blue"
    assert _route_target() == "https://b.lambda-url.us-east-1.on.aws", \
        "本步骤写了路由表——提交点必须留在 register_route"


def test_idle_alias_moves_to_the_new_version_before_the_health_gate(aws, monkeypatch):
    """顺序：publish_version → update_alias(空闲色) → invoke(空闲色)。

    **健康门打的是颜色 alias，不是裸版本号**：颜色的 Function URL 挂在 alias 这个
    qualifier 上，所以只有 invoke 那个 alias 才是在测"真正会服务流量的东西"。先健康
    门再移 alias 的话，测的是版本号那个 qualifier，与将来服务的 qualifier 不是同一个
    ——移 alias 这一步就成了没被验证的动作。空闲色不在路由上，先移它对线上零影响。
    """
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://b.lambda-url.us-east-1.on.aws")
    lam = _lam_mock(exists=True, colors=("blue", "green"))
    with patch.object(d, "_lambda", return_value=lam):
        d.handler(dict(EVENT), None)
    names = [c[0] for c in lam.method_calls]
    assert names.index("publish_version") < names.index("update_alias")
    assert names.index("update_alias") < names.index("invoke")
    # 健康门必须在挂 URL / 授权之前：那两步是让这一色可被外部调用
    assert names.index("invoke") < names.index("create_function_url_config")


def test_unhealthy_candidate_leaves_route_and_live_untouched(aws, monkeypatch):
    """提交点在 register_route，本步失败 ⇒ 路由没动、线上零影响。"""
    import io

    import pytest

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://b.lambda-url.us-east-1.on.aws")
    lam = _lam_mock(exists=True, colors=("blue", "green"))
    lam.invoke.return_value = {"FunctionError": "Unhandled",
                               "Payload": io.BytesIO(b'{"errorMessage":"boom"}')}
    with patch.object(d, "_lambda", return_value=lam):
        # Ruling 54：断言**是哪一条分支**拒的，不只断言异常类型
        with pytest.raises(d.BackendUnhealthy, match="FunctionError"):
            d.handler(dict(EVENT), None)
    assert _route_target() == "https://b.lambda-url.us-east-1.on.aws"
    # 且候选色没被挂上 URL——健康门没过就不该让它可被调用
    for c in lam.create_function_url_config.call_args_list:
        assert c.kwargs.get("Qualifier") != "green"


def test_unmigrated_site_fails_closed(aws, monkeypatch):
    """路由指着无 qualifier 的旧 URL 且没有任何颜色 alias ⇒ 拒绝部署，
    要求先跑迁移脚本。**不做隐式半迁移**（v1 的 P1-1）：半套迁移会让这次更新
    仍然把未经健康门的代码暴露在 $LATEST 上。

    三件事一起断言：抛的是 UnmigratedSite **且是未迁移那条分支**（Ruling 54）、
    `$LATEST` 一个字节都没动、**路由一个字没改**。只断言抛异常的话，"先把代码
    推上 $LATEST 再检查"这种顺序错会照样绿——而那正是 v1 的原缺陷。
    """
    import pytest

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://old.lambda-url.us-east-1.on.aws")
    lam = _lam_mock(exists=True, colors=())
    with patch.object(d, "_lambda", return_value=lam):
        with pytest.raises(d.UnmigratedSite, match="migrate_sites_to_blue_green"):
            d.handler(dict(EVENT), None)
    lam.update_function_code.assert_not_called()      # $LATEST 都没碰
    lam.publish_version.assert_not_called()
    lam.update_alias.assert_not_called()
    lam.create_alias.assert_not_called()
    lam.invoke.assert_not_called()
    assert _route_target() == "https://old.lambda-url.us-east-1.on.aws"


def test_brand_new_site_starts_on_blue(aws, monkeypatch):
    """首次部署：没有任何颜色 ⇒ 去 COLORS[0]，且 alias 是**新建**而不是更新。"""
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    with patch.object(d, "_lambda", return_value=lam):
        out = d.handler(dict(EVENT), None)
    assert out["deploy_color"] == "blue"
    assert lam.create_function_url_config.call_args.kwargs["Qualifier"] == "blue"
    for c in lam.add_permission.call_args_list:
        assert c.kwargs["Qualifier"] == "blue"
    # alias 不存在 ⇒ update_alias 抛 ⇒ 走 create_alias。两个都断言，否则
    # "update_alias 静默成功"这种替身失真会让建 alias 那条分支从未被执行。
    lam.create_alias.assert_called_once()
    assert lam.create_alias.call_args.kwargs["Name"] == "blue"
    assert lam.create_alias.call_args.kwargs["FunctionVersion"] == "7"


def test_half_migrated_site_fails_closed(aws, monkeypatch):
    """**半迁移**（blue alias + blue URL 都建好了，但路由还指着无 qualifier 的旧
    URL）⇒ 同样必须拒绝，且必须在动任何字节**之前**。

    这是 Codex 2026-08-17 P1-3。可达性不是纸面的：迁移脚本
    (`migrate_sites_to_blue_green.migrate_one`) 的健康门失败时正好留下这个状态
    ——它建完 alias / URL / 授权才跑健康门，不过就返回 `skipped:unhealthy` 并
    **故意不切路由**。

    旧判据 `live is None and not urls` 的那个 AND 漏掉这一态：`urls` 非空 ⇒ 闸门
    放行 ⇒ `update_function_code` 推 $LATEST，而路由此刻正指着 $LATEST 的 URL ⇒
    未经健康门的新代码当场对外服务。健康门随后即使失败也已经太晚了。

    所以断言的重点是"**$LATEST 一个字节都没动**"，不只是"抛了异常"。
    """
    import pytest

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://old.lambda-url.us-east-1.on.aws")   # 路由仍在 $LATEST
    lam = _lam_mock(exists=True, colors=("blue",))           # 但 blue 已经建好了
    with patch.object(d, "_lambda", return_value=lam):
        with pytest.raises(d.UnmigratedSite, match="migrate_sites_to_blue_green"):
            d.handler(dict(EVENT), None)
    lam.update_function_code.assert_not_called()      # ← 这条才是 P1-3 的要害
    lam.publish_version.assert_not_called()
    lam.update_alias.assert_not_called()
    lam.invoke.assert_not_called()
    assert _route_target() == "https://old.lambda-url.us-east-1.on.aws"


def test_existing_function_without_any_route_is_treated_as_a_first_deploy(
        aws, monkeypatch):
    """函数与 blue alias/URL 都在、但**路由根本不存在** ⇒ 不是未迁移，照常部署。

    可达性：首次部署在 deploy_lambda_site 之后、register_route 提交之前失败
    （健康门过了但写路由那步炸了，或 SFN 超时），重试就落在这个状态。

    这一条是把 P1-3 的闸门收成 `if live is None: raise` 会踩的坑：那样这个站点
    将**永远**无法再部署，且报的是"去跑迁移脚本"——一条根本不适用的指引。区分点
    是路由**在不在**，不是有没有颜色 URL：M7 建的站点从不给 $LATEST 挂 URL，
    所以没有路由时推 $LATEST 对外零暴露。
    """
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    assert _route_target() is None                       # 路由不存在
    lam = _lam_mock(exists=True, colors=("blue",))
    with patch.object(d, "_lambda", return_value=lam):
        out = d.handler(dict(EVENT), None)
    # live 认不出（没有路由）⇒ _idle_color(None) ⇒ COLORS[0]
    assert out["deploy_color"] == "blue"
    lam.update_function_code.assert_called_once()


def test_route_pointing_at_an_unrecognised_target_fails_closed(aws, monkeypatch):
    """路由指着一个既不是任何颜色、也不是本站点函数的目标 ⇒ fail-closed。

    旧判据在 `urls` 非空时会放行这一态（等于"认不出线上在服务什么，但还是照推
    $LATEST"）。认不出时唯一安全的动作是停下来让人核对。
    """
    import pytest

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    _route_item("https://someone-elses-endpoint.example.com")
    lam = _lam_mock(exists=True, colors=("blue", "green"))
    with patch.object(d, "_lambda", return_value=lam):
        with pytest.raises(d.UnmigratedSite):
            d.handler(dict(EVENT), None)
    lam.update_function_code.assert_not_called()


def test_conflicting_permission_statement_is_replaced_not_ignored(aws, monkeypatch):
    """同名 StatementId 已存在时必须**替换**，不能忽略（Codex 2026-08-17 P1-5）。

    同名只说明"有一条语句叫这个名字"，不说明它的内容是对的。一条内容错误的同名
    语句（principal 不对、少了 Qualifier、少了 InvokedViaFunctionUrl）会让 Edge 调用
    403，而这条路径上没有任何东西能发现它：健康门是 `lambda:invoke` 直调、压根不经过
    Function URL 的授权；提交点之后的 smoke 又可能命中 Edge 的旧路由缓存而对**旧**
    目标返回 200。于是缓存过期之后整站才开始 403。

    红的条件：`remove_permission` 没被调用（= 那条错语句被留下了）。
    """
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    # 两条语句都已存在（内容未知/可能是错的）：**每个 sid 的第一次** add 冲突，
    # 删掉再加才成功。按 sid 计数而不是按总调用次数——后者会让第二个 sid 的
    # 两次尝试都落在"冲突"上，测到的就是另一条分支（第二次仍冲突 ⇒ 抛）。
    seen = set()

    def _add(**kw):
        sid = kw["StatementId"]
        if sid not in seen:
            seen.add(sid)
            raise lam.exceptions.ResourceConflictException()
        return {}
    lam.add_permission.side_effect = _add

    with patch.object(d, "_lambda", return_value=lam):
        d.handler(dict(EVENT), None)

    removed = {c.kwargs["StatementId"] for c in lam.remove_permission.call_args_list}
    assert removed == {"edge-invoke", "edge-invoke-function"}, \
        f"冲突的语句没被替换，被静默忽略了：removed={removed}"
    for c in lam.remove_permission.call_args_list:
        assert c.kwargs["Qualifier"] == "blue", \
            "remove_permission 没带 Qualifier——删的不是挂在颜色上的那条"
    # 替换之后两条都必须真的加上去了
    added = {c.kwargs["StatementId"] for c in lam.add_permission.call_args_list}
    assert added == {"edge-invoke", "edge-invoke-function"}


def test_a_permission_that_conflicts_twice_is_not_swallowed(aws, monkeypatch):
    """删了再加还冲突 ⇒ 让它抛出去，不许静默继续。

    那说明有别的东西在同时写这条资源策略，此时"授权可能是错的"必须响亮失败——
    静默继续会得到一个健康门全绿、缓存过期后整站 403 的部署。
    """
    import pytest

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    lam.add_permission.side_effect = lam.exceptions.ResourceConflictException()

    with patch.object(d, "_lambda", return_value=lam):
        with pytest.raises(lam.exceptions.ResourceConflictException):
            d.handler(dict(EVENT), None)


def test_existing_url_with_authtype_none_is_forced_back_to_aws_iam(aws,
                                                                  monkeypatch):
    """已有候选色 URL 被漂移成 AuthType=NONE ⇒ 提交前必须改回 AWS_IAM。

    这是 Codex 2026-08-18 P1-5A：create 报 Conflict、get 照样给出 URL，语句替换
    又只管我们自己那两条 sid——于是一个**公开可达**的候选色会被原样提交，新后端
    绕过 Edge 的全部鉴权直接暴露公网。健康门是 `lambda:invoke` 直调发现不了；
    smoke 打 Edge 域名也发现不了。

    红的条件：`update_function_url_config` 没被调用（旧行为——存在即当对）。
    """
    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    # 首次 create 冲突（URL 已存在），get 返回一个 **NONE** 的配置
    lam.create_function_url_config.side_effect = \
        lam.exceptions.ResourceConflictException()
    lam.get_function_url_config.side_effect = lambda **kw: {
        "FunctionUrl": _color_url(kw["Qualifier"]), "AuthType": "NONE"}

    with patch.object(d, "_lambda", return_value=lam):
        d.handler(dict(EVENT), None)

    fix = [c.kwargs for c in lam.update_function_url_config.call_args_list]
    assert fix and fix[0]["AuthType"] == "AWS_IAM" \
        and fix[0]["Qualifier"] == "blue", \
        f"AuthType=NONE 的候选色 URL 被原样接受了：{fix}"


def test_stray_policy_statements_on_the_candidate_color_are_removed(aws,
                                                                   monkeypatch):
    """候选色 resource policy 里**非预期 sid** 的语句必须被清掉。

    只替换自己那两条 sid 清不掉别的 sid 下塞进来的 Principal:* 之类的额外授权
    ——那同样让新后端绕过 Edge 公网可达（P1-5A 的另一半）。
    """
    import json as _json

    import deploy_lambda_site as d, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    lam.get_policy.side_effect = None
    lam.get_policy.return_value = {"Policy": _json.dumps({"Statement": [
        {"Sid": "edge-invoke", "Principal": {"AWS": "edge"}},
        {"Sid": "totally-legit-public-access", "Principal": "*"},
    ]})}

    with patch.object(d, "_lambda", return_value=lam):
        d.handler(dict(EVENT), None)

    removed = {c.kwargs["StatementId"]
               for c in lam.remove_permission.call_args_list}
    assert "totally-legit-public-access" in removed, \
        "非预期 sid 下的额外授权（Principal:*）没被清掉——新后端公网可达"
    assert removed - {"totally-legit-public-access"} <= \
        {"edge-invoke", "edge-invoke-function"}
