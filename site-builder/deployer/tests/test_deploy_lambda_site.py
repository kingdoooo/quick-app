import io
import json
from unittest.mock import MagicMock, patch

LWA_ARN = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"

# 未带 Qualifier 的 Function URL 调用返回的 URL。**函数级 URL 这条路还活着**：
# 当下的 handler 仍给函数本身挂 URL，B2 才改成按颜色挂。两种形态在本 mock 里并存，
# 所以 B1 加颜色支持不必改既有用例的期望值。
LEGACY_URL = "https://xyz.lambda-url.us-east-1.on.aws/"

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

    def _get_url(FunctionName, Qualifier=None):
        if Qualifier is None:            # 函数级 URL（B2 之前的形态）
            return {"FunctionUrl": LEGACY_URL}
        if Qualifier in colors:
            return {"FunctionUrl": _color_url(Qualifier)}
        raise lam.exceptions.ResourceNotFoundException()
    lam.get_function_url_config.side_effect = _get_url

    def _create_url(**kw):
        q = kw.get("Qualifier")
        return {"FunctionUrl": LEGACY_URL if q is None else _color_url(q)}
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
    assert out["api_target"] == "https://xyz.lambda-url.us-east-1.on.aws"

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
    lam = _lam_mock(exists=True)
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
