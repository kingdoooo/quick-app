from unittest.mock import MagicMock, patch

LWA_ARN = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"

EVENT = {"job_id": "job-1", "site_id": "s-1",
         "manifest": {"backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080},
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "notes", "pk": "id"}]}},
         "env_vars": {"TABLE_NOTES": "site-data-s-1-notes"},
         "backend_zip_key": "artifacts/job-1/backend.zip"}


def _lam_mock(exists: bool):
    lam = MagicMock()
    if not exists:
        class NF(Exception): pass
        lam.exceptions.ResourceNotFoundException = NF
        lam.get_function.side_effect = NF()
        class RC(Exception): pass
        lam.exceptions.ResourceConflictException = RC
    else:
        lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
        lam.exceptions.ResourceConflictException = type("RC", (Exception,), {})
    lam.create_function_url_config.return_value = {
        "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/"}
    lam.get_function_url_config.return_value = {
        "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/"}
    return lam


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
