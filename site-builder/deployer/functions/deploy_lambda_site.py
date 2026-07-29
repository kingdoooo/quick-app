"""SFN 步骤 4：per-site 执行角色 + 站点 Lambda——zip + LWA Layer（禁止镜像模式）。
站点代码不可信：角色带 PermissionsBoundary，inline policy 精确到本站点资源。"""
import os
import time

import boto3

import common

LWA_LAYER = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"


def _lambda():
    return boto3.client("lambda")


# 角色创建/授权逻辑集中在 common：provision_dsql 也要用它（AWS IAM GRANT 要求
# IAM 角色先存在），两处各写一份必然漂移。
_ensure_site_role = common.ensure_site_role


def _ensure_log_group(fn: str) -> None:
    """预建站点日志组并设保留期。Lambda 首次执行会自动建组但不设 retention
    （永久保留）；这里先建好，站点日志 30 天自动过期。undeploy 时整组删除。"""
    logs = boto3.client("logs")
    name = f"/aws/lambda/{fn}"
    try:
        logs.create_log_group(logGroupName=name)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName=name, retentionInDays=30)


def handler(event, context):
    common.update_job(event["job_id"], phase="deploy-backend")
    edge_role_arn = os.environ["EDGE_ROLE_ARN"]  # 缺失即 KeyError——不允许 * fallback
    lam = _lambda()
    fn = f"site-{event['site_id']}"
    _ensure_log_group(fn)
    engine = event["manifest"].get("database", {}).get("engine", "none")
    role_arn = _ensure_site_role(event["site_id"], engine)
    env = {"AWS_LAMBDA_EXEC_WRAPPER": "/opt/bootstrap", "PORT": "8080",
           "AWS_LWA_INVOKE_MODE": "BUFFERED", **event.get("env_vars", {})}
    code = {"S3Bucket": os.environ["ARTIFACTS_BUCKET"], "S3Key": event["backend_zip_key"]}
    runtime = event["manifest"]["backend"]["runtime"]

    try:
        lam.get_function(FunctionName=fn)
        lam.update_function_code(FunctionName=fn, **code)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
        lam.update_function_configuration(
            FunctionName=fn, Runtime=runtime, Handler="run.sh", Role=role_arn,
            Layers=[LWA_LAYER], Environment={"Variables": env},
            MemorySize=512, Timeout=30)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):  # 新建 IAM 角色传播延迟
            try:
                lam.create_function(
                    FunctionName=fn, Runtime=runtime, Handler="run.sh",
                    Role=role_arn, Code=code,
                    Layers=[LWA_LAYER], Environment={"Variables": env},
                    MemorySize=512, Timeout=30,
                    Tags={"project": "site-builder", "site_id": event["site_id"]})
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 5:
                    raise
                time.sleep(5)
        lam.get_waiter("function_active").wait(FunctionName=fn)

    try:
        url = lam.create_function_url_config(FunctionName=fn,
                                             AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
    # 2025-10 起新建 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两个权限
    # （AWS 官方文档 urls-auth）；只给前者会让 Edge 调用返回 403。
    # InvokedViaFunctionUrl 把 InvokeFunction 限定为仅经 Function URL 调用。
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke",
                           Action="lambda:InvokeFunctionUrl",
                           Principal=edge_role_arn,
                           FunctionUrlAuthType="AWS_IAM")
    except lam.exceptions.ResourceConflictException:
        pass
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke-function",
                           Action="lambda:InvokeFunction",
                           Principal=edge_role_arn,
                           InvokedViaFunctionUrl=True)
    except lam.exceptions.ResourceConflictException:
        pass

    event["api_target"] = url.rstrip("/")
    return event
