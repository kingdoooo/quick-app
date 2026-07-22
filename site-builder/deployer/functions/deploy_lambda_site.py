"""SFN 步骤 4：per-site 执行角色 + 站点 Lambda——zip + LWA Layer（禁止镜像模式）。
站点代码不可信：角色带 PermissionsBoundary，inline policy 精确到本站点资源。"""
import json
import os
import time

import boto3

import common

LWA_LAYER = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})


def _lambda():
    return boto3.client("lambda")


def _site_policy(site_id: str, engine: str) -> str:
    region, acct = "us-east-1", os.environ["ACCOUNT_ID"]
    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/site-{site_id}*"}]
    if engine == "dynamodb":
        statements.append({
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": f"arn:aws:dynamodb:{region}:{acct}:table/site-data-{site_id}-*"})
    elif engine == "dsql":
        statements.append({"Effect": "Allow", "Action": "dsql:DbConnect",
                           "Resource": "*"})  # 数据隔离由 per-site PG role 保证
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _ensure_site_role(site_id: str, engine: str) -> str:
    iam = boto3.client("iam")
    name = f"site-rt-{site_id}"
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=TRUST,
            PermissionsBoundary=os.environ["RUNTIME_BOUNDARY_ARN"],
            Tags=[{"Key": "project", "Value": "site-builder"},
                  {"Key": "site_id", "Value": site_id}])["Role"]["Arn"]
    iam.put_role_policy(RoleName=name, PolicyName="site-scope",
                        PolicyDocument=_site_policy(site_id, engine))
    return arn


def handler(event, context):
    common.update_job(event["job_id"], phase="deploy-backend")
    edge_role_arn = os.environ["EDGE_ROLE_ARN"]  # 缺失即 KeyError——不允许 * fallback
    lam = _lambda()
    fn = f"site-{event['site_id']}"
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
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke",
                           Action="lambda:InvokeFunctionUrl",
                           Principal=edge_role_arn,
                           FunctionUrlAuthType="AWS_IAM")
    except lam.exceptions.ResourceConflictException:
        pass

    event["api_target"] = url.rstrip("/")
    return event
