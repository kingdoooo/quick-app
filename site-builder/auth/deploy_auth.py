"""部署 auth-service：打 zip（session.py+login_handler.py+pyjwt 依赖）→ 建/更新 Lambda
→ Function URL(AWS_IAM，仅 Edge role 可调) → 生成 JWT_SECRET 存 SSM
→ 路由表注册 subdomain=auth → pre-token-generation 触发器（email 注入 access
token，部署 MCP 的 owner 识别依赖它）。幂等可重跑。"""
import configparser
import io
import secrets
import subprocess
import tempfile
import zipfile
from pathlib import Path

import boto3

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parent.parent / "config.ini")
REGION = CFG["Platform"]["region"]
BASE = CFG["Platform"]["base_domain"]
FN = "site-auth-service"

ssm = boto3.client("ssm", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
ddb = boto3.client("dynamodb", region_name=REGION)
iam = boto3.client("iam")


def ensure_secret(name: str, generate) -> str:
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        val = generate()
        ssm.put_parameter(Name=name, Value=val, Type="SecureString")
        return val


def build_zip() -> bytes:
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["python3", "-m", "pip", "install", "-r", str(src / "requirements.txt"),
                        "-t", td, "-q", "--platform", "manylinux2014_x86_64",
                        "--only-binary", ":all:", "--python-version", "3.13"], check=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in Path(td).rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(td))
            z.write(src / "session.py", "session.py")
            z.write(src / "login_handler.py", "login_handler.py")
        return buf.getvalue()


def main():
    jwt_secret = ensure_secret("/site-builder/jwt-secret", lambda: secrets.token_hex(32))
    client_secret = ssm.get_parameter(Name="/site-builder/site-client-secret",
                                      WithDecryption=True)["Parameter"]["Value"]
    role_arn = ensure_lambda_role()
    env = {"Variables": {
        "JWT_SECRET": jwt_secret,
        "COGNITO_DOMAIN": CFG["Cognito"]["domain"],
        "CLIENT_ID": CFG["Cognito"]["site_client_id"],
        "CLIENT_SECRET": client_secret,
        "BASE_DOMAIN": BASE,
        "USER_POOL_ID": CFG["Cognito"]["user_pool_id"]}}
    code = build_zip()
    try:
        lam.get_function(FunctionName=FN)
        lam.update_function_code(FunctionName=FN, ZipFile=code)
        lam.get_waiter("function_updated").wait(FunctionName=FN)
        lam.update_function_configuration(FunctionName=FN, Environment=env)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_function(FunctionName=FN, Runtime="python3.13",
                            Handler="login_handler.handler", Role=role_arn,
                            Code={"ZipFile": code}, Timeout=15, MemorySize=256,
                            Environment=env)
        lam.get_waiter("function_active").wait(FunctionName=FN)
    # AWS_IAM 而非 NONE：NONE + Principal:* 是 world-accessible，会触发安全扫描
    # 告警甚至自动处置（实际发生过：resource policy 被整个删除，连 Edge 路径一起 403）。
    # Edge 的 _route_to_lambda 对所有 Lambda URL 路由（含 api-only）都签 SigV4，
    # 所以只授权 edge role 即可，公网直连被 IAM 挡住。
    try:
        url = lam.create_function_url_config(FunctionName=FN, AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        cfg = lam.get_function_url_config(FunctionName=FN)
        url = cfg["FunctionUrl"]
        if cfg["AuthType"] != "AWS_IAM":
            lam.update_function_url_config(FunctionName=FN, AuthType="AWS_IAM")
    # 清掉历史的 Principal:* 语句（老版本部署留下的；已被 mitigate 删除时容忍不存在）
    for sid in ("public-url", "public-url-invoke"):
        try:
            lam.remove_permission(FunctionName=FN, StatementId=sid)
        except lam.exceptions.ResourceNotFoundException:
            pass
    # 2025-10 起 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两条语句
    # （缺一个就 403）。两条各自幂等；与 deploy_lambda_site.py 的站点授权同模式。
    edge_role_arn = CFG["Deployer"]["edge_role_arn"]
    for sid, action, extra in (
        ("edge-invoke", "lambda:InvokeFunctionUrl", {"FunctionUrlAuthType": "AWS_IAM"}),
        ("edge-invoke-function", "lambda:InvokeFunction", {"InvokedViaFunctionUrl": True}),
    ):
        try:
            lam.add_permission(FunctionName=FN, StatementId=sid, Action=action,
                               Principal=edge_role_arn, **extra)
        except lam.exceptions.ResourceConflictException:
            pass
    ddb.put_item(TableName=CFG["Platform"]["routing_table"], Item={
        "subdomain": {"S": "auth"}, "site_id": {"S": "auth-service"},
        "route_mode": {"S": "api-only"},  # 全路径走 Lambda（/login 不匹配 /api/*）
        "static_prefix": {"S": ""}, "api_target": {"S": url.rstrip("/")},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "platform"}})
    ensure_pre_token_trigger(role_arn)
    print(f"auth-service: {url}  →  https://auth.{BASE}/")


# update-user-pool 是整体替换语义——只回传这些已知可变字段，避免误清其他配置。
_POOL_MUTABLE = ("Policies", "DeletionProtection", "AutoVerifiedAttributes",
                 "MfaConfiguration", "EmailConfiguration", "AdminCreateUserConfig",
                 "AccountRecoverySetting", "UserAttributeUpdateSettings",
                 "VerificationMessageTemplate", "UserPoolTier")


def ensure_pre_token_trigger(role_arn: str) -> None:
    """部署 pre-token-generation V2 Lambda 并挂到用户池。

    真机钉死（2026-07-29，AGENTCORE-SPIKE.md §7）：部署 MCP 网关只接受
    access token，而 Cognito access token 默认不含 email——owner 识别全靠
    这个触发器把 email 注入 access token。要求用户池 Essentials+ tier。
    """
    fn = "site-auth-pre-token"
    pool_id = CFG["Cognito"]["user_pool_id"]
    cog = boto3.client("cognito-idp", region_name=REGION)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(Path(__file__).parent / "pre_token_email.py", "pre_token_email.py")
    code = buf.getvalue()
    try:
        lam.get_function(FunctionName=fn)
        lam.update_function_code(FunctionName=fn, ZipFile=code)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_function(FunctionName=fn, Runtime="python3.13",
                            Handler="pre_token_email.handler", Role=role_arn,
                            Code={"ZipFile": code}, Timeout=5, MemorySize=128)
        lam.get_waiter("function_active").wait(FunctionName=fn)
    fn_arn = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
    try:
        lam.add_permission(FunctionName=fn, StatementId="cognito-invoke",
                           Action="lambda:InvokeFunction",
                           Principal="cognito-idp.amazonaws.com",
                           SourceArn=f"arn:aws:cognito-idp:{REGION}:"
                                     f"{CFG['Platform']['account_id']}:userpool/{pool_id}")
    except lam.exceptions.ResourceConflictException:
        pass
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    cfg = pool.get("LambdaConfig", {}).get("PreTokenGenerationConfig", {})
    if cfg.get("LambdaArn") == fn_arn and cfg.get("LambdaVersion") == "V2_0":
        return  # 已挂好，不动用户池
    kwargs = {k: pool[k] for k in _POOL_MUTABLE if k in pool}
    # describe 回传的废弃字段，与 PasswordPolicy.TemporaryPasswordValidityDays
    # 同传会被 update-user-pool 拒绝
    kwargs.get("AdminCreateUserConfig", {}).pop("UnusedAccountValidityDays", None)
    kwargs["LambdaConfig"] = {"PreTokenGenerationConfig": {
        "LambdaVersion": "V2_0", "LambdaArn": fn_arn}}
    cog.update_user_pool(UserPoolId=pool_id, **kwargs)
    print(f"pre-token trigger 已挂到 {pool_id}: {fn_arn}")


def ensure_lambda_role() -> str:
    name = "site-auth-service-role"
    try:
        return iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        r = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json_trust())
        iam.attach_role_policy(RoleName=name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
        import time; time.sleep(10)  # IAM 传播
        return r["Role"]["Arn"]


def json_trust() -> str:
    return ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')


if __name__ == "__main__":
    main()
