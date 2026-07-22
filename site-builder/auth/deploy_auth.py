"""部署 auth-service：打 zip（session.py+login_handler.py+pyjwt 依赖）→ 建/更新 Lambda
→ Function URL(NONE) → 生成 JWT_SECRET 存 SSM → 路由表注册 subdomain=auth。幂等可重跑。"""
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
    try:
        url = lam.create_function_url_config(FunctionName=FN, AuthType="NONE")["FunctionUrl"]
        lam.add_permission(FunctionName=FN, StatementId="public-url",
                           Action="lambda:InvokeFunctionUrl", Principal="*",
                           FunctionUrlAuthType="NONE")
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=FN)["FunctionUrl"]
    ddb.put_item(TableName=CFG["Platform"]["routing_table"], Item={
        "subdomain": {"S": "auth"}, "site_id": {"S": "auth-service"},
        "route_mode": {"S": "api-only"},  # 全路径走 Lambda（/login 不匹配 /api/*）
        "static_prefix": {"S": ""}, "api_target": {"S": url.rstrip("/")},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "platform"}})
    print(f"auth-service: {url}  →  https://auth.{BASE}/")


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
