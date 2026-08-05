"""部署 auth-service：打 zip（session.py+login_handler.py+pyjwt 依赖）→ 建/更新 Lambda
→ Function URL(AWS_IAM，仅 Edge role 可调) → 生成 JWT_SECRET 存 SSM
→ 路由表注册 subdomain=auth → pre-token-generation 触发器（email 注入 access
token，部署 MCP 的 owner 识别依赖它）。幂等可重跑。"""
import configparser
import io
import re
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
        "USER_POOL_ID": CFG["Cognito"]["user_pool_id"],
        # email 是授权主键，而联邦 email 默认 unverified——见 login_handler 的
        # REQUIRE_EMAIL_VERIFIED。默认 "true"；只有接入不发该 claim 的 IdP 时
        # 才在 config.ini 里设 false。**必须显式下发**：漏了这一项时 Lambda
        # 环境变量缺失、代码回落默认值（true），行为仍然安全，但配置里写的
        # false 不生效——运维会以为关掉了却没关。
        "REQUIRE_EMAIL_VERIFIED": _require_email_verified_cfg()}}
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


def _require_email_verified_cfg() -> str:
    """config.ini [IdP] require_email_verified → Lambda 环境变量的字符串值。

    默认 "true"（缺 section / 缺键 / 空值都算默认）。只有显式写成 false
    才关闭——拼错（yes/0/off 之类）一律当 true，与"安全开关默认开、
    写错时不静默降级"的取向一致。
    """
    raw = ""
    if CFG.has_section("IdP"):
        raw = CFG["IdP"].get("require_email_verified", "")
    # configparser 保留行内注释，先切掉再判断
    head = raw.split("#")[0].split(";")[0].strip().lower()
    return "false" if head == "false" else "true"


def pool_update_params(cog, pool: dict) -> dict:
    """describe_user_pool 的结果 → update_user_pool 可接受的**完整**参数。

    **本函数是 deploy_pool.py 与本文件的唯一实现**（deploy_pool 直接 import
    它）。两边各留一份手抄白名单是这个坑上一次的形态：本文件那份连
    LambdaConfig 都没有，于是挂触发器时会把它自己刚设的值又清掉。

    为什么不能用手工白名单：update_user_pool 是整体替换语义，官方要求请求
    携带全部既有配置，遗漏项恢复默认值。手抄名单**必然随 AWS 加字段而腐烂**
    ——实测当前 botocore 里可保留却不在旧名单上的有 10 项，包括
    UserPoolAddOns（threat protection）、DeviceConfiguration、SmsConfiguration、
    UserPoolTags。即"幂等重跑"会静默关掉威胁防护与短信配置。

    按 service model 动态求交：describe 输出成员 ∩ update 输入成员。
    """
    sm = cog.meta.service_model
    describe_members = set(sm.operation_model(
        "DescribeUserPool").output_shape.members["UserPool"].members)
    update_members = set(sm.operation_model(
        "UpdateUserPool").input_shape.members)
    kwargs = {k: v for k, v in pool.items()
              if k in describe_members & update_members}
    # describe 回传的废弃字段，与 PasswordPolicy.TemporaryPasswordValidityDays
    # 同传会被 update_user_pool 拒绝（一期实测）
    if isinstance(kwargs.get("AdminCreateUserConfig"), dict):
        kwargs["AdminCreateUserConfig"] = {
            k: v for k, v in kwargs["AdminCreateUserConfig"].items()
            if k != "UnusedAccountValidityDays"}
    return kwargs


def ensure_pre_token_trigger(role_arn: str, pool_id: str | None = None) -> None:
    """部署 pre-token-generation V2 Lambda 并挂到用户池。

    真机钉死（2026-07-29，AGENTCORE-SPIKE.md §7）：部署 MCP 网关只接受
    access token，而 Cognito access token 默认不含 email——owner 识别全靠
    这个触发器把 email 注入 access token。要求用户池 Essentials+ tier。

    pool_id 显式传入时用它（deploy_pool.py 建新 pool 后立即挂载）；
    默认取 config.ini 的当前 pool。
    """
    fn = "site-auth-pre-token"
    pool_id = pool_id or CFG["Cognito"]["user_pool_id"]
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
    # StatementId 必须带 pool 标识：固定 id + 吞掉 ResourceConflictException
    # 会让新 pool 的授权永远加不上（旧语句已占用该 id，但它的 SourceArn 绑的是
    # 旧 pool）→ 新 pool 调用触发器被拒 → email/idp claim 注入失败，
    # MCP 的 owner 识别整条链断掉，token 签发本身也可能报 trigger 错误。
    # 迁移期新旧两条语句并存，验证通过后再删旧的。
    sid = "cognito-invoke-" + re.sub(r"[^A-Za-z0-9-]", "-", pool_id)
    try:
        lam.add_permission(FunctionName=fn, StatementId=sid,
                           Action="lambda:InvokeFunction",
                           Principal="cognito-idp.amazonaws.com",
                           SourceArn=f"arn:aws:cognito-idp:{REGION}:"
                                     f"{CFG['Platform']['account_id']}:userpool/{pool_id}")
        print(f"  已授权 {pool_id} 调用 {fn}（{sid}）")
    except lam.exceptions.ResourceConflictException:
        pass  # 同一 pool 重复运行，幂等
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    cfg = pool.get("LambdaConfig", {}).get("PreTokenGenerationConfig", {})
    if cfg.get("LambdaArn") == fn_arn and cfg.get("LambdaVersion") == "V2_0":
        return  # 已挂好，不动用户池
    kwargs = pool_update_params(cog, pool)
    # **在现有 LambdaConfig 上改这一项，不要整体替换**：update_user_pool 是
    # 整体替换语义，而 LambdaConfig 自己也是一个整体——直接赋一个只含
    # PreTokenGenerationConfig 的 dict 会把 pool 上其他触发器
    # （PreSignUp / PostAuthentication / CustomMessage……）全部摘掉，
    # 而 Cognito 侧不会报错：那些触发器就此静默失效。
    lambda_cfg = dict(pool.get("LambdaConfig") or {})
    lambda_cfg["PreTokenGenerationConfig"] = {
        "LambdaVersion": "V2_0", "LambdaArn": fn_arn}
    # LambdaConfig 里 V1 的 PreTokenGeneration（string）与 V2 的
    # PreTokenGenerationConfig（structure）是两个并存字段（已对 botocore 的
    # service model 核实）。pool 上原本挂着 V1 时把它对齐到同一个函数：
    # 留一个指向旧函数的 V1 指针，会让"当前生效的是哪个版本"变成一个需要
    # 现场翻配置才能回答的问题，而两版的 event 结构并不相同。
    if "PreTokenGeneration" in lambda_cfg:
        lambda_cfg["PreTokenGeneration"] = fn_arn
    kwargs["LambdaConfig"] = lambda_cfg
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
