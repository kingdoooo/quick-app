#!/usr/bin/env python3
"""部署 M3 控制台（panel）。幂等可重跑。

流程：复制依赖模块 → 打 zip → 建/更新 IAM 角色 → 建/更新 Lambda →
Function URL（AWS_IAM，仅授权 edge role）→ 上传前端到版本化 S3 前缀 →
注册 console route。

关键约束（改动前先读）：
- Function URL **必须** AuthType=AWS_IAM，且 resource policy 恰好两条语句、
  Principal 是逐字符 exact 的 edge role ARN。2025-10 起需要
  InvokeFunctionUrl + InvokeFunction(InvokedViaFunctionUrl) 两条，缺一即 403；
  `AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（实测删光整个
  resource policy）。**缺 edge_role_arn 一律抛错中止，绝不 fallback 到宽权限**
  ——那会让 panel 的整套身份假设失效（handler.py 依赖"x-user-email 存在即
  请求来自 Edge"）。
- 环境变量**只下发 SSM 参数名**，明文密钥严禁进环境变量：
  GetFunctionConfiguration 会原样回显，拿到 JWT_SECRET 即可伪造任意用户会话。
- panel role 的 SSM 资源限定**精确** jwt-secret ARN，**不照抄 auth 的
  `parameter/site-builder/*` 前缀**（那是 auth 还要读 site-client-secret 的
  业务需要）——拿前缀等于被攻破时顺带交出 Cognito client secret。

用法：
    python3 deploy_panel.py                 # 全量
    python3 deploy_panel.py --skip-frontend # 只更新后端
"""
import argparse
import configparser
import io
import json
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

import boto3

HERE = Path(__file__).parent
CFG = configparser.ConfigParser(interpolation=None)
CFG.read(HERE.parent / "config.ini")


def _cfg(section: str, key: str, default: str | None = None) -> str:
    try:
        raw = CFG[section][key]
    except KeyError:
        if default is not None:
            return default
        sys.exit(f"config.ini 缺 [{section}] {key}")
    return raw.split("#")[0].split(";")[0].strip()


FN_NAME = "site-panel"
ROLE_NAME = "site-panel-role"
FUNCTION_URL_AUTH_TYPE = "AWS_IAM"
RUNTIME = "python3.13"

# 构建时复制进包的模块。**四个都必需**：
#   common.py / permissions.py —— 授权与表访问的单一真源
#   ops_log.py                 —— permissions.py import 它（M3 审计落点）
#   session.py                 —— upgrade code 与会话 JWT 的单一编解码实现
# 漏任何一个都是"单测全绿、部署后 ImportError"，由
# test_copy_files_covers_every_local_module_panel_imports 按传递闭包核对。
COPY_FILES = ("common.py", "permissions.py", "ops_log.py", "session.py")


def _region() -> str:
    return _cfg("Platform", "region")


def _account() -> str:
    return _cfg("Platform", "account_id")


def _base_domain() -> str:
    return _cfg("Platform", "base_domain")


def console_host() -> str:
    return f"console.{_base_domain()}"


def frontend_prefix(version: str | None = None) -> str:
    """S3 里前端资源的版本化前缀。旧版本保留以便回滚（同站点前端模式）。

    **不带尾斜杠**，与 `register_route.py` 写站点 `static_prefix` 的形态一致
    （`sites/{site_id}/{job_id}`）。Edge 的静态改写是
    `f"/{route['static_prefix']}{path}"` 且 `path` 已以 `/` 开头——尾斜杠会拼出
    `platform/console/v1//index.html`，与上传的
    `platform/console/v1/index.html` **不是同一个对象**，控制台整站 403。
    两侧单测各自都会绿（一边只看前缀开头、一边只看拼接不报错），所以由
    `tests/test_frontend_contract.py::test_edge_static_key_matches_what_deploy_panel_uploads`
    用**真实 Edge 代码**逐字符比对两边的 key。
    """
    v = version or _cfg("Panel", "console_version", "v1")
    return f"platform/console/{v}"


def function_url_statements(edge_role_arn: str) -> list[dict]:
    """Function URL 的两条 resource policy 语句。

    **缺 edge_role_arn 或给通配一律抛错**：fallback 到 `Principal:*` 会让
    Function URL 全网可调，而 handler.py 把"x-user-email 存在"当作"请求经过
    Edge"的证据——两者一起失效意味着任何人都能伪造任意身份调用面板 API。
    """
    arn = (edge_role_arn or "").strip()
    if not arn:
        raise ValueError(
            "config.ini [Deployer] edge_role_arn 为空——Function URL 的调用者"
            "必须绑定到 exact edge role，不能放宽。请先部署路由层并回填该值")
    if "*" in arn or not arn.startswith("arn:aws:iam::"):
        raise ValueError(f"edge_role_arn 必须是精确的 IAM role ARN: {arn!r}")
    return [
        {"StatementId": "edge-invoke-url",
         "Action": "lambda:InvokeFunctionUrl",
         "Principal": arn,
         "FunctionUrlAuthType": FUNCTION_URL_AUTH_TYPE},
        # 2025-10 起 InvokeFunctionUrl 单条不够，缺 InvokeFunction 即 403。
        # InvokedViaFunctionUrl 把它限定为仅经 Function URL 调用。
        {"StatementId": "edge-invoke-function",
         "Action": "lambda:InvokeFunction",
         "Principal": arn,
         "InvokedViaFunctionUrl": True},
    ]


def role_statements() -> list[dict]:
    """panel 执行角色的 inline policy。

    收窄取向逐条说明：
      · sites 表：读 + UpdateItem，**无 PutItem/DeleteItem**——整条覆盖能绕过
        owner 判定重写站点归属（MCP 侧同样禁止，contract test 全表扫描锁定）；
      · jobs 表：Get/Query/PutItem——undeploy 要建 job，且要读部署历史；
      · admins 表：读写都要（permissions 的事务维护 __count__ sentinel），
        但 panel **代码**里禁止 raw 写，由 Task 6 的 AST 断言保证；
      · 路由表：**仅 UpdateItem**——Put 能整条切流、Delete 能摘掉站点；
      · ops-log：**仅 PutItem**，审计 append-only；
      · session-codes：PutItem（jti 一次性消费的条件写）；
      · SSM：**精确** jwt-secret ARN + kms:Decrypt 带 ViaService。
    """
    region, acct = _region(), _account()
    tbl = f"arn:aws:dynamodb:{region}:{acct}:table"
    routing = _cfg("Platform", "routing_table")
    return [
        {"Sid": "SitesReadAndScopedUpdate", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"],
         "Resource": [f"{tbl}/site-sites", f"{tbl}/site-sites/index/*"]},
        {"Sid": "JobsReadAndCreate", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem"],
         "Resource": [f"{tbl}/site-deploy-jobs",
                      f"{tbl}/site-deploy-jobs/index/*"]},
        {"Sid": "AdminsViaPermissionsModule", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:PutItem",
                    "dynamodb:UpdateItem", "dynamodb:DeleteItem",
                    "dynamodb:ConditionCheckItem"],
         "Resource": f"{tbl}/site-admins"},
        # ConditionCheckItem 是**事务必需**的，不是多给的：write_permissions 在
        # "站点还没首次部署成功（无 route item）"时走降级事务，其中对路由表做的是
        # `attribute_not_exists(subdomain)` 的 ConditionCheck。缺这个 action 时
        # 该路径以 AccessDeniedException 收场 → panel 返回 500。
        # **实测过**：moto 不校验 IAM，所以 144 个单测全绿，真机上"对无 route 的
        # 站点做任何写操作"全部 500（Task 14 Step 3 真机验收发现）。
        # MCP 侧的同一张表早就带着它（deploy_agentcore.py 的 RoutingProjection，
        # 注释写明"register_route / write_permissions 的事务需要"）——panel 漏了。
        # 仍然**没有 Put/Delete**：update-only 的收窄取向不变（Put 能整条切流、
        # Delete 能摘掉站点），由 test_panel_role_routing_table_is_update_only 锁定。
        {"Sid": "RoutingProjectionUpdateOnly", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem",
                    "dynamodb:ConditionCheckItem"],
         "Resource": f"{tbl}/{routing}"},
        {"Sid": "OpsLogAppendOnly", "Effect": "Allow",
         "Action": "dynamodb:PutItem",
         "Resource": f"{tbl}/site-ops-log"},
        {"Sid": "SessionCodesConsume", "Effect": "Allow",
         "Action": "dynamodb:PutItem",
         "Resource": f"{tbl}/site-session-codes"},
        {"Sid": "ReadJwtSecretOnly", "Effect": "Allow",
         "Action": "ssm:GetParameter",
         "Resource": f"arn:aws:ssm:{region}:{acct}:parameter/site-builder/jwt-secret"},
        {"Sid": "DecryptViaSSM", "Effect": "Allow",
         "Action": "kms:Decrypt", "Resource": "*",
         "Condition": {"StringEquals": {
             "kms:ViaService": f"ssm.{region}.amazonaws.com"}}},
        {"Sid": "InvokeUndeploy", "Effect": "Allow",
         "Action": "lambda:InvokeFunction",
         "Resource": f"arn:aws:lambda:{region}:{acct}:function:site-deployer-undeploy"},
        {"Sid": "Logs", "Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                    "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{FN_NAME}*"},
    ]


def lambda_environment() -> dict:
    """Lambda 环境变量。**只有参数名，没有明文密钥**（见模块 docstring）。"""
    return {
        "JOBS_TABLE": "site-deploy-jobs",
        "SITES_TABLE": "site-sites",
        "ADMINS_TABLE": "site-admins",
        "OPS_LOG_TABLE": "site-ops-log",
        "SESSION_CODES_TABLE": "site-session-codes",
        "ROUTING_TABLE": _cfg("Platform", "routing_table"),
        "BASE_DOMAIN": _base_domain(),
        "CONSOLE_HOST": console_host(),
        "UNDEPLOY_FN": "site-deployer-undeploy",
        "JWT_SECRET_PARAM": "/site-builder/jwt-secret",
    }


def console_route_item(function_url: str) -> dict:
    """routing 表里的 console 记录。

    route_mode=split：`/api/*` 走 Function URL，其余走 S3 静态前缀。
    require_auth=True：面板必须登录才能访问。
    owner="platform" 只是**记录**——Edge 判平台身份只认 host 白名单
    （origin_request.PLATFORM_SUBDOMAINS），绝不读这个可写字段。
    """
    return {"subdomain": "console",
            "route_mode": "split",
            "api_target": function_url.rstrip("/"),
            "static_prefix": frontend_prefix(),
            "require_auth": True,
            "allowed_users": "org",
            "owner": "platform",
            "collaborators": []}


def _build_zip() -> bytes:
    """把 panel 模块 + 复制来的依赖打成 zip（内存里，不落盘残留）。"""
    fn_dir = HERE.parent / "deployer" / "functions"
    auth_dir = HERE.parent / "auth"
    staged = []
    for name in COPY_FILES:
        src = fn_dir / name
        if not src.exists():
            src = auth_dir / name
        if not src.exists():
            sys.exit(f"复制清单里的 {name} 找不到源文件")
        dst = HERE / name
        shutil.copyfile(src, dst)
        staged.append(dst)
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for py in sorted(HERE.glob("*.py")):
                if py.name == "deploy_panel.py":
                    continue
                z.write(py, py.name)
        return buf.getvalue()
    finally:
        for p in staged:
            p.unlink(missing_ok=True)


def ensure_role() -> str:
    iam = boto3.client("iam")
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]})
    created = False
    try:
        arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=ROLE_NAME,
                                      PolicyDocument=trust)
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=ROLE_NAME,
                              AssumeRolePolicyDocument=trust,
                              Description="M3 console panel Lambda",
                              Tags=[{"Key": "project", "Value": "site-builder"}]
                              )["Role"]["Arn"]
        created = True
    iam.put_role_policy(
        RoleName=ROLE_NAME, PolicyName="panel-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": role_statements()}))
    if created:
        time.sleep(10)      # IAM 传播
    return arn


def ensure_function(role_arn: str, code: bytes) -> str:
    lam = boto3.client("lambda", region_name=_region())
    env = {"Variables": lambda_environment()}
    try:
        lam.get_function(FunctionName=FN_NAME)
        lam.update_function_code(FunctionName=FN_NAME, ZipFile=code)
        lam.get_waiter("function_updated").wait(FunctionName=FN_NAME)
        lam.update_function_configuration(
            FunctionName=FN_NAME, Role=role_arn, Handler="handler.handler",
            Runtime=RUNTIME, Timeout=30, MemorySize=512, Environment=env)
        lam.get_waiter("function_updated").wait(FunctionName=FN_NAME)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):
            try:
                lam.create_function(
                    FunctionName=FN_NAME, Runtime=RUNTIME, Role=role_arn,
                    Handler="handler.handler", Code={"ZipFile": code},
                    Timeout=30, MemorySize=512, Environment=env,
                    Tags={"project": "site-builder"})
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 5:
                    raise
                time.sleep(5)   # 新角色尚未传播
        lam.get_waiter("function_active").wait(FunctionName=FN_NAME)

    try:
        url = lam.create_function_url_config(
            FunctionName=FN_NAME,
            AuthType=FUNCTION_URL_AUTH_TYPE)["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        cur = lam.get_function_url_config(FunctionName=FN_NAME)
        if cur["AuthType"] != FUNCTION_URL_AUTH_TYPE:
            # 幂等纠正：绝不容忍线上是 NONE
            lam.update_function_url_config(
                FunctionName=FN_NAME, AuthType=FUNCTION_URL_AUTH_TYPE)
        url = cur["FunctionUrl"]

    for stmt in function_url_statements(_cfg("Deployer", "edge_role_arn", "")):
        kwargs = {k: v for k, v in stmt.items() if k != "StatementId"}
        try:
            lam.add_permission(FunctionName=FN_NAME,
                               StatementId=stmt["StatementId"], **kwargs)
        except lam.exceptions.ResourceConflictException:
            pass        # 幂等：同 StatementId 已存在
    return url


def upload_frontend() -> int:
    """上传 frontend/ 到版本化前缀。返回文件数。"""
    src = HERE / "frontend"
    if not src.exists():
        print("  frontend/ 不存在，跳过（Task 14 才移植视图层）")
        return 0
    s3 = boto3.client("s3", region_name=_region())
    bucket = f"site-frontend-{_account()}"
    # frontend_prefix() 不带尾斜杠（见其 docstring），这里显式补一个分隔符。
    prefix = frontend_prefix() + "/"
    types = {".html": "text/html", ".js": "application/javascript",
             ".css": "text/css", ".json": "application/json",
             ".svg": "image/svg+xml", ".ico": "image/x-icon"}
    n = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        key = prefix + str(path.relative_to(src))
        s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes(),
                      ContentType=types.get(path.suffix,
                                            "application/octet-stream"),
                      # 面板资源版本化，但仍不长缓存：改动要能立刻生效
                      CacheControl="no-cache")
        n += 1
    return n


def register_route(function_url: str) -> None:
    item = console_route_item(function_url)
    boto3.resource("dynamodb", region_name=_region()).Table(
        _cfg("Platform", "routing_table")).put_item(Item=item)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-frontend", action="store_true")
    args = ap.parse_args()

    print("① 校验 Function URL 授权配置（缺 edge_role_arn 即中止）")
    function_url_statements(_cfg("Deployer", "edge_role_arn", ""))

    print("② IAM 角色")
    role_arn = ensure_role()
    print(f"   {role_arn}")

    print("③ 打包并部署 Lambda")
    url = ensure_function(role_arn, _build_zip())
    print(f"   Function URL: {url}")

    if not args.skip_frontend:
        print("④ 上传前端")
        print(f"   {upload_frontend()} 个文件 → {frontend_prefix()}")

    print("⑤ 注册 console route")
    register_route(url)
    print(f"   https://{console_host()}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
