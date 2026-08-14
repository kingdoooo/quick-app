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
import hashlib
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

# 构建时复制进包的模块。**七个都必需**：
#   common.py / permissions.py —— 授权与表访问的单一真源
#   ops_log.py                 —— permissions.py import 它（M3 审计落点）
#   session.py                 —— upgrade code 与会话 JWT 的单一编解码实现
#   edge_caller.py             —— "调用者真是 Edge"的单一判定（handler 的第 ⓪ 步，
#                                 与 key-proxy 共用同一份，见该模块 docstring）
#   keystore.py                —— `site-api-keys` 的唯一访问层（api.py 只经它
#                                 碰这张表）。漏了它 api.py 顶层 import 就失败，
#                                 **所有**控制台 API 500——不只 Key 相关的
#   keygen.py                  —— keystore.py import 它（明文/哈希的唯一算法）
#   analytics.py               —— 访问统计的唯一读取层（二期 M5）。api.py 同样是
#                                 **顶层** import，所以漏它 = 所有控制台 API 500
#   access_rollup.py           —— analytics.py import 它的 day_stats（pv/uv 口径的
#                                 唯一定义）。两份会漂移成"今天的数与历史曲线口径
#                                 不同"，所以读取层不重写、直接 import
# 全部从 `deployer/functions/` 取（`_build_zip` 的两级查找会命中第一级）。
# 漏任何一个都是"单测全绿、部署后 ImportError"，由
# test_copy_files_covers_every_local_module_panel_imports 按传递闭包核对——
# **清单以那条断言为准**，不要照着记性加减（本清单曾经漏过 keystore.py）。
COPY_FILES = ("common.py", "permissions.py", "ops_log.py", "session.py",
              "edge_caller.py", "keystore.py", "keygen.py",
              "analytics.py", "access_rollup.py")


def _region() -> str:
    return _cfg("Platform", "region")


def _account() -> str:
    return _cfg("Platform", "account_id")


def _base_domain() -> str:
    return _cfg("Platform", "base_domain")


def console_host() -> str:
    return f"console.{_base_domain()}"


def frontend_content_version() -> str:
    """前端产物的内容指纹（12 位 hex），用作版本段。

    为什么不是 config 里的 `console_version = v1`（Codex 审查 2026-08-10
    P2-2）：那个值没人会记得改，于是每次前端修复都传到同一个 `v1/` 前缀里
    **原地覆盖**。真机核对过：`platform/console/` 下只有 v1 的三个对象，且
    桶未开版本控制——旧内容不可恢复，"可回滚"是句空话。

    改成由内容推导后，"改了前端"与"换了前缀"变成同一件事，不依赖人的记性。
    指纹覆盖**文件相对路径 + 内容**：只哈希内容会让"重命名文件"得到同一个
    版本；带上路径才能反映出增删改名。
    """
    src = HERE / "frontend"
    h = hashlib.sha256()
    for path in sorted(p for p in src.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(src)).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:12]


def frontend_prefix(version: str | None = None) -> str:
    """S3 里前端资源的版本化前缀。

    版本段默认是**内容指纹**（见 frontend_content_version），所以每个前缀
    一旦发布就**不可变**（immutable）：`upload_frontend` 拒绝往已存在且内容
    不同的前缀里写。旧版本因此自然留存，回滚 = 把 route 的 static_prefix
    指回旧前缀。**这不是靠 S3 版本控制**——那个桶没开。

    **不带尾斜杠**，与 `register_route.py` 写站点 `static_prefix` 的形态一致
    （`sites/{site_id}/{job_id}`）。Edge 的静态改写是
    `f"/{route['static_prefix']}{path}"` 且 `path` 已以 `/` 开头——尾斜杠会拼出
    `platform/console/v1//index.html`，与上传的
    `platform/console/v1/index.html` **不是同一个对象**，控制台整站 403。
    两侧单测各自都会绿（一边只看前缀开头、一边只看拼接不报错），所以由
    `tests/test_frontend_contract.py::test_edge_static_key_matches_what_deploy_panel_uploads`
    用**真实 Edge 代码**逐字符比对两边的 key。
    """
    # config 的 console_version 仍可作为**显式覆盖**（回滚到手工指定的前缀），
    # 但默认不再用它——留空即走内容指纹。
    v = version or _cfg("Panel", "console_version", "") or frontend_content_version()
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
      · api-keys：Get/Put/Update + 两个 GSI 的 Query，**无 DeleteItem**（吊销
        是置 `revoked` 而不是删行，删了就没有审计痕迹）、**无 Scan**；
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
        # 二期 M4：api.py 经 keystore 访问这张表。**index/\\* 不可省**——
        # 列 Key 走 email-index、吊销走 keyid-index，GSI 上的 Query 要的是
        # **索引 ARN** 而不是表 ARN。moto 不校验 IAM，所以漏了它单测全绿、
        # 真机 AccessDenied → 500（M3-FINDINGS §2.18 的同一形态：panel 曾漏
        # ConditionCheckItem，144 个单测全绿而真机全 500）。
        # 权限集不手抄：test_role_grants_every_api_keys_action_keystore_needs
        # 从 keystore.py 的操作与 IndexName 推导后交叉核对。
        {"Sid": "ApiKeysViaKeystore", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:PutItem",
                    "dynamodb:UpdateItem", "dynamodb:Query"],
         "Resource": [f"{tbl}/site-api-keys", f"{tbl}/site-api-keys/index/*"]},
        # 二期 M5：analytics.py 只对这两张表做 Query（明细按 site_date 分区、
        # 聚合按 site_id + date 区间），**没有任何写权限**——读取层不该能改数，
        # 明细的唯一写入者是 Edge、聚合的唯一写入者是 rollup Lambda。
        # 也**不给 Scan**：Scan 能跨站点读出别人站点的访问明细（含邮箱），而
        # 本层的每个查询都带 site_id 分区键，压根不需要它。
        # 没有 GSI，所以不需要 index/*（与 api-keys 那条刻意不同）。
        {"Sid": "AccessTablesQueryOnly", "Effect": "Allow",
         "Action": "dynamodb:Query",
         "Resource": [f"{tbl}/site-access-events", f"{tbl}/site-access-daily"]},
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


def edge_role_id(edge_role_arn: str) -> str:
    """Edge 执行角色的 **RoleId**（`AROA...`），给 handler 校验调用者用。

    为什么需要它而不能直接用 ARN（Codex 审查 2026-08-10 P1-1）：Edge 调过来
    的身份是 STS assumed-role 形态，`callerId` 是 `{RoleId}:{session_name}`，
    与 config 里的 `arn:aws:iam::<acct>:role/<name>` **永不相等**。真机实测
    （RoleId 本体按仓库红线打码成 `AROA<...>`——形态是这里唯一有信息量的
    部分，真值现查 `aws iam get-role`）：
        callerId: AROA<...>:us-east-1.ApplicationWebRouterStack-...
    RoleId 由 IAM 分配、STS 填写，调用方不可伪造，是这里唯一稳定的锚点。

    用 get_role 现查而不是让人往 config 里再抄一个值：手抄的第二份真源会漂移
    （本项目记录过"不变量被手抄多份"这一类缺陷）。
    """
    name = (edge_role_arn or "").strip().rsplit("/", 1)[-1]
    if not name:
        raise ValueError("edge_role_arn 为空，无法解析 Edge 角色名")
    role_id = boto3.client("iam").get_role(RoleName=name)["Role"]["RoleId"]
    if not role_id.startswith("AROA"):
        raise ValueError(f"解析出的 RoleId 形态不对: {role_id!r}")
    return role_id


def lambda_environment(edge_role_id_value: str = "") -> dict:
    """Lambda 环境变量。**只有参数名，没有明文密钥**（见模块 docstring）。

    EDGE_ROLE_ID 不是秘密（它是个公开的资源标识，不能用来签发任何东西），
    但**缺了它 handler 会拒绝所有请求**——见 edge_caller.caller_is_edge：
    "配置缺失就不检查"恰好是这个缺陷的原始形态，所以宁可整站拒绝。
    """
    return {
        "EDGE_ROLE_ID": edge_role_id_value,
        "JOBS_TABLE": "site-deploy-jobs",
        "SITES_TABLE": "site-sites",
        "ADMINS_TABLE": "site-admins",
        "OPS_LOG_TABLE": "site-ops-log",
        "SESSION_CODES_TABLE": "site-session-codes",
        # 二期 M4：keystore.py 读它（表名与 role_statements 的 api-keys 资源
        # 必须同名，由 test_role_grants_every_api_keys_action_keystore_needs
        # 交叉核对——它按这个环境变量的值去 role 里找资源）。
        "API_KEYS_TABLE": "site-api-keys",
        # 二期 M5：analytics.py 读这两个（api.py 经 analytics 访问访问明细与
        # 日聚合表）。缺任一个的症状是 KeyError → 500，而 conftest 里有值兜着
        # 所以单测看不出来——由 test_environment_covers_every_env_var_the_code_reads
        # 按进包清单的可达性闭包核对。表名与 role_statements 的 AccessTablesQueryOnly
        # 资源、以及 infra/app.py 建的两张表必须同名。
        "ACCESS_EVENTS_TABLE": "site-access-events",
        "ACCESS_DAILY_TABLE": "site-access-daily",
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


def ensure_function(role_arn: str, code: bytes, edge_role_id_value: str) -> str:
    lam = boto3.client("lambda", region_name=_region())
    env = {"Variables": lambda_environment(edge_role_id_value)}
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
    """上传 frontend/ 到版本化前缀。返回文件数。

    **版本前缀不可变**（Codex 审查 2026-08-10 P2-2）：前缀已存在且内容不同时
    直接中止。这是"旧版本可回滚"的技术前提——桶没开版本控制，一旦允许覆盖，
    旧产物就永久消失了（真机核对过：此前 `platform/console/v1/` 被反复覆盖，
    只剩当前一份）。
    同前缀同内容仍然放行：那是重跑部署脚本，本脚本的幂等契约不能破。
    """
    src = HERE / "frontend"
    if not src.exists():
        print("  frontend/ 不存在，跳过（Task 14 才移植视图层）")
        return 0
    s3 = boto3.client("s3", region_name=_region())
    bucket = f"site-frontend-{_account()}"
    # frontend_prefix() 不带尾斜杠（见其 docstring），这里显式补一个分隔符。
    prefix = frontend_prefix() + "/"

    # 已存在的对象逐个比 ETag（S3 的 ETag 对非分段上传就是 MD5；本目录都是
    # 几十 KB 的小文件，不会走分段）。**只要有一个不同就中止**——那说明这个
    # 前缀已经发布过别的构建，覆盖它等于销毁可回滚的旧版本。
    existing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    if existing.get("KeyCount"):
        local = {prefix + str(p.relative_to(src)):
                 hashlib.md5(p.read_bytes()).hexdigest()
                 for p in sorted(src.rglob("*")) if p.is_file()}
        for obj in existing.get("Contents", []):
            key, remote = obj["Key"], obj.get("ETag", "").strip('"')
            if key not in local or local[key] != remote:
                sys.exit(
                    f"前缀 {prefix} 已发布过**不同内容**（{key} 的 ETag 不一致）。\n"
                    f"版本前缀不可变：请先确认是否需要回滚，或改动前端让内容指纹"
                    f"变化后重跑。\n"
                    f"（当前指纹 {frontend_content_version()}；"
                    f"如需强制指定前缀，设 config.ini [Panel] console_version）")
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


def register_route(function_url: str, static_prefix: str | None = None) -> None:
    """写 console route。`static_prefix` 只在 `--skip-frontend` 时传。

    传值 = "保留线上现有前缀"。默认 None 走 `console_route_item` 里按**内容指纹**
    算出的新前缀（正常全量部署的语义）。见 main() 里那段注释：只部后端却把 route
    挪到未上传的前缀上，会让控制台整站 403 而部署脚本全程"成功"。
    """
    item = console_route_item(function_url)
    if static_prefix is not None:
        item["static_prefix"] = static_prefix
    boto3.resource("dynamodb", region_name=_region()).Table(
        _cfg("Platform", "routing_table")).put_item(Item=item)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-frontend", action="store_true")
    args = ap.parse_args()

    print("① 校验 Function URL 授权配置（缺 edge_role_arn 即中止）")
    edge_arn = _cfg("Deployer", "edge_role_arn", "")
    function_url_statements(edge_arn)
    # RoleId 现查：handler 用它确认调用者真是 Edge（同账号 IAM 身份能绕开
    # resource policy 直连，判定见 edge_caller.caller_is_edge——Task 1 把它提成
    # panel 与 key-proxy 共用的唯一实现，原来那个 handler._edge_caller_ok 已不
    # 存在）。查不到就中止——空值会让线上拒绝所有请求。
    eid = edge_role_id(edge_arn)
    print(f"   Edge RoleId: {eid}")

    print("② IAM 角色")
    role_arn = ensure_role()
    print(f"   {role_arn}")

    print("③ 打包并部署 Lambda")
    url = ensure_function(role_arn, _build_zip(), eid)
    print(f"   Function URL: {url}")

    if not args.skip_frontend:
        print("④ 上传前端")
        print(f"   {upload_frontend()} 个文件 → {frontend_prefix()}")

    print("⑤ 注册 console route")
    # **`--skip-frontend` 时绝不能把 route 挪到新算出来的前缀上。**
    # 2026-08-13 实测踩到：前缀是**前端内容的指纹**，所以改过前端之后即使这次
    # 只部后端，`frontend_prefix()` 也会算出一个新值——而 `--skip-frontend`
    # 跳过了上传，于是 route 指向一个**从未上传过的前缀**，控制台整站 403/404。
    # 症状还特别隐蔽：部署脚本全程"成功"，只有真去开页面才发现
    # （这次是 verify_deployed_components ⑦ 段的"首页对象存在"抓出来的）。
    # 正确语义：只部后端时保留线上现有前缀（那份前端还在，是可用的）。
    keep = None
    if args.skip_frontend:
        cur = boto3.resource("dynamodb", region_name=_region()).Table(
            _cfg("Platform", "routing_table")).get_item(
                Key={"subdomain": "console"}, ConsistentRead=True).get("Item")
        cur_prefix = str((cur or {}).get("static_prefix", ""))
        if not cur_prefix:
            sys.exit("--skip-frontend 但线上没有 console route（或没有 "
                     "static_prefix）——首次部署不能跳过前端")
        if cur_prefix != frontend_prefix():
            print(f"   ⚠️  前端内容已变（线上 {cur_prefix} → 本地算出 "
                  f"{frontend_prefix()}），但本次 --skip-frontend 没上传。")
            print("      **保留线上前缀**，不把 route 指向未上传的对象。"
                  "要发布新前端请去掉 --skip-frontend 重跑。")
        keep = cur_prefix
    register_route(url, static_prefix=keep)
    print(f"   https://{console_host()}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
