"""部署 auth-service：打 zip（login_handler.py + session.py + session_kms.py + verifier_env.py + 锁定依赖）
→ 建/更新 Lambda → Function URL(AWS_IAM，仅 Edge role 与 verifier 角色可调) → 路由表注册 subdomain=auth
→ pre-token-generation 触发器（email 注入 access token，部署 MCP 的 owner 识别依赖它）。幂等可重跑。

3c-final：会话签名密钥是两把 KMS 非对称 CMK（deployer 栈建），本脚本**不再生成任何会话密钥**——
它只在第一次写之前核对每个 RS kid 的 KMS 四项（`session_kms.precheck_keys`，spec §11.6 第 1 层），
并给执行角色授 `kms:Sign`（带算法与 `MessageType` 两个条件）+ `kms:GetPublicKey` 的精确 key ARN。
唯一还由本脚本 ensure 的 SSM 密钥是 auth 私有的 login-flow HMAC（spec §11.3 / ADR 0004）。
`[Verification]`（spec §11.7）开着时另建 `site-builder-verifier` 角色，并把它的两条 invoke 语句
交给共享的 Function URL 收敛。"""
import configparser
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import boto3

# 共享的 Function URL resource policy 实现（三个平台脚本 + 闸门共用；构建期 import，不进 auth 的部署包）
sys.path.insert(0, str(Path(__file__).parent.parent / "deployer" / "functions"))
sys.path.insert(0, str(Path(__file__).parent))   # 被 verify_deployed_components 按路径加载时也能找到同目录模块
import session_kms

from alarm_pipeline import ensure_alarm_pipeline
from function_url_policy import converge as converge_function_url_policy
from function_url_policy import expected_projection as function_url_projection
from function_url_policy import expected_statements as function_url_statements
from secrets_util import ensure_secret as _ensure_secret, precheck_parameters
from session_keys import (env_json, key_refs, kms_key_arns, load_session_keys, ssm_parameter_arns,
                          ssm_parameter_names)

FN = "site-auth-service"
CFG_PATH = Path(__file__).parent.parent / "config.ini"
_CFG: configparser.ConfigParser | None = None
_CLIENTS: dict[str, object] = {}


def cfg() -> configparser.ConfigParser:
    """**懒读**配置。形状照 mcp/server.py 的 _s3()/_sfn()（函数 + 模块级缓存）。

    模块级读会让 tests/test_requirements_locked.py 里那条截获真实 pip argv 的守卫
    在干净 clone 里被 skip（config.ini 是 gitignored，Codex 复审 P2-e 实测
    3 passed / 1 skipped）——而它是"依赖真的按 hash 装"的唯一证据。

    **不给缺配置留兜底默认值**：拿假值继续跑会把资源建到错的账号/区域上去。
    """
    global _CFG
    if _CFG is None:
        c = configparser.ConfigParser()
        if not c.read(CFG_PATH):
            raise SystemExit(f"缺少 {CFG_PATH}——从同目录 config.ini.example 复制并回填")
        _CFG = c
    return _CFG


def region() -> str:
    return cfg()["Platform"]["region"]


def base_domain() -> str:
    return cfg()["Platform"]["base_domain"]


def _client(service: str, *, regional: bool = True):
    """懒建 + **缓存** boto3 client。

    缓存不只是省时间：`except lam.exceptions.ResourceNotFoundException` 这种写法
    比对的是 client 实例上动态生成的异常类，每次新建 client 就有让 except 匹配不上
    的风险——那会把"函数不存在所以要创建"变成一次崩溃。
    """
    if service not in _CLIENTS:
        kw = {"region_name": region()} if regional else {}
        _CLIENTS[service] = boto3.client(service, **kw)
    return _CLIENTS[service]


def _ssm():
    return _client("ssm")


def _lam():
    return _client("lambda")


def _ddb():
    return _client("dynamodb")


def _iam():
    # IAM 是全局服务，原来这个 client 就不带 region_name
    return _client("iam", regional=False)


def _kms():
    """3c-final：部署前四项校验的 KMS client（本脚本只读 DescribeKey / GetPublicKey，从不签名）。"""
    return _client("kms")


def ensure_secret(name: str, generate) -> str:
    # 单一实现在 secrets_util.py；这里只是绑定本脚本的 client
    return _ensure_secret(name, generate, ssm=_ssm())


def build_zip() -> bytes:
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory() as td:
        # --require-hashes：清单里有 hash 但装的时候不校验，等于什么都没做。
        # 全量语义——任何一个包（含传递依赖）缺 hash 或对不上即整条 install
        # 失败，而不是静默装一个被替换过的包。requirements.txt 的平台/Python
        # 参数必须与下面这三个开关一致，理由见那个文件的头部。
        subprocess.run(["python3", "-m", "pip", "install", "--require-hashes",
                        "-r", str(src / "requirements.txt"),
                        "-t", td, "-q", "--platform", "manylinux2014_x86_64",
                        "--only-binary", ":all:", "--python-version", "3.13"], check=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in Path(td).rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(td))
            # login_handler 的本地依赖闭包：漏任一个 = Runtime.ImportModuleError = **整个 auth 502**
            # （2026-09-02 实测：verifier_env.py 漏进包，登录与 /console-session 全部 502）。
            # 清单由 tests/test_deploy_auth_package.py 按 AST 传递闭包核对，别照记性加减。
            for name in AUTH_PACKAGE_MODULES:
                z.write(src / name, name)
        return buf.getvalue()


# 进包的本地模块（handler + 它 import 的同目录模块）；与 panel 的 COPY_FILES 同一种"清单以闭包断言为准"的纪律
AUTH_PACKAGE_MODULES = ("login_handler.py", "session.py", "verifier_env.py", "session_kms.py")
CLIENT_SECRET_PARAM = "/site-builder/site-client-secret"

# ---- `[Verification]`：验收夹具签发器与它的调用者（spec §11.7 / ADR 0002）--------------------
VERIFIER_ROLE_NAME = "site-builder-verifier"
_PRINCIPAL_RE = re.compile(r"^arn:aws:iam::(\d{12}):(role|user)/[^*?]+$")


@dataclass(frozen=True)
class Verification:
    fixture_issuer: bool
    trusted_principals: tuple


def read_verification(c: configparser.ConfigParser, *, account: str) -> Verification:
    """`[Verification]`（spec §11.7）。段缺失 = 组件不存在（fixture_issuer=False）。开着时清单必须非空、每项都是
    **本账号**的精确 role/user ARN——通配会让"谁能签夹具会话"变成账号内任何人，而那是一条冒充路径。"""
    if not c.has_section("Verification"):
        return Verification(False, ())
    flag = c.get("Verification", "fixture_issuer", fallback="false").split("#")[0].strip().lower()
    if flag not in ("true", "false"):
        raise SystemExit(f"config.ini [Verification] fixture_issuer 必须是 true/false（当前 {flag!r}）")
    raw = c.get("Verification", "verifier_trusted_principals", fallback="").split("#")[0]
    principals = tuple(p.strip() for p in raw.split(",") if p.strip())
    if flag == "false":
        return Verification(False, ())
    bad = [p for p in principals if not _PRINCIPAL_RE.match(p) or _PRINCIPAL_RE.match(p).group(1) != account]
    if not principals or bad:
        raise SystemExit("config.ini [Verification] verifier_trusted_principals 必须是本账号精确 role/user ARN 的"
                         f"非空清单（不接受通配），拒绝部署（任何写都未发生）：坏项 {bad}，共 {len(principals)} 项")
    return Verification(True, principals)


def _verifier_invoke_statements(fn_arn: str, verifier_arn: str) -> list:
    """verifier 角色 inline policy 的两条语句：Action 与 Condition **从共享渲染器推导**（`function_url_policy`
    的 `expected_projection`），不在这里手写第二份。

    形态必须与 resource policy 侧逐字相同（AWS 文档 lambda/latest/dg/urls-auth）：
    `lambda:InvokeFunctionUrl` 配 `StringEquals lambda:FunctionUrlAuthType=AWS_IAM`，
    `lambda:InvokeFunction` 配 **`Bool lambda:InvokedViaFunctionUrl=true`**（操作符是 Bool 不是 StringEquals，
    条件键也不同）。identity 侧与 resource 侧的实际授权是两者求交：把第二条写成 `FunctionUrlAuthType`
    看上去很对，但那个键在 `InvokeFunction` 上不产生，条件永不满足 ⇒ verifier 调用 403，而两侧的单测
    各自都绿——所以这里只许有一个真源。传 `verifier_arn` 只为过渲染器那条精确 role ARN 校验，
    Principal 由本函数丢弃（identity policy 没有 Principal）。
    """
    out = []
    for _sid, (_effect, action, _principal, triples) in function_url_projection(verifier_arn).items():
        cond: dict = {}
        for op, key, val in triples:
            cond.setdefault(op, {})[key] = val
        sid = "InvokeAuthUrl" if action == "lambda:InvokeFunctionUrl" else "InvokeAuthViaUrl"
        out.append({"Sid": sid, "Effect": "Allow", "Action": action, "Resource": fn_arn, "Condition": cond})
    return out


def ensure_verifier_role(iam, verification: Verification, *, account: str, region: str):
    """`site-builder-verifier`（spec §11.7）：开 ⇒ 建 / 收敛并返回 ARN；关 ⇒ 存在则删并返回 None。
    信任策略只列显式 ARN，会话上限 1 小时；权限只有对 auth 函数的两条 invoke（与 edge role **逐字同形**，
    见 `_verifier_invoke_statements`）。"""
    fn_arn = f"arn:aws:lambda:{region}:{account}:function:{FN}"
    verifier_arn = f"arn:aws:iam::{account}:role/{VERIFIER_ROLE_NAME}"
    try:
        iam.get_role(RoleName=VERIFIER_ROLE_NAME)
        exists = True
    except iam.exceptions.NoSuchEntityException:
        exists = False
    if not verification.fixture_issuer:
        if exists:
            # inline policy 可能已经不在（上一次 create_role 成功、put_role_policy 没写成的半失败状态）。
            # 对它抛 NoSuchEntity 会让"关掉夹具组件"把**整个 auth 部署**堵死（本函数在 deploy_function 之前），
            # 而这里想要的终态就是角色消失——所以缺 policy 不是错误，缺了照样往下删角色
            # （IAM 不允许删还带 inline policy 的角色，所以这一步不能跳过）。
            try:
                iam.delete_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyName="invoke-auth-function-url")
            except iam.exceptions.NoSuchEntityException:
                pass
            iam.delete_role(RoleName=VERIFIER_ROLE_NAME)
            print(f"  [Verification] 已关闭：删除角色 {VERIFIER_ROLE_NAME}")
        return None
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": list(verification.trusted_principals)},
        "Action": "sts:AssumeRole"}]})
    if exists:
        iam.update_assume_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyDocument=trust)
        iam.update_role(RoleName=VERIFIER_ROLE_NAME, MaxSessionDuration=3600)
    else:
        # Description 只说 IAM 真的能表达的事：**IAM 无法按路径限权**，这两条语句覆盖 auth Function URL 的
        # 每一个路径；"只能打 /fixture-session"是 handler 里那道调用者检查的事，不是这个角色的边界。
        iam.create_role(RoleName=VERIFIER_ROLE_NAME, AssumeRolePolicyDocument=trust, MaxSessionDuration=3600,
                        Description="site-builder acceptance verifier - may invoke only the auth Function URL"
                                    " (any path); the /fixture-session restriction is enforced by the handler")
    iam.put_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyName="invoke-auth-function-url",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": _verifier_invoke_statements(fn_arn, verifier_arn)}))
    if not exists:
        import time; time.sleep(10)
    return verifier_arn


def lambda_env() -> dict:
    """Lambda 环境变量：**只下发参数名，不下发密钥明文**。

    `lambda:GetFunctionConfiguration` 会原样回显环境变量（部署时实测确认），
    而那是个常见的只读权限。两个 `*_PARAM` 都只是参数名，值运行时才读
    （login_handler._secret() 从 SSM SecureString 读并在容器内缓存）。
    3c-final 起会话签名密钥在 KMS 里，环境变量只有 kid / key_arn / spki_sha256。
    """
    keys = load_session_keys(CFG_PATH)
    env = {
        # 3c-1B：登录流程（OAuth state 与 __Host-sb_pkce cookie）的 HMAC 密钥参数名。
        # 键名照 `_secret(name)` 的 `{name}_PARAM` 约定，所以 login_handler._login_flow_sig 只改了
        # 一个字符串就换了密钥。**auth 私有**——panel 与 Edge 都不下发它（spec §11.3）。
        "LOGIN_FLOW_SECRET_PARAM": keys.login_flow_secret_param,
        "CLIENT_SECRET_PARAM": CLIENT_SECRET_PARAM,
        "COGNITO_DOMAIN": cfg()["Cognito"]["domain"],
        "CLIENT_ID": cfg()["Cognito"]["site_client_id"],
        "BASE_DOMAIN": base_domain(),
        "USER_POOL_ID": cfg()["Cognito"]["user_pool_id"],
        # email 是授权主键，而联邦 email 默认 unverified——见 login_handler 的
        # REQUIRE_EMAIL_VERIFIED。默认 "true"；只有接入不发该 claim 的 IdP 时
        # 才在 config.ini 里设 false。**必须显式下发**：漏了这一项时 Lambda
        # 环境变量缺失、代码回落默认值（true），行为仍然安全，但配置里写的
        # false 不生效——运维会以为关掉了却没关。
        "REQUIRE_EMAIL_VERIFIED": _require_email_verified_cfg(),
        # 3c-final：两个 family 的 kid 清单（kid / alg / role / key_arn / spki_sha256，**没有任何密钥材料**）。
        # 形态由 auth/session_keys.py 唯一定义；panel 的那份只含 console（各自 verifier 各自的 allowlist）。
        "SESSION_KEYS_JSON": env_json(keys, ("site", "console")),
        # 夹具签发器开关（spec §11.7）：`POST /fixture-session` 只在 "on" 时存在。真源是 [Verification]
        # fixture_issuer；verify_deployed_components 按"env 整体 == lambda_env()"比对，所以这一项自动入闸。
        "FIXTURE_ISSUER": "on" if read_verification(cfg(), account=cfg()["Platform"]["account_id"]).fixture_issuer else "off",
    }
    return {"Variables": env}


def required_parameters() -> list:
    """部署前必须已存在的 SSM 参数：只剩 deploy_pool 建的 site client secret。login-flow 由本脚本 ensure（ADR 0004，
    只有 auth 一个消费方，排除是安全的）；会话签名密钥在 KMS，由 precheck() 里的 session_kms.precheck_keys 四项校验。

    **与 spec §11.8.12 的字面清单有意不同**，裁定真源是
    `docs/adr/0004-login-flow-secret-outside-the-pre-write-precheck.md`：核对 login-flow 等于让本脚本对它的
    缺省补建永远走不到（首次部署必然被自己拒掉）。核对的意义是"**多个**消费方必须就同一个值达成一致，
    所以不能由本脚本随手造一把"——login-flow 只有 auth 一个消费方（panel 与 Edge 永不持有它，spec §11.3）。
    与 role 的 ARN 清单同一上游（ssm_parameter_names），两处不会分叉。
    """
    keys = load_session_keys(CFG_PATH)
    return [p for p in ssm_parameter_names(keys, ("site", "console"), login_flow=True, extra=(CLIENT_SECRET_PARAM,))
            if p != keys.login_flow_secret_param]


def precheck() -> None:
    """第一次写之前：SSM 参数存在 + 每个 RS kid 的 KMS 四项（spec §11.6 第 1 层 / §11.8.12）。只读、不打印值。"""
    precheck_parameters(required_parameters(), ssm=_ssm(), hint="client secret 由 scripts/deploy_pool.py 创建；先跑它。")
    session_kms.precheck_keys(_kms(), key_refs(load_session_keys(CFG_PATH), ("site", "console")))


def edge_role_arn() -> str:
    """`[Deployer] edge_role_arn`，先过 `function_url_statements` 的校验（空 / 通配 / 非 role ARN 即 SystemExit）。

    与 panel / key-proxy 第 ① 步同一条纪律：缺配置**中止**，绝不 fallback 到宽权限。放在 precheck 之后、
    任何写之前——拿空值往下跑的话 Lambda 与角色都建好了才在授权那一步炸，留下半个部署。
    """
    arn = cfg().get("Deployer", "edge_role_arn", fallback="")
    try:
        function_url_statements(arn)
    except ValueError as exc:
        raise SystemExit(f"config.ini [Deployer] edge_role_arn 不可用，拒绝部署（任何写都未发生）：{exc}")
    return arn


def deploy_function(lam, *, role_arn: str, env: dict, code: bytes) -> None:
    """**先配置、后代码**（spec §11.8.3）：旧代码忽略新变量无害，而新代码缺新变量会 500 几秒
    （2026-09-02 那次 502 的同一窗口形状）。3c-final 这次两侧都变——新代码要 `SESSION_KEYS_JSON` 的 RS 行，
    而 HS 时代那三个键同时消失——所以顺序反过来的窗口是"新代码 + 旧 env"，即整段登录 500。
    两步各自等 function_updated。"""
    try:
        lam.get_function(FunctionName=FN)
        lam.update_function_configuration(FunctionName=FN, Environment=env)
        lam.get_waiter("function_updated").wait(FunctionName=FN)
        lam.update_function_code(FunctionName=FN, ZipFile=code)
        lam.get_waiter("function_updated").wait(FunctionName=FN)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_function(FunctionName=FN, Runtime="python3.13",
                            Handler="login_handler.handler", Role=role_arn,
                            Code={"ZipFile": code}, Timeout=15, MemorySize=256,
                            Environment=env)
        lam.get_waiter("function_active").wait(FunctionName=FN)


def main():
    # ⓪ 任何写之前：本函数要读的外部参数都得在（缺参 = 运行时全部登录 500 而脚本 exit 0），
    #    且 Function URL 要授权的 edge role 必须是一个精确的 role ARN（缺 / 通配即中止）。
    precheck()
    edge_arn = edge_role_arn()
    # `[Verification]`（spec §11.7）也在**任何写之前**读：清单空 / 含通配 / 跨账号一律 SystemExit，
    # 否则一个写宽了的信任策略要等到角色已经建好才被发现。
    verification = read_verification(cfg(), account=cfg()["Platform"]["account_id"])
    keys = load_session_keys(CFG_PATH)
    # login-flow secret（spec §11.3）：**本脚本的 `ensure_secret` 是唯一的创建方**（3c-final 起，
    # 那个专门建密钥的脚本已删除，plan 08 D5；ADR 0004 说明它为什么不进写前核对清单）——
    # 只创建不覆盖。**它是本脚本唯一还 ensure 的密钥**：会话签名密钥是
    # KMS 里的 CMK（deployer 栈建），本脚本只在 precheck 里核对它们。
    # 覆盖它的后果是所有**进行中**的登录失败一次（已签发的会话不受影响），见 _login_flow_sig 的说明。
    ensure_secret(keys.login_flow_secret_param, lambda: secrets.token_hex(32))
    role_arn = ensure_lambda_role()
    # 夹具签发器的调用者角色：开着 ⇒ 建 / 收敛并拿到 ARN（下面进 Function URL 的期望集合）；
    # 关着 ⇒ 存在则删、返回 None ⇒ 那两条语句在同一次 converge 里被当野 Sid 清掉。
    verifier_arn = ensure_verifier_role(_iam(), verification,
                                        account=cfg()["Platform"]["account_id"], region=region())
    env = lambda_env()
    code = build_zip()
    lam = _lam()
    deploy_function(lam, role_arn=role_arn, env=env, code=code)
    # AWS_IAM 而非 NONE：NONE + Principal:* 是 world-accessible，会触发安全扫描
    # 告警甚至自动处置（实际发生过：resource policy 被整个删除，连 Edge 路径一起 403）。
    # Edge 的 _route_to_lambda 对所有 Lambda URL 路由（含 api-only）都签 SigV4，
    # 所以只授权 edge role 即可，公网直连被 IAM 挡住。
    try:
        url = lam.create_function_url_config(FunctionName=FN, AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        # 局部名不叫 cfg——那会把模块级的 cfg() 在**整个 main() 里**变成局部名
        # （Python 的作用域是按函数整体判的），后面每一处 cfg()[...] 都会炸。
        url_cfg = lam.get_function_url_config(FunctionName=FN)
        url = url_cfg["FunctionUrl"]
        if url_cfg["AuthType"] != "AWS_IAM":
            lam.update_function_url_config(FunctionName=FN, AuthType="AWS_IAM")
    # resource policy 按期望集合**等值收敛**（merged review M07）：读回 → 内容不对的同名语句替换（edge role
    # 重建后 IAM 会把 Principal 改写成已删角色的 AROA 形态，同名 Sid 存在但永不匹配）→ 缺的补上 → 野 Sid
    # 删除（含老版本留下的 public-url / public-url-invoke）→ 写后读回核对。一致时零写入。
    # "同名 StatementId 已存在就 pass"是这条缺陷的原始形态：同名只说明有一条语句叫这个名字，不说明内容对。
    # 唯一实现在 deployer/functions/function_url_policy.py，panel / key-proxy / 闸门共用同一份判定。
    # extra_principals 只在 [Verification] 开着时带上 verifier 的两条（spec §11.7）；关着时是 None，
    # 于是上一次留下的 verifier-invoke / verifier-invoke-function 在这里就是野 Sid，被删掉。
    extra_principals = {"verifier": verifier_arn} if verifier_arn else None
    drift = converge_function_url_policy(lam, FN, edge_arn, extra_principals=extra_principals)
    print(f"  Function URL 授权（收敛前的漂移；「一致」= 零写入，其它 = 已按期望集合改写并读回核对）："
          f"{drift.summary()}")
    _ddb().put_item(TableName=cfg()["Platform"]["routing_table"], Item={
        "subdomain": {"S": "auth"}, "site_id": {"S": "auth-service"},
        "route_mode": {"S": "api-only"},  # 全路径走 Lambda（/login 不匹配 /api/*）
        "static_prefix": {"S": ""}, "api_target": {"S": url.rstrip("/")},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "platform"}})
    ensure_pre_token_trigger(role_arn)
    # 登录失败告警：**本脚本是唯一配置真源**（M3 前置 B2）。
    # 现网那套原本是手工建的；同名 upsert 收编，从此只有一个 writer。
    #
    # **filter_name 必须字节级等于现网那个手工 filter 的名字**（实测现网是
    # `auth-invalid-grant`，而 alarm 是 `site-builder-auth-invalid-grant`
    # ——两者本来就不同名）。put_metric_filter 的 upsert 键是 filterName：
    # 换个名字不是"改名"，而是在同一日志组上**再建一个** filter。后果不是
    # 多一个闲置资源：两个 filter 都往 SiteBuilder/AuthInvalidGrant 发点，
    # 同一条日志被计两次（Sum 翻倍），而手工那个仍在——"只有一个 writer"
    # 当场失效，正是本次收编要消灭的状态。
    result = ensure_alarm_pipeline(
        region=region(), log_group=f"/aws/lambda/{FN}",
        namespace="SiteBuilder", metric_name="AuthInvalidGrant",
        filter_name="auth-invalid-grant",
        filter_pattern='{ $.event = "token_exchange_invalid_grant" }',
        topic_name="site-builder-alarms",
        alarm_name="site-builder-auth-invalid-grant",
        email=_alert_email(), account_id=cfg()["Platform"]["account_id"])
    print(f"  告警管道已收敛：{', '.join(result['changed'])}")
    if result["subscription_state"] != "confirmed":
        # **不能只打印一行提示**：未确认的订阅意味着 alarm 会进 ALARM 而
        # 无人收到通知——那是这套告警要防的盲区本身。
        print(f"⚠️  email 订阅状态：{result['subscription_state']}"
              f"（**未完成**）——收件人必须点确认链接，否则告警无人知情。"
              f"确认后重跑本脚本或用 verify_auth_alarm.sh 核对。")
    print(f"auth-service: {url}  →  https://auth.{base_domain()}/")


def _alert_email() -> str:
    """告警收件人：环境变量优先（CI），否则 config.ini [Alerting] email。

    **不能有默认值**：默认到某个邮箱是错的（发给不相关的人），默认到空串
    会让 ensure_alarm_pipeline 抛错——那正是我们要的响亮失败。
    """
    env = os.environ.get("SB_ALERT_EMAIL", "").strip()
    if env:
        return env
    if cfg().has_section("Alerting"):
        raw = cfg()["Alerting"].get("email", "")
        return raw.split("#")[0].split(";")[0].strip()
    return ""


def _require_email_verified_cfg() -> str:
    """config.ini [IdP] require_email_verified → Lambda 环境变量的字符串值。

    默认 "true"（缺 section / 缺键 / 空值都算默认）。只有显式写成 false
    才关闭——拼错（yes/0/off 之类）一律当 true，与"安全开关默认开、
    写错时不静默降级"的取向一致。
    """
    raw = ""
    if cfg().has_section("IdP"):
        raw = cfg()["IdP"].get("require_email_verified", "")
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


def ensure_pre_token_trigger(role_arn: str, pool_id: str | None = None,
                             fn_name: str = "site-auth-pre-token") -> None:
    """部署 pre-token-generation V2 Lambda 并挂到用户池。

    真机钉死（2026-07-29，AGENTCORE-SPIKE.md §7）：部署 MCP 网关只接受
    access token，而 Cognito access token 默认不含 email——owner 识别全靠
    这个触发器把 email 注入 access token。要求用户池 Essentials+ tier。

    pool_id 显式传入时用它（deploy_pool.py 建新 pool 后立即挂载）；
    默认取 config.ini 的当前 pool。

    **fn_name 必须随隔离 pool 一起改**：本函数对已存在的函数走
    update_function_code，而生产 pool 正在调用 `site-auth-pre-token`——
    spike 若沿用默认名，会把新版代码推到生产在用的函数上，静默改掉线上
    token 的 claim 形态（实测差异：线上仅 access token 注 email，新版往
    id/access 两个容器注 email/email_verified/idp/auth_via）。
    与 _store_client_secrets 的 SSM 前缀隔离是同一类要求。
    """
    fn = fn_name
    lam = _lam()
    pool_id = pool_id or cfg()["Cognito"]["user_pool_id"]
    cog = boto3.client("cognito-idp", region_name=region())
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
                           SourceArn=f"arn:aws:cognito-idp:{region()}:"
                                     f"{cfg()['Platform']['account_id']}"
                                     f":userpool/{pool_id}")
        print(f"  已授权 {pool_id} 调用 {fn}（{sid}）")
    except lam.exceptions.ResourceConflictException:
        pass  # 同一 pool 重复运行，幂等
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    # 局部名不叫 cfg（理由同 main() 里那处）：本函数上面就在用 cfg()
    ptg = pool.get("LambdaConfig", {}).get("PreTokenGenerationConfig", {})
    if ptg.get("LambdaArn") == fn_arn and ptg.get("LambdaVersion") == "V2_0":
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
    """auth 服务与 pre-token 触发器的执行角色。幂等收敛，不只在创建时配。

    **不能对已存在的角色 early-return**：那样线上角色永远拿不到新增权限
    （本函数加 SSM 读权限时就踩到——已有角色不补策略，运行时读密钥
    AccessDenied，症状是所有登录 500）。与 deploy_pool 的
    "幂等重跑不能把线上加固打回默认"是同一类要求。
    """
    name = "site-auth-service-role"
    iam = _iam()
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        created = False
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=name,
                              AssumeRolePolicyDocument=json_trust())["Role"]["Arn"]
        created = True
    # 每次都收敛：基础执行策略 + 密钥读取
    iam.attach_role_policy(RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    # 两把 SSM 密钥（login-flow 与 client secret）运行时读（见 lambda_env 的说明），故需要
    # GetParameter + kms:Decrypt。资源是精确 ARN 清单——给前缀通配等于让这个角色能读
    # 本平台前缀下未来的一切秘密。
    keys = load_session_keys(CFG_PATH)
    key_arns = kms_key_arns(keys, ("site", "console"))
    iam.put_role_policy(RoleName=name, PolicyName="read-platform-secrets",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Sid": "ReadPlatformSecrets", "Effect": "Allow",
             "Action": "ssm:GetParameter",
             # login_flow=True 只有 auth 传：那把密钥 panel 与 Edge 永不持有（spec §11.3）
             "Resource": ssm_parameter_arns(keys, ("site", "console"),
                                            region=region(), account=cfg()["Platform"]["account_id"],
                                            login_flow=True, extra=(CLIENT_SECRET_PARAM,))},
            # SecureString 用账号默认的 aws/ssm key 加密；解密走 SSM 服务，
            # 故用 ViaService 限定，避免这个角色能直接拿 KMS key 干别的。
            {"Sid": "DecryptViaSSM", "Effect": "Allow",
             "Action": "kms:Decrypt", "Resource": "*",
             "Condition": {"StringEquals": {
                 "kms:ViaService": f"ssm.{region()}.amazonaws.com"}}},
            # 3c-final（spec §11.2 / ADR 0001）：kms:Sign 只经 identity policy 授、精确到两个 family 的 key ARN，
            # 两个条件把 §11.5 的合同钉进 IAM（零自锁风险）；GetPublicKey 给 verifier 冷启动与 signer 自检用。
            {"Sid": "SignSessionTokens", "Effect": "Allow", "Action": "kms:Sign", "Resource": key_arns,
             "Condition": {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                            "kms:MessageType": "RAW"}}},
            {"Sid": "ReadSessionPublicKeys", "Effect": "Allow", "Action": "kms:GetPublicKey",
             "Resource": key_arns},
        ]}))
    if created:
        import time; time.sleep(10)  # IAM 传播
    return arn


def json_trust() -> str:
    return ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')


if __name__ == "__main__":
    main()
