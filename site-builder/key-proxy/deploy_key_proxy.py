#!/usr/bin/env python3
"""部署 M4 的 API Key 交换层（key-proxy）。幂等可重跑。

流程：组件门禁 → 校验配置（缺一即中止）→ IAM 角色 → 打包 Lambda →
Function URL（AWS_IAM，只授权 edge role）→ `__switch__` 哨兵行（**不存在才建，
且建成关**）→ 注册 `{mcp_subdomain}.{base_domain}` route → 打印开关当前状态。

关键约束（改动前先读）：

- **组件门禁返回 0，不是报错**：没配 `[ApiKey]` 段 = 平台只允许 OAuth 一条
  认证路径（推荐的默认，spec §5.1.1）。"没配置"是合法的默认状态，部署全平台的
  脚本链不该因此中断。判定的**唯一真源**是
  `deployer/functions/api_key_config.api_key_enabled`——本脚本自己不判
  （三个部署脚本各写一次 `has_section` 就是三个判定点，漏改一处得到的是
  **部分部署**，而部分部署恰好是最危险的状态：网关放行而容器拒绝，症状是
  HTTP 200 加一句业务错误文案）。门禁不通过时**一次 AWS 调用都不发**。

- **哨兵行只在不存在时创建，且创建成 `enabled=False`；已存在时一个字都不改。**
  绝不"把线上收敛成配置里的值"——那正是 2026-08-11 把关闸开关移出 `config.ini`
  的理由：否则下一次重跑部署会把管理员的关闸**静默覆盖成开**。条件写
  `attribute_not_exists(key_hash)` 让并发部署也不会互相覆盖。
  `enabled` 必须是 DynamoDB **BOOL**：`keystore.lookup` 的判定是
  `enabled is not True`，字符串 `"true"` 同样被拒，症状是"控制台显示开着但
  所有 Key 都 401"（两侧单测各自都绿）。

- Function URL **必须** AuthType=AWS_IAM，且 resource policy 恰好两条语句、
  Principal 是逐字符 exact 的 edge role ARN。2025-10 起需要 InvokeFunctionUrl
  + InvokeFunction(InvokedViaFunctionUrl) 两条，缺一即 403；`AuthType=NONE` +
  `Principal:*` 会被安全扫描自动处置（实测删光整个 resource policy）。
  **缺 edge_role_arn 一律抛错中止，绝不 fallback 到宽权限**——handler 的第 ⓪ 步
  （`edge_caller.caller_is_edge`）是把"绕过 Edge"挡住的那一层，而 Edge 是 Key
  暴力尝试唯一的可观测位置。

- 环境变量**只下发 SSM 参数名**，明文密钥严禁进环境变量：
  `lambda:GetFunctionConfiguration` 会原样回显环境变量，而那是个常见的只读权限。

- **route 的 `require_auth` 必须是布尔 `False`**：Edge 的判定是
  `require_auth is False`，字符串会落进"按需要登录处理"，而 key-proxy 的调用方
  （只能配静态 Header 的 MCP 客户端）没有平台会话——结果是 302 到登录页，
  客户端拿到一坨 HTML 而不是 MCP 响应。

- **`api_target` 不带尾斜杠**：Edge 拼接时会得到双斜杠，与实际对象/路径不是
  同一个（M3 实测整站 403，见 `deploy_panel.frontend_prefix` 的 docstring）。

- **`mcp` 子域故意不进 Edge 的 `PLATFORM_SUBDOMAINS`**（plan 决定 9）：
  key-proxy 只认 `X-API-Key`，不需要平台 cookie；进白名单只会让一个公网组件
  白拿一个顶域会话 JWT。本脚本不碰 Edge 的任何配置。

用法：
    cd site-builder/key-proxy && python3 deploy_key_proxy.py
"""
import argparse
import configparser
import io
import json
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3

HERE = Path(__file__).parent

# 门禁判定与三个共享常量都**从真源 import**，不在本脚本里重写字面量：
#   api_key_config  —— "有没有 [ApiKey] 段"的唯一判定 + `{rs}/{scope}` 的唯一拼接
#   edge_caller     —— 环境变量名（下发 A、代码读 B 时两侧单测都绿而线上全拒）
#   keygen          —— 哨兵行主键
#   handler         —— AgentCore 端点的环境变量名（该常量的 docstring 指名由本
#                      脚本引用）
# 落点是 `deployer/functions/` 而不是 `scripts/`：本脚本从 site-builder/key-proxy/
# 执行，那个目录看不到 scripts/，`import deploy_pool` 会在任何 AWS 调用**之前**
# ModuleNotFoundError（Codex 审查 2026-08-11 P1-3，已实测复现）。
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
sys.path.insert(0, str(HERE))
from api_key_config import (api_key_enabled, machine_scope,  # noqa: E402
                            mcp_subdomain)
from edge_caller import EDGE_ROLE_ID_ENV                      # noqa: E402
from handler import AGENTCORE_ENDPOINT_ENV                    # noqa: E402
from keygen import SWITCH_PK                                  # noqa: E402
import keystore                                               # noqa: E402

CFG = configparser.ConfigParser(interpolation=None)
CFG.read(HERE.parent / "config.ini")

FN_NAME = "site-key-proxy"
ROLE_NAME = "site-key-proxy-role"
FUNCTION_URL_AUTH_TYPE = "AWS_IAM"
RUNTIME = "python3.13"
# handler 的转发超时是 25s，Lambda 侧留 30s：反过来的话客户端拿到的是空响应
# 而不是一条可归因的 504。
TIMEOUT_SECONDS = 30
MEMORY_MB = 512

# 凭证表名。**与 `deployer/infra/app.py` 建表用的 `table_name` 同名**（那是表的
# 唯一创建者），也与 `deploy_panel.lambda_environment` 下发的同名——三处漂移的
# 症状是 key-proxy 读一张空表：所有 Key 都 `unknown-key` → 401。
# 由 test_api_keys_table_name_matches_the_cdk_table 交叉核对。
API_KEYS_TABLE = "site-api-keys"

# machine client secret 的 SSM 参数名。**写入者是 `scripts/deploy_pool.py`**
# （`_store_client_secrets`，参数前缀 `/site-builder`）——这里只是读取方，
# 两处必须同名，由 test_machine_secret_param_agrees_with_deploy_pool 从
# deploy_pool 的源码推导后交叉核对（手抄的第二份真源会漂移：症状是
# machine_token 报 `TokenUnavailable: 无法读取 machine client secret`，
# 而排查方向会指向 Cognito）。
MACHINE_SECRET_PARAM = "/site-builder/machine-client-secret"

# 构建时复制进部署包的模块。**七个都必需**（前六个由传递闭包点名）：
#   edge_caller.py     —— handler 第 ⓪ 步"调用者真是 Edge"的唯一判定
#   keystore.py        —— `site-api-keys` 的唯一访问层（handler 第 ③ 步）
#   keygen.py          —— 明文/哈希与哨兵行主键的唯一算法（keystore + handler）
#   permissions.py     —— keystore 借它的 EMAIL_RE 判邮箱形态（不再写第二条正则）
#   common.py          —— permissions.py 与 keystore.py 的分页/表助手
#   ops_log.py         —— permissions.py 与 keystore.py 的审计落点
#   api_key_config.py  —— **不在 import 闭包里，是有意加的**：门禁判定的真源随
#                         包走（该模块 docstring 说明"它天然进 Lambda/容器打包"），
#                         且 Task 10 的真机闸门按本清单逐字节比对产物模块。
#                         它是纯函数模块（不 import boto3、不读环境变量），带上
#                         它不引入任何新依赖。
# `machine_token.py` 与 `handler.py` 是 key-proxy 自己的文件，不在复制清单里
# （`_build_zip` 打的就是本目录的 *.py）。
# **清单以闭包断言为准**，不要照着记性加减（panel 的同一份清单曾漏过
# keystore.py，症状是所有 API 500 而不只是 Key 相关的）。
COPY_FILES = ("api_key_config.py", "common.py", "edge_caller.py", "keygen.py",
              "keystore.py", "ops_log.py", "permissions.py")

# 哨兵行的三种收敛结果（`ensure_switch_row` 的返回值）。
SWITCH_CREATED_DISABLED = "created-disabled"
SWITCH_EXISTING_ENABLED = "existing-enabled"
SWITCH_EXISTING_DISABLED = "existing-disabled"


def _cfg(cfg, section: str, key: str, default: str | None = None) -> str:
    """取一个配置项并切掉 configparser 保留的行内注释。

    ConfigParser 默认 `inline_comment_prefixes=None`，值里会带着 `# …` 文本。
    与 `deploy_panel._cfg` / `api_key_config._value` 同一口径。
    """
    try:
        raw = cfg[section][key]
    except KeyError:
        if default is not None:
            return default
        sys.exit(f"config.ini 缺 [{section}] {key}")
    return raw.split("#")[0].split(";")[0].strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _region(cfg=None) -> str:
    return _cfg(CFG if cfg is None else cfg, "Platform", "region")


def _account(cfg=None) -> str:
    return _cfg(CFG if cfg is None else cfg, "Platform", "account_id")


def mcp_host(cfg=None) -> str:
    """交换层的主机名。子域来自 api_key_config（未启用组件时它返回 ""）。"""
    cfg = CFG if cfg is None else cfg
    sub = mcp_subdomain(cfg)
    if not sub:
        raise ValueError("mcp_subdomain 为空——组件未启用时不该走到这里")
    return f"{sub}.{_cfg(cfg, 'Platform', 'base_domain')}"


def agentcore_endpoint(cfg=None) -> str:
    """AgentCore invocations URL（`config.ini [MCP] endpoint_url`）。

    **空值或非 https 一律中止**，不下发一个空环境变量：
      · 空 → handler 每次请求都 `EndpointMisconfigured` → 502。部署"成功"而
        组件全挂，且症状与上游故障无法区分；
      · http → 这个请求带着机器 token，明文会把凭证放到线上，而症状是
        "一切正常"（handler 自己也拒 http，这里是第一道）。
    """
    cfg = CFG if cfg is None else cfg
    url = _cfg(cfg, "MCP", "endpoint_url", "")
    if not url:
        sys.exit("config.ini [MCP] endpoint_url 为空——先跑 deploy_agentcore.py "
                 "并回填它；空端点会让 key-proxy 的每次转发都 502")
    if not url.startswith("https://"):
        sys.exit(f"[MCP] endpoint_url 必须是 https（拿到 {url!r}）——"
                 "明文转发会把机器 token 泄漏在线上")
    return url


def machine_client_id(cfg=None) -> str:
    """`config.ini [Cognito] machine_client_id`。**空值中止。**

    与 `deploy_agentcore.machine_client_id` 读的是同一个配置键（不是第二份
    真源——那边的派生点管的是"网关 allowedClients 与容器环境变量同开同关"）。
    段存在而值为空时静默跳过会得到"以为部署了 API Key 其实换不到 token"的状态，
    而 machine_token 报的是 `invalid_client`，排查方向会指向 Cognito 配置。
    """
    cfg = CFG if cfg is None else cfg
    mid = _cfg(cfg, "Cognito", "machine_client_id", "")
    if not mid:
        sys.exit("[ApiKey] 段存在但 [Cognito] machine_client_id 为空——"
                 "先跑 deploy_pool.py 建 machine client 并回填 config.ini")
    return mid


def function_url_statements(edge_role_arn: str) -> list[dict]:
    """Function URL 的两条 resource policy 语句（形态与 panel 一致）。

    **缺 edge_role_arn 或给通配一律抛错**：fallback 到 `Principal:*` 会让
    Function URL 全网可调。对 key-proxy 而言绕过 Edge 不等于绕过认证（攻击者
    还得有一把有效 Key），但 **Edge 是限流与可观测性的唯一位置**——绕过它意味着
    Key 的暴力尝试不留任何可告警痕迹。
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
        {"StatementId": "edge-invoke-function",
         "Action": "lambda:InvokeFunction",
         "Principal": arn,
         "InvokedViaFunctionUrl": True},
    ]


def role_statements(cfg=None) -> list[dict]:
    """key-proxy 执行角色的 inline policy。**比 panel 窄得多**，逐条说明：

      · api-keys 表：**只有 GetItem + UpdateItem**。
        - 无 `BatchGetItem`：开关与 Key 是两次独立的 GetItem（合并成一次
          BatchGet 会让"关闸期间零 Key 查询"这条短路不成立，Codex P2-6）；
        - 无 `PutItem`：发 Key 是控制台（panel）的事。包里带着
          `keystore.create` 是有意接受的——**代码在但权限不在**是纵深；
        - 无 `DeleteItem`：吊销是置 `revoked`，删行就没有审计痕迹了；
        - 无 `Scan`：Scan 等于能读全表凭证行；
        - **不给任何 `index/*`**：本组件的两条路径（lookup / touch_last_used）
          都按主键走，GSI 查询是 panel 的列表与吊销路径。
      · SSM：**精确** machine-client-secret ARN（不用 `parameter/site-builder/*`
        前缀——拿前缀等于被攻破时顺带交出 jwt-secret 与 site client secret，
        而前者能伪造任意用户的会话）。
      · kms:Decrypt 带 `ViaService` 限定，否则这个角色能拿那把 key 干别的。
      · **没有任何 bedrock 权限**：AgentCore 的 invocations 端点只认 Bearer JWT，
        不走 SigV4（见 `handler._endpoint` 的 docstring）。
      · 没有 `iam:*` / `lambda:*`：这个函数不建资源、不调别的函数。
      · 没有 ops-log 表：key-proxy 走的两条 keystore 路径都不写审计
        （写审计的 create / revoke / set_switch 全在 panel）。
    """
    cfg = CFG if cfg is None else cfg
    region, acct = _region(cfg), _account(cfg)
    tbl = f"arn:aws:dynamodb:{region}:{acct}:table"
    return [
        # lookup 的两次强一致 GetItem（开关行 + Key 行）。**读整行**——判定要用到
        # email / revoked / enabled，所以这一条不能带 dynamodb:Attributes 限制。
        # 权限集不手抄：test_role_grants_exactly_what_the_key_proxy_paths_need
        # 从 keystore.py 的 AST 推导 lookup / touch_last_used 实际用到的操作。
        {"Sid": "ApiKeysLookupRead", "Effect": "Allow",
         "Action": "dynamodb:GetItem",
         "Resource": f"{tbl}/{API_KEYS_TABLE}"},
        # touch_last_used 的节流写。**必须按字段收窄，不能只给裸 UpdateItem**
        # （Codex 审查 2026-08-13 P1-1，本仓库实测 IAM 引擎判为 allowed）：
        #   · DynamoDB 的 UpdateItem 默认是 **upsert**——主键不存在就建行。
        #     `_update_last_used` 自己带了 `attribute_exists(key_hash)` 挡住它，
        #     但那是**代码层**的防线，而这条授权要防的是"代码被绕过"
        #     （公网组件被 RCE 后攻击者直接拿这个 role 调 API）；
        #   · 不带字段限制时可以写**任意**属性，于是能
        #     ① 造一行带任意 email 的凭证（伪造的 Key 从此可从任何地方经正常路径
        #        使用，**RCE 修好之后依然有效** = 持久化后门）；
        #     ② 把 `__switch__.enabled` 改回 true，**击穿管理员的应急关闸**。
        #
        # 需要说清的是：被 RCE 的 key-proxy 本来就能冒充任何人（它持有
        # MACHINE_SECRET_PARAM、能换机器 token，而容器信任的正是它发的
        # X-SB-On-Behalf-Of）。所以这条收窄挡的**不是**"冒充"，而是上面那两条
        # ——持久化与关闸完整性。定级按这两条，别按"防冒充"。
        #
        # `ForAllValues` 的语义陷阱：条件键缺失时它返回 true。这里可以接受——
        # UpdateItem 请求必然带主键，`dynamodb:Attributes` 不可能缺。
        # `ReturnValues` 用 `IfExists`：我们的调用不传该参数（默认 NONE），
        # 而显式传 ALL_OLD 的攻击请求会被拒——否则 UpdateItem 能被当读接口用，
        # 把整行（含 email）回显出来，绕过上面的字段限制。
        {"Sid": "ApiKeysTouchLastUsedOnly", "Effect": "Allow",
         "Action": "dynamodb:UpdateItem",
         "Resource": f"{tbl}/{API_KEYS_TABLE}",
         "Condition": {
             "ForAllValues:StringEquals": {
                 "dynamodb:Attributes": ["key_hash", "last_used_at"]},
             "StringEqualsIfExists": {"dynamodb:ReturnValues": "NONE"}}},
        {"Sid": "ReadMachineClientSecretOnly", "Effect": "Allow",
         "Action": "ssm:GetParameter",
         "Resource": (f"arn:aws:ssm:{region}:{acct}:parameter"
                      f"{MACHINE_SECRET_PARAM}")},
        {"Sid": "DecryptViaSSM", "Effect": "Allow",
         "Action": "kms:Decrypt", "Resource": "*",
         "Condition": {"StringEquals": {
             "kms:ViaService": f"ssm.{region}.amazonaws.com"}}},
        {"Sid": "Logs", "Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                    "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{FN_NAME}*"},
    ]


def edge_role_id(edge_role_arn: str) -> str:
    """Edge 执行角色的 **RoleId**（`AROA…`），给 handler 校验调用者用。

    为什么不能直接用 ARN：Edge 调过来的身份是 STS assumed-role 形态，
    `callerId` 是 `{RoleId}:{session_name}`，与 config 里的
    `arn:aws:iam::<acct>:role/<name>` **永不相等**（判定的唯一实现与真机抓到的
    形态见 `edge_caller.caller_is_edge`）。

    **现查而不是让人往 config 里再抄一个值**：手抄的第二份真源会漂移。
    与 `deploy_panel.edge_role_id` 是同形态的两份 6 行实现——刻意不共用：
    共用得把它塞进某个被复制进部署包的模块，而那些模块的复制闭包正是
    "部署产物里到底有什么"的唯一守卫，加宽它的代价比这点重复更大
    （`edge_caller.py` 还有"不得 import boto3"的约束）。**被手抄的是查询动作，
    不是那个值**——两边都从 IAM 现查，不会漂。
    """
    name = (edge_role_arn or "").strip().rsplit("/", 1)[-1]
    if not name:
        raise ValueError("edge_role_arn 为空，无法解析 Edge 角色名")
    role_id = boto3.client("iam").get_role(RoleName=name)["Role"]["RoleId"]
    if not role_id.startswith("AROA"):
        raise ValueError(f"解析出的 RoleId 形态不对: {role_id!r}")
    return role_id


def lambda_environment(edge_role_id_value: str = "", cfg=None) -> dict:
    """Lambda 环境变量。**只有参数名，没有明文密钥**（见模块 docstring）。

    `EDGE_ROLE_ID` 不是秘密（公开的资源标识，签不出任何东西），但**缺了它
    handler 拒绝所有请求**——`edge_caller.caller_is_edge` 刻意 fail-closed：
    "配置缺失就不检查"恰好是这个缺陷的原始形态。

    `MACHINE_SCOPE` 是**拼好的完整串**（`{resource_server_id}/{scope}`）。
    拼接在 `api_key_config.machine_scope` 里发生**这一次**，运行时只读不拼
    （Codex 审查 2026-08-11 P1-2a）：硬编码 `site-builder-mcp/invoke` 会绕开
    "config.ini 是唯一取值来源"，而两处各拼一次会出现"建的 scope 与换 token
    用的 scope 不是同一个"，Cognito 报 `invalid_scope`、文案指向 client 配置。
    """
    cfg = CFG if cfg is None else cfg
    scope = machine_scope(cfg)
    if not scope:
        # 组件启用时 machine_scope 有默认值，永不为空；真为空说明门禁被绕开了。
        # **绝不下发空 scope**：Cognito 会拒，而错误文案把排查方向带向 client。
        sys.exit("MACHINE_SCOPE 推导为空——组件未启用却走到了下发环境变量这一步")
    return {
        EDGE_ROLE_ID_ENV: edge_role_id_value,
        "API_KEYS_TABLE": API_KEYS_TABLE,
        AGENTCORE_ENDPOINT_ENV: agentcore_endpoint(cfg),
        "COGNITO_DOMAIN": _cfg(cfg, "Cognito", "domain"),
        "MACHINE_CLIENT_ID": machine_client_id(cfg),
        # **参数名，不是 secret 本体**：GetFunctionConfiguration 会原样回显。
        "MACHINE_SECRET_PARAM": MACHINE_SECRET_PARAM,
        "MACHINE_SCOPE": scope,
    }


def mcp_route_item(function_url: str, cfg=None) -> dict:
    """routing 表里的 `mcp` 记录。

    `route_mode=api-only`：全路径走 Function URL（MCP 是单端点 POST，没有静态
    资源），所以 `static_prefix` 是空串。
    `require_auth` 是**布尔 False**：Edge 的判定是 `require_auth is False`，
    字符串会落进"按需要登录处理"→ 302 到登录页，而调用方是 MCP 客户端。
    `owner="platform"` 只是**记录**——Edge 判平台身份只认 host 白名单
    （`origin_request.PLATFORM_SUBDOMAINS`，`mcp` 故意不在其中，见决定 9），
    绝不读这个可写字段。
    """
    cfg = CFG if cfg is None else cfg
    return {"subdomain": mcp_subdomain(cfg),
            "site_id": "key-proxy",
            "route_mode": "api-only",
            # 尾斜杠会让 Edge 拼出双斜杠（M3 实测整站 403）
            "api_target": function_url.rstrip("/"),
            "static_prefix": "",
            "require_auth": False,
            "allowed_users": "org",
            "owner": "platform",
            "collaborators": []}


def _build_zip() -> bytes:
    """把 key-proxy 自己的模块 + 复制来的共享模块打成 zip（内存里，不落盘残留）。

    查找顺序 `deployer/functions` → `auth`，与 panel 的 `_build_zip` 一致
    （复制清单的闭包断言用的也是这两个目录）。
    """
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
                if py.name == Path(__file__).name:
                    continue
                z.write(py, py.name)
        return buf.getvalue()
    finally:
        for p in staged:
            p.unlink(missing_ok=True)


def ensure_role(cfg=None) -> str:
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
                              Description="M4 API Key exchange layer",
                              Tags=[{"Key": "project", "Value": "site-builder"}]
                              )["Role"]["Arn"]
        created = True
    iam.put_role_policy(
        RoleName=ROLE_NAME, PolicyName="key-proxy-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": role_statements(cfg)}))
    if created:
        time.sleep(10)      # IAM 传播
    return arn


def ensure_function(role_arn: str, code: bytes, edge_role_id_value: str,
                    cfg=None) -> str:
    cfg = CFG if cfg is None else cfg
    lam = boto3.client("lambda", region_name=_region(cfg))
    env = {"Variables": lambda_environment(edge_role_id_value, cfg)}
    try:
        lam.get_function(FunctionName=FN_NAME)
        lam.update_function_code(FunctionName=FN_NAME, ZipFile=code)
        lam.get_waiter("function_updated").wait(FunctionName=FN_NAME)
        lam.update_function_configuration(
            FunctionName=FN_NAME, Role=role_arn, Handler="handler.handler",
            Runtime=RUNTIME, Timeout=TIMEOUT_SECONDS, MemorySize=MEMORY_MB,
            Environment=env)
        lam.get_waiter("function_updated").wait(FunctionName=FN_NAME)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):
            try:
                lam.create_function(
                    FunctionName=FN_NAME, Runtime=RUNTIME, Role=role_arn,
                    Handler="handler.handler", Code={"ZipFile": code},
                    Timeout=TIMEOUT_SECONDS, MemorySize=MEMORY_MB,
                    Environment=env, Tags={"project": "site-builder"})
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

    for stmt in function_url_statements(_cfg(cfg, "Deployer", "edge_role_arn",
                                             "")):
        kwargs = {k: v for k, v in stmt.items() if k != "StatementId"}
        try:
            lam.add_permission(FunctionName=FN_NAME,
                               StatementId=stmt["StatementId"], **kwargs)
        except lam.exceptions.ResourceConflictException:
            pass        # 幂等：同 StatementId 已存在
    return url


def _api_keys_table(cfg=None):
    """`site-api-keys` 的 Table 资源（单测把这个函数换成间谍/记录器）。"""
    return boto3.resource("dynamodb", region_name=_region(cfg)).Table(
        API_KEYS_TABLE)


def ensure_switch_row(cfg=None) -> str:
    """哨兵行：**不存在才建，且建成 `enabled=False`；已存在则一个字都不改。**

    返回三种收敛结果之一（供 main 打印）：`created-disabled` /
    `existing-enabled` / `existing-disabled`。

    **为什么不是"把线上收敛成配置里的值"**（2026-08-11 与用户定的决定 6）：
    关闸开关**故意不在** `config.ini` 里，而是这张表的一行，管理员在控制台开关
    （即时生效、有审计）。部署脚本若带上"收敛"语义，下一次重跑就会把管理员的
    关闸**静默覆盖成开**——那比没有开关更危险。

    **条件写 `attribute_not_exists(key_hash)`**：两个部署并发跑时，"先 GetItem
    看看有没有、没有就 Put"会两边都看到"没有"、两边都 Put，于是后写的那个把
    先写的覆盖掉。真正的风险不是重复创建，而是**覆盖一行已经被管理员开过的
    哨兵行**（把 enabled=true 打回 false 是"莫名其妙全部 401"，反过来更糟）。

    行里**只有固定的四个字段**，绝不带 `email` / `key_id`：那两个是
    `email-index` / `keyid-index` 的分区键，带上就会让平台开关行冒进某个人的
    Key 列表（`keystore.set_switch` 用 PutItem 整行覆盖也是同一个理由）。
    """
    table = _api_keys_table(cfg)
    try:
        table.put_item(
            Item={"key_hash": SWITCH_PK,
                  # 布尔 False，不是字符串 "false"（见模块 docstring）
                  "enabled": False,
                  "updated_at": _now_iso(),
                  "updated_by": Path(__file__).name},
            ConditionExpression="attribute_not_exists(key_hash)")
        return SWITCH_CREATED_DISABLED
    except Exception as e:
        # 判据借 keystore 的那一份（同一个包里的同一个文件），不再写第二遍。
        if not keystore._is_conditional_check_failure(e):
            raise
    # 已存在：**只读**，读什么就报什么。强一致读——刚创建/刚被控制台改过的行
    # 在最终一致读里可能还是旧值，而这个值是要打印给运维看的结论。
    row = table.get_item(Key={"key_hash": SWITCH_PK},
                         ConsistentRead=True).get("Item") or {}
    return (SWITCH_EXISTING_ENABLED if row.get("enabled") is True
            else SWITCH_EXISTING_DISABLED)


def register_route(function_url: str, cfg=None) -> None:
    cfg = CFG if cfg is None else cfg
    item = mcp_route_item(function_url, cfg)
    boto3.resource("dynamodb", region_name=_region(cfg)).Table(
        _cfg(cfg, "Platform", "routing_table")).put_item(Item=item)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="部署 API Key 交换层（key-proxy）。幂等可重跑。")
    ap.parse_args(argv)

    cfg = CFG
    # ⓪ 组件门禁（spec §5.1.1）。**返回 0 而不是报错**，且此前后都不发任何
    #    AWS 调用："没配 [ApiKey] 段"是合法的默认状态（OAuth-only）。
    if not api_key_enabled(cfg):
        print("跳过 key-proxy：config.ini 无 [ApiKey] 段 = 平台只允许 OAuth "
              "一条认证路径（spec §5.1.1 组件门禁）。")
        print("  需要给「只能配静态 Header 的 MCP 客户端」发 Key 时，"
              "照 config.ini.example 的 [ApiKey] 段配置后重跑本脚本。")
        return 0

    print("① 校验配置（缺一即中止，绝不带着空值部署）")
    edge_arn = _cfg(cfg, "Deployer", "edge_role_arn", "")
    function_url_statements(edge_arn)        # 缺 / 通配 → 抛错中止
    env_preview = lambda_environment("preview", cfg)   # 端点 / client / scope
    print(f"   MACHINE_SCOPE: {env_preview['MACHINE_SCOPE']}")
    print(f"   {AGENTCORE_ENDPOINT_ENV}: "
          f"{env_preview[AGENTCORE_ENDPOINT_ENV][:60]}…")
    # RoleId 现查：handler 用它确认调用者真是 Edge（edge_caller.caller_is_edge）。
    # 查不到就中止——空值会让线上拒绝所有请求。
    eid = edge_role_id(edge_arn)
    print(f"   Edge RoleId: {eid}")

    print("② IAM 角色")
    role_arn = ensure_role(cfg)
    print(f"   {role_arn}")

    print("③ 打包并部署 Lambda + Function URL(AWS_IAM，仅 edge role)")
    url = ensure_function(role_arn, _build_zip(), eid, cfg)
    print(f"   Function URL: {url}")

    print("④ 哨兵行（不存在才建，且建成关；已存在一个字都不改）")
    state = ensure_switch_row(cfg)
    print(f"   {state}")

    print(f"⑤ 注册 {mcp_subdomain(cfg)} route")
    register_route(url, cfg)
    print(f"   https://{mcp_host(cfg)}/")

    # **组件部署完 ≠ 通道打开**。把这句话说全，否则现场会以为部署失败
    # （拿一把 Key 直连必然 401：keystore 对 `enabled is not True` 一律拒）。
    if state == SWITCH_EXISTING_ENABLED:
        print("\n✅ API Key 总开关：**开**（本次部署未改动它）")
    else:
        print("\n⚠️  API Key 总开关：**关**"
              f"（{'本次新建，fail-closed' if state == SWITCH_CREATED_DISABLED else '线上原本就是关的'}）"
              "\n   此时任何 Key 直连都会 401。去控制台（console 的 API Key 页面，"
              "管理员）打开开关；\n   开关的每次变更都有 ops_log 审计。"
              "\n   本脚本**不会**替你打开它——那会让重跑部署静默覆盖管理员的关闸。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
