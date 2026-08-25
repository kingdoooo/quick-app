#!/usr/bin/env python3
"""账号信任边界的漂移闸门（M09 第 2 步的可执行部分）。

**它不是 M09 的修复，也不假装是。** M09 那条缺陷——同账号持有
`lambda:InvokeFunction` 的 principal 可以直接 invoke panel 与站点 Lambda、
在合成 event 里伪造 `x-user-email`——在**本账号里关不掉**：

- SCP 对 Organizations 管理账号无效，而本部署就在管理账号（`policies/README.md` 边界①）；
- Lambda 的 resource policy 没有写 Deny 的 API（`AddPermission` 只能写 Allow）；
- 应用层给 Edge 加签名也不成立：能读到那把 HS256 密钥的 principal 远多于能 invoke 的，
  于是签名与被签名的东西都在攻击者手里。

**只收窄 `lambda:InvokeFunction` 是假修复**：同一批 principal 还握着密钥读取、
`lambda:UpdateFunctionCode` 与 `iam:PutRolePolicy`，边界一寸也没有移动。
更要紧的是——**冒充任意用户根本不需要 invoke**：拿到密钥就能签任意 email 的会话
cookie 与 `scope=console` 的 `__Host-sb_console`（同一个 `/site-builder/jwt-secret`）。
完整风险模型与实测证据见 `docs/security/account-trust-boundary.md`。

在那之前，本脚本承担唯一还能自动化的职责：**这个集合别再长**。

## 形状：一种能力 = 一个动作等价类 × 一个资源等价类

这句话是本文件最重要的不变量，因为把它压成"单个动作 / 单个资源"这个错误
**已经犯过三次**，每次都产生一个当时看不出来的 false-green：

| 压成什么 | 漏掉了谁 |
|---|---|
| 只探未限定函数 ARN | 挂在 `blue` alias 上的授权（M7 之后站点的 Function URL 全在 alias 上） |
| 只探当前那一个 CDK asset | 带同一把活密钥的 9 个历史对象 |
| 只探 `ssm:GetParameter` | 一个**只**被授予 `ssm:GetParameters`（复数）的角色 |
| IAM 写只对着字面量 `role/*` 模拟 | 6 个精确/窄授权的 principal（IAM 里请求资源是具体 ARN，policy 的 `role/ExactRole` 不匹配字面量 `role/*`；而 `CreatePolicyVersion` 的资源类型根本是 **policy**） |

所以动作与资源都以**类**为单位（见 `A_*` 常量与 `Targets`）。往任一类里加成员时，
同时加一条**只命中该新成员**的用例。

## 它测三层

① **identity 授权**（`iam:SimulatePrincipalPolicy`，枚举全部非 service-linked 角色
   与 IAM 用户）。授权记成 `grant` 串而**不是布尔标签**：
   `invoke-platform:site-panel` 与 `invoke-platform:site-deployer-undeploy` 是两条
   不同的 grant，`invoke-platform:site-panel` 与 `invoke-platform@alias:site-panel`
   也是——压平任一维，对应的扩权就会静静地绿。
   站点全量用稳定聚合 `:all`（否则每建一个站点都会把基线拽红）；**子集带成员指纹**
   `:some(k):<fp>`——只记数量时「失去 site-a、新增 site-b」前后都是 `some(1)`，
   受影响的租户换了一批而闸门不动。

   **限定符是"存在性类"，类内部的成员不区分**：blue 与 green 都算 `@alias`。
   对"能不能冒充任意用户"这个问题，经哪个颜色碰到代码是等价的；而按颜色分开记会
   在每次 blue/green 切换时产生漂移却不带来任何安全信号。**颜色级完整性不由这一层
   负责**——它由 ② 的逐成员比对、部署期的健康门与 `smoke_router.sh` 覆盖。

② **IAM 策略变更**（`iam-policy-write`）走**两步**，不和上面一起模拟：
   先静态解析全部 identity policy 发现候选（`iam:*` / `iam:Put*` 这类通配要展开，
   `Allow`+`NotAction` 保守算命中），再用模拟器对**具体** ARN 确认——资源按动作的
   资源类型落（role / user / **policy**）。判定**三值**：确认有（`:any` / `:scoped`）、
   判不出（`:condition-gated`，模拟器给 implicitDeny 但带 `MissingContextValues`）、
   确认没有。三值是必需的：实测某角色的 `AttachRolePolicy` 被 `iam:PolicyARN`
   限定到两个无害的托管策略，把"判不出"当成"没有"会让它连基线都进不去，
   条件哪天放宽也没人看见。

   **这条 grant 的语义是字面的**："对至少一个真实 IAM 目标持有策略变更动作"，
   **不是**"存在一条完整提权链"——后者还要看目标策略挂在谁身上、能否
   AssumeRole/PassRole、boundary 拦不拦，那是可达性分析，本闸门不做。

③ **resource policy**（`lambda:GetPolicy`，**含每个 alias 与每个已发布版本**）。
   `SimulatePrincipalPolicy` **不会**自动纳入 resource policy（AWS 契约：它只能
   为 IAM user 选择性地带一份，对 role 根本不支持）⇒ 只测 ① 会漏掉
   「给某个角色新加一条 `AddPermission`」。版本不能漏——实测 Edge 的 version 9
   上有一条版本级语句。
   平台函数按**集合等值**比（丢一条 Function URL 授权 = 入口断掉，同样要红）；
   站点函数的 alias **逐成员**比（每个颜色都必须有规范语句——并起来比的话
   「active 色丢了授权、inactive 色还留着」会全绿；已核 blue/green 切换后旧颜色的
   alias/URL/语句都保留，所以逐成员不会误报），版本级做**子集**检查
   （AWS 的 replicator 语句只在当前版本上，旧版本合法地没有）；
   **legacy 形态只认基线里的点名豁免**——
   「存量迁移站点要兼容 legacy」不等于「新站点也可以再产生 legacy」。

④ **密钥物化位置的事实**。密钥有三处明文副本，每次都**实测**而不是假设：
   Edge 函数产物（含每个仍含活密钥的已发布版本）、**CDK bootstrap S3 asset**
   （全部仍含活密钥的对象；asset 位置从**已部署的 CloudFormation 模板**推导，
   不手抄对象 key）、以及 SSM 参数。都比对 SHA-256；某处不再含活密钥时，
   对应资源自动掉出集合、grant 随之消失并报成改善——根治了它，闸门自己就知道。

## 红绿口径（两套，刻意不对称）

- `platform` 类 principal 的授权是"精确且必需"的 ⇒ 按**集合等值**比，
  任一方向的差异都红。只比"新增"时，「Edge 丢掉 `invoke-platform:site-panel`
  但保留 key-proxy」会照样过前缀检查并退出 0。
- 其它类别（含 `platform-overbroad`）：新增红、缩小是改善。
  `platform-overbroad` **就是**要缩小的那一类。
- 事实类数字（`principals_with_missing_context` 等）只报 delta，**不参与红绿**：
  它们随账号里任何一条带 Condition 的新策略变动，让它们决定退出码就会频繁红在
  无关变更上，进而训练出"红了就更新基线"。

## 它**不**证明什么（别把它当"暴露面已穷尽"）

- `SimulatePrincipalPolicy` 对带 Condition 的策略需要调用方补 `ContextEntries`；
  本脚本不补，于是那些 principal 的判定是**下界**。带 `MissingContextValues`
  的 principal 数被记进基线并打印 delta。
- 动作等价类不是穷尽的。
- `iam-policy-write` 只说明持有策略变更动作，**不**证明存在可用的提权链。
- 它只看 IAM 与 Lambda resource policy 两条通道，不看 KMS grants、
  VPC endpoint policy、以及其它服务的 resource policy。
- 它不看跨账号 principal，也看不见"临时建了一个角色用完就删"。

用法（**用系统 python3 跑**，deployer/.venv 的 CA 信任库是空的）：

    python3 site-builder/scripts/verify_account_trust_boundary.py
    python3 site-builder/scripts/verify_account_trust_boundary.py --update-baseline
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import configparser
import hashlib
import io
import json
import re
import sys
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SITE_BUILDER = _HERE.parent
BASELINE_PATH = _HERE / "account_trust_baseline.json"
CONFIG_PATH = _SITE_BUILDER / "config.ini"
APP_PY = _SITE_BUILDER / "deployer" / "infra" / "app.py"

BASELINE_SCHEMA = 2
JWT_PARAM_NAME = "/site-builder/jwt-secret"
DEPLOYER_EXEC_ROLE = "site-deployer-exec-role"

# Edge 函数名：router 栈的两个 Lambda@Edge 里，**origin-request 那个**才内联着
# 会话密钥（`stack.py` 把 `{{JWT_SECRET}}` 替换进它）。origin-response 不验签。
EDGE_ORIGIN_REQUEST_FN = "ApplicationWebRouterStack-application-web-router"
EDGE_ORIGIN_RESPONSE_FN = "ApplicationWebRouterStack-origin-response"
# **这两个必须手写**：它们属于 router 栈，而 `PLATFORM_FUNCTION_NAMES` 是
# deployer 栈 `infra/app.py` 里的清单，结构上不可能含它们。漏掉的后果实测过一次
# ——Edge 的 9 个已发布版本一个都没被枚举，于是「谁能读某个旧版本的 Edge 代码
# （里面就是明文密钥）」「谁能 UpdateFunctionCode 换掉 Edge」两条完全在视野外。
EDGE_FUNCTIONS = (EDGE_ORIGIN_REQUEST_FN, EDGE_ORIGIN_RESPONSE_FN)
# 产物里密钥的形态：`JWT_SECRET = "<64 hex>"`。只用来**定位**，不打印取到的值。
_SECRET_ASSIGN_RE = re.compile(r"""JWT_SECRET\s*=\s*["']([^"']*)["']""")

# ---- grant 词表 ----------------------------------------------------------
# grant 是 `种类[:资源]` 形态的字符串，进基线文件。改词表等于基线全量漂移。
G_INVOKE_PLATFORM = "invoke-platform"      # + ":<函数名>"
G_INVOKE_SITE = "invoke-site"              # + ":all" / ":some(k)"
G_REPLACE_CODE = "replace-platform-code"   # + ":<函数名>"
# 读密钥的三条路**必须分开记**：严重度与修法都不同。
#  · read-edge-code：`lambda:GetFunction` 下载 Edge 产物，密钥是**明文**在
#    `index.py` 里（Lambda@Edge 不支持环境变量，只能部署时字符串替换）。
#    不经 KMS、不需 invoke。AWS 托管的 `ReadOnlyAccess` 就带这个动作。
#  · read-edge-asset：同一份产物在 **CDK bootstrap S3 桶**里还有一份（asset）。
#    每次 Edge 部署留一个新对象，旧对象不会被删 ⇒ 密钥不轮转的话，**历次**
#    asset 都带着当前有效的密钥。桶策略只 Deny 非 TLS；对象用 `alias/aws/s3`，
#    该托管键的策略是 `Principal:*` + `ViaService=s3` 的**直接授权**，所以
#    identity policy 里的 `s3:GetObject` 单独就够。
#  · read-jwt-param：`ssm:GetParameter` 读 SecureString。KMS 那道同样是虚的
#    （`alias/aws/ssm` 的 key policy 是同一种直接授权形态）。
G_READ_EDGE_CODE = "read-edge-code"
G_READ_EDGE_ASSET = "read-edge-asset"
G_READ_JWT_PARAM = "read-jwt-param"
# **名字刻意不叫 self-escalate**：持有一个 IAM 策略变更动作**不等于**存在一条完整
# 提权链——还要看目标策略挂在谁身上、能否 AssumeRole/PassRole、boundary 拦不拦。
# 那是可达性分析，本闸门不做（写进文档的"不证明什么"）。这条 grant 的语义就是
# 字面意思：**对至少一个真实 IAM 目标持有策略变更动作**。
G_IAM_POLICY_WRITE = "iam-policy-write"
SECRET_GRANTS = (G_READ_EDGE_CODE, G_READ_EDGE_ASSET, G_READ_JWT_PARAM)

# ---- 动作等价类 ----------------------------------------------------------
# **一种能力 = 一个动作等价类 × 一个资源等价类。** 这个形状是本文件最重要的
# 不变量，因为把它压成"单个动作/单个资源"这个错误已经犯过三次：
#   · 首版只探未限定函数 ARN ⇒ 挂在 blue alias 上的授权全看不见（M7 之后站点
#     的 Function URL 都在 alias 上）；
#   · 首版只探当前那一个 CDK asset ⇒ 带同一把活密钥的 9 个历史对象看不见；
#   · 首版只探 `ssm:GetParameter` ⇒ 一个**只**被授予 `ssm:GetParameters`
#     （复数）的角色被整个漏掉（2026-08-25 实测，它没有 boundary，
#     `WithDecryption=true` 即可读出当前密钥）。
# 往任一类里加动作/资源时，同时加一条只命中该新成员的用例。
A_INVOKE = ("lambda:InvokeFunction",)
A_REPLACE = ("lambda:UpdateFunctionCode",)
# 下载产物：`GetFunction` 返回代码的预签名 URL。`GetFunctionConfiguration`
# 不返回代码，所以不在类里。
A_READ_CODE = ("lambda:GetFunction",)
# 桶开着版本控制（noncurrent 保留 30 天），而 `GetObjectVersion` 是**另一个**
# 动作 ⇒ 对象被删之后旧版本仍可按 version ID 读到。
A_READ_OBJECT = ("s3:GetObject", "s3:GetObjectVersion")
# 四个动作都能读出同一个 SecureString 的明文；AWS 明确警告
# `GetParameterHistory` 在拒绝 `GetParameter` 时仍可能读到当前值。
A_READ_PARAM = ("ssm:GetParameter", "ssm:GetParameters",
                "ssm:GetParametersByPath", "ssm:GetParameterHistory")
# IAM 策略变更动作。**不能和上面几类一起丢给模拟器**：IAM 里请求资源是具体 ARN，
# 而 policy 里的 `role/ExactRole` 不会匹配字面量 `role/*` ⇒ 拿 `role/*` 去问，
# 精确授权全部隐形（实测漏掉 6 个 principal）。而且 `iam:CreatePolicyVersion`
# 的资源类型是 **policy** 不是 role，对着 role ARN 问等于永远问不到。
# 所以这一类走"静态解析发现候选 → 模拟器对**具体** ARN 确认"两步，见
# `iam_write_candidates_from_statements` / `confirm_iam_write`。
IAM_WRITE_ACTIONS = ("iam:PutRolePolicy", "iam:AttachRolePolicy",
                     "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion",
                     "iam:PutUserPolicy", "iam:AttachUserPolicy")
IAM_WRITE_RESOURCE_KIND = {
    "iam:PutRolePolicy": "role", "iam:AttachRolePolicy": "role",
    "iam:UpdateAssumeRolePolicy": "role",
    "iam:CreatePolicyVersion": "policy",
    "iam:PutUserPolicy": "user", "iam:AttachUserPolicy": "user",
}

# 限定符类：grant 串里用 `@alias` / `@version` 标出来。**不能与未限定合并**
# ——`function:foo` 与 `function:foo:blue` 在 IAM 里是两个资源，合并之后
# 「原来只能调 :blue、现在还能调未限定」这种扩权会静静地绿。
Q_UNQUALIFIED = ""
Q_ALIAS = "@alias"
Q_VERSION = "@version"

# 两条正向控制：这两个 principal **必须**保留下列 grant（按前缀命中即可）。
# 丢了的真机症状分别是「全站 403」与「每次部署在健康门失败」，两者都不会在
# 任何单测里出现——所以收窄动作把平台自己锁死时，只有这条会红。
REQUIRED_GRANT_PREFIXES = {
    "edge": (f"{G_INVOKE_PLATFORM}:", f"{G_INVOKE_SITE}",),
    # blue/green 健康门是**带 Qualifier** 的直调，所以这里锁 alias 那一类，
    # 不是"任意 invoke-site"——收窄只砍掉 alias 授权时前者才会红。
    "deployer": (f"{G_INVOKE_SITE}{Q_ALIAS}:",),
}

# 两次 simulate 调用的动作分组：函数类资源一组，其余一组。分开是为了不产生
# 大量无意义的 (动作, 资源) 组合——一次调用的响应体是资源数 × 动作数。
ACTIONS_FUNCTION = A_INVOKE + A_REPLACE + A_READ_CODE
ACTIONS_OTHER = A_READ_OBJECT + A_READ_PARAM
ACTIONS = ACTIONS_FUNCTION + ACTIONS_OTHER


# ---------------------------------------------------------------- 纯函数部分

def _group(hex_digest: str, size: int = 4) -> str:
    return "-".join(hex_digest[i:i + size] for i in range(0, len(hex_digest), size))


def principal_fingerprint(arn: str) -> str:
    """ARN → 16 位指纹。

    基线文件里**只能**出现指纹：账号内若干角色的名字内嵌账号 ID（CDK bootstrap
    那几个），照抄角色名就把账号值提交进了仓库（仓库红线）。指纹单向、稳定，
    足够回答"这个 principal 之前在不在基线里"。

    **每 4 位分组**（`a1b2-c3d4-…`）不是为了好看：裸 16 位十六进制里会偶然出现
    12 位连续数字，而 `scripts/scan_staged_secrets.sh` 按 `[0-9]{12}` 找账号 ID
    ⇒ 每次更新基线都命中一次假阳性。假阳性反复出现的代价是有人开始无脑
    `--allow-hits`，那时真的账号值就进去了。分组让最长数字串等于 4，结构上不可能命中。
    """
    return _group(hashlib.sha256(arn.encode("utf-8")).hexdigest()[:16])


def decisions_from_simulation(evaluation_results: list[dict]) -> dict[str, str]:
    """`SimulatePrincipalPolicy` 的结果 → `{"action|resource_arn": decision}`。

    **必须读 `ResourceSpecificResults`。** 传多个 `ResourceArns` 时，顶层
    `EvalDecision` 是聚合项、顶层 `EvalResourceName` 是
    `arn:aws:lambda:${Region}:${Account}:${ResourceType}:${ResourceId}` 这样的
    ARN 模板。只读顶层会把「对某一个函数 allowed」读成「对全部资源 allowed」，
    而且模板串会作为一个不存在的资源混进结果里。
    """
    out: dict[str, str] = {}
    for res in evaluation_results:
        action = res["EvalActionName"]
        per_resource = res.get("ResourceSpecificResults") or []
        if not per_resource:
            # 单资源（或未传 ResourceArns）时 AWS 只给顶层。此时顶层就是真值，
            # 但要挡住 ARN 模板混进来。
            name = res.get("EvalResourceName", "*")
            if "${" not in name:
                out[f"{action}|{name}"] = res["EvalDecision"]
            continue
        for rr in per_resource:
            out[f"{action}|{rr['EvalResourceName']}"] = rr["EvalResourceDecision"]
    return out


def missing_context_in(evaluation_results: list[dict]) -> bool:
    """这批判定里有没有"因为缺 Condition 上下文而不确定"的部分。

    **必须同时看顶层与每个 `ResourceSpecificResults` 条目**：真实响应里
    `MissingContextValues` 常常**只**出现在逐资源那一层，只看顶层会把它读成
    "没有不确定"（Codex 复审 P2 指出，已复现）。

    有不确定就说明该 principal 的 grant 集合只是**下界**。本脚本不补
    `ContextEntries`（补不全），但必须把这件事记下来，不能把未知静默压成
    "没有权限"。
    """
    for res in evaluation_results:
        if res.get("MissingContextValues"):
            return True
        for rr in res.get("ResourceSpecificResults") or []:
            if rr.get("MissingContextValues"):
                return True
    return False


@dataclass(frozen=True)
class Targets:
    """模拟的目标资源（ARN 形态，由调用方按真实账号拼好）。

    每一项都是一个**资源等价类**，不是单个资源：

    - `alias_arns` / `version_arns`：未限定 ARN → 它的 alias / 版本 ARN。
      M7 之后站点的 Function URL 与授权语句都挂在 `blue` 上，且 AWS 支持把
      permission 限定到具体 version ⇒ 只探未限定 ARN 等于看一个空集。
    - `edge_code_arns`：Edge 函数**及其每个仍含活密钥的已发布版本**。
    - `edge_assets`：CDK bootstrap 桶里**全部**仍含活密钥的对象（实测 9 个，
      因为旧 asset 不删而密钥从未轮转）。空元组表示已根治，此时不产生
      `read-edge-asset`——闸门因此是在测事实，不是复读写死的假设。
    """
    platform_functions: tuple[str, ...]
    site_functions: tuple[str, ...]
    edge_code_arns: tuple[str, ...]
    edge_assets: tuple[str, ...]
    jwt_parameter: str
    alias_arns: dict[str, tuple[str, ...]] = field(default_factory=dict)
    version_arns: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def function_resources(self) -> list[str]:
        out = list(self.platform_functions) + list(self.site_functions)
        out.extend(self.edge_code_arns)
        for mapping in (self.alias_arns, self.version_arns):
            for arns in mapping.values():
                out.extend(arns)
        return sorted(set(out))

    def other_resources(self) -> list[str]:
        return sorted(set(self.edge_assets) | {self.jwt_parameter})


def _fn_name(arn: str) -> str:
    return arn.rsplit(":function:", 1)[-1]


def grants_from_decisions(decisions: dict[str, str], t: Targets) -> set[str]:
    """逐资源判定 → grant 集合。

    形状是 `种类[@限定符类][:资源]`。三条刻意的选择：

    - **平台函数逐个记名字**：压成一个布尔时，「只能调 undeploy」与
      「还能调 panel」在基线里长得一样，而后者才是 panel 读面失守的入口。
    - **站点函数按类聚合**（`:all` / `:some(k)`）：逐个记名字会让每次建站/下线
      都把基线拽红，于是基线被迫频繁重写，"新增即红"随之失效。
    - **限定符不并入未限定**：`function:foo` 与 `function:foo:blue` 是两个资源。
    """
    def allowed(actions, resources) -> bool:
        return any(decisions.get(f"{a}|{r}") == "allowed"
                   for a in actions for r in resources)

    grants = set()
    for arn in t.platform_functions:
        name = _fn_name(arn)
        for qual, resources in ((Q_UNQUALIFIED, (arn,)),
                                (Q_ALIAS, t.alias_arns.get(arn, ())),
                                (Q_VERSION, t.version_arns.get(arn, ()))):
            if resources and allowed(A_INVOKE, resources):
                grants.add(f"{G_INVOKE_PLATFORM}{qual}:{name}")
        # UpdateFunctionCode 只作用于未限定函数（alias/version 没有自己的代码）。
        if allowed(A_REPLACE, (arn,)):
            grants.add(f"{G_REPLACE_CODE}:{name}")

    if t.site_functions:
        total = len(t.site_functions)
        for qual, pick in ((Q_UNQUALIFIED, lambda a: (a,)),
                           (Q_ALIAS, lambda a: t.alias_arns.get(a, ())),
                           (Q_VERSION, lambda a: t.version_arns.get(a, ()))):
            n = sum(1 for arn in t.site_functions
                    if pick(arn) and allowed(A_INVOKE, pick(arn)))
            members = sorted(_fn_name(arn) for arn in t.site_functions
                             if pick(arn) and allowed(A_INVOKE, pick(arn)))
            if len(members) == total:
                # `all` 保持稳定聚合：否则每建一个站点都把基线拽红。
                grants.add(f"{G_INVOKE_SITE}{qual}:all")
            elif members:
                # 子集形态**带成员指纹**：只记数量时，「失去 site-a、新增 site-b」
                # 前后都是 some(1)，受影响的租户换了一批而闸门不动。
                # 指纹只覆盖被允许的那些站点 ⇒ 新建一个它碰不到的站点不产生漂移。
                grants.add(f"{G_INVOKE_SITE}{qual}:some({len(members)}):"
                           f"{principal_fingerprint('sites:' + ','.join(members))}")

    if t.edge_code_arns and allowed(A_READ_CODE, t.edge_code_arns):
        grants.add(G_READ_EDGE_CODE)
    if t.edge_assets and allowed(A_READ_OBJECT, t.edge_assets):
        grants.add(G_READ_EDGE_ASSET)
    if allowed(A_READ_PARAM, (t.jwt_parameter,)):
        grants.add(G_READ_JWT_PARAM)
    return grants


def policy_statements(document) -> list[dict]:
    """策略文档 → 语句列表。

    `GetAccountAuthorizationDetails` 有时把文档作为 **URL 编码的字符串**返回
    （实测踩到过，不解码就静默漏掉整份策略）；`Statement` 也可能是单个对象而
    不是列表。
    """
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    statements = document.get("Statement", [])
    return statements if isinstance(statements, list) else [statements]


def expand_iam_write_actions(patterns) -> set[str]:
    """动作模式 → 命中的 IAM 写动作集合。`*` / `iam:*` / `iam:Put*` 都要展开。"""
    patterns = patterns if isinstance(patterns, list) else [patterns]
    hit = set()
    for raw in patterns:
        pat = raw.lower()
        if pat in ("*", "iam:*"):
            return set(IAM_WRITE_ACTIONS)
        if pat.endswith("*"):
            prefix = pat[:-1]
            hit |= {a for a in IAM_WRITE_ACTIONS if a.lower().startswith(prefix)}
        else:
            hit |= {a for a in IAM_WRITE_ACTIONS if a.lower() == pat}
    return hit


def iam_write_resource_kind(action: str) -> str:
    return IAM_WRITE_RESOURCE_KIND[action]


def iam_write_candidates_from_statements(statements: list[dict]) -> dict:
    """一个 principal 的全部语句 → IAM 写候选（动作 + 目标模式 + 是否无限制）。

    **这是"发现"，不是"判定"**：静态解析不评估 Condition，所以会过报；
    每个候选都要再用模拟器对一个**具体** ARN 确认（`confirm_iam_write`）。
    反过来它必须是超集——已用正对照核过：模拟器用 `role/*` 找到的 16 个
    全部落在静态解析的 22 个里。
    """
    actions: set[str] = set()
    targets: list[str] = []
    unrestricted = False
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            # `Allow` + `NotAction` 约等于"除了这些之外全给"。解析不出具体动作时
            # 保守算命中——把它当"没有"才是危险方向。
            hit = set(IAM_WRITE_ACTIONS)
        else:
            hit = expand_iam_write_actions(st.get("Action", []))
        if not hit:
            continue
        actions |= hit
        res = st.get("Resource", "*")
        res = res if isinstance(res, list) else [res]
        for r in res:
            if r == "*":
                unrestricted = True
            targets.append(r)
    return {"actions": actions, "targets": sorted(set(targets)),
            "unrestricted": unrestricted}


def iam_write_grants(candidate: dict) -> set[str]:
    """静态解析结果 → grant（**只用于单测与文档说明**；真机走
    `iam_write_grants_from_probes`，因为静态解析不评估 Condition）。"""
    if not candidate.get("actions"):
        return set()
    scope = "any" if candidate.get("unrestricted") else "scoped"
    return {f"{G_IAM_POLICY_WRITE}:{scope}"}


def iam_write_grants_from_probes(probes: list[dict]) -> set[str]:
    """模拟器对具体 ARN 的确认结果 → grant。**三值，不是两值。**

    `probes` 的每项：`{"pattern", "decision", "missing_context"}`。

    - 有 `allowed` ⇒ `:any`（目标模式是 `*`）或 `:scoped`；
    - 全不 allowed 但**有** `MissingContextValues` ⇒ `:condition-gated`
      ——"判不出"不能静默当成"没有"。实测现场：某角色的 `AttachRolePolicy` 被
      `iam:PolicyARN` 的 ArnEquals 限定到两个无害的 AWS 托管策略，模拟器给
      `implicitDeny` + 缺 `iam:PolicyARN`。把它当"没有"的话，这个 principal 连基线
      都进不去，条件哪天被放宽也没人会看见；记成 `condition-gated` 之后，
      放宽会表现为**新** grant ⇒ 红。
    - 其余 ⇒ 无 grant。
    """
    allowed = [p for p in probes if p.get("decision") == "allowed"]
    if allowed:
        scope = "any" if any(p["pattern"] == "*" for p in allowed) else "scoped"
        return {f"{G_IAM_POLICY_WRITE}:{scope}"}
    if any(p.get("missing_context") for p in probes):
        return {f"{G_IAM_POLICY_WRITE}:condition-gated"}
    return set()


# 拿来把模式落成具体 ARN 的固定后缀。**必须是固定值**：随机值会让两次运行的
# 模拟请求不同，而"这个 principal 能不能改 IAM"的答案不该随探针名字变。
_PROBE_SUFFIX = "sb-trust-probe"


def concrete_target(pattern: str, kind: str, *, account: str) -> str:
    """目标模式 → 一个可以喂给模拟器的**具体** ARN。

    模拟器要的是具体资源；拿 `role/*` 这种字面量去问，policy 里的
    `role/ExactRole` 匹配不上 ⇒ 精确授权全部隐形（这正是首版的缺陷）。
    """
    if pattern == "*" or ":" not in pattern:
        return f"arn:aws:iam::{account}:{kind}/{_PROBE_SUFFIX}"
    _, _, tail = pattern.partition(f":{kind}/")
    if not tail:
        # 模式的资源类型与该动作不符（例如把 policy 模式配给 PutRolePolicy）：
        # 落一个该类型下的探针名，让模拟器给出真实答案而不是靠猜。
        return f"arn:aws:iam::{account}:{kind}/{_PROBE_SUFFIX}"
    # **账号段一律落成本账号**：跨账号模式（`arn:aws:iam::*:role/x*`）不换的话，
    # 喂给模拟器的字面量 `*` 恰好会被模式里的 `*` 匹配上——答案碰巧对，
    # 而碰巧对的判据下一次就可能碰巧错。名字段里的 `*` 换成固定探针名。
    return f"arn:aws:iam::{account}:{kind}/{tail.replace('*', _PROBE_SUFFIX)}"


def statement_fingerprint(statement: dict, *, account: str, function: str,
                          qualifier: str | None = None) -> str:
    """Lambda resource policy 的单条语句 → 指纹。

    归一化掉账号 ID、**函数自身**的名字、以及 alias 名，这样不同站点函数的
    `edge-invoke` 语句会得到同一个指纹 ⇒ 可以用少数几份"形态"覆盖全部站点函数，
    新建站点不产生漂移，而多出一条语句的站点会被咬住。

    **alias 名归一化成 `<alias>` 而不是抹掉**：挂在 `blue` 上与挂在未限定函数上
    是两种不同宽度的授权（后者更宽），抹掉会让两者变成同一个指纹。

    只存指纹：语句里的 Principal 是带账号 ID 的角色 ARN（仓库红线）。
    """
    raw = json.dumps(statement, sort_keys=True, ensure_ascii=False)
    raw = raw.replace(account, "<acct>")
    if qualifier:
        raw = raw.replace(f"{function}:{qualifier}", "<self>:<alias>")
    raw = raw.replace(function, "<self>")
    return _group(hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16])


def resource_policy_snapshot(policies: dict[str, list[tuple[str | None, dict]]], *,
                             account: str, platform: tuple[str, ...],
                             sites: tuple[str, ...],
                             aliases: dict[str, tuple[str, ...]]) -> dict:
    """`{函数名: [(qualifier, 语句)…]}` → 快照。**这里不做任何判断。**

    平台函数记成一个扁平指纹集合（名字稳定，逐个比）；站点函数**按限定符类
    分组**（`unqualified` / `alias` / `version`），因为"有没有未限定语句"正是
    legacy 与 modern 两种部署形态的判据，压平之后就没法只允许 modern。

    合法性判据在基线里（见 `compare_to_baseline`）。早先版本在这里用**并集**
    算规范形态，结果最宽松的那个站点函数反而成了规范、规矩的那个被报成偏离
    ——判断和观测混在一处就会这样。
    """
    def fp(fn: str, q: str | None, st: dict) -> str:
        return statement_fingerprint(st, account=account, function=fn, qualifier=q)

    def qual_class(fn: str, q: str | None) -> str:
        if q is None:
            return "unqualified"
        return "alias" if q in aliases.get(fn, ()) else "version"

    flat = {fn: sorted({fp(fn, q, st) for q, st in policies.get(fn, [])})
            for fn in platform}
    grouped: dict[str, dict] = {}
    for fn in sites:
        # **alias 逐成员记**（`{颜色: [指纹…]}`）：并起来记的话，
        # 「blue 丢了授权、green 还留着」两者相加仍等于规范集合 ⇒ 全绿。
        # M7 切换后旧颜色的 alias / Function URL / 两条语句都保留（代码里没有任何
        # 地方删它们），所以"每个颜色都完整"不会误报。
        alias_members: dict[str, set[str]] = {a: set() for a in aliases.get(fn, ())}
        version_fps: set[str] = set()
        unqualified: set[str] = set()
        for q, st in policies.get(fn, []):
            kind = qual_class(fn, q)
            if kind == "alias":
                alias_members.setdefault(q, set()).add(fp(fn, q, st))
            elif kind == "version":
                version_fps.add(fp(fn, q, st))
            else:
                unqualified.add(fp(fn, q, st))
        grouped[fn] = {"alias": {a: sorted(v) for a, v in alias_members.items()},
                       "version": sorted(version_fps),
                       "unqualified": sorted(unqualified)}
    return {"platform": flat, "sites": grouped}


def site_shape_canonicals(sites: dict[str, dict[str, list[str]]]) -> dict:
    """写基线时从实测推出四件事：

    - `site_alias_canonical` —— alias 上那份语句的规范形态（众数）；
    - `site_version_canonical` —— 版本级语句的规范形态（当前站点函数上为空）；
    - `site_legacy_canonical` —— legacy 站点残留的未限定语句形态；
    - `site_legacy_exempt` —— **点名豁免**的 legacy 站点（存站点名指纹）。

    为什么 legacy 必须是点名豁免而不是全局合法形态：「存量迁移站点需要兼容
    legacy」不等于「今后新建站点也可以再产生 legacy」。把两种形态都设成全局
    白名单时，一个**全新**站点带着未限定 policy 也会全绿（Codex 复审 P1-3③）。
    豁免集合只能缩小——某个 legacy 站点迁成 modern 之后，闸门会把"豁免可以去掉"
    报成改善。
    """
    def mode(shapes) -> list[str]:
        counts: dict[tuple[str, ...], int] = {}
        for shape in shapes:
            k = tuple(sorted(shape))
            if k:
                counts[k] = counts.get(k, 0) + 1
        if not counts:
            return []
        return list(max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0])

    # alias 的规范形态取**逐成员**的众数（每个颜色一票），不是每个站点一票。
    alias_shapes = [fps for shape in sites.values()
                    for fps in (shape.get("alias") or {}).values()]
    # 版本级语句做**子集**检查，所以规范形态取并集：AWS 的 replicator 语句只出现在
    # 当前 Edge 版本上，旧版本合法地没有它——逐成员等值会把 1..8 全报成缺语句。
    version_union = sorted({fp for shape in sites.values()
                            for fp in shape.get("version", [])})
    legacy = sorted(fn for fn, shape in sites.items() if shape.get("unqualified"))
    return {"site_alias_canonical": mode(alias_shapes),
            "site_version_canonical": version_union,
            "site_legacy_canonical": mode(
                [shape.get("unqualified", []) for shape in sites.values()]),
            "site_legacy_exempt": [site_fingerprint(fn) for fn in legacy]}


def site_fingerprint(function_name: str) -> str:
    """站点函数名 → 指纹（豁免名单只存指纹，与 principal 同一套编码规则）。"""
    return principal_fingerprint(f"site:{function_name}")


# 红字段的**唯一真源**：(字段名, render 的标签, main() 的处置文案 key)。
#
# 为什么要有这张表：红判据原先散在**三处**——`Report.ok`、`render()` 里带「（红）」的
# 标签、以及 `main()` 里两条处置文案的条件。加一个红字段而忘了改 `ok`，闸门就跑绿，
# 而"跑绿"与"确实没有漂移"在输出上一模一样；当时 62 条用例没有一条会红。
#
# 加字段必须同时进这张表或 `GREEN_FIELDS`，否则
# `test_report_fields_are_all_classified` 会红（它按 dataclass 字段全集比对）。
RED_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("new_principals",       "新增 principal（红）",                         "grew"),
    ("new_grants",           "已知 principal 长出新授权（红）",              "grew"),
    ("missing_required",     "必需授权丢失（红）",                           "lost"),
    ("new_statements",       "新增 resource policy 语句（红）",              "grew"),
    ("site_policy_outliers", "站点函数的 resource policy 偏离规范形态（红）", "grew"),
)
GREEN_FIELDS: tuple[tuple[str, str], ...] = (
    ("unclassified", "基线里未分类（请标注 category）"),
    ("improvements", "集合缩小（绿；可更新基线）"),
    ("notes",        "事实与口径（不参与红绿）"),
)
# 每个红字段都要有一条**处置**文案：闸门红了但不说该怎么办，等于把判断推给下一个人，
# 而最省力的"处置"永远是更新基线。
RED_MESSAGES = {
    "grew": ("闸门红：账号里能冒充任意用户的授权面**变大了**。这不是又出了一个新缺陷，"
             "而是既有暴露面扩张。处理方式见 docs/security/account-trust-boundary.md。"),
    "lost": ("闸门红：平台自己的必需 invoke 权限丢了。真机症状是全站 403（Edge）或每次"
             "部署在健康门失败（deployer）——**先确认是不是刚做过一次收窄**，别去查网络。"),
}


@dataclass
class Report:
    new_principals: list[str] = field(default_factory=list)
    new_grants: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    new_statements: list[str] = field(default_factory=list)
    site_policy_outliers: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(getattr(self, name) for name, _, _ in RED_FIELDS)

    def render(self) -> str:
        lines = []
        for name, label in ([(n, l) for n, l, _ in RED_FIELDS] + list(GREEN_FIELDS)):
            rows = getattr(self, name)
            if rows:
                lines.append(f"{label}：")
                lines.extend(f"  - {r}" for r in rows)
        if not lines:
            lines.append("与基线一致。")
        return "\n".join(lines)


def compare_to_baseline(observed: dict[str, dict], baseline: dict, *,
                        required: dict[str, str],
                        resource_policies: dict | None = None,
                        facts: dict | None = None) -> Report:
    """observed = {fingerprint: {"name", "arn", "grants"}}。

    **红绿口径按类别分两套，这是刻意的不对称**：

    - `platform` 类的授权是"精确且必需"的 ⇒ 按**集合等值**比，
      任一方向的差异都红。首版只比 `gained`，于是「Edge 丢掉
      `invoke-platform:site-panel` 但保留 key-proxy」照样过前缀检查、
      退出 0（Codex 复审 P1-4 的最小反例）。
    - 其它类别（含 `platform-overbroad`）保持不对称：新增红、缩小是改善。
      `platform-overbroad` **就是**要缩小的那一类，把它的缩小判成红会
      把我们想要的修复报成故障。
    """
    base = baseline.get("principals", {})
    rep = Report()

    for fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        grants = set(p["grants"])
        if fp not in base:
            rep.new_principals.append(f"{p['name']}  [{fp}]  {sorted(grants)}")
            continue
        was = set(base[fp].get("grants", []))
        category = base[fp].get("category")
        gained, lost = grants - was, was - grants
        if gained:
            rep.new_grants.append(f"{p['name']}  [{fp}]  +{sorted(gained)}")
        if lost:
            if category == "platform":
                rep.missing_required.append(
                    f"{p['name']}（platform）丢了 {sorted(lost)}——平台授权是精确且"
                    f"必需的，丢失同样要红")
            else:
                rep.improvements.append(f"{p['name']}  [{fp}]  -{sorted(lost)}")
        if category in (None, "", "unclassified"):
            rep.unclassified.append(f"{p['name']}  [{fp}]")

    for fp, b in sorted(base.items()):
        if fp not in observed:
            entry = (f"[{fp}] 不再具备任何敏感授权（原 {b.get('category', '?')}："
                     f"{sorted(b.get('grants', []))}）")
            if b.get("category") == "platform":
                rep.missing_required.append(
                    f"[{fp}] 是 platform 角色却整个消失了：{entry}")
            else:
                rep.improvements.append(entry)

    by_name = {p["name"]: set(p["grants"]) for p in observed.values()}
    for label, role_name in required.items():
        prefixes = REQUIRED_GRANT_PREFIXES[label]
        have = by_name.get(role_name)
        if have is None:
            rep.missing_required.append(
                f"{role_name}（{label}）不在结果里——它必须保留 {list(prefixes)}")
            continue
        for prefix in prefixes:
            if not any(g.startswith(prefix) for g in have):
                rep.missing_required.append(
                    f"{role_name}（{label}）缺 {prefix}*（现有 {sorted(have)}）")

    if resource_policies is not None:
        _compare_resource_policies(rep, baseline.get("resource_policies") or {},
                                   resource_policies)

    _compare_facts(rep, baseline.get("facts") or {}, facts)
    return rep


def _compare_resource_policies(rep: Report, base_rp: dict, now_rp: dict) -> None:
    """平台函数按**集合等值**比（丢失一条 Function URL 授权语句 = 控制台或站点
    入口断掉，首版把它写成"改善"）；站点函数按限定符类逐类比，legacy 只认
    点名豁免。"""
    base_platform = base_rp.get("platform", {})
    for fn in sorted(set(base_platform) | set(now_rp.get("platform", {}))):
        was = set(base_platform.get(fn, []))
        now = set(now_rp.get("platform", {}).get(fn, []))
        if now - was:
            rep.new_statements.append(f"{fn}: +{sorted(now - was)}")
        if was - now:
            rep.new_statements.append(
                f"{fn}: 少了 {sorted(was - now)}——平台函数的 resource policy 是"
                f"精确且必需的，丢失同样要红")

    alias_canon = set(base_rp.get("site_alias_canonical", []))
    version_canon = set(base_rp.get("site_version_canonical", []))
    legacy_canon = set(base_rp.get("site_legacy_canonical", []))
    exempt = set(base_rp.get("site_legacy_exempt", []))
    seen_exempt = set()

    for fn, shape in sorted((now_rp.get("sites") or {}).items()):
        fp = site_fingerprint(fn)
        version = set(shape.get("version", []))
        unqualified = set(shape.get("unqualified", []))
        problems = []
        # alias **逐成员**比：每个颜色都必须有规范语句。并起来比的话，
        # 「active 色丢了授权、inactive 色还留着」会全绿。
        for color, fps in sorted((shape.get("alias") or {}).items()):
            member = set(fps)
            if member == alias_canon:
                continue
            extra, missing = sorted(member - alias_canon), sorted(alias_canon - member)
            if extra:
                problems.append(f"alias `{color}` 多出语句 {extra}")
            if missing:
                problems.append(
                    f"alias `{color}` 缺语句 {missing}"
                    f"（这一色的入口已断；若它是 active color 则该站点整站 403）")
        # 版本级只做**子集**检查（见 site_shape_canonicals 里的理由）。
        if version - version_canon:
            problems.append(f"版本级出现未知语句 {sorted(version - version_canon)}")
        if unqualified:
            if fp not in exempt:
                problems.append(
                    f"出现未限定 policy {sorted(unqualified)}——只有基线点名豁免的"
                    f"存量 legacy 站点允许有它，新站点必须是 alias-only")
            elif unqualified != legacy_canon:
                problems.append(f"legacy 未限定语句偏离 {sorted(unqualified ^ legacy_canon)}")
            else:
                seen_exempt.add(fp)
        if problems:
            rep.site_policy_outliers.append(f"{fn}: " + "；".join(problems))

    for fp in sorted(exempt - seen_exempt):
        rep.improvements.append(
            f"[{fp}] 这个 legacy 站点已不再有未限定 policy（迁成 alias-only 或已下线）"
            f"——可以把它从 site_legacy_exempt 豁免名单里去掉")


def _compare_facts(rep: Report, base_facts: dict, now_facts: dict | None) -> None:
    """事实类数字只报 delta，**不参与红绿**——理由写在这里，因为它是个刻意的选择。

    `principals_with_missing_context` 会随账号里任何一条带 Condition 的新策略
    变动，跟本平台无关；让它决定退出码就会频繁红在无关变更上，
    进而训练出"红了就更新基线"。所以：算出来、打印出来、不影响退出码。
    带活密钥的 asset 数同理（每次 Edge 部署就多一个）。
    """
    if not base_facts and not now_facts:
        return
    if now_facts is None:
        rep.notes.append(
            f"基线记录的事实：{json.dumps(base_facts, ensure_ascii=False)}"
            f"（本次未重新测量）")
        return
    for key in sorted(set(base_facts) | set(now_facts)):
        was, now = base_facts.get(key), now_facts.get(key)
        if isinstance(was, int) and isinstance(now, int) and was != now:
            rep.notes.append(f"{key}: {was} → {now}（{now - was:+d}）")
        elif was != now:
            rep.notes.append(f"{key}: {was!r} → {now!r}")
        else:
            rep.notes.append(f"{key}: {now}（与基线一致）")


def platform_function_names(app_py: Path = APP_PY) -> tuple[str, ...]:
    """`infra/app.py` 的 `PLATFORM_FUNCTION_NAMES`（AST 取，不 import——
    app.py 顶层 import aws_cdk，普通解释器里没有）。

    手抄一份平台函数名清单就会与栈漂移：新加一个平台函数时，
    它会被当成"用户站点"，于是逐函数的 grant 少记一条。
    """
    src = app_py.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == "PLATFORM_FUNCTION_NAMES"):
            return tuple(e.value for e in node.value.elts)  # type: ignore[attr-defined]
    raise SystemExit(f"{app_py} 里找不到 PLATFORM_FUNCTION_NAMES——闸门会空转")


def read_config(path: Path = CONFIG_PATH) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(path, encoding="utf-8")
    if not cfg.sections():
        raise SystemExit(
            f"{path} 读不到任何段——configparser 对缺失文件是静默的，"
            f"再往下跑会拿空值拼出假结论。先确认路径与 cwd。")
    return cfg


def secret_in_zip_bytes(blob: bytes, secret: str) -> bool:
    """zip 里的 .py 是否含 `secret` 这个字面量。**不打印、不返回密钥本身。**"""
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        src = b"".join(z.read(n) for n in z.namelist()
                       if n.endswith(".py")).decode("utf-8", "ignore")
    except (zipfile.BadZipFile, KeyError):
        return False
    return any(m == secret for m in _SECRET_ASSIGN_RE.findall(src)) or secret in src


# ---------------------------------------------------------------- 真机部分

def _aws_clients(region: str):
    import boto3
    from botocore.config import Config
    cfg = Config(retries={"max_attempts": 12, "mode": "adaptive"})
    return {n: boto3.client(n, region_name=region, config=cfg)
            for n in ("iam", "lambda", "sts", "s3", "ssm", "cloudformation")}


def list_principals(iam) -> list[dict]:
    """非 service-linked 角色 + 全部 IAM 用户，**连它们的 policy 语句一起收**。

    **用户不能漏**：账号 owner 的 IAM 用户同样是一个 principal，只数角色会漏掉它。
    语句是 IAM 写那一类的**发现**输入——那一类不能靠模拟器猜资源（见
    `iam_write_candidates_from_statements`），所以要读真实策略。
    """
    managed: dict[str, object] = {}
    roles: list[dict] = []
    users: list[dict] = []
    for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]):
        roles.extend(page.get("RoleDetailList", []))
        users.extend(page.get("UserDetailList", []))
        for pol in page.get("Policies", []):
            for version in pol.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    managed[pol["Arn"]] = version["Document"]

    def statements_of(detail: dict, inline_key: str) -> list[dict]:
        out: list[dict] = []
        for pol in detail.get(inline_key, []):
            out.extend(policy_statements(pol["PolicyDocument"]))
        for att in detail.get("AttachedManagedPolicies", []):
            doc = managed.get(att["PolicyArn"])
            if doc is not None:
                out.extend(policy_statements(doc))
        return out

    out = []
    for r in roles:
        if r["Path"].startswith("/aws-service-role/"):
            continue
        out.append({"kind": "role", "name": r["RoleName"], "arn": r["Arn"],
                    "statements": statements_of(r, "RolePolicyList")})
    for u in users:
        out.append({"kind": "user", "name": u["UserName"], "arn": u["Arn"],
                    "statements": statements_of(u, "UserPolicyList")})
    return out


def confirm_iam_write(iam, principal_arn: str, candidate: dict, *,
                      account: str) -> set[str]:
    """静态解析出的 IAM 写候选 → 用模拟器对**具体** ARN 确认后的 grant。

    静态解析不评估 Condition ⇒ 会过报，所以每个候选动作都要真问一次。
    问的资源按动作的**资源类型**（role / user / policy）从它自己的目标模式落成
    具体 ARN——拿字面量 `role/*` 去问是首版的缺陷，那样精确授权全部隐形。
    判定三值化在 `iam_write_grants_from_probes` 里。
    """
    probes: list[dict] = []
    for action in sorted(candidate["actions"]):
        kind = iam_write_resource_kind(action)
        patterns = candidate["targets"] or ["*"]
        by_arn = {concrete_target(pat, kind, account=account): pat
                  for pat in patterns}
        if not by_arn:
            continue
        results = iam.simulate_principal_policy(
            PolicySourceArn=principal_arn, ActionNames=[action],
            ResourceArns=sorted(by_arn))["EvaluationResults"]
        decisions = decisions_from_simulation(results)
        missing = missing_context_in(results)
        for arn, pattern in by_arn.items():
            probes.append({"pattern": pattern,
                           "decision": decisions.get(f"{action}|{arn}", "unknown"),
                           "missing_context": missing})
    return iam_write_grants_from_probes(probes)


def site_function_names(lam, platform: tuple[str, ...]) -> tuple[str, ...]:
    names = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            n = fn["FunctionName"]
            if n.startswith("site-") and n not in platform:
                names.append(n)
    return tuple(sorted(names))


def edge_asset_location(clients, function_name: str) -> tuple[str, str]:
    """已部署 Edge 函数的 CDK asset 在哪（bucket, key）。

    **从函数自己的 CloudFormation tag 推栈名、再读已部署模板**——不手抄栈名、
    也不手抄对象 key。手抄 key 的闸门在下一次 Edge 部署后就在测一个旧对象。
    """
    tags = clients["lambda"].get_function(FunctionName=function_name).get("Tags", {})
    stack = tags.get("aws:cloudformation:stack-name")
    if not stack:
        raise SystemExit(f"{function_name} 没有 CloudFormation stack tag——"
                         f"推不出 asset 位置，闸门会漏掉 read-edge-asset 这条路")
    body = clients["cloudformation"].get_template(
        StackName=stack, TemplateStage="Processed")["TemplateBody"]
    if isinstance(body, str):
        body = json.loads(body)
    for res in body.get("Resources", {}).values():
        if res.get("Type") != "AWS::Lambda::Function":
            continue
        if res.get("Properties", {}).get("FunctionName") != function_name:
            continue
        code = res["Properties"].get("Code", {})
        if "S3Bucket" in code and "S3Key" in code:
            return code["S3Bucket"], code["S3Key"]
    raise SystemExit(f"{stack} 的模板里找不到 {function_name} 的 S3 asset——"
                     f"它可能改成了内联代码，这条路要重新判定")


def assets_carrying_key(clients, bucket: str, live_key: str,
                        max_size: int = 200 * 1024) -> list[str]:
    """bootstrap 桶里**全部**仍带着当前有效密钥的对象键。

    返回的是键的列表而**不是计数**：只探"当前 CloudFormation 模板指向的那一个"
    时，「只能读旧对象」的 principal 完全不可见（Codex 复审 P1-2）。
    每次 Edge 部署留一个新对象、旧对象不删 ⇒ 这个集合只会涨。

    **连历史版本一起扫**：桶开着版本控制（noncurrent 保留 30 天），
    对象被删之后旧版本仍可按 version ID 读到，而 `s3:GetObjectVersion`
    是另一个动作（已进 `A_READ_OBJECT`）。IAM 里两者的资源 ARN 相同，
    所以这里只需要键去重。
    """
    keys: set[str] = set()
    paginator = clients["s3"].get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Versions", []):
            key = obj["Key"]
            if key in keys or not key.endswith(".zip") or obj["Size"] > max_size:
                continue
            blob = clients["s3"].get_object(
                Bucket=bucket, Key=key, VersionId=obj["VersionId"])["Body"].read()
            if secret_in_zip_bytes(blob, live_key):
                keys.add(key)
    return sorted(keys)


def function_versions(lam, names) -> dict[str, tuple[str, ...]]:
    """`{函数名: (已发布版本号…)}`（不含 `$LATEST`）。

    AWS 支持把 permission 限定到具体 version，且实测 Edge 的 version 9 上确实
    存在版本级 resource policy ⇒ 不枚举版本就有一整条授权通道看不见。
    """
    out = {}
    for name in names:
        versions = []
        for page in lam.get_paginator("list_versions_by_function").paginate(
                FunctionName=name):
            versions.extend(v["Version"] for v in page["Versions"]
                            if v["Version"] != "$LATEST")
        if versions:
            out[name] = tuple(sorted(versions, key=lambda v: int(v)))
    return out


def edge_code_arns_carrying_key(clients, function_name: str, fn_arn: str,
                                versions: tuple[str, ...], live_key: str) -> tuple[str, ...]:
    """Edge 函数**及其每个仍含活密钥的已发布版本**的 ARN。

    与 asset 那条同理：密钥没轮转过，所以历史版本的代码里也是这把密钥，
    只探未限定 ARN 会漏掉「只能读某个旧版本」的 principal。逐个实测，
    某个版本不再含活密钥时它自己就掉出集合。
    """
    import urllib.request
    out = []
    for qualifier in (None, *versions):
        kw = {"FunctionName": function_name}
        if qualifier:
            kw["Qualifier"] = qualifier
        try:
            url = clients["lambda"].get_function(**kw)["Code"]["Location"]
        except clients["lambda"].exceptions.ResourceNotFoundException:
            continue
        with urllib.request.urlopen(url) as fh:      # noqa: S310 (AWS 预签名 URL)
            if secret_in_zip_bytes(fh.read(), live_key):
                out.append(fn_arn if qualifier is None else f"{fn_arn}:{qualifier}")
    return tuple(out)


def function_aliases(lam, names) -> dict[str, tuple[str, ...]]:
    """`{函数名: (alias 名…)}`。M7 之后站点函数都有 `blue`/`green`。"""
    out = {}
    for name in names:
        aliases = []
        for page in lam.get_paginator("list_aliases").paginate(FunctionName=name):
            aliases.extend(a["Name"] for a in page["Aliases"])
        if aliases:
            out[name] = tuple(sorted(aliases))
    return out


def function_policy_statements(lam, name: str,
                              qualifiers: tuple[str, ...]) -> list[tuple[str | None, dict]]:
    """未限定函数 + 每个 alias 的 resource policy 语句。

    **不能只读未限定的那份**：M7 之后站点的 Function URL 与它的授权语句都挂在
    alias 上，只读未限定会把整条 invoke 授权面看漏（实测：M7 之后新建的站点
    未限定 policy 根本不存在）。**版本也要读**——实测 Edge 的 version 9 上有一条
    版本级语句（`replicator.lambda.GetFunction`）。
    """
    out: list[tuple[str | None, dict]] = []
    for qualifier in (None, *qualifiers):
        kw = {"FunctionName": name}
        if qualifier:
            kw["Qualifier"] = qualifier
        try:
            doc = json.loads(lam.get_policy(**kw)["Policy"])
        except lam.exceptions.ResourceNotFoundException:
            continue
        out.extend((qualifier, s) for s in doc.get("Statement", []))
    return out


def simulate(iam, principal_arn: str, t: Targets) -> tuple[dict[str, str], bool]:
    """两次调用：函数类资源一组、其余一组。

    分组不是为了省钱，是为了不产生大量无意义的 (动作, 资源) 组合——一次调用的
    响应体是 资源数 × 动作数，而 `ssm:*` 对 Lambda ARN、`lambda:*` 对 S3 ARN
    都是纯噪音。
    """
    out: dict[str, str] = {}
    missing = False
    for actions, resources in ((ACTIONS_FUNCTION, t.function_resources()),
                               (ACTIONS_OTHER, t.other_resources())):
        if not resources:
            continue
        for page in iam.get_paginator("simulate_principal_policy").paginate(
                PolicySourceArn=principal_arn, ActionNames=list(actions),
                ResourceArns=resources):
            out.update(decisions_from_simulation(page["EvaluationResults"]))
            missing = missing or missing_context_in(page["EvaluationResults"])
    return out, missing


def measure(region: str, *, workers: int = 4, scan_assets: bool = True) -> dict:
    clients = _aws_clients(region)
    iam, lam = clients["iam"], clients["lambda"]
    cfg = read_config()
    account = clients["sts"].get_caller_identity()["Account"]

    edge_role_arn = cfg.get("Deployer", "edge_role_arn").split("#")[0].strip()
    cfg_account = edge_role_arn.split(":")[4]
    if cfg_account != account:
        raise SystemExit(
            f"账号不匹配：当前凭证在 {account}，而 config.ini 的 edge_role_arn 属于 "
            f"{cfg_account}。闸门会对着另一个账号出结论——先切凭证或改 config。")
    edge_role_name = edge_role_arn.rsplit("/", 1)[-1]

    # 平台函数 = deployer 栈的清单（AST 取，不手抄）+ router 栈的两个 Edge 函数。
    platform = platform_function_names() + EDGE_FUNCTIONS
    sites = site_function_names(lam, platform)
    all_functions = list(platform) + list(sites)

    def fn_arn(n: str) -> str:
        return f"arn:aws:lambda:{region}:{account}:function:{n}"

    live_key = clients["ssm"].get_parameter(
        Name=JWT_PARAM_NAME, WithDecryption=True)["Parameter"]["Value"]
    facts: dict[str, object] = {}

    aliases = function_aliases(lam, all_functions)
    versions = function_versions(lam, all_functions)

    # ---- 密钥的物化位置：**实测**，不假设 ----
    edge_versions = versions.get(EDGE_ORIGIN_REQUEST_FN, ())
    edge_code = edge_code_arns_carrying_key(
        clients, EDGE_ORIGIN_REQUEST_FN, fn_arn(EDGE_ORIGIN_REQUEST_FN),
        edge_versions, live_key)
    facts["edge_code_targets_carrying_live_key"] = len(edge_code)

    asset_bucket, asset_key = edge_asset_location(clients, EDGE_ORIGIN_REQUEST_FN)
    if scan_assets:
        asset_keys = assets_carrying_key(clients, asset_bucket, live_key)
    else:
        blob = clients["s3"].get_object(Bucket=asset_bucket, Key=asset_key)["Body"].read()
        asset_keys = [asset_key] if secret_in_zip_bytes(blob, live_key) else []
        print("（--no-asset-scan：只看当前 asset，历史对象未扫）", file=sys.stderr)
    if asset_key not in asset_keys and scan_assets:
        # 当前部署的 asset 不含活密钥 = 根治已生效（或密钥刚轮转）。这是好消息，
        # 但要说出来——它会让 read-edge-asset 的资源集合变小。
        print("注意：当前部署的 asset 已不含活密钥", file=sys.stderr)
    facts["edge_assets_carrying_live_key"] = len(asset_keys)

    targets = Targets(
        platform_functions=tuple(fn_arn(n) for n in platform),
        site_functions=tuple(fn_arn(n) for n in sites),
        edge_code_arns=edge_code,
        edge_assets=tuple(f"arn:aws:s3:::{asset_bucket}/{k}" for k in asset_keys),
        jwt_parameter=f"arn:aws:ssm:{region}:{account}:parameter{JWT_PARAM_NAME}",
        alias_arns={fn_arn(n): tuple(f"{fn_arn(n)}:{a}" for a in al)
                    for n, al in aliases.items()},
        version_arns={fn_arn(n): tuple(f"{fn_arn(n)}:{v}" for v in vs)
                      for n, vs in versions.items()},
    )

    # ---- resource policy 快照（SimulatePrincipalPolicy 不覆盖这条通道）----
    policies = {name: function_policy_statements(
                    lam, name, aliases.get(name, ()) + versions.get(name, ()))
                for name in all_functions}
    rp = resource_policy_snapshot(policies, account=account, platform=platform,
                                 sites=sites, aliases=aliases)

    principals = list_principals(iam)
    print(f"账号 {account} / 区 {region}：平台函数 {len(platform)}、站点函数 "
          f"{len(sites)}、待模拟 principal {len(principals)}；"
          f"探测资源 {len(targets.function_resources()) + len(targets.other_resources())} 个"
          f"（含 alias {sum(len(v) for v in targets.alias_arns.values())}、"
          f"版本 {sum(len(v) for v in targets.version_arns.values())}）；"
          f"含活密钥的 Edge 代码目标 {len(edge_code)} 个、asset {len(asset_keys)} 个",
          file=sys.stderr)

    observed: dict[str, dict] = {}
    failures: list[str] = []
    n_missing = 0
    iam_candidates: list[str] = []
    iam_confirmed: list[str] = []
    iam_gated: list[str] = []

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(simulate, iam, p["arn"], targets): p for p in principals}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            p = futs[fut]
            try:
                decisions, missing = fut.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{p['name']}: {type(exc).__name__}: {exc}")
                continue
            n_missing += bool(missing)
            grants = grants_from_decisions(decisions, targets)
            candidate = iam_write_candidates_from_statements(p["statements"])
            if candidate["actions"]:
                iam_candidates.append(p["name"])
                confirmed = confirm_iam_write(iam, p["arn"], candidate,
                                              account=account)
                grants |= confirmed
                if any(g.endswith(":any") or g.endswith(":scoped")
                       for g in confirmed):
                    iam_confirmed.append(p["name"])
                elif confirmed:
                    iam_gated.append(p["name"])
            if grants:
                observed[principal_fingerprint(p["arn"])] = {
                    "name": p["name"], "arn": p["arn"], "kind": p["kind"],
                    "grants": sorted(grants)}
            if i % 100 == 0:
                print(f"  已模拟 {i}/{len(principals)}", file=sys.stderr)

    if failures:
        # 静默丢一个 principal 就等于"没看见"，而没看见与"不具备权限"在输出上
        # 一模一样。这里必须硬失败。
        raise SystemExit(f"{len(failures)} 个 principal 模拟失败，结果不完整："
                         f"{failures[:3]}")

    facts["principals_with_missing_context"] = n_missing
    # 两个数都记：候选是静态解析（不评估 Condition，会过报），确认是模拟器的答案。
    # 差值变大说明账号里带 Condition 的 IAM 授权变多了，值得看一眼。
    facts["iam_write_candidates"] = len(iam_candidates)
    facts["iam_write_confirmed"] = len(iam_confirmed)
    facts["iam_write_condition_gated"] = len(iam_gated)
    return {"principals": observed, "resource_policies": rp, "facts": facts,
            "required": {"edge": edge_role_name, "deployer": DEPLOYER_EXEC_ROLE}}


def write_baseline(bundle: dict, baseline: dict, path: Path) -> None:
    old = baseline.get("principals", {})
    principals = {}
    # **指纹从 ARN 重算，不沿用 bundle 的键**：`--from-dump` 读的快照可能是旧格式
    # 生成的（指纹编码改过一次），沿用键就会把整份基线写成旧形态而单测才发现。
    for p in sorted(bundle["principals"].values(), key=lambda x: x["arn"]):
        fp = principal_fingerprint(p["arn"])
        principals[fp] = {
            # `--classify` 传进来的标注优先；否则沿用基线里已有的；都没有才 unclassified。
            "category": p.get("category")
            or old.get(fp, {}).get("category", "unclassified"),
            "grants": p["grants"],
        }
    path.write_text(json.dumps(
        {"schema": BASELINE_SCHEMA,
         "note": ("account trust boundary baseline —— 只存 ARN 与策略语句的指纹"
                  "（仓库红线：真实账号值/角色名不进被跟踪文件）。见 "
                  "docs/security/account-trust-boundary.md 与 "
                  "scripts/verify_account_trust_boundary.py。"),
         # platform-overbroad：平台自己的角色，但这条授权它并不需要
         # （当前唯一一个：跑不可信站点依赖安装的 CodeBuild 角色，CDK 自动给了它
         #  整个 bootstrap 桶的读权限 ⇒ 它能读到 Edge asset 里的明文密钥）。
         "categories": ["platform", "platform-overbroad", "admin", "break-glass",
                        "cdk-admin", "cdk-readonly", "unrelated-workload",
                        "unclassified"],
         "facts": bundle["facts"],
         "principals": principals,
         # 站点函数只落**规范形态 + legacy 豁免名单**，不落逐站点条目：
         # 逐站点会让每次建站/下线都改基线，而"新增即红"依赖基线是稳定的。
         "resource_policies": {
             "platform": bundle["resource_policies"]["platform"],
             **site_shape_canonicals(bundle["resource_policies"]["sites"]),
         }},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--update-baseline", action="store_true",
                    help="把当前实测写回基线（category 保留已有标注，新条目为 "
                         "unclassified，需人工标注）")
    ap.add_argument("--dump-observed", metavar="PATH",
                    help="把带**真实名字**的实测清单写到 PATH（分类基线时要看名字）。"
                         "产物含账号内标识，**不要提交进仓库**——写到 /tmp。")
    ap.add_argument("--from-dump", metavar="PATH",
                    help="不发 AWS 调用，直接读 --dump-observed 的产物。"
                         "用于分类/复核，省掉重跑模拟。"
                         "**注意它是快照**：拿旧快照当闸门结果会得出过期结论。")
    ap.add_argument("--classify", metavar="PATH",
                    help="从 PATH 读 {角色名: category} 映射，据此标注基线的 "
                         "category（配合 --update-baseline）。映射文件同样"
                         "含真实名字，**不要提交**。")
    ap.add_argument("--no-asset-scan", action="store_true",
                    help="跳过「bootstrap 桶里有多少 asset 带活密钥」那一遍扫描"
                         "（默认做；它要读几十个小对象）")
    args = ap.parse_args()

    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) \
        if BASELINE_PATH.exists() else {"schema": BASELINE_SCHEMA, "principals": {}}

    if args.from_dump:
        bundle = json.loads(Path(args.from_dump).read_text(encoding="utf-8"))
        print(f"（--from-dump：读的是快照 {args.from_dump}，未发 AWS 调用）",
              file=sys.stderr)
    else:
        bundle = measure(args.region, workers=args.workers,
                        scan_assets=not args.no_asset_scan)

    observed = bundle["principals"]
    print(f"\n具备至少一项敏感授权的 principal：{len(observed)}")
    for _fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        print(f"  [{p['kind'][0]}] {p['name']:62} {sorted(p['grants'])}")
    print(f"\n事实：{json.dumps(bundle['facts'], ensure_ascii=False)}")

    if args.dump_observed:
        Path(args.dump_observed).write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n实测清单（含真实名字，勿提交）已写入 {args.dump_observed}")

    if args.update_baseline:
        classify = json.loads(Path(args.classify).read_text(encoding="utf-8")) \
            if args.classify else {}
        if classify:
            for p in observed.values():
                if p["name"] in classify:
                    p["category"] = classify[p["name"]]
        write_baseline(bundle, baseline, BASELINE_PATH)
        print(f"\n已写入 {BASELINE_PATH}（新条目 category=unclassified，请人工标注）")
        return 0

    rep = compare_to_baseline(observed, baseline, required=bundle["required"],
                              resource_policies=bundle["resource_policies"],
                              facts=bundle["facts"])
    print("\n" + rep.render())
    # 处置文案由 RED_FIELDS 的第三列驱动（`dict.fromkeys` 去重且保序）：
    # 原先这里手抄了一遍字段名单，加红字段时最容易漏的就是这一处。
    for key in dict.fromkeys(k for name, _, k in RED_FIELDS if getattr(rep, name)):
        print("\n" + RED_MESSAGES[key])
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
