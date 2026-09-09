#!/usr/bin/env python3
"""账号信任边界的漂移闸门（M09 第 2 步的可执行部分）。

**它不是 M09 的修复，也不假装是。** M09 那条缺陷——同账号持有
`lambda:InvokeFunction` 的 principal 可以直接 invoke panel 与站点 Lambda、
在合成 event 里伪造 `x-user-email`——在**本账号里关不掉**：

- SCP 对 Organizations 管理账号无效，而本部署就在管理账号（`policies/README.md` 边界①）；
- Lambda 的 resource policy 没有写 Deny 的 API（`AddPermission` 只能写 Allow）；
- 应用层给 Edge 加签名也不成立：Edge 得能验签，而验签要用的东西按定义是公开的。

**只收窄 `lambda:InvokeFunction` 是假修复**：同一批 principal 还握着
`lambda:UpdateFunctionCode` 与 `iam:PutRolePolicy`，边界一寸也没有移动。
更要紧的是——**冒充任意用户根本不需要 invoke**。3c-final 之后私钥不出 KMS，
但能 `kms:Sign`（或先 `kms:PutKeyPolicy` / `kms:CreateGrant` 给自己授权再签）的
principal 照样能签出任意 email 的会话 cookie 与 `scope=console` 的
`__Host-sb_console`。完整风险模型与实测证据见 `docs/security/account-trust-boundary.md`。

在那之前，本脚本承担唯一还能自动化的职责：**这个集合别再长**。

## 形状：一种能力 = 一个动作等价类 × 一个资源等价类

这句话是本文件最重要的不变量，因为把它压成"单个动作 / 单个资源"这个错误
**已经犯过三次**，每次都产生一个当时看不出来的 false-green：

| 压成什么 | 漏掉了谁 |
|---|---|
| 只探未限定函数 ARN | 挂在 `blue` alias 上的授权（M7 之后站点的 Function URL 全在 alias 上） |
| 只探当前那一个 CDK asset | （HS 时代）带同一把活密钥的那批历史 asset 对象 |
| 只探 `ssm:GetParameter` | 一个**只**被授予 `ssm:GetParameters`（复数）的角色 |
| IAM 写只对着字面量 `role/*` 模拟 | 6 个精确/窄授权的 principal（IAM 里请求资源是具体 ARN，policy 的 `role/ExactRole` 不匹配字面量 `role/*`；而 `CreatePolicyVersion` 的资源类型根本是 **policy**） |

所以动作与资源都以**类**为单位（见 `A_*` 常量与 `Targets`）。往任一类里加成员时，
同时加一条**只命中该新成员**的用例。

## 它测什么（A 两组观测 + B 一层快照；C 不在本闸门）

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

② **IAM 策略变更**——**纯静态文本快照，不做权限分析，不进模拟器**（层 B）。
   收 role / user / **group** 的 inline + attached 托管 + **permissions boundary**，
   用**全 glob**（`fnmatch`）判语句是否与 IAM 策略变更动作相关，**Allow 与 Deny 都收**，
   逐条归一化（丢 `Sid`、**当前**账号 ID → `<acct>`、递归排序）后只存指纹。
   **任何 added / removed / changed 都红，不判改善。**

   **为什么"消失"也红**：Allow 消失不等于收紧——语句可能被拆成两条更宽的、可能从
   inline 挪到另一份 policy，也可能是**解析器漏收了**；把"旧指纹消失"自动判成改善，
   正好会把解析器退化显示成好消息。而 **Deny 消失是实实在在的扩权**
   （`Allow iam:* on *` + `Deny PutRolePolicy on EdgeRole`，删掉 Deny 则 Allow 集合
   完全没变 ⇒ 只收 Allow 的设计全绿）。

   托管策略文档/版本解析不到时**硬失败**，不静默跳过：跳过整份 policy 的输出与
   "这份策略没有相关语句"一模一样。`managed_policy_versions` 只记**贡献了相关语句**
   的那几份（账号里实测有 300 份托管策略，全记会让 AWS 每更新任意一份都红一次）。

   **原先那套两步（静态发现候选 → 模拟器对具体 ARN 确认 → 三值分类）已删除。**
   它要求闸门回答"谁能提权"，而那等于要造一个 IAM 权限分析器：statement 归因、
   Condition 语义、NotResource 集合代数、policy variable、`SourcePolicyType` 碰撞
   ——每修一维下一维才暴露，这是这道闸门被前五轮复审反复点名的根因。所以 B 的承诺刻意收窄成
   **"可能影响这些动作的语句集合没有变化"**，仅此而已。

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

④ **KMS 层**（3c-final）。会话私钥不出 KMS，所以"密钥的明文副本在哪"这个问题没有了；
   取而代之的是**每把会话签名 CMK 自己的快照**：key policy 指纹、`ListGrants` 每条
   grant 的指纹、`KeySpec` / `KeyUsage`、以及公钥的 `spki_sha256`。任一字段变化都红
   （默认 key policy 是 root 委派，能改它的人本来就在冒充面里，但**变了**就要有人看）；
   key 集合的增减必须用 `--new-key` / `--retire-key` 声明。
   公钥指纹与 `config.ini` 的 `[SessionKeys]` 不一致时**硬失败**：那说明 config 指的
   不是这把 key，闸门对着别的东西出结论没有意义。

⑤ **Edge 产物的三条硬断言**（不落 facts、连 `--update-baseline` 一起挡）：
   CloudFront **当前关联**的那个 origin-request 版本必须带**每一把** site kid 的公钥
   （缺 = 线上全员 302，部署的不是这份 config）；**不得**出现任何 console kid 的公钥
   （spec §4.1）；**不得**出现 login-flow secret 的值（spec §11.3）。

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

**A（直接失守）**

- `SimulatePrincipalPolicy` 对带 Condition 的策略需要调用方补 `ContextEntries`；
  本脚本**只补 KMS 签名合同那两个键**（`kms:SigningAlgorithm` / `kms:MessageType`，
  值由 spec §11.5 固定；不补的话平台自己那条必需的 `kms:Sign` 会判成"缺上下文"、
  正向控制假红），其余一概不补，于是那些判定是**下界**。逐项的不确定面记在 `coverage.undecided_items`
  （成员级：同一个 principal 多出一项判不出的目标也会红；顶层的 `MissingContextValues`
  保守地归给该动作下每个非 allowed 的资源）。`principals_with_missing_context`
  那个笼统计数只报 delta、不参与红绿。
- 动作等价类不是穷尽的。
- 它看 IAM、Lambda resource policy、bootstrap 桶的 bucket policy、以及会话签名 CMK
  的 key policy 与 grants；**不看** VPC endpoint policy、其它服务的 resource policy，
  **也不看 S3 access point**。KMS 那一层只做**快照比对**（任一字段变化即红），
  不做权限分析——"这条 grant 是否真的让某人能签"要的是 KMS 授权语义分析器，
  与 B 层刻意不造 IAM 分析器同一条理由。
- 它不看跨账号 principal（但语句里出现**外部账号**的 principal 会改变指纹 ⇒ 会红）。
- 它看不见"临时建了一个角色用完就删"。

**B（IAM 写观察）**

- **不判断某条语句是否生效**（Condition 没求值，boundary 与 SCP 没参与评估）。
- **不判断是否构成提权链**——那要看目标策略挂在谁身上、能否 AssumeRole/PassRole、
  boundary 拦不拦。B 的语义就是字面意思：**存在一条可能影响 IAM 策略变更动作的语句**。
- **不判断变化方向**是收紧还是放宽。刻意的：判方向需要的正是上面那套分析器。

**C（站点 route/alias 可达性）——不由本闸门保证**，归部署验收
（见 merged review §9）；含 **idle 颜色被整个删除检测不到**。

用法（**用系统 python3 跑**，deployer/.venv 的 CA 信任库是空的）：

    python3 site-builder/scripts/verify_account_trust_boundary.py
    python3 site-builder/scripts/verify_account_trust_boundary.py --update-baseline
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import configparser
import fnmatch
import hashlib
import io
import json
import os
import re
import sys
import threading
import urllib.parse
import warnings
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SITE_BUILDER = _HERE.parent
BASELINE_PATH = _HERE / "account_trust_baseline.json"
CONFIG_PATH = _SITE_BUILDER / "config.ini"
APP_PY = _SITE_BUILDER / "deployer" / "infra" / "app.py"

# 6 = 3c-final：HS 层（SSM 参数 / Edge 产物里的明文密钥）整层换成 KMS 层。
# **没有 3/4/5 → 6 的迁移通道**：旧形态里根本没有 KMS 分节可比，硬失败并让操作者删掉重生成
# （基线含单账号实测、不随资产分发，采用者首跑就是 `--update-baseline`）。
BASELINE_SCHEMA = 6
DEPLOYER_EXEC_ROLE = "site-deployer-exec-role"
AUTH_SERVICE_ROLE = "site-auth-service-role"      # deploy_auth.py 建的执行角色名
PANEL_DEPLOY_PY = _SITE_BUILDER / "panel" / "deploy_panel.py"
SESSION_KMS_PY = _SITE_BUILDER / "auth" / "session_kms.py"
# [SessionKeys] 的唯一定义在 auth/session_keys.py；闸门按它枚举两个 family 的 RS 行
# （kid / key ARN / spki_sha256）。它只 import 标准库 ⇒ 模块级 import 是安全的。
# **`session_kms` 刻意只在 `measure()` 里 import**：它 `import session`，那条链要 `cryptography`，
# 而闸门跑在不带路径的 python3 上（CLAUDE.md「仓库外的几样东西」第 3 步只给它装了 boto3 与
# pip-system-certs）。放在模块级会让 `--from-dump`、`--help`、标签校验与全部单测都跟着要那个包。
sys.path.insert(0, str(_SITE_BUILDER / "auth"))
from session_keys import FAMILIES as KEY_FAMILIES, key_refs, load_session_keys  # noqa: E402
if str(_HERE) not in sys.path:          # 测试用 spec_from_file_location 加载本文件时，本目录不在 sys.path
    sys.path.insert(0, str(_HERE))
from _secure_write import write_private_text  # noqa: E402


def _module_constant(path: Path, name: str) -> str:
    """按 AST 取某个模块级字符串常量。

    **不 import**：那些模块顶层会 import boto3 / cryptography，而闸门跑在不带路径的 python3 上
    （见上面的注释）。**也不手抄**：手抄的副本在对面改值时不会红，闸门会静静地测错东西
    （`kms:Sign` 的 Condition 值对不上 ⇒ 平台自己的必需 grant 消失 ⇒ 正向控制假红）。
    """
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == name
                and isinstance(node.value, ast.Constant)):
            return node.value.value
    raise SystemExit(f"{path} 里找不到模块级常量 {name}——它被改名或改成计算出来的了？"
                     f"闸门靠它与对面保持同一份合同，拿不到就不能往下跑。")

# Edge 函数名：router 栈的两个 Lambda@Edge 里，**origin-request 那个**才内联着 site family 的
# 公钥 allowlist（`stack.py` 把 `{{SITE_ALLOWLIST_JSON}}` 替换进它）。origin-response 不验签。
EDGE_ORIGIN_REQUEST_FN = "ApplicationWebRouterStack-application-web-router"
EDGE_ORIGIN_RESPONSE_FN = "ApplicationWebRouterStack-origin-response"
# **这两个必须手写**：它们属于 router 栈，而 `PLATFORM_FUNCTION_NAMES` 是
# deployer 栈 `infra/app.py` 里的清单，结构上不可能含它们。漏掉的后果实测过一次
# ——Edge 的已发布版本一个都没被枚举，于是「谁能 UpdateFunctionCode 换掉 Edge」
# （3c-final 之后这仍是一条冒充路：换掉 verifier 就等于自己定义谁是谁）完全在视野外。
EDGE_FUNCTIONS = (EDGE_ORIGIN_REQUEST_FN, EDGE_ORIGIN_RESPONSE_FN)

# ---- grant 词表 ----------------------------------------------------------
# grant 是 `种类[:资源]` 形态的字符串，进基线文件。改词表等于基线全量漂移。
G_INVOKE_PLATFORM = "invoke-platform"      # + ":<函数名>"
G_INVOKE_SITE = "invoke-site"              # + ":all" / ":some(k)"
G_REPLACE_CODE = "replace-platform-code"   # + ":<函数名>"
# 能签会话的两条路**必须分开记**（spec §1 的 `sign:kms-direct` / `sign:kms-self-authorize`）：
#  · kms-sign:<kid>            —— identity policy 上就有 `kms:Sign` on 这把 CMK。key policy 是
#    默认的 root 委派（ADR 0001），所以 identity 那一侧允许就是真的能签。
#  · kms-self-authorize:<kid>  —— `kms:PutKeyPolicy` 或 `kms:CreateGrant`：现在不能签，
#    但能先给自己授权再签。严重度与修法都与上一条不同（前者是收权限，后者是改 key 的治理），
#    合成一条就看不出"今天能签的人"与"随时能让自己能签的人"是两批。
G_KMS_SIGN = "kms-sign"                      # + ":<kid>"
G_KMS_SELF_AUTHORIZE = "kms-self-authorize"  # + ":<kid>"
# `kms:GetPublicKey` **刻意不是 grant**：公钥按定义是公开的（Edge 产物里就内联着它），
# 读到它签不出任何东西。把它记成 grant 会让冒充面的数字凭空变大。
# 3c-1B：登录流程的 HMAC 密钥（auth 私有，签 OAuth state 与 __Host-sb_pkce cookie）。
# **刻意不算冒充面、is_secret_grant() 对它返回 False**：读到它只能伪造一次登录 CSRF
# （state 与 cookie 都只活 300 秒），**签不出任何会话**——把它算进冒充面会让那个数字凭空
# 变大，而"冒充面"这个词在 docs/security/account-trust-boundary.md 里有精确含义（能以任意
# 用户身份访问任意站点与控制台写接口）。分类错的代价是双向的：算进去会稀释真正的靶子，
# 漏掉一条真能签会话的路才是漏报。
G_READ_LOGIN_FLOW = "read-login-flow-secret"


def is_secret_grant(grant: str) -> bool:
    """能产生一个 verifier 会接受的签名的 grant（3c-final：只有 KMS 两类）。

    读 SSM / 读 Edge 产物 / 读 bootstrap asset **都不再算**：那里只剩公钥与 login-flow。
    `read-login-flow-secret` 同样不在其中，理由见 G_READ_LOGIN_FLOW 的注释。
    """
    return (grant.startswith(G_KMS_SIGN + ":")
            or grant.startswith(G_KMS_SELF_AUTHORIZE + ":"))


# ---- 迁移声明的标签 ----------------------------------------------------------
# `--new-key LABEL` / `--retire-key LABEL` 的 LABEL ∈ 已配置 kid ∪ {login-flow}。
# `legacy` 这个标签随 HS 层一起消失了（3c-final 没有 legacy 入口）。
LABEL_LOGIN_FLOW = "login-flow"
NON_KID_LABELS = (LABEL_LOGIN_FLOW,)


def grants_for_labels(labels) -> set:
    """LABEL 集合 → 它们对应的 grant 字符串集合。

    一个 kid 映到**两条** grant（`kms-sign:` 与 `kms-self-authorize:`）：新建/退役一把 CMK
    时，同一批"能对 `key/*` 做这些动作"的 principal 两条 grant 会同时增减，只声明一条会让
    另一条照红，而那不是本次迁移之外的任何信息。
    """
    out: set = set()
    for label in labels:
        if label == LABEL_LOGIN_FLOW:
            out.add(G_READ_LOGIN_FLOW)
        else:
            out |= {f"{G_KMS_SIGN}:{label}", f"{G_KMS_SELF_AUTHORIZE}:{label}"}
    return out


def classes_for_labels(labels, t: "Targets | None" = None) -> frozenset:
    """被声明的 key label → 它们在 coverage 里对应的**资源类**名（3c-1B-G A6）。

    与 `grants_for_labels` 对偶：那个管 grant delta，这个管 coverage 指纹。
    资源类名必须与 `undecided_resource_class` 完全一致，否则反事实算出来的集合对不上
    （对不上的后果是"声明了却仍然红"，与修之前一样，所以下面有一条用例钉住这个对应关系）。
    """
    out = set()
    for label in labels:
        out.add("login-flow-param" if label == LABEL_LOGIN_FLOW else f"kms-key:{label}")
    del t          # 目前不需要实例；留参数是为了将来按 targets 推导
    return frozenset(out)


def configured_kids(session_keys) -> list:
    """config 里声明过的全部 kid。family 清单取 `session_keys.FAMILIES`，**不手抄**——
    手抄的第三份副本在加 family 时会让一个合法 kid 被判成"未知标签"并硬退出。"""
    return [r.kid for fam in KEY_FAMILIES for r in session_keys.allowlist(fam)]


def baseline_kids(baseline: dict) -> list:
    """**基线**里记过的 kid（`kms` 分节的键）。

    `--retire-key <kid>` 必须认这一处，否则退役那一步无法执行：退役的动作正是"把 kid 从
    config 里删掉再重部"，而 grant 的丢失只有重部之后才出现 ⇒ 到能声明的时刻，
    `configured_kids()` 已经不含它了（DEPLOY.md 轮转 runbook 的最后一步）。基线是那把 key
    "曾经存在过"的唯一记录，且它同样不能随手编，所以拿它当第二个来源不会放松"标签打错一个
    字就硬失败"这条守卫——`site-rs-v9` 两处都不在，照样退出。
    """
    return sorted(baseline.get("kms") or {})


def check_migration_labels(labels, *, known_kids) -> None:
    """LABEL 必须是 `known_kids` 里的 kid 或非 kid 标签之一，否则**硬失败**。

    `known_kids` = config 里配置着的 kid **∪** 基线里记过的 kid（`baseline_kids`）。后半个
    并集是退役那一步必需的，理由见 `baseline_kids` 的 docstring。

    不校验的后果很隐蔽：`--retire-key site-rs-v9`（打错一个字）会被静默接受，
    生成一条永不匹配的 grant，于是操作者以为已经声明、闸门照样红，或者更糟——
    以为声明生效而实际红的是别的东西。
    """
    unknown = [x for x in labels if x not in set(known_kids) | set(NON_KID_LABELS)]
    if unknown:
        raise SystemExit(
            f"--new-key/--retire-key 的标签 {unknown} 不是已配置的 kid（config ∪ 基线两处都没有），"
            f"也不是 {list(NON_KID_LABELS)}。可用 kid：{sorted(set(known_kids))}")


# ---- 动作等价类 ----------------------------------------------------------
# **一种能力 = 一个动作等价类 × 一个资源等价类。** 这个形状是本文件最重要的
# 不变量，因为把它压成"单个动作/单个资源"这个错误已经犯过三次：
#   · 首版只探未限定函数 ARN ⇒ 挂在 blue alias 上的授权全看不见（M7 之后站点
#     的 Function URL 都在 alias 上）；
#   · 首版只探当前那一个 CDK asset ⇒（HS 时代）带同一把活密钥的那批历史对象看不见；
#   · 首版只探 `ssm:GetParameter` ⇒ 一个**只**被授予 `ssm:GetParameters`
#     （复数）的角色被整个漏掉（2026-08-25 实测，它没有 boundary，
#     `WithDecryption=true` 即可读出当前值）。
# 往任一类里加动作/资源时，同时加一条只命中该新成员的用例。
A_INVOKE = ("lambda:InvokeFunction",)
A_REPLACE = ("lambda:UpdateFunctionCode",)
# 四个动作都能读出同一个 SecureString 的明文；AWS 明确警告
# `GetParameterHistory` 在拒绝 `GetParameter` 时仍可能读到当前值。
# 3c-final 起 SSM 里只剩 login-flow secret 这一个目标（会话密钥全在 KMS）。
A_READ_PARAM = ("ssm:GetParameter", "ssm:GetParameters",
                "ssm:GetParametersByPath", "ssm:GetParameterHistory")
# 3c-final：签名能力（spec §1 的 sign:kms-direct / sign:kms-self-authorize）。key policy 是
# 默认的 root 委派（ADR 0001），所以 identity policy 上的 `kms:Sign` 就是能签；
# `PutKeyPolicy` / `CreateGrant` 是"先给自己授权再签"。
# **`kms:GetPublicKey` 刻意不在任何类里**：公钥是公开的，读到它签不出东西。
A_KMS_SIGN = ("kms:Sign",)
A_KMS_SELF_AUTHORIZE = ("kms:PutKeyPolicy", "kms:CreateGrant")
# 模拟 `kms:Sign` 时喂给 Condition 的上下文：auth / panel 的语句带 SigningAlgorithm 与
# MessageType 两个 StringEquals（deploy_auth / deploy_panel 把 spec §11.5 的合同钉进 IAM）。
# 不给上下文时模拟器判"缺上下文"⇒ 平台角色的必需 grant 会从结果里消失、正向控制假红。
KMS_SIGNING_ALGORITHM = _module_constant(SESSION_KMS_PY, "SIGNING_ALGORITHM")
KMS_MESSAGE_TYPE = _module_constant(SESSION_KMS_PY, "MESSAGE_TYPE")
# **`kms:MessageType` 的两个取值都要模拟。** 只喂合同值（今天是 RAW）时，一条
# `StringEquals kms:MessageType: DIGEST` 的 `kms:Sign` 语句会评估成 implicitDeny
# ——不是"缺上下文"（上下文喂了，只是值不匹配）⇒ `missing_context_in` 那条路也看不见，
# 持有者被干干净净地报成"不能签"。而 `RSASSA_PKCS1_V1_5_SHA_256` 下这两条路**产出
# 同一个签名**：DIGEST 只是让 KMS 跳过哈希这一步，调用方在本地对 `header.payload`
# 做 SHA-256 再签那 32 字节摘要，得到的字节与 RAW 路逐字节相同 ⇒ 三个 verifier 全接受。
# 「任一取值下能签」就是能签，所以两腿的判定取并集（`merge_allowed`）。
# 合同值放第一位并去重：`session_kms.MESSAGE_TYPE` 改成别的值时它仍然在被模拟的取值里
# （闸门必须测平台真正走的那条路），DIGEST/RAW 两条也仍然都在。
# EXTERNAL_MU 不进这里：它对 RSA 不可达。
KMS_MESSAGE_TYPES = tuple(dict.fromkeys((KMS_MESSAGE_TYPE, "RAW", "DIGEST")))


def kms_context(message_type: str) -> list[dict]:
    return [{"ContextKeyName": "kms:SigningAlgorithm",
             "ContextKeyValues": [KMS_SIGNING_ALGORITHM],
             "ContextKeyType": "string"},
            {"ContextKeyName": "kms:MessageType",
             "ContextKeyValues": [message_type],
             "ContextKeyType": "string"}]


# 合同值那一条：`ACTIONS_OTHER` 那一组（`ssm:Get*` + `kms:*`）用它。
KMS_CONTEXT = kms_context(KMS_MESSAGE_TYPE)
# 每个 principal 的模拟腿数：函数类一腿 + 其余一腿（含合同 MessageType）+ `kms:Sign`
# 其余每个 MessageType 各一腿。**进度输出报这个数**，而不是写死"2 次"——腿数由
# `KMS_MESSAGE_TYPES` 决定，写死的字面量会在加/减一腿时静静地说谎（有一条单测把这个
# 常量与 `simulate` 真正发出的调用数对齐）。
SIM_LEGS_PER_PRINCIPAL = 1 + len(KMS_MESSAGE_TYPES)
# IAM 策略变更动作。**这一类不进模拟器**——它只用来判"哪些语句进 B 的静态快照"。
#
# 原先这里走的是"静态解析发现候选 → 模拟器对具体 ARN 确认 → 三值分类"两步。已删除：
# 它要求闸门回答"谁能提权"，而那等于要造一个 IAM 权限分析器（statement 归因、
# Condition 语义、NotResource 集合代数、policy variable、SourcePolicyType 碰撞
# ——每修一维下一维才暴露）。B 现在只做一件窄而可签字的事：**把可能影响这些动作的
# 语句（Allow 与 Deny）逐条指纹化，任何变化都红**，不判生效、不判提权链、不判方向。
IAM_WRITE_ACTIONS: tuple[str, ...] = (
                     "iam:PutRolePolicy", "iam:AttachRolePolicy",
                     "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion",
                     "iam:PutUserPolicy", "iam:AttachUserPolicy",
                     # 不改任何语句就能把托管策略切到另一个版本。
                     "iam:SetDefaultPolicyVersion",
                     # **per-site 隔离整个建立在 boundary 上** ⇒ 能改它就能拆掉那道隔离。
                     "iam:PutRolePermissionsBoundary",
                     "iam:DeleteRolePermissionsBoundary")
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
    # 3c-final：签名侧的两条正向控制。auth 签站点会话与控制台升级码/会话 ⇒ 两个 family 都要；
    # panel 只签 console family（spec §4.3：拿到 site 的 key 等于 panel 被攻破就能伪造站点会话）。
    # 丢了的真机症状是「全平台登录 500」与「面板会话签不出来」，两者都不会在任何单测里出现。
    "auth": (f"{G_KMS_SIGN}:site-", f"{G_KMS_SIGN}:console-"),
    "panel": (f"{G_KMS_SIGN}:console-",),
}

# simulate 调用的动作分组：函数类资源一组，其余一组。分开是为了不产生
# 大量无意义的 (动作, 资源) 组合——一次调用的响应体是资源数 × 动作数。
# 每个 principal 的调用数 = 2 + `len(KMS_MESSAGE_TYPES) - 1`（多出来的每腿**只有**
# `kms:Sign`、**只对** CMK：把 `ACTIONS_OTHER` 全套再跑一遍是成本翻倍换不来信号，
# `ssm:Get*` 与 `kms:MessageType` 无关）。今天是 3 腿。
ACTIONS_FUNCTION = A_INVOKE + A_REPLACE
ACTIONS_OTHER = A_READ_PARAM + A_KMS_SIGN + A_KMS_SELF_AUTHORIZE
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
    - `kms_keys`：kid → 会话签名 CMK 的 key ARN（两个 family 的全部 RS 行）。3c-final 起
      "谁能签会话"这个问题的目标集合就是它；密钥的明文副本不再存在，所以没有
      Edge 产物 / bootstrap asset / SSM 那三类目标了。
    """
    platform_functions: tuple[str, ...]
    site_functions: tuple[str, ...]
    kms_keys: dict[str, str] = field(default_factory=dict)
    alias_arns: dict[str, tuple[str, ...]] = field(default_factory=dict)
    version_arns: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # 3c-1B：auth 私有的 login-flow secret 的 SSM 参数 ARN。空串 = 不追踪。
    # 它进模拟目标（"谁能读它"是要记的事实），但它的 grant **不算冒充面**——见 G_READ_LOGIN_FLOW。
    login_flow_parameter: str = ""

    def function_resources(self) -> list[str]:
        out = list(self.platform_functions) + list(self.site_functions)
        for mapping in (self.alias_arns, self.version_arns):
            for arns in mapping.values():
                out.extend(arns)
        return sorted(set(out))

    def other_resources(self) -> list[str]:
        extra = {self.login_flow_parameter} if self.login_flow_parameter else set()
        return sorted(set(self.kms_keys.values()) | extra)


# 动作 → 动作等价类名。coverage 的成员指纹按**类**记，不按单个动作
# （否则同一能力的四个 SSM 动作会各记一项，噪音换不来信号）。
ACTION_CLASS_NAMES = {
    **{a: "invoke" for a in A_INVOKE},
    **{a: "replace-code" for a in A_REPLACE},
    **{a: "read-param" for a in A_READ_PARAM},
    **{a: "kms-sign" for a in A_KMS_SIGN},
    **{a: "kms-self-authorize" for a in A_KMS_SELF_AUTHORIZE},
}


def undecided_pairs(evaluation_results) -> set[tuple[str, str]]:
    """→ {(动作, 资源)}：该资源**非 allowed**，且它自己或**顶层**带 `MissingContextValues`。

    比 `missing_context_in`（principal 级的一个 bool）细一档，因为那个集合会漏掉这个
    反例：P 原本只对 site-a 的 Invoke 判不出，后来对某把会话签名 CMK 的 `kms:Sign`
    也判不出——按 principal 集合前后都是 `{P}` ⇒ 绿，而新增的**签名**不确定面
    没被发现。

    **顶层的 `MissingContextValues` 也算**（并进每个非 allowed 资源的键集）：只在
    `ResourceSpecificResults` 为空时才看顶层的写法，会让「顶层带、逐资源条目自己不带」
    这一形态返回空集——**那比旧的 bool 判据还弱**，是相对现状的倒退。

    `allowed` 的逐资源结果永远不算"判不出"：它已经有答案了。所以顶层带缺失上下文而
    逐资源全 allowed 时，本函数正确地返回空集（旧 bool 在同一输入上是 True）。

    **资源那一维只在它真的携带信息时才保留。** 实测（40 个 principal / 78 条
    EvaluationResults）：AWS 把顶层缺的键**机械地复制进每一个逐资源条目**，键集完全
    相同（逐资源计数恰好是顶层计数 × 资源数），而缺的是 `aws:ResourceAccount` /
    `aws:CalledViaLast` / `iam:PassedToService` / `aws:TagKeys` 这类**请求上下文**键
    ——它们与具体资源无关。照"每个非 allowed 资源各记一项"扇开，实测产生 **9985** 条
    成员（基线涨 10 倍），而那一维**零信息量**：新增一个带 Condition 的 principal 会
    一次冒出几十条，红被噪音淹没，正是"红了就更新基线"的训练场。

    **本函数逐资源产出，不做任何折叠。** 上一版按 action 全局折叠成 `(action, "")`，
    于是 `{site-panel}` 与 `{site-panel, site-deployer-undeploy}` 变成同一个成员
    ——一个 principal 对第二个精确平台函数变成"判不出"时闸门仍绿（Codex 第五轮 P2）。
    缺失键相同只说明**不确定的成因**与资源无关，**不说明后果与资源无关**：
    后果就是"还有哪些资源没被排除"，那正是安全边界。
    数量的封顶交给 `undecided_members()`——它按「动作类 × 资源类集合」折，不丢资源维度。
    """
    out: set[tuple[str, str]] = set()
    for res in evaluation_results:
        action = res.get("EvalActionName", "?")
        top = frozenset(res.get("MissingContextValues") or ())
        specific = res.get("ResourceSpecificResults") or []
        if specific:
            for rr in specific:
                if rr.get("EvalResourceDecision") == "allowed":
                    continue        # 已经有答案了，不是"判不出"
                if frozenset(rr.get("MissingContextValues") or ()) | top:
                    name = rr.get("EvalResourceName", "")
                    out.add((action, "" if "${" in name else name))
        elif top and res.get("EvalDecision") != "allowed":
            # 顶层资源名可能是 `${Region}` 这样的模板 ⇒ 归不到具体资源。
            # 老实记 unattributed，别硬塞一个不存在的 ARN（那会造出一个永远存在的假成员）。
            name = res.get("EvalResourceName", "")
            out.add((action, "" if "${" in name else name))
    return out


def _undecided_by_action(pairs, t: "Targets") -> dict[str, set[str]]:
    """(动作, 资源) 对 → {动作等价类: {判不出的资源类}}。两种成员形态共用这一步。"""
    by_action: dict[str, set[str]] = {}
    for action, resource in pairs:
        cls = ACTION_CLASS_NAMES.get(action, action)
        by_action.setdefault(cls, set()).add(undecided_resource_class(resource, t))
    return by_action


def undecided_members(principal_arn: str, pairs, t: "Targets") -> set[str]:
    """(动作, 资源) 集合 → 该 principal 的 coverage **成员**集合（可分解形态，见 `undecided_item`）。

    成员 = `(principal 指纹, 动作等价类, 该动作下判不出的**资源类集合**)`。

    两头都踩过坑，所以形状是这样：
    - **逐资源各记一项**：实测 **9985** 条（基线涨 10 倍），而"新增一个带 Condition 的
      principal 一次冒出几十条红"会训练出无脑更新基线。
    - **按 action 全局折叠成 unattributed**：`{site-panel}` 与
      `{site-panel, undeploy}` 成为同一个成员 ⇒ 扩大不可见（Codex 第五轮 P2）。

    取中间：**资源类集合整体进成员**。上界回到「principal × 动作类」= 5 条/principal，
    而集合一变成员就变 ⇒ 多出一个精确平台函数照样红。

    **形态为什么是可分解的、不再是一个哈希**（3c-1B-G A6 复审 P1-1）：资源类集合整体进成员，
    所以一把 key 的增减会让每个受影响 principal 的成员换值。要把这种 churn 归因给被声明的
    key，**两侧**都得能"剔掉那个资源类再比"。基线侧若只存哈希就剔不掉——新增 key 时还能只在
    本次观测上剔（schema 4 的做法），**退役**时那个类只在基线里有、观测里根本没有，哈希形态下
    无从归一 ⇒ ⑩ 的 `--retire-key` 声明过照样整批红（用生产比较器构造过反例）。成员里只有
    指纹与类名、没有账号值（类名来源见 `undecided_resource_class`），仓库红线不变。
    """
    return {undecided_item(principal_arn, cls, classes)
            for cls, classes in _undecided_by_action(pairs, t).items() if classes}


def undecided_resource_class(resource: str, t: "Targets") -> str:
    """资源 → **稳定**的资源类名。

    站点函数折叠成 `sites`：逐站点会让每次建站都把基线拽红，而"新增即红"依赖基线稳定。
    平台函数保留精确名字——那一维正好是安全边界（「对 site-panel 判不出」与
    「对 site-deployer-undeploy 判不出」不是一回事）。
    **限定符（alias/version）刻意折叠掉**：版本号每次部署都变，带上它会让 coverage
    每次部署漂移；同一函数名下的覆盖缺口由函数名这一级体现。
    """
    if not resource:
        return "unattributed"
    if t.login_flow_parameter and resource == t.login_flow_parameter:
        return "login-flow-param"
    for kid, arn in t.kms_keys.items():
        if resource == arn:
            return f"kms-key:{kid}"
    parts = resource.split(":")
    if len(parts) >= 7 and parts[2] == "lambda":
        name = parts[6]
        if any(a.split(":")[6] == name for a in t.site_functions):
            return "sites"
        return f"fn:{name}"
    if resource.startswith("arn:aws:s3:::"):
        return "s3-other"
    return "other"


_PFP_RE = re.compile(r"[0-9a-f]{4}(?:-[0-9a-f]{4}){3}")
# 可分解成员：`<principal 指纹>|<动作等价类>|<资源类>[,<资源类>…]`。资源类名里不许有 `|` `,` 与空白
# （`fn:<函数名>` / `kms-key:<kid>` 都满足：Lambda 函数名与 KID_RE 都不含这三种字符）。
UNDECIDED_ITEM_RE = re.compile(
    rf"{_PFP_RE.pattern}\|[a-z][a-z-]*\|[^|,\s]+(?:,[^|,\s]+)*")


def undecided_item(principal_arn: str, action_class: str, classes) -> str:
    """成员 = `<principal 指纹>|<动作等价类>|<资源类,资源类,…>`（资源类排序、逗号分隔）。

    三段都不是账号值：principal 只进指纹（与 `principals` 分节同一种指纹）；动作等价类是
    `ACTION_CLASS_NAMES` 的值；资源类是 `undecided_resource_class` 的输出（`sites` /
    `kms-key:<kid>` / `login-flow-param` / `fn:<平台函数名>` …，平台函数名本来就在 app.py 里）。
    可分解 ⇒ 基线侧也能剔类（A6 的退役反事实非它不可）。
    """
    return f"{principal_fingerprint(principal_arn)}|{action_class}|{','.join(sorted(classes))}"


def parse_undecided_item(item: str) -> tuple[str, str, frozenset]:
    pfp, cls, classes = item.split("|", 2)
    return pfp, cls, frozenset(classes.split(","))


def normalize_undecided_items(items, ignore_classes: frozenset) -> set[str]:
    """把被声明 key 的资源类从每个成员里剔掉再重编（A6 的归一化，**两侧都做**）。

    剔空的成员消失——与 `undecided_members` 的 `if classes` 同一条规则，两侧才可比。
    """
    out: set[str] = set()
    for item in items:
        pfp, cls, classes = parse_undecided_item(item)
        rest = classes - ignore_classes
        if rest:
            out.add(f"{pfp}|{cls}|{','.join(sorted(rest))}")
    return out


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

    for kid, arn in t.kms_keys.items():
        if allowed(A_KMS_SIGN, (arn,)):
            grants.add(f"{G_KMS_SIGN}:{kid}")
        if allowed(A_KMS_SELF_AUTHORIZE, (arn,)):
            grants.add(f"{G_KMS_SELF_AUTHORIZE}:{kid}")
    if t.login_flow_parameter and allowed(A_READ_PARAM, (t.login_flow_parameter,)):
        grants.add(G_READ_LOGIN_FLOW)
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


def expand_relevant_actions(patterns) -> set[str]:
    """动作模式 → 命中的 IAM 策略变更动作。**B 唯一的漏报入口，所以用全 glob。**

    用 `fnmatch.fnmatchcase` 对**小写串**匹配，不是 `endswith("*")`：实测旧写法下
    `iam:*RolePolicy` / `iam:*PolicyVersion` / `iam:Attach?olePolicy` 都返回**空集**
    ⇒ 这些语句整个漏不进快照，而闸门跑绿。

    用 `fnmatchcase` + 手工小写而不是 `fnmatch.fnmatch`：后者的大小写行为随文件系统变。
    `[seq]` 在 IAM 里不是通配而 fnmatch 把它当字符类 ⇒ 那是**过报**方向（安全）。
    """
    pats = patterns if isinstance(patterns, list) else [patterns]
    return {a for a in IAM_WRITE_ACTIONS for p in pats
            if fnmatch.fnmatchcase(a.lower(), str(p).lower())}


def is_relevant_iam_statement(st: dict) -> bool:
    """这条语句是否**可能影响 IAM 策略变更动作**。**Allow 与 Deny 都算相关。**

    为什么 Deny 也收：`Allow iam:* on *` + `Deny PutRolePolicy on EdgeRole`，删掉那条
    Deny 之后 **Allow 集合完全没变** ⇒ 只收 Allow 的设计全绿，而那是实实在在的扩权。
    """
    if st.get("Effect") not in ("Allow", "Deny"):
        return False
    if "NotAction" in st:
        # `NotAction` 是**补集**，算得准就算准：`NotAction: s3:*` 命中全部 IAM 写动作，
        # `NotAction: iam:*` 一个都不命中。一律保守算全命中会把"明确排除了 iam:*"
        # 也拖进快照，噪音换不来信号。
        return bool(set(IAM_WRITE_ACTIONS) - expand_relevant_actions(st["NotAction"]))
    return bool(expand_relevant_actions(st.get("Action", [])))


def relevant_iam_statements(statements: list[dict]) -> list[dict]:
    return [st for st in statements if is_relevant_iam_statement(st)]


def statements_for_entity(detail: dict, inline_key: str, *, managed: dict,
                          versions: dict) -> list[tuple[str | None, dict]]:
    """→ `[(来源托管策略 ARN | None, 语句)]`。inline 的来源是 `None`。

    语句**带来源**是为了让 `managed_policy_versions` 只记真正贡献了相关语句的那几份：
    账号里实测有 300 份托管策略，全记进基线会让 AWS 每更新任意一份都红一次，
    而那种噪音会训练出无脑更新基线。

    **纯函数**，不发网络调用：attached 托管策略的文档与版本必须由调用方预先解析进
    `managed` / `versions`（见 `list_principals`）。缺了就**硬失败**——静默跳过整份
    policy 的输出与"这份 policy 里没有相关 IAM 写语句"**一模一样**，那是 false-green。
    """
    out: list[tuple[str | None, dict]] = []
    for pol in detail.get(inline_key, []):
        out.extend((None, st) for st in policy_statements(pol["PolicyDocument"]))
    for att in detail.get("AttachedManagedPolicies", []):
        arn = att["PolicyArn"]
        if arn not in managed:
            raise SystemExit(
                f"attached 托管策略 {arn} 的文档没解析到——静默跳过它与「这份策略没有"
                f"相关 IAM 写语句」在输出上一模一样，那是 false-green")
        if arn not in versions:
            raise SystemExit(
                f"attached 托管策略 {arn} 的 DefaultVersionId 未知——不能拿占位值兜底"
                f"写进基线，那等于把「不知道」记成一个值")
        out.extend((arn, st) for st in policy_statements(managed[arn]))
    return out


def statements_for_user(detail: dict, *, groups: dict, managed: dict,
                        versions: dict) -> list[tuple[str | None, dict]]:
    """用户自己的语句 + 它所在 **group** 的语句。

    **只影响 B**：A 走 `SimulatePrincipalPolicy(PolicySourceArn=user)`，模拟器本来就
    评估 group 策略。实测账号内 0 个 group ⇒ 加这一层不改基线，但缺了它，
    哪天建了 group 就是一个静默的漏报口。
    """
    out = statements_for_entity(detail, "UserPolicyList", managed=managed,
                               versions=versions)
    for name in detail.get("GroupList", []):
        gr = groups.get(name)
        if gr is None:
            # **硬失败，不静默跳过**：那个 group 里的 IAM 写语句会从 B 快照消失，
            # 而输出与"该 group 没有相关语句"一模一样。IAM 的最终一致性窗口或并发
            # 变更都可能撞上。这与 attached 托管策略"文档缺失必须硬失败"同一条原则。
            raise SystemExit(
                f"用户 {detail.get('UserName')} 属于 group {name!r}，但它不在 "
                f"GetAccountAuthorizationDetails 返回的 GroupDetailList 里——"
                f"静默跳过它与「该 group 没有相关语句」在输出上一模一样，那是 false-green")
        out.extend(statements_for_entity(gr, "GroupPolicyList",
                                         managed=managed, versions=versions))
    return out


def statement_fingerprint(statement: dict, *, account: str, function: str,
                          qualifier: str | None = None,
                          qualifier_class: str = "alias") -> str:
    """Lambda resource policy 的单条语句 → 指纹。

    归一化掉账号 ID、**函数自身**的名字、以及 alias 名，这样不同站点函数的
    `edge-invoke` 语句会得到同一个指纹 ⇒ 可以用少数几份"形态"覆盖全部站点函数，
    新建站点不产生漂移，而多出一条语句的站点会被咬住。

    **限定符归一化成它的「类」而不是抹掉，且 alias 与 version 必须是两个类**：
    - 挂在 `blue` 上与挂在未限定函数上是两种不同宽度的授权（后者更宽）；
    - 挂在 `blue`（alias）上与挂在 `9`（version）上也是两回事。原先一律替换成
      `<alias>`，于是同一条语句从 alias 挪到 version（或反过来）指纹不变、比较结果
      是"与基线一致"（Codex 第五轮 P2；实测 `blue` 与 `9` 指纹逐字相同）。
    - **同类内部的成员仍然合并**：`blue` 与 `green` 同指纹是刻意的——颜色不该产生
      漂移，颜色级完整性由逐成员比对负责，不由指纹负责。

    只存指纹：语句里的 Principal 是带账号 ID 的角色 ARN（仓库红线）。
    """
    raw = json.dumps(statement, sort_keys=True, ensure_ascii=False)
    raw = raw.replace(account, "<acct>")
    if qualifier:
        raw = raw.replace(f"{function}:{qualifier}", f"<self>:<{qualifier_class}>")
    raw = raw.replace(function, "<self>")
    return _group(hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16])


def canonicalize_statement(statement: dict, *, account: str) -> str:
    """policy 语句 → **唯一**的归一化 JSON 串。指纹与人读原文都由它产出，所以
    "双跑确定"与"人看到的 diff"用的是同一个 oracle。

    两边各自归一化时，只排顶层键的那一边会随 AWS 返回的数组顺序变化 ⇒ 指纹稳而
    文本漂移，于是双跑 `--dump-observed` 的确定性检查会**误报**"快照不确定"，
    把人引去查一个根本不存在的不确定性。

    归一化：丢顶层 `Sid`（改名不是授权变化，留着只制造噪音）、**当前**账号 ID →
    `<acct>`、**递归**排序字典键与数组元素（`Action: [a,b]` 与 `[b,a]` 是同一条语句）。

    **只归一化当前账号**：语句里出现**另一个**账号的 principal 是重要漂移，必须改指纹。
    把所有 12 位数字都替换掉会让"授权给外部账号"与"授权给本账号"变成同一个指纹，
    而跨账号信任被引入的那一刻正是最该红的时候。

    `Condition` / `Resource` / `NotResource` **原样保留**——把它们排除出去，
    语义反转的改动（`SecureTransport false` → `true`）就会全绿。
    """
    def norm(node):
        if isinstance(node, dict):
            return {k: norm(v) for k, v in sorted(node.items())}
        if isinstance(node, list):
            return sorted((norm(x) for x in node),
                          key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
        return node

    body = {k: norm(v) for k, v in sorted(statement.items()) if k != "Sid"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False).replace(account, "<acct>")


def canonical_statement_fp(statement: dict, *, account: str) -> str:
    """任意 policy 语句 → 指纹。

    **与 `statement_fingerprint` 是两个函数，刻意不合并**：那个专给 Lambda resource
    policy（要把函数自身与 alias 名归一化成 `<self>` / `<alias>`，好让不同站点函数的
    同一条语句得到同一个指纹）。合成一个会改掉 `resource_policies.platform` 里已有的
    全部指纹，等于把一份能用的基线推平。
    """
    raw = canonicalize_statement(statement, account=account)
    return _group(hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16])


def canonical_statement_text(statement: dict, *, account: str) -> str:
    """给人看的归一化原文。**只进 stdout 与 /tmp 快照，不进基线。**

    与指纹共用 `canonicalize_statement` ⇒ 指纹相同的两条语句，文本也必然相同。
    外部账号 ID 会原样出现在这里——刻意的：它正是要人看见的那个漂移。所以这个串
    只进 stdout 与显式写到 /tmp 的产物，不落任何被跟踪文件。
    """
    return canonicalize_statement(statement, account=account)


def resource_policy_snapshot(policies: dict[str, list[tuple[str | None, dict]]], *,
                             account: str, platform: tuple[str, ...],
                             sites: tuple[str, ...],
                             aliases: dict[str, tuple[str, ...]]) -> dict:
    """`{函数名: [(qualifier, 语句)…]}` → 快照。**这里不做任何判断。**

    平台与站点函数**都按限定符类分组**（`unqualified` / `alias` / `version`，
    且 `alias` 逐成员），因为"有没有未限定语句"正是 legacy 与 modern 两种部署形态
    的判据，压平之后就没法只允许 modern；平台那半边压平还会丢掉 alias↔version
    的移动与"两个 alias 语句相同、删掉其中一个"（见 `bucketed`）。

    合法性判据在基线里（见 `compare_to_baseline`）。早先版本在这里用**并集**
    算规范形态，结果最宽松的那个站点函数反而成了规范、规矩的那个被报成偏离
    ——判断和观测混在一处就会这样。
    """
    def qual_class(fn: str, q: str | None) -> str:
        if q is None:
            return "unqualified"
        return "alias" if q in aliases.get(fn, ()) else "version"

    def fp(fn: str, q: str | None, st: dict) -> str:
        return statement_fingerprint(st, account=account, function=fn, qualifier=q,
                                     qualifier_class=qual_class(fn, q))

    def bucketed(fn: str) -> dict:
        """按限定符类分桶，alias **逐成员**（`{颜色: [指纹…]}`）。

        平台函数原先压成一个扁平集合，于是两种 false-green：① 语句从 alias 挪到
        version 指纹不变（见 `statement_fingerprint`）；② 两个 alias 有相同语句时，
        删掉其中一个而另一个还在，集合不变 ⇒ 绿。后者正是站点 alias 已经修过的
        「成员并集」问题，平台这条路当时留着没改。

        **alias 必须逐成员记**的站点侧理由同源：并起来记的话，「blue 丢了授权、
        green 还留着」两者相加仍等于规范集合 ⇒ 全绿。M7 切换后旧颜色的 alias /
        Function URL / 两条语句都保留（代码里没有任何地方删它们），所以"每个颜色
        都完整"不会误报。
        """
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
        return {"alias": {a: sorted(v) for a, v in alias_members.items()},
                "version": sorted(version_fps),
                "unqualified": sorted(unqualified)}

    # 两边**同一个分桶函数**：早先平台与站点各有一份逐字相同的循环，于是第五轮的
    # 「平台压平了」是只改一边留下的。同体之后不会再出现"修了一边"。
    return {"platform": {fn: bucketed(fn) for fn in platform},
            "sites": {fn: bucketed(fn) for fn in sites}}


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
    ("bucket_policy_drift",  "bootstrap 桶 policy 漂移（红）",                "bucket"),
    ("new_undecided_items",  "新增判不出的项（红）",                          "undecided"),
    ("iam_write_drift",      "IAM 写语句快照漂移（红）",                      "iam"),
    ("boundary_drift",       "permissions boundary 漂移（红）",               "iam"),
    ("kms_drift",            "KMS 层漂移（key policy / grants / 公钥 / key 集合）（红）", "kms"),
)
GREEN_FIELDS: tuple[tuple[str, str], ...] = (
    ("unclassified", "基线里未分类（请标注 category）"),
    ("migration_grants", "声明过的密钥增减（--new-key / --retire-key；绿，可更新基线）"),
    ("migration_undecided", "声明过的密钥引起的 coverage 成员迁移（绿；两侧剔掉该 key 的资源类后相等才落这里）"),
    ("improvements", "集合缩小（绿；可更新基线）"),
    ("notes",        "事实与口径（不参与红绿）"),
)
# 每个红字段都要有一条**处置**文案：闸门红了但不说该怎么办，等于把判断推给下一个人，
# 而最省力的"处置"永远是更新基线。
RED_MESSAGES = {
    "kms": ("闸门红：会话签名 CMK 的 key policy、grants、公钥或 key 集合变了。默认 key policy"
            "（ADR 0001）下能改它的人本来就在冒充面里，但**变了**就要有人看：新 grant = 多了"
            "能签会话的 principal；key 集合变化必须用 --new-key / --retire-key 声明。"),
    "grew": ("闸门红：账号里能冒充任意用户的授权面**变大了**。这不是又出了一个新缺陷，"
             "而是既有暴露面扩张。处理方式见 docs/security/account-trust-boundary.md。"),
    "lost": ("闸门红：平台自己的必需 invoke 权限丢了。真机症状是全站 403（Edge）或每次"
             "部署在健康门失败（deployer）——**先确认是不是刚做过一次收窄**，别去查网络。"),
    "bucket": ("闸门红：CDK bootstrap 桶的 bucket policy 变了。Edge 的部署产物就在这个桶里，"
               "而 SimulatePrincipalPolicy **不看** bucket policy（对 role 更是不支持"
               "模拟 resource policy）⇒ 这条通道只有这份快照能咬住。新增 Allow = 多了能读"
               "Edge 产物的人；丢掉那条 TLS Deny 同样是扩权。上面每条都打了归一化语句原文。"),
    "undecided": ("闸门红：判不出的 (principal, 动作类, 资源) 项变多了。这**不等于**有人拿到"
                  "了新权限，但**闸门对这一块的答案退化成了下界**——先看新增那几项对应哪条 "
                  "Condition（`--dump-observed` 看带真实名字的快照），再决定是补 "
                  "ContextEntries 还是接受并更新基线。"),
    "iam": ("闸门红：账号内可能影响 IAM 策略变更的**语句集合**变了（Allow 或 Deny），"
            "或某个 principal 的 permissions boundary 变了。**这一层刻意只报变化、"
            "不判方向**：它不声称语句是否生效、是否构成提权链、变化是收紧还是放宽"
            "（判这些需要一个 IAM 权限分析器，那正是本闸门被前五轮复审反复点名的根因）。"
            "上面每条都打了归一化后的语句原文——自己 diff 一遍再决定是否更新基线。"
            "若同一份策略的 VersionId 也变了，大概是 AWS 更新了托管策略。"),
}


@dataclass
class Report:
    new_principals: list[str] = field(default_factory=list)
    new_grants: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    new_statements: list[str] = field(default_factory=list)
    site_policy_outliers: list[str] = field(default_factory=list)
    bucket_policy_drift: list[str] = field(default_factory=list)
    new_undecided_items: list[str] = field(default_factory=list)
    iam_write_drift: list[str] = field(default_factory=list)
    boundary_drift: list[str] = field(default_factory=list)
    kms_drift: list[str] = field(default_factory=list)
    migration_grants: list[str] = field(default_factory=list)
    migration_undecided: list[str] = field(default_factory=list)
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
                        facts: dict | None = None,
                        coverage: dict | None = None,
                        iam_write: dict | None = None,
                        kms: dict | None = None,
                        new_keys: tuple = (),
                        retired_keys: tuple = ()) -> Report:
    """observed = {fingerprint: {"name", "arn", "grants"}}。

    `new_keys` / `retired_keys`：操作者用 `--new-key` / `--retire-key` 显式声明的标签
    （LABEL ∈ 已配置 kid ∪ {login-flow}，`--new-kid` 是 `--new-key` 的别名）。
    两个桶**互为镜像**，替代"看到红之后人工 --update-baseline"（1A 首跑就是那么放的，
    于是"当时为什么绿"只存在于 progress 里）：

    - **新增桶**：被声明的那条 grant 在**此前已能签某把会话密钥**的 principal 上不算扩权
      （同一批 `kms:*` on `key/*` 的授权自然覆盖新 CMK），单列进 migration_grants；在此前
      **不能**签的 principal 上仍是红——那是真扩权。未声明的一律红。
    - **退役桶**：platform 类 principal **丢掉**被声明的那条 grant 计入 migration_grants
      而不红；同一轮丢的其它 grant 照样红（`missing_required`）。非 platform 类的丢失
      仍按"改善"处理，与声明无关。
      退役桶**没有**新增桶那条"此前已能读密钥"的前置条件：丢一条 grant 不可能是扩权，
      唯一要挡的是"顺手放行了别的丢失"，而"只有被声明的那条"已经挡住了。

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
    declared_new = grants_for_labels(new_keys)
    declared_retired = grants_for_labels(retired_keys)

    for fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        grants = set(p["grants"])
        if fp not in base:
            rep.new_principals.append(f"{p['name']}  [{fp}]  {sorted(grants)}")
            continue
        was = set(base[fp].get("grants", []))
        category = base[fp].get("category")
        gained, lost = grants - was, was - grants
        if gained:
            # **前置条件"这个 principal 原本就能读到某把会话密钥"是刻意的，别按"改成看被声明的
            # grant 类"去放宽**（3c-1B-G A6 复核；两轮 review 都提过这条，结论是不改）：
            # 声明的语义是"我新建了一把 key，能对**同一批**资源做这些动作的人自然多一把可签"——
            # 那是良性的。而一个**原先签不出任何会话**的 principal 现在能签了，
            # 那是**能力面真的变大**，不该被一句 `--new-key` 抹掉，必须红、必须人看。
            # 两条既有用例把这个意图钉住了：`…without_prior_secret_read_stays_red` 与
            # `…could_not_read_any_key_stays_red`。
            migr = ((gained & declared_new)
                    if any(is_secret_grant(x) for x in was) else set())
            if migr:
                rep.migration_grants.append(
                    f"{p['name']}  [{fp}]  +{sorted(migr)}（--new-key 已声明）")
            if gained - migr:
                rep.new_grants.append(f"{p['name']}  [{fp}]  +{sorted(gained - migr)}")
        if lost:
            if category == "platform":
                retired = lost & declared_retired
                if retired:
                    rep.migration_grants.append(
                        f"{p['name']}  [{fp}]  -{sorted(retired)}（--retire-key 已声明）")
                if lost - retired:
                    rep.missing_required.append(
                        f"{p['name']}（platform）丢了 {sorted(lost - retired)}——平台授权是精确且"
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

    if coverage is not None:
        _compare_coverage(rep, (baseline.get("coverage") or {}).get("undecided_items"),
                          coverage.get("undecided_items"),
                          declared_labels=tuple(new_keys) + tuple(retired_keys))

    if iam_write is not None:
        # 第二个实参是整个 baseline：B 的三个分节都在基线顶层。
        _compare_iam_write(rep, baseline, iam_write)

    if kms is not None:
        _compare_kms(rep, baseline.get("kms") or {}, kms,
                     new_keys=tuple(new_keys), retired_keys=tuple(retired_keys))

    _compare_facts(rep, baseline.get("facts") or {}, facts)
    return rep


def _compare_kms(rep: Report, base: dict, now: dict, *, new_keys: tuple,
                 retired_keys: tuple) -> None:
    """KMS 层：会话签名 CMK 自己的快照。**任一字段变化都红，不判方向。**

    与 B 层同一条纪律（只报变化、不做权限分析）：判断"这条新 grant 是否真的让某人能签"
    需要一个 KMS 授权语义分析器，而那正是本闸门被反复点名的根因。

    key 集合的增减必须**声明**（`--new-key` / `--retire-key`）才落绿桶：轮转期新 key 就位、
    旧 key 退役都是计划内的，而"多出一把没人声明的会话签名 CMK"是要有人看的事。

    **逐字段比的清单由 `BUNDLE_SHAPE["kms"]["*"]` 派生，不在这里手写**：手写的那一份在有人给
    快照加第七个字段时不会跟着变，于是新字段进了观测与基线却从不参与比较——而"多了一个字段"
    与"那个字段没变过"在输出上一模一样（这正是本文件被反复点名的那类 false-green）。
    `grants` 从标量清单里剔掉、单独比：它是列表，要按排序后的集合比，并把条数差打出来。
    """
    scalars = [k for k in BUNDLE_SHAPE["kms"]["*"] if k != "grants"]
    for kid in sorted(set(base) | set(now)):
        if kid not in base:
            (rep.migration_grants if kid in new_keys else rep.kms_drift).append(
                f"kms {kid}：新出现"
                + ("（--new-key 已声明）" if kid in new_keys else "——未声明的新 key"))
            continue
        if kid not in now:
            (rep.migration_grants if kid in retired_keys else rep.kms_drift).append(
                f"kms {kid}：消失"
                + ("（--retire-key 已声明）" if kid in retired_keys else "——未声明的 key 退场"))
            continue
        for k in scalars:
            if base[kid].get(k) != now[kid].get(k):
                rep.kms_drift.append(f"kms {kid}：{k} 变了")
        if sorted(base[kid].get("grants", [])) != sorted(now[kid].get("grants", [])):
            rep.kms_drift.append(
                f"kms {kid}：grants 从 {len(base[kid].get('grants', []))} 条变成 "
                f"{len(now[kid].get('grants', []))} 条")


def _compare_iam_write(rep: Report, base: dict, now: dict) -> None:
    """B：IAM 写的静态文本快照。**任何 added / removed / changed 都红，不判改善。**

    **不声称**语句是否生效、是否构成提权链、变化方向是收紧还是放宽。判这些需要
    statement 归因 + Condition 语义 + NotResource 集合代数 + policy variable，
    也就是一个 IAM 权限分析器——那正是这道闸门被前五轮复审反复点名的根因。

    **为什么"消失"也红**：Allow 消失不等于收紧——语句可能被拆成两条更宽的、可能从
    inline 挪到另一份 policy，也可能是**解析器漏收了**。把"旧指纹消失"自动判成改善，
    正好会把解析器退化显示成好消息。而 **Deny 消失是实实在在的扩权**
    （`Allow iam:* on *` + `Deny PutRolePolicy on EdgeRole`，删掉 Deny 则 Allow 集合
    完全没变 ⇒ 只收 Allow 的设计全绿）。
    """
    texts = now.get("texts") or {}
    base_v = base.get("managed_policy_versions") or {}
    now_v = now.get("managed_versions") or {}
    ver_moved = sorted(f"[{k}] {base_v.get(k)} → {now_v.get(k)}"
                       for k in set(base_v) | set(now_v) if base_v.get(k) != now_v.get(k))

    base_st, now_st = base.get("iam_write_statements") or {}, now.get("statements") or {}
    for fp in sorted(set(base_st) | set(now_st)):
        was, is_ = set(base_st.get(fp, [])), set(now_st.get(fp, []))
        for s in sorted(is_ - was):
            rep.iam_write_drift.append(
                f"[{fp}] +语句 [{s}]\n      {texts.get(s, '（原文不在本次快照里）')}")
        for s in sorted(was - is_):
            rep.iam_write_drift.append(
                f"[{fp}] -语句 [{s}]——**消失也红**：Allow 可能被拆成两条更宽的、"
                f"可能挪到另一份 policy，也可能是解析器漏收了；Deny 消失是实实在在的扩权")
    # 让"AWS 更新了托管策略"这类红**自解释**：否则人只看到一串指纹变了就会无脑更新基线。
    if rep.iam_write_drift and ver_moved:
        rep.iam_write_drift.append("托管策略版本同时变了：" + "；".join(ver_moved))
    elif ver_moved:
        rep.notes.append("托管策略版本变了（语句集合未变）：" + "；".join(ver_moved))

    base_b, now_b = base.get("permissions_boundaries") or {}, now.get("boundaries") or {}
    for fp in sorted(set(base_b) | set(now_b)):
        was_b, is_b = base_b.get(fp), now_b.get(fp)
        if was_b == is_b:
            continue
        if is_b is None:
            rep.boundary_drift.append(
                f"[{fp}] permissions boundary 整个不见了——**per-site 隔离整个建立在 "
                f"boundary 上**，这不是收紧")
        elif was_b is None:
            rep.boundary_drift.append(
                f"[{fp}] 新增了 permissions boundary {is_b['policy_fp']}")
        else:
            rep.boundary_drift.append(
                f"[{fp}] boundary 变了：policy {was_b['policy_fp']} → {is_b['policy_fp']}；"
                f"语句 ±{sorted(set(was_b['stmt_fps']) ^ set(is_b['stmt_fps']))}")


def _compare_coverage(rep: Report, base_items, now_items, *,
                      declared_labels: tuple = ()) -> None:
    """判不出的项按**成员**比：**新成员红、消失算改善、数量只作文档摘要。**

    成员是 `(principal, 动作等价类, 资源类集合)`（可分解形态，`undecided_item`）。按 principal
    集合比会漏掉这个反例：P 原本只对 site-a 的 Invoke 判不出，后来对某把会话 CMK 的
    `kms:Sign` 也判不出 —— 前后都是 `{P}` ⇒ 绿，而新增的**签名**不确定面没被发现。

    **被声明 key 引起的 churn**（3c-1B-G A6；复审 P1-1 改成两侧归一化）：资源类集合整体进成员，
    所以一把 key 的增减会让每个受影响 principal 的成员换值（旧的消失 + 新的出现）。判据：把被
    声明 key 的资源类从**基线与本次两侧**的成员里都剔掉再比——相等 ⇒ 这一轮 churn 完全由被声明
    的 key 解释，整批记进 `migration_undecided`（绿）；**剔掉之后仍多出来的成员照红**。两侧都剔
    才同时覆盖新增（类只在本次有）、退役（类只在基线有）与二者同轮发生；旧实现只在本次观测上剔
    （"反事实"快照），退役声明过也照样红。
    """
    was, now = set(base_items or []), set(now_items or [])
    gained, gone = now - was, was - now
    if declared_labels and (gained or gone):
        ignore = classes_for_labels(declared_labels, None)
        was_n = normalize_undecided_items(was, ignore)
        now_n = normalize_undecided_items(now, ignore)
        gained_n, gone_n = now_n - was_n, was_n - now_n
        explained = (len(gained) - len(gained_n), len(gone) - len(gone_n))
        if explained != (0, 0):
            # 措辞按事实分两档（复审二轮）：只有归一化后**两个方向都没有**剩余差异才说"相等"；
            # 否则只说解释了多少，剩余差异按下面的常规红绿处理（新成员红、消失算改善）。
            tail = ("两侧剔掉其资源类后归一化**相等**" if not (gained_n or gone_n) else
                    f"归一化后仍有 {len(gained_n)} 项新成员 / {len(gone_n)} 项消失，按常规红绿处理")
            rep.migration_undecided.append(
                f"被声明的 key（{sorted(declared_labels)}）解释了 {explained[0]} 项新成员 / "
                f"{explained[1]} 项旧成员的 churn；{tail}（--new-key/--retire-key 已声明）")
        if gained_n:
            rep.notes.append(
                f"声明的 key 解释不了全部 churn：剔掉其资源类后仍有 {len(gained_n)} 项新成员，下面照红")
        gained, gone = gained_n, gone_n
    for fp in sorted(gained):
        rep.new_undecided_items.append(
            f"[{fp}] 新增一项判不出的 (principal, 动作类, 资源)——不确定面变大了；"
            f"用 --dump-observed 看它对应哪条 Condition")
    for fp in sorted(gone):
        rep.improvements.append(f"[{fp}] 这一项已能判定（可更新基线）")
    rep.notes.append(f"undecided_items: {len(was)} → {len(now)}（{len(now) - len(was):+d}）")


def _platform_buckets(was_shape, now_shape):
    """产出 `(桶名, 基线集合, 本次集合)`，覆盖两边出现过的每个桶与每个 alias 成员。

    `None` 当空处理（函数新增或消失时另一边没有形状）。
    """
    was_shape = was_shape or {}
    now_shape = now_shape or {}
    for bucket in ("unqualified", "version"):
        yield bucket, set(was_shape.get(bucket) or []), set(now_shape.get(bucket) or [])
    was_alias = was_shape.get("alias") or {}
    now_alias = now_shape.get("alias") or {}
    for name in sorted(set(was_alias) | set(now_alias)):
        yield (f"alias {name}", set(was_alias.get(name) or []),
               set(now_alias.get(name) or []))


def _compare_resource_policies(rep: Report, base_rp: dict, now_rp: dict) -> None:
    """平台函数按**集合等值**比（丢失一条 Function URL 授权语句 = 控制台或站点
    入口断掉，首版把它写成"改善"）；站点函数按限定符类逐类比，legacy 只认
    点名豁免。"""
    base_platform = base_rp.get("platform", {})
    now_platform = now_rp.get("platform", {})
    for fn in sorted(set(base_platform) | set(now_platform)):
        # **逐桶比**（unqualified / 每个 alias / version），不是压成一个扁平集合：
        # 扁平集合下「语句从 alias 挪到 version」与「两个 alias 有相同语句、删掉其中
        # 一个」都不变 ⇒ 绿（Codex 第五轮 P2）。平台授权是精确且必需的，所以每个桶
        # 按**集合等值**比，任一方向的差异都红。
        for bucket, was, now in _platform_buckets(base_platform.get(fn),
                                                  now_platform.get(fn)):
            if now - was:
                rep.new_statements.append(f"{fn} [{bucket}]: +{sorted(now - was)}")
            if was - now:
                rep.new_statements.append(
                    f"{fn} [{bucket}]: 少了 {sorted(was - now)}——平台函数的 resource "
                    f"policy 是精确且必需的，丢失同样要红")

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

    _compare_bucket_policy(rep, base_rp.get("bootstrap_bucket"),
                           now_rp.get("bootstrap_bucket"),
                           texts=now_rp.get("bootstrap_bucket_texts") or {})


def _compare_bucket_policy(rep: Report, base_fps, now_fps, *, texts: dict) -> None:
    """CDK bootstrap 桶的 bucket policy：**任何 added / removed / changed 都红，不判改善。**

    为什么单独有这一层：`SimulatePrincipalPolicy` 不纳入 resource-based policy（对 role
    根本不支持模拟它），而 S3 bucket policy 单独就能授权读 asset——桶里有 9 个仍带活
    密钥的对象。今天这个桶只有一条 `AllowSSLRequestsOnly`（Deny 非 TLS）。

    **消失也红**：丢掉那条 TLS Deny 是实实在在的扩权；整条 policy 被删也走这一支。
    **不证明什么**：不看 S3 access point（另一条命名空间，本闸门不覆盖）。
    """
    was, now = set(base_fps or []), set(now_fps or [])
    for fp in sorted(now - was):
        rep.bucket_policy_drift.append(
            f"bootstrap 桶新增语句 [{fp}]\n      {texts.get(fp, '（原文不在本次快照里）')}")
    for fp in sorted(was - now):
        rep.bucket_policy_drift.append(
            f"bootstrap 桶少了语句 [{fp}]——**消失也红**：丢掉现有的 TLS Deny 是扩权")


def assert_edge_artifacts(code_hits: dict, asset_hits: dict, *, site_kids, console_kids) -> None:
    """Edge 产物的**三条硬断言**（3c-final）。都是 SystemExit，不是红字段。

    为什么是硬失败而不是走基线比较：① 它们不落 facts ⇒ 没有可比较的基线数字；
    ② 必须连 `--update-baseline` 一起挡住——红字段挡不住那条路，而这三种形态没有任何
    可以接受的基线；③ spec §11.8.7 对 login-flow 那条明写"实现为直接断言、不新增 facts"，
    另两条同理。

    三条各自防什么：
    · **当前关联的版本必须带每一把 site kid 的公钥**——缺了不是"少一点观测"，而是线上
      **全员 302**（Edge 的 allowlist 里没有这个 kid ⇒ `unknown_kid`）。它是"部署的确实是
      这份 config"的唯一可执行证据；`edge_current_version` 刻意按 CloudFront 的关联取版本，
      不按"版本号最大"挑（$LATEST 可能已经是下一次要发的代码）。
    · **不得出现任何 console kid 的公钥**（spec §4.1）：进了 Edge 的 allowlist ⇒ panel signer
      被攻破就能伪造站点会话。
    · **不得出现 login-flow secret 的值**（spec §11.3）：它是 auth 私有的，只签 OAuth state
      与 `__Host-sb_pkce` cookie，Edge 与 panel 永不持有。

    **一条已知代价**（3c-1B /code-review 转来）：`--from-dump` 覆盖不到这三条——快照里没有
    这些信息（它们刻意不落 facts），所以拿快照出结论时它们不成立。`main()` 的 `--from-dump`
    提示里已明说。抛点在 IAM 模拟（本文件最慢的一段）**之前**，而快照本来就要等模拟结束才
    完整 ⇒ 任何保留 BUNDLE_SHAPE 的实现都拿不到那份快照。
    """
    problems = []
    for kid in site_kids:
        if not code_hits.get(f"site:{kid}"):
            problems.append(
                f"当前关联的 Edge 版本里没有 {kid} 的公钥——部署的不是这份 config 的 allowlist，"
                f"线上会全员 302")
    for kid in console_kids:
        if code_hits.get(f"console:{kid}") or asset_hits.get(f"console:{kid}"):
            problems.append(
                f"Edge 产物里出现了 console family 的公钥 {kid}——spec §4.1：panel signer 被攻破"
                f"就能伪造站点会话。先查 router/infrastructure/stack.py 的 site allowlist 只取 site family")
    if code_hits.get(LABEL_LOGIN_FLOW) or asset_hits.get(LABEL_LOGIN_FLOW):
        problems.append(
            "Edge 产物里出现了 login-flow secret 的值——它是 auth 私有的（spec §11.3）：只签 "
            "OAuth state 与 __Host-sb_pkce cookie，Edge 与 panel 永不持有。出现在这里说明注入"
            "路径把它当成了会话密钥；Edge 产物全球复制，写进去就等于永久泄漏")
    if problems:
        raise SystemExit("闸门硬失败（不接受基线放行）：\n  " + "\n  ".join(problems))


def _compare_facts(rep: Report, base_facts: dict, now_facts: dict | None) -> None:
    """事实类数字只报 delta，**不参与红绿**——理由写在这里，因为它是个刻意的选择。

    `principals_with_missing_context` 会随账号里任何一条带 Condition 的新策略
    变动，跟本平台无关；让它决定退出码就会频繁红在无关变更上，
    进而训练出"红了就更新基线"。所以：算出来、打印出来、不影响退出码。
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


def secret_in_zip_bytes(blob: bytes, value: str) -> bool:
    """zip 里的 .py 是否含 `value` 这个字面量。**不打印、不返回取到的值本身。**

    要找的东西有两类：base64 的 SPKI 公钥（`SITE_ALLOWLIST_JSON` 里那些 `spki_b64`，
    392 字符）与 login-flow secret 的值。两者都够长 ⇒ 子串命中不会有假阳性，所以判据就是
    朴素的子串包含。**别为了"更严"加回按赋值语句形态精确匹配的那一支**：注入点的形态
    （今天是一整份 JSON 里的一个字段）不由本函数决定，绑死形态只会让某次 stack.py 改写
    注入方式时三条硬断言集体失效，而失效方向是"没找到"⇒ 其中两条负向断言会静静地绿。
    """
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        src = b"".join(z.read(n) for n in z.namelist()
                       if n.endswith(".py")).decode("utf-8", "ignore")
    except (zipfile.BadZipFile, KeyError):
        return False
    return value in src


# ---------------------------------------------------------------- 真机部分

def harden_tls_warnings() -> None:
    """把「这次请求没校验服务端证书」升成**致命错误**，不许只打印后继续退出 0。

    实测现场（2026-08-26）：`measure()` 原先把**同一个** IAM client 交给 4 个 worker
    并发用，于是 400 个 principal 的模拟里有十几次是在**未校验证书**的连接上完成的。
    对照实验：同一批请求顺序执行 **0** 次、每线程独立 client **0** 次 —— 是共享 client
    的并发形态触发的，不是机器环境的背景噪音。

    为什么必须致命：闸门的答案要是能被主动 MITM 伪造，那次"绿"就不能当安全证据，
    而"打印一条 warning 然后退出 0"与"一切正常"在 CI 上长得一模一样。
    """
    from urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter("error", InsecureRequestWarning)


_TLS_LOCAL = threading.local()
# botocore 的 session/client 构造不保证线程安全，所以建的时候上锁；建好之后每线程各用自己的。
_CLIENT_LOCK = threading.Lock()


def thread_iam_client(region: str):
    """**每线程一个** IAM client。

    共享一个 client 并发用会让一部分请求跳过证书校验（见 `harden_tls_warnings`）。
    同一线程内复用——否则 400 个 principal 会建 400 个 client。
    """
    if not hasattr(_TLS_LOCAL, "iam"):
        import boto3
        from botocore.config import Config
        with _CLIENT_LOCK:
            _TLS_LOCAL.iam = boto3.client(
                "iam", region_name=region,
                config=Config(retries={"max_attempts": 12, "mode": "adaptive"}))
    return _TLS_LOCAL.iam


def _aws_clients(region: str):
    import boto3
    from botocore.config import Config
    harden_tls_warnings()
    cfg = Config(retries={"max_attempts": 12, "mode": "adaptive"})
    clients = {n: boto3.client(n, region_name=region, config=cfg)
               for n in ("iam", "lambda", "sts", "s3", "ssm", "cloudformation", "kms")}
    # CloudFront 是全局服务：带 region_name 也只会打到 us-east-1，但显式不带，
    # 免得将来有人把 --region 改成别的区时这一路静默变成"对着另一个区问分发"。
    clients["cloudfront"] = boto3.client("cloudfront", config=cfg)
    return clients


def resolve_managed_policy(iam, arn: str, *, docs: dict, versions: dict):
    """托管策略 ARN → `(文档, DefaultVersionId)`。**解析不出就硬失败，绝不 continue。**

    `GetAccountAuthorizationDetails` 只返回它认为"被附加"的托管策略。一旦某份缺席
    （权限不足、返回形态变化、新的 policy 类型没进 Filter、boundary 不算附加），
    静默跳过它的输出与"这份策略里没有相关语句"**一模一样** ⇒ B 是 false-green。
    boundary 与普通 attached 策略走同一条路，就不会再有两套宽严不一的规则。
    """
    if arn in docs and arn in versions:
        return docs[arn], versions[arn]
    try:
        ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=arn,
                                     VersionId=ver)["PolicyVersion"]["Document"]
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            f"解析不出托管策略 {arn}：{type(exc).__name__}: {exc} —— 静默跳过它与"
            f"「这份策略没有相关语句」在输出上一模一样，那正是 false-green") from exc
    if doc is None:
        raise SystemExit(f"托管策略 {arn} 的文档为空——不能当成「没有相关语句」")
    docs[arn], versions[arn] = doc, ver
    return doc, ver


def principal_auth_digest(p: dict) -> str:
    """一个 principal 在本轮里被用到的**全部授权输入** → 稳定摘要。

    覆盖 `uid`、boundary（ARN **与它那份文档的语句**）、**带来源的全部语句**、以及
    每份贡献策略的 `DefaultVersionId`。

    为什么是"全部语句"而不是"`is_relevant_iam_statement` 挑出来的那些"：A 组是模拟器在
    T2 对**完整**策略求值的结果，B 组是 T1 抄下来的相关语句。只要任何一条语句在窗口内
    变过，这两组就来自两个不同的账号状态——那条语句本身相不相关，不改变"这份快照混了
    两个时刻"这个事实。按"相关"过滤会把判据缩得比主语窄。

    **为什么 boundary 的文档必须单独收**（Codex 第八轮的 blocker，实测复现）：
    boundary **不算"被附加"**，所以它的语句根本不在 `statements` 里（见
    `list_principals`）。早先的摘要只放了 `boundary_arn` ⇒ boundary 那份托管策略换了
    默认版本、ARN 不变时，摘要的输入一个字都不变 ⇒ 复查看不见，**而且这个变化是持久的**
    （不是 ABA 那种巧合）。两层都受影响：B 的 `boundaries[fp].stmt_fps` 是 T1 抄的；
    而 `SimulatePrincipalPolicy` 不传 `PermissionsBoundaryPolicyInputList` 时用的就是
    实体**当前**那份 boundary（该参数的语义是**覆盖**已附加的那份，AWS 文档明确），
    所以 A 的判定按 T2 的 boundary 算。

    **版本号也进摘要，包括"只换版本、语句逐字相同"那一种。** 早先这里写着一条不声称
    （"下一轮自己会红，权限面确实没动"）。那是个 carve-out，而这份文档被推翻的历次都是
    carve-out：`managed_versions` 同样**持久化进基线**，T1 记的版本与 T3 的现实不一致时
    快照里那个值就是错的。实测代价为零——7 天 CloudTrail 里 `CreatePolicyVersion` 与
    `SetDefaultPolicyVersion` 都是 0 次。

    语句先各自序列化再**排序**：AWS 两次返回同一份策略的语句顺序不保证一致，不排序
    会把顺序抖动误报成漂移，而反复的假红会训练出"红了就重跑到绿为止"。
    """
    payload = json.dumps(
        {"kind": p["kind"], "uid": p["uid"], "boundary": p["boundary_arn"],
         "boundary_statements": sorted(json.dumps(st, sort_keys=True, default=str)
                                       for st in p["boundary_statements"]),
         "policy_versions": {k: p["policy_versions"][k]
                             for k in sorted(p["policy_versions"])},
         "statements": sorted(json.dumps([src, st], sort_keys=True, default=str)
                              for src, st in p["statements"])},
        sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def enumeration_drift(before: list[dict], after: list[dict]) -> dict[str, list[str]]:
    """模拟前后两次枚举 → **分类**后的漂移原因。空 dict = principal 层**窗口两端一致**。

    **注意这不是"原子性"，别这么叫**（Codex 第八轮把原先那个说法判成过宽，成立）。
    两点比较只能证明 T1 与 T3 相等，证明不了中间没变过。**已接受的三个盲区**：

    1. **改了又改回来（ABA）**：T1 有授权 → T2 前撤掉 → T3 恢复成与 T1 逐字相同。
       复查报无漂移，而 A 那次模拟看到的是撤掉后的状态（可能报成 improvement）。
    2. **枚举后新建、复查前删除**：两端都不存在，整轮不知道它来过。
    3. **单次枚举自己也不是一个时刻**：`GetAccountAuthorizationDetails` 分页实测跨约
       90 秒，翻页期间的变化对本函数不可见。

    要真正关掉这三个，需要一条独立的**单调事件源**（变更审计屏障），而不是靠两端状态
    相等。CloudTrail 不能直接当那个屏障——它有投递延迟（分钟级且无上界保证），
    拿它做同步屏障要么阻塞不确定的时间，要么给出虚假保证。所以这里**只声称**：
    **窗口两端不一致就作废本轮**，即持久性的漂移会被咬住。

    三类分开报，是因为操作者要能一眼分辨是哪种 churn：站点部署/下线会造出与销毁
    `site-rt-*`（平台自己的行为），另一套 workload 会同名重建。只说一句"本轮作废"
    会让人以为闸门坏了。

    **三类都作废本轮**，包括看起来"安全"的那两类：
    - `changed`：同一个 principal 的 A 与 B 来自两代 ⇒ 直接的 false-negative。
    - `appeared`：T1 之后新建的 principal 整个没被模拟 ⇒ 覆盖不全，它可能带新 grant。
    - `vanished`：模拟完成后才消失 ⇒ 快照里报着一个已经不存在的 principal。这一类
      方向上是**多报**（不会藏住新权限），但仍作废：一轮观测要么描述一个时刻，
      要么不算权威。给"缩小是安全的"这类单独放行开一个口子，正是历次 false-green
      的共同形状。
    """
    b = {p["arn"]: p for p in before}
    a = {p["arn"]: p for p in after}
    changed = []
    for arn in sorted(set(b) & set(a)):
        if b[arn]["uid"] != a[arn]["uid"]:
            changed.append(f"{b[arn]['name']}（同 ARN 换代：uid 变了）")
        elif principal_auth_digest(b[arn]) != principal_auth_digest(a[arn]):
            changed.append(f"{b[arn]['name']}（策略/boundary 在窗口内被改）")
    out = {"changed": changed,
           "appeared": sorted(a[arn]["name"] for arn in set(a) - set(b)),
           "vanished": sorted(b[arn]["name"] for arn in set(b) - set(a))}
    return {k: v for k, v in out.items() if v}


def list_principals(iam) -> dict:
    """非 service-linked 角色 + 全部 IAM 用户，**连语句、boundary、托管策略版本一起收**。

    → `{"principals": [{kind,name,arn,statements,boundary_arn}],
         "policy_docs": {arn: doc}, "managed_versions": {arn: VersionId}}`

    **用户不能漏**：账号 owner 的 IAM 用户同样是一个 principal，只数角色会漏掉它。
    **Group 也不能漏**：用户经 group 拿到的 IAM 写语句否则整个不可见（只影响 B——
    A 走模拟器，它本来就评估 group 策略）。实测账号内 0 个 group，但缺了这一层，
    哪天建了 group 就是一个静默的漏报口。

    语句是 B 的输入（纯静态文本快照）。先把**全部**被引用的托管策略解析齐，
    再交给纯函数 `statements_for_entity` —— 网络回退集中在一处，纯函数保持可单测。
    """
    docs: dict[str, object] = {}
    versions: dict[str, str] = {}
    roles: list[dict] = []
    users: list[dict] = []
    groups: dict[str, dict] = {}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]):
        roles.extend(page.get("RoleDetailList", []))
        users.extend(page.get("UserDetailList", []))
        for gr in page.get("GroupDetailList", []):
            groups[gr["GroupName"]] = gr
        for pol in page.get("Policies", []):
            for version in pol.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    docs[pol["Arn"]] = version["Document"]
                    versions[pol["Arn"]] = version["VersionId"]

    roles = [r for r in roles if not r["Path"].startswith("/aws-service-role/")]

    # 预解析：任何被引用但没出现在上面那份 map 里的托管策略都单独取（取不到就硬失败）。
    # permissions boundary 尤其要走这一步——它**不算"被附加"**，所以可能整个缺席，
    # 而 per-site 隔离整个建立在 boundary 上。
    referenced: set[str] = set()
    for detail in list(roles) + list(users) + list(groups.values()):
        referenced |= {a["PolicyArn"] for a in detail.get("AttachedManagedPolicies", [])}
        boundary = (detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        if boundary:
            referenced.add(boundary)
    for arn in sorted(referenced):
        resolve_managed_policy(iam, arn, docs=docs, versions=versions)

    # `uid`（RoleId / UserId）是**换代检测**的唯一依据：同名同路径的角色被删了重建，
    # ARN 一模一样而 uid 必然是新的。本账号里这不是理论情形——实测 2026-08-27 有两个
    # 固定名字的角色各被重建 4 次、拿到 4 个不同的 RoleId。只比 ARN 的话，
    # 「T1 抄的语句」与「T2 模拟的那个角色」可能属于两代，见 `enumeration_drift`。
    # uid **只在进程内用**、不进快照也不进基线：合法重建每天都发生，把它写进基线
    # 等于每天红一次而没有任何安全含义，那种噪音会训练出无脑更新基线。
    # boundary 的**文档内容**与每份贡献策略的**默认版本号**也要随 principal 带出来，
    # 否则 `principal_auth_digest` 看不见它们（boundary 不算"被附加"⇒ 它的语句不在
    # `statements` 里）。这两项与 `uid` 一样**只在进程内用**：boundary 语句已经由 B 以
    # 指纹形态进基线，版本号也已经在 `iam_write.managed_versions` 里，这里再存一份原文
    # 只为了做窗口两端的等值比较。
    def _decorate(entry: dict) -> dict:
        b_arn = entry["boundary_arn"]
        # `docs` / `versions` 里必须已经有它——上面对全部 referenced 策略（含 boundary）
        # 预解析过，解析不出会硬失败。**故意用直接索引**：`.get()` 兜出 None/空 list 时，
        # 两端都是空 ⇒ 摘要恒等 ⇒ 复查永远说"没变"，与"账号很安静"逐字相同。
        entry["boundary_statements"] = policy_statements(docs[b_arn]) if b_arn else []
        srcs = {src for src, _ in entry["statements"] if src is not None}
        if b_arn:
            srcs.add(b_arn)
        entry["policy_versions"] = {a: versions[a] for a in sorted(srcs)}
        return entry

    out = []
    for r in roles:
        out.append(_decorate({
            "kind": "role", "name": r["RoleName"], "arn": r["Arn"],
            "uid": r["RoleId"],
            "statements": statements_for_entity(r, "RolePolicyList",
                                                managed=docs, versions=versions),
            "boundary_arn": (r.get("PermissionsBoundary") or {})
                            .get("PermissionsBoundaryArn")}))
    for u in users:
        out.append(_decorate({
            "kind": "user", "name": u["UserName"], "arn": u["Arn"],
            "uid": u["UserId"],
            "statements": statements_for_user(u, groups=groups, managed=docs,
                                              versions=versions),
            "boundary_arn": (u.get("PermissionsBoundary") or {})
                            .get("PermissionsBoundaryArn")}))
    return {"principals": out, "policy_docs": docs, "managed_versions": versions}


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
        raise SystemExit(
            f"{function_name} 没有 CloudFormation stack tag——推不出当前 asset 的位置。"
            f"asset 那一侧是 `assert_edge_artifacts` 两条负向断言（不得含 console 公钥 / "
            f"不得含 login-flow 值）的一半输入，缺了它闸门只剩 code 那一半，"
            f"而“少扫了一处”与“那里干净”在输出上一模一样")
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


def edge_code_arns_carrying_keys(clients, function_name: str, fn_arn: str,
                                 qualifiers: tuple[str, ...],
                                 values: dict[str, str]) -> dict[str, tuple]:
    """扫点名的那几个 Edge 代码目标，每个只下载一次，对每个待找的值各判一次。

    **`qualifiers` 是精确清单，函数自己不再补一个未限定的 `$LATEST`**（3c-final）：
    `assert_edge_artifacts` 那条"当前关联的版本必须带每把 site 公钥"的断言只有在
    `code_hits` 里**只有**那个版本时才成立——把 `$LATEST` 一起扫进来的话，一次"代码已更新
    但 CloudFront 还指着旧版本"的部署（正是要抓的那种）会因为 `$LATEST` 命中而变绿。
    "最新代码里有没有不该有的东西"由当前 CDK asset 那一路覆盖（它就是产出 `$LATEST` 的字节）。
    """
    import urllib.request
    out: dict[str, list[str]] = {label: [] for label in values}
    for qualifier in qualifiers:
        kw = {"FunctionName": function_name}
        if qualifier:
            kw["Qualifier"] = qualifier
        try:
            url = clients["lambda"].get_function(**kw)["Code"]["Location"]
        except clients["lambda"].exceptions.ResourceNotFoundException:
            continue
        with urllib.request.urlopen(url) as fh:      # noqa: S310 (AWS 预签名 URL)
            blob = fh.read()
        arn = fn_arn if not qualifier else f"{fn_arn}:{qualifier}"
        for label, value in values.items():
            if secret_in_zip_bytes(blob, value):
                out[label].append(arn)
    return {label: tuple(v) for label, v in out.items()}


def edge_current_version(clients) -> str:
    """CloudFront **当前关联**的 origin-request Lambda 版本号。

    与 `verify_deployed_edge.sh` ① / `verify_deployed_components._edge_deployed_source` 同一
    规则：**不按"版本号最大"挑**。刚 `cdk deploy` 完但复制还没铺开、或改了代码没重部分发时，
    最大版本号与线上真正在跑的不是一回事，而这道断言的全部意义就是"线上跑的是不是这份 config"。

    分发 ID 从 router 栈的 CfnOutput 取（config.ini 只放输入，不放部署产物）。
    """
    rcfg = configparser.ConfigParser(interpolation=None)
    rcfg.read(_SITE_BUILDER.parent / "router" / "config.ini", encoding="utf-8")
    if not rcfg.sections():
        raise SystemExit("router/config.ini 读不到任何段——configparser 对缺失文件是静默的，"
                         "再往下跑会拿空栈名去问 CloudFormation。先确认路径与 cwd。")
    stack = rcfg["CDK"]["stack_name"].split("#")[0].strip()
    outs = clients["cloudformation"].describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    dist = next((o["OutputValue"] for o in outs if o["OutputKey"] == "DistributionId"), "")
    if not dist:
        raise SystemExit(f"栈 {stack} 没有 CfnOutput DistributionId——router 栈没部？")
    assoc = (clients["cloudfront"].get_distribution_config(Id=dist)["DistributionConfig"]
             ["DefaultCacheBehavior"].get("LambdaFunctionAssociations", {}).get("Items", []))
    arns = [a["LambdaFunctionARN"] for a in assoc if a.get("EventType") == "origin-request"]
    if len(arns) != 1 or not arns[0].rsplit(":", 1)[-1].isdigit():
        raise SystemExit(f"origin-request 关联的不是恰好一个编号版本：{arns}——"
                         f"Lambda@Edge 必须关联编号版本，这是探针前提")
    return arns[0].rsplit(":", 1)[-1]


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


def bucket_policy_statements(s3, bucket: str) -> list[dict]:
    """CDK bootstrap 桶的 bucket policy → 语句列表；无策略时 `[]`。

    **为什么必须单独有这一层**：`SimulatePrincipalPolicy` 不纳入 resource-based policy
    （对 role 根本不支持模拟它），而 S3 bucket policy 单独就能授权读写这个桶里的对象。
    3c-final 之后 asset 里已经没有私钥了，这一层要防的换成了**写**那一侧：Edge 的部署产物
    就在这个桶里，能改它的人等于能换掉 verifier，也就是能自己定义谁是谁。有人往桶上加一条
    Allow 时 A 那一层会全绿，只有这份快照能咬住。返回 `[]` 时随后会被比成"少了语句" ⇒ 红，
    所以整条 policy 被删也咬得住。
    """
    from botocore.exceptions import ClientError
    try:
        return policy_statements(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        return []


def merge_allowed(base: dict[str, str], extra: dict[str, str]) -> None:
    """把一腿的逐资源判定并进累积结果：**allowed 粘住**。

    裸 `dict.update` 在多腿下是错的：后一腿（DIGEST）对同一个 `动作|资源` 判
    implicitDeny 时会把前一腿（RAW）的 allowed 覆盖掉——**加一腿反而制造出一个新的
    假绿**。"任一 MessageType 下能签就是能签"，所以并集的方向只能是 allowed 优先。
    """
    for key, decision in extra.items():
        if base.get(key) != "allowed":
            base[key] = decision


def simulate(iam, principal_arn: str,
             t: Targets) -> tuple[dict[str, str], bool, set[tuple[str, str]]]:
    """分腿调用：函数类资源一组、其余一组，`kms:Sign` 的每个额外 `MessageType` 各一组。

    分组不是为了省钱，是为了不产生大量无意义的 (动作, 资源) 组合——一次调用的
    响应体是 资源数 × 动作数，而 `ssm:*` / `kms:*` 对 Lambda ARN、`lambda:*` 对 KMS key ARN
    都是纯噪音。

    第二组带 `ContextEntries=KMS_CONTEXT`：auth / panel 的 `kms:Sign` 语句上有
    `kms:SigningAlgorithm` 与 `kms:MessageType` 两个 StringEquals，不喂上下文时模拟器判
    "缺上下文"⇒ 平台自己那条必需的 grant 会从结果里消失、正向控制假红。喂进去的值是
    spec §11.5 固定的合同值（`session_kms` 的两个常量，不手抄）。

    **`kms:Sign` 还要按 `KMS_MESSAGE_TYPES` 的其余取值各跑一腿**（今天就是 DIGEST 一腿，
    只对 CMK 这几个资源）。理由见 `KMS_MESSAGE_TYPES`：PKCS#1 v1.5 下 DIGEST 路签出的
    字节与 RAW 路相同，所以一条只允许 DIGEST 的语句同样是完整的冒充能力，而它在 RAW
    上下文下评估成 implicitDeny ⇒ 只跑一腿的闸门会把持有者报成"不能签"。多腿的判定
    用 `merge_allowed` 取并集。

    返回三项：逐资源判定、`missing`（principal 级的 bool，喂 `facts` 那个笼统计数，
    只报 delta 不参与红绿）、`pairs`（item 级的判不出集合，**新成员即红**）。
    两者都要：前者是环境事实，后者才是判据。
    """
    out: dict[str, str] = {}
    missing = False
    pairs: set[tuple[str, str]] = set()
    legs: list[tuple[tuple[str, ...], list[str], list[dict] | None]] = [
        (ACTIONS_FUNCTION, t.function_resources(), None),
        (ACTIONS_OTHER, t.other_resources(), KMS_CONTEXT),
    ]
    legs += [(A_KMS_SIGN, sorted(t.kms_keys.values()), kms_context(mt))
             for mt in KMS_MESSAGE_TYPES[1:]]
    for actions, resources, context in legs:
        if not resources:
            continue
        extra = {"ContextEntries": context} if context else {}
        for page in iam.get_paginator("simulate_principal_policy").paginate(
                PolicySourceArn=principal_arn, ActionNames=list(actions),
                ResourceArns=resources, **extra):
            merge_allowed(out, decisions_from_simulation(page["EvaluationResults"]))
            missing = missing or missing_context_in(page["EvaluationResults"])
            pairs |= undecided_pairs(page["EvaluationResults"])
    # 某一腿判 allowed 的项**不是**"判不出"：另一腿在它上面缺上下文也改不了这件事。
    # 不滤掉的话，一个已经确定能签的 (动作, 资源) 会同时进 coverage 成员，
    # 方向是假红，但那种红同样会训练出"红了就更新基线"。
    pairs = {(action, resource) for action, resource in pairs
             if out.get(f"{action}|{resource}") != "allowed"}
    return out, missing, pairs


def canonical_json(text: str) -> str:
    """policy 文本的规范化：解析再按排序键紧凑序列化。

    key policy 的原文来自 `GetKeyPolicy`，AWS 返回的空白与键序不保证稳定 ⇒ 直接对原文取指纹
    会把格式抖动误报成漂移，而反复的假红会训练出无脑更新基线。
    """
    return json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))


def panel_role_name(path: Path | None = None) -> str:
    """panel 执行角色的名字 = `panel/deploy_panel.py` 的 `ROLE_NAME`（真源在那边）。

    手抄的副本在 panel 改角色名时不会红，正向控制会盯着一个不存在的角色，症状是
    "panel 缺 kms-sign"这种假红。
    """
    return _module_constant(path or PANEL_DEPLOY_PY, "ROLE_NAME")


def measure(region: str, *, workers: int = 4) -> dict:
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

    # ---- KMS 层：每把会话签名 CMK 自己的快照（3c-final）----
    # `session_kms` 在这里才 import（它 import session ⇒ 要 cryptography）：只有实测路径需要
    # 取公钥并做四项校验，`--from-dump` 与全部纯函数路径都不该被这个包卡住。
    import session_kms
    session_keys = load_session_keys(CONFIG_PATH)
    refs = key_refs(session_keys, KEY_FAMILIES)
    kms = clients["kms"]
    kms_section: dict = {}
    spki_b64_by: dict[str, str] = {}
    for ref in refs:
        der, fp = session_kms.describe_public_key(kms, ref.key_arn)   # 形态四项在这里就过了
        if fp != ref.spki_sha256:
            raise SystemExit(
                f"闸门硬失败：{ref.kid} 的 KMS 公钥指纹 {fp} != config 的 {ref.spki_sha256}——"
                "config.ini 指的不是这把 key；不出结论也不写基线")
        meta = kms.describe_key(KeyId=ref.key_arn)["KeyMetadata"]
        policy = kms.get_key_policy(KeyId=ref.key_arn, PolicyName="default")["Policy"]
        # grant 逐条指纹化：`GranteePrincipal` 是带账号 ID 的 ARN（仓库红线，不进基线原文），
        # 而 `Operations` / `Constraints` 决定这条 grant 到底给了什么。三者一起进指纹。
        grants = [principal_fingerprint(json.dumps(
                      [g.get("GranteePrincipal"), sorted(g.get("Operations", [])),
                       g.get("Constraints", {})], sort_keys=True))
                  for page in kms.get_paginator("list_grants").paginate(KeyId=ref.key_arn)
                  for g in page["Grants"]]
        kms_section[ref.kid] = {
            "arn_fp": principal_fingerprint(ref.key_arn),
            "key_policy_fp": principal_fingerprint(canonical_json(policy)),
            "key_spec": meta["KeySpec"], "key_usage": meta["KeyUsage"],
            "spki_sha256": fp, "grants": sorted(grants)}
        spki_b64_by[f"{ref.family}:{ref.kid}"] = session_kms.spki_b64(der)
    # login-flow 的值**只进扫描输入、不进 kms_keys**：它不是会话签名 key（读到它签不出会话），
    # 混进冒充面的目标集合会让那个数字凭空变大。这条刻意的排除由
    # test_login_flow_secret_is_deliberately_absent_from_the_key_enumeration 正向断言。
    login_flow_value = clients["ssm"].get_parameter(
        Name=session_keys.login_flow_secret_param, WithDecryption=True)["Parameter"]["Value"]
    scan_values = {**spki_b64_by, LABEL_LOGIN_FLOW: login_flow_value}
    facts: dict[str, object] = {}

    aliases = function_aliases(lam, all_functions)
    versions = function_versions(lam, all_functions)

    # ---- Edge 产物：只看 CloudFront **当前关联**的版本 + **当前** asset ----
    # 3c-final 之后产物里只有公钥，历史版本不再是负债 ⇒ 不扫历史（那条"跳过历史扫描"的旗标
    # 连带它"扫描不完整"的岔路一起删掉了）。这一段产出三条硬断言的输入，不落 facts。
    current_version = edge_current_version(clients)
    edge_code_by = edge_code_arns_carrying_keys(
        clients, EDGE_ORIGIN_REQUEST_FN, fn_arn(EDGE_ORIGIN_REQUEST_FN),
        (current_version,), scan_values)
    asset_bucket, asset_key = edge_asset_location(clients, EDGE_ORIGIN_REQUEST_FN)
    blob = clients["s3"].get_object(Bucket=asset_bucket, Key=asset_key)["Body"].read()
    asset_by = {label: ([asset_key] if secret_in_zip_bytes(blob, v) else [])
                for label, v in scan_values.items()}
    assert_edge_artifacts(edge_code_by, asset_by,
                          site_kids=[r.kid for r in refs if r.family == "site"],
                          console_kids=[r.kid for r in refs if r.family == "console"])
    print(f"Edge 当前关联版本 {current_version}：site 公钥齐、无 console 公钥、无 login-flow 值",
          file=sys.stderr)

    targets = Targets(
        platform_functions=tuple(fn_arn(n) for n in platform),
        site_functions=tuple(fn_arn(n) for n in sites),
        kms_keys={r.kid: r.key_arn for r in refs},
        login_flow_parameter=(f"arn:aws:ssm:{region}:{account}:parameter"
                              f"{session_keys.login_flow_secret_param}"),
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

    # bootstrap 桶的 bucket policy：模拟器看不见这条通道，而 Edge 的部署产物就在这个桶里。
    bucket_stmts = bucket_policy_statements(clients["s3"], asset_bucket)
    rp["bootstrap_bucket"] = sorted({canonical_statement_fp(s, account=account)
                                    for s in bucket_stmts})
    # 原文只进 stdout 与 /tmp 快照，**不进基线**（Principal 是带账号 ID 的角色 ARN）。
    rp["bootstrap_bucket_texts"] = {canonical_statement_fp(s, account=account):
                                    canonical_statement_text(s, account=account)
                                    for s in bucket_stmts}
    print(f"bootstrap 桶 {len(bucket_stmts)} 条 bucket policy 语句", file=sys.stderr)

    listing = list_principals(iam)
    principals = listing["principals"]
    policy_docs, managed_versions = listing["policy_docs"], listing["managed_versions"]

    # ---- B：IAM 写的**纯静态文本快照**（不进模拟器）--------------------------
    # 只记真正贡献了相关语句的托管策略版本：账号里实测有 300 份，全记进基线会让 AWS
    # 每更新任意一份都红一次，而那种噪音会训练出无脑更新基线。
    iam_stmts: dict[str, list[str]] = {}
    boundaries: dict[str, dict] = {}
    stmt_texts: dict[str, str] = {}
    used_policies: dict[str, str] = {}

    def _record(st: dict) -> str:
        sfp = canonical_statement_fp(st, account=account)
        stmt_texts[sfp] = canonical_statement_text(st, account=account)
        return sfp

    for p in principals:
        fp = principal_fingerprint(p["arn"])
        fps = set()
        for src_arn, st in p["statements"]:
            if not is_relevant_iam_statement(st):
                continue
            fps.add(_record(st))
            if src_arn is not None:
                used_policies[principal_fingerprint("policy:" + src_arn)] = \
                    managed_versions[src_arn]
        if fps:
            iam_stmts[fp] = sorted(fps)
        if p["boundary_arn"]:
            doc, ver = resolve_managed_policy(iam, p["boundary_arn"],
                                              docs=policy_docs, versions=managed_versions)
            pol_fp = principal_fingerprint("policy:" + p["boundary_arn"])
            boundaries[fp] = {"policy_fp": pol_fp,
                              "stmt_fps": sorted({_record(st)
                                                  for st in policy_statements(doc)})}
            # boundary 本身也是一份托管策略 ⇒ 它的版本同样要能解释红。
            used_policies[pol_fp] = ver
    print(f"IAM 写静态快照：{len(iam_stmts)} 个 principal / "
          f"{sum(len(v) for v in iam_stmts.values())} 条语句；"
          f"{len(boundaries)} 个 principal 有 permissions boundary；"
          f"记了版本的托管策略 {len(used_policies)} 份", file=sys.stderr)

    print(f"账号 {account} / 区 {region}：平台函数 {len(platform)}、站点函数 "
          f"{len(sites)}、待模拟 principal {len(principals)} × {SIM_LEGS_PER_PRINCIPAL} 腿"
          f"（函数类 / 其余 / kms:Sign 的 MessageType "
          f"{'+'.join(KMS_MESSAGE_TYPES)}）；"
          f"探测资源 {len(targets.function_resources()) + len(targets.other_resources())} 个"
          f"（含 alias {sum(len(v) for v in targets.alias_arns.values())}、"
          f"版本 {sum(len(v) for v in targets.version_arns.values())}）；"
          f"会话签名 CMK {len(kms_section)} 把",
          file=sys.stderr)

    observed: dict[str, dict] = {}
    failures: list[str] = []
    n_missing = 0
    # item 级的判不出集合：成员是 (principal, 动作等价类, 资源类) 的指纹。
    # `n_missing` 那个 principal 级计数继续留作环境事实（只报 delta），红绿看这个。
    undecided: set[str] = set()

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        # **每线程独立 client**：共享一个 client 并发用会让一部分请求跳过证书校验
        # （实测 12/40 次未校验；顺序执行与每线程独立都是 0）。
        futs = {pool.submit(lambda a: simulate(thread_iam_client(region), a, targets),
                            p["arn"]): p for p in principals}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            p = futs[fut]
            try:
                decisions, missing, pairs = fut.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{p['name']}: {type(exc).__name__}: {exc}")
                continue
            n_missing += bool(missing)
            # 折成成员指纹。放在下面 `if grants:` 的**外面**——一个 principal 可能一条
            # grant 都没有却有判不出的项，而那正是最该盯住的那种（条件哪天放宽就是新 grant）。
            undecided |= undecided_members(p["arn"], pairs, targets)
            grants = grants_from_decisions(decisions, targets)
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

    # ---- 窗口两端一致性复查：枚举(T1) → 逐个模拟(T2) → 复查(T3)，窗口约 10 分钟 ----
    # B 组是 T1 抄下来的静态语句，A 组是 T2 模拟出来的判定。窗口内有人改了某个
    # principal 的策略、或把同名角色删了重建，这一份快照就同时描述两个时刻，而
    # 「B 里没有这条 IAM 写语句」与「这条语句是 T1 之后才加的」在输出上一模一样。
    # 上一个 `failures` 只咬住"模拟时角色已经不在了"这一种 churn，咬不住这一类。
    #
    # **这不是理论风险，实测发生过**：2026-08-27 那次写基线的运行，窗口内有两条
    # `PutRolePolicy`（CloudTrail 可查），只是恰好落在既不进 A 也不进 B 的角色上
    # ⇒ 值没错，但"这是一个时刻的快照"这句话当时是假的。
    #
    # 复查的代价是再做一次 `GetAccountAuthorizationDetails`（实测约 1.5 分钟）。
    #
    # **它声称的东西比"原子"窄，两处都别读过头**（Codex 第八轮）：
    #   ① 只覆盖 **principal 层**——函数清单、alias、resource policy、asset 各自在自己
    #      的时刻测得，跨层没有任何一致性保证；
    #   ② 只能证明**窗口两端相等**，证明不了中间没变过：改了又改回来、枚举后新建又在
    #      复查前删除、以及单次枚举自己分页那 ~90 秒内的变化，都不可见（见
    #      `enumeration_drift` 的 docstring，三个盲区各有一条钉住它们的用例）。
    # 所以它是一道**持久漂移**闸门，不是原子快照的证明。
    drift = enumeration_drift(principals, list_principals(iam)["principals"])
    if drift:
        detail = "；".join(f"{k}: {', '.join(v[:5])}"
                          + (f" 等 {len(v)} 个" if len(v) > 5 else "")
                          for k, v in drift.items())
        raise SystemExit(
            f"本轮观测作废——枚举与模拟之间 principal 层发生了持久变化，"
            f"这份快照会同时描述两个时刻的账号，不能出结论也不能写基线。"
            f"漂移：{detail}。"
            f"（站点部署/下线会产生 `site-rt-*` 的增减；账号里另一套 workload 会同名"
            f"重建角色。等账号静默下来重跑即可——实测 7 天里 96.6% 的 10 分钟窗口是"
            f"干净的。）")
    print(f"复查枚举：principal 层的授权投影**两端一致**（{len(principals)} 个；"
          f"只覆盖 principal 层、只保证两端相等，见 enumeration_drift 的三个盲区）",
          file=sys.stderr)

    facts["principals_with_missing_context"] = n_missing
    return {# 快照带 schema：`--from-dump` 要能拒绝旧形态的快照
            # （缺分节时比较器整层跳过，输出与"真的没漂移"逐字相同）。
            "schema": BASELINE_SCHEMA,
            "principals": observed, "resource_policies": rp, "facts": facts,
            "coverage": {"undecided_items": sorted(undecided)},
            # `texts` 只进 stdout 与 --dump-observed 的产物，**不进基线**。
            "iam_write": {"statements": iam_stmts, "boundaries": boundaries,
                          "managed_versions": used_policies, "texts": stmt_texts},
            "kms": kms_section,
            # 四条正向控制的角色名。auth / panel 那两条是签名侧（3c-final）：
            # panel 的名字从 deploy_panel.py 的 ROLE_NAME 读，不手抄。
            "required": {"edge": edge_role_name, "deployer": DEPLOYER_EXEC_ROLE,
                         "auth": AUTH_SERVICE_ROLE, "panel": panel_role_name()}}


def load_baseline(path: Path) -> dict:
    """读基线并**硬校验 schema**。3c-final 起**没有迁移通道**。

    两条语义：
    · **文件不存在**不是"与空基线比"，而是"这一轮只能生成第一份基线"。返回一个空壳并在
      stderr 说清楚；`main()` 在不带 `--update-baseline` 时会硬退出——否则每个 principal
      都会被报成"新增"，一屏红而真因只是没有基线（那种红会训练出"红了就更新基线"）。
      基线含单账号实测、**不随资产分发**（ADR 0005），所以采用者首跑就是这一步。
    · **schema 不是当前版本**⇒ 硬失败并让操作者删掉重生成。不做 3/4/5 → 6 的迁移：旧形态里
      根本没有 KMS 分节可比，"迁移"出来的只会是一份半真半假的基线。
    """
    if not path.exists():
        print(f"（没有基线 {path}：本次只能 --update-baseline 生成第一份，不能出结论——"
              "基线含单账号实测、不随资产分发，采用者首跑就是这一步）", file=sys.stderr)
        return {"schema": BASELINE_SCHEMA, "principals": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != BASELINE_SCHEMA:
        raise SystemExit(
            f"基线 schema 是 {data.get('schema')}，脚本要 {BASELINE_SCHEMA}。3c-final 起没有"
            "迁移通道（旧形态没有 KMS 层可比）：删掉这个文件，跑一次 --update-baseline 重生成。")
    # coverage 成员必须是可分解形态。哈希形态混进来（手改、或把旧 schema 的文件改个版本号）
    # 会让退役声明静默失效——照红、与没修一样。所以在读入时就拒。
    items = (data.get("coverage") or {}).get("undecided_items")
    if items is not None:
        _check_shape(items, _list_of_undecided_items,
                     path="coverage.undecided_items", where=f"基线 {path}")
    return data


def _nonempty_str(v) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _plain_int(v) -> bool:
    # bool 是 int 的子类；facts 里放个 True 当计数要拒。
    return isinstance(v, int) and not isinstance(v, bool)


def _list_of_str(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _list_of_undecided_items(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and UNDECIDED_ITEM_RE.fullmatch(x)
                                       for x in v)


# 一份**权威**观测必须有的分节、**内层键**与类型。**递归默认拒绝**：
# 规格里没写的键一律不放行。
#
# 为什么必须递归到内层（Codex 第六轮 blocker）：上一版只要求 `coverage` /
# `resource_policies` 是 dict，于是两个实测 false-green——
#   ① `coverage = {}`         ⇒ `.get("undecided_items")` 是 None ⇒ 基线里 774 项
#      判不出的全被记成 improvements，`rep.ok == True`；
#   ② `resource_policies` 缺 `sites` ⇒ 逐站点那层一个都不检查，`red={}` 且**零 note**，
#      输出与「真的没漂移」逐字相同。
#   ③ 同一个洞往下一层还有一次：`sites` 键在、但**某个站点**的 shape 截断成 `{}`
#      ⇒ 比较器 `shape.get("alias") or {}` 走空路径，那个站点一条 alias 都不比
#      （实测 `ok=True`、`site_policy_outliers=[]`、零 note）。所以 `platform`/`sites`
#      不能只声明「是 dict」，逐成员的三个桶也要在合同里。
# 恰好是这几层的原因：它们的比较器是**单向**的（消失=改善，或只遍历本次观测）。双向
# 的那些（B 的语句、boundary、bucket policy、platform 逐桶——消失也红）内层缺失会自己
# 红出来（实测 `iam_write = {}` 是 44+7 条红）。**规律：单向比较器的层必须由合同兜住
# 下限**；做成递归默认拒绝就不必逐层去记哪层是哪个方向，加新层时也不会漏。
#
# **不声称**的一件事：本合同只封「键缺失 / 类型不对」。`"sites": {}`（键在、一个成员
# 都没有）与「这个账号真的没有站点」在数据上无法区分，闸门不猜——那条要靠比较器的
# canonical 集合与部署验收（§9 的 3e）覆盖。
_POLICY_SHAPE: dict = {"alias": {"*": _list_of_str}, "version": _list_of_str,
                       "unqualified": _list_of_str}

BUNDLE_SHAPE: dict = {
    "schema": int,
    "principals": {"*": {"name": _nonempty_str, "arn": _nonempty_str,
                         "kind": _nonempty_str, "grants": _list_of_str}},
    "resource_policies": {"platform": {"*": _POLICY_SHAPE},
                          "sites": {"*": _POLICY_SHAPE},
                          "bootstrap_bucket": _list_of_str,
                          "bootstrap_bucket_texts": dict},
    # 3c-final：只剩这一个事实数字。密钥的物化位置不再是"事实"（私钥不出 KMS），
    # Edge 产物那三件事改成硬断言（`assert_edge_artifacts`）——它们不该有可比较的基线数字。
    "facts": {"principals_with_missing_context": _plain_int},
    # 成员必须是可分解形态（不是任意字符串）：写成哈希或带账号值都要在这里被拒。
    "coverage": {"undecided_items": _list_of_undecided_items},
    "iam_write": {"statements": dict, "boundaries": dict,
                  "managed_versions": dict, "texts": dict},
    # 3c-final：每把会话签名 CMK 一组。键是 kid（不是账号值）；ARN 与 key policy 只落指纹。
    "kms": {"*": {"arn_fp": _nonempty_str, "key_policy_fp": _nonempty_str,
                  "key_spec": _nonempty_str, "key_usage": _nonempty_str,
                  "spki_sha256": _nonempty_str, "grants": _list_of_str}},
    "required": {"edge": _nonempty_str, "deployer": _nonempty_str,
                 "auth": _nonempty_str, "panel": _nonempty_str},
}


def _spec_label(spec) -> str:
    return getattr(spec, "__name__", str(spec))


def _check_shape(value, spec, *, path: str, where: str) -> None:
    """按 `spec` 递归校验 `value`。**规格里没写的键一律拒**。"""
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            raise SystemExit(f"{where}：{path} 应该是 dict，实际是 "
                             f"{type(value).__name__}——空列表冒充空字典这类会让"
                             f"比较器静默走空路径")
        if "*" in spec:          # 通配层：键是指纹，逐成员按同一份子规格校验
            for member, mv in value.items():
                _check_shape(mv, spec["*"], path=f"{path}.{member}", where=where)
            return
        for key, sub in spec.items():
            if key not in value:
                raise SystemExit(
                    f"{where}：观测缺 {path}.{key} —— 缺一层的症状与「那一层没有漂移」"
                    f"一模一样（比较器拿到 None 就整层跳过，单向比较器还会把它记成"
                    f"改善）。不许拿它出闸门结论或改写基线；重新跑一次完整的 "
                    f"--dump-observed。")
            _check_shape(value[key], sub, path=f"{path}.{key}", where=where)
        unknown = sorted(set(value) - set(spec))
        if unknown:
            raise SystemExit(
                f"{where}：{path} 出现规格外的键 {unknown}——新分节必须同时进 "
                f"BUNDLE_SHAPE，否则它就是下一个「截断了也看不出」的层（默认拒绝）")
        return
    if isinstance(spec, type):
        if not isinstance(value, spec):
            raise SystemExit(f"{where}：{path} 应该是 {spec.__name__}，实际是 "
                             f"{type(value).__name__}")
        return
    if not spec(value):         # 谓词（_nonempty_str / _plain_int / _list_of_str）
        raise SystemExit(f"{where}：{path} 不满足 {_spec_label(spec)}"
                         f"（实际 {type(value).__name__}: {str(value)[:40]!r}）")


def check_bundle_complete(bundle: dict, *, where: str) -> None:
    """出闸门结论 / 写基线之前，校验观测是**完整**的。

    这是一条 fail-closed 合同：**不完整的观测不许变成一个权威的绿。**
    """
    missing = [k for k in BUNDLE_SHAPE if k not in bundle]
    if missing:
        raise SystemExit(
            f"{where}：观测缺分节 {missing} —— 缺一节的症状与「那一层没有漂移」一模一样"
            f"（比较器拿到 None 就整层跳过），不许拿它出闸门结论或改写基线。"
            f"重新跑一次完整的 --dump-observed。")
    for key, spec in BUNDLE_SHAPE.items():
        _check_shape(bundle[key], spec, path=key, where=where)
    unknown = sorted(set(bundle) - set(BUNDLE_SHAPE))
    if unknown:
        raise SystemExit(
            f"{where}：观测里出现规格外的分节 {unknown}——新分节必须同时进 BUNDLE_SHAPE，"
            f"否则它就是下一个「截断了也看不出」的层（默认拒绝）")


def write_dump(path: Path, bundle: dict) -> None:
    """`--dump-observed` 的产物**按 0600 原子落盘**（复审二轮 P2-3 + 三轮 P2）。

    它不是密钥，但是完整的账号拓扑：真实 principal 名与 ARN、grant 清单、归一化前的 IAM 语句原文。
    `write_text` 按 umask 落成 0644；`os.open(..., 0o600)` 对已有文件不生效且跟随 symlink。
    写法与 `_session_mint.save_token` 共用 `_secure_write.write_private_text`（理由见那个模块）。
    """
    write_private_text(Path(path), json.dumps(bundle, ensure_ascii=False, indent=2) + "\n")


def load_dump(path: Path) -> dict:
    """`--from-dump` 的快照。**schema 与完整性都要校验。**

    旧快照缺新分节（coverage / iam_write），拿它当闸门结果会把"这些分节都空"当成
    "没有漂移"——那是最坏的一种 false-green，因为输出与真的没漂移逐字相同。
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    got = data.get("schema")
    if got != BASELINE_SCHEMA:
        raise SystemExit(
            f"快照 {path} 的 schema 是 {got}，脚本要 {BASELINE_SCHEMA}——"
            f"重新跑一次 --dump-observed，不要拿旧快照当闸门结果")
    check_bundle_complete(data, where=f"快照 {path}")
    return data


def wants_baseline(args) -> bool:
    """只有"要出闸门结论"或"要写基线"时才需要读基线。

    `--dump-observed` 单独用时是**纯观测**：基线还是旧 schema（或还不存在）时，若在发
    AWS 调用前就硬校验，dump 根本产不出来——**而那次 dump 正是重建基线的输入**。
    这是一个真实踩过的死锁。
    """
    return not (args.dump_observed and not args.update_baseline)


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
         "note": ("account trust boundary baseline —— principal 与策略语句只存指纹；coverage 成员是"
                  "「principal 指纹|动作等价类|资源类,…」，资源类名来自脚本词表（sites / "
                  "kms-key:<kid> / login-flow-param / fn:<平台函数名> …），不含账号值"
                  "（仓库红线：真实账号值/角色名/ARN 不进被跟踪文件）。见 "
                  "docs/security/account-trust-boundary.md 与 "
                  "scripts/verify_account_trust_boundary.py。"),
         # platform-overbroad：平台自己的角色，但这条授权它并不需要
         # （典型的一个：跑不可信站点依赖安装的 CodeBuild 角色，CDK 自动给了它
         #  整个 bootstrap 桶的读权限）。
         "categories": ["platform", "platform-overbroad", "admin", "break-glass",
                        "cdk-admin", "cdk-readonly", "unrelated-workload",
                        "unclassified"],
         "facts": bundle["facts"],
         # 判不出的项按**成员**存（新成员即红）。principal 级的那个笼统计数在 facts 里，
         # 只报 delta——它会随账号里任何一条带 Condition 的新策略变动。
         "coverage": {"undecided_items": bundle["coverage"]["undecided_items"]},
         # 3c-final：会话签名 CMK 的快照（key policy / grants / 公钥指纹只落指纹或 hex，
         # key ARN 本身含账号 ID ⇒ 只落 arn_fp）。
         "kms": bundle["kms"],
         "principals": principals,
         # B：IAM 写的纯静态文本快照。**只落指纹**——语句原文（`texts`）刻意不写，
         # 它含账号内标识（Principal 是带账号 ID 的角色 ARN）。
         "iam_write_statements": bundle["iam_write"]["statements"],
         "permissions_boundaries": bundle["iam_write"]["boundaries"],
         "managed_policy_versions": bundle["iam_write"]["managed_versions"],
         # 站点函数只落**规范形态 + legacy 豁免名单**，不落逐站点条目：
         # 逐站点会让每次建站/下线都改基线，而"新增即红"依赖基线是稳定的。
         "resource_policies": {
             "platform": bundle["resource_policies"]["platform"],
             **site_shape_canonicals(bundle["resource_policies"]["sites"]),
             # 只落指纹；`bootstrap_bucket_texts` 刻意**不写**（语句原文含账号内标识）。
             "bootstrap_bucket": bundle["resource_policies"]["bootstrap_bucket"],
         }},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--update-baseline", action="store_true",
                    help="把当前实测写回基线（category 保留已有标注，新条目为 "
                         "unclassified，需人工标注）")
    ap.add_argument("--dump-observed", metavar="PATH",
                    help="把带**真实名字**的实测清单写到 PATH（分类基线时要看名字）。"
                         "产物含账号内标识，**不要提交进仓库**——落 .scratch/（gitignored；/tmp 会被 "
                         "macOS 清理，⑩ 曾因此丢掉 ⑥ 的快照）。文件按 0600 写。")
    ap.add_argument("--from-dump", metavar="PATH",
                    help="不发 AWS 调用，直接读 --dump-observed 的产物。"
                         "用于分类/复核，省掉重跑模拟。"
                         "**注意它是快照**：拿旧快照当闸门结果会得出过期结论。")
    ap.add_argument("--classify", metavar="PATH",
                    help="从 PATH 读 {角色名: category} 映射，据此标注基线的 "
                         "category（配合 --update-baseline）。映射文件同样"
                         "含真实名字，**不要提交**。")
    ap.add_argument("--new-key", "--new-kid", action="append", metavar="LABEL", dest="new_key",
                    help="本轮**首次出现**的密钥标签（可重复）。LABEL ∈ 已配置 kid ∪ "
                         "{login-flow}。它对应的 grant 在此前已能签某把会话密钥的 "
                         "principal 上单列为迁移，不算扩权；此前不能签的 principal 上仍红；"
                         "未声明的一律红。kid 的增减同时决定 kms 分节比较的口径。"
                         "`--new-kid` 是本参数的别名（3c-1A 的旧名）。")
    ap.add_argument("--retire-key", action="append", metavar="LABEL", dest="retire_key",
                    help="本轮**退役**的密钥标签（可重复）。platform 类 principal "
                         "丢掉它对应的 grant 计入迁移不红；同一轮丢的其它 grant 照样红。"
                         "轮转 runbook 的最后一步（--retire-key site-rs-v1 …）用它。"
                         "**kid 的合法来源是 config ∪ 基线**——退役时 config 已经不含它了，"
                         "基线是它曾经存在过的记录。")
    args = ap.parse_args(argv)
    # 标签打错一个字的后果是"以为声明了、其实没有"——静默的，所以在任何比较之前就校验。
    # 位置在所有分支**之上**，只读 config、不发 AWS 调用 ⇒ `--from-dump` 那条也一样覆盖。
    declared_labels = tuple(args.new_key or ()) + tuple(args.retire_key or ())
    if declared_labels:
        cfg_keys = load_session_keys(CONFIG_PATH)
        # 基线只在这里读一次原始 JSON（不走 load_baseline 的 schema 硬校验：那条会在基线不存在
        # 或形态旧时把本校验挡死，而这里只需要"这个 kid 曾经存在过"这一个事实）。读不到就只认 config。
        try:
            raw_baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw_baseline = {}
        check_migration_labels(declared_labels,
                               known_kids=configured_kids(cfg_keys) + baseline_kids(raw_baseline))
    # **纯 dump 模式不读基线**：基线还是旧 schema（或还不存在）时，在这里硬校验就会把 dump
    # 挡死——而那次 dump 正是重建基线的输入。
    baseline = load_baseline(BASELINE_PATH) if wants_baseline(args) else {}
    # **没有基线且不是在生成基线** ⇒ 硬退出。与空基线比较会把每个 principal 都报成"新增"，
    # 一屏红而真因只是没有基线，那种红会训练出"红了就更新基线"。
    if wants_baseline(args) and not args.update_baseline and not BASELINE_PATH.exists():
        raise SystemExit(
            f"没有基线 {BASELINE_PATH}，先 --update-baseline 生成第一份再出结论"
            "（基线含单账号实测、不随资产分发；生成时会先打印一遍比较报告）。")

    if args.from_dump:
        bundle = load_dump(Path(args.from_dump))
        print(f"（--from-dump：读的是快照 {args.from_dump}，未发 AWS 调用。"
              f"**快照里没有 Edge 产物那三条硬断言的信息**（它们刻意不进 facts / BUNDLE_SHAPE），"
              f"所以「当前 Edge 版本带齐 site 公钥 / 不含 console 公钥 / 不含 login-flow 值」"
              f"在本次运行里不成立——它们只在实测路径上评估。）", file=sys.stderr)
    else:
        # 声明（--new-key/--retire-key）**不进观测**：A6 的归一化在比较时对两侧做，
        # 所以同一份快照可以按不同声明重比（复审 P1-1 之前快照里存着按声明算的反事实）。
        bundle = measure(args.region, workers=args.workers)

    observed = bundle["principals"]
    print(f"\n具备至少一项敏感授权的 principal：{len(observed)}")
    for _fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        print(f"  [{p['kind'][0]}] {p['name']:62} {sorted(p['grants'])}")
    print(f"\n事实：{json.dumps(bundle['facts'], ensure_ascii=False)}")

    if args.dump_observed:
        write_dump(Path(args.dump_observed), bundle)
        print(f"\n实测清单（含真实名字，勿提交；已按 0600 落盘）已写入 {args.dump_observed}")
        if not args.update_baseline:
            # **纯观测**：不与基线比较，退出码不代表闸门结论。分开是刻意的——
            # 把"产出用于分类/迁移的快照"与"出闸门结论"混在一条命令里，迁移期就会
            # 因为基线还是旧 schema 而根本产不出快照。
            print("\n（--dump-observed：**纯观测模式**，未与基线比较；"
                  "退出码不代表闸门结论。要出结论请不带 --dump-observed 再跑一次。）",
                  file=sys.stderr)
            return 0

    if args.update_baseline:
        check_bundle_complete(bundle, where="--update-baseline")
        classify = json.loads(Path(args.classify).read_text(encoding="utf-8")) \
            if args.classify else {}
        if classify:
            for p in observed.values():
                if p["name"] in classify:
                    p["category"] = classify[p["name"]]
        # **先渲染一遍比较报告，再写基线**（3c-1B-G A6）。原先这条分支在
        # `compare_to_baseline` 之前就 return ⇒ 写基线那条路**什么都不打印**，
        # "这一次到底接受了什么"只存在于操作者的记忆里。spec §11.8.7 反对人工放行的
        # 核心理由正是这个：接受的内容必须留痕。报告只打印、不改退出码——这条命令的
        # 语义仍是"我知道并接受这些变化"。
        # **报告生成失败就不写**（复审 P1-2）：比较器主动拒绝（形态混杂、schema 4 基线配了
        # 没有 v4 指纹的快照…）意味着"接受了什么"根本没法看清；原先这里 `except SystemExit`
        # 打一句就照写，等于给普通闸门里的硬失败开了一条 --update-baseline 后门。
        print("\n── 即将被写进基线的变化（先看清再接受）"
              "──────────────────────────")
        preview = compare_to_baseline(
            observed, baseline, required=bundle["required"],
            resource_policies=bundle["resource_policies"], facts=bundle["facts"],
            coverage=bundle["coverage"], iam_write=bundle["iam_write"],
            kms=bundle["kms"],
            new_keys=tuple(args.new_key or ()), retired_keys=tuple(args.retire_key or ()))
        print(preview.render())
        write_baseline(bundle, baseline, BASELINE_PATH)
        print(f"\n已写入 {BASELINE_PATH}（新条目 category=unclassified，请人工标注）")
        return 0

    check_bundle_complete(bundle, where="出闸门结论")
    rep = compare_to_baseline(observed, baseline, required=bundle["required"],
                              resource_policies=bundle["resource_policies"],
                              facts=bundle["facts"],
                              coverage=bundle["coverage"],
                              iam_write=bundle["iam_write"],
                              kms=bundle["kms"],
                              new_keys=tuple(args.new_key or ()),
                              retired_keys=tuple(args.retire_key or ()))
    print("\n" + rep.render())
    # 处置文案由 RED_FIELDS 的第三列驱动（`dict.fromkeys` 去重且保序）：
    # 原先这里手抄了一遍字段名单，加红字段时最容易漏的就是这一处。
    for key in dict.fromkeys(k for name, _, k in RED_FIELDS if getattr(rep, name)):
        print("\n" + RED_MESSAGES[key])
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
