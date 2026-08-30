#!/usr/bin/env python3
"""3c 的冒充面探针：**迁到非对称签名之后**，账号内谁还能冒充任意用户。

**这不是闸门。** 闸门是 `verify_*`（漂移检测、有基线、会红）。本脚本是 3c 的
**量测工具**：它回答"3c 的收益边界在哪"，产出进
`docs/security/3c-impersonation-surface.json`（tracked，只有计数与指纹）与一份
可选的原始名字 dump（**gitignored**）。`docs/superpowers/specs/2026-08-28-
asymmetric-session-signing-spec.md` §1 的数字由本脚本产生。

## 为什么要单独有它（而不是直接读闸门基线）

闸门的 `replace-platform-code` 把"能替换平台代码"建模成**一个动作**
（`lambda:UpdateFunctionCode`）。那个模型两个方向都错，本脚本按
**动作等价类 × 资源等价类**重建：

- **过度声称**：对 Lambda@Edge 不成立。`UpdateFunctionCode` 只改未发布的
  `$LATEST`，而 CloudFront **必须**关联编号版本（CFN 文档原文："You must specify
  the ARN of a function version; you can't specify an alias or `$LATEST`"）
  ⇒ 光有它不改变正在执行的代码。同理对**站点函数**也不成立：M7 之后站点的
  Function URL 挂在 blue/green alias 上，改 `$LATEST` 不改变 alias 指向的版本。
- **同时少算**：至少漏三条等价路径——
  ① `UpdateFunctionCode(Publish=True)` 一次调用即改码即发版本，不需要单独的
     `PublishVersion`；
  ② `cloudformation:UpdateStack` 与 `CreateChangeSet`+`ExecuteChangeSet`（router
     栈**已关联** CFN service role 且**无 stack policy** ⇒ 调用方自己不需要
     `iam:PassRole`，CFN 会继续用那个 role）；
  ③ **劫持 signer 本身**：`site-auth-service` / `site-panel` 的 Function URL
     **无 qualifier**、部署脚本用裸 `update_function_code` ⇒ 服务的是 `$LATEST`，
     于是 `lambda:UpdateFunctionCode` 一个动作就是"在那个执行角色下跑任意代码"。
     3c 之后这两个角色持 `kms:Sign` ⇒ 这条路**既不需要攻击者自己有 `kms:Sign`，
     也不需要碰 Edge**。闸门今天记的 `replace-platform-code:site-auth-service`
     其实就是它，但 spec §1 的口径没把它算进冒充面。

⇒ 对 auth/panel 这类"Function URL 服务 `$LATEST`"的函数，单动作模型**恰好是对的**；
错的是把同一个模型套到必须关联编号版本的 Edge 与挂 alias 的站点函数上。

## 只读

只发 `sts:GetCallerIdentity`、`iam:ListRoles`/`ListUsers`、
`iam:SimulatePrincipalPolicy`、`lambda:GetFunction`、`cloudfront:ListDistributions`
/`GetDistributionConfig`。**不发任何写调用。**

## 三条实测坑（都花过时间）

1. **产物不要只放 `/tmp`。** 第一版的探针输出、人工核对过的 dump、RS256 原型全放
   `/tmp`，隔天被系统清理，spec 引的数字一度失去可复跑依据。**但"搬到 gitignored
   目录"只解决了 /tmp 清理，没解决可复现**——新 clone / 别的机器 / 外部复审都拿不到。
   所以本脚本自己是 tracked 的，脱敏聚合结果也是 tracked 的，只有名字留在 gitignored。
2. **别用闸门的 `list_principals` 做轻量枚举。** 它走
   `GetAccountAuthorizationDetails`，要把账号里 ~300 份托管策略的**完整文档**拉回来
   （B 层需要，本脚本不需要）：实测单页最慢 94 秒。只要 principal ARN 就用
   `ListRoles`+`ListUsers`（秒级）。
3. **`read_timeout` 不能取小值。** 30 秒会把 GAAD 变成超时→重试的死循环，
   表现与挂死一模一样（0% CPU、输出 0 字节）。"加超时防挂死"与"超时取太小造成假
   挂死"是同一枚硬币的两面。这里取 120 秒，并且 `python3 -u` + 逐步打点。

## 用法

**系统 `python3`**（`deployer/.venv` 的 CA 信任库是空的，每次 HTTPS 都会
`CERTIFICATE_VERIFY_FAILED`，症状读起来像网络故障）：

    # 反例自检，不碰 AWS、秒级——改过 classify() 必须先跑这个
    python3 site-builder/scripts/probe_impersonation_surface.py --self-test

    # 真机量测（只读，实测约 4-6 分钟），写 tracked 聚合 + gitignored 名字 dump
    python3 -u site-builder/scripts/probe_impersonation_surface.py \
        --write-evidence \
        --dump-observed docs/design/3c-spike/observed-impersonation-surface.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import configparser
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent                      # 仓库根（**不写绝对路径**）
GATE = _HERE / "verify_account_trust_boundary.py"
ROUTER_CONFIG = _ROOT / "router" / "config.ini"
EVIDENCE = _ROOT / "docs" / "security" / "3c-impersonation-surface.json"

# ---------------------------------------------------------------- 动作等价类
#
# **一种能力 = 一个动作等价类 × 一个资源等价类。** 这条形状是闸门里最重要的不变量，
# 本脚本沿用（`verify_account_trust_boundary.py` 的 `A_*` 注释记了它被违反过的
# 三次）。往任一维加成员时，同时在 `--self-test` 里加一条**只命中该新成员**的反例。

# 直接签。KMS 的 key policy 是权威的 ⇒ 这里量到的是 **identity policy 的上界**。
KMS_SIGN = ("kms:Sign",)
# 自助授权：改 key policy 或给自己发 grant，然后再签。
KMS_SELF_AUTHORIZE = ("kms:PutKeyPolicy", "kms:CreateGrant")
# 只为对照打印，不构成冒充能力（公钥不是秘密）。
KMS_READONLY = ("kms:GetPublicKey", "kms:DescribeKey")

# 在某个函数的执行角色下跑任意代码。
#   · `UpdateFunctionCode`：直接换码。
#   · `UpdateFunctionConfiguration`：可挂 Layer（Layer 里的模块能遮蔽 handler
#     import 的模块）⇒ 同样是任意代码执行。**这是上界口径的选择**：它还需要能
#     发布/读到一个 Layer，本脚本不追那一步，宁可高估也不漏报。
LAMBDA_CODE_EXEC = ("lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration")
LAMBDA_PUBLISH = ("lambda:PublishVersion",)
LAMBDA_CREATE = ("lambda:CreateFunction",)
CF_READ = ("cloudfront:GetDistributionConfig",)
CF_WRITE = ("cloudfront:UpdateDistribution",)
# router 栈已关联 CFN service role 且无 stack policy ⇒ 这两条都不需要 PassRole。
CFN_UPDATE = ("cloudformation:UpdateStack",)
CFN_CHANGESET = ("cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet")
IAM_PASSROLE = ("iam:PassRole",)

# ---------------------------------------------------------------- 能力标签
#
# `sign:*` = 能产生一个 verifier 会接受的签名；`edge:*` = 能改变 verifier 本身。
# 两类都是冒充，冒充面 = 并集。
SIGN_PREFIX = "sign:"
EDGE_PREFIX = "edge:"

S_KMS_DIRECT = "sign:kms-direct"
S_KMS_SELF = "sign:kms-self-authorize"
S_HIJACK_AUTH = "sign:hijack-auth-signer"
S_HIJACK_PANEL = "sign:hijack-panel-signer"
E_PUBLISH_THEN_ASSOCIATE = "edge:code+publish+associate"
E_PUBLISH_INLINE = "edge:code(Publish=True)+associate"
E_NEW_FUNCTION = "edge:new-function+associate"
E_CFN_UPDATE_STACK = "edge:cfn-update-stack"
E_CFN_CHANGE_SET = "edge:cfn-change-set"

ALL_LABELS = (S_KMS_DIRECT, S_KMS_SELF, S_HIJACK_AUTH, S_HIJACK_PANEL,
              E_PUBLISH_THEN_ASSOCIATE, E_PUBLISH_INLINE, E_NEW_FUNCTION,
              E_CFN_UPDATE_STACK, E_CFN_CHANGE_SET)

# ---------------------------------------------------------------- 候选缓解措施
#
# **"少算一个动作"与"这个措施值不值得做"是两个问题。** 旧口径拿
# `sign_only`（能签名但不能替换 Edge）当限制性 key policy 的收益判据，那是错的：
# 劫持 signer 那条路**不需要攻击者自己有 `kms:Sign`**（恶意代码是以 signer 角色的
# 身份调 KMS 的），所以 key policy 收不掉它。真正的判据是**边际收益**：
# 关掉这一组路径之后，有多少 principal **完全**离开冒充面。
MITIGATIONS: dict[str, tuple[str, ...]] = {
    # 限制性 KMS key policy（spec §1 的决策点、§11 未决项 2）
    "restrictive-kms-key-policy": (S_KMS_DIRECT, S_KMS_SELF),
    # 收窄谁能改 site-auth-service / site-panel 的代码与配置
    "harden-signer-code-update": (S_HIJACK_AUTH, S_HIJACK_PANEL),
    # 给 router 栈加 stack policy（今天**没有**，实测）
    "router-stack-policy": (E_CFN_UPDATE_STACK, E_CFN_CHANGE_SET),
    # 锁住 Edge 的 association / 换码那条直接链
    "lock-edge-association": (E_PUBLISH_INLINE, E_PUBLISH_THEN_ASSOCIATE,
                              E_NEW_FUNCTION),
}


@dataclass(frozen=True)
class Surface:
    """探针要打的资源集合。**全部靠发现，不硬编码**——distribution ID / 账号 ID /
    内部角色名都不许出现在被跟踪的源码里（仓库红线）。"""
    region: str
    kms_key: str            # 占位 ARN：3c 的两把 CMK 还不存在
    edge_fn: str
    auth_fn: str
    panel_fn: str
    new_fn: str             # 占位 ARN：给"新建函数再关联"那条路
    distribution: str
    stack: str
    edge_role: str
    # 载荷性前提：association 真的挂在**编号版本**上（不是 alias / $LATEST）
    edge_association_qualifier: str = ""

    def groups(self) -> tuple[tuple[list[str], list[str]], ...]:
        """按服务分组批量模拟。跨服务混在一条调用里会产生大量无意义的
        action×resource 组合（都是 implicitDeny），既慢又难读。"""
        return (
            (list(KMS_SIGN + KMS_SELF_AUTHORIZE + KMS_READONLY), [self.kms_key]),
            (list(LAMBDA_CODE_EXEC + LAMBDA_PUBLISH + LAMBDA_CREATE),
             [self.edge_fn, self.auth_fn, self.panel_fn, self.new_fn]),
            (list(CF_READ + CF_WRITE), [self.distribution]),
            (list(CFN_UPDATE + CFN_CHANGESET), [self.stack]),
            (list(IAM_PASSROLE), [self.edge_role]),
        )


def classify(allowed: frozenset[str], s: Surface) -> set[str]:
    """一个 principal 的 `"action|resource"` 允许集合 → 它持有的**能力标签**。

    **纯函数**，不碰 AWS ⇒ 反例可以在本文件里跑（`--self-test`）。这是本脚本唯一
    的判定逻辑；真机部分只负责把 `allowed` 填出来。
    """
    def ok(actions, resource: str) -> bool:
        return any(f"{a}|{resource}" in allowed for a in actions)

    labels: set[str] = set()

    if ok(KMS_SIGN, s.kms_key):
        labels.add(S_KMS_DIRECT)
    if ok(KMS_SELF_AUTHORIZE, s.kms_key):
        labels.add(S_KMS_SELF)
    # 劫持 signer：这两个函数的 Function URL 无 qualifier、服务 `$LATEST`
    # ⇒ 换码即刻生效，**不需要发版本、不需要碰 CloudFront**。
    if ok(LAMBDA_CODE_EXEC, s.auth_fn):
        labels.add(S_HIJACK_AUTH)
    if ok(LAMBDA_CODE_EXEC, s.panel_fn):
        labels.add(S_HIJACK_PANEL)

    # Edge：必须让 CloudFront 关联到攻击者的代码上。三类等价路径。
    if ok(CF_WRITE, s.distribution):
        if ok(LAMBDA_CODE_EXEC, s.edge_fn):
            labels.add(E_PUBLISH_INLINE)          # UpdateFunctionCode(Publish=True)
            if ok(LAMBDA_PUBLISH, s.edge_fn):
                labels.add(E_PUBLISH_THEN_ASSOCIATE)
        if (ok(LAMBDA_CREATE, s.new_fn) and ok(LAMBDA_PUBLISH, s.new_fn)
                and ok(IAM_PASSROLE, s.edge_role)):
            labels.add(E_NEW_FUNCTION)
    if ok(CFN_UPDATE, s.stack):
        labels.add(E_CFN_UPDATE_STACK)
    if all(f"{a}|{s.stack}" in allowed for a in CFN_CHANGESET):
        labels.add(E_CFN_CHANGE_SET)
    return labels


def summarize(by_principal: dict[str, set[str]]) -> dict[str, Any]:
    """能力标签 → 聚合结论。**只出计数与集合关系，不出名字。**"""
    def holders(pred) -> set[str]:
        return {arn for arn, ls in by_principal.items() if pred(ls)}

    per_label = {lb: len(holders(lambda ls, lb=lb: lb in ls)) for lb in ALL_LABELS}
    can_sign = holders(lambda ls: any(l.startswith(SIGN_PREFIX) for l in ls))
    can_edge = holders(lambda ls: any(l.startswith(EDGE_PREFIX) for l in ls))
    surface = can_sign | can_edge

    # 每个候选措施的**边际收益** = 关掉那一组路径后完全离开冒充面的 principal 数。
    marginal: dict[str, dict[str, int]] = {}
    for name, closed in MITIGATIONS.items():
        remaining = {arn for arn, ls in by_principal.items() if ls - set(closed)}
        marginal[name] = {
            "closes_paths": len(closed),
            "surface_after": len(remaining),
            "principals_removed": len(surface) - len(remaining),
        }
    return {
        "principals_simulated": len(by_principal),
        "per_label": per_label,
        "can_sign": len(can_sign),
        "can_replace_edge_verifier": len(can_edge),
        "impersonation_surface_union": len(surface),
        "both": len(can_sign & can_edge),
        "sign_only": len(can_sign - can_edge),
        "edge_only": len(can_edge - can_sign),
        "marginal_value_if_closed": marginal,
        "_sets": {"can_sign": can_sign, "can_edge": can_edge, "surface": surface},
    }


# ---------------------------------------------------------------- 反例自检

def _fake_surface() -> Surface:
    return Surface(region="r", kms_key="KEY", edge_fn="EDGE", auth_fn="AUTH",
                   panel_fn="PANEL", new_fn="NEW", distribution="DIST",
                   stack="STACK", edge_role="EDGEROLE",
                   edge_association_qualifier="7")


def self_test() -> int:
    """**每条新等价路径都要有一条只命中它的反例**，外加一条正向控制证明我们
    没有把"单个动作"当成能力。这些用例是 Codex 第十四轮明确要求的独立反例。
    """
    s = _fake_surface()

    def labels(*pairs: str) -> set[str]:
        return classify(frozenset(pairs), s)

    cases: list[tuple[str, set[str], set[str]]] = [
        # ---- 正向控制：单动作**不足以**替换正在运行的 Edge ----
        ("只有 UpdateFunctionCode(Edge)：闸门今天会记 replace-platform-code，"
         "而它改不了正在执行的代码",
         labels("lambda:UpdateFunctionCode|EDGE"), set()),
        ("UpdateFunctionCode+PublishVersion 但不能改 association",
         labels("lambda:UpdateFunctionCode|EDGE", "lambda:PublishVersion|EDGE"),
         set()),
        # ---- 反例①：Publish=True 一次调用，无 PublishVersion ----
        ("UpdateFunctionCode(Publish=True)+UpdateDistribution（无 PublishVersion）",
         labels("lambda:UpdateFunctionCode|EDGE",
                "cloudfront:UpdateDistribution|DIST"),
         {E_PUBLISH_INLINE}),
        ("三个都有时两条 Edge 路径都记",
         labels("lambda:UpdateFunctionCode|EDGE", "lambda:PublishVersion|EDGE",
                "cloudfront:UpdateDistribution|DIST"),
         {E_PUBLISH_INLINE, E_PUBLISH_THEN_ASSOCIATE}),
        # ---- 反例②：change set 链 ----
        ("CreateChangeSet+ExecuteChangeSet（无 UpdateStack）",
         labels("cloudformation:CreateChangeSet|STACK",
                "cloudformation:ExecuteChangeSet|STACK"),
         {E_CFN_CHANGE_SET}),
        ("只有 CreateChangeSet 不够（不能执行）",
         labels("cloudformation:CreateChangeSet|STACK"), set()),
        ("UpdateStack 单动作即可（栈已关联 service role、无 stack policy）",
         labels("cloudformation:UpdateStack|STACK"), {E_CFN_UPDATE_STACK}),
        # ---- 反例③：劫持 signer，不碰 Edge、自己没有 kms:Sign ----
        ("只有 UpdateFunctionCode(auth)：无 KMS 权限也能签站点+console 会话",
         labels("lambda:UpdateFunctionCode|AUTH"), {S_HIJACK_AUTH}),
        ("只有 UpdateFunctionCode(panel)：能签 console 会话",
         labels("lambda:UpdateFunctionCode|PANEL"), {S_HIJACK_PANEL}),
        ("UpdateFunctionConfiguration(auth) 也算（Layer 遮蔽模块）",
         labels("lambda:UpdateFunctionConfiguration|AUTH"), {S_HIJACK_AUTH}),
        # ---- 反例④：资源维度不许折叠 ----
        ("Edge 上的换码权限**不能**外溢成劫持 auth signer",
         labels("lambda:UpdateFunctionCode|EDGE",
                "cloudfront:UpdateDistribution|DIST"),
         {E_PUBLISH_INLINE}),
        ("auth 上的换码权限**不能**外溢成替换 Edge",
         labels("lambda:UpdateFunctionCode|AUTH",
                "cloudfront:UpdateDistribution|DIST"),
         {S_HIJACK_AUTH}),
        # ---- 反例⑤：新建函数再关联，缺 PassRole 不成立 ----
        ("CreateFunction+PublishVersion+UpdateDistribution 但无 PassRole",
         labels("lambda:CreateFunction|NEW", "lambda:PublishVersion|NEW",
                "cloudfront:UpdateDistribution|DIST"), set()),
        ("补上 PassRole 后成立",
         labels("lambda:CreateFunction|NEW", "lambda:PublishVersion|NEW",
                "cloudfront:UpdateDistribution|DIST", "iam:PassRole|EDGEROLE"),
         {E_NEW_FUNCTION}),
        # ---- 反例⑥：KMS ----
        ("kms:Sign", labels("kms:Sign|KEY"), {S_KMS_DIRECT}),
        ("kms:CreateGrant 自助授权", labels("kms:CreateGrant|KEY"), {S_KMS_SELF}),
        ("kms:GetPublicKey 不是冒充能力（公钥不是秘密）",
         labels("kms:GetPublicKey|KEY"), set()),
        ("空集", labels(), set()),
    ]

    bad = [(w, got, want) for w, got, want in cases if got != want]
    for why, got, want in cases:
        print(f"  {'ok  ' if got == want else 'FAIL'} {why}")
        if got != want:
            print(f"       期望 {sorted(want)} 实得 {sorted(got)}")

    # 聚合层的反例：sign 与 edge 两类必须分别计入并集，不能只算一类。
    agg = summarize({
        "p-sign-only": {S_HIJACK_AUTH},
        "p-edge-only": {E_CFN_UPDATE_STACK},
        "p-both": {S_KMS_DIRECT, E_CFN_CHANGE_SET},
    })
    want_agg = {"can_sign": 2, "can_replace_edge_verifier": 2,
                "impersonation_surface_union": 3, "both": 1,
                "sign_only": 1, "edge_only": 1}
    agg_bad = {k: (agg[k], v) for k, v in want_agg.items() if agg[k] != v}
    print(f"  {'ok  ' if not agg_bad else 'FAIL'} 聚合：sign/edge 两类都进并集")
    if agg_bad:
        print(f"       {agg_bad}")

    # 边际收益的反例：**限制性 key policy 收不掉劫持 signer 那条路**。
    # `p-kms-only` 只有 KMS 直签 ⇒ 会离开；`p-kms-and-hijack` 还剩劫持 signer
    # ⇒ 留在面里。旧口径（拿"能签名但不能替换 Edge"当判据）会把后者算成收益。
    mv = summarize({
        "p-kms-only": {S_KMS_DIRECT},
        "p-kms-and-hijack": {S_KMS_DIRECT, S_HIJACK_AUTH},
        "p-cfn-only": {E_CFN_UPDATE_STACK},
    })["marginal_value_if_closed"]
    mv_want = {"restrictive-kms-key-policy": 1, "harden-signer-code-update": 0,
               "router-stack-policy": 1}
    mv_bad = {k: (mv[k]["principals_removed"], v) for k, v in mv_want.items()
              if mv[k]["principals_removed"] != v}
    print(f"  {'ok  ' if not mv_bad else 'FAIL'} 边际收益：key policy 收不掉劫持 signer")
    if mv_bad:
        print(f"       {mv_bad}")

    if bad or agg_bad or mv_bad:
        print(f"\n{len(bad) + len(agg_bad) + len(mv_bad)} 条反例未通过", file=sys.stderr)
        return 1
    print(f"\n全部 {len(cases)} 条反例 + 2 条聚合/边际断言通过")
    return 0


# ---------------------------------------------------------------- 真机部分

def load_gate():
    """复用闸门的真源助手（平台函数名 AST 解析、TLS 加固、每线程 client、指纹），
    不维护第二份副本——CLAUDE.md「优先用生产 helper，不留简化副本」。"""
    spec = importlib.util.spec_from_file_location("_gate", GATE)
    assert spec is not None and spec.loader is not None, GATE
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


def discover(gate, clients, region: str, account: str) -> Surface:
    """从 config + 真机状态推出资源集合。**不接受硬编码的 distribution ID。**"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(ROUTER_CONFIG, encoding="utf-8")
    if not cfg.sections():
        raise SystemExit(
            f"{ROUTER_CONFIG} 读不到任何段——configparser 对缺失文件是静默的，"
            f"再往下会拿空值拼出假结论。")
    wildcard = cfg["CloudFront"]["domain_name"].strip()
    stack_name = cfg["CDK"]["stack_name"].strip()

    platform = set(gate.platform_function_names())
    for want in ("site-auth-service", "site-panel"):
        if want not in platform:
            raise SystemExit(f"平台函数清单里没有 {want}——探针会漏掉一条 signer 路径")
    edge_fn = gate.EDGE_ORIGIN_REQUEST_FN

    def fn(n: str) -> str:
        return f"arn:aws:lambda:{region}:{account}:function:{n}"

    # distribution：按 router/config.ini 的通配域名找，**ID 不进源码**。
    cfn = clients["cloudfront"]
    dist_id = ""
    for page in cfn.get_paginator("list_distributions").paginate():
        for d in (page["DistributionList"].get("Items") or ()):
            if wildcard in (d.get("Aliases", {}).get("Items") or ()):
                dist_id = d["Id"]
                break
        if dist_id:
            break
    if not dist_id:
        raise SystemExit(f"找不到别名含 {wildcard} 的 distribution")

    # **载荷性前提**：association 真的挂在编号版本上。若哪天变成 alias/$LATEST，
    # 「单动作证明不了能替换正在运行的代码」这条推理就不成立 ⇒ 响亮失败。
    dcfg = cfn.get_distribution_config(Id=dist_id)["DistributionConfig"]
    quals = {a["LambdaFunctionARN"].rsplit(":", 1)[-1]
             for a in (dcfg["DefaultCacheBehavior"]
                       .get("LambdaFunctionAssociations", {}).get("Items") or ())
             if f":function:{edge_fn}:" in a["LambdaFunctionARN"]}
    numbered = sorted(q for q in quals if q.isdigit())
    if not numbered:
        raise SystemExit(
            f"{edge_fn} 的 association 限定符不是编号版本（实得 {sorted(quals)}）"
            f"——本探针的 Edge 路径建模前提不成立，先核对再改模型")

    # Edge 函数的执行角色：给"新建函数再关联"那条路做 PassRole 的资源。
    edge_role = clients["lambda"].get_function(
        FunctionName=edge_fn)["Configuration"]["Role"]

    return Surface(
        region=region,
        # 3c 的两把 CMK 还不存在 ⇒ 用占位 ARN 量"对本账号任意 key 的 identity 上界"。
        kms_key=f"arn:aws:kms:{region}:{account}:key/"
                "00000000-0000-0000-0000-000000000000",
        edge_fn=fn(edge_fn), auth_fn=fn("site-auth-service"),
        panel_fn=fn("site-panel"),
        new_fn=fn("probe-placeholder-new-function"),
        distribution=f"arn:aws:cloudfront::{account}:distribution/{dist_id}",
        stack=f"arn:aws:cloudformation:{region}:{account}:stack/{stack_name}/*",
        edge_role=edge_role,
        edge_association_qualifier=",".join(numbered))


def list_principals(iam) -> list[dict[str, str]]:
    """`ListRoles`+`ListUsers`（**不是** GAAD——见模块 docstring 的坑 2）。
    service-linked 角色按 path 排除，与闸门同一条判据。"""
    out: list[dict[str, str]] = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if not r["Path"].startswith("/aws-service-role/"):
                out.append({"arn": r["Arn"], "name": r["RoleName"]})
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            out.append({"arn": u["Arn"], "name": u["UserName"]})
    return out


def simulate_all(gate, s: Surface, principals: list[dict[str, str]],
                 workers: int) -> dict[str, frozenset[str]]:
    """每个 principal → 允许的 `"action|resource"` 集合。

    **必须保留资源维度。** 折叠成"动作集合"会让"能换 auth 的码"与"能换 Edge 的码"
    变成同一件事——那正是闸门里犯过的那一类建模错。
    """
    got: dict[str, frozenset[str]] = {}
    failures: list[str] = []
    groups = s.groups()

    def probe(arn: str) -> frozenset[str]:
        cl = gate.thread_iam_client(s.region)
        allowed: set[str] = set()
        for actions, resources in groups:
            r = cl.simulate_principal_policy(
                PolicySourceArn=arn, ActionNames=actions, ResourceArns=resources)
            for res in r["EvaluationResults"]:
                act = res["EvalActionName"]
                rsr = res.get("ResourceSpecificResults") or ()
                if rsr:
                    for rr in rsr:
                        if rr.get("EvalResourceDecision") == "allowed":
                            allowed.add(f"{act}|{rr['EvalResourceName']}")
                elif res.get("EvalDecision") == "allowed":
                    # 单资源组时 IAM 可能不返回 ResourceSpecificResults。
                    for one in resources:
                        allowed.add(f"{act}|{one}")
        return frozenset(allowed)

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, p["arn"]): p for p in principals}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            p = futs[fut]
            try:
                got[p["arn"]] = fut.result()
            except Exception as exc:                       # noqa: BLE001
                failures.append(f"{p['name']}: {type(exc)}: {exc}")
            if i % 50 == 0:
                print(f"  {i}/{len(principals)}", flush=True)
    if failures:
        # 部分失败 ⇒ 集合不完整 ⇒ **交集/并集全部作废**，不出结论。
        raise SystemExit(f"{len(failures)} 个 principal 模拟失败，结果不完整，"
                         f"不出结论：{failures[:3]}")
    return got


def head_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                             capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=_ROOT,
                               capture_output=True, text=True, check=True)
        return out.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true",
                    help="只跑 classify() 的反例，不碰 AWS")
    ap.add_argument("--write-evidence", action="store_true",
                    help=f"写 tracked 聚合证据到 {EVIDENCE.relative_to(_ROOT)}")
    ap.add_argument("--dump-observed", metavar="PATH",
                    help="把**名字**写到这里（必须是 gitignored 路径）")
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    # 名字不许进被跟踪的文件（仓库红线）。**在发第一个请求之前就检查**——
    # 跑 5 分钟再拒绝写等于白跑一趟。
    dump = Path(args.dump_observed).resolve() if args.dump_observed else None
    if dump is not None:
        r = subprocess.run(["git", "check-ignore", "-q", str(dump)], cwd=_ROOT)
        if r.returncode != 0:
            raise SystemExit(
                f"--dump-observed 指向的 {dump} 不是 gitignored 路径。"
                f"内部角色名不进被跟踪的文件——换到 docs/design/ 下。")

    gate = load_gate()
    gate.harden_tls_warnings()
    import boto3
    from botocore.config import Config

    # `read_timeout` 取 120 秒：见模块 docstring 的坑 3。
    cfg = Config(retries={"max_attempts": 6, "mode": "standard"},
                 connect_timeout=10, read_timeout=120)
    region = "us-east-1"           # Lambda@Edge + CloudFront 证书的硬约束
    account = boto3.client("sts", region_name=region,
                           config=cfg).get_caller_identity()["Account"]
    clients = {n: boto3.client(n, region_name=region, config=cfg)
               for n in ("iam", "lambda", "cloudfront")}
    print(f"区 {region}（账号值不打印）", flush=True)

    s = discover(gate, clients, region, account)
    print(f"Edge association 限定符 = 编号版本 {s.edge_association_qualifier}"
          f"（单动作模型不成立的前提，已实测）", flush=True)

    print("枚举 principal（ListRoles+ListUsers，不拉策略文档）…", flush=True)
    principals = list_principals(clients["iam"])
    print(f"待模拟 {len(principals)} 个 × {len(s.groups())} 组", flush=True)

    decisions = simulate_all(gate, s, principals, args.workers)
    by_principal = {arn: classify(a, s) for arn, a in decisions.items()}
    agg = summarize(by_principal)
    sets = agg.pop("_sets")

    names = {p["arn"]: p["name"] for p in principals}
    raw = {
        "can_sign": sorted(names[a] for a in sets["can_sign"]),
        "can_replace_edge_verifier": sorted(names[a] for a in sets["can_edge"]),
        "sign_only": sorted(names[a] for a in sets["can_sign"] - sets["can_edge"]),
        "edge_only": sorted(names[a] for a in sets["can_edge"] - sets["can_sign"]),
        "per_label": {lb: sorted(names[a] for a, ls in by_principal.items()
                                 if lb in ls) for lb in ALL_LABELS},
    }
    raw_blob = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    raw_hash = hashlib.sha256(raw_blob.encode("utf-8")).hexdigest()

    print("\n===== 每条能力路径的持有者数 =====")
    for lb in ALL_LABELS:
        print(f"  {lb:38} {agg['per_label'][lb]:>4}")
    print("\n===== 冒充面 =====")
    for k in ("can_sign", "can_replace_edge_verifier",
              "impersonation_surface_union", "both", "sign_only", "edge_only"):
        print(f"  {k:32} {agg[k]:>4}")
    print("\n===== 关掉某一组路径的边际收益（离开冒充面的 principal 数）=====")
    for name, m in agg["marginal_value_if_closed"].items():
        print(f"  {name:32} 面 {agg['impersonation_surface_union']:>3}"
              f" → {m['surface_after']:<3}（-{m['principals_removed']}）")
    print("\n提醒：`sign:kms-*` 是 identity policy 的**上界**；KMS 的 key policy 是"
          "权威的，\n真实可签名集合 = 该上界 ∩ key policy 放行的集合。"
          "\n`sign:hijack-*` 与 key policy 无关——恶意代码是**以 signer 角色身份**调用的。")

    evidence = {
        "_what": "3c（会话签名迁非对称）之后的冒充面量测。**不是闸门**，没有基线，"
                 "不会红。产生者：site-builder/scripts/probe_impersonation_surface.py",
        "_privacy": "只存计数与指纹；principal 名字在 --dump-observed 的 "
                    "gitignored 产物里，其 sha256 记在 raw_observed_sha256。",
        "commit": head_sha(),
        "probed_at_utc": dt.datetime.now(dt.timezone.utc)
                           .replace(microsecond=0).isoformat(),
        "region": region,
        "action_equivalence_classes": {
            "kms_sign": list(KMS_SIGN),
            "kms_self_authorize": list(KMS_SELF_AUTHORIZE),
            "lambda_code_exec": list(LAMBDA_CODE_EXEC),
            "lambda_publish": list(LAMBDA_PUBLISH),
            "lambda_create": list(LAMBDA_CREATE),
            "cloudfront_write": list(CF_WRITE),
            "cfn_update": list(CFN_UPDATE),
            "cfn_change_set": list(CFN_CHANGESET),
            "iam_passrole": list(IAM_PASSROLE),
        },
        "resource_equivalence_classes": [
            "kms:placeholder-key(3c 的 CMK 还不存在，量的是对本账号任意 key 的上界)",
            "lambda:edge-origin-request", "lambda:site-auth-service",
            "lambda:site-panel", "lambda:placeholder-new-function",
            "cloudfront:wildcard-distribution", "cloudformation:router-stack",
            "iam:edge-execution-role(PassRole)",
        ],
        "edge_association_qualifier_is_numbered_version": True,
        "aggregate": agg,
        "raw_observed_sha256": raw_hash,
        "known_gaps": [
            "IAM 自助提权（iam:PutRolePolicy 等）没有折进 can_sign：默认 key policy "
            "委派给账号 root 时，任何能给自己加 kms:Sign 的 principal 都进冒充面。"
            "那一层由闸门 B 组（IAM 写的静态文本快照）单独覆盖，口径不同不合并。",
            "kms:Sign 的真实集合还要 ∩ key policy；本探针只量 identity policy 上界。",
            "lambda:UpdateFunctionConfiguration 计为代码执行是**上界口径**："
            "还需要能发布/读到一个 Layer，本探针不追那一步。",
            "UpdateFunctionCode(Publish=True) 是否在 IAM 上额外要求 "
            "lambda:PublishVersion，AWS 文档未明确说明；本探针按**不要求**建模"
            "（取上界）。要证实只能做写调用，超出只读范围。",
            "只覆盖会话签名这一族。Cognito 的 site-auth-pre-token（注入 email "
            "claim）是另一条 MCP 侧冒充路径，不在 3c 范围。",
            "site-deployer-* 等平台角色是否在 3c 后持 kms:Sign 取决于实现；"
            "本探针按 spec §4.1 只算 auth 与 panel。",
        ],
    }
    if args.write_evidence:
        EVIDENCE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False)
                            + "\n", encoding="utf-8")
        print(f"\n已写 {EVIDENCE.relative_to(_ROOT)}")
    if dump is not None:
        dump.parent.mkdir(parents=True, exist_ok=True)
        dump.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        print(f"已写名字 dump（gitignored）{dump}")
    if not args.write_evidence:
        print("\n（未加 --write-evidence，聚合证据没有落盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
