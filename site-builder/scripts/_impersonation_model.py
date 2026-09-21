"""冒充面判定模型：闸门与探针**共用**的那一份纯函数。

## 为什么是独立模块

`verify_account_trust_boundary.py`（闸门，有基线、会红）与
`probe_impersonation_surface.py`（量测工具，无基线）此前各有一套判定，且两套都失真：
闸门把"能替换平台代码"建模成 `lambda:UpdateFunctionCode` 一个动作（对 Edge 过度声称、
对 CFN 少算），探针把代码更新与配置更新合成一类、CFN 前提停留在 ADR 0007 之前、
还多要了一个 `PublishVersion`。**不变量是"两边共用同一份经反例验证的模型"**，
不是"其中一边是对的"。反例集在 `deployer/tests/test_impersonation_model.py`。

## 形状

**一种能力 = 一个动作等价类 × 一个资源等价类。** 把它压成"单个动作/单个资源"这个错误
在本仓库犯过四次（闸门的 `A_*` 注释记了三次，第四次就是 3g 本身）。

## 前提是观测，不是假设

每条路径都有可观测前提：函数入口服务的是 `$LATEST` 还是编号版本 / alias、栈的
stack policy 是否拦住受保护资源、栈到底控制什么。前提是**多值**的，`unknown`
**不得**按"否"解释——那正是"闸门给假绿"的形状。

## 零 AWS 依赖

本模块不 import boto3/botocore、不读 config：`probe --self-test` 与闸门的纯函数
路径都必须能在没有这些包的解释器上 import 它。采集在各自的调用方。
"""
from __future__ import annotations

from dataclasses import dataclass, replace

# ---------------------------------------------------------------- 观测值域
ENTRY_LATEST = "latest"      # 入口（Function URL / 直调）服务未发布的 $LATEST
ENTRY_ALIAS = "alias"        # 入口挂在 alias 上（站点的 blue/green）
ENTRY_VERSION = "version"    # 入口是编号版本（Lambda@Edge 必须如此）
ENTRY_UNKNOWN = "unknown"    # 观测不到 ⇒ 不出确定结论

GUARD_PROTECTED = "protected"         # stack policy 拦住受保护资源的 Update
GUARD_OPEN = "open"                   # 没有 stack policy，或它不拦
GUARD_UNKNOWN = "unknown"             # 解析不出 / 读不到 ⇒ 不出确定结论

CONTROLS_EDGE = "edge-verifier"       # 该栈管理 Edge 验签函数 / 分发
CONTROLS_SESSION_KEY = "session-key"  # 该栈管理会话签名 CMK

# ---------------------------------------------------------------- 动作等价类
A_KMS_SIGN = ("kms:Sign",)
A_KMS_SELF_AUTHORIZE = ("kms:PutKeyPolicy", "kms:CreateGrant")
A_INVOKE = ("lambda:InvokeFunction",)
# **刻意分开的两类**（3g）：`UpdateFunctionCode` 的输入含 `Publish` ⇒ 一次调用即改码即发
# 版本；`UpdateFunctionConfiguration` **没有** `Publish`（botocore 服务模型实测），它的
# 任意代码执行靠挂 Layer，而 Lambda@Edge **不支持 Layer**（AWS 文档）。合成一类会让
# "只有 UpdateFunctionConfiguration(Edge)" 错判成能替换正在运行的 Edge 代码。
A_UPDATE_CODE = ("lambda:UpdateFunctionCode",)
A_UPDATE_CONFIG = ("lambda:UpdateFunctionConfiguration",)
A_PUBLISH_VERSION = ("lambda:PublishVersion",)
# `CreateFunction` 的输入**也含 `Publish`**（同上实测）⇒ 新建函数那条路不需要单独的
# `PublishVersion`。把它当必需前提是少算。
A_CREATE_FUNCTION = ("lambda:CreateFunction",)
A_CF_WRITE = ("cloudfront:UpdateDistribution",)
A_CFN_UPDATE = ("cloudformation:UpdateStack",)
A_CFN_CREATE_CHANGESET = ("cloudformation:CreateChangeSet",)
A_CFN_EXECUTE_CHANGESET = ("cloudformation:ExecuteChangeSet",)
# ADR 0007：越过 stack policy 的门槛就是它（AWS 文档原话；ExecuteChangeSet 没有临时覆盖选项）。
A_CFN_SET_POLICY = ("cloudformation:SetStackPolicy",)
A_PASSROLE = ("iam:PassRole",)

# ---------------------------------------------------------------- 能力标签
SIGN_PREFIX = "sign:"
EDGE_PREFIX = "edge:"

S_KMS_DIRECT = "sign:kms-direct"
S_KMS_SELF = "sign:kms-self-authorize"
S_HIJACK_AUTH = "sign:hijack-auth-signer"
S_HIJACK_PANEL = "sign:hijack-panel-signer"
S_FIXTURE_ISSUER = "sign:fixture-issuer"
E_PUBLISH_INLINE = "edge:code(Publish=True)+associate"
E_PUBLISH_THEN_ASSOCIATE = "edge:code+publish+associate"
E_NEW_FUNCTION = "edge:new-function+associate"
# CFN：两条更宽的路。**router 栈自 ADR 0007 起有 stack policy**，所以单动作不再足够。
E_CFN_UPDATE_STACK = "edge:cfn-update-stack"
E_CFN_CHANGE_SET = "edge:cfn-change-set"
# stack policy 挡住的是**受保护资源的直接更新**，不等于关闭了全部 CFN 提权路径
# （service role 权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰那四个资源）。
# ⇒ 这条**不进冒充面并集**，但必须留在视野里、参与漂移比较。
E_CFN_TEMPLATE_UNANALYZED = "edge:cfn-template-unanalyzed"
S_CFN_SESSION_KEY_STACK = "sign:cfn-session-key-stack"
S_CFN_SESSION_KEY_UNANALYZED = "sign:cfn-session-key-stack-unanalyzed"

# **不构成冒充面成员资格**的标签：受限冒充与前提未核实的那几条。
# 它们仍然进 per-label 计数与逐 principal 的集合比较（新增即红），只是不进并集。
NON_SURFACE_LABELS = frozenset({S_FIXTURE_ISSUER, S_CFN_SESSION_KEY_UNANALYZED,
                                E_CFN_TEMPLATE_UNANALYZED})

# **"不进并集"与"可以算它离开了并集"是两件事**（R1-L1）：
#   · `sign:fixture-issuer` 的可排除性有依据——ADR 0002 的 verifier 侧边界是**已证明**的
#     （Edge 只在夹具站点认夹具会话、panel 拒夹具域邮箱），所以只剩它的 principal 真的离开了；
#   · 两条 `*-unanalyzed` 恰恰相反：它们的意思是**还没分析**。把它们当成"可排除"，就会把
#     "已建模的路径都关了"读成"这个人已经不在冒充面里"，而那正是 ADR 0007 与 spec §3/§9
#     禁止的"确定收益"声明。
# ⇒ 边际收益里它们**阻止定论**，见 `summarize` 的 `principals_uncertain`。
UNANALYZED_LABELS = frozenset({S_CFN_SESSION_KEY_UNANALYZED, E_CFN_TEMPLATE_UNANALYZED})


@dataclass(frozen=True)
class FnFact:
    """一个函数的**观测**事实。`entry` 决定"换码是否立刻生效"，
    `layers_supported` 决定"改配置是否等于任意代码执行"。"""
    arn: str
    entry: str = ENTRY_UNKNOWN
    layers_supported: bool = True


@dataclass(frozen=True)
class StackFact:
    """一个 CloudFormation 栈的**观测**事实。

    `label` 是逻辑标签（"router" / "deployer"），进 grant 串；`resource` 是真实 StackId，
    只用于模拟，**不进基线也不进文档**。`premises_verified` 表示该栈那条路径的全部前提
    （谁执行这次更新、那个身份是否真能改目标资源）都已核实。
    """
    resource: str
    label: str
    guard: str = GUARD_UNKNOWN
    service_role: str | None = None
    controls: frozenset[str] = frozenset()
    premises_verified: bool = False


@dataclass(frozen=True)
class Surface:
    """判定要用到的全部资源与事实。**没有账号值的默认值**——调用方按真机拼。"""
    kms_keys: tuple[str, ...]
    auth: FnFact
    panel: FnFact
    edge: FnFact
    new_candidates: tuple[str, ...] = ()
    distribution: str = ""
    edge_role: str = ""
    stacks: tuple = ()                      # tuple[StackFact, ...]
    service_roles: tuple[str, ...] = ()
    verifier_role_name: str = "site-builder-verifier"


def replace_fn(s: Surface, which: str, **changes) -> Surface:
    """测试辅助：换掉 `auth` / `panel` / `edge` 的某个观测字段，其余不动。"""
    return replace(s, **{which: replace(getattr(s, which), **changes)})


def classify(allowed: frozenset[str], s: Surface, name: str = "") -> set[str]:
    """`{"action|resource"}` 允许集合（+ principal 名字）→ 它持有的能力标签。

    **纯函数**：不碰 AWS，反例可以直接跑。`name` 只服务一条判据——夹具签发器角色
    本身即持有那条入口（它的 inline policy 就是对 auth Function URL 的两条 invoke）。
    """
    def ok(actions, resource: str) -> bool:
        return bool(resource) and any(f"{a}|{resource}" in allowed for a in actions)

    def ok_any_key(actions) -> bool:
        return any(ok(actions, k) for k in s.kms_keys)

    def code_exec(fact: FnFact) -> bool:
        """在该函数的执行角色下跑任意代码，**且入口立刻服务它**。"""
        if fact.entry != ENTRY_LATEST:
            return False
        if ok(A_UPDATE_CODE, fact.arn):
            return True
        return fact.layers_supported and ok(A_UPDATE_CONFIG, fact.arn)

    labels: set[str] = set()
    if ok_any_key(A_KMS_SIGN):
        labels.add(S_KMS_DIRECT)
    if ok_any_key(A_KMS_SELF_AUTHORIZE):
        labels.add(S_KMS_SELF)
    if code_exec(s.auth):
        labels.add(S_HIJACK_AUTH)
    if code_exec(s.panel):
        labels.add(S_HIJACK_PANEL)
    if ok(A_INVOKE, s.auth.arn) or (name and name == s.verifier_role_name):
        labels.add(S_FIXTURE_ISSUER)

    # Edge：光有换码不够，必须让 CloudFront 关联到攻击者的代码上。
    # `edge.entry` 必须是**观测到的**编号版本——这正是旧模型过度声称的那一步。
    if s.edge.entry == ENTRY_VERSION and ok(A_CF_WRITE, s.distribution):
        if ok(A_UPDATE_CODE, s.edge.arn):
            labels.add(E_PUBLISH_INLINE)              # UpdateFunctionCode(Publish=True)
            if ok(A_PUBLISH_VERSION, s.edge.arn):
                labels.add(E_PUBLISH_THEN_ASSOCIATE)
        # `CreateFunction` 自带 `Publish` ⇒ **不要**把 `PublishVersion` 当必需前提。
        if any(ok(A_CREATE_FUNCTION, c) for c in s.new_candidates) \
                and ok(A_PASSROLE, s.edge_role):
            labels.add(E_NEW_FUNCTION)

    # CFN：逐栈判。**前提是观测**——guard 三值、栈控制什么、前提是否核实。
    for st in s.stacks:
        via_update = ok(A_CFN_UPDATE, st.resource)
        via_change_set = (ok(A_CFN_CREATE_CHANGESET, st.resource)
                          and ok(A_CFN_EXECUTE_CHANGESET, st.resource))
        if not (via_update or via_change_set):
            continue
        # `protected` 下的门槛是 `SetStackPolicy`；`unknown` 一律不算通过。
        passable = (st.guard == GUARD_OPEN
                    or (st.guard == GUARD_PROTECTED and ok(A_CFN_SET_POLICY, st.resource)))
        definite = passable and st.premises_verified
        if CONTROLS_EDGE in st.controls:
            if definite:
                if via_update:
                    labels.add(E_CFN_UPDATE_STACK)
                if via_change_set:
                    labels.add(E_CFN_CHANGE_SET)
            else:
                labels.add(E_CFN_TEMPLATE_UNANALYZED)
        if CONTROLS_SESSION_KEY in st.controls:
            labels.add(S_CFN_SESSION_KEY_STACK if definite
                       else S_CFN_SESSION_KEY_UNANALYZED)
    return labels


def is_surface_label(label: str) -> bool:
    """这个标签本身是否构成**冒充面成员资格**。

    按 `NON_SURFACE_LABELS` **显式名单**排除，不按前缀猜：新增标签必须在那份名单上
    做一次决定。`sign:fixture-issuer` 是受限冒充（只能签夹具域邮箱），两条
    `*-unanalyzed` 是前提未核实 ⇒ 都带 `sign:` / `edge:` 前缀好在 per-label 计数里与
    同类排在一起，但**不进并集**。
    """
    return label not in NON_SURFACE_LABELS and (label.startswith(SIGN_PREFIX)
                                                or label.startswith(EDGE_PREFIX))


def fake_surface() -> Surface:
    """反例用的假 surface。两把 key（site / console）都要在，否则"任一把成立即算"
    这条判据没有反例可打。"""
    return Surface(
        kms_keys=("KEY_SITE", "KEY_CONSOLE"),
        auth=FnFact("AUTH", entry=ENTRY_LATEST, layers_supported=True),
        panel=FnFact("PANEL", entry=ENTRY_LATEST, layers_supported=True),
        edge=FnFact("EDGE", entry=ENTRY_VERSION, layers_supported=False),
        new_candidates=("NEW1", "NEW2"),
        distribution="DIST",
        edge_role="EDGEROLE",
        stacks=(),
    )


def fake_stack(label: str, *, controls: frozenset[str],
               guard: str = GUARD_UNKNOWN, premises_verified: bool = False) -> StackFact:
    """反例用的假栈。`resource` 用标签拼一个不含账号值的假 StackId。"""
    return StackFact(resource=f"STACK_{label.upper()}", label=label, guard=guard,
                     service_role=None, controls=controls,
                     premises_verified=premises_verified)


ALL_LABELS: tuple[str, ...] = (
    S_KMS_DIRECT, S_KMS_SELF, S_HIJACK_AUTH, S_HIJACK_PANEL, S_FIXTURE_ISSUER,
    S_CFN_SESSION_KEY_STACK, S_CFN_SESSION_KEY_UNANALYZED,
    E_PUBLISH_INLINE, E_PUBLISH_THEN_ASSOCIATE, E_NEW_FUNCTION,
    E_CFN_UPDATE_STACK, E_CFN_CHANGE_SET, E_CFN_TEMPLATE_UNANALYZED)

# 候选缓解措施：**"少算一个动作"与"这个措施值不值得做"是两个问题。**
# 边际收益 = 关掉这一组路径后**完全**离开冒充面的 principal 数。
MITIGATIONS: dict[str, tuple[str, ...]] = {
    "restrictive-kms-key-policy": (S_KMS_DIRECT, S_KMS_SELF),
    "harden-signer-code-update": (S_HIJACK_AUTH, S_HIJACK_PANEL),
    "router-stack-policy": (E_CFN_UPDATE_STACK, E_CFN_CHANGE_SET),
    "lock-edge-association": (E_PUBLISH_INLINE, E_PUBLISH_THEN_ASSOCIATE, E_NEW_FUNCTION),
    "harden-session-key-stack-update": (S_CFN_SESSION_KEY_STACK,),
    # 夹具签发器的"缓解"就是 verifier 侧的边界（ADR 0002），已经在生产代码里；
    # 关掉这一组等于关掉整套验收工具 ⇒ 边际收益按 0 记（`summarize` 会算出 0）。
    "fixture-issuer-verifier-boundary": (S_FIXTURE_ISSUER,),
}

# **显式声明未覆盖**的标签：它们不是"某个措施能关掉"的路径，而是"还没分析"的范围。
UNCOVERED_LABELS: dict[str, str] = {
    E_CFN_TEMPLATE_UNANALYZED:
        "stack policy 只挡住受保护资源的直接更新；service role 权限足够高时的模板层路径"
        "（新增 IAM 授权类资源等）尚未分析 ⇒ 没有对应措施，只有「去做那次分析」。",
    S_CFN_SESSION_KEY_UNANALYZED:
        "前提（这次更新以谁的身份执行、那个身份是否真能改 key policy）尚未核实 ⇒ "
        "先核实前提，再谈措施。",
}


def summarize(by_principal: dict) -> dict:
    """能力标签 → 聚合结论。**只出计数与集合关系，不出名字。**"""
    def holders(pred) -> set:
        return {arn for arn, ls in by_principal.items() if pred(ls)}

    per_label = {lb: len(holders(lambda ls, lb=lb: lb in ls)) for lb in ALL_LABELS}
    can_sign = holders(lambda ls: any(is_surface_label(l) and l.startswith(SIGN_PREFIX)
                                      for l in ls))
    can_edge = holders(lambda ls: any(is_surface_label(l) and l.startswith(EDGE_PREFIX)
                                      for l in ls))
    surface = can_sign | can_edge
    marginal: dict = {}
    for name, closed in MITIGATIONS.items():
        # 三分，而不是二分（R1-L1）：已建模路径是否全关 × 是否还持未分析路径。
        remaining, uncertain = set(), set()
        for arn in surface:
            labels = by_principal[arn]
            if {l for l in labels if is_surface_label(l)} - set(closed):
                remaining.add(arn)            # 还有**已建模**的路径没关 ⇒ 确定仍在面里
            elif set(labels) & UNANALYZED_LABELS:
                uncertain.add(arn)            # 已建模的都关了，但还有未分析路径 ⇒ **不定论**
        marginal[name] = {
            "closes_paths": len(closed),
            # 两个数字都朝安全方向取：收益是**下界**，剩余是**上界**。
            "surface_after": len(remaining) + len(uncertain),
            "principals_removed": len(surface) - len(remaining) - len(uncertain),
            "principals_uncertain": len(uncertain),
        }
    return {
        "principals_simulated": len(by_principal),
        "per_label": per_label,
        "can_sign": len(can_sign),
        "can_replace_edge_verifier": len(can_edge),
        "fixture_issuer_holders": len(holders(lambda ls: S_FIXTURE_ISSUER in ls)),
        # 只持"受限 / 未分析"标签的 principal 数：他们**不在**并集里，但也不是零信息。
        "non_surface_only_holders": len(holders(
            lambda ls: bool(ls) and not any(is_surface_label(l) for l in ls))),
        "impersonation_surface_union": len(surface),
        "both": len(can_sign & can_edge),
        "sign_only": len(can_sign - can_edge),
        "edge_only": len(can_edge - can_sign),
        "marginal_value_if_closed": marginal,
        "_sets": {"can_sign": can_sign, "can_edge": can_edge, "surface": surface},
    }
