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
