# 3g 冒充判定模型对齐 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把"谁能冒充任意用户"的判定从闸门与探针各自一套（且各有失真）收敛成一份经反例验证的共享纯模型，闸门在 grant 层之上新增派生能力层，基线升到 schema 7。

**Architecture:** 新建纯函数模块 `site-builder/scripts/_impersonation_model.py`（零 AWS 依赖），`probe_impersonation_surface.py` 与 `verify_account_trust_boundary.py` 各自的采集层向它提供**观测事实**（函数入口类型、stack policy 的 guard 三值、栈控制什么、前提是否核实），由它输出能力标签。闸门保留逐 (动作类 × 资源类) 的 grant 层作为漂移主锚，能力层只做派生断言；两层都进基线、都参与红绿。

**Tech Stack:** Python 3.12（`site-builder/deployer/.venv`），pytest，botocore/boto3（仅采集层），IAM `SimulatePrincipalPolicy`。

**Spec:** `docs/superpowers/specs/2026-09-20-3g-impersonation-model-alignment-spec.md`

## Global Constraints

- **一种能力 = 一个动作等价类 × 一个资源等价类。** 往任一维加成员时，同时加一条**只命中该新成员**的反例。
- **grant 层不得被能力层取代。** 两层都进基线、都参与红绿。
- **前提未核实 ⇒ 不出确定结论。** guard 与函数入口类型都是三值/四值；`unknown` 不得按"否"解释。
- **裁剪掉的 (动作, 资源) 组合是"未覆盖"，不是 deny。** 不得进入任何"他不能"的结论。
- **采集层既有硬保证不得放弃**：分页、`kms:MessageType` 的 RAW/DIGEST 两腿与合同值上下文、`merge_allowed` 取并集、模拟失败即硬失败、枚举—模拟窗口两端一致性复查、`BUNDLE_SHAPE` 递归默认拒绝。
- **不造 IAM 权限分析器**：不求值 Condition、不做 statement 归因、不算 `NotResource` 代数、不追 AssumeRole/PassRole 传递闭包。
- **不主张任何"收益 −N"的数字**（ADR 0007 已要求）。
- **真实账号 ID / 内部角色名 / StackId / distribution ID 不进被跟踪文件**；基线里 ARN 只落指纹。
- 本机 `site-builder/config.ini` 是精简+脱敏态 ⇒ **所有真机步骤（闸门首跑、基线生成、探针重量测、耗时量测）不在本机做**，见 Task 12。
- 所有新增测试都跑在 `site-builder/deployer/.venv`（含 pytest 与 moto）。

---

### Task 1: 共享模块骨架 + 签名侧标签（KMS 与劫持 signer）

**Files:**
- Create: `site-builder/scripts/_impersonation_model.py`
- Test: `site-builder/deployer/tests/test_impersonation_model.py`

**Interfaces:**
- Consumes: 无（第一个任务）
- Produces: `FnFact(arn, entry, layers_supported)`、`StackFact(resource, label, guard, service_role, controls, premises_verified)`、`Surface(kms_keys, auth, panel, edge, new_candidates, distribution, edge_role, stacks, verifier_role_name)`、常量 `ENTRY_{LATEST,ALIAS,VERSION,UNKNOWN}` / `GUARD_{PROTECTED,OPEN,UNKNOWN}` / `CONTROLS_{EDGE,SESSION_KEY}`、动作等价类 `A_*`、标签 `S_KMS_DIRECT` `S_KMS_SELF` `S_HIJACK_AUTH` `S_HIJACK_PANEL` `S_FIXTURE_ISSUER`、`classify(allowed: frozenset[str], s: Surface, name: str = "") -> set[str]`、`fake_surface() -> Surface`

- [ ] **Step 1: 先确认两套现有测试是绿的（不要在红底上开工）**

Run:
```bash
cd /Users/kentpeng/projects/quick-app/site-builder/deployer
.venv/bin/pytest tests/test_probe_impersonation_surface.py tests/test_verify_account_trust_boundary.py -q
```
Expected: 全绿。若有红，先停下来报告——那不是本计划引入的，但会让后面每一步的"失败→通过"失去意义。

- [ ] **Step 2: 写失败的测试**

创建 `site-builder/deployer/tests/test_impersonation_model.py`：

```python
"""共享冒充判定模型（`scripts/_impersonation_model.py`）的反例集。

这份文件是**模型的真源**：`probe --self-test` 与闸门单测都引用同一批用例，
所以"改判定顺手改期望"在这里只会改一处，而两个消费方都会红。

模型的形状不变量：**一种能力 = 一个动作等价类 × 一个资源等价类**；
前提（函数入口类型、stack policy 的 guard）是观测输入，`unknown` 不得按"否"解释。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_MODULE = _ROOT / "site-builder" / "scripts" / "_impersonation_model.py"


def _load():
    spec = importlib.util.spec_from_file_location("_impersonation_model", _MODULE)
    assert spec is not None and spec.loader is not None, _MODULE
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_impersonation_model"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def m():
    return _load()


def test_module_has_no_aws_imports():
    """**零 AWS 依赖**：`probe --self-test` 与闸门的纯函数路径必须能在没有 boto3 的
    解释器上 import 它。有人往这里 `import boto3` 会让那两条路一起断。"""
    src = _MODULE.read_text(encoding="utf-8")
    for forbidden in ("import boto3", "import botocore", "configparser"):
        assert forbidden not in src, f"共享模型里出现了 {forbidden}"


def test_kms_sign_on_either_key_is_full_impersonation(m):
    """**任一把**成立即算：site 那把签站点会话、console 那把签面板会话。
    折成"只看 site"会漏掉一整个 family。"""
    s = m.fake_surface()
    assert len(s.kms_keys) >= 2, s.kms_keys
    for key in s.kms_keys:
        assert m.classify(frozenset({f"kms:Sign|{key}"}), s) == {m.S_KMS_DIRECT}, key
        assert m.classify(frozenset({f"kms:CreateGrant|{key}"}), s) == {m.S_KMS_SELF}, key
        assert m.classify(frozenset({f"kms:PutKeyPolicy|{key}"}), s) == {m.S_KMS_SELF}, key


def test_public_key_read_is_not_a_capability(m):
    """公钥按定义是公开的（Edge 产物里就内联着它）⇒ 读到它签不出任何东西。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"kms:GetPublicKey|{s.kms_keys[0]}",
                                 f"kms:DescribeKey|{s.kms_keys[0]}"}), s) == set()


def test_update_code_on_auth_is_full_impersonation(m):
    """auth 的 Function URL 无 qualifier、服务 `$LATEST` ⇒ 换码即刻生效，
    **不需要**自己有 `kms:Sign`、不需要碰 Edge。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.auth.arn}"}), s) \
        == {m.S_HIJACK_AUTH}
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.panel.arn}"}), s) \
        == {m.S_HIJACK_PANEL}


def test_update_config_counts_only_where_layers_work(m):
    """`UpdateFunctionConfiguration` 能挂 Layer 遮蔽 handler import 的模块 ⇒ 任意代码执行，
    **但只在支持 Layer 的函数上**。Lambda@Edge 不支持 Layer（AWS 文档
    《Restrictions on Lambda@Edge》），所以同一个动作打在 Edge 上什么都不是。"""
    s = m.fake_surface()
    assert s.auth.layers_supported is True
    assert s.edge.layers_supported is False
    assert m.classify(frozenset({f"lambda:UpdateFunctionConfiguration|{s.auth.arn}"}), s) \
        == {m.S_HIJACK_AUTH}


def test_signer_hijack_requires_observed_latest_entry(m):
    """入口类型是**观测**，不是默认值。查不到 alias / 查不到 association 都是
    `unknown` ⇒ 不发确定标签（"默认成 `$LATEST`"会把过度声称重新引进来）。"""
    s = m.fake_surface()
    unknown_auth = m.replace_fn(s, "auth", entry=m.ENTRY_UNKNOWN)
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.auth.arn}"}),
                      unknown_auth) == set()


def test_fixture_issuer_is_listed_separately(m):
    """夹具签发器只给夹具域邮箱签站点会话、TTL ≤ 30 分钟（ADR 0002）⇒ **受限冒充**，
    单列、不进冒充面并集。角色名本身也是一条入口（它的 inline policy 就是那两条 invoke）。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:InvokeFunction|{s.auth.arn}"}), s) \
        == {m.S_FIXTURE_ISSUER}
    assert m.classify(frozenset(), s, s.verifier_role_name) == {m.S_FIXTURE_ISSUER}
    assert m.classify(frozenset(), s, "site-deployer-validate") == set()
    assert m.is_surface_label(m.S_FIXTURE_ISSUER) is False


def test_invoke_on_panel_is_not_the_fixture_entry(m):
    """资源维度不许折叠：同一个动作打在 panel 上不是夹具入口。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:InvokeFunction|{s.panel.arn}"}), s) == set()
```

- [ ] **Step 3: 运行，确认它以 import 失败告终**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: FAIL，全部用例在 `_load()` 处报 `FileNotFoundError` / `spec is None`（模块还不存在）。

- [ ] **Step 4: 写最小实现**

创建 `site-builder/scripts/_impersonation_model.py`：

```python
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

GUARD_PROTECTED = "protected"   # stack policy 拦住受保护资源的 Update
GUARD_OPEN = "open"             # 没有 stack policy，或它不拦
GUARD_UNKNOWN = "unknown"       # 解析不出 / 读不到 ⇒ 不出确定结论

CONTROLS_EDGE = "edge-verifier"    # 该栈管理 Edge 验签函数 / 分发
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
    stacks: tuple[StackFact, ...] = ()
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
    return labels


def is_surface_label(label: str) -> bool:
    """这个标签本身是否构成**冒充面成员资格**。

    `sign:fixture-issuer` 是受限冒充（只能签夹具域邮箱）⇒ 带 `sign:` 前缀只为在
    per-label 计数里与其它签名路径排在一起，**不进并集**。
    """
    return label != S_FIXTURE_ISSUER and (label.startswith(SIGN_PREFIX)
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
```

- [ ] **Step 5: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: PASS（8 条）。

- [ ] **Step 6: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/_impersonation_model.py site-builder/deployer/tests/test_impersonation_model.py
git commit -m "feat(3g): 共享冒充判定模型骨架 + 签名侧反例

代码更新与配置更新分成两个动作等价类（UpdateFunctionConfiguration 无 Publish，
Lambda@Edge 不支持 Layer）；函数入口类型是观测值，unknown 不发确定标签。"
```

---

### Task 2: Edge 侧标签（换码 / 发版本 / 新建函数 + 关联）

**Files:**
- Modify: `site-builder/scripts/_impersonation_model.py`
- Test: `site-builder/deployer/tests/test_impersonation_model.py`

**Interfaces:**
- Consumes: Task 1 的 `Surface` / `FnFact` / `classify` / `fake_surface` / `A_*`
- Produces: 标签 `E_PUBLISH_INLINE` `E_PUBLISH_THEN_ASSOCIATE` `E_NEW_FUNCTION`

- [ ] **Step 1: 写失败的测试**

追加到 `site-builder/deployer/tests/test_impersonation_model.py`：

```python
# ---- Edge 侧：必须让 CloudFront 关联到攻击者的代码上 ----------------------------

def test_update_code_alone_cannot_replace_running_edge_code(m):
    """**正向控制**：闸门旧模型（只 `UpdateFunctionCode`）对 Edge 是过度声称。
    CloudFront 必须关联编号版本，而该动作只改 `$LATEST`。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}"}), s) == set()
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}",
                                 f"lambda:PublishVersion|{s.edge.arn}"}), s) == set()


def test_update_config_on_edge_yields_nothing(m):
    """3g 的核心反例：`UpdateFunctionConfiguration(Edge)` + `UpdateDistribution`
    **不是** `edge:code(Publish=True)+associate`——配置更新没有 `Publish`，
    而 Lambda@Edge 不支持 Layer ⇒ 这一组什么都不构成。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:UpdateFunctionConfiguration|{s.edge.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == set()


def test_inline_publish_plus_associate(m):
    """`UpdateFunctionCode(Publish=True)` 一次调用即改码即发版本 ⇒ 把
    `PublishVersion` 当**必需**会少算 principal。"""
    s = m.fake_surface()
    labels = m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}",
                                   f"cloudfront:UpdateDistribution|{s.distribution}"}), s)
    assert labels == {m.E_PUBLISH_INLINE}
    both = m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}",
                                 f"lambda:PublishVersion|{s.edge.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s)
    assert both == {m.E_PUBLISH_INLINE, m.E_PUBLISH_THEN_ASSOCIATE}


def test_new_function_path_does_not_require_publish_version(m):
    """`CreateFunction` 的输入含 `Publish` ⇒ 建函数那条路不需要单独 `PublishVersion`。
    （旧探针要求它，于是只持 CreateFunction+PassRole+UpdateDistribution 的
    principal 被漏掉。）"""
    s = m.fake_surface()
    cand = s.new_candidates[0]
    assert m.classify(frozenset({f"lambda:CreateFunction|{cand}",
                                 f"iam:PassRole|{s.edge_role}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == {m.E_NEW_FUNCTION}


def test_new_function_path_requires_passrole(m):
    """缺 `PassRole` 不成立：新函数得挂一个 Edge 能用的执行角色。"""
    s = m.fake_surface()
    cand = s.new_candidates[0]
    assert m.classify(frozenset({f"lambda:CreateFunction|{cand}",
                                 f"lambda:PublishVersion|{cand}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == set()


def test_each_new_candidate_is_checked_independently(m):
    """两个候选 ARN 是为了缩小"按名字前缀授权"的盲区 ⇒ **任一**成立即算。"""
    s = m.fake_surface()
    for cand in s.new_candidates:
        assert m.classify(frozenset({f"lambda:CreateFunction|{cand}",
                                     f"iam:PassRole|{s.edge_role}",
                                     f"cloudfront:UpdateDistribution|{s.distribution}"}),
                          s) == {m.E_NEW_FUNCTION}, cand


def test_edge_chain_needs_observed_version_entry(m):
    """Edge 入口观测不到时不发确定标签（两个采集方都会在更早处硬失败，
    这条是纯函数层的兜底，不许默认成"能"）。"""
    s = m.replace_fn(m.fake_surface(), "edge", entry=m.ENTRY_UNKNOWN)
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|EDGE",
                                 f"cloudfront:UpdateDistribution|DIST"}), s) == set()


def test_edge_code_rights_do_not_spill_into_signer_hijack(m):
    """资源维度不许折叠，两个方向都测。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == {m.E_PUBLISH_INLINE}
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.auth.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == {m.S_HIJACK_AUTH}
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: FAIL，8 条新用例报 `AttributeError: module has no attribute 'E_PUBLISH_INLINE'`。

- [ ] **Step 3: 写最小实现**

在 `_impersonation_model.py` 的标签区追加：

```python
E_PUBLISH_INLINE = "edge:code(Publish=True)+associate"
E_PUBLISH_THEN_ASSOCIATE = "edge:code+publish+associate"
E_NEW_FUNCTION = "edge:new-function+associate"
```

在 `classify()` 的 `return labels` 之前插入：

```python
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
```

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: PASS（16 条）。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/_impersonation_model.py site-builder/deployer/tests/test_impersonation_model.py
git commit -m "feat(3g): Edge 侧三条等价路径 + 反例

UpdateFunctionConfiguration(Edge) 不再产出 code(Publish=True)；
新建函数那条路去掉 PublishVersion 这个过严前提（CreateFunction 自带 Publish）。"
```

---

### Task 3: CFN 侧标签（guard 三值 + router / deployer 两个栈）

**Files:**
- Modify: `site-builder/scripts/_impersonation_model.py`
- Test: `site-builder/deployer/tests/test_impersonation_model.py`

**Interfaces:**
- Consumes: Task 1/2 的全部
- Produces: 标签 `E_CFN_UPDATE_STACK` `E_CFN_CHANGE_SET` `E_CFN_TEMPLATE_UNANALYZED` `S_CFN_SESSION_KEY_STACK` `S_CFN_SESSION_KEY_UNANALYZED`；辅助 `fake_stack(label, controls, guard, premises_verified) -> StackFact`

- [ ] **Step 1: 写失败的测试**

追加到 `site-builder/deployer/tests/test_impersonation_model.py`：

```python
# ---- CFN 侧：两个栈、guard 三值 ------------------------------------------------

def _router(m, **kw):
    return m.fake_stack("router", controls=frozenset({m.CONTROLS_EDGE}), **kw)


def _deployer(m, **kw):
    return m.fake_stack("deployer", controls=frozenset({m.CONTROLS_SESSION_KEY}), **kw)


def _with(m, *stacks):
    from dataclasses import replace
    return replace(m.fake_surface(), stacks=tuple(stacks))


def test_update_stack_on_open_router_stack_replaces_edge(m):
    """栈已关联 CFN service role ⇒ 调用方自己不需要 `iam:PassRole`。
    没有 stack policy 时单动作即成立。"""
    s = _with(m, _router(m, guard=m.GUARD_OPEN, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}"}), s) \
        == {m.E_CFN_UPDATE_STACK}


def test_stack_policy_closes_the_direct_update_path(m):
    """ADR 0007：router 栈对四个精确逻辑 ID `Deny Update:*` ⇒ 直接更新那条路被挡住。
    **但不等于该 principal 退出了冒充面**：模板层路径未分析 ⇒ 单列标签。"""
    s = _with(m, _router(m, guard=m.GUARD_PROTECTED, premises_verified=True))
    st = s.stacks[0]
    labels = m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}"}), s)
    assert labels == {m.E_CFN_TEMPLATE_UNANALYZED}
    assert m.is_surface_label(m.E_CFN_TEMPLATE_UNANALYZED) is False


def test_set_stack_policy_reopens_the_path(m):
    """越过 stack policy 的门槛就是 `SetStackPolicy`（AWS 文档原话）。"""
    s = _with(m, _router(m, guard=m.GUARD_PROTECTED, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}",
                                 f"cloudformation:SetStackPolicy|{st.resource}"}), s) \
        == {m.E_CFN_UPDATE_STACK}


def test_unknown_guard_never_yields_a_definite_label(m):
    """`GetStackPolicy` 读不到、或策略语法不认识 ⇒ `unknown`。
    **不得**按"没拦住"也不得按"拦住了"解释。"""
    s = _with(m, _router(m, guard=m.GUARD_UNKNOWN, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}"}), s) \
        == {m.E_CFN_TEMPLATE_UNANALYZED}


def test_change_set_chain_needs_both_actions(m):
    """`CreateChangeSet` 单独不够（建了不能执行）；两个都有才等价于 UpdateStack。"""
    s = _with(m, _router(m, guard=m.GUARD_OPEN, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:CreateChangeSet|{st.resource}"}), s) \
        == set()
    assert m.classify(frozenset({f"cloudformation:CreateChangeSet|{st.resource}",
                                 f"cloudformation:ExecuteChangeSet|{st.resource}"}), s) \
        == {m.E_CFN_CHANGE_SET}


def test_change_set_chain_is_also_closed_by_the_guard(m):
    """`ExecuteChangeSet` 没有临时覆盖 stack policy 的选项（ADR 0007）。"""
    s = _with(m, _router(m, guard=m.GUARD_PROTECTED, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:CreateChangeSet|{st.resource}",
                                 f"cloudformation:ExecuteChangeSet|{st.resource}"}), s) \
        == {m.E_CFN_TEMPLATE_UNANALYZED}


def test_deployer_stack_is_a_signing_path(m):
    """两把会话签名 CMK 由 deployer 栈创建（`infra/app.py` 的 `kms.Key`）⇒ 能更新那个栈
    就能改 key policy。它**不是** Edge 路径，标签也不同。"""
    s = _with(m, _deployer(m, guard=m.GUARD_OPEN, premises_verified=True))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}"}), s) \
        == {m.S_CFN_SESSION_KEY_STACK}
    assert m.is_surface_label(m.S_CFN_SESSION_KEY_STACK) is True


def test_unverified_premises_downgrade_to_unanalyzed(m):
    """"拥有 CMK ∧ 无 stack policy"**还不足以**推出"能改 key policy"：
    要看这次更新以谁的身份执行、那个身份是否真能 `kms:PutKeyPolicy`。
    前提未核实 ⇒ 单列，不进并集。"""
    s = _with(m, _deployer(m, guard=m.GUARD_OPEN, premises_verified=False))
    st = s.stacks[0]
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{st.resource}"}), s) \
        == {m.S_CFN_SESSION_KEY_UNANALYZED}
    assert m.is_surface_label(m.S_CFN_SESSION_KEY_UNANALYZED) is False


def test_two_stacks_are_judged_independently(m):
    """资源维度不许折叠：对 router 的更新权不外溢成签名能力，反之亦然。"""
    s = _with(m, _router(m, guard=m.GUARD_OPEN, premises_verified=True),
              _deployer(m, guard=m.GUARD_OPEN, premises_verified=True))
    router, deployer = s.stacks
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{router.resource}"}), s) \
        == {m.E_CFN_UPDATE_STACK}
    assert m.classify(frozenset({f"cloudformation:UpdateStack|{deployer.resource}"}), s) \
        == {m.S_CFN_SESSION_KEY_STACK}
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: FAIL，9 条新用例报 `AttributeError: module has no attribute 'fake_stack'`。

- [ ] **Step 3: 写最小实现**

标签区追加：

```python
# CFN：两条更宽的路。**router 栈自 ADR 0007 起有 stack policy**，所以单动作不再足够。
E_CFN_UPDATE_STACK = "edge:cfn-update-stack"
E_CFN_CHANGE_SET = "edge:cfn-change-set"
# stack policy 挡住的是**受保护资源的直接更新**，不等于关闭了全部 CFN 提权路径
# （service role 权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰那四个资源）。
# ⇒ 这条**不进冒充面并集**，但必须留在视野里、参与漂移比较。
E_CFN_TEMPLATE_UNANALYZED = "edge:cfn-template-unanalyzed"
S_CFN_SESSION_KEY_STACK = "sign:cfn-session-key-stack"
S_CFN_SESSION_KEY_UNANALYZED = "sign:cfn-session-key-stack-unanalyzed"
```

`classify()` 的 `return labels` 之前追加：

```python
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
```

`is_surface_label` 改成按**显式名单**排除（新增标签必须在这里做决定，不能靠前缀猜）：

```python
# **不构成冒充面成员资格**的标签：受限冒充与前提未核实的那几条。
# 它们仍然进 per-label 计数与逐 principal 的集合比较（新增即红），只是不进并集。
NON_SURFACE_LABELS = frozenset({S_FIXTURE_ISSUER, S_CFN_SESSION_KEY_UNANALYZED,
                                E_CFN_TEMPLATE_UNANALYZED})


def is_surface_label(label: str) -> bool:
    return label not in NON_SURFACE_LABELS and (label.startswith(SIGN_PREFIX)
                                                or label.startswith(EDGE_PREFIX))
```

`fake_surface` 下方追加：

```python
def fake_stack(label: str, *, controls: frozenset[str],
               guard: str = GUARD_UNKNOWN, premises_verified: bool = False) -> StackFact:
    """反例用的假栈。`resource` 用标签拼一个不含账号值的假 StackId。"""
    return StackFact(resource=f"STACK_{label.upper()}", label=label, guard=guard,
                     service_role=None, controls=controls,
                     premises_verified=premises_verified)
```

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: PASS（25 条）。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/_impersonation_model.py site-builder/deployer/tests/test_impersonation_model.py
git commit -m "feat(3g): CFN 侧 guard 三值 + router/deployer 两个栈

ADR 0007 之后 UpdateStack 单动作不再等于替换 Edge；protected 下门槛是 SetStackPolicy；
unknown 与前提未核实都落单列的 *-unanalyzed，不进冒充面并集。"
```

---

### Task 4: 聚合层（`summarize` / `ALL_LABELS` / `MITIGATIONS` / 显式未覆盖）

**Files:**
- Modify: `site-builder/scripts/_impersonation_model.py`
- Test: `site-builder/deployer/tests/test_impersonation_model.py`

**Interfaces:**
- Consumes: Task 1-3 的标签与 `is_surface_label`
- Produces: `ALL_LABELS: tuple[str, ...]`、`MITIGATIONS: dict[str, tuple[str, ...]]`、`UNCOVERED_LABELS: dict[str, str]`、`summarize(by_principal: dict[str, set[str]]) -> dict`

- [ ] **Step 1: 写失败的测试**

追加：

```python
# ---- 聚合层 -------------------------------------------------------------------

def test_union_counts_both_classes_and_excludes_non_surface(m):
    """sign 与 edge 两类都进并集；受限/未分析标签单列不进。"""
    agg = m.summarize({
        "p-sign": {m.S_HIJACK_AUTH},
        "p-edge": {m.E_CFN_UPDATE_STACK},
        "p-both": {m.S_KMS_DIRECT, m.E_CFN_CHANGE_SET},
        "p-fixture": {m.S_FIXTURE_ISSUER},
        "p-unanalyzed": {m.E_CFN_TEMPLATE_UNANALYZED},
    })
    assert agg["can_sign"] == 2
    assert agg["can_replace_edge_verifier"] == 2
    assert agg["impersonation_surface_union"] == 3
    assert agg["both"] == 1 and agg["sign_only"] == 1 and agg["edge_only"] == 1
    assert agg["fixture_issuer_holders"] == 1
    assert agg["non_surface_only_holders"] == 2   # 夹具 + 未分析各一个


def test_marginal_value_uses_the_same_membership_predicate(m):
    """进面与离面必须用**同一个**判据。`{kms-direct, fixture-issuer}` 在 KMS 那组关掉后
    真的离开了冒充面；按"还有标签"判会把它算成留下 ⇒ key policy 的收益少报一个。"""
    mv = m.summarize({
        "p-kms": {m.S_KMS_DIRECT},
        "p-kms+hijack": {m.S_KMS_DIRECT, m.S_HIJACK_AUTH},
        "p-cfn": {m.E_CFN_UPDATE_STACK},
        "p-kms+fixture": {m.S_KMS_DIRECT, m.S_FIXTURE_ISSUER},
    })["marginal_value_if_closed"]
    assert mv["restrictive-kms-key-policy"]["principals_removed"] == 2
    # 劫持 signer 那条路**不需要**攻击者自己有 kms:Sign ⇒ key policy 收不掉它。
    assert mv["harden-signer-code-update"]["principals_removed"] == 0
    assert mv["router-stack-policy"]["principals_removed"] == 1


def test_every_label_is_covered_by_a_mitigation_or_declared_uncovered(m):
    """每个标签要么落在某个候选措施里，要么**显式**声明未覆盖并写明理由。

    漏一个的后果是：讨论"关掉哪条路值不值得"时那条路根本不在讨论范围内，而并集里它还在。
    （旧版这条用例的名字里写着 or_declared_uncovered，但没有任何声明机制——名实不符。）
    """
    covered = {lb for group in m.MITIGATIONS.values() for lb in group}
    missing = set(m.ALL_LABELS) - covered - set(m.UNCOVERED_LABELS)
    assert not missing, f"这些路径既没有候选措施也没声明未覆盖：{sorted(missing)}"
    for label, why in m.UNCOVERED_LABELS.items():
        assert label in m.ALL_LABELS, label
        assert len(why) > 10, f"{label} 的未覆盖理由太短，等于没写"


def test_all_labels_is_exhaustive(m):
    """`ALL_LABELS` 必须与模块里定义的标签常量全集一致——漏登记的标签在 per_label
    里不出现，闸门的能力层就少比一项。"""
    defined = {v for k, v in vars(m).items()
               if k.startswith(("S_", "E_")) and isinstance(v, str)
               and (v.startswith(m.SIGN_PREFIX) or v.startswith(m.EDGE_PREFIX))}
    assert defined == set(m.ALL_LABELS)
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: FAIL，4 条新用例报 `AttributeError: module has no attribute 'summarize'`。

- [ ] **Step 3: 写最小实现**

`_impersonation_model.py` 末尾追加：

```python
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
        "（新增 IAM 授权类资源等）尚未分析 ⇒ 没有对应措施，只有"去做那次分析"。",
    S_CFN_SESSION_KEY_UNANALYZED:
        "前提（这次更新以谁的身份执行、那个身份是否真能改 key policy）尚未核实 ⇒ "
        "先核实前提，再谈措施。",
}


def summarize(by_principal: dict[str, set[str]]) -> dict:
    """能力标签 → 聚合结论。**只出计数与集合关系，不出名字。**"""
    def holders(pred) -> set[str]:
        return {arn for arn, ls in by_principal.items() if pred(ls)}

    per_label = {lb: len(holders(lambda ls, lb=lb: lb in ls)) for lb in ALL_LABELS}
    can_sign = holders(lambda ls: any(is_surface_label(l) and l.startswith(SIGN_PREFIX)
                                      for l in ls))
    can_edge = holders(lambda ls: any(is_surface_label(l) and l.startswith(EDGE_PREFIX)
                                      for l in ls))
    surface = can_sign | can_edge
    marginal: dict[str, dict[str, int]] = {}
    for name, closed in MITIGATIONS.items():
        remaining = {arn for arn in surface
                     if {l for l in by_principal[arn] if is_surface_label(l)} - set(closed)}
        marginal[name] = {"closes_paths": len(closed),
                          "surface_after": len(remaining),
                          "principals_removed": len(surface) - len(remaining)}
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
```

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: PASS（29 条）。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/_impersonation_model.py site-builder/deployer/tests/test_impersonation_model.py
git commit -m "feat(3g): 聚合层 + 显式未覆盖声明

进面与离面用同一个判据；UNCOVERED_LABELS 让那条名实不符的用例第一次真的有机制可断言。"
```

---

### Task 5: 变形测试（证明反例集不是摆设）

**Files:**
- Test: `site-builder/deployer/tests/test_impersonation_model.py`

**Interfaces:**
- Consumes: Task 1-4 的全部
- Produces: 无新生产接口（只加元测试）

- [ ] **Step 1: 写测试（这一步的"失败"是变形后原用例仍绿）**

追加：

```python
# ---- 变形/元测试：去掉守卫必须能复现缺陷 -----------------------------------------
#
# 这些用例从**外面**改模型的常量，再断言上面那批反例转红。它们防的是本仓库反复吃到的
# 那类：守卫看着绿，其实什么都没证明。


def _cases_pass(mod) -> bool:
    """把上面那批断言压成一个布尔：任一条不成立就 False。

    只挑**每条变形真正针对**的那几个判定，避免变形测试之间互相遮蔽。
    """
    s = mod.fake_surface()
    from dataclasses import replace
    router_open = replace(s, stacks=(mod.fake_stack(
        "router", controls=frozenset({mod.CONTROLS_EDGE}),
        guard=mod.GUARD_OPEN, premises_verified=True),))
    router_protected = replace(s, stacks=(mod.fake_stack(
        "router", controls=frozenset({mod.CONTROLS_EDGE}),
        guard=mod.GUARD_PROTECTED, premises_verified=True),))
    checks = [
        # 配置更新不等于代码更新（Edge 上什么都不构成）
        mod.classify(frozenset({f"lambda:UpdateFunctionConfiguration|{s.edge.arn}",
                                f"cloudfront:UpdateDistribution|{s.distribution}"}), s)
        == set(),
        # 建函数那条路不需要 PublishVersion
        mod.classify(frozenset({f"lambda:CreateFunction|{s.new_candidates[0]}",
                                f"iam:PassRole|{s.edge_role}",
                                f"cloudfront:UpdateDistribution|{s.distribution}"}), s)
        == {mod.E_NEW_FUNCTION},
        # guard=protected 下直接更新那条路关闭
        mod.classify(frozenset({"cloudformation:UpdateStack|STACK_ROUTER"}),
                     router_protected) == {mod.E_CFN_TEMPLATE_UNANALYZED},
        # guard=open 下成立
        mod.classify(frozenset({"cloudformation:UpdateStack|STACK_ROUTER"}),
                     router_open) == {mod.E_CFN_UPDATE_STACK},
        # change-set 单独不够
        mod.classify(frozenset({"cloudformation:CreateChangeSet|STACK_ROUTER"}),
                     router_open) == set(),
        # 未分析标签不进并集
        mod.summarize({"p": {mod.E_CFN_TEMPLATE_UNANALYZED}})[
            "impersonation_surface_union"] == 0,
    ]
    return all(checks)


def test_the_case_set_passes_unmutated(m):
    assert _cases_pass(m) is True


def test_goes_red_when_code_and_config_are_lumped_together(m):
    """把配置更新并回代码类 ⇒ `UpdateFunctionConfiguration(Edge)` 又会产出 Edge 能力。"""
    m.A_UPDATE_CODE = ("lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration")
    assert _cases_pass(m) is False


def test_goes_red_when_publish_version_is_required_again(m):
    """把 `PublishVersion` 加回新建函数那条路的前提 ⇒ 少算重现。"""
    original = m.classify

    def patched(allowed, s, name=""):
        labels = original(allowed, s, name)
        if m.E_NEW_FUNCTION in labels and not any(
                f"lambda:PublishVersion|{c}" in allowed for c in s.new_candidates):
            labels.discard(m.E_NEW_FUNCTION)
        return labels

    m.classify = patched
    assert _cases_pass(m) is False


def test_goes_red_when_guard_is_ignored(m):
    """把 guard 判据删掉（protected 也算通过）⇒ 假绿重现。"""
    original = m.classify

    def patched(allowed, s, name=""):
        from dataclasses import replace
        opened = replace(s, stacks=tuple(replace(st, guard=m.GUARD_OPEN)
                                         for st in s.stacks))
        return original(allowed, opened, name)

    m.classify = patched
    assert _cases_pass(m) is False


def test_goes_red_when_unanalyzed_labels_enter_the_union(m):
    """把未分析标签并进冒充面 ⇒ 并集断言转红（数字会凭空变大）。"""
    m.NON_SURFACE_LABELS = frozenset({m.S_FIXTURE_ISSUER})
    assert _cases_pass(m) is False


def test_goes_red_when_changeset_chain_needs_only_one_action(m):
    """只要 `CreateChangeSet` 就算 ⇒ "建了不能执行"那条反例转红。"""
    m.A_CFN_EXECUTE_CHANGESET = ("cloudformation:CreateChangeSet",)
    assert _cases_pass(m) is False
```

- [ ] **Step 2: 运行，确认 6 条变形全部按预期红/绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_impersonation_model.py -q`
Expected: PASS（35 条）。

若某条变形测试**失败**（即变形后 `_cases_pass` 仍为 True），说明 `_cases_pass` 里缺少针对该维度的检查
——**修 `_cases_pass`，不要改期望**。

- [ ] **Step 3: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/deployer/tests/test_impersonation_model.py
git commit -m "test(3g): 六条变形测试证明模型反例集不是摆设"
```

---

### Task 6: guard 语义谓词（与 `policy_problems()` 刻意分开的第二个谓词）

**Files:**
- Create: `site-builder/scripts/_stack_policy_guard.py`
- Test: `site-builder/deployer/tests/test_stack_policy_guard.py`

**Interfaces:**
- Consumes: Task 1 的 `GUARD_{PROTECTED,OPEN,UNKNOWN}`
- Produces: `guard_for(policy: dict | None, logical_ids: list[str]) -> str`

- [ ] **Step 1: 写失败的测试**

创建 `site-builder/deployer/tests/test_stack_policy_guard.py`：

```python
"""stack policy 的 **guard 语义谓词**。

**为什么不能用 `router/infrastructure/stack_policy.py` 的 `policy_problems()`**：
那个函数判的是"线上策略是否与本项目规定的形态**等价**"（`verify_deployed_edge.sh` ⑤ 用它），
它的 `covered` 只收 Deny 语句里**字面**的 Resource 串。一份**更严格**的
`Deny Update:* on "*"` 会让 `want - covered` 非空（want 是精确的 LogicalResourceId/<id>）
⇒ 报"没有 Deny 语句覆盖 X"，还会再报一条"Resource 含通配"。
⇒ **`policy_problems() != [] 推不出 guard == "open"`。**

所以闸门用本模块这个目的单一的谓词。两个谓词的职责在各自的 docstring 里互相点名，
防止后来者"统一"掉。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_MODULE = _ROOT / "site-builder" / "scripts" / "_stack_policy_guard.py"
_STACK_POLICY = _ROOT / "router" / "infrastructure" / "stack_policy.py"
IDS = ["OriginRequestFunctionABC", "OriginResponseFunctionDEF",
       "DistributionGHI", "SubdomainMappingTableJKL"]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def g():
    return _load(_MODULE, "_stack_policy_guard")


def _deny(resources, actions=("Update:*",), **extra):
    return {"Statement": [
        {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": list(actions), "Principal": "*",
         "Resource": list(resources), **extra}]}


def test_no_policy_is_open(g):
    assert g.guard_for(None, IDS) == g.GUARD_OPEN


def test_exact_logical_ids_are_protected(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS])
    assert g.guard_for(policy, IDS) == g.GUARD_PROTECTED


def test_stricter_deny_all_is_also_protected(g):
    """这正是 `policy_problems()` 会判成"有问题"的那一份——**它更严格，不是更松**。"""
    assert g.guard_for(_deny(["*"]), IDS) == g.GUARD_PROTECTED
    assert g.guard_for(_deny(["LogicalResourceId/*"]), IDS) == g.GUARD_PROTECTED


def test_prefix_wildcard_must_actually_cover_the_id(g):
    assert g.guard_for(_deny(["LogicalResourceId/OriginRequest*",
                              "LogicalResourceId/OriginResponse*",
                              "LogicalResourceId/Distribution*",
                              "LogicalResourceId/Subdomain*"]), IDS) == g.GUARD_PROTECTED
    # 少一个就不是 protected：漏掉的那个资源照样能被直接更新。
    assert g.guard_for(_deny(["LogicalResourceId/OriginRequest*"]), IDS) == g.GUARD_OPEN


def test_missing_one_id_is_open(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS[:-1]])
    assert g.guard_for(policy, IDS) == g.GUARD_OPEN


def test_narrower_action_set_is_open(g):
    """ADR 0007：Edge 换码是 `Update:Modify`。只拒 Replace/Delete 拦不住它。"""
    assert g.guard_for(_deny([f"LogicalResourceId/{i}" for i in IDS],
                             actions=("Update:Replace", "Update:Delete")),
                       IDS) == g.GUARD_OPEN


def test_modify_replace_delete_triple_is_protected(g):
    """三个都点名 = 与 `Update:*` 等效（`DENIED_ACTIONS` 全集）。"""
    assert g.guard_for(_deny([f"LogicalResourceId/{i}" for i in IDS],
                             actions=("Update:Modify", "Update:Replace", "Update:Delete")),
                       IDS) == g.GUARD_PROTECTED


def test_condition_makes_it_unknown(g):
    """带 Condition 的 Deny 要求求值 ⇒ 本谓词不猜，返回 unknown。"""
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS],
                   Condition={"StringEquals": {"ResourceType": "AWS::Lambda::Function"}})
    assert g.guard_for(policy, IDS) == g.GUARD_UNKNOWN


def test_non_star_principal_is_unknown(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS])
    policy["Statement"][1]["Principal"] = {"AWS": "arn:aws:iam::123456789012:root"}
    assert g.guard_for(policy, IDS) == g.GUARD_UNKNOWN


def test_unparseable_policy_is_unknown(g):
    assert g.guard_for({"Statement": "not-a-list"}, IDS) == g.GUARD_UNKNOWN
    assert g.guard_for({}, IDS) == g.GUARD_UNKNOWN


def test_empty_logical_ids_is_unknown(g):
    """要保护的逻辑 ID 一个都没推出来时，"protected"是无意义的断言。"""
    assert g.guard_for(_deny(["*"]), []) == g.GUARD_UNKNOWN


def test_policy_problems_cannot_be_used_as_the_guard_predicate(g):
    """把上面那条"更严格的 Deny-all"喂给 `policy_problems()`：它**非空**。
    这条用例把两个谓词的差别钉死——将来有人想"统一"就会在这里红。"""
    sp = _load(_STACK_POLICY, "_stack_policy_shape")
    expected = sp.build_policy({cid: lid for (cid, _), lid
                                in zip(sp.PROTECTED_CONSTRUCTS, IDS)})
    problems = sp.policy_problems(_deny(["*"]), expected)
    assert problems, "policy_problems 认为 Deny-all 没问题？那两个谓词就该合并了"
    assert g.guard_for(_deny(["*"]), IDS) == g.GUARD_PROTECTED
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_stack_policy_guard.py -q`
Expected: FAIL，全部用例在 `_load` 处失败（模块不存在）。

- [ ] **Step 3: 写最小实现**

创建 `site-builder/scripts/_stack_policy_guard.py`：

```python
""""这份 stack policy 是否拦住了这些逻辑 ID 的 Update" —— 闸门用的 guard 谓词。

**与 `router/infrastructure/stack_policy.py` 的 `policy_problems()` 是两个谓词，
刻意不合并**：那个判"线上策略与本项目规定的形态是否等价"（部署形态一致性，
`verify_deployed_edge.sh` ⑤ 用它），一份**更严格**的 `Deny Update:* on "*"` 会让它
返回非空 ⇒ 拿它当 guard 会把"更严格"读成"没保护"。本模块只回答闸门要的那一个问题，
且**三值**：判不出就是 `unknown`，不许按"没拦住"解释（那是 3g 要修的假绿形状）。
"""
from __future__ import annotations

import fnmatch

GUARD_PROTECTED = "protected"
GUARD_OPEN = "open"
GUARD_UNKNOWN = "unknown"

# `Update:*` 的展开（与 stack_policy.DENIED_ACTIONS 同一集合；这里独立写一份是因为
# 本模块不 import 那个文件——它属于 router 包，闸门不该为一个常量拖进 CDK 侧的依赖。
# 两处不一致时 test_stack_policy_guard 里那条对账用例会红）。
DENIED_ACTIONS = ("Update:Modify", "Update:Replace", "Update:Delete")


def _as_list(v) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def _covers(resource_pattern: str, logical_id: str) -> bool:
    """Deny 的一个 Resource 串是否覆盖这个逻辑 ID。

    接受三种形态：`*`、`LogicalResourceId/<id>` 逐字、`LogicalResourceId/<前缀>*`。
    """
    target = f"LogicalResourceId/{logical_id}"
    return resource_pattern == "*" or fnmatch.fnmatchcase(target, resource_pattern)


def guard_for(policy: dict | None, logical_ids: list[str]) -> str:
    """→ `protected` / `open` / `unknown`。

    `protected` 的判据（全部满足）：存在 Deny 语句，`Action` 含 `Update:*` 或覆盖
    `DENIED_ACTIONS` 全集，`Principal` 为 `*`，`Resource` 覆盖**每一个** `logical_ids`，
    且该语句**没有 Condition**。任何解析不动的形态一律 `unknown`。
    """
    if policy is None:
        return GUARD_OPEN
    if not logical_ids:
        # 要保护什么都没推出来 ⇒ "已保护"是个无意义的断言。
        return GUARD_UNKNOWN
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        return GUARD_UNKNOWN
    covered: set[str] = set()
    for st in statements:
        if not isinstance(st, dict):
            return GUARD_UNKNOWN
        if st.get("Effect") != "Deny":
            continue
        if st.get("Condition"):
            # 求值 Condition 就是造分析器 ⇒ 不猜。
            return GUARD_UNKNOWN
        if st.get("Principal") != "*":
            return GUARD_UNKNOWN
        actions = set(_as_list(st.get("Action")))
        if "Update:*" not in actions and not set(DENIED_ACTIONS) <= actions:
            continue
        patterns = _as_list(st.get("Resource"))
        covered |= {lid for lid in logical_ids
                    if any(_covers(p, lid) for p in patterns)}
    return GUARD_PROTECTED if covered >= set(logical_ids) else GUARD_OPEN
```

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_stack_policy_guard.py -q`
Expected: PASS（13 条）。

- [ ] **Step 5: 在 `policy_problems()` 上加反向指针**

Modify `router/infrastructure/stack_policy.py`，在 `policy_problems` 的 docstring 末尾追加一行：

```python
    **这不是 guard 谓词。** 它判"与本项目规定的形态是否等价"：一份更严格的
    `Deny Update:* on "*"` 在这里是"有问题"。闸门要回答"这些逻辑 ID 的 Update 被拦住了吗"
    时用 `site-builder/scripts/_stack_policy_guard.guard_for()`（三值）。两者刻意分开。
```

- [ ] **Step 6: 跑 router 单测确认没碰坏**

Run: `cd /Users/kentpeng/projects/quick-app/router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: PASS（只改了 docstring）。

- [ ] **Step 7: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/_stack_policy_guard.py site-builder/deployer/tests/test_stack_policy_guard.py router/infrastructure/stack_policy.py
git commit -m "feat(3g): guard 语义谓词（三值），与 policy_problems 刻意分开

policy_problems 对更严格的 Deny-all 返回非空 ⇒ 它推不出 open。
一条对账用例把两个谓词的差别钉死，两处 docstring 互相点名。"
```

---

### Task 7: 探针改用共享模型（含 guard / 两个栈的观测）

**Files:**
- Modify: `site-builder/scripts/probe_impersonation_surface.py`
- Modify: `site-builder/deployer/tests/test_probe_impersonation_surface.py`

**Interfaces:**
- Consumes: Task 1-6 的 `_impersonation_model`（`classify` / `summarize` / `Surface` / `FnFact` / `StackFact` / `MITIGATIONS`）、`_stack_policy_guard.guard_for`
- Produces: `discover(gate, clients, region, account) -> model.Surface`；`sim_groups(s) -> tuple[tuple[list[str], list[str]], ...]`；`self_test()` 改为委托共享用例

- [ ] **Step 1: 写失败的测试**

改写 `site-builder/deployer/tests/test_probe_impersonation_surface.py`：**删掉**已迁到共享模块的判定用例
（`test_resource_dimension_is_not_collapsed`、`test_single_action_is_not_a_capability_for_edge`、
`test_publish_inline_does_not_require_publish_version`、`test_sign_on_either_key_counts`、
`test_direct_invoke_of_the_auth_function_is_the_fixture_issuer_entry`、
`test_fixture_issuer_is_a_label_and_has_a_candidate_mitigation`、
`test_every_label_is_covered_by_a_mitigation_or_declared_uncovered`、三条 `test_self_test_goes_red_*`），
**保留** `test_script_exists_and_is_tracked`、`test_script_self_test_passes`、
`test_the_two_real_cmks_come_from_config_not_a_placeholder_arn`、
`test_evidence_file_carries_no_account_id_or_role_names`，并追加：

```python
def test_probe_does_not_carry_its_own_judgement(probe):
    """判定必须来自共享模型：探针里不许再有第二份 `classify` 定义。

    这条防的是"对齐"退化成"复制"——复制之后两边会各自漂移，而漂移的那一边正是
    给假绿的那一边（3g 的成因）。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "def classify(" not in src, "探针里又有一份 classify 定义"
    assert "_impersonation_model" in src, "探针没有 import 共享模型"
    assert probe.classify is probe.model.classify


def test_self_test_delegates_to_the_shared_cases(probe, capsys):
    """`--self-test` 的用例来自共享模块 ⇒ 改模型只会改一处，两个消费方都会红。"""
    assert probe.self_test() == 0
    out = capsys.readouterr().out
    assert "共享模型" in out


def test_stale_no_stack_policy_claim_is_gone(probe):
    """ADR 0007 之后"router 栈无 stack policy"是过期说法，源码里不许再出现。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "无 stack policy" not in src, "过期前提还在源码注释里"


def test_discover_observes_guard_and_both_stacks(probe, monkeypatch):
    """`discover()` 必须**观测** guard 与两个栈，不许假设。"""
    calls = {}

    class FakeCfn:
        def get_stack_policy(self, StackName):
            calls.setdefault("policies", []).append(StackName)
            return {"StackPolicyBody": '{"Statement":[]}'}

        def describe_stacks(self, StackName):
            return {"Stacks": [{"StackId": f"arn:aws:cloudformation:r:1:stack/{StackName}/x",
                                "RoleARN": "arn:aws:iam::1:role/cfn-exec"}]}

        def describe_stack_resources(self, StackName):
            return {"StackResources": []}

    monkeypatch.setattr(probe, "_stack_facts",
                        lambda *a, **k: (probe.model.StackFact(
                            resource="S1", label="router",
                            guard=probe.model.GUARD_PROTECTED,
                            controls=frozenset({probe.model.CONTROLS_EDGE}),
                            premises_verified=True),
                            probe.model.StackFact(
                            resource="S2", label="deployer",
                            guard=probe.model.GUARD_OPEN,
                            controls=frozenset({probe.model.CONTROLS_SESSION_KEY}),
                            premises_verified=False)))
    facts = probe._stack_facts(FakeCfn(), "r", "1")
    labels = {f.label for f in facts}
    assert labels == {"router", "deployer"}, labels
    assert all(f.guard in (probe.model.GUARD_PROTECTED, probe.model.GUARD_OPEN,
                           probe.model.GUARD_UNKNOWN) for f in facts)
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_probe_impersonation_surface.py -q`
Expected: FAIL — `test_probe_does_not_carry_its_own_judgement` 报 "探针里又有一份 classify 定义"。

- [ ] **Step 3: 改探针**

1. 在 `_HERE` 定义之后追加 import（与闸门同一套 sys.path 写法）：

```python
if str(_HERE) not in sys.path:      # 测试用 spec_from_file_location 加载本文件时本目录不在 sys.path
    sys.path.insert(0, str(_HERE))
import _impersonation_model as model              # noqa: E402
from _stack_policy_guard import guard_for         # noqa: E402

# 判定与聚合**不在本文件**：共享模型见 `_impersonation_model.py`，反例集见
# `deployer/tests/test_impersonation_model.py`。这里只负责把观测填出来。
classify = model.classify
summarize = model.summarize
MITIGATIONS = model.MITIGATIONS
ALL_LABELS = model.ALL_LABELS
```

2. **删除**本文件里的 `Surface` 类、`classify`、`is_surface_label`、`summarize`、
   `MITIGATIONS`、全部 `S_*` / `E_*` / `A_*` 常量定义、`_fake_surface`，以及 `self_test()` 里那张
   `cases` 表（判定用例已迁到共享测试）。模块 docstring 里"两个方向都错"那段改写成指向共享模型：

```python
## 判定不在本文件

`classify()` 与聚合口径住在 `_impersonation_model.py`（闸门也 import 同一份），
反例集在 `deployer/tests/test_impersonation_model.py`。本文件只做两件事：
**观测**（真机拼出 `Surface`）与**报告**（聚合计数落 tracked 证据）。
```

3. `self_test()` 改成：

```python
def self_test() -> int:
    """委托共享模型的聚合断言，并打印它来自哪里。

    **判定层的反例不在这里**：它们在 `deployer/tests/test_impersonation_model.py`
    （pytest 会真的跑到），本函数只做一次"共享模型能 import 且聚合口径正常"的冒烟。
    """
    print("判定与聚合来自共享模型 _impersonation_model.py"
          "（反例集：deployer/tests/test_impersonation_model.py）")
    agg = model.summarize({
        "p-sign": {model.S_HIJACK_AUTH},
        "p-edge": {model.E_CFN_UPDATE_STACK},
        "p-both": {model.S_KMS_DIRECT, model.E_CFN_CHANGE_SET},
        "p-fixture": {model.S_FIXTURE_ISSUER},
        "p-unanalyzed": {model.E_CFN_TEMPLATE_UNANALYZED},
    })
    want = {"can_sign": 2, "can_replace_edge_verifier": 2,
            "impersonation_surface_union": 3, "both": 1,
            "fixture_issuer_holders": 1, "non_surface_only_holders": 2}
    bad = {k: (agg[k], v) for k, v in want.items() if agg[k] != v}
    print(f"  {'ok  ' if not bad else 'FAIL'} 聚合：两类进并集，受限/未分析单列不进")
    if bad:
        print(f"       {bad}", file=sys.stderr)
        return 1
    return 0
```

4. 新增 `_stack_facts()` 并在 `discover()` 里调用：

```python
def _stack_facts(cfn, region: str, account: str) -> tuple[model.StackFact, ...]:
    """两个栈的**观测**事实：guard、service role、控制什么、前提是否核实。

    router 栈名来自 `router/config.ini`；deployer 栈名从平台函数的
    `aws:cloudformation:stack-name` tag 反查（与闸门 `edge_asset_location` 同一手法）。
    """
    facts: list[model.StackFact] = []
    for label, stack_name, logical_ids, controls in _stack_targets(cfn):
        body = cfn.get_stack_policy(StackName=stack_name).get("StackPolicyBody")
        policy = json.loads(body) if body else None
        described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        facts.append(model.StackFact(
            resource=described["StackId"],
            label=label,
            guard=guard_for(policy, logical_ids),
            service_role=described.get("RoleARN"),
            controls=controls,
            # **前提核实留到后续任务**：本轮只把"谁执行这次更新"观测出来；
            # "那个身份是否真能改目标资源"还没核 ⇒ 一律 False，判定会落 *-unanalyzed。
            premises_verified=False))
    return tuple(facts)
```

`_stack_targets(cfn)` 返回 `(label, stack_name, logical_ids, controls)` 四元组：
router 用 `router/config.ini` 的 `[CDK] stack_name` + `describe_stack_resources` 里
Edge 两函数/分发/路由表的 `LogicalResourceId`（controls = `{CONTROLS_EDGE}`）；
deployer 用平台函数 tag 反查的栈名 + 两把 CMK 的 `LogicalResourceId`
（controls = `{CONTROLS_SESSION_KEY}`，logical_ids 给 guard 判"CMK 是否被 stack policy 保护"）。

5. `discover()` 的 `return Surface(...)` 改成返回 `model.Surface`：

```python
    return model.Surface(
        kms_keys=session_key_arns(),
        auth=model.FnFact(fn("site-auth-service"), entry=model.ENTRY_LATEST,
                          layers_supported=True),
        panel=model.FnFact(fn("site-panel"), entry=model.ENTRY_LATEST,
                           layers_supported=True),
        # Lambda@Edge **不支持 Layer**（AWS 文档）⇒ 改配置不等于任意代码执行。
        # `entry` 由上面那段 association 观测硬保证是编号版本。
        edge=model.FnFact(fn(edge_fn), entry=model.ENTRY_VERSION,
                          layers_supported=False),
        new_candidates=(fn("probe-placeholder-new-function"),
                        fn(f"{stack_name}-probe-placeholder")),
        distribution=f"arn:aws:cloudfront::{account}:distribution/{dist_id}",
        edge_role=edge_role,
        stacks=_stack_facts(clients["cloudformation"], region, account))
```

6. `Surface.groups()` 迁成本文件的 `sim_groups(s)`，并补上新动作与新资源：

```python
def sim_groups(s: model.Surface) -> tuple[tuple[list[str], list[str]], ...]:
    """按服务分组批量模拟。跨服务混在一条调用里会产生大量无意义的 action×resource
    组合（都是 implicitDeny），既慢又难读。"""
    fns = [s.edge.arn, s.auth.arn, s.panel.arn, *s.new_candidates]
    return (
        (list(model.A_KMS_SIGN + model.A_KMS_SELF_AUTHORIZE), list(s.kms_keys)),
        (list(model.A_UPDATE_CODE + model.A_UPDATE_CONFIG + model.A_PUBLISH_VERSION
              + model.A_CREATE_FUNCTION + model.A_INVOKE), fns),
        (list(model.A_CF_WRITE), [s.distribution]),
        (list(model.A_CFN_UPDATE + model.A_CFN_CREATE_CHANGESET
              + model.A_CFN_EXECUTE_CHANGESET + model.A_CFN_SET_POLICY),
         [st.resource for st in s.stacks]),
        (list(model.A_PASSROLE),
         [s.edge_role, *(st.service_role for st in s.stacks if st.service_role)]),
    )
```

`simulate_all` 里原来调用 `s.groups()` 的地方改成 `sim_groups(s)`。

- [ ] **Step 4: 运行，确认全绿**

Run:
```bash
cd /Users/kentpeng/projects/quick-app/site-builder/deployer
.venv/bin/pytest tests/test_probe_impersonation_surface.py tests/test_impersonation_model.py -q
```
Expected: PASS。

- [ ] **Step 5: 跑探针自检（不碰 AWS）**

Run: `cd /Users/kentpeng/projects/quick-app && python3 site-builder/scripts/probe_impersonation_surface.py --self-test`
Expected: 退出 0，打印"判定与聚合来自共享模型"。

- [ ] **Step 6: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/probe_impersonation_surface.py site-builder/deployer/tests/test_probe_impersonation_surface.py
git commit -m "refactor(3g): 探针改用共享模型，并观测 guard 与两个栈

删掉本地 classify/Surface/标签定义（判定只剩一份）；删掉 ADR 0007 之后过期的
「router 栈无 stack policy」；新增 deployer 栈与 service role 观测。"
```

---

### Task 8: 闸门 grant 词表（重命名 + 新增动作/资源类）

**Files:**
- Modify: `site-builder/scripts/verify_account_trust_boundary.py`
- Test: `site-builder/deployer/tests/test_verify_account_trust_boundary.py`

**Interfaces:**
- Consumes: Task 1-6
- Produces: `G_UPDATE_CODE="update-fn-code"`、`G_UPDATE_CONFIG="update-fn-config"`、`G_PUBLISH_VERSION="publish-fn-version"`、`G_CREATE_FN="create-fn"`、`G_UPDATE_DISTRIBUTION="update-distribution"`、`G_CFN_UPDATE="cfn-update-stack"`、`G_CFN_CREATE_CHANGESET="cfn-create-change-set"`、`G_CFN_EXECUTE_CHANGESET="cfn-execute-change-set"`、`G_CFN_SET_POLICY="cfn-set-stack-policy"`、`G_PASSROLE="pass-role"`；扩展后的 `Targets`（新字段 `distribution` / `edge_role` / `new_fn_candidates` / `stacks` / `service_roles`）

- [ ] **Step 1: 写失败的测试**

追加到 `site-builder/deployer/tests/test_verify_account_trust_boundary.py`：

```python
def test_replace_platform_code_grant_is_renamed(gate):
    """`replace-platform-code` 声称"已能替换正在执行的代码"，对 Edge 与挂 alias 的函数
    都不成立（3g）。grant 层只说动作事实：**能改 `$LATEST` 的代码**。"""
    src = (_ROOT / "site-builder" / "scripts"
           / "verify_account_trust_boundary.py").read_text(encoding="utf-8")
    assert "replace-platform-code" not in src
    assert gate.G_UPDATE_CODE == "update-fn-code"


def test_grants_cover_the_new_action_classes(gate):
    """新动作各自成 grant：合并任何两条都会让对应的扩权静静地绿。"""
    t = gate.Targets(
        platform_functions=("arn:aws:lambda:r:1:function:site-auth-service",),
        site_functions=(),
        distribution="arn:aws:cloudfront::1:distribution/D1",
        edge_role="arn:aws:iam::1:role/edge",
        new_fn_candidates=("arn:aws:lambda:r:1:function:probe-new",),
        stacks=(gate.model.StackFact(resource="S_ROUTER", label="router",
                                     guard=gate.model.GUARD_OPEN,
                                     controls=frozenset({gate.model.CONTROLS_EDGE})),),
        service_roles=("arn:aws:iam::1:role/cfn-exec",))
    fn = t.platform_functions[0]
    decisions = {
        f"lambda:UpdateFunctionCode|{fn}": "allowed",
        f"lambda:UpdateFunctionConfiguration|{fn}": "allowed",
        f"lambda:PublishVersion|{fn}": "allowed",
        f"lambda:CreateFunction|{t.new_fn_candidates[0]}": "allowed",
        f"cloudfront:UpdateDistribution|{t.distribution}": "allowed",
        "cloudformation:UpdateStack|S_ROUTER": "allowed",
        "cloudformation:CreateChangeSet|S_ROUTER": "allowed",
        "cloudformation:ExecuteChangeSet|S_ROUTER": "allowed",
        "cloudformation:SetStackPolicy|S_ROUTER": "allowed",
        f"iam:PassRole|{t.edge_role}": "allowed",
    }
    grants = gate.grants_from_decisions(decisions, t)
    assert grants == {
        "update-fn-code:site-auth-service",
        "update-fn-config:site-auth-service",
        "publish-fn-version:site-auth-service",
        "create-fn:probe-new",
        "update-distribution",
        "cfn-update-stack:router",
        "cfn-create-change-set:router",
        "cfn-execute-change-set:router",
        "cfn-set-stack-policy:router",
        "pass-role:edge",
    }, sorted(grants)


def test_change_set_actions_are_two_separate_grants(gate):
    """`all()` 组合属于能力层。grant 层合成一条会让"只有 CreateChangeSet"与
    "两个都有"在基线里长得一样。"""
    t = gate.Targets(platform_functions=(), site_functions=(),
                     stacks=(gate.model.StackFact(resource="S_ROUTER", label="router"),))
    only_create = gate.grants_from_decisions(
        {"cloudformation:CreateChangeSet|S_ROUTER": "allowed"}, t)
    assert only_create == {"cfn-create-change-set:router"}


def test_stack_grants_carry_the_logical_label_not_the_stack_id(gate):
    """StackId 含账号 ID（仓库红线）⇒ grant 串里只许出现逻辑标签。"""
    t = gate.Targets(
        platform_functions=(), site_functions=(),
        stacks=(gate.model.StackFact(
            resource="arn:aws:cloudformation:us-east-1:123456789012:stack/Foo/abc",
            label="router"),))
    grants = gate.grants_from_decisions(
        {f"cloudformation:UpdateStack|{t.stacks[0].resource}": "allowed"}, t)
    assert grants == {"cfn-update-stack:router"}
    assert not any("123456789012" in g for g in grants)


def test_action_class_names_cover_every_simulated_action(gate):
    """coverage 的成员按**动作等价类**记 ⇒ 新动作漏登记会让它落进一个空类名。"""
    for action in gate.ACTIONS:
        assert action in gate.ACTION_CLASS_NAMES, action


def test_new_resource_classes_are_stable_and_account_free(gate):
    """coverage 的资源类名不许含账号值，且新资源不能全落进 `other`。"""
    t = gate.Targets(
        platform_functions=(), site_functions=(),
        distribution="arn:aws:cloudfront::123456789012:distribution/D1",
        edge_role="arn:aws:iam::123456789012:role/edge",
        new_fn_candidates=("arn:aws:lambda:r:123456789012:function:probe-new",),
        stacks=(gate.model.StackFact(
            resource="arn:aws:cloudformation:r:123456789012:stack/Foo/abc",
            label="router"),),
        service_roles=("arn:aws:iam::123456789012:role/cfn-exec",))
    got = {gate.undecided_resource_class(r, t) for r in
           (t.distribution, t.edge_role, t.new_fn_candidates[0],
            t.stacks[0].resource, t.service_roles[0])}
    assert got == {"distribution", "role:edge", "fn:new-candidate",
                   "stack:router", "role:cfn-service"}, sorted(got)
    assert not any("123456789012" in c for c in got)
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -k "renamed or new_action or change_set_actions or logical_label or class_names or resource_classes"`
Expected: FAIL（`G_UPDATE_CODE` 不存在 / `Targets` 没有 `distribution` 字段）。

- [ ] **Step 3: 改闸门**

1. 模块 import 区（`_secure_write` 那行之后）追加：

```python
import _impersonation_model as model              # noqa: E402
from _stack_policy_guard import guard_for         # noqa: E402
```

2. grant 词表：把 `G_REPLACE_CODE` 换成下面这组（**注释说明为什么改名**）：

```python
# 3g：旧名 `replace-platform-code` 声称"已能替换正在执行的代码"。那对 Edge 不成立
# （CloudFront 关联编号版本，本动作只改 `$LATEST`），对挂 alias 的函数也不成立。
# grant 层只说**动作事实**，"这些授权能组成哪条路"交给能力层。
G_UPDATE_CODE = "update-fn-code"            # + ":<函数名>"
G_UPDATE_CONFIG = "update-fn-config"        # + ":<函数名>"
G_PUBLISH_VERSION = "publish-fn-version"    # + ":<函数名>"
G_CREATE_FN = "create-fn"                   # + ":<候选函数名>"
G_UPDATE_DISTRIBUTION = "update-distribution"
G_CFN_UPDATE = "cfn-update-stack"                  # + ":<栈逻辑标签>"
# **两条分开**：`all()` 组合属于能力层；合成一条会让"只有 CreateChangeSet"与"两个都有"
# 在基线里长得一样。
G_CFN_CREATE_CHANGESET = "cfn-create-change-set"   # + ":<栈逻辑标签>"
G_CFN_EXECUTE_CHANGESET = "cfn-execute-change-set" # + ":<栈逻辑标签>"
G_CFN_SET_POLICY = "cfn-set-stack-policy"          # + ":<栈逻辑标签>"
G_PASSROLE = "pass-role"                           # + ":<角色类>"
```

3. 动作等价类：删掉 `A_REPLACE`，改用共享模型的常量（**不再手抄第二份**）：

```python
# 动作等价类**全部来自共享模型**（3g）：闸门与探针各抄一份就是 3g 的成因。
A_INVOKE = model.A_INVOKE
A_UPDATE_CODE = model.A_UPDATE_CODE
A_UPDATE_CONFIG = model.A_UPDATE_CONFIG
A_PUBLISH_VERSION = model.A_PUBLISH_VERSION
A_CREATE_FUNCTION = model.A_CREATE_FUNCTION
A_CF_WRITE = model.A_CF_WRITE
A_CFN_UPDATE = model.A_CFN_UPDATE
A_CFN_CREATE_CHANGESET = model.A_CFN_CREATE_CHANGESET
A_CFN_EXECUTE_CHANGESET = model.A_CFN_EXECUTE_CHANGESET
A_CFN_SET_POLICY = model.A_CFN_SET_POLICY
A_PASSROLE = model.A_PASSROLE
A_KMS_SIGN = model.A_KMS_SIGN
A_KMS_SELF_AUTHORIZE = model.A_KMS_SELF_AUTHORIZE
```
（`A_READ_PARAM` 保留原样——SSM 只是 login-flow 的读面，不在共享模型里。）

4. `ACTION_CLASS_NAMES` 追加新类名（`replace-code` → `update-fn-code`）：

```python
ACTION_CLASS_NAMES = {
    **{a: "invoke" for a in A_INVOKE},
    **{a: "update-fn-code" for a in A_UPDATE_CODE},
    **{a: "update-fn-config" for a in A_UPDATE_CONFIG},
    **{a: "publish-version" for a in A_PUBLISH_VERSION},
    **{a: "create-function" for a in A_CREATE_FUNCTION},
    **{a: "update-distribution" for a in A_CF_WRITE},
    **{a: "cfn-update" for a in A_CFN_UPDATE},
    **{a: "cfn-create-change-set" for a in A_CFN_CREATE_CHANGESET},
    **{a: "cfn-execute-change-set" for a in A_CFN_EXECUTE_CHANGESET},
    **{a: "cfn-set-stack-policy" for a in A_CFN_SET_POLICY},
    **{a: "pass-role" for a in A_PASSROLE},
    **{a: "read-param" for a in A_READ_PARAM},
    **{a: "kms-sign" for a in A_KMS_SIGN},
    **{a: "kms-self-authorize" for a in A_KMS_SELF_AUTHORIZE},
}
```

5. `Targets` 新增字段与访问器：

```python
    # 3g 新增的资源等价类。空值 = 本轮不探（`--from-dump` 的旧快照也走这条）。
    distribution: str = ""
    edge_role: str = ""
    new_fn_candidates: tuple[str, ...] = ()
    stacks: tuple = ()                      # tuple[model.StackFact, ...]
    service_roles: tuple[str, ...] = ()

    def publish_resources(self) -> list[str]:
        """发布/建函数那一腿的资源：Edge 两函数 + 候选 ARN。
        **不与全部 alias/版本做笛卡尔积**——那两个动作在别的资源上不携带信号。"""
        return sorted(set(self.platform_functions) | set(self.new_fn_candidates))

    def misc_resources(self) -> list[str]:
        """CFN / CloudFront / PassRole 合成一腿：动作 6 个、资源 ~5 个 ⇒ 响应体很小。"""
        return sorted({st.resource for st in self.stacks}
                      | ({self.distribution} if self.distribution else set())
                      | ({self.edge_role} if self.edge_role else set())
                      | set(self.service_roles))
```

6. `grants_from_decisions` 的平台函数循环里，把
`if allowed(A_REPLACE, (arn,)): grants.add(f"{G_REPLACE_CODE}:{name}")` 换成：

```python
        # 三个动作各自成 grant（alias/version 没有自己的代码，所以只对未限定 ARN 问）。
        for actions, kind in ((A_UPDATE_CODE, G_UPDATE_CODE),
                              (A_UPDATE_CONFIG, G_UPDATE_CONFIG),
                              (A_PUBLISH_VERSION, G_PUBLISH_VERSION)):
            if allowed(actions, (arn,)):
                grants.add(f"{kind}:{name}")
```

并在 KMS 那段之前追加：

```python
    for cand in t.new_fn_candidates:
        if allowed(A_CREATE_FUNCTION, (cand,)):
            grants.add(f"{G_CREATE_FN}:{_fn_name(cand)}")
    if t.distribution and allowed(A_CF_WRITE, (t.distribution,)):
        grants.add(G_UPDATE_DISTRIBUTION)
    for st in t.stacks:
        for actions, kind in ((A_CFN_UPDATE, G_CFN_UPDATE),
                              (A_CFN_CREATE_CHANGESET, G_CFN_CREATE_CHANGESET),
                              (A_CFN_EXECUTE_CHANGESET, G_CFN_EXECUTE_CHANGESET),
                              (A_CFN_SET_POLICY, G_CFN_SET_POLICY)):
            if allowed(actions, (st.resource,)):
                # **逻辑标签**进 grant，StackId 不进（它含账号 ID）。
                grants.add(f"{kind}:{st.label}")
    for role, cls in ([(t.edge_role, "edge")] if t.edge_role else []) \
            + [(r, "cfn-service") for r in t.service_roles]:
        if allowed(A_PASSROLE, (role,)):
            grants.add(f"{G_PASSROLE}:{cls}")
```

7. `undecided_resource_class` 在 lambda 分支**之前**插入新资源类判定：

```python
    if t.distribution and resource == t.distribution:
        return "distribution"
    if t.edge_role and resource == t.edge_role:
        return "role:edge"
    if resource in t.service_roles:
        return "role:cfn-service"
    if resource in t.new_fn_candidates:
        return "fn:new-candidate"
    for st in t.stacks:
        if resource == st.resource:
            return f"stack:{st.label}"
```

8. `ACTIONS_FUNCTION` / `ACTIONS_OTHER` 与新腿常量：

```python
ACTIONS_FUNCTION = A_INVOKE + A_UPDATE_CODE + A_UPDATE_CONFIG
ACTIONS_PUBLISH = A_PUBLISH_VERSION + A_CREATE_FUNCTION
ACTIONS_MISC = (A_CFN_UPDATE + A_CFN_CREATE_CHANGESET + A_CFN_EXECUTE_CHANGESET
                + A_CFN_SET_POLICY + A_CF_WRITE + A_PASSROLE)
ACTIONS_OTHER = A_READ_PARAM + A_KMS_SIGN + A_KMS_SELF_AUTHORIZE
ACTIONS = ACTIONS_FUNCTION + ACTIONS_PUBLISH + ACTIONS_MISC + ACTIONS_OTHER
```

- [ ] **Step 4: 运行，确认新用例绿、旧用例的 grant 名字期望同步更新**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q`
Expected: 先会看到一批旧用例因为 `replace-platform-code` 字面量而红。**逐条把期望改成新名字**
（`grep -n "replace-platform-code\|replace-code" tests/test_verify_account_trust_boundary.py`），
不要改判定。改完全绿。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/verify_account_trust_boundary.py site-builder/deployer/tests/test_verify_account_trust_boundary.py
git commit -m "feat(3g): 闸门 grant 词表对齐动作事实 + 新增 CFN/CloudFront/PassRole 资源类

replace-platform-code → update-fn-code（不再声称已能替换正在执行的代码）；
change-set 两个动作分开记；栈只落逻辑标签；动作等价类改为 import 共享模型。"
```

---

### Task 9: 闸门采集层（新腿 + 观测 guard / 栈 / 入口类型）

**Files:**
- Modify: `site-builder/scripts/verify_account_trust_boundary.py`
- Test: `site-builder/deployer/tests/test_verify_account_trust_boundary.py`

**Interfaces:**
- Consumes: Task 8 的 `Targets` 与 `ACTIONS_*`
- Produces: `SIM_LEGS_PER_PRINCIPAL = 3 + len(KMS_MESSAGE_TYPES)`；`router_and_deployer_stacks(clients, lam, platform) -> tuple[model.StackFact, ...]`；`measure()` 产出的 bundle 新增 `model_inputs` 分节

- [ ] **Step 1: 写失败的测试**

追加：

```python
def test_sim_legs_constant_matches_the_calls_simulate_makes(gate):
    """腿数常量写死会在加/减一腿时静静说谎（进度输出报的就是它）。"""
    calls = []

    class FakeIam:
        def get_paginator(self, _name):
            outer = self

            class P:
                def paginate(self, **kw):
                    outer_calls = calls
                    outer_calls.append(kw)
                    return iter([{"EvaluationResults": []}])
            return P()

    t = gate.Targets(
        platform_functions=("arn:aws:lambda:r:1:function:site-auth-service",),
        site_functions=(),
        kms_keys={"site-rs-v1": "arn:aws:kms:r:1:key/k1"},
        distribution="arn:aws:cloudfront::1:distribution/D1",
        edge_role="arn:aws:iam::1:role/edge",
        new_fn_candidates=("arn:aws:lambda:r:1:function:probe-new",),
        stacks=(gate.model.StackFact(resource="S_ROUTER", label="router"),),
        service_roles=("arn:aws:iam::1:role/cfn-exec",),
        login_flow_parameter="arn:aws:ssm:r:1:parameter/lf")
    gate.simulate(FakeIam(), "arn:aws:iam::1:role/x", t)
    assert len(calls) == gate.SIM_LEGS_PER_PRINCIPAL, \
        f"{len(calls)} 腿 != 常量 {gate.SIM_LEGS_PER_PRINCIPAL}"


def test_publish_leg_is_not_crossed_with_every_alias(gate):
    """裁剪按**模型消费面**：`PublishVersion` / `CreateFunction` 不与全部 alias、
    版本 ARN 做笛卡尔积。"""
    t = gate.Targets(
        platform_functions=("arn:aws:lambda:r:1:function:p",),
        site_functions=("arn:aws:lambda:r:1:function:s",),
        alias_arns={"arn:aws:lambda:r:1:function:s":
                    ("arn:aws:lambda:r:1:function:s:blue",)},
        new_fn_candidates=("arn:aws:lambda:r:1:function:probe-new",))
    assert "arn:aws:lambda:r:1:function:s:blue" not in t.publish_resources()
    assert set(t.publish_resources()) == {"arn:aws:lambda:r:1:function:p",
                                          "arn:aws:lambda:r:1:function:probe-new"}


def test_model_inputs_records_guard_and_entry_kinds(gate):
    """`model_inputs` 是"能力层为什么变"的唯一对账依据，且要能抓住
    "没人持 UpdateStack 时 guard 翻转"这种对能力层不可见的变化。"""
    stacks = (gate.model.StackFact(resource="S1", label="router",
                                   guard=gate.model.GUARD_PROTECTED,
                                   service_role="arn:aws:iam::1:role/cfn-exec",
                                   controls=frozenset({gate.model.CONTROLS_EDGE}),
                                   premises_verified=True),)
    surface = gate.model.Surface(
        kms_keys=("k",),
        auth=gate.model.FnFact("A", entry=gate.model.ENTRY_LATEST),
        panel=gate.model.FnFact("P", entry=gate.model.ENTRY_LATEST),
        edge=gate.model.FnFact("E", entry=gate.model.ENTRY_VERSION,
                               layers_supported=False),
        stacks=stacks)
    section = gate.model_inputs_section(surface)
    assert section["stacks"]["router"]["guard"] == "protected"
    assert section["stacks"]["router"]["controls"] == ["edge-verifier"]
    assert section["stacks"]["router"]["premises_verified"] is True
    assert section["edge_entry"] == "version"
    assert section["signers"]["A"] == {"entry": "latest", "layers_supported": True}
    # service role ARN 含账号 ID ⇒ 只落指纹
    assert "arn:aws:iam" not in json.dumps(section)


def test_model_inputs_drift_is_red_in_both_directions(gate):
    """任一字段变化都红，不判方向：guard 从 protected 变 open 是扩权，
    反过来也要有人看（它会改变能力层的解释）。"""
    base = {"stacks": {"router": {"guard": "protected", "controls": ["edge-verifier"],
                                  "service_role_fp": "aaaa-bbbb-cccc-dddd",
                                  "premises_verified": True}},
            "edge_entry": "version",
            "signers": {"A": {"entry": "latest", "layers_supported": True}}}
    now = json.loads(json.dumps(base))
    now["stacks"]["router"]["guard"] = "open"
    rep = gate.Report()
    gate._compare_model_inputs(rep, base, now)
    assert rep.model_input_drift, "guard 翻转没有红"
    assert not rep.ok
```

（文件顶部若还没 `import json`，补上。）

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -k "sim_legs or publish_leg or model_inputs"`
Expected: FAIL（`model_inputs_section` / `_compare_model_inputs` / `model_input_drift` 不存在；腿数不匹配）。

- [ ] **Step 3: 改闸门**

1. `simulate()` 的 `legs` 列表插入两腿（放在函数腿之后、KMS 额外腿之前）：

```python
    legs: list[tuple[tuple[str, ...], list[str], list[dict] | None]] = [
        (ACTIONS_FUNCTION, t.function_resources(), None),
        # 裁剪按**模型消费面**：这两个动作只在 Edge 两函数与新建候选上携带信号。
        (ACTIONS_PUBLISH, t.publish_resources(), None),
        # CFN / CloudFront / PassRole 合成一腿：6 动作 × ~5 资源 = 响应体很小。
        (ACTIONS_MISC, t.misc_resources(), None),
        (ACTIONS_OTHER, t.other_resources(), KMS_CONTEXT),
    ]
```

2. 腿数常量：

```python
# 每个 principal 的模拟腿数 = 函数腿 + 发布腿 + misc 腿 + 其余腿（含合同 MessageType）
# + `kms:Sign` 其余每个 MessageType 各一腿。**进度输出报这个数**，写死的字面量会在
# 加/减一腿时静静说谎（有一条单测把它与 `simulate` 真正发出的调用数对齐）。
SIM_LEGS_PER_PRINCIPAL = 3 + len(KMS_MESSAGE_TYPES)
```

3. 新增栈观测（放在 `edge_current_version` 附近，共用同一份 router 栈解析）：

```python
def _router_stack_and_distribution(clients) -> tuple[str, str]:
    """router 栈名与分发 ID。**从 `edge_current_version` 里抽出来**，两个调用方共用
    同一次解析：分发 ID 是部署产物，config.ini 只放输入。"""
    rcfg = configparser.ConfigParser(interpolation=None)
    rcfg.read(_SITE_BUILDER.parent / "router" / "config.ini", encoding="utf-8")
    if not rcfg.sections():
        raise SystemExit("router/config.ini 读不到任何段——configparser 对缺失文件是静默的，"
                         "再往下跑会拿空栈名去问 CloudFormation。先确认路径与 cwd。")
    stack = rcfg["CDK"]["stack_name"].split("#")[0].strip()
    outs = clients["cloudformation"].describe_stacks(
        StackName=stack)["Stacks"][0].get("Outputs", [])
    dist = next((o["OutputValue"] for o in outs if o["OutputKey"] == "DistributionId"), "")
    if not dist:
        raise SystemExit(f"栈 {stack} 没有 CfnOutput DistributionId——router 栈没部？")
    return stack, dist


def _stack_logical_ids(cfn, stack: str, types: tuple[str, ...]) -> list[str]:
    """栈里这些资源类型的 `LogicalResourceId`。guard 谓词要按它们判"拦住了什么"。"""
    out = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        for r in page["StackResourceSummaries"]:
            if r["ResourceType"] in types:
                out.append(r["LogicalResourceId"])
    return sorted(out)


def router_and_deployer_stacks(clients, lam, platform: tuple[str, ...]) -> tuple:
    """两个栈的**观测**事实。

    router 栈名来自 `router/config.ini`；deployer 栈名从平台函数的
    `aws:cloudformation:stack-name` tag 反查（与 `edge_asset_location` 同一手法，
    **不手抄栈名**）。`premises_verified` 本轮一律 False：谁执行这次更新已经观测到了
    （`RoleARN`），但"那个身份是否真能改目标资源"还没核 ⇒ 判定落 `*-unanalyzed`，
    这是刻意的下界（spec §9）。
    """
    cfn = clients["cloudformation"]
    router_stack, _dist = _router_stack_and_distribution(clients)
    tagged = lam.get_function(FunctionName=platform[0])["Tags"] or {}
    deployer_stack = tagged.get("aws:cloudformation:stack-name", "")
    if not deployer_stack:
        raise SystemExit(
            f"{platform[0]} 没有 CloudFormation stack tag——推不出 deployer 栈名，"
            f"而"能更新那个栈"是一条签名路径（它拥有两把会话签名 CMK）。")
    plan = ((router_stack, "router", frozenset({model.CONTROLS_EDGE}),
             ("AWS::Lambda::Function", "AWS::CloudFront::Distribution",
              "AWS::DynamoDB::Table")),
            (deployer_stack, "deployer", frozenset({model.CONTROLS_SESSION_KEY}),
             ("AWS::KMS::Key",)))
    facts = []
    for name, label, controls, types in plan:
        body = cfn.get_stack_policy(StackName=name).get("StackPolicyBody")
        described = cfn.describe_stacks(StackName=name)["Stacks"][0]
        facts.append(model.StackFact(
            resource=described["StackId"], label=label,
            guard=guard_for(json.loads(body) if body else None,
                            _stack_logical_ids(cfn, name, types)),
            service_role=described.get("RoleARN"), controls=controls,
            premises_verified=False))
    return tuple(facts)
```

4. `model_inputs` 分节与比较器：

```python
def model_inputs_section(surface) -> dict:
    """能力层的**前提**落成可比较的快照。

    为什么必须单独一节：guard 从 protected 翻成 open，在"当前没人持 `UpdateStack`"的
    账号里对能力层完全不可见（标签集合一个都不变），而它是实打实的 latent risk。
    反过来，能力层真的变了时，这一节是"为什么变"的唯一对账依据。
    ARN 只落指纹（service role ARN 含账号 ID）。
    """
    return {
        "stacks": {st.label: {"guard": st.guard,
                              "controls": sorted(st.controls),
                              "service_role_fp": (principal_fingerprint(st.service_role)
                                                  if st.service_role else ""),
                              "premises_verified": st.premises_verified}
                   for st in surface.stacks},
        "edge_entry": surface.edge.entry,
        "signers": {fact.arn.rsplit(":", 1)[-1]:
                    {"entry": fact.entry, "layers_supported": fact.layers_supported}
                    for fact in (surface.auth, surface.panel)},
    }


def _compare_model_inputs(rep: "Report", base: dict, now: dict | None) -> None:
    """**任一字段变化都红，不判方向**（与 B 层、KMS 层同一条纪律）。"""
    if now is None:
        return
    if not base:
        rep.notes.append("model_inputs：基线里还没有这一节（首次生成）")
        return
    base_flat = json.dumps(base, sort_keys=True, ensure_ascii=False)
    now_flat = json.dumps(now, sort_keys=True, ensure_ascii=False)
    if base_flat != now_flat:
        rep.model_input_drift.append(
            f"能力层的前提变了：基线 {base_flat} → 本次 {now_flat}")
```

5. `Report` 新增字段 + `RED_FIELDS` 新增一行 + `RED_MESSAGES` 新增一条：

```python
    model_input_drift: list[str] = field(default_factory=list)
```
```python
    ("model_input_drift",    "能力层前提漂移（guard / 入口类型 / 栈控制面）（红）", "model"),
```
```python
    "model": ("闸门红：能力层的**前提**变了（stack policy 的 guard、函数入口类型、栈控制什么）。"
              "这不一定意味着有人拿到新权限，但它改变了所有能力结论的解释——"
              "guard 从 protected 变 open 时，持 CFN 更新权的 principal 会重新进冒充面；"
              "反过来也要有人看：那条路只是**直接更新**被挡住，模板层路径仍未分析。"),
```

6. `measure()`：在 `aliases = function_aliases(...)` 之后构造 surface 与 targets 新字段，
并把 `model_inputs` 放进返回的 bundle：

```python
    stacks = router_and_deployer_stacks(clients, lam, platform)
    router_stack, dist_id = _router_stack_and_distribution(clients)
    distribution = f"arn:aws:cloudfront::{account}:distribution/{dist_id}"
    # 两个候选 ARN：一个中性名、一个与平台栈同前缀 ⇒ 缩小"按名字前缀授权"的盲区。
    # **它们只能代表这两个名字**，不能代表任意新函数名（spec §9 的已记盲区）。
    new_candidates = (fn_arn("sb-probe-new-function"),
                      fn_arn(f"{router_stack}-probe-new-function"))
    surface = model.Surface(
        kms_keys=tuple(ref.key_arn for ref in refs),
        auth=model.FnFact(fn_arn(AUTH_FUNCTION_NAME), entry=model.ENTRY_LATEST,
                          layers_supported=True),
        panel=model.FnFact(fn_arn(PANEL_FUNCTION_NAME), entry=model.ENTRY_LATEST,
                           layers_supported=True),
        # `current_version` 那条硬断言已经保证 association 是编号版本。
        # Lambda@Edge **不支持 Layer**（AWS 文档）⇒ 改配置不等于任意代码执行。
        edge=model.FnFact(fn_arn(EDGE_ORIGIN_REQUEST_FN), entry=model.ENTRY_VERSION,
                          layers_supported=False),
        new_candidates=new_candidates, distribution=distribution,
        edge_role=edge_role_arn, stacks=stacks,
        service_roles=tuple(st.service_role for st in stacks if st.service_role))
```
（`AUTH_FUNCTION_NAME` / `PANEL_FUNCTION_NAME` 用闸门里已有的平台函数名常量；没有的话
从 `platform` 里按名字取，**不新增手抄字面量**。）

`Targets(...)` 构造处补齐 `distribution=distribution, edge_role=edge_role_arn,
new_fn_candidates=new_candidates, stacks=stacks, service_roles=surface.service_roles`。

返回字典追加 `"model_inputs": model_inputs_section(surface),`。

7. `BUNDLE_SHAPE` 追加（含新的 `_plain_bool` 谓词）：

```python
def _plain_bool(v) -> bool:
    return isinstance(v, bool)
```
```python
    "model_inputs": {
        "stacks": {"*": {"guard": _nonempty_str, "controls": _list_of_str,
                         "service_role_fp": str, "premises_verified": _plain_bool}},
        "edge_entry": _nonempty_str,
        "signers": {"*": {"entry": _nonempty_str, "layers_supported": _plain_bool}},
    },
```

8. `compare_to_baseline` 新增关键字参数 `model_inputs=None` 并在 `_compare_facts` 之前调用
`_compare_model_inputs(rep, baseline.get("model_inputs") or {}, model_inputs)`；
`main()` 两处调用点补 `model_inputs=bundle["model_inputs"]`；
`write_baseline` 的 JSON 追加 `"model_inputs": bundle["model_inputs"],`。

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q`
Expected: PASS。`test_report_fields_are_all_classified` 会在漏登记 `model_input_drift` 时红——它是这一步的守卫。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/verify_account_trust_boundary.py site-builder/deployer/tests/test_verify_account_trust_boundary.py
git commit -m "feat(3g): 闸门采集 guard/两个栈/入口类型 + model_inputs 分节

新增两腿（发布腿、misc 腿），按模型消费面裁剪、不与全部 alias 做笛卡尔积；
model_inputs 让"没人持 UpdateStack 时 guard 翻转"也能红。"
```

---

### Task 10: 闸门能力层（派生标签进基线并参与红绿）

**Files:**
- Modify: `site-builder/scripts/verify_account_trust_boundary.py`
- Test: `site-builder/deployer/tests/test_verify_account_trust_boundary.py`

**Interfaces:**
- Consumes: Task 8/9 的 `Targets` / `surface` / `model.classify`
- Produces: 每个 observed principal 的 `capabilities: list[str]`；`Report.new_capabilities`；基线 `principals[*].capabilities`

- [ ] **Step 1: 写失败的测试**

追加：

```python
def test_capabilities_are_recorded_per_principal(gate):
    """能力层按 **principal × 标签集合** 比较——只比总人数或一个布尔会让
    "A 失去、B 获得"静静地绿。"""
    observed = {"fp1": {"name": "r1", "arn": "arn:aws:iam::1:role/r1", "kind": "role",
                        "grants": ["update-fn-code:site-auth-service"],
                        "capabilities": ["sign:hijack-auth-signer"]}}
    baseline = {"schema": gate.BASELINE_SCHEMA,
                "principals": {"fp1": {"category": "admin",
                                       "grants": ["update-fn-code:site-auth-service"],
                                       "capabilities": []}}}
    rep = gate.compare_to_baseline(observed, baseline, required={})
    assert rep.new_capabilities, "新增能力标签没有红"
    assert not rep.ok


def test_grant_growth_is_red_even_when_capabilities_are_unchanged(gate):
    """**Codex 点名要求的用例**：能力标签集合完全不变，但授权扩到另一个受保护资源
    ⇒ 仍然红。证明能力层没有吃掉 grant 层的灵敏度。"""
    observed = {"fp1": {"name": "r1", "arn": "arn:aws:iam::1:role/r1", "kind": "role",
                        "grants": ["update-fn-code:site-auth-service",
                                   "update-fn-code:site-panel"],
                        "capabilities": ["sign:hijack-auth-signer"]}}
    baseline = {"schema": gate.BASELINE_SCHEMA,
                "principals": {"fp1": {"category": "admin",
                                       "grants": ["update-fn-code:site-auth-service"],
                                       "capabilities": ["sign:hijack-auth-signer"]}}}
    rep = gate.compare_to_baseline(observed, baseline, required={})
    assert rep.new_grants, "grant 扩到另一个资源却没红"
    assert not rep.new_capabilities
    assert not rep.ok


def test_platform_losing_a_capability_is_red(gate):
    """platform 类按**集合等值**比：丢失同样要红（丢掉 auth 的签名能力 =
    全平台登录不可用，而那不会在任何单测里出现）。"""
    observed = {"fp1": {"name": "site-auth-service", "arn": "arn:aws:iam::1:role/a",
                        "kind": "role", "grants": ["kms-sign:site-rs-v1"],
                        "capabilities": []}}
    baseline = {"schema": gate.BASELINE_SCHEMA,
                "principals": {"fp1": {"category": "platform",
                                       "grants": ["kms-sign:site-rs-v1"],
                                       "capabilities": ["sign:kms-direct"]}}}
    rep = gate.compare_to_baseline(observed, baseline, required={})
    assert rep.missing_required, "platform 丢能力标签没红"


def test_non_platform_losing_a_capability_is_an_improvement(gate):
    observed = {"fp1": {"name": "r1", "arn": "arn:aws:iam::1:role/r1", "kind": "role",
                        "grants": [], "capabilities": []}}
    baseline = {"schema": gate.BASELINE_SCHEMA,
                "principals": {"fp1": {"category": "admin", "grants": [],
                                       "capabilities": ["sign:kms-direct"]}}}
    rep = gate.compare_to_baseline(observed, baseline, required={})
    assert rep.improvements
    assert rep.ok


def test_key_declarations_do_not_apply_to_capabilities(gate):
    """`--new-key` / `--retire-key` 对能力层无效：标签是"任一把 key 成立即算"的口径，
    加/退一把 CMK 不改变它 ⇒ 轮转期能力层若变化，那不是轮转的副作用。"""
    observed = {"fp1": {"name": "r1", "arn": "arn:aws:iam::1:role/r1", "kind": "role",
                        "grants": ["kms-sign:site-rs-v2"],
                        "capabilities": ["sign:kms-direct"]}}
    baseline = {"schema": gate.BASELINE_SCHEMA,
                "principals": {"fp1": {"category": "admin",
                                       "grants": ["kms-sign:site-rs-v1"],
                                       "capabilities": []}}}
    rep = gate.compare_to_baseline(observed, baseline, required={},
                                   new_keys=("site-rs-v2",))
    assert rep.new_capabilities, "能力标签新增被密钥声明抹掉了"


def test_capabilities_come_from_the_shared_model(gate):
    """闸门不许有第二份判定。"""
    src = (_ROOT / "site-builder" / "scripts"
           / "verify_account_trust_boundary.py").read_text(encoding="utf-8")
    assert "def classify(" not in src
    assert "model.classify(" in src


def test_headline_counts_do_not_drive_the_exit_code(gate):
    """headline 只打印：红绿在逐 principal 那一层已经判过了。"""
    rep = gate.Report()
    rep.notes.append("headline: can_sign=15")
    assert rep.ok
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -k "capabilit or grant_growth or headline"`
Expected: FAIL（`Report` 没有 `new_capabilities`）。

- [ ] **Step 3: 改闸门**

1. `Report` 追加字段、`RED_FIELDS` 追加一行（复用 `"grew"` 文案）：

```python
    new_capabilities: list[str] = field(default_factory=list)
```
```python
    ("new_capabilities",     "已知 principal 长出新的冒充能力路径（红）",     "grew"),
```

2. `compare_to_baseline` 的 principal 循环里，grant 比较之后追加能力比较：

```python
        caps = set(p.get("capabilities") or ())
        was_caps = set(base[fp].get("capabilities") or ())
        # **密钥声明对能力层无效**：标签是"任一把 key 成立即算"，加/退一把不改变它。
        if caps - was_caps:
            rep.new_capabilities.append(
                f"{p['name']}  [{fp}]  +{sorted(caps - was_caps)}")
        if was_caps - caps:
            if category == "platform":
                rep.missing_required.append(
                    f"{p['name']}（platform）丢了能力路径 {sorted(was_caps - caps)}"
                    f"——平台自己的能力是精确且必需的")
            else:
                rep.improvements.append(
                    f"{p['name']}  [{fp}]  -{sorted(was_caps - caps)}（能力路径）")
```

3. `measure()` 的 per-principal 循环里，`grants = grants_from_decisions(...)` 之后：

```python
            allowed_pairs = frozenset(k for k, v in decisions.items() if v == "allowed")
            caps = model.classify(allowed_pairs, surface, p["name"])
            if grants or caps:
                observed[principal_fingerprint(p["arn"])] = {
                    "name": p["name"], "arn": p["arn"], "kind": p["kind"],
                    "grants": sorted(grants), "capabilities": sorted(caps)}
```

4. headline 打印（`measure()` 返回前）：

```python
    agg = model.summarize({fp: set(rec["capabilities"]) for fp, rec in observed.items()})
    print(f"能力层 headline（**只打印，不参与红绿**；红绿在逐 principal 的集合比较那一层）："
          f"能签 {agg['can_sign']}、能替换 Edge 验签 {agg['can_replace_edge_verifier']}、"
          f"并集 {agg['impersonation_surface_union']}（受限/未分析单列 "
          f"{agg['non_surface_only_holders']}）。**这是下界**：模板层 CFN 路径与 "
          f"CreateFunction 的名字空间都未分析（spec §9）。", file=sys.stderr)
```

5. `BUNDLE_SHAPE` 的 principals 子规格追加 `"capabilities": _list_of_str`；
`write_baseline` 的 principals 字典追加 `"capabilities": p.get("capabilities") or []`。

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/verify_account_trust_boundary.py site-builder/deployer/tests/test_verify_account_trust_boundary.py
git commit -m "feat(3g): 闸门新增派生能力层（逐 principal 集合比较）

grant 层灵敏度不变（有一条用例钉住：能力不变但 grant 扩到另一个受保护资源仍红）；
密钥声明对能力层无效；headline 只打印。"
```

---

### Task 11: schema 7 + `--carry-categories`

**Files:**
- Modify: `site-builder/scripts/verify_account_trust_boundary.py`
- Test: `site-builder/deployer/tests/test_verify_account_trust_boundary.py`

**Interfaces:**
- Consumes: Task 8-10
- Produces: `BASELINE_SCHEMA = 7`、`CATEGORIES: tuple[str, ...]`、`load_carried_categories(path: Path) -> dict[str, str]`、CLI `--carry-categories PATH`

- [ ] **Step 1: 写失败的测试**

追加：

```python
def test_schema_is_seven_and_old_baselines_are_refused(gate, tmp_path):
    assert gate.BASELINE_SCHEMA == 7
    old = tmp_path / "b.json"
    old.write_text(json.dumps({"schema": 6, "principals": {}}), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        gate.load_baseline(old)
    assert "7" in str(e.value)


def test_baseline_with_retired_grant_prefix_is_refused(gate, tmp_path):
    """手改出的半真半假基线（schema 改成 7 但 grant 还是旧名）必须在读入时被拒。"""
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"schema": 7, "principals": {
        "aaaa-bbbb-cccc-dddd": {"category": "admin",
                                "grants": ["replace-platform-code:site-panel"],
                                "capabilities": []}}}), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        gate.load_baseline(p)
    assert "replace-platform-code" in str(e.value)


def test_carry_categories_imports_only_categories(gate, tmp_path):
    """只导入 category；grants / capabilities / 豁免 / 其它状态一概不读。"""
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"schema": 6, "principals": {
        "aaaa-bbbb-cccc-dddd": {"category": "platform",
                                "grants": ["replace-platform-code:x"]},
        "1111-2222-3333-4444": {"category": "admin", "grants": []}}}),
        encoding="utf-8")
    got = gate.load_carried_categories(old)
    assert got == {"aaaa-bbbb-cccc-dddd": "platform",
                   "1111-2222-3333-4444": "admin"}


def test_carry_categories_rejects_bad_shape_and_bad_values(gate, tmp_path):
    bad_shape = tmp_path / "s.json"
    bad_shape.write_text(json.dumps({"principals": ["not", "a", "dict"]}),
                         encoding="utf-8")
    with pytest.raises(SystemExit):
        gate.load_carried_categories(bad_shape)

    bad_fp = tmp_path / "f.json"
    bad_fp.write_text(json.dumps({"principals": {
        "not-a-fingerprint": {"category": "platform"},
        "aaaa-bbbb-cccc-dddd": {"category": "not-a-category"},
        "1111-2222-3333-4444": {"category": "platform"}}}), encoding="utf-8")
    got = gate.load_carried_categories(bad_fp)
    assert got == {"1111-2222-3333-4444": "platform"}, got


def test_write_baseline_precedence_classify_over_carried_over_existing(gate, tmp_path):
    bundle = {"schema": 7, "facts": {"principals_with_missing_context": 0},
              "coverage": {"undecided_items": []}, "kms": {},
              "model_inputs": {"stacks": {}, "edge_entry": "version", "signers": {}},
              "iam_write": {"statements": {}, "boundaries": {},
                            "managed_versions": {}, "texts": {}},
              "resource_policies": {"platform": {}, "sites": {},
                                    "bootstrap_bucket": [], "bootstrap_bucket_texts": {}},
              "principals": {"x": {"name": "r1", "arn": "arn:aws:iam::1:role/r1",
                                   "kind": "role", "grants": ["update-fn-code:p"],
                                   "capabilities": []}}}
    fp = gate.principal_fingerprint("arn:aws:iam::1:role/r1")
    out = tmp_path / "new.json"
    gate.write_baseline(bundle, {"principals": {fp: {"category": "cdk-admin"}}}, out,
                        carried={fp: "platform"})
    written = json.loads(out.read_text(encoding="utf-8"))
    # 沿用基线里已有的分类优先级最低 ⇒ carried 生效
    assert written["principals"][fp]["category"] == "platform"


def test_platform_still_goes_red_after_carrying_categories(gate, tmp_path):
    """**迁移后等值约束必须真的恢复**：category 丢失时 platform 丢一条 grant 只会
    被当成"改善"，这条用例证明 carry 之后它照样红。"""
    bundle = {"schema": 7, "facts": {"principals_with_missing_context": 0},
              "coverage": {"undecided_items": []}, "kms": {},
              "model_inputs": {"stacks": {}, "edge_entry": "version", "signers": {}},
              "iam_write": {"statements": {}, "boundaries": {},
                            "managed_versions": {}, "texts": {}},
              "resource_policies": {"platform": {}, "sites": {},
                                    "bootstrap_bucket": [], "bootstrap_bucket_texts": {}},
              "principals": {"x": {"name": "site-edge", "arn": "arn:aws:iam::1:role/e",
                                   "kind": "role",
                                   "grants": ["invoke-platform:site-panel",
                                              "invoke-site:all"],
                                   "capabilities": []}}}
    fp = gate.principal_fingerprint("arn:aws:iam::1:role/e")
    out = tmp_path / "new.json"
    gate.write_baseline(bundle, {"principals": {}}, out, carried={fp: "platform"})
    baseline = json.loads(out.read_text(encoding="utf-8"))
    shrunk = {fp: {"name": "site-edge", "arn": "arn:aws:iam::1:role/e", "kind": "role",
                   "grants": ["invoke-site:all"], "capabilities": []}}
    rep = gate.compare_to_baseline(shrunk, baseline, required={})
    assert rep.missing_required, "platform 丢 grant 没红 ⇒ 等值约束没恢复"


def test_carry_categories_conflicting_with_classify_is_fatal(gate, tmp_path):
    """冲突必须报明，不许静默覆盖。"""
    with pytest.raises(SystemExit) as e:
        gate.merge_categories(carried={"aaaa-bbbb-cccc-dddd": "platform"},
                              by_name={"r1": "admin"},
                              observed={"aaaa-bbbb-cccc-dddd":
                                        {"name": "r1", "arn": "a", "kind": "role",
                                         "grants": [], "capabilities": []}})
    assert "r1" in str(e.value)
```

- [ ] **Step 2: 运行，确认失败**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -k "schema_is_seven or retired_grant or carry_categories or precedence or after_carrying"`
Expected: FAIL。

- [ ] **Step 3: 改闸门**

1. `BASELINE_SCHEMA = 7` 并改注释：

```python
# 7 = 3g：判定模型换成共享的 `_impersonation_model`。grant 词表改名
# （`replace-platform-code` → `update-fn-code`）、新增 CFN/CloudFront/PassRole 类、
# principals 多一个 `capabilities`、多一个 `model_inputs` 分节 ⇒ 整份基线的形态都变了。
# **没有 6 → 7 的迁移通道**（沿用先例）：删/移走旧文件重生成，但**要带
# `--carry-categories <旧文件>`**，否则全部 platform 标注会变成 unclassified，
# 而那会把 platform 的集合等值约束静默降级成"只看新增"。
BASELINE_SCHEMA = 7
```

2. 抽 `CATEGORIES` 常量（`write_baseline` 里那份 JSON 引用它）：

```python
# 人工标注的类别白名单。`--classify` 与 `--carry-categories` 都按它校验。
CATEGORIES: tuple[str, ...] = ("platform", "platform-overbroad", "admin", "break-glass",
                               "cdk-admin", "cdk-readonly", "unrelated-workload",
                               "unclassified")
```

3. `load_baseline` 追加退役 grant 前缀检查：

```python
    retired = sorted({g for rec in (data.get("principals") or {}).values()
                      for g in (rec.get("grants") or ())
                      if g.startswith("replace-platform-code:")})
    if retired:
        raise SystemExit(
            f"基线里还有已退役的 grant 名 {retired[:3]}（schema 7 已改名为 "
            f"`{G_UPDATE_CODE}:`）。这份文件是手改出来的半真半假形态：schema 号是新的、"
            f"内容是旧的 ⇒ 比较结果没有意义。移走它、按 DEPLOY.md 的见证流程重生成。")
```

4. 新增两个函数：

```python
def load_carried_categories(path: Path) -> dict[str, str]:
    """从**任意 schema** 的旧基线里只取 `principals[*].category`。

    为什么需要它：`write_baseline` 只从"这一轮读进来的基线 dict"沿用 category，而
    schema 不匹配时既有提示是"删掉重生成"⇒ 一次 schema 跳变会把全部 `platform`
    标注变成 `unclassified`，`platform` 的**集合等值**约束静默降级成"只看新增"，
    而 `unclassified` 只是绿色报告里的一个字段（不会红）。

    **"支持旧 schema"不等于接受任意结构**：指纹形态与 category 取值都要校验，
    不合法的逐条报出、不导入。除 category 以外一概不读（grants / capabilities /
    豁免 / coverage 都不读——那些必须来自本轮观测）。
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    principals = data.get("principals")
    if not isinstance(principals, dict):
        raise SystemExit(f"{path} 没有 dict 形态的 principals 分节——这不是一份基线")
    out: dict[str, str] = {}
    skipped: list[str] = []
    for fp, rec in principals.items():
        cat = rec.get("category") if isinstance(rec, dict) else None
        if not _PFP_RE.fullmatch(str(fp)):
            skipped.append(f"{fp}（指纹形态不合法）")
        elif cat == "unclassified" or cat is None:
            skipped.append(f"{fp}（没有有效分类）")
        elif cat not in CATEGORIES:
            skipped.append(f"{fp}（类别 {cat!r} 不在白名单）")
        else:
            out[str(fp)] = cat
    if skipped:
        print(f"--carry-categories：跳过 {len(skipped)} 条：{skipped[:5]}", file=sys.stderr)
    print(f"--carry-categories：从 {path} 带过来 {len(out)} 条分类"
          f"（只读 category，其余一概不读）", file=sys.stderr)
    return out


def merge_categories(*, carried: dict, by_name: dict, observed: dict) -> dict:
    """→ {指纹: category}。优先级 `--classify`（按名字）> `--carry-categories`（按指纹）。

    **冲突硬失败**：两处对同一个 principal 给出不同分类时，静默择一等于让操作者
    以为自己标了 A 而实际生效 B。
    """
    merged = dict(carried)
    conflicts = []
    for fp, rec in observed.items():
        named = by_name.get(rec["name"])
        if named is None:
            continue
        if named not in CATEGORIES:
            raise SystemExit(f"--classify 里 {rec['name']} 的类别 {named!r} 不在白名单 "
                             f"{list(CATEGORIES)}")
        if fp in carried and carried[fp] != named:
            conflicts.append(f"{rec['name']}：--classify={named} vs "
                             f"--carry-categories={carried[fp]}")
        merged[fp] = named
    if conflicts:
        raise SystemExit("--classify 与 --carry-categories 冲突（不静默覆盖，请自己定）："
                         + "；".join(conflicts))
    return merged
```

5. `write_baseline` 签名加 `carried: dict | None = None`，category 解析改成：

```python
        principals[fp] = {
            "category": (p.get("category") or (carried or {}).get(fp)
                         or old.get(fp, {}).get("category", "unclassified")),
            "grants": p["grants"],
            "capabilities": p.get("capabilities") or [],
        }
```
（`"categories": list(CATEGORIES),` 替换原来那份字面量。）

6. CLI 与 `main()`：

```python
    ap.add_argument("--carry-categories", metavar="PATH",
                    help="从**任意 schema** 的旧基线里只带过来 principals[*].category"
                         "（配合 --update-baseline）。schema 跳变时不带它 = 全部 platform "
                         "标注变成 unclassified ⇒ platform 的集合等值约束静默降级成"
                         ""只看新增"。只读 category，其余一概不读；与 --classify 冲突即报错。")
```
```python
    if args.carry_categories and not args.update_baseline:
        raise SystemExit("--carry-categories 只与 --update-baseline 同用：它的唯一作用是"
                         "写新基线时保住人工标注，单独给出没有语义。")
```
`--update-baseline` 分支里：

```python
        carried = (load_carried_categories(Path(args.carry_categories))
                   if args.carry_categories else {})
        by_name = json.loads(Path(args.classify).read_text(encoding="utf-8")) \
            if args.classify else {}
        for fp, cat in merge_categories(carried=carried, by_name=by_name,
                                        observed=observed).items():
            if fp in observed:
                observed[fp]["category"] = cat
        ...
        write_baseline(bundle, baseline, BASELINE_PATH, carried=carried)
```
（删掉原来那段 `if classify: for p in observed.values(): ...`。）

- [ ] **Step 4: 运行，确认全绿**

Run: `cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add site-builder/scripts/verify_account_trust_boundary.py site-builder/deployer/tests/test_verify_account_trust_boundary.py
git commit -m "feat(3g): BASELINE_SCHEMA=7 + --carry-categories

schema 跳变会把 platform 标注洗成 unclassified、把集合等值降级成只看新增；
--carry-categories 只带 category（校验指纹与白名单），与 --classify 冲突即报错；
读到退役 grant 名的基线一律拒（半真半假的手改形态）。"
```

---

### Task 12: 文档与真源同步

**Files:**
- Modify: `docs/security/account-trust-boundary.md`
- Modify: `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`（§9 的 3g 行 + §4 M04 那半句）
- Create: `docs/adr/0008-two-predicates-for-stack-policy.md`
- Modify: `CLAUDE.md`（跨组件改动矩阵 + 闸门那段的旗标说明）
- Modify: `site-builder/DEPLOY.md`（schema 7 与 `--carry-categories`；见证流程只写"在仓库外做"）

- [ ] **Step 1: 写 ADR 0008**

```markdown
---
status: accepted
date: 2026-09-21
---
# stack policy 有两个谓词：部署形态一致性，与闸门的 guard 语义判定

`router/infrastructure/stack_policy.py` 的 `policy_problems(actual, expected)` 判的是
**线上策略与本项目规定的形态是否等价**（`verify_deployed_edge.sh` ⑤ 用它，忘了 `apply`
时靠它红）。它的 `covered` 只收 Deny 语句里**字面**的 Resource 串，所以一份**更严格**的
`Deny Update:* on "*"` 会让 `want - covered` 非空（want 是精确的 `LogicalResourceId/<id>`），
再加一条"Resource 含通配"。⇒ **`policy_problems() != []` 推不出"没有保护"。**

决定：信任边界闸门用第二个谓词 `site-builder/scripts/_stack_policy_guard.guard_for()`，
只回答"这些逻辑 ID 的 Update 被拒了吗"，**三值**（`protected` / `open` / `unknown`）。
解析不动的形态（未识别语法、带 Condition、`Principal` 不是 `*`、读不到）一律 `unknown`，
**不得**按"没拦住"解释——那正是 3g 要修的假绿形状。

两处 docstring 互相点名。**不要把它们合并**：一个服务"部署是不是按规定做的"，另一个服务
"这条威胁路径是不是被挡住了"，后者必须接受比规定形态更严格的策略。

## Consequences

- `guard == "protected"` **只**表示受保护资源的**直接更新**路径被挡住。service role 权限
  足够高时，改模板新增 IAM 授权类资源等路径未必需要碰那四个资源 ⇒ 判定落
  `edge:cfn-template-unanalyzed`（单列、不进冒充面并集），不得据此宣称某 principal
  退出冒充面，也不得算确定收益（ADR 0007 已有同样要求）。
- `DENIED_ACTIONS` 在两个文件里各有一份（闸门不为一个常量拖进 router 侧依赖），
  由 `test_stack_policy_guard.py` 的对账用例咬住。
```

- [ ] **Step 2: 改 `docs/security/account-trust-boundary.md`**

在 headline 数字处插入醒目标记，并新增一节"未分析范围"：

```markdown
> **⚠️ 本页的 headline 与集合关系数字待真机重测（3g，2026-09-21）。** 判定模型已换成
> `scripts/_impersonation_model.py`（共享，经反例验证），grant 词表与基线 schema 一并升到 7。
> 旧数字由旧模型算出：它对 Edge 过度声称（只 `UpdateFunctionCode`）、少算 CFN 两条路与
> `UpdateFunctionConfiguration`、多要了一个 `PublishVersion`，且 CFN 前提停留在 ADR 0007 之前。
> 重测前不要引用本页任何计数。

## 未分析范围（3g 明确记录）

1. **CFN 模板层路径**：`guard == "protected"` 只关掉"直接更新那四个受保护资源"。
   service role 权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰受保护资源
   ⇒ 持 CFN 更新权的 principal 落 `edge:cfn-template-unanalyzed`（单列、不进并集）。
   **不得**据 guard 宣称某 principal 退出冒充面，也不得算确定收益。
2. **`CreateFunction` 的名字空间**：只对两个候选 ARN 有判定（一个中性名、一个与平台栈同前缀）。
   按名字前缀授权的策略可能在别的名字上成立 ⇒ 这条是下界。
3. **deployer 栈那条签名路径的前提**：`premises_verified` 目前一律 False
   （"谁执行这次更新"已观测，"那个身份是否真能改 key policy"未核）⇒ 落
   `sign:cfn-session-key-stack-unanalyzed`。
4. 既有三个盲区（Condition 下界、动作等价类不穷尽、临时角色）不变。
```

- [ ] **Step 3: 改 merged review §9**

3g 行末尾追加（**不打完成勾**）：

```markdown
**2026-09-21：模型已对齐、待真机重测**（spec `docs/superpowers/specs/2026-09-20-3g-*`）。
判定收敛到共享 `_impersonation_model.py`，闸门 grant 层改名+扩类、新增派生能力层与
`model_inputs`，基线 schema 6→7（带 `--carry-categories`）。**核验后订正本行两处**：
① 闸门对**站点函数**并没有发 `replace-platform-code`（只对平台函数发），那半句不成立；
② "判据与 probe 的 `classify()` 一致"不成立——probe 自己有三处失真（CFN 前提在 ADR 0007
之后过期、代码更新与配置更新被合成一类、新建函数那条路多要了 `PublishVersion`），
所以不变量是"两边共用同一份经反例验证的模型"。真机首跑/基线重生成/文档数字仍未做。
```

- [ ] **Step 4: 改 `CLAUDE.md`**

跨组件改动矩阵追加一行：

```markdown
| `scripts/_impersonation_model.py`（冒充判定模型） | `probe_impersonation_surface.py` 与 `verify_account_trust_boundary.py` 两个消费方、`deployer/tests/test_impersonation_model.py`（反例真源）、`_stack_policy_guard.py`（guard 三值）、基线 schema（改模型 = 改基线形态）、`docs/security/account-trust-boundary.md` 的数字。**判定只许有一份**——两边各抄一份正是 3g 的成因 |
```

闸门那段的旗标说明追加：

```markdown
# schema 7（3g）：grant 改名 + 能力层 + model_inputs。旧基线一律硬失败，重生成时**必须**带
# `--carry-categories <旧基线>`——不带会把全部 platform 标注洗成 unclassified，
# 而那会把 platform 的集合等值约束静默降级成"只看新增"（唯一症状：什么都不红）。
```

- [ ] **Step 5: 改 `site-builder/DEPLOY.md`**

在信任边界闸门那节追加：

```markdown
**schema 7（3g）的一次性迁移**：旧基线（schema 6）一律硬失败。重生成的**唯一正确姿势**是
`--update-baseline --carry-categories <旧基线副本>`；不带 `--carry-categories` 会丢掉全部
人工分类，platform 的集合等值约束随之静默降级。

见证流程（旧码跑绿 → 同一份观测喂旧/新两版判定 → 用那份 dump 写新基线 → 新基线复核）
**在仓库外做**，产物落 `.scratch/`（gitignored）：它是本验证环境的中间步骤，不属于交付资产。
```

- [ ] **Step 6: 跑文档守卫（DEPLOY.md / CLAUDE.md 有 AST 与文本守卫）**

Run:
```bash
cd /Users/kentpeng/projects/quick-app/site-builder/deployer && .venv/bin/pytest tests -q -k "doc or deploy_md or claude or bootstrap"
```
Expected: PASS。若某条守卫要求"每一处 router 部署点写成三步"之类的形态，按它的报错补齐。

- [ ] **Step 7: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add docs/security/account-trust-boundary.md docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md docs/adr/0008-two-predicates-for-stack-policy.md CLAUDE.md site-builder/DEPLOY.md
git commit -m "docs(3g): 数字标待重测 + 未分析范围 + ADR 0008（两个 stack policy 谓词）

§9 3g 记"模型已对齐待真机重测"并订正原条目两处说法；CLAUDE.md 加矩阵行与
--carry-categories 的静默降级警告；DEPLOY.md 写明迁移的唯一正确姿势。"
```

---

### Task 13: 全量本机闸门 + 证据分级收尾

**Files:**
- Modify: `docs/superpowers/specs/2026-09-20-3g-impersonation-model-alignment-spec.md`（只改状态行）

- [ ] **Step 1: 串行跑七个包**

**必须串行**（`contract/tests/test_redlines.py` 有一条墙钟哨兵，并行会假红）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/contract && .venv/bin/pytest tests -q)
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/mcp && python3 -m pytest tests -q)
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```
Expected: 全绿。**mcp / panel 的 deploy 类测试在本机会 SystemExit**（config.ini 是精简+脱敏态）
——那不是本次引入的，照 HANDOFF 的记载判断，不要去"修"。
若 contract 那条墙钟哨兵红，**先单独重跑一次**再判断。

- [ ] **Step 2: 探针自检 + 闸门纯函数路径冒烟**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/probe_impersonation_surface.py --self-test
python3 -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('g', 'site-builder/scripts/verify_account_trust_boundary.py')
m = importlib.util.module_from_spec(spec); sys.modules['g'] = m; spec.loader.exec_module(m)
print('schema', m.BASELINE_SCHEMA, '腿数', m.SIM_LEGS_PER_PRINCIPAL)
print('动作数', len(m.ACTIONS), '标签数', len(m.model.ALL_LABELS))
"
```
Expected: 探针退 0；打印 `schema 7`、腿数 5、动作数与标签数非零。
**这两条都不碰 AWS**——闸门的真机路径本机跑不了（config.ini 是脱敏态）。

- [ ] **Step 3: 更新 spec 的状态行，写清证据分级**

把 spec 第一行的状态改成：

```markdown
状态：代码与单测已实施（2026-09-21，证据等级 **unit/fake + 静态**：模型反例 35 条、
guard 谓词 13 条、闸门侧用例见 `test_verify_account_trust_boundary.py`；
botocore 服务模型与 AWS 文档核验见 §1.1）。**真机部分未做**：闸门首跑、schema 7 基线生成、
探针重量测、`account-trust-boundary.md` 的数字、新增两腿的耗时量测——都需要真实 AWS 与
完整 config.ini，见 §11。
```

- [ ] **Step 4: 提交**

```bash
cd /Users/kentpeng/projects/quick-app
git add docs/superpowers/specs/2026-09-20-3g-impersonation-model-alignment-spec.md
git commit -m "docs(3g): spec 状态改为「代码+单测已实施，真机待做」并标明证据等级"
```

- [ ] **Step 5: 把真机待办交回**

在收尾报告里明确列出（**不要自己伪造结果**）：

1. `python3 site-builder/scripts/verify_account_trust_boundary.py`（旧码，须**绿**，不是只跑 `--dump-observed`）；
2. `.scratch` 的一次扫描双模型 runner（包住 `gate.simulate` 记 decisions，调一次 `gate.measure()`）；
3. `--from-dump <那份> --update-baseline --carry-categories <旧基线副本>`；
4. 新基线复核一次必须绿；
5. `python3 site-builder/scripts/probe_impersonation_surface.py --write-evidence --dump-observed .scratch/...`；
6. 回填 `docs/security/account-trust-boundary.md` 的数字并去掉 ⚠️ 标记；
7. 量测新增两腿对那 ~11 分钟的影响，记进 DEPLOY.md。

---

## 自审记录

**spec 覆盖**：§4.1 观测输入→Task 1/3/7/9；§4.2 标签词表→Task 1/2/3；§4.3 guard 三值→Task 6；
§5.1 grant 词表→Task 8；§5.2 能力层→Task 10；§5.3 `model_inputs`→Task 9；§5.4 裁剪→Task 8/9；
§5.5 正向控制→Task 8（未改动，旧用例继续守）；§6 probe→Task 7；§7 测试矩阵→Task 1-5 + 8-11；
§8 迁移→Task 11 + Task 12 的 DEPLOY.md；§9 未分析范围→Task 12；§10 真源→Task 12；
§11 证据分级→Task 13。

**命名一致性**：`model.classify` / `model.summarize` / `model.Surface` / `model.FnFact` /
`model.StackFact` / `guard_for` / `model_inputs_section` / `_compare_model_inputs` /
`load_carried_categories` / `merge_categories` / `write_baseline(..., carried=)` 在
Task 7-11 里用的是同一组名字；grant 常量 `G_UPDATE_CODE` 等只在 Task 8 定义、Task 10/11 引用。

**已知的实施期风险**（不是占位符，是要在执行时判断的事）：
- Task 8 Step 4 会有一批旧用例因 `replace-platform-code` 字面量而红——**改期望，不改判定**。
- Task 9 的 `AUTH_FUNCTION_NAME` / `PANEL_FUNCTION_NAME`：若闸门里没有现成常量，从
  `platform` 元组按名字取，**不要新增手抄字面量**（会与 `app.py` 漂移）。
- Task 9 的 `_stack_logical_ids` 用 `list_stack_resources`；若某个栈资源过多导致分页慢，
  只取需要的类型（代码已按 `types` 过滤），**不要改成不分页**。
