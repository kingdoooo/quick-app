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
    """加载一份**独立**的模型模块。

    注册进 `sys.modules` 用的是一个**测试专用的名字**，不是 `_impersonation_model`：
    下面那批变形测试会就地改模块常量（`A_UPDATE_CODE`、`NON_SURFACE_LABELS`…），而闸门与
    探针都按真名 `import _impersonation_model`。用真名注册就等于把改坏的那份塞进全局缓存，
    于是**同一个进程里后加载的闸门会拿到被变形的模型** —— 实测症状是单独跑这个文件全绿、
    跑整个 tests 目录时闸门那边 11 条红（而且红在 grant 与 coverage 这些看起来毫不相关
    的用例上）。`fixture` 那边另有一层兜底：跑完把这个名字清掉。
    """
    spec = importlib.util.spec_from_file_location("_impersonation_model_undertest",
                                                  _MODULE)
    assert spec is not None and spec.loader is not None, _MODULE
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_impersonation_model_undertest"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def m():
    mod = _load()
    yield mod
    # 变形测试改的是这份私有副本，用完即弃——别让它跨用例存活。
    sys.modules.pop("_impersonation_model_undertest", None)


def test_module_has_no_aws_imports():
    """**零 AWS 依赖**：`probe --self-test` 与闸门的纯函数路径必须能在没有 boto3 的
    解释器上 import 它。有人往这里 `import boto3` 会让那两条路一起断。

    **按 AST 判，不按子串判**：子串版会把 docstring 里"本模块不 import boto3"这句话
    也算成违规（实测），于是守卫逼着人不许在注释里讨论它——那是假阳性，而假阳性
    最终会被"顺手放宽"掉。AST 只看真的 import 语句。
    """
    import ast
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
    forbidden = {"boto3", "botocore", "configparser"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & forbidden), f"共享模型 import 了 {sorted(imported & forbidden)}"


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
    assert m.classify(frozenset({"lambda:UpdateFunctionCode|EDGE",
                                 "cloudfront:UpdateDistribution|DIST"}), s) == set()


def test_edge_code_rights_do_not_spill_into_signer_hijack(m):
    """资源维度不许折叠，两个方向都测。"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.edge.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == {m.E_PUBLISH_INLINE}
    assert m.classify(frozenset({f"lambda:UpdateFunctionCode|{s.auth.arn}",
                                 f"cloudfront:UpdateDistribution|{s.distribution}"}), s) \
        == {m.S_HIJACK_AUTH}


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
    # 并集外的未分析持有者：只有 `p-unanalyzed`（夹具那位不持未分析标签）
    assert agg["unanalyzed_outside_union"] == 1


def test_unanalyzed_holders_inside_the_union_are_not_counted_as_outside(m):
    """**R3-b**：`unanalyzed_outside_union` 是 `marginal_value_if_closed` 那层上界的
    **差额**——反事实只遍历初始并集，所以并集外只持未分析路径的人根本不进
    `remaining`/`uncertain`。既然是差额，它就必须**只**数并集外的人：

    · 同时持已建模路径与未分析路径的人**在**并集里 ⇒ 他已经被 `uncertain` 覆盖，不算差额
      （算了就等于同一个人被数两次，那句范围声明又会反过来说小）；
    · 一个未分析标签都不持的人（受限的夹具签发器）也不算。
    """
    agg = m.summarize({
        "p-inside-both": {m.S_KMS_DIRECT, m.E_CFN_TEMPLATE_UNANALYZED},   # 在并集里
        "p-outside": {m.S_CFN_SESSION_KEY_UNANALYZED},                    # 并集外，算
        "p-fixture": {m.S_FIXTURE_ISSUER},                                # 不持未分析，不算
    })
    assert agg["impersonation_surface_union"] == 1
    assert agg["unanalyzed_outside_union"] == 1
    # 并集内那位由 uncertain 覆盖（关掉 KMS 那组后他仍不定论）
    assert agg["marginal_value_if_closed"]["restrictive-kms-key-policy"][
        "principals_uncertain"] == 1
    # 两条路都没有未分析持有者时是 0（证明它不是常数）
    assert m.summarize({"p": {m.S_KMS_DIRECT}})["unanalyzed_outside_union"] == 0


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


# ---- 从探针测试迁来的聚合语义用例（3g：判定与聚合都归共享模型）-------------------

def test_read_only_kms_is_still_not_a_capability(m):
    """反例：只有 `kms:GetPublicKey` 的 principal 既不能签，也拿不到夹具会话。
    公钥不是秘密——把它算进冒充面会让 headline 虚高一大截。"""
    s = m.fake_surface()
    for key in s.kms_keys:
        assert m.classify(frozenset({f"kms:GetPublicKey|{key}",
                                     f"kms:DescribeKey|{key}"}), s) == set()


def test_the_verifier_role_itself_is_the_url_entry(m):
    """夹具签发器角色**本身**就持有那条入口（它的 inline policy 就是对 auth Function URL
    的两条 invoke 语句）⇒ 名字判据要命中，别的名字不许因为名字拿到它。"""
    s = m.fake_surface()
    assert m.classify(frozenset(), s, s.verifier_role_name) == {m.S_FIXTURE_ISSUER}
    assert m.classify(frozenset(), s, "some-other-role") == set()


def test_fixture_issuer_is_reported_separately_from_can_sign(m):
    """夹具签发器是**受限**冒充（只签夹具域邮箱、TTL ≤ 30 分钟、Edge 只在夹具站点认）
    ⇒ 单列，不并进 `can_sign`。并进去会让"3c 之后还有多少人能冒充任意用户"这个数字
    把验收工具的持有者也算进来。
    """
    agg = m.summarize({"p-fixture-only": {m.S_FIXTURE_ISSUER},
                       "p-real-sign": {m.S_KMS_DIRECT}})
    assert agg["can_sign"] == 1, "夹具签发器被并进了 can_sign"
    assert agg["impersonation_surface_union"] == 1
    assert agg["fixture_issuer_holders"] == 1


def test_no_mitigation_can_report_a_negative_marginal_value(m):
    """边际收益 = 冒充面里离开的人数，**分母是冒充面**。拿全体 principal 做分母时，
    只持夹具入口的人会让 `principals_removed` 变成负数（面 1 → remaining 2）。
    """
    agg = m.summarize({"p-fixture-only": {m.S_FIXTURE_ISSUER},
                       "p-cfn-only": {m.E_CFN_UPDATE_STACK}})
    for name, mv in agg["marginal_value_if_closed"].items():
        assert 0 <= mv["principals_removed"] <= agg["impersonation_surface_union"], (name, mv)
        assert mv["surface_after"] <= agg["impersonation_surface_union"], (name, mv)
    assert agg["marginal_value_if_closed"]["fixture-issuer-verifier-boundary"][
        "principals_removed"] == 0, "关掉验收工具不该被记成冒充面收益"


def test_a_principal_left_with_only_the_fixture_label_has_left_the_surface(m):
    """`{sign:kms-direct, sign:fixture-issuer}` 的 principal 在 KMS 那一组关掉后只剩受限
    入口（只能签夹具域邮箱）⇒ 它**真的离开了冒充面**，必须计入收益。

    旧口径拿"还有标签没被关掉"当判据，于是它留在 `remaining` 里，
    `restrictive-kms-key-policy` 的 `principals_removed` 少报一个——而那个数字就是
    "限制性 key policy 值不值得做"的唯一依据。单标签的反例照不出这个错：两个标签才行。
    """
    agg = m.summarize({
        "p-kms-and-fixture": {m.S_KMS_DIRECT, m.S_FIXTURE_ISSUER},
        "p-kms-and-hijack": {m.S_KMS_DIRECT, m.S_HIJACK_AUTH},
    })
    assert agg["impersonation_surface_union"] == 2
    mv = agg["marginal_value_if_closed"]["restrictive-kms-key-policy"]
    assert mv["principals_removed"] == 1, mv      # 只有 p-kms-and-fixture 离开
    assert mv["surface_after"] == 1, mv           # p-kms-and-hijack 还剩劫持 signer
    assert agg["marginal_value_if_closed"]["harden-signer-code-update"][
        "principals_removed"] == 0


def test_the_same_membership_criterion_decides_entering_and_leaving_the_surface(m):
    """进面与离面必须用**同一个**判据（`is_surface_label`）。

    两套判据的症状不是崩，而是一个安静地算错的数字：受限标签既不让人进面，
    就不能在离面时把人留住。
    """
    assert m.is_surface_label(m.S_KMS_DIRECT)
    assert m.is_surface_label(m.E_CFN_UPDATE_STACK)
    assert not m.is_surface_label(m.S_FIXTURE_ISSUER)
    # 全部标签都要有明确归属：要么进面，要么在显式的 NON_SURFACE_LABELS 名单里
    for lb in m.ALL_LABELS:
        assert m.is_surface_label(lb) or lb in m.NON_SURFACE_LABELS, lb


def test_the_verifier_role_name_is_pinned_to_the_deploy_auth_constant(m):
    """`Surface.verifier_role_name` 的默认值是那个角色名的**第四份**字面量，必须钉住。

    改了角色名而漏改这里的症状是**静默**的：名字判据不再命中任何 principal，
    `sign:fixture-issuer` 的计数少掉 URL 入口那一半，而闸门与探针都照样 exit 0。

    按 AST 从 `auth/deploy_auth.py`（生产真源）读，**不 import 它**——本模型刻意零 AWS
    依赖，import 会把 boto3 拖进这条路。
    """
    import ast
    src = (_ROOT / "site-builder" / "auth" / "deploy_auth.py").read_text(encoding="utf-8")
    found = [n.value.value for n in ast.parse(src).body
             if isinstance(n, ast.Assign) and len(n.targets) == 1
             and getattr(n.targets[0], "id", None) == "VERIFIER_ROLE_NAME"
             and isinstance(n.value, ast.Constant)]
    assert len(found) == 1, f"deploy_auth.py 里的 VERIFIER_ROLE_NAME 不唯一：{found}"
    assert m.Surface.verifier_role_name == found[0], (
        f"模型写的是 {m.Surface.verifier_role_name!r}，deploy_auth.py 是 {found[0]!r}"
        "——名字判据已经命不中任何 principal 了")


def test_goes_red_when_the_fixture_issuer_entry_is_dropped(m):
    """变形：把"直接 invoke auth"这条入口从动作等价类里去掉 ⇒ 夹具入口的判定转红。
    （这条原先在探针的 `--self-test` 里；判定搬走之后它必须跟着搬。）"""
    s = m.fake_surface()
    assert m.classify(frozenset({f"lambda:InvokeFunction|{s.auth.arn}"}), s) \
        == {m.S_FIXTURE_ISSUER}
    m.A_INVOKE = ("lambda:ThisActionDoesNotExist",)
    assert m.classify(frozenset({f"lambda:InvokeFunction|{s.auth.arn}"}), s) == set()


def test_the_test_copy_is_not_registered_under_the_real_module_name(m):
    """**测试隔离的守卫**：这份可变形的副本不许占用真名 `_impersonation_model`。

    占用的后果是跨文件污染：闸门与探针都按真名 import，同一个进程里后加载的那个会拿到
    被变形测试改坏的模型。实测症状很难往这边猜——单独跑本文件全绿，跑整个 tests 目录时
    闸门那边 11 条红，且红在 grant / coverage 这些看起来毫不相关的用例上。
    """
    assert sys.modules.get("_impersonation_model") is not m, \
        "可变形的测试副本占用了真名 ⇒ 会污染闸门与探针"


# ---- R1-L1：未分析路径**阻止**"确定离场"的定论 -----------------------------------

def test_unanalyzed_path_blocks_a_definite_benefit_claim(m):
    """**Reviewer R1-L1（major）**：`{sign:kms-direct, edge:cfn-template-unanalyzed}` 的
    principal 在 KMS 那组关掉后，"已建模的路径"确实都关了，但它还持一条**未分析**路径
    ⇒ 不能算"确定离开冒充面"。

    修之前实测 `principals_removed=1, surface_after=0`——那正是 ADR 0007 与 spec §3/§9
    禁止的"确定收益"声明：CFN 模板层路径还没分析，凭什么说这个人已经出去了。
    """
    mv = m.summarize({"p": {m.S_KMS_DIRECT, m.E_CFN_TEMPLATE_UNANALYZED}})[
        "marginal_value_if_closed"]["restrictive-kms-key-policy"]
    assert mv["principals_removed"] == 0, mv      # 收益是下界
    assert mv["principals_uncertain"] == 1, mv    # 被未分析路径阻止定论
    assert mv["surface_after"] == 1, mv           # 剩余是上界


def test_proven_restricted_label_still_counts_as_leaving(m):
    """对照：`sign:fixture-issuer` 的可排除性**有依据**（ADR 0002 的 verifier 侧边界是已证明的）
    ⇒ 只剩它的 principal 仍然算离开。修 R1-L1 时不许把这条一起收紧。"""
    mv = m.summarize({"p": {m.S_KMS_DIRECT, m.S_FIXTURE_ISSUER}})[
        "marginal_value_if_closed"]["restrictive-kms-key-policy"]
    assert mv["principals_removed"] == 1, mv
    assert mv["principals_uncertain"] == 0, mv
    assert mv["surface_after"] == 0, mv


def test_goes_red_when_unanalyzed_labels_stop_blocking_the_claim(m):
    """变形：把 `UNANALYZED_LABELS` 清空（即回到"未分析也算可排除"）⇒ 上面那条必须转红。"""
    m.UNANALYZED_LABELS = frozenset()
    mv = m.summarize({"p": {m.S_KMS_DIRECT, m.E_CFN_TEMPLATE_UNANALYZED}})[
        "marginal_value_if_closed"]["restrictive-kms-key-policy"]
    assert mv["principals_removed"] == 1 and mv["principals_uncertain"] == 0, mv


def test_every_unanalyzed_label_is_a_non_surface_label(m):
    """两个集合的关系必须单向成立：未分析 ⊂ 不进并集。反过来不成立（fixture 是例外），
    所以不能把它们合成一个集合。"""
    assert m.UNANALYZED_LABELS <= m.NON_SURFACE_LABELS
    assert m.S_FIXTURE_ISSUER in m.NON_SURFACE_LABELS
    assert m.S_FIXTURE_ISSUER not in m.UNANALYZED_LABELS
