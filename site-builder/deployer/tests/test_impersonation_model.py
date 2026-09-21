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
