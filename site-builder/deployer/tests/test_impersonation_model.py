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
