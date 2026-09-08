"""deployer 栈里两把会话签名 CMK 的形态守卫（spec §11.2 / ADR 0001），按 AST 读 app.py，不 synth。"""
import ast
from pathlib import Path

APP = Path(__file__).parents[1] / "infra" / "app.py"


def _key_calls():
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Key" \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "kms":
            cid = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
            out[cid] = {k.arg: ast.unparse(k.value) for k in node.keywords}
    return out


def test_exactly_two_session_keys_one_per_family_with_the_kid_in_the_construct_id():
    keys = _key_calls()
    assert set(keys) == {"SiteSessionKeyRsV1", "ConsoleSessionKeyRsV1"}, keys.keys()


def test_every_session_key_is_rsa_2048_sign_verify_unrotated_and_retained():
    for cid, kw in _key_calls().items():
        assert kw["key_spec"] == "kms.KeySpec.RSA_2048", cid
        assert kw["key_usage"] == "kms.KeyUsage.SIGN_VERIFY", cid
        assert kw["enable_key_rotation"] == "False", cid      # 非对称 CMK 不支持自动轮转（spec §3.3）
        assert kw["removal_policy"] == "RemovalPolicy.RETAIN", cid
        assert "alias/site-builder/session/" in kw["alias"], cid
        assert "—" not in kw.get("description", "") and "–" not in kw.get("description", "")


def test_no_key_policy_is_passed_so_the_default_root_delegation_applies():
    for cid, kw in _key_calls().items():
        assert "policy" not in kw and "admins" not in kw, f"{cid}: ADR 0001 —— 默认 key policy，不做限制性策略"


def test_each_key_arn_is_exported_for_the_config_backfill():
    src = APP.read_text(encoding="utf-8")
    assert 'CfnOutput(self, "SiteSessionKeyRsV1Arn"' in src or '"SiteSessionKeyRsV1Arn"' in src
    assert '"ConsoleSessionKeyRsV1Arn"' in src
