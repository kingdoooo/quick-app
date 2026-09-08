"""deployer 栈里两把会话签名 CMK 的形态守卫（spec §11.2 / ADR 0001），按 AST 读 app.py，不 synth。"""
import ast
import re
from pathlib import Path

import pytest

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


def _kid_of(construct_id: str) -> str:
    """construct ID → 它**应该**服务的 kid（`SiteSessionKeyRsV1` → `site-rs-v1`）。"""
    m = re.fullmatch(r"(Site|Console)SessionKeyRsV(\d+)", construct_id)
    assert m, f"{construct_id}: construct ID 不是 `{{Site|Console}}SessionKeyRsV<n>` 形态"
    return f"{m.group(1).lower()}-rs-v{m.group(2)}"


def test_every_alias_names_the_same_kid_as_its_own_construct():
    """alias / description / CfnOutput 都必须指向**这个 construct 自己的** kid。

    两把 key 的参数只差 kid 一个词，是复制粘贴出来的（见 app.py 那段注释：显式两段是为了让本文件
    的 AST 判据取得到 construct ID）。漏改一处的后果不是崩：console 那把会挂上 site 的 alias，
    于是控制台里两个 alias 指着同一把 key、另一把没有 alias，而 `key_arn` 仍然是对的
    ⇒ 部署、闸门、指纹脚本全绿，只有人在控制台里读错。**逐 construct 对账**，不做全文匹配。
    """
    src = APP.read_text(encoding="utf-8")
    keys = _key_calls()
    assert keys, "一把 key 都没解析到——先看 _key_calls 的判据"
    for cid, kw in keys.items():
        kid = _kid_of(cid)
        try:
            alias = ast.literal_eval(kw["alias"])
        except (ValueError, SyntaxError):
            pytest.fail(f"{cid}: alias 不是字面量（{kw['alias']}）——AST 守卫读不出它服务哪个 kid")
        assert alias == f"alias/site-builder/session/{kid}", (cid, alias)
        assert kid in ast.literal_eval(kw["description"]), (cid, kw["description"])
        # CfnOutput 也逐个对账：名字是本脚本与 session_key_fingerprint.py 之间的唯一契约
        assert f'CfnOutput(self, "{cid}Arn"' in src, f"{cid} 没有对应的 CfnOutput"
