"""`scripts/verify_sfn_failure_paths.py` 对 `[Deployer] artifacts_bucket` 的解析（Codex review：原先把
`site-artifacts-{account_id}` 字面量原样塞进环境变量，验收工具对着一个不存在的桶跑）。

evidence: fake/unit。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location(
    "verify_sfn_failure_paths", ROOT / "site-builder" / "scripts" / "verify_sfn_failure_paths.py")
vsf = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_sfn_failure_paths"] = vsf
_SPEC.loader.exec_module(vsf)

ACCT = "111122223333"


def test_the_template_resolves_to_the_cdk_convention():
    assert vsf.resolve_artifacts_bucket("site-artifacts-{account_id}", ACCT) == f"site-artifacts-{ACCT}"
    assert vsf.resolve_artifacts_bucket(f"site-artifacts-{ACCT}", ACCT) == f"site-artifacts-{ACCT}"   # 等值字面量放行


@pytest.mark.parametrize("raw,account,fragment", [
    ("site-artifacts-{account_id}", "", "12 位数字"),
    ("site-artifacts-{account_id}", "12345", "12 位数字"),
    ("my-own-bucket", ACCT, "写死"),
    ("site-artifacts-{acct}", ACCT, "写死"),           # 占位符名字写错 ⇒ 花括号原样留下 ⇒ 不等于约定名
])
def test_anything_but_the_convention_is_rejected(raw, account, fragment):
    with pytest.raises(SystemExit, match=fragment):
        vsf.resolve_artifacts_bucket(raw, account)


def test_main_wires_the_resolver_in_front_of_the_env_var():
    """接线守卫：环境变量必须经解析器，不许再直接赋 read_cfg 的原值。"""
    src = (ROOT / "site-builder" / "scripts" / "verify_sfn_failure_paths.py").read_text(encoding="utf-8")
    assert 'os.environ["ARTIFACTS_BUCKET"] = resolve_artifacts_bucket(' in src
    assert 'os.environ["ARTIFACTS_BUCKET"] = read_cfg(' not in src
