"""`scripts/verify_sfn_failure_paths.py` 的产物桶名**派生**（Codex review 两轮）：原先读 `[Deployer] artifacts_bucket`
且不插值（对着 `site-artifacts-{account_id}` 字面量跑）；那个键是假配置面（唯一读者是本脚本、CDK 写死桶名），已从
`.example` 删除，桶名改由 `[Platform] account_id` 派生。账号校验用 ASCII 正则（`isdigit()` 会放过全角 / 阿拉伯数字）。

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


def test_the_bucket_is_derived_from_the_account():
    assert vsf.artifacts_bucket_for(ACCT) == f"site-artifacts-{ACCT}"
    assert vsf.artifacts_bucket_for(f"  {ACCT}\n") == f"site-artifacts-{ACCT}"     # 只剥两端空白


@pytest.mark.parametrize("account", [
    "", "12345", "1111222233334",
    "١١١١٢٢٢٢٣٣٣٣",          # 阿拉伯-印度数字：str.isdigit() 为 True，但不是 AWS 账号
    "１１１１２２２２３３３３",  # 全角数字：同上
    "11112222333a", "111122223333 # 注释",
])
def test_non_ascii_or_malformed_accounts_are_rejected(account):
    if account in ("١١١١٢٢٢٢٣٣٣٣", "１１１１２２２２３３３３"):
        assert account.isdigit() and len(account) == 12, "这两条正是 isdigit() 放过的反例——它们要是不再 isdigit，负例就失去意义"
    with pytest.raises(SystemExit, match="12 位 ASCII 数字"):
        vsf.artifacts_bucket_for(account)


def test_main_derives_the_env_var_and_no_longer_reads_a_config_key():
    src = (ROOT / "site-builder" / "scripts" / "verify_sfn_failure_paths.py").read_text(encoding="utf-8")
    assert 'os.environ["ARTIFACTS_BUCKET"] = artifacts_bucket_for(read_cfg("Platform", "account_id"))' in src
    assert 'artifacts_bucket"' not in src.replace('artifacts_bucket_for', ''), "不许再读 [Deployer] artifacts_bucket"


def test_the_dead_key_is_gone_from_the_example():
    ex = (ROOT / "site-builder" / "config.ini.example").read_text(encoding="utf-8")
    assert "\nartifacts_bucket" not in ex, ".example 里的 artifacts_bucket 是假配置面（CDK 写死桶名、无人读）"
