"""stack.py 的静态守卫（stack.py import aws_cdk，普通解释器里没有，所以按源码文本断言）。"""
from pathlib import Path

SRC = (Path(__file__).parents[1] / "stack.py").read_text()


def test_stack_uses_shared_session_keys_helpers_not_inline_copies():
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert "legacy_entry(" in body and '"on" if keys.legacy_param else "off"' not in body
    assert "env_json" not in body, "局部名 env_json 与 session_keys.env_json 撞名"


def test_stack_ssm_failure_injects_the_synth_placeholder_not_an_empty_allowlist():
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert 'text = "{}"' not in body, "空 allowlist 看起来合法，synth 与部署前测试都过；要注入带 SYNTH-ONLY 标记的占位"
    assert "SYNTH_PLACEHOLDER_ALLOWLIST_JSON" in body
