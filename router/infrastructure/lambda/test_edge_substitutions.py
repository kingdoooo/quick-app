"""`edge_substitutions.py` 自己的用例（3c-1B ticket 22）。

它是四个套件共用的 helper，所以它自身必须有元用例证明：少一项替换会红、拼错 override 会红。
**不能靠"某个套件恰好炸"**——那正是这一票要消掉的形状（模块级 json.loads 让报文变成
JSONDecodeError，完全不提占位符）。
"""
import json
import re
from pathlib import Path

import pytest

import edge_substitutions as es

HERE = Path(__file__).resolve().parent


def test_defaults_cover_every_placeholder_in_the_real_edge_source():
    """真源里的每个 `{{…}}` 都要有默认值——这条就是"加了注入点忘了补表"的闸。"""
    src = es.EDGE_SRC_PATH.read_text(encoding="utf-8")
    found = {m[2:-2] for m in es.PLACEHOLDER_RE.findall(src)}
    assert found, "源码里一个占位符都没有？取值路径变了"
    missing = found - set(es.DEFAULTS)
    assert not missing, f"DEFAULTS 缺这些占位符: {sorted(missing)}"
    unused = set(es.DEFAULTS) - found
    assert not unused, f"DEFAULTS 有源码里已经不存在的项（该删）: {sorted(unused)}"


def test_the_real_source_substitutes_clean_and_imports():
    """端到端：真源经默认值替换后无残留、且**替换值真的能被消费**。

    ticket 21 之后 allowlist 是惰性解析的（`_SITE_ALLOWLIST` 在 import 期是 None），所以这里
    必须调那个取值函数——只断言 import 成功已经不能证明"注入值是合法 JSON"了
    （不替换也能 import 正是那张票买的东西，见 test_edge_lazy_config.py）。
    """
    src = es.edge_source()
    assert not es.PLACEHOLDER_RE.findall(src)
    mod = es.load_edge_module("_edge_subs_selftest")
    allowlist = mod._site_allowlist()
    assert isinstance(allowlist, dict) and set(allowlist) == set(es.DEFAULT_SITE_ALLOWLIST)


def test_a_missing_substitution_is_a_loud_error_naming_the_placeholder():
    """元用例：源码里多一个表里没有的占位符 ⇒ 抛，且报文点名它。"""
    src = "X = '{{BRAND_NEW_THING}}'\n"
    with pytest.raises(AssertionError, match=r"BRAND_NEW_THING"):
        es.substitute(src)


def test_a_placeholder_containing_digits_is_also_caught():
    """回归：原来的正则是 `[A-Z_]+`，含数字的占位符会**静默**留在源码里。"""
    assert es.PLACEHOLDER_RE.findall("a {{ACCESS_TABLE_V2}} b") == ["{{ACCESS_TABLE_V2}}"]
    with pytest.raises(AssertionError, match=r"ACCESS_TABLE_V2"):
        es.substitute("X = '{{ACCESS_TABLE_V2}}'\n")
    # 旧正则确实看不见它——把"这条守卫真的有用"钉住，而不是只信正则长得对
    assert not re.compile(r"\{\{[A-Z_]+\}\}").findall("{{ACCESS_TABLE_V2}}")


def test_a_typo_in_an_override_name_is_rejected_not_silently_ignored():
    """`REQUIRE_IDP_CLAIMM="false"` 静默用默认值 = 调用方以为自己关了开关，实际没关。"""
    with pytest.raises(AssertionError, match=r"REQUIRE_IDP_CLAIMM"):
        es.edge_source(REQUIRE_IDP_CLAIMM="false")


def test_overrides_win_and_defaults_fill_the_rest():
    src = es.edge_source(REQUIRE_IDP_CLAIM="false", BASE_DOMAIN="example.test")
    assert 'REQUIRE_IDP_CLAIM = "false"' in src and 'BASE_DOMAIN = "example.test"' in src
    assert 'for x in "Feishu,Okta"' in src          # 没被覆盖的那些仍取默认值（收紧值）


def test_default_security_switches_are_the_tightened_values():
    """测试的默认态不许比生产松：白名单为空 + REQUIRE_IDP_CLAIM=true 会全站锁死，
    而"默认就把 REQUIRE_IDP_CLAIM 设成 false"会让一整类鉴权用例在假前提下通过。"""
    assert es.DEFAULTS["REQUIRE_IDP_CLAIM"] == "true"
    assert es.DEFAULTS["TRUSTED_IDPS"].strip()
    allow = json.loads(es.DEFAULTS["SITE_ALLOWLIST_JSON"])      # 合法 JSON，否则首次取值就炸
    # 默认 allowlist 只含 **site family 的公钥**（spec §4.1：console 的 key 不进 Edge），
    # 且形态必须是 3c-final 那一套——注成 HS 形态的话 `_site_allowlist` 会在 b64 解码处才炸。
    assert allow and all(e["alg"] == "RS256" and e["spki_b64"] and "secret" not in e
                         for e in allow.values())
    assert all(kid.startswith("site-") for kid in allow)


def test_load_edge_module_can_write_the_copy_where_router_conftest_expects_it(tmp_path):
    """router 那边靠 `_*_testable` 的模块名给埋点装假件，所以落盘这条路要留着。"""
    mod = es.load_edge_module("_edge_subs_written_testable", write_to=tmp_path,
                              BASE_DOMAIN="written.example.test")
    assert (tmp_path / "_edge_subs_written_testable.py").exists()
    assert mod.BASE_DOMAIN == "written.example.test"
    import sys
    assert sys.modules["_edge_subs_written_testable"] is mod
