"""`scripts/verify_session_token_semantics.py`：判定逻辑（纯函数）与自测。

3c-1B ticket 01 起判据全按新形态；**3c-1B-G A1 起八条**，且"用途混用"与"跨 family"
拆成各自只改一个变量的两组判据（见被测脚本 docstring 里那段"为什么混用那两枚用 site kid"）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import verify_session_token_semantics as gate  # noqa: E402  —— import 期不得碰 AWS（原版在 import 时就读 SSM）

TOKENS = dict(good="GOOD", upgrade="UPG", console_session="CONS", cross_family="XFAM")
SITE, AUTH = "https://app-x.example.test/", "auth.example.test"


def _names(get=None):
    return [c.name for c in gate.run_checks(get or gate._ideal_responder(), gate.Tokens(**TOKENS),
                                            site_url=SITE, auth_host=AUTH)]


def test_import_has_no_side_effects():
    assert callable(gate.main) and callable(gate.run_checks)


def test_criteria_are_expressed_in_kid_form_not_old_typ():
    names = _names()
    assert len(names) == 8
    assert not any("typ" in n for n in names)


def test_the_two_mix_use_criteria_say_they_are_signed_by_the_site_kid():
    """混用那两条必须**自陈**用的是 site kid。

    这条防的是本票要修的那个退化：如果它们又变回 console kid 签，Edge 会在 allowlist
    就拒掉、`token_use` 比较根本没执行，而判据名字还写着"证明用途比较" ⇒ 假证据。
    """
    mix = [n for n in _names() if "token_use" in n]
    assert len(mix) == 2, mix
    assert all("site kid 签" in n for n in mix), mix


def test_exactly_one_criterion_isolates_the_kid_family_variable():
    fam = [n for n in _names() if "kid family" in n]
    assert len(fam) == 1 and "console kid" in fam[0], fam


def test_allow_paths_require_200_not_merely_non_302():
    checks = gate.run_checks(
        lambda u, c: (500, {}) if "GOOD" in c else (302, {"location": f"https://{AUTH}/login"}),
        gate.Tokens(**TOKENS), site_url=SITE, auth_host=AUTH)
    assert [c.ok for c in checks if "放行" in c.name] == [False, False, False]


def test_self_test_is_green_on_ideal_and_red_on_each_broken_path():
    assert gate.self_test() == 0
    assert gate.self_test(break_shadow=True) != 0
    assert gate.self_test(break_mixuse=True) != 0
    assert gate.self_test(break_family=True) != 0


def test_the_two_bad_paths_are_separable_not_one_flag():
    """`break_mixuse` 只该弄红用途那两条，`break_family` 只该弄红跨 family 那条。

    合成一个旗标的话，"用途比较坏了"与"family 隔离坏了"在报告里分不开，
    而两者的修法与后果完全不同（一个是 Edge 少比一个字段，一个是 allowlist 装错了 key）。
    """
    def red(**flags):
        return {c.name for c in gate.run_checks(gate._ideal_responder(**flags), gate.Tokens(**TOKENS),
                                                site_url=SITE, auth_host=AUTH) if not c.ok}

    mix, fam = red(break_mixuse=True), red(break_family=True)
    assert all("token_use" in n for n in mix) and len(mix) == 2, mix
    assert all("kid family" in n for n in fam) and len(fam) == 1, fam
    assert not (mix & fam)


def test_every_criterion_has_some_break_path_that_makes_it_red():
    """元用例：除两条对照外，每条判据都必须能被某个 break 旗标弄红——否则它是 pass-now 的。"""
    all_red = set()
    for flags in ({"break_shadow": True}, {"break_mixuse": True}, {"break_family": True}):
        all_red |= {c.name for c in gate.run_checks(gate._ideal_responder(**flags), gate.Tokens(**TOKENS),
                                                    site_url=SITE, auth_host=AUTH) if not c.ok}
    never_red = [n for n in _names() if n not in all_red and "对照" not in n]
    assert not never_red, f"这些判据没有任何 break 路径能让它红：{never_red}"
