"""`scripts/verify_session_token_semantics.py`：判定逻辑（纯函数）与自测。3c-1B ticket 01 起七条判据全按新形态。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import verify_session_token_semantics as gate  # noqa: E402  —— import 期不得碰 AWS（原版在 import 时就读 SSM）


def test_import_has_no_side_effects():
    assert callable(gate.main) and callable(gate.run_checks)


def test_criteria_are_expressed_in_kid_form_not_old_typ():
    names = [c.name for c in gate.run_checks(gate._ideal_responder(), gate.Tokens("GOOD", "UPG", "CONS"),
                                             site_url="https://app-x.example.test/", auth_host="auth.example.test")]
    assert len(names) == 7
    assert not any("typ" in n for n in names)
    assert sum("console kid" in n for n in names) == 2     # 升级码 + 面板会话两条混用判据


def test_allow_paths_require_200_not_merely_non_302():
    checks = gate.run_checks(lambda u, c: (500, {}) if "GOOD" in c else (302, {"location": "https://auth.example.test/login"}),
                             gate.Tokens("GOOD", "UPG", "CONS"),
                             site_url="https://app-x.example.test/", auth_host="auth.example.test")
    assert [c.ok for c in checks if "放行" in c.name] == [False, False, False]


def test_self_test_is_green_on_ideal_and_red_on_each_broken_path():
    assert gate.self_test() == 0
    assert gate.self_test(break_shadow=True) != 0
    assert gate.self_test(break_mixuse=True) != 0
