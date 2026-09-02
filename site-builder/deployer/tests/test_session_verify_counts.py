"""`scripts/session_verify_counts.py` 的纯函数：结果解析、汇总渲染、词表（plan 3c-1A Task 5）。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import session_verify_counts as svc  # noqa: E402


def test_outcome_vocabulary_matches_session_module():
    import session
    assert set(svc.OUTCOMES) == set(session.OUTCOMES)


def test_parse_results_keeps_only_vocabulary_and_sums_duplicates():
    rows = [[{"field": "outcome", "value": "accepted_legacy"}, {"field": "n", "value": "3"}],
            [{"field": "outcome", "value": "accepted_legacy"}, {"field": "n", "value": "2.0"}],
            [{"field": "outcome", "value": "totally_made_up"}, {"field": "n", "value": "9"}],
            [{"field": "n", "value": "9"}]]
    assert svc.parse_results(rows) == {"accepted_legacy": 5}


def test_render_totals_and_legacy_count():
    text, total, legacy = svc.render({"auth": {"accepted_legacy": 2, "unknown_kid": 1},
                                      "panel": {"accepted_current": 4},
                                      "edge": {"accepted_legacy": 10, "expired": 1}})
    assert (total, legacy) == (18, 12)
    assert "accepted_legacy" in text and "总量 18" in text


def test_query_filters_on_the_event_marker_and_groups_by_outcome():
    assert '"event": "session_verify"' in svc.QUERY and "by outcome" in svc.QUERY
