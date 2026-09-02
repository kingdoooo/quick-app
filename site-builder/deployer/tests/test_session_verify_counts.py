"""`scripts/session_verify_counts.py` 的纯函数：结果解析、汇总渲染、词表（plan 3c-1A Task 5）。"""
import sys
from pathlib import Path

import pytest

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


def test_edge_function_name_comes_from_the_gate_not_a_second_literal():
    sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
    import verify_account_trust_boundary as g
    assert svc.EDGE_FN is g.EDGE_ORIGIN_REQUEST_FN


def test_require_each_fails_when_any_single_verifier_is_silent():
    """§8：退役判据的另一半是"埋点在工作"——按 verifier 分别看，Edge 列为 0 不能被 auth/panel 的总量遮住。"""
    by = {"auth": {"accepted_legacy": 3}, "panel": {"accepted_legacy": 1}, "edge": {}}
    assert svc.silent_verifiers(by) == ["edge"]
    assert svc.silent_verifiers({"auth": {"x": 1}, "panel": {"y": 2}, "edge": {"accepted_legacy": 5}}) == []


def test_no_edge_log_group_anywhere_is_an_error_not_a_silent_skip():
    with pytest.raises(SystemExit):
        svc.require_edge_groups([])
