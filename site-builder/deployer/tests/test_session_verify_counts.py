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


# ---- 3c-1B ticket 18：脚本自己下判断，不把三列留给人读；区级失败不静默 --------------------------
#
# ⑨ 守的是不可逆的 ⑩（删 SSM 参数）。原来 `--require-total` 只判"总量非 0"，`accepted_*` 的归零
# 全靠人读三列，脚本 exit 0 ≠ 闸门绿；而 `edge_log_groups` 把任一区的 AccessDenied / 限流 / 网络
# 错误都当"该区没有日志组"跳过，少算一区就是 `accepted_previous` 假 0。

import types as _types  # noqa: E402


def test_nonzero_outcomes_names_the_verifier_columns_that_are_not_zero():
    by = {"auth": {"accepted_previous": 0, "accepted_current": 5},
          "panel": {"accepted_current": 2},
          "edge": {"accepted_previous": 3, "accepted_legacy": 1}}
    got = svc.nonzero_outcomes(by, ["accepted_previous", "accepted_legacy"])
    assert got == ["accepted_previous: auth=0 panel=0 edge=3", "accepted_legacy: auth=0 panel=0 edge=1"]
    assert svc.nonzero_outcomes(by, ["accepted_previous"]) == ["accepted_previous: auth=0 panel=0 edge=3"]
    assert svc.nonzero_outcomes({"auth": {}, "panel": {}, "edge": {"accepted_current": 9}},
                                ["accepted_previous", "accepted_legacy"]) == []


@pytest.mark.parametrize("edge_counts,expect_rc", [({"accepted_current": 4}, 0),
                                                   ({"accepted_current": 4, "accepted_previous": 1}, 1)])
def test_require_zero_flag_decides_the_exit_code(monkeypatch, capsys, edge_counts, expect_rc):
    """⑨ 的判定命令要能直接当闸门用：`--require-zero accepted_previous` 在任一列 > 0 时退 1。"""
    by = {"auth": {"accepted_current": 1}, "panel": {"accepted_current": 1}, "edge": edge_counts}
    monkeypatch.setattr(svc, "collect", lambda session, hours: by)
    monkeypatch.setattr(svc.boto3, "Session", lambda: None)
    rc = svc.main(["--hours", "26", "--require-total", "--require-zero", "accepted_previous"])
    assert rc == expect_rc
    err = capsys.readouterr().err
    assert ("accepted_previous" in err) == (expect_rc == 1)


def test_require_zero_rejects_outcomes_outside_the_vocabulary():
    """打错字不能被静默接受成"永远为 0 的列"。"""
    with pytest.raises(SystemExit) as ei:
        svc.main(["--require-zero", "accepted_previuos"])
    assert ei.value.code == 2   # argparse 的用法错误


def test_require_zero_is_repeatable_and_all_must_hold(monkeypatch):
    by = {"auth": {"accepted_current": 1}, "panel": {"accepted_current": 1},
          "edge": {"accepted_current": 1, "accepted_legacy": 2}}
    monkeypatch.setattr(svc, "collect", lambda session, hours: by)
    monkeypatch.setattr(svc.boto3, "Session", lambda: None)
    assert svc.main(["--require-zero", "accepted_previous"]) == 0
    assert svc.main(["--require-zero", "accepted_previous", "--require-zero", "accepted_legacy"]) == 1


class _FakeLogs:
    def __init__(self, behaviour):
        self._b = behaviour

    def describe_log_groups(self, logGroupNamePrefix):
        if isinstance(self._b, Exception):
            raise self._b
        return {"logGroups": [{"logGroupName": n} for n in self._b]}


class _FakeSession:
    """`describe_regions()` 默认只返回**已启用**的区，所以每区的失败都不是"未启用"。"""
    def __init__(self, per_region):
        self._per_region = per_region

    def client(self, service, region_name):
        if service == "ec2":
            return _types.SimpleNamespace(describe_regions=lambda: {
                "Regions": [{"RegionName": r} for r in self._per_region]})
        return _FakeLogs(self._per_region[region_name])


def test_edge_log_groups_skips_regions_without_the_group_but_keeps_the_rest():
    name = f"/aws/lambda/us-east-1.{svc.EDGE_FN}"
    sess = _FakeSession({"us-east-1": [name, "/aws/lambda/other"], "eu-west-1": [], "ap-northeast-1": [name]})
    assert svc.edge_log_groups(sess) == [("ap-northeast-1", name), ("us-east-1", name)]


def test_edge_log_groups_aborts_when_any_region_query_fails_instead_of_undercounting():
    """部分失明必须响亮：一区 AccessDenied 静默跳过 = 那一区的 accepted_previous 永远读成 0。"""
    name = f"/aws/lambda/us-east-1.{svc.EDGE_FN}"
    sess = _FakeSession({"us-east-1": [name], "eu-west-1": RuntimeError("AccessDeniedException"), "ap-south-1": [name]})
    with pytest.raises(SystemExit) as ei:
        svc.edge_log_groups(sess)
    msg = str(ei.value)
    assert "eu-west-1" in msg and "AccessDeniedException" in msg


def test_missing_outcome_columns_names_the_verifiers_where_it_is_zero():
    """判据的另一半："三列 accepted_current 全 > 0"，按列判、不被别列遮住。"""
    by = {"auth": {"accepted_current": 3}, "panel": {"accepted_legacy": 1}, "edge": {"accepted_current": 0}}
    assert svc.missing_outcome_columns(by, ["accepted_current"]) == ["accepted_current: panel=0 edge=0"]
    assert svc.missing_outcome_columns({"auth": {"accepted_current": 1}, "panel": {"accepted_current": 1},
                                        "edge": {"accepted_current": 1}}, ["accepted_current"]) == []


@pytest.mark.parametrize("panel_counts,expect_rc", [({"accepted_current": 1}, 0), ({"unknown_kid": 1}, 1)])
def test_require_nonzero_flag_decides_the_exit_code(monkeypatch, capsys, panel_counts, expect_rc):
    by = {"auth": {"accepted_current": 1}, "panel": panel_counts, "edge": {"accepted_current": 1}}
    monkeypatch.setattr(svc, "collect", lambda session, hours: by)
    monkeypatch.setattr(svc.boto3, "Session", lambda: None)
    rc = svc.main(["--require-total", "--require-nonzero", "accepted_current"])
    assert rc == expect_rc
    assert ("panel=0" in capsys.readouterr().err) == (expect_rc == 1)


# ---- 3c-1B-G A2：命名排空闸门 -----------------------------------------------------------------
#
# 不可逆的 ⑩ 之前那一步判定，原先靠操作者同时输对四个参数
# （`--hours 26 --require-total --require-zero X --require-nonzero accepted_current`）。
# 少任何一个都会**静默放宽**，最坏的一种是空窗口：`--require-zero` 只报非零列，
# 三列全空自然"通过"⇒ exit 0 被读成"已排空"，然后就去删参数了。
# `--drain-gate` 把这四条锁进脚本，操作者只需要选 previous 还是 legacy。

def _gate(monkeypatch, by, argv):
    monkeypatch.setattr(svc, "collect", lambda session, hours: by)
    monkeypatch.setattr(svc.boto3, "Session", lambda: None)
    return svc.main(argv)


FULL = {"auth": {"accepted_current": 2}, "panel": {"accepted_current": 1},
        "edge": {"accepted_current": 5}}


def test_drain_gate_passes_only_when_all_four_conditions_hold(monkeypatch):
    assert _gate(monkeypatch, FULL, ["--drain-gate", "previous"]) == 0


def test_drain_gate_fails_on_an_empty_window_where_require_zero_alone_passes(monkeypatch, capsys):
    """**本票的核心反例**：空窗口下裸 `--require-zero` 退 0，而 `--drain-gate` 必须退 1。"""
    empty = {"auth": {}, "panel": {}, "edge": {}}
    assert _gate(monkeypatch, empty, ["--hours", "26", "--require-zero", "accepted_previous"]) == 0
    assert _gate(monkeypatch, empty, ["--drain-gate", "previous"]) == 1
    err = capsys.readouterr().err
    # 空窗口要被**两条**判据同时抓住：埋点静默 + accepted_current 没有非零列
    assert "没有任何 session_verify" in err and "accepted_current" in err, err


@pytest.mark.parametrize("by,why", [
    ({"auth": {"accepted_current": 1}, "panel": {"accepted_current": 1},
      "edge": {"accepted_current": 1, "accepted_previous": 1}}, "previous 列非零"),
    ({"auth": {"accepted_current": 1}, "panel": {}, "edge": {"accepted_current": 1}}, "panel 总量为 0"),
    ({"auth": {"unknown_kid": 3}, "panel": {"unknown_kid": 1}, "edge": {"unknown_kid": 9}},
     "有流量但 accepted_current 三列全 0（signer 其实没在发新形态）"),
])
def test_drain_gate_catches_each_way_the_four_conditions_can_break(monkeypatch, by, why):
    assert _gate(monkeypatch, by, ["--drain-gate", "previous"]) == 1, why


def test_drain_gate_refuses_a_window_shorter_than_the_ttl_budget(monkeypatch):
    """`--hours 2.6`（把 26 打错）必须响亮拒绝，而不是按 2.6 小时给出一个"通过"。"""
    with pytest.raises(SystemExit) as ei:
        _gate(monkeypatch, FULL, ["--drain-gate", "previous", "--hours", "2.6"])
    assert "26" in str(ei.value)


def test_drain_gate_defaults_to_the_full_window_without_being_told(monkeypatch):
    seen = {}

    def _collect(session, hours):
        seen["hours"] = hours
        return FULL

    monkeypatch.setattr(svc, "collect", _collect)
    monkeypatch.setattr(svc.boto3, "Session", lambda: None)
    assert svc.main(["--drain-gate", "legacy"]) == 0
    assert seen["hours"] >= 26


def test_drain_gate_picks_the_outcome_column_from_its_argument(monkeypatch, capsys):
    by = {"auth": {"accepted_current": 1}, "panel": {"accepted_current": 1},
          "edge": {"accepted_current": 1, "accepted_legacy": 4}}
    assert _gate(monkeypatch, by, ["--drain-gate", "previous"]) == 0    # legacy 列不在本闸门判据里
    assert _gate(monkeypatch, by, ["--drain-gate", "legacy"]) == 1
    assert "accepted_legacy" in capsys.readouterr().err


def test_drain_gate_rejects_an_unknown_target():
    with pytest.raises(SystemExit) as ei:
        svc.main(["--drain-gate", "current"])
    assert ei.value.code == 2
