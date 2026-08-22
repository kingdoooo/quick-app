"""体检脚本的单测。**必须有**：它是 S1 发布闸门之一，而它上一版是假绿的。"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "scripts"))
import audit_policy_rows as apr  # noqa: E402


def _row(**over):
    row = {"site_id": {"S": "s-1"}, "status": {"S": "ACTIVE"},
           "owner": {"S": "o@example.test"}, "require_login": {"BOOL": True},
           "allowed_users": {"S": "org"}, "collaborators": {"L": []}}
    row.update(over)
    return row


def test_clean_row_passes():
    assert apr.audit([_row()]) == (1, [])


def test_deleted_rows_are_not_audited():
    assert apr.audit([_row(status={"S": "DELETED"},
                           require_login={"N": "0"})]) == (0, [])


@pytest.mark.parametrize("field,value", [
    ("require_login", {"N": "0"}),                    # 会被 bool() 洗成 False
    ("allowed_users", {"L": [{"N": "7"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("allowed_users", {"L": []}),                     # 空名单 ← v1 假绿点
    ("allowed_users", {"L": [{"S": "not-an-email"}]}),  # 过不了 EMAIL_RE ← v1 假绿点
    ("collaborators", {"L": [{"N": "9"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("owner", {"S": ""}),                             # 空 owner
])
def test_bad_shapes_are_reported(field, value):
    n, bad = apr.audit([_row(**{field: value})])
    assert n == 1 and len(bad) == 1, f"{field}={value} 应被报出来"


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_missing_ambiguous_field_is_reported(field):
    row = _row()
    del row[field]
    assert len(apr.audit([row])[1]) == 1


def test_missing_collaborators_is_fine():
    row = _row()
    del row["collaborators"]
    assert apr.audit([row]) == (1, [])


# ---- 非 ACTIVE 行的可见性（fix round 1）----
# 背景：绿字原本写的是"不会卡住任何**现有站点**"，而证据只覆盖 ACTIVE 行。
# 77 行里 70 行没被评价，其中 15 行实测会被拒 —— 操作员读到的那句话是错的。
# 闸门（退出码）仍然只由 ACTIVE 驱动，这是对的；但被拒的非 ACTIVE 行必须**可见**。


def _bad_deleted(site_id="s-old"):
    """一条 DELETED 且缺 require_login 的行——真机上那 15 行就是这个形态。"""
    row = _row(site_id={"S": site_id}, status={"S": "DELETED"})
    del row["require_login"]
    return row


def _run_main(monkeypatch, capsys, rows):
    """跑 main()，把 scan 换成给定的行。→ (退出码, stdout)"""
    monkeypatch.setattr(apr, "_cfg", lambda: {
        "Platform": {"region": "us-east-1"},
        "Deployer": {"sites_table": "sites-under-test"}})

    class _DDB:
        def scan(self, **kw):
            return {"Items": rows}

    monkeypatch.setattr(apr.boto3, "client", lambda *a, **kw: _DDB())
    code = apr.main()
    return code, capsys.readouterr().out


def test_non_active_refusals_are_surfaced():
    """非 ACTIVE 的坏行必须能被查出来（原来根本没有这个出口）。"""
    bad = apr.audit_non_active([_row(), _bad_deleted()])
    assert len(bad) == 1
    site_id, status, reason = bad[0]
    assert (site_id, status) == ("s-old", "DELETED")
    assert "require_login" in reason


def test_audit_return_shape_is_unchanged():
    """`audit()` 仍是 (ACTIVE 数, [(site_id, 原因)]) 两元组——闸门契约不许变。"""
    assert apr.audit([_row(), _bad_deleted()]) == (1, [])


def test_gate_stays_green_while_the_warning_is_printed(monkeypatch, capsys):
    """**本轮修复的核心**：绿闸门 + 可见警告要同时成立，所以两个都断言。

    只断退出码会让"警告被删掉"照样全绿；只断输出会让"闸门被非 ACTIVE 行
    带红"照样全绿。这两个错误方向恰好互为对方的漏网之鱼。
    """
    code, out = _run_main(monkeypatch, capsys, [_row(), _bad_deleted()])
    assert code == 0, "非 ACTIVE 行不该把闸门带红"
    assert "非 ACTIVE" in out and "1" in out, "警告块缺失"
    assert "s-old" in out, "警告块必须点出是哪一行"
    assert "DELETED" in out, "警告块必须点出它的 status"
    assert "require_login" in out, "警告块必须带 effective_policy 给出的原因"


def test_green_sentence_is_scoped_to_what_was_checked(monkeypatch, capsys):
    """绿字不许再说"任何现有站点"——证据只覆盖 ACTIVE 行。"""
    code, out = _run_main(monkeypatch, capsys, [_row(), _bad_deleted()])
    assert code == 0
    assert "任何现有站点" not in out, "绿字仍在做证据支撑不了的全量承诺"
    assert "ACTIVE" in out


def test_redeploy_semantics_are_explained(monkeypatch, capsys):
    """警告块要告诉操作员这些行意味着什么，否则他只能自己猜要不要拦发布。"""
    _code, out = _run_main(monkeypatch, capsys, [_row(), _bad_deleted()])
    assert "重新部署" in out, "没说清是「重新部署时才相关」"
    assert "seed" in out or "补" in out, "没说清缺失字段会被 seed 补上"


def test_active_bad_row_still_fails_the_gate(monkeypatch, capsys):
    """闸门契约没变：ACTIVE 坏行照样退出码 1。"""
    row = _row()
    del row["require_login"]
    code, out = _run_main(monkeypatch, capsys, [row])
    assert code == 1
    assert "s-1" in out


def test_active_verdict_is_printed_with_its_own_count_not_after_the_warning(
        monkeypatch, capsys):
    """ACTIVE 的结论要紧跟在 ACTIVE 计数下面，不能被挤到警告块之后。

    否则操作员在 15 行 `--` 明细之后读到一句缩进的"无 —— 不会卡住任何 ACTIVE
    站点"，看起来像是在给那 15 行下结论（而它其实回答的是上面的 ACTIVE 计数）。
    """
    code, out = _run_main(monkeypatch, capsys, [_row(), _bad_deleted()])
    assert code == 0
    verdict = out.index("无 —— ")
    warning = out.index("非 ACTIVE 行中会被拒绝的")
    assert verdict < warning, "ACTIVE 结论被挤到警告块后面了"


def test_status_breakdown_is_printed(monkeypatch, capsys):
    """按 status 报数：DEPLOYING 行还没被 register_route seed 过权限字段，
    形态上必然会被拒——今天没有这种行只是这个窗口此刻恰好空着，
    不是"这一类不存在"。所以它必须出现在输出里。"""
    deploying = _row(site_id={"S": "s-new"}, status={"S": "DEPLOYING"})
    del deploying["require_login"]
    _code, out = _run_main(monkeypatch, capsys, [_row(), deploying])
    assert "DEPLOYING" in out
