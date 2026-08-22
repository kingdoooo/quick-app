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


def test_status_breakdown_line_carries_the_real_counts(monkeypatch, capsys):
    """按 status 报数：DEPLOYING 行还没被 register_route seed 过权限字段，
    形态上必然会被拒——今天没有这种行只是这个窗口此刻恰好空着，
    不是"这一类不存在"。所以它必须出现在输出里。

    **断言钉的是报数行的内容，不是"DEPLOYING 这个词出现过"。**
    上一版断的是后者，而 DEPLOYING 那句单独提示把字面量写死在代码里且无条件
    打印：0 行 DEPLOYING 也能让它通过，把整条报数行删掉它照样绿。那正是本任务
    已经出过一次的缺陷类——闸门脚本里有个不会红的检查。
    """
    deploying = _row(site_id={"S": "s-new"}, status={"S": "DEPLOYING"})
    del deploying["require_login"]
    _code, out = _run_main(monkeypatch, capsys, [
        _row(), _row(site_id={"S": "s-2"}), deploying, _bad_deleted()])
    assert "各 status 行数：ACTIVE 2、DELETED 1、DEPLOYING 1" in out
    assert "（其中 DEPLOYING 1 行" in out, "DEPLOYING 提示没带上真实计数"
    assert "为 0 只代表" not in out, "有 DEPLOYING 行时还在说「为 0 只代表……」"


def test_deploying_zero_still_says_dont_read_the_zero_as_a_promise(
        monkeypatch, capsys):
    """0 行 DEPLOYING 时那句免责必须在——它是这条提示存在的理由。

    与上一个用例合起来钉住两个分支：无条件写"为 0 只代表……"会让有 DEPLOYING
    行时那句自相矛盾，而按计数分支之后，0 的那支不能顺手丢掉免责。
    """
    _code, out = _run_main(monkeypatch, capsys, [_row()])
    assert "（其中 DEPLOYING 0 行" in out
    assert "为 0 只代表此刻没有在途首次部署" in out


# ---- 畸形 status 既不许带红闸门、也不许吞掉警告（fix round 2）----
# 触发条件是两条**被拒**的非 ACTIVE 行，其 status 反序列化后类型不同：
# `{"N":"1"}` 是 Decimal、`{"NULL":true}` 是 None、`{"L":[]}` 是 list。
# 按 status 分组报数时，`Counter` 要哈希它（list/dict 过不了）、`sorted` 要比较它
# （跨类型 TypeError）。两种炸法的后果一样，而且都违反本脚本的契约：
#   1. 未捕获异常 = 非零退出。ACTIVE 行一条不坏，Task 10 Step 2 的
#      `set -euo pipefail` 却把发布停在这里——用一行不被服务的历史垃圾拦发布。
#   2. 异常发生在逐行打印之前，于是操作员**恰好**拿不到这段警告——而这段警告
#      正是上一轮加它的理由。
# 平台今天的三个 writer 只写 `{"S": ...}`，所以真机不会出现；但这个脚本是专门
# 用来查畸形行的仪器，它不该是最后一个被畸形行搞挂的地方。


def _bad_with_raw_status(site_id, status_av):
    """一条会被拒（缺 require_login）且 status 是给定原始 AttributeValue 的行。"""
    row = _row(site_id={"S": site_id}, status=status_av)
    del row["require_login"]
    return row


@pytest.mark.parametrize("statuses", [
    [{"S": "DELETED"}, {"N": "1"}],       # str vs Decimal ← 复核实测的那条
    [{"S": "DELETED"}, {"NULL": True}],   # str vs None ← 复核实测的那条
    [{"N": "1"}, {"NULL": True}],         # Decimal vs None，一条 S 都没有
    [{"S": "DELETED"}, {"L": []}],        # list：连 Counter 的哈希都过不了
])
def test_weird_status_neither_reddens_the_gate_nor_hides_the_warning(
        monkeypatch, capsys, statuses):
    rows = [_row()] + [_bad_with_raw_status(f"s-w{i}", av)
                       for i, av in enumerate(statuses)]
    code, out = _run_main(monkeypatch, capsys, rows)
    assert code == 0, "ACTIVE 行一条不坏，闸门不该红"
    assert f"非 ACTIVE 行中会被拒绝的：{len(statuses)}" in out, "警告块整块没了"
    for i in range(len(statuses)):
        assert f"s-w{i}" in out, "警告块漏了某一行"
        assert "require_login" in out


def test_breakdown_tells_a_missing_status_apart_from_a_non_string_one(
        monkeypatch, capsys):
    """「没有 status 字段」与「status 类型写错」是两种行，修法不同。

    上一版的报数用 `raw["status"].get("S", "<无 status>")`，把后者也算进
    `<无 status>`——操作员会去补一个已经存在的字段。
    """
    no_status = _row(site_id={"S": "s-none"})
    del no_status["status"]
    _code, out = _run_main(monkeypatch, capsys, [
        _row(), no_status, _bad_with_raw_status("s-weird", {"N": "1"})])
    assert "<无 status> 1" in out, "缺 status 的行数被算错了"
    assert "<非字符串 status" in out, "类型写错的 status 被混进「无 status」"
