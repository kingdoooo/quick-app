"""`scripts/preflight_config_states.py` 的安全护栏（3c-1B ticket 17 第 9 条）。

这个脚本会**就地改写 `site-builder/config.ini`**——所有部署脚本与 CDK 栈的唯一取值来源。
被守的失败面不是"它跑得对不对"，而是"它没跑完时留下什么"：进程被硬杀 ⇒ `finally` 不执行 ⇒
config 静默停在模拟态（例如 `site_current = site-hs-v2` 而那把参数还不存在）⇒ 之后任何
`deploy_*` 都会照着它动生产。所以这里钉三件事：import 无副作用、哨兵能拦住下一次运行、还原核对
不是 `assert`（`python3 -O` 会把 assert 整条删掉）。

**本文件不跑那个脚本的主流程**（它要跑六个包的单测、十几分钟，且真的会改 config）。
"""
import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SRC_PATH = ROOT / "site-builder" / "scripts" / "preflight_config_states.py"
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
import preflight_config_states as pf  # noqa: E402  import 本身就是被测性质之一


def test_import_has_no_side_effects_and_exposes_main():
    """没有 `__main__` guard 时，`import` 会把改写 config + 跑六套单测整段执行掉。"""
    assert callable(pf.main) and callable(pf.refuse_if_mutation_in_flight)
    tree = ast.parse(SRC_PATH.read_text(encoding="utf-8"))
    guarded = [n for n in tree.body if isinstance(n, ast.If) and "__name__" in ast.dump(n.test)]
    assert guarded, "缺 __main__ guard"
    # 模块顶层不许有"写 config"的语句：只允许 import / 常量 / 函数 / 类 / guard
    allowed = (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.FunctionDef,
               ast.ClassDef, ast.Expr, ast.If)
    bad = [type(n).__name__ for n in tree.body if not isinstance(n, allowed)]
    assert not bad, bad
    for n in tree.body:
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
            pytest.fail(f"顶层有调用语句：{ast.unparse(n)[:60]}")


def test_backup_and_sentinel_live_under_scratch_not_a_predictable_tmp_path():
    """备份路径不能是 `/tmp` 里那个可预测的名字：config 里有真实账号/域名/证书 ARN，
    而还原时又会把那个路径读回来写进 config。`.scratch/` 是 gitignored 且不被系统清理。"""
    src = SRC_PATH.read_text(encoding="utf-8")
    assert "/tmp/config.ini.preflight-backup" not in src
    assert pf.SENTINEL.is_relative_to(ROOT / ".scratch"), pf.SENTINEL


def test_restore_check_is_a_real_raise_not_an_assert():
    """`python3 -O` 会把 `assert` 整条去掉——那正好是"看起来还原了其实没有"。"""
    src = ast.parse(SRC_PATH.read_text(encoding="utf-8"))
    fn = next(n for n in src.body if isinstance(n, ast.FunctionDef) and n.name == "restore")
    assert not [n for n in ast.walk(fn) if isinstance(n, ast.Assert)], "restore 里还有 assert"
    assert [n for n in ast.walk(fn) if isinstance(n, ast.Raise)], "restore 不会抛"


def test_restore_raises_and_keeps_the_sentinel_when_the_bytes_do_not_match(tmp_path, monkeypatch):
    """还原不成功时必须抛、且**不能**删哨兵（否则下一次运行不会被拦住）。"""
    cfg = tmp_path / "config.ini"; cfg.write_text("mutated\n")
    backup = tmp_path / "backup.ini"; backup.write_text("not-the-base\n")
    sentinel = tmp_path / "sentinel.json"; sentinel.write_text("{}")
    monkeypatch.setattr(pf, "CFG", cfg); monkeypatch.setattr(pf, "SENTINEL", sentinel)
    with pytest.raises(RuntimeError, match="未能还原"):
        pf.restore(backup, "the-real-base\n")
    assert sentinel.exists(), "还原失败却把哨兵删了 ⇒ 下一次运行不会被拦住"


def test_restore_clears_the_sentinel_on_success(tmp_path, monkeypatch):
    cfg = tmp_path / "config.ini"; cfg.write_text("mutated\n")
    backup = tmp_path / "backup.ini"; backup.write_text("base\n")
    sentinel = tmp_path / "sentinel.json"; sentinel.write_text("{}")
    monkeypatch.setattr(pf, "CFG", cfg); monkeypatch.setattr(pf, "SENTINEL", sentinel)
    pf.restore(backup, "base\n")
    assert cfg.read_text() == "base\n" and not sentinel.exists()


def test_a_leftover_sentinel_refuses_the_next_run_and_says_how_to_recover(tmp_path, monkeypatch, capsys):
    """核心那条：进程被硬杀之后，下一次运行必须**拒绝**，而不是在模拟态上再叠一层。"""
    cfg = tmp_path / "config.ini"; cfg.write_text("MUTATED STATE\n")
    sentinel = tmp_path / "sentinel.json"
    sentinel.write_text(json.dumps({"pristine_sha256": "deadbeef", "backup": str(tmp_path / "b.ini"),
                                    "pid": 4242, "started_at": "2026-09-04T00:00:00Z"}))
    monkeypatch.setattr(pf, "CFG", cfg); monkeypatch.setattr(pf, "SENTINEL", sentinel)
    with pytest.raises(SystemExit) as ei:
        pf.refuse_if_mutation_in_flight()
    msg = str(ei.value)
    assert "不一致" in msg and str(tmp_path / "b.ini") in msg, msg
    assert "deploy_" in msg, "没有警告在还原前不要跑部署脚本"


def test_no_sentinel_means_no_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "SENTINEL", tmp_path / "absent.json")
    pf.refuse_if_mutation_in_flight()      # 不抛


def test_signals_are_handled_so_the_finally_actually_runs():
    """SIGINT/SIGTERM/SIGHUP 都要先还原再退出——Ctrl-C 与关终端是最常见的"没跑完"。"""
    src = SRC_PATH.read_text(encoding="utf-8")
    for sig in ("SIGINT", "SIGTERM", "SIGHUP"):
        assert sig in src, sig
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "main")
    handler = next((n for n in ast.walk(fn) if isinstance(n, ast.FunctionDef) and n.name == "_on_signal"), None)
    assert handler is not None and any(
        isinstance(n, ast.Call) and getattr(n.func, "id", "") == "restore" for n in ast.walk(handler)), \
        "信号处理里没有还原"


def test_the_four_simulated_states_still_match_the_runbook_steps():
    """状态函数是这个脚本的全部价值：少一个就有一步的假红不会被提前发现。"""
    base = (ROOT / "site-builder" / "config.ini.example").read_text(encoding="utf-8")
    l3 = pf.state_l3(base)
    assert "legacy_param =\n" in l3 or l3.rstrip().endswith("legacy_param =")
    stage = pf.state_stage(base)
    assert "[SessionKey:site-hs-v2]" in stage and "site_previous = site-hs-v2" in stage
    switch = pf.state_switch(base)
    assert "site_current = site-hs-v2" in switch and "site_previous = site-hs-v1" in switch
    retire = pf.state_retire(base)
    assert "[SessionKey:site-hs-v1]" not in retire and "site_previous =\n" in retire


# ---- 3c-1B-G A3：版本推导、非法状态先拦、RED 必须非零退出 --------------------------------

LIVE_SHAPE = """[Platform]
account_id = 111111111111

[SessionKeys]
site_current = site-hs-v2
site_previous =
console_current = console-hs-v2
console_previous =
signer = current
legacy_param =
login_flow_secret_param = /site-builder/login-flow-secret

[SessionKey:site-hs-v2]
alg = HS256
ssm_param = /site-builder/session-keys/site-hs-v2

[SessionKey:console-hs-v2]
alg = HS256
ssm_param = /site-builder/session-keys/console-hs-v2
"""


def test_next_kid_is_derived_from_the_current_config_not_hardcoded():
    """轮转过一轮之后 current 就是 v2 —— 写死 v2 会让 ⑥ 追加出重复小节。

    这是本票的现场：v1→v2 之后再跑这个脚本，`configparser` 直接 `DuplicateSectionError`，
    六个套件全在 collection 期炸，而汇总只打印"红 0 条"。
    """
    assert pf.next_kids(LIVE_SHAPE) == {"site": "site-hs-v3", "console": "console-hs-v3"}
    stage = pf.state_stage(LIVE_SHAPE)
    assert stage.count("[SessionKey:site-hs-v2]") == 1, "既有小节被复制了"
    assert "[SessionKey:site-hs-v3]" in stage and "site_previous = site-hs-v3" in stage


def test_next_kid_can_be_named_explicitly():
    nxt = pf.next_kids(LIVE_SHAPE, {"site": "site-hs-v9"})
    assert nxt == {"site": "site-hs-v9", "console": "console-hs-v3"}


def test_the_simulated_states_load_under_the_real_loader():
    """四个状态都必须是**合法配置**——否则套件红的原因与本脚本要找的东西无关。"""
    sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
    import session_keys as sk
    for tag, fn in (("l3", pf.state_l3), ("stage", pf.state_stage),
                    ("switch", pf.state_switch), ("retire", pf.state_retire)):
        text = fn(LIVE_SHAPE)
        path = Path(__file__).parent / f"_pf_{tag}.ini"
        path.write_text(text)
        try:
            sk.load_session_keys(path)      # 抛即失败
        finally:
            path.unlink(missing_ok=True)


def test_l3_also_switches_the_signer_because_the_loader_rejects_the_pair():
    """出厂 `signer = legacy` + 空 `legacy_param` 被加载器硬拒 ⇒ ⑤ 必须一起切 signer。"""
    example = (ROOT / "site-builder" / "config.ini.example").read_text(encoding="utf-8")
    assert "signer = legacy" in example, "出厂默认变了，这条用例的前提要更新"
    l3 = pf.state_l3(example)
    assert "signer = current" in l3 and "signer = legacy" not in l3


def test_state_transforms_raise_instead_of_asserting():
    """`-O` 会删掉 assert ⇒ 变换静默 no-op ⇒ 拿未改的 config 跑出"四个状态全绿"。"""
    import ast
    src = SRC_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for fn in ("setkey", "drop_section", "current_kids", "next_kids"):
        node = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == fn)
        assert not [n for n in ast.walk(node) if isinstance(n, ast.Assert)], f"{fn} 里还有裸 assert"
        assert [n for n in ast.walk(node) if isinstance(n, ast.Raise)], f"{fn} 没有真异常"


def test_a_transform_that_cannot_find_its_anchor_is_loud():
    with pytest.raises(pf.PreflightError, match="legacy_param"):
        pf.setkey("[SessionKeys]\nsigner = current\n", "legacy_param", "")
    with pytest.raises(pf.PreflightError, match="site_current"):
        pf.current_kids("[SessionKeys]\nsigner = current\n")


def test_red_suites_make_the_script_exit_nonzero(monkeypatch, capsys, tmp_path):
    """**本票的核心反例**：原先无论多少 RED 都 `return 0`。"""
    monkeypatch.setattr(pf, "CFG", tmp_path / "config.ini")
    pf.CFG.write_text(LIVE_SHAPE)
    monkeypatch.setattr(pf, "SENTINEL", tmp_path / ".scratch" / "sentinel.json")
    monkeypatch.setattr(pf, "validate", lambda text, tag: None)
    monkeypatch.setattr(pf, "run_all", lambda tag: [("panel", ["FAILED tests/x.py::y"])])
    assert pf.main([]) == 1
    assert "红" in capsys.readouterr().err
    monkeypatch.setattr(pf, "run_all", lambda tag: [])
    assert pf.main([]) == 0


def test_a_bad_next_kid_fails_before_any_backup_or_sentinel_exists(tmp_path, monkeypatch):
    """**复审 P2-1**：`--next-kid site=<current>` 抛 PreflightError 时 config 一个字没改，
    但第一版已经写下了哨兵 ⇒ 下一次运行被拦、要人手工清"假哨兵"。纯计算失败不得留下任何状态。"""
    monkeypatch.setattr(pf, "CFG", tmp_path / "config.ini")
    pf.CFG.write_text(LIVE_SHAPE)
    scratch = tmp_path / ".scratch"
    monkeypatch.setattr(pf, "SENTINEL", scratch / "sentinel.json")
    monkeypatch.setattr(pf, "run_all", lambda tag: pytest.fail("不该跑到套件"))
    cur = pf.current_kids(LIVE_SHAPE)["site"][0]
    with pytest.raises(pf.PreflightError, match="相同"):
        pf.main([f"--next-kid=site={cur}"])
    assert not pf.SENTINEL.exists(), "假哨兵"
    assert not scratch.exists() or not list(scratch.iterdir()), "留下了备份目录"
    assert pf.CFG.read_text() == LIVE_SHAPE
    # 正向控制：合法的 --next-kid 走到套件（这里让 run_all 立即返回空 = 全绿）
    monkeypatch.setattr(pf, "validate", lambda text, tag: None)
    monkeypatch.setattr(pf, "run_all", lambda tag: [])
    assert pf.main(["--next-kid=site=site-hs-v9"]) == 0
    assert not pf.SENTINEL.exists() and pf.CFG.read_text() == LIVE_SHAPE


def test_collection_errors_are_reported_not_counted_as_zero():
    """pytest 死在 collection 时只有 ERROR 行，没有 FAILED 行——不能报成"红 0 条"。"""
    stdout = ("ERROR tests/test_x.py - session_keys.SessionKeysError: 缺 site_current\n"
              "E   session_keys.SessionKeysError: 缺 site_current\n"
              "!!!! Interrupted: 1 error during collection !!!!\n")
    lines = pf.suite_failures(stdout, "")
    assert lines and any("SessionKeysError" in l for l in lines), lines
    # stdout 一无所有时退到 stderr，绝不返回空列表
    assert pf.suite_failures("", "bad interpreter: No such file or directory\n")
    assert pf.suite_failures("", "")
