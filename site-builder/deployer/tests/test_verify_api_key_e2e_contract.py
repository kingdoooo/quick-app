"""`scripts/verify_api_key_e2e.py` 作为**分发验收集第七条**的两条契约（Codex review P1/P2）：

  · 没有 `[ApiKey]` 段 ⇒ 打印 `PASS  组件缺席` 并**退 0**，在任何 AWS 调用之前（组件不存在是合法状态，
    验收集里这条无条件执行；bash 里包 `if grep` 的做法被文档守卫禁了）；
  · 全局关闸 / 开闸（场景 ④⑤）只在 `--include-global-switch` 下执行——关闸窗口内所有真实 Key 401，
    进程被杀会留在关闸态，不属于可反复跑的验收。

evidence: fake/unit（不碰 AWS；absent 路径在建任何 boto3 客户端之前就返回）。
"""
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "site-builder" / "scripts" / "verify_api_key_e2e.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_api_key_e2e", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_api_key_e2e"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_missing_apikey_section_is_a_pass_with_exit_zero(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.ini"
    cfg.write_text(
        "[Platform]\nregion = us-east-1\nbase_domain = example.test\naccount_id = 111122223333\n"
        "routing_table = routing\n[Deployer]\nsites_table = site-sites\n", encoding="utf-8")
    mod = _load()
    monkeypatch.setattr(mod, "CFG_PATH", cfg)
    monkeypatch.setattr(sys, "argv", ["verify_api_key_e2e.py"])
    # 兜底：万一走到了建客户端那一步，boto3 会因假凭据/无网络而失败——那正是我们要抓的越界
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    rc = mod.main()
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "PASS  组件缺席" in out and "[ApiKey]" in out, out


def test_global_switch_scenarios_are_gated_behind_the_flag():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "--include-global-switch" in src
    gate = src.index("if args.include_global_switch:")
    off = src.index("keystore.set_switch(False, actor=ACTOR)")
    on = src.index("keystore.set_switch(True, actor=ACTOR)")
    assert gate < off < on, "关闸/开闸必须都在 --include-global-switch 的分支里"
    # 关闸那行的缩进要深于 `if` 那行（真的在分支体内，不是紧跟其后的同级语句）
    gate_indent = len(re.search(r"^( *)if args.include_global_switch:", src, re.M).group(1))
    off_indent = len(re.search(r"^( *)keystore.set_switch\(False, actor=ACTOR\)", src, re.M).group(1))
    assert off_indent > gate_indent
    # finally 里默认模式不写开关（否则每次验收都留一条假的 enable 审计行）
    fin = src.index("finally:", on)
    assert "if args.include_global_switch:" in src[fin:fin + 600]
