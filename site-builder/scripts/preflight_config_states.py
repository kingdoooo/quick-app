"""把轮转 runbook 剩余各步的 `config.ini` 状态**提前模拟**，跑单测看哪条会红。

为什么要有它（2026-09-03 真机踩出来的）：演练的每一步都在改 `[SessionKeys]`
（⑤ 清空 `legacy_param`、⑥ 加 v2 两节 + 设 `*_previous`、⑦ 互换槽位、⑩ 清 previous + 删 v1 两节）。
把配置的**当前值**写死的用例会在**改完配置、部署之后**才成片转红——ticket 10 就是这么撞上的，
而它们要守的性质其实一条都没变。本脚本在动生产之前把这些假红全找出来：首跑实测 panel
在 ⑤⑥⑦ 各 3 条红、⑩ 6 条红，其余六包全绿。

**不发任何 AWS 调用**，但**它会就地改写 `site-builder/config.ini`**——那是所有部署脚本与 CDK 栈的
唯一取值来源。因此有三道保护（3c-1B ticket 17 第 9 条加的；此前只有一个 `finally` + `assert`）：

1. **哨兵文件**。第一次写之前落 `.scratch/preflight-config-mutation.json`（原文 sha256 + 备份路径 +
   pid + 时刻），还原成功才删。**下次启动看见它就拒绝运行**并打印怎么恢复——进程被硬杀
   （SIGKILL / 关终端 / OOM / 睡眠后重启）时 `finally` 不会执行，此前的症状是 config 静默留在
   模拟态、而后续 `deploy_*` 会照着它把 v2 那种"参数还不存在"的状态部出去。
2. **备份落 `.scratch/`**（gitignored、不被 macOS 清理），不再用 `/tmp` 里那个**可预测**路径——
   config 里有真实账号/域名/证书 ARN，而还原时又会把那个路径读回来写进 config。
3. **信号处理 + 真异常**。SIGINT/SIGTERM 先还原再退出；还原核对改成 `raise RuntimeError`
   而不是 `assert`（`python3 -O` 会把 assert 整条去掉，那正好是"看起来还原了其实没有"）。

跑期间不要并行跑任何读 config 的东西（部署脚本、verify_* 闸门都读它）。**生产处在轮转中途时
不要跑它**：收益是"预演状态"，而它本身就在改真源。

    python3 site-builder/scripts/preflight_config_states.py
"""
import hashlib, json, os, re, shutil, signal, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "site-builder" / "config.ini"
SENTINEL = ROOT / ".scratch" / "preflight-config-mutation.json"

V2 = """
[SessionKey:site-hs-v2]
alg = HS256
ssm_param = /site-builder/session-keys/site-hs-v2

[SessionKey:console-hs-v2]
alg = HS256
ssm_param = /site-builder/session-keys/console-hs-v2
"""

def setkey(t, k, v):
    out, n = re.subn(rf"(?m)^{re.escape(k)}\s*=.*$", f"{k} = {v}".rstrip(), t)
    assert n == 1, f"{k}: expected 1 line, got {n}"
    return out

def drop_section(t, name):
    out = re.sub(rf"(?ms)\n\[{re.escape(name)}\]\n.*?(?=\n\[|\Z)", "", t)
    assert f"[{name}]" not in out, name
    return out

def state_l3(t):                       # ⑤
    return setkey(t, "legacy_param", "")

def state_stage(t):                    # ⑥（在 ⑤ 之后）
    t = state_l3(t) + V2
    t = setkey(t, "site_previous", "site-hs-v2")
    return setkey(t, "console_previous", "console-hs-v2")

def state_switch(t):                   # ⑦
    t = state_stage(t)
    t = setkey(t, "site_current", "site-hs-v2");   t = setkey(t, "site_previous", "site-hs-v1")
    t = setkey(t, "console_current", "console-hs-v2"); return setkey(t, "console_previous", "console-hs-v1")

def state_retire(t):                   # ⑩
    t = state_switch(t)
    t = setkey(t, "site_previous", ""); t = setkey(t, "console_previous", "")
    t = drop_section(t, "SessionKey:site-hs-v1")
    return drop_section(t, "SessionKey:console-hs-v1")

SUITES = [
    ("contract",  "site-builder/contract",           ".venv/bin/pytest tests -q"),
    ("auth",      "site-builder/auth",               "../contract/.venv/bin/pytest tests -q"),
    ("router",    "router/infrastructure/lambda",    "../../../site-builder/deployer/.venv/bin/pytest . -q"),
    ("deployer",  "site-builder/deployer",           ".venv/bin/pytest tests -q"),
    ("panel",     "site-builder/panel",              "../deployer/.venv/bin/pytest tests -q"),
    ("key-proxy", "site-builder/key-proxy",          "../deployer/.venv/bin/pytest tests -q"),
]

def run_all(tag):
    bad = []
    for name, cwd, cmd in SUITES:
        r = subprocess.run(cmd, shell=True, cwd=ROOT / cwd, capture_output=True, text=True)
        tail = [l for l in r.stdout.strip().splitlines() if l.strip()][-1:] or [""]
        status = "ok " if r.returncode == 0 else "RED"
        print(f"  [{tag}] {status} {name:10} {tail[0][:70]}")
        if r.returncode != 0:
            fails = [l for l in r.stdout.splitlines() if l.startswith("FAILED")]
            bad.append((name, fails))
    return bad

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def refuse_if_mutation_in_flight() -> None:
    """上一次跑没能还原（哨兵还在）⇒ 拒绝运行，并说清怎么恢复。

    这条比 `finally` 重要：`finally` 只覆盖"进程还活着"的失败，而这里要防的是它根本没机会跑。
    """
    if not SENTINEL.exists():
        return
    try:
        st = json.loads(SENTINEL.read_text())
    except ValueError:
        st = {}
    now = _sha(CFG.read_text())
    ok = now == st.get("pristine_sha256")
    raise SystemExit(
        f"发现上一次运行留下的哨兵 {SENTINEL}\n"
        f"  上次开始于 {st.get('started_at')}（pid {st.get('pid')}），备份在 {st.get('backup')}\n"
        f"  当前 config.ini 与原文 " + ("**一致**——大概只是哨兵没删干净，确认后手工删掉它再跑。\n"
                                        if ok else
                                        "**不一致 ⇒ config.ini 很可能还停在模拟态**。\n"
                                        f"  先 `cp {st.get('backup')} {CFG}` 还原并核对，再删哨兵。\n") +
        "  在还原之前**不要跑任何 deploy_* 或 verify_***（它们会照着模拟态的配置动生产）。")


def restore(backup: Path, base: str) -> None:
    shutil.copy2(backup, CFG)
    if CFG.read_text() != base:
        raise RuntimeError(f"config.ini 未能还原！备份在 {backup}，先手工恢复再做别的")
    SENTINEL.unlink(missing_ok=True)
    print("\nconfig.ini 已还原（逐字节核对通过），哨兵已清")


def main() -> int:
    refuse_if_mutation_in_flight()
    base = CFG.read_text()
    SENTINEL.parent.mkdir(parents=True, exist_ok=True)
    backup_dir = Path(SENTINEL.parent / f"preflight-backup-{int(time.time())}")
    backup_dir.mkdir(mode=0o700)
    backup = backup_dir / "config.ini"
    shutil.copy2(CFG, backup)
    SENTINEL.write_text(json.dumps({"pristine_sha256": _sha(base), "backup": str(backup),
                                    "pid": os.getpid(), "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                                    time.gmtime())}, indent=1))

    def _on_signal(signum, _frame):
        print(f"\n收到信号 {signum}——先还原 config.ini 再退出", file=sys.stderr)
        restore(backup, base)
        raise SystemExit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _on_signal)

    report = {}
    try:
        for tag, fn in (("⑤L3", state_l3), ("⑥stage", state_stage),
                        ("⑦switch", state_switch), ("⑩retire", state_retire)):
            CFG.write_text(fn(base))
            print(f"\n=== 模拟 {tag} ===")
            report[tag] = run_all(tag)
    finally:
        restore(backup, base)

    print("\n===== 汇总 =====")
    for tag, bad in report.items():
        if not bad:
            print(f"{tag}: 全绿")
        else:
            for name, fails in bad:
                print(f"{tag}: {name} 红 {len(fails)} 条")
                for f in fails: print(f"    {f}")
    return 0


if __name__ == "__main__":      # 没有这道 guard 时，`import preflight_config_states` 会把整段跑掉
    sys.exit(main())
