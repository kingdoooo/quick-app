"""把轮转 runbook 剩余各步的 `config.ini` 状态**提前模拟**，跑单测看哪条会红。

为什么要有它（2026-09-03 真机踩出来的）：演练的每一步都在改 `[SessionKeys]`
（⑤ 清空 `legacy_param`、⑥ 加 v2 两节 + 设 `*_previous`、⑦ 互换槽位、⑩ 清 previous + 删 v1 两节）。
把配置的**当前值**写死的用例会在**改完配置、部署之后**才成片转红——ticket 10 就是这么撞上的，
而它们要守的性质其实一条都没变。本脚本在动生产之前把这些假红全找出来：首跑实测 panel
在 ⑤⑥⑦ 各 3 条红、⑩ 6 条红，其余六包全绿。

**只读 config、不发任何 AWS 调用**；`try/finally` 保证还原，并逐字节核对。
跑之前先确认工作树里没有未保存的 config 改动；跑期间不要并行跑任何读 config 的东西
（部署脚本、verify_* 闸门都读它）。

    python3 site-builder/scripts/preflight_config_states.py
"""
import re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "site-builder" / "config.ini"
BAK = Path("/tmp/config.ini.preflight-backup")   # 只是保险；真源是内存里的 base

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

shutil.copy2(CFG, BAK)
report = {}
try:
    base = CFG.read_text()
    for tag, fn in (("⑤L3", state_l3), ("⑥stage", state_stage),
                    ("⑦switch", state_switch), ("⑩retire", state_retire)):
        CFG.write_text(fn(base))
        print(f"\n=== 模拟 {tag} ===")
        report[tag] = run_all(tag)
finally:
    shutil.copy2(BAK, CFG)
    assert CFG.read_text() == base, "config.ini 未能还原！"
    print("\nconfig.ini 已还原（逐字节核对通过）")

print("\n===== 汇总 =====")
for tag, bad in report.items():
    if not bad:
        print(f"{tag}: 全绿")
    else:
        for name, fails in bad:
            print(f"{tag}: {name} 红 {len(fails)} 条")
            for f in fails: print(f"    {f}")
