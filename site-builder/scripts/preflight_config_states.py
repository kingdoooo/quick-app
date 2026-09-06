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

3c-1B-G A3 修了三条会让它变成"打印 RED 然后 exit 0"的报告脚本的缺陷：

4. **下一版 kid 从 config 推导**（`{family}_current` 的版本号 +1），不再写死 `*-hs-v2`。
   v1→v2 那轮之后线上 current 就是 v2，无条件追加 `[SessionKey:*-hs-v2]` 会让
   configparser 抛 `DuplicateSectionError` ⇒ 六个套件全在 collection 期炸。`--next-kid`
   可以点名（`--next-kid site=site-hs-v9`）。
5. **⑤ 同时把 signer 切成 current**，并且每个模拟状态**先过 `load_session_keys` 自校验**
   再跑套件。加载器硬拒 `(signer=legacy, 空 legacy_param)`，而出厂默认就是 `signer = legacy`。
6. **任一套件红 ⇒ 退出码非零**，且 collection `ERROR`/`E   ` 行与 stderr 都进报告
   （原先只 filter `FAILED`，collection 期失败会显示成"红 0 条"）。
   状态变换里的裸 `assert` 也换成了 `PreflightError`——`-O` 下 assert 被删掉的话，
   变换静默 no-op，脚本会拿**未修改**的配置跑出"四个状态全绿"。

    python3 site-builder/scripts/preflight_config_states.py
    python3 site-builder/scripts/preflight_config_states.py --next-kid site=site-hs-v9
"""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "site-builder" / "config.ini"
SENTINEL = ROOT / ".scratch" / "preflight-config-mutation.json"

class PreflightError(RuntimeError):
    """状态变换本身出错（锚点没命中、节没删掉、推导不出版本）。

    **刻意不是 `assert`**：`python3 -O` 会把 assert 整条去掉，于是变换静默 no-op，
    脚本拿**未修改**的配置跑六个套件、全绿、报告"四个状态都没问题"——那正是本脚本
    要防的那类假绿的最坏形态（还原核对早在 ticket 17 就因为同一条理由改成了真异常）。
    """


def setkey(t, k, v):
    out, n = re.subn(rf"(?m)^{re.escape(k)}\s*=.*$", f"{k} = {v}".rstrip(), t)
    if n != 1:
        raise PreflightError(f"{k}: 期望恰好 1 行，实际 {n} —— config 的键名或格式变了")
    return out

def drop_section(t, name):
    out = re.sub(rf"(?ms)\n\[{re.escape(name)}\]\n.*?(?=\n\[|\Z)", "", t)
    if f"[{name}]" in out:
        raise PreflightError(f"[{name}] 没被删掉 —— 小节格式变了")
    return out


def current_kids(t):
    """→ {family: (kid, 版本号)}，取 `{family}_current`。**版本从配置读，不写死。**"""
    out = {}
    for fam in ("site", "console"):
        m = re.search(rf"(?m)^{fam}_current\s*=\s*(\S+)\s*$", t)
        if not m:
            raise PreflightError(f"config 里找不到 {fam}_current —— 没法推导下一版 kid")
        kid = m.group(1)
        v = re.fullmatch(rf"{fam}-hs-v(\d+)", kid)
        if not v:
            raise PreflightError(f"{fam}_current={kid!r} 不是 `{fam}-hs-v<N>` 形态 —— 无法推导下一版")
        out[fam] = (kid, int(v.group(1)))
    return out


def next_kids(t, explicit: dict | None = None):
    """下一轮要就位的 kid：默认 current 的版本号 +1；`explicit` 可点名（`--next-kid`）。

    **不能写死 `*-hs-v2`**（3c-1B-G A3）：v1→v2 那轮之后线上 current 就是 v2，
    再无条件追加一份 `[SessionKey:*-hs-v2]` 会让 configparser 直接
    `DuplicateSectionError` ⇒ 六个套件全在 collection 期炸，而报告里只看到"红 0 条"。
    """
    cur = current_kids(t)
    out = {}
    for fam, (kid, n) in cur.items():
        nxt = (explicit or {}).get(fam) or f"{fam}-hs-v{n + 1}"
        if nxt == kid:
            raise PreflightError(f"{fam} 的下一版 kid 与 current 相同（{kid}）——那不是一次轮转")
        out[fam] = nxt
    return out


def key_sections(kids: dict) -> str:
    """给 kid 生成 `[SessionKey:<kid>]` 小节；`ssm_param` 必须**恰好**是前缀 + kid（A4 的等值约束）。"""
    return "".join(f"\n[SessionKey:{kid}]\nalg = HS256\n"
                   f"ssm_param = /site-builder/session-keys/{kid}\n" for kid in kids.values())


def state_l3(t, nxt=None):             # ⑤
    """清空 legacy_param。**必须同时把 signer 切成 current**：加载器硬拒
    `(signer=legacy, 空 legacy_param)` 这个组合，而出厂 `config.ini.example` 的
    signer 就是 legacy ⇒ 不切的话四个模拟状态全是非法配置，六个套件一片红，
    而红的原因与本脚本要找的"写死当前值的用例"毫无关系（3c-1B-G A3）。"""
    return setkey(setkey(t, "signer", "current"), "legacy_param", "")

def state_stage(t, nxt=None):          # ⑥（在 ⑤ 之后）
    nxt = nxt or next_kids(t)
    t = state_l3(t) + key_sections(nxt)
    t = setkey(t, "site_previous", nxt["site"])
    return setkey(t, "console_previous", nxt["console"])

def state_switch(t, nxt=None):         # ⑦
    nxt = nxt or next_kids(t)
    cur = {f: k for f, (k, _) in current_kids(t).items()}
    t = state_stage(t, nxt)
    t = setkey(t, "site_current", nxt["site"]);       t = setkey(t, "site_previous", cur["site"])
    t = setkey(t, "console_current", nxt["console"]); return setkey(t, "console_previous", cur["console"])

def state_retire(t, nxt=None):         # ⑩
    nxt = nxt or next_kids(t)
    cur = {f: k for f, (k, _) in current_kids(t).items()}
    t = state_switch(t, nxt)
    t = setkey(t, "site_previous", ""); t = setkey(t, "console_previous", "")
    t = drop_section(t, f"SessionKey:{cur['site']}")
    return drop_section(t, f"SessionKey:{cur['console']}")


def validate(text: str, tag: str) -> None:
    """模拟出来的状态**先过加载器**再跑套件。

    非法配置（例如忘了切 signer、或推导出的 kid 与既有小节重复）应当在这里一句话响亮失败，
    而不是让六个套件各自以 collection error 的形式红一片——那种报告读不出根因。
    """
    sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
    from session_keys import SessionKeysError, load_session_keys
    tmp = SENTINEL.parent / f"preflight-validate-{os.getpid()}.ini"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(text)
    try:
        load_session_keys(tmp)
    except SessionKeysError as exc:
        raise PreflightError(f"模拟状态 {tag} 本身不是合法配置：{exc}") from None
    finally:
        tmp.unlink(missing_ok=True)

SUITES = [
    ("contract",  "site-builder/contract",           ".venv/bin/pytest tests -q"),
    ("auth",      "site-builder/auth",               "../contract/.venv/bin/pytest tests -q"),
    ("router",    "router/infrastructure/lambda",    "../../../site-builder/deployer/.venv/bin/pytest . -q"),
    ("deployer",  "site-builder/deployer",           ".venv/bin/pytest tests -q"),
    ("panel",     "site-builder/panel",              "../deployer/.venv/bin/pytest tests -q"),
    ("key-proxy", "site-builder/key-proxy",          "../deployer/.venv/bin/pytest tests -q"),
]

def suite_failures(stdout: str, stderr: str) -> list:
    """从 pytest 输出里挑出**能解释红的行**。

    只 filter `FAILED` 是不够的（3c-1B-G A3）：配置非法时 pytest 死在 **collection**，
    输出的是 `ERROR` 行、`E   SessionKeysError: …` 行，一条 `FAILED` 都没有 ⇒
    调用方拿到空列表 ⇒ 报告打印"红 0 条"，而实际上整套都没跑起来。
    stderr 也要看：venv 缺失、解释器不对这类失败只写 stderr。
    """
    lines = [l for l in stdout.splitlines()
             if l.startswith(("FAILED", "ERROR")) or l.startswith("E   ")
             or " error" in l.lower() and l.startswith("=")]
    if not lines:
        lines = [l for l in stderr.splitlines() if l.strip()][:5]
    return lines or ["（pytest 非零退出但没有可解释的行——手工跑一次那条命令）"]


def run_all(tag):
    bad = []
    for name, cwd, cmd in SUITES:
        r = subprocess.run(cmd, shell=True, cwd=ROOT / cwd, capture_output=True, text=True)
        tail = [l for l in r.stdout.strip().splitlines() if l.strip()][-1:] or [""]
        status = "ok " if r.returncode == 0 else "RED"
        print(f"  [{tag}] {status} {name:10} {tail[0][:70]}")
        if r.returncode != 0:
            bad.append((name, suite_failures(r.stdout, r.stderr)))
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


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--next-kid", action="append", default=[], metavar="FAMILY=KID",
                    help="点名下一轮要就位的 kid（可重复，如 site=site-hs-v3）。"
                         "缺省从 config 里 `{family}_current` 的版本号 +1 推导")
    args = ap.parse_args(argv)
    explicit = {}
    for item in args.next_kid:
        fam, _, kid = item.partition("=")
        if fam not in ("site", "console") or not kid:
            raise SystemExit(f"--next-kid 要写成 site=<kid> 或 console=<kid>，得到 {item!r}")
        explicit[fam] = kid
    refuse_if_mutation_in_flight()
    base = CFG.read_text()
    SENTINEL.parent.mkdir(parents=True, exist_ok=True)
    # `mkdtemp` 而不是"秒级时间戳 + 严格 mkdir"：同一秒内的第二次运行（重试、或紧接着再跑
    # 一次）会撞名，而严格 mkdir 会抛 FileExistsError ⇒ 脚本根本没跑起来。
    # **不能改成 exist_ok**：那会让两次运行往同一个目录写备份，"还原用的是哪一份"就不确定了。
    # `mkdtemp` 保证唯一，且默认就是 0700（备份里有真实账号/域名/证书 ARN）。
    backup_dir = Path(tempfile.mkdtemp(prefix=f"preflight-backup-{int(time.time())}-",
                                       dir=SENTINEL.parent))
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

    nxt = next_kids(base, explicit)
    print(f"下一轮就位的 kid（从 config 的 current 推导，可用 --next-kid 点名）：{nxt}")
    report = {}
    try:
        for tag, fn in (("⑤L3", state_l3), ("⑥stage", state_stage),
                        ("⑦switch", state_switch), ("⑩retire", state_retire)):
            text = fn(base, nxt)
            validate(text, tag)          # 非法配置在这里就响亮失败，不浪费六套件的时间
            CFG.write_text(text)
            print(f"\n=== 模拟 {tag} ===")
            report[tag] = run_all(tag)
    finally:
        restore(backup, base)

    print("\n===== 汇总 =====")
    red = 0
    for tag, bad in report.items():
        if not bad:
            print(f"{tag}: 全绿")
        else:
            red += len(bad)
            for name, fails in bad:
                print(f"{tag}: {name} 红 {len(fails)} 条")
                for f in fails: print(f"    {f}")
    # **任一套件红 ⇒ 非零退出**（3c-1B-G A3）。原先无条件 `return 0`，于是这个"preflight"
    # 可以打印一屏 RED 然后 exit 0——被 `set -e` 的脚本或 CI 读成通过。
    if red:
        print(f"\n{red} 个（状态 × 套件）组合是红的——先把它们改成从加载器推导，再动生产", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":      # 没有这道 guard 时，`import preflight_config_states` 会把整段跑掉
    sys.exit(main())
