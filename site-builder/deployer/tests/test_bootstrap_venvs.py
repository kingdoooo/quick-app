"""`scripts/bootstrap_venvs.sh` 与仓库根 `orca.yaml` 的守卫：静态形状 + 前置检查的真跑负向。

脚本是 CLAUDE.md「仓库外的几样东西」第 2 步的脚本化。五个 venv 的路径与清单**从 CLAUDE.md
的那张表抄**、不新发明，所以这里就按那张表核对——表改了脚本没改、或反过来，本条红。
"真跑一遍建出五个 venv 并让七套件全绿"是验收，不在单测里；单测只证明三件事：

  · 形状对：每条 `-m venv` 都带 `--clear`（shebang 是绝对路径，不带就一直 bad interpreter）；
    两份 `requirements-dev.txt` 里的 `-e` 按**进程 cwd** 解析，所以装之前必须先 `cd` 进目录，
    且所有 `pip install -r` 都只经过那一个先 cd 的函数；全量重跑前先删旧的成功标记；
  · 前置检查真的会拒绝（用假的 `python3` / 只有 `python3` 的 PATH 真跑，看退出码与指引文案）；
  · orca.yaml 的 setup 段 fail fast，且只做两件事——复制两份 config.ini（cp 不 ln）+ 跑脚本
    （不带 --host-deps）。

**每条静态判定都是一个吃文本的函数**，`test_static_checks_can_fail` 对每一条各做一次变形，
证明它们能红——否则"什么都不检查"也能让上面全绿。
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

from test_delivery_docs_current import _read, _section

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "site-builder" / "scripts" / "bootstrap_venvs.sh"
ORCA_YAML = ROOT / "orca.yaml"
GITIGNORE = ROOT / ".gitignore"
CLAUDE_MD = ROOT / "CLAUDE.md"
DEPLOY_MD = ROOT / "site-builder" / "DEPLOY.md"
OUTSIDE_REPO_HEADING = "### 仓库外的几样东西（新 clone / 新机器按这个顺序恢复）"
HOST_DEPS_CMD = "python3 -m pip install --user --break-system-packages boto3 pip-system-certs cryptography"
VENV_EXEC_LINE = '"$PY" -m venv --clear .venv'


# ── 静态判定（纯函数：文本 → 违规/布尔；正向用例与变形对照共用）───────────────
def claude_md_venv_table(sec: str) -> dict:
    """CLAUDE.md 第 2 步那张表：`| \\`dir/.venv\\` | \\`manifest\\` | 备注 |` → {dir: manifest}。"""
    rows = re.findall(r"^\s*\| `([^`]+)/\.venv` \| `([^`]+)` \|", sec, flags=re.M)  # 表在列表项里，行首有缩进
    assert rows, "CLAUDE.md 里找不到 venv 表——标题或表头被改过？"
    return dict(rows)


def script_venv_table(text: str) -> dict:
    """脚本里 `VENVS=( "dir|manifest" … )` 的那张表。"""
    m = re.search(r"^VENVS=\((.*?)^\)", text, flags=re.M | re.S)
    assert m, "脚本里找不到 VENVS=( … ) 表"
    return dict(re.findall(r'"([^"|]+)\|([^"|]+)"', m.group(1)))


def _code_lines(text: str) -> list:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def venv_lines_missing_clear(text: str) -> list:
    return [ln for ln in _code_lines(text) if re.search(r"-m venv\b", ln) and "--clear" not in ln]


def has_fail_fast(text: str) -> bool:
    return any(ln.strip() == "set -euo pipefail" for ln in text.splitlines()[:40])


def function_body(text: str, name: str) -> list:
    """`name() {` 到配对 `}` 的行（按缩进：第 0 列的 `}` 收尾）。"""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\(\)\s*\{{", ln):
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("}"):
                    return lines[i + 1:j]
            raise AssertionError(f"函数 {name} 没有收尾的 }}")
    raise AssertionError(f"脚本里找不到函数 {name}()")


def cd_precedes_install(body: list) -> bool:
    """build_one 里：先 cd 进 venv 目录，再 venv --clear，再 pip install -r。"""
    idx = {"cd": None, "venv": None, "pip": None}
    for i, ln in enumerate(body):
        s = ln.strip()
        if s.startswith("#"):
            continue
        if idx["cd"] is None and re.match(r"cd\s+\"?\$ROOT/\$dir\"?", s):
            idx["cd"] = i
        if idx["venv"] is None and re.search(r"-m venv\b", s):
            idx["venv"] = i
        if idx["pip"] is None and re.search(r"pip install\b.*\s-r\s", s):
            idx["pip"] = i
    return (None not in idx.values()) and idx["cd"] < idx["venv"] < idx["pip"]


def requirement_installs_outside(text: str, body: list) -> list:
    """所有 `pip install … -r` 都必须在 build_one 里——否则 cd 的守卫会被第二条安装路径绕过。"""
    inside = set(body)
    return [ln for ln in _code_lines(text) if re.search(r"pip install\b.*\s-r\s", ln) and ln not in inside]


def stamp_name(text: str) -> str:
    m = re.search(r'STAMP="\$ROOT/(\.[\w.-]+)"', text)
    assert m, "脚本没有声明 STAMP 文件"
    return m.group(1)


def stale_stamp_removed_before_build(text: str) -> bool:
    """全量模式在第一条 build_one 调用之前 rm -f 旧标记（重跑失败不能留着上次的成功标记）。"""
    lines = _code_lines(text)
    rm_i = next((i for i, ln in enumerate(lines) if re.search(r'rm -f "\$STAMP"', ln)), None)
    build_i = next((i for i, ln in enumerate(lines) if re.match(r"\s*build_one ", ln)), None)
    return rm_i is not None and build_i is not None and rm_i < build_i


def gitignore_lists(ignore_text: str, name: str) -> bool:
    return name in ignore_text.splitlines()


# ── 静态：形状 ────────────────────────────────────────────────────────────────
def test_script_exists_is_executable_and_parses():
    assert SCRIPT.exists(), f"{SCRIPT} 不存在"
    assert SCRIPT.stat().st_mode & stat.S_IXUSR, "脚本没有可执行位"
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert has_fail_fast(SCRIPT.read_text(encoding="utf-8")), "缺 set -euo pipefail"


def test_script_table_matches_claude_md_table_and_manifests_exist():
    doc = claude_md_venv_table(_section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING))
    scr = script_venv_table(SCRIPT.read_text(encoding="utf-8"))
    assert len(doc) == 5, doc
    assert scr == doc, f"脚本与 CLAUDE.md 的 venv 表不一致：\n脚本 {scr}\n文档 {doc}"
    for d, manifest in doc.items():
        assert (ROOT / d / manifest).is_file(), f"{d}/{manifest} 不存在"


def test_every_venv_creation_carries_clear():
    text = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"-m venv\b", text), "脚本里没有任何 -m venv"
    assert venv_lines_missing_clear(text) == []


def test_install_happens_after_cd_and_only_inside_build_one():
    text = SCRIPT.read_text(encoding="utf-8")
    body = function_body(text, "build_one")
    assert cd_precedes_install(body), "\n".join(body)
    assert requirement_installs_outside(text, body) == []


def test_host_deps_command_is_the_one_claude_md_prescribes():
    text = SCRIPT.read_text(encoding="utf-8")
    assert HOST_DEPS_CMD in text, "脚本里 --host-deps 装的不是 CLAUDE.md 第 3 步那条命令"
    sec = _section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING)
    assert HOST_DEPS_CMD in sec.replace("`", ""), "CLAUDE.md 第 3 步的命令改了，脚本要跟"


def test_stamp_is_gitignored_and_stale_one_is_removed_before_a_full_build():
    text = SCRIPT.read_text(encoding="utf-8")
    assert gitignore_lists(GITIGNORE.read_text(encoding="utf-8"), stamp_name(text)), \
        f".gitignore 没列 {stamp_name(text)}"
    assert stale_stamp_removed_before_build(text)


# ── 变形对照：每条静态判定都能红 ────────────────────────────────────────────────
def test_static_checks_can_fail(tmp_path):
    text = SCRIPT.read_text(encoding="utf-8")
    body = function_body(text, "build_one")
    cd_i = next(i for i, ln in enumerate(body) if re.match(r"\s*cd\s", ln))
    doc = claude_md_venv_table(_section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING))

    # ① 去掉真正执行那一行（不是头部注释里那句）的 --clear
    mutated = text.replace(VENV_EXEC_LINE, '"$PY" -m venv .venv')
    assert mutated != text, "找不到执行 venv 的那一行"
    assert venv_lines_missing_clear(mutated), "去掉 --clear 后守卫没红"
    # ② 表里改一个目录名
    mutated = text.replace('"site-builder/mcp|requirements.txt"', '"site-builder/mcpx|requirements.txt"')
    assert script_venv_table(mutated) != doc, "改表后守卫没红"
    # ③ cd 挪到 pip install 之后；④ 去掉 cd
    assert not cd_precedes_install(body[:cd_i] + body[cd_i + 1:] + [body[cd_i]]), "cd 挪到后面守卫没红"
    assert not cd_precedes_install(body[:cd_i] + body[cd_i + 1:]), "去掉 cd 守卫没红"
    # ⑤ 在 build_one 之外加第二条 pip install -r
    mutated = text.replace("T_ALL0=$(date +%s)", 'pip install -r extra.txt\nT_ALL0=$(date +%s)')
    assert requirement_installs_outside(mutated, body), "函数外的第二条安装路径没被抓到"
    # ⑥ 去掉 set -euo pipefail
    assert not has_fail_fast(text.replace("set -euo pipefail", "set -u")), "去掉 fail-fast 守卫没红"
    # ⑦ 换掉 --host-deps 的命令
    assert HOST_DEPS_CMD not in text.replace("--break-system-packages ", ""), "改 host-deps 命令守卫没红"
    # ⑧ 旧标记不删 / 删在 build 之后
    assert not stale_stamp_removed_before_build(text.replace('rm -f "$STAMP"', "true")), "不删旧标记守卫没红"
    lines = text.splitlines()
    rm_line = next(ln for ln in lines if 'rm -f "$STAMP"' in ln)
    moved = [ln for ln in lines if ln != rm_line]
    moved.insert(next(i for i, ln in enumerate(moved) if ln.startswith("echo \"== 结果\"")), rm_line)
    assert not stale_stamp_removed_before_build("\n".join(moved)), "删在 build 之后守卫没红"
    # ⑨ .gitignore 漏列
    ig = GITIGNORE.read_text(encoding="utf-8")
    assert not gitignore_lists(ig.replace(stamp_name(text) + "\n", ""), stamp_name(text)), "漏列守卫没红"
    # ⑩ 可执行位
    copy = tmp_path / "s.sh"
    copy.write_text(text, encoding="utf-8"); copy.chmod(0o644)
    assert not copy.stat().st_mode & stat.S_IXUSR


# ── 真跑：前置检查会拒绝、旗标解析正确 ─────────────────────────────────────────
def _stub(dir_: Path, name: str, body: str) -> None:
    p = dir_ / name
    p.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    p.chmod(0o755)


def _run(*args, path: str) -> subprocess.CompletedProcess:
    env = {"PATH": path, "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C.UTF-8"}
    return subprocess.run(["/bin/bash", str(SCRIPT), *args], capture_output=True,
                          text=True, env=env, cwd=str(ROOT))


def _bin(tmp_path: Path, **stubs: str) -> str:
    """只含给定 stub 的 bin 目录（不掺 /usr/bin，所以"缺某个解释器"不依赖本机布局）。"""
    d = tmp_path / "bin"; d.mkdir(exist_ok=True)
    for name, body in stubs.items():
        _stub(d, name.replace("_", "."), body)
    return str(d)


def test_help_exits_zero_and_lists_flags():
    r = _run("--help", path="/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    for flag in ("--host-deps", "--only", "--check"):
        assert flag in r.stdout, f"--help 里没有 {flag}"


def test_unknown_flag_is_rejected():
    assert _run("--bogus", path="/usr/bin:/bin").returncode == 2


def test_check_and_host_deps_are_mutually_exclusive(tmp_path):
    r = _run("--check", "--host-deps", path=_bin(tmp_path, python3_12='echo "Python 3.12.0"', python3='echo "Python 3.12.0"'))
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "--host-deps" in r.stderr


def test_missing_python312_is_fatal(tmp_path):
    """PATH 里只有一个 python3、没有 python3.12 ⇒ 非零退出并点名它。不借本机 /usr/bin。"""
    r = _run("--check", path=_bin(tmp_path, python3='echo "Python 3.12.0"'))
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "python3.12" in r.stderr


def test_old_unqualified_python3_is_fatal_with_the_two_layer_fix(tmp_path):
    """`python3` 是 3.9（macOS 自带那个）⇒ 非零退出，并把 CLAUDE.md 第 0 步的两层解法打出来。"""
    r = _run("--check", path=_bin(tmp_path, python3_12="exit 0", python3='echo "Python 3.9.6"') + ":/usr/bin:/bin")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "3.9.6" in r.stderr and "3.10" in r.stderr
    assert ".zshenv" in r.stderr and "libexec/bin" in r.stderr, r.stderr
    assert "ln -s" in r.stderr, "没给出软链那层解法"


def test_missing_python313_only_warns(tmp_path):
    r = _run("--check", path=_bin(tmp_path, python3_12='echo "Python 3.12.0"', python3='echo "Python 3.12.0"') + ":/usr/bin:/bin")
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "python3.13" in r.stderr and "run_locked_tests" in r.stderr


def test_only_rejects_a_dir_outside_the_table(tmp_path):
    path = _bin(tmp_path, python3_12='echo "Python 3.12.0"', python3_13='echo "Python 3.13.0"', python3='echo "Python 3.12.0"')
    r = _run("--only", "site-builder/auth", path=path + ":/usr/bin:/bin")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "site-builder/auth" in r.stderr and "site-builder/mcp" in r.stderr, "拒绝时要列出合法目录"


# ── orca.yaml：setup hook 的形状 ───────────────────────────────────────────────
def _setup_block() -> str:
    data = yaml.safe_load(ORCA_YAML.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and "scripts" in data, data
    assert set(data) <= {"scripts", "issueCommand"}, f"Orca 只认 scripts / issueCommand：{set(data)}"
    assert set(data["scripts"]) <= {"setup", "archive"}, data["scripts"]
    setup = data["scripts"]["setup"]
    assert isinstance(setup, str) and setup.strip(), "scripts.setup 为空"
    return setup


def _copy_part(setup: str) -> str:
    return "\n".join(ln for ln in setup.splitlines() if "bootstrap_venvs.sh" not in ln)


def test_orca_setup_hook_fails_fast_and_runs_the_bootstrap_without_host_deps(tmp_path):
    setup = _setup_block()
    lines = setup.splitlines()
    assert lines[0].strip() == "set -euo pipefail", "setup 段第一行必须 fail fast"
    # setup runner 继承 GUI 进程的 PATH（/usr/bin 在 /opt/homebrew/bin 之前）⇒ 不前置就会拿到 3.9 被 bootstrap 拒绝
    prepend = next((i for i, ln in enumerate(lines) if "python@3.12/libexec/bin" in ln and "PATH=" in ln), None)
    boot = next(i for i, ln in enumerate(lines) if "bootstrap_venvs.sh" in ln)
    assert prepend is not None and prepend < boot, "要在跑脚本之前前置 Homebrew python@3.12 的 libexec/bin"
    assert lines[prepend].lstrip().startswith("[ -d "), "前置要带 -d 守卫，没装 Homebrew 的机器不能因此红"
    assert "site-builder/scripts/bootstrap_venvs.sh" in setup
    assert "--host-deps" not in setup, "hook 不该改机器（--host-deps 归人手跑）"
    f = tmp_path / "setup.sh"
    f.write_text(setup, encoding="utf-8")
    r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_orca_setup_hook_copies_both_config_ini_from_root_checkout():
    setup = _setup_block()
    for cfg in ("site-builder/config.ini", "router/config.ini"):
        assert cfg in setup, f"hook 没复制 {cfg}"
    assert "$ORCA_ROOT_PATH" in setup, "来源必须是主 checkout（$ORCA_ROOT_PATH）"
    assert re.search(r"\bcp\b", setup), "要 cp"
    assert not re.search(r"\bln\b", setup), "不许软链——worker 误改会直写主 worktree 的配置"


def _fixture_trees(tmp_path: Path):
    root = tmp_path / "root"; wt = tmp_path / "wt"
    for base in (root, wt):
        (base / "site-builder").mkdir(parents=True); (base / "router").mkdir(parents=True)
    (root / "site-builder" / "config.ini").write_text("from-root\n", encoding="utf-8")
    (wt / "router" / "config.ini").write_text("already-here\n", encoding="utf-8")
    return root, wt


def test_orca_setup_hook_copy_skips_existing_and_missing(tmp_path):
    """真跑 setup 段的复制部分：主 checkout 有的才复制、目标已存在不覆盖、主 checkout 缺的不报错。"""
    root, wt = _fixture_trees(tmp_path)
    r = subprocess.run(["bash", "-c", _copy_part(_setup_block())], cwd=str(wt), capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "ORCA_ROOT_PATH": str(root)})
    assert r.returncode == 0, r.stderr
    assert (wt / "site-builder" / "config.ini").read_text() == "from-root\n"
    assert (wt / "router" / "config.ini").read_text() == "already-here\n", "已存在的被覆盖了"


def test_orca_setup_hook_without_root_path_or_with_failing_cp_exits_nonzero(tmp_path):
    """负向：ORCA_ROOT_PATH 没设 ⇒ set -u 当场红，而不是静默建出没配置的 worktree；cp 失败同样红。"""
    root, wt = _fixture_trees(tmp_path)
    r = subprocess.run(["bash", "-c", _copy_part(_setup_block())], cwd=str(wt), capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"})
    assert r.returncode != 0 and "ORCA_ROOT_PATH" in r.stderr, (r.returncode, r.stderr)
    (wt / "site-builder").chmod(0o555)      # 目标目录不可写 ⇒ cp 失败
    try:
        r = subprocess.run(["bash", "-c", _copy_part(_setup_block())], cwd=str(wt), capture_output=True, text=True,
                           env={"PATH": "/usr/bin:/bin", "ORCA_ROOT_PATH": str(root)})
    finally:
        (wt / "site-builder").chmod(0o755)
    assert r.returncode != 0, "cp 失败却退 0"


# ── 文档：两处入口都指向脚本 ───────────────────────────────────────────────────
def test_claude_md_step_two_points_at_the_script():
    sec = _section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING)
    assert "bootstrap_venvs.sh" in sec
    assert "orca.yaml" in sec, "要说明 Orca worktree 由 orca.yaml 的 setup hook 自动跑它"


def test_deploy_md_toolchain_section_points_at_the_script():
    sec = _section(_read(DEPLOY_MD), "### 本机工具链")
    assert "bootstrap_venvs.sh" in sec
