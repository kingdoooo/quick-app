"""`scripts/bootstrap_venvs.sh` 与仓库根 `orca.yaml` 的守卫：静态形状 + 前置检查的真跑负向。

脚本是 CLAUDE.md「仓库外的几样东西」第 2 步的脚本化。五个 venv 的路径与清单**从 CLAUDE.md
的那张表抄**、不新发明，所以这里就按那张表核对——表改了脚本没改、或反过来，本条红。
"真跑一遍建出五个 venv 并让七套件全绿"是验收，不在单测里；单测只证明三件事：

  · 形状对：每条 `-m venv` 都带 `--clear`（shebang 是绝对路径，不带就一直 bad interpreter）；
    两份 `requirements-dev.txt` 里的 `-e` 按**进程 cwd** 解析，所以装之前必须先 `cd` 进目录；
  · 前置检查真的会拒绝（用假的 `python3` / 缺 `python3.12` 的 PATH 真跑，看退出码与指引文案）；
  · orca.yaml 的 setup 段只做两件事——复制两份 config.ini（cp 不 ln）+ 跑脚本（不带 --host-deps）。

每条静态判定都有一条变形对照（`test_static_checks_can_fail`），否则"什么都不检查"也能全绿。
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from test_delivery_docs_current import _read, _section

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "site-builder" / "scripts" / "bootstrap_venvs.sh"
ORCA_YAML = ROOT / "orca.yaml"
CLAUDE_MD = ROOT / "CLAUDE.md"
DEPLOY_MD = ROOT / "site-builder" / "DEPLOY.md"
OUTSIDE_REPO_HEADING = "### 仓库外的几样东西（新 clone / 新机器按这个顺序恢复）"
HOST_DEPS_CMD = "python3 -m pip install --user --break-system-packages boto3 pip-system-certs"


# ── 解析器（被正向用例与变形对照共用）──────────────────────────────────────────
def claude_md_venv_table() -> dict:
    """CLAUDE.md 第 2 步那张表：`| \\`dir/.venv\\` | \\`manifest\\` | 备注 |` → {dir: manifest}。"""
    sec = _section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING)
    rows = re.findall(r"^\s*\| `([^`]+)/\.venv` \| `([^`]+)` \|", sec, flags=re.M)  # 表在列表项里，行首有缩进
    assert rows, "CLAUDE.md 里找不到 venv 表——标题或表头被改过？"
    return dict(rows)


def script_venv_table(text: str) -> dict:
    """脚本里 `VENVS=( "dir|manifest" … )` 的那张表。"""
    m = re.search(r"^VENVS=\((.*?)^\)", text, flags=re.M | re.S)
    assert m, "脚本里找不到 VENVS=( … ) 表"
    return dict(re.findall(r'"([^"|]+)\|([^"|]+)"', m.group(1)))


def venv_lines_missing_clear(text: str) -> list:
    return [ln for ln in text.splitlines()
            if re.search(r"-m venv\b", ln) and not ln.lstrip().startswith("#") and "--clear" not in ln]


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


# ── 静态：形状 ────────────────────────────────────────────────────────────────
def test_script_exists_is_executable_and_parses():
    assert SCRIPT.exists(), f"{SCRIPT} 不存在"
    assert SCRIPT.stat().st_mode & stat.S_IXUSR, "脚本没有可执行位"
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    head = SCRIPT.read_text(encoding="utf-8").splitlines()
    assert any(ln.strip() == "set -euo pipefail" for ln in head[:40]), "缺 set -euo pipefail"


def test_script_table_matches_claude_md_table_and_manifests_exist():
    doc = claude_md_venv_table()
    scr = script_venv_table(SCRIPT.read_text(encoding="utf-8"))
    assert len(doc) == 5, doc
    assert scr == doc, f"脚本与 CLAUDE.md 的 venv 表不一致：\n脚本 {scr}\n文档 {doc}"
    for d, manifest in doc.items():
        assert (ROOT / d / manifest).is_file(), f"{d}/{manifest} 不存在"


def test_every_venv_creation_carries_clear():
    text = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"-m venv\b", text), "脚本里没有任何 -m venv"
    assert venv_lines_missing_clear(text) == []


def test_install_happens_after_cd_into_the_venv_dir():
    body = function_body(SCRIPT.read_text(encoding="utf-8"), "build_one")
    assert cd_precedes_install(body), "\n".join(body)


def test_host_deps_command_is_the_one_claude_md_prescribes():
    text = SCRIPT.read_text(encoding="utf-8")
    assert HOST_DEPS_CMD in text, "脚本里 --host-deps 装的不是 CLAUDE.md 第 3 步那条命令"
    sec = _section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING)
    assert HOST_DEPS_CMD in sec.replace("`", ""), "CLAUDE.md 第 3 步的命令改了，脚本要跟"


def test_stamp_file_is_gitignored():
    text = SCRIPT.read_text(encoding="utf-8")
    m = re.search(r'STAMP="\$ROOT/(\.[\w.-]+)"', text)
    assert m, "脚本没有声明 STAMP 文件"
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert m.group(1) in ignored, f".gitignore 没列 {m.group(1)}"


# ── 变形对照：每条静态判定都能红 ────────────────────────────────────────────────
def test_static_checks_can_fail():
    text = SCRIPT.read_text(encoding="utf-8")
    # ① 去掉真正执行那一行（不是头部注释里那句）的 --clear
    mutated = text.replace('"$PY" -m venv --clear .venv', '"$PY" -m venv .venv')
    assert mutated != text, "找不到执行 venv 的那一行"
    assert venv_lines_missing_clear(mutated), "去掉 --clear 后守卫没红"
    # ② 表里改一个目录名
    mutated = text.replace('"site-builder/mcp|requirements.txt"', '"site-builder/mcpx|requirements.txt"')
    assert script_venv_table(mutated) != claude_md_venv_table(), "改表后守卫没红"
    # ③ cd 挪到 pip install 之后
    body = function_body(text, "build_one")
    cd_i = next(i for i, ln in enumerate(body) if re.match(r"\s*cd\s", ln))
    moved = body[:cd_i] + body[cd_i + 1:] + [body[cd_i]]
    assert not cd_precedes_install(moved), "cd 挪到后面守卫没红"
    # ④ 去掉 cd
    assert not cd_precedes_install(body[:cd_i] + body[cd_i + 1:]), "去掉 cd 守卫没红"


# ── 真跑：前置检查会拒绝、旗标解析正确 ─────────────────────────────────────────
def _stub(dir_: Path, name: str, body: str) -> None:
    p = dir_ / name
    p.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    p.chmod(0o755)


def _run(*args, path: str) -> subprocess.CompletedProcess:
    env = {"PATH": path, "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C.UTF-8"}
    return subprocess.run(["/bin/bash", str(SCRIPT), *args], capture_output=True,
                          text=True, env=env, cwd=str(ROOT))


def test_help_exits_zero_and_lists_flags():
    r = _run("--help", path="/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    for flag in ("--host-deps", "--only", "--check"):
        assert flag in r.stdout, f"--help 里没有 {flag}"


def test_unknown_flag_is_rejected():
    r = _run("--bogus", path="/usr/bin:/bin")
    assert r.returncode == 2, (r.returncode, r.stderr)


def test_missing_python312_is_fatal(tmp_path):
    """PATH 里没有 python3.12 ⇒ 非零退出并点名它。/usr/bin 上没有 3.12（Homebrew 装在别处）。"""
    r = _run("--check", path="/usr/bin:/bin")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "python3.12" in r.stderr


def test_old_unqualified_python3_is_fatal_with_the_two_layer_fix(tmp_path):
    """`python3` 是 3.9（macOS 自带那个）⇒ 非零退出，并把 CLAUDE.md 第 0 步的两层解法打出来。"""
    _stub(tmp_path, "python3.12", "exit 0")
    _stub(tmp_path, "python3", 'echo "Python 3.9.6"')
    r = _run("--check", path=f"{tmp_path}:/usr/bin:/bin")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "3.9.6" in r.stderr and "3.10" in r.stderr
    assert ".zshenv" in r.stderr and "libexec/bin" in r.stderr, r.stderr
    assert "ln -s" in r.stderr, "没给出软链那层解法"


def test_missing_python313_only_warns(tmp_path):
    _stub(tmp_path, "python3.12", 'echo "Python 3.12.0"')
    _stub(tmp_path, "python3", 'echo "Python 3.12.0"')
    r = _run("--check", path=f"{tmp_path}:/usr/bin:/bin")
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "python3.13" in r.stderr and "run_locked_tests" in r.stderr


def test_only_rejects_a_dir_outside_the_table(tmp_path):
    _stub(tmp_path, "python3.12", 'echo "Python 3.12.0"')
    _stub(tmp_path, "python3.13", 'echo "Python 3.13.0"')
    _stub(tmp_path, "python3", 'echo "Python 3.12.0"')
    r = _run("--only", "site-builder/auth", path=f"{tmp_path}:/usr/bin:/bin")
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


def test_orca_setup_hook_runs_the_bootstrap_without_host_deps(tmp_path):
    setup = _setup_block()
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


def test_orca_setup_hook_copy_skips_existing_and_missing(tmp_path):
    """真跑 setup 段的复制部分：主 checkout 有的才复制、目标已存在不覆盖、主 checkout 缺的不报错。"""
    setup = _setup_block()
    copy_lines = "\n".join(ln for ln in setup.splitlines() if "bootstrap_venvs.sh" not in ln)
    root = tmp_path / "root"; wt = tmp_path / "wt"
    for base in (root, wt):
        (base / "site-builder").mkdir(parents=True); (base / "router").mkdir(parents=True)
    (root / "site-builder" / "config.ini").write_text("from-root\n", encoding="utf-8")
    (wt / "router" / "config.ini").write_text("already-here\n", encoding="utf-8")
    r = subprocess.run(["bash", "-c", copy_lines], cwd=str(wt), capture_output=True, text=True,
                       env={**os.environ, "ORCA_ROOT_PATH": str(root)})
    assert r.returncode == 0, r.stderr
    assert (wt / "site-builder" / "config.ini").read_text() == "from-root\n"
    assert (wt / "router" / "config.ini").read_text() == "already-here\n", "已存在的被覆盖了"


# ── 文档：两处入口都指向脚本 ───────────────────────────────────────────────────
def test_claude_md_step_two_points_at_the_script():
    sec = _section(_read(CLAUDE_MD), OUTSIDE_REPO_HEADING)
    assert "bootstrap_venvs.sh" in sec
    assert "orca.yaml" in sec, "要说明 Orca worktree 由 orca.yaml 的 setup hook 自动跑它"


def test_deploy_md_toolchain_section_points_at_the_script():
    sec = _section(_read(DEPLOY_MD), "### 本机工具链")
    assert "bootstrap_venvs.sh" in sec
