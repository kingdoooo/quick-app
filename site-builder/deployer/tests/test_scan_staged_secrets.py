"""`scan_staged_secrets.sh` 的回归——在**临时 git 仓库**里真跑那个脚本。

这个脚本以前一直没有测试，而它是每个提交步骤的闸门。本轮加它的直接原因是一个实测的
假阳性：diff 的行首 `+` 属于 email 规则的 local-part 字符类，于是
`+@pytest.mark.parametrize(...)` 被拼成"邮箱"而命中——**任何**新增的 `@pytest.mark.*`
装饰器都复现。这类反复出现的假阳性最大的害处不是噪音，而是把人训练成无脑加
`--allow-hits`，那时真命中也会被一起放行。

所以这里既要证明"那条假阳性没了"，也要证明"真命中还在"——**只测前者会把一个什么都不
报的扫描器判成修好了**。
"""
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "scan_staged_secrets.sh"


def _repo(tmp_path: Path) -> Path:
    d = tmp_path / "repo"
    d.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=d, check=True,
                                    capture_output=True, text=True)
    run("init", "-q")
    run("config", "user.email", "t@t.invalid")
    run("config", "user.name", "t")
    (d / "seed.txt").write_text("seed\n", encoding="utf-8")
    run("add", "seed.txt")
    run("commit", "-q", "-m", "seed")
    return d


def _scan(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), *args], cwd=repo,
                          capture_output=True, text=True)


def _stage(repo: Path, name: str, body: str) -> None:
    (repo / name).write_text(body, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=repo, check=True,
                   capture_output=True, text=True)


# ── 假阳性必须消失 ────────────────────────────────────────────────────────
def test_added_pytest_decorator_is_not_a_hit(tmp_path):
    """行首 `+` 不再与 `@pytest.mark.*` 拼成邮箱。"""
    repo = _repo(tmp_path)
    _stage(repo, "t.py", '@pytest.mark.parametrize("label", ["a", "b"])\ndef t(): pass\n')
    r = _scan(repo)
    assert r.returncode == 0, f"仍被判成命中：\n{r.stderr}"
    assert "clean" in r.stdout


# ── 真命中必须仍在（否则上面那条可以由"什么都不报"来满足）────────────────
@pytest.mark.parametrize("label,body", [
    ("真邮箱", "owner = \"user+tag@example.com\"\n"),
    ("12 位账号 ID", "acct = \"123456789012\"\n"),
    ("宿主机家目录", "p = \"/Users/someone/projects/x\"\n"),
    ("AWS access key id", "AKIAIOSFODNN7EXAMPLE\n"),
    ("GitHub token", "ghp_" + "a" * 24 + "\n"),
    ("私钥头", "-----BEGIN RSA PRIVATE KEY-----\n"),
])
def test_real_secrets_are_still_hits(tmp_path, label, body):
    repo = _repo(tmp_path)
    _stage(repo, "t.txt", body)
    r = _scan(repo)
    assert r.returncode == 1, f"{label} 没被拦：rc={r.returncode}\n{r.stdout}{r.stderr}"


# ── 只看新增行 ────────────────────────────────────────────────────────────
def test_secret_only_in_context_lines_is_not_a_new_leak(tmp_path):
    """已在仓库里的内容出现在 context 行里，不算这次"新增泄漏"。

    这是一次**刻意的范围收窄**（脚本注释里也写了）：本脚本的主语是"这次新增了什么"。
    """
    repo = _repo(tmp_path)
    # 先把 secret 提交进去，再改同文件的另一行——secret 只会作为 context 出现
    lines = ["x = 1\n"] * 3 + ["acct = \"123456789012\"\n"] + ["y = 2\n"] * 3
    (repo / "t.txt").write_text("".join(lines), encoding="utf-8")
    subprocess.run(["git", "add", "t.txt"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "with secret"], cwd=repo, check=True,
                   capture_output=True)
    lines[0] = "x = 99\n"
    _stage(repo, "t.txt", "".join(lines))
    r = _scan(repo)
    assert r.returncode == 0, f"context 行里的旧 secret 被当成新增：\n{r.stderr}"


def test_removing_a_secret_is_not_a_hit(tmp_path):
    """把 secret 删掉的那次提交不该被拦——否则清理动作本身过不去闸门。"""
    repo = _repo(tmp_path)
    (repo / "t.txt").write_text("acct = \"123456789012\"\n", encoding="utf-8")
    subprocess.run(["git", "add", "t.txt"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "with secret"], cwd=repo, check=True,
                   capture_output=True)
    _stage(repo, "t.txt", "acct = None\n")
    r = _scan(repo)
    assert r.returncode == 0, f"删除 secret 的提交被拦了：\n{r.stderr}"


def test_file_path_header_is_not_scanned(tmp_path):
    """`+++ b/path` 是文件头不是内容。"""
    repo = _repo(tmp_path)
    _stage(repo, "harmless.txt", "nothing here\n")
    r = _scan(repo)
    assert r.returncode == 0, r.stderr


# ── --files 模式不受影响（它扫的是文件本体，没有 diff 前缀）──────────────
def test_files_mode_still_scans_whole_file(tmp_path):
    repo = _repo(tmp_path)
    (repo / "t.txt").write_text("acct = \"123456789012\"\n", encoding="utf-8")
    r = _scan(repo, "--files", "t.txt")
    assert r.returncode == 1, f"--files 模式漏了：{r.stdout}{r.stderr}"


def test_files_mode_decorator_is_a_hit_because_the_at_follows_a_word(tmp_path):
    """**边界要说清**：`--files` 模式下 `@pytest.mark.x` 本身不含 local-part，

    所以不命中；而 `--files` 扫的是文件原文、没有 diff 前缀，所以那条假阳性在这个
    模式下从来就不存在。这条用例把这个差别钉住，避免以后有人"顺手统一"两条路径。
    """
    repo = _repo(tmp_path)
    (repo / "t.py").write_text('@pytest.mark.parametrize("l", ["a"])\n', encoding="utf-8")
    r = _scan(repo, "--files", "t.py")
    assert r.returncode == 0, f"--files 模式误报：{r.stderr}"


# ── fail-closed 的既有行为不许退化 ────────────────────────────────────────
def test_empty_stage_is_refused(tmp_path):
    repo = _repo(tmp_path)
    r = _scan(repo)
    assert r.returncode == 2, "空 stage 必须拒绝放行（否则等于没扫）"


def test_outside_a_git_repo_is_refused(tmp_path):
    r = subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path,
                       capture_output=True, text=True)
    assert r.returncode == 2, "非 git 目录必须拒绝放行，不许 fail-open"


def test_allow_hits_still_exits_zero_but_prints_the_hits(tmp_path):
    repo = _repo(tmp_path)
    _stage(repo, "t.txt", "acct = \"123456789012\"\n")
    r = _scan(repo, "--allow-hits")
    assert r.returncode == 0
    assert "123456789012" in r.stderr, "放行时也必须把命中打出来给人看"
