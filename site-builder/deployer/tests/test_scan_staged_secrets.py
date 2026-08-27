"""`scan_staged_secrets.sh` 的回归——在**临时 git 仓库**里真跑那个脚本。

这个脚本以前一直没有测试，而它是每个提交步骤的闸门。本轮加它的直接原因是一个实测的
假阳性：diff 的行首 `+` 属于 email 规则的 local-part 字符类，于是
`+@pytest.mark.parametrize(...)` 被拼成"邮箱"而命中——**任何**新增的 `@pytest.mark.*`
装饰器都复现。这类反复出现的假阳性最大的害处不是噪音，而是把人训练成无脑加
`--allow-hits`，那时真命中也会被一起放行。

所以这里既要证明"那条假阳性没了"，也要证明"真命中还在"——**只测前者会把一个什么都不
报的扫描器判成修好了**。

第二轮加的是 `--range` 的 **commit message** 覆盖：那个模式（推公开 remote 前的最后一道
闸门）原来只跑 `git diff <range>`，commit message 一个字都没看，实测漏过一条把内部角色名
前缀写在提交信息里的提交而报 clean。同一条"某个来源根本没被扫却报 clean"的形状在这里出现
过两次（先是空 stage，再是 message），所以下面的用例既钉住"message 里的 secret 会被拦"，
也钉住"这条新路径的每个失败出口都 fail-closed"。
"""
import os
import shutil
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


# ── 预处理失败必须 fail-closed ────────────────────────────────────────────
# 本脚本只 `set -uo pipefail`、**没有** `set -e`，所以
# `text="$(… | strip_added_lines)"` 失败时赋值只是把 text 置空、脚本继续往下走 →
# grep 扫空串 → 报 clean → exit 0。这是外部复审用一个返回 2 的假 awk 实测出来的
# fail-open：staged diff 里带真 AKIA fixture 也报 clean。
def _fake_awk_path(tmp_path: Path) -> str:
    d = tmp_path / "fakebin"
    d.mkdir()
    (d / "awk").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    (d / "awk").chmod(0o755)
    import os
    return f"{d}:{os.environ['PATH']}"


@pytest.mark.parametrize("mode", ["staged", "range"])
def test_preprocessor_failure_refuses_to_pass(tmp_path, mode):
    import os
    repo = _repo(tmp_path)
    _stage(repo, "t.txt", "AKIAIOSFODNN7EXAMPLE\n")
    if mode == "range":
        subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True,
                       capture_output=True)
        args = ["--range", "HEAD~1...HEAD"]
    else:
        args = []
    env = dict(os.environ, PATH=_fake_awk_path(tmp_path))
    r = subprocess.run(["bash", str(SCRIPT), *args], cwd=repo,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2, (
        f"预处理失败却放行了（rc={r.returncode}）——那是 fail-open\n{r.stdout}{r.stderr}")
    assert "提取失败" in r.stderr


# ── --range 路径（原来一条测试都没有）──────────────────────────────────────
def test_range_mode_decorator_is_not_a_hit(tmp_path):
    repo = _repo(tmp_path)
    _stage(repo, "t.py", '@pytest.mark.parametrize("l", ["a"])\n')
    subprocess.run(["git", "commit", "-q", "-m", "add test"], cwd=repo, check=True,
                   capture_output=True)
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 0, f"range 模式误报：\n{r.stderr}"


def test_range_mode_real_secret_is_a_hit(tmp_path):
    repo = _repo(tmp_path)
    _stage(repo, "t.txt", "AKIAIOSFODNN7EXAMPLE\n")
    subprocess.run(["git", "commit", "-q", "-m", "add secret"], cwd=repo, check=True,
                   capture_output=True)
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 1, f"range 模式漏了真 secret：{r.stdout}{r.stderr}"


def test_range_mode_with_bad_ref_is_refused(tmp_path):
    repo = _repo(tmp_path)
    r = _scan(repo, "--range", "no-such-ref...HEAD")
    assert r.returncode == 2, "不存在的 ref 必须拒绝放行，不许 fail-open"


# ── --range 的 commit message（外部复审报的洞：原来只跑 git diff）─────────────
# 提交信息和文件内容一样会被 push 出去，公开 remote 上一样能读。
NOREPLY_TRAILER = "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"


def _commit(repo: Path, message: str, *, name: str = "t.txt",
            body: str = "nothing here\n") -> None:
    """提交一次。**文件内容默认无害**——这样命中只可能来自 message。"""
    (repo / name).write_text(body, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True,
                   capture_output=True, text=True)


def test_range_mode_catches_secret_only_in_commit_message(tmp_path):
    """本轮的回归主体：secret **只**在提交信息里，文件内容干净。"""
    repo = _repo(tmp_path)
    _commit(repo, "chore: rotate the key\n\nAKIAIOSFODNN7EXAMPLE\n")
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 1, f"message 里的 secret 没被拦：rc={r.returncode}\n{r.stdout}{r.stderr}"
    assert "AKIAIOSFODNN7EXAMPLE" in r.stderr, "命中内容必须打出来给人判断"
    assert "commit message" in r.stderr, "必须说清命中来自 commit message 而不是 diff"


def test_range_mode_diff_hit_is_labelled_as_added_lines(tmp_path):
    """两个来源要能区分开——人得知道该改文件还是改提交信息。"""
    repo = _repo(tmp_path)
    _commit(repo, "chore: harmless subject\n", body="AKIAIOSFODNN7EXAMPLE\n")
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 1, f"{r.stdout}{r.stderr}"
    assert "新增行" in r.stderr, f"没标出命中来自 diff 的新增行：\n{r.stderr}"


def test_range_mode_noreply_coauthor_trailer_alone_is_not_a_hit(tmp_path):
    """本仓库**每个**提交都带这条 trailer。它每跑必中的话，操作者会被训练成无脑加
    `--allow-hits`，真命中跟着一起放行——那正是本脚本头注释警告的失效模式。
    """
    repo = _repo(tmp_path)
    _commit(repo, f"docs: tidy up\n\n{NOREPLY_TRAILER}\n")
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 0, f"机器人 noreply co-author trailer 被报成命中：\n{r.stderr}"
    assert "clean" in r.stdout


@pytest.mark.parametrize("label,message", [
    # 正文里的真人邮箱：豁免不能顺手把 message 里的 email 规则整条关掉
    ("正文里的真人邮箱", "fix: reported by someone@example.com\n"),
    # 同样是 co-author trailer，只是地址不是 noreply@ ——豁免的键是地址，不是 trailer 名
    ("非 noreply 的 co-author", "docs: x\n\nCo-Authored-By: A Human <human@example.com>\n"),
    # noreply trailer 行上**除地址以外**的部分照旧参与扫描（这里是宿主机家目录）
    ("noreply 行的其余部分", "docs: x\n\nCo-Authored-By: /Users/someone/ <noreply@anthropic.com>\n"),
])
def test_range_mode_message_exclusion_stays_narrow(tmp_path, label, message):
    repo = _repo(tmp_path)
    _commit(repo, message)
    r = _scan(repo, "--range", "HEAD~1...HEAD")
    assert r.returncode == 1, f"{label} 被豁免误伤了：rc={r.returncode}\n{r.stdout}{r.stderr}"


def test_range_mode_message_scan_uses_two_dot_semantics(tmp_path):
    """`git log A...B` 是**对称差**，会把只在 A 上、这次根本不会被 push 的提交也扫进来。

    那些 message 早就在远端了，报出来是与本次 push 无关的噪音——保证命中的噪音就是
    `--allow-hits` 跑步机。所以 message 必须按两点（`A..B` = 这次真会推过去的那批）扫。
    带 positive control：先证明对称差里**确实**有那个 secret，clean 才有意义。
    """
    repo = _repo(tmp_path)
    base = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo,
                          check=True, capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "checkout", "-q", "-b", "other"], cwd=repo, check=True,
                   capture_output=True)
    _commit(repo, "wip: AKIAIOSFODNN7EXAMPLE\n", name="other.txt", body="x\n")
    subprocess.run(["git", "checkout", "-q", base], cwd=repo, check=True,
                   capture_output=True)
    _commit(repo, "feat: harmless\n", body="hello\n")

    symmetric = subprocess.run(["git", "log", "--format=%B", "other...HEAD", "--"],
                               cwd=repo, check=True, capture_output=True, text=True).stdout
    assert "AKIAIOSFODNN7EXAMPLE" in symmetric, "positive control 失效：对称差里没有那条提交"

    r = _scan(repo, "--range", "other...HEAD")
    assert r.returncode == 0, (
        "扫到了只在 other 分支上、这次不会被 push 的提交信息（log 用成三点了）：\n"
        f"{r.stderr}")


def test_range_mode_rejects_a_non_range_ref(tmp_path):
    """`--range HEAD` 这种单个 ref 不是提交区间（`git log <ref>` 会列出整条历史）。

    **必须显式拒绝、不能静默跳过 message 扫描**——"某个来源根本没被扫却报 clean"就是
    本轮要修的那个洞，换个入口再犯一次一样是洞。
    """
    repo = _repo(tmp_path)
    r = _scan(repo, "--range", "HEAD")
    assert r.returncode == 2, f"非区间的 --range 必须拒绝放行：rc={r.returncode}\n{r.stdout}{r.stderr}"
    assert "提交区间" in r.stderr


# message 预处理也必须 fail-closed。上面那个"永远失败"的假 awk 只打得中第一步
# （strip_added_lines），证明不了第二步（noreply 豁免那道 awk）失败时会不会 fail-open。
def _fake_awk_failing_on_nth(tmp_path: Path, n: int) -> str:
    real = shutil.which("awk")
    assert real, "环境里没有 awk"
    d = tmp_path / "fakebin-nth"
    d.mkdir()
    counter = d / "count"
    (d / "awk").write_text(
        "#!/bin/sh\n"
        f'c="{counter}"\n'
        'n=$(cat "$c" 2>/dev/null || echo 0)\n'
        'n=$((n+1))\n'
        'printf %s "$n" > "$c"\n'
        f'[ "$n" -ne {n} ] || exit 2\n'
        f'exec {real} "$@"\n',
        encoding="utf-8")
    (d / "awk").chmod(0o755)
    return f"{d}:{os.environ['PATH']}"


def test_commit_message_preprocessor_failure_refuses_to_pass(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "chore: AKIAIOSFODNN7EXAMPLE\n")
    env = dict(os.environ, PATH=_fake_awk_failing_on_nth(tmp_path, 2))
    r = subprocess.run(["bash", str(SCRIPT), "--range", "HEAD~1...HEAD"], cwd=repo,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2, (
        f"message 预处理失败却放行了（rc={r.returncode}）——那是 fail-open\n{r.stdout}{r.stderr}")
    assert "commit message 预处理失败" in r.stderr


def test_grep_error_still_refuses_to_pass_from_inside_the_scan_helper(tmp_path):
    """grep 的"≥2 是出错、不是无命中"那道检查现在住在 `scan` 函数里。

    **这条不是本轮的回归用例**（改动前那道检查是内联的，一样 exit 2），它守的是重构本身：
    哪天有人把 `scan` 写成 `$(scan …)` 或 `scan … | …`，里面的 `exit 2` 就只杀得掉子 shell，
    主流程会带着"没命中"走完 → 报 clean。已用"把 scan 挪进子 shell"的变异确认这条会红。
    """
    repo = _repo(tmp_path)
    _commit(repo, "chore: AKIAIOSFODNN7EXAMPLE\n")
    d = tmp_path / "fakegrep"
    d.mkdir()
    (d / "grep").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    (d / "grep").chmod(0o755)
    env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
    r = subprocess.run(["bash", str(SCRIPT), "--range", "HEAD~1...HEAD"], cwd=repo,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2, f"grep 出错却放行了（rc={r.returncode}）\n{r.stdout}{r.stderr}"
    assert "clean" not in r.stdout
    assert "grep 执行出错" in r.stderr
