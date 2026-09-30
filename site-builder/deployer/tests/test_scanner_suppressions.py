r"""扫描器抑制标注的形态守卫（ProbeScan：semgrep / bandit / gitleaks）。

**本文件的书写约定**：抑制 token（短别名 `#nosem`、长形态 `#nosemgrep`）在这里**一律紧跟
注释符写、前面不留空白**，样例行则在运行期用 `_N` / `_NG` 拼出来。真实标注是「空白 + token」，
而 semgrep 只认那一种；写成 `#nosem` 就既能说清形态、又不会让本文件自己变成一堆真抑制。
为什么非要这样：见下面第 1 条与 `test_this_file_itself_carries_no_literal_suppression_token`。

ProbeScan 跑的是**默认行为**的 semgrep、bandit（认 `#nosec`）与 `gitleaks detect`
（git 历史模式，认仓库根的 `.gitleaksignore`）。抑制标注写错的代价不对称：

- 规则 ID 按 `[^\s,]+` 切——ID 后面紧跟全角括号、闭引号之类的字符会被吞进 ID，semgrep 报
  `Malformed_rule_ID` 然后**整次扫描以 exit 2 中止**（本地实测：这不是"这一条没压住"，
  是整个 semgrep 作业没结果）。
- 每条抑制都必须带**非空**理由（` —— ` 之后），否则下一个人无法判断它是否还成立。
- `.gitleaksignore` 里的每一行要么是注释、要么是完整指纹 `提交:文件:规则:行`，且该提交
  **在扫描覆盖的历史里可达**。

**五条实测过的陷阱**（1–4 由 Codex R1 复审逐条构造反例证明原版会假绿/假红；5 是修 1–4
时连带坐实的、原版自己的洞）：

1. 短别名与长形态等价、**大小写不敏感**、而且 token 后面**紧跟别的字母也算**
   （实测 `#nosem` + `i` 同样压掉发现）。只找字面量小写长形态、且大小写敏感的前置过滤，
   会让这几种裸抑制整条绕过本守卫——而它们压掉的是该行的**全部**规则。
2. 抑制能生效的文件**不止编程语言后缀**：`detected-jwt-token` 是 `languages: [regex]`，
   tracked 的 `config.ini.example` 同样被扫、同样能被抑制压住。所以候选集是"全部 tracked
   文本文件"，不是一张后缀白名单。
3. 只检查分隔符存在 ⇒ 理由位置只写一个 ` —— ` 的**空理由**能过。
4. `git cat-file -e` 只证明"对象还在库里"：rebase 之后被丢掉的悬空提交在 GC 前照样能找到，
   而 `--depth 1` 浅克隆里**完整历史缺失**会把好指纹报成失效。可达性要用
   `merge-base --is-ancestor`，历史不足要显式跳过而不是报红。
5. 原版把本文件整个排除在被审集合之外（它的样例行里有故意写坏的形态），于是**唯一不受
   这条政策约束的文件就是政策本身所在的文件**。代价是实测出来的：a5a5849 的这份文件
   单独扫时 semgrep **exit 2、scanned 0**（样例里的 ID 吃到了闭引号），放进整仓扫描则降级
   成 warn + 该文件"仅部分分析"⇒ 这个文件里的发现被静默漏掉。现在样例改成运行期拼，
   排除项随之取消。

实测矩阵（semgrep 1.58.0 + rules@95ac7231，单文件逐行验证）：裸短别名 / 全大写 /
混合大小写带 ID / token 后紧跟字母 / 行内任意位置的裸 token，全部压掉该行**所有**规则；
`#nosemgrep: <id> —— 理由`、`#nosemgrep: <id1>, <id2> —— 理由`、`#nosemgrep=<id>` 只压指定
规则；`#nosemgrep: <不存在的 id> —— 理由` 照报。
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[3]

# semgrep 1.58 的行内抑制语法（**按实测**，不按 `semgrep/constants.py`——1.58 的抑制判定
# 在 semgrep-core 里，那份 Python 常量只用来给报告剥注释）：token 前面要有空白、大小写
# 不敏感、短别名与长形态等价、ID 列表前的分隔符是 `:` **或** `=`，ID 取到下一个空白或逗号
# 为止（所以 ID 之后可以跟 ` —— 理由` 而不影响定向抑制）。矩阵见模块 docstring 末尾。
# ⇒ 「token 后面紧跟别的字母」不是安全的普通英文词，而是一条**裸抑制**，必须报。
# 前缀用 `\s` 捕获（Python 的 `\s` 含 TAB、NBSP、全角空格），再单独判它是不是 **ASCII 空格**：
# semgrep 只认 ASCII 空格（R2 复审的单文件矩阵：TAB / NBSP / 全角空白前缀一律**不生效**，
# 该行照报 ERROR）。所以非 ASCII 空格前缀不是"藏起来的抑制"，而是"以为压住了、其实没压住"——
# 方向相反，但同样要报。
# 分隔符写成 `(?::|=)` 而**不是**字符类 `[:=]`：semgrep 1.58 的 ReDoS 分析器会把 `[:` 当成
# POSIX 字符类（`[:alpha:]`）的起始，词法失败（`Failure: lexing: empty token`）⇒ 本文件被标成
# "only partially analyzed"、里面的发现被静默漏掉（Codex R2 发现，最小复现：两段代码
# ——`re.compile(<含 [:=] 的正则>)` 加同文件对它的 `.search()`；`[=:]` 与 `(?::|=)` 都不触发）。
_NOSEM_RE = re.compile(
    r"(?P<pre>\s)nosem(?:grep)?(?:(?::|=)\s?(?P<ids>[^\s,]+(?:\s*,\s*[^\s,]+)*))?(?P<rest>.*)$",
    re.IGNORECASE)
# 候选行的前置过滤必须与上面同源（同样认短别名、同样不分大小写、同样不要求词尾、同样的前缀集合）
_NOSEM_HINT_RE = re.compile(r"\snosem", re.IGNORECASE)
# 规则 ID 是 ASCII token：字母数字起头，后面可带 `.`（semgrep 的完整点分 ID）、`_`、`-`
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_FINGERPRINT_RE = re.compile(r"^(?P<commit>[0-9a-f]{40}):(?P<file>[^:]+):(?P<rule>[a-z0-9\-]+):(?P<line>\d+)$")
# 理由后面跟着的注释闭合符不算理由内容
_COMMENT_CLOSERS = ("*/", "-->", "--}}", "}}", "#}", "]]>")
# 二进制不进候选集（当前仓库一个都没有，留着是为了将来加了也不会炸）
_BINARY_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
                    ".tgz", ".whl", ".woff", ".woff2", ".ttf", ".eot", ".so",
                    ".dylib", ".jar", ".class", ".der", ".p12")
# 文件选择的正对照：这几个 tracked 文件必须在候选集里，否则"选择口径"悄悄缩了
# （前三个真的带着抑制标注；后四个是曾被后缀白名单漏掉的那一类）
_MUST_BE_CANDIDATES = (
    "site-builder/panel/frontend/app.js",
    "router/infrastructure/stack.py",
    "docs/superpowers/plans/2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover.md",
    "site-builder/config.ini.example",
    "router/config.ini.example",
    "site-builder/mcp/Dockerfile",
    "site-builder/contract/pyproject.toml",
)


def _git(*args, cwd=None) -> subprocess.CompletedProcess:
    """跑 git。**剥掉 GIT_DIR 之类的继承环境**——带着它时 `cwd=` 会被无声忽略，
    于是元用例里的临时仓库会去查主仓库的历史（那正好让断言假绿）。"""
    env = {k: v for k, v in os.environ.items()
           if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
    return subprocess.run(["git", *args], cwd=cwd or ROOT, env=env,
                          capture_output=True, text=True)


def _tracked_text_files() -> list:
    """全部 tracked 文本文件。

    **不是后缀白名单**：`detected-jwt-token` 这类 `languages: [regex]` 的规则对
    `config.ini.example`、Dockerfile、`pyproject.toml` 一样生效，行内抑制在那里一样管用。
    """
    r = _git("ls-files", "-z")
    assert r.returncode == 0, f"git ls-files 失败：{r.stderr}"
    out = []
    for rel in r.stdout.split("\0"):
        if not rel or rel.lower().endswith(_BINARY_SUFFIXES):
            continue
        try:
            (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue      # 二进制或读不到：扫描器也拿不到行内抑制
        out.append(rel)
    assert len(out) > 100, f"git ls-files 结果过少（{len(out)}）——本条空转"
    missing = [p for p in _MUST_BE_CANDIDATES if p not in out]
    assert not missing, f"文件选择漏了这些 tracked 文件（抑制标注放进去就不受检）：{missing}"
    return out


def _nosem_problems(line: str) -> list:
    m = _NOSEM_RE.search(line)
    if not m:
        return []
    problems = []
    if m.group("pre") != " ":
        problems.append(f"token 前缀是 {m.group('pre')!r} 不是 ASCII 空格（semgrep 不认，这条抑制不生效）")
    ids = m.group("ids")
    if not ids:
        problems.append("没写规则 ID（裸抑制会压掉这一行将来的所有发现）")
    else:
        for rid in re.split(r"\s*,\s*", ids):
            if not _RULE_ID_RE.match(rid):
                problems.append(f"规则 ID 形态不对（semgrep 会整次中止）：{rid!r}")
    rest = m.group("rest") or ""
    if "——" not in rest:
        problems.append("没写理由（ID 之后用 ` —— 理由`）")
    else:
        why = rest.split("——", 1)[1]
        for closer in _COMMENT_CLOSERS:
            why = why.replace(closer, " ")
        if not why.strip():
            problems.append("理由是空的（只写了分隔符）")
    return problems


def test_every_nosemgrep_annotation_is_well_formed_and_justified():
    offenders, seen = [], 0
    for rel in _tracked_text_files():
        for i, line in enumerate((ROOT / rel).read_text(encoding="utf-8",
                                                        errors="replace").splitlines(), 1):
            if not _NOSEM_HINT_RE.search(line):
                continue
            seen += 1
            offenders += [f"{rel}:{i} {p}" for p in _nosem_problems(line)]
    assert seen >= 40, f"只扫到 {seen} 处抑制标注——提取规则坏了或标注被删了，本条空转"
    assert not offenders, "抑制标注有问题：\n  " + "\n  ".join(offenders)


# 样例行里的抑制 token **在运行期拼**，不留字面量。
# 理由不是洁癖：样例写成字面量时，ID 按 `[^\s,]+` 会一直吃到**闭引号**
# ⇒ `Malformed_rule_ID`。实测（a5a5849 的这份文件单独扫）：
# semgrep **exit 2、scanned 0**；放在整仓扫描里则降级成 warn + 该文件"仅部分分析"，
# 于是这个文件里的发现会被静默漏掉。原版靠"扫描时跳过本文件"绕开自检，
# 那正好让它自己成了唯一不受这条政策约束的文件。拼出来之后本文件也进被审集合。
_N = "nose" + "m"              # 短别名
_NG = _N + "grep"              # 长形态


def test_nosem_checker_catches_the_forms_that_break_or_hide_things():
    # 形态坏：ID 被吞 / 没 ID / 没理由 / 理由是空的
    assert _nosem_problems(f"time.sleep(5)  # {_NG}: arbitrary-sleep（轮询间隔）")
    assert _nosem_problems(f"time.sleep(5)  # {_NG}")
    assert _nosem_problems(f"time.sleep(5)  # {_NG}: arbitrary-sleep")
    assert _nosem_problems(f"time.sleep(5)  # {_NG}: arbitrary-sleep ——")
    assert _nosem_problems(f"time.sleep(5)  # {_NG}: arbitrary-sleep ——   ")
    assert _nosem_problems(f"x  /* {_NG}: insecure-innerhtml —— */")
    # 短别名与大小写：semgrep 一样认，所以这几种裸抑制也必须被判成问题
    assert _nosem_problems(f"time.sleep(5)  # {_N}")
    assert _nosem_problems(f"time.sleep(5)  # {_NG.upper()}")
    assert _nosem_problems(f"time.sleep(5)  # {_N.capitalize()}: arbitrary-sleep")
    # token 后面紧跟字母同样是裸抑制（实测压掉了发现），别放过
    assert _nosem_problems(f"time.sleep(5)  # {_N}i")
    assert _nosem_problems(f"time.sleep(5)  # 讲 autonomy 的时候提到 {_NG}")
    # 前缀不是 ASCII 空格：semgrep 不认 ⇒ 抑制不生效 ⇒ 也要报（方向与上面相反）
    for pre in ("\t", "\u00a0", "\u3000"):
        assert _nosem_problems(f"time.sleep(5)  #{pre}{_NG}: arbitrary-sleep —— 轮询间隔"), repr(pre)
    # 合格：三种写法 × 有 ID 有理由（含 `=` 分隔符）
    assert not _nosem_problems(f"time.sleep(5)  # {_NG}: arbitrary-sleep —— 轮询间隔")
    assert not _nosem_problems(f"time.sleep(5)  # {_N}: arbitrary-sleep —— 轮询间隔")
    assert not _nosem_problems(f"time.sleep(5)  # {_N.upper()}: arbitrary-sleep —— 轮询间隔")
    assert not _nosem_problems(
        f"x  // {_NG}: insecure-innerhtml, insecure-document-method —— 已 esc")
    assert not _nosem_problems(f"time.sleep(5)  # {_NG}=arbitrary-sleep —— 轮询间隔")
    # 点分的完整 ID（不带 --no-rewrite-rule-ids 时 semgrep 报的就是这种）
    assert not _nosem_problems(
        f"x  # {_NG}: python.lang.security.audit.arbitrary-sleep —— 轮询间隔")
    assert not _nosem_problems("print('没有抑制标注的普通行')")


def test_this_file_itself_carries_no_literal_suppression_token():
    """本文件不许留抑制 token 的字面量（上面那段注释讲了为什么）。

    判据：源码里任何一行都不能有「空白 + 短别名」。样例全部由 `_N` / `_NG` 拼出，
    所以这条既保证扫描器不会在这里踩到畸形 ID，也保证本文件能被上面那条逐行断言审查。
    """
    src = Path(__file__).read_text(encoding="utf-8")
    hits = [f"{i}: {l.strip()[:80]}" for i, l in enumerate(src.splitlines(), 1)
            if _NOSEM_HINT_RE.search(l)]
    assert not hits, "本文件里出现了抑制 token 的字面量：\n  " + "\n  ".join(hits)


def _repo_is_shallow(cwd=None) -> bool:
    return _git("rev-parse", "--is-shallow-repository", cwd=cwd).stdout.strip() == "true"


def _commit_in_scanned_history(commit: str, cwd=None) -> bool:
    """提交在**扫描覆盖的历史里可达**吗（不是"对象还在库里"）。

    gitleaks 以 `detect --log-opts=master` 扫 master 可达的那段历史，所以"指纹还有效"
    的判据是可达性。`git cat-file -e` 只证明对象存在：rebase 丢掉的旧提交在 GC 前照样过。
    """
    return _git("merge-base", "--is-ancestor", commit, "HEAD", cwd=cwd).returncode == 0


def test_gitleaksignore_lines_are_real_fingerprints_from_history():
    lines = (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
    entries = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    assert entries, ".gitleaksignore 里一条指纹都没有——本条空转"
    fps = []
    for ln in entries:
        m = _FINGERPRINT_RE.match(ln)
        assert m, f"不是完整指纹（提交:文件:规则:行）：{ln}"
        fps.append((ln, m["commit"]))

    # 形态查完再查可达性。浅克隆里历史被截断，"查不到"是**历史不足**而不是指纹失效——
    # 原版在 `git clone --depth 1` 的干净树上假红（实测 1 failed / 2 passed）。
    if _repo_is_shallow():
        pytest.skip("浅克隆（--depth）：历史被截断，指纹可达性无法判定——"
                    "要验这一条需要 `git fetch --unshallow`")

    for ln, commit in fps:
        assert _commit_in_scanned_history(commit), (
            f"指纹里的提交不在 HEAD 可达的历史里（被 rebase 掉或从未合入 ⇒ 指纹失效，"
            f"那条发现会重新冒出来）：{ln}")


def _tiny_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", "-b", "main", cwd=path)
    _git("config", "user.email", "t@e2e.invalid", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    return path


def test_history_check_rejects_a_commit_that_only_still_exists_as_an_object(tmp_path):
    """元用例：悬空提交必须被拒。

    这正是原版的假绿——`git cat-file -e` 找得到 rebase 后遗留的对象，于是一条早已
    失效的指纹（对应的行/提交已不在被扫历史里）会被认证成"仍然有效"。
    """
    repo = _tiny_repo(tmp_path / "dangling")
    (repo / "a.txt").write_text("1\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "base", cwd=repo)
    (repo / "a.txt").write_text("2\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "doomed", cwd=repo)
    doomed = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    _git("reset", "-q", "--hard", "HEAD~1", cwd=repo)
    head = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()

    # 正对照：对象确实还在（所以原版那条判据会通过）
    assert _git("cat-file", "-e", doomed + "^{commit}", cwd=repo).returncode == 0
    # 判据必须只认可达
    assert not _commit_in_scanned_history(doomed, cwd=repo), "悬空提交被当成了有效指纹"
    assert _commit_in_scanned_history(head, cwd=repo), "可达的提交被误拒"


def test_shallow_detection_is_true_only_for_a_truncated_clone(tmp_path):
    """元用例：浅/全历史必须分得开，否则上面那条 skip 分支要么不触发、要么永远触发。"""
    src = _tiny_repo(tmp_path / "src")
    for n in ("1", "2"):
        (src / "a.txt").write_text(n + "\n")
        _git("add", ".", cwd=src)
        _git("commit", "-qm", "c" + n, cwd=src)
    dst = tmp_path / "shallow"
    r = _git("clone", "-q", "--depth", "1", f"file://{src}", str(dst))
    assert r.returncode == 0, f"浅克隆没建起来：{r.stderr}"
    assert _repo_is_shallow(cwd=dst), "浅克隆没被认出来 ⇒ 干净 clone 上会假红"
    assert not _repo_is_shallow(cwd=src), "完整历史被当成浅克隆 ⇒ 这一条永远 skip"
    # 刻意**不**断言本仓库不是浅克隆：那不是判据的性质，而是当前 checkout 的状态，
    # 在 `--depth 1` 的干净 clone 上会变成又一条假红（本条第一版就是这么炸的）。
