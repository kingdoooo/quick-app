"""扫描器抑制标注的形态守卫（ProbeScan：semgrep / bandit / gitleaks）。

ProbeScan 跑的是**默认行为**的 semgrep（认 `nosemgrep`）、bandit（认 `# nosec`）与
`gitleaks detect`（git 历史模式，认仓库根的 `.gitleaksignore`）。抑制标注写错的代价不对称：

- `nosemgrep:` 后面的规则 ID 按 `[^\\s,]+` 切——ID 后面紧跟全角括号之类的字符会被吞进 ID，
  semgrep 报 `Malformed_rule_ID` 然后**整次扫描以 exit 2 中止**（本地实测：这不是"这一条没压住"，
  是整个 semgrep 作业没结果）。
- 每条抑制都必须带理由（` —— ` 之后），否则下一个人无法判断它是否还成立。
- `.gitleaksignore` 里的每一行要么是注释、要么是完整指纹 `提交:文件:规则:行`，且提交真在历史里。
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[3]
# semgrep 1.58 的行内抑制语法：`nosemgrep` 前面必须有空白，`:` 之后可有一个空白，
# 之后是逗号分隔的 ID 列表（每个 ID 取到下一个空白或逗号为止）
_NOSEM_RE = re.compile(r"(?:^|\s)nosem(?:grep)?(?::\s?(?P<ids>[^\s,]+(?:\s*,\s*[^\s,]+)*))?(?P<rest>.*)$")
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*$")
_FINGERPRINT_RE = re.compile(r"^(?P<commit>[0-9a-f]{40}):(?P<file>[^:]+):(?P<rule>[a-z0-9\-]+):(?P<line>\d+)$")


def _tracked_text_files() -> list:
    r = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True)
    out = []
    for rel in r.stdout.split("\0"):
        if rel and rel.endswith((".py", ".js", ".md", ".sh", ".yml", ".yaml", ".html", ".json")):
            out.append(rel)
    assert len(out) > 100, "git ls-files 结果过少——本条空转"
    return out


def _nosem_problems(line: str) -> list:
    m = _NOSEM_RE.search(line)
    if not m:
        return []
    problems = []
    ids = m.group("ids")
    if not ids:
        problems.append("没写规则 ID（裸 nosemgrep 会压掉这一行将来的所有发现）")
    else:
        for rid in re.split(r"\s*,\s*", ids):
            if not _RULE_ID_RE.match(rid):
                problems.append(f"规则 ID 形态不对（semgrep 会整次中止）：{rid!r}")
    if "——" not in (m.group("rest") or ""):
        problems.append("没写理由（ID 之后用 ` —— 理由`）")
    return problems


def test_every_nosemgrep_annotation_is_well_formed_and_justified():
    offenders, seen = [], 0
    for rel in _tracked_text_files():
        if rel == "site-builder/deployer/tests/test_scanner_suppressions.py":
            continue
        for i, line in enumerate((ROOT / rel).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "nosemgrep" not in line:
                continue
            seen += 1
            offenders += [f"{rel}:{i} {p}" for p in _nosem_problems(line)]
    assert seen >= 40, f"只扫到 {seen} 处 nosemgrep——提取规则坏了或标注被删了，本条空转"
    assert not offenders, "nosemgrep 标注有问题：\n  " + "\n  ".join(offenders)


def test_nosem_checker_catches_the_forms_that_break_or_hide_things():
    assert _nosem_problems("time.sleep(5)  # nosemgrep: arbitrary-sleep（轮询间隔）")  # 全角括号吞进 ID
    assert _nosem_problems("time.sleep(5)  # nosemgrep")                            # 裸抑制
    assert _nosem_problems("time.sleep(5)  # nosemgrep: arbitrary-sleep")           # 没理由
    assert not _nosem_problems("time.sleep(5)  # nosemgrep: arbitrary-sleep —— 轮询间隔")
    assert not _nosem_problems("x  // nosemgrep: insecure-innerhtml, insecure-document-method —— 已 esc")
    assert not _nosem_problems("print('没有抑制标注的普通行')")


def test_gitleaksignore_lines_are_real_fingerprints_from_history():
    lines = (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
    entries = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    assert entries, ".gitleaksignore 里一条指纹都没有——本条空转"
    for ln in entries:
        m = _FINGERPRINT_RE.match(ln)
        assert m, f"不是完整指纹（提交:文件:规则:行）：{ln}"
        r = subprocess.run(["git", "cat-file", "-e", m["commit"] + "^{commit}"], cwd=ROOT)
        assert r.returncode == 0, f"指纹里的提交不在历史里（指纹失效，那条发现会重新冒出来）：{ln}"
