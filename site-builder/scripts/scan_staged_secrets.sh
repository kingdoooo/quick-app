#!/usr/bin/env bash
# Staged-diff 敏感信息扫描（~/AGENTS.md 的全局提交纪律）。
#
# 为什么要有这个脚本：计划里原先每个提交步骤都内联一条
#   git diff --cached | grep -nE '...' && echo "⚠️ 命中" || echo "clean"
# 这种写法**命中时不会阻断**——`&&` 后面只是 echo，紧跟的 git commit 照常执行。
# 自动化跑整段代码块时，命中敏感信息也会提交出去，正好违反它想遵守的约束。
# 而且各处内联的 regex 互相不一致（漏掉 gho_ / Slack token / 家目录 / 12 位
# 账号 ID 等）。统一到一个脚本：命中即 exit 1，让 `&&` 链自然停在 commit 之前。
#
# 用法（**必须在 git add 之后**——git diff --cached 只看已 stage 的内容，
# 放在 add 之前扫的是空 stage，永远报 clean，等于没扫）：
#
#     git add <files>
#     bash site-builder/scripts/scan_staged_secrets.sh && git commit -m "..."
#
# 未跟踪的新文件在首次 add 前另扫文件本体（git diff 看不到它们）：
#
#     bash site-builder/scripts/scan_staged_secrets.sh --files path/a.py path/b.py
#
# push 前对待推送的 commit 再扫一次：
#
#     bash site-builder/scripts/scan_staged_secrets.sh --range origin/master...HEAD
#
# 命中不等于必须改——公开 URL、测试 fixture、co-author trailer 都会命中。
# 脚本只负责**停下来**；判断交给人。确认是故意的之后用 --allow-hits 放行：
#
#     bash site-builder/scripts/scan_staged_secrets.sh --allow-hits && git commit ...
#
# 本仓库可预期的故意命中：*@x.com 假邮箱、000000000000 占位账号、
# ProbeOnly!2026x 探测口令、botocore Stubber 的 aws_access_key_id="t"、
# config.ini.example 里的空 client_secret =。
# 还有一类天然会整片命中：**本脚本自己的回归测试**
# （`deployer/tests/test_scan_staged_secrets.py`）——它必须写进 AKIAIOSFODNN7EXAMPLE、
# `user+tag@example.com`、`123456789012`、`/Users/someone/`、私钥头这些 fixture，
# 否则"真命中还在"根本证明不了。改那个文件时用 --allow-hits 是预期的。
set -uo pipefail

# 覆盖 ~/AGENTS.md 列出的全部类别（凭证/令牌、个人标识、本机信息、基础设施内部）
PATTERN='AKIA[0-9A-Z]{16}'
PATTERN+='|ASIA[0-9A-Z]{16}'
PATTERN+='|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}'
PATTERN+='|xox[baprs]-[A-Za-z0-9-]{10,}'
PATTERN+='|sk-[A-Za-z0-9_-]{20,}'
PATTERN+='|sk-ant-[A-Za-z0-9_-]{10,}'
PATTERN+='|BEGIN [A-Z ]*PRIVATE KEY'
PATTERN+='|aws_secret_access_key|aws_access_key_id'
PATTERN+='|[Aa]uthorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._-]{16,}'
PATTERN+='|(password|passwd|secret|token)[[:space:]]*[=:][[:space:]]*[^[:space:]"'"'"',)}]{6,}'
PATTERN+='|/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/'
PATTERN+='|[0-9]{12}'
PATTERN+='|vpc-[0-9a-f]{8,}|subnet-[0-9a-f]{8,}'
PATTERN+='|postgres(ql)?://|mysql://|mongodb(\+srv)?://|redis://'
PATTERN+='|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
PATTERN+='|(\+?[0-9]{1,3}[-. ]?)?1[3-9][0-9]{9}'

mode=staged
allow_hits=0
range=""
files=()
while [ $# -gt 0 ]; do
  case "$1" in
    --files) mode=files; shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do files+=("$1"); shift; done ;;
    --range) mode=range; range="${2:?--range 需要一个 git range}"; shift 2 ;;
    --allow-hits) allow_hits=1; shift ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

# diff 模式下**只扫新增行，并先剥掉行首那个 `+`**。
#
# 为什么必须剥：email 规则的 local-part 字符类含 `+`，于是 diff 里的
#   +@pytest.mark.parametrize("label", ...)
# 会被 `+` 与后面的 `pytest.mark.parametrize` 拼成"邮箱"而命中——**任何**新增的
# `@pytest.mark.*` 装饰器都复现（实测）。这类反复出现的假阳性最大的害处不是噪音，
# 而是把人训练成无脑加 `--allow-hits`，那时真命中也会被一起放行。
#
# 顺带缩小范围：不再扫 context 行与 `-` 行。本脚本的主语是"这次**新增**了什么"，
# 而 context/removed 里的内容都是已经在仓库里的——把它们算成"新增泄漏"只会产生
# 与本次改动无关的命中。**这是一次刻意的范围收窄，写在这里以免被当成 bug。**
# `+++ b/path` 是文件头不是内容，也排除（仓库内路径本来就是相对路径）。
strip_added_lines() {
  awk '/^\+\+\+ /{next} /^\+/{print substr($0, 2)}'
}

# 取待扫文本。**必须与 grep 分开做并检查 git 的退出码**：
# 早期版本写成 hits="$(git diff --cached | grep -nE ...)"，git 失败时（不在 git
# 仓库里、--range 给了不存在的 ref）hits 为空 → 报 "clean" → exit 0。
# 那是 fail-open，正是本脚本要消灭的故障模式（实测：仓库外跑 exit=0 "clean"）。
text=""
case "$mode" in
  staged)
    git rev-parse --git-dir >/dev/null 2>&1 || {
      echo "🛑 当前目录不是 git 仓库——无法扫描，拒绝放行" >&2; exit 2; }
    if git diff --cached --quiet; then
      echo "⚠️  stage 是空的——先 git add，否则这次扫描什么都没看（见脚本头注释）" >&2
      exit 2
    fi
    subject="staged diff"
    raw="$(git diff --cached)" || {
      echo "🛑 git diff --cached 失败——无法扫描，拒绝放行" >&2; exit 2; }
    text="$(printf '%s\n' "$raw" | strip_added_lines)" ;;
  range)
    git rev-parse --git-dir >/dev/null 2>&1 || {
      echo "🛑 当前目录不是 git 仓库——无法扫描，拒绝放行" >&2; exit 2; }
    subject="range $range"
    raw="$(git diff "$range")" || {
      echo "🛑 git diff $range 失败（ref 不存在？）——无法扫描，拒绝放行" >&2
      exit 2; }
    text="$(printf '%s\n' "$raw" | strip_added_lines)" ;;
  files)
    if [ "${#files[@]}" -eq 0 ]; then echo "--files 需要至少一个路径" >&2; exit 2; fi
    for f in "${files[@]}"; do
      # ${f} 的花括号是必须的：裸 $f 紧跟中文破折号时，bash 会把多字节字符
      # 并进变量名 → set -u 下 "unbound variable" 崩掉（本脚本已被这个坑咬过
      # 两次：先是 ${subject}，然后是这里）。所有紧跟中文的插值都要加花括号。
      [ -r "$f" ] || { echo "🛑 读不到文件: ${f}——拒绝放行" >&2; exit 2; }
    done
    subject="files ${files[*]}"
    text="$(cat -- "${files[@]}")" || {
      echo "🛑 读取文件失败——拒绝放行" >&2; exit 2; } ;;
esac

# grep 的退出码：0=有命中，1=无命中，≥2=出错。只有 1 才是真正的 clean。
hits="$(printf '%s\n' "$text" | grep -nE "$PATTERN")"
grep_status=$?
if [ "$grep_status" -ge 2 ]; then
  echo "🛑 grep 执行出错（status=${grep_status}）——无法确认，拒绝放行" >&2
  exit 2
fi

if [ -z "$hits" ]; then
  echo "secret scan: clean (${subject})"
  exit 0
fi

# 注意 ${subject} 的花括号：紧跟中文全角括号时，裸 $subject 会被 bash 把多字节
# 字符并进变量名，set -u 下直接 "unbound variable" 退出——命中信息根本不打印。
echo "🛑 secret scan 命中（${subject}）——**已阻断，未提交**：" >&2
echo "$hits" >&2
echo >&2
echo "逐条确认是否为故意的 fixture/占位符/公开 URL。" >&2
echo "确认无误后加 --allow-hits 重跑本脚本再提交；不要自动清洗。" >&2
if [ "$allow_hits" -eq 1 ]; then
  echo "（--allow-hits 已指定：视为已人工确认，放行）" >&2
  exit 0
fi
exit 1
