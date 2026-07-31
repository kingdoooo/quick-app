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

case "$mode" in
  staged)
    if git diff --cached --quiet 2>/dev/null; then
      echo "⚠️  stage 是空的——先 git add，否则这次扫描什么都没看（见脚本头注释）" >&2
      exit 2
    fi
    subject="staged diff"
    hits="$(git diff --cached | grep -nE "$PATTERN")" ;;
  range)
    subject="range $range"
    hits="$(git diff "$range" | grep -nE "$PATTERN")" ;;
  files)
    if [ "${#files[@]}" -eq 0 ]; then echo "--files 需要至少一个路径" >&2; exit 2; fi
    subject="files ${files[*]}"
    hits="$(grep -nE "$PATTERN" "${files[@]}")" ;;
esac

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
