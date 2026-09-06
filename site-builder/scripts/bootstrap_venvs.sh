#!/usr/bin/env bash
# 一条命令建齐本仓库的五个 venv —— CLAUDE.md「仓库外的几样东西」第 2 步的脚本化。
#
# 用法（从仓库任意位置跑都行，路径按脚本自身定位）：
#   bash site-builder/scripts/bootstrap_venvs.sh                         # 五个全部 --clear 重建
#   bash site-builder/scripts/bootstrap_venvs.sh --only site-builder/deployer   # 只重建一个（可重复给）
#   bash site-builder/scripts/bootstrap_venvs.sh --host-deps             # 顺带做第 3 步：给不带路径的
#                                                                        #   python3 装 boto3 + pip-system-certs
#                                                                        #   （改的是机器不是仓库，默认不做）
#   bash site-builder/scripts/bootstrap_venvs.sh --check                 # 只做前置检查，不建 venv
#
# 三条纪律（都在 CLAUDE.md 里，这里只是让脚本替人记住）：
#   ① 每个 venv 都 `python3.12 -m venv --clear` 重建。shebang 是绝对路径，仓库被移动/克隆到新路径、
#      或另开一个 worktree 之后旧 venv 一直 bad interpreter，**不带 --clear 不会重写**，重跑也修不了。
#   ② 两份 requirements-dev.txt 里的 `-e .` / `-e ../contract` 按**进程 cwd** 解析，不按文件位置，
#      所以每个 venv 都在自己的目录里装（build_one 先 cd 再装）。
#   ③ 五个都用 python3.12。python3.13 只给 mcp/run_locked_tests.sh（与容器基础镜像一致），那个脚本
#      自建 venv、自己会报缺解释器，这里缺 3.13 只警告。
#
# 表里的路径与清单**从 CLAUDE.md 那张表抄**，deployer/tests/test_bootstrap_venvs.py 按那张表核对；
# 改一边必须改另一边。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY=python3.12          # 五个 venv 的母解释器
PY_LOCKED=python3.13   # 只给 site-builder/mcp/run_locked_tests.sh
STAMP="$ROOT/.venv-bootstrap.stamp"   # 全量成功后写；worktree 自动化可以等它出现再开工（gitignored）

# "目录|清单"，与 CLAUDE.md「仓库外的几样东西」第 2 步的表逐行对应
VENVS=(
  "router/infrastructure|requirements.txt"
  "site-builder/contract|requirements-dev.txt"
  "site-builder/deployer|requirements-dev.txt"
  "site-builder/deployer/infra|requirements.txt"
  "site-builder/mcp|requirements.txt"
)

usage() {
  cat <<EOF
用法: bash site-builder/scripts/bootstrap_venvs.sh [--only <目录>]... [--host-deps] [--check]

  --only <目录>   只重建这一个 venv（目录相对仓库根，如 site-builder/deployer；可重复）
  --host-deps     顺带给不带路径的 python3 装 boto3 + pip-system-certs（--user；改机器不改仓库）
  --check         只做前置检查（python3.12 / python3.13 / python3 >= 3.10），不建 venv
  -h, --help      本说明

五个 venv（目录 -> 清单）：
EOF
  local entry
  for entry in "${VENVS[@]}"; do
    printf '  %-30s %s\n' "${entry%%|*}/.venv" "${entry#*|}"
  done
}

die() { echo "bootstrap_venvs: $*" >&2; exit 1; }
add_only() { local d="${1%/}"; ONLY+=("${d%/.venv}"); }   # 接受 dir、dir/ 与 dir/.venv 三种写法

HOST_DEPS=0
CHECK_ONLY=0
ONLY=()
while [ $# -gt 0 ]; do
  case "$1" in
    --host-deps) HOST_DEPS=1 ;;
    --check) CHECK_ONLY=1 ;;
    --only)
      shift
      [ $# -gt 0 ] || { echo "bootstrap_venvs: --only 后面要跟目录" >&2; exit 2; }
      add_only "$1"
      ;;
    --only=*) add_only "${1#--only=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "bootstrap_venvs: 未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [ "$CHECK_ONLY" = 1 ] && [ "$HOST_DEPS" = 1 ]; then
  echo "bootstrap_venvs: --check 与 --host-deps 互斥（--check 什么都不装）" >&2; exit 2
fi

# ── 前置检查 ────────────────────────────────────────────────────────────────────
command -v "$PY" >/dev/null 2>&1 \
  || die "找不到 ${PY}（五个 venv 的母解释器）。macOS: brew install python@3.12；其它平台装一个 3.12 并放进 PATH"

if command -v "$PY_LOCKED" >/dev/null 2>&1; then
  echo "bootstrap_venvs: ${PY_LOCKED} 就位（$("$PY_LOCKED" --version 2>&1)）"
else
  echo "bootstrap_venvs: 警告——找不到 ${PY_LOCKED}。只影响 site-builder/mcp/run_locked_tests.sh（与容器基础镜像同版本，它自己会再报），本脚本继续" >&2
fi

command -v python3 >/dev/null 2>&1 || die "找不到不带路径的 python3（scripts/*.py 与真机闸门都用它跑）"
PY3_VER="$(python3 --version 2>&1 | awk '{print $2}')"
IFS=. read -r PY3_MAJ PY3_MIN _ <<<"$PY3_VER"
if [ "${PY3_MAJ:-0}" -lt 3 ] || { [ "${PY3_MAJ:-0}" -eq 3 ] && [ "${PY3_MIN:-0}" -lt 10 ]; }; then
  cat >&2 <<EOF
bootstrap_venvs: 不带路径的 python3 是 ${PY3_VER}，本仓库 scripts/*.py（含 verify_* 闸门）要求 >= 3.10
  （一批脚本用了 \`X | None\` 标注却没写 from __future__ import annotations，3.9 上函数定义那一刻就 TypeError；
   macOS 自带的 /usr/bin/python3 是 3.9，brew install python@3.12 又不提供 python3 这个名字）。
两层解法任选或都做（CLAUDE.md「仓库外的几样东西」第 0 步）：
  ① ~/.zshenv 里前置（必须是 .zshenv 不是 .zshrc：脚本、编辑器/Agent 起的非交互 shell 只读前者）：
       export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:\$PATH"
  ② 或两个软链（与 shell 无关；将来 brew install python 报 symlink 冲突时删掉即可）：
       ln -s /opt/homebrew/opt/python@3.12/libexec/bin/python3 /opt/homebrew/bin/python3
       ln -s /opt/homebrew/opt/python@3.12/libexec/bin/pip3    /opt/homebrew/bin/pip3
EOF
  exit 1
fi
echo "bootstrap_venvs: python3 = ${PY3_VER}，${PY} = $("$PY" --version 2>&1 | awk '{print $2}')"

# ── 选择要建的 venv ─────────────────────────────────────────────────────────────
SELECTED=()
if [ "${#ONLY[@]}" -eq 0 ]; then
  SELECTED=("${VENVS[@]}")
else
  for want in "${ONLY[@]}"; do
    hit=""
    for entry in "${VENVS[@]}"; do
      [ "${entry%%|*}" = "$want" ] && hit="$entry"
    done
    [ -n "$hit" ] || die "--only ${want} 不在表里。合法目录：$(printf ' %s' "${VENVS[@]%%|*}")"
    SELECTED+=("$hit")
  done
fi

if [ "$CHECK_ONLY" = 1 ]; then
  echo "bootstrap_venvs: 前置检查通过（--check，不建 venv）"
  exit 0
fi

# ── 建 venv ─────────────────────────────────────────────────────────────────────
build_one() {   # build_one <目录> <清单>
  local dir="$1" manifest="$2" t0 t1
  [ -f "$ROOT/$dir/$manifest" ] || die "缺清单 $dir/$manifest（表与仓库不一致？）"
  t0=$(date +%s)
  echo "==> $dir/.venv  <-  $manifest"
  (
    cd "$ROOT/$dir"          # -e 的相对路径按进程 cwd 解析：必须先进目录再装
    "$PY" -m venv --clear .venv
    .venv/bin/pip install --quiet --disable-pip-version-check -r "$manifest"
  )
  t1=$(date +%s)
  echo "    完成 $((t1 - t0))s"
}

# 全量模式先删旧标记：重跑中途失败时，不能让上一次的成功标记继续骗等待它的自动化
[ "${#ONLY[@]}" -eq 0 ] && rm -f "$STAMP"

T_ALL0=$(date +%s)
for entry in "${SELECTED[@]}"; do
  build_one "${entry%%|*}" "${entry#*|}"
done

if [ "$HOST_DEPS" = 1 ]; then
  echo "==> python3 (${PY3_VER}) 上装 boto3 + pip-system-certs（--user，只写 user site）"
  python3 -m pip install --user --break-system-packages boto3 pip-system-certs
fi

# ── 证据：每个 venv 的解释器版本与 pytest ────────────────────────────────────────
echo "== 结果"
for entry in "${SELECTED[@]}"; do
  dir="${entry%%|*}"
  venv="$ROOT/$dir/.venv"
  ver="$("$venv/bin/python" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
  if [ -x "$venv/bin/pytest" ]; then
    pt="$("$venv/bin/pytest" --version 2>&1 | head -n 1)"
  else
    pt="(无 pytest——按 CLAUDE.md「测试命令」借别的 venv)"
  fi
  printf '  %-30s python %-8s %s\n' "$dir/.venv" "$ver" "$pt"
done
T_ALL1=$(date +%s)
echo "== 总耗时 $((T_ALL1 - T_ALL0))s"

if [ "${#ONLY[@]}" -eq 0 ]; then
  printf '%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$("$PY" --version 2>&1)" "${#SELECTED[@]} venvs" > "$STAMP"
  echo "== 已写 ${STAMP#"$ROOT"/}（全量成功的标记；自动化可等它出现再开工）"
fi
