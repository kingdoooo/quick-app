#!/usr/bin/env bash
# 在**锁定依赖**下跑 MCP 测试。
#
# 为什么需要它：`python3 -m pytest tests -q` 用的是宿主机 site-packages
# （实测 mcp 1.26.0 / boto3 1.43.25），而容器锁定的是 requirements.txt 里的
# 版本（1.29.0 / 1.43.64）。"宿主机全绿"证明不了"容器里也全绿"——lock 更新后
# 这个缺口会让 CI 继续测旧依赖，而部署出去的是新依赖。
#
# 用 --require-hashes 安装，与 Dockerfile 完全同一份清单同一套校验。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${1:-/tmp/sb-mcp-locked-venv}"
PY="${PYTHON:-python3.13}"        # 与 Dockerfile 基础镜像一致
command -v "$PY" >/dev/null || { echo "找不到 $PY（Dockerfile 基础镜像是 3.13，版本不一致时解析出的依赖集合可能不同）"; exit 1; }

# **venv 复用必须凭指纹，不能凭"pytest 存在"**：旧 venv 里有可执行 pytest
# 不代表它装的是当前 lock 的版本——那样"锁定测试"会在旧依赖下全绿（实测过：
# 宿主 mcp 1.26.0 的 venv 被复用后自称 locked 且 88 passed），恰好是本脚本
# 声称要关闭的测试漂移。指纹 = requirements.txt 内容 + Python 解释器版本，
# 任一变化都整个 --clear 重建（不做增量修补——修补路径无法证明等价于全新安装）。
STAMP_FILE="$VENV/.lock-stamp"
STAMP="$({ cat "$HERE/requirements.txt"; "$PY" -c 'import sys; print(sys.version)'; } | "$PY" -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
if [ ! -f "$STAMP_FILE" ] || [ "$(cat "$STAMP_FILE")" != "$STAMP" ]; then
  "$PY" -m venv --clear "$VENV"
  "$VENV/bin/pip" install --quiet --require-hashes -r "$HERE/requirements.txt"
  # 测试框架与 moto 不进生产镜像（故不在 requirements.txt 里），单独装。
  # -c 用 lock 当 constraints：pytest/moto 的依赖解析**不得升级**任何已锁定
  # 的运行依赖（否则跑测试的 boto3 又不是容器里那个了）。
  # constraints 必须去掉 hash：pip 见到带 hash 的 constraints 会对本次安装
  # 隐式启用 --require-hashes，而 pytest/moto 不在 lock 里、没有 hash，
  # 直接安装失败。版本钉住即可——完整性由上面 --require-hashes 那步保证。
  # lock 由 pip-compile --strip-extras 生成，包名不含 extras 方括号
  CONSTRAINTS="$VENV/.constraints.txt"
  grep -oE '^[A-Za-z0-9_.-]+==[^ ]+' "$HERE/requirements.txt" | sed 's/ *\\$//' > "$CONSTRAINTS"
  "$VENV/bin/pip" install --quiet -c "$CONSTRAINTS" pytest "moto[dynamodb,s3]>=5"
  printf '%s' "$STAMP" > "$STAMP_FILE"
fi

# 安装后的最终防线：程序化比对 venv 里所有 lock 声明的包版本。指纹能挡住
# "lock 变了但 venv 没变"，挡不住"venv 被手工动过/安装静默出偏差"——比对不
# 一致必须非零退出，不能只打印一行版本号靠人眼看。
"$VENV/bin/python" - "$HERE/requirements.txt" <<'EOF'
import importlib.metadata as m, re, sys
mismatch = []
for line in open(sys.argv[1]):
    spec = line.split("#")[0].split(";")[0].strip().rstrip("\\").strip()
    got = re.match(r"([A-Za-z0-9_.\[\]-]+)==(\S+)", spec)
    if not got:
        continue
    name, want = re.sub(r"\[.*\]", "", got.group(1)), got.group(2)
    try:
        have = m.version(name)
    except m.PackageNotFoundError:
        have = "<未安装>"
    if have != want:
        mismatch.append(f"  {name}: 装的是 {have}, lock 要求 {want}")
if mismatch:
    sys.exit("venv 与 lock 不一致（重跑前先删掉 venv）：\n" + "\n".join(mismatch))
print("locked mcp:", m.version("mcp"), "| boto3:", m.version("boto3"))
EOF

cd "$HERE" && "$VENV/bin/pytest" tests -q
