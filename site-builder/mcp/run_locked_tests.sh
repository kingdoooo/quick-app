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
[ -x "$VENV/bin/pytest" ] || {
  "$PY" -m venv --clear "$VENV"
  "$VENV/bin/pip" install --quiet --require-hashes -r "$HERE/requirements.txt"
  # 测试框架与 moto 不进生产镜像（故不在 requirements.txt 里），单独装。
  # 不带 --require-hashes：它们不是运行时依赖，不构成 TCB 的一部分。
  "$VENV/bin/pip" install --quiet pytest "moto[dynamodb,s3]>=5"
}
"$VENV/bin/python" -c "import importlib.metadata as m; print('locked mcp:', m.version('mcp'), '| boto3:', m.version('boto3'))"
cd "$HERE" && "$VENV/bin/pytest" tests -q
