# AgentCore Runtime 跑在 ARM64（Graviton）——必须钉平台，否则容器起不来
# （x86 上不钉会构出 amd64 镜像，运行时报 exec format error）。
#
# **基础镜像钉 digest，不钉 tag**：本容器里的代码对"站点归属"而言是 TCB
# （见 deploy_agentcore.py 里 SitesWrite 的注释）——`python:3.13-slim` 这个 tag
# 上游随时会重新指向新镜像，那等于 TCB 在无人察觉时被换掉，且历史构建不可复现。
# 下面是 linux/arm64 的 manifest digest（2026-08-05 解析）。
# 升级基础镜像时用这条命令重新解析，并在提交里说明为什么升：
#   docker manifest inspect public.ecr.aws/docker/library/python:3.13-slim \
#     | python3 -c 'import json,sys; [print(m["digest"]) for m in \
#       json.load(sys.stdin)["manifests"] if m["platform"]["architecture"]=="arm64"]'
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.13-slim@sha256:8c5de2243cba89f49a93e05cacb78e27058bcaa69c148baac127005da03af39e

WORKDIR /app

COPY requirements.txt ./
# --require-hashes 由 requirements.txt 里的 --hash 触发：任何依赖（含传递依赖）
# 少了 hash 或对不上，pip 直接失败，而不是装一个被替换过的包。
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# server.py 与 common.py（deploy_agentcore.py 从 deployer/functions/ 复制进构建
# 上下文）必须同目录：server.py 按同目录解析 common。
COPY server.py common.py permissions.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# AgentCore 契约：0.0.0.0:8000，POST /mcp
EXPOSE 8000

CMD ["python", "server.py"]
