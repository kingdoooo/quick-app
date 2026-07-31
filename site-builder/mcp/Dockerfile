# AgentCore Runtime 跑在 ARM64（Graviton）——必须钉平台，否则容器起不来
# （x86 上不钉会构出 amd64 镜像，运行时报 exec format error）。
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# server.py 与 common.py（deploy_agentcore.py 从 deployer/functions/ 复制进构建
# 上下文）必须同目录：server.py 按同目录解析 common。
COPY server.py common.py permissions.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# AgentCore 契约：0.0.0.0:8000，POST /mcp
EXPOSE 8000

CMD ["python", "server.py"]
