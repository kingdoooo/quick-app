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

# **非 root 运行**（AgentCore 容器安全指引要求）。对这个容器格外要紧：它持有
# 能管理全部站点的 runtime 角色凭证（见 deploy_agentcore.py 的 TCB 说明），
# 以 root 跑等于把"进程内的漏洞"直接放大成"容器内任意写"。
#
# **/app 故意不 chown**：代码与依赖由 root 装好后保持 root:root，运行用户
# 只读执行。若把 /app 交给运行用户，进程内漏洞可改写 server.py，后门在
# 容器重启前对所有后续请求生效——降权就白做了。server 不写 /app：
# PYTHONDONTWRITEBYTECODE 关掉 .pyc，工具全部无状态；需要临时文件走
# /tmp 或 $HOME（--create-home 建出的 /home/appuser 归运行用户）。
#
# UID 固定为 10001 而不是让系统分配：镜像层里的所有权是数字 UID，
# 固定值让"同一份代码换台机器构建"得到一致的文件所有权。
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser
USER 10001

# AgentCore 契约：0.0.0.0:8000，POST /mcp
# 8000 > 1024，非特权用户可以直接绑定（这也是能降权的前提）。
EXPOSE 8000

CMD ["python", "server.py"]
