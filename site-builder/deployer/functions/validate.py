"""SFN 步骤 1：下载上传包 → 解包 → 合同校验（schema+红线）→ 回写解包内容。"""
import io
import json
import os
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import boto3
import botocore.exceptions

from contract import scan_redlines, validate_manifest
import common


# 解包上界。**Task A5 的 CDK 断言按名字 AST 取 MAX_UNPACKED_BYTES**给 validate 定
# **磁盘**（ephemeral storage）尺寸——改上界不同时改磁盘即红（同 access_rollup 的
# SCAN_WORKERS ↔ 内存那条式子）。绑的是磁盘这一条轴，别读成内存。
#
# 落 /tmp 的有两样，所以磁盘下界是本上界的 2 倍：
#   · `extractall` 解出来的整棵树（≤ 本上界；准确说 ≤ zip 里**声明**的总大小）；
#   · `_pack_build_input` 重新打包出来的工件（run.sh + backend/ 的子集）。
# 留在**内存**里的是另一回事，本上界管不到：下载下来的整个上传包（`data`）、
# 以及 extracted/ 上传循环里当下那一个文件的字节。前者现在由下面的
# `MAX_UPLOAD_BYTES` 在 `read()` **之前**兜住（Task F1；在那之前它无常量可绑）。
MAX_ZIP_ENTRIES = 2000
MAX_UNPACKED_BYTES = 200 * 1024 * 1024

# confirm_upload 在 MCP 入口对**那一刻**的对象查过 50MB（mcp/server.py 的
# MAX_ZIP_BYTES，由 test_upload_cap_matches_the_50mb_check_at_the_mcp_entrance
# 按 AST 锁住两处相等）。这里再查一次是因为那个检查是 HEAD、而预签名 PUT URL 还活
# 900s ⇒ 确认之后仍可被覆盖成任意大小。**必须在 read() 之前**：本函数 512MB 内存，
# 读一个 5GB 对象是 OOM 而不是拒绝。
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# CodeBuild 唯一允许的输入前缀。owner 只有 uploads/{job_id}.zip 的预签名 PUT，
# 碰不到这里 ⇒ **owner 写不进本前缀**（这一条为真）。
#
# 但"本前缀下的对象在 job 生命周期内不可变"**不成立**，别那么读：
#   · validate 自己在重试时会重写它（SFN 对本步骤有 MaxAttempts:6 的
#     service-exception 重试）。重写的字节是同一份——那由下面 `IfMatch` 保证
#     （test_upload_is_pinned_to_the_bytes_confirm_upload_checked /
#      test_retry_with_the_pinned_bytes_still_succeeds），而不是由"没人能写"保证；
#   · `infra/app.py` 里所有 step Lambda 共用的 `exec_role` 对整个 artifacts 桶
#     都有 `PutObject`/`DeleteObject` ⇒ 兄弟步骤在 IAM 上也能写这里。
# "只有 validate 能写这个前缀"要靠独立 IAM 角色 + exec_role 显式 Deny 收口
# （Task F7），**本文件不承诺那一条**。
VALIDATED_PREFIX = "validated"


def validated_key(job_id: str) -> str:
    return f"{VALIDATED_PREFIX}/{job_id}/backend-src.zip"


def _pack_build_input(root: Path, dest: Path) -> int:
    """把**已解包并逐文件扫描过的那棵树**里构建所需的部分重新打包到 `dest`，
    返回打进去的**条目数**。

    不是重新读一遍上传 key ⇒ 不存在"校验的字节"与"构建的字节"不同的窗口（P1-1）。
    只打 run.sh + backend/：buildspec 也只用这两样，前端与 site.json 不进构建容器。

    **写文件而不是返回 bytes**：返回 bytes 时这个 zip 与已经读进内存的上传包同时
    常驻，等于把峰值内存抬高整整一个包的量级——而这一份是 M7 才引入的，之前没有。
    落到 /tmp 再流式上传，占的是 CDK 已按解包上界定过尺寸的那块磁盘
    （`infra/app.py` 的 `VALIDATE_EPHEMERAL_MB`），不是 512MB 的内存。

    **"空"由返回的条目数判定，不许对产物做真值判断**（A2 的 `b""` 哨兵换了个形状，
    语义不变）：零条目的 zip 自身就是 22 字节的合法 zip（只有 EOCD 记录），恒为真
    ——文件形态下更显然，`dest` 无论如何都存在。所以这里**照样把空包写出来**，
    "不上传"的决定单点留在调用方那个 `if`：留下空对象会让"validated/ 下有对象"
    不再等价于"有东西要构建"，连带让"失败不许留工件"那条用例失去信号。
    """
    members = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if rel == "run.sh" or rel.startswith("backend/"):
            members.append((p, rel))
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p, rel in members:
            z.write(p, rel)
    return len(members)


class ContractViolation(Exception):
    pass


def handler(event, context):
    job_id, site_id = event["job_id"], event["site_id"]
    common.update_job(job_id, status="RUNNING", phase="validate")
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    # 钉住 confirm_upload 当时那份字节。SFN 对本步骤有 MaxAttempts:6 的
    # service-exception 重试，而上传 URL 在 900s 内仍可覆盖 ⇒ 不钉的话两次 attempt
    # 可以读到不同的包：extracted/ 变成两棵树的并集（旧前端文件仍会被发布、被删掉的
    # migration 仍会执行），且 SFN 携带的 manifest 与 CodeBuild 读到的代码可能来自
    # 不同 attempt。IfMatch 让第二种情况变成 412 而不是静默分歧。
    job = common.get_job(job_id) or {}
    etag = job.get("upload_etag")
    if not etag:
        raise ContractViolation(
            "任务记录里没有 upload_etag——请重新调用 confirm_upload（本任务可能由旧版"
            "MCP 创建）")
    try:
        obj = s3.get_object(Bucket=bucket, Key=f"uploads/{job_id}.zip", IfMatch=etag)
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") not in ("PreconditionFailed", "412"):
            raise
        raise ContractViolation(
            "上传的 site.zip 在确认之后被改动过，本次部署已取消——请重新上传并"
            "重新确认（校验与构建必须是同一份字节）") from e
    if obj["ContentLength"] > MAX_UPLOAD_BYTES:
        raise ContractViolation(
            f"site.zip {obj['ContentLength']} 字节超过 "
            f"{MAX_UPLOAD_BYTES // 1024 // 1024}MB 上限")
    data = obj["Body"].read()

    # 两个临时目录都在 /tmp（尺寸由 VALIDATE_EPHEMERAL_MB 覆盖）：`root` 是解包树，
    # `spool` 只放重新打包出来的工件。**工件不能写进 root**——`_pack_build_input`
    # 与下面 extracted/ 那个上传循环都在 rglob(root)，落在被遍历的树里就会把自己
    # 也卷进去（或卷进下一次遍历）。
    with TemporaryDirectory() as td, TemporaryDirectory() as spool:
        root = Path(td)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ContractViolation(f"文件数 {len(infos)} 超过 {MAX_ZIP_ENTRIES} 上限")
            total = sum(i.file_size for i in infos)
            if total > MAX_UNPACKED_BYTES:
                raise ContractViolation(
                    f"解压后总大小 {total} 超过 {MAX_UNPACKED_BYTES // 1024 // 1024}MB 上限")
            compressed = max(1, sum(i.compress_size for i in infos))
            if total / compressed > 100:
                raise ContractViolation(f"压缩比 {total // compressed}:1 超过 100:1（疑似 zip bomb）")
            names = z.namelist()
            for m in names:  # zip-slip 防护
                if m.startswith("/") or ".." in m:
                    raise ContractViolation(f"非法路径: {m}")
            # 按**落盘路径**去重，不是按原名：extractall 丢掉空段与 "." 段
            # （"backend/app.js"、"./backend/app.js"、"backend//app.js" 全落到同一个
            # 文件）且保留**最后**一份字节，于是三个各不相同的 namelist 条目只留一份
            # ——按原名去重看不见这种撞车。".." 已被上面拒掉，故只需处理 "" 与 "."。
            # 不替用户挑赢家，一律拒绝。**这段必须留在 MAX_ZIP_ENTRIES 之下**：下面的
            # count() 是 O(n²)，靠条目数上限先兜住（test_entry_cap_precedes_dup_check 锁死）。
            paths = ["/".join(s for s in n.split("/") if s not in ("", "."))
                     for n in names]
            if len(paths) != len(set(paths)):
                dup = sorted({p for p in paths if paths.count(p) > 1})
                raise ContractViolation(
                    f"zip 内有重名条目（按落盘路径）{dup[:5]}——解包方与校验方对重名的"
                    "处置不必然一致，一律拒绝")
            z.extractall(root)

        manifest_path = root / "site.json"
        if not manifest_path.exists():
            raise ContractViolation("缺少 site.json")
        manifest = json.loads(manifest_path.read_text())

        errors = validate_manifest(manifest)
        errors += scan_redlines(root, manifest)
        if errors:
            raise ContractViolation("；".join(errors))

        for p in root.rglob("*"):
            if p.is_file():
                s3.put_object(Bucket=bucket,
                              Key=f"extracted/{job_id}/{p.relative_to(root)}",
                              Body=p.read_bytes())

        # CodeBuild 的唯一输入。**必须在校验全部通过之后写**——提到校验之前，
        # 失败的运行就会覆盖上一次的好工件
        # （test_validation_failure_writes_no_build_artifact 锁死）。
        pack = Path(spool) / "backend-src.zip"
        if _pack_build_input(root, pack):   # 0 条目 = static tier，不留空对象
            with pack.open("rb") as fh:     # 流式上传，不把整份读进内存
                s3.put_object(Bucket=bucket, Key=validated_key(job_id), Body=fh)

    return {"job_id": job_id, "site_id": site_id, "manifest": manifest}
