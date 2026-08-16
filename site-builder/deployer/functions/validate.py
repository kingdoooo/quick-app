"""SFN 步骤 1：下载上传包 → 解包 → 合同校验（schema+红线）→ 回写解包内容。"""
import io
import json
import os
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import boto3

from contract import scan_redlines, validate_manifest
import common


# 解包上界。**Task A5 的 CDK 断言按名字 AST 取这两个值**给 validate 定磁盘尺寸
# ——改上界不同时改磁盘即红（同 access_rollup 的 SCAN_WORKERS ↔ 内存那条式子）。
MAX_ZIP_ENTRIES = 2000
MAX_UNPACKED_BYTES = 200 * 1024 * 1024

# CodeBuild 唯一允许的输入前缀。owner 只有 uploads/{job_id}.zip 的预签名 PUT，
# 碰不到这里 ⇒ 本前缀下的对象在 job 生命周期内不可变。
VALIDATED_PREFIX = "validated"


def validated_key(job_id: str) -> str:
    return f"{VALIDATED_PREFIX}/{job_id}/backend-src.zip"


def _pack_build_input(root: Path) -> bytes:
    """把**已解包并逐文件扫描过的那棵树**里构建所需的部分重新打包。

    不是重新读一遍上传 key ⇒ 不存在"校验的字节"与"构建的字节"不同的窗口（P1-1）。
    只打 run.sh + backend/：buildspec 也只用这两样，前端与 site.json 不进构建容器。

    没有任何构建输入（static tier）时返回 `b""` 这个哨兵，调用方据此**不写对象**。
    "空"必须由条目数判定再编码成 `b""`，不能让调用方直接对打包结果做真值判断：
    零条目的 zip 自身就是 22 字节的合法 zip（只有 EOCD 记录），恒为真。留下这种空对象
    会让"validated/ 下有对象"不再等价于"有东西要构建"。
    """
    members = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if rel == "run.sh" or rel.startswith("backend/"):
            members.append((p, rel))
    if not members:
        return b""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p, rel in members:
            z.write(p, rel)
    return buf.getvalue()


class ContractViolation(Exception):
    pass


def handler(event, context):
    job_id, site_id = event["job_id"], event["site_id"]
    common.update_job(job_id, status="RUNNING", phase="validate")
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    obj = s3.get_object(Bucket=bucket, Key=f"uploads/{job_id}.zip")
    data = obj["Body"].read()

    with TemporaryDirectory() as td:
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
        build_input = _pack_build_input(root)
        if build_input:      # static tier 没有构建输入，不留空对象
            s3.put_object(Bucket=bucket, Key=validated_key(job_id),
                          Body=build_input)

    return {"job_id": job_id, "site_id": site_id, "manifest": manifest}
