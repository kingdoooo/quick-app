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
            if len(infos) > 2000:
                raise ContractViolation(f"文件数 {len(infos)} 超过 2000 上限")
            total = sum(i.file_size for i in infos)
            if total > 200 * 1024 * 1024:
                raise ContractViolation(f"解压后总大小 {total} 超过 200MB 上限")
            compressed = max(1, sum(i.compress_size for i in infos))
            if total / compressed > 100:
                raise ContractViolation(f"压缩比 {total // compressed}:1 超过 100:1（疑似 zip bomb）")
            names = z.namelist()
            if len(names) != len(set(names)):
                dup = sorted({n for n in names if names.count(n) > 1})
                raise ContractViolation(
                    f"zip 内有重名条目 {dup[:5]}——解包方与校验方对重名的处置"
                    "不必然一致，一律拒绝")
            for m in z.namelist():  # zip-slip 防护
                if m.startswith("/") or ".." in m:
                    raise ContractViolation(f"非法路径: {m}")
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

    return {"job_id": job_id, "site_id": site_id, "manifest": manifest}
