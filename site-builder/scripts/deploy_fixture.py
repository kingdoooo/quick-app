#!/usr/bin/env python3
"""打包 fixture → 上传 → 建 job → 跑状态机 → 轮询到终态。用法：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/nosql-notes"""
import configparser
import io
import json
import secrets
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parents[1] / "config.ini")
ACCT = CFG["Platform"]["account_id"]


def main(fixture_dir: str):
    root = Path(fixture_dir)
    manifest = json.loads((root / "site.json").read_text())
    site_id = f"{manifest['name'][:20]}-{secrets.token_hex(3)}"
    job_id = f"job-{secrets.token_hex(8)}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in root.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(root))
        run_sh = root.parent / "run.sh"
        if manifest["tier"] != "static" and run_sh.exists():
            z.write(run_sh, "run.sh")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.put_object(Bucket=f"site-artifacts-{ACCT}", Key=f"uploads/{job_id}.zip",
                  Body=buf.getvalue())
    now = datetime.now(timezone.utc).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["jobs_table"]).put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "fixture@test",
            "status": "PENDING", "phase": "submitted", "error": "", "url": "",
            "created_at": now, "updated_at": now})
    boto3.client("stepfunctions", region_name="us-east-1").start_execution(
        stateMachineArn=CFG["Deployer"]["state_machine_arn"],
        input=json.dumps({"job_id": job_id, "site_id": site_id}))

    jobs = boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["jobs_table"])
    while True:
        job = jobs.get_item(Key={"job_id": job_id})["Item"]
        print(f"  [{job['status']}] {job['phase']}")
        if job["status"] in ("SUCCEEDED", "FAILED"):
            print(json.dumps(job, indent=2, ensure_ascii=False, default=str))
            sys.exit(0 if job["status"] == "SUCCEEDED" else 1)
        time.sleep(10)


if __name__ == "__main__":
    main(sys.argv[1])
