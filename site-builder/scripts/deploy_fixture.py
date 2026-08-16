#!/usr/bin/env python3
"""打包 fixture → 上传 → 建 job → 跑状态机 → 轮询到终态。用法：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/nosql-notes
python3 site-builder/scripts/deploy_fixture.py <fixture> --owner me@example.com

owner 默认 `fixture@test`（E2E 用，不对应真人）。**要用 MCP 工具操作这个站点时
必须传 --owner 你的登录邮箱**——否则 role_of() 判你不是 owner，所有权限工具
都会拒绝，而症状看起来像"工具坏了"。"""
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


def main(fixture_dir: str, owner: str = "fixture@test"):
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
    body = buf.getvalue()
    put = s3.put_object(Bucket=f"site-artifacts-{ACCT}",
                        Key=f"uploads/{job_id}.zip", Body=body)
    now = datetime.now(timezone.utc).isoformat()
    # **必须先建 sites 记录**：MCP 的 do_deploy_site 会调 common.upsert_site 写
    # owner/name/status，而本脚本绕过 MCP 直接起状态机——不写的话 sites 表里
    # 没有 owner（register_route 会从 job 兜底写进路由表，所以只有真源缺失，
    # 两表不一致）。后果：role_of() 判调用者不是 owner，全部权限工具拒绝，
    # 症状看起来像"工具坏了"。实测踩过（2026-08-06）。
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["sites_table"]).update_item(
            Key={"site_id": site_id},
            UpdateExpression=("SET #o = :o, #n = :n, #s = :s"),
            ExpressionAttributeNames={"#o": "owner", "#n": "name", "#s": "status"},
            ExpressionAttributeValues={":o": owner, ":n": manifest["name"],
                                       ":s": "DEPLOYING"})
    # **同理必须自己钉 upload_etag**：MCP 的 do_confirm_upload 会把它 HEAD 到的
    # ETag 写进 job 记录，而 validate 用 `IfMatch` 读同一份字节、缺这个属性一律
    # fail-closed（不做假值兜底）。本脚本绕过 MCP ⇒ 不写的话它建的**每个** job 都会
    # 在第一步以"任务记录里没有 upload_etag"失败，连带 test_e2e_fixtures.py 全红。
    # ETag 取**上面那次 put_object 的返回**，不为此再 HEAD 一次：第二次 HEAD 可能
    # 已经看到另一个对象（与 mcp/server.py 里同一条理由）。
    # upload_bytes 只是审计字段，真正的校验是 validate 对 ContentLength 那一次。
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["jobs_table"]).put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": owner,
            "status": "PENDING", "phase": "submitted", "error": "", "url": "",
            "upload_etag": put["ETag"], "upload_bytes": len(body),
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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture_dir")
    ap.add_argument("--owner", default="fixture@test",
                    help="站点 owner 邮箱；要用 MCP 权限工具操作它就填你的登录邮箱")
    a = ap.parse_args()
    main(a.fixture_dir, a.owner)
