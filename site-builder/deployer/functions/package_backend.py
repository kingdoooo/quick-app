"""SFN 步骤 3：触发 CodeBuild 装依赖打 backend.zip，同步等待完成。"""
import os
import time

import boto3

import common


class PackageError(Exception):
    pass


def _codebuild():
    return boto3.client("codebuild")


def handler(event, context):
    common.update_job(event["job_id"], phase="package")
    cb = _codebuild()
    build_id = cb.start_build(
        projectName=os.environ["PACKAGE_PROJECT"],
        environmentVariablesOverride=[
            {"name": "JOB_ID", "value": event["job_id"]},
            {"name": "ARTIFACTS_BUCKET", "value": os.environ["ARTIFACTS_BUCKET"]},
        ])["build"]["id"]

    deadline = time.time() + 13 * 60
    while True:
        build = cb.batch_get_builds(ids=[build_id])["builds"][0]
        status = build["buildStatus"]
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            raise PackageError(f"依赖打包失败（{status}），日志: "
                               f"{build.get('logs', {}).get('deepLink', 'n/a')}")
        if time.time() > deadline:
            raise PackageError("依赖打包超时（13 分钟）")
        time.sleep(5)

    event["backend_zip_key"] = f"artifacts/{event['job_id']}/backend.zip"
    return event
