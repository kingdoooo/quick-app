"""SFN 终态收敛：EventBridge 实时层 + sweeper 兜底层。

**这些用例必须能在缺陷存在时变红**（本项目两次"验证本身无效"的教训）：
Step 2 会先确认它们全部 FAIL，Step 4 才确认转绿。
"""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest

import reconcile_job


def _put_job(status="RUNNING", phase="package", job_id="job-r1", site_id="s1"):
    now = datetime.now(timezone.utc).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "u@x.com",
            "status": status, "phase": phase, "error": "", "url": "",
            "created_at": now, "updated_at": now})


def _get_job(job_id="job-r1"):
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").get_item(Key={"job_id": job_id}).get("Item")


def _event(status="TIMED_OUT", job_id="job-r1",
           sm="arn:aws:states:us-east-1:1:stateMachine:site-deploy"):
    """真实 EventBridge Step Functions status-change 事件形态。

    job_id 只从 executionArn 的 name 段取——**不从 input 取**（input 是
    调用方可控的不可信数据，且可能被改写）。
    """
    return {"detail-type": "Step Functions Execution Status Change",
            "detail": {"status": status,
                       "stateMachineArn": sm,
                       "executionArn": f"arn:aws:states:us-east-1:1:execution:site-deploy:{job_id}",
                       "input": json.dumps({"job_id": "job-ATTACKER"})}}


@pytest.mark.parametrize("status", ["TIMED_OUT", "ABORTED"])
def test_running_converges_to_failed(aws, status):
    _put_job(status="RUNNING", phase="package")
    out = reconcile_job.handler(_event(status), None)
    assert out["outcome"] == "converged"
    job = _get_job()
    assert job["status"] == "FAILED"
    assert job["phase"] == "package", "必须保留最后 phase"
    assert job["error"], "必须写入固定 error 文案"
    assert "ATTACKER" not in json.dumps(job)


@pytest.mark.parametrize("phase", ["submitted", "queued", "validate",
                                   "provision-db", "package", "deploy-backend",
                                   "upload-frontend", "register-route",
                                   "smoke-test"])
def test_converges_from_any_phase(aws, phase):
    """timeout/abort 可发生在任意 phase——不得带 phase=queued 条件。"""
    _put_job(status="RUNNING", phase=phase)
    assert reconcile_job.handler(_event(), None)["outcome"] == "converged"
    assert _get_job()["status"] == "FAILED"


@pytest.mark.parametrize("terminal", ["SUCCEEDED", "FAILED", "DELETED"])
def test_terminal_status_is_noop(aws, terminal):
    _put_job(status=terminal, phase="smoke-test")
    assert reconcile_job.handler(_event(), None)["outcome"] == "noop"
    assert _get_job()["status"] == terminal, "终态不得被覆盖"


def test_absent_job_is_not_created(aws):
    """job 不存在只记日志，**绝不能凭空创建**（UpdateItem 默认会 upsert）。"""
    assert reconcile_job.handler(_event(job_id="job-ghost"), None)["outcome"] == "absent"
    assert _get_job("job-ghost") is None


def test_duplicate_event_is_idempotent(aws):
    _put_job(status="RUNNING")
    first = reconcile_job.handler(_event(), None)
    updated_at = _get_job()["updated_at"]
    second = reconcile_job.handler(_event(), None)
    assert (first["outcome"], second["outcome"]) == ("converged", "noop")
    assert _get_job()["updated_at"] == updated_at, "重复事件不得再写"


def test_out_of_order_event_does_not_clobber_success(aws):
    """乱序：SUCCEEDED 先落库，迟到的 ABORTED 事件不得把它改成 FAILED。"""
    _put_job(status="SUCCEEDED", phase="smoke-test")
    assert reconcile_job.handler(_event("ABORTED"), None)["outcome"] == "noop"
    assert _get_job()["status"] == "SUCCEEDED"


def test_foreign_state_machine_is_rejected(aws):
    """rule 已按 ARN 过滤，但 handler 自己也要核对（纵深）。"""
    _put_job(status="RUNNING")
    out = reconcile_job.handler(
        _event(sm="arn:aws:states:us-east-1:1:stateMachine:other-sm"), None)
    assert out["outcome"] == "ignored"
    assert _get_job()["status"] == "RUNNING"


# ---- sweeper 兜底层 ----

def _stale_job(job_id, minutes, status="RUNNING"):
    t = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": "s1", "owner": "u@x.com",
            "status": status, "phase": "package", "error": "", "url": "",
            "created_at": t, "updated_at": t})


def test_sweeper_converges_stale_running_with_terminal_execution(aws):
    _stale_job("job-stale1", 60)
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "TIMED_OUT"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 1
    assert _get_job("job-stale1")["status"] == "FAILED"


def test_sweeper_skips_fresh_jobs(aws):
    """未超龄的 RUNNING 不碰——它可能正在正常部署。"""
    _stale_job("job-fresh", 5)
    sfn = MagicMock()
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["scanned"] == 0 and out["converged"] == 0
    sfn.describe_execution.assert_not_called()
    assert _get_job("job-fresh")["status"] == "RUNNING"


def test_sweeper_leaves_still_running_execution_alone(aws):
    _stale_job("job-longrun", 60)
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "RUNNING"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 0
    assert _get_job("job-longrun")["status"] == "RUNNING"


def test_sweeper_reports_orphan_without_guessing(aws):
    """找不到 execution → 计入 orphans 并记日志，**不猜终态**。"""
    import botocore.exceptions
    _stale_job("job-orphan", 60)
    sfn = MagicMock()
    sfn.describe_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionDoesNotExist"}}, "DescribeExecution")
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["orphans"] == 1 and out["converged"] == 0
    assert _get_job("job-orphan")["status"] == "RUNNING", "不得猜测终态"
