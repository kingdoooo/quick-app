"""SFN 终态收敛：让 TIMED_OUT / ABORTED 的 job 不再永久停在 RUNNING。

**缺口**：状态机整体 TimeoutSeconds 到点（TIMED_OUT）与人工 StopExecution
（ABORTED）**不执行任何 State**——add_catch 只覆盖步骤内失败，所以 mark_job
不被调用，job 永久 RUNNING。而 confirm_upload 只接受 PENDING，用户既看不到
结果也无法重试。

**两层收敛**（缺一不算闭合）：
  ① 实时层 handler()：EventBridge Step Functions status-change 事件。秒级。
  ② 兜底层 sweeper_handler()：定时扫超龄 RUNNING + DescribeExecution 核对。
Step Functions 的状态变化事件是 **best-effort**（AWS 不保证投递），单靠 ①
会漏；单靠 ② 最坏要等一个调度周期。两层共用 converge_job_to_failed，
收敛语义只有一份。
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
import botocore.exceptions

import common

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 终态：这些状态的 job 不得被覆盖。
TERMINAL = ("SUCCEEDED", "FAILED", "DELETED")

# sweeper 的超龄阈值：状态机 TimeoutSeconds=1800（30 分钟）+ 余量。
STALE_MINUTES = 45

# **固定、无敏感信息**的 error 文案：事件里的 input / cause 可能含用户数据或
# 内部 ARN，一律不落库。
TIMEOUT_ERROR = ("部署执行超时已被系统终止（超过 30 分钟上限）。"
                 "请重新发起一次部署（会生成新任务）。")
ABORT_ERROR = ("部署执行已被中止。请重新发起一次部署（会生成新任务）。")
_REASON_ERROR = {"TIMED_OUT": TIMEOUT_ERROR, "ABORTED": ABORT_ERROR,
                 "FAILED": ABORT_ERROR}

_sfn_client = None


def _state_machine_arn() -> str:
    """只收敛本状态机的执行——rule 已按 ARN 过滤，这里再核一次（纵深）。

    **每次调用都读环境变量，不缓存成模块级常量**：Lambda 里 env 在 import 前
    就绪，两种写法都能跑，但模块级快照在测试里永远是空字符串（test 模块的
    `import reconcile_job` 发生在 fixture setenv **之前**），会让"外来状态机
    必须被拒"这条纵深防线变成没被验证过的死代码。
    """
    return os.environ.get("STATE_MACHINE_ARN", "")


def _sfn():
    global _sfn_client
    if _sfn_client is None:
        _sfn_client = boto3.client(
            "stepfunctions",
            region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _sfn_client


def _ddb():
    return boto3.client(
        "dynamodb", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def converge_job_to_failed(job_id: str, *, reason: str) -> str:
    """把停在 RUNNING 的 job 条件收敛为 FAILED。返回 converged/noop/absent。

    条件三条，缺一不可：
      · attribute_exists(job_id) —— UpdateItem 默认是 upsert，缺这条会给一个
        不存在的 job_id **凭空建行**（伪造/迟到事件即可污染 jobs 表）；
      · #s = :running —— 终态不得被覆盖（乱序/重复事件幂等靠它）；
      · **不带 phase 条件** —— timeout/abort 可发生在任意 phase，照抄
        _rollback_job_to_pending 的 phase=queued 会让绝大多数场景收敛失败。

    保留最后 phase（诊断用），只改 status / error / updated_at。
    """
    error = _REASON_ERROR.get(reason, ABORT_ERROR)
    try:
        _ddb().update_item(
            TableName=os.environ["JOBS_TABLE"],
            Key={"job_id": {"S": job_id}},
            UpdateExpression="SET #s = :failed, #e = :err, updated_at = :t",
            ConditionExpression=("attribute_exists(job_id) AND #s = :running"),
            ExpressionAttributeNames={"#s": "status", "#e": "error"},
            ExpressionAttributeValues={
                ":failed": {"S": "FAILED"}, ":running": {"S": "RUNNING"},
                ":err": {"S": error},
                ":t": {"S": datetime.now(timezone.utc).isoformat()}})
        logger.info(f'{{"event":"job_converged","job_id":"{job_id}",'
                    f'"reason":"{reason}"}}')
        return "converged"
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise    # 真错误要冒出去，让 Lambda retry / DLQ 生效
        # 条件失败有两种原因，需要分辨（否则"不存在"会被当成"已终态"而静默）
        item = _ddb().get_item(TableName=os.environ["JOBS_TABLE"],
                               Key={"job_id": {"S": job_id}},
                               ConsistentRead=True).get("Item")
        if not item:
            logger.info(f'{{"event":"job_absent","job_id":"{job_id}",'
                        f'"reason":"{reason}"}}')
            return "absent"
        logger.info(f'{{"event":"job_already_terminal","job_id":"{job_id}",'
                    f'"status":"{item.get("status", {}).get("S", "")}"}}')
        return "noop"


def _job_id_from_execution_arn(arn: str) -> str:
    """execution ARN 的最后一段就是 execution name，当前约定 name == job_id。

    **不从 event["detail"]["input"] 取 job_id**：input 是提交方可控的数据，
    伪造/被改写的 input 能让收敛写到别人的 job 上。ARN 由 Step Functions
    服务自己填，且 rule 已按 stateMachineArn 过滤。
    """
    return arn.rsplit(":", 1)[-1] if arn else ""


def handler(event, context):
    """实时层：EventBridge Step Functions Execution Status Change。"""
    detail = event.get("detail") or {}
    status = detail.get("status", "")
    sm_arn = detail.get("stateMachineArn", "")
    job_id = _job_id_from_execution_arn(detail.get("executionArn", ""))

    expected_arn = _state_machine_arn()
    if expected_arn and sm_arn != expected_arn:
        logger.warning(f'{{"event":"foreign_state_machine","arn":"{sm_arn}"}}')
        return {"job_id": job_id, "outcome": "ignored"}
    if status not in ("TIMED_OUT", "ABORTED"):
        return {"job_id": job_id, "outcome": "ignored"}
    if not job_id:
        logger.error('{"event":"missing_execution_arn"}')
        return {"job_id": "", "outcome": "ignored"}
    return {"job_id": job_id, "outcome": converge_job_to_failed(job_id,
                                                                reason=status)}


def sweeper_handler(event, context):
    """兜底层：扫超龄 RUNNING job，按 DescribeExecution 的真实状态收敛。

    分页安全、串行处理（站点量级下不需要并发；无界并发会打爆 SFN 的
    DescribeExecution 限流）。找不到 execution 时**不猜终态**——只计 orphan
    并打 ERROR 日志（进告警面）。
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=STALE_MINUTES)).isoformat()
    sm_arn = _state_machine_arn()
    table = common._table("JOBS_TABLE")
    scanned = converged = orphans = 0
    start_key = None
    while True:
        kwargs = {
            "FilterExpression": "#s = :running AND updated_at < :cutoff",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": "RUNNING",
                                          ":cutoff": cutoff},
            "ProjectionExpression": "job_id",
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            job_id = item["job_id"]
            arn = f"{sm_arn.replace(':stateMachine:', ':execution:')}:{job_id}"
            try:
                ex_status = _sfn().describe_execution(
                    executionArn=arn)["status"]
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("ExecutionDoesNotExist", "ValidationException"):
                    orphans += 1
                    logger.error(f'{{"event":"job_running_without_execution",'
                                 f'"job_id":"{job_id}"}}')
                    continue
                raise
            if ex_status in ("TIMED_OUT", "ABORTED", "FAILED"):
                if converge_job_to_failed(job_id, reason=ex_status) == "converged":
                    converged += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    logger.info(f'{{"event":"sweep_done","scanned":{scanned},'
                f'"converged":{converged},"orphans":{orphans}}}')
    return {"scanned": scanned, "converged": converged, "orphans": orphans}
