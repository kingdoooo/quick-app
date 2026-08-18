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
# PURGE_FAILED（M3 修复引入）："站点已下线但数据没清干净"——它是终态，
# 不能被 sweeper 再收敛成 FAILED（那会把"URL 已失效"说成"下线失败"）。
#
# **它是文档与用例的登记表，不是运行时判据**：收敛的真正闸门是
# `converge_job_to_failed` 的 `#s = :running` 条件（任何非 RUNNING 都不动），
# 部署租约判"持有者还在跑吗"用的也是 RUNNING（common.plan_deploy_lease，
# 那里解释了为什么**不能**改成"非终态即忙"——PENDING 会把站点永久锁死）。
# 新增终态仍要登记到这里：test_purge_failed_is_registered_terminal 按它断言。
TERMINAL = ("SUCCEEDED", "FAILED", "DELETED", "PURGE_FAILED")

# undeploy job 的超龄阈值。比 STALE_MINUTES 短得多：undeploy 是单个异步
# Lambda（timeout ≤15 分钟），不像部署要走 30 分钟的状态机。超过这个时长还
# RUNNING，只可能是 Lambda 被杀/超时/OOM——那些情形下进程没机会写终态。
UNDEPLOY_STALE_MINUTES = 20

# undeploy 中途失败/被杀后的固定文案。**不含事件里的 cause**（可能带用户
# 数据或内部 ARN）。措辞要如实：站点可能已经部分删除，不能说"未受影响"。
UNDEPLOY_ORPHAN_ERROR = (
    "下线任务异常中断（执行进程未能写入结果）。站点可能处于部分下线状态："
    "路由可能已删除但资源尚未清理完毕。请联系平台管理员核对，勿直接重试。")

# sweeper 的超龄阈值：状态机 TimeoutSeconds=1800（30 分钟）+ 余量。
STALE_MINUTES = 45

# **固定、无敏感信息**的 error 文案：事件里的 input / cause 可能含用户数据或
# 内部 ARN，一律不落库。
TIMEOUT_ERROR = ("部署执行超时已被系统终止（超过 30 分钟上限）。"
                 "请重新发起一次部署（会生成新任务）。")
ABORT_ERROR = ("部署执行已被中止。请重新发起一次部署（会生成新任务）。")
# 部署 job 超龄且**没有对应 execution**（按确定性 name 查证）：start 从未发生。
# 措辞要点出"没有任何改动"——这一态与 TIMED_OUT（跑了一半）的处置完全不同。
ORPHANED_ERROR = ("部署执行未能启动（未找到对应的执行记录，站点未做任何改动）。"
                  "请重新发起一次部署（会生成新任务）。")

_REASON_ERROR = {"TIMED_OUT": TIMEOUT_ERROR, "ABORTED": ABORT_ERROR,
                 "FAILED": ABORT_ERROR,
                 "ORPHANED": ORPHANED_ERROR,
                 "UNDEPLOY_ORPHAN": UNDEPLOY_ORPHAN_ERROR}

_sfn_client = None


def _compensate_committed_route(job_id: str) -> str | None:
    """**收敛之前**：这条 job 若已提交过路由，先做与 MarkFailed 相同的幂等补偿，
    返回被放弃时的说明（成功/无事可做返回 None）。

    这是收敛闭环缺的另一半（Codex 2026-08-18 P1-4）：TIMED_OUT / ABORTED、以及
    "MarkFailed 自己重试耗尽后 SFN FAILED"都**不执行任何 State**，于是路由补偿
    没人做。

    **必须先补偿、后写终态**（Codex 2026-08-18 R4 P1-1）：部署租约判"忙"看的是
    holder 的 RUNNING，converge 一写 FAILED 租约即可被抢——补偿还没跑时新部署
    就会在"已提交但未回滚"的路由上开跑，随后补偿再把路由写回它正在改的那个色。
    job 还是 RUNNING 时补偿是安全的：补偿条件锚的是"线上还是这条 job 提交的
    那份"，与 job 状态无关。

    补偿函数与 MarkFailed **同一份**（`mark_job._restore_route`，自带全部幂等与
    放弃判定；M/NULL 解码也只活在它那一处的回落里）。`route_commit` 缺席 =
    从未提交或不是 deploy job ⇒ 路由一个字不动。job 已非 RUNNING ⇒ 别的写入者
    （MarkFailed）已经处理过，这里不重复。

    自身失败只告警不外溢：让补偿的异常打断 sweeper 的整轮扫描，会把一个站点的
    问题放大成所有站点都不收敛；converge 仍会执行（宁可"终态但没补偿+响亮日志"
    也不要"永远 RUNNING 卡死整站"——那才是把可用性押给一次读失败）。
    """
    import mark_job     # 同目录同产物；函数级 import 免得拖累无关调用的冷启
    try:
        item = _ddb().get_item(TableName=os.environ["JOBS_TABLE"],
                               Key={"job_id": {"S": job_id}},
                               ConsistentRead=True).get("Item") or {}
        if item.get("status", {}).get("S") != "RUNNING":
            return None     # 已被 MarkFailed/上一轮收敛处理，不重复
        # **不按 route_commit 的有无提前返回**：有没有提交、要不要恢复、以及
        # "升级窗口老代码 execution 没有 route_commit 但确实提交过"的启发式
        # 判定，全部在 _restore_route 里（唯一定义）。这里多判一次就是那套
        # 判定的第二份手抄。
        note = mark_job._restore_route(
            {"job_id": job_id, "site_id": item["site_id"]["S"]})
        logger.info(f'{{"event":"route_compensated","job_id":"{job_id}",'
                    f'"abandoned":{"true" if note else "false"}}}')
        return note
    except Exception:       # noqa: BLE001
        # **读失败 ≠ 无需补偿**（Codex 2026-08-18 R5 P1）：返回 None 会让
        # _compensate_then_converge 把它当"没有补偿问题"，job 收敛成 FAILED 而
        # error 里没有任何人工处置提示——操作者完全不知道要去查路由。
        # 这里是**最后一环**，仍然收敛（不收敛 = 站点永久锁死），但必须把
        # "路由状态未知"如实写进 job。
        logger.exception("收敛前的路由补偿失败 job_id=%s——路由可能仍停在该次"
                         "部署的新目标上，需人工核对", job_id)
        return mark_job.ROUTE_RESTORE_FAILED


def _compensate_then_converge(job_id: str, reason: str) -> str:
    """补偿 → **一次写**收敛（终态与最终错误文案同一个 UpdateItem）。

    **不许先写终态、再补一笔 error**（Codex 2026-08-19 R6 P2）：两笔写之间
    第二笔可以暂时失败，而重试进来时 job 已经 FAILED——补偿因非 RUNNING 跳过、
    converge 是 noop，**那条"路由可能没回滚、需人工核对"的提示再也没有机会
    写回**。操作者最终只看到普通的"执行超时"，一个已知"路由状态未知"的场景
    静默退化成 false-green 运维信号。合成最终文案再一次写入，窗口不存在。

    截断纪律与 mark_job.handler 相同：砍原因、不砍提示。
    """
    note = _compensate_committed_route(job_id)
    error = None
    if note:
        base = _REASON_ERROR.get(reason, ABORT_ERROR)
        error = f"{base[:max(0, 500 - len(note) - 3)]} | {note}"
    return converge_job_to_failed(job_id, reason=reason, error=error)


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


def converge_job_to_failed(job_id: str, *, reason: str,
                           error: str | None = None) -> str:
    """把停在 RUNNING 的 job 条件收敛为 FAILED。返回 converged/noop/absent。

    `error`：**最终**错误文案（缺省按 reason 查 `_REASON_ERROR`）。带补偿提示的
    调用方（_compensate_then_converge）必须把合成好的文案从这里**一次写入**——
    终态与文案分两笔写的话，第二笔失败 + 重试 = 提示永久丢失（R6 P2）。

    条件三条，缺一不可：
      · attribute_exists(job_id) —— UpdateItem 默认是 upsert，缺这条会给一个
        不存在的 job_id **凭空建行**（伪造/迟到事件即可污染 jobs 表）；
      · #s = :running —— 终态不得被覆盖（乱序/重复事件幂等靠它）；
      · **不带 phase 条件** —— timeout/abort 可发生在任意 phase，照抄
        _rollback_job_to_pending 的 phase=queued 会让绝大多数场景收敛失败。

    保留最后 phase（诊断用），只改 status / error / updated_at。
    """
    error = error or _REASON_ERROR.get(reason, ABORT_ERROR)
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
    # 补偿在 converge **之前**（_compensate_committed_route 的 docstring）：
    # 它自带"非 RUNNING 即跳过"，所以早已终态的 job 不会被白惊动。
    return {"job_id": job_id,
            "outcome": _compensate_then_converge(job_id, status)}


def sweeper_handler(event, context):
    """兜底层：扫超龄 RUNNING job，按 DescribeExecution 的真实状态收敛。

    分页安全、串行处理（站点量级下不需要并发；无界并发会打爆 SFN 的
    DescribeExecution 限流）。找不到 execution 时**不猜终态**——只计 orphan
    并打 ERROR 日志（进告警面）。

    **按 kind 分流**（Codex 审查 2026-08-10 P1-4）：undeploy 是独立异步
    Lambda，没有 SFN execution。原来对它调 DescribeExecution 必然
    ExecutionDoesNotExist，于是被计成 orphan 后永久停在 RUNNING——
    实测复现过 job=RUNNING/route=已删除/site=ACTIVE 这个不收敛状态。
    undeploy 的判据只有"超龄"：它的 Lambda timeout ≤15 分钟，超过
    UNDEPLOY_STALE_MINUTES 还 RUNNING 只可能是进程被杀/超时/OOM，
    那些情形下代码没有机会写终态。
    """
    # 取两个阈值里更宽松的那个做扫描下限，各类型再按自己的阈值判定，
    # 避免把 undeploy 的短阈值套到 deploy 上（那会误杀正常部署）。
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=STALE_MINUTES)).isoformat()
    undeploy_cutoff = (now - timedelta(minutes=UNDEPLOY_STALE_MINUTES)).isoformat()
    scan_cutoff = min(cutoff, undeploy_cutoff)
    sm_arn = _state_machine_arn()
    table = common._table("JOBS_TABLE")
    scanned = converged = orphans = 0
    start_key = None
    while True:
        kwargs = {
            "FilterExpression": "#s = :running AND updated_at < :cutoff",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": "RUNNING",
                                          ":cutoff": scan_cutoff},
            # kind 必须投影出来，否则分不出 deploy/undeploy
            "ProjectionExpression": "job_id, kind, updated_at",
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            job_id = item["job_id"]
            # ---- undeploy：不查 SFN，只看超龄 ----
            if item.get("kind") == "undeploy":
                if item.get("updated_at", "") >= undeploy_cutoff:
                    continue        # 还没到它自己的阈值
                scanned += 1
                if converge_job_to_failed(
                        job_id, reason="UNDEPLOY_ORPHAN") == "converged":
                    converged += 1
                continue
            # ---- deploy：保持原逻辑（DescribeExecution 核对真实状态）----
            if item.get("updated_at", "") >= cutoff:
                continue            # 未达部署阈值（扫描下限更宽松，这里再筛）
            scanned += 1
            arn = f"{sm_arn.replace(':stateMachine:', ':execution:')}:{job_id}"
            try:
                ex_status = _sfn().describe_execution(
                    executionArn=arn)["status"]
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ExecutionDoesNotExist":
                    # **收敛，不再只记 orphan**（Codex 2026-08-18 R4 P1-2 的
                    # 配套）。这不是猜：execution name == job_id 是两个入口
                    # （MCP 与 deploy_fixture）都钉死的约定，且 execution 结束后
                    # 记录保留 90 天——"这个 name 不存在"就是"start 从未发生"的
                    # 权威证词。而且这一态现在是**合法可达**的：StartExecution
                    # 网络错误但结果不确定时，入口保持 RUNNING（不回滚），把
                    # 核实交给这里——不收敛的话租约永远 busy，站点永久锁死。
                    logger.error(f'{{"event":"job_running_without_execution",'
                                 f'"job_id":"{job_id}","action":"converge"}}')
                    # **直接收敛，不走补偿**：execution 从未存在 ⇒ register_route
                    # 从未运行 ⇒ route_commit 不可能存在（它是 execution 内部与
                    # 路由提交同一笔写下的）。走补偿路径只会多两次读，且读一旦
                    # 抖动还会把"路由可能没回滚"的 note 粘到"站点未做任何改动"
                    # 的文案上——自相矛盾。
                    if converge_job_to_failed(
                            job_id, reason="ORPHANED") == "converged":
                        converged += 1
                    continue
                if code == "ValidationException":
                    # ARN 拼不出来（job_id 形态异常？）——**这才是不能猜的那种**：
                    # 无法核实 execution 状态，收敛可能杀掉一个活着的执行。
                    orphans += 1
                    logger.error(f'{{"event":"job_running_without_execution",'
                                 f'"job_id":"{job_id}","action":"skip"}}')
                    continue
                raise
            if ex_status in ("TIMED_OUT", "ABORTED", "FAILED"):
                # FAILED 也要补偿：execution FAILED 而 job 还停在 RUNNING 意味着
                # MarkFailed 自己重试耗尽都没跑成——路由补偿没人做过。
                # 补偿在 converge 之前（P1-1 的同一条顺序纪律）。
                if _compensate_then_converge(job_id, ex_status) == "converged":
                    converged += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    logger.info(f'{{"event":"sweep_done","scanned":{scanned},'
                f'"converged":{converged},"orphans":{orphans}}}')
    return {"scanned": scanned, "converged": converged, "orphans": orphans}
