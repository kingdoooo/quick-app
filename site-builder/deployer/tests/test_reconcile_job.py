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


def test_sweeper_converges_a_job_whose_execution_never_started(aws):
    """ExecutionDoesNotExist → **收敛成 FAILED**，不再只记 orphan。

    这不是猜（旧口径"不猜终态"针对的是 name 不确定的年代）：execution name ==
    job_id 是两个入口都钉死的约定，且 execution 结束后记录保留 90 天——
    "这个 name 不存在"就是"start 从未发生"的权威证词。而且这一态现在**合法
    可达**：StartExecution 网络错误、结果不确定时，入口保持 RUNNING 不回滚
    （Codex 2026-08-18 R4 P1-2），把核实交给这里。不收敛的话租约永远 busy，
    站点**永久锁死**。
    """
    import botocore.exceptions
    _stale_job("job-orphan", 60)
    sfn = MagicMock()
    sfn.describe_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionDoesNotExist"}}, "DescribeExecution")
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 1 and out["orphans"] == 0
    job = _get_job("job-orphan")
    assert job["status"] == "FAILED"
    assert "未能启动" in job["error"], \
        f"错误文案要点出『没启动、站点未改动』：{job['error']!r}"


def test_sweeper_still_does_not_guess_on_validation_exception(aws):
    """ValidationException（ARN 拼不出来）→ 仍只记 orphan，不收敛。

    这一类**无法核实** execution 状态——收敛可能杀掉一个活着的执行的 job。
    与 ExecutionDoesNotExist 的区别就是有没有权威证词。
    """
    import botocore.exceptions
    _stale_job("job-orphan", 60)
    sfn = MagicMock()
    sfn.describe_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ValidationException"}}, "DescribeExecution")
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["orphans"] == 1 and out["converged"] == 0
    assert _get_job("job-orphan")["status"] == "RUNNING", "不得猜测终态"


# ── undeploy job 的独立收敛规则（Codex 审查 2026-08-10 P1-4）───────────
# undeploy 是**独立异步 Lambda**，没有 SFN execution。原 sweeper 假设每个
# RUNNING job 都对应一个 execution，于是 undeploy 中途失败后只会记一条
# job_running_without_execution，job 永久 RUNNING（实测复现过）。
# 所以按 kind 分流：undeploy 不查 SFN，只看超龄。

def _stale_undeploy(job_id, minutes, status="RUNNING"):
    t = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": "s1", "owner": "u@x.com",
            "status": status, "phase": "undeploy", "kind": "undeploy",
            "error": "", "url": "", "created_at": t, "updated_at": t})


def test_sweeper_converges_stale_undeploy_without_calling_sfn(aws):
    """超龄的 undeploy job 必须收敛，且**不查 SFN**（它本来就没有 execution）。"""
    _stale_undeploy("job-und1", 60)
    sfn = MagicMock()
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    sfn.describe_execution.assert_not_called()
    assert out["converged"] == 1, out
    job = _get_job("job-und1")
    assert job["status"] == "FAILED", job
    assert job.get("error"), "收敛后必须留下用户可读的原因"


def test_sweeper_skips_fresh_undeploy(aws):
    """未超龄的 undeploy 不碰——它可能正在正常执行（清 DSQL 可能要几十秒）。"""
    _stale_undeploy("job-und-fresh", 5)
    sfn = MagicMock()
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 0
    assert _get_job("job-und-fresh")["status"] == "RUNNING"


def test_sweeper_does_not_touch_purge_failed(aws):
    """PURGE_FAILED 是终态：站点确实已下线，不能被改写成"下线失败"。"""
    _stale_undeploy("job-und-pf", 60, status="PURGE_FAILED")
    sfn = MagicMock()
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        reconcile_job.sweeper_handler({}, None)
    assert _get_job("job-und-pf")["status"] == "PURGE_FAILED"


def test_purge_failed_is_registered_terminal(aws):
    """漏登记 TERMINAL 会让新状态被当成"可覆盖"——按常量断言，不靠行为推断。"""
    assert "PURGE_FAILED" in reconcile_job.TERMINAL


def test_converge_does_not_overwrite_purge_failed(aws):
    """即便被直接调用，也不得覆盖 PURGE_FAILED（条件写只认 RUNNING）。"""
    _stale_undeploy("job-und-pf2", 60, status="PURGE_FAILED")
    assert reconcile_job.converge_job_to_failed(
        "job-und-pf2", reason="ABORTED") == "noop"
    assert _get_job("job-und-pf2")["status"] == "PURGE_FAILED"


# ---------------------------------------------------------------------------
# 收敛之后的路由补偿（Codex 2026-08-18 P1-4）
# ---------------------------------------------------------------------------

def _routing_item(site_id="s1"):
    return boto3.client("dynamodb", region_name="us-east-1").get_item(
        TableName="routing",
        Key={"subdomain": {"S": f"app-{site_id}"}}).get("Item")


def _put_committed_state(job_id="job-r1", site_id="s1"):
    """构造"路由已提交、job 里有完整 route_commit"的状态，返回切换前的旧路由。

    形态照 register_route 的产物：线上是本次 job 的新路由（static_prefix 带
    job_id、rev=4），job 记录里 route_commit 持久化了整值快照与提交锚。
    """
    import common
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    prev = {"subdomain": {"S": f"app-{site_id}"}, "site_id": {"S": site_id},
            "route_mode": {"S": "split"},
            "api_target": {"S": "https://b.lambda-url.us-east-1.on.aws"},
            "static_prefix": {"S": f"sites/{site_id}/job-old"},
            "require_auth": {"BOOL": True},
            "allowed_users": {"L": [{"S": "v@x.com"}]},
            "collaborators": {"L": []}, "owner": {"S": "u@x.com"},
            "permissions_rev": {"N": "4"}, "legacy_marker": {"S": "keep-me"}}
    committed = dict(prev)
    committed["api_target"] = {"S": "https://g.lambda-url.us-east-1.on.aws"}
    committed["static_prefix"] = {
        "S": common.static_prefix_for(site_id, job_id)}
    ddb.put_item(TableName="routing", Item=committed)     # 线上：新目标
    ddb.update_item(
        TableName="site-deploy-jobs", Key={"job_id": {"S": job_id}},
        UpdateExpression="SET route_commit = :rc",
        ExpressionAttributeValues={":rc": {"M": {
            "previous_route": {"M": prev},
            "committed_route": {"M": committed}}}})
    return prev


def test_timed_out_after_route_commit_restores_the_route(aws):
    """路由已提交后状态机 TIMED_OUT ⇒ 收敛 job **并且**把路由整值写回切换前。

    这是收敛闭环缺的另一半：TIMED_OUT/ABORTED 不执行任何 State，MarkFailed 的
    补偿没人做。只把 job 改成 FAILED 的后果有两层，且互相放大——路由停在这次
    从未通过验证的新目标上；而 job 一到 FAILED，部署租约立即可抢，下一次部署在
    一个"路由不是任何一次成功部署写下的"状态上开跑。

    红的条件：路由没被恢复（旧实现必红——converge 只改 job 状态）。
    """
    _put_job(status="RUNNING", phase="smoke-test")
    prev = _put_committed_state()

    out = reconcile_job.handler(_event("TIMED_OUT"), None)

    assert out["outcome"] == "converged"
    assert _get_job()["status"] == "FAILED"
    assert _routing_item() == prev, (
        "TIMED_OUT 之后路由没有恢复——仍停在未经验证的新目标上\n"
        f"  线上: {_routing_item()}")


def test_timed_out_before_route_commit_leaves_the_route_alone(aws):
    """route_commit 缺席（超时发生在 register_route 之前）⇒ 路由一个字不动。"""
    _put_job(status="RUNNING", phase="package")
    live = {"subdomain": {"S": "app-s1"},
            "api_target": {"S": "https://b.lambda-url.us-east-1.on.aws"},
            "static_prefix": {"S": "sites/s1/job-old"}}
    boto3.client("dynamodb", region_name="us-east-1").put_item(
        TableName="routing", Item=live)

    reconcile_job.handler(_event("TIMED_OUT"), None)

    assert _get_job()["status"] == "FAILED"
    assert _routing_item() == live, "没提交过路由却动了路由"


def test_compensation_abandons_when_a_newer_deploy_committed(aws):
    """超时 job 的补偿同样要认得"更晚的部署已提交"——放弃并如实写进 job。

    补偿函数与 MarkFailed **同一份**（mark_job._restore_route），所以提交端锚
    （static_prefix + rev）的全部判定这里自动生效。本用例锁的是 reconcile 这条
    调用路径没有绕过那些判定。
    """
    _put_job(status="RUNNING", phase="smoke-test")
    _put_committed_state()
    # 更晚的部署已经把路由换成了它自己的
    import common
    newer = {"subdomain": {"S": "app-s1"}, "site_id": {"S": "s1"},
             "api_target": {"S": "https://n.lambda-url.us-east-1.on.aws"},
             "static_prefix": {"S": common.static_prefix_for("s1", "job-newer")},
             "permissions_rev": {"N": "4"}}
    boto3.client("dynamodb", region_name="us-east-1").put_item(
        TableName="routing", Item=newer)

    reconcile_job.handler(_event("TIMED_OUT"), None)

    assert _routing_item() == newer, "把更晚那次成功部署的路由覆盖了"
    assert "人工" in _get_job()["error"], "补偿被放弃却没写进 job 错误信息"


def test_sweeper_compensates_a_failed_execution_after_commit(aws):
    """sweeper 路径同样要补偿：execution FAILED 而 job 还 RUNNING = MarkFailed
    自己重试耗尽都没跑成，路由补偿没人做过。"""
    _put_job(status="RUNNING", phase="smoke-test")
    prev = _put_committed_state()
    # 让 job 超龄
    old = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").update_item(
        Key={"job_id": "job-r1"}, UpdateExpression="SET updated_at = :t",
        ExpressionAttributeValues={":t": old})
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "FAILED"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        reconcile_job.sweeper_handler({}, None)

    assert _get_job()["status"] == "FAILED"
    assert _routing_item() == prev, "sweeper 收敛了 job 却没有恢复路由"


def test_reconciler_compensates_before_writing_the_terminal_state(aws, monkeypatch):
    """reconciler 同样**先补偿、后收敛**（Codex 2026-08-18 R4 P1-1）。

    converge 一写 FAILED 租约即可被抢，而补偿还没跑——与 MarkFailed 同一条
    顺序纪律。断言进入补偿那一刻 job 仍是 RUNNING。
    """
    _put_job(status="RUNNING", phase="smoke-test")
    prev = _put_committed_state()

    seen = {}
    import mark_job
    real = mark_job._restore_route

    def _spy(event):
        seen["status"] = _get_job()["status"]
        return real(event)

    monkeypatch.setattr(mark_job, "_restore_route", _spy)
    out = reconcile_job.handler(_event("TIMED_OUT"), None)

    assert out["outcome"] == "converged"
    assert seen.get("status") == "RUNNING", (
        f"进入补偿时 job 已是 {seen.get('status')}——租约此刻已可被抢")
    assert _get_job()["status"] == "FAILED"
    assert _routing_item() == prev


def test_sweeper_is_the_last_resort_for_a_persistently_failing_restore(aws,
                                                                      monkeypatch):
    """恢复的 AWS 调用持续失败时，sweeper 是**最后一环**：收敛 + 如实写 note，
    不再"保持 busy 重试"——那会把站点永久锁死。

    分工：MarkFailed 遇到恢复调用失败会**抛出**（保持 RUNNING，把重试预算交给
    SFN）；重试耗尽后 execution FAILED、job 还 RUNNING，落到这里。这里若也
    "保持 busy"，一个持久性的恢复故障（如 IAM 配错）= 站点无限期不可部署且
    没有任何用户可见的信号。收敛 + note 让操作者在 job 记录里看到确切处置。
    """
    import botocore.client
    _put_job(status="RUNNING", phase="compensating")
    _put_committed_state()
    old = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").update_item(
        Key={"job_id": "job-r1"}, UpdateExpression="SET updated_at = :t",
        ExpressionAttributeValues={":t": old})

    real = botocore.client.BaseClient._make_api_call

    def _boom(self, op, params):
        if op in ("PutItem", "DeleteItem") and params.get("TableName") == "routing":
            raise RuntimeError("ddb unavailable（注入）")
        return real(self, op, params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _boom)
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "FAILED"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        reconcile_job.sweeper_handler({}, None)

    job = _get_job()
    assert job["status"] == "FAILED", "最后一环也不收敛 = 站点永久锁死"
    assert "回滚请求失败" in job["error"], \
        f"收敛了却没如实告知路由可能没回滚：{job['error']!r}"


def test_last_resort_convergence_reports_a_failed_compensation_read(aws,
                                                                   monkeypatch):
    """最后一环（reconciler）补偿状态**读失败** ⇒ 仍收敛，但 job.error 必须带
    人工处置提示（Codex 2026-08-18 R5 P1）。

    折叠成 None 的后果：CloudWatch 里有"路由可能仍停在新目标"，job.error 里只有
    普通的"部署执行超时"——操作者完全不知道要去查路由。
    """
    import botocore.client
    _put_job(status="RUNNING", phase="smoke-test")
    _put_committed_state()

    real = botocore.client.BaseClient._make_api_call
    armed = {"on": True}

    def _boom(self, op, params):
        # 只打 jobs 表的 GetItem（route_commit 读）；converge 的 UpdateItem 照常
        if (armed["on"] and op == "GetItem"
                and params.get("TableName") == "site-deploy-jobs"):
            raise RuntimeError("jobs 读超时（注入）")
        return real(self, op, params)
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _boom)

    out = reconcile_job.handler(_event("TIMED_OUT"), None)
    armed["on"] = False          # 断言自己也要读 jobs 表

    assert out["outcome"] == "converged"
    job = _get_job()
    assert job["status"] == "FAILED", "最后一环必须收敛（否则永久锁站）"
    assert "回滚请求失败" in job["error"], (
        f"补偿状态读失败却没写人工处置提示，操作者不知道要查路由：{job['error']!r}")


def test_terminal_state_and_manual_note_land_in_one_write(aws, monkeypatch):
    """终态与人工处置提示必须在**同一个** UpdateItem 里落库（Codex 2026-08-19
    R6 P2）。

    分两笔写的失败形态：第一笔（FAILED + 普通超时文案）成功、第二笔（补提示）
    暂时失败 → 重试进来时 job 已 FAILED → 补偿因非 RUNNING 跳过、converge 是
    noop → 提示**再也没有机会写回**。一个已知"路由状态未知"的场景静默退化成
    普通超时——false-green 运维信号。

    断言两件事：① 最终 error 含提示；② 对 jobs 表**只有一笔**同时写 status 与
    error 的 UpdateItem（两笔写的实现即使内容最终对了也红——窗口本身就是缺陷）。
    """
    import botocore.client
    _put_job(status="RUNNING", phase="smoke-test")
    _put_committed_state()

    real = botocore.client.BaseClient._make_api_call
    writes = []

    def _spy(self, op, params):
        if (op == "UpdateItem"
                and params.get("TableName") == "site-deploy-jobs"
                and "job-r1" in str(params.get("Key"))):
            writes.append(params)
        # 让补偿的恢复写失败 ⇒ note = ROUTE_RESTORE_FAILED（要有提示可写）
        if op in ("PutItem", "DeleteItem") and params.get("TableName") == "routing":
            raise RuntimeError("ddb unavailable（注入）")
        return real(self, op, params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _spy)
    out = reconcile_job.handler(_event("TIMED_OUT"), None)

    assert out["outcome"] == "converged"
    job = _get_job()
    assert job["status"] == "FAILED"
    assert "回滚请求失败" in job["error"], f"提示丢了：{job['error']!r}"
    status_and_error = [
        w for w in writes
        if "status" in str(w.get("ExpressionAttributeNames", {}).values())
        and ":err" in str(w.get("ExpressionAttributeValues", {}))]
    error_writes = [w for w in writes
                    if "回滚请求失败" in str(w.get("ExpressionAttributeValues"))]
    assert len(error_writes) == 1 and error_writes[0] in status_and_error, (
        f"提示不在写终态的那一笔里（共 {len(writes)} 笔 UpdateItem）——"
        "两笔写之间第二笔失败即提示永久丢失")
