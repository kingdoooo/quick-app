#!/usr/bin/env python3
"""Step Functions 故障路径的真机验收：失败之后 job 是否留在**可恢复**状态。

为什么值得单独一个脚本：正常成功路径每次部署都在验，而故障路径几乎没人跑——
偏偏"job 永久停在 RUNNING、用户只能一直轮询"这类问题就藏在里面（上一轮的
StartExecution 失败与 ExecutionAlreadyExists 都是这个形态）。

判据统一成一句话：**任何终止（成功/失败/超时/中止）之后，job 都不能停在
RUNNING**。停在 RUNNING 意味着用户既看不到结果也无法重试。

F/G 两段验的是 SFN **终态收敛**（`reconcile_job` 的两层）：状态机级超时
（TIMED_OUT）与 StopExecution（ABORTED）**不执行任何 State**，add_catch 覆盖
不到，只能靠 EventBridge 实时层 + sweeper 定时层兜底。这两层只有真机能验——
事件投递与 DescribeExecution 都不是本地能造出来的。

只碰一次性探针数据（job_id 前缀 `job-sfnprobe-`），不动真实 job 与站点。
两处写操作各有**唯一入口 + 可执行闸门**（不是注释约定）：
  · StopExecution → stop_probe_execution（前缀 + 本轮 probe_jobs 双重检查）
  · 改 job 行     → probe_update（只允许本轮 probe_jobs 里的 job_id）
用 raise 而非 assert，`python -O` 下也不会被剔除。
用法：
    ./verify_sfn_failure_paths.py
    ./verify_sfn_failure_paths.py --keep    # 保留探针数据
"""
import argparse
import configparser
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/deployer/functions"))
sys.path.insert(0, str(ROOT / "site-builder/mcp"))
CFG_PATH = HERE.parent / "config.ini"


def read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


SUFFIX = uuid.uuid4().hex[:8]
results: list[tuple[bool, str, str]] = []
probe_jobs: set[str] = set()

# sweeper 的函数名在 infra/app.py 里硬编码（不进 config.ini），这里照抄。
SWEEPER_FN = "site-deployer-sweep-jobs"

# 只 Stop 名字带这个前缀的 execution——见 stop_probe_execution。
PROBE_PREFIX = "job-sfnprobe-"


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def stale_iso(minutes: int) -> str:
    """回拨 minutes 分钟的时间戳，格式与 common._now() 一致（可字典序比较）。

    G 段用它造"超龄"状态：sweeper 按 `updated_at < cutoff` 过滤
    （cutoff = now - STALE_MINUTES=45），不回拨的话它**正确地**跳过探针行，
    那条检查就变成验不到东西。
    """
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.parse_args()

    region = read_cfg("Platform", "region")
    os.environ.setdefault("AWS_DEFAULT_REGION", region)
    os.environ["JOBS_TABLE"] = read_cfg("Deployer", "jobs_table")
    os.environ["SITES_TABLE"] = read_cfg("Deployer", "sites_table")
    os.environ["ADMINS_TABLE"] = read_cfg("Deployer", "admins_table")
    os.environ["ROUTING_TABLE"] = read_cfg("Platform", "routing_table")
    os.environ["ARTIFACTS_BUCKET"] = read_cfg("Deployer", "artifacts_bucket")
    os.environ["BASE_DOMAIN"] = read_cfg("Platform", "base_domain")
    sm_arn = read_cfg("Deployer", "state_machine_arn")
    os.environ["STATE_MACHINE_ARN"] = sm_arn

    import boto3
    import botocore.exceptions
    from botocore.config import Config

    _RETRY = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    _oc = boto3.client
    boto3.client = lambda *a, **k: _oc(*a, **{**k, "config": k.get("config", _RETRY)})

    import common
    import reconcile_job  # 收敛语义的唯一定义：error 文案从这里取，不复制字面量
    import server        # MCP 薄壳：故障处置逻辑在这里

    sfn = boto3.client("stepfunctions", region_name=region)
    ddb = boto3.client("dynamodb", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    jobs_t = os.environ["JOBS_TABLE"]

    def new_probe_job(site_id: str) -> str:
        """建一条探针 job（不起真实部署）。"""
        jid = f"job-sfnprobe-{SUFFIX}-{uuid.uuid4().hex[:6]}"
        probe_jobs.add(jid)
        now = common._now()
        ddb.put_item(TableName=jobs_t, Item={
            "job_id": {"S": jid}, "site_id": {"S": site_id},
            "owner": {"S": f"sfnprobe-{SUFFIX}@example.invalid"},
            "status": {"S": "PENDING"}, "phase": {"S": "submitted"},
            "error": {"S": ""}, "url": {"S": ""},
            "created_at": {"S": now}, "updated_at": {"S": now}})
        return jid

    def job_of(jid: str) -> dict:
        it = ddb.get_item(TableName=jobs_t, Key={"job_id": {"S": jid}},
                          ConsistentRead=True).get("Item", {})
        return {k: list(v.values())[0] for k, v in it.items()}

    def poll_job_status(jid: str, want: str, *, timeout_s: int = 120) -> bool:
        """轮询强一致读，等 job 变成 want。**有界等待**——超时即返回 False
        让 check() 判失败，不能无限等（挂住的验收脚本读起来像通过）。"""
        deadline = time.time() + timeout_s
        while True:
            if job_of(jid).get("status") == want:
                return True
            if time.time() >= deadline:
                return False
            time.sleep(3)

    def probe_update(jid: str, expr: str, names: dict, values: dict) -> None:
        """改 job 行的**唯一入口**：不在本轮 probe_jobs 里的 job_id 一律拒绝。

        这是可执行闸门而非注释约定——F/G 段要把 job 改回 RUNNING、把
        updated_at 回拨，写错一个 id 就是在改真实用户的部署状态。
        """
        if jid not in probe_jobs:
            raise RuntimeError(f"拒绝改写非探针 job: {jid}")
        ddb.update_item(TableName=jobs_t, Key={"job_id": {"S": jid}},
                        UpdateExpression=expr,
                        ExpressionAttributeNames=names,
                        ExpressionAttributeValues=values)

    def stop_probe_execution(ex_arn: str) -> None:
        """StopExecution 的**唯一入口**，两道硬闸门都在代码里：

          ① 名字必须带 job-sfnprobe- 前缀；
          ② 名字必须在**本次运行**的 probe_jobs 里（光有前缀不够——并发的另一
             轮验收也叫 job-sfnprobe-，停别人的探针会让那一轮误判）。

        名字取自 ARN 末段：ARN 由 Step Functions 服务端填，调用方伪造不了。
        用 raise 而不是 assert——assert 在 `python -O` 下会被整条剔除，
        保护生产执行的闸门不能依赖解释器开关。
        """
        ex_name = ex_arn.rsplit(":", 1)[-1]
        if not ex_name.startswith(PROBE_PREFIX):
            raise RuntimeError(
                f"拒绝 stop_execution：{ex_name} 没有 {PROBE_PREFIX} 前缀")
        if ex_name not in probe_jobs:
            raise RuntimeError(
                f"拒绝 stop_execution：{ex_name} 不在本轮 probe_jobs 内")
        sfn.stop_execution(executionArn=ex_arn, cause=f"sfnprobe-{SUFFIX}")

    def invoke_sweeper() -> dict:
        """同步调 sweeper，返回它自己报的 {scanned, converged, orphans}。

        **必须查 FunctionError**：Lambda 内部抛异常时 invoke 仍返回 HTTP 200，
        只在 FunctionError 里体现。不查的话"权限不足导致 sweeper 根本没干活"
        会伪装成"job 没被收敛"，把错因指向完全错误的地方。
        """
        resp = lam.invoke(FunctionName=SWEEPER_FN,
                          InvocationType="RequestResponse", Payload=b"{}")
        raw = resp["Payload"].read().decode()
        if resp.get("FunctionError"):
            raise RuntimeError(f"{SWEEPER_FN} 执行出错: {raw[:300]}")
        return json.loads(raw)

    print(f"探针后缀 {SUFFIX}；状态机 {sm_arn.rsplit(':', 1)[-1]}")

    # ---------- A. 历史执行：终止后不得停在 RUNNING ----------
    print("\n── A 历史执行的终态与 job 状态一致 ─────────────────")
    # **必须翻页**：原来只取 maxResults=60 却声称"所有已终止执行"，名不副实
    # （2026-08-08 独立审查指出）。执行数会随时间增长，不翻页迟早漏掉尾部。
    execs = []
    token = None
    while True:
        kw = {"stateMachineArn": sm_arn, "maxResults": 100}
        if token:
            kw["nextToken"] = token
        resp = sfn.list_executions(**kw)
        execs.extend(resp.get("executions", []))
        token = resp.get("nextToken")
        if not token:
            break
    by_status: dict[str, int] = {}
    for e in execs:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
    print(f"  历史执行分布（共 {len(execs)} 条）: {by_status}")
    stuck, absent = [], []
    for e in execs:
        if e["status"] in ("RUNNING",):
            continue
        j = job_of(e["name"])          # execution name == job_id（幂等设计）
        if not j:
            # **"job 行不存在"是未知，不是通过**：原来 `if j and ...` 把它
            # 静默跳过。undeploy 会删 job 行，所以这类是正常的，但必须报出
            # 数量，否则"检查了 N 条"里有多少条其实没检查是看不见的。
            absent.append(e["name"])
            continue
        if j.get("status") == "RUNNING":
            stuck.append((e["name"], e["status"], j.get("phase")))
    check(not stuck,
          "所有已终止执行对应的 job 都不停在 RUNNING",
          f"卡住的: {stuck[:3]}" if stuck
          else f"检查了 {len(execs) - len(absent)} 条，{len(absent)} 条 job 行已删除（未检查）")
    # TIMED_OUT/ABORTED **不再是缺陷**（M3 前置 B1 起由 reconciler 两层收敛）。
    # 判据从"存在即失败"改成"存在即必须已被收敛"——而"已被收敛"正是上面第一条
    # check 的内容（终止执行对应的 job 不停在 RUNNING），它已覆盖这些执行。
    #
    # **不能保留原来的"存在 TIMED_OUT/ABORTED 即 FAIL"**：本脚本 F 段自己就会
    # 造 ABORTED 探针执行，那条判据会让**下一次**运行必然红——脚本自我否定，
    # 不是缺陷。（探针 job 行跑完就删，但 execution 记录会留在 SFN 历史里，
    # list_executions 仍看得到；90 天后过期。）
    uncaught = {s: n for s, n in by_status.items()
                if s in ("TIMED_OUT", "ABORTED")}
    if uncaught:
        print(f"  ⓘ 历史上有 {uncaught} 执行；它们的 job 落账情况已由上一条"
              "check 覆盖（含本脚本 F 段留下的探针）")
    else:
        print("  ⓘ 历史上没有 TIMED_OUT/ABORTED 执行；F/G 两段会主动造一个来验")

    # ---------- B. StartExecution 失败后可重试 ----------
    print("\n── B StartExecution 失败 → job 退回 PENDING，可重试 ────")
    jid = new_probe_job(f"sfnprobe-{SUFFIX}")
    # 直接驱动回滚函数：它是失败处置的唯一入口
    probe_update(jid, "SET #s = :r, phase = :q", {"#s": "status"},
                 {":r": {"S": "RUNNING"}, ":q": {"S": "queued"}})
    server._rollback_job_to_pending(jid)
    check(job_of(jid).get("status") == "PENDING",
          "刚置 RUNNING/queued 的 job 可被回滚成 PENDING",
          f"status={job_of(jid).get('status')}")

    # ---------- C. 回滚不得踩掉真在推进的部署 ----------
    print("\n── C 回滚条件足够窄：已推进的 job 不受影响 ─────────")
    jid2 = new_probe_job(f"sfnprobe-{SUFFIX}")
    probe_update(jid2, "SET #s = :r, phase = :p", {"#s": "status"},
                 {":r": {"S": "RUNNING"}, ":p": {"S": "validate"}})
    server._rollback_job_to_pending(jid2)
    j2 = job_of(jid2)
    check(j2.get("status") == "RUNNING" and j2.get("phase") == "validate",
          "phase 已推进（SFN 在跑）→ 回滚是 no-op",
          f"status={j2.get('status')} phase={j2.get('phase')}")

    jid3 = new_probe_job(f"sfnprobe-{SUFFIX}")
    probe_update(jid3, "SET #s = :s, phase = :p, #u = :u",
                 {"#s": "status", "#u": "url"},
                 {":s": {"S": "SUCCEEDED"}, ":p": {"S": "done"},
                  ":u": {"S": "https://probe.invalid/"}})
    server._rollback_job_to_pending(jid3)
    check(job_of(jid3).get("status") == "SUCCEEDED",
          "已 SUCCEEDED 的 job → 回滚是 no-op（终态不被覆盖）")

    # ---------- D. 同名 execution 已关闭：不得留下假 RUNNING ----------
    print("\n── D 同名 execution 已关闭 → 如实 FAILED，不留假 RUNNING ──")
    # 用一个**已经跑完**的真实 execution 名字来触发 ExecutionAlreadyExists：
    # 这是真机独有的验证——moto 造不出"名字已被 90 天内关闭的执行占用"。
    done = [e for e in execs if e["status"] in ("SUCCEEDED", "FAILED")]
    if not done:
        print("  ⚠️  历史上没有已结束的执行，跳过（不算通过也不算失败）")
    else:
        taken = done[0]["name"]
        try:
            sfn.start_execution(stateMachineArn=sm_arn, name=taken,
                                input=json.dumps({"probe": SUFFIX}))
            check(False, "复用已关闭执行的名字竟然成功了",
                  "契约变了，本脚本的前提需重新核对")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            check(code == "ExecutionAlreadyExists",
                  "复用已关闭执行的名字 → ExecutionAlreadyExists",
                  f"实际 {code}；证明'收到该错误即执行已关闭'这条推论成立")

    # ---------- E. 30 分钟状态机超时的覆盖缺口 ----------
    print("\n── E 状态机级超时/中止的覆盖情况 ───────────────────")
    definition = sfn.describe_state_machine(stateMachineArn=sm_arn)
    body = json.loads(definition["definition"])
    top_timeout = body.get("TimeoutSeconds")
    has_catch = any("Catch" in s for s in body.get("States", {}).values())
    check(has_catch, "各步骤有 Catch → 步骤内失败会走 MarkFailed 落账")
    # Catch 只覆盖步骤抛错；状态机级 TimeoutSeconds 到点与人工 StopExecution
    # 都不执行任何 State，mark_job 不被调用。该缺口由 F/G 两段验证的
    # **两层收敛**闭合（M3 前置 B1）。
    print(f"  ⓘ 状态机 TimeoutSeconds={top_timeout}（30 分钟）。"
          "超时与 StopExecution **不触发** Catch，")
    print("    需靠 reconciler 两层收敛落账 —— 见下面 F（实时层）与 G（兜底层）。")

    # ---------- F. 实时层：EventBridge reconciler ----------
    print("\n── F 实时层：EventBridge → reconciler 收敛 ABORTED ────")
    # **绝不 Stop 任何真实生产部署**：StopExecution 只经 stop_probe_execution
    # （前缀 + 本轮 probe_jobs 双闸门，用 raise 不用 assert）。
    def abort_probe_execution(attempts: int = 4) -> tuple[str, str | None]:
        """造出"execution 已终态、job 仍 RUNNING"的探针。

        返回 (job_id, execution 终态)；execution 完全没起来时终态为 None。
        调用方**按终态分别把门**（两层的前提不同，不能共用一个布尔）：
          · F（实时层）要 ABORTED —— rule 只匹配 TIMED_OUT/ABORTED；
          · G（兜底层）任何终态都行 —— sweeper 按 DescribeExecution 收敛
            FAILED/TIMED_OUT/ABORTED 三者。

        每次尝试都**新建一条探针 job 并让 execution 与它同名**（execution name
        == job_id 是平台既有不变量，reconciler 正是靠它从 ARN 反推 job_id）。
        重试必须连 job 行一起换，不能只给执行名加后缀：那样名字与 job 行对不上，
        reconciler 会去收敛一个不存在的 job（返回 absent），断言随即失败，
        看起来像"收敛坏了"，其实是探针自己搭错了。

        竞速：探针 input **刻意不含 job_id**，于是 Validate 第一行
        `event["job_id"]` 立即 KeyError；add_catch 转到 MarkFailed，而 mark_job
        同样读 event["job_id"]，也 KeyError——**没有任何写入者会碰探针行**，
        error 文案的归属因此不会被混淆（这正是 F 段第三条断言的立足点）。
        代价是这条执行失败得很快，start 之后立刻 stop 未必抢得到；抢不到时终态
        是 FAILED 而非 ABORTED，rule 不匹配 FAILED，实时层就没有事件可验。
        故最多试 attempts 次，仍拿不到 ABORTED 就如实报"无法验证"，
        绝不退化成宽松断言。

        （反过来说，input 里放 job_id 会让 Validate 把 phase 改成 validate、
        让 MarkFailed 把 status 写成 FAILED——F 段三条断言都变成在验别的写入者。
        别"顺手补上"这个字段。）
        """
        st = None
        jid = ""
        for i in range(attempts):
            jid = new_probe_job(f"sfnprobe-{SUFFIX}")
            # phase 刻意用 package（**不是 queued**）：证明任意 phase 都能收敛，
            # 即没有照抄 _rollback_job_to_pending 的 phase=queued 条件。
            probe_update(jid, "SET #s = :r, phase = :p", {"#s": "status"},
                         {":r": {"S": "RUNNING"}, ":p": {"S": "package"}})
            try:
                arn = sfn.start_execution(
                    stateMachineArn=sm_arn, name=jid,
                    input=json.dumps({"probe": SUFFIX}))["executionArn"]
            except botocore.exceptions.ClientError as e:
                # 起不来就如实记一项失败并返回，让调用方跳过后续断言，
                # 而不是抛异常中断整个脚本（cleanup 必须照常跑）。
                check(False, "起探针 execution 失败（F/G 段无法验证）",
                      e.response["Error"]["Code"])
                return jid, None
            stop_probe_execution(arn)   # 两道硬闸门在该函数内（raise，不用 assert）
            for _ in range(20):
                st = sfn.describe_execution(executionArn=arn)["status"]
                if st != "RUNNING":
                    break
                time.sleep(1)
            if st == "ABORTED":
                return jid, st
            print(f"  ⓘ 第 {i + 1} 次探针执行终态是 {st}（没抢在 Validate 快速"
                  f"失败之前停下）"
                  + ("，换一条探针重试" if i + 1 < attempts else "，不再重试"))
        return jid, st

    probe_recon, ex_status = abort_probe_execution()
    if ex_status is not None and ex_status != "ABORTED":
        # 没抢到 ABORTED：如实报"无法验证实时层"，**不要**退化成
        # "断言 job 是 FAILED"——那条断言可能由别的写入者满足，
        # 读起来像通过而 reconciler 根本没跑。
        check(False, "探针执行未能进入 ABORTED（F 段无法验证实时层）",
              f"最后一次终态={ex_status}；rule 只匹配 TIMED_OUT/ABORTED")

    if ex_status == "ABORTED":
        converged = poll_job_status(probe_recon, "FAILED", timeout_s=120)
        check(converged, "EventBridge reconciler 把 ABORTED 收敛成 FAILED",
              f"job={probe_recon}")
        j = job_of(probe_recon)
        check(j.get("phase") == "package",
              "收敛保留最后 phase（非 queued 也能收敛）",
              f"phase={j.get('phase')}")
        # **逐字匹配 reconciler 的固定文案，不能只断言"非空且不含 ARN"**：
        # 宽松判据下，任何把 error 写成非空的写入者都能让这条 PASS，
        # reconciler 究竟有没有收敛就看不出来了。文案从 reconcile_job 取
        # （收敛语义的唯一定义），不在本脚本复制字面量——否则改文案时这里会
        # 悄悄失配成红，或更糟：判据与实现各说各话。
        err = j.get("error", "")
        expected = (reconcile_job.ABORT_ERROR, reconcile_job.TIMEOUT_ERROR)
        is_recon_copy = err in expected
        check(is_recon_copy and "arn:aws" not in err,
              "error 是 reconciler 的固定文案（不含 ARN，且证明确由它写入）",
              "逐字匹配 ABORT_ERROR/TIMEOUT_ERROR" if is_recon_copy
              else f"非 reconciler 文案: {err[:60]}")

    # ---------- G. 兜底层：周期 sweeper ----------
    print("\n── G 兜底层：sweeper 收敛\"执行已终态、job 仍 RUNNING\" ──")
    # 这一层的前提比 F 宽：sweeper 按 DescribeExecution 的真实状态收敛
    # FAILED/TIMED_OUT/ABORTED 三者，所以上面竞速输了（终态 FAILED）也能验。
    if ex_status in ("ABORTED", "FAILED", "TIMED_OUT"):
        # 造出缺口本身：execution 已终态，把 job 改回 RUNNING，并把 updated_at
        # 回拨到超龄阈值（STALE_MINUTES=45）之前——不回拨的话 sweeper 会
        # **正确地**跳过它，那样验的就不是收敛能力而是"什么都没发生"。
        probe_update(probe_recon, "SET #s = :r, updated_at = :old",
                     {"#s": "status"},
                     {":r": {"S": "RUNNING"}, ":old": {"S": stale_iso(90)}})
        swept = invoke_sweeper()      # 内部查 FunctionError，异常不会伪装成"没收敛"
        check(poll_job_status(probe_recon, "FAILED", timeout_s=60),
              "sweeper 收敛 execution 已终态但 job 仍 RUNNING 的缺口",
              f"job={probe_recon}，execution 终态={ex_status}，sweeper 自报 {swept}")
    else:
        check(False, "sweeper 收敛验证未执行（探针 execution 没起来）",
              f"execution 终态={ex_status}")

    # 未超龄的 RUNNING 不能被动——否则正在跑的真实部署会被误杀成 FAILED
    fresh = new_probe_job(f"sfnprobe-{SUFFIX}")
    probe_update(fresh, "SET #s = :r, updated_at = :now", {"#s": "status"},
                 {":r": {"S": "RUNNING"}, ":now": {"S": common._now()}})
    invoke_sweeper()
    still = job_of(fresh).get("status")
    check(still == "RUNNING",
          "sweeper 不动未超龄的 RUNNING（防误杀在跑的部署）",
          f"status={still}")

    return 0


def cleanup(region: str, keep: bool) -> int:
    import boto3
    if keep:
        print(f"\n── 清理 ──\n  --keep：保留探针 job（后缀 {SUFFIX}）")
        return 0
    print("\n── 清理 ──────────────────────────────────────────")
    ddb = boto3.client("dynamodb", region_name=region)
    left = 0
    for jid in sorted(probe_jobs):
        try:
            ddb.delete_item(TableName=os.environ["JOBS_TABLE"],
                            Key={"job_id": {"S": jid}})
        except Exception as exc:            # noqa: BLE001
            print(f"  ⚠️  删除 {jid} 失败: {exc}")
    for jid in sorted(probe_jobs):
        got = ddb.get_item(TableName=os.environ["JOBS_TABLE"],
                           Key={"job_id": {"S": jid}}, ConsistentRead=True)
        if "Item" in got:
            print(f"  ⚠️  {jid} 仍存在 —— 手工删除")
            left += 1
    print("  探针 job 已清理并核对" if not left else f"  {left} 项残留")
    return left


if __name__ == "__main__":
    _keep = "--keep" in sys.argv
    _region = read_cfg("Platform", "region")
    rc = 1
    try:
        rc = main()
    except Exception:                       # noqa: BLE001
        import traceback
        traceback.print_exc()
        rc = 1
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        left = cleanup(_region, _keep and failed > 0)
        # 下限存在的理由：脚本中途崩溃/凭证失效时 results 会很短，
        # 而"0/0 项通过"读起来像成功。
        #
        # 11 = **全绿路径应产出的条数**，不是 check() 的静态个数（15）：
        # 有 4 处是互斥分支或只在故障时触发，全绿时不执行——
        #   A 第 2 项  已改成 print（TIMED_OUT/ABORTED 不再算缺陷，见 A 段注释）
        #   D 两项     start 成功 / ExecutionAlreadyExists 二者只中一个
        #   F 起执行失败、F 未拿到 ABORTED、G 探针没起来：三条都是 check(False)
        # 全绿明细：A1 + B1 + C2 + D1 + E1 + F3 + G2 = 11。
        #
        # 该数先由读代码逐段推算，2026-08-09 真机跑出 **11/11** 得到确认
        # （计划书里写的 12 是按静态条数估的，与分支结构不符）。
        # 增删 check 时同步这个数。
        # 另注：D 段在"状态机从未有已结束执行"的空账号上产出 0 项，
        # 那种情况下即使一切正常也会触发下限——属预期（无历史即无法验 D）。
        MIN_CHECKS = 11
        print()
        if len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）—— "
                  "验收**未完成**，状态不可信")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else "")
                  + (f"，{left} 项残留" if left else ""))
            if failed or left:
                rc = 1
    sys.exit(rc)
