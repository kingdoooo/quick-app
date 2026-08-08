#!/usr/bin/env python3
"""Step Functions 故障路径的真机验收：失败之后 job 是否留在**可恢复**状态。

为什么值得单独一个脚本：正常成功路径每次部署都在验，而故障路径几乎没人跑——
偏偏"job 永久停在 RUNNING、用户只能一直轮询"这类问题就藏在里面（上一轮的
StartExecution 失败与 ExecutionAlreadyExists 都是这个形态）。

判据统一成一句话：**任何终止（成功/失败/超时/中止）之后，job 都不能停在
RUNNING**。停在 RUNNING 意味着用户既看不到结果也无法重试。

只碰一次性探针数据（job_id 前缀 `job-sfnprobe-`），不动真实 job 与站点。
用法：
    ./verify_sfn_failure_paths.py
    ./verify_sfn_failure_paths.py --keep    # 保留探针数据
"""
import argparse
import configparser
import json
import os
import sys
import uuid
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


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


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
    import server        # MCP 薄壳：故障处置逻辑在这里

    sfn = boto3.client("stepfunctions", region_name=region)
    ddb = boto3.client("dynamodb", region_name=region)
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
    # 未被 add_catch 覆盖的终态是已知缺口：明确报告而不是假装没有
    uncaught = {s: n for s, n in by_status.items()
                if s in ("TIMED_OUT", "ABORTED")}
    if uncaught:
        check(False, "存在 TIMED_OUT/ABORTED 执行（add_catch 覆盖不到）",
              f"{uncaught} —— 这类执行不会调用 MarkFailed，job 会停在 RUNNING")
    else:
        print(f"  ⓘ 历史上没有 TIMED_OUT/ABORTED 执行；该缺口仍在（见 D）")

    # ---------- B. StartExecution 失败后可重试 ----------
    print("\n── B StartExecution 失败 → job 退回 PENDING，可重试 ────")
    jid = new_probe_job(f"sfnprobe-{SUFFIX}")
    # 直接驱动回滚函数：它是失败处置的唯一入口
    ddb.update_item(TableName=jobs_t, Key={"job_id": {"S": jid}},
                    UpdateExpression="SET #s = :r, phase = :q",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":r": {"S": "RUNNING"},
                                               ":q": {"S": "queued"}})
    server._rollback_job_to_pending(jid)
    check(job_of(jid).get("status") == "PENDING",
          "刚置 RUNNING/queued 的 job 可被回滚成 PENDING",
          f"status={job_of(jid).get('status')}")

    # ---------- C. 回滚不得踩掉真在推进的部署 ----------
    print("\n── C 回滚条件足够窄：已推进的 job 不受影响 ─────────")
    jid2 = new_probe_job(f"sfnprobe-{SUFFIX}")
    ddb.update_item(TableName=jobs_t, Key={"job_id": {"S": jid2}},
                    UpdateExpression="SET #s = :r, phase = :p",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":r": {"S": "RUNNING"},
                                               ":p": {"S": "validate"}})
    server._rollback_job_to_pending(jid2)
    j2 = job_of(jid2)
    check(j2.get("status") == "RUNNING" and j2.get("phase") == "validate",
          "phase 已推进（SFN 在跑）→ 回滚是 no-op",
          f"status={j2.get('status')} phase={j2.get('phase')}")

    jid3 = new_probe_job(f"sfnprobe-{SUFFIX}")
    ddb.update_item(TableName=jobs_t, Key={"job_id": {"S": jid3}},
                    UpdateExpression="SET #s = :s, phase = :p, #u = :u",
                    ExpressionAttributeNames={"#s": "status", "#u": "url"},
                    ExpressionAttributeValues={
                        ":s": {"S": "SUCCEEDED"}, ":p": {"S": "done"},
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
    # **这不是"通过"，是如实报告一个已知缺口**：Catch 只覆盖步骤抛错，
    # 状态机级 TimeoutSeconds 到点、或人工 StopExecution，都不会执行任何 State，
    # 于是 mark_job 不会被调用，job 停在 RUNNING。
    print(f"  ⓘ 状态机 TimeoutSeconds={top_timeout}（30 分钟）。"
          "超时与 StopExecution **不触发** Catch，")
    print("    job 会停在 RUNNING。要闭合需要 EventBridge 订阅"
          "Step Functions 执行状态变更 →")
    print("    对 TIMED_OUT/ABORTED 把 job 落成 FAILED。属未实现项，"
          "见 DEPLOY.md 的说明。")

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
        MIN_CHECKS = 6
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
