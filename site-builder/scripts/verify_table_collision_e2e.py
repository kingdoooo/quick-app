#!/usr/bin/env python3
"""表名碰撞的真机 E2E 闸门（部署后可随时跑；自建两个一次性站点、跑完自清理）。

构造碰撞对（构造在 `collision_pair`，前提由单测锁住）：

    A: site_id=clsn-{a6}        logical={b6}-notes ┐
    B: site_id=clsn-{a6}-{b6}   logical=notes      ┴→ site-data-clsn-{a6}-{b6}-notes

证明五件事：① B 正常部署成功（正对照：合法路径没被弄坏）；② A 的碰撞 manifest
被**线上 validate** 拒绝（错误信息是 TABLE_NAME_RE 的原话）；③ 失败后 A 侧零资源
残留；④ B 侧逐字段不变（表 schema/tags/role policy/data_tables）；⑤ purge 三态
幂等——真实 purge 成功后**对已购清站点重复 purge 收敛到 DELETED**（修复前是
PURGE_FAILED，Codex 复审 8f8b0c6 的 P2-1）。

**证据等级**：真实 AWS 行为。**范围界定**（别把它说成别的）：清理与幂等探针走的
是直接 Event 调 `site-deployer-undeploy`（复刻 MCP 建 job 之后的动作，**绕过**
MCP/panel 的鉴权入口）——它证明**部署函数**的行为（purge 三态/归属核验），不是
MCP 授权链路的 E2E（那由 verify_api_key_e2e.py 覆盖）。

实测过的两个坑（2026-08-24 首轮探针）：失败 job 的终态 phase 是 `compensating`
不是 `validate`（SFN 失败后走补偿步；拒绝点看 error 原话）；DeleteTable 是异步的
（DELETING 态还能 describe 到），幂等重试探针必须先等 `table_not_exists`。

sites/jobs 的 DELETED 历史行**保留**（与既有 fixture E2E 同一口径）；表/角色/路由
必须清零，finally 里强一致读回核对。

用法：
    python3 site-builder/scripts/verify_table_collision_e2e.py
    python3 site-builder/scripts/verify_table_collision_e2e.py --json-out /tmp/x.json
"""
import argparse
import configparser
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
SB = HERE.parent                      # site-builder/
ROOT = SB.parent                      # 仓库根

# 表名格式的唯一定义在 common.site_table_name——本脚本不手拼
# （`test_table_name_format_has_a_single_definition` 按 AST 钉死）。
sys.path.insert(0, str(SB / "deployer" / "functions"))
import common as sb_common            # noqa: E402

# **一项都没跑完 ≠ 通过**：低于下限一律不可信（与 verify_permission_matrix 同款）。
MIN_CHECKS = 23

results: list[tuple[bool, str, str]] = []
SUMMARY: dict = {"pair": {}, "jobs": {}, "leftover": None}


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((bool(ok), name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


class CollisionPair(NamedTuple):
    site_a: str
    site_b: str
    logical_a: str
    physical: str          # 两个站点共同拼出的物理表名


def collision_pair(a6: str, b6: str) -> CollisionPair:
    """碰撞对的唯一构造。单测锁两条前提：A/B 真的拼出同一物理名；A 的逻辑名
    正是 TABLE_NAME_RE 要拒的形态（改成合法名会让探针测一个假阴性）。

    物理名从 B 侧经 `site_table_name` 推导（logical=notes 合法）；A 侧的
    等价拼法 `site-data-{site_a}-{logical_a}` 没法走它（连字符会被拒——那正是
    攻击形态），等式由单测独立手拼核对。"""
    site_a = f"clsn-{a6}"
    site_b = f"clsn-{a6}-{b6}"
    return CollisionPair(site_a, site_b, f"{b6}-notes",
                         sb_common.site_table_name(site_b, "notes"))


def _cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(SB / "config.ini")
    try:
        return c[section][key].split("#")[0].strip()
    except KeyError as e:
        raise SystemExit(f"config.ini 缺少 {e}") from e


def _assert_target_account(boto3, region: str, expected: str) -> None:
    """与 `[Platform] account_id` **严格相等**（同 verify_site_table_integrity）。
    跑错账号时"全 FAIL"读起来像故障，"全绿"更糟——空账号里断言平凡成立。"""
    acct = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    if acct != expected:
        raise SystemExit(
            f"当前凭证账号（…{acct[-4:]}）不是 config.ini 的 [Platform] "
            f"account_id（…{expected[-4:]}）——中止。先确认 AWS_PROFILE / 凭证。")


def _site_data_tables(ddb, prefix: str) -> list[str]:
    """ListTables **分页**取（单页上限 100，账号表多时不翻页会静默漏）。"""
    names, kw = [], {}
    while True:
        page = ddb.list_tables(**kw)
        names += [t for t in page["TableNames"] if t.startswith(prefix)]
        if "LastEvaluatedTableName" not in page:
            return names
        kw["ExclusiveStartTableName"] = page["LastEvaluatedTableName"]


def _role_policies(iam, role: str) -> dict:
    pols = {}
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role):
        for n in page["PolicyNames"]:
            pols[n] = iam.get_role_policy(RoleName=role,
                                          PolicyName=n)["PolicyDocument"]
    return pols


def snapshot_table_tags(ddb, table_arn: str) -> list:
    """B 侧快照的 tag 读取。必须走 `common.table_tags`（分页 + 读不到即抛）——
    裸 `list_tags_of_resource` 不翻页，tag 多于一页时快照会拿到不完整集合，
    "前后一致"的比较就退化成"前后同样不完整"。read_attempts=1：这张表不是
    刚建的，没有 tag 可见性延迟可等。接线由
    `deployer/tests/test_verify_table_collision_e2e.py` 钉住。"""
    return sorted(sb_common.table_tags(ddb, table_arn, read_attempts=1).items())


def main() -> int:
    import boto3

    ap = argparse.ArgumentParser()
    ap.add_argument("--json-out", help="把结构化摘要另存到该路径")
    args = ap.parse_args()

    region = _cfg("Platform", "region")
    account = _cfg("Platform", "account_id")
    sites_t = _cfg("Deployer", "sites_table")
    jobs_t = _cfg("Deployer", "jobs_table")
    routes_t = _cfg("Platform", "routing_table")
    _assert_target_account(boto3, region, account)

    ddb = boto3.client("dynamodb", region_name=region)
    res = boto3.resource("dynamodb", region_name=region)
    iam = boto3.client("iam")
    lam = boto3.client("lambda", region_name=region)

    pair = collision_pair(secrets.token_hex(3), secrets.token_hex(3))
    SUMMARY["pair"] = pair._asdict()
    print(f"碰撞对：A={pair.site_a} (logical {pair.logical_a}) / "
          f"B={pair.site_b} (logical notes)")
    print(f"碰撞物理表名：{pair.physical}\n")

    def deploy_fixture(fixture_dir: Path, site_id: str) -> tuple[int, str]:
        p = subprocess.run(
            [sys.executable, str(HERE / "deploy_fixture.py"), str(fixture_dir),
             "--site-id", site_id, "--owner", "probe@collision"],
            capture_output=True, text=True, timeout=900)
        return p.returncode, p.stdout + p.stderr

    def jobs_for(site_id: str) -> list[dict]:
        out, kw = [], {}
        t = res.Table(jobs_t)
        while True:
            page = t.scan(FilterExpression="site_id = :s",
                          ExpressionAttributeValues={":s": site_id}, **kw)
            out += page.get("Items", [])
            if "LastEvaluatedKey" not in page:
                return sorted(out, key=lambda j: str(j.get("created_at", "")))
            kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def undeploy(site_id: str, *, purge_data: bool,
                 data_tables=None, tag: str = "") -> dict:
        """复刻 MCP 建 job 后的动作：RUNNING+kind=undeploy 落库 → Event 调
        site-deployer-undeploy → 轮询终态。探针站点无并发，省去租约事务。"""
        job_id = f"probe-clsn-{secrets.token_hex(4)}"
        SUMMARY["jobs"][tag or f"undeploy-{site_id}"] = job_id
        res.Table(jobs_t).put_item(Item={
            "job_id": job_id, "site_id": site_id, "status": "RUNNING",
            "kind": "undeploy", "owner": "probe@collision",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        payload: dict = {"job_id": job_id, "site_id": site_id}
        if purge_data:
            payload["purge_data"] = True
        if data_tables is not None:
            payload["data_tables"] = data_tables
        lam.invoke(FunctionName="site-deployer-undeploy",
                   InvocationType="Event", Payload=json.dumps(payload))
        deadline = time.time() + 180
        while time.time() < deadline:
            job = res.Table(jobs_t).get_item(
                Key={"job_id": job_id}, ConsistentRead=True).get("Item", {})
            if job.get("status") in ("DELETED", "PURGE_FAILED", "FAILED"):
                return job
            time.sleep(5)
        return {"status": "TIMEOUT", "job_id": job_id}

    def table_exists(name: str) -> bool:
        try:
            ddb.describe_table(TableName=name)
            return True
        except ddb.exceptions.ResourceNotFoundException:
            return False

    def role_exists(name: str) -> bool:
        try:
            iam.get_role(RoleName=name)
            return True
        except iam.exceptions.NoSuchEntityException:
            return False

    def route_exists(site_id: str) -> bool:
        got = ddb.get_item(TableName=routes_t,
                           Key={"subdomain": {"S": f"app-{site_id}"}},
                           ConsistentRead=True)
        return "Item" in got

    def snapshot_b() -> dict:
        t = ddb.describe_table(TableName=pair.physical)["Table"]
        tags = snapshot_table_tags(ddb, t["TableArn"])
        row = res.Table(sites_t).get_item(Key={"site_id": pair.site_b},
                                          ConsistentRead=True)["Item"]
        return {"key_schema": t["KeySchema"], "attrs": t["AttributeDefinitions"],
                "status": t["TableStatus"], "arn": t["TableArn"], "tags": tags,
                "policies": _role_policies(iam, f"site-rt-{pair.site_b}"),
                "data_tables": sorted(row.get("data_tables", []))}

    state = {"b_deployed": False, "b_purged": False,
             "a_attempted": False, "a_cleaned": False}
    try:
        print("── ① B 正常部署（正对照：合法路径没被弄坏）──")
        rc, out = deploy_fixture(SB / "fixtures/nosql-notes", pair.site_b)
        state["b_deployed"] = True          # 半成品也要进 finally 清理
        check(rc == 0, "B 部署 SUCCEEDED",
              "" if rc == 0 else out.strip().splitlines()[-1][:100])
        if rc != 0:
            print(out[-3000:])
            return 1
        b_jobs = jobs_for(pair.site_b)
        SUMMARY["jobs"]["deploy-b"] = str(b_jobs[-1]["job_id"]) if b_jobs else "?"
        check(table_exists(pair.physical), "B 的表已创建", pair.physical)
        before = snapshot_b()

        print("\n── ② A 的碰撞 manifest 必须被线上 validate 拒绝 ──")
        with tempfile.TemporaryDirectory(prefix="clsn-probe-") as td:
            base = Path(td)
            tmp = base / "fixture-a"
            shutil.copytree(SB / "fixtures/nosql-notes", tmp)
            # run.sh 在 fixtures 的父目录共享，deploy_fixture 从 fixture 的
            # parent 取——丢了它会在**本地打包**就失败，探针会把那误当成
            # "线上 validate 拒绝"（2026-08-24 实测踩过）
            shutil.copy2(SB / "fixtures/run.sh", base / "run.sh")
            manifest = json.loads((tmp / "site.json").read_text())
            manifest["database"]["tables"][0]["name"] = pair.logical_a
            (tmp / "site.json").write_text(json.dumps(manifest,
                                                      ensure_ascii=False))
            state["a_attempted"] = True
            rc, out = deploy_fixture(tmp, pair.site_a)
        check(rc != 0, "A 部署失败（预期）", f"rc={rc}")
        a_jobs = jobs_for(pair.site_a)
        job_a = a_jobs[-1] if a_jobs else {}
        SUMMARY["jobs"]["deploy-a-rejected"] = str(job_a.get("job_id", "?"))
        check(job_a.get("status") == "FAILED", "A 的 job 状态是 FAILED",
              f"status={job_a.get('status')} phase={job_a.get('phase')}")
        check(job_a.get("phase") in ("validate", "compensating"),
              "失败终态的 phase 是 validate 或其后的补偿步",
              f"phase={job_a.get('phase')}")
        err = str(job_a.get("error", ""))
        check("连字符" in err and "表名" in err,
              "错误信息是线上 validate 的表名字符集规则原话", err[:100])

        print("\n── ③ A 侧零残留 ──")
        check(not role_exists(f"site-rt-{pair.site_a}"),
              f"没有 site-rt-{pair.site_a} 角色")
        # A 侧前缀也从唯一定义推导（去掉哨兵 logical），不手拼 site-data- 格式
        a_prefix = sb_common.site_table_name(pair.site_a, "probe")[:-len("probe")]
        a_tables = _site_data_tables(ddb, a_prefix)
        check(not [t for t in a_tables if t != pair.physical],
              "A 前缀下只有 B 的表（碰撞名），没有新表", str(a_tables))
        row_a = res.Table(sites_t).get_item(Key={"site_id": pair.site_a},
                                            ConsistentRead=True).get("Item")
        check(row_a is not None and "data_tables" not in row_a,
              "A 的 sites 行存在（DEPLOYING 历史）且没有 data_tables",
              f"row={'缺失' if row_a is None else str(sorted(row_a.keys()))[:70]}")
        check(not route_exists(pair.site_a), "A 没有路由")

        print("\n── ④ B 侧逐字段不变 ──")
        after = snapshot_b()
        for k in before:
            check(before[k] == after[k], f"B 的 {k} 不变",
                  "" if before[k] == after[k]
                  else f"{before[k]!r} -> {after[k]!r}")

        print("\n── ⑤ 清理 B：真实 undeploy(purge_data=True) ──")
        job = undeploy(pair.site_b, purge_data=True, tag="purge-b")
        state["b_purged"] = job.get("status") == "DELETED"
        check(state["b_purged"], "B 下线且数据清理成功（job DELETED）",
              f"status={job.get('status')} error={str(job.get('error', ''))[:60]}")
        # DeleteTable 异步：先等它真的消失，否则 ⑥ 测到的是"DELETING 且 tag
        # 读不到 → fail-closed"那个中间态而不是幂等收敛
        ddb.get_waiter("table_not_exists").wait(TableName=pair.physical)
        check(not table_exists(pair.physical), "B 的表真的删了")
        check(not role_exists(f"site-rt-{pair.site_b}"), "B 的角色删了")
        check(not route_exists(pair.site_b), "B 的路由删了")

        print("\n── ⑥ purge 三态幂等：对已购清的 B 再 purge 一次（表已不存在）──")
        job = undeploy(pair.site_b, purge_data=True, data_tables=["notes"],
                       tag="repurge-b-idempotent")
        check(job.get("status") == "DELETED",
              "重复 purge 幂等收敛到 DELETED（修复前这里是 PURGE_FAILED）",
              f"status={job.get('status')} error={str(job.get('error', ''))[:80]}")

        print("\n── ⑦ 清理 A（无数据，不带 purge——A 的行没有 tier，purge 会走"
              "engine_unknown 的既定异常路径）──")
        job = undeploy(pair.site_a, purge_data=False, tag="cleanup-a")
        state["a_cleaned"] = job.get("status") == "DELETED"
        check(state["a_cleaned"], "A 下线成功", f"status={job.get('status')}")
        return 0
    finally:
        print("\n── 清理读回核对（强一致；中途失败也走到这里）──")
        leftover = 0
        if state["b_deployed"] and not state["b_purged"]:
            job = undeploy(pair.site_b, purge_data=True, tag="finally-purge-b")
            print(f"  补偿清理 B：{job.get('status')}")
        if state["a_attempted"] and not state["a_cleaned"]:
            job = undeploy(pair.site_a, purge_data=False, tag="finally-cleanup-a")
            print(f"  补偿清理 A：{job.get('status')}")
        for name, gone in (
                (f"表 {pair.physical}", not table_exists(pair.physical)),
                *((f"表 {t}", False) for t in
                  _site_data_tables(ddb, "site-data-clsn-")),
                (f"角色 site-rt-{pair.site_a}",
                 not role_exists(f"site-rt-{pair.site_a}")),
                (f"角色 site-rt-{pair.site_b}",
                 not role_exists(f"site-rt-{pair.site_b}")),
                (f"路由 app-{pair.site_a}", not route_exists(pair.site_a)),
                (f"路由 app-{pair.site_b}", not route_exists(pair.site_b))):
            if not gone:
                print(f"  ⚠️  {name} 仍存在——手工清理")
                leftover += 1
        SUMMARY["leftover"] = leftover
        print("  探针资源已清零（sites/jobs 保留 DELETED 历史行）"
              if not leftover else f"  {leftover} 项残留，见上面的 ⚠️")
        if args.json_out:
            Path(args.json_out).write_text(
                json.dumps(_summary(), ensure_ascii=False, indent=2))


def _summary() -> dict:
    failed = sum(1 for ok, _, _ in results if not ok)
    return dict(SUMMARY, checks=[{"ok": ok, "name": n, "detail": d}
                                 for ok, n, d in results],
                passed=len(results) - failed, failed=failed)


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception:                   # noqa: BLE001 摘要与下限判定必须走到
        import traceback
        traceback.print_exc()
        rc = 1
    failed = sum(1 for ok, _, _ in results if not ok)
    print()
    if len(results) < MIN_CHECKS:
        print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）—— "
              "验收**未完成**，状态不可信，不要当成通过")
        rc = 1
    else:
        print(f"结果：{len(results) - failed}/{len(results)} 项通过"
              + (f"，{failed} 项未达预期" if failed else "")
              + (f"，{SUMMARY['leftover']} 项资源残留"
                 if SUMMARY.get("leftover") else ""))
        if failed or SUMMARY.get("leftover"):
            rc = 1
    print("\nJSON 摘要（site/job ID 供审计定位）：")
    print(json.dumps(_summary(), ensure_ascii=False))
    sys.exit(rc)
