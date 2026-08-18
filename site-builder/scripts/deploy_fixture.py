#!/usr/bin/env python3
"""打包 fixture → 上传 → 建 job → 跑状态机 → 轮询到终态。用法：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/nosql-notes
python3 site-builder/scripts/deploy_fixture.py <fixture> --owner me@example.com
python3 site-builder/scripts/deploy_fixture.py <fixture> --site-id notes-abc123 --marker m7-b

owner 默认 `fixture@test`（E2E 用，不对应真人）。**要用 MCP 工具操作这个站点时
必须传 --owner 你的登录邮箱**——否则 role_of() 判你不是 owner，所有权限工具
都会拒绝，而症状看起来像"工具坏了"。

`--site-id` 复用同一个 site_id（不给就随机，行为与从前逐字相同），`--marker` 把一个
串写进后端 `/api/health` 的响应体。**两个开关是配套的**：只有"同一个站点连着部两次、
每次带不同的 marker"才能把"第二次部署真的换上了新字节"与"第二次部署被整个忽略了"
区分开——后者在只断言 HTTP 200 的 E2E 里同样是绿的（M7 spec §5）。
"""
import argparse
import configparser
import contextlib
import io
import json
import re
import secrets
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3
import botocore.exceptions

# common.py：per-site 部署租约的唯一定义。本脚本**绕过 MCP 直接 start_execution**，
# 所以"同一站点同时只有一次部署"这条闸门必须在这里也走一遍——只在 MCP 那侧拿租约
# 的话，这个脚本就是那道闸门的一个后门，而它正是 E2E 用来反复部署同一站点的工具。
sys.path.insert(0, str(Path(__file__).parents[1] / "deployer" / "functions"))
import common as sb_common      # noqa: E402

CFG_PATH = Path(__file__).parents[1] / "config.ini"
_CFG: configparser.ConfigParser | None = None

# marker 落在响应对象的这个字段上。E2E 只按**随机串出现在响应体里**断言，不依赖
# 字段名——所以改名不会悄悄让那些断言失效，但保留一个固定名字便于人工 curl 排查。
MARKER_FIELD = "sb_marker"
# marker 会被写进一个 JS 字符串字面量。带引号/空白/换行的值不是安全问题（值由跑
# 测试的人给），而是**站点起不来**：真机上表现为莫名的 BackendUnhealthy，根因离
# 症状隔了整条流水线。所以在这里就拒掉。
MARKER_RE = re.compile(r"[A-Za-z0-9._-]{1,60}")
# 注入点：`/api/health` 那一行的 `res.json({`。只认同一行内的写法——合同要求后端
# 必须有 GET /api/health（contract/redlines.py），而黄金 fixture 都是一行写完的。
# 认不出来就抛（见 inject_marker），不做"找不到就当没这回事"的静默回落。
_HEALTH_JSON_RE = re.compile(r"/api/health[^\n]*?res\.json\(\s*\{")
_BACKEND_SUFFIXES = (".js", ".mjs", ".cjs")


def cfg() -> configparser.ConfigParser:
    """config.ini 懒加载。

    **不在 import 时读**：config.ini 是 gitignored 的，模块级读取会让任何 import
    这个脚本的单测在干净 clone 里直接报错（而不是通过）。同 auth/deploy_auth.py。
    """
    global _CFG
    if _CFG is None:
        c = configparser.ConfigParser()
        if not c.read(CFG_PATH):
            raise SystemExit(
                f"缺少 {CFG_PATH}——从同目录 config.ini.example 复制并回填")
        _CFG = c
    return _CFG


def inject_marker(tree: Path, marker: str) -> Path:
    """把 marker 写进后端 `/api/health` 的响应对象。返回被改的文件。

    **就地改 `tree`**，所以调用方必须先把 fixture 复制到临时目录：直接改仓库里的
    fixture 会让工作树被污染，之后每一次部署都带着上一次的 marker。

    **找不到注入点一律抛，不静默跳过**：静默的话 E2E 那几条 marker 断言会去验一个
    根本不存在的字段，而部署照样绿——那正是本任务要消除的假绿形态。
    """
    if not MARKER_RE.fullmatch(marker or ""):
        raise SystemExit(
            f"--marker 只允许 {MARKER_RE.pattern}（它会被写进 JS 字符串字面量，"
            f"带引号或空白会让站点起不来）：得到 {marker!r}")
    backend = tree / "backend"
    if not backend.is_dir():
        raise SystemExit(
            f"{tree} 没有 backend/ 目录（static fixture 没有 /api/health），"
            "--marker 对它无意义")
    hits = []
    for p in sorted(backend.rglob("*")):
        if (p.is_file() and p.suffix in _BACKEND_SUFFIXES
                and "node_modules" not in p.parts):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _HEALTH_JSON_RE.search(text):
                hits.append((p, text))
    if not hits:
        raise SystemExit(
            f"{backend} 里找不到 `/api/health` 的 `res.json({{` 注入点——"
            "--marker 无法证明新字节上线了，拒绝继续")
    if len(hits) > 1:
        raise SystemExit(
            f"{backend} 里有多处 `/api/health` 注入点（{[str(p) for p, _ in hits]}），"
            "无法判断该改哪一处")
    path, text = hits[0]
    m = _HEALTH_JSON_RE.search(text)
    path.write_text(text[:m.end()] + f' "{MARKER_FIELD}": "{marker}",'
                    + text[m.end():], encoding="utf-8")
    return path


def build_zip(tree: Path, manifest: dict, run_sh: Path) -> bytes:
    """打上传包。`run_sh` 由调用方给：它在 fixture 的**父目录**里，而带 marker 时
    打包的是临时副本——从 `tree.parent` 取会静默丢掉它（Lambda 的 Handler 就是
    run.sh，丢了以后真机上表现为 BackendUnhealthy）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in tree.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(tree))
        if manifest["tier"] != "static":
            if not run_sh.exists():
                raise SystemExit(
                    f"缺少 {run_sh}——非 static 的 fixture 必须带 run.sh"
                    "（Lambda 的 Handler 就是它）")
            z.write(run_sh, "run.sh")
    return buf.getvalue()


def main(fixture_dir: str, owner: str = "fixture@test", *,
         site_id: str | None = None, marker: str | None = None):
    root = Path(fixture_dir)
    manifest = json.loads((root / "site.json").read_text())
    # site_id 缺省仍是"name + 6 位随机"，与从前逐字相同。给了就逐字用——那是
    # "同一个站点的更新路径"唯一的入口。
    site_id = site_id or f"{manifest['name'][:20]}-{secrets.token_hex(3)}"
    job_id = f"job-{secrets.token_hex(8)}"
    run_sh = root.parent / "run.sh"

    with contextlib.ExitStack() as stack:
        tree = root
        if marker:
            # 注入在**临时副本**上做，仓库里的 fixture 一个字节都不动。
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            tree = tmp / root.name
            shutil.copytree(root, tree)
            inject_marker(tree, marker)
        body = build_zip(tree, manifest, run_sh)

    conf = cfg()
    acct = conf["Platform"]["account_id"]
    s3 = boto3.client("s3", region_name="us-east-1")
    put = s3.put_object(Bucket=f"site-artifacts-{acct}",
                        Key=f"uploads/{job_id}.zip", Body=body)
    now = datetime.now(timezone.utc).isoformat()
    # **必须先建 sites 记录**：MCP 的 do_deploy_site 会调 common.upsert_site 写
    # owner/name/status，而本脚本绕过 MCP 直接起状态机——不写的话 sites 表里
    # 没有 owner（register_route 会从 job 兜底写进路由表，所以只有真源缺失，
    # 两表不一致）。后果：role_of() 判调用者不是 owner，全部权限工具拒绝，
    # 症状看起来像"工具坏了"。实测踩过（2026-08-06）。
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        conf["Deployer"]["sites_table"]).update_item(
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
    # per-site 部署租约。**在 start_execution 之前**：拿不到就一个 execution 都不起。
    # 判定与条件都来自 common（唯一定义）；这里只把拒绝翻成一句人能读的话。
    # 走 os.environ 是因为 common 从环境变量取表名（它本来是 Lambda 里的模块）。
    import os
    os.environ["JOBS_TABLE"] = conf["Deployer"]["jobs_table"]
    try:
        lease_items = sb_common.plan_deploy_lease(site_id, job_id)
    except sb_common.DeployInProgress as e:
        raise SystemExit(f"拒绝部署：{e}") from e
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    try:
        # **建 job 与拿租约同一笔事务**（Codex 2026-08-18 P1-3）：先 put 后拿租约
        # 的话，租约被拒时已经留下一条 RUNNING 却永远没有 execution 的 job——
        # 污染部署历史，且 sweeper 只会把它记成 orphan。
        # **RUNNING，不是 PENDING**：本脚本紧接着就 start_execution。租约判
        # "持有者还在跑吗"看的是 RUNNING；sweeper 也只扫 RUNNING。
        ddb.transact_write_items(TransactItems=[
            {"Put": {"TableName": conf["Deployer"]["jobs_table"],
                     "Item": {"job_id": {"S": job_id}, "site_id": {"S": site_id},
                              "owner": {"S": owner},
                              "status": {"S": "RUNNING"}, "phase": {"S": "queued"},
                              "error": {"S": ""}, "url": {"S": ""},
                              "upload_etag": {"S": put["ETag"]},
                              "upload_bytes": {"N": str(len(body))},
                              "created_at": {"S": now}, "updated_at": {"S": now}}}},
            *lease_items])
    except ddb.exceptions.TransactionCanceledException as e:
        # 两个请求同时读到"空闲"时只有一个的条件成立。job 的 Put 在同一笔里，
        # 所以被拒时**什么都没写下**。
        raise SystemExit(
            f"拒绝部署：站点 {site_id} 有另一次部署刚刚开始") from e
    try:
        # **name=job_id 不可省**（Codex 2026-08-18 P1-3）：sweeper 按
        # `{sm_arn}:{job_id}` 构造 execution ARN 去 DescribeExecution。不传 name
        # 时 AWS 自己生成名字，这个 job 卡住后 sweeper 查的永远是一个不存在的
        # ARN ⇒ 只记 orphan、不收敛 ⇒ 租约永远 busy，站点再也无法部署。
        # 顺带获得与 MCP 相同的幂等语义（同 name 同 input 的重复调用是安全的）。
        boto3.client("stepfunctions", region_name="us-east-1").start_execution(
            stateMachineArn=conf["Deployer"]["state_machine_arn"],
            name=job_id,
            input=json.dumps({"job_id": job_id, "site_id": site_id}))
    except botocore.exceptions.ClientError:
        # **确定被拒**（SFN 收到并拒绝）⇒ 条件回滚到 PENDING（与 MCP 的
        # `_rollback_job_to_pending` 同语义：只有"还没有任何步骤跑过"才回滚）。
        # 回滚成 PENDING 后持有者不再是 RUNNING，下一次部署可按"陈旧持有者"
        # 顶掉租约。
        try:
            ddb.update_item(
                TableName=conf["Deployer"]["jobs_table"],
                Key={"job_id": {"S": job_id}},
                UpdateExpression="SET #s = :pending, phase = :p",
                ConditionExpression="#s = :running AND phase = :queued",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": {"S": "PENDING"}, ":p": {"S": "submitted"},
                    ":running": {"S": "RUNNING"}, ":queued": {"S": "queued"}})
        except Exception:
            pass    # 回滚失败不能盖掉 start_execution 的原始错误（那才是根因）
        raise
    except Exception:
        # **结果不确定**（网络错误——非 ClientError）⇒ **不回滚**（Codex
        # 2026-08-18 R4 P1-2，与 MCP 同一处置）：请求可能已到 SFN、执行在跑。
        # 回滚成 PENDING 会让租约把它当陈旧持有者放行 ⇒ 两条执行并行。保持
        # RUNNING：真在跑 ⇒ 正常推进；没起来 ⇒ sweeper 按确定性 name 查证
        # ExecutionDoesNotExist 后收敛（≤45 分钟），租约随之放开。
        print(f"  ⚠️  start_execution 网络错误、结果不确定：job {job_id} 保持 "
              "RUNNING。若执行已在跑会正常推进；否则 sweeper 会在 ≤45 分钟内"
              "判定失败。", file=sys.stderr)
        raise

    jobs = boto3.resource("dynamodb", region_name="us-east-1").Table(
        conf["Deployer"]["jobs_table"])
    while True:
        job = jobs.get_item(Key={"job_id": job_id})["Item"]
        print(f"  [{job['status']}] {job['phase']}")
        if job["status"] in ("SUCCEEDED", "FAILED"):
            print(json.dumps(job, indent=2, ensure_ascii=False, default=str))
            sys.exit(0 if job["status"] == "SUCCEEDED" else 1)
        time.sleep(10)


def cli(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture_dir")
    ap.add_argument("--owner", default="fixture@test",
                    help="站点 owner 邮箱；要用 MCP 权限工具操作它就填你的登录邮箱")
    ap.add_argument("--site-id",
                    help="复用/指定 site_id（默认按 site.json 的 name 随机生成）；"
                         "同一个 site_id 再部一次走的就是「更新」路径")
    ap.add_argument("--marker",
                    help=f"把这个串写进后端 /api/health 响应的 {MARKER_FIELD} 字段，"
                         "用来证明这次部署的字节真的上线了")
    a = ap.parse_args(argv)
    main(a.fixture_dir, a.owner, site_id=a.site_id, marker=a.marker)


if __name__ == "__main__":
    cli()
