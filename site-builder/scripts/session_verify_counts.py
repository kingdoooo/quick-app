#!/usr/bin/env python3
"""三个 verifier 的 `session_verify` outcome 计数（CloudWatch Logs Insights，**只读**）。

spec §8：退役 legacy 入口的判据是 `accepted_legacy == 0 且总量非 0` 持续超过最长 TTL。
"总量非 0" 那半句是为了证明埋点本身在工作（埋点异常一律吞掉，丢行是无声的）。
本脚本就是那个读数工具（3c-1A 先建好；3c-1B/L2→L3 用它下判断）。

日志组：
  auth   /aws/lambda/site-auth-service                         （us-east-1）
  panel  /aws/lambda/site-panel                                （us-east-1）
  edge   /aws/lambda/us-east-1.<origin-request 函数名>           （**每个执行过的区都有一份**）
Edge 的组名前缀 `us-east-1.` 是 Lambda@Edge 的固定形态；区清单用 DescribeRegions 现取，
没有该组的区跳过。

用法（用不带路径的 python3，见 CLAUDE.md）：
    python3 site-builder/scripts/session_verify_counts.py --hours 1
    python3 site-builder/scripts/session_verify_counts.py --hours 24 --require-total   # 总量 0 即退 1
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict

import boto3

AUTH_FN = "site-auth-service"
PANEL_FN = "site-panel"
EDGE_FN = "ApplicationWebRouterStack-application-web-router"
OUTCOMES = ("accepted_current", "accepted_previous", "accepted_legacy", "unknown_kid",
            "alg_mismatch", "wrong_audience", "wrong_token_use", "bad_signature", "expired")
QUERY = ('fields @message | filter @message like /"event": "session_verify"/ '
         '| parse @message /"outcome": "(?<outcome>[a-z_]+)"/ | stats count() as n by outcome')


def edge_log_groups(session) -> list[tuple[str, str]]:
    """→ [(region, log_group)]，只含真实存在该组的区。"""
    regions = [r["RegionName"] for r in session.client("ec2", region_name="us-east-1")
               .describe_regions()["Regions"]]
    name = f"/aws/lambda/us-east-1.{EDGE_FN}"
    out = []
    for region in sorted(regions):
        logs = session.client("logs", region_name=region)
        try:
            groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        except Exception:      # 未启用的区 / 无权限：跳过，不是本脚本要判断的事
            continue
        if any(g["logGroupName"] == name for g in groups):
            out.append((region, name))
    return out


def run_query(logs, group: str, start: int, end: int, timeout_s: int = 120) -> dict[str, int]:
    qid = logs.start_query(logGroupName=group, startTime=start, endTime=end,
                           queryString=QUERY, limit=100)["queryId"]
    deadline = time.monotonic() + timeout_s
    while True:
        res = logs.get_query_results(queryId=qid)
        if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        if time.monotonic() > deadline:
            raise SystemExit(f"Logs Insights 查询超时：{group}")
        time.sleep(1.0)
    if res["status"] != "Complete":
        raise SystemExit(f"Logs Insights 查询 {res['status']}：{group}")
    return parse_results(res["results"])


def parse_results(rows) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        cells = {c["field"]: c["value"] for c in row}
        outcome, n = cells.get("outcome"), cells.get("n")
        if outcome in OUTCOMES and n is not None:
            counts[outcome] = counts.get(outcome, 0) + int(float(n))
    return counts


def collect(session, hours: float) -> dict[str, dict[str, int]]:
    end = int(time.time())
    start = end - int(hours * 3600)
    by_verifier: dict[str, dict[str, int]] = {"auth": {}, "panel": {}, "edge": {}}
    logs_east = session.client("logs", region_name="us-east-1")
    for label, fn in (("auth", AUTH_FN), ("panel", PANEL_FN)):
        by_verifier[label] = run_query(logs_east, f"/aws/lambda/{fn}", start, end)
    merged: dict[str, int] = defaultdict(int)
    for region, group in edge_log_groups(session):
        for k, v in run_query(session.client("logs", region_name=region), group, start, end).items():
            merged[k] += v
    by_verifier["edge"] = dict(merged)
    return by_verifier


def render(by_verifier: dict[str, dict[str, int]]) -> tuple[str, int, int]:
    lines = [f"{'outcome':18s} {'auth':>8s} {'panel':>8s} {'edge':>8s}"]
    total = legacy = 0
    for o in OUTCOMES:
        row = [by_verifier[v].get(o, 0) for v in ("auth", "panel", "edge")]
        total += sum(row)
        if o == "accepted_legacy":
            legacy = sum(row)
        lines.append(f"{o:18s} {row[0]:>8d} {row[1]:>8d} {row[2]:>8d}")
    lines.append(f"总量 {total}；accepted_legacy {legacy}")
    return "\n".join(lines), total, legacy


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hours", type=float, default=1.0)
    ap.add_argument("--require-total", action="store_true",
                    help="总量为 0 时退 1（证明埋点在工作；退役判据的另一半）")
    args = ap.parse_args(argv)
    text, total, _legacy = render(collect(boto3.Session(), args.hours))
    print(text)
    if args.require_total and total == 0:
        print("总量为 0：三处埋点没有任何一条 session_verify——埋点没在工作，或窗口里没有请求", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
