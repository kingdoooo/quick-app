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
    python3 site-builder/scripts/session_verify_counts.py --hours 24 --require-total   # 任一 verifier 为 0 即退 1
    # 排空闸门（runbook 的 ④ / ⑨）**只用这一个旗标**：四条判据锁在脚本里（3c-1B-G A2）
    python3 site-builder/scripts/session_verify_counts.py --drain-gate previous    # ④ 用 --drain-gate legacy
    # 下面这些是**诊断**旗标，自由组合、可配短窗口；**空窗口下 --require-zero 会退 0**，所以它们不是闸门
    python3 site-builder/scripts/session_verify_counts.py --hours 1 --require-total --require-zero accepted_previous

退出码：0 = 所有要求都满足；1 = 任一要求不满足（stderr 说明是哪条）；2 = 用法错误（如 --require-zero 打错词表外的 outcome）。
**区级失败不静默**：Edge 日志组按 DescribeRegions 返回的（**已启用**）区逐个查，任一区 DescribeLogGroups 失败
（AccessDenied / 限流 / 网络）即退出——静默跳过 = 少算一区 = `accepted_*` 假 0，而 ⑨ 守的是不可逆的 ⑩。
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict

import boto3

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from verify_account_trust_boundary import EDGE_ORIGIN_REQUEST_FN as EDGE_FN  # noqa: E402  平台函数名的唯一定义处

AUTH_FN = "site-auth-service"
PANEL_FN = "site-panel"
# 排空闸门（3c-1B-G A2）：`--drain-gate <目标>` → 要求为 0 的那一列。
# 26 h 的来历见 DEPLOY.md：站点会话 TTL 24 h + auth 的 secret 缓存 5 min + Edge 全球复制 10–20 min + 余量。
DRAIN_TARGETS = {"previous": "accepted_previous", "legacy": "accepted_legacy"}
DRAIN_MIN_HOURS = 26
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
        except Exception as exc:  # noqa: BLE001
            # DescribeRegions 默认只给**已启用**的区，所以到这里的失败都是 AccessDenied / 限流 / 网络，
            # 不是"该区未启用"。静默跳过 = 这一区的 accepted_* 永远读成 0（3c-1B ticket 18 修）。
            raise SystemExit(f"区 {region} 的 DescribeLogGroups 失败（{type(exc).__name__}: {exc}）——"
                             f"少算一区就是 accepted_* 假 0，不出结论") from exc
        if any(g["logGroupName"] == name for g in groups):
            out.append((region, name))
    return out


def require_edge_groups(groups: list) -> list:
    """Edge 至少要在一个区留下日志组；一个都没有 = 名字/区找错了，不是"没流量"。"""
    if not groups:
        raise SystemExit(f"任何区都找不到 Edge 日志组 /aws/lambda/us-east-1.{EDGE_FN}——函数名或区枚举错了")
    return groups


def nonzero_outcomes(by_verifier: dict, outcomes: list) -> list:
    """要求为 0 的 outcome 里，任一 verifier 列 > 0 的那些；每条带三列读数，给 stderr 直接打。

    ④/⑨ 的判据是"三列 accepted_legacy / accepted_previous 全 0"——原来由人读三列，脚本 exit 0 并不代表它。
    """
    out = []
    for o in outcomes:
        row = {v: by_verifier.get(v, {}).get(o, 0) for v in ("auth", "panel", "edge")}
        if any(row.values()):
            out.append(f"{o}: " + " ".join(f"{v}={n}" for v, n in row.items()))
    return out


def missing_outcome_columns(by_verifier: dict, outcomes: list) -> list:
    """要求 > 0 的 outcome 里，有任一 verifier 列为 0 的那些（只列为 0 的列）。

    "三列 accepted_current 全 > 0" 是判据的正面那半：证明新形态在**每处** verifier 都真的被接受过，
    不能被别列的读数遮住。
    """
    out = []
    for o in outcomes:
        zero = [v for v in ("auth", "panel", "edge") if by_verifier.get(v, {}).get(o, 0) == 0]
        if zero:
            out.append(f"{o}: " + " ".join(f"{v}=0" for v in zero))
    return out


def silent_verifiers(by_verifier: dict) -> list:
    """总量为 0 的 verifier。§8 的退役判据要求**每处**埋点都在工作，不能被别处的总量遮住。"""
    return [v for v in ("auth", "panel", "edge") if sum(by_verifier.get(v, {}).values()) == 0]


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
    for region, group in require_edge_groups(edge_log_groups(session)):
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
                    help="任一 verifier 的总量为 0 即退 1（按 auth / panel / edge 分别看：证明每处埋点都在工作，"
                         "这是退役判据的另一半；Edge 列为 0 不能被 auth/panel 的总量遮住）")
    ap.add_argument("--require-zero", action="append", default=[], metavar="OUTCOME", choices=OUTCOMES,
                    help="该 outcome 在任一 verifier 列 > 0 即退 1（可重复）。⑨ 用 accepted_previous、④ 用 accepted_legacy："
                         "这是退役判据的正面那半，脚本自己判，不留给人读三列")
    ap.add_argument("--require-nonzero", action="append", default=[], metavar="OUTCOME", choices=OUTCOMES,
                    help="该 outcome 在**每一**verifier 列都必须 > 0，否则退 1（可重复）。④/⑨ 用 accepted_current：证明新形态"
                         "在三处都真的被接受过")
    ap.add_argument("--drain-gate", choices=tuple(DRAIN_TARGETS), metavar="{previous,legacy}",
                    help="排空闸门（runbook 的 ④ / ⑨ 只用这一个旗标）：把四条判据锁进脚本"
                         f"——窗口 ≥ {DRAIN_MIN_HOURS} h、每个 verifier 总量 > 0、"
                         "accepted_{previous,legacy} 三列全 0、accepted_current 三列全 > 0。"
                         "不可逆的退役步骤只许用它，别用下面那几个自由组合的诊断旗标")
    args = ap.parse_args(argv)
    if args.drain_gate:
        # **把四条判据合成一个旗标**（3c-1B-G A2）：原先它们是四个独立参数，少任何一个都
        # 静默放宽，而最坏的一种不是"少判一条"而是**空窗口**——`--require-zero` 只报非零列，
        # 三列全空自然通过 ⇒ exit 0 被读成"已排空"，下一步就是删 SSM 参数（不可逆）。
        if args.hours != ap.get_default("hours") and args.hours < DRAIN_MIN_HOURS:
            raise SystemExit(
                f"--drain-gate 的窗口不得短于 {DRAIN_MIN_HOURS} h（给的是 {args.hours}）——"
                "26 = 站点会话 TTL 24 h + auth 的 secret 缓存 5 min + Edge 全球复制 10–20 min 再加余量。"
                "想看短窗口读数用不带 --drain-gate 的诊断旗标。")
        args.hours = max(args.hours, float(DRAIN_MIN_HOURS))
        args.require_total = True
        args.require_zero = list(args.require_zero) + [DRAIN_TARGETS[args.drain_gate]]
        args.require_nonzero = list(args.require_nonzero) + ["accepted_current"]
    elif set(args.require_zero) & set(DRAIN_TARGETS.values()):
        # 复审低优先级 1：旧文档里的那条组合仍然合法（诊断用），但它不是闸门——空窗口照样退 0。
        # 不拒绝（短窗口看"previous 还有没有人用"是正当需求），只在 stderr 说一句。
        print("提醒：--require-zero accepted_previous/accepted_legacy 不带 --drain-gate 时**不是排空闸门**"
              "——空窗口也会退 0。判 ④/⑨ 用 --drain-gate {previous,legacy}。", file=sys.stderr)
    by_verifier = collect(boto3.Session(), args.hours)
    text, _total, _legacy = render(by_verifier)
    print(text)
    rc = 0
    silent = silent_verifiers(by_verifier)
    if args.require_total and silent:
        print(f"这些 verifier 在窗口里没有任何 session_verify：{silent}——埋点没在工作，或窗口里没有请求", file=sys.stderr)
        rc = 1
    missing = missing_outcome_columns(by_verifier, args.require_nonzero)
    if missing:
        print("要求 > 0 的 outcome 有 verifier 列为 0：\n  " + "\n  ".join(missing)
              + "\n——新形态没在这一处被接受过，先跑四个 verify_* 造流量再判", file=sys.stderr)
        rc = 1
    nonzero = nonzero_outcomes(by_verifier, args.require_zero)
    if nonzero:
        print("要求为 0 的 outcome 仍有读数（按 verifier 列）：\n  " + "\n  ".join(nonzero)
              + "\n——窗口未排空，不许进下一步；按「最后一次出现 + 26 h」重排时刻", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
