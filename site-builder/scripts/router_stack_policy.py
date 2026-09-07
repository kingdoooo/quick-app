#!/usr/bin/env python3
"""router 栈的 CloudFormation stack policy：`open` → `cdk deploy` → `apply`，闸门用 `check`。

为什么是脚本而不是 CDK 里的资源：CloudFormation 模板没有 stack policy 这个概念，`cdk deploy`
也没有传它的旗标；栈内用自定义资源去 SetStackPolicy 要多一个 Lambda 与角色（谁能 Invoke 它谁就能
解保护），而且属性不变时不会在每次部署重申。所以策略由本脚本在部署**之后**按已部署模板推导并写上，
每次部署都重申一遍；`verify_deployed_edge.sh` ⑤ 用 `check` 核对。

三个子命令（精确逻辑 ID 与策略体的推导都在 `router/infrastructure/stack_policy.py`）：

  open    部署前：把策略换成 Allow-all（stack policy 设上就删不掉，只能换）。栈不存在（首次部署）
          打印 SKIP 并退 0；栈 *_IN_PROGRESS 拒绝并退 1。**open 之后不管 deploy 成败都要 apply。**
  apply   部署后：GetTemplate → 推导四个逻辑 ID → SetStackPolicy → GetStackPolicy 读回比对。
          读回与期望不等价即退 1（写了但没生效不算成功）。栈不存在 / *_IN_PROGRESS 退 1。
  check   只读闸门：DescribeStacks + GetTemplate + GetStackPolicy，策略缺失、被 open 着、未覆盖
          任一受保护资源、或 Deny 里带通配都退 1。**不发任何写调用。**

策略防什么：持有 `cloudformation:UpdateStack` 或 `CreateChangeSet`+`ExecuteChangeSet` **但没有**
`cloudformation:SetStackPolicy` 的 principal 改不了 Edge 两函数、分发与路由表（含 Modify——Edge 换码
就是 Lambda `Code` 的 Modify）。不防什么：持有 SetStackPolicy 的人（等于能 open）、DeleteStack
（termination protection 另配）、绕开 CloudFormation 直接调 Lambda / CloudFront API 的那条路。

忘了 open 的症状：`cdk deploy` 在 ExecuteChangeSet 阶段失败，栈事件里该资源 UPDATE_FAILED、原因含
"stack policy"，整栈回滚——**Edge 不受影响**，open 后重跑即可。
忘了 apply 的症状：没有任何部署输出会提示，只有 `verify_deployed_edge.sh` ⑤ 会红。

用法（仓库根，宿主机 `python3` ≥ 3.10 + boto3，与其它 scripts/*.py 相同）：
    python3 site-builder/scripts/router_stack_policy.py open
    (cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
    python3 site-builder/scripts/router_stack_policy.py apply
    python3 site-builder/scripts/router_stack_policy.py check     # 闸门；verify_deployed_edge.sh ⑤ 调它

需要的权限（操作者自己的凭据，不走 CDK bootstrap 的角色——那些角色没有 SetStackPolicy）：
cloudformation:DescribeStacks / GetTemplate / GetStackPolicy（check），外加 SetStackPolicy（open / apply）。
"""
from __future__ import annotations

import argparse
import configparser
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "router" / "infrastructure"))
from stack_policy import (  # noqa: E402
    OPEN_POLICY, StackPolicyError, build_policy, canonical, policy_problems, protected_logical_ids,
)

ROUTER_CFG = ROOT / "router" / "config.ini"


def load_stack_target(cfg_path: Path = ROUTER_CFG) -> tuple[str, str, str]:
    """(stack_name, region, account_id)，都来自 router/config.ini——键缺失必须硬失败、不回落字面量
    （与 verify_deployed_edge.sh 的 read_cfg 同一条纪律）。"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(cfg_path)
    if not cfg.sections():
        raise SystemExit(f"读不到 {cfg_path} 的任何段——config.ini 没从 .example 复制？")
    def _v(section: str, key: str) -> str:
        return cfg[section][key].split("#")[0].split(";")[0].strip()
    try:
        return _v("CDK", "stack_name"), _v("AWS", "region"), _v("AWS", "account_id")
    except KeyError as exc:
        raise SystemExit(f"{cfg_path} 缺少 {exc}（需要 [CDK] stack_name、[AWS] region、[AWS] account_id）") from exc


def refuse_wrong_account(caller_account: str, target_account: str) -> int:
    """第一次写之前先核对凭据属于哪个账号。同名栈在别的账号里完全可能存在（采用者照 DEPLOY.md 建的），
    AWS_PROFILE 指错时 open 会把**那个**账号的保护剥掉并打印 PASS——与 backfill_site_role_policies.py 同一条纪律。
    check 也核：读错账号的栈会给出一个与本部署无关的结论。"""
    if caller_account != target_account:
        print(f"FAIL  当前凭据属于账号 {caller_account}，而 router/config.ini 的目标账号是 {target_account}"
              "——拒绝执行，一个调用都没发。切换 AWS_PROFILE / 凭据后重试。", file=sys.stderr)
        return 1
    return 0


def _is_missing_stack(exc: Exception) -> bool:
    err = getattr(exc, "response", {}).get("Error", {})
    return err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", "")


def stack_status(cfn, stack: str) -> str | None:
    """栈状态；不存在返回 None。其它异常（凭据、限流）照抛——那不是"没有栈"。"""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except Exception as exc:  # noqa: BLE001
        if _is_missing_stack(exc):
            return None
        raise


def current_policy(cfn, stack: str) -> dict | None:
    body = cfn.get_stack_policy(StackName=stack).get("StackPolicyBody")
    return json.loads(body) if body else None


def expected_policy(cfn, stack: str) -> tuple[dict, dict[str, str]]:
    """按**已部署**的模板推导（不读本地 cdk.out：那可能陈旧，也可能刚被 rm -rf）。
    boto3 对 JSON 模板返回 dict、对 YAML 返回 str，两种都接。"""
    body = cfn.get_template(StackName=stack, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else body
    ids = protected_logical_ids(template)
    return build_policy(ids), ids


def _refuse_in_progress(status: str | None, verb: str) -> int:
    if status == "REVIEW_IN_PROGRESS":
        print(f"FAIL  栈处于 {status}：有一个建好但没执行的 change set（首次部署的 cdk deploy 中断过？）。"
              f"先在 CloudFormation 里执行或删掉它，再 {verb}", file=sys.stderr)
        return 1
    if status is not None and status.endswith("_IN_PROGRESS"):
        print(f"FAIL  栈处于 {status}，{verb} 要等它结束（并发部署？）", file=sys.stderr)
        return 1
    return 0


def _print_recovery(label: str, policy: dict | None) -> None:
    """把即将被覆盖的策略体原样打出来：stack policy 没有版本，这一行就是唯一的恢复状态。"""
    print(f"INFO  {label}（恢复用，原样可回填 SetStackPolicy）：{json.dumps(policy, ensure_ascii=False, sort_keys=True) if policy is not None else '<无策略>'}")


def _print_ids(ids: dict[str, str]) -> None:
    for cid, lid in ids.items():
        print(f"      {cid:24s} LogicalResourceId/{lid}")


def cmd_open(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"SKIP  栈 {stack} 不存在（首次部署）——没有策略可 open；cdk deploy 之后跑 apply")
        return 0
    if _refuse_in_progress(status, "open"):
        return 1
    _print_recovery("open 前的策略", current_policy(cfn, stack))
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=json.dumps(OPEN_POLICY))
    got = current_policy(cfn, stack)
    if got is None or canonical(got) != canonical(OPEN_POLICY):
        print("FAIL  open 写入后读回的策略不是 Allow-all", file=sys.stderr)
        return 1
    print(f"PASS  栈 {stack} 的 stack policy 已换成 Allow-all。**部署完成后（无论成败）必须 apply**；"
          "verify_deployed_edge.sh ⑤ 会核对")
    return 0


def cmd_apply(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"FAIL  栈 {stack} 不存在——apply 只在 cdk deploy 之后跑", file=sys.stderr)
        return 1
    if _refuse_in_progress(status, "apply"):
        return 1
    expected, ids = expected_policy(cfn, stack)
    before = current_policy(cfn, stack)
    if before is not None and canonical(before) != canonical(expected) and canonical(before) != canonical(OPEN_POLICY):
        _print_recovery("apply 前的策略（不是 open 留下的 Allow-all，也不是本次期望）", before)
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=json.dumps(expected))
    problems = policy_problems(current_policy(cfn, stack), expected)
    if problems:
        for p in problems:
            print(f"FAIL  写入后读回仍不等价：{p}", file=sys.stderr)
        return 1
    changed = before is None or canonical(before) != canonical(expected)
    print(f"PASS  栈 {stack} 的 stack policy {'已更新' if changed else '未变化（重申）'}；受保护资源：")
    _print_ids(ids)
    return 0


def cmd_check(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"FAIL  栈 {stack} 不存在", file=sys.stderr)
        return 1
    expected, ids = expected_policy(cfn, stack)
    problems = policy_problems(current_policy(cfn, stack), expected)
    if problems:
        for p in problems:
            print(f"FAIL  {p}", file=sys.stderr)
        print("      修复：python3 site-builder/scripts/router_stack_policy.py apply", file=sys.stderr)
        return 1
    deny_actions = sorted({a for s in expected["Statement"] if s.get("Effect") == "Deny"
                           for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])})
    print(f"PASS  栈 {stack} 的 stack policy 覆盖全部受保护资源（Deny {deny_actions}）：")
    _print_ids(ids)
    return 0


COMMANDS = {"open": cmd_open, "apply": cmd_apply, "check": cmd_check}


def main(argv: list[str] | None = None, cfn=None, caller_account: str | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=sorted(COMMANDS))
    ap.add_argument("--config", type=Path, default=ROUTER_CFG, help="router/config.ini 的路径（测试用）")
    args = ap.parse_args(argv)
    stack, region, account = load_stack_target(args.config)
    if caller_account is None:
        import boto3
        caller_account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    if refuse_wrong_account(caller_account, account):
        return 1
    if cfn is None:
        import boto3
        cfn = boto3.client("cloudformation", region_name=region)
    try:
        return COMMANDS[args.command](cfn, stack)
    except StackPolicyError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
