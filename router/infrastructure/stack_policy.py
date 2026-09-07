"""router 栈的 CloudFormation stack policy：**声明**受保护资源、从模板**推导**它们的逻辑 ID、
生成并**比较**策略。只依赖标准库——三处调用方里有两处没有 aws_cdk：

  · `stack.py`（synth 期）：`assert_protected_constructs(self)`——声明与栈不一致就让 synth 失败；
  · `site-builder/scripts/router_stack_policy.py`（部署前后 / 闸门）：`protected_logical_ids`
    + `build_policy` + `policy_problems`，用宿主机 `python3` 跑；
  · `lambda/test_stack_policy.py`（router 套件，借 deployer 的 venv，那里没有 aws_cdk）。

## 模型

stack policy 只管 **UpdateStack / ExecuteChangeSet** 路径上的 `Update:Modify|Replace|Delete`。
设了之后**默认全拒**，所以策略里必须先有一条 `Allow Update:* on *`，再用显式 `Deny` 点名资源
（CloudFormation 按逻辑 ID 与资源类型**分别**评估，`NotResource` 那种写法拦不住——AWS 文档原话）。
越过它必须持有 `cloudformation:SetStackPolicy`；`ExecuteChangeSet` 根本不接受临时覆盖策略。
它**不管** DeleteStack（那是 termination protection 的事），也不管绕开 CloudFormation 直接调
Lambda / CloudFront API 的路——那两条由账号信任边界文档另算。

## 逻辑 ID 怎么来

不硬编码哈希。CDK 给顶层 construct 的 L1 分配的逻辑 ID = construct ID + 8 位大写十六进制路径哈希
（`OriginRequestFunction/Resource` → `OriginRequestFunction` + 8 hex）；`Version` 子资源是
`…CurrentVersion` + 8 hex + 40 hex，被 `[0-9A-F]{8}$` 的锚排除。`protected_logical_ids` 按
"construct ID 前缀 + 8 hex + Type 相符 + 恰好命中一个"从**已部署模板**里取；
`assert_protected_constructs` 在 synth 期拿 CDK 自己算出的 ID 核对同一条正则。两边任何一边变了
都是响亮失败，而不是 `apply` 静默保护错对象。刻意不读 `Metadata.aws:cdk:path`：直接
`python3 stack.py` 时模板里没有它（那是 CDK CLI 加的上下文）。
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

# (construct ID, 期望的 CloudFormation 资源类型)。改这张表 = 改 stack.py 的 construct ID，
# 而**改 construct ID 就是替换资源**（逻辑 ID 变）——对分发与路由表那是事故，不是重构。
PROTECTED_CONSTRUCTS: tuple[tuple[str, str], ...] = (
    ("OriginRequestFunction", "AWS::Lambda::Function"),
    ("OriginResponseFunction", "AWS::Lambda::Function"),
    ("Distribution", "AWS::CloudFront::Distribution"),
    ("SubdomainMappingTable", "AWS::DynamoDB::Table"),
)

# 决策门 D1。`Update:*` 含 Modify：Edge 换码是 Lambda `Code` 的 Modify，只拒 Replace/Delete
# 拦不住"经 UpdateStack 替换验签代码"这条路。代价是每次 router 部署都要 open → deploy → apply。
DENIED_ACTIONS: tuple[str, ...] = ("Update:*",)

ALLOW_ALL_STATEMENT = {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}
# `open` 用的临时策略：等于没有保护。stack policy 一旦设上就删不掉，只能换成这个。
OPEN_POLICY: dict[str, Any] = {"Statement": [dict(ALLOW_ALL_STATEMENT)]}


class StackPolicyError(ValueError):
    """声明与模板/栈不一致。调用方应当让 synth / apply / check 失败，而不是继续。"""


def logical_id_pattern(construct_id: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(construct_id)}[0-9A-F]{{8}}$")


def protected_logical_ids(template: Mapping[str, Any]) -> dict[str, str]:
    """construct ID → 模板里的逻辑 ID。任何一项缺失 / 多义 / 类型不符都抛，并点名是哪一项。"""
    resources = template.get("Resources") or {}
    out: dict[str, str] = {}
    problems: list[str] = []
    for cid, rtype in PROTECTED_CONSTRUCTS:
        pat = logical_id_pattern(cid)
        hits = sorted(lid for lid in resources if pat.match(lid))
        if len(hits) != 1:
            problems.append(f"{cid}: 期望恰好 1 个逻辑 ID 匹配 {pat.pattern}，实得 {hits}")
            continue
        got = resources[hits[0]].get("Type")
        if got != rtype:
            problems.append(f"{cid}: {hits[0]} 的 Type 是 {got!r}，期望 {rtype!r}")
            continue
        out[cid] = hits[0]
    if problems:
        raise StackPolicyError("模板里推不出全部受保护资源：\n  " + "\n  ".join(problems))
    return out


def build_policy(logical_ids: Mapping[str, str]) -> dict[str, Any]:
    """先 Allow 全部，再 Deny 点名的精确逻辑 ID。缺了 Allow 整栈会被冻住（stack policy 默认拒）。"""
    missing = [cid for cid, _ in PROTECTED_CONSTRUCTS if cid not in logical_ids]
    if missing:
        raise StackPolicyError(f"build_policy 缺少逻辑 ID：{missing}")
    return {"Statement": [
        dict(ALLOW_ALL_STATEMENT),
        {"Effect": "Deny", "Action": list(DENIED_ACTIONS), "Principal": "*",
         "Resource": [f"LogicalResourceId/{logical_ids[cid]}" for cid, _ in PROTECTED_CONSTRUCTS]},
    ]}


def _as_list(v: Any) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def canonical(policy: Mapping[str, Any]) -> str:
    """语句顺序、Action/Resource 的 str-vs-list 形态都不算差异。"""
    stmts = []
    for s in policy.get("Statement", []):
        d = dict(s)
        for k in ("Action", "NotAction", "Resource", "NotResource"):
            if k in d:
                d[k] = sorted(_as_list(d[k]))
        stmts.append(json.dumps(d, sort_keys=True))
    return json.dumps(sorted(stmts))


def policy_problems(actual: Mapping[str, Any] | None, expected: Mapping[str, Any]) -> list[str]:
    """空列表 = 线上策略与期望**等价**。否则逐条说清差在哪（缺谁的 Deny、用了通配、被 open 着）。"""
    if actual is None:
        return ["栈没有 stack policy"]
    if canonical(actual) == canonical(expected):
        return []
    problems: list[str] = []
    want = {r for s in expected["Statement"] if s["Effect"] == "Deny" for r in _as_list(s["Resource"])}
    covered: set[str] = set()
    for s in actual.get("Statement", []):
        if s.get("Effect") != "Deny":
            continue
        acts = set(_as_list(s.get("Action")))
        if "Update:*" in acts or set(DENIED_ACTIONS) <= acts:
            covered |= set(_as_list(s.get("Resource")))
    for r in sorted(want - covered):
        problems.append(f"没有 Deny 语句以 {list(DENIED_ACTIONS)} 覆盖 {r}")
    if "*" in covered or any(r.endswith("*") for r in covered):
        problems.append("Deny 语句的 Resource 含通配——策略要求精确逻辑 ID")
    if not any(s.get("Effect") == "Allow" for s in actual.get("Statement", [])):
        problems.append("没有 Allow 语句——这份策略会冻住整栈的所有更新")
    if not problems:
        problems.append("策略与期望不等价（多出的语句、Condition，或不同的动作集合）")
    return problems


def assert_protected_constructs(stack) -> dict[str, str]:
    """synth 期守卫（duck-typed，不 import aws_cdk）：四个 construct 都在、L1 类型对、
    CDK 分到的逻辑 ID 符合 `protected_logical_ids` 用的同一条正则。返回 construct ID → 逻辑 ID。"""
    out: dict[str, str] = {}
    problems: list[str] = []
    for cid, rtype in PROTECTED_CONSTRUCTS:
        child = stack.node.try_find_child(cid)
        cfn = child.node.default_child if child is not None else None
        if cfn is None:
            problems.append(f"{cid}: 栈里没有这个 construct（改名了？同步 PROTECTED_CONSTRUCTS）")
            continue
        got = getattr(cfn, "cfn_resource_type", None)
        if got != rtype:
            problems.append(f"{cid}: L1 类型是 {got!r}，期望 {rtype!r}")
            continue
        lid = stack.get_logical_id(cfn)
        if not logical_id_pattern(cid).match(lid):
            problems.append(f"{cid}: CDK 分到的逻辑 ID {lid!r} 不符合 {logical_id_pattern(cid).pattern}"
                            "——router_stack_policy.py 推不出它")
            continue
        out[cid] = lid
    if problems:
        raise StackPolicyError("stack policy 的受保护资源声明与栈不一致：\n  " + "\n  ".join(problems))
    return out
