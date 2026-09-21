""""这份 stack policy 是否拦住了这些逻辑 ID 的 Update" —— 闸门用的 guard 谓词。

**与 `router/infrastructure/stack_policy.py` 的 `policy_problems()` 是两个谓词，
刻意不合并**：那个判"线上策略与本项目规定的形态是否等价"（部署形态一致性，
`verify_deployed_edge.sh` ⑤ 用它），一份**更严格**的 `Deny Update:* on "*"` 会让它
返回非空 ⇒ 拿它当 guard 会把"更严格"读成"没保护"。本模块只回答闸门要的那一个问题，
且**三值**：判不出就是 `unknown`，不许按"没拦住"解释（那是 3g 要修的假绿形状）。

对账靠 `deployer/tests/test_stack_policy_guard.py` 那两条用例：本项目
`build_policy()` 产出的策略必须判 `protected`、`OPEN_POLICY` 必须判 `open`。
"""
from __future__ import annotations

import fnmatch

GUARD_PROTECTED = "protected"
GUARD_OPEN = "open"
GUARD_UNKNOWN = "unknown"

# CFN stack policy 里 Update 只有这三个动作 ⇒ 三个都点名与 `Update:*` 语义等效。
# **这不是 `stack_policy.DENIED_ACTIONS` 的副本**：那个是"我们往策略里写什么"
# （今天是 `("Update:*",)`），这个是"什么算拒绝了 Update"的判据。两者语义相容由
# 测试里的 `build_policy` round-trip 咬住，不是靠常量相等。
CONCRETE_UPDATE_ACTIONS = ("Update:Modify", "Update:Replace", "Update:Delete")


def _as_list(v) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def _covers(resource_pattern: str, logical_id: str) -> bool:
    """Deny 的一个 Resource 串是否覆盖这个逻辑 ID。

    接受三种形态：`*`、`LogicalResourceId/<id>` 逐字、`LogicalResourceId/<前缀>*`。
    """
    target = f"LogicalResourceId/{logical_id}"
    return resource_pattern == "*" or fnmatch.fnmatchcase(target, resource_pattern)


def guard_for(policy: dict | None, logical_ids: list) -> str:
    """→ `protected` / `open` / `unknown`。

    `protected` 的判据（全部满足）：存在 Deny 语句，`Action` 含 `Update:*` 或覆盖
    `CONCRETE_UPDATE_ACTIONS` 全集，`Principal` 为 `*`，`Resource` 覆盖**每一个**
    `logical_ids`，且该语句**没有 Condition**。任何解析不动的形态一律 `unknown`。
    """
    if policy is None:
        return GUARD_OPEN
    if not logical_ids:
        # 要保护什么都没推出来 ⇒ "已保护"是个无意义的断言。
        return GUARD_UNKNOWN
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        return GUARD_UNKNOWN
    covered: set = set()
    for st in statements:
        if not isinstance(st, dict):
            return GUARD_UNKNOWN
        if st.get("Effect") != "Deny":
            continue
        if st.get("Condition"):
            # 求值 Condition 就是造分析器 ⇒ 不猜。
            return GUARD_UNKNOWN
        if st.get("Principal") != "*":
            return GUARD_UNKNOWN
        actions = set(_as_list(st.get("Action")))
        if "Update:*" not in actions and not set(CONCRETE_UPDATE_ACTIONS) <= actions:
            continue
        patterns = _as_list(st.get("Resource"))
        covered |= {lid for lid in logical_ids
                    if any(_covers(p, lid) for p in patterns)}
    return GUARD_PROTECTED if covered >= set(logical_ids) else GUARD_OPEN
