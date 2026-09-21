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

    **CFN stack policy 是"有策略即默认保护"**（AWS Prescriptive Guidance
    《CloudFormation stack policies》，2026-09-22 查：*By default, a stack policy helps
    protect all resources in the stack... To allow updates for specific resources, you
    include an explicit `Allow` statement*）。所以逐个逻辑 ID 的判定是三步：

      1. 有覆盖它的 Deny ⇒ 受保护（显式 Deny 优先于 Allow）；
      2. 否则有覆盖它的 Allow ⇒ 开放；
      3. 都没有 ⇒ **受保护**（默认拒）。

    **只看 Deny 是不够的**（本函数第一版的缺陷）：一份没有 Allow-all 的策略（比如只写了
    针对别的资源的 Allow）其实保护着我们关心的 ID，而只找 Deny 会把它判成 `open`。
    那个方向对安全闸门是保守的（高报风险），但它会让"改成默认拒的策略"这种真实加固
    **认不出来**，闸门继续声称那条路是开的。

    `protected` 的 Deny 判据：`Action` 含 `Update:*` 或覆盖 `CONCRETE_UPDATE_ACTIONS` 全集、
    `Principal` 为 `*`、`Resource` 覆盖该 ID、且该语句**没有 Condition**。
    任何解析不动的形态（未识别结构、带 Condition、`Principal` 不是 `*`）一律 `unknown`
    ——包括 Allow 侧：一条带 Condition 的 Allow 是否生效要求值，本函数不猜。
    """
    if policy is None:
        return GUARD_OPEN
    if not logical_ids:
        # 要保护什么都没推出来 ⇒ "已保护"是个无意义的断言。
        return GUARD_UNKNOWN
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        return GUARD_UNKNOWN
    denied: set = set()
    allowed: set = set()
    for st in statements:
        if not isinstance(st, dict):
            return GUARD_UNKNOWN
        effect = st.get("Effect")
        if effect not in ("Deny", "Allow"):
            return GUARD_UNKNOWN
        if st.get("Condition"):
            # 求值 Condition 就是造分析器 ⇒ 不猜。Allow 与 Deny 两侧同样对待。
            return GUARD_UNKNOWN
        if st.get("Principal") != "*":
            return GUARD_UNKNOWN
        actions = set(_as_list(st.get("Action")))
        covers_update = ("Update:*" in actions
                         or set(CONCRETE_UPDATE_ACTIONS) <= actions)
        patterns = _as_list(st.get("Resource"))
        hit = {lid for lid in logical_ids if any(_covers(p, lid) for p in patterns)}
        if effect == "Deny":
            if covers_update:
                denied |= hit
        else:
            # Allow 侧只要**沾到** Update 就算放开（`Update:Modify` 单独放开也足以换 Edge 的码）。
            if covers_update or any(a.startswith("Update:") for a in actions):
                allowed |= hit
    # 显式 Deny 优先；既无 Deny 也无 Allow 的 ID 按默认拒算受保护。
    open_ids = {lid for lid in logical_ids if lid not in denied and lid in allowed}
    return GUARD_OPEN if open_ids else GUARD_PROTECTED
