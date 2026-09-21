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

# 本谓词**能解析**的语句字段。出现别的字段（`NotAction` / `NotResource` / `Condition` /
# 任何没见过的键）一律 `unknown`——CFN stack policy 确实支持 NotAction/NotResource
# （文档已验证：Prevent updates to stack resources，2026-09-22 查），而把它们当成"没写"
# 会给出**方向错误**的答案：`Allow Update:* NotResource <别的>` 实际放开了我们的 ID，
# 按"没写 Resource"算会判成受保护 ⇒ **低报风险**，正是安全闸门最不能犯的那种错。
_PARSEABLE_KEYS = frozenset({"Effect", "Action", "Principal", "Resource", "Sid"})


def _update_actions(actions: set) -> set:
    """Action 集合 → 它覆盖的**具体** Update 动作集合。

    `Update:*`（或裸 `*`）展开成三个。**必须展开再按动作合并**：三条各写一个具体动作的
    Deny 合起来等于 `Update:*`，而"要求单条语句一次覆盖三个动作"会把那种写法判成没保护。
    """
    out: set = set()
    for a in actions:
        if a in ("Update:*", "*"):
            out |= set(CONCRETE_UPDATE_ACTIONS)
        elif a in CONCRETE_UPDATE_ACTIONS:
            out.add(a)
    return out


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
    include an explicit `Allow` statement*）。所以判定是**逐 (逻辑 ID, 具体 Update 动作)**
    做的，三步：

      1. 有覆盖它的 Deny ⇒ 拒（显式 Deny 优先于 Allow）；
      2. 否则有覆盖它的 Allow ⇒ 放开；
      3. 都没有 ⇒ **拒**（默认保护）。

    整栈 `protected` 的条件是：**每个** ID 的**三个** Update 动作都落在"拒"。任一被放开即
    `open`。取"三个都要拒"这个较严的门槛是刻意的——`Update:Modify` 换 Lambda 的 Code、
    `Update:Replace` 换掉整个函数资源，两条都改变正在执行的 Edge 代码，所以不能只看 Modify；
    宁可在"只拒了一部分"时报 `open`（高报风险、方向保守）。

    两类**不猜**的情形一律 `unknown`：
      · 语句里出现本谓词解析不了的字段（`NotAction` / `NotResource` / `Condition` /
        未识别键，见 `_PARSEABLE_KEYS`）——把它们当"没写"会给出方向错误的答案；
      · `Effect` 不是 Deny/Allow、`Principal` 不是 `*`、`Statement` 不是非空列表、
        或者一个 logical id 都没推出来。
    """
    if policy is None:
        return GUARD_OPEN
    if not logical_ids:
        # 要保护什么都没推出来 ⇒ "已保护"是个无意义的断言。
        return GUARD_UNKNOWN
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        return GUARD_UNKNOWN
    denied: dict = {lid: set() for lid in logical_ids}
    allowed: dict = {lid: set() for lid in logical_ids}
    for st in statements:
        if not isinstance(st, dict):
            return GUARD_UNKNOWN
        if set(st) - _PARSEABLE_KEYS:
            return GUARD_UNKNOWN
        effect = st.get("Effect")
        if effect not in ("Deny", "Allow"):
            return GUARD_UNKNOWN
        if st.get("Principal") != "*":
            return GUARD_UNKNOWN
        acts = _update_actions(set(_as_list(st.get("Action"))))
        if not acts:
            continue                      # 与 Update 无关的语句（如 Delete:*）不影响本判定
        patterns = _as_list(st.get("Resource"))
        bucket = denied if effect == "Deny" else allowed
        for lid in logical_ids:
            if any(_covers(p, lid) for p in patterns):
                bucket[lid] |= acts
    for lid in logical_ids:
        for action in CONCRETE_UPDATE_ACTIONS:
            if action in denied[lid]:
                continue                  # 显式 Deny 优先
            if action in allowed[lid]:
                return GUARD_OPEN         # 被放开 ⇒ 这条路开着
            # 既无 Deny 也无 Allow ⇒ 默认拒 ⇒ 这个动作算被挡住
    return GUARD_PROTECTED
