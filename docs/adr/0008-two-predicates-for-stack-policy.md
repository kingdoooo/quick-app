---
status: accepted
date: 2026-09-21
---
# stack policy 有两个谓词：部署形态一致性，与闸门的 guard 语义判定

`router/infrastructure/stack_policy.py` 的 `policy_problems(actual, expected)` 判的是
**线上策略与本项目规定的形态是否等价**（`verify_deployed_edge.sh` ⑤ 用它，忘了 `apply`
时靠它红）。它的 `covered` 只收 Deny 语句里**字面**的 Resource 串，所以一份**更严格**的
`Deny Update:* on "*"` 会让 `want - covered` 非空（`want` 是精确的
`LogicalResourceId/<id>`），并再报一条"Resource 含通配"。

⇒ **`policy_problems() != []` 推不出"这个栈没有保护"。**

决定：信任边界闸门用第二个谓词
`site-builder/scripts/_stack_policy_guard.guard_for(policy, logical_ids)`，只回答
"这些逻辑 ID 的 Update 被拒了吗"，且**三值**：

| 观测 | guard |
|---|---|
| 无 stack policy | `open` |
| Deny 覆盖了**每一个**受保护逻辑 ID（`Update:*` 或三个具体 Update 动作全集、`Principal: *`、无 Condition） | `protected` |
| 能解析但没覆盖全 | `open` |
| 解析不动（未识别语法、带 Condition、`Principal` 不是 `*`、读不到） | `unknown` |

`unknown` **不得**按"没拦住"解释，也不得按"拦住了"解释：持 CFN 更新权的 principal 在
`unknown` 下只拿到 `edge:cfn-template-unanalyzed`（单列、不进冒充面并集）。
"未知被当成否"正是 3g 要修的那个假绿形状。

两处 docstring 互相点名。**不要把它们合并**：一个服务"部署是不是按规定做的"（更严格
也算偏离），另一个服务"这条威胁路径是不是被挡住了"（更严格就是挡住了）。

## Consequences

- 对账**不靠"两个 `DENIED_ACTIONS` 常量相等"**——那两个常量是不同的东西：
  `stack_policy.DENIED_ACTIONS` 是我们**写进**策略的动作列表（今天 `("Update:*",)`），
  `_stack_policy_guard.CONCRETE_UPDATE_ACTIONS` 是"什么算拒绝了 Update"的判据。
  改用更强的 round-trip：本项目 `build_policy()` 的产物必须判 `protected`、
  `OPEN_POLICY` 必须判 `open`（`deployer/tests/test_stack_policy_guard.py`）。
- `guard == "protected"` **只**表示受保护资源的**直接更新**路径被挡住。service role
  权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰那四个资源 ⇒ 不得据 guard
  宣称某 principal 退出冒充面，也不得算确定收益（ADR 0007 已有同样要求）。
- guard 进闸门基线的 `model_inputs` 分节（任一变化都红）：它翻转时，如果当下没有人持
  `UpdateStack`，能力层的标签集合一个都不会变——那种变化只有这一节能看见。
