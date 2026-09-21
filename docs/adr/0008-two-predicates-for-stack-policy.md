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

判定按**逐个逻辑 ID**做三步，因为 **CFN stack policy 是"有策略即默认保护"**
（AWS Prescriptive Guidance《CloudFormation stack policies》，2026-09-22 查：*By default,
a stack policy helps protect all resources in the stack… To allow updates for specific
resources, you include an explicit `Allow` statement*）：

判定的粒度是 **(逻辑 ID, 具体 Update 动作)**，`Update:*` 先展开成
`Update:Modify` / `Update:Replace` / `Update:Delete` 再按动作合并（三条各写一个动作的 Deny
合起来等于 `Update:*`；要求单条语句一次覆盖三个动作会把那种写法读成"没保护"）：

| 该 (ID, 动作) 的观测 | 结果 |
|---|---|
| 有覆盖它的 Deny | 拒（显式 Deny 优先） |
| 否则有覆盖它的 Allow | 放开 |
| 两者都没有 | **拒**（默认保护） |

整栈 `protected` = **每个** ID 的**三个**动作都落在"拒"；任一被放开即 `open`。
取"三个都要拒"这个较严的门槛是刻意的：`Update:Modify` 换 Lambda 的 `Code`、
`Update:Replace` 换掉整个函数资源，两条都改变正在执行的 Edge 代码。
无 stack policy = `open`。

**解析不了就 `unknown`，不许当"没写"**：`NotAction` / `NotResource` / `Condition` /
任何未识别字段、`Effect` 不是 Deny/Allow、`Principal` 不是 `*` 都落 `unknown`。
这一条的方向最要紧——`Allow Update:* NotResource <别的>` 实际**放开**了我们的 ID，
把它当"没写 Resource"会判成 `protected`，那是**低报风险**。

**只看 Deny 是不够的**（本谓词第一版的缺陷，R1-L2 复审时发现）：一份没有 Allow-all 的策略
其实保护着受保护 ID，而只找 Deny 会判成 `open`。那个方向对安全闸门是保守的（高报风险），
但它会让"改成默认拒的策略"这种真实加固**认不出来**。

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
