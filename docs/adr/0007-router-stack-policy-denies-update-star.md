---
status: accepted
date: 2026-09-07
---
# router 栈的 stack policy 拒 `Update:*`，代价是每次 router 部署三步走

router 栈关联着 CloudFormation service role：任何能 `UpdateStack`、或 `CreateChangeSet` + `ExecuteChangeSet` 的
principal 都能替换 Edge 的验签代码，自己不需要 `iam:PassRole`（merged review §9 3f）。决定：给栈设 stack policy，
对四个精确逻辑 ID（Edge 两个函数、CloudFront 分发、路由表）显式 `Deny Update:*`，其余 `Allow`；越过它的门槛
变成 `cloudformation:SetStackPolicy`（AWS 文档原话；`ExecuteChangeSet` 没有临时覆盖策略的选项）。策略由
`site-builder/scripts/router_stack_policy.py` 在部署后按**已部署模板**推导并写上，每次部署重申；
`verify_deployed_edge.sh` ⑤ 用只读的 `check` 核对。

**为什么不是工单原话的 `Update:Replace` + `Update:Delete`**：Edge 换码是 Lambda `Code` 属性的 `Update:Modify`
（CloudFormation 标 *No interruption*），分发指向新版本也是 Modify。只拒 Replace/Delete 拦得住误删表、换域名，
却对 §9 3f 的威胁路径没有作用——形状与 CLAUDE.md 里警告过的"收窄 invoke"假修复相同。

## Consequences

- **每次 router 部署三步**：`router_stack_policy.py open` → `cdk deploy` → `apply`。忘 `open` 的症状是
  `ExecuteChangeSet` 阶段 `UPDATE_FAILED` 并整栈回滚，Edge 不受影响；忘 `apply` **没有任何症状**，只有闸门 ⑤ 会红。
  文档里每一处 router 部署点都被守卫要求写成三步（`test_every_router_deploy_site_is_wrapped_by_stack_policy_open_and_apply`）。
- **不可逆的一面**：stack policy 设上就删不掉，只能换。撤掉本功能的代码不会撤掉策略——要先 `open`
  （或手工 `set-stack-policy` 成 Allow-all）再撤代码。
- **它不减少持有 `SetStackPolicy` 者的能力**，也不管 `DeleteStack`（termination protection 是另一个控制面，另开票）、
  不管绕开 CloudFormation 直接调 Lambda / CloudFront API 的那条路。§9 3f 与 spec §1 表里的"−4"要在冒充面探针
  加上 `cloudformation:SetStackPolicy` 这个等价类之后重算，本 ADR 不主张那个数字。
- 被否决的替代：栈内自定义资源去 `SetStackPolicy`（多一个 Lambda 与角色，谁能 Invoke 它谁就能解保护，且属性不变时
  不会在每次部署重申）；把 `EdgeFunctionRole` 也列进保护集（给 edge role 加权限是正常路径，不在威胁路径上）。
