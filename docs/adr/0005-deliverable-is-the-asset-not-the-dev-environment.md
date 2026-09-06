---
status: accepted
date: 2026-09-06
---
# 交付物是可分发资产；验证环境按硬切换处理，HS256 与迁移脚手架不进 v1

本项目的产出是 `site-builder/` 与 `router/` 这套供任意 AWS 用户在自己账号部署的资产（边界按部署所需划），而不是作者账号里那套
部署。此前 3c 的分包（2A 闸门先行 → 2B 切 `kms:Sign` → 3 退役 HS）、跨算法双接受与 26 小时
排空判据，全都是为了让**一个在位生产**从 HS 迁到 KMS 时不登出用户。验证环境没有这个约束。
决定：3c-2A、2B、3 合并为一个包 **3c-final**，直接实现 KMS-only 的 signer 与 verifier，在验证
环境**硬切换**（现存会话作废、重新登录）；HS256 密钥形态、legacy 入口、跨算法双接受、基线
schema 3/4→5 通道、HS 版轮转 runbook、blue/green 存量迁移脚本一律删除，**从未存在于资产里**。
保留的是 **kid 级** current/previous 双接受与 `--drain-gate`，因为采用者轮转 KMS 密钥要用。

**为什么 KMS-only 而不是"HS 简易模式 + KMS 加固模式"**：资产会落进采用者的共享账号，
AWS 托管策略 `ReadOnlyAccess` 就含 `ssm:Get*` 与 `lambda:GetFunction`，在 HS 形态下这等于能签
任意用户的会话（`docs/security/account-trust-boundary.md`）。给别人的方案里留这个模式，等于
留一个必须解释的漏洞；两把非对称 CMK 的成本对建站平台可忽略。

**因此改变归属的两件事**：§9 的 3d「迁独立成员账号」从工程包降为 DEPLOY.md 的部署建议
（那是采用者的决定；建议正文由工单 12 写入 DEPLOY.md，写入前手册里还没有这段）；M08「blue/green 迁移脚本不持租约」从"修"改为"删"（新账号没有存量站点）。

## Consequences

- 单账号实测数字、部署时间线、迁移过程记录只留在 spec/review（文件头声明性质）与 gitignored
  目录；采用者文档（CLAUDE.md、README、DEPLOY.md、client-setup、skills references、CONTEXT.md、ADR）必须过
  "全新用户在全新账号上 clone，这段对他有意义吗"这道检查。**CLAUDE.md 在采用者那一层**：它是采用者的
  Agent 第一个读的文件，验证环境的"现在到哪了"（部署日期、时间线、当前配置形态）不得写在里面，
  只住 gitignored 的接手点文件与 spec 的状态列——否则每个后续 session 都被这些状态牵着走。
- `account_trust_baseline.json` 与冒充面探针结果**将**移出 tracked（工单 12 执行；今天仍是 tracked）；采用者首跑
  `--update-baseline` 生成自己的。执行时要同时处理 `test_verify_account_trust_boundary.py` 里十余处直接读基线文件的
  断言与"新 clone 无基线"的闸门路径，否则 untrack 的那一刻套件与闸门都是 FileNotFoundError。
- v1 的出口验收是在一个全新账号里只看 DEPLOY.md 从零部署并跑分发的验收集；通过才打 `v1.0.0`。
- **硬切换有一个不可消除的窗口**：signer（auth/panel，约 5 分钟）与 Edge verifier（router 重部 + 10 到 20 分钟
  全球复制）不可能同时换，而跨形态双接受被删掉了，所以无论哪个先切，复制期内都有一部分边缘节点拒绝当时
  的 cookie 形态，登录会循环。这在验证环境可接受（窗口内不做验收，结束后全员重新登录一次），在生产不可接受
  ——这正是"只在验证环境做"的含义。采用者将来的 KMS 轮转走 kid 级 current/previous 双接受，不经历这个窗口。
- 被否决的替代方案：按 spec 在位迁移（多一套只服务验证环境的双接受代码与一轮 26 小时等待）；
  保留 HS 作为可选模式（见上）；把 3d 当工程包（采用者账号不由我们决定）。

出处：2026-09-06 grill 定稿，原文在
`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.9。
