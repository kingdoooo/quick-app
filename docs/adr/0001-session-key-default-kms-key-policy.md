---
status: accepted
date: 2026-09-02
---
# 会话签名 CMK 用默认 KMS key policy，不做限制性策略

3c 把会话签名迁到两把非对称 CMK 时，直觉是给 key policy 只列 auth / panel 两个 signer。
生产只读量测（`docs/security/3c-impersonation-surface.json` 的 `marginal_value_if_closed`）
显示限制性 key policy 只让 1 个 principal 离开冒充面，且结构上收不掉"劫持 signer 代码"那条路：
恶意代码以 signer 角色的身份调 KMS，key policy 必须放行它。代价是自锁风险，加一个必须纳入
闸门枚举的破窗 principal。所以两把 CMK 用默认 key policy（root 委派）；`kms:Sign` 只经 IAM
identity policy 授给 auth（两把）与 panel（console 一把），并带
`kms:SigningAlgorithm = RSASSA_PKCS1_V1_5_SHA_256` 与 `kms:MessageType = RAW` 两个条件；
闸门把 `kms:Sign` / `kms:PutKeyPolicy` / `kms:CreateGrant` 的持有者与 key policy 快照当静态基线。

## Considered Options

- 限制性 key policy + 破窗 principal：减 1 个 principal，换来自锁风险与一个新暴露面。否决。
- key policy 里 Deny 非 signer：能被 `PutKeyPolicy` 持有者撤销，收益与上一条相同。否决。
- 默认 key policy + IAM 条件 + 闸门枚举：选定。

出处：`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §1、§11.2。
