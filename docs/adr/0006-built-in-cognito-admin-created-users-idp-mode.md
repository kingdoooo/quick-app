---
status: accepted
date: 2026-09-06
---
# 资产内置"Cognito 管理员建户"IdP 模式，仍走 OIDC 联邦，不重开原生登录

平台把身份绑定在邮箱上，所以 `deploy_pool.py` 刻意关闭了 Cognito 原生登录：用户不得自注册、
不得自改邮箱，邮箱必须由身份源控制。但多数采用者拿到资产时没有现成的 OIDC IdP，"先去申请一个
IdP 客户端"是首次部署最大的门槛。决定：`deploy_pool.py` 增加一个可选模式，再建**第二个** Cognito
用户池充当 OIDC IdP——只允许管理员建户、邮箱属性对应用客户端不可写——平台池照常以 OIDC 联邦
接入它。平台代码零改动，"邮箱由身份源控制"的硬要求由第二个池的配置满足，而不是放松平台池。

**不是**重开平台池的原生登录：那会让邮箱回到用户自己手里，破坏 owner / allowed_users /
会话 claim 全以 email 为键的模型。

## Consequences

- v1 前的 IdP 验证用两个免费 IdP：Google（真正的外部第三方、发 `email_verified`）与这个第二
  Cognito 池（零外部依赖）。Microsoft Entra 默认不发 `email_verified`，只作为手册里的已知差异。
- DEPLOY.md 给采用者三条身份路径：已有 OIDC IdP、Google、内置 Cognito 管理员建户。飞书降为其中
  一种参考适配器。
