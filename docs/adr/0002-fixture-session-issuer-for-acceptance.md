---
status: accepted
date: 2026-09-02
---
# 验收闸门的登录态来自 auth 内的受控夹具签发，不给 kms:Sign，也不走真实登录

会话签名非对称化后，闸门与 E2E 无法再"读 SSM 明文、本地 mint 会话"。真实登录在本平台等于
每次人工飞书扫码（Cognito 原生登录流被 `deploy_pool.py` 设计性禁用、Edge 拒非托管登录来源），
会让无人值守闸门全部报废；给验收角色 `kms:Sign` 则是一个不受限的新冒充 principal，因为
`kms:Sign` 不限制签什么 claims。决定在 auth 上加 `POST /fixture-session`：Function URL 走
AWS_IAM，resource policy 只多一个 `site-builder-verifier` 角色（两条语句，缺一即 403），
应用层再核对 `userArn`；只签夹具域 `e2e.invalid` 的站点会话，`auth_via` 打专用值
`fixture-issuer`，TTL 不超过 30 分钟；升级码与面板会话一律走真实换取链路。

**边界由 verifier 强制，不靠签发方自律**：`allowed_users = "org"` 的站点会放行任何可信来源的邮箱，
所以 Edge 只在 owner 属于夹具域的路由上认 `fixture-issuer` 会话，其它路由一律 302；panel 的 admin
名单与非夹具站点的权限字段拒收夹具域邮箱。这样夹具会话的危害上限是"夹具站点"，而不是"全组织"。

**已知入口两个**：经 Function URL 的 verifier 角色，以及对 auth 函数的直接 `lambda:InvokeFunction`
（调用方自己构造整个事件，`userArn` 可伪造，`edge_caller.py` 的 Path A 实测过）。两个都作为
`sign:fixture-issuer` 路径纳入冒充面枚举；正因为有第二个入口，上一段的 verifier 侧边界才是必需品。

## Consequences

- `verify_session_token_semantics.py` 不再冒充真实 owner，改打常驻夹具站点。
- E2E 的 `e2e@test.com` 改为夹具域身份。
- Edge 与 panel 的夹具边界规则必须先于签发器上线（同在 3c-2A）。
- 谁能改 auth 代码谁就能签夹具域会话。相对今天"谁能改 auth 代码谁能签任意会话"，这是收窄，不是新增。

出处：`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.7。
