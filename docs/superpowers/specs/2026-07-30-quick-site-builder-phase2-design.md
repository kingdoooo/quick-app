# Quick Site Builder 二期设计文档（控制台 + 权限身份 + 访问统计）

- **日期**：2026-07-30
- **状态**：设计已确认（brainstorming 完成），待实施计划
- **范围决策**：大切——需求清单（`docs/phase2-requirements.md`）A/B/C 全做；
  D 组纳入部署历史展示与 OAuth PKCE+nonce 两项，其余（自定义域名、版本回滚、
  Fargate、计费、Python runtime、精细缓存）不纳入
- **一期基线**：`2026-07-21-quick-site-builder-design.md`（已实现快照，只读）；
  一期已在真实 AWS 全量部署并端到端验证

## 1. 背景与目标

一期交付了"自然语言开发 → 一句部署 → 可分享 URL"的完整链路，但管理能力空缺，
实测暴露的痛点：

- 改 allowed_users 名单必须改 site.json 重走整个部署，太重；
- owner 死绑单人，owner 休假别人连站点状态都查不了；
- 没有管理员概念，没人能管别人的站点；
- Quick Desktop Remote MCP 只支持静态 Headers，OAuth 走不通，靠 stdio 代理绕；
- 没有任何访问统计，站点被谁用、用得多不多完全不可见。

**二期目标**：给平台补上管理面（Web 控制台 + MCP 工具双入口）、多人协作的
权限模型、免代理的 API Key 认证、按天/周/月的 PV/UV 统计与访问审计。

**成功标准（端到端验收链路）**：

1. 用户经平台身份层登录 `console.{base_domain}`，看到自己的站点，在线把一个
   站点的 allowed_users 改掉，约 1 分钟内新名单生效，全程不碰 site.json、
   不重部署；
2. owner 给站点加协作者，协作者能部署更新、能看统计，但不能下线站点；
   owner 转移后新 owner 全权、原 owner 降为协作者；
3. 用户在控制台创建 API Key，把它配进 Quick Desktop Remote MCP 的静态
   Header，直连部署一个站点成功；控制台吊销该 Key 后调用立即 401；
4. 管理员在全局视图找到任意站点并强制下线，操作留有审计记录；
5. 站点详情页能看到按天/周/月的 PV 曲线；鉴权站点能看到 UV 与
   "谁在什么时候访问过"的审计表。

## 2. 总体架构

二期不改一期五层架构，在其上加两个平台组件、一条统计管道，并改造权限数据流：

```
                    ┌──────────────────────────────────────────┐
                    │ ⑥ 控制台 (site-builder/panel/)     【新】 │
                    │   console.{base_domain}，route_mode=split │
                    │   前端: S3 平台前缀 platform/console/{ver}│
                    │   API:  panel Lambda（Function URL,       │
                    │         AWS_IAM 仅 edge role，仿 auth）   │
                    └────────────┬─────────────────────────────┘
                                 │ 读写 sites 表（权限唯一真源）
                                 │ 投影到路由表（UpdateItem 仅权限字段）
   ② 部署 MCP ──┬── 新工具（权限/协作者/统计）───┤ 共用 permissions 模块
                │                               │
                └── ⑦ API Key 交换层（key-proxy）【新】
                    mcp.{base_domain} → 验 Key → 换 machine token
                    + X-SB-On-Behalf-Of → AgentCore runtime

   ④ Edge ── 鉴权放行后 print 一行结构化访问日志（零请求路径开销）
                 ↓ 各区 CloudWatch Logs（30 天保留 = 审计原始数据窗口）
   ⑧ 统计聚合器【新】：EventBridge 每小时 → 跨区 Logs Insights
                 → DynamoDB site-access-stats / site-access-audit

   ⑤ 身份层：平台专用 user pool（禁自注册 + 仅企业 IdP）+ PKCE/nonce 增强
              + pre-token 注入 email/idp claim
              + /console-session 发一次性 code → console 侧签发面板会话
```

**新增资源**：panel Lambda、key-proxy Lambda、聚合器 Lambda、6 张 DynamoDB 表
（`site-access-stats`、`site-access-audit`、`site-api-keys`、`site-admins`、
`site-ops-log`、`site-session-codes`——会话升级一次性 code 的消费标记，
带 TTL）、1 条 EventBridge 定时规则、1 个新 user pool + 2 个 app client（`site` / `mcp`；`machine` 随 M4 的 resource server 一起建——client_credentials 不能用空 scope 创建）。

**改动组件**：sites 表（+权限字段 +`permissions_rev` +GSI，成为真源）、
register_route（从 sites 表读权限 + 输出 effective policy）、smoke_test
（读 effective policy 而非 manifest）、mark_job（**不再写 owner**）、
Edge origin-request（+collaborators 放行、+List 反序列化、+两个 `__Host-`
保留 cookie、+`idp` claim 校验、+访问日志行）、MCP server（+3 新工具、
角色判定替换 owner 校验、信任代理 on-behalf 头）、auth 服务（PKCE/nonce、
/console-session 发一次性 code）、pre_token_email（+`idp` claim）。

**明确不动的东西**（一期安全模型零破坏）：

- 站点 runtime boundary：`site-rt-*` 角色、PermissionsBoundary、per-site
  数据隔离——控制台与 key-proxy 是平台组件，走独立 IAM 角色，不进站点体系；
- CloudFront 全站禁缓存（鉴权正确性前提）；
- 部署合同与执行器 10 步主链（仅 register_route 的权限取值来源变化）；
- 部署凭证全在服务端。

### 关键设计决策（brainstorming 结论）

1. **控制台是平台组件，不是站点**。需要读全量 sites 表、改路由表，超出站点
   runtime boundary 的能力面。仿 auth 服务模式：`deploy_panel.py` 幂等脚本
   部署（平台部署时一次性完成，用户零操作），路由表注册 `owner=platform`
   的 `console` 子域——不进 sites 表，`list_my_sites` 不可见；`undeploy_site`
   校验 owner==调用者邮箱，"platform" 永远匹配不上任何邮箱，MCP 无法误删。
2. **控制台面向全体用户**，不是管理员专属：普通用户自助管理自己的站点与
   API Key，管理员多一个全局视图。子域取 `console` 而非 `admin`，语义即
   "控制台"。
3. **权限唯一真源 = sites 表，路由表是投影**。site.json 的 `auth` 字段仅首次
   部署时作为初始值；重部署忽略之（消除"在线修改被重部署覆盖"的风险——
   现状 register_route 是 put_item 整条覆盖）。
4. **统计数据源 = Edge 日志行 + 异步聚合**（两候选方案的杂交）：Edge 在鉴权
   放行后 print 一行 JSON 到自身 CloudWatch Logs——零网络调用、零请求延迟，
   且拿得到 email（真 UV + 审计），这是 CloudFront standard logs 做不到的；
   聚合走小时级定时任务。代价（已接受）：小时级延迟；日志散在各请求区域需
   跨区聚合；若三期做精细缓存会低估 PV（届时再评，已记联动项）。
5. **平台专用 user pool 二期第一批切**。与 Quick SSO 共享 pool 解耦，趁用户
   少、切换成本最低时做；此后平台侧配置（触发器、client、token 形态）不再
   有影响 Quick SSO 的顾虑。
6. **API Key 平台自管 + 交换层**。Key 哈希存平台表（可即时吊销、映射到
   email），入口加轻量交换层换 Cognito machine token。不用 Cognito
   client_credentials 直发（每用户一个 client 管理笨重、静态 Header 客户端
   无法自己发起 token 交换）、不用 refresh token 寄存（泄露即全权、无法细
   粒度吊销）。
7. **协作者两级模型**：owner + collaborator，owner 可转移（原 owner 自动降级
   为 collaborator）。不做三级 viewer（YAGNI）。
8. **会话隔离折中：仅控制台升级**。普通站点维持顶域共享 cookie（一次登录处
   处可用的体验保留）；控制台写操作要求只在 console 子域可见的
   `__Host-sb_console` cookie——把隔离投在风险最高的地方。该 cookie 必须由
   **console host 自己**签发（见 §4.5：host-only cookie 的作用域就是签发它
   的主机，auth 子域签发的发不到 console 子域）。全量按站点隔离记为后续增强。
9. **身份层保持 IdP 无关**。新 pool 联邦到任意能给 email claim 的 **OIDC**
   IdP：当前用飞书适配器（feishu-quick-sso），标准 IdP（Okta 等）按
   DEPLOY.md 已有分支配置。平台全部组件只消费 email/name claim。二期切新
   pool 时顺带把标准 IdP 分支真机验证一次（覆盖需求清单 B 组遗留项）。
   SAML 联邦本期不实现（Cognito 支持，但两种 provider 的属性映射与部署脚本
   路径不同，无真实需求前不做——记入 §11）。
10. **管理员名单存平台表 + config 种子**。首个管理员从 config.ini 幂等注入，
    后续由现有管理员在控制台增删——管理员变更不走重部署，与二期"在线改"
    主旨一致。
11. **身份只能来自企业 IdP；边界是 app client 不开原生认证 flow**。
    `allowed_users="org"` 的语义前提：Edge 对 org 只看"持有有效平台会话"，
    不查邮箱域。四条：① 关自注册；② 生产 client 不列 `COGNITO`；
    ③ token 的 `idp` + `auth_via` claim 校验（Edge 与 MCP 两个入口，纵深）；
    **④ `ExplicitAuthFlows` 只含 `ALLOW_REFRESH_TOKEN_AUTH`——这是边界**。
    ①② 不阻止 SDK 原生认证（AWS 明说）；③ 也不够：`idp` 是静态属性、
    `auth_via` 会被 "原生认证 → refresh 刷一次" 洗白（AWS 明说 refresh token
    两种来源都签发，`TokenGeneration_RefreshTokens` 不区分）。只有 ④ 让原生
    认证发不起来。部署脚本必须断言并纠偏 ④ 的配置漂移。
    `REQUIRE_IDP_CLAIM` 置 true 是 M1 的完成条件。详见 §3.5。

## 3. 权限模型与数据真源

### 3.1 sites 表扩展（权限唯一真源）

现有字段不动，新增：

```
require_login            BOOL
allowed_users            "org" | List<String>（原生 List，不再是 JSON 字符串）
collaborators            List<String>
permissions_updated_at   ISO8601
permissions_updated_by   email
permissions_rev          N（乐观并发版本号，事务条件写用；缺失视为 0）
+ GSI owner-index（PK owner；照抄 jobs 表既有模式 infra/app.py:27-30）
```

### 3.2 三方取值关系

- **site.json `auth` 字段**：仅首次部署（sites 表尚无该 site_id 或无权限
  字段）时作为初始值写入 sites 表。重部署时忽略；若与真源不一致，job 结果
  附提示"线上权限以控制台为准"。合同文档
  （`skills/site-builder/references/contract.md`）同步改写此语义。
- **路由表**：纯投影，仅存 Edge 需要的字段（require_auth、allowed_users、
  collaborators、owner）。`register_route` 改为从 sites 表读权限字段写入
  路由（部署时的整条 put_item 保留——原子切流语义不变，但权限值来自真源）。
- **在线改权限走 DynamoDB 事务（`TransactWriteItems`）**，两表一起成功或一起
  失败。**不能用"先写 sites 再同步路由"的两步顺序写**：若第二步失败，
  收紧权限的场景会留下"sites 表显示已私有、Edge 仍按旧路由公开放行"的
  状态——这是安全状态错误，不是可接受的最终一致性。事务两条 item：
  - sites 表：`Update` 权限字段，`ConditionExpression` 校验 `permissions_rev`
    等于读取时的值（乐观并发，防两个 owner/collaborator 同时改互相覆盖），
    同时 `permissions_rev` 自增；
  - 路由表：`Update` **仅**权限字段（require_auth / allowed_users /
    collaborators / owner），不整条覆盖——部署时的 `register_route` 是整条
    `put_item`（原子切流），两者都整写会踩掉 static_prefix / api_target。
    `ConditionExpression: attribute_exists(subdomain)`。
  - 站点尚未部署成功（无路由 item）时事务会因该条件失败：此时降级为**只写
    sites 表**（真源），首次部署时 `register_route` 会带上正确值。这条降级
    是显式分支，不是异常吞掉。
  - 两表在同一账号同区域，`TransactWriteItems` 跨表可用；条件失败返回
    `TransactionCanceledException`，按 CancellationReasons 区分是并发冲突
    （提示重试）还是路由缺失（走降级分支）。
- **`register_route`（部署第 6 步）也必须条件写**，否则事务白做。它的现有形态
  是"普通读 sites → 无条件 `put_item` 整条路由"，与在线改权限存在这样的交错：
  ① register_route 读到旧策略（公开）→ ② owner 在线改成私有，事务把两表都改成
  私有 → ③ register_route 用步骤 ① 的旧快照无条件 put_item → **最终 sites=私有、
  Edge=公开**，正是事务本该消除的安全状态错误。DynamoDB 事务只保证事务内的
  原子性，不会把事务之前的普通读与之后的普通写合成一个业务事务（标准读是
  read-committed，不阻止读后被改）。因此：
  - 路由表投影带上 `permissions_rev`；
  - `register_route` 改用 `TransactWriteItems`：对 sites 表做
    `ConditionCheck`（`permissions_rev` == 读到的值）+ 对路由表 `Put` 整条；
  - 事务被取消（说明期间有人改了权限）→ 重读 sites、用新策略重建 item 再试，
    重试上限 3 次；仍失败则该步骤失败（部署 FAILED，比留下错误的公开状态好）。
  - 首次部署的"权限字段不存在则用 manifest 初始化"同样要条件写
    （`attribute_not_exists(require_login)`），否则会覆盖并发的首次在线修改。
- **Edge**：读路由表逻辑不变，新增 collaborators 放行（隐式在 allowed_users
  内，同 owner 现有语义）；`_deser` 扩展支持 List 类型（现状只认 S/BOOL，
  origin_request.py:143-148）。

### 3.3 两级角色

| 操作 | owner | collaborator |
|---|---|---|
| 部署更新、查状态、看统计/审计 | ✓ | ✓ |
| 改 require_login / allowed_users | ✓ | ✓ |
| 增删 collaborator | ✓ | ✗ |
| 转移 owner | ✓ | ✗ |
| undeploy / purge_data | ✓ | ✗ |

- **owner 转移**：owner 指定新 owner 邮箱，原 owner 自动降级为 collaborator
  （防转错人即失联，可再被移除）。转移记入 ops-log。
- **管理员**：`site-admins` 表（PK=email）。首个管理员从 config.ini
  `[Platform] admin_seed` 由部署脚本幂等 upsert；后续由现有管理员在控制台
  增删（不能删到名单为空）。管理员对任意站点拥有 owner 等价权限 + 全局
  列表；所有代管操作记 ops-log。
- **操作审计表 `site-ops-log`**：PK `target`（site_id 或 "platform"）、
  SK `{ts}#{actor}` → {action, detail}；TTL 400 天。记录：权限修改、协作者
  变更、owner 转移、下线/purge、Key 创建/吊销、admin 名单变更与代管操作。
  控制台与 MCP 的写操作都经 permissions 后端统一落一条。
- **共用校验模块 `permissions.py`**：输入 caller email + site 记录（+admins
  表），输出角色。判定顺序 **owner → admin → collaborator**：身兼 collaborator
  的平台管理员必须拿到 admin 权限（若 collaborator 先匹配，该 admin 会失去
  undeploy / 转移所有权的能力）。审计需要区分"owner 本人"与"admin 代管"时用
  单独返回的 `is_admin` 标志，不靠角色字符串。MCP server 与 panel Lambda 各自
  引入（沿用 common.py 的构建时复制模式）。现有 `_assert_owner` 全部替换为
  按操作粒度的角色判定。

### 3.3.1 job 的发起者与站点 owner 必须解耦

一期只有 owner 能部署，所以 `mark_job` 在成功分支里用
`upsert_site(owner=job["owner"])` 把发起者写回站点 owner——同一个人，无害。
**二期放开 collaborator 部署后这行会变成提权路径**：collaborator B 发起一次
更新部署，成功后 sites.owner 就变成 B，B 随即获得 undeploy、转移所有权、
增删协作者的能力；而 `register_route` 早一步写入的仍是原 owner A，最终形成
sites 表 owner=B、路由表 owner=A 的分裂状态。

因此：

- **`mark_job` 不再写 `owner`**（站点 owner 只由 `permissions.transfer_owner`
  与首次部署的初始化路径写）；
- jobs 表的 `owner` 字段语义改为 **`requested_by`**（谁发起了这次部署），
  保留 `owner` 字段名以兼容存量数据与 `owner-index` GSI，但代码与文档一律
  按"发起者"理解——它不再参与任何授权判定，只用于审计与"我发起的部署"列表；
- 首次部署（sites 表无该 site_id）时 `do_deploy_site` 已把调用者写为 owner，
  这条路径不变；
- 验收项：collaborator 跑完整 SFN 后，sites.owner 与路由表 owner 都不变
  （真机 E2E，不能只测"拿到 upload_url"）。

### 3.3.2 部署链上所有 manifest 权限消费方都要改

真源迁移不止 `register_route` 一处。**`smoke_test` 也从
`event["manifest"]["auth"]["require_login"]` 取值**（`smoke_test.py:47`），
它据此断言首页应 302（需登录）还是 200（公开）。在线把 require_login 从 true
改成 false 后重部署，路由按真源写成公开、smoke 按旧 manifest 期待 302，实际
得到 200 → 部署被判 FAILED，**而路由切换已经发生**（第 6 步早于第 7 步），
线上处于"新版本已上线但 job 显示失败"的状态。反方向（false→true）同样失败。

因此 `register_route` 把本次实际写入路由的 effective policy 放进 event
（`event["effective_auth"] = {"require_login": ..., "allowed_users": ...}`），
`smoke_test` 读它而非 manifest。改真源时必须把 manifest 的所有下游消费方过
一遍——本期确认只有这两处（`register_route`、`smoke_test`）。

### 3.4 存量迁移

一次性脚本：遍历路由表，把 require_auth/allowed_users/owner 回填到 sites 表
（已有权限字段的跳过）。迁移完成前 Edge 仍以路由表现值工作，无中断窗口。
allowed_users 从 JSON 字符串转原生 List 在回填时完成；Edge 的 `_deser` 先上
（兼容两种格式读），投影写入后统一为 List。

**无法解析的 allowed_users 必须报错并跳过，绝不降级为 `"org"`**：Edge 现行为
是 JSON 解析失败即用空名单（仅 owner 可访问，fail-closed，
`origin_request.py:308-315`）。若迁移把它写成 `"org"`，下一次部署会把这个值
投影到路由表，权限从"仅 owner"扩大为"全体登录用户"——一次数据修复动作变成
了扩权。这类记录进 `errors` 报告，由人工判断原意后手工修。

### 3.5 `allowed_users="org"` 的语义前提

Edge 对 `"org"` 的判定是"持有本平台签发的有效会话 JWT 即放行"，**不检查邮箱
域**。这个判定只有在"平台 pool 里的身份必然来自企业 IdP"时才等于"全组织
用户"。**边界由 app client 的 `ExplicitAuthFlows` 提供（第 4 条），claim 校验
只是纵深**——下面四条按"谁真正拦住攻击"排序：

1. **pool 侧关自注册**：`AllowAdminCreateUserOnly=True`。挡住公开 `SignUp`
   API。
2. **生产 app client 的 `SupportedIdentityProviders` 只列企业 IdP，不含
   `COGNITO`**。注意其**真实效力有限**——AWS 明确说明：把 `COGNITO` 从该列表
   移除只影响 managed login 登录页展示哪些 IdP，**不阻止**用 SDK 经 user
   pools API 认证本地用户（官方原文：*"The removal of COGNITO from this list
   doesn't prevent authentication operations for local users with the user
   pools API in an AWS SDK. The only way to prevent SDK-based authentication
   is to block access with a AWS WAF rule."*，见
   [CreateUserPoolClient](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html)）。
   所以这条只是减少暴露面，不能当成边界。
3. **`idp` + `auth_via` claim 校验（纵深，两个入口都要做）**：pre-token 触发器注入
   `idp`；**Web 入口** — auth 服务 mint 会话 JWT 时带上，Edge 校验它在可信
   provider 白名单内（`{{TRUSTED_IDPS}}` 占位符，同 JWT_SECRET 的注入机制），
   缺失或不匹配按未登录处理；**MCP 入口** — `_caller_email()` 校验 access
   token 的 `idp`（`TRUSTED_IDPS` 环境变量）。只做 Web 那侧等于防线只做一半：
   MCP 能部署、改权限、下线站点，能力面比访问站点更大。

   **两个 claim 各自的效力边界（都不足以当边界，必须理解）**：
   - `idp` 取自用户档案的**静态**属性 `identities[0].providerName`，证明的是
     "这个账号关联过某个可信 IdP"，**不是**"本次登录由它验证"。
     `AdminLinkProviderForUser` 链过的本地用户（AWS：*linked local users can
     also sign in with SDK-based API operations like `InitiateAuth` after they
     sign in at least once through their IdP*）与
     `AdminSetUserPassword` 设过密码的联邦用户，原生登录时照样带着合法 `idp`。
   - `auth_via`（pre-token 的 `triggerSource`）证明的是"**本次 token 怎么来
     的**"，但它**不携带首次认证的 lineage**，因此会被 refresh 流程洗白：
     原生认证拿到的 token 虽然是 `TokenGeneration_Authentication`（会被拒），
     但用它换出的 refresh token 再刷一次，新 token 的 triggerSource 就变成
     `TokenGeneration_RefreshTokens`——落进白名单。AWS 明确说 refresh token
     *"in response to successful authentication with the managed login
     authorization-code flow **and with API operations or SDK methods**"*
     两种来源都会签发，`TokenGeneration_RefreshTokens` 本身不区分二者。
     若把 `RefreshTokens` 从白名单里去掉，正常用户的会话续期又会全断。

   所以这两个 claim 是纵深，不是边界：它们拦住"从未关联可信 IdP 的纯本地
   用户"和"直接拿原生 token 来用"，拦不住"原生认证 → refresh 洗白"。

4. **边界：app client 的 `ExplicitAuthFlows` 不开任何原生认证 flow**。
   这是本期唯一真正不可绕过的一条——原生认证根本发起不了，就不存在
   "原生 token"，也就不存在可洗白的 refresh token。具体：
   - `site` / `mcp` client 的 `ExplicitAuthFlows` **只含
     `ALLOW_REFRESH_TOKEN_AUTH`**，不含 `ALLOW_USER_PASSWORD_AUTH` /
     `ALLOW_USER_SRP_AUTH` / `ALLOW_CUSTOM_AUTH` / `ALLOW_USER_AUTH` 或任何
     `ALLOW_ADMIN_USER_PASSWORD_AUTH`。缺了这些 flow，`InitiateAuth` /
     `AdminInitiateAuth` 对该 client 直接失败——linked 用户与设过密码的联邦
     用户都无从发起原生登录。**部署脚本必须断言这一点，且每次重跑都纠偏**
     （client 配置漂移即边界失效）；
   - 配套运维红线：**不对本平台 pool 调
     `AdminLinkProviderForUser` / `AdminSetUserPassword` / `AdminCreateUser`**
     ——它们制造"本可原生登录的身份"，虽然被上一条挡着，但一旦有人给某个
     client 加回 flow，这些身份立刻可用。写进 DEPLOY.md；
   - **漂移恢复不是"改回配置"就完事**：refresh token 一旦签发，在有效期内
     可持续换新 token，而新 token 的 `auth_via` 正是受信的
     `TokenGeneration_RefreshTokens`。所以若曾经发生过"原生 flow 被打开"
     （哪怕只几分钟），关掉 flow **不能**使已签发的 refresh token 失效。
     恢复流程必须三步：① 改回 `ExplicitAuthFlows`；② **吊销存量 refresh
     token**——按用户 `AdminUserGlobalSignOut`，或（无法枚举受影响用户时）
     直接轮换 app client；③ 复验 `initiate-auth` 失败**且吊销前签发的
     access token 已被拒**。
   - **吊销 ≠ 立即失效**：`AdminUserGlobalSignOut` / `RevokeToken` 只断掉
     "再换新 token"，**已经换出去的 access token 在自身过期前仍可用**。AWS 明
     说 *"Other requests might be valid until your user's token expires"*，
     且被吊销的 token 对"只校验签名与过期时间的 JWT 库"依然有效——AgentCore
     的 inbound authorizer 正是这种（只验 discovery/公钥/exp/`allowedClients`，
     不逐请求回查 Cognito），Edge 验的是平台自签会话 JWT，同理不回查。
     要求立即失效只有两条路：轮换 app client **并**同步更新 AgentCore 的
     `allowedClients`；或轮换 `JWT_SECRET` 并重部署路由层（作废全部会话）。
   - 配套把 `RefreshTokenValidity` 从默认 30 天收到 **1 天**，并把
     `AccessTokenValidity` / `IdTokenValidity` 从默认 60 分钟收到 **15 分钟**
     （两者都要——**暴露窗口 = refresh 有效期 + access 有效期**，只收 refresh
     会留下最长一小时的残留窗口）。代价是用户每天重新登录一次（站点会话
     cookie 本就是 24h，节奏一致）。
   - **三期**：WAF 挡 user pools API 是最后一层（防"有人新建了带原生 flow
     的 client"这类配置漂移）——记入 §11，本期不做。

**四条的定位一句话**：①② 减小暴露面；③ 纵深（拦纯本地用户与直接的原生
token）；**④ 是边界**。验收时若只验 ③ 而没验 ④，等于没有边界。

**为什么不能只靠 ①②③**：只做 ①② 时 SDK 原生认证仍可用（AWS 明说移除
`COGNITO` 不阻止它）；只做 ③ 时 linked / 设过密码的用户可以"原生认证 →
用 refresh token 刷一次"把 `auth_via` 洗成可信值。④ 从源头上让原生认证发不
起来，是本期唯一不可绕过的一条。

**存量兼容**：迁移期已签发的会话 JWT 没有 `idp` claim，Edge 需允许一个宽限
窗口（部署时开关 `{{REQUIRE_IDP_CLAIM}}`，切换 pool 且全部用户重新登录后置
true）——**开关翻到 true 是 M1 的完成条件，不是可选项**；停在 false 等于本节
第 3 条没生效。

**claim 传播链（四段都要落地，缺一即断）**：

| 段 | 落点 | 关键约束 |
|---|---|---|
| 注入 | `auth/pre_token_email.py` | 注入 `idp`（来源关联）与 `auth_via`（本次 token 的 `triggerSource`）。pre-token V2 的 `idTokenGeneration` 与 `accessTokenGeneration` 是**两个独立容器**，只写后者不会进 ID token（[官方文档](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html)）。Web 登录读 ID token、MCP 网关读 access token，**两者都要写** |
| 换取 | `auth/login_handler.py:_exchange_code` | 从验签后的 id_token claims 里取 `idp` **与 `auth_via`** 一并返回 |
| 签发 | `auth/session.py:mint_session_jwt` | 会话 JWT payload 加 `idp` **与 `auth_via`**（都只在非空时写入，保持与一期 token 字节兼容）；与 Edge 的验签算法保持字节级同步的约束不变 |
| 校验（Web） | `router/.../origin_request.py` | `REQUIRE_IDP_CLAIM` 为真时，`claims["idp"]` 必须在 `TRUSTED_IDPS` 内**且 `claims["auth_via"]` 在受信来源内**，否则按未登录处理 |
| 校验（MCP） | `mcp/server.py:_caller_email` | **同一道防线的第二个入口**：AgentCore authorizer 只验 issuer 与 `allowedClients`，不看 claim——issuer/client 合法但缺 `idp`/`auth_via` 的 access token 否则能直接部署、改权限、下线站点。同样校验两个 claim；`TRUSTED_IDPS` 为空时放行（迁移宽限期，与 Edge 开关对齐），但 config 已配 IdP 时部署脚本须拒绝空值 |

**两个入口都要配**：只做 Edge 就只保护了站点访问，MCP 这条管理面通道仍然
开着——而它的能力面比访问站点大得多（部署、改权限、下线）。

## 4. 控制台（管理面板）

### 4.1 部署形态

平台组件 `site-builder/panel/`，`deploy_panel.py` 幂等脚本（仿
`auth/deploy_auth.py`，选脚本而非并入 CDK 栈的原因相同：要做"注册路由表"
等 CDK 不好表达的动作）：

- panel Lambda（Python 3.13）+ Function URL（AuthType=AWS_IAM，仅授权 edge
  role，含 InvokeFunctionUrl + InvokeFunction 两条语句——一期实测坑）；
- 静态前端上传 S3 平台前缀 `platform/console/{version}/`；
- 路由表注册 `console` 子域：`route_mode=split`、`require_auth=True`、
  `allowed_users="org"`、`owner=platform`。

**IAM 角色**：独立平台角色。权限 = sites/jobs/access-stats/access-audit/
api-keys/admins/ops-log 表读写 + 路由表 UpdateItem + invoke
`site-deployer-undeploy`。不带 site-rt boundary，但同样最小化——无建删基础
设施权限。

### 4.2 前端

纯静态 SPA（原生 JS 或轻量无构建链方案，与仓库"前端即静态文件"现状一致），
调 `/api/*`。UI 设计由用户以 opendesign 另行产出，功能面如下。

### 4.3 页面功能面

1. **站点列表**（首页）：我的站点（owner ∪ collaborator）——名称、URL、状态
   徽章、tier、我的角色、近 7 天 PV 迷你趋势；管理员可切"全部站点"视图
   （含 owner 列与搜索）；空状态引导指向 Agent 客户端。
2. **站点详情**四标签页：
   - 概览：URL/状态/tier/owner/协作者/访问策略摘要/最近部署；
   - 权限：require_login 开关、allowed_users 编辑（org/邮箱名单）、协作者
     增删与 owner 转移（仅 owner 可操作，非 owner 置灰）、保存后提示
     "约 1 分钟内全网生效"；
   - 部署历史：jobs 表时间线（时间/状态/phase/错误摘要展开）；
   - 访问统计：PV 折线（天/周/月切换）、鉴权站点显示 UV 与访问审计表
     （访问者邮箱、次数、最近访问时间），公开站点标注"仅 PV 无访客身份"。
3. **危险区域**：下线、下线并清数据——二次确认需输入站点名。
4. **API Key 管理**：列表（备注名、前缀 `sk-xxxx…`、创建时间、最后使用）、
   创建（明文完整显示一次 + 复制 + "关闭后不再显示"警告）、吊销。
5. **管理员页**（仅 admin 可见）：全局站点表格（搜索/筛选/代管/强制下线）、
   管理员名单增删。
6. **通用**：导航（我的站点/API Key/管理员）、当前用户 email 与登出、
   骨架屏、错误 toast。中文界面，桌面优先。

### 4.4 panel Lambda API 面

```
GET  /api/me                          email、是否 admin、面板会话状态
GET  /api/sites                       owner ∪ collaborator；admin 可 ?all=1
GET  /api/sites/{id}                  详情
GET  /api/sites/{id}/jobs             部署历史
GET  /api/sites/{id}/stats?g=day|week|month   访问统计
GET  /api/sites/{id}/audit            访问审计（仅鉴权站点有数据）
PUT  /api/sites/{id}/permissions      改 require_login/allowed_users（owner+collab）
PUT  /api/sites/{id}/collaborators    增删协作者（仅 owner/admin）
PUT  /api/sites/{id}/owner            转移所有权（仅 owner/admin）
POST /api/sites/{id}/undeploy         下线（仅 owner/admin；purge_data 显式传）
GET/POST/DELETE /api/keys             我的 API Key
GET/PUT /api/admins                   管理员名单（仅 admin）
POST /api/admin/resync/{id}           路由表重同步（仅 admin，见 §8 错误处理）
GET  /api/session-callback            会话升级回调（见 §4.5；由 console host
                                      自己 Set-Cookie，不需要面板会话）
```

### 4.5 鉴权两层

- **身份**：Edge 注入的 `x-user-email`（读操作直接用）。
- **写操作**（权限修改、undeploy、Key 管理、admin 操作）额外要求只在 console
  子域可见的 `__Host-sb_console` cookie。目的：站点 XSS 偷到顶域 `sb_session`
  后不能直接冒充调面板写 API。

**签发流程（必须由 console host 自己 Set-Cookie）**：

```
panel 写 API 缺 __Host-sb_console → 401 {"need":"console-session"}
  → 前端 302 到 https://auth.{domain}/console-session?redirect=<console URL>
      auth 校验顶域 sb_session 有效 → 生成一次性 code
        （HMAC 签名 + 60s 过期 + 绑 email，同 state 的签名机制；一次性由
         code 内的 jti 落 DynamoDB 消费标记保证）
      → 302 到 https://console.{domain}/api/session-callback?code=...
  → panel 的 session-callback 验 code → Set-Cookie:
      __Host-sb_console=<JWT scope=console, TTL 4h>; Path=/; Secure;
      HttpOnly; SameSite=Lax     ← 无 Domain 属性，由 console host 签发
  → 302 回原页面，前端重放请求
```

**为什么不能让 auth 服务直接种这个 cookie**：不带 `Domain` 属性的 cookie 的
作用域就是**发送该 Set-Cookie 响应的主机**。`auth.{domain}` 种出来的
host-only cookie 只会回发给 `auth.{domain}`，兄弟域 `console.{domain}` 永远
收不到——按那种设计，面板的写操作会 100% 拿不到凭证。`__Host-` 前缀额外强制
（浏览器校验）：必须 Secure、必须 `Path=/`、**必须无 Domain**，即便将来有人
误加 Domain，浏览器会直接拒绝这个 cookie 而不是静默放宽作用域。

**CSRF 防护是独立的一层**：host-only cookie 只防"被兄弟子域读取/覆盖"，不防
兄弟子域发起的跨站请求（同 site，cookie 照发）。因此 panel 的所有写 API 还必须：

- 校验 `Origin` 头等于 `https://console.{base_domain}`（缺失即拒绝，不做
  Referer 回退）；
- 要求 `Content-Type: application/json`（阻断 HTML form 的简单请求）；
- 写操作一律用 `PUT`/`POST`/`DELETE`，不接受 `GET` 触发副作用。

三条同时满足才放行。这也是"站点 XSS → 改全局权限"这条攻击链的最终闸门。

## 5. API Key 与 MCP 改造

### 5.1 Key 形态与存储

- 明文：`sk-` + 16 位随机 base62（约 95 bit 熵，内部平台足够）；仅创建响应
  出现一次。
- `site-api-keys` 表：PK `key_hash`（SHA-256）→ email、name（备注）、
  prefix（`sk-` 后 4 位，展示用——只展示 4 位以保留剩余 12 位约 71 bit
  熵）、created_at、last_used_at、revoked；
  GSI `email-index`（控制台按人列 Key）。
- 吊销 = 置 revoked；交换层每请求查表，即时生效。
- **Key 管理只在控制台**（要求升级会话）。故意不做"MCP 工具管 Key"——
  持 Key 者能再造 Key 会让吊销失去意义。

### 5.2 交换层（key-proxy）

新平台组件，复用路由基建：路由表注册 `mcp.{base_domain}`
（`route_mode=api-only`、`require_auth=False`、`owner=platform`）→ key-proxy
Lambda（Function URL，AWS_IAM 仅 edge role）：

```
客户端（静态 Header: X-API-Key: sk-…）
  → CloudFront → Edge → key-proxy：
     1. SHA-256 查 site-api-keys，验 revoked → 得 email；
        异步更新 last_used_at（节流：每 Key 每小时至多一次写）
     2. 用 machine app client（client_credentials）换 Cognito 机器 token
        （进程内缓存至过期）
     3. 转发原 MCP 请求到 AgentCore endpoint：
        Authorization: Bearer {机器token} + X-SB-On-Behalf-Of: {email}
```

### 5.3 MCP server 信任规则

`_caller_email()` 扩展：token 有 `email` claim 直接用（现有 OAuth 路径不变）；
否则若 token 的 `client_id` == machine client **且**带 `X-SB-On-Behalf-Of`
头，取头值为 caller（只有 key-proxy 持有 machine client secret，且已验 Key）。

**实施期 spike（真机验证后才锁定）**：AgentCore `allowedClients` 加 machine
client 后 client_credentials token 能否过 authorizer；
`requestHeaderAllowlist` 能否放行自定义头 `X-SB-On-Behalf-Of`。任一不通则
回退备选：key-proxy 自签平台 JWT（含 email claim），authorizer 的
discoveryUrl 指向平台自建 JWKS——形态更重，仅在主案受阻时启用。

### 5.3.1 MCP runtime 是站点归属的 TCB（实施期实证，2026-08-05 回写）

**决定**：部署 MCP 的 AgentCore runtime 角色对"站点管理操作"而言属于
**可信计算基（TCB）**。runtime 一旦被攻破，攻击者可接管任意站点的 owner，
进而部署、下线、改权限。这是**已知且被接受**的取舍，不是待修缺陷。

**为什么 IAM 关不掉**（实施期核实，不要再尝试用策略解决）：

- 站点管理的写权限已按 `dynamodb:Attributes` 收窄到白名单，但该条件键约束的是
  **可写哪些字段**，不是**可写哪些行**；
- `owner` 必须留在白名单内——建站要写它、`transfer_owner` 要改它，都是 MCP 的
  正常功能。所以"改 owner 绕过应用层判定"这条路径无法用属性白名单封堵；
- `dynamodb:LeadingKeys` 只能把主体限制在"由其身份推出的分区键"（多租户
  `${...:user_id}` 模式），而单个 runtime 角色服务全部用户、合法地需要访问
  任意 `site_id`；
- 真正的授权规则（`owner` / `collaborators`）**存在数据行里**，是数据驱动的，
  而 IAM 策略是静态的、读不到行内容。

**因此站点归属的最终裁决者是应用层代码 + runtime 角色自身的完整性。**
属性白名单仍然保留，它挡住的是另一层：部署链字段（`data_tables` /
`migrations_applied` / `last_job_id`）与路由的 `static_prefix` / `api_target`
（改后两者可劫持流量）。

**推论：镜像完整性即安全边界。** 既然 runtime 是 TCB，"它跑的是哪份字节"就
等同于"谁能接管站点"。故构建链必须：ECR 仓库 `IMMUTABLE`（省略时 AWS 默认
`MUTABLE`）、镜像 tag 带 git sha、runtime 按 **digest** 而非 tag 部署、基础
镜像钉 digest、依赖锁版本 + `--require-hashes`。详见 DEPLOY.md
「MCP runtime 的信任边界」。注意 `--provenance=false` 与供应链无关，它只是
规避 AgentCore 不认 attestation manifest。

**收敛方向（M3+）**：把建站 / `transfer_owner` / 权限写入拆成**各自持有独立
角色并做服务端授权**的窄接口。§2 已把控制台与 key-proxy 定为"走独立 IAM
角色的平台组件"，届时 MCP runtime 不再持有通用的 sites `UpdateItem`。

### 5.4 MCP 工具面变化

新增 4 工具（与控制台共用 permissions 后端语义），分属两个模块：

| 工具 | 模块 | 授权 | 说明 |
|---|---|---|---|
| `update_site_permissions(site_id, require_login?, allowed_users?)` | M2 | owner/collab/admin | 在线改访问策略 |
| `manage_collaborators(site_id, add?, remove?, transfer_owner?)` | M2 | 仅 owner/admin | 协作者与转移 |
| `get_site_permissions(site_id)` | M2 | owner/collab/admin | 读当前策略、owner、协作者、我的角色 |
| `get_site_stats(site_id, granularity)` | M5 | owner/collab/admin | day/week/month（依赖 M5 的统计表） |

工具数随模块推进：一期 5 → M2 后 8 → M5 后 9。
`test_agentcore_contract.py` 的期望清单每次同步。

现有 5 工具改造：`_assert_owner` 全部替换为角色判定——`deploy_site`（更新）
/`get_deploy_status`/`list_my_sites` 放宽到 collaborator；`undeploy_site`
仍仅 owner/admin。`list_my_sites` 用 sites 表新 GSI `owner-index` + 对
collaborators 的查询替掉全表 Scan（collaborator 维度量小，可先 Scan
FilterExpression contains，站点数上百再优化——记为已知取舍）。

MCP 扩展点四处同步（server.py 工具、deploy_agentcore.py IAM/环境变量、
Dockerfile COPY、test_agentcore_contract.py 工具数断言）按侦察结论逐一处理。

**Quick Desktop 从此可用 Remote MCP + 静态 Header 直连**；stdio 代理
（quick-desktop-proxy）保留为兼容方案，文档降级标注。

## 6. 访问统计管道

### 6.1 采集（Edge 日志行）

`_check_auth` 放行后 print 一行 JSON（一次 print，无网络调用、零延迟）：

```json
{"_sb":1,"site":"<site_id>","e":"<email 或 - >","p":"<path 首段>","t":<epoch>}
```

- 公开站点（require_login=false）`e` 为 `-`（只有 PV 无 UV，两方案本就相同）；
- 静态资源按扩展名过滤（.js/.css/.png 等不记），只记页面与 `/api/*` 请求；
- 平台路由（owner=platform）不记。

### 6.2 聚合（小时级）

EventBridge 每小时触发聚合 Lambda：

1. 对"已发现的 Edge 日志组区域清单"逐区跑 Logs Insights——查询必须同时产出
   audit 需要的时间边界，否则第 4 步无从填 first_ts/last_ts：
   `filter _sb=1 | stats count() as pv, min(t) as first_ts, max(t) as last_ts
   by site, e`；区域清单存 meta item，定期（每日一次）全区
   describe-log-groups 发现新区；
2. 幂等策略：每轮对"水位线以来被触及的自然日"**重查完整当日**（day 起点
   到当前），按 stat_key 覆盖写 day 行——不做增量 ADD，重跑/迟到日志天然
   不重计；水位线（存 stats 表 meta item）只用于确定要重算哪些天（含跨午夜
   的前一天），推进失败下轮自动补算；
3. week/month 行从 day 行二次汇总（同一 Lambda 顺带做，同样覆盖写）；
4. 写 `site-access-audit`（仅鉴权站点）：`email#date` 粒度 upsert
   count/first_ts/last_ts；
5. 周/月 UV 不可从 day 的 uv 加总——从 audit 表反推 distinct email；
   公开站点周/月只有 PV。

### 6.3 数据表与保留期

```
site-access-stats  PK site_id, SK stat_key
                   （"day#2026-07-30" | "week#2026-W31" | "month#2026-07"
                    | "meta#watermark" | "meta#regions"）
                   → {pv, uv}；TTL 400 天
site-access-audit  PK site_id, SK "email#date" → {count, first_ts, last_ts}
                   TTL 90 天
```

原始 Edge 日志组统一设 30 天保留（= 审计原始数据窗口；顺带把现状"永久保留"
的平台 Lambda 日志组——deployer 10 个、auth、pre-token、两个 Edge 函数——
全部补上 30 天 retention，一期遗留清理）。

### 6.4 已知取舍（已接受）

- 小时级延迟：统计不是监控，可接受；
- 跨区聚合复杂度：Edge 日志天然落在请求区，聚合器按区遍历；
- 三期若做 CloudFront 精细缓存，origin-request 执行率下降会低估 PV——
  届时统计数据源需重评（记为三期联动项）。

## 7. 身份层改造

### 7.1 平台专用 user pool（二期第一批）

1. 新建 `site-builder-users` pool（Essentials 档，pre-token V2 需要）+ 域名
   前缀 + pre-token 触发器（迁移现有 `pre_token_email.py`，扩展为同时注入
   email 与 `idp` claim，见 §3.5）。**`AllowAdminCreateUserOnly=True`**
   （关闭自注册，§2 决策 11 的前提）。
2. **IdP 配置保持 IdP 无关**：联邦到任意能给 email claim 的 OIDC IdP。
   当前部署接飞书适配器（feishu-quick-sso，适配器本身零改动；其回调 URL 需
   在飞书应用后台追加新 Cognito 域名——记实施 spike 确认）；标准 IdP
   （Okta 等）按 DEPLOY.md ① 标准 IdP 分支配置。**二期切换时在新 pool 上把
   标准 IdP 分支真机验证一次**（覆盖需求清单 B 组遗留项）。DEPLOY.md 的
   IdP 一节改写为两个平行分支，飞书不再是叙述主线。
3. **两个 app client**：`site`（auth 服务）、`mcp`（OAuth 客户端，回调含
   AgentCore identities + `localhost:18765`）。**`machine`（key-proxy 用）
   不在本期建**——client_credentials 只能授 resource server 的 custom scope，
   空 scope 会被 Cognito 跨字段校验拒绝、导致部署脚本在建 client 这步中止；
   它随 M4 的 resource server 一起建。**API 创建的 app client 必须显式套 branding
   style**：AWS 明确说明经 `CreateUserPoolClient` 建的 client 不会自动获得
   branding style，*在套上之前 managed login 与 classic hosted UI 页面都不可用*
   （见 [CreateUserPoolClient](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html)）——
   控制台建的 client 会自动有，所以这个坑只在脚本化部署时出现。部署脚本对
   `site`/`mcp` 调 `CreateManagedLoginBranding(UseCognitoProvidedValues=True)`
   （用 Cognito 默认样式，不做定制），否则 §7.1 之后的所有登录验证都会在
   `/oauth2/authorize` 第一步失败。**`ManagedLoginVersion` 是 domain 级参数**
   （`CreateUserPoolDomain` / `UpdateUserPoolDomain`）——client API 没有这个
   字段，传进 `CreateUserPoolClient` 会 `ParamValidationError`；domain 不显式
   指定时默认 classic hosted UI（v1），与 managed login 的 branding style 不
   匹配、登录页依然不可用，所以建/更新 domain 时要显式 `ManagedLoginVersion=2`。
   **`site` 与 `mcp` 的
   `SupportedIdentityProviders` 只列企业 IdP，不含 `COGNITO`**——否则托管
   登录仍暴露本地用户登录入口（§3.5 第 1 条）。`machine` 走
   client_credentials，与用户身份无关，不涉及此项。
4. **pre-token 触发器的 Lambda resource policy 必须按 pool 区分
   StatementId**。一期 `ensure_pre_token_trigger` 用固定
   `StatementId="cognito-invoke"` 且把 `ResourceConflictException` 直接
   `pass` 掉：切新 pool 时该语句已存在（绑的是旧 pool 的 SourceArn），冲突被
   吞掉，Lambda policy 里始终没有新 pool 的授权 → 新 pool 的 pre-token 调用
   被拒，email/idp claim 注入失败，MCP 的 owner 识别整条链断掉，且 token
   签发本身可能直接报 trigger 错误。改为 `cognito-invoke-{pool_id}`
   （pool id 里的下划线等非法字符替换为连字符），迁移期新旧两条并存，
   验证通过后再删旧语句。
5. 切换点：auth 服务 config、AgentCore authorizer discoveryUrl/
   allowedClients、onboarding 重生成（`gen_onboarding.py`）。验证通过后清理
   旧 pool 上的平台配置（触发器授权语句、两个 client）——平台与 Quick SSO
   共享 pool 从此解耦。
6. 用户影响：一次性重新登录（站点会话 + MCP OAuth），发一句话公告。
   重新登录也是 §3.5 `REQUIRE_IDP_CLAIM` 开关得以置 true 的前提。

### 7.2 PKCE + nonce（auth 服务）

`/login` 生成 code_verifier + nonce → Hosted UI 带 code_challenge（S256）；
`/callback` 换 token 时带 verifier、验 id_token 的 nonce claim。改动局限
`login_handler.py`。

**verifier 不进 authorize URL 的 state**。RFC 7636 的分工是授权请求只发
`code_challenge`、令牌请求才发 `code_verifier`；把明文 verifier 放进随
authorize URL 传输的 state（即便 state 有 HMAC 签名，内容是 base64 明文），
等于让它经浏览器地址栏、Referer、IdP 侧日志与浏览器历史暴露一遍，PKCE 本
应提供的"授权码被截获也换不到 token"的独立防护就削弱了。本期 site client
是 confidential（有 client secret），所以这不是可直接利用的绕过，但没有理由
自废一层。

做法：`/login` 把 verifier 与 nonce 写进 auth 子域的 host-only 短期 cookie
（`__Host-sb_pkce`，`Max-Age=300`、`Secure`、`HttpOnly`、`SameSite=Lax`），
state 里只放 redirect 与过期时间（仍 HMAC 签名，防 redirect 篡改）。
`/callback` 与 `/login` 同在 `auth.{domain}`，能读到该 cookie；用完即
`Max-Age=0` 清除。cookie 丢失（用户跨浏览器、cookie 被清）时 callback 返回
400 并提示重新登录——比静默降级到无 PKCE 安全。

**为什么不用服务端存储**：auth 服务是多实例无状态 Lambda，存 DynamoDB 要多
一张表加 TTL 清理；host-only 短期 cookie 在同一子域内往返，语义等价且零新增
基础设施。（与 §4.5 的 `__Host-sb_console` 是两个不同 cookie：前者在 auth
子域、生命周期 5 分钟；后者在 console 子域、4 小时。）

### 7.3 面板会话升级（/console-session + console 侧回调）

auth 服务新增 `/console-session`：校验现有顶域 `sb_session` 有效 → 生成
一次性 code（HMAC 签名 + 60s 过期 + 绑 email + jti 落库防重放）→ 302 到
`https://console.{domain}/api/session-callback?code=...`。

**cookie 由 console host 签发**，不是 auth 签发——完整理由与流程见 §4.5。
panel 的 `/api/session-callback` 验 code 后 mint `scope:"console"` 的 JWT
（TTL 4h，同一 JWT_SECRET、同 session.py 算法）并
`Set-Cookie: __Host-sb_console=...`。

**Edge 配套**：`__Host-sb_console` 与 `__Host-sb_pkce` 都加入
`RESERVED_COOKIES`（站点路由剥除，站点代码不可信），但对 platform 路由放行
转发（panel / auth Lambda 要读它们）。`origin_response.py` 的同名列表同步
（一期已有的"站点不得写平台 cookie"约束覆盖到新 cookie）。

### 7.4 Edge 改动汇总（评审 1MB 限制与双同步风险）

collaborators 放行、`_deser` 支持 List、两个 `__Host-` 保留 cookie、
`idp` claim 校验（含 `REQUIRE_IDP_CLAIM` 开关与 `TRUSTED_IDPS` 白名单两个新
占位符）、访问日志 print——均为小改，单文件零依赖模式不变；
`_verify_session_jwt` 与 session.py 的字节级同步约束不变（本期 session.py
增加带 scope/idp claim 的 mint 函数，Edge 不验 scope——scope 校验在 panel
Lambda 侧）。

## 8. 错误处理

| 场景 | 处理 |
|---|---|
| 在线改权限：两表写入 | `TransactWriteItems` 原子提交（§3.2），不存在"一半成功"的中间态。事务被取消时按 CancellationReasons 分流：并发冲突（`permissions_rev` 不匹配）→ 重读后重试一次，仍冲突则返回 409 让用户重试；路由 item 不存在 → 降级为只写 sites 表（站点尚未首次部署成功） |
| 两表仍出现不一致（人为改库、迁移中断等） | 以 sites 表为准；admin 有 `/api/admin/resync/{id}` 手动重投影 |
| 面板写请求缺 Origin / Origin 不匹配 / 非 JSON Content-Type | 403，不做 Referer 回退（§4.5 CSRF 三条同时满足才放行） |
| 会话升级 code 被重放 | jti 已消费 → 400；code 过期（>60s）同样 400，前端重走升级流程 |
| 会话 JWT 缺 `idp` claim | `REQUIRE_IDP_CLAIM=true` 时按未登录处理（302 登录）；迁移宽限期内放行并打点，供确认存量会话已清空。开关停在 false = §3.5 第 3 条未生效，不算完成 |
| `register_route` 与在线改权限并发 | 条件事务（§3.2）：检测到 `permissions_rev` 变化即重读重试（≤3 次），仍冲突则该部署 FAILED——绝不用旧快照把路由写回公开 |
| app client 无 branding style | `/oauth2/authorize` 直接失败（managed login 页面不可用）。部署脚本对 site/mcp 调 `CreateManagedLoginBranding` 后才验证登录（§7.1） |
| 权限修改生效延迟 | Edge 路由缓存 60s；UI/MCP 返回文案统一"约 1 分钟生效" |
| key-proxy 收到无效/吊销 Key | 401 + 统一文案，不泄露 Key 是否存在过 |
| 聚合单区查询失败 | 该区跳过、水位线不推进，下轮重试补齐；stat_key 粒度覆盖写保证幂等 |
| 面板写操作无/过期 `__Host-sb_console` | 401 `{"need":"console-session"}` + 前端自动走 §4.5 升级流程后重放 |
| owner 转移目标邮箱打错 | 平台无通讯录可校验：确认对话框输入两遍 + 原 owner 保留 collaborator 兜底 |
| 管理员误删自己 | 禁止把 admins 名单删空；删自己需二次确认 |
| 存量站点无权限字段 | 迁移脚本回填（§3.4）；迁移前 Edge 行为不变 |
| 迁移遇到无法解析的 allowed_users | 进 errors 报告并跳过该站点，**不降级为 "org"**（§3.4：那会把"仅 owner"扩权成"全体登录用户"） |
| collaborator 部署成功 | 站点 owner 不变（`mark_job` 不再写 owner，§3.3.1）；jobs 表记 `requested_by` |
| 重部署时 site.json 的 auth 与真源不一致 | 按真源部署，job 结果附提示；smoke test 用本次写入的 effective policy 断言（§3.3.2），不用 manifest |
| machine token 过期/被拒 | key-proxy 重取一次 token 再转发；仍失败 502 + 日志 |

## 9. 测试策略

沿用一期分层与工作约定（**每处改动真实 AWS API 实证验证**——本项目 mock 层
出过多次问题）：

- **单测**：permissions.py 角色判定矩阵（owner/collab/admin/none ×
  各操作）；Key 哈希与验证；聚合水位线与窗口重叠逻辑；Edge 新增分支
  （现有 test_edge_auth.py 占位符替换机制自动覆盖）；panel API 授权矩阵
  （借鉴 mcp 的 do_* 纯函数模式，直接测纯函数层）。
- **集成/E2E（真实 AWS）**：
  1. 新 pool 全链路登录（飞书 + 标准 IdP 两分支）；
  2. **公网自注册被拒**：调新 pool 的 `SignUp` 应失败。**必须用无 client
     secret 的 client（`mcp`）做这条负测**——带 secret 的 client 少传
     `SecretHash` 也会返回 `NotAuthorizedException`，用 `site` client 测会把
     "缺 SecretHash" 误判成"自注册已禁用"（假通过）；
  3. **边界：原生认证发不起来**（§3.5 第 4 条，最重要的一条）：对
     `site` / `mcp` client 调 `InitiateAuth`（`USER_PASSWORD_AUTH` /
     `USER_SRP_AUTH`）与 `AdminInitiateAuth` 均须失败（`InvalidParameter` /
     `NotAuthorized`：该 flow 未启用）；`describe-user-pool-client` 的
     `ExplicitAuthFlows` 只有 `ALLOW_REFRESH_TOKEN_AUTH`。
     **这条不过就没有边界**——③ 的 claim 校验可被 refresh 洗白；
  4. **`idp` / `auth_via` claim 全链路（纵深）**：access token 与 **id token**
     里都有这两个 claim（pre-token 的两个容器各写一次）；会话 cookie 的 JWT
     payload 里有；`REQUIRE_IDP_CLAIM=true` 后三类负测被拦（无 `idp`、
     不可信 `idp`、`auth_via=TokenGeneration_Authentication`），而正常托管
     登录的会话仍可访问；MCP 侧跑正负一对（**用同一个 mcp client 签发、
     issuer/client_id 合法但缺 claim 的 token**——用 machine client 的 token
     做负测无效，它的 client_id 不在 authorizer 的 allowedClients 里，
     会在到达容器前被网关拒掉，无论 `_caller_email` 有没有校验都"通过"）；
  5. **refresh 洗白路径已被 ④ 关闭，且暴露窗口有界**：确认无法先拿到原生
     token（第 3 条已验），因此不存在"原生认证 → refresh 刷一次"的洗白链；
     `describe-user-pool-client` 的 `RefreshTokenValidity` ≤ 1 天
     **且 `AccessTokenValidity` ≤ 15 分钟**（只查前者会漏掉吊销后残留的
     access token 窗口）。
     **漂移恢复演练**（至少做一次，证明恢复流程有效）：临时给一个测试用
     client 打开 `ALLOW_USER_PASSWORD_AUTH` → 用它拿一个 refresh token
     **与一个 access token** → 关掉 flow → 确认该 refresh token **仍能**换到
     新 token（这是预期的，证明"改配置不足以恢复"）→ 执行
     `AdminUserGlobalSignOut` 或轮换 client → 确认该 refresh token 失效，
     **并用吊销前那个 access token 再调一次受保护入口，确认它是否仍被接受**
     （AWS 文档说会——把实测结论记进 DEPLOY.md；要立即失效必须轮换 client +
     更新 AgentCore `allowedClients`，或轮换 `JWT_SECRET`）。演练用独立的临时
     client，不要动 site/mcp；
  4. 在线改 allowed_users，60s+缓存窗口内新名单生效（拒绝名单外用户）；
  5. 在线**翻转 require_login**（两个方向各一次）后重部署成功——覆盖
     §3.3.2 的 smoke test 取值路径；
  6. collaborator 能部署更新、看统计；undeploy 被拒；**跑完整 SFN 后
     sites.owner 与路由表 owner 都不变**（§3.3.1 的提权路径回归）；
  7. owner 转移后：新 owner 全权、原 owner 是 collaborator；
  8. 身兼 collaborator 的 admin 仍能 undeploy（§3.3 判定顺序回归）；
  9. **两表事务**：注入路由表写失败（临时改 IAM 拒 UpdateItem 或用不存在的
     路由 item），验证 sites 表不会留下"已私有"而 Edge 仍公开的状态；
  10. API Key 直连（Quick Desktop Remote MCP 静态 Header）完成一次部署；
      吊销后立即 401；
  11. 统计端到端：访问站点 → 下一小时聚合 → 面板/MCP 可查到 PV/UV/审计
      （含 first_ts/last_ts 有值）；
  12. **面板会话隔离与 CSRF**：仅持顶域 `sb_session` 调面板写 API 应 401；
      `__Host-sb_console` 确实由 console host 签发且在 auth 子域不可见；
      伪造 Origin / 缺 Origin / form-urlencoded Content-Type 均 403；
  13. admin 强制下线 + ops-log 留痕。
- **冒烟**：`smoke_router.sh` 扩展 console/mcp 子域探测。
- **迁移彩排**：存量站点（team-reading-list、team-kudos-wall）跑迁移脚本后
  行为不变。

## 10. 实施顺序（供 writing-plans 参考）

| 模块 | 内容 | 依赖 |
|---|---|---|
| M2 权限真源 | sites 表扩展 + GSI + permissions.py + register_route/smoke_test/mark_job/Edge 改造 + 存量迁移 + MCP 权限工具 | 无 |
| M1 身份层 | 新 pool（禁自注册 + 仅企业 IdP + `ExplicitAuthFlows` 不开原生认证=org 边界）+ 2 client（site/mcp）+ pre-token（email+idp+auth_via）+ PKCE/nonce + 切换 + 标准 IdP 验证 | 无 |
| M3 控制台 | panel Lambda + 前端 + 会话升级（console 侧签发 + CSRF）+ admins + ops-log | M2 |
| M4 API Key | keys 表 + key-proxy + AgentCore spike + Quick 直连验证 | M1（与 M3/M5 可并行） |
| M5 统计 | Edge 日志行 + 聚合器 + stats/audit 表 + 面板图表 + MCP 工具 | M2、M3（图表部分） |
| M6 收尾 | E2E 全量、DEPLOY.md 扩写（新阶段：panel/key-proxy/聚合器）、onboarding 重生成、文档同步 | 全部 |

**M2 与 M1 相互独立**（权限判定全以 email 为键，与站在哪个 user pool 上无关）。
推荐顺序 **M2 → M1**：让"在线改权限"这个头号功能最早落地，并把"全员重新
登录 + 两个 IdP 侧 spike"的风险放在其后。反过来（M1 先）也成立——若更希望
一次性把身份切干净、后续都建在新 pool 上。**Edge 的 `idp` claim 校验属 M1**，
但它与 M2 改同一个文件（`origin_request.py`），两模块串行做以免冲突。

**实施 spike 清单**（真机验证后才锁定的点）：

1. AgentCore：client_credentials token 过 authorizer + 自定义头透传（§5.3）；
2. 飞书应用后台追加新 Cognito 域名回调（§7.1）；
3. Logs Insights 跨区查询的权限与配额形态（聚合器 IAM 与并发）；
4. pre-token V2 能否稳定拿到 `identities[0].providerName`（§3.5 的 `idp`
   claim 来源；联邦用户应有，需真机确认字段形态与首次登录时序）。

## 11-pre. M3 前置：运行时正确性、自动化部署与测试卫生（2026-08-09 追加）

> 本节在 M1+M2 全量部署并真机验证后追加（brainstorming 结论）。分两类：
> **Blocking**（M3 核心开发前必须完成）与 **Parallel**（可与 M3 并行，
> 最迟在 M3 最终 E2E 前完成）。M3 本身的细化 spec 见
> `2026-08-09-phase2-m3-console-spec.md`（本文件只增不改的原则不变）。

### 11-pre.1 Blocking 1：SFN 终态 reconciler（两层收敛）

**缺口**：每个 Task 有 `add_catch(States.ALL) → MarkFailed`，但状态机整体
`TimeoutSeconds=1800` 到点产生的 `TIMED_OUT` 与人工 `StopExecution` 产生的
`ABORTED` **不执行任何 State** → `mark_job` 不被调用 → job 永久停在
RUNNING；`confirm_upload` 只接受 PENDING，用户无法重试。历史 0 例，缺口真实。

**Step Functions 状态变化事件是 best-effort**——只实现一条 EventBridge rule
不算闭合，必须两层收敛：

**实时层：EventBridge reconciler**（并入 deployer CDK 栈——它监控的就是本栈
的状态机与 jobs 表，ARN 同栈引用零硬编码，rule/target/DLQ 可被 CDK 断言锁定）：

- rule 只匹配当前 deploy state machine ARN，status 只匹配
  `TIMED_OUT` / `ABORTED`；
- job_id 从 execution ARN 提取 execution name（当前约定 name == job_id），
  **不从不可信/可变的 input 里猜**；
- handler 只在 job 存在且 `status == RUNNING` 时条件更新——**不得照抄
  `_rollback_job_to_pending` 的 `phase=queued` 条件**：timeout/abort 可发生在
  任意 phase；
- 更新内容：`status=FAILED`、保留最后 phase、写入固定且无敏感信息的 error
  文案、刷 `updated_at`；
- job 不存在 → 只记结构化日志，**不得**通过 UpdateItem 凭空创建 job；
- 已 SUCCEEDED / FAILED / DELETED → no-op（条件失败即静默）；
- 重复/乱序事件幂等（条件更新天然幂等，乱序不覆盖终态）；
- Lambda 失败 retry（×2）+ SQS DLQ；
- **独立窄 IAM 角色**（不用 exec_role）：jobs 表条件更新 + 自身日志，无其他。

**兜底层：周期 sweeper**（EventBridge Scheduler 每 30 分钟）：

- 扫描超龄仍 RUNNING 的 job（阈值 45 分钟 = 状态机 1800s 上限 + 余量）；
- 按 execution name（=job_id）拼 ARN 调 `DescribeExecution`：
  - execution 已 TIMED_OUT / ABORTED / FAILED 而 job 仍 RUNNING →
    **与实时层相同的条件更新**收敛到 FAILED；
  - execution 仍 RUNNING → 不处理；
  - 找不到 execution → 记 ERROR 级结构化日志（进告警面），**不直接猜终态**；
- 分页、限流、重复执行安全；不允许扫全表后无界并发（站点量级下串行处理）。

**验收**：

- 单测矩阵：RUNNING+TIMED_OUT→FAILED；RUNNING+ABORTED→FAILED；已
  SUCCEEDED/FAILED/DELETED→no-op；job 不存在→不创建；重复事件幂等；乱序
  事件不覆盖终态；**任意 phase 的 RUNNING 都能收敛**；
- CDK 断言测试锁定 rule / target / IAM / DLQ / schedule；
- 真机验收用临时 execution / 探针 job，**不得 Stop 当前真实生产部署**；
- 扩展 `verify_sfn_failure_paths.py`：证明 EventBridge 与 sweeper 两层均有效。

### 11-pre.2 Blocking 2：登录失败告警自动化部署

**缺口**：现网 `invalid_grant` alarm（metric filter + SNS `site-builder-alarms`
+ alarm，双语描述、AlarmActions/OKActions 均已配）是**手工创建**的；只运行
现有 CDK/部署脚本不会收敛出该配置，"从零部署"得不到相同环境。

**唯一真源 = `deploy_auth.py` 的幂等声明式 provisioning**（brainstorming
决策：告警监控的就是该脚本部署的 auth Lambda 日志组，同一脚本声明全部配套
资源，生命周期一致；**文档中不称其为 IaC**）。不得再维护第二个 writer——
现网手工资源被脚本同名 upsert 收编。

自动收敛的对象与当前环境阈值：

- CloudWatch Logs Metric Filter、SNS Topic、CloudWatch Metric Alarm；
- 双语 AlarmDescription、AlarmActions、OKActions（ALARM 与 OK 同一 topic）；
- Sum / Period=300 / EvaluationPeriods=2 / Threshold=1 /
  GreaterThanOrEqualToThreshold / TreatMissingData=notBreaching。

约束：

- email 地址不写入任何 git tracked 文件——从 gitignored config.ini
  （`[Alerting]`）或环境变量输入；
- subscription 创建幂等（先 list 后建），不得每次部署重复创建；
- `PendingConfirmation` 必须显式报告为「未完成」（email 订阅需收件人手工
  确认，文档写清楚）；从零部署验收必须验证实际 **confirmed** subscription；
- OK 文案统一称**「告警解除」**：只表示指标不再满足阈值，规则仍启用，
  不代表根因确认修复。

**验收**：`verify_auth_alarm.sh` 增加「线上配置 == 脚本声明值」比对段与
confirmed subscription 检查。

### 11-pre.3 Parallel：测试 fixture 自动清理

非阻塞，可与 M3 开发并行，**必须在 M3 最终 E2E 前完成**。

**smoke_router.sh**：

- 随机后缀，禁止固定 `app-smoke*`；
- trap 覆盖成功、失败、Ctrl-C；
- 只删除本次创建的 route / S3 objects；删除后用强一致读 / 实际 S3 list 核对；
- 少于预期断言数判定「未完成」，不能 0/0 通过；
- 显式 `--keep-on-failure` 供排查，默认清理。

**E2E fixture finalizer**：

- 每个测试记录自己创建的 site_id / job_id，只清理本次创建的资源；
- 默认 undeploy + `purge_data=true`；清理范围含 NoSQL table、DSQL
  schema/role、Lambda、IAM role、S3、route；
- **清理失败必须让测试失败**，不能 warning 后继续报绿；
- 失败时可通过显式开关保留现场；
- 不得按 `owner=fixture@test` 之类批量删除历史资源。

### 11-pre.4 组件部署一致性真源脚本重构

`verify_contract_fixtures.py` 的职责已扩到「线上 Lambda 产物 == 本地源码」，
M3 还要覆盖 panel Lambda / permissions.py / common.py 字节比对、panel
Function URL AuthType 与 resource policy、console route、CloudFront 实际
关联的 Edge 版本、console-session callback 的 cookie 行为。**重构为
`verify_deployed_components.py`**：contract scanner 段原样保留为其中一段，
旧脚本删除、文档引用全部同步——组件部署一致性只能有一个真源，不维护两份
互相漂移的脚本。

## 11-clarify. M3/M4/M5 边界澄清（2026-08-09 追加）

§4 是跨 M3/M4/M5 的完整产品视图，不代表其中所有功能都属于 M3：

- **M3 实现**：panel Lambda + Function URL、`deploy_panel.py`、console 静态
  前端与路由、console-session 升级 + CSRF、/api/me、我的/全部站点列表、站点
  基础详情、permissions / collaborators / owner transfer、jobs 历史、
  undeploy / purge_data、admin 名单与代管、admin resync、ops-log；
- **M4**（不在 M3 写假接口/假数据/临时表）：API Key 的 UI 与 API（§4.4 的
  `/api/keys`、§5 全部）。原型（Open Design 侧维护）里的 `sk-site-` 前缀与
  `key_id` 字段与本 spec §5.1（`sk-` + 16 位 base62、PK=`key_hash`）
  **不一致，是 M4 待确认项**，以 M4 实施时的决议为准；
- **M5**（同上不做假实现）：stats / audit 数据、`/api/sites/{id}/stats`、
  `/api/sites/{id}/audit`、图表与站点列表的 PV 迷你趋势；
- 前端对 M4/M5 入口显示明确的 disabled / coming later 状态，或不显示，
  **不得请求不存在的 API**。

M3 的完整细化（window.API 接口契约映射、前端移植方案、安全硬约束展开）见
`docs/superpowers/specs/2026-08-09-phase2-m3-console-spec.md`。

## 11. 范围外（三期候选）

- 全量按站点会话隔离（本期只做控制台）
- SAML IdP 联邦（Cognito 支持；本期只做 OIDC，两者属性映射与部署脚本路径不同）
- **同一 pool 上多 IdP 并存**：本期 `deploy_pool.client_configs` 只接受单个
  `idp_name`，并把 `SupportedIdentityProviders` 整体替换为它——在生产 pool 上
  换 IdP 重跑会把原 IdP 移除、切断线上登录。所以标准 IdP 的真机验证用**独立
  临时 pool**（M1 Task 15 Step 7）。真要并存需要三处同批改并重部署：
  `client_configs` 收 provider 列表、Edge 的 `trusted_idps`、MCP 的
  `TRUSTED_IDPS`——漏掉后两者会让新 IdP 用户拿着合法 token 仍被拦
- **WAF 挡住 user pools API 的原生认证**（`InitiateAuth` 等）：本期的边界是
  app client 的 `ExplicitAuthFlows` 不开原生 flow（§3.5 第 4 条），它在
  "配置正确"的前提下已足够；WAF 的价值是防**配置漂移本身**——例如有人新建了
  一个带原生 flow 的 client、或临时打开又忘了恢复（那种情况下已签发的
  refresh token 需要显式吊销才能失效）。三期评估 WAF 关联 user pool 的基建
  与成本
- CloudFront 精细缓存（与统计数据源联动重评）
- 版本回滚、自定义域名、Fargate 档位、计费/配额、Python 站点 runtime
- 站点级通知（部署结果/统计周报推送）
