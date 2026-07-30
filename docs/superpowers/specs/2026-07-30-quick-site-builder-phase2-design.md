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

   ⑤ 身份层：平台专用 user pool（二期第一批切换）+ PKCE/nonce 增强
              + /console-session 面板会话升级端点
```

**新增资源**：panel Lambda、key-proxy Lambda、聚合器 Lambda、5 张 DynamoDB 表
（`site-access-stats`、`site-access-audit`、`site-api-keys`、`site-admins`、
`site-ops-log`）、1 条 EventBridge 定时规则、1 个新 user pool + 3 个 app client。

**改动组件**：sites 表（+权限字段 +GSI，成为真源）、register_route（从 sites
表读权限）、Edge origin-request（+collaborators 放行、+List 反序列化、
+sb_console 保留 cookie、+访问日志行）、MCP server（+3 新工具、角色判定替换
owner 校验、信任代理 on-behalf 头）、auth 服务（PKCE/nonce、/console-session）。

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
   处可用的体验保留）；控制台写操作要求 host-only 的 `sb_console` cookie
   ——把隔离投在风险最高的地方。全量按站点隔离记为后续增强。
9. **身份层保持 IdP 无关**。新 pool 联邦到任意能给 email claim 的 OIDC/SAML
   IdP：当前用飞书适配器（feishu-quick-sso），标准 IdP（Okta 等）按
   DEPLOY.md 已有分支配置。平台全部组件只消费 email/name claim。二期切新
   pool 时顺带把标准 IdP 分支真机验证一次（覆盖需求清单 B 组遗留项）。
10. **管理员名单存平台表 + config 种子**。首个管理员从 config.ini 幂等注入，
    后续由现有管理员在控制台增删——管理员变更不走重部署，与二期"在线改"
    主旨一致。

## 3. 权限模型与数据真源

### 3.1 sites 表扩展（权限唯一真源）

现有字段不动，新增：

```
require_login            BOOL
allowed_users            "org" | List<String>（原生 List，不再是 JSON 字符串）
collaborators            List<String>
permissions_updated_at   ISO8601
permissions_updated_by   email
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
- **在线改权限**：同一后端函数内"写 sites 表 → UpdateItem 同步路由表权限
  字段"两步；路由表侧只 update 权限字段、不整条覆盖，避免与部署原子切流
  互踩。
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
  表），输出角色（owner/collaborator/admin/none）；MCP server 与 panel
  Lambda 各自引入（沿用 common.py 的构建时复制模式）。现有 `_assert_owner`
  全部替换为按操作粒度的角色判定。

### 3.4 存量迁移

一次性脚本：遍历路由表，把 require_auth/allowed_users/owner 回填到 sites 表
（已有权限字段的跳过）。迁移完成前 Edge 仍以路由表现值工作，无中断窗口。
allowed_users 从 JSON 字符串转原生 List 在回填时完成；Edge 的 `_deser` 先上
（兼容两种格式读），投影写入后统一为 List。

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
```

### 4.5 鉴权两层

- **身份**：Edge 注入的 `x-user-email`（读操作直接用）。
- **写操作**（权限修改、undeploy、Key 管理、admin 操作）额外要求面板会话
  cookie `sb_console`：panel 返回 401 时前端自动 302 经 auth 服务
  `/console-session` 静默升级（用户无感，不多一次扫码），升级后重放请求。
  防站点 XSS 偷顶域 `sb_session` 后冒充调面板写 API。

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

### 5.4 MCP 工具面变化

新增 3 工具（与控制台共用 permissions 后端语义）：

| 工具 | 授权 | 说明 |
|---|---|---|
| `update_site_permissions(site_id, require_login?, allowed_users?)` | owner/collab/admin | 在线改访问策略 |
| `manage_collaborators(site_id, add?, remove?, transfer_owner?)` | 仅 owner/admin | 协作者与转移 |
| `get_site_stats(site_id, granularity)` | owner/collab/admin | day/week/month |

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

1. 对"已发现的 Edge 日志组区域清单"逐区跑 Logs Insights
   （`filter _sb=1 | stats count() by site, e`）；区域清单存 meta item，
   定期（每日一次）全区 describe-log-groups 发现新区；
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
   前缀 + pre-token 触发器（迁移现有 `pre_token_email.py`）。
2. **IdP 配置保持 IdP 无关**：联邦到任意能给 email claim 的 OIDC/SAML IdP。
   当前部署接飞书适配器（feishu-quick-sso，适配器本身零改动；其回调 URL 需
   在飞书应用后台追加新 Cognito 域名——记实施 spike 确认）；标准 IdP
   （Okta 等）按 DEPLOY.md ① 标准 IdP 分支配置。**二期切换时在新 pool 上把
   标准 IdP 分支真机验证一次**（覆盖需求清单 B 组遗留项）。DEPLOY.md 的
   IdP 一节改写为两个平行分支，飞书不再是叙述主线。
3. 三个 app client：`site`（auth 服务）、`mcp`（OAuth 客户端，回调含
   AgentCore identities + `localhost:18765`）、`machine`（key-proxy，
   client_credentials，新增）。
4. 切换点：auth 服务 config、AgentCore authorizer discoveryUrl/
   allowedClients、onboarding 重生成（`gen_onboarding.py`）。验证通过后清理
   旧 pool 上的平台配置（触发器、两个 client）——平台与 Quick SSO 共享
   pool 从此解耦。
5. 用户影响：一次性重新登录（站点会话 + MCP OAuth），发一句话公告。

### 7.2 PKCE + nonce（auth 服务）

`/login` 生成 code_verifier（进签名 state）+ nonce → Hosted UI 带
code_challenge（S256）；`/callback` 换 token 带 verifier、验 id_token 的
nonce claim。改动局限 `login_handler.py`。

### 7.3 面板会话升级（/console-session）

auth 服务新增端点：校验现有顶域 `sb_session` 有效 → 签发第二个 JWT
（claims 加 `scope:"console"`，TTL 4h，同一 JWT_SECRET、同 session.py 算法）
种 host-only cookie `sb_console`（不设 Domain 属性，仅 console 子域可见）
→ 302 回面板。

**Edge 配套**：`sb_console` 加入 `RESERVED_COOKIES`（站点路由剥除），但对
platform 路由放行转发（panel Lambda 要读它验证写操作）。

### 7.4 Edge 改动汇总（评审 1MB 限制与双同步风险）

collaborators 放行、`_deser` 支持 List、`sb_console` 保留 cookie、访问日志
print——均为小改，单文件零依赖模式不变；`_verify_session_jwt` 与
session.py 的字节级同步约束不变（本期 session.py 增加 scope claim 的 mint
函数，Edge 不验 scope——scope 校验在 panel Lambda 侧）。

## 8. 错误处理

| 场景 | 处理 |
|---|---|
| 在线改权限：sites 表成功、路由表同步失败 | 同函数内重试一次；仍失败回滚 sites 表并报错（可重试）。不一致时以 sites 为准，admin 有 `/api/admin/resync/{id}` 手动重同步 |
| 权限修改生效延迟 | Edge 路由缓存 60s；UI/MCP 返回文案统一"约 1 分钟生效" |
| key-proxy 收到无效/吊销 Key | 401 + 统一文案，不泄露 Key 是否存在过 |
| 聚合单区查询失败 | 该区跳过、水位线不推进，下轮重试补齐；stat_key 粒度覆盖写保证幂等 |
| 面板写操作无/过期 sb_console | 401 + 前端自动跳 /console-session 升级后重放 |
| owner 转移目标邮箱打错 | 平台无通讯录可校验：确认对话框输入两遍 + 原 owner 保留 collaborator 兜底 |
| 管理员误删自己 | 禁止把 admins 名单删空；删自己需二次确认 |
| 存量站点无权限字段 | 迁移脚本回填（§3.4）；迁移前 Edge 行为不变 |
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
  2. 在线改 allowed_users，60s+缓存窗口内新名单生效（拒绝名单外用户）；
  3. collaborator 能部署更新、看统计；undeploy 被拒；
  4. owner 转移后：新 owner 全权、原 owner 是 collaborator；
  5. API Key 直连（Quick Desktop Remote MCP 静态 Header）完成一次部署；
     吊销后立即 401；
  6. 统计端到端：访问站点 → 下一小时聚合 → 面板/MCP 可查到 PV/UV/审计；
  7. 面板会话隔离：仅持顶域 sb_session 调面板写 API 应 401；
  8. admin 强制下线 + ops-log 留痕。
- **冒烟**：`smoke_router.sh` 扩展 console/mcp 子域探测。
- **迁移彩排**：存量站点（team-reading-list、team-kudos-wall）跑迁移脚本后
  行为不变。

## 10. 实施顺序（供 writing-plans 参考）

| 模块 | 内容 | 依赖 |
|---|---|---|
| M1 身份层 | 新 pool + 3 client + 切换 + PKCE/nonce + 标准 IdP 验证 | 无（第一批） |
| M2 权限真源 | sites 表扩展 + GSI + permissions.py + register_route/Edge 改造 + 存量迁移 + MCP 权限工具 | M1 |
| M3 控制台 | panel Lambda + 前端 + /console-session + admins + ops-log | M2 |
| M4 API Key | keys 表 + key-proxy + AgentCore spike + Quick 直连验证 | M1（与 M3/M5 可并行） |
| M5 统计 | Edge 日志行 + 聚合器 + stats/audit 表 + 面板图表 + MCP 工具 | M2、M3（图表部分） |
| M6 收尾 | E2E 全量、DEPLOY.md 扩写（新阶段：panel/key-proxy/聚合器）、onboarding 重生成、文档同步 | 全部 |

**实施 spike 清单**（真机验证后才锁定的点）：

1. AgentCore：client_credentials token 过 authorizer + 自定义头透传（§5.3）；
2. 飞书应用后台追加新 Cognito 域名回调（§7.1）；
3. Logs Insights 跨区查询的权限与配额形态（聚合器 IAM 与并发）。

## 11. 范围外（三期候选）

- 全量按站点会话隔离（本期只做控制台）
- CloudFront 精细缓存（与统计数据源联动重评）
- 版本回滚、自定义域名、Fargate 档位、计费/配额、Python 站点 runtime
- 站点级通知（部署结果/统计周报推送）
