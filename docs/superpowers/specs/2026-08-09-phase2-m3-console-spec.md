# Quick Site Builder 二期 M3：控制台（console）细化 spec

- **日期**：2026-08-09
- **状态**：设计已确认（brainstorming 完成），待实施计划
- **母 spec**：`2026-07-30-quick-site-builder-phase2-design.md`（下称 phase2
  spec）。本文件只细化 M3，不重复母 spec 内容；冲突时以本文件为准（更新）。
  M3 前置任务（SFN reconciler / 告警自动化 / fixture 清理 / 验收脚本重构）
  见 phase2 spec §11-pre，本文件不重复。
- **基线**：M1+M2 已全量部署并真机验证（Edge v5 / deployer 8 Lambda /
  auth / MCP runtime v5；六个真机闸门全绿）。
- **UI 参照**：Open Design 侧维护的控制台原型（gitignored
  `docs/design/site-builder-console.html`，1900 行）。其 407–712 行的
  `window.API` mock 是前后端接口契约初稿；本 spec 把它逐个映射到后端能力。
  **该文件不在仓库内编辑**；仓库内的前端副本（见 §3）从此是发布真源。

## 1. 三个前置决策点的落定

1. **在线改权限不重部署**——已由 M2 实现并真机验证：权限真源 = sites 表，
   路由表是投影，`permissions.write_permissions` 事务双写，Edge 每请求读
   路由表（60s 缓存）。UI 文案「约 1 分钟内全网生效」与现实一致。M3 只是给
   已有机制加 Web 入口，**不新建任何权限机制**。
2. **访问统计数据源**——phase2 spec §6 已定杂交方案（Edge 鉴权放行后 print
   日志行 + 小时级跨区聚合），属 **M5**。M3 前端统计入口一律
   disabled / coming later，不发请求。
3. **API Key（`sk-site-` 前缀）**——仓库目前**没有** API Key 体系。原型的
   `sk-site-` 前缀、`key_id` 字段与 phase2 spec §5.1（`sk-` + 16 位
   base62、PK=`key_hash`）不一致，**记为 M4 待确认项**，M3 不实现、不写
   假接口、不建临时表。

## 2. 平台级约束（显式）

**控制台需要跨站点权限，不能作为普通 site-builder 站点部署。** 它要读全量
sites 表、按 permissions.py 写权限（事务含路由表投影）、invoke
`site-deployer-undeploy`——全部超出 `site-runtime-boundary` 的能力面。因此：

- 部署形态：平台组件 `site-builder/panel/` + `deploy_panel.py` 幂等脚本
  （仿 `auth/deploy_auth.py`），phase2 spec §4.1 不变；
- **独立平台 IAM 角色**（panel role），最小化：
  - sites / jobs / admins / ops-log / session-codes 表的必要动作
    （见 §6 逐表清单）；
  - invoke `site-deployer-undeploy`；
  - 自身日志；
  - 路由表：**仅** UpdateItem（permissions.py 的 `write_permissions` 事务
    做权限字段投影所需，与 MCP runtime 同模式；ConditionCheck 所需权限
    一并核对）——没有 PutItem/DeleteItem（整条路由写只属于部署链）；
  - SSM：`ssm:GetParameter` 限定**精确参数 ARN**
    `parameter/site-builder/jwt-secret`（不是 auth role 的
    `parameter/site-builder/*` 前缀——auth 用前缀是因为它还要读
    `site-client-secret`；panel 只需要 JWT_SECRET，照抄前缀会让被攻破的
    panel 顺带读到 Cognito client secret 与该前缀下未来的一切秘密）+
    `kms:Decrypt`（ViaService 条件，机制照抄、资源不照抄；见 §5.4）；
  - **没有**：建删基础设施权限、stats/audit/api-keys 表（M4/M5 才建）；
- 路由表注册 `console` 子域：`route_mode=split`、`require_auth=True`、
  `allowed_users="org"`、`owner=platform`——不进 sites 表，
  `list_my_sites` 不可见，`undeploy_site` 的 owner==邮箱校验天然保护它。

## 3. 前端：移植原型视图层

- 原型视图层（约 1200 行）复制进 `site-builder/panel/frontend/`，去除
  一切真实值（域名、邮箱等 mock 数据全部替换/删除）；
- 原型自我声明「接真后端时只替换 `window.API` IIFE」——照此把 mock IIFE
  换成真 fetch 实现（`/api/*` 相对路径，凭 Edge 会话与
  `__Host-sb_console`）；
- M4/M5 页面（API Key 管理、统计图表、访问审计、站点列表 PV 迷你趋势）
  改为 disabled / coming later 态，**不发请求**；
- 仓库副本从此是发布真源，Open Design 原型仅作设计参考；
- 上传 S3 平台前缀 `platform/console/{version}/`（phase2 spec §4.1）。

## 4. 接口契约：window.API 17 方法 → panel API → 后端能力

鉴权层次见 §5；下表「已有」= 复用 M2 已上线的函数，panel 只做 HTTP 薄封装。

| # | window.API（原型） | panel API | 后端能力 | 状态 |
|---|---|---|---|---|
| 1 | `me()` | `GET /api/me` | Edge 注入 `x-user-email`/`x-user-name`（后者 decodeURIComponent）+ `permissions.is_admin` + 面板会话状态 | 新建（薄封装） |
| 2 | `listSites({scope,q,status,owner})` | `GET /api/sites`，admin 可 `?all=1` | mine：`common.list_sites_for_user`（owner-index ∪ collaborators scan）；all：admin 全表 Scan（分页；站点量级小） | mine 已有；all 新建 |
| 3 | `listOwners()` | 不单独建 | 前端从 `?all=1` 结果派生 | 派生 |
| 4 | `getSite(siteId)` | `GET /api/sites/{id}` | `common.get_site` + `permissions.role_of`（同 MCP `get_site_permissions` 语义），含 url/subdomain/我的角色 | 已有（薄封装） |
| 5 | `updateAccess(siteId, {require_login, allowed_users})` | `PUT /api/sites/{id}/permissions` | `permissions.set_access_policy`（与 MCP `update_site_permissions` 同后端） | 已有 |
| 6 | `setCollaborators(siteId, emails)` | `PUT /api/sites/{id}/collaborators` | `permissions.set_collaborators`（增删语义：panel 侧把目标全量名单 diff 成 add/remove 再调用，或直接暴露 add/remove——实施时取后者，与 MCP `manage_collaborators` 对齐） | 已有 |
| 7 | `transferOwnership(siteId, newOwner)` | `PUT /api/sites/{id}/owner` | `permissions.transfer_owner`（原 owner 自动降协作者） | 已有 |
| 8 | `listDeploys(siteId)` | `GET /api/sites/{id}/jobs` | jobs 表按 site_id 查。现只有 owner-index（发起者维度）——**新增 GSI `site-index`（PK site_id, SK created_at）**。`by` 字段 = jobs.owner（requested_by 语义，phase2 spec §3.3.1）；`duration_s` 从 `updated_at - created_at` 派生，不加新字段 | 新建（含 GSI） |
| 9 | `getAnalytics(siteId, granularity)` | — | 统计管道 | **M5，不做** |
| 10 | `listVisitors(siteId)` | — | 审计表 | **M5，不做** |
| 11 | `undeploySite(siteId, {purge_data})` | `POST /api/sites/{id}/undeploy` | `assert_can(undeploy)` + invoke `site-deployer-undeploy`，权限 rev 快照守卫与 MCP 同路径 | 已有（薄封装） |
| 12 | `listApiKeys()` | — | Key 体系 | **M4，不做** |
| 13 | `createApiKey(label)` | — | 同上 | **M4，不做** |
| 14 | `revokeApiKey(keyId)` | — | 同上 | **M4，不做** |
| 15 | `listAdmins()` | `GET /api/admins` | `permissions.list_admins`（已滤 `__count__`） | 已有 |
| 16 | `addAdmin(email)` | `PUT /api/admins` | `permissions.add_admin`（维护 `__count__` sentinel） | 已有 |
| 17 | `removeAdmin(email)` | `DELETE /api/admins` | `permissions.remove_admin`（禁删空、入口验邮箱格式） | 已有 |

原型之外、属 M3 的补充接口（均已在 phase2 spec 定义）：

| panel API | 后端能力 | 来源 |
|---|---|---|
| `POST /api/admin/resync/{id}` | 以 sites 表为准重投影路由（仅 admin） | phase2 spec §8 |
| `GET /api/session-callback` | 会话升级回调，console host 自己 Set-Cookie | phase2 spec §4.5/§7.3 |

原型 `decorate()` 的 `pv7`（近 7 天 PV）属 M5，前端该列 disabled；
`last_deploy` 从 jobs `site-index` 首条派生。

### 4.1 接口契约核对结论（视图层 ↔ mock ↔ 后端真实代码三方对照）

方法级映射无缺漏、无多余：视图层实际调用的方法全部在上表，上表也没有
视图层用不到的方法。字段级核对发现以下缺口与偏差：

**字段级缺口（后端补齐或前端适配）**：

1. **sites 表没有 `created_at`**（`upsert_site` 全链路从不写它，只有 jobs
   表有）。处理：首次部署路径（`do_deploy_site` 建站分支）开始写入 +
   一次性幂等回填脚本（从 jobs `site-index` 该站点最早一条 job 的
   created_at 推导；仿 `migrate_permissions.py` 模式，已有值跳过）。
2. **sites 表永远不会出现 `status=FAILED`**：`mark_job` 失败分支只写
   job，不碰 site——首次部署失败的站点永远停在 DEPLOYING。处理：**不改
   真源**（重部署失败时站点仍在线服务旧版本，写 site=FAILED 是错的）；
   panel 在**展示层派生**——仅对 `status==DEPLOYING` 的站点查
   `site-index` 最新 job，若 FAILED 显示失败徽章。
3. **phase 词表**：原型 `PHASE_LABEL` 的 key 是 SFN 节点名
   （`Validate`/`PackageBackend`/…），jobs 表实际存小写串（`submitted`
   / `queued` / `validate` / `provision-db` / `package` /
   `deploy-backend` / `upload-frontend` / `register-route` /
   `smoke-test` / `undeploy`）。前端移植时按真实词表重写；注意
   SUCCEEDED 的 job phase 停留在 `smoke-test`（成功分支不再写 phase）。
4. **undeploy 是异步的**（返回 job_id 后 `InvocationType=Event`）：原型
   按同步写（立即置 DELETED）。前端改为提交后显示「下线中」并轮询。

**有 API 无 UI（取向声明）**：

- `POST /api/admin/resync/{id}`：M3 按 **API-only** 交付（罕用人工修复
  操作），不加页面；
- ops-log：M3 只写不读，无查看 UI（M5 的访问审计是另一张表，勿混淆）；
- `GET /api/session-callback`：不可见管道，前端只感知 401→升级→重放；
- 登出：**不是 panel API**——按钮链去已有的 `auth.{domain}/logout`。
  残留的 `__Host-sb_console`（4h）无害：§5.4 已要求 cookie email 与
  `x-user-email` 一致性检查，换人登录后强制重新升级。

**声明即可的偏差（非缺口）**：

- `listSites` 的 q/status/owner 筛选与 `listOwners()`：后端只提供
  `GET /api/sites[?all=1]`，筛选/派生在新 window.API 实现内客户端完成
  （站点量级小）——原型方法签名不变，视图层零改动；
- 原型禁止空 `allowed_users` 名单；后端语义里空名单 = 仅 owner 可访问
  （合法状态）。保留 UI 侧防呆，不算冲突。

**结论：写路径 100% 复用 permissions.py 高层函数**（`assert_can` /
`CAPABILITIES` / `write_permissions` / `snapshot_condition` /
`sites_snapshot_guard` / `set_access_policy` / `set_collaborators` /
`transfer_owner` / `add_admin` / `remove_admin` / `rebuild_admin_count`）。
panel 代码不出现任何手写 DynamoDB UpdateExpression / 角色表 / 权限 rev
守卫；site-admins 不做 raw PutItem/DeleteItem/UpdateItem。现有结构性测试
扫描手写守卫，不得绕过、禁用或改窄其扫描范围。M3 实质新建的后端能力只有
三个：admin 全量站点列表、jobs `site-index` GSI、admin resync。

## 5. 安全硬约束

### 5.1 授权复用（见 §4 结论）

panel Lambda 与 MCP server 同模式引入 `permissions.py` / `common.py`
（构建时复制），授权语义单一真源。

### 5.2 Edge 平台子域白名单

`origin_request.py` 的 `PLATFORM_SUBDOMAINS = ("auth",)` → `("auth",
"console")`。平台身份**只能**由请求 host 解析出的 hardcoded subdomain
白名单判定：

- 不得根据 `route.owner == "platform"` 判断（owner 是可写投影字段，能写
  权限的角色可控——现有代码注释已记录此攻击面）；
- 不得信任 route item 中任何可写字段；
- 客户端伪造 `x-sb-platform-origin` 必须被剥除（现有机制覆盖到 console）；
- 普通 `app-*` route 即使 owner 被写成 platform 也不得获得平台待遇。

同步面（六处）：`origin_request.py`、origin-request 测试、
`origin_response.py` 注释/测试、testable 产物生成机制、Edge 部署、
`verify_deployed_edge.sh`。

`RESERVED_COOKIES`（现为 `("sb_session",)`，origin_request 与
origin_response 两份必须一致）加入 `__Host-sb_console` 与
`__Host-sb_pkce`（M1 实现了 pkce cookie 但未列入保留名单，实施时核对补齐）：
站点路由剥除，平台路由放行转发。

真机必须证明：console callback 的 `Set-Cookie: __Host-sb_console` 到达
浏览器；auth/console 平台 origin 可写各自平台 cookie；普通站点不能写平台
cookie；**CloudFront 实际关联的是新 Edge 版本**（不是只存在一个未引用的
新 Lambda 版本）。

### 5.3 Function URL 只能由 Edge 调用

- `AuthType=AWS_IAM`；resource policy Principal 必须是 exact edge role，
  同时具备 `lambda:InvokeFunctionUrl` 与 `lambda:InvokeFunction`
  （InvokedViaFunctionUrl）两条语句（一期实测坑）；
- 不允许 `Principal=*`、不允许 public Function URL、不允许配置缺失时
  fallback 到宽权限（缺 edge_role_arn 即抛错中止部署）；
- panel role 与 Function URL policy 有 contract test；
- 真机：直连 Function URL 被拒；经 console CloudFront 域名成功。
  只有请求确实经过 Edge，`x-user-email` 才可信。

### 5.4 console-session 与 CSRF 前置于一切业务副作用

所有写 API 在读取/写入业务资源前**按序**完成：

1. `__Host-sb_console` 验签、过期、`scope=="console"`、email 与
   `x-user-email` 一致性检查；
2. `Origin == https://console.{base_domain}`；
3. 缺 Origin 直接拒绝，不回退 Referer；
4. `Content-Type: application/json`；
5. 方法仅 PUT / POST / DELETE；
6. 然后才执行权限判断与副作用。

**不得出现「先更新 DynamoDB，再发现 CSRF 不合法」。**

一次性 upgrade code：HMAC 签名、60 秒过期、绑定 email、**带
context/type 标记**（不能与 login state / PKCE cookie 跨上下文复用）、
jti 原子消费（条件写 `site-session-codes` 表，TTL）、重放拒绝。auth 服务
新增 `/console-session`（校验顶域 `sb_session` → 发 code → 302 到
console callback），panel 的 `/api/session-callback` 验 code 后只设置
host-only `__Host-sb_console`（JWT scope=console，TTL 4h，
`session.py:mint_session_jwt(scope=...)` 已具备）：Secure、HttpOnly、
SameSite=Lax、Path=/、**无 Domain**。

**跨 Lambda 密钥与契约（Codex review 2026-08-09 补齐——安全边界不留给
实施期临场发明）**：

- **密钥交付**：auth（签 code、验 `sb_session`）与 panel（验 code、
  mint/验 `__Host-sb_console`）共用**同一个已存在的 SSM 参数**
  `/site-builder/jwt-secret`——不新开密钥通道。panel 沿用 auth 的运行时
  读取模式：环境变量只下发**参数名**（`JWT_SECRET_PARAM`），Lambda 内从
  SSM SecureString 读取并带 TTL 缓存。**明文密钥严禁进 Lambda 环境变量**
  （`deploy_auth.py` 已注释原因：`GetFunctionConfiguration` 会原样回显，
  拿到 JWT_SECRET 即可伪造任意用户会话）。panel role 需要
  `ssm:GetParameter` 资源限定**精确 ARN**
  `parameter/site-builder/jwt-secret` + `kms:Decrypt`
  （`kms:ViaService = ssm.{region}.amazonaws.com` 条件）。**机制照抄
  auth 的 `read-platform-secrets`，资源不照抄**：auth 用
  `parameter/site-builder/*` 前缀是它自己的业务需要（还要读
  `site-client-secret`），不是最小权限模板——panel 拿前缀等于被攻破时
  顺带交出 Cognito client secret 与该前缀下未来的一切秘密。
- **code 编解码的字节级契约**：编码/解码函数**单一实现**放
  `site-builder/auth/session.py`（与会话 JWT 同文件——它已经是 auth 与
  Edge 之间字节级同步的锚点），panel 构建时复制该文件（同 `common.py` /
  `permissions.py` 的构建时复制模式，`deploy_panel.py` 打包时带上
  `session.py`）。code 载荷字段固定：`typ="console-upgrade"`（上下文
  标记，login state / PKCE cookie 不认此值）、`email`、`jti`、`exp`
  （60 秒）；签名算法与 `mint_session_jwt` 同族（HS256 同密钥）。
- **交叉契约测试**：auth 侧签 code → panel 侧验通过；篡改任一字段 →
  验失败；`typ` 不符（拿 login state 冒充）→ 拒绝；auth 与 panel 两个包
  的测试各跑一遍同一组用例向量（防两份复制品漂移——与 Edge/session.py
  的字节级同步测试同思路）。

### 5.5 ops-log

- 新表 `site-ops-log`（phase2 spec §3.3 形态：PK target、SK
  `{ts}#{actor}`、TTL 400 天），审计记录 append-only；
- panel role 对该表只允许 `PutItem`；
- 记录 actor、action、site_id、result、timestamp、request correlation id；
- 不记录 token、cookie、secret、完整 API Key、上游错误原文；
- 失败操作也要有可判读记录；但日志写入失败不得把已成功的业务动作回滚成
  未知状态（业务成功 + 落日志失败 → 返回成功并打 ERROR 日志）；
- 必须覆盖：admin 强制下线、owner 转移、协作者变更、权限变更、admin
  名单变化；
- **落点在 permissions.py 的高层写函数内部**（唯一真源原则——在 panel
  handler 层落会让 MCP 侧漏记）：`set_access_policy` /
  `set_collaborators` / `transfer_owner` / `add_admin` / `remove_admin`
  与 undeploy 路径各落一条。因此 MCP 与控制台自动同轮覆盖
  （phase2 spec §3.3「控制台与 MCP 的写操作都经 permissions 后端统一落
  一条」）；MCP runtime role 需补该表 PutItem 并重部署 MCP，属 M3。

## 6. 新增/改动资源清单

| 资源 | 动作 | 归属 |
|---|---|---|
| `site-ops-log` 表 | 新建（deployer CDK 栈，RETAIN） | M3 |
| `site-session-codes` 表 | 新建（deployer CDK 栈，TTL——code 由 auth 无状态签发，jti 消费标记由 panel 条件写；表进 CDK 栈以获得断言测试与统一表真源） | M3 |
| jobs 表 GSI `site-index`（PK site_id, SK created_at） | 新增 | M3 |
| panel Lambda + Function URL + panel role | 新建（deploy_panel.py） | M3 |
| console route（路由表） | 新建（deploy_panel.py 注册） | M3 |
| S3 `platform/console/{version}/` | 新建前缀 | M3 |
| Edge：PLATFORM_SUBDOMAINS、RESERVED_COOKIES | 改动 + 重部署 | M3 |
| Edge role S3 policy：`{frontend_bucket}/platform/*` | 新增（现只有 `sites/*`——console 前端走 S3 SigV4 分支，缺则 AccessDenied） | M3 |
| auth：`/console-session` | 改动 + 重部署 | M3 |
| reconciler/sweeper Lambda + rule + DLQ + schedule | 新建（deployer CDK 栈） | M3 前置 B1 |
| 告警管道（filter/topic/alarm/subscription） | 收编进 deploy_auth.py | M3 前置 B2 |
| `verify_deployed_components.py` | 重构自 verify_contract_fixtures.py | M3 前置 |
| sites `created_at` 回填脚本 | 一次性幂等（§4.1 缺口 1） | M3 |
| stats / audit / api-keys 表 | **不建** | M4/M5 |

## 7. 测试硬约束

- **加固测试必须先反向验证会红**：把守卫改成永真、模拟 direct Function
  URL、伪造平台 route、删 CSRF 检查，确认测试失败，再还原；
- 源码文本断言排除注释/docstring，或改用 AST / 实际产物解析；
- 断言脚本有最小检查数；中途崩溃、AWS 调用失败、下载截断都非零退出；
- unit test 绿 ≠ 部署生效：必须下载并比对真实 Lambda / Edge 产物
  （`verify_deployed_components.py`）；
- panel E2E 至少覆盖：普通 owner；collaborator；outsider；admin；owner
  transfer；collaborator 禁止 undeploy；admin 撤销立刻生效；
  console-session 缺失/过期/重放；缺 Origin/伪造 Origin/form content
  type；direct Function URL 被拒；console callback cookie 真正在浏览器
  可见；panel 权限写入后 sites/route 两表一致；下线与 purge；ops-log
  留痕。

## 8. 实施顺序（供 writing-plans）

1. SFN reconciler + sweeper（Blocking，phase2 spec §11-pre.1）；
2. 告警自动化部署（Blocking，§11-pre.2）；
3. M3 核心（panel 后端 → Edge/auth 改造 → 前端移植 → 部署与真机验收，
   `verify_deployed_components.py` 重构在部署验收段完成）；
4. fixture 自动清理（§11-pre.3）最迟在最终 E2E 前完成。

## 9. 范围外（重申）

API Key（M4）、stats/audit（M5）、全量按站点会话隔离（三期）、原型里
一切 mock 数据形态（`sk-site-` 前缀、`key_id`）不构成约定。
