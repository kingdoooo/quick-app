# S1 · 隔离与鉴权加固 设计文档

> 输入来源：`docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`（Claude + Codex
> 两轮独立对抗性审查合并版，v3）。本文只覆盖该文档拆出的 **S1** 包：M01、M02、M05、M06。
> 其余包（S2 迁移可重放性 / S3 部署期正确性 / S4 守卫化 / S5 账号边界）各自独立成 spec。
>
> **红线**：本文不含真实账号 ID / 域名 / site_id / 邮箱 / 角色名，一律用占位符。

## 0.5 v2 修订（Codex 复核 No-Go 后）

Codex 复核 v1 给出 No-Go，其中一条 P1 成立且是**设计错误**，已改：

**v1 选了「M01 靠下次部署自然收敛，不写迁移脚本」，理由是残留只有
「休眠站点保留通配、何时修完不可知」。那个理由是错的。** 通配是**向前看的**：
`table/site-data-{A}-*` 覆盖的是所有以 A 的 id 为前缀的 site_id，
**包括 S1 上线之后才创建的**。所以懒收敛不是"旧风险留在原地"，
而是把每个存量站点都留成**对未来任意嵌套站点生效的陷阱**——
M01 的修复对现存站点等于没生效。已实测该匹配为 True。

**实测存量（只读，跑在提交 `33f88df` 之前；为什么不用日期做锚见 §8.1）**：

| 项 | 数 |
|---|---|
| 存量 `site-rt-*` 角色 | **7** |
| 其中带通配的 | **7（全部）** |
| 带 DynamoDB 通配 `table/site-data-{id}-*` | 2（即 2 个 `fullstack-nosql` 站点） |
| 带日志组裸前缀 `/aws/lambda/site-{id}*` | **7（全部）** |
| 已是精确 ARN 的 | 0 |
| DELETED 站点遗留的孤儿角色 | 0 |

**⇒ 存量角色 backfill 纳入 S1**（见 §4.2.1），并以「不合格角色数 == 0」
作为**硬发布闸门**。backfill 零人工：2 个 nosql 站点的 sites 行有 `data_tables`
（`provision_dynamodb` 为让 undeploy 精确删除而持久化），5 个 sql 站点是 DSQL、
本就没有 DynamoDB 语句。

其余同轮接受的修订（细节见 plan 的对应任务）：体检脚本改为复用同一份严格解析
而不是手抄第二套；AST 守卫的声称范围收敛到实际覆盖；补真正的 GSI 触发器；
ops_log 覆盖三个投影 writer 而不只是写路径；部署顺序里的 Edge 等待点从
「router 之前」移到「router 之后并等 CloudFront `Status == Deployed`」。

---

## 1. 背景与目标

四条 finding 共享同一个失效形态：**不变量的检查存在，但绕过它的东西到达了检查点。**

| ID | 一句话 | 严重度 |
|---|---|---|
| M01 | per-site IAM 资源用 `site-data-{site_id}-*` 前缀匹配，而 site_id 可嵌套 ⇒ 跨站点读写 | P1 |
| M02 | 权限写入层把坏数据洗成合法的 `BOOL False` / `"org"`，反转 Edge 的 fail-closed | P1 |
| M05 | 会话 verifier 不查 `typ`，升级码可当会话用且可无限续期 | P2 |
| M06 | `_get_cookie` 只取第一条同名 cookie ⇒ 路径遮蔽造成全平台 `/api/*` 持久 DoS | P2 |

**目标**：把这四条不变量各收敛到**一处定义**，并给每处配一条**先会红**的守卫，
使同一类缺陷不能靠"再抄一份"回来。

**非目标**：不追求把这四条背后的架构问题一次改完（见 §2 与 §8）。

## 2. 范围

### 2.1 做

- M02：新增严格解析函数，**三个投影 writer** 改为调用它（带审计的入口）；
  第四个 writer（迁移入口）形态不同，收紧方式见 §4.1。
- M01：表名格式提成唯一定义；per-site IAM 策略改为精确 ARN；收窄日志组资源；
  **存量角色 backfill + 「不合格角色数 == 0」硬闸门**（v2 纳入，见 §4.2.1）。
- M05：会话 token 加 `typ`，verifier 增加**必填** `expected_typ`；auth 与 Edge 内嵌两份同步。
- M06：`_get_cookie` 改为返回全部同名值并逐个验签，带候选上限。

### 2.2 明确不做（防范围膨胀）

| 不做 | 理由 | 归属 |
|---|---|---|
| host-only 会话重设计 | 会话不能再跨子域共享，而"登录一次访问所有站点"正是靠顶域 cookie 成立；需要重新设计站点级会话交换，属产品级改动 | 独立成包 |
| ~~M01 存量迁移脚本~~ | **v2 已纳入**（见 §0.5 与 §4.2.1）——懒收敛会让每个存量站点成为对未来嵌套站点生效的陷阱 | S1 内 |
| 读取侧统一严格解析（`get_site` 包一层） | 会让只读路径（panel 展示、analytics 授权）也在坏数据上抛错，把写入侧问题扩散成站点级不可用，破坏"坏数据 fail-closed 但站点仍可服务"这个既有性质 | 已否决 |
| 部署合同变更 | 强制 `IF NOT EXISTS` 要同步 contract / skills / fixtures 三处，影响所有生成方 | S2 |
| ~~通配策略残留的可观测性~~ | **v2 已纳入**：不再是"可观测性"，而是 §7.2 的**硬发布闸门**（不合格角色数 == 0） | S1 内 |
| `PolicyDataInvalid` 告警 | 当前 0 例，且这是"数据脏了"而非"正在被攻击"，告警不成比例 | S4（按需） |

## 3. 总体设计

S1 不新增组件。它落地为 **5 个「唯一定义」**：

| # | 唯一定义 | 现状 | 服务 |
|---|---|---|---|
| 1 | `permissions.effective_policy(site)` → 干净 dict 或抛 `PolicyDataInvalid` | 不存在；坏数据处理散在 4 个 writer | M02 |
| 2 | `common.site_table_name(site_id, logical)` | **手写在 3 处** | M01 |
| 3 | `common.site_policy(site_id, engine, *, tables)` | 现签名两参，资源用通配 | M01 |
| 4 | `session.verify_session_jwt(..., *, expected_typ)` | 无 typ 概念 | M05 |
| 5 | `origin_request._get_cookies(request, name)`（复数）+ 上限 | 只返回第一条 | M06 |

第 2 项是实施期发现的：表名格式 `site-data-{site_id}-{logical}` 被手抄在
`common.py:592`（授权）、`provision_dynamodb.py:12`（建表）、`undeploy.py:43`（删表）
三处，而 M01 的修复恰好要求这三处对同一格式达成一致。不抽出来就等于在三处各写一遍新格式。

### 3.1 唯一的跨组件顺序约束

**M05 必须 auth 先、Edge 后。** Edge 全球复制需 10–20 分钟；窗口内 auth 已签发带 `typ`
的 token 而 Edge 尚未要求它——这是安全方向。反过来（Edge 先要求）会让所有既有会话
与新签发会话同时失效 ⇒ 全站锁死。

## 4. 组件设计

### 4.1 M02 · `effective_policy(site)`

新增异常 `PolicyDataInvalid`。解析用**一条统一判据**而非逐字段特判：

> 每个字段**要么类型明确，要么它的「缺失」有唯一安全解释**；两者都不成立即抛错。

| 字段 | 合法形态 | 缺失时 | 理由 |
|---|---|---|---|
| `require_login` | 真 `bool` | **抛错** | 缺失无唯一解释（True 还是 False？） |
| `allowed_users` | `"org"` 或 `list[str]`（邮箱过 `EMAIL_RE`） | **抛错** | 缺失无唯一解释（org 还是空名单？） |
| `collaborators` | `list[str]` | `[]` | 唯一安全解释：没有协作者 |
| `owner` | 非空 `str` | **抛错** | 站点必须有 owner |

返回 `{"require_login": bool, "allowed_users": "org" | list[str], "collaborators": list[str], "owner": str}`。

**三个投影 writer 改为调用它**（v2 更正了 v1 "四个 writer 全部调用它"的说法
——第 4 个形态不同，见下）：

1. `permissions.write_permissions`（`permissions.py:507-511`）
2. `permissions.resync_route`（`permissions.py:760-788`）
3. `register_route._route_item`（`register_route.py:119,129`）—— **部署路径，两轮审查都漏了这一个**

第 4 个 writer `scripts/migrate_permissions._parse_allowed`（`migrate_permissions.py:55-82`）
**不能调 `effective_policy`**：它的输入是路由表的原始 AttributeValue，
不是一行 sites 记录，签名根本不匹配。它的收紧方式是
**把 allowed_users 的规则委托给同一个底层原语 `normalize_allowed_users`**，
并删掉那条基于过时 Edge 默认的 `"org"` 回落。规则仍然只有一处定义，
只是入口不同。

**守卫相应分三条**（v1 只有一条，且 docstring 声称"防第五个 writer"是假话
——它是硬编码名单）：
1. 针对已知三个 writer 的 tripwire（不许直接 `site.get(<权限字段>)`）；
2. **自动发现版**：任何函数体里出现字面量 `require_auth` 的函数都必须调
   **`effective_policy_audited`**（只接受带审计的那个——接受纯函数会让
   "某个 writer 绕过审计包装"照样通过守卫）；
3. **边界哨兵**：`functions/` 下除 permissions / register_route / smoke_test
   之外的模块不得出现该字面量。否则第三个模块里的新 writer 仍会逃过第 2 条
   （它的扫描边界只有两个文件）。

第 3 个是实施期发现的：`_seed_permissions` 用 `if_not_exists(...)`，**只补缺失字段、
不碰错类型字段**，所以 `require_login = Decimal(0)` 会穿过种子逻辑，在 `:129` 被
`bool()` 洗成字面 `BOOL False` 写进路由——**每次部署都重洗一遍**。

第 4 个当前是**反例**（它已显式抛错），但它保留的「属性整体缺失 ⇒ `"org"`」回落，
理由引用的是 Edge 的旧默认（`route.get("allowed_users", "org")`）。**Edge 已改成
缺失即空名单**，该推导已过时，注释与实现一并改正。

#### 两个诚实的代价

1. **`resync_route` 的 docstring 论证要重写。** 它现在明写「让一个修复工具在最需要它
   的脏数据上抛异常，等于没有这个工具」——统一拒绝后这句不再成立。新论证：
   **修复投影漂移 ≠ 修复源数据损坏**，后者必须由人判定意图。
2. **坏数据行会让站点既不能改权限、也不能部署**，直到人修那一行。这是选定的方向
   （三个投影 writer + 迁移入口统一拒绝），代价可接受的前提是错误文案**直接给出修法**——
   否则这条就变成第二个 M03（见 §5）。

### 4.2 M01 · 精确 ARN

- `common.site_table_name(site_id, logical) -> str`：格式唯一定义，替换手写的三处。
- `common.site_policy(site_id, engine, *, tables: list[str]) -> str`：
  `engine == "dynamodb"` 时**每张表发一条精确 Resource**，不用任何通配。

  `tables` 的接口约定（写明以免实现时各自猜）：
  - **必填关键字参数**，即使 engine 不是 dynamodb 也要传——迫使调用方表态，
    而不是靠默认值悄悄跳过；
  - `engine` 为 `"dsql"` 或 `"none"` 时**忽略**它（这两种没有 DynamoDB 表）；
  - `engine == "dynamodb"` 且 `tables` 为空 ⇒ **抛错**（schema 要求至少一张表，
    且空 Resource 列表本身是非法 IAM）。
- `common.ensure_site_role(site_id, engine, *, tables)` 透传。两个调用点：
  - `deploy_lambda_site.py:164` —— 从 `event["manifest"]["database"]["tables"]` 取
    （已确认 manifest 在该处可用，`:163` 就在读它）；
  - `provision_dsql.py:109` —— 传 `tables=[]`（DSQL 站点没有 DynamoDB 表）。
- **日志组收窄**：函数名就是 `site-{site_id}`，日志组是精确的
  `/aws/lambda/site-{site_id}`。收窄成该精确名 **加** `:*` 两条——
  `CreateLogStream` / `PutLogEvents` 作用在 stream 层，只给 group ARN 会 403。

#### 为什么不用「拒绝像 site_id 的站点名」

审查 v1 曾提议在 `validate_site_name` 拒绝 fullmatch `SITE_ID_RE` 的名字。**不充分**，
已实测：名字 `foo-k3d9x1-longname` 合法、**不** fullmatch `SITE_ID_RE`，
而它产生的 id `foo-k3d9x1-longname-{6位}` 仍被 `site-data-foo-k3d9x1-*` 匹配。
该正则规则**只作为纵深防御可选保留**，不算修复。

#### GSI

当前**不需要** `table/<name>/index/*`：`provision_dynamodb` 不建任何 GSI，
contract schema 也不允许声明索引（两处均已核）。

**但 v1 把这条记成"T3 的精确 ARN 断言会在加 GSI 时变红"是错的**（Codex 指出）
——那三条断言压根不看索引 ARN，将来加了 GSI 它们仍会全绿，而运行时访问索引
会因缺 `table/.../index/*` 而 403。所以要一条**真正的触发器**：断言
`provision_dynamodb` 不创建 GSI、且 contract schema 不接受索引声明；
将来谁加了 GSI 支持，这条变红并强制他同步 `site_policy`。

### 4.2.1 存量角色 backfill（v2 纳入）

一次性脚本，枚举**实际存在的 IAM 角色**（`site-rt-*`）而不是遍历 sites 行
——孤儿角色（下线清理失败留下的）恰恰是最该收的那类。对每个角色调用
**同一个** `ensure_site_role(site_id, engine, tables=...)` 重写 policy，
不另写一条策略构造路径。

engine 与 tables 的来源：

| 来源 | 用途 | fail-closed |
|---|---|---|
| sites 行的 `tier` | 经 `common.tier_engine(tier)` 得 engine | 未知 tier ⇒ 跳过该角色并计入"需人工"，不猜 |
| sites 行的 `data_tables` | engine 为 dynamodb 时的表清单 | 缺失而 engine 是 dynamodb ⇒ 跳过并计入"需人工" |

**`tier_engine` 也要提成唯一定义**：真源是 `contract.schema.TIER_ENGINE`
（`{"static": "none", "fullstack-nosql": "dynamodb", "fullstack-sql": "dsql"}`），
而 `undeploy.py:180` 已经手抄了第二份（`"dsql" if tier == "fullstack-sql" else
"dynamodb"`）。加 `common.tier_engine()` 并让 `undeploy.py:180` 也用它，
配一条守卫断言它与 `contract.schema.TIER_ENGINE` 逐项一致。
（这是本轮发现的第 6 个"手抄多份"，与 §3 那五个同类。）

**硬闸门**：脚本跑完后断言 不合格角色数 == 0。判据四层，缺一不可：

1. **实际 site-scope 与「从当前 sites 行推导的期望 policy」完整文档等值**，
   而不是「没有通配」：指向错误账号、错误 region、或漏了某张表的 policy 都
   不含通配，却同样不可用。**等值必须是递归规范化后的整文档比较**（只对
   无序列表排序，不丢字段）——只比 (Effect, Action, Resource) 会把「精确
   ARN + 额外限区 Condition」判成合格，--check 绿而站点不可用（Codex 指出）。
2. **角色上只许有 site-scope 这一条 policy**：inline 除 site-scope 外必须
   为空、attached 必须为空。只比 site-scope 会对"多出来的调试 policy"失明
   ——boundary 对全部 DynamoDB 数据动作放行整个 `site-data-*`，残留的
   identity policy 与它取交集仍是有效跨租户权限（Codex 指出：IAM 的评估
   规则是 identity policies 的并集与 boundary 取交集）。多余 policy 计
   "需人工移除"，**不自动删**——自动删未知 policy 违反"判不出就不猜"。
3. **反向存在性**：从 ACTIVE 非 static 的 sites 行反推，期望角色必须全部
   存在。只从现存 site-rt-* 角色出发是单向的——"角色整个缺失"不可见，
   IAM 里一个角色都没有时闸门反而全绿。缺失计"需人工"，**不自动重建**：
   ACTIVE 站点的角色凭空消失本身是异常（谁删的？），自动重建会盖掉根因；
   这也让备份免于出现"角色原本不存在"态——GetRolePolicy 的 NoSuchEntity
   分不出"角色不存在"和"角色在、只缺 policy"，自动重建就得让回滚会删
   整个角色（Codex 指出的 null 歧义）。分流需人工后回滚永远不删角色。
4. **功能模拟**：`--check` 在前三层全绿后，对**全部** dynamodb 站点跑
   IAM 策略模拟器验收，动作为期望 policy 里的**全部** DynamoDB 数据动作
   （从期望现取，不手抄第二份）：自己的表每个动作都 allowed、嵌套邻居的表
   **任何一个动作** allowed 都算失败——只模拟 GetItem 验不出"邻居表可写"，
   M01 的读写修复就只验了读（Codex 指出）。模拟器会算 permissions
   boundary 与角色全部 identity policy，反映真实判定。

这条同时进 §7.2 的真机验收——非 0 就不算 S1 交付完成。

### 4.3 M05 · 必填 `expected_typ`

`session.py`：
- `mint_session_jwt` 加 `typ: "session"` claim；
- `verify_session_jwt(token, secret, now=None, *, expected_typ)` —— **必填关键字参数**；
- `mint_upgrade_code` / `verify_upgrade_code` 不动（已有并已检查 `typ`）。

调用方（全部显式传）：
- `login_handler.py:491`（`/console-session` 读 sb_session）→ `expected_typ="session"`。
  **这一行就是链式续期的修复点**：当前它用不查 typ 的 verifier，
  于是把升级码当 sb_session 递进来即可换出**新的**升级码，无限续期，
  「60 秒 + 一次性」两个属性同时失效。
- `console_session.py:131`（`verify_console_cookie`）→ `expected_typ="session"`。
  面板 cookie 是带 `scope="console"` 的会话 JWT，因此也带 `typ="session"`；
  两道检查正交、互不替代。
- Edge 内嵌 `_verify_session_jwt`（`origin_request.py:452-470`）→ 要求
  `claims.get("typ") == "session"`。

三个 `verify_*_e2e.py` 通过 `mint_session_jwt` 造会话，自动带上 typ，无需改。

#### 「全员重登一次」分两波发生

已确认**不设宽限期**（理由：本项目已有多次"迁移宽限开关没人翻回来"的教训，
再加一个临时放行开关正是那个形态）。后果分两波：

1. **auth 部署完成的那一刻**——`/console-session` 开始拒绝老 sb_session，
   控制台用户先被弹一次；
2. **Edge 全球复制生效的那一刻**——站点访问的老会话失效，第二波。

必须写进运维说明，否则第一波会被当成 bug 去查。

### 4.4 M06 · `_get_cookies`（**不设条数上限**）

`_get_cookie` → `_get_cookies(request, name) -> list[str]`，按 header 顺序返回全部
同名值；`_check_auth` 逐个验签，**第一个通过的胜出**，全不通过则 302。

**两处都要改**（v4 补）：Edge 的 `_check_auth`，以及 auth 服务的
`/console-session`（`login_handler._session_cookie_candidates`）。后者曾漏掉，
而它**不在 Edge 的 gate 后面**——`auth` 子域注册为 `require_auth=False`，是 auth
自己验 cookie，所以 Edge 那侧的修复覆盖不到它。漏掉的后果是控制台**写操作**
（改权限 / 协作者 / 所有权 / 下线 / Key 管理）陷入持久登录循环，而 `/callback`
只重写 `Path=/` 那条、清不掉遮蔽项。

**不设条数上限**（v4 更正；v1 取 8、v3 取 64，两者都是错的方向）：**任何有限
上限都满足不了它自己声称的那条性质**（"设在任何可达值之外"）。可遮蔽条数的上界
是 `4n − 2`，`n` 是请求路径的段数；`_check_auth` 同样跑在**站点**请求上，而站点的
URL 空间由站点作者决定、平台不约束 ⇒ `n` 无界 ⇒ 可遮蔽条数无界。上限设成 `C`，
站点作者写出 `n ≥ (C + 2) / 4` 段的路径，M06 就在那些路径上原样复活（方向是
fail-closed 的 302，但用户被挡在登录循环里，且重新登录清不掉遮蔽项）。

真正在兜底的是 **Cookie 头体积**（浏览器/CloudFront 约 8KB——这个数字是本仓库的
自述、**没有对应到 AWS 配额文档**，但结论只需要"存在一个由传输层强制的上界"）。
放大是不可能的：总 HMAC 输入字节数由头体积封顶，与候选条数无关。实测
（in-process，非真机）8182B 头 / 248 候选 = 0.076ms，32734B 头 / 992 候选
= 0.185ms。也就是说"防放大"从来没有数字支撑，而它换来的是一个按路径深度复活的
DoS。要加限制的话，限的应该是**头体积**（那才是真正的界、且与路径深度无关），
不是候选条数。

**为什么 8 是错的**：原本的理由是「正常 1 条、病态 2 条，8 留足余量」——那是对
**意外重复**的估计，而 M06 的威胁模型是**有人故意投毒**。RFC 6265 §5.1.4 规定请求
路径的**每一个 `/` 边界前缀**都是合法 cookie 路径，§5.4.2 规定路径长的排在前面。
任一平台子域上的站点 JS 能给两个父域设 cookie，于是对
`console.…/api/sites/{id}/analytics` 这条真实路径，可投毒的路径有 `/api`、`/api/`、
`/api/sites`、`/api/sites/`、`/api/sites/{id}`、`/api/sites/{id}/`、
`/api/sites/{id}/analytics` 共 7 个 × 2 个域 = **14 条**，全部排在真正那条
`Path=/` 会话 cookie 之前。上限 8 会在第 8 条就停，真 token 在第 15 位永远不被验
⇒ **M06 描述的持久 302 原封不动地留着**。就连更浅的 `/api/sites/{id}` 也有 5 × 2 = 10。
即上限 8 只保护 ≤2 段的路径（`/api/me`、`/api/sites`、`/api/keys`），而站点详情 /
权限 / 协作者 / 所有权 / 下线 / 统计 / 访客这些端点都更深——**恰好是受害者想去
排查或自救时要用的那些**。攻击者只需让受害者打开自己任一站点的一个页面，
`require_auth: false` 的公开站点连登录都不需要。

**为什么 64 也是错的**（v4）：上面那条"要耗尽它需要约 16 段的 URL，不可行"是
**只对平台路由成立**的判断——平台最深的路由是 4 段，但站点路径不受平台约束，
17 段以上就打满 64。这不是"不存在的路径"，而是把残留面当成了不可达。
边界用例也随之换了形状：从常量派生的用例对**任何**有限上限都是绿的（那是它原本
的语义），所以它证明不了"没有上限"。现在改成两条——一条行为断言（第 301 条候选
仍须被尝试）、一条结构断言（模块里不得再出现条数上限常量或对候选列表的切片），
后者才是防"有人又加回一个看起来够用的值"的那一条。

`_strip_reserved_cookies`（`origin_request.py:543-548`）已按段过滤、会剥掉**全部**
同名保留 cookie，转发给站点那侧**不用改**（已核，写在此处免得评审重查）。

## 5. 数据流与错误处理

### 5.1 只有两条数据流改变形状

1. **权限写入流**（panel/MCP → `write_permissions` → 事务）：多一步
   `effective_policy(site)`，位置在**读到 site 行之后、构造事务之前**。
   抛错则事务根本不发起 ⇒ 零副作用。**这个位置是硬要求**，不能放进事务里。
2. **部署流**（`register_route`）：`_seed_permissions`（补缺失）→
   `effective_policy`（校验类型）→ `_route_item`。**顺序不能换**——
   种子先跑，"缺失"才不会成为常态错误。

M01 / M05 / M06 只改步骤内部的取值与判定，不改流形状。

### 5.2 错误处理

| 出口 | 映射 | 理由 |
|---|---|---|
| panel | **409** + 点名 site_id 与坏字段 + **直接给出修法** | 确实是"资源当前状态阻止本次操作"；panel 里 409 已用于 `PermissionConflict`，语义相邻，运维不用学新东西。**必须给专门分支**——否则会被 `handler.py` 的兜底吞成 500「服务内部错误」，这条修复的"响亮失败"就白做了 |
| MCP | 可读工具错误（同 `NotOwner` 形态） | 与既有口径一致 |
| `resync_route` | 异常文案直接透出 | admin 工具 |
| 审计 | 每次拒绝写 `ops_log.record(action="reject_policy_projection", result="rejected")`。**三个投影 writer 都要写**（`write_permissions` / `resync_route` / `register_route`），不是只包写路径——v1 只包了写路径，另两个的拒绝路径没有记录（Codex 指出） | 通道现成，`permissions.py:496/603` 已在用 |

其余三条的失败方向：
- `register_route` 抛错发生在**提交点之前** ⇒ 线上零影响（同 `upload_frontend`
  空产物拒绝的模式）；
- `site_policy` 的空 `tables` 抛错同样在部署早期；
- Edge 侧 `typ` 不匹配走既有 **302** 分支而非 403——与 idp/auth_via 检查口径一致：
  引导去登录，而不是让用户以为"没权限"；
- M06 候选全不通过仍是 302。

## 6. 测试策略

**每条修复先写一条会红的用例。** 本仓库已记过这条教训：安全闸门的测试若没反向
验证过，"加了守卫"与"守卫不生效"在 CI 上长得一模一样。

### 6.1 M02（deployer 包）

1. **核心红用例**：sites 行 `require_login = Decimal(0)`，跑一次**无关**修改
   （加协作者）→ 断言路由 `require_auth` 仍为 `True`。当前实现下是 `False`。
2. 部署路径同形：同一坏行跑 `register_route` → 断言拒绝且路由未被写。
3. **结构断言（两条）**：① 针对已知三个投影 writer 的 tripwire——体内不再出现 `bool(site.get(` /
   `site.get("allowed_users"` 这类直接取值。仓库已有此手法
   （`test_keys_api.py` 用 ast 锁定返回路径都经过 `_shape_key`）。
   **它是硬编码名单，不会自动发现新 writer**；
   ② **自动发现版**：按**写投影的行为特征**（item dict 里的
   `"require_auth"` 键，或 UpdateExpression 里的 `require_auth =` 赋值）
   识别 writer，命中者必须调 `effective_policy_audited`（**只接受带审计的
   那个**——接受纯函数会让"绕过审计包装"照样通过）。**判据不能是"出现过
   字面量"**：docstring 与只读取的函数（`_finish` 从 committed_route 反推
   effective_auth）都会被误伤，且误伤在三个真 writer 修完后**永远红**；
   ③ **边界哨兵**：`functions/` 下除 permissions / register_route /
   smoke_test 之外的模块不得出现**非 docstring** 的该字面量，否则第三个
   模块里的新 writer 仍会逃过 ②。docstring 排除（当前有三处纯说明），但
   不给文件开整文件白名单——那会让新 writer 藏进被豁免的文件；哨兵故意比
   ② 宽（读取也报，白名单需说明理由）。"守卫会咬"由**常驻 meta-test**
   验证：tmp 目录写探针文件、调用同一个扫描 helper——不往真实 tracked
   文件注入（`git checkout --` 还原会丢掉未提交修改，中断时探针残留）。
4. `collaborators` 缺失 → `[]`；其余三字段缺失 → 抛错。

### 6.2 M01（deployer 包）

5. **红用例用 `foo-k3d9x1` / `foo-k3d9x1-longname-abc123` 这一对**——不用
   `-ab12cd`，因为长名字那一对能证明修的是 ARN 本身而不是名字形态。
6. 表名格式单一定义：断言三处调用方都走 `site_table_name`。
7. `engine=="dynamodb"` 且 `tables` 为空 → 抛错。
8. 日志组资源集合"不多不少"恰好两条（group 与 `group:*`），仿
   `test_stack_edge_iam.py` 的既有口径。

### 6.3 M05（auth + router 包）

9. **红用例**：`verify_session_jwt(mint_upgrade_code(...), secret, expected_typ="session")` → `None`。
10. 链式续期被切断：升级码当 sb_session 打 `/console-session` → 拿不到新码。
11. Edge 侧缺 `typ` → 302。借既有占位符替换机制（`test_edge_auth.py` 读
    `origin_request.py` 现替换），Edge 改动**自动流入**，不需要手工同步测试副本。
12. `expected_typ` 漏传即 `TypeError`——必填参数本身也要有守卫。

### 6.4 M06（router 包 **+ auth 包**）

13. **红用例**：两条 `sb_session`，第一条垃圾 → 断言放行。
13b. **auth 侧同一条**（v4 补，原先整条漏了）：`/console-session` 递两枚
    `sb_session`、垃圾排在前 → 仍须换出 code。那个端点**不在 Edge 的 gate
    后面**（`auth` 子域 `require_auth=False`），Edge 侧的修复覆盖不到它。
14. **不设条数上限**（v4 更正）。原文写的是「第 9 条之后不再尝试」——那是把残留面
    写成了需求。现在是一条行为断言（按 Cookie 头体积生成候选、真 token 排最后
    仍须放行）＋一条 AST 结构断言（迭代对象不得被切片／islice 截断）。
15. 回归：`_strip_reserved_cookies` 仍剥掉全部同名（防改 `_get_cookies` 时顺手动坏）。

### 6.5 三条影响任务排序的跨包耦合

- **`session.py` 改签名 ⇒ panel 侧会红。** panel 测试期是从 `auth/` 直接 import
  `session.py`（部署时才由 `deploy_panel.py` 复制），所以改 auth 的**同一个任务**里
  必须一起改 `console_session.py:131` 的调用，**不能拆成两个任务**。
- **`permissions.py` 被复制进三个产物** ⇒ 改完 panel / key-proxy / MCP **都要重部**，
  S1 验收必须包含 `verify_deployed_components.py`。
- Edge 改动跑 router 那套：
  `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`

## 7. 部署与回滚

### 7.1 顺序

```
1. deployer 栈（M01 + M02 的 permissions.py / register_route.py / common.py）
2. panel / key-proxy / MCP 重部（permissions.py 被复制进这三个产物）
3. 存量角色 backfill（§4.2.1）+ 断言不合格角色数 == 0            ← v2 新增，必须在 ① 之后
4. auth（M05 上半：签发 typ + 自身 verifier 要求 typ）   ← 第一波重登
5. router（M05 下半 + M06）
6. 等 CloudFront `Status == Deployed`                    ← 第二波重登在此期间发生
7. 跑 §7.2 的真机验收
```

**第 6 步的位置是 v2 修正的**：v1 把"等 Edge 全球复制"放在 router 部署**之前**
（当时的第 4 步），那时压根还没有新的 Edge 版本要传播，纯属无意义等待
（Codex 指出）。真正触发传播的是 router 部署本身，所以等待必须在它**之后**，
而且判据用 CloudFront 分发的 `Status`（传播中是 `InProgress`，完成是 `Deployed`），
不用盲等 10–20 分钟。

**第 3 步必须在第 1 步之后**：backfill 调的是新版 `ensure_site_role`/`site_policy`。

### 7.2 真机验收

- **不合格角色数 == 0** —— **硬闸门**（判据见 §4.2.1 的四层：完整文档等值 +
  角色上唯一 policy + 反向存在性 + 全站点全动作功能模拟）。非 0 就不算 S1
  交付完成：M01 的修复对那些站点等于没生效，而它们仍是对未来嵌套站点生效的陷阱
- `verify_deployed_components.py` —— 唯一能发现"产物陈旧"的闸门（第 2 步之后必跑）
- `verify_permission_matrix.py` —— M02 改完后唯一覆盖权限矩阵端到端的闸门
- `verify_console_e2e.py` —— 跑之前要**重新登录一次**（两波重登会让 token 失效）
- 部署前**重跑一次 §8.1 的只读体检**（行形态可能已变）

### 7.3 回滚

- 第 1–2 步：代码回滚 + 重部，无数据迁移，可逆。
- 第 4–6 步：**Edge 回滚要 10–20 分钟全球复制**。

#### backfill（第 3 步）不是纯代码部署

v1 的本节只写了"前面几步是代码回滚、无数据迁移"，那在 backfill 纳入之后不成立
了（Codex 指出）——第 3 步会**批量重写 7 个角色的 IAM inline policy**。

- **覆盖前留档，且留档先于第一笔写入**：`--apply` 把**全部** target 的旧
  policy 写到 `site-builder/scripts/backfill-old-policies.json`
  （**gitignored**，含账号 ARN），**必须在任何 put_role_policy 之前原子落盘**
  （临时文件 + `os.replace`）。攒在内存、循环结束才写文件的实现是错的：
  第 2 个角色写入抛异常（IAM 限流最常见）时第 1 个已被改而备份不存在，
  本节承诺的回滚材料落空（Codex 复现过）。重跑时**合并、绝不覆盖已有
  快照**——已收敛的角色不再是 target，无条件覆盖会丢掉它们的原始通配
  policy，而回滚要的恰是第一份。配调用顺序守卫用例：备份写失败 ⇒
  `ensure_site_role` 零调用。
- **备份格式带账号元数据**：`{schema_version, account_id, region, roles}`，
  合并前逐项核对、不一致就拒绝执行并提示把旧文件移走——没有元数据时，
  切到另一个账号后"绝不覆盖"会把 A 账号同名 role 的旧快照保留成 B 账号的
  回滚材料，回滚时把 A 的资源 ARN 写进 B（Codex 指出）。
- **读快照只认 NoSuchEntity 为"不存在"**：其他读错误（限流/断网/
  AccessDenied）必须原样抛出且零 IAM 写入。裸吞异常返回 None 会把一次
  限流**永久**落盘成"原本没有 policy"（合并策略不覆盖已有条目），
  真要回滚时原 policy 已不可恢复（Codex 复现过）。
- **回滚方式**：拿那份备份逐个 `put_role_policy` 还原；值为 `null` 的条目
  = 该角色当时没有 site-scope（角色本身必然存在——缺失角色分流需人工、
  不进自动重写，所以 null 只有这一个含义），回滚动作是 `delete_role_policy`
  删掉新写的那条。**回滚永远不需要删除整个角色。**「角色存在」是技术保证
  而非运维假设：备份对 null 补一次 GetRole 复核——角色在枚举后被带外删除
  （TOCTOU 窗口）时，`--apply` 在第一笔 IAM 写入前中止（Codex 签核附带项；
  运维上 backfill 期间也不要人工修改/删除 `site-rt-*` 角色）。
  因为 backfill 排在 auth/router **之前**，回滚它不受 CloudFront 传播窗口
  影响，是即时的。
- **但回滚 backfill 会重新引入 M01**。所以只在"backfill 本身写坏了"时才回滚
  ——判据是脚本自己的功能验收（用 IAM 策略模拟器断言站点**能**访问自己的表、
  **不能**访问嵌套邻居的表）报了问题。若只是某一个站点有问题，
  单独还原那一个角色，不要整批回滚。
- **不要在没查明原因时回滚整批**：更可能的原因是某个站点的 `data_tables`
  与实际表不一致，那属于数据问题，还原 policy 只会把通配放回去。

**回滚必须严格逆序：先 router，再 auth。**
- 回滚 router（Edge 不再要求 typ）后，auth 签发的带 typ token 仍被老 Edge 接受
  ——老 Edge 只查签名 / exp / email，忽略未知 claim ⇒ 兼容。这是"auth 先"的另一个好处。
- **反过来会锁死**：若先回滚 auth（重新签发不带 typ 的 token）而 Edge 仍要求 typ，
  则新签发的会话一律被 302，用户陷入登录循环。

## 8. 已接受的残留与风险

### 8.1 上线前体检结果（只读实测，锚定在提交 `33f88df`）

> **不用日期做锚，用提交哈希。** 两个审查环境对"今天是几号"不一致
> （本环境报 2026-08-22，Codex 环境报 2026-08-21，且都声称是 +08:00），
> 说明至少一侧存在 **host clock skew**。我无法从环境内部判定谁对，
> 所以证据一律锚在可验证的提交上而不是日期上：
> 下表是在 `33f88df` 这次提交之前跑的，重跑方式见 §9 的 T1。
> **部署前必须重跑**，届时以那次的输出为准——这也让日期争议无关紧要。

对 sites 表全量 Scan，7 个 ACTIVE 行的字段形态：

| 字段 | 形态 |
|---|---|
| `require_login` | `BOOL` × 7 |
| `allowed_users` | `S` × 7（值均为 `"org"`） |
| `collaborators` | `L` × 7 |
| `owner` | `S` × 7，均非空 |

**严格解析会拒绝的 ACTIVE 行：0** ⇒ S1 上线不会卡住任何现有站点。
（另有 70 个 `DELETED` 行不参与投影。）

**衍生风险**：7 个站点的 `allowed_users` 全是 `"org"`，即
`allowed_users` 的 `list[str]` 分支**在生产中从未被使用**，只有测试覆盖。
实现时要保证该分支的用例够厚。

### 8.2 残留

| 残留 | 说明 | 出路 |
|---|---|---|
| ~~休眠站点保留通配策略~~ | **v2 已消除**：backfill 纳入 S1，且以不合格角色数 == 0为硬闸门。v1 把这条当"可观测性残留"是**错的**——通配向前看，等于给未来的嵌套站点留门（§0.5） | 已闭环 |
| M06 只关 DoS、**不关身份混淆** | 攻击者若持有另一个**合法** session token，注入到 `path=/api` 后仍会先被取到并验签通过，受害者在 `/api/*` 上被当成攻击者。**`/console-session` 同类，但触发链更长**（v4 收窄；原文写成“受害者会拿到攻击者身份的面板会话”是**过强的**，Codex 复审指出）：只遮蔽 `/console-session` 时，auth 确实会签出攻击者邮箱的升级码，但 panel 的 `/api/session-callback` 会拿它与 **Edge 注入的当前邮箱**核对（`console_session.consume_code(..., expected_email=email)`，`panel/handler.py:168`），不一致即 401 ⇒ 结果是登录循环，不是身份切换。要真拿到攻击者的面板会话，攻击者那枚 token 必须**同时**在 callback 那条路径上也胜出。残留仍然成立（v4 只保证“真会话不会被垃圾值挤掉”，即只关 DoS 那一半），但链条要写全 | 根治是 host-only 会话，独立成包 |
| ~~候选条数上限在深路径上打满 → M06 复活~~ | v3 的上限 64 在 `n ≥ 17` 段的站点路径上被打满，M06 在那些路径上原样复活（fail-closed 的持久 302）。**v1/v3 都把它当成不可达而没记进本表**，是漏记 | **v4 已闭环**：删掉条数上限（§4.4），界改由 Cookie 头体积给 |
| M01 的正则纵深防御未加 | 已论证不充分，故不作为修复 | 可选 |
| 坏数据行会卡住站点 | 三个投影 writer + 迁移入口统一拒绝的既定代价 | 靠错误文案给出修法（§5.2）缓解 |

### 8.3 与 M09 的关系

M09（同账号 `lambda:InvokeFunction` 可伪造 `x-user-email`）**不在 S1 内**，
且 S1 的四条修复**都不依赖账号边界** ⇒ 迁不迁账号，S1 都照此实现。
但需知：M09 未修时，M02 保护的权限投影仍可被直接 invoke 绕过——
S1 收紧的是**数据面的正确性**，不是**身份来源的可信性**。

## 9. 实施模块划分（供 writing-plans 参考）

| 任务 | 内容 | 依赖 |
|---|---|---|
| T1 | 把 §8.1 的**行形态**只读体检固化为可重跑脚本（判断严格解析会不会拒绝现有行）。**注意与 S4 的"通配策略残留"审计不是同一件事**——那个查的是 IAM policy，这个查的是 sites 行 | — |
| T2 | `common.site_table_name` + 三处调用方切换（含红用例 6） | — |
| T3 | `common.site_policy` 精确 ARN + 日志组收窄 + `ensure_site_role` 透传 + GSI 触发器（红用例 5/7/8） | T2 |
| T3b | `common.tier_engine()` + `undeploy.py:180` 切过去 + 与 `contract.TIER_ENGINE` 一致性守卫 | — |
| T3c | 存量角色 backfill 脚本 + 「不合格角色数 == 0」硬闸门 + STS 账号核对 + 功能验收（§4.2.1） | T3、T3b |
| T4 | `permissions.effective_policy` + `PolicyDataInvalid`（红用例 1/4） | — |
| T5 | 三个投影 writer 切到 `effective_policy_audited` + 三条 AST 断言；迁移入口改委托 `normalize_allowed_users`（红用例 2/3） | T4 |
| T6 | panel 409 分支 + MCP 错误映射 + ops_log 审计 | T5 |
| T7 | `session.py` 加 `typ` + `expected_typ` **并同步改 `console_session.py:131`**（同一任务，红用例 9/10/12） | — |
| T8 | Edge `_verify_session_jwt` 要求 typ（红用例 11） | T7 |
| T9 | Edge `_get_cookies`**（不设上限）** + auth `/console-session` 逐个验（红用例 13/13b/14/15） | — |
| T10 | 全量单测 + 按 §7.1 顺序部署 + §7.2 真机验收 | 全部 |
