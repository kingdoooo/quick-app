# Quick Site Builder 二期 M5：访问记录 / 统计 细化 spec

- **日期**：2026-08-14
- **状态**：设计已确认（brainstorming 完成），待实施计划
- **母 spec**：`2026-07-30-quick-site-builder-phase2-design.md`（下称 phase2
  spec）。本文件细化 M5，**并推翻其 §6 的数据源选型**——见 §0，冲突时以本文件
  为准。
- **需求来源**：`docs/phase2-requirements.md` 的「C. 访问记录 / 统计」。
- **基线**：M4（API Key + key-proxy）已全量交付并真机验收，31 个提交未 push，
  分支 master。M1-M4 的五层 + 控制台均在线。
- **检查清单**：`docs/design/M4-FINDINGS.md`（§3.1-§3.12，gitignored）与
  `M3-FINDINGS.md`。本文件多处直接引用其条目编号。

---

## 0. 对 phase2 spec §6 的推翻（显式记录）

phase2 spec §6 把 M5 定为**日志侧聚合**：Edge `print` 一行 JSON（零延迟）→
EventBridge 每小时触发聚合 Lambda → 逐区跑 Logs Insights → 水位线幂等重查 →
写 `site-access-stats` / `site-access-audit`。§6.4 接受小时级延迟。

**本 spec 改为 Edge 写穿 DynamoDB（原需求文档的「方案 a」）。**

### 0.1 推翻的依据（2026-08-14 实测，非推演）

近 14 天，平台分发（`*.{base_domain}`）：

| 观测量 | 值 |
|---|---|
| CloudFront 请求总量 | 1742（**日均 124**） |
| origin-request 函数耗时 | **p50 = 2.0ms** / p90 = 789ms / p99 = 867ms |
| origin-response 函数耗时 | p50 = 1.2ms / p90 = 11ms |
| Edge 执行区分布（Invocations） | **ap-southeast-1 1481（91.6%）** / ap-northeast-1 72（4.5%）/ us-east-1 63（3.9%） |
| 分发标准访问日志 | 未开启 |

**跨区写入延迟（2026-08-14 探针实测，非估算）**：临时 Lambda 各区 3 轮冷启动
× 6 次 `PutItem` → us-east-1 表，跑完删除全部临时资源。

| 路径 | 冷连接首次 | 暖连接 |
|---|---|---|
| **ap-southeast-1 → us-east-1** | 716 / 722 / 719 → **中位 719ms** | 226–246 → **中位 229ms** |
| us-east-1 → us-east-1（基线） | 48 / 58 / 60 → 中位 58ms | 4–14 → **中位 6ms** |

- 跨区净成本 = 229 − 6 = **223ms**（≈ 新加坡↔弗吉尼亚 RTT）。
- 冷连接的 719ms ≈ 229（请求 1 RTT）+ 约 490ms（DNS + TCP + TLS ≈ 2 RTT）。
- **交叉印证**：719ms 与现有 Edge 在 ap-southeast-1 的 p90 = 789ms 相互解释
  （`Duration` 不含 `InitDuration`，故 p90 基本就是一次冷连接 GetItem）。
  **今天的 p90 请求已经在付这 719ms**；M5 在同一条暖连接上再加 229ms。
- 保真度声明：探针是普通 Lambda，不是 Lambda@Edge 副本。**被测的是网络路径**
  （同区容器 → us-east-1 表，两者都无 VPC、都用环境变量凭证），不能由此推断
  Edge 的总耗时。

**方案 a 的代价因此定量为**：p50 页面请求 2ms → 231ms；p90 请求 789ms →
约 1018ms；**每页面只付一次**（资源请求走 2ms 快路径，见 §2.2）。金额可忽略
（约 3700 写/月）。

三方案的对照：

- **方案 b（CloudFront 标准日志）出局，非取舍问题而是能力问题**：标准日志字段是
  固定集合，身份只可能来自 `cs(Cookie)`，而该字段要 `IncludeCookies=true` 才有
  值——它写的是**整个 Cookie 头**，内含 `sb_session`（HS256，未过期即可重放）。
  本仓库已为「认证材料不进日志」写过脱敏函数，且有真机泄漏证据
  （`origin_request._redact_querystring` docstring 记的 2026-08-03 明文 OAuth
  code）。选 b 等于放弃需求 §C 的 UV 与访问审计，或把会话凭证写进 S3。
- **方案 a 的代价只有延迟，且已实测**（上表）——没有静默失效面。
- **方案 c（= phase2 spec §6）的成本是常驻机械复杂度**：水位线、迟到日志、
  跨区 region 发现、Logs Insights 查询成本；且区域清单漏一个就**静默少算**，
  需要另配 fail-loud 守卫。实测目前 3 个区域有 Edge 日志组，但 Lambda@Edge 可在
  更多区域执行——「观测到 3 个」不等于「只会有 3 个」。

**裁决依据（两条比延迟更重要）**：

1. **失效形状与本仓库的历史伤口对齐。** M3/M4-FINDINGS 记录的痛点几乎全是
   **静默失效**（§3.1 DELETE+body、§3.2 过期断言、§3.5 负测空转、§3.6 永久
   SKIP、§3.9 手抄清单漏项、§3.10 cwd 漂移、`enabled` 字符串）。c 的每一种失效
   模式**都是这个形状**：数字偏小、无报错、两侧单测各自都绿。a 的失效是丢一行
   加一条 `[WARN]`，或是一个人能感觉到的延迟——都可观测。
2. **可复算窗口 90 天 vs 30 天，且性质不同。** a 的真源是耐久明细行：rollup 坏
   89 天，重跑即全部恢复。c 的真源是会过期的日志（phase2 spec §6.3 定 30 天）：
   聚合器坏 31 天，数据**永久丢失**，且期间无人会知道。

**c 唯一但真实的优势**：请求路径零风险。a 的最坏情况不对称——若异常逃出 try 块
或 client 在 import 期抛错，坏的是**全平台路由**，而 Edge 回滚要 10-20 分钟全球
复制。这条由 §2.3 的具体措施压制（且必须有注入验证），但不等于消失，是选 a 要
接受的那一条。

### 0.2 风险已被设计吸收：摄取层可替换

**摄取层是单一写入点，下游只读表。** 面板 API、MCP 工具、聚合 rollup、schema
全部不知道事件行是谁写的。若日后流量或延迟成为问题，把「Edge 写穿」换成
phase2 spec §6 的日志侧聚合，**只需替换写入端**，不动 schema / 面板 / MCP。
这条是本设计对推翻母 spec 所付的对价，必须在实施中保持（见 §5.2 守卫）。

**而且延迟这条有更便宜的先手**（见 §0.4），不必先动摄取层。

### 0.3 与 phase2 spec §6 的其余偏移

| phase2 spec §6 | 本 spec | 理由 |
|---|---|---|
| 记「页面与 `/api/*`」 | **只记页面级** | 每条写穿 = 实测 229ms；SPA 的 API 调用会把单页成本乘以调用次数。PV 语义也更干净（= 真实页面浏览） |
| `owner=platform` 排除平台路由 | **`app-` 前缀判定** | `owner` 是权限投影字段，能写权限的角色可控——phase2 spec §3 的权限模型自己否掉了这种推导（详见 §2.1） |
| `site-access-stats`（含 week#/month# 物化行） | 只物化 day 行，周/月**读时汇总** | 少一类物化行 = 少一处可漂移的真源；周/月 UV 无论如何都受明细窗口限制（母 spec 的 audit 表同样 90 天），物化不能解决 |
| `site-access-audit`（`email#date` 粒度 upsert） | 逐请求明细行 | 写穿的自然单位是 `PutItem`；`email#date` upsert 要给 Edge `UpdateItem`，而本设计**故意只给 PutItem**（§1.1）。代价：PII 密度更高（见 §1.3） |

**未偏移**：phase2 spec §6.3 的「平台 Lambda 日志组统一设 30 天保留」仍在 M5
范围内。但**该条对现状的描述已过时**，2026-08-14 实测的真实范围如下：

| 日志组 | 现状 | 本轮 |
|---|---|---|
| 2 个 Edge 副本函数（× 3 个执行区） | **未设 = 永不过期** | 补 30 天 |
| `site-panel` · `site-key-proxy` · `site-deployer-reconcile-job` · `site-deployer-sweep-jobs` | **未设** | 补 30 天 |
| `site-auth-pre-token-spike-…`（spike 遗留） | 未设 | 补 30 天或删除（spike 残留，实施时确认） |
| deployer 的 10 个 Lambda | **90 天**（不是母 spec 说的「永久保留」） | 收敛到 30 天 |
| `site-auth-pre-token` | 90 天 | 收敛到 30 天 |
| `site-auth-service` · 6 个站点函数 | 已 30 天 | 不动 |

⚠️ **收敛动作会修剪存量日志**：DEPLOY.md 已记过这个坑（「首次在存量环境运行会
修剪日志……超过 30 天的日志会被标记删除」）。把 90 天收敛到 30 天前要先确认
30-90 天窗口内的日志无排查/审计价值——**这是有损操作，不是附带效果**。

### 0.4 消掉跨区，而不是消掉同步（**本轮范围内**）

**先看代价的拆分**（用 §0.1 的两组实测数相减）：

```
229ms  =  223ms 跨太平洋的网络  +  6ms DynamoDB 本身
```

**97% 的代价是那条腿，不是「同步写」这个动作。** 同步写本身只要 6ms，低于噪声。
所以对症的解法是给明细表加 **DynamoDB Global Table 副本**，让 Edge 写它执行区
的本地副本：

| | 单表 us-east-1 | 加 ap-southeast-1 + ap-northeast-1 副本 |
|---|---|---|
| 暖连接写 | 229ms | **6ms** |
| 冷连接首次写 | 719ms | **58ms** |
| 覆盖流量 | — | **96.1%**（§0.1 实测执行区分布） |
| 页面请求 Edge p50 | 2ms → 231ms | 2ms → **约 8ms** |
| 成本 | 约 3700 写/月 | ×3 区 ×1.5 rWCU，仍是每月几分钱 |

**这与方案 c 的性质完全不同**：异步（c）是用可靠性换延迟；加副本是**直接把延迟
拿掉，不换任何东西**——没有水位线、没有区域发现、没有静默少算，明细行仍是耐久
的可复算真源。

#### 落地顺序（三步，任一步失败都不丢数据）

有一个前置未知：**`AWS_REGION` 运行时变量在 Lambda@Edge 里是否可用，本轮开始时
未验证**。CLAUDE.md 那条「Lambda@Edge 不支持环境变量」指的是**用户自定义**变量，
运行时注入的是另一回事——但**不拿推测当结论**（§5.4）。因此：

1. **第一次部署 Edge（版本 8）时带一行探测**，把 `os.environ.get("AWS_REGION")`
   与 `context.invoked_function_arn` 打进日志。M5 本来就要部 Edge，这一步不额外
   花时间，也不额外部署一次。
2. **埋点代码把「写哪个 endpoint」做成单一解析值 + 硬回落 us-east-1。**
   区域检测失败 = 跨区写 = **正确但慢**，永不丢数据。于是第 1 步的结果无论如何
   都不会变成故障，最坏情况只是「229ms 保持现状」。
   - 若 `AWS_REGION` 不可用，第二候选是从 `context.invoked_function_arn` 解析
     区域（**同样未验证**，按第 1 步的日志判定）；两者都拿不到就回落。
   - 解析出的区域**不在副本清单里**时也回落 us-east-1（不能对着没有副本的区域
     发请求）。副本清单是代码里的常量，与 CDK 的副本配置由测试锁死一致。
3. 读回日志确认后再开副本（**对存量表加副本是在线操作**），并按 §5.1 复验。

#### 由此产生的三个连带要求

- **IAM 资源集合变成三个 ARN**（每个副本区一个），不是一个。副本表的 ARN 是
  `arn:aws:dynamodb:{replica_region}:{account}:table/site-access-events`，是
  **独立资源**——漏给一个 = 那个区的埋点全部 AccessDenied 后被 §2.3 规矩 3
  吞掉 = **该区静默零数据**。`test_stack_edge_iam.py` 按副本清单**推导**断言，
  不手抄（§3.9 的教训）。
- **复制是异步的**（典型 < 1s，无 SLA）。面板与 rollup 都读 us-east-1 副本，
  所以「今天的实时数」可能落后约 1s——对统计无影响，但**闸门必须轮询等待**，
  不能发完请求立刻断言，否则 `verify_analytics_e2e.py` 会是个 flaky 闸门。
- **`site-access-daily` 不做全球表**：只有 rollup 写它，而 rollup 在 us-east-1
  跑。多一个副本只增加成本与删表复杂度。

#### 仍留给三期

三期若做 CloudFront 精细缓存，本项与 §4.3 的联动要一并重评。

---

## 1. 数据模型

### 1.1 `site-access-events`（明细，TTL 90 天）

| | |
|---|---|
| PK | `site_date` = `{site_id}#{YYYY-MM-DD}`（UTC） |
| SK | `ts_id` = `{ISO8601}#{6 位随机 hex}` |
| 属性 | `site_id` · `email` · `path` · `decision` · `expires_at` |
| 计费 | PAY_PER_REQUEST |
| 策略 | `RemovalPolicy.DESTROY`（90 天滚动数据，删栈丢掉可接受） |
| 副本 | **Global Table：us-east-1（主）+ ap-southeast-1 + ap-northeast-1**（§0.4） |
| 唯一 writer | **Edge 角色，且只有 `dynamodb:PutItem`**（三个副本 ARN 各一条） |

- `decision` ∈ `{"allow", "denied_403", "redirect_login"}`。
- `email`：`allow` 与 `denied_403` 时是**已验签**的邮箱；`redirect_login`
  （未登录）时为空串 `""`（无身份可言）。公开站点（`require_auth=False`）
  同样为空串——只有 PV 无 UV，与需求 §C 的说明一致。
- SK 的随机后缀照 `ops_log.ts_actor` 先例：同毫秒两条请求不会互相覆盖
  （`ops_log` 的 docstring 记过「固定时钟后表里只剩一行（实测）」）。
- **不给 `UpdateItem` / `DeleteItem`**：Edge 是公网请求路径上的组件，只该有
  「追加一行」的能力，不该能改写或删除访问历史。
- `RemovalPolicy.DESTROY` ⇒ 本表**不进** `deletion_protection` 不变量
  （`test_every_retained_table_has_deletion_protection` 从模板的
  `DeletionPolicy: Retain` 推导，DESTROY 表天然在范围外）。

**为什么按 `site_id#date` 分区**：一次 Query 该分区即同时得到当天 PV（行数）
与 UV（distinct `email`），不需要计数器行——于是**热路径只有一次写**。
（这条在加了副本之后依然成立：省一次往返总是对的，且未命中副本的区域仍要回落
跨区，那时一次与两次的差别就是 229ms 与 458ms。）

**Global Table 的两个实现注意点**：

- CDK 侧用 `aws_dynamodb.TableV2`（原生多区）比给 `Table` 配
  `replication_regions`（自定义资源）干净。本表是仓库里唯一的多区表，引入第二种
  构造类型是有意的局部选择，其余 `site-*` 表不动。
- TTL 删除会复制到各副本；SK 全局唯一（随机后缀），不存在需要 last-write-wins
  仲裁的写冲突。
- 删表要先摘副本——本表 `DESTROY`，所以 `cdk destroy` 路径要能处理（`TableV2`
  负责），实施时实测一次而不是假定。

### 1.2 `site-access-daily`（日聚合，TTL 400 天）

| | |
|---|---|
| PK | `site_id` |
| SK | `date`（`YYYY-MM-DD`，UTC） |
| 属性 | `pv` · `uv` · `pv_denied` · `expires_at` |
| 策略 | `RemovalPolicy.RETAIN` + `deletion_protection=True` |
| 唯一 writer | rollup Lambda（`PutItem`）。**Edge 对本表零权限** |

- `pv` / `uv` 只统计 `decision == "allow"`；`pv_denied` 是 `denied_403` 与
  `redirect_login` 之和（被拒不进 PV 曲线，但可查）。
- RETAIN + deletion protection 的理由与 `ops_log` / `site-admins` /
  `site-api-keys` 同：**400 天趋势一旦丢不可重建**（明细 90 天后就没了）。
  按仓库既有不变量，设了 RETAIN 就必须一并挡住直接 `DeleteTable`，本表会被
  `test_every_retained_table_has_deletion_protection` 自动纳入。
- TTL 400 天对齐 `ops_log.TTL_DAYS = 400`（= 13 个月，够看同月同比）。

### 1.3 保留期与 PII（决定记录）

| 数据 | TTL | 先例 |
|---|---|---|
| 明细（含 email） | **90 天** | 介于日志组 30 天与 ops_log 400 天之间；一个季度的审计窗口 |
| 日聚合（仅计数） | **400 天** | `ops_log.TTL_DAYS` |

**已接受的取舍**：明细是逐请求行，比 phase2 spec §6 的 `email#date` 日粒度
汇总 PII 密度更高——它保存 90 天内「谁在什么时候访问了哪个页面」。这正是需求
§C 要的访问审计能力（原文：「甚至访问审计（谁在什么时候访问过）」），代价是
逐人浏览记录落盘 90 天。日聚合不含任何 email。

### 1.4 跨月 UV 的诚实边界

- **日 UV 永远精确**，活 400 天（聚合行里就存着）。
- **PV 可相加，UV 不能相加去重**。周/月 UV 只在该区间**完整落在 90 天明细
  窗口内**时精确（从明细 Query 算 distinct）；落到窗口外的桶返回
  `uv: null` + `uv_exact: false`，前端**显式标注**「超出明细留存窗口」。
- 不显示一个站不住的数字——与控制台现有占位页的立场一致（现文案：「避免把空
  数据当成没人访问」）。这条语义写进 API 契约（§3.1），不让前端猜。

---

## 2. 摄取：origin-request 里一次 PutItem

### 2.1 记不记：用分区键前缀，不用可写字段

```
record iff subdomain.startswith("app-")   →   site_id = subdomain[4:]
```

- **实证（2026-08-14）**：路由表 12 条中 9 个用户站点全为 `app-{site_id}`，
  三个平台组件为 `auth` / `console` / `mcp`；`site_id` 与 sites 表逐字一致。
  `deployer/functions/common.py:240` 的 `return f"app-{site_id}"` 是该前缀的
  **唯一代码来源**。
- **不用 `_is_platform_route()`**：`mcp` 子域**故意**不在 `PLATFORM_SUBDOMAINS`
  里（CLAUDE.md 明写理由），用它会把 key-proxy 的每次调用记成一个「站点」，
  并给每次调用加 229ms。
- **不用 `owner != "platform"`**（phase2 spec §6.1 的写法）：`owner` 是权限
  投影字段，`permissions.write_permissions` 的 route_update 会写它，凡能写权限
  投影的角色都能改。`origin_request.PLATFORM_SUBDOMAINS` 上方那段长注释正是
  为此否掉了 owner 推导。`subdomain` 是路由表**分区键**、由真实 Host 解析得出，
  不可伪造。

### 2.2 页面级判定：复用已有的那一个条件

```python
"." not in uri.rsplit("/", 1)[-1]        # → 页面
```

即 `_route_request` 里决定是否改写成 `/index.html` 的同一个条件。**不新写一份
扩展名清单**（phase2 spec §6.1 的「按扩展名过滤」会成为第二处定义，与静态改写
逻辑漂移时症状是「统计和路由对同一个 URI 判断不一致」）。

`route_mode == "api-only"` 的用户站点没有「页面 vs 资源」之分，全记。
**当前有零个这样的站点**（9 个用户站点全为 split），但规则必须先定义。

### 2.3 六条 Lambda@Edge 约束 → 实现规矩

1. **不往返回的 `request` 对象加自定义键**——CloudFront 会校验其形状。已验签
   邮箱通过一个**独立的 out-param dict** 从 `_check_auth` 带出，
   **`_check_auth` 的返回类型一个字不改**（M4-FINDINGS §3.3：因审查从单值改
   多值的函数，调用方最容易按旧签名继续用）。现有代码给**route** dict 加
   `_PLATFORM_KEY` 是同一种「不碰 request」的写法。
2. **没有后台异步**（返回即冻结容器）——所以是同步写穿，实测 229ms 由此而来。
   「起线程不 join、靠下次调用收尾」**已否掉**：容器冻结期间线程不前进，日均
   124 请求下容器空闲死亡率高 = 静默丢数据，且冻结线程能否续跑无文档保证。
3. **埋点失败绝不能影响路由/鉴权**：整段 `try/except` 吞掉 + 打一行
   `[WARN]`。这里 fail-open 是对的——**统计不是安全控制**（与本仓库其它
   fail-closed 判定的区别要写在注释里，避免以后被「统一改成 fail-closed」）。
   异常兜底必须覆盖 client 取用本身，不能只包住 `put_item` 调用。
4. **超时预算按「本区副本」算，不是按跨区算——但下限由跨区回落决定。**
   这条经过两次修正，两次的理由都必须留在代码注释里，否则会被"优化"回去：
   - **初版**：给埋点新建一个 client 并配 `connect_timeout=0.3 /
     read_timeout=0.5`。**探针实测否掉**：跨区冷连接首次 PutItem 要 **719ms**，
     而预算合计 0.8s 且分属两个阶段 ⇒ 每个冷容器的首次埋点必然超时，又被规矩 3
     吞掉 ⇒ **静默丢行**，正是 §0.1 用来否掉方案 c 的那种失效形状。
   - **第二版**：改成复用模块级 `dynamodb` client（`_lookup_route` 已在同一次
     调用里把连接暖好）。**加了副本（§0.4）之后这条也不成立**——模块级 client
     钉在 `DYNAMODB_REGION`（us-east-1），而埋点要写的是**本区副本**，
     两者不是同一个连接池，蹭不到。
   - **定版**：`ACCESS_REPLICA_REGIONS` 里的每个区一个**惰性创建并缓存**的
     client（`_ACCESS_CLIENTS` 字典），配 `connect_timeout=1.0 /
     read_timeout=2.0 / retries={"max_attempts": 0}`。
     - 正常路径是**同区**：实测冷 **58ms** / 暖 **6ms**，离 1.0/2.0 的预算差两个
       数量级，不存在初版那个问题。
     - 预算之所以给到 1.0/2.0 而不是更紧：**回落路径**（§2.3 规矩 5）是跨区，
       冷连接要 719ms。预算必须容得下它，否则回落就从"正确但慢"退化成"丢行"。
     - 代价（已接受）：极端情况下单个请求最多多等 3s，且只发生在回落路径的
       冷容器首次写。**不给重试**——埋点重试的价值低于它带来的延迟方差。
   - **不要把预算收紧回去**：它的下限由跨区回落的 719ms 定，而不是由正常路径的
     58ms 定。收紧到"够本区用"就等于让回落路径静默丢行。
5. **写哪个 endpoint 是一个单一解析值，且硬回落 us-east-1**（§0.4 第 2 步）。
   区域解析顺序：`AWS_REGION` → `context.invoked_function_arn` → 回落。
   解析出的区域**不在副本清单常量里**同样回落。回落 = 跨区写 = **正确但慢**，
   **永不丢数据**——这条是「加副本」这个优化不会变成故障的唯一保证，注入验证
   必须覆盖「解析不出区域」与「解析出一个没有副本的区域」两种情形。
   副本清单常量与 CDK 的副本配置由测试锁死一致（两处漂移 = 某区静默零数据）。
6. **调用点在 `lambda_handler` 里、所有鉴权判定之后、`return` 之前**，
   三种 `decision` 走同一条记录路径（`allow` / `denied_403` /
   `redirect_login`）。**被拒记录只可能在 origin-request 拿到**：302/403 由
   origin-request 直接生成响应，此时 origin-response 根本不触发。

### 2.4 IAM 与跨栈引用

- `site-access-events` / `site-access-daily` 建在 **deployer 栈**（与全部
  `site-*` 表一致，继承 TTL / RETAIN / deletion-protection 的既有形态与不变量
  测试）。
- **router 栈**给 edge_role 加 `dynamodb:PutItem`，资源为明细表在**每个副本区**
  的 ARN（§0.4：三个），表名与副本清单走 `router/config.ini` 的 `[SiteBuilder]`
  新键（照 `frontend_bucket` / `base_domain` 先例：router 栈按名字串引用
  site-builder 侧资源）。
- `router/infrastructure/lambda/test_stack_edge_iam.py` 加断言锁死
  **恰好这一个 action、恰好这组资源**，且资源集合**从副本清单推导**、不手抄
  （该文件已用同样形态锁着 S3 的两个前缀；手抄的清单每加一个区就漏一个，§3.9）。
  同一份副本清单同时被 Edge 代码的回落判定用（§2.3 规矩 5），**三处必须由测试
  锁成一致**：CDK 副本配置 / IAM 资源集合 / Edge 的清单常量。
- **部署顺序有依赖**：表必须先于 Edge 存在。反了的话写失败被 §2.3 规矩 3 吞掉，
  症状是**「部署全绿、零数据」**。这条要进 DEPLOY.md，**并由闸门验证**
  （§5.1）——只写文档不够。

---

## 3. 聚合与读取

### 3.1 面板 API（两个 GET）

路径形状对齐现有 `/api/sites/{site_id}/jobs`：

```
GET /api/sites/{site_id}/analytics?period=day|week|month&n=<桶数>
GET /api/sites/{site_id}/visitors?days=<N>&limit=<M>&cursor=<opaque>
```

`analytics` 响应契约（要点）：

- 时间序列每个桶：`{bucket, pv, uv, pv_denied, uv_exact}`。
- `date < today` 读 `site-access-daily`；`today` 从明细实时 Query 补上
  ——今天的数字实时，历史耐久。
- `period=week|month` 且区间超出 90 天明细窗口 ⇒ `uv: null` +
  `uv_exact: false`（§1.4）。`uv_exact` 是契约的一部分，不是可选字段。

`visitors` 响应契约（要点）：

- 每行：`{ts, email, path, decision}`；`email` 可能为空串（未登录被拒）。
- `days ≤ 90`（= 明细留存），`limit ≤ 100`，翻页用 `LastEvaluatedKey` 编成
  不透明 `cursor`。**参数走查询串是可以的**（`site_id` 与 `days` 都不敏感）；
  M4-FINDINGS §3.1 禁止的是把 `key_id` / 邮箱放进查询串，因为那会进
  CloudFront 访问日志。

### 3.2 权限

`permissions.CAPABILITIES` 新增一个动作：

```python
"view_analytics": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
```

- **不复用 `read`**：访问明细含**其他访问者的 email**，属于另一个敏感度等级。
  单独一个动作名让「以后要收紧成只有 owner+admin」变成改一个字典项，且不牵动
  其它读路径。
- 面板与 MCP **共用这一处判定**（`CAPABILITIES` 是动作→角色的唯一真源，未登记
  的动作对所有人拒绝）。不在任何地方另写角色子句。

### 3.3 rollup Lambda（`site-access-rollup`，deployer 栈）

照 `JobSweepRule` 先例：`events.Rule` + `Schedule` + DLQ + `retry_attempts`。
每天 00:20 UTC 一次。

1. 每轮处理**过去 7 个完整 UTC 日**，不是只处理昨天。`PutItem` 覆盖写、
   天然幂等 ⇒ 连续几天失败无需人工补跑。
2. 只封口 `date < today`（今天的数由读路径实时算，见 §3.1）。
3. site_id 从 sites 表枚举（DynamoDB 无法枚举分区键）。约 31 个站点 × 7 天
   ≤ 217 次 Query/天，成本可忽略。
4. **Query 无行则不写聚合行**——避免给 23 个 DELETED 站点每天各写一行 0
   （2026-08-14 实测 sites 表：DELETED 23 / ACTIVE 6 / DEPLOYING 2，合计 31）。
5. IAM 最小化：明细表只 `Query`、聚合表只 `PutItem`、sites 表只读。它是唯一
   能写聚合表的身份。

### 3.4 MCP 工具

```python
get_site_analytics(site_id: str, period: str = "day", days: int = 30) -> dict
```

- **返回单个 dict**，series 数组放在 dict 里，**不返回裸列表**——M4-FINDINGS
  §3.4 实测线上这台 server 不发 `structuredContent`，返回列表会被拆成多个
  text 块，调用方「取 `content[0].text` 解析」会**静默只拿到第一个元素**。
  审计明细同样作为该 dict 的一个字段返回。
- 权限走 `_assert_permission(email, site_id, "view_analytics")`。

### 3.5 前端

- `renderAnalyticsTab` 由占位改为真实图表 + 访问明细表。
- 超出明细窗口的周/月桶，UV 位置显示显式标注而非数字（§1.4）。
- 现有那段「**不发任何请求**」的注释与占位文案一并删除/改写。

---

## 4. 三个已知坑的处置

### 4.1 `verify_console_e2e.py` ⑪ 段的两条 404 断言 → **删掉**

本 spec 的路由是 `/api/sites/{site_id}/analytics`，所以裸路径 `/api/analytics`
在 M5 之后**仍然 404**。那两条断言不会变假红——它们会**永远绿**，退化成
「断言我们从没打算建的东西不存在」，即 M4-FINDINGS §3.6 的死重量。

**处置**：删除这两条，换成对新路径**真实行为**的断言（200 + 形态 + 无权者
403）。「不泄漏路由表」由该段已有的通用「未知路由（带合法会话）→ 404」继续
覆盖（`verify_console_e2e.py:380`）。这是 §3.2 教训的正确落地——不是改数字，
也不是改路径后继续枚举。

### 4.2 `test_frontend_contract.py` 的守卫 → 从真源推导

现状（该文件约 413-424 行）：禁止前端请求一批**枚举出来的**不存在路径
（`/api/analytics` / `/api/visitors` / `/api/stats` / `/api/pv` /
`/api/api-keys`）。与 4.1 同一个病——枚举「什么还不存在」。

**改成**：前端可能发出的每个 API 路径都必须能匹配 `handler.ROUTES`。这样下一个
里程碑加路由时它既不假红也不假绿。实施要点（计划阶段定形）：

- 新增路径收敛到前端一处常量表，守卫渲染样例 `site_id` 后逐条对 `ROUTES` 匹配；
- 存量散落的 fetch 保留一条较弱的前缀扫描，抓「请求了压根不存在的接口」；
- 保留现有的**剥注释**预处理（注释里写 `/api/analytics` 不该让守卫变红——
  该文件第 28 行已记这个坑）。

### 4.3 缓存策略：不动它，但给它第一条断言

`CACHING_DISABLED` 目前**只有注释、没有任何断言**
（`router/infrastructure/stack.py:271` 是注释，`:284` 是配置）。M5 之后禁缓存
**同时**是鉴权正确性与统计完整性的前提：缓存命中 ⇒ origin-request 不执行 ⇒
**静默漏计**。

**处置**：加一条断言锁定分发的 cache policy 就是 `CACHING_DISABLED`，注释里写明
两个理由都指向这**同一条**配置。**只加守卫，不加第二处定义。**
（phase2 spec §6.4 已把「三期做精细缓存会低估 PV」记为联动项，本条使其可执行。）

---

## 5. 测试与真机闸门

### 5.1 新增/改动的闸门

- **新增 `verify_analytics_e2e.py`**：真机发一次页面请求 → 明细表出现一行
  （`email` / `decision` / `path` 逐字核对）→ 触发 rollup → 聚合行出现 →
  面板 API 返回同一数字 → MCP 工具返回同一数字。
  - **必须轮询等待那一行**（有上限、超时即红），不能发完立刻断言：Global Table
    复制是异步的（§0.4）。立刻断言会做出一个 flaky 闸门，而 flaky 闸门的代价
    是下一个人学会忽略它（同 §3.2 的假红逻辑）。
  - **副本落点核对**：读回该行时确认它在 us-east-1 可见（面板/rollup 的读侧），
    并在 §0.4 第 1 步的日志里确认 Edge 实际写的是本地副本而非回落——否则
    「副本已开但代码一直在回落」会是一个只表现为「慢」的静默退化。
  - **负测必须配正对照**（M4-FINDINGS §3.5）：请求 `.css` 不产生行、请求
    `console` 不产生行——**各自配一条**「页面请求确实产生了行」的正对照。
    否则「埋点压根没部署」会让两条负测永远绿。
  - `denied_403` 与 `redirect_login` 各验一次（被拒记录是本轮明确要的能力）。
  - 清理：先恢复全局状态、再按**依赖顺序**删（M4-FINDINGS §3.8）。
- **`verify_deployed_components.py` 新增一段**：明细表存在 · **三个副本区各自
  ACTIVE**（`describe_table` 的 `Replicas`，按副本清单推导，不手抄）· Edge 角色
  **有且只有** `PutItem` 且资源恰好是那三个 ARN · 聚合表 deletion protection
  开着 · rollup 的 EventBridge 规则 enabled。这一段同时是 §2.4「部署顺序」的闸门。
  **别拿 CFN 的 `StackStatus` 当副本已开的结论**——直接 `describe_table` 读回
  `Replicas`（§5.4）。
- **`verify_deployed_edge.sh`**：核对 Edge 版本 8（Edge 改动要 10-20 分钟
  全球复制）。
- **`verify_console_e2e.py`**：按 §4.1 改造 ⑪ 段。

### 5.2 单测（按包）

- **edge**：`app-` 前缀判定的正/负、页面级判定与静态改写条件的一致性、
  **区域解析与回落**（解析不出区域 → 回落；解析出无副本的区域 → 回落；两种都
  要注入验证，§2.3 规矩 5）、
  三种 decision 的记录形态、埋点异常不影响返回值、**不往 request 加键**、
  **摄取层可替换性**（§0.2：断言写入点只有一处）。
- **deployer**：两张表的 PK/SK/TTL/RemovalPolicy、RETAIN⇒deletion protection
  不变量（自动纳入）、rollup 的幂等与 7 天回溯窗口、无行不写、IAM 最小集。
- **router 栈**：`test_stack_edge_iam.py` 的精确 action/资源集合（**从副本清单
  推导**）、「CDK 副本配置 / IAM 资源集合 / Edge 清单常量三处一致」的锁定断言、
  §4.3 的 cache policy 断言。
- **panel**：两个新路由 · `view_analytics` 授权（含 403 路径）· 分页游标 ·
  `uv_exact` 语义 · `days`/`limit` 上限 · `test_no_route_uses_delete_with_body`
  仍绿。
- **mcp**：新工具的 dict 返回形态（§3.4）、权限判定委派。
- **frontend**：§4.2 改造后的守卫。

### 5.3 反向验证纪律（每个守卫）

注入它要防的缺陷 → 确认变红 → **用 /tmp 备份还原**（**不用
`git checkout --`**，会连未提交的工作一起冲掉）→ `diff -q` + `git status`
双证。§3.9 的追加要求：能说清「旧守卫会漏」的地方，一并证明旧版本保持绿。

### 5.4 硬纪律（本轮沿用）

- 一切文件操作从仓库根用绝对路径；`configparser.read()` 读不到文件是**静默
  返回空**，任何 `has_section` 判断前先 `assert c.sections()`（§3.10）。
- 说「实测过」之前，确认测的是**真实调用路径算出的参数**，不是手填的。
- 永久 SKIP 的检查是死重量（§3.6）；负测必须配正对照（§3.5）。
- 别拿 CFN 的 `StackStatus` 当部署结论，直接读回被改的那个属性。**注意**：这条
  与「对生产做破坏性调用要先问」目前**只在 M4 progress 的「本轮两条新的方法论
  记录（已进 M4-FINDINGS 的候选）」里，尚未真正补进 M4-FINDINGS**（该文件到
  §3.12 为止）。本轮第一个 Task 顺手补入并编号 §3.13 / §3.14——它们正是 M5 要
  用的判据，而「候选」状态意味着下一个人读检查清单时看不到。
- `--skip-X` 类开关要检查「跳过的那步是不是后续步骤的前提」。
- commit 不带 `--no-verify`；Code Defender 拦 AROA/AIDA 整串字面量时改拼接形态，
  不动扫描器配置。
- 中文字符串里不用全角引号（要引用就用「」）。
- `site-builder/config.ini` 与 `router/config.ini` 是 gitignored 且含真实值：
  不 `git add -f`、不打印全文、真实账号/域名/邮箱不进任何被跟踪文件。

---

## 6. 新增 / 改动资源清单

**新增**

| 资源 | 位置 |
|---|---|
| `site-access-events` 表（`TableV2`，DESTROY，TTL 90d，**3 区 Global Table**） | deployer 栈 |
| `site-access-daily` 表（RETAIN + deletion protection，TTL 400d） | deployer 栈 |
| `site-access-rollup` Lambda + EventBridge daily rule + DLQ | deployer 栈 |
| `verify_analytics_e2e.py` | `site-builder/scripts/` |
| `[SiteBuilder]` 新键（明细表名 + **副本区清单**） | `router/config.ini(.example)` |

**改动**

| 文件 | 改什么 |
|---|---|
| `router/infrastructure/lambda/origin_request.py` | 埋点（§2）→ Edge 版本 8 |
| `router/infrastructure/stack.py` | edge_role 的 PutItem 语句（**三个副本 ARN**） |
| `router/infrastructure/lambda/test_stack_edge_iam.py` | 精确资源集合断言 + cache policy 断言（§4.3） |
| `site-builder/deployer/functions/permissions.py` | `CAPABILITIES` 加 `view_analytics` |
| `site-builder/panel/handler.py` / `api.py` | 两个新 GET 路由 |
| `site-builder/panel/frontend/app.js` | 真实统计页（删占位与「不发请求」注释） |
| `site-builder/panel/tests/test_frontend_contract.py` | §4.2 守卫改造 |
| `site-builder/panel/deploy_panel.py` | 两张表的环境变量 |
| `site-builder/mcp/server.py` | `get_site_analytics` 工具 |
| `site-builder/scripts/verify_console_e2e.py` | §4.1 ⑪ 段改造 |
| `site-builder/scripts/verify_deployed_components.py` | 新增一段（§5.1） |
| 平台 Lambda 日志组保留期 | 按 §0.3 的实测清单补/收敛到 30 天（含 3 个区域的 Edge 副本；**收敛是有损操作**） |
| `docs/design/M4-FINDINGS.md` | 补入 §3.13 / §3.14 两条候选条目（见 §5.4） |
| `site-builder/DEPLOY.md` | 部署顺序（表先于 Edge）+ 新组件章节 |

---

## 7. 范围外（重申）

- CloudFront 精细缓存（与本设计直接冲突，见 §4.3）——三期。
- 站点自身的业务埋点 / 自定义事件——站点代码不可信，不给它写平台表的权限。
- 跨站点的全局访问报表（管理员视角的平台总量）——需求 §C 未要求，YAGNI。
- 实时告警 / 异常流量检测——统计不是监控（phase2 spec §6.4 已记）。
- 把统计数据源换回日志侧聚合——已设计成可替换（§0.2），但本轮不实现两套。
