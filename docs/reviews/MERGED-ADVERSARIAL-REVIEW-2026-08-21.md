# Quick Site Builder 一期/二期 对抗性 Review（合并版）

> 本文合并两次独立对抗性审查的结论：
> - **Codex** 的 `docs/reviews/CODEX-ADVERSARIAL-REVIEW-2026-08-21.md`（3×P1 + 2×P2）
> - **Claude** 的本轮审查（控制器直审 + 12 个子代理，8 个最终交付）
>
> 目的是给 Codex 做**交叉确认**，确认后再定 fix plan。所以每条都写了
> **可复现的验证动作**与**证据来源**，并显式标出「我没验证的部分」——
> 交叉确认应优先打这些点。
>
> **红线**：`docs/reviews/` 未被 `.gitignore` 忽略（只忽略 `docs/design/`），
> 本文若被提交会进 git。因此全文不含任何真实账号 ID / 域名 / 资源 ID，
> 一律用 `{account_id}` / `{base_domain}` 占位。已核对 Codex 那份同样干净
> （account_id / base_domain / user_pool_id / AROA / 12 位数字命中数均为 0）。

## -1. 交叉确认后的修订（v2，2026-08-21）

Codex 复核了 v1，提了 5 条关键异议。**我逐条实证复核后，5 条全部接受**，
其中 3 条是我的实质性错误。本节列出所有改动，便于审计：

| 改动 | 原（v1） | 现（v2） | 我错在哪 |
|---|---|---|---|
| **M09** | 降为 P2，「panel 那半已被 `caller_is_edge` 挡住」 | **恢复 P1（条件型）** | **我的判断错了。** `edge_caller.py:21-39` 的**模块 docstring** 明确写了本函数挡不住直接 `lambda:Invoke`（Path A），因为那条路上调用方自己构造整个 payload、连 `callerId` 字段本身都能伪造，并记了 2026-08-15 对 site-panel 的实测（伪造后 `/api/me` 返回 200 且被识别成管理员）。**我当时只 grep 了函数体（`:51-71`），没读上面那段**——而那段的存在目的正是防止我做出的那个推论。这是「截断的读取产出错误断言」，本仓库已记过这条教训。 |
| **M01 处方** | 「一行修复：`validate_site_name` 拒绝匹配 `SITE_ID_RE`」 | **改为精确 ARN 枚举**；正则规则降为纵深防御 | Codex 给的绕过变体成立，我已实测：B 名 `foo-k3d9x1-longname` 是合法名、**不** fullmatch `SITE_ID_RE`（所以我的规则拦不住），而 B id `foo-k3d9x1-longname-abc123` 仍被 A 的 `site-data-foo-k3d9x1-*` 匹配。 |
| **M03 严重度** | P1「永久无法部署」 | **P2「同输入重试不幂等，需修 SQL 或人工介入才能恢复」** | 「永久」过重：用户改自己的 SQL 加 `IF NOT EXISTS` 即可自救，不需要运维碰库。 |
| **M03 处方** | 「记录语句级进度」 | 改为「强制可重放 DDL + 单文件单不可幂等语句 + reconcile + 富失败信息」 | 语句级 marker 解决不了 DSQL 与 DynamoDB **无原子事务**这一点：DDL 已提交而 marker 写失败的窗口依然存在。 |
| **M04** | 汇总表里写「成立」 | **移出正式 finding，降为待验证假设** | 我的「`logo(1).png` 在两种语义下都会坏」推理**是错的**：我只算了 `quote()` 会把 `(` 转成 `%28`，**没算 S3 侧也会按 SigV4 规则把收到的 `(` 编码成 `%28`** ⇒ 两侧收敛、反而匹配。该实验不具决定性。 |
| **M05 泄漏面** | 「码会进 CloudFront 访问日志」 | 删除该说法 | 已核：router 栈里**没有**任何 CloudFront standard logging 配置（`grep logging` 零命中）。这句是我凭常识写的，无依据。 |
| **M02 处方** | 内部矛盾（resync 拒绝投影，但 migrate 改空名单） | **统一为「判不出就拒绝投影并报数据完整性错误」** | Codex 指出的矛盾成立：改 `"org"` 是静默扩权，改 `[]` 是静默收紧，两者都在猜历史意图。 |
| **M06 处方** | 「逐个尝试同名 cookie」 | 标注为**短期缓解**，根治是 host-only 会话 | 服务端拿不到每条 cookie 的 path 元数据；顶域共享 cookie 的设计本身允许任意子域写父域非 HttpOnly cookie。 |
| **M16** | — | 附加验收条件：`list_objects_v2` **无 paginator** | Codex 补的边界，成立。 |
| **M18** | 计为 defect | 标为**已接受风险** | 与既有的成本/DoS 取舍重叠，不应重复计数。 |
| **§0 基线** | 2081 passed | **1881 passed / 54 skipped / 1935 collected（7 个包）** | **我算错了加法**（差 200），且「8 个包」也不对——`CLAUDE.md` 是 7 条测试命令。 |
| **§6** | 把 `caller_is_edge` 列为「已验证无问题」 | 改为「仅对 Path B 有效」 | 同 M09。 |

**未达成一致的点：无。** 5 条异议我全部接受。

### v3 修订（Codex re-review 后，2026-08-21）

Codex 复核 v2 后认可它可作为 fix plan 的事实基线，并提了 3 处必补 + 若干实现约束。
**全部接受并已落入文档**：

| 改动 | 内容 | 依据 |
|---|---|---|
| **M01 利用链** | 补上第 4 步「受害者把攻击者从 collaborators 移除」。v2 漏了它，导致缺陷被表述得不精确 | 已核 `permissions.py:728-729`：`transfer_owner` **自动**把旧 owner 加进 collaborators（「防转错人即失联」）⇒ 移交刚完成时攻击者仍是合法协作者。真正的缺陷是**控制面已撤权、另一站点 runtime 仍保留数据面权限** |
| **M01 现网状态** | 新增只读实测：**7 ACTIVE + 70 DELETED = 77 行，嵌套对 0**（含 DELETED 一起查也是 0） | 我对生产 sites 表做了一次只读 Scan。⇒ M01 **潜伏、未被利用**，支持按正确方式修而非热补 |
| **M01 ARN 范围** | GSI 当前**不需要**索引 ARN（`provision_dynamodb` 不建 GSI、schema 不允许声明，两处 grep 零命中），但守卫要能在将来加 GSI 时变红；日志组收窄；删表语义；现网前置扫描固化 | Codex 补 + 我核 |
| **M09 暴露面** | 从「panel 全部接口」收窄为「读面失守 / 写面仍被一道 HMAC 挡住 / 站点数据面失守」三分 | Codex 指出 v2 那句会被误读 |
| **M09 写面（我对 Codex 的修正）** | Codex 把 Origin 匹配与 Content-Type 也算作写面保护——**在 direct Invoke 上这两条不提供任何保护**（合成 event 里两个头都由攻击者填）。唯一承重的是 `__Host-sb_console` 的 HMAC 验签 ⇒ **M09 写面与 M05 耦合** | 已核 `console_session.py:143-164` 与 `:131-140` |
| **M09 验收身份** | direct Invoke 负向闸门必须用**专用低权限 role**，不能用管理员自己；且「owner 自己 invoke 仍成功」不算修复失败 | Codex 的关键提醒 |
| **↑ 上面三行已被 v5 推翻（2026-08-25）** | 写面**没有**被挡住（密钥 **57** 个 principal 可读，可自签 `scope=console`）；负向探针**不做**（断言的命题不成立）。以 §4 的 M09 v5 + 「v5 的自我更正」与 `docs/security/account-trust-boundary.md` 为准 | 只读实测 |
| **M14 实现约束** | 持久化 lock 必须绑定 package.json hash / Node / npm / registry / lockfile hash，存在只有构建控制面可写的不可变位置 | Codex 补 |

---

## 0. 基线

审查开始时全量单测（`CLAUDE.md` 的 **7** 条命令，同一 SHA `05797af`）：

| 包 | passed | skipped | collected |
|---|---|---|---|
| contract | 123 | 0 | 123 |
| auth | 145 | 0 | 145 |
| router edge | 220 | 4 | 224 |
| deployer | 672 | 50 | 722 |
| mcp | 215 | 0 | 215 |
| panel | 345 | 0 | 345 |
| key-proxy | 161 | 0 | 161 |
| **合计** | **1881** | **54** | **1935** |

**0 failed。**（v1 写的 2081 是我的加法错误，已更正；与 Codex 独立统计一致。）
**未计入**：CDK 模板断言（默认 skip，需 `SB_CDK_TESTS=1` + PYTHONPATH 桥接）、
`mcp/run_locked_tests.sh`（同 215 条用锁定依赖重跑一遍）。

所有下述缺陷都在「全绿」状态下成立——这本身是一条结论：现有闸门覆盖不到它们。

---

## 1. 汇总表

严重度沿用 Codex 的 P1/P2/P3 口径：
**P1** = 跨租户 / 鉴权绕过 / 永久性数据或可用性损失；
**P2** = 影响显著但有触发条件或限于单租户；
**P3** = 卫生、文档、可观测性。

| ID | 严重度 | 来源 | 状态 | 一句话 |
|---|---|---|---|---|
| M01 | **P1** | Claude（Codex 未发现） | 成立，当前线上未触发 | per-site IAM 资源用 `site-data-{site_id}-*` 前缀匹配，site_id 可嵌套 ⇒ 跨站点读写 |
| M02 | **P1** | **Codex P1-2**（Claude 漏） | 成立，当前线上无坏数据 | 权限写入层把坏数据洗成合法的 `BOOL False` / `"org"`，反转 Edge 的 fail-closed |
| M09 | **P1（条件型）** | **Codex P1-1** | **成立；2026-08-25 的 v5 + 自我更正把它扩大了，结论移交 `docs/security/account-trust-boundary.md`** | 同账号 `lambda:InvokeFunction` 可对 **panel 与站点**伪造 `x-user-email`；**且冒充根本不需要 invoke**——只读级权限即可取得 HS256 会话密钥（**三条**路：Edge 产物 / **CDK bootstrap asset** / SSM；**57** 个 principal 能读到），读面与**写面**一起失守。应用层对称签名结构上挡不住；账号内可用非对称签名关掉只读那批，迁独立账号才能移出管理身份 |
| M03 | P2 | Claude（Codex 未发现） | 成立，可被普通 typo 触发 | DSQL 迁移半途失败后同输入重试不幂等，需改 SQL 或人工介入才能恢复 |
| M05 | P2 | **双方**（Codex P1-3 / Claude F8） | 成立，两半各有条件 | 升级码可当会话用，且可**无限续期** |
| M06 | P2 | Claude | 成立，已本地复现 | cookie 路径遮蔽 ⇒ 全平台 `/api/*` 持久性拒绝服务 |
| M07 | P2 | Claude | 成立 | 三个平台 Function URL 的 Principal 永不重建，且 auth 那条无任何闸门 |
| M08 | P2 | Claude | 成立，仅存量环境 | blue/green 迁移脚本不持租约、提交无乐观并发条件 |
| ~~M04~~ | — | Claude | **待验证假设，非正式 finding** | 静态资源 SigV4 签的路径 ≠ 转发的路径；是否真的 403 缺真机证据，见 §4 |
| M10 | P2 | Claude | 成立 | `--mcp-callback` 文档零出现，且裸重跑会**吊销**它 |
| M11 | P2（潜伏） | Claude | 成立 | 无任何守卫绑定 Edge 的 `{{PLACEHOLDER}}` 集合 |
| M12 | P2（潜伏） | Claude | 成立 | `SYNTH-ONLY-PLACEHOLDER` 只 warning，模板仍可部署 |
| M13 | P2（潜伏） | Claude | 成立，当前两侧一致 | IdP 信任清单在两份 config 里，校验强度不对称 |
| M14 | P3 | **Codex P2-1** | 成立 | 站点后端依赖未锁定，构建产物不可复现 |
| M15 | P3 | **Codex P2-2** | 成立 | 访问趋势陈旧响应覆盖（错档位 / 跨站点） |
| M16 | P3 | Claude | 成立，已复现 | `migrations/` 子目录的 SQL 被执行但不被扫描；marker 按 basename 撞车 |
| M17 | P3 | Claude | 成立 | 两份 `.example` 对同一个桶用了不同约定，其一硬编码占位账号 |
| M18 | P3（已接受风险） | Claude | 成立 | 未登录请求也写埋点行 ⇒ 公网可驱动无上限计费写入 |
| M19 | P3 | Claude | 成立 | `_ROUTE_CACHE` 无上界且缓存 miss，键由攻击者选 |
| M20 | P3 | Claude | 成立，仅 dev 脚本 | `deploy_fixture.py` 无条件写 sites 行 ⇒ 静默接管 owner |
| M21 | P3 | Claude | 成立 | 模板↔fixture 字节一致是文档要求，无可执行守卫 |
| M22 | P3 | Claude | 成立 | `[Alerting] email` 不在就绪清单；三个 config 键无人读 |
| M23 | P3（风险） | Claude | 观测结论 | 埋点跨区回落路径**线上从未执行过**，却决定整个超时预算 |
| ~~F9~~ | — | Claude | **已撤回** | 「站点可覆盖平台环境变量」——错误结论，见 §5 |

---

## 2. 与 Codex 报告的差异（交叉确认优先看这节）

> **v2 说明**：本节是 v1 写的「我与 Codex 的分歧」。Codex 复核后，
> 我原先在 P1-1 与 P2-2 上的判断被推翻，已在下表内改正并标注。

| Codex 条目 | v1 我的判断 | v2 定论 |
|---|---|---|
| P1-1 | 降为 P2，「场景 A 已被 `caller_is_edge` 挡住」 | **我错，Codex 对。恢复 P1（条件型）。** `caller_is_edge` 只在**经 Function URL** 调用时拿到可信输入；直接 `lambda:Invoke` 时调用方构造整个 payload，连 `callerId` 都能伪造。`edge_caller.py:21-39` 的模块 docstring 把这条写得很清楚并附 2026-08-15 实测，我漏读了那一段。Codex 本轮又做了一次只读复现（伪造 callerId + 虚构邮箱打 `/api/me`，返回 200、`forged email accepted: true`）。 |
| P1-2 | 同意成立，同意 P1 | 维持。补充：Codex 的第 4 个引用位置 `migrate_permissions.py:57-80` 引错了（那是反例），但**我在那里发现了另一个独立缺陷**（注释里的推导依据已过时），见 M02「附带发现」。Codex 已确认这条独立成立。 |
| P1-3 | 降为 P2，机理写得比原文更强 | **双方一致**：链式续期与 `require_idp_claim` 无关，当站点会话用则受该开关限制；P2 合理。但我关于「码会进 CloudFront 访问日志」的说法**无依据**，已删（见 M05）。 |
| P2-1 | 同意成立，处方需改 | 双方一致。Codex 补充：持久化 lock 需绑定 `package.json` hash、Node/npm/registry 版本、不可变存储与首次解析审计。已采纳进 M14。 |
| P2-2 | 同意成立，「有更省的修法」 | **表述需纠正**：响应回显的 `period` 只修「错档位」那半，跨站点/跨 tab 覆盖仍必须 generation 或 abort。我 v1 已经这么写了，但摘要那句「更省的修法」容易被读成"只需一行"，已在 M15 内改清楚。 |
| — | Codex 未覆盖 | M01、M03、M06、M07、M08、M10、M16~M23。其中 **M01 是唯一一条真正的跨租户数据读写**（Codex 复核后确认 P1）。 |

---

## 3. 详述（上）：M01 – M03

> **注意分节不再按严重度**：v2 重新定级后，M03 降为 P2 但仍留在本节，
> 而 **M09 升为 P1 却在下一节**（§4）。以 §1 汇总表的严重度为准。

### M01 · [P1] per-site IAM 前缀可跨站点匹配

- **来源**：Claude（Codex 未发现）
- **状态**：代码缺陷成立；利用需要构造两个嵌套 site_id，当前线上未见此形态
- **代码位置**
  - `site-builder/deployer/functions/common.py:592` — `arn:...:table/site-data-{site_id}-*`
  - `site-builder/deployer/functions/common.py:586` — `log-group:/aws/lambda/site-{site_id}*`（`*` **前面连分隔符都没有**，更松）
  - `site-builder/deployer/functions/common.py:277-287` — `validate_site_name` 只挡保留词前缀
  - `site-builder/deployer/functions/common.py:290-293` — `new_site_id` = `name[:20].rstrip('-') + "-" + 6 位随机`
  - `site-builder/deployer/infra/app.py:298-309` — PermissionsBoundary 放开**整个** `site-data-*`
- **机理**：site_id 允许内部连字符，站点**名**又没有「不得长得像 site_id」的限制。
  于是站点 A（名 `foo` ⇒ id `foo-k3d9x1`）的资源模式 `site-data-foo-k3d9x1-*`
  会匹配站点 B（名 `foo-k3d9x1` ⇒ id `foo-k3d9x1-ab12cd`）的全部表。
- **为什么 boundary 不救**：boundary 放开的是 `site-data-*`（所有站点），
  它只封顶「最坏能力面」，**per-tenant 隔离完全依赖 inline policy**，而那份是前缀歧义的。
- **我做过的验证**：用 `fnmatch.fnmatchcase` 逐条比对，A 的模式对 B 的
  `site-data-foo-k3d9x1-ab12cd-notes` / `-users` 均返回 `True`；日志组同样 `True`；
  `SITE_NAME_RE.fullmatch("foo-k3d9x1")` 为真。
- **利用路径（v3：按 Codex 的要求补全关键一步）**

  **不能针对已存在的站点**——`permissions.py:56-57` 的 `role_of` 在 `site`
  为假时先返回 `ROLE_NONE`（在 `is_admin` 分支之前），所以任何调用方
  （含管理员）都无法对一个凭空构造的 site_id 操作。所以只能**先设陷阱再移交**：

  1. 攻击者建 A（名 `foo`）⇒ id `foo-k3d9x1`，其 runtime role 的
     DynamoDB ARN 前缀可覆盖未来任何以 `foo-k3d9x1-` 开头的 site_id；
  2. 攻击者建 B（名 `foo-k3d9x1` 或 `foo-k3d9x1-longname`）⇒ id 落在该前缀下；
  3. 攻击者用 `PUT /api/sites/{id}/owner` 把 B 移交给受害者（移交是平台一等功能）；
  4. **受害者随后把攻击者从 B 的 collaborators 移除**；
  5. 此时 Edge / MCP / panel **三条控制面都不再承认**攻击者对 B 有任何权限；
  6. **但攻击者仍可在 A 的 runtime 内按表名直接读写 B 的数据**——A 的 inline
     policy 从未被刷新（`ensure_site_role` 只在**该站点自己**部署时跑），
     且 ARN 前缀仍然匹配。

  **第 4 步是本条的要害，v2 漏了它**（Codex 指出）：`transfer_owner` 会
  **自动把旧 owner 加进 collaborators**（`permissions.py:728-729`，
  注释理由是「防转错人即失联」，我已核）。所以移交刚完成时攻击者仍是 B 的
  **合法协作者**，访问 B 并不构成越权。真正的缺陷必须表述成：
  **权限已在控制面撤销之后，另一个站点的 runtime 仍保留数据面权限。**
- **当前是否已被触发（v3 新增，只读实测）**：对生产 sites 表做了一次只读 Scan：
  **7 ACTIVE + 70 DELETED = 77 行**（与 Codex 的「7 个有效站点」一致）。
  - 7 个 ACTIVE 之间的嵌套对：**0**
  - 含全部 70 个 DELETED 行在内的嵌套对：**0**
  - 7 个 ACTIVE 里 legacy 形态（不匹配 `SITE_ID_RE`）的 id：**0**
    （11 个 legacy 形态的 id 全部落在 DELETED 行里）

  ⇒ **M01 当前是潜伏项，不是已被利用的在线暴露。** 这支持「按正确方式修
  （精确 ARN）」而不是「紧急热补」。含 DELETED 行一起查是必要的：
  下线清理若失败，陈旧的 per-site role 可能仍带着前缀匹配的 policy 存活。
- **DSQL 不受影响**（已核对）：`common.py:559-560` 的
  `dsql_schema_for` = `"site_" + site_id.replace("-","")`，两者得出
  `site_fook3d9x1` 与 `site_fook3d9x1ab12cd`，是不同字符串；且所有 GRANT 用精确名。
- **修复方向（v2：Codex 推翻了我的「一行修复」，已改）**

  v1 我提议「`validate_site_name` 拒绝 fullmatch `SITE_ID_RE` 的名字」。
  **这不充分**，Codex 给的绕过变体我已实测确认：

  | B 的名字 | 合法？ | 被我的正则规则拦住？ | A 的 policy 仍匹配 B 的表？ |
  |---|---|---|---|
  | `foo-k3d9x1` | 是 | 是 | 是 |
  | `foo-k3d9x1-longname` | 是 | **否**（末段 8 位，不是 6 位） | **是** |

  只要 B 的 **id** 以 A 的 id + `-` 开头即成立，而「名字像不像一个完整
  site_id」拦不住这一族。**必须消除资源命名的前缀歧义本身**：

  1. **首选：inline policy 枚举实际表的精确 ARN**，不用任何通配。
     可行性已核：`common.py:612` 的 `site_policy(site_id, engine)` 目前只收
     两个参数，但表名来自 **manifest**（`provision_dynamodb.py:12` 按
     `site-data-{site_id}-{spec['name']}` 生成），而 manifest 从 validate 起
     就在 event 里；且 `ensure_site_role` 每次部署都刷新 inline policy
     （`deploy_lambda_site.py:164`、`provision_dsql.py:109`）。
     所以把声明的表名列表传进去即可，是局部改动。
  2. 或者用无歧义标识：`site-data-{site_id_hash}-{logical_table}`（要迁移存量表名）。
  3. 日志组那条同样别以裸 `*` 结尾（`common.py:586`）。
  4. `validate_site_name` 的正则规则**只作为纵深防御保留**，不算修复。

  **实现时要一并确认（v3，Codex 补 + 我已核）**：
  - **GSI**：当前**不需要** `table/<name>/index/*`——`provision_dynamodb.py`
    不建任何 GSI，contract schema 也不允许声明索引（两处 grep 均零命中）。
    但修复要写成「将来加 GSI 会让守卫变红」，而不是默默漏掉索引 ARN。
  - **日志组**同样要从裸前缀通配收窄（`common.py:586`）。
  - **manifest 删表后**旧表的访问权按产品语义决定去留（现在是自动继续覆盖）。
  - **上线前先扫一遍现网**找历史嵌套记录——我已经扫过，结果见上（0 对）。
    这个脚本应该固化下来，作为修复的前置与回归的一部分。
- **回归测试要求**：先写一条**会红**的用例——用
  `foo-k3d9x1` / `foo-k3d9x1-longname-abc123` 这一对（**不是** v1 写的
  `foo-k3d9x1-ab12cd`，那一对会被正则规则挡住而掩盖问题），
  断言 A 的 policy 文档不匹配 B 的任何表 ARN。
  另加一条**撤权后的数据面**用例：模拟第 4 步（从 collaborators 移除）之后，
  断言 A 的 runtime 已无法访问 B 的表——这条才对应真正的不变量。

### M02 · [P1] 权限写入层把坏数据洗成「公开」/「全组织」

- **来源**：**Codex P1-2**。Claude 本轮漏掉（我读过 `resync_route`，
  但只在查「会不会踩掉 blue/green 切色」，没问「投影本身对坏源数据安全吗」）
- **状态**：代码缺陷成立；Codex 报告当前 7 个站点 / 7 条用户路由无坏数据形态，与我的观察一致
- **代码位置**
  - `site-builder/deployer/functions/permissions.py:507-511` — `effective` 的两个默认值
  - `site-builder/deployer/functions/permissions.py:572-573` — 写进路由：`{"BOOL": effective["require_login"]}` / `allowed_users_av(...)`
  - `site-builder/deployer/functions/permissions.py:760-788` — `resync_route` 同形，且更松
- **机理（两条独立的「洗白」路径）**
  1. `bool(site.get("require_login", True))`：sites 行里 `require_login` 若是
     **假值非布尔**（`Decimal(0)`、`""`、`[]`、DynamoDB `NULL`），`bool()` 得到
     `False`，随后以**字面 `BOOL False`** 写进路由。而 Edge 的判定正是
     「`require_auth is False` ⇒ 公开」，于是它被当成**站主显式声明公开**——
     完全公网可读，连登录都不要。
  2. `site.get("allowed_users", "org")`：缺字段 ⇒ `"org"` = 全组织可见。
     `resync_route` 写的是 `normalize_allowed_users(raw) if raw else "org"`，
     对**任何假值**都触发，比缺字段更宽。
- **为什么这条特别严重**：Edge 在 2026-08-06 专门加了 `_UNKNOWN` 哨兵
  （`origin_request.py:349-371`、`:589-596`、`:628-640`），就是为了让坏数据
  fail-closed。写入层把坏数据**转换成一个合法的 `BOOL False`**，等于把那次
  加固整个抵消掉。Codex 的表述最准确：**读路径与写路径对坏数据的语义相反。**
- **触发面比想象大**：`effective` 在**每次**权限写入时都从存量行重算，
  与用户这次改的是哪个字段无关。所以「改协作者」会顺带重投影 `require_auth`。
  另外 `create_site_record` 建站只写 owner/name/status ⇒ 新站点在首次成功部署前
  本身就是稀疏行（该窗口内路由行还不存在，事务会因
  `attribute_exists(subdomain)` 失败，所以那一段是被挡住的）。
- **附带发现（Codex 未提，且是它引用错位置换来的）**：
  `site-builder/scripts/migrate_permissions.py:55-82` 的 `_parse_allowed`
  是**反例**——它对无法解析的值和未知 AttributeValue 类型**显式抛错**，
  docstring 把这条扩权论证写得很完整。但它保留的那个「属性整体缺失 ⇒ `"org"`」
  的理由是：*"Edge 的默认正是如此：`route.get("allowed_users", "org")`"*。
  **Edge 已经不是这个行为了**——现在是
  `route.get("allowed_users") if "allowed_users" in route else []`，
  并注明缺失时默认 `"org"` 是 fail-open。**推导依据已过时，代码没跟着改。**
  这是本仓库的招牌失效形态：不变量在第二处被手抄推导，真源后来变了。
- **修复方向（v2：统一为「判不出就拒绝投影」，已消除 v1 的内部矛盾）**

  Codex 指出 v1 的处方自相矛盾：一边说 `resync_route` 不该静默收紧，
  一边又说 `migrate_permissions.py` 的 `"org"` 回落改成空名单。**这条批评成立**
  ——改 `"org"` 是静默扩权，改 `[]` 是静默收紧，**两者都在猜历史意图**。统一为：
  - `require_login`：必须 `isinstance(x, bool)`，否则**抛错**；绝不 `bool(x)`。
  - `allowed_users`：判不出就**拒绝投影并报数据完整性错误**，
    报文点名 site_id 与坏字段，让人去修那一行。
    三个 writer（`write_permissions`、`resync_route`、`migrate_permissions`）
    **一律如此**，不各自选方向。
  - 唯一允许「从 manifest 初始化权限」的情形：**首次部署**、route 尚不存在、
    manifest 已过 validate、且受控 seed 条件成立。
  - 顺带删掉 `migrate_permissions.py:55-82` 注释里那句已过时的推导
    （它说 Edge 默认是 `"org"`，现行 Edge 是空名单）。
- **回归测试要求**：先写会红的用例——sites 行 `require_login = Decimal(0)`，
  跑一次**无关**的权限修改（例如加协作者），断言路由行的 `require_auth`
  **仍为 True**。当前实现下它会是 `False`（这就是「先会红」）。

### M03 · [P2] DSQL 迁移半途失败后同输入重试不幂等

> **v2**：v1 定级 P1「永久无法部署」。Codex 指出「永久」过重——用户改自己的
> SQL 加 `IF NOT EXISTS` 即可自救，不需要运维碰库。**接受，降为 P2。**
> 但保留一条限定：当前失败信息只抛原始 SQLSTATE（`42P07`），
> 一个业务用户/Agent 未必知道要去加 `IF NOT EXISTS`，所以
> 「理论上可恢复」要靠**失败文案点名补救办法**才等于「实际上可恢复」。

- **来源**：Claude（子代理 rev-bluegreen 提出，我逐条核实；Codex 用状态化
  fake cursor 独立复现了同一序列）
- **状态**：成立，可由一次普通 typo 触发
- **代码位置**
  - `site-builder/deployer/functions/provision_dsql.py:25,38` — `autocommit=True`
  - 同文件 `:2` — *"DSQL 约束：无 CREATE DATABASE；每事务一条 DDL → 逐条 execute（autocommit）"*
  - 同文件 `:145-151` — `run_file` 跑完**整个文件**才 `applied.append(marker)` + `upsert_site`
  - 同文件 `:120-123` — `_exec_ignoring_duplicate` **只用于**引导期的 role/GRANT DDL
  - `site-builder/contract/src/contract/redlines.py:45-51` — `IF NOT EXISTS` 只是「支持且推荐」，**未强制**
- **机理**：autocommit 不是选择而是 DSQL 的约束。`schema.sql` 第 3 条失败
  （typo，或 300s 超时落在文件中间）⇒ 前 2 条已提交、marker 未写、无人回滚。
  下次部署 `applied` 里仍没有 `"schema.sql"` ⇒ 从第 1 条重跑 ⇒ `42P07
  duplicate_table` ⇒ `cur.execute` 抛出。此后**每一次**部署都同样失败。
- **为什么闸门抓不到**：单测把连接 mock 掉了，「一个记得住第 2 条语句的数据库」
  从未被重放。
- **后果**：站点进入「同一份产物再也部署不上去」的状态，直到 SQL 被改成可重放
  （用户可自救）或运维修库。
- **修复方向（v2：Codex 推翻了我的「语句级 marker」，已改）**

  v1 我提议记录语句级进度。**不充分**：DSQL 与 DynamoDB 之间**没有原子事务**，
  所以「DDL 已提交 → marker 写入失败或响应丢失 → 重试时不知道这条生效没有」
  这个窗口依然存在，只是变窄。采纳 Codex 的组合方案：
  1. 合同层**强制可重放形式**：`CREATE TABLE IF NOT EXISTS`、
     `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`（这是最高性价比的一条，
     且 `redlines.py` 已有 SQL 扫描器，加规则即可）；
  2. 一条**不可幂等**的迁移语义单独成文件，缩小重放粒度；
  3. 为每类迁移定义受控的 reconcile/inspect，而不是泛化地吞掉 duplicate；
  4. 失败信息记全：文件名、第几条语句、SQLSTATE、已知已提交的对象，
     **并直接给出补救办法**（见本条开头的限定）。
- **回归测试要求**：用真能记住状态的 fake（不是 mock 掉 execute），
  让第 3 条抛错，再重跑一次，断言第二次**不是** `duplicate_table` 失败。
- **与 M16 的联动**：`migrations/` 子目录绕过红线扫描会让「DSQL 不兼容语句
  在执行期才失败」更容易发生 ⇒ 更容易踩进本条。若采纳上面第 1 条，
  M16 必须一起修，否则子目录里的 SQL 照样绕过 `IF NOT EXISTS` 强制。

---

## 4. 详述（下）：M04 – M23（**含 P1 的 M09**）

### ~~M04~~ · 待验证假设（非正式 finding）

> **v2**：v1 把这条列为「成立」的 P2。**Codex 的异议成立，已降级。**
> 我 v1 提出的「`logo(1).png` 在两种编码语义下都会坏，所以是决定性实验」
> **推理有错**：我只算了 `quote()` 会把 `(` 转成 `%28`，
> **没算 S3 侧也会按 SigV4 规则把收到的裸 `(` 编码成 `%28`**
> ⇒ 两侧收敛、反而匹配。该实验不具决定性，这条也就没有确证。

- **可确证的部分（代码不对称，事实）**：
  `router/infrastructure/lambda/origin_request.py:697` 用
  `urllib.parse.quote(uri)` 参与签名，而同文件 `:674` 写回
  `request["uri"]` 的是**未 quote 的** `uri`。两者在
  `uri != quote(uri)` 时不是同一个字符串。
- **不能确证的部分**：由此**不能**推出 S3 必然 403。SigV4 的 CanonicalURI
  本身要求 URI 编码，若 S3 用收到的裸路径按同一规则重新编码，两侧就收敛。
  而 **CloudFront 交给 Lambda@Edge 的 `uri` 是否已 percent-encoded，
  两次审查都没拿到权威答案**（AWS 文档工具对双方都报
  `No module named 'rich.traceback'`）。
- **为什么即便成立也不会被现有闸门发现**（这部分与结论无关，是事实）：
  合同对**文件名字符集零校验**；`upload_frontend.py:34` 原样保留名字；
  `smoke_test.py:75-77` 只取 `/` 与 `/api/health`，而 `require_auth` 站点的
  `/` 返回 302、**根本不碰 S3**。
- **最小真机判别实验（无副作用，做完再决定要不要修）**：
  在专用测试站点的 `static_prefix` 下上传这 5 个文件，逐个访问，
  同时记录 Edge 收到的 `request.uri` 形态（只记文件名，不记 query）与 S3 响应码：

  | 文件名 | 探什么 |
  |---|---|
  | `a b.png` | 裸空格 |
  | `logo(1).png` | 保留字符（两侧是否都编码成 `%28`） |
  | `我.png` | 非 ASCII |
  | `100%.png` | 字面 `%` |
  | `a%20b.png` | **双重编码判别键**——文件名本身长得像已编码序列 |

  最后一行是 Codex 补的，也是真正能分辨「CloudFront 给的是已编码还是已解码」的那个。
- **在拿到实验结果之前，本条不进入修复优先级。**
- 若确证，修法是让「签的字符串」与「写回 `request["uri"]` 的字符串」
  **由构造保证同一个**，而不是各算一次。

### M05 · [P2] 升级码可当会话用，且可无限续期

- **来源**：Codex P1-3 与 Claude F8 独立命中同一处；**链式续期是 Codex 的贡献**
- **代码位置**
  - `site-builder/auth/session.py:40-51` — `verify_session_jwt` 只校验签名 + `exp`，不看 `typ`/`scope`/`jti`
  - `site-builder/auth/login_handler.py:491` — `/console-session` 用它校验 `sb_session`
  - 同文件 `:502` — 校验通过即 `mint_upgrade_code(claims["email"], ...)`
  - `site-builder/auth/session.py:72-82` — 升级码含 `typ="console-upgrade"`，TTL ≤60s，一次性
- **我做过的验证**（脚本实跑）：
  1. `verify_session_jwt(upgrade_code)` 返回完整 claims ⇒ 被当成普通会话接受；
  2. 把升级码当 `sb_session` 喂进 `/console-session` 的那两行，**连续 3 轮**都成功
     换出新的 60s 升级码 ⇒ 「一次性 + 60 秒」两个属性同时失效；
  3. 升级码 claims 里 `idp` 与 `auth_via` 均为 `None`。
- **两半的触发条件不同（比 Codex 的写法更准）**
  - **链式续期**：与 `require_idp_claim` **无关**。`auth` 子域注册为
    `require_auth=False`（`deploy_auth.py:192-196`），Edge 不 gate `/console-session`，
    是 auth 服务自己校验 cookie。所以泄漏一个码即可永久续期。
  - **当站点会话用**：受 `require_idp_claim` 控制。当前线上 `=true`，
    升级码缺 `idp`/`auth_via` ⇒ Edge 302 挡住。**但
    `router/config.ini.example:106` 出厂是 `false`**，新账号默认落在暴露态。
- **泄漏面（v2 已收敛表述）**：码走在 query string 里
  （`console.{base_domain}/api/session-callback?code=...`）。
  v1 我写「会进 CloudFront 访问日志」——**这句无依据，已删**：
  已核 router 栈里没有任何 CloudFront standard logging 配置（`grep logging` 零命中）。
  准确的泄漏面是：浏览器历史、浏览器扩展、本机代理、截图/录屏、
  以及**将来可能新增的日志链路**。
  （另注：Edge **自己**的 CloudWatch 日志曾真实记到过明文 OAuth code，
  这也是 `origin_request._redact_querystring` 存在的原因，现已脱敏。）
  原设计靠「60s + 一次性」把泄漏价值压到近零，链式续期把它还原成长期凭证。
- **未升级为 P1 的理由**：需要先拿到一个码；且站点会话那半在当前配置下被挡。
  双方一致。
- **修复方向**：`verify_session_jwt` 增加**必填**的 `expected_typ`
  （给会话 token 也签一个 `typ`），缺省即拒；调用方全部显式传。
  **必须同步改 Edge 内嵌的那份 verifier**（`origin_request.py:452-470`）——
  只改 `auth/session.py` 等于只修了一半，而这两处按设计必须字节等价。
  Codex 建议 C（分离密钥）更强，可作为二阶段。
  另建议把 `router/config.ini.example:106` 的出厂值从 `false` 改掉，
  或至少在旁边写明「出厂值使本条可利用」。
- **回归测试要求**：先写会红的用例——把 `mint_upgrade_code` 的产物喂给
  `verify_session_jwt` 断言得到 `None`；再断言把它当 `sb_session` 打
  `/console-session` 得不到新码。

### M06 · [P2] cookie 路径遮蔽 ⇒ 全平台 `/api/*` 持久性 DoS

- **代码位置**：`router/infrastructure/lambda/origin_request.py:473-479`
  （`_get_cookie` 返回**第一个**命中）；`site-builder/auth/login_handler.py:469`
  （`sb_session` 带 `Domain=.{base_domain}`、`HttpOnly`）
- **机理**：`HttpOnly` 只阻止用 `document.cookie` 覆盖
  **同 (name, domain, path)** 的那一条。站点页面 JS 写
  `sb_session=garbage; domain=.{base_domain}; path=/api` 是**新建第二条** cookie，
  浏览器不拦。RFC 6265 §5.4.2 规定**路径更长的先发**，而 `_get_cookie` 只取第一条。
- **我做过的验证**：对真实 verifier 实跑——cookie 头为
  `sb_session=garbage; sb_session=<真 token>` 时 `_get_cookie` 返回 `garbage`、
  验签失败；仅有真 token 时验签通过。
- **后果**：受害者只要访问过那个（可以是 public 的）站点，此后所有站点
  **以及 `console.{base_domain}`** 的 `/api/*` 全部 302 回登录；重新登录只写
  `path=/`，不清除遮蔽 ⇒ 持久。表象极难诊断：人是登录状态、静态页正常，只有接口在弹。
  登录本身仍可用（`auth` 子域 `require_auth=False`）。
- **不构成会话固定**（我核实后否掉了这半）：`site-builder/panel/console_session.py:83-91`
  的 `consume_code` 在**原子消费 jti 之前**先比对 `expected_email` 与 Edge 注入的
  `x-user-email`，且空值不算相等。所以只有可用性影响。
- **修复方向（v2：区分缓解与根治）**
  - **短期缓解**：`_get_cookie` 收集**同名的全部值**，`_check_auth` 逐个尝试，
    任一验签通过即放行。这能消掉垃圾 cookie 造成的 DoS。
  - **但这不是完整隔离**（Codex 的补充，成立）：服务端拿到的 Cookie 头
    **没有每条 cookie 的 path 元数据**；若攻击者手里有另一个**合法**的
    session token，注入它仍可造成身份混淆；顶域共享 cookie 的设计本身
    就允许任意子域写父域的非 HttpOnly cookie。
  - **长期根治**：站点/控制台会话改用 host-only 的 `__Host-` 形态，
    或做站点级会话交换（每个站点一个不可跨站重放的会话）。
- **回归测试要求**：先写会红的用例——两条 `sb_session`，第一条是垃圾，
  断言仍然放行。

### M07 · [P2] 平台 Function URL 的 Principal 永不重建；auth 那条无闸门

- **代码位置**
  - **正确形态**：`site-builder/deployer/functions/deploy_lambda_site.py:262-315`
    ——读 policy、删掉所有非预期 Sid、`remove`→`add`、最后一轮仍冲突则**抛出**。
    注释注明这是 Codex 2026-08-17 P1-5 的加固，理由是
    *「同名 StatementId 已存在只说明有一条语句叫这个名字，不说明它的内容是对的」*。
  - **未同步**：`site-builder/auth/deploy_auth.py:186-190`、
    `site-builder/panel/deploy_panel.py:441-444`、
    `site-builder/key-proxy/deploy_key_proxy.py:493-497`
    ——仍是 `except ResourceConflictException: pass`，不读 policy、不核 Principal、不清野 Sid。
  - **文档声称了但代码不校验**：`deploy_panel.py:9-11` 与
    `deploy_key_proxy.py:26-28` 都把「resource policy **恰好两条语句**、
    Principal 逐字符 exact」写成关键约束。
  - **闸门缺口**：`site-builder/scripts/verify_deployed_components.py:344`
    的 `_check_function_url_authz` 确实断言 principals 集合，但只在
    `:550`（panel）与 `:1080`（key-proxy）被调用——**`site-auth-service` 从未被检查**。
- **后果**：`edge_role_arn` 一旦变化（router 栈重建、角色重创、config 改错后修正），
  重跑脚本报成功而 policy 仍授权旧 principal ⇒ Edge 403。auth 那条一挂
  = 全平台登录不可用，且没有任何闸门会指出来。
- **已核对为**没问题**的一半**：`AuthType` 漂移回 `AWS_IAM` 三处都查
  （`deploy_auth.py:171-172`、panel `:432-435`、key-proxy `:484-487`）。
- **修复方向**：把 `deploy_lambda_site` 那段（清野 Sid + remove→add + 抛出）
  抽成单一实现，三个平台脚本共用；`_check_function_url_authz` 补上 auth。

### M08 · [P2] blue/green 迁移脚本不持租约

- **代码位置**：`site-builder/scripts/migrate_sites_to_blue_green.py:292`
  ——`UpdateExpression="SET api_target = :t"`，`ConditionExpression` 只有
  `attribute_exists(subdomain)`，**没有**对读到的 `api_target` 做乐观并发条件；
  全脚本 `lease` / `RUNNING` / `DeployInProgress` 零命中。
- **对照**：租约设计本身是健全的（`common.py:308-460`），
  「持有 ⟺ 持有者 job 为 RUNNING」，因此不存在忘记释放的失效模式；
  读后判定也用同一笔事务里的 `ConditionCheck` 关掉了 TOCTOU。
  问题只是**这个 writer 没接进去**。
- **后果**：`--apply` 期间用户发起部署 ⇒ 迁移脚本用自己算出的 URL 覆盖
  刚提交的路由，两边还可能同时动同一个色的 alias ⇒ 正是
  `common.py:308-312` 所述「前端来自 A、后端来自 B」那条不变量被破坏。
- **范围**：只有存量环境需要跑，运维手动触发，默认 dry-run。
- **修复方向**：最小改动是把读到的旧值放进条件
  （`api_target = :expected_old`），把静默覆盖变成响亮失败；更彻底是接租约。
- **已核实为安全**（本条的邻域，勿重复排查）：补偿**不会删掉线上色**——
  两个 cleanup 只在成功分支调用，`keep_extra=(deploy_version,)` 专门吸收
  alias 读陈旧的情况，且任何非 `ResourceNotFound` 失败会中止整个 cleanup
  而不是部分执行（来源：子代理 rev-bluegreen，引 `mark_job.py:294-319,449-455`；
  **我未逐行复读该文件**）。

### M09 · [P1（条件型）] 同账号 `lambda:InvokeFunction` 可对 panel 与站点伪造 `x-user-email`

> **v2 全面改写。v1 我判「panel 那半已被 `caller_is_edge` 挡住」——这是错的。**
> 我当时只 `grep -A 22 "def caller_is_edge"`（拿到 `:51-71`），
> **没有读上面的模块 docstring `:21-39`**——而那 19 行的存在目的，
> 恰恰是防止读者做出我做的那个推论。这是「截断的读取产出错误断言」，
> 本仓库已记过这条教训。**恢复 Codex 的 P1 定级。**

- **来源**：Codex P1-1（2026-08-10 首次发现，2026-08-15 与本轮各实测一次）
- **状态**：**当前线上成立**，两条路径都成立
- **代码自己写了这件事**（`site-builder/deployer/functions/edge_caller.py:21-39`，原文）：
  - **Path A：直接 `lambda:Invoke`**（不经 Function URL）——调用方自己构造
    **整个 payload**，包括 `requestContext.authorizer.iam.callerId` 这个字段本身
    ⇒ 可以把自己伪造成 Edge 的 RoleId。
    *"2026-08-15 对 site-panel 实测过：伪造后 `/api/me` 返回 200 并被识别成管理员。
    **本函数读的就是那个字段，所以在这条路上天然被绕过**——不是实现不严，
    是这一层拿不到可信输入。"*
  - **Path B：经 Function URL 调用**（SigV4）——`callerId` 由 **STS** 填写，
    调用方不可伪造 ⇒ `caller_is_edge` 在这条路上有效。
  - docstring 结尾明写：*"本层的定位是**纵深防御**，**不是**同账号绕过这条缺陷的修复。
    看到这段不要推论成'已经没有绕过路径了'。"*
- **Codex 本轮的只读复现**：对线上 `site-panel` 直接 Invoke，event 里伪造
  Edge RoleId 的 `callerId` + 虚构邮箱 `merged-review-probe@example.invalid`，
  只打 `/api/me`：`Invoke status: 200 / Handler status: 200 /
  forged email accepted: true / is_admin: false`。
- **暴露面（v3 收窄表述，Codex 指出 v2 那句会被读成「panel 全部接口立即失守」）**

  Path A 绕过的是**「身份来源」这道边界**，不是 panel 的全部鉴权：

  | 面 | direct Invoke 的效果 |
  |---|---|
  | panel **读**接口 | **已失守**——`x-user-email` 可任意伪造，站点列表、访问统计、访客明细、部署历史等都是权限边界内的数据 |
  | panel **写**接口 | **仍被挡住**，但**只靠一道**：`__Host-sb_console` 的 HMAC 验签 + `scope==console` + email 与 `x-user-email` 一致（`console_session.py:131-140`） |
  | 站点 Lambda | **数据面失守**——站点按设计信任 Edge 注入头，且没有第二道平台鉴权 |

  **我对 Codex 这段的一处修正**：它把「Origin 逐字符匹配」与
  「Content-Type 必须 application/json」也算作写面的保护。
  在 direct Invoke 这条路上**这两条不提供任何保护**——`check_csrf`
  （`console_session.py:143-164`）读的是 `headers` 里的 `origin` 与
  `content-type`，而合成 event 里这两个头完全由攻击者填。
  唯一**真正承重**的是那道 HMAC 验签：攻击者可以把 `x-user-email` 写成任何人，
  但没有 JWT 密钥就造不出与之匹配的、`scope=console` 的签名 token。
  这一点值得单独记住，因为它意味着 **M09 的写面与 M05 是耦合的**：
  一旦出现任何能拿到「任意 email 的 console 作用域 token」的路径，
  direct Invoke 立刻从「读面失守」升级为「写面失守」。
- **闸门为什么没抓住**：`verify_deployed_components.py` 的 73/73 覆盖的是
  **Function URL 入口**（Path B），不是 direct Invoke（Path A）。
- **前提**：调用方需已持有同账号 `lambda:InvokeFunction`。
  **per-site 角色没有该权限**（boundary 只有 dynamodb / dsql / logs，
  见 `infra/app.py:298-309`）⇒ 恶意站点作者走不通这条路。

- **实测暴露面（v4 新增；这条把「接受风险」这个选项排除了）**

  v3 的第 0 步是「先写准风险模型」，其潜台词是「也许只有账号 owner 有这个权限，
  那就是接受风险而非修复」。**已实测，该潜台词不成立。**

  方法：`iam:GetAccountAuthorizationDetails` 全量拉取 + 本地筛出候选，
  再用 **`iam:SimulatePrincipalPolicy`** 逐个确认（只读；
  模拟器会算 permissions boundary，且本账号无有效 SCP）。

  | 项 | 数 |
  |---|---|
  | 账号内非 service-linked 角色总数 | **398** |
  | 本地初筛候选 | 21 |
  | **模拟器确认可 `lambda:InvokeFunction` on `site-panel`** | **18** |
  | 其中管理 / break-glass 类（属既定信任模型） | 5 |
  | 其中**合法**需要该权限的平台角色 | **1**（Edge 执行角色） |
  | 其中**与本项目无关的工作负载角色** | **12** |

  那 12 个按类别（**不写角色原名**——其中 3 个是 CDK 约定命名、
  名字里嵌着账号 ID，写进被跟踪文件会违反仓库红线）：
  - 2 × 某无关工作负载的 **EC2 实例角色**（instance profile）
  - 3 × **CDK CloudFormation 执行角色**（通常是 AdministratorAccess，
    任何能跑 CDK 部署的人都能用）
  - 1 × SageMaker 执行角色
  - 2 × 另一套 GenAI Agent 栈的 runtime / gateway 角色
  - 1 × 某 Web 应用角色、1 × 某 agent 角色
  - 1 × EKS 相关、1 × QuickSetup StackSet 执行角色

  ⇒ **任何一个上述工作负载被拿下（或任何能在本账号跑 notebook / EC2 /
  CDK 部署的人），都可以对控制台与任意站点冒充任意用户。**
  这不再是「只有我有权限」的个人账号模型，而是一个多工作负载共享账号。

  **一处自我更正**：本地初筛给出 21，其中 3 个（SageMaker 的两个
  query-execution 角色等）被模拟器判为 `implicitDeny`——我的本地匹配器
  **没有评估 Condition**，所以过报。**以模拟器的 18 为准。**
- **为什么「贴 SCP」在本账号里不成立**（这是 fix plan 的关键约束）：
  `site-builder/policies/` 已有一份**可选**的 SCP 模板
  （`scp-site-invoke-only-edge.json`）与 `README.md` 里的三条边界，
  第一条就是：*"SCP 对 Organizations **管理账号无效**……
  **本部署所在的账号就是管理账号**"*。所以贴上它**也不等于 Path A 被关闭**。
- **合法需要该权限的白名单（实测确认，修复不能碰这几个）**
  1. **Edge 执行角色**——经 Function URL 调 panel / key-proxy / auth / 站点后端；
  2. **`site-deployer-exec-role`**——blue/green 的健康门是**真的直调**
     （`deploy_lambda_site.py:91-103`，带 Qualifier 以强制冷启），
     模拟器确认它对站点函数 `allowed`。**砍掉它会打断部署**；
  3. panel 角色对 `site-deployer-undeploy` 这一个函数（`deploy_panel.py` 的 `UNDEPLOY_FN`）；
  4. Step Functions 角色对各步骤 Lambda。

  **「用 Lambda 就需要 `lambda:InvokeFunction`」是个误解**，值得写下来，
  因为它决定了这条能不能修：Lambda 的**执行角色**并不需要该权限——
  它只在「这个函数要去调另一个函数」时才需要。所以上面那 12 个无关角色
  拿到它靠的是**过宽授权**（多为 `Resource: "*"`），不是真实需要。
  **⇒ 收窄是可行的，不会打断任何东西。**

- **修复方向（v4 按实测结果重排）**
  1. ~~先写准风险模型再决定要不要动~~ → **已经测完，必须动。**
     文档里保留这句事实陈述：*"应用层不能抵抗持有同账号
     `lambda:InvokeFunction` 的 principal"*，但它现在是**待修**而非**已接受**。
  2. **收窄那 12 个角色的过宽授权**（identity policy / permissions boundary）。
     注意**不能靠 SCP**（本账号是 Organizations 管理账号，见
     `site-builder/policies/README.md` 边界①），
     也**不能靠 Lambda resource policy**——同账号下 identity policy 单独即可
     授权 invoke，`AddPermission` 又只能写 Allow。
  3. **结构性修复（本轮实测后应升为首选，不再是「长期项」）**：
     把平台迁到**独立的 Organizations 成员账号**。理由是数量——
     账号内有 398 个角色、十几个互不相关的工作负载，
     逐个收窄是在一个会持续漂移的集合上打地鼠；
     换账号之后 SCP 才生效，且 blast radius 一次性收敛。
  4. 补 direct Invoke 负向闸门（验收身份的设计见下）。
  4. 补一条**负向闸门**：验收脚本里加一次 direct Invoke 探针，断言它被拒
     ——现在没有任何闸门覆盖 Path A。

     **但验收身份必须设计对（v3，Codex 的关键提醒，接受）**：
     如果跑验收的 principal 本身是账号管理员 / root / break-glass 角色，
     它本来就有 `lambda:InvokeFunction`、也本来就能改 IAM 策略，
     那么「让它 direct Invoke 然后期待 403」不是有意义的断言。正确做法：
     1. 建一个**专用低权限测试 role**，不在 Edge / deployer / break-glass 白名单里；
     2. 对它显式施加 intended Deny / permission boundary；
     3. 用**该 role** 执行 direct Invoke 探针，必须 `AccessDenied`；
     4. 同时正向验证：Edge 角色经 Function URL 仍可用、deployer 健康检查所需调用仍可用；
     5. 管理员 / break-glass 的保留权限，按你**明确写下来的**风险模型核对。

     **不要把「账号 owner 自己 direct Invoke 仍然成功」判成修复失败**
     ——那是管理员信任模型的一部分，不是漏洞。
- **对 Codex 建议 C 的异议（这条我维持）**：给函数加应用层 Edge 签名，
  对 panel / key-proxy 是冗余的；对**站点 Lambda 不可行**——验签需要站点持有密钥，
  而站点代码是不可信的 AI 生成代码，把平台密钥注入它的环境正是
  PermissionsBoundary 要防的事，且与「站点代码零 auth 逻辑」这条核心设计冲突。

- **v5（2026-08-25，执行 M09 第 1 步时的实测。本条的结论移交
  `docs/security/account-trust-boundary.md`，那份文档是随仓库分发的真源）**

  重跑了 v4 的方法并扩了两项动作，结果在两个方向上都比 v4 更坏：

  | v4 说 | v5 实测 |
  |---|---|
  | 18 个角色可对 `site-panel` direct invoke | 41 个 principal 具备至少一项敏感能力；其中**非平台**身份可直调平台/站点函数的 18 个（与 v4 数吻合），**但这已不是主要暴露面** |
  | 写面「仍被一道 HMAC 挡住」 | **没挡住。** 那把 HS256 密钥 35 个 principal 能读到，于是可以签出 `scope=console` 的 `__Host-sb_console` |
  | 修复方向 = 收窄那 12 个角色的 invoke | **按原话执行是假修复**：同一批身份还握着密钥读取、`lambda:UpdateFunctionCode` 与 `iam:PutRolePolicy` |

  **v4 漏掉的那条路（比 invoke 更轻、更广）**：冒充任意用户**不需要**
  `lambda:InvokeFunction`。密钥有两条只读路径可得，两条都实测可用：

  1. `lambda:GetFunction` 下载 Edge origin-request 函数的部署包——密钥是**明文**
     在 `index.py` 里（Lambda@Edge 不支持环境变量，CDK 部署时字符串替换注入）。
     实测：包里有且仅有一处 `JWT_SECRET = "<64 字符>"`，其值与 SSM 参数**逐字节相同**
     （比对 SHA-256，未落盘明文）。**不经 KMS**，且 AWS 托管策略 `ReadOnlyAccess`
     就带这个动作（模拟器的 `MatchedStatements` 直接指向 `ReadOnlyAccess`）。
  2. `ssm:GetParameter` 读那个 SecureString。**KMS 这一道是虚的**：参数用
     `alias/aws/ssm`，该托管密钥的 key policy 是
     `Principal:{"AWS":"*"}` + `kms:CallerAccount` + `kms:ViaService=ssm.*` 的
     **直接授权**（已读 key policy 核实），identity policy 里不需要任何 `kms:*`。

  拿到密钥即可为任意 email 签出真实会话 cookie（走正常 HTTPS 进来，Edge 验签会通过）
  与 `scope=console` 的面板会话 ⇒ **读面与写面一起失守**。
  ⇒ 「M09 写面与 M05 耦合」这个判断方向是对的，但耦合点不是 M05 的 `typ` 校验，
  而是**密钥可得性**本身。

  **一条正面结论（v4 没测）**：平台自己那 6 个角色的 invoke 权限都**精确到单个
  函数**——Edge（平台+站点）、deployer exec（**只有**站点函数）、Step Functions
  （只有步骤函数）、panel 与 MCP runtime（**各只有** `site-deployer-undeploy`）、
  auth（不能 invoke）。所以平台侧没有可收窄的东西，暴露面 100% 来自平台之外。

  **本条的落地（M09 第 2 步的重定义）**：
  - 写准风险模型 → `docs/security/account-trust-boundary.md`（**已做**）；
  - 可执行的部分 = 一道**漂移闸门**
    `site-builder/scripts/verify_account_trust_boundary.py` + 仓库内基线
    （只存 ARN 指纹，不含账号值）：新 principal / 新能力即红，Edge 或 deployer
    丢掉必需 invoke 也红（防「收窄」把平台自己锁死）。**已做，已对生产跑绿，
    并做过两种变形证明它真能红。**
  - ~~收窄那 12 个角色~~ → **不做**，理由见上（假修复，且属账号治理不属本仓库）；
  - ~~建专用低权限 role 跑 direct invoke 负向探针~~ → **不做**。v3 设计那条探针的
    前提是「收窄之后 invoke 会被拒」；既然不收窄，该探针断言的是一个不成立的命题，
    跑绿也只证明「一个本来就没权限的 role 没有权限」。漂移闸门覆盖的是真问题。
  - **唯一真修复**：把平台迁到独立的 Organizations 成员账号（独立设计包，未排期）。

- **v5 的自我更正（同日，Codex 对首版实现复审后。v5 的数字是错的，"唯一"也过绝对）**

  Codex 复审首版闸门（commit `e79a230`）报了两条 P1 与一条 P2，**三条都成立**，
  已逐条实测复现。更正后的完整结论在 `docs/security/account-trust-boundary.md`
  （那份是真源，本节只记差异）。

  | v5 说 | 更正后（实测） |
  |---|---|
  | 密钥有**两条**路可得 | **三条。** 漏掉的是 **CDK bootstrap S3 asset** |
  | 41 个 principal 具备敏感授权、35 个能拿到密钥 | **62 / 56**（漏掉的 21 个只在 asset 那条路上）；第二次复审更正为 **63 / 57**（漏了 `ssm:GetParameters`）；第三次复审更正为 **66 / 57**（IAM 写只对着字面量 `role/*` 模拟） |
  | 「唯一真修复是迁独立账号」 | 太绝对。迁账号是唯一能移出**管理身份**的办法，但「只读级工作负载能窃取密钥」这条在**现账号内**可以用**非对称签名**关掉（KMS `kms:Sign` + Edge 只放公钥）；代价见那份文档 |

  **漏掉的第三条路**（`router/infrastructure/stack.py` 先把明文替换进 `index.py`，
  随后把该目录交给 `lambda.Code.from_asset()`）：产物同时是一个 CDK file asset，
  被上传到 `cdk-hnb659fds-assets-*` 桶。实测（asset 位置从**已部署的
  CloudFormation 模板**取，不手抄对象 key）：

  - 对象里的密钥与 SSM 值**逐字节相同**（比对 SHA-256）；
  - 桶策略只有一条 Deny 非 TLS，没有任何限制读取的语句；
  - 对象用 `alias/aws/s3`，该托管键 key policy 是 `Principal:*` + `ViaService=s3`
    的**直接授权** ⇒ identity policy 里不需要任何 `kms:*`；
  - 旧 asset 不删、密钥从未轮转 ⇒ 桶里 **9 个**对象仍带着当前有效密钥
    （最早 2026-07-28）。轮转密钥必须连带清理它们。

  **一条新的、比 M09 更贴近核心威胁模型的发现**：跑**不可信站点依赖安装**的
  CodeBuild 角色（`site-package`）拿到了整个 bootstrap 桶的读权限——不是本仓库写的，
  是 CDK 给 `BuildSpec.from_asset()` 自动加的（buildspec 本身也是 asset）。于是
  「站点作者」与「平台签名密钥」之间当前只隔着 `buildspec-package.yml` 里的
  `npm install --ignore-scripts`（外加先删站点自带 `.npmrc`）。今天不可达，
  但那条 flag 是唯一的隔断，而站点 `package.json` 由 AI 生成、owner 可任意改。
  **这条可以单独收窄，不必等账号迁移。**

  **闸门实现的三处修正（Codex P1-2 成立）**：
  - 授权原先压成布尔标签（`invoke-platform`），于是「某角色原来只能调
    `site-deployer-undeploy`、现在还能调 `site-panel`」这种资源扩权**全绿**。
    改成 grant 串（`invoke-platform:<函数名>`）后该变形立刻红（已端到端验过）。
  - 原先没看 **Lambda resource policy**（`SimulatePrincipalPolicy` 不自动纳入它，
    对 role 更是不支持模拟），也没看 **alias**——而 M7 之后站点的 Function URL 与
    授权语句都挂在 `blue` 上，M7 后新建的站点未限定 policy 根本不存在。都补上了。
  - `MissingContextValues`（实测 162 个 principal）不再被静默压成"无权限"：
    计数进基线并打印，同时在文档里写明这道闸门**不是** fail-closed 的。

  修正后的闸门对生产跑绿（约 5 分钟），并用四种变形验过该红/该绿：资源扩权、
  平台 resource policy 新语句、站点 policy 偏离，以及「asset 不再含活密钥」时
  **21 个 principal 退出暴露面并报成改善**（即：单独修 asset 这一条路，
  暴露面就从 62 降到 41）。

- **第二次自我更正（同日，Codex 对重建版复审后。数字又错了一次，41→62→63）**

  Codex 复审 `f4c3fd1` 报了四条 P1 与一条 P2，**五条全部成立**，已逐条实测复现。
  真源仍是 `docs/security/account-trust-boundary.md`；本节只记差异与根因。

  **根因是同一个建模错误犯了第三次**：把一种「能力」写成**单个 API 动作 / 单个
  资源**。三次的形状完全一样，只是压平的那一维不同：

  | 压成了什么 | 漏掉了谁 | 发现于 |
  |---|---|---|
  | 只探未限定函数 ARN | 挂在 `blue` alias 上的授权 | 第一次复审 |
  | 只探当前那一个 CDK asset | 带同一把活密钥的 9 个历史对象 | 第一次复审 |
  | 只探 `ssm:GetParameter` | 一个**只**被授予 `ssm:GetParameters`（复数）的角色 | 第二次复审 |

  逐条：

  1. **SSM 读是一个动作类，不是一个动作**（当前就在触发）。实测四个动作在这个
     参数上的 allowed 数：`GetParameter` 27 / `GetParameters` 26 /
     `GetParametersByPath` 18 / `GetParameterHistory` 18，**并集 28**。其中一个角色
     只有复数那个（`Resource:*` 显式 Allow、无 boundary、`WithDecryption=true` 即可
     读出明文），首版把它整个漏掉 ⇒ 数字从 62/56 更正为 **63/57**。
  2. **9 个历史 asset 只被计数、没被模拟**。现在全部进 `Targets`，并把
     `s3:GetObjectVersion` 加进动作类——桶开着版本控制（noncurrent 保留 30 天），
     对象删掉之后旧版本仍可按 version ID 读到。
  3. **限定符与版本被压平**。`invoke-platform:foo` / `@alias:foo` / `@version:foo`
     现在是三条不同的 grant。另外发现一个我自己的残留盲区：两个 Edge 函数属于
     **router 栈**，不在 deployer 栈的 `PLATFORM_FUNCTION_NAMES` 里，所以首版
     **完全没看它们**——Edge 的 9 个已发布版本一个没枚举，「谁能读旧版本 Edge 代码
     （里面就是明文密钥）」与「谁能 `UpdateFunctionCode` 换掉 Edge」都在视野外。
     现在两者纳入，含 version 9 上那条版本级 resource policy。
  4. **站点 legacy 形态被全局白名单化**：一个**全新**站点退回 legacy 也全绿。
     改成**点名豁免**（当前 6 个存量站点），豁免只能缩小。
  5. **平台侧的授权丢失被判成绿/改善**。`platform` 类现在按**集合等值**比——
     Codex 的最小反例（Edge 丢掉 `invoke-platform:site-panel` 但保留 key-proxy）
     和「平台函数少一条 Function URL 授权语句」现在都红。
     `platform-overbroad` 保持不对称（它就是要缩小的那一类）。
  6. **P2**：`MissingContextValues` 现在同时读顶层与 `ResourceSpecificResults`
     （真实响应里常常只出现在后者），且 facts 出 delta。
     **仍不影响退出码**——这个数随账号里任何一条带 Condition 的新策略变动，
     让它决定红绿会训练出"红了就更新基线"。Codex 明确允许这个取舍。

  重建后：45 条守卫（每条 finding 各有只命中新成员的用例）；生产实跑绿、退出码 0、
  约 9 分钟；五种变形端到端验过该红/该绿。**可量化的中间修复**：只把 CDK asset
  那条路修掉，21 个 principal 整个退出暴露面（63 → 42），可读密钥 57 → 36。

- **第三次自我更正（同日，Codex 对第二版复审后。数字 62→63→66）**

  Codex 报一条 P1 + 两条 P2，**三条全部成立**，已逐条实测复现。真源仍是
  `docs/security/account-trust-boundary.md`。

  **P1 又是同一个建模错误，这次错在资源那一侧**：`self-escalate` 的四个动作统统只
  对着字面量 `arn:aws:iam::<acct>:role/*` 模拟。IAM 里请求资源是具体 ARN，policy 的
  `role/ExactRole` 不匹配字面量 `role/*` ⇒ 精确授权全部隐形；而
  `iam:CreatePolicyVersion` 的资源类型根本是 **policy** 不是 role。
  实测：**22** 个 principal 持有这些动作，其中 3 个在基线里缺 grant、3 个完全不在
  基线里 ⇒ 总数 63 → **66**（Codex 报的是 4/2，实际更多）。

  改法：这一类改走**两步**——静态解析全部 identity policy 发现候选（通配展开、
  `Allow`+`NotAction` 保守算命中；**已用正对照核过静态解析是模拟器结果的超集**，
  `role/*` 找到的 16 个全部落在 22 个里），再用模拟器对**具体** ARN 确认，
  资源按动作的资源类型落。判定**三值**：`:any` / `:scoped` / `:condition-gated`。
  第三值是自己补的：实测某角色的 `AttachRolePolicy` 被 `iam:PolicyARN` 限定到两个
  无害的 AWS 托管策略，模拟器给 implicitDeny + 缺 `iam:PolicyARN`——那是"判不出"。
  把它当"没有"会让这个 principal 连基线都进不去，条件哪天放宽也没人看见。
  grant 也从 `self-escalate` 改名为 `iam-policy-write`：持有一个 IAM 变更动作
  **不等于**存在完整提权链（还要看 AssumeRole/PassRole/附着目标/boundary），
  那是可达性分析，本闸门明确不做。

  **P2a（alias/version 类内部成员不可见）**：一半接受一半按不同方式做。
  - **接受并修**：站点 resource policy 的 alias 改**逐成员**比。原先并起来比，
    「active 色丢了授权、inactive 色还留着」相加仍等于规范集合 ⇒ 全绿。
    已核 blue/green 切换后旧颜色的 alias/URL/两条语句都保留（没有任何代码删它们），
    所以逐成员不会误报。版本级保持**子集**检查——AWS 的 replicator 语句只在当前
    Edge 版本上，逐成员等值会把 version 1..8 全报成缺语句。
  - **不按其处方做**：identity 侧的 `@alias` / `@version` 保持**存在性类**
    （blue 与 green 不分）。理由：对"能不能冒充任意用户"，经哪个颜色碰到代码是等价的；
    按颜色分开记会在每次切换时产生漂移却不带来安全信号。已按 Codex 的另一个选项
    在文档里**明确写成存在性类**，并点名颜色级完整性由谁负责。
  - **顺带记一条观察**：切换后旧颜色的 Function URL 与授权都留着，
    "以为已经换掉的代码"其实仍可被 Edge 调用。不扩大身份边界，但容易误判。

  **P2b（站点子集按数量聚合）**：接受并修。`some(k)` 改成 `some(k):<成员指纹>`
  ——只记数量时「失去 site-a、新增 site-b」前后都是 `some(1)`。指纹只覆盖被允许的
  站点，所以新建一个它碰不到的站点不产生漂移。

  验证：62 条守卫；生产实跑绿、退出码 0、约 11 分钟；三种新变形端到端验过
  （条件放宽 → 红、某颜色丢 alias 语句 → 红并点名颜色、子集换成员 → 红）。

- **第四次自我更正（2026-08-25，闸门收缩轮。这一次改的不是数字，是闸门的职责边界）**

  前三次更正都在补漏（动作类、资源类），补完仍被复审推翻。**根因不是每次差一行，
  而是一个 `grant` 模型被要求同时证明三件事**：①谁能直接失守（集合成员问题，模拟器
  对具体资源可靠）、②IAM 策略有没有变（压成"谁能提权"就等于要造一个 IAM 权限
  分析器：statement 归因、Condition 语义、NotResource 集合代数、policy variable、
  `SourcePolicyType` 碰撞——每修一维下一维才暴露）、③平台还通不通（liveness）。
  一个模型证明三件事，就必然在其中一件上过强。

  所以这一轮**收窄承诺、拆开职责**：

  | 层 | 声明 | 明确不声称 |
  |---|---|---|
  | **A**（headline） | identity policy 层面「能直接失守」的集合没变大；敏感资源的 resource-based policy 无漂移 | 条件语义、跨账号 principal、临时角色、不看 S3 access point |
  | **B** | 账号内**可能影响 IAM 策略变更动作的语句集合**（Allow **与 Deny**）+ 各 principal 的 boundary 没有任何变化 | 语句是否生效、是否构成提权链、变化方向是收紧还是放宽 |
  | **C** | —— **移出本闸门**，归「部署验收」（见 §9） | 站点 route / alias 可达性 |

  **B 整层是净删代码**：模拟器探针、statement 归因、三值（`:any` / `:scoped` /
  `:condition-gated`）、`concrete_target`、NotResource 方向推断全部删除，换成
  **纯静态文本快照**（逐条语句归一化后只存指纹，任何 added/removed/changed 都红）。
  `iam-policy-write` 从 A 的 grant 词表移除 ⇒ **A 的 headline 从 66 变成 62**，
  B 的 22 单独呈现；A ∪ B 仍是 66，但**那个并集不再是 headline**——把"持有一条
  未证明可提权的 IAM 写语句"与"现在就能拿密钥"相加当成一个风险数字，正是要消掉的错误。

  **顺带修的两条 fail-closed**（原先只有 boundary 想到了，普通 attached 是两套宽严）：
  attached 托管策略文档缺席不再静默跳过（跳过整份 policy 的输出与"这份策略没有相关
  语句"一模一样）；`DefaultVersionId` 未知不再拿占位值兜底写进基线。

  **一条实测推翻了自己的处方**：复审要求"顶层 `MissingContextValues` 归给该 action 下
  全部非 allowed 资源"。照做实测产生 **9985** 条 coverage 成员（基线涨 10 倍）。
  再探 40 个 principal / 78 条 `EvaluationResults` 才看清：AWS 把顶层缺的键**机械地
  复制进每一个逐资源条目**，键集完全相同，而缺的是 `aws:ResourceAccount` /
  `aws:CalledViaLast` / `iam:PassedToService` 这类**请求上下文**键——**资源那一维零
  信息量**。于是改成"不确定均匀时折叠成 `unattributed`、键集在资源之间不同时才逐资源
  记"，**774** 条，且反查 100% 可解释（覆盖 162 个 principal，与
  `principals_with_missing_context` 完全吻合）。

  **闸门本身不降低任何风险**——它只保证暴露面别再静默变大。所以这一轮之后立刻转
  真修复，顺序见 §9：收窄 CodeBuild 对 bootstrap 桶的读权限 → 非对称签名 → 独立账号。

  验证：双跑 `--dump-observed` 逐分节一致（确定性）；schema 2→3 一次性迁移后生产实跑
  退出码 0、实测 9.5–10.5 分钟；文档 14 个带标记数字全部由基线断言。
  **守卫条数与变形结果不写在这里**（会过时）：跑
  `site-builder/deployer/.venv/bin/pytest tests/test_verify_account_trust_boundary.py -q`
  与 `site-builder/scripts/metamorphic_trust_boundary.py` 即是最新结果。

### M10 · [P2] `--mcp-callback` 文档零出现，且裸重跑会吊销它

- **代码位置**：`site-builder/scripts/deploy_pool.py:686`
  （`--mcp-callback`，`action="append"`, `default=[]`）;
  `client_configs` 约 `:166` 构造 `[MCP_LOCALHOST_CALLBACK] + extra`;
  `_client_update_params` 约 `:511` 以整体替换语义合并;
  `:428-436` 为 `SupportedIdentityProviders` 加了显式保留，
  **`CallbackURLs` 没有**。
- **验证**：`grep -c "mcp-callback" site-builder/DEPLOY.md` = **0**。
- **后果**：DEPLOY.md 要求 mcp app client 的 `CallbackURLs` 含 AgentCore
  回调，但唯一机制是一个从未出现在任何文档命令里的 flag；
  且任何裸重跑（DEPLOY.md 有 4 处，其中一处还写着「幂等，重跑它是安全的」）
  会把带外加进去的回调**吊销**。
- **说明**：这修正了我先前一句话——「Cognito URL 整体替换 ⇒ 没有无上限追加」
  对**追加**成立，但整体替换本身对「合法存在带外成员的列表」是**吊销风险**。
- **来源**：子代理 rev-deploy-supply；`:686` 与 grep 计数我已复核，
  `:166/:428-436/:511` **未逐行复读**。

### M11 · [P2，潜伏] 无守卫绑定 Edge 的 `{{PLACEHOLDER}}` 集合

占位符定义在 `router/infrastructure/lambda/origin_request.py`（9 个），
替换在 `router/infrastructure/stack.py:232-240` 手工维护，
单测又在 `router/infrastructure/lambda/test_edge_access_log.py:11-24`
维护第三份 `_SUBS`。**没有任何断言把三者绑定**。新增一个占位符、只记得改
`_SUBS`，就会把字面量 `{{...}}` 部署上去；对布尔开关而言字面量为假
⇒ 安全控制静默关闭。当前 9 个都齐，且 `require_idp_claim`/`trusted_idps`
在 synth 期有硬校验（`stack.py:210-231`），所以是潜伏项。

### M12 · [P2，潜伏] `SYNTH-ONLY-PLACEHOLDER` 仍可部署

`router/infrastructure/stack.py:76-83`：SSM 读失败只打 stderr warning 并返回
`"SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"`，模板照样可部署。部署出去 ⇒
全平台会话验签失败，而 Edge 回滚要 10-20 分钟全球复制。
应改为**硬失败**，仅在显式 opt-in（如 `SB_SYNTH_ONLY=1`）时才允许离线 synth。

### M13 · [P2，潜伏] IdP 信任清单两份 config，校验强度不对称

- `router/config.ini` 的 `[SiteBuilder] trusted_idps` → Edge：synth 期硬校验
  （`stack.py:210-231`，拒行内注释、开关为 true 时不许空）。
- `site-builder/config.ini` 的 `[IdP] provider_name` → MCP 的 `TRUSTED_IDPS`
  （`site-builder/mcp/deploy_agentcore.py:604`）：**零校验**。
- `site-builder/mcp/server.py:752-761` 用 `if trusted:` 包住检查，空值时
  **同时跳过** `idp` 与 `auth_via` 两道（后者是拦原生 InitiateAuth token 洗白的那道），
  而 `site-builder/mcp/tests/test_agentcore_contract.py:195` 把
  「空 = 放行」**钉成**了「迁移宽限期」的预期行为。
- 「两侧必须一致」目前只写在 `router/config.ini.example:108` 的注释里，无可执行守卫。
- 已实测当前两侧一致（均为单一 provider），故为潜伏项。

### M14 · [P3] 站点后端依赖未锁定（Codex P2-1）

`site-builder/deployer/buildspec-package.yml:13` 用 `npm install`（非 `npm ci`）；
`find site-builder/fixtures -name package-lock.json` 为空；
`package-lock` 在 contract 与 skills 下零命中。**同一份上传字节在不同时间可装出不同依赖树。**

- **跨租户影响为零**（站点本身已隔离），真实代价是：
  ① 事后无法回答「当时线上跑的是哪份代码」；
  ② 与平台自己的强不变量矛盾——validate 用 S3 `IfMatch` 钉住上传字节
  （`validate.py:120-129`，注明「校验与构建必须是同一份字节」），
  然后构建期把依赖放开，于是保证止于用户自己那部分代码，**不覆盖真正上线的产物**。
- **对 Codex 处方的异议**：不要在合同里强制 `package-lock.json`。
  生成方是 Agent，它无法凭空产出有效 lockfile（必须由 npm 对着 registry 解析），
  这会打断平台的核心用法，且 5 个 fixture 全要重造。
  **改为**：把 `npm install` 解析出的依赖树/lockfile 作为**构建产物持久化**，
  并在 `package.json` 未变的更新部署里复用它。这样拿到取证可复现与重复部署稳定，
  又不给生成方增加负担。

  **实现约束（v3，Codex 补，接受）**：复用的前提是把持久化的 lock 绑定到
  一组完整的键，否则「复用上次 lock」自己会变成另一个可替换输入：
  - 归一化后的 `package.json` hash
  - Node 版本、npm 版本
  - registry policy / host
  - lockfile 自身的 hash

  且必须存放在**只有构建控制面可写**的不可变位置（现有
  `artifacts/*` 的 PutObject 授权范围要一并收窄，见我在 §6 里对
  CodeBuild 角色的记录）。
- 相邻观测（子代理 rev-isolation）：lockfile 的 `resolved` URL 可指向任意 tarball——
  这条在「持久化并复用 lockfile」之后才变成需要考虑的问题，届时应校验 registry 主机。

### M15 · [P3] 访问趋势陈旧响应覆盖（Codex P2-2）

- **代码位置**：`site-builder/panel/frontend/app.js:1265`（`trendPref` 模块级）、
  `:1274`（发请求时读 `trendPref.q`）、`:1279/:1280/:1290/:1293`
  （**响应回来时又读一次**，用于标题、按月/按日文案、按钮 pressed 态）、
  `:1439-1440`（换档位时先改 `trendPref.q` 再重入）。
  无 AbortController、无 generation、无 site 比对、无 in-flight 检查。
- **两种表现**：① 慢的 90 天响应可以渲染在「近 7 天」标题 + 7 天按钮选中之下；
  ② 请求在途时切站点，陈旧响应仍写进 `panel.innerHTML` ⇒ 甲站点的流量显示在乙站点页面。
  后者不是越权（两个站点用户都有权看），但在审计场景里是误导。
- **有比 Codex 更省的修法**：接口已经回显 `period`
  （`site-builder/panel/api.py:470` 返回 `{"period": period, "series": ...}`），
  **用响应里的 `period` 出标题与选中态**即可修掉错档位，一行；
  generation 守卫只需为跨站点覆盖那半加。AbortController 两者都不需要。

### M16 · [P3] `migrations/` 子目录的 SQL 被执行但不被扫描

- **校验方**：`site-builder/contract/src/contract/redlines.py:364-366`
  用 `migrations.glob("*.sql")`（**非递归**）。
- **执行方**：`site-builder/deployer/functions/provision_dsql.py:156-161`
  用 `list_objects_v2(Prefix=".../backend/migrations/")`（S3 前缀 = 递归），
  并按 `PurePosixPath(key).name`（**basename**）匹配。
- 于是 `backend/migrations/sub/001_foo.sql` 会被执行、但从未被扫描。
  这是本仓库已在别处关掉的「校验/执行差异」类（zip 落盘路径归一化、ETag 钉字节），此处仍开着。
- 红线**不是**安全边界（见 §6），所以直接影响是「站点自己 schema 内的 lint 被绕过」；
  但它会让 DSQL 不兼容语句推迟到执行期才失败，**正是 M03 永久 brick 的触发条件**。
- **附带**：`applied` 按 basename 记录 ⇒ `migrations/a/001_x.sql` 与
  `migrations/b/001_x.sql` 撞车，其中一个被当成「已执行」**静默跳过**。
- **修复方向**：执行方拒绝 migrations 前缀之后仍含 `/` 的 key（保持合同收窄），
  比放宽扫描器更好；或让扫描方与执行方共用**同一个受测试约束的选文件函数**。
- **附加验收条件（Codex 补，成立）**：`provision_dsql.py:157` 的
  `list_objects_v2` **没有用 paginator**。当前扁平 `NNN_*.sql` 命名下编号上限
  有限，但嵌套目录 + basename 碰撞本来就是不受控输入，
  所以这一条要一起收——否则将来放宽文件名规则时会变成**静默截断**（漏跑迁移）。
- **与 M03 的联动**：若采纳 M03 的「强制 `IF NOT EXISTS`」，
  本条必须一起修，否则子目录里的 SQL 照样绕过该强制。

### M17 · [P3] 两份 `.example` 对同一个桶用了不同约定

`router/config.ini.example:91` 硬编码 `frontend_bucket = site-frontend-123456789012`
（AWS 文档用的占位账号），而 `site-builder/config.ini.example:33` 是
`site-frontend-{account_id}` 模板。无任何交叉校验；`stack.py:138` 不校验；
而 `verify_deployed_components.py` 读的是 **site-builder 那侧**的值，
结构上看不见 router 侧写错。症状是每个静态资源 403——正是文档自己
警告过「私有桶上 403 不等于 404」的难诊断类别。

### M18 · [P3，已接受风险] 未登录请求也写埋点行

> **v2**：Codex 建议标为「已接受风险」而不是新 defect——它与既有的
> 成本/DoS 取舍重叠，不应重复计数。**接受**。保留在册但不计入修复队列，
> 除非账单出现异常。

`router/infrastructure/lambda/origin_request.py:214-217` 在 `_check_auth` 之后
仍调 `_maybe_record`，`:173-180` 对 302 分支写 `decision="redirect_login"`。
于是任意公网客户端可对任意 `app-` 站点的页面路径驱动**每请求一次** DynamoDB
PutItem（回落时还是跨区），无限流、无采样、无去重；行带 90 天 TTL；
异常按设计吞掉 ⇒ 量与账单从应用侧不可见。

### M19 · [P3] `_ROUTE_CACHE` 无上界且缓存 miss

`origin_request.py:31-32` 的字典无容量上限、无淘汰（过期项只在再次查询时被覆盖），
`_lookup_route` 在 miss 时也写入 `(expiry, None)`。分发挂着
`*.{base_domain}` 别名 ⇒ 攻击者可用无限个不同子域名把字典撑大，
每个新标签还附带一次 DynamoDB GetItem。来源：子代理 rev-edge-auth，机理我已复核。

### M20 · [P3] dev 脚本可静默接管 owner

`site-builder/scripts/deploy_fixture.py:162` 以无条件 `SET owner, name, status`
写 sites 行，绕过 `create_site_record` 专门用来防止静默接管的
`attribute_not_exists(site_id)` 条件（`common.py:176` 附近有该理由的注释）。
仅 dev 用，但它读 `config.ini`，可以指向生产表。
来源：子代理 rev-bluegreen，**我未复读该文件**。

### M21 · [P3] 模板↔fixture 字节一致无守卫

`CLAUDE.md` 把「模板与 fixture 字节一致」列为改合同时的要求，但任何测试或脚本
都不引用 `templates/`。子代理 rev-contract 逐对 diff 过 5 组，当前一致——
即无缺陷、但无守卫，与 M11 同类。

### M22 · [P3] 文档/配置漂移

- `site-builder/config.ini.example:83` 的 `[Alerting] email` 出厂为空，而
  `site-builder/auth/alarm_pipeline.py` 在其为空时抛 `ValueError`
  （`deploy_auth.py` 会走到它）；§0 的就绪清单没列这个键。响亮失败、文案清楚，**改清单不改代码**。
- `[Panel] ops_log_table`、`[Panel] session_codes_table`、`[ApiKey] keys_table`
  三个键**无人读**——`site-builder/panel/deploy_panel.py:307-317` 把表名写成字面量。
  运维改这些值会静默无效。（我的 config 校验只做了「代码读的都有文档」这一向，
  反向的三个死键由 rev-deploy-supply 指出，我已用 grep 复核。）

### M23 · [P3，风险而非缺陷] 埋点跨区回落路径线上从未执行

子代理 rev-analytics 拉 Logs Insights（2026-08-14→08-21）：
ap-northeast-1 侧 97/97、us-east-1 侧 62/62 全部同区解析，
**0 次回落、0 条 `[WARN] 访问埋点失败`**。而那条 719ms 冷启回落路径
决定了整个 1.0s/2.0s 超时预算，且预算作用在 origin-request 里、
挡在每个站点每次页面加载前面。它目前只有「把 client patch 掉」的单测覆盖。
真触发时（区域故障，恰好最需要它的时刻）跑的是一条端到端从未验证过的路径。
既然埋点明确不是安全控制、丢行本就可接受，最省的降险是让它**不阻塞请求**。
（本条数据我未自行复跑 Logs Insights。）

---

## 5. 已撤回 / 已修正的结论（请 Codex 一并核对）

1. **撤回**：「站点可通过 site.json 覆盖平台注入的环境变量」。
   我先前据 `deploy_lambda_site.py:166`（`**event.get("env_vars", {})` 在
   平台三个 LWA 变量**之后**）判定站点可覆盖 `PORT` /
   `AWS_LAMBDA_EXEC_WRAPPER`。**这是错的**：`env_vars` 全仓库只出现 3 处，
   且都是平台**生产**方——`provision_dynamodb.py:24` 写
   `TABLE_{name.upper()}`、`provision_dsql.py:170-172` 写 `DSQL_*`，
   在 `:166` 被消费。合同 schema 里没有任何 env 字段。
   连碰撞都构造不出来：声明一张名为 `port` 的表得到的是 `TABLE_PORT`。
2. **修正 M04 的证据强度**：见该条「证据边界」。我先前说「已机械确认」过强。
3. **修正 M05 的两处**：先前既**漏了**链式续期，又**高估了**当前可利用性
   （说它「在其生命周期内就是有效站点会话」，而当前 `require_idp_claim=true`
   下 Edge 会挡住）。两个方向都错。
4. **修正一句**：「Cognito URL 整体替换所以安全」只对「无上限追加」成立，
   对带外成员是吊销风险（见 M10）。

### v2 新增的自我更正（Codex 复核后）

5. **M09 判错**：说「panel 那半已被 `caller_is_edge` 挡住」。
   根因是**截断的读取**——只 grep 了函数体，漏了上方 19 行模块 docstring，
   而那段专门写了「不要推论成已经没有绕过路径了」。已恢复 P1。
6. **M01 处方不足**：「拒绝 fullmatch `SITE_ID_RE` 的名字」拦不住
   `foo-k3d9x1-longname` 这一族（已实测）。已改为精确 ARN 枚举。
7. **M04 推理有错**：我说 `logo(1).png` 在两种编码语义下都会坏，
   漏算了**S3 侧也会把裸 `(` 编码成 `%28`** ⇒ 两侧收敛。该实验不具决定性，
   整条已降为待验证假设。
8. **M05 泄漏面无依据**：「会进 CloudFront 访问日志」——router 栈里没有
   任何 CloudFront logging 配置。已删。
9. **M03 定级过重 + 处方不足**：「永久无法部署」→ P2；
   「语句级 marker」解决不了 DSQL/DynamoDB 无原子事务。已改。
10. **基线算错**：2081 → **1881**（7 个包，不是 8 个）。加法错误，差 200。

---

## 6. 已验证为无问题的区域（避免重复投入）

以下均为本轮实际读码/实跑后的结论，其中带 †的由我与子代理**独立两次**得到同一结论。

- **无 fail-open 到站点 origin †**：`origin_request.py` 全部 `try/except` 与
  带默认值的 `.get()` 终点都是 500 / 404 / 403 / 302；
  `require_auth is False` 是唯一的免鉴权放行，且要求显式 DynamoDB `BOOL`。
- **Host 解析不能选错路由行 †**：大写标签打不中大小写敏感的分区键 ⇒ 404；
  端口后缀、结尾点、userinfo `@` 都不改变 `split(".")[0]` 或过不了 CloudFront 别名匹配。
- **OAuth 流**：`_is_safe_redirect` 显式拒反斜杠、锚 scheme 与 host 后缀，
  且在 `/login` 与 `/callback` 两处都调用；PKCE verifier 与 nonce 放
  `__Host-` host-only cookie 并带类型标记；`email_verified` fail-closed。
- **`caller_is_edge` 仅对 Path B 有效（v2 更正）**：v1 把它列为「已验证无问题」
  是**错的**。它只在**经 Function URL**（SigV4）调用时拿到可信输入；
  直接 `lambda:Invoke` 时调用方构造整个 payload、连 `callerId` 都能伪造
  ⇒ 天然被绕过。见 M09。它在 Path B 上的实现本身是严谨的
  （按 `:` 边界比、不用 startswith/in、缺配置即全拒），这一点仍然成立。
- **on-behalf 信任链**：`mcp/server.py:719-781` 先看 token 自带的 email claim，
  只在**没有** email claim 时才看 on-behalf 头；`:84-127` 要求
  `MACHINE_CLIENT_ID` 非空 + `compare_digest` 比对 client_id +
  `EMAIL_RE.fullmatch`。key-proxy 侧 `_outbound_headers`
  （`key-proxy/handler.py:178-198`）**从零按白名单构建**出站头，
  刻意不透传 `x-sb-on-behalf-of`，且「我们加的两个头」与白名单循环分开写
  ——比「先复制再剥除」强，任何大小写/重复变体都无法存活。
- **9 个 MCP 工具全部有鉴权**：4 个直接 `_assert_permission`；
  `confirm_upload`/`get_deploy_status` 先解析 job 再对其 site 断言；
  `list_my_sites` 按分区键取（不是查回来再过滤）；
  `update_site_permissions`/`manage_collaborators` **刻意不预先鉴权**——
  判定在 `permissions.write_permissions` 内与 rev 同源完成，避免
  「鉴权通过后权限被撤销、写入仍成功」的 TOCTOU（`server.py:635-637` 有论证）。
- **panel 六步前置**：`caller_is_edge` → `x-user-email` → CSRF → `__Host-sb_console`
  （验签 + `scope==console` + email 与 Edge 注入值一致）→ 路由 → 副作用；
  每个读端点都有 `assert_can`；`do_resync` 看似无守卫，但 admin 判定在
  `permissions.resync_route:756` 内。
- **一次性升级码的消费**：`console_session.py` 先验签 → 再比对 email → 再条件写消费 jti。
- **归档处理**：ETag 钉住「校验字节 == 构建字节」；条目数/解压尺寸/压缩比上限；
  zip-slip；按落盘路径归一化后拒重名；Python `zipfile` 不还原符号链接。
- **API Key**：`_shape_key` 是白名单且永不返回 `key_hash`；
  `list_for` 按 `email-index` 分区取；revoke 对「不存在」与「不是你的」
  返回同一句文案（防 key_id 枚举）；总开关两个 writer 都写**真布尔**
  （`keystore.py:502` 的 `isinstance` 在 `:506` 的 put_item 之前；
  `deploy_key_proxy.py:530` 写 `False` 且带 `attribute_not_exists` ⇒ 只建不改）。
- **统计聚合 †**：rollup 幂等（`_put_daily` 是重算后的无条件覆盖，
  `verify_analytics_e2e.py` 用「跑两次断言不变 + 删一行断言下降」在真机证明）；
  5 处 Query/Scan 全部按 `LastEvaluatedKey` 分页，唯一设上限的读**抛
  `ReadTooLarge`** 而不是返回短结果；日界两侧都是 UTC 且前端标注；
  迟到行由 7 天重算窗口吸收；`path`/`email` 在
  `panel/frontend/app.js:1510-1511` 经 `esc()` ⇒ 控制台无存储型 XSS。
- **CodeBuild 无攻击者代码执行**：`--ignore-scripts`、删 `.npmrc`
  （`buildspec-package.yml:7,9`）、runtime 限 `nodejs22.x`、
  site.json 没有 build 命令被调用；CodeBuild 角色只有
  `validated/*` 的 GetObject 与 `artifacts/*` 的 PutObject，无 ListBucket、无 DeleteObject。
- **站点拿不到平台密钥**：boundary（`app.py:298-309`）里没有任何
  ssm / secretsmanager 语句，也没有非 `site-data-` 前缀的表；无 `s3` ⇒ 无法改别人前端。
- **红线不是安全边界**：只有 `validate.py` 引用 contract，无任何运行时组件查它；
  相关规则自述为纵深防御。所以其正则可绕不构成边界失效。
- **无 CORS 信任 `*.{base_domain}`**：`check_csrf` 逐字符 exact，
  panel/auth/key-proxy/edge 全无 `Access-Control-*` 头。
- **供应链（平台自身）**：所有被跟踪的 pip install 都带 `--require-hashes`；
  ECR 被主动置为 IMMUTABLE（含把已存在的 MUTABLE 仓库改过去，
  `deploy_agentcore.py:94-101`）。
- **无真实账号值落进被跟踪文件**：以当前 config 的 account_id / base_domain /
  user_pool_id 逐一 `git grep -F`，命中数均为 0。

---

## 7. 本轮**未**验证的部分（交叉确认建议优先打这里）

1. **M04 的字符类**：CloudFront 交给 Lambda@Edge 的 `uri` 是否已 percent-encoded，
   双方都没拿到权威答案。需真机跑 `logo(1).png` 那个判别实验。
2. **Codex 的复现脚本我没有实跑**，只核了它们依赖的代码事实。
3. **DSQL 的 `pg_catalog` 可见性**：站点的 PG role 能否读
   `pg_catalog` / DSQL 的 IAM role 映射，从而枚举其他租户的 schema 名与角色 ARN
   （信息泄漏，非数据访问）。需连真集群查。
4. **子代理来源、我未逐行复读的位置**：`mark_job.py:294-319,449-455`、
   `access_rollup.py:83-88,122-126,165,187-198`、`analytics.py:91-105,122-131`、
   `reconcile_job.py:98-105`、`deploy_fixture.py:162,182-205`、
   `deploy_pool.py:166,428-436,511`、`provision_dynamodb.py:24-25`、
   `schema.py:48`、`package_backend.py:23-26`、`verify_analytics_e2e.py:758-772`、
   M23 的 Logs Insights 数据。
5. **panel 鉴权只有一遍**：负责该面的子代理最终没有交付，
   所以那一层只有我自己的逐路由矩阵，没有第二意见。
6. **CDK 模板断言默认 skip**：`test_stack_edge_iam.py` 与
   `deployer/tests/test_infra_tables.py` 需显式 `SB_CDK_TESTS=1` + PYTHONPATH 桥接，
   本轮未跑（要 synth / Docker）。**被 skip 的守卫不是守卫。**

---

## 8. 交叉确认的具体问题（**Codex 已全部回答，结论见 §-1**）

> 8 个问题 Codex 都答了。第 4 题（M09）我答错、它答对；
> 第 1/2/3/7 题双方一致；第 5 题（M01）它独立确认成立并推翻了我的处方；
> 第 6 题（M03）它确认机理并正确指出定级与处方都要改；
> 第 8 题它指出的三处遗漏（M09 的错误结论、M16 的分页边界、基线不可复核）**全部成立**。
> 以下保留原问题供追溯。

1. **M02**：同意「`migrate_permissions.py:57-80` 是反例而非缺陷实例」吗？
   以及那里「属性整体缺失 ⇒ `"org"`」的理由引用的 Edge 默认已经过时
   （现行是缺失 ⇒ 空名单）——同意这是一条独立的漂移缺陷吗？
2. **M02 的处方**：同意「拒绝投影并响亮失败」优于「改成 fail-closed 空名单」吗？
   后者会让 `resync_route` 静默收紧线上站点。
3. **M05**：同意链式续期与 `require_idp_claim` 无关（因为 `auth` 子域
   `require_auth=False`），而该开关只决定「能否当站点会话」吗？
   据此同意整条降为 P2 吗？
4. **M09**：同意场景 A 已被 `edge_caller.caller_is_edge` 挡住、
   只有场景 B（站点 Lambda）成立吗？同意建议 C 不应施加于站点 Lambda 吗？
5. **M01**：这条 Codex 未发现，请独立核一遍 IAM 前缀匹配与
   「先设陷阱再移交」的可行性，特别是 `role_of` 那条约束是否真的排除了
   「直接对已存在站点下手」。
6. **M03**：请独立核 autocommit + marker 时序，以及是否存在我漏看的补偿路径。
7. **M14 / M15 的处方**：同意「持久化解析结果而非强制 lockfile」与
   「用响应回显的 `period` 出标题」这两个替代方案吗？
8. 有没有本文遗漏、而你那轮覆盖过的面？特别是 panel 鉴权（见 §7.5）。

---

## 9. 建议的修复优先级（待确认后细化成 fix plan）

**v2 已按交叉确认结论重排。** 与 Codex 的最终建议一致。

| 顺序 | 条目 | 理由 |
|---|---|---|
| 0 | ~~**M09 的第 1 步**（只写文档）~~ **已做（2026-08-25）** | 产物 `docs/security/account-trust-boundary.md`。写的时候实测出比原判更坏的事实：冒充**不需要** invoke，只读级权限即可取得会话密钥，写面同样失守。见 §4 的 M09 v5 |
| 1 | **M01** | 唯一一条真正的跨租户数据读写。改为精确 ARN 枚举（**不是** v1 说的一行正则） |
| 2 | **M02** | 抵消了已经付过成本的 Edge 加固；三个 writer 统一为「判不出就拒绝投影」 |
| 3 | **M09 的第 2 步**（2026-08-25 重定义并落地，同日按 Codex 复审重建） | ~~收窄人/CI 身份策略 + direct Invoke 负向闸门~~ → 实测后判定为**假修复**（同一批身份还握着密钥读取与自助提权），负向探针也断言了一个不成立的命题。**实际落地**：漂移闸门 `scripts/verify_account_trust_boundary.py` + 仓库内基线（只存指纹），覆盖 identity 授权（逐资源，不压布尔）/ Lambda resource policy（含 alias）/ 密钥三处副本的事实；四种变形验过能红。**2026-08-25 又做了一轮收缩**（第四次自我更正）：拆成 A（直接失守，headline 62）+ B（IAM 写的纯静态文本快照，22，不做提权分析），C 移出归 3e；B 整层净删代码。**闸门已收缩至可签字版。****两条真修复见 3b/3c/3d** |
| 3b | **M09 的第 3 步：真修复 ①「收窄 CodeBuild 对 bootstrap 桶的读权限」** | **闸门不降低任何风险，所以收缩完立刻做这条。** 只少 **1 个** principal，但它跨越「不可信站点输入 → 平台签名密钥」这条威胁边界：跑站点依赖安装的 CodeBuild 角色（CDK 给 `BuildSpec.from_asset()` 自动加的整桶读）能读到 Edge asset 里的明文密钥，今天唯一的隔断是 `buildspec-package.yml` 里的 `npm install --ignore-scripts`。**是生产 IAM 改动**，动手前先把改法与验收方式过一遍。**纠正一处流传的数字**：这条**不会**移除约 21 个 principal——那 21 个是"只能通过 asset 这条路读到密钥"的其它角色，它们要消失的前提是 asset 里不再有活密钥，即下一条 |
| 3c | **M09 的第 3 步：真修复 ②「改非对称签名」** | KMS 非对称密钥 + Edge 只放公钥 ⇒ 读 Edge 代码 / 历史 asset / SSM 都不再等于能签会话，**57 个里的绝大多数一次清掉**（A 62→41 / 密钥 57→36 只是其中一部分）。独立设计包：Lambda@Edge 里没有 crypto 库（验签要自带纯 Python 实现）、登录路径多一次 `kms:Sign` 往返、密钥轮转与「站点会话 / console 会话」两类受众拆分都要重做。**建议先 spike** |
| 3d | **M09 的第 3 步：真修复 ③「迁独立成员账号」** | 才能把管理身份移出边界。做完 ①② 之后再评估 |
| 3e | **C：站点 route / alias 可达性 —— 归「部署完整性验收」，不是账号信任边界** | 从 M09 闸门里**移出**的那部分（第四次自我更正）。已探明的事实先记在这里：active color **哪儿都没存**（由路由 `api_target` 反推；生产 helper 是 `deploy_lambda_site.{COLORS,_color_urls,_live_color}`）；**不能断言两色都在**（首次部署 / 刚迁移只有 blue，static 站点无 Lambda）；alias 与 alias URL 一旦建成**永不删除**；**没有任何现有闸门检查站点 alias 存在性或 alias 上的 Function URL** ⇒ **idle 颜色被整个删除检测不到**。被否掉的思路：从 jobs 表推导「该有几个颜色」不成立（有站点 2 次成功部署却只有 blue，因为其中一次在 M7 之前）。落点应是 `verify_deployed_components.py` 或部署后冒烟，**不要**塞回信任边界闸门 |
| 4 | **M05** | 给两处 verifier（`auth/session.py` 与 Edge 内嵌那份）加必填 `expected_typ`，顺带处理 `.example` 出厂开关 |
| 5 | **M06** | 短期缓解（逐个尝试同名 cookie）门槛低、收益大；host-only 根治列入长期 |
| 6 | M07（含闸门缺口）、M08、M10、M12 | 部署期正确性；都是小改 |
| 7 | **M03 + M16** | 必须**一起**做：强制可重放 DDL 的前提是子目录不能绕过扫描 |
| 8 | **M04 的判别实验** | 无副作用的真机实验；出结果再决定是否进队列 |
| 9 | M11、M13、M17、M21 | 把手抄的不变量变成可执行守卫 |
| 10 | M14、M15、M19、M20、M22 | 卫生、文档、可观测性 |
| — | M18、M23 | 已接受风险 / 风险观察，不进修复队列 |

**共同要求**：每条修复都先写一条**会红**的用例。本仓库已记过这条教训——
安全闸门与验收脚本的测试必须反向验证过，否则「加了守卫」和「守卫不生效」
在 CI 上长得一模一样。
