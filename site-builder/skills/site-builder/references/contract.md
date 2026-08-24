# 部署合同（Deployment Contract）

部署合同是纯文件约定：产物目录结构 + `site.json` 部署清单。部署执行器只认合同，
与生成代码的 agent 无关。合同校验（schema 校验 + 代码红线扫描）在部署第一步
`validate` 阶段执行，任何一条不满足都会直接 FAILED 并返回具体报错。

## 产物目录结构

```
my-site/
├── site.json              # 部署清单（合同核心，必须在 zip 根）
├── run.sh                 # fullstack 必须；templates/run.sh 原样复制，不改内容
├── frontend/              # 静态前端（所有 tier 必须）
│   ├── index.html
│   └── assets/...         # 其余静态资源任意组织
└── backend/               # 仅 fullstack tier 出现；static 禁止
    ├── server.js          # Express 入口（Node 22）
    ├── package.json       # 依赖清单（部署时 npm install --omit=dev）
    ├── db.js              # 仅 fullstack-sql；templates/db.js 原样复制
    ├── schema.sql         # 仅 fullstack-sql；全部建表 DDL
    └── migrations/        # 仅 fullstack-sql 迭代时；NNN_描述.sql
```

- `run.sh` 是 Lambda Web Adapter 的启动脚本（内容固定 `exec node server.js`）。
  打包器强制检查 zip 根存在 `run.sh`，缺失即部署失败（static tier 不需要）。
- **`frontend/index.html` 必须存在且非空**（所有 tier，校验器强制）：站点首页由
  路由层固定取该文件，缺失时首页会永久 403。纯 API 场景也要放一个最小页面
  （例如一句用途说明），不能只放 assets。
- 打包为 `site.zip` 时 `site.json` 必须位于 zip 根（不要多套一层目录）。
- zip 上限：压缩后 ≤50MB；解压后 ≤200MB、≤2000 个文件、压缩比 ≤100:1；
  路径禁止绝对路径与 `..`。

## site.json 全字段表

| 字段路径 | 类型 | 必填 | 约束 | 示例值 |
|---|---|---|---|---|
| `name` | string | 必填 | 小写字母开头，仅含 `[a-z0-9-]`，长度 2–30（正则 `[a-z][a-z0-9-]{1,29}`）；且不得命中**保留前缀**（见下节） | `"expense-tracker"` |
| `tier` | string（枚举） | 必填 | `static` \| `fullstack-nosql` \| `fullstack-sql` 三选一 | `"fullstack-sql"` |
| `backend` | object | fullstack 必填；`tier=static` 时**禁止出现** | 见下三行 | — |
| `backend.runtime` | string（枚举） | fullstack 必填 | 目前仅支持 `nodejs22.x`（Express）；Python 记为二期 | `"nodejs22.x"` |
| `backend.entrypoint` | string | fullstack 必填 | 非空字符串；启动命令 | `"node server.js"` |
| `backend.port` | number | fullstack 必填 | 必须为 `8080`（Lambda Web Adapter 约定） | `8080` |
| `database` | object | 必填 | `engine` 必须与 tier 匹配（见下） | — |
| `database.engine` | string（枚举） | 必填 | 由 tier 唯一确定：`static`→`"none"`、`fullstack-nosql`→`"dynamodb"`、`fullstack-sql`→`"dsql"`，不匹配即校验失败 | `"dsql"` |
| `database.tables` | array | 仅 `engine=dynamodb` 必填（≥1 项） | dynamodb：1–10 张表，表名不得重复、**不得含连字符**（用 `_`）；**dsql 禁止声明 tables**（填 `[]` 或省略，schema 全写 `backend/schema.sql`）；static 省略 | `[{"name": "notes", "pk": "id"}]` |
| `database.tables[].name` | string | dynamodb 每项必填 | 正则 `[a-z][a-z0-9_]{0,29}`（小写开头，长度 1–30）——**不得含连字符**，见下方「表名与属性名的字符集为什么不同」 | `"notes"` |
| `database.tables[].pk` | string | dynamodb 每项必填 | 分区键属性名，正则 `[a-z][a-z0-9_-]{0,29}`——**允许连字符**（与表名不同，属性名不参与资源命名）；类型固定为字符串（S） | `"id"` |
| `auth` | object | 必填 | 见下两行 | — |
| `auth.require_login` | boolean | 必填 | `true`：访问者必须飞书登录；`false`：匿名可访问 | `true` |
| `auth.allowed_users` | string 或 array | 必填 | `"org"`（全组织飞书用户）或非空邮箱数组（每项须为合法邮箱） | `"org"` 或 `["a@corp.com", "b@corp.com"]` |

> **`auth` 只在站点首次部署时生效。** 站点建好后，访问策略的真源是平台侧
> 记录：用户在控制台（`https://console.<域名>`）或 MCP 工具
> `update_site_permissions` 在线修改，约 1 分钟内全网生效，**不需要重新
> 部署**。重部署时 `site.json` 里的 `auth` 会被忽略——所以不要靠改
> `site.json` 来改权限，也不要因为线上策略与 `site.json` 不一致就去"修正"
> 它。协作者与所有权同理，只能在控制台或 MCP 工具里管理。

三档完整样例见 `templates/site.json.static.example`、
`templates/site.json.nosql.example`、`templates/site.json.sql.example`——直接以
对应样例为底稿改 `name` / `tables` / `auth`，不要凭记忆手写。

## 表名与属性名的字符集为什么不同

`database.tables[].name` 的正则是 `[a-z][a-z0-9_]{0,29}`——**不含连字符**；
而 `database.tables[].pk` 的正则是 `[a-z][a-z0-9_-]{0,29}`，**允许连字符**。
两者刻意不同，不要"顺手统一"：

- **表名会成为物理资源名的一段**：真实的 DynamoDB 表名是
  `site-data-{site_id}-{表名}`，而 `site_id` 自身可以含连字符。表名也允许连字符时，
  两个**不同**站点能拼出同一个物理表名，于是一个站点的 IAM 策略会精确指向另一个
  站点的数据表（跨租户读写，且下线清理会删错表）。禁掉表名里的连字符就让这种碰撞
  在构造上不可能。
- 表名还会转成大写作为 Lambda 环境变量名 `TABLE_<NAME>`，而环境变量名不接受连字符。
- **属性名（pk）不参与任何资源命名**，DynamoDB 本身也接受连字符，所以不跟着收紧。

**写法**：把 `daily-log` 改成 `daily_log`（读 `process.env.TABLE_DAILY_LOG`）。

## 站点名的保留前缀

下面这些词是平台自留的，`name` **不能是它们本身、也不能以「该词 + 连字符」起头**
（不写个数——数字会随代码漂，真源是 `common.RESERVED_SITE_NAME_PREFIXES`）：

`panel`、`auth`、`key-proxy`、`access`、`deployer`、`runtime`、`rt`

判定规则只有这两种形态（整词，或 `词-` 起头），**不是任意位置的子串**：所以
`authors`、`paneling`、`accessible`、`runtimes` 都是合法站点名，而 `auth`、
`auth-tool`、`rt-foo`、`panel-v2` 会在 `deploy_site` 入口就被拒绝，报错文案会点名
是哪个前缀。取名时撞上了就换一个词，不要试图绕（比如改成 `authtool` 虽然合法，
但意思已经变了——不如换个真正描述用途的名字）。

为什么留：平台自己的 Lambda 也叫 `site-*`（`site-auth-service`、`site-panel-api`
……），而站点名 `auth-tool` 会生成 `site-auth-tool-x1y2z3`。两者共用一个命名空间时，
任何按前缀通配平台函数的安全策略（IAM Deny / SCP）都不再可判定——留出这几个前缀，
通配才有确定含义。

## 三档 tier 生成约束

| tier | 前端 | 后端 | 数据库 | 典型场景 |
|---|---|---|---|---|
| `static` | 纯 HTML/JS/CSS | 无（禁止 backend 字段与 backend/ 目录） | 无（`engine: "none"`） | 展示页、报表页 |
| `fullstack-nosql` | 静态 + fetch `/api/*` | Express（Node 22） | DynamoDB；每张声明的表以环境变量 `TABLE_<NAME>`（表名转大写）注入真实表名——**这也是表名不得含连字符的原因之一**（Lambda 的环境变量名不接受 `-`） | 记录型小工具 |
| `fullstack-sql` | 静态 + fetch `/api/*` | Express（Node 22） | Aurora DSQL；平台注入 `DSQL_ENDPOINT` / `DSQL_SCHEMA` / `DSQL_USER`，只被模板 `db.js` 读取 | 关系型业务 |

后端通用约定（fullstack 两档）：

- 监听端口读 `process.env.PORT`（部署时为 8080，本地演示可任意）。
- DynamoDB 表名不要硬编码：读 `process.env.TABLE_<NAME>`，如声明了
  `{"name": "notes", ...}` 就读 `process.env.TABLE_NOTES`。
  表名里用下划线而不是连字符：`daily_log` → `TABLE_DAILY_LOG`；`daily-log` 会被校验拒绝。
- DSQL 连接只通过 `db.js` 的 `makePool()`；`DSQL_*` 环境变量由平台注入，
  站点代码不读不写。业务代码不需要（也不应该）指定 schema——`makePool()`
  已 `SET search_path` 到站点专属 schema。

## migrations 约定（仅 fullstack-sql）

- **首次部署**：执行器按顺序执行 `backend/schema.sql` 里的全部 DDL。
- **后续 schema 变更**：不改已有 `schema.sql`，新建
  `backend/migrations/NNN_描述.sql`（`NNN` 为三位数字序号，文件名须匹配
  `^\d{3}_.+\.sql$`，如 `001_add_category.sql`），执行器按文件名排序执行
  未跑过的文件。
- **每执行完一个文件立即记录**：已应用的文件（含 `schema.sql`）记录在站点
  元数据 `migrations_applied` 中，重新部署不会重复执行——所以已应用过的
  文件内容**不可再修改**（改了也不会重跑），要改就加新序号文件。
- DSQL 每事务只允许一条 DDL：执行器会把文件拆成单条语句逐条执行
  （autocommit）。migration 文件里只写 DDL/DML 语句，**不要写
  `BEGIN`/`COMMIT`**，且每条语句必须能独立成功。
- schema 内容同样受红线约束（见 `references/redlines.md` 的 DSQL 禁用特性表）。

## 部署 phase 顺序（get_deploy_status 播报用）

`validate` → `provision-db`（仅 fullstack）→ `package`（仅 fullstack，装依赖）
→ `deploy-backend`（仅 fullstack）→ `upload-frontend` → `register-route`
→ `smoke-test`。终态 `SUCCEEDED`（返回 `url`）或 `FAILED`（返回 `error`）。
