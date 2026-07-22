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
- 打包为 `site.zip` 时 `site.json` 必须位于 zip 根（不要多套一层目录）。
- zip 上限：压缩后 ≤50MB；解压后 ≤200MB、≤2000 个文件、压缩比 ≤100:1；
  路径禁止绝对路径与 `..`。

## site.json 全字段表

| 字段路径 | 类型 | 必填 | 约束 | 示例值 |
|---|---|---|---|---|
| `name` | string | 必填 | 小写字母开头，仅含 `[a-z0-9-]`，长度 2–30（正则 `[a-z][a-z0-9-]{1,29}`） | `"expense-tracker"` |
| `tier` | string（枚举） | 必填 | `static` \| `fullstack-nosql` \| `fullstack-sql` 三选一 | `"fullstack-sql"` |
| `backend` | object | fullstack 必填；`tier=static` 时**禁止出现** | 见下三行 | — |
| `backend.runtime` | string（枚举） | fullstack 必填 | 目前仅支持 `nodejs22.x`（Express）；Python 记为二期 | `"nodejs22.x"` |
| `backend.entrypoint` | string | fullstack 必填 | 非空字符串；启动命令 | `"node server.js"` |
| `backend.port` | number | fullstack 必填 | 必须为 `8080`（Lambda Web Adapter 约定） | `8080` |
| `database` | object | 必填 | `engine` 必须与 tier 匹配（见下） | — |
| `database.engine` | string（枚举） | 必填 | 由 tier 唯一确定：`static`→`"none"`、`fullstack-nosql`→`"dynamodb"`、`fullstack-sql`→`"dsql"`，不匹配即校验失败 | `"dsql"` |
| `database.tables` | array | 仅 `engine=dynamodb` 必填（≥1 项） | dynamodb：1–10 张表，表名不得重复；**dsql 禁止声明 tables**（填 `[]` 或省略，schema 全写 `backend/schema.sql`）；static 省略 | `[{"name": "notes", "pk": "id"}]` |
| `database.tables[].name` | string | dynamodb 每项必填 | 正则 `[a-z][a-z0-9_-]{0,29}`（小写开头，长度 1–30） | `"notes"` |
| `database.tables[].pk` | string | dynamodb 每项必填 | 分区键属性名，正则 `[a-z][a-z0-9_-]{0,29}`；类型固定为字符串（S） | `"id"` |
| `auth` | object | 必填 | 见下两行 | — |
| `auth.require_login` | boolean | 必填 | `true`：访问者必须飞书登录；`false`：匿名可访问 | `true` |
| `auth.allowed_users` | string 或 array | 必填 | `"org"`（全组织飞书用户）或非空邮箱数组（每项须为合法邮箱） | `"org"` 或 `["a@corp.com", "b@corp.com"]` |

三档完整样例见 `templates/site.json.static.example`、
`templates/site.json.nosql.example`、`templates/site.json.sql.example`——直接以
对应样例为底稿改 `name` / `tables` / `auth`，不要凭记忆手写。

## 三档 tier 生成约束

| tier | 前端 | 后端 | 数据库 | 典型场景 |
|---|---|---|---|---|
| `static` | 纯 HTML/JS/CSS | 无（禁止 backend 字段与 backend/ 目录） | 无（`engine: "none"`） | 展示页、报表页 |
| `fullstack-nosql` | 静态 + fetch `/api/*` | Express（Node 22） | DynamoDB；每张声明的表以环境变量 `TABLE_<NAME>`（表名转大写）注入真实表名 | 记录型小工具 |
| `fullstack-sql` | 静态 + fetch `/api/*` | Express（Node 22） | Aurora DSQL；平台注入 `DSQL_ENDPOINT` / `DSQL_SCHEMA` / `DSQL_USER`，只被模板 `db.js` 读取 | 关系型业务 |

后端通用约定（fullstack 两档）：

- 监听端口读 `process.env.PORT`（部署时为 8080，本地演示可任意）。
- DynamoDB 表名不要硬编码：读 `process.env.TABLE_<NAME>`，如声明了
  `{"name": "notes", ...}` 就读 `process.env.TABLE_NOTES`。
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
