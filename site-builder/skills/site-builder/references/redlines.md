# 代码红线

部署第一步 `validate` 会对产物做静态扫描（扫描 `frontend/`、`backend/` 下的
`.html .htm .js .mjs .cjs .css .py .json .txt` 文件，node_modules 除外）。
扫描是**启发式的、宁可误报不可漏报**——正则命中即失败，注释里出现违禁模式
同样会被判违规。命中任何一条，部署直接 FAILED，error 中含下列确切报错。

## 红线 1：前端 API 一律相对路径 `/api/*`

- **规则**：前端代码禁止出现 `localhost`、`127.x.x.x`、`0.0.0.0`、`[::1]`，
  也禁止把 API 写成绝对地址（引号内的 `http(s)://.../api/`）。
- **为什么**：前后端同域名部署，路由层按 `/api/*` 分流。硬编码地址在部署后
  必然指向错误位置，且站点子域名在部署前不可知。
- **违反后果**（两条报错，按命中分别出现）：
  - `frontend/xxx: 前端禁止 localhost/127.0.0.1，API 一律相对路径 /api/*`
  - `frontend/xxx: 前端 API 调用禁止绝对地址，改为相对路径 /api/*`
- **正确**：
  ```js
  const notes = await (await fetch("/api/notes")).json();
  ```
- **错误**：
  ```js
  const notes = await (await fetch("http://localhost:8080/api/notes")).json();
  const r = await fetch("https://my-site.example.com/api/notes");  // 同样违规
  ```
- 注意：`localhost` 出现在**注释**里也会命中（frontend 文件不要写含
  localhost 的注释）。本地预览时直接跑 `node server.js` 并从同源打开页面，
  代码里不需要任何本地地址。

## 红线 2：禁止 innerHTML 渲染用户输入（存储型 XSS）

- **规则**：前端禁止 `innerHTML` / `outerHTML` 赋值或拼接（`=`、`+=`、
  `||=`、`??=`），禁止 `insertAdjacentHTML()`、`document.write()` /
  `document.writeln()`。
- **为什么**：站点在组织内共享同一个登录会话（顶域 cookie），存储型 XSS 的
  危害被放大——一个用户提交的恶意内容会在所有访问者的登录态下执行。
- **违反后果**：
  `frontend/xxx: 前端禁止 innerHTML 赋值/拼接（存储型 XSS 风险），改用 textContent 或安全模板`
- **正确**：
  ```js
  const li = document.createElement("li");
  li.textContent = note.text;          // 用户输入只走 textContent
  list.replaceChildren(li);
  ```
- **错误**：
  ```js
  list.innerHTML += `<li>${note.text}</li>`;         // 违规
  el.insertAdjacentHTML("beforeend", note.text);      // 违规
  ```
- 静态骨架也用 DOM API（`createElement` / `append` / `replaceChildren`）
  构建；比较运算 `a.innerHTML === b` 不会误伤，但赋值一律命中。

## 红线 3：站点代码零登录逻辑

- **规则**：后端禁止出现任何自带鉴权的痕迹：`jwt.sign`、`jsonwebtoken`、
  `passport`、`OAuth2`、`client_secret`、`express-session`、`cookie-session`、
  `res.cookie(`、`Set-Cookie`、`set_cookie(...session` 等。
- **为什么**：登录/鉴权由平台边缘层统一处理（IdP 联邦 + 顶域会话 cookie）。
  站点自带 auth 代码是 AI 生成错误的重灾区，且会与平台鉴权冲突。
- **违反后果**：
  `backend/xxx: 站点代码禁止自带 auth 逻辑（鉴权由平台边缘层统一处理）`
- **正确**（需要当前用户时读平台注入的请求头，直接信任）：
  ```js
  const email = req.headers["x-user-email"] || "anonymous";
  // x-user-name 必须解码，见红线 4
  const name = decodeURIComponent(req.headers["x-user-name"] || "");
  ```
- **错误**：
  ```js
  const jwt = require("jsonwebtoken");                 // 违规
  res.cookie("session", token);                        // 违规
  ```
- 访问控制在 `site.json` 的 `auth` 字段声明（`require_login` +
  `allowed_users`），不在代码里实现。注意扫描含 `Set-Cookie` 等关键词的
  注释/字符串同样命中——后端代码里完全不要出现这些词。

## 红线 4：x-user-name 必须 decodeURIComponent

- **规则**：代码里出现 `x-user-name`（前端或后端、任意大小写与引号写法）时，
  必须**对这个头的值**调 `decodeURIComponent(`。两种写法都算通过：
  ① 同一表达式里解码（`decodeURIComponent(req.headers['x-user-name'])`，
  允许夹 `|| ''`、`String(...)` 等）；② 先把头值存进变量、再解码那个变量。
  **解码别的东西不算**——文件里有 `decodeURIComponent(req.query.q)` 而头值
  原样使用，仍会被拦下。
- **为什么**：HTTP 头不能携带非 ASCII 字节，所以平台边缘层注入这个头时做了
  **URL 编码**（不编码的话中文名字会被 CloudFront 直接拒掉）。
  `x-user-email` 是 ASCII，**不编码**，不需要解码。
- **为什么值得一条红线**：漏掉解码**不会报错**——页面上显示
  `%E5%BD%AD%E9%87%91%E5%86%AC`，写进数据库的也是这串编码。等发现时历史数据
  已经脏了，只能单独清洗。真实站点踩过这个坑。
- **违反后果**：
  `backend/server.js: 用了 x-user-name 但没有对它 decodeURIComponent —— 该头是 URL 编码的…（注意：解码别的东西（如 req.query.x）不算——必须解码这个头的值）`
- **正确**：
  ```js
  const name = decodeURIComponent(req.headers["x-user-name"] || "");
  ```
- **错误**：
  ```js
  const name = req.headers["x-user-name"] || "";        // 违规：拿到的是编码串

  const raw = req.headers["x-user-name"];
  const q = decodeURIComponent(req.query.q);            // 违规：解码的不是这个头
  save(raw);
  ```
- 判定按**文件**而非按行：先取头存进变量、在别处解码那个变量也算通过。
  黄金样例见 `fixtures/nosql-notes/backend/server.js`。

## 红线 5：禁止写本地文件

- **规则**：后端禁止 `fs.writeFile`、`fs.appendFile`、`fs.promises.*`、
  `fs.createWriteStream`、引入 `fs/promises`（含 `node:fs/promises`），
  以及 Python `open(..., "w"/"a"/"x")`。
- **为什么**：站点跑在 Lambda，文件系统只读（/tmp 也不持久），写文件的
  数据必然丢失。持久化一律走声明的数据库。
- **违反后果**：
  `backend/xxx: 禁止写本地文件（Lambda 文件系统只读）`
- **正确**（数据进数据库）：
  ```js
  await db.send(new PutCommand({ TableName: TABLE, Item: item }));
  ```
- **错误**：
  ```js
  fs.writeFileSync("./data.json", JSON.stringify(items));   // 违规
  const fsp = require("node:fs/promises");                  // 违规（整包被禁）
  ```

## 红线 6：后端必须实现 `GET /api/health`

- **规则**：backend 代码中必须出现 `/api/health` 端点。
- **为什么**：部署最后一步冒烟测试会请求 `/api/health` 验证后端存活，
  没有它部署永远过不了 smoke-test。
- **违反后果**：
  `backend: 必须实现 GET /api/health 端点（部署冒烟测试依赖）`
- **正确**：
  ```js
  app.get("/api/health", (req, res) => res.json({ ok: true }));
  ```
- **错误**：只写业务路由、没有 health 端点。

## 红线 7：DSQL 禁用特性（仅 fullstack-sql）

- **规则**：`backend/schema.sql` 必须存在，且不得出现 `REFERENCES`、
  `SERIAL`、`JSONB`、`CREATE TRIGGER`、`CREATE TEMP`。
- **规则（索引）**：建索引**必须**写 `CREATE INDEX ASYNC`（`UNIQUE` 同理：
  `CREATE UNIQUE INDEX ASYNC`）。DSQL 不支持同步建索引。
  这条对 `schema.sql` 与 `migrations/*.sql` **一视同仁**。
- **为什么**：这些 PostgreSQL 特性在 DSQL 上不可用（DDL 会在 provision-db 阶段
  执行失败），静态扫描把它们拦在 validate 阶段。
- **`JSONB` 的准确情况**（真机实测过，别照抄旧说法）：
  - **数据层全部可用**：jsonb 列、`NOT NULL DEFAULT '{}'::jsonb`、
    `->` `->>` `#>` `@>` `?`、`jsonb_set` / `jsonb_agg` / `jsonb_build_object` /
    `jsonb_array_elements_text`，以非 admin 的 per-site role 身份也全部通过。
  - **但 GIN 索引不支持**：`CREATE INDEX ASYNC ... USING GIN (col)` 报
    `USING not supported for CREATE INDEX`。实测 `@>` 查询的计划是**全表扫描
    + Filter**，不是索引查找。
  - 所以"DSQL 不支持 JSONB"是错的，"用 JSONB 没有代价"也是错的：
    **它可用但不可索引**。数据量一大、又要按 jsonb 内容过滤时会退化成全表扫。
  - 平台因此**继续禁用**它：`TEXT` 存 JSON 至少不会让人误以为有索引加速。
    确实需要按某个字段过滤时，把它**提成一个独立列**（可建普通索引），
    这比塞进 jsonb 再指望索引更快也更清晰。
- **扫描面**：禁用特性表与索引 `ASYNC` 规则对 `backend/schema.sql` 与
  `backend/migrations/*.sql` **一视同仁**，都在 validate 阶段静态扫描
  （执行器用同一个连接、同样逐条执行两者，所以禁用特性写在哪个文件里都会在
  provision-db 阶段失败）。**写 migrations 时同样遵守本表。**
- **违反后果**：
  - `backend/schema.sql: fullstack-sql 必须提供建表 SQL`（文件缺失）
  - `backend/schema.sql: 含 DSQL 不支持的 REFERENCES（见红线文档替代方案）`
    （逐关键词报，`SERIAL`/`JSONB`/`CREATE TRIGGER`/`CREATE TEMP` 同理；
    migrations 文件报自己的相对路径，如
    `backend/migrations/001_add.sql: 含 DSQL 不支持的 SERIAL…`）
  - `backend/schema.sql: DSQL 建索引必须写 CREATE INDEX ASYNC`
    （漏 `ASYNC` 时 provision-db 阶段报
    `unsupported mode. please use CREATE INDEX ASYNC.`，**站点不会上线**）
- 扫描是大写后子串匹配：**注释里出现这些词也会命中**，schema.sql 里
  不要写含 `references`、`serial` 等词的注释。

### DSQL 禁用特性 → 替代方案

| 禁用特性 | 替代方案 |
|---|---|
| 外键约束（`REFERENCES` / `FOREIGN KEY`） | 只存关联 id 列（如 `owner_id UUID NOT NULL`），关联存在性由应用层校验 |
| `SERIAL` / `BIGSERIAL` 自增主键 | `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` |
| `JSONB` 列（DSQL 可存但**无法建 GIN 索引**，见上） | `TEXT` 存 JSON 字符串；**要按内容过滤就提成独立列**（可建普通索引）；确需 SQL 内解析时查询时转换 `col::jsonb` |
| `ON DELETE CASCADE` | 软删除（`deleted_at TIMESTAMPTZ` 标记），或应用层按序删除子记录 |
| 触发器（`CREATE TRIGGER` / PLpgSQL） | 逻辑放应用层（Express 路由内处理） |
| 临时表（`CREATE TEMP TABLE`） | 用 CTE（`WITH ... AS`）或普通表 |
| 同步建索引（`CREATE INDEX`） | `CREATE INDEX ASYNC`（加一个词即可，索引本身完全可用） |

> **索引不是禁用特性，只是换关键字。** 上表其它几项要改设计，这项加个
> `ASYNC` 就行。DSQL 的索引是异步构建的：语句立刻返回，索引在后台建好，
> 期间查询照常可用（只是暂时用不上该索引）。

**正确的 schema.sql 样例**（黄金样例，来自 templates 同源 fixture）：

```sql
CREATE TABLE IF NOT EXISTS expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  amount NUMERIC(10,2) NOT NULL,
  spender TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 需要索引时**必须**带 ASYNC（DSQL 不支持同步建索引）
CREATE INDEX ASYNC IF NOT EXISTS idx_expenses_created_at ON expenses (created_at);
```

**错误写法**：

```sql
CREATE TABLE orders (                                  -- 违规：缺 IF NOT EXISTS（红线 9）
  id SERIAL PRIMARY KEY,                              -- 违规：SERIAL
  user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- 违规：REFERENCES
  meta JSONB                                           -- 违规：JSONB
);

-- 违规：缺 ASYNC。provision-db 阶段报
-- unsupported mode. please use CREATE INDEX ASYNC. → 站点不会上线
CREATE INDEX idx_orders_user ON orders (user_id);
```

另：DSQL 连接**只允许**原样复制 `templates/db.js` 并通过 `makePool()` 获取
连接池——不要自写连接串/签名逻辑（平台按站点注入专属数据库身份，自写必错）。

**schema.sql / migrations 的执行身份**：平台用本站点专属的 migrator 角色执行，
该角色只对本站点 schema 有建对象权限。因此这些 SQL 里**不要**写跨 schema 操作
（`DROP SCHEMA other`、`GRANT ... TO other`）、角色管理（`CREATE ROLE`、
`ALTER ROLE`、`AWS IAM GRANT`）或全局 DDL——不是被扫描器拦下，而是执行时因
权限不足直接失败。只写本站点自己的表/索引/视图。

## 红线 8：后端依赖必须锁定（仅 fullstack）

- **规则**：`backend/package.json` 与 `backend/package-lock.json` 必须同时存在；
  lockfile 的 `lockfileVersion 必须是 [2, 3]` 之一（npm ≥ 7 生成的就是），每个包的
  `resolved` 必须以 `https://registry.npmjs.org/` 开头且带 `sha512` 的 `integrity`；
  lockfile 根条目的依赖声明必须与 `package.json` 一致；禁止 `backend/npm-shrinkwrap.json`；
  `package.json` 四个依赖段（`dependencies` / `devDependencies` / `optionalDependencies` /
  `peerDependencies`）的规格只许 semver 范围或 dist-tag——禁止 `file:`、`git+…`、
  `github:user/repo`、`user/repo`、URL、`npm:alias`（判据：规格里不能有 `:` 或 `/`）。
- **为什么**：部署时用 `npm ci` 按 lockfile 安装，同一份上传在任何时间装出同一棵依赖树，
  事后能回答"当时线上跑的是哪些包"。没有 lockfile 的话 `npm ci` 会在 provision-db 之后
  才失败；`resolved` 指向别的主机等于绕开平台的 registry 限制；`file:` / `link` 依赖装的是
  本地字节，`npm ci` 不会拒它，所以由校验器拒。
- **怎么做**：在 `backend/` 下跑一次 `npm install`（本地预览本来就要跑），会生成
  `package-lock.json`；打包时排除 `node_modules`、**保留** `package-lock.json`。
  只想生成锁文件不装依赖、或机器上配了私有镜像时用：
  ```bash
  cd backend && npm install --package-lock-only --registry=https://registry.npmjs.org/
  ```
  改过 `package.json` 之后重跑同一条命令。
- **违反后果**（按命中分别出现，报错尾巴都带上面那条重生成命令）：
  - `backend/package.json 缺失：后端依赖必须锁定，构建用 npm ci（…）`
  - `backend/package-lock.json 缺失：后端依赖必须锁定，构建用 npm ci（…）`
  - `backend/npm-shrinkwrap.json: 禁止——npm ci 会优先读它、跳过被校验的 package-lock.json`
  - `backend/package-lock.json: lockfileVersion 必须是 [2, 3] 之一，得到 1（…）`
  - `backend/package-lock.json: packages['node_modules/x'].resolved 必须以 https://registry.npmjs.org/ 开头，得到 '…'（其它 registry/镜像/任意 URL 一律拒绝）`
  - `backend/package-lock.json: packages['node_modules/x'].integrity 缺少 sha512（…）`
  - `backend/package-lock.json: packages['libs/x'] 不是从 registry 安装的包（workspace / file: / link 依赖不可复现，禁止）`
  - `backend/package-lock.json: packages[""].dependencies 与 package.json 不一致——改了 package.json 之后要重新生成 lockfile（…）`
  - `backend/package.json: dependencies.dep 的规格 'file:./dep' 不是 registry 依赖（禁止 file:/git/URL/别名规格——它们绕开锁定与 registry 校验）`
- **正确**：
  ```json
  { "name": "notes-backend", "private": true,
    "dependencies": { "express": "^4.19", "@aws-sdk/lib-dynamodb": "^3" } }
  ```
  加上 `npm install` 生成的 `package-lock.json`，两者一起进 zip。
- **错误**：
  ```json
  { "dependencies": { "helper": "file:../helper", "tool": "github:someone/tool" } }
  ```
  或者 zip 里只有 `package.json` 没有 `package-lock.json`。
- 黄金样例：`fixtures/nosql-notes/backend/` 与 `fixtures/sql-expenses/backend/` 各带一份
  lockfile。无依赖的后端同样要放这一对（对空依赖的 `package.json` 跑同一条命令即可）。

## 红线 9：DSQL 建表/迁移的 DDL 必须可重放（仅 fullstack-sql）

- **规则**：`backend/schema.sql` 与 `backend/migrations/*.sql` 里的每一条 **DDL** 都必须
  是下列可重放形态之一，否则 validate 拒：

  | 允许的 DDL 形态 | 说明 |
  |---|---|
  | `CREATE TABLE IF NOT EXISTS …` | 建表 |
  | `CREATE [UNIQUE] INDEX ASYNC IF NOT EXISTS <索引名> …` | 用 `IF NOT EXISTS` 时**索引名必填** |
  | `ALTER TABLE [IF EXISTS] … ADD COLUMN IF NOT EXISTS …` | 加列 |
  | `ALTER TABLE [IF EXISTS] … DROP COLUMN IF EXISTS …` | 删列 |
  | `ALTER TABLE [IF EXISTS] … DROP CONSTRAINT IF EXISTS …` | 删约束 |
  | `CREATE OR REPLACE VIEW …` | 建视图（`RECURSIVE` 也可） |

  多动作的 `ALTER TABLE`（`action [, ...]`）要求**每个动作**都是幂等形态——一个幂等动作
  不能替同语句里的其它动作背书。

- **DML（`INSERT` / `UPDATE` / `DELETE`）不受本红线约束**，但要知道重放语义，见下面
  「种子数据」一节。
- **规则（子目录）**：迁移文件必须直接放在 `backend/migrations/` 下，**不允许子目录**。
- **为什么**：DSQL 每条语句 autocommit（一个事务只许一条 DDL，且 DDL 与 DML 不能同
  事务，所以"把整个文件包进一个事务"**做不到**），而 DSQL 与平台元数据之间**没有原子
  事务**。一个文件跑到一半失败（一个 typo、或超时落在文件中间），前面的语句**已经提交**
  而"这个文件跑过了"的标记没写上 —— 重试会**整文件重跑**。此时不可重放的 DDL
  （裸 `CREATE TABLE`）第二次撞上"已存在"而失败，站点会卡在
  「同一份产物再也部署不上去」，直到 SQL 被改成可重放。**这是可部署性问题**，也正是
  本红线只管 DDL 的原因（见「种子数据」）。
- **两条容易踩的边界**（AWS 文档原话）：
  - `IF NOT EXISTS` 的守卫**只看名字，不比对类型**。文档对列的说法是 "a column already
    exists with this name"；索引那边更直白："no guarantee that the existing index
    resembles the one that would have been created"。**⇒ 改过某列的类型之后重放会
    静默 no-op**，不会报错也不会改成新类型。要改类型就新加一个迁移文件换列。
  - 同步 DDL 失败后**是否原子回滚，DSQL 文档没有说**，不要假设。唯一有明确说法的是
    异步索引：`CREATE INDEX ASYNC` 失败会留在 `INVALID` 状态，官方建议显式 `DROP` 后重建。
- **违反后果**：
  - `backend/schema.sql: 不可重放的语句 \`CREATE TABLE orders (id UUID PRIMARY KEY)\`——…`
  - `backend/migrations/nested/: 不允许子目录——迁移文件必须直接放在 backend/migrations/ 下…`
- **正确**：

  ```sql
  CREATE TABLE IF NOT EXISTS expenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL
  );
  CREATE INDEX ASYNC IF NOT EXISTS idx_expenses_title ON expenses (title);
  CREATE OR REPLACE VIEW expenses_recent AS SELECT * FROM expenses;
  ALTER TABLE IF EXISTS expenses ADD COLUMN IF NOT EXISTS note TEXT;
  ```

- **错误**：

  ```sql
  CREATE TABLE orders (id UUID PRIMARY KEY);        -- 缺 IF NOT EXISTS
  ALTER TABLE orders ADD COLUMN note TEXT;          -- 缺 IF NOT EXISTS
  ALTER TABLE orders ADD COLUMN IF NOT EXISTS a TEXT, ADD COLUMN b TEXT;  -- 第二个动作缺
  CREATE VIEW v AS SELECT 1;                        -- 缺 OR REPLACE
  DROP TABLE old_orders;                            -- 白名单外（IF 形态文档未确认幂等）
  CREATE SCHEMA extra;                              -- 白名单外（同上；而且站点无权建 schema）
  BEGIN; … COMMIT;                                  -- 禁止事务包裹（DSQL 一事务一条 DDL）
  ```

- **为什么是白名单**：只放行 AWS 文档**确认**支持幂等 `IF` 形态的语句。`CREATE SCHEMA`、
  `DROP TABLE`、`CREATE SEQUENCE` 这些的 `IF` 形态在 DSQL 文档里没有说法，所以一律拒——
  与其猜，不如让站点作者用已确认可行的那几种形态表达同样的意图。
- **已经上线的站点怎么升级**：本红线在**每次**部署的 validate 都跑，所以一个 `schema.sql`
  里写着裸 `CREATE TABLE` 的存量站点，连"只改前端"的部署也会被拒。修法是**直接把那些
  DDL 补上 `IF NOT EXISTS`**——这与「已应用过的文件不可再修改」不冲突：改动对运行时
  是**无副作用的**（已应用标记仍然按文件名跳过该文件，补上的 `IF NOT EXISTS` 一次都不会
  被执行），它的唯一作用就是让 validate 通过，并让**将来**万一需要重跑时是安全的。
  多动作的 `ALTER TABLE` 要每个动作都补。种子 `INSERT` **不需要改**（不在本红线射程内）。

### 种子数据（`INSERT`）：不被拦，但重放会重复插入

本红线**不管 DML**。四条理由，其中两条会直接影响你怎么写：

1. **它不会让部署卡死。** 裸 `INSERT` 重放是**成功**的（没有约束冲突），文件跑完、标记
   写上、部署 SUCCEEDED。多出来的只是几行重复数据 —— 数据质量问题，不是可部署性问题。
2. **`ON CONFLICT` 的子句级支持，DSQL 文档没有说。** userguide 只在总表里粗粒度写了
   `INSERT INTO … VALUES/SELECT [ON CONFLICT]`，没有 INSERT 的详细语法页。既然本红线拒
   `DROP TABLE IF EXISTS` 的理由就是"文档没说"，那它也不该**强制**一个文档没说的形态。
3. **强制它常常是空转的**：`id UUID PRIMARY KEY DEFAULT gen_random_uuid()` 且没有自然键
   时，`ON CONFLICT DO NOTHING` 的冲突目标每次都是新 uuid ⇒ 永不冲突 ⇒ 照样重复插入。
   过了检查却没有变幂等，是**假安全感**。
4. 平台从不要求你写种子数据。

**所以：想让种子数据幂等，靠的是自然键，不是加一句 `ON CONFLICT`。** 推荐写法（`UNIQUE`
列约束在 DSQL 的 `CREATE TABLE` 支持语法内，且不走异步索引任务）：

```sql
CREATE TABLE IF NOT EXISTS categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT NOT NULL UNIQUE,          -- 自然键：重放时靠它判重
  name TEXT NOT NULL
);
INSERT INTO categories (code, name) VALUES ('food', '餐饮')
  ON CONFLICT (code) DO NOTHING;
```

**不要用 `CREATE UNIQUE INDEX ASYNC` 当冲突目标**：文档明说异步索引初始为 `INVALID`、
要后台构建完才有效（可用 `sys.jobs` 或 `pg_index.indisvalid` 看状态、`sys.wait_for_job()`
等待），紧跟其后的 `ON CONFLICT` 不一定能用上它。表内联的 `UNIQUE` 没有这个问题。


## 运行时约束（扫描器不查，但违反同样部署失败或线上出错）

- 监听端口读 `process.env.PORT`，不要硬编码。
- API 请求/响应体 ≤1MB（边缘转发上限），大文件场景不要做。
- 无后台常驻任务（`setInterval` 长任务、队列 worker 等——Lambda 请求结束
  即冻结）。
- fullstack 项目根必须放 `run.sh`（`templates/run.sh` 原样复制），打包器
  强制检查，缺失即失败。
