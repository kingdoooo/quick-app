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
- **为什么**：站点在组织内共享飞书登录会话（顶域 cookie），存储型 XSS 的
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
- **为什么**：登录/鉴权由平台边缘层统一处理（飞书 SSO + 顶域会话 cookie）。
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
  `backend/server.js: 用了 x-user-name 但没有 decodeURIComponent —— 该头是 URL 编码的…`
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
- **为什么**：Aurora DSQL 不支持这些 PostgreSQL 特性，DDL 会在
  provision-db 阶段执行失败；静态扫描把它们拦在 validate 阶段。
  migrations 文件不做静态扫描，但同样的禁用特性会在 provision-db 执行时
  直接报 SQL 错误——**写 migrations 时同样遵守本表**。
- **违反后果**：
  - `backend/schema.sql: fullstack-sql 必须提供建表 SQL`（文件缺失）
  - `backend/schema.sql: 含 DSQL 不支持的 REFERENCES（见红线文档替代方案）`
    （逐关键词报，`SERIAL`/`JSONB`/`CREATE TRIGGER`/`CREATE TEMP` 同理）
- 扫描是大写后子串匹配：**注释里出现这些词也会命中**，schema.sql 里
  不要写含 `references`、`serial` 等词的注释。

### DSQL 禁用特性 → 替代方案

| 禁用特性 | 替代方案 |
|---|---|
| 外键约束（`REFERENCES` / `FOREIGN KEY`） | 只存关联 id 列（如 `owner_id UUID NOT NULL`），关联存在性由应用层校验 |
| `SERIAL` / `BIGSERIAL` 自增主键 | `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` |
| `JSONB` 列 | `TEXT` 存 JSON 字符串；确需 SQL 内解析时查询时转换 `col::jsonb` |
| `ON DELETE CASCADE` | 软删除（`deleted_at TIMESTAMPTZ` 标记），或应用层按序删除子记录 |
| 触发器（`CREATE TRIGGER` / PLpgSQL） | 逻辑放应用层（Express 路由内处理） |
| 临时表（`CREATE TEMP TABLE`） | 用 CTE（`WITH ... AS`）或普通表 |

**正确的 schema.sql 样例**（黄金样例，来自 templates 同源 fixture）：

```sql
CREATE TABLE IF NOT EXISTS expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  amount NUMERIC(10,2) NOT NULL,
  spender TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
```

**错误写法**：

```sql
CREATE TABLE orders (
  id SERIAL PRIMARY KEY,                              -- 违规：SERIAL
  user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- 违规：REFERENCES
  meta JSONB                                           -- 违规：JSONB
);
```

另：DSQL 连接**只允许**原样复制 `templates/db.js` 并通过 `makePool()` 获取
连接池——不要自写连接串/签名逻辑（平台按站点注入专属数据库身份，自写必错）。

**schema.sql / migrations 的执行身份**：平台用本站点专属的 migrator 角色执行，
该角色只对本站点 schema 有建对象权限。因此这些 SQL 里**不要**写跨 schema 操作
（`DROP SCHEMA other`、`GRANT ... TO other`）、角色管理（`CREATE ROLE`、
`ALTER ROLE`、`AWS IAM GRANT`）或全局 DDL——不是被扫描器拦下，而是执行时因
权限不足直接失败。只写本站点自己的表/索引/视图。

## 运行时约束（扫描器不查，但违反同样部署失败或线上出错）

- 监听端口读 `process.env.PORT`，不要硬编码。
- API 请求/响应体 ≤1MB（边缘转发上限），大文件场景不要做。
- 无后台常驻任务（`setInterval` 长任务、队列 worker 等——Lambda 请求结束
  即冻结）。
- fullstack 项目根必须放 `run.sh`（`templates/run.sh` 原样复制），打包器
  强制检查，缺失即失败。
