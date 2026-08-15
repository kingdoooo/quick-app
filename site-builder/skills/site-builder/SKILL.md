---
name: site-builder
description: 开发并一键部署简易 Web 站点到 AWS。当用户想创建/搭建/部署一个网站、
  小工具、数据看板、记录系统，或要求修改/更新/下线已部署的站点时使用。
  产出带子域名 URL 的站点，访问与管理权限绑定飞书账号。
---

# Site Builder：开发 → 一键部署

你帮业务用户用自然语言开发简易站点并部署上线。全程不要求用户懂 AWS。

## 工作流

1. **澄清需求**：问清站点用途、需要记录什么数据、谁能访问（全组织/指定人）。
2. **定 tier**（三选一，宁低勿高）：
   - 纯展示、无交互存储 → `static`
   - 要记录数据、结构简单（列表/表单）→ `fullstack-nosql`（DynamoDB）
   - 数据有关联查询/统计聚合 → `fullstack-sql`（Aurora DSQL）
3. **生成代码**：严格按 `references/contract.md` 的目录结构与 site.json 格式；
   严格遵守 `references/redlines.md` 的全部红线。模板：
   - `templates/site.json.*.example` 为三档清单样例
   - fullstack 后端一律 Express（Node 22）；`templates/run.sh` 原样放项目根
   - fullstack-sql 的数据库访问必须原样复制 `templates/db.js`，只通过
     `makePool()` 连接，schema 全部写进 `backend/schema.sql`
4. **本地预览**：static 直接开 index.html；fullstack 跑 `node server.js` 演示。
   用户确认后再部署。
5. **部署**（MCP: site-builder-deploy）：
   a. 项目目录打包为 site.zip（site.json 在 zip 根；**排除 node_modules**，
      依赖由平台按 package.json 安装）
   b. 调 `deploy_site(site_name)`（更新已有站点则带 site_id）→ 得 upload_url + job_id
   c. HTTP PUT site.zip 到 upload_url：`curl -X PUT -T site.zip "<upload_url>"`。
      **不要带 Content-Type 头**——预签名 URL 按无该头签名，
      加了必 403 SignatureDoesNotMatch
   d. 调 `confirm_upload(job_id)`
   e. 每 15 秒调 `get_deploy_status(job_id)` 直到 SUCCEEDED/FAILED，
      向用户播报 phase 进展（validate → provision-db → package → deploy-backend
      → upload-frontend → register-route → smoke-test）
   f. 成功：把 url 给用户；失败：把 error 翻译成用户能懂的话，修复代码后从 a 重来
6. **迭代**：用户要改站点 → 改代码 → 同 site_id 重新走部署流程（URL 不变，
   schema 变更写 `backend/migrations/NNN_描述.sql`，不改已有 schema.sql）。
7. **管理**：站点建好之后的所有动作（列站点、改权限、协作者、看访问统计、下线）
   都有对应工具，见下面「MCP 工具面」那张表。下线默认**保留数据库数据**：
   若用户明确要求"连数据一起删干净"，再传 `purge_data=true`——它会永久删除该
   站点的数据表 / DSQL schema，**不可恢复**，传之前必须单独确认一次
   （"确认要一并删除数据吗？此操作不可恢复"）。不确定就用默认值，数据留着比误删好。

## MCP 工具面（`site-builder-deploy`，全部秒级返回）

前三个在上面的部署流程里用；其余是**建完之后**的自助动作——用户提到就直接调，
不要让他自己去控制台点（控制台是同一套后端的另一个入口，不是必经之路）。
拿不到 site_id 就先 `list_my_sites`，别让用户背 ID。

<!-- tool-list:begin  由 site-builder/mcp/tests/test_doc_tool_surface.py 对着 MCP 实时
     注册表校验：漏一个工具、或留着已删除的工具都会变红。区域内**只写工具名**，
     参数名与返回字段名请写在区域外（否则会被当成"多出来的工具"）。 -->

| 工具 | 用户这么说的时候用它 |
|---|---|
| `deploy_site` | "部署 / 上线 / 更新一下"——取得上传地址与任务号，更新已有站点要带上它的站点 ID |
| `confirm_upload` | zip 已传完，启动这次部署 |
| `get_deploy_status` | 部署进行中，每 15 秒问一次并向用户播报阶段 |
| `list_my_sites` | "我有哪些站点""上次那个叫什么""地址是多少"——也是把站点名换成站点 ID 的正规途径 |
| `get_site_permissions` | "谁能看""谁是协作者""我是什么角色"——**改权限之前先读一次**，把现状念给用户确认再改 |
| `update_site_permissions` | "改成全组织可看""只给这几个人""公开不用登录"——在线生效约 1 分钟，**不用重新部署** |
| `manage_collaborators` | "让某人也能改这个站点""把站点转给某人"——加/删协作者与转移所有权（转移与加删互斥，分两次调） |
| `get_site_analytics` | "有人用吗""多少人访问""谁来过""有人打不开"——详见下一节 |
| `undeploy_site` | "下线 / 不要了 / 删掉"——先跟用户确认；默认保留数据（见工作流第 7 步） |

<!-- tool-list:end -->

### 看访问统计：`get_site_analytics(site_id, period="day", days=30)`

返回**一个对象**（不是列表），两个字段：

- `series`：恰好 `days` 个桶，升序，没数据的桶补 0；每项含 `pv`（页面被成功
  打开的次数）、`uv`（独立访客）、`pv_denied`（**没进去的次数**）。
- `recent_visitors`：最近的访问明细（最新在前，最多 50 条，最多回溯 7 天），
  每项含时间、邮箱、路径与 `decision`：`allow` 正常访问 /
  `redirect_login` 当时还没登录、被送去登录页 / `denied_403` 登录了但不在名单里。

`pv_denied` 数的是**所有没进去的请求**，`redirect_login` 也算在里面——而每个
用户第一次访问都会先被送去登录，所以**这个数大不等于"有人被挡在外面"**。
用户说"同事打不开"时，去 `recent_visitors` 里看那个人的 `decision` 是哪一种：
`denied_403` 才是权限问题（用 `update_site_permissions` 把他加进名单）。

参数与口径（调之前必须知道）：

- `period` 取 `day`|`week`|`month`，`days` 是**桶数**（1–400）而不是天数：
  `period="month", days=6` = 最近 6 个月，最后一个桶是"本月至今"。
  用户只问"最近有人用吗"就用默认值。
- **`uv` 可能是 `null`**（同一个桶里 `uv_exact` 为 `false`）：那段区间超出了
  90 天明细留存窗口，独立访客无法精确去重。这时要说"这段时间的独立访客数已
  无法精确统计"，**绝不能当成 0 报给用户**；同一桶的 `pv` 仍然准确，照常用。
  日粒度（`period="day"`）的 `uv` 永远精确。
- 站点 owner、协作者、平台管理员都能看；其他人调用会被拒。统计只记**页面级**
  访问（不含 `/api/*` 与静态资源），今天的数字实时算，历史日期读日聚合。

## 关键约束速查（详见 references/）

- 前端调后端只写相对路径 `/api/*`
- 站点代码零登录逻辑；当前用户 = 请求头 `x-user-email` / `x-user-name`
  （name 是 URL 编码的，用 `decodeURIComponent` 解码后再用）
- 后端必须实现 `GET /api/health`
- 不写本地文件；端口读 `process.env.PORT`；API 请求体 ≤1MB
- 渲染用户输入用 textContent / DOM API，禁止拼 innerHTML（存储型 XSS）
- DSQL 禁：外键/SERIAL/JSONB 列/触发器/TEMP TABLE → 用 UUID 主键、TEXT 存 JSON
- 数据库访问只用模板 db.js 的 makePool()，不自写连接（平台注入专属只读身份）
- site.json 的 auth.require_login=true 时访问者需飞书登录；
  allowed_users 填 "org"（全组织）或邮箱数组
