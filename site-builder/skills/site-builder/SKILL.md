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
   a. 项目目录打包为 site.zip（site.json 在 zip 根）
   b. 调 `deploy_site(site_name)`（更新已有站点则带 site_id）→ 得 upload_url + job_id
   c. HTTP PUT site.zip 到 upload_url
   d. 调 `confirm_upload(job_id)`
   e. 每 15 秒调 `get_deploy_status(job_id)` 直到 SUCCEEDED/FAILED，
      向用户播报 phase 进展（validate → provision-db → package → deploy-backend
      → upload-frontend → register-route → smoke-test）
   f. 成功：把 url 给用户；失败：把 error 翻译成用户能懂的话，修复代码后从 a 重来
6. **迭代**：用户要改站点 → 改代码 → 同 site_id 重新走部署流程（URL 不变，
   schema 变更写 `backend/migrations/NNN_描述.sql`，不改已有 schema.sql）。
7. **管理**：`list_my_sites` 列站点；`undeploy_site(site_id)` 下线（先跟用户确认）。

## 关键约束速查（详见 references/）

- 前端调后端只写相对路径 `/api/*`
- 站点代码零登录逻辑；当前用户 = 请求头 `x-user-email` / `x-user-name`
- 后端必须实现 `GET /api/health`
- 不写本地文件；端口读 `process.env.PORT`；API 请求体 ≤1MB
- 渲染用户输入用 textContent / DOM API，禁止拼 innerHTML（存储型 XSS）
- DSQL 禁：外键/SERIAL/JSONB 列/触发器/TEMP TABLE → 用 UUID 主键、TEXT 存 JSON
- 数据库访问只用模板 db.js 的 makePool()，不自写连接（平台注入专属只读身份）
- site.json 的 auth.require_login=true 时访问者需飞书登录；
  allowed_users 填 "org"（全组织）或邮箱数组
