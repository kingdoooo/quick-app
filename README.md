# Site-Builder：给 AI Agent 打造的应用上线平台

业务人员在自己常用的 Agent 客户端里（Claude Code、Amazon Quick Desktop，或任何支持
Skill 和 MCP 的客户端）用自然语言做出一个小应用，说一句"部署"，就能拿到一个可以分享给
同事的网址：`https://app-{站点 ID}.{你的域名}`。

整套平台部署在**你自己的 AWS 账号**里：应用、数据和登录身份都留在你的账号内，谁能访问
由站点的所有者自己决定。业务人员全程不用打开 AWS 控制台，也不需要懂云。

## 解决什么问题

财务的台账、HR 的入职清单、市场的活动报名页，这类内部小工具用 Agent 几分钟就能写出来。
难的是上线：域名和证书从哪来、谁能访问、数据放在哪、成本怎么算。这些都是云和部署的知识，
业务人员既不懂，也不该需要懂。

Site-Builder 把这些问题在平台里一次性解决。之后每个应用上线，都只是和 Agent 说一句话。

## 用起来是什么样

一次性准备：在 Agent 客户端里导入建站 Skill、添加部署 MCP，用企业身份登录一次。之后全靠对话：

1. **说需求**。Agent 按 Skill 先问清楚：站点做什么、要存什么数据、谁能访问。
2. **生成和预览**。Agent 自动选择站点类型（纯静态、带简单数据、带关联查询），按应用规范
   生成代码，先在本地跑起来给你看。
3. **说"部署"**。Agent 上传代码并播报进度，分钟级拿到站点网址。
4. **改权限、加协作者**。比如"改成全组织可见""只给这几个人看"，约 1 分钟生效，不用重新部署。
5. **看访问情况**。访问量、独立访客、被拒次数，以及最近的访问记录。
6. **迭代**。改完再部署一次，网址不变。新版本通过健康检查才会切换，没通过就继续跑旧版本。
   数据库迁移是例外：它在切换之前执行、不能回滚，所以必须兼容旧版本（见「设计要点」）。

## 架构

```
 ① 建站 Skill ── 加载在 Agent 客户端里，告诉 Agent 按什么规范生成代码
        │  MCP 调用，带着用户的登录身份
        ▼
 ② 部署 MCP ── Amazon Bedrock AgentCore Runtime，所有工具秒级返回
        │  启动异步部署
        ▼
 ③ 部署执行器 ── AWS Step Functions + CodeBuild + Lambda
        │  校验代码 → 建库 → 打包 → 部署后端 → 上传前端 → 注册路由 → 冒烟测试
        ▼
 ④ 路由与鉴权 ── Amazon CloudFront + Lambda@Edge + DynamoDB 路由表
        │  每个请求：查路由 → 验登录 → 按名单放行 → 转发到站点
        ▼
    站点本身 ── 前端在私有 S3，后端是站点自己的 Lambda，数据在 DynamoDB 或 Aurora DSQL

 ⑤ 身份 ── Amazon Cognito，联邦到你的企业 IdP；会话签名的私钥锁在 AWS KMS 里

 控制台 console.{你的域名} · 可选的 API Key 交换层 mcp.{你的域名}
```

部署 MCP 提供的工具：

<!-- tool-list:begin 由 site-builder/mcp/tests/test_doc_tool_surface.py 对着 MCP 注册表校验，请勿删除 -->

| 工具 | 做什么 |
|---|---|
| `deploy_site` | 发起一次部署（更新已有站点时带上站点 ID），返回代码包的上传地址和任务号 |
| `confirm_upload` | 确认代码包已上传，启动部署 |
| `get_deploy_status` | 查询部署进度；成功时返回站点网址，失败时返回原因 |
| `list_my_sites` | 列出自己拥有或参与协作的站点 |
| `get_site_permissions` | 查看站点的访问策略、所有者、协作者，以及自己的角色 |
| `update_site_permissions` | 修改访问策略，约 1 分钟生效，不用重新部署 |
| `manage_collaborators` | 增删协作者，或转移所有权 |
| `get_site_analytics` | 按日、周或月查看访问量、独立访客、被拒次数和最近的访问记录 |
| `undeploy_site` | 下线站点；默认保留数据库，明确要求时才删除数据 |

<!-- tool-list:end -->

另外两个组件：

- **控制台**（`console.{你的域名}`）：在网页上看自己的站点和部署历史、改权限、管协作者、
  下线站点；管理员另有全局视图。建站仍然只在 Agent 里完成。站点与 MCP 不依赖它，但部署后
  验收要求它，所以标准部署包含它。
- **API Key 交换层**（`mcp.{你的域名}`，可选）：给只能配置静态 Header、走不了 OAuth 的 MCP
  客户端用。默认不部署。

## 设计要点

- **应用规范是唯一的约定**。规范包括 `site.json` 格式、目录约定和代码红线。哪个 Agent
  生成的代码都行，平台只按这份规范校验，不合规就不部署。
- **站点代码一律当作不可信**。代码由 AI 生成，依赖来自公共源。每个站点有自己的 IAM 角色，
  只能访问自己的数据表或数据库 schema；打包时不执行任何安装脚本。
- **鉴权全部在边缘完成**。站点代码里没有任何登录逻辑：Lambda@Edge 验证登录、按名单放行，
  再把可信的用户邮箱传给站点。为了让每个请求都经过鉴权，CloudFront 全站不缓存。
- **只读权限冒充不了用户**。会话签名的私钥锁在 AWS KMS 里，只有登录服务和控制台后端能调用签名
  （控制台只能签自己的面板会话），Edge 只有公钥。能冒充用户的只剩能调用签名、或能改签名/验签代码的
  少数高权限身份，所以平台的安全边界就是 AWS 账号本身。平台防谁、不防谁，见 [docs/security/account-trust-boundary.md](docs/security/account-trust-boundary.md)。
- **更新是原子切换**。每个站点的后端有 blue、green 两个别名。新版本先部署到备用的那一个，
  通过健康检查后才切换路由；切换后冒烟测试不通过，就按旧路由恢复。原子的是代码与路由，
  不含数据库：`fullstack-sql` 站点的迁移在切换之前执行、每条语句立即提交，健康检查失败时迁移
  也已经生效。所以迁移必须兼容还在运行的旧版本：只加表、加旧代码不写也不出错的列，删列或改名
  留到下一次部署。
- **三类站点**。`static`（纯前端）、`fullstack-nosql`（Node.js 后端 + DynamoDB）、
  `fullstack-sql`（Node.js 后端 + Aurora DSQL）。选 Aurora DSQL，是因为它不用 VPC、
  用 IAM 认证不用管密码、兼容 PostgreSQL，AI 生成的代码可以直接用。
- **全 Serverless**。没有常驻服务器，站点没人访问时几乎不产生计算费用。

## 部署到你自己的账号

需要准备：

- **一个 AWS 账号，区域必须是 `us-east-1`**。Lambda@Edge 和 CloudFront 用的证书都要求在
  这个区域。建议用专用账号：账号里能碰签名密钥的身份越少，安全边界越紧。
- **一个能改 DNS 的域名**，以及签发在 us-east-1 的 `*.{你的域名}` 通配符证书。建议用一个
  专用的二级子域（如 `app.example.com`）当平台域名。
- **一个身份源**，二选一：已有的 OIDC IdP（如 Okta、Entra ID、Google；飞书这类没有标准
  OIDC 端点的，经适配器接入），或者让平台自己再建一个 Cognito 用户池当 IdP，由管理员
  创建用户。
- **本机工具**：AWS CLI、Docker、Python 3.12 和 Node.js。

所有与账号相关的值只写在两份配置文件里：`site-builder/config.ini` 与 `router/config.ini`，从同目录的 `.example` 复制出来。

完整步骤见 **[site-builder/DEPLOY.md](site-builder/DEPLOY.md)**：先看「前置要求」，再照
「部署顺序总览」执行。有两点要先知道：

- 手册的小节编号不是执行顺序。组件之间有依赖，全新账号上执行器栈要部署两次。漏掉第二次
  不会报错，要到第一次建站才会暴露；手册顺序里的"夹具站点"一步就是用来发现这个问题的。
- 单账号实测，全新账号首装约 40 分钟（不含部署后验收），途中遇到了三处失败重试。三处的报错
  都指向错误的原因，手册里写了原样报错、触发条件和处理办法。

部署完成后，照手册的「部署后验收」跑一遍验收脚本，就能确认每个组件在你的账号里工作正常。
客户端怎么接入，见 [site-builder/docs/client-setup.md](site-builder/docs/client-setup.md)。

## 成本

部署手册按 PoC 规模估算：数十个低流量站点、路由层每月约 100 万次请求、Cognito 月活 50 人以内，合计每月约 17 到 52 美元。实际费用以账单为准。

## 当前限制

- 只能部署在 `us-east-1`。
- 站点后端只支持 Node.js（Express），不支持 Python 等其它运行时。
- CloudFront 全站不缓存，这是鉴权正确的前提。高流量站点要单独评估成本。
- 站点网址固定为 `app-{站点 ID}.{你的域名}`，不支持给单个站点绑定自定义域名。
- 身份以邮箱为准，IdP 必须提供 email；部署脚本按 OIDC 方式接入 IdP。

## 目录导览

| 路径 | 内容 |
|---|---|
| `site-builder/DEPLOY.md` | 部署手册：前置要求、部署顺序、各阶段操作、部署后验收、密钥轮换 |
| `site-builder/docs/client-setup.md` | Agent 客户端接入指引 |
| `site-builder/skills/site-builder/` | 建站 Skill：给 Agent 的应用规范、代码红线和模板 |
| `site-builder/contract/` | 应用规范的校验器 |
| `site-builder/mcp/` | 部署 MCP |
| `site-builder/deployer/` | 部署执行器：状态机、各步骤、CDK 栈 |
| `router/` | 路由与鉴权层：CloudFront + Lambda@Edge |
| `site-builder/auth/` | 登录服务与会话签名 |
| `site-builder/panel/` | 控制台 |
| `site-builder/key-proxy/` | API Key 交换层（可选） |
| `site-builder/clients/quick-desktop-proxy/` | 本地 MCP 代理：替客户端完成 OAuth 登录并自动续期（Claude Code 与 Amazon Quick Desktop 默认都用它） |
| `site-builder/fixtures/` | 三类站点的样例 |
| `site-builder/scripts/` | 部署、验收和运维脚本 |
| `site-builder/policies/` | 可选的账号级加固样例 |
| `docs/adr/` | 设计决策记录 |
| `docs/security/` | 账号信任边界：平台防谁、不防谁 |
| `docs/superpowers/` | 各阶段的设计与实施记录，是历史快照，不代表当前实现 |

## 开发与测试

- 本地 Python 环境一条命令建齐：`bash site-builder/scripts/bootstrap_venvs.sh`。
  需要 Python 3.12；加 `--host-deps` 会顺带给宿主 `python3` 装部署脚本要用的依赖。
- 各个包的测试命令不一样（有的借用别的包的 venv），照 [CLAUDE.md](CLAUDE.md) 的「测试命令」
  一节执行。这里不写测试数量，跑一遍的输出就是当前结果。

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
