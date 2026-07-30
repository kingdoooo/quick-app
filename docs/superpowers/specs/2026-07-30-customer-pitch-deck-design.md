# 客户方案介绍 PPT（HTML）设计文档

2026-07-30 brainstorming 产出。目标：一份面向**潜在客户技术人员**的方案介绍 PPT，
HTML 单文件形态，现场演讲配套（30-45 分钟技术交流）。

## 需求确认（已与用户逐项澄清）

| 决策项 | 结论 |
|---|---|
| 使用场景 | 现场演讲配套：每页要点少、图大字大，细节靠口述 |
| 语言 | 中文为主，AWS 服务名/技术术语保留英文 |
| 时长/页数 | 30-45 分钟，20 页 |
| 技术形态 | 纯手写单文件 HTML，零外部依赖（CSS/JS/SVG 内联） |
| 成本口径 | 企业内部工具画像：每 App 日均 100 次访问（50-200 区间取中）、几十用户 |
| 交付形态 | 部署到客户自己的 AWS 账号（数据不出域、成本即客户账单） |
| 额外内容 | 安全模型专页、二期路线图页、与 Manus 对比（重点：部署过程与体验；不提 Meta 收购） |
| 产出位置 | `docs/presentation/slides.html` |

## 叙事结构（方案 A：问题驱动）

痛点 → 方案总览 → 架构逐层 → 安全 → AWS 组件/成本 → Manus 对比 → 路线图。
Manus 对比放在成本之后：此时听众已理解差异化（自有账号、边缘鉴权、企业身份），
对比页说服力最强。

## 逐页大纲（20 页）

### 开场（P1-P3）

- **P1 封面**：标题「Quick 自动化建站平台——让业务人员的 Web App 自动部署到你的 AWS」
  + 副标题 + 状态行（已在真实 AWS 全量部署验证）
- **P2 痛点**：Agent 在企业推广的"最后一站"——Agent 已能生成完整 Web App 代码，
  落地卡在三件事：①非开发人员不会部署（AWS 控制台/CI-CD 门槛）
  ②运维成本（每个小工具配一套基础设施不现实）③权限失控（内部工具不能裸奔公网）。
  配"代码已生成 → ？ → 可用的内部应用"断层示意
- **P3 方案一句话**：业务人员在 Quick Desktop / Claude Code 里说"部署"→ 90 秒后得到
  `https://app-xxx.your-domain.com`，访问权限绑定飞书账号。
  配端到端时序小图（用户→Agent→MCP→URL），兼任演示流程页

### 架构与原理（P4-P9）

- **P4 架构总览**：五层架构 SVG（本 PPT 核心资产），标注每层职责与数据流
- **P5 ①建站 Skill + ②部署 MCP**：部署合同（site.json + 目录约定 + 红线）是锚点——
  任何 Agent 生成的代码都行，执行器只认合同；MCP 5 工具秒级返回、OAuth 携带飞书身份
- **P6 ③异步执行器**：Step Functions 流水线图（validate → 建库 → CodeBuild →
  站点 Lambda → 前端 S3 → 路由原子切流 → 冒烟），强调合同校验前置拦截
- **P7 ④路由与鉴权**：CloudFront 泛域名 + Lambda@Edge：查路由表 → 验会话 JWT →
  注入 x-user-email → 分流；站点代码零 auth 逻辑
- **P8 ⑤身份层**：Cognito 联邦到飞书（可换任意标准 IdP）；一套身份三处消费
  （站点访问 / MCP 部署 / Quick SSO）；身份即邮箱，对 IdP 无感
- **P9 三档 tier**：static / fullstack-nosql（Express+DynamoDB）/
  fullstack-sql（Express+Aurora DSQL）；DSQL 选型理由（免 VPC、闲置零成本、IAM 免密码）

P5-P8 复用 P4 的五层图：当前层高亮、其余压暗，听众始终有"地图感"。

### 安全专页（P10-P11）

- **P10 安全模型**：核心叙事"站点代码按不可信对待"——per-site IAM 角色 +
  PermissionsBoundary、DSQL per-site schema + 非 admin role、DynamoDB 前缀隔离、
  CodeBuild --ignore-scripts、红线扫描器。配隔离层次图
- **P11 鉴权正确性设计**：鉴权全部在边缘、全站禁缓存的原因（origin-request 只在
  cache miss 执行）、会话 JWT 双端字节级同步——"我们想清楚了"的细节页

### 落地与成本（P12-P15）

- **P12 AWS 组件全景**：一页列全所有服务及角色（CloudFront、Lambda@Edge、Lambda、
  S3、DynamoDB、Aurora DSQL、Step Functions、CodeBuild、Cognito、AgentCore、
  SSM、ACM、Route53），客户回去汇报可直接引用
- **P13 成本模型假设 + free tier**：流量画像 + 永久免费额度表（见下节）
- **P14 成本测算**：20/50/200 三档表 + SVG 柱状对比图（见下节）
- **P15 部署要求**：客户账号前置（us-east-1、域名+ACM 通配符证书、飞书企业自建应用、
  Docker），七阶段部署顺序，"换账号照手册可重部署"（已实测）

### 对比与展望（P16-P19）

- **P16 部署体验对比（vs Manus）**：两条时间线并排（见下节）
- **P17 架构取舍对比（vs Manus）**：解耦 Agent 的企业价值（见下节）
- **P18 二期路线图**：管理面板、在线改权限（不重部署）、协作者/管理员、
  MCP API Key、访问统计（PV/真 UV/访问审计）——来源 `docs/phase2-requirements.md`
- **P19 总结**：三个核心主张（跑在你的 AWS / 企业身份接管访问 / Agent 中立）+ 联系方式

### 附录（P20）

- 测试与质量数据（154 单测 + 4 E2E fixture 377s）、文档清单。现场不讲，备 Q&A。

## 成本模型（已用 AWS Price List API 核验，us-east-1，2026-07-30）

### 流量假设（写在 P13 页面上，客户可自行校准）

- 每 App 日均 100 次页面访问；每次访问 ~10 个 HTTP 请求，其中 30% 打后端 API
- 30% 的 App 用 fullstack-sql 档；每 SQL 查询 ~5 DPU（估计值，与站点代码强相关）
- 每 App 每月重部署 4 次；Edge 鉴权 30ms@128MB；站点 Lambda 100ms@512MB
- 全公司几百 MAU

### 核验过的单价（PPT 脚注引用）

| 项 | 单价 |
|---|---|
| Lambda@Edge | $0.60/百万请求 + $0.00005001/GB-s（**无 free tier**） |
| Lambda | $0.20/百万请求 + $0.0000166667/GB-s |
| CloudFront | $1.00/百万 HTTPS 请求（US） |
| DynamoDB on-demand | 读 $0.125/百万 RRU，写 $0.625/百万 WRU |
| Aurora DSQL | $8/百万 DPU + $0.33/GB-月 |
| Step Functions | $25/百万状态转换 |
| CodeBuild general1.small | $0.005/分钟 |
| AgentCore Runtime | $0.0895/vCPU-h + $0.00945/GB-h（消费型） |
| Cognito Essentials | $0.015/MAU |
| CloudWatch Logs | $0.50/GB 摄入 + $0.03/GB-月 |

### Free tier（always-free，每月，P13 单列一栏）

| 服务 | 永久免费额度 | 三档覆盖情况 |
|---|---|---|
| CloudFront | 1TB 流出 + 1000 万请求 | ✅ 200 App（600 万请求/180GB）仍全免 |
| Lambda | 100 万请求 + 40 万 GB-s | ✅ 20/50 全免，200 略超 |
| Aurora DSQL | 10 万 DPU + 1GB 存储 | 20 App 大部分覆盖 |
| Step Functions | 4000 次状态转换 | ✅ 20 App 全免 |
| CodeBuild | 100 分钟/月 | 部分覆盖 |
| Cognito | 10,000 MAU（Essentials/Lite） | ✅ 三档全免 |
| DynamoDB | 25GB 存储 | 存储全免，请求按量 |

### 测算结果（脚本精算值 → PPT 展示区间含 50-100% 缓冲）

| 成本项 | 20 App | 50 App | 200 App |
|---|---|---|---|
| Lambda@Edge（鉴权） | $0.5 | $1.2 | $4.7 |
| Aurora DSQL | $0.3 | $1.9 | $10.0 |
| CodeBuild | $0.7 | $2.5 | $11.5 |
| DynamoDB | $0.2 | $0.4 | $1.5 |
| CloudWatch Logs | $0.4 | $1.0 | $3.9 |
| AgentCore + SFN + S3 + Route53 | $0.9 | $1.5 | $4.9 |
| CloudFront / 站点 Lambda / Cognito | $0（free tier） | ~$0 | $0.2 |
| **理论合计** | **~$3** | **~$8.5** | **~$37** |
| **PPT 展示区间** | **$3-8** | **$9-18** | **$37-70** |

### P14 两个论点（替代原"边际递减"叙事——精算显示 free tier 在小规模吸收大头，
每 App 成本实为 $0.15→0.17→0.18，递减叙事不成立）

1. **Free tier 吃掉小规模的大部分成本**：20 App 理论月成本 ~$3
2. **200 App 也不到 $40-70/月**：对照传统模式（每 App 一套 ALB+最小实例 ≈$28/月
   → 200 App $5600+/月），差两个数量级

脚注：估算基于 us-east-1 2026-07 Price List API 现价与上述画像；DSQL DPU 与站点
代码强相关；PoC 实测账单 $15-50/月（含开发期反复部署）作现实锚点；实施前可用
AWS Pricing Calculator 按客户实际流量复核。

## Manus 对比（P16-P17）

定调："Manus 证明了'对话中一句话上线'是最好的建站体验——我们把这个体验搬进企业，
并把 Agent 解耦出来。"**不提 Meta 收购。**不贬低 Manus：它验证了体验标准，
个人/对外站点场景很好；本方案主场是企业内部工具 + 数据敏感 + 已有 Agent 投入。

### P16 部署体验对比（两条时间线并排，用户视角逐步对齐）

| 步骤 | Manus | 本方案 |
|---|---|---|
| 描述需求 | 对话框输入 prompt | Quick Desktop / Claude Code 对话（员工日常工具） |
| 生成代码 | Manus 云 VM 生成 | 任意 Agent 生成（合同约束产物格式） |
| 触发部署 | 说 "publish" | 说"部署"（MCP 调用，OAuth 自动带飞书身份） |
| 部署过程 | 平台内置托管，分钟级 | SFN 流水线全自动，**实测 ~90 秒**，可随时查进度 |
| 拿到 URL | xxx.manus.space | app-xxx.客户域名（企业品牌） |
| 配访问权限 | 面板配内置账号/角色 | site.json 写 allowed_users（飞书邮箱），访问者免注册飞书扫码 |
| 后续迭代 | 对话说改动，自动重部署 | 同样对话式重部署，路由原子切流不中断 |

结论行：体验对齐 Manus（对话→URL 一步到位），三个关键不同——跑在你的 AWS、
用你的企业身份、不绑定任何一家 Agent。

### P17 架构取舍对比（解耦 Agent 的企业价值）

| 维度 | Manus（一体化） | 本方案（解耦） |
|---|---|---|
| Agent 与部署 | 生成+托管绑死一个平台 | 部署合同做接口：任意 Skill+MCP 客户端接入 |
| 换 Agent 代价 | 迁移整个应用 | 零——合同不变，Agent 随便换/升级 |
| 代码/数据归属 | Manus 云（代码可导出） | 客户 AWS 账号，数据不出域 |
| 访问身份 | 平台内置注册登录 | 企业 IdP 联邦（飞书 SSO），员工零注册 |
| 安全边界 | 平台黑盒 | per-site IAM boundary / schema 隔离，可审计 |
| 成本 | 订阅+credits，难预测 | AWS 按量，200 App ~$40-70/月 |

底部点题："Manus 验证了体验标准；本方案把同样的体验实现在企业自己的云上，
并把'生成'与'部署'解耦——生成能力随 Agent 生态进步，部署基础设施保持稳定。"

（素材来源：manus.im/features/webapp、manus.im/docs/website-builder/
{publishing,access-control,custom-domains}，2026-07-30 检索）

## HTML 技术与视觉设计

### 技术形态

- 单文件 `docs/presentation/slides.html`，CSS/JS/SVG 全内联，零外部请求，双击即放
- 翻页：←/→、Space、PgUp/PgDn、点击屏幕左右边缘；Home/End 跳首尾；
  右下角页码 n/20；URL hash（#5）直接跳页、刷新保位
- 16:9 固定画布（1280×720 基准，transform: scale() 自适应窗口）
- 页面切换简单淡入；内容不做分步 build（不打乱现场节奏）
- @media print 每页一张 A4 横版，浏览器可直接导出 PDF

### 视觉设计（制作时先读 dataviz skill 的 palette 参考）

- 深色主题：近黑背景 + 高对比正文 + 单一强调色（当前层高亮、数字、结论行）
- 中文无衬线系统字栈（PingFang SC / Microsoft YaHei 回退），代码/URL 等宽字体
- 架构图：内联 SVG 五层图，P5-P8 复用并高亮当前层
- 成本页：分项表 + 三档 SVG 柱状图（遵循 dataviz 规范）
- 统一版式：左上章节眉标（痛点/架构/安全/成本/对比/路线）、标题、内容区、
  底部结论行（一句话带走要点）

### 内容红线

- 域名统一 `app-xxx.your-domain.com` 占位；账号 ID 等真实值一律不出现
  （与仓库"git 历史已清洗、不写真实账号值"约定一致）

## 验收标准

- 单文件双击打开即可全屏演示，翻页/跳页/页码正常，断网可用
- 20 页内容与本 spec 大纲一一对应；成本数字与本 spec 测算表一致
- 全文无真实账号 ID/域名/证书 ARN
- 浏览器打印导出 PDF 不跑版
