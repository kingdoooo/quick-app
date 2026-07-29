# Site Builder 二期需求候选清单（brainstorming 输入）

2026-07-29 一期全量部署验证完成后整理。范围决策：**大切**——管理功能一次做全。
本文档是需求输入，不是设计；新 session 从 brainstorming 开始，产出正式 spec 到
`docs/superpowers/specs/`。来源标注：〔§9〕= 一期设计文档范围外清单；
〔实测〕= 部署/使用中暴露的真实痛点；〔新增〕= 2026-07-29 讨论新提出。

## A. 管理面板（Web UI）

- **站点列表**：用户视图（我的站点）+ 管理员全局视图〔§9〕
- **站点详情页**：状态 / tier / owner / 协作者 / 访问策略 / 部署历史 / 访问统计
- **在线改权限**：改 require_login、allowed_users 名单**不需重部署**
  〔实测：现在改名单 = 改 site.json 重走部署，太重〕
- 下线 / purge_data 操作（带二次确认）
- ⚠️ 设计决策点：面板本身需要平台级权限（读全量 sites 表、改路由表），
  超出站点 runtime boundary 的能力面——**不能作为普通 site-builder 站点部署**，
  需要作为平台组件（或给面板一个特权部署形态）。dogfooding 的边界要想清楚。

## B. 权限与身份

- **权限修改 API**：MCP 工具与面板共用同一后端〔实测〕
- **站点协作者 / 所有权转移**：多人共管一个站点〔§9；实测：owner 死绑单人，
  owner 休假别人连状态都查不了〕
- **管理员角色**：全局站点列表、代管、强制下线；现在没人能管别人的站点〔实测〕
- **MCP 个人 API Key 认证**〔§9〕：不支持 OAuth 的客户端免 stdio 代理
  （Quick Desktop Remote MCP 只支持静态 Headers——实测，代理方案见
  `site-builder/clients/quick-desktop-proxy/`；API Key 是治本方案）
- **平台专用 user pool**〔新增〕：与上游（feishu-quick-sso / Quick）的 pool 解耦，
  pre-token 触发器等平台配置不再影响别的消费方
- 标准 IdP（Okta 等）路径真机验证〔新增；文档已备：DEPLOY.md ① 标准 IdP 分支〕
- OAuth PKCE + nonce 增强〔§9〕
- 按站点会话隔离（替代顶域共享 cookie）〔§9〕

## C. 访问记录 / 统计〔新增〕

- **每站点 PV，按天/周/月聚合**；面板图表展示 + MCP 工具可查
- **真 UV**：鉴权站点的访问者带 email（Edge 验签后已知身份）——能做到
  "按人"的独立访客数，甚至**访问审计**（谁在什么时候访问过），
  这比一般网站分析强，是权限模型的自然延伸
- 数据源选型（brainstorm 决策点）：
  - 方案 a：Edge origin-request 里异步埋点（DynamoDB 计数器 site_id×date）
    ——实现直接（全站禁缓存 = 每请求都过 Edge，天然全量），但加 Edge 延迟/成本；
  - 方案 b：CloudFront standard logs → S3 → 定时聚合（Athena 或 Lambda）
    ——零请求路径开销，但延迟高（分钟~小时级）、Host→site_id 需解析；
  - 公开站点（require_login=false）只有 PV 无 UV，两方案同。
- 保留期与成本：参照日志组 30 天先例定聚合粒度与 TTL

## D. 站点能力扩展（§9 其余，优先级预计低于 A-C）

- 自定义域名绑定
- GitOps 化：版本回滚、部署历史审计（与 A 的部署历史联动）
- ECS Fargate 有状态站点档位
- 计费 / 配额、多租户隔离
- Python 3.13 站点 runtime（db.py 模板、Python fixture、E2E）
- CloudFront 精细缓存（viewer-request 鉴权 + cache key 分区；做了 C 的方案 a 会受影响，注意联动）

## 一期遗留的已知限制（做二期时顺手核对）

- 顶域 cookie 共享登录（B 的会话隔离解决）
- 改权限必须重部署（A/B 解决）
- x-user-name URL 编码需站点解码（已修合同文档；已部署站点需重部署才生效）
