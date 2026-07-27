# 部署前置要求

部署本方案到**你自己的 AWS 账号**之前需要准备的资源。全部就绪后按
[DEPLOY.md](DEPLOY.md) 执行七个阶段。

下文用 `<BASE_DOMAIN>`、`<ACCOUNT_ID>` 等占位符表示你的实际值；填进
`site-builder/config.ini`（从 `config.ini.example` 复制）与
`router/config.ini`（从 `router/config.ini.example` 复制），两份配置都是
gitignored，不会被提交。

## 1. AWS 账号与区域

| 项 | 要求 | 为什么 |
|---|---|---|
| AWS 账号 | 任意，需有创建 IAM 角色/Lambda/CloudFront/DynamoDB/S3/Step Functions/CodeBuild/DSQL 的权限 | — |
| 区域 | **必须 `us-east-1`** | Lambda@Edge 函数与 ACM 证书（CloudFront 用）强制在 us-east-1；Quick Desktop 身份区域当前也要求 us-east-1。三者一致，全栈锚定该区 |

区域这一条不是偏好，是硬约束——换区需要改代码（见 DEPLOY.md 已知 Minor 里
region 硬编码的两处）。

## 2. 域名与证书

| 项 | 要求 |
|---|---|
| 域名 | 一个你能改 DNS 的域名，记为 `<BASE_DOMAIN>`（如 `example.com`） |
| DNS 托管 | Route53 hosted zone，或任意支持通配符 CNAME 的 DNS 服务商 |
| ACM 证书 | **`*.<BASE_DOMAIN>` 通配符证书，签发在 us-east-1，状态 ISSUED** |

站点 URL 形如 `https://app-<siteid>.<BASE_DOMAIN>`，登录端点固定为
`auth.<BASE_DOMAIN>`——所以必须是通配符证书，单域名证书不够。

```bash
# 申请通配符证书（DNS 验证）
aws acm request-certificate --region us-east-1 \
  --domain-name "*.<BASE_DOMAIN>" \
  --validation-method DNS
# 按输出的 CNAME 记录完成验证，等状态变 ISSUED：
aws acm describe-certificate --region us-east-1 \
  --certificate-arn <CERT_ARN> --query 'Certificate.Status'
```

证书 ARN 填 `router/config.ini` 的 `[CloudFront] certificate_arn`。

> **顶域 cookie 的影响**：会话 cookie 下发在 `.<BASE_DOMAIN>`，所有
> `app-*.<BASE_DOMAIN>` 站点共享一次登录。建议用**专用域名或子域**
> （如 `apps.example.com` 作为 `<BASE_DOMAIN>`），不要用承载其他业务的主域，
> 避免会话作用域覆盖无关系统。

## 3. 飞书企业自建应用

站点登录与部署权限都绑飞书账号，需要一个企业自建应用：

| 项 | 值 |
|---|---|
| App ID / App Secret | 创建后获取，① 阶段部署 SSO 时作为参数输入 |
| 必需权限 | 获取用户 userid、获取用户邮箱 |
| 重定向 URI | 由 ① 阶段的 Cognito Hosted UI 决定，创建 Cognito 后回飞书后台补填 |

**邮箱权限是必需的**：`owner`（谁部署的、谁能改/删站点）与访问名单
（`allowed_users`）都以飞书邮箱为标识，拿不到邮箱则整个权限模型不成立。

## 4. SSM 参数

| 参数名 | 何时创建 | 用途 |
|---|---|---|
| `/site-builder/jwt-secret` | **部署前手工创建** | 站点会话 JWT 的 HS256 签名密钥。Edge 函数与登录服务两处共用，必须一致 |
| `/site-builder/site-client-secret` | ① 阶段部署 Cognito 后写入 | 站点登录 App Client 的 secret |

```bash
# 生成并写入会话密钥（32 字节随机十六进制）
aws ssm put-parameter --region us-east-1 \
  --name /site-builder/jwt-secret --type SecureString \
  --value "$(openssl rand -hex 32)"
```

`jwt-secret` 必须在部署 `router/` 栈**之前**存在：栈部署时从 SSM 读它并
字符串替换注入 Edge 函数（Lambda@Edge 不支持环境变量）。若读取失败，
synth 会打印 `SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY` 警告——此时**不要继续部署**，
否则每个会话 token 都验签失败，表现为无限登录跳转。

## 5. 本机工具链

| 工具 | 要求 |
|---|---|
| AWS CLI | 已配置指向目标账号（`aws sts get-caller-identity` 确认） |
| CDK CLI | 用 `npx -y aws-cdk@latest`（部分环境的全局 CDK 版本过旧） |
| Docker | ④ 执行器栈需要（bundling 装 psycopg，拉 x86_64 镜像）；⑤ MCP 需要 buildx 构 ARM64 镜像 |
| Python | 3.12+（各包自带 venv 创建说明见 DEPLOY.md） |
| Node.js | 仅 `npx` 用于 CDK 与 MCP Inspector |

## 6. 成本预期（PoC 量级）

| 项 | 估算/月 |
|---|---|
| 路由层（CloudFront + Lambda@Edge + DynamoDB，1M 请求） | ~$2-5 |
| 站点 Lambda + S3（数十站点低流量） | ~$5-20 |
| Aurora DSQL 共享 cluster（低用量，按请求计费） | ~$0-10 |
| AgentCore MCP + Step Functions + CodeBuild | ~$5-15 |
| Cognito（月活 <50） | 免费额度内 |
| **合计** | **~$15-50/月** |

CloudFront 全站禁缓存是鉴权正确性的前提（origin-request 事件只在 cache miss
时执行），PoC 流量下成本影响可忽略；高流量场景需评估精细缓存方案（二期）。

## 就绪检查清单

```
[ ] AWS 凭证指向目标账号，区域 us-east-1
[ ] <BASE_DOMAIN> 的 DNS 可修改（Route53 hosted zone 或等价）
[ ] *.<BASE_DOMAIN> ACM 证书在 us-east-1，状态 ISSUED
[ ] 飞书企业自建应用 App ID/Secret（含用户 userid + 邮箱权限）
[ ] SSM /site-builder/jwt-secret 已创建（SecureString）
[ ] Docker 运行中；npx 可用
[ ] site-builder/config.ini 与 router/config.ini 已从 .example 复制并填好基础值
```

全部勾选后 → [DEPLOY.md](DEPLOY.md)
