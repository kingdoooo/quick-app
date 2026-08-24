# Quick 自动化建站方案 — 部署 Runbook

本文档是把本方案部署到**你自己的 AWS 账号**的操作手册，覆盖的是**需要真实 AWS
资源、DNS、IdP 凭证**的部署门禁——这些无法自动化，也是单元测试覆盖不到的部分。

**部署的是当前最新版本（含二期全部里程碑：控制台、API Key 交换层、访问统计、
blue/green 原子更新）**：照 ①→⑦ 走一遍即可（⑤b 控制台、⑤c API Key 均可选），
无需先部旧版本再升级。
已在运行旧版本的环境见[从一期环境升级](#从一期环境升级本仓库自己的环境走过这条路)。

- **区域**：`us-east-1`（Lambda@Edge 与 CloudFront 用的 ACM 证书共同强制）
- 下文 `{account_id}`、`{base_domain}` 等**花括号占位符需手工替换成你的实际值**
  （与 config.ini 中对应字段一致）。注意与 `config.ini` 里的
  `frontend_bucket = site-frontend-{account_id}` 区分——那处是脚本读取时自动插值的，
  不需要手改；本文档里的命令是给你复制粘贴执行的，必须先替换
- **中心配置**：`site-builder/config.ini` 与 `router/config.ini`（都从同目录
`.example` 复制，gitignored；部署过程中逐段回填）
- 设计文档 `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`，实施计划 `docs/superpowers/plans/2026-07-21-quick-site-builder.md`

---

## 0. 前置要求（全部备齐才开始）

### AWS 账号与区域

任意 AWS 账号，需有创建 IAM 角色 / Lambda / CloudFront / DynamoDB / S3 /
Step Functions / CodeBuild / Aurora DSQL 的权限。

区域**必须 `us-east-1`**：Lambda@Edge 函数与 CloudFront 用的 ACM 证书强制在
us-east-1。这不是偏好而是硬约束——
换区需要改代码（见文末 Minor 里 region 硬编码的两处）。

### 域名与通配符证书

需要一个你能改 DNS 的域名（记为 `{base_domain}`），以及**签发在 us-east-1 的
`*.{base_domain}` 通配符证书**。站点 URL 形如
`https://app-{site_id}.{base_domain}`，登录端点固定 `auth.{base_domain}`——
所以必须通配符，单域名证书不够。

```bash
# 申请通配符证书（DNS 验证）
aws acm request-certificate --region us-east-1 \
  --domain-name "*.{base_domain}" --validation-method DNS
# 按输出的 CNAME 完成验证，等状态变 ISSUED：
aws acm describe-certificate --region us-east-1 \
  --certificate-arn {cert_arn} --query 'Certificate.Status'
```

证书 ARN 填 `router/config.ini` 的 `[CloudFront] certificate_arn`。

**强烈建议用专用二级子域作为 `{base_domain}`**（如 `app.example.com`，而不是
`example.com`）。三个原因：

1. **通配符 DNS 会抢占主域下所有未定义子域**。路由层要求
   `*.{base_domain}` 指向 CloudFront，Edge 查不到路由表记录就返回 404。若主域下
   已有其他服务（`api.`、`chat.` 等各自指向不同 CloudFront/ALB），显式记录优先级
   高于通配符、不会被覆盖；但此后**新增**任何子域都会先落到本方案的 404，容易误诊。
2. **`auth.{base_domain}` 是本方案固定占用的登录端点**。若主域下这个名字已被占用，
   必须换 `{base_domain}`——代码里 `auth.` 前缀写死在 Edge 重定向、OAuth
   `redirect_uri` 与 cookie 作用域三处，不是配置项。
3. 会话 cookie 下发在 `.{base_domain}`，用专用子域能把作用域限制在建站平台内，
   不外溢到主域其他系统。

**用二级子域时注意证书**：ACM 通配符只匹配一层，`*.example.com` **不覆盖**
`*.app.example.com`。所以 `{base_domain}=app.example.com` 时必须单独申请
`*.app.example.com` 证书（已有的 `*.example.com` 证书不能复用）。

代码对二级子域无额外要求：Edge 取 host 第一段 label 作路由键
（`app-notes-abc.app.example.com` → `app-notes-abc`），层数不影响。

```
{base_domain} = app.example.com
  站点：  https://app-{site_id}.app.example.com
  登录：  https://auth.app.example.com
  DNS：   *.app.example.com  →  CloudFront
  证书：  *.app.example.com（us-east-1）
```

### 身份源（IdP）场景选择

平台对上游 IdP 的唯一硬要求：**Cognito 能联邦到它，且能拿到用户 email claim**
（owner / allowed_users 全以邮箱为标识）。按你组织的身份源二选一，
后文所有标 **【飞书】** 的步骤只在飞书场景执行，标准 IdP 场景跳过：

| | 【飞书】场景 | 【标准 IdP】场景（Okta / Azure AD / IAM Identity Center 等） |
|---|---|---|
| 适用 | 组织用飞书，用户以飞书账号登录 | 组织已有标准 OIDC/SAML IdP |
| Cognito 联邦方式 | 经**自建 OIDC 适配器**（① 部署的 API Gateway+Lambda，把飞书 OAuth 包装成 OIDC） | Cognito **原生 OIDC/SAML 联邦**，无需适配器 |
| ① 阶段做法 | 部署 feishu-quick-sso 上游方案 | 自建 user pool + 控制台添加 IdP（见 ① 的标准 IdP 分支） |
| email 来源 | 飞书通讯录（两个坑见下节） | IdP 的 email attribute mapping |
| 本手册验证状态 | **全流程真机验证过** | 架构兼容（平台代码不感知 IdP），未真机验证 |

> **"org" 的边界 = 你联邦的 IdP 的用户集合，不是邮箱域名**。
> `allowed_users: "org"` 的判定链是"会话有效 + 来自 trusted_idps 里的 provider
> 即放行"——代码里没有任何按 `@域名` 过滤的逻辑，邮箱只是标识符（owner/名单里
> 的键）。飞书场景：org = 创建企业自建应用的那个租户（成员邮箱可以是任意域，
> 含个人 Gmail）；标准 IdP 场景：org = 该目录里能对此应用完成 SSO 的用户（受
> IdP 侧 app assignment 约束）。想要"仅限本公司员工"，联邦你自己的企业 IdP 就
> 自动得到；IdP 里有外部账号时在 IdP 侧收窄，不要指望按邮箱域名筛。

> **与 Agent 客户端的账号体系无关**：Claude Code / Codex / Quick 各自怎么登录
> 是客户端自己的事，本方案对此不做任何假设、也无任何依赖。用户在客户端里添加
> 部署 MCP 时，走的是**本平台** Cognito 的 OAuth（联邦到你在这一步接入的 IdP）；
> 站点访问与控制台同理。唯一的实务建议：IdP 给出的邮箱要与你日常用于
> allowed_users 名单的邮箱一致，否则名单对不上人。

### 【飞书】企业自建应用

站点登录与部署权限都绑飞书账号，需要一个企业自建应用：App ID / App Secret
（① 阶段部署 SSO 时作为参数输入），**必需权限：获取用户 userid、获取用户邮箱**。

> **"组织"的边界 = 创建该应用的飞书租户**。企业自建应用只能被本租户成员授权
> （跨租户需上应用商店，不在本方案范围）。两点推论：
> ① 用**个人版飞书**建应用做 PoC 时，"租户"是你的个人版团队——`allowed_users:
> "org"` 实际只覆盖你自己和你邀请进团队的成员；给客户正式部署时应在**客户的
> 企业租户**里建应用，"org" 才是整个公司，且可用「可用范围」进一步收窄。
> ② 平台对邮箱域名无要求（个人 Gmail 也能当 owner），它只是身份标识，
> 能从飞书通讯录取到即可。
重定向 URI 需在 ① 部署完后回飞书后台「安全设置 → 重定向 URL」补填。
**注意填的不是 Cognito Hosted UI 域名**，而是上游 SSO 适配器（API Gateway）的
callback（2026-07-29 实测，漏注册报飞书错误码 20029"重定向 URL 有误"）：

```bash
# 从 IdP 配置取适配器 issuer，回调即 {issuer}/callback：
aws cognito-idp describe-identity-provider --user-pool-id {user_pool_id} \
  --provider-name Feishu --region us-east-1 \
  --query 'IdentityProvider.ProviderDetails.oidc_issuer' --output text
# 形如 https://xxxx.execute-api.us-east-1.amazonaws.com/prod
# → 在飞书后台注册 https://xxxx.execute-api.us-east-1.amazonaws.com/prod/callback
```

站点登录与部署 MCP OAuth 两条通道共用这一条注册。

邮箱权限不可省：`owner`（谁部署的、谁能改/删站点）与访问名单 `allowed_users`
都以飞书邮箱为标识，拿不到邮箱则整个权限模型不成立。

**⚠️ 两个条件缺一不可（2026-07-29 实测踩坑）**：
① 应用在「权限管理」开通 `contact:user.email:readonly` + `contact:user.employee:readonly`
并发布版本；② **用户在通讯录里真的填了邮箱**——飞书个人版账号默认只绑手机号，
邮箱为空。缺任一个的症状完全相同：OAuth 授权页正常走完，最后回调报
`invalid_request: Feishu Error - 500 internal_error`（SSO 适配器
`FeishuQuickSsoFeishuAdapterFunction` 日志里是
`ValueError: feishu user has no email`）。排查办法：用 app 的 tenant token 调
`GET /open-apis/contact/v3/users/{open_id}` 看返回里有没有
email/enterprise_email 字段。

### SSM 参数


| 参数名                                | 何时创建               | 用途                                   |
| ---------------------------------- | ------------------ | ------------------------------------ |
| `/site-builder/jwt-secret`         | **部署 ② 之前手工创建**    | 站点会话 JWT 的 HS256 签名密钥，Edge 函数与登录服务共用 |
| `/site-builder/site-client-secret` | ① 阶段建完 Cognito 后写入 | 站点登录 App Client 的 secret             |


```bash
aws ssm put-parameter --region us-east-1 \
  --name /site-builder/jwt-secret --type SecureString \
  --value "$(openssl rand -hex 32)"
```

`jwt-secret` 必须早于 ② 存在：② 的栈部署时从 SSM 读它并字符串替换注入 Edge
函数（Lambda@Edge 不支持环境变量）。读取失败时会打印
`SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY` 警告，此时**不要继续**——否则每个会话
token 都验签失败，表现为无限登录跳转。

**两个密钥都不进 Lambda 环境变量**：auth 服务只拿到参数名
（`JWT_SECRET_PARAM` / `CLIENT_SECRET_PARAM`），运行时读 SSM 并在容器内缓存。
原因是 `lambda:GetFunctionConfiguration` 会原样回显环境变量，而那是个很常见的
只读权限；JWT secret 泄漏尤重——Edge 只验 HS256 签名，拿到它即可伪造任意用户的
会话 cookie，绕过 owner / allowed_users / collaborators 全部判定。
auth 的执行角色因此需要 `ssm:GetParameter`（限定 `/site-builder/*`）与
`kms:Decrypt`（`ViaService` 限定 ssm），`deploy_auth.py` 每次运行都会收敛这两条。

#### ⚠️ 轮转 `jwt-secret`：当前实现下**不能就地改值**

两个密钥的轮转代价完全不同，别按同一套做：

- `site-client-secret`：**不能只改 SSM**。这个值不是我们自己定的——它必须是
  Cognito 那个 app client 认可的 secret。直接写一个新随机值进 SSM，5 分钟后
  auth 拿着它去换 token，Cognito 一律返回 `invalid_client`：**全员登录失败**
  （而且这正好是 `token_exchange_invalid_grant` 告警要发现的那类事故）。
  Cognito 现在支持一个 app client 同时有 **2 个 active secret**，按这个顺序做
  零停机轮转：

  ```bash
  # ① Cognito 侧新增第二个 secret（不影响现有那个）
  aws cognito-idp add-user-pool-client-secret --region us-east-1 \
    --user-pool-id <pool> --client-id <site_client_id>
  #    返回 ClientSecretDescriptor.{ClientSecretId, ClientSecretValue}：
  #    · ClientSecretValue —— 新 secret 明文，**只有本次响应里有**，立刻用于 ②；
  #    · ClientSecretId    —— 新 secret 的 id，记下来以便区分新旧。

  # ①b 列出该 client 的全部 secret，拿到**旧** secret 的 ClientSecretId
  #     （④ 要用它。`describe-user-pool-client` 只返回 ClientSecret 值、
  #      **不返回 ClientSecretId**，用它拿不到可删除的 id）
  aws cognito-idp list-user-pool-client-secrets --region us-east-1 \
    --user-pool-id <pool> --client-id <site_client_id> \
    --query 'sort_by(ClientSecrets,&ClientSecretCreateDate)[0].ClientSecretId' \
    --output text
  #     返回 ClientSecrets[]（每项含 ClientSecretId 与 ClientSecretCreateDate，
  #     不含明文）；上面的 --query 直接取**创建时间最早**的那个 id = 旧 secret。
  #     无需分页：一个 client 同时最多 2 个 secret，API 一次全返回。

  # ② 写进 SSM
  aws ssm put-parameter --region us-east-1 --overwrite \
    --name /site-builder/site-client-secret --type SecureString --value "<新值>"

  # ③ 等 auth 收敛（≤5 分钟，见 SECRET_TTL_SECONDS）后**实际登录验证一次**
  #    ——两个 secret 此时都有效，验不过就回退 SSM（见下），不要往下走。
  #
  #    回退方法：旧值此刻已无处可查（list-user-pool-client-secrets 只给元数据，
  #    add 的响应也只出现过一次），**唯一来源是 SSM 的历史版本**：
  #      aws ssm get-parameter-history --region us-east-1 \
  #        --name /site-builder/site-client-secret --with-decryption \
  #        --query 'Parameters[-2].Value' --output text
  #    取到后重新 put-parameter 覆盖回去即可（旧 secret 仍在 Cognito 里有效，
  #    因为第 ④ 步还没执行——这也是"先验证再删"顺序的意义）。

  # ④ 确认无误后删掉旧 secret（删不掉最后一个，所以顺序不能颠倒）
  aws cognito-idp delete-user-pool-client-secret --region us-east-1 \
    --user-pool-id <pool> --client-id <site_client_id> \
    --client-secret-id <旧 secret 的 id>
  ```

  顺序反了（先删旧、再加新）会在两步之间造成登录中断，且旧值已不可恢复。
- `jwt-secret`：**只改 SSM 会造成一段全员无法登录的窗口**。它有两个消费方，
  且更新速度不同：
  - auth（签发）——读 SSM，最长 5 分钟切到新值；
  - Edge（验签）——值是 CDK 部署时**字符串替换**注入的（Lambda@Edge 不支持
    环境变量），要重新部署 ② 并等 **10–20 分钟全球复制**。

  auth 先切、Edge 后到，这期间新签发的 cookie 在尚未更新的边缘节点验签失败，
  用户登录后立刻被踢回登录页；而**已登录用户的旧 cookie 在 auth 切换后仍在
  旧 Edge 节点上有效**，于是同一时刻不同用户、不同地区表现不一致。
  症状（无限登录跳转）与"密钥读取失败"完全一样，极难定位到密钥版本。

**当前实现不支持安全轮转**：Edge 只用单个 `{{JWT_SECRET}}` 占位符验签。真要
做双密钥（Edge 同时接受 `{新, 旧}`、复制完成后 auth 再切到新值签发、确认无旧
cookie 后移除旧值），**必须改这三处**——少改任何一处方案都部署不出去：

| 文件 | 改什么 |
|---|---|
| `router/infrastructure/stack.py:199` | 注入的地方。现在只 `.replace("{{JWT_SECRET}}", jwt_secret)`，要改成读并注入两个版本 |
| `router/infrastructure/lambda/origin_request.py` | `_verify_session_jwt()` 改成依次试两个 key |
| `site-builder/auth/session.py` + `login_handler.py` | 签发侧始终只用 active key，配合切换顺序 |

> ⚠️ 别只照"`origin_request.py` 与 `auth/session.py` 两处同步"去改：
> `session.py` 里的 `verify_session_jwt()` **只有测试在用**，不是生产验签
> 消费方（生产验签是 Edge 里的 `_verify_session_jwt`）。真正卡住双密钥部署的
> 是 `stack.py` 那一行——它不改的话，CDK 仍然只注入一个 secret，Edge 代码改了
> 也拿不到第二个值。

这是代码改动，不在一期/二期范围内。

**如果密钥已泄漏、必须立刻失效**（走"可用性换安全性"，别装作无损）：
按 `SSM 改值 → 立刻重部署 ② → 公告全员重新登录` 执行，并接受
10–20 分钟内登录不稳定。这是有意选择的取舍，不是回归——处置期间不要因为
"用户报登录跳转"就回滚 Edge，回滚只会把窗口拉长。

### 本机工具链


| 工具      | 要求                                                                 |
| ------- | ------------------------------------------------------------------ |
| AWS CLI | 已配置指向目标账号（`aws sts get-caller-identity` 确认）                        |
| CDK CLI | 用 `npx -y aws-cdk@latest`（部分环境全局 CDK 过旧）                           |
| Docker  | ④ 执行器栈需要（bundling 装 psycopg，拉 x86_64 镜像）；⑤ MCP 需 buildx 构 ARM64 镜像 |
| Python  | 3.12+                                                              |
| Node.js | 仅 `npx`（CDK 与 MCP Inspector）                                       |


### 成本预期（PoC 量级）


| 项                                              | 估算/月          |
| ---------------------------------------------- | ------------- |
| 路由层（CloudFront + Lambda@Edge + DynamoDB，1M 请求） | ~$2-5         |
| 站点 Lambda + S3（数十站点低流量）                        | ~$5-20        |
| Aurora DSQL 共享 cluster（低用量，按请求计费）              | ~$0-10        |
| AgentCore MCP + Step Functions + CodeBuild     | ~$5-15        |
| Cognito（月活 &lt;50）                             | 免费额度内         |
| **合计**                                         | **~$15-50/月** |


CloudFront 全站禁缓存是鉴权正确性的前提（origin-request 事件只在 cache miss
时执行），PoC 流量下成本影响可忽略；高流量场景需评估精细缓存（二期）。

## 部署顺序总览

**这份 Runbook 部署的是当前最新版本（含二期全部里程碑）。全新账号照 ①→⑦ 走一遍
即可，不需要"先部一期再升级"。** 已经跑着一期的环境要升级，见文末
[从一期环境升级](#从一期环境升级本仓库自己的环境走过这条路)。

组件间有依赖，必须按序：

```
①身份层        →  ②路由层  →  ③DSQL  →  ④执行器  →  ⑤部署MCP  →  ⑤b控制台   →  ⑥客户端接入  →  ⑦端到端彩排
   deploy_pool.py   CloudFront    cluster    SFN+Lambda   AgentCore     deploy_panel   Skill+MCP      RUN_E2E
   + deploy_auth    (Task 8)      (Task 13)  (Task 17)    (Task 20)     (二期 M3)      (Task 22)      (Task 23)
   (Task 3)
                                             ⑤c API Key（可选，二期 M4）· ⑤d 访问统计（二期 M5）
```

### ⚠️ 存量重部时顺序不同：**MCP 必须先于执行器栈**

上面那条 ①→⑦ 是**全新账号首次 bootstrap** 的顺序，那时 `config.ini` 的
`state_machine_arn` 还空着，必须先建栈再回填，MCP 才有 ARN 可用
（`deploy_agentcore.py` 启动时就在检查这件事，空值直接退出并让你回到 ④）。

**已经在跑的环境重部时，顺序要反过来：先 ⑤ MCP，再 ④ 执行器栈。**

| | 为什么 |
|---|---|
| 先 MCP 是安全的 | 存量环境里 `config.ini` 已回填，而 `deploy_agentcore.py` **只读 config.ini 里那个静态值、不读 CloudFormation 输出**（全文没有 `describe_stacks` 消费）⇒ 它不依赖本次栈更新 |
| 先栈**不**安全 | 新版 `validate` 在任务记录缺 `upload_etag` 时**一律 fail-closed**（不做假值兜底），而旧版 MCP 不写这个属性 ⇒ 从栈更新完成到 MCP 部署完成的那个窗口里，**所有**部署都会在第一步失败 |

**这条是无声的**：顺序错了的症状是"所有部署都在第一步挂"，与代码缺陷难以分辨。
**排障锚点**——看到下面这句原文就说明 MCP 还没部署（或 jobs 表读到了旧副本）：

```
任务记录里没有 upload_etag——请重新调用 confirm_upload（本任务可能由旧版MCP 创建）
```

### 存量站点迁移到 blue/green（M7；**只有存量环境需要**）

栈更新之后，已有站点还挂在旧的"函数级 Function URL"上（`$LATEST`）。新版部署逻辑对
**未迁移**的站点是 fail-closed 的（抛 `UnmigratedSite`，拒绝隐式半迁移），所以升级后
要跑一次迁移：

```bash
cd /path/to/repo            # 从仓库根跑
python3 site-builder/scripts/migrate_sites_to_blue_green.py              # 默认 dry-run，只打印计划
python3 site-builder/scripts/migrate_sites_to_blue_green.py --apply      # 真的写
python3 site-builder/scripts/migrate_sites_to_blue_green.py --apply --site-id <site_id>   # 单点重跑
```

- **默认 dry-run**：不带 `--apply` 时一个字都不写，先看计划再执行。
- **`--site-id` 可单点重跑**：某个站点失败后不必重跑全量。
- **`static` 站点会被报成 `skipped`，那不是失败**：纯静态站点没有后端 Lambda，
  没有 alias 可建，本来就不参与 blue/green。看到 `skipped: static` 是预期结果。
- **共用同一个旧 Function URL 的站点会被**拒绝**并要求人工处理**：那种情况下无法判定
  该把哪个站点切到哪个颜色，脚本不猜。

⑤c 与 ⑤d 不是独立的部署阶段，而是**跨已有组件的改动**：全新账号照 ①→⑦ 走一遍就
把它们一起装上了（两张统计表在 ④ 的栈里、埋点在 ② 的 Edge 里、读侧在 ⑤/⑤b 里）。
**已经在跑的环境要单独升级到 M5，见下面的 `⑤d 访问统计` 一节——那里的顺序是硬依赖，
反了不会报错，只会静默丢数据。**

依赖关系：②需要①产出的 JWT_SECRET（已在 SSM）与 edge role；④需要①的 boundary、②的 edge_role_arn、③的 DSQL endpoint；⑤需要④的 state_machine_arn 与①的 Cognito；**⑤b 需要②的 edge_role_arn、④的五张表与①的 jwt-secret**（可选组件：不部署它只是没有控制台，站点与 MCP 通道不受影响）。

④ 建 `site-admins` 表，而 **admin 种子必须在 ④ 之后单独跑**（CDK 只建表不写
数据，漏了则谁都不是 admin——见 ① 末尾）。

开始前的就绪清单（详见上面 §0）：

- [ ] AWS 凭证指向目标账号 / us-east-1（`aws sts get-caller-identity`）
- [ ] `*.{base_domain}` ACM 证书 ISSUED（us-east-1）
- [ ] `{base_domain}` DNS 可修改（Route53 hosted zone 或等价）
- [ ] SSM `/site-builder/jwt-secret` 已创建（SecureString）
- [ ] 身份源就绪：【飞书】企业自建应用（App ID/Secret，含用户 userid + 邮箱权限）
      / 【标准 IdP】OIDC/SAML 应用已建、email attribute 可映射
- [ ] Docker 运行中；`npx` 可用
- [ ] `site-builder/config.ini` 与 `router/config.ini` 已从 `.example` 复制并填好

---

## S1 加固（M01/M02/M05/M06）：存量环境的升级、闸门与回滚

**全新账号不需要这一节**：照 ①→⑦ 走一遍装出来的就已经是 S1 之后的版本。
这一节是给**已经在跑的环境**升级用的，写成可以在压力下从上往下照做，
不需要先读 spec（四条加固各自的道理在 `docs/superpowers/specs/`，这里只讲
怎么部、每个闸门证明了什么、失败怎么办）。

### 顺序不可变，且每一步停下都是安全的

| # | 动作 | 为什么必须在这个位置 |
|---|---|---|
| 0 | 部署前体检 `audit_policy_rows.py` | 非 0 就**先停**：那些 ACTIVE 行上线后既不能改权限也不能部署 |
| 1 | deployer 栈 | 提供新版 `ensure_site_role` / `site_policy`，第 3 步要调它 |
| 2 | panel + key-proxy + MCP **三个都重部** | `permissions.py` 被复制进这三个产物，漏一个就是产物陈旧而部署脚本一切正常。**第一波**强制重登从这一刻开始（见下面「三波重登」） |
| 3 | `backfill_site_role_policies.py --apply` | **必须在 1 之后**（它调新版 `ensure_site_role`）。全流程唯一不可逆的一步 |
| 4 | auth | **第二波**重登从这一刻开始 |
| 5 | router（Edge） | 必须在 auth 之后：反过来会让新签发的会话被 Edge 拒（登录循环） |
| 6 | 等 CloudFront `Status == Deployed` | **放在 5 之后而不是之前**：触发 Lambda@Edge 全球传播的是 router 部署本身，在它之前等待不会等到任何新版本。判据用 `Status`，不要盲等固定分钟数。**第三波**重登在这期间发生 |
| 7 | 真机验收（7 条 + 硬闸门） | 见下面「六个硬闸门」 |

> ⚠️ **本节的顺序假定部署窗口内没有并发业务**（本仓库当前是测试开发环境）。把同一套
> 代码升级到**已有用户流量**的环境时，只在部署前扫一次 jobs 表**是不够的**，必须先冻结
> 准入再 drain：`do_confirm_upload` 会事务性把 PENDING 改成 RUNNING 并
> `StartExecution`，`do_undeploy` 是对 undeploy Lambda 的异步调用——两条入口都能在
> "扫描 job=0"之后立刻被 MCP/panel 触发，而 CloudFormation 更新一组 Lambda **不是**
> 瞬时切换，于是旧 Validate / Provision / Undeploy 会在混合版本窗口里跑。
> 冻结方式二选一：① MCP/panel 两条入口共用一个维护开关，拒绝 deploy/confirm/undeploy；
> ② 临时 IAM deny（对发起者拒 `states:StartExecution` 与对 undeploy 函数的
> `lambda:InvokeFunction`）。冻结后要确认：jobs 表无 deploy/undeploy 处于 RUNNING、
> Step Functions 无 RUNNING execution、无活跃 site lease，**再**部署，跑完闸门才解冻。

**中途停下是安全且可重跑的**：若在第 3 步失败中止，此时是"deployer + 三个产物
已更新、auth/router 还是旧版"。这个中间态自洽——旧 auth 签发不带 `typ` 的会话，
旧 Edge 也不检查 `typ`，M05/M06 只是**还没生效**，不会互相打架。修掉原因后从
第 3 步继续即可。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# 0 部署前体检（非 0 就停下先修行，别继续）
python3 site-builder/scripts/audit_policy_rows.py

# 1 deployer 栈（M01 + M02）
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)

# 2 三个产物都带 permissions.py 的副本 —— 三个都要重部
#   **panel 不许加 --skip-frontend**：S1 改了 panel 前端（错误提示的渲染），
#   带上这个开关等于代码改对了而线上没换，界面与后端互相矛盾。
(cd site-builder/panel     && python3 deploy_panel.py)
(cd site-builder/key-proxy && python3 deploy_key_proxy.py)
(cd site-builder/mcp       && python3 deploy_agentcore.py)

# 3 存量角色 backfill（唯一不可逆的一步）
#   期间不要人工改/删 site-rt-* 角色。
python3 site-builder/scripts/backfill_site_role_policies.py            # 先看计划（不写任何东西）
python3 site-builder/scripts/backfill_site_role_policies.py --apply    # 真写 + 自带闸门

# 4 auth（第二波重登从这里开始）
(cd site-builder/auth && python3 deploy_auth.py)

# 5 router / Edge
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
```

**第 6 步**（等 CloudFront 分发 `Status` 回到 `Deployed`，第三波重登在这期间发生）
用计划 Task 10 Step 4 里那段 python：
`docs/superpowers/plans/2026-08-22-s1-isolation-and-auth-hardening.md`。
判据是分发的 `Status`（传播中 `InProgress`），不要盲等固定分钟数，也不要用 aws CLI
的退出码判断（它不可靠）。

**第 7 步**验收：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# **M01 闸门的退出码先存起来、在块末才生效——这个写法不要"整理"成直接中止。**
# 直接中止的话，一个与 M02/M05/M06 完全无关的数据条件（下面那条没有 tier 的
# ACTIVE 行，必须人工修）会把另外七条验收全部吃掉，那次部署就在**没有任何
# M02/M05/M06 证据**的情况下收尾。反过来把闸门挪到最后也不行：`--check` 是唯一
# 对全部 ACTIVE dynamodb 站点跑功能模拟的地方（`--apply` 结尾只做结构检查），
# 它必须留在执行记录最前面。
set +e
python3 site-builder/scripts/backfill_site_role_policies.py --check
m01_rc=$?
set -e
echo "M01 闸门退出码：$m01_rc（非 0 会在本块末尾让这一步失败）"

# per-site 数据表的归属完整性。**与 M01 闸门不冗余**：那条比的是"实际 policy
# == 按代码推导的期望 policy"，而期望值是从 sites 行的 data_tables 推出来的
# ——两边**同源**，data_tables 被污染时两边一致、闸门照样全绿。这条引入
# 「表自己的 tag」作为独立信源，并要求 role 的表 ARN 集合与**同一个站点**
# 自己的表精确相等（不多、不少、不含通配、不含别站的表）。
python3 site-builder/scripts/verify_site_table_integrity.py

# 表名碰撞的**行为**证据：自建碰撞对（B 正常部署、A 的碰撞 manifest 必须被线上
# validate 拒绝、B 侧逐字段不变、purge 三态幂等），跑完自清理并强一致读回。
# 会真实部署/下线两个一次性站点（约 4 分钟）。--json-out 可留结构化审计摘要。
python3 site-builder/scripts/verify_table_collision_e2e.py

# **必须在业务验收之前**：唯一能证明"CloudFront 现在关联的 Edge 就是这份源码"的闸门。
# 少了它，M05 的 Edge 半边与 M06 整条可以**完全没生效而四条业务验收全绿**——
# 新会话多带一个 typ claim，旧 Edge 只是忽略它；单枚正常 cookie 在旧、新 Edge 上
# 都放行。也就是说业务探针**结构上**看不出 Edge 还是旧版。放在这里而不是最后：
# Edge 是旧的时候，后面几条的结果没有解读价值。
bash    site-builder/scripts/verify_deployed_edge.sh         # 逐行比对分发关联版本的产物 == 本地源码 + S1 哨兵

python3 site-builder/scripts/verify_session_token_semantics.py  # M05/M06 的**行为**证据（只发 GET）
python3 site-builder/scripts/verify_deployed_components.py   # 第 2 步之后必跑：唯一能发现**三个 Lambda 产物**陈旧的闸门（不含 Edge，见上）
python3 site-builder/scripts/verify_permission_matrix.py     # M02 之后唯一覆盖权限矩阵端到端的闸门
python3 site-builder/scripts/verify_console_e2e.py           # 跑之前先在浏览器登录一次（重登让 token 失效了）
bash    site-builder/scripts/smoke_router.sh                 # 路由层冒烟（含 65s 等 Edge 缓存）

exit "$m01_rc"
```

期望：`不合格的 site-rt-* 角色：0`、`M01 闸门退出码：0`，七条验收全部通过，整块退 0。
`verify_console_e2e.py` 报 token 过期时先 `node site-builder/clients/quick-desktop-proxy/auth.js`
重新登录一次。

### 六个硬闸门：各自证明什么，以及**不**证明什么

| 闸门 | 什么时候跑 | 它证明 | 它**不**证明 |
|---|---|---|---|
| `audit_policy_rows.py` | 第 0 步（部署前） | 没有 ACTIVE 行会被新的严格解析拒绝。退出码**只由 ACTIVE 行驱动** | 非 ACTIVE 行的问题只报成警告、不进退出码；畸形 `status`（`N`/`NULL`/`L`/缺失）四种形态只有夹具覆盖过，真表里从未出现过这种行 |
| `backfill_site_role_policies.py --check` | 第 7 步 | 四层：site-scope 与期望**完整等值**、角色上只有 site-scope 一条 policy、ACTIVE 站点的角色反向存在、全部 dynamodb 站点过 IAM 模拟器**全部六个数据动作** | **不看信任策略**（`AssumeRolePolicyDocument` 被放宽的角色四层全过）、**不看 `site-runtime-boundary` 还挂着没有**——而 `ensure_site_role` 只在**新建**角色时挂 boundary，所以 `--apply` 不会把被摘掉的 boundary 挂回去。DSQL 站点只有文本等值，没有功能模拟 |
| `verify_deployed_components.py` | 第 7 步，且**必须在第 2 步之后** | 线上产物里的 `permissions.py` / `common.py` / `session.py` / `login_handler.py` 与仓库逐字节一致；**每个 `site-deployer-*` 函数自己的 handler**（从部署定义的 Handler 派生，如 `provision_dynamodb.py` / `undeploy.py`）与本地一致；validate 包的 `contract/redlines.py` **和 `contract/schema.py`** 都一致 | 这是**唯一**能发现"某个 **Lambda** 产物漏部了"的闸门。漏一个的症状是产物陈旧而部署脚本全程正常。曾只比守卫三件套——"common 新、handler 旧"的半量部署照样全绿（Codex deployed-state 复审 2026-08-24 指出，判定已抽成纯函数反向验证）。**它不覆盖 Edge**：它下载 Edge 产物，但只问一个问题（`mcp` 有没有进 `PLATFORM_SUBDOMAINS`），M05/M06 的 Edge 半边它一个字都没看 |
| `verify_table_collision_e2e.py` | 第 7 步（部署后可随时跑；**会真实部署/下线两个一次性站点**） | 表名碰撞在真机上关闭的**行为**证据：B 正常部署（正对照）、A 的碰撞 manifest 被线上 validate 以 `TABLE_NAME_RE` 原话拒绝、A 侧零资源残留、B 侧逐字段不变（表 schema/tags/role policy/data_tables）、purge 三态幂等（对已购清站点重复 purge 收敛到 DELETED）。跑完强一致读回核对清零，输出含 site/job ID 的 JSON 摘要 | 清理与幂等探针**直接 Event 调 `site-deployer-undeploy`**（复刻 MCP 建 job 后的动作）——证明的是部署函数行为，不是 MCP/panel 鉴权链路（那由 `verify_api_key_e2e.py` 覆盖）。sites/jobs 的 DELETED 历史行保留 |
| `verify_deployed_edge.sh` | 第 7 步，**在业务验收之前**（第 6 步等到 `Deployed` 之后） | CloudFront **当前关联的那个版本**的产物与本地 `origin_request.py` 逐行相同（只允许占位符行有差异）、占位符全部替换、安全开关是收紧值，外加 M05（查 `typ`）与 M06（逐个验、不截断）两条哨兵 | **证据等级是静态产物比对，不是行为探针**：它证明"跑在线上的就是这份源码"，M05/M06 的**行为**由下面那条闸门单独证。也不看非默认 cache behavior 上的关联 |
| `verify_site_table_integrity.py` | 第 7 步（部署后自检，也可随时跑） | per-site 数据表的归属：ACTIVE NoSQL 站点的表存在且 tag `project`/`site_id` 正确；**每个 `site-rt-{site_id}` 角色的 DynamoDB 表 ARN 集合与同一站点自己的表精确相等**（不多、不少、无通配、不含别站的表）；DSQL 角色没有任何表 ARN；static（engine=none）站点**没有**运行时角色是合法态（角色存在时表 ARN 集合必须为空）；全部 `data_tables` 逻辑名符合 `TABLE_NAME_RE` | 只看**当前 ACTIVE** 站点——历史/DELETED 行不做全量对账（表可能已删），但它们含连字符的 `data_tables` 仍会被报出来。不核 DSQL 侧的 schema/role 隔离（那在 PG 层）。要害判定抽成了纯函数 `role_arn_problems`，反向验证在 `deployer/tests/test_verify_site_table_integrity.py` |
| `verify_session_token_semantics.py` | 第 7 步，紧跟上一条 | M05/M06 的**真机行为**：遮蔽 cookie 排在合法会话之前时 `/console-session` 仍换出升级码、Edge 侧仍放行（含 14 条遮蔽的量级）、console 升级码当站点会话被拒；含正对照（单枚合法会话能进）与负对照（无 cookie 仍 302）。**只发 GET，不写数据** | 它只挑路由表里第一个 `require_auth=True` 的站点，不遍历全部站点；候选条数上限那一类**回归**残留由单测的结构守卫管，不在这里 |

另两条：`verify_permission_matrix.py`（权限矩阵端到端，M02 之后唯一覆盖它的）、
`verify_console_e2e.py` + `smoke_router.sh`（控制台与路由层）。

**为什么必须有 `verify_deployed_edge.sh` 这一条**（否则整套 S1 验收对 M05/M06
可以全绿而 Edge 根本没换）：新会话多带一个 `typ` claim，**旧 Edge 只是忽略这个
它不认识的 claim**；单枚正常 cookie 在旧、新 Edge 上都放行。于是四条业务验收
**结构上**分辨不出 Edge 是新是旧——它们没有一条会发"升级码当站点会话"或
"同名遮蔽 cookie"这种请求。这不是"多跑一条更稳妥"，而是补上唯一的判据。

**闸门命令是 `--check`。裸跑不是闸门，绝不要接进任何发布检查**：裸跑打印计划，
"policy 与期望不一致"这类**不计入退出码**（它退 0，这是故意的——第 3 步要在
`set -e` 下先裸跑再 `--apply`），只有"需人工"的几类（多余 policy、角色缺失、
判不出 engine）才让它退 1。两条命令对同一份不合格数据的差别**只在退出码上**，
读输出读不出来。

**automation 只许看退出码与计数，绝不要 grep 输出文本。** 那些补救文案来自运行时
的 `permissions.py`，不是稳定契约：两次真机跑就因为中途改过那段措辞而输出不同，
S1 收尾又改了一次（给"缺 owner"单独一支）。契约是退出码，以及
`严格解析会拒绝的 ACTIVE 行：N` / `不合格的 site-rt-* 角色：N` 这两个计数。

### 三波强制重新登录，都是预期行为

按发生顺序：

1. **第 2 步 panel 部署完成那一刻**——控制台的 `__Host-sb_console` cookie 全部失效
   （新 panel 要求 `typ`，旧 cookie 没有）。**只影响写操作**：GET 读接口不要面板
   会话，所以控制台看起来是正常的，直到用户第一次改权限/加协作者，前端收到
   `401 {"need":"console-session"}` 后**自动**整页跳一次 `auth.{base_domain}/console-session`
   再回来。**它自愈，不需要运维介入**：此刻 auth 还是旧版，会照常接受不带 `typ`
   的顶域会话并发一次性 code，新 panel 用它签出带 `typ` 的新面板 cookie。
   （前端对一次浏览器会话只自动重试一次；若用户看到"面板会话无法建立"，
   让他关掉标签页重开——那个标记在 sessionStorage 里。）
2. **第 4 步 auth 部署完成那一刻**——`/console-session` 开始拒绝不带 `typ` 的旧
   顶域会话，控制台用户被要求重新登录。
3. **第 6 步 CloudFront 传播完成那一刻**——站点访问的旧会话失效，第三波。

spec 里只写了后两波。第一波是最终复核发现的，症状是"刚部完 panel，改权限的人被
弹去登录"——**别当成故障去查**。

### 失败处置速查

| 你看到 | 怎么办 |
|---|---|
| `--apply` 报「验证失败」 | **先重跑 `--check` 再下结论**。IAM 与策略模拟器是最终一致的，脚本内建 2/4/8 秒退避只能减少、不能消除一次**完全正确**的跑被记成红 |
| `--check` 报某行「sites 行没有 tier，判不出 engine」 | **脚本永远修不到 0，必须人工修那一行**（`tier` 只在部署成功路径写，所以这是可达状态，不是假设）。修好再重跑；这一条不影响另外七条验收（那就是 Step 5 把退出码延后生效的原因） |
| `--check` 报「site-scope 之外还有别的 policy」 | 需人工移除那条多余的 inline/attached policy。脚本**不自动删未知 policy** |
| `--check` 报「ACTIVE 站点的角色缺失」 | 先查为什么没了。脚本**不自动重建**（自动建会盖掉根因，也会让备份里的 `null` 出现第二种含义） |
| 「临时备份文件已存在——判为另一个 backfill 正在运行」 | **等一下再重跑，绝不要删那个 `.tmp`**。它同时是跨进程锁；此刻一笔 IAM 写入都没发生。若确认是上一次崩溃的残留，人工看过内容再删 |
| 想让两个人同时跑 backfill | 别。锁只罩住快照文件的读-改-写，罩不住之后的 IAM 写入循环——两个人可以并发改 IAM（快照不会丢，但没人说得清最终状态由谁决定） |
| 控制台/站点大面积 302 | 先确认第 5、6 步的顺序没颠倒：Edge 要求 `typ` 而 auth 还在签不带 `typ` 的会话 ⇒ 登录循环。回滚见下 |

还有一条与部署无关但会浪费时间的：**MCP/panel/key-proxy 正在部署时不要跑 deployer
测试套件**。三个部署脚本都会把 `deployer/functions/common.py` 之类的共享模块复制进
自己的包目录、打完包在 `finally` 删掉，MCP 那次的窗口覆盖整个 buildx+push（分钟级）。
S1 已经把那几条"唯一定义"守卫的豁免改成**按内容**判定，所以逐字节相同的副本不再
让它们变红；但复制被中断/替换到一半时副本就不再逐字节相同，那时守卫会红，而那个红
是真的（文件确实不一样），排查会指向完全错误的方向。

### 回滚

**先 router，再 auth，严格逆序。** 反过来（先回滚 auth 让它重新签发不带 `typ` 的
token，而 Edge 仍要求 `typ`）会让**所有**新签发的会话被 302，用户陷入登录循环。
panel 不需要参与任何方向：旧 panel 带着自己那份旧 `session.py`，新 panel 只验它
自己签的 cookie。

**M01 的角色 policy 单独回滚**，用 `--apply` 留下的快照。它是第一笔 IAM 写入
**之前**就原子落盘并 fsync 过的（内容与目录各一次），所以"IAM 已改而回滚材料没了"
这个窗口不存在；重跑只合并、不覆盖已有快照，所以第一份原始 policy 一直在。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
"""把 per-site 角色的 site-scope policy 回滚成 backfill 之前的样子。

**先看清代价**：快照里存的多半是带 `site-data-{site_id}-*` 通配的旧 policy，
写回去就等于把 M01 重新打开（通配是**向前看**的，会覆盖将来创建的嵌套 site_id）。
所以这是可用性措施，不是终态：查明 backfill 为什么写坏之后要重新 `--apply`。

**两种条目两种动作**：
  · 有 policy 文档 ⇒ put_role_policy 写回；
  · `null` ⇒ 备份时那个角色**存在、但没有 site-scope**（脚本用 GetRole 复核过，
    所以 null 不可能是"角色不存在"）⇒ 正确动作是 delete_role_policy，
    删掉 backfill 新写的那条，而不是写回一个不存在的文档。
**本循环从不删除角色**，也不碰信任策略、boundary、别的 policy。
整个循环幂等：中断后原样重跑即可。
"""
import configparser
import json
import pathlib

import boto3
from botocore.exceptions import ClientError

SNAP = pathlib.Path("site-builder/scripts/backfill-old-policies.json")
POLICY_NAME = "site-scope"

snap = json.loads(SNAP.read_text())
cfg = configparser.ConfigParser(interpolation=None)
cfg.read("site-builder/config.ini")
acct_now = boto3.client("sts").get_caller_identity()["Account"]

# 动手之前先核对元数据：快照、config、当前凭证三者必须是同一个账号/区域。
# 不核对的话，切错 profile 就会把 A 账号的资源 ARN 写进 B 账号的同名角色。
assert snap.get("schema_version") == 1, f"未知快照格式：{snap.get('schema_version')}"
assert snap["account_id"] == cfg["Platform"]["account_id"].strip() == acct_now, (
    f"账号不一致：快照 {snap['account_id']} / config "
    f"{cfg['Platform']['account_id'].strip()} / 当前凭证 {acct_now}——拒绝执行")
assert snap["region"] == cfg["Platform"]["region"].strip(), (
    f"区域不一致：快照 {snap['region']} / config {cfg['Platform']['region'].strip()}")

iam = boto3.client("iam")
restored = deleted = already = 0
for name, doc in sorted(snap["roles"].items()):
    if doc is None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName=POLICY_NAME)
            deleted += 1
            print(f"  {name}: 删掉了 backfill 新写的 site-scope（快照里是 null）")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
            already += 1          # 已经回滚过；幂等重跑走到这里
            print(f"  {name}: 已无 site-scope，无需动作")
    else:
        iam.put_role_policy(RoleName=name, PolicyName=POLICY_NAME,
                            PolicyDocument=json.dumps(doc))
        restored += 1
        print(f"  {name}: 写回快照里的旧 policy")
print(f"\n回滚完成：写回 {restored}，删除 {deleted}，本来就没有 {already}。"
      "**没有删除任何角色**。")
print("提醒：写回的旧 policy 多半带通配 ⇒ M01 对这些站点重新打开，"
      "查明原因后要重新跑 --apply。")
PY
```

---

## 决定安全边界的几项配置（先读这节）

这几项**没做完，安全边界就没生效**，而代码里全绿的测试覆盖不到它们
（都是配置与一次性动作）：

1. **身份层用脚本建，不要手工建 pool**：

   ```bash
   # 先在 site-builder/config.ini 填好 [IdP] 段（provider_name/issuer/client_id/
   # client_secret），再跑。幂等可重跑。
   python3 site-builder/scripts/deploy_pool.py
   ```

   `client_secret` 也可以不落磁盘——用环境变量注入，优先于 config 值：

   ```bash
   # secret 存在 Secrets Manager 时（明文只存在于子进程，不进 shell 历史）
   asm-exec -- env SB_IDP_CLIENT_SECRET='{{resolve:secretsmanager:<secret-arn>:SecretString:<json-key>}}' \
     python3 site-builder/scripts/deploy_pool.py
   ```

   走飞书适配器路径时，联邦 secret 在适配器自己的 Secrets Manager 条目里
   （Lambda 环境变量 `SECRET_ARN` 指向它，JSON 键名见适配器 `handler.py` 的
   `Secrets` 类——本仓库对接的那版用 `cognitoClientSecret`）。

   两者都缺时脚本在**部署时**明确退出——空 secret 建出的 provider 只在用户
   登录换 token 那一刻才报 `invalid_client`，症状是"登录页正常、回调失败"，
   难查得多。

   #### 轮换这个 secret（泄漏后必做）

   **先分清它是什么**：走飞书适配器路径时，Cognito IdP 里那个 `client_secret`
   **不是飞书 App Secret**。看 `describe-identity-provider` 就明白——
   `client_id` 是 `cognito-federation-client`、`oidc_issuer` 指向适配器自己的
   API Gateway。它是**适配器 ↔ Cognito** 这一对的凭证，两份副本：

   | 持有方 | 位置 |
   |---|---|
   | Cognito | IdP `ProviderDetails.client_secret` |
   | 适配器 | 它自己的 Secrets Manager 条目，JSON 键 `cognitoClientSecret` |

   所以**飞书后台一个字都不用改**（飞书 App ID/Secret 是同一条 Secrets Manager
   记录里的**另外**几个字段，与本次轮换无关）。这一点值得先确认，否则会误以为
   要去协调飞书管理员、把一个 10 分钟的操作拖成跨团队排期。

   **影响面比想象的小**：这个 secret 只在"Cognito 拿授权码去适配器换 token"
   那一步用到。所以
   - **已登录的用户不受影响**——会话 JWT 是平台自己用 `JWT_SECRET` 签的；
   - **refresh 也不受影响**——Cognito 刷新不回调 IdP；
   - 受影响的只有**轮换窗口内的新登录**（回调报 `invalid_client`）。

   **窗口不可避免**：上游适配器（`aws-samples/sample-for-amazon-quick-sso-with-feishu`，
   本仓库不含其源码）不同时接受新旧两个值。所以两侧更新之间必然有一段新登录失败，
   选低峰期做，两条命令背靠背执行。

   **适配器确实校验这个 secret（2026-08-13 实测，不是假设）。** 判定方法可复用——
   拿一个**明显无效**的 code 去打两次 `{issuer}/token`：不消费任何真实凭据、不改
   任何状态，只看两次报错的差异：

   | 探测 | 实测结果 | 含义 |
   |---|---|---|
   | client_secret **正确** | `502 {"error":"upstream_error"}` | 过了客户端认证，之后拿假 code 去飞书换才失败 |
   | client_secret **错误** | `401 {"error":"invalid_client"}` | 在客户端认证这一步就被拒 |

   两次报错不同 ⇒ 校验真实存在 ⇒ **两侧必须同值，③ 不能跳**（只改 Cognito 一侧的
   后果是所有新登录立刻 `invalid_client`）。这条值得记**方法**而不只记结论：哪天
   换了适配器实现、两次报错变成一样，那说明它不校验客户端凭证——那时该修的是
   适配器，而不是庆幸轮换省了一步。

   顺带一条会被低估的事：本节上文记着适配器的 `/authorize` **不校验 `redirect_uri`**。
   拿到这个 client_secret 的人就能在它的 token 端点换 code——两条弱点叠加，比单看
   泄漏更值得处理。

   **适配器可能缓存 secret**（源码不在本仓库，缓存行为未核实）。若 ③④ 都做完后
   登录仍报 `invalid_client`，**先等约 5 分钟**让 warm 容器回收再试一次，**然后**
   才考虑回滚——否则会把一次缓存滞后误判成轮换失败，进而把已经正确的两侧又改回旧值。

   ```bash
   # ① 记下当前指纹（只打指纹，绝不打印密文）——回滚与核对都要它
   python3 - <<'EOF'
   import boto3, configparser, hashlib
   c = configparser.ConfigParser(interpolation=None); c.read("site-builder/config.ini")
   assert c.sections(), "config.ini 读空了"
   pool = c["Cognito"]["user_pool_id"].split("#")[0].strip()
   name = c["IdP"]["provider_name"].split("#")[0].strip()
   d = boto3.client("cognito-idp", region_name=c["Platform"]["region"].split("#")[0].strip())
   v = d.describe_identity_provider(UserPoolId=pool, ProviderName=name
       )["IdentityProvider"]["ProviderDetails"]["client_secret"]
   print(f"当前 client_secret: {len(v)} 字符, sha256[:12]={hashlib.sha256(v.encode()).hexdigest()[:12]}")
   EOF

   # ② 生成新值（48 字符，与现值同形态）。**别落盘、别进 shell 历史**
   #    ——直接管进下一步，或存进剪贴板管理器之外的临时变量
   openssl rand -base64 36 | tr -d '\n' | cut -c1-48

   # ③ 更新**适配器**那一侧：只改它 Secrets Manager 条目里的 cognitoClientSecret
   #    键。**必须 read-modify-write**——这条记录是多字段 JSON（同一条里还装着
   #    飞书 App Secret），只发一个键的写入会把其它字段一起覆盖掉，结果是适配器
   #    连飞书都连不上，比泄漏本身严重得多。用 jq 保住其它字段：
   NEW="$(openssl rand -base64 36 | tr -d '\n' | cut -c1-48)"
   ARN="<adapter-secret-arn>"
   #    **用 `env.NEW` 而不是 `jq --arg s "$NEW"`**：后者会把展开后的明文放进
   #    jq 的**进程参数**里，同机的 `ps` / 进程审计能看到它，与"密文不进命令
   #    参数"的目标相矛盾（Codex 审查 2026-08-13 P2-2）。环境变量只有同一用户
   #    读得到 /proc/<pid>/environ，暴露面小一档。
   aws secretsmanager get-secret-value --secret-id "$ARN" \
        --query SecretString --output text \
     | NEW="$NEW" jq '.cognitoClientSecret = env.NEW' \
     | aws secretsmanager put-secret-value --secret-id "$ARN" \
         --secret-string file:///dev/stdin
   #    改完核对**键的数量与名字没变**（只打键名，不打值）：
   aws secretsmanager get-secret-value --secret-id "$ARN" \
        --query SecretString --output text | jq -r 'keys | @csv'

   # ④ 更新 Cognito 那一侧：走**唯一的写入口** deploy_pool.py，明文只经环境变量
   #    进子进程、不落 config.ini
   asm-exec -- env SB_IDP_CLIENT_SECRET='{{resolve:secretsmanager:<adapter-secret-arn>:SecretString:cognitoClientSecret}}' \
     python3 site-builder/scripts/deploy_pool.py

   # ⑤ 用 ① 那段再打一次指纹：必须与 ② 的新值一致、与 ① 的旧值不同
   ```

   **为什么第 ④ 步不写个专用轮换脚本**：`deploy_pool._ensure_oidc_idp` 是
   `ProviderDetails` 的**唯一写入方**（它把 issuer / scopes / 属性映射一并声明）。
   再写一个只改 secret 的脚本就是第二份真源——漏掉 `email_verified` 映射之类的字段
   时，症状是"登录成功但邮箱变成未验证"，而那正是整个授权模型的地基。
   `deploy_pool.py` 幂等，重跑它是安全的（它同时会读回并保住 client 的
   `ExplicitAuthFlows` 与 IdP 名单，见 ④ 的输出）。

   **验证只能靠真人登录一次**（HTTP 层验不出来：要走完飞书同意页才会用到这个
   secret）。拿上面那张「登录链路实测基线」表对照。失败症状是回调
   `invalid_client` —— 此时把 ③④ 两侧都回滚成旧值即可恢复。

   **回滚**：旧明文不该留副本，所以回滚**不是**"把旧值粘回去"，而是从
   Secrets Manager 的 `AWSPREVIOUS` 版本取回它（`put-secret-value` 会自动把上一版
   打成这个标签）。第 ① 步那个指纹的作用是**核对**，不是还原——指纹不可逆
   （Codex 审查 2026-08-13 P2-2 指出原文这里自相矛盾）。

   ```bash
   # ③' 适配器一侧：把 cognitoClientSecret 换回上一版的值（其余字段取当前版本，
   #     只回退这一个键——同一条记录里还有飞书 App Secret）
   OLD="$(aws secretsmanager get-secret-value --secret-id "$ARN" \
            --version-stage AWSPREVIOUS --query SecretString --output text \
          | jq -r '.cognitoClientSecret')"
   aws secretsmanager get-secret-value --secret-id "$ARN" \
        --query SecretString --output text \
     | OLD="$OLD" jq '.cognitoClientSecret = env.OLD' \
     | aws secretsmanager put-secret-value --secret-id "$ARN" \
         --secret-string file:///dev/stdin
   unset OLD
   # ④' Cognito 一侧：重跑第 ④ 步那条 asm-exec 命令（它从 Secrets Manager 读，
   #     所以 ③' 落盘之后它自然拿到回退后的值）
   # ⑤' 再打一次指纹：必须回到第 ① 步记下的那个值
   ```

   注意 `AWSPREVIOUS` 只保留**一代**。如果轮换后又误改了一次，第一次的旧值就
   取不回来了——所以每次只改一个键、改完立刻验证登录，别连续改两轮。

   它建平台专用 pool（关自注册 + ESSENTIALS tier）、site/mcp 两个 app client
   （**不列 COGNITO**，只列你的 IdP）、branding、OIDC 联邦（含
   `email_verified` 映射）、pre-token 触发器，并把 client secret 写进 SSM。
   跑完回填 `[Cognito]` 四项。

   **登录链路的实测基线（2026-08-05，飞书适配器路径）**——部署后自己走一遍
   登录时可拿它对照，值不一致说明配置有偏差：

   | 观察项 | 实测值 |
   |---|---|
   | 飞书是否要求重新输账号密码 | 否（浏览器已有飞书登录态即可） |
   | 飞书授权同意页 | **只第一次弹**（"获取用户邮箱信息"），之后静默通过 |
   | 打开链接 → 拿到授权码 | 3.1–3.2 秒 |
   | 用户属性 `email_verified` | `true`（靠 `map_email_verified` 映射，见下） |
   | token 里 `email_verified` | `true`，**JSON 布尔**（id/access 两个 token 一致） |
   | `idp` | `Feishu`（须与 `trusted_idps` 逐字符一致） |
   | `auth_via` | `TokenGeneration_HostedAuth`（在 Edge/MCP 的 `TRUSTED_AUTH_SOURCES` 里） |
   | access token TTL | 900 秒（= 配置的 15 分钟） |
   | auth 服务冷启动（含首次读 SSM 密钥） | 约 2.5 秒；`/callback` 换 token 约 850ms |

   ⚠️ **`map_email_verified` 与 `require_email_verified` 必须一起看**：联邦
   映射进 Cognito 的 email **默认 unverified**，而 `require_email_verified`
   默认 `true` 会拒绝 unverified 的登录。本脚本默认配上 `email_verified`
   映射，两者因此自洽；若你手工建过 pool 而漏了映射，**该 pool 上所有登录都会
   被拒**（实测过，见文末升级一节）。

   ⚠️ **接 IdP 前先确认**：平台的授权主键是 email（owner/allowed_users/会话
   claim 全用它），而联邦映射进 Cognito 的 email 默认是 unverified。因此 IdP
   必须满足「邮箱由组织分配、用户不可自改、不被回收再分配」——允许用户自设
   邮箱的 IdP 上，攻击者改个 email 就能继承他人站点权限。详见
   `config.ini.example` 的 `[IdP]` 注释。

2. **`router/config.ini` 必须补两个键**（在 `[SiteBuilder]` 段）：

   ```ini
   # 全新部署直接填 true（没有存量会话要照顾）；trusted_idps 填 Cognito 里的
   # provider name，逗号分隔，须与 ① 建的 provider 逐字符一致
   require_idp_claim = true
   trusted_idps = Feishu
   ```

   **全新部署直接 `true`**——它是 org 边界的执行点（"身份必须来自企业 IdP"
   只有这里能落到请求路径上）。留 `false` 只有一个理由：环境里已有不带
   `idp` claim 的存量会话（见文末升级一节）。

   **上面的注释必须像这样单独成行——本片段可直接复制。** configparser 会把
   行内注释并进值：写成 `require_idp_claim = true  # 注释` 时读出来是
   `'true  # 注释'`，`require_idp_claim` 因此变成 false（防线静默关闭）；
   `trusted_idps` 则被污染成没有任何 idp 能匹配（开关为 true 时 = 全站锁死）。
   stack.py 对这两种情况都有断言，所以照错写法会在 synth 阶段被拒。

   两个键都是必填：缺键时 CDK synth 直接 `NoOptionError` 报错（响亮失败，
   不会把占位符部署出去）。

   ⚠️ Edge 改一次要 **10-20 分钟**全球复制，**回滚同样慢**——部署前先确认
   `trusted_idps` 与 Cognito 里的 provider name 逐字符一致（写错 = 全站锁死）。
   部署后务必核对部署出去的代码（不是本地源码）：

   ```bash
   # 取 CDK 输出里 EdgeFunctionArn 末尾的版本号，下载该版本实际代码
   aws lambda get-function --function-name ApplicationWebRouterStack-application-web-router \
     --qualifier <版本号> --region us-east-1 --query Code.Location --output text \
     | xargs curl -s -o /tmp/edge.zip && unzip -o -q /tmp/edge.zip -d /tmp/edge
   grep -E '^(REQUIRE_IDP_CLAIM|TRUSTED_IDPS)' /tmp/edge/index.py
   grep -c SYNTH-ONLY-PLACEHOLDER /tmp/edge/index.py    # 必须是 0
   ```

   出现 `SYNTH-ONLY-PLACEHOLDER` 说明 synth 时读 SSM 失败，**部署出去的所有
   会话验签都会失败**（Lambda@Edge 不支持环境变量，配置靠部署时字符串替换）。

3. **admin 种子**（在 ④ 建出 `site-admins` 表之后跑）：`site-builder/config.ini`
   的 `admin_seed` 填第一个管理员邮箱，然后注入（**CDK 只建表，不写任何管理员**）：

   ```bash
   python3 site-builder/scripts/seed_admin.py           # dry-run
   python3 site-builder/scripts/seed_admin.py --apply
   ```

   这一步漏掉的后果不易察觉：表存在、部署全绿，但**谁都不是 admin**——
   owner 离职或误撤自己权限的站点没有代管入口，而「添加管理员」本身需要
   admin 权限，从 UI 加不了第一个（死锁）。脚本幂等，可重跑。

4. **给登录失败建告警**（否则一类全员事故没人知道）：Cognito 的
   `invalid_grant` 既表示"用户重放了授权码"，也表示"app client 缺少 scope
   所需的属性读取权限"——后者是**每个用户每次登录都失败**的配置事故，而两者
   在响应里无法可靠区分，所以代码统一返回用户可读的 400。
   区分靠的是**频率**：偶发几条是正常的用户行为，持续高频就是配置写坏。
   auth 服务已按 `{"event":"token_exchange_invalid_grant",...}` 打结构化日志。
   **告警管道由 `deploy_auth.py` 幂等声明式收敛，不要手工建**（M3 前置 B2）。

   唯一配置真源是 `site-builder/auth/alarm_pipeline.py`：日志组与保留期、
   metric filter、SNS topic、email 订阅、alarm（含双语 AlarmDescription 与
   Alarm/OK actions）全部在那里声明；资源名与维度是 `deploy_auth.py` 里那次
   `ensure_alarm_pipeline(...)` 调用的字面量实参。改阈值就改 `ALARM_PARAMS`
   然后重跑 `cd site-builder/auth && python3 deploy_auth.py`。

   > 刻意**不称其为 IaC**：没有状态文件、没有漂移检测、没有依赖图。它只是
   > 每次运行都把这几样资源收敛到声明值的幂等脚本，与 `deploy_auth.py`
   > 其余部分同模式。

   **不要再手工 `aws logs put-metric-filter` / `aws cloudwatch put-metric-alarm`**
   ——那会造出第二个 writer，两份配置互相漂移。尤其注意 `put-metric-filter`
   的 upsert 键是 `filterName`：**换个名字不是改名，而是在同一日志组上再建
   一个 filter**，两个 filter 都往 `SiteBuilder/AuthInvalidGrant` 发点，
   同一条日志被计两次（Sum 翻倍）。现网那个手工 filter 名为
   `auth-invalid-grant`，脚本就照这个名字收编它。

   前提：`config.ini` 的 `[Alerting] email` 已填（gitignored），或设
   `SB_ALERT_EMAIL` 环境变量。缺失时脚本**响亮失败**，不会静默造出一个没人
   收通知的 alarm。

   ⚠️ **email 订阅必须由收件人手工点确认链接**——脚本只能创建订阅。未确认时
   alarm 照样进 ALARM 而无人知情，所以脚本把 `PendingConfirmation` 显式报告
   为「未完成」。

   保留期：脚本把该日志组声明为 **90 天**（2026-08-15 起的全平台统一值，见
   下方「日志组保留期」一节）。**这一行不再修剪日志**——90 天是抬高保留期，
   无损、可反复运行，没有配套门禁。
   > 2026-08-15 之前这里写的是 30 天并附一条"首次在存量环境运行会修剪日志"
   > 的警告（超过 30 天的日志会被标记删除、约 72 小时内物理删除）。统一到
   > 90 天后该危险消失，警告与门禁一并作废；留这一句只为让读过旧版的人知道
   > 它是**被撤销**的，不是被忘了。

   **从零部署验收**（"日志打了/metric 有点了"不等于"alarm 会响"）：

   ```bash
   SNS_TOPIC_ARN=<topic ARN> ./site-builder/scripts/verify_auth_alarm.sh
   ```

   它**比对线上配置 == 声明值**（阈值/双语描述/Alarm 与 OK actions 都等于声明的
   topic ARN，声明值由 AST 解析上述两个文件得出，脚本里不复制第二份字面量）、
   要求存在**声明的那个收件人**的 confirmed 订阅（别人的 confirmed 不算、
   `PendingConfirmation` 判 FAIL）、触发一次真实 `invalid_grant`、**确认日志里
   出现 `token_exchange_invalid_grant`**（不然测到的是 cookie 缺失分支的 400，
   不是目标逻辑）、建临时 1/1 阈值探针 alarm 验证真的进 ALARM，然后自动清理
   （trap 保证异常路径也清）。脚本全程只读线上状态——**不调
   `aws sns create-topic`**，否则"topic 缺失"这个该 FAIL 的状态会被脚本自己
   顺手修好并判 PASS。

   `OK` 通知统一称为**告警解除**：它只表示最近指标不再满足 ALARM 条件，告警规则
   仍然存在并持续监控；由于缺失数据按 `notBreaching` 处理，`OK` 也不等于已经确认
   登录功能或根因恢复。收到告警解除通知后仍应执行一次真实登录验证。

   ⚠️ **阈值 10 只是起步值，低流量环境必须调小**：如果日活登录只有几十次，
   "100% 登录失败"也可能 5 分钟凑不满 10 次——告警永不触发，而这正是它要发现
   的事故。这类环境改成 `--threshold 1 --evaluation-periods 2`（连续两个周期
   各 ≥1），或改为对失败率告警。**把最终阈值与理由写回本文档**，否则下一个人
   无法判断这个数字是否适合当时的流量。

   > **本仓库环境的取值（2026-08-05）**：`--threshold 1 --period 300
   > --evaluation-periods 2`，即连续两个 5 分钟周期各至少 1 次失败才告警。
   > 理由：当前只有个位数用户，用起步值 10 会让"全员登录失败"也凑不满阈值；
   > 而要求**连续两个周期**能滤掉单次用户重放授权码的正常噪声。
   > ALARM 与 OK（告警解除）均通知 SNS topic `site-builder-alarms`
   > （邮件订阅已确认）。验收探针名称使用 `TEST-` 前缀，Description 明确标注
   > `TEST ONLY`，避免被误认成生产事故。
   > 用户量上来后应重新评估——阈值 1 在高流量下会被正常的偶发失败刷响。
   >
   > 端到端验证过一次：打合成数据点 → alarm 进 ALARM → CloudWatch 记录
   > `Successfully executed action` → 订阅邮箱收到通知 → 删除探针 alarm。

   `token_exchange_upstream_error` 事件伴随 5xx，按 Lambda Errors 告警即可覆盖。

   日志只记**固定词汇**的字段（`event` / `error` / `hint` / `status`），
   不记上游 `error_description` 原文——Cognito 会在里面回显请求值，实测出现过
   `bad code <授权码> for user <邮箱>`，原样记录等于把授权码和邮箱写进
   CloudWatch，而日志保留期远长于授权码寿命。见 `login_handler._describe_hint`。

---

## ① 身份层（Task 3）

**产出**：Cognito User Pool（平台专用）+ IdP 联邦 + site/mcp 两个 app client
+ pre-token 触发器；回填 `config.ini [Cognito]` 全部 4 项。

**pool 与 client 全部由 `scripts/deploy_pool.py` 建，不要手工建**——它一并配好
几项手工极易漏掉、而漏掉即安全边界失效的东西：只列你的 IdP 不列 COGNITO、
不开任何原生认证 flow、refresh/access 双 TTL、`email_verified` 映射、
pre-token 触发器、managed login branding。命令与实测基线见前面
[决定安全边界的几项配置](#决定安全边界的几项配置先读这节)第 1 项。

下面步骤 1 是**准备 IdP**（按 §0 选定的场景二选一），步骤 2 起是拿到 pool 之后
的通用核对（把命令里的 IdP 名 `Feishu` 换成你实际的 provider name）。

1. **【飞书】** 克隆并按其 README 部署上游方案（把飞书 OAuth 包装成标准 OIDC
   的适配器；平台把它当成一个普通 OIDC IdP 来联邦）：
  ```bash
   git clone https://github.com/aws-samples/sample-for-amazon-quick-sso-with-feishu /tmp/feishu-sso
   cd /tmp/feishu-sso && cat README.md
   # 按 README 部署，飞书 App ID/Secret 作为参数输入
  ```

   部署完把适配器的 issuer 与联邦 client 凭证填进 `site-builder/config.ini`
   的 `[IdP]` 段，然后跑 `deploy_pool.py`。适配器的 `/authorize` 不校验
   `redirect_uri`（原样透传给 Cognito），所以**新建 pool 不需要在飞书后台改
   任何回调**——飞书侧登记的始终是适配器自己的 `{issuer}/callback`。

   **【标准 IdP】** 无需上游方案与适配器：把 IdP 的 issuer / client_id /
   client_secret 填进 `[IdP]` 段，`deploy_pool.py` 会用 Cognito 原生 OIDC
   联邦建好（含 email 与 `email_verified` 映射）。IdP 侧登记 Cognito 的回调
   `https://{hosted-ui-domain}/oauth2/idpresponse`（脚本跑完会打印这个地址）。
   SAML IdP 目前脚本未覆盖，需按下面官方文档手工加 provider，其余步骤相同——
   **attribute mapping 里把 IdP 的 email 映射到 pool 的 email 属性是硬要求**，
   漏了整个权限模型不成立。

   逐步操作的 AWS 官方文档：
   - **Okta（SAML，逐步截图版，含 Okta 侧配置）**：
     [How do I set up Okta as a SAML identity provider in an Amazon Cognito user pool?](https://repost.aws/knowledge-center/cognito-okta-saml-identity-provider)
     ——第 9 步的 email attribute mapping 就是上面说的硬要求
   - SAML IdP 通用（控制台/CLI）：
     [Adding and managing SAML identity providers in a user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managing-saml-idp-console.html)
   - OIDC IdP 通用（Okta 也可走 OIDC；回调登记、issuer 自动发现）：
     [Using OIDC identity providers with a user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html)
   - attribute mapping 专篇（CLI `--attribute-mapping` 语法在此）：
     [Mapping IdP attributes to profiles and tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)
   - Azure AD / Entra ID：
     [How to set up Amazon Cognito for federated authentication using Azure AD](https://aws.amazon.com/blogs/security/how-to-set-up-amazon-cognito-for-federated-authentication-using-azure-ad/)

2. **跑脚本建 pool 与 client**（幂等可重跑）：

  ```bash
   # [IdP] 段填好后跑；client_secret 可用 SB_IDP_CLIENT_SECRET 注入不落磁盘
   python3 site-builder/scripts/deploy_pool.py
  ```

   它建：平台专用 pool（关自注册 + ESSENTIALS tier，pre-token V2 需要）、
   托管域名（managed login v2）、OIDC 联邦（含 `email` 与 `email_verified`
   映射）、`site` 与 `mcp` 两个 app client、managed login branding、pre-token
   触发器，并把 site client 的 secret 写进 SSM `/site-builder/site-client-secret`。

   跑完按输出回填 `config.ini [Cognito]` 四项。`domain` **必须带 `https://`
   前缀、末尾不带斜杠**——`login_handler.py` 直接拼接使用
   （`f"{COGNITO_DOMAIN}/oauth2/authorize"`），裸域名会拼出无 scheme 的地址。

   > 这个 domain 不是你自己的域名，是 AWS 生成的 Cognito Hosted UI 地址
   > （承载登录页与 `/oauth2/authorize`、`/oauth2/token`）。你自己的域名填在
   > `[Platform] base_domain`，两者用途不同，别混。

3. **核对脚本产出**（这几项任一不符，安全边界就不成立）：

  ```bash
   aws cognito-idp describe-user-pool-client --user-pool-id {user_pool_id} \
     --client-id {site_client_id} --region us-east-1 \
     --query 'UserPoolClient.{IdPs:SupportedIdentityProviders,Flows:ExplicitAuthFlows,
              CB:CallbackURLs,LO:LogoutURLs,RefreshD:RefreshTokenValidity,
              AccessM:AccessTokenValidity}'
  ```

   期望值（2026-08-05 实测基线）：

   | 字段 | 期望 | 不符的后果 |
   |---|---|---|
   | `SupportedIdentityProviders` | 只有你的 IdP，**不含 `COGNITO`** | 托管登录页暴露本地用户登录/注册入口，`allowed_users="org"` 的语义被击穿 |
   | `ExplicitAuthFlows` | 只有 `ALLOW_REFRESH_TOKEN_AUTH` | 开着任何原生 flow 即可绕过联邦、用本地用户密码拿 token |
   | `CallbackURLs` | `https://auth.{base_domain}/callback` | 与 `login_handler` 发送的 `redirect_uri` 逐字符不同即 `redirect_mismatch` |
   | `LogoutURLs` | 含 `/logged-out` **与** `/logout` | 缺 `/logged-out` 则登出报错（Cognito 只接受已登记的 sign-out URL）；把 `logout_uri` 指向 `/logout` 本身会无限重定向 |
   | `RefreshTokenValidity` | 1（天） | 默认 30 天——吊销后残留 token 仍可续期 |
   | `AccessTokenValidity` | 15（分钟） | AgentCore authorizer 不回查撤销状态，吊销后 access token 在过期前仍能调 MCP |

   mcp client 另需确认**没有 secret**（public client）且回调含
   `http://localhost:18765/callback`（给 Claude Code 等本机客户端的 OAuth 用；
   Cognito 不支持 dynamic client registration，端口选 18765 是因为 8765/8766
   被 Quick Desktop 的 quickwork-agent 常驻占用，详见 `docs/client-setup.md`）
   与 AgentCore 的 identities 回调。

   > Cognito 的 `/logout` **不登出上游 IdP**（飞书会话仍在），所以 UI 文案不能
   > 承诺"已完全退出"。

7. **验证点**：`deploy_pool.py` 结束时打印的核对项全部通过 + 上面步骤里的
   describe 核对全部符合，即可进入 ②。**端到端的真人登录验证不在这一步**：
   完整链路（Hosted UI → IdP → 回调 → 会话）要等 ② 路由层与登录服务都在线
   才存在，放在 ⑥ 客户端接入（auth.js 首次 OAuth 能拿到含 email 的 access
   token）与 ⑦ 彩排里做。

> **MCP 的 token 形态已钉死**（2026-07-29 真机）：AgentCore 网关只接受
> **access token**（id_token 会被 401 `Claim 'client_id' value mismatch`），
> 而 Cognito access token 默认不含 email——靠 pre-token V2 触发器注入，
> `deploy_pool.py` 已一并挂好。**不要把 authorizer 改成 allowedAudience**。

---

## ② 路由 + 鉴权层 — WebRouterStack（Task 8）

**产出**：CloudFront 分发（`*.{base_domain}`）+ 扩展路由表 + 前端桶；回填 `config.ini [Deployer] edge_role_arn`。

**前置**（来自 ①，缺任一项本阶段会失败）：
- `site-builder/config.ini [Cognito]` 四项已填（auth-service 要读 `site_client_id`）
- SSM `/site-builder/site-client-secret` 已写入（① 的 `deploy_pool.py` 自动写）
- SSM `/site-builder/jwt-secret` 已存在（§0；栈部署时注入 Edge 函数）

确认 `router/config.ini` 已填好：account_id / domain_name / certificate_arn /
frontend_bucket / base_domain（从 `router/config.ini.example` 复制）。
`[SiteBuilder]` 段还必须有 `require_idp_claim` 与 `trusted_idps` 两键
（缺任一 synth 直接 NoOptionError）。**全新部署直接填 `true` + 你的 provider
name**；值必须是裸 `true`/`false`——configparser 会把行内注释并进值，
`true  # 注释` 会被当成 false，防线静默关闭。已有存量会话的环境见文末升级一节。

1. 建私有前端桶（若不存在）。**注意此桶不由 CDK 管理**，需手工建并配好
   public-access-block：
  ```bash
   # us-east-1 不要带 --create-bucket-configuration LocationConstraint
   aws s3api create-bucket --bucket site-frontend-{account_id} --region us-east-1
   aws s3api put-public-access-block --bucket site-frontend-{account_id} \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  ```
   桶必须保持私有：Edge 函数用 SigV4 签名读它（见 `_add_s3_sigv4_auth`），
   不依赖公开访问。

   > **这个桶上不要配 `sites/` 前缀的生命周期规则。** 2026-08-17 之前这里教的是
   > 加一条 `expire-old-site-versions`（`Filter.Prefix=sites/`、`Expiration.Days=30`）
   > 当作旧版本清理的兜底。**那条规则是错的，已从文档与生产桶上移除**：
   >
   > 站点**线上正在服务**的那一份前端也住在 `sites/{site_id}/{job_id}/` 下，
   > 而这个前缀写一次之后**永不重写**（每次部署换一个新前缀）。桶又没开版本控制。
   > 于是任何 **30 天没有重新部署过**的站点会被这条规则把线上前端删掉，
   > 而且因为桶是私有的，症状是**整站 403 而不是 404**——很容易被当成权限故障去查。
   > 实测：规则移除时生产上最老的存量前缀已 19 天（`team-kudos-wall-1d5lpc`，
   > 2026-07-29 上传），离触发只剩约 11 天，还没有站点被删过。
   >
   > 存储上界由 `mark_job._cleanup_old_versions` 提供：它每次成功部署后清掉本站点
   > 的陈旧前缀，只保留当前那一份、上一份（Edge 路由缓存 60s 内仍会引用它）、
   > 以及 30 分钟内新上传的（可能是另一次正在跑的部署）。站点下线时
   > `undeploy.py` 整个 `sites/{site_id}/` 前缀删除。
   > **口径的边界**：清理只在**成功**分支跑，所以"上界"只对持续有成功部署的
   > 站点成立——一个再也没成功部署过的站点，其失败部署留下的前缀会一直躺到
   > 下一次成功部署或下线。这是接受的代价（几 MB 级），不要为它把生命周期
   > 规则加回来。
   >
   > 生命周期规则表达不了"除了每个站点最新的那一份"，所以这里没有"改窄"的写法，
   > 只能不配。
2. 部署栈（首次需先 bootstrap）：
  ```bash
   cd router/infrastructure
   # --clear：首次创建与已存在时重建都适用。venv 的 shebang 是绝对路径，
   # 仓库被移动或改名后旧 venv 会报 "bad interpreter"，而不带 --clear 的
   # python3 -m venv 对已存在目录不会重写 shebang（重跑也修不了）
   python3 -m venv --clear .venv
   .venv/bin/pip install -r requirements.txt -q
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest bootstrap aws://{account_id}/us-east-1   # 首次
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
  ```

   stack.py 部署时会从 SSM 读真实 JWT_SECRET 注入 Edge 函数（`load_jwt_secret`）；若打印
   `SYNTH-ONLY-PLACEHOLDER` 警告说明 SSM 读取失败，**不要继续**——检查凭证与 SSM 参数。

   > **`cdk deploy` 会长时间挂在最后一步**（Lambda@Edge 复制到全球边缘节点，可达
   > 10-20 分钟），期间 CloudFormation 可能已是 `UPDATE_COMPLETE`。用
   > `aws cloudfront get-distribution --id {distribution_id} --query 'Distribution.Status'`
   > 判断是否 `Deployed`，不必盯着 CLI 输出。
   >
   > **改过 config.ini 后要先 `rm -rf cdk.out`**：陈旧 asset 里仍是旧的
   > `BASE_DOMAIN`，直接 synth/deploy 会用到过期值。
   >
   > **改过依赖清单（`bundling-requirements.txt`）也必须 `rm -rf cdk.out`**，而且这
   > 一条与上一条是**两个独立的原因**：CDK 的 asset hash **只看 `/asset-input` 那个
   > 源目录，不含挂载卷里的清单内容**——实测过两份不同的 lockfile 算出同一个
   > `asset.<同一串>`。于是"只改清单、不改 `app.py`"时 CDK 会复用旧 asset，
   > 新清单当次**根本没生效**，而部署脚本一切正常。
   >
   > **改过 `site-builder/contract/` 同样必须 `rm -rf cdk.out`**，原因与上一条**完全
   > 相同**：合同包也是**挂载卷**（`infra/app.py` 的 `/asset-contract` → `contract/src`，
   > 用 `cp -r` 进产物），不进 asset hash。而它被打进**全部 10 个 `site-deployer-*`
   > step Lambda**（`step_fn` 的 bundling 命令是统一的），所以漏清的后果是"部署全绿
   > 而 10 个函数继续跑旧的校验器字节"——校验规则改严了却完全没生效，是最难发现的
   > 那一类。这条以前不在本清单里（只列了 config.ini 与依赖清单），补上。
   >
   > **`default_origin` 必须是可解析域名**。origin-request 事件在 CloudFront 解析
   > origin **之后**才触发，填不可解析的值（如 `.invalid` 保留 TLD）会让所有请求
   > 在 Edge 执行前就 `502 CloudFront wasn't able to resolve the origin domain name`,
   > 连 Edge 自己的 404 都返回不了。
3. 记录 CfnOutput 的 **EdgeRoleArn**，回填 `site-builder/config.ini [Deployer] edge_role_arn`（Task 17 执行器需要它给站点 Function URL 授权）。记录 **DistributionDomainName**。
4. DNS：在 `{base_domain}` 加通配符 CNAME 或 A-alias 指向 CloudFront 域名：
  ```
   *.{base_domain}  →  {distribution_domain_name}  (如 d1234abcd.cloudfront.net)
  ```
   同 zone 下**已有的显式子域记录不受影响**（DNS 显式记录优先于通配符）；但此后
   新增子域在建记录前会先落到本方案并返回 404，排查时留意。
5. **部署 auth-service Lambda**（Task 5 的登录端点，依赖①的 Cognito + 本步骤的路由表；
   **还依赖上一步回填的 `[Deployer] edge_role_arn`**，脚本要用它授权 Function URL）：
  ```bash
   cd ../../site-builder/auth && python3 deploy_auth.py
   # 它会：打 zip（含 pyjwt）→ 建/更新 Lambda site-auth-service
   #      → Function URL(AWS_IAM，仅 edge role 可调，公网直连 403)
   #      → 生成/复用 SSM /site-builder/jwt-secret → 路由表注册 subdomain=auth (route_mode=api-only)
   #      → 部署 pre-token-generation V2 触发器 site-auth-pre-token 并挂到用户池
   #        （把 email 注入 access token；⑤ 部署 MCP 的 owner 识别依赖它，
   #         用户池须 Essentials+ tier，原理见 ⑤ 的 token 形态说明）
  ```

   > Function URL **不要用 AuthType=NONE**：NONE + `Principal:*` 会被判定
   > world-accessible（AWS 内部曾自动 mitigate——直接删光 resource policy，
   > 导致 CloudFront 路径也 403）。Edge 对 api-only 路由同样签 SigV4，
   > AWS_IAM + 只授权 edge role 即可，登录功能不受影响。
   > 验证：`https://auth.{base_domain}/login` 返回 302（跳 Cognito），
   > Function URL 直连 `/login` 返回 403 `{"Message":"Forbidden"}`。
6. **冒烟**（CloudFront 传播需 15-30 分钟后再跑）：
  ```bash
   cd {仓库根} && bash site-builder/scripts/smoke_router.sh
  ```

   预期 6 行 PASS：static route / no cross-site cache / auth 302 / auth subdomain api-only routing / unknown 404 / route update visible。

   脚本会往路由表与前端桶写测试数据（`app-smoke*` 路由、`sites/smoke*` 对象），
   验证完记得清理：删掉那几条 `subdomain` item 与 `s3://{frontend_bucket}/sites/smoke*`。

   除脚本外建议再手工验一次**带真实会话 cookie 的鉴权闭环**（脚本只验到 302）：
  ```bash
   SECRET=$(aws ssm get-parameter --name /site-builder/jwt-secret --with-decryption \
     --region us-east-1 --query 'Parameter.Value' --output text)
   COOKIE=$(python3 -c "
   import sys; sys.path.insert(0,'site-builder/auth')
   from session import mint_session_jwt
   print(mint_session_jwt('you@example.com','You',sys.argv[1],
                          idp='Feishu', auth_via='TokenGeneration_HostedAuth'),
         end='')" "$SECRET")
   # 对一个 require_auth=true 的测试路由：
   curl -s -o /dev/null -w '%{http_code}\n' https://app-<test>.{base_domain}/            # 期望 302
   curl -s -w '\n' -H "Cookie: sb_session=$COOKIE" https://app-<test>.{base_domain}/     # 期望 200 + 内容
   curl -s -o /dev/null -w '%{http_code}\n' -H "Cookie: sb_session=${COOKIE}x" \
     https://app-<test>.{base_domain}/                                                    # 期望 302（验签失败）
  ```

   > **`idp` 与 `auth_via` 两个 claim 必须带上**（Edge 的
   > `REQUIRE_IDP_CLAIM=true` 起作用后）：不带就会被 302 回登录页，而这
   > **看起来与"Edge 回归了"完全一样**——操作者会因此怀疑一次正确的部署。
   > 两个值要与 `TRUSTED_IDPS` / `TRUSTED_AUTH_SOURCES` 对齐（见
   > `router/infrastructure/lambda/origin_request.py`）：`idp` 取
   > `config.ini [IdP] provider_name`（本环境为 `Feishu`），`auth_via` 取
   > `TokenGeneration_HostedAuth`。
   > 反过来，**"不带 claim → 302" 本身就是一条值得跑的负向用例**：把上面的
   > `idp=`/`auth_via=` 去掉再请求一次，期望 302——这证明的是 Edge 真的在
   > 校验身份来源，而不是碰巧放行了。

---

## ③ Aurora DSQL cluster（Task 13）

**产出**：共享 DSQL cluster；回填 `config.ini [DSQL] cluster_endpoint`。

```bash
# 建 cluster（返回 identifier，26 位小写字母数字）
CID=$(aws dsql create-cluster --region us-east-1 \
  --tags Key=project,Value=site-builder \
  --no-deletion-protection-enabled \
  --query 'identifier' --output text)
echo "cluster id: $CID"

# 等状态变 ACTIVE（通常几十秒）
aws dsql get-cluster --identifier "$CID" --region us-east-1 --query 'status' --output text

# endpoint 需按固定格式自己拼——API 不返回它：
echo "$CID.dsql.us-east-1.on.aws"
```

**回填 `[DSQL] cluster_endpoint` 用裸主机名**，形如
`abcdefghij0123456789abcdef.dsql.us-east-1.on.aws`——不要带 `https://`、
不要带端口、不要带路径。它同时被用作 `generate_db_connect_auth_token` 的
`Hostname` 参数与 psycopg / pg 的 `host`，多余前缀会导致签名或连接失败。

站点数据隔离由执行器在部署 SQL 站点时创建 per-site schema + 两个 per-site PG role
（运行时 role 只读写本 schema 的表，migrator role 才能建对象）+ `AWS IAM GRANT`
映射到对应 IAM 角色（`provision_dsql.py`）。此处只需 cluster 存在且 ACTIVE。

> `--no-deletion-protection-enabled` 是为了 PoC 便于清理；生产环境应开启删除保护。

**DSQL 权限模型已在真实 cluster 验证通过**（2026-07-28，此前标注为"未验证"）：
`AWS IAM GRANT` 语法可用、两条 per-site 映射确实写入 `sys.iam_pg_role_mappings`；
migrator role 能在本 schema 建表，但建其他 schema / 建角色 / 改 IAM 映射全部被
拒（sqlstate 42501）；运行时 role 能读写表但不能建表。

两点实测结论：
- `ALTER DEFAULT PRIVILEGES FOR ROLE` **会被 DSQL 拒绝**（42501 permission denied
  to change default privileges）。代码已按 best-effort 处理，末尾对已有表的显式
  `GRANT` 是真正生效的那条——实测运行时 role 靠它拿到读写权限，功能不受影响。
- **`undeploy` 默认不清理数据侧资源**（DSQL schema / per-site role / IAM 映射，
  DynamoDB 的 `site-data-*` 表同理），这是"数据保留防误删"的默认行为。
  传 `purge_data=true`（MCP 工具 `undeploy_site` 的参数，需向用户确认后再传）
  才会连数据一起清——**已真机验证（2026-07-29）**：purge 后 DSQL 无孤儿
  schema/role/映射、`site-data-*` 表删除。
  默认（不 purge）路径会删掉 `site-rt-*` IAM 角色，于是 `sys.iam_pg_role_mappings`
  里留下指向已删角色的孤儿映射（④ 冒烟后实测复现）。孤儿映射本身无安全风险
  （目标角色已不存在，无法用它认证），但会累积。手工清理顺序有讲究：

  ```sql
  -- 必须先 REVOKE 再 DROP ROLE，否则 DROP ROLE 报 2BP01（有对象依赖）
  AWS IAM REVOKE site_xxx_app FROM 'arn:aws:iam::{account_id}:role/site-rt-xxx';
  AWS IAM REVOKE site_xxx_mig FROM 'arn:aws:iam::{account_id}:role/site-deployer-exec-role';
  DROP SCHEMA "site_xxx" CASCADE;
  DROP ROLE site_xxx_app;
  DROP ROLE site_xxx_mig;
  ```

  查残留：
  ```sql
  SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'site_%';
  SELECT arn, pg_role_name FROM sys.iam_pg_role_mappings WHERE pg_role_name LIKE 'site_%';
  ```

---

## ④ 异步执行器 — SiteDeployerStack（Task 17）

**产出**：jobs/sites 表、artifacts 桶、CodeBuild、状态机 `site-deploy`、10 个 step Lambda、undeploy Lambda、runtime boundary、exec role；回填 `config.ini [Deployer] state_machine_arn`。

**前置**：`[Deployer] edge_role_arn`（来自②）、`[DSQL] cluster_endpoint`（来自③）必须已回填，否则站点 Function URL 授权与 DSQL 连接会失败。

```bash
cd site-builder/deployer/infra
python3 -m venv --clear .venv                  # 见 ② 的说明：venv 不可跨路径复用
.venv/bin/pip install -r requirements.txt -q
# 部署（bundling 用 Docker 拉 x86_64 镜像，按锁定清单 --require-hashes 装
#  psycopg[binary]+sqlparse；**合同包是 cp 包目录进去的，不走 pip**——site-contract 是
#  PEP 517 项目，pip 会在默认 build isolation 下联网装一个未锁版本、未锁 hash 的
#  setuptools 并执行它，那等于「依赖已锁」这个结论对构建工具链不成立）
PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

记录 CfnOutput 的 **StateMachineArn**，回填 `site-builder/config.ini [Deployer] state_machine_arn`。

**冒烟（手工触发一次 static 部署，验证执行器全链路）**：

```bash
cd {仓库根}
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_e2e_fixtures.py::test_static_site_public_200 -q
# 或用 deploy_fixture.py 直接跑：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/static-hello
```

预期：SFN execution SUCCEEDED，`curl https://app-{site_id}.{base_domain}/` 返回 fixture 首页。

**⚠️ Docker 拉镜像 403**：若 `public.ecr.aws` 凭证过期，先 `docker logout public.ecr.aws`
再重试（bundling 用匿名拉取）。

---

## ⑤ 部署 MCP — AgentCore Runtime（Task 20）

**代码已就绪并在本地真实容器里验证过**（ARM64 镜像构建 → 起容器 → 完整 MCP
握手 → Bearer token 的 email claim 被 `_caller_email()` 正确解出 → 平台注入的
`Mcp-Session-Id` 被容忍）。`get_http_headers` 问题早已按 spike 结论修掉，
详见 `site-builder/mcp/AGENTCORE-SPIKE.md`。

**前置**：④ 的 `state_machine_arn`、① 的 `mcp_client_id` / `user_pool_id` 必须已回填。

```bash
cd site-builder/mcp
python3 deploy_agentcore.py        # 建 ECR → buildx ARM64 → 推送 → 建角色 → 建/更新 runtime
# 只改配置不重建镜像：python3 deploy_agentcore.py --skip-build
```

脚本做的事（全部幂等）：ECR 仓库 → cp `deployer/functions/common.py` 进构建上下文 →
`docker buildx --platform linux/arm64` 构建推送 → runtime 执行角色
（jobs/sites 表、`uploads/*` presign、`states:StartExecution`、undeploy `lambda:InvokeFunction`）→
`create_agent_runtime`（`serverProtocol=MCP`、Cognito `customJWTAuthorizer`、
`requestHeaderAllowlist=["Authorization"]`）。运行结束会打印要回填的
`[MCP] endpoint_url`。

**三个契约要点**（违反的症状都是"部署完才发现连不上"，已由 `tests/test_agentcore_contract.py` 锁定）：

- 容器必须 **ARM64**，监听 **0.0.0.0:8000**、暴露 **POST /mcp**、**stateless** streamable-http；
- `Authorization` 必须显式进 `requestHeaderAllowlist`，否则平台不透传该头，
所有工具报"无法识别调用者身份"；而透传 `Authorization` 又要求配 `customJWTAuthorizer`；
- `agentRuntimeName` 只允许 `[a-zA-Z][a-zA-Z0-9_]{0,47}`（连字符会被 API 拒）。

**⚠️ ECR 镜像校验的误导性报错**：`CreateAgentRuntime` 若报
"Access denied while validating ECR URI ... requires permissions for
ecr:GetAuthorizationToken/BatchGetImage/GetDownloadUrlForLayer"，**大概率与
IAM 无关**（实测权限齐全时同样报）。真实原因是 `docker buildx` 默认给
manifest list 附加一条 `os=unknown/arch=unknown` 的 attestation manifest，
AgentCore 校验不认。`deploy_agentcore.py` 已带 `--provenance=false` 规避；
手工构建镜像时必须同样加上该参数。

**冒烟**：`npx @modelcontextprotocol/inspector` 连 endpoint（带 Cognito Bearer token），
确认列出 <!-- tool-count:begin -->9<!-- tool-count:end --> 个工具、无 token 返回 401、
`list_my_sites` 的 owner == 登录用户飞书邮箱。应当列出的是：

<!-- tool-list:begin  本区域由 site-builder/mcp/tests/test_doc_tool_surface.py 对着
     MCP 实时注册表校验；区域内只写工具名。 -->

- 部署三件套：`deploy_site` / `confirm_upload` / `get_deploy_status`
- 管理五件套：`list_my_sites` / `undeploy_site` / `update_site_permissions` /
  `manage_collaborators` / `get_site_permissions`
- 统计（二期 M5）：`get_site_analytics`

<!-- tool-list:end -->

工具面在运行时由 `mcp/tests/test_agentcore_contract.py` 的 `EXPECTED_TOOLS` 锁定，
在文档里由 `mcp/tests/test_doc_tool_surface.py` 锁定（两侧都对着实时注册表比）。

**token 形态已真机钉死（2026-07-29）**：网关配 `allowedClients` 时只接受
**access token**（id_token 会 401 "Claim 'client_id' value mismatch"，因为
id_token 用 `aud` 而非 `client_id`），MCP 客户端按 OAuth 规范发的也正是
access token。而 Cognito access token 默认不含 email，所以 **email 注入靠
pre-token-generation V2 Lambda**（`auth/pre_token_email.py` → 函数
`site-auth-pre-token`，挂在用户池 LambdaConfig，V2_0，要求 Essentials+ tier）。
真机验证过：工具列出、无 token 401、owner == 登录用户邮箱、跨用户查 job 被拒。
**权限三件套（`update_site_permissions` / `manage_collaborators` /
`get_site_permissions`）尚未真机验证**——单测覆盖，但 IAM 的字段级闸门
（`dynamodb:Attributes`）只有真机能证伪。
**不要**改 `allowedAudience`——那会反过来把 access token 拒掉。
详见 `mcp/AGENTCORE-SPIKE.md` §7 与 `docs/client-setup.md`。

---

### IAM 属性闸门的真机验收（部署完 ⑤ 后跑一次）

MCP runtime 角色靠 `dynamodb:Attributes` 条件把可写字段收窄。**这道闸门只有真机
能证伪**——moto 不执行 IAM 授权，Stubber 只校验请求参数形态，所以单测全绿不代表
它生效。

```bash
./site-builder/scripts/verify_mcp_iam_scope.sh
```

脚本建一个一次性影子角色（只复制线上策略里的 DynamoDB statements）+ fixture 站点，
跑四条探针：两条越权写必须被拒、一条正常权限投影必须成功、一条 GSI 读必须不被
误伤；然后自动删除全部探针资源（`trap` 保证 Ctrl-C 与中途失败也删——残留的影子
角色就是一条可 assume 的站点管理权限后门）。任一探针不符预期即非零退出。

`owner` 在白名单内是**有意的**（建站与 transfer_owner 都要写它），所以"改 owner
接管站点"这条路径 IAM 关不掉，由应用层与 runtime 完整性负责（见下面的信任边界
一节）。不要因为这个脚本把 `owner` 从白名单删掉：那会让建站直接 AccessDenied。

---

## ⑤b 自助管理控制台 — panel（二期 M3）

业务人员在 `https://console.{base_domain}/` 自助管理站点权限/协作者/所有权/
部署历史/下线；平台管理员另有全局站点视图与管理员名单。**站点仍然只能在 Agent
客户端里创建**——控制台不建站。

**为什么排在 ⑤ 之后**：它要 ② 产出的 `edge_role_arn`（Function URL 只授权这个
角色）、④ 建的 `site-sites` / `site-deploy-jobs` / `site-admins` /
`site-ops-log` / `site-session-codes` 五张表，以及 ① 的 `/site-builder/jwt-secret`
（面板会话与站点会话同一套 HS256）。

```bash
cd site-builder/panel && python3 deploy_panel.py
# 只改后端不动前端： python3 deploy_panel.py --skip-frontend
```

脚本幂等，一次做五件事：复制依赖模块打包 → panel role → Lambda +
Function URL(**AuthType=AWS_IAM，只授权 exact edge role**) → 前端上传到
`platform/console/{version}/` → 注册 `console` route（`route_mode=split`：
`/api/*` 走 Function URL，其余走 S3）。

**DNS/证书不需要额外动作**：`console` 是 `*.{base_domain}` 通配证书与 CloudFront
分发下的一个子域，② 建好之后它自动可解析。前提是 `console` 已在 Edge 的
`PLATFORM_SUBDOMAINS` 白名单里（M3 的 Edge 版本已含，见 `verify_deployed_edge.sh`）。

`auth` 服务需要 `/console-session` 端点（签发一次性升级码）。若你的 auth 是
M3 之前部署的，**先重跑一次** `cd site-builder/auth && python3 deploy_auth.py`。

**验收（部署完立刻跑，从仓库根）**：

```bash
python3 site-builder/scripts/verify_console_e2e.py     # 64 项
```

它覆盖未登录 fail-closed、伪造 `x-user-email` 直连 Function URL 仍 403、
前端真的能加载、越权读写全拒且**线上数据零改动**、CSRF 四形态、合法写与审计、
`/console-session` 全链路（含同一 code 重放 401）。会建 2 条 fixture 记录并自动
清理（删后强一致读回核对）。

**三个实测坑**（都会让控制台看起来"部署成功但打不开"）：

- **`static_prefix` 不能带尾斜杠**。Edge 的静态改写是
  `f"/{static_prefix}{path}"` 且 `path` 已以 `/` 开头——带尾斜杠会去取
  `platform/console/v1//index.html`，与上传的单斜杠 key **不是同一个对象**，
  整站 403。`verify_deployed_components.py` 第 ⑦ 段专门断言这一条。
- **panel role 必须有路由表的 `dynamodb:ConditionCheckItem`**。
  `write_permissions` 在"站点还没首次部署成功（无 route item）"时走降级事务，
  对路由表做 `attribute_not_exists(subdomain)` 的 ConditionCheck；缺这个 action
  时**对任何无 route 的站点做写操作都 500**。moto 不校验 IAM，所以单测全绿。
- **私有桶上浏览器的约定路径一律 403（不是 404）**。`/favicon.ico`、
  `/robots.txt`、`/.well-known/*` 这些浏览器会自作主张请求的路径在 S3 上不存在，
  私有桶回 403，读起来像鉴权故障。前端已用内联 data URI 声明 favicon 消掉这条。
  **排查线上 403 先分清"没权限"还是"没这个对象"。**

---

## ⑤c API Key 组件（二期 M4，**可选**）

给"只能配静态 Header 的 MCP 客户端"（如 Quick Desktop 的 Remote MCP）一条不走
浏览器 OAuth 的路：客户端把 `X-API-Key: sk-…` 打到 `https://mcp.{base_domain}/`，
交换层验 Key → 换组件自身的机器 token → **不懂 MCP 协议地透明转发**到 AgentCore，
只多一个 `X-SB-On-Behalf-Of: {email}` 告诉 MCP server 以谁的身份行事。

**不需要就整段不配置——这是推荐的默认。** `config.ini` 没有 `[ApiKey]` 段 =
平台只允许 OAuth 一条认证路径：不建 Cognito resource server / machine client、
不部署 key-proxy、不注册 `mcp` 子域、machine client 不进 AgentCore 的
`allowedClients`、`X-SB-On-Behalf-Of` 也不在网关的 allowlist 里。即使有人拿到
一把 Key 也在**网关层**被拒，不经过任何业务代码。四个部署脚本各自会打印
"跳过：无 `[ApiKey]` 段"并**返回 0**（不是报错——"没配置"是合法状态，部署全平台
的脚本链不该因此中断）。

### 四步顺序，以及为什么任一步停下都不产生提权窗口

先在 `config.ini` 配好 `[ApiKey]` 段（照 `config.ini.example` 的注释块），然后：

```bash
# ① Cognito：建 resource server + scope + machine client（secret 落 SSM）
cd site-builder && python3 scripts/deploy_pool.py
#    回填 config.ini 的 [Cognito] machine_client_id

# ② 执行器栈：建 site-api-keys 表（PK=key_hash，email-index / keyid-index）
cd site-builder/deployer/infra && rm -rf cdk.out && \
  PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never

# ③ MCP runtime：machine client 进 allowedClients、放行 on-behalf 头、
#    容器下发 MACHINE_CLIENT_ID（三者同一个派生点，同开同关）
cd site-builder/mcp && python3 deploy_agentcore.py

# ④ 交换层：key-proxy Lambda + Function URL(AWS_IAM 仅 edge role) +
#    mcp route + 哨兵行（**建成关**）
cd site-builder/key-proxy && python3 deploy_key_proxy.py

# ⑤ 控制台前端要能看到 Key 页面
cd site-builder/panel && python3 deploy_panel.py
```

**中途停下不会开出一条提权路径**，每一步都缺后一步的必要条件：

| 停在哪 | 为什么安全 |
|---|---|
| ① 之后 | machine client 存在且能换 token，但它**不在** AgentCore 的 `allowedClients` 里 → 拿它直调网关是 `401 Claim 'client_id' value mismatch`（本仓库实测过） |
| ② 之后 | 表建好了但没人能写它（发 Key 的接口在 panel，交换层还不存在） |
| ③ 之后 | 网关认这个 client 了，但没有交换层把 Key 换成它——而 machine client 的 secret 只在 SSM，公开的 `mcp` client **换不到** client_credentials token（实测 `400 invalid_client`） |
| ④ 之后 | 组件齐了，但**哨兵行是关的** → 任何 Key 直连都 401 |

### 三处组件门禁：漏一处的症状（排查表）

三处都从 `deployer/functions/api_key_config.api_key_enabled` 这**同一个判定**派生，
正常情况下同开同关。真出现不一致时按症状定位：

| 缺的是哪一处 | 症状 | 怎么确认 |
|---|---|---|
| ① machine client 不在 `allowedClients` | 所有 Key 调用 **HTTP 401**，响应体是网关的 `Claim 'client_id' value mismatch` 而不是我们的 JSON | `get_agent_runtime` 读 `authorizerConfiguration.customJWTAuthorizer.allowedClients` |
| ② `X-SB-On-Behalf-Of` 不在 `requestHeaderAllowlist` | 请求过网关但容器收不到身份 → **HTTP 200 + "无法识别调用者身份"** 的业务文案 | 读 `requestHeaderConfiguration.requestHeaderAllowlist` |
| ③ 容器的 `MACHINE_CLIENT_ID` 为空 | 与 ② 同症状（**最难查的那一半**：网关放行、容器拒绝） | 读 runtime 的 `environmentVariables` |

**②③ 是最容易漂的一对**——它们分处网关配置与容器环境，分别写就会不一致。
`verify_deployed_components.py` 第 ⑧ 段有一条"当且仅当"断言盯着它。

### 首次部署后开关是**关**的，要去控制台开一次

`deploy_key_proxy.py` 建哨兵行时写 `enabled=false`（fail-closed），并且**重跑时
一个字都不改**——否则下一次部署会把管理员的关闸静默覆盖成开。所以部署完的正确
状态就是"组件已上线、通道未开"，脚本最后会明确打印这一点。

开闸：管理员进 `https://console.{base_domain}/` 的 API Key 页面打开开关。
**每次开关变更都落 `site-ops-log` 审计**（`enable_api_key_switch` /
`disable_api_key_switch` + actor）。

### 应急旁路：控制台不可用时直改哨兵行

**只在控制台打不开时用**（正常关闸一律走控制台——CLI 直改**绕过 ops_log
审计**，事后没人查得出是谁关的）：

```bash
# 关闸（enabled 必须是 BOOL，不是字符串 "false"）
aws dynamodb update-item --region us-east-1 --table-name site-api-keys \
  --key '{"key_hash":{"S":"__switch__"}}' \
  --update-expression "SET #e = :f, #t = :now, #w = :who" \
  --expression-attribute-names '{"#e":"enabled","#t":"updated_at","#w":"updated_by"}' \
  --expression-attribute-values "{\":f\":{\"BOOL\":false},\":now\":{\"S\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"},\":who\":{\"S\":\"emergency-cli\"}}"

# 读回核对（**必须强一致读**，最终一致读可能还是旧值）
aws dynamodb get-item --region us-east-1 --table-name site-api-keys \
  --key '{"key_hash":{"S":"__switch__"}}' --consistent-read \
  --query 'Item.enabled'
```

三条纪律：

- **`enabled` 必须写成 DynamoDB `BOOL`**。`keystore.lookup` 的判定是
  `enabled is not True`，字符串 `"true"` 同样被拒——症状是"控制台显示开着但所有
  Key 都 401"，而两侧单测各自都是绿的。`update-item` 用 `{"BOOL":false}`，别用
  `{"S":"false"}`。
- **只 `SET` 这三个字段，别用 `put-item` 整行覆盖**。哨兵行绝不能带 `email` /
  `key_id`——那两个是 `email-index` / `keyid-index` 的分区键，带上会让平台开关行
  冒进某个人的 Key 列表。
- `enabled` 走 `ExpressionAttributeNames`（`#e`）而不是裸名，省得踩 DynamoDB
  保留字。
- 用完之后**回控制台再点一次**，让后续变更重新有审计。

### 验收（部署完立刻跑，从仓库根）

```bash
python3 site-builder/scripts/verify_deployed_components.py    # 含第 ⑧ 段
python3 site-builder/scripts/verify_api_key_e2e.py            # 六场景 + 四负测
python3 site-builder/scripts/verify_oauth_and_impersonation.py  # 需先 auth.js 登录
```

`verify_api_key_e2e.py` 会**创建真实 Key 并完成一次真实部署**，跑完删除并读回
核对；其中场景 ④ 会**临时关闸再开回来**（`finally` 恢复成进入时的值）。
`verify_oauth_and_impersonation.py` 需要一个真实用户 token：先跑一次
`node site-builder/clients/quick-desktop-proxy/auth.js "<endpoint>" "<client_id>"`
（refresh 有效期只有 1 天，超时重登是**预期行为**不是故障）。

### 实测坑（都在真机上踩过）

- **带请求体的 `DELETE` 在这条链路上必 403**。CloudFront 把 DELETE 的 body 交给
  Lambda@Edge（`include_body=True`，Edge 因此按真实 body 算 payload hash 去签
  SigV4），但转发到源站时那个 body 不在了——Function URL 按空 body 校验，
  `403 The request signature we calculated does not match…`，**在 panel 任何代码
  之前**就被拒。四组对照：DELETE 带 body → 403；DELETE 不带 body → 到达 panel；
  POST 带 body → 200；`DELETE /api/admins` 带 body → 同样 403。
  所以控制台的删除类动作是 `POST /api/keys/revoke` 与 `POST /api/admins/remove`；
  参数也**不搬进查询串**（那会把 `key_id` 与管理员邮箱写进 CloudFront 访问日志）。
  `panel/tests/test_handler.py::test_no_route_uses_delete_with_body` 按路由表锁住
  "一条 DELETE 都不许有"。
- **`deploy_agentcore.py` 不接受 `--skip-build`**（当 `server.py` 改过时）：
  tag 由构建输入的内容指纹派生，指向一个 ECR 里不存在的镜像会被脚本拒绝。
  于是"配置先行、镜像后行"的中间态在本仓库的设计下**不可分**，③ 是一步到位的。
- **预签名 PUT 不能带 `Content-Type`**（签名按无该头计算，带了必 403）。注意
  Python 的 `urllib.request` 在有 body 时会**自动补**这个头——用它上传必失败，
  而报错指向签名、把排查方向带向 IAM。
- **机器 token 的 scope 是 `{resource_server_id}/{scope}` 拼好的完整串**，拼接
  只在 `api_key_config.machine_scope` 发生一次。两处各拼一次会出现"建的 scope 与
  换 token 用的不是同一个"，而 Cognito 报 `invalid_scope`、文案指向 client 配置。

### 下线这个组件（**删掉 `[ApiKey]` 段是不够的**）

Codex 审查 2026-08-13 P1-3：组件门禁只对**首次部署**成立。已经启用过之后再把
`config.ini` 的 `[ApiKey]` 段删掉，`deploy_key_proxy.py` 会打印"跳过"并返回 0、
**一次 AWS 调用都不发**——于是线上的 Lambda、`mcp` route、已开的哨兵行、
未吊销的 Key、machine client 与它的 SSM secret **一个都不会被拆**。
配置显示 OAuth-only 而凭证通道仍然通，这正是本项目反复栽过的双真源。

**正确的下线顺序**（先断通道，再拆资源——反过来会留下一段"route 还在但后端没了"
的 502 窗口）：

```bash
# ① 先关闸：所有 Key 立刻 401（管理员在控制台点，或用上面的应急旁路命令）
# ② 吊销存量 Key（可选但建议：留着的话将来重新开闸它们会立刻复活）
#    按人吊销用 scripts/revoke_keys_for.py；要全量的话遍历 email-index
# ③ 摘掉 route（Edge 立刻不再把 mcp 子域转给 key-proxy）
aws dynamodb delete-item --region us-east-1 \
  --table-name "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('site-builder/config.ini');print(c['Platform']['routing_table'].split('#')[0].strip())")" \
  --key '{"subdomain":{"S":"mcp"}}'
# ④ 删 Lambda 与 Function URL
aws lambda delete-function --region us-east-1 --function-name site-key-proxy
# ⑤ 关掉网关侧两道门禁：删 config.ini 的 [ApiKey] 段后重跑
cd site-builder/mcp && python3 deploy_agentcore.py   # machine client 出 allowedClients、
                                                     # on-behalf 头出 allowlist
# ⑥ 收掉 machine client 与它的 secret（Cognito + SSM）——按需
# ⑦ 核对：无 [ApiKey] 段时 ⑧ 段会跑 absence 断言（**不是 SKIP**）
python3 site-builder/scripts/verify_deployed_components.py
```

第 ⑦ 步是这套流程能不能信的关键：`verify_deployed_components.py` 在**无
`[ApiKey]` 段**时不再 SKIP，而是断言"线上真的没有这条通道"——Lambda 不存在、
route 不存在、总开关不是开、`allowedClients` 没多出 machine client、
allowlist 没有 on-behalf 头。**凭证表本身是 `RemovalPolicy.RETAIN` + deletion
protection，不会也不该被删**（历史 Key 行是审计证据）；断言盯的是"开关不是开"，
因为只要它是开的、又还有未吊销的 Key，通道就仍然是通的。

### 已知取舍（向使用方说明）

- **用户离职后旧 Key 仍然有效**（决定 8）：Key 绑的是 email 字符串，
     **不联动 IdP 的账号状态**。IdP 账号一禁用，OAuth 那条路立刻走不通，
     但他手里的 Key 还能建新站点、重新部署、改自己仍有权限站点的策略，并持续
     产生 AWS 费用。所以离职流程里必须显式吊销：

     ```bash
     python3 site-builder/scripts/revoke_keys_for.py 离职者@example.com        # dry-run
     python3 site-builder/scripts/revoke_keys_for.py 离职者@example.com --yes  # 执行
     ```

     **控制台做不到这件事**（2026-08-13 更正）：本文档此前写的"控制台按 owner
     列得出来"是**错的**——`do_list_keys` 只查调用者自己的 email 分区、
     `keystore.revoke` 硬性要求 `row.email == actor`，管理员手里只有全局总开关
     （关掉会同时中断所有正常用户，不能当常规 offboarding 手段）。
     一个**不存在的补偿控制比没有更糟**：它让人以为 offboarding 已经有办法了。
     上面那个脚本就是这句话的落地（带 ops_log 审计，action 是
     `revoke_api_key_offboard`，与本人自助吊销分得开）。

     它**刻意不接进控制台**："能吊销任意人的 Key"放进公网端点要多背一整套授权面
     （谁算 admin、CSRF、防 key_id 枚举），而 offboarding 本来就是带 AWS 凭证的
     运维动作——攻击面留在 IAM 比留在 HTTP 小。

     注意吊销 Key **不影响**他已部署站点的存在，只断掉用 Key 调部署 MCP 的通道；
     站点的所有权转移/下线是另一件事。
- Key **只认证"谁在调部署 MCP"**，与访问已部署站点的 `require_login` /
  `allowed_users` 是两套独立的认证平面，它碰不到站点访问。
- 明文 Key 在服务端**只出现一次**（创建响应）。用户没抄下来只能吊销重发；
  列表接口与所有日志里都没有明文（有一条真机负测扫两个日志组做零命中断言）。

---

## ⑤d 访问统计（二期 M5）

站点 owner 在控制台看自己站点的 PV/UV 趋势与访问明细，Agent 侧同一组数字由 MCP 的
`get_site_analytics` 返回。数据来自 **Edge 主动埋点**（不是 CloudFront 访问日志）：
`origin_request` 在鉴权判完之后顺带写一行明细，**只记页面级请求、只记 `app-` 前缀的
站点子域**；每天一次 rollup 把昨天及更早的明细聚合成日粒度。

两张表都由 ④ 的执行器栈（`SiteDeployerStack`）创建：

| 表 | 键 | 保留 | 说明 |
|---|---|---|---|
| `site-access-events` | `site_date` + `ts_id` | TTL 90 天 | 明细。DynamoDB **Global Table**，副本区见下 |
| `site-access-daily` | `site_id` + `date` | TTL 400 天 | 日聚合。`RETAIN` + deletion protection |

### 部署目标是**五个**，顺序不能随便调

| # | 目标 | 命令 |
|---|---|---|
| ① | 执行器栈（两张表 + rollup Lambda + EventBridge 规则） | `cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never` |
| ② | 路由层（Edge 埋点 + edge role 的 PutItem） | `cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never` |
| ③ | 控制台 panel（统计页 + 站点列表迷你趋势） | `cd site-builder/panel && python3 deploy_panel.py` |
| ④ | key-proxy（**容易漏**，见下） | `cd site-builder/key-proxy && python3 deploy_key_proxy.py` |
| ⑤ | MCP（第 9 个工具） | `cd site-builder/mcp && python3 deploy_agentcore.py` |

**两条硬依赖，而且违反时两边都是静默的**：

- **① 必须在 ② 之前。** Edge 的 `PutItem` 授权的是三个副本 ARN；表不存在时写入
  AccessDenied/ResourceNotFound，而埋点失败**按设计被吞掉**（统计不能拖垮鉴权路径）
  ⇒ 没有任何报错，只是一条数据都不落。
- **① 必须在 ③ 之前。** `/api/sites`（控制台首页）要算每个站点的 `pv7` 迷你趋势。

**不要拿「控制台首页能打开」当作顺序正确的证据**：`pv7` 读失败是**刻意降级**的
（返回 `[]` = 未知，前端就不画那条线，只留一条 CloudWatch warning），首页照样正常
打开。要判定顺序对不对，看**统计页签 / MCP 工具 / 验收脚本**，或直接查 panel 日志里
有没有那条 warning。三档响度：

| 路径 | 表缺失 / 缺 IAM 时 | 响亮吗 |
|---|---|---|
| `/api/sites`（首页 + `pv7`） | 正常打开、趋势线不画、一条 warning | **不响亮** |
| `/api/sites/{id}/analytics`、`/visitors` | 500 | 响亮 |
| MCP `get_site_analytics` | 工具报错 | 响亮 |
| **Edge 埋点** | 异常被设计性吞掉 | **完全静默，只丢数据** |

**为什么 key-proxy 也在名单里**：M5 给 `permissions.py` 加了 `view_analytics` 能力，
而 panel、key-proxy、MCP **三个组件各自把这个共享模块打进自己的产物**（key-proxy 只
用它的 `EMAIL_RE`、从不读 `CAPABILITIES`，所以功能上无影响——但产物陈旧本身就是个
要留到下次去排查的坑）。**改了 `permissions.py`，这三个都要重部。**
`verify_deployed_components.py` 是唯一会点出产物陈旧的地方。

其它两条部署面的注意事项：

- **Edge 改动要 10-20 分钟做全球复制**。CDK 返回成功 ≠ 各区已经在跑新代码；紧接着
  跑验收会看到旧行为。用 `verify_deployed_edge.sh` 确认版本号。
- **panel 改了前端就不能带 `--skip-frontend`**（M5 动了 `app.js`）。那个开关只跳过上传，
  部署脚本仍会全绿。

### 副本清单三处必须一致

`site-access-events` 是 Global Table，副本区清单出现在三个地方，**唯一真源是
`router/config.ini` 的 `access_replica_regions`**：

1. deployer 的 CDK（`TableV2(replicas=...)`）——决定表真的有哪些副本；
2. router 栈的 IAM（edge role 的 PutItem 资源逐个副本 ARN）；
3. Edge 代码里的 `ACCESS_REPLICA_REGIONS` 常量（部署时字符串替换注入）。

第 2、3 条腿由 router 的单测锁在真源上，**但第 1 条腿钉的是 deployer 测试里的字面量
集合、看不见 `router/config.ini`**。所以「只往 `router/config.ini` 加一个区」会让两个
包的单测都绿，而 Edge 往一个不存在的副本写、异常被吞 ⇒ **那个区静默零数据**。
兜住这条的是 `verify_deployed_components.py` 第 ⑨ 段的真机 `describe_table`
`Replicas` 检查——单测覆盖不到。

**`_access_region` 的那行 INFO 日志是有意留下的**（`origin_request.py`）：每记一条页面
请求打一行 `[INFO] m5-region env=… arn=… -> …`。Lambda@Edge 拿不到自定义环境变量，
所以「副本路径在用、还是一直在跨区回落」这件事**线上只有这一行能证明**（回落是正确
但慢的，不报错，没有它就永远分不清两者）。三个值都不敏感。流量长上去之后再考虑采样。

### 新账号首次部署会踩一次：首建 Global Table 的 SLR 传播竞态

本账号第一张 DynamoDB Global Table 会让 CloudFormation 顺带创建
`AWSServiceRoleForDynamoDBReplication`，而约 **10 秒后**的建副本调用会失败：

```
UnrecognizedClientException: The security token included in the request is invalid
```

**这个报文是误导性的**——凭证没问题，是刚创建的 IAM principal 还没传播到副本区。
（可以先排除掉三个经典成因：副本区 `list-tables` 通不通、区域 opt-in 状态、
`get-session-token` 在副本区是否成功。都通的话就是这条。）

**处置：重跑同一条部署命令即可**（SLR 此后永久存在）。但**回滚会留下一张孤儿表**，
让原地重试因名字冲突必然失败：`site-access-daily` 是 `RETAIN` + deletion protection，
回滚时被打成 `DELETE_SKIPPED`——**这正是「统计数据不能被一次回滚删掉」这条不变量在
起作用，不是缺陷**。重试前的清理步骤：

```bash
# ① 确认它真的是空的——**必须实时 scan**：describe-table 的 ItemCount 有最多 6 小时延迟
aws dynamodb scan --table-name site-access-daily --select COUNT --region us-east-1
# ② 确认它不属于任何栈（describe-stack-resources 查不到 site-access 资源）
# ③ 关掉 deletion protection，再删
aws dynamodb update-table --table-name site-access-daily \
  --no-deletion-protection-enabled --region us-east-1
aws dynamodb delete-table --table-name site-access-daily --region us-east-1
# ④ 读回确认不存在，然后重跑部署
```

### 验收（部署完立刻跑，从仓库根）

```bash
python3 site-builder/scripts/verify_analytics_e2e.py
```

**必须用系统 `python3`**：`site-builder/deployer/.venv/bin/python3` 的 CA 信任库是空的
（`ssl.create_default_context().cert_store_stats()` 全 0），于是每一次 HTTPS 都
`CERTIFICATE_VERIFY_FAILED`——读起来像网络/代理故障，其实不是。这条对所有
`scripts/verify_*` 都成立。

脚本自建 fixture 站点、发真实请求、跑一次 rollup 再清理，数字精确到「一行不多一行
不少」。已在真机证明的关键性质：真实 Edge 写入落库且**非零**（区分「读不到」与
「没数据」）、三种 `decision` 逐字一致、真实 `LastEvaluatedKey` 分页、伪造游标不越权、
rollup **重算即修复**、**绝不封今天**、封口后面板读的是聚合表、panel 与 MCP 返回
**字段级相同**的 series。

**它的 MCP 那一段要求用户 OAuth token 是新鲜的**（二期把 refresh TTL 收到 1 天）。
过期时先登录一次：`node site-builder/clients/quick-desktop-proxy/auth.js`。
拿不到 token **不 SKIP 而是记 FAIL**（设计如此：`MIN_CHECKS` 达不到就
`sys.exit(1)`，「验收未完成」不能长得像「验收通过」）。

顺带一并跑 `verify_deployed_components.py`（第 ⑨ 段是 M5 的跨包一致性）与
`verify_console_e2e.py`（⑪ 段换成了统计端点的真实行为断言）。

### 日志组保留期（统一 90 天，2026-08-15 定稿）

**现行口径：平台全部日志组一律 90 天。** 用户 2026-08-15 的决定（原话「统一到 90 天，
内部访问量不大。如果真的变大，可以后面再来改」），**取代此前「统一 30 天」的口径**。
本节是这个数字的现行真源。

统一后的实测分布（三个区合计，2026-08-15；按 `site-` / `site_builder` / `SiteDeployer` /
`ApplicationWebRouter` 四个模式合并统计）：

| 保留期 | 数量 | 是谁 |
|---|---|---|
| **90 天** | **33** | **全部**：执行器 12 步 / rollup / panel / key-proxy / auth 服务 / auth pre-token（含 spike 遗留）/ CodeBuild / MCP 的 AgentCore runtime / 6 个 per-site Lambda / Edge 两函数（三区各 2）/ 执行器栈的 S3 auto-delete 自定义资源 |
| 未设 | **0** | —— |

（另有 2 个 731 天的 `FeishuQuickSso*` 组属飞书适配器——上游组件，不是本仓库的代码，不动。）

**这个数字的真源是代码，不是控制台。** 只手工改存量日志组是无效的：

- `deployer/functions/deploy_lambda_site.py` 的 `_ensure_log_group` 给**每个新建站点**的
  Lambda 写 90 天——手工改存量组不影响新站点，下次部署又按代码里的值写回去。
- `auth/alarm_pipeline.py` 的 ⓪ 段给 `site-auth-service` 组写 90 天（`deploy_auth.py` 重跑即收敛）。

两处的数字现在各有用例锁住：`deployer/tests/test_deploy_lambda_site.py::test_site_log_group_retention_is_ninety_days`
（moto 读回 `describe_log_groups`）与 `auth/tests/test_alarm_pipeline.py` 的 Stubber
`expected_params`。**2026-08-15 之前两侧都只断言"调用发生了"、不断言值**——把 30 改成
任何别的数字，两个包的单测都照样全绿。加断言时先反向验证过（改回 30 → 两侧确实变红）。

**「母 spec §6.3 统一 30 天」已作废。** 那句话的出处是
`docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md` §6.3
（原文：「原始 Edge 日志组统一设 30 天保留」），M5 spec 的 §0.3 与 M3 计划各引用了它。
这些都是**已实现快照 / 历史决策记录**，按仓库惯例不回改（见 CLAUDE.md「勿改」约定），
所以**现行策略只看本节**。`docs/phase2-requirements.md` 只写了"参照日志组 30 天先例"，
没定策略。

**方向决定有损与否**：30→90 无损（只让日志活得更久，可反复运行）；反向的 90→30 有损
（超过 30 天的日志被标记删除、约 72 小时内物理删除，事后调回也找不回）。把**未设**
（永久留存）设成 90 天同样是有损的——本轮那一个组只有一条 2026-07-28 起的流，
早于 90 天的日志根本不存在，才确认无损后执行。将来再收紧任何一档前先算这笔账。

### 两条埋点可观测性告警（原「两个已知的可观测性缺口」，2026-08-15 闭合）

一次性闸门覆盖不了这两件事，而**偶发变红的闸门比没有闸门更糟**（下一个人会学会忽略
它，连带它本来能抓的真问题）。所以两件都做成告警，**互为对方的守卫**：

| 告警 | 抓什么 | 谁抓不到它 |
|---|---|---|
| `m5-rollup-no-successful-invocation-24h` | 聚合器**本身**停了（定时任务没跑、或每次都报错） | 下面那条：聚合器不跑就不发指标，而缺数据要连续两天才告警 |
| `m5-edge-analytics-failed-global` | 任意 POP 所在区的埋点在**静默丢行** | 上面那条：rollup 调用成功 ≠ 它扫出来的数是对的 |

第二条的完整设计见下一节。第一条是 `Invocations - Errors < 1`（metric math，周期
86400、连续 2 个周期、缺失数据按 breaching），**留着别删**：它是「聚合器的宿主死了」
这一格，而聚合器正是第二条告警的数据来源——只有第二条时，rollup 停了会表现成
「指标缺数据」，但那要连续两天才够条件；只有第一条时，rollup 跑得好好的而扫描每轮
都失败会完全无声。

**两条都由执行器栈声明**（`site-builder/deployer/infra/app.py`，构造 ID
`EdgeAnalyticsFailedAlarm` / `RollupLivenessAlarm`；通知发到 `auth/deploy_auth.py`
建的那个 `site-builder-alarms`）。**手工 `put-metric-alarm` 建的不算交付物**，理由与
参数逐条的实测依据见下一节末尾「两条告警都由 CDK 声明」与「阈值与周期」。

### 跨区聚合 Edge 埋点失败（`m5-edge-analytics-failed-global`）

**问题**：Lambda@Edge 在 **POP 所在区**执行，日志就落在那个区。而 CloudWatch 告警
**不能跨区**——它只读同区指标、只能通知同区 SNS topic。本账号实测有 **8 个区**
执行过 Edge 函数，分布极不均：

| 区 | 占比 |
|---|---|
| `ap-southeast-1` | 87.8% |
| `ap-northeast-1` | 5.3% |
| `us-east-1` | 3.5% |
| 其余五个区合计 | 2.4% |

所以一条 us-east-1 的告警只盯得住 **3.5%** 的流量。

**为什么不按区各建一条**（曾经就是这么建的三条 metric filter + 一条告警，已删）：
别的部署**不知道自己的 POP 会落在哪些区**（随 CloudFront 选路、也随 AWS 新开区变化），
按区建的资源在新账号上根本不存在。同理不能用 Logs metric filter——metric filter
本身就是按区建的资源。

**做法**：把跨区扫描搭进**已有的** `site-access-rollup`（每天 00:20 UTC 那一轮，
us-east-1），**零新增基础设施**。每轮：

1. `ec2:DescribeRegions` **动态**枚举本账号已启用的区（实测 18 个）——不硬编码区列表，
   这就是可移植性要求本身；
2. 每个区按**形状**发现 Edge 日志组：前缀 `/aws/lambda/us-east-1.`。
   Lambda@Edge 的日志组在**每个执行区**都叫 `/aws/lambda/{函数归属区}.{函数名}`，
   前缀里的区是**归属区**（Edge 函数只能建在 us-east-1，平台硬约束），与执行区无关。
   **不能拼函数名**：它是 `{stack_name}-{origin_request_function_name}`，两段都来自
   `router/config.ini`（本仓库当前值是 `ApplicationWebRouterStack-application-web-router`），
   每个部署可以不一样；

   > ⚠️ **这个前缀会连账号里别人的 Edge 函数一起扫到——那是有意接受的代价，
   > 不要"顺手优化"掉。** 本账号实测就有两个不相干的：`us-east-1.redirectEdge`
   > （多数区都有）与 `us-east-1.BedrockproxyStack-…`（us-west-2）。它们**不可能
   > 产生假阳性**，因为判据是那两条中文 WARN 短语，别的函数不会打；代价只是每天多
   > 几十次 API 调用（18 区 × ≤3 组）。
   >
   > 把发现改成"硬编码栈名/函数名"看起来更精确，实际是**把这个设计存在的理由删掉**
   > ——那个名字来自 gitignored 的 `router/config.ini`，换个部署就扫不到任何日志组，
   > 而症状是指标恒为 0（= 一切健康），**没有任何东西会报错**。
   > `test_log_group_discovery_does_not_hardcode_this_deployment_s_stack_name`
   > 从 `router/config.ini.example` 读出栈名、断言它**没有**出现在
   > `access_rollup.py` 里，就是为了挡这次"优化"。
3. 对发现到的每个组发 `logs:FilterLogEvents`，窗口 24 小时，pattern
   `?"[WARN] 访问埋点失败" ?"[WARN] 埋点判定失败"`（`?A ?B` 是 CloudWatch 的 **OR**；
   空格分隔的裸短语是 AND，写错方向的症状是一条都匹配不到而两侧单测照样绿）。
   两条 WARN 都盯：一条是写失败、一条是判定失败，结果都是少一行且无人知晓；
4. 把总条数发成 **us-east-1 的一个指标** `SiteBuilder/M5 / EdgeAnalyticsFailedGlobal`，
   **不带任何维度**（加了区维度就又回到按区建告警）。

于是一条告警覆盖所有 POP，**包括将来才出现的区**。

**承重的两条设计**（改之前先读）：

- **扫成功且为 0 时必须发一个显式 0**。只在有失败时才发的话，「健康」与「扫描器瞎了」
  在指标上是同一个形态（都没有数据点），告警分不开这两件事。发了显式 0 之后，
  缺数据只剩一个含义——本轮没扫成——交给 `TreatMissingData=breaching`。
- **任何一个区扫不动就整体不发，绝不发部分和**。部分和会被当成「就这么多」= 健康。
  扫描失败时 rollup 只记一条 `logger.warning` 并**什么都不发**（既不发 0，也不是
  `except: pass`）；真正的信号是指标缺数据。扫描放在**封口之后**且异常不外抛——
  封口是耐久工作，观测不能把它带崩，也不该让 rollup 那次调用被标记成失败
  （那会触发 EventBridge 重试 + DLQ，还会把上面第一条告警一起拖响）。

**IAM**（`infra/app.py` 的 `rollup_role`，CDK 断言钉在
`tests/test_infra_tables.py::test_rollup_role_can_scan_cross_region_logs_and_publish_one_metric`
与 `…_has_no_over_broad_actions`）：资源里的 **region 段只能是 `*`**（要扫哪些区在
部署期未知），但其余各段都收窄——`logs:FilterLogEvents` 限定在
`log-group:/aws/lambda/us-east-1.*`（裸 `*` 等于让聚合器能读 auth/panel/站点的全部
日志，里面有邮箱），`cloudwatch:PutMetricData` 带 `cloudwatch:namespace` 条件
（该动作没有资源级权限，namespace 条件是唯一的收窄手段）。**没有任何新增的
DynamoDB 写权限。**

> **⚠️ 手工建过同名资源的话，必须先删再部——删除是部署的前置条件，不是善后。**
> 2026-08-15 实测：这两条告警先前是手工 `put-metric-alarm` 建的，于是第一次
> `cdk deploy` 直接失败：
>
> ```
> Resource of type 'AWS::CloudWatch::Alarm' with identifier
> 'm5-rollup-no-successful-invocation-24h' already exists.
> (at /Resources/RollupLivenessAlarm72085CAD)
> ```
>
> **CloudFormation 接管不了不是它建的资源**，所以手工建的东西不只是「不可复现」，
> 它会**主动阻塞代码版本永远无法存在**。当时的判断是「先部署成功、再删手工资源，
> 免得中间出现监控空窗」——**顺序正好是反的**。正确做法：先
> `aws cloudwatch delete-alarms --alarm-names <名字>`（本轮还一并删了三个分区
> metric filter），再 `cdk deploy`。空窗只有几分钟，而且新告警本来就要等
> 指标有数据才离开 `INSUFFICIENT_DATA`。失败那次 `LastUpdatedTime` 没动、
> 零部分应用，所以直接重部即可。
>
> 这条对**任何**与 CDK 资源同名的手工资源都成立，不限于告警。

**两条告警都由 CDK 声明，不要手工建。** 真源是
`site-builder/deployer/infra/app.py`（挨着 rollup Lambda 与那条 EventBridge 规则），
随执行器栈一起部署：

```bash
cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH \
  npx -y aws-cdk@latest deploy --require-approval never
```

**为什么不能 `aws cloudwatch put-metric-alarm`**（这两条一开始正是那么建的，已作废）：
手工建的告警**新部署拿不到**、**被人删掉不会被任何东西发现**，而当时的 DEPLOY.md
还把它们写成「M5 不交付的缺口」——即它不是可复现的交付物。这与本文档
「日志组保留期」一节刚立的**真源是代码不是控制台**是同一条纪律。
配置由 `tests/test_infra_tables.py` 的 5 条断言逐项钉住（指标坐标从
`access_rollup.py` 派生，不在测试里抄第二份；阈值/周期/2-of-2/breaching/
两组通知动作全部按值断言）。

**SNS topic 由本栈"引用"而不是"创建"**：`site-builder-alarms` 的真源是
`auth/deploy_auth.py`（`alarm_pipeline.py` 幂等收敛，**连带那个必须由收件人手工点
确认的邮件订阅**）。两个创建方就是两个真源，症状是告警照样进 ALARM 而没有任何人
收到通知（已确认的订阅挂在另一个 topic 上）。两侧的名字字面量由
`test_alarm_topic_name_matches_the_script_that_creates_it` 跨文件 AST 断言钉住
——因为 **CloudWatch 不校验 action 指向的 topic 是否存在**，任一侧改名后告警照样
建得出来、照样进 ALARM，只是通知发进虚空。

> 由此还有一条**部署顺序**的软依赖：全新账号若先部执行器栈、后跑 `deploy_auth.py`，
> 那段时间里告警存在但 topic 还不存在 ⇒ 通知无处可去。名字一致时 topic 建出来后
> 会自动生效（ARN 对得上），所以不是硬阻塞，但别把它当"已经在通知了"。

⚠️ **阈值与周期是按实测流量定的，换环境必须重算**（与登录失败告警同一条纪律）：

> **本仓库环境的取值（2026-08-15）**：`--threshold 3`（配 `GreaterThanThreshold`
> ⇒ 一天 ≥4 条失败、连续两天才响）、`--period 86400`、
> `--evaluation-periods 2 --datapoints-to-alarm 2`、`--statistic Maximum`、
> `--treat-missing-data breaching`。
>
> · **流量分母（先纠正一个算错的数）**：实测 18 条 `[INFO] m5-region`（每次尝试写
>   明细恰好打一行）落在 **约 3.2 小时**里 ⇒ **≈5.6 次/小时 ≈ 134 次/天**。
>   本节此前写的是「7 天 18 次（≈2.6 次/天）」，**那个除法错了约 50 倍**：
>   `[INFO] m5-region` 这行是 `8a8fb20` 才随路由层部署上线的（`git log -S` 只有那
>   一个提交动过它），而查询用的是 7 天窗口——**18 条跨不了 7 天，它们只跨了探针
>   上线以来的那几小时**。分母改用探针**寿命**而不是查询窗口之后，与
>   `analytics.py` 里独立写着的「全平台日均 124 行」对得上（那个数字的出处是
>   `docs/design/M5-FINDINGS.md` §4.26，**gitignored、新 clone 里没有**；能核对的
>   tracked 依据是 `analytics.py` 自己那行注释）。
>
>   > **这个错法很容易再犯**：刚部署一行新日志就去 CloudWatch 拉「N 条 / 7 天」，
>   > 拿到的一定是被稀释过的速率。查之前先问一句「这行日志存在多久了」，
>   > 分母取 `min(查询窗口, 日志上线至今)`。
>
> · **旧的「1 小时内 > 10 条」仍然作废**（这条结论不受上面的纠正影响，也正是这轮
>   改造的出发点）：5.6 次/小时的**100% 失败**也凑不满 10 条/小时 ⇒ 那条告警**在数学
>   上不可能触发**，而它要抓的正是"全都在丢"。
>
> · **为什么阈值是 3**：`4/134 ≈ 3%` —— 这条告警说的是「一天丢了 3% 以上的访问行，
>   而且两天连着」。按各区流量占比换算它能抓到多大的故障：
>
>   | 故障形态 | 每天失败条数 | 这条告警 |
>   |---|---|---|
>   | 全平台埋点全坏 | ≈134 | 抓到（第 2 天） |
>   | `ap-southeast-1`（87.8%）全坏 | ≈118 | 抓到（第 2 天） |
>   | `ap-northeast-1`（5.3%）全坏 | ≈7 | 抓到（第 2 天） |
>   | `us-east-1`（3.5%）全坏 | ≈4.7 | 抓到，但要等到某两天都 ≥4，可能几天 |
>   | 单个小区（各 <1%）全坏 | <1 | **抓不到** —— 见下面的覆盖边界 |
>
> · **⚠️ 底噪没有测过，所以 3 是「假设」不是「结论」**。我们手上关于失败率的全部
>   证据是**18 次尝试里 0 次失败**；按 rule of three（95% 单侧上界 ≈ 3/n）这只能把
>   失败率压到 **≲17%** —— 也就是说「底噪是 0」与「底噪是 20 次/天」**现有数据分不
>   出来**。而底噪可能确实非 0：埋点写入**刻意不重试**（`origin_request` 那边
>   `max_attempts=0`，统计不该拖慢请求），跨区回落实测 719ms 冷启动对 2s 读超时。
>
>   取 3 是在两种错法之间选，不是精确计算出来的：**若底噪是 1%（≈1.3 次/天）**，
>   `threshold=0` 会长期误报（Poisson `P(X≥1)≈73%`，连着两天 ≈53% ⇒ 几乎天天响），
>   而 `threshold=3` 约 **1.4 年**才误报一次（`P(X≥4)≈4.6%`，成对 ≈0.2%）；
>   若底噪真是 0，两者都不误报，代价只是 3 比 0 晚一点发现小规模丢失。
>
>   **怎么证伪（部署当天就能做）**：手工调一次 rollup 发出来的那个数，就是底噪的
>   第一个真实 24h 样本。**它 >0 就说明底噪不是 0**，本段的假设当场被推翻，按下面
>   的复查条款处理。
>
> · **复查触发条件（写下来，免得变成永远不动的数字）**：上线**第一周**内若在没有
>   真故障时响过 ⇒ 底噪高于 0 ⇒ 抬阈值或换成比率；一周内没响过，则这个 3 保留，
>   并在流量再涨一个数量级时重算 3% 那笔账。
> · **为什么要求连续两个周期**：周期 86400 的告警评估的是**滚动 24 小时窗口**
>   （实测 `StateReasonData` 的 `startDate` 就是 `queryDate - 24h`，不对齐 UTC 零点）。
>   而每日那一轮的落点会有抖动（EventBridge 调度延迟 + 封口耗时），只要今天比昨天晚
>   一点，窗口里就会有几分钟一个数据点都没有 ⇒ 1/1 配置下**系统健康时也会响**。
>   要求 2/2 之后，单个空窗被相邻窗口的数据点兜住。代价是检出延迟到约 48 小时——
>   可以接受：系统性故障（IAM 挂了、副本表没了）不会自愈，而「宿主死了」这一格由
>   `m5-rollup-no-successful-invocation-24h` 在 24 小时内独立覆盖。
> · **`Maximum` 而不是 `Sum`**：手工重跑 rollup 会在同一个窗口里多打一个数据点，
>   `Sum` 会把它们加起来、凭空越过阈值。
> · **已知的覆盖边界（绝对阈值的代价）**：灵敏度挂在流量上，而且是挂在**出故障
>   那一部分**的流量上。上面那张表最后一行就是这个边界：占比 <1% 的区整个坏掉，
>   一天也凑不满 4 条，这条告警永远不会响。流量若整体掉下来（放假、演示环境闲置），
>   同一个边界会向上蔓延到更大的区。所以「写路径是不是好的」这件事的确定性检查
>   仍然是 `verify_analytics_e2e.py`（做一次真实访问再逐行核对），告警负责持续盯着，
>   两者不可互相替代。
> · **什么时候改成比率告警，以及为什么不是现在**（写在这里免得下一个人只是"觉得
>   3 太敏感/太钝"就顺手改数字）：比率 = 失败条数 ÷ 当天埋点写入尝试数，分母可以由
>   rollup 用**同一次跨区扫描**数 `[INFO] m5-region` 那行、一并发第二个指标算出来
>   （不引入第二个真源）。它比绝对值好在流量变化时不用重算阈值。
>
>   **这一轮没做，理由是它今天不会改变任何判断**：比率的分子仍然是同一个未知的
>   底噪 —— 底噪未测量时，`失败/尝试 > x%` 该取多少与 `失败 > n` 该取多少是同一个
>   猜。先用一周真实数据把底噪测出来，再决定是抬绝对阈值还是换比率，那时两者都
>   有依据。**改造的触发信号**（任一成立即动手）：① 复查期内这条告警在没有真故障时
>   响过；② 日写入尝试数再涨一个数量级（≈1300/天）——那时 3 条对应 0.3%，会被偶发
>   跨区超时刷响；③ 出现"看一眼发现只有一两条、没什么可做的"ALARM。

**这个账号上曾经存在、需要删掉的东西**（CDK 里那两条告警上线后即被取代；新部署
根本不会有这些，**别照着老状态复原**）：

| 要删的 | 是什么 | 为什么取代 |
|---|---|---|
| `m5-edge-access-write-failed` × 3 | us-east-1 / ap-southeast-1 / ap-northeast-1 各一条 metric filter，指标 `SiteBuilder/M5 / EdgeAccessWriteFailed` | metric filter 本身就是**按区建的资源**，新部署不会有；而三条里只有一条的指标真被告警读着 |
| `m5-edge-access-write-failed-us-east-1` | 手工建的告警（Sum / 3600 / 阈值 10 / `notBreaching`） | 只覆盖 **3.5%** 的流量；阈值 10 在本环境**永不触发**；`notBreaching` 让"扫不到"与"没失败"同样判健康 |

三条 filter 都指向同一个日志组名——那部分是**对的**（Lambda@Edge 的日志组名在各区
相同，见上面那段），问题在于**告警不能跨区**，于是另外两个区的指标没有任何告警在读。

```bash
for r in us-east-1 ap-southeast-1 ap-northeast-1; do
  aws logs delete-metric-filter --region $r \
    --log-group-name /aws/lambda/us-east-1.{路由层栈名}-{origin_request_function_name} \
    --filter-name m5-edge-access-write-failed
done
aws cloudwatch delete-alarms --region us-east-1 \
  --alarm-names m5-edge-access-write-failed-us-east-1
```

**顺序要求**：先部署（让 CDK 那两条告警到位）**再删**，否则中间有一段完全无覆盖的窗口。
删完读回确认：三个区 `describe-metric-filters` 都查不到该名字、
`describe-alarms` 查不到旧告警、且**查得到** CDK 建的那两条。

**`SiteBuilder/M5` 里那个 `IamProbeDeleteMe` 指标是什么**：一次性 IAM 探测的产物
（用 `sts:GetFederationToken` 带 rollup 那套策略验证过正/负权限，见下面 PITR 那节的
同一条纪律）。值恒为 0，**没有任何告警读它**。CloudWatch **指标名无法删除**，
约 15 个月后自然消失——所以看到它不是有东西坏了。

### 数据表的时点恢复（PITR）：防的是"写坏"，不是"被删"

四道保护各管一段，**互不重叠，别拿一个当另一个用**：

| 机制 | 挡什么 | 挡不住什么 |
|---|---|---|
| `RemovalPolicy.RETAIN` | 删栈 / 资源被替换时 CloudFormation 不删表 | 一条 `aws dynamodb delete-table` |
| `deletion_protection` | 直接调 `DeleteTable`（控制台、CLI、任何拿到该权限的脚本） | **写坏** |
| TTL | 到期行自动消失 | **写坏** |
| **PITR** | **写坏**——回到过去 35 天内任意一秒 | 表被删（PITR 随表一起消失） |

**为什么这一轮必须补上**：`site-access-daily` 的 400 天趋势在明细 90 天 TTL 到期后
**不可重建**（`infra/app.py` 自己就是这么声明的），而 rollup 的设计**就是反复覆盖同一
批行**（连"归零对账"都会覆盖已存在的行）。一个跑错版本的 rollup、一个手工补跑脚本、
或写入逻辑的一个缺陷，都能把没有第二份来源的历史改坏——而上面前三道**一道都拦不住**。

覆盖范围（CDK 声明，`infra/app.py` 的 `_PITR`）：

- **凡 `RETAIN` 的表都开**：`site-admins`、`site-ops-log`、`site-api-keys`、
  `site-access-daily`。判据不是手抄的表名，而是**"设了 RETAIN"这个声明本身**
  ——设 RETAIN 就等于宣布"这份数据不能丢"，那个宣布不该只在删表这条路径上成立。
  `test_every_retained_table_has_pitr` 按模板里的 `DeletionPolicy` 推导，
  **新增 RETAIN 表时自动被要求**（与紧邻的 deletion-protection 那条同一套推导）。
- **明细表 `site-access-events` 也开**，尽管它是 `DESTROY`（90 天滚动、删栈可丢）：
  它是聚合表的**重建来源**。模块 docstring 与 spec §0.1 用来否掉"日志侧聚合"的那条
  属性是「只要明细还在，数就还能算回来」——那句话只在明细**自己没被写坏**时成立。

⚠️ **两种资源类型的属性形状不同，断言必须读渲染后的模板**（实测）：

- `AWS::DynamoDB::Table` → `PointInTimeRecoverySpecification` 在**顶层**；
- `TableV2` 渲染成 `AWS::DynamoDB::GlobalTable` → 顶层**根本没有这个键**，
  它在**每个 replica 里各一份**（CDK 的表级 prop 会分发到含主副本在内的全部 3 个）。

拿 `Table` 那个形状去断言 GlobalTable 会永远查不到那个键 ⇒ **用例空转而两侧都"绿"**。
所以那条断言（`test_every_global_table_replica_has_pitr`）**逐个副本**检查，而不是
"有一个开了就算"——PITR 是按副本计费与恢复的，只在一个区开等于另两个区没有可回溯
的点。反向验证里为此单独注入过一条：只把 `ap-southeast-1` 那一个副本关掉（表级 prop
仍在），断言要能只点出这一个区。它也**按资源类型推导**（扫全部 GlobalTable 而不是
点名 `site-access-events`），所以将来再加多区表会自动被要求。

**部署后必须读回**，不要拿 `StackStatus` 当证据：

```bash
for t in site-access-daily site-access-events site-admins site-ops-log site-api-keys; do
  echo -n "$t: "
  aws dynamodb describe-continuous-backups --table-name $t --region us-east-1 \
    --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
    --output text
done
# 明细表的副本要逐区查（PITR 按副本设）
for r in ap-southeast-1 ap-northeast-1; do
  echo -n "site-access-events@$r: "
  aws dynamodb describe-continuous-backups --table-name site-access-events --region $r \
    --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
    --output text
done
```

全部应为 `ENABLED`。**`site-deploy-jobs` 与 `site-sites` 目前没有开**（两者都是
`DESTROY` 语义）。`site-sites` 值得单独评估一次——它存 `owner` / `allowed_users`，
是**授权投影**，写坏的后果不是"数字不好看"而是"权限错了"；只是它能从各站点的
部署记录部分重建，且不在本轮范围内。**这是一个明确留下的待决项，不是遗漏。**

---

## ⑥ 客户端接入（Task 22）

**Claude Code（先做，自动化程度高）**：

```bash
mkdir -p ~/.claude/skills && cp -r site-builder/skills/site-builder ~/.claude/skills/
# 必须带 --client-id 与固定回调端口（Cognito 不支持 dynamic client registration，
# 裸 add 报 "Incompatible auth server"）；并需在 deploy-mcp client 预注册
# http://localhost:18765/callback——完整命令见 docs/client-setup.md
claude mcp add --transport http site-builder-deploy {mcp_endpoint_url} \
  --client-id {mcp_client_id} --callback-port 18765
```

配好后在会话里 `/mcp` → site-builder-deploy → Authenticate 走平台 IdP 的 OAuth（飞书场景即飞书授权页）。
新会话提示："用 site-builder 技能给我做一个团队读书清单站点，能加书标记读完，全组织可看，做完部署" → 应走完 Skill 工作流 → MCP 部署 → 返回 URL → 浏览器飞书登录 + 加书验证。
（已实测走通：真实站点部署成功，validate→smoke-test 一次过。）

**Amazon Quick Desktop（人工）**：导入 site-builder Skill；它的 Remote MCP 不支持 OAuth——走本地 stdio 代理，或启用 API Key 组件后用 Remote MCP + `X-API-Key`。

完整步骤、逐客户端冒烟清单与 email claim 排查办法见 [**docs/client-setup.md**](docs/client-setup.md)。

---

## ⑦ 端到端彩排（Task 23）

```bash
# 前一天跑：全链路 E2E（用 JWT_SECRET mint 测试会话 cookie，自动化 CRUD，无需人工扫码）
cd {仓库根}
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q
```

预期 4 passed：static 200、notes 未登录 302 + 登录后 CRUD + author=飞书邮箱、expenses DSQL CRUD、undeploy 后 404。

演示叙事（10 分钟）与故障预案见 plan Task 23。

---

## 部署后回填检查清单

`site-builder/config.ini` 全部字段应非空：


| 段          | 字段                                                     | 来源                          |
| ---------- | ------------------------------------------------------ | --------------------------- |
| [Platform] | admin_seed                                             | 你指定的首个管理员邮箱（① 末尾的种子脚本要读）    |
| [IdP]      | provider_name / issuer / client_id / client_secret     | 你的 IdP；secret 可用环境变量注入不落磁盘  |
| [Cognito]  | user_pool_id / domain / site_client_id / mcp_client_id | ① `deploy_pool.py` 输出       |
| [DSQL]     | cluster_endpoint                                       | ③                           |
| [Deployer] | admins_table                                           | 固定 `site-admins`（④ 建表）      |
| [Deployer] | edge_role_arn                                          | ② CfnOutput EdgeRoleArn     |
| [Deployer] | state_machine_arn                                      | ④ CfnOutput StateMachineArn |
| [MCP]      | endpoint_url                                           | ⑤                           |
| [Alerting] | email                                                  | 你指定的告警收件人（**必须手工点确认订阅链接**） |
| [Panel]    | ops_log_table / session_codes_table / console_version   | 直接用 `.example` 的默认值（⑤b 读它） |

`router/config.ini` 的 `[SiteBuilder]` 还需 `require_idp_claim` /
`trusted_idps`（见 ②）。

一次性动作（**不做则安全边界不成立，且测试覆盖不到**）：

- [ ] admin 种子已注入（`seed_admin.py --apply`，在 ④ 之后）
- [ ] `require_idp_claim = true` 且部署出去的 Edge 代码已核对（零占位符）
- [ ] 登录失败告警由 `deploy_auth.py` 自动收敛（**不手工建**），且 `verify_auth_alarm.sh` 全绿（含声明收件人的 confirmed 订阅）
- [ ] 两条埋点告警**由执行器栈部署出来**（`m5-rollup-no-successful-invocation-24h`
      与 `m5-edge-analytics-failed-global`，**不手工建**），且阈值按**本环境实测流量**
      重算过并写回文档（见「两条埋点可观测性告警」；起步值在低流量下会让告警永不触发）
- [ ] 五张表的 PITR 读回全部 `ENABLED`（`describe-continuous-backups`，明细表要
      **逐副本区**查），不拿 `StackStatus` 当证据（见「数据表的时点恢复」）
- [ ] 自己走过一次真实登录，claim 值与 ① 的实测基线一致
- [ ] （部署了 ⑤b 控制台时）`verify_console_e2e.py` 全绿，且在**真浏览器**里确认过
      `__Host-sb_console` 落盘：Path=/、**无 Domain=**、HttpOnly+Secure。
      DevTools 的 Domain 列对 `__Host-` cookie 显示的是**精确 host 且无前导点**，
      那是浏览器推断的 host-only 归属，不代表服务端设了 Domain（设了会被整条丢弃）；
      对比 `sb_session` 显示的是 `.{base_domain}`（**有**前导点 = 真的设了 Domain）

SSM 参数：`/site-builder/jwt-secret`（§0 手工建）、`/site-builder/site-client-secret`（① 的 `deploy_pool.py` 写入）。

## per-site 部署租约（M7 加固；排障必读）

同一站点同时只允许**一次**部署或下线。实现是 jobs 表里一条 `site-lease#<site_id>`
行（不是 job；故意不带 site_id/owner/status，所以不进任何 GSI、也不被 sweeper
扫到），由 `confirm_upload` / 下线的建 job 事务原子获取。**没有释放动作**：
判据是"持有者那条 job 还是 RUNNING 吗"，job 一到终态租约自动可抢。

排障口径：

- 用户报"站点 X 已有一次部署/下线正在进行" ⇒ 读 `site-lease#X` 行拿 holder
  job_id，看那条 job：RUNNING 且真在跑 ⇒ 等它；RUNNING 但卡住 ⇒ reconciler
  两层收敛（EventBridge 实时 + sweeper ≤45 分钟）会把它推成 FAILED，随即可重试。
- **不要手工删租约行**去"解锁"：那正是它要挡的第三次并发操作。真要人工介入，
  先把 holder job 收敛到终态（查明它确实没有活着的 execution），租约自然放开。
- **这是跨组件协议**：deployer 栈、MCP、panel 三方都要跑到带租约的版本，
  只升级一部分 = 互斥只对一部分入口生效（另一部分是后门）。升级窗口内避免
  并发部署同一站点。

## 合同收紧（2026-08-18）：frontend/index.html 必须存在且非空

`contract/redlines.py` 新增要求：任何 tier 的站点包必须带非空的
`frontend/index.html`（Edge 把 `/` 固定改写为 `/{prefix}/index.html`，缺它则
首页**永久 403**，而健康门/冒烟都发现不了）。**升级后的行为变化**：此前能部署
成功（但首页 403）的包，现在在 validate 一步就被拒，错误信息点名 index.html。
存量六个真实站点都带 index.html，不受影响；若有用户报"以前能部署现在不行"，
先看是不是这一条。

## 已知限制与延后项（向客户声明）

- 顶域 cookie 使所有 `app-*.{base_domain}` 站点共享一次登录（PoC 可接受，产品化需按站点隔离会话）
- PoC 仅 Node.js 后端（Python 3.13 延后）
- MCP 接入有 OAuth 与 **API Key** 两条路（API Key 走可选组件 key-proxy，二期 M4 已交付；
  无 `[ApiKey]` 段时该组件整体不存在）
- CloudFront 全站禁缓存（正确性优先；精细缓存延后）
- 详见设计文档 §8 风险 / §9 范围外

### 状态机级超时/中止的落账（二期 M3 已闭合，此节保留说明机制）

各步骤都挂了 `add_catch(States.ALL) → MarkFailed`，所以**步骤内**的失败都会把
job 写成 FAILED（真机核对过：历史 3 个 FAILED 执行的 job 都是
`status=FAILED, phase=provision-db`，没有卡住的）。

但有两类终止**不执行任何 State**，因此 `mark_job` 根本不会被调用：

- 状态机级 `TimeoutSeconds=1800`（30 分钟）到点 → 执行 `TIMED_OUT`；
- 人工 `StopExecution` → 执行 `ABORTED`。

**二期 M3 已闭合这个缺口（原先 job 会永久停在 `RUNNING`）。** 现在是两层收敛，
共用同一个条件更新函数（`deployer/functions/reconcile_job.py`）：

- **实时层**：EventBridge 规则 `site-deploy-terminal-status` 订阅本状态机的
  执行状态变更、只匹配 `TIMED_OUT`/`ABORTED` → `site-deployer-reconcile-job`
  把对应 job 落成 FAILED（带 SQS DLQ）；
- **兜底层**：`site-deployer-sweep-jobs` 由 Scheduler 每 30 分钟 `DescribeExecution`
  扫一遍长时间 RUNNING 的 job（防事件丢失/规则被停用）。

收敛是**条件更新且不带 phase 条件**（超时可发生在任意 phase），幂等、乱序安全、
对不存在的 job 不创建、对已是终态的 job no-op。

真机核对：`./site-builder/scripts/verify_sfn_failure_paths.py`（11 项，两层各自
有效性都验）。规则与函数是否真的在线上启用，用这条看：

```bash
aws events list-rules --query "Rules[?Name=='site-deploy-terminal-status'].[Name,State]" --output text
aws lambda get-function --function-name site-deployer-reconcile-job --query 'Configuration.LastModified' --output text
```

### 账号级加固（可选，**不是部署步骤**）

`site-builder/policies/` 下有一份 SCP 模板
（`scp-site-invoke-only-edge.json`）与它的说明（`policies/README.md`），用来收窄
"同账号 principal 直接 `lambda:Invoke` 站点函数、绕过 Edge 鉴权"这条路。
**贴不贴都能正常运行，本手册的任何步骤都不依赖它。**

**这份模板未经真机验证**：`aws:PrincipalArn` 对 assumed-role 会话的取值没有实测过，
所以模板用 `ArnNotLike` 容忍两种写法。**贴之前先用 IAM policy simulator，或先挂到一个
空 OU 上试**——写错的后果是把平台自己锁在外面。（相对地，`policies/README.md` 里那条
生成用户站点 ARN 列表的命令**已在真机跑过**：输出正好是用户站点函数，平台函数全被排除。）

贴之前必须读 `policies/README.md` 的三条边界，其中两条会直接决定它有没有用：

1. **SCP 对 Organizations 管理账号无效**（AWS 硬规则，包括 root）。**本部署所在的
   账号就是管理账号** ⇒ 在这里贴上它对本账号里的 IAM 身份没有任何约束。想真的生效
   得先把工作负载搬到成员账号。**所以：贴了它不等于那条绕过被关闭。**
2. **资源不能用 `function:site-*` 通配**：平台自己的函数与用户站点共用 `site-`
   命名空间，通配会同时命中 `site-panel` / `site-auth-service` / `site-deployer-*`，
   后果是**所有部署与下线立刻失效**。模板用显式 ARN 列表占位符，README 给了生成命令
   （按 `PLATFORM_FUNCTION_NAMES` 排除平台函数）。
3. 例外名单里 `site-deployer-exec-role` **必须在**——M7 的健康门会直接 invoke 候选
   颜色，漏了它每次部署都在健康门失败。

代码侧的 `functions/edge_caller.py` 只挡得住**经 Function URL** 的那条路
（`callerId` 由 STS 填写、不可伪造）；**直接 `lambda:Invoke` 可以自造整个 payload
里的 `callerId`**（2026-08-15 对 site-panel 实测：伪造成 Edge 的 RoleId → 200）。
两者合起来是纵深防御，**不是**这条缺陷的修复——当前暴露面按 README 那三条边界判断。

### MCP runtime 的信任边界（不要外推 IAM 的保护范围）

**部署 MCP 的 runtime 角色对"站点管理操作"而言属于 TCB（可信计算基）。**
它的 IAM 策略按属性白名单收窄了**可写哪些字段**，但**不能**限制"可写哪些
站点的行"：

- `owner` 必须在白名单内（建站写 owner、`transfer_owner` 改 owner 都是正常
  功能），所以 runtime 一旦被攻破，**可以把任意站点的 owner 改成攻击者**，
  再以新 owner 身份走正常接口部署/下线/改权限。
- 这条路径 IAM 关不掉：`dynamodb:LeadingKeys` 只能把主体限制在"由其身份推出
  的分区键"（多租户模式），而本 runtime 服务全部用户、合法地需要访问任意
  `site_id`；真正的授权规则（owner/collaborators）**存在行里**，是数据驱动的，
  而 IAM 策略是静态的、读不到行内容。
- 同一角色另外还持有 jobs `PutItem`、`states:StartExecution` 和 undeploy
  Lambda 的调用权限。

因此**站点归属的最终裁决者是应用层代码加上 runtime 角色自身的完整性**，
不是 IAM。属性白名单的价值在别处：它挡住对部署链字段
（`data_tables` / `migrations_applied` / `last_job_id` …）的篡改，
以及路由表的 `static_prefix` / `api_target`（改这两个可劫持流量）。

要让 IAM 真正兜住站点归属，必须把建站 / `transfer_owner` / 权限写入拆成
**各自持有独立角色并做服务端授权**的窄接口（M3 控制台与 key-proxy 已按
"独立 IAM 角色"设计，见设计文档 §2）。那是架构改动，未纳入 M1+M2。

#### 既然 runtime 是 TCB，镜像完整性就是站点归属的安全边界

`deploy_agentcore.py` 已落实下面五条。**改动构建链前先读这段**——每一条都
直接对应"谁能换掉这个 TCB"：

| 措施 | 不做会怎样 |
|---|---|
| ECR 仓库 `imageTagMutability=IMMUTABLE`（省略时 AWS 默认 **MUTABLE**） | 任何有 push 权限的主体覆盖同名 tag 即换掉 TCB，无痕迹 |
| 镜像 tag = `git-<sha>`（构建输入未提交时 `wip-<内容指纹>`，默认拒绝部署，联调加 `--allow-dirty`） | 用 `latest` 时"线上跑哪份代码"无法回答 |
| runtime 引用 **image digest**，不引用 tag | tag 是名字，digest 才是内容 |
| 复用已有 tag 前校验 runtime 当前 digest 与其一致（不一致 fail closed，人工核实后 `--trust-existing-image` 放行） | tag 从 commit SHA 可预测——push 权限收敛到 CI 之前，抢占者可提前 push 恶意镜像占住 `git-<sha>`，IMMUTABLE 反而保护它不被覆盖，脚本会跳过构建直接把攻击者的 digest 部署为 TCB |
| 容器非 root（UID 10001）且 `/app` 保持 root:root 只读 | 进程内漏洞升级为改写 server.py 的持久后门 |
| 基础镜像钉 digest（`python:3.13-slim@sha256:…`） | 上游重指 tag 即在无人察觉时换掉 TCB，历史构建不可复现 |
| 依赖锁版本 + `--require-hashes` | 被污染的上游版本 = 任意站点 owner 可被接管 |

⚠️ **`--provenance=false` 不是供应链保护**。它是关闭 buildx 的 attestation
manifest（因为 AgentCore 的 CreateAgentRuntime 校验不认，见 ⑤ 的坑），
与镜像完整性无关——不要把它当成一项防护写进任何说明。

仍未做、需要时另开一轮：把 `scanOnPush` 的扫描结果变成**部署 gate**
（当前只是开着扫描，有高危发现也不阻断部署）；以及为 ECR 加仓库策略，
把 push 权限收敛到 CI 主体。

容器内不执行站点提供的代码（站点代码只经 CodeBuild 打包，不进 MCP 容器）。

## 2026-07-27 独立审查后的修复（已实证验证，部署前必读）

两轮独立审查（本机 + Codex）确认的 P0 已修复并用真实 AWS API 验证：


| 问题                                                        | 修复                                                                                            | 验证方式                                                           |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Edge S3 签名缺 `x-amz-content-sha256`，所有静态页 400              | 改用 `S3SigV4Auth`                                                                              | 真实 us-east-1 桶探针：修前 400 InvalidRequest，修后 404 NoSuchKey（签名被接受） |
| 顶域 `sb_session` 被转发给不可信站点后端，可跨站重放                         | Edge 验签后按 origin 剥除；新增 origin-response 剥除站点写的平台 cookie                                        | 4 个场景单测（站点剥除/站点自有 cookie 保留/auth 子域保留/伪造标记被剥）                  |
| Function URL 缺 2025-10 起要求的第二个权限                          | 三处各加 `lambda:InvokeFunction` + `InvokedViaFunctionUrl`                                        | AWS 官方文档 urls-auth 明确要求两者                                      |
| exec role 缺 `lambda:GetFunctionConfiguration`（waiter 轮询它） | 补该 action                                                                                     | `aws iam simulate-custom-policy`：修前 implicitDeny，修后 allowed    |
| `site_name` 未校验 → DSQL admin SQL 注入 + IAM/Lambda 命名炸裂     | `common.validate_site_name` 入口卡 `^[a-z][a-z0-9-]{1,29}$`                                      | 单测覆盖注入串/空格/大写等 9 种非法输入                                         |
| `npm install` 执行站点 preinstall 脚本（CodeBuild 内任意代码执行）       | `--ignore-scripts` + 删 `.npmrc` + 红线拦生命周期脚本 + CodeBuild 角色收窄到 `validated/*` 只读（validate 产出的不可变工件，非 owner 上传的原包）、`artifacts/*` 只写 | 红线单测 + synth 确认无整桶读写                                           |
| 站点 SQL 以 DSQL admin 执行，可跨 schema 读写/销毁                    | 拆两个连接：admin 只引导 schema/role；站点提交的 SQL 以 per-site migrator role 执行                             | 单测断言站点 DDL 绝不出现在 admin 连接；bootstrap SQL 过 DSQL linter          |
| `CREATE ROLE`/`AWS IAM GRANT` 裸 `except: pass` 吞真实错误      | 只容忍 duplicate（SQLSTATE 42710/42P06），其余抛出                                                      | 单测覆盖 42601 语法错/42501 权限不足必抛                                    |
| 回跳白名单可被 `https://evil.com\.{base_domain}/` 绕过             | 拒反斜杠 + 强制 https                                                                               | 8 组用例；Python urlparse 与 Node WHATWG 解析差异实测                     |


**仍需真机验证**：`AWS IAM GRANT` 对真实 DSQL 的语法与幂等 sqlstate（③ 冒烟覆盖）；
migrator role 的 `ALTER DEFAULT PRIVILEGES FOR ROLE` 是否被接受（失败无损，末尾有显式 GRANT 兜底）。

## 待部署时验证的 Minor（来自各任务审查，记录在 .superpowers/sdd/progress.md）

- `_add_s3_sigv4_auth` 用 `quote(uri)` 签名但转发原样 URI：非 ASCII 文件名（中文/空格）可能 SignatureDoesNotMatch。PoC 生成的资产路径均 ASCII，不受影响；若客户站点用非 ASCII 静态文件名需修。
- `_site_policy` 与 Edge S3 签名 region 硬编码 us-east-1（与部署区一致，换区需改）。
- `provision_dsql` 的 `migrations/*.sql` 不经红线扫描（只扫 schema.sql）；migration 里的禁用 DDL 会在 provision-db 阶段才失败（可读报错，非静默）。
- 跑测试的 venv：`site-builder/auth` 无自己的 venv，用 `site-builder/contract/.venv/bin/pytest tests`（含 pyjwt）；`site-builder/deployer` 必须 `pytest tests`（裸 `pytest -q` 会误收集 `infra/cdk.out` 里的 asset 副本）。


---

## 从一期环境升级（本仓库自己的环境走过这条路）

**全新部署不需要读这一节**——上面 ①-⑦ 已经是最新版本。这里只记"已经跑着
一期、要原地升到二期"时额外需要的动作与顺序。本仓库的环境在 2026-08-05
按这个顺序做过一遍，下面的坑都是实测的。

### 为什么必须换一个 Cognito pool

一期复用了上游 Quick SSO 的 pool。**pre-token 触发器是 pool 级的且不按
client_id 区分**——它对该 pool 里所有 app client 的 token 一律注入 claim。
于是平台升级触发器等于改上游 Quick Desktop/Web 在用的 token 形态，反之亦然，
而这个耦合没有任何测试能覆盖。另外共享 pool 里的 client 可能开着原生认证
flow（实测那个 mcp client 开着 `ALLOW_USER_SRP_AUTH`），org 边界不成立。

### 顺序（每一步的前后依赖都踩过）

1. **先部 ④ 执行器**：它建 `site-admins` 表与 sites 表的 `owner-index` GSI。
   GSI 是在线添加、不替换表，等 `IndexStatus` 变 `ACTIVE` 再继续（实测约 60 秒）。
   注意 `ItemCount` 会有统计延迟显示 0，用一次真实 Query 确认回填才可靠。

2. **建专用 pool**（`deploy_pool.py`，见上面第 1 项），回填 `[Cognito]` 四项。

   想先验证登录体验再切，可以用 `--pool-name <临时名>` 建隔离 pool 预演——
   它会自动隔离 SSM 前缀与 pre-token 函数名。**这两处隔离缺一不可**：函数名
   若不隔离，spike 会 `update_function_code` 到生产在用的那个函数上，静默改掉
   线上 token 形态而 Cognito 侧毫无异常显示。

3. **部 auth 服务**（`deploy_auth.py`），它会把 Lambda 指到新 pool。

4. **迁移存量站点权限**（一期站点在 sites 表没有权限字段，不迁移则
   `role_of` 判不出 owner）：

   ```bash
   python3 site-builder/scripts/migrate_permissions.py           # dry-run，先看报告
   python3 site-builder/scripts/migrate_permissions.py --apply
   ```

   dry-run 是唯一的人工审查关口——逐条打印「将写什么值 / 保留哪些在线值」。
   报告里出现 `问题:` 的站点一律跳过未写，需人工判断原意后手工修，
   **脚本绝不会自动把无法解析的名单降级成 `org`**（那是扩权）。

   迁移范围是**路由表里在线的站点**，不是 sites 表全量——sites 表里还有已下线
   记录与 fixture。`owner=platform` 的 auth 路由会被正确跳过。

5. **admin 种子**（见上面第 3 项）。

6. **部 ⑤ MCP**：镜像会因代码变化重新构建。若 ECR 仓库是一期用 MUTABLE 建的，
   脚本会顺手纠正为 IMMUTABLE（实测本环境正是这种情况——此前镜像链一直没有
   防覆盖保护）。

7. **部 Edge，但 `require_idp_claim` 先留 `false`**。这是与全新部署唯一的实质
   差异：**存量会话没有 `idp` claim，提前翻 `true` 会把所有已登录用户 302 到
   登录页**（包括你自己）。

8. **自己走一遍登录**，拿到新 pool 签发的会话。

9. **翻 `require_idp_claim = true`，再部一次 Edge**（`rm -rf cdk.out` 必须，
   否则用陈旧 asset）。翻之前可以先验证它会怎么判——把部署出去的那份代码下载
   下来、改开关在本地跑它的判定逻辑，比翻完再补救便宜得多：

   ```bash
   # 判定点在 index.py 的请求处理里（搜 REQUIRE_IDP_CLAIM），
   # 不在 _verify_session_jwt（那个只管验签）——测错层会得到"全部放行"的假象
   ```

   本环境实测结果：新会话（`idp=Feishu` + `auth_via=TokenGeneration_HostedAuth`）
   与 refresh 续期出的会话放行；一期旧会话、伪造 idp、原生认证来源全部 302。

### 升级期的其它实测坑

- **一期 pool 里联邦用户的 `email_verified` 是 `false`**（一期没配这个映射），
  而 `require_email_verified` 默认 `true` 会拒绝它——**所以顺序必须是先切 pool
  再开这个开关**，反过来是全员登录失败。新 pool 由 `deploy_pool.py` 配好映射，
  实测切完即为 `true`。
- **同一个人在两个 pool 里是两个独立 Cognito 用户**（`identities.dateCreated`
  各自新建），所以切 pool 必然要求全员重新登录一次，顺带把飞书那次授权同意
  点掉（同意页只弹第一次）。
- **旧 pool 与旧 client 不要立刻删**：迁移期两个 pool 的 pre-token 调用授权并存
  （`add_permission` 的 StatementId 带 pool 标识），保留旧的即可随时回滚。
- **一期建的站点可能存着 URL 编码的用户名**：Edge 对 `x-user-name` 做 URL 编码
  是必须的（HTTP 头不能放非 ASCII），站点须 `decodeURIComponent`。一期的合同
  示例漏了这句，那时建的站点会把 `%E5%BD%AD...` 存进数据里。改站点代码后重新
  部署即可，历史脏数据需单独清洗。
