# Quick 自动化建站方案 — 部署 Runbook

本文档是把本方案部署到**你自己的 AWS 账号**的操作手册，覆盖的是**需要真实 AWS
资源、DNS、IdP 凭证**的部署门禁——这些无法自动化，也是单元测试覆盖不到的部分。

**部署的是当前最新版本**：照 ①→⑦ 走一遍即可，无需先部旧版本再升级。
已在运行旧版本的环境见[从一期环境升级](#从一期环境升级本仓库自己的环境走过这条路)。

- **区域**：`us-east-1`（Lambda@Edge、ACM、Quick Desktop 身份区域共同强制）
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
us-east-1，Quick Desktop 身份区域当前也要求 us-east-1。这不是偏好而是硬约束——
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

> 与"用什么登录 Quick"解耦：Quick Desktop/Web 的登录方式（飞书/Okta/IdC）
> 和本平台的 IdP 是两个独立的认证上下文，互不影响。用户即使用 Okta 登录 Quick，
> 添加部署 MCP 时走的仍是本平台 Cognito 的 OAuth。两者可同源可不同源；
> 建议同源，避免 allowed_users 名单里的邮箱与用户实际登录身份的邮箱错配。

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

站点登录、部署 MCP OAuth、Quick Desktop 三条通道共用这一条注册。

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

**这份 Runbook 部署的是当前最新版本（含二期 M1+M2）。全新账号照 ①→⑦ 走一遍
即可，不需要"先部一期再升级"。** 已经跑着一期的环境要升级，见文末
[从一期环境升级](#从一期环境升级本仓库自己的环境走过这条路)。

组件间有依赖，必须按序：

```
①身份层        →  ②路由层  →  ③DSQL  →  ④执行器  →  ⑤部署MCP  →  ⑥客户端接入  →  ⑦端到端彩排
   deploy_pool.py   CloudFront    cluster    SFN+Lambda   AgentCore     Skill+MCP      RUN_E2E
   + deploy_auth    (Task 8)      (Task 13)  (Task 17)    (Task 20)     (Task 22)      (Task 23)
   (Task 3)
```

依赖关系：②需要①产出的 JWT_SECRET（已在 SSM）与 edge role；④需要①的 boundary、②的 edge_role_arn、③的 DSQL endpoint；⑤需要④的 state_machine_arn 与①的 Cognito。

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
   auth 服务已按 `{"event":"token_exchange_invalid_grant",...}` 打结构化日志，
   部署后建一个 metric filter + 阈值告警：

   ```bash
   aws logs put-metric-filter --region us-east-1 \
     --log-group-name /aws/lambda/site-auth-service \
     --filter-name auth-invalid-grant \
     --filter-pattern '{ $.event = "token_exchange_invalid_grant" }' \
     --metric-transformations \
       metricName=AuthInvalidGrant,metricNamespace=SiteBuilder,metricValue=1
   ```

   然后建告警（**阈值必须按你的真实流量定**，见下）：

   ```bash
   aws cloudwatch put-metric-alarm --region us-east-1 \
     --alarm-name site-builder-auth-invalid-grant \
     --alarm-description '【中文】Site Builder 登录授权码交换持续失败。触发条件：连续 2 个 5 分钟周期，每个周期 AuthInvalidGrant >= 1。可能影响：用户可能无法登录。常见原因：授权码过期/重放、Cognito App Client 属性读取权限或 OAuth client/grant/redirect URI 配置错误。ALARM=告警触发；OK=告警解除（仅表示指标不再满足阈值，告警规则仍启用，不代表根因已确认修复；缺失数据按 notBreaching 处理）。【English】Site Builder OAuth authorization-code exchanges are failing continuously. Threshold: AuthInvalidGrant >= 1 in each of 2 consecutive 5-minute periods. ALARM=condition breached; OK=alarm condition cleared. The alarm remains enabled, and OK does not confirm root-cause resolution because missing data is treated as notBreaching.' \
     --namespace SiteBuilder --metric-name AuthInvalidGrant \
     --statistic Sum --period 300 --evaluation-periods 2 \
     --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
     --treat-missing-data notBreaching \
     --alarm-actions <SNS topic ARN> \
     --ok-actions <SNS topic ARN>
   ```

   **建完用脚本验收**（"日志打了/metric 有点了"不等于"alarm 会响"）：

   ```bash
   SNS_TOPIC_ARN=<topic ARN> ./site-builder/scripts/verify_auth_alarm.sh
   ```

   它检查正式配置存在、触发一次真实 `invalid_grant`、**确认日志里出现
   `token_exchange_invalid_grant`**（不然测到的是 cookie 缺失分支的 400，
   不是目标逻辑）、建临时 1/1 阈值探针 alarm 验证真的进 ALARM，然后自动清理
   （trap 保证异常路径也清）。最后一步仍需人工：去 SNS 订阅端确认收到通知——
   **topic 没有订阅或订阅未确认时 alarm 照样进 ALARM 而无人知情**。

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

1. **【飞书】** 克隆并按其 README 部署上游方案（提供 OIDC 适配器 + Quick Desktop
   代理；平台把这个适配器当成一个普通 OIDC IdP 来联邦）：
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
   漏了整个权限模型不成立。若还需要 Quick Desktop
   走同一个 pool 登录，另需 offline_access 剥离代理，参考
   [aws-samples Quick Desktop Cognito 方案](https://aws-samples.github.io/sample-amazon-quick-suite-knowledge-hub/amazon-quick-on-desktop/)。

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

7. **验证点（人工门禁）**：在 Quick Web/Desktop 配置该 IdP，用上游身份
   （飞书账号 / Okta 账号等）登录成功。Desktop 身份区域须 us-east-1。
   （此步只关乎 Quick 登录通道；若组织的 Quick 用别的方式登录、只用本平台
   建站功能，可跳过。）

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
   public-access-block 与生命周期规则：
  ```bash
   # us-east-1 不要带 --create-bucket-configuration LocationConstraint
   aws s3api create-bucket --bucket site-frontend-{account_id} --region us-east-1
   aws s3api put-public-access-block --bucket site-frontend-{account_id} \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   # 旧版本前端清理：upload_frontend 只写新前缀不删旧的（发布期间线上仍用旧前缀），
   # mark_job 成功后清理当前站点旧版本；这条规则是兜底，防残留无限累积。
   aws s3api put-bucket-lifecycle-configuration --bucket site-frontend-{account_id} \
     --lifecycle-configuration '{"Rules":[{"ID":"expire-old-site-versions","Status":"Enabled","Filter":{"Prefix":"sites/"},"Expiration":{"Days":30}}]}'
  ```
   桶必须保持私有：Edge 函数用 SigV4 签名读它（见 `_add_s3_sigv4_auth`），
   不依赖公开访问。
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
# 部署（bundling 会用 Docker 拉 x86_64 镜像装 psycopg[binary]+sqlparse+contract 包）
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
确认列出 8 工具、无 token 返回 401、`list_my_sites` 的 owner == 登录用户飞书邮箱。
八个工具 = 部署五件套（`deploy_site` / `confirm_upload` / `get_deploy_status` /
`list_my_sites` / `undeploy_site`）+ 权限三件套（`update_site_permissions` /
`manage_collaborators` / `get_site_permissions`）。工具面由
`mcp/tests/test_agentcore_contract.py` 的 `EXPECTED_TOOLS` 锁定。

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

配好后在会话里 `/mcp` → site-builder-deploy → Authenticate 走飞书 OAuth。
新会话提示："用 site-builder 技能给我做一个团队读书清单站点，能加书标记读完，全组织可看，做完部署" → 应走完 Skill 工作流 → MCP 部署 → 返回 URL → 浏览器飞书登录 + 加书验证。
（已实测走通：真实站点部署成功，validate→smoke-test 一次过。）

**Quick Desktop（人工，核心演示通道）**：导入 site-builder Skill + Capabilities→MCP 添加 endpoint（OAuth 走飞书登录）。

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

`router/config.ini` 的 `[SiteBuilder]` 还需 `require_idp_claim` /
`trusted_idps`（见 ②）。

一次性动作（**不做则安全边界不成立，且测试覆盖不到**）：

- [ ] admin 种子已注入（`seed_admin.py --apply`，在 ④ 之后）
- [ ] `require_idp_claim = true` 且部署出去的 Edge 代码已核对（零占位符）
- [ ] 登录失败告警已建（metric filter + alarm，阈值按真实流量定）
- [ ] 自己走过一次真实登录，claim 值与 ① 的实测基线一致

SSM 参数：`/site-builder/jwt-secret`（§0 手工建）、`/site-builder/site-client-secret`（① 的 `deploy_pool.py` 写入）。

## 已知限制与延后项（向客户声明）

- Quick Desktop 为 preview、身份区域须 us-east-1
- 顶域 cookie 使所有 `app-*.{base_domain}` 站点共享一次登录（PoC 可接受，产品化需按站点隔离会话）
- PoC 仅 Node.js 后端（Python 3.13 延后）；MCP 仅 OAuth（API Key fallback 延后）
- CloudFront 全站禁缓存（正确性优先；精细缓存延后）
- 详见设计文档 §8 风险 / §9 范围外

### 状态机级超时/中止不落账（job 会停在 RUNNING）

各步骤都挂了 `add_catch(States.ALL) → MarkFailed`，所以**步骤内**的失败都会把
job 写成 FAILED（真机核对过：历史 3 个 FAILED 执行的 job 都是
`status=FAILED, phase=provision-db`，没有卡住的）。

但有两类终止**不执行任何 State**，因此 `mark_job` 根本不会被调用：

- 状态机级 `TimeoutSeconds=1800`（30 分钟）到点 → 执行 `TIMED_OUT`；
- 人工 `StopExecution` → 执行 `ABORTED`。

这两类之后 job 会**永久停在 `RUNNING`**：用户既拿不到结果，也无法重试
（`confirm_upload` 的条件迁移要求 `PENDING`，会返回"已启动过"）。目前只能人工
把该 job 改成 FAILED，或让用户重新发起一次部署（会拿到新 job_id）。

要闭合需要一条 EventBridge 规则订阅 Step Functions 执行状态变更、对
`TIMED_OUT`/`ABORTED` 把对应 job 落成 FAILED —— **未实现**。
现状与该缺口由 `site-builder/scripts/verify_sfn_failure_paths.py` 持续核对
（它会把历史上出现过的 TIMED_OUT/ABORTED 报成 FAIL，所以真的发生过就不会被漏掉）。

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
| `npm install` 执行站点 preinstall 脚本（CodeBuild 内任意代码执行）       | `--ignore-scripts` + 删 `.npmrc` + 红线拦生命周期脚本 + CodeBuild 角色收窄到 `uploads/*` 只读、`artifacts/*` 只写 | 红线单测 + synth 确认无整桶读写                                           |
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
