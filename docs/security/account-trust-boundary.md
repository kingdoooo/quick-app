# 账号信任边界：平台能防谁，不能防谁

> **状态：已知未修（不是已接受）。** 最近一次实测 2026-08-25，方法与原始数据见下。
> 这份文档是 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 里
> **M09 第 1 步**的产物，并且**扩大了 M09 的结论**——见「M09 的框架不够大」一节。

## 一句话

**这个平台的安全边界是 AWS 账号本身。** 账号内任何具备「读 Lambda 产物」、
「读 CDK bootstrap S3 桶」或「读 SSM 参数」这类**只读级**权限的 principal，
都可以取得会话签名密钥，从而以任意用户身份访问任意站点与控制台（读与写都算）。
应用层的任何一道检查都挡不住这件事，因为它们全都以那把密钥为根。

> **这份文档的数字被推翻过四次，每次都是同一个建模错误**：把一种「能力」写成
> **单个 API 动作 / 单个资源**。① 漏了 CDK bootstrap asset 这条路（41→62）；
> ② 漏了 `ssm:GetParameters`（复数，62→63）；③ IAM 策略变更只对着字面量
> `role/*` 模拟，漏了 6 个精确/窄授权的 principal（63→66）。
> **读这份文档时把数字当下界看，不要当上界。** 产生它们的闸门现在按
> 「动作等价类 × 资源等价类」建模，但仍不是穷尽的（见最后一节「这道闸门不证明什么」）。

对**不具备**账号级权限的一切东西——站点代码、per-site IAM 角色、公网访问者——
「身份只能来自 Edge」这条不变量是成立的，而那正是这套设计要防的威胁。

## 这份文档回答什么

- 平台对哪类攻击者提供保证，对哪类不提供（下面两节）；
- 为什么不能靠 SCP / Lambda resource policy / 应用层对称签名 / 收窄 invoke 来修；
- 账号内**能**做到什么（非对称签名那条路，以及它的代价）；
- 在真修复之前，用什么纪律保证暴露面**别再变大**。

它**不**回答「怎么把账号里那 38 个无关工作负载清理干净」——那是账号治理，
不是本仓库能提交的改动。

## 实测（2026-08-25，全部只读）

方法：`iam:GetAccountAuthorizationDetails` 枚举账号内**全部**非 service-linked
角色与 IAM 用户，逐个 `iam:SimulatePrincipalPolicy`（模拟器会算 permissions
boundary；本账号是 Organizations 管理账号，SCP 对它无效）。
400 个 principal 全部**收到**模拟结果、无一因限流丢失——丢一个与「它没有权限」在
输出上一模一样，所以脚本对模拟失败是硬失败。

复跑（这就是最新结果的取得方式，本文不承诺数字长期有效）：

```bash
python3 site-builder/scripts/verify_account_trust_boundary.py
```

闸门分**两层**，承诺宽度不同，所以数字也分两组（见「这道闸门不证明什么」）：

| 组 | 项 | 数 |
|---|---|---|
| **A 直接失守** | 具备非 IAM-write 敏感授权的 principal | 62 <!-- baseline:A总数=62 --> |
| | 其中**能取得会话签名密钥**的 | 57 <!-- baseline:可读密钥=57 --> |
| | 其中**非平台**身份可直接 `lambda:InvokeFunction` 平台或站点函数的 | 18 <!-- baseline:非平台可直调=18 --> |
| | Edge 函数里仍带着当前有效密钥的**代码目标**（未限定 + 已发布版本） | 10 <!-- baseline:带活密钥的Edge代码目标=10 --> |
| | CDK bootstrap 桶里仍带着**当前有效**密钥的 asset 对象 | 9 <!-- baseline:带活密钥的asset=9 --> |
| **B IAM 写观察** | 持有相关 IAM 策略变更语句的 principal | 22 <!-- baseline:B持有IAM写语句=22 --> |
| | 其中**不在 A 里**（只有 IAM 写、**未证明可提权**） | 4 <!-- baseline:仅IAM写=4 --> |

> **A + B 的并集是 66，但那个数不是 headline。** A 是"现在就能拿到密钥或直接调用平台
> 函数"；B 只是"持有一条可能影响 IAM 策略的语句"，本闸门**明确不证明**它构成提权链
> （判那个需要一个 IAM 权限分析器——那正是这道闸门被复审五轮的根因）。
> 把两者相加当成一个风险数字，是这一轮收缩要消掉的那个错误。
>
> **B 里那 4 个不在 A 里的 principal 没有类别分布可写**：schema 3 的 `principals`
> 只保留 A 的 62 个，那 4 个的 `category` 不在基线里 ⇒ 任何按类别的拆分都没有真源，
> 只能靠人记，下次 B 的成员变了就会静默腐烂。要看它们是谁，跑
> `--dump-observed` 看带真实名字的快照（产物含账号内标识，勿提交）。

**A 组**按类别（**不写角色原名**：其中若干名字内嵌账号 ID，另有一批是企业内部托管
角色，写进被跟踪文件既违反仓库红线也没有必要）：

| 类别 | 数 | 说明 |
|---|---|---|
| `platform` | 6 <!-- baseline:类别_platform=6 --> | 平台自己的角色，授权都是**必需且精确**的，见下节 |
| `platform-overbroad` | 1 <!-- baseline:类别_platform_overbroad=1 --> | 平台自己的角色，但这条授权它**不需要**：见「平台侧唯一的过宽授权」 |
| `admin` | 3 <!-- baseline:类别_admin=3 --> | 账号管理身份（含账号 owner 的 IAM 用户）。属既定信任模型 |
| `break-glass` | 6 <!-- baseline:类别_break_glass=6 --> | 企业内部托管的管理/审计角色。不由本项目控制 |
| `cdk-admin` | 6 <!-- baseline:类别_cdk_admin=6 --> | CDK bootstrap 的 CloudFormation 执行角色与部署角色（各 3 个区），按约定是 `AdministratorAccess`。**任何能在本账号跑 `cdk deploy` 的人都能用** |
| `cdk-readonly` | 4 <!-- baseline:类别_cdk_readonly=4 --> | CDK bootstrap 的 lookup 与 file-publishing 角色。它们**足以拿到密钥** |
| `unrelated-workload` | 36 <!-- baseline:类别_unrelated=36 --> | 与本平台无关的工作负载：EC2/ECS/EMR/EKS 实例角色、多个 SageMaker 与 Personalize 执行角色、Glue、Batch、SSM 自动化与 QuickSetup、另一套 GenAI Agent 栈、若干应用与 CDK BucketDeployment 角色 |

合计 62 = A 组总数。**这一轮把这张表的裸数字也加上了校验标记**：`unrelated-workload`
那个曾经写着 38，而 A 收缩后是 36——裸数字正是文档腐烂的入口。

⇒ 这不是「只有我一个人有权限」的个人账号，而是一个**多工作负载共享账号**。
任何一个上述工作负载被拿下（含任何能在本账号里跑 notebook / EC2 / `cdk deploy`
的人），都可以冒充任意用户。

## 密钥有三条路能拿到，三条都实测可用

会话 JWT 与控制台会话（`__Host-sb_console`）用**同一把** HS256 密钥，
真源是 SSM SecureString `/site-builder/jwt-secret`。

**路 ①：`lambda:GetFunction` 下载 Edge 产物，密钥是明文。**（**10 个目标**：
未限定函数 + 9 个已发布版本，每一个都实测过仍含当前有效密钥——密钥没轮转过，
所以历史版本的代码里是同一把。`function:foo` 与 `function:foo:9` 在 IAM 里是两个
资源，只探未限定 ARN 会漏掉「只能读某个旧版本」的 principal。）
Lambda@Edge 不支持环境变量，所以密钥由 CDK 在部署时**字符串替换**进 Edge 函数源码
（`router/infrastructure/stack.py` 的 `{{JWT_SECRET}}`）。实测：下载 origin-request
函数的部署包，`index.py` 里有且仅有一处 `JWT_SECRET = "<64 字符>"`，其值与 SSM
参数**逐字节相同**（比对 SHA-256，未落盘明文）。这条路**不经 KMS、也不需要
`lambda:InvokeFunction`**，而 AWS 托管策略 `ReadOnlyAccess` 就带 `lambda:GetFunction`
（模拟器给出的 `MatchedStatements` 直接指向 `ReadOnlyAccess`）。

**路 ②：`s3:GetObject` 读 CDK bootstrap 桶里的同一份产物。**
`stack.py` 把替换过密钥的目录交给 `lambda.Code.from_asset()`，于是它同时是一个
**CDK file asset**，被上传到 `cdk-hnb659fds-assets-*` 桶。实测：从**已部署的
CloudFormation 模板**取到当前 Edge 函数的 `S3Bucket`/`S3Key`，下载该对象，
里面的密钥与 SSM 值逐字节相同。三条边界都核过：

- 桶策略只有一条 `AllowSSLRequestsOnly`（Deny 非 TLS），**没有**任何限制读取的语句；
- 对象用 `alias/aws/s3` 加密，该 AWS 托管键的 key policy 是
  `Principal: {"AWS": "*"}` + `kms:CallerAccount` + `kms:ViaService=s3.*` 的
  **直接授权** ⇒ identity policy 里不需要任何 `kms:*` 动作；
- **旧对象不会被删**：每次 Edge 部署留一个新 asset。密钥从未轮转过，所以扫描
  bootstrap 桶发现 **9 个**对象仍带着当前有效的密钥（最早的是 2026-07-28）。
  ⇒ 只把当前那一个对象删掉不解决问题，而轮转密钥必须连带清理这 9 个。

**路 ③：读那个 SecureString——而"读"不止一个动作。**
看起来还有 KMS 一道，实际没有：参数用的是 AWS 托管密钥 `alias/aws/ssm`，其 key
policy 与上面 `aws/s3` 那条形态完全相同（`Principal:*` + `ViaService=ssm.*` 的
直接授权，已读该 key policy 核实）。这类 `parameter/*` 读权限广泛存在于
EC2/ECS/EMR/EKS 实例角色与 SSM 自动化角色的托管策略里。

**四个动作都能读出同一个明文**，逐个实测（allowed 的 principal 数）：

| 动作 | 可读 |
|---|---|
| `ssm:GetParameter` | 27 |
| `ssm:GetParameters`（复数，支持 `WithDecryption`） | 26 |
| `ssm:GetParametersByPath` | 18 |
| `ssm:GetParameterHistory`（AWS 明确警告：拒绝 `GetParameter` 时它仍可能读到当前值） | 18 |
| **四者并集** | **28** |

其中有一个角色**只**被授予 `ssm:GetParameters`、没有单数那个：它的策略是
`Resource:*` 上的显式 Allow、没有 permissions boundary，所以 `WithDecryption=true`
就能读出当前密钥。首版闸门只探单数动作，把它整个漏掉了——这是本文档数字被推翻的
第二次。

## 拿到密钥意味着什么：读面和写面一起失守

- 可以为**任意 email** 签出站点会话 cookie ⇒ 以任意用户身份访问任意站点，
  Edge 那侧的验签会通过，因为签名是真的；
- 可以签出 `scope=console` 的 `__Host-sb_console` ⇒ **控制台写接口也失守**
  （`site-builder/panel/console_session.py` 从 `JWT_SECRET_PARAM` 读的就是同一个
  参数，写面唯一承重的就是这道 HMAC 验签）；
- `Origin` 逐字符匹配与 `Content-Type` 检查在这条路上**不提供任何保护**：
  direct invoke 的合成 event 里这两个头由攻击者填；走真实 HTTP 时它们也不是身份。

## 平台自己这一侧：6 个精确，1 个过宽

6 个 `platform` 角色的 invoke 权限都**精确到单个函数**，实测逐一确认：

| 角色 | 能 invoke 什么 | 为什么必须有 |
|---|---|---|
| Edge 执行角色 | 平台函数 + 站点函数 | 唯一合法的调用方；砍掉 = 全站 403 |
| deployer exec 角色 | **只有**站点函数（含 `blue` alias） | blue/green 健康门带 `Qualifier` 真的直调候选颜色；砍掉 = 每次部署在健康门失败 |
| Step Functions 角色 | 只有各步骤 Lambda | 编排 |
| panel 角色 | **只有** `site-deployer-undeploy` | 控制台触发下线 |
| MCP runtime 角色 | **只有** `site-deployer-undeploy` | MCP 的下线工具 |
| auth 服务角色 | 不能 invoke；只读 jwt 参数 | 签会话 |

deployer exec 角色另有 `role/site-rt-*` 上的 `PutRolePolicy` / `AttachRolePolicy`
——那是 per-site 运行时角色拿到自己那份精确表 ARN 策略的唯一途径，属设计内。
它同时意味着**部署器有能力放宽任意 per-site 角色**，所以 `platform` 类的授权按
集合等值盯死（多一条少一条都红）。**这条授权现在由层 B 的静态语句快照盯着**，
不再是 A 的一条 grant——A 只回答"现在就能拿密钥/直接调用平台函数"。

**一个顺带的观察**（不是缺陷，但读代码的人常会误判）：blue/green 切换之后
**旧颜色的 alias、Function URL 与两条 Edge 授权语句都保留**，没有任何代码删它们。
所以"上一个版本的代码"仍然可经它自己的 Function URL 被 Edge 角色调用。
这不扩大身份边界（仍只有 Edge 能调），但"我以为已经换掉的代码"其实还在。

### 平台侧唯一的过宽授权（`platform-overbroad`）

跑**不可信站点依赖安装**的 CodeBuild 角色（`site-package` 项目）拿到了
`s3:GetObject*`/`GetBucket*`/`List*` on **整个** `cdk-hnb659fds-assets-*` 桶。
这不是本仓库写的策略——它是 CDK 给 `BuildSpec.from_asset()` 自动加的
（buildspec 本身也是一个 asset）。后果：**那个构建容器能读到 Edge asset 里的
明文签名密钥**。

它今天**不可达**，隔断只有一条：`buildspec-package.yml` 里
`npm install --ignore-scripts`（外加先删掉站点自带的 `.npmrc`）。
站点的 `package.json` 由 AI 生成、owner 可任意改，所以一旦那条 flag 被去掉、
或出现任何其它在构建期执行站点代码的路径（例如将来支持 Python 后端而用
`pip install` 装 sdist），这条链就从「账号内部暴露」变成
**「不可信站点作者可窃取平台签名密钥」**——而后者正是整套设计声称要防的威胁。

⇒ 这条不需要等账号迁移，可以单独收窄（把 buildspec 改成不走 asset，
或给该角色加显式 Deny 到 Edge asset 前缀）。**它也是"别把可签名的对称密钥
物化进部署资产"这条结论最直接的证据。**

### 两个 Edge 函数也在监控范围里（补的是另一个盲区）

`origin-request` 与 `origin-response` 属于 **router 栈**，不在 deployer 栈的
`PLATFORM_FUNCTION_NAMES` 清单里，所以首版闸门**完全没看它们**——于是
「谁能读某个旧版本的 Edge 代码（里面就是明文密钥）」与「谁能
`lambda:UpdateFunctionCode` 直接换掉 Edge」两条都在视野外。现在两者都纳入了，
连同 Edge 的 9 个已发布版本，以及 version 9 上那条版本级 resource policy
（`replicator.lambda.GetFunction`，Lambda@Edge 的复制服务加的，属正常）。

## 为什么这几种修法都不成立

| 手段 | 为什么不成立 |
|---|---|
| **贴 SCP** | SCP 对 Organizations **管理账号无效**（含 root），而本部署就在管理账号。`site-builder/policies/README.md` 边界①已写明；那份模板是纵深防御制品，不是修复 |
| **Lambda resource policy 加 Deny** | Lambda 只有 `AddPermission`/`RemovePermission`，**只能写 Allow**；且同账号下 identity policy 单独即可授权 invoke，不需要命中 resource policy |
| **应用层给 Edge 请求加对称签名** | 签名的根就是那把密钥，而 57 个 principal 能读到它。对站点 Lambda 另外还不可行：验签要求站点持有密钥，而站点代码是不可信的 AI 生成代码 |
| **只收窄 `lambda:InvokeFunction`** | **假修复。** 同一批身份还握着密钥读取、`lambda:UpdateFunctionCode`（可整体替换 panel 代码）与 IAM 策略变更动作。收掉 invoke 之后边界一寸也没移动，但会读起来像修好了 |
| **收窄那 38 个无关工作负载** | 能缩小 blast radius，但**关不掉**：`cdk-admin` 与 `admin`/`break-glass` 必须保留管理权限，而它们本身就足够。且那是账号治理，不是本仓库的改动 |

## 两条真修复，各自能关掉什么

原先这里写的是「唯一真修复是迁独立账号」。**那句话太绝对**（Codex 复审 P2 指出，
已接受）：迁账号是唯一能把**管理员/CDK/break-glass** 也移出信任边界的办法，
但「只读级工作负载能窃取密钥」这条路，在**现账号内**也有技术方案。

**A. 迁到独立的 Organizations 成员账号。** 关掉的是账号级管理信任：

- SCP 才真正生效（`site-builder/policies/scp-site-invoke-only-edge.json` 从
  「纸面制品」变成可执行控制）；
- 暴露面从「62 个具备敏感授权的 principal」一次性收敛到「平台自己的 6 个 + 该账号的
  管理身份」，且不再随别人的工作负载漂移；
- 迁移后本文档的数字表与漂移闸门的基线应当**重置**，而不是继续沿用。

代价：跨账号部署、bootstrap、DNS/证书、Cognito 归属、数据迁移都要重新推。
独立设计包，未排期。

**B. 把会话签名从对称改成非对称。** 关掉的是「读到什么就能签什么」：

- 私钥用 KMS **非对称**密钥，不可导出；签名侧（auth / panel）调 `kms:Sign`；
- Edge 与验证侧只需要**公钥**——公钥进产物、进 asset、进 SSM 都无所谓，
  上面三条读取路径就全部失效；
- 顺带把站点会话与 console 会话拆成不同密钥/受众（今天它们共用一把，
  所以「读面失守」自动升级成「写面失守」）。

它**不**防账号管理员（管理员能直接调 `kms:Sign`），但本文档已把管理员定义为
既定信任模型，所以那不是这条方案的缺口。

代价，按本仓库的实际约束点清（不是小改）：Lambda@Edge 里没有 `cryptography`
这类库，验签要么自带一份纯 Python 的实现，要么改变验证位置；
`kms:Sign` 给登录路径加一次网络往返；密钥轮转、以及
`site-builder/DEPLOY.md`「轮转 `jwt-secret`」那一节记的"当前实现不支持安全轮转"
都要一起重做。**它是独立设计包，本轮没有做。**

**顺序建议**：B 关掉的是当前 57 个 principal 里绝大多数（只读级那批），
且不依赖账号迁移；A 关掉的是剩下的管理身份。先 B 后 A，或者只做 B 也能把
风险从「账号内任何只读身份」压到「账号管理员」。

**一个可量化的中间步骤**：只把 CDK asset 那条路修掉（不物化密钥进 asset，
或清理带活密钥的对象），实测会让 **21** 个 principal 整个退出暴露面
（**A 组 62 → 41**），可读密钥从 57 降到 36。这是用闸门的变形测试算出来的，不是估计。

## 在那之前的运行纪律

暴露面既然关不掉，唯一还能自动化的就是**别让它继续长**：

```bash
python3 site-builder/scripts/verify_account_trust_boundary.py
```

它的形状是**一种能力 = 一个动作等价类 × 一个资源等价类**。这句话是这道闸门最
重要的不变量，因为把它压成"单个动作 / 单个资源"这个错误已经犯过三次，每次都留下
一个当时看不出来的 false-green：

| 压成了什么 | 漏掉了谁 |
|---|---|
| 只探未限定函数 ARN | 挂在 `blue` alias 上的授权（M7 之后站点的 Function URL 全在 alias 上） |
| 只探当前那一个 CDK asset | 带同一把活密钥的 9 个历史对象 |
| 只探 `ssm:GetParameter` | 一个**只**被授予 `ssm:GetParameters`（复数）的角色 |
| IAM 写只对着字面量 `role/*` 模拟 | 6 个精确/窄授权的 principal |

第四条值得单独说明，因为它错在**资源**那一侧：IAM 里请求资源是具体 ARN，
policy 里的 `role/ExactRole` 不会匹配字面量 `role/*` ⇒ 精确授权全部隐形；
而 `iam:CreatePolicyVersion` 的资源类型根本是 **policy** 不是 role，
对着 role ARN 问等于永远问不到。

它测四层：

1. **identity 授权**——授权记成 `invoke-platform:site-panel` 这样的 grant 串，
   **不是布尔标签**。压成布尔时「某角色原来只能调 undeploy、现在还能调 panel」
   这种资源扩权会静静地绿，而那正是 panel 读面失守的分界。限定符也是一维：
   `invoke-platform:foo` / `invoke-platform@alias:foo` / `invoke-platform@version:foo`
   是三条不同的 grant（IAM 里 `function:foo`、`function:foo:blue`、`function:foo:9`
   是三个资源）。站点全量用稳定聚合 `:all`；**子集带成员指纹** `:some(k):<fp>`
   ——只记数量时「失去 site-a、新增 site-b」前后都是 `some(1)`，受影响的租户换了
   一批而闸门不动。

   **限定符是"存在性类"，类内部的成员不区分**：blue 与 green 都算 `@alias`。
   对"能不能冒充任意用户"这个问题，经哪个颜色碰到代码是等价的；按颜色分开记会在
   每次 blue/green 切换时产生漂移，却不带来任何安全信号。**颜色级完整性不由这一层
   负责**——它由第 3 层的逐成员比对、部署期的 blue/green 健康门与
   `smoke_router.sh` 覆盖。

2. **IAM 策略变更（层 B）——纯静态文本快照，不做权限分析，不进模拟器。**
   收 role / user / **group** 的 inline + attached 托管 + **permissions boundary**，
   用**全 glob**（`fnmatch`）判语句是否与那九个 IAM 策略变更动作相关，
   **Allow 与 Deny 都收**，逐条归一化（丢 `Sid`、**当前**账号 ID → `<acct>`、
   递归排序键与数组）后只存指纹。**任何 added / removed / changed 都红，不判改善。**
   实测规模：22 个 principal / 43 条语句（21 条来自 AWS 托管策略、22 条 inline）。

   **为什么"消失"也红**：Allow 消失不等于收紧——语句可能被拆成两条更宽的、可能从
   inline 挪到另一份 policy，也可能是**解析器漏收了**；把"旧指纹消失"自动判成改善，
   正好会把解析器退化显示成好消息。而 **Deny 消失是实实在在的扩权**
   （`Allow iam:* on *` + `Deny PutRolePolicy on EdgeRole`，删掉 Deny 则 Allow 集合
   完全没变 ⇒ 只收 Allow 的设计全绿）。

   托管策略文档 / 版本解析不到时**硬失败**，不静默跳过：跳过整份 policy 的输出与
   「这份策略没有相关语句」一模一样。`managed_policy_versions` 只记**贡献了相关语句**
   的那几份（账号里实测 300 份托管策略，全记会让 AWS 每更新任意一份都红一次）。

   **原先那套两步（静态发现候选 → 模拟器对具体 ARN 确认 → 三值分类 `:any` /
   `:scoped` / `:condition-gated`）已删除。** 它要求闸门回答「谁能提权」，而那等于
   要造一个 IAM 权限分析器：statement 归因、Condition 语义、NotResource 集合代数、
   policy variable、`SourcePolicyType` 碰撞——每修一维下一维才暴露。
   **这是这道闸门被外部复审五轮的根因。** 所以 B 的承诺刻意收窄成一句：
   **「可能影响这些动作的语句集合没有变化」**，仅此而已；它**不**声称某条语句是否
   生效、是否构成提权链、变化方向是收紧还是放宽。
   （所以这 22 个里有一部分——例如只能给一个 SSM 实例角色附两个指定托管策略的那个
   ——并不构成实际提权，而闸门也不再假装能分辨。）
3. **Lambda resource policy（含每个 alias 与每个已发布版本）**——
   `SimulatePrincipalPolicy` **不**自动纳入 resource policy（AWS 契约：它只能为
   IAM user 选择性地带一份，对 role 根本不支持），而同账号 resource-based Allow
   单独即可授权，所以这条通道必须单独快照。
   平台函数按**集合等值**比：丢一条 Function URL 授权语句 = 控制台或站点入口断掉，
   和新增一样要红。站点函数的 alias **逐成员**比——每个颜色都必须有规范语句，
   并起来比的话「active 色丢了授权、inactive 色还留着」会全绿；已核 blue/green
   切换后旧颜色的 alias / Function URL / 两条语句都保留（代码里没有任何地方删它们），
   所以逐成员不会误报。版本级做**子集**检查（AWS 的 replicator 语句只出现在当前
   Edge 版本上，旧版本合法地没有它）。**legacy 形态只认基线里的点名豁免**
   （`site_legacy_exempt`，当前 6 个）——「存量迁移站点要兼容 legacy」不等于
   「新站点也可以再产生 legacy」，把 legacy 设成全局合法形态时一个全新站点带着
   未限定 policy 也会全绿。豁免名单只能缩小：某个站点迁成 alias-only 之后，
   闸门会把"可以去掉这条豁免"报成改善。
4. **密钥物化位置的事实**——三处副本每次都实测（比对 SHA-256），
   某处不再含活密钥时对应资源自动掉出集合、grant 随之消失并报成改善。
   **根治了它，闸门自己就知道。**（当前：Edge 代码目标 10 个、asset 对象 9 个。）

红绿规则分两套，**刻意不对称**：

- `platform` 类 principal 的授权是"精确且必需"的 ⇒ 按**集合等值**比，
  任一方向的差异都红。只比"新增"时，「Edge 丢掉 `invoke-platform:site-panel`
  但保留 key-proxy」会照样过前缀检查并退出 0。
- 其它类别（含 `platform-overbroad`）：新增红、缩小算改善。`platform-overbroad`
  **就是**要缩小的那一类，把它的缩小判成红会把我们想要的修复报成故障。
- 另有两条正向控制：Edge 角色必须保留平台与站点的 invoke，deployer exec 角色必须
  保留**alias 限定**的站点 invoke（健康门是带 `Qualifier` 的直调）。真机症状分别是
  全站 403 与每次部署在健康门失败，两者都不会在任何单测里出现。
- 事实类数字（`principals_with_missing_context` 等）只报 delta，**不参与红绿**：
  它们随账号里任何一条带 Condition 的新策略变动，让它们决定退出码就会频繁红在无关
  变更上，进而训练出"红了就更新基线"。

一次完整运行实测 **8.5–10.5 分钟**（四次实测 10:32 / 9:49 / 9:36 / 8:47；
最后那次是每线程独立 IAM client 之后的——共享 client 的连接池争用同时也拖慢了它）（400 个 principal × 2 次 IAM 模拟 + 一次
`GetAccountAuthorizationDetails` 静态收语句 + 扫 bootstrap 桶 + 逐版本校验 Edge 代码）。
去掉 IAM 写的逐个模拟确认之后省下的时间不多——主要成本一直是那 800 次模拟。

**`--dump-observed` 是纯观测模式**：它不读基线、不比较，退出码不代表闸门结论。
分开是刻意的——把「产出用于分类/迁移的快照」与「出闸门结论」混在一条命令里，
迁移期就会因为基线还是旧 schema 而根本产不出快照，而那份快照正是迁移的输入。

基线在 `site-builder/scripts/account_trust_baseline.json`，**只存指纹**
（`sha256[:16]`，每 4 位分组）与类别，不含任何账号值——账号内有若干角色名内嵌账号
ID，resource policy 的 `Principal` 也是带账号 ID 的角色 ARN，照抄就把账号值提交进
仓库。分组不是为了好看：裸 16 位十六进制里会偶然出现 12 位连续数字，
撞 `scan_staged_secrets.sh` 找账号 ID 的规则，而反复的假阳性会训练出无脑
`--allow-hits`。

更新基线（确认过新增项是可接受的之后）：

```bash
# ① 先拿到带真实名字的清单（产物含账号内标识，写 /tmp，勿提交）
python3 site-builder/scripts/verify_account_trust_boundary.py \
    --dump-observed /tmp/trust-observed.json
# ② 写一份 {角色名: category} 映射，再落基线（--from-dump 复用①的快照，不重跑模拟）
python3 site-builder/scripts/verify_account_trust_boundary.py \
    --from-dump /tmp/trust-observed.json --classify /tmp/trust-classify.json \
    --update-baseline
# ③ 同步本文档的 14 个带标记数字（deployer/tests/test_verify_account_trust_boundary.py 会校验）
```

`docs/security/` 下的这份文档、基线文件与闸门脚本三者互相咬着：
文档的 14 个带标记数字由基线算出并由单测断言（**正文里显示的数字必须紧挨着校验标记**，
否则标记与正文可以各写一个数），基线由闸门写入，闸门的纯函数由单测覆盖。
改任何一个都会把另外两个拽红。

### 这道闸门**不**证明什么

写在这里，因为把它当成「暴露面已穷尽」是最容易犯的错。
**按层分开说**——三层的承诺宽度不同，混着读就会把窄的当宽的。

**A（直接失守）**

- `SimulatePrincipalPolicy` 对带 Condition 的策略需要调用方补 `ContextEntries`，
  本脚本不补 ⇒ 那些判定是**下界**。逐项的不确定面记在 `coverage.undecided_items`
  里，成员 = `(principal, 动作等价类, **判不出的资源类集合**)`。三种写法都试过：
  按 principal 记（「原本只对站点函数判不出、后来对 jwt-secret 也判不出」前后同一个
  集合 ⇒ 漏）、逐资源各记一项（实测 **9985** 条，基线涨 10 倍，一个新 principal 一次
  冒出几十条红 ⇒ 噪音）、按动作类全局折叠成 `unattributed`（`{site-panel}` 与
  `{site-panel, undeploy}` 同一个成员 ⇒ 又漏）。**资源类集合整体进指纹**同时满足两边：
  上界 5 条/principal，而集合一变指纹就变。最近一次实测 **774** 项，覆盖 **162** 个
  principal（与 `principals_with_missing_context` 吻合）。
  笼统计数 `principals_with_missing_context`（同样是 162）只报 delta、不参与红绿：
  它随账号里任何一条带 Condition 的新策略变动。
  **它不是 fail-closed 的**：真要 fail-closed 就得把这些全判成有权限，
  那样闸门永远红、也就没有信号。
- **动作等价类不是穷尽的。** `IAM_WRITE_ACTIONS` 手工列了九个 IAM 动作，
  而 IAM 的提权面比这大；`A_READ_PARAM` 等同理。往任一类里加成员时，同时加一条
  只命中该新成员的用例——这个纪律是**四次** false-green 换来的。
- 它只看 IAM、Lambda resource policy、以及 **bootstrap 桶的 bucket policy**
  （模拟器不纳入 resource-based policy，对 role 更是不支持模拟它），
  不看 KMS grants、VPC endpoint policy、其它服务的 resource policy，
  **也不看 S3 access point**。
- 它不看跨账号 principal。但语句里出现**外部账号**的 principal 会改变指纹 ⇒ 会红
  （账号归一化只归**当前**账号，就是为了留住这个信号）。
- 它统计的是**当前**存在的 principal 与资源；某人临时建一个角色用完删掉，
  两次运行之间看不见。
- 它给出的是**下界**，不是上界。这份文档的数字被推翻过**四次**，每次都是因为
  漏掉了一个等价动作或一类等价资源。

**闸门自己的 fail-closed（这些都不会"打印一条警告然后退出 0"）**

- **未校验服务端证书的请求是致命错误**。实测过一次真实现场：共享一个 IAM client 给 4 个
  worker 并发用，800 次模拟里有十几次跳过了证书校验（顺序执行 0 次、每线程独立 client
  0 次）。闸门的答案能被主动 MITM 伪造的话，那次"绿"就不能当安全证据。
  现在每线程一个独立 client，且 `InsecureRequestWarning` 直接抛。
- **不完整的观测不会变成一个权威的绿**：`--no-asset-scan` 只能用于纯
  `--dump-observed`（它不扫历史 asset ⇒ 只能读那批对象的 principal 会消失，而比较器
  会把它报成「集合缩小（绿）」）；产出的快照带 `asset_scan_complete: false`，
  `--from-dump` 拒绝它；缺分节的快照同样硬失败（缺一节的症状与「那一层没有漂移」
  逐字相同）。
- **解析不出来的东西一律硬失败**，不静默跳过：attached 托管策略的文档与
  `DefaultVersionId`、permissions boundary 的文档、`GroupList` 里的 group。
  静默跳过它们的输出与「那里没有相关语句」一模一样。

**B（IAM 写观察）**

- **不判断某条语句是否生效**（Condition 没求值，boundary 与 SCP 没参与评估）。
- **不判断是否构成提权链**——那要看目标策略挂在谁身上、能否 AssumeRole/PassRole、
  boundary 拦不拦。B 的语义就是字面意思：**存在一条可能影响 IAM 策略变更动作的语句**。
- **不判断变化方向**是收紧还是放宽。这是刻意的：判方向需要的正是上面那套分析器。
  **宁可多红**——报文里打了归一化后的语句原文，自己 diff 一遍再决定。

**C（站点 route / alias 可达性）——已移出本闸门**

- 站点的 route 活性、alias 存在性、alias 上的 Function URL **不由本闸门保证**，
  归**部署验收**（已记进 merged review §9）。含：**idle 颜色被整个删除检测不到**。
- 被否掉的思路：从 jobs 表推导「该有几个颜色」不成立——有站点有 2 次成功部署却只有
  blue，因为其中一次在 M7 之前。

## M09 的框架不够大

merged review 的 M09 记的是「同账号 `lambda:InvokeFunction` 可对 panel 与站点伪造
`x-user-email`」，并把控制台**写面**记成「仍被一道 HMAC 挡住」。2026-08-25 的实测
在两处扩大了它：

1. **冒充任意用户不需要 invoke。** 只读级的 `lambda:GetFunction`、
   `s3:GetObject`/`GetObjectVersion`（CDK asset）或四个 `ssm:GetParameter*`
   动作里的任一个就够——直接签一个真的会话
   cookie，走正常 HTTPS 进来。M09 描述的 invoke 路径是这件事的一个子集
   （62 个里 18 个非平台身份能走 invoke，而 57 个能拿到密钥）。
2. **写面并没有被挡住。** 那道 HMAC 的密钥，57 个 principal 能读到。
   review 里「写面唯一承重的是 `__Host-sb_console` 的 HMAC 验签」这句在**机制上**
   是对的，但它承重的前提（密钥不可得）不成立。

所以 M09 的「第 2 步：收窄人/CI 身份策略」按原话执行会得到一个假修复
（见上表）。本文档取代它成为该条的结论，可执行的部分是上面那道漂移闸门。

## 相关

- `site-builder/policies/README.md` —— SCP 模板与它的三条边界（为什么在管理账号里不生效）
- `site-builder/deployer/functions/edge_caller.py` —— `caller_is_edge` 的模块 docstring：
  它**只在** Function URL 那条路（`callerId` 由 STS 填）有效，是纵深防御不是修复。
  **那段 docstring 早于本文档，它的 Path A / Path B 二分不够大**：还有一条路——
  攻击者用读到的密钥签一个**真实**会话 cookie 走正常 HTTPS 进来，此时 `callerId`
  确实是 Edge 的，`caller_is_edge` 会放行、而且**应该**放行（请求真的来自 Edge），
  垮掉的是「会话 cookie 只能由平台签发」。所以别把它读成
  「经 Function URL 进来的身份都可信」。
  （这段话没有写进那个文件：`edge_caller.py` 会被打进 panel 与 key-proxy 的部署包，
  动它一个字节就要重部三个组件才能让「产物 == 源码」那道闸门恢复绿——
  为一条注释付这个代价不值。下次因别的原因重部这三个组件时可以顺手补进去。）
- `site-builder/deployer/buildspec-package.yml` —— `--ignore-scripts` 那一行；
  它是「不可信站点依赖」与「平台签名密钥」之间当前唯一的隔断（见上文过宽授权一节）
- `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §4 的 `M09` 与 §9 优先级表
- `site-builder/DEPLOY.md` 「轮转 `jwt-secret`」一节 —— 当前实现不支持安全轮转。
  这与本文档直接相关：密钥一旦被读，换掉它既需要一个全员重新登录的窗口，
  **也要连带清理 bootstrap 桶里那 9 个仍带旧密钥的 asset 对象**
