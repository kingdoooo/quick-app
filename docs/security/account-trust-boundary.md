# 账号信任边界：平台能防谁，不能防谁

> **状态：已知未修（不是已接受）。** 最近一次实测 2026-08-25，方法与原始数据见下。
> 这份文档是 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 里
> **M09 第 1 步**的产物，并且**扩大了 M09 的结论**——见「M09 的框架不够大」一节。

## 一句话

**这个平台的安全边界是 AWS 账号本身。** 账号内任何具备「读 Lambda 产物」、
「读 CDK bootstrap S3 桶」或「读 SSM 参数」这类**只读级**权限的 principal，
都可以取得会话签名密钥，从而以任意用户身份访问任意站点与控制台（读与写都算）。
应用层的任何一道检查都挡不住这件事，因为它们全都以那把密钥为根。

对**不具备**账号级权限的一切东西——站点代码、per-site IAM 角色、公网访问者——
「身份只能来自 Edge」这条不变量是成立的，而那正是这套设计要防的威胁。

## 这份文档回答什么

- 平台对哪类攻击者提供保证，对哪类不提供（下面两节）；
- 为什么不能靠 SCP / Lambda resource policy / 应用层对称签名 / 收窄 invoke 来修；
- 账号内**能**做到什么（非对称签名那条路，以及它的代价）；
- 在真修复之前，用什么纪律保证暴露面**别再变大**。

它**不**回答「怎么把账号里那 35 个无关工作负载清理干净」——那是账号治理，
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

| 项 | 数 |
|---|---|
| 具备至少一项敏感授权的 principal | 62 <!-- baseline:总数=62 --> |
| 其中**能取得会话签名密钥**的 | 56 <!-- baseline:可读密钥=56 --> |
| 其中**非平台**身份可直接 `lambda:InvokeFunction` 平台或站点函数的 | 18 <!-- baseline:非平台可直调=18 --> |
| 其中与本平台**完全无关**的工作负载角色 | 35 <!-- baseline:无关工作负载=35 --> |
| CDK bootstrap 桶里仍带着**当前有效**密钥的 asset 对象 | 9 <!-- baseline:带活密钥的asset=9 --> |

按类别（**不写角色原名**：其中若干名字内嵌账号 ID，另有一批是企业内部托管角色，
写进被跟踪文件既违反仓库红线也没有必要）：

| 类别 | 数 | 说明 |
|---|---|---|
| `platform` | 6 | 平台自己的角色，授权都是**必需且精确**的，见下节 |
| `platform-overbroad` | 1 | 平台自己的角色，但这条授权它**不需要**：见「平台侧唯一的过宽授权」 |
| `admin` | 3 | 账号管理身份（含账号 owner 的 IAM 用户）。属既定信任模型 |
| `break-glass` | 7 | 企业内部托管的管理/审计角色。不由本项目控制 |
| `cdk-admin` | 6 | CDK bootstrap 的 CloudFormation 执行角色与部署角色（各 3 个区），按约定是 `AdministratorAccess`。**任何能在本账号跑 `cdk deploy` 的人都能用** |
| `cdk-readonly` | 4 | CDK bootstrap 的 lookup 与 file-publishing 角色。它们**足以拿到密钥** |
| `unrelated-workload` | 35 | 与本平台无关的工作负载：EC2/ECS/EMR/EKS 实例角色、多个 SageMaker 与 Personalize 执行角色、Glue、Batch、SSM 自动化与 QuickSetup、另一套 GenAI Agent 栈、若干应用与 CDK BucketDeployment 角色 |

⇒ 这不是「只有我一个人有权限」的个人账号，而是一个**多工作负载共享账号**。
任何一个上述工作负载被拿下（含任何能在本账号里跑 notebook / EC2 / `cdk deploy`
的人），都可以冒充任意用户。

## 密钥有三条路能拿到，三条都实测可用

会话 JWT 与控制台会话（`__Host-sb_console`）用**同一把** HS256 密钥，
真源是 SSM SecureString `/site-builder/jwt-secret`。

**路 ①：`lambda:GetFunction` 下载 Edge 产物，密钥是明文。**
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

**路 ③：`ssm:GetParameter` 读那个 SecureString。**
看起来还有 KMS 一道，实际没有：参数用的是 AWS 托管密钥 `alias/aws/ssm`，其 key
policy 与上面 `aws/s3` 那条形态完全相同（`Principal:*` + `ViaService=ssm.*` 的
直接授权，已读该 key policy 核实）。而 `ssm:GetParameter` on `parameter/*` 广泛
存在于 EC2/ECS/EMR/EKS 实例角色与 SSM 自动化角色的托管策略里。

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

## 为什么这几种修法都不成立

| 手段 | 为什么不成立 |
|---|---|
| **贴 SCP** | SCP 对 Organizations **管理账号无效**（含 root），而本部署就在管理账号。`site-builder/policies/README.md` 边界①已写明；那份模板是纵深防御制品，不是修复 |
| **Lambda resource policy 加 Deny** | Lambda 只有 `AddPermission`/`RemovePermission`，**只能写 Allow**；且同账号下 identity policy 单独即可授权 invoke，不需要命中 resource policy |
| **应用层给 Edge 请求加对称签名** | 签名的根就是那把密钥，而 56 个 principal 能读到它。对站点 Lambda 另外还不可行：验签要求站点持有密钥，而站点代码是不可信的 AI 生成代码 |
| **只收窄 `lambda:InvokeFunction`** | **假修复。** 同一批身份还握着密钥读取、`lambda:UpdateFunctionCode`（可整体替换 panel 代码）与 `iam:PutRolePolicy`（自助提权）。收掉 invoke 之后边界一寸也没移动，但会读起来像修好了 |
| **收窄那 35 个无关工作负载** | 能缩小 blast radius，但**关不掉**：`cdk-admin` 与 `admin`/`break-glass` 必须保留管理权限，而它们本身就足够。且那是账号治理，不是本仓库的改动 |

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

**顺序建议**：B 关掉的是当前 56 个 principal 里绝大多数（只读级那批），
且不依赖账号迁移；A 关掉的是剩下的管理身份。先 B 后 A，或者只做 B 也能把
风险从「账号内任何只读身份」压到「账号管理员」。

## 在那之前的运行纪律

暴露面既然关不掉，唯一还能自动化的就是**别让它继续长**：

```bash
python3 site-builder/scripts/verify_account_trust_boundary.py
```

它测三层：

1. **identity 授权**——授权记成 `invoke-platform:site-panel` 这样的 grant 串，
   **不是布尔标签**。压成布尔时「某角色原来只能调 undeploy、现在还能调 panel」
   这种资源扩权会静静地绿，而那正是 panel 读面失守的分界。
   `function:foo` 与 `function:foo:blue` 在 IAM 里是两个资源，所以 alias ARN
   一起探（M7 之后站点的 Function URL 都挂在 alias 上）。
2. **Lambda resource policy（含每个 alias）**——`SimulatePrincipalPolicy`
   **不**自动纳入 resource policy，而同账号 resource-based Allow 单独即可授权，
   所以这条通道必须单独快照。站点函数记下**全部合法形态**（两种都合法：
   M7 迁移来的站点残留一份未限定 policy，M7 之后新建的只有 alias 那份），
   匹配任一形态即合规 ⇒ 新建站点不产生漂移，多一条或少一条语句的站点被点名。
3. **密钥物化位置的事实**——三处副本每次都实测（比对 SHA-256），
   某处不再含活密钥时对应 grant 自动消失并报成改善。**根治了它，闸门自己就知道。**

红绿规则：出现新 principal、已知 principal 长出新 grant、新增 resource policy
语句、站点 policy 偏离已知形态 → **红**；Edge 角色或 deployer exec 角色丢掉必需的
invoke → **红**（这两条防的是「收窄」把平台自己锁死：真机症状分别是全站 403 与每次
部署在健康门失败，两者都不会在任何单测里出现）；集合缩小 → 绿，并打印提示更新基线。

基线在 `site-builder/scripts/account_trust_baseline.json`，**只存指纹**
（`sha256[:16]`）与类别，不含任何账号值——账号内有若干角色名内嵌账号 ID，
resource policy 的 `Principal` 也是带账号 ID 的角色 ARN，照抄就把账号值提交进仓库。

更新基线（确认过新增项是可接受的之后）：

```bash
# ① 先拿到带真实名字的清单（产物含账号内标识，写 /tmp，勿提交）
python3 site-builder/scripts/verify_account_trust_boundary.py \
    --dump-observed /tmp/trust-observed.json
# ② 写一份 {角色名: category} 映射，再落基线（--from-dump 复用①的快照，不重跑模拟）
python3 site-builder/scripts/verify_account_trust_boundary.py \
    --from-dump /tmp/trust-observed.json --classify /tmp/trust-classify.json \
    --update-baseline
# ③ 同步本文档的五个数字（deployer/tests/test_verify_account_trust_boundary.py 会校验）
```

`docs/security/` 下的这份文档、基线文件与闸门脚本三者互相咬着：
文档的五个数字由基线算出并由单测断言（**正文里显示的数字必须紧挨着校验标记**，
否则标记与正文可以各写一个数），基线由闸门写入，闸门的纯函数由单测覆盖。
改任何一个都会把另外两个拽红。

### 这道闸门**不**证明什么

写在这里，因为把它当成「暴露面已穷尽」是最容易犯的错：

- `SimulatePrincipalPolicy` 对带 Condition 的策略需要调用方补 `ContextEntries`，
  本脚本不补 ⇒ 那些 principal 的判定是**下界**。最近一次实测有 **162** 个
  principal 的响应带 `MissingContextValues`。这个数被记进基线并打印，涨了就说明
  「不确定的部分变多了」。**它不是 fail-closed 的**：真要 fail-closed 就得把这 162
  个全判成有权限，那样闸门永远红、也就没有信号。
- 它只看 IAM 与 Lambda resource policy 两条通道，不看 KMS grants、
  VPC endpoint policy、其它服务的 resource policy。
- 它不看跨账号 principal。
- 它统计的是**当前**存在的 principal 与资源；某人临时建一个角色用完删掉，
  两次运行之间看不见。

## M09 的框架不够大

merged review 的 M09 记的是「同账号 `lambda:InvokeFunction` 可对 panel 与站点伪造
`x-user-email`」，并把控制台**写面**记成「仍被一道 HMAC 挡住」。2026-08-25 的实测
在两处扩大了它：

1. **冒充任意用户不需要 invoke。** 只读级的 `lambda:GetFunction`、
   `s3:GetObject`（CDK asset）或 `ssm:GetParameter` 就够——直接签一个真的会话
   cookie，走正常 HTTPS 进来。M09 描述的 invoke 路径是这件事的一个子集
   （62 个里 18 个非平台身份能走 invoke，而 56 个能拿到密钥）。
2. **写面并没有被挡住。** 那道 HMAC 的密钥，56 个 principal 能读到。
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
