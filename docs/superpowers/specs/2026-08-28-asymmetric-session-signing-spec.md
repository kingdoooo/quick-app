# 3c：会话签名迁到非对称（设计 spec）

日期 **2026-08-28**（末次修订 **2026-09-06**）。状态：**3c-0 裁决完成；3c-1A 与 3c-1B 已实施并部署
（2026-09-02 / 2026-09-05）；2A/2B/3 于 2026-09-06 合并为 3c-final（§11.9）；3c-final 已实施并在
验证环境硬切换（日期见 §6.1）。**
（§11 七个未决项已于 2026-09-02 逐条定稿；§11.1 的冷启动数字已按最终实现形态复测通过（第一轮
判读作废）；外部复审第十三、十四轮的 P1 与 Codex 对 3c-0 的 6 条阻断项已按下文吸收。
**1A/1B 的落地情况见 §6.1 那两行**——1B 含 signer 切 family `kid`、L3 关闭 legacy 入口、
一次真实 v1→v2 轮转与生产回滚演示，其中 **④ 观察窗口经操作者裁决跳过**；
1A/1B 当时的签名仍是对称 HS256；非对称化（2B）与它的闸门前置（2A）已随 3c-final 一并完成。）
术语以根 `CONTEXT.md` 为准；三条随裁决立下的 ADR 在 `docs/adr/0001` 到 `0003`。
3c-1A 的实施计划：`docs/superpowers/plans/2026-09-02-3c-1a-verifier-kid-allowlist.md`（批准即为 1A 的授权）。
对应 merged review §9 的 **3c**
（M09 真修复 ②）。前一条 3b（收窄 CodeBuild 对 bootstrap 桶的读权限）已于 2026-08-27
部署，见 `2026-08-27-codebuild-bootstrap-read-narrowing-spec.md`。

结论真源仍是 `docs/security/account-trust-boundary.md`；本文件只管 3c 的设计。

---

## 0. 这份文档的范围

**它定的是接口与协议，不是实现细节。** 之所以先写完整 spec 再动第一行代码：下面这几件事
**都会改变第一个实现包的接口**，任何一件留到实现中途再定，第一包就得重做——

- 两个 key family 还是一个；
- 三类 token 各自的 `kid` / `token_use` / `aud`；
- legacy（无 `kid`）token 怎么迁移、什么时候可以拒；
- Edge 的公钥集合怎么打包、怎么全球发布；
- `current` / `previous` 的条数上限与退役条件；
- signer / verifier 的部署与回滚次序；
- RSA 验签用 vendored 库还是纯 Python。

**这七件事在 §11 都已裁定**；最后一条以冷启动 spike 的实测为闸，最终形态复测已通过（§11.1）。

**明确不在本文档范围**：账号迁移（§9 的 3d）、`dsql:DbConnect` 的 `Resource: *`、
同名 cookie 的身份混淆（host-only 会话，独立成包）。

---

## 1. 为什么做，以及收益的**准确边界**

3c 的论点是"Edge 只放公钥 ⇒ 只读那批 principal 拿不到签名能力"。这个论点**成立**。

下面的数字来自生产只读模拟（401 个 principal = 399 个非 service-linked 角色 + 2 个用户，
与闸门基线那次的 400 口径一致）。探针、脱敏聚合证据与已知盲区清单见 §12.1；
**它是可复跑的 tracked 产物，不是本文档里的手抄数字。**

| | 数量 |
|---|---|
| 今天能拿到 HS256 明文密钥 ⇒ 能签任意人的会话 | **56** |
| 3c 后能签会话（`can_sign`） | **15** |
| 3c 后能替换**CloudFront 正在执行的** Edge 验签代码（`can_replace_edge_verifier`） | **17** |
| **⇒ 3c 之后的冒充面（两者并集）** | **19** |

> **这个 19 是「已知下界」，不是上界。** 它是"按下面九条已建模路径量出来的并集"，
> 而聚合证据里带着一份 `known_gaps`（KMS key policy 未纳入、IAM 自助提权归闸门 B 组、
> `UpdateFunctionConfiguration` 取上界口径、Cognito pre-token 那条不在 3c 范围……）。
> **口径必须写成下界**——把它写成"上界"是上一稿被连续两轮复审咬住的同一个错误：
> 每次都是"我建模的路径的并集"被当成了"全部路径的并集"。

九条已建模路径各自的持有者数：

| 能力路径 | 持有者 |
|---|---|
| `sign:kms-direct`（`kms:Sign`） | 12 |
| `sign:kms-self-authorize`（`PutKeyPolicy` / `CreateGrant` 自助授权） | 13 |
| **`sign:hijack-auth-signer`**（换 `site-auth-service` 的代码/配置） | **14** |
| **`sign:hijack-panel-signer`**（换 `site-panel` 的代码/配置） | **14** |
| `edge:code+publish+associate` | 12 |
| **`edge:code(Publish=True)+associate`**（一次调用即改码即发版本） | 12 |
| `edge:new-function+associate`（新建函数 + `PassRole` edge 执行角色） | 12 |
| `edge:cfn-update-stack`（router 栈） | **17** |
| **`edge:cfn-change-set`**（`CreateChangeSet`+`ExecuteChangeSet`） | 16 |

> **3c-2A 之后多一条已建模路径**：`sign:fixture-issuer`，即 `site-builder-verifier` 角色经 auth 的
> `/fixture-session` 签**夹具域**站点会话（§11.7）。它是**受限**冒充（只签 `e2e.invalid` 域、只签
> `site-session`，且 Edge 只在夹具站点上认它，§11.7），仍精确纳入 A 组枚举，单列标签、不与
> `sign:kms-direct` 合并。**这条路径有两个入口**：经 Function URL 的 `site-builder-verifier` 角色，以及对
> `site-auth-service` 的直接 `lambda:InvokeFunction`（调用方自己构造整个事件，`userArn` 字段随手伪造，
> `edge_caller.py` 的 Path A 实测过）。探针两个都要建模。

### 被外部复审连续纠正过两次的地方（务必别照抄任何旧说法）

**第一次**（第十三轮）：草案说"残留那 12 个 12/12 都持 `replace-platform-code`，
所以不给 `kms:Sign` 也能直接换掉 Edge"。不成立——闸门的 `replace-platform-code`
只模拟 `lambda:UpdateFunctionCode`，而它改的是**未发布的 `$LATEST`**，
Lambda@Edge **必须**关联编号版本（CFN 文档原文："You must specify the ARN of a
function version; you can't specify an alias or `$LATEST`"）。**已实测**：本
distribution 上 origin-request 的 association 限定符就是一个编号版本
（探针每次跑都重新验这条前提，不成立就响亮失败）。

**第二次**（第十四轮，就是把 18 改成 19 的这次）：上一稿把冒充面定义成
"能签名 ∪ 能替换 Edge"，但**漏了「能劫持 signer 本身」这一整类**。3c 之后 auth 的执行
角色持两把 key 的 `kms:Sign`、panel 持 console key 的 `kms:Sign`；而**实测**：

- `site-auth-service` 与 `site-panel` 的 Function URL **都没有 qualifier**，
  两个部署脚本用的都是裸 `update_function_code`（不带 `Publish`）
  ⇒ **它们服务的是 `$LATEST`**；
- 于是 `lambda:UpdateFunctionCode` **一个动作**就是"在那个执行角色下跑任意代码"，
  **既不需要攻击者自己有 `kms:Sign`，也不需要碰 Edge、不需要发版本**。

⇒ `can_sign` 从 13 涨到 **15**，冒充面从 18 涨到 **19**。

**另外两条第十四轮要求补测的等价路径，量出来没有改变总数**（但模型现在是对的，
以后账号形状变了就会体现）：`UpdateFunctionCode(Publish=True)` 与
`CreateChangeSet`+`ExecuteChangeSet` 的持有者分别是 12 与 16，都落在既有集合里。
**"提出来的路径实测没加人"与"不必建模"是两回事**——不建模的话，哪天某个角色只拿到
change-set 那两条就整个漏掉。

一句话仍然成立：**3c 把边界从「账号内任何只读身份」压到「能改写平台代码或能签名的
身份」**，从 56 压到 19。它**不**声称防住管理员。

### 各候选缓解措施的**边际收益**（这一栏推翻了上一稿的 key policy 论证）

判据不是"某条路有几个人"，而是**关掉这一组路径之后有多少 principal 完全离开冒充面**：

| 措施 | 冒充面 | 离开的 principal |
|---|---|---|
| **给 router 栈加 stack policy**（今天**没有**，实测） | 19 → **15** | **−4** |
| 限制性 KMS key policy | 19 → 18 | −1 |
| 收窄谁能改 auth/panel 的代码与配置 | 19 → 18 | −1 |
| 锁住 Edge 的换码/association 直接链 | 19 → 19 | **−0** |

三条结论，都与上一稿不同：

1. **`kms:Sign` 的限制性 key policy 只值 1 个 principal，而且它结构上收不掉劫持
   signer 那条路**——恶意代码是**以 signer 角色的身份**调 KMS 的，key policy 必须放行
   它。上一稿拿"能签名但不能替换 Edge"（当时 1 个）当收益判据，**那个判据本身是错的**，
   不只是数字小。结论仍是**不值得**（换来自锁风险 + 一个必须纳入闸门枚举的破窗
   principal），但这次的理由经得起复核。
2. **"锁住 Edge 的换码/association 直接链"边际收益是 0。** 持有那条直接链的人**全部**
   同时持有 CFN 那条路 ⇒ 只收窄 Lambda+CloudFront 而不管 CloudFormation 是**假修复**，
   与 merged review 里 M09 第 2 步"收窄 invoke"那条假修复是同一个形状。
3. **反过来，router 栈的 stack policy 是这四条里唯一一次能减 4 的**，而且它与 3c 正交、
   便宜、可单独做。**它不在本 spec 的范围里**，应当作为独立项进 merged review §9。

### 顺带发现：闸门的 `replace-platform-code` 是个坏代理，两个方向都错

- **过度声称**：它只有 `UpdateFunctionCode`。对 **Edge** 证明不了能替换正在运行的代码
  （必须关联编号版本）；对**站点函数**同样不成立——M7 之后站点 Function URL 挂在
  blue/green alias 上，而 alias 指向的是 `publish_version` 出来的编号版本，改 `$LATEST`
  改不动它。**但对 `site-auth-service` / `site-panel` 它恰好是对的**（那两个服务
  `$LATEST`）⇒ 同一个标签在不同函数上强度不同，这本身就是"把能力压成单个动作"的代价。
- **同时少算**：`cloudformation:UpdateStack`（17）比 Lambda+CloudFront 那条直接链（12）
  **更宽**，而闸门完全没看 CFN 这条路；change-set 那条（16）也没看。

⇒ 闸门应当把"能替换正在运行的平台代码"建模成**完整链**（动作等价类 × 资源等价类），
判据与探针的 `classify()` 一致。这条归 §10，且**它本身就是当前基线的一处低估**，
与 3c 是否做无关。

**顺带一个今天没有、3c 之后自动获得的性质**：Lambda@Edge 必须关联**已发布的编号版本**，
所以每次 Edge 部署都留下一个版本，而每个版本的代码里都带着**当时有效**的对称密钥
（bootstrap 桶里的 asset 同理）。换成非对称后，历史版本里留下的只有**公钥**，
版本累积从此不再是负债。这也是为什么"把那些 asset 删掉"不是 3c 的替代方案。
（**两处的当前数量一律去 `account-trust-boundary.md` 的基线断言表查**，本文件写的日期是
2026-08-28，那时的数字与今天不同——每部署一次 Edge asset 就 +1。）

---

## 2. 起点快照（写于 2026-08-28）：一把密钥，4 处签、5 处验

> ⚠️ **这一节是 3c-1 之前的起点快照，不是今天的线上形态。** 3c-1A/1B（2026-09-02 / 09-05）
> 之后：签发用**两把带 `kid` 的 family 密钥**（`site-hs-v2` / `console-hs-v2`），OAuth state 与
> PKCE cookie 用一把 **auth 私有的 login-flow secret**，`/site-builder/jwt-secret` 只剩下
> **已关闭**的 legacy 入口那一条身份、三处 verifier 都不再接受它（待 3c-3 删）。
> 下面的行号与"全部用同一把密钥"那句都按当时的代码写的，**读的时候当历史看**；
> 今天的形态见 §6.1 的 1B 行与 §6.2 的状态机现状。**本节的设计推理不受影响**——
> 它论证的是"为什么必须迁非对称"，而那个论点 1B 一条都没改（密钥仍是对称的）。

| # | 签名点 | 位置 | 产物 |
|---|---|---|---|
| 1 | 站点会话 `sb_session` | `auth/login_handler.py:503` → `session.mint_session_jwt` | `typ=session`，24h |
| 2 | console 一次性升级码 | `auth/login_handler.py:545` → `session.mint_upgrade_code` | `typ=console-upgrade`，≤60s |
| 3 | 面板会话 `__Host-sb_console` | `panel/console_session.py:109` → `session.mint_session_jwt(scope="console")` | `typ=session` + `scope=console`，4h |
| 4 | OAuth state | `auth/login_handler.py:102` `_login_flow_sig` | **裸 HMAC，不是 JWT** |

| # | 验签点 | 位置 | 验的是什么 |
|---|---|---|---|
| 1 | Edge | `router/infrastructure/lambda/origin_request.py:452` | 站点访问的 `sb_session` |
| 2 | auth | `auth/login_handler.py:530` | `/console-session` 换升级码时的 `sb_session` |
| 3 | panel | `panel/console_session.py:131` | 每个控制台写请求的 `__Host-sb_console` |
| 4 | panel | `panel/console_session.py:82` | 消费一次性升级码 |
| 5 | auth | `_decode_state`（`login_handler.py:128`） | OAuth state |

**四处签、五处验，全部用同一把 `/site-builder/jwt-secret`。**

> `DEPLOY.md` 从前把生产验签写成"只有 Edge 一处"，那是 M3/M05 之前的旧话，已于
> `fe5298d` 修正并加了派生守卫。**按"只改 Edge 一处"估 3c 的改动范围会漏掉两个生产
> 验签点**，而 panel 至今没有 `requirements.txt`、产物里只有 `.py`。

**今天两类长期会话的区分有多薄**：`sb_session` 与 `__Host-sb_console` 的 `typ`
**都是 `session`**，只差一个 `scope`，而 **Edge 根本不查 `scope`**——一个 console token
的值若被当作 `sb_session` 递上来，Edge 会接受它。今天靠浏览器的 `__Host-` 前缀
（host-only、限 `console.{base}`）隔开，**不是靠验签逻辑**。这正是
`account-trust-boundary.md` 说的"读面失守自动升级成写面失守"。

---

## 3. 硬约束（每条都有出处，不是推测）

### 3.1 Lambda@Edge

来源：CloudFront 开发者指南 *Quotas on Lambda@Edge* 与 *Restrictions on Lambda@Edge*。

- 压缩后部署包上限 **50 MB**；超时 **30 秒**；内存同 Lambda 常规。**这三项在现行文档里
  都在「通用」表里，origin 与 viewer 相同**——流传的"viewer 1 MB / 5 秒 / 128 MB"
  在现行文档中查不到（只在一篇旧博客里有 1 MB 那句）。按事件类型区分的只剩一项：
  **函数自己生成的响应体**（viewer 40 KB / origin 1 MB）。
  ⇒ **包大小从来不是这次的约束。**
- **不支持环境变量**（现在密钥靠 `{{PLACEHOLDER}}` 部署时替换就是因为这条，
  换公钥后这机制照用）、**不支持 Layers**、**不支持容器镜像**、**不支持 arm64**。
- **必须关联已发布的编号版本**（不能用 `$LATEST`）⇒ **公钥集合最终必须进入 Edge 的
  部署包**，且每次公钥集合变化都产生一个新版本 + 一次全球发布。
  **这条必须在轮转协议里就位，不能实现到一半再补**（§7）。

### 3.2 Edge 不能每请求调 KMS

不是"不能发网络请求"——配额表明确写着函数可以调 AWS 区域内资源，30 秒够。挡住这条路的是
两件事：

- **RSA 加密操作是账号级共享 1,000 rps**（KMS *requests-per-second* 页），
  而 Lambda@Edge 单区就有 10,000 rps；
- 跨区同步调用的延迟。本仓库自己实测过 Edge 跨区写 DynamoDB **热 229 ms / 冷 719 ms**
  （CLAUDE.md 埋点预算那条）。

⇒ **Edge 只能本地验签**。这恰好就是"Edge 只放公钥"的形状，约束与设计同向。

### 3.3 非对称 CMK 不支持自动轮转

CFN `AWS::KMS::Key` 文档：自动轮转只支持 `SYMMETRIC_DEFAULT`；非对称密钥必须
省略或置 `false`。

⇒ **双接受（多 `kid`）不是迁移期的临时脚手架，而是长期必需能力。** 这直接决定了分包
顺序：先把轮转底座建起来（3c-1），再迁 KMS（3c-2）。

### 3.4 KMS key policy 是权威的

KMS 开发者指南 *Key policies*：

> No AWS principal, including the account root user or key creator, has any permissions to
> a KMS key unless they are explicitly allowed, and never denied, in a key policy, IAM
> policy, or grant.
>
> Unless the key policy explicitly allows it, you cannot use IAM policies to *allow*
> access to a KMS key. Without permission from the key policy, IAM policies that allow
> permissions have no effect.

同指南 *Default key policy* 另有自锁警告；`PutKeyPolicy` 的 required permission 是
`kms:PutKeyPolicy`（key policy），并有 lockout safety check（可被
`BypassPolicyLockoutSafetyCheck=true` 关掉）。

⇒ 若采用限制性 key policy（§1 的决策点），**必须留一个明确的破窗 principal 持
`kms:PutKeyPolicy`**，并且**那个 principal 就是新的暴露面，闸门必须枚举它**。

### 3.5 算法与计费

- JWT `RS256` ⇒ KMS `SigningAlgorithm = RSASSA_PKCS1_V1_5_SHA_256`，`KeySpec = RSA_2048`。
- `kms:Sign` 的 `Message` 上限 4096 字节（JWT signing input 远低于此）。
- **`RSA_2048` 的非对称请求与对称同价**（$0.03/万次）；其余非对称（含全部 ECC）
  **$0.15/万次**，且非对称请求**不含免费额度**。签名只发生在登录/换码路径，不在每请求
  路径 ⇒ 这笔钱可忽略。
- `kms:GetPublicKey` 返回 **DER 编码的 SPKI**（RFC 5280）；CLI/HTTP 下是 base64。

---

## 4. 目标模型

### 4.1 两个独立 key family

| key family | 签发者 | 验证者 | token |
|---|---|---|---|
| **site-session** | auth | Edge、auth | `sb_session` |
| **console** | auth、panel | panel | 升级码、`__Host-sb_console` |

3c-2 阶段对应**两把独立 CMK**，权限按 family 分：

- **auth role**：可 `Sign` site key；因为它也签升级码，需要**受限地** `Sign` console key；
- **panel role**：**只能** `Sign` console key；
- **Edge**：**零 KMS 权限**，只内嵌 site 公钥；
- **Edge 的 allowlist 里不出现 console 公钥**。公钥不是秘密，但**"接受哪些 key"本身
  就是授权边界**——这一条让"panel signer 被攻破 ⇒ 伪造站点会话"和"site key 暴露 ⇒
  升级成 console 写权限"两条路在密码学层断开。

**两个 key family 从第一包（3c-1，仍是 HS256）的数据模型就开始**，不是等到 3c-2 才拆。
否则 3c-1 建出来的 allowlist 形状要重做。

### 4.2 三类 token 各自的用途与受众

**不再让两类长期会话都用 `{"typ": "session"}`。** 定义三种精确用途，各绑固定 `aud`：

| token | `token_use` | `aud` | TTL |
|---|---|---|---|
| 站点会话 | `site-session` | `site-edge` | 24h |
| 升级码 | `console-upgrade` | `console-exchange` | ≤60s |
| 面板会话 | `console-session` | `console-panel` | 4h |

> 现有的 `typ` claim 与 `SESSION_TYP` / `UPGRADE_TYP` 常量是 M05 的产物，语义上就是
> `token_use`。迁移时**改名要连 legacy 兼容一起设计**（§7 的 legacy 入口），不能直接换名
> 把存量 cookie 全判死。
>
> 字面量、`aud` 的类型（单个字符串）、新 token 的 claim 集合与 `kid` 格式在 §11.4 定稿。

### 4.3 每个 verifier 的 allowlist

**每个 verifier 只认它自己那份 allowlist，不共享一个全局 registry。**

| verifier | 接受的 key family | 接受的 `token_use` |
|---|---|---|
| Edge | site-session | `site-session` |
| auth `/console-session` | site-session | `site-session` |
| panel（面板会话） | console | `console-session` |
| panel（升级码） | console | `console-upgrade` |

### 4.4 verifier allowlist 的形态

`kid → {key family, alg, key material}`，**固定 allowlist**，每个 family 最多两把：
`current` + `previous`。

**禁止（每条都要有反例覆盖，见 §9）**：

- **按不可信的 `kid` 动态拼** SSM path / KMS ARN / 文件名。`kid` 来自 token，是攻击者
  控制的输入；用它去拼资源标识就是把资源选择权交出去。
- **相信 JWT header 自带的 `alg`**。`alg` 只用来**比对** allowlist 里该 `kid` 绑定的算法，
  不能用来分派实现。
- **一个全局 key registry 被 Edge / auth / panel 全部共享**。
- **只靠 cookie 名、`__Host-` 前缀或 `scope` 做用途隔离**。

---

## 5. 验签合同

每个 verifier 在**验签通过之后**、按此顺序检查：

1. `kid` 存在，且在**本 verifier 自己的** allowlist 里；
2. header 的 `alg` 与 allowlist 中该 `kid` 绑定的算法**精确一致**；
3. 签名用该 `kid` 对应的 key material 验过；
4. `token_use` **精确一致**；
5. `aud` **精确一致**；
6. `exp`（以及既有的身份字段合同：`email` 非空等）。

**顺序不能反**：先验签、再解析并信任 payload。反了就是在未验签数据上做逻辑判断。

**RS256 阶段（3c-2B）额外必须做到的，分两层，别混**（Codex 复审：上一稿把 JOSE 层的检查错归到
纯 Python 分支）：

- **JOSE 层，与用哪个 RSA 实现无关，一律必须**：base64url 必须规范形式（拒 `=` 填充、拒标准
  字母表、拒非规范尾比特）；拒 `crit` 头；`alg` 只与 allowlist 比对（§4.4）；签名长度**严格等于
  模长**；公钥侧在部署时校验 SPKI 是 `rsaEncryption`、DER 最小形式、模长 ∈ {2048,3072,4096}、
  **指数等于 65537**。这一层的反例用例是 3c-2B 的交付物，选 vendored `cryptography`（§11.1）也逃不掉。
- **RSA 原语层，只在选纯 Python 实现时才由我们负责**（§11.1 已否决，条款保留为唯一可接受的替代
  实现）：重建完整 EMSA-PKCS1-v1_5 编码后**整块定时比较**（绝不在解出的 EM 里查找/`endswith`
  DigestInfo——那是 Bleichenbacher 2006 那一类伪造的唯一入口）；签名整数 `s < n`；定时安全比较；
  并有变形测试证明它们真会红（把整块比较改成 `endswith` 时，EMSA 那组必须全部转红）。

---

## 6. 分包与顺序

**3c-0（spec + spike） → 3c-1A（verifier 认新形态） → 3c-1B（HS signer 切 `kid`
＋轮转演练） → 3c-2A（闸门与验收先认 KMS） → 3c-2B（signer 切 `kms:Sign`） →
3c-3（HS 退役与清理）。**

> **2026-09-06 裁定（§11.9，ADR 0005）：2A、2B、3 合并为一个包 3c-final，在验证环境硬切换。**
> 下面 §6.1 表里这三行与 §6.2 的对应小节保留为设计内容的真源（要做什么没变），但"先后发布、
> 双接受过渡、26 小时排空"这些**时序**条款不再适用于这次切换——理由是交付物是资产而不是
> 验证环境，见 §11.9。kid 级 current/previous 与 `--drain-gate` 保留给采用者的 KMS 轮转。

**闸门与验收必须前移到它们要观察的那次变化之前**（外部复审 P1-1，成立）。生产 signing
surface 在 3c-1/3c-2 就已经变了，把闸门改动堆到 3c-3 意味着整个迁移期间闸门看不全新面。

### 6.1 change-impact matrix（**时序的唯一真源**）

**这张表是本 spec 里时序的唯一真源。** 下面 §6.2 的分包说明、§10 的闸门清单都只能
**引用**它，不得各写一套——第十三轮修复只追加了正确段落而没删掉旧段落，于是 §3c-3 与
§10 里同时留着"KMS 闸门放到 3c-3""基线全部重置"两条已被否掉的结论，照着实施仍会踩原
blocker（外部复审第十四轮 P1-2，成立）。

| 包 | 交付什么 | **进这个包之前**闸门/验收必须已完成 |
|---|---|---|
| **3c-0** | 本 spec 定稿 + Edge crypto spike 裁决（§11） | 冒充面探针与脱敏聚合证据 tracked 且可复跑 |
| **3c-1A** | 全部 verifier 认 `kid`→{family, alg, key} 固定 allowlist、每 family `current`+`previous`、legacy 第三入口（状态机 L1）；`[SessionKeys]` 按 §11.6 的 schema 落地（此时只有 HS 行）。**signer 不动** | 闸门认识**两个 HS key family** 与 legacy/current/previous（今天它只认识一个 `JWT_PARAM_NAME`、一套 Edge/asset 密钥定位）；§9 全部 verifier 反例齐备并验过红绿 **已实施并部署 2026-09-02**（plan `2026-09-02-3c-1a-verifier-kid-allowlist.md`） |
| **3c-1B** | signer 开始发 family-specific `kid` + 新 `token_use`/`aud`（状态机 L2）；两把新 HS secret `/site-builder/session-keys/<kid>` + login-flow secret（§11.3）；观察归零后**关闭** legacy 入口（进入 L3，删除仍归 3c-3）；一次真实 HS 轮转演练 R1/R2。**逐条裁定见 §11.8**。**已实施并部署 2026-09-05**（十步 runbook 首次执行完毕；`cf5db89` = ③ 切 signer/T0、`9245703` = ⑤ 进 L3、`03d2a14` = ⑥ v2 经 `previous` 就位、`a2dd16a` = ⑦⑧ 切 v2 + 生产回滚演示、`19c9f7f` = ⑨⑩ 排空判定 + v1 退役含删参数、`a38fee1` = 本次收尾文档）。**注意：④ 观察窗口在首次演练中经操作者裁决跳过**——单人开发账号、只读读数已证实 T0 以来 `accepted_legacy` 三列全 0，且**没有**做"缩短窗口版的 ④"；因此**观察窗口机制的真机证明只有 ⑨ 这一次**，它按满 26 h 等待并 exit 0 通过。三个时刻（**生产实测**）：**T0 = `2026-09-03T13:51:18Z`**、**④ 跳过裁决 = `2026-09-04T01:40:40Z`**、**⑨ 判定 = `2026-09-05T12:31Z`**（T2 + 30h12m，闸下限 T2+26h）。完整时间线与时长在 `site-builder/DEPLOY.md` 的 runbook 首节 | 四个 `verify_*` 与 10 条 E2E 的登录态工具能 mint **带新 `kid` 的 HS token**（否则 signer 一切就全红，读起来像功能坏了）；且必须在 signer 切换**之前**改完，否则它们自己就是 `accepted_legacy` 的来源（§11.8.2） |
| **3c-2A**（→ 并入 3c-final，§11.9） | **只改闸门与验收，不动生产签名**：KMS 探测（`kms:Sign` 持有者、key policy 快照、grants、自助授权、公钥指纹）+ 验收入口改造（auth `/fixture-session`、`site-builder-verifier` 角色、**Edge 与 panel 的夹具会话边界规则与签发器同一次部署上线、不得晚于它**（原写"先于"；并入 3c-final 后没有先后，见 ADR 0002/0005）、`ensure_fixture_site.py` 常驻夹具站点、探针 `sign:fixture-issuer` 两个入口，§11.7） | 上一格全绿；本包**自己**先验过红绿（新探测要能真的红） |
| **3c-2B**（→ 并入 3c-final，§11.9） | 两把 KMS 非对称 CMK（deployer CDK 栈创建，默认 key policy + IAM 条件，§11.2）；signer 切 `kms:Sign`（`RAW`，§11.5；identity policy 同时授 `kms:GetPublicKey`，§11.2）；三层 kid 绑定校验（§11.6）；verifier 双接受 | ~~**3c-2A 已上线**~~（并入 3c-final 后不再有先后）；五个验收入口拿到**真实登录态**（不再靠读 SSM 明文本地 mint），且验过红绿 |
| **3c-3**（→ 并入 3c-final，§11.9） | 退役 HS256、删旧 SSM secret、删 legacy 入口（状态机 L3）、基线**精确 delta** | `accepted_legacy == 0` 且总量非 0 持续超过最长 TTL（§8） |
| **3c-final** | 上面 2A、2B、3 三行的**全部设计内容**合成一个包（§11.9 第 1、4 条）：KMS 非对称 CMK + signer 切 `kms:Sign` + Edge/auth/panel 验 RS256 + 闸门 KMS 探测 + 夹具签发器 + 删除 HS 密钥材料、legacy 入口、跨算法双接受与迁移脚手架。在验证环境**硬切换**（见 CONTEXT.md 词条与 ADR 0005 后果）。kid 级 current/previous 双接受保留 | 3c-1B 全绿；本包自己先验过红绿（KMS 探测要能真的红）；一份 plan、SDD 串行、主会话执行（`.scratch/asset-v1/spec.md`）。**已实施并部署 <日期>**（plan `2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover.md`） |

> **为什么不能反**：若先切 `kms:Sign` 再补 KMS 闸门，3c-2 可以部署成功，而旧闸门只看到
> HS 暴露面大幅"改善"，**根本没观察新的 signing surface**——那正是这一整轮复审反复咬住的
> false-green 形状。同理，验收入口在 signer 切换的那一刻立即失效，留到清理包就等于
> 迁移期间没有真机验收。**这就是把 3c-2 拆成 2A/2B 的唯一原因**：闸门与验收自己要有一个
> 能独立上线、独立验红绿的发布单元，而不是挂在密码学切换那一包的前置条款里。

不做"整包一次上"：那会把安全闸门修复、生产收权与密码学迁移混成一个更难复核、更难回滚的
发布单元。

### 6.2 各包的内容

### 3c-0：spec + Edge crypto spike

已完成的部分：

- 生产只读量测 §1 的冒充面（**探针与脱敏聚合证据现在都是 tracked 的**，见 §12）；
- 签/验点全图（§2）；
- Lambda@Edge 与 KMS 的硬约束（§3）；
- 纯 Python RS256 验签的可行性原型：**0.24 ms/次**（2048-bit），32 项对抗性断言
  （含 `alg` 混淆、256 位逐位翻转、Bleichenbacher 类宽松解析伪造、长度/整数范围变形、
  base64url 规范化）＋一条刻意会红的正向控制。ES256 纯 Python **4.5 ms**（20 倍），
  且 KMS 请求贵 5 倍 ⇒ **排除 ES256**。

**§11 七条已全部裁定（2026-09-02），含 §11.1 的最终形态复测**：vendored `cryptography`，冷路径总差
128 MB 下中位数 +143.3 ms / p95 +147.1 ms（闸 300 / 600），Edge 维持 128 MB；第一轮按 Init 差判读、
总差 300.14 ms 压在闸上的那次已作废。脚本与数字见 §11.1、§12。

### 3c-1：HS256 双 key-ring 轮转协议

**仍然全程 HS256**，不引入任何 KMS / 网络延迟 / RSA 变量。它关闭的是 `DEPLOY.md`
记的"当前实现不支持安全轮转"这个既有缺陷。

按部署阶段拆开：

#### 3c-1A：verifier-first

全部验证方先支持：`kid → {family, alg, key}` 的固定 allowlist；每个 family
`current` + `previous` 两把；**legacy（无 `kid`）token 的显式临时入口**；
**signer 保持不变**。

部署次序：先 auth / panel，**再部署 Edge 并独立确认全球关联版本已生效**。

#### 3c-1B：signer adoption

仍是 HS256，但签发端开始写固定 `kid`：auth 签站点会话、auth 签升级码、panel 签面板会话。

**完成后必须做至少一次真实 HS256 轮转演练**：

1. verifier 同时接受 old / new；
2. signer 从 old 切到 new；
3. **把 signer 回滚到 old 仍然可用**；
4. 等过最长 token TTL；
5. 移除 old；
6. 缺失 / 未知的 old `kid` 开始被拒绝。

> **这一段是这次设计里被外部复审纠正过的一处，记下来**：我原先说"第一包完全不动签名侧
> 就已经修复安全轮转"。**那是错的**——纯 verifier 改动只让轮转**成为可能**，没有证明真实
> 签发链能安全切换。所以 3c-1 不能停在 verifier-only。

### 3c-1 的 legacy 状态机（**这是可执行协议，不是描述**）

外部复审 P1-3 指出：原文只写了"verifier 接受无 `kid`、signer 开始写 `kid`、最后拒旧"，
**不足以让实施者写出唯一的实现**——至少六个点没定义（legacy 算不算某个 family 的
`previous`、第一次写 `kid` 时用旧共享 secret 还是立刻切两把新的、legacy token 的旧 claims
怎么验、新旧 `token_use`/`aud` 并存还是二选一、"未知旧 `kid` 被拒"与"legacy 根本没有
`kid`"什么关系、三条接受路径同时在场时到底是两把还是三条）。成立。定义如下：

| 状态 | verifier 接受 | signer 发什么 | 退出条件 |
|---|---|---|---|
| **L0** | 只有 legacy（无 `kid`，旧共享 secret，旧 `typ`/`scope` 合同） | legacy | 现状 |
| **L1** | legacy **＋** `site-hs-v1` **＋** `console-hs-v1` | **仍发 legacy**（signer 不动） | Edge 全球关联版本已确认生效 |
| **L2** | 同 L1 | 全部改发 family-specific `v1`（带 `kid`、新 `token_use`+`aud`） | 观测到 `accepted_legacy == 0` 且总量非 0，持续 > 最长 TTL |
| **L3** | 只有两个 family 的 `v1` | family `v1` | **进入** = legacy 入口**关闭**（三处 verifier `LEGACY_ENTRY=off` 且 Edge 已 Deployed，1B 内，§11.8.1）；**退出** = 3c-3 完成代码路径与旧参数的**删除** |
| **R1/R2** | family 内 `current`+`previous`（`v1`→`v2`） | 切 `v2`，可回滚回 `v1` | 真正的轮转演练，见下 |

> **1B 之后的现状（2026-09-05，生产实况）**：状态机停在 **L3**，且 R1/R2 已经跑完一轮——
> 两个 family 的 `current` 都是 `*-hs-v2`，`previous` 两槽**为空**，v1 的两把 SSM 参数已删除
> （不可逆）。所以今天的接受集合是「每 family 一把 v2」，**既没有 legacy 入口，也没有
> `previous`**；下一次轮转从 ⑥（新 key 经 `previous` 就位）重新进入这张表。
> L3 的**退出**仍归 3c-3：legacy 的代码路径、`legacy_param` 那条配置行与旧参数的删除都还没做，
> 精确清单见 §6.2 的 3c-3 一节。

**关键定义，逐条回答那六个点**：

1. **legacy 是 family 外的第三条入口**，不是任何 family 的 `previous`。理由：它用的是
   旧共享 secret（跨 family），把它塞进某个 family 的 `previous` 会让"每 family 最多两把"
   这条不变量在语义上撕裂，也会让 R1/R2 的轮转演练与"首次拆 family"混成一件事。
   ⇒ **接受路径在 L1/L2 期间是"2 + 1"：每 family 的 `current`（此时还没有 `previous`）
   加一条 legacy 入口。**
2. **L1 不动 signer**（这是 verifier-first 的定义）。**L2 一次性切到两把新的 HS secret**，
   不存在"带 `kid` 但仍用旧共享 secret"的中间态——那种中间态会让"`kid` → key"的映射
   在同一个 `kid` 下指向两把不同的 key，是后面所有推理的地基裂缝。
3. **legacy token 按旧合同验**（`site`：`typ=session` 且无 `scope`；`console-session`：
   `typ=session` + `scope=console`；`upgrade`：`typ=console-upgrade`），**且只在 legacy
   入口里这么验**。新入口**只**认 `token_use`+`aud`，不接受旧 `typ`/`scope`。
4. ⇒ **新旧合同并存，但按入口二分，不在同一条路径里混判。** 这样"哪条路放行了它"
   在观测里是可区分的（`accepted_legacy` vs `accepted_current`）。
5. **"未知 `kid` 被拒"与 legacy 无关**：有 `kid` 但不在本 verifier 的 allowlist ⇒ 直接拒，
   **不回落到 legacy 入口**。回落会让攻击者用一个乱写的 `kid` 把验证降级到旧合同。
   legacy 入口的进入条件是**根本没有 `kid`**，且在 L3 之后该条件直接拒。
6. **L3 之后才允许开始 R1**：先把"首次从共享 key 拆成两个 family"做完、观测归零，
   再做 family 内部的 `v1`→`v2` 轮转演练。**两件事分开**，否则 3c-1 把"拆 family"与
   "常规轮转"压成一次演练，实施者会有多种合理但互不兼容的解释。

### 3c-2A：闸门与验收先认 KMS（**不动生产签名**）

这一包**只改观测方**：闸门加 KMS 探测（`kms:Sign` / `kms:PutKeyPolicy` /
`kms:CreateGrant` 的持有者、key policy 快照、grants、公钥指纹），四个 `verify_*` 与
E2E 的登录态获取方式按 §11.7 改造（auth 的 `/fixture-session` + `site-builder-verifier` 角色 +
常驻夹具站点）。**本包自己要先验过红绿**——
新探测必须能真的红，否则 3c-2B 上线后基线只会显示一个很大的"改善"，而真正要盯的那一面
根本没被测量（闸门今天明确"不看 KMS grants"）。

`replace-platform-code` 重建成完整链（§1 的顺带发现）也在这一包，理由见 §10。

### 3c-2B：两把 KMS 非对称 CMK

把新的 asymmetric `kid` 加为 `current`、旧 HS256 作为 `previous`；signer 切 `kms:Sign`；
verifier 双接受。key policy 按 §11.2（默认策略 + IAM 条件），CMK 由 deployer 的 CDK 栈创建；
`kms:Sign` 输入按 §11.5；kid 绑定按 §11.6。**前置条件是 3c-2A 已上线**，见 §6.1。

### 3c-3：清理与闸门

**这一包只做清理与结算，不新增观测能力**——闸门的 KMS 探测、`replace-platform-code`
重建、验收入口改造全部在 **3c-2A**（§6.1）。放到这里就等于整个迁移期间没有新观测。

- 退役 HS256；删除旧 SSM secret；删除 legacy 入口（状态机 L3）；
- 确认 Edge asset 不再含活的对称签名密钥；
- **基线做 schema 迁移 + 精确 delta，不是"全部重置"**（外部复审 P1-1，成立）。
  我原先引 `account-trust-boundary.md` 那句"迁移后基线应当重置"来支持全量重置——
  **引错了节**：那句在 **A（迁独立成员账号）= §9 的 3d** 一节里，不在 B（非对称签名）。
  3c 要做的是：保留 B 的 IAM 文本快照、resource policies、coverage、站点形状等**不相关
  层**；**精确断言** HS 读取类 grant 与 facts 的退出；**精确吸收**新增的 KMS policy /
  grant / 公钥指纹 facts；**任何无关变化继续红**。
  全量重置会把同一窗口里无关的 IAM 漂移一起合法化——那等于用一次迁移把闸门清零。

#### 3c-1B 留给 3c-3 的精确清单（2026-09-05 按源码点清，收尾时写下）

L3 只**关闭**了入口，下面这些**都还在**。删的时候按这张表逐项核对，删完 legacy 这个词
应当只出现在历史记录里。**顺序**：先删代码路径与配置行、再跑闸门第二次 `--retire-key legacy`、
最后删 SSM 参数（与 ⑩ 删 v1 参数同一形状：不可逆，单独确认）。

| 类别 | 精确对象 |
|---|---|
| **verifier 的 legacy 分支** | `auth/session.py` 的 `verify_with_legacy` / `verify_session_jwt` / `verify_upgrade_code`；`router/…/origin_request.py` 的 `_verify_legacy_site_session` 与 `LEGACY_ENTRY` 注入点及其分支；`panel/console_session.py` 的 legacy 分支；`auth/verifier_env.py` 的 `legacy_secret()`（**只有这一个在 verifier_env 里**）|
| **配置加载器里的 legacy 语义** | `auth/session_keys.py`：`legacy_entry()`（`:190`，三个消费方是 `deploy_auth.py` / `deploy_panel.py` / `router/infrastructure/stack.py`）、`legacy_param` 的解析与"允许为空 = L3"那段语义、`ssm_parameter_names()` 里产出 legacy 参数的分支、以及**硬拒 `signer=legacy` + 空 `legacy_param`** 那条组合校验（删 legacy 之后 `signer` 只剩一个合法值，这条校验与 `signer` 开关本身一起消失）|
| **signer 的 legacy 分支** | `auth/session.py` 的 `mint_session_jwt` / `mint_upgrade_code`；`login_handler.py` 与 `panel/console_session.py` 里 `signer == "legacy"` 那一侧（连同 `test_signer_switch_guard.py` 要求"两侧都在"的那条正对照——删 legacy 侧时这条断言要一起改，否则它会红） |
| **密钥取值路径** | `login_handler._secret("JWT_SECRET")` 这条 `{name}_PARAM` 用法；`deploy_auth` / `deploy_panel` 下发的 `JWT_SECRET_PARAM` 与角色 SSM 清单里那一项（**panel 的写前核对清单含它、auth 的不含**，见 `docs/adr/0004-*.md`）；`router/infrastructure/stack.py` 的 `load_jwt_secret()` 与 `{{JWT_SECRET}}` 注入点 |
| **SSM 参数本体** | `/site-builder/jwt-secret`（**删它才让 A 组的"可读密钥"真正少一把**；`facts.edge_code_targets_carrying_live_key` 与 `edge_assets_carrying_live_key` 也要到这一步之后才可能归零——历史 Edge 版本与 bootstrap asset 里的副本随版本过期而消失） |
| **闸门常量与第二次声明** | `scripts/verify_account_trust_boundary.py` 的 `JWT_PARAM_NAME` 常量、`LABEL_LEGACY` 与它映到的 `read-jwt-param` grant、`jwt_parameter` 那条 fact；**`--retire-key legacy` 的第二次使用**（第一次是 ⑤ 收 grant，这一次是删参数本体）|
| **配置与文档** | `config.ini.example` 里 `[SessionKeys]` 的 `legacy_param` 键及其上方那段"清空本行即关闭 legacy 入口"的说明（**按键名找，别按行号**——行号会随文件增删漂移）、`signer` 说明里"legacy / current 两个合法取值"的措辞；`site-builder/DEPLOY.md` 十步 runbook 的 ①–⑤ 一段（那是"legacy 入口的一次性收敛"，届时整段成为历史）；根 `CLAUDE.md` 里"legacy 共享密钥待 3c-3 删除"那句 |
| **验收脚本** | `verify_deployed_components.py` / `verify_deployed_edge.sh` 里断言"legacy 为空串 / 开关 off"的那些格子——它们在参数删除后要改成断言"根本不存在" |
| **3c-1B-G 复审留下的迁移期残留** | `scripts/verify_account_trust_boundary.py`：`undecided_item_fp` / `undecided_members_v4` / bundle 里的 `coverage.schema4_fingerprints` / `_compare_coverage` 的 v4 分支 / `--migrate-from-schema` 的 3、4→5 通道（基线已是 schema 5，这些只为那一次迁移保留；删时连 `BUNDLE_SHAPE` 与 `_complete_bundle` 里的那个键一起删）；`router/infrastructure/stack.py` 的 `_session_keys_on_path()`：`site-builder/auth` 常驻 `sys.path[0]`（3c-1B-G 只做了幂等去重，没改成像 `_edge_placeholder_re` 那样按路径加载——三处 `from session_keys import …` 依赖它） |

---

## 7. 部署与回滚协议

1. **verifier-first**：所有验证方先能接受新形态；
2. **独立证据证明 Edge 全球部署完成**（不是"CDK 说部署好了"）；
3. 才允许 signer 开始发新 `kid`；
4. **回滚只回 signer，verifier 保持双接受**；
5. 等过最长 TTL 再退役旧 key：

   | token | TTL |
   |---|---|
   | 站点会话 | 24h |
   | 面板会话 | 4h |
   | 升级码 | 60s |

   **再加余量**：auth 的 secret 缓存最长 5 分钟（`SECRET_TTL_SECONDS`）、Edge 全球复制
   10–20 分钟。
6. 最后退役 `previous` / legacy 入口。

**为什么次序不能反**（DEPLOY.md 已记的实测症状）：auth 读 SSM 最长 5 分钟切换，
Edge 要重新部署并等 10–20 分钟全球复制。signer 先切的话，新签发的 cookie 在尚未更新的
边缘节点验签失败——用户登录后立刻被踢回登录页，而已登录用户的旧 cookie 在旧节点上仍有效，
于是同一时刻不同地区表现不一致，**症状与"密钥读取失败"完全一样，极难定位到密钥版本**。

> 注意这与 CLAUDE.md 不变量里那条"auth 先于 router"**方向相反**：那条讲的是**新建部署**
> 的依赖（② 的栈部署时要从 SSM 读 jwt-secret）；而**切换**必须 verifier 先行。
> 两条都对，适用阶段不同——实现时必须在 DEPLOY.md 里把这个区别写清楚，否则照抄不变量
> 就会把顺序做反。
>
> **3c-2B 另有一条新建依赖**：CMK 在 deployer 的 CDK 栈里（§11.2），所以那一包里 deployer 栈
> 先于 auth 的 signer 切换。（2026-09-02 grill 核对：deployer 栈与 `deployer/functions` 今天
> **不读** jwt-secret，此前写的"3c-3 删掉 deployer 栈对 jwt-secret 的 SSM 读取"一句作废；legacy
> 密钥的消费方只有三处 verifier 与验收工具，见 §11.8.1。）

---

## 8. 观测

**不记录 token。** 只记固定、低基数的结果计数：

```
accepted_current   accepted_previous   accepted_legacy
unknown_kid        alg_mismatch        wrong_audience
wrong_token_use    bad_signature       expired
```

**退役条件是可观测的、不是估计的**：只有 `accepted_legacy == 0` 持续超过最长 TTL，
才允许删除 legacy 入口。

（埋点异常一律吞掉——统计不是安全控制。但这意味着丢行是无声的，所以退役判据不能只看
"计数是 0"，还要看**总量非 0**，即那条埋点确实在工作。）

---

## 9. 失败面与必须存在的反例

### `kid` 解析

- 未知 `kid`；
- 缺失 `kid`；
- JSON 里**重复的** `kid` 键；
- `kid` 对、`alg` 错；
- `alg=none`（以及 `None` / `NONE` / 大小写变形）；
- **site 的 `kid` 投给 panel**；
- **console 的 `kid` 投给 Edge**；
- `current` / `previous` 之外的第三把 key；
- **legacy 入口在截止时间之后仍被接受**。

### 用途与受众

- `token_use` 不匹配；`aud` 不匹配；
- 升级码当面板会话用、面板会话当站点会话用（M05 那一类的完整矩阵）；
- 只靠 cookie 名或 `__Host-` 前缀就放行。

### 跨组件

- auth 签出来的 token 必须能过 Edge 的 verifier（**正向**跨组件向量——只有负向用例时，
  把 signer 的 `token_use` 改个字而 verifier 仍查旧值，全部负向用例照样绿，
  而线上所有会话失效。今天这条向量在 `test_edge_auth.py:611` 已经存在，迁移时要按新模型
  重写而不是删掉）。

---

## 10. 闸门与守卫要改什么

**不一起改就会假绿或部署不出去。** **每一行的"什么时候改"一律以 §6.1 的
change-impact matrix 为准**，本节只说"改什么"，不重复时序（上一轮就是因为这里另写了
一套时序而与 §6 矛盾）。

| 对象 | 要改什么 | 属于哪个包（§6.1） |
|---|---|---|
| `verify_account_trust_boundary.py`（HS 侧） | `JWT_PARAM_NAME` 变成**两个 HS key family** + legacy/current/previous；产物里定位密钥的正则要能同时找多把 | 3c-1A |
| `verify_account_trust_boundary.py`（login-flow secret） | 读取者记为 grant `read-login-flow-secret`，**不进** `is_secret_grant()`（不算冒充面）；Edge 产物含其值即红（硬断言，不落 facts）；**schema 留 4**（§11.8.7） | 3c-1B |
| `verify_account_trust_boundary.py`（迁移桶） | `--new-kid` 泛化为 `--new-key LABEL` / `--retire-key LABEL`，LABEL ∈ kid ∪ {legacy, login-flow}；平台角色**丢**被声明的 grant 算迁移不算红；`legacy_param` 为空时仍按 `JWT_PARAM_NAME` 追踪 legacy 参数直到 3c-3（§11.8.7） | 3c-1B |
| `router/infrastructure/stack.py`（legacy 注入） | `load_jwt_secret()` 改从 `[SessionKeys] legacy_param` 取路径，不再硬编码；为空时 `{{JWT_SECRET}}` 注入空串、`LEGACY_ENTRY=off`（§11.8.1） | 3c-1B |
| `deploy_auth.py` / `deploy_panel.py`（signer 开关） | 下发 `SESSION_SIGNER`；先 `update_function_configuration` 再 `update_function_code`；第一次写之前 `GetParameter` 核对本组件每个 HS 参数存在（§11.8.3、§11.8.12） | 3c-1B |
| `scripts/_session_mint.py`（新）+ 四个 `verify_*` + `verify_kid_entry_live.py` + `test_e2e_fixtures.py` | 六处本地 mint 收成一个模块、改用 `session.mint_token` 发新形态；`verify_kid_entry_live.py` 加 `--role` / `--retired-token`（§11.8.4、§11.8.11） | 3c-1B（2A 换成夹具签发器） |
| `auth/tests/test_signer_untouched_in_1a.py` | 删除；替换为"handler 只经 signer 助手签发、legacy mint 只在开关=legacy 分支"的 AST 守卫 + auth→Edge **新形态**正向向量（§9 今天只有 legacy 形态那条） | 3c-1B |
| `site-builder/DEPLOY.md`「轮转 jwt-secret」节 | 改写成 §11.8.9 的十步 runbook（本次演练即首次执行） | 3c-1B |
| `verify_account_trust_boundary.py`（KMS 侧） | **新增 KMS 探测**：`kms:Sign` / `kms:PutKeyPolicy` / `kms:CreateGrant` 持有者、key policy 快照、grants、公钥指纹 | 3c-2A |
| `verify_account_trust_boundary.py`（`replace-platform-code`） | 重建成**完整链**（动作等价类 × 资源等价类），判据与 `scripts/probe_impersonation_surface.py` 的 `classify()` 一致 | 3c-2A（**但它是当前基线的一处低估，与 3c 是否做无关，可提前单独修**） |
| `verify_account_trust_boundary.py`（基线） | **schema 迁移 + 精确 delta，不是全部重置**——理由见 §6.2 的 3c-3 一节 | 3c-3 |
| `verify_deployed_edge.sh` | 它按源码字面量 grep 产物里的 `typ` 检查；验签函数重写后那条 regex 必失配 | 3c-1A |
| `verify_console_e2e.py` / `verify_api_key_e2e.py` / `verify_analytics_e2e.py` / `verify_session_token_semantics.py` | **四个都靠"读 SSM 明文 → 本地 mint 会话"免掉人工登录**。非对称化后本地拿不到私钥 ⇒ **这四个闸门的登录态获取方式按 §11.7 重做**：assume `site-builder-verifier` → auth `/fixture-session` 取夹具域 `sb_session` → 其余 token 走真实换取链路；`verify_session_token_semantics.py` 改打常驻夹具站点。**不要写成"给验收角色一条受限的 `kms:Sign`"——`kms:Sign` 不限制 claims，那本身就是一个新的冒充 principal。** 这条影响的正是"我们用来验证一切的东西" | 3c-2A |
| `deployer/tests/test_e2e_fixtures.py` | 同上（10 条 E2E 的登录态全靠它） | 3c-2A |
| `test_edge_auth.py` / `test_origin_request.py` / `test_edge_access_log.py` | 占位符替换表、手搓 HMAC 的用例、跨组件向量、签名形状断言 | 3c-1A（HS 形态）→ 3c-2B（RS 形态） |
| auth / panel 的测试 | `test_session.py`、`test_upgrade_code.py`、`test_console_session.py`、`test_deploy_panel_contract.py`（"SSM 资源必须是精确 jwt-secret ARN"）等 | 3c-1A/1B → 3c-2B |
| `verify_deployed_components.py` | "环境变量不得有明文密钥"那两处检查；新增线上产物 / `config.ini` / KMS 的三方指纹对账（§11.6） | 3c-2B |
| `deploy_auth.py` | `/fixture-session` 与 verifier 的**两条** Function URL 语句（受 `[Verification]` 开关）、login-flow secret 的 `ensure_secret`、RS `kid` 的部署前四项校验、identity policy 的 `kms:Sign` 条件 + `kms:GetPublicKey` | 3c-1B（secret）→ 3c-2A（fixture）→ 3c-2B（校验） |
| `deploy_panel.py` / `router/infrastructure/stack.py` | 各自 family 的 `[SessionKeys]` 读取与部署前校验；stack.py 另加 Edge 的 pip 交叉装法与 `requirements-edge.txt`（§11.1） | 3c-1A → 3c-2B |
| `deployer/infra/app.py` | 两个 `kms.Key`（`RSA_2048` / `SIGN_VERIFY` / RETAIN）+ `CfnOutput`；`test_infra_tables.py` 断言 KeySpec / KeyUsage / RETAIN | 3c-2B |
| `scripts/ensure_fixture_site.py`（新） | 幂等创建常驻夹具站点（static、`require_auth=True`、只允许 `probe@e2e.invalid`） | 3c-2A |
| `scripts/probe_impersonation_surface.py` | 新标签 `sign:fixture-issuer`，**两个入口**（verifier 角色经 URL；对 auth 函数的直接 `lambda:InvokeFunction`），`--self-test` 加对应反例 | 3c-2A |
| `origin_request.py`（夹具分支） | `auth_via = fixture-issuer` 的会话只在 owner 属夹具域的路由上判定，其它路由 302；反例：夹具会话投给真实 org 站点必须 302 | 3c-final（与签发器**同一次部署**，不得晚于它；原写"先于、3c-2A"） |
| `permissions.py` / `deploy_panel.py` | 拒绝把夹具域邮箱写进非夹具站点的权限字段；admin 名单排除夹具域（三个产物重部，见跨组件矩阵） | 3c-2A |
| `site-builder/config.ini.example` / `router/config.ini.example` | `[SessionKeys]` + `[SessionKey:<kid>]` + `[Verification]` 的占位形态 | 3c-1A |

**文档**（都是状态真源）：`CLAUDE.md`（不变量 §"auth/session 与 Edge verifier 是同一契约"
+ 开头"三条仍然成立的边界"）、`site-builder/DEPLOY.md`（轮转整节 + 依赖关系 + §7 那条
"新建部署 vs 切换"的方向差别）、`docs/security/account-trust-boundary.md`（结论真源与
基线数字）、merged review §9 的 3c、`router/config.ini.example`。

---

## 11. 3c-0 裁定（原"未决项"，2026-09-02 逐条定稿）

七条全部裁定，含 §11.1 的冷启动实测。术语按根 `CONTEXT.md`；
§11.2、§11.7、§11.1 另立 ADR（`docs/adr/0001`、`0002`、`0003`）。**§11.8 是 3c-1B 的裁定**
（2026-09-02 grill，同一形态：判据 + 被否决项）。**判据与被否决的选项都留在这里**，
以后有人想"顺手改回去"时先读这一节。

### 11.1 Edge 的 RS256 验签：vendored `cryptography`，以冷启动 spike 为闸

**裁定（2026-09-02 最终形态复测后定稿）：vendored `cryptography`（与 auth / MCP 锁定清单里同一个
`cryptography==50.0.0`，hash 钉死）；Edge 内存维持 128 MB。**

**判据（Codex 复审后重述）**：在与 Edge 相同的 python3.11 / x86_64 上，vendored 版相对 stdlib-only 版
**新增的冷路径总时延**（`Init Duration` 差 **加** 冷调用 handler `Duration` 差）中位数 ≤ 300 ms 且
p95 ≤ 600 ms；**被测函数必须是最终实现形态**：公钥在模块顶层加载并在 import 时预热一次验签，
handler 里只做验签。128 MB 不达标而 256 MB 达标时接受上调 `router/config.ini` 的 `memory_size`
（7 个活跃站点的流量下成本可忽略）；256 MB 仍不达标才转纯 Python（§5 RSA 原语层的条款随之成为
交付物）。

**第一轮 spike 的判读作废**：那一轮只按 `Init` 差判、且 PEM 解析放在 handler 里。按总时延重算，
128 MB 的中位数差是 **300.14 ms**（Init +130.6 加 handler +169.4），正压在闸上，"4 倍余量"不成立；
256 MB 约 205 ms。数字保留在 §12 作对照。复测的假设：Init 阶段有 CPU 加速而 handler 阶段按内存
配比 CPU（同一份 vendored 代码 Init 在两档内存下都是 211 ms，handler 却是 170 对 75 ms），所以把
解析与预热搬进模块顶层应当让 128 MB 的总差明显下降。**复测证实了这个假设，见下面的数字。**

**为什么不是纯 Python 优先**：平台的 signer（auth）已经信任 `cryptography`，"新增供应链依赖"只对
Edge 这一个部署单元成立；而 §5 RSA 原语层那一整套陷阱是**我们自己永久背的审计面**。真正未知的
只有冷启动，所以只让冷启动来裁。ADR：`docs/adr/0003-edge-verifier-vendored-cryptography.md`。

**打包方式**：不引 Docker。复用 `deploy_auth.py` 那条
`pip install --require-hashes --platform manylinux2014_x86_64 --only-binary :all:` 交叉装法
（改 `--python-version 3.11`），在 CDK synth 时装进 Edge 的 temp_dir；锁定清单
`router/infrastructure/lambda/requirements-edge.txt`；`auth/tests/test_requirements_locked.py`
的 AST 守卫扩到 `router/infrastructure/stack.py`。3c-2B 的 Edge 单测另断言 handler 路径里没有
`load_pem_public_key` 调用（解析必须在模块顶层）。

**复测要求**（脚本 `site-builder/scripts/spike_edge_crypto_coldstart.py`，按 Codex P2 修过：不复用
已存在的函数、依赖用带 hash 的锁定清单装、cleanup 失败非零退出）：stdlib / vendored 两臂 ×
128 / 256 MB，每配置 20 次冷启动，每次冷启动后再 3 次热调用；报告 Init 差、首次调用差、总差、
热调用验签中位数。原始输出在 gitignored 的 `docs/design/3c-spike/`。

**复测结果（2026-09-02，最终形态；每配置 20 次冷启动 + 60 次热调用；原始输出
`docs/design/3c-spike/edge-crypto-coldstart-20260902T102034Z.json`）**：

| 配置 | Init 中位数 | Init p95 | 首次调用中位数 | 冷路径总计中位数 | 总计 p95 | 热调用中位数 | Max Memory |
|---|---|---|---|---|---|---|---|
| stdlib @ 128 MB | 81.3 ms | 86.7 ms | 1.3 ms | 82.6 ms | 88.1 ms | 1.06 ms | 38 MB |
| vendored @ 128 MB | 224.6 ms | 233.6 ms | 1.4 ms | 225.9 ms | 235.2 ms | 1.18 ms | 55 MB |
| stdlib @ 256 MB | 81.3 ms | 85.0 ms | 1.3 ms | 82.6 ms | 86.4 ms | 1.06 ms | 38 MB |
| vendored @ 256 MB | 227.0 ms | 235.2 ms | 1.4 ms | 228.3 ms | 236.7 ms | 1.19 ms | 55 MB |

冷路径总差（vendored 减 stdlib）：**128 MB 中位数 +143.3 ms / p95 +147.1 ms**（配对差 +143.0 / +153.3）；
256 MB +145.7 / +150.3。闸 300 / 600 ⇒ **两档都通过，中位数约 2 倍余量、p95 约 4 倍**；内存对结果无
影响，所以 Edge 维持 128 MB。首次调用差归零（0.0 / 0.1 ms）：把解析与预热搬进模块顶层后，第一轮里
那 170 ms 的 handler 开销消失，总差从 300 降到 143，证实了上面的 Init 阶段 CPU 假设。**热调用验签
增量 0.12 ms**（359 字节 signing input 的 RSA-2048 PKCS1 v1.5 验签），每请求预算可以忽略。包：压缩
4.93 MB / 解压 15.8 MB / 172 个文件；wheel cryptography 50.0.0、cffi 2.1.1、pycparser 3.0，锁定清单
`site-builder/scripts/spike_edge_crypto_requirements.txt`（带 sha256；装的时候不加 `--no-deps`，
所以 pip 同时证明依赖闭包完整）。资源全部删除并二次核实。

### 11.2 KMS key policy：默认（root 委派），不做限制性策略

**裁定**：两把 CMK 用默认 key policy；`kms:Sign` 只经 IAM identity policy 授给 auth role
（两把）与 panel role（console 一把），并带两个条件：
`kms:SigningAlgorithm = RSASSA_PKCS1_V1_5_SHA_256`、`kms:MessageType = RAW`（把 §11.5 的
合同钉进 IAM，零自锁风险）；**同一条 identity policy 还要授 `kms:GetPublicKey`**（§11.6 的运行时指纹
自检要用；公钥不是秘密，但漏了就是冷启动 AccessDenied，Codex 复审指出上一稿只写了 `kms:Sign`），
`deploy_auth.py` / `deploy_panel.py` 的合同测试按精确 key ARN 断言这两个动作。不设破窗 principal。闸门（3c-2A）把 `kms:Sign` /
`kms:PutKeyPolicy` / `kms:CreateGrant` 持有者与 key policy 快照记成静态基线。

**判据**：§1 量出限制性 key policy 只减 1 个 principal，且结构上收不掉"劫持 signer"那条路
（恶意代码以 signer 角色身份调 KMS，key policy 必须放行它）；换来的是自锁风险加一个必须
纳入 A 组枚举的破窗 principal。ADR：`docs/adr/0001-session-key-default-kms-key-policy.md`。

**CMK 由谁创建**：deployer 的 CDK 栈（`deployer/infra/app.py`），`kms.Key`
`RSA_2048` / `SIGN_VERIFY` / `enable_key_rotation=False` / `RemovalPolicy.RETAIN`，
`CfnOutput` 输出 ARN，由人回填 `[SessionKeys]`（§11.6）；轮转到 v2 = 加一个新 construct。
SPKI 指纹 CFN 给不出，由 `deploy_auth.py` 部署时 `GetPublicKey` 算出并与配置比对。
**部署依赖随之变化**：3c-2B 里 deployer 栈先于 auth 的 signer 切换，写进 DEPLOY.md。（原文
"3c-3 删掉 deployer 栈对 jwt-secret 的读取"一句已作废，deployer 今天不读它，见 §7 注与 §11.8.1。）

### 11.3 登录流程 HMAC 密钥（state 与 PKCE cookie）：独立的 login-flow secret，归 3c-1B

**实况**：`_login_flow_sig` 不只签 OAuth state，也签 `__Host-sb_pkce` cookie
（`login_handler.py:142-157`，带 `"t":"pkce"` 类型标记），两者 TTL 都是 300 s。

**裁定**：3c-1B 起（signer 离开共享密钥的同一刻）改用一把 **auth 私有**的 SSM SecureString
`/site-builder/login-flow-secret`（env `LOGIN_FLOW_SECRET_PARAM`，`deploy_auth.py` 的
`ensure_secret` 生成）。它**不属于任何 key family、没有 `kid`**；轮转就是覆盖参数值，代价
是 auth 5 分钟缓存窗口内进行中的登录失败一次。闸门把它列为"可读密钥"事实但**归类为非会话
签名**（读到只值一个登录 CSRF）。

**否决**：借 `site-hs-v1` 到 3c-3 再迁（二次迁移）；去掉 HMAC 改随机 state 存 cookie
（丢掉 pkce cookie 的类型标记防线，改动面反而更大）。

### 11.4 `token_use` / `aud` / `kid` 字面量：按 §4.2 定稿

- `token_use` 三个值与 `aud` 三个值就是 §4.2 表里那六个；`aud` 是**单个字符串**，数组直接拒。
- 新 token 的 header 带 `kid`；payload 的 claim 集合**按三类 token 分别定义**（Codex 复审：上一稿
  一句"只带……"漏了升级码的 `jti`，那会拆掉 panel 的原子消费与并发重放保护）：

  | token | payload claims |
  |---|---|
  | 站点会话 | `token_use`、`aud`、`email`、`name`、`idp`、`auth_via`、`exp`、`iat` |
  | 升级码 | `token_use`、`aud`、`email`、**`jti`**（panel 条件写 session-codes 表原子消费，今天就有）、`exp`、`iat` |
  | 面板会话 | `token_use`、`aud`、`email`、`name`、`exp`、`iat` |

  三类都**不再写 `typ`（payload）与 `scope`**。新入口忽略未知 claim，但反例必须证明只带
  `typ=session` 过不了新入口，且缺 `jti` 的升级码必须被拒。
- `kid` 格式 `{family}-{alg}-v{n}`：`site-hs-v1` / `console-hs-v1` / `site-rs-v1` /
  `console-rs-v1`。verifier 把它当不透明字符串查 allowlist，**不解析**。
- `name` 在 mint 时截到 256 字符（`name` 来自 IdP、今天不限长，配合 §11.5 的长度闸）。
- `token_use` 与同一个 handler 里 Cognito token 的 `token_use`（`id` / `access`）同名：两类
  token 由不同的 allowlist 验，不会互相通过；保留同名是因为它就是 Cognito 的约定叫法。

### 11.5 `kms:Sign` 输入合同：`RAW`

**裁定**：`MessageType=RAW`，`Message` = JWS signing input 的 ASCII 字节，
`SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`；signer 侧**任何地方不做本地哈希**；mint 前
硬检查 `len(signing_input) ≤ 4096`，不满足直接拒（今天约 350 字节，只有 `name` 失控才会碰到）。

**为什么**：PKCS1 v1.5 是确定性签名，`RAW` 与正确实现的 `DIGEST` 产出**同一个**签名，
跨组件测试向量不受影响；选 `RAW` 是为了把"双哈希"这一类错误从结构上消灭（KMS 文档原话：
拿摘要走 `RAW` 会被再哈希一次，验签方按单哈希算就失败）。

**测试向量**：用本地一次性 RSA 密钥生成 tracked 的黄金三元组（signing input、SPKI、
signature）给各 verifier 单测；"KMS 输出 == 本地 `cryptography` 输出"这条 parity 放 3c-2A
的真机验收。

### 11.6 `kid` 与 KMS key 的绑定：住在 `config.ini`，三个部署脚本校验，signer 每次断言

**裁定**：指纹是每个部署账号各自的值，写进 tracked 代码会把仓库绑死到一个账号；所以绑定
住在 `site-builder/config.ini`（新增段，HS 与 RS 两阶段共用，**3c-1A 就按此 schema 落地**）：

```ini
[SessionKeys]
site_current = site-rs-v1
site_previous = site-hs-v1
console_current = console-rs-v1
console_previous = console-hs-v1
login_flow_secret_param = /site-builder/login-flow-secret

[SessionKey:site-hs-v1]
alg = HS256
ssm_param = /site-builder/session-keys/site-hs-v1

[SessionKey:site-rs-v1]
alg = RS256
key_arn = arn:aws:kms:us-east-1:<acct>:key/<uuid>
spki_sha256 = <hex>
```

router 只读 site family、panel 只读 console family、auth 读两个 family 加 login-flow；
`previous` 可以为空；`config.ini.example` 同步占位形态。

**校验分三层**：
1. **部署前**：auth / panel / router 三个部署脚本对每个 RS `kid` 做 `DescribeKey` +
   `GetPublicKey`，`KeySpec=RSA_2048`、`KeyUsage=SIGN_VERIFY`、`SigningAlgorithms` 含
   `RSASSA_PKCS1_V1_5_SHA_256`、SHA-256(SPKI) 等于 `spki_sha256`，四项任一不符**拒绝部署**。
   Edge asset 内嵌的就是这次拉取到的 PEM + kid + alg。
2. **运行时**：signer 每次 `Sign` 断言响应 `KeyId` 等于配置的 `key_arn`；容器冷启动做一次
   `GetPublicKey` 指纹自检，不符则拒签（fail closed）。
3. **事后**：`verify_deployed_components.py` 把线上产物、`config.ini`、KMS 三方对账。

`key_arn` 必须是带 UUID 的完整 ARN，**代码永不引用 alias**（可以给 key 建人读 alias，只为
控制台可读）。否决"kid = JWK thumbprint"：日志里不可读，且状态机已经用标签。

### 11.7 验收身份：auth 内的受控签发（方案 ③）

**实况**：四个 `verify_*` 与 10 条 E2E 今天全靠"读 SSM 明文 → 本地 mint"，身份是随机后缀的
`@example.com`（两个例外：`verify_session_token_semantics.py` 冒充生产站点的**真实 owner**；
E2E 用 `e2e@test.com`，`test.com` 是真域名）。Cognito 原生登录流被 `deploy_pool.py` 设计性
禁用、Edge 拒 `TokenGeneration_Authentication`，所以方案 ①"真实登录"在本仓库等于每次人工
飞书扫码，无人值守闸门全部报废。方案 ② 给验收角色 `kms:Sign` 是一个**不受限**的新冒充
principal。

**裁定**：方案 ③，实现为 auth 上的 `POST /fixture-session`：
- 走现有 Function URL（AWS_IAM）。resource policy 只多**一个** principal：新建
  `site-builder-verifier` 角色，信任策略只列 `[Verification] verifier_trusted_principals`
  里的显式 ARN，会话上限 1 小时；给它的是**两条**语句（`lambda:InvokeFunctionUrl`，以及
  `lambda:InvokeFunction` 带 `InvokedViaFunctionUrl=true`，与 edge role 今天那两条同形，**缺一即 403**，
  CLAUDE.md 高频坑），只在 `[Verification] fixture_issuer = true` 时存在。**无该配置 = 路径 404、
  语句不存在**，与 ApiKey 组件同款"不存在"。
- auth 在应用层核对 `requestContext.authorizer.iam.userArn` 匹配
  `assumed-role/site-builder-verifier/*`，否则 403：Edge role 能调同一个 URL，必须在这里
  也拒掉它。**这道检查只挡经 Function URL 的调用**：直接 `lambda:InvokeFunction` 的调用方自己构造
  整个事件，`userArn` 可以伪造（`edge_caller.py` 的 Path A 实测过）。所以持 auth 函数
  `lambda:InvokeFunction` 的 principal 也能取得夹具会话，探针把这个入口一并建模进
  `sign:fixture-issuer`；它的危害上限由下面那条边界规则决定，不由这道检查决定。
- 只签 `token_use=site-session`；email 必须匹配夹具域 `e2e.invalid`（RFC 2606 保留域，
  `EMAIL_RE` 接受），该域是 **auth 代码里的常量**而不是配置项（授权边界该进 git review），
  闸门与 E2E 从 auth 导入同一个常量；TTL ≤ 30 分钟；`idp` 打 `fixture`、`auth_via` 打
  `fixture-issuer`，**不打真实 IdP 的值**。
- **夹具会话的边界由 Edge 与 panel 强制，不靠"只签夹具域"这句话**（Codex 复审：
  `allowed_users = "org"` 的站点放行任何 `idp` / `auth_via` 可信的邮箱，上一稿的夹具会话能进所有
  组织级站点）：Edge 在 idp / auth_via 检查处加一条分支，`auth_via = fixture-issuer` 的会话**只在
  owner 属于夹具域的路由上**按 allowed_users 正常判定（含 `org`），其它路由一律 302；真实的
  `TRUSTED_AUTH_SOURCES` 不变。panel 对夹具身份照常（它只能动自己拥有的夹具站点），但
  `deploy_panel.py` 断言 admin 名单里没有夹具域邮箱，`permissions.write_permissions` 拒绝把夹具域
  邮箱写进非夹具站点的 owner / collaborators / allowed_users。**夹具站点的标记就是 owner 的域**，
  `ensure_fixture_site.py` 与闸门"站点形状"层用同一条规则。反例：夹具会话投给真实 org 站点必须 302。
- **升级码与面板会话不另签**：拿夹具 `sb_session` 走真实的 `/console-session` →
  `/api/session-callback` 链路换取。于是带外签发的只有一种 token、一个域。
- 约束写在代码里，所以谁能改 auth 的代码谁就在面里，这正是把它挂在**已经是 signer** 的
  组件上而不新建组件的理由。探针加 `sign:fixture-issuer` 标签，A 组精确枚举
  `site-builder-verifier` 并注明"限夹具域"。

**代价两条**：`verify_session_token_semantics.py` 不能再冒充真实 owner，改打一个**常驻**
夹具站点（static、`require_auth=True`、`allowed_users` 只有 `probe@e2e.invalid`，由新脚本
`scripts/ensure_fixture_site.py` 幂等创建，作为部署验收的一步；探针保持只发 GET）；E2E 的
`e2e@test.com` 改成夹具域。sites 表里今天没有活着的夹具站点（107 条 DELETED 墓碑、7 条
ACTIVE 全是真实 owner）。那 107 条墓碑**不在 3c-0 处理**，另开数据卫生变更；闸门"站点形状"层
只统计 ACTIVE 行、按 owner 域识别夹具站点、不依赖总行数，为常驻夹具站点做一次精确 delta。
ADR：`docs/adr/0002-fixture-session-issuer-for-acceptance.md`。

**不能写成"给验收角色一条受限的 `kms:Sign`"**：`kms:Sign` 不限制 claims，那本身就是一个
新的冒充 principal。这句保留，防止以后有人把 ③ 又简化回 ②。

### 11.8 3c-1B 裁定（2026-09-02 grill 定稿）

范围：signer 切 `kid`、login-flow secret、观察归零后**关闭** legacy 入口（L3）、一次真实 HS 轮转
演练 R1/R2。术语按根 `CONTEXT.md`，本轮新增六条（legacy 入口的"关闭 vs 删除"、signer 开关、
观察窗口、就位、退役、`current`/`previous` 的槽位语义）。**不立 ADR**：十二条裁定都能靠改配置或
小回退撤回，三条判据都不满足。§6.1 的 1B 行、§6.2 的 L3 行、§7 注、§10 表已按本节做了最小交叉
引用修改，正文没有重写。

#### 11.8.1 1B 的终点是 L3（关闭），删除归 3c-3

**矛盾**：§6.1 把 L3 归 3c-3；状态机第 6 条要求 L3 之后才许 R1；§6.1/§6.2 又把 R1/R2 放进 1B。

**裁定**：把 L3 重定义为"三处 verifier 的 `LEGACY_ENTRY=off` 且 Edge 已 Deployed"，即 legacy 入口
**关闭**；代码路径与旧 SSM 参数的**删除**留 3c-3。实现形态就是清空 `[SessionKeys] legacy_param`：
`session_keys.py` 放开"3c-3 之前必填"；`deploy_auth`/`deploy_panel` 不再下发 `JWT_SECRET_PARAM`、
角色 SSM 精确清单不再含它；`stack.py` 的 `load_jwt_secret()` 改从 `legacy_param` 取路径（今天硬编码
`/site-builder/jwt-secret`，与唯一真源分叉），为空时给 `{{JWT_SECRET}}` 注入空串并下发
`LEGACY_ENTRY=off`。L3 因此有三个可量的闸门 delta：auth/panel 丢 `read-jwt-param`、Edge 产物的
legacy 计数归零、56 个宽读者对 jwt-secret 的读权限**不变**（参数到 3c-3 才删）。3c-3 只剩：删
`mint_session_jwt`/`verify_session_jwt`/`verify_with_legacy` 的 legacy 分支/Edge
`_verify_legacy_site_session`/`{{JWT_SECRET}}` 占位/`LEGACY_ENTRY` 变量、删参数、基线精确 delta。

**否决**：(b) 把 R1/R2 挪到 3c-3——2B 的 HS→RS 本身就是一次轮转，在它之前从未演练过 HS 轮转，
正是 §6.2 说的"verifier-only 不证明签发链能安全切换"那类假信心；(c) legacy 开着就演练——第 6 条
的理由（别把"拆 family"和"常规轮转"压成一次）仍成立。

**代价**：1B 的日历跨度 ≥ 3 天（切换 → 26 h+ 观察 → L3 → 演练含 24 h+ 排空）。
**核对过的事实**：deployer 栈、`deployer/functions`、key-proxy、MCP、`smoke_router.sh` 都不读
jwt-secret；legacy 密钥的消费方只有三处 verifier 与验收工具，切 L3 不影响部署链。

#### 11.8.2 观察窗口：不定固定天数，用 §8 的字面判据

legacy token 只在 T0（**两个** signer 都切完的时刻，取较晚者）之前签出，24 h 后全部过期；Edge 复制
与 auth 缓存与排空无关（verifier 早已双接受）。

**裁定**：不早于 T0+26 h 跑 `session_verify_counts.py --hours 26 --require-total`，三条同时成立才过：
三列 `accepted_legacy` 全 0；三列 `accepted_current` 全 > 0（新形态在流动）；每个 verifier 总量
> 0（`--require-total`）。实际落点在 26–52 h 之间，取决于最后一枚 legacy cookie 何时被用。两条
配套：判断前先把四个 `verify_*` 跑一遍，否则 panel 列可能因 26 h 无人用控制台而总量为 0；验收
工具必须在 T0 之前就改发新形态（§11.8.4），否则它们自己就是 `accepted_legacy` 的来源。L3 之后
零星的 `unknown_kid` 是过期 legacy cookie（无 `kid` ⇒ 不在 allowlist），属预期。

**否决**：固定 48 h——它只是 26 h 窗口的一个特例，且说不出"为什么是 48"。

#### 11.8.3 signer 切换是配置项：`[SessionKeys] signer = legacy | current`

**裁定**：一个全局开关，两个 family 同步；下发为 auth/panel 的环境变量 `SESSION_SIGNER`。校验住在
`session_keys.py`：`legacy` 要求 `legacy_param` 非空；`legacy_param` 为空（L3）要求 `current`。
取签发 key 的逻辑加在 `verifier_env.py`（`signing_key(family)` 返回 role=current 的 kid + secret；
**不改文件名**，避免同时动 `AUTH_PACKAGE_MODULES` 与 `COPY_FILES`）。回滚 = 改一行配置重跑两个部署
脚本，代码不变，不与同批的其它改动纠缠；`verify_deployed_components.py` 已按"env 整体 == 本地
推导"比对，开关自动入闸。3c-3 删 legacy 时连开关一起删。

**顺序**：panel 先、auth 后。面板会话只有 panel 自己验、TTL 4 h，是最小爆炸半径的先行指标；auth 一切
同时影响 Edge（站点会话）与 panel（升级码）。

**login-flow secret 单独一次部署，在 signer 切换之前**：它只影响 /login 的进行中登录（5 分钟窗口失败
一次），signer 只影响会话有效性；混在一次部署里会让 signer 回滚连带回滚它。

**部署脚本改成先 `update_function_configuration` 再 `update_function_code`**：1B 的两处 env 变化都是
新增变量（`LOGIN_FLOW_SECRET_PARAM`、`SESSION_SIGNER`），旧代码忽略新变量无害，而新代码缺新变量会
500 几秒；L3 删 `JWT_SECRET_PARAM` 时旧代码在那几秒里也不会碰它（signer 已是 current、legacy 分支只在
无 `kid` token 上走，届时都已过期）。

**不在生产演示 legacy 回滚**：回滚目标就是十分钟前还在跑的配置，同一个脚本同一条路；演示只会多签一批
legacy token、把观察窗口推后 24 小时。

**否决**：用 git 回退代替开关——回退会把同批的 login-flow 改动一起带回去。

#### 11.8.4 验收工具的过渡形态：一个共享 mint 模块

今天 6 处各自读 SSM 明文再 `mint_session_jwt`（四个 `verify_*`、`verify_kid_entry_live.py`、E2E 的
`session_cookie`）。

**裁定**：新增 `scripts/_session_mint.py`：用 `session_keys.load_session_keys` 读 `[SessionKeys]`，按
family 取 `current`（默认）或 `previous`/`legacy` 的 SSM 值，调用生产 `session.mint_token`；六处全部改
import 它，2A 只换这一个模块为夹具签发器（§11.7）。所有工具从 1B 第一票起默认发新形态。
`verify_session_token_semantics.py` 里按 legacy 语义写的那条（"升级码被 Edge 拒绝（typ != session）"）
改成新形态两条：console kid 的升级码投给 Edge 必拒（`unknown_kid`）、console-session token 投给 Edge
必拒；遮蔽 cookie 与正负对照不变。冒充真实 owner 与 `e2e@test.com` 沿用到 2A（已记录的偏差）。

**否决**：每个脚本各改各的——2A 要改六处。

#### 11.8.5 新 token 的 claim 集合：不另裁定，§11.4 就是真源

`mint_token` 已按 §11.4 实现：`name` 截 256、`iat` 三类无条件写、升级码 `min(ttl, 60)`。TTL 沿用现值
（站点 86400、面板 `CONSOLE_TTL_SECONDS`、升级码 60）。补一条事实：panel 今天不读面板会话里的 `name`
（用 Edge 注入的 `x-user-name`），`name` 留着是为与 §11.4 一致，成本为零。1B 不改任何 claim 集合。

#### 11.8.6 login-flow secret：按 §11.3 字面命名

**词表冲突**：讨论中出现过 `IN_FLOW_SECRET_PARAM` 一名，与 §11.3/§11.6 与 `CONTEXT.md` 的
**login-flow secret** 冲突。**裁定按 spec 字面**：参数 `/site-builder/login-flow-secret`、config 键
`[SessionKeys] login_flow_secret_param`、env `LOGIN_FLOW_SECRET_PARAM`（正好套 `_secret(name)` 的
`{name}_PARAM` 约定，`_login_flow_sig` 只改一个字符串）。`ensure_session_keys.py` 扩到也创建它（部署序列第
①步一次建齐所有 config 声明的密钥），`deploy_auth.py` 的 `ensure_secret` 保留为兜底；只进 auth 角色的
SSM 精确清单，panel/Edge 永不持有。轮转 = `put-parameter --overwrite`，5 分钟窗口进行中登录失败一次，
写进 DEPLOY.md，1B 不演练它。闸门归类见 §11.8.7。

#### 11.8.7 闸门：`--new-key` / `--retire-key` 两个桶，schema 留 4

**事实**：`compare_to_baseline` 对 category=platform 的 principal **丢**任何 grant 判红
（`missing_required`）；今天只有 `--new-kid` 这个"新增"桶。L3 与演练第 ⑩ 步都会让平台角色丢 grant。
`facts` 只报 delta、不参与红绿；`BUNDLE_SHAPE` 拒绝规格外的键。

**裁定**：`--new-kid` 泛化为 `--new-key LABEL` / `--retire-key LABEL`，LABEL ∈ kid ∪ {legacy,
login-flow}，`--new-kid` 留作别名。退役桶与新增桶镜像：只有被声明的那一条 grant 在平台角色上消失
才算迁移，其它丢失照样红。login-flow 的读取者记为 grant `read-login-flow-secret`（首次出现用
`--new-key login-flow` 声明），**不进** `is_secret_grant()`（读到只值一个登录 CSRF，不算冒充面）；
Edge 产物含其值即红——**硬断言，不落 facts**，与 console-in-Edge 同款。**schema 留 4**：grant 是
字串列表，加新字串不改 schema；不新增 facts 就不需要迁移。今天硬校验 `legacy_param == JWT_PARAM_NAME`
那条改成"`JWT_PARAM_NAME` 常量是追踪 legacy 参数的真源直到 3c-3 删参数；`legacy_param` 非空时必须
等于它，为空时照常追踪"，否则 L3 会把闸门炸掉。L3 时 Edge 产物 legacy 计数归零只是 facts 的 delta，
不需声明。

**否决**：用 `--update-baseline` 人工放行——1A 首跑就是这么放的，进 progress 而不进代码，下次没人知道
当时为什么绿；schema 5——为一个不参与红绿的数字做一次基线迁移是纯 churn。

#### 11.8.8 新 key 经 `previous` 槽位就位

每 family 只有 `current` + `previous` 两个槽位，演练有三个阶段（就位、切签发、排空），就位期 v2 必须
占一个槽位而 v1 仍在签发。

**裁定**：v2 先进 `previous`，切换时两槽互换。槽位语义定死（已进 `CONTEXT.md`）：`current` = signer
开关为 current 时签发用的那把；`previous` = 另一把被接受的 key，**要么是排空中的旧 key，要么是就位中
的新 key**。就位期 `accepted_previous` 应只来自我们自己的探针（探针之外出现 = 有人拿就位中的 key 签了
token，红）；切换后 `accepted_previous` 就是排空曲线。2B 的 RS 就位沿用同一套。

**否决**：(B) 独立的 `site_signer = <kid>` 指针——它可以指向 `previous`，回滚态下 auth/panel 的标签同样
错乱，还多一个可配错的键；(C) 第三个角色 `next`——要改 §8 词表（`accepted_next`）、三处 verifier、读数
工具与闸门，而它给的红旗（就位 key 被提前使用）(A) 用"就位期 previous 计数 = 探针数"同样能给。

#### 11.8.9 演练十步（两个 family 同步；这是 DEPLOY.md runbook 的首次执行）

每个 Edge 部署都 `rm -rf cdk.out`、等 CloudFront Deployed、跑 `verify_deployed_edge.sh`；每步的闸门
delta 都用 §11.8.7 的桶声明；T0/T1/T2 与每步证据记进 progress（gitignored），tracked 文件只放规则。

```
① 前置代码一次上齐：signer 开关（=legacy）、login-flow、_session_mint、工具改新形态、
   闸门 --new-key/--retire-key、stack.py 改读 legacy_param、部署脚本 config 先于 code、
   部署前参数核对（§11.8.12）、删 test_signer_untouched_in_1a + 新守卫 + auth→Edge 新形态向量
② ensure_session_keys（含 login-flow）→ 闸门 --new-key login-flow
   → deploy_auth（开关仍 legacy）→ GET /login 必 302 且带 __Host-sb_pkce → 操作者人工登录一次
   （顺带刷新 MCP token）→ 闸门复跑（auth role +read-login-flow-secret，已声明）
③ 开关 = current：deploy_panel --skip-frontend → deploy_auth（= T0）
   → 四个 verify_* 全跑 + verify_kid_entry_live + smoke_router
   → session_verify_counts --hours 1：三列 accepted_current > 0 → E2E 后台跑一次（约 37 min）
   → 用 _session_mint --role legacy --save 预存 legacy 探针 token（⑤ 用；届时已过期，
     但 §5 合同 kid 先于 exp ⇒ 结果仍是 unknown_kid，与过期无关）
④ 观察窗口（§11.8.2）
⑤ L3：legacy_param 清空 → deploy_auth → deploy_panel → Edge → 闸门 --retire-key legacy
   → 负向：预存 legacy token 打 Edge 必 302、panel 必 401；日志 unknown_kid
⑥ 就位：加 [SessionKey:site-hs-v2]/[SessionKey:console-hs-v2]，*_previous = *-hs-v2
   → ensure_session_keys → 闸门 --new-key site-hs-v2 --new-key console-hs-v2
   → deploy_auth → deploy_panel → Edge → 探针 --role previous 必 200 → 闸门复跑
⑦ 切换：两槽互换 → deploy_panel → deploy_auth（= T1）→ 探针 current/previous 都 200
   → Edge 重部一次（只为标签正确，§11.8.10）
⑧ 回滚演示：互换回去 → deploy_panel → deploy_auth → 探针 → 再换回来 → deploy_panel → deploy_auth（= T2）
⑨ 排空：T2 + 26 h 起 --hours 26 --require-total：三列 accepted_previous 全 0、accepted_current 全 > 0
⑩ 退役 v1：先 _session_mint --role previous --save 预存 v1 token → *_previous 清空、删 [SessionKey:*-hs-v1]
   → deploy_auth → deploy_panel → Edge → 负向：预存 token 必拒（unknown_kid）
   → 闸门 --retire-key site-hs-v1 --retire-key console-hs-v1 → 删两把 v1 SSM 参数（不可逆，跑时单独确认）
```

**四条已嵌在序列里的裁定**：L3（⑤）与就位（⑥）**不合并**成一次 Edge 部署——第 6 条要 L3 在 R1 之前，合并
会让失败无法归因，代价只是 20 分钟；**排空时钟从 T2 起算**——回滚演示又签了几分钟 v1，最后一枚 v1 的
出生时刻在 T2；**⑩ 包含删 SSM 参数**——否则一把无人接受的密钥留给 56 个宽读者、闸门还要为不在 config
里的 kid 记账；**③ 的 legacy 回滚不在生产演示**（§11.8.3）。Edge 部署共 4 次（⑤⑥⑦⑩）。演练结束后
config 是 `current = *-hs-v2`、`previous` 空，2B 的 RS key 从这里经 `previous` 就位。

#### 11.8.10 Edge 的标签倒置：切换后重部一次

⑦ 切换后到 Edge 重部之前，Edge 仍把 v1 标 current、v2 标 previous，与 auth/panel 相反。

**裁定**：⑦ 之后立刻重部 Edge 一次把标签摆正。站点会话的绝大多数验签发生在 Edge，排空曲线本来就该在
Edge 列上读；代价 20 分钟且不在关键路径（Edge 早已双接受）。⑧ 回滚演示那几分钟 Edge 标签再次倒置，
不处理，⑧ 结束后 Edge 配置（current=v2）与 signer 重新一致。

**否决**：排空判据只看 auth/panel 两列——等于放弃主要观测点。

#### 11.8.11 runbook，不写编排器；探针只扩两个既有脚本

**裁定**：十步写进 `DEPLOY.md`，替换今天那节"当前实现下不能就地改值"；每步 = 现成脚本 + 一处 config
修改 + 硬停止点。探针侧：`verify_kid_entry_live.py` 加 `--role current|previous`（正向）与
`--retired-token FILE`（负向，用 ⑤/⑩ 之前预存的 token）；`_session_mint.py` 带 `--save FILE` 供预存，
文件放 `.scratch/`（gitignored）。

**否决**：编排脚本——会把硬停止点藏进一个进程里，1A 那次 502 正是"脚本说 exit 0"掩盖的。

#### 11.8.12 部署前核对 HS 参数存在

auth/panel 的密钥值在运行时才按参数名读，参数缺失的症状是全部登录 500，与 1A 那次 502 同一形状
（部署脚本 exit 0、线上全红）；⑥ 若忘跑 `ensure_session_keys.py` 就会撞上。stack.py 缺值会落 SYNTH
占位符、`verify_deployed_edge.sh` 事后能抓，但 auth/panel 没有事前防线。

**裁定**：两个部署脚本在第一次写之前对各自 family 集合里的每个 HS `ssm_param` 做一次
`GetParameter`，任一缺失即拒绝部署。只读、幂等、不打印值；与 §11.6 第 1 层
"RS kid 的部署前校验"是同一位置，2B 在同一个钩子里加四项 KMS 校验。守卫：单测断言这个核对发生在任何
Lambda/IAM 写调用之前。

> **上面这条裁定原先写的是"auth 另加 login-flow 与非空的 legacy"，实施时按
> `docs/adr/0004-login-flow-secret-outside-the-pre-write-precheck.md` 在 **auth 一侧**排除了这两条**，
> 正文已按 ADR 改口。**panel 一侧没有这条排除**：`deploy_panel.required_parameters()` 就是
> `ssm_parameter_names(keys, ("console",))`，其首项**是** `legacy_param` ⇒ legacy 参数被删时
> panel 部署会被拦住、auth 不会。（auth 的清单另含 site client secret，不只是 family HS 行。）理由：核对发生在任何写之前，把 login-flow 列进清单就让 §11.8.6 要求保留的 `ensure_secret`
> 缺省补建永远走不到——而它存在的唯一理由正是首次部署，于是首次部署必然被自己拒掉。判据是"核对到底在
> 防什么"：它防的是**多个消费方必须就同一个值达成一致**，而 login-flow 只有 auth 一个消费方，所以这条
> 排除是**安全**的。**照本条原话把 login-flow 加回清单会让首次部署自我拒绝。**
>
> **legacy 参数走同一条排除，但那一条并不安全，是一个已知缺口**（3c-1A 的既定取舍，非 1B 引入）：它的
> 第二个消费方是 Edge，那份值是 CDK 部署时字符串替换注入的。成熟部署上参数若被删，auth 会静默重造一把
> 而 Edge 仍拿着旧的 ⇒ 正是 precheck 本要防的全员登录循环。今天唯一的现场信号是 `ensure_secret` 创建时
> 打的那一行。**ADR 0004 的"安全"结论只覆盖 login-flow 一把，不要把它读成对 legacy 的背书**；真正的修复
> 要能区分"首次部署"与"这个参数不该不存在"，那是独立的设计面（1B 不做）。

#### 11.8.13 实施纪律（1A 的教训，供 /to-tickets 逐票引用）

- **auth 的进包清单是 `deploy_auth.AUTH_PACKAGE_MODULES`，由 `auth/tests/test_deploy_auth_package.py`
  按 login_handler 的 import 闭包核对**；panel 那边叫 `COPY_FILES`。给 handler 新加同目录 import 却
  没进包 ⇒ `Runtime.ImportModuleError` ⇒ 整个 auth 502（2026-09-02 实测约 4 分钟，单测与
  `verify_deployed_components` 当时都绿）。1B 不新增 auth 模块（`signing_key` 进 `verifier_env.py`），
  但每一票合并前都跑这两条守卫。
- **别用 `publish_version` 做回滚锚点**：闸门会多出每个 principal 一条 `@version` invoke grant（1A 实测
  19 条噪音）。回滚 = 改配置重部（signer 开关）或 git 重部（代码）。
- **变形测试用 `git stash` 或临时副本，别对含未提交修改的文件 `git checkout --`**（1A 把未提交的
  `AUTH_PACKAGE_MODULES` 修复冲掉过一次）。
- **每个有时间闸的阶段是独立的一票**，进入条件 = 上一阶段的证据（T0/T1/T2、闸门报告、探针输出），证据
  按 static / fake-unit / integration / production 标注，进 progress（gitignored）。
- **七个包的单测串行跑**（`test_redlines.py` 的墙钟哨兵）。
- **已知要改的既有测试**：`panel/tests/test_deploy_panel_contract.py` 里 `JWT_SECRET_PARAM` 必存在那条
  在 L3 变成条件断言；`auth/tests/test_secret_loading.py::test_jwt_secret_rotation_hazard_is_documented`
  盯的 docstring 要随 signer 切换改写；`panel/tests/upgrade_code_vectors.py` 加新形态向量；
  `router/infrastructure/lambda/test_edge_auth.py` 今天**没有**用 `mint_token` 的 auth→Edge 正向向量
  （§9 要求的那条只有 legacy 形态），1B 补上。
- **真实账号/域名/角色名不进任何被跟踪的文件**；预存 token 与 T0/T1/T2 记录放 `.scratch/` 或 progress。
- **最终签字用 commit SHA + 干净工作树**；/code-review 的固定点是 `e4e8d97`。

---

### 11.9 资产框架裁定（2026-09-06 grill 定稿；ADR 0005 / 0006）

**前提被重述**：本项目的交付物是 `site-builder/` 资产，供任意 AWS 用户在自己账号部署；作者账号
是验证环境，不是生产。威胁模型按采用者的**共享账号**设计——`ReadOnlyAccess` 就含 `ssm:Get*` 与
`lambda:GetFunction`。在这个前提下逐条裁定：

| # | 问题 | 裁定 |
|---|---|---|
| 1 | 2A 与 2B 是否分开发布 | **合并**。拆分的唯一理由是闸门先于它观察的变化上线、避免验证环境迁移期的盲窗；验证环境可以接受盲窗 |
| 2 | 验收工具是否随资产分发 | **是**。夹具签发器（§11.7）是资产功能，按生产代码质量做；分发 `verify_deployed_*` + `smoke_router` + 四个 `verify_*`；10 条 E2E 留作开发者回归 |
| 3 | 最终资产是否保留 HS256 | **不保留**。只有 KMS 非对称；HS 两个 key family 的密钥材料、legacy 入口、跨算法双接受在 3c-final 删除 |
| 4 | 验证环境如何从 HS 到 KMS | **硬切换**：直接部署 KMS-only 的 signer 与 verifier，现存会话作废、重新登录。因此 2A、2B、3 合为 **3c-final**，§8 的 26 小时排空不用于这次切换 |
| 5 | 迁移脚手架去向 | v1 冻结前**删除**：legacy 状态机、`--migrate-from-schema` 与 schema 3/4→5 通道、runbook ①–⑩ 的 HS 版本、blue/green 存量迁移脚本（§9 的 M08 改"删"）、各次部署时间线。教训进 spec/ADR，过程记录留 gitignored |
| 6 | 单账号实测数据是否分发 | **不分发**。`account_trust_baseline.json` 与冒充面探针结果移出 tracked；采用者首跑生成；文档只留方法与边界定义，数字标"单账号实测" |
| 7 | 3d 迁独立账号 | 从工程包降为 DEPLOY.md 的**部署建议** |
| 8 | 账号信任边界闸门与探针 | 作为**可选**自检工具分发，闸门的 KMS 探测按此定位做 |
| 9 | IdP | 通用 OIDC 已是配置驱动。v1 前用 **Google**（外部第三方）与**第二个 Cognito 池**（零外部依赖）各走一遍；资产内置"Cognito 管理员建户"IdP 模式（ADR 0006）；Entra 缺 `email_verified` 只写进手册 |
| 10 | 文档 | 两层：采用者文档（CLAUDE.md、README、DEPLOY.md、client-setup、skills references、CONTEXT.md、ADR）必须过"新用户新账号"检查；决策记录（spec、plan、review、security）保留 tracked，文件头声明性质 |
| 11 | v1 的定义与出口 | v1 = 3c-final + 与采用者有关的小项（3h、3f、M03+M16、M07、M19、M14、M17、M22）。出口验收：全新账号只看 DEPLOY.md 从零部署 + 分发的验收集通过；打 `v1.0.0` |
| 12 | 顺序 | 与签名无关的小项 → IdP 两条 → 3c-final → 配置类小项 → 文档两层 → 出口验收 |

**保留不变的**：kid 级 current/previous 双接受与就位/退役协议（采用者轮转 KMS 密钥要用，
`--drain-gate previous` 是删旧密钥前的判据）；§11.1–11.7 的技术裁定；§11.7 的夹具签发器设计。

**被否决的**：按原分包在位迁移；HS 作为"简易模式"保留；3d 当工程包；M08 修而不删。

工单与接手点：`.scratch/asset-v1/`（gitignored，不是状态真源）。

## 12. 附录：spike 的实测数据与出处

| 事实 | 来源 |
|---|---|
| 56 能读明文密钥；3c 后 `can_sign` **15**、能替换运行中 Edge **17**、并集 **19**（**已知下界**） | `docs/security/3c-impersonation-surface.json`（tracked，只读 `SimulatePrincipalPolicy`，401 个 principal，2026-08-30） |
| 九条能力路径各自的持有者数、四个候选措施的边际收益 | 同上（`aggregate.per_label` / `aggregate.marginal_value_if_closed`） |
| **router 栈已关联 CFN service role 且无 stack policy** ⇒ CFN 那条路的调用方自己不需要 `iam:PassRole` | `cloudformation:DescribeStacks` + `GetStackPolicy`（只读） |
| **`site-auth-service` / `site-panel` 的 Function URL 无 qualifier、服务 `$LATEST`** ⇒ 换码即劫持 signer | `lambda:GetFunctionUrlConfig` + `GetFunction`（只读）+ 两个部署脚本的裸 `update_function_code` |
| **Edge 的 association 限定符是编号版本** ⇒ 单动作证明不了能替换运行中的代码 | `cloudfront:GetDistributionConfig`（只读，探针每次跑都重验这条前提） |
| 站点函数的 alias 指向 `publish_version` 出来的编号版本 ⇒ 改 `$LATEST` 改不动线上 | `deployer/functions/deploy_lambda_site.py:243-253` |
| 账号内已有一把客户自管 `RSA_2048 SIGN_VERIFY` CMK，其 key policy 是全开默认形态 | `kms:DescribeKey` + `GetKeyPolicy`（只读） |
| `alias/aws/ssm` 的 key policy 是 `Principal:*` + `ViaService` ⇒ 今天那道 KMS 是虚的 | 同上 |
| Lambda@Edge 50 MB / 30 s / 无 env / 无 Layers / 无 arm64 | CloudFront 开发者指南 *Quotas on Lambda@Edge*、*Restrictions on Lambda@Edge* |
| RSA 加密操作账号级共享 1,000 rps | KMS 开发者指南 *requests-per-second* |
| 非对称 CMK 不支持自动轮转 | CFN `AWS::KMS::Key` 文档 |
| key policy 权威性与自锁警告 | KMS 开发者指南 *Key policies* / *Default key policy* / `PutKeyPolicy` API |
| `RSA_2048` 非对称请求与对称同价、ECC 贵 5 倍、非对称不含免费额度 | AWS Pricing API（只读）+ KMS pricing 页 |
| 纯 Python RS256 验签 0.24 ms、ES256 4.5 ms | 本机实测，1000 次取平均 |
| Edge vendored `cryptography`：最终形态复测 128 MB 冷路径总差中位数 **+143.3 ms** / p95 **+147.1 ms**（闸 300 / 600），热调用验签 +0.12 ms；第一轮（PEM 解析在 handler 里、只看 Init 差）总差 300.14 ms 的判读已作废 | `site-builder/scripts/spike_edge_crypto_coldstart.py` + `spike_edge_crypto_requirements.txt`（tracked，一次性 Lambda、跑完自删；2026-09-02 两轮各 80 次冷启动）→ 原始输出 `docs/design/3c-spike/edge-crypto-coldstart-20260902T{093211,102034}Z.json`（gitignored） |
| Edge 跨区调用 热 229 ms / 冷 719 ms | 本仓库既有实测（CLAUDE.md 埋点预算） |

### 12.1 产物位置：**分三层，前两层 tracked**

| 层 | 位置 | 内容 |
|---|---|---|
| 探针本体 | `site-builder/scripts/probe_impersonation_surface.py`（**tracked**） | 资源全靠发现（不硬编码 distribution ID / 账号 / 角色名 / 绝对路径）；`--self-test` 是 18 条反例 + 2 条聚合断言，不碰 AWS |
| 聚合证据 | `docs/security/3c-impersonation-surface.json`（**tracked**） | commit SHA、探测时间、区、动作/资源等价类、各集合计数与交集、每个候选措施的边际收益、原始输出的 sha256、**已知盲区清单** |
| 原始名字 | `docs/design/3c-spike/observed-*.json`（**gitignored**） | principal 名字。探针在发第一个请求**之前**用 `git check-ignore` 挡住写进 tracked 路径 |

> **证据里的 `commit` 字段写的是 `bd615de…+dirty`**，这是诚实的：那一跑发生在引入探针
> 本身的那次提交**之前**（工作树里已有探针）。**数字与仓库状态无关**（量的是账号里的 IAM
> 形状），所以 `+dirty` 不影响结论；但要复跑对照时，请以本 spec 定稿那个提交为基准重跑一次
> 再比。**不要手工编辑那个 JSON 去"修好"这个字段**——它的价值来自"由脚本生成"。

**为什么必须是三层而不是两层**（外部复审第十四轮 P1-3，成立）：上一轮把产物从 `/tmp`
搬到 `docs/design/3c-spike/` **只解决了"系统清理 /tmp"，没解决可复现**——那个目录被
`.gitignore` 排除，新 clone、外部复审、下一台机器都拿不到探针代码、聚合结果与 headline
的计算逻辑，而 tracked 的 spec 却把它当证据引用。本仓库自己的 `CLAUDE.md` 已经规定
gitignored 的 `docs/design/` 不能当状态真源。原始输出确实含真实账号与内部角色名、不能
直接提交 ⇒ 拆层：**代码与聚合脱敏后 tracked，名字留在 gitignored**。

**一条流程教训**：spike 第一轮的探针输出、人工核对过的 `m09-3b-observed.json`、
以及 RS256 原型全放在 `/tmp`，**隔天被系统清理掉**，spec 引的实测数字一度失去可复跑的
依据（基线本体是 tracked 的、只存指纹，没受影响）。**spec 依赖的 spike 产物不能只活在
`/tmp`，也不能只活在 gitignored 目录里。** 另一条：给探针加超时是对的，但
`read_timeout` 取 30 秒会把
`GetAccountAuthorizationDetails`（要传账号里 ~300 份托管策略的完整文档、单页实测最慢
94 秒）变成超时→重试的死循环——**"加超时防挂死"与"超时取太小造成假挂死"是同一枚硬币
的两面**。本探针改用 `ListRoles`/`ListUsers` 只取 ARN，枚举从分钟级降到秒级。

**注**：§1 那些残留 principal 的**名字不写进本文档**（内部角色名不进被跟踪文件，
仓库红线）。要看是谁，跑闸门的 `--dump-observed`。
