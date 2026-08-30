# 3c：会话签名迁到非对称（设计 spec）

日期 **2026-08-28**（末次修订 **2026-08-31**）。状态：**待修订的设计草案，未实施**
（外部复审第十三、十四轮的 P1 已按下文吸收；**它不构成 3c-0/3c-1 的实施授权**）。
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

**最后一条刻意留空**，由 3c-0 的 spike 裁决，见 §11。本文档不预先承诺手写 RSA 验签。

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
所以每次 Edge 部署都留下一个版本，今天那 10 个代码目标每一个都带着**当前有效**的对称密钥
（bootstrap 桶里另有 9 个 asset 同理）。换成非对称后，历史版本里留下的只有**公钥**，
版本累积从此不再是负债。这也是为什么"删掉那 9 个 asset"不是 3c 的替代方案。

---

## 2. 现状：一把密钥，4 处签、5 处验

| # | 签名点 | 位置 | 产物 |
|---|---|---|---|
| 1 | 站点会话 `sb_session` | `auth/login_handler.py:503` → `session.mint_session_jwt` | `typ=session`，24h |
| 2 | console 一次性升级码 | `auth/login_handler.py:545` → `session.mint_upgrade_code` | `typ=console-upgrade`，≤60s |
| 3 | 面板会话 `__Host-sb_console` | `panel/console_session.py:109` → `session.mint_session_jwt(scope="console")` | `typ=session` + `scope=console`，4h |
| 4 | OAuth state | `auth/login_handler.py:102` `_state_sig` | **裸 HMAC，不是 JWT** |

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

### 4.1 两个独立 key ring

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

**两个 key ring 从第一包（3c-1，仍是 HS256）的数据模型就开始**，不是等到 3c-2 才拆。
否则 3c-1 建出来的 registry 形状要重做。

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

### 4.3 每个 verifier 的 allowlist

**每个 verifier 只认它自己那份 allowlist，不共享一个全局 registry。**

| verifier | 接受的 key family | 接受的 `token_use` |
|---|---|---|
| Edge | site-session | `site-session` |
| auth `/console-session` | site-session | `site-session` |
| panel（面板会话） | console | `console-session` |
| panel（升级码） | console | `console-upgrade` |

### 4.4 kid registry 的形态

`kid → {key family, alg, key material}`，**固定 allowlist**，每个 family 最多两把：
`current` + `previous`。

**禁止（每条都要有反例覆盖，见 §9）**：

- **按不可信的 `kid` 动态拼** SSM path / KMS ARN / 文件名。`kid` 来自 token，是攻击者
  控制的输入；用它去拼资源标识就是把资源选择权交出去。
- **相信 JWT header 自带的 `alg`**。`alg` 只用来**比对** registry 里该 `kid` 绑定的算法，
  不能用来分派实现。
- **一个全局 key registry 被 Edge / auth / panel 全部共享**。
- **只靠 cookie 名、`__Host-` 前缀或 `scope` 做用途隔离**。

---

## 5. 验签合同

每个 verifier 在**验签通过之后**、按此顺序检查：

1. `kid` 存在，且在**本 verifier 自己的** allowlist 里；
2. header 的 `alg` 与 registry 中该 `kid` 绑定的算法**精确一致**；
3. 签名用该 `kid` 对应的 key material 验过；
4. `token_use` **精确一致**；
5. `aud` **精确一致**；
6. `exp`（以及既有的身份字段合同：`email` 非空等）。

**顺序不能反**：先验签、再解析并信任 payload。反了就是在未验签数据上做逻辑判断。

**RS256 阶段（3c-2）额外必须做到的**，若最终选纯 Python 实现（3c-0 裁决）：
重建完整 EMSA-PKCS1-v1_5 编码后**整块定时比较**（绝不在解出的 EM 里查找/`endswith`
DigestInfo——那是 Bleichenbacher 2006 那一类伪造的唯一入口）；签名长度**严格等于模长**；
签名整数 `s < n`；公钥侧校验 SPKI 是 `rsaEncryption`、DER 最小形式、模长 ∈ {2048,3072,4096}、
**指数等于 65537**；base64url 必须规范形式（拒 `=` 填充、拒标准字母表、拒非规范尾比特）；
拒 `crit` 头；定时安全比较。**这一整套连同它们的反例用例是 3c-2 的交付物之一**，
并且要有变形测试证明它们真会红（把整块比较改成 `endswith` 时，EMSA 那组必须全部转红）。

---

## 6. 分包与顺序

**3c-0（spec + spike） → 3c-1A（verifier 认新形态） → 3c-1B（HS signer 切 `kid`
＋轮转演练） → 3c-2A（闸门与验收先认 KMS） → 3c-2B（signer 切 `kms:Sign`） →
3c-3（HS 退役与清理）。**

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
| **3c-1A** | 全部 verifier 认 `kid`→{family, alg, key} 固定 allowlist、每 family `current`+`previous`、legacy 第三入口（状态机 L1）。**signer 不动** | 闸门认识**两个 HS key ring** 与 legacy/current/previous（今天它只认识一个 `JWT_PARAM_NAME`、一套 Edge/asset 密钥定位）；§9 全部 verifier 反例齐备并验过红绿 |
| **3c-1B** | signer 开始发 family-specific `kid` + 新 `token_use`/`aud`（状态机 L2）；一次真实 HS 轮转演练 R1/R2 | 四个 `verify_*` 与 10 条 E2E 的登录态工具能 mint **带新 `kid` 的 HS token**（否则 signer 一切就全红，读起来像功能坏了） |
| **3c-2A** | **只改闸门与验收，不动生产签名**：KMS 探测（`kms:Sign` 持有者、key policy 快照、grants、自助授权、公钥指纹）+ 验收入口改造 | 上一格全绿；本包**自己**先验过红绿（新探测要能真的红） |
| **3c-2B** | 两把 KMS 非对称 CMK；signer 切 `kms:Sign`；verifier 双接受；key policy 宽严裁定 | **3c-2A 已上线**；五个验收入口拿到**真实登录态**（不再靠读 SSM 明文本地 mint），且验过红绿 |
| **3c-3** | 退役 HS256、删旧 SSM secret、删 legacy 入口（状态机 L3）、基线**精确 delta** | `accepted_legacy == 0` 且总量非 0 持续超过最长 TTL（§8） |

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

**仍未回答、3c-0 收尾必须给出的**（见 §11）：vendored `cryptography` 在 Lambda@Edge 的
真实 zip 大小、构建平台与**冷启动实测**，对比"受审计的纯 Python RSA verify"的审计成本。
**在这个实测之前不承诺自己手写 RSA 验签。**

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
| **L3** | 只有两个 family 的 `v1` | family `v1` | legacy 入口删除完成 |
| **R1/R2** | family 内 `current`+`previous`（`v1`→`v2`） | 切 `v2`，可回滚回 `v1` | 真正的轮转演练，见下 |

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
E2E 的登录态获取方式按 §11 未决项 7 裁定的那条路改造。**本包自己要先验过红绿**——
新探测必须能真的红，否则 3c-2B 上线后基线只会显示一个很大的"改善"，而真正要盯的那一面
根本没被测量（闸门今天明确"不看 KMS grants"）。

`replace-platform-code` 重建成完整链（§1 的顺带发现）也在这一包，理由见 §10。

### 3c-2B：两把 KMS 非对称 CMK

把新的 asymmetric `kid` 加为 `current`、旧 HS256 作为 `previous`；signer 切 `kms:Sign`；
verifier 双接受。key policy 的宽严（§1 的决策点）在这一包裁定。**前置条件是 3c-2A 已
上线**，见 §6.1。

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

---

## 8. 观测

**不记录 token。** 只记固定、低基数的结果计数：

```
accepted_current   accepted_previous   accepted_legacy
unknown_kid        alg_mismatch        wrong_audience
wrong_token_use    bad_signature       expired
```

**退役条件是可观测的、不是估计的**：只有 `accepted_legacy == 0` 持续超过最长 TTL，
才允许删除 legacy fallback。

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
- **legacy fallback 在截止时间之后仍被接受**。

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
| `verify_account_trust_boundary.py`（HS 侧） | `JWT_PARAM_NAME` 变成**两个 HS key ring** + legacy/current/previous；产物里定位密钥的正则要能同时找多把 | 3c-1A |
| `verify_account_trust_boundary.py`（KMS 侧） | **新增 KMS 探测**：`kms:Sign` / `kms:PutKeyPolicy` / `kms:CreateGrant` 持有者、key policy 快照、grants、公钥指纹 | 3c-2A |
| `verify_account_trust_boundary.py`（`replace-platform-code`） | 重建成**完整链**（动作等价类 × 资源等价类），判据与 `scripts/probe_impersonation_surface.py` 的 `classify()` 一致 | 3c-2A（**但它是当前基线的一处低估，与 3c 是否做无关，可提前单独修**） |
| `verify_account_trust_boundary.py`（基线） | **schema 迁移 + 精确 delta，不是全部重置**——理由见 §6.2 的 3c-3 一节 | 3c-3 |
| `verify_deployed_edge.sh` | 它按源码字面量 grep 产物里的 `typ` 检查；验签函数重写后那条 regex 必失配 | 3c-1A |
| `verify_console_e2e.py` / `verify_api_key_e2e.py` / `verify_analytics_e2e.py` / `verify_session_token_semantics.py` | **四个都靠"读 SSM 明文 → 本地 mint 会话"免掉人工登录**。非对称化后本地拿不到私钥 ⇒ **这四个闸门的登录态获取方式要重新设计**，按 **§11 未决项 7** 裁定的那条路改（①真实登录 / ②新增一个 signer principal 并精确纳入 A 组枚举 / ③固定身份的受控签发服务）。**不要写成"给验收角色一条受限的 `kms:Sign`"——`kms:Sign` 不限制 claims，那本身就是一个新的冒充 principal。** 这条影响的正是"我们用来验证一切的东西" | 3c-2A |
| `deployer/tests/test_e2e_fixtures.py` | 同上（10 条 E2E 的登录态全靠它） | 3c-2A |
| `test_edge_auth.py` / `test_origin_request.py` / `test_edge_access_log.py` | 占位符替换表、手搓 HMAC 的用例、跨组件向量、签名形状断言 | 3c-1A（HS 形态）→ 3c-2B（RS 形态） |
| auth / panel 的测试 | `test_session.py`、`test_upgrade_code.py`、`test_console_session.py`、`test_deploy_panel_contract.py`（"SSM 资源必须是精确 jwt-secret ARN"）等 | 3c-1A/1B → 3c-2B |
| `verify_deployed_components.py` | "环境变量不得有明文密钥"那两处检查 | 3c-2B |

**文档**（都是状态真源）：`CLAUDE.md`（不变量 §"auth/session 与 Edge verifier 是同一契约"
+ 开头"三条仍然成立的边界"）、`site-builder/DEPLOY.md`（轮转整节 + 依赖关系 + §7 那条
"新建部署 vs 切换"的方向差别）、`docs/security/account-trust-boundary.md`（结论真源与
基线数字）、merged review §9 的 3c、`router/config.ini.example`。

---

## 11. 未决项（3c-0 收尾必须回答）

1. **Edge 的 RSA 验签用 vendored `cryptography` 还是纯 Python？**
   已知：包大小**不是**约束（50 MB 上限，wheel 压缩 4.5 MiB / 解压 14.2 MiB）；
   真正的代价是 Lambda@Edge **不支持 arm64** ⇒ 必须交叉构建 manylinux x86_64
   （本仓库在 psycopg 上踩过同一类，deployer bundling 钉死 `platform: linux/amd64`
   就是为此），且给鉴权关键路径新增一个供应链依赖。
   **判据**：真机冷启动实测 + 审计成本。**在此之前不承诺手写实现。**
2. **key policy 的宽严**（§1 的决策点）：默认 root 委派，还是限制性 policy + 破窗
   principal。判据是可检测性收益是否值得自锁风险与新增暴露面。
3. **OAuth state 的 `_state_sig`** 用同一把密钥做裸 HMAC。它是 auth 内部自签自验，
   可以留对称，但**必须换一把独立密钥**——否则旧对称密钥必须留着，"读到就能签"这条路
   对 state 仍然成立（CSRF 面）。这一项归 3c-1 还是 3c-2 待定。
4. `token_use` / `aud` 的具体字面量是否就用 §4.2 那六个值（一旦签发就进存量 cookie，
   改名要付 legacy 兼容的代价）。
5. **`kms:Sign` 的输入合同**（外部复审要求，不能留到实现里猜——它改变跨组件测试向量）：
   选 `MessageType=DIGEST` + `Message=SHA-256(JWS signing input)` +
   `SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`，还是选 `RAW`。`DIGEST` 可规避 `RAW` 的
   4096 字节上限，但**必须保证只哈希一次**（哈希两次是这条路的经典错法）。
6. **`kid` 与 KMS key 的不可变绑定**：每个非对称 `kid` 必须绑定不可变的 key ARN/KeyId、
   SPKI 指纹、`KeySpec`/`KeyUsage`、`SigningAlgorithm`。**不要让 signer 只引用一个可被
   重新指向别的 key 的 alias 却继续发同一个 `kid`**。若确实用 `current` alias，则
   `kms:Sign` 返回的 `KeyId` 必须与该 `kid` 期望的 key ID 一致，否则**硬失败**。
7. **验收身份怎么拿**（这条我原先写成"给验收角色一条受限的 `kms:Sign`"，**那个说法是错的**）：
   `kms:Sign` **不限制签什么 claims**——拥有该权限就能为任意身份产生合法签名，
   **它本身就是一个新的 impersonation principal**。三条路里必须选一条并写清：
   ① 走真实登录；② 接受新增一个 signer principal，并把它**精确纳入 M09 的 A 组枚举**；
   ③ 设计一个固定身份/固定用途的受控签发服务。**不能把裸 `kms:Sign` 描述成"内容受限"。**

---

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
