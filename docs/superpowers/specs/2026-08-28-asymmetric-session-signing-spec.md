# 3c：会话签名迁到非对称（设计 spec）

日期 **2026-08-28**。状态：**设计，未实施**。对应 merged review §9 的 **3c**
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

3c 的论点是"Edge 只放公钥 ⇒ 只读那批 principal 拿不到签名能力"。这个论点**成立**，
2026-08-28 用生产只读模拟量过（400 个 principal，与 M09 闸门同一份枚举）：

| | 数量 |
|---|---|
| 今天能拿到 HS256 明文密钥 ⇒ 能签任意人的会话 | **56** |
| 迁 KMS 后能 `kms:Sign` | **12** |
| 再加上能 `kms:PutKeyPolicy` / `kms:CreateGrant` 给自己授权的 | **13** |
| **彻底失去冒充能力** | **43** |
| 新进来的（今天读不到密钥、但能签名） | **0** |

**但收益到 13 就停了，原因必须写下来**：那 12 个 principal **每一个都同时持有
`replace-platform-code`**（Edge 函数的 `lambda:UpdateFunctionCode`，12/12，实测）。
即便 `kms:Sign` 一个都不给，他们直接把验签代码换掉即可。

因此：

- **不要指望用限制性 key policy 把管理员也挡在外面来"再赚一笔"。** KMS 的 key policy
  确实是权威的（§3.4），去掉 root 委派语句后仅凭 identity policy 无法使用该密钥——
  这在技术上做得到，但**集合仍是 12**，因为那 12 个换代码就绕过了。
- 它唯一改变的是**攻击的响声与速度**：`kms:Sign` 是静默且瞬时；替换 Edge 产物会改变
  已部署代码（`verify_deployed_edge.sh` 就是比对产物与源码的），且要等 10–20 分钟全球
  复制。这个可检测性差值值不值得换"自锁风险 + 一个破窗 principal（它本身成为新暴露面、
  闸门必须枚举它）"，**留作 3c-2 的一个显式决策点，不在本文档预先拍定**。
- 一句话：**3c 把边界从「账号内任何只读身份」压到「能改写平台代码的身份」**，
  与 `account-trust-boundary.md` 对账号边界的定义一致。它**不**声称防住管理员。

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

**3c-0（本文档 + spike） → 3c-1（HS256 轮转协议，含 signer 切换与一次真实演练） →
3c-2（两把 KMS 非对称 CMK） → 3c-3（清理与闸门）。**

不做"整包一次上"：那会把安全闸门修复、生产收权与密码学迁移混成一个更难复核、更难回滚的
发布单元。

### 3c-0：spec + Edge crypto spike

已完成的部分（2026-08-28，产物在 `/tmp`，仓库零改动）：

- 生产只读量测 §1 的 56 → 12/13 与 12/12 的 `replace-platform-code` 重叠；
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

### 3c-2：两把 KMS 非对称 CMK

把新的 asymmetric `kid` 加为 `current`、旧 HS256 作为 `previous`；signer 切 `kms:Sign`；
verifier 双接受。key policy 的宽严（§1 的决策点）在这一包裁定。

### 3c-3：清理与闸门

- 退役 HS256；删除旧 SSM secret；
- 确认 Edge asset 不再含活的对称签名密钥；
- **重设 M09 基线**（`account-trust-boundary.md` 已明写迁移后基线应重置而非沿用）；
- **闸门加 KMS 探测**：`kms:Sign` / `kms:PutKeyPolicy` / `kms:CreateGrant` 的持有者、
  key policy 快照、公钥指纹。**不加这一层，基线会显示一个很大的改善而真正要盯的那一面
  根本没被测量**——闸门今天明确"不看 KMS grants"。这是 3c 的一部分，不是后续项。
- 重设全部真机验收（§10）。

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

**不一起改就会假绿或部署不出去**：

| 对象 | 要改什么 |
|---|---|
| `verify_account_trust_boundary.py` | `JWT_PARAM_NAME`、产物里定位密钥的正则、A/B 两组基线**全部重置**；**新增 KMS 探测**（§3c-3） |
| `verify_deployed_edge.sh` | 它按源码字面量 grep 产物里的 `typ` 检查；验签函数重写后那条 regex 必失配 |
| `verify_console_e2e.py` / `verify_api_key_e2e.py` / `verify_analytics_e2e.py` / `verify_session_token_semantics.py` | **四个都靠"读 SSM 明文 → 本地 mint 会话"免掉人工登录**。非对称化后本地拿不到私钥 ⇒ **这四个闸门的登录态获取方式要重新设计**（给验收角色一条受限的 `kms:Sign`，或走真实登录）。这条影响的正是"我们用来验证一切的东西" |
| `deployer/tests/test_e2e_fixtures.py` | 同上（10 条 E2E 的登录态全靠它） |
| `test_edge_auth.py` / `test_origin_request.py` / `test_edge_access_log.py` | 占位符替换表、手搓 HMAC 的用例、跨组件向量、签名形状断言 |
| auth / panel 的测试 | `test_session.py`、`test_upgrade_code.py`、`test_console_session.py`、`test_deploy_panel_contract.py`（"SSM 资源必须是精确 jwt-secret ARN"）等 |
| `verify_deployed_components.py` | "环境变量不得有明文密钥"那两处检查 |

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

---

## 12. 附录：spike 的实测数据与出处

| 事实 | 来源 |
|---|---|
| 56 → 12 `kms:Sign` / 13 含自授权 / 43 失去 / 0 新增 | 生产只读 `SimulatePrincipalPolicy`，400 个 principal，2026-08-28 |
| 12/12 残留签名者同时持 `replace-platform-code` | 同上 + M09 基线 dump 交叉 |
| 账号内已有一把客户自管 `RSA_2048 SIGN_VERIFY` CMK，其 key policy 是全开默认形态 | `kms:DescribeKey` + `GetKeyPolicy`（只读） |
| `alias/aws/ssm` 的 key policy 是 `Principal:*` + `ViaService` ⇒ 今天那道 KMS 是虚的 | 同上 |
| Lambda@Edge 50 MB / 30 s / 无 env / 无 Layers / 无 arm64 | CloudFront 开发者指南 *Quotas on Lambda@Edge*、*Restrictions on Lambda@Edge* |
| RSA 加密操作账号级共享 1,000 rps | KMS 开发者指南 *requests-per-second* |
| 非对称 CMK 不支持自动轮转 | CFN `AWS::KMS::Key` 文档 |
| key policy 权威性与自锁警告 | KMS 开发者指南 *Key policies* / *Default key policy* / `PutKeyPolicy` API |
| `RSA_2048` 非对称请求与对称同价、ECC 贵 5 倍、非对称不含免费额度 | AWS Pricing API（只读）+ KMS pricing 页 |
| 纯 Python RS256 验签 0.24 ms、ES256 4.5 ms | 本机实测，1000 次取平均 |
| Edge 跨区调用 热 229 ms / 冷 719 ms | 本仓库既有实测（CLAUDE.md 埋点预算） |

**注**：§1 那 12 个残留签名者的**名字不写进本文档**（内部角色名不进被跟踪文件，
仓库红线）。要看是谁，跑闸门的 `--dump-observed`。
