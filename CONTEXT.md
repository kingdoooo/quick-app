# Quick Site Builder

自动化建站平台：业务人员在 Agent 里用自然语言生成站点，平台负责部署、路由与边缘鉴权。
本文件只是词表：定义本仓库特有的概念，选定唯一叫法，列出要避开的同义词。不放实现细节。

## Language

### 会话签名

**Signer**：
签发平台 token 的组件。auth 与 panel 是 signer。
_Avoid_: issuer（会与 JWT 的 `iss` 混淆）、发牌方

**Verifier**：
验证平台 token 并据此放行的组件。Edge、auth、panel 各自是独立的 verifier。
_Avoid_: validator、authorizer

**Key family**：
服务同一类 token 的一组密钥，同一时刻最多持有 current 与 previous 两把。平台只有两个 family：site-session 与 console。两个槽位的含义固定：**current** 是 signer 开关为 current 时签发用的那把；**previous** 是另一把被接受的 key，它要么是排空中的旧 key，要么是就位中的新 key。
_Avoid_: key ring、密钥组、key set、把 previous 理解成"一定比 current 旧"

**Staging（就位）**：
一把新 key 已被某 family 的全部 verifier 接受、但尚无任何 signer 用它签发的状态。就位期该 key 占 previous 槽位；就位期出现探针之外的 previous 接受计数是红旗。
_Avoid_: 预发布、pre-rotation、灰度

**Retire（退役）**：
把一把 key 或 legacy 入口从所有 verifier 的接受集合中移除，并销毁其密钥材料。只在观察窗口判据满足之后进行；退役后持该 key 的 token 被当作未知 kid 拒绝，与是否过期无关。
_Avoid_: 删 key、rotate out、下线、把硬切换叫退役

**kid**：
一把具体密钥在 token header 里的不透明标签。verifier 只拿它查表，从不解析其内容。
_Avoid_: key name、key alias

**Verifier allowlist**：
一个 verifier 自己接受的 kid 集合，以及每个 kid 绑定的算法与密钥材料。不同 verifier 之间不共享。
_Avoid_: key registry（暗示全局共享）、trust store

**Legacy entry（legacy 入口）**：
迁移期接受无 kid 旧 token 的独立第三条验证路径。带 kid 但不在 allowlist 的 token 直接被拒，不会进入它。它有两个不同的终态：**关闭**（所有 verifier 不再接受无 kid token，路径本身仍存在）与**删除**（路径与旧密钥不复存在）。状态机的 L3 由"关闭"定义，"删除"是之后的清理。
_Avoid_: legacy fallback、回落、兜底、把"关闭"说成"删除"

**Signer switch（signer 开关）**：
决定 signer 以 legacy 形态还是以 current key 签发的单一开关，两个 key family 同步切换。它只改签发，不改任何 verifier 接受什么。
_Avoid_: feature flag、灰度、signer mode

**Observation window（观察窗口）**：
从最后一个 signer 切换完成起算、长度不短于最长 token TTL 的滑动窗口。退役 legacy 入口或 previous key 的判据只在这个窗口上评估：被退役的一方接受计数为 0，且每个 verifier 都有非 0 的总量。
_Avoid_: 静默期、冷却期、固定天数

**token_use**：
写在 token 里的固定用途标记，与 aud 一起决定该 token 只能被哪个 verifier 接受。三个值：site-session、console-upgrade、console-session。
_Avoid_: typ（payload 里的旧标记）、scope、type

**Login-flow secret**：
auth 私有的 HMAC 密钥，只保护登录流程中的 OAuth state 与 PKCE cookie，不签发任何会话。
_Avoid_: state secret、jwt secret

**冒充面（impersonation surface）**：
账号内能够以任意用户身份取得平台会话的 principal 集合。按已建模路径量出的数字是下界，不是上界。
_Avoid_: attack surface（太宽）、上界

### 验收

**Fixture identity（夹具身份）**：
只存在于保留域 `e2e.invalid` 下、供闸门与 E2E 使用的合成用户身份。
_Avoid_: test user、bot、`@example.com` / `@test.com` 邮箱

**Fixture session（夹具会话）**：
由 auth 的受控签发路径为夹具身份签出的站点会话。它是闸门与 E2E 唯一可以带外取得的 token，其余 token 一律走真实换取链路。
_Avoid_: test token、synthetic session、本地 mint 的 cookie

### 交付与分包

**资产（Asset）**：
本仓库的交付物：`site-builder/` 与 `router/` 这套任意 AWS 账号都能独立部署的代码、配置模板与手册。资产之外的一切（本仓库作者的账号、其部署历史、迁移步骤）都不是交付物。
_Avoid_: 项目、平台、线上、把"我们的部署"当成交付物

**采用者（Adopter）**：
拿到资产、在自己账号里部署并运维的 AWS 用户。与站点作者（在 Agent 里建站的业务人员）和站点访问者是三种不同的人。
_Avoid_: 用户（三义）、客户、租户

**验证环境（Dev environment）**：
本仓库作者用来验证资产的那个 AWS 账号与部署。它不是生产：没有必须保护的用户会话，可以硬切换、可以重建；它经历过的中间状态不进资产。
_Avoid_: 生产、线上、prod（指这个账号时）

**硬切换（Hard cutover）**：
在一个变更窗口内把 verifier 与 signer 先后换到新的密钥形态，**不提供跨形态双接受**：窗口等于 Edge 全球复制期（10 到 20 分钟），窗口内登录会失败，窗口结束后所有用户重新登录一次。与滚动切换（就位 → 切换 → 排空 → 退役）相对；只在验证环境里做。它**不是退役**：整个旧密钥形态一次作废，不进入退役流程，也不评估观察窗口。
_Avoid_: 迁移、in-place migration、灰度

**v1 冻结（v1 freeze）**：
资产第一次可分发的状态：出口验收通过后打 tag 的那个提交。冻结之前的所有改动都是"为了让新账号能直接部署到这个状态"。
_Avoid_: 上线、发布、GA

**出口验收（Exit acceptance）**：
在一个全新账号里只看手册从零部署资产并跑分发的验收集，作为冻结的唯一判据。它验的是交付物，不是验证环境。
_Avoid_: E2E（那是开发者回归）、冒烟

分包编号（3c-1A、3c-1B、3c-final …）不是领域词，唯一定义在
`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §6.1（3c-final 那一行）与 §11.9。
