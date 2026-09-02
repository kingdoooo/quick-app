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
服务同一类 token 的一组密钥，同一时刻最多持有 current 与 previous 两把。平台只有两个 family：site-session 与 console。
_Avoid_: key ring、密钥组、key set

**kid**：
一把具体密钥在 token header 里的不透明标签。verifier 只拿它查表，从不解析其内容。
_Avoid_: key name、key alias

**Verifier allowlist**：
一个 verifier 自己接受的 kid 集合，以及每个 kid 绑定的算法与密钥材料。不同 verifier 之间不共享。
_Avoid_: key registry（暗示全局共享）、trust store

**Legacy entry（legacy 入口）**：
迁移期接受无 kid 旧 token 的独立第三条验证路径。带 kid 但不在 allowlist 的 token 直接被拒，不会进入它。
_Avoid_: legacy fallback、回落、兜底

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
