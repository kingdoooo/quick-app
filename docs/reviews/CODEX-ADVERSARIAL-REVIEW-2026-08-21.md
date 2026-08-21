# Quick Site Builder 一期/二期完整对抗性 Review

- **Review 日期**：2026-08-21
- **审查提交**：`05797af372f2577fafa5e8fd1ae54a3343d475be`
- **审查分支**：`master`
- **提交状态**：`HEAD == origin/master == github/master`，审查开始时工作树干净
- **审查性质**：个人项目防御性审核；本文只记录问题、复现步骤与加固建议

## 1. 总结

本轮形成以下正式 findings：

| 编号 | 等级 | 状态 | 概要 |
|---|---|---|---|
| P1-1 | P1 | 已知、当前线上可复现 | 同账号 `lambda:InvokeFunction` 可伪造 Edge 身份 |
| P1-2 | P1 | 新发现、代码路径成立 | 稀疏或错类型权限记录在修改/重投影时可能静默扩权 |
| P1-3 | P1 | 新发现、条件触发 | `require_idp_claim=false` 时一次性升级码可被当作普通站点会话 |
| P2-1 | P2 | 新发现 | 站点后端依赖解析未锁定，最终构建产物不可复现 |
| P2-2 | P2 | 新发现 | 访问趋势异步请求存在陈旧响应覆盖 |

当前环境边界：

- 当前线上唯一直接成立的高风险项是 **P1-1**，但调用者必须已经拥有同账号 Lambda invoke 权限。
- **P1-2** 的代码缺陷成立，但当前线上 7 个有效站点和 7 条用户路由未发现坏数据形态。
- **P1-3** 的代码缺陷成立，但当前线上 `require_idp_claim=true` 且配置了可信 IdP，因此未处于触发配置。
- 当前线上部署一致性检查：**73/73 通过**。
- 本地七包测试：**1881 passed / 54 skipped**。
- CDK 模板断言：**33 passed**。
- 锁定依赖环境 MCP：**215 passed**。
- 当前 pinned Python 依赖与临时解析的 fixture npm 依赖未发现已知漏洞；这不解决 P2-1 的未来解析漂移。

---

# 2. P1-1：直接 `lambda:InvokeFunction` 可以伪造 Edge 身份

## 2.1 状态

**已知问题，当前线上仍可复现。**

这不是公网匿名请求可以直接利用的问题。利用者首先必须拥有当前 AWS 账号内针对目标函数的 `lambda:InvokeFunction` 权限。

## 2.2 根本原因

`site-panel` 和 `site-key-proxy` 通过以下事件字段判断请求是否来自 Edge：

```text
requestContext.authorizer.iam.callerId
```

相关代码：

- `site-builder/deployer/functions/edge_caller.py:21-39`
- `site-builder/deployer/functions/edge_caller.py:51-96`
- `site-builder/panel/handler.py:124-140`

经 Function URL 调用时，该字段由 AWS 填充，普通调用者不能自行修改。

但经 `lambda:InvokeFunction` 直接调用时，调用者提供的整个 JSON 就是 Lambda event，因此也可以自行构造：

```text
requestContext.authorizer.iam.callerId
x-user-email
x-user-name
```

`caller_is_edge()` 无法从该 event 本身判断这些字段究竟来自 AWS Function URL authorizer，还是来自直接 Invoke 的调用者。

## 2.3 安全复现步骤

只使用虚构邮箱，并且只访问无副作用的 `/api/me`。

### Step 1：读取 Edge Role ID

从 `site-panel` 环境变量或对应 IAM role 获取当前 `EDGE_ROLE_ID`。

不要把真实 Role ID 写入仓库或 Review 文档。

### Step 2：构造只读 probe event

```json
{
  "requestContext": {
    "http": {
      "method": "GET"
    },
    "authorizer": {
      "iam": {
        "callerId": "<EDGE_ROLE_ID>:review-probe"
      }
    }
  },
  "rawPath": "/api/me",
  "headers": {
    "x-user-email": "review-probe@example.invalid",
    "x-user-name": "review-probe"
  }
}
```

### Step 3：直接 Invoke Lambda

```bash
aws lambda invoke \
  --function-name site-panel \
  --cli-binary-format raw-in-base64-out \
  --payload fileb://probe-event.json \
  /tmp/probe-result.json
```

### Step 4：查看结果

```bash
cat /tmp/probe-result.json
```

本轮实际观察：

- Lambda 调用成功；
- handler 返回 `200`；
- `/api/me` 接受了伪造的邮箱身份。

## 2.4 具体失败场景

### 场景 A：控制台数据读取

1. 同账号 IAM principal 获得 `lambda:InvokeFunction`。
2. 调用者知道目标用户邮箱。
3. 直接调用 `site-panel`，伪造 Edge `callerId` 和目标邮箱。
4. GET 接口把目标邮箱当成已经过 Edge 验证的身份。

可能读取：

- 目标用户的站点列表；
- 站点权限；
- 部署历史；
- API Key 元数据；
- 访问统计及访客邮箱；
- 如果伪造管理员邮箱，还可能进入管理员读取路径。

控制台写接口仍然有 console cookie 和 CSRF 校验，因此单独这一条不一定能直接完成写操作；但读权限边界已经失效。

### 场景 B：直接调用用户站点 Lambda

站点后端通常直接信任 Edge 注入的：

```text
x-user-email
x-user-name
```

如果同账号 principal 能直接调用用户站点 Lambda，就可以构造任意邮箱身份，并绕过该站点在 Edge 上的 `allowed_users` 判定。

如果站点 API 有数据读写能力，影响将超出控制台只读数据泄露。

## 2.5 为什么现有 73/73 没抓住

现有线上闸门主要验证：

- 非 Edge principal 经 Function URL 调用；
- Function URL 的 `callerId` 由 STS 生成；
- handler 返回 403。

它覆盖的是 `edge_caller.py` 注释中的 **Path B**。

没有覆盖：

- 直接 `lambda:InvokeFunction`；
- 调用者自行构造整个 event 的 **Path A**。

因此“73/73 全绿”和“P1-1 当前仍成立”并不矛盾。

## 2.6 加固建议

### 建议 A：账号级 IAM 隔离，作为主防线

建立明确的 Lambda 调用者白名单：

- Edge 执行角色；
- deployer 健康检查角色；
- 必需的运维 break-glass 角色；
- 其余 principal 显式拒绝 `lambda:InvokeFunction`。

重点审计：

```text
lambda:InvokeFunction
lambda:InvokeFunctionUrl
lambda:*
Resource: *
Resource: arn:aws:lambda:*:*:function:site-*
```

对于个人专用账号，可以将“只有项目所有者拥有管理员 AWS 凭证”声明为信任假设；但新增 CI、第三方自动化或其他 IAM 用户后必须重新审计。

### 建议 B：工作负载迁移到 Organizations 成员账号

在成员账号使用 SCP 或权限边界限制调用者。

如果工作负载仍部署在 Organizations 管理账号，不能把 SCP 视为已经关闭该路径。

### 建议 C：可信平台函数增加应用层 Edge 签名

适用于 `site-panel` 和 `site-key-proxy`。

Edge 注入：

```text
x-sb-edge-ts
x-sb-edge-nonce
x-sb-edge-signature
```

签名内容至少包括：

```text
method + path + body_hash + x-user-email + timestamp + nonce
```

后端校验：

- HMAC；
- 时间窗口，例如 30 秒；
- 签名邮箱与请求邮箱一致；
- 可选 nonce 重放保护。

密钥只允许 Edge 和目标平台 Lambda 读取。

用户站点代码本身不可信，不能仅依靠站点实现这项校验；用户站点仍应以 IAM 隔离为主。

## 2.7 必须补的回归闸门

1. 直接 `InvokeFunction` + 伪造 `callerId` → 必须 403。
2. 经真实 Edge 调用 → 正常成功。
3. 经 Function URL、非 Edge principal → 403。
4. 缺签名、错误签名、过期签名、签名邮箱不一致 → 全部 403。
5. IAM 自动审计：白名单之外没有 principal 可 invoke 用户站点或平台函数。

---

# 3. P1-2：稀疏或错误类型权限记录在修改时可能静默扩权

## 3.1 状态

**新发现；当前生产数据没有触发，但代码路径成立。**

## 3.2 根本原因

Edge 对坏数据使用 fail-closed 语义：

- `require_auth` 只有字面量布尔 `False` 才表示公开；
- 缺失或错误类型按“需要登录”处理；
- 缺失 `allowed_users` 按空名单处理，即只有 owner/collaborator 可进入。

相关代码：

- `router/infrastructure/lambda/origin_request.py:583-646`

但权限写入层使用：

```python
effective = {
    "require_login": bool(site.get("require_login", True)),
    "allowed_users": site.get("allowed_users", "org"),
}
```

相关代码：

- `site-builder/deployer/functions/permissions.py:507-510`
- `site-builder/deployer/functions/permissions.py:565-579`
- `site-builder/deployer/functions/permissions.py:760-788`
- `site-builder/scripts/migrate_permissions.py:57-80`

这导致读取和写入的坏数据语义相反：

- Edge 读取时按最严格处理；
- 权限写入、迁移或 resync 时把未知值固化为公开或全组织。

## 3.3 本地复现步骤

使用 moto 创建：

- sites 表；
- routing 表；
- admins 表；
- ops-log 表。

### Step 1：写入错误类型的 sites 行

```python
{
    "site_id": "s-1",
    "owner": "owner@x.com",
    "require_login": Decimal(0),
    "collaborators": [],
    "permissions_rev": 1
    # allowed_users 缺失
}
```

`Decimal(0)` 模拟 DynamoDB `N:0`，不是合法 BOOL。

### Step 2：写入安全路由

```python
{
    "subdomain": "app-s-1",
    "require_auth": True,
    "allowed_users": ["owner@x.com"],
    "owner": "owner@x.com",
    "collaborators": [],
    "permissions_rev": 1
}
```

此时线上实际语义是：

- 需要登录；
- 只有 owner 可进入。

### Step 3：执行无关权限修改

```python
permissions.set_collaborators(
    "s-1",
    actor="owner@x.com",
    add=["collaborator@x.com"],
)
```

### Step 4：读取 route

本轮观察结果：

```text
修改前：
require_auth = True
allowed_users = ["owner@x.com"]

修改后：
require_auth = False
allowed_users = "org"
```

sites 表中的 `allowed_users` 仍然缺失。

## 3.4 原因展开

```python
bool(Decimal(0)) is False
```

所以错误类型 `N:0` 被转换成了合法的公开配置。

同时：

```python
site.get("allowed_users", "org")
```

把“不知道原意”解释成了权限最宽的“全组织”。

## 3.5 可触发的真实路径

- 一期遗留记录缺字段；
- 迁移过程中只成功写了一半字段；
- 人工使用 DynamoDB 控制台时写错类型；
- 旧脚本写入 `N:0`、`S:"false"` 或 `NULL`；
- 从旧备份恢复出稀疏记录；
- 然后执行：
  - 添加/删除协作者；
  - 转移所有权；
  - 修改另一项访问策略；
  - `resync_route()`；
  - `migrate_permissions.py --apply`。

## 3.6 当前生产数据状态

本轮强一致检查：

- 7 条有效 site 记录；
- 7 条用户站点 route；
- 未发现 `require_login`、`allowed_users`、owner、collaborators、rev 类型异常。

所以这不是当前已有站点正在暴露，而是坏数据恢复和迁移路径的 P1。

## 3.7 加固建议

### 建议 A：建立唯一严格解析函数

```python
def strict_access_policy(site: dict) -> dict:
    require_login = site.get("require_login")
    if type(require_login) is not bool:
        raise DataIntegrityError("require_login 缺失或不是 BOOL")

    allowed = site.get("allowed_users")
    if allowed == "org":
        pass
    elif isinstance(allowed, list) and allowed:
        allowed = normalize_allowed_users(allowed)
    else:
        raise DataIntegrityError("allowed_users 缺失或形态非法")

    return {
        "require_login": require_login,
        "allowed_users": allowed,
    }
```

以下路径统一使用同一函数：

- `write_permissions()`；
- `resync_route()`；
- `register_route()`；
- `migrate_permissions.py`；
- panel/MCP 的权限输出 shaping。

### 建议 B：未知权限不得自动解释成 `org`

系统无法知道缺失名单的原意究竟是：

- 全组织；
- 指定名单；
- owner-only。

正确行为应是：

```text
停止写入 + 报数据完整性错误 + 要求管理员明确修复
```

### 建议 C：首次部署与已上线站点分开处理

只有满足以下全部条件时，才能从 manifest 补权限：

- route 尚不存在；
- site 处于首次部署；
- 条件写确认字段仍缺失；
- manifest 已经过合同校验；
- 两个权限字段在受控事务中完成初始化。

已经有 route 的站点如果真源缺字段，应停止并要求人工修复。

### 建议 D：迁移脚本 fail-closed

以下情况必须进入 `errors`，不得写入：

- route 缺 `allowed_users`；
- `allowed_users` 类型未知；
- `require_auth` 不是 BOOL；
- sites 与 route 身份字段冲突；
- 无法推断原始权限意图。

## 3.8 必须补的回归测试

| sites 输入 | 操作 | 期望 |
|---|---|---|
| `require_login=N:0` | 加协作者 | 报错，route 零写入 |
| `require_login=S:"false"` | 改名单 | 报错，route 零写入 |
| `require_login=NULL` | resync | 报错 |
| 缺 `allowed_users` | 转移 owner | 报错，不能写 `org` |
| 缺 `allowed_users` | migration dry-run | 进入 errors |
| 完整合法记录 | 加协作者 | 正常成功 |
| 首次部署、route 不存在 | seed manifest | 正常补齐 |

---

# 4. P1-3：一次性升级码可被当作普通站点会话

## 4.1 状态

**新发现；仅在 `require_idp_claim=false` 时形成站点身份越权。当前线上未触发。**

## 4.2 根本原因

普通站点会话、console 会话和 console upgrade code 使用同一套 HS256 密钥。

升级码包含：

```json
{
  "typ": "console-upgrade",
  "email": "...",
  "jti": "...",
  "exp": "..."
}
```

`verify_upgrade_code()` 正确检查了 `typ`。

但是通用：

```python
verify_session_jwt()
```

只检查：

- 签名；
- `exp`。

它不检查：

- `typ`；
- `scope`；
- `jti`；
- token 用途。

相关代码：

- `site-builder/auth/session.py:40-49`
- `site-builder/auth/session.py:72-104`
- `site-builder/auth/login_handler.py:475-506`

因此 upgrade code 可以反向冒充普通 `sb_session`。

## 4.3 本地复现步骤

### Step 1：生成升级码

```python
code = mint_upgrade_code(
    "victim@example.com",
    secret,
    ttl_seconds=60,
)
```

### Step 2：交给普通 session verifier

```python
claims = verify_session_jwt(code, secret)
```

当前结果：

```text
claims != None
```

### Step 3：模拟迁移期 Edge

```text
REQUIRE_IDP_CLAIM = false
TRUSTED_IDPS = ()
```

请求：

```http
Cookie: sb_session=<upgrade-code>
```

route：

```python
{
    "require_auth": True,
    "allowed_users": ["victim@example.com"]
}
```

调用 `_check_auth()` 后，本轮观察：

- 返回 `None`，表示允许；
- 注入 `x-user-email: victim@example.com`。

### Step 4：用 upgrade code 续发新 code

```text
GET /console-session
Cookie: sb_session=<upgrade-code>
```

当前返回 302，并在 Location 中带一个新 upgrade code。

因此原本“一次性、60 秒”的 code 能在过期前换出新的 60 秒 code。

## 4.4 触发前提

需要同时满足：

1. 获得一个合法 upgrade code；
2. Edge 设置 `require_idp_claim=false`；
3. 目标站点允许 code 中的邮箱。

upgrade code 可能暴露于：

- 浏览器历史或当前地址；
- 浏览器扩展；
- 本机代理；
- 屏幕录制或截图；
- 未正确脱敏的外围日志；
- 恶意本机软件。

## 4.5 当前线上状态

本轮确认线上 Edge 产物为：

```text
REQUIRE_IDP_CLAIM = true
TRUSTED_IDPS = ("Feishu",)
```

所以当前线上 upgrade code 因缺少 `idp/auth_via` 会被引导重新登录，不能作为站点会话。

但配置模板明确支持首次迁移阶段：

```ini
require_idp_claim = false
trusted_idps =
```

因此这是受支持配置下的真实缺陷。

## 4.6 加固建议

### 建议 A：为每类 token 增加明确用途

```text
typ=site-session
typ=console-session
typ=console-upgrade
```

site session 必须包含：

```text
typ=site-session
email
idp
auth_via
exp
```

console session 必须包含：

```text
typ=console-session
scope=console
email
exp
```

### 建议 B：verifier 必须要求 expected type

不要再提供无上下文的：

```python
verify_session_jwt(token, secret)
```

改为：

```python
verify_session_jwt(
    token,
    secret,
    expected_typ="site-session",
)
```

或拆成：

```python
verify_site_session()
verify_console_session()
verify_upgrade_code()
```

约束：

- Edge 只认 `site-session`；
- `/console-session` 只认 `site-session`；
- panel 写接口只认 `console-session`；
- callback 只认 `console-upgrade`。

### 建议 C：更强方案是分离密钥

```text
/site-builder/site-session-secret
/site-builder/console-session-secret
/site-builder/upgrade-code-secret
```

即使某个 verifier 忘记检查 `typ`，不同上下文签名也不能互认。

### 建议 D：安全兼容旧 token

如果必须兼容无 `typ` 的一期 token：

```python
if "typ" not in claims:
    if "scope" in claims or "jti" in claims:
        reject()
    accept_legacy_until(DEADLINE)
```

必须有明确截止时间和 legacy 使用量日志。

## 4.7 必须补的回归测试

1. upgrade code 交给 site verifier → 拒绝。
2. console session 交给 site verifier → 拒绝。
3. site session 交给 upgrade verifier → 拒绝。
4. upgrade code 作为 `/console-session` 的 `sb_session` → 拒绝。
5. `require_idp_claim=false` 时 upgrade code 仍不能访问站点。
6. 正常 site session 在迁移配置下仍正常工作。
7. legacy 无 typ token 只在迁移窗口接受。
8. 带 `jti` 或 `scope` 的无 typ token不得进入 legacy 分支。

---

# 5. P2-1：站点后端构建产物不可复现

## 5.1 根本原因

构建脚本使用：

```bash
npm install --omit=dev --no-audit --no-fund --ignore-scripts
```

位置：

- `site-builder/deployer/buildspec-package.yml:13-24`

合同不要求 `package-lock.json`，官方 fixtures 也使用范围版本：

```json
"express": "^4.19"
"@aws-sdk/client-dynamodb": "^3"
"@aws-sdk/dsql-signer": "^3"
```

相同上传字节在不同时间可能安装不同的直接或传递依赖。

## 5.2 验证步骤

1. 取 `site-builder/fixtures/nosql-notes/backend/package.json`。
2. 确认目录没有 `package-lock.json`。
3. 确认合同验证仍然通过。
4. 确认 CodeBuild 执行 `npm install`。
5. 记录生成包中的依赖版本，例如：

```text
node_modules/express/package.json
node_modules/@aws-sdk/*/package.json
```

6. 当范围内发布新版本后，用相同上传 zip 再部署。
7. 比较两次 `backend.zip` 或 dependency tree。

## 5.3 后果

- 回滚不一定恢复原后端字节；
- 相同 commit 在不同日期行为不同；
- 新发布的依赖可能造成运行时回归；
- 被污染的依赖会在站点 Lambda 中执行；
- M7 只保证上传源码一致，没有保证最终可执行产物一致。

`--ignore-scripts` 只阻止构建期生命周期脚本，不阻止依赖在站点运行时被加载执行。

## 5.4 加固建议

### 强制 package-lock

所有 fullstack 站点必须包含：

```text
backend/package.json
backend/package-lock.json
```

缺失 lockfile 时 validate 拒绝。

### 使用 npm ci

```bash
npm ci --omit=dev --ignore-scripts --no-audit --no-fund
```

禁止回退 `npm install`。

### 校验 lockfile

- package.json 与 lockfile 一致；
- lockfileVersion 在支持范围；
- 不允许非批准 registry；
- 不允许本机绝对路径和不可移植 `file:` 依赖；
- 必要时限制 git/url dependency。

### 记录构建证据

建议 job 保存：

```text
upload_etag
package_lock_sha256
backend_zip_sha256
node_version
npm_version
build_image_digest
```

### 固定构建工具链

更强方案：

- 自建 CodeBuild ECR 镜像；
- 按 digest 引用；
- 固定 Node/npm；
- 使用 CodeArtifact 或受控 registry mirror。

同时锁定：

- `aws-cdk-lib`；
- `constructs`；
- boto3/botocore；
- CDK CLI，避免无限变化的 `@latest`。

## 5.5 必须补的回归测试

1. fullstack 缺 package-lock → validate 拒绝。
2. package.json 与 lock 不一致 → build 失败。
3. buildspec 只能使用 `npm ci`。
4. `npm ci` 必须带 `--ignore-scripts`。
5. fixtures 全部带 lockfile。
6. 同一 fixture 连续构建两次，依赖树和 artifact hash 一致。
7. lockfile 指向非批准 registry → 拒绝。

---

# 6. P2-2：访问统计异步请求存在陈旧响应覆盖

## 6.1 根本原因

时间范围保存在模块级全局对象：

```javascript
const trendPref = {
  q: 'period=day&n=30',
  view: 'chart'
};
```

请求发出时读取一次 `trendPref.q`，响应返回时又读取当前 `trendPref.q` 来生成标题和选中态。

相关代码：

- `site-builder/panel/frontend/app.js:1264-1308`
- `site-builder/panel/frontend/app.js:1437-1442`

当前没有：

- AbortController；
- request generation；
- site ID 比对；
- tab 比对；
- 最新请求检查。

## 6.2 浏览器复现一：档位错配

1. 打开站点访问统计。
2. 在 DevTools 中启用网络节流。
3. 点击“近 90 天”，延迟该请求。
4. 立即点击“近 7 天”。
5. 让 7 天请求先完成。
6. 再释放旧的 90 天请求。

可能结果：

- 标题显示“近 7 天”；
- 7 天按钮处于选中态；
- 实际 series 来自 90 天请求。

## 6.3 浏览器复现二：跨页签覆盖

1. 打开访问统计。
2. 延迟 analytics 请求。
3. 在请求完成前切换到概览、访问权限、部署历史或另一个站点。
4. 等旧 analytics 请求返回。

旧 Promise 仍持有 panel DOM 引用，可能把统计内容写回已经切换后的页面。

## 6.4 后果

- 90 天数据被标成 7 天；
- 旧站点数据覆盖当前站点内容；
- tab 与内容不一致；
- 用户看到的是正常外观下的错误数据，而不是明显异常。

## 6.5 加固建议

### request generation

```javascript
let analyticsGeneration = 0;

function renderAnalyticsTab(panel, site) {
  const generation = ++analyticsGeneration;
  const query = trendPref.q;
  const siteId = site.site_id;

  return Promise.all([
    apiGet('/api/sites/' + encodeURIComponent(siteId)
      + '/analytics?' + query),
    apiGet('/api/sites/' + encodeURIComponent(siteId)
      + '/visitors?days=7&limit=50')
  ]).then((res) => {
    if (generation !== analyticsGeneration) return;
    if (currentSiteId() !== siteId) return;
    if (currentTab() !== 'analytics') return;

    const range = TREND_RANGES.find((r) => r[0] === query);
    renderResult(res, range);
  });
}
```

渲染必须使用请求发出时捕获的 `query`，不能再读当前 `trendPref.q`。

### AbortController

切档、切站点或切 tab 时取消前一个请求：

```javascript
currentAnalyticsController?.abort();
currentAnalyticsController = new AbortController();
```

`AbortError` 不应显示为页面故障。

### visitors 不随档位重复请求

时间档位只影响 trend，不影响固定“近 7 天访问明细”。

初次进入分别加载；切换档位只刷新趋势数据。

## 6.6 必须补的回归测试

1. 发出 90 天请求。
2. 发出 7 天请求。
3. 先 resolve 7 天。
4. 再 resolve 90 天。
5. 最终 DOM 必须仍显示 7 天数据。

另外覆盖：

- analytics 请求中切到权限 tab；
- analytics 请求中切换站点；
- abort 不显示错误；
- 慢旧请求不能发生后续 `innerHTML` 写入；
- visitors 不因每次切档重复请求。

---

# 7. 修复优先级

## 第一批：建议立即修复

1. **P1-2 权限数据严格解析**
   - 修复范围清晰；
   - 一旦触发就是公开或全组织扩权；
   - 迁移和修复工具不应猜测权限。

2. **P1-3 token 用途隔离**
   - 增加 `typ` 和 expected type；
   - 修复成本有限；
   - 能用明确负向测试封闭。

## 第二批：明确账号信任模型

3. **P1-1 直接 Invoke**
   - 个人专用账号可以暂时接受“只有项目所有者拥有 AWS invoke 权限”的假设；
   - 仍应补 IAM 自动审计和直接 Invoke 负向闸门；
   - 新增 CI、第三方服务或其他 IAM 用户时必须关闭。

## 第三批

4. **P2-1 lockfile + npm ci**
   - 建议在下一次正式发布前完成；
   - 否则相同源码可重现部署不成立。

5. **P2-2 analytics generation/abort**
   - 不影响后台授权边界；
   - 但会展示看似可信的错误数据，应在下一轮 UI 修复。

---

# 8. 修复完成后的最小验收矩阵

| 范围 | 必须通过的新增验证 |
|---|---|
| P1-1 | 直接 Invoke + 伪造 Edge event 必须 403；真实 Edge 正向请求必须成功 |
| P1-2 | 缺字段、N/S/NULL 错类型在所有权限 writer/resync/migration 中均 fail-closed 且零写入 |
| P1-3 | 三类 token 全部不能跨用途；false 迁移配置下仍拒 upgrade/console token 作为站点会话 |
| P2-1 | 缺 lock 拒绝；`npm ci`；同一输入连续构建 hash 一致 |
| P2-2 | 逆序 resolve 与跨 tab/site 导航时旧响应零 DOM 写入 |
| 全量 | 七包回归、CDK 断言、locked MCP、部署一致性闸门全部重新运行 |

