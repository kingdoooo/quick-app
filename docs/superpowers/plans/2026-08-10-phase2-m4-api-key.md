# Site Builder 二期 M4 实施计划（API Key + key-proxy 交换层）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让"只能配静态 Header"的客户端（Quick Desktop Remote MCP 等）用一把 `sk-` API Key 直连部署 MCP，免 stdio 代理；Key 由用户在控制台自助创建/吊销，可即时生效；整套能力是**可选组件**（不配置 `[ApiKey]` 即 OAuth-only），且带一个 admin 可在控制台操作的应急关闸开关。

**Architecture:** 四段。① 数据面：新表 `site-api-keys`（PK=`key_hash`，两个 GSI）+ 一条 `__switch__` 哨兵行承载全局开关，表访问收口在 `deployer/functions/keystore.py`（panel 与 key-proxy 都复制它）；② 交换层：新组件 `site-builder/key-proxy/`（Lambda + Function URL AWS_IAM 仅 edge role + `mcp.{base_domain}` route），**先强一致读开关（关则立即拒、不读 Key、不产生任何写），再强一致读 Key**，两者都不缓存 → 换 Cognito machine token（**进程内缓存至过期前 5 分钟**）→ **不懂 MCP 协议地透明转发**到 AgentCore endpoint；③ 信任规则：`_caller_email()` 新增 on-behalf 路径（`client_id == machine client` **且** `X-SB-On-Behalf-Of` 头存在且是邮箱形态），以及三处"缺一即不通"的组件门禁（`deploy_pool` 建 resource server + machine client、`deploy_agentcore` 的 `allowedClients` + `requestHeaderAllowlist`、`deploy_key_proxy` 部署与 route）；④ 控制台：`/api/keys` 三个端点 + `/api/settings/api-key` 开关（admin-only）+ 前端把 `pageKeys()` 占位换成真实实现。

**Tech Stack:** Python 3.13（key-proxy / panel Lambda）、Python 3.12（MCP 容器，实际由 Dockerfile 决定）、boto3、DynamoDB（强一致 GetItem + 两个 GSI + 条件写/条件更新）、Cognito（resource server + custom scope + client_credentials）、Bedrock AgentCore Runtime（customJWTAuthorizer + requestHeaderAllowlist）、Lambda Function URL（AWS_IAM）、CDK（deployer 栈）、pytest + moto、原生 JS 静态 SPA（无构建链）。

---

## Global Constraints

以下约束来自 spec、`CLAUDE.md`、M3 计划与 `docs/design/M3-FINDINGS.md`，**每个任务都隐含包含**：

### 通用（沿用 M3，逐条仍然有效）

- **区域**：一切资源在 `us-east-1`（Lambda@Edge / ACM / Quick 身份区域硬约束）。
- **配置唯一来源**：`site-builder/config.ini` 与 `router/config.ini`（均 gitignored，从同目录 `.example` 复制）。代码不硬编码账号 ID / 域名 / 邮箱。**不要把真实账号值（12 位账号 ID、真实域名、真实邮箱、真实 ARN、session UUID、本机绝对路径）写进任何被 git 跟踪的文件**——`.example` 里一律用 `000000000000` / `example.com`。
- **`docs/design/` 与 `.superpowers/` 都 gitignored**，**不得 `git add -f`**。
- **测试命令按包区分 venv**（照抄，别猜）：
  - `cd site-builder/contract && .venv/bin/pytest tests -q`
  - `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`
  - `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
  - `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests`**）
  - `cd site-builder/mcp && python3 -m pytest tests -q`
  - `cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`
  - **key-proxy 包借 deployer 的 venv**：`cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q`（同 panel 的理由：需要 moto + boto3，key-proxy 无自己的 venv。Task 3 建立此约定后同步写进 `CLAUDE.md`）
- **CDK 模板断言测试默认 skip**，要真跑必须带 PYTHONPATH 桥接：
  `cd site-builder/deployer && PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`（synth 需 Docker）。
- **Function URL 一律 `AuthType=AWS_IAM`** 且只授权 exact edge role，需要 `lambda:InvokeFunctionUrl`（`FunctionUrlAuthType=AWS_IAM`）+ `lambda:InvokeFunction`（`InvokedViaFunctionUrl=True`）**两条**语句，缺一即 403。不允许 `Principal=*`、不允许 public Function URL、**不允许配置缺失时 fallback 到宽权限**（缺 `edge_role_arn` 必须抛错中止部署）。
- **CloudFront 全站禁缓存是鉴权正确性前提**——**不得添加任何缓存策略**。
- **fail-closed 优先**：权限/身份/开关相关的解析与判定失败一律取最严格解释，绝不"取最宽松的默认值继续"。
- **加固测试必须先反向验证会红**：把守卫改成永真、注入它要防的缺陷，确认测试 FAIL，再还原。这是本项目栽过多次"验证本身无效"后的硬要求。
- **源码文本断言必须排除注释/docstring**，或改用 AST / 实际产物解析。
- **断言脚本必须有最小检查数下限**；中途崩溃、AWS 调用失败、下载截断都必须非零退出。**本机 aws CLI 在 API 错误时也可能返回 exit 0**（实测），判失败必须同时校验输出是合法 JSON。
- **unit test 绿 ≠ 部署生效**：必须下载并比对真实 Lambda/容器产物（`verify_deployed_components.py`）。
- **moto 不校验 IAM**：给任何组件加事务/条件写路径时，同步核对角色策略（M3-FINDINGS §2.18：145 个单测全绿、真机每个写请求 500）。
- **git**：`commit` **不带** `--no-verify`（让 Code Defender 执行）；本轮**不 push**（用户明确指示）。每次 commit 前三步：
  ```bash
  git add <本任务文件>
  bash site-builder/scripts/scan_staged_secrets.sh || exit 1
  git diff --cached          # 人工审核
  git commit -m "..."
  ```
  新文件首次 `git add` 之前另扫文件本体：`bash site-builder/scripts/scan_staged_secrets.sh --files <路径...> || exit 1`。命中不等于必须改——**必须先给用户看命中项再提交，不要自动清洗**，确认后加 `--allow-hits` 放行。
- **重命名文件时 pathspec 要含新旧两个路径**，提交后用 `git ls-tree HEAD <目录> --name-only` 核对旧名真的不在了（M3-FINDINGS §2.13）。
- **验证纪律**：每处改动用真实 AWS API 实证验证。标 `[真机]` 的步骤必须在真实 AWS 上跑，不能只靠 moto。
- **动真实 AWS 之前先问用户**（本轮用户明确要求）。所有 `[真机]` 步骤在执行前停下来征得同意。
- **发现文档与实际不符就同步更新**（`site-builder/DEPLOY.md`、`docs/` 下相关文档、`CLAUDE.md`）。
- **不实现 M5**：不写假接口、假数据或临时表。前端对 stats/audit（M5）保持 disabled / coming later，**不得请求不存在的 API**。

### M4 专属（安全性质决定的额外约束）

- **API Key 是新的认证路径，出错等于凭证泄漏。** 每条安全判定 fail-closed，且"网关放行"与"容器采信"是两件事（spike 已实证）。
- **禁止缓存授权数据**（spec §5.1 定死）。这不是"不写缓存代码"就自动满足的——**Lambda 的模块级变量跨请求存活**，把 `key_hash → email` 或开关值放进任何模块级 dict / `functools.lru_cache` / 模块级单例，就会在容器复用期间静默变成缓存。允许缓存的只有 machine token（它不是授权判定，只是 key-proxy 证明自己身份的凭证）。参照 `mcp/server.py:36` 的既有教训（`_trusted_idps()` 每次调用读环境变量，固化成模块级常量后 monkeypatch 失效）。
- **明文 Key 只出现在创建响应体里**，不得进任何 `logger` / `print` / ops-log / 异常消息 / URL / 查询参数。
- **响应体不得出现 `key_hash`**（哪怕是 admin 视图）。
- **判定顺序：先开关后 Key，两次独立的强一致 `GetItem`。** 关闸时**不发出 Key 的读请求**、不更新 `last_used_at`——关闸期间不该产生任何写。**不得合并成 `BatchGetItem`**：那样 Key 行必然被一起请求，短路就不成立（Codex P2-6）。
- **key-proxy 不读任何 cookie。** `mcp` 子域**不进** `PLATFORM_SUBDOMAINS`（决定已定），所以 Edge 会剥除保留 cookie；代码层再加一层"不读 cookie"的断言，两层冗余。
- **单把 Key 的启用/禁用就是 `revoked`，不加第三个状态。** 明文只在创建时显示一次、服务端不存明文，所以"暂停再恢复"的前提是用户手里还留着明文——安全收益为零，而多一个状态就多一处可能写成 fail-open 的分支。
- **整体开关必须是独立的、优先于逐 Key 判定的短路，不是逐 Key 状态的聚合。** 逐个吊销全部 Key 不等价于关闸：非原子（N 次写，中途失败即"关了一半"）、不覆盖未来创建的 Key、且若泄漏的是面板会话则攻击者能一边建一边吊销。

---

## 已定稿的决定（不要在实施期重新讨论）

来自 spec §5.1 / §5.1.1 / §5.3（提交 `3d7c3f3`）与本轮 brainstorming：

| # | 决定 | 出处 |
|---|---|---|
| 1 | 明文 `sk-` + 16 位随机 base62（95.3 bit）；**PK = `key_hash`**（SHA-256 hex）；外加**独立随机** 8 位 base62 `key_id`（非秘密，供列表/吊销引用，**不得由 hash 派生**） | spec §5.1 |
| 2 | 交换层**禁止缓存** `hash → email`（缓存了"即时吊销"就不成立） | spec §5.1 |
| 3 | Key 管理**只在控制台**（要求面板会话）；故意不做"MCP 工具管 Key" | spec §5.1 |
| 4 | API Key 是**可选组件**，两层门禁：组件门禁为主（无 `[ApiKey]` 段 → machine client 不进 `allowedClients` → 网关层就拒）、开关为副（应急关闸） | spec §5.1.1 |
| 5 | 主案成立（machine token + on-behalf 头），**不必回退**"自签 JWT + 自建 JWKS" | spike，spec §5.3 |
| 6 | **开关落 DDB 哨兵行**（`site-api-keys` 表 `key_hash="__switch__"`），由 console 上的 admin 操作；`config.ini` 的 `[ApiKey]` **不再有 `enabled` 键**。**spec §5.1.1 与 `config.ini.example` 已在 2026-08-11 同步改掉**（Codex P1-1：两个真源比没有开关更危险——运维照旧文档设 `enabled=false` 而实现只读哨兵行，Key 全部继续有效且现场以为已关） | brainstorming 2026-08-10；spec 回写 2026-08-11 |
| 7 | key-proxy 是**不懂协议的透明管道**：不解 JSON-RPC、不看 method、不过滤工具名；双向透传 `Mcp-Session-Id` / `Accept` / `Content-Type`，SSE 整体缓冲后原样回传 | brainstorming 2026-08-10 |
| 8 | on-behalf 的 email 可信性由**创建时已验**保证（Key 只能在 console 创建，而 console 身份来自 Edge 注入的 `x-user-email`，那条路径已过 `REQUIRE_IDP_CLAIM` 的 `idp`/`auth_via` 校验）。机器 token 天生没有这三个 claim，on-behalf 路径**跳过**它们，但必须断言 `client_id == machine` 且头存在且是邮箱形态。已知取舍：用户离职后旧 Key 仍有效，靠审计 + 吊销处理 | brainstorming 2026-08-10 |
| 9 | `mcp` 子域**不进** `PLATFORM_SUBDOMAINS` | brainstorming 2026-08-10 |

## 计划级补充（spec 未写，由 spec 要求推导；控制器已裁决）

| # | 补充 | 推导链 |
|---|---|---|
| A | `site-api-keys` 加 GSI **`keyid-index`**（PK `key_id`）；**`key_id` 的唯一性由创建时的条件写保证，不靠 GSI** | spec §4.4 的 `DELETE /api/keys` 拿到的是 `key_id`，而表 PK 是 `key_hash`。没有这个 GSI 只能全表 Scan；而吊销必须先查到该行的 `email` 与调用者比对（"只能吊销自己的"），Scan 在这条路径上既慢又容易写成"扫到就删"。**唯一性部分是 Codex 审查 2026-08-11 P2-7 补的**——DynamoDB 的 GSI **不提供唯一约束**，而原方案的"生成 3000 个没重复"只证明了随机源没坏，不构成线上唯一性保证（8 位 base62 ≈ 47.6 bit，生日碰撞在几万把 Key 量级仍是小概率但非零）。三条补救见下 |
| B | **先读开关（强一致），关则短路；再读 Key（强一致）**——两次独立 `GetItem`，不合并 | spec §5.1 只说"每请求查表"。**这一条是 Codex 审查 2026-08-11 P2-6 改的**：原方案写"同一次 `BatchGetItem` 拿两条，是同一时刻的原子快照"，两处都错。① `BatchGetItem` 是多个 `GetItem` 的并行 wrapper，`ConsistentRead=True` 只保证**每项**强一致，**不提供跨项原子快照**（要原子读集得用 `TransactGetItems`）；② 更要紧的是它与我自己定的"关闸时不查 Key"**自相矛盾**——一次 BatchGet 必然把 Key 行一起请求了。取舍：关闸时 1 次读、放行时 2 次读（原方案恒 1 次）。为多出的那次读换回真正的短路语义与自洽的成本论证，值得 |
| C | `/api/me` 新增 `features.api_key`，**是三态对象不是布尔** | spec §5.1.1 要求"组件未部署时 API Key 页面必须显式 disabled"。判据必须由**后端派生**（哨兵行可读性 + 其 `enabled` 值），不能让前端读 config.ini。**三态是 Codex 审查 2026-08-11 P1-5 改的**：原方案是单布尔，而首次部署强制把哨兵行建成 `enabled=false`，若前端按 `api_key=false` 就"不发请求、不渲染入口"，admin 将**无处点开闸**——部署流程自锁。形态定为 `{"deployed": bool, "enabled": bool}`：`deployed` 决定 UI 是否可用，`enabled` 只驱动状态提示与开关初值 |
| D | Edge 调用者校验提成**唯一实现** `deployer/functions/edge_caller.py`，panel 与 key-proxy 共用 | `44aef8d` 的 P1-1 给 panel 加了 `_edge_caller_ok()`（真机实证：同账号 principal 只要 identity policy 允许就能绕开 resource policy 直连）。key-proxy 是同一个缺陷面，抄第二份就是新的漂移源（M3-FINDINGS「别打地鼠，修那一类」）。落点见下方「为什么三个共享模块都落 `deployer/functions/`」 |
| F | 组件门禁判定 `api_key_enabled()` 落 **`deployer/functions/api_key_config.py`**，不落 `deploy_pool.py` | **Codex 审查 2026-08-11 P1-3 改的，已复现**：原方案让 `deploy_agentcore.py` 与 `deploy_key_proxy.py` 都 `import deploy_pool`，但两个脚本的实际执行目录（`site-builder/mcp/`、`site-builder/key-proxy/`）都不含 `scripts/`。实测 `cd site-builder/mcp && python3 -c 'import deploy_pool'` → `ModuleNotFoundError`，即两个部署脚本会在任何 AWS 调用**之前**崩。落 `functions/` 后三个脚本都能 `sys.path.insert` 同一个相对路径（`deploy_pool.py` 现成的 `HERE.parent / "auth"` 就是这个形态），且它天然进 Lambda/容器打包 |
| E | `keygen.py` 与 `keystore.py` 同样落 `deployer/functions/`，而不是 `key-proxy/` | 同 D 的落点理由，**self-review 期改的**。两条推力：① `panel/tests/test_deploy_panel_contract.py:43-44` 的传递闭包只搜 `deployer/functions` 与 `auth`，放 key-proxy 会迫使我**加宽一条既有安全断言的搜索路径**——"改断言让它通过"是本项目最危险的操作方向（M3-FINDINGS §2.16）；② 这两个模块**两个组件都要用**（panel 建 Key/改开关，key-proxy 验 Key/读开关），而哨兵行的形态（`enabled` 必须是布尔 `True`）必须只有一个定义，否则写入侧写字符串、读取侧按布尔判，症状是"控制台显示开着但所有 Key 都 401"且两侧单测各自都绿 |

---

## 与新基线（`44aef8d`）的衔接

`44aef8d`（M3 的 Codex 审查 7 项修复）动了 M4 要碰的每个文件。**已核对的四个衔接点**，实施期直接按这里的结论做，不要重新调研：

1. **`ops_log.record()` 的 SK 已是 `{ts}#{actor}#{uniq}`**（P2-1）。Key 创建/吊销/开关三个动作会在同一 target 上高频写，正需要这个修复——**直接用现成的 `record()`，不要自己拼 SK**。
2. **前端版本前缀已改内容指纹**（P2-2，`deploy_panel.frontend_content_version()`）。M4 改 `pageKeys()` 后重跑 `deploy_panel.py` 会自动得到新前缀，**不要**手动改 `console_version`（留空即走指纹）；但**必须不带 `--skip-frontend`** 才会上传。同前缀不同内容会被脚本拒绝，这是预期行为。
3. **panel `handler.py` 已有 ⓪ 传输层校验 `_edge_caller_ok()`**（P1-1），环境变量 `EDGE_ROLE_ID` 由 `deploy_panel.edge_role_id()` 现查 IAM 下发。M4 按补充 D 把它提成共用模块，并给 panel 加"不得再有自己的 callerId 解析"的断言。
4. **`verify_deployed_components.py` 已是 36/36**，第 ⑤ 段含 `_verify_direct_invoke_is_rejected()` 反向闸门（真打一次直连，当前身份无权限时明确 SKIP 而非 PASS）。M4 的第 ⑧ 段照它的形态给 key-proxy 也写一条。

---

## 文件结构

**新建：**

> **为什么四个共享模块都落 `deployer/functions/`**（`edge_caller.py`、`keygen.py`、`keystore.py`、`api_key_config.py`）：三条理由叠加，与 `ops_log.py` 当年的落点决定同源（M3-FINDINGS §2.14）。
> ① deployer 的 Lambda 打包**整个 `functions/` 目录**，所以放这里对 deployer 侧零成本；
> ② panel / key-proxy 都已有"构建时复制"机制（`COPY_FILES`），复制源目录本就包含它；
> ③ **`panel/tests/test_deploy_panel_contract.py:43-44` 的传递闭包只搜 `deployer/functions` 与 `auth`**。放这两个目录之外，就得去加宽那条既有安全断言的搜索路径——本项目已记录过"放宽断言让它通过"如何让断言永久失效（M3-FINDINGS §2.16）。
> ④（`api_key_config.py` 专属）**部署脚本从三个不同目录执行**（`site-builder/`、`site-builder/mcp/`、`site-builder/key-proxy/`），只有 `functions/` 是三者都能用同一个相对路径 `sys.path.insert` 到的位置。放 `scripts/` 会让后两个脚本 `ModuleNotFoundError`（Codex P1-3 已实测复现）。
>
> 推论：**key-proxy 自己的 `COPY_FILES` 闭包断言也要用同样的两个搜索目录**，这样两个组件的复制清单断言形态一致，将来再加共享模块时两边都会自动变红。

| 文件 | 职责 |
|---|---|
| `site-builder/deployer/functions/edge_caller.py` | **唯一**的"IAM 调用者是否 Edge 执行角色"判定（`caller_is_edge(event) -> bool`）。panel 与 key-proxy 构建时复制 |
| `site-builder/deployer/tests/test_keygen.py` | Key 生成/哈希的单测（**随模块落 deployer 包**，跑法 `cd site-builder/deployer && .venv/bin/pytest tests -q`） |
| `site-builder/deployer/tests/test_edge_caller.py` | 判定矩阵 + 四种绕过形态负测（`{id}EVIL:s` / `AIDAX:{id}` / `x{id}:s` / 小写） |
| `site-builder/key-proxy/handler.py` | Function URL 入口：⓪ Edge 调用者 → ① 开关 → ② Key → ③ 换 token → ④ 透明转发 |
| `site-builder/deployer/functions/keystore.py` | `site-api-keys` 的**唯一**访问层（panel 与 key-proxy 都复制）：`lookup()` / `touch_last_used()`（key-proxy 用）、`create()` / `list_for()` / `revoke()` / `switch_state()` / `set_switch()`（panel 用）。落点理由同 `keygen.py`，另见 Task 3 |
| `site-builder/key-proxy/machine_token.py` | `client_credentials` 换 token + 进程内缓存至**过期前 5 分钟**；`invalidate()` 供 502 重试路径 |
| `site-builder/deployer/functions/keygen.py` | Key 生成与哈希的**唯一**实现：`new_key() -> (plaintext, key_hash, key_id, prefix)`、`hash_key(plaintext)`、`SWITCH_PK`。panel 与 key-proxy 构建时各自复制（落点理由见本表上方的说明框） |
| `site-builder/key-proxy/deploy_key_proxy.py` | 幂等部署：role + Lambda + Function URL(AWS_IAM 仅 edge role) + `mcp` route + `__switch__` 哨兵行（首次创建为 `enabled=false`） |
| `site-builder/key-proxy/tests/conftest.py` | moto 表夹具（api-keys + routing）+ ENV |
| `site-builder/deployer/tests/test_keystore.py` | 开关短路顺序、fail-closed 矩阵、**不缓存**的行为断言（随模块落 deployer 包） |
| `site-builder/key-proxy/tests/test_machine_token.py` | 缓存**确实复用** + 提前换新 + `invalidate` 后重取 |
| `site-builder/key-proxy/tests/test_handler.py` | 六步顺序、透明转发（头透传/body 不改写/SSE 原样）、错误码与文案不泄露 |
| `site-builder/key-proxy/tests/test_no_module_level_cache.py` | AST 结构性：无模块级可变容器持有 Key/开关、无 `lru_cache` 装饰授权查询 |
| `site-builder/key-proxy/tests/test_deploy_key_proxy_contract.py` | 组件门禁跳过分支、Function URL 两条语句、环境变量无明文密钥、哨兵行首次 `false` |
| `site-builder/panel/tests/test_keys_api.py` | Key 端点授权矩阵 + 响应不含 hash + 明文不进日志 |
| `site-builder/scripts/verify_api_key_e2e.py` | **真机闸门**：创建 → 静态 Header 直连完成一次真实部署 → 吊销后立即 401 → 关闸 → 开闸恢复 → on-behalf 冒充负测 |

**修改：**

| 文件 | 改动 |
|---|---|
| `site-builder/deployer/infra/app.py` | 新增 `site-api-keys` 表（PK `key_hash`，GSI `email-index` / `keyid-index`，`RemovalPolicy.RETAIN`） |
| `site-builder/deployer/tests/test_infra_tables.py` | 新表与两个 GSI 的 CDK 断言 + RETAIN 断言 |
| `site-builder/scripts/deploy_pool.py` | 新增 `ensure_resource_server()` 与 `api_key_enabled()`；**`_ensure_clients()` 签名加 `include_machine` / `machine_scopes` 两个 kwarg 并透传给 `client_configs`**（现签名只到 `idp_name`，`client_configs` 的 `include_machine` 分支目前没有调用方）；`_store_client_secrets` 的循环加 machine；`main()` 在有 `[ApiKey]` 段时建 resource server；回填提示补 `machine_client_id` |
| `site-builder/mcp/deploy_agentcore.py` | `allowedClients` 与 `requestHeaderAllowlist` 从**硬编码单值**改为按 `[ApiKey]` 段派生；**`environmentVariables` 增加 `MACHINE_CLIENT_ID`**（有 `[ApiKey]` 段时取 `[Cognito] machine_client_id`，否则空串——**漏了这一条则容器内 `_machine_client_id()` 恒为空、所有 API Key 调用被 fail-closed 拒绝**，Codex 审查 2026-08-11 P1-2b）；`_BUILD_INPUTS` 与 `build_and_push` 复制清单不变（server.py 改动已被指纹覆盖） |
| `site-builder/mcp/server.py` | `_caller_email()` 新增 on-behalf 路径；新增 `_machine_client_id()`（每次读环境变量） |
| `site-builder/mcp/tests/test_tools.py` | on-behalf 正负测（**含"普通 OAuth 用户加头冒充他人"必须被拒**） |
| `site-builder/panel/handler.py` | `ROUTES` 加 5 条；`_dispatch` 加分支；`_edge_caller_ok` 改为委托 `edge_caller.caller_is_edge` |
| `site-builder/panel/api.py` | `do_list_keys` / `do_create_key` / `do_revoke_key` / `do_get_key_switch` / `do_set_key_switch`；`do_me` 加 `features` |
| `site-builder/panel/deploy_panel.py` | 复制清单加 **`edge_caller.py` + `keystore.py` + `keygen.py` + `api_key_config.py`**（四个都在 `deployer/functions/`，`_build_zip` 现成的两目录查找即可命中）；role 加 api-keys 表读写与两个 GSI Query；环境变量加 `API_KEYS_TABLE`。**漏 `keystore.py` 会让契约测试当场红，放宽它则真机 panel 全部 500**（Codex 审查 2026-08-11 P1-4） |
| `site-builder/panel/frontend/app.js` | `pageKeys()` 实现；导航去掉"规划中"；admin 页加开关；**按 `features.api_key.deployed` 决定 disabled**（不是 `.enabled`——见 Task 9） |
| `site-builder/panel/tests/test_frontend_contract.py` | Key 页面的静态契约（明文只显示一次的警告、复制按钮、不请求不存在的接口） |
| `site-builder/panel/tests/test_handler.py` | 新端点的六步前置继承（CSRF / 面板会话 / admin-only） |
| `site-builder/panel/tests/test_deploy_panel_contract.py` | 复制清单与 role 权限的推导式断言（沿用 §2.18 的 AST 交叉核对形态） |
| `router/infrastructure/lambda/origin_request.py` | **不改 `PLATFORM_SUBDOMAINS`**（决定 9）。仅在 `PLATFORM_SUBDOMAINS` 注释里补一句"mcp 故意不在此列，理由见 M4 计划" |
| `router/infrastructure/lambda/test_edge_auth.py` | `mcp` 子域**不是**平台路由的负测（保留 cookie 必须被剥除） |
| `site-builder/scripts/verify_deployed_components.py` | 新增第 ⑧ 段：key-proxy 产物 + Function URL 两条语句 + 环境变量无明文密钥 + 直连必须 403 + `mcp` route 形态 + `allowedClients`/allowlist 含新值 + 哨兵行存在 |
| `site-builder/config.ini.example` | `[ApiKey]` 段**删掉 `enabled` 键**（改为哨兵行），补 `mcp_subdomain` 说明与"开关在控制台"的指引 |
| `site-builder/DEPLOY.md` | 新阶段「⑤c API Key 组件（可选）」+ 应急旁路（aws CLI 直改哨兵行）+ 三处门禁的部署顺序 |
| `CLAUDE.md` | key-proxy 包 venv 归属；部署命令补 `deploy_key_proxy.py`；架构图补 ⑦ |
| `site-builder/docs/client-setup.md` | Quick Desktop Remote MCP + 静态 Header 直连章节；stdio 代理降级标注 |
| `site-builder/scripts/gen_onboarding.py` | 组件已部署时输出 API Key 接入指引 |
| `.superpowers/sdd/progress.md` | 按任务追加记录 |

---

## 任务顺序与依赖

```
Task 1 (edge_caller 提取 + panel 改为委托)          ← 先做：Task 5/8 都依赖它
Task 2 (keygen + api-keys 表 CDK)
  → Task 3 (keystore：表访问唯一收口，一次写全两侧用的函数)
      ├→ Task 4 (machine_token) → Task 5 (key-proxy handler 组装)
      └→ Task 6 (panel Key 端点，只消费 keystore)
Task 7 (三处组件门禁：pool / agentcore / server 信任规则)   ← 与 2-6 并行
Task 5,7 → Task 8 (deploy_key_proxy.py)
Task 6 → Task 9 (前端 Key 页面 + 开关 UI)
Task 8,9 → Task 10 [真机] 分四步部署 + verify 第 ⑧ 段
Task 10 → Task 11 [真机] verify_api_key_e2e.py（六场景 + 冒充负测）
Task 11 → Task 12 (全量回归 + 文档收尾)
```

**subagent 写范围互斥**：`deployer/functions/edge_caller.py`（Task 1 独占）、`deployer/functions/keygen.py`（Task 2 独占）、`deployer/functions/keystore.py`（Task 3 独占）、`mcp/server.py`+`deploy_agentcore.py`+`deploy_pool.py`（Task 7 独占）、`panel/*`（Task 6 → Task 9 顺序执行）、`key-proxy/*`（Task 4 → 5 → 8 顺序）、`infra/app.py`（Task 2 独占）、本 plan 与 spec（仅控制器修改）。

**注意 Task 3 与 Task 6 的依赖方向**：`keystore.py` 由 Task 3 建立并**一次写全**（key-proxy 侧的 `lookup`/`touch_last_used` 与 panel 侧的 CRUD/开关都在其中），Task 6 只消费不修改。这样"哨兵行形态"与"表访问收口"两个不变量都只有一次落地机会。

**[真机] 步骤集中在 Task 10-11**，且**执行前必须停下来征得用户同意**。Task 1-9 全部可在 moto 上完成。

---

## 部署顺序（Task 10 的四步，不可调换）

spike 已实证"先加 client、后改 server"的中间态安全（machine client 已进 `allowedClients` 但 server 未改造时，机器 token 调工具得到"无法识别调用者身份"，拿不到任何数据）。因此顺序是：

```
① deploy_pool.py       建 resource server + machine client（此时无人能用它）
② deploy_agentcore.py  allowedClients + allowlist（此时机器 token 能过网关但拿不到数据）
③ MCP server 改造      on-behalf 路径生效（此时只有持 machine secret 者能用，而只有 key-proxy 有）
④ deploy_key_proxy.py  key-proxy 上线 + 哨兵行 enabled=false（此时仍无人能用，要 admin 开闸）
⑤ 控制台开闸           admin 打开开关
```

任一步停下都不产生提权窗口。**②③ 之间与 ③④ 之间都可以过夜**。

---

## Task 1: 把 Edge 调用者校验提成唯一实现

**Files:**
- Create: `site-builder/deployer/functions/edge_caller.py`
- Create: `site-builder/deployer/tests/test_edge_caller.py`
- Modify: `site-builder/panel/handler.py`（`_edge_caller_ok` 改为委托）
- Modify: `site-builder/panel/deploy_panel.py`（复制清单加 `edge_caller.py`）
- Modify: `site-builder/panel/tests/test_handler.py`（补"panel 不得自己解析 callerId"）
- Modify: `site-builder/panel/tests/test_deploy_panel_contract.py`（复制清单断言）

**Interfaces:**
- Produces:
  - `caller_is_edge(event: dict) -> bool` —— 从 `event["requestContext"]["authorizer"]["iam"]["callerId"]` 取 AROA 段，与环境变量 `EDGE_ROLE_ID` 按 `:` 边界比较；`EDGE_ROLE_ID` 缺失/空 → **返回 False 并记 ERROR 日志**
  - `EDGE_ROLE_ID_ENV = "EDGE_ROLE_ID"` —— 环境变量名常量（部署脚本引用它，不再各自写字符串字面量）
- Consumes: 无（纯函数 + `os.environ` + `logging`）

**为什么提取而不是让 key-proxy 抄一份**：`44aef8d` 的 P1-1 已在 panel 落了一份实现，key-proxy 是同一个缺陷面（同账号 principal 能绕开 resource policy 直连）。本项目反复栽在"同一不变量被手抄多份、漏判一处即失效"（M3-FINDINGS「别打地鼠，修那一类」；§2.18 的 panel 漏 `ConditionCheckItem` 就是手抄 MCP 权限清单时漏的）。

**落点为什么在 `deployer/functions/`**：与 `ops_log.py` 完全相同的理由（M3-FINDINGS §2.14）——deployer 的 Lambda 打包**整个 `functions/` 目录**，而 panel / key-proxy 是构建时复制。放 `panel/` 会让 key-proxy 复制不到；放任一侧都会让另一侧成为"跨包 import"。

**`EDGE_ROLE_ID` 缺失必须拒绝**：`44aef8d` 已写明"配置缺失就不检查"恰是该缺陷的原始形态。提取时**不得**顺手把它改成"缺失就跳过"。

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_edge_caller.py`：

```python
"""Edge 调用者判定（唯一实现）。

**这些用例必须能在缺陷存在时变红**：Step 2 先确认全部 FAIL，Step 4 确认转绿，
Step 5 再逐条注入缺陷确认变红（本项目"验证本身无效"栽过多次）。
"""
import pytest

import edge_caller

# 测试用的假 RoleId。**拼接而不是写成一个字面量**：Code Defender 的
# HARD_CODED_SECRET 规则按 `AROA` 前缀 + 长度匹配，整串写出来会被拦下
# （本计划提交时实际发生过）。它的 remediation 建议是往 secrets.allowed
# 里加例外——那是放宽扫描器，本项目明令不走这个方向。
# 既有的 panel/tests/test_handler.py 里有一份整串写法（先于此规则生效时提交的），
# 实施 Task 1 时可顺手改成同样的拼接形态。
ROLE_ID = "AROA" + "EDGEROLEID" + "XXXXXX"


def _event(caller_id):
    return {"requestContext": {"authorizer": {"iam": {"callerId": caller_id}}}}


def test_real_edge_caller_is_accepted(monkeypatch):
    """真机抓到的形态：{RoleId}:{session_name}，session name 含区域前缀。"""
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(
        _event(f"{ROLE_ID}:us-east-1.ApplicationWebRouterStack-EdgeFn-abc123"))


def test_missing_env_rejects_everything(monkeypatch, caplog):
    """**配置缺失不得退化成"不检查"**——那正是 P1-1 的原始形态。"""
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False
    assert any("EDGE_ROLE_ID" in r.message for r in caplog.records), \
        "缺配置必须留一行可告警的 ERROR，否则整站 403 无从排查"


@pytest.mark.parametrize("empty", ["", "   "])
def test_blank_env_rejects_everything(monkeypatch, empty):
    monkeypatch.setenv("EDGE_ROLE_ID", empty)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False


@pytest.mark.parametrize("evil", [
    f"{ROLE_ID}EVIL:us-east-1.x",   # startswith 骗得过
    f"AIDAX5GB:{ROLE_ID}",          # in 骗得过（把真 id 放进 session name 段）
    f"x{ROLE_ID}:s",                # 前缀污染
    ROLE_ID.lower() + ":s",         # 大小写：AROA 段是大写敏感的
    ROLE_ID,                        # 没有 session 段（不是 assumed-role 形态）
    "",                             # 空 callerId
])
def test_lookalike_callers_are_rejected(monkeypatch, evil):
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(_event(evil)) is False


@pytest.mark.parametrize("broken", [
    {},                                              # 没有 requestContext
    {"requestContext": {}},                          # 没有 authorizer
    {"requestContext": {"authorizer": {}}},          # 没有 iam
    {"requestContext": {"authorizer": {"iam": {}}}}, # 没有 callerId
    {"requestContext": None},                        # 显式 null（真实 payload 见过）
    {"requestContext": {"authorizer": None}},
])
def test_malformed_event_is_rejected_not_crashed(monkeypatch, broken):
    """AuthType=NONE 或平台改形态时 event 会缺这些层级——必须拒绝而不是抛异常。

    抛异常会变成 502，而 502 与 403 的运维含义完全不同（前者像故障、
    后者是策略），排查方向会被带偏。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(broken) is False
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_edge_caller.py -q`
Expected: FAIL（`ModuleNotFoundError: No module named 'edge_caller'`）。

- [ ] **Step 3: 实现 `edge_caller.py`**

把 `panel/handler.py:60-95` 的 `_edge_caller_ok` **整体搬过来**（含全部注释——那些注释记录了真机抓到的形态与"为什么不用 ARN"，是不可再生的证据），改名 `caller_is_edge`，并补上 Step 1 里 `test_malformed_event_is_rejected_not_crashed` 要求的容错（`requestContext` 显式 `None` 时 `.get` 会抛 `AttributeError`——现有实现用 `(event.get("requestContext") or {})` 已覆盖，搬迁时不要简化掉那个 `or {}`）。

模块 docstring 写清三件事：① 它是唯一实现，panel 与 key-proxy 构建时复制；② 为什么锚点是 RoleId 而不是 ARN（真机形态 + 两者永不相等）；③ 缺配置即全拒的理由。

- [ ] **Step 4: panel 改为委托**

`panel/handler.py`：
- 顶部 `import edge_caller`
- `_edge_caller_ok(event)` 改为 `return edge_caller.caller_is_edge(event)`，或直接在 ⓪ 处调用 `edge_caller.caller_is_edge(event)` 并删掉本地函数。**选后者**——留一个只有一行的包装函数会让"panel 有自己的实现"这个印象持续存在，而断言要盯的正是"panel 不再自己解析"。
- 模块 docstring 的 ⓪ 条改为指向 `edge_caller`（保留"为什么需要这一层"的说明，那是安全推理）。

`panel/deploy_panel.py`：复制清单加 `edge_caller.py`（与 `common.py` / `permissions.py` / `ops_log.py` / `session.py` 同一处）。

- [ ] **Step 5: 反向验证（逐条注入）**

对**每一条**断言注入它要防的缺陷，确认变红，再还原。逐条记录到 `.superpowers/sdd/` 的 progress：

| 注入 | 必须变红的用例 |
|---|---|
| `if not expected: return True` | `test_missing_env_rejects_everything` + 两条 blank |
| `role_id` 比较改 `caller.startswith(expected)` | `{ROLE_ID}EVIL:...` |
| 改 `expected in caller` | `AIDAX5GB:{ROLE_ID}` |
| 改 `.lower()` 两侧 | 小写那条 |
| 去掉 `or {}` 容错 | 四条 malformed |
| panel 的 ⓪ 处删掉整个调用 | panel 侧的 `test_*_direct_invoke_*`（`44aef8d` 已有） |

- [ ] **Step 6: 加"panel 不得自己解析 callerId"的结构性断言**

在 `panel/tests/test_handler.py` 追加（AST 而非文本——文本会命中注释，M3-FINDINGS §2.1 第 4 条）：

```python
def test_panel_delegates_edge_caller_check_and_has_no_own_parser():
    """panel 不得自己解析 callerId——唯一实现在 edge_caller.py。

    为什么要这条：P1-1 的判定逻辑有四个易错点（AROA 段、`:` 边界、大小写、
    缺配置即拒）。同一份逻辑存在两处时，改对一处、漏改另一处正是本项目
    反复出现的缺陷形态（M3-FINDINGS「别打地鼠，修那一类」）。
    """
    import ast
    import pathlib
    src = (pathlib.Path(__file__).parents[1] / "handler.py").read_text()
    tree = ast.parse(src)
    # ① 必须 import edge_caller
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    assert "edge_caller" in imported, "panel 必须依赖唯一实现"
    # ② 不得出现 callerId 的取值（那是自己解析的标志）
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "callerId" not in strings, \
        "panel 出现了 callerId 字面量——说明又抄了一份解析逻辑"
    # ③ 不得再有 AROA 相关的比较常量
    assert not any("AROA" in s for s in strings), "panel 不该关心 RoleId 形态"
```

**注意 ② 的边界**：`test_handler.py` 自己的夹具里有 `callerId`（构造 event 用），断言扫的是 `handler.py` 不是测试文件——不要扫错文件（M3-FINDINGS §2.10：断言不能把它要禁的东西列进自己的扫描范围）。

- [ ] **Step 7: 复制清单的推导式断言**

`panel/tests/test_deploy_panel_contract.py:37` 的 `test_copy_files_covers_every_local_module_panel_imports` **已核对是真的传递闭包**（从 `PANEL.glob("*.py")` 出发，在 `deployer/functions` 与 `auth` 两个目录里解析 import 并入队递归，最后 `needed - set(dp.COPY_FILES)`）。所以给 `handler.py` 加 `import edge_caller` 后它会**自动变红**，提示 `edge_caller.py` 不在 `COPY_FILES` 里——这正是期望行为。

**先跑一次确认它真的红了**（这是"断言确实在盯着"的证据，不是走过场），再把 `edge_caller.py` 加进 `deploy_panel.COPY_FILES`（第 66 行的元组）。

Run: `cd site-builder/panel && ../deployer/.venv/bin/pytest tests/test_deploy_panel_contract.py -q`
Expected（加 import 之后、改 COPY_FILES 之前）：FAIL，报 `这些模块被 import 但不在复制清单: ['edge_caller.py']`。

**注意闭包的搜索目录只有两个**（`deployer/functions` 与 `auth`）。`edge_caller.py` 放在 `deployer/functions/` 正好被覆盖——这也是补充 D 选这个落点的一个附带好处（放别处就要同时改这个断言的搜索路径，而改断言以让它通过是最危险的操作方向）。

Run: `cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`

- [ ] **Step 8: 全量回归 + 提交**

```bash
cd site-builder/deployer && .venv/bin/pytest tests -q
cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q
```

提交（按 Global Constraints 的三步）：`refactor(m4): Edge 调用者校验提成唯一实现，panel 改为委托`

---

## Task 2: Key 生成/哈希 + `site-api-keys` 表

**Files:**
- Create: `site-builder/deployer/functions/keygen.py`
- Create: `site-builder/deployer/tests/test_keygen.py`
- Create: `site-builder/key-proxy/tests/conftest.py`（Task 3 起用；本 Task 先建好夹具）
- Modify: `site-builder/deployer/infra/app.py`
- Modify: `site-builder/deployer/tests/test_infra_tables.py`
- Modify: `CLAUDE.md`（key-proxy 包借 deployer venv 的约定）

**Interfaces:**
- Produces（`keygen.py`）：
  - `new_key() -> NewKey` —— `NamedTuple(plaintext, key_hash, key_id, prefix)`
  - `hash_key(plaintext: str) -> str` —— SHA-256 hex（**校验端唯一入口**）
  - `PLAINTEXT_RE` —— `^sk-[0-9A-Za-z]{16}$`，供入口形态校验（**先验形态再查库**：形态不对直接拒，不产生一次 DynamoDB 读，也避免把任意长字符串当 key 去 hash）
  - `SWITCH_PK = "__switch__"` —— 哨兵行主键值（keystore 与 deploy 脚本共用同一常量）
  - `ALPHABET` —— base62 字符集
- Consumes: `secrets`、`hashlib`

**为什么 `keygen.py` 物理放 `deployer/functions/`**：创建端在 panel、校验端在 key-proxy，算法只能有一份，所以它必须落在一个**两个组件的复制清单都能覆盖**的地方。详细理由见「文件结构」上方的说明框（补充 E）——关键一条是 panel 的传递闭包断言只搜 `deployer/functions` 与 `auth`，放别处要加宽既有安全断言。

**`key_id` 必须独立随机，不得由 `key_hash` 派生**（spec §5.1）：派生会让它变成哈希预言机——拿到 `key_id` 就能验证对 `key_hash` 的猜测。

**`key_id` 的唯一性必须由写入路径保证**（Codex P2-7）。**不改 spec 定稿的 8 位长度**——它是给人看/给人粘的标识符，加长会牺牲那个用途，而正确的修法本来就在写入侧而不是长度侧（加长只是把碰撞概率压小，不是消除，仍然需要下面第 2、3 条来处理"万一"）。三条一起做：

1. **创建时检测并重试**：`keystore.create()` 先按 `keyid-index` Query 该 `key_id`，命中则重新生成（≤5 次，全失败则抛错而不是硬写下去）。这不是原子的（GSI 最终一致 + 无条件约束），所以还需要第 2 条兜底。
2. **吊销时 Query 返回行数 ≠ 1 一律 fail-closed**：0 行 → 与"别人的 Key"同一句话（不泄露存在性）；**≥2 行 → 拒绝并记 ERROR 日志**，绝不"取第一行删掉"——那会误吊销别人的 Key（M3-FINDINGS 记过 prefix 匹配误删的同类风险）。
3. **吊销的 `UpdateItem` 带条件表达式** `key_id = :kid AND email = :em`：Query 到 `key_hash` 之后的这一步是真正落地的写，条件必须重新断言两个字段。理由与 `sites_snapshot_guard` 同源——Query 与 Update 之间有窗口，而 GSI 是最终一致的（读到的行可能已经被改过）。

**`__switch__` 与真 hash 不可能碰撞**：真 hash 是 64 位小写 hex，`__switch__` 含下划线。这条要有断言（而不是靠"显然"）——将来若有人把 hash 换成 base64 形态，`_` 就在字符集里了。

- [ ] **Step 1: 写失败测试**

创建 `site-builder/key-proxy/tests/conftest.py`（本 Task 先建好，Task 3 起真正用它）：照抄 `site-builder/panel/tests/conftest.py` 的整体形态，差异：
① `sys.path` 插入 `key-proxy` 目录与 `deployer/functions`（后者提供 `keygen` / `edge_caller` / `ops_log`）；
② ENV 需 `API_KEYS_TABLE` / `ROUTING_TABLE` / `AGENTCORE_ENDPOINT` / `COGNITO_DOMAIN` / `MACHINE_CLIENT_ID` / `MACHINE_SECRET_PARAM` / **`MACHINE_SCOPE`** / `EDGE_ROLE_ID` / `AWS_DEFAULT_REGION`（`MACHINE_SCOPE` 是 Codex P1-2a 补的，见 Task 4）；
③ 建表清单只需 `site-api-keys`（PK `key_hash`，两个 GSI）与 routing。

创建 `site-builder/deployer/tests/test_keygen.py`（跑法是 deployer 包的 venv；**已核对** `deployer/tests/conftest.py:10` 把 `functions/` 插进了 `sys.path`，所以 `import keygen` 直接可用）：

```python
"""Key 生成与哈希。**算法只有一份**（创建端 panel 复制本模块）。"""
import re

import keygen


def test_plaintext_shape_is_sk_plus_16_base62():
    p = keygen.new_key().plaintext
    assert re.fullmatch(r"sk-[0-9A-Za-z]{16}", p), p
    assert keygen.PLAINTEXT_RE.fullmatch(p)


def test_hash_is_sha256_hex_of_exact_plaintext():
    import hashlib
    k = keygen.new_key()
    assert k.key_hash == hashlib.sha256(k.plaintext.encode()).hexdigest()
    assert len(k.key_hash) == 64 and k.key_hash.islower()


def test_key_id_is_independent_of_hash():
    """**不得由 hash 派生**——派生会让 key_id 变成哈希预言机。

    判据不能只看"两个值不相等"（那对任何派生都成立）。做法：固定 hash
    不可能固定（明文随机），所以反过来——同一明文重复 new_key 是不可能的，
    改为对 key_id 与 key_hash 做统计独立性的**结构**检查：
    key_id 不是 key_hash 的任何前缀/后缀/子串，且不在 hash 的字符集里
    （hash 只有 [0-9a-f]，key_id 含大写的概率极高）。
    再加一条源码级断言（见 test_keygen_source_does_not_derive_id_from_hash）。
    """
    for _ in range(200):
        k = keygen.new_key()
        assert k.key_id not in k.key_hash
        assert k.key_hash not in k.key_id
        assert len(k.key_id) == 8


def test_keygen_source_does_not_derive_id_from_hash():
    """源码级：key_id 的赋值表达式不得引用 key_hash / sha256 / digest。

    行为断言抓不到"取 hash 的第 9-16 位当 key_id"这种派生（子串检查会抓到，
    但"取 hash 再另做一次 hash"就抓不到了）。用 AST 定位 key_id 的来源。
    """
    import ast
    import pathlib
    src = (pathlib.Path(keygen.__file__)).read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "new_key")
    # 找出所有形如 key_id = <expr> 的赋值，检查 expr 里不出现这些名字
    banned = {"key_hash", "sha256", "digest", "hexdigest", "h"}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if "key_id" in targets:
                names = {n.id for n in ast.walk(node.value)
                         if isinstance(n, ast.Name)}
                names |= {n.attr for n in ast.walk(node.value)
                          if isinstance(n, ast.Attribute)}
                assert not (names & banned), \
                    f"key_id 的来源引用了 {names & banned}——那是哈希预言机"


def test_prefix_is_sk_plus_first_4_and_leaves_12_chars_secret():
    """展示用前缀只暴露 4 位，剩余 12 位（71.5 bit）仍是秘密（spec §5.1）。"""
    k = keygen.new_key()
    assert k.prefix == k.plaintext[:7]          # "sk-" + 4
    assert len(k.prefix) == 7
    assert k.plaintext[7:] not in k.prefix


def test_entropy_no_collision_in_bulk():
    """随机源自检。**这条不构成线上唯一性保证**（Codex P2-7）——

    它只证明随机源没坏（比如没退化成常量或低位固定）。8 位 base62 ≈ 47.6 bit，
    线上唯一性由 keystore.create() 的"Query 检测 + 重试"与吊销侧的
    "行数 ≠ 1 即 fail-closed"共同保证，见 test_keystore.py 的对应用例。
    """
    ks = [keygen.new_key() for _ in range(3000)]
    assert len({k.plaintext for k in ks}) == 3000
    assert len({k.key_hash for k in ks}) == 3000
    assert len({k.key_id for k in ks}) == 3000


def test_switch_sentinel_cannot_be_produced_by_any_real_hash():
    """哨兵行主键必须落在真 hash 的字符集之外。

    不是"显然成立"就不用断言：将来若有人把 hash 换成 base64（`_` 在字符集里）
    或 uuid 形态，这条会立刻红——那时哨兵行就可能被一把精心构造的 Key 命中，
    等于用户能自己写平台开关。
    """
    import re as _re
    assert not _re.fullmatch(r"[0-9a-f]{64}", keygen.SWITCH_PK)
    assert keygen.SWITCH_PK == "__switch__"
    # 反向：随机取样的真 hash 全部匹配 hex64（证明上一条的前提成立）
    for _ in range(50):
        assert _re.fullmatch(r"[0-9a-f]{64}", keygen.new_key().key_hash)


def test_hash_key_rejects_nothing_but_is_only_called_after_shape_check():
    """hash_key 本身不做形态校验（它只是哈希函数），形态校验是 PLAINTEXT_RE
    的职责。这条用例锁定分工，防止后人把校验塞进 hash_key 又在别处漏掉。"""
    assert keygen.hash_key("anything") == keygen.hash_key("anything")
    assert not keygen.PLAINTEXT_RE.fullmatch("anything")
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_keygen.py -q`
Expected: FAIL（`ModuleNotFoundError: No module named 'keygen'`）。

- [ ] **Step 3: 实现 `keygen.py`**

用 `secrets.choice(ALPHABET)` 逐位取（**不要** `secrets.token_urlsafe` 再截断——那会引入 `-`/`_` 且截断后熵不可控）。`ALPHABET` 是 `string.digits + string.ascii_letters`（62 字符，16 位 = 95.27 bit）。

`key_id` 独立循环再取 8 位（8 × log2(62) = 47.6 bit，够做非秘密标识符）。

**模块不得 import boto3 或读环境变量**：它是纯算法模块，被 panel 与 key-proxy 两侧复制。带上 I/O 依赖会让两侧的复制清单闭包多牵进无关模块。

- [ ] **Step 4: 确认转绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`（跑整包，确认没影响既有 289 个）

- [ ] **Step 5: 反向验证**

| 注入 | 必须变红 |
|---|---|
| `key_id = key_hash[:8]` | `test_key_id_is_independent_of_hash` + `test_keygen_source_does_not_derive_id_from_hash` |
| `key_id = hashlib.sha256(key_hash.encode()).hexdigest()[:8]` | **只有** source 那条（这正是它存在的理由——行为断言抓不到） |
| 明文改 15 位 | shape + entropy |
| `ALPHABET` 加 `-_` | shape（`PLAINTEXT_RE` 不含它们） |
| `prefix = plaintext[:11]` | `test_prefix_*` |
| `SWITCH_PK = "0"*64` | `test_switch_sentinel_*` |

- [ ] **Step 6: `site-api-keys` 表（CDK）**

`site-builder/deployer/infra/app.py` 在 `session_codes` 之后追加：

```python
        # 二期 M4：API Key。PK 是 **key_hash**（SHA-256(明文)）而不是 key_id
        # ——库被读走时攻击者只拿到哈希，反推不出可用的 Key（spec §5.1）。
        # RETAIN 与 admins/ops_log 同理：这是凭证表，误删等于全体 Key 用户断服，
        # 而且**无法恢复**（服务端不存明文，用户手里的 Key 再也对不上任何行）。
        api_keys = ddb.Table(
            self, "ApiKeys", table_name="site-api-keys",
            partition_key=ddb.Attribute(name="key_hash",
                                        type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN)
        # 控制台按人列 Key。
        api_keys.add_global_secondary_index(
            index_name="email-index",
            partition_key=ddb.Attribute(name="email",
                                        type=ddb.AttributeType.STRING))
        # **吊销必须靠它**（计划级补充 A）：DELETE /api/keys 拿到的是 key_id，
        # 而 PK 是 key_hash。没有这个 GSI 就只能全表 Scan，而吊销路径必须先
        # 查到该行的 email 与调用者比对（"只能吊销自己的"）——Scan 在这条
        # 路径上既慢又容易写成"扫到就删"。
        api_keys.add_global_secondary_index(
            index_name="keyid-index",
            partition_key=ddb.Attribute(name="key_id",
                                        type=ddb.AttributeType.STRING))
```

**注意**：哨兵行 `__switch__` 没有 `email` / `key_id` 属性，所以它**不会出现在任何 GSI 里**（DynamoDB 的 GSI 只投影有该键的 item）。这是好事——按人列 Key 时哨兵行天然不出现，不需要在应用层过滤。**这条要写成断言**（Task 3 Step 1），否则将来有人给哨兵行加个 `email` 字段就会让它出现在某人的 Key 列表里。

- [ ] **Step 7: CDK 断言**

`site-builder/deployer/tests/test_infra_tables.py` 追加（沿用该文件既有的 template 断言形态）：表存在、PK 是 `key_hash`、两个 GSI 名与键、`DeletionPolicy: Retain`（**不是** Delete——这条要能在改成 DESTROY 时变红）。

Run: `cd site-builder/deployer && PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`

- [ ] **Step 8: `CLAUDE.md` 补 venv 约定 + 提交**

在测试命令块加：
```
cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q   # key-proxy 无自己的 venv，借 deployer 的（需 moto+boto3）；keygen/edge_caller 的单测在 deployer 包里（模块落 functions/）
```

提交：`feat(m4): Key 生成/哈希唯一实现 + site-api-keys 表（PK=key_hash，两个 GSI）`

---

## Task 3: keystore——`site-api-keys` 的唯一访问层（不缓存）

**Files:**
- Create: `site-builder/deployer/functions/keystore.py`
- Create: `site-builder/deployer/tests/test_keystore.py`
- Create: `site-builder/key-proxy/tests/test_no_module_level_cache.py`

**Interfaces:**
- Produces（**这张表的全部访问都在本模块**，panel 与 key-proxy 都复制它）：
  - `Verdict` —— `NamedTuple(ok: bool, email: str, key_id: str, reason: str)`；`reason` 只用于**日志**，不回给客户端
  - `lookup(plaintext: str) -> Verdict` —— 形态校验 → **强一致读开关（关即短路返回）→ 强一致读 Key**（key-proxy 用）
  - `touch_last_used(key_hash: str, key_id: str) -> None` —— 节流更新（每 Key 每小时至多一次写），失败只记日志不影响转发（key-proxy 用）
  - `create(email, *, name) -> dict` —— 生成 + **`key_id` 唯一性重试（≤5 次）** + `PutItem` with `attribute_not_exists(key_hash)`
  - `list_for(email) -> list[dict]` / `revoke(key_id, *, actor) -> dict` —— revoke 经 `keyid-index` Query，**行数 ≠ 1 一律 fail-closed**，`UpdateItem` 带 `key_id + email` 条件
  - `switch_state() -> tuple[bool, bool]` —— 返回 `(deployed, enabled)`。**不是单个 `switch_enabled()`**（Codex P1-5）：`deployed` = 哨兵行可读，`enabled` = 该行 `enabled is True`。两者必须分开返回，否则控制台无法区分"未部署"与"已部署但关闸"，而首次部署后正是后者
  - `set_switch(enabled: bool, *, actor: str) -> None`（panel 与部署脚本用）
  - `SWITCH_PK` —— 从 `keygen` 再导出（**同一个常量，不重新定义**）
- Consumes: `keygen.{PLAINTEXT_RE, hash_key, new_key, SWITCH_PK}`、`ops_log.record`、`boto3` DynamoDB

**为什么落 `deployer/functions/` 且是唯一访问层**（self-review 期修正，与补充 E 同源）：
- panel 需要 `switch_state` / `set_switch` / CRUD，key-proxy 需要 `lookup` / `touch_last_used`。**两个组件都要**，所以必须落在两边复制清单都覆盖的目录（panel 的传递闭包只搜 `deployer/functions` 与 `auth`）。
- 更重要的是**哨兵行的形态只能有一个定义**：panel 写它、key-proxy 读它。拆成两个模块就等于把"`enabled` 必须是布尔 `True`"这条不变量写两遍——而写入侧写成字符串、读取侧按布尔判，症状是"控制台显示开着但所有 Key 都 401"，且两侧单测各自都绿。这正是本项目反复出现的缺陷形态（M3-FINDINGS「别打地鼠，修那一类」）。
- 同一理由下，`permissions.py` 当年也是这么收口的（权限写入只走 `write_permissions` 一个入口）。

**key-proxy 的包里会有它不需要的 `create`**：这是有意接受的。key-proxy 的 role **没有** `PutItem`（Task 8 的断言锁定），所以那条路径在真机上会 AccessDenied——代码在但权限不在，是纵深而非缺陷。反过来把模块拆开的代价（上一条）更大。

**先开关后 Key，两次独立强一致读**（计划级补充 B，Codex P2-6 修正）：

```
_get_switch()  →  GetItem(__switch__, ConsistentRead=True)
    enabled is not True  →  立即返回 Verdict(ok=False)   ← 不读 Key、不写 last_used
_get_key(hash)  →  GetItem(key_hash, ConsistentRead=True)
```

**不要合并成 `BatchGetItem`**：那样"关闸时不查 Key"就不成立（一次 BatchGet 必然把两条一起请求），而这条短路是"关闸期间零写、零 Key 查询"的前提。也**不要用 `TransactGetItems`** 去追求原子快照——两个值之间没有需要原子性的不变量（开关关了就拒，与 Key 行当时是什么状态无关），`TransactGetItems` 只会带来两倍的读容量成本与一个 `dynamodb:TransactGetItems` 权限。

**判定顺序：先开关后 Key。** 关闸时立即返回，不判 Key、**不调 `touch_last_used`**。理由：关闸期间不该产生任何写；且"关闸时仍在更新 last_used_at"会让审计看起来像"关闸没生效"。

**fail-closed 矩阵**（每一行都要有用例）：

| 情况 | 结果 | 为什么不能反过来 |
|---|---|---|
| 哨兵行不存在 | **拒** | 表刚建好还没跑部署脚本时，默认必须是关 |
| 哨兵行 `enabled` 不是布尔 `True`（缺失/`"true"` 字符串/`1`/`None`） | **拒** | 照 Edge `require_auth` 的既有形态：`if x is not True`，不是 `if not x`。M3 实测过四种非布尔形态都能骗过 `if not x` |
| 开关 `GetItem` 抛异常 | **拒** | 读不到就不知道开关状态，此时放行等于开关形同虚设 |
| Key `GetItem` 抛异常 | **拒** | 不能因为"开关是开的"就放行 |
| 任一读被节流 | **拒，且不重试** | 重试会把一次限流放大成多次，且转发已经有超时预算 |
| Key 行不存在 | 拒 | — |
| Key 行 `revoked` 为真值（任何形态） | **拒** | 这一侧要 `if truthy` 而不是 `if x is True`——**与开关方向相反**：开关是"必须显式为真才放行"，吊销是"只要像真就拒绝"。两个方向都取最严 |
| Key 行缺 `email` 或 `email` 不是邮箱形态 | **拒** | 脏数据不能变成"以空身份调用"（下游 `_caller_email` 会拿到空串） |
| 明文形态不匹配 `PLAINTEXT_RE` | 拒，**且不查库** | 省一次读，也防止把任意长字符串当 key 去 hash |

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_keystore.py`（deployer 包；夹具用该包 conftest 已有的 moto 表，需为 `site-api-keys` 加一张带两个 GSI 的表）：

```python
"""keystore：开关 + Key 的单次强一致查询。

**核心不变量是"不缓存"**（spec §5.1：缓存了"即时吊销"就不成立）。
Lambda 的模块级变量跨请求存活，所以"没写缓存代码"不等于没缓存——
本文件有专门的行为用例（test_revocation_takes_effect_on_next_call 等）
把这一点钉住，test_no_module_level_cache.py 从结构上再钉一次。
"""
import pytest

import keygen
import keystore


def _put_switch(enabled=True):
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item={
            "key_hash": keygen.SWITCH_PK, "enabled": enabled,
            "updated_at": "2026-08-10T00:00:00+00:00", "updated_by": "seed"})


def _put_key(email="u@x.com", revoked=False, **extra):
    import boto3
    k = keygen.new_key()
    item = {"key_hash": k.key_hash, "key_id": k.key_id, "email": email,
            "name": "笔记本", "prefix": k.prefix, "revoked": revoked,
            "created_at": "2026-08-10T00:00:00+00:00", "last_used_at": ""}
    item.update(extra)
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item=item)
    return k


# ---------- happy path ----------

def test_valid_key_with_switch_on_resolves_email(aws):
    _put_switch(True)
    k = _put_key(email="alice@x.com")
    v = keystore.lookup(k.plaintext)
    assert v.ok and v.email == "alice@x.com" and v.key_id == k.key_id


# ---------- 开关优先于 Key ----------

def test_switch_off_rejects_even_a_valid_key(aws):
    _put_switch(False)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is False


def test_switch_off_does_not_write_last_used(aws, monkeypatch):
    """关闸期间不得产生任何写——否则审计看起来像"关闸没生效"。"""
    calls = []
    monkeypatch.setattr(keystore, "touch_last_used",
                        lambda *a, **kw: calls.append(a))
    _put_switch(False)
    k = _put_key()
    keystore.lookup(k.plaintext)
    assert calls == []


def test_switch_missing_row_rejects(aws):
    """哨兵行不存在 = 表刚建好还没部署 → 必须是关。"""
    _put_key()      # 有 Key，没有哨兵行
    assert keystore.lookup(_put_key().plaintext).ok is False


@pytest.mark.parametrize("bad", [None, "true", "True", 1, 0, "", [], {}])
def test_switch_non_boolean_true_rejects(aws, bad):
    """照 Edge require_auth 的既有形态：必须显式布尔 True。

    M3 实测过四种非布尔形态都能骗过 `if not x`（{"NULL":true}、
    {"N":"0"}、{"L":[]}、未识别类型），所以这里用 `is not True`。
    """
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item={"key_hash": keygen.SWITCH_PK,
                                        "enabled": bad})
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is False


def test_switch_read_failure_rejects(aws, monkeypatch):
    """读不到就不知道开关状态——此时放行等于开关形同虚设。"""
    def boom(*a, **kw):
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, "_get_switch_row", boom)
    assert keystore.lookup("sk-" + "a" * 16).ok is False


def test_key_read_failure_rejects(aws, monkeypatch):
    """开关读到了、Key 读失败 —— 同样必须拒（不能"开关是开的就放行"）。"""
    _put_switch(True)
    def boom(*a, **kw):
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, "_get_key_row", boom)
    assert keystore.lookup(_put_key().plaintext).ok is False


def test_neither_read_is_retried(aws, monkeypatch):
    """两个读都**不重试**：重试会把一次限流放大成多次，而转发本身有超时预算。"""
    n = {"switch": 0, "key": 0}
    rs, rk = keystore._get_switch_row, keystore._get_key_row
    monkeypatch.setattr(keystore, "_get_switch_row",
                        lambda *a, **kw: (n.__setitem__("switch", n["switch"] + 1),
                                          rs(*a, **kw))[1])
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: (n.__setitem__("key", n["key"] + 1),
                                          rk(*a, **kw))[1])
    _put_switch(True)
    keystore.lookup(_put_key().plaintext)
    assert n == {"switch": 1, "key": 1}


# ---------- Key 侧的 fail-closed ----------

def test_unknown_key_rejects(aws):
    _put_switch(True)
    assert keystore.lookup(keygen.new_key().plaintext).ok is False


@pytest.mark.parametrize("revoked", [True, "true", 1, "yes", ["x"]])
def test_revoked_truthy_rejects(aws, revoked):
    """吊销侧方向与开关**相反**：只要像真就拒。两个方向都取最严。"""
    _put_switch(True)
    k = _put_key(revoked=revoked)
    assert keystore.lookup(k.plaintext).ok is False


@pytest.mark.parametrize("email", [None, "", "   ", "notanemail", "a@b"])
def test_dirty_email_rejects(aws, email):
    """脏数据不能变成"以空身份调用"——下游 _caller_email 会拿到空串。"""
    _put_switch(True)
    k = _put_key()
    import boto3
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    if email is None:
        t.update_item(Key={"key_hash": k.key_hash},
                      UpdateExpression="REMOVE email")
    else:
        t.update_item(Key={"key_hash": k.key_hash},
                      UpdateExpression="SET email = :e",
                      ExpressionAttributeValues={":e": email})
    assert keystore.lookup(k.plaintext).ok is False


@pytest.mark.parametrize("bad", ["", "sk-", "sk-short", "SK-" + "a" * 16,
                                "sk-" + "a" * 17, "sk_" + "a" * 16,
                                "sk-" + "a" * 15 + "-", "x" * 500])
def test_malformed_plaintext_rejects_without_db_read(aws, bad, monkeypatch):
    """形态不对时**不查库**：省一次读，也防止把任意长串当 key 去 hash。"""
    calls = []
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: calls.append(1) or ({}, {}))
    assert keystore.lookup(bad).ok is False
    assert calls == [], "形态校验必须在查库之前"


# ---------- 不缓存（行为层） ----------

def test_revocation_takes_effect_on_next_call(aws):
    """**同一进程内**：第一次成功后吊销，第二次必须立刻失败。

    这是"禁止缓存 hash→email"的行为断言。加任何缓存都会让它变红。
    """
    _put_switch(True)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is True
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").update_item(
            Key={"key_hash": k.key_hash},
            UpdateExpression="SET revoked = :t",
            ExpressionAttributeValues={":t": True})
    assert keystore.lookup(k.plaintext).ok is False, \
        "吊销未即时生效——检查是否引入了缓存"


def test_switch_flip_takes_effect_on_next_call(aws):
    """开关同形：进程内翻转必须立刻生效。"""
    _put_switch(True)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is True
    _put_switch(False)
    assert keystore.lookup(k.plaintext).ok is False, \
        "关闸未即时生效——检查是否缓存了开关"


def test_every_lookup_hits_the_database(aws, monkeypatch):
    """计数断言：N 次 lookup 必须有 N 次开关读 + N 次 Key 读。

    上面两条能抓住"永久缓存"，抓不住"带 TTL 的缓存"（TTL 内的第二次调用
    仍是旧值，但用例里两次调用间隔远小于 TTL 时也会红——不可靠）。
    这条直接数读次数，任何缓存都会让它红。
    """
    _put_switch(True)
    k = _put_key()
    n = {"switch": 0, "key": 0}
    rs, rk = keystore._get_switch_row, keystore._get_key_row

    def cs(*a, **kw):
        n["switch"] += 1
        return rs(*a, **kw)

    def ck(*a, **kw):
        n["key"] += 1
        return rk(*a, **kw)
    monkeypatch.setattr(keystore, "_get_switch_row", cs)
    monkeypatch.setattr(keystore, "_get_key_row", ck)
    for _ in range(5):
        keystore.lookup(k.plaintext)
    assert n == {"switch": 5, "key": 5}, f"存在缓存: {n}"


def test_both_reads_are_strongly_consistent(aws):
    """两个读都必须 ConsistentRead=True：最终一致读会留下"吊销后仍放行"、
    "关闸后仍放行"的窗口。

    断言方式：读 keystore 记录的最后一次请求参数（模块暴露
    LAST_READ_CONSISTENCY 供测试观察，它不是授权数据，见
    test_no_module_level_cache 的白名单说明）。
    """
    _put_switch(True)
    keystore.lookup(_put_key().plaintext)
    assert keystore.LAST_READ_CONSISTENCY == {"switch": True, "key": True}


def test_switch_is_read_before_key_and_short_circuits(aws, monkeypatch):
    """顺序断言：开关先读；关闸时**根本没有** Key 读。

    这条替代了原方案的"两者必须来自同一次 BatchGetItem"（Codex P2-6：
    BatchGetItem 不提供跨项原子快照，且一次 BatchGet 必然把 Key 行一起
    请求了——与"关闸时不查 Key"自相矛盾）。
    """
    order = []
    rs, rk = keystore._get_switch_row, keystore._get_key_row
    monkeypatch.setattr(keystore, "_get_switch_row",
                        lambda *a, **kw: (order.append("switch"), rs(*a, **kw))[1])
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: (order.append("key"), rk(*a, **kw))[1])
    _put_switch(True)
    k = _put_key()
    keystore.lookup(k.plaintext)
    assert order == ["switch", "key"], "开关必须先读"
    order.clear()
    _put_switch(False)
    keystore.lookup(k.plaintext)
    assert order == ["switch"], f"关闸时仍查了 Key: {order}"


# ---------- key_id 唯一性（Codex P2-7）----------

def test_create_retries_on_key_id_collision(aws, monkeypatch):
    """GSI 不提供唯一约束，唯一性必须由创建路径保证。"""
    _put_switch(True)
    first = keystore.create("a@x.com", name="one")
    # 强迫下一次生成撞上已有的 key_id 一次，然后恢复随机
    seq = [first["key_id"]]
    real_new = keygen.new_key

    def rigged():
        k = real_new()
        return k._replace(key_id=seq.pop(0)) if seq else k
    monkeypatch.setattr(keygen, "new_key", rigged)
    second = keystore.create("b@x.com", name="two")
    assert second["key_id"] != first["key_id"], "碰撞未被检测与重试"


def test_revoke_fails_closed_when_index_returns_multiple_rows(aws, monkeypatch):
    """**≥2 行绝不能"取第一行删掉"**——那会误吊销别人的 Key。"""
    _put_switch(True)
    a = keystore.create("a@x.com", name="one")
    monkeypatch.setattr(keystore, "_query_by_key_id",
                        lambda kid: [{"key_hash": "h1", "email": "a@x.com",
                                      "key_id": kid},
                                     {"key_hash": "h2", "email": "b@x.com",
                                      "key_id": kid}])
    with pytest.raises(Exception):
        keystore.revoke(a["key_id"], actor="a@x.com")


def test_revoke_update_carries_key_id_and_email_condition(aws):
    """Query 与 Update 之间有窗口，且 GSI 是最终一致的——落地的那一步
    必须重新断言两个字段（同 sites_snapshot_guard 的既有理由）。"""
    _put_switch(True)
    k = keystore.create("a@x.com", name="one")
    import ast, pathlib
    src = pathlib.Path(keystore.__file__).read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "revoke")
    body = ast.get_source_segment(src, fn) or ""
    assert "ConditionExpression" in body
    assert "key_id" in body and "email" in body


# ---------- 哨兵行不得出现在 GSI ----------

def test_switch_row_never_appears_in_email_index(aws):
    """哨兵行没有 email/key_id 属性 → 天然不进 GSI（按人列 Key 时不出现）。

    **这条不是"显然成立"**：将来有人给哨兵行加个 email 字段（比如想记
    "谁改的"而误用 email 而不是 updated_by），它就会出现在某人的 Key 列表里。
    """
    import boto3
    _put_switch(True)
    _put_key(email="alice@x.com")
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    for idx, key, val in (("email-index", "email", "alice@x.com"),):
        rows = t.query(IndexName=idx,
                       KeyConditionExpression=boto3.dynamodb.conditions.Key(key).eq(val))["Items"]
        assert all(r["key_hash"] != keygen.SWITCH_PK for r in rows)
    # 全量扫 GSI 也不该有它
    assert all(r["key_hash"] != keygen.SWITCH_PK
               for r in t.scan(IndexName="email-index")["Items"])
    assert all(r["key_hash"] != keygen.SWITCH_PK
               for r in t.scan(IndexName="keyid-index")["Items"])


# ---------- last_used_at 节流 ----------

def test_touch_last_used_throttles_to_once_per_hour(aws):
    """每 Key 每小时至多一次写（spec §5.2）。"""
    _put_switch(True)
    k = _put_key()
    keystore.touch_last_used(k.key_hash, k.key_id)
    import boto3
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    first = t.get_item(Key={"key_hash": k.key_hash})["Item"]["last_used_at"]
    assert first
    keystore.touch_last_used(k.key_hash, k.key_id)      # 立刻再来一次
    second = t.get_item(Key={"key_hash": k.key_hash})["Item"]["last_used_at"]
    assert second == first, "节流失效——每次调用都写"


def test_touch_last_used_failure_does_not_raise(aws, monkeypatch):
    """更新失败不得影响转发（它是遥测，不是授权）。"""
    def boom(*a, **kw):
        raise RuntimeError("nope")
    monkeypatch.setattr(keystore, "_update_last_used", boom)
    keystore.touch_last_used("deadbeef", "abc12345")    # 不抛即通过
```

创建 `site-builder/key-proxy/tests/test_no_module_level_cache.py`：

```python
"""结构性：授权数据不得进任何跨请求存活的容器。

**为什么需要结构断言而不只靠行为断言**：行为断言（test_every_lookup_hits_
the_database 等）能抓住今天的缺陷；这条抓的是"下一个人为了性能加缓存"。
Lambda 的模块级变量跨请求存活，所以缓存可以在不改任何函数签名的情况下引入。
"""
import ast
import pathlib

# **两个模块住在不同的包里**（控制器 pre-flight 修正 2026-08-11）：
# keystore.py 在 deployer/functions/（panel 与 key-proxy 共用，见补充 E），
# handler.py 在 key-proxy/。按 parents[1] 拼 keystore.py 会指向
# key-proxy/keystore.py —— 那个文件不存在，用例会 error 而不是 fail
# （又一处"模块搬家后引用没跟着改"，同 Codex P1-4 的形态）。
KP = pathlib.Path(__file__).parents[1]                      # site-builder/key-proxy
FN = KP.parent / "deployer" / "functions"                   # deployer/functions
MODULES = {"keystore.py": FN, "handler.py": KP}
# **目录用 assert，文件才用 skip**（Task 3 实施期实测）：控制器 pre-flight 的
# 第一版写成 `KP.parents[1]`，那是 quick-app/ —— 拼出的目录不存在，而用例既不
# error 也不 fail，是 **skip**："我找错了地方"被伪装成"Task 5 还没做"。
# 所以对目录 `assert directory.is_dir()`（找不到是本文件自己的 bug），
# 只对文件缺失用 skip 并写明"文件缺失不等于已检查通过"。


def _tree(name):
    src = (MODULES[name] / name).read_text()
    return ast.parse(src), src


def test_no_module_level_mutable_containers(): ...
    # 模块顶层不得有 dict/list/set 字面量赋值（machine_token.py 例外，
    # 它是唯一允许缓存的模块，且不在 MODULES 里）


def test_no_lru_cache_on_authorization_functions(): ...
    # lookup / _get_switch_row / _get_key_row / switch_state 不得被 functools.lru_cache /
    # cache / cached_property 装饰


def test_machine_token_is_the_only_module_allowed_to_cache(): ...
    # 反向：确认 machine_token.py **确实**有缓存（否则每次调用都换 token，
    # 会撞 Cognito 频率限制）——这条防止"为了让上面两条绿而把缓存全删了"
```

（三个函数体在 Step 3 写实现时补全；此处列出意图与边界，实施时按 M3-FINDINGS §2.1 第 4 条用 AST 而非文本。）

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_keystore.py -q`
Expected: FAIL（`No module named 'keystore'`）。

- [ ] **Step 3: 实现 `keystore.py`**

要点：
- **两个读入口**：`_get_switch_row()` 与 `_get_key_row(key_hash)`，各自 `GetItem(ConsistentRead=True)`。测试靠 monkeypatch 它们做计数、顺序与故障注入
- `_query_by_key_id(key_id)` 是 `keyid-index` 的唯一查询入口（revoke 用；测试注入多行场景靠它）
- `LAST_READ_CONSISTENCY` 模块级 dict **是允许的**（它不是授权数据，只是给测试看的最后一次请求形态）——在 `test_no_module_level_mutable_containers` 的白名单里显式列出并注明理由
- `lookup()` 的顺序严格是：形态 → 开关（关即 return）→ Key → `revoked` → `email` 形态
- 节流用 `ConditionExpression`（`attribute_not_exists(last_used_at) OR last_used_at < :cutoff`）而不是"先读再写"——并发下"先读再写"会两边都写
- `set_switch()` 用 `PutItem`（整行覆盖，字段固定），并调 `ops_log.record()`（**不自己拼 SK**，见衔接点 1）

- [ ] **Step 4: 确认转绿**

- [ ] **Step 5: 反向验证（这一步是本 Task 的重点）**

| 注入 | 必须变红 |
|---|---|
| `lookup` 顶部加 `_CACHE: dict` 并命中即返回 | `test_revocation_takes_effect_on_next_call`、`test_switch_flip_*`、`test_every_lookup_hits_the_database`、`test_no_module_level_mutable_containers` |
| 给 `_get_switch_row` 或 `_get_key_row` 加 `@functools.lru_cache` | 同上 + `test_no_lru_cache_*` |
| 开关判定改 `if not enabled: reject` | 8 条 `test_switch_non_boolean_true_rejects` |
| 开关与 Key 合并成一次 `BatchGetItem` | `test_switch_is_read_before_key_and_short_circuits`（关闸时会多出一条 "key"） |
| 先读 Key 再读开关 | 同上（`order` 反了） |
| `create` 去掉碰撞检测重试 | `test_create_retries_on_key_id_collision` |
| `revoke` 在多行时取第一行 | `test_revoke_fails_closed_when_index_returns_multiple_rows` |
| `revoke` 的 `UpdateItem` 去掉条件表达式 | `test_revoke_update_carries_key_id_and_email_condition` |
| 任一读改 `ConsistentRead=False` | `test_both_reads_are_strongly_consistent` |
| 吊销判定改 `if revoked is True` | `test_revoked_truthy_rejects` 的 `"true"`/`1`/`"yes"`/`["x"]` 四条 |
| 哨兵行缺失时 `return Verdict(ok=True, ...)` | `test_switch_missing_row_rejects` |
| 开关读异常时 `pass` 继续 | `test_switch_read_failure_rejects` |
| Key 读异常时按"开关是开的"放行 | `test_key_read_failure_rejects` |
| 任一读加重试 | `test_neither_read_is_retried` |
| 形态校验挪到查库之后 | `test_malformed_plaintext_rejects_without_db_read` |
| 关闸分支里仍调 `touch_last_used` | `test_switch_off_does_not_write_last_used` |
| 节流改成无条件写 | `test_touch_last_used_throttles_*` |
| 删掉 `machine_token` 的缓存 | `test_machine_token_is_the_only_module_allowed_to_cache` |

- [ ] **Step 6: 提交**

`feat(m4): keystore——开关与 Key 单次强一致查询，禁止缓存（含 13 条反向验证）`

---

## Task 4: machine_token——唯一允许缓存的模块

**Files:**
- Create: `site-builder/key-proxy/machine_token.py`
- Create: `site-builder/key-proxy/tests/test_machine_token.py`

**Interfaces:**
- Produces:
  - `get_token() -> str` —— 返回有效的 access token；缓存至**过期前 300 秒**
  - `invalidate() -> None` —— 丢弃缓存（供转发拿到 401/403 时重取一次，spec §8）
  - `TokenUnavailable` —— 换不到 token 的异常（handler 转成 502）
- Consumes: Cognito `POST {domain}/oauth2/token`（`grant_type=client_credentials`）、SSM SecureString 读 machine client secret（TTL 缓存，照 `panel/console_session._secret()` 的既有形态）
- 环境变量：`COGNITO_DOMAIN`、`MACHINE_CLIENT_ID`、`MACHINE_SECRET_PARAM`、**`MACHINE_SCOPE`**

**`MACHINE_SCOPE` 必须由部署脚本从 config 派生下发**（Codex 审查 2026-08-11 P1-2a）：`config.ini` 的 `[ApiKey]` 允许自定义 `resource_server_id` 与 `scope`，而 token 请求要带 `scope={resource_server_id}/{scope}`。原方案的环境变量清单里两个值都没有，实施者只能二选一——硬编码 `site-builder-mcp/invoke`（违反"config 是唯一取值来源"）或自行发明一个未记录的变量（说明计划不完整）。定为**下发拼好的完整 scope 串**而不是两个分量：拼接逻辑只应存在于 `deploy_key_proxy.py` 一处，运行时不再重新拼（少一处可写错的地方）。缺失/空 → `TokenUnavailable`（**不能用空 scope 去换**：Cognito 会拒，而错误文案指向 client 配置，排查方向会被带偏）。

**为什么这个模块允许缓存**：token 不是授权判定，只是 key-proxy 向 AgentCore 证明"我是 key-proxy"的凭证。它的作用域是**整个组件**，与"哪个用户在调"无关——吊销某个用户的 Key 不需要换 token（用户身份走 on-behalf 头，每请求现查）。不缓存会让每次 MCP 调用多一次 Cognito 往返并撞频率限制。

**提前 300 秒换新，不等 401**：spec §8 的"machine token 过期/被拒 → 重取一次再转发"是**兜底**，不是主路径。等到 401 才换会让每个 token 生命周期末尾的请求多一次往返 + 一次失败日志（噪音会掩盖真实故障）。

**secret 不进环境变量**：环境变量只有 `MACHINE_SECRET_PARAM`（SSM 参数名）。`GetFunctionConfiguration` 会原样回显环境变量，而这是一个常见的只读权限（`44aef8d` 之前的 auth 就踩过明文密钥进环境变量）。

- [ ] **Step 1: 写失败测试**

`test_machine_token.py` 覆盖：

| 用例 | 断言 |
|---|---|
| `test_first_call_exchanges_and_second_reuses` | 两次 `get_token()` 只有一次 HTTP |
| `test_refreshes_before_expiry_with_margin` | 把 `expires_in` 设成 310，快进 20 秒后必须**不**换（290 > 300 ✗ → 重算：设 `expires_in=310`，快进 11 秒 → 剩 299 < 300 → 必须换）。**用注入的时钟，不用 `time.sleep`** |
| `test_expired_token_is_not_returned` | 快进超过 `expires_in` 后必须换新 |
| `test_invalidate_forces_reexchange` | `invalidate()` 后必须换新 |
| `test_secret_read_from_ssm_not_env` | 环境变量里没有 secret；读的是 `MACHINE_SECRET_PARAM` 指向的参数 |
| `test_secret_is_not_logged` | caplog 里不出现 secret 值 |
| `test_token_is_not_logged` | 同上（token 也是凭证） |
| `test_exchange_failure_raises_token_unavailable` | 非 200 / 网络异常 → `TokenUnavailable`，**不返回空串**（空串会变成 `Authorization: Bearer ` 打到网关） |
| `test_failure_does_not_poison_cache` | 一次失败后下次调用要重试，不能把失败结果缓存住 |
| `test_scope_is_sent` | 请求体含 `scope` 且其值**逐字符等于** `MACHINE_SCOPE` 环境变量（不是硬编码的 `site-builder-mcp/invoke`——把环境变量设成别的值，断言必须跟着变） |
| `test_missing_scope_env_raises_not_empty_scope_request` | `MACHINE_SCOPE` 缺失/空 → `TokenUnavailable`，且**没有发出任何 HTTP**（不能拿空 scope 去撞 Cognito） |

**时钟注入**：`machine_token._now()` 函数（测试 monkeypatch 它）。不要用 `time.monotonic` 直接调用——那样只能靠 sleep 测。

- [ ] **Step 2-4: 确认失败 → 实现 → 确认转绿**

- [ ] **Step 5: 反向验证**

| 注入 | 必须变红 |
|---|---|
| 去掉缓存（每次换新） | `test_first_call_exchanges_and_second_reuses` |
| margin 改 0 | `test_refreshes_before_expiry_with_margin` |
| 失败时 `return ""` | `test_exchange_failure_raises_token_unavailable` |
| 失败结果也写进缓存 | `test_failure_does_not_poison_cache` |
| secret 改从环境变量读 | `test_secret_read_from_ssm_not_env` |
| 加一行 `logger.info(token)` | `test_token_is_not_logged` |
| 请求体去掉 scope | `test_scope_is_sent` |
| scope 改成硬编码 `"site-builder-mcp/invoke"` | `test_scope_is_sent`（它按环境变量断言，硬编码时改环境变量就不一致） |
| `MACHINE_SCOPE` 缺失时用空串继续 | `test_missing_scope_env_raises_not_empty_scope_request` |

- [ ] **Step 6: 提交**

`feat(m4): machine_token——client_credentials 换 token 与受控缓存`

---

## Task 5: key-proxy handler——六步 + 透明转发

**Files:**
- Create: `site-builder/key-proxy/handler.py`
- Create: `site-builder/key-proxy/tests/test_handler.py`

**Interfaces:**
- Produces: `handler(event, context) -> dict`（Function URL payload v2 形态）
- Consumes: `edge_caller.caller_is_edge`、`keystore.{lookup,touch_last_used}`、`machine_token.{get_token,invalidate,TokenUnavailable}`

**六步顺序（顺序是安全边界）：**

```
⓪ 传输层：edge_caller.caller_is_edge(event) —— 否则 403
① 方法与路径：只接受 POST（MCP streamable-http 全走 POST）
② X-API-Key 存在 —— 否则 401
③ keystore.lookup() —— 开关与 Key（不缓存）→ 得 email
④ machine_token.get_token()
⑤ 透明转发 + 异步 touch_last_used
```

**⓪ 为什么 key-proxy 也要**：`44aef8d` 的 P1-1 真机实证同账号 principal 能绕开 resource policy 直连。对 key-proxy 而言绕过 Edge 不等于绕过认证（它认 `X-API-Key`，攻击者还得有有效 Key），但 **Edge 是可观测性与限流的唯一位置**——绕过它意味着 Key 暴力尝试不留任何可告警痕迹。且同一仓库里两个 Function URL 组件一个校验一个不校验，下次审查还会再报一遍。

**透明转发的具体口径**（决定 7）：

| 项 | 做法 |
|---|---|
| 请求 body | **bytes 原样**（`isBase64Encoded` 时先 decode）。不解析、不改写、不重新序列化 |
| 请求头 | 只透传白名单：`content-type`、`accept`、`mcp-session-id`、`mcp-protocol-version`。**不透传** `authorization`（换成机器 token）、`x-api-key`（不能泄给下游）、`cookie`（决定 9）、`host` |
| 新增头 | `Authorization: Bearer {机器token}`、`X-SB-On-Behalf-Of: {email}` |
| 响应 body | 原样回传。`content-type` 是 `text/event-stream` 时**整体缓冲**（Lambda 响应不能流式经过 Lambda@Edge）后原样返回，不重新组包 |
| 响应头 | 透传 `content-type`、`mcp-session-id`；其余丢弃 |
| 响应码 | 原样 |

**401/403 的重试**（spec §8）：转发拿到 401/403 时 `machine_token.invalidate()` + 重取 + **重发一次**。重发要用**同一份 body bytes**（不能是已消费的流）。仍失败 → 502 + 日志。**只重试一次**。

**错误文案不泄露信息**（spec §8）：无效 / 吊销 / 关闸 / 未知 Key **同一句话同一状态码**（401 + `{"error":"API Key 无效或已被吊销"}`）——不得让调用方区分"这把 Key 不存在"与"这把 Key 被吊销了"与"平台关闸了"。`Verdict.reason` 只进日志。

- [ ] **Step 1: 写失败测试**

`test_handler.py` 覆盖（按组）：

**顺序组**（每条都要证明"前置失败时后续零副作用"，做法照 `panel/tests/test_csrf.py::test_csrf_failure_performs_zero_writes` 在 boto3 层装间谍）：
- 非 Edge 调用者 → 403，且**不查库、不换 token、不转发**
- 缺 `X-API-Key` → 401，且不查库
- 非 POST → 405，且不查库
- 开关关 → 401，且**不换 token、不转发、不写 last_used**
- Key 无效 → 401，且不换 token、不转发

**透明性组**：
- body 里的非法 JSON **也要被转发**（证明不解析）——下游返回什么就回什么
- body 是 JSON-RPC batch（数组）时照样转发
- `Mcp-Session-Id` 请求→上游、上游响应→客户端 双向透传
- SSE 响应（`text/event-stream`）原样回传，**逐字节相等**
- `authorization` / `x-api-key` / `cookie` 请求头**不出现**在上游请求里
- 上游收到的 `X-SB-On-Behalf-Of` 等于 keystore 解出的 email
- body 的 `isBase64Encoded` 形态正确解码（Function URL 对二进制会 base64）

**错误组**：
- 四种拒绝原因的响应体**逐字节相同**、状态码相同
- `TokenUnavailable` → 502，响应体不含内部细节（无 ARN / 表名 / 堆栈）
- 上游 401 → invalidate + 重发一次；两次都 401 → 502
- 重发用的是**同一份 body**（间谍记录两次上游请求的 body，断言相等）
- 上游超时 → 504 或 502（择一并写清），不挂起

**日志组**：
- caplog 里**不出现**明文 Key（任何分支）
- caplog 里不出现机器 token
- 拒绝时日志**有** `reason` 与 `key_id`（能排查），但没有明文

- [ ] **Step 2-4: 确认失败 → 实现 → 确认转绿**

实现要点：
- HTTP 用标准库 `urllib.request`（Lambda 运行时自带；不引第三方依赖，与 Edge 的约束同源）
- 超时显式设（如 25s，留 Lambda 30s 预算的余量）
- **不要**在异常消息里拼接明文 Key（`f"invalid key {plaintext}"` 会进日志）

- [ ] **Step 5: 反向验证**

| 注入 | 必须变红 |
|---|---|
| 删掉 ⓪ | 非 Edge 直连那条 |
| ③ 挪到 ④ 之后 | "开关关时不换 token" |
| 四种拒绝文案改成各不相同 | 错误组第一条 |
| 转发时把 body `json.loads` 再 `json.dumps` | 非法 JSON 那条 + batch 那条 |
| 透传 `authorization` 原头 | 头白名单那条 |
| 透传 `cookie` | cookie 那条 |
| SSE 重新组包（按行 split 再 join） | SSE 逐字节那条 |
| 重发时重新取 body（空） | "重发用同一份 body" |
| 重试上限改 3 | "两次都 401 → 502" |
| 加一行 `logger.info(f"key={plaintext}")` | 日志组第一条 |
| 502 响应体带上异常 `str(e)` | "不含内部细节" |

- [ ] **Step 6: 提交**

`feat(m4): key-proxy handler——六步前置 + 不懂协议的透明转发`

---

## Task 6: panel 的 Key 端点与开关

**Files:**
- Modify: `site-builder/panel/api.py`
- Modify: `site-builder/panel/handler.py`（`ROUTES` + `_dispatch`）
- Modify: `site-builder/panel/deploy_panel.py`（复制清单 + role + 环境变量）
- Create: `site-builder/panel/tests/test_keys_api.py`
- Modify: `site-builder/panel/tests/test_handler.py`
- Modify: `site-builder/panel/tests/test_deploy_panel_contract.py`

**Interfaces:**
- Produces（`api.py`，全部纯函数，入参 email 已是 Edge 验过的身份）：
  - `do_list_keys(email) -> dict` —— `{"keys": [...]}`，按 `email-index` Query，**不含 `key_hash`**
  - `do_create_key(email, *, name) -> dict` —— `{"plaintext": ..., "key_id": ..., ...}`，明文**只在此出现一次**
  - `do_revoke_key(email, *, key_id) -> dict` —— 经 `keyid-index` 查行 → 比对 email → 置 `revoked`
  - `do_get_key_switch(email) -> dict` —— admin-only
  - `do_set_key_switch(email, *, enabled: bool) -> dict` —— admin-only，落 ops_log
  - `do_me` 增加 `features: {"api_key": {"deployed": bool, "enabled": bool}}`（计划级补充 C，Codex P1-5）
- Consumes: `keystore.{create,list_for,revoke,switch_state,set_switch}`、`permissions.is_admin`。**panel 不直接碰 api-keys 表、也不直接调 `keygen`**——全部经 keystore（同 panel 对 sites 表「只走 permissions.py 高层函数」的既有约束，由 `test_no_handwritten_guards.py` 的同类断言扩展锁定）

**路由（spec §4.4）：**
```
GET    /api/keys                  列我的 Key
POST   /api/keys                  创建（body: {name}）
POST   /api/keys/revoke           吊销（body: {key_id}）
GET    /api/settings/api-key      开关状态（admin-only）
PUT    /api/settings/api-key      改开关（admin-only，body: {enabled}）
```

**全部继承 M3 的六步前置**（`handler.py` 已有）：`GET` 走读路径，三个写方法自动要求 CSRF + `__Host-sb_console`。**不新发明鉴权**。

**`enabled` 必须严格 `isinstance(bool)`**：`44aef8d` 的 P1-2 就是 `bool("false") is True` 导致 `{"purge_data":"false"}` 被当成永久删除。开关是同一个陷阱形态——`{"enabled":"false"}` 若被当成 True 就是"以为关了其实开着"。显式 `null` 也拒。

**`features.api_key` 的派生**（不读 config.ini）：调 `keystore.switch_state()` 得 `(deployed, enabled)`。`deployed` = 哨兵行**读到了**（表不存在 / 行不存在 / AccessDenied 一律 `False`）；`enabled` = 该行 `enabled is True`。**这个派生只影响 UI 展示，不是门禁**——真门禁在网关层。

**为什么必须是两个字段而不是一个布尔**（Codex 审查 2026-08-11 P1-5）：首次部署强制把哨兵行建成 `enabled=false`，若只有一个布尔且前端按它 disabled + 零请求，管理员**无处点开闸**，部署流程自锁。`deployed` 决定 UI 可用性，`enabled` 只驱动状态提示与开关初值。

对应的硬用例（Task 6 Step 1 的开关组）：**哨兵行存在且 `enabled=false` 时，`do_me` 必须返回 `deployed=true`**，且 admin 仍能 `do_get_key_switch` / `do_set_key_switch`；同一状态下 key-proxy 侧的 `lookup` 必须拒绝（Task 3 已覆盖）。两者同时成立才是正确的"已部署但关闸"。

- [ ] **Step 1: 写失败测试**

`test_keys_api.py` 覆盖：

**授权组**：
- 别人的 `key_id` 吊销不了（`keyid-index` 查到行但 email 不匹配 → `PermissionDenied`）
- 不存在的 `key_id` 与别人的 `key_id` **同一句话**（否则是 Key 枚举探测器，同 `do_get_site` 的既有口径）
- 非 admin 读/写开关 → `PermissionDenied`
- `do_list_keys` 只返回自己的（另一个人的 Key 不出现）
- 哨兵行不出现在任何人的列表里（Task 3 已有 GSI 层断言，这里再加一层 API 层）

**泄漏组**：
- `do_list_keys` 的每一项**不含** `key_hash` 键（逐 key 检查，不是 `"key_hash" not in json`——后者会被嵌套结构骗过）
- `do_create_key` 的响应含 `plaintext`，而 `do_list_keys` **不含**
- 创建后再 `do_list_keys`，明文**不出现**在任何字段里
- caplog 与 ops_log 里都不出现明文（ops_log 记 `key_id`）
- `_shape_key` 是唯一出口（AST：`do_list_keys` / `do_create_key` 的返回值都经过它）

**开关组**：
- `{"enabled": "false"}` / `"0"` / `0` / `1` / `None` / `[]` → `ValueError`（→ 400）
- `{"enabled": False}` 与 `True` 都放行
- 改开关落 ops_log（`action` 含开关语义、`actor` 是操作者）

**创建组**：
- `name` 缺失/空/超长 → `ValueError`
- 同一人可以有多把 Key
- 写入行含 `key_id` / `email` / `prefix` / `created_at`，`revoked=False`，`last_used_at=""`

`test_handler.py` 追加：5 条新路由的六步前置继承（缺 `__Host-sb_console` 的 `POST /api/keys` → 401；伪造 Origin → 403；且**都是零写**）。

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**

`api.py` 新增函数。**`_shape_key()` 是唯一出口**：

```python
def _shape_key(row: dict) -> dict:
    """Key 的对外形态。**唯一出口**——绝不返回 key_hash。

    为什么必须收口到一个函数：key_hash 是这张表最值得保护的字段
    （spec §5.1：库被读走时攻击者只拿到哈希）。把它挡在一个地方，
    比在三个端点各写一次 `del row["key_hash"]` 可靠——后者漏一处即泄漏，
    而"漏一处"正是本项目反复出现的缺陷形态。
    tests/test_keys_api.py 用 AST 锁定所有返回路径都经过本函数。
    """
    return {"key_id": row.get("key_id", ""), "name": row.get("name", ""),
            "prefix": row.get("prefix", ""),
            "created_at": row.get("created_at", ""),
            "last_used_at": row.get("last_used_at", ""),
            "revoked": bool(row.get("revoked"))}
```

`deploy_panel.py`：
- **`COPY_FILES` 加四个模块**：`edge_caller.py`（Task 1 已加）、`keystore.py`、`keygen.py`、`api_key_config.py`——**全部从 `deployer/functions/` 取**（`_build_zip` 现成的 `fn_dir` → `auth_dir` 两级查找会自动命中第一级，不需要改它）。
  > 这一条被 Codex P1-4 抓出过两个错：原文写"从 `key-proxy/` 复制 `keygen.py`"（那个目录里已经没有它了，是我 self-review 期移走后漏改的），且**整个清单漏了 `keystore.py`**——而 Task 6 的 `api.py` 正是只经 keystore 访问表。后果链是确定的：加 `import keystore` → `test_copy_files_covers_every_local_module_panel_imports` 变红 → 若为赶进度放宽该测试 → 真机 panel `ModuleNotFoundError: keystore`，**所有**控制台 API 500（不只 Key 相关的，因为 `api.py` 顶层 import 失败）。
- role 加 `site-api-keys` 的 `GetItem`/`PutItem`/`UpdateItem`/`Query`（含两个 GSI 的 `index/*`）。**不给 `DeleteItem`**——吊销是置 `revoked` 不是删行（保留审计痕迹）；也**不给 `Scan`**
- 环境变量加 `API_KEYS_TABLE`

- [ ] **Step 4: 确认转绿**

- [ ] **Step 5: 反向验证**

| 注入 | 必须变红 |
|---|---|
| `_shape_key` 加回 `key_hash` | 泄漏组前三条 |
| 某个端点绕过 `_shape_key` 直接返回 row | AST 那条 |
| 吊销不比对 email | 授权组第一条 |
| 不存在与别人的返回不同文案 | 授权组第二条 |
| 开关改 `bool(body.get("enabled"))` | 开关组 6 条 |
| 开关端点去掉 `_require_admin` | 授权组第三条 |
| `logger.info` 打明文 | 泄漏组第四条 |
| ops_log 记明文而非 key_id | 同上 |
| role 去掉 `index/*` | `test_deploy_panel_contract` 的推导式断言（`keyid-index` Query 会 AccessDenied） |

**role 权限的断言用推导式**（M3-FINDINGS §2.18）：不要手抄一份"需要哪些 action"——那份清单本身就是下一个漂移源。沿用既有的 `test_role_grants_every_dynamodb_action_the_transactions_actually_need` 形态，扩展到"`api.py` 里对 api-keys 表的每个操作与每个 `IndexName`"。

- [ ] **Step 6: 提交**

`feat(m4): panel 的 Key 端点与 admin 开关（明文只出现一次、响应不含 hash）`

---

## Task 7: 三处组件门禁 + MCP 信任规则

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`
- Modify: `site-builder/mcp/deploy_agentcore.py`
- Modify: `site-builder/mcp/server.py`
- Modify: `site-builder/mcp/tests/test_tools.py`
- Modify: `site-builder/config.ini.example`
- Create: `site-builder/mcp/tests/test_component_gate.py`

**Interfaces:**
- Produces:
  - `deploy_pool.ensure_resource_server(cog, pool_id, *, identifier, scope) -> str` —— 幂等；返回 `{identifier}/{scope}`
  - **`api_key_config.py`（新建于 `deployer/functions/`）**：`api_key_enabled(cfg) -> bool`（唯一的"有没有 `[ApiKey]` 段"判定）、`machine_scope(cfg) -> str`（唯一的 `{resource_server_id}/{scope}` 拼接）、`mcp_subdomain(cfg) -> str`。三个部署脚本共用（不各自 `cfg.has_section`、不各自拼 scope）
  - `deploy_agentcore.allowed_clients(cfg) -> list[str]` / `request_header_allowlist(cfg) -> list[str]` —— 从配置派生，纯函数（可单测）
  - `server._machine_client_id() -> str` —— **每次调用读环境变量**
- Consumes: Cognito `CreateResourceServer` / `DescribeResourceServer`

**`api_key_enabled()` 必须是唯一判定**：三个脚本各写一次 `cfg.has_section("ApiKey")` 就是三个判定点，漏改一处即"部分部署"——而部分部署恰好是最危险的状态（例如 allowlist 放了头但 machine client 没进 allowedClients，或者反过来）。

**落点是 `deployer/functions/api_key_config.py`，不是 `deploy_pool.py`**（Codex 审查 2026-08-11 P1-3，**已实测复现**）：三个脚本从三个不同目录执行——
```
cd site-builder          && python3 scripts/deploy_pool.py
cd site-builder/mcp      && python3 deploy_agentcore.py
cd site-builder/key-proxy && python3 deploy_key_proxy.py
```
后两个目录都不含 `scripts/`。实测 `cd site-builder/mcp && python3 -c 'import deploy_pool'` → `ModuleNotFoundError`，即**两个部署脚本会在任何 AWS 调用之前直接崩**。放 `functions/` 后三者都能用同一个相对路径 `sys.path.insert`（`deploy_pool.py:219` 现成的 `HERE.parent / "auth"` 就是这个形态），且它天然进 Lambda/容器打包，key-proxy 运行时也能用同一份判定。

**每个脚本都要有一条"按文档里的真实 CLI 命令执行"的测试**（不只是 pytest 里 import 得到）：用 `subprocess` 从计划/DEPLOY.md 写的那个工作目录跑 `python3 <脚本> --help`（或一个 dry-run 开关），断言退出码 0 且 stderr 无 `ModuleNotFoundError`。理由：pytest 的 `sys.path` 与真实执行目录不同，本条缺陷正是只在真实调用形态下暴露。

**`_caller_email()` 的改造（M4 安全核心）：**

```
现有路径（一字不改）：token 有 email claim → idp/auth_via/email_verified 三重校验 → 返回
新增 on-behalf 路径：token **无** email claim
  且 claims.get("client_id") 与 _machine_client_id() 用 hmac.compare_digest 相等
  且 _machine_client_id() 非空
  且 X-SB-On-Behalf-Of 头存在且 permissions.EMAIL_RE.fullmatch 通过
  → 返回头值
其余 → NotOwner（现有文案一字不改）
```

四条硬约束：
1. `MACHINE_CLIENT_ID` **每次调用读环境变量**（`server.py:36` 的既有教训：固化成模块级常量后 monkeypatch 失效，拒绝类用例会永远假通过）
2. 环境变量缺失/空 → **拒绝**，不得因为"没配置"就跳过 client_id 比对（那正是 fail-open）
3. `hmac.compare_digest` 比对
4. **只有这条路径能跳过三重 claim 校验**，理由写在代码里（决定 8：创建时已验）

**为什么 on-behalf 路径跳过三重校验是安全的**（写进代码注释）：机器 token 天生没有 `idp`/`auth_via`/`email_verified`（spike 实测 claims 只有 10 个字段，一个都不是）。这个 email 的可信性来自**创建时**：Key 只能在 console 创建，而 console 的身份是 Edge 注入的 `x-user-email`，那条路径已过 `REQUIRE_IDP_CLAIM` 的校验。已知取舍：用户离职后旧 Key 仍有效，靠审计 + 吊销处理。

- [ ] **Step 1: 写失败测试（信任规则）**

`mcp/tests/test_tools.py` 追加。**最要紧的是冒充负测**：

```python
def test_ordinary_oauth_user_cannot_impersonate_with_the_header(monkeypatch):
    """**只看头 = 任何 OAuth 用户加个头就能冒充别人。**

    这条是 M4 最重要的负测。构造：一个**合法的** OAuth 用户 token
    （有 email claim、idp/auth_via 齐全、能正常调工具），额外带上
    X-SB-On-Behalf-Of: victim@x.com。必须解析成**他自己**，绝不是受害者。
    """


def test_machine_token_without_header_is_rejected(monkeypatch):
    """spike 已实证改造前的行为（"无法识别调用者身份"）；改造后仍必须拒。"""


def test_machine_token_with_header_resolves_to_header_value(monkeypatch):
    """正路径。"""


def test_wrong_client_id_with_header_is_rejected(monkeypatch):
    """client_id 不是 machine client 的 token 带头 → 拒。

    注意构造：**不能**用 mcp client 的 token 做这条（它有 email claim，
    会走第一条路径）。要构造"无 email claim 且 client_id 是别的值"的 token。
    """


@pytest.mark.parametrize("env", ["", "   ", None])
def test_missing_machine_client_env_rejects_all_on_behalf(monkeypatch, env):
    """**配置缺失不得退化成"不比对"**。"""


@pytest.mark.parametrize("bad", ["", "   ", "notanemail", "a@b",
                                "a@b.c,d@e.f", "<script>@x.com",
                                "a@b.com\nX-Injected: 1"])
def test_malformed_on_behalf_header_is_rejected(monkeypatch, bad):
    """头值必须过 EMAIL_RE.fullmatch。

    最后一条（含换行）尤其重要：邮箱形态校验顺带挡住头注入。
    """


def test_machine_client_id_is_read_per_call_not_module_level(monkeypatch):
    """照 _trusted_idps 的既有形态：固化成模块级常量会让拒绝类用例假通过。

    做法：先 import server（此时 env 未设），再 setenv，再调用——
    必须看到新值。
    """
```

`mcp/tests/test_component_gate.py`（新文件）覆盖三处门禁的纯函数：
- 无 `[ApiKey]` 段 → `api_key_enabled()` False；`allowed_clients()` 只有 mcp client；`request_header_allowlist()` 只有 `Authorization`
- 有 `[ApiKey]` 段 → 各自多一项
- **三个脚本用的是同一个 `api_key_enabled`**（AST：`deploy_agentcore.py` 与 `deploy_key_proxy.py` 不得出现 `has_section("ApiKey")` 字面量）

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/mcp && python3 -m pytest tests -q`

- [ ] **Step 3: 实现 `deploy_pool.ensure_resource_server` + `api_key_enabled`**

`ensure_resource_server`：`DescribeResourceServer` 命中即比对 scope 是否齐全（缺则 `UpdateResourceServer`），否则 `CreateResourceServer`。返回 `f"{identifier}/{scope}"`。

`main()` 的 ④ 步：

```python
    machine_scopes = ()
    if api_key_enabled(cfg):
        print("④a resource server + custom scope（API Key 组件已启用）")
        machine_scopes = (ensure_resource_server(
            cog, pool_id,
            identifier=cfg["ApiKey"].get("resource_server_id", "site-builder-mcp"),
            scope=cfg["ApiKey"].get("scope", "invoke")),)
    else:
        print("④a 跳过 resource server / machine client"
              "（config.ini 无 [ApiKey] 段 = OAuth-only，spec §5.1.1 组件门禁）")
    clients = _ensure_clients(cog, pool_id, base_domain, args.mcp_callback,
                              idp_name, include_machine=bool(machine_scopes),
                              machine_scopes=machine_scopes)
```

**`_ensure_clients()` 的签名要一并改**（现签名只到 `idp_name`，`client_configs` 的 `include_machine` 分支目前**没有任何调用方**）：加 `*, include_machine=False, machine_scopes=()` 两个 kwarg 并原样透传给 `client_configs`。不改它的话 `main()` 传了参数会 `TypeError`。

`_store_client_secrets` 的循环加 machine（仅当它存在）——写 `/site-builder/machine-client-secret`。注意该函数的 `param_prefix` 隔离逻辑不要动（spike 用临时 pool 时的保护），且它现在的循环是硬编码的单元素元组 `(("site", ...),)`，要改成按 `clients` 里实际存在的 key 取。

**`_assert_no_native_flows` / `_verify_no_native_flows` 对 machine client 是安全的**（已核对）：两者都是 `flows & set(NATIVE_AUTH_FLOWS)` 求交集，machine 的 `ExplicitAuthFlows` 是 `[]` → 交集为空 → 放行。它们判的是"有没有开原生 flow"，不是"有没有配 flow"，所以空列表不会被误判成漏配。**但要加一条用例锁定这一点**——将来若有人把判定改成"必须等于 `NATIVE_AUTH_DISABLED`"，machine client 会当场部署失败。

- [ ] **Step 4: 实现 `deploy_agentcore` 的两处派生**

`deploy_runtime()` 里：

```python
        authorizerConfiguration={"customJWTAuthorizer": {
            "discoveryUrl": _discovery_url(),
            "allowedClients": allowed_clients(CFG)}},
        ...
        requestHeaderConfiguration={
            "requestHeaderAllowlist": request_header_allowlist(CFG)},
```

两个纯函数：

```python
ON_BEHALF_HEADER = "X-SB-On-Behalf-Of"

# api_key_config 来自 deployer/functions/（**不是** scripts/deploy_pool）——
# 本脚本从 site-builder/mcp/ 执行，那个目录看不到 scripts/（Codex P1-3 实测）。
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
from api_key_config import api_key_enabled  # noqa: E402


def allowed_clients(cfg) -> list[str]:
    """authorizer 的 allowedClients。**这是组件门禁的第一层**（spec §5.1.1）。

    无 [ApiKey] 段时 machine client 不在此列 → 机器 token 在**网关层**就被拒，
    不经过我们任何代码。spike 已实证这条链 fail-closed。
    """
    out = [cfg["Cognito"]["mcp_client_id"]]
    if api_key_enabled(cfg):
        mid = cfg["Cognito"].get("machine_client_id", "").strip()
        if not mid:
            raise SystemExit(
                "[ApiKey] 段存在但 [Cognito] machine_client_id 为空——"
                "先跑 deploy_pool.py 建 machine client 并回填 config.ini")
        out.append(mid)
    return out
```

**`machine_client_id` 为空必须中止而不是静默跳过**：静默跳过会得到"以为部署了 API Key 其实网关不认"的状态，而排查方向会指向 server 端。

**同一处还要加 `environmentVariables` 的 `MACHINE_CLIENT_ID`**（Codex 审查 2026-08-11 P1-2b——原计划的修改清单漏了它，直到真机步骤才要求读回，严格照 Task 7 实施会得到"网关放行但容器内 `_machine_client_id()` 恒为空 → 所有 API Key 调用 fail-closed 被拒"）：

```python
        environmentVariables={
            ...
            # 有 [ApiKey] 段时下发；否则空串（server 侧空值 = 拒绝全部
            # on-behalf 请求，与组件门禁同向 fail-closed）。
            "MACHINE_CLIENT_ID": (CFG["Cognito"]["machine_client_id"].strip()
                                  if api_key_enabled(CFG) else ""),
            ...
        }
```

配套断言（纯函数层，不需要真机）：`allowed_clients` 含 machine client **当且仅当** `environmentVariables["MACHINE_CLIENT_ID"]` 非空。这两者一个来自网关配置、一个来自容器环境，**分别写就会漂移**——而漂移的那一半正好是"网关放行、容器拒绝"这个最难排查的状态（症状是 200 的 HTTP 加一句业务错误文案）。

- [ ] **Step 5: 实现 `server._caller_email()` 的 on-behalf 路径**

在现有 `if email:` 分支之后、`raise NotOwner` 之前插入。取头用与现有 `authorization` 相同的方式（`dict(request.headers)` 已 lower-case）。

- [ ] **Step 6: 确认转绿**

- [ ] **Step 7: 反向验证（本 Task 的重点）**

| 注入 | 必须变红 |
|---|---|
| on-behalf 路径去掉 client_id 比对 | `test_ordinary_oauth_user_cannot_impersonate_with_the_header` |
| `MACHINE_CLIENT_ID` 空时跳过比对继续 | 3 条 `test_missing_machine_client_env_rejects_all` |
| `MACHINE_CLIENT_ID` 改模块级常量 | `test_machine_client_id_is_read_per_call` |
| 头值不做 `EMAIL_RE.fullmatch` | 7 条 malformed（尤其含换行那条） |
| `EMAIL_RE.match` 而非 `fullmatch` | 含换行/逗号那两条 |
| `allowed_clients` 无条件加 machine | `test_component_gate` 的"无段"那条 |
| `machine_client_id` 空时不中止 | 对应用例 |
| `request_header_allowlist` 无条件加头 | 同上 |
| `deploy_agentcore` 自己写 `has_section("ApiKey")` | AST 那条 |
| `environmentVariables` 去掉 `MACHINE_CLIENT_ID` | "allowedClients 含 machine ⟺ MACHINE_CLIENT_ID 非空"那条 |
| `MACHINE_CLIENT_ID` 无条件下发（无 `[ApiKey]` 段也给值） | 同上（反方向） |
| 从 `site-builder/mcp/` 跑 `python3 deploy_agentcore.py --help` | 真实 CLI 那条（若 import 路径写错，这里 `ModuleNotFoundError`） |

- [ ] **Step 8: `config.ini.example` 更新**

`[ApiKey]` 段**删掉 `enabled` 键**，改为：

```ini
# 需要给"只能配静态 Header 的客户端"（如 Quick Desktop Remote MCP）用时才配：
# [ApiKey]
# keys_table = site-api-keys
# # client_credentials 必须有 resource server + scope（不能用空 scope 建 client）
# resource_server_id = site-builder-mcp
# scope = invoke
# # 交换层的子域（route_mode=api-only、require_auth=False）。
# # **它不进 Edge 的 PLATFORM_SUBDOMAINS**：key-proxy 只认 X-API-Key，
# # 不需要平台 cookie，进白名单只会让它白拿一个顶域会话 JWT。
# mcp_subdomain = mcp
#
# **应急关闸开关不在这里**：它是 site-api-keys 表里的一条哨兵行
# （key_hash="__switch__"），由管理员在控制台开关，即时生效、有审计。
# 放在 config.ini 会有两个陷阱：改了配置却不生效，或下一次部署把
# 控制台的关闸静默覆盖成开。首次部署 deploy_key_proxy.py 建行时是
# **关**（fail-closed）——部署完要去控制台开。
# 控制台不可用时的应急旁路见 DEPLOY.md「⑤c API Key 组件」。
```

- [ ] **Step 9: 提交**

`feat(m4): 三处组件门禁 + MCP on-behalf 信任规则（含冒充负测）`

---

## Task 8: `deploy_key_proxy.py`

**Files:**
- Create: `site-builder/key-proxy/deploy_key_proxy.py`
- Create: `site-builder/key-proxy/tests/test_deploy_key_proxy_contract.py`

**Interfaces:**
- Produces（可单测的纯函数 + 幂等收敛函数）：
  - `function_url_statements(edge_role_arn) -> list[dict]` —— 照抄 panel 的形态（两条语句，缺 arn 抛错）
  - `role_statements() -> list[dict]`
  - `lambda_environment(edge_role_id_value) -> dict`
  - `mcp_route_item(function_url) -> dict` —— `route_mode=api-only`、`require_auth=False`、`owner=platform`、`static_prefix=""`
  - `ensure_switch_row() -> str` —— 幂等：**不存在才建，且建成 `enabled=false`**；已存在则**一字不改**并返回当前值
  - `main() -> int`
- Consumes: `keygen.SWITCH_PK`、`api_key_config.{api_key_enabled,machine_scope,mcp_subdomain}`（来自 `deployer/functions/`，**不是** `scripts/deploy_pool`——见 Task 7 的 P1-3 说明）、`edge_caller.EDGE_ROLE_ID_ENV`

**`ensure_switch_row` 的幂等语义是本 Task 最容易写错的地方**：
- 不存在 → `PutItem` with `attribute_not_exists(key_hash)`，`enabled=False`
- **已存在 → 什么都不做**。绝不能"收敛成 config 里的值"——那正是决定 6 要消灭的陷阱（下一次部署把 admin 的关闸静默覆盖成开）
- 部署脚本最后**打印当前开关状态**，让人看到"组件已部署但开关是关的"

**组件门禁**：`main()` 开头 `if not api_key_enabled(cfg): print(理由); return 0`。**不是抛错**——"没配置"是合法的默认状态（OAuth-only），部署全平台的脚本链不应该因此中断。

- [ ] **Step 1: 写失败测试**

`test_deploy_key_proxy_contract.py` 覆盖：

| 组 | 用例 |
|---|---|
| 门禁 | 无 `[ApiKey]` 段时 `main()` 返回 0 且**零 AWS 调用**（boto3 层装间谍） |
| 门禁 | 无段时不建 route、不建哨兵行 |
| Function URL | 恰好两条语句、两个 action、Principal 逐字符等于 edge role；缺 `edge_role_arn` 抛错**中止** |
| role | 只对 api-keys 表有 `GetItem`/`UpdateItem`（**无 `BatchGetItem`**——已改成两次 GetItem；**无 `PutItem`**——创建在 panel；**无 `DeleteItem`**；**无 `Scan`**）；SSM 只有精确 ARN 的 `GetParameter`（**不用前缀**）；无 `iam:*`、无 `lambda:*` |
| 环境变量 | 无明文密钥（沿用 verify 脚本的两类判据）；含 `MACHINE_SECRET_PARAM` 而非 secret；含 `EDGE_ROLE_ID`；**含 `MACHINE_SCOPE` 且其值 == `{resource_server_id}/{scope}`（从 config 派生，不得硬编码 `site-builder-mcp/invoke`）** |
| route | `route_mode == "api-only"`、`require_auth is False`（**布尔不是字符串**）、`owner == "platform"`、`static_prefix == ""`、`api_target` 无尾斜杠 |
| 哨兵行 | 首次建为 `enabled=False`（**不是 True**）；已存在时重跑**一字不改**（先置 True 再重跑，仍是 True） |
| 哨兵行 | `attribute_not_exists` 条件写（并发部署不会互相覆盖） |
| 复制清单 | 传递闭包核对 `handler.py` 的 import 链（照 panel 的 `test_copy_files_covers_every_local_module_panel_imports`，**用同样的两个搜索目录**）。清单至少含 `edge_caller.py` / `keystore.py` / `keygen.py` / `api_key_config.py` |
| 真实 CLI | `subprocess` 从 `site-builder/key-proxy/` 跑 `python3 deploy_key_proxy.py --help`，退出码 0 且 stderr 无 `ModuleNotFoundError`（Codex P1-3：pytest 的 sys.path 与真实执行目录不同） |

- [ ] **Step 2-4: 确认失败 → 实现 → 确认转绿**

`require_auth` 写 `{"BOOL": False}`（不是 `{"S": "false"}`）——Edge 的判定是 `require_auth is False`，字符串会走进"按需要登录处理"，而 key-proxy 的调用方没有会话，结果是 302 到登录页（客户端拿到一坨 HTML）。

- [ ] **Step 5: 反向验证**

| 注入 | 必须变红 |
|---|---|
| 门禁改成无段也部署 | 门禁两条 |
| `MACHINE_SCOPE` 不下发 / 硬编码 `site-builder-mcp/invoke` | 环境变量组的 `MACHINE_SCOPE == {resource_server_id}/{scope}` 那条 |
| `import deploy_pool` 取门禁判定 | 真实 CLI 那条（`ModuleNotFoundError`） |
| 哨兵行首次建成 `True` | 哨兵行第一条 |
| `ensure_switch_row` 改成无条件 `PutItem(enabled=cfg值)` | 哨兵行第二条（重跑不改） |
| 去掉 `attribute_not_exists` | 条件写那条 |
| role 加 `PutItem` | role 组 |
| SSM 改前缀通配 | role 组 |
| `require_auth` 写字符串 | route 组 |
| `api_target` 带尾斜杠 | route 组 |
| Function URL 只留一条语句 | Function URL 组 |
| 缺 `edge_role_arn` 时 fallback 到 `*` | Function URL 组 |

- [ ] **Step 6: 提交**

`feat(m4): deploy_key_proxy.py（幂等；哨兵行首次为关，重跑不覆盖）`

---

## Task 9: 前端 Key 页面与开关

**Files:**
- Modify: `site-builder/panel/frontend/app.js`
- Modify: `site-builder/panel/frontend/app.css`（如需）
- Modify: `site-builder/panel/tests/test_frontend_contract.py`
- Modify: `site-builder/panel/tests/test_frontend_boot.py`（如启动路径受影响）

**Interfaces:** 前端调 Task 6 的 5 个端点；`state.me.features.api_key.deployed` 决定 disabled 与否，`.enabled` 只驱动状态提示与开关初值（Codex P1-5：**不能用 `.enabled` 做 UI 门禁**，否则首次部署后 admin 无处点开闸）。

**三层测试分工照 M3-FINDINGS §2.20 的结论**（不可互相替代）：
- `test_frontend_contract.py` 查"代码里有没有"
- `test_frontend_boot.py` 查"跑起来会不会崩"
- `verify_api_key_e2e.py`（Task 11）查"线上通不通"

**M3 的五处前端假绿形态要避开**（M3-FINDINGS §2.17）——本前端**全用 `+` 拼接**（不是模板插值），断言要按**顶层 `+`** 切分；不要绑定到 `setTimeout` / `tries` / `application/json` 这类通用字样。

**功能面（spec §4.3 第 4 条）：**
1. 列表：备注名、前缀 `sk-xxxx…`、创建时间、最后使用、状态
2. 创建：明文**完整显示一次** + 复制按钮 + "关闭后不再显示"警告
3. 吊销：二次确认
4. admin 额外：开关（含"关闸后所有 Key 立即失效"的说明）
5. `features.api_key.deployed` 为 false → 页面与导航显示 disabled + 说明原因，**不发任何请求**
6. `deployed=true` 且 `enabled=false`（首次部署后的正常状态）→ **页面可用**：列表/创建照常，顶部显示"API Key 当前已被管理员全局关闸，新建的 Key 暂时无法调用"，admin 额外看到开关且能打开

- [ ] **Step 1: 写失败测试**

`test_frontend_contract.py` 追加：

| 用例 | 绑定到本功能特有的东西 |
|---|---|
| 创建响应的明文**只写进 DOM 一次**且不进 `localStorage`/`sessionStorage`/URL | 断言不出现 `localStorage.setItem` 与 `location.hash =` 携带明文的形态 |
| 明文展示区有"不再显示"警告文案 | 查该文案常量 |
| 吊销走 `POST /api/keys/revoke` + body 带 `key_id`（**不是明文**） | 解析该 fetch 调用的 method 与 body 键 |
| `deployed=false` 时**零 fetch** | 在 boot harness 里跑，间谍 fetch |
| `deployed=true, enabled=false` 时**页面可用且 admin 能看到开关** | 同一 harness 换 features 取值；断言渲染出开关控件且发了列表请求。**这条是部署自锁的闸门**——按单布尔实现时它必红 |
| 所有插值过 `esc()` | 按顶层 `+` 切分（M3-FINDINGS §2.17 第 11 条的二段坑：不能要求两侧都有 `+`，续行开头的表达式会被跳过） |
| 开关 UI 只在 `is_admin` 时渲染 | — |
| 不请求 M5 的 stats/audit | 沿用既有断言 |

`test_frontend_boot.py`：Key 页面在 `features.api_key` 的**三种**状态下都能渲染不崩（`deployed=false` / `deployed=true,enabled=false` / 两者都 true）。M3 那条"骨架屏卡死"就是 boot 路径的执行顺序问题，静态断言看不见。

- [ ] **Step 2-4: 确认失败 → 实现 → 确认转绿**

- [ ] **Step 5: 反向验证**

删掉"不再显示"警告、把 `key_id` 换成明文、把 `esc()` 去掉一处、`deployed=false` 时仍发请求、开关对非 admin 也渲染、**把门禁判据从 `.deployed` 改成 `.enabled`**（必须让"已部署但关闸"那条红）——逐条确认变红。

**假红同样要处理**（M3-FINDINGS §2.16）：新断言若命中的是自己写的注释，必须修断言（用剥注释器）而不是放宽它。

- [ ] **Step 6: 提交**

`feat(m4): 控制台 Key 页面与 admin 开关（组件未部署时 disabled）`

---

## Task 10 [真机]: 四步部署 + verify 第 ⑧ 段

> **执行前停下来征得用户同意**（Global Constraints）。本 Task 会改动生产 Cognito pool 与生产 AgentCore runtime。

**Files:**
- Modify: `site-builder/scripts/verify_deployed_components.py`（第 ⑧ 段）

**部署顺序严格按上文「部署顺序」的 ①→⑤**，每步之间**读回核对**再进下一步。

- [ ] **Step 1: 部署前基线快照**

记录（供回滚与事后核对）：
```bash
aws cognito-idp describe-user-pool-client --user-pool-id <pool> --client-id <mcp> --query 'UserPoolClient.{flows:ExplicitAuthFlows,providers:SupportedIdentityProviders,at:AccessTokenValidity,rt:RefreshTokenValidity}'
aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id <id> --query '{clients:authorizerConfiguration.customJWTAuthorizer.allowedClients,allow:requestHeaderConfiguration.requestHeaderAllowlist,uri:agentRuntimeArtifact.containerConfiguration.containerUri}'
```
**核对 `allowedClients` 现在是 1 个、allowlist 只有 `Authorization`**（spike 后确认过的状态；若不是，先查清是谁改的再继续）。

- [ ] **Step 2: 部署 deployer 栈（新表）**

```bash
cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```
读回：表存在、两个 GSI `ACTIVE`、`DeletionProtection`/RETAIN 形态符合预期。

- [ ] **Step 3: ① `deploy_pool.py`（resource server + machine client）**

先在 `config.ini` 加 `[ApiKey]` 段（**gitignored**，真实值不进仓库）。

```bash
cd site-builder && python3 scripts/deploy_pool.py
```
读回：
- `describe-resource-server` 有 `site-builder-mcp` + scope `invoke`
- machine client 存在，`AllowedOAuthFlows == ["client_credentials"]`、`AllowedOAuthScopes == ["site-builder-mcp/invoke"]`、`ExplicitAuthFlows == []`
- **site/mcp client 的 `SupportedIdentityProviders` 与 Step 1 快照一致**（`client_configs` 的独立副本机制；M4 走 `include_machine=True` 是"最可能第一次踩到"共享 list 的路径——`deploy_pool.py:100-103` 的注释明写了这条）
- SSM 有 `/site-builder/machine-client-secret`，且**没打印明文**
- 回填 `machine_client_id` 到 config.ini

**立刻验一次负向**：此时用 machine client 换 token 调 AgentCore 应该**仍然失败**（它还没进 allowedClients）。这条证明 ① 单独部署没有开任何门。

- [ ] **Step 4: ② `deploy_agentcore.py`（allowedClients + allowlist）**

```bash
cd site-builder/mcp && python3 deploy_agentcore.py --skip-build
```
（`--skip-build` 只改配置——此时 server.py 还没改，不需要重建镜像。）

读回：`allowedClients` 2 个、allowlist 含 `X-SB-On-Behalf-Of`。

**立刻验中间态安全**（spike 的结论要在生产上复现一次）：机器 token + on-behalf 头调 `list_my_sites` → 必须得到"无法识别调用者身份（缺少 OAuth email claim）"。**这一步拿到数据就是严重缺陷，立即停止并回滚 allowedClients。**

- [ ] **Step 5: ③ MCP server 改造上线**

```bash
cd site-builder/mcp && python3 deploy_agentcore.py
```
（不带 `--skip-build`：server.py 改了，要重建镜像。`_BUILD_INPUTS` 含 `mcp/server.py`，tag 会变。）

读回：runtime 按新 digest 部署（`@sha256:` 变了）、**环境变量 `MACHINE_CLIENT_ID` 非空且等于 config 里的值**（Task 7 已把它加进 `environmentVariables`；若为空则容器内所有 on-behalf 请求都会 fail-closed 被拒——这正是 Codex P1-2b 指出的漏接线）。

**此时验证正路径**：手动用 machine token + on-behalf 头调 `list_my_sites` → 应返回**该 email 的站点**。同时验冒充负测：用自己的 OAuth token + `X-SB-On-Behalf-Of: 别人` → 必须返回**自己的**站点。

- [ ] **Step 6: ④ `deploy_key_proxy.py`**

```bash
cd site-builder/key-proxy && python3 deploy_key_proxy.py
```
读回：Lambda 存在、Function URL AuthType=AWS_IAM + 两条语句、`mcp` route 形态正确、**哨兵行 `enabled=false`**、**环境变量 `MACHINE_SCOPE` 等于 `{resource_server_id}/{scope}`**、脚本明确打印了"开关是关的，去控制台开"。

此时用一把 Key 直连 → 必须 401（开关关着）。

- [ ] **Step 7: `deploy_panel.py`（Key 页面 + 端点）**

```bash
cd site-builder/panel && python3 deploy_panel.py
```
**不带 `--skip-frontend`**（衔接点 2：前端改了要上传，内容指纹会给出新前缀）。

读回：新前缀的三个对象在、console route 的 `static_prefix` 指向新前缀、旧前缀仍在（可回滚）。

- [ ] **Step 8: ⑤ 控制台开闸**

**开闸之前先验"已部署但关闸"这个状态是可操作的**（Codex P1-5 的真机确认）：此时哨兵行是 `enabled=false`，浏览器进控制台 → API Key 页面**必须可用**（不是 disabled）、`/api/me` 返回 `features.api_key = {deployed: true, enabled: false}`、admin 能看到开关。**若此时页面是 disabled，就是自锁缺陷，停止并回到 Task 6/9。**

然后 admin 打开开关 → 读回哨兵行 `enabled=true`、`updated_by` 是操作者、ops_log 有一条。

- [ ] **Step 9: `verify_deployed_components.py` 第 ⑧ 段**

新增 `run_key_proxy()`，照第 ⑤ 段的形态（含 `_verify_direct_invoke_is_rejected` 的复用——把它参数化成接受 `fn` 与探测路径）：

| 断言 | 说明 |
|---|---|
| `site-key-proxy` 存在 + LastModified | — |
| 产物的模块与本地字节一致 | `handler.py`/`keystore.py`/`machine_token.py`/`keygen.py`/`edge_caller.py`/`api_key_config.py`（**从 `deploy_key_proxy.COPY_FILES` 推导，不手抄**） |
| **同时修 ⑤ 段（panel）的清单** | 现在是**硬编码的 7 个模块**（`verify_deployed_components.py:316-333`），而 panel 的 `COPY_FILES` 已是 5 个共享模块 + Task 6 后共 8 个 → `edge_caller.py` 等**进了部署包却从不做真机字节比对**，单测闭包与这道闸门**同时绿**。改成从 `deploy_panel.COPY_FILES` + panel 自有 `.py` **推导**（Task 1 审查的 Minor 2；手抄的清单本身就是下一个漂移源，M3-FINDINGS §2.18） |
| 环境变量无明文密钥 | 沿用两类判据；含 `MACHINE_SECRET_PARAM` 且以 `/` 开头 |
| Function URL AuthType=AWS_IAM + 恰好两条语句 + Principal 逐字符 | — |
| `EDGE_ROLE_ID` == IAM 真实 RoleId | 沿用第 ⑤ 段的现查形态 |
| **非 Edge 直连必须 403** | 反向闸门；当前身份无权限时 SKIP 而非 PASS |
| `mcp` route 形态 | `api-only` / `require_auth is False` / `owner=platform` / `api_target` 无尾斜杠 |
| **`mcp` 不在 Edge 产物的 `PLATFORM_SUBDOMAINS` 里** | 决定 9 的闸门 |
| `allowedClients` 含 machine client、allowlist 含 on-behalf 头 | 从线上 runtime 读 |
| 哨兵行存在且 `enabled` 是**布尔** | 类型也要断言（字符串 `"true"` 会被 keystore 拒，症状是"开了但全 401"） |
| key-proxy 环境变量 `MACHINE_SCOPE` == config 派生值 | 硬编码或缺失都要抓（Codex P1-2a） |
| MCP runtime 环境变量 `MACHINE_CLIENT_ID` 非空 ⟺ `allowedClients` 含 machine client | 两者分处网关与容器，**分别写就会漂移**；漂移的那一半正好是最难排查的"网关放行、容器拒绝"（Codex P1-2b） |
| key-proxy role 无 `PutItem`/`DeleteItem`/`Scan` on api-keys | 权限收窄的闸门 |

**最小检查数下限**要相应提高（Global Constraints）。

- [ ] **Step 10: 跑全部闸门**

```bash
python3 site-builder/scripts/verify_deployed_components.py
python3 site-builder/scripts/verify_console_e2e.py      # 从仓库根跑
bash site-builder/scripts/smoke_router.sh
bash site-builder/scripts/verify_deployed_edge.sh
python3 site-builder/scripts/verify_permission_matrix.py
```
**Edge 没改**（决定 9 只加注释），所以 `verify_deployed_edge.sh` 应无变化——若它红了说明动了不该动的。

- [ ] **Step 11: 提交**

`feat(m4): 四步真机部署 + verify 第 ⑧ 段（key-proxy 一致性闸门）`

---

## Task 11 [真机]: `verify_api_key_e2e.py`

> **执行前停下来征得用户同意。** 本脚本会创建真实 Key 并完成一次真实部署。

**Files:**
- Create: `site-builder/scripts/verify_api_key_e2e.py`

**六个场景 + 负测**（每个都必须是真机 HTTP，不是 moto）：

| # | 场景 | 断言 |
|---|---|---|
| 1 | 控制台创建 Key | 响应含明文；再列表时**不含**明文与 hash |
| 2 | 静态 Header 直连 `mcp.{domain}` 完成一次**真实部署** | MCP `initialize` → `tools/list` → `deploy_site` → `confirm_upload` → 轮询到 SUCCEEDED → 站点 URL 可访问 |
| 3 | 吊销后**立即** 401 | 吊销与下一次调用之间不等待（这是"不缓存"的真机证据） |
| 4 | 关闸 → 全部 Key 401 | 用另一把有效 Key 验（证明是全局关闸不是单 Key） |
| 5 | 开闸 → 恢复 | — |
| 6 | 四种拒绝原因**响应体逐字节相同** | 无效/吊销/关闸/未知 |
| N1 | 普通 OAuth token + on-behalf 头 | 解析成**自己**，不是头里那个人 |
| N2 | 机器 token 直连 AgentCore（绕过 key-proxy）不带头 | 拒（"无法识别调用者身份"） |
| N3 | 非 Edge 直连 key-proxy Function URL | 403 |
| N4 | 明文 Key 不在任何日志里 | 查 key-proxy 与 panel 的 CloudWatch 日志组，grep 明文**零命中** |

**纪律**（照 spike 与 M3 的既有做法）：
- 一次性后缀资源（Key 备注名带随机后缀、站点名带后缀）
- `finally` 里逐个删除并**读回核对**
- 清理失败即测试失败（不是打印警告）
- `MIN_CHECKS` 下限 + 非零退出
- 脚本自身不打印明文 Key（只打前缀）
- **开关状态要在 finally 里恢复成进入时的值**——脚本跑一半崩掉不能把生产开关留在关闸状态

**N4 的实现要点**：CloudWatch Logs 的 `FilterLogEvents` 用明文做 filter pattern。**注意这本身会把明文写进 API 调用参数**（可能进 CloudTrail）。改为：拉回时间窗内的日志事件到本地，在本地 grep。这条要写在脚本注释里，否则下一个人会"优化"成服务端 filter。

- [ ] **Step 1: 写脚本（先跑负向确认它会红）**

**这个脚本自己也要双向验证**（M3-FINDINGS §2.19：验收脚本的假红/假绿影响面比单测更大，因为它决定"要不要动生产"）。做法：临时把开关关掉，确认场景 2 变红；临时用错的 email 断言，确认场景 1 变红。

- [ ] **Step 2: 跑通六场景 + 四负测**

- [ ] **Step 3: 反向验证脚本自身**

至少三条：① 把某条 `check()` 的期望值改反，确认变红；② 让清理路径抛异常，确认脚本非零退出；③ 把 `MIN_CHECKS` 提高到超过实际数，确认它报"检查数不足"而不是静默通过。

- [ ] **Step 4: 提交**

`test(m4): verify_api_key_e2e.py——六场景 + 四条负测（含冒充与日志泄漏）`

---

## Task 12: 全量回归与文档收尾

**Files:**
- Modify: `site-builder/DEPLOY.md`、`CLAUDE.md`、`site-builder/docs/client-setup.md`、`site-builder/scripts/gen_onboarding.py`
- Modify: `docs/design/HANDOFF-2026-08-07.md`（gitignored，新增「更新 12」）
- Modify: `docs/design/M3-FINDINGS.md` 或新建 `M4-FINDINGS.md`（gitignored）
- Modify: `.superpowers/sdd/<本计划>/progress.md`

- [ ] **Step 1: 七个包全量回归**

```bash
cd site-builder/contract && .venv/bin/pytest tests -q
cd site-builder/auth     && ../contract/.venv/bin/pytest tests -q
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q
cd site-builder/deployer && .venv/bin/pytest tests -q
cd site-builder/mcp      && python3 -m pytest tests -q
cd site-builder/panel    && ../deployer/.venv/bin/pytest tests -q
cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q
```
另跑 `site-builder/mcp/run_locked_tests.sh`（改过 server.py，要确认锁定依赖那套也全绿）。

- [ ] **Step 2: 九个闸门**

M3 的八个 + 新增 `verify_api_key_e2e.py`。数字记进 HANDOFF，**不写进 `CLAUDE.md`**（会过时）。

- [ ] **Step 3: 核对 spec 与 `config.ini.example` 的开关口径已经是哨兵行**

**这一步在 2026-08-11 已经先做掉了**（Codex 审查 P1-1 要求"不能把 spec 修复留到实施后"，而当时 Task 12 也没写这件事）：
- `spec §5.1.1` 第 2 条已从 `[ApiKey] enabled = false` 改为哨兵行，并写明"两个真源比没有开关更危险"与三条选型理由，另追加"未部署 vs 已部署但关闸必须可区分"（P1-5）；
- `config.ini.example` 的 `[ApiKey]` 段已删掉 `enabled` 键，补 `mcp_subdomain` 与"开关在控制台 + 应急旁路指向 DEPLOY.md ⑤c"。

本步只需**核对没有回退**（改代码期间可能有人照旧文档又加回来）：
```bash
grep -n "enabled" site-builder/config.ini.example        # [ApiKey] 段内不得有 enabled =
grep -n "ApiKey. enabled" docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md
```
两条都应无命中（spec 里只应出现在"已改为哨兵行"的说明文字中）。

- [ ] **Step 4: `DEPLOY.md` 新阶段「⑤c API Key 组件（可选）」**

必须含：
- **四步部署顺序与"任一步停下都不产生提权窗口"的理由**
- 三处门禁各自的表现（漏一处的症状分别是什么——这是排查表）
- **应急旁路**：控制台不可用时用 aws CLI 直改哨兵行的确切命令
- **首次部署后开关是关的**，要去控制台开
- 不需要 API Key 时**整段不配置**即可（推荐默认）
- 已知取舍：用户离职后旧 Key 仍有效（决定 8）

- [ ] **Step 5: `CLAUDE.md`**

架构图补 ⑦ key-proxy；测试命令补 key-proxy 包；部署命令补 `deploy_key_proxy.py`；高频坑补两条（哨兵行 `enabled` 必须是布尔；`mcp` 子域故意不在平台白名单）。**不写测试数与闸门数字**（指向 HANDOFF）。

- [ ] **Step 6: `client-setup.md` + `gen_onboarding.py`**

Remote MCP + 静态 Header 的配置片段；stdio 代理降级标注为"兼容方案"。`gen_onboarding.py` 在组件已部署时输出 API Key 章节。

- [ ] **Step 7: HANDOFF「更新 12」**

进度、部署状态、闸门数字、本轮的实测发现、以及**下一步（M5）的入口**。

- [ ] **Step 8: 实测发现归档**

本轮凡是"跑出来才知道"的都要记（形态照 M3-FINDINGS §2）：假绿/假红的具体形态、真机与文档不符之处、以及每条"注入后确实变红"的记录。

- [ ] **Step 9: 提交**

`docs(m4): 全量回归 + DEPLOY/CLAUDE/client-setup 同步（M4 交付）`

---

## Codex 审查轮（2026-08-11）：5 个 P1 + 2 个 P2，全部已改

审查基线：spec `3d7c3f3` / M3 修复 `44aef8d` / 本计划 `a6b3106`。结论是 NO-GO，**7 条我全部核对后接受**（其中 P1-3 我在本仓库实测复现了 `ModuleNotFoundError`）。两个 P2 的**诊断**接受、**建议的修法**未采纳，理由见下。

| # | 问题 | 处置 |
|---|---|---|
| P1-1 | 开关有两个真源：spec §5.1.1 与 `config.ini.example` 仍写 `enabled=false`，而计划只读哨兵行 → 运维按文档设 `false` 而 Key 全部继续有效 | **接受**。spec §5.1.1 与 `config.ini.example` **本轮就改**（不留到实施后），Task 12 加一步核对没回退 |
| P1-2a | key-proxy 不知道该请求哪个 scope（环境变量清单里既无 `resource_server_id` 也无完整 scope），实施者只能硬编码或自造变量 | **接受**。新增 `MACHINE_SCOPE` 环境变量，由 `deploy_key_proxy.py` 从 config 拼好下发；缺失即 `TokenUnavailable` 且不发 HTTP |
| P1-2b | Task 7 的修改清单没要求把 `MACHINE_CLIENT_ID` 加进 AgentCore `environmentVariables`，直到真机步骤才读回它 → 严格照 Task 7 实施则容器内恒为空、所有 Key 调用被拒 | **接受**。Task 7 显式加该环境变量 + 一条"`allowedClients` 含 machine ⟺ 环境变量非空"的纯函数断言 |
| P1-3 | `deploy_agentcore.py` / `deploy_key_proxy.py` 从各自目录执行，都看不到 `scripts/`，`import deploy_pool` 必崩（**已实测复现**） | **接受**。门禁判定移到 `deployer/functions/api_key_config.py`；每个脚本加一条"按文档里的真实 CLI 命令跑 `--help`"的 subprocess 测试 |
| P1-4 | panel 复制清单漏 `keystore.py`，且 `keygen.py` 写成从已不存在的 `key-proxy/` 复制 | **接受**。这是我 self-review 期移动模块后漏改的自相矛盾。清单明确为四个模块、全部从 `deployer/functions/` 取 |
| P1-5 | `features.api_key` 单布尔无法表达三态；首次部署哨兵行是关的 → 前端 disabled + 零请求 → admin 无处开闸，**部署自锁** | **接受**。改 `{"deployed", "enabled"}`；`deployed` 决定 UI 可用性，`enabled` 只驱动提示。Task 9 与 Task 10 Step 8 各加一条闸门 |
| P2-6 | "同一次 `BatchGetItem` = 同一时刻原子快照"是错误的 AWS 契约；且它与"关闸时不查 Key"自相矛盾 | **诊断接受，修法二选一里取"先开关后 Key 两次读"**。不用它提的 `TransactGetItems`：两个值之间没有需要原子性的不变量（开关关了就拒，与 Key 当时什么状态无关），用事务读只是白付两倍读容量 + 多一个 IAM action |
| P2-7 | `key_id` 当唯一吊销标识但 GSI 无唯一约束；"3000 个不重复"不证明线上唯一 | **诊断接受，不采纳"改成 128-bit"**。`key_id` 是给人看/粘的标识符，spec §5.1 已定 8 位，加长牺牲该用途且**仍需**处理"万一"。改在写入侧：创建时 Query 检测 + 重试（≤5）、吊销时行数 ≠ 1 一律 fail-closed（**绝不取第一行**）、`UpdateItem` 带 `key_id + email` 条件 |

**这一轮暴露的方法论问题**（值得记进 M4-FINDINGS）：P1-4 与 P1-2b 都是**我自己在 self-review 期改了落点/加了要求，但没有把所有引用处一起改**——与 M3-FINDINGS「别打地鼠，修那一类」同源，只不过这次载体是计划文档而不是代码。教训：移动一个模块后要 grep 全文所有提到它的地方（我只改了"文件结构"表，漏了 Task 6 的正文步骤）。

---

## Self-Review 结论

**Placeholder 扫描**：Task 3 的 `test_no_module_level_cache.py` 三个函数体标了"Step 3 补全"——这是有意的（函数体依赖实现细节，先定意图与边界），不是 TBD。其余无占位。

**Codex 轮之后的一致性复查**（2026-08-11）：`switch_enabled` → `switch_state` 全文替换完毕；`_batch_get` / `BatchGetItem` 的残留只剩两处，都是**有意的**（补充 B 里解释"原方案为什么错"、Task 3 反向验证表里作为要注入的缺陷）；`features.api_key` 的所有引用都已带 `.deployed` / `.enabled` 限定；key-proxy role 的 action 清单去掉了 `BatchGetItem`；Tech Stack 行改成"强一致 GetItem"。

**内部一致性**：
- 决定 6（开关落 DDB）与 Task 7 Step 8（`config.ini.example` 删 `enabled` 键）一致
- 决定 9（`mcp` 不进白名单）与"修改"表里 `origin_request.py` 只加注释一致，且 Task 10 Step 10 明确要求 `verify_deployed_edge.sh` **无变化**
- 补充 D（`edge_caller` 提取）排在 Task 1，被 Task 5（key-proxy handler）与 Task 8（复制清单）依赖，顺序图正确

**范围**：12 个 Task，与 M3 的 16 个同量级。M5（统计）严格排除。

**歧义消解**：
- "不缓存"明确到"哪些不能、哪个能"（Task 3/4 各有断言，且 Task 3 Step 5 有"删掉 machine_token 缓存必须红"的反向条目，防止为了让结构断言绿而把缓存全删）
- "透明转发"明确到逐项的头白名单与 SSE 口径（Task 5 的表）
- 开关的 `enabled` 判定方向与 `revoked` 的判定方向**相反**，两处都写明了理由（Task 3 的 fail-closed 矩阵）
