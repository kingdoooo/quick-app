# asset-v1 · 08 3c-final：会话签名 KMS-only 硬切换 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **本 plan 在主会话（coordinator）里按 `executing-plans` 串行执行。** 标了 ★ 的 Task 是 coordinator 手动任务（部署 / 真机闸门 / 不可逆步骤），`executing-plans` 的 checkpoint 落在它们上；其余 Task 是代码任务，每个都以"该包套件绿 + commit"收尾。

**Goal:** 让资产的会话签名只剩一种形态——两把 KMS 非对称 CMK（RS256，`kms:Sign` RAW）签、三处 verifier 本地验公钥——并把 HS256 密钥材料、legacy 入口、signer 开关、跨算法双接受、基线迁移通道与 blue/green 存量迁移脚本从资产里**删掉**；验收工具改为经 auth 的受控夹具签发器取得登录态；账号信任边界闸门开始观测 KMS 面；验证环境按 ADR 0005 **硬切换**一次。

**Architecture:** `auth/session.py` 变成 RS256 的 JOSE 合同（严格 base64url、拒 `crit`、`alg` 只与 allowlist 比对、签名长度等于模长、公钥侧 SPKI 四项检查），签名由注入的 `sign(bytes)->bytes` 回调完成（生产 = 新模块 `auth/session_kms.py` 的 `KmsSigner`，测试 = 本地私钥）；`verifier_env.load_allowlist` 的每一行按 `key_arn` 经 `kms:GetPublicKey` 取公钥并与 `spki_sha256` 比对后才装进 allowlist（fail closed）。Edge 的 allowlist 从"kid → secret"变成"kid → base64 DER SPKI"，验签用 synth 时按 hash 交叉装进产物的 `cryptography`（ADR 0003），import 期用 tracked 的黄金三元组预热一次。CMK 由 deployer CDK 栈创建（默认 key policy，ADR 0001），`[SessionKeys]` 只剩 RS 行，三个部署脚本在第一次写之前对每个 RS kid 做 `DescribeKey` + `GetPublicKey` 四项校验。auth 新增 `POST /fixture-session`（只对 `site-builder-verifier` 角色、只签夹具域 `e2e.invalid` 的站点会话；ADR 0002），Edge 与 panel 同一次部署上线夹具会话的边界规则；`scripts/_session_mint.py` 整体换成夹具签发器的客户端，六处调用方的接口不变。闸门 `verify_account_trust_boundary.py` 删 HS 扫描与 3/4→5 迁移通道、加 KMS 层（`kms:Sign` / `kms:PutKeyPolicy` / `kms:CreateGrant` 持有者、key policy 快照、grants、公钥指纹），schema 6，基线不再 tracked。

**Tech Stack:** Python 3.12（五个 venv）/ 3.13（auth、panel Lambda）/ 3.11（Lambda@Edge，x86_64）；`cryptography==50.0.0`（auth 与 MCP 锁定清单里同一版本，hash 钉死；panel 与 Edge 新增同一版本的交叉装法）；boto3 KMS（`DescribeKey` / `GetPublicKey` / `Sign`）、STS（`AssumeRole`）、Lambda、IAM；AWS CDK v2（`aws_kms.Key`）；pytest + moto（KMS 的 RS 行为**不用 moto**——moto 的 `kms:Sign` 对 RSA 不产出可验的签名，用本文件定义的 `FakeKms` 替身，签名由本地私钥算）。

**Spec:** 工单 `.scratch/asset-v1/issues/08-3c-final-kms-only-hard-cutover.md`（gitignored，主 worktree）；设计真源 `docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md`（§6.1 的 3c-final 行是当前定义；§6.2「3c-1B 留给 3c-3 的精确清单」是删除清单；§11.1 vendored cryptography、§11.2 key policy、§11.4 字面量、§11.5 `kms:Sign` RAW、§11.6 三层绑定、§11.7 夹具签发器、§11.9 资产框架）；ADR 0001 / 0002 / 0003 / 0005；威胁模型 `docs/security/account-trust-boundary.md`；工单 Comments 里 2026-09-06 code-review 的三条（硬切换窗口、删迁移脚本要连带删两处守卫与两处文档、删 HS 时矩阵两行一起删）。

**证据分级（本计划自身）**：下面每个 Task 的代码块是**候选实现**，写 plan 时只做了静态校验（`ast.parse`、引用的路径 / 函数 / 常量在当前源码里存在、与 §6.2 删除清单逐项对上）——级别是 **static**；72 个 Python 代码块里 56 个可独立 `ast.parse`，16 个是标了「【片段】」的函数体 / 字典片段（执行时按落点缩进）；三个 bash 块内嵌的 `python3 - <<'PY'` 也各自 `ast.parse` 过。没有在任何 venv 里收集或运行过（本 plan 与 04/09 不同：它删的是三处 verifier 共用的合同，任何一处先改都会让六个套件成片转红，没有"先在镜像上跑绿"的中间态）。每个 Task 的 Step 2 都写了预期的红，执行时以那个为准；真机行为由 ★ Task 的部署与闸门给出，标 **production**。

## 决策门（plan 过门前请逐条裁定；每条都给了推荐项，全按推荐即可开工。过门时经 grill 核验，九处修订已并入：D1 理由、D2 双对照、D3 代价、D6 路由表实况、D7 回滚就位、D11 每次 mint 现 assume、Task 0 Step 2b、Task 17 Step 3b、Task 19 的 MCP / key-proxy 重部）

| # | 决策 | 推荐 | 理由 / 代价 | 备选（否决理由） |
|---|---|---|---|---|
| D1 | `account_trust_baseline.json` 在**本票**就 untrack，还是留给工单 12 | **本票 untrack**（Task 13 改 `.gitignore` + `git rm --cached`，Task 21 ★ 用 `--update-baseline` 重生成到 gitignored 路径） | 作者账号的基线（哪怕只是指纹）对采用者没有意义，过不了 ADR 0005 的"全新用户新账号"检查；3c-final 之后基线整个换形（schema 6），本票反正要动读基线的十余处断言，顺手 untrack 不另花功夫。**换 schema 本身不需要迁移通道**（重生成即可）——真正的取舍只在审计轨迹：tracked 时 git 历史就是"接受了什么"的留痕，untrack 后这条轨迹改由 `.scratch/asset-v1/08/` 里 `--update-baseline` 打印的比较报告 + 工单 Comments 承担（Task 21 ★ / 22 ★）。ADR 0005 Consequences 里"工单 12 执行"那句随本票改成"工单 08"；工单 12 第 3 条收窄为只剩探针 JSON（Task 22 ★） | 留给 12：`test_verify_account_trust_boundary.py` 十余处读基线文件的断言本票已要改一遍，留给 12 等于同一批用例改两次；且基线以 schema 6 重生成后再 tracked 一次，只是多一个马上要删的提交 |
| D2 | 切换后闸门怎么"接受"：精确 delta 声明，还是一次 `--update-baseline` | **一次 `--update-baseline`**，但前置**两次对照**：Task 0 ★ 在动任何代码之前用旧代码 + 旧基线跑一遍闸门必须绿（开工许可）；Task 17 ★ 在切换前夕用 Task 0 SHA 的 worktree（旧代码——HEAD 的闸门脚本自 Task 2 起已读不了 HS 形态的 config）再跑一遍并重出 `gate-before-dump.json`，Task 21 ★ 对照的是**这一份**，中间十几个代码 Task 期间账号里的无关漂移不会被顺手合法化 | HS 层（`read-jwt-param` / `read-session-key:*` / 三条 Edge 产物 grant）整层消失、KMS 层整层新增，`--new-key` / `--retire-key` 的标签合法域（config ∪ 基线 kid）在切换后已不含 HS kid；为一次性切换补声明语义等于再造一套只服务验证环境的桥。spec §6.2 3c-3 那句"不是全部重置"被 §11.9 第 4/5 条取代，plan 里写明 | 逐项声明：要给 `--retire-key` 接受"两处都不认识的 kid"（削弱那条守卫）且要保留 HS grant 词表到删除之后 |
| D3 | 夹具签发器的签发范围 | **只签 `token_use=site-session`、只签夹具域、TTL ≤ 30 min，加一个 `role: current\|previous` 参数**（ADR 0002 原文 + 就位探针所需）。语义闸门里"site kid 签 console 用途 / console kid 签 site 用途"三条**改为静态证据**（单测 + `verify_deployed_edge.sh` 对产物按公钥 base64 精确对账），不再真机 mint | KMS 之后没有任何组件能带外签 console family；给签发器加"任意 token_use / 任意 family"就是 §11.7 明写否决的方案 ②（不受限的新冒充 principal）。`role=previous` 是就位期正向探针的唯一来源，仍限夹具域 + 站点会话，不扩大受众。**已接受的代价**：console family 就位期没有正向探针（签发器不签 console family），第一次证明发生在 signer 切过去那一刻——可接受，因为 console family 的 verifier 只有 auth 与 panel（Edge 不持 console 公钥），切错的回滚是改一行 config 重部两个 Lambda，约 5 分钟、无 CloudFront 窗口；写进 KMS runbook ② | 扩成 probe 模式签任意 token_use：改 ADR 0002，签发器成为 console 会话的第二签发点 |
| D4 | panel 的 RS256 验签实现 | **panel 产物也交叉装 `cryptography`**（新增 `panel/requirements.txt`，只含 cryptography 闭包三包，hash 与 auth 清单同一份；`deploy_panel._build_zip` 照抄 `deploy_auth.build_zip` 的 pip 开关，`--python-version 3.13`）；`auth/tests/test_requirements_locked.py` 的 AST 守卫扩到 `deploy_panel.py` | panel 是升级码与面板会话的 verifier，必须本地验 RS256；ADR 0003 已否决手写 RSA；spec §2 早已点名"panel 至今没有 requirements.txt"是这次的改动面 | 每请求 `kms:Verify`：给公网组件多一条 KMS 权限、每个写请求多一次跨服务往返、吃 1,000 rps 账号级配额 |
| D5 | `scripts/ensure_session_keys.py` 去留 | **删除**（含 `deployer/tests/test_ensure_session_keys.py`、DEPLOY.md / CLAUDE.md 的那一步） | HS 行删掉后它只剩 login-flow 一把，而 `deploy_auth.py` 的 `ensure_secret` 本来就是它的兜底（ADR 0004）；两条只创建不覆盖的路径对同一把密钥是 YAGNI | 保留只建 login-flow：多一个部署步骤、多一份要维护的清单 |
| D6 | Edge 对夹具会话的放行范围 | **夹具站点（route owner 的域是 `e2e.invalid`）∪ 平台路由（`_is_platform_route`，即 console）**，其余一律 302 | ADR 0002 要求"升级码与面板会话走真实换取链路"，那条链路的入口 `console.{base}/api/session-callback` 与 console 首页都在 console 平台路由上（`require_auth=True`、owner=`platform`）——不放行平台路由，控制台链路无法走通；panel 对夹具身份照常（它只能动自己拥有的夹具站点）。ADR 0002 加一句注明。路由表实况（单账号只读）：平台路由里只有 console 一条 `require_auth=true`，auth / mcp 都是 false、走不到验签步，所以 `_is_platform_route` 与写死 console 行为等价——用既有谓词，不加常量 | 只放夹具站点：`verify_console_e2e` / `verify_api_key_e2e` 全部失效 |
| D7 | 硬切换顺序 | **verifier 先行：router（open → deploy → apply）→ panel → auth**；HS SSM 参数最后删 | 与不变量"切换 verifier 先行"一致；三处 verifier 都是 RS-only 后，signer 才切；旧 HS 参数保留到全部闸门绿之后，回滚 = 用 Task 0 SHA 的 worktree 重部三处（worktree 与 router 的 CDK venv 在 Task 17 ★ 预先建好并带 HS 形态的 config 副本；Task 18 ★ 改 config 之前再备份一份到 `.scratch/asset-v1/08/`——config.ini 是 gitignored，`git stash` 收不到它） | signer 先行：窗口同长，且与不变量方向相反 |
| D8 | 基线 schema | **6，无迁移通道**；`load_baseline` 对 ≠ 6 的文件 SystemExit 并指示删掉重生成 | 采用者首跑就是 6；验证环境按 D2 重生成 | 留 5 加 facts 键：`BUNDLE_SHAPE` 递归拒绝未知键，旧基线照样加载失败 |
| D9 | Edge 公钥的加载时机 | **`cryptography` import 与黄金三元组预热在模块顶层；allowlist 的 JSON 解析与 `load_der_public_key` 仍在首次使用时**（ticket 21 的惰性形态） | §11.1 的 143 ms 是"库初始化 + 首次验签"搬到 Init 阶段的结果，逐把公钥的 DER 解析不到 0.1 ms；保留惰性解析让注入坏掉时只有带 cookie 的私有请求 500，公开站点与 console 前端不受影响（ticket 21 的理由不变）。ADR 0003 Consequences 那句"handler 路径里没有 `load_pem_public_key`"改写为"预热在顶层、allowlist 首次使用时解析一次" | 全部搬到顶层：注入坏掉 = 整个分发 502 |
| D10 | `preflight_config_states.py` 去留 | **保留，改成 RS 的三个状态**（就位 / 切换 / 退役；删 ⑤ 清空 legacy 与 signer 切换） | 采用者轮转 KMS 密钥前同样需要"改完 config 先跑一遍单测看哪条会红" | 删除：那类假红（写死当前 kid 的用例）会在采用者轮转时重现 |
| D11 | E2E 会话 fixture 的作用域 | **改成 function 级**（每条用例取一枚新的夹具会话，TTL 30 min） | E2E 全程约 37 分钟，module 级的一枚 30 分钟 token 会在中途过期；签发一次只是一个 HTTPS 调用。配套：`Minter` **每次 mint 都重新 `assume_role`**（一枚 token 一次 STS 调用，E2E 全程十次左右，零时钟逻辑）——验收角色会话上限 3600 s 而 E2E 约 37 min，构造时只 assume 一次会贴着上限，过期症状是 Function URL 403、读起来像授权配错 | 保留 module 级 + 到期刷新：多一套时钟逻辑 |
| D12 | `docs/security/account-trust-boundary.md` 的数字标记表 | **本票只把标记表改成 KMS 口径并在 Task 21 ★ 后按本地基线回填数字**；`test_doc_counts_come_from_the_baseline` 改为"本地无基线即 skip" | 守卫按类别要求正文出现标记，删表会让守卫红；数字"是否随资产分发"归工单 12/13 | 现在就删数字：守卫要先改，且工单 12 会再改一次 |

## Global Constraints

- **主会话执行、SDD 串行。** 代码 Task 的收尾是"该包套件绿 → `scan_staged_secrets.sh` → commit"；★ Task 是 coordinator 手动步骤，plan 只写命令与硬停止点。不派 Orca worker（`.scratch/asset-v1/spec.md`「执行方式」）。commit 前缀 `feat(asset-v1/08):` / `refactor(asset-v1/08):` / `docs(asset-v1/08):`；`git commit` 不带 `--no-verify`；push 到 github 带 `--no-verify`、到 origin 不带。
- **七套件顺序跑、不并行**（CLAUDE.md「测试命令」，contract 有墙钟哨兵）。每个代码 Task 只跑它碰到的包；Task 16 与 Task 22 ★ 跑全部七套：

  ```bash
  set -euo pipefail
  cd "$(git rev-parse --show-toplevel)"
  (cd site-builder/contract && .venv/bin/pytest tests -q)
  (cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
  (cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
  (cd site-builder/deployer && .venv/bin/pytest tests -q)
  (cd site-builder/mcp && python3 -m pytest tests -q)
  (cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
  (cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
  ```

- **TDD**：每条守卫先写、先跑红、再实现、再跑绿；每组反例配正对照；能证明"守卫会红"的变形测试用 `git stash` 或临时副本，**不对含未提交修改的文件 `git checkout --`**（spec §11.8.13）。
- **删除清单以 spec §6.2「3c-1B 留给 3c-3 的精确清单」为准**，本 plan 在 Task 1–15 里逐项对应；删完之后 `legacy` / `HS256` / `jwt-secret` / `JWT_SECRET` / `SESSION_SIGNER` / `LEGACY_ENTRY` / `mint_session_jwt` / `verify_with_legacy` / `signer =` / `ensure_session_keys` / `migrate_sites_to_blue_green` 这些词只许出现在 spec / ADR / review / 历史 plan 里（Task 16 有一条 grep 守卫；ADR 在例外目录里，所以 ADR 0004 里把 `ensure_session_keys.py` 写成 login-flow secret 创建方的那句要在 Task 16 手工修订）。
- **字面量（spec §11.4 / §11.5 / §11.7）**：kid `site-rs-v1` / `console-rs-v1`；JOSE `alg` `RS256`；KMS `SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`、`MessageType=RAW`、`KeySpec=RSA_2048`、`KeyUsage=SIGN_VERIFY`；`token_use` / `aud` 三对不变；夹具域 `e2e.invalid`、`idp=fixture`、`auth_via=fixture-issuer`、夹具会话 TTL 上限 1800 s；验收角色名 `site-builder-verifier`（会话上限 3600 s）；常驻夹具站点 `site_id=e2e-probe`、owner `probe@e2e.invalid`。
- **跨部署单元的同一契约**（CLAUDE.md 不变量）：`session.py` 的验签核心与 Edge 内嵌那份**字节等价**（Task 10 有逐段比对守卫）；auth / panel / Edge 三处 allowlist 的形态由 `session_keys.env_json`（auth、panel）与 `stack.load_site_allowlist`（Edge）产出，字段名 `kid` / `alg` / `role` + `key_arn` / `spki_sha256`（Lambda）或 `spki_b64`（Edge）。
- **不写真实账号 / 域名 / ARN 进 tracked 文件**：测试用 `111111111111` / `example.test` / `arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-555555555555`；`spki_sha256` 用 64 个 `0` 或从测试密钥现算。测试里的 RSA 密钥**在 import 时生成**，不落 PEM 进仓库（`scan_staged_secrets.sh` 拦 `BEGIN ... PRIVATE KEY`）。
- **AWS 资源名与描述不用全角破折号**（`~/CLAUDE.md`）：KMS alias `alias/site-builder/session/<kid>`，description 只用连字符。
- **CLAUDE.md 有状态词守卫**（`test_status_free_docs_carry_no_environment_status`）：不写日期、SHA、"已部署 / 尚未 / 待做"。工单、NEXT.md、spec 状态行、merged review §9 允许写日期。
- **Lambda@Edge 约束**（spec §3.1）：无环境变量（配置仍走 `{{PLACEHOLDER}}` 字符串替换）、必须关联编号版本、x86_64 python3.11；产物从 1 个文件变成约 172 个（vendored 包 ≈ 15.8 MB 解压，远低于 50 MB）。**Edge 内存维持 128 MB**（§11.1 复测结论）。
- **router 栈有 stack policy**：每次 router 部署三步 `router_stack_policy.py open` → `cdk deploy` → `apply`，open 之后无论成败都要 apply（CLAUDE.md）。
- **硬切换窗口**（ADR 0005）：router 部署到 CloudFront Deployed 之间约 10–20 分钟内登录会循环；窗口内不跑任何 `verify_*`；窗口结束后操作者与所有用户重新登录一次。回滚路径写在 Task 19 ★。
- **不可逆步骤单列**：删三把 HS SSM 参数（Task 20 ★）只在全部闸门绿之后做，删前逐条读出参数名核对账号。
- 命令块里不写绝对主机路径；回仓库根用 `cd "$(git rev-parse --show-toplevel)"`；多命令块以 `set -euo pipefail` 开头；`verify_*` 与 `scripts/*.py` 一律用不带路径的 `python3`（≥ 3.10 + pip-system-certs，见 CLAUDE.md）。

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/auth/session.py` | RS256 JOSE 合同：严格 base64url、公钥 SPKI 四项检查、`mint_token(sign=…)`、`verify_token`、夹具常量、黄金三元组 | 重写（删 HS / legacy 全部函数） |
| `site-builder/auth/session_kms.py` | KMS 边界的唯一实现：`describe_public_key`、`fetch_verified_public_key_der`（部署前四项）、`precheck_keys`、`public_key_loader`（verifier 冷启动取公钥 + 指纹核对）、`KmsSigner`（RAW 签名 + `KeyId` 断言 + 冷启动自检） | 新建；进 `AUTH_PACKAGE_MODULES` 与 panel `COPY_FILES` |
| `site-builder/auth/session_keys.py` | `[SessionKeys]` RS-only schema；删 `signer` / `legacy_param` / HS 行；`kms_key_arns`；`key_refs`；SYNTH 占位 allowlist 的 RS 形态 | 重写局部 |
| `site-builder/auth/verifier_env.py` | `load_allowlist(…, get_public_key)`、`signing_ref(…, role)`；删 `signer_mode` / `legacy_secret` | 修改 |
| `site-builder/auth/login_handler.py` | `_signer(family, role)`（KmsSigner）、`/callback` 与 `/console-session` 切 RS、新增 `POST /fixture-session`；删 legacy 分支与 `_secret("JWT_SECRET")` | 修改 |
| `site-builder/auth/deploy_auth.py` | KMS IAM 两条语句、`FIXTURE_ISSUER` env、precheck 加 KMS 四项、`[Verification]` 加载 + `ensure_verifier_role`、Function URL policy 的 verifier 两条 | 修改 |
| `site-builder/auth/tests/*` | 见各 Task；删 `test_signer_switch_guard.py`、`test_session.py`、`test_upgrade_code.py` 的 HS 部分 | 修改 / 新建 / 删除 |
| `site-builder/deployer/functions/function_url_policy.py` | `expected_statements(edge_role_arn, *, extra_principals)`；verifier 的两个 Sid | 修改 |
| `site-builder/deployer/functions/permissions.py` | `FIXTURE_DOMAIN`、`is_fixture_email`；`write_permissions` / `add_admin` 拒夹具域越界 | 修改 |
| `site-builder/panel/requirements.txt` | cryptography 闭包三包（hash 与 auth 清单同一份） | 新建 |
| `site-builder/panel/console_session.py` | RS 验签 + KmsSigner 签发；删 `_secret*` / legacy / signer 开关 | 修改 |
| `site-builder/panel/deploy_panel.py` | pip 交叉装、KMS IAM、env、precheck KMS、admin 名单夹具域断言；`COPY_FILES` += `session_kms.py` | 修改 |
| `site-builder/panel/tests/upgrade_code_vectors.py` | 三个套件共用的测试密钥（import 期生成）、`FakeKms`、`spki_b64`；RS 向量 | 重写 |
| `router/infrastructure/lambda/origin_request.py` | RS256 验签（vendored cryptography）、`spki_b64` allowlist、黄金预热、夹具边界分支；删 `JWT_SECRET` / `LEGACY_ENTRY` / HMAC | 修改 |
| `router/infrastructure/lambda/edge_substitutions.py` | DEFAULTS 换 RS 形态（测试密钥的 SPKI） | 修改 |
| `router/infrastructure/lambda/requirements-edge.txt` | cp311 / manylinux2014_x86_64 的 hash 钉死闭包（自 `scripts/spike_edge_crypto_requirements.txt` 复制） | 新建 |
| `router/infrastructure/stack.py` | `load_site_allowlist(keys, kms=…)`（GetPublicKey + 四项）、`vendor_edge_dependencies`；删 `load_jwt_secret` / `{{JWT_SECRET}}` / `{{LEGACY_ENTRY}}` | 修改 |
| `router/infrastructure/lambda/test_*.py` | RS 向量、负例矩阵、夹具边界、字节等价、源码守卫 | 修改 |
| `site-builder/deployer/infra/app.py` | 两个 `kms.Key` + `CfnOutput` | 修改 |
| `site-builder/deployer/tests/test_infra_kms_keys.py` | 不依赖 CDK 的 AST 守卫（KeySpec / KeyUsage / 不轮转 / RETAIN / construct ID 带 kid） | 新建 |
| `site-builder/scripts/session_key_fingerprint.py` | 从 CfnOutput 的 key ARN 算 `spki_sha256`、打印可粘贴的 `[SessionKey:<kid>]` | 新建 |
| `site-builder/scripts/_session_mint.py` | 夹具签发器客户端（assume `site-builder-verifier` → `POST /fixture-session`；console 会话走真实换取链路）；`live_target` 改指常驻夹具站点 | 重写 |
| `site-builder/scripts/ensure_fixture_site.py` | 幂等创建常驻夹具站点 `e2e-probe` | 新建 |
| `site-builder/scripts/verify_session_token_semantics.py` / `verify_kid_entry_live.py` | 判据按 D3 收缩；夹具边界两条新判据 | 修改 |
| `site-builder/scripts/verify_console_e2e.py` / `verify_api_key_e2e.py` / `verify_analytics_e2e.py` / `deploy_fixture.py` | 身份改夹具域；console 会话走链路 | 修改 |
| `site-builder/deployer/tests/test_e2e_fixtures.py` | 会话 fixture 改 function 级夹具会话；删 `test_legacy_site_migrates_…` | 修改 |
| `site-builder/scripts/verify_account_trust_boundary.py` | KMS 层、schema 6、删 HS 与迁移通道、基线路径 gitignored | 修改 |
| `site-builder/scripts/session_verify_counts.py` | 词表删 `accepted_legacy`；`--drain-gate` 只剩 `previous` | 修改 |
| `site-builder/scripts/verify_deployed_components.py` / `verify_deployed_edge.sh` | 三方公钥对账、verifier 语句、Edge 产物公钥精确对账 | 修改 |
| `site-builder/scripts/probe_impersonation_surface.py` | KMS 目标改成配置里的两把 key；新标签 `sign:fixture-issuer` | 修改 |
| `site-builder/scripts/preflight_config_states.py` | RS 三状态 | 修改 |
| `site-builder/scripts/ensure_session_keys.py`、`site-builder/scripts/migrate_sites_to_blue_green.py` 及各自测试 | — | 删除 |
| `site-builder/config.ini.example` | `[SessionKeys]` RS-only + `[SessionKey:*-rs-v1]` + `[Verification]` | 修改 |
| `CLAUDE.md`、`CONTEXT.md`、`README.md`、`site-builder/DEPLOY.md`、`docs/security/account-trust-boundary.md`、`docs/adr/0002`、`docs/adr/0003`、`docs/adr/0005`、spec 状态行、merged review §9 | 文档 | 修改 |

**不改**：`deployer/functions/deploy_lambda_site.py` 的 blue/green 逻辑（只改 `UnmigratedSite` 的报文，不再指向已删脚本）；`key-proxy/`（它不验会话；`permissions.py` 副本重部由 Task 19 ★ Step 2 的 `deploy_key_proxy.py` 覆盖）；`mcp/`（同上，`deploy_agentcore.py` 完整 build——`permissions.py` 在镜像里）；`docs/security/3c-impersonation-surface.json`（不重跑探针，untrack 归工单 12）。

---

### Task 0 ★：切换前的对照——旧代码 + 旧基线的闸门必须绿（D2 的前置）

**Files:** 不改任何文件。产物：`.scratch/asset-v1/08/gate-before.txt`（gitignored）。

**Interfaces:** 无。它是 D2 那条"一次 `--update-baseline`"能被接受的前提证据。

- [ ] **Step 1: 确认工作树干净、在 master 最新提交上**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git status --porcelain | wc -l      # 期望 0
git log -1 --format=%H
mkdir -p .scratch/asset-v1/08 && chmod 700 .scratch/asset-v1/08
```

- [ ] **Step 2: 用现有代码跑一遍闸门（约 11 分钟，只读）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_account_trust_boundary.py --dump-observed .scratch/asset-v1/08/gate-before-dump.json 2>&1 | tee .scratch/asset-v1/08/gate-before.txt
python3 site-builder/scripts/verify_account_trust_boundary.py --from-dump .scratch/asset-v1/08/gate-before-dump.json 2>&1 | tee -a .scratch/asset-v1/08/gate-before.txt
```

Expected: 第二条 exit 0（"与基线一致"）。**红则停**：先按现有 runbook 处理漂移（那是与本票无关的账号变化），绿了再开工——否则 Task 21 ★ 的 `--update-baseline` 会把这份漂移一起合法化，正是 spec §6.2 反对"全量重置"的那个理由。这份 dump 是**开工许可**；Task 21 ★ 对照用的 before 快照由 Task 17 ★ Step 3b 在切换前夕重出（D2）。

- [ ] **Step 2b: M08 删脚本的前置——没有站点还挂在 `$LATEST` 上（只读）**

Task 15 删 `migrate_sites_to_blue_green.py` 之后就没有补救路径了，所以删之前要留痕证明"没有东西需要它"。判据与 `deploy_lambda_site` 的 `UnmigratedSite` 同源：站点 Lambda 不得有无 qualifier 的 Function URL（无 qualifier 的 ARN 恰好 6 个冒号，alias 形态是 7 个）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY' 2>&1 | tee -a .scratch/asset-v1/08/gate-before.txt
import configparser, sys
import boto3
cfg = configparser.ConfigParser(interpolation=None)
cfg.read("site-builder/config.ini")
if not cfg.sections():
    sys.exit("site-builder/config.ini 读空了——configparser 对缺失文件是静默的")
region = cfg.get("Platform", "region", fallback="us-east-1")
sites_table = cfg["Deployer"]["sites_table"]
ddb = boto3.client("dynamodb", region_name=region)
lam = boto3.client("lambda", region_name=region)
active = [i["site_id"]["S"] for page in ddb.get_paginator("scan").paginate(TableName=sites_table)
          for i in page["Items"] if i.get("status", {}).get("S") == "ACTIVE"]
still_on_latest = {}
for sid in active:
    fn = f"site-{sid}"
    try:
        cfgs = lam.list_function_url_configs(FunctionName=fn)["FunctionUrlConfigs"]
    except lam.exceptions.ResourceNotFoundException:
        continue                                   # static 站点没有后端 Lambda，不参与 blue/green
    unqualified = [c["FunctionUrl"] for c in cfgs if c["FunctionArn"].count(":") == 6]
    if unqualified:
        still_on_latest[fn] = unqualified
print(f"M08 前置：ACTIVE 站点 {len(active)} 个；仍挂 $LATEST Function URL 的：{still_on_latest or '无'}")
sys.exit(1 if still_on_latest else 0)
PY
```

Expected: exit 0，打印"无"。**非空则停**：先用还在的 `migrate_sites_to_blue_green.py --apply` 把这些站点迁完（DEPLOY.md「存量站点迁移到 blue/green」），再回到本步重跑。结论写进 progress，标 production。

- [ ] **Step 3: 把 SHA、时间、结论写进 progress**

在 `.superpowers/sdd/2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover/progress.md`（gitignored）记一行：`Task 0 | production | <SHA> | gate exit 0 | <UTC 时刻>`。

---

### Task 1：`session.py` 变成 RS256 合同 + 三个套件共用的测试密钥模块

**Files:**
- Modify: `site-builder/auth/session.py`（全文重写；删 `_sign` / `mint_session_jwt` / `verify_session_jwt` / `mint_upgrade_code` / `verify_upgrade_code` / `verify_with_legacy` / `_has_kid` / `SESSION_TYP` / `UPGRADE_TYP` / `accepted_legacy`）
- Modify: `site-builder/panel/tests/upgrade_code_vectors.py`（全文重写为 RS 测试密钥 + `FakeKms` + 向量）
- Modify: `site-builder/auth/tests/conftest.py`（`SITE_KID_SECRET` 等改为从 vectors 取；假 SSM 只剩 login-flow）
- Modify: `site-builder/auth/tests/test_verifier_allowlist.py`（RS 形态重写）
- Modify: `site-builder/auth/tests/test_upgrade_code.py`（只留跨侧向量，RS 形态）
- Delete: `site-builder/auth/tests/test_session.py`（全部是 HS `mint_session_jwt` 用例）
- Test: `site-builder/auth/tests/test_verifier_allowlist.py`、`test_upgrade_code.py`

**Interfaces:**
- Consumes: `cryptography`（contract venv 49.0.0 供测试；Lambda 锁 50.0.0，API 相同）。
- Produces（后续 Task 全部依赖这些名字）:
  - `session.ALG == "RS256"`、`TOKEN_USES`、`OUTCOMES`（8 项，无 `accepted_legacy`）、`NAME_MAX`、`SIGNING_INPUT_MAX`、`UPGRADE_MAX_TTL`、`RSA_MODULUS_BITS`、`RSA_PUBLIC_EXPONENT`
  - `session.FIXTURE_DOMAIN = "e2e.invalid"`、`FIXTURE_IDP = "fixture"`、`FIXTURE_AUTH_VIA = "fixture-issuer"`、`FIXTURE_MAX_TTL = 1800`
  - `session.spki_sha256(der: bytes) -> str`（64 位 hex）
  - `session.load_public_key_der(der: bytes) -> RSAPublicKey`（四项检查，抛 `ValueError`）
  - `session.local_signer(private_key) -> Callable[[bytes], bytes]`
  - `session.mint_token(*, kid, sign, token_use, email, ttl_seconds, name="", idp="", auth_via="", now=None) -> str`
  - `session.verify_token(token, *, allowlist, token_use, now=None) -> tuple[dict | None, str]`，allowlist 行形态 `{"alg": "RS256", "public_key": RSAPublicKey, "role": "current" | "previous"}`
  - `session.RS256_GOLDEN = {"spki_b64": str, "signing_input": str, "signature_b64": str}`（tracked 黄金三元组；Edge 预热与字节等价守卫用）
  - `upgrade_code_vectors`：`SITE_KID / SITE_PREV_KID / CONSOLE_KID`、`SITE_KEY / SITE_PREV_KEY / CONSOLE_KEY`（RSAPrivateKey，import 期生成）、`KEY_ARN[kid]`、`spki_der(key) / spki_b64(key) / spki_hex(key)`、`public_entry(key, role)`、`SITE_ALLOWLIST / CONSOLE_ALLOWLIST`、`session_keys_json(*(kid, role))`、`class FakeKms`、`MUTATIONS`、`RS_MUTATIONS`

- [ ] **Step 1: 重写测试密钥模块（三个套件共用，先写它，后面的红测试都要用）**

`site-builder/panel/tests/upgrade_code_vectors.py`：

```python
"""三个套件（auth / panel / router）共用的 RS256 测试密钥与契约向量（3c-final）。

为什么共用一份：panel 构建时**复制** session.py，Edge 内嵌一份字节等价的验签核心——两份副本
各自漂移是本项目已知的风险类型。同一组密钥、同一组变形向量在三侧都跑，漂移当场暴露。

密钥在 **import 期生成**（三把 RSA-2048 约 0.2 s），**不落 PEM 进仓库**：`scan_staged_secrets.sh`
拦 `BEGIN … PRIVATE KEY`，而测试也不需要跨进程稳定的密钥——只需要同一进程里三侧看到同一把。
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SITE_KID, SITE_PREV_KID, CONSOLE_KID = "site-rs-v1", "site-rs-v0", "console-rs-v1"
SITE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SITE_PREV_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CONSOLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# 与生产同形的假 ARN（账号 111111111111，仓库红线）；kid → key ARN 一一对应
KEY_ARN = {SITE_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000001",
           SITE_PREV_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000000",
           CONSOLE_KID: "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000002"}
PRIVATE = {SITE_KID: SITE_KEY, SITE_PREV_KID: SITE_PREV_KEY, CONSOLE_KID: CONSOLE_KEY}
SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"


def spki_der(private_key) -> bytes:
    return private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_b64(private_key) -> str:
    return base64.b64encode(spki_der(private_key)).decode()


def spki_hex(private_key) -> str:
    return hashlib.sha256(spki_der(private_key)).hexdigest()


def public_entry(private_key, role: str) -> dict:
    """verifier allowlist 的一行（session.verify_token 消费的形态）。"""
    return {"alg": "RS256", "public_key": private_key.public_key(), "role": role}


def signer(private_key):
    return lambda data: private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


SITE_ALLOWLIST = {SITE_KID: public_entry(SITE_KEY, "current")}
CONSOLE_ALLOWLIST = {CONSOLE_KID: public_entry(CONSOLE_KEY, "current")}


def session_keys_json(*rows: tuple[str, str]) -> str:
    """`SESSION_KEYS_JSON` 的形态（与 session_keys.env_json 一致）：rows 是 (kid, role)。"""
    out: dict = {}
    for kid, role in rows:
        fam = kid.split("-")[0]
        out.setdefault(fam, []).append({"kid": kid, "alg": "RS256", "role": role,
                                        "key_arn": KEY_ARN[kid], "spki_sha256": spki_hex(PRIVATE[kid])})
    return json.dumps(out, separators=(",", ":"))


class FakeKms:
    """KMS 替身：DescribeKey / GetPublicKey / Sign 按本模块的私钥回答，并**记录每次调用**。

    `wrong_key_id_for`：让 Sign 的响应 KeyId 指向别的 ARN（测 signer 的 KeyId 断言）；
    `tamper_public_key_for`：让 GetPublicKey 返回另一把的 SPKI（测指纹自检）；
    `describe_overrides`：覆盖 KeyMetadata 字段（测部署前四项校验的每一项）。
    """

    def __init__(self, arns: dict | None = None):
        self.arns = dict(arns or {v: k for k, v in KEY_ARN.items()})   # arn -> kid
        self.calls: list = []
        self.wrong_key_id_for: dict = {}
        self.tamper_public_key_for: dict = {}
        self.describe_overrides: dict = {}

    def _key(self, arn: str):
        if arn not in self.arns:
            raise RuntimeError(f"FakeKms: 未知 KeyId {arn!r}（测试意外碰了配置外的 key）")
        return PRIVATE[self.arns[arn]]

    def describe_key(self, KeyId):
        self.calls.append(("describe_key", KeyId))
        self._key(KeyId)
        meta = {"Arn": KeyId, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled",
                "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384",
                                      "RSASSA_PSS_SHA_256"]}
        meta.update(self.describe_overrides.get(KeyId, {}))
        return {"KeyMetadata": meta}

    def get_public_key(self, KeyId):
        self.calls.append(("get_public_key", KeyId))
        key = self._key(KeyId)
        der = spki_der(self.tamper_public_key_for.get(KeyId, key))
        return {"KeyId": KeyId, "PublicKey": der, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append(("sign", KeyId, MessageType, SigningAlgorithm, len(Message)))
        assert MessageType == "RAW" and SigningAlgorithm == SIGNING_ALGORITHM, "合同（spec §11.5）"
        sig = self._key(KeyId).sign(Message, padding.PKCS1v15(), hashes.SHA256())
        return {"KeyId": self.wrong_key_id_for.get(KeyId, KeyId), "Signature": sig,
                "SigningAlgorithm": SigningAlgorithm}


# ---- 变形向量：auth 侧签、panel 侧验，两个包各跑一遍 -------------------------------------

def _tamper_payload(code: str) -> str:
    h, _, rest = code.partition(".")
    _, _, sig = rest.partition(".")
    return f"{h}.eyJhIjoxfQ.{sig}"


def _drop_sig(code: str) -> str:
    h, p, _ = code.split(".")
    return f"{h}.{p}."


def _pad_sig(code: str) -> str:
    """签名段带上 `=` 填充：同一签名的第二种编码，规范 base64url 必须拒。"""
    h, p, s = code.split(".")
    return f"{h}.{p}.{s}{'=' * (-len(s) % 4) or '='}"


def _std_alphabet_sig(code: str) -> str:
    """签名段换成标准字母表（+ /）。这枚签名的 base64 里恰好没有 + / 时（概率约 2e-5）退化成带 = 填充的
    形态——两种都是"同一签名的第二种编码"，规范 base64url 都必须拒。"""
    h, p, s = code.split(".")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    std = base64.b64encode(raw).decode().rstrip("=")
    return f"{h}.{p}.{std}" if std != s else _pad_sig(code)


def _crit_header(code: str) -> str:
    """header 加 crit：RFC 7515 要求不认识的 critical 扩展必须拒，本平台不认任何一个。"""
    h, p, s = code.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    hdr["crit"] = ["exp"]
    h2 = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{h2}.{p}.{s}"


def _alg_none(code: str) -> str:
    h, p, s = code.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    hdr["alg"] = "none"
    h2 = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{h2}.{p}."


def _short_sig(code: str) -> str:
    """签名少一个字节：长度不等于模长必须拒，不许交给 RSA 层"补零"。"""
    h, p, s = code.split(".")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))[:-1]
    return f"{h}.{p}.{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}"


# (名字, 变换函数, 期望被拒)
MUTATIONS = [
    ("完好", lambda c: c, False),
    ("签名被截断", lambda c: c[:-4], True),
    ("签名整段删除", _drop_sig, True),
    ("篡改 payload 保留旧签名", _tamper_payload, True),
    ("整段替换成 login state 形态", lambda c: "abc.def.ghi", True),
    ("段数不足", lambda c: c.rsplit(".", 1)[0], True),
    ("空串", lambda c: "", True),
]
RS_MUTATIONS = MUTATIONS + [
    ("签名带 = 填充", _pad_sig, True),
    ("签名用标准字母表", _std_alphabet_sig, True),
    ("header 带 crit", _crit_header, True),
    ("alg=none", _alg_none, True),
    ("签名少一字节", _short_sig, True),
]
CONSOLE_SESSION_TTL = 4 * 3600


def console_session_token(mint_token, *, email="u@x.com", name="U", kid=CONSOLE_KID,
                          key=CONSOLE_KEY, **kw) -> str:
    """新形态面板会话 token。`mint_token` 由调用方传入**自己那份** session.py 的实现。"""
    return mint_token(kid=kid, sign=signer(key), token_use="console-session", email=email,
                      ttl_seconds=CONSOLE_SESSION_TTL, name=name, **kw)
```

保留原文件里 `console_session_token` 之后的全部辅助函数（若有），只把 HS 参数换成 `key=`。删掉 `SECRET` / `CONSOLE_KID_SECRET` / `SITE_KID_SECRET` 三个常量——它们的每个引用点在后面的 Task 里逐个改。

- [ ] **Step 2: 重写 `auth/tests/conftest.py`**

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "panel" / "tests"))   # upgrade_code_vectors（三套件共用）

import pytest

import upgrade_code_vectors as vectors  # noqa: E402

LOGIN_FLOW_SECRET = "login-flow-secret-v1"
LOGIN_FLOW_PARAM = "/site-builder/login-flow-secret"


@pytest.fixture(autouse=True)
def _fake_platform_clients(monkeypatch):
    """login_handler 的两个 AWS 边界都换成替身：SSM 只认 login-flow 那一把；KMS 按 vectors 的三把私钥
    回答 DescribeKey / GetPublicKey / Sign。任何别的参数名 / KeyId 都响亮失败。"""
    import login_handler as lh
    values = {LOGIN_FLOW_PARAM: LOGIN_FLOW_SECRET}

    class _SSM:
        @staticmethod
        def get_parameter(Name, WithDecryption=False):
            if Name in values:
                return {"Parameter": {"Value": values[Name]}}
            raise RuntimeError(f"测试里意外读了 SSM 参数 {Name}")

    kms = vectors.FakeKms()
    lh._secret_cache.clear()
    lh._reset_signers()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    monkeypatch.setattr(lh, "_kms", lambda: kms)
    yield kms
    lh._secret_cache.clear()
    lh._reset_signers()
```

`lh._reset_signers()` 与 `lh._kms()` 在 Task 5 才出现——在那之前 `import login_handler` 会因缺属性让 monkeypatch 抛 `AttributeError`。**这是预期的红**（conftest 先于实现），Task 5 之前 auth 套件里所有 import login_handler 的用例都红；Task 1 只跑下面点名的两个文件（它们不 import login_handler）。

- [ ] **Step 3: 写 RS 形态的 allowlist 用例（先红）**

`site-builder/auth/tests/test_verifier_allowlist.py` 全文替换：

```python
"""RS256 验签核心（spec §5 / §9 / §11.4；3c-final）。每条负例配一条正对照。"""
import base64
import json
import time

import pytest

import session
import upgrade_code_vectors as v

NOW = 1_800_000_000


def _mint(token_use="site-session", *, kid=v.SITE_KID, key=v.SITE_KEY, email="a@x.com", **kw):
    return session.mint_token(kid=kid, sign=v.signer(key), token_use=token_use, email=email,
                              ttl_seconds=600, name="A", idp="Feishu", auth_via="TokenGeneration_HostedAuth",
                              now=NOW, **kw)


def _verify(token, token_use="site-session", allowlist=None):
    return session.verify_token(token, allowlist=allowlist or v.SITE_ALLOWLIST, token_use=token_use, now=NOW + 1)


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def test_current_site_token_is_accepted_with_full_claims():
    claims, outcome = _verify(_mint())
    assert outcome == "accepted_current"
    assert set(claims) == {"token_use", "aud", "email", "name", "idp", "auth_via", "exp", "iat"}
    assert (claims["token_use"], claims["aud"]) == ("site-session", "site-edge")


def test_previous_key_is_accepted_and_labelled_previous():
    al = {**v.SITE_ALLOWLIST, v.SITE_PREV_KID: v.public_entry(v.SITE_PREV_KEY, "previous")}
    _, outcome = _verify(_mint(kid=v.SITE_PREV_KID, key=v.SITE_PREV_KEY), allowlist=al)
    assert outcome == "accepted_previous"


def test_console_family_positive_controls():
    code = _mint("console-upgrade", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)
    claims, outcome = _verify(code, "console-upgrade", v.CONSOLE_ALLOWLIST)
    assert outcome == "accepted_current" and set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"}
    cs = _mint("console-session", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)
    assert _verify(cs, "console-session", v.CONSOLE_ALLOWLIST)[1] == "accepted_current"


def test_header_is_exactly_alg_typ_kid_and_alg_is_rs256():
    hdr = _unb64(_mint().split(".")[0])
    assert hdr == {"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID}


def test_signature_is_exactly_the_modulus_length():
    sig = _mint().split(".")[2]
    assert len(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))) == 256


# ---- kid 解析（spec §9）----

def test_unknown_kid_is_rejected():
    tok = _mint(kid="site-rs-v9")
    assert _verify(tok) == (None, "unknown_kid")


def test_missing_kid_is_unknown_kid():
    h, p, s = _mint().split(".")
    hdr = _unb64(h); hdr.pop("kid")
    assert _verify(f"{_b64(hdr)}.{p}.{s}") == (None, "unknown_kid")


def test_duplicate_kid_keys_in_header_are_rejected():
    _, p, s = _mint().split(".")
    raw = '{"alg":"RS256","typ":"JWT","kid":"site-rs-v1","kid":"site-rs-v9"}'
    h = base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()
    assert _verify(f"{h}.{p}.{s}") == (None, "bad_signature")


@pytest.mark.parametrize("alg", ["HS256", "RS512", "PS256", "none", "None", "NONE", "ES256"])
def test_right_kid_wrong_alg_is_alg_mismatch(alg):
    h, p, s = _mint().split(".")
    hdr = _unb64(h); hdr["alg"] = alg
    assert _verify(f"{_b64(hdr)}.{p}.{s}") == (None, "alg_mismatch")


def test_site_kid_presented_to_console_allowlist_is_unknown():
    assert _verify(_mint(), "console-upgrade", v.CONSOLE_ALLOWLIST) == (None, "unknown_kid")


def test_console_kid_presented_to_site_allowlist_is_unknown():
    tok = _mint(kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)   # console kid 签的 **site-session**：只改 kid family
    assert _verify(tok) == (None, "unknown_kid")


def test_third_key_signing_under_a_known_kid_is_bad_signature():
    tok = _mint(kid=v.SITE_KID, key=v.SITE_PREV_KEY)     # header 声称 v1，签名是别的私钥
    assert _verify(tok) == (None, "bad_signature")


def test_crit_header_is_rejected_even_with_a_valid_signature():
    h, p, _ = _mint().split(".")
    hdr = _unb64(h); hdr["crit"] = ["exp"]
    h2 = _b64(hdr)
    sig = v.signer(v.SITE_KEY)(f"{h2}.{p}".encode())
    tok = f"{h2}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    assert _verify(tok) == (None, "bad_signature")


# ---- JOSE 层：规范 base64url 与签名长度（spec §5）----

@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_rs_mutation_vectors(name, mutate, expect_reject):
    claims, _ = _verify(mutate(_mint()))
    assert (claims is None) == expect_reject, name


def test_non_canonical_trailing_bits_in_signature_are_rejected():
    h, p, s = _mint().split(".")
    last = s[-1]
    # 同一段字节的另一种编码：把末字符换成"解码相同、编码不同"的字符（尾比特非零）。
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    idx = alphabet.index(last)
    alias = alphabet[idx ^ 1]      # 翻最低位：len%4==2 时末字符低 4 位是尾比特，==3 时低 2 位
    if len(s) % 4 == 0:
        pytest.skip("本次签名编码没有尾比特")
    tok = f"{h}.{p}.{s[:-1]}{alias}"
    assert tok != _mint() and _verify(tok) == (None, "bad_signature")


def test_signature_length_check_precedes_rsa_verify(monkeypatch):
    """钉住的是 **verify_token 不补零**：255 字节的签名必须原样交到 `_rsa_verify`（它再拒）。
    spy 在 `_rsa_verify` 的长度守卫**之前**就记下长度 ⇒ 本用例管不了那句守卫本身，
    守卫由下面那条直接用例钉（执行时修订，见 SDD ledger Ruling R4）。"""
    calls = []
    orig = session._rsa_verify

    def spy(pub, data, sig):
        calls.append(len(sig)); return orig(pub, data, sig)
    monkeypatch.setattr(session, "_rsa_verify", spy)
    _verify(v._short_sig(_mint()))
    assert calls == [255]


def test_rsa_verify_rejects_a_wrong_length_signature_without_calling_the_primitive():
    """长度不等于模长 ⇒ 直接 False，**不调** RSA 原语（spec §5：不许交给 RSA 层"补零"）。
    用一把假公钥：verify() 被调到就抛，所以本用例只在守卫存在时才能过。
    （执行时补，见 SDD ledger Ruling R4）"""
    class _Key:
        key_size = 2048
        def verify(self, *a, **kw):
            raise AssertionError("长度不符时不许调到 RSA 原语")
    for bad_len in (255, 257, 0):
        assert session._rsa_verify(_Key(), b"x", b"\x00" * bad_len) is False


# ---- 用途与受众 ----

@pytest.mark.parametrize("token_use,allowlist,wrong_use", [
    ("site-session", v.SITE_ALLOWLIST, "console-session"),
    ("site-session", v.SITE_ALLOWLIST, "console-upgrade"),
    ("console-upgrade", v.CONSOLE_ALLOWLIST, "console-session"),
    ("console-session", v.CONSOLE_ALLOWLIST, "console-upgrade"),
])
def test_token_use_matrix_off_diagonal_is_rejected(token_use, allowlist, wrong_use):
    kid, key = (v.SITE_KID, v.SITE_KEY) if token_use == "site-session" else (v.CONSOLE_KID, v.CONSOLE_KEY)
    tok = _mint(wrong_use, kid=kid, key=key)
    assert _verify(tok, token_use, allowlist) == (None, "wrong_token_use")


def test_aud_mismatch_is_rejected_even_with_right_token_use():
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["aud"] = "console-panel"
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_audience")


def test_aud_as_list_is_rejected():
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["aud"] = ["site-edge"]
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_audience")


def test_expired_is_rejected():
    assert session.verify_token(_mint(), allowlist=v.SITE_ALLOWLIST, token_use="site-session",
                                now=NOW + 601) == (None, "expired")


@pytest.mark.parametrize("email", ["", None, 5])
def test_missing_or_empty_email_is_rejected(email):
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["email"] = email
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "bad_signature")


def test_upgrade_code_without_jti_is_rejected():
    h, p, _ = _mint("console-upgrade", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY).split(".")
    claims = _unb64(p); claims.pop("jti")
    p2 = _b64(claims)
    sig = v.signer(v.CONSOLE_KEY)(f"{h}.{p2}".encode())
    tok = f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    assert _verify(tok, "console-upgrade", v.CONSOLE_ALLOWLIST) == (None, "bad_signature")


def test_typ_session_alone_does_not_pass_the_new_entry():
    """旧合同（typ=session、无 token_use/aud）用 site key 签出来：新入口必须拒。"""
    h = _b64({"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID})
    p = _b64({"typ": "session", "email": "a@x.com", "exp": NOW + 600})
    sig = v.signer(v.SITE_KEY)(f"{h}.{p}".encode())
    assert _verify(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_token_use")


@pytest.mark.parametrize("garbage", ["", ".", "..", "a.b", "a.b.c.d", "\x00.\x00.\x00", "ey.ey.ey"])
def test_garbage_never_raises_and_outcome_is_in_vocabulary(garbage):
    claims, outcome = _verify(garbage)
    assert claims is None and outcome in session.OUTCOMES


def test_outcome_vocabulary_is_exactly_spec_section_8_minus_legacy():
    assert session.OUTCOMES == ("accepted_current", "accepted_previous", "unknown_kid", "alg_mismatch",
                                "wrong_audience", "wrong_token_use", "bad_signature", "expired")


# ---- claim 集合（spec §11.4）----

def test_site_session_claims_are_exactly_the_spec_table():
    assert set(_unb64(_mint().split(".")[1])) == {"token_use", "aud", "email", "name", "idp", "auth_via", "exp", "iat"}


def test_upgrade_code_claims_are_exactly_the_spec_table_and_ttl_is_capped():
    tok = session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="console-upgrade",
                             email="a@x.com", ttl_seconds=999, now=NOW)
    claims = _unb64(tok.split(".")[1])
    assert set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"} and claims["exp"] - claims["iat"] == 60


def test_console_session_claims_are_exactly_the_spec_table():
    tok = v.console_session_token(session.mint_token)
    assert set(_unb64(tok.split(".")[1])) == {"token_use", "aud", "email", "name", "exp", "iat"}


def test_name_is_capped_at_256_chars():
    tok = session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="site-session",
                             email="a@x.com", ttl_seconds=60, name="x" * 300, now=NOW)
    assert len(_unb64(tok.split(".")[1])["name"]) == 256


def test_oversize_signing_input_is_refused_before_sign_is_called():
    called = []

    def sign(data):
        called.append(1); return b"\x00" * 256
    with pytest.raises(ValueError, match="4096"):
        session.mint_token(kid=v.SITE_KID, sign=sign, token_use="site-session", email="a" * 4000 + "@x.com",
                           ttl_seconds=60, now=NOW)
    assert not called, "超长 signing input 不许到 KMS"


def test_mint_token_rejects_unknown_token_use():
    with pytest.raises(KeyError):
        session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="session", email="a@x.com", ttl_seconds=1)


# ---- 公钥侧四项（spec §5）----

def test_load_public_key_der_accepts_the_test_keys():
    for key in (v.SITE_KEY, v.CONSOLE_KEY):
        pub = session.load_public_key_der(v.spki_der(key))
        assert pub.key_size == 2048


def test_load_public_key_der_rejects_non_rsa_and_bad_exponent_and_short_modulus():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa as _rsa
    ec_der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        v.serialization.Encoding.DER, v.serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match="rsaEncryption"):
        session.load_public_key_der(ec_der)
    with pytest.raises(ValueError, match="65537"):
        session.load_public_key_der(v.spki_der(_rsa.generate_private_key(public_exponent=3, key_size=2048)))
    with pytest.raises(ValueError, match="模长"):
        session.load_public_key_der(v.spki_der(_rsa.generate_private_key(public_exponent=65537, key_size=1024)))


def test_load_public_key_der_rejects_non_minimal_der():
    der = v.spki_der(v.SITE_KEY)
    with pytest.raises(ValueError):
        session.load_public_key_der(der + b"\x00")


def test_spki_sha256_is_64_hex_of_the_der():
    assert session.spki_sha256(v.spki_der(v.SITE_KEY)) == v.spki_hex(v.SITE_KEY)


# ---- 黄金三元组（Edge 预热与三处 verifier 共用）----

def test_golden_triple_verifies_and_is_canonical():
    g = session.RS256_GOLDEN
    pub = session.load_public_key_der(base64.b64decode(g["spki_b64"]))
    assert session._rsa_verify(pub, g["signing_input"].encode(), base64.b64decode(g["signature_b64"]))
    assert g["signing_input"].count(".") == 1     # 就是一个 JWS signing input（header.payload）


# ---- 夹具常量（ADR 0002）----

def test_fixture_constants_are_the_adr_literals():
    assert (session.FIXTURE_DOMAIN, session.FIXTURE_IDP, session.FIXTURE_AUTH_VIA, session.FIXTURE_MAX_TTL) == \
        ("e2e.invalid", "fixture", "fixture-issuer", 1800)


def test_fixture_domain_matches_the_permissions_copy():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deployer" / "functions"))
    import permissions
    assert permissions.FIXTURE_DOMAIN == session.FIXTURE_DOMAIN
```

`test_fixture_domain_matches_the_permissions_copy` 在 Task 9 之前红（`permissions.FIXTURE_DOMAIN` 不存在）——预期。

- [ ] **Step 4: 跑红**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_verifier_allowlist.py -q -x`
Expected: FAIL，第一条就是 `AttributeError: module 'session' has no attribute 'load_public_key_der'` 或 `TypeError: mint_token() got an unexpected keyword argument 'sign'`。

- [ ] **Step 5: 重写 `session.py`**

```python
"""平台 token 的 JOSE 合同（RS256，3c-final）。

**签发**由调用方注入 `sign(signing_input: bytes) -> bytes`（生产：`session_kms.KmsSigner`，
测试与夹具单测：`local_signer(private_key)`）；**验签**在本模块用 `cryptography` 本地完成。
Edge（router/infrastructure/lambda/origin_request.py）内嵌一份**字节等价**的验签核心
（`_b64url_decode_strict` / `_strict_json` / `load_public_key_der` / `_rsa_verify` / `verify_token` 的判定段），
改这里必须同步那边（CLAUDE.md 不变量；router 的 test_edge_kid_allowlist.py 逐段比对）。
panel 构建时复制本文件（deploy_panel.COPY_FILES）。

顺序按 spec §5：kid ∈ allowlist → alg 与绑定值精确一致 → 验签 → token_use → aud → exp → 身份字段。
**先验签再信 payload。** `kid` 是攻击者控制的输入：只拿它查表，不拼资源。

JOSE 层（spec §5，与用哪个 RSA 实现无关，一律必须）：base64url 规范形式（拒 `=`、拒标准字母表、
拒非规范尾比特）；拒 `crit` 头；`alg` 只与 allowlist 比对、不用来分派实现；签名长度**严格等于**模长；
公钥侧 SPKI 必须是 rsaEncryption、DER 最小形式、模长 ∈ {2048, 3072, 4096}、指数 65537。
RSA 原语层交给 cryptography（ADR 0003）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALG = "RS256"
TOKEN_USES = {"site-session": "site-edge",
              "console-upgrade": "console-exchange",
              "console-session": "console-panel"}
OUTCOMES = ("accepted_current", "accepted_previous",
            "unknown_kid", "alg_mismatch", "wrong_audience",
            "wrong_token_use", "bad_signature", "expired")
NAME_MAX = 256
SIGNING_INPUT_MAX = 4096      # spec §11.5：kms:Sign RAW 的 Message 上限；超过在调 sign 之前拒
UPGRADE_MAX_TTL = 60          # 升级码只在 302 跳转那一瞬间有效：上限，不是默认值
RSA_MODULUS_BITS = (2048, 3072, 4096)
RSA_PUBLIC_EXPONENT = 65537

# 夹具身份（spec §11.7 / ADR 0002）。**授权边界要进 git review，所以是常量不是配置。**
# Edge 内嵌同一组字面量（它拿不到本模块；router 单测钉住等值），panel 经 COPY_FILES 拿到本文件，
# deployer/functions/permissions.py 另有一份 FIXTURE_DOMAIN（auth 单测钉住等值）。
FIXTURE_DOMAIN = "e2e.invalid"
FIXTURE_IDP = "fixture"
FIXTURE_AUTH_VIA = "fixture-issuer"
FIXTURE_MAX_TTL = 1800

_PAD = padding.PKCS1v15()
_HASH = hashes.SHA256()
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode_strict(s: str) -> bytes:
    """规范 base64url：字母表只许 A-Za-z0-9-_（拒 `=` 填充与标准字母表的 + /），且重编码必须逐字符
    相等（拒非规范尾比特——同一串字节的第二种编码是"同一签名两种写法"的入口）。"""
    if not isinstance(s, str) or not _B64URL_RE.fullmatch(s):
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64url(raw) != s:
        raise ValueError("non-canonical base64url")
    return raw


def _strict_json(raw: bytes) -> dict:
    """拒绝重复键：Python 默认取最后一个，攻击者可放两个 kid 让不同实现看到不同值。"""
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d
    obj = json.loads(raw, object_pairs_hook=no_dupes)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def spki_sha256(der: bytes) -> str:
    """`[SessionKey:<kid>] spki_sha256` 的定义：SHA-256(DER SPKI) 的 64 位 hex。"""
    return hashlib.sha256(der).hexdigest()


def load_public_key_der(der: bytes):
    """DER SPKI → RSAPublicKey，公钥侧四项（spec §5）：rsaEncryption、指数 65537、模长 ∈ RSA_MODULUS_BITS、
    DER 最小形式（重新序列化逐字节相等）。任一不符抛 ValueError；调用方（部署脚本 / verifier 冷启动）
    把它当硬失败，不回落。"""
    key = serialization.load_der_public_key(der)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("SPKI 不是 rsaEncryption")
    if key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("RSA 公钥指数不是 65537")
    if key.key_size not in RSA_MODULUS_BITS:
        raise ValueError(f"RSA 模长 {key.key_size} 不在 {RSA_MODULUS_BITS}")
    canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if canonical != der:
        raise ValueError("SPKI DER 不是最小形式")
    return key


def _rsa_verify(public_key, signing_input: bytes, sig: bytes) -> bool:
    """签名长度必须**严格等于**模长（spec §5）——不许交给 RSA 层去"补零"；其余交给 PKCS1 v1.5 验签。"""
    if len(sig) != public_key.key_size // 8:
        return False
    try:
        public_key.verify(sig, signing_input, _PAD, _HASH)
        return True
    except InvalidSignature:
        return False


def local_signer(private_key):
    """测试 / 夹具单测用的 `sign`：本地私钥 PKCS1 v1.5 + SHA-256。生产 signer 是 session_kms.KmsSigner，
    两者对同一 signing input 产出**同一个**签名（PKCS1 v1.5 是确定性签名，spec §11.5）。"""
    return lambda signing_input: private_key.sign(signing_input, _PAD, _HASH)


def _aud_matches(got, want: str) -> bool:
    """字符串**精确相等**。数组形态的 aud 一律不匹配（RFC 7519 允许数组，本平台不允许）。"""
    return isinstance(got, str) and got == want


def mint_token(*, kid: str, sign, token_use: str, email: str,
               ttl_seconds: int, name: str = "", idp: str = "",
               auth_via: str = "", now: int | None = None) -> str:
    """claim 集合按 spec §11.4 的三类表；header 是 {alg, typ, kid}；不写 typ（payload）与 scope。

    `sign(signing_input: bytes) -> bytes` 返回**原始签名字节**（KMS `Sign` 响应的 `Signature`，或本地私钥），
    本函数负责 base64url。signing input 超过 4096 字节在调 `sign` **之前**拒（spec §11.5）。"""
    aud = TOKEN_USES[token_use]
    t = int(time.time()) if now is None else now
    claims = {"token_use": token_use, "aud": aud, "email": email,
              "exp": t + int(ttl_seconds), "iat": t}
    if token_use == "site-session":
        claims.update(name=name[:NAME_MAX], idp=idp, auth_via=auth_via)
    elif token_use == "console-upgrade":
        claims["jti"] = _b64url(secrets.token_bytes(16))
        claims["exp"] = t + min(int(ttl_seconds), UPGRADE_MAX_TTL)
    else:
        claims["name"] = name[:NAME_MAX]
    header = _b64url(json.dumps({"alg": ALG, "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    if len(signing_input) > SIGNING_INPUT_MAX:
        raise ValueError("signing input 超过 4096 字节，拒签")
    return f"{header}.{payload}.{_b64url(sign(signing_input))}"


def verify_token(token: str, *, allowlist: dict, token_use: str,
                 now: int | None = None) -> tuple[dict | None, str]:
    """→ (claims 或 None, outcome ∈ OUTCOMES)。任何异常都归为拒绝（fail-closed）。

    allowlist: kid -> {"alg": "RS256", "public_key": RSAPublicKey, "role": "current" | "previous"}。
    **下面从 `try` 到 `return claims` 这一段与 Edge 的 `_verify_site_session` 字节等价**（router 单测逐段比对）。"""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = _strict_json(_b64url_decode_strict(header_b64))
    except Exception:
        return None, "bad_signature"
    if "crit" in header:                      # RFC 7515 §4.1.11：本平台不认任何 critical 扩展
        return None, "bad_signature"
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in allowlist:
        return None, "unknown_kid"
    entry = allowlist[kid]
    if header.get("alg") != entry["alg"]:
        return None, "alg_mismatch"
    try:
        sig = _b64url_decode_strict(sig_b64)
        if not _rsa_verify(entry["public_key"], f"{header_b64}.{payload_b64}".encode(), sig):
            return None, "bad_signature"
        claims = _strict_json(_b64url_decode_strict(payload_b64))
    except Exception:
        return None, "bad_signature"
    if claims.get("token_use") != token_use:
        return None, "wrong_token_use"
    if not _aud_matches(claims.get("aud"), TOKEN_USES[token_use]):
        return None, "wrong_audience"
    t = int(time.time()) if now is None else now
    try:
        if int(claims.get("exp", 0)) <= t:
            return None, "expired"
    except Exception:
        return None, "bad_signature"
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        return None, "bad_signature"
    if token_use == "console-upgrade" and not claims.get("jti"):
        return None, "bad_signature"
    return claims, f"accepted_{entry['role']}"


# 黄金三元组（spec §11.5）：一次性本地私钥签出的 (SPKI, signing input, signature)。**公钥与签名都不是秘密。**
# 用途：① Edge 在 import 期用它做一次预热验签（spec §11.1 的冷启动判据建立在"库初始化 + 首次验签发生在
# Init 阶段"上）；② 三处 verifier 的单测用同一组字节证明 RSA 层一致。**不要用它签任何 token**：私钥已丢弃。
# 生成方式见 docs/superpowers/plans/2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover.md Task 1 Step 6。
RS256_GOLDEN = {
    "spki_b64": "<Task 1 Step 6 生成后粘贴>",
    "signing_input": "<Task 1 Step 6 生成后粘贴>",
    "signature_b64": "<Task 1 Step 6 生成后粘贴>",
}
```

- [ ] **Step 6: 生成黄金三元组并粘进 `RS256_GOLDEN`**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/auth"
../contract/.venv/bin/python - <<'PY'
import base64, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
spki = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT","kid":"golden-rs-v0"}').rstrip(b"=").decode()
pl = base64.urlsafe_b64encode(b'{"token_use":"site-session","aud":"site-edge","email":"golden@e2e.invalid","exp":0,"iat":0}').rstrip(b"=").decode()
si = f"{hdr}.{pl}"
sig = k.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
print(json.dumps({"spki_b64": base64.b64encode(spki).decode(), "signing_input": si,
                  "signature_b64": base64.b64encode(sig).decode()}, indent=4))
PY
```

把输出的三个值粘进 `session.py` 的 `RS256_GOLDEN`（私钥随进程丢弃；kid `golden-rs-v0` 不合 `KID_RE` 的 family 前缀，永不会进任何 allowlist）。

- [ ] **Step 7: 改 `test_upgrade_code.py`、删 `test_session.py`**

`site-builder/auth/tests/test_upgrade_code.py` 全文替换为只剩跨侧向量（HS 的 `verify_upgrade_code` / `expected_typ` 用例随函数一起删）：

```python
"""升级码与面板会话的跨侧向量（auth 这一侧）。同一组向量在 panel/tests/test_console_session.py 再跑一遍。"""
import pytest

import session
import upgrade_code_vectors as v


def _code(email="u@x.com"):
    return session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="console-upgrade",
                              email=email, ttl_seconds=60)


def test_payload_shape_is_the_declared_contract():
    claims, outcome = session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert outcome == "accepted_current" and set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"}


def test_each_code_has_a_distinct_jti():
    jtis = {session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")[0]["jti"]
            for _ in range(5)}
    assert len(jtis) == 5


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_mutation_vectors(name, mutate, expect_reject):
    claims, _ = session.verify_token(mutate(_code()), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert (claims is None) == expect_reject, name


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_console_session_cookie_vectors_match_the_panel_side(name, mutate, expect_reject):
    tok = v.console_session_token(session.mint_token)
    claims, _ = session.verify_token(mutate(tok), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session")
    assert (claims is None) == expect_reject, name


def test_upgrade_code_is_not_a_console_session_and_vice_versa():
    assert session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session") == (None, "wrong_token_use")
    tok = v.console_session_token(session.mint_token)
    assert session.verify_token(tok, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade") == (None, "wrong_token_use")


def test_console_session_token_is_rejected_when_verified_as_a_site_session():
    tok = v.console_session_token(session.mint_token)
    assert session.verify_token(tok, allowlist=v.SITE_ALLOWLIST, token_use="site-session") == (None, "unknown_kid")
```

```bash
git rm site-builder/auth/tests/test_session.py
```

- [ ] **Step 8: 跑绿（只跑这两个文件）**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_verifier_allowlist.py tests/test_upgrade_code.py -q`
Expected: 全绿，只有 `test_fixture_domain_matches_the_permissions_copy` 红（Task 9 修）。若 `test_non_canonical_trailing_bits_in_signature_are_rejected` 报 skip，多跑几次确认它有过一次非 skip 的通过（签名长度 256 字节 ⇒ 编码长 342、`len % 4 == 2`，不该 skip；skip 说明 `_short_sig` 之类改坏了长度）。

- [ ] **Step 9: 变形自证（守卫真的会红）**

三处变形，每处只改一行；用 `git stash` 还原，不用 `git checkout --`：

1. 把 `verify_token` 传给 `_rsa_verify` 的签名改成「补零到模长再验」（`sig = sig.rjust(public_key.key_size // 8, b"\x00")`）⇒ `test_signature_length_check_precedes_rsa_verify` 必红（`calls` 变成 `[256]`）。
2. 把 `_rsa_verify` 里的 `if len(sig) != public_key.key_size // 8: return False` 注掉 ⇒ `test_rsa_verify_rejects_a_wrong_length_signature_without_calling_the_primitive` 必红（假公钥的 `verify()` 被调到即抛）。
3. 把 `if "crit" in header` 注掉 ⇒ `test_crit_header_is_rejected_even_with_a_valid_signature` 必红。

**别把第 2 条的变形配给第 1 条的 meta-test**：注掉 `_rsa_verify` 的长度守卫红不了它——spy 在守卫之前就记下了长度，且 cryptography 自己也会拒 255 字节的签名。同理 `RS_MUTATIONS` 的「签名少一字节」在两种实现下都是拒，配不了任何一条。（执行时修订，见 SDD ledger Ruling R4）

- [ ] **Step 10: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/auth/session.py site-builder/panel/tests/upgrade_code_vectors.py site-builder/auth/tests/conftest.py \
        site-builder/auth/tests/test_verifier_allowlist.py site-builder/auth/tests/test_upgrade_code.py
git commit -m "feat(asset-v1/08): session.py 改 RS256 合同（严格 JOSE 层、注入式 sign、公钥四项检查）；三套件共用 RS 测试密钥；删 HS/legacy 函数"
```

（此刻 auth 套件其余文件是红的——Task 5 之前预期如此；不要为它们改 conftest。）

---

### Task 2：`session_keys.py` 只认 RS 行；删 `signer` / `legacy_param` / HS 语义

**Files:**
- Modify: `site-builder/auth/session_keys.py`
- Modify: `site-builder/auth/tests/test_session_keys.py`
- Test: `site-builder/auth/tests/test_session_keys.py`

**Interfaces:**
- Produces:
  - `KID_RE = re.compile(r"^(site|console)-rs-v(\d+)$")`；`FAMILIES = ("site", "console")`；`ALG = "RS256"`
  - `KeyRef(kid, family, alg, role, key_arn, spki_sha256)`（删 `ssm_param`）
  - `SessionKeys(families, login_flow_secret_param)`（删 `legacy_param` / `signer`）；`allowlist(family) -> tuple[KeyRef, ...]`
  - `load_session_keys(path) -> SessionKeys`
  - `env_json(keys, families) -> str`：行 `{"kid","alg","role","key_arn","spki_sha256"}`
  - `key_refs(keys, families) -> list[KeyRef]`（去重保序）
  - `kms_key_arns(keys, families) -> list[str]`（IAM 资源清单的唯一构造器）
  - `ssm_parameter_names(keys, families, *, login_flow=False, extra=()) -> list`（只剩 login-flow + extra；签名不变，deploy_auth 继续用）
  - `ssm_parameter_arns(...)`（同上）
  - `SYNTH_PLACEHOLDER_ALLOWLIST_JSON`（RS 形态：`spki_b64` 是 `SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY` 的 base64，kid 不合 `KID_RE`）
  - **删**：`SIGNER_MODES`、`HS_PARAM_PREFIX`、`ALGS`、`legacy_entry()`

- [ ] **Step 1: 重写 `test_session_keys.py`（先红）**

```python
"""`[SessionKeys]` 的加载与校验（RS-only，3c-final）。"""
import json
import textwrap

import pytest

import session_keys as sk
import upgrade_code_vectors as v

RS = textwrap.dedent(f"""
    [SessionKeys]
    site_current = site-rs-v1
    site_previous =
    console_current = console-rs-v1
    console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_KEY)}

    [SessionKey:console-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.CONSOLE_KID]}
    spki_sha256 = {v.spki_hex(v.CONSOLE_KEY)}
""")
RS_WITH_PREVIOUS = RS.replace("site_previous =", "site_previous = site-rs-v0") + textwrap.dedent(f"""
    [SessionKey:site-rs-v0]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_PREV_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_PREV_KEY)}
""")


def _load(tmp_path, text):
    p = tmp_path / "config.ini"
    p.write_text(text)
    return sk.load_session_keys(p)


def test_minimal_config_loads_two_families_with_no_previous(tmp_path):
    keys = _load(tmp_path, RS)
    assert [r.kid for r in keys.allowlist("site")] == ["site-rs-v1"]
    assert [r.kid for r in keys.allowlist("console")] == ["console-rs-v1"]
    ref = keys.allowlist("site")[0]
    assert (ref.alg, ref.role, ref.key_arn, ref.spki_sha256) == ("RS256", "current", v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert keys.login_flow_secret_param == "/site-builder/login-flow-secret"


def test_session_keys_has_no_signer_and_no_legacy_fields(tmp_path):
    keys = _load(tmp_path, RS)
    assert not hasattr(keys, "signer") and not hasattr(keys, "legacy_param")
    assert not hasattr(sk, "legacy_entry") and not hasattr(sk, "SIGNER_MODES") and not hasattr(sk, "HS_PARAM_PREFIX")


def test_previous_is_loaded_and_ordered_after_current(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    assert [(r.kid, r.role) for r in keys.allowlist("site")] == [("site-rs-v1", "current"), ("site-rs-v0", "previous")]


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace("site_current = site-rs-v1", "site_current = site-hs-v1"), "HS kid 不再合法"),
    (lambda t: t.replace("alg = RS256\nkey_arn = " + v.KEY_ARN[v.SITE_KID], "alg = HS256\nkey_arn = " + v.KEY_ARN[v.SITE_KID]), "alg 只许 RS256"),
    (lambda t: t.replace(v.KEY_ARN[v.SITE_KID], "alias/site-builder/session/site-rs-v1"), "alias 不接受"),
    (lambda t: t.replace(v.spki_hex(v.SITE_KEY), "abc"), "spki 必须 64 位 hex"),
    (lambda t: t.replace("[SessionKey:console-rs-v1]", "[SessionKey:console-rs-v2]"), "缺小节"),
    (lambda t: t.replace("site_current = site-rs-v1", "site_current ="), "缺 current"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param ="), "缺 login-flow"),
    (lambda t: t.replace("[SessionKeys]", "[SessionKeys]\nsigner = current"), "signer 键已删——出现即配置错"),
    (lambda t: t.replace("[SessionKeys]", "[SessionKeys]\nlegacy_param = /site-builder/jwt-secret"), "legacy_param 键已删——出现即配置错"),
    (lambda t: t.replace("[SessionKey:site-rs-v1]\nalg = RS256", "[SessionKey:site-rs-v1]\nalg = RS256\nssm_param = /x"), "RS 行不许带 ssm_param"),
])
def test_misconfiguration_raises_instead_of_falling_back(tmp_path, mutate, why):
    # 三处变形的写法在执行时修订过（SDD ledger：Task 2 Step 1 笔误）：`RS` 经过 textwrap.dedent，
    # 行首没有缩进 ⇒ 变形串里不能写 "\n    key_arn"（replace 会无操作，配置仍合法、raises 不触发）；
    # `signer` 必须插在 `[SessionKeys]` 之后而不是追加到文本末尾（末尾属于最后一个 [SessionKey:*] 小节，
    # `[SessionKeys]` 的 REMOVED_KEYS 检查看不到它）。
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, mutate(RS)), why


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace(v.KEY_ARN[v.CONSOLE_KID], v.KEY_ARN[v.SITE_KID]), "两个 kid 指向同一把 CMK"),
    (lambda t: t.replace(v.spki_hex(v.CONSOLE_KEY), v.spki_hex(v.SITE_KEY)), "两个 kid 同一个公钥指纹"),
])
def test_rs_key_material_must_be_unique_across_families(tmp_path, mutate, why):
    with pytest.raises(sk.SessionKeysError, match="同一"):
        _load(tmp_path, mutate(RS)), why


def test_inline_comments_are_stripped_not_folded_into_values(tmp_path):
    keys = _load(tmp_path, RS.replace("site_current = site-rs-v1", "site_current = site-rs-v1   # 当前"))
    assert keys.allowlist("site")[0].kid == "site-rs-v1"


def test_missing_file_is_an_error_not_an_empty_config(tmp_path):
    with pytest.raises(sk.SessionKeysError):
        sk.load_session_keys(tmp_path / "nope.ini")


def test_error_type_is_a_value_error_so_callers_cannot_swallow_it_as_config_missing():
    assert issubclass(sk.SessionKeysError, ValueError)


def test_example_config_in_repo_loads():
    from pathlib import Path
    keys = sk.load_session_keys(Path(__file__).resolve().parents[2] / "config.ini.example")
    assert {r.kid for f in sk.FAMILIES for r in keys.allowlist(f)} == {"site-rs-v1", "console-rs-v1"}


def test_env_json_carries_only_requested_families_and_no_values(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    console = json.loads(sk.env_json(keys, ("console",)))
    assert list(console) == ["console"]
    assert console["console"] == [{"kid": "console-rs-v1", "alg": "RS256", "role": "current",
                                   "key_arn": v.KEY_ARN[v.CONSOLE_KID], "spki_sha256": v.spki_hex(v.CONSOLE_KEY)}]
    both = json.loads(sk.env_json(keys, ("site", "console")))
    assert [r["kid"] for r in both["site"]] == ["site-rs-v1", "site-rs-v0"]
    with pytest.raises(sk.SessionKeysError):
        sk.env_json(keys, ("edge",))


def test_kms_key_arns_is_the_single_builder_for_iam_resources(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    assert sk.kms_key_arns(keys, ("site", "console")) == [v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.SITE_PREV_KID], v.KEY_ARN[v.CONSOLE_KID]]
    assert sk.kms_key_arns(keys, ("console",)) == [v.KEY_ARN[v.CONSOLE_KID]]
    assert [r.kid for r in sk.key_refs(keys, ("site",))] == ["site-rs-v1", "site-rs-v0"]


def test_ssm_parameter_names_is_login_flow_and_extras_only(tmp_path):
    keys = _load(tmp_path, RS)
    assert sk.ssm_parameter_names(keys, ("site", "console")) == []
    assert sk.ssm_parameter_names(keys, ("site", "console"), login_flow=True, extra=("/x",)) == \
        ["/site-builder/login-flow-secret", "/x"]
    assert sk.ssm_parameter_arns(keys, ("site",), region="us-east-1", account="1", login_flow=True) == \
        ["arn:aws:ssm:us-east-1:1:parameter/site-builder/login-flow-secret"]


def test_login_flow_secret_is_loaded_but_belongs_to_no_family(tmp_path):
    keys = _load(tmp_path, RS)
    assert "login-flow" not in sk.env_json(keys, ("site", "console"))
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, RS.replace("/site-builder/login-flow-secret", "relative/path"))


def test_synth_placeholder_allowlist_is_valid_json_but_can_never_match_a_kid():
    data = json.loads(sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON)
    (kid, entry), = data.items()
    assert not sk.KID_RE.match(kid) and "SYNTH-ONLY-PLACEHOLDER" in kid
    assert entry["alg"] == "RS256" and set(entry) == {"alg", "spki_b64", "role"}
    assert "\\" not in sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON and "'''" not in sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON
```

- [ ] **Step 2: 跑红**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_session_keys.py -q -x`
Expected: FAIL（`test_session_keys_has_no_signer_and_no_legacy_fields` 之前的第一条就红：`SessionKeysError: 缺 signer`，因为旧加载器要求 `signer`）。

- [ ] **Step 3: 重写 `session_keys.py`**

```python
"""`[SessionKeys]` 的唯一定义：加载 + 校验，**不读 SSM、不调 KMS**。

auth 拥有本文件；panel 打包时复制（deploy_panel.py 的 COPY_FILES）；router 栈 synth 时从 site-builder/auth
import；闸门与脚本同样只经它读 kid 清单。取公钥 / 签名是调用方的事（session_kms.py）：本模块只把 config
变成结构，并把每一种"配置写错了但程序照常跑"的形态变成响亮的 SessionKeysError（configparser 对缺失是
静默的，本仓库的既定做法是读不到就硬失败）。

schema 见 spec §11.6（3c-final 起只有 RS 行）：

    [SessionKeys]
    site_current = site-rs-v1        console_current = console-rs-v1
    site_previous =                  console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:<kid>]   alg = RS256 + key_arn（带 :key/ 的完整 ARN，永不写 alias）+ spki_sha256（64 位 hex）

kid 格式 `{family}-rs-v{n}`：family 前缀必须与所属 family 一致。verifier 把 kid 当不透明字符串查表，
**这里的解析只用于校验配置，不用于运行时分派**。

槽位语义（CONTEXT.md「Key family」）：`current` = 签发用的那把；`previous` = 另一把被接受的 key
——要么是排空中的旧 key，要么是就位中的新 key。新 key 一律经 previous 就位（DEPLOY.md「轮转会话密钥」）。

`login_flow_secret_param`（spec §11.3）是唯一的 SSM 参数：auth 私有的 HMAC 密钥，只签 OAuth state 与
`__Host-sb_pkce` cookie，**不属于任何 family、没有 kid、不签发也不验证会话**。它不进 `allowlist()`、
不进 `env_json()`，只在 `ssm_parameter_names(login_flow=True)` 时出现——那个开关只有 deploy_auth 打开，
panel 与 Edge 永不持有它。

**没有 `signer`、没有 `legacy_param`**（3c-final 删）：签发形态只有一种，legacy 入口不存在。这两个键若出现在
config 里就是配置错（多半是从旧环境抄来的），硬失败——让"以为还能切回 HS"的人在 synth / 部署前就知道。
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

KID_RE = re.compile(r"^(site|console)-rs-v(\d+)$")
ALG = "RS256"
FAMILIES = ("site", "console")
REMOVED_KEYS = ("signer", "legacy_param")     # 3c-final 删掉的键：出现即拒


class SessionKeysError(ValueError):
    """配置缺失或自相矛盾。调用方不得捕获后回落默认值。"""


@dataclass(frozen=True)
class KeyRef:
    kid: str
    family: str
    alg: str
    role: str                     # "current" | "previous"
    key_arn: str
    spki_sha256: str


@dataclass(frozen=True)
class SessionKeys:
    families: dict            # family -> {"current": KeyRef, "previous": KeyRef | None}
    login_flow_secret_param: str

    def allowlist(self, family: str) -> tuple[KeyRef, ...]:
        """该 family 的接受集合，current 在前。"""
        fam = self.families[family]
        return tuple(k for k in (fam["current"], fam["previous"]) if k is not None)


def _strip(v: str) -> str:
    # configparser 默认把行内注释并进值（CLAUDE.md 记过的坑），这里统一剥掉
    return v.split("#")[0].strip()


def _key_ref(cfg: configparser.ConfigParser, kid: str, family: str, role: str) -> KeyRef:
    m = KID_RE.match(kid)
    if not m or m.group(1) != family:
        raise SessionKeysError(f"[SessionKeys] {family}_{role}={kid!r} 不是本 family 的合法 kid（形态 {family}-rs-v<n>）")
    sect = f"SessionKey:{kid}"
    if not cfg.has_section(sect):
        raise SessionKeysError(f"缺 [{sect}] 小节")
    alg = _strip(cfg.get(sect, "alg", fallback=""))
    if alg != ALG:
        raise SessionKeysError(f"[{sect}] alg={alg!r}，3c-final 起只有 {ALG}")
    if cfg.has_option(sect, "ssm_param"):
        raise SessionKeysError(f"[{sect}] 带 ssm_param——RS 行没有 SSM 密钥；这是 HS 时代的键，删掉")
    key_arn = _strip(cfg.get(sect, "key_arn", fallback=""))
    spki = _strip(cfg.get(sect, "spki_sha256", fallback=""))
    if not re.fullmatch(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}", key_arn):
        raise SessionKeysError(
            f"[{sect}] key_arn 必须是带 :key/<uuid> 的完整 KMS key ARN（不接受 alias），当前 {key_arn!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", spki):
        raise SessionKeysError(f"[{sect}] spki_sha256 必须是 64 位小写 hex（scripts/session_key_fingerprint.py 算），当前 {spki!r}")
    return KeyRef(kid, family, alg, role, key_arn=key_arn, spki_sha256=spki)


def load_session_keys(config_path: Path) -> SessionKeys:
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        found = cfg.read(config_path)
    except configparser.Error as exc:            # 重复键 / 坏语法：同样是配置错，不许静默
        raise SessionKeysError(f"{config_path} 解析失败：{exc}") from exc
    if not found or not cfg.has_section("SessionKeys"):
        raise SessionKeysError(f"{config_path} 缺 [SessionKeys] 段（或文件不存在）")
    for removed in REMOVED_KEYS:
        if cfg.has_option("SessionKeys", removed):
            raise SessionKeysError(
                f"[SessionKeys] 含 {removed}——3c-final 起没有 HS/legacy 形态，这个键已删除；"
                "把它从 config.ini 去掉（参照 config.ini.example）")
    families: dict = {}
    seen: set[str] = set()
    for fam in FAMILIES:
        cur = _strip(cfg.get("SessionKeys", f"{fam}_current", fallback=""))
        prev = _strip(cfg.get("SessionKeys", f"{fam}_previous", fallback=""))
        if not cur:
            raise SessionKeysError(f"[SessionKeys] 缺 {fam}_current")
        if prev == cur:
            raise SessionKeysError(f"[SessionKeys] {fam}_previous 与 current 相同")
        refs = {"current": _key_ref(cfg, cur, fam, "current"),
                "previous": _key_ref(cfg, prev, fam, "previous") if prev else None}
        for r in refs.values():
            if r is not None:
                if r.kid in seen:
                    raise SessionKeysError(f"kid {r.kid} 出现在两个 family")
                seen.add(r.kid)
        families[fam] = refs
    login_flow = _strip(cfg.get("SessionKeys", "login_flow_secret_param", fallback=""))
    if not login_flow:
        raise SessionKeysError(
            "[SessionKeys] 缺 login_flow_secret_param（spec §11.3 的字面路径是 /site-builder/login-flow-secret）")
    if not login_flow.startswith("/"):
        raise SessionKeysError(f"[SessionKeys] login_flow_secret_param={login_flow!r} 不是绝对 SSM 路径")
    # **任何两把 key material 都不许指向同一处**：同一把 CMK 或同一个公钥指纹出现两次就不是两把 key，
    # family 隔离与轮转都会失效。
    rows = [r for fam in families.values() for r in fam.values() if r is not None]
    for attr, what in (("key_arn", "KMS key"), ("spki_sha256", "公钥指纹")):
        vals = [getattr(r, attr) for r in rows]
        if len(vals) != len(set(vals)):
            raise SessionKeysError(f"[SessionKeys] 两个 kid 指向同一个 {what}（{sorted(vals)}）——那不是两把 key")
    return SessionKeys(families=families, login_flow_secret_param=login_flow)


def key_refs(keys: SessionKeys, families: tuple) -> list:
    """调用方要的 family 的全部 KeyRef（current 在前，去重保序）。deploy 脚本的部署前四项校验按它逐把做。"""
    out: list = []
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
        out += list(keys.allowlist(fam))
    return list(dict.fromkeys(out))


def kms_key_arns(keys: SessionKeys, families: tuple) -> list:
    """某个执行角色要 `kms:Sign` / `kms:GetPublicKey` 的 key ARN **精确清单**（auth 两个 family、panel 只 console）。
    deploy_auth / deploy_panel 共用，不各拼一份。"""
    return [r.key_arn for r in key_refs(keys, families)]


def env_json(keys: SessionKeys, families: tuple) -> str:
    """给 Lambda 下发的 SESSION_KEYS_JSON：kid / alg / role / key_arn / spki_sha256，**没有任何密钥材料**
    （公钥运行时按 key_arn 取，再与 spki_sha256 核对——verifier_env.load_allowlist）。只含调用方要的 family
    （auth 两个都要，panel 只要 console；Edge 不用它，Edge 由 stack.py 直接注入公钥）。"""
    import json
    out = {}
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
        out[fam] = [{"kid": r.kid, "alg": r.alg, "role": r.role, "key_arn": r.key_arn,
                     "spki_sha256": r.spki_sha256} for r in keys.allowlist(fam)]
    return json.dumps(out, separators=(",", ":"))


def ssm_parameter_names(keys: SessionKeys, families: tuple, *, login_flow: bool = False,
                        extra: tuple = ()) -> list:
    """某个执行角色要读的 SSM 参数**名**（login-flow（仅 auth）→ extra；去重保序）。

    3c-final 起会话密钥不在 SSM 里，所以 `families` 对结果没有影响——参数保留是为了让两个部署脚本的
    调用点不用改形，也让"某天有人给 family 加回 SSM 行"在这里被一眼看见。`login_flow=True` **只有
    deploy_auth 传**：那把密钥是 auth 私有的（spec §11.3），panel 与 Edge 永不持有它。"""
    for fam in families:
        if fam not in FAMILIES:
            raise SessionKeysError(f"未知 family {fam!r}")
    params = [keys.login_flow_secret_param] if login_flow else []
    params += list(extra)
    return list(dict.fromkeys(p for p in params if p))


def ssm_parameter_arns(keys: SessionKeys, families: tuple, *, region: str, account: str,
                       login_flow: bool = False, extra: tuple = ()) -> list:
    return [f"arn:aws:ssm:{region}:{account}:parameter{p}"
            for p in ssm_parameter_names(keys, families, login_flow=login_flow, extra=extra)]


# stack.py 在 KMS 读不到且显式 APP_SYNTH_OFFLINE=1 时注入它：**合法 JSON**、带 SYNTH-ONLY 标记
# （verify_deployed_edge.sh 的"无 SYNTH-ONLY-PLACEHOLDER"那条会抓）、kid 不合 KID_RE（永不匹配任何 token）、
# spki_b64 是标记串的 base64（解不出合法 SPKI ⇒ Edge 首次用到时响亮失败，而不是静默放行）。
SYNTH_PLACEHOLDER_ALLOWLIST_JSON = (
    '{"SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY": {"alg": "RS256", '
    '"spki_b64": "U1lOVEgtT05MWS1QTEFDRUhPTERFUi1ETy1OT1QtREVQTE9Z", "role": "current"}}')
```

- [ ] **Step 4: 同步 `config.ini.example` 的 `[SessionKeys]`**（`test_example_config_in_repo_loads` 读它；完整文案在 Task 16，这里先把机器可读部分改对）

把 `site-builder/config.ini.example` 从 `# 会话签名密钥（3c，spec §11.6）` 那段注释起到文件末尾整段替换为：

```ini
# ============================================================================
# 会话签名密钥（spec §11.6）。只有 KMS 非对称 CMK（RS256）一种形态。
# ============================================================================
[SessionKeys]
# 两把 CMK 由 deployer CDK 栈创建（默认 key policy，docs/adr/0001-*.md）。部署顺序见 DEPLOY.md：
# 先部 deployer 栈拿到两个 CfnOutput 的 key ARN，再用 scripts/session_key_fingerprint.py 算出
# 每把的 spki_sha256，回填下面两个 [SessionKey:*] 小节，然后才部 router / auth / panel。
# key_arn 必须是带 :key/<uuid> 的完整 ARN（永不写 alias）；spki_sha256 是 SHA-256(DER SPKI) 的 64 位 hex。
# 槽位语义（术语真源是根 CONTEXT.md 的 Key family / 就位 两条；DEPLOY.md「轮转会话密钥」同源）：
#   *_current  = **签发**用的那把；
#   *_previous = 另一把**被接受**的 key——要么是排空中的旧 key，要么是就位中的新 key。
# 新 key 一律**经 previous 就位**，切换 = 两槽互换，排空（--drain-gate previous）后清空 previous
# 并删掉那一节。**不要就地换掉任何一把 key 的 ARN**：那会造成一段全员登录循环
# （auth/panel 5 分钟切换 vs Edge 重部 + 10–20 分钟全球复制）。
site_current = site-rs-v1
site_previous =
console_current = console-rs-v1
console_previous =
# 登录流程（OAuth state 与 __Host-sb_pkce cookie）的 HMAC 密钥，**auth 私有**，是唯一的 SSM SecureString。
# 不是 kid、不属于任何 family、不签发也不验证会话；panel 与 Edge 永不持有它。
# deploy_auth.py 不存在时自动创建（只创建、不覆盖）；轮转 = put-parameter --overwrite
# （auth 5 分钟缓存窗口内进行中的登录失败一次，无会话影响）。
login_flow_secret_param = /site-builder/login-flow-secret

[SessionKey:site-rs-v1]
alg = RS256
key_arn = arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000
spki_sha256 = 0000000000000000000000000000000000000000000000000000000000000000

[SessionKey:console-rs-v1]
alg = RS256
key_arn = arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001
spki_sha256 = 0000000000000000000000000000000000000000000000000000000000000001

# ── 验收（可选组件；spec §11.7 / docs/adr/0002-*.md）────────────────────────
# fixture_issuer = true 时 deploy_auth.py 会：建 IAM 角色 site-builder-verifier（信任下面列出的
# principal，会话上限 1 小时）、给 auth 的 Function URL 多两条只对该角色的语句、给 auth 下发
# FIXTURE_ISSUER=on 让 POST /fixture-session 生效。该接口**只**给夹具域 e2e.invalid 的邮箱签
# 站点会话（TTL ≤ 30 分钟，idp=fixture / auth_via=fixture-issuer），Edge 只在夹具站点与平台路由上
# 认这种会话，panel 拒绝把夹具域邮箱写进管理员名单或非夹具站点的权限字段。
# **不配置 = 路径 404、角色与语句都不存在**（与 [ApiKey] 同款"不存在"）。四个 verify_* 闸门、
# smoke_router 之外的真机验收与 E2E 都依赖它；不跑那些就不用开。
# verifier_trusted_principals：逗号分隔的精确 IAM ARN（user 或 role，不接受通配），即"谁能 assume
# site-builder-verifier"。留空且 fixture_issuer=true 是配置错。
[Verification]
fixture_issuer = false
verifier_trusted_principals =
```

（旧文件里 `[SessionKeys]` 之前的所有段落不动。）

- [ ] **Step 5: 跑绿**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_session_keys.py -q`
Expected: 全绿。

- [ ] **Step 6: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/auth/session_keys.py site-builder/auth/tests/test_session_keys.py site-builder/config.ini.example
git commit -m "feat(asset-v1/08): [SessionKeys] 只认 RS 行（key_arn + spki_sha256），删 signer/legacy_param/HS 语义；example 加 [Verification]"
```

---

### Task 3：`session_kms.py`——KMS 边界的唯一实现（部署前四项、公钥加载器、签名器）

**Files:**
- Create: `site-builder/auth/session_kms.py`
- Create: `site-builder/auth/tests/test_session_kms.py`
- Test: 同上

**Interfaces:**
- Consumes: `session.load_public_key_der`、`session.spki_sha256`、`session.SIGNING_INPUT_MAX`；`session_keys.KeyRef`。
- Produces:
  - `SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"`、`KEY_SPEC = "RSA_2048"`、`KEY_USAGE = "SIGN_VERIFY"`、`MESSAGE_TYPE = "RAW"`
  - `class KeyMaterialMismatch(RuntimeError)`
  - `describe_public_key(kms, key_arn) -> tuple[bytes, str]`：`(DER, spki_sha256)`，含 DescribeKey 三项 + `load_public_key_der`（**不**比对配置指纹——`session_key_fingerprint.py` 用它算出指纹）
  - `fetch_verified_public_key_der(kms, ref: KeyRef) -> bytes`：四项（KeySpec / KeyUsage / SigningAlgorithms 含 RSASSA_PKCS1_V1_5_SHA_256 / 指纹 == `ref.spki_sha256`），任一不符抛 `KeyMaterialMismatch`（**按 key 汇总全部不符项后再抛**，不是遇到第一项就抛——Step 1 的 `test_precheck_keys_lists_every_mismatch…` 要求如此；两个函数共用私有 `_verified`。执行时修订，见 SDD ledger Ruling R10/R11）
  - `precheck_keys(kms, refs) -> None`：逐把 `fetch_verified_public_key_der`，汇总所有不符项后 `SystemExit`（与 `secrets_util.precheck_parameters` 同形：任何写之前调）
  - `public_key_loader(kms)`：返回 `get_public_key(key_arn, spki_sha256) -> RSAPublicKey`，容器内按 ARN 缓存；指纹不符抛 `KeyMaterialMismatch`（verifier 冷启动 fail closed）
  - `class KmsSigner(kms, key_arn, spki_sha256)`：可调用 `(signing_input: bytes) -> bytes`；首次调用先做一次 `GetPublicKey` 指纹自检；每次 `Sign` 断言响应 `KeyId == key_arn`；`MessageType=RAW`、`SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`；超过 `SIGNING_INPUT_MAX` 拒

- [ ] **Step 1: 写测试（先红）**

```python
"""`session_kms.py`：部署前四项、verifier 公钥加载、KMS 签名器（spec §11.2 / §11.5 / §11.6）。"""
import pytest

import session
import session_kms as sm
import upgrade_code_vectors as v
from session_keys import KeyRef


def _ref(kid=v.SITE_KID, key=v.SITE_KEY, **kw):
    base = dict(kid=kid, family=kid.split("-")[0], alg="RS256", role="current",
                key_arn=v.KEY_ARN[kid], spki_sha256=v.spki_hex(key))
    base.update(kw)
    return KeyRef(**base)


def test_describe_public_key_returns_der_and_fingerprint_without_needing_a_configured_value():
    der, fp = sm.describe_public_key(v.FakeKms(), v.KEY_ARN[v.SITE_KID])
    assert der == v.spki_der(v.SITE_KEY) and fp == v.spki_hex(v.SITE_KEY)


def test_fetch_verified_public_key_der_passes_the_four_checks_for_a_matching_key():
    assert sm.fetch_verified_public_key_der(v.FakeKms(), _ref()) == v.spki_der(v.SITE_KEY)


@pytest.mark.parametrize("override,why", [
    ({"KeySpec": "RSA_4096"}, "KeySpec 不是 RSA_2048"),
    ({"KeyUsage": "ENCRYPT_DECRYPT"}, "KeyUsage 不是 SIGN_VERIFY"),
    ({"SigningAlgorithms": ["RSASSA_PSS_SHA_256"]}, "不含 RSASSA_PKCS1_V1_5_SHA_256"),
    ({"KeyState": "PendingDeletion"}, "key 不是 Enabled"),
])
def test_each_describe_key_check_fails_loudly(override, why):
    kms = v.FakeKms()
    kms.describe_overrides[v.KEY_ARN[v.SITE_KID]] = override
    with pytest.raises(sm.KeyMaterialMismatch):
        sm.fetch_verified_public_key_der(kms, _ref()), why


def test_fingerprint_mismatch_is_the_fourth_check():
    with pytest.raises(sm.KeyMaterialMismatch, match="spki_sha256"):
        sm.fetch_verified_public_key_der(v.FakeKms(), _ref(spki_sha256="0" * 64))


def test_tampered_public_key_is_caught_by_the_fingerprint_not_by_luck():
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    with pytest.raises(sm.KeyMaterialMismatch, match="spki_sha256"):
        sm.fetch_verified_public_key_der(kms, _ref())


def test_precheck_keys_lists_every_mismatch_and_exits_before_any_write(capsys):
    kms = v.FakeKms()
    kms.describe_overrides[v.KEY_ARN[v.CONSOLE_KID]] = {"KeyUsage": "ENCRYPT_DECRYPT"}
    with pytest.raises(SystemExit) as ei:
        sm.precheck_keys(kms, [_ref(), _ref(v.CONSOLE_KID, v.CONSOLE_KEY, spki_sha256="0" * 64)])
    msg = str(ei.value)
    assert "console-rs-v1" in msg and "KeyUsage" in msg and "spki_sha256" in msg and "site-rs-v1" not in msg


def test_precheck_keys_is_silent_and_read_only_when_everything_matches():
    kms = v.FakeKms()
    sm.precheck_keys(kms, [_ref(), _ref(v.CONSOLE_KID, v.CONSOLE_KEY)])
    assert {c[0] for c in kms.calls} == {"describe_key", "get_public_key"}


def test_public_key_loader_caches_per_arn_and_checks_the_fingerprint():
    kms = v.FakeKms()
    get = sm.public_key_loader(kms)
    pub = get(v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert pub.public_numbers() == v.SITE_KEY.public_key().public_numbers()
    get(v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert [c for c in kms.calls if c[0] == "get_public_key"] == [("get_public_key", v.KEY_ARN[v.SITE_KID])]
    with pytest.raises(sm.KeyMaterialMismatch):
        get(v.KEY_ARN[v.CONSOLE_KID], "f" * 64)


def test_signer_signs_raw_with_the_contract_algorithm_and_the_signature_verifies():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    tok = session.mint_token(kid=v.SITE_KID, sign=signer, token_use="site-session", email="a@x.com", ttl_seconds=60)
    assert session.verify_token(tok, allowlist=v.SITE_ALLOWLIST, token_use="site-session")[1] == "accepted_current"
    sign_calls = [c for c in kms.calls if c[0] == "sign"]
    assert sign_calls and sign_calls[0][2:4] == ("RAW", "RSASSA_PKCS1_V1_5_SHA_256")


def test_signer_self_checks_the_public_key_once_at_first_use_then_only_signs():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    signer(b"a.b"); signer(b"a.c")
    assert [c[0] for c in kms.calls] == ["get_public_key", "sign", "sign"]


def test_signer_refuses_to_sign_when_the_self_check_fails():
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(sm.KeyMaterialMismatch):
        signer(b"a.b")
    assert not [c for c in kms.calls if c[0] == "sign"], "自检失败后不许再调 Sign"


def test_signer_asserts_the_response_key_id_equals_the_configured_arn():
    kms = v.FakeKms()
    kms.wrong_key_id_for[v.KEY_ARN[v.SITE_KID]] = v.KEY_ARN[v.CONSOLE_KID]
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(sm.KeyMaterialMismatch, match="KeyId"):
        signer(b"a.b")


def test_signer_refuses_oversize_input_before_calling_kms():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(ValueError, match="4096"):
        signer(b"x" * 4097)
    assert not [c for c in kms.calls if c[0] == "sign"]


def test_kms_signature_equals_a_local_pkcs1_signature_for_the_same_input():
    """spec §11.5：PKCS1 v1.5 是确定性签名，RAW 与本地实现对同一 signing input 产出同一签名——
    这条让本地私钥能替代 KMS 做单测与跨组件向量。"""
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert signer(b"h.p") == session.local_signer(v.SITE_KEY)(b"h.p")


def test_module_imports_no_boto3_at_import_time():
    import ast
    from pathlib import Path
    tree = ast.parse((Path(sm.__file__)).read_text(encoding="utf-8"))
    top_imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {a.name for n in top_imports if isinstance(n, ast.Import) for a in n.names} | \
            {n.module for n in top_imports if isinstance(n, ast.ImportFrom)}
    assert "boto3" not in names, "client 由调用方传入（与 function_url_policy.py 同一纪律）"
```

- [ ] **Step 2: 跑红**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_session_kms.py -q -x`
Expected: `ModuleNotFoundError: No module named 'session_kms'`。

- [ ] **Step 3: 实现 `session_kms.py`**

```python
"""KMS 边界的**唯一实现**（spec §11.2 / §11.5 / §11.6；3c-final）。

三个使用面、一份代码：
- **部署前**（spec §11.6 第 1 层）：`precheck_keys` 对每个 RS kid 做 DescribeKey + GetPublicKey 四项校验
  （KeySpec=RSA_2048、KeyUsage=SIGN_VERIFY、SigningAlgorithms 含 RSASSA_PKCS1_V1_5_SHA_256、
  SHA-256(SPKI) == 配置的 spki_sha256），任一不符**拒绝部署**。deploy_auth / deploy_panel / router 栈都调它。
- **verifier 冷启动**：`public_key_loader` 按 key_arn 取公钥、与 spki_sha256 核对后才装进 allowlist
  （fail closed；`verifier_env.load_allowlist` 的 get_public_key 参数）。
- **signer**（spec §11.6 第 2 层）：`KmsSigner` 首次调用做一次 GetPublicKey 指纹自检，每次 Sign 断言
  响应 KeyId == 配置的 key_arn；`MessageType=RAW`，任何地方不做本地哈希（spec §11.5）。

本模块**不 import boto3、不读配置、不读环境变量**：client 由调用方传入（deploy 脚本、login_handler、
console_session、stack.py 各自缓存自己的），与 function_url_policy.py 同一纪律。
auth 拥有本文件；panel 打包时复制（deploy_panel.COPY_FILES）；login_handler import 它 ⇒ 它在
`deploy_auth.AUTH_PACKAGE_MODULES` 里（test_deploy_auth_package.py 按 import 闭包核对）。
"""
from __future__ import annotations

import base64

import session

SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
KEY_SPEC = "RSA_2048"
KEY_USAGE = "SIGN_VERIFY"
MESSAGE_TYPE = "RAW"


class KeyMaterialMismatch(RuntimeError):
    """KMS 里的 key 与配置声明的不是同一把、或不是合同要求的形态。调用方不得捕获后继续。"""


def _describe_checks(meta: dict, key_arn: str) -> list:
    problems = []
    if meta.get("Arn") != key_arn:
        problems.append(f"DescribeKey 返回的 Arn {meta.get('Arn')!r} != 配置的 {key_arn!r}")
    if meta.get("KeySpec") != KEY_SPEC:
        problems.append(f"KeySpec={meta.get('KeySpec')!r}，要 {KEY_SPEC}")
    if meta.get("KeyUsage") != KEY_USAGE:
        problems.append(f"KeyUsage={meta.get('KeyUsage')!r}，要 {KEY_USAGE}")
    if SIGNING_ALGORITHM not in (meta.get("SigningAlgorithms") or []):
        problems.append(f"SigningAlgorithms={meta.get('SigningAlgorithms')!r} 不含 {SIGNING_ALGORITHM}")
    if meta.get("KeyState") != "Enabled":
        problems.append(f"KeyState={meta.get('KeyState')!r}，要 Enabled")
    return problems


def _verified(kms, key_arn: str, label: str, expect_fp: str | None = None) -> tuple[bytes, str]:
    """四项校验的**唯一实现**（下面两个函数的共同体，spec §11.6 第 1 层）。**汇总**这把 key 的所有不符项后
    以 `label` 为前缀抛一个 `KeyMaterialMismatch`（precheck 直接把它 str 进汇总 ⇒ Step 1 的"列出每一项不符"
    成立）：

    1. `_describe_checks`：DescribeKey 形态五项；
    2. `GetPublicKey`——**必须包在 try 里**：真 KMS 对 pending-deletion / disabled 的 key 会拒 GetPublicKey
       （DisabledException / KMSInvalidStateException），那不是"KMS 不可达"而是"这把 key 不能用"，得归成
       `KeyMaterialMismatch`（否则 Task 11 的离线退化路径会把它误判成"读不到 KMS"）。只记类名与消息；
    3. `load_public_key_der`：公钥侧四项（ValueError → 一条 problem）；
    4. `expect_fp` 给定时比对指纹；不给 = `describe_public_key` 的算指纹用法，不与任何配置值比对。
    """
    problems = _describe_checks(kms.describe_key(KeyId=key_arn)["KeyMetadata"], key_arn)
    der = fp = None
    try:
        der = kms.get_public_key(KeyId=key_arn)["PublicKey"]
    except Exception as exc:  # noqa: BLE001  pending-deletion / disabled / AccessDenied 都会抛
        problems.append(f"GetPublicKey 失败：{type(exc).__name__}: {exc}")
    if der is not None:
        try:
            session.load_public_key_der(der)
        except ValueError as exc:
            problems.append(f"公钥 SPKI 不合合同（{exc}）")
        fp = session.spki_sha256(der)
        if expect_fp is not None and fp != expect_fp:
            problems.append(
                f"KMS 公钥的 spki_sha256={fp} != 配置的 {expect_fp}——"
                "config.ini 指的不是这把 key（或 key 被换过）")
    if problems:
        raise KeyMaterialMismatch(f"{label}: " + "；".join(problems))
    return der, fp


def describe_public_key(kms, key_arn: str) -> tuple[bytes, str]:
    """→ (DER SPKI, spki_sha256)。DescribeKey 形态检查 + 公钥侧四项（session.load_public_key_der），
    **不**与任何配置值比对——`scripts/session_key_fingerprint.py` 靠它算出要回填的指纹。"""
    return _verified(kms, key_arn, key_arn)


def fetch_verified_public_key_der(kms, ref) -> bytes:
    """spec §11.6 第 1 层：DescribeKey 形态 + 公钥侧四项 + 指纹等值。任一不符抛 `KeyMaterialMismatch`
    （以 `ref.kid` 标识，汇总全部不符项）。"""
    der, _ = _verified(kms, ref.key_arn, ref.kid, expect_fp=ref.spki_sha256)
    return der


def precheck_keys(kms, refs) -> None:
    """部署脚本在**第一次写之前**调：对每个 RS kid 做四项校验，汇总全部不符项后 SystemExit（与
    secrets_util.precheck_parameters 同形）。只读，不打印任何密钥材料（公钥不是秘密，但也不需要打）。"""
    problems = []
    for ref in refs:
        try:
            fetch_verified_public_key_der(kms, ref)
        except KeyMaterialMismatch as exc:
            problems.append(str(exc))
        except Exception as exc:  # noqa: BLE001  AccessDenied / NotFound 同样是"部署出去会 500"
            problems.append(f"{ref.kid}: {type(exc).__name__}: {exc}")
    if problems:
        raise SystemExit("部署前核对失败：这些会话签名 key 与 [SessionKeys] 声明不符，拒绝部署（任何写都未发生）：\n  "
                         + "\n  ".join(problems)
                         + "\n先部 deployer 栈拿到 key ARN，用 scripts/session_key_fingerprint.py 算指纹回填 config.ini。")


def public_key_loader(kms):
    """→ `get_public_key(key_arn, spki_sha256) -> RSAPublicKey`，容器内按 ARN 缓存。
    指纹不符抛 KeyMaterialMismatch：verifier 宁可 500 也不装一把来历不明的公钥进 allowlist。"""
    cache: dict = {}

    def get_public_key(key_arn: str, spki_sha256: str):
        hit = cache.get(key_arn)
        if hit is not None:
            return hit
        der = kms.get_public_key(KeyId=key_arn)["PublicKey"]
        fp = session.spki_sha256(der)
        if fp != spki_sha256:
            raise KeyMaterialMismatch(f"{key_arn}: 公钥指纹 {fp} != 配置的 {spki_sha256}——拒绝装进 allowlist")
        pub = session.load_public_key_der(der)
        cache[key_arn] = pub
        return pub
    return get_public_key


class KmsSigner:
    """`session.mint_token(sign=…)` 的生产实现。首次调用先做一次 GetPublicKey 指纹自检（spec §11.6 第 2 层：
    不符则拒签，fail closed）；每次 Sign 断言响应 KeyId == key_arn；`MessageType=RAW`（spec §11.5）。"""

    def __init__(self, kms, key_arn: str, spki_sha256: str):
        self._kms = kms
        self.key_arn = key_arn
        self.spki_sha256 = spki_sha256
        self._checked = False

    def self_check(self) -> None:
        """一次 GetPublicKey + 指纹比对。login_handler 在烧掉一次性授权码之前调它（ticket 20 的同一理由）。"""
        if self._checked:
            return
        der = self._kms.get_public_key(KeyId=self.key_arn)["PublicKey"]
        fp = session.spki_sha256(der)
        if fp != self.spki_sha256:
            raise KeyMaterialMismatch(f"{self.key_arn}: 公钥指纹 {fp} != 配置的 {self.spki_sha256}——拒签")
        self._checked = True

    def __call__(self, signing_input: bytes) -> bytes:
        if len(signing_input) > session.SIGNING_INPUT_MAX:
            raise ValueError(f"signing input {len(signing_input)} 字节超过 {session.SIGNING_INPUT_MAX}，拒签")
        self.self_check()
        resp = self._kms.sign(KeyId=self.key_arn, Message=signing_input, MessageType=MESSAGE_TYPE,
                              SigningAlgorithm=SIGNING_ALGORITHM)
        if resp.get("KeyId") != self.key_arn:
            raise KeyMaterialMismatch(f"Sign 响应的 KeyId {resp.get('KeyId')!r} != 配置的 {self.key_arn!r}")
        return resp["Signature"]


def spki_b64(der: bytes) -> str:
    """Edge 注入用的形态（stack.py）：base64（标准字母表，无换行）。JSON 里没有反斜杠、没有换行。"""
    return base64.b64encode(der).decode()
```

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_session_kms.py -q`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/auth/session_kms.py site-builder/auth/tests/test_session_kms.py
git commit -m "feat(asset-v1/08): session_kms.py——部署前四项校验、verifier 公钥加载器、KmsSigner（RAW + KeyId 断言 + 冷启动自检）"
```

---

### Task 4：`verifier_env.py`——allowlist 按公钥装配，签发只给 (kid, key_arn, spki)

**Files:**
- Modify: `site-builder/auth/verifier_env.py`
- Modify: `site-builder/auth/tests/test_verifier_env.py`
- Test: 同上

**Interfaces:**
- Produces:
  - `_rows(env_json, family, allowed_families) -> list`（不变）
  - `load_allowlist(env_json, family, get_public_key, *, allowed_families) -> dict`：行 → `{"alg", "public_key": get_public_key(key_arn, spki_sha256), "role"}`
  - `signing_ref(env_json, family, *, allowed_families, role="current") -> tuple[str, str, str]`：`(kid, key_arn, spki_sha256)`；`role="previous"` 没有行时 `RuntimeError("… 没有 previous …")`
  - `log_verify(verifier, outcome)`（不变）
  - **删**：`signing_key`、`signer_mode`、`legacy_secret`

- [ ] **Step 1: 重写 `test_verifier_env.py`（先红）**

```python
"""auth 与 panel 共用的 verifier 运行时装配（RS-only）。"""
import json

import pytest

import upgrade_code_vectors as v
import verifier_env as ve

ENV = v.session_keys_json((v.SITE_KID, "current"), (v.SITE_PREV_KID, "previous"), (v.CONSOLE_KID, "current"))
CONSOLE_ONLY = v.session_keys_json((v.CONSOLE_KID, "current"))


def _get(kms=None):
    import session_kms
    return session_kms.public_key_loader(kms or v.FakeKms())


def test_load_allowlist_resolves_public_keys_by_arn_for_the_requested_family():
    al = ve.load_allowlist(ENV, "site", _get(), allowed_families=("site", "console"))
    assert set(al) == {v.SITE_KID, v.SITE_PREV_KID}
    assert al[v.SITE_KID]["alg"] == "RS256" and al[v.SITE_KID]["role"] == "current"
    assert al[v.SITE_KID]["public_key"].public_numbers() == v.SITE_KEY.public_key().public_numbers()
    assert al[v.SITE_PREV_KID]["role"] == "previous"


def test_load_allowlist_rejects_families_the_verifier_must_not_hold():
    with pytest.raises(RuntimeError, match="不该持有"):
        ve.load_allowlist(ENV, "console", _get(), allowed_families=("console",))


def test_load_allowlist_missing_or_invalid_env_raises_not_empty():
    with pytest.raises(RuntimeError):
        ve.load_allowlist(None, "site", _get(), allowed_families=("site",))
    with pytest.raises(RuntimeError):
        ve.load_allowlist("{not json", "site", _get(), allowed_families=("site",))
    with pytest.raises(RuntimeError, match="没有 site"):
        ve.load_allowlist(CONSOLE_ONLY, "site", _get(), allowed_families=("site", "console"))


def test_load_allowlist_fails_closed_when_a_public_key_does_not_match_its_fingerprint():
    import session_kms
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_PREV_KID]] = v.CONSOLE_KEY
    with pytest.raises(session_kms.KeyMaterialMismatch):
        ve.load_allowlist(ENV, "site", _get(kms), allowed_families=("site", "console"))


def test_signing_ref_returns_the_current_row_without_touching_kms():
    kms = v.FakeKms()
    assert ve.signing_ref(ENV, "site", allowed_families=("site", "console")) == \
        (v.SITE_KID, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert kms.calls == []


def test_signing_ref_previous_returns_the_previous_row_or_fails_loudly():
    assert ve.signing_ref(ENV, "site", allowed_families=("site", "console"), role="previous")[0] == v.SITE_PREV_KID
    with pytest.raises(RuntimeError, match="previous"):
        ve.signing_ref(ENV, "console", allowed_families=("site", "console"), role="previous")
    with pytest.raises(RuntimeError, match="role"):
        ve.signing_ref(ENV, "site", allowed_families=("site", "console"), role="legacy")


def test_signing_ref_rejects_families_the_component_must_not_sign_for():
    with pytest.raises(RuntimeError, match="不该持有"):
        ve.signing_ref(ENV, "site", allowed_families=("console",))


@pytest.mark.parametrize("rows,why", [
    ([], "0 个 current"),
    ([{"kid": v.SITE_KID, "alg": "RS256", "role": "current", "key_arn": v.KEY_ARN[v.SITE_KID], "spki_sha256": "0" * 64},
      {"kid": v.SITE_PREV_KID, "alg": "RS256", "role": "current", "key_arn": v.KEY_ARN[v.SITE_PREV_KID], "spki_sha256": "0" * 64}], "2 个 current"),
])
def test_signing_ref_requires_exactly_one_current(rows, why):
    with pytest.raises(RuntimeError, match="恰好 1"):
        ve.signing_ref(json.dumps({"site": rows}), "site", allowed_families=("site",)), why


def test_removed_hs_helpers_are_gone():
    for name in ("signing_key", "signer_mode", "legacy_secret"):
        assert not hasattr(ve, name), name


def test_log_verify_prints_fixed_vocabulary_and_swallows_errors(capsys):
    ve.log_verify("auth", "accepted_current")
    assert json.loads(capsys.readouterr().out) == {"event": "session_verify", "verifier": "auth", "outcome": "accepted_current"}
    ve.log_verify("auth", object())        # json 不可序列化：吞掉，不抛
```

- [ ] **Step 2: 跑红**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_verifier_env.py -q -x`
Expected: `TypeError`（`load_allowlist` 的行里没有 `ssm_param`）或 `AttributeError: signing_ref`。

- [ ] **Step 3: 重写 `verifier_env.py`**

```python
"""auth 与 panel 共用的 verifier / signer 运行时装配（3c-final，RS-only）。

原先两处各手写一份（login_handler / console_session），复制品漂移正是本仓库最怕的风险类型，所以收成一份：
auth 拥有本文件，panel 打包时复制（deploy_panel.py 的 COPY_FILES）。
- load_allowlist：SESSION_KEYS_JSON（kid / alg / role / key_arn / spki_sha256，**没有密钥材料**）→ 本 verifier
  那份 kid allowlist，公钥按 key_arn 经 `get_public_key(key_arn, spki_sha256)` 取（session_kms.public_key_loader：
  GetPublicKey + 指纹核对，不符抛）。**出现本 verifier 不该持有的 family 直接拒**（spec §4.3：panel 只持 console）；
  缺配置直接抛，不静默成空 allowlist（空 allowlist 会把全部会话拒掉而看起来像"用户没登录"）。
- signing_ref：同一份 JSON 里 role=current（或显式 previous）的 (kid, key_arn, spki_sha256)。**故意复用 _rows**：
  签发用的 kid 必须是本 verifier 自己也接受的那把，共用一条解析路径就不可能分叉。它不调 KMS——签名器
  （session_kms.KmsSigner）由调用方用返回值构造并缓存。
- log_verify：spec §8 的固定低基数词表，**不记 token**，异常一律吞掉。
"""
from __future__ import annotations

import json

ROLES = ("current", "previous")


def _rows(env_json: str | None, family: str, allowed_families: tuple) -> list:
    if env_json is None:
        raise RuntimeError("SESSION_KEYS_JSON 缺失——部署脚本没下发")
    try:
        keys = json.loads(env_json)
    except ValueError as exc:
        raise RuntimeError("SESSION_KEYS_JSON 不是 JSON——部署脚本坏了") from exc
    if not isinstance(keys, dict) or not set(keys) <= set(allowed_families):
        raise RuntimeError(f"SESSION_KEYS_JSON 含本 verifier 不该持有的 family：{sorted(keys) if isinstance(keys, dict) else keys!r}")
    if family not in keys:
        raise RuntimeError(f"SESSION_KEYS_JSON 没有 {family} family——部署脚本没下发")
    return keys[family]


def load_allowlist(env_json: str | None, family: str, get_public_key, *, allowed_families: tuple) -> dict:
    """验签用的 allowlist：**每一行都取公钥**（current 与 previous 都要能验签）。"""
    return {r["kid"]: {"alg": r["alg"], "public_key": get_public_key(r["key_arn"], r["spki_sha256"]),
                       "role": r["role"]}
            for r in _rows(env_json, family, allowed_families)}


def signing_ref(env_json: str | None, family: str, *, allowed_families: tuple,
                role: str = "current") -> tuple[str, str, str]:
    """→ (kid, key_arn, spki_sha256)：该 family 里指定 role 的那把。签发用，**只有 signer 侧调用**。

    `role="previous"` 只给 auth 的 /fixture-session（就位期正向探针，spec §11.8.8）；生产签发一律 current。
    current 不唯一（0 个或 2 个）时硬失败——env_json 只会给出一个，出现别的数量说明下发的 JSON 被手改过。
    """
    if role not in ROLES:
        raise RuntimeError(f"role 必须是 {ROLES} 之一，得到 {role!r}")
    rows = _rows(env_json, family, allowed_families)
    current = [r for r in rows if r.get("role") == "current"]
    if len(current) != 1:
        raise RuntimeError(f"SESSION_KEYS_JSON 的 {family} family 有 {len(current)} 个 role=current 的 kid，"
                           "必须恰好 1 个——部署脚本坏了")
    picked = current if role == "current" else [r for r in rows if r.get("role") == "previous"]
    if not picked:
        raise RuntimeError(f"SESSION_KEYS_JSON 的 {family} family 没有 previous 行——就位之前没有 previous key 可签")
    row = picked[0]
    return row["kid"], row["key_arn"], row["spki_sha256"]


def log_verify(verifier: str, outcome) -> None:
    try:
        print(json.dumps({"event": "session_verify", "verifier": verifier, "outcome": outcome}))
    except Exception:
        pass
```

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_verifier_env.py tests/test_session_kms.py tests/test_session_keys.py tests/test_verifier_allowlist.py tests/test_upgrade_code.py -q`
Expected: 全绿（除 Task 9 那一条）。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/auth/verifier_env.py site-builder/auth/tests/test_verifier_env.py
git commit -m "feat(asset-v1/08): verifier_env 按公钥装配 allowlist、signing_ref 只给 (kid, key_arn, spki)；删 signer_mode/legacy_secret/signing_key"
```

---

### Task 5：`login_handler.py`——KMS 签发、RS 验签、`POST /fixture-session`；删 legacy 与 signer 开关

**Files:**
- Modify: `site-builder/auth/login_handler.py`
- Modify: `site-builder/auth/tests/test_login_handler.py`
- Modify: `site-builder/auth/tests/test_secret_loading.py`
- Modify: `site-builder/auth/tests/test_edge_new_form_vector.py`（只改 allowlist 形态；Edge 侧在 Task 10 才能绿——本 Task 允许它红）
- Modify: `site-builder/auth/tests/test_pkce.py`（**执行时补进本 Task 的清单，见 SDD ledger Ruling R12**：它测的是 login_handler 的登录流，而 Task 1 删掉 conftest 的 `*_KID_SECRET` 后它就 collection error，原 plan 里没有任何 Task 认领它。改法：`ENV` 加 `SESSION_KEYS_JSON` / `FIXTURE_ISSUER`、删 `SESSION_SIGNER`，`mint_session_jwt` 的 seam 换成 `mint_token`；两条"state 用会话密钥签"的 HS 负例换成 RS 等价性质——`_login_flow_sig` 零 KMS 调用且只读 `LOGIN_FLOW_SECRET_PARAM`、换 secret 后旧 state 不再验过 + 一条正对照。无 RS 类比的 HS 断言删掉并在报告里列出）
- Create: `site-builder/auth/tests/test_fixture_session.py`
- Create: `site-builder/auth/tests/test_signer_guard.py`
- Delete: `site-builder/auth/tests/test_signer_switch_guard.py`
- Modify: `site-builder/auth/deploy_auth.py` **只改一行**：`AUTH_PACKAGE_MODULES = ("login_handler.py", "session.py", "verifier_env.py", "session_kms.py")`（其余 deploy_auth 改动在 Task 7；`test_deploy_auth_package.py` 的闭包断言要求本 Task 就加）
- Test: `test_login_handler.py`、`test_fixture_session.py`、`test_signer_guard.py`、`test_secret_loading.py`、`test_deploy_auth_package.py`、`test_pkce.py`（R12）

**Interfaces:**
- Consumes: `session.mint_token / verify_token / FIXTURE_*`、`session_kms.KmsSigner / public_key_loader`、`verifier_env.load_allowlist / signing_ref`。
- Produces（deploy_auth、verify_deployed_components、E2E 依赖）:
  - 环境变量：`SESSION_KEYS_JSON`（RS 行）、`LOGIN_FLOW_SECRET_PARAM`、`CLIENT_SECRET_PARAM`、`FIXTURE_ISSUER`（`"on"` / `"off"`）；**删** `JWT_SECRET_PARAM` / `LEGACY_ENTRY` / `SESSION_SIGNER`
  - `lh._kms()`、`lh._reset_signers()`（测试钩子）、`lh._signer(family, role="current") -> tuple[str, Callable]`、`lh._allowlist(family)`
  - `POST /fixture-session`：请求 JSON `{"email": str, "ttl_seconds"?: int, "name"?: str, "role"?: "current"|"previous"}`；响应 200 JSON `{"token", "kid", "ttl_seconds"}`，`cache-control: no-store`；404（`FIXTURE_ISSUER != "on"`）、405（非 POST）、403（`requestContext.authorizer.iam.userArn` 不是本账号 `assumed-role/site-builder-verifier/*`）、400（email 不是 `@e2e.invalid` / role 非法 / previous 不存在 / body 不是 JSON）
  - `lh.VERIFIER_ROLE_NAME = "site-builder-verifier"`

- [ ] **Step 1: 改 `test_login_handler.py` 的基线 ENV 与助手（先红）**

顶部 `ENV` 改为（删 `JWT_SECRET` / `LEGACY_ENTRY` / `SESSION_SIGNER`，`SESSION_KEYS_JSON` 来自 vectors）：

```python
import upgrade_code_vectors as v

ENV = {"COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "cs", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test", "LOGIN_FLOW_SECRET_PARAM": "/site-builder/login-flow-secret",
       "SESSION_KEYS_JSON": v.session_keys_json((v.SITE_KID, "current"), (v.CONSOLE_KID, "current")),
       "FIXTURE_ISSUER": "off"}
```

（保留原 ENV 里其余键值——`REQUIRE_EMAIL_VERIFIED` 等——只删上面三个、改 `SESSION_KEYS_JSON`。）删掉 `ENV_CURRENT`，所有 `ENV_CURRENT` 引用改成 `ENV`。

加两个助手，替换全部 `session.mint_session_jwt(...)` / `session.mint_upgrade_code(...)` 调用（原文件里约 12 处，用 `grep -n "mint_session_jwt\|mint_upgrade_code\|verify_upgrade_code\|verify_session_jwt\|JWT_SECRET" tests/test_login_handler.py` 逐个改）：

```python
def _site_session(email="u@x.com", name="U", *, key=v.SITE_KEY, kid=v.SITE_KID, ttl=600, **kw):
    return session.mint_token(kid=kid, sign=v.signer(key), token_use="site-session", email=email,
                              ttl_seconds=ttl, name=name, idp="Feishu", auth_via="TokenGeneration_HostedAuth", **kw)


def _upgrade_claims(code: str) -> dict:
    claims, outcome = session.verify_token(code, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert claims, outcome
    return claims
```

规则：原来 `session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"], …)` → `_site_session("u@x.com", "U")`；原来 `session.verify_upgrade_code(code, ENV["JWT_SECRET"])` → `_upgrade_claims(code)`；原来手搓 HMAC 的用例（第 763 行附近 `hmac.new(ENV["JWT_SECRET"]…)`）改成用 `v.signer(v.SITE_PREV_KEY)` 在 `kid=site-rs-v1` 下签（"第三把 key 冒充已知 kid"）。

**删掉**这些用例（它们测的形态不再存在）：`test_callback_keeps_the_legacy_wire_form_byte_for_byte_when_signer_is_legacy`、`test_console_session_keeps_the_legacy_upgrade_code_form_when_signer_is_legacy`、`test_console_session_legacy_entry_off`、`test_console_session_verification_path_is_unchanged_by_the_signer_switch`、`test_missing_or_illegal_session_signer_fails_loudly_instead_of_signing`。
**改名 + 改断言**：`test_console_session_unknown_kid_does_not_fall_back_to_legacy` → `test_console_session_rejects_an_unknown_kid`（断言 302 到登录、日志 outcome `unknown_kid`）；`test_callback_signs_the_site_session_with_the_site_current_kid_when_signer_is_current` → 去掉 `_when_signer_is_current`，header 断言 `{"alg": "RS256", "typ": "JWT", "kid": "site-rs-v1"}`；`test_callback_cookie_max_age_matches_the_token_exp_in_both_signer_modes` → 只跑 ENV 一次；`test_callback_signature_is_the_site_family_key_not_the_legacy_one` → `…_not_the_console_key`（用 `v.CONSOLE_ALLOWLIST` 验必 `unknown_kid`）。

`test_callback_fetches_the_signing_key_before_burning_the_authorization_code` 的参数化改为三种会让 `_signer("site")` 失败的 env：缺 `SESSION_KEYS_JSON`、`SESSION_KEYS_JSON` 里 site 没有 current、KMS 指纹不符（用 `kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY`，通过 conftest 的 fixture 返回值拿到 `kms`）；断言 `_exchange_code` 一次都没被调。

- [ ] **Step 2: 写 `test_fixture_session.py`（先红）**

```python
"""auth 的 `POST /fixture-session`（spec §11.7 / ADR 0002）：只对 site-builder-verifier、只签夹具域、只签站点会话。"""
import json
from unittest.mock import patch

import pytest

import login_handler as lh
import session
import upgrade_code_vectors as v
from test_login_handler import ENV

ON = dict(ENV, FIXTURE_ISSUER="on")
WITH_PREVIOUS = dict(ON, SESSION_KEYS_JSON=v.session_keys_json(
    (v.SITE_KID, "current"), (v.SITE_PREV_KID, "previous"), (v.CONSOLE_KID, "current")))
VERIFIER = "arn:aws:sts::111111111111:assumed-role/site-builder-verifier/probe-1"


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:111111111111:function:site-auth-service"


def _event(body, *, caller=VERIFIER, method="POST"):
    return {"rawPath": "/fixture-session", "queryStringParameters": {}, "cookies": [],
            "body": json.dumps(body) if isinstance(body, dict) else body,
            "requestContext": {"http": {"method": method}, "authorizer": {"iam": {"userArn": caller}}}}


def _call(env, body, **kw):
    with patch.dict(lh.os.environ, env):
        return lh.handler(_event(body, **kw), _Ctx())


def test_is_404_when_the_component_is_not_configured():
    assert _call(ENV, {"email": "p@e2e.invalid"})["statusCode"] == 404


def test_issues_a_site_session_for_a_fixture_email_that_verifies_under_the_site_key():
    r = _call(ON, {"email": "probe@e2e.invalid", "ttl_seconds": 600, "name": "Probe"})
    assert r["statusCode"] == 200 and r["headers"]["cache-control"] == "no-store" and "cookies" not in r
    body = json.loads(r["body"])
    assert body["kid"] == v.SITE_KID and body["ttl_seconds"] == 600
    claims, outcome = session.verify_token(body["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
    assert outcome == "accepted_current"
    assert (claims["email"], claims["name"], claims["idp"], claims["auth_via"]) == \
        ("probe@e2e.invalid", "Probe", "fixture", "fixture-issuer")
    assert claims["exp"] - claims["iat"] == 600


def test_ttl_is_capped_at_thirty_minutes_and_defaults_to_it():
    for body, want in (({"email": "p@e2e.invalid"}, 1800), ({"email": "p@e2e.invalid", "ttl_seconds": 99999}, 1800),
                       ({"email": "p@e2e.invalid", "ttl_seconds": 5}, 5)):
        out = json.loads(_call(ON, body)["body"])
        claims, _ = session.verify_token(out["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
        assert claims["exp"] - claims["iat"] == want and out["ttl_seconds"] == want


@pytest.mark.parametrize("email", ["a@example.com", "a@e2e.invalid.evil.com", "a@evil.e2e.invalid", "e2e.invalid",
                                   "", None, 5, "a@E2E.INVALID"])
def test_non_fixture_emails_are_refused(email):
    r = _call(ON, {"email": email})
    assert r["statusCode"] == 400, email


@pytest.mark.parametrize("caller", [
    "arn:aws:sts::111111111111:assumed-role/site-edge-role/edge",          # Edge role 能调同一个 URL，必须在这里也拒
    "arn:aws:iam::111111111111:user/kent",
    "arn:aws:sts::222222222222:assumed-role/site-builder-verifier/x",       # 别的账号同名角色
    "arn:aws:sts::111111111111:assumed-role/site-builder-verifier-2/x",
    "", None])
def test_only_the_verifier_role_of_this_account_may_call(caller):
    assert _call(ON, {"email": "p@e2e.invalid"}, caller=caller)["statusCode"] == 403


def test_get_is_not_allowed():
    assert _call(ON, {"email": "p@e2e.invalid"}, method="GET")["statusCode"] == 405


def test_garbage_body_is_400_not_500():
    assert _call(ON, "{not json")["statusCode"] == 400
    assert _call(ON, "[]")["statusCode"] == 400


def test_role_previous_signs_with_the_previous_site_kid_or_fails_when_there_is_none():
    out = json.loads(_call(WITH_PREVIOUS, {"email": "p@e2e.invalid", "role": "previous"})["body"])
    assert out["kid"] == v.SITE_PREV_KID
    al = {**v.SITE_ALLOWLIST, v.SITE_PREV_KID: v.public_entry(v.SITE_PREV_KEY, "previous")}
    assert session.verify_token(out["token"], allowlist=al, token_use="site-session")[1] == "accepted_previous"
    assert _call(ON, {"email": "p@e2e.invalid", "role": "previous"})["statusCode"] == 400
    assert _call(ON, {"email": "p@e2e.invalid", "role": "legacy"})["statusCode"] == 400


def test_fixture_session_never_carries_a_real_idp_or_auth_via():
    out = json.loads(_call(ON, {"email": "p@e2e.invalid", "idp": "Feishu", "auth_via": "TokenGeneration_HostedAuth"})["body"])
    claims, _ = session.verify_token(out["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
    assert (claims["idp"], claims["auth_via"]) == ("fixture", "fixture-issuer"), "请求体不许指定来源标记"


def test_fixture_session_is_only_ever_a_site_session(_fake_platform_clients):
    kms = _fake_platform_clients
    _call(ON, {"email": "p@e2e.invalid"})
    signs = [c for c in kms.calls if c[0] == "sign"]
    assert signs and all(c[1] == v.KEY_ARN[v.SITE_KID] for c in signs), "夹具签发只许用 site family 的 key"


def test_issue_is_logged_without_the_token(_fake_platform_clients, capsys):
    out = json.loads(_call(ON, {"email": "p@e2e.invalid"})["body"])
    logs = capsys.readouterr().out
    assert '"event": "fixture_session_issued"' in logs and "p@e2e.invalid" in logs and out["token"] not in logs
```

- [ ] **Step 3: 写 `test_signer_guard.py`（替换 `test_signer_switch_guard.py`；先红）**

```python
"""签发面守卫（3c-final）：**每一次 `mint_token` 的 kid 与 sign 都来自 `_signer(...)` 的返回值**，且只有
login_handler.py 与 panel/console_session.py 会签发。替换 3c-1B 的 test_signer_switch_guard.py（signer 开关已删）。

为什么值得一条 AST 守卫：手写一个 kid 字面量、或把别的可调用递给 `sign=`，签出来的是"kid 声称是 A 而签名是 B"
的 token，验签端表现为 bad_signature（不是 unknown_kid），排查方向完全错；多一条不经 `_signer` 的签发路径
则绕开了 KmsSigner 的 KeyId 断言与冷启动自检。自测（test_guard_catches_*）证明检查器本身会红。
"""
import ast
from pathlib import Path

import pytest

AUTH = Path(__file__).resolve().parents[1]
PANEL = AUTH.parent / "panel"
SIGNER_FILES = (AUTH / "login_handler.py", PANEL / "console_session.py")
NON_SIGNER_FILES = (AUTH / "pre_token_email.py", PANEL / "handler.py", PANEL / "api.py")
FORBIDDEN_NAMES = {"mint_session_jwt", "mint_upgrade_code", "verify_session_jwt", "verify_upgrade_code",
                   "verify_with_legacy", "legacy_secret", "signer_mode", "signing_key"}


def _mint_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name == "mint_token":
                yield node


def _signer_bound_names(fn: ast.FunctionDef) -> set:
    """函数体里 `kid, sign = _signer(...)`（或 `kid, sign = self._signer(...)`）绑定出来的名字对。"""
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if fname == "_signer" and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple):
                names = [e.id for e in node.targets[0].elts if isinstance(e, ast.Name)]
                if len(names) == 2:
                    out.add(tuple(names))
    return out


def check_source(src: str) -> list:
    """→ 违规清单（空 = 通过）。"""
    tree = ast.parse(src)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            problems.append(f"line {node.lineno}: 引用了已删除的 HS/legacy 名字 {node.id}")
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_NAMES:
            problems.append(f"line {node.lineno}: 引用了已删除的 HS/legacy 名字 {node.attr}")
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        bound = _signer_bound_names(fn)
        for call in _mint_calls(fn):
            kw = {k.arg: k.value for k in call.keywords}
            if "kid" not in kw or "sign" not in kw:
                problems.append(f"line {call.lineno}: mint_token 缺 kid= 或 sign=")
                continue
            pair = (kw["kid"].id if isinstance(kw["kid"], ast.Name) else None,
                    kw["sign"].id if isinstance(kw["sign"], ast.Name) else None)
            if pair not in bound:
                problems.append(f"line {call.lineno}: mint_token 的 kid/sign 不是同一次 `kid, sign = _signer(...)` 绑定出来的 {pair}")
    return problems


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_every_mint_takes_kid_and_sign_from_the_signer_helper(path):
    assert check_source(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_signer_files_actually_mint_so_the_guard_has_something_to_guard(path):
    assert list(_mint_calls(ast.parse(path.read_text(encoding="utf-8")))), f"{path.name} 里没有 mint_token 调用了？"


@pytest.mark.parametrize("path", NON_SIGNER_FILES, ids=lambda p: p.name)
def test_files_that_must_never_sign_contain_no_mint_at_all(path):
    assert not list(_mint_calls(ast.parse(path.read_text(encoding="utf-8")))), f"{path.name} 多开了一条签发路径"


GOOD = """
def f():
    kid, sign = _signer("site")
    return mint_token(kid=kid, sign=sign, token_use="site-session", email=e, ttl_seconds=1)
"""
BAD = [
    ("kid 字面量", GOOD.replace("kid=kid", 'kid="site-rs-v1"')),
    ("sign 来自别处", GOOD.replace("sign=sign", "sign=other")),
    ("不经 _signer", GOOD.replace("_signer(", "_other(")),
    ("引用已删的 legacy 名", GOOD + "\ndef g():\n    return mint_session_jwt(e, n, s)\n"),
    ("引用已删的 signer 开关", GOOD + "\ndef g():\n    return verifier_env.signer_mode(x)\n"),
]


def test_guard_passes_the_correct_shape():
    assert check_source(GOOD) == []


@pytest.mark.parametrize("why,src", BAD, ids=[b[0] for b in BAD])
def test_guard_catches_every_way_of_bypassing_the_signer_helper(why, src):
    assert check_source(src), why
```

`git rm site-builder/auth/tests/test_signer_switch_guard.py`

- [ ] **Step 4: `test_secret_loading.py` 里的三处改动（先红）**

- `test_deploy_auth_ships_session_keys_json_and_legacy_switch_without_values` → 改名 `test_deploy_auth_ships_session_keys_json_and_fixture_switch_without_values`：断言 env 段含 `"SESSION_KEYS_JSON"` 与 `"FIXTURE_ISSUER"`，**不含** `"LEGACY_ENTRY"` / `"SESSION_SIGNER"` / `"JWT_SECRET_PARAM"`、不含 `"secret"` / `token_hex`。
- 删 `test_deploy_auth_ships_the_signer_switch_from_config_not_a_literal`、`test_deploy_auth_legacy_param_has_one_source_of_truth`。
- `test_deploy_auth_does_not_ship_plaintext_secrets`：最后一行改为 `assert "CLIENT_SECRET_PARAM" in src and "JWT_SECRET_PARAM" not in src`。
- `test_lambda_role_grants_ssm_read_on_every_run`：`kms:Decrypt` 那条断言不变（login-flow 与 client secret 仍是 SecureString），**追加** `assert "kms:Sign" in src and "kms:GetPublicKey" in src and "RSASSA_PKCS1_V1_5_SHA_256" in src and '"kms:MessageType": "RAW"' in src`。
- `test_session_key_rotation_protocol_is_documented_where_the_secret_is_read` 不改（Step 5 重写 `_secret` docstring 时保留 `Edge` / `轮转` / `kid` / `previous` / `DEPLOY.md` 五个词）。

- [ ] **Step 5: 改 `login_handler.py`**

（a）import 段：

```python
from session import (FIXTURE_AUTH_VIA, FIXTURE_DOMAIN, FIXTURE_IDP, FIXTURE_MAX_TTL,  # noqa: F401
                     UPGRADE_MAX_TTL, mint_token, verify_token)
import session_kms
import verifier_env
```

（b）`_secret` 的 docstring 里从 "⚠️ **会话密钥的轮转不能靠就地改值…" 起那一段改为：

```
    ⚠️ **本函数只管两把 HMAC / OAuth 密钥（login-flow secret 与 Cognito client secret）。会话签名密钥不在 SSM
    里**：它们是 KMS 非对称 CMK，签发经 `_signer()`（session_kms.KmsSigner），验签经 `_allowlist()` 按
    key_arn 取公钥。它们的轮转按 `kid` + `current` / `previous` 双槽位走（新 key 经 `previous` 就位、Edge
    重部复制完成后才互换），协议在 DEPLOY.md「轮转会话密钥」——**动手前先读它**；Edge 那份公钥是 CDK
    部署时注入的，改一次要 10–20 分钟全球复制，所以顺序是 verifier 先行。
```

（c）把 `_secret_by_param` 到 `_signing_key` 那一段（含 `_allowlist` / `_legacy_secret` / `_signer_mode` / `_signing_key`）整段替换为：

```python
_kms_client = None
_SIGNERS: dict = {}          # key_arn -> KmsSigner（容器复用：自检只做一次）
_public_key = None           # session_kms.public_key_loader(_kms())（容器复用：每把公钥只取一次）
VERIFIER_ROLE_NAME = "site-builder-verifier"


def _kms():
    global _kms_client
    if _kms_client is None:
        import boto3
        _kms_client = boto3.client("kms", region_name="us-east-1")
    return _kms_client


def _reset_signers() -> None:
    """测试钩子：换掉 `_kms()` 之后清掉按 ARN 缓存的 signer 与公钥加载器。"""
    global _public_key
    _SIGNERS.clear()
    _public_key = None


def _get_public_key(key_arn: str, spki_sha256: str):
    global _public_key
    if _public_key is None:
        _public_key = session_kms.public_key_loader(_kms())
    return _public_key(key_arn, spki_sha256)


def _allowlist(family: str) -> dict:
    """本 verifier 那份 allowlist（auth 持两个 family）：公钥按 key_arn 取、与 spki_sha256 核对（fail closed）。"""
    return verifier_env.load_allowlist(os.environ.get("SESSION_KEYS_JSON"), family, _get_public_key,
                                       allowed_families=("site", "console"))


def _signer(family: str, role: str = "current") -> tuple:
    """→ (kid, sign)。**handler 取签发材料的唯一入口**（tests/test_signer_guard.py 的 AST 守卫锁死：
    每次 mint_token 的 kid/sign 都必须是本函数同一次调用绑定出来的）。`role="previous"` 只给
    /fixture-session（就位期探针）。KmsSigner 按 ARN 缓存：首次调用做一次 GetPublicKey 指纹自检。"""
    kid, key_arn, spki = verifier_env.signing_ref(os.environ.get("SESSION_KEYS_JSON"), family,
                                                  allowed_families=("site", "console"), role=role)
    signer = _SIGNERS.get(key_arn)
    if signer is None:
        signer = _SIGNERS[key_arn] = session_kms.KmsSigner(_kms(), key_arn, spki)
    return kid, signer
```

（d）`/callback` 分支：把 `signer = _signer_mode()` 到 `legacy_signing_secret = _secret("JWT_SECRET")` 那段替换为

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        # 签发材料先取、`_exchange_code` 后调：响亮失败必须发生在**烧掉这枚一次性授权码之前**（ticket 20）。
        # 会失败的是 SESSION_KEYS_JSON 缺失 / site 缺 current / kms:GetPublicKey AccessDenied / 公钥指纹
        # 与配置不符（KmsSigner.self_check）——都比"环境变量漏下发"常见。自检只在容器首次签发时打一次 KMS。
        kid, sign = _signer("site")
        sign.self_check()
```

并把两分支的 mint 替换为单条：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        token = mint_token(kid=kid, sign=sign, token_use="site-session",
                           email=user["email"], ttl_seconds=SESSION_TTL_SECONDS,
                           name=user["name"], idp=user.get("idp", ""),
                           auth_via=user.get("auth_via", ""))
```

（e）`/console-session` 分支：`site_allowlist = _allowlist("site")`；删 `legacy_secret = _legacy_secret()`；循环里改为 `claims, outcome = verify_token(candidate, allowlist=site_allowlist, token_use="site-session")`；升级码改为

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        kid, sign = _signer("console")
        code = mint_token(kid=kid, sign=sign, token_use="console-upgrade",
                          email=claims["email"], ttl_seconds=UPGRADE_MAX_TTL)
```

（f）在 `/logout` 分支**之前**插入：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    if path == "/fixture-session":
        # 验收身份的受控签发（spec §11.7 / ADR 0002）。**不配置 = 404**（与 ApiKey 组件同款"不存在"）。
        if os.environ.get("FIXTURE_ISSUER") != "on":
            return {"statusCode": 404, "body": "not found"}
        if ((event.get("requestContext") or {}).get("http") or {}).get("method") != "POST":
            return {"statusCode": 405, "body": ""}
        # 应用层核对调用者：Edge role 能调同一个 Function URL（resource policy 放行它），必须在这里也拒。
        # **这道检查只挡经 Function URL 的调用**——直接 lambda:InvokeFunction 的调用方自己构造整个事件，
        # userArn 可伪造（edge_caller.py 的 Path A）；那条入口的危害上限由 Edge / panel 的夹具边界规则给，
        # 不由这里给（ADR 0002）。
        caller = (((event.get("requestContext") or {}).get("authorizer") or {}).get("iam") or {}).get("userArn") or ""
        account = (getattr(context, "invoked_function_arn", "") or "").split(":")[4:5]
        if not account or not re.fullmatch(
                rf"arn:aws:sts::{re.escape(account[0])}:assumed-role/{re.escape(VERIFIER_ROLE_NAME)}/[^/]+", caller):
            return {"statusCode": 403, "body": "forbidden"}
        try:
            body = json.loads(event.get("body") or "")
            if not isinstance(body, dict):
                raise ValueError("not an object")
        except ValueError:
            return {"statusCode": 400, "body": "body must be a JSON object"}
        email = body.get("email")
        # 夹具域是常量不是配置（授权边界要进 git review）；大小写敏感、精确后缀，不接受子域。
        if (not isinstance(email, str) or email.count("@") != 1 or not email.split("@")[1] == FIXTURE_DOMAIN
                or not email.split("@")[0]):
            return {"statusCode": 400, "body": f"email must be <local>@{FIXTURE_DOMAIN}"}
        role = body.get("role", "current")
        if role not in ("current", "previous"):
            return {"statusCode": 400, "body": "role must be current or previous"}
        try:
            ttl = min(int(body.get("ttl_seconds", FIXTURE_MAX_TTL)), FIXTURE_MAX_TTL)
        except (TypeError, ValueError):
            return {"statusCode": 400, "body": "ttl_seconds must be an integer"}
        if ttl <= 0:
            return {"statusCode": 400, "body": "ttl_seconds must be positive"}
        name = body.get("name") if isinstance(body.get("name"), str) and body.get("name") else email.split("@")[0]
        try:
            kid, sign = _signer("site", role=role)
        except RuntimeError as exc:                 # previous 槽位为空：就位之前没有 previous key 可签
            if "previous" in str(exc):
                return {"statusCode": 400, "body": "no previous site key is staged"}
            raise
        # 只签站点会话；来源标记是**夹具专用值**，请求体不能指定（Edge 据此只在夹具站点与平台路由上放行）。
        token = mint_token(kid=kid, sign=sign, token_use="site-session", email=email,
                           ttl_seconds=ttl, name=name, idp=FIXTURE_IDP, auth_via=FIXTURE_AUTH_VIA)
        print(json.dumps({"event": "fixture_session_issued", "email": email, "kid": kid, "ttl_seconds": ttl,
                          "caller": caller}))
        return {"statusCode": 200,
                "headers": {"content-type": "application/json", "cache-control": "no-store"},
                "body": json.dumps({"token": token, "kid": kid, "ttl_seconds": ttl})}
```

`import re` 加进文件顶部（若尚无）。

（g）`_verify_… ` 之外的地方若还引用 `SESSION_TYP` / `verify_session_jwt` / `mint_session_jwt` / `mint_upgrade_code` / `verify_with_legacy` / `_secret("JWT_SECRET")`，全部删掉（`grep -n` 确认为 0）。

（h）`deploy_auth.py` 只改一行：`AUTH_PACKAGE_MODULES = ("login_handler.py", "session.py", "verifier_env.py", "session_kms.py")`。

（i）`test_edge_new_form_vector.py`：`EDGE_ALLOWLIST` 改为 `{v.SITE_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"}}`，`EDGE_OVERRIDES = {"SITE_ALLOWLIST_JSON": json.dumps(EDGE_ALLOWLIST)}`（删 `JWT_SECRET` / `LEGACY_ENTRY`），import 改为 `import upgrade_code_vectors as v`；`_session_cookie(_do_callback(ENV, …))`。它在 Task 10 前红（Edge 还是 HS）——记进 progress，不在本 Task 修。

- [ ] **Step 6: 跑绿**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q --deselect tests/test_edge_new_form_vector.py --deselect tests/test_deploy_auth_sequence.py --deselect tests/test_requirements_locked.py --deselect tests/test_verifier_allowlist.py::test_fixture_domain_matches_the_permissions_copy`
Expected: 全绿。`test_deploy_auth_sequence.py` 在 Task 7 才绿（它读 deploy_auth 的 env / 角色）；`test_requirements_locked.py` 在 Task 8（panel 清单）后才绿。

- [ ] **Step 7: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add -A site-builder/auth/login_handler.py site-builder/auth/deploy_auth.py site-builder/auth/tests
git commit -m "feat(asset-v1/08): auth 切 KMS 签发与 RS 验签，新增 POST /fixture-session（只对 site-builder-verifier、只签夹具域站点会话）；删 legacy 分支与 signer 开关"
```

---

### Task 6：`function_url_policy.py` 支持额外 principal（verifier 的两条语句）

**Files:**
- Modify: `site-builder/deployer/functions/function_url_policy.py`
- Modify: `site-builder/deployer/tests/test_function_url_policy.py`（追加）
- Test: 同上

**Interfaces:**
- Produces:
  - `expected_statements(edge_role_arn, *, extra_principals: dict | None = None) -> list[dict]`：`extra_principals` 是 `{"verifier": "<role arn>"}` 这种 `标签 → 精确 role ARN`；每个标签产出 `f"{label}-invoke"` / `f"{label}-invoke-function"` 两条，形态与 edge 两条相同
  - `expected_projection(edge_role_arn, *, extra_principals=None)`、`drift(policy, edge_role_arn, *, extra_principals=None)`、`converge(lam, fn, edge_role_arn, *, qualifier=None, log=print, extra_principals=None)`
  - `EXPECTED_SIDS` 保留为 edge 两条；新增 `sids_for(edge_role_arn, extra_principals) -> tuple[str, ...]`（全部期望 Sid，按声明顺序）
  - panel / key-proxy 调用形不变（默认 `extra_principals=None` ⇒ 行为字节不变）

- [ ] **Step 1: 追加用例（先红）**

在 `site-builder/deployer/tests/test_function_url_policy.py` 末尾追加（该文件已有 `EDGE`、`fake_lambda_policy` 的夹具与 `_policy()` 助手——沿用；若助手名不同，按文件里现有的名字改）：

```python
VERIFIER = "arn:aws:iam::111111111111:role/site-builder-verifier"


def test_extra_principal_adds_two_statements_of_the_same_shape():
    stmts = fup.expected_statements(EDGE, extra_principals={"verifier": VERIFIER})
    sids = [s["StatementId"] for s in stmts]
    assert sids == ["edge-invoke", "edge-invoke-function", "verifier-invoke", "verifier-invoke-function"]
    ver = {s["StatementId"]: s for s in stmts}
    assert ver["verifier-invoke"] == {"StatementId": "verifier-invoke", "Action": "lambda:InvokeFunctionUrl",
                                      "Principal": VERIFIER, "FunctionUrlAuthType": "AWS_IAM"}
    assert ver["verifier-invoke-function"] == {"StatementId": "verifier-invoke-function", "Action": "lambda:InvokeFunction",
                                               "Principal": VERIFIER, "InvokedViaFunctionUrl": True}


def test_no_extra_principal_is_byte_identical_to_before():
    assert fup.expected_statements(EDGE) == fup.expected_statements(EDGE, extra_principals=None) == \
        fup.expected_statements(EDGE, extra_principals={})


@pytest.mark.parametrize("bad", ["", "*", "arn:aws:iam::111111111111:role/*", "site-builder-verifier",
                                 "arn:aws:iam::111111111111:user/kent"])
def test_extra_principal_must_be_an_exact_role_arn(bad):
    with pytest.raises(ValueError):
        fup.expected_statements(EDGE, extra_principals={"verifier": bad})


def test_drift_treats_a_missing_verifier_statement_as_missing_and_a_leftover_one_as_stray():
    pol = _policy(fup.expected_statements(EDGE, extra_principals={"verifier": VERIFIER}))   # 四条都在
    assert fup.drift(pol, EDGE, extra_principals={"verifier": VERIFIER}).ok
    d = fup.drift(pol, EDGE)                                    # 期望里没有 verifier ⇒ 那两条是野 Sid
    assert set(d.stray) == {"verifier-invoke", "verifier-invoke-function"} and not d.missing
    d2 = fup.drift(_policy(fup.expected_statements(EDGE)), EDGE, extra_principals={"verifier": VERIFIER})
    assert set(d2.missing) == {"verifier-invoke", "verifier-invoke-function"}


def test_converge_adds_the_verifier_pair_and_removes_it_when_the_component_is_turned_off():
    lam = FakeLambdaPolicy()          # deployer/tests/fake_lambda_policy.py 的有状态替身
    fup.converge(lam, "site-auth-service", EDGE, extra_principals={"verifier": VERIFIER}, log=lambda *_: None)
    assert fup.drift(lam.policy("site-auth-service"), EDGE, extra_principals={"verifier": VERIFIER}).ok
    fup.converge(lam, "site-auth-service", EDGE, log=lambda *_: None)      # 关掉组件：verifier 两条被当野 Sid 删掉
    assert fup.drift(lam.policy("site-auth-service"), EDGE).ok
    assert {s["Sid"] for s in lam.policy("site-auth-service")["Statement"]} == {"edge-invoke", "edge-invoke-function"}
```

（`FakeLambdaPolicy` 与 `_policy` 以 `fake_lambda_policy.py` 里实际导出的类名 / 助手为准；该文件是 04 票建的，读一眼再写。）

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_function_url_policy.py -q -x`
Expected: `TypeError: expected_statements() got an unexpected keyword argument 'extra_principals'`。

- [ ] **Step 3: 实现**

```python
def _exact_role_arn(arn: str, what: str) -> str:
    arn = (arn or "").strip()
    if not arn:
        raise ValueError(f"{what} 为空——Function URL 的调用者必须绑定到 exact role ARN，不能放宽")
    if "*" in arn or not arn.startswith("arn:aws:iam::") or ":role/" not in arn:
        raise ValueError(f"{what} 必须是精确的 IAM role ARN: {arn!r}")
    return arn


def _pair(label: str, arn: str) -> list[dict]:
    return [
        {"StatementId": f"{label}-invoke", "Action": "lambda:InvokeFunctionUrl",
         "Principal": arn, "FunctionUrlAuthType": FUNCTION_URL_AUTH_TYPE},
        # 2025-10 起 InvokeFunctionUrl 单条不够，缺 InvokeFunction 即 403。InvokedViaFunctionUrl 把它限定为仅经 Function URL 调用。
        {"StatementId": f"{label}-invoke-function", "Action": "lambda:InvokeFunction",
         "Principal": arn, "InvokedViaFunctionUrl": True},
    ]


def expected_statements(edge_role_arn: str, *, extra_principals: dict | None = None) -> list[dict]:
    """期望语句：edge role 两条 + `extra_principals`（标签 → 精确 role ARN）每个两条，形态相同。

    **缺 edge_role_arn 或给通配一律抛错**（理由见上）。`extra_principals` 今天只有一个使用方：auth 在
    `[Verification] fixture_issuer = true` 时给 `site-builder-verifier` 角色的两条（spec §11.7）；
    关掉组件时不传它 ⇒ 那两条在下一次 converge 里被当野 Sid 删掉。
    """
    out = _pair("edge", _exact_role_arn(edge_role_arn, "config.ini [Deployer] edge_role_arn"))
    for label, arn in (extra_principals or {}).items():
        out += _pair(label, _exact_role_arn(arn, f"额外 principal {label!r}"))
    return out


def sids_for(edge_role_arn: str, extra_principals: dict | None = None) -> tuple:
    return tuple(s["StatementId"] for s in expected_statements(edge_role_arn, extra_principals=extra_principals))


def expected_projection(edge_role_arn: str, *, extra_principals: dict | None = None) -> dict:
    return {s["StatementId"]: ("Allow", s["Action"], s["Principal"], _rendered_condition(s))
            for s in expected_statements(edge_role_arn, extra_principals=extra_principals)}


def drift(policy: dict | None, edge_role_arn: str, *, extra_principals: dict | None = None) -> Drift:
    want = expected_projection(edge_role_arn, extra_principals=extra_principals)
    sids = tuple(want)
    got: dict = {}
    strays: list = []
    for s in (policy or {}).get("Statement", []):
        sid = s.get("Sid")
        if not sid:
            strays.append(NO_SID)
        elif sid in want:
            got[sid] = _project(s)
        else:
            strays.append(sid)
    return Drift(missing=tuple(sid for sid in sids if sid not in got),
                 mismatched=tuple(sid for sid in sids if sid in got and got[sid] != want[sid]),
                 stray=tuple(strays))


def converge(lam, fn: str, edge_role_arn: str, *, qualifier: str | None = None, log=print,
             extra_principals: dict | None = None) -> Drift:
    stmts = {s["StatementId"]: s for s in expected_statements(edge_role_arn, extra_principals=extra_principals)}
    q = {"Qualifier": qualifier} if qualifier else {}
    before = drift(_read_policy(lam, fn, q), edge_role_arn, extra_principals=extra_principals)
    if before.ok:
        return before
    if NO_SID in before.stray:
        raise PolicyDriftError(...)          # 原文不变
    for sid in before.mismatched:
        log(f"  {fn}: 语句 {sid!r} 内容与期望不同（principal / action / condition 漂移），替换")
        lam.remove_permission(FunctionName=fn, StatementId=sid, **q)
    for sid in stmts:
        if sid in before.missing or sid in before.mismatched:
            _add_replacing_conflict(lam, fn, stmts[sid], q)
    for sid in before.stray:
        log(f"  {fn}: resource policy 有非预期语句 {sid!r}，删除")
        lam.remove_permission(FunctionName=fn, StatementId=sid, **q)
    for attempt in range(_READBACK_ATTEMPTS):
        after = drift(_read_policy(lam, fn, q), edge_role_arn, extra_principals=extra_principals)
        if after.ok:
            return before
        if attempt + 1 < _READBACK_ATTEMPTS:
            _sleep(_READBACK_DELAY_SECONDS)
    raise PolicyDriftError(...)              # 原文不变
```

（`EXPECTED_SIDS` 常量保留 = edge 两条，供 `deploy_lambda_site` 的 parity 用例；模块 docstring 加一段"额外 principal 只有 verifier 一个使用方"。）

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_function_url_policy.py tests/test_deploy_lambda_site.py -q`（后者有 parity 用例）
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/deployer/functions/function_url_policy.py site-builder/deployer/tests/test_function_url_policy.py
git commit -m "feat(asset-v1/08): function_url_policy 支持额外 principal（verifier 两条同形语句），默认行为字节不变"
```

---

### Task 7：`deploy_auth.py`——KMS IAM、`FIXTURE_ISSUER`、KMS 四项 precheck、`[Verification]` 角色与 URL 语句

**Files:**
- Modify: `site-builder/auth/deploy_auth.py`
- Modify: `site-builder/auth/tests/test_deploy_auth_sequence.py`
- Test: 同上 + `test_secret_loading.py` + `test_deploy_auth_package.py`

**Interfaces:**
- Consumes: `session_keys.load_session_keys / key_refs / kms_key_arns / ssm_parameter_arns / ssm_parameter_names / env_json`、`session_kms.precheck_keys`、`function_url_policy.converge(extra_principals=…)`。
- Produces:
  - `read_verification(cfg) -> Verification(fixture_issuer: bool, trusted_principals: tuple[str, ...])`；`fixture_issuer=true` 且清单空 / 含通配 / 非 `arn:aws:iam::<acct>:(role|user)/…` ⇒ `SystemExit`（写前）
  - `VERIFIER_ROLE_NAME = "site-builder-verifier"`；`ensure_verifier_role(iam, verification, *, account, region) -> str | None`：开 ⇒ 建 / 收敛角色（信任策略 = 清单里的 ARN，`MaxSessionDuration=3600`，inline policy 两条只对 auth 函数 ARN）并返回 ARN；关 ⇒ 若角色存在则删（先删 inline policy）并返回 `None`
  - `lambda_env()["Variables"]`：`LOGIN_FLOW_SECRET_PARAM`、`CLIENT_SECRET_PARAM`、`COGNITO_DOMAIN`、`CLIENT_ID`、`BASE_DOMAIN`、`USER_POOL_ID`、`REQUIRE_EMAIL_VERIFIED`、`SESSION_KEYS_JSON`、`FIXTURE_ISSUER`
  - `required_parameters() == [CLIENT_SECRET_PARAM]`；`precheck()` = `precheck_parameters` + `session_kms.precheck_keys(_kms(), key_refs(keys, ("site","console")))`
  - `ensure_lambda_role()` 的 inline policy 四条语句：`ReadPlatformSecrets`（ssm:GetParameter，精确 ARN：login-flow + client secret）、`DecryptViaSSM`、`SignSessionTokens`（`kms:Sign`，Resource = 两个 family 的全部 key ARN，Condition `StringEquals {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256", "kms:MessageType": "RAW"}`）、`ReadSessionPublicKeys`（`kms:GetPublicKey`，同一批 ARN）
  - `main()` 顺序：`precheck()` → `edge_role_arn()` → `read_verification()` → `ensure_secret(login-flow)` → `ensure_lambda_role()` → `ensure_verifier_role()` → env / zip / `deploy_function` → Function URL → `converge(lam, FN, edge_arn, extra_principals={"verifier": arn} if arn else None)` → 路由表 → pre-token → alarm

- [ ] **Step 1: 改 `test_deploy_auth_sequence.py`（先红）**

`CFG` 的 `[SessionKeys]` 段换成 Task 2 `RS` 那段（含两把 key 的 ARN 与 `spki_hex`），并追加

```
    [Verification]
    fixture_issuer = false
    verifier_trusted_principals =
```

`CFG_FIXTURE = CFG.replace("fixture_issuer = false", "fixture_issuer = true").replace(
    "verifier_trusted_principals =", "verifier_trusted_principals = arn:aws:iam::111111111111:user/kent, arn:aws:iam::111111111111:role/ci")`。

`cfg_files` 夹具另 monkeypatch `da._CLIENTS["kms"] = v.FakeKms()`（`_run_main` 同）。删 `cfg_files_l3` 夹具与全部 `l3_*` 用例、`test_before_l3_the_jwt_secret_param_is_still_shipped`、`test_main_creates_the_login_flow_secret_when_it_is_absent` 里对 HS 参数的 `present` 集合改成 `{da.CLIENT_SECRET_PARAM}`。

改写 / 新增：

```python
def test_required_parameters_are_only_the_client_secret(cfg_files):
    """会话密钥在 KMS 里（precheck 走 KMS 四项）；login-flow 由本脚本 ensure（ADR 0004）⇒ 核对清单只剩 deploy_pool 建的 client secret。"""
    assert da.required_parameters() == [da.CLIENT_SECRET_PARAM]


def test_precheck_checks_every_configured_key_with_kms_before_any_write(cfg_files, monkeypatch):
    kms = v.FakeKms()
    monkeypatch.setitem(da._CLIENTS, "kms", kms)
    monkeypatch.setitem(da._CLIENTS, "ssm", FakeSSM(present={da.CLIENT_SECRET_PARAM}))
    da.precheck()
    assert {c[1] for c in kms.calls if c[0] == "describe_key"} == {v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.CONSOLE_KID]}


def test_precheck_refuses_a_key_whose_fingerprint_is_not_the_configured_one(cfg_files, monkeypatch):
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    monkeypatch.setitem(da._CLIENTS, "kms", kms)
    monkeypatch.setitem(da._CLIENTS, "ssm", FakeSSM(present={da.CLIENT_SECRET_PARAM}))
    with pytest.raises(SystemExit, match="console-rs-v1"):
        da.precheck()


def test_lambda_env_has_no_hs_keys_and_ships_the_fixture_switch(cfg_files):
    env = da.lambda_env()["Variables"]
    for gone in ("JWT_SECRET_PARAM", "LEGACY_ENTRY", "SESSION_SIGNER"):
        assert gone not in env, gone
    assert env["FIXTURE_ISSUER"] == "off"
    rows = json.loads(env["SESSION_KEYS_JSON"])
    assert set(rows) == {"site", "console"}
    assert rows["site"][0] == {"kid": "site-rs-v1", "alg": "RS256", "role": "current",
                               "key_arn": v.KEY_ARN[v.SITE_KID], "spki_sha256": v.spki_hex(v.SITE_KEY)}


def test_role_grants_kms_sign_with_both_conditions_and_get_public_key_on_exact_key_arns(cfg_files, monkeypatch):
    iam = Recorder()
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    da.ensure_lambda_role()
    doc = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])
    by_sid = {s["Sid"]: s for s in doc["Statement"]}
    sign = by_sid["SignSessionTokens"]
    assert sign["Action"] == "kms:Sign"
    assert sorted(sign["Resource"]) == sorted([v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.CONSOLE_KID]])
    assert sign["Condition"] == {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                                  "kms:MessageType": "RAW"}}
    pub = by_sid["ReadSessionPublicKeys"]
    assert pub["Action"] == "kms:GetPublicKey" and sorted(pub["Resource"]) == sorted(sign["Resource"])
    ssm_res = by_sid["ReadPlatformSecrets"]["Resource"]
    assert ssm_res == [f"arn:aws:ssm:us-east-1:111111111111:parameter{LOGIN_FLOW_PARAM}",
                       f"arn:aws:ssm:us-east-1:111111111111:parameter{da.CLIENT_SECRET_PARAM}"]
    assert not any("*" in r for r in sign["Resource"] + pub["Resource"] + ssm_res)


def test_verification_off_means_no_role_no_statements_and_switch_off(cfg_files, monkeypatch):
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, _ = _run_main(monkeypatch, ssm)
    assert _CONVERGE_CALLS == [(lam, da.FN, "arn:aws:iam::111111111111:role/site-edge-role", None)]
    assert "create_role" not in iam.calls or all(kw.get("RoleName") != da.VERIFIER_ROLE_NAME
                                                 for kw in [iam.kwargs.get("create_role", {})])


def test_verification_on_creates_the_verifier_role_and_passes_it_to_converge(tmp_path, monkeypatch):
    p = tmp_path / "config.ini"; p.write_text(CFG_FIXTURE)
    c = configparser.ConfigParser(); c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p); monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, _ = _run_main(monkeypatch, ssm)
    verifier_arn = f"arn:aws:iam::111111111111:role/{da.VERIFIER_ROLE_NAME}"
    assert _CONVERGE_CALLS[-1][3] == {"verifier": verifier_arn}
    trust = json.loads(iam.kwargs["update_assume_role_policy"]["PolicyDocument"]) if "update_assume_role_policy" in iam.kwargs \
        else json.loads(iam.kwargs["create_role"]["AssumeRolePolicyDocument"])
    assert sorted(trust["Statement"][0]["Principal"]["AWS"]) == ["arn:aws:iam::111111111111:role/ci",
                                                                  "arn:aws:iam::111111111111:user/kent"]
    pol = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])       # 最后一次 put_role_policy 是 verifier 的
    acts = {s["Action"] for s in pol["Statement"]}
    assert acts == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}
    assert all(s["Resource"] == f"arn:aws:lambda:us-east-1:111111111111:function:{da.FN}" for s in pol["Statement"])
    assert "3600" in json.dumps(iam.kwargs.get("update_role", iam.kwargs.get("create_role", {})))
    assert da.lambda_env()["Variables"]["FIXTURE_ISSUER"] == "on"


@pytest.mark.parametrize("bad", ["", "arn:aws:iam::111111111111:role/*", "*", "kent",
                                 "arn:aws:iam::222222222222:user/kent"])
def test_verification_on_with_a_bad_principal_list_aborts_before_any_write(tmp_path, monkeypatch, bad):
    p = tmp_path / "config.ini"
    p.write_text(CFG.replace("fixture_issuer = false", "fixture_issuer = true")
                 .replace("verifier_trusted_principals =", f"verifier_trusted_principals = {bad}"))
    c = configparser.ConfigParser(); c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p); monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
    with pytest.raises(SystemExit, match="verifier_trusted_principals"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []


def test_verification_turned_off_deletes_an_existing_verifier_role(cfg_files, monkeypatch):
    iam = Recorder()          # get_role 命中 ⇒ 角色"存在"
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    assert da.ensure_verifier_role(iam, da.Verification(False, ()), account="111111111111", region="us-east-1") is None
    assert "delete_role_policy" in iam.calls and "delete_role" in iam.calls
    assert iam.calls.index("delete_role_policy") < iam.calls.index("delete_role")
```

`_run_main` 的 converge 记录器改为四元组 `(client, fn, arn, kwargs.get("extra_principals"))`：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    monkeypatch.setattr(da, "converge_function_url_policy",
                        lambda client, fn, arn, **kw: _CONVERGE_CALLS.append((client, fn, arn, kw.get("extra_principals"))) or _DriftStub())
```

并在 `_run_main` 里 `monkeypatch.setitem(da._CLIENTS, "kms", v.FakeKms())`。文件顶部 `import upgrade_code_vectors as v`（conftest 已把 `panel/tests` 放进 sys.path）。

- [ ] **Step 2: 跑红**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_deploy_auth_sequence.py -q -x`
Expected: 第一条就红（`load_session_keys` 拒绝 CFG——RS 配置已可加载，红在 `required_parameters()` 仍含 HS 参数或 `_CLIENTS["kms"]` 不存在）。

- [ ] **Step 3: 改 `deploy_auth.py`**

（a）import：`from session_keys import env_json, key_refs, kms_key_arns, load_session_keys, ssm_parameter_arns, ssm_parameter_names`；`import session_kms`；`from dataclasses import dataclass`。删 `legacy_entry` import 与 `JWT_SECRET_PARAM` 常量。

（b）client：`def _kms(): return _client("kms")`。

（c）`[Verification]`：

```python
VERIFIER_ROLE_NAME = "site-builder-verifier"
_PRINCIPAL_RE = re.compile(r"^arn:aws:iam::(\d{12}):(role|user)/[^*?]+$")


@dataclass(frozen=True)
class Verification:
    fixture_issuer: bool
    trusted_principals: tuple


def read_verification(c: configparser.ConfigParser, *, account: str) -> Verification:
    """`[Verification]`（spec §11.7）。段缺失 = 组件不存在（fixture_issuer=False）。开着时清单必须非空、每项都是
    **本账号**的精确 role/user ARN——通配会让"谁能签夹具会话"变成账号内任何人，而那是一条冒充路径。"""
    if not c.has_section("Verification"):
        return Verification(False, ())
    flag = c.get("Verification", "fixture_issuer", fallback="false").split("#")[0].strip().lower()
    if flag not in ("true", "false"):
        raise SystemExit(f"config.ini [Verification] fixture_issuer 必须是 true/false（当前 {flag!r}）")
    raw = c.get("Verification", "verifier_trusted_principals", fallback="").split("#")[0]
    principals = tuple(p.strip() for p in raw.split(",") if p.strip())
    if flag == "false":
        return Verification(False, ())
    bad = [p for p in principals if not _PRINCIPAL_RE.match(p) or _PRINCIPAL_RE.match(p).group(1) != account]
    if not principals or bad:
        raise SystemExit("config.ini [Verification] verifier_trusted_principals 必须是本账号精确 role/user ARN 的"
                         f"非空清单（不接受通配），拒绝部署（任何写都未发生）：坏项 {bad}，共 {len(principals)} 项")
    return Verification(True, principals)


def ensure_verifier_role(iam, verification: Verification, *, account: str, region: str):
    """`site-builder-verifier`（spec §11.7）：开 ⇒ 建 / 收敛并返回 ARN；关 ⇒ 存在则删并返回 None。
    信任策略只列显式 ARN，会话上限 1 小时；权限只有对 auth 函数的两条 invoke（与 edge role 同形）。"""
    fn_arn = f"arn:aws:lambda:{region}:{account}:function:{FN}"
    try:
        iam.get_role(RoleName=VERIFIER_ROLE_NAME)
        exists = True
    except iam.exceptions.NoSuchEntityException:
        exists = False
    if not verification.fixture_issuer:
        if exists:
            iam.delete_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyName="invoke-auth-function-url")
            iam.delete_role(RoleName=VERIFIER_ROLE_NAME)
            print(f"  [Verification] 已关闭：删除角色 {VERIFIER_ROLE_NAME}")
        return None
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": list(verification.trusted_principals)},
        "Action": "sts:AssumeRole"}]})
    if exists:
        iam.update_assume_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyDocument=trust)
        iam.update_role(RoleName=VERIFIER_ROLE_NAME, MaxSessionDuration=3600)
    else:
        # Description 别写"只许调 POST /fixture-session"：IAM 不能按 HTTP 路径限，Function URL 的 invoke 权限覆盖
        # 每一个路径；"只能打 /fixture-session"是 handler 里那道调用者检查的事，不是这个角色的边界。
        iam.create_role(RoleName=VERIFIER_ROLE_NAME, AssumeRolePolicyDocument=trust, MaxSessionDuration=3600,
                        Description="site-builder acceptance verifier - may invoke only the auth Function URL"
                                    " (any path); the /fixture-session restriction is enforced by the handler")
    iam.put_role_policy(RoleName=VERIFIER_ROLE_NAME, PolicyName="invoke-auth-function-url",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": _verifier_invoke_statements(fn_arn, verifier_arn)}))
    if not exists:
        import time; time.sleep(10)
    return f"arn:aws:iam::{account}:role/{VERIFIER_ROLE_NAME}"


def _verifier_invoke_statements(fn_arn: str, verifier_arn: str) -> list:
    """两条 invoke 语句的 Action 与 Condition **从共享渲染器推导**（Task 6 的
    `function_url_policy.expected_projection`，import 为 `function_url_projection`），不在这里手写第二份。

    `lambda:InvokeFunctionUrl` 配 `StringEquals lambda:FunctionUrlAuthType=AWS_IAM`，
    `lambda:InvokeFunction` 配 **`Bool lambda:InvokedViaFunctionUrl=true`**——操作符是 `Bool` 不是
    `StringEquals`，条件键也不同。identity 侧与 resource 侧的实际授权是两者求交，把第二条也写成
    `FunctionUrlAuthType` 看着很对，但那个键在 `InvokeFunction` 上不产生 ⇒ 条件永不满足 ⇒ verifier 调用 403，
    而两侧单测各自都绿。传 `verifier_arn` 只为过渲染器那条精确 role ARN 校验，Principal 由本函数丢弃
    （identity policy 没有 Principal）。
    """
    out = []
    for _sid, (_effect, action, _principal, triples) in function_url_projection(verifier_arn).items():
        cond: dict = {}
        for op, key, val in triples:
            cond.setdefault(op, {})[key] = val
        sid = "InvokeAuthUrl" if action == "lambda:InvokeFunctionUrl" else "InvokeAuthViaUrl"
        out.append({"Sid": sid, "Effect": "Allow", "Action": action, "Resource": fn_arn, "Condition": cond})
    return out
```

（执行时修订，见 SDD ledger Task 7 review Important 1 + Ruling R15：plan 原文把两条语句都写成
`StringEquals lambda:FunctionUrlAuthType`，第二条的条件键错 ⇒ 部署出去 verifier 必 403；且那是
`function_url_policy` 已有形态的第二份手抄。修法要求从渲染器派生，并对两条 `Condition` 逐字断言。
`Description` 同时改掉"只许调 POST /fixture-session"那句——IAM 不能按路径限，路径限制由 handler 里的
调用者检查执行。）

（d）`lambda_env()`：删 `LEGACY_ENTRY` / `SESSION_SIGNER` / `JWT_SECRET_PARAM` 三处；`"SESSION_KEYS_JSON": env_json(keys, ("site", "console"))` 不变；加 `"FIXTURE_ISSUER": "on" if read_verification(cfg(), account=cfg()["Platform"]["account_id"]).fixture_issuer else "off"`。docstring 里 "JWT_SECRET 泄漏尤其致命…" 那段改为一句"会话签名密钥在 KMS 里，环境变量只有 kid / key_arn / spki_sha256"。

（e）`required_parameters()`：

```python
def required_parameters() -> list:
    """部署前必须已存在的 SSM 参数：只剩 deploy_pool 建的 site client secret。login-flow 由本脚本 ensure（ADR 0004，
    只有 auth 一个消费方，排除是安全的）；会话签名密钥在 KMS，由 precheck() 里的 session_kms.precheck_keys 四项校验。"""
    keys = load_session_keys(CFG_PATH)
    return [p for p in ssm_parameter_names(keys, ("site", "console"), login_flow=True, extra=(CLIENT_SECRET_PARAM,))
            if p != keys.login_flow_secret_param]


def precheck() -> None:
    """第一次写之前：SSM 参数存在 + 每个 RS kid 的 KMS 四项（spec §11.6 第 1 层 / §11.8.12）。只读、不打印值。"""
    precheck_parameters(required_parameters(), ssm=_ssm(), hint="client secret 由 scripts/deploy_pool.py 创建；先跑它。")
    session_kms.precheck_keys(_kms(), key_refs(load_session_keys(CFG_PATH), ("site", "console")))
```

（f）`ensure_lambda_role()` 的 PolicyDocument：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        keys = load_session_keys(CFG_PATH)
        key_arns = kms_key_arns(keys, ("site", "console"))
        ... "Statement": [
            {"Sid": "ReadPlatformSecrets", "Effect": "Allow", "Action": "ssm:GetParameter",
             "Resource": ssm_parameter_arns(keys, ("site", "console"), region=region(),
                                            account=cfg()["Platform"]["account_id"],
                                            login_flow=True, extra=(CLIENT_SECRET_PARAM,))},
            {"Sid": "DecryptViaSSM", ...不变...},
            # 3c-final（spec §11.2 / ADR 0001）：kms:Sign 只经 identity policy 授、精确到两个 family 的 key ARN，
            # 两个条件把 §11.5 的合同钉进 IAM（零自锁风险）；GetPublicKey 给 verifier 冷启动与 signer 自检用。
            {"Sid": "SignSessionTokens", "Effect": "Allow", "Action": "kms:Sign", "Resource": key_arns,
             "Condition": {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                            "kms:MessageType": "RAW"}}},
            {"Sid": "ReadSessionPublicKeys", "Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": key_arns},
        ]
```

（g）`main()`：删 `if keys.legacy_param: ensure_secret(...)`；在 `edge_arn = edge_role_arn()` 之后加 `verification = read_verification(cfg(), account=cfg()["Platform"]["account_id"])`；`role_arn = ensure_lambda_role()` 之后加 `verifier_arn = ensure_verifier_role(_iam(), verification, account=cfg()["Platform"]["account_id"], region=region())`；converge 调用改为 `converge_function_url_policy(lam, FN, edge_arn, extra_principals={"verifier": verifier_arn} if verifier_arn else None)`。

（h）`test_main_source_calls_precheck_before_every_write_helper` 与 `test_main_validates_edge_role_after_precheck_and_before_the_first_write` 的写助手清单里加 `ensure_verifier_role`（源码顺序守卫会自动覆盖）。

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q --deselect tests/test_edge_new_form_vector.py --deselect tests/test_requirements_locked.py --deselect tests/test_verifier_allowlist.py::test_fixture_domain_matches_the_permissions_copy`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/auth/deploy_auth.py site-builder/auth/tests/test_deploy_auth_sequence.py
git commit -m "feat(asset-v1/08): deploy_auth——kms:Sign(两条件)+GetPublicKey 精确 ARN、KMS 四项 precheck、[Verification] 角色与 URL 语句、FIXTURE_ISSUER；删 legacy ensure 与 HS env"
```

---

### Task 8：panel——RS 验签 + KMS 签发、交叉装 `cryptography`、KMS IAM、admin 名单夹具域断言

**Files:**
- Create: `site-builder/panel/requirements.txt`
- Modify: `site-builder/panel/console_session.py`
- Modify: `site-builder/panel/deploy_panel.py`
- Modify: `site-builder/panel/tests/conftest.py`（ENV 与 `secret` 夹具 → `keys` 夹具）
- Modify: `site-builder/panel/tests/test_console_session.py`、`test_deploy_panel_contract.py`、`test_deploy_panel_sequence.py`、`test_handler.py`（用到 `secret` 夹具的地方）
- Modify: `site-builder/auth/tests/test_requirements_locked.py`（守卫扩到 `deploy_panel.py` 与 `panel/requirements.txt`）
- Test: panel 套件 + `auth/tests/test_requirements_locked.py`

**Interfaces:**
- Consumes: `session.verify_token / mint_token`、`session_kms.KmsSigner / public_key_loader / precheck_keys`、`verifier_env.load_allowlist / signing_ref`、`session_keys.env_json / key_refs / kms_key_arns`。
- Produces:
  - `console_session._kms()`、`_reset_signing()`（测试钩子）、`_console_allowlist()`、`_signer() -> tuple[str, Callable]`（console current）、`ensure_signing_material()`（= `_signer()[1].self_check()`）、`console_cookie(email, name)`、`consume_code`、`verify_console_cookie`；**删** `_secret` / `_secret_by_param` / `_legacy_secret` / `_signer_mode` / `_signing_key` / `SECRET_TTL_SECONDS` / `_secret_cache` / `CONSOLE_SCOPE`
  - `deploy_panel.COPY_FILES` += `"session_kms.py"`；`REQUIREMENTS = HERE / "requirements.txt"`；`_build_zip()` 先 pip 交叉装再加 `.py`
  - `deploy_panel.role_statements()`：**删** `ReadSessionKeysConsoleOnly` / `DecryptViaSSM`；**加** `SignConsoleTokens`（kms:Sign，console key ARN，两个条件）/ `ReadConsolePublicKeys`（kms:GetPublicKey）
  - `deploy_panel.lambda_environment()`：**删** `JWT_SECRET_PARAM` / `LEGACY_ENTRY` / `SESSION_SIGNER`
  - `deploy_panel.required_parameters() == []`；`precheck()` = `session_kms.precheck_keys(kms, key_refs(keys, ("console",)))`
  - `deploy_panel.assert_no_fixture_admins(ddb, table, admin_seed)`：`[Platform] admin_seed` 或 admins 表任一行是 `@e2e.invalid` ⇒ `SystemExit`（在 precheck 之后、任何写之前）

- [ ] **Step 1: `panel/requirements.txt`（从 auth 清单抽三包，hash 逐字节相同）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder"
{
  cat <<'HDR'
# panel Lambda 的**锁定**依赖清单（装时必须带 --require-hashes）。3c-final 起 panel 本地验 RS256
# （升级码与面板会话），所以要 cryptography；三包的版本与 hash **与 auth/requirements.txt 逐字节相同**
# （auth/tests/test_requirements_locked.py 钉住），重新生成时先改 auth 那份再把这三段抄过来。
# 交叉装法与 deploy_auth.build_zip 相同：--platform manylinux2014_x86_64 --only-binary :all: --python-version 3.13。
HDR
  awk '/^cffi==/,/^    # via/' auth/requirements.txt
  awk '/^cryptography==/,/^    # via/' auth/requirements.txt
  awk '/^pycparser==/,/^    # via/' auth/requirements.txt
} > panel/requirements.txt
grep -c -- '--hash=sha256' panel/requirements.txt    # > 0
```

（`awk` 的区间以每段后面的 `# via …` 注释行收尾；若 auth 清单里某段没有 `# via` 行，改用 `sed -n '/^cffi==/,/^[a-z]/p' | sed '$d'` 取到下一个包名之前。）

- [ ] **Step 2: 改 `panel/tests/conftest.py`（先红）**

`ENV` 里删 `JWT_SECRET_PARAM` / `LEGACY_ENTRY` / `SESSION_SIGNER`；`SESSION_KEYS_JSON` 改为 `upgrade_code_vectors.session_keys_json((CONSOLE_KID, "current"))`（顶部 `import upgrade_code_vectors as v`；文件所在目录已在 sys.path）。把 `secret` 夹具替换为：

```python
@pytest.fixture
def keys(monkeypatch):
    """把 panel 的 KMS 边界换成 vectors 的替身：公钥与签名都由 CONSOLE_KEY 算。返回 FakeKms 供用例看调用。"""
    import console_session
    kms = v.FakeKms()
    console_session._reset_signing()
    monkeypatch.setattr(console_session, "_kms", lambda: kms)
    yield kms
    console_session._reset_signing()
```

全仓 `panel/tests` 里 `secret` 夹具参数改名 `keys`（`grep -ln "secret)" panel/tests/*.py`），`from upgrade_code_vectors import MUTATIONS, SECRET` 改为 `from upgrade_code_vectors import RS_MUTATIONS as MUTATIONS`（`SECRET` 常量已删）。

- [ ] **Step 3: 改 `test_console_session.py`（先红）**

- `_code()` 类助手改用 `session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="console-upgrade", email=…, ttl_seconds=60)`；凡 `session.mint_upgrade_code(...)` / `mint_session_jwt(... scope="console")` 全换成 `v.console_session_token(session.mint_token, …)`。
- 删：`test_scope_must_be_console`、`test_secret_is_read_from_ssm_not_environment`、`test_secret_cache_has_a_ttl`、`test_legacy_entry_off_rejects_legacy_code_but_not_kid_form`、`test_console_cookie_keeps_the_legacy_wire_form_when_signer_is_legacy`、`test_console_cookie_keeps_the_host_prefix_trio_in_both_signer_modes`（改成单模式 `test_console_cookie_keeps_the_host_prefix_trio`）、`signer_current` 夹具。
- `test_console_cookie_uses_the_console_current_kid_when_signer_is_current` → 去掉后缀；header 断言 `{"alg": "RS256", "typ": "JWT", "kid": "console-rs-v1"}`。
- 新增：

```python
def test_public_keys_come_from_kms_by_arn_and_are_fingerprint_checked(aws, keys):
    console_session.verify_console_cookie(
        f"{console_session.CONSOLE_COOKIE}={v.console_session_token(session.mint_token)}", x_user_email="u@x.com")
    assert ("get_public_key", v.KEY_ARN[v.CONSOLE_KID]) in keys.calls
    assert not [c for c in keys.calls if c[0] == "sign"]


def test_verify_fails_closed_when_the_public_key_does_not_match_the_configured_fingerprint(aws, keys):
    import session_kms
    keys.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    console_session._reset_signing()
    with pytest.raises(session_kms.KeyMaterialMismatch):
        console_session.verify_console_cookie(
            f"{console_session.CONSOLE_COOKIE}={v.console_session_token(session.mint_token)}", x_user_email="u@x.com")


def test_console_cookie_is_signed_by_kms_with_the_console_key_only(aws, keys):
    c = console_session.console_cookie("u@x.com", "U")
    signs = [x for x in keys.calls if x[0] == "sign"]
    assert signs == [("sign", v.KEY_ARN[v.CONSOLE_KID], "RAW", "RSASSA_PKCS1_V1_5_SHA_256", signs[0][4])]
    tok = _cookie_token(c)
    assert session.verify_token(tok, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session")[1] == "accepted_current"


def test_ensure_signing_material_self_checks_without_signing(aws, keys):
    console_session.ensure_signing_material()
    assert [x[0] for x in keys.calls] == ["get_public_key"]
    console_session.console_cookie("u@x.com", "U")
    assert [x[0] for x in keys.calls] == ["get_public_key", "sign"], "自检只做一次，随后直接签"


def test_panel_never_touches_ssm(aws, monkeypatch):
    import os
    calls = []
    monkeypatch.setattr(boto3, "client", lambda svc, *a, **k: calls.append(svc) or type("C", (), {})())
    for gone in ("_secret", "_secret_by_param", "_legacy_secret", "_signer_mode", "_signing_key", "SECRET_TTL_SECONDS"):
        assert not hasattr(console_session, gone), gone
    assert "JWT_SECRET_PARAM" not in os.environ and "LEGACY_ENTRY" not in os.environ and "SESSION_SIGNER" not in os.environ
```

- [ ] **Step 4: 改 `test_deploy_panel_contract.py`（先红）**

- 删：`test_panel_role_ssm_resources_are_exact_arns_for_legacy_and_console_family_only`、`test_kms_decrypt_is_scoped_via_ssm`、`test_lambda_environment_ships_the_signer_switch_from_config_not_a_literal`、`test_panel_legacy_param_env_comes_from_session_keys_not_a_literal`、`test_l3_panel_env_drops_the_jwt_secret_param_key_entirely`、`test_before_l3_panel_env_still_ships_it`、`test_l3_panel_role_ssm_list_no_longer_carries_the_legacy_arn`、`test_env_coverage_still_catches_a_missing_var_while_legacy_is_on`、`test_panel_deploy_script_does_not_pass_login_flow_to_the_ssm_helper`（改为下面 `test_panel_has_no_ssm_statement_at_all`）。
- `test_environment_session_keys_json_has_only_the_console_family`：行键集合改 `{"kid", "alg", "role", "key_arn", "spki_sha256"}`；删 `LEGACY_ENTRY` 断言。
- `test_environment_has_no_plaintext_secret`：删 `JWT_SECRET_PARAM` 条件块；末尾 `get_parameter` 那条改为 `assert "get_parameter" not in src`（panel 不再读任何 SSM）。
- `test_panel_role_cannot_read_the_login_flow_secret` / `test_panel_environment_has_no_login_flow_secret_param` 保留。
- 新增：

```python
def test_panel_has_no_ssm_statement_at_all():
    assert not [s for s in dp.role_statements() if any(a.startswith("ssm:") or a == "kms:Decrypt" for a in _actions(s))], \
        "panel 不再读任何 SSM 参数；会话签名密钥在 KMS"


def test_panel_role_signs_and_reads_public_key_for_the_console_key_only():
    by_sid = {s["Sid"]: s for s in dp.role_statements()}
    sign, pub = by_sid["SignConsoleTokens"], by_sid["ReadConsolePublicKeys"]
    assert sign["Action"] == "kms:Sign" and sign["Resource"] == [v.KEY_ARN[v.CONSOLE_KID]]
    assert sign["Condition"] == {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256", "kms:MessageType": "RAW"}}
    assert pub["Action"] == "kms:GetPublicKey" and pub["Resource"] == [v.KEY_ARN[v.CONSOLE_KID]]
    assert not any("site" in r for r in sign["Resource"] + pub["Resource"])


def test_copy_files_include_the_kms_module_and_the_zip_vendors_cryptography(monkeypatch):
    assert "session_kms.py" in dp.COPY_FILES
    src = (PANEL / "deploy_panel.py").read_text()
    body = src[src.index("def _build_zip"):src.index("\ndef ", src.index("def _build_zip") + 10)]
    for flag in ("--require-hashes", "--platform", "manylinux2014_x86_64", "--only-binary", "--python-version", "3.13"):
        assert flag in body, flag
    assert "requirements.txt" in body


def test_panel_requirements_pin_the_same_cryptography_closure_as_auth():
    import re
    def pins(p):
        return dict(re.findall(r"^([a-zA-Z0-9_-]+)==([^ \\]+)", p.read_text(), re.M))
    panel, auth = pins(PANEL / "requirements.txt"), pins(PANEL.parent / "auth" / "requirements.txt")
    assert set(panel) == {"cffi", "cryptography", "pycparser"}
    assert all(auth[k] == vv for k, vv in panel.items()), (panel, {k: auth.get(k) for k in panel})


def test_required_parameters_is_empty_and_precheck_hits_kms(monkeypatch):
    assert dp.required_parameters() == []
    kms = v.FakeKms()
    monkeypatch.setattr(dp, "_kms", lambda: kms)
    dp.precheck()
    assert {c[1] for c in kms.calls if c[0] == "describe_key"} == {v.KEY_ARN[v.CONSOLE_KID]}


def test_deploy_refuses_a_fixture_domain_admin_seed_or_admin_row(aws, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    dp.assert_no_fixture_admins(ddb, "site-admins", "ops@example.test")        # 干净：不抛
    with pytest.raises(SystemExit, match="e2e.invalid"):
        dp.assert_no_fixture_admins(ddb, "site-admins", "probe@e2e.invalid")
    ddb.put_item(TableName="site-admins", Item={"email": {"S": "x@e2e.invalid"}})
    with pytest.raises(SystemExit, match="e2e.invalid"):
        dp.assert_no_fixture_admins(ddb, "site-admins", "ops@example.test")
```

`_expected_panel_ssm_suffixes` 等只服务已删用例的助手一并删。`test_deploy_panel_sequence.py` 里若有对 `precheck` 用 FakeSSM 的用例，改成 monkeypatch `dp._kms`。

（执行时修订：原文这里还有一条"`deployer/tests/test_redeploy_targets.py::test_vendor_map_matches_the_hardcoded_snapshot` 的快照加 `session_kms.py → {auth, panel}`"——**那条是错的，不要做**。`which_targets_to_redeploy.vendor_map()` 的键只来自 `deployer/functions/*.py`（deployer 打整个目录，三份复制清单再往上加组件），而 `session_kms.py` 住在 `auth/`，永远不会出现在那张表里；`auth` / `panel` 的牵连由 `DIR_RULES` 的目录规则给。见 SDD ledger Task 8 记录。另外本 Step 顺带补了 `deploy_panel.CFG_PATH` 与 conftest 的 `rs_config` 夹具——panel 的 deploy 类测试不得依赖 gitignored 的真 config。）

- [ ] **Step 5: `auth/tests/test_requirements_locked.py` 扩到 panel（先红）**

```python
PANEL_DIR = Path(__file__).parents[2] / "panel"
PANEL_REQ = PANEL_DIR / "requirements.txt"
DEPLOY_PANEL = PANEL_DIR / "deploy_panel.py"


def test_panel_every_package_is_pinned_and_hashed():
    _assert_all_pinned_and_hashed(PANEL_REQ)      # 与 test_auth_every_package_is_pinned_and_hashed 同一个助手


def test_deploy_panel_installs_with_require_hashes():
    """与 test_deploy_auth_installs_with_require_hashes 同一套截获真实 pip argv 的做法，对象换成 deploy_panel._build_zip。"""
    ...
```

按文件里 `test_deploy_auth_installs_with_require_hashes` 的实现复制一份（它 patch `subprocess.run` 截获 argv 并断言含 `--require-hashes` / `--platform manylinux2014_x86_64` / `--only-binary :all:` / `--python-version 3.13` / `-r <requirements.txt>`），把 `da.build_zip` 换成 `dp._build_zip`（按路径加载 `deploy_panel.py`，避免 import 期读 config：`_load_deploy_module` 的做法在 `verify_deployed_components.py` 有现成写法）。

- [ ] **Step 6: 改 `console_session.py`**

```python
import os
import time
from datetime import datetime, timezone

import boto3

import session
import session_kms
import verifier_env

CONSOLE_COOKIE = "__Host-sb_console"
CONSOLE_TTL_SECONDS = 4 * 3600
CONSUMED_TTL_SECONDS = 3600
WRITE_METHODS = ("PUT", "POST", "DELETE")

_kms_client = None
_public_key = None
_SIGNER = None            # console current 的 KmsSigner（容器复用：自检只做一次）


def _kms():
    global _kms_client
    if _kms_client is None:
        _kms_client = boto3.client("kms", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _kms_client


def _reset_signing() -> None:
    """测试钩子：换掉 _kms() 后清掉缓存的公钥加载器与 signer。"""
    global _public_key, _SIGNER
    _public_key = None
    _SIGNER = None


def _get_public_key(key_arn: str, spki_sha256: str):
    global _public_key
    if _public_key is None:
        _public_key = session_kms.public_key_loader(_kms())
    return _public_key(key_arn, spki_sha256)


def _console_allowlist() -> dict:
    """panel 自己那份 allowlist：**只有 console family**（spec §4.3）。公钥按 key_arn 取、与 spki_sha256 核对。"""
    return verifier_env.load_allowlist(os.environ.get("SESSION_KEYS_JSON"), "console", _get_public_key,
                                       allowed_families=("console",))


def _signer() -> tuple:
    """→ (kid, sign)：console family 的 current。**panel 只签面板会话，只碰 console family。**
    与 auth 同形（tests/test_signer_guard.py 按路径读本文件）。"""
    global _SIGNER
    kid, key_arn, spki = verifier_env.signing_ref(os.environ.get("SESSION_KEYS_JSON"), "console",
                                                  allowed_families=("console",))
    if _SIGNER is None or _SIGNER.key_arn != key_arn:
        _SIGNER = session_kms.KmsSigner(_kms(), key_arn, spki)
    return kid, _SIGNER
```

`_log_verify` / `_codes_table` 不变；`consume_code` 与 `verify_console_cookie` 里的 `session.verify_with_legacy(…, legacy_secret=…)` 改为 `session.verify_token(code or "", allowlist=_console_allowlist(), token_use="console-upgrade")` / `session.verify_token(token, allowlist=_console_allowlist(), token_use="console-session")`；

```python
def ensure_signing_material() -> None:
    """签发前把材料取一遍（3i）：解析 SESSION_KEYS_JSON、构造 signer、做一次 GetPublicKey 自检。**不签发**。"""
    _signer()[1].self_check()


def console_cookie(email: str, name: str) -> str:
    kid, sign = _signer()
    token = session.mint_token(kid=kid, sign=sign, token_use="console-session",
                               email=email, ttl_seconds=CONSOLE_TTL_SECONDS, name=name)
    return (f"{CONSOLE_COOKIE}={token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={CONSOLE_TTL_SECONDS}")
```

模块 docstring 里"密钥：环境变量只有参数名 JWT_SECRET_PARAM…"那段改为"密钥：会话签名 key 在 KMS；环境变量只有 kid / key_arn / spki_sha256，公钥运行时取、指纹核对后才用"。

- [ ] **Step 7: 改 `deploy_panel.py`**

- `COPY_FILES = ("common.py", "permissions.py", "ops_log.py", "session.py", "verifier_env.py", "session_kms.py", …其余不变…)`；`REQUIREMENTS = HERE / "requirements.txt"`。
- `_build_zip()`：在 `try:` 之前建 `td = tempfile.mkdtemp()` 并 `subprocess.run(["python3", "-m", "pip", "install", "--require-hashes", "-r", str(REQUIREMENTS), "-t", td, "-q", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:", "--python-version", RUNTIME.replace("python", "")], check=True)`；zip 先写 `td` 下全部文件（`for p in Path(td).rglob("*"): if p.is_file(): z.write(p, p.relative_to(td))`），再写 `.py`；`finally` 里 `shutil.rmtree(td, ignore_errors=True)`。`import subprocess, tempfile`。
- `role_statements()`：删 `ReadSessionKeysConsoleOnly` 与 `DecryptViaSSM` 两条；在列表开头加

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        # 3c-final（spec §11.2 / ADR 0001）：panel 只签面板会话 ⇒ 只对 console family 的 key 有 kms:Sign；
        # 两个条件把 §11.5 的合同钉进 IAM；GetPublicKey 给验签冷启动与 signer 自检用。
        {"Sid": "SignConsoleTokens", "Effect": "Allow", "Action": "kms:Sign", "Resource": console_keys,
         "Condition": {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                        "kms:MessageType": "RAW"}}},
        {"Sid": "ReadConsolePublicKeys", "Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": console_keys},
```

其中 `console_keys = kms_key_arns(load_session_keys(HERE.parent / "config.ini"), ("console",))`；import 改为 `from session_keys import env_json, key_refs, kms_key_arns, load_session_keys`。docstring 里"SSM：精确 jwt-secret ARN…"那条删。
- `lambda_environment()`：删 `LEGACY_ENTRY` / `SESSION_SIGNER` / `JWT_SECRET_PARAM` 三处。
- `required_parameters()` 返回 `[]`（docstring：panel 不读 SSM）；`precheck()`：`session_kms.precheck_keys(_kms(), key_refs(load_session_keys(HERE.parent / "config.ini"), ("console",)))`；`def _kms(): return boto3.client("kms", region_name=_region())`；`import session_kms`（`sys.path` 已含 auth 目录——文件顶部 `sys.path.insert(0, str(HERE.parent / "auth"))` 已有，若无则加）。
- 新增：

```python
def assert_no_fixture_admins(ddb, admins_table: str, admin_seed: str) -> None:
    """ADR 0002：管理员名单里不许有夹具域邮箱（夹具会话能到 console，但绝不能是 admin）。
    读 [Platform] admin_seed 与 admins 表（Scan 一张几十行的小表），任一命中即拒绝部署——在任何写之前。"""
    from permissions import FIXTURE_DOMAIN, is_fixture_email
    bad = []
    if is_fixture_email(admin_seed):
        bad.append(f"[Platform] admin_seed={admin_seed}")
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=admins_table, ProjectionExpression="email"):
        for it in page.get("Items", []):
            e = it.get("email", {}).get("S", "")
            if is_fixture_email(e):
                bad.append(f"admins 表：{e}")
    if bad:
        raise SystemExit(f"管理员名单不许含夹具域 @{FIXTURE_DOMAIN}（ADR 0002），拒绝部署（任何写都未发生）：{bad}")
```

`main()` 里 `precheck()` 之后、`①` 之前调用：`assert_no_fixture_admins(boto3.client("dynamodb", region_name=_region()), "site-admins", _cfg("Platform", "admin_seed", ""))`。（`permissions.is_fixture_email` 在 Task 9 才有——本 Task 里 panel 套件那条 admin 用例红到 Task 9；其余绿。）

- [ ] **Step 8: 跑绿**

Run: `cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`；`cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_requirements_locked.py tests/test_signer_guard.py -q`
Expected: panel 除 `test_deploy_refuses_a_fixture_domain_admin_seed_or_admin_row`（Task 9）外全绿；auth 两文件全绿（`test_deploy_panel_installs_with_require_hashes` 会真的调 pip？——不会：它 patch 了 `subprocess.run`）。

- [ ] **Step 9: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/panel site-builder/auth/tests/test_requirements_locked.py
git commit -m "feat(asset-v1/08): panel 切 KMS 签发与 RS 验签（交叉装 cryptography、hash 与 auth 同一份）；KMS IAM 精确 ARN；删 SSM 读取与 legacy/signer 开关；部署拒夹具域管理员"
```

---

### Task 9：`permissions.py`——夹具域不得越界（write_permissions / add_admin）

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py`
- Modify: `site-builder/deployer/tests/test_permissions.py`（追加）
- Test: `deployer/tests/test_permissions.py`、`panel/tests/test_deploy_panel_contract.py`、`auth/tests/test_verifier_allowlist.py::test_fixture_domain_matches_the_permissions_copy`

**Interfaces:**
- Produces: `permissions.FIXTURE_DOMAIN = "e2e.invalid"`；`permissions.is_fixture_email(email) -> bool`（精确域，大小写敏感）；`permissions.site_is_fixture(site) -> bool`（owner 的域）；`write_permissions` 在**非夹具站点**上遇到夹具域的 `new_owner` / `collaborators` / `allowed_users`（list）任一项 ⇒ `PolicyDataInvalid`（读到 site 行之后、构造事务之前，零副作用）；`add_admin` 对夹具域 ⇒ `ValueError`

- [ ] **Step 1: 追加用例（先红）**

```python
# ---- ADR 0002：夹具域邮箱只能出现在夹具站点上；永不做管理员 ----

FIX = "probe@e2e.invalid"


def test_fixture_domain_constant_and_predicates():
    assert perm.FIXTURE_DOMAIN == "e2e.invalid"
    assert perm.is_fixture_email(FIX) and not perm.is_fixture_email("a@example.com")
    assert not perm.is_fixture_email("a@e2e.invalid.evil") and not perm.is_fixture_email("a@E2E.INVALID")
    assert perm.site_is_fixture({"owner": FIX}) and not perm.site_is_fixture({"owner": "o@x.com"}) and not perm.site_is_fixture({})


def _seed_site(owner="o@x.com", site_id="s-fx"):
    import boto3, os
    boto3.client("dynamodb", region_name="us-east-1").put_item(
        TableName=os.environ["SITES_TABLE"],
        Item={"site_id": {"S": site_id}, "owner": {"S": owner}, "status": {"S": "ACTIVE"}, "tier": {"S": "static"},
              "require_login": {"BOOL": True}, "allowed_users": {"S": "org"}, "collaborators": {"L": []},
              "permissions_rev": {"N": "1"}})
    return site_id


@pytest.mark.parametrize("kw", [
    {"collaborators": [FIX]},
    {"allowed_users": ["a@x.com", FIX]},
    {"new_owner": FIX},
])
def test_fixture_email_may_not_enter_a_non_fixture_site(aws, kw):
    site_id = _seed_site()
    with pytest.raises(perm.PolicyDataInvalid, match="e2e.invalid"):
        perm.write_permissions(site_id, actor="o@x.com", action="set_collaborators" if "collaborators" in kw
                               else ("transfer_owner" if "new_owner" in kw else "set_access_policy"), **kw)
    item = perm._site_or_raise(site_id, consistent=True)
    assert item.get("permissions_rev") == 1 and FIX not in json.dumps(item, default=str), "拒绝必须零副作用"


def test_fixture_site_may_hold_fixture_emails(aws):
    site_id = _seed_site(owner=FIX)
    out = perm.write_permissions(site_id, actor=FIX, action="set_access_policy",
                                 allowed_users=[FIX, "visitor@e2e.invalid"])
    assert sorted(out["allowed_users"]) == ["probe@e2e.invalid", "visitor@e2e.invalid"]


def test_fixture_site_may_not_be_transferred_to_a_real_owner_either(aws):
    """反向也拒：把夹具站点转给真实邮箱，会让一个由验收工具建的站点变成"真实站点"而 allowed_users 里还留着夹具账号。"""
    site_id = _seed_site(owner=FIX)
    with pytest.raises(perm.PolicyDataInvalid, match="e2e.invalid"):
        perm.write_permissions(site_id, actor=FIX, action="transfer_owner", new_owner="real@x.com")


def test_add_admin_refuses_fixture_domain(aws):
    with pytest.raises(ValueError, match="e2e.invalid"):
        perm.add_admin(FIX, added_by="t")
    assert not perm.is_admin(FIX)
```

（`_site_or_raise` 与 `write_permissions` 的返回形态以文件里现有用例 `test_write_permissions_updates_both_tables_atomically` 的写法为准；`action` 名取 `CAPABILITIES` 里的真实键。）

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q -x -k fixture`
Expected: `AttributeError: module 'permissions' has no attribute 'FIXTURE_DOMAIN'`。

- [ ] **Step 3: 实现**

在 `EMAIL_RE` 之后加：

```python
# ---- 夹具身份（spec §11.7 / ADR 0002）--------------------------------------------------------
# 与 auth/session.py 的 FIXTURE_DOMAIN 是同一个字面量（auth 单测钉住等值）。夹具会话能进 console（Edge 放行
# 平台路由），所以 panel 侧必须由**数据层**保证：夹具域邮箱只能出现在夹具站点（owner 是夹具域）的权限字段里，
# 且永不是管理员。这两条让夹具会话的危害上限是"夹具站点"，而不是"全组织"。
FIXTURE_DOMAIN = "e2e.invalid"


def is_fixture_email(email) -> bool:
    return isinstance(email, str) and email.count("@") == 1 and email.split("@")[1] == FIXTURE_DOMAIN


def site_is_fixture(site: dict | None) -> bool:
    """夹具站点的标记就是 owner 的域（ensure_fixture_site.py 与闸门"站点形状"层用同一条规则）。"""
    return is_fixture_email((site or {}).get("owner"))
```

`write_permissions` 里，在 `effective = effective_policy_audited(site, actor=actor)` 之后、`sets = [...]` 之前加：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    # ADR 0002：夹具域不得越界。**位置**与 M02 那条相同——读到 site 行之后、构造事务之前 ⇒ 抛错时零副作用。
    fixture_site = site_is_fixture(site)
    incoming = list(collaborators or []) + (list(allowed_users) if isinstance(allowed_users, list) else []) \
        + ([new_owner] if new_owner is not None else [])
    if not fixture_site and any(is_fixture_email(e) for e in incoming):
        raise PolicyDataInvalid(f"站点 {site_id} 不是夹具站点，不许把 @{FIXTURE_DOMAIN} 的邮箱写进权限字段（ADR 0002）")
    if fixture_site and new_owner is not None and not is_fixture_email(new_owner):
        raise PolicyDataInvalid(f"夹具站点 {site_id} 不许转给非 @{FIXTURE_DOMAIN} 的 owner（ADR 0002）")
```

`add_admin` 里 `EMAIL_RE.fullmatch` 之后加 `if is_fixture_email(email): raise ValueError(f"夹具域 @{FIXTURE_DOMAIN} 的邮箱不能做管理员（ADR 0002）: {email!r}")`。

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py tests/test_seed_admin.py -q`；`cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`；`cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_verifier_allowlist.py -q`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/deployer/functions/permissions.py site-builder/deployer/tests/test_permissions.py
git commit -m "feat(asset-v1/08): permissions——夹具域邮箱只许出现在夹具站点、永不做管理员（ADR 0002 的数据层边界）"
```

---

### Task 10：Edge `origin_request.py`——RS256 验签（vendored cryptography）、`spki_b64` allowlist、黄金预热、夹具边界；删 legacy/HMAC

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py`
- Modify: `router/infrastructure/lambda/edge_substitutions.py`
- Modify: `router/infrastructure/lambda/test_edge_kid_allowlist.py`（重写）、`test_edge_auth.py`、`test_edge_lazy_config.py`、`test_edge_access_log.py` / `test_origin_request.py` / `test_edge_route_cache.py`（只改 token 生成助手）
- Modify: `router/infrastructure/lambda/test_edge_substitutions.py`（**执行时补进清单**：它的元用例按名字引用 `edge_substitutions.DEFAULTS` 里已删的 `JWT_SECRET` / `LEGACY_ENTRY` 键，Step 2 改完 DEFAULTS 后它必红）
- Modify: `site-builder/panel/tests/test_frontend_contract.py`、`site-builder/deployer/tests/test_migrate_permissions.py`（它们经 `edge_substitutions` 加载 Edge——只需确认不再传 `JWT_SECRET` / `LEGACY_ENTRY`）
- Test: router 套件（`cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`）+ `auth/tests/test_edge_new_form_vector.py`

**Interfaces:**
- Consumes: `cryptography`（deployer venv 49.0.0 供测试；产物由 Task 11 交叉装 50.0.0）。
- Produces（stack.py、verify_deployed_edge.sh、闸门依赖）:
  - 注入点：`{{SITE_ALLOWLIST_JSON}}`（`kid -> {"alg": "RS256", "spki_b64": <base64 DER SPKI>, "role"}`）；**删** `{{JWT_SECRET}}` / `{{LEGACY_ENTRY}}`
  - 模块级：`RS256_GOLDEN`（与 `session.RS256_GOLDEN` 字面相同）、`FIXTURE_DOMAIN / FIXTURE_IDP / FIXTURE_AUTH_VIA`（与 session.py 相同）、import 期一次黄金验签
  - `_site_allowlist() -> dict`（首次使用解析 JSON 并 `_load_public_key_der`，缓存）
  - `_verify_site_session(token) -> tuple[claims | None, outcome]`（与 `session.verify_token` 判定段字节等价，token_use 固定 `site-session`）；`_verify_session_jwt(token) -> claims | None`（不变）
  - `_check_auth`：新增夹具分支（`auth_via == FIXTURE_AUTH_VIA` 或 `idp == FIXTURE_IDP` ⇒ 两者必须同时为夹具值，且路由必须是平台路由或 owner 域为夹具域，否则 302）
  - `edge_substitutions.DEFAULTS`：`SITE_ALLOWLIST_JSON` 用 `upgrade_code_vectors.SITE_KEY` 的 SPKI；**删** `JWT_SECRET` / `LEGACY_ENTRY`

- [ ] **Step 1: 重写 `test_edge_kid_allowlist.py`（先红）**

```python
"""Edge 内嵌 verifier 认 site family 的 RS256 allowlist（3c-final）：正向跨组件向量、spec §9 负例矩阵、
夹具边界（ADR 0002）、与 auth/session.py 的字节等价守卫。"""
import base64
import json
import logging
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "auth"))
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import edge_substitutions as es  # noqa: E402
import session as auth_session  # noqa: E402
import upgrade_code_vectors as v  # noqa: E402

SRC = es.EDGE_SRC_PATH.read_text(encoding="utf-8")
ALLOWLIST = {v.SITE_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"},
             v.SITE_PREV_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_PREV_KEY), "role": "previous"}}
orq = es.load_edge_module("_edge_kid_testable", write_to=HERE, SITE_ALLOWLIST_JSON=json.dumps(ALLOWLIST))

ROUTE = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x", "api_target": "",
         "require_auth": True, "allowed_users": "org", "owner": "o@example.test"}
FIXTURE_ROUTE = {**ROUTE, "subdomain": "app-e2e-probe", "site_id": "e2e-probe", "owner": "probe@e2e.invalid",
                 "allowed_users": ["probe@e2e.invalid"]}
CONSOLE_ROUTE = {"subdomain": "console", "site_id": "console", "static_prefix": "platform/console/v",
                 "api_target": "https://p.lambda-url.us-east-1.on.aws", "route_mode": "split",
                 "require_auth": True, "allowed_users": "org", "owner": "platform", orq._PLATFORM_KEY: True}


def _req(token: str, host="app-x.example.com"):
    return {"uri": "/", "querystring": "", "method": "GET",
            "headers": {"host": [{"key": "Host", "value": host}],
                        "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}


def allowed(mod, token: str, route=None, host="app-x.example.com") -> bool:
    return mod._check_auth(_req(token, host), dict(route or ROUTE), host) is None


def site_token(**kw) -> str:
    args = dict(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="site-session", email="v@example.test",
                ttl_seconds=600, name="V", idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    args.update(kw)
    return auth_session.mint_token(**args)


def fixture_token(email="probe@e2e.invalid", **kw) -> str:
    return site_token(email=email, idp="fixture", auth_via="fixture-issuer", **kw)


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def resign(token: str, key, *, header=None, payload=None) -> str:
    h, p, _ = token.split(".")
    h2 = b64(header) if header is not None else h
    p2 = b64(payload) if payload is not None else p
    sig = v.signer(key)(f"{h2}.{p2}".encode())
    return f"{h2}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


# ---- 正向 ----

def test_auth_minted_current_kid_token_verifies_at_the_edge():
    claims = orq._verify_session_jwt(site_token())
    assert claims and claims["email"] == "v@example.test"


def test_auth_minted_previous_kid_token_verifies_at_the_edge():
    assert allowed(orq, site_token(kid=v.SITE_PREV_KID, sign=v.signer(v.SITE_PREV_KEY)))


def test_verify_function_keeps_its_contract_for_check_auth():
    assert orq._verify_session_jwt("garbage") is None
    assert isinstance(orq._verify_session_jwt(site_token()), dict)


# ---- spec §9 负例 ----

def test_console_kid_is_not_in_the_edge_allowlist():
    tok = auth_session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="site-session",
                                  email="v@example.test", ttl_seconds=600, idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    assert not allowed(orq, tok)


def test_unknown_kid_is_rejected():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": "site-rs-v7"}))


def test_missing_kid_is_rejected():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT"}))


def test_wrong_token_use_is_rejected():
    tok = auth_session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="console-session",
                                  email="v@example.test", ttl_seconds=600, name="V")
    assert not allowed(orq, tok)


def test_aud_as_list_is_rejected():
    claims = unb64(site_token().split(".")[1]); claims["aud"] = ["site-edge"]
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, payload=claims))


@pytest.mark.parametrize("alg", ["none", "None", "HS256", "RS512", "PS256"])
def test_alg_other_than_the_allowlisted_one_is_rejected(alg):
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": alg, "typ": "JWT", "kid": v.SITE_KID}))


def test_third_key_under_known_kid_is_rejected():
    assert not allowed(orq, site_token(sign=v.signer(v.CONSOLE_KEY)))     # header 说 site-rs-v1，签名是别的私钥


def test_expired_kid_token_is_rejected():
    assert not allowed(orq, site_token(ttl_seconds=-5))


def test_idp_and_auth_via_are_still_required_on_the_new_entry():
    assert not allowed(orq, site_token(idp="", auth_via=""))
    assert not allowed(orq, site_token(auth_via="TokenGeneration_Authentication"))


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_rs_mutation_vectors_at_the_edge(name, mutate, expect_reject):
    assert allowed(orq, mutate(site_token())) == (not expect_reject), name


def test_crit_header_is_rejected_even_with_a_valid_signature():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID, "crit": ["exp"]}))


def test_outcome_is_logged_as_fixed_vocabulary_without_the_token(caplog):
    with caplog.at_level(logging.INFO):
        tok = site_token()
        orq._verify_session_jwt(tok)
        orq._verify_session_jwt(resign(tok, v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": "nope"}))
    outcomes = [json.loads(r.getMessage())["outcome"] for r in caplog.records
                if r.getMessage().startswith("{") and '"session_verify"' in r.getMessage()]
    assert outcomes == ["accepted_current", "unknown_kid"]
    assert tok not in caplog.text and "accepted_legacy" not in caplog.text


# ---- 夹具边界（ADR 0002 / D6）----

def test_fixture_session_is_accepted_on_a_fixture_owned_route():
    assert allowed(orq, fixture_token(), FIXTURE_ROUTE, host="app-e2e-probe.example.com")


def test_fixture_session_is_accepted_on_the_console_platform_route():
    assert allowed(orq, fixture_token(), CONSOLE_ROUTE, host="console.example.com")


def test_fixture_session_is_redirected_on_a_real_org_route():
    """`allowed_users = "org"` 的真实站点放行任何可信邮箱——夹具会话必须在这里被 302，否则夹具签发器就是全组织的钥匙。"""
    resp = orq._check_auth(_req(fixture_token()), dict(ROUTE), "app-x.example.com")
    assert resp and resp["status"] == "302"


def test_fixture_session_on_a_real_route_that_lists_the_fixture_email_is_still_redirected():
    route = {**ROUTE, "allowed_users": ["probe@e2e.invalid"]}      # 数据层本该拒绝写入；Edge 独立再拒一次
    assert not allowed(orq, fixture_token(), route)


def test_fixture_marks_must_both_be_present_or_both_absent():
    assert not allowed(orq, site_token(idp="fixture"), FIXTURE_ROUTE, host="app-e2e-probe.example.com")
    assert not allowed(orq, site_token(auth_via="fixture-issuer"), FIXTURE_ROUTE, host="app-e2e-probe.example.com")


def test_a_real_idp_session_still_enters_a_fixture_site_when_listed():
    route = {**FIXTURE_ROUTE, "allowed_users": ["v@example.test"]}
    assert allowed(orq, site_token(), route, host="app-e2e-probe.example.com")


def test_fixture_domain_is_matched_exactly_on_the_owner():
    for owner in ("x@e2e.invalid.evil", "x@evil.e2e.invalid", "platform", "", "probe@E2E.INVALID"):
        assert not allowed(orq, fixture_token(), {**FIXTURE_ROUTE, "owner": owner}, host="app-e2e-probe.example.com"), owner


def test_fixture_literals_match_auth_session():
    assert (orq.FIXTURE_DOMAIN, orq.FIXTURE_IDP, orq.FIXTURE_AUTH_VIA) == \
        (auth_session.FIXTURE_DOMAIN, auth_session.FIXTURE_IDP, auth_session.FIXTURE_AUTH_VIA)


# ---- 与 auth/session.py 的字节等价（CLAUDE.md 不变量）----

def _segment(src: str, start: str, end: str) -> str:
    s = src.index(start)
    return src[s:src.index(end, s + 1)]


def test_edge_verifier_core_is_byte_identical_to_session_py():
    auth_src = (HERE.parents[2] / "site-builder" / "auth" / "session.py").read_text(encoding="utf-8")
    for start, end in (("def _b64url_decode_strict", "def _strict_json"),
                       ("def _strict_json", "def spki_sha256"),
                       ("def load_public_key_der", "def _rsa_verify"),
                       ("def _rsa_verify", "def local_signer")):
        assert _segment(auth_src, start, end).strip() == _segment(SRC, start, end.replace("local_signer", "_aud_matches") if end == "def local_signer" else end).strip(), start
    # verify_token 的判定段：auth 从 `try:` 到 `return claims`；Edge 的 _verify_site_session 同一段，只多 allowlist 取值行
    auth_body = _segment(auth_src, "def verify_token", "# 黄金三元组")
    edge_body = _segment(SRC, "def _verify_site_session", "def _get_cookies")
    a = auth_body[auth_body.index("    try:"):auth_body.rindex("return claims")]
    e = edge_body[edge_body.index("    try:"):edge_body.rindex("return claims")]
    e = e.replace("    allowlist = _site_allowlist()\n", "").replace('"site-session"', "token_use").replace(
        'TOKEN_USES["site-session"]', "TOKEN_USES[token_use]")
    assert a == e, "Edge 的验签判定段与 auth/session.py 分叉了"


def test_golden_triple_matches_auth_session():
    assert orq.RS256_GOLDEN == auth_session.RS256_GOLDEN


# ---- 源码守卫（spec §4.4：kid 不拼资源、allowlist 只按 kid 查表；§11.1：预热在顶层）----

def test_source_indexes_allowlist_only_by_kid_and_parses_it_once():
    verify = SRC[SRC.index("def _verify_site_session"):SRC.index("def _get_cookies")]
    indexes = re.findall(r"\ballowlist\[([^\]]+)\]", verify)
    assert indexes and all(i == "kid" for i in indexes), indexes
    assert "_site_allowlist()" in verify
    assert SRC.count("json.loads(SITE_ALLOWLIST_JSON)") == 1


def test_source_has_no_kid_derived_resource_paths():
    assert not re.search(r"(ssm|kms|s3|arn:)[^\n]*\bkid\b", SRC)


def test_source_has_no_hmac_no_legacy_and_no_shared_secret_left():
    for bad in ("hmac", "JWT_SECRET", "LEGACY_ENTRY", "_verify_legacy_site_session", "accepted_legacy", "HS256"):
        assert bad not in SRC, bad


def test_warmup_verify_happens_at_import_time_with_the_golden_triple():
    top = SRC[:SRC.index("def _site_allowlist")]
    assert "RS256_GOLDEN" in top and ".verify(" in top, "spec §11.1：预热验签必须在模块顶层"
    handler_side = SRC[SRC.index("def lambda_handler"):]
    assert "load_pem_public_key" not in SRC and "RS256_GOLDEN" not in handler_side


def test_public_key_parsing_stays_lazy_so_public_routes_survive_a_bad_injection():
    """D9：解析仍在首次使用（ticket 21）——注入坏掉时只有带 cookie 的私有请求 500。"""
    top = SRC[:SRC.index("def _site_allowlist")]
    assert "json.loads(SITE_ALLOWLIST_JSON)" not in top and "_load_public_key_der(base64" not in top
```

- [ ] **Step 2: 改 `edge_substitutions.py`（先红）**

```python
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import upgrade_code_vectors as _v  # noqa: E402  三套件共用的 RS 测试密钥（import 期生成）

DEFAULT_SITE_ALLOWLIST = {_v.SITE_KID: {"alg": "RS256", "spki_b64": _v.spki_b64(_v.SITE_KEY), "role": "current"}}
DEFAULTS: dict[str, str] = {
    "DYNAMODB_TABLE_NAME": "t",
    "DYNAMODB_REGION": "us-east-1",
    "FRONTEND_BUCKET_DOMAIN": "b.s3.us-east-1.amazonaws.com",
    "BASE_DOMAIN": "example.com",
    "SITE_ALLOWLIST_JSON": json.dumps(DEFAULT_SITE_ALLOWLIST),
    "REQUIRE_IDP_CLAIM": "true",
    "TRUSTED_IDPS": "Feishu,Okta",
    "ACCESS_TABLE": "site-access-events",
    "ACCESS_REPLICA_REGIONS": "us-east-1",
}
```

（删 `JWT_SECRET` / `LEGACY_ENTRY`。`substitute()` 对拼错 / 多给的 override 抛——所以任何还传 `JWT_SECRET=` 的调用方会在 Step 5 被点出来。）

- [ ] **Step 3: 跑红**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_kid_allowlist.py -q -x`
Expected: `AssertionError: 替换后仍有占位符 ['{{JWT_SECRET}}', '{{LEGACY_ENTRY}}']`（DEFAULTS 已删它们而源码还有）。

- [ ] **Step 4: 改 `origin_request.py`**

（a）顶部 import 加：

```python
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
```

（b）配置常量段：删 `JWT_SECRET = "{{JWT_SECRET}}"` 与 `LEGACY_ENTRY = …`；`SITE_ALLOWLIST_JSON` 的注释改为"kid -> {alg, spki_b64, role}；只含 site family；公钥不是秘密，但**接受哪些 key 本身就是授权边界**（spec §4.1），console 的公钥不进这里"。

（c）`_site_allowlist()`：解析后逐行换成公钥对象：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        _SITE_ALLOWLIST = {kid: {"alg": e["alg"], "public_key": _load_public_key_der(base64.b64decode(e["spki_b64"])),
                                 "role": e["role"]} for kid, e in parsed.items()}
```

（报文措辞把"它是每个 kid 的签名密钥"改成"值不打印：形态由 stack.py 决定"。）

（d）加 RS 段（**与 session.py 逐字相同的七个函数**——从 session.py 复制粘贴，不手抄）。**落点由 Step 1 的两条守卫定，不是 `BASE_DOMAIN` 之前**（执行时修订）：

- 整段必须落在 `def _site_allowlist` **之前**——`test_warmup_verify_happens_at_import_time_with_the_golden_triple` 取的 `top` 是 `SRC[:SRC.index("def _site_allowlist")]`，要求 `RS256_GOLDEN` 与 `.verify(` 都在里面。实测落点是配置常量段（`SITE_ALLOWLIST_JSON` / `_SITE_ALLOWLIST = None`）之后、`def _site_allowlist` 之前；`BASE_DOMAIN` 在文件里远在其后，按原文写会让那条守卫红。
- `_load_public_key_der = load_public_key_der` 这行别名要放在 **`_aud_matches` 之后**（不是 `_rsa_verify` 与 `_aud_matches` 之间）：字节等价守卫的第七段用它作 Edge 侧的结束锚点（`("def _aud_matches", "def mint_token", "_load_public_key_der = load_public_key_der")`），第六段的 Edge 侧结束锚点是 `def _aud_matches`。放错位置两段一起红。
- 七个函数之间**不许夹任何一行**（注释也算）——两侧逐字比对，注释算差异。

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
# ---- RS256 验签核心：与 site-builder/auth/session.py **字节等价**（test_edge_kid_allowlist.py 逐段比对）----
ALG = "RS256"
TOKEN_USES = {"site-session": "site-edge",
              "console-upgrade": "console-exchange",
              "console-session": "console-panel"}
RSA_MODULUS_BITS = (2048, 3072, 4096)
RSA_PUBLIC_EXPONENT = 65537
_PAD = padding.PKCS1v15()
_HASH = hashes.SHA256()
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# 夹具身份（spec §11.7 / ADR 0002）——与 auth/session.py 同一组字面量
FIXTURE_DOMAIN = "e2e.invalid"
FIXTURE_IDP = "fixture"
FIXTURE_AUTH_VIA = "fixture-issuer"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode_strict(s: str) -> bytes:
    …（session.py 原文）…


def _strict_json(raw: bytes) -> dict:
    …（session.py 原文）…


def spki_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def load_public_key_der(der: bytes):
    …（session.py 原文）…


def _rsa_verify(public_key, signing_input: bytes, sig: bytes) -> bool:
    …（session.py 原文）…


def _aud_matches(got, want: str) -> bool:
    …（session.py 原文）…


_load_public_key_der = load_public_key_der      # 内部名别名；也是字节等价守卫最后一段的结束锚点

# 黄金三元组（与 auth/session.py 字面相同）+ **import 期预热一次验签**（spec §11.1 / ADR 0003 的判据建立在
# "库初始化 + 首次验签发生在 Init 阶段"上；材料坏了在 Init 就炸，与 spike 同形）。
RS256_GOLDEN = {…与 session.py 相同…}
load_public_key_der(base64.b64decode(RS256_GOLDEN["spki_b64"])).verify(
    base64.b64decode(RS256_GOLDEN["signature_b64"]), RS256_GOLDEN["signing_input"].encode(), _PAD, _HASH)
```

（`import hashlib, re` 若顶部没有则加。原有的 `_b64url_decode` / `_strict_json` 旧定义删掉，`_get_cookies` 等其它调用点若用 `_b64url_decode` 改用 `_b64url_decode_strict`——grep 确认。）

（e）`_verify_site_session` 全文替换：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
def _verify_site_session(token: str) -> tuple:
    """**从 `try:` 到 `return claims` 与 auth/session.py 的 verify_token 字节等价**（token_use 固定 site-session，
    allowlist 在 try 之后才取——位置是契约的一部分，见 _site_allowlist 的说明）。"""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = _strict_json(_b64url_decode_strict(header_b64))
    except Exception:
        return None, "bad_signature"
    if "crit" in header:                      # RFC 7515 §4.1.11：本平台不认任何 critical 扩展
        return None, "bad_signature"
    allowlist = _site_allowlist()
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in allowlist:
        return None, "unknown_kid"
    entry = allowlist[kid]
    if header.get("alg") != entry["alg"]:
        return None, "alg_mismatch"
    try:
        sig = _b64url_decode_strict(sig_b64)
        if not _rsa_verify(entry["public_key"], f"{header_b64}.{payload_b64}".encode(), sig):
            return None, "bad_signature"
        claims = _strict_json(_b64url_decode_strict(payload_b64))
    except Exception:
        return None, "bad_signature"
    if claims.get("token_use") != "site-session":
        return None, "wrong_token_use"
    if not _aud_matches(claims.get("aud"), TOKEN_USES["site-session"]):
        return None, "wrong_audience"
    t = int(time.time()) if now is None else now
    …
```

**注意**：auth 的 `verify_token` 带 `now` 参数而 Edge 没有——为了字节等价，Edge 的 `_verify_site_session(token: str, now: int | None = None)` 也带上（默认 None），判定段里 `t = int(time.time()) if now is None else now` 与 auth 一致；`import time` 放顶部（删函数内的 `import base64, hashlib, hmac as _hmac, time as _t`）。字节等价守卫比对的正是 `try:` 到 `return claims` 那段，所以两侧的 `now` 处理、`jti` 检查（`if token_use == "console-upgrade" and not claims.get("jti")`——Edge 里 `token_use` 是字面量 `"site-session"`，守卫用 `.replace('"site-session"', "token_use")` 归一）都要逐字相同。**做法**：写完后跑 `test_edge_verifier_core_is_byte_identical_to_session_py`，按报错把 Edge 那段改到与 auth 相同，而不是反过来改 auth。

（f）删 `_verify_legacy_site_session` 整个函数与 `_verify_session_jwt` docstring 里的「2 + 1」段。

（g）`_check_auth`：在 `if REQUIRE_IDP_CLAIM:` 之前插入夹具分支，并把原 `if REQUIRE_IDP_CLAIM:` 改为 `elif`：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    # 夹具会话（spec §11.7 / ADR 0002 / D6）：两个来源标记必须**同时**是夹具值，且只在夹具站点
    # （route owner 的域是夹具域）或平台路由（console 的升级链路要经它）上按 allowed_users 正常判定；
    # 其它路由一律 302——`allowed_users = "org"` 的真实站点放行任何可信邮箱，这条分支就是不让夹具会话
    # 成为全组织的钥匙。平台身份用 _is_platform_route（按 host 推导），不看 route 的可写字段。
    is_fixture = claims.get("auth_via") == FIXTURE_AUTH_VIA or claims.get("idp") == FIXTURE_IDP
    if is_fixture:
        both = claims.get("auth_via") == FIXTURE_AUTH_VIA and claims.get("idp") == FIXTURE_IDP
        owner = route.get("owner")
        owner_is_fixture = (isinstance(owner, str) and owner.count("@") == 1
                            and owner.split("@")[1] == FIXTURE_DOMAIN and bool(owner.split("@")[0]))
        if not both or not (_is_platform_route(route) or owner_is_fixture):
            return _redirect_login(host, request.get("uri", "/"), request.get("querystring", ""))
    elif REQUIRE_IDP_CLAIM:
        …原有 idp / auth_via 检查…
```

（h）`edge_substitutions.py` 之外：`test_edge_auth.py` 顶部那段手写替换表改成 `import edge_substitutions as es; orq = es.load_edge_module("_edge_auth_testable", write_to=Path(__file__).parent)`，`_jwt()` 助手改为用 `upgrade_code_vectors.SITE_KEY` 签 RS token（保留 `email=None` 省略字段、`exp_delta`、`idp` / `auth_via` 参数；`typ` 载荷改成 `token_use` / `aud`）；`test_edge_rejects_a_token_without_typ` → `…without_token_use`、`test_edge_rejects_a_console_upgrade_code_as_a_site_session` 用 console key 的 RS 升级码、`test_check_auth_redirects_a_typeless_token_to_login`、`test_edge_expected_typ_is_not_caller_supplied`、`test_edge_rejects_falsy_typ_claims` 改成 `token_use` 版本或删（被 `test_edge_kid_allowlist` 覆盖的删）；`test_a_real_auth_token_verifies_at_the_edge` 用 `session.mint_token` + `v.SITE_KEY`。`test_edge_lazy_config.py`：`test_legacy_entry_tokens_do_not_need_the_allowlist_at_all` 删；其余不动。`test_edge_access_log.py` / `test_origin_request.py` / `test_edge_route_cache.py` 若手搓 HMAC token，改用同一个 `_jwt()`（放进一个共用的 `_edge_test_tokens.py`？——不：直接从 `test_edge_auth` import `_jwt`，或各自三行调用 `auth_session.mint_token`；保持现有文件组织）。`panel/tests/test_frontend_contract.py` 与 `deployer/tests/test_migrate_permissions.py` 里 `es.load_edge_module(...)` 若传了 `JWT_SECRET=` / `LEGACY_ENTRY=` 就删那两个参数。

- [ ] **Step 5: 跑绿**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`；`cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_edge_new_form_vector.py -q`；`cd site-builder/panel && ../deployer/.venv/bin/pytest tests/test_frontend_contract.py -q`；`cd site-builder/deployer && .venv/bin/pytest tests/test_migrate_permissions.py -q`
Expected: 全绿（`test_stack_*` 那几个文件在 Task 11 之前会红——它们读 `stack.py`；先只看 `test_edge_*` / `test_origin_request`）。

- [ ] **Step 6: 变形自证**

临时把 `_check_auth` 夹具分支里 `or owner_is_fixture` 改成 `or True` ⇒ `test_fixture_session_is_redirected_on_a_real_org_route` 必红；把 `if "crit" in header` 删掉 ⇒ `test_crit_header_…` 必红；改 Edge 的 `_rsa_verify` 任一字符 ⇒ 字节等价守卫必红。`git stash` 还原。

- [ ] **Step 7: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add router/infrastructure/lambda site-builder/auth/tests/test_edge_new_form_vector.py site-builder/panel/tests/test_frontend_contract.py site-builder/deployer/tests/test_migrate_permissions.py
git commit -m "feat(asset-v1/08): Edge 改 RS256 验签（vendored cryptography、黄金预热、spki_b64 allowlist、夹具边界分支）；删 legacy 入口与 HMAC；与 session.py 字节等价守卫"
```

---

### Task 11：`router/infrastructure/stack.py`——公钥注入（KMS 四项）、Edge 依赖交叉装；删 `load_jwt_secret`

**Files:**
- Create: `router/infrastructure/lambda/requirements-edge.txt`
- Modify: `router/infrastructure/requirements.txt`（**执行时补进清单，见 SDD ledger Ruling R18**：加 `cryptography==50.0.0`（与 auth / panel / `requirements-edge.txt` 同钉）。router venv 原先只有 CDK 依赖，而 Task 10 让 `edge_substitutions` 顶层 import 测试向量、部署模式 synth 又经 `session_kms` 真需要它 ⇒ **任何模式下 synth 都 import 不了 `cryptography`**。连带 Task 16：CLAUDE.md 的 venv 表与 DEPLOY.md「本机工具链」里"router venv 只有 CDK 依赖"那句要改）
- Modify: `router/infrastructure/stack.py`
- Modify: `router/infrastructure/lambda/test_stack_static.py`
- Modify: `site-builder/auth/tests/test_requirements_locked.py`（守卫扩到 `stack.py` 与 `requirements-edge.txt`）
- Test: `router/infrastructure/lambda/test_stack_static.py`、`test_stack_policy.py`、`test_stack_edge_iam.py`（后者 synth 需 `router/infrastructure/.venv` 的 aws_cdk——按其文件头的跳过 / 桥接规则）；`auth/tests/test_requirements_locked.py`

**Interfaces:**
- Produces:
  - `load_site_allowlist(keys, *, kms=None) -> str`（JSON；每行 `{"alg": "RS256", "spki_b64", "role"}`；非 RS 行任何模式都抛；KMS 失败默认让 synth 失败，`APP_SYNTH_OFFLINE=1` 才注 `SYNTH_PLACEHOLDER_ALLOWLIST_JSON`；`APP_SITE_ALLOWLIST_JSON` 显式覆盖仍在）。**`keys` 既可以是已加载的 `SessionKeys`，也可以是取值函数（thunk）**——`WebRouterStack` 传后者，见 Step 4 与 Ruling R17
  - `EDGE_REQUIREMENTS = Path(__file__).parent / "lambda" / "requirements-edge.txt"`；`vendor_edge_dependencies(target_dir: str) -> None`（pip `--require-hashes --platform manylinux2014_x86_64 --only-binary :all: --python-version 3.11 --implementation cp`）
  - `SYNTH_ONLY_SENTINEL`（哨兵文件名）、`_synth_only_marker()`（标记字串的唯一来源 = 占位 allowlist 的那个 kid）、`_asset_is_synth_only(site_allowlist_json) -> bool`、`_write_synth_only_sentinel(target_dir)`（执行时新增，见 Step 4）
  - **删**：`load_jwt_secret`、`{{JWT_SECRET}}` / `{{LEGACY_ENTRY}}` 两处 `.replace`、`legacy_entry` import
  - `_session_keys_on_path()` / `_session_keys()` / `assert_edge_source_fully_injected` / `_synth_offline` 不变

- [ ] **Step 1: `requirements-edge.txt`**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
{
  cat <<'HDR'
# Lambda@Edge（origin-request）的**锁定**依赖闭包：cryptography 及其两个传递依赖，manylinux2014_x86_64 / cp311
# 的 wheel 各钉一个 sha256（ADR 0003；数字与装法见 spec §11.1）。stack.py 在 synth 时用
# `pip install --require-hashes --platform manylinux2014_x86_64 --only-binary :all: --python-version 3.11 --implementation cp`
# 把它装进 Edge 的 asset 目录；auth/tests/test_requirements_locked.py 守着这四个开关与"每个包都带 hash"。
# 重新生成：python3 site-builder/scripts/spike_edge_crypto_coldstart.py --regen-requirements 之后把
# site-builder/scripts/spike_edge_crypto_requirements.txt 的 requirement 正文抄进来（版本必须与 auth 清单同）。
HDR
  grep -v '^#' site-builder/scripts/spike_edge_crypto_requirements.txt | sed '/^$/d'
} > router/infrastructure/lambda/requirements-edge.txt
cat router/infrastructure/lambda/requirements-edge.txt
```

- [ ] **Step 2: 改 `test_stack_static.py`（先红）**

- 删：`test_legacy_parameter_path_is_not_hardcoded_anymore`、`test_empty_legacy_param_injects_an_empty_string_and_stays_silent`、`test_the_empty_string_is_not_the_synth_placeholder`、`test_explicit_override_still_wins_when_the_entry_is_open`、`test_override_is_ignored_once_the_entry_is_closed`、`test_real_ssm_failure_still_falls_back_to_the_synth_placeholder`、`test_legacy_entry_follows_the_same_single_switch`、`test_legacy_secret_ssm_failure_fails_synth_by_default_too`，以及那段 `exec` `load_jwt_secret` 片段的夹具。
- `test_stack_uses_shared_session_keys_helpers_not_inline_copies`：改为 `assert "legacy_entry(" not in body and "load_jwt_secret" not in SRC`。
- `test_session_keys_is_parsed_once_for_both_injected_values` → `…_for_the_injected_allowlist`：断言 `"session_keys = _session_keys()"` 与 `"load_site_allowlist(session_keys)"` 在，`"load_jwt_secret"` 不在。
- `test_allowlist_takes_only_the_site_family_and_reads_each_secret_from_ssm` → 重写为：

```python
def test_allowlist_takes_only_the_site_family_and_fetches_each_public_key_from_kms(clean_env, monkeypatch):
    mod = _fragment()                     # 现有夹具：exec load_site_allowlist 片段进一个假模块
    import upgrade_code_vectors as v
    keys = sk.load_session_keys(_cfg_with(RS_WITH_PREVIOUS))   # Task 2 的 RS 配置文本，写进 tmp 后加载
    kms = v.FakeKms()
    text = mod.load_site_allowlist(keys, kms=kms)
    got = json.loads(text)
    assert got == {"site-rs-v1": {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"},
                   "site-rs-v0": {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_PREV_KEY), "role": "previous"}}
    assert v.spki_b64(v.CONSOLE_KEY) not in text, "console 的公钥进了 Edge"
    assert {c[0] for c in kms.calls} == {"describe_key", "get_public_key"}
    assert "\\" not in text and "'''" not in text


def test_a_key_whose_fingerprint_differs_from_config_fails_synth_in_every_mode(clean_env, monkeypatch, offline_flag):
    import upgrade_code_vectors as v
    kms = v.FakeKms(); kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    with pytest.raises(session_kms.KeyMaterialMismatch):
        _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=kms)


def test_kms_failure_fails_synth_by_default_instead_of_injecting_the_placeholder(clean_env, monkeypatch, capsys):
    class Boom:
        def describe_key(self, **kw): raise RuntimeError("AccessDeniedException")
    with pytest.raises(RuntimeError, match="AccessDeniedException") as ei:
        _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=Boom())
    assert "APP_SYNTH_OFFLINE" in str(ei.value)


def test_kms_failure_falls_back_to_the_placeholder_only_when_offline_is_explicit(clean_env, monkeypatch, capsys):
    monkeypatch.setenv("APP_SYNTH_OFFLINE", "1")
    class Boom:
        def describe_key(self, **kw): raise RuntimeError("no network")
    text = _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=Boom())
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in text and "DO NOT deploy" in capsys.readouterr().err


def test_vendoring_runs_hash_checked_cross_platform_pip_into_the_asset_dir(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd) or type("R", (), {"returncode": 0})())
    _fragment_vendor().vendor_edge_dependencies("/tmp/x")
    argv = calls[0]
    for flag in ("--require-hashes", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                 "--python-version", "3.11", "--implementation", "cp", "--target", "/tmp/x"):
        assert flag in argv, flag
    assert argv[argv.index("-r") + 1].endswith("lambda/requirements-edge.txt")


def test_vendoring_is_skipped_only_in_explicit_offline_synth_and_runs_before_the_asset_is_taken():
    body = SRC[SRC.index("class WebRouterStack"):]
    vend = body.index("vendor_edge_dependencies(temp_dir)")
    asset = body.index("lambda_.Code.from_asset(temp_dir)")
    assert vend < asset
    assert "if not _synth_offline():" in body[vend - 200:vend]
```

（`_fragment()` / `_cfg_with()` / `_fragment_vendor()` 按文件里现有 `exec` 片段夹具的写法补：片段起止改为 `def load_site_allowlist` → `class WebRouterStack`，前置 helpers 段 `def _synth_offline` 与 `def vendor_edge_dependencies`；`RS` / `RS_WITH_PREVIOUS` 文本从 `auth/tests/test_session_keys.py` import。）

- [ ] **Step 3: `test_requirements_locked.py` 扩到 stack.py（先红）**

```python
ROUTER_STACK = Path(__file__).parents[3] / "router" / "infrastructure" / "stack.py"
EDGE_REQ = Path(__file__).parents[3] / "router" / "infrastructure" / "lambda" / "requirements-edge.txt"


def test_edge_every_package_is_pinned_and_hashed():
    _assert_all_pinned_and_hashed(EDGE_REQ)


def test_edge_requirements_pin_the_same_versions_as_auth():
    import re
    pins = lambda p: dict(re.findall(r"^([a-zA-Z0-9_-]+)==([^ \\]+)", p.read_text(), re.M))
    edge, auth = pins(EDGE_REQ), pins(AUTH_REQ)
    assert set(edge) == {"cffi", "cryptography", "pycparser"} and all(auth[k] == v for k, v in edge.items())


def test_stack_vendoring_pip_argv_carries_the_four_cross_install_switches():
    """AST 取 stack.py 里 vendor_edge_dependencies 的 subprocess.run 参数列表（与 deploy_auth 那条同一套做法）。"""
    tree = ast.parse(ROUTER_STACK.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "vendor_edge_dependencies")
    consts = [s for node in ast.walk(fn) if isinstance(node, ast.Call) for a in node.args for s in _str_consts(a)]
    for want in ("--require-hashes", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                 "--python-version", "3.11", "--implementation", "cp"):
        assert want in consts, want
```

- [ ] **Step 4: 改 `stack.py`**

- 删 `load_jwt_secret` 整个函数；`load_site_allowlist(keys, *, kms=None) -> str`：

```python
def load_site_allowlist(keys, *, kms=None) -> str:
    """3c-final：Edge 只认 site family 的 RS256 公钥 allowlist（spec §4.1 / §11.6）。

    → JSON 文本 `kid -> {"alg": "RS256", "spki_b64": <base64 DER SPKI>, "role"}`。每把 key 在这里过 spec §11.6
    第 1 层的四项校验（DescribeKey 三项 + 指纹 == config；session_kms.fetch_verified_public_key_der），任一不符
    **任何模式都抛**——那不是"读不到"，是配置指错了 key。**只取 site family，console 的公钥不进 Edge**
    （公钥不是秘密，但"接受哪些 key"本身就是授权边界）。

    `keys` 可以是已加载的 `SessionKeys`，**也可以是取值函数（thunk）**：`WebRouterStack` 传后者，因为
    "只想看模板"的两条路（显式覆盖、显式离线）必须在 `[SessionKeys]` **根本加载不动**时仍然走得通——
    切换窗口里 site-builder/config.ini 还是旧形态，急加载会让 `SessionKeysError` 在进本函数之前就抛。

    三类失败，三种处置（`_degrade` 是唯一退化点）：
    1. **配置写错**——非 RS256 行、或 KMS 里的 key 与配置声明的不是同一把（`KeyMaterialMismatch`）：
       **任何模式都抛**，绝不注占位；
    2. **配置读不动 / 依赖装不上 / KMS 调不通**：默认让 synth 失败；只有显式 `APP_SYNTH_OFFLINE=1`
       才注入带 SYNTH-ONLY 标记的占位 allowlist 并在 stderr 警告（该模板绝不能部署）。配置读不动那一路
       重抛的类型仍是 `SessionKeysError`（调用方与闸门按它判"这是配置错，不是环境故障"）；
    3. `APP_SITE_ALLOWLIST_JSON` 在场 ⇒ 用它，**根本不加载配置、不碰 KMS**。

    `import session_kms` **刻意放在取公钥那一步里、不在函数顶部**：它拖着 cryptography 闭包，放顶部会让
    "只想看模板"这条路死在 import 上，而那正是 R17 要保住的路。
    """
    _session_keys_on_path()
    from session_keys import SYNTH_PLACEHOLDER_ALLOWLIST_JSON, SessionKeysError

    def _degrade(reason_cn: str, reason_en: str, exc: Exception, fix: str = "",
                 *, as_config_error: bool = False) -> str:
        way_out = ("离线只看模板请显式设 APP_SYNTH_OFFLINE=1（产物带 SYNTH-ONLY 标记、且不含 "
                   "cryptography/，不可部署）或用 APP_SITE_ALLOWLIST_JSON 覆盖。")
        if not _synth_offline():
            if as_config_error:
                raise SessionKeysError(f"{exc}——synth 拒绝生成模板，什么都不会部署。{way_out}") from exc
            raise RuntimeError(f"{reason_cn}（{type(exc).__name__}: {exc}）——synth 拒绝生成模板，"
                               f"什么都不会部署。{fix}" + way_out) from exc
        print(f"WARNING: {reason_en} ({exc}); APP_SYNTH_OFFLINE=1 ⇒ injecting the SYNTH-ONLY "
              "placeholder allowlist. DO NOT deploy this template.", file=sys.stderr)
        return SYNTH_PLACEHOLDER_ALLOWLIST_JSON

    override = os.getenv("APP_SITE_ALLOWLIST_JSON")
    if override:
        text = override
    else:
        try:
            site_refs = list((keys() if callable(keys) else keys).allowlist("site"))
        except SessionKeysError as exc:
            text = _degrade("读 [SessionKeys] 失败", "could not load [SessionKeys]", exc, as_config_error=True)
            site_refs = None
        if site_refs is not None:
            for ref in site_refs:      # 已加载成功的行：非 RS256 是配置错，在 try 之外 ⇒ 任何模式都抛
                if ref.alg != "RS256":
                    raise ValueError(f"{ref.kid}: Edge 只支持 RS256 行（3c-final）")
            try:
                import boto3
                import session_kms
            except ImportError as exc:
                text = _degrade("synth 取公钥要 boto3 与 cryptography（session_kms 的闭包）",
                                "boto3/cryptography missing in the synth interpreter", exc,
                                "先给 router/infrastructure/.venv 装 requirements.txt；")
            else:
                try:
                    kms = kms or boto3.client("kms", region_name="us-east-1")
                    allow = {ref.kid: {"alg": ref.alg,
                                       "spki_b64": session_kms.spki_b64(
                                           session_kms.fetch_verified_public_key_der(kms, ref)),
                                       "role": ref.role} for ref in site_refs}
                    text = json.dumps(allow, separators=(",", ":"))
                except session_kms.KeyMaterialMismatch:
                    raise                          # 配置指错 key：任何模式都不注占位
                except Exception as exc:  # noqa: BLE001
                    text = _degrade("按 [SessionKeys] 从 KMS 取 site 公钥失败",
                                    "could not fetch site public keys from KMS", exc,
                                    "这是 cdk deploy 路径：先确认 deployer 栈已建 CMK、凭据有 "
                                    "kms:DescribeKey / GetPublicKey；")
    if "\'\'\'" in text or "\\" in text:
        raise ValueError("allowlist JSON 含三引号或反斜杠，注进三引号字符串会破坏 Edge 源码")
    json.loads(text)
    return text


SYNTH_ONLY_SENTINEL = "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt"


def _synth_only_marker() -> str:
    """SYNTH-ONLY 标记的**唯一来源**：占位 allowlist 的那个 kid（定义在 session_keys.py）。
    不在这里抄第二份字面量——占位常量、哨兵、verify_deployed_edge.sh 的 grep 必须是同一个字符串。"""
    _session_keys_on_path()
    from session_keys import SYNTH_PLACEHOLDER_ALLOWLIST_JSON
    return next(iter(json.loads(SYNTH_PLACEHOLDER_ALLOWLIST_JSON)))


def _asset_is_synth_only(site_allowlist_json: str) -> bool:
    """这份产物是不是"看得出不可部署"的那种：**注进去的** allowlist 带 SYNTH-ONLY 标记。
    用包含而不是等值比：显式 `APP_SITE_ALLOWLIST_JSON` 里带上标记同样算"我知道这份不可部署"。"""
    return _synth_only_marker() in site_allowlist_json


def _write_synth_only_sentinel(target_dir: str) -> Path:
    """跳过 vendoring 时往 asset 里放一个带标记的哨兵文件，让"缺依赖"在产物里看得见。"""
    path = Path(target_dir) / SYNTH_ONLY_SENTINEL
    path.write_text(f"{_synth_only_marker()}\n\n……（说明：allowlist 是占位、且没有交叉安装 "
                    "cryptography 闭包，冷启动会 import 失败；不要部署它）\n", encoding="utf-8")
    return path


EDGE_REQUIREMENTS = Path(__file__).parent / "lambda" / "requirements-edge.txt"


def vendor_edge_dependencies(target_dir: str) -> None:
    """把 Edge 的锁定依赖（cryptography 闭包）按 hash 交叉装进 asset 目录（ADR 0003 / spec §11.1）。
    与 deploy_auth.build_zip 同一套开关，目标换成 Lambda@Edge 的 python3.11 / x86_64。"""
    subprocess.run([sys.executable, "-m", "pip", "install", "--require-hashes", "-r", str(EDGE_REQUIREMENTS),
                    "--target", target_dir, "-q", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                    "--python-version", "3.11", "--implementation", "cp"], check=True)
```

- `WebRouterStack.__init__`：`session_keys = _session_keys`（**不加括号——传函数本身**，见上面 thunk 那段与 Ruling R17）；`site_allowlist_json = load_site_allowlist(session_keys)`；替换链删 `.replace("{{JWT_SECRET}}", jwt_secret)` 与 `.replace("{{LEGACY_ENTRY}}", legacy_entry)`；写完 `index.py` 后、`Code.from_asset(temp_dir)` 之前加：

```python
# 【片段】不是完整模块：插进正文所指的落点
if _asset_is_synth_only(site_allowlist_json):
    _write_synth_only_sentinel(temp_dir)
else:
    vendor_edge_dependencies(temp_dir)
```

  `import subprocess`。**判据是注进产物的 allowlist 带不带 SYNTH-ONLY 标记，不是 `_synth_offline()` 那个旗标**
  （执行时修订，见 SDD ledger Task 11 review Important 1）：按旗标判会开出第四种组合——旗标还留在 shell / CI
  环境里（陈旧变量），而 config 已是 RS 形态、KMS 可达、四项校验通过 ⇒ 注进去的是**真** allowlist（产物没有
  标记、看起来完全正常），却跳过了 vendoring ⇒ asset 里没有 `cryptography/` ⇒ **每次** Edge 冷启动 import 失败
  = 所有子域 502，而 Edge 回滚要 10–20 分钟全球复制。「标记 ⇔ 不可部署」这条叙事在这里按**构造**维持：
  跳过 vendoring 的那一支一定写标记哨兵，没有标记的那一支一定装依赖；带真 allowlist 而 pip 装不动时
  `check=True` 让 synth 响亮失败（那种产物既没标记又缺依赖）。
- 模块 docstring / 注释里 "JWT secret comes from SSM at deploy time" 之类改成 KMS 公钥。

- [ ] **Step 5: 跑绿**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`；`cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_requirements_locked.py -q`
Expected: 全绿。`test_stack_edge_iam.py` 若 synth：需 `router/infrastructure/.venv` 有 aws_cdk 且本机能 pip 下载 wheel（vendoring 在 synth 路径上）——离线时按它文件头的说明设 `APP_SYNTH_OFFLINE=1`（那时跳过 vendoring）。

- [ ] **Step 6: 本机 synth 一次（static → integration）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure"
rm -rf cdk.out && APP_SYNTH_OFFLINE=1 PATH=.venv/bin:$PATH npx -y aws-cdk@latest synth --quiet >/dev/null
ls cdk.out/asset.*/                   # 离线模式：index.py + SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt，无 cryptography/
grep -c 'SYNTH-ONLY-PLACEHOLDER' cdk.out/asset.*/index.py   # ≥ 1（占位，不可部署）
```

离线产物里那个哨兵文件是 Step 4 的修订带来的（执行时修订：原文写"只有 index.py"）——跳过 vendoring 与写哨兵
是同一支，所以离线 asset 一定是两个文件。这条离线 synth 也是 R17 的落地判据：它必须在 `[SessionKeys]`
**还是旧形态、`load_session_keys` 必拒**的情况下跑得通（验证环境的真 config 到 Task 18 ★ 才回填）。

真机 synth（含 vendoring 与 KMS 取公钥）在 Task 19 ★ 的 `cdk deploy` 里发生；`verify_deployed_edge.sh` 事后核对产物里有 `cryptography/` 目录与 site 公钥。

- [ ] **Step 7: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add router/infrastructure/stack.py router/infrastructure/requirements.txt router/infrastructure/lambda/requirements-edge.txt router/infrastructure/lambda/test_stack_static.py site-builder/auth/tests/test_requirements_locked.py
git commit -m "feat(asset-v1/08): router 栈按 KMS 四项校验注入 site 公钥（spki_b64）、synth 时按 hash 交叉装 Edge 依赖；删 load_jwt_secret 与 LEGACY_ENTRY 注入"
```

---

### Task 12：验收身份——`_session_mint.py` 变成夹具签发器客户端；六处调用方、E2E、常驻夹具站点

**Files:**
- Modify: `site-builder/scripts/_session_mint.py`（全文重写；文件名不变——六处 `import _session_mint as sm` 不动）
- Create: `site-builder/scripts/ensure_fixture_site.py`
- Modify: `site-builder/scripts/deploy_fixture.py`（默认 owner → `fixture@e2e.invalid`；docstring）
- Modify: `site-builder/scripts/verify_session_token_semantics.py`、`verify_kid_entry_live.py`、`verify_console_e2e.py`、`verify_api_key_e2e.py`、`verify_analytics_e2e.py`
- Modify: `site-builder/deployer/tests/test_e2e_fixtures.py`（`session_cookie` → function 级夹具会话；删 `test_legacy_site_migrates_…`；`e2e@test.com` → `e2e-bot@e2e.invalid`）
- Modify: `site-builder/deployer/tests/test_session_mint.py`（重写）、`test_verify_session_token_semantics.py`、`test_verify_kid_entry_live.py`
- Create: `site-builder/deployer/tests/test_ensure_fixture_site.py`
- Test: 上述 deployer 测试 + `test_deploy_fixture_flags.py`

**Interfaces:**
- Consumes: auth 的 `POST /fixture-session`（Task 5）、`[Verification]`（Task 7）、`permissions.FIXTURE_DOMAIN / is_fixture_email`（Task 9）。
- Produces:
  - `_session_mint.Minter.from_config(config_path=CONFIG_PATH, *, session=None) -> Minter`（读 `[Platform]` 与 `[Verification]`；`fixture_issuer` 不是 true ⇒ `SystemExit`；`lambda.get_function_url_config("site-auth-service")`；**不在这里 assume**——凭据不缓存）
  - `Minter.site_session(email, *, ttl_seconds=1800, name=None, role="current") -> str`（每次调用先 `sts.assume_role(site-builder-verifier, DurationSeconds=900)` 再 SigV4 `POST {url}fixture-session`——D11：角色会话上限 3600 s、E2E 约 37 min，缓存一份会贴着上限过期）
  - `Minter.upgrade_code(email, *, site_session=None) -> str`（真实链路：`GET https://auth.{base}/console-session` → Location 里的 code）
  - `Minter.console_session(email, *, site_session=None) -> str`（再 `GET https://console.{base}/api/session-callback?code=…` → `__Host-sb_console`）
  - `Minter.mint(token_use, email, *, ttl_seconds=1800, role="current", name=None) -> str`（六处调用方的兼容入口；**删** `family=`）
  - `_session_mint.PROBE_EMAIL = "probe@e2e.invalid"`、`FIXTURE_SITE_ID = "e2e-probe"`、`live_target(config_path, *, ddb=None) -> Target`（只认 owner == PROBE_EMAIL 且 `require_auth=True` 的路由；没有 ⇒ `SystemExit` 指向 `ensure_fixture_site.py`）
  - `save_token / load_saved_token / Target` 不变；CLI：`--token-use {site-session,console-upgrade} --email --role {current,previous} --ttl --save`
  - `ensure_fixture_site.ensure(config_path, *, deploy=deploy_fixture.main, ddb=None) -> dict`（`{"deployed": bool, "permissions_changed": bool}`）；已有同 id 站点但 owner 不是夹具域 ⇒ `SystemExit`
  - `deploy_fixture.main(fixture_dir, owner="fixture@e2e.invalid", *, site_id=None, marker=None)`

- [ ] **Step 1: 重写 `test_session_mint.py`（先红）**

```python
"""`scripts/_session_mint.py`：夹具签发器的客户端（3c-final；ADR 0002）。**import 期不得碰 AWS。**"""
import base64
import json
import sys
import textwrap
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "auth", "deployer/functions"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import _session_mint as sm  # noqa: E402

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.test
    account_id = 111111111111
    routing_table = site-routes

    [Verification]
    fixture_issuer = true
    verifier_trusted_principals = arn:aws:iam::111111111111:user/kent
""")
CFG_OFF = CFG.replace("fixture_issuer = true", "fixture_issuer = false")
URL = "https://abc.lambda-url.us-east-1.on.aws/"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6InByb2JlQGUyZS5pbnZhbGlkIn0.c2ln"
CODE = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJ4In0.c2ln"
CONSOLE = "eyJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl91c2UiOiJjb25zb2xlLXNlc3Npb24ifQ.c2ln"


class FakeSession:
    """boto3.Session 替身：sts.assume_role 与 lambda.get_function_url_config。"""
    def __init__(self):
        self.calls = []

    def client(self, svc, region_name=None):
        outer = self

        class C:
            def assume_role(self, **kw):
                outer.calls.append(("assume_role", kw))
                return {"Credentials": {"AccessKeyId": "AKIA" + "X" * 16, "SecretAccessKey": "s", "SessionToken": "t"}}

            def get_function_url_config(self, FunctionName):
                outer.calls.append(("get_function_url_config", FunctionName))
                return {"FunctionUrl": URL, "AuthType": "AWS_IAM"}
        return C()


class FakeHttp:
    """记录每个请求；按 URL 路径给出理想应答（auth 的 /fixture-session、/console-session、panel 的 callback）。"""
    def __init__(self, *, fixture_status=200):
        self.requests = []
        self.fixture_status = fixture_status

    def __call__(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        path = urlparse(url).path
        if path.endswith("/fixture-session"):
            b = json.loads(body)
            return self.fixture_status, {"content-type": "application/json"}, json.dumps(
                {"token": TOKEN, "kid": "site-rs-v1" if b.get("role", "current") == "current" else "site-rs-v0",
                 "ttl_seconds": b.get("ttl_seconds", 1800)})
        if path == "/console-session":
            return 302, {"location": f"https://console.example.test/api/session-callback?code={CODE}"}, ""
        if path == "/api/session-callback":
            return 302, {"location": "https://console.example.test/",
                         "set-cookie": [f"__Host-sb_console={CONSOLE}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=14400"]}, ""
        raise AssertionError(f"unexpected {method} {url}")


def _cfg(tmp_path, text=CFG):
    p = tmp_path / "config.ini"; p.write_text(text); return p


def _minter(tmp_path, http=None, text=CFG):
    return sm.Minter.from_config(_cfg(tmp_path, text), session=FakeSession(), http=http or FakeHttp())


def test_import_has_no_side_effects_and_exposes_the_api():
    for name in ("Minter", "live_target", "save_token", "load_saved_token", "PROBE_EMAIL", "FIXTURE_SITE_ID"):
        assert hasattr(sm, name), name
    assert sm.PROBE_EMAIL == "probe@e2e.invalid" and sm.FIXTURE_SITE_ID == "e2e-probe"


def test_from_config_only_finds_the_auth_url_and_each_mint_assumes_the_role_afresh(tmp_path):
    fs = FakeSession()
    m = sm.Minter.from_config(_cfg(tmp_path), session=fs, http=FakeHttp())
    assert [c[0] for c in fs.calls] == ["get_function_url_config"] and fs.calls[0][1] == "site-auth-service"
    m.site_session("probe@e2e.invalid")
    m.site_session("probe@e2e.invalid")
    # D11：验收角色会话上限 3600 s、E2E 约 37 min——构造时只 assume 一次会贴着上限，过期症状是 Function URL 403、
    # 读起来像授权配错。每次 mint 一次 AssumeRole（900 s 是 STS 允许的最小值），没有到期刷新那套时钟逻辑。
    assert [c[0] for c in fs.calls] == ["get_function_url_config", "assume_role", "assume_role"]
    kw = fs.calls[1][1]
    assert kw["RoleArn"] == "arn:aws:iam::111111111111:role/site-builder-verifier" and kw["DurationSeconds"] == 900
    assert kw["RoleSessionName"].startswith("verify-")


def test_from_config_refuses_when_the_component_is_off(tmp_path):
    with pytest.raises(SystemExit, match="fixture_issuer"):
        sm.Minter.from_config(_cfg(tmp_path, CFG_OFF), session=FakeSession(), http=FakeHttp())


def test_site_session_posts_a_sigv4_signed_request_with_the_contract_body(tmp_path):
    http = FakeHttp()
    tok = _minter(tmp_path, http).site_session("probe@e2e.invalid", ttl_seconds=600, name="Probe")
    assert tok == TOKEN
    method, url, headers, body = http.requests[0]
    assert (method, url) == ("POST", URL + "fixture-session")
    assert json.loads(body) == {"email": "probe@e2e.invalid", "ttl_seconds": 600, "name": "Probe", "role": "current"}
    h = {k.lower(): v for k, v in headers.items()}
    assert h["authorization"].startswith("AWS4-HMAC-SHA256") and "x-amz-security-token" in h and "x-amz-date" in h
    assert h["content-type"] == "application/json"


def test_role_previous_is_passed_through(tmp_path):
    http = FakeHttp()
    _minter(tmp_path, http).site_session("probe@e2e.invalid", role="previous")
    assert json.loads(http.requests[0][3])["role"] == "previous"


@pytest.mark.parametrize("email", ["a@example.com", "a@e2e.invalid.x", "", "a@E2E.INVALID"])
def test_non_fixture_emails_are_refused_client_side_before_any_request(tmp_path, email):
    http = FakeHttp()
    with pytest.raises(SystemExit, match="e2e.invalid"):
        _minter(tmp_path, http).site_session(email)
    assert http.requests == []


def test_non_200_from_the_issuer_is_fatal_and_names_the_status(tmp_path):
    with pytest.raises(SystemExit, match="403"):
        _minter(tmp_path, FakeHttp(fixture_status=403)).site_session("probe@e2e.invalid")


def test_upgrade_code_and_console_session_walk_the_real_exchange_chain(tmp_path):
    http = FakeHttp()
    m = _minter(tmp_path, http)
    assert m.upgrade_code("probe@e2e.invalid") == CODE
    http.requests.clear()
    assert m.console_session("probe@e2e.invalid") == CONSOLE
    paths = [(r[0], urlparse(r[1]).netloc, urlparse(r[1]).path) for r in http.requests]
    assert paths == [("POST", urlparse(URL).netloc, "/fixture-session"),
                     ("GET", "auth.example.test", "/console-session"),
                     ("GET", "console.example.test", "/api/session-callback")]
    assert http.requests[1][2]["cookie"] == f"sb_session={TOKEN}"
    assert parse_qs(urlparse(http.requests[2][1]).query)["code"] == [CODE]


def test_mint_dispatches_by_token_use_and_has_no_family_override(tmp_path):
    m = _minter(tmp_path)
    assert m.mint("site-session", "p@e2e.invalid") == TOKEN
    assert m.mint("console-upgrade", "p@e2e.invalid") == CODE
    assert m.mint("console-session", "p@e2e.invalid") == CONSOLE
    with pytest.raises(TypeError):
        m.mint("site-session", "p@e2e.invalid", family="console")
    with pytest.raises(SystemExit):
        m.mint("legacy", "p@e2e.invalid")


def test_live_target_picks_only_the_resident_fixture_site(aws, tmp_path):
    import boto3
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    t = ddb.create_table(TableName="site-routes", KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
    t.put_item(Item={"subdomain": "app-real", "require_auth": True, "owner": "real@example.test"})
    with pytest.raises(SystemExit, match="ensure_fixture_site"):
        sm.live_target(_cfg(tmp_path), ddb=ddb)
    t.put_item(Item={"subdomain": "app-e2e-probe", "require_auth": True, "owner": sm.PROBE_EMAIL})
    tgt = sm.live_target(_cfg(tmp_path), ddb=ddb)
    assert (tgt.subdomain, tgt.owner, tgt.base) == ("app-e2e-probe", sm.PROBE_EMAIL, "example.test")
```

保留原文件里 `save_token` / `load_saved_token` 的全部用例（它们不碰签发；`test_cli_mints_and_saves_with_role_and_prints_no_token` 改成 monkeypatch `sm.Minter.from_config` 返回 `_minter(...)`，断言写出的记录 `{"token_use","role","kid","email","minted_at","ttl_seconds","token"}` 且 stdout 无 token）。删：`test_default_role_is_current_and_token_is_kid_form`、`test_console_family_tokens_use_console_current_kid`、`test_previous_role_uses_the_previous_kid`、`test_previous_role_fails_loudly_when_previous_is_empty`、`test_legacy_role_mints_the_old_kid_less_form`、`test_unknown_role_is_rejected`、`test_each_ssm_parameter_is_read_once`、`test_empty_secret_value_is_fatal_not_an_empty_key`、`test_trusted_idp_is_the_first_entry_and_missing_is_fatal`、`test_live_target_picks_a_require_auth_site_that_is_not_platform`、`test_live_target_is_fatal_when_no_site_qualifies`、`test_family_override_*`、`test_live_target_pages_through_the_whole_routing_table`（翻页逻辑保留在实现里，改写成一条对夹具站点在第二页的用例）。

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_session_mint.py -q -x`
Expected: `TypeError: from_config() got an unexpected keyword argument 'session'`（或 `http`）。

- [ ] **Step 3: 重写 `_session_mint.py`**

```python
#!/usr/bin/env python3
"""验收工具唯一的登录态入口（3c-final；spec §11.7 / ADR 0002）：**夹具签发器的客户端**。

四个 `verify_*`、`verify_kid_entry_live.py` 与 E2E 的会话 cookie fixture 都从这里拿 token；本模块**不持有
任何密钥**（KMS 之后本地也拿不到）。三条路：
- 站点会话：`sts.assume_role(site-builder-verifier)`（只有 `[Verification] verifier_trusted_principals` 里列的
  principal 能 assume）→ SigV4 `POST` auth 的 Function URL `/fixture-session` → 只给夹具域 `@e2e.invalid`、
  TTL ≤ 30 min、`role=current|previous`（就位期探针用 previous）。
- 升级码：拿夹具站点会话走**真实**的 `GET https://auth.{base}/console-session`，从 302 Location 里取 code。
- 面板会话：再 `GET https://console.{base}/api/session-callback?code=…`（经 CloudFront → Edge → panel），
  从 Set-Cookie 里取 `__Host-sb_console`。**这一步会消费那枚一次性升级码**（session-codes 表多一行，1 h TTL）。
所以带外签发的只有一种 token、一个域（ADR 0002）；`family=` 覆盖已删——KMS 之后没有任何组件能带外签 console
family，"console kid 签 site-session"这类跨 family 反例改由单测 + 产物公钥对账证明（plan D3）。

调用方接口沿用 `Minter.mint(token_use, email, ttl_seconds=, role=, name=)`。`--save FILE` 只许写进 `.scratch/`。
用不带路径的 python3 跑（CLAUDE.md）。

    python3 site-builder/scripts/_session_mint.py --token-use site-session --email probe@e2e.invalid \
        --role previous --ttl 600 --save rotation/site-previous.json
"""
from __future__ import annotations

import argparse
import configparser
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))
from permissions import FIXTURE_DOMAIN, is_fixture_email  # noqa: E402  夹具域的唯一定义（与 auth/session.py 等值）
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from _secure_write import write_private_text  # noqa: E402

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
SCRATCH_ROOT = ROOT / ".scratch"
ROLES = ("current", "previous")
TOKEN_USES = ("site-session", "console-upgrade", "console-session")
VERIFIER_ROLE_NAME = "site-builder-verifier"
AUTH_FN = "site-auth-service"
PROBE_EMAIL = f"probe@{FIXTURE_DOMAIN}"
FIXTURE_SITE_ID = "e2e-probe"
FIXTURE_MAX_TTL = 1800


def _strip(v: str) -> str:
    return v.split("#")[0].split(";")[0].strip()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _urllib_http(method: str, url: str, headers: dict, body: str | None):
    """→ (status, headers（http.client.HTTPMessage，支持 get_all）, text)。不跟随 302——Location 就是要读的东西。"""
    req = urllib.request.Request(url, method=method, headers=headers, data=body.encode() if body else None)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.headers, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode(errors="replace")


def _hdr(headers, name: str):
    """大小写不敏感取头；`set-cookie` 取全部（urllib 的 HTTPMessage 与测试替身的 dict 都支持）。"""
    if hasattr(headers, "get_all"):
        vals = headers.get_all(name) or []
        return vals if name.lower() == "set-cookie" else (vals[0] if vals else "")
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v if name.lower() == "set-cookie" and isinstance(v, list) else ([v] if name.lower() == "set-cookie" else v)
    return [] if name.lower() == "set-cookie" else ""


def _require_fixture_email(email) -> None:
    if not is_fixture_email(email):
        raise SystemExit(f"验收身份必须是 <local>@{FIXTURE_DOMAIN}（ADR 0002），得到 {email!r}——签发器也会拒，这里提前停")


class Minter:
    """夹具签发器客户端。`http(method, url, headers, body) -> (status, headers, text)` 可替换（测试）。"""

    def __init__(self, *, base_domain: str, region: str, account_id: str, function_url: str, session, http=None):
        self.base = base_domain
        self.region = region
        self.account_id = account_id
        self.function_url = function_url if function_url.endswith("/") else function_url + "/"
        self._session = session          # boto3.Session（或测试替身）；凭据不缓存，每次 mint 现 assume（D11）
        self._http = http or _urllib_http

    @classmethod
    def from_config(cls, config_path: Path = CONFIG_PATH, *, session=None, http=None) -> "Minter":
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(config_path)
        if not cfg.sections():
            raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")
        if _strip(cfg.get("Verification", "fixture_issuer", fallback="false")).lower() != "true":
            raise SystemExit("config.ini [Verification] fixture_issuer 不是 true——验收工具的登录态来自 auth 的 /fixture-session"
                             "（ADR 0002），先开它并重部 auth（deploy_auth.py 会建 site-builder-verifier 角色）")
        base = _strip(cfg["Platform"]["base_domain"])
        region = _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1"
        account = _strip(cfg["Platform"]["account_id"])
        if session is None:
            import boto3
            session = boto3.Session()
        url = session.client("lambda", region_name=region).get_function_url_config(FunctionName=AUTH_FN)["FunctionUrl"]
        return cls(base_domain=base, region=region, account_id=account, function_url=url, session=session, http=http)

    def _verifier_credentials(self) -> dict:
        """每次 mint 现 assume（D11）：角色会话上限 3600 s 而 E2E 约 37 min，缓存一份会贴着上限过期，症状是
        Function URL 403、读起来像授权配错。900 s 是 STS 允许的最小 DurationSeconds，一枚凭据只签一个请求。"""
        return self._session.client("sts", region_name=self.region).assume_role(
            RoleArn=f"arn:aws:iam::{self.account_id}:role/{VERIFIER_ROLE_NAME}",
            RoleSessionName=f"verify-{os.getpid()}-{int(time.time())}", DurationSeconds=900)["Credentials"]

    # ---- 站点会话：带外签发的唯一一种 token ----

    def site_session(self, email: str, *, ttl_seconds: int = FIXTURE_MAX_TTL, name: str | None = None,
                     role: str = "current") -> str:
        _require_fixture_email(email)
        if role not in ROLES:
            raise SystemExit(f"role 必须是 {ROLES} 之一，得到 {role!r}")
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        body = json.dumps({"email": email, "ttl_seconds": int(ttl_seconds),
                           "name": name or email.split("@")[0], "role": role})
        url = self.function_url + "fixture-session"
        req = AWSRequest(method="POST", url=url, data=body,
                         headers={"content-type": "application/json", "host": urllib.parse.urlparse(url).netloc})
        creds = self._verifier_credentials()
        SigV4Auth(Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]),
                  "lambda", self.region).add_auth(req)
        status, _, text = self._http("POST", url, dict(req.headers), body)
        if status != 200:
            raise SystemExit(f"/fixture-session 返回 {status}：{text[:200]}——"
                             "403 = 调用者不是 site-builder-verifier（本机凭据不在 verifier_trusted_principals 里？）；"
                             "404 = auth 没开 FIXTURE_ISSUER（重部 auth）")
        return json.loads(text)["token"]

    # ---- 升级码与面板会话：真实换取链路 ----

    def upgrade_code(self, email: str, *, site_session: str | None = None) -> str:
        tok = site_session or self.site_session(email)
        status, headers, _ = self._http("GET", f"https://auth.{self.base}/console-session",
                                        {"cookie": f"sb_session={tok}"}, None)
        loc = _hdr(headers, "location")
        if status != 302 or "/api/session-callback?code=" not in loc:
            raise SystemExit(f"/console-session 没有换出升级码：{status} {loc[:120]}——夹具站点会话没被 auth 接受？")
        return urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]

    def console_session(self, email: str, *, site_session: str | None = None) -> str:
        tok = site_session or self.site_session(email)
        code = self.upgrade_code(email, site_session=tok)
        status, headers, text = self._http(
            "GET", f"https://console.{self.base}/api/session-callback?code={urllib.parse.quote(code, safe='')}",
            {"cookie": f"sb_session={tok}"}, None)
        for c in _hdr(headers, "set-cookie"):
            name, _, rest = c.partition("=")
            if name.strip() == "__Host-sb_console":
                return rest.split(";")[0]
        raise SystemExit(f"/api/session-callback 没有下发面板会话：{status} {text[:120]}——panel 拒了升级码（夹具身份被 Edge 302？）")

    def mint(self, token_use: str, email: str, *, ttl_seconds: int = FIXTURE_MAX_TTL, role: str = "current",
             name: str | None = None) -> str:
        """六处调用方的兼容入口。`console-*` 两种 token 不接受 role/ttl（真实链路决定）。"""
        if token_use == "site-session":
            return self.site_session(email, ttl_seconds=ttl_seconds, name=name, role=role)
        if token_use == "console-upgrade":
            return self.upgrade_code(email)
        if token_use == "console-session":
            return self.console_session(email)
        raise SystemExit(f"token_use 必须是 {TOKEN_USES} 之一，得到 {token_use!r}")


# ---- 探针目标：常驻夹具站点 ---------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    subdomain: str
    owner: str
    base: str
    region: str

    @property
    def site_url(self) -> str:
        return f"https://{self.subdomain}.{self.base}/"

    @property
    def auth_host(self) -> str:
        return f"auth.{self.base}"

    @property
    def console_host(self) -> str:
        return f"console.{self.base}"


def live_target(config_path: Path = CONFIG_PATH, *, ddb=None) -> Target:
    """路由表里 owner == PROBE_EMAIL 且 require_auth=True 的那条（常驻夹具站点，ensure_fixture_site.py 建）。
    **必须翻页**（3c-1B-G A5）。不再冒充任何真实 owner（ADR 0002）。"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    base = _strip(cfg["Platform"]["base_domain"])
    region = _strip(cfg.get("Platform", "region", fallback="us-east-1")) or "us-east-1"
    table = _strip(cfg["Platform"]["routing_table"])
    if ddb is None:
        import boto3
        ddb = boto3.resource("dynamodb", region_name=region)
    t = ddb.Table(table)
    kwargs: dict = {}
    while True:
        page = t.scan(**kwargs)
        for it in page.get("Items", []):
            if it.get("require_auth") is True and it.get("owner") == PROBE_EMAIL:
                return Target(subdomain=str(it["subdomain"]), owner=PROBE_EMAIL, base=base, region=region)
        last = page.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last
    raise SystemExit(f"路由表 {table} 里没有 owner={PROBE_EMAIL} 的常驻夹具站点——先跑 "
                     "python3 site-builder/scripts/ensure_fixture_site.py（已翻完所有页）")
```

`save_token` / `load_saved_token` 原文照抄（含全部注释）；`main()`：

```python
def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--token-use", required=True, choices=("site-session", "console-upgrade"),
                    help="面板会话记录不接受：panel 只在写请求上验它，探针只发 GET")
    ap.add_argument("--email", default=PROBE_EMAIL)
    ap.add_argument("--role", default="current", choices=ROLES)
    ap.add_argument("--ttl", type=int, default=600, help="秒（≤ 1800）；升级码由链路决定 60 s")
    ap.add_argument("--save", required=True, metavar="FILE", help="写 JSON 记录（只许 .scratch/ 下）；不在终端打印 token")
    args = ap.parse_args(argv)
    m = Minter.from_config(CONFIG_PATH)
    token = m.mint(args.token_use, args.email, role=args.role, ttl_seconds=args.ttl)
    kid = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==")).get("kid")
    out = save_token(Path(args.save), {"token_use": args.token_use, "role": args.role, "kid": kid,
                                       "email": args.email, "minted_at": int(time.time()),
                                       "ttl_seconds": args.ttl, "token": token}, scratch_root=SCRATCH_ROOT)
    print(f"已写 {out}：{args.token_use} role={args.role} kid={kid}（token 不打印）")
    return 0
```

（`import base64` 加到顶部。）

- [ ] **Step 4: `ensure_fixture_site.py` + 测试（先红）**

`site-builder/deployer/tests/test_ensure_fixture_site.py`：

```python
"""`scripts/ensure_fixture_site.py`：幂等创建常驻夹具站点（spec §11.7 / ADR 0002）。"""
import sys
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "deployer/functions"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import ensure_fixture_site as efs  # noqa: E402


def _site(ddb, **over):
    item = {"site_id": {"S": efs.FIXTURE_SITE_ID}, "owner": {"S": efs.PROBE_EMAIL}, "status": {"S": "ACTIVE"},
            "tier": {"S": "static"}, "require_login": {"BOOL": True},
            "allowed_users": {"L": [{"S": efs.PROBE_EMAIL}]}, "collaborators": {"L": []}, "permissions_rev": {"N": "1"}}
    item.update(over)
    ddb.put_item(TableName="site-sites", Item=item)


def test_deploys_when_the_site_is_absent_and_then_converges_permissions(aws, monkeypatch):
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy",
                        lambda site_id, **kw: calls.append(("perm", site_id, kw)) or {"require_login": True, "allowed_users": [efs.PROBE_EMAIL]})
    out = efs.ensure(deploy=lambda fixture, owner, *, site_id=None, marker=None: calls.append(("deploy", fixture, owner, site_id)))
    assert calls[0] == ("deploy", "static-hello", efs.PROBE_EMAIL, efs.FIXTURE_SITE_ID)
    assert calls[1][1] == efs.FIXTURE_SITE_ID and calls[1][2] == {"actor": efs.PROBE_EMAIL, "require_login": True,
                                                                  "allowed_users": [efs.PROBE_EMAIL]}
    assert out == {"deployed": True, "permissions_changed": True}


def test_is_a_no_op_when_the_resident_site_is_already_correct(aws, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: pytest.fail("不该改权限"))
    out = efs.ensure(deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out == {"deployed": False, "permissions_changed": False}


def test_converges_permissions_without_redeploying_when_only_policy_drifted(aws, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, require_login={"BOOL": False}, allowed_users={"S": "org"})
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda site_id, **kw: calls.append(kw) or {})
    out = efs.ensure(deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert calls == [{"actor": efs.PROBE_EMAIL, "require_login": True, "allowed_users": [efs.PROBE_EMAIL]}]
    assert out["permissions_changed"] and not out["deployed"]


def test_refuses_when_the_site_id_is_held_by_a_non_fixture_owner(aws):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, owner={"S": "someone@example.test"})
    with pytest.raises(SystemExit, match="e2e.invalid"):
        efs.ensure(deploy=lambda *a, **k: pytest.fail("不该覆盖别人的站点"))


def test_deleted_tombstone_is_treated_as_absent(aws, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, status={"S": "DELETED"})
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: {})
    efs.ensure(deploy=lambda *a, **k: calls.append(a))
    assert calls, "墓碑行不是活站点，应当重新部署"
```

`site-builder/scripts/ensure_fixture_site.py`：

```python
#!/usr/bin/env python3
"""幂等创建**常驻夹具站点**（spec §11.7 / ADR 0002）：`site_id = e2e-probe`、owner `probe@e2e.invalid`、
static 站点（fixtures/static-hello）、`require_login=True`、`allowed_users = [probe@e2e.invalid]`。

它是部署验收的一步（DEPLOY.md）：`verify_session_token_semantics.py` / `verify_kid_entry_live.py` 只打这个站点，
不再冒充任何真实 owner。绕过 MCP 直接起状态机（deploy_fixture.py 那条路，含 per-site 部署租约），
所以 owner 可以是夹具域——MCP 建站的 owner 是 OAuth 身份，夹具域没有 OAuth 身份。

四种起点都处理：sites 行不存在 / DELETED 墓碑 / **路由行缺失** ⇒ 部署；存在但权限或**路由投影上的名单**
漂了 ⇒ 收敛（经 permissions.set_access_policy，真源 + 投影原子写）；存在但 owner 不是夹具域 ⇒ 拒绝
（有人占了这个 site_id，不覆盖别人的站点）。收敛后按**闸门自己那段查找**读回核对，核不到就响亮失败——
否则操作者会被闸门指回一个刚说"没问题"的脚本（执行时修订，Ruling R20）。
用不带路径的 python3 跑（CLAUDE.md）。
"""
from __future__ import annotations

import configparser
import contextlib
import os
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402  subdomain_for（子域拼法的唯一定义，别在这里手拼 f"app-{site_id}"）
import permissions  # noqa: E402
from _session_mint import FIXTURE_SITE_ID, PROBE_EMAIL, live_target  # noqa: E402  三者的唯一定义

CONFIG_PATH = ROOT / "site-builder" / "config.ini"
FIXTURE = "static-hello"

# 键 → (小节, 选项, 默认)。permissions.py 与 common.py 按环境变量找表（与 E2E 的 _platform_env 同一批键）。
_ENV_FROM_CONFIG = (
    ("SITES_TABLE", "Deployer", "sites_table", "site-sites"),
    ("ADMINS_TABLE", "Deployer", "admins_table", "site-admins"),
    ("OPS_LOG_TABLE", "Panel", "ops_log_table", "site-ops-log"),
    ("ROUTING_TABLE", "Platform", "routing_table", None),
    ("BASE_DOMAIN", "Platform", "base_domain", None),
    ("AWS_DEFAULT_REGION", "Platform", "region", "us-east-1"),
)

# 小助手（各三五行，实现时按这些名字写）：`_site_row(ddb)` / `_route_row(ddb)` 读两张表的行（
# ConsistentRead）；`_wanted_users()` = `[PROBE_EMAIL]`；`_site_needs_convergence(site)` 判真源上的
# require_login / allowed_users；`_route_users_drifted(route)` 判**路由投影**上的名单（`live_target`
# 不看名单，所以这一条要自己判）；`_gate_target(config_path)` 用 `live_target` 查一次、`SystemExit`
# 时返回 None——收敛后的读回核对必须走闸门自己那段查找，否则会出现"本脚本说没问题、闸门说先跑本脚本"
# 的死循环（执行时修订，Ruling R20）。


@contextlib.contextmanager
def _config_env(config_path: Path):
    """把 config.ini 的表名/域名/区域**无条件**导成环境变量，退出时还原（同 E2E 的 `_platform_env`）。

    **不用 `os.environ.setdefault`**（执行时修订，见 SDD ledger Task 12 review Important 1）：那会让
    进程里已有的 `SITES_TABLE` / `ROUTING_TABLE` 等悄悄盖过 config.ini —— 而 CLAUDE.md 的硬约束是
    "config.ini 是唯一取值来源"。症状是脚本去**别的账号/别的表**读写夹具站点，而它一切正常地退 0。
    任一取值为空 ⇒ `SystemExit`，不从环境变量兜底。还原是因为本函数可被 import 调用（单测、验收编排），
    留下进程级副作用会让同一进程里的另一个模块去错的表读数。
    """
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    if not cfg.sections():
        raise SystemExit(f"{config_path} 读空了——configparser 对缺失文件是静默的")
    want = {}
    for key, section, option, default in _ENV_FROM_CONFIG:      # 模块级表：键 → (小节, 选项, 默认)
        raw = cfg.get(section, option, fallback=default) or ""
        want[key] = raw.split("#")[0].strip() or (default or "")
    missing = sorted(k for k, v in want.items() if not v)
    if missing:
        raise SystemExit(f"{config_path} 里这些取值是空的：{missing}——回填后再跑"
                         "（config.ini 是唯一取值来源，本脚本不从环境变量兜底）")
    saved = {k: os.environ.get(k) for k in want}
    os.environ.update(want)
    try:
        yield want
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _deploy_default(fixture: str, owner: str, *, site_id=None, marker=None):
    """`deploy_fixture.main` 轮询到终态后 **`sys.exit(0/1)`**（它是给 CLI 写的）——成功的 exit 0 要吞掉，
    否则本函数还没来得及收敛权限就把进程带走了；非 0 原样上抛（部署失败不是本脚本能修的）。"""
    import deploy_fixture
    try:
        deploy_fixture.main(str(ROOT / "site-builder" / "fixtures" / fixture), owner, site_id=site_id, marker=marker)
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def ensure(config_path: Path = CONFIG_PATH, *, deploy=_deploy_default, ddb=None) -> dict:
    """三种起点：不存在 / DELETED 墓碑 / 路由行缺失 ⇒ 部署；权限或路由投影漂了 ⇒ 收敛；
    owner 不是夹具域 ⇒ 拒绝。**最后按闸门自己那段查找读回核对**（执行时修订，Ruling R20）。"""
    with _config_env(config_path) as env:
        ddb = ddb or boto3.client("dynamodb", region_name=env["AWS_DEFAULT_REGION"])
        site = _site_row(ddb)
        if site and site.get("status", {}).get("S") != "DELETED":
            owner = site.get("owner", {}).get("S", "")
            if not permissions.is_fixture_email(owner):
                raise SystemExit(f"site_id {FIXTURE_SITE_ID} 已被 owner={owner!r} 占用，不是夹具域 "
                                 f"@{permissions.FIXTURE_DOMAIN}——不覆盖别人的站点；"
                                 "换 FIXTURE_SITE_ID 或先处理那个站点")
            live = True
        else:
            live = False
        route = _route_row(ddb)                  # 路由投影是 Edge 的真源，**也要收敛**
        deployed = False
        if not live or not route:
            why = "sites 行缺失或已是墓碑" if not live else "路由行缺失（只有部署路径会建它）"
            print(f"  部署常驻夹具站点 {FIXTURE_SITE_ID}（{FIXTURE}，owner {PROBE_EMAIL}）：{why}…")
            deploy(FIXTURE, PROBE_EMAIL, site_id=FIXTURE_SITE_ID)
            deployed = True
            site, route = _site_row(ddb), _route_row(ddb)
        changed = False
        if _site_needs_convergence(site) or _route_users_drifted(route) or _gate_target(config_path) is None:
            permissions.set_access_policy(FIXTURE_SITE_ID, actor=PROBE_EMAIL, require_login=True,
                                          allowed_users=_wanted_users())
            changed = True
        if _gate_target(config_path) is None:    # 读回核对：**用闸门自己那段查找**（`_session_mint.live_target`）
            route = _route_row(ddb)
            # 整行打出来，不在这里逐个点名字段：闸门的判据只有它自己那一份定义，
            # 本脚本复述任何一个字段名都会变成第二份判据。
            raise SystemExit(
                f"收敛之后闸门在路由表里仍然找不到 {common.subdomain_for(FIXTURE_SITE_ID)}"
                f"（当前那行：{route or '不存在'}）——常见原因是权限事务的投影那一半没写成"
                "（返回 route_synced=False，真源已写、路由没写）。先看这条路由行是否存在、"
                "是否被别的写入方踩过，再重跑本脚本")
        print(f"  夹具站点 {FIXTURE_SITE_ID}：deployed={deployed} permissions_changed={changed} "
              f"→ https://{common.subdomain_for(FIXTURE_SITE_ID)}.{env['BASE_DOMAIN']}/"
              f"（只有 {PROBE_EMAIL} 能进）")
        return {"deployed": deployed, "permissions_changed": changed}


def main() -> int:
    ensure()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

（`have_users` 那行的三元表达式写清楚：`changed_needed = have_login is not True or not isinstance(have_users, list) or sorted(have_users) != want_users`——实现时用这一行，不要照抄上面压成一行的写法。）

- [ ] **Step 5: `deploy_fixture.py` 默认 owner**

`main(fixture_dir, owner: str = "fixture@e2e.invalid", …)`、`ap.add_argument("--owner", default="fixture@e2e.invalid", …)`；docstring 里 `fixture@test` 改为 `fixture@e2e.invalid` 并加一句"夹具域（ADR 0002）：Edge 只在夹具站点上认夹具会话，所以 E2E 建的站点 owner 必须在这个域"。

- [ ] **Step 6: 四个 verify_* 与 kid 探针**

`verify_console_e2e.py`：三个身份改 `f"conse2e-owner-{suf}@e2e.invalid"` / outsider / collab 同域；`mint()` 改 `return minter.mint("console-session" if scope == "console" else "site-session", email)`（去掉 `ttl_seconds`——console 链路不接受）；`from_config(CFG_PATH)`（去掉 router config 参数）。其余断言不动（"站点会话当面板会话必 401"这类仍成立）。

`verify_api_key_e2e.py`：`owner = f"apikeye2e-{suf}@e2e.invalid"`；`mint(scope)` 同上；`sm.Minter.from_config(CFG_PATH)`。

`verify_analytics_e2e.py`：四个身份改夹具域；`mint(email, scope)` 同上；`from_config(ROOT / "site-builder" / "config.ini")`。

`verify_session_token_semantics.py`：判据收缩为（docstring 与 `Tokens` 同步改）：
  1. 遮蔽 cookie 排在合法会话前时 `/console-session` 仍换出升级码；
  2. 同上，Edge 侧站点请求仍 200；14 条遮蔽亦然；
  3. **未知 kid** 的 token（本地造：header `kid=site-rs-v9`、随机 256 字节签名）必 302；
  4. **夹具会话投给真实 org 站点必 302**（ADR 0002 边界；路由表里找一条 `allowed_users="org"`、owner 不是夹具域、`require_auth=True` 的路由——没有时该条报 `skip: 账号里没有 org 站点`，**不算失败**）；
  5. 正对照：单枚合法夹具会话进夹具站点 200；
  6. 负对照：无 cookie 302。
  用途混用与跨 family 三条改由静态证据给（docstring 写明：`auth/tests/test_verifier_allowlist.py` 的 token_use 矩阵与 `router/.../test_edge_kid_allowlist.py::test_console_kid_is_not_in_the_edge_allowlist`，加 `verify_deployed_edge.sh` 的公钥精确对账）。`tokens = Tokens(good=minter.mint("site-session", owner, ttl_seconds=600), unknown_kid=_unknown_kid_token(owner))`；`_unknown_kid_token` 本地构造（不需要密钥：签名段随机 256 字节 base64url）。`test_verify_session_token_semantics.py` 的三条判据措辞守卫改成：判据里没有 `typ`；`Tokens` 恰好两枚（good、unknown_kid）；docstring 点名两个静态证据文件路径且它们存在。

`verify_kid_entry_live.py`：`Tokens(site_kid, unknown_kid)`（删 legacy / console_kid / wrong_use 与它们的判据）；默认判据：夹具会话进夹具站点 200、未知 kid 302 且不回落、`/console-session` 换出升级码；`--role current|previous`：`minter.site_session(PROBE_EMAIL, role=role)` 200 + `minter.console_session(...)` 拿到面板 cookie（消费一枚码）；`--retired-token FILE` 不变；`--self-test` 的理想应答器与四条坏路径按新判据缩成三条；`test_verify_kid_entry_live.py` 里 `test_legacy_positive_control_is_omitted…`、`test_edge_accepts_the_cross_family_token_once_the_console_kid_leaks_in`、`test_the_old_two_variable_probe_shape_stays_green_on_the_same_leak`、`test_break_family_targets_exactly_the_four_kid_entry_assertions` 删（跨 family 的证明移到 Edge 单测 `test_console_kid_is_not_in_the_edge_allowlist` + Task 14 的产物公钥对账），其余按新 `Tokens` 形态改。

- [ ] **Step 7: E2E**

`test_e2e_fixtures.py`：

```python
E2E_EMAIL = "e2e-bot@e2e.invalid"      # 夹具域（ADR 0002）：Edge 只在夹具站点上认夹具会话；deploy_fixture 的默认 owner 也在这个域


@pytest.fixture(scope="module")
def _minter(cfg):
    sys.path.insert(0, str(ROOT / "site-builder/scripts"))
    import _session_mint as sm
    return sm.Minter.from_config(ROOT / "site-builder/config.ini")


@pytest.fixture
def session_cookie(_minter):
    """每条用例一枚新的夹具会话（TTL 30 min 上限，E2E 全程约 37 min ⇒ module 级会中途过期，D11）。"""
    return "sb_session=" + _minter.site_session(E2E_EMAIL, name="E2E Bot")
```

`created["author"] == "e2e@test.com"` 与 `probe["author"] == "e2e@test.com"` 改 `E2E_EMAIL`；`test_update_visible_and_undeploy_404` 里 undeploy job 的 `"owner": "fixture@test"` 改 `"fixture@e2e.invalid"`（与 `deploy_fixture` 的新默认 owner 同域）；删 `test_legacy_site_migrates_to_blue_green_and_then_survives_a_bad_update` 整条与文件头注释里提到 `migrate_sites_to_blue_green._public_check` 的那两行（改成 `smoke_test._head → urlopen()`，因为 `_ensure_default_ssl_trust` 的理由仍成立——`deploy_lambda_site` 的健康门在进程外，但 `verify_*` 类在进程内直连的生产代码仍走默认上下文）。

- [ ] **Step 8: 跑绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_session_mint.py tests/test_ensure_fixture_site.py tests/test_verify_session_token_semantics.py tests/test_verify_kid_entry_live.py tests/test_deploy_fixture_flags.py tests/test_verify_script_exit_contracts.py -q`；`RUN_E2E` 不设时 `tests/test_e2e_fixtures.py` 应全部 skip 且**可收集**：`.venv/bin/pytest tests/test_e2e_fixtures.py -q`。
Expected: 全绿 / 全 skip。

- [ ] **Step 9: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/scripts/_session_mint.py site-builder/scripts/ensure_fixture_site.py site-builder/scripts/deploy_fixture.py \
        site-builder/scripts/verify_session_token_semantics.py site-builder/scripts/verify_kid_entry_live.py \
        site-builder/scripts/verify_console_e2e.py site-builder/scripts/verify_api_key_e2e.py site-builder/scripts/verify_analytics_e2e.py \
        site-builder/deployer/tests/test_session_mint.py site-builder/deployer/tests/test_ensure_fixture_site.py \
        site-builder/deployer/tests/test_e2e_fixtures.py site-builder/deployer/tests/test_verify_session_token_semantics.py \
        site-builder/deployer/tests/test_verify_kid_entry_live.py
git commit -m "feat(asset-v1/08): 验收身份改夹具签发器（assume site-builder-verifier → /fixture-session；console 走真实换取链路）；常驻夹具站点 e2e-probe；六处调用方与 E2E 切夹具域"
```

---

### Task 13：账号信任边界闸门——KMS 层进、HS 层与迁移通道出、schema 6、基线不再 tracked

**Files:**
- Modify: `site-builder/scripts/verify_account_trust_boundary.py`
- Modify: `site-builder/deployer/tests/test_verify_account_trust_boundary.py`
- Modify: `site-builder/deployer/tests/test_blind_spot_coverage.py`（只在它引用被删符号时）
- Modify: `site-builder/scripts/metamorphic_trust_boundary.py`（**执行时补进清单，见 SDD ledger Ruling R21**：闸门守卫的变形/元测试 harness，威胁模型文档与 merged review §9 引它作证据，原 plan 里没有任何 Task 认领它。改法：删/替换 5 条已过时的变形（HS 层与迁移通道那批），加 KMS 层变形（`kms-sign` / `kms-self-authorize` grant、`_compare_kms` 漂移、`assert_edge_artifacts` 三条各一），本地跑到 exit 0。**它运行时会临时改工作树，所以要在 review 之后串行做**）
- Modify: `.gitignore`（`site-builder/scripts/account_trust_baseline.json`）；`git rm --cached` 该文件（D1）
- Test: `deployer/tests/test_verify_account_trust_boundary.py`、`test_blind_spot_coverage.py`、`test_verify_script_exit_contracts.py`

**Interfaces:**
- Consumes: `session_keys.load_session_keys / key_refs`（RS 行）、`session_kms.describe_public_key`。
- Produces（脚本内部与测试依赖）:
  - `BASELINE_SCHEMA = 6`；`load_baseline(path)`：不存在 ⇒ `{"schema": 6, "principals": {}, ...空分节}` 并在 stderr 说明"没有基线：只能 `--update-baseline` 生成，不能出结论"；`schema != 6` ⇒ `SystemExit`（无迁移通道，指示删掉重生成）
  - 动作类：`A_KMS_SIGN = ("kms:Sign",)`、`A_KMS_SELF_AUTHORIZE = ("kms:PutKeyPolicy", "kms:CreateGrant")`；`ACTIONS_OTHER = A_READ_PARAM + A_KMS_SIGN + A_KMS_SELF_AUTHORIZE`（`A_READ_OBJECT` 与 `A_READ_CODE` 删——Edge 产物与 asset 不再承载密钥）；`simulate()` 对 `ACTIONS_OTHER` 那组带 `ContextEntries`（`kms:SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256`、`kms:MessageType=RAW`，字符串类型）。**`kms:Sign` 还要按 `kms:MessageType` 的另一个取值再模拟一腿（`DIGEST`），两腿的判定取并集**（`merge_allowed`，allowed 优先）——**执行时补，见 SDD ledger 终审 Important 1**：只喂合同值 `RAW` 时，一条 `StringEquals kms:MessageType: DIGEST` 的 `kms:Sign` 语句会被模拟器判成 implicit deny 而漏报，而 PKCS#1 v1.5 下调用方在本地先 hash 再走 DIGEST 签出的字节与 RAW 逐字节相同 ⇒ 那是**真实的冒充能力**。裸 `dict.update` 在多腿下是错的：后一腿的 implicitDeny 会抹掉前一腿的 allowed（假绿）。`KMS_MESSAGE_TYPES` 以合同值开头（闸门必须测平台真正走的那条路）。进度输出报的腿数由这张表派生，不要写死"2 次"
  - grant：`G_KMS_SIGN = "kms-sign"`（`:<kid>`）、`G_KMS_SELF_AUTHORIZE = "kms-self-authorize"`（`:<kid>`）、`G_READ_LOGIN_FLOW` 不变；`is_secret_grant(g)` = `g.startswith("kms-sign:") or g.startswith("kms-self-authorize:")`；**删** `G_READ_EDGE_CODE / G_READ_EDGE_ASSET / G_READ_JWT_PARAM / SECRET_GRANTS / G_READ_SESSION_KEY / JWT_PARAM_NAME / LABEL_LEGACY / check_legacy_param`
  - `Targets`：**删** `edge_code_arns / edge_assets / jwt_parameter / session_key_parameters`；**加** `kms_keys: dict[str, str]`（kid → key ARN）；`other_resources()` = kms key ARN ∪ login-flow 参数 ARN
  - `undecided_resource_class`：kms key ARN → `f"kms-key:{kid}"`；login-flow 不变；删 `jwt-param` / `session-key:` / `edge-asset` / `edge-code`
  - `NON_KID_LABELS = (LABEL_LOGIN_FLOW,)`；`grants_for_labels(kid)` → `{f"kms-sign:{kid}", f"kms-self-authorize:{kid}"}`；`classes_for_labels(kid)` → `{f"kms-key:{kid}"}`；`baseline_kids(baseline)` 读 `baseline["kms"]` 的键
  - bundle 新分节 `"kms": {kid: {"arn_fp": str, "key_policy_fp": str, "key_spec": str, "key_usage": str, "spki_sha256": str, "grants": [str, ...]}}`（`grants` 是 `ListGrants` 每条 grant 的 `(GranteePrincipal, Operations, Constraints)` 规范化后的指纹）；`_compare_kms(rep, base, now, *, new_keys, retired_keys)`：kid 新增未声明 / 消失未声明 / 任一字段变化 ⇒ `rep.kms_drift`（红）；声明过的新增 / 消失 ⇒ `rep.migration_grants`
  - `facts` 只剩 `{"principals_with_missing_context": int}`；**删** `edge_code_targets_carrying_live_key / edge_assets_carrying_live_key / session_keys` 与 `_check_console_key_not_in_edge`
  - Edge 产物**三条硬断言**（不落 facts、连 `--update-baseline` 一起挡）：`assert_edge_artifacts(code_hits, asset_hits, *, site_spki_b64s, console_spki_b64s, login_flow_value)`——当前关联版本的 `index.py` 必须含**每一把** site kid 的 `spki_b64`（缺 = 全员 302，部署的不是这份配置）、**不得**含任一 console kid 的 `spki_b64`（spec §4.1）、**不得**含 login-flow 值（既有）；扫描仍用 `edge_code_arns_carrying_keys` / `assets_carrying_keys` 的机制，扫描值表 = `{f"site:{kid}": spki_b64, f"console:{kid}": spki_b64, "login-flow": value}`
  - `REQUIRED_GRANT_PREFIXES` 加正向控制：`"auth": ("kms-sign:site-", "kms-sign:console-")`、`"panel": ("kms-sign:console-",)`（丢了 = 登录 / 面板会话全部 500）；`required` 分节多两个键 `auth` / `panel`（角色名 `site-auth-service-role` / panel 的 `ROLE_NAME`——从 `deploy_panel.ROLE_NAME` 读，不手抄）
  - **删** `--migrate-from-schema`、`--migrate-baseline-only`、`migrate_baseline_3_to_4 / 4_to_5`、`undecided_members_v4`、`undecided_item_fp`、`_list_of_v4_fingerprints`、`coverage.schema4_fingerprints`、`_compare_coverage` 的 `now_v4` 参数与 v4 分支、`coverage_form`（只剩可分解一种形态，改为 `_check_shape` 的谓词）、`--no-asset-scan`（asset 不再承载密钥；login-flow / console 公钥的 asset 扫描只看**当前** asset——历史 asset 里的 console 公钥不构成风险，login-flow 那条历史 asset 早已由 1B 扫过）

- [ ] **Step 1: 测试改动（先红）——按三类处理**

删除（连同它们的夹具 `_targets_sk` / `_SK_ARNS`）：`test_asset_grant_disappears_when_the_asset_no_longer_carries_the_key`、`test_every_live_key_asset_is_probed_not_only_the_current_one`、`test_the_legacy_grant_string_exists_only_for_migration`、`test_old_baseline_schema_hard_fails`（改写见下）、`test_migration_only_accepts_schema_3_or_4_to_5`、`test_a_schema_5_baseline_on_disk_must_carry_decomposable_members`、`test_migrate_baseline_only_refuses_every_path_to_5_because_members_need_a_live_run`、`test_schema4_fingerprints_in_a_snapshot_must_be_real_fingerprints`、`test_no_asset_scan_may_not_produce_a_verdict_or_rewrite_the_baseline`、`test_incomplete_asset_scan_cannot_be_replayed_as_a_verdict`、`test_asset_scan_complete_must_be_a_true_bool`、`test_session_key_grants_are_per_kid_and_separate_from_legacy`、`test_session_key_params_are_simulated_and_classified_by_kid`、`test_console_key_inside_edge_artifacts_is_red`、`test_multi_key_scan_downloads_each_artifact_once_and_reports_per_key`（改写为公钥版）、`test_migrate_3_to_4_is_structural_only`、`test_bundle_shape_accepts_session_key_facts_and_rejects_unknown_fact_keys`、`test_declaring_legacy_does_not_also_release_the_edge_artifact_grants`、`test_load_baseline_names_the_migration_channel_for_a_schema_4_file`、`test_empty_legacy_param_is_accepted_so_l3_does_not_blow_up_the_gate`、`test_matching_non_empty_legacy_param_is_accepted`、`test_mismatched_non_empty_legacy_param_is_still_rejected`、`test_the_legacy_parameter_is_still_tracked_and_still_produces_its_grant`、`test_a_schema_4_baseline_is_compared_by_the_old_hashes_and_absorbs_nothing`、`test_undecided_item_fp_carries_no_principal_name`。

改写：所有在 grant 字面量里写 `read-jwt-param` / `read-session-key:*` / `read-edge-code` / `read-edge-asset` 的用例改用 `kms-sign:site-rs-v1` / `kms-sign:console-rs-v1`（"能读密钥"的语义换成"能签"）；`_GRANT_RE` 文法改为

```python
_GRANT_RE = re.compile(
    r"(?:invoke-platform|replace-platform-code)(?:@alias|@version)?:[A-Za-z0-9._-]+"
    r"|invoke-site(?:@alias|@version)?:(?:all|some\(\d+\):" + _FP_RE + r")"
    r"|kms-sign:(?:site|console)-rs-v\d+"
    r"|kms-self-authorize:(?:site|console)-rs-v\d+"
    r"|read-login-flow-secret")
```

`test_baseline_schema_is_current` 的分节清单加 `kms`、删 `facts.session_keys`；**所有直接读 `_BASELINE` 文件的用例**（`test_doc_counts_come_from_the_baseline`、`test_no_unclassified_principal_in_baseline`、`test_baseline_schema_is_current`、`test_baseline_carries_no_account_values` 等）改成：`if not _BASELINE.exists(): pytest.skip("本地无基线（gitignored；采用者首跑 --update-baseline 生成）")`，且新增一条**正对照**用 `write_baseline` 从合成 bundle 写到 `tmp_path` 再跑同一组断言（保证 skip 不是空转）。`test_doc_counts_come_from_the_baseline` 的 `expected` 表按 D12 改：删 `带活密钥的asset` / `带活密钥的Edge代码目标`，`可读密钥` 改名 `可签会话`（`is_secret_grant` 现在就是 kms 两类），加 `kms_key 数 = len(data["kms"])`。

新增（放在文件末尾新节 `# ---- 3c-final：KMS 层 ----`）：

```python
KEY = {"site-rs-v1": "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000001",
       "console-rs-v1": "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-000000000002"}


def _targets_kms(g):
    return g.Targets(platform_functions=(), site_functions=(), kms_keys=dict(KEY),
                     login_flow_parameter="arn:aws:ssm:us-east-1:111111111111:parameter/site-builder/login-flow-secret")


def test_kms_sign_and_self_authorize_are_per_kid_grants_and_both_count_as_impersonation():
    g = _gate()
    t = _targets_kms(g)
    sign_site = g.grants_from_decisions({f"kms:Sign|{KEY['site-rs-v1']}": "allowed"}, t)
    grant_console = g.grants_from_decisions({f"kms:CreateGrant|{KEY['console-rs-v1']}": "allowed"}, t)
    policy_console = g.grants_from_decisions({f"kms:PutKeyPolicy|{KEY['console-rs-v1']}": "allowed"}, t)
    assert sign_site == {"kms-sign:site-rs-v1"}
    assert grant_console == policy_console == {"kms-self-authorize:console-rs-v1"}
    assert all(g.is_secret_grant(x) for x in sign_site | grant_console)
    assert not g.is_secret_grant("read-login-flow-secret") and not g.is_secret_grant("invoke-platform:site-panel")


def test_kms_get_public_key_is_not_a_grant():
    g = _gate()
    assert g.grants_from_decisions({f"kms:GetPublicKey|{KEY['site-rs-v1']}": "allowed"}, _targets_kms(g)) == set()


def test_kms_keys_are_simulated_with_the_contract_context_and_classified_by_kid():
    g = _gate()
    t = _targets_kms(g)
    assert set(KEY.values()) <= set(t.other_resources())
    assert g.undecided_resource_class(KEY["site-rs-v1"], t) == "kms-key:site-rs-v1"
    calls = []

    class _IAM:
        def get_paginator(self, name):
            class _P:
                def paginate(self, **kw):
                    calls.append(kw); return iter(())
            return _P()
    g.simulate(_IAM(), "arn:aws:iam::111111111111:role/x", t)
    ctx = {(e["ContextKeyName"], tuple(e["ContextKeyValues"])) for c in calls for e in c.get("ContextEntries", [])}
    assert ("kms:SigningAlgorithm", ("RSASSA_PKCS1_V1_5_SHA_256",)) in ctx and ("kms:MessageType", ("RAW",)) in ctx


def test_hs_era_symbols_are_gone():
    g = _gate()
    for name in ("JWT_PARAM_NAME", "LABEL_LEGACY", "G_READ_JWT_PARAM", "G_READ_SESSION_KEY", "G_READ_EDGE_CODE",
                 "G_READ_EDGE_ASSET", "SECRET_GRANTS", "check_legacy_param", "migrate_baseline_3_to_4",
                 "migrate_baseline_4_to_5", "undecided_members_v4", "undecided_item_fp", "coverage_form",
                 "_check_console_key_not_in_edge"):
        assert not hasattr(g, name), name
    src = _SCRIPT.read_text(encoding="utf-8")
    for bad in ("--migrate-from-schema", "--migrate-baseline-only", "--no-asset-scan", "schema4_fingerprints",
                "edge_code_targets_carrying_live_key", "edge_assets_carrying_live_key"):
        assert bad not in src, bad


def _kms_entry(**over):
    base = {"arn_fp": "aaaa-bbbb-cccc-dddd", "key_policy_fp": "1111-2222-3333-4444", "key_spec": "RSA_2048",
            "key_usage": "SIGN_VERIFY", "spki_sha256": "0" * 64, "grants": []}
    base.update(over); return base


def test_kms_section_red_on_policy_change_grant_or_undeclared_key_add_or_remove():
    g = _gate()
    base = {"site-rs-v1": _kms_entry(), "console-rs-v1": _kms_entry(spki_sha256="1" * 64)}
    same = json.loads(json.dumps(base))
    rep = g.Report(); g._compare_kms(rep, base, same, new_keys=(), retired_keys=())
    assert not rep.kms_drift
    for mutate, why in (
        (lambda d: d["site-rs-v1"].__setitem__("key_policy_fp", "9999-9999-9999-9999"), "key policy 变了"),
        (lambda d: d["site-rs-v1"]["grants"].append("abcd-abcd-abcd-abcd"), "多了一条 grant"),
        (lambda d: d["site-rs-v1"].__setitem__("spki_sha256", "f" * 64), "公钥换了"),
        (lambda d: d.__setitem__("site-rs-v2", _kms_entry()), "未声明的新 key"),
        (lambda d: d.pop("console-rs-v1"), "未声明的 key 消失"),
    ):
        now = json.loads(json.dumps(base)); mutate(now)
        rep = g.Report(); g._compare_kms(rep, base, now, new_keys=(), retired_keys=())
        assert rep.kms_drift and not rep.ok, why


def test_declared_new_or_retired_key_lands_in_the_green_migration_bucket():
    g = _gate()
    base = {"site-rs-v1": _kms_entry()}
    now = {**base, "site-rs-v2": _kms_entry(spki_sha256="2" * 64)}
    rep = g.Report(); g._compare_kms(rep, base, now, new_keys=("site-rs-v2",), retired_keys=())
    assert rep.ok and rep.migration_grants
    rep = g.Report(); g._compare_kms(rep, now, base, new_keys=(), retired_keys=("site-rs-v2",))
    assert rep.ok and rep.migration_grants


def test_bundle_shape_requires_the_kms_section_and_only_the_missing_context_fact():
    g = _gate()
    assert set(g.BUNDLE_SHAPE["facts"]) == {"principals_with_missing_context"}
    assert set(g.BUNDLE_SHAPE["kms"]["*"]) == {"arn_fp", "key_policy_fp", "key_spec", "key_usage", "spki_sha256", "grants"}
    assert "schema4_fingerprints" not in g.BUNDLE_SHAPE["coverage"]


def test_edge_artifact_assertions_fail_closed_in_both_directions():
    g = _gate()
    site, console = "U0lURQ==", "Q09OU09MRQ=="
    g.assert_edge_artifacts({"site:site-rs-v1": ["code"], "console:console-rs-v1": [], "login-flow": []},
                            {"site:site-rs-v1": ["a.zip"], "console:console-rs-v1": [], "login-flow": []},
                            site_kids=["site-rs-v1"], console_kids=["console-rs-v1"])
    with pytest.raises(SystemExit, match="site-rs-v1"):        # 当前 Edge 没带 site 公钥 = 全员 302
        g.assert_edge_artifacts({"site:site-rs-v1": [], "console:console-rs-v1": [], "login-flow": []},
                                {"site:site-rs-v1": [], "console:console-rs-v1": [], "login-flow": []},
                                site_kids=["site-rs-v1"], console_kids=["console-rs-v1"])
    with pytest.raises(SystemExit, match="console-rs-v1"):     # console 公钥进了 Edge（spec §4.1）
        g.assert_edge_artifacts({"site:site-rs-v1": ["code"], "console:console-rs-v1": ["code"], "login-flow": []},
                                {"site:site-rs-v1": ["a"], "console:console-rs-v1": [], "login-flow": []},
                                site_kids=["site-rs-v1"], console_kids=["console-rs-v1"])
    with pytest.raises(SystemExit, match="login-flow"):
        g.assert_edge_artifacts({"site:site-rs-v1": ["code"], "console:console-rs-v1": [], "login-flow": ["code"]},
                                {"site:site-rs-v1": ["a"], "console:console-rs-v1": [], "login-flow": []},
                                site_kids=["site-rs-v1"], console_kids=["console-rs-v1"])


def test_schema_six_has_no_migration_channel(tmp_path):
    g = _gate()
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"schema": 5, "principals": {}}))
    with pytest.raises(SystemExit, match="重生成"):
        g.load_baseline(p)
    p.write_text(json.dumps({"schema": 3, "principals": {}}))
    with pytest.raises(SystemExit):
        g.load_baseline(p)


def test_missing_baseline_is_not_a_verdict(tmp_path, capsys, monkeypatch):
    g = _gate()
    monkeypatch.setattr(g, "BASELINE_PATH", tmp_path / "nope.json")
    empty = g.load_baseline(g.BASELINE_PATH)
    assert empty["schema"] == g.BASELINE_SCHEMA and empty["principals"] == {}
    assert "--update-baseline" in capsys.readouterr().err


def test_baseline_file_is_gitignored_not_tracked():
    rel = "site-builder/scripts/account_trust_baseline.json"
    tracked = subprocess.run(["git", "ls-files", rel], cwd=_ROOT, capture_output=True, text=True).stdout.strip()
    assert tracked == "", "基线含单账号实测，不随资产分发（ADR 0005）"
    ign = subprocess.run(["git", "check-ignore", "-q", rel], cwd=_ROOT).returncode
    assert ign == 0, "基线路径必须在 .gitignore 里，否则下次 git add -A 又会把它加回来"


def test_auth_and_panel_signing_grants_are_positive_controls():
    g = _gate()
    assert g.REQUIRED_GRANT_PREFIXES["auth"] == ("kms-sign:site-", "kms-sign:console-")
    assert g.REQUIRED_GRANT_PREFIXES["panel"] == ("kms-sign:console-",)
```

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -x -k "kms or hs_era or schema_six or missing_baseline or gitignored or positive_controls"`
Expected: `AttributeError`（`Targets` 没有 `kms_keys` 等）。

- [ ] **Step 3: 改脚本**

按接口清单逐项落地。几段关键实现：

```python
# ---- 动作等价类 ----
A_INVOKE = ("lambda:InvokeFunction",)
A_REPLACE = ("lambda:UpdateFunctionCode",)
A_READ_PARAM = ("ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory")
# 3c-final：签名能力（spec §1 的 sign:kms-direct / sign:kms-self-authorize）。key policy 是默认的 root 委派（ADR 0001），
# 所以 identity policy 上的 kms:Sign 就是能签；PutKeyPolicy / CreateGrant 是"先给自己授权再签"。
A_KMS_SIGN = ("kms:Sign",)
A_KMS_SELF_AUTHORIZE = ("kms:PutKeyPolicy", "kms:CreateGrant")
ACTIONS_FUNCTION = A_INVOKE + A_REPLACE
ACTIONS_OTHER = A_READ_PARAM + A_KMS_SIGN + A_KMS_SELF_AUTHORIZE
# 模拟 kms:Sign 时喂给 Condition 的上下文：auth/panel 的语句带 SigningAlgorithm / MessageType 两个 StringEquals，
# 不给上下文时模拟器判"缺上下文"⇒ 平台角色的必需 grant 会从结果里消失、正向控制假红。
KMS_CONTEXT = [{"ContextKeyName": "kms:SigningAlgorithm", "ContextKeyValues": ["RSASSA_PKCS1_V1_5_SHA_256"],
                "ContextKeyType": "string"},
               {"ContextKeyName": "kms:MessageType", "ContextKeyValues": ["RAW"], "ContextKeyType": "string"}]

G_KMS_SIGN = "kms-sign"                    # + ":<kid>"
G_KMS_SELF_AUTHORIZE = "kms-self-authorize"  # + ":<kid>"
G_READ_LOGIN_FLOW = "read-login-flow-secret"


def is_secret_grant(grant: str) -> bool:
    """能产生一个 verifier 会接受的签名（3c-final：只有 KMS 两类；读 Edge 产物 / SSM 不再算——那里只有公钥与 login-flow）。"""
    return grant.startswith(G_KMS_SIGN + ":") or grant.startswith(G_KMS_SELF_AUTHORIZE + ":")


LABEL_LOGIN_FLOW = "login-flow"
NON_KID_LABELS = (LABEL_LOGIN_FLOW,)


def grants_for_labels(labels) -> set:
    out: set = set()
    for label in labels:
        if label == LABEL_LOGIN_FLOW:
            out.add(G_READ_LOGIN_FLOW)
        else:
            out |= {f"{G_KMS_SIGN}:{label}", f"{G_KMS_SELF_AUTHORIZE}:{label}"}
    return out


def classes_for_labels(labels, t=None) -> frozenset:
    return frozenset("login-flow-param" if l == LABEL_LOGIN_FLOW else f"kms-key:{l}" for l in labels)


def baseline_kids(baseline: dict) -> list:
    return sorted(baseline.get("kms") or {})
```

`Targets`：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
@dataclass
class Targets:
    platform_functions: tuple
    site_functions: tuple
    kms_keys: dict = field(default_factory=dict)          # kid -> key ARN（两个 family 的全部 RS 行）
    alias_arns: dict = field(default_factory=dict)
    version_arns: dict = field(default_factory=dict)
    login_flow_parameter: str = ""

    def function_resources(self) -> list: ...（不变，去掉 edge_code_arns）
    def other_resources(self) -> list:
        extra = {self.login_flow_parameter} if self.login_flow_parameter else set()
        return sorted(set(self.kms_keys.values()) | extra)
```

`grants_from_decisions` 的尾段：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    for kid, arn in t.kms_keys.items():
        if allowed(A_KMS_SIGN, (arn,)):
            grants.add(f"{G_KMS_SIGN}:{kid}")
        if allowed(A_KMS_SELF_AUTHORIZE, (arn,)):
            grants.add(f"{G_KMS_SELF_AUTHORIZE}:{kid}")
    if t.login_flow_parameter and allowed(A_READ_PARAM, (t.login_flow_parameter,)):
        grants.add(G_READ_LOGIN_FLOW)
```

`simulate()`：第二组 `paginate(..., ContextEntries=KMS_CONTEXT)`。`undecided_resource_class`：`for kid, arn in t.kms_keys.items(): if resource == arn: return f"kms-key:{kid}"`。

`measure()` 的密钥段替换为：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
    session_keys = load_session_keys(CONFIG_PATH)
    refs = key_refs(session_keys, KEY_FAMILIES)
    kms = clients["kms"]
    kms_section: dict = {}
    spki_b64_by: dict = {}
    for ref in refs:
        der, fp = session_kms.describe_public_key(kms, ref.key_arn)      # 形态四项；指纹与 config 比对在下面
        if fp != ref.spki_sha256:
            raise SystemExit(f"闸门硬失败：{ref.kid} 的 KMS 公钥指纹 {fp} != config 的 {ref.spki_sha256}——"
                             "config.ini 指的不是这把 key；不出结论也不写基线")
        meta = kms.describe_key(KeyId=ref.key_arn)["KeyMetadata"]
        policy = kms.get_key_policy(KeyId=ref.key_arn, PolicyName="default")["Policy"]
        grants = [principal_fingerprint(json.dumps([g.get("GranteePrincipal"), sorted(g.get("Operations", [])),
                                                    g.get("Constraints", {})], sort_keys=True))
                  for page in kms.get_paginator("list_grants").paginate(KeyId=ref.key_arn) for g in page["Grants"]]
        kms_section[ref.kid] = {"arn_fp": principal_fingerprint(ref.key_arn),
                                "key_policy_fp": principal_fingerprint(canonical_json(policy)),
                                "key_spec": meta["KeySpec"], "key_usage": meta["KeyUsage"],
                                "spki_sha256": fp, "grants": sorted(grants)}
        spki_b64_by[f"{ref.family}:{ref.kid}"] = session_kms.spki_b64(der)
    login_flow_value = clients["ssm"].get_parameter(Name=session_keys.login_flow_secret_param,
                                                    WithDecryption=True)["Parameter"]["Value"]
    scan_values = {**spki_b64_by, LABEL_LOGIN_FLOW: login_flow_value}
    facts: dict = {}
    aliases = function_aliases(lam, all_functions)
    versions = function_versions(lam, all_functions)
    # ---- Edge 产物：只看 CloudFront 当前关联的版本 + 当前 asset（3c-final：产物里只有公钥，历史版本不再是负债）----
    current_version = edge_current_version(clients)      # 下面定义：CloudFront 当前关联的 origin-request 版本号
    edge_code_by = edge_code_arns_carrying_keys(clients, EDGE_ORIGIN_REQUEST_FN, fn_arn(EDGE_ORIGIN_REQUEST_FN),
                                                (current_version,), scan_values)
    asset_bucket, asset_key = edge_asset_location(clients, EDGE_ORIGIN_REQUEST_FN)
    blob = clients["s3"].get_object(Bucket=asset_bucket, Key=asset_key)["Body"].read()
    asset_by = {label: ([asset_key] if secret_in_zip_bytes(blob, v) else []) for label, v in scan_values.items()}
    assert_edge_artifacts(edge_code_by, asset_by,
                          site_kids=[r.kid for r in refs if r.family == "site"],
                          console_kids=[r.kid for r in refs if r.family == "console"])
    targets = Targets(platform_functions=..., site_functions=..., kms_keys={r.kid: r.key_arn for r in refs},
                      login_flow_parameter=..., alias_arns=..., version_arns=...)
```

`canonical_json(s)` = `json.dumps(json.loads(s), sort_keys=True, separators=(",", ":"))`（key policy 文本的规范化，避免空白差异误报）。 `edge_current_version`（与 `verify_deployed_edge.sh` ① / `verify_deployed_components._edge_deployed_source` 同一规则——**不按"版本号最大"挑**）：

```python
def edge_current_version(clients) -> str:
    """CloudFront 当前关联的 origin-request Lambda **版本号**。分发 ID 从 router 栈的 CfnOutput 取（config 只放输入）。"""
    rcfg = configparser.ConfigParser(interpolation=None)
    rcfg.read(_SITE_BUILDER.parent / "router" / "config.ini")
    stack = rcfg["CDK"]["stack_name"].split("#")[0].strip()
    outs = clients["cloudformation"].describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    dist = next((o["OutputValue"] for o in outs if o["OutputKey"] == "DistributionId"), "")
    if not dist:
        raise SystemExit(f"栈 {stack} 没有 CfnOutput DistributionId——router 栈没部？")
    assoc = (clients["cloudfront"].get_distribution_config(Id=dist)["DistributionConfig"]["DefaultCacheBehavior"]
             .get("LambdaFunctionAssociations", {}).get("Items", []))
    arns = [a["LambdaFunctionARN"] for a in assoc if a.get("EventType") == "origin-request"]
    if len(arns) != 1 or not arns[0].rsplit(":", 1)[-1].isdigit():
        raise SystemExit(f"origin-request 关联的不是恰好一个编号版本：{arns}——Lambda@Edge 必须关联编号版本，这是探针前提")
    return arns[0].rsplit(":", 1)[-1]
```

（`_aws_clients` 加 `cloudformation` / `cloudfront` 两个 client，`cloudfront` 不带 region。）`assert_edge_artifacts`：

```python
def assert_edge_artifacts(code_hits: dict, asset_hits: dict, *, site_kids, console_kids) -> None:
    """三条硬断言（不落 facts，连 --update-baseline 一起挡）：当前 Edge 必带每把 site 公钥；不得带任何 console 公钥
    （spec §4.1）；不得带 login-flow 值（spec §11.3）。"""
    problems = []
    for kid in site_kids:
        if not code_hits.get(f"site:{kid}"):
            problems.append(f"当前关联的 Edge 版本里没有 {kid} 的公钥——部署的不是这份 config 的 allowlist，线上会全员 302")
    for kid in console_kids:
        if code_hits.get(f"console:{kid}") or asset_hits.get(f"console:{kid}"):
            problems.append(f"Edge 产物里出现了 console family 的公钥 {kid}——spec §4.1：panel signer 被攻破就能伪造站点会话")
    if code_hits.get(LABEL_LOGIN_FLOW) or asset_hits.get(LABEL_LOGIN_FLOW):
        problems.append("Edge 产物里出现了 login-flow secret 的值——它是 auth 私有的（spec §11.3）")
    if problems:
        raise SystemExit("闸门硬失败（不接受基线放行）：\n  " + "\n  ".join(problems))
```

`compare_to_baseline(..., kms=None)` 新参数，调 `_compare_kms(rep, baseline.get("kms") or {}, kms, new_keys=..., retired_keys=...)`；`Report` 加 `kms_drift: list`；`RED_FIELDS` 加 `("kms_drift", "KMS 层漂移（key policy / grants / 公钥 / key 集合）", "kms")`；`RED_MESSAGES["kms"]` = "闸门红：会话签名 CMK 的 key policy、grants、公钥或 key 集合变了。默认 key policy（ADR 0001）下能改它的人本来就在冒充面里，但**变了**就要有人看：新 grant = 多了能签会话的 principal；key 集合变化必须用 --new-key / --retire-key 声明。"；`GREEN_FIELDS` 不变。`_compare_kms`：

```python
def _compare_kms(rep: Report, base: dict, now: dict, *, new_keys: tuple, retired_keys: tuple) -> None:
    """**逐字段比的清单由 `BUNDLE_SHAPE["kms"]["*"]` 派生，不在这里手写**（执行时修订，见 SDD ledger
    Task 13 review Important 2）：手写那一份在有人给快照加第七个字段时不会跟着变，于是新字段进了观测
    与基线却从不参与比较——而"多了一个字段"与"那个字段没变过"在输出上一模一样，正是本文件被反复
    点名的那类 false-green。`grants` 从标量清单里剔掉、单独按排序后的集合比。"""
    scalars = [k for k in BUNDLE_SHAPE["kms"]["*"] if k != "grants"]
    for kid in sorted(set(base) | set(now)):
        if kid not in base:
            (rep.migration_grants if kid in new_keys else rep.kms_drift).append(
                f"kms {kid}：新出现" + ("（--new-key 已声明）" if kid in new_keys else "——未声明的新 key"))
            continue
        if kid not in now:
            (rep.migration_grants if kid in retired_keys else rep.kms_drift).append(
                f"kms {kid}：消失" + ("（--retire-key 已声明）" if kid in retired_keys else "——未声明的 key 退场"))
            continue
        for k in scalars:                       # 派生，不手写这五个名字
            if base[kid].get(k) != now[kid].get(k):
                rep.kms_drift.append(f"kms {kid}：{k} 变了")
        if sorted(base[kid].get("grants", [])) != sorted(now[kid].get("grants", [])):
            rep.kms_drift.append(f"kms {kid}：grants 从 {len(base[kid].get('grants', []))} 条变成 {len(now[kid].get('grants', []))} 条")
```

`BUNDLE_SHAPE`：`"facts": {"principals_with_missing_context": _plain_int}`；`"kms": {"*": {"arn_fp": _nonempty_str, "key_policy_fp": _nonempty_str, "key_spec": _nonempty_str, "key_usage": _nonempty_str, "spki_sha256": _nonempty_str, "grants": _list_of_str}}`；`"coverage": {"undecided_items": _list_of_undecided_items}`；`"required": {"edge": _nonempty_str, "deployer": _nonempty_str, "auth": _nonempty_str, "panel": _nonempty_str}`。`check_bundle_complete` 删 `asset_scan_complete` 那段（`measure` 不再产出该键）。`write_baseline` 写入 `"kms": bundle["kms"]`，`note` 文案改（资源类词表：`sites / kms-key:<kid> / login-flow-param / fn:<平台函数名>`）。`load_baseline`：

```python
def load_baseline(path: Path) -> dict:
    if not path.exists():
        print(f"（没有基线 {path}：本次只能 --update-baseline 生成第一份，不能出结论——"
              "基线含单账号实测、不随资产分发，采用者首跑就是这一步）", file=sys.stderr)
        return {"schema": BASELINE_SCHEMA, "principals": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != BASELINE_SCHEMA:
        raise SystemExit(f"基线 schema 是 {data.get('schema')}，脚本要 {BASELINE_SCHEMA}。3c-final 起没有迁移通道"
                         "（旧形态没有 KMS 层可比）：删掉这个文件，跑一次 --update-baseline 重生成。")
    return data
```

`main()` 里没有基线且不带 `--update-baseline` ⇒ 在比较前 `SystemExit("没有基线，先 --update-baseline")`（避免"与空基线比较 ⇒ 全部 new_principals 红"这种误读）。`REQUIRED_GRANT_PREFIXES` 加 `"auth"` / `"panel"`；`measure()` 的 `required` 加 `"auth": "site-auth-service-role", "panel": <deploy_panel.ROLE_NAME>`（按路径 `_load_deploy_module` 读，与 `verify_deployed_components` 同法；或 AST 取常量——不 import boto3 的那条路）。`_aws_clients` 加 `"kms"`。`--dump-observed` / `--from-dump` 不变（`check_bundle_complete` 会要求新分节）。

`.gitignore` 加一行 `site-builder/scripts/account_trust_baseline.json`；`git rm --cached site-builder/scripts/account_trust_baseline.json`（本地文件保留，Task 21 ★ 会重生成覆盖）。

- [ ] **Step 4: 跑绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py tests/test_blind_spot_coverage.py tests/test_verify_script_exit_contracts.py -q`
Expected: 全绿（读本地基线的用例在本地因旧 schema 5 文件仍存在会红——**先把本地旧基线移到 `.scratch/asset-v1/08/account_trust_baseline.schema5.json` 备份**，让那批用例 skip；Task 21 ★ 生成新基线后它们重新生效）。

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
mv site-builder/scripts/account_trust_baseline.json .scratch/asset-v1/08/account_trust_baseline.schema5.json
bash site-builder/scripts/scan_staged_secrets.sh
git add .gitignore site-builder/scripts/verify_account_trust_boundary.py site-builder/deployer/tests/test_verify_account_trust_boundary.py site-builder/deployer/tests/test_blind_spot_coverage.py
git rm --cached -q site-builder/scripts/account_trust_baseline.json || true
git commit -m "feat(asset-v1/08): 信任边界闸门观测 KMS 层（kms:Sign/自助授权持有者、key policy、grants、公钥指纹；Edge 产物三条硬断言），schema 6 无迁移通道，删 HS 扫描与 3/4→5 通道；基线不再 tracked"
```

---

### Task 14：部署面闸门——`verify_deployed_components.py`、`verify_deployed_edge.sh`、`session_verify_counts.py`

**Files:**
- Modify: `site-builder/scripts/verify_deployed_components.py`、`verify_deployed_edge.sh`、`session_verify_counts.py`
- Modify: `site-builder/deployer/tests/test_verify_deployed_components.py`、`test_session_verify_counts.py`
- Test: 同上

**Interfaces:**
- `verify_deployed_components.py`：`AUTH_SESSION_PARAM_KEYS = ("LOGIN_FLOW_SECRET_PARAM",)`、`PANEL_SESSION_PARAM_KEYS = ()`；新增 `_check_session_keys_three_way(kms, env_json: str, label: str, families: tuple) -> None`（每个 kid 一条 check：`env` 行的 `key_arn` / `spki_sha256` == config 行 == `kms.get_public_key` 的 SHA-256）；`_check_function_url_authz(lam, fn, label, edge_role, *, extra_principals=None)`（auth 那处传 `{"verifier": arn}` 当 `[Verification] fixture_issuer=true`，并另出一条 check：`FIXTURE_ISSUER` env 与配置一致、`site-builder-verifier` 角色存在与否与配置一致）；Edge 段新增 `_check_edge_public_keys(src: str, site_b64s: list, console_b64s: list)`（当前关联版本的 `index.py` 含每把 site `spki_b64`、不含任何 console `spki_b64`、含 `RS256_GOLDEN`、不含 `JWT_SECRET =` / `LEGACY_ENTRY`）；`MIN_DEPLOYED_CHECKS` 重算并在注释里写出算式
- `verify_deployed_edge.sh`：④ 段删 legacy / `typ` / `JWT_SECRET` 三处；改 allowlist 对账为**公钥精确对账**（对每个 site kid：`aws kms get-public-key --key-id <arn> --query PublicKey --output text` 的值必须逐字节出现在 `index.py` 的 `SITE_ALLOWLIST_JSON` 里；每个 console kid 的公钥必须**不**出现）；新增 `test -d "$TMP/cryptography"`（vendored 依赖在产物里）与 `grep -q '^RS256_GOLDEN = '`
- `session_verify_counts.py`：`OUTCOMES` 删 `accepted_legacy`；`DRAIN_TARGETS = {"previous": "accepted_previous"}`；`render()` 尾行改 `总量 {total}；accepted_previous {prev}`；帮助文案里的 ④/legacy 删

- [ ] **Step 1: 测试（先红）**

`test_verify_deployed_components.py`：`AUTH_PARAM_KEYS = ("LOGIN_FLOW_SECRET_PARAM",)`、`GOOD_ENV` 删 `JWT_SECRET_PARAM`；`test_the_gate_passes_both_auth_param_keys_not_just_jwt` → `…passes_the_login_flow_param_key`（常量 == `{"LOGIN_FLOW_SECRET_PARAM"}`）；`test_min_param_checks_*` 与 `MIN_DEPLOYED_CHECKS + l3 == 24` 那条按新算式改；新增：

```python
def test_three_way_key_check_is_green_when_env_config_and_kms_agree_and_red_on_any_disagreement(monkeypatch):
    import upgrade_code_vectors as v          # deployer 测试也能拿到（sys.path 加 panel/tests）
    g = _gate(); g.results.clear()
    env_json = v.session_keys_json((v.SITE_KID, "current"), (v.CONSOLE_KID, "current"))
    monkeypatch.setattr(g, "_config_key_rows", lambda families: json.loads(env_json))
    g._check_session_keys_three_way(v.FakeKms(), env_json, "auth", ("site", "console"))
    assert [ok for ok, _, _ in g.results] == [True, True]
    g.results.clear()
    kms = v.FakeKms(); kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    g._check_session_keys_three_way(kms, env_json, "auth", ("site", "console"))
    assert [ok for ok, _, _ in g.results] == [True, False]


def test_edge_public_key_check_requires_every_site_key_and_forbids_console_keys():
    g = _gate()
    src = 'SITE_ALLOWLIST_JSON = \'\'\'{"site-rs-v1": {"alg": "RS256", "spki_b64": "U0lURQ==", "role": "current"}}\'\'\'\nRS256_GOLDEN = {}\n'
    g.results.clear(); g._check_edge_public_keys(src, ["U0lURQ=="], ["Q09OU09MRQ=="])
    assert all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src, ["T1RIRVI="], ["Q09OU09MRQ=="])
    assert not all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src.replace("U0lURQ==", "Q09OU09MRQ=="), ["Q09OU09MRQ=="], ["Q09OU09MRQ=="])
    assert not all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src + 'JWT_SECRET = "x"\n', ["U0lURQ=="], [])
    assert not all(ok for ok, _, _ in g.results)


def test_function_url_authz_expects_the_verifier_pair_only_when_the_component_is_on():
    g = _gate()
    ver = "arn:aws:iam::000000000000:role/site-builder-verifier"
    lam = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE))
    g.results.clear(); g._check_function_url_authz(lam, "site-auth-service", "auth", FUP_EDGE, extra_principals={"verifier": ver})
    assert not all(ok for ok, _, _ in g.results), "开着组件却没有 verifier 两条 ⇒ 红"
    lam2 = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE) + flp.good_pair(ver, label="verifier"))
    g.results.clear(); g._check_function_url_authz(lam2, "site-auth-service", "auth", FUP_EDGE, extra_principals={"verifier": ver})
    assert all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_function_url_authz(lam2, "site-auth-service", "auth", FUP_EDGE)
    assert not all(ok for ok, _, _ in g.results), "关了组件而语句还在 ⇒ 野 Sid 红"
```

（`fake_lambda_policy.good_pair(arn, label="edge")` 加一个 `label` 参数产出 `f"{label}-invoke"` 两条——Task 6 的替身补这一手。）

`test_session_verify_counts.py`：`test_render_totals_and_legacy_count` → `…_and_previous_count`；`test_drain_gate_rejects_an_unknown_target` 加断言 `legacy` 也是未知目标；参数化里的 `"legacy"` 全删。

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_verify_deployed_components.py tests/test_session_verify_counts.py -q -x`

- [ ] **Step 3: 实现**

`verify_deployed_components.py`：

```python
AUTH_SESSION_PARAM_KEYS = ("LOGIN_FLOW_SECRET_PARAM",)
PANEL_SESSION_PARAM_KEYS: tuple = ()


def _config_key_rows(families: tuple) -> dict:
    sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
    from session_keys import env_json, load_session_keys
    return json.loads(env_json(load_session_keys(ROOT / "site-builder" / "config.ini"), families))


def _check_session_keys_three_way(kms, env_json_text: str, label: str, families: tuple) -> None:
    """spec §11.6 第 3 层：线上 env 的每一行 == config 的同一行，且 KMS 公钥的 SHA-256 == 那行的 spki_sha256。"""
    import hashlib
    env_rows = json.loads(env_json_text or "{}")
    cfg_rows = _config_key_rows(families)
    for fam in families:
        for row in cfg_rows.get(fam, []):
            live = next((r for r in env_rows.get(fam, []) if r.get("kid") == row["kid"]), None)
            try:
                der = kms.get_public_key(KeyId=row["key_arn"])["PublicKey"]
                kms_fp = hashlib.sha256(der).hexdigest()
            except Exception as exc:  # noqa: BLE001
                kms_fp = f"<{type(exc).__name__}>"
            ok = live == row and kms_fp == row["spki_sha256"]
            check(ok, f"{label} 的 {row['kid']}：env == config == KMS 公钥指纹（三方对账）",
                  "一致" if ok else f"env={live} config={row} kms_spki={kms_fp}")


def _check_edge_public_keys(src: str, site_b64s: list, console_b64s: list) -> None:
    m = re.search(r"^SITE_ALLOWLIST_JSON = '''(.*?)'''$", src, re.S | re.M)
    body = m.group(1) if m else ""
    check(bool(m) and all(b in body for b in site_b64s), "Edge 产物含每把 site 公钥（否则全员 302）",
          f"缺 {[b[:12] for b in site_b64s if b not in body]}" if m else "找不到 SITE_ALLOWLIST_JSON")
    check(not any(b in src for b in console_b64s), "Edge 产物不含任何 console 公钥（spec §4.1）")
    check("RS256_GOLDEN = " in src and "JWT_SECRET =" not in src and "LEGACY_ENTRY" not in src,
          "Edge 产物是 RS256 形态（有黄金预热、无 HS/legacy 残留）")
```

`run_deployed()`：auth 段加 `_check_session_keys_three_way(boto3.client("kms", region_name=region), got_env.get("SESSION_KEYS_JSON"), "site-auth-service", ("site", "console"))`；`_check_function_url_authz(..., extra_principals=({"verifier": f"arn:aws:iam::{account}:role/site-builder-verifier"} if fixture_on else None))`，其中 `fixture_on = _parsed_cfg(CFG_PATH).get("Verification", "fixture_issuer", fallback="false").split("#")[0].strip().lower() == "true"`（段缺失 = 关；不用 `read_cfg`——它对缺键硬退出，而 `[Verification]` 是可选段）；再一条 `check(got_env.get("FIXTURE_ISSUER") == ("on" if fixture_on else "off"), "auth 的 FIXTURE_ISSUER 与 [Verification] 一致")` 与一条 `check(role_exists == fixture_on, "site-builder-verifier 角色存在性与 [Verification] 一致")`。`run_panel()`：`_check_session_keys_three_way(kms, env.get("SESSION_KEYS_JSON"), "panel", ("console",))`。Edge 段（`run_mcp_and_route` 里 `_edge_deployed_source()` 之后）：`_check_edge_public_keys(src, site_b64s, console_b64s)`，两组 b64 由 `kms.get_public_key` 现取并 base64。`_check_function_url_authz` 签名加 `extra_principals=None` 透传给 `drift`。`MIN_DEPLOYED_CHECKS` 按新增条数重算（算式写进注释），`_min_param_checks` 逻辑不变（自动变 1）。`test_verify_deployed_components.py` 里的下限用例按新值改。

`verify_deployed_edge.sh` ④ 段：删 legacy `typ`、`LEGACY_ENTRY`、`JWT_SECRET` 三块；`SK_EXPECTED` 改为读 config 的 site kid 与 key ARN，再 `aws kms get-public-key --key-id "$ARN" --region us-east-1 --query PublicKey --output text` 取 base64，`grep -qF -- "$B64" "$TMP/index.py"` 为 PASS；console kid 同法取 b64 后 `! grep -qF`；加：

```bash
if [ -d "$TMP/cryptography" ] && grep -qE '^RS256_GOLDEN = ' "$TMP/index.py"; then
  echo "PASS  产物带 vendored cryptography 与黄金预热（RS256 形态，ADR 0003）"
else
  fail "产物不是 RS256 形态：缺 cryptography/ 目录或 RS256_GOLDEN —— 部署的是 3c-final 之前的代码"
fi
if grep -qE '^JWT_SECRET = |^LEGACY_ENTRY = ' "$TMP/index.py"; then
  fail "产物里还有 JWT_SECRET / LEGACY_ENTRY —— HS/legacy 残留"
fi
```

③ 段的逐行比对不变（vendored 目录不在 diff 范围，只比 `index.py`）。

`session_verify_counts.py`：按接口清单改；docstring 里"④ 判 legacy"那些句子删。

- [ ] **Step 4: 跑绿 + Commit**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_verify_deployed_components.py tests/test_session_verify_counts.py tests/test_function_url_policy.py -q`

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add site-builder/scripts/verify_deployed_components.py site-builder/scripts/verify_deployed_edge.sh site-builder/scripts/session_verify_counts.py \
        site-builder/deployer/tests/test_verify_deployed_components.py site-builder/deployer/tests/test_session_verify_counts.py site-builder/deployer/tests/fake_lambda_policy.py
git commit -m "feat(asset-v1/08): 部署面闸门——auth/panel 三方公钥对账、verifier 语句按 [Verification] 期望、Edge 产物公钥精确对账与 RS256 形态；排空闸门只剩 previous"
```

---

### Task 15：CDK 两把 CMK、指纹脚本、删除清单（ensure_session_keys / 迁移脚本）、preflight RS 化、探针标签

**Files:**
- Modify: `site-builder/deployer/infra/app.py`
- Create: `site-builder/deployer/tests/test_infra_kms_keys.py`；Modify: `test_infra_tables.py`（追加两条 CDK 断言）
- Create: `site-builder/scripts/session_key_fingerprint.py`；Create: `site-builder/deployer/tests/test_session_key_fingerprint.py`
- Delete: `site-builder/scripts/ensure_session_keys.py`、`site-builder/deployer/tests/test_ensure_session_keys.py`（D5）
- Delete: `site-builder/scripts/migrate_sites_to_blue_green.py`、`site-builder/deployer/tests/test_migrate_blue_green.py`；Modify: `deployer/functions/deploy_lambda_site.py`（`UnmigratedSite` 报文）、`deployer/tests/test_deploy_lambda_site.py`（两处 `match=`）、`deployer/tests/test_seed_permissions.py`（清单删一行）、`scripts/backfill_site_role_policies.py`（docstring 一处）
- Modify: `site-builder/scripts/preflight_config_states.py`、`deployer/tests/test_preflight_config_states.py`（D10）
- Modify: `site-builder/scripts/probe_impersonation_surface.py`、`deployer/tests/test_probe_impersonation_surface.py`
- Test: 上述 deployer 测试

**Interfaces:**
- `app.py`：construct `SiteSessionKeyRsV1` / `ConsoleSessionKeyRsV1`（`kms.Key`：`key_spec=RSA_2048`、`key_usage=SIGN_VERIFY`、`enable_key_rotation=False`、`removal_policy=RETAIN`、`alias=f"alias/site-builder/session/{kid}"`、description 只用连字符）；`CfnOutput("SiteSessionKeyRsV1Arn")` / `("ConsoleSessionKeyRsV1Arn")`。**轮转到 v2 = 再加一个 construct `…RsV2`**，旧 construct 删掉时 RETAIN 留 key 给 ⑩ 之后手工 `schedule-key-deletion`
- `session_key_fingerprint.py`：`python3 site-builder/scripts/session_key_fingerprint.py --kid site-rs-v1 --arn <arn> [--kid console-rs-v1 --arn <arn>]`（或 `--from-stack` 直接读 deployer 栈的两个 CfnOutput）→ 打印可粘贴的 `[SessionKey:<kid>]` 小节；用 `session_kms.describe_public_key`（形态检查 + 指纹）；不写 config
- `preflight_config_states.py`：状态 `stage`（`{fam}-rs-v{n+1}` 进 previous，小节用假 ARN `arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-00000000000{n}` 与 `spki_sha256 = <64 个 0 的变体>`）、`switch`、`retire`；`current_kids` 认 `{fam}-rs-v(\d+)`；删 `state_l3` 与 `signer` 处理
- `probe_impersonation_surface.py`：`Surface.kms_keys: dict[str, str]`（从 config 读两把 key ARN，替代占位 ARN）；`S_KMS_DIRECT` / `S_KMS_SELF` 对任一把成立即标；新标签 `S_FIXTURE_ISSUER = "sign:fixture-issuer"`：持有对 `site-auth-service` 的 `lambda:InvokeFunction`（直接入口）**或**名字就是 `site-builder-verifier`（URL 入口）的 principal；`ALL_LABELS` 加它；`--self-test` 加两条反例（直接 invoke ⇒ 有标签；只有 `kms:GetPublicKey` ⇒ 无）；evidence 的 `resource_equivalence_classes` 与 `known_gaps` 文案更新（assume-role 链不建模）

- [ ] **Step 1: 测试（先红）**

`test_infra_kms_keys.py`（不依赖 CDK）：

```python
"""deployer 栈里两把会话签名 CMK 的形态守卫（spec §11.2 / ADR 0001），按 AST 读 app.py，不 synth。"""
import ast
from pathlib import Path

APP = Path(__file__).parents[1] / "infra" / "app.py"


def _key_calls():
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Key" \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "kms":
            cid = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
            out[cid] = {k.arg: ast.unparse(k.value) for k in node.keywords}
    return out


def test_exactly_two_session_keys_one_per_family_with_the_kid_in_the_construct_id():
    keys = _key_calls()
    assert set(keys) == {"SiteSessionKeyRsV1", "ConsoleSessionKeyRsV1"}, keys.keys()


def test_every_session_key_is_rsa_2048_sign_verify_unrotated_and_retained():
    for cid, kw in _key_calls().items():
        assert kw["key_spec"] == "kms.KeySpec.RSA_2048", cid
        assert kw["key_usage"] == "kms.KeyUsage.SIGN_VERIFY", cid
        assert kw["enable_key_rotation"] == "False", cid      # 非对称 CMK 不支持自动轮转（spec §3.3）
        assert kw["removal_policy"] == "RemovalPolicy.RETAIN", cid
        assert "alias/site-builder/session/" in kw["alias"], cid
        assert "—" not in kw.get("description", "") and "–" not in kw.get("description", "")


def test_no_key_policy_is_passed_so_the_default_root_delegation_applies():
    for cid, kw in _key_calls().items():
        assert "policy" not in kw and "admins" not in kw, f"{cid}: ADR 0001 —— 默认 key policy，不做限制性策略"


def test_each_key_arn_is_exported_for_the_config_backfill():
    src = APP.read_text(encoding="utf-8")
    assert 'CfnOutput(self, "SiteSessionKeyRsV1Arn"' in src or '"SiteSessionKeyRsV1Arn"' in src
    assert '"ConsoleSessionKeyRsV1Arn"' in src
```

`test_infra_tables.py` 追加（CDK opt-in）：

```python
def test_session_signing_keys_are_asymmetric_retained_and_default_policy(template):
    template.resource_count_is("AWS::KMS::Key", 2)
    template.has_resource("AWS::KMS::Key", {"DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
                                            "Properties": {"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}})
    for res in template.find_resources("AWS::KMS::Key").values():
        props = res["Properties"]
        assert props.get("EnableKeyRotation") in (None, False)
        stmts = props["KeyPolicy"]["Statement"]
        assert len(stmts) == 1 and stmts[0]["Action"] == "kms:*" and "root" in json.dumps(stmts[0]["Principal"])
    template.resource_count_is("AWS::KMS::Alias", 2)
```

`test_session_key_fingerprint.py`：用 `upgrade_code_vectors.FakeKms`，断言输出正好是两个 `[SessionKey:<kid>]` 小节（`alg = RS256`、`key_arn = <arn>`、`spki_sha256 = <spki_hex>`），`--kid` 与 `--arn` 数量不一致 ⇒ `SystemExit`，kid 不合 `KID_RE` ⇒ `SystemExit`，形态不符（`describe_overrides`）⇒ `SystemExit`。

`test_preflight_config_states.py` 追加：`state_stage` 对 RS 配置产出 `site_previous = site-rs-v2` 与含 `key_arn` / `spki_sha256` 的新节且过 `load_session_keys`；`state_switch` 互换；`state_retire` 清空 previous 并删 v1 节；`hasattr(pf, "state_l3")` 为 False；源码里没有 `signer` / `legacy_param` / `hs-v`。

`test_probe_impersonation_surface.py`：`ALL_LABELS` 含 `sign:fixture-issuer`；`classify` 反例两条；`Surface` 有 `kms_keys` 且 `classify` 对任一把 key 的 `kms:Sign` 标 `S_KMS_DIRECT`；源码无 `placeholder-key`。

`test_deploy_lambda_site.py` 两处 `match="migrate_sites_to_blue_green"` 改 `match="UnmigratedSite|未迁移"`；`test_seed_permissions.py` 删 `"scripts/migrate_sites_to_blue_green.py"` 及其注释。

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_infra_kms_keys.py tests/test_session_key_fingerprint.py tests/test_preflight_config_states.py tests/test_probe_impersonation_surface.py -q -x`

- [ ] **Step 3: 实现**

`app.py`（`from aws_cdk import aws_kms as kms`；放在 `admins` 表之后）：

```python
# 【片段】不是完整模块：插进正文所指的函数体 / 字典 / 调用点，缩进以落点为准
        # ---- 3c-final：两把会话签名 CMK（spec §11.2 / ADR 0001）----
        # 默认 key policy（root 委派）：限制性策略只减 1 个 principal、结构上收不掉"劫持 signer"那条路，
        # 且带自锁风险；kms:Sign 只经 auth / panel 的 identity policy 授（deploy_auth / deploy_panel）。
        # 非对称 CMK 不支持自动轮转（spec §3.3）⇒ 轮转 = 加一个新 construct（…RsV2），走 DEPLOY.md
        # 「轮转会话密钥」的就位 → 切换 → 排空 → 退役；旧 construct 删掉时 RETAIN 留下 key，退役最后一步
        # 才 schedule-key-deletion。alias 只为控制台可读，**代码永不引用 alias**（config 写完整 key ARN）。
        for construct_id, kid in (("SiteSessionKeyRsV1", "site-rs-v1"), ("ConsoleSessionKeyRsV1", "console-rs-v1")):
            key = kms.Key(self, construct_id,
                          key_spec=kms.KeySpec.RSA_2048, key_usage=kms.KeyUsage.SIGN_VERIFY,
                          enable_key_rotation=False, removal_policy=RemovalPolicy.RETAIN,
                          alias=f"alias/site-builder/session/{kid}",
                          description=f"site-builder session signing key {kid} - RS256 - default key policy per ADR 0001")
            CfnOutput(self, f"{construct_id}Arn", value=key.key_arn)
```

`session_key_fingerprint.py`：

```python
#!/usr/bin/env python3
"""把 deployer 栈建出来的会话签名 CMK 变成可粘贴进 config.ini 的 `[SessionKey:<kid>]` 小节（spec §11.6）。

    python3 site-builder/scripts/session_key_fingerprint.py --from-stack            # 读栈的两个 CfnOutput
    python3 site-builder/scripts/session_key_fingerprint.py --kid site-rs-v1 --arn arn:aws:kms:…:key/…

只读（DescribeKey + GetPublicKey），不写 config；形态四项（KeySpec / KeyUsage / SigningAlgorithms / SPKI）
在这里就校验——指纹算错的症状是三个部署脚本的 precheck 全部拒绝部署。用不带路径的 python3 跑。
"""
from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import session_kms  # noqa: E402
from session_keys import KID_RE  # noqa: E402

STACK_OUTPUTS = {"site-rs-v1": "SiteSessionKeyRsV1Arn", "console-rs-v1": "ConsoleSessionKeyRsV1Arn"}


def sections(kms, pairs) -> str:
    out = []
    for kid, arn in pairs:
        if not KID_RE.match(kid):
            raise SystemExit(f"{kid!r} 不是合法 kid（形态 site-rs-v<n> / console-rs-v<n>）")
        _, fp = session_kms.describe_public_key(kms, arn)
        out.append(f"[SessionKey:{kid}]\nalg = RS256\nkey_arn = {arn}\nspki_sha256 = {fp}\n")
    return "\n".join(out)


def from_stack(cfn, stack_name: str) -> list:
    outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])}
    missing = [k for k in STACK_OUTPUTS.values() if k not in outs]
    if missing:
        raise SystemExit(f"栈 {stack_name} 缺 CfnOutput {missing}——先部 deployer 栈")
    return [(kid, outs[key]) for kid, key in STACK_OUTPUTS.items()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kid", action="append", default=[])
    ap.add_argument("--arn", action="append", default=[])
    ap.add_argument("--from-stack", action="store_true", help="从 deployer 栈的 CfnOutput 读两把 key 的 ARN")
    args = ap.parse_args(argv)
    if len(args.kid) != len(args.arn):
        raise SystemExit("--kid 与 --arn 必须成对出现")
    import boto3
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(ROOT / "site-builder" / "config.ini")
    region = (cfg.get("Platform", "region", fallback="us-east-1") or "us-east-1").split("#")[0].strip()
    pairs = list(zip(args.kid, args.arn))
    if args.from_stack:
        stack = (cfg.get("Deployer", "stack_name", fallback="SiteDeployerStack") or "SiteDeployerStack").split("#")[0].strip()
        pairs += from_stack(boto3.client("cloudformation", region_name=region), stack)
    if not pairs:
        raise SystemExit("给 --from-stack 或至少一对 --kid/--arn")
    print(sections(boto3.client("kms", region_name=region), pairs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

（deployer 栈名：查 `deployer/infra/app.py` 里 `SiteDeployerStack(app, "<name>")` 的实际字面量，若 config 没有 `[Deployer] stack_name` 就用那个字面量作 fallback。）

`preflight_config_states.py`：`current_kids` 的正则改 `{fam}-rs-v(\d+)`；`key_sections(kids)` 产出 RS 行（假 ARN 按 kid 序号生成、`spki_sha256 = f"{n:064x}"`——纯校验用的假值，加载器只检查形态）；删 `state_l3`；`state_stage(t, nxt)` = `t + key_sections(nxt)` 再设两个 `*_previous`；`state_switch` / `state_retire` 逻辑不变；docstring 里 ⑤/L3/signer 的段落删；`STATES = (("stage", state_stage), ("switch", state_switch), ("retire", state_retire))`。

`probe_impersonation_surface.py`：`Surface.kms_keys: tuple[str, ...]`（从 `site-builder/config.ini` 的 `[SessionKeys]` 经 `session_keys.key_refs` 取两把 ARN；配置读不到时 SystemExit——不再用占位 ARN）；`classify()` 里 `kms:Sign|<任一 key>` ⇒ `S_KMS_DIRECT`，`PutKeyPolicy|CreateGrant` 同理 ⇒ `S_KMS_SELF`；新增 `S_FIXTURE_ISSUER`：`lambda:InvokeFunction|<auth_fn>` 成立 ⇒ 加标签（直接入口）；principal 名字 == `site-builder-verifier` ⇒ 加标签（URL 入口）；`ALL_LABELS` 加；`aggregate` 的 `can_sign` **不**并入 `sign:fixture-issuer`（受限冒充，单列——spec §1 那段"单列标签、不与 sign:kms-direct 合并"），evidence 多一个 `fixture_issuer_holders` 计数；`self_test()` 加两条；`known_gaps` 加"能 assume site-builder-verifier 的链不建模（信任策略分析），只把角色本身与直接 invoke 入口计入"。删 `kms:placeholder-key` 文案。**`MITIGATIONS` 必须多一项**（`test_every_label_is_covered_by_a_mitigation_or_declared_uncovered` 要求每个标签落在某个候选措施里）：`"fixture-issuer-verifier-boundary": (S_FIXTURE_ISSUER,)`——它的"缓解"就是 ADR 0002 的 verifier 侧边界（Edge / panel 只在夹具站点与平台路由上认夹具会话），关掉它等于关掉验收工具，边际收益按 0 记。

删除清单：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git rm site-builder/scripts/ensure_session_keys.py site-builder/deployer/tests/test_ensure_session_keys.py
git rm site-builder/scripts/migrate_sites_to_blue_green.py site-builder/deployer/tests/test_migrate_blue_green.py
```

`deploy_lambda_site.py`：`UnmigratedSite` 的 docstring 与报文里"先跑 scripts/migrate_sites_to_blue_green.py 把路由切到某个颜色"改为"这个部署没有存量迁移路径（资产不含它，ADR 0005）：把路由的 api_target 指向 blue/green 任一色的 Function URL 后重试，或下线重建"；两处 `test_deploy_lambda_site.py` 的 `match=` 同步。`backfill_site_role_policies.py` 第 70 行注释删掉对迁移脚本的引用。`bootstrap_venvs.sh` 与 `test_bootstrap_venvs.py` 不涉及。

- [ ] **Step 4: 跑绿 + Commit**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests/`**）
Expected: 全绿（`test_infra_tables.py` 默认 skip；要真跑：`PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`，需 Docker）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add -A site-builder/deployer/infra/app.py site-builder/deployer/tests site-builder/deployer/functions/deploy_lambda_site.py \
        site-builder/scripts/session_key_fingerprint.py site-builder/scripts/preflight_config_states.py \
        site-builder/scripts/probe_impersonation_surface.py site-builder/scripts/backfill_site_role_policies.py
git commit -m "feat(asset-v1/08): deployer 栈建两把 RSA_2048 SIGN_VERIFY CMK（默认 key policy、RETAIN、不轮转）+ 指纹脚本；preflight 改 RS 三状态；探针加 sign:fixture-issuer；删 ensure_session_keys 与 blue/green 存量迁移脚本"
```

---

### Task 16：文档与配置模板——DEPLOY.md（部署顺序 + KMS 版轮转 runbook）、CLAUDE.md、CONTEXT.md、README、威胁模型、ADR、spec 状态、§9；全仓 HS 词汇守卫

**Files:**
- Modify: `site-builder/DEPLOY.md`、`CLAUDE.md`、`CONTEXT.md`、`README.md`、`docs/security/account-trust-boundary.md`、`docs/adr/0002-*.md`、`docs/adr/0003-*.md`、`docs/adr/0005-*.md`、`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md`（只改状态行与 §6.1 3c-final 行的状态列）、`docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`（§9 的 3c、6、12 行）
- Modify: `site-builder/deployer/tests/test_delivery_docs_current.py`（删 `test_migrate_script_has_an_entry_in_both_deploy_and_claude`；`wanted` 集合改 `{"verify_token", "_verify_session_jwt"}`；新增 HS 词汇守卫）
- Test: deployer 套件（doc 守卫都在这里）+ 全部七套件（本 Task 末尾）

**Interfaces:** 无代码接口。DEPLOY.md 是唯一的采用者部署手册；CLAUDE.md 有状态词守卫。

- [ ] **Step 1: 新增 HS 词汇守卫（先红）**

`test_delivery_docs_current.py` 追加：

```python
_HS_ERA_TOKENS = ("HS256", "jwt-secret", "JWT_SECRET", "SESSION_SIGNER", "LEGACY_ENTRY", "legacy_param",
                  "mint_session_jwt", "verify_with_legacy", "ensure_session_keys", "migrate_sites_to_blue_green",
                  "--drain-gate legacy", "signer = legacy", "signer = current")
# 决策记录允许出现（文件头声明性质）；采用者文档不许
_HS_ALLOWED_PREFIXES = ("docs/superpowers/", "docs/reviews/", "docs/adr/", "docs/security/3c-", ".scratch/")


def test_adopter_docs_and_code_carry_no_hs_era_vocabulary():
    """3c-final 之后 HS256 / legacy 入口 / signer 开关只存在于决策记录里（spec / review / ADR）。
    采用者文档（CLAUDE.md、README、DEPLOY.md、client-setup、skills、CONTEXT.md）与全部源码 / 测试都不许再提。"""
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    hits = []
    for rel in tracked:
        if rel.startswith(_HS_ALLOWED_PREFIXES) or not rel.endswith((".md", ".py", ".sh", ".ini", ".example", ".txt", ".yaml", ".yml")):
            continue
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for tok in _HS_ERA_TOKENS:
            if tok in text:
                hits.append(f"{rel}: {tok}")
    assert not hits, "HS/legacy 词汇残留（要么删掉，要么它属于决策记录并搬到允许的目录）：\n  " + "\n  ".join(hits)
```

`test_deploy_md_lists_every_production_session_verifier` 的 `wanted = {"verify_token", "_verify_session_jwt"}`（`verify_session_jwt` / `verify_with_legacy` 已不存在）。删 `test_migrate_script_has_an_entry_in_both_deploy_and_claude`。`test_claude_md_test_commands_carry_the_two_measured_traps` 若引用 `verify_kid_entry_live` 的 legacy 旗标措辞，按新措辞改。

- [ ] **Step 2: 跑红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q -x -k hs_era`
Expected: 一屏命中（CLAUDE.md / DEPLOY.md / README / CONTEXT.md / account-trust-boundary.md…）。**这份命中清单就是本 Task 的工单**：逐条改到零。

- [ ] **Step 3: `site-builder/DEPLOY.md`**

（a）`### SSM 参数` 一节：表只留 `site-client-secret`（① 阶段建）与 `login-flow-secret`（`deploy_auth.py` 不存在时创建；轮转 = `put-parameter --overwrite`，5 分钟窗口内进行中登录失败一次）；删 `jwt-secret` 与 `session-keys/*` 两行与下面 `aws ssm put-parameter …jwt-secret` 代码块；"两个密钥都不进 Lambda 环境变量"段改写为"会话签名密钥不在 SSM：它们是 KMS 非对称 CMK（下一节）"。

（b）在 `### SSM 参数` 之后新增 `### 会话签名密钥（KMS）`：

```markdown
### 会话签名密钥（KMS）

会话 token（站点会话 `sb_session`、升级码、面板会话 `__Host-sb_console`）用 **RS256** 签，私钥在两把
KMS 非对称 CMK 里（`RSA_2048` / `SIGN_VERIFY`，默认 key policy——理由见 `docs/adr/0001-*.md`），
由 ④ 的 deployer 栈创建；auth 持两把的 `kms:Sign`，panel 只持 console 那把，Edge **零 KMS 权限**、
只内嵌 site 公钥。**任何组件的产物、环境变量、SSM 里都没有能签会话的材料**——这是资产在共享账号里
站得住的前提（`docs/security/account-trust-boundary.md`）。

回填 `config.ini` 的 `[SessionKeys]`：④ 部完后

```bash
python3 site-builder/scripts/session_key_fingerprint.py --from-stack     # 打印两个 [SessionKey:*] 小节（含 spki_sha256）
```

把输出粘进 `site-builder/config.ini`（替换 `.example` 里的占位）。三个部署脚本（router 栈 synth、`deploy_auth`、
`deploy_panel`）在第一次写之前都会对每把 key 做 DescribeKey + GetPublicKey 四项校验，指纹与 config 不符即
拒绝部署——所以**先部 ④ 再部 ②**（下面「部署顺序总览」的依赖箭头）。

每把 key 运行时的成本：$1/月 + `kms:Sign` 每万次 $0.03（只在登录 / 换码路径调用，不在每请求路径）。
```

（c）`#### 轮转密钥：四类的代价完全不同` → 改为三类（client secret / login-flow / 会话签名 key），删 `jwt-secret` 那类。

（d）`#### 轮转会话密钥：十步 runbook` 整节（到 `##### 应急` 之前）替换为 KMS 版：

```markdown
#### 轮转会话密钥（KMS）：就位 → 切换 → 排空 → 退役

**这是可执行协议，不是描述。** 每一步 = 一处 `config.ini`（或 `deployer/infra/app.py`）修改 + 现成脚本 +
一个硬停止点 + 该步的闸门声明。非对称 CMK 不支持自动轮转（spec §3.3），所以轮转就是**加一把新 key、
让三处 verifier 先认它、再切签发、排空后退役旧 key**。两个 family 可以同步做，也可以只轮一个。

##### 开始之前

```bash
python3 site-builder/scripts/preflight_config_states.py     # 只读 config、不碰 AWS：把就位/切换/退役三个状态各跑一遍单测，先找出写死当前 kid 的用例
```

##### 两个方向相反的顺序，别照抄错

- **新建部署**：**④ deployer 栈先于 ② router 与 auth / panel**（依赖——三处 synth / 部署时要从 KMS 取公钥并核对指纹）。
- **切换（本 runbook）**：**verifier 先行**。所有验签方先能接受新 key，才允许 signer 用它签。理由是速度差——
  auth / panel 重部几分钟就切，Edge 要重部 + 10–20 分钟全球复制；signer 先切等于让新 cookie 在旧边缘节点上
  验签失败，用户登录后立刻被踢回登录页。

##### 槽位语义

术语真源是根 `CONTEXT.md` 的 **Key family** / **就位** 两条：`current` = 签发用的那把；`previous` = 另一把
**被接受**的 key——要么是排空中的旧 key，要么是就位中的新 key。新 key 一律经 `previous` 就位，切换 = 两槽互换。
就位期 `accepted_previous` 应当只来自我们自己的探针。

##### ① 建新 key（deployer 栈）

`deployer/infra/app.py` 里那个 `for construct_id, kid in (...)` 元组**加一项**（`("SiteSessionKeyRsV2", "site-rs-v2")`；
不动旧项），然后：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/session_key_fingerprint.py --kid site-rs-v2 --arn "$(aws cloudformation describe-stacks --stack-name SiteDeployerStack --query "Stacks[0].Outputs[?OutputKey=='SiteSessionKeyRsV2Arn'].OutputValue | [0]" --output text)"
```

把打印的 `[SessionKey:site-rs-v2]` 小节粘进 `config.ini`，**先不改 `site_previous`**。闸门第一轮（只有 key、还没人
持它的 grant——auth / panel 的 IAM 在下一步才扩）：

```bash
python3 site-builder/scripts/verify_account_trust_boundary.py --new-key site-rs-v2      # 期望：kms 分节新出现 site-rs-v2（已声明，绿）
```

##### ② 就位：新 key 进 `previous`，三处 verifier 先认

`config.ini`：`site_previous = site-rs-v2`。然后 **auth → panel → Edge** 重部（auth / panel 的 IAM 随之多出对
v2 的 `kms:Sign` / `GetPublicKey`；Edge 的 allowlist 多一把公钥）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/auth && python3 deploy_auth.py)
(cd site-builder/panel && python3 deploy_panel.py --skip-frontend)
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
# 等 CloudFront 真的 Deployed（10–20 分钟），然后：
bash site-builder/scripts/verify_deployed_edge.sh
python3 site-builder/scripts/verify_kid_entry_live.py --role previous        # 用就位中的 key 签的夹具会话必须 200（会消费一枚升级码）
python3 site-builder/scripts/verify_account_trust_boundary.py --new-key site-rs-v2   # auth 多出 kms-sign:site-rs-v2（已声明）
python3 site-builder/scripts/verify_account_trust_boundary.py --new-key site-rs-v2 --update-baseline
```

**console family 的就位没有正向探针**（夹具签发器只签站点会话，ADR 0002）：`console_previous` 就位后能做的只有
`verify_deployed_components.py` 的三方公钥对账（静态证据），第一次真机证明发生在 ③ 切换那一刻。这是刻意接受的代价：
console family 的 verifier 只有 auth 与 panel（Edge 不持 console 公钥），切错的回滚是把 ③ 那两行 config 改回来重部两个
Lambda，约 5 分钟、无 CloudFront 窗口。
（**就位期没有正向探针这一条仍然成立；退役期的负向探针不同——那一条是有的**，见 ⑤ 与 SDD ledger Ruling R26。）

##### ③ 切换：两槽互换（= T1）

`config.ini`：`site_current = site-rs-v2`、`site_previous = site-rs-v1`。**panel 先、auth 后**重部，然后 Edge
重部一次只为把 current / previous 标签摆正（排空曲线要在 Edge 列上读）：

```bash
# ⚠️ **换槽位之前先预存 console family 的负向探针**（执行时补，见 SDD ledger Ruling R26）：升级码永远由
# console 的 **current** key 签（`_session_mint` 在 argparse 层就拒 `--role previous` 配 console-upgrade），
# 所以"要退役的那把"只有在**这一刻**还是 current；换完槽位就再也签不出用旧 key 签的升级码了。
# 这是整条 runbook 里唯一一处"晚了就补不回来"的取证。
python3 site-builder/scripts/_session_mint.py --token-use console-upgrade --email probe@e2e.invalid \
  --save rotation/console-v1-upgrade.json
#   记录里 role 写的是 `current`——那是**诚实的**：签它的就是当时的 current key（即将退役的那把）。
#   码的 TTL 只有 60 秒，到 ⑤ 早已过期，但那不妨碍这条证明：spec §5 的合同是 **kid 先于 exp**
#   （`session.verify_token` 在 kid 不在 allowlist 时直接返回 `unknown_kid`，根本走不到过期判定）。
#   **只在本轮真的要退役 console family 时才预存它**；同理只轮 console 时 site 那条 --save 也不要做。
(cd site-builder/panel && python3 deploy_panel.py --skip-frontend)
(cd site-builder/auth && python3 deploy_auth.py)
python3 site-builder/scripts/verify_kid_entry_live.py --role current
python3 site-builder/scripts/verify_kid_entry_live.py --role previous
# Edge 重部（同 ② 的三步 + 等 Deployed）
```

回滚 = 两槽换回去、重部 panel + auth（Edge 不动：它两把都认）。

##### ④ 排空（≥ T1 + 26 h）

```bash
python3 site-builder/scripts/verify_console_e2e.py && python3 site-builder/scripts/verify_analytics_e2e.py   # 先证明埋点在工作
python3 site-builder/scripts/session_verify_counts.py --drain-gate previous    # 四条判据锁在脚本里：窗口 ≥ 26 h、每处总量 > 0、accepted_previous 三列全 0、accepted_current 三列全 > 0
```

exit 0 才算过。26 = 站点会话 TTL 24 h + Edge 全球复制 + 余量。

##### ⑤ 退役旧 key（**最后一步不可逆**）

```bash
python3 site-builder/scripts/_session_mint.py --token-use site-session --role previous --save rotation/site-v1.json   # 先预存负向探针
```

**退役是按 family 各做一遍的**，两个 family 的动作不一样（Edge 只持 site 公钥）——**执行时修订：原文只写了
site 那一路**（见 SDD ledger Task 16 fix round 2）：

| 要退役的 family | `config.ini` | `app.py` | 重部 |
|---|---|---|---|
| **site** | `site_previous =`，删 `[SessionKey:site-rs-v1]` 小节 | 删 `SiteSessionKeyRsV1` 那**一整段**（`kms.Key` + `CfnOutput`） | **auth → panel → Edge**，等 CloudFront `Deployed` |
| **console** | `console_previous =`，删 `[SessionKey:console-rs-v1]` 小节 | 删 `ConsoleSessionKeyRsV1` 那一整段 | **auth → panel**（Edge 不持 console 公钥 ⇒ 不用重部、没有 10–20 分钟窗口）|

`RemovalPolicy.RETAIN` ⇒ 删掉 construct 只是让 key 脱离栈管理，key 与 alias 留在账号里；最后一步
`schedule-key-deletion` 才真的删。**只轮一个 family 时只做那一行**：③ 的预存与下面的探针都只对**本轮真的
在退役**的 family 有意义，拿一个仍在 allowlist 里的 kid 去跑探针会得到**假绿**。重部完之后：

```bash
# ① 真机负向：本轮退役了哪个 family 就带哪条 --retired-token（两个都退就都带）
#    站点会话期望 302（Edge），升级码期望 401（panel）
python3 site-builder/scripts/verify_kid_entry_live.py \
  --retired-token .scratch/rotation/site-v1.json \
  --retired-token .scratch/rotation/console-v1-upgrade.json
# ② **HTTP 状态本身不是证据**（执行时修订，Task 16 fix round 2）：预存的 token 到这时早已过期，而"过期"与
#    "kid 已退役"在两处都被压成同一个响应（Edge 都是 302 回登录，panel 的 UpgradeRejected 都是 401）
#    ⇒ kid 其实还在 allowlist 里也会绿。分辨只能读埋点的 outcome：`unknown_kid` 那一行，
#    **site 探针看 `edge` 列、console 探针看 `panel` 列**，本轮退役的 family 对应的那列必须 ≥ 1。
#    （`expired` ≥ 1 而 `unknown_kid` 仍是 0 ⇒ 退役没生效，别继续往下走。）
python3 site-builder/scripts/session_verify_counts.py --hours 1
python3 site-builder/scripts/verify_account_trust_boundary.py --retire-key site-rs-v1
python3 site-builder/scripts/verify_account_trust_boundary.py --retire-key site-rs-v1 --update-baseline
# 不可逆：先读回 key 的描述核对账号与 alias，再排期删除（7–30 天窗口内仍可取消）
aws kms describe-key --key-id <site-rs-v1 的 key ARN> --query 'KeyMetadata.[Arn,Description,KeyState]'
aws kms schedule-key-deletion --key-id <site-rs-v1 的 key ARN> --pending-window-in-days 7
```

**console family 的真机负向探针靠 ③ 里预存的那枚升级码**（Ruling R26 修正了先前"码过期所以 401 证明不了什么、
console 只能有静态证据"的裁定：`verify_token` 先查 kid 再查 exp，退役后过期的旧码仍得 `unknown_kid`）。
**静态证据保留为补充，不是替代**：panel 的 allowlist 单测 + `verify_deployed_components.py` 的三方对账
（退役 kid 同时不在 env、config 与 KMS 集合里）+ 闸门的 `--retire-key`。site 的负向探针**不能**替 console
作证，反之亦然——两个 family 的 allowlist 各自独立注入。

##### 回滚一览

| 出问题的步骤 | 回滚动作 | 要不要动 Edge |
|---|---|---|
| ② 就位 | `*_previous` 清空 → 重部三处 | 要 |
| ③ 切换 | 两槽互换回去 → 重部 panel + auth | 不要 |
| ⑤ 退役（删 key 之前） | **按本轮退役过的每个 family 各回一遍**：site → 填回 `site_previous` + 小节 + `SiteSessionKeyRsV1` construct，重部 auth → panel → Edge；console → 填回 `console_previous` + 小节 + `ConsoleSessionKeyRsV1`，重部 auth → panel。**回滚后对应的负向探针会失败**（旧 kid 又被接受了）——那是预期，不是新缺陷 | site 要，console 不要 |
| ⑤ 退役（已 schedule-key-deletion） | 窗口内 `aws kms cancel-key-deletion`，否则建新 key 从 ① 重走 | 要 |
| 代码本身有 bug | git 重部（`AUTH_PACKAGE_MODULES` / `COPY_FILES` 守卫先跑一遍） | 视改动 |

三条原则：signer 的回滚永远只是"改配置重部 auth/panel"（verifier 全程两把都认）；verifier 不回滚（它认的是超集）；
key 只在 ⑤ 的最后一步删。

##### 应急：一把会话签名 key 疑似被滥用

`kms:Sign` 的调用者与次数在 CloudTrail 里（`eventName=Sign`、`resources.ARN`）——先看是谁。处置走 ①→②→③ 再**直接跳到 ⑤**
（跳过 26 h 排空），代价是每个持旧 cookie 的用户被踢回登录页一次（不是循环）。**处置期间不要因为"用户报登录跳转"
就回滚 Edge**，回滚只会把窗口拉长。login-flow secret 泄漏的处置是 `aws ssm put-parameter --overwrite`（5 分钟内
进行中的登录失败一次，无会话影响）。
```

（e）`## 部署顺序总览`：箭头图改为

```
①身份层 → ③DSQL → ④执行器(第一次) → 回填 [SessionKeys] → ②路由层 → 回填 edge_role_arn → ④执行器(第二次) → auth → ⑤部署MCP → ⑤b控制台 → 夹具站点 → ⑥客户端接入 → ⑦端到端彩排
```

**（执行时修订，见 SDD ledger Task 16 review Important 1）：原文只把 ④ 挪到 ② 之前，那样写会成环——
必须写成 ④ 部两次。** ② 与 auth / ⑤b 依赖 ④ 建的两把 CMK（router 栈 synth 时从 KMS 取 site 公钥、
auth / panel 部署前核对 `spki_sha256`，不符即拒绝部署），而 ④ 的 step Lambda 又要 ② 产出的
`edge_role_arn` ⇒ **全新账号上 ④ 要部两次**：④（只为建 CMK）→ 回填 `[SessionKeys]` → ② →
回填 `edge_role_arn` → ④ 再一次。**漏掉第二次是无声的**（空 `EDGE_ROLE_ARN` 照过 synth 与部署，
到第一次真实建站才炸），所以这一段要在箭头图下方明文写出来，不能只靠箭头。
存量重部顺序不变（`MCP 先于执行器栈` 那条照旧）。`### 存量站点迁移到 blue/green` 整节删。`验收` 相关处加 `python3 site-builder/scripts/ensure_fixture_site.py`（建常驻夹具站点；`[Verification] fixture_issuer = true` 时才有意义）与四个 `verify_*` 的前置说明（登录态来自夹具签发器，`[Verification]` 段与 `verifier_trusted_principals` 里要列本机凭据对应的 IAM ARN）。生产验签点那张表（`test_deploy_md_lists_every_production_session_verifier` 守着）：三行的函数名改 `verify_token`（auth `/console-session`、panel 升级码与面板会话）与 `_verify_session_jwt`（Edge）。`S1 加固` 一节里若引用 `ensure_session_keys` / `jwt-secret` 的行改掉。

（f）「本机工具链」：Python 一行加"host `python3` **需要** `cryptography`"——`deploy_auth` / `deploy_panel` /
`verify_deployed_components` / `session_key_fingerprint.py` 与两个闸门现在 import 期就经 `session_kms` → `session`
用它解析公钥、核对指纹。**（执行时修订，见 SDD ledger Ruling R14：plan 原文写的是"不需要 cryptography
（闸门脚本只用 boto3 + hashlib）"，那是 3c-final 之前的事实，必须反转。）** 同时把宿主依赖三件套改成四件：
`bootstrap_venvs.sh --host-deps`、CLAUDE.md「仓库外的几样东西」第 3 步、DEPLOY.md「本机工具链」三处同步
（宿主上不钉版本；Lambda 产物里钉 50.0.0）。R18 连带：CLAUDE.md 的 venv 表与「本机工具链」里
"router venv 只有 CDK 依赖"那句要改成"CDK 依赖 + `cryptography`（synth 期核对 KMS 公钥指纹）"。

（g）散落处（survey 点名的行；行号会漂，按原文 grep）：`## 部署顺序总览` 里"②需要①产出的 JWT_SECRET（已在 SSM）…⑤b 需要…①的 jwt-secret"那句改成"② 与 auth / ⑤b 都需要 ④ 的两把 CMK（config 回填 `[SessionKeys]` 后才能部）"；`## 部署后回填检查清单` 里 `SSM /site-builder/jwt-secret 已创建` 与 `ensure_session_keys.py 已跑过` 两条删，换成 `[SessionKeys] 两个 [SessionKey:*-rs-v1] 小节已按 session_key_fingerprint.py 回填` 与（可选）`[Verification] 已配置且 ensure_fixture_site.py 已跑`；`## ② 路由 + 鉴权层` 的 step 5 注释"生成/复用 SSM /site-builder/jwt-secret"删、"stack.py 从 SSM 读密钥"那段改成"synth 时从 KMS 取 site 公钥并核对指纹，读不到即 synth 失败"；`router/config.ini.example` 里 "Create the keys with site-builder/scripts/ensure_session_keys.py … ten-step runbook" 两行改为 "Keys are KMS CMKs created by the deployer stack; the Edge only embeds site public keys (stack.py fetches them at synth). Rotation follows DEPLOY.md「轮转会话密钥（KMS）」"；`scripts/which_targets_to_redeploy.py` 的 `SEMANTIC_COUPLINGS` 注释里 "HS256 会话验签" 改 "RS256 会话验签"。

- [ ] **Step 4: `CLAUDE.md`**

- 第 26 行「资产包含什么」：`会话签名带 kid，每个 key family…legacy…signer = legacy…密钥形态是 HS256 对称，非对称化（KMS）是…3c-final` 那段改为：`会话签名是 RS256：两把 KMS 非对称 CMK（site / console 两个 key family，各有 current 与 previous 两个 kid 槽位，可轮转），auth 持两把的 kms:Sign、panel 只持 console、Edge 零 KMS 权限只内嵌 site 公钥；验收工具的登录态来自 auth 的 /fixture-session（夹具域 e2e.invalid，可选组件 [Verification]）。`
- 第 32 行「三条设计边界」第三条整段改为：`**平台的安全边界是 AWS 账号本身，但面从"能读"收到了"能签或能改验签代码"**：账号内能 kms:Sign 两把 CMK（或能给自己授权）、能改 auth / panel 的代码或配置、能替换 CloudFront 正在执行的 Edge 版本的 principal 仍能冒充任意用户；只读级权限（ReadOnlyAccess）不再够——Edge 产物、bootstrap asset、SSM 里都只有公钥与 login-flow secret。数字与方法在 docs/security/account-trust-boundary.md，闸门是 verify_account_trust_boundary.py（KMS 层：kms:Sign / PutKeyPolicy / CreateGrant 持有者、key policy、grants、公钥指纹）。**别按 merged review 里 M09 第 2 步的原话去收窄 invoke，那是假修复。**`
- 「测试命令」块：E2E 那行的 `**10 条**` 改 `**9 条**`（存量迁移那条随脚本删了）；`verify_kid_entry_live.py` 注释改 `--role current|previous`（正向，夹具站点；消费一枚升级码）/ `--retired-token FILE`；`session_verify_counts.py` 注释里删 `（legacy 用 --drain-gate legacy）`；`verify_account_trust_boundary.py` 注释里 `LABEL ∈ 已配置 kid ∪ {legacy, login-flow}` 改 `∪ {login-flow}`，`--new-key` 的前置条件那句改成"该 principal 原本就能签某把会话 key"，加一句"**没有基线时只能 --update-baseline 生成，不能出结论**（基线 gitignored，含单账号实测）"。加 `python3 site-builder/scripts/ensure_fixture_site.py   # 常驻夹具站点（四个 verify_* 与 kid 探针只打它）`。
- 「部署/重部署命令」块：删 `ensure_session_keys.py` 那段（含前面六行注释）与 `migrate_sites_to_blue_green.py` 两行及注释；在执行器栈之后加 `python3 site-builder/scripts/session_key_fingerprint.py --from-stack   # 首次 / 加 key 时：把两个 [SessionKey:*] 小节粘进 config.ini`；router 栈那段前加一句 `# 依赖 ④ 的 CMK：synth 时从 KMS 取 site 公钥并核对 config 的 spki_sha256`。
- 「不可破坏的系统不变量」auth/session ↔ Edge 那条：`session.verify_with_legacy` → `session.verify_token`；「顺序有两个方向」：新建 = `deployer 栈先于 router 与 auth/panel`（依赖 CMK），切换 = verifier 先行（理由不变）。
- 「跨组件改动矩阵」：删 `signer(legacy|current)` 与 `legacy_param 清空` 两行；`[SessionKeys]` 行改为 `config.ini.example、session_key_fingerprint.py、deploy_auth/deploy_panel 的 env（SESSION_KEYS_JSON 的 RS 行）与 KMS IAM 清单、router/infrastructure/stack.py 的公钥注入、闸门 kms 分节、verify_deployed_edge.sh 的公钥对账、verifier_env.py（auth 拥有、panel 复制）、session_kms.py（同上）`；`login_flow_secret_param` 行删 `ensure_session_keys.py 创建、`；`_session_mint.py` 行改 `夹具签发器客户端：六处调用方 + ensure_fixture_site.py；改它等于同时改六个验收面；它不持任何密钥`；`function_url_policy.py` 行加 `extra_principals（[Verification] 开着时 auth 多 verifier 两条）`；新加一行 `session.py 的 FIXTURE_* 常量 | Edge 内嵌字面量（router 单测钉住等值）、permissions.FIXTURE_DOMAIN（auth 单测钉住等值）、deploy_panel 的 admin 断言、ensure_fixture_site.py、闸门站点形状层`。
- 「文档地图」：`轮转会话密钥` 行改为 KMS 版 runbook 描述（就位 → 切换 → 排空 → 退役），删 `.scratch/3c-1b/` 那句；`3c` 那行保留但去掉"HS 不进 v1"之外的时序描述不动（那是 spec 自己的事）。
- 「高频坑」：加一条 `**auth / panel 的 `SESSION_KEYS_JSON` 只有 kid / key_arn / spki_sha256，公钥运行时按 ARN 取、指纹不符即拒（冷启动 500 而不是接受一把来历不明的公钥）。改了 CMK 却没重跑 session_key_fingerprint.py 回填 config，三个部署脚本都在第一次写之前拒绝部署——那不是权限问题。**`；`ensure_session_keys` 相关的坑删。

改完跑 `cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q`——状态词守卫与 HS 词汇守卫都在这里。

- [ ] **Step 5: `CONTEXT.md`、`README.md`、ADR、spec、§9、威胁模型**

- `CONTEXT.md`：删 **Legacy entry** 与 **Signer switch** 两条；**Key family** 里 "current 是 signer 开关为 current 时签发用的那把" → "current 是签发用的那把"；**Retire** 里 "或 legacy 入口" 删；**Observation window** 里 "退役 legacy 入口或 previous key" → "退役 previous key"。
- `README.md`：第 77 行 `Lambda@Edge 验 HS256 会话 cookie` → `验 RS256 会话 cookie（公钥内嵌，私钥在 KMS）`；第 105 行 `用平台 JWT_SECRET 直接 mint 测试会话 cookie` → `经 auth 的 /fixture-session 取夹具会话（ADR 0002）`；第 123 行 `SSM 里的会话签名密钥` → `两把 KMS 非对称 CMK`；成本段（若 README 有成本行）加一行 `KMS：两把 RSA_2048 CMK $2/月 + kms:Sign 每万次 $0.03（只在登录 / 换码路径）`。
- `docs/adr/0002`：Consequences 加一条"Edge 对夹具会话的放行范围是**夹具站点 ∪ 平台路由（console）**——升级码与面板会话走真实换取链路，那条链路的入口在 console 平台路由上（plan 08 D6）"；"不得晚于它" 那条保留。
- `docs/adr/0003`：Consequences 第二条改为"`cryptography` 的 import 与一次黄金三元组验签在模块顶层（预热），allowlist 的公钥在首次使用时解析一次（ticket 21 的惰性形态，让注入坏掉时公开路由不受影响）；Edge 单测断言两者的位置"。
- `docs/adr/0004`：正文里把 `ensure_session_keys.py` 写成 login-flow secret 创建方的那处，改为"创建方只剩 `deploy_auth.ensure_secret`（`ensure_session_keys.py` 随 3c-final 删除，plan 08 D5）"；结论（不进写前核对清单）不动。ADR 目录在 HS 词汇守卫的例外里，这一句守卫抓不到，要手工改。
- `docs/adr/0005`：第 30 行 "工单 12 执行；今天仍是 tracked" → "工单 08 执行（3c-final 的闸门改动同一处）"。
- spec 状态行（第 3 行起）：追加 "3c-final 已实施并在验证环境硬切换（日期见 §6.1）"；§6.1 3c-final 行末加 "**已实施并部署 <日期>**（plan `2026-09-07-asset-v1-08-3c-final-kms-only-hard-cutover.md`）"——**日期在 Task 22 ★ 填**。
- merged review §9：3c 行加 "**✅ 3c-final 已部署 <日期>**（asset-v1 工单 08）"；第 6 行 M08 "→ 删脚本" 加 "✅ 已删（工单 08）"；第 12 行加 "基线 untrack 已随 08 完成；探针结果 JSON 与 DEPLOY.md 时间线仍归本行"。
- `docs/security/account-trust-boundary.md`（D12 的范围）：头部状态段加一段「3c-final 之后」：面从"能读密钥"收到"能签（kms:Sign / 自助授权）∪ 能替换 Edge / 劫持 signer"，读 Edge 产物 / asset / SSM 不再进冒充面；`## 实测` 表：删 `带活密钥的Edge代码目标` / `带活密钥的asset` 两行，`可读密钥` 行改 `可签会话`（标记 `baseline:可签会话=`），加一行 `会话签名 CMK 数 <!-- baseline:CMK数=2 -->`；数字在 Task 21 ★ 后按本地基线回填。`## 密钥有三条路能拿到` 一节顶部加 "**历史（HS256 形态）**：3c-final 之后这三条路读到的只有公钥" 的横幅（守卫 `_SUPERSEDED_MARKERS` 认 "历史记录"）。`### 这道闸门不证明什么` 里 "不看 KMS grants" 那句改为 "KMS 层看 key policy 快照、grants、kms:Sign / PutKeyPolicy / CreateGrant 的 identity policy 上界；不看 assume-role 链"。**其余大段改写归工单 12/13。**

- [ ] **Step 6: 七套件全绿 + Commit**

按 Global Constraints 的顺序跑全部七套（约 15 分钟；contract 的墙钟哨兵红了先重跑一次）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh
git add CLAUDE.md CONTEXT.md README.md site-builder/DEPLOY.md docs/security/account-trust-boundary.md docs/adr docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md site-builder/deployer/tests/test_delivery_docs_current.py
git commit -m "docs(asset-v1/08): 采用者文档改 KMS-only（部署顺序、KMS 轮转 runbook、CLAUDE.md 边界与矩阵、CONTEXT 词表、ADR 0002/0003/0005 修订）；HS 词汇只许留在决策记录（守卫）"
```

---

### Task 17 ★：切换前的最后一道——七套件、/code-review、`verify_*` 的自测、Orca 状态

- [ ] **Step 1: 七套件顺序全绿**（同 Task 16 Step 6；结果写进 progress，标 fake/unit）
- [ ] **Step 2: `/code-review`**：固定点 = Task 0 的 SHA（`git log -1 --format=%H` 记的那个），范围 = 到当前 HEAD 的全部 commit；按 `superpowers:receiving-code-review` 处理 findings，修复各自 commit（前缀 `fix(asset-v1/08):`），只复审 finding-closure diff。
- [ ] **Step 3: 不碰 AWS 的自测**：`python3 site-builder/scripts/verify_kid_entry_live.py --self-test`、`python3 site-builder/scripts/verify_session_token_semantics.py --self-test`、`python3 site-builder/scripts/probe_impersonation_surface.py --self-test`、`bash site-builder/scripts/verify_deployed_edge.sh --help 2>/dev/null || bash -n site-builder/scripts/verify_deployed_edge.sh`（语法）。
- [ ] **Step 3b: 切换前夕的 before 快照 + 回滚就位（同一个 worktree）**

HEAD 的闸门脚本自 Task 2 起是 RS-only、读不了 HS 形态的 config，所以切换前的最后一次对照只能用 Task 0 SHA 的旧代码；这个 worktree 同时就是 Task 19 ★ Step 7 的回滚工作树。**必须在 Step 4 改 config 之前做**（复制进去的要是未加 `[Verification]` 的 HS 形态原件）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
SHA0=<Task 0 ★ Step 3 记进 progress 的 SHA>
git worktree add .scratch/asset-v1/08/wt-before "$SHA0"
cp site-builder/config.ini .scratch/asset-v1/08/wt-before/site-builder/config.ini
cp router/config.ini .scratch/asset-v1/08/wt-before/router/config.ini
chmod 600 .scratch/asset-v1/08/wt-before/site-builder/config.ini .scratch/asset-v1/08/wt-before/router/config.ini
# ① 旧代码 + 旧基线再跑一遍闸门（约 11 分钟、只读；宿主 python3，不需要 venv）——Task 21 ★ 对照的是这一份
(cd .scratch/asset-v1/08/wt-before && python3 site-builder/scripts/verify_account_trust_boundary.py --dump-observed ../gate-before-dump.json 2>&1 | tee ../gate-before.txt)
(cd .scratch/asset-v1/08/wt-before && python3 site-builder/scripts/verify_account_trust_boundary.py --from-dump ../gate-before-dump.json 2>&1 | tee -a ../gate-before.txt)
# ② 回滚就位：router 的 CDK venv 现在就建（同机另开 worktree 必须重建，CLAUDE.md；热缓存约 3.5 分钟）。
#    只建这一个：回滚不碰 deployer 栈（两把 CMK 留着无害），panel / auth 的部署脚本用宿主 python3。
(cd .scratch/asset-v1/08/wt-before && bash site-builder/scripts/bootstrap_venvs.sh --only router/infrastructure)
```

Expected: 第二条闸门 exit 0（与 Task 0 同样"与基线一致"）；**红则停**——那是 Task 0 之后账号里新出现的无关漂移，先处理再切换。`bootstrap_venvs.sh` 结束时打印 router venv 的解释器版本。Task 0 那份旧 dump 被覆盖是刻意的：before 快照只保留切换前夕这一份。

- [ ] **Step 4: 写前置**：`site-builder/config.ini` 加 `[Verification]`（`fixture_issuer = true`、`verifier_trusted_principals = <本机凭据对应的 IAM ARN，aws sts get-caller-identity 取；assumed-role 形态要换成 role ARN>`）；`[SessionKeys]` **暂不改**（Task 18 ★ 回填 RS 行——此刻 config 仍是 HS 行，`load_session_keys` 会拒，所以本步之后到 Task 18 ★ 之间**不要跑任何读 config 的脚本**）。
- [ ] **Step 5: 停止点**：progress 记 HEAD SHA；确认当前时间窗口可以接受 10–20 分钟登录中断，通知（若有）其他使用者。

---

### Task 18 ★：建 CMK、回填 `[SessionKeys]`（无用户影响）

- [ ] **Step 1: 部署 deployer 栈（bundling 需 Docker）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest diff 2>&1 | tail -40)
# diff 预期（执行时修订，见 SDD ledger Task 18 ★ Step 1）：2 个 AWS::KMS::Key（新增）+ 2 个 AWS::KMS::Alias
# （新增）+ 2 个 Output（新增）+ **全部 step Lambda 的 Code（且只有 Code）**。别的变化先停下解释。
#
# 那批 Code 更新是本分支自己的改动，不是意外：Task 6 / 9 / 15 改了 `deployer/functions/` 下四个文件
# （deploy_lambda_site / function_url_policy / permissions / register_route），而 `app.py` 把**整个**
# functions/ 目录打进每一个 step Lambda 的产物（bundling 的与裸 from_asset 的都算）⇒ 每个 Lambda 的
# asset S3Key 都变。核对方法：`git diff --stat <SHA0>..HEAD -- site-builder/deployer/functions`
# 只应是那四个文件；要更硬的证据就下载线上任一 step Lambda 的产物，与 SHA0 的 worktree 逐字节比
# （除那四个文件外应完全相同）。IAM 变化只应有两把 key 的 root 委派 key policy。
#
# 顺带（pre-existing，不属本票）：`from_asset` 没有 `exclude` ⇒ `functions/__pycache__` 会被打进产物，
# asset hash 跨 worktree / 跨次不可复现，所以**每次** deployer 栈部署都会更新全部 step Lambda。
# 功能无害（Python 按源文件 mtime/size 校验 .pyc），归后续工单（`exclude=["__pycache__"]`）。
(cd site-builder/deployer/infra && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
```

Expected: 栈 UPDATE_COMPLETE；`aws kms describe-key --key-id <ARN>` 两把都是 `RSA_2048` / `SIGN_VERIFY` / `Enabled`。**这一步对线上零影响**（没人用这两把 key）。

- [ ] **Step 2: 备份两份 config，再回填**

config.ini 是 gitignored，`git stash` 收不到它——改之前先留一份 HS 形态的副本（Task 17 ★ 的 worktree 里已有一份；这里是第二份，worktree 丢了时用）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cp site-builder/config.ini .scratch/asset-v1/08/config.ini.site-builder.pre-3c-final
cp router/config.ini .scratch/asset-v1/08/config.ini.router.pre-3c-final
chmod 600 .scratch/asset-v1/08/config.ini.*.pre-3c-final
python3 site-builder/scripts/session_key_fingerprint.py --from-stack
```

把两个小节粘进 `site-builder/config.ini`：`[SessionKeys]` 段删 `signer` / `legacy_param` 两行，`site_current = site-rs-v1`、`console_current = console-rs-v1`、两个 `*_previous` 空，删 `[SessionKey:site-hs-v2]` / `[SessionKey:console-hs-v2]` 两节，加粘贴的两节。自检：

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/auth" && ../contract/.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from session_keys import load_session_keys; k = load_session_keys(__import__('pathlib').Path('../config.ini'))
print([r.kid for f in ('site','console') for r in k.allowlist(f)])"      # ['site-rs-v1', 'console-rs-v1']
```

- [ ] **Step 3: 停止点**：progress 记两把 key ARN 的**指纹**（不记 ARN 本体——它含账号 ID；ARN 只在 config.ini）。此刻线上仍是 HS，一切照常。

---

### Task 19 ★：硬切换（verifier 先行：router → panel → auth），窗口，验收

**窗口开始于 router 部署完成的那一刻**（Edge 新版本开始在部分边缘节点接管 ⇒ 现存 HS cookie 被拒 ⇒ 302 登录 ⇒ auth 仍签 HS ⇒ 再被拒 ⇒ 循环），**结束于 auth 部署完成 + CloudFront Deployed**。全程约 15–25 分钟。窗口内不跑任何 `verify_*`。

- [ ] **Step 1: router（open → deploy → apply）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never) || true
python3 site-builder/scripts/router_stack_policy.py apply        # open 之后无论成败都要 apply
```

Expected: synth 阶段打印 pip 交叉装（cryptography 三包）且**没有** `SYNTH-ONLY` 警告；`cdk deploy` 成功，Edge 新版本号 +1。失败则不部 panel / auth，线上仍是 HS，无窗口（回到 Task 11 排查）。

- [ ] **Step 2: panel、auth**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/panel && python3 deploy_panel.py)              # 不带 --skip-frontend：前端没改也无妨；带上会走 keep 逻辑
(cd site-builder/auth && python3 deploy_auth.py)               # 创建 site-builder-verifier、Function URL 多两条语句、FIXTURE_ISSUER=on
# 下面两个不验会话、不在窗口关键路径上；它们各自把 permissions.py 打进产物（mcp/Dockerfile 的 COPY、deploy_key_proxy 的 COPY 清单），
# Task 9 改了它 ⇒ 必须重部，MCP 还必须完整 build（不能 --skip-build）。漏了的症状是部署脚本一切正常而
# verify_deployed_components.py 报副本陈旧（CLAUDE.md 高频坑）。buildx 的几分钟正好落在等 CloudFront Deployed 的时间里。
(cd site-builder/mcp && python3 deploy_agentcore.py)
(cd site-builder/key-proxy && python3 deploy_key_proxy.py)     # 无 [ApiKey] 段时打印跳过并返回 0
```

Expected: panel / auth 两个脚本的 precheck 打印 KMS 四项通过；MCP 打印新镜像 digest 与 runtime 更新完成；`deploy_auth` 打印 `Function URL 授权（收敛前的漂移…）：缺 2 条(verifier-invoke, verifier-invoke-function)`（第一次）；`deploy_panel` 的 admin 断言通过。

- [ ] **Step 3: 等 CloudFront Deployed，然后全员重登**

```bash
aws cloudfront get-distribution --id "$(aws cloudformation describe-stacks --stack-name "$(python3 - <<'PY'
import configparser; c=configparser.ConfigParser(interpolation=None); c.read('router/config.ini'); print(c['CDK']['stack_name'].split('#')[0].strip())
PY
)" --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue | [0]" --output text)" --query 'Distribution.Status' --output text
```

`Deployed` 之后：操作者浏览器里对 `console.{base}` 登录一次（顺带刷新 MCP token：`node site-builder/clients/quick-desktop-proxy/auth.js`）。

- [ ] **Step 4: 部署面闸门**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/verify_deployed_edge.sh
python3 site-builder/scripts/verify_deployed_components.py
```

Expected: 全 PASS（含 Edge 产物公钥对账、三方指纹、verifier 两条语句、`FIXTURE_ISSUER=on`）。

- [ ] **Step 5: 常驻夹具站点 + 真机闸门**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/ensure_fixture_site.py                       # 首次：部署 e2e-probe（约 3 分钟）
python3 site-builder/scripts/verify_kid_entry_live.py
python3 site-builder/scripts/verify_kid_entry_live.py --role current
python3 site-builder/scripts/verify_session_token_semantics.py
bash site-builder/scripts/smoke_router.sh
python3 site-builder/scripts/verify_console_e2e.py
python3 site-builder/scripts/verify_analytics_e2e.py
python3 site-builder/scripts/verify_api_key_e2e.py                        # 有 [ApiKey] 段才跑
python3 site-builder/scripts/session_verify_counts.py --hours 1 --require-total
```

Expected: 全绿；`session_verify_counts` 三列 `accepted_current > 0`、无 `accepted_legacy` 列。**任一红且判断为切换缺陷** ⇒ 回滚（Step 7）。

- [ ] **Step 6: E2E 后台跑（约 37 分钟，超时 3600 s）**

```bash
cd "$(git rev-parse --show-toplevel)" && RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q > .scratch/asset-v1/08/e2e.txt 2>&1 &
```

Expected: 9 passed（原 10 条减去已删的存量迁移那条）。

- [ ] **Step 7（只在需要时）: 回滚路径**

HS SSM 参数此刻仍在（Task 20 ★ 才删）。回滚工作树在 Task 17 ★ Step 3b 已就位：`.scratch/asset-v1/08/wt-before`（Task 0 SHA、两份 HS 形态的 config.ini 副本、router 的 CDK venv 已装）。在那里按 **router（open/deploy/apply）→ panel → auth** 重部三处，等 Deployed，全员再登录一次；窗口再来一次 10–20 分钟。**不回滚的**：deployer 栈（两把 CMK 留着无害）、MCP 与 key-proxy（新 `permissions.py` 只多了夹具域拒绝，与旧 panel 兼容）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/.scratch/asset-v1/08/wt-before"
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never) || true
python3 site-builder/scripts/router_stack_policy.py apply
(cd site-builder/panel && python3 deploy_panel.py)
(cd site-builder/auth && python3 deploy_auth.py)
```

worktree 丢了时：`git worktree add` 同一个 SHA 重建，config 从 `.scratch/asset-v1/08/config.ini.*.pre-3c-final`（Task 18 ★ Step 2 的备份）复制——config.ini 是 gitignored，`git stash` 收不到它；再 `bootstrap_venvs.sh --only router/infrastructure`。不要在主工作树上 `git checkout` 旧提交（它会把 Task 1–16 的未推送提交留在游离状态）。

---

### Task 20 ★：删三把 HS SSM 参数（**不可逆**，单独确认）

前置：Task 19 ★ 全绿、E2E 通过。三把参数：`/site-builder/jwt-secret`、`/site-builder/session-keys/site-hs-v2`、`/site-builder/session-keys/console-hs-v2`（以 Task 18 ★ 之前 config 里的实际值为准；1B 演练后 v1 两把已删）。

- [ ] **Step 1: 先核对账号，逐条读出参数名（只读、不解密）**

```bash
set -euo pipefail
aws sts get-caller-identity --query Account --output text
for p in /site-builder/jwt-secret /site-builder/session-keys/site-hs-v2 /site-builder/session-keys/console-hs-v2; do
  aws ssm get-parameter --region us-east-1 --name "$p" --query 'Parameter.[Name,Type,LastModifiedDate]' --output text
done
```

- [ ] **Step 2: 确认没有任何消费方**：`grep -rn "jwt-secret\|session-keys/" site-builder router --include='*.py' --include='*.sh' | grep -v '^.*tests/'` 必须为空；`verify_deployed_components.py` 已绿。

- [ ] **Step 3: 删（操作者手敲，不写进脚本）**

```bash
for p in /site-builder/jwt-secret /site-builder/session-keys/site-hs-v2 /site-builder/session-keys/console-hs-v2; do
  aws ssm delete-parameter --region us-east-1 --name "$p"
done
```

- [ ] **Step 4: 重跑 `python3 site-builder/scripts/verify_deployed_components.py`**（auth / panel 的 precheck 清单里早已没有它们；绿）。progress 记时刻，标 production。

---

### Task 21 ★：闸门——生成 schema 6 基线（一次 `--update-baseline`），分类，回填文档数字

- [ ] **Step 1: 观测（约 11 分钟）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_account_trust_boundary.py --dump-observed .scratch/asset-v1/08/gate-after-dump.json
```

Expected: stderr 有"没有基线：本次只能 --update-baseline 生成"；三条 Edge 产物硬断言通过；打印的 principal 清单里 auth 角色带 `kms-sign:site-rs-v1` / `kms-sign:console-rs-v1`，panel 带 `kms-sign:console-rs-v1`，若干 admin / cdk-admin / break-glass 类带两条 `kms-*`。

- [ ] **Step 2: 分类 + 写基线**

对照 Task 17 ★ Step 3b 重出的 `gate-before-dump.json`（切换前夕的旧代码快照；`principals` 的名字集合）写 `.scratch/asset-v1/08/classify.json`（`{角色名: category}`，新出现的 principal 参照它们在旧基线里的类别；本次新增的 `site-builder-verifier` 归 `platform`）。然后：

```bash
python3 site-builder/scripts/verify_account_trust_boundary.py --from-dump .scratch/asset-v1/08/gate-after-dump.json --classify .scratch/asset-v1/08/classify.json --update-baseline
python3 site-builder/scripts/verify_account_trust_boundary.py --from-dump .scratch/asset-v1/08/gate-after-dump.json      # 期望 exit 0
```

**对照读法**：把新基线 `principals` 里带 `kms-sign:*` / `kms-self-authorize:*` 的指纹集合，与旧基线里带 `read-jwt-param` 的指纹集合比——新集合应当是旧集合的**子集**且小得多（spec §1 量过的方向：56 → 十几）。不是子集的那几个（原先读不到 SSM、现在能 `kms:Sign`）要逐个说明是谁（用 dump 里的名字），写进 progress；说明不了的就是本次要停下来看的东西。

- [ ] **Step 3: 回填文档数字**：按新基线更新 `docs/security/account-trust-boundary.md` 的标记表（Task 16 改过形态），跑 `cd site-builder/deployer && .venv/bin/pytest tests/test_verify_account_trust_boundary.py -q -k doc_counts`。

- [ ] **Step 4: Commit**（只有文档数字）：`docs(asset-v1/08): 信任边界文档按 3c-final 后的基线回填数字（单账号实测）`。

---

### Task 22 ★：收尾——证据、状态、提交、推送、Orca

- [ ] **Step 1: 七套件顺序全绿**（最终；含 Task 21 的文档改动）。
- [ ] **Step 2: spec 状态行、§6.1 3c-final 行、merged review §9 三行填日期**（Task 16 留的 `<日期>`）；commit `docs(asset-v1/08): 3c-final 状态收口`。
- [ ] **Step 3: 工单与接手点**（gitignored）：`.scratch/asset-v1/issues/08-…md` 的 `Status: done`，Comments 记：SHA 列表、切换窗口实际时长、Edge 版本号、E2E 结果、闸门数字（对照 Task 17 ★ 的 before 快照）、三把 HS 参数删除时刻、`--update-baseline` 的报告摘要（基线已不 tracked，这份摘要就是"接受了什么"的留痕，D1）；`.scratch/asset-v1/issues/12-…md` 第 3 条收窄为只剩 `3c-impersonation-surface.json`（基线的 untrack 已随 08 完成）；`.scratch/asset-v1/NEXT.md` 的「现在到哪了」改为"08 完成；10 / 11 / 13 可派；12 等 07"。最后 `git worktree remove .scratch/asset-v1/08/wt-before`（回滚窗口已过）。
- [ ] **Step 4: 推送**：`git push origin master`；`git push --no-verify github master`。
- [ ] **Step 5: Orca**：用 `orchestration` skill 把 run `run_a850a9060b06` 里的 H08（`task_bd775f0d2965`）标完成，让 I10 / I11 / I13 变 ready（H12 还等 H07）。派 I10 / I11 / I13 前先读工单 16 的 Comments 四条实测坑。

---

## Self-review

**Spec coverage（工单「What to build」逐条 → Task）**：KMS 两把 CMK 默认 key policy → T15/T18；`[SessionKeys]` 只剩 RS 行 → T2；三个部署脚本三层绑定 → T3/T7/T8/T11（第 1 层）、T3/T5/T8（第 2 层 KmsSigner）、T14（第 3 层三方对账）；signer 切 `kms:Sign` RAW + `GetPublicKey` → T5/T7/T8；Edge RS256 + vendored cryptography → T10/T11；auth/panel 同步、kid 级 current/previous 保留 → T4/T5/T8；闸门 KMS 探测 + 基线不 tracked → T13/T21；夹具签发器与六处调用方 → T5/T12；删除清单（HS 材料、`ensure_session_keys` HS 部分→整删 D5、legacy 入口与状态机、跨算法双接受、`--migrate-from-schema` 与 3/4→5、`undecided_item_fp`/`undecided_members_v4`/`schema4_fingerprints`、runbook HS 版、blue/green 迁移脚本、preflight HS 状态）→ T1/T2/T4/T5/T8/T10/T11/T13/T15/T16；硬切换 → T19；四个 verify_* + smoke → T19；文档（KMS runbook、README 成本）→ T16。工单 Comments 三条：窗口 task（T19 有"窗口内不做验收、结束后全员重登"）；删迁移脚本连带两处守卫两处文档（T15/T16）；矩阵两行一起删（T16）。spec §6.2 3c-3 精确清单：每一行都能在 T1–T16 里找到对应删除项（`_session_keys_on_path` 的 `sys.path[0]` 常驻那条**本 plan 不改**——它不是 HS 残留，改动面与本票无关，留在清单里注明）。

**Placeholder scan**：`RS256_GOLDEN` 三个值与 spec / §9 的 `<日期>` 是执行时才存在的量，各自有生成 / 填写步骤；`_run_main` / `_fragment` 等引用的既有夹具名以文件现状为准，plan 里已注明"按文件里现有的名字改"。其余无 TBD。

**Type consistency**：`sign(bytes)->bytes`（T1）被 `KmsSigner.__call__`（T3）、`local_signer`、`vectors.signer` 实现；`load_allowlist(env_json, family, get_public_key, *, allowed_families)` 与 `session_kms.public_key_loader(kms)` 的 `(key_arn, spki_sha256)` 签名一致（T3/T4/T5/T8）；`signing_ref` 返回三元组，`_signer` 用它构造 `KmsSigner`（T5/T8）；Edge allowlist 行键 `spki_b64`（T2 的 SYNTH 占位、T10、T11、T14 一致）；`expected_statements(..., extra_principals=)` 在 T6/T7/T14 一致；`Minter.mint(token_use, email, *, ttl_seconds, role, name)` 与六处调用方（T12）一致；闸门 grant 词表 `kms-sign:<kid>` / `kms-self-authorize:<kid>` 在 T13 的常量、文法、测试、`REQUIRED_GRANT_PREFIXES`、文档标记一致。

**已知留给后续工单的**：探针结果 JSON 与 DEPLOY.md 时间线的 untrack（12）；`account-trust-boundary.md` 的整体改写与数字去留（12/13）；`verify_*` 作为分发验收集的打包与 README 的"开发者工具 vs 验收集"分层（13/14）；console family 就位期没有正向探针（D3 的已接受代价，写进 KMS runbook 的 ② 说明）。
