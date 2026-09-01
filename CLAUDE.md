# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目是什么

Quick 自动化建站平台（Site Builder）：业务人员在任意支持 Skill+MCP 的 Agent 客户端
（Claude Code / Quick Desktop）用自然语言开发简易全栈站点，一句"部署"得到
`https://app-{site_id}.{base_domain}` 的可分享 URL。站点访问与管理权限绑定飞书账号
（身份源可换成任意能给 email claim 的 Cognito 联邦 IdP）。

**当前状态：一期、二期与加固包都已在真实 AWS 部署。** 二期含
`console.{base_domain}` 自助管理控制台、API Key 交换层、访问统计聚合；站点更新走
blue/green 原子切换（M7）。加固包（跨租户 IAM 隔离 / 权限数据洗白 / token 用途混用 /
同名 cookie 遮蔽 DoS，即 merged review §9 优先级表里的 M01/M02/M05/M06 四条）已按
`site-builder/DEPLOY.md` 的「S1 加固」一节部署并过全部闸门，**含真机行为探针**
（`verify_session_token_semantics.py`）。**§9 表里其余各条还没做。**

**所以本文件的架构描述与线上是一致的**（包括下面「站点代码按不可信对待」那条写的
「禁止 `site-data-{site_id}-*` 前缀通配」——存量 per-site 角色已全部收敛成精确表
ARN，通配已清零）。不再需要"读文档时减去一层"。

> **三条仍然成立的边界，别当成已解决**：per-site IAM 的 `dsql:DbConnect` 仍是
> `Resource: *`（DSQL 的租户隔离在 PG 层——per-site schema + 非 admin role，不在 IAM
> 层，这是既定设计而非残留）；同名 cookie 遮蔽只关掉了 DoS，**没关身份混淆**
> （攻击者持有另一个**合法** token 时仍会先被取到，根治是 host-only 会话，独立成包）；
> **平台的安全边界就是这个 AWS 账号**——账号内任何具备只读级权限的 principal 都能取得
> HS256 会话密钥（**三条路**：Edge 产物里是明文（含 9 个历史版本）、同一份产物在 CDK
> bootstrap S3 桶里还有 9 个带活密钥的 asset、SSM 参数有**四个**动作都能读出明文而
> KMS 那道是虚的），从而以任意用户身份访问任意
> 站点**与控制台写接口**。**别按 merged review 里 M09 第 2 步的原话去收窄 invoke，
> 那是假修复**（同一批身份还握着密钥读取与自助提权）。两条真修复都未排期：账号内改
> **非对称签名**（Edge 只放公钥）能关掉只读那批；迁**独立成员账号**才能移出管理身份。
> 实测数字、为什么 SCP/resource policy/对称签名都不成立、以及盯住暴露面别再变大的
> 闸门（**已收缩成 A 直接失守 + B IAM 写静态快照两层，C 站点 route/alias 可达性移出归
> 部署验收**；真修复顺序：收窄 CodeBuild 对 bootstrap 桶的读权限（**§9 的 3b，
> 2026-08-27 已部署**：那条整桶读整条消失，A 62→61、可读密钥 57→56、
> `platform-overbroad` 清零）→ 非对称签名 → 迁独立账号，见 merged review §9 的
> 3b/3c/3d），
> 见 `docs/security/account-trust-boundary.md`。**那份文档里还有一条值得单独记住**：
> 跑不可信站点依赖安装的 CodeBuild 角色**曾经**能读到那把密钥（CDK 给
> `BuildSpec.from_asset()` 自动授的整桶读）——**2026-08-27 已收窄，它现在对 bootstrap 桶
> 零权限**，S3 权限全集由检查器按等值断言（`deployer/tests/security_contracts.py`）。
> 但 **`--ignore-scripts` 仍然必须留着**，因为构建容器里任意代码执行仍能读
> `validated/*`、写 `artifacts/*`。
> **那条隔断分两层，别记成"只有一条 flag"**：站点**自己的** `package.json` 生命周期脚本与
> `backend/.npmrc` 由合同校验器在 CodeBuild **之前**就拒（`contract/redlines.py` 的
> `NPM_LIFECYCLE_KEYS`）；但**依赖里**的生命周期脚本**只有** `buildspec-package.yml` 的
> `npm install --ignore-scripts` 一道——`_scan_package_json` 从不检查 `dependencies`，
> 而 `.tgz` 依赖根本不在扫描后缀里（实测：带 `preinstall` 的包打成本地 `.tgz` 作依赖，
> `npm install` 会执行它，加上 `--ignore-scripts` 不会）。

**具体进度与闸门数字不写在本文件**（会过时）：确切数字靠下面的测试命令自己跑；
**待办与优先级**见 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9
（**随仓库分发**，是"还剩什么"的真源）。二期需求清单在
`docs/phase2-requirements.md`；部署手册 `site-builder/DEPLOY.md` 含全部实测坑。
`docs/design/` 下的 HANDOFF / FINDINGS 是当时的过程记录，**gitignored、不随仓库分发**，
新 clone 里不存在——**不要把它们当状态真源**。

## 测试命令（有坑，别猜）

每个包的 venv 归属不同，照抄下面的组合（三个例外都验证过）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

(cd site-builder/contract && .venv/bin/pytest tests -q)
# auth 无自己的 venv，借 contract 的——含 pyjwt 与 boto3；重建该 venv 后两者都要手工重装
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
# router 的 .venv 只有 CDK 依赖没有 pytest，借 deployer 的（含 boto3）
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
# 必须指定 tests/——裸 pytest 会误收集 infra/cdk.out 里的 asset 副本
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/mcp && python3 -m pytest tests -q)
# panel 无自己的 venv，借 deployer 的；测试期从 auth/ 直接 import session.py，部署时复制
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
# keygen/edge_caller 的单测在 deployer 包里（模块落 functions/）
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```

单测跑法：`.venv/bin/pytest tests/test_xxx.py::test_name -q`。

**三条实测坑（都花过时间，别重踩）**：

- **最终闸门别把七个包并行跑**。`contract/tests/test_redlines.py` 里有一条**墙钟**哨兵
  （3000 组 decode 调用必须 10 秒内跑完，防 `_check_user_name_decoded` 退化回 O(n²)）。
  它对机器争用敏感：并行跑多套件时实测被拖到 **13.6 秒**假红，重负载散去后单独重跑
  **5.2 秒**。看到这条红先重跑一次再判断，别去"优化"那段解析。

- **改了 `deployer/infra/app.py` 的 bundling 段，要跑 auth 那套才会红**。那段的守卫
  （每条 pip install 都必须带 `--require-hashes`、合同包必须 cp 不 pip）住在
  `auth/tests/test_requirements_locked.py` 里——AST 解析器在那边。只跑 deployer 全绿
  不代表 bundling 改对了。这是一条跨包耦合：deployer 的源码，auth 的守卫。
- **E2E 的 CA 陷阱**：`deployer/.venv` 的**默认** SSL 上下文信任库是空的
  （`ssl.create_default_context().cert_store_stats()` 全 0），而 E2E 会**在进程内调用
  发起 HTTPS 的生产代码**——那条路径用的是默认上下文，不是测试自己造的那个。
  **只设 `SSL_CERT_FILE` 不够**：`HTTPSHandler` 在构造时就把上下文定格了。现在由
  fixture 自动修好，但看到 `CERTIFICATE_VERIFY_FAILED` 时**别当成网络/证书故障**去查
  代理和防火墙——先确认是不是又碰到了这个上下文。

**MCP 的上面那条用宿主机依赖，不等于容器里的依赖**（实测宿主 mcp 1.26.0 /
boto3 1.43.25，而 `mcp/requirements.txt` 锁的是 1.29.0 / 1.43.64）。
改过锁定清单、或要确认"部署出去的那套依赖也全绿"时跑：

```bash
site-builder/mcp/run_locked_tests.sh    # 建 py3.13 venv + --require-hashes 装锁定依赖再跑
```

它用与 Dockerfile 同一份清单同一套 hash 校验，Python 版本也钉 3.13（与基础镜像
一致——不同版本解析出的依赖集合与 marker 分支不同）。

deployer 的 CDK 模板断言（`tests/test_infra_tables.py`）默认 skip；要真跑必须
带 PYTHONPATH 桥接（aws_cdk 只在 `infra/.venv`，不带时会报错而非静默 skip）：
`cd site-builder/deployer && PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`（synth 需 Docker）。

venv 的 shebang 是绝对路径：仓库被移动/克隆到新路径后必须
`python3 -m venv --clear .venv` 重建（不带 `--clear` 不会重写 shebang，一直报
bad interpreter）。

E2E（需要真实 AWS 部署 + config.ini 已回填）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q   # **10 条**，实测约 37 分钟
# ↑ 别按「4 个 fixture / 约 6 分钟」记（那是旧数字）。它超过很多工具的单次超时上限，
#   中途被杀会让 autouse 的清理 fixture 跑不完 ⇒ 留下真站点。要后台跑或调大超时。
bash site-builder/scripts/smoke_router.sh    # 路由层冒烟（会写测试数据，跑完清理；含 65s 等 Edge 缓存）
python3 site-builder/scripts/verify_console_e2e.py      # 控制台端到端
python3 site-builder/scripts/verify_analytics_e2e.py    # 统计端到端（二期 M5）
# 账号信任边界的漂移闸门（只读；A 直接失守 + B IAM 写静态快照两层；400 个 principal × 2 次
# IAM 模拟 + **两次** GetAccountAuthorizationDetails（第二次是模拟后的**窗口两端一致性
# 复查**——两端不一致就作废本轮、不出结论也不写基线。它**不保证原子**：只覆盖 principal
# 层，且只证明两端相等，三个已接受盲区见 docs/security/account-trust-boundary.md）
# + 扫 bootstrap 桶，实测 11±1 分钟：11m33s / 10m57s 两次）
python3 site-builder/scripts/verify_account_trust_boundary.py
```

`site-builder/scripts/verify_*` 是真机闸门（部署后跑，不是单测）。**本文件不记数量与
最新结果**（都会过时）：闸门清单就是上面那段命令，跑一遍即是最新结果。

**这些脚本一律用系统 `python3` 跑，不要借 `deployer/.venv/bin/python3`**：那个解释器的
CA 信任库是空的（`ssl.create_default_context().cert_store_stats()` 全 0），于是每一次
HTTPS 都 `CERTIFICATE_VERIFY_FAILED`——症状读起来像网络/代理故障，其实不是。
系统 `python3` 走 pip 装的 `truststore`（读 macOS keychain），且同样有 boto3。

`verify_analytics_e2e.py` 会自建 fixture 站点、发真实请求、跑一次 rollup 再清理，
其中 MCP 那一段要求**用户 OAuth token 是新鲜的**（二期把 refresh TTL 收到 1 天）；
过期时要先在浏览器里登录一次（`node site-builder/clients/quick-desktop-proxy/auth.js`）。
三个 verify 脚本共用 `site-builder/scripts/_mcp_client.py`（MCP 客户端 + token 读取，
`verify_analytics_e2e.py` / `verify_api_key_e2e.py` / `verify_oauth_and_impersonation.py`）
——改它要意识到是同时改三个闸门。

## 部署/重部署命令

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# 路由层（改过 config.ini 必须先 rm -rf cdk.out，否则用陈旧 asset）
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)

# 执行器（bundling 需要 Docker）
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)

# auth 服务（Lambda + Function URL + pre-token 触发器，幂等）
(cd site-builder/auth && python3 deploy_auth.py)

# MCP（buildx ARM64 → ECR → AgentCore runtime；--skip-build 只改配置）
(cd site-builder/mcp && python3 deploy_agentcore.py)

# API Key 交换层 key-proxy（二期 M4，**可选组件**；无 [ApiKey] 段时打印跳过并返回 0）
# 顺序：deploy_pool → deployer 栈 → deploy_agentcore → 本脚本 → deploy_panel
(cd site-builder/key-proxy && python3 deploy_key_proxy.py)

# 控制台 panel（Lambda + Function URL + 前端上传 + console route，幂等）
# --skip-frontend 只改后端。改前端后必须重跑（不带该开关）才会上传。
(cd site-builder/panel && python3 deploy_panel.py)

# 存量站点迁移到 blue/green（M7；**只有存量环境需要**，新账号不必跑）
# 默认 dry-run 只打印计划，--apply 才写；--site-id 可单点重跑。
# static 站点会被报成 skipped（没有后端 Lambda，不参与 blue/green）——那不是失败。
python3 site-builder/scripts/migrate_sites_to_blue_green.py            # 看计划
python3 site-builder/scripts/migrate_sites_to_blue_green.py --apply    # 真写

# 生成含真实值的用户接入指引（产物 gitignored）
python3 site-builder/scripts/gen_onboarding.py
```

配置全在 `site-builder/config.ini` 与 `router/config.ini`（gitignored，从同目录
`.example` 复制）。**config.ini 是各部署脚本与 CDK 栈的唯一取值来源**，代码不硬编码
账号/域名。git 历史已清洗过真实账号 ID——不要把真实账号值写进任何被跟踪的文件。

## 架构（五层 + 控制台，读代码前先建这张图）

```
① 建站 Skill (site-builder/skills/)  ← Agent 客户端加载的"部署合同"说明书
        ↓ MCP 调用（OAuth 带飞书身份）
② 部署 MCP (site-builder/mcp/)       ← AgentCore Runtime，9 工具全部秒级返回
        ↓ 条件迁移 PENDING→RUNNING + 启动 SFN
③ 异步执行器 (site-builder/deployer/) ← Step Functions 10 步：validate → provision-db
        ↓ 写路由表                       → CodeBuild 打包 → 站点 Lambda → 前端 S3 → 路由 → 冒烟
④ 路由+鉴权层 (router/)              ← CloudFront *.{domain} + Lambda@Edge
        ↓ 未登录 302                     查路由表 → 验会话 JWT → 注入 x-user-email → 分流
                                         顺带写一行访问明细（只页面级、只 `app-` 前缀；二期 M5）
⑤ 身份层 (site-builder/auth/)        ← Cognito(联邦到飞书) + 登录服务 + pre-token 触发器

交换层 (site-builder/key-proxy/)      ← mcp.{domain}，二期 M4 的**可选**组件
   给只能配静态 Header 的 MCP 客户端一条路：验 X-API-Key → 换组件自身的机器
   token → 不懂协议地透明转发到 ②，只多一个 X-SB-On-Behalf-Of 头告诉 ② 以谁
   的身份行事。config.ini 无 [ApiKey] 段 = 整个组件不存在（推荐默认）

控制台 (site-builder/panel/)          ← console.{domain}，二期 M3；**建站仍只在 Agent 里**
   走 ④ 的 split 路由：/api/* → panel Function URL(AWS_IAM 仅 edge role)，其余 → S3
   自助改权限/协作者/所有权/看部署历史/下线；管理员另有全局视图与 admin 名单
   写接口要"面板会话"（__Host-sb_console，由 auth 的 /console-session 发一次性 code 换取）
```

理解整个系统的关键抽象：

- **部署合同是锚点**：`site.json` schema + 目录约定 + 代码红线
  （`site-builder/contract/`）。哪个 Agent 生成的代码都行，执行器只认合同；
  validate 步骤把不合规产物在部署前拦下。改合同要同步三处：
  `contract/src/contract/`（校验器）、`skills/site-builder/references/`
  （给 Agent 的文档）、`fixtures/`（黄金样例，模板与 fixture 字节一致）。
- **站点代码按不可信对待**：per-site IAM 角色带 PermissionsBoundary，
  但 boundary 只限制最大能力面，**不提供租户隔离**。DynamoDB 租户隔离依赖
  runtime role 的逐表精确 ARN，禁止使用 `site-data-{site_id}-*` 前缀通配；
  DSQL 使用 per-site schema + 非 admin PG role。CodeBuild 装依赖使用
  `--ignore-scripts`。任何给执行器/站点加权限的改动都要维持这个模型。
- **鉴权全部在边缘**：站点代码零 auth 逻辑。Edge 验 HS256 会话 cookie
  （与 `auth/session.py` 同算法，**两处必须字节级同步**，见
  `router/infrastructure/lambda/origin_request.py` 注释）、按 allowed_users
  放行、注入 `x-user-email` / `x-user-name`（后者 URL 编码，站点须
  decodeURIComponent）。**CloudFront 全站禁缓存是鉴权正确性前提**
  （origin-request 只在 cache miss 执行）——别加缓存策略。
- **身份即邮箱**：owner / allowed_users / 会话 claim 全以 email 为键，对 IdP
  无感。Cognito access token 默认不含 email，靠 pre-token V2 触发器
  （`auth/pre_token_email.py`）注入——MCP 网关只收 access token
  （id_token 会 401，不要把 authorizer 改成 allowedAudience）。
- **Lambda@Edge 不支持环境变量**：Edge 函数的配置（表名、JWT 密钥）由 CDK
  部署时字符串替换注入（`{{PLACEHOLDER}}` 形态）。看到
  `SYNTH-ONLY-PLACEHOLDER` 警告说明 SSM 读取失败，此时部署出去所有会话验签失败。

## 不可破坏的系统不变量

- **sites 表是真源，路由表是 Edge 投影。** 权限修改必须通过
  `permissions.write_permissions` 原子更新真源与投影，并用同一权限快照/rev
  绑定鉴权与写入；调用方不得手写第二套角色判定或条件表达式。
- **路由切换是部署提交点。** `register_route` 之前失败不得影响线上；提交后失败必须按
  持久化的整条 `previous_route` 补偿。不得只恢复部分字段，也不得只把补偿状态放在返回值中。
- **平台信任不能来自可写业务字段。** 平台 origin 只认真实请求 host 对应的
  `PLATFORM_SUBDOMAINS`；不得从 route owner 或其他权限投影字段推导平台身份。
- **站点 origin 不可信。** 平台 cookie、`x-user-*` 与平台标记在到达站点前必须剥除；
  可信身份头只能由 Edge 验签后重新注入。
- **auth/session 与 Edge verifier 是跨部署单元的同一契约。** claim、算法或密钥形态变化
  必须同步 auth、panel、Edge、跨组件测试和部署顺序；auth 先于 router。
- **异步调用结果未知时保留恢复状态。** 网络超时不等于请求未受理；不得在结果不确定时
  释放租约、回滚为可重试状态或允许新的部署/下线并发进入。

## 跨组件改动矩阵

| 改动 | 必须同步检查 |
|---|---|
| `contract/` schema/redlines | validator、Skill references、fixtures、生成模板 |
| `permissions.py` | deployer tests、panel、key-proxy、MCP、三个产物重部 |
| `auth/session.py` | auth 调用方、panel copy、Edge verifier、auth→Edge 向量 |
| `origin_request.py` | router tests、origin-response 对称契约、CDK asset、Edge 部署 |
| 路由权限字段 | permissions、register/resync、补偿恢复、Edge 反序列化 |
| DynamoDB/DSQL 资源 | runtime inline policy、boundary、undeploy、backfill、IAM 模拟 |

## 高频坑（都是真机踩过的）

- Function URL 一律 `AuthType=AWS_IAM` + 只授权 edge role，且 2025-10 起需要
  `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl) 两条语句，缺一即 403。
  `AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（删光 resource policy）。
- AgentCore 镜像构建必须 `--provenance=false`（buildx 默认加 attestation
  manifest，CreateAgentRuntime 校验失败但报成 IAM 权限错误文案）。
- S3 预签名 PUT 不能带 Content-Type 头（签名按无该头计算，加了必 403）。
- MCP 客户端 OAuth：Cognito 无 dynamic client registration，必须
  `--client-id` + `--callback-port 18765`（8765/8766 被 Quick Desktop 常驻占用）。
  Quick Desktop Remote MCP 不支持 OAuth，走 `site-builder/clients/quick-desktop-proxy/`。
- deployer 的 CDK bundling 钉死 `platform: linux/amd64`——Apple Silicon 上去掉会装出
  aarch64 psycopg，Lambda 运行时 import 失败。
- DSQL：API 不返回 endpoint（自拼 `{id}.dsql.{region}.on.aws`）；清理顺序必须先
  `AWS IAM REVOKE` 再 `DROP ROLE`（否则 2BP01）。
- git push 用 `--no-verify`（用户全局约定）；us-east-1 是硬约束
  （Lambda@Edge 与 CloudFront 的 ACM 证书），换区要改代码。
- **路由表的 `static_prefix` 不带尾斜杠**。Edge 的静态改写是
  `f"/{static_prefix}{path}"` 且 `path` 已以 `/` 开头——带尾斜杠会拼出双斜杠，
  与上传的 key 不是同一个对象，整站 403（两侧单测各自都会绿）。
- **私有前端桶上，浏览器的约定路径一律 403 而非 404**（`/favicon.ico`、
  `/robots.txt`、`/.well-known/*`）。排查线上 403 先分清"没权限"还是"没这个对象"。
- **带请求体的 `DELETE` 在 CloudFront → Edge → Function URL 这条链路上必 403**。
  Edge 拿到 body 并按它算 payload hash 去签 SigV4，而 CloudFront 转发到源站时
  那个 body 不在了 → 源站按空 body 校验 → 签名不匹配，**在业务代码之前**就被拒。
  所以删除类接口一律用 POST 子路径（`/api/keys/revoke`、`/api/admins/remove`），
  参数放请求体、**不放查询串**（查询串会进 CloudFront 访问日志）。
  `panel/tests/test_handler.py::test_no_route_uses_delete_with_body` 按路由表锁死。
  这个缺陷在生产上活了整个 M3 周期——单测直接调 handler，不经 CloudFront。
- **API Key 总开关的 `enabled` 必须是 DynamoDB `BOOL`**：`keystore.lookup` 判的是
  `enabled is not True`，字符串 `"true"` 同样被拒。症状是"控制台显示开着但所有
  Key 都 401"，而两侧单测各自都绿。手工改哨兵行时用 `{"BOOL":false}`。
- **`mcp` 子域故意不在 Edge 的 `PLATFORM_SUBDOMAINS` 里**：key-proxy 只认
  `X-API-Key`，不需要平台 cookie；进白名单只会让一个公网组件白拿一个顶域会话
  JWT。别"顺手补齐"这个名单。
- **moto 不校验 IAM**：事务里的 `ConditionCheck` 需要 `dynamodb:ConditionCheckItem`，
  漏给时单测全绿、真机 500。给 Lambda 加事务路径时同步核对角色策略。
- **统计埋点的超时预算不能按同区算**：Edge 写本区副本是 6ms（冷 58ms），但回落路径是
  跨区 229ms（冷 **719ms**，实测）。预算的下限由回落决定；收紧到「够本区用」就等于让
  回落路径静默丢行。埋点异常一律吞掉（统计不是安全控制），所以丢行是**无声的**。
- **改了 `permissions.py` 这类共享模块，要重部的是三个组件**：panel、key-proxy、MCP
  各自把它打进自己的产物（key-proxy 也带，虽然它只用 `EMAIL_RE`）。漏一个的症状是
  产物陈旧而部署脚本一切正常——`verify_deployed_components.py` 是唯一会点出来的地方。

## 文档地图

| 要做什么 | 看哪里 |
|---|---|
| 部署到新账号 / 排查部署问题 | `site-builder/DEPLOY.md`（①→⑦ + ⑤b 控制台 + ⑤c API Key + 全部实测坑） |
| 客户端接入（人/Agent） | `site-builder/docs/client-setup.md`；含真实值版本跑 `gen_onboarding.py` |
| 合同细节（给站点生成方） | `site-builder/skills/site-builder/references/{contract,redlines}.md` |
| **还剩什么没做 / 优先级** | `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9（**tracked**；两轮独立对抗性审查的合并版。S1 取的是表里 M01/M02/M05/M06 四条；M09 已按 v5 重定义并落地，其余各条还没做） |
| **平台防谁 / 不防谁（账号信任边界）** | `docs/security/account-trust-boundary.md`（**tracked**；M09 的结论真源。含只读实测方法、**14 个由基线断言的数字**（A/B 两组 + 按类别）、为什么 SCP/resource policy/应用层签名/收窄 invoke 都不成立） |
| **M09 真修复①的设计与实施记录（2026-08-27 已部署）** | `docs/superpowers/specs/2026-08-27-codebuild-bootstrap-read-narrowing-spec.md`（**tracked**；收窄 CodeBuild 对 CDK bootstrap 桶的读权限＝§9 的 3b。含为什么已有那条 AST 守卫看不见这个洞、三层守卫各自能证明什么、部署窗口的干净失败面；末尾「实施记录与验收证据」一节是 handover）|
| **M09 真修复②的设计（3c，未实施）** | `docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md`（**tracked**；会话签名迁非对称。**状态是待修订草案，不构成实施授权**。含量测过的收益边界（56 → **冒充面 19，这是已知下界不是上界**）、两个 key ring 的模型、分包顺序 3c-0/1A/1B/**2A**/2B/3（2A 是"闸门与验收先认 KMS"的独立发布单元）、部署与回滚协议、以及「四个 verify_* 闸门靠读 SSM 明文本地 mint 会话，非对称化后要重新设计」这条容易漏的代价）|
| **3c 冒充面的可复跑证据** | `site-builder/scripts/probe_impersonation_surface.py`（**tracked**，只读，实测约 20 分钟）→ `docs/security/3c-impersonation-surface.json`（**tracked**，只有计数/等价类/边际收益/盲区清单，名字只进 gitignored dump）。**`--self-test` 不碰 AWS**，18 条反例 + 变形测试在 `deployer/tests/test_probe_impersonation_surface.py`。**别再引用 56→13 / 并集 18 那两组旧数字** |
| 加固包 S1 的设计与实施 | `docs/superpowers/specs/2026-08-22-s1-isolation-and-auth-hardening-spec.md` + `docs/superpowers/plans/2026-08-22-s1-isolation-and-auth-hardening.md`；升级/闸门/回滚见 `site-builder/DEPLOY.md` 的「S1 加固」一节 |
| 一期设计决策与范围 | `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`（已实现快照，勿改） |
| 二期设计与需求 | `docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md`；需求清单 `docs/phase2-requirements.md` |
| 任务级实现/审查证据链 | `.superpowers/sdd/<计划日期>-<计划名>/progress.md`（**gitignored**、每个 plan 一个目录；`.superpowers/sdd/progress.md` 那个扁平路径是一期的旧布局） |
| 各里程碑实测发现 | `docs/design/M{3,4,5}-FINDINGS.md`、`M4-SPIKE-2026-08-10.md`、`M7-SPEC-2026-08-16.md`（**gitignored**；含可复用的断言自查清单，已验证过的别再跑一遍） |
| 历史过程记录 | `docs/design/HANDOFF-2026-08-07.md`（**gitignored**；写到二期为止、**不含 S1**——**不是**状态真源，见上面「当前状态」） |

> **接手时的读法**：要知道"生产现在是什么样"，读本文件 + `README.md` +
> `site-builder/DEPLOY.md`，数字自己跑测试；要知道"还剩什么"，读上面那份 merged
> review 的 §9。**不要**依赖 `docs/design/` 里的任何一份——它们和 `.superpowers/`
> 都 gitignored（含真实账号/资源值），新 clone 里根本不存在，**也不要 `git add -f`**。

### 换机器 / 新 clone 之后怎么恢复开发

**`git clone` 拿不到能跑的环境**——下面四样都在仓库外，缺任何一样症状都不像"没配置"。
按这个顺序做：

1. **两份 `config.ini`**（`site-builder/` 与 `router/`，各从同目录 `.example` 复制并
   回填真实账号/域名/证书 ARN）。**它们是所有部署脚本与 CDK 栈的唯一取值来源。**
   `configparser` 对缺失文件是**静默的** ⇒ 不回填不会报"缺配置"，而是拿空值往下跑并
   拼出假结论（本仓库为此在闸门里专门加了"读不到任何段就硬失败"）。
2. **五个 venv 全部重建**：`router/infrastructure`、`site-builder/{contract,deployer,mcp}`、
   `site-builder/deployer/infra`。**必须带 `--clear`**（`python3 -m venv --clear .venv`）
   ——shebang 是绝对路径，不带 `--clear` 不重写，一直报 bad interpreter。
   `auth` / `panel` / `key-proxy` 没有自己的 venv，借别人的，组合见上面「测试命令」。
   重建 `contract/.venv` 后 **pyjwt 与 boto3 要手工重装**（auth 的测试靠它）。
3. **MCP 的 OAuth token**：`node site-builder/clients/quick-desktop-proxy/auth.js`
   登录一次。token 过期时 MCP server 会以 `-32603 token 过期且刷新失败` 连不上，
   **那是认证过期，不是没配置**。
4. **两个远端各自的凭据**：`github` 走普通 SSH key；`origin`（gitlab.aws.dev）走公司
   内网凭据，**会话中途会过期**，症状是 `Permission denied (publickey)`。
   从 GitHub clone 之后 `origin` 指的是 GitHub，要手工把内网那个加回来。

**拿不回来、也不用拿回来的**：`docs/design/` 与 `.superpowers/sdd/` 下的全部过程记录
（每个 plan 的 progress、task brief/report、review diff）——**gitignored** 且含真实
资源值，新 clone 里不存在。**它们不是状态真源**，别为了"补齐上下文"去找它们。
真源是本文件 + `README.md` + `site-builder/DEPLOY.md` + merged review §9；
数字靠跑测试与闸门。3c 冒充面那份名字 dump 同理——**重跑探针即可重生成**
（`probe_impersonation_surface.py --dump-observed …`，只读约 20 分钟）。

**本地 `backup/*` 分支只在原机器上**（都是已完成的历史重写的安全锚点，两个远端上都没有）。
换机器等于放弃它们；确认不再需要就在旧机器上删掉，别推到公开仓。
>
> **加固包的编号别用 `S1`/`S2`…写进代码或文档正文**：`S3` 会和 Amazon S3 撞车（本仓库
> 到处在说 S3 桶），grep 出来全是噪音。用 merged review 里的 `M` 编号
> （`M03+M16`、`M07/M08/M10/M12`…）或主题名指代。
