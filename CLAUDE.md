# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目是什么

Quick 自动化建站平台（Site Builder）：业务人员在任意支持 Skill+MCP 的 Agent 客户端（Claude Code / Quick Desktop）用自然语言开发简易全栈站点，一句"部署"得到 `https://app-{site_id}.{base_domain}` 的可分享 URL。站点访问与管理权限绑定一个能给 email claim 的 Cognito 联邦 IdP（飞书是参考适配器）。

### 本项目的交付物是可分发资产，不是任何一个具体环境

本仓库作者用来验证的 AWS 账号与部署只是**验证环境**。交付物是 `site-builder/` 与 `router/` 这套资产（边界按"部署所需"划，不按目录名；`site-builder/policies/` 的 SCP 样例是可选制品）—— 其它 AWS 用户拿到它后能独立部署和使用。词表见 `CONTEXT.md`「交付与分包」，决策见 `docs/adr/0005-*.md`。

**这意味着每次改动要过一道心理检查：**

> "如果一个全新用户在全新账号上 clone 这个仓库，这次改动对他有意义吗？"

- **有意义的**：最终状态的代码、配置模板、部署手册、spec/ADR 里的设计决策与教训。
- **没意义的**：验证环境的中间迁移步骤、过渡脚本、临时修复路径、"从部署 1 升级到部署 2"的操作记录——最终用户直接到部署 2，中间过程不需要再走。

对后一类，该记的教训提炼进 spec/ADR（标明"单账号实测"的证据强度），其余留在 gitignored 的过程文件里，**不进版本库、不进交付文档**。**本文件也在这条规则之内**：验证环境"现在到哪了"（部署日期、当前配置形态、进度）不写在这里，只住 gitignored 的接手点文件（`.scratch/<feature>/NEXT.md`，新 clone 里不存在）与 spec 的状态列。

已有的硬约束继续生效：不硬编码账号值、config.ini 是唯一取值来源、实测数据只进 gitignored 文件或 spec 注释（标明来源与强度）。

### 资产包含什么

一期建站链路、二期的 `console.{base_domain}` 自助控制台、API Key 交换层（可选组件）、访问统计聚合、站点更新的 blue/green 原子切换，以及加固包（merged review §9 里的 M01 跨租户 IAM 精确 ARN 隔离、M02 权限数据 fail-closed、M05 token 用途绑定、M06 同名 cookie 遮蔽的 DoS 关闭）。会话签名是 RS256：两把 KMS 非对称 CMK（site / console 两个 key family，各有 `current` 与 `previous` 两个 `kid` 槽位，可轮转），auth 持两把的 `kms:Sign`、panel 只持 console、Edge 零 KMS 权限只内嵌 site 公钥；验收工具的登录态来自 auth 的 `/fixture-session`（夹具域 `e2e.invalid`，可选组件 `[Verification]`）。

### 三条设计边界，别当成已解决

- per-site IAM 的 `dsql:DbConnect` 是 `Resource: *`。DSQL 的租户隔离在 PG 层（per-site schema + 非 admin role），不在 IAM 层，这是既定设计而非残留。
- 同名 cookie 遮蔽只关掉了 DoS，**没关身份混淆**：攻击者持有另一个**合法** token 时仍会先被取到。根治是 host-only 会话，独立成包。
- **平台的安全边界是 AWS 账号本身，但面从"能读"收到了"能签或能改验签代码"**：账号内能 `kms:Sign` 两把 CMK（或能给自己授权）、能改 auth / panel 的代码或配置、能替换 CloudFront 正在执行的 Edge 版本的 principal 仍能冒充任意用户；只读级权限（`ReadOnlyAccess`）不再够——Edge 产物与 bootstrap asset 里只有**公钥**，SSM 里只剩两把**对称**密钥（login-flow secret 与 `site-client-secret`），三者都签不出会话。数字与方法在 `docs/security/account-trust-boundary.md`，闸门是 `verify_account_trust_boundary.py`（KMS 层：`kms:Sign` / `PutKeyPolicy` / `CreateGrant` 持有者、key policy、grants、公钥指纹）。**别按 merged review 里 M09 第 2 步的原话去收窄 invoke，那是假修复。**

**CodeBuild 那道隔断分两层，别记成"只有一条 flag"**：跑不可信站点依赖安装的 CodeBuild 角色对 bootstrap 桶零权限（S3 权限全集由 `deployer/tests/security_contracts.py` 按等值断言），但 `--ignore-scripts` 仍然必须留着，因为构建容器里任意代码执行仍能读 `validated/*`、写 `artifacts/*`。站点**自己的** `package.json` 生命周期脚本与 `backend/.npmrc` 由合同校验器在 CodeBuild **之前**就拒（`contract/redlines.py` 的 `NPM_LIFECYCLE_KEYS`）；**依赖里**的生命周期脚本**只有** `buildspec-package.yml` 的 `npm ci --ignore-scripts` 一道——合同的红线 8 拒的是 `file:` / git / URL 规格与非公共 registry 的 lockfile 条目（可复现性），registry 上的依赖照样能带 `preinstall`，所以那条 flag 不能去（实测：带 `preinstall` 的包打成本地 `.tgz` 作依赖，`npm install` 会执行它，加上 `--ignore-scripts` 不会；今天这种 `file:` 规格在 validate 就被拒，但结论对 registry 依赖同样成立）。

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
# router 的 .venv 有 CDK 依赖与 cryptography（synth 期核对 KMS 公钥指纹）但**没有 pytest**，借 deployer 的（含 boto3）
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
# 必须指定 tests/——裸 pytest 会误收集 infra/cdk.out 里的 asset 副本
(cd site-builder/deployer && .venv/bin/pytest tests -q)
# mcp 的 .venv 里**没有 pytest**（只装运行期依赖），所以这条借的是宿主机的 python3。
# 宿主 python3 没装 pytest 时它会报 `No module named pytest`——那不是代码红，
# 改用下面的 run_locked_tests.sh（自建 py3.13 venv，不依赖宿主 pytest）。
# **别借 deployer 的 venv**：那里没有 `mcp` 包，实测 148 条假红。
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
- **E2E 的 CA 陷阱**：E2E 会**在进程内调用发起 HTTPS 的生产代码**，那条路径用的是
**默认** SSL 上下文，不是测试自己造的那个（测试自己那条走显式 certifi，一直是好的
——所以缺陷在"测试能访问站点"上完全看不出来）。**venv 的默认信任库是不是空的取决于
母解释器**：python.org 那种构建下是 0 个 CA（原始事故现场，跑了 21 分钟才炸），
Homebrew 的 `python@3.12` 指向 `/opt/homebrew/etc/openssl@3/cert.pem`，venv 里有
198 个（换机器实测）。**只设 `SSL_CERT_FILE` 不够**：`HTTPSHandler`
在构造时就把上下文定格了。现在由 fixture 自动修好，守卫
（`test_deploy_fixture_flags.py` 里那三条 `*ssl*`）**自己把"空信任库下 import"这个
前提造出来**，所以在两种解释器上验的都是同一个缺陷。看到
`CERTIFICATE_VERIFY_FAILED` 时**别当成网络/证书故障**去查代理和防火墙——先确认是不是
又碰到了这个上下文。

**MCP 的上面那条用宿主机依赖，不等于容器里的依赖**（宿主的 mcp / boto3 版本与
`mcp/requirements.txt` 锁的通常不同）。改过锁定清单、或要确认"部署出去的那套依赖也全绿"时跑：

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

E2E 与真机闸门（需要真实 AWS 部署 + config.ini 已回填）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q   # **9 条**，实测约 37 分钟
# ↑ 它超过很多工具的单次超时上限，中途被杀会让 autouse 的清理 fixture 跑不完 ⇒ 留下真站点。
#   要后台跑或调大超时。
bash site-builder/scripts/smoke_router.sh    # 路由层冒烟（会写测试数据，跑完清理；含 65s 等 Edge 缓存）
python3 site-builder/scripts/verify_console_e2e.py      # 控制台端到端
python3 site-builder/scripts/verify_analytics_e2e.py    # 统计端到端
python3 site-builder/scripts/ensure_fixture_site.py     # 常驻夹具站点（四个 verify_* 与 kid 探针只打它）
python3 site-builder/scripts/verify_kid_entry_live.py   # 会话入口真机正/负向（只发 GET；--self-test 不碰 AWS）
# ↑ 轮转时用两个旗标：`--role current|previous`（正向，打夹具站点；会消费一枚升级码）、
#   `--retired-token FILE`（负向，期望 Edge 302 / panel 401 且 outcome=unknown_kid）。
#   FILE 由 `_session_mint.py --save` 预存，**只许写进 .scratch/**（gitignored，token 是活凭证）。
python3 site-builder/scripts/session_verify_counts.py --hours 1 --require-total   # 三处 session_verify 埋点读数（只读；任一 verifier 为 0 即退 1）
# ↑ 轮转的排空闸门是 `--drain-gate previous`，四条判据锁在脚本里
#   （窗口 ≥ 26 h、每处总量 > 0、目标列三列全 0、accepted_current 三列全 > 0），exit 0 才算过。
#   手写那四个旗标少任何一个都是静默放宽——空窗口下裸 `--require-zero` 会退 0，而下一步是不可逆的退役 key。
#   判据说明见 DEPLOY.md 的轮转 runbook
# 账号信任边界的漂移闸门（只读；A 直接失守 + B IAM 写静态快照两层；几百个 principal × 3 次
# IAM 模拟（第三次是 kms:Sign 的 MessageType=DIGEST 那一腿）+ **两次** GetAccountAuthorizationDetails——第二次是模拟后的**窗口两端一致性复查**，
# 两端不一致就作废本轮、不出结论也不写基线；它**不保证原子**，只覆盖 principal 层、只证明两端相等，
# 三个已接受盲区见 docs/security/account-trust-boundary.md）+ 扫 bootstrap 桶，实测约 11 分钟
python3 site-builder/scripts/verify_account_trust_boundary.py
# 密钥增减必须**声明**，否则一律红：`--new-key LABEL` / `--retire-key LABEL`
# （LABEL ∈ 已配置 kid ∪ {login-flow}）。声明管**两件**事：
#   ① grant delta → `migration_grants`（绿）。**前置条件是该 principal 原本就能签某把
#      会话 key**——"原先签不了、现在能签"是能力面真的变大，声明不该抹掉它，**这是刻意的**；
#   ② coverage 成员迁移 → `migration_undecided`（绿）。成员是**可分解**形态
#      `指纹|动作类|资源类,…`，判据是把被声明 key 的资源类从**基线与本次两侧**剔掉再比：
#      相等才整批落绿，**剔完仍多出来的照红**。两侧都剔才同时覆盖新增（类只在本次有）与退役（类只在基线有）。
# `--update-baseline` **先打印一遍比较报告再写；报告生成不了就不写**——这条命令的语义是
# "我知道并接受这些变化"，接受了什么必须留痕。用 `--dump-observed` 一次扫描 + 多条 `--from-dump`
# 省掉第二个 11 分钟（dump 含真实角色名，落 .scratch/，按 0600 写）；声明不进快照、比较时才归一化
# ⇒ 同一份快照可按不同声明重比；**只有一条只在实测路径上评估**：login-flow 那条硬断言（快照刻意不含它）。
# **没有基线时只能 `--update-baseline` 生成，不能出结论**（基线 gitignored，含单账号实测值）。
```

`site-builder/scripts/verify_*` 是真机闸门（部署后跑，不是单测）。**本文件不记数量与
最新结果**（都会过时）：闸门清单就是上面那段命令，跑一遍即是最新结果。

**这些脚本一律用 `python3` 跑（不带路径的那个），不要借 `deployer/.venv/bin/python3`。**
两个前提，缺任一都不是"配置没写对"的症状：

- **`python3` 必须 ≥ 3.10。** `scripts/*.py` 里有一批（约三分之一，含 `verify_*` 闸门）用了 `X | None` 标注却没写
`from __future__ import annotations`，在 3.9 上**函数定义那一刻**就
`TypeError: unsupported operand type(s) for |`。macOS 自带的 `/usr/bin/python3` 是 3.9
⇒ 直接跑不了，见下面「仓库外的几样东西」。
- **CA 信任库要能用。** 靠 **`pip-system-certs`**（装完会在 site-packages 放一个
`pip_system_certs.pth`，import 期把 `ssl` 的默认上下文换成读系统 keychain 的那个；
它内部用 truststore，所以**直接 `import truststore` 是失败的、`cert_store_stats()` 会抛
`NotImplementedError`——这两个现象都正常，不是坏了**），缺它的症状是每一次 HTTPS 都
`CERTIFICATE_VERIFY_FAILED`，读起来像网络/代理故障。

**"借 venv 的解释器"为什么仍然不推荐**：能不能 HTTPS 取决于母解释器（Homebrew
`python@3.12` 建的 venv 有 198 个 CA、能跑；python.org 那种构建是 0 个、每条 HTTPS 全红），
而闸门脚本不该依赖这个差异。`python3` 那条路是确定的。

`verify_analytics_e2e.py` 会自建 fixture 站点、发真实请求、跑一次 rollup 再清理，
其中 MCP 那一段要求**用户 OAuth token 是新鲜的**（refresh TTL 为 1 天）；
过期时要先在浏览器里登录一次（`node site-builder/clients/quick-desktop-proxy/auth.js`）。
三个 verify 脚本共用 `site-builder/scripts/_mcp_client.py`（MCP 客户端 + token 读取，
`verify_analytics_e2e.py` / `verify_api_key_e2e.py` / `verify_oauth_and_impersonation.py`）
——改它要意识到是同时改三个闸门。

## 部署/重部署命令

**下面是重部署顺序**（各组件已存在、config.ini 已回填）。**全新账号的首装顺序不同**：
④ 与 ② 互为前置（② 要 ④ 的 CMK 公钥，④ 的 step Lambda 要 ② 的 `edge_role_arn`），所以
**④ 要部两次**——④（只为建 CMK）→ 回填 `[SessionKeys]` → ② → 回填 `edge_role_arn` → ④ 再一次。
漏掉第二次是无声的（空 `EDGE_ROLE_ARN` 照过，到第一次真实建站才炸），完整说明在
`site-builder/DEPLOY.md`「部署顺序总览」。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# 执行器（bundling 需要 Docker；两把会话签名 CMK 也在这个栈里）
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)

# 首次 / 加 key 时：把两个 [SessionKey:*] 小节（含 spki_sha256）粘进 site-builder/config.ini
python3 site-builder/scripts/session_key_fingerprint.py --from-stack

# 路由层（改过 config.ini 必须先 rm -rf cdk.out，否则用陈旧 asset）
# 依赖 ④ 的 CMK：synth 时从 KMS 取 site 公钥并核对 config 的 spki_sha256，取不到或不符即 synth 失败
# router 栈有 stack policy（拒 Update:* 落在 Edge 两函数 / 分发 / 路由表上），所以三步一组：
# open 打开（首次部署栈不存在时打印 SKIP）→ deploy → apply 关回去并读回核对。**open 之后无论 deploy 成败都要 apply。**
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply

# auth 服务（Lambda + Function URL + pre-token 触发器，幂等）
(cd site-builder/auth && python3 deploy_auth.py)

# MCP（buildx ARM64 → ECR → AgentCore runtime；--skip-build 只改配置）
(cd site-builder/mcp && python3 deploy_agentcore.py)

# API Key 交换层 key-proxy（**可选组件**；无 [ApiKey] 段时打印跳过并返回 0）
# 顺序：deploy_pool → deployer 栈 → deploy_agentcore → 本脚本 → deploy_panel
(cd site-builder/key-proxy && python3 deploy_key_proxy.py)

# 控制台 panel（Lambda + Function URL + 前端上传 + console route，幂等）
# --skip-frontend 只改后端。改前端后必须重跑（不带该开关）才会上传。
(cd site-builder/panel && python3 deploy_panel.py)

# 生成含真实值的用户接入指引（产物 gitignored）
python3 site-builder/scripts/gen_onboarding.py
```

配置全在 `site-builder/config.ini` 与 `router/config.ini`（gitignored，从同目录
`.example` 复制）。**config.ini 是各部署脚本与 CDK 栈的唯一取值来源**，代码不硬编码
账号/域名。git 历史已清洗过真实账号 ID——不要把真实账号值写进任何被跟踪的文件。

## 架构（五层 + 控制台，读代码前先建这张图）

```
① 建站 Skill (site-builder/skills/)  ← Agent 客户端加载的"部署合同"说明书
        ↓ MCP 调用（OAuth 带 IdP 身份）
② 部署 MCP (site-builder/mcp/)       ← AgentCore Runtime，9 工具全部秒级返回
        ↓ 条件迁移 PENDING→RUNNING + 启动 SFN
③ 异步执行器 (site-builder/deployer/) ← Step Functions 10 步：validate → provision-db
        ↓ 写路由表                       → CodeBuild 打包 → 站点 Lambda → 前端 S3 → 路由 → 冒烟
④ 路由+鉴权层 (router/)              ← CloudFront *.{domain} + Lambda@Edge
        ↓ 未登录 302                     查路由表 → 验会话 JWT → 注入 x-user-email → 分流
                                         顺带写一行访问明细（只页面级、只 `app-` 前缀）
⑤ 身份层 (site-builder/auth/)        ← Cognito(联邦到 OIDC IdP) + 登录服务 + pre-token 触发器

交换层 (site-builder/key-proxy/)      ← mcp.{domain}，**可选**组件
   给只能配静态 Header 的 MCP 客户端一条路：验 X-API-Key → 换组件自身的机器
   token → 不懂协议地透明转发到 ②，只多一个 X-SB-On-Behalf-Of 头告诉 ② 以谁
   的身份行事。config.ini 无 [ApiKey] 段 = 整个组件不存在（推荐默认）

控制台 (site-builder/panel/)          ← console.{domain}；**建站仍只在 Agent 里**
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
- **鉴权全部在边缘**：站点代码零 auth 逻辑。Edge 验 RS256 会话 cookie（只内嵌 site family 的
公钥，零 KMS 权限）（与 `auth/session.py` 同算法，**两处必须字节级同步**，见
`router/infrastructure/lambda/origin_request.py` 注释）、按 allowed_users
放行、注入 `x-user-email` / `x-user-name`（后者 URL 编码，站点须
decodeURIComponent）。**CloudFront 全站禁缓存是鉴权正确性前提**
（origin-request 只在 cache miss 执行）——别加缓存策略。
- **身份即邮箱**：owner / allowed_users / 会话 claim 全以 email 为键，对 IdP
无感。Cognito access token 默认不含 email，靠 pre-token V2 触发器
（`auth/pre_token_email.py`）注入——MCP 网关只收 access token
（id_token 会 401，不要把 authorizer 改成 allowedAudience）。
- **Lambda@Edge 不支持环境变量**：Edge 函数的配置（表名、site family 的公钥 allowlist）由 CDK
部署时字符串替换注入（`{{PLACEHOLDER}}` 形态）。取公钥失败时 **synth 直接失败、什么都不部**
（指纹与 config 的 `spki_sha256` 不符同样抛，且不看 `APP_SYNTH_OFFLINE`——那不是"读不到"是写错了）；
占位符只在显式 `APP_SYNTH_OFFLINE=1` 下出现，产物带 SYNTH-ONLY 标记、不可部署，`verify_deployed_edge.sh` 会抓。

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
- **auth/session 与 Edge verifier 是跨部署单元的同一契约**（含 `[SessionKeys]` 的 allowlist：`session.verify_token` 与 Edge 的 `_verify_session_jwt` 字节等价，Edge 只持 site family 的公钥、panel 只持 console）。claim、算法或密钥形态变化
必须同步 auth、panel、Edge、跨组件测试和部署顺序。
**顺序有两个方向，别照抄错**：**新建部署**是 `deployer 栈先于 router 与 auth/panel`（依赖——两把
CMK 在那个栈里，router 栈 synth 要从 KMS 取 site 公钥注入 Edge，auth/panel 部署前核对指纹）；
**切换/轮转**必须 **verifier 先行**（速度差——auth/panel 改配置重部几分钟就切，Edge 要重部 +
10–20 分钟全球复制；signer 先切 = 新 cookie 在旧边缘节点验签失败，症状与"公钥注入坏了"一模一样）。
切换的完整协议是 `site-builder/DEPLOY.md`「轮转会话密钥（KMS）」一节。
- **异步调用结果未知时保留恢复状态。** 网络超时不等于请求未受理；不得在结果不确定时
释放租约、回滚为可重试状态或允许新的部署/下线并发进入。

## 跨组件改动矩阵

| 改动 | 必须同步检查 |
|---|---|
| `contract/` schema/redlines | validator、Skill references、fixtures、生成模板；红线 8（lockfile）还与 `deployer/buildspec-package.yml` 的 `npm ci` 和 `deployer/tests/security_contracts.py` 的精确命令 allowlist 互为前提——撤任何一侧另一侧就失效 |
| `permissions.py` | deployer tests、panel、key-proxy、MCP、三个产物重部 |
| `auth/session.py` | auth 调用方、panel copy、Edge verifier、auth→Edge 向量 |
| `origin_request.py` | router tests、origin-response 对称契约、CDK asset、Edge 部署 |
| router 栈的四个受保护 construct ID（`OriginRequestFunction` / `OriginResponseFunction` / `Distribution` / `SubdomainMappingTable`） | `router/infrastructure/stack_policy.py` 的 `PROTECTED_CONSTRUCTS`（synth 期守卫 `assert_protected_constructs` 会红）、`scripts/router_stack_policy.py`、`verify_deployed_edge.sh` ⑤、DEPLOY.md ② 的 open → deploy → apply。**改 construct ID = 换逻辑 ID = 替换资源**——对分发与路由表那是事故 |
| 路由权限字段 | permissions、register/resync、补偿恢复、Edge 反序列化 |
| DynamoDB/DSQL 资源 | runtime inline policy、boundary、undeploy、backfill、IAM 模拟 |
| `[SessionKeys]`（`auth/session_keys.py`） | `config.ini.example`、`session_key_fingerprint.py`、`deploy_auth`/`deploy_panel` 的 env（`SESSION_KEYS_JSON` 的 RS 行）与 KMS IAM 清单、`router/infrastructure/stack.py` 的公钥注入、闸门 kms 分节、`verify_deployed_edge.sh` 的公钥对账、`verifier_env.py`（auth 拥有、panel 复制）、`session_kms.py`（同上） |
| `[SessionKeys] login_flow_secret_param` | 只进 auth（`LOGIN_FLOW_SECRET_PARAM` + 角色清单），`login_handler._login_flow_sig` 是唯一读取点；`deploy_auth.ensure_secret` 创建（**不进写前核对清单**，见 `docs/adr/0004-*.md`）；panel 有三条负向断言锁死它永不持有；闸门记成 grant `read-login-flow-secret` 且**不算冒充面** |
| CLAUDE.md「仓库外的几样东西」第 2 步的 venv 表 | `scripts/bootstrap_venvs.sh` 的 `VENVS` 表（守卫 `deployer/tests/test_bootstrap_venvs.py` 按表逐行核对）、DEPLOY.md「本机工具链」 |
| 验收工具的夹具签发器客户端（`scripts/_session_mint.py`） | 六处调用方（四个 `verify_*`、`verify_kid_entry_live.py`、E2E 的会话 cookie fixture）+ `ensure_fixture_site.py`。改它等于同时改六个验收面；**它不持任何密钥**（登录态全部经 auth 的 `/fixture-session`），带外签发只此一处 |
| `session.py` 的 `FIXTURE_*` 常量 | Edge 内嵌字面量（router 单测钉住等值）、`permissions.FIXTURE_DOMAIN`（auth 单测钉住等值）、`deploy_panel` 的 admin 断言、`ensure_fixture_site.py`、闸门的站点形状层 |
| 两份 `config.ini.example` 的共享键（`frontend_bucket` / `account_id` / `region` / `base_domain` / `routing_table` / IdP 名） | `deployer/tests/test_example_config_consistency.py`（按语义配对，且共享键的值里不许带行内注释——生产是裸 `ConfigParser`，注释会并进值）、`router/infrastructure/stack.py` 的 `resolve_frontend_bucket`（桶名是**约定**：插值后必须等于 `site-frontend-<account_id>`，四个生产方写死了它 —— app.py 的 IAM ARN 与 `FRONTEND_BUCKET` env、deploy_panel、upload/undeploy/mark_job、verify_deployed_components）与 `assert_frontend_bucket_matches_site_builder`（synth 期跨 config 对账，离线/读不到则警告跳过）、`verify_deployed_edge.sh` 的 `FRONTEND_BUCKET_DOMAIN` 段。**改桶名不是改这一个键** |
| `deployer/functions/function_url_policy.py`（Function URL resource policy 的唯一实现） | 三个部署脚本的 `converge_function_url_policy` 调用（auth 的 `edge_role_arn()` 校验、panel / key-proxy 的 `ensure_function`）、闸门 `_check_function_url_authz` 与 `MIN_DEPLOYED_CHECKS`、`deploy_lambda_site` 的 parity 用例（站点色授权与平台三条同形）、`fake_lambda_policy.py` 的渲染形态、`extra_principals`（`[Verification]` 开着时 auth 多 verifier 两条） |

## 高频坑（都是真机踩过的）

- Function URL 一律 `AuthType=AWS_IAM` + 只授权 edge role，且需要
`InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl) 两条语句，缺一即 403。
`AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（删光 resource policy）。
**三个平台脚本的 resource policy 由 `function_url_policy.converge` 每次部署按期望集合等值写**
（读回、替换内容不对的同名语句、删野 Sid、写后读回核对；一致时零写入）——"同名 StatementId 已存在
就 pass"是假幂等：edge role 被删后重建时 IAM 会把 policy 里的 Principal 改写成已删角色的 AROA 形态，
同名语句存在但永不匹配，症状是重部 exit 0 而 Edge 全 403（auth 那条 = 全平台登录不可用）。
`verify_deployed_components.py` 对 auth / panel / key-proxy 三条都用同一个 `drift` 断言。
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
- us-east-1 是硬约束（Lambda@Edge 与 CloudFront 的 ACM 证书），换区要改代码。
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
这个缺陷曾在真机上活了整个控制台开发周期——单测直接调 handler，不经 CloudFront。
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
- **auth 的部署包清单是 `deploy_auth.AUTH_PACKAGE_MODULES`，由 `auth/tests/test_deploy_auth_package.py` 按 login_handler 的 import 闭包核对**。实测过：给 login_handler 新加一个同目录 import 却没进包 ⇒ `Runtime.ImportModuleError` ⇒ **整个 auth 502 约 4 分钟**，而单测全绿、`verify_deployed_components` 也绿（它当时只核对两个点名文件）。同一条纪律 panel 那边叫 `COPY_FILES`。
- **改了 `permissions.py` 这类共享模块，要重部的是三个组件**：panel、key-proxy、MCP
各自把它打进自己的产物（key-proxy 也带，虽然它只用 `EMAIL_RE`）。漏一个的症状是
产物陈旧而部署脚本一切正常——`verify_deployed_components.py` 是唯一会点出来的地方。
- **auth / panel 的 `SESSION_KEYS_JSON` 只有 `kid` / `key_arn` / `spki_sha256`，公钥运行时按 ARN 取、
指纹不符即拒**（冷启动 500，而不是接受一把来历不明的公钥）。改了 CMK 却没重跑
`session_key_fingerprint.py` 回填 config，三个部署脚本（router 栈 synth、`deploy_auth`、`deploy_panel`）
都在第一次写之前拒绝部署——**那不是权限问题**，是 config 与 KMS 里的 key 不是同一把。
- **router 栈有 stack policy，`cdk deploy` 前后各一步**：`router_stack_policy.py open` → deploy → `apply`。
  忘 open 的症状：`cdk deploy` 在 ExecuteChangeSet 阶段失败、栈事件里该资源 UPDATE_FAILED 且原因含
  "stack policy"、整栈回滚（Edge 不受影响；open 后重跑）。忘 apply **没有任何症状**——保护一直开着，
  只有 `verify_deployed_edge.sh` ⑤ 会红。策略拒的是 `Update:*`（Edge 换码是 Lambda `Code` 的
  Modify，只拒 Replace/Delete 拦不住它），越过它要 `cloudformation:SetStackPolicy`；它不管
  DeleteStack（termination protection 另配），也不管绕开 CloudFormation 直接调 Lambda/CloudFront API。

## 文档地图

| 要做什么 | 看哪里 |
|---|---|
| 部署到新账号 / 排查部署问题 | `site-builder/DEPLOY.md`（①→⑦ + ⑤b 控制台 + ⑤c API Key + 全部实测坑） |
| 客户端接入（人/Agent） | `site-builder/docs/client-setup.md`；含真实值版本跑 `gen_onboarding.py` |
| 合同细节（给站点生成方） | `site-builder/skills/site-builder/references/{contract,redlines}.md` |
| **还剩什么没做 / 优先级** | `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9（**tracked**；两轮独立对抗性审查的合并版。做完的行带对勾或删除线；第 11 行起的先后由 spec §11.9 第 12 条与工单给，不由行号给） |
| **平台防谁 / 不防谁（账号信任边界）** | `docs/security/account-trust-boundary.md`（**tracked**；M09 的结论真源。含只读实测方法、由基线断言的数字、为什么 SCP/resource policy/应用层签名/收窄 invoke 都不成立） |
| **CodeBuild 对 bootstrap 桶读权限的收窄（§9 的 3b）** | `docs/superpowers/specs/2026-08-27-codebuild-bootstrap-read-narrowing-spec.md`（**tracked**；含为什么已有那条 AST 守卫看不见这个洞、三层守卫各自能证明什么、部署窗口的干净失败面） |
| **轮转会话密钥（KMS）** | `site-builder/DEPLOY.md`「轮转会话密钥（KMS）」一节（① 建新 key → ② 就位 → ③ 切换 → ④ 排空 → ⑤ 退役，附回滚表与应急）。非对称 CMK 不支持自动轮转，所以轮转 = 加一把新 key + verifier 先行 + 排空后退役。裁定原文在 spec §11.8 |
| **会话签名非对称化的设计（3c；分包与顺序）** | `docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md`（**tracked**；§6.1 是时序真源，其中 3c-final 那一行是当前定义、2A/2B/3 三行只保留设计内容；§11 是全部裁定与被否决项，§11.9 是"交付物是资产"框架下的收敛：2A/2B/3 合为 3c-final、验证环境硬切换、HS 不进 v1；ADR 在 `docs/adr/`。含量测过的收益边界、两个 key family 的模型、部署与回滚协议、以及「四个 verify_* 闸门的登录态改由夹具签发器提供」这条容易漏的代价） |
| **3c 冒充面的可复跑证据** | `site-builder/scripts/probe_impersonation_surface.py`（**tracked**，只读，约 20 分钟）→ `docs/security/3c-impersonation-surface.json`（**tracked**，只有计数/等价类/边际收益/盲区清单，名字只进 gitignored dump）。**`--self-test` 不碰 AWS**，反例与变形测试在 `deployer/tests/test_probe_impersonation_surface.py` |
| 加固包的设计与实施 | `docs/superpowers/specs/2026-08-22-s1-isolation-and-auth-hardening-spec.md` + `docs/superpowers/plans/2026-08-22-s1-isolation-and-auth-hardening.md`；存量环境的升级/闸门/回滚见 `site-builder/DEPLOY.md` 的「S1 加固」一节 |
| 一期设计决策与范围 | `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`（已实现快照，勿改） |
| 二期设计与需求 | `docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md`；需求清单 `docs/phase2-requirements.md` |
| 任务级实现/审查证据链 | `.superpowers/sdd/<计划日期>-<计划名>/progress.md`（**gitignored**、每个 plan 一个目录；`.superpowers/sdd/progress.md` 那个扁平路径是一期的旧布局） |
| 各里程碑实测发现 | `docs/design/M{3,4,5}-FINDINGS.md`、`M4-SPIKE-2026-08-10.md`、`M7-SPEC-2026-08-16.md`（**gitignored**；含可复用的断言自查清单，已验证过的别再跑一遍） |
| 历史过程记录 | `docs/design/HANDOFF-2026-08-07.md`（**gitignored**；写到二期为止——**不是**状态真源） |

> **接手时的读法**：要知道"资产是什么样"，读本文件 + `README.md` + `site-builder/DEPLOY.md`，
> 数字自己跑测试；要知道"还剩什么"，读上面那份 merged review 的 §9；验证环境"现在到哪了"
> 只在 gitignored 的 `.scratch/<feature>/NEXT.md` 里，新 clone 里不存在，也不该需要它。
> **不要**依赖 `docs/design/` 里的任何一份——它们和 `.superpowers/` 都 gitignored
> （含真实账号/资源值），新 clone 里根本不存在，**也不要 `git add -f`**。

### 仓库外的几样东西（新 clone / 新机器按这个顺序恢复）

**`git clone` 拿不到能跑的环境**——下面几样都在仓库外，缺任何一样症状都不像"没配置"。
按这个顺序做：

0. **两个 Python 解释器**：`brew install python@3.12 python@3.13`。3.12 是五个 venv 的
   母解释器；3.13 只给 `mcp/run_locked_tests.sh`（与容器基础镜像一致，找不到它时那个
   脚本会明确报出来）。**macOS 自带的 `/usr/bin/python3` 是 3.9，跑不了本仓库的脚本**
   （见上面「测试命令」里 `X | None` 那段）。
   **坑：`brew install python@3.12` 不提供 `python3` 这个名字**——未版本化的
   `python3`/`pip3` 只在 `/opt/homebrew/opt/python@3.12/libexec/bin` 里，`brew link`
   也不吐到 `/opt/homebrew/bin`。于是 `python3` 仍是 3.9，症状是那条 `TypeError` 而
   不是"版本不对"。两层解法任选或都做：
   `~/.zshenv` 里把那个 `libexec/bin` 前置（**必须是 `.zshenv` 不是 `.zshrc`**：非交互
   shell——脚本、编辑器/Agent 起的子进程——只读前者）；或
   `/opt/homebrew/bin/{python3,pip3}` 两个符号链接指向它（这层与 shell 无关；将来若
   `brew install python` 会报 symlink 冲突，删掉这两个软链即可）。
1. **两份 `config.ini`**（`site-builder/` 与 `router/`，各从同目录 `.example` 复制并
   回填真实账号/域名/证书 ARN）。**它们是所有部署脚本与 CDK 栈的唯一取值来源。**
   `configparser` 对缺失文件是**静默的** ⇒ 不回填不会报"缺配置"，而是拿空值往下跑并
   拼出假结论（本仓库为此在闸门里专门加了"读不到任何段就硬失败"）。
2. **五个 venv 全部重建：`bash site-builder/scripts/bootstrap_venvs.sh`**（幂等；`--only <目录>`
   只建一个、`--check` 只做前置检查、`--host-deps` 顺带做第 3 步；结束时打印每个 venv 的解释器
   版本与 pytest 版本作为"能跑"的证据，全量成功后写 gitignored 的 `.venv-bootstrap.stamp`）。
   它做的就是下面这张表，守卫 `deployer/tests/test_bootstrap_venvs.py` 按这张表核对脚本——
   **改表必须改脚本**。用 Orca 开 worktree 时由仓库根 `orca.yaml` 的 setup hook 自动跑它，并从主
   checkout **复制**（不软链）两份 gitignored 的 config.ini。手工建时的三条坑：
   **必须带 `--clear`**（`python3.12 -m venv --clear .venv`）——
   shebang 是绝对路径，不带 `--clear` 不重写，一直报 bad interpreter。
   **venv 不能从别的机器拷**：`pyvenv.cfg` 的 `home =` 与 `bin/*` 的 shebang 都是绝对路径，
   编译扩展按 CPU 架构 + Python ABI 装，而 contract/deployer 那两份是
   editable 安装（site-packages 里写死源码树路径）——**同一台机器上另开一个 worktree 也要重建**。
   五个都用 **Python 3.12**（`mcp/run_locked_tests.sh` 另建一个钉 3.13 的，与
   基础镜像一致，不要拿它替换 `mcp/.venv`）。每个 venv 装哪份清单：

   | venv | 依赖清单 | 备注 |
   |---|---|---|
   | `router/infrastructure/.venv` | `requirements.txt` | CDK 依赖 + `cryptography`（synth 期取 KMS 公钥并核对指纹），**没有 pytest**（router 的测试借 deployer 的 venv） |
   | `site-builder/contract/.venv` | `requirements-dev.txt` | 含 `-e .`，一条 `pip install -r` 装完 |
   | `site-builder/deployer/.venv` | `requirements-dev.txt` | 含 `-e ../contract`，同上 |
   | `site-builder/deployer/infra/.venv` | `requirements.txt` | aws_cdk **只在这个** venv 里 |
   | `site-builder/mcp/.venv` | `requirements.txt` | — |

   **那两份 `requirements-dev.txt` 必须在各自目录下 `pip install`**：里面 `-e` 的相对
   路径按**进程 cwd** 解析，不是按文件位置。`auth` / `panel` / `key-proxy` 没有自己的
   venv，借别人的，组合见上面「测试命令」。deployer 那份是精确钉死的，直接依赖的原始声明
   留在文件头注释里。两份都实测过：空 venv 一条命令装完，六个借用它们的套件全绿。
3. **`python3`（第 0 步那个 3.12）上装三个包**：
   `python3 -m pip install --user --break-system-packages boto3 pip-system-certs cryptography`
   （即 `bootstrap_venvs.sh --host-deps`；默认不做，因为它改的是机器不是仓库）。
   `cryptography` 是 3c-final 加的：两个部署脚本、`session_key_fingerprint.py` 与两个闸门都经
   `session_kms` → `session` 用它解析公钥、核对指纹。宿主上不钉版本；Lambda 产物里钉 50.0.0。
   **五个 `verify_*` 真机闸门与所有 `scripts/*.py` 都用它跑。**
   两个开关缺一不可：Homebrew 的 python 带 PEP 668 标记，不加
   `--break-system-packages` 直接被拒；加 `--user` 是为了只写 user site
   （`~/Library/Python/3.12/...`）而不动 brew 自己的 site-packages。
   缺 `pip-system-certs` 的症状是每一次 HTTPS 都 `CERTIFICATE_VERIFY_FAILED`——**读起来
   像公司代理/防火墙问题，其实不是**，别去查网络。
4. **MCP 的 OAuth token**：`node site-builder/clients/quick-desktop-proxy/auth.js`
   登录一次（那两个 `.js` 只用 Node 内置模块，**不需要 `npm install`**）。
   token 过期时 MCP server 会以 `-32603 token 过期且刷新失败` 连不上，
   **那是认证过期，不是没配置**。
5. **远端凭据**是维护者自己的事，不属于资产：远端名、SSH 证书、known_hosts 的约定写在
   gitignored 的接手点文件里，新 clone 只需要一个能拉取的远端。

**拿不回来、也不用拿回来的**：`docs/design/` 与 `.superpowers/sdd/` 下的全部过程记录
（每个 plan 的 progress、task brief/report、review diff）——**gitignored** 且含真实
资源值，新 clone 里不存在。**它们不是状态真源**，别为了"补齐上下文"去找它们。
真源是本文件 + `README.md` + `site-builder/DEPLOY.md` + merged review §9；
数字靠跑测试与闸门。3c 冒充面那份名字 dump 同理——**重跑探针即可重生成**
（`probe_impersonation_surface.py --dump-observed …`，只读约 20 分钟）。

> **加固包的编号别用 `S1`/`S2`…写进代码或文档正文**：`S3` 会和 Amazon S3 撞车（本仓库
> 到处在说 S3 桶），grep 出来全是噪音。用 merged review 里的 `M` 编号
> （`M03+M16`、`M07/M08/M10`…）或主题名指代。

## Agent skills

mattpocock 那套 engineering skill（`to-tickets` / `to-spec` / `triage` / `wayfinder` /
`code-review` / `domain-modeling` …）需要知道"issue 存哪、标签叫什么、术语表在哪"。
下面三行就是把它们指到 `docs/agents/` 的那份配置（由 `/setup-matt-pocock-skills` 生成）；
换 tracker 直接改那边的文件，不必重跑该 skill。

### Issue tracker

issue 与 spec 存成本地 markdown（`.scratch/<feature>/`，**gitignored、不进任何远端**，
因为 GitHub 那个远端是公开的）。See `docs/agents/issue-tracker.md`.

### Triage labels

五个默认角色，标签串与角色同名（`needs-triage` / `needs-info` / `ready-for-agent` /
`ready-for-human` / `wontfix`）。本地 markdown 下它们体现为每个 issue 文件顶部的
`Status:` 行，不是真的标签。See `docs/agents/triage-labels.md`.

### Domain docs

single-context：根 `CONTEXT.md` + `docs/adr/`。由 `/domain-modeling` 在术语或决策真的定下来时
才追加，不预先占位。See `docs/agents/domain.md`.
