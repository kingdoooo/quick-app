# Site Builder 二期 M3 实施计划（控制台 + 两个 Blocking 前置）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 `console.{base_domain}` Web 控制台（自助管理站点权限/协作者/所有权/部署历史/下线 + 管理员全局视图与名单），并在此之前闭合两个 Blocking 前置：SFN 终态两层收敛（TIMED_OUT/ABORTED 不再让 job 永久停 RUNNING）与登录失败告警的自动化部署。

**Architecture:** 四段。① 前置 B1：deployer CDK 栈新增 reconciler Lambda（EventBridge rule 匹配 TIMED_OUT/ABORTED）+ sweeper Lambda（Scheduler 每 30 分钟 DescribeExecution 兜底），两者共用同一条件更新函数、独立窄 IAM 角色、SQS DLQ；② 前置 B2：`deploy_auth.py` 追加 `ensure_alarm_pipeline()`，把手工创建的 metric filter/SNS topic/alarm/subscription 收编为唯一幂等真源；③ M3 核心：新建 `site-builder/panel/`（panel Lambda + Function URL AWS_IAM 仅 edge role + `deploy_panel.py` 幂等脚本 + 移植的静态前端），授权 100% 复用 `permissions.py` 高层函数，写 API 前置 console-session + CSRF 五步校验，Edge 加 `console` 平台子域白名单与 `__Host-sb_console` 保留 cookie，auth 服务加 `/console-session`；④ 收尾：`verify_deployed_components.py`（重构自 `verify_contract_fixtures.py`，唯一组件部署一致性真源）+ fixture 自动清理 + 真机 E2E。

**Tech Stack:** Python 3.13（panel/reconciler/sweeper/auth Lambda）、Python 3.11（Lambda@Edge）、boto3、DynamoDB（含 TransactWriteItems / TTL / GSI）、Step Functions、EventBridge Rules + Scheduler、SQS DLQ、CloudWatch Logs/Metrics/Alarms、SNS、CDK（deployer + router 两栈）、pytest + moto、原生 JS 静态 SPA（无构建链）。

## Global Constraints

以下约束来自 spec、`CLAUDE.md` 与 M1+M2 计划，**每个任务都隐含包含**：

- **区域**：一切资源在 `us-east-1`（Lambda@Edge / ACM / Quick 身份区域硬约束）。
- **配置唯一来源**：`site-builder/config.ini` 与 `router/config.ini`（均 gitignored，从同目录 `.example` 复制）。代码不硬编码账号 ID / 域名 / 邮箱。**不要把真实账号值（12 位账号 ID、真实域名、真实邮箱、真实 ARN、session UUID、本机绝对路径）写进任何被 git 跟踪的文件**——`.example` 里一律用 `000000000000` / `example.com`。
- **`docs/design/` 已 gitignore**：控制台原型 HTML 由 Open Design 侧维护，**不在仓库内编辑它**，也**不得 `git add -f`** 任何 gitignored 的 handoff/config/progress/design 文件。
- **测试命令按包区分 venv**（照抄，别猜）：
  - `cd site-builder/contract && .venv/bin/pytest tests -q`
  - `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`（auth 无自己的 venv，借 contract 的，含 pyjwt）
  - `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`（router 的 .venv 只有 CDK 依赖，借 deployer 的，含 boto3）
  - `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests`**，裸 pytest 会误收集 `infra/cdk.out` 里的 asset 副本）
  - `cd site-builder/mcp && python3 -m pytest tests -q`
  - **panel 包借 deployer 的 venv**：`cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`（panel 无自己的 venv；需要 moto + boto3，deployer 的 venv 两者都有。Task 6 建立此约定后同步写进 `CLAUDE.md`）
- **CDK 模板断言测试默认 skip**，要真跑必须带 PYTHONPATH 桥接（`aws_cdk` 只在 `infra/.venv`）：
  `cd site-builder/deployer && PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`（synth 需 Docker）。
- **Edge 函数约束**：Lambda@Edge 不支持环境变量，配置由 CDK synth 时字符串替换 `{{PLACEHOLDER}}` 注入（`router/infrastructure/stack.py`）；单文件、零第三方依赖（只用运行时自带 boto3/botocore + 标准库）；1MB 代码上限；`origin_request.py` 的 `_verify_session_jwt` 与 `site-builder/auth/session.py` 的 HS256 算法**必须字节等价**。
- **CloudFront 全站禁缓存是鉴权正确性前提**（origin-request 只在 cache miss 执行）——**不得添加任何缓存策略**。
- **Function URL 一律 `AuthType=AWS_IAM`** 且只授权 exact edge role，并且需要 `lambda:InvokeFunctionUrl`（`FunctionUrlAuthType=AWS_IAM`）+ `lambda:InvokeFunction`（`InvokedViaFunctionUrl=True`）**两条**语句，缺一即 403。不允许 `Principal=*`、不允许 public Function URL、**不允许配置缺失时 fallback 到宽权限**（缺 `edge_role_arn` 必须抛错中止部署）。
- **权限写入只走一个入口**：`permissions.write_permissions`（`TransactWriteItems` 两表原子）。panel **不得**另写角色表、角色判断、权限 rev 守卫或手写 DynamoDB UpdateExpression；site-admins **不得** raw PutItem/DeleteItem/UpdateItem，必须经 `add_admin`/`remove_admin` 维护 `__count__` sentinel。现有结构性测试会扫描手写守卫，**不得绕过、禁用或改窄其扫描范围**。
- **fail-closed 优先**：权限/身份相关的解析与判定失败一律取最严格解释（空名单、按未登录处理、报错跳过），绝不"取最宽松的默认值继续"。
- **平台身份只认 host 解析出的 hardcoded subdomain 白名单**：不得根据 `route.owner == "platform"` 或任何 route item 可写字段判断平台身份。
- **加固测试必须先反向验证会红**：把守卫改成永真、模拟 direct Function URL、伪造平台 route、删 CSRF 检查，确认测试 FAIL，再还原。这是本项目历史上栽过两次"验证本身无效"后的硬要求。
- **源码文本断言必须排除注释/docstring**，或改用 AST / 实际产物解析（历史教训：断言字样留在注释里导致改错代码仍绿）。
- **断言脚本必须有最小检查数下限**；中途崩溃、AWS 调用失败、下载截断都必须非零退出。**本机 aws CLI 在 API 错误时也可能返回 exit 0**（实测），所以判失败必须同时校验输出是合法 JSON。
- **unit test 绿 ≠ 部署生效**：必须下载并比对真实 Lambda/Edge 产物（`verify_deployed_components.py`）。
- **git**：`commit` **不带** `--no-verify`（让 Code Defender 执行）；`push` **必须带** `--no-verify`（用户全局约定）。每次 commit 前三步：
  ```bash
  git add <本任务文件>
  bash site-builder/scripts/scan_staged_secrets.sh || exit 1
  git diff --cached          # 人工审核
  git commit -m "..."
  ```
  新文件首次 `git add` 之前另扫文件本体：`bash site-builder/scripts/scan_staged_secrets.sh --files <路径...> || exit 1`（`git diff` 看不到未跟踪文件）。命中不等于必须改（公开 URL、测试 fixture、co-author trailer 都会命中）——**必须先给用户看命中项再提交，不要自动清洗**，确认后加 `--allow-hits` 放行。
- **验证纪律**：每处改动用真实 AWS API 实证验证（本项目 mock 层出过多次问题）。标 `[真机]` 的步骤必须在真实 AWS 上跑，不能只靠 moto。
- **发现文档与实际不符就同步更新**（`site-builder/DEPLOY.md`、`docs/` 下相关文档、`CLAUDE.md`）。
- **不实现 M4/M5**：不写假接口、假数据或临时表。前端对 API Key（M4）与 stats/audit（M5）显示 disabled / coming later，**不得请求不存在的 API**。
- **OK 通知统一称「告警解除」**：只表示指标不再满足阈值，规则仍启用，不代表根因确认修复。
- **jobs 表 `owner` 字段是发起者（requested_by 语义）**，不参与任何授权判定；站点 owner 只由 `permissions.transfer_owner` 与首次部署路径写。

---

## 文件结构

**新建：**

| 文件 | 职责 |
|---|---|
| `site-builder/deployer/functions/reconcile_job.py` | SFN 终态收敛：EventBridge handler（实时层）+ sweeper handler（兜底层）+ 共用的条件更新函数 `converge_job_to_failed` |
| `site-builder/deployer/tests/test_reconcile_job.py` | 收敛矩阵单测（任意 phase / 幂等 / 乱序 / 不存在不创建 / 终态 no-op） |
| `site-builder/deployer/tests/test_infra_reconciler.py` | CDK 断言：rule pattern、target、DLQ、schedule、IAM 窄权限 |
| `site-builder/auth/alarm_pipeline.py` | `ensure_alarm_pipeline()`：metric filter / SNS topic / subscription / alarm 的幂等声明式收敛（唯一真源） |
| `site-builder/auth/tests/test_alarm_pipeline.py` | 告警管道幂等性与参数正确性单测（botocore Stubber） |
| `site-builder/panel/handler.py` | panel Lambda 入口：路由分发 + 身份提取 + CSRF/console-session 前置校验 |
| `site-builder/panel/api.py` | 各 `/api/*` 端点的纯函数实现（do_* 模式，便于单测） |
| `site-builder/panel/console_session.py` | upgrade code 校验入口（调构建时复制的 `session.py:verify_upgrade_code`）+ jti 原子消费 + `__Host-sb_console` cookie 构造。**code 编解码不在此实现**——单一实现在 `auth/session.py`，panel 构建时复制 |
| `site-builder/panel/ops_log.py` | ops-log 写入（append-only，PutItem only，字段脱敏） |
| `site-builder/panel/deploy_panel.py` | 幂等部署脚本：Lambda（打包时构建复制 `permissions.py`/`common.py`/`session.py`）+ Function URL(AWS_IAM 仅 edge role) + panel role（SSM 限定精确 jwt-secret ARN，**不用 auth 的前缀**）+ 前端上传 S3 + console route 注册 |
| `site-builder/panel/frontend/index.html` 等 | 移植的静态 SPA（原型视图层 + 真 fetch 实现的 window.API） |
| `site-builder/panel/tests/conftest.py` | panel 测试的 moto 表夹具（sites/jobs/admins/ops-log/session-codes/routing） |
| `site-builder/panel/tests/test_authz.py` | panel 授权矩阵（owner/collaborator/outsider/admin × 各端点） |
| `site-builder/panel/tests/test_csrf.py` | CSRF/console-session 前置校验（含"副作用前置"的顺序断言） |
| `site-builder/panel/tests/test_no_handwritten_guards.py` | 结构性测试：panel 不得出现手写 UpdateExpression / 角色判断 / admins raw 写 |
| `site-builder/scripts/verify_deployed_components.py` | **唯一**组件部署一致性真源（重构自 `verify_contract_fixtures.py`，7 段） |
| `site-builder/scripts/backfill_site_created_at.py` | 一次性幂等回填 sites.created_at（从 jobs site-index 最早一条推导） |
| `site-builder/deployer/tests/test_backfill_created_at.py` | 回填脚本测试（已有值跳过、无 job 的站点跳过并报告） |

**修改：**

| 文件 | 改动 |
|---|---|
| `site-builder/deployer/infra/app.py` | jobs 表加 `site-index` GSI；新增 `site-ops-log`（RETAIN）与 `site-session-codes`（TTL）表；新增 reconciler/sweeper Lambda + 独立窄角色 + EventBridge rule + Scheduler + SQS DLQ |
| `site-builder/auth/deploy_auth.py` | `main()` 末尾调 `ensure_alarm_pipeline()`；新增 `/console-session` 所需环境变量（session-codes 表名）；role 补 SNS/CW 所需权限（若脚本自身调用需要） |
| `site-builder/auth/login_handler.py` | 新增 `/console-session` 路径：校验顶域 `sb_session` → 签发一次性 code → 302 到 console callback |
| `site-builder/auth/session.py` | 新增 `mint_upgrade_code` / `verify_upgrade_code`（console-session 一次性 code 的**单一编解码实现**，HS256 同 JWT_SECRET，`typ="console-upgrade"`）；`mint_session_jwt(scope=...)` M1 已具备不动 |
| `site-builder/deployer/functions/common.py` | 加 `list_jobs_by_site`（用新 `site-index` GSI）；`upsert_site` 首次部署路径写 `created_at` |
| `site-builder/mcp/server.py` | `do_deploy_site` 建站分支改用 `create_site_record`（单次条件写整条记录）+ `SiteIdCollision` 重生成 ID（≤3 次） |
| `site-builder/deployer/functions/permissions.py` | 五个高层写函数 + undeploy 路径内落 ops-log（唯一落点） |
| `site-builder/mcp/deploy_agentcore.py` | MCP runtime role 补 `site-ops-log` PutItem |
| `router/infrastructure/stack.py` | Edge role 的 S3 GetObject 资源加 `{frontend_bucket}/platform/*`（现只有 `sites/*`——console 前端在 `platform/console/{version}/`，缺这条则 route_mode=split 的静态请求全部 AccessDenied，控制台页面加载不出来） |
| `router/infrastructure/lambda/origin_request.py` | `PLATFORM_SUBDOMAINS` 加 `console`；`RESERVED_COOKIES` 加 `__Host-sb_console`、`__Host-sb_pkce` |
| `router/infrastructure/lambda/origin_response.py` | `RESERVED_COOKIES` 同步（两份必须一致） |
| `router/infrastructure/lambda/test_edge_auth.py` | console 平台路由用例 + 伪造 platform route 负测 |
| `router/infrastructure/lambda/test_origin_request.py` | 保留 cookie 剥除/放行用例 |
| `site-builder/scripts/verify_deployed_edge.sh` | 断言产物含 `console` 白名单与新保留 cookie；断言 CloudFront 实际关联版本 |
| `site-builder/scripts/verify_sfn_failure_paths.py` | 扩两段：EventBridge 实时层与 sweeper 兜底层各自有效 |
| `site-builder/scripts/verify_auth_alarm.sh` | 增加「线上配置 == 脚本声明值」比对段 + confirmed subscription 检查 |
| `site-builder/scripts/smoke_router.sh` | 随机后缀 + trap 全覆盖 + 只删本次资源 + 强一致读回核对 + 最小断言数 + `--keep-on-failure` |
| `site-builder/deployer/tests/test_e2e_fixtures.py` | fixture finalizer：记录本次资源、默认 undeploy + purge、清理失败即测试失败 |
| `site-builder/config.ini.example` | `[Alerting] email`；`[Panel]` 段（session_codes_table / ops_log_table / console_version） |
| `site-builder/DEPLOY.md` | 新阶段：panel 部署；告警改为自动收敛（不称 IaC）；reconciler 说明；六→七个闸门更名 |
| `CLAUDE.md` | panel 包 venv 归属；验收脚本改名；部署命令补 `deploy_panel.py` |
| `.superpowers/sdd/progress.md` | 按任务追加记录 |

**删除：**

| 文件 | 原因 |
|---|---|
| `site-builder/scripts/verify_contract_fixtures.py` | 重构进 `verify_deployed_components.py`；只能有一个组件部署一致性真源，不留兼容 shim |

---

## 任务顺序与依赖

```
Task 1 (reconciler 逻辑) → Task 2 (reconciler CDK+真机)     [Blocking B1]
Task 3 (告警管道逻辑)    → Task 4 (告警真机验收)             [Blocking B2]
Task 5 (表+GSI+created_at 回填) ─┬→ Task 6 (panel 授权/API 纯函数)
                                 ├→ Task 7 (console-session+CSRF)
                                 └→ Task 8 (ops-log 落点)
Task 6,7,8 → Task 9 (panel handler 组装) → Task 10 (deploy_panel.py)
Task 11 (Edge console 白名单+保留 cookie)  ← 与 Task 6-10 并行，但独占 Edge 文件
Task 12 (auth /console-session)            ← 与 Task 6-10 并行，独占 auth 文件
Task 10,11,12 → Task 13 (部署三层 + verify_deployed_components.py 重构)
Task 13 → Task 14 (前端移植 + 真机 panel E2E)
Task 15 (fixture 清理) — 可并行，**必须在 Task 16 前完成**
Task 14,15 → Task 16 (全量回归 + 文档收尾)
```

**subagent 写范围互斥**：`permissions.py`（Task 8 独占）、Edge 两文件（Task 11 独占）、auth 两文件（Task 4/12 顺序执行，不并发）、`infra/app.py`（Task 2/5 顺序执行，不并发）、本 plan 与 spec（仅控制器修改）。

---

## Task 1: SFN 终态收敛逻辑（reconciler + sweeper handler）

**Files:**
- Create: `site-builder/deployer/functions/reconcile_job.py`
- Create: `site-builder/deployer/tests/test_reconcile_job.py`

**Interfaces:**
- Consumes: `common._table("JOBS_TABLE")`、`common._now()`（已存在）
- Produces:
  - `converge_job_to_failed(job_id: str, *, reason: str) -> str` —— 返回 `"converged"` / `"noop"` / `"absent"`；只在 `status == "RUNNING"` 且 `attribute_exists(job_id)` 时条件更新为 FAILED
  - `handler(event, context) -> dict` —— EventBridge Step Functions status-change 事件入口，返回 `{"job_id": ..., "outcome": ...}`
  - `sweeper_handler(event, context) -> dict` —— 定时兜底入口，返回 `{"scanned": N, "converged": M, "orphans": K}`
  - `TIMEOUT_ERROR` / `ABORT_ERROR` —— 固定无敏感信息的 error 文案常量
  - `STALE_MINUTES = 45` —— sweeper 的超龄阈值

**为什么两层**：Step Functions 状态变化事件是 **best-effort**（AWS 明确不保证投递），只实现 EventBridge rule 不算闭合。实时层负责秒级收敛，sweeper 负责补漏。两层共用同一个条件更新函数，所以"收敛语义"只有一份。

**为什么不能照抄 `_rollback_job_to_pending` 的条件**：那个函数要求 `#s = :running AND phase = :queued`——它保护的是"我刚写进去、SFN 没碰过"的状态。而 TIMED_OUT / ABORTED 可以发生在**任意 phase**（validate / package / register-route…），带 `phase=queued` 条件会让绝大多数真实卡死场景收敛失败。

**`STATE_MACHINE_ARN` 必须每次调用读环境变量，不做模块级常量**（Task 1 实施期发现）：Lambda 里两种写法都能跑（env 在 import 前就绪），但模块级快照在 pytest 里永远是空字符串——测试模块顶部的 `import reconcile_job` 发生在 `aws` fixture 的 `monkeypatch.setenv` **之前**。而守卫是 `if expected_arn and sm_arn != expected_arn`，空串直接短路，于是"外来状态机必须被拒"这条纵深防线成了**永不被验证的死代码**（正是本项目"验证本身无效"的同一类问题）。写成 `_state_machine_arn()` 函数，`handler` 与 `sweeper_handler` 都走它（sweeper 在循环外取一次复用）。

- [ ] **Step 1: 写失败测试（收敛矩阵）**

创建 `site-builder/deployer/tests/test_reconcile_job.py`：

```python
"""SFN 终态收敛：EventBridge 实时层 + sweeper 兜底层。

**这些用例必须能在缺陷存在时变红**（本项目两次"验证本身无效"的教训）：
Step 2 会先确认它们全部 FAIL，Step 4 才确认转绿。
"""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest

import reconcile_job


def _put_job(status="RUNNING", phase="package", job_id="job-r1", site_id="s1"):
    now = datetime.now(timezone.utc).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "u@x.com",
            "status": status, "phase": phase, "error": "", "url": "",
            "created_at": now, "updated_at": now})


def _get_job(job_id="job-r1"):
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").get_item(Key={"job_id": job_id}).get("Item")


def _event(status="TIMED_OUT", job_id="job-r1",
           sm="arn:aws:states:us-east-1:1:stateMachine:site-deploy"):
    """真实 EventBridge Step Functions status-change 事件形态。

    job_id 只从 executionArn 的 name 段取——**不从 input 取**（input 是
    调用方可控的不可信数据，且可能被改写）。
    """
    return {"detail-type": "Step Functions Execution Status Change",
            "detail": {"status": status,
                       "stateMachineArn": sm,
                       "executionArn": f"arn:aws:states:us-east-1:1:execution:site-deploy:{job_id}",
                       "input": json.dumps({"job_id": "job-ATTACKER"})}}


@pytest.mark.parametrize("status", ["TIMED_OUT", "ABORTED"])
def test_running_converges_to_failed(aws, status):
    _put_job(status="RUNNING", phase="package")
    out = reconcile_job.handler(_event(status), None)
    assert out["outcome"] == "converged"
    job = _get_job()
    assert job["status"] == "FAILED"
    assert job["phase"] == "package", "必须保留最后 phase"
    assert job["error"], "必须写入固定 error 文案"
    assert "ATTACKER" not in json.dumps(job)


@pytest.mark.parametrize("phase", ["submitted", "queued", "validate",
                                   "provision-db", "package", "deploy-backend",
                                   "upload-frontend", "register-route",
                                   "smoke-test"])
def test_converges_from_any_phase(aws, phase):
    """timeout/abort 可发生在任意 phase——不得带 phase=queued 条件。"""
    _put_job(status="RUNNING", phase=phase)
    assert reconcile_job.handler(_event(), None)["outcome"] == "converged"
    assert _get_job()["status"] == "FAILED"


@pytest.mark.parametrize("terminal", ["SUCCEEDED", "FAILED", "DELETED"])
def test_terminal_status_is_noop(aws, terminal):
    _put_job(status=terminal, phase="smoke-test")
    assert reconcile_job.handler(_event(), None)["outcome"] == "noop"
    assert _get_job()["status"] == terminal, "终态不得被覆盖"


def test_absent_job_is_not_created(aws):
    """job 不存在只记日志，**绝不能凭空创建**（UpdateItem 默认会 upsert）。"""
    assert reconcile_job.handler(_event(job_id="job-ghost"), None)["outcome"] == "absent"
    assert _get_job("job-ghost") is None


def test_duplicate_event_is_idempotent(aws):
    _put_job(status="RUNNING")
    first = reconcile_job.handler(_event(), None)
    updated_at = _get_job()["updated_at"]
    second = reconcile_job.handler(_event(), None)
    assert (first["outcome"], second["outcome"]) == ("converged", "noop")
    assert _get_job()["updated_at"] == updated_at, "重复事件不得再写"


def test_out_of_order_event_does_not_clobber_success(aws):
    """乱序：SUCCEEDED 先落库，迟到的 ABORTED 事件不得把它改成 FAILED。"""
    _put_job(status="SUCCEEDED", phase="smoke-test")
    assert reconcile_job.handler(_event("ABORTED"), None)["outcome"] == "noop"
    assert _get_job()["status"] == "SUCCEEDED"


def test_foreign_state_machine_is_rejected(aws):
    """rule 已按 ARN 过滤，但 handler 自己也要核对（纵深）。"""
    _put_job(status="RUNNING")
    out = reconcile_job.handler(
        _event(sm="arn:aws:states:us-east-1:1:stateMachine:other-sm"), None)
    assert out["outcome"] == "ignored"
    assert _get_job()["status"] == "RUNNING"


# ---- sweeper 兜底层 ----

def _stale_job(job_id, minutes, status="RUNNING"):
    t = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": "s1", "owner": "u@x.com",
            "status": status, "phase": "package", "error": "", "url": "",
            "created_at": t, "updated_at": t})


def test_sweeper_converges_stale_running_with_terminal_execution(aws):
    _stale_job("job-stale1", 60)
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "TIMED_OUT"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 1
    assert _get_job("job-stale1")["status"] == "FAILED"


def test_sweeper_skips_fresh_jobs(aws):
    """未超龄的 RUNNING 不碰——它可能正在正常部署。"""
    _stale_job("job-fresh", 5)
    sfn = MagicMock()
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["scanned"] == 0 and out["converged"] == 0
    sfn.describe_execution.assert_not_called()
    assert _get_job("job-fresh")["status"] == "RUNNING"


def test_sweeper_leaves_still_running_execution_alone(aws):
    _stale_job("job-longrun", 60)
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "RUNNING"}
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["converged"] == 0
    assert _get_job("job-longrun")["status"] == "RUNNING"


def test_sweeper_reports_orphan_without_guessing(aws):
    """找不到 execution → 计入 orphans 并记日志，**不猜终态**。"""
    import botocore.exceptions
    _stale_job("job-orphan", 60)
    sfn = MagicMock()
    sfn.describe_execution.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExecutionDoesNotExist"}}, "DescribeExecution")
    with patch.object(reconcile_job, "_sfn", return_value=sfn):
        out = reconcile_job.sweeper_handler({}, None)
    assert out["orphans"] == 1 and out["converged"] == 0
    assert _get_job("job-orphan")["status"] == "RUNNING", "不得猜测终态"
```

- [ ] **Step 2: 运行测试确认全部失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_reconcile_job.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'reconcile_job'`（全部用例 error）

- [ ] **Step 3: 实现 `reconcile_job.py`**

创建 `site-builder/deployer/functions/reconcile_job.py`：

```python
"""SFN 终态收敛：让 TIMED_OUT / ABORTED 的 job 不再永久停在 RUNNING。

**缺口**：状态机整体 TimeoutSeconds 到点（TIMED_OUT）与人工 StopExecution
（ABORTED）**不执行任何 State**——add_catch 只覆盖步骤内失败，所以 mark_job
不被调用，job 永久 RUNNING。而 confirm_upload 只接受 PENDING，用户既看不到
结果也无法重试。

**两层收敛**（缺一不算闭合）：
  ① 实时层 handler()：EventBridge Step Functions status-change 事件。秒级。
  ② 兜底层 sweeper_handler()：定时扫超龄 RUNNING + DescribeExecution 核对。
Step Functions 的状态变化事件是 **best-effort**（AWS 不保证投递），单靠 ①
会漏；单靠 ② 最坏要等一个调度周期。两层共用 converge_job_to_failed，
收敛语义只有一份。
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
import botocore.exceptions

import common

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 只收敛本状态机的执行——rule 已按 ARN 过滤，handler 再核一次（纵深）。
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")

# 终态：这些状态的 job 不得被覆盖。
TERMINAL = ("SUCCEEDED", "FAILED", "DELETED")

# sweeper 的超龄阈值：状态机 TimeoutSeconds=1800（30 分钟）+ 余量。
STALE_MINUTES = 45

# **固定、无敏感信息**的 error 文案：事件里的 input / cause 可能含用户数据或
# 内部 ARN，一律不落库。
TIMEOUT_ERROR = ("部署执行超时已被系统终止（超过 30 分钟上限）。"
                 "请重新发起一次部署（会生成新任务）。")
ABORT_ERROR = ("部署执行已被中止。请重新发起一次部署（会生成新任务）。")
_REASON_ERROR = {"TIMED_OUT": TIMEOUT_ERROR, "ABORTED": ABORT_ERROR,
                 "FAILED": ABORT_ERROR}

_sfn_client = None


def _sfn():
    global _sfn_client
    if _sfn_client is None:
        _sfn_client = boto3.client(
            "stepfunctions",
            region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _sfn_client


def _ddb():
    return boto3.client(
        "dynamodb", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def converge_job_to_failed(job_id: str, *, reason: str) -> str:
    """把停在 RUNNING 的 job 条件收敛为 FAILED。返回 converged/noop/absent。

    条件三条，缺一不可：
      · attribute_exists(job_id) —— UpdateItem 默认是 upsert，缺这条会给一个
        不存在的 job_id **凭空建行**（伪造/迟到事件即可污染 jobs 表）；
      · #s = :running —— 终态不得被覆盖（乱序/重复事件幂等靠它）；
      · **不带 phase 条件** —— timeout/abort 可发生在任意 phase，照抄
        _rollback_job_to_pending 的 phase=queued 会让绝大多数场景收敛失败。

    保留最后 phase（诊断用），只改 status / error / updated_at。
    """
    error = _REASON_ERROR.get(reason, ABORT_ERROR)
    try:
        _ddb().update_item(
            TableName=os.environ["JOBS_TABLE"],
            Key={"job_id": {"S": job_id}},
            UpdateExpression="SET #s = :failed, #e = :err, updated_at = :t",
            ConditionExpression=("attribute_exists(job_id) AND #s = :running"),
            ExpressionAttributeNames={"#s": "status", "#e": "error"},
            ExpressionAttributeValues={
                ":failed": {"S": "FAILED"}, ":running": {"S": "RUNNING"},
                ":err": {"S": error},
                ":t": {"S": datetime.now(timezone.utc).isoformat()}})
        logger.info(f'{{"event":"job_converged","job_id":"{job_id}",'
                    f'"reason":"{reason}"}}')
        return "converged"
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise    # 真错误要冒出去，让 Lambda retry / DLQ 生效
        # 条件失败有两种原因，需要分辨（否则"不存在"会被当成"已终态"而静默）
        item = _ddb().get_item(TableName=os.environ["JOBS_TABLE"],
                               Key={"job_id": {"S": job_id}},
                               ConsistentRead=True).get("Item")
        if not item:
            logger.info(f'{{"event":"job_absent","job_id":"{job_id}",'
                        f'"reason":"{reason}"}}')
            return "absent"
        logger.info(f'{{"event":"job_already_terminal","job_id":"{job_id}",'
                    f'"status":"{item.get("status", {}).get("S", "")}"}}')
        return "noop"


def _job_id_from_execution_arn(arn: str) -> str:
    """execution ARN 的最后一段就是 execution name，当前约定 name == job_id。

    **不从 event["detail"]["input"] 取 job_id**：input 是提交方可控的数据，
    伪造/被改写的 input 能让收敛写到别人的 job 上。ARN 由 Step Functions
    服务自己填，且 rule 已按 stateMachineArn 过滤。
    """
    return arn.rsplit(":", 1)[-1] if arn else ""


def handler(event, context):
    """实时层：EventBridge Step Functions Execution Status Change。"""
    detail = event.get("detail") or {}
    status = detail.get("status", "")
    sm_arn = detail.get("stateMachineArn", "")
    job_id = _job_id_from_execution_arn(detail.get("executionArn", ""))

    if STATE_MACHINE_ARN and sm_arn != STATE_MACHINE_ARN:
        logger.warning(f'{{"event":"foreign_state_machine","arn":"{sm_arn}"}}')
        return {"job_id": job_id, "outcome": "ignored"}
    if status not in ("TIMED_OUT", "ABORTED"):
        return {"job_id": job_id, "outcome": "ignored"}
    if not job_id:
        logger.error('{"event":"missing_execution_arn"}')
        return {"job_id": "", "outcome": "ignored"}
    return {"job_id": job_id, "outcome": converge_job_to_failed(job_id,
                                                                reason=status)}


def sweeper_handler(event, context):
    """兜底层：扫超龄 RUNNING job，按 DescribeExecution 的真实状态收敛。

    分页安全、串行处理（站点量级下不需要并发；无界并发会打爆 SFN 的
    DescribeExecution 限流）。找不到 execution 时**不猜终态**——只计 orphan
    并打 ERROR 日志（进告警面）。
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=STALE_MINUTES)).isoformat()
    table = common._table("JOBS_TABLE")
    scanned = converged = orphans = 0
    start_key = None
    while True:
        kwargs = {
            "FilterExpression": "#s = :running AND updated_at < :cutoff",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": "RUNNING",
                                          ":cutoff": cutoff},
            "ProjectionExpression": "job_id",
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            job_id = item["job_id"]
            arn = f"{STATE_MACHINE_ARN.replace(':stateMachine:', ':execution:')}:{job_id}"
            try:
                ex_status = _sfn().describe_execution(
                    executionArn=arn)["status"]
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("ExecutionDoesNotExist", "ValidationException"):
                    orphans += 1
                    logger.error(f'{{"event":"job_running_without_execution",'
                                 f'"job_id":"{job_id}"}}')
                    continue
                raise
            if ex_status in ("TIMED_OUT", "ABORTED", "FAILED"):
                if converge_job_to_failed(job_id, reason=ex_status) == "converged":
                    converged += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    logger.info(f'{{"event":"sweep_done","scanned":{scanned},'
                f'"converged":{converged},"orphans":{orphans}}}')
    return {"scanned": scanned, "converged": converged, "orphans": orphans}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_reconcile_job.py -q`
Expected: PASS（**22** 个用例：2 + 9 + 3 + 1 + 1 + 1 + 1 + 4 sweeper = 22——早先写 21 是算术笔误）

- [ ] **Step 5: 反向验证——确认测试在缺陷存在时会红**

三处各改一次，每次跑测试确认 FAIL，然后**还原**：

1. 把 `ConditionExpression` **整条**删掉（并同步删掉随之不再被引用的
   `:running` 值，否则 DynamoDB 先报 `ValidationException:
   ExpressionAttributeValues unused`——那是变异操作的假象而不是缺陷信号）→
   Run: `.venv/bin/pytest tests/test_reconcile_job.py::test_absent_job_is_not_created -q`
   Expected: **FAIL**（`assert 'converged' == 'absent'`，凭空建了 job）

   **不要只删 `attribute_exists(job_id) AND `**（Task 1 实施期实测修正）：
   剩下的 `#s = :running` 在 item 不存在时比较缺失属性 → 条件求值 false →
   条件检查照样失败，upsert 不发生，用例仍然 **PASS**。即防"凭空建行"的
   承重条件是 `#s = :running`，`attribute_exists(job_id)` 是冗余的第二道锁
   （保留它有价值：将来有人把 `#s = :running` 改宽或删掉时它仍能挡住 upsert）
   ——但**不能把它当成被单测覆盖的防线**。
2. 在 `ConditionExpression` 末尾加 ` AND phase = :queued`（并加对应 value）→
   Run: `.venv/bin/pytest tests/test_reconcile_job.py::test_converges_from_any_phase -q`
   Expected: **FAIL**（除 queued 外 8 个 phase 全部收敛失败）
3. 把 `_job_id_from_execution_arn` 改成从 `input` 读 job_id →
   Run: `.venv/bin/pytest tests/test_reconcile_job.py::test_running_converges_to_failed -q`
   Expected: **FAIL**（写到了 `job-ATTACKER`）

三处还原后重跑全套确认 PASS。

- [ ] **Step 6: 运行 deployer 全量回归**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS（原有 222+8skip 基线 + 21 新增；无回归）

- [ ] **Step 7: Commit**

```bash
git add site-builder/deployer/functions/reconcile_job.py \
        site-builder/deployer/tests/test_reconcile_job.py
bash site-builder/scripts/scan_staged_secrets.sh --files \
  site-builder/deployer/functions/reconcile_job.py \
  site-builder/deployer/tests/test_reconcile_job.py || exit 1
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "feat(deployer): SFN 终态两层收敛逻辑（reconciler + sweeper）

TIMED_OUT/ABORTED 不执行任何 State，mark_job 不被调用 → job 永久停
RUNNING 且 confirm_upload 只收 PENDING 导致无法重试。

两层收敛（SFN 状态变化事件是 best-effort，单层不算闭合）：
- 实时层：EventBridge 事件，job_id 只从 execution ARN 取（不信 input）
- 兜底层：sweeper 扫超龄 RUNNING + DescribeExecution 核对，orphan 不猜终态

条件更新不带 phase=queued（timeout/abort 可发生在任意 phase），
带 attribute_exists(job_id) 作为纵深第二道锁。22 个用例含反向验证。"
```

---

## Task 2: reconciler 的 CDK 定义与真机验收

**Files:**
- Modify: `site-builder/deployer/infra/app.py`（新增 reconciler/sweeper Lambda + 独立角色 + EventBridge rule + Scheduler + SQS DLQ）
- Create: `site-builder/deployer/tests/test_infra_reconciler.py`
- Modify: `site-builder/scripts/verify_sfn_failure_paths.py`（扩两段）

**Interfaces:**
- Consumes: Task 1 的 `reconcile_job.handler` / `reconcile_job.sweeper_handler`；`app.py` 里已有的 `jobs` 表与 `sm`（状态机）对象
- Produces:
  - Lambda `site-deployer-reconcile-job`（handler `reconcile_job.handler`）
  - Lambda `site-deployer-sweep-jobs`（handler `reconcile_job.sweeper_handler`）
  - IAM role `site-deployer-reconciler-role`（**独立窄角色**，不用 exec_role）
  - EventBridge rule `site-deploy-terminal-status`
  - Scheduler/Rule `site-deploy-job-sweep`（rate 30 分钟）
  - SQS queue `site-deployer-reconcile-dlq`

**为什么独立角色**：exec_role 有 `dynamodb:*` on `site-*`、`iam:*` on `site-rt-*`、Lambda 建删权限——reconciler 只需要 jobs 表条件更新 + DescribeExecution + 自身日志。复用 exec_role 等于给一个由**外部事件触发**的函数配上整个部署链的权限面。

- [ ] **Step 1: 写 CDK 断言测试**

创建 `site-builder/deployer/tests/test_infra_reconciler.py`：

```python
"""reconciler/sweeper 的 CDK 模板断言。

与 test_infra_tables.py 同机制：默认 skip，要真跑需
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1
（aws_cdk 只装在 infra/.venv；不带 PYTHONPATH 会报错而非静默 skip）
"""
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("SB_CDK_TESTS"),
                                reason="需要 SB_CDK_TESTS=1 与 infra/.venv 的 aws_cdk")


@pytest.fixture(scope="module")
def template():
    sys.path.insert(0, str(Path(__file__).parents[1] / "infra"))
    from aws_cdk import App, Environment
    from aws_cdk.assertions import Template
    import app as infra_app
    a = App()
    stack = infra_app.SiteDeployerStack(
        a, "T", env=Environment(account="000000000000", region="us-east-1"))
    return Template.from_stack(stack)


def _resources(template, kind):
    return template.find_resources(kind)


def test_rule_matches_only_terminal_statuses_of_this_state_machine(template):
    rules = _resources(template, "AWS::Events::Rule")
    terminal = [r for r in rules.values()
                if "TIMED_OUT" in str(r["Properties"].get("EventPattern", ""))]
    assert len(terminal) == 1, "应有且仅有一条终态 rule"
    pattern = terminal[0]["Properties"]["EventPattern"]
    detail = pattern["detail"]
    assert set(detail["status"]) == {"TIMED_OUT", "ABORTED"}, \
        "只匹配 TIMED_OUT/ABORTED——FAILED 已由 add_catch→MarkFailed 覆盖，" \
        "重复收敛会把 mark_job 写的真实错因覆盖成通用文案"
    assert "stateMachineArn" in detail, "必须按状态机 ARN 过滤，不能收全账号事件"
    assert pattern["source"] == ["aws.states"]


def test_rule_target_has_dlq_and_retry(template):
    rules = _resources(template, "AWS::Events::Rule")
    terminal = [r for r in rules.values()
                if "TIMED_OUT" in str(r["Properties"].get("EventPattern", ""))][0]
    targets = terminal["Properties"]["Targets"]
    assert len(targets) == 1
    t = targets[0]
    assert "DeadLetterConfig" in t, "投递失败必须进 DLQ，否则事件静默丢失"
    retry = t.get("RetryPolicy", {})
    assert retry.get("MaximumRetryAttempts", 0) >= 2


def test_sweeper_schedule_is_every_30_minutes(template):
    rules = _resources(template, "AWS::Events::Rule")
    sched = [r for r in rules.values()
             if "rate(30 minutes)" == r["Properties"].get("ScheduleExpression")]
    assert len(sched) == 1, "sweeper 必须有 30 分钟定时触发"


def _narrow_policy(template):
    policies = _resources(template, "AWS::IAM::Policy")
    recon = [p for p in policies.values()
             if "states:DescribeExecution" in str(p["Properties"])]
    assert len(recon) == 1, "reconciler 应有独立的 inline policy"
    return recon[0]


def test_reconciler_functions_actually_use_the_narrow_role(template):
    """两个 reconciler 函数**真的挂在**那个窄角色上。

    **这条不能省**（Task 2 实施期实测）：只断言"窄 policy 存在"挡不住本任务
    最可能的退化方式——把 `role=recon_role` 改回 `role=exec_role` 时，
    `recon_role` 构造仍在、窄 policy 照样 synth 出来，于是
    `test_reconciler_role_is_narrow` 照样绿，而两个函数已经挂上了带
    `dynamodb:*` / `iam:*` / Lambda 建删的 exec_role。
    从窄 policy 的 Roles 反查角色逻辑 ID 再比对函数的 Role——不写死 CDK
    生成的哈希后缀，也不写死字面量 ARN。
    """
    role_refs = _narrow_policy(template)["Properties"]["Roles"]
    assert len(role_refs) == 1
    role_lid = role_refs[0]["Ref"]
    fns = {f["Properties"].get("FunctionName"): f["Properties"]["Role"]
           for f in _resources(template, "AWS::Lambda::Function").values()
           if isinstance(f["Properties"].get("FunctionName"), str)}
    for name in ("site-deployer-reconcile-job", "site-deployer-sweep-jobs"):
        assert fns.get(name) == {"Fn::GetAtt": [role_lid, "Arn"]}, \
            f"{name} 没有用窄角色（很可能被改回了 exec_role）"


def test_reconciler_role_is_narrow(template):
    """不得复用 exec_role：只允许 jobs 表条件更新 + DescribeExecution + 日志。"""
    doc = str(_narrow_policy(template)["Properties"]["PolicyDocument"])
    for forbidden in ("iam:CreateRole", "iam:PutRolePolicy",
                      "lambda:CreateFunction", "codebuild:StartBuild",
                      "dsql:DbConnectAdmin", "s3:PutObject",
                      "dynamodb:DeleteItem", "dynamodb:PutItem"):
        assert forbidden not in doc, f"reconciler 角色不得有 {forbidden}"
    assert "dynamodb:UpdateItem" in doc and "dynamodb:GetItem" in doc
    assert "site-sites" not in doc, "reconciler 不需要 sites 表"


def test_reconciler_functions_exist_with_right_handlers(template):
    fns = _resources(template, "AWS::Lambda::Function")
    handlers = {f["Properties"].get("FunctionName"): f["Properties"]["Handler"]
                for f in fns.values() if isinstance(
                    f["Properties"].get("FunctionName"), str)}
    assert handlers.get("site-deployer-reconcile-job") == "reconcile_job.handler"
    assert handlers.get("site-deployer-sweep-jobs") == "reconcile_job.sweeper_handler"


def test_dlq_exists(template):
    assert _resources(template, "AWS::SQS::Queue"), "必须有 DLQ"
```

- [ ] **Step 2: 运行确认失败**

Run:
```bash
cd site-builder/deployer && \
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_reconciler.py -q
```
Expected: FAIL —— 全部用例红（无 Events::Rule、无 SQS、handler 不存在）

- [ ] **Step 3: 在 `infra/app.py` 加 reconciler 定义**

在 `app.py` 顶部 import 增加 `aws_events as events, aws_events_targets as targets, aws_sqs as sqs`；在 `sm = sfn.StateMachine(...)` **之后**（需要 `sm.state_machine_arn`）插入：

```python
        # ---- M3 前置 B1：SFN 终态两层收敛 ----
        # 缺口：状态机级 TimeoutSeconds 到点（TIMED_OUT）与人工 StopExecution
        # （ABORTED）**不执行任何 State**——add_catch 只覆盖步骤内失败，于是
        # mark_job 不被调用、job 永久停在 RUNNING，而 confirm_upload 只接受
        # PENDING，用户既看不到结果也无法重试。
        #
        # 为什么两层：Step Functions 的状态变化事件是 **best-effort**（AWS 不
        # 保证投递），只挂一条 EventBridge rule 不算闭合。sweeper 定时用
        # DescribeExecution 兜底。
        #
        # **独立窄角色，不用 exec_role**：exec_role 有 dynamodb:* on site-*、
        # iam:* on site-rt-*、Lambda 建删权限。reconciler 由外部事件触发，
        # 只需要 jobs 表条件更新 + DescribeExecution + 自身日志。
        recon_role = iam.Role(
            self, "ReconcilerRole", role_name="site-deployer-reconciler-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        recon_role.add_to_policy(iam.PolicyStatement(
            # 只读 + 条件更新 jobs 表。**不给 PutItem/DeleteItem**：收敛只改
            # 已存在行的 status/error/updated_at，给 PutItem 就等于允许凭空建行。
            actions=["dynamodb:GetItem", "dynamodb:UpdateItem",
                     "dynamodb:Scan"],
            resources=[jobs.table_arn]))
        recon_role.add_to_policy(iam.PolicyStatement(
            actions=["states:DescribeExecution"],
            resources=[f"arn:aws:states:{REGION}:{ACCOUNT}:execution:"
                       f"{sm.state_machine_name}:*"]))

        recon_env = {"JOBS_TABLE": jobs.table_name,
                     "STATE_MACHINE_ARN": sm.state_machine_arn}

        def recon_fn(cid: str, fn_name: str, handler: str) -> lam_.Function:
            # 与 step_fn 不同：不需要 psycopg/contract，纯标准库 + boto3。
            # 用 from_asset 直接打包 functions/ 目录（reconcile_job 只 import
            # common，同目录）。
            return lam_.Function(
                self, cid, function_name=fn_name,
                runtime=lam_.Runtime.PYTHON_3_13, handler=handler,
                code=lam_.Code.from_asset(fn_dir),
                role=recon_role, timeout=Duration.seconds(60),
                memory_size=256, environment=recon_env)

        f_recon = recon_fn("FnReconcile", "site-deployer-reconcile-job",
                           "reconcile_job.handler")
        f_sweep = recon_fn("FnSweepJobs", "site-deployer-sweep-jobs",
                           "reconcile_job.sweeper_handler")

        dlq = sqs.Queue(self, "ReconcileDlq",
                        queue_name="site-deployer-reconcile-dlq",
                        retention_period=Duration.days(14))

        # rule 只匹配**本状态机**的 TIMED_OUT / ABORTED。
        # 不匹配 FAILED：那条路径已由每个 Task 的 add_catch → MarkFailed 覆盖，
        # 重复收敛会把 mark_job 写入的真实错因覆盖成通用文案。
        events.Rule(
            self, "TerminalStatusRule", rule_name="site-deploy-terminal-status",
            event_pattern=events.EventPattern(
                source=["aws.states"],
                detail_type=["Step Functions Execution Status Change"],
                detail={"status": ["TIMED_OUT", "ABORTED"],
                        "stateMachineArn": [sm.state_machine_arn]}),
            targets=[targets.LambdaFunction(
                f_recon, dead_letter_queue=dlq,
                retry_attempts=2,
                max_event_age=Duration.hours(2))])

        # 兜底层：30 分钟一轮（超龄阈值 45 分钟 = 状态机 30 分钟上限 + 余量，
        # 见 reconcile_job.STALE_MINUTES）。
        events.Rule(
            self, "JobSweepRule", rule_name="site-deploy-job-sweep",
            schedule=events.Schedule.rate(Duration.minutes(30)),
            targets=[targets.LambdaFunction(
                f_sweep, dead_letter_queue=dlq, retry_attempts=2)])

        CfnOutput(self, "ReconcileDlqUrl", value=dlq.queue_url)
```

**注意**：`recon_fn` 用不带 bundling 的 `from_asset(fn_dir)`——reconcile_job 只 import `common`（同目录）与运行时自带的 boto3/botocore，不需要 psycopg/sqlparse/contract 包。这与 `step_fn` 的 bundled asset 是两个不同 asset hash，互不影响。

- [ ] **Step 4: 运行 CDK 断言测试确认通过**

Run:
```bash
cd site-builder/deployer && \
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_reconciler.py -q
```
Expected: PASS（7 个断言函数）

- [ ] **Step 5: 反向验证 CDK 断言**

1. 把 rule 的 `detail` 里 `"stateMachineArn": [sm.state_machine_arn]` 删掉 →
   Expected: `test_rule_matches_only_terminal_statuses_of_this_state_machine` **FAIL**
2. 把两个 `recon_fn(...)` 调用里的 `role=recon_role` 改成 `role=exec_role` →
   Expected: `test_reconciler_functions_actually_use_the_narrow_role` **FAIL**
   （`AssertionError: … 没有用窄角色（很可能被改回了 exec_role）`），
   而 `test_reconciler_role_is_narrow` **仍然绿**——后者只验"窄 policy 存在"，
   `recon_role` 构造还在就照样 synth 出来。**这个绿本身就是缺陷信号**，
   正是必须加第 4 条断言的原因（Task 2 实施期实测）。
   另一形态（`recon_role = exec_role` 整体别名掉）不会给出干净的断言失败，
   而是 CDK 自己抛 `Template is undeployable … dependency cycle`
   （reconciler policy 加到 exec_role 上会把状态机拉进环）——那是"撞墙即拦"，
   证明不了断言有效性，不要用它做反向验证。
3. 把 `dead_letter_queue=dlq` 删掉 →
   Expected: `test_rule_target_has_dlq_and_retry` **FAIL**

三处还原，重跑 PASS。

- [ ] **Step 6: synth 确认模板可生成**

Run: `cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest synth > /dev/null && echo SYNTH_OK`
Expected: `SYNTH_OK`（需要 Docker——step_fn 的 bundling）

- [ ] **Step 7: Commit（部署前先提交代码）**

```bash
git add site-builder/deployer/infra/app.py \
        site-builder/deployer/tests/test_infra_reconciler.py
bash site-builder/scripts/scan_staged_secrets.sh --files \
  site-builder/deployer/tests/test_infra_reconciler.py || exit 1
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "feat(deployer): reconciler/sweeper 的 CDK 定义（rule/schedule/DLQ/窄角色）

rule 只匹配本状态机的 TIMED_OUT/ABORTED（FAILED 已由 add_catch 覆盖，
重复收敛会盖掉真实错因）；target 带 DLQ + retry；sweeper 30 分钟一轮。

reconciler 用独立窄角色而非 exec_role：只有 jobs 表 GetItem/UpdateItem/Scan
+ DescribeExecution + 自身日志，没有 PutItem（防凭空建行）、没有 sites 表、
没有 IAM/Lambda/CodeBuild/DSQL 权限。7 个 CDK 断言含反向验证。"
```

- [ ] **Step 8: [真机] 部署 deployer 栈**

**部署门禁**：Step 4-7 全绿 + synth 成功 + 已提交。

```bash
cd site-builder/deployer/infra && rm -rf cdk.out && \
  PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

Expected: `SiteDeployerStack: deploy succeeded`，输出含 `ReconcileDlqUrl`。

**回滚锚点**：部署前记录当前 8 个 Lambda 的 `CodeSha256`：
```bash
for f in validate provision_dynamodb provision_dsql package_backend \
         deploy_lambda_site upload_frontend register_route smoke_test mark_job undeploy; do
  aws lambda get-function-configuration --function-name "site-deployer-${f//_/-}" \
    --query '[FunctionName,CodeSha256,LastModified]' --output text 2>/dev/null
done | tee /tmp/deployer-sha-before.txt
```
**回滚方式**：`git revert` 本任务两个提交后重新 deploy（CDK 会删除新增的 rule/Lambda/DLQ）。reconciler 是纯增量组件，不改动主链任何一步——最坏情况是"收敛不生效"，回到 Task 1 之前的状态，不会让部署链变坏。

- [ ] **Step 9: [真机] 确认部署产物 == 源码**

```bash
aws lambda get-function --function-name site-deployer-reconcile-job \
  --query 'Code.Location' --output text | xargs curl -s -o /tmp/recon.zip
unzip -p /tmp/recon.zip reconcile_job.py > /tmp/recon-deployed.py
diff <(shasum -a 256 < /tmp/recon-deployed.py) \
     <(shasum -a 256 < site-builder/deployer/functions/reconcile_job.py) \
  && echo "PASS: 产物与源码字节一致"
```
Expected: `PASS: 产物与源码字节一致`

同时确认 rule 真的存在且 pattern 正确：
```bash
aws events describe-rule --name site-deploy-terminal-status \
  --query 'EventPattern' --output text | python3 -m json.tool
```
Expected: JSON 含 `"status": ["TIMED_OUT", "ABORTED"]` 与本状态机 ARN。

- [ ] **Step 10: 扩展 `verify_sfn_failure_paths.py` 两段**

在该脚本 `main()` 的现有 6 段之后追加两段（沿用其 `check()` / `SUFFIX` / `probe_jobs` 机制与"少于 N 项即判不可信"的下限）：

```python
    # ---- ⑦ 实时层：EventBridge reconciler 真机有效 ----
    # **用临时 execution，绝不 Stop 真实生产部署。**
    # 做法：起一条注定超时/被中止的探针 execution（name == 探针 job_id），
    # 然后 StopExecution 制造 ABORTED，观察 job 是否被收敛。
    probe_job = f"job-sfnprobe-recon-{SUFFIX}"
    probe_jobs.add(probe_job)
    jobs_tbl.put_item(Item={
        "job_id": probe_job, "site_id": f"probe-{SUFFIX}", "owner": "probe@invalid",
        "status": "RUNNING", "phase": "package",   # 非 queued：验任意 phase 都能收敛
        "error": "", "url": "", "created_at": now_iso(), "updated_at": now_iso()})
    # 输入刻意不合法（缺 manifest）→ Validate 会失败，但我们在它跑完前 Stop 它，
    # 得到的是 ABORTED（不是 FAILED），正是本层要覆盖的状态。
    ex = sfn.start_execution(stateMachineArn=sm_arn, name=probe_job,
                             input=json.dumps({"job_id": probe_job,
                                               "site_id": f"probe-{SUFFIX}"}))
    sfn.stop_execution(executionArn=ex["executionArn"], cause="probe")
    converged = _poll_job_status(jobs_tbl, probe_job, want="FAILED", timeout_s=120)
    check(converged, "EventBridge reconciler 收敛 ABORTED → FAILED",
          f"job={probe_job}")
    job = jobs_tbl.get_item(Key={"job_id": probe_job})["Item"]
    check(job.get("phase") == "package", "收敛保留最后 phase（非 queued）",
          f"phase={job.get('phase')}")
    check(bool(job.get("error")) and "arn:aws" not in job.get("error", ""),
          "error 文案固定且不含 ARN/敏感信息")

    # ---- ⑧ 兜底层：sweeper 真机有效 ----
    # 造一个"execution 已终态、job 仍 RUNNING"的状态：直接把上面那条探针 job
    # 改回 RUNNING（它的 execution 已经是 ABORTED），再手工触发 sweeper。
    jobs_tbl.update_item(
        Key={"job_id": probe_job},
        UpdateExpression="SET #s = :r, updated_at = :old",
        ExpressionAttributeNames={"#s": "status"},
        # updated_at 回拨到超龄之前，否则 sweeper 的 45 分钟阈值会跳过它
        ExpressionAttributeValues={":r": "RUNNING", ":old": stale_iso(60)})
    lam.invoke(FunctionName="site-deployer-sweep-jobs",
               InvocationType="RequestResponse", Payload=b"{}")
    swept = _poll_job_status(jobs_tbl, probe_job, want="FAILED", timeout_s=60)
    check(swept, "sweeper 收敛 execution 已终态但 job 仍 RUNNING 的缺口")

    # 未超龄的 RUNNING 不能被 sweeper 动（否则正在跑的真实部署会被误杀）
    fresh_job = f"job-sfnprobe-fresh-{SUFFIX}"
    probe_jobs.add(fresh_job)
    jobs_tbl.put_item(Item={
        "job_id": fresh_job, "site_id": f"probe-{SUFFIX}", "owner": "probe@invalid",
        "status": "RUNNING", "phase": "validate", "error": "", "url": "",
        "created_at": now_iso(), "updated_at": now_iso()})
    lam.invoke(FunctionName="site-deployer-sweep-jobs",
               InvocationType="RequestResponse", Payload=b"{}")
    still = jobs_tbl.get_item(Key={"job_id": fresh_job})["Item"]["status"]
    check(still == "RUNNING", "sweeper 不动未超龄的 RUNNING（防误杀在跑的部署）",
          f"status={still}")
```

同时把脚本头部的最小检查数下限从 6 提到 **12**（原 6 段 + 新 6 项）。需要新增两个小 helper：`_poll_job_status(table, job_id, *, want, timeout_s)` 轮询强一致读；`stale_iso(minutes)` 生成回拨时间戳。

- [ ] **Step 11: [真机] 跑扩展后的验收脚本**

Run: `./site-builder/scripts/verify_sfn_failure_paths.py`
Expected: `12/12 项通过`，探针数据清理后读回核对为空。

- [ ] **Step 12: Commit**

```bash
git add site-builder/scripts/verify_sfn_failure_paths.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "test(scripts): verify_sfn_failure_paths 覆盖两层收敛（6→12 项）

⑦ EventBridge 实时层：探针 execution + StopExecution 造 ABORTED，验收敛、
   保留非 queued 的 phase、error 文案不含 ARN
⑧ sweeper 兜底层：造\"execution 已终态 job 仍 RUNNING\"缺口验收敛，
   并验未超龄的 RUNNING 不被误杀

用临时 execution 与探针 job，不 Stop 任何真实生产部署。最小检查数下限 6→12。"
```

---

## Task 3: 告警管道的幂等声明式收敛逻辑

**Files:**
- Create: `site-builder/auth/alarm_pipeline.py`
- Create: `site-builder/auth/tests/test_alarm_pipeline.py`
- Modify: `site-builder/config.ini.example`（`[Alerting]` 段）
- Modify: `CLAUDE.md`（auth 测试 venv 注释：contract venv 需含 boto3）

**Interfaces:**
- Consumes: `config.ini` 的 `[Alerting] email`（gitignored）或环境变量 `SB_ALERT_EMAIL`
- Produces:
  - `ensure_alarm_pipeline(*, region, log_group, namespace, metric_name, filter_name, filter_pattern, topic_name, alarm_name, email, account_id) -> dict`
    —— 返回 `{"topic_arn", "subscription_state", "alarm_name", "changed": [...]}`；`subscription_state` ∈ `{"confirmed", "pending", "absent"}`
  - `ALARM_DESCRIPTION` —— 中英双语 AlarmDescription 常量
  - `ALARM_PARAMS` —— 阈值参数常量（Sum/300/2/1/GreaterThanOrEqualToThreshold/notBreaching）

**为什么真源选 `deploy_auth.py` 而不是 CDK**：告警监控的就是 `deploy_auth.py` 部署的那个 Lambda 的日志组，同一脚本声明全部配套资源、生命周期一致；CDK 方案要跨体系引用日志组、email 还得新开 context 通道并会进 `cdk.out` 模板。**文档中不称其为 IaC**，称"幂等声明式 provisioning"。

**为什么必须自动化**：现网这套（metric filter + SNS topic + alarm + 双语描述 + Alarm/OK actions）是**手工建的**——只跑现有部署脚本不会收敛出它，"从零部署"得不到相同环境。

- [ ] **Step 0: 给 contract venv 补 boto3/botocore（auth 测试的宿主 venv）**

auth 测试借 `contract/.venv`（CLAUDE.md 约定），该 venv **只有 PyJWT 没有
boto3/botocore**（实测 `ModuleNotFoundError`）——本任务的 Stubber 测试会在
collection 阶段就挂掉（Codex 复审第二轮实测确认）。PyJWT 本身也不在 contract
的 pyproject 里，是当年为 auth 测试手工补进去的；boto3 照同一模式补：

```bash
site-builder/contract/.venv/bin/pip install -q 'boto3>=1.40' && \
site-builder/contract/.venv/bin/python -c "import boto3, botocore.stub; print('OK')"
```

Expected: `OK`。

同时更新 `CLAUDE.md` 测试命令一节的 auth 行注释：
`（auth 无自己的 venv，借 contract 的——含 pyjwt 与 boto3；重建该 venv 后两者都要手工重装）`。

- [ ] **Step 1: 写失败测试**

创建 `site-builder/auth/tests/test_alarm_pipeline.py`：

```python
"""告警管道的幂等声明式收敛。

用 botocore Stubber 而非 moto：需要精确断言"发出了哪些 API 调用、参数是
什么"（幂等性与配置漂移纠偏都是关于调用序列的），moto 的状态机模型看不到
这一层。
"""
import sys
from pathlib import Path

import boto3
import pytest
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(Path(__file__).parents[1]))
import alarm_pipeline


ARGS = dict(region="us-east-1", log_group="/aws/lambda/site-auth-service",
            namespace="SiteBuilder", metric_name="AuthInvalidGrant",
            filter_name="site-builder-auth-invalid-grant",
            filter_pattern='{ $.event = "token_exchange_invalid_grant" }',
            topic_name="site-builder-alarms",
            alarm_name="site-builder-auth-invalid-grant",
            account_id="000000000000")
TOPIC_ARN = "arn:aws:sns:us-east-1:000000000000:site-builder-alarms"


@pytest.fixture
def clients(monkeypatch):
    logs = boto3.client("logs", region_name="us-east-1",
                        aws_access_key_id="t", aws_secret_access_key="t")
    sns = boto3.client("sns", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    cw = boto3.client("cloudwatch", region_name="us-east-1",
                      aws_access_key_id="t", aws_secret_access_key="t")
    stubs = {"logs": Stubber(logs), "sns": Stubber(sns), "cw": Stubber(cw)}
    monkeypatch.setattr(alarm_pipeline, "_clients",
                        lambda region: (logs, sns, cw))
    for s in stubs.values():
        s.activate()
    yield logs, sns, cw, stubs
    for s in stubs.values():
        s.deactivate()


def _stub_common(stubs, *, subs, sub_result=None, fresh_account=False):
    """公共调用序列：建日志组（幂等）→ retention → metric filter → topic
    → 列订阅 → alarm。

    fresh_account=True 模拟全新账号：日志组不存在，create_log_group 成功；
    默认模拟现网：日志组已存在，create 抛 AlreadyExists 被吞。
    """
    if fresh_account:
        stubs["logs"].add_response("create_log_group", {})
    else:
        stubs["logs"].add_client_error("create_log_group",
                                       "ResourceAlreadyExistsException")
    stubs["logs"].add_response("put_retention_policy", {})
    stubs["logs"].add_response("put_metric_filter", {})
    stubs["sns"].add_response("create_topic", {"TopicArn": TOPIC_ARN})
    stubs["sns"].add_response("list_subscriptions_by_topic",
                              {"Subscriptions": subs})
    if sub_result is not None:
        stubs["sns"].add_response("subscribe", sub_result)
    stubs["cw"].add_response("put_metric_alarm", {})


def test_confirmed_subscription_is_not_recreated(clients):
    """已确认的订阅不得重复 subscribe（否则每次部署都给收件人发确认邮件）。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc-123"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "confirmed"
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_pending_confirmation_is_reported_as_incomplete(clients):
    """SubscriptionArn == 'PendingConfirmation' 必须显式报告为未完成——
    topic 有订阅但未确认时 alarm 照样进 ALARM 而无人知情。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": "PendingConfirmation"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "pending"


def test_missing_subscription_is_created_once(clients):
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[], sub_result={"SubscriptionArn": "PendingConfirmation"})
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "pending"
    assert "subscription" in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_alarm_params_match_current_environment(clients):
    """阈值必须与当前环境一致：Sum/300/2/1/GTE/notBreaching，
    且 ALARM 与 OK 通知同一 topic。

    走 _stub_common 而不是自铺调用序列：实现的调用序列变化（如新增日志组
    前置）时只改一处，否则本用例会 Operation mismatch（Codex 复审第二轮
    实际抓到：这里曾直接从 put_metric_filter 开始 stub，而实现第一个调用
    已是 create_log_group）。
    """
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    p = alarm_pipeline.ALARM_PARAMS
    assert p["Statistic"] == "Sum"
    assert p["Period"] == 300
    assert p["EvaluationPeriods"] == 2
    assert p["Threshold"] == 1
    assert p["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
    assert p["TreatMissingData"] == "notBreaching"


def test_alarm_description_is_bilingual_and_says_alarm_cleared(clients):
    """OK 文案统一「告警解除」：只表示指标不再满足阈值，规则仍启用，
    不代表根因确认修复。"""
    d = alarm_pipeline.ALARM_DESCRIPTION
    assert "告警解除" in d
    assert "仍启用" in d or "未被删除" in d
    assert "不代表根因" in d or "不代表根因已确认修复" in d
    assert "English" in d or "alarm condition cleared" in d.lower()


def test_alarm_and_ok_actions_use_same_topic(clients):
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email", "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["topic_arn"] == TOPIC_ARN


def test_empty_email_raises_instead_of_silently_skipping(clients):
    """email 缺失时必须响亮失败——静默跳过会造出一个没人收通知的 alarm。"""
    with pytest.raises(ValueError, match="email"):
        alarm_pipeline.ensure_alarm_pipeline(email="", **ARGS)


def test_fresh_account_creates_log_group_before_metric_filter(clients):
    """全新账号：/aws/lambda/<fn> 日志组在函数**第一次被调用**时才自动创建。
    刚 CreateFunction 完还没人调过 → 不先建组，put_metric_filter 直接
    ResourceNotFoundException（Codex review 2026-08-09：从零部署会失败在
    半部署状态）。Stubber 的顺序断言保证 create_log_group 在 filter 之前。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}],
                 fresh_account=True)
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert "log_group" in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_existing_log_group_still_converges_retention(clients):
    """现网路径：组已存在（AlreadyExists 被吞），retention 仍要收敛到 30 天
    （spec §6.3 平台日志组统一 30 天；现网曾是 90 天）。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert "log_group" not in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_alarm_pipeline.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alarm_pipeline'`

- [ ] **Step 3: 实现 `alarm_pipeline.py`**

创建 `site-builder/auth/alarm_pipeline.py`：

```python
"""登录失败告警管道的**唯一配置真源**（幂等声明式 provisioning）。

注意用词：这**不是 IaC**——没有状态文件、没有漂移检测、没有依赖图。它是一个
每次运行都把四样资源收敛到声明值的幂等脚本，与 deploy_auth.py 的其余部分同
模式。

为什么归 deploy_auth.py 而不是 CDK：告警监控的就是本脚本部署的那个 Lambda
的日志组，同一脚本声明全部配套资源、生命周期一致；CDK 要跨体系引用已存在的
日志组，email 还得新开 context 通道并且会进 cdk.out 模板。

为什么必须自动化：现网这套是**手工建的**——只跑部署脚本不会收敛出它，
"从零部署得到相同配置"这个要求不成立。收编方式是同名 upsert，从此
**只有一个 writer**。

`invalid_grant` 为什么值得告警：它既表示"用户重放授权码"（无害），也表示
"app client 缺少 scope 所需的属性读取权限"（**每个用户每次登录都失败**的
配置事故），两者在响应里无法可靠区分。唯一的发现手段是频率告警。
"""
import logging

import boto3

logger = logging.getLogger(__name__)

# 当前环境的阈值。改这里就是改线上——它是唯一真源。
ALARM_PARAMS = {
    "Statistic": "Sum",
    "Period": 300,
    "EvaluationPeriods": 2,
    "Threshold": 1.0,
    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
    "TreatMissingData": "notBreaching",
}

# 中英双语。**OK 一律称「告警解除」**：只表示指标不再满足阈值，告警规则仍然
# 启用，不代表根因已确认修复（notBreaching 意味着"没有数据"也会转 OK）。
ALARM_DESCRIPTION = (
    "【中文】Site Builder 登录授权码交换持续失败。触发条件：连续 2 个 5 分钟"
    "周期，每个周期 AuthInvalidGrant >= 1。可能影响：用户可能无法登录。"
    "常见原因：授权码过期/重放、Cognito App Client 属性读取权限或 "
    "OAuth client/grant/redirect URI 配置错误。ALARM=告警触发；"
    "OK=告警解除（仅表示指标不再满足阈值，告警规则仍启用，"
    "不代表根因已确认修复；缺失数据按 notBreaching 处理）。"
    "【English】Site Builder OAuth authorization-code exchanges are failing "
    "continuously. Threshold: AuthInvalidGrant >= 1 in each of 2 consecutive "
    "5-minute periods. ALARM=condition breached; OK=alarm condition cleared. "
    "The alarm remains enabled, and OK does not confirm root-cause resolution "
    "because missing data is treated as notBreaching.")


def _clients(region):
    return (boto3.client("logs", region_name=region),
            boto3.client("sns", region_name=region),
            boto3.client("cloudwatch", region_name=region))


def ensure_alarm_pipeline(*, region, log_group, namespace, metric_name,
                          filter_name, filter_pattern, topic_name, alarm_name,
                          email, account_id) -> dict:
    """把 metric filter / topic / subscription / alarm 收敛到声明值。

    返回 {"topic_arn", "subscription_state", "alarm_name", "changed"}。
    subscription_state ∈ {"confirmed", "pending", "absent"}——**pending 必须
    被调用方当作"未完成"报告**：topic 有未确认订阅时 alarm 照样进 ALARM
    而无人知情，那正是这套告警要防的盲区。
    """
    if not (email or "").strip():
        raise ValueError(
            "缺少告警通知 email——配置 [Alerting] email 或环境变量 "
            "SB_ALERT_EMAIL。不允许静默跳过：那会造出一个没人收通知的 alarm，"
            "比没有 alarm 更危险（会让人以为已有监控）。")
    logs, sns, cw = _clients(region)
    changed = []

    # ⓪ 日志组必须先存在：Lambda 的 /aws/lambda/<fn> 日志组在**函数第一次被
    # 调用**时才自动创建，不是 CreateFunction 时。全新账号跑 deploy_auth.py
    # 时函数刚建好还没被调过 → put_metric_filter 直接
    # ResourceNotFoundException，B2 部署失败且 auth Lambda 已被改动（半部署）。
    try:
        logs.create_log_group(logGroupName=log_group)
        changed.append("log_group")
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    # retention 收敛到 30 天（spec §6.3：平台日志组统一 30 天）。
    # ⚠️ 这是**有意的数据修剪**，不是无害配置：现网若是更长保留期（曾是
    # 90 天），超过 30 天的日志会被标记删除、约 72 小时内物理删除，事后调回
    # 也找不回。首次在存量环境运行前，部署方必须确认历史日志无保留需要
    # （deploy 门禁项，见 plan Task 4 Step 4）。
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=30)

    # ① metric filter：put 是 upsert 语义，直接声明即可
    logs.put_metric_filter(
        logGroupName=log_group, filterName=filter_name,
        filterPattern=filter_pattern,
        metricTransformations=[{"metricName": metric_name,
                                "metricNamespace": namespace,
                                "metricValue": "1",
                                "defaultValue": 0.0}])
    changed.append("metric_filter")

    # ② topic：create_topic 对已存在的同名 topic 返回其 ARN（幂等）
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]

    # ③ subscription：**先 list 再 subscribe**。无条件 subscribe 会在每次
    # 部署给收件人发一封确认邮件（已确认的订阅也会被再创建一条 pending）。
    state = "absent"
    paginator = sns.get_paginator("list_subscriptions_by_topic")
    existing = []
    for page in paginator.paginate(TopicArn=topic_arn):
        existing.extend(page.get("Subscriptions", []))
    mine = [s for s in existing
            if s.get("Protocol") == "email" and s.get("Endpoint") == email]
    if any(s.get("SubscriptionArn", "").startswith("arn:") for s in mine):
        state = "confirmed"
    elif mine:
        state = "pending"
    else:
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email,
                      ReturnSubscriptionArn=True)
        changed.append("subscription")
        state = "pending"    # email 订阅**必须由收件人手工点确认链接**

    # ④ alarm：put_metric_alarm 是 upsert。ALARM 与 OK 通知同一 topic。
    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription=ALARM_DESCRIPTION,
        Namespace=namespace, MetricName=metric_name,
        ActionsEnabled=True,
        AlarmActions=[topic_arn], OKActions=[topic_arn],
        **ALARM_PARAMS)
    changed.append("alarm")

    return {"topic_arn": topic_arn, "subscription_state": state,
            "alarm_name": alarm_name, "changed": changed}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_alarm_pipeline.py -q`
Expected: PASS（9 个用例）

- [ ] **Step 5: 反向验证**

1. 把 `if not (email or "").strip(): raise` 改成 `return {...}` 静默跳过 →
   Expected: `test_empty_email_raises_instead_of_silently_skipping` **FAIL**
2. 把"先 list 再 subscribe"改成无条件 `sns.subscribe(...)` →
   Expected: `test_confirmed_subscription_is_not_recreated` **FAIL**（Stubber 报未预期的 subscribe 调用）
3. 把 `ALARM_DESCRIPTION` 里"告警解除"改成"已恢复" →
   Expected: `test_alarm_description_is_bilingual_and_says_alarm_cleared` **FAIL**
4. 把 `create_log_group` / `put_retention_policy` 两行删掉 →
   Expected: `test_fresh_account_creates_log_group_before_metric_filter` **FAIL**
   （Stubber 报 create_log_group 响应未被消费）

四处还原，重跑 PASS。

- [ ] **Step 6: 在 `config.ini.example` 加 `[Alerting]` 段**

在 `site-builder/config.ini.example` 末尾追加：

```ini
# 告警通知收件人。**真实邮箱只写进 gitignored 的 config.ini，不进本文件。**
# 也可用环境变量 SB_ALERT_EMAIL 覆盖（CI 场景）。
#
# deploy_auth.py 会幂等收敛：metric filter → SNS topic → email 订阅 → alarm。
# ⚠️ email 订阅**必须由收件人手工点确认链接**——脚本只能创建订阅，
# 无法代为确认。未确认时 alarm 照样进 ALARM 而无人收到通知，
# 所以脚本会把 PendingConfirmation 显式报告为「未完成」。
[Alerting]
email =
```

- [ ] **Step 7: 运行 auth 全量回归**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`
Expected: PASS（原有 105 基线 + 9 新增）

- [ ] **Step 8: Commit**

```bash
git add site-builder/auth/alarm_pipeline.py \
        site-builder/auth/tests/test_alarm_pipeline.py \
        site-builder/config.ini.example
bash site-builder/scripts/scan_staged_secrets.sh --files \
  site-builder/auth/alarm_pipeline.py \
  site-builder/auth/tests/test_alarm_pipeline.py || exit 1
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "feat(auth): 登录失败告警的幂等声明式收敛（唯一真源）

现网 metric filter/topic/alarm 是手工建的——从零部署得不到相同配置。
ensure_alarm_pipeline() 把四样资源收敛到声明值，同名 upsert 收编现网资源，
从此只有一个 writer。刻意不称 IaC（无状态文件/漂移检测/依赖图）。

- 阈值集中在 ALARM_PARAMS：Sum/300/2/1/GTE/notBreaching
- 双语 AlarmDescription，OK 统一称「告警解除」（规则仍启用、不代表根因修复）
- subscription 先 list 后建（无条件 subscribe 会每次部署发确认邮件）
- PendingConfirmation 显式报「未完成」；email 缺失响亮失败不静默跳过
- email 从 gitignored config.ini [Alerting] 或 SB_ALERT_EMAIL 读"
```

---

## Task 4: 告警管道接入 `deploy_auth.py` 并真机验收

**Files:**
- Modify: `site-builder/auth/deploy_auth.py`（`main()` 末尾调用 + `[Alerting]` 读取 + 结果报告）
- Modify: `site-builder/scripts/verify_auth_alarm.sh`（加「线上配置 == 声明值」比对段 + confirmed subscription 检查）
- Modify: `site-builder/DEPLOY.md`（告警一节改写为自动收敛）

**Interfaces:**
- Consumes: Task 3 的 `ensure_alarm_pipeline` / `ALARM_PARAMS` / `ALARM_DESCRIPTION`
- Produces: `deploy_auth.py` 运行后线上四样资源与声明值一致；`verify_auth_alarm.sh` 的检查项从当前数量增加 5 项

- [ ] **Step 1: 在 `deploy_auth.py` 接入**

在 `deploy_auth.py` 顶部加 `import os` 与 `from alarm_pipeline import ensure_alarm_pipeline`；新增读取函数，并在 `main()` 的 `print(f"auth-service: ...")` **之前**插入调用：

```python
def _alert_email() -> str:
    """告警收件人：环境变量优先（CI），否则 config.ini [Alerting] email。

    **不能有默认值**：默认到某个邮箱是错的（发给不相关的人），默认到空串
    会让 ensure_alarm_pipeline 抛错——那正是我们要的响亮失败。
    """
    env = os.environ.get("SB_ALERT_EMAIL", "").strip()
    if env:
        return env
    if CFG.has_section("Alerting"):
        raw = CFG["Alerting"].get("email", "")
        return raw.split("#")[0].split(";")[0].strip()
    return ""
```

在 `main()` 里 `ensure_pre_token_trigger(role_arn)` 之后插入：

```python
    # 登录失败告警：**本脚本是唯一配置真源**（M3 前置 B2）。
    # 现网那套原本是手工建的；同名 upsert 收编，从此只有一个 writer。
    result = ensure_alarm_pipeline(
        region=REGION, log_group=f"/aws/lambda/{FN}",
        namespace="SiteBuilder", metric_name="AuthInvalidGrant",
        filter_name="site-builder-auth-invalid-grant",
        filter_pattern='{ $.event = "token_exchange_invalid_grant" }',
        topic_name="site-builder-alarms",
        alarm_name="site-builder-auth-invalid-grant",
        email=_alert_email(), account_id=CFG["Platform"]["account_id"])
    print(f"  告警管道已收敛：{', '.join(result['changed'])}")
    if result["subscription_state"] != "confirmed":
        # **不能只打印一行提示**：未确认的订阅意味着 alarm 会进 ALARM 而
        # 无人收到通知——那是这套告警要防的盲区本身。
        print(f"⚠️  email 订阅状态：{result['subscription_state']}"
              f"（**未完成**）——收件人必须点确认链接，否则告警无人知情。"
              f"确认后重跑本脚本或用 verify_auth_alarm.sh 核对。")
```

- [ ] **Step 2: 确认 auth 测试仍绿（接入不应破坏现有测试）**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`
Expected: PASS

- [ ] **Step 3: 在 `verify_auth_alarm.sh` 加配置比对段**

在该脚本现有检查之后追加（沿用其 `FAILURES` 计数与 trap 清理机制）：

```bash
# ── 正式 alarm 的配置必须与 alarm_pipeline.py 的声明值逐项一致 ──────────
# 为什么要比对而不只看"存在"：手工改过的 alarm 与脚本声明的可能已漂移，
# 而"存在"检查会全绿。真源只有一份，线上必须等于它。
PROD_ALARM="site-builder-auth-invalid-grant"
DECLARED="$(python3 - <<'PY'
import json, sys
sys.path.insert(0, "site-builder/auth")
from alarm_pipeline import ALARM_PARAMS, ALARM_DESCRIPTION
out = dict(ALARM_PARAMS)
out["AlarmDescription"] = ALARM_DESCRIPTION
print(json.dumps(out, sort_keys=True))
PY
)"
LIVE="$(aws cloudwatch describe-alarms --region "$REGION" \
          --alarm-names "$PROD_ALARM" --output json 2>/dev/null || echo '')"
# **aws CLI 在 API 错误时也可能 exit 0**（实测）——所以必须校验输出是合法 JSON
if ! printf '%s' "$LIVE" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  echo "  FAIL  无法读取线上 alarm（输出非合法 JSON，可能是凭证/网络问题）"
  FAILURES=$((FAILURES + 1))
else
  # $LIVE 作为 argv 传入复用——**不要在 python 里重新调 aws CLI**：那次重查
  # 不带 --region，会打到默认 region（与 config.ini 不同时报 0 个 alarm 的
  # 假失败，或比较到另一区域的同名 alarm；Codex 复审第二轮 P2）。
  # （不用 stdin 传：heredoc 已占用 stdin。）
  python3 - "$DECLARED" "$LIVE" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys
declared = json.loads(sys.argv[1])
live = json.loads(sys.argv[2])["MetricAlarms"]
if len(live) != 1:
    print(f"  FAIL  线上 alarm 数量为 {len(live)}，期望 1"); sys.exit(1)
a = live[0]
bad = []
for k, v in declared.items():
    got = a.get(k)
    if k == "Threshold":
        ok = float(got or 0) == float(v)
    else:
        ok = got == v
    if not ok:
        bad.append(f"{k}: 线上={got!r} 声明={v!r}")
# **AlarmActions/OKActions 必须等于声明的 topic ARN**——只验"两者相等且非空"
# 会漏掉"同时漂移到另一个 topic"的假绿：actions 指向 topic-B，而下面的订阅
# 检查在查 topic-A（site-builder-alarms），两段各自 PASS 但互不相干。
expected_topic = (f"arn:aws:sns:{a['AlarmArn'].split(':')[3]}:"
                  f"{a['AlarmArn'].split(':')[4]}:site-builder-alarms")
if a.get("AlarmActions") != [expected_topic]:
    bad.append(f"AlarmActions={a.get('AlarmActions')} 期望=[{expected_topic}]")
if a.get("OKActions") != [expected_topic]:
    bad.append(f"OKActions={a.get('OKActions')} 期望=[{expected_topic}]")
if bad:
    print("  FAIL  线上 alarm 与声明值漂移：")
    for b in bad:
        print(f"          {b}")
    sys.exit(1)
print("  PASS  线上 alarm 配置 == alarm_pipeline.py 声明值"
      "（含双语描述、Alarm/OK actions == 声明 topic）")
PY
fi

# ── SNS 订阅：**声明的那个收件人**必须已确认 ────────────────────────────
# 只查"存在任意 confirmed email"有假绿：告警邮箱从 old@ 换成 new@ 后，
# old 仍 confirmed、new 还在 PendingConfirmation——"存在 1 个 confirmed"
# 照样 PASS，而声明的新收件人收不到任何通知。必须绑定 Endpoint == 声明值。
DECLARED_EMAIL="$(SB_ALERT_EMAIL="${SB_ALERT_EMAIL:-}" python3 - <<'PY'
import configparser, os, sys
env = os.environ.get("SB_ALERT_EMAIL", "").strip()
if env:
    print(env); sys.exit(0)
c = configparser.ConfigParser(interpolation=None)
c.read("site-builder/config.ini")
raw = c["Alerting"].get("email", "") if c.has_section("Alerting") else ""
print(raw.split("#")[0].split(";")[0].strip())
PY
)"
TOPIC="$(aws sns create-topic --region "$REGION" --name site-builder-alarms \
           --query TopicArn --output text 2>/dev/null || echo '')"
if [ -z "$DECLARED_EMAIL" ]; then
  echo "  FAIL  无法读取声明的告警邮箱（[Alerting] email 或 SB_ALERT_EMAIL）"
  FAILURES=$((FAILURES + 1))
elif [ -z "$TOPIC" ] || [ "$TOPIC" = "None" ]; then
  echo "  FAIL  无法解析 SNS topic ARN"
  FAILURES=$((FAILURES + 1))
else
  # 分页完整：list-subscriptions-by-topic 单页 100 条，aws cli 不加
  # --no-paginate 时自动翻页，但 --query 的 length() 只作用于合并结果——
  # 用 json 输出交给 python 数，顺带把"状态"算清楚。
  SUB_STATE="$(aws sns list-subscriptions-by-topic --region "$REGION" \
                 --topic-arn "$TOPIC" --output json 2>/dev/null | \
               python3 -c "
import json, sys
declared = '''$DECLARED_EMAIL'''.strip()
subs = json.load(sys.stdin).get('Subscriptions', [])
mine = [s for s in subs
        if s.get('Protocol') == 'email' and s.get('Endpoint') == declared]
if any(s.get('SubscriptionArn', '').startswith('arn:') for s in mine):
    print('confirmed')
elif mine:
    print('pending')
else:
    print('absent')
" 2>/dev/null || echo error)"
  case "$SUB_STATE" in
    confirmed)
      echo "  PASS  声明收件人（[Alerting] email）的订阅已确认" ;;
    pending)
      echo "  FAIL  声明收件人的订阅还在 PendingConfirmation——必须点确认链接"
      echo "        （其他历史收件人是否 confirmed 与本项无关：换邮箱后旧的"
      echo "         仍 confirmed 会造成假绿，所以只认声明的那一个）"
      FAILURES=$((FAILURES + 1)) ;;
    absent)
      echo "  FAIL  topic 下没有声明收件人的订阅——先跑 deploy_auth.py"
      FAILURES=$((FAILURES + 1)) ;;
    *)
      echo "  FAIL  订阅状态查询失败（凭证/网络），不能当作通过"
      FAILURES=$((FAILURES + 1)) ;;
  esac
fi
```

同时把脚本的最小检查数下限相应提高（当前值 + 5）。

- [ ] **Step 4: [真机] 跑 `deploy_auth.py` 收编现网资源**

**部署门禁**：Step 2 全绿；`config.ini` 的 `[Alerting] email` 已填真实邮箱（gitignored）；**已确认 30-90 天窗口的历史日志无保留需要（或已导出）**——见下方 retention 警告。

**回滚锚点**：先导出现网配置（含**日志组 retention**——脚本会把它收敛到 30 天）：
```bash
aws cloudwatch describe-alarms --alarm-names site-builder-auth-invalid-grant \
  --output json > /tmp/alarm-before.json
aws logs describe-metric-filters --log-group-name /aws/lambda/site-auth-service \
  --output json > /tmp/filter-before.json
aws sns list-subscriptions-by-topic \
  --topic-arn "$(aws sns create-topic --name site-builder-alarms --query TopicArn --output text)" \
  --output json > /tmp/subs-before.json
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/site-auth-service \
  --query 'logGroups[0].retentionInDays' --output text > /tmp/retention-before.txt
```

**⚠️ retention 30 天是一次有意的数据修剪，不是可逆配置**：现网该组是
90 天，收敛到 30 天后，**超过 30 天的历史日志会被标记删除（通常 72 小时内
物理删除）**——事后把 retention 改回 90 **找不回已删的日志**。30 天符合
母 spec §6.3「平台日志组统一 30 天」，但执行前必须单独确认：

- 若近 90 天日志有排查/审计价值（如最近的登录失败调查还没结案），先导出
  再部署：`aws logs create-export-task`（导 S3）或按需 Insights 查询存档；
- 该确认是 Step 4 部署门禁的一部分，**不视为告警收编的附带效果**。

**回滚方式**：alarm/filter/subscription 用三份 `/tmp/*-before.json` 的值
还原（同名 upsert 不删资源，订阅不会丢）；retention 可改回
`/tmp/retention-before.txt` 的值，但**只对之后的新日志生效**，30-90 天窗口
内已删的日志不可恢复——这是本任务唯一不可逆的动作，所以放在部署门禁里而
不是回滚说明里兜底。

Run: `cd site-builder/auth && python3 deploy_auth.py`
Expected: 输出含 `告警管道已收敛：metric_filter, alarm`（订阅已存在时不含 `subscription`），且**不**出现 `⚠️ email 订阅状态`（因为现网订阅已确认）。

- [ ] **Step 5: [真机] 跑扩展后的 `verify_auth_alarm.sh`**

Run: `SNS_TOPIC_ARN="$(aws sns create-topic --name site-builder-alarms --query TopicArn --output text)" ./site-builder/scripts/verify_auth_alarm.sh`
Expected: 全部 PASS，含新增两项（`线上 alarm 配置 == 声明值`——Alarm/OK actions 必须等于声明 topic ARN；`声明收件人的订阅已确认`——绑定 `[Alerting] email`，其他收件人 confirmed 不算），探针 alarm 清理确认。

**负向验证（假绿场景真的会红）**：临时把 `config.ini` 的 `[Alerting] email` 改成一个未订阅的假邮箱再跑脚本 → Expected: `声明收件人` 一项 **FAIL**（`absent`），即使现网旧收件人仍 confirmed。改回后重跑 PASS。

- [ ] **Step 6: 验证幂等——再跑一次 `deploy_auth.py`**

Run: `cd site-builder/auth && python3 deploy_auth.py`
Expected: 输出不含 `subscription`（未重复创建订阅），无 `⚠️`；随后 `aws sns list-subscriptions-by-topic` 的 email 订阅数**与 Step 4 之前相同**（不得增长）：
```bash
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC" \
  --query "length(Subscriptions[?Protocol=='email'])" --output text
```
Expected: 与 `/tmp/subs-before.json` 里的 email 订阅数一致。

- [ ] **Step 7: 更新 `DEPLOY.md` 告警一节**

把原来"部署后建一个 metric filter + 阈值告警"的手工命令段改写为：

```markdown
   告警管道由 `deploy_auth.py` **幂等声明式收敛**（不是 IaC——没有状态文件与
   漂移检测，但每次运行都把配置收敛到声明值）。唯一真源是
   `site-builder/auth/alarm_pipeline.py`：metric filter、SNS topic、email
   订阅、alarm（含双语 AlarmDescription 与 Alarm/OK actions）全部在那里声明。

   **不要再手工 `aws logs put-metric-filter` / `aws cloudwatch put-metric-alarm`**
   ——那会造出第二个 writer，两份配置互相漂移。改阈值就改 `ALARM_PARAMS`
   然后重跑 `python3 deploy_auth.py`。

   前提：`config.ini` 的 `[Alerting] email` 已填（gitignored），或设
   `SB_ALERT_EMAIL` 环境变量。缺失时脚本**响亮失败**，不会静默造出一个
   没人收通知的 alarm。

   ⚠️ **email 订阅必须由收件人手工点确认链接**——脚本只能创建订阅。
   未确认时 alarm 照样进 ALARM 而无人知情，所以脚本把 `PendingConfirmation`
   显式报告为「未完成」。

   **从零部署验收**：
   ```bash
   SNS_TOPIC_ARN=<topic ARN> ./site-builder/scripts/verify_auth_alarm.sh
   ```
   它比对**线上配置 == `alarm_pipeline.py` 声明值**（含双语描述、Alarm/OK
   actions、Sum/300s/2 周期/≥1/notBreaching），并要求存在**已确认**的 email
   订阅（PendingConfirmation 判 FAIL），然后触发一次真实 `invalid_grant`、
   建临时探针 alarm 验证真的进 ALARM，最后自动清理（trap 覆盖异常路径）。

   > 术语：ALARM 与 OK（**告警解除**）均通知 SNS topic `site-builder-alarms`。
   > 「告警解除」只表示指标不再满足阈值，**告警规则仍然启用**，
   > 也**不表示根因已确认修复**（缺失数据按 notBreaching 处理）。
```

同时把该文件的检查清单项 `- [ ] 登录失败告警已建（metric filter + alarm，阈值按真实流量定）` 改为 `- [ ] 登录失败告警由 deploy_auth.py 自动收敛，且 verify_auth_alarm.sh 全绿（含 confirmed 订阅）`。

- [ ] **Step 8: Commit**

```bash
git add site-builder/auth/deploy_auth.py \
        site-builder/scripts/verify_auth_alarm.sh \
        site-builder/DEPLOY.md
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "feat(auth): deploy_auth.py 收编告警管道 + 验收脚本比对声明值

deploy_auth.py 末尾调 ensure_alarm_pipeline()，现网手工资源被同名 upsert
收编。email 缺失响亮失败；PendingConfirmation 显式报「未完成」。

verify_auth_alarm.sh 新增两项：
- 线上 alarm 配置逐项 == alarm_pipeline.py 声明值（含双语描述、
  ALARM/OK 同 topic）——只查\"存在\"会让手工漂移全绿
- 必须存在**已确认**的 email 订阅（PendingConfirmation 判 FAIL）
比对用 python3 校验 JSON：aws CLI 在 API 错误时也可能 exit 0（实测）。

DEPLOY.md 手工命令段改写为自动收敛，明确不称 IaC、禁止第二个 writer。"
```

---

> **以下 Task 5-16 为 M3 核心与收尾。** 前置 B1（Task 1-2）与 B2（Task 3-4）
> 必须先全部完成并真机验收通过，才进入 Task 5。

## Task 5: 数据层——三张表/GSI + `created_at` 回填

**Files:**
- Modify: `site-builder/deployer/infra/app.py`（jobs 表 `site-index` GSI；`site-ops-log`；`site-session-codes`）
- Modify: `site-builder/deployer/functions/common.py`（`list_jobs_by_site`；`create_site_record` + `SiteIdCollision`）
- Modify: `site-builder/mcp/server.py`（`do_deploy_site` 建站分支改用 `create_site_record` + 碰撞重试）
- Create: `site-builder/scripts/backfill_site_created_at.py`
- Create: `site-builder/deployer/tests/test_backfill_created_at.py`
- Modify: `site-builder/deployer/tests/conftest.py`、`site-builder/mcp/tests/conftest.py`（新表与 GSI 夹具）
- Modify: `site-builder/deployer/tests/test_infra_tables.py`（新表断言）
- Modify: `site-builder/config.ini.example`（`[Panel]` 段）

**Interfaces:**
- Produces:
  - jobs 表 GSI `site-index`（PK `site_id`, SK `created_at`）
  - 表 `site-ops-log`（PK `target`, SK `ts_actor`, TTL `expires_at`, RemovalPolicy RETAIN）
  - 表 `site-session-codes`（PK `jti`, TTL `expires_at`, RemovalPolicy DESTROY）
  - `common.list_jobs_by_site(site_id: str, limit: int = 50) -> list[dict]` —— 按 created_at 倒序
  - `common.create_site_record(site_id: str, *, owner: str, name: str, status: str = "DEPLOYING") -> None` —— 整条记录 `attribute_not_exists(site_id)` 单次条件写；碰撞抛 `common.SiteIdCollision`
  - `backfill_site_created_at.py` CLI：`--dry-run`（默认）/ `--apply`

**为什么 session-codes 用 DESTROY 而 ops-log 用 RETAIN**：session-codes 是 60 秒 TTL 的一次性消费标记，删栈时丢掉无害；ops-log 是审计记录（TTL 400 天），误删会丢失合规证据——与 `site-admins` 的 RETAIN 同理。

- [ ] **Step 1: 写失败测试（common + 回填脚本）**

创建 `site-builder/deployer/tests/test_backfill_created_at.py`：

```python
"""sites.created_at 回填：控制台要显示创建时间，但 upsert_site 全链路从不写它。

只有 jobs 表有 created_at——从该站点最早一条 job 推导。
"""
import sys
from pathlib import Path

import boto3
import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))


def _put_site(site_id, **extra):
    boto3.resource("dynamodb", region_name="us-east-1").Table("site-sites").put_item(
        Item={"site_id": site_id, "owner": "u@x.com", "status": "ACTIVE", **extra})


def _put_job(job_id, site_id, created_at):
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-deploy-jobs").put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "u@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": created_at, "updated_at": created_at})


def _site(site_id):
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-sites").get_item(Key={"site_id": site_id}).get("Item")


def test_backfills_from_earliest_job(aws):
    import backfill_site_created_at as bf
    _put_site("s1")
    _put_job("job-b", "s1", "2026-07-20T10:00:00+00:00")
    _put_job("job-a", "s1", "2026-06-18T09:41:00+00:00")   # 更早
    out = bf.run(apply=True)
    assert out["updated"] == 1
    assert _site("s1")["created_at"] == "2026-06-18T09:41:00+00:00"


def test_existing_value_is_not_overwritten(aws):
    import backfill_site_created_at as bf
    _put_site("s2", created_at="2026-01-01T00:00:00+00:00")
    _put_job("job-c", "s2", "2026-07-20T10:00:00+00:00")
    out = bf.run(apply=True)
    assert out["skipped_existing"] == 1 and out["updated"] == 0
    assert _site("s2")["created_at"] == "2026-01-01T00:00:00+00:00"


def test_site_without_jobs_is_reported_not_guessed(aws):
    """无 job 的站点**不能猜**创建时间（写 now 会是错的）——报告后跳过。"""
    import backfill_site_created_at as bf
    _put_site("s3")
    out = bf.run(apply=True)
    assert out["no_jobs"] == 1 and out["updated"] == 0
    assert "created_at" not in (_site("s3") or {})


def test_dry_run_writes_nothing(aws):
    import backfill_site_created_at as bf
    _put_site("s4")
    _put_job("job-d", "s4", "2026-05-01T00:00:00+00:00")
    out = bf.run(apply=False)
    assert out["would_update"] == 1
    assert "created_at" not in _site("s4")
```

在 `site-builder/deployer/tests/test_common.py` 追加：

```python
def test_list_jobs_by_site_returns_newest_first(aws):
    import common
    for jid, ts in [("job-1", "2026-06-01T00:00:00+00:00"),
                    ("job-2", "2026-07-01T00:00:00+00:00"),
                    ("job-3", "2026-05-01T00:00:00+00:00")]:
        common._table("JOBS_TABLE").put_item(Item={
            "job_id": jid, "site_id": "sx", "owner": "u@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": ts, "updated_at": ts})
    # 另一个站点的 job 不得混入
    common._table("JOBS_TABLE").put_item(Item={
        "job_id": "job-other", "site_id": "sy", "owner": "u@x.com",
        "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
        "created_at": "2026-08-01T00:00:00+00:00",
        "updated_at": "2026-08-01T00:00:00+00:00"})
    jobs = common.list_jobs_by_site("sx")
    assert [j["job_id"] for j in jobs] == ["job-2", "job-1", "job-3"]
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_backfill_created_at.py tests/test_common.py::test_list_jobs_by_site_returns_newest_first -q`
Expected: FAIL（`ModuleNotFoundError: backfill_site_created_at`；`AttributeError: module 'common' has no attribute 'list_jobs_by_site'`）

- [ ] **Step 3: 在 `infra/app.py` 加 GSI 与两张表**

在 `jobs.add_global_secondary_index(index_name="owner-index", ...)` 之后追加：

```python
        # 二期 M3：控制台的"部署历史"按 site_id 查。owner-index 是**发起者**
        # 维度（jobs.owner = requested_by），查不出"这个站点的所有部署"——
        # 协作者发起的部署 owner 是协作者。
        jobs.add_global_secondary_index(
            index_name="site-index",
            partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="created_at", type=ddb.AttributeType.STRING))
```

在 `admins = ddb.Table(...)` 之后追加：

```python
        # 二期 M3：操作审计（append-only）。写入方只被授予 PutItem。
        # RETAIN 与 admins 同理：审计记录误删会丢失合规证据。
        ops_log = ddb.Table(
            self, "OpsLog", table_name="site-ops-log",
            partition_key=ddb.Attribute(name="target", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="ts_actor", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            removal_policy=RemovalPolicy.RETAIN)

        # 二期 M3：面板会话升级的一次性 code 消费标记（jti）。
        # DESTROY（不同于 ops_log）：60 秒 TTL 的一次性标记，删栈丢掉无害。
        session_codes = ddb.Table(
            self, "SessionCodes", table_name="site-session-codes",
            partition_key=ddb.Attribute(name="jti", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            removal_policy=RemovalPolicy.DESTROY)
```

在 `CfnOutput` 的字典里加 `"OpsLogTable": ops_log.table_name, "SessionCodesTable": session_codes.table_name`；在 `common_env` 里加 `"OPS_LOG_TABLE": ops_log.table_name`。

exec_role 已有 `dynamodb:*` on `site-*`，新表自动覆盖——无需改 IAM。

- [ ] **Step 4: 在 `common.py` 加 `list_jobs_by_site` 与 `created_at`**

在 `list_jobs_by_owner` 之后追加：

```python
def list_jobs_by_site(site_id: str, limit: int = 50) -> list[dict]:
    """某站点的部署历史，**最新在前**（控制台"部署历史"标签页）。

    用 site-index 而非 owner-index：后者是**发起者**维度
    （jobs.owner = requested_by），协作者发起的部署 owner 是协作者，
    按 owner 查不出"这个站点的所有部署"。
    """
    resp = _table("JOBS_TABLE").query(
        IndexName="site-index",
        KeyConditionExpression=Key("site_id").eq(site_id),
        ScanIndexForward=False,    # created_at 倒序
        Limit=limit)
    return resp.get("Items", [])
```

在 `upsert_site` 的 docstring 后追加一个专用函数（不改 `upsert_site` 语义，避免所有调用方都写 created_at）：

```python
class SiteIdCollision(Exception):
    """site_id 已被占用。建站路径捕获它并重新生成 ID。"""


def create_site_record(site_id: str, *, owner: str, name: str,
                       status: str = "DEPLOYING") -> None:
    """**首次**建站：单次条件 UpdateItem 写整条记录，已存在即抛 SiteIdCollision。

    条件必须是 `attribute_not_exists(site_id)` 且**一次写完整条**——不能拆成
    "条件写 created_at + 无条件 upsert_site(owner/name/…)"两步：第一步条件
    失败被吞后，第二步会把**已有站点**的 owner/name/status 覆盖成本次调用者，
    随机 ID 碰撞就变成误接管（Codex review 2026-08-09 P1，moto 已复现；
    一期的 upsert_site 建站路径本就有此行为，本函数一并修掉）。

    **用 UpdateItem 而非 PutItem**（Codex 复审第二轮 P1）：MCP runtime 的
    IAM 对 sites 表**故意不给 PutItem**（挡"整条覆盖改站点归属"，
    `test_sites_table_has_no_putitem` 全表扫描锁定这一点），只有带属性白名单
    的 UpdateItem。UpdateItem + attribute_not_exists(site_id) 条件在语义上
    等价于条件 PutItem：item 不存在 → 条件通过并创建；已存在 → 条件失败，
    **原子性相同**。用 PutItem 会本地 moto 全绿、部署后真实 IAM 全部拒绝。
    代价：本函数写的字段必须在 deploy_agentcore.py 的
    SITE_WRITABLE_ATTRIBUTES 白名单内（created_at 需新增，见 Step 5b）。

    created_at 只在建站这一刻写；碰撞由调用方重新生成 ID 重试，
    **绝不对已有行继续写**。
    """
    import botocore.exceptions
    try:
        _table("SITES_TABLE").update_item(
            Key={"site_id": site_id},
            UpdateExpression="SET #o = :o, #n = :n, #s = :s, created_at = :t",
            ConditionExpression="attribute_not_exists(site_id)",
            ExpressionAttributeNames={"#o": "owner", "#n": "name",
                                      "#s": "status"},
            ExpressionAttributeValues={":o": owner, ":n": name,
                                       ":s": status, ":t": _now()})
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise SiteIdCollision(site_id) from e
        raise
```

同时在 `test_common.py` 追加**三条**用例——断言必须覆盖 owner/name/status（只断言 created_at 会假绿：覆盖行为恰好不碰 created_at）：

```python
def test_create_site_record_collision_raises_and_writes_nothing(aws):
    """碰撞必须抛 SiteIdCollision，且已有站点的**每个字段**原样不动。"""
    import common
    common._table("SITES_TABLE").put_item(Item={
        "site_id": "victim-abc123", "owner": "victim@x.com",
        "name": "victim", "status": "ACTIVE",
        "created_at": "2026-01-01T00:00:00+00:00"})
    import pytest
    with pytest.raises(common.SiteIdCollision):
        common.create_site_record("victim-abc123",
                                  owner="attacker@x.com", name="attacker")
    site = common.get_site("victim-abc123")
    assert site["owner"] == "victim@x.com"      # 不只 created_at——
    assert site["name"] == "victim"             # owner/name/status 全部
    assert site["status"] == "ACTIVE"           # 必须原样（假绿教训）
    assert site["created_at"] == "2026-01-01T00:00:00+00:00"


def test_create_site_record_writes_full_record_once(aws):
    import common
    common.create_site_record("s-new", owner="u@x.com", name="fresh")
    site = common.get_site("s-new")
    assert site["owner"] == "u@x.com" and site["status"] == "DEPLOYING"
    assert site["created_at"]


前两条进 `site-builder/deployer/tests/test_common.py`；第三条（走到 `do_deploy_site`）进 `site-builder/mcp/tests/test_tools.py`：

```python
def test_deploy_site_regenerates_id_on_collision(aws, monkeypatch):
    """建站分支撞 ID 时重新生成，不得对已有行做任何写。"""
    import common, server
    common._table("SITES_TABLE").put_item(Item={
        "site_id": "notes-aaaaaa", "owner": "victim@x.com",
        "name": "notes", "status": "ACTIVE",
        "created_at": "2026-01-01T00:00:00+00:00"})
    ids = iter(["notes-aaaaaa", "notes-bbbbbb"])   # 第一次碰撞，第二次成功
    monkeypatch.setattr(common, "new_site_id", lambda name: next(ids))
    out = server.do_deploy_site("caller@x.com", "notes")
    assert out["site_id"] == "notes-bbbbbb"
    victim = common.get_site("notes-aaaaaa")
    assert victim["owner"] == "victim@x.com" and victim["status"] == "ACTIVE"
```

- [ ] **Step 5: `mcp/server.py` 建站分支改用 `create_site_record` + 碰撞重试**

把 `do_deploy_site` 里的
```python
        site_id = common.new_site_id(common.validate_site_name(site_name))
        common.upsert_site(site_id, owner=owner, name=site_name, status="DEPLOYING")
```
改为
```python
        # create_site_record 而非 upsert_site：整条记录 attribute_not_exists
        # 单次条件写。upsert 语义下随机 ID 碰撞会把已有站点的 owner/name/
        # status 覆盖成本次调用者（误接管）；碰撞重新生成 ID 重试。
        # 36^6 ≈ 21.8 亿的后缀空间里 3 次连撞视为异常（大概率是环境/代码问题），
        # 响亮失败而不是无限重试。
        for _ in range(3):
            site_id = common.new_site_id(common.validate_site_name(site_name))
            try:
                common.create_site_record(site_id, owner=owner, name=site_name)
                break
            except common.SiteIdCollision:
                continue
        else:
            raise common.InvalidSiteName(
                "站点 ID 连续碰撞，请重试；若持续出现请联系平台管理员")
```

**注意**：`SiteIdCollision` 定义在 `common.py`（Step 4 的代码块里），`server.py` 通过 `common.SiteIdCollision` 引用。

- [ ] **Step 5b: `deploy_agentcore.py` 的 `SITE_WRITABLE_ATTRIBUTES` 加 `created_at`**

`create_site_record` 用带属性白名单的 UpdateItem 写 sites 表，新写入的
`created_at` 必须进白名单——**少这一项时线上建站直接 AccessDenied**（且报错
形态是 IAM 拒绝，不是条件冲突，排查时容易误判；见该常量注释的既有说明）。

```python
SITE_WRITABLE_ATTRIBUTES = ("site_id", "owner", "name", "status", "created_at",
                            "require_login", "allowed_users", "collaborators",
                            "permissions_rev", "permissions_updated_at",
                            "permissions_updated_by")
```

并在常量注释的"do_deploy_site 创建站点时写"一行加上 created_at。
`test_agentcore_contract.py` 从实现源码解析比对该清单（不手抄第二份），
本步骤后跑 mcp 测试确认：

Run: `cd site-builder/mcp && python3 -m pytest tests/test_agentcore_contract.py -q`
Expected: PASS，其中 `test_sites_table_has_no_putitem` 仍绿（`create_site_record`
用的是 UpdateItem，policy 不需要也不能出现 PutItem）。

**Task 13 部署 MCP 后的真机 IAM 探针**（写进 Task 13 验收）：以 runtime role
的凭证对 sites 表发一次含 `created_at` 的条件 UpdateItem（不存在的探针
site_id，写后即删），确认不再 AccessDenied——单测与 contract test 都看不到
真实 IAM，这一步是唯一的真机证据。

- [ ] **Step 6: 写回填脚本**

创建 `site-builder/scripts/backfill_site_created_at.py`：

```python
#!/usr/bin/env python3
"""一次性幂等回填 sites.created_at（控制台要显示创建时间）。

缺口：upsert_site 全链路从不写 created_at，只有 jobs 表有。存量站点因此没有
这个字段。从该站点**最早一条 job** 的 created_at 推导。

**无 job 的站点不猜**：写 now() 会是个错的日期，且看不出是猜的。这类记录进
报告由人工判断。同 migrate_permissions.py 的"损坏数据报错跳过，不降级"取向。

用法：
    ./backfill_site_created_at.py            # dry-run（默认，只报告）
    ./backfill_site_created_at.py --apply    # 真写
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/deployer/functions"))
CFG_PATH = HERE.parent / "config.ini"


def _read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


def run(*, apply: bool) -> dict:
    import boto3
    from boto3.dynamodb.conditions import Key
    import common

    ddb = boto3.resource("dynamodb",
                         region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    sites_tbl = ddb.Table(os.environ["SITES_TABLE"])
    jobs_tbl = ddb.Table(os.environ["JOBS_TABLE"])
    stats = {"total": 0, "updated": 0, "would_update": 0,
             "skipped_existing": 0, "no_jobs": 0}
    reports: list[str] = []

    sites = common._paginate(sites_tbl.scan,
                             ProjectionExpression="site_id, created_at")
    for site in sites:
        stats["total"] += 1
        site_id = site["site_id"]
        if site.get("created_at"):
            stats["skipped_existing"] += 1
            continue
        # 最早一条 job：site-index 正序取第一条
        resp = jobs_tbl.query(IndexName="site-index",
                              KeyConditionExpression=Key("site_id").eq(site_id),
                              ScanIndexForward=True, Limit=1)
        items = resp.get("Items", [])
        if not items or not items[0].get("created_at"):
            stats["no_jobs"] += 1
            reports.append(f"  跳过 {site_id}：没有可推导创建时间的 job（不猜）")
            continue
        ts = items[0]["created_at"]
        if not apply:
            stats["would_update"] += 1
            reports.append(f"  将回填 {site_id} → {ts}")
            continue
        try:
            sites_tbl.update_item(
                Key={"site_id": site_id},
                UpdateExpression="SET created_at = :t",
                ConditionExpression="attribute_not_exists(created_at)",
                ExpressionAttributeValues={":t": ts})
            stats["updated"] += 1
        except Exception as e:      # 条件失败=并发写入了，属正常
            if "ConditionalCheckFailed" not in str(type(e).__name__) + str(e):
                raise
            stats["skipped_existing"] += 1
    for line in reports:
        print(line)
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="真写（默认 dry-run 只报告）")
    args = ap.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", _read_cfg("Platform", "region"))
    os.environ["SITES_TABLE"] = _read_cfg("Deployer", "sites_table")
    os.environ["JOBS_TABLE"] = _read_cfg("Deployer", "jobs_table")
    stats = run(apply=args.apply)
    print(f"\n站点总数 {stats['total']}｜"
          f"{'已回填' if args.apply else '待回填'} "
          f"{stats['updated'] or stats['would_update']}｜"
          f"已有值跳过 {stats['skipped_existing']}｜无 job 跳过 {stats['no_jobs']}")
    if stats["no_jobs"]:
        print("⚠️  有站点无法推导创建时间——控制台会显示为空，需人工确认后手工补")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 7: 更新 conftest 夹具（deployer + mcp）**

`site-builder/deployer/tests/conftest.py`：在 jobs 表的 `create_table` 里加 `site-index` GSI 定义（照抄 `owner-index` 的形态，PK `site_id` / SK `created_at`，并把两个属性加进 `AttributeDefinitions`）；新增 `site-ops-log`（PK `target` / SK `ts_actor`）与 `site-session-codes`（PK `jti`）两张表；`ENV` 加 `"OPS_LOG_TABLE": "site-ops-log", "SESSION_CODES_TABLE": "site-session-codes"`。

`site-builder/mcp/tests/conftest.py`：同样加 `site-index` GSI 与 `site-ops-log` 表 + `OPS_LOG_TABLE` 环境变量（Task 8 的 ops-log 落点在 permissions.py，MCP 测试会走到）。

- [ ] **Step 8: 在 `test_infra_tables.py` 加新表断言**

```python
def test_ops_log_and_session_codes_tables(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    by_name = {t["Properties"]["TableName"]: t
               for t in tables.values()
               if isinstance(t["Properties"].get("TableName"), str)}
    ops = by_name["site-ops-log"]
    # 审计表误删会丢合规证据——与 site-admins 同为 RETAIN
    assert ops["DeletionPolicy"] == "Retain"
    assert ops["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
    codes = by_name["site-session-codes"]
    assert codes["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"


def test_jobs_has_site_index(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    jobs = [t for t in tables.values()
            if t["Properties"].get("TableName") == "site-deploy-jobs"][0]
    idx = {g["IndexName"]: g for g in jobs["Properties"]["GlobalSecondaryIndexes"]}
    assert "site-index" in idx, "控制台部署历史需要按 site_id 查"
    keys = {k["KeyType"]: k["AttributeName"] for k in idx["site-index"]["KeySchema"]}
    assert keys == {"HASH": "site_id", "RANGE": "created_at"}
```

- [ ] **Step 9: 运行测试确认通过**

Run:
```bash
cd site-builder/deployer && .venv/bin/pytest tests -q && \
cd ../mcp && python3 -m pytest tests -q
```
Expected: 两处均 PASS（deployer 新增 7 用例：回填 4 + list_jobs_by_site 1 + 碰撞 2；mcp 新增 1：碰撞重生成）

CDK 断言：
```bash
cd site-builder/deployer && \
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```
Expected: PASS

- [ ] **Step 10: 反向验证**

1. 把回填脚本的 `ConditionExpression="attribute_not_exists(created_at)"` 删掉 →
   Expected: `test_existing_value_is_not_overwritten` **FAIL**
2. 把"无 job 就跳过"改成 `ts = common._now()` →
   Expected: `test_site_without_jobs_is_reported_not_guessed` **FAIL**
3. 把 `list_jobs_by_site` 的 `ScanIndexForward=False` 改成 `True` →
   Expected: `test_list_jobs_by_site_returns_newest_first` **FAIL**
4. 把 `create_site_record` 改回"条件写 created_at 被吞 + 无条件 upsert_site"
   的两步写法 →
   Expected: `test_create_site_record_collision_raises_and_writes_nothing`
   **FAIL**（owner 被覆盖成 attacker@x.com——这正是 Codex 复现的接管路径；
   若此用例在两步写法下仍绿，说明断言漏了 owner/name/status，用例本身是坏的）

四处还原，重跑 PASS。

- [ ] **Step 11: 在 `config.ini.example` 加 `[Panel]` 段**

```ini
# 二期 M3 控制台（panel）。deploy_panel.py 从这里取值。
[Panel]
ops_log_table = site-ops-log
session_codes_table = site-session-codes
# 前端静态资源的版本前缀：S3 platform/console/{console_version}/
# 每次前端改动递增，旧版本保留以便回滚（与站点前端的版本化上传同模式）。
console_version = v1
```

- [ ] **Step 12: Commit**

```bash
git add site-builder/deployer/infra/app.py \
        site-builder/deployer/functions/common.py \
        site-builder/mcp/server.py \
        site-builder/scripts/backfill_site_created_at.py \
        site-builder/deployer/tests/test_backfill_created_at.py \
        site-builder/deployer/tests/test_common.py \
        site-builder/deployer/tests/test_infra_tables.py \
        site-builder/deployer/tests/conftest.py \
        site-builder/mcp/tests/conftest.py \
        site-builder/config.ini.example
bash site-builder/scripts/scan_staged_secrets.sh --files \
  site-builder/scripts/backfill_site_created_at.py \
  site-builder/deployer/tests/test_backfill_created_at.py || exit 1
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git diff --cached
git commit -m "feat(deployer): M3 数据层——site-index GSI + ops-log/session-codes 表 + created_at

- jobs 加 site-index GSI（PK site_id/SK created_at）：owner-index 是发起者
  维度，协作者发起的部署查不出\"这个站点的所有部署\"
- site-ops-log（RETAIN + TTL）：审计误删会丢合规证据，同 site-admins
- site-session-codes（DESTROY + TTL）：60 秒一次性标记，删栈丢掉无害
- create_site_record()：整条记录 attribute_not_exists(site_id) 单次条件写，
  碰撞抛 SiteIdCollision 由建站分支重生成 ID。修掉一期 upsert 建站的
  \"随机 ID 碰撞误接管已有站点\"路径（Codex review 复现）
- backfill_site_created_at.py：从最早一条 job 推导；**无 job 不猜**（写 now
  是错日期且看不出是猜的），报告后跳过。默认 dry-run"
```

- [ ] **Step 13: [真机] 部署 deployer 栈并等待 `site-index` ACTIVE**

**部署门禁**：Step 9-10 全绿 + Step 12 已提交。

```bash
cd site-builder/deployer/infra && rm -rf cdk.out && \
  PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

**GSI 加到已有表后先处于 CREATING，期间 Query 会报错**（AWS 契约：backfilling
完成转 ACTIVE 前不可查）。存量 job 数量级小（几十条），通常几分钟内 ACTIVE，
但必须显式等待而不是假设：

```bash
JOBS_TABLE=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Deployer']['jobs_table'])")
for i in $(seq 1 60); do
  S=$(aws dynamodb describe-table --table-name "$JOBS_TABLE" \
        --query "Table.GlobalSecondaryIndexes[?IndexName=='site-index'].IndexStatus | [0]" \
        --output text)
  echo "site-index: $S"
  [ "$S" = "ACTIVE" ] && break
  sleep 10
done
[ "$S" = "ACTIVE" ] || { echo "FAIL: site-index 未在 10 分钟内 ACTIVE"; exit 1; }
```

Expected: `site-index: ACTIVE`。再真机验证 GSI 可查（任取一个存量站点）：

```bash
aws dynamodb query --table-name "$JOBS_TABLE" --index-name site-index \
  --key-condition-expression "site_id = :s" \
  --expression-attribute-values "{\":s\":{\"S\":\"<存量 site_id>\"}}" \
  --no-scan-index-forward --max-items 3 \
  --query 'Items[].{job:job_id.S,at:created_at.S,st:#s.S}' \
  --output table 2>/dev/null || \
aws dynamodb query --table-name "$JOBS_TABLE" --index-name site-index \
  --key-condition-expression "site_id = :s" \
  --expression-attribute-values "{\":s\":{\"S\":\"<存量 site_id>\"}}" \
  --no-scan-index-forward --max-items 3 --output json | python3 -m json.tool | head -30
```

Expected: 返回该站点的 job（最新在前）。**这个真机形态（返回字段、排序）
是 Task 6 `/api/sites/{id}/jobs` 响应契约的输入。**

- [ ] **Step 14: [真机] 跑 created_at 回填（先 dry-run 再 apply 再读回）**

```bash
./site-builder/scripts/backfill_site_created_at.py            # dry-run
```
Expected: 报告"将回填 N 个 / 已有值跳过 0 / 无 job 跳过 K"。人工过目
`将回填` 列表（site_id → 推导出的时间戳）无异常后：

```bash
./site-builder/scripts/backfill_site_created_at.py --apply
```
Expected: `已回填 N`（与 dry-run 的 N 一致）。

**读回核对**（强一致读，逐站点确认真的写进去了）：

```bash
SITES_TABLE=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Deployer']['sites_table'])")
aws dynamodb scan --table-name "$SITES_TABLE" --consistent-read \
  --projection-expression "site_id, created_at" --output json | \
python3 -c "
import json, sys
items = json.load(sys.stdin)['Items']
missing = [i['site_id']['S'] for i in items if 'created_at' not in i]
print(f'站点 {len(items)} 个，缺 created_at：{len(missing)} 个')
for s in missing: print(f'  （无 job 站点，控制台创建时间显示为空）{s}')
"
```
Expected: 缺 created_at 的数量 == dry-run 报告的 `无 job 跳过 K`（且这 K 个
已人工确认）。**回填的实际覆盖率是 Task 14 前端"创建时间"列展示逻辑的输入。**

再幂等验证：重跑 `--apply` 一次，Expected: `已回填 0｜已有值跳过 N+...`
（不重复写）。

**回滚方式**：created_at 是新增字段，回滚 = 逐站点 `REMOVE created_at`
（无消费方读它——panel 尚未部署）；GSI 回滚 = `git revert` 后重新 deploy
（CDK 删索引）。两者都不影响现有部署链。

- [ ] **Step 15: 记录真机结果供 Task 6 展开使用**

把以下三项写进 `.superpowers/sdd/progress.md` 的 Task 5 条目（**不含真实
site_id/账号值**，用计数与形态描述）：

1. `site-index` Query 的真机返回形态（字段集合、`ScanIndexForward=False`
   生效与否）；
2. created_at 回填覆盖率（N 回填 / K 无 job）；
3. 无 job 站点清单的处置结论（前端显示为空 or 人工补）。

**此步骤产出即 Task 6-16 展开所需的全部真机输入**——展开工作不依赖其他
未完成事项。

---

> **Task 6-16 的详细步骤**：本计划已覆盖两个 Blocking 前置（Task 1-4，可立即
> 开始实施）与 M3 数据层（Task 5）。Task 6-16 的接口契约、文件清单与验收标准
> 已在上方「文件结构」「任务顺序与依赖」与 spec
> `2026-08-09-phase2-m3-console-spec.md` 中锁定，逐步骤展开在 **Task 5 全部
> 完成（含 Step 13-15 的真机部署、GSI ACTIVE、回填与读回）后**由控制器追加
> ——`site-index` 的真机查询形态与 `created_at` 回填覆盖率（Step 15 记录进
> progress.md）是 `/api/sites` 与 `/api/sites/{id}/jobs` 响应契约的输入。
> Task 5 不产出这些就不算完成，展开工作不依赖其他未完成事项（Codex review
> 2026-08-09：早先版本的 Task 5 只有单测与 commit、没有真机步骤，"等 Task 5
> 真机结果"构成循环依赖——已由 Step 13-15 修复）。
> **在 Task 6-16 逐步骤追加进本文件之前，不得开始实施这些任务。**
>
> **Task 6-16 概要**（每个任务的 Files / Interfaces / 验收标准）：
>
> - **Task 6 panel 授权与 API 纯函数**：`panel/api.py` 的 do_* 层 + `tests/test_authz.py`（owner/collaborator/outsider/admin × 各端点矩阵）+ `tests/test_no_handwritten_guards.py`。授权 100% 走 `permissions.assert_can` / 高层写函数。
>   **必须包含的两条结构性断言**（AST 解析 `panel/*.py`，不用文本匹配——注释里出现这些字样不算违规）：
>   ① panel 模块内不出现任何 `UpdateExpression=` / `ConditionExpression=` 关键字实参，也不出现对 sites/admins 表的 `put_item`/`update_item`/`delete_item` 调用；权限与 admin 写入只能是对 `permissions.<高层函数>` 的 Call。
>   ② admin 增删只能命中 `permissions.add_admin` / `permissions.remove_admin`——它们维护 `__count__` sentinel（`remove_admin` 的"不能删到名单为空"条件依赖它）。panel 若 raw 写 admins 表，sentinel 会与实际 item 数漂移，`remove_admin` 的守卫随之失效。
>   反向验证：在 `panel/api.py` 里临时插一句 `_admins_table().put_item(Item={"email": "x@x.com"})`，确认 ① ② 各自 FAIL 后删除。
> - **Task 7 console-session + CSRF**：
>   ① **code 编解码单一实现进 `auth/session.py`**（`mint_upgrade_code` / `verify_upgrade_code`，HS256 同 JWT_SECRET，载荷 `typ="console-upgrade"` / `email` / `jti` / `exp`≤60s）；panel 构建时复制 `session.py`（同 common.py/permissions.py 模式）——**不得在 panel 里手写第二份编解码**；
>   ② `panel/console_session.py`：调 `verify_upgrade_code` + jti 条件写 `site-session-codes` 原子消费（`attribute_not_exists(jti)`）+ 重放拒绝 + `__Host-sb_console` cookie 构造（Secure/HttpOnly/SameSite=Lax/Path=//无 Domain）；
>   ③ **密钥交付**：panel 环境变量只下发 `JWT_SECRET_PARAM`（参数名），运行时 SSM 读 + TTL 缓存，照抄 auth 的 `_secret()` 模式。**明文严禁进环境变量**（GetFunctionConfiguration 会回显，拿到即可伪造任意用户会话——deploy_auth.py:54-65 已记录）；panel role 的 SSM 语句资源限定**精确 ARN** `parameter/site-builder/jwt-secret`（**不照抄 auth 的 `parameter/site-builder/*` 前缀**——那是 auth 自己还要读 site-client-secret 的业务需要，panel 拿前缀等于被攻破时顺带交出 Cognito client secret；Codex 复审第二轮 P2）+ `kms:Decrypt` ViaService 条件。Task 10 的 contract test 断言：SSM 资源 == 精确 jwt-secret ARN，出现 `*` 结尾的前缀即 FAIL；
>   ④ **交叉契约测试**：同一组用例向量（合法 code / 篡改各字段 / typ 不符 / 过期 / jti 重放）在 auth 与 panel 两个测试包各跑一遍，防两份复制品漂移；
>   ⑤ `tests/test_csrf.py`：**副作用前置顺序断言**——mock DynamoDB 客户端，验证 CSRF 失败路径下零写调用。
> - **Task 8 ops-log 落点**：`permissions.py` 五个高层写函数 + undeploy 路径内落 ops-log（唯一落点，MCP 与控制台自动同轮覆盖）+ `panel/ops_log.py`（PutItem only、字段脱敏）+ `mcp/deploy_agentcore.py` 补 ops-log PutItem。
> - **Task 9 panel handler 组装**：`panel/handler.py` 路由分发 + 五步前置校验顺序 + 错误码（401 `{"need":"console-session"}` / 403 / 409）。
> - **Task 10 `deploy_panel.py`**：Lambda + Function URL + panel role（表清单见 spec §2，路由表**仅** UpdateItem）+ 前端上传 S3 `platform/console/{console_version}/` + console route 注册。
>   **Function URL trust 的三条可验证断言**（contract test + 真机各一遍）：
>   ① `AuthType == "AWS_IAM"`（不是 NONE——`NONE` + `Principal:*` 会被安全扫描自动处置，实测把整个 resource policy 删光）；
>   ② resource policy 恰好两条语句、Principal 是**逐字符 exact** edge role ARN（不是 `*`、不是账号根、不做前缀匹配），action 分别是 `lambda:InvokeFunctionUrl`（含 `FunctionUrlAuthType=AWS_IAM` 条件）与 `lambda:InvokeFunction`（含 `InvokedViaFunctionUrl=true` 条件）——2025-10 起缺任一条即 403；
>   ③ `edge_role_arn` 缺失/空串时 `deploy_panel.py` **抛错中止**，不得 fallback 到 `Principal:*` 或跳过授权（照抄 `deploy_lambda_site.py` 的 KeyError 形态）。
>   真机：unsigned `curl` 直连 Function URL 期望 403（这**只**证明 AuthType=AWS_IAM 在工作）；经 `https://console.{base_domain}` 期望 200。**只有请求确实经过 Edge，`x-user-email` 才可信**——②③ 是这个前提的唯一保证。
>   反向验证 Principal 精确绑定（**不能用 unsigned curl**：AWS_IAM 下未签名请求恒 403，与 resource policy 无关——把 Principal 改成 `*` 后 unsigned curl 依然 403，永远得不到"变 200"的信号；照那个思路做的实施者可能改 AuthType=NONE 去"让测试通过"，反而真正公开 endpoint。Codex review 2026-08-09 P2）：
>   用一个**非 Edge、且无 identity-based lambda:InvokeFunctionUrl 权限**的已签名 IAM principal（如临时建的探针角色）发 SigV4 请求：
>   ① Principal=exact edge role 时 → 探针请求 403（resource policy 不认它）；
>   ② 临时把 Principal 改成 `*` 部署 → 同一探针请求变 200（证明改的就是这条边界）；
>   ③ 还原 exact Principal 重新部署 → 探针再次 403；contract test 同步确认 FAIL→PASS。
>   探针角色用完即删（trap 清理，与 verify 脚本的探针数据同纪律）。
> - **Task 11 Edge console 白名单 + 平台前缀 S3 权限**：
>   ① `PLATFORM_SUBDOMAINS` 加 `console`、`RESERVED_COOKIES` 加两个 `__Host-`（origin_request/origin_response 两文件同步）+ 伪造 platform route 负测；
>   ② **`stack.py` Edge role 的 S3 policy 加 `{frontend_bucket}/platform/*`**（Codex review 2026-08-09 P1：现只有 `sites/*`，而 console 前端在 `platform/console/{version}/`、route_mode=split 的非 `/api/*` 请求走 S3 SigV4 分支——缺这条则控制台首页 AccessDenied 加载不出来）。收窄取向：给 `platform/*` 而非整桶，站点前缀与平台前缀仍然分离；
>   ③ `verify_deployed_edge.sh` 断言产物含新白名单/新保留 cookie、CloudFront 实际关联版本。**S3 IAM 生效的真机验证用临时探针，不用 console 首页**（Codex 复审第二轮 P1：Task 11 与 Task 10 并行、前端要到 Task 14 才上传——console route/S3 key 此时都不存在，`https://console.{domain}/` 的 404/403 与 IAM 是否正确无关，会把正确的修复误判失败）：上传临时对象 `platform/probe-{随机}/index.html` + 注册临时 probe route（`app-probe-{随机}`，require_auth=False、static_prefix 指向该前缀）→ 经 CloudFront 请求期望 200（探针对象在 `platform/*` 下，200 即证明新 IAM 语句生效）→ trap 清理 route 与对象并强一致读回核对（同 smoke_router.sh 的清理纪律）。**console 首页 200（带会话 cookie）的端到端验收归 Task 14**（那时 route/前端/Edge 全部就位）；
>   ④ CDK 断言：Edge role 的 S3 语句资源集合 == `{sites/*, platform/*}`（不多不少——出现整桶 `/*` 即 FAIL）。
>   反向验证：临时把 `platform/*` 那条删掉 synth → CDK 断言 FAIL；（真机负向不必做——部署前的 AccessDenied 已由现状证明。）
> - **Task 12 auth `/console-session`**：`session.py` 加 `mint_upgrade_code` / `verify_upgrade_code`（Task 7 契约的签发端）；`login_handler.py` 加 `/console-session` 路径（校验顶域 `sb_session` 有效 → `mint_upgrade_code(email)` → 302 到 `https://console.{base_domain}/api/session-callback?code=...`；无有效会话则 302 到 `/login?redirect=<console-session URL>` 走完整登录）；`__Host-sb_pkce` 与新 cookie 的作用域测试；重部署 auth（`python3 deploy_auth.py`）后真机验证 302 链路。
> - **Task 13 三层部署 + `verify_deployed_components.py`**：重构自 `verify_contract_fixtures.py`（7 段，旧脚本删除、文档引用同步），部署 deployer/Edge/auth/panel/MCP 并逐一核对产物。另含三项收口：
>   ① **MCP 部署后补跑第二轮 created_at 回填**（dry-run → apply → 读回）：Task 5 回填到 Task 13 部署新 MCP 之间，线上旧 MCP 建的新站点仍走旧 `upsert_site` 不写 created_at（Codex 复审第二轮 P2 时序缺口）。最终 E2E 前要求除 `无 job 跳过` 外零缺失；
>   ② **真机 IAM 探针**（Task 5 Step 5b 的收口）：以 runtime role 凭证对 sites 表发含 `created_at` 的条件 UpdateItem（探针 site_id，写后即删），确认白名单更新真的生效；
>   ③ console 首页端到端（Task 11 移交过来的验收前置——route/前端/Edge 就位后才有意义）。
> - **Task 14 前端移植 + panel E2E**：原型视图层进 `panel/frontend/`（去敏感值、`window.API` 换真 fetch、M4/M5 入口 disabled、PHASE_LABEL 按 jobs 表真实词表重写、undeploy 改轮询、FAILED 展示层派生）+ spec §7 的 13 项 E2E 全覆盖。
> - **Task 15 fixture 自动清理**（可与 6-14 并行，**必须在 Task 16 前完成**）：`smoke_router.sh` 随机后缀 + trap + 只删本次 + 强一致读回 + 最小断言数 + `--keep-on-failure`；`test_e2e_fixtures.py` finalizer（记录本次 site_id/job_id、默认 undeploy + purge、清理失败即测试失败、禁按 owner 批量删）。
> - **Task 16 全量回归与文档收尾**：五个包测试 + 七个真机闸门 + `DEPLOY.md` 新阶段 + `CLAUDE.md` 同步（panel venv 归属、验收脚本改名、`deploy_panel.py` 部署命令）+ `progress.md` + HANDOFF 更新 6。

---

## Self-Review 结论

**1. Spec 覆盖**：phase2 spec §11-pre.1（Task 1-2）、§11-pre.2（Task 3-4）、§11-pre.3（Task 15）、§11-pre.4（Task 13）；M3 spec §2 平台约束（Task 10）、§3 前端（Task 14）、§4 接口映射（Task 6/9）、§4.1 四个缺口（Task 5 的 created_at 与 Task 14 的 FAILED 派生/phase 词表/undeploy 轮询）、§5.1-5.5 安全硬约束（Task 6/7/8/10/11）、§6 资源清单（Task 5/10）、§7 测试硬约束（各任务的反向验证步骤 + Task 13/14）。**Task 1-5 已逐步骤覆盖无遗漏；Task 6-16 为锁定契约后的分阶段展开**（早先版本此处写"无遗漏"是过度声明——Codex review 指出后修正）。

**2. 占位符扫描**：Task 1-5 的每个代码步骤都有可直接落地的完整代码；Task 6-16 是**明示的分阶段展开**（附完整 Files/Interfaces/验收标准），不是 "TBD"——理由已写明（数据层真机形态影响 panel 响应契约）。

**3. 类型一致性**：`converge_job_to_failed` 在 Task 1 定义、Task 2 的 CDK handler 引用一致；`list_jobs_by_site` / `create_site_record` 在 Task 5 定义，Task 6/14 消费；`ensure_alarm_pipeline` 在 Task 3 定义、Task 4 消费，参数名逐一对应；`ALARM_PARAMS` / `ALARM_DESCRIPTION` 在 Task 3 定义、Task 4 的验收脚本 import 同名。

**4. 自审发现并已修的五处**（记录于此，避免实施时重蹈）：

| 问题 | 修法 |
|---|---|
| Task 2 CDK 片段残留 `f_sweep.add_alias  # noqa` 占位行 | 删除，改为说明 `recon_fn` 与 `step_fn` 的 asset 差异（前者无 bundling） |
| Task 5 `create_site_record` 的条件失败处理写在正文而非代码里 | ~~补 try/except 吞条件失败~~ **此修法本身有缺陷**，被 Codex review F1 推翻——见下方第 6 节 |
| Function URL trust 只在 Global Constraints 有一句，Task 10 无可验证断言 | Task 10 展开三条断言（AuthType / exact Principal 双语句 / 缺配置抛错不 fallback）+ 真机正负各一 + 反向验证（反向验证方式后被 Codex F7 修正，见第 6 节） |
| admin `__count__` sentinel 同上——只在约束里，Task 6 无守卫 | Task 6 展开两条 AST 结构性断言（禁 panel 内 UpdateExpression/表直写、admin 增删只能命中 helper）+ 反向验证 |
| Task 6 的结构性测试原写"AST 扫描"但未说明为何不能用文本匹配 | 明确写出：注释/docstring 里出现这些字样不算违规（本项目历史教训：文本断言锁住了注释里的旧表达式，改错代码仍绿） |

**5. 七个检查点复核**：M3/M4/M5 范围（Global Constraints 第 47 行 + spec §11-clarify，`stats` 在计划里的其余出现均为回填脚本的本地变量名，非 M5 功能）；console 平台白名单（Task 11 + 约束第 32 行禁 `route.owner` 推导）；Function URL trust（Task 10 三条，已补）；EventBridge best-effort + sweeper（Task 1 docstring + Task 2 rule/schedule 断言 + Task 2 Step 10 真机两层各自有效）；admin sentinel（Task 6 两条，已补）；CSRF 前置副作用（Task 7 的"CSRF 失败路径下零写调用"顺序断言 + Task 9 五步顺序）；清理与部署门禁（Task 2/4 各有部署门禁+回滚锚点+回滚方式，Task 15 fixture 清理且硬性早于 Task 16）。

**6. Codex review（2026-08-09，7 findings）处置记录**：

| # | Finding | 处置 | 落点 |
|---|---|---|---|
| F1 | `create_site_record` 两步写在 ID 碰撞时接管已有站点（moto 复现成立） | **接受修法，拒绝定性**：覆盖行为源自一期 `upsert_site` 建站路径（`server.py:190`），非 7e22215 新引入；且攻击者无法选 site_id（36^6 随机 + 直传分支有格式校验与 `_assert_permission`），是健壮性缺陷非可诱导攻击。修法照做：整条记录 `attribute_not_exists(site_id)` 单次条件写 + `SiteIdCollision` + 建站分支重生成 ID（≤3 次）；用例断言 owner/name/status 全字段 | Task 5 Step 4/5/10 |
| F2 | Edge role S3 只有 `sites/*`，console 前端 `platform/console/*` 必然 AccessDenied | **接受**（本轮最实际的一条） | Task 11 ②③④ + 文件表 `stack.py` 行 |
| F3 | console-session 缺跨 Lambda 密钥交付与 code 字节级契约 | **接受**（修正其前提：JWT_SECRET 是沿用现有 SSM 参数 + `_secret()` 模式，非新通道）。编解码单一实现进 `auth/session.py`，panel 构建时复制；密钥明文禁进环境变量；交叉契约测试 | M3 spec §5.4 + Task 7/12 概要 + 文件表 |
| F4 | Task 6-16 占位 + "等 Task 5 真机结果"是循环依赖 | **部分接受**：循环依赖成立——Task 5 补 Step 13-15（deploy、GSI ACTIVE 等待、回填 dry-run/apply、读回核对、结果记录）；"不算完整 plan"不接受——分阶段展开是显式声明的交付方式，但自审"无遗漏"确系过度声明，已改口径，并加"Task 6-16 未展开前不得实施"门禁 | Task 5 Step 13-15 + 展开说明 + 自审第 1 节 |
| F5 | 从零部署时日志组不存在，`put_metric_filter` 抛 ResourceNotFound | **接受**（严重性下调：现网组已存在 retention 90 天，这是"从零部署"路径缺陷——但那正是 B2 的目标）。`ensure_alarm_pipeline` 加 ⓪ 段：幂等 `create_log_group` + retention 收敛 30 天（顺手满足 spec §6.3）；Stubber 加 fresh-account 正反两用例 | Task 3 Step 1/3/4/5 |
| F6 | 告警验收未绑定声明 topic + 声明收件人，两个假绿场景 | **接受**：actions 必须 == 声明 topic ARN（不只 Alarm==OK）；订阅必须是 `[Alerting] email` 那个 Endpoint 已确认（其他人 confirmed 不算）；分页交给 python 数；加负向验证（假邮箱必 FAIL） | Task 4 Step 3/5 |
| F7 | "Principal=* 后 unsigned curl 变 200"违反 AWS_IAM 契约 | **接受**（P2，自审引入的错误）：AWS_IAM 下未签名请求恒 403 与 resource policy 无关，且该指引会诱导实施者改 AuthType=NONE。改为已签名的非 Edge 探针 principal 做正反验证，并写明原因 | Task 10 反向验证段 |

**7. Codex 复审第二轮（2026-08-09，3 P1 + 4 P2）处置记录**：

| # | Finding | 处置 | 落点 |
|---|---|---|---|
| R1 | F1 改用 PutItem 与 MCP runtime IAM 冲突（policy 只有 UpdateItem，`test_sites_table_has_no_putitem` 全表禁 PutItem）——本地 moto 全绿、线上建站全挂 | **接受**（上一轮修复引入的真实部署回归——"加固动作自己带缺陷"第 N 次）：`create_site_record` 改**单次条件 UpdateItem**（`attribute_not_exists(site_id)` + 一次 SET 全字段，原子性与条件 PutItem 等价）；新增 Step 5b：`SITE_WRITABLE_ATTRIBUTES` 加 `created_at` + contract test 复核 + Task 13 真机 IAM 探针 | Task 5 Step 4/5b、Task 13 概要 ② |
| R2 | contract venv 无 boto3/botocore，Task 3 测试 collection 即挂（实测确认）；且 `test_alarm_params_match_current_environment` 自铺 stub 序列漏了新加的 create_log_group | **接受**（两个独立错误都成立，实测复核一致）：新增 Task 3 Step 0 给 contract venv 补 boto3（照 PyJWT 当年同模式）+ 更新 CLAUDE.md venv 注释；该用例改走 `_stub_common`（调用序列只维护一处） | Task 3 Step 0/1、CLAUDE.md |
| R3 | Task 11 的"console 首页 200"验收在其执行阶段不可能成立（与 Task 10 并行、前端在 Task 14）——会把正确的 IAM 修复误判失败 | **接受**（采纳其方案二）：Task 11 改用临时 `platform/probe-*` 对象 + 临时 probe route 只验 S3 IAM（trap 清理 + 读回核对）；console 首页端到端移到 Task 14/13 | Task 11 概要 ③、Task 13 概要 ③ |
| R4 | Task 5 回填到 Task 13 部署新 MCP 之间，旧 MCP 建的新站点仍缺 created_at，Step 15 覆盖率过期 | **接受**（采纳其方案二——先部署 MCP 会把 Task 13 的部署拆散）：Task 13 部署 MCP 后强制第二轮回填（dry-run→apply→读回），最终 E2E 前除 `无 job 跳过` 外零缺失 | Task 13 概要 ① |
| R5 | panel 照抄 auth 的 `parameter/site-builder/*` 前缀过宽——顺带能读 site-client-secret | **接受**：收窄到精确 `parameter/site-builder/jwt-secret` ARN；spec 与 plan 同步改写为"机制照抄、资源不照抄"，contract test 断言出现前缀即 FAIL | spec §2/§5.4、Task 7 概要 ③、文件表 |
| R6 | 验收脚本第一遍带 `--region` 查到 `$LIVE` 后丢弃，python 里重查不带 region——默认 region 不同时假失败/比错对象 | **接受**（本机默认恰是 us-east-1 所以没炸，但缺陷真实）：`$LIVE` 作为 argv 传给 python 复用，不二次调 aws CLI（heredoc 占 stdin，故用 argv 不用管道） | Task 4 Step 3 |
| R7 | retention 90→30 会删 30-90 天历史日志（72h 内物理删除），回滚说明"最坏是描述/阈值被改写"失真，且不该称"顺手" | **接受**：回滚锚点补导出 retention 现值；Step 4 部署门禁加"确认历史日志无保留需要（或先导出）"；回滚方式写明 retention 改回**不可恢复已删日志**；`alarm_pipeline.py` 注释从"顺手收敛"改为"有意的数据修剪 + 门禁确认" | Task 4 Step 4、Task 3 Step 3 注释 |

**对第二轮两个非 finding 结论的回应**：①"本提交只改 Spec/Plan 未实现代码"——符合预期：当前在计划阶段（brainstorm→spec→plan→自审→实施），代码属 Task 1 起的实施阶段，计划文档就是本阶段的交付物；②"Task 6-16 仍不是完整计划"——立场同上轮 F4：分阶段展开是显式声明的交付方式，展开门禁（Task 5 Step 13-15 真机产出）已闭环，实施顺序上 Task 1-4 先行、展开发生在 Task 5 之后，不阻塞开工。
