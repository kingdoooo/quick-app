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
| `site-builder/panel/console_session.py` | 一次性 upgrade code 的签发校验（HMAC + 60s + 绑 email + context 标记 + jti 原子消费）与 `__Host-sb_console` cookie 构造 |
| `site-builder/panel/ops_log.py` | ops-log 写入（append-only，PutItem only，字段脱敏） |
| `site-builder/panel/deploy_panel.py` | 幂等部署脚本：Lambda + Function URL(AWS_IAM 仅 edge role) + panel role + 前端上传 S3 + console route 注册 |
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
| `site-builder/auth/session.py` | 无算法改动；确认 `mint_session_jwt(scope=...)` 已可用（M1 已加） |
| `site-builder/deployer/functions/common.py` | 加 `list_jobs_by_site`（用新 `site-index` GSI）；`upsert_site` 首次部署路径写 `created_at` |
| `site-builder/mcp/server.py` | `do_deploy_site` 建站分支写 `created_at` |
| `site-builder/deployer/functions/permissions.py` | 五个高层写函数 + undeploy 路径内落 ops-log（唯一落点） |
| `site-builder/mcp/deploy_agentcore.py` | MCP runtime role 补 `site-ops-log` PutItem |
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
Expected: PASS（21 个用例：2 + 9 + 3 + 1 + 1 + 1 + 1 + 4 sweeper）

- [ ] **Step 5: 反向验证——确认测试在缺陷存在时会红**

三处各改一次，每次跑测试确认 FAIL，然后**还原**：

1. 把 `ConditionExpression` 里的 `attribute_exists(job_id) AND ` 删掉 →
   Run: `.venv/bin/pytest tests/test_reconcile_job.py::test_absent_job_is_not_created -q`
   Expected: **FAIL**（凭空建了 job）
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
带 attribute_exists(job_id) 防 UpdateItem 凭空建行。21 个用例含反向验证。"
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


def test_reconciler_role_is_narrow(template):
    """不得复用 exec_role：只允许 jobs 表条件更新 + DescribeExecution + 日志。"""
    policies = _resources(template, "AWS::IAM::Policy")
    recon = [p for p in policies.values()
             if "states:DescribeExecution" in str(p["Properties"])]
    assert len(recon) == 1, "reconciler 应有独立的 inline policy"
    doc = str(recon[0]["Properties"]["PolicyDocument"])
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
Expected: FAIL —— 7 个用例全红（无 Events::Rule、无 SQS、handler 不存在）

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
        f_sweep.add_alias  # noqa: B018  (占位：无别名，保持对象被引用)

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

**注意**：删掉上面 `f_sweep.add_alias  # noqa` 那一行（它只是提醒，不要留在代码里）。

- [ ] **Step 4: 运行 CDK 断言测试确认通过**

Run:
```bash
cd site-builder/deployer && \
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_reconciler.py -q
```
Expected: PASS（7 个用例）

- [ ] **Step 5: 反向验证 CDK 断言**

1. 把 rule 的 `detail` 里 `"stateMachineArn": [sm.state_machine_arn]` 删掉 →
   Expected: `test_rule_matches_only_terminal_statuses_of_this_state_machine` **FAIL**
2. 把 `recon_role` 换成 `exec_role` →
   Expected: `test_reconciler_role_is_narrow` **FAIL**
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

**Interfaces:**
- Consumes: `config.ini` 的 `[Alerting] email`（gitignored）或环境变量 `SB_ALERT_EMAIL`
- Produces:
  - `ensure_alarm_pipeline(*, region, log_group, namespace, metric_name, filter_name, filter_pattern, topic_name, alarm_name, email, account_id) -> dict`
    —— 返回 `{"topic_arn", "subscription_state", "alarm_name", "changed": [...]}`；`subscription_state` ∈ `{"confirmed", "pending", "absent"}`
  - `ALARM_DESCRIPTION` —— 中英双语 AlarmDescription 常量
  - `ALARM_PARAMS` —— 阈值参数常量（Sum/300/2/1/GreaterThanOrEqualToThreshold/notBreaching）

**为什么真源选 `deploy_auth.py` 而不是 CDK**：告警监控的就是 `deploy_auth.py` 部署的那个 Lambda 的日志组，同一脚本声明全部配套资源、生命周期一致；CDK 方案要跨体系引用日志组、email 还得新开 context 通道并会进 `cdk.out` 模板。**文档中不称其为 IaC**，称"幂等声明式 provisioning"。

**为什么必须自动化**：现网这套（metric filter + SNS topic + alarm + 双语描述 + Alarm/OK actions）是**手工建的**——只跑现有部署脚本不会收敛出它，"从零部署"得不到相同环境。

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


def _stub_common(stubs, *, subs, sub_result=None):
    """公共调用序列：metric filter upsert → topic upsert → 列订阅 → alarm upsert"""
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
    且 ALARM 与 OK 通知同一 topic。"""
    logs, sns, cw, stubs = clients
    stubs["logs"].add_response("put_metric_filter", {})
    stubs["sns"].add_response("create_topic", {"TopicArn": TOPIC_ARN})
    stubs["sns"].add_response("list_subscriptions_by_topic", {"Subscriptions": [
        {"Protocol": "email", "Endpoint": "ops@example.com",
         "SubscriptionArn": TOPIC_ARN + ":abc"}]})
    captured = {}
    stubs["cw"].add_response("put_metric_alarm", {}, captured)
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
Expected: PASS（7 个用例）

- [ ] **Step 5: 反向验证**

1. 把 `if not (email or "").strip(): raise` 改成 `return {...}` 静默跳过 →
   Expected: `test_empty_email_raises_instead_of_silently_skipping` **FAIL**
2. 把"先 list 再 subscribe"改成无条件 `sns.subscribe(...)` →
   Expected: `test_confirmed_subscription_is_not_recreated` **FAIL**（Stubber 报未预期的 subscribe 调用）
3. 把 `ALARM_DESCRIPTION` 里"告警解除"改成"已恢复" →
   Expected: `test_alarm_description_is_bilingual_and_says_alarm_cleared` **FAIL**

三处还原，重跑 PASS。

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
Expected: PASS（原有 105 基线 + 7 新增）

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
  python3 - "$DECLARED" <<'PY' || FAILURES=$((FAILURES + 1))
import json, subprocess, sys
declared = json.loads(sys.argv[1])
live = json.loads(subprocess.run(
    ["aws", "cloudwatch", "describe-alarms", "--alarm-names",
     "site-builder-auth-invalid-grant", "--output", "json"],
    capture_output=True, text=True, check=True).stdout)["MetricAlarms"]
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
# ALARM 与 OK 必须通知同一 topic，且都非空
if not a.get("AlarmActions") or a.get("AlarmActions") != a.get("OKActions"):
    bad.append(f"AlarmActions={a.get('AlarmActions')} OKActions={a.get('OKActions')}")
if bad:
    print("  FAIL  线上 alarm 与声明值漂移：")
    for b in bad:
        print(f"          {b}")
    sys.exit(1)
print("  PASS  线上 alarm 配置 == alarm_pipeline.py 声明值（含双语描述与 OK actions）")
PY
fi

# ── SNS 订阅必须**已确认**（PendingConfirmation 不算） ─────────────────
TOPIC="$(aws sns create-topic --region "$REGION" --name site-builder-alarms \
           --query TopicArn --output text 2>/dev/null || echo '')"
if [ -z "$TOPIC" ] || [ "$TOPIC" = "None" ]; then
  echo "  FAIL  无法解析 SNS topic ARN"
  FAILURES=$((FAILURES + 1))
else
  CONFIRMED="$(aws sns list-subscriptions-by-topic --region "$REGION" \
                 --topic-arn "$TOPIC" \
                 --query "length(Subscriptions[?Protocol=='email' && starts_with(SubscriptionArn, 'arn:')])" \
                 --output text 2>/dev/null || echo 0)"
  if [ "${CONFIRMED:-0}" -ge 1 ]; then
    echo "  PASS  SNS email 订阅已确认（${CONFIRMED} 个）"
  else
    echo "  FAIL  没有已确认的 email 订阅——alarm 会进 ALARM 但无人收到通知"
    echo "        （PendingConfirmation 不算：收件人必须点确认链接）"
    FAILURES=$((FAILURES + 1))
  fi
fi
```

同时把脚本的最小检查数下限相应提高（当前值 + 5）。

- [ ] **Step 4: [真机] 跑 `deploy_auth.py` 收编现网资源**

**部署门禁**：Step 2 全绿；`config.ini` 的 `[Alerting] email` 已填真实邮箱（gitignored）。

**回滚锚点**：先导出现网配置：
```bash
aws cloudwatch describe-alarms --alarm-names site-builder-auth-invalid-grant \
  --output json > /tmp/alarm-before.json
aws logs describe-metric-filters --log-group-name /aws/lambda/site-auth-service \
  --output json > /tmp/filter-before.json
aws sns list-subscriptions-by-topic \
  --topic-arn "$(aws sns create-topic --name site-builder-alarms --query TopicArn --output text)" \
  --output json > /tmp/subs-before.json
```
**回滚方式**：`aws cloudwatch put-metric-alarm` 用 `/tmp/alarm-before.json` 的值还原（或直接 `git revert` 后重跑脚本）。收编是同名 upsert，不删除任何资源——订阅不会丢，最坏是描述/阈值被改写，可用备份还原。

Run: `cd site-builder/auth && python3 deploy_auth.py`
Expected: 输出含 `告警管道已收敛：metric_filter, alarm`（订阅已存在时不含 `subscription`），且**不**出现 `⚠️ email 订阅状态`（因为现网订阅已确认）。

- [ ] **Step 5: [真机] 跑扩展后的 `verify_auth_alarm.sh`**

Run: `SNS_TOPIC_ARN="$(aws sns create-topic --name site-builder-alarms --query TopicArn --output text)" ./site-builder/scripts/verify_auth_alarm.sh`
Expected: 全部 PASS，含新增两项（`线上 alarm 配置 == 声明值`、`SNS email 订阅已确认`），探针 alarm 清理确认。

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
- Modify: `site-builder/deployer/functions/common.py`（`list_jobs_by_site`；`created_at` 写入）
- Modify: `site-builder/mcp/server.py`（`do_deploy_site` 建站分支写 `created_at`）
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
def create_site_record(site_id: str, **attrs) -> None:
    """**首次**建站：写入 created_at 后调 upsert_site。

    created_at 只在建站那一刻有意义，所以单独一个入口而不是塞进 upsert_site
    （后者被部署链多处调用，每次都写会把创建时间刷成最后一次部署时间）。
    条件是"该属性不存在"——重复调用不覆盖。
    """
    _table("SITES_TABLE").update_item(
        Key={"site_id": site_id},
        UpdateExpression="SET created_at = :t",
        ConditionExpression="attribute_not_exists(created_at)",
        ExpressionAttributeValues={":t": _now()})
    if attrs:
        upsert_site(site_id, **attrs)
```

**注意**：条件失败会抛 `ConditionalCheckFailedException`——`create_site_record` 需要捕获它并继续（已有 created_at 是正常情况）。实现时用 try/except `ClientError` 判 `ConditionalCheckFailedException` 后 `pass`。

- [ ] **Step 5: `mcp/server.py` 建站分支改用 `create_site_record`**

把 `do_deploy_site` 里的
```python
        common.upsert_site(site_id, owner=owner, name=site_name, status="DEPLOYING")
```
改为
```python
        # create_site_record 而非 upsert_site：首次建站要写 created_at
        # （控制台显示创建时间；条件写，重复调用不覆盖）。
        common.create_site_record(site_id, owner=owner, name=site_name,
                                  status="DEPLOYING")
```

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
Expected: 两处均 PASS（deployer 新增 5 用例，mcp 无回归）

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

三处还原，重跑 PASS。

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
- create_site_record()：首次建站条件写 created_at（不塞进 upsert_site——
  它被部署链多处调用，每次都写会把创建时间刷成最后一次部署时间）
- backfill_site_created_at.py：从最早一条 job 推导；**无 job 不猜**（写 now
  是错日期且看不出是猜的），报告后跳过。默认 dry-run"
```

---

> **Task 6-16 的详细步骤**：本计划已覆盖两个 Blocking 前置（Task 1-4，可立即
> 开始实施）与 M3 数据层（Task 5）。Task 6-16 的接口契约、文件清单与验收标准
> 已在上方「文件结构」「任务顺序与依赖」与 spec
> `2026-08-09-phase2-m3-console-spec.md` 中锁定，逐步骤展开在 Task 5 完成后
> 追加——避免在数据层真机验证前把 panel 的 handler 签名写死（`site-index`
> GSI 的真机查询形态、`created_at` 回填的实际覆盖率会影响 `/api/sites` 与
> `/api/sites/{id}/jobs` 的响应契约）。
>
> **Task 6-16 概要**（每个任务的 Files / Interfaces / 验收标准）：
>
> - **Task 6 panel 授权与 API 纯函数**：`panel/api.py` 的 do_* 层 + `tests/test_authz.py`（owner/collaborator/outsider/admin × 各端点矩阵）+ `tests/test_no_handwritten_guards.py`（AST 扫描：panel 不得出现手写 UpdateExpression、角色字符串比较、admins raw 写）。授权 100% 走 `permissions.assert_can` / 高层写函数。
> - **Task 7 console-session + CSRF**：`panel/console_session.py`（HMAC code 签发校验、60s、绑 email、context 标记 `typ:"console-upgrade"`、jti 条件写 `site-session-codes` 原子消费）+ `tests/test_csrf.py`（**副作用前置顺序断言**：mock DynamoDB 客户端，验证 CSRF 失败路径下零写调用）。
> - **Task 8 ops-log 落点**：`permissions.py` 五个高层写函数 + undeploy 路径内落 ops-log（唯一落点，MCP 与控制台自动同轮覆盖）+ `panel/ops_log.py`（PutItem only、字段脱敏）+ `mcp/deploy_agentcore.py` 补 ops-log PutItem。
> - **Task 9 panel handler 组装**：`panel/handler.py` 路由分发 + 五步前置校验顺序 + 错误码（401 `{"need":"console-session"}` / 403 / 409）。
> - **Task 10 `deploy_panel.py`**：Lambda + Function URL(AWS_IAM 仅 exact edge role 双语句，缺 edge_role_arn 抛错) + panel role（表清单见 spec §2，路由表**仅** UpdateItem）+ 前端上传 + console route 注册 + contract test 断言 role/policy。
> - **Task 11 Edge console 白名单**：`PLATFORM_SUBDOMAINS` 加 `console`、`RESERVED_COOKIES` 加两个 `__Host-`（两文件同步）+ 伪造 platform route 负测 + `verify_deployed_edge.sh` 断言产物含新值与 CloudFront 实际关联版本。
> - **Task 12 auth `/console-session`**：校验顶域 `sb_session` → 签发 code → 302 到 console callback；`__Host-sb_pkce` 与新 cookie 的作用域测试。
> - **Task 13 三层部署 + `verify_deployed_components.py`**：重构自 `verify_contract_fixtures.py`（7 段，旧脚本删除、文档引用同步），部署 deployer/Edge/auth/panel/MCP 并逐一核对产物。
> - **Task 14 前端移植 + panel E2E**：原型视图层进 `panel/frontend/`（去敏感值、`window.API` 换真 fetch、M4/M5 入口 disabled、PHASE_LABEL 按 jobs 表真实词表重写、undeploy 改轮询、FAILED 展示层派生）+ spec §7 的 13 项 E2E 全覆盖。
> - **Task 15 fixture 自动清理**（可与 6-14 并行，**必须在 Task 16 前完成**）：`smoke_router.sh` 随机后缀 + trap + 只删本次 + 强一致读回 + 最小断言数 + `--keep-on-failure`；`test_e2e_fixtures.py` finalizer（记录本次 site_id/job_id、默认 undeploy + purge、清理失败即测试失败、禁按 owner 批量删）。
> - **Task 16 全量回归与文档收尾**：五个包测试 + 七个真机闸门 + `DEPLOY.md` 新阶段 + `CLAUDE.md` 同步（panel venv 归属、验收脚本改名、`deploy_panel.py` 部署命令）+ `progress.md` + HANDOFF 更新 6。

---

## Self-Review 结论

**1. Spec 覆盖**：phase2 spec §11-pre.1（Task 1-2）、§11-pre.2（Task 3-4）、§11-pre.3（Task 15）、§11-pre.4（Task 13）；M3 spec §2 平台约束（Task 10）、§3 前端（Task 14）、§4 接口映射（Task 6/9）、§4.1 四个缺口（Task 5 的 created_at 与 Task 14 的 FAILED 派生/phase 词表/undeploy 轮询）、§5.1-5.5 安全硬约束（Task 6/7/8/10/11）、§6 资源清单（Task 5/10）、§7 测试硬约束（各任务的反向验证步骤 + Task 13/14）。**无遗漏**。

**2. 占位符扫描**：Task 1-5 的每个代码步骤都有可直接落地的完整代码；Task 6-16 是**明示的分阶段展开**（附完整 Files/Interfaces/验收标准），不是 "TBD"——理由已写明（数据层真机形态影响 panel 响应契约）。

**3. 类型一致性**：`converge_job_to_failed` 在 Task 1 定义、Task 2 的 CDK handler 引用一致；`list_jobs_by_site` / `create_site_record` 在 Task 5 定义，Task 6/14 消费；`ensure_alarm_pipeline` 在 Task 3 定义、Task 4 消费，参数名逐一对应；`ALARM_PARAMS` / `ALARM_DESCRIPTION` 在 Task 3 定义、Task 4 的验收脚本 import 同名。
