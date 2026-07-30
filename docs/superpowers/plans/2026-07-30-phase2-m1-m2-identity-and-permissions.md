# Site Builder 二期 M1+M2 实施计划（身份层切换 + 权限真源）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把平台身份切到专用 Cognito user pool（含 PKCE/nonce 增强），并把站点权限的唯一真源从"site.json + 路由表"迁移到 sites 表，使"在线改权限 / 协作者 / 所有权转移"端到端可用且不再需要重部署。

**Architecture:** 三层改造。① 身份层新建 `site-builder-users` pool（IdP 无关但**禁本地用户**：关自注册 + 生产 client 只列企业 IdP，3 个 app client），pre-token 注入 email + `idp` claim，auth 服务加 PKCE + nonce；② 数据层给 `site-sites` 表加权限字段、`permissions_rev` 与 `owner-index` GSI，新增 `permissions.py` 作为唯一角色判定与权限写入模块——权限写入统一走 `write_permissions`（`TransactWriteItems` 两表原子），MCP 与后续 panel 共用（沿用 `common.py` 的构建时复制模式）；③ 消费层改 `register_route`（权限来自 sites 表并输出 effective policy）、`smoke_test`（读 effective policy）、`mark_job`（不再写 owner）、Edge（collaborators 放行 + List 反序列化）、MCP（角色判定替换 `_assert_owner` + 3 个新工具）。存量站点用一次性脚本从路由表回填 sites 表（损坏数据报错跳过，不扩权）。

**Tech Stack:** Python 3.13（Lambda/MCP）、Python 3.11（Lambda@Edge）、boto3、DynamoDB、Cognito、CDK（router + deployer 两个栈）、pytest + moto、AgentCore Runtime。

## Global Constraints

以下约束来自 spec 与仓库 CLAUDE.md，**每个任务都隐含包含**：

- **区域**：一切资源在 `us-east-1`（Lambda@Edge / ACM / Quick 身份区域硬约束）。
- **配置唯一来源**：`site-builder/config.ini` 与 `router/config.ini`（均 gitignored，从同目录 `.example` 复制）。代码不硬编码账号 ID / 域名。**不要把真实账号值（如 12 位账号 ID、真实域名）写进任何被 git 跟踪的文件**——`.example` 里一律用 `000000000000` / `example.com`。
- **测试命令按包区分 venv**（照抄，别猜）：
  - `cd site-builder/contract && .venv/bin/pytest tests -q`
  - `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`（auth 无自己的 venv，借 contract 的）
  - `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`（router 的 .venv 只有 CDK 依赖，借 deployer 的）
  - `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests`**，裸 pytest 会误收集 `infra/cdk.out` 里的 asset 副本）
  - `cd site-builder/mcp && python3 -m pytest tests -q`
- **Edge 函数约束**：Lambda@Edge 不支持环境变量，配置由 CDK synth 时字符串替换 `{{PLACEHOLDER}}` 注入；单文件、零第三方依赖（只用运行时自带 boto3/botocore + 标准库）；1MB 代码上限；`origin_request.py` 的 `_verify_session_jwt` 与 `site-builder/auth/session.py` 的 HS256 算法**必须字节等价**。
- **Edge 路由表投影只认已支持的 DynamoDB 类型**：本计划 Task 8 之前 `_deser` 只认 `S`/`BOOL`，新增任何 `L`/`N`/`SS` 字段前必须先扩展 `_deser`，否则 Edge 侧静默变成 `False`。
- **Function URL 一律 `AuthType=AWS_IAM`** 且只授权 edge role，并且需要 `lambda:InvokeFunctionUrl` + `lambda:InvokeFunction`（`InvokedViaFunctionUrl`）**两条**语句，缺一即 403。`AuthType=NONE` + `Principal:*` 会被安全扫描自动处置。
- **git**：改动分批提交；`git push` 一律带 `--no-verify`。提交信息用中文或英文均可，遵循仓库现有 `type(scope): subject` 风格。
- **每次 commit 前必须扫 staged diff**（`~/AGENTS.md` 的全局要求，适用于每个仓库的每次提交，"看起来显然安全"也要扫）。**顺序很重要**：`git diff --cached` 只看已 stage 的内容，所以必须 **`git add` 之后、`git commit` 之前**扫——放在 `git add` 前扫的是空 stage，永远报 clean，等于没扫。本计划每个提交步骤都是这个顺序：
  ```bash
  git add <files>
  git diff --cached | grep -nE 'AKIA|ASIA|ghp_|gho_|xoxb-|xoxp-|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=|/Users/[a-z]+/|[0-9]{12}' \
    && echo "⚠️ 上面是命中项，逐条确认是否为故意的 fixture/占位符后再提交" \
    || echo "secret scan: clean"
  git commit -m "..."
  ```
- **新文件首次 `git add` 之前**另扫一遍文件本体（`git diff` 看不到未跟踪文件）：
  ```bash
  grep -nE '<同上模式>' <新文件路径...> || echo "new-file scan: clean"
  ```
- 命中不等于必须改——公开 URL、测试 fixture、co-author trailer 都会命中。**必须先给用户看命中项再提交，不要自动清洗**。本计划里可预期的命中：`*@x.com` 假邮箱、`000000000000` 占位账号、`ProbeOnly!2026x` 探测口令、`client_secret =` 空配置项——这些是刻意写的，确认即可。
- **push 前**（若已过提交点）对待推送的 commit 再扫一次：`git diff origin/<branch>...HEAD | grep -nE '<同上模式>'`。
- **验证纪律**：每处改动用真实 AWS API 实证验证（本项目被 mock 掉的层出过多次问题）。计划中标 `[真机]` 的步骤必须在真实 AWS 上跑，不能只靠 moto。
- **发现文档与实际不符就同步更新**（`site-builder/DEPLOY.md`、`docs/` 下相关文档、`CLAUDE.md`）。
- **`allowed_users` 语义**：`"org"`（字面量字符串）或邮箱数组。sites 表里存原生 List；路由表投影里 `"org"` 存 `S`、名单存 `L`（Task 8 起）。
- **`"org"` 的安全前提**（spec §3.5）：Edge 对 org 的判定只是"持有有效平台会话"，不查邮箱域。因此平台 pool **必须**关自注册（`AllowAdminCreateUserOnly=True`）且生产 client 只列企业 IdP（不含 `COGNITO`）。任何放宽这两条的改动都等于把全部 org 站点对公网开放。
- **权限写入只走一个入口**：`permissions.write_permissions`（`TransactWriteItems` 两表原子）。**不要**在别处写"先改 sites 再同步路由"的顺序两写——收紧权限时第二步失败会留下 sites 已私有、Edge 仍公开的安全状态错误。
- **fail-closed 优先**：权限相关的解析/判定失败一律取最严格解释（空名单、按未登录处理、报错跳过），绝不"取最宽松的默认值继续"。
- **角色语义（两级 + admin）**：owner 可做全部操作；collaborator 可部署更新 / 查状态 / 看统计 / 改 `require_login` 与 `allowed_users`；仅 owner（或 admin）可增删 collaborator、转移 owner、undeploy/purge。admin 对任意站点等价 owner。

---

## 文件结构

**新建：**

| 文件 | 职责 |
|---|---|
| `site-builder/deployer/functions/permissions.py` | 唯一的角色判定 + 权限读写模块（纯逻辑 + DynamoDB 访问）。MCP 与 panel 共用（构建时复制，同 `common.py`） |
| `site-builder/deployer/tests/test_permissions.py` | `permissions.py` 的角色矩阵与权限写入测试 |
| `site-builder/scripts/migrate_permissions.py` | 一次性迁移：路由表 → sites 表回填权限字段 |
| `site-builder/scripts/deploy_pool.py` | 幂等创建/更新平台专用 user pool + 3 个 app client + pre-token 触发器挂载 |
| `site-builder/auth/tests/test_pkce.py` | PKCE/nonce 的 state 编解码与 callback 校验测试 |
| `site-builder/auth/tests/test_pre_token.py` | pre-token 触发器注入 email/idp claim 的测试 |
| `site-builder/deployer/tests/test_migrate_permissions.py` | 迁移脚本测试（含"损坏名单不扩权"） |

**修改：**

| 文件 | 改动 |
|---|---|
| `site-builder/auth/login_handler.py` | `/login` 生成 code_verifier + nonce 进签名 state；`/callback` 带 verifier 换 token、验 id_token 的 nonce |
| `site-builder/auth/deploy_auth.py` | pre-token 触发器支持传 pool_id；**StatementId 按 pool 区分**（固定 id + 吞冲突会让新 pool 授权加不上） |
| `site-builder/config.ini.example` | `[Cognito]` 加 `machine_client_id`；`[Platform]` 加 `admin_seed`；`[Deployer]` 加 `admins_table` |
| `site-builder/deployer/infra/app.py` | sites 表加 `owner-index` GSI；新增 `site-admins` 表；exec role 权限相应扩展 |
| `site-builder/deployer/functions/register_route.py` | 权限字段从 sites 表读（不再从 manifest）；首次部署时用 manifest 初始化；输出 `effective_auth` 供 smoke_test |
| `site-builder/deployer/functions/mark_job.py` | **不再写站点 owner**（否则 collaborator 部署一次即夺权，Task 5a） |
| `site-builder/deployer/functions/smoke_test.py` | 读 `effective_auth` 而非 manifest（Task 5b） |
| `site-builder/auth/pre_token_email.py` | 额外注入 `idp` claim（org 语义的**主防线**数据来源，两个 token 容器都写） |
| `site-builder/deployer/functions/common.py` | 加 `list_sites_by_owner`（用新 GSI） |
| `router/infrastructure/lambda/origin_request.py` | `_deser` 支持 `L`；`_check_auth` 放行 collaborators；`allowed_users` 兼容 List 与 JSON 字符串两种形态 |
| `router/infrastructure/lambda/test_edge_auth.py` | 新增 collaborators / List 形态用例 |
| `site-builder/mcp/server.py` | `_assert_owner` → `permissions` 角色判定；新增 3 工具；`do_list_sites` 用 GSI + collaborator 维度 |
| `site-builder/mcp/deploy_agentcore.py` | IAM 加 admins 表与 sites GSI；工具数变化 |
| `site-builder/mcp/Dockerfile` | `COPY` 加 `permissions.py` |
| `site-builder/mcp/tests/test_agentcore_contract.py` | 工具数断言 5 → 8 |
| `site-builder/mcp/tests/conftest.py`、`site-builder/deployer/tests/conftest.py` | sites 表加 GSI 定义；新增 admins 表 |
| `site-builder/skills/site-builder/references/contract.md` | 写明 `auth` 字段仅首次部署生效、之后以控制台为准 |
| `site-builder/DEPLOY.md` | ① 阶段改写为 IdP 无关两分支 + 新 pool 部署步骤；加迁移脚本步骤 |

---

## Task 1: `permissions.py` — 角色判定纯逻辑

**Files:**
- Create: `site-builder/deployer/functions/permissions.py`
- Test: `site-builder/deployer/tests/test_permissions.py`

**Interfaces:**
- Consumes: `common.get_site(site_id)`（已存在，返回 dict 或 None）
- Produces:
  - `ROLE_OWNER = "owner"`, `ROLE_COLLABORATOR = "collaborator"`, `ROLE_ADMIN = "admin"`, `ROLE_NONE = "none"`
  - `role_of(email: str, site: dict | None, is_admin: bool = False) -> str`
    （判定顺序 **owner → admin → collaborator**，见 Step 3 注释）
  - `can(role: str, action: str) -> bool`；`action` ∈ `{"deploy", "read", "set_access_policy", "manage_collaborators", "transfer_owner", "undeploy"}`
  - `class PermissionDenied(Exception)`、`class PermissionConflict(Exception)`
  - `assert_can(email: str, site: dict | None, action: str, *, is_admin: bool = False, what: str = "") -> str`（返回 role，失败抛 `PermissionDenied`）

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_permissions.py`：

```python
import pytest

import permissions as perm


SITE = {"site_id": "s-1", "owner": "o@x.com", "collaborators": ["c@x.com"]}


def test_role_of_owner():
    assert perm.role_of("o@x.com", SITE) == perm.ROLE_OWNER


def test_role_of_collaborator():
    assert perm.role_of("c@x.com", SITE) == perm.ROLE_COLLABORATOR


def test_role_of_outsider():
    assert perm.role_of("x@x.com", SITE) == perm.ROLE_NONE


def test_admin_flag_wins_over_outsider():
    assert perm.role_of("adm@x.com", SITE, is_admin=True) == perm.ROLE_ADMIN


def test_owner_is_not_downgraded_by_admin_flag():
    # owner 本人同时是 admin 时报 owner——审计与文案更准确，权限集相同
    assert perm.role_of("o@x.com", SITE, is_admin=True) == perm.ROLE_OWNER


def test_admin_who_is_also_collaborator_gets_admin():
    """判定顺序必须 owner→admin→collaborator。

    若 collaborator 先匹配，这个平台管理员会失去 undeploy / 转移所有权的
    能力——admin 身兼某站点协作者很常见（先是协作者、后被提为管理员），
    不能因此被降权。
    """
    assert perm.role_of("c@x.com", SITE, is_admin=True) == perm.ROLE_ADMIN


def test_admin_collaborator_can_undeploy():
    role = perm.role_of("c@x.com", SITE, is_admin=True)
    assert perm.can(role, "undeploy") is True


def test_role_of_missing_site_is_none():
    assert perm.role_of("o@x.com", None) == perm.ROLE_NONE


def test_missing_collaborators_field_defaults_empty():
    assert perm.role_of("c@x.com", {"site_id": "s", "owner": "o@x.com"}) == perm.ROLE_NONE


@pytest.mark.parametrize("action,expected", [
    ("read", True), ("deploy", True), ("set_access_policy", True),
    ("manage_collaborators", False), ("transfer_owner", False), ("undeploy", False)])
def test_collaborator_capabilities(action, expected):
    assert perm.can(perm.ROLE_COLLABORATOR, action) is expected


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_owner_can_everything(action):
    assert perm.can(perm.ROLE_OWNER, action) is True


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_admin_can_everything(action):
    assert perm.can(perm.ROLE_ADMIN, action) is True


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_none_can_nothing(action):
    assert perm.can(perm.ROLE_NONE, action) is False


def test_unknown_action_denied_for_everyone():
    # 未知动作一律拒绝（fail-closed）：新增动作忘记登记时不会被静默放行
    assert perm.can(perm.ROLE_OWNER, "launch_missiles") is False


def test_assert_can_returns_role():
    assert perm.assert_can("c@x.com", SITE, "deploy") == perm.ROLE_COLLABORATOR


def test_assert_can_raises_for_outsider():
    with pytest.raises(perm.PermissionDenied):
        perm.assert_can("x@x.com", SITE, "read", what="站点 s-1")


def test_assert_can_raises_for_missing_site():
    with pytest.raises(perm.PermissionDenied):
        perm.assert_can("o@x.com", None, "read", what="站点 s-9")
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'permissions'`

- [ ] **Step 3: 写最小实现**

创建 `site-builder/deployer/functions/permissions.py`：

```python
"""站点权限的唯一判定与写入模块。

真源是 sites 表（site-sites）：owner / collaborators / require_login /
allowed_users 全部以此为准；路由表只是给 Edge 读的投影（见 write_permissions）。
MCP（site-builder/mcp/）与控制台（site-builder/panel/）都引入本模块，
两处的授权语义因此不会漂移——新增受控动作时只改 CAPABILITIES。
"""

ROLE_OWNER = "owner"
ROLE_COLLABORATOR = "collaborator"
ROLE_ADMIN = "admin"
ROLE_NONE = "none"

# 动作 → 允许的角色集合。未登记的动作对所有人拒绝（fail-closed）。
CAPABILITIES = {
    "read": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "deploy": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "set_access_policy": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "manage_collaborators": {ROLE_OWNER, ROLE_ADMIN},
    "transfer_owner": {ROLE_OWNER, ROLE_ADMIN},
    "undeploy": {ROLE_OWNER, ROLE_ADMIN},
}


class PermissionDenied(Exception):
    pass


class PermissionConflict(Exception):
    """并发修改：读到的 permissions_rev 已被别人推进。调用方转 409 提示重试。"""
    pass


def role_of(email: str, site: dict | None, is_admin: bool = False) -> str:
    """判定顺序 owner → admin → collaborator。

    admin 必须排在 collaborator 之前：管理员身兼某站点协作者时若返回
    collaborator，他就拿不到 undeploy / transfer_owner（CAPABILITIES 里
    collaborator 没有这两项）——等于被自己的协作者身份降权。
    审计要区分"owner 本人"与"admin 代管"时用单独的 is_admin 标志，
    不要从角色字符串反推。
    """
    if not site:
        return ROLE_NONE
    if email and email == site.get("owner"):
        return ROLE_OWNER
    if is_admin:
        return ROLE_ADMIN
    if email and email in (site.get("collaborators") or []):
        return ROLE_COLLABORATOR
    return ROLE_NONE


def can(role: str, action: str) -> bool:
    return role in CAPABILITIES.get(action, frozenset())


def assert_can(email: str, site: dict | None, action: str, *,
               is_admin: bool = False, what: str = "") -> str:
    role = role_of(email, site, is_admin)
    if not can(role, action):
        target = what or "该站点"
        if role == ROLE_NONE:
            raise PermissionDenied(f"你无权访问 {target}")
        raise PermissionDenied(f"{target}：{role} 角色无权执行 {action}")
    return role
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: PASS（22 passed）

- [ ] **Step 5: 提交**

```bash
git add site-builder/deployer/functions/permissions.py site-builder/deployer/tests/test_permissions.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(permissions): 角色判定模块（owner/collaborator/admin 两级+管理员）"
```

---

## Task 2: `permissions.py` — admin 名单与权限写入

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py`
- Modify: `site-builder/deployer/tests/test_permissions.py`
- Modify: `site-builder/deployer/tests/conftest.py`（加 `site-admins` 表 + `ADMINS_TABLE` env）

**Interfaces:**
- Consumes: Task 1 的 `role_of` / `assert_can` / `PermissionDenied`；`common.upsert_site`、`common.get_site`
- Produces:
  - `is_admin(email: str) -> bool`（读 `ADMINS_TABLE` 环境变量指向的表）
  - `list_admins() -> list[str]`
  - `add_admin(email: str, added_by: str) -> None`
  - `remove_admin(email: str) -> None`（拒绝删空，抛 `PermissionDenied`）
  - `set_access_policy(site_id, *, actor, require_login=None, allowed_users=None) -> dict`
  - `set_collaborators(site_id, *, actor, add=None, remove=None) -> list[str]`
  - `transfer_owner(site_id, *, actor, new_owner) -> dict`
  三者都**不自己鉴权**——授权判定在 `write_permissions` 内与 rev 同源完成（见下）
  - `normalize_allowed_users(value) -> str | list[str]`（`"org"` 或去重排序后的邮箱 list）
  - `allowed_users_av(allowed) -> dict`（DynamoDB AttributeValue：`"org"` → `{"S":"org"}`；名单 → `{"L":[...]}`）
  - `now_iso() -> str`（ISO8601 时间戳，register_route 与迁移脚本共用）
  - `EMAIL_RE`（与 contract 的 `EMAIL_RE` 同 pattern）
  - `class PermissionConflict(Exception)`（并发修改，调用方转 409）
  - `write_permissions(site_id, *, actor, action, require_login=None, allowed_users=None, collaborators=None, new_owner=None, mutate=None) -> dict`
    —— **唯一的权限写入入口，同时也是唯一的授权判定点**：一次强一致读同时得出
    角色与 `permissions_rev`，二者一起进事务（`TransactWriteItems` 原子更新
    sites 真源 + 路由投影；admin 路径额外对 admins 表做 `ConditionCheck`）。
    `mutate(site) -> dict` 回调用于在同一快照上做 read-modify-write。
    路由 item 不存在时降级为只写 sites（仍带 rev 条件）。返回
    `{"require_login","allowed_users","collaborators","owner","route_synced"}`

**为什么必须是一个事务入口**：spec §3.2 要求两表一起成功或一起失败。顺序两写在"收紧权限"场景下会留下 sites 表已私有、Edge 仍按旧路由公开放行的状态——安全状态错误，不是可接受的最终一致性。把它收成单一入口，MCP（Task 11）、控制台（M3）、迁移脚本就不可能各写一份半正确的版本。`register_route` 复用 `allowed_users_av` 保证两条写路径编码一致。

- [ ] **Step 1: 给 conftest 加 admins 表**

修改 `site-builder/deployer/tests/conftest.py`：在 `ENV` 字典里加一项（放在 `"ACCOUNT_ID": "1",` 之后）：

```python
       "ADMINS_TABLE": "site-admins",
```

并在 `aws` fixture 里、创建 `routing` 表之后加：

```python
        ddb.create_table(TableName="site-admins",
                         KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "email",
                                                "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
```

- [ ] **Step 2: 写失败测试**

在 `site-builder/deployer/tests/test_permissions.py` 末尾追加：

```python
def test_is_admin_false_when_absent(aws):
    assert perm.is_admin("nobody@x.com") is False


def test_add_and_list_admins(aws):
    perm.add_admin("adm@x.com", added_by="seed")
    assert perm.is_admin("adm@x.com") is True
    assert perm.list_admins() == ["adm@x.com"]


def test_add_admin_is_idempotent(aws):
    perm.add_admin("adm@x.com", added_by="seed")
    perm.add_admin("adm@x.com", added_by="other")
    assert perm.list_admins() == ["adm@x.com"]


def test_remove_admin(aws):
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    perm.remove_admin("a@x.com")
    assert perm.list_admins() == ["b@x.com"]


def test_remove_last_admin_is_refused(aws):
    perm.add_admin("only@x.com", added_by="seed")
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("only@x.com")
    assert perm.is_admin("only@x.com") is True


def test_normalize_allowed_users_org():
    assert perm.normalize_allowed_users("org") == "org"


def test_normalize_allowed_users_dedups_and_sorts():
    assert perm.normalize_allowed_users(
        ["b@x.com", "a@x.com", "b@x.com"]) == ["a@x.com", "b@x.com"]


def test_normalize_allowed_users_rejects_bad_email():
    with pytest.raises(ValueError):
        perm.normalize_allowed_users(["not-an-email"])


def test_normalize_allowed_users_rejects_empty_list():
    with pytest.raises(ValueError):
        perm.normalize_allowed_users([])


def test_set_access_policy_writes_sites_table(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = perm.set_access_policy("s-1", actor="o@x.com", require_login=False,
                                 allowed_users=["a@x.com"])
    assert out["require_login"] is False
    assert out["allowed_users"] == ["a@x.com"]
    site = common.get_site("s-1")
    assert site["allowed_users"] == ["a@x.com"]
    assert site["permissions_updated_by"] == "o@x.com"
    assert site["permissions_updated_at"]


def test_set_access_policy_partial_update_keeps_other_field(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users=["keep@x.com"], collaborators=[])
    perm.set_access_policy("s-1", actor="o@x.com", require_login=False)
    site = common.get_site("s-1")
    assert site["require_login"] is False
    assert site["allowed_users"] == ["keep@x.com"]


def test_set_collaborators_add_and_remove(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    assert perm.set_collaborators("s-1", actor="o@x.com",
                                  add=["c@x.com", "d@x.com"]) == ["c@x.com", "d@x.com"]
    assert perm.set_collaborators("s-1", actor="o@x.com", remove=["c@x.com"]) == ["d@x.com"]


def test_set_collaborators_refuses_owner_as_collaborator(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    with pytest.raises(ValueError):
        perm.set_collaborators("s-1", actor="o@x.com", add=["o@x.com"])


def test_transfer_owner_demotes_previous_owner(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"])
    out = perm.transfer_owner("s-1", actor="o@x.com", new_owner="new@x.com")
    assert out["owner"] == "new@x.com"
    site = common.get_site("s-1")
    assert site["owner"] == "new@x.com"
    assert "o@x.com" in site["collaborators"]
    # 新 owner 不应同时留在 collaborators 里
    assert "new@x.com" not in site["collaborators"]


def test_transfer_owner_from_collaborator_position(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"])
    perm.transfer_owner("s-1", actor="o@x.com", new_owner="c@x.com")
    site = common.get_site("s-1")
    assert site["owner"] == "c@x.com"
    assert site["collaborators"] == ["o@x.com"]


def test_transfer_owner_rejects_bad_email(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    with pytest.raises(ValueError):
        perm.transfer_owner("s-1", actor="o@x.com", new_owner="oops")


def test_allowed_users_av_org_is_string():
    assert perm.allowed_users_av("org") == {"S": "org"}


def test_allowed_users_av_list_is_L():
    assert perm.allowed_users_av(["a@x.com"]) == {"L": [{"S": "a@x.com"}]}


def test_write_permissions_updates_both_tables_atomically(aws):
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": "https://fn.lambda-url.us-east-1.on.aws"},
        "require_auth": {"BOOL": True}, "allowed_users": {"S": "org"},
        "collaborators": {"L": []}, "owner": {"S": "o@x.com"}})

    out = perm.write_permissions("s-1", actor="o@x.com",
                                 action="set_access_policy",
                                 require_login=False,
                                 allowed_users=["a@x.com"])
    assert out["route_synced"] is True

    site = common.get_site("s-1")
    assert site["require_login"] is False
    assert site["allowed_users"] == ["a@x.com"]
    assert int(site["permissions_rev"]) == 1

    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is False
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]
    # 投影只动权限字段：部署态字段必须原样保留（否则会踩掉原子切流）
    assert item["static_prefix"]["S"] == "sites/s-1/j"
    assert item["api_target"]["S"] == "https://fn.lambda-url.us-east-1.on.aws"


def test_write_permissions_degrades_when_route_absent(aws):
    """站点尚未首次部署成功：只写真源，显式返回 route_synced=False。"""
    import common
    common.upsert_site("nodeploy", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = perm.write_permissions("nodeploy", actor="o@x.com",
                                action="set_access_policy",
                                require_login=False)
    assert out["route_synced"] is False
    assert common.get_site("nodeploy")["require_login"] is False


def test_write_permissions_rolls_back_when_route_write_fails(aws, monkeypatch):
    """路由表写失败时 sites 表不能留下"已收紧"的假象。

    这是 spec §3.2 的核心保证：顺序两写会产生 sites 私有 / Edge 公开的
    安全状态错误。用事务后，注入失败应让两边都不变。
    """
    import boto3
    import botocore.exceptions
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[])
    # 故意不建路由 item，同时强制关闭降级分支——模拟"路由本该存在但写失败"
    monkeypatch.setattr(perm, "_ALLOW_ROUTE_ABSENT", False)
    with pytest.raises(botocore.exceptions.ClientError):
        perm.write_permissions("s-1", actor="o@x.com",
                               action="set_access_policy", require_login=True)
    # 真源未被改动：仍是公开
    assert common.get_site("s-1")["require_login"] is False


def test_write_permissions_detects_concurrent_modification(aws, monkeypatch):
    """两个人同时改：后到者必须失败而不是静默覆盖。

    rev 由 write_permissions 自己那次强一致读取得（不再由调用方传入），
    所以这里模拟"读完之后、提交之前别人先写成功"的交错。
    """
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["b@x.com"],
                       require_login=True, allowed_users="org",
                       permissions_rev=0)
    real = perm._site_or_raise

    def _bump_after_read(site_id, *, consistent=False):
        site = real(site_id, consistent=consistent)
        common.upsert_site(site_id, allowed_users=["a@x.com"],
                           permissions_rev=1)      # 别人先提交了
        return site

    monkeypatch.setattr(perm, "_site_or_raise", _bump_after_read)
    with pytest.raises(perm.PermissionConflict):
        perm.write_permissions("s-1", actor="b@x.com",
                               action="set_access_policy",
                               allowed_users=["b@x.com"])
    assert common.get_site("s-1")["allowed_users"] == ["a@x.com"]


def test_revocation_between_authz_and_commit_is_blocked(aws, monkeypatch):
    """授权读与事务提交之间被撤权 → 写入必须失败（授权 TOCTOU 回归）。

    这是把 actor/action 收进 write_permissions 的原因：分开做（调用方先
    assert_can、setter 再读 rev 写入）时，刚被移除的 collaborator 仍能完成
    一次写。
    """
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"],
                       require_login=True, allowed_users="org",
                       permissions_rev=0)
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": [{"S": "c@x.com"}]},
        "owner": {"S": "o@x.com"}, "permissions_rev": {"N": "0"}})

    real = perm._site_or_raise

    def _revoke_after_read(site_id, *, consistent=False):
        site = real(site_id, consistent=consistent)
        # 授权判定用的就是这个快照；判定通过后 owner 把他移除并推进 rev
        common.upsert_site(site_id, collaborators=[], permissions_rev=1)
        return site

    monkeypatch.setattr(perm, "_site_or_raise", _revoke_after_read)
    with pytest.raises(perm.PermissionConflict):
        perm.set_access_policy("s-1", actor="c@x.com", require_login=False)
    # 撤权后的写入没有生效
    assert common.get_site("s-1")["require_login"] is True


def test_admin_removed_mid_write_is_blocked(aws, monkeypatch):
    """admin 代管路径同理：名单里被移除后不得完成写入。"""
    import boto3
    import common
    perm.add_admin("adm@x.com", added_by="seed")
    perm.add_admin("keep@x.com", added_by="seed")   # 留一个，避免删空被拦
    common.upsert_site("s-1", owner="o@x.com", collaborators=[],
                       require_login=True, allowed_users="org", permissions_rev=0)
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": []},
        "owner": {"S": "o@x.com"}, "permissions_rev": {"N": "0"}})

    real_is_admin = perm.is_admin

    def _admin_then_revoked(email):
        result = real_is_admin(email)
        if email == "adm@x.com" and result:
            perm.remove_admin("adm@x.com")     # 判定后立刻被撤
        return result

    monkeypatch.setattr(perm, "is_admin", _admin_then_revoked)
    with pytest.raises(perm.PermissionDenied):
        perm.set_access_policy("s-1", actor="adm@x.com", require_login=False)
    assert common.get_site("s-1")["require_login"] is True


def test_duplicate_add_admin_keeps_count_consistent(aws):
    """并发/重复添加同一邮箱不得把计数加两次（否则删除时可能删空）。"""
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("a@x.com", added_by="again")
    perm.add_admin("b@x.com", added_by="seed")
    assert perm.list_admins() == ["a@x.com", "b@x.com"]
    # 计数与实际一致：删掉一个后仍能删（n=2 → 1），再删被拦
    perm.remove_admin("a@x.com")
    assert perm.list_admins() == ["b@x.com"]
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("b@x.com")


def test_rebuild_admin_count_repairs_drift(aws):
    """存量表/中间失败导致的计数漂移可修。"""
    import boto3
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    # 人为把计数改错
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-admins").put_item(Item={"email": "__count__", "n": 99})
    assert perm.rebuild_admin_count() == 2
    perm.remove_admin("a@x.com")
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("b@x.com")


def test_write_permissions_transfers_owner_to_both_tables(aws):
    import boto3
    import common
    common.upsert_site("s-1", owner="old@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": []},
        "owner": {"S": "old@x.com"}})
    perm.write_permissions("s-1", actor="old@x.com", action="transfer_owner",
                           new_owner="new@x.com", collaborators=["old@x.com"])
    assert common.get_site("s-1")["owner"] == "new@x.com"
    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["owner"]["S"] == "new@x.com"
    assert item["collaborators"]["L"] == [{"S": "old@x.com"}]
```

**注意**：这些测试需要 `ROUTING_TABLE` 环境变量。`site-builder/deployer/tests/conftest.py` 的 `ENV` 里已有 `"ROUTING_TABLE": "routing"`，无需再加。

**moto 的事务支持**：`TransactWriteItems` 在 moto ≥4 已支持（含
`ConditionExpression` 与 `TransactionCanceledException`）。跑不通先确认
`site-builder/deployer/.venv` 里的 moto 版本：`.venv/bin/pip show moto`；
低于 4 则 `.venv/bin/pip install -U moto` 并在提交里带上版本变化。

- [ ] **Step 3: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: FAIL — `AttributeError: module 'permissions' has no attribute 'is_admin'`

- [ ] **Step 4: 写实现**

先在 `site-builder/deployer/functions/permissions.py` 的 docstring 之后补 import 区（Task 1 建的文件目前没有 import）：

```python
import os
import re
from datetime import datetime, timezone

import boto3

import common
```

然后在文件末尾追加：

```python
# 与 contract.schema.EMAIL_RE 同 pattern：权限入口与合同校验对邮箱的判定必须一致
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

_ddb = None


def _admins_table():
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb",
                              region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _ddb.Table(os.environ["ADMINS_TABLE"])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_admin(email: str) -> bool:
    if not email or email == "__count__":
        return False
    # 强一致读：撤权后必须立刻生效，最终一致读会留下代管窗口
    return "Item" in _admins_table().get_item(Key={"email": email},
                                              ConsistentRead=True)


def list_admins() -> list[str]:
    items = common._paginate(_admins_table().scan, ProjectionExpression="email")
    # __count__ 是 remove_admin 的并发 sentinel，不是管理员
    return sorted(i["email"] for i in items if i["email"] != "__count__")


def add_admin(email: str, added_by: str) -> None:
    """幂等新增管理员，并维护 __count__ sentinel（remove_admin 的条件依赖它）。

    Put 与计数递增必须在**同一事务**里：三步顺序写（读→put→加计数）有两个
    坏结局——① 两个相同邮箱并发添加都看到"不存在"，计数被加两次而表里只有
    一个管理员（计数虚高 → 两人并发删除时 n > 1 都通过 → 表被删空）；
    ② put 成功但计数未加就崩，重试看到"已存在"直接返回，计数永久偏低
    （正常删除被误拦）。条件 attribute_not_exists 让重复添加走幂等分支。
    """
    import botocore.exceptions
    if not EMAIL_RE.fullmatch(email or ""):
        raise ValueError(f"非法邮箱: {email!r}")
    ddb = boto3.client("dynamodb",
                       region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    table = os.environ["ADMINS_TABLE"]
    try:
        ddb.transact_write_items(TransactItems=[
            {"Put": {"TableName": table,
                     "Item": {"email": {"S": email},
                              "added_by": {"S": added_by},
                              "added_at": {"S": now_iso()}},
                     "ConditionExpression": "attribute_not_exists(email)"}},
            {"Update": {"TableName": table,
                        "Key": {"email": {"S": "__count__"}},
                        "UpdateExpression": ("SET n = if_not_exists(n, :zero) "
                                             "+ :one"),
                        "ExpressionAttributeValues": {":zero": {"N": "0"},
                                                      ":one": {"N": "1"}}}}])
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "TransactionCanceledException":
            return      # 已存在：幂等成功，计数不动
        raise


def rebuild_admin_count() -> int:
    """按实际 item 数重建 __count__。

    给存量表（sentinel 引入前建的）与"计数疑似漂移"时用；部署脚本种子
    管理员后调一次即可。返回重建后的计数。
    """
    n = len(list_admins())
    _admins_table().put_item(Item={"email": "__count__", "n": n})
    return n


def remove_admin(email: str) -> None:
    """删管理员。名单删空 = 平台永久失去管理入口，因此硬拦。

    scan → delete 两步之间有并发窗口（两个管理员同时删自己，各自都看到
    "还有两个"，结果表被删空）。用一条 sentinel item 记计数、在同一事务里
    条件递减来关掉这个窗口：计数降到 0 的那次事务必然失败。
    """
    import botocore.exceptions
    current = list_admins()
    if email not in current:
        return
    if len(current) <= 1:
        raise PermissionDenied("不能删除最后一个管理员")
    ddb = boto3.client("dynamodb",
                       region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    table = os.environ["ADMINS_TABLE"]
    try:
        ddb.transact_write_items(TransactItems=[
            {"Delete": {"TableName": table,
                        "Key": {"email": {"S": email}},
                        "ConditionExpression": "attribute_exists(email)"}},
            # sentinel 记录当前管理员数；条件保证递减后仍 ≥1
            {"Update": {"TableName": table,
                        "Key": {"email": {"S": "__count__"}},
                        "UpdateExpression": "SET n = n - :one",
                        "ConditionExpression": "n > :one",
                        "ExpressionAttributeValues": {":one": {"N": "1"}}}}])
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "TransactionCanceledException":
            raise PermissionDenied(
                "不能删除最后一个管理员（或名单刚被他人修改，请刷新重试）") from e
        raise


def normalize_allowed_users(value):
    """校验并规范化 allowed_users：返回 "org" 或去重排序后的邮箱 list。"""
    if value == "org":
        return "org"
    if not isinstance(value, list) or not value:
        raise ValueError('allowed_users 必须为 "org" 或非空邮箱数组')
    for e in value:
        if not isinstance(e, str) or not EMAIL_RE.fullmatch(e):
            raise ValueError(f"allowed_users 含非法邮箱: {e!r}")
    return sorted(set(value))


def _site_or_raise(site_id: str, *, consistent: bool = False) -> dict:
    """取站点记录。

    consistent=True 用强一致读：授权判定与 read-modify-write 都基于它，
    最终一致读会放大"权限刚被撤销但旧请求仍读到旧名单"的窗口。
    """
    site = (common.get_site_consistent(site_id) if consistent
            else common.get_site(site_id))
    if not site:
        raise PermissionDenied(f"站点 {site_id} 不存在")
    return site


# ---- 权限写入：唯一入口，两表原子提交 ----
# 真源是 sites 表，路由表是给 Edge 读的投影。两者必须一起成功或一起失败：
# 顺序两写在"收紧权限"场景下会留下 sites 已私有、Edge 仍公开放行的状态
# （安全状态错误，不是最终一致性）。见 spec §3.2。
#
# 测试钩子：站点尚未首次部署成功时路由 item 不存在，此时降级为只写 sites。
# 该降级是显式分支——把它关掉才能测"路由本该存在却写失败"的回滚路径。
_ALLOW_ROUTE_ABSENT = True


def allowed_users_av(allowed) -> dict:
    """allowed_users 的 DynamoDB AttributeValue：字面量 org 用 S，名单用 L。

    Edge 的 _deser 必须已支持 L——否则名单会被读成 False，站点变成
    "全员放行"。部署顺序：Edge 先上，写侧后上。
    """
    if allowed == "org":
        return {"S": "org"}
    return {"L": [{"S": e} for e in allowed]}


def _ddb_client():
    return boto3.client("dynamodb",
                        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def _cancel_reasons(err) -> list[str]:
    return [r.get("Code", "") for r in
            err.response.get("CancellationReasons", [])]


def write_permissions(site_id: str, *, actor: str, action: str,
                      require_login=None, allowed_users=None,
                      collaborators=None, new_owner=None,
                      mutate=None) -> dict:
    """权限写入的唯一入口：授权判定 + sites 表（真源）+ 路由表（投影）原子提交。

    **授权与写入必须绑定同一个快照**，这是本函数把 actor/action 收进来的原因。
    分离写法（调用方先 assert_can、再调 setter）有 TOCTOU：
      旧 owner/collaborator 通过鉴权 → 另一请求把他移除、rev 前进 →
      setter 重新读到新 rev → 用新 rev 成功写入
    结果是刚被撤销权限的人仍能完成一次写。所以：一次强一致读同时得出角色与
    rev，rev 进事务条件，角色由该次读的 owner/collaborators 判定——两者要么
    一起成立，要么事务被 rev 条件挡下。

    mutate: 可选回调 `(site) -> dict`，在同一快照上计算要写的字段
    （collaborators 这类 read-modify-write 用它，避免调用方再读一次）。
    返回的 dict 会覆盖同名的显式参数。

    抛 PermissionDenied（无权）、PermissionConflict（并发修改，调用方转 409）
    或原始 ClientError。
    """
    import botocore.exceptions

    site = _site_or_raise(site_id, consistent=True)
    caller_is_admin = is_admin(actor)
    # 与 rev 同源的授权判定——不要在调用方另做一次
    role = assert_can(actor, site, action, is_admin=caller_is_admin,
                      what=f"站点 {site_id}")
    rev = int(site.get("permissions_rev", 0))
    if mutate is not None:
        overrides = mutate(site) or {}
        require_login = overrides.get("require_login", require_login)
        allowed_users = overrides.get("allowed_users", allowed_users)
        collaborators = overrides.get("collaborators", collaborators)
        new_owner = overrides.get("new_owner", new_owner)

    effective = {
        "require_login": bool(site.get("require_login", True)),
        "allowed_users": site.get("allowed_users", "org"),
        "collaborators": list(site.get("collaborators") or []),
        "owner": site.get("owner", ""),
    }
    sets = ["permissions_updated_at = :t", "permissions_updated_by = :by",
            "permissions_rev = :nrev"]
    vals = {":t": {"S": now_iso()}, ":by": {"S": actor},
            ":nrev": {"N": str(rev + 1)}, ":rev": {"N": str(rev)}}
    names = {}

    if require_login is not None:
        if not isinstance(require_login, bool):
            raise ValueError("require_login 必须为布尔值")
        effective["require_login"] = require_login
        sets.append("require_login = :rl")
        vals[":rl"] = {"BOOL": require_login}
    if allowed_users is not None:
        effective["allowed_users"] = normalize_allowed_users(allowed_users)
        sets.append("allowed_users = :au")
        vals[":au"] = allowed_users_av(effective["allowed_users"])
    if collaborators is not None:
        effective["collaborators"] = list(collaborators)
        sets.append("collaborators = :co")
        vals[":co"] = {"L": [{"S": e} for e in effective["collaborators"]]}
    if new_owner is not None:
        effective["owner"] = new_owner
        sets.append("#o = :ow")
        names["#o"] = "owner"
        vals[":ow"] = {"S": new_owner}
    if len(sets) == 3:
        raise ValueError("没有要更新的字段")

    site_update = {
        "TableName": os.environ["SITES_TABLE"],
        "Key": {"site_id": {"S": site_id}},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ConditionExpression": ("attribute_not_exists(permissions_rev) "
                                "OR permissions_rev = :rev"),
        "ExpressionAttributeValues": vals,
    }
    if names:
        site_update["ExpressionAttributeNames"] = names

    # 路由表只 update 权限字段，不整条覆盖——register_route 是整条 put_item
    # （原子切流），两者都整写会踩掉 static_prefix / api_target。
    route_update = {
        "TableName": os.environ["ROUTING_TABLE"],
        "Key": {"subdomain": {"S": common.subdomain_for(site_id)}},
        "UpdateExpression": ("SET require_auth = :a, allowed_users = :u, "
                             "collaborators = :c, #ro = :o, permissions_rev = :rv"),
        "ConditionExpression": "attribute_exists(subdomain)",
        "ExpressionAttributeNames": {"#ro": "owner"},
        "ExpressionAttributeValues": {
            ":a": {"BOOL": effective["require_login"]},
            ":u": allowed_users_av(effective["allowed_users"]),
            ":c": {"L": [{"S": e} for e in effective["collaborators"]]},
            ":o": {"S": effective["owner"]},
            # 投影带上 rev：register_route 用它判断"我读到的策略是否还是最新"
            # （见 register_route 的条件事务）。
            ":rv": {"N": str(rev + 1)}},
    }

    items = [{"Update": site_update}, {"Update": route_update}]
    if role == ROLE_ADMIN:
        # admin 代管路径：把"调用者此刻仍是管理员"也放进同一事务。
        # 否则 admin 被移出名单与本次写入之间同样有 TOCTOU 窗口。
        items.append({"ConditionCheck": {
            "TableName": os.environ["ADMINS_TABLE"],
            "Key": {"email": {"S": actor}},
            "ConditionExpression": "attribute_exists(email)"}})

    ddb = _ddb_client()
    try:
        ddb.transact_write_items(TransactItems=items)
        return {**effective, "route_synced": True}
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        reasons = _cancel_reasons(e)
        site_failed = len(reasons) > 0 and reasons[0] == "ConditionalCheckFailed"
        route_failed = len(reasons) > 1 and reasons[1] == "ConditionalCheckFailed"
        admin_failed = len(reasons) > 2 and reasons[2] == "ConditionalCheckFailed"
        if admin_failed:
            # 管理员身份在鉴权与提交之间被撤销
            raise PermissionDenied("你的管理员权限已被撤销") from e
        if site_failed:
            raise PermissionConflict(
                "站点权限已被其他人修改，请刷新后重试") from e
        if route_failed and _ALLOW_ROUTE_ABSENT:
            # 站点还没首次部署成功（无路由 item）：只写真源，
            # 首次部署时 register_route 会带上正确值。
            # 仍要带 rev 条件，避免这条降级路径绕过并发保护。
            try:
                ddb.update_item(**site_update)
            except botocore.exceptions.ClientError as inner:
                if inner.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    raise PermissionConflict(
                        "站点权限已被其他人修改，请刷新后重试") from inner
                raise
            return {**effective, "route_synced": False}
        raise


# 三个 setter 都不自己鉴权、不自己读快照——全部交给 write_permissions，
# 保证"授权判定"与"写入条件"用同一次强一致读（见其 docstring 的 TOCTOU 说明）。
# read-modify-write 的计算通过 mutate 回调在同一快照上做。

def set_access_policy(site_id: str, *, actor: str, require_login=None,
                      allowed_users=None) -> dict:
    """改访问策略（owner / collaborator / admin 均可）。"""
    out = write_permissions(site_id, actor=actor, action="set_access_policy",
                            require_login=require_login,
                            allowed_users=allowed_users)
    return {"require_login": out["require_login"],
            "allowed_users": out["allowed_users"]}


def set_collaborators(site_id: str, *, actor: str, add=None, remove=None) -> list[str]:
    """增删协作者（仅 owner / admin）。"""
    def _mutate(site):
        current = list(site.get("collaborators") or [])
        for e in (add or []):
            if not EMAIL_RE.fullmatch(e or ""):
                raise ValueError(f"非法邮箱: {e!r}")
            if e == site.get("owner"):
                raise ValueError("owner 已隐式拥有全部权限，不能同时作为协作者")
            if e not in current:
                current.append(e)
        for e in (remove or []):
            if e in current:
                current.remove(e)
        return {"collaborators": current}

    return write_permissions(site_id, actor=actor,
                             action="manage_collaborators",
                             mutate=_mutate)["collaborators"]


def transfer_owner(site_id: str, *, actor: str, new_owner: str) -> dict:
    """转移所有权：原 owner 自动降级为 collaborator（防转错人即失联）。"""
    if not EMAIL_RE.fullmatch(new_owner or ""):
        raise ValueError(f"非法邮箱: {new_owner!r}")
    captured = {}

    def _mutate(site):
        old_owner = site.get("owner", "")
        if new_owner == old_owner:
            raise ValueError("新 owner 与当前 owner 相同")
        collaborators = [e for e in (site.get("collaborators") or [])
                         if e != new_owner]
        if old_owner and old_owner not in collaborators:
            collaborators.append(old_owner)
        captured["previous_owner"] = old_owner
        return {"new_owner": new_owner, "collaborators": collaborators}

    out = write_permissions(site_id, actor=actor, action="transfer_owner",
                            mutate=_mutate)
    return {"owner": out["owner"], "collaborators": out["collaborators"],
            "previous_owner": captured.get("previous_owner", "")}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: PASS（全部通过）

- [ ] **Step 6: 跑 deployer 全量回归**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS（原有测试 + 新增，无回归）

- [ ] **Step 7: 提交**

```bash
git add site-builder/deployer/functions/permissions.py site-builder/deployer/tests/test_permissions.py site-builder/deployer/tests/conftest.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(permissions): admin 名单与权限写入（访问策略/协作者/所有权转移）"
```

---

## Task 3: sites 表加 GSI + admins 表（CDK）

**Files:**
- Modify: `site-builder/deployer/infra/app.py:31-34`（sites 表定义）与 exec role 语句
- Modify: `site-builder/config.ini.example`
- Test: `site-builder/deployer/tests/test_infra_tables.py`（新建，用 CDK assertions 断言模板）

**Interfaces:**
- Consumes: 无（基础设施层）
- Produces: `site-sites` 表带 `owner-index` GSI（PK `owner`，无 sort key）；`site-admins` 表（PK `email`）；两者的表名与 `ADMINS_TABLE` 环境变量出现在所有 step Lambda 的 `common_env` 里

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_infra_tables.py`：

```python
"""CDK 模板断言：二期新增的表与索引必须存在，且 step Lambda 拿到 ADMINS_TABLE。

**opt-in（默认 skip）**：本文件要 synth 整个 stack，而 step Lambda 用
Code.from_asset(bundling=...) —— synth 阶段就会起 Docker 装 psycopg。
所以默认不跑，需要时显式开：

    SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q

日常回归靠"部署后 describe-table 真机核对"（见本任务 Step 5 与 Task 9）。
"""
import os
import sys
from pathlib import Path

import pytest

INFRA = Path(__file__).parents[1] / "infra"
CONFIG = Path(__file__).parents[2] / "config.ini"

pytestmark = [
    pytest.mark.skipif(os.environ.get("SB_CDK_TESTS") != "1",
                       reason="需 SB_CDK_TESTS=1（synth 会起 Docker 做 bundling）"),
    pytest.mark.skipif(not CONFIG.exists(),
                       reason="需要 site-builder/config.ini"),
]


@pytest.fixture(scope="module")
def template():
    aws_cdk = pytest.importorskip("aws_cdk")
    from aws_cdk import assertions
    sys.path.insert(0, str(INFRA))
    import importlib
    mod = importlib.import_module("app")
    app = aws_cdk.App()
    stack = mod.SiteDeployerStack(app, "TestStack")
    return assertions.Template.from_stack(stack)


def test_sites_table_has_owner_index(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "TableName": "site-sites",
        "GlobalSecondaryIndexes": [{
            "IndexName": "owner-index",
            "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"}}]})


def test_admins_table_exists(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "TableName": "site-admins",
        "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}]})


def test_step_lambdas_get_admins_table_env(template):
    template.has_resource_properties("AWS::Lambda::Function", {
        "FunctionName": "site-deployer-register_route",
        "Environment": {"Variables": {"ADMINS_TABLE": "site-admins"}}})
```

**注意**：`app.py` 模块底部直接 `app.synth()`——`import app` 会 synth 一次默认 app（起 Docker bundling，慢但无副作用，不部署）。测试再建一个独立 `App()` 与 stack 实例即可。这也是本文件默认 skip 的原因。

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`
Expected: FAIL — sites 表没有 `GlobalSecondaryIndexes`；`site-admins` 表不存在
（首次运行会拉 Docker 镜像装 psycopg，耗时几分钟；Docker 未运行则报
`Cannot connect to the Docker daemon`——此时跳过本文件，靠 Step 5 的 synth
与 Task 9 的真机 describe-table 验证。）

- [ ] **Step 3: 改 CDK**

修改 `site-builder/deployer/infra/app.py`，把 sites 表定义（当前 31-34 行）替换为：

```python
        sites = ddb.Table(self, "Sites", table_name="site-sites",
                          partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                          removal_policy=RemovalPolicy.DESTROY)
        # 二期：list_my_sites / 控制台按 owner 查（替掉全表 Scan）。
        # 无 sort key——站点数量级小，按 owner 一次 query 即可。
        sites.add_global_secondary_index(
            index_name="owner-index",
            partition_key=ddb.Attribute(name="owner", type=ddb.AttributeType.STRING))

        # 二期：平台管理员名单。首个管理员由 deploy 脚本从 config.ini
        # [Platform] admin_seed 幂等注入；之后由控制台增删（不走重部署）。
        admins = ddb.Table(self, "Admins", table_name="site-admins",
                           partition_key=ddb.Attribute(name="email",
                                                       type=ddb.AttributeType.STRING),
                           billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                           removal_policy=RemovalPolicy.RETAIN)
```

**注意 `removal_policy=RETAIN`**：管理员名单误删会让平台失去管理入口，与 jobs/sites 的 DESTROY 语义不同，这是有意为之——在代码注释里写明。

在 `common_env` 字典（当前 142-155 行）里加一项：

```python
            "ADMINS_TABLE": admins.table_name,
```

在 `CfnOutput` 循环（当前 132-137 行）的 dict 里加一项：

```python
                     "AdminsTable": admins.table_name,
```

exec role 的 DynamoDB 语句已经是 `table/site-*` 前缀通配（当前 106-110 行），`site-admins` 与 `site-sites/index/*` 都已覆盖，无需改动——**在 Step 5 用 synth 输出确认**。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q`
Expected: PASS（3 passed）

- [ ] **Step 5: 确认 exec role 覆盖新表**

Run:
```bash
cd site-builder/deployer/infra && PATH=.venv/bin:$PATH npx -y aws-cdk@latest synth 2>/dev/null | grep -A3 'table/site-\*'
```
Expected: 输出里包含 `table/site-*` 与 `table/site-*/index/*` 两条 Resource——确认 `site-admins` 与 sites 的 GSI 都在授权范围内。若 `index/*` 不在，把它加进 `app.py` 的 DynamoDB 语句 resources。

- [ ] **Step 6: 加 config 项**

修改 `site-builder/config.ini.example`：

```ini
[Platform]
base_domain = example.com
account_id = 000000000000
region = us-east-1
routing_table = ApplicationWebRouterStack-subdomain-mapping
# 首个平台管理员邮箱（部署脚本幂等写入 site-admins 表）。
# 之后的管理员增删在控制台完成，不需要改这里重部署。
admin_seed =

[Cognito]
user_pool_id =
domain =
site_client_id =
mcp_client_id =
# 二期：key-proxy 用的 client_credentials 客户端（M4 才用到，M1 一并创建）
machine_client_id =

[DSQL]
cluster_endpoint =

[Deployer]
jobs_table = site-deploy-jobs
sites_table = site-sites
admins_table = site-admins
artifacts_bucket = site-artifacts-{account_id}
frontend_bucket = site-frontend-{account_id}
state_machine_arn =
edge_role_arn =

[MCP]
endpoint_url =
```

- [ ] **Step 7: 提交**

```bash
git add site-builder/deployer/infra/app.py site-builder/deployer/tests/test_infra_tables.py site-builder/config.ini.example
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(infra): sites 表加 owner-index GSI；新增 site-admins 表"
```

---

## Task 4: `common.list_sites_by_owner` + collaborator 查询

**Files:**
- Modify: `site-builder/deployer/functions/common.py`
- Modify: `site-builder/deployer/tests/test_common.py`
- Modify: `site-builder/deployer/tests/conftest.py`（sites 表加 GSI 定义）
- Modify: `site-builder/mcp/tests/conftest.py`（同上，MCP 测试共用 sites 表）

**Interfaces:**
- Consumes: Task 3 的 `owner-index` GSI
- Produces:
  - `common.list_sites_by_owner(owner: str) -> list[dict]`（GSI query）
  - `common.list_sites_for_user(email: str) -> list[dict]`（owner 的 ∪ collaborator 的，按 site_id 去重）

- [ ] **Step 1: 给两个 conftest 的 sites 表加 GSI**

`site-builder/deployer/tests/conftest.py` 与 `site-builder/mcp/tests/conftest.py` 里，把 `site-sites` 建表调用替换为（两个文件内容相同）：

```python
        ddb.create_table(TableName="site-sites",
                         KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[
                             {"AttributeName": "site_id", "AttributeType": "S"},
                             {"AttributeName": "owner", "AttributeType": "S"}],
                         GlobalSecondaryIndexes=[{
                             "IndexName": "owner-index",
                             "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
                             "Projection": {"ProjectionType": "ALL"}}],
                         BillingMode="PAY_PER_REQUEST")
```

`site-builder/mcp/tests/conftest.py` 的 `ENV` 里也加 `"ADMINS_TABLE": "site-admins",`，并在建表处加 admins 表（与 Task 2 Step 1 相同的建表代码）。

- [ ] **Step 2: 写失败测试**

在 `site-builder/deployer/tests/test_common.py` 末尾追加：

```python
def test_list_sites_by_owner_uses_gsi(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", name="one")
    common.upsert_site("s-2", owner="o@x.com", name="two")
    common.upsert_site("s-3", owner="other@x.com", name="three")
    got = {s["site_id"] for s in common.list_sites_by_owner("o@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_by_owner_empty(aws):
    import common
    assert common.list_sites_by_owner("nobody@x.com") == []


def test_list_sites_for_user_includes_collaborations(aws):
    import common
    common.upsert_site("s-1", owner="me@x.com", collaborators=[])
    common.upsert_site("s-2", owner="other@x.com", collaborators=["me@x.com"])
    common.upsert_site("s-3", owner="other@x.com", collaborators=["nope@x.com"])
    got = {s["site_id"] for s in common.list_sites_for_user("me@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_for_user_dedups(aws):
    import common
    # 理论上 owner 不该同时在 collaborators 里（permissions 层会拦），
    # 但历史数据可能有——不能返回重复项
    common.upsert_site("s-1", owner="me@x.com", collaborators=["me@x.com"])
    got = [s["site_id"] for s in common.list_sites_for_user("me@x.com")]
    assert got == ["s-1"]
```

- [ ] **Step 3: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_common.py -q`
Expected: FAIL — `AttributeError: module 'common' has no attribute 'list_sites_by_owner'`

- [ ] **Step 4: 写实现**

在 `site-builder/deployer/functions/common.py` 的 `get_site` 之后追加：

```python
def get_site_consistent(site_id: str) -> dict | None:
    """强一致读。授权判定与 read-modify-write 用它：最终一致读会放大
    "权限刚被撤销但旧请求仍读到旧名单"的窗口。"""
    return _table("SITES_TABLE").get_item(
        Key={"site_id": site_id}, ConsistentRead=True).get("Item")


def _paginate(method, **kwargs) -> list[dict]:
    """DynamoDB query/scan 分页汇总。

    单次 query/scan 最多返回 1MB，**超出会静默截断**——不翻页就会出现
    "站点列表少了几个"、"管理员名单看起来只剩一个"这类难查的问题。
    """
    items, start_key = [], None
    while True:
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = method(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            return items


def list_sites_by_owner(owner: str) -> list[dict]:
    table = _table("SITES_TABLE")
    return _paginate(table.query, IndexName="owner-index",
                     KeyConditionExpression=Key("owner").eq(owner))


def list_sites_for_user(email: str) -> list[dict]:
    """我 owner 的 ∪ 我是 collaborator 的站点，按 site_id 去重。

    collaborator 维度没有索引（DynamoDB 不能对 List 建 GSI），用 Scan +
    contains 过滤。站点规模到数百时改为维护反向索引表。
    """
    from boto3.dynamodb.conditions import Attr
    table = _table("SITES_TABLE")
    items = {s["site_id"]: s for s in list_sites_by_owner(email)}
    for s in _paginate(table.scan,
                       FilterExpression=Attr("collaborators").contains(email)):
        items.setdefault(s["site_id"], s)
    return list(items.values())
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_common.py -q`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add site-builder/deployer/functions/common.py site-builder/deployer/tests/test_common.py site-builder/deployer/tests/conftest.py site-builder/mcp/tests/conftest.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(common): 按 owner 查站点用 GSI；新增 owner∪collaborator 列表"
```

---

## Task 5: `register_route` 改为从 sites 表取权限

**Files:**
- Modify: `site-builder/deployer/functions/register_route.py`
- Test: `site-builder/deployer/tests/test_finalize_steps.py`（已有 register_route 测试，在此扩展）

**Interfaces:**
- Consumes: `common.get_site`、`common.upsert_site`、Task 2 的 `permissions.normalize_allowed_users`
- Produces: 路由表 item 的权限字段来自 sites 表，写入走 **`TransactWriteItems`**（sites 的 `ConditionCheck` + 路由 `Put`，冲突重读重试 ≤3 次）；路由 item 多一个 `permissions_rev` 字段；首次部署的权限初始化用条件写 `attribute_not_exists(require_login)`；`event["effective_auth"] = {"require_login": bool, "allowed_users": "org"|list}` 供下游 smoke_test 使用（Task 5b）。路由表 `allowed_users` 写法：`"org"` → `{"S": "org"}`；名单 → `{"L": [{"S": email}, ...]}`
- Consumes（补）: `permissions.allowed_users_av`、`permissions.now_iso`、`SITES_TABLE` 环境变量（条件写与 ConditionCheck 都要用到——`register_route` 此前只用 `ROUTING_TABLE`，确认 `common_env` 里两者都有）

**依赖**：Task 8（Edge `_deser` 支持 L）必须**先于本任务部署到生产**，否则 Edge 读到 `L` 会静默变 `False`。代码合并顺序上本任务可以先写，但**部署顺序必须 Task 8 先上**——在提交信息里写明。

- [ ] **Step 1: 先确认现有测试怎么写的**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q -v 2>&1 | head -30`
Expected: 看到现有 register_route 相关测试名，了解 fixture 与 event 形状后再动手。

- [ ] **Step 2: 写失败测试**

在 `site-builder/deployer/tests/test_finalize_steps.py` 末尾追加：

```python
def test_register_route_seeds_permissions_from_manifest_on_first_deploy(aws):
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", name="one")  # 无权限字段
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True,
                                   "allowed_users": ["a@x.com"]}}}
    register_route.handler(event, None)

    site = common.get_site("s-1")
    assert site["require_login"] is True
    assert site["allowed_users"] == ["a@x.com"]

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is True
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]


def test_register_route_prefers_sites_table_over_manifest(aws):
    """在线改过权限后重部署：manifest 的旧值必须被忽略。"""
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users=["online@x.com"], collaborators=["c@x.com"])
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}}
    register_route.handler(event, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is False           # 线上值，不是 manifest 的 True
    assert item["allowed_users"]["L"] == [{"S": "online@x.com"}]
    assert item["collaborators"]["L"] == [{"S": "c@x.com"}]
    # sites 表不被 manifest 覆盖
    assert common.get_site("s-1")["require_login"] is False


def test_register_route_refuses_stale_snapshot(aws, monkeypatch):
    """并发交错：读到"公开"后，别人把权限改成私有 → 本次不得把路由写回公开。

    模拟 spec §3.2 描述的那条交错：在 register_route 读完 sites、写路由之前，
    在线改权限的事务已经把 sites 与路由都改成私有（rev 也推进了）。
    条件事务必须拒绝这次写入，重读后用新策略成稿。
    """
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    job_id = common.create_job("o@x.com", "s-1")

    real_get_site = common.get_site
    calls = {"n": 0}

    def _racing_get_site(site_id):
        site = real_get_site(site_id)
        calls["n"] += 1
        if calls["n"] == 1:
            # 第一次读之后、写路由之前，别人把权限收紧了（rev 推进）
            common.upsert_site(site_id, require_login=True,
                               allowed_users=["vip@x.com"], permissions_rev=1)
        return site

    monkeypatch.setattr(register_route.common, "get_site", _racing_get_site)
    register_route.handler({"job_id": job_id, "site_id": "s-1", "api_target": "",
                            "manifest": {"auth": {"require_login": False,
                                                  "allowed_users": "org"}}}, None)

    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    # 最终必须是收紧后的策略，而不是第一次读到的"公开"
    assert item["require_auth"]["BOOL"] is True
    assert item["allowed_users"]["L"] == [{"S": "vip@x.com"}]
    assert int(item["permissions_rev"]["N"]) == 1


def test_register_route_seed_does_not_overwrite_concurrent_online_change(aws):
    """首次部署的初始化必须条件写：不能覆盖并发的首次在线权限修改。"""
    import common
    import register_route
    # 用户在首次部署跑到这一步之前就用控制台设了策略
    common.upsert_site("s-2", owner="o@x.com", require_login=False,
                       allowed_users=["early@x.com"], collaborators=[],
                       permissions_rev=1)
    job_id = common.create_job("o@x.com", "s-2")
    register_route.handler({"job_id": job_id, "site_id": "s-2", "api_target": "",
                            "manifest": {"auth": {"require_login": True,
                                                  "allowed_users": "org"}}}, None)
    site = common.get_site("s-2")
    assert site["require_login"] is False               # 在线值保留
    assert site["allowed_users"] == ["early@x.com"]     # 不被 manifest 覆盖


def test_register_route_emits_effective_auth_for_smoke_test(aws):
    """smoke_test 读 event["effective_auth"]，不读 manifest（spec §3.3.2）。"""
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users=["online@x.com"], collaborators=[])
    job_id = common.create_job("o@x.com", "s-1")
    event = {"job_id": job_id, "site_id": "s-1", "api_target": "",
             "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}}
    out = register_route.handler(event, None)
    assert out["effective_auth"] == {"require_login": False,
                                     "allowed_users": ["online@x.com"]}


def test_register_route_writes_org_as_string(aws):
    import boto3
    import common
    import register_route
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    job_id = common.create_job("o@x.com", "s-1")
    register_route.handler({"job_id": job_id, "site_id": "s-1", "api_target": "",
                            "manifest": {"auth": {"require_login": True,
                                                  "allowed_users": "org"}}}, None)
    item = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["allowed_users"] == {"S": "org"}
    assert item["collaborators"] == {"L": []}
```

- [ ] **Step 3: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q -k register_route`
Expected: FAIL — 现实现从 `event["manifest"]["auth"]` 取值，且 `allowed_users` 写成 JSON 字符串

- [ ] **Step 4: 写实现**

用以下内容替换 `site-builder/deployer/functions/register_route.py` 全文：

```python
"""SFN 步骤 6：注册子域名路由（含 auth 策略与 owner）。

put_item 覆盖整个 item = 原子切流：static_prefix 指向本次 job 的版本化前缀，
写入瞬间所有新请求走新版本（Edge 路由缓存最多再滞后 60s）。

权限字段（require_auth / allowed_users / collaborators / owner）的**真源是
sites 表**，不是 manifest——用户可能在控制台在线改过，manifest 里带的是
生成代码时的旧值。仅首次部署（sites 表尚无 require_login 字段）用 manifest
的 auth 段初始化真源。改这段逻辑前先读
docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md §3。
"""
import os

import boto3

import common
import permissions


MAX_ROUTE_ATTEMPTS = 3


def _seed_permissions_if_absent(site_id: str, manifest_auth: dict,
                                owner: str) -> None:
    """首次部署：把 manifest 的 auth 落进 sites 表作为初始值。

    条件写 attribute_not_exists(require_login)——否则与"用户在首次部署期间
    就用控制台改了权限"并发时会把在线修改覆盖掉。条件不满足说明已有真源，
    什么都不做（本次部署用真源的值）。
    """
    import botocore.exceptions
    allowed = permissions.normalize_allowed_users(manifest_auth["allowed_users"])
    try:
        boto3.resource("dynamodb", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1")).Table(
            os.environ["SITES_TABLE"]).update_item(
            Key={"site_id": site_id},
            UpdateExpression=("SET require_login = :rl, allowed_users = :au, "
                              "permissions_updated_at = :t, "
                              "permissions_updated_by = :by, "
                              "permissions_rev = if_not_exists(permissions_rev, :zero)"),
            ConditionExpression="attribute_not_exists(require_login)",
            ExpressionAttributeValues={
                ":rl": bool(manifest_auth["require_login"]),
                ":au": allowed,
                ":t": permissions.now_iso(),
                ":by": owner,
                ":zero": 0})
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise   # 真源已存在：用它的值，不覆盖


def _route_item(event, site: dict, owner: str, subdomain: str) -> dict:
    allowed = site.get("allowed_users", "org")
    return {"subdomain": {"S": subdomain},
            "site_id": {"S": event["site_id"]},
            "route_mode": {"S": "split"},
            "static_prefix": {"S": f"sites/{event['site_id']}/{event['job_id']}"},
            "api_target": {"S": event.get("api_target", "")},
            "require_auth": {"BOOL": bool(site.get("require_login", True))},
            "allowed_users": permissions.allowed_users_av(allowed),
            "collaborators": {"L": [{"S": e} for e in
                                    (site.get("collaborators") or [])]},
            "owner": {"S": owner},
            "permissions_rev": {"N": str(int(site.get("permissions_rev", 0)))}}


def handler(event, context):
    """写路由（原子切流）。权限值取自 sites 表真源，并用条件事务防并发覆盖。

    为什么必须是事务：本步骤是"读 sites → 写整条路由"。若中间有人在线收紧
    权限（那边是两表事务，sites 与路由都已改成私有），这里再用旧快照
    put_item 整条，就把路由写回公开——sites=私有 / Edge=公开，正是在线改权限
    的事务本该消除的安全状态错误。DynamoDB 事务只保证事务内原子，不会把事务
    之前的普通读与之后的普通写合成一个业务事务。见 spec §3.2。

    做法：对 sites 表做 ConditionCheck（permissions_rev 仍是我读到的值）+
    对路由表 Put 整条，同一事务提交。冲突则重读重试（≤3 次）；仍冲突就让
    本步骤失败——部署 FAILED 比留下错误的公开状态好。
    """
    import botocore.exceptions

    common.update_job(event["job_id"], phase="register-route")
    subdomain = common.subdomain_for(event["site_id"])
    ddb = boto3.client("dynamodb")

    site = common.get_site(event["site_id"]) or {}
    owner = site.get("owner") or common.get_job(event["job_id"])["owner"]
    _seed_permissions_if_absent(event["site_id"], event["manifest"]["auth"], owner)

    for attempt in range(MAX_ROUTE_ATTEMPTS):
        site = common.get_site(event["site_id"]) or {}
        owner = site.get("owner") or owner
        rev = int(site.get("permissions_rev", 0))
        try:
            ddb.transact_write_items(TransactItems=[
                {"ConditionCheck": {
                    "TableName": os.environ["SITES_TABLE"],
                    "Key": {"site_id": {"S": event["site_id"]}},
                    "ConditionExpression": (
                        "attribute_not_exists(permissions_rev) OR "
                        "permissions_rev = :rev"),
                    "ExpressionAttributeValues": {":rev": {"N": str(rev)}}}},
                {"Put": {"TableName": os.environ["ROUTING_TABLE"],
                         "Item": _route_item(event, site, owner, subdomain)}}])
            break
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            if attempt == MAX_ROUTE_ATTEMPTS - 1:
                raise RuntimeError(
                    "写路由时站点权限被并发修改，已重试 "
                    f"{MAX_ROUTE_ATTEMPTS} 次仍冲突——本次部署失败，请重新部署"
                ) from e
            # 重读循环顶部会拿到新 rev 与新策略

    # smoke_test 必须按本次实际写入路由的策略断言，不能按 manifest
    # （在线翻转过 require_login 时两者不一致，会把成功的部署判成 FAILED，
    #  而路由切换已经发生）。见 spec §3.3.2。
    event["effective_auth"] = {"require_login": bool(site.get("require_login", True)),
                               "allowed_users": site.get("allowed_users", "org")}
    event["url"] = f"https://{subdomain}.{os.environ['BASE_DOMAIN']}"
    return event
```

**注意 `require_login` 默认值取 `True`**：sites 表意外缺字段时按"需要登录"处理（fail-closed），不能默认公开。

- [ ] **Step 5: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q`
Expected: PASS（含新增 3 个）

- [ ] **Step 6: 跑 deployer 全量**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add site-builder/deployer/functions/register_route.py site-builder/deployer/tests/test_finalize_steps.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(deployer): register_route 权限取自 sites 表（真源），allowed_users 投影为 L

部署顺序约束：本改动写入 DynamoDB L 类型，必须在 Edge 的 _deser 支持 L
之后才能部署到生产，否则名单会被 Edge 读成 False（全员放行）。"
```

---

## Task 5a: `mark_job` 不再写站点 owner（P0 提权路径）

**Files:**
- Modify: `site-builder/deployer/functions/mark_job.py:37-42`
- Test: `site-builder/deployer/tests/test_finalize_steps.py`

**Interfaces:**
- Consumes: `common.get_job`、`common.upsert_site`
- Produces: 成功分支不再写 `owner` 字段；jobs 表的 `owner` 语义确立为"发起者"

**为什么这是 P0**：一期只有 owner 能部署，`upsert_site(owner=job["owner"])`
写回的就是同一个人，无害。Task 10 放开 collaborator 部署后，这行变成提权路径：
collaborator B 发起一次更新部署，成功后 `sites.owner` 变成 B，B 随即获得
undeploy / 转移所有权 / 增删协作者的能力；而 `register_route`（第 6 步）早一步
写入的仍是原 owner A，最终形成 sites 表 owner=B、路由表 owner=A 的分裂状态。
见 spec §3.3.1。

**本任务必须在 Task 10（放开 collaborator 部署）之前合并。**

- [ ] **Step 1: 写失败测试**

在 `site-builder/deployer/tests/test_finalize_steps.py` 末尾追加：

```python
def test_mark_success_does_not_change_site_owner(aws):
    """collaborator 发起的部署成功后，站点 owner 必须不变（spec §3.3.1）。"""
    import common
    import mark_job
    common.upsert_site("s-1", owner="alice@x.com", collaborators=["bob@x.com"],
                       require_login=True, allowed_users="org")
    job_id = common.create_job("bob@x.com", "s-1")      # 发起者是协作者
    mark_job.handler({"job_id": job_id, "site_id": "s-1",
                      "url": "https://app-s-1.example.com",
                      "manifest": {"tier": "static", "name": "one"}}, None)

    site = common.get_site("s-1")
    assert site["owner"] == "alice@x.com"               # 不是 bob
    assert site["status"] == "ACTIVE"                   # 其余收尾照常
    assert site["last_job_id"] == job_id
    assert site["tier"] == "static"


def test_mark_success_still_sets_owner_absent_field(aws):
    """sites 表缺 owner（异常数据）时不因为不写 owner 而永久缺字段——
    首次部署路径由 do_deploy_site 写入 owner，这里只断言不会崩。"""
    import common
    import mark_job
    common.upsert_site("s-2", name="two")               # 无 owner
    job_id = common.create_job("carol@x.com", "s-2")
    mark_job.handler({"job_id": job_id, "site_id": "s-2",
                      "url": "https://app-s-2.example.com",
                      "manifest": {"tier": "static", "name": "two"}}, None)
    assert common.get_site("s-2")["status"] == "ACTIVE"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q -k owner`
Expected: FAIL — `assert 'bob@x.com' == 'alice@x.com'`（现实现把发起者写成了 owner）

- [ ] **Step 3: 改实现**

把 `site-builder/deployer/functions/mark_job.py` 的 `handler` 成功分支改为：

```python
    job = common.get_job(job_id)
    common.update_job(job_id, status="SUCCEEDED", url=event["url"])
    # 不写 owner：jobs 表的 owner 字段是**发起者**（requested_by 语义），
    # 而站点 owner 只由 permissions.transfer_owner 与首次部署的
    # do_deploy_site 写。二期放开 collaborator 部署后，把发起者写回站点
    # owner 会让协作者部署一次就夺取所有权（spec §3.3.1）。
    common.upsert_site(event["site_id"], status="ACTIVE", last_job_id=job_id,
                       tier=event["manifest"]["tier"],
                       name=event["manifest"]["name"],
                       subdomain=common.subdomain_for(event["site_id"]))
```

`job` 变量若在此之后不再被用到，一并删掉该行（`update_job` 不需要它）——
用 `grep -n 'job\b' site-builder/deployer/functions/mark_job.py` 确认后再删。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q`
Expected: PASS

- [ ] **Step 5: 把 jobs 表的字段语义写进文档**

在 `site-builder/deployer/functions/common.py` 的 `create_job` 上方加注释：

```python
# jobs 表的 owner 字段是**发起者**（requested_by 语义）：谁按下了这次部署。
# 它不参与任何授权判定——授权一律走 permissions.py 对 sites 表的角色判定。
# 保留 owner 这个字段名是为了兼容存量数据与 owner-index GSI。
```

- [ ] **Step 6: 提交**

```bash
git add site-builder/deployer/functions/mark_job.py site-builder/deployer/functions/common.py site-builder/deployer/tests/test_finalize_steps.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "fix(deployer): mark_job 不再把 job 发起者写成站点 owner

放开 collaborator 部署后，原逻辑会让协作者部署一次即夺取所有权
（并造成 sites/路由表 owner 分裂）。jobs.owner 语义确立为发起者。"
```

---

## Task 5b: `smoke_test` 改读 effective policy

**Files:**
- Modify: `site-builder/deployer/functions/smoke_test.py:45-51`
- Test: `site-builder/deployer/tests/test_finalize_steps.py`

**Interfaces:**
- Consumes: Task 5 写入的 `event["effective_auth"]`
- Produces: smoke 断言依据本次实际写入路由的策略，与 manifest 解耦

**故障路径**：线上把 require_login 从 true 改成 false（不重部署），site.json
仍是 true。下次重部署时 `register_route` 按真源把路由写成公开，`smoke_test`
按旧 manifest 期待 302，实际拿到 200 → 部署判 FAILED，**而路由切换已经发生**
（第 6 步早于第 7 步），线上处于"新版本已上线但 job 显示失败"。反方向同样失败。
见 spec §3.3.2。

- [ ] **Step 1: 写失败测试**

在 `site-builder/deployer/tests/test_finalize_steps.py` 末尾追加：

```python
def test_smoke_test_uses_effective_auth_not_manifest(aws, monkeypatch):
    """线上已改成公开、manifest 仍是 true：smoke 必须按公开断言（期待 200）。"""
    import common
    import smoke_test
    job_id = common.create_job("o@x.com", "s-1")
    calls = []

    def _fake_check(url, require_auth, login_prefix, what):
        calls.append((url, require_auth))

    monkeypatch.setattr(smoke_test, "_check", _fake_check)
    smoke_test.handler({"job_id": job_id, "site_id": "s-1",
                        "url": "https://app-s-1.example.com",
                        "manifest": {"auth": {"require_login": True}},
                        "effective_auth": {"require_login": False,
                                           "allowed_users": "org"}}, None)
    assert calls and all(require_auth is False for _, require_auth in calls)


def test_smoke_test_falls_back_to_manifest_when_effective_absent(aws, monkeypatch):
    """兼容：老 execution 的 event 里没有 effective_auth（部署过程中升级）。"""
    import common
    import smoke_test
    job_id = common.create_job("o@x.com", "s-1")
    calls = []
    monkeypatch.setattr(smoke_test, "_check",
                        lambda url, ra, lp, what: calls.append(ra))
    smoke_test.handler({"job_id": job_id, "site_id": "s-1",
                        "url": "https://app-s-1.example.com",
                        "manifest": {"auth": {"require_login": True}}}, None)
    assert calls == [True]
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q -k smoke`
Expected: FAIL — 第一个测试拿到 `require_auth=True`（现实现读 manifest）

- [ ] **Step 3: 改实现**

把 `site-builder/deployer/functions/smoke_test.py` 的 `handler` 前两行改为：

```python
def handler(event, context):
    common.update_job(event["job_id"], phase="smoke-test")
    # 按本次实际写入路由的策略断言，不按 manifest：用户可能在线改过
    # require_login，manifest 里是生成代码时的旧值（spec §3.3.2）。
    # effective_auth 由 register_route 写入；缺失时回落 manifest，
    # 兼容升级窗口里已在运行的 execution。
    effective = event.get("effective_auth") or {}
    require_auth = bool(effective.get("require_login",
                                      event["manifest"]["auth"]["require_login"]))
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_finalize_steps.py -q`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/deployer/functions/smoke_test.py site-builder/deployer/tests/test_finalize_steps.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "fix(deployer): smoke_test 按 effective policy 断言而非 manifest

在线翻转 require_login 后重部署会被旧 manifest 判成 FAILED（而路由已切换）。"
```

---

## Task 6: 合同文档与 schema 注释同步

**Files:**
- Modify: `site-builder/skills/site-builder/references/contract.md`
- Modify: `site-builder/contract/src/contract/schema.py`（仅注释，校验逻辑不变）
- Test: `site-builder/contract/tests/`（跑回归，确认无行为变化）

**Interfaces:**
- Consumes: 无
- Produces: 无代码接口——这是给 Agent 与人读的语义澄清

- [ ] **Step 1: 找到 contract.md 里描述 auth 的段落**

Run: `grep -n "allowed_users\|require_login" site-builder/skills/site-builder/references/contract.md`
Expected: 定位到 `auth` 字段说明处

- [ ] **Step 2: 改文档**

在 `site-builder/skills/site-builder/references/contract.md` 的 `auth` 字段说明后追加：

```markdown
> **`auth` 只在站点首次部署时生效。** 站点建好后，访问策略的真源是平台侧
> 记录：用户在控制台（`https://console.<域名>`）或 MCP 工具
> `update_site_permissions` 在线修改，约 1 分钟内全网生效，**不需要重新
> 部署**。重部署时 `site.json` 里的 `auth` 会被忽略——所以不要靠改
> `site.json` 来改权限，也不要因为线上策略与 `site.json` 不一致就去"修正"
> 它。协作者与所有权同理，只能在控制台或 MCP 工具里管理。
```

- [ ] **Step 3: 在 schema.py 加注释**

修改 `site-builder/contract/src/contract/schema.py`，在 `auth = manifest.get("auth")` 那一行之前插入注释：

```python
    # auth 段只在首次部署时被 register_route 落进 sites 表作为初始值；
    # 之后访问策略的真源是 sites 表（控制台/MCP 在线修改，见二期 spec §3）。
    # 这里仍做完整校验——首次部署要靠它把住格式。
```

- [ ] **Step 4: 跑 contract 回归**

Run: `cd site-builder/contract && .venv/bin/pytest tests -q`
Expected: PASS（67 tests，无行为变化）

- [ ] **Step 5: 提交**

```bash
git add site-builder/skills/site-builder/references/contract.md site-builder/contract/src/contract/schema.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "docs(contract): 明确 site.json auth 仅首次部署生效，之后以控制台为准"
```

---

## Task 7: 存量权限迁移脚本

**Files:**
- Create: `site-builder/scripts/migrate_permissions.py`
- Test: `site-builder/deployer/tests/test_migrate_permissions.py`

**Interfaces:**
- Consumes: `common.get_site`、`common.upsert_site`、`permissions.normalize_allowed_users`
- Produces:
  - `migrate(routing_table: str, *, dry_run: bool = True) -> dict`（返回 `{"scanned": n, "migrated": [site_id...], "skipped": [...], "errors": [...]}`）
  - CLI：`python3 site-builder/scripts/migrate_permissions.py [--apply]`（默认 dry-run）

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_migrate_permissions.py`：

```python
"""迁移脚本：路由表现值 → sites 表权限字段。"""
import sys
from pathlib import Path

import boto3
import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))


def _put_route(subdomain, site_id, *, require_auth=True, allowed="org",
               owner="o@x.com"):
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": subdomain}, "site_id": {"S": site_id},
        "route_mode": {"S": "split"}, "static_prefix": {"S": f"sites/{site_id}/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": require_auth},
        "allowed_users": {"S": allowed}, "owner": {"S": owner}})


def test_migrates_org_route(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-1", owner="o@x.com", name="one")
    _put_route("app-s-1", "s-1")

    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == ["s-1"]
    site = common.get_site("s-1")
    assert site["require_login"] is True
    assert site["allowed_users"] == "org"
    assert site["collaborators"] == []


def test_migrates_json_string_allowlist(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-2", owner="o@x.com")
    _put_route("app-s-2", "s-2", require_auth=True, allowed='["b@x.com","a@x.com"]')

    mig.migrate("routing", dry_run=False)
    # 迁移时顺带规范化：去重 + 排序
    assert common.get_site("s-2")["allowed_users"] == ["a@x.com", "b@x.com"]


def test_dry_run_writes_nothing(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-3", owner="o@x.com")
    _put_route("app-s-3", "s-3")

    out = mig.migrate("routing", dry_run=True)
    assert out["migrated"] == ["s-3"]          # 报告"会迁移"
    assert "require_login" not in common.get_site("s-3")   # 但没写


def test_skips_already_migrated(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-4", owner="o@x.com", require_login=False,
                       allowed_users=["keep@x.com"], collaborators=[])
    _put_route("app-s-4", "s-4", require_auth=True, allowed="org")

    out = mig.migrate("routing", dry_run=False)
    assert out["skipped"] == ["s-4"]
    # 已迁移的站点不被路由表值覆盖
    assert common.get_site("s-4")["allowed_users"] == ["keep@x.com"]


def test_skips_platform_routes(aws):
    import migrate_permissions as mig
    _put_route("auth", "auth-service", owner="platform")
    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == [] and out["skipped"] == []
    assert out["scanned"] == 1


def test_malformed_allowlist_errors_and_does_not_widen(aws):
    """损坏的名单必须进 errors 并跳过——绝不能被写成 "org"（扩权）。"""
    import common
    import migrate_permissions as mig
    common.upsert_site("s-bad", owner="o@x.com")
    _put_route("app-s-bad", "s-bad", allowed="{not json")

    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == []
    assert out["errors"] and "s-bad" in out["errors"][0]
    # 真源没被写入任何权限字段，Edge 继续按现行 fail-closed 行为工作
    assert "allowed_users" not in common.get_site("s-bad")


def test_reports_route_without_site_record(aws):
    import migrate_permissions as mig
    _put_route("app-ghost", "ghost")     # sites 表没有对应记录
    out = mig.migrate("routing", dry_run=False)
    assert out["errors"] and "ghost" in out["errors"][0]
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_migrate_permissions.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'migrate_permissions'`

- [ ] **Step 3: 写实现**

创建 `site-builder/scripts/migrate_permissions.py`：

```python
#!/usr/bin/env python3
"""一次性迁移：把路由表里的权限现值回填到 sites 表（二期权限真源）。

背景：一期权限存在两处（site.json 每次部署携带 + 路由表 Edge 读），
sites 表没有权限字段。二期让 sites 表成为唯一真源，存量站点需要回填。

安全性：默认 dry-run 只报告；已有 require_login 字段的站点一律跳过
（那是二期之后写入的真源，不能被路由表旧值覆盖）。迁移期间 Edge 行为
不变（仍读路由表现值），无中断窗口。

用法：
    python3 site-builder/scripts/migrate_permissions.py           # dry-run
    python3 site-builder/scripts/migrate_permissions.py --apply   # 实际写入
"""
import argparse
import configparser
import json
import os
import sys
from pathlib import Path

import boto3

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))


def _load_config() -> None:
    """从 config.ini 填好 common/permissions 需要的环境变量。"""
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    os.environ.setdefault("SITES_TABLE", cfg["Deployer"]["sites_table"])
    os.environ.setdefault("JOBS_TABLE", cfg["Deployer"]["jobs_table"])
    os.environ.setdefault("ADMINS_TABLE", cfg["Deployer"]["admins_table"])
    os.environ.setdefault("AWS_DEFAULT_REGION", cfg["Platform"]["region"])


class UnparsableAllowlist(ValueError):
    pass


def _parse_allowed(raw) -> str | list[str]:
    """路由表的 allowed_users 现状：S 里存 "org" 或 JSON 数组字符串。

    **无法解析必须抛错，绝不降级为 "org"**：Edge 现行为是 JSON 解析失败即用
    空名单（仅 owner 可访问，fail-closed，origin_request.py:308-315）。若迁移
    把它写成 "org"，下一次部署会把这个值投影到路由表，权限从"仅 owner"扩大成
    "全体登录用户"——一次数据修复动作变成扩权。见 spec §3.4。
    """
    if "L" in raw:                       # 已是二期形态
        return [e["S"] for e in raw["L"]]
    value = raw.get("S", "org")
    if value == "org":
        return "org"
    try:
        parsed = json.loads(value)
    except Exception as e:
        raise UnparsableAllowlist(f"allowed_users 不是合法 JSON: {value!r}") from e
    if not isinstance(parsed, list):
        raise UnparsableAllowlist(f"allowed_users 解析后不是数组: {parsed!r}")
    return parsed


def migrate(routing_table: str, *, dry_run: bool = True) -> dict:
    import common
    import permissions

    ddb = boto3.client("dynamodb")
    report = {"scanned": 0, "migrated": [], "skipped": [], "errors": []}
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=routing_table):
        for item in page.get("Items", []):
            report["scanned"] += 1
            owner = item.get("owner", {}).get("S", "")
            if owner == "platform":      # auth-service / 控制台等平台路由无站点记录
                continue
            site_id = item.get("site_id", {}).get("S", "")
            site = common.get_site(site_id)
            if not site:
                report["errors"].append(
                    f"路由 {item['subdomain']['S']} 指向的站点 {site_id} 无 sites 记录")
                continue
            if "require_login" in site:
                report["skipped"].append(site_id)
                continue
            try:
                allowed = permissions.normalize_allowed_users(
                    _parse_allowed(item.get("allowed_users", {})))
            except ValueError as e:
                # UnparsableAllowlist 也是 ValueError 的子类，一并落在这里：
                # 报告并跳过，由人工判断原意后手工修——不自动放宽。
                report["errors"].append(f"{site_id}: allowed_users 无法规范化（{e}）")
                continue
            report["migrated"].append(site_id)
            if dry_run:
                continue
            common.upsert_site(
                site_id,
                require_login=bool(item.get("require_auth", {}).get("BOOL", True)),
                allowed_users=allowed,
                collaborators=list(site.get("collaborators") or []),
                permissions_updated_at=permissions.now_iso(),
                permissions_updated_by="migration")
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写入（默认只报告）")
    args = ap.parse_args()
    _load_config()
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    report = migrate(cfg["Platform"]["routing_table"], dry_run=not args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] 扫描 {report['scanned']} 条路由")
    print(f"  迁移: {len(report['migrated'])} {report['migrated']}")
    print(f"  跳过（已有真源）: {len(report['skipped'])} {report['skipped']}")
    if report["errors"]:
        print(f"  问题: {len(report['errors'])}")
        for e in report["errors"]:
            print(f"    - {e}")
    if not args.apply and report["migrated"]:
        print("\n确认无误后加 --apply 实际写入")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_migrate_permissions.py -q`
Expected: PASS（6 passed）

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/migrate_permissions.py site-builder/deployer/tests/test_migrate_permissions.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(scripts): 存量权限迁移脚本（路由表 → sites 表，默认 dry-run）"
```

---

## Task 8: Edge 支持 List 与 collaborators

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py:143-148`（`_deser`）与 `:292-320`（`_check_auth`）
- Test: `router/infrastructure/lambda/test_edge_auth.py`

**Interfaces:**
- Consumes: 路由表 item（Task 5 写入的形态）
- Produces: `_deser` 支持 `L`（→ list of str）与 `N`（→ int）；`_check_auth` 的名单判定接受 `list` 与 JSON 字符串两种 `allowed_users` 形态，并把 `collaborators` 视为隐式在名单内

**这个任务必须先于 Task 5 部署到生产。**

- [ ] **Step 1: 写失败测试**

在 `router/infrastructure/lambda/test_edge_auth.py` 末尾追加：

```python
def test_deser_handles_list_of_strings():
    out = orq._deser({"allowed_users": {"L": [{"S": "a@x.com"}, {"S": "b@x.com"}]},
                      "require_auth": {"BOOL": True},
                      "owner": {"S": "o@x.com"}})
    assert out["allowed_users"] == ["a@x.com", "b@x.com"]
    assert out["require_auth"] is True
    assert out["owner"] == "o@x.com"


def test_deser_handles_empty_list():
    assert orq._deser({"collaborators": {"L": []}})["collaborators"] == []


def test_deser_handles_number():
    assert orq._deser({"n": {"N": "42"}})["n"] == 42


def test_native_list_allowlist_admits_member():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='vip@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_native_list_allowlist_rejects_outsider():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='nope@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_collaborator_admitted_by_named_allowlist():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"],
             "collaborators": ["c@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='c@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None
    assert r["headers"]["x-user-email"][0]["value"] == "c@x.com"


def test_non_collaborator_still_rejected():
    route = {**ROUTE_AUTH, "allowed_users": ["vip@x.com"],
             "collaborators": ["c@x.com"]}
    r = _req(cookie=f"sb_session={_jwt(email='stranger@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_legacy_json_string_allowlist_still_works():
    """迁移期间路由表里可能还是一期的 JSON 字符串形态。"""
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    r = _req(cookie=f"sb_session={_jwt(email='vip@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_unparsable_allowlist_is_fail_closed():
    route = {**ROUTE_AUTH, "allowed_users": "{not json"}
    r = _req(cookie=f"sb_session={_jwt(email='a@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_org_route_admits_anyone_with_valid_session():
    r = _req(cookie=f"sb_session={_jwt(email='anyone@x.com')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_auth.py -q`
Expected: FAIL — `_deser` 把 `L` 变成 `False`；`collaborators` 未被识别

- [ ] **Step 3: 改 `_deser`**

替换 `router/infrastructure/lambda/origin_request.py` 的 `_deser`（143-148 行）：

```python
def _deser(item: dict) -> dict:
    """DynamoDB AttributeValue -> plain dict（本表用到的类型：S / BOOL / L / N）。

    新增类型必须在此登记：未识别的类型会落到 False，而 allowed_users 变成
    False 意味着名单检查被跳过（全员放行）——加字段前先加解析。
    """
    out = {}
    for k, v in item.items():
        if "S" in v:
            out[k] = v["S"]
        elif "BOOL" in v:
            out[k] = v["BOOL"]
        elif "L" in v:
            out[k] = [e.get("S", "") for e in v["L"]]
        elif "N" in v:
            out[k] = int(v["N"])
        else:
            out[k] = False
    return out
```

- [ ] **Step 4: 改 `_check_auth` 的名单判定**

把 `origin_request.py` 的 `_check_auth` 里从 `allowed = route.get(...)` 到 `return _forbidden()` 的那一段（308-315 行）替换为：

```python
    allowed = route.get("allowed_users", "org")
    if allowed != "org":
        if isinstance(allowed, list):
            allowlist = allowed
        else:
            # 迁移期兼容：一期把名单存成 JSON 字符串。解析失败按空名单处理
            # （fail-closed：宁可全员 403 也不能全员放行）。
            try:
                allowlist = json.loads(allowed)
            except Exception:
                allowlist = []
            if not isinstance(allowlist, list):
                allowlist = []
        email = claims["email"]
        # owner 与 collaborator 隐式在名单内：他们能改这个名单，
        # 要求他们把自己也写进去只会制造"把自己锁在门外"的工单。
        insiders = [route.get("owner", "")] + list(route.get("collaborators") or [])
        if email not in allowlist and email not in insiders:
            return _forbidden()
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: PASS（原 23 + 新增 10）

- [ ] **Step 6: 确认 Edge 代码体积仍在限制内**

Run: `wc -c router/infrastructure/lambda/origin_request.py`
Expected: 远小于 1MB（当前约 15KB）——记录数字，确认改动没有引入依赖。

- [ ] **Step 7: 提交**

```bash
git add router/infrastructure/lambda/origin_request.py router/infrastructure/lambda/test_edge_auth.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(edge): _deser 支持 L/N；名单判定接受原生 List 并放行 collaborators

必须先于 deployer 的 register_route L 类型投影部署（否则名单读成 False）。"
```

---

## Task 8b: Edge 校验 `idp` claim（org 语义的执行点）

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py`（新增两个占位符 + `_check_auth` 校验）
- Modify: `router/infrastructure/stack.py:146-186`（注入两个新占位符）
- Modify: `router/config.ini.example`（`[SiteBuilder]` 加两项）
- Modify: `router/infrastructure/lambda/test_edge_auth.py`

**Interfaces:**
- Consumes: 会话 JWT 的 `idp` claim（Task 13 Step 2b 起由 auth 服务签入）
- Produces: Edge 侧两个部署期占位符
  - `REQUIRE_IDP_CLAIM`（`"true"`/`"false"` 字符串，模块级转 bool）
  - `TRUSTED_IDPS`（逗号分隔的 provider 名单，如 `"Feishu"` 或 `"Okta,Feishu"`）

**为什么必须做**：spec §3.5 的三道约束里，前两条（关自注册、client 不列
`COGNITO`）只减小暴露面——AWS 明确说移除 `COGNITO` **不阻止** SDK 经 user
pools API 认证本地用户。**这一条是唯一在请求路径上执行"身份必须来自企业
IdP"的地方**。不做它，`allowed_users="org"` 就等于"任何能拿到本 pool token
的人"。

**上线顺序**：本任务与 Task 8 一起部署（同一个 Edge 函数文件），但
`require_idp_claim` 先配 `false`——存量会话没有 `idp` claim，直接置 true 会把
所有人拦在门外。翻转到 `true` 是 Task 15 Step 6c（M1 的完成条件）。

- [ ] **Step 1: 写失败测试**

在 `router/infrastructure/lambda/test_edge_auth.py` 末尾追加。注意本文件顶部的
占位符替换字典也要加两项（否则 `_edge_auth_testable.py` 里留着未替换的
`{{...}}` 字面量）：

```python
# 文件顶部的替换字典加这两项：
#     "{{REQUIRE_IDP_CLAIM}}": "true", "{{TRUSTED_IDPS}}": "Feishu,Okta",
# 改完后本文件所有既有用例仍需通过——它们用的 _jwt() 要相应带上 idp。


def _jwt_idp(email="a@x.com", idp="Feishu", exp_delta=3600, secret="test-secret"):
    """带 idp claim 的会话 JWT（Task 13 起 auth 服务签的就是这种）。"""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"email": email, "name": "Alice",
               "exp": int(time.time()) + exp_delta}
    if idp:
        payload["idp"] = idp
    p = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_trusted_idp_session_is_admitted():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='Feishu')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


def test_second_trusted_idp_also_admitted():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='Okta')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None


def test_session_without_idp_is_rejected_when_required():
    """本地用户（SDK 直接认证 user pool）签出的会话没有 idp——必须拦住。

    这是 spec §3.5 的核心：移除 COGNITO 不阻止 SDK 认证本地用户，
    只有这条校验能把"身份必须来自企业 IdP"落到请求路径上。
    """
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    resp = orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    assert resp["status"] == "302"          # 按未登录处理，不是 403


def test_untrusted_idp_is_rejected():
    r = _req(cookie=f"sb_session={_jwt_idp(idp='EvilCorp')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH),
                           "app-x.example.com")["status"] == "302"


def test_idp_check_applies_to_named_allowlist_too():
    """名单站点同样要过 idp 校验——不能因为在名单里就跳过来源检查。"""
    route = {**ROUTE_AUTH, "allowed_users": ["a@x.com"]}
    r = _req(cookie=f"sb_session={_jwt_idp(email='a@x.com', idp=None)}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "302"


def test_public_route_skips_idp_check():
    """公开站点（require_auth=False）根本不验会话，自然也不验 idp。"""
    route = {**ROUTE_AUTH, "require_auth": False}
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    assert orq._check_auth(r, route, "app-x.example.com") is None


def test_idp_check_disabled_by_switch():
    """开关为 false 时放行无 idp 的会话——迁移宽限期的行为。

    用独立的 testable 副本验证：把占位符替换成 false 后重新加载模块。
    """
    import importlib
    import sys
    src = (Path(__file__).parent / "origin_request.py").read_text()
    for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
                 "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
                 "{{JWT_SECRET}}": "test-secret", "{{BASE_DOMAIN}}": "example.com",
                 "{{REQUIRE_IDP_CLAIM}}": "false",
                 "{{TRUSTED_IDPS}}": "Feishu"}.items():
        src = src.replace(k, v)
    (Path(__file__).parent / "_edge_noidp_testable.py").write_text(src)
    sys.path.insert(0, str(Path(__file__).parent))
    mod = importlib.import_module("_edge_noidp_testable")
    importlib.reload(mod)
    r = _req(cookie=f"sb_session={_jwt_idp(idp=None)}")
    assert mod._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None
```

顶部若无 `from pathlib import Path` 则加上；`_edge_noidp_testable.py` 与既有的
`_edge_auth_testable.py` 一样是生成物，加进 `.gitignore`（若该目录的
gitignore 用的是通配 `_edge_*_testable.py` 则无需改）。

- [ ] **Step 2: 修既有测试（它们现在会因缺 idp 而失败）**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: 多条既有用例 FAIL——`_jwt()` 签的 token 没有 `idp`，而占位符已置
`true`。把 `_jwt()` 的 payload 加上 `"idp": "Feishu"`（保留一个不带 idp 的
变体给 Step 1 的负向用例用，即上面的 `_jwt_idp(idp=None)`）：

```python
def _jwt(email="a@x.com", name="Alice", exp_delta=3600, secret="test-secret",
         idp="Feishu"):
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"name": name, "exp": int(time.time()) + exp_delta}
    if email is not None:  # email=None -> payload 完全省略 email 字段
        payload["email"] = email
    if idp:
        payload["idp"] = idp
    p = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"
```

`test_org_route_admits_anyone_with_valid_session` 的语义也要收紧——它现在断言
"任意有效会话都能进 org 站点"，与本任务直接冲突。改为：

```python
def test_org_route_admits_any_email_from_trusted_idp():
    """org 的语义是"来自可信 IdP 的任何人"，不是"任何有效会话"。"""
    r = _req(cookie=f"sb_session={_jwt(email='anyone@x.com')}")   # 带 idp
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None
```

- [ ] **Step 3: 改 Edge 实现**

`router/infrastructure/lambda/origin_request.py`：在 `BASE_DOMAIN` 声明附近加
两个占位符与解析：

```python
# spec §3.5：org 语义的执行点。移除 COGNITO 不阻止 SDK 认证本地用户，
# 只有这里能把"身份必须来自企业 IdP"落到请求路径上。
# 迁移宽限期用开关控制（存量会话没有 idp claim）——切 pool 且全员重新登录后
# 置 true，这是 M1 的完成条件。
REQUIRE_IDP_CLAIM = "{{REQUIRE_IDP_CLAIM}}".strip().lower() == "true"
TRUSTED_IDPS = tuple(x.strip() for x in "{{TRUSTED_IDPS}}".split(",") if x.strip())
```

在 `_check_auth` 里、`claims` 验签通过之后、名单判定之前插入：

```python
    if REQUIRE_IDP_CLAIM:
        # 按未登录处理（302）而非 403：本地用户/旧会话应被引导去正规登录，
        # 403 会让用户以为"没权限"而去找站点 owner 加名单。
        if claims.get("idp") not in TRUSTED_IDPS:
            return _redirect_login(host, request.get("uri", "/"),
                                   request.get("querystring", ""))
```

- [ ] **Step 4: CDK 注入占位符**

`router/infrastructure/stack.py` 的占位符替换链（`jwt_secret` 那段）加两项：

```python
        lambda_code = (lambda_code
            .replace("{{FRONTEND_BUCKET_DOMAIN}}",
                     f"{frontend_bucket}.s3.us-east-1.amazonaws.com")
            .replace("{{JWT_SECRET}}", jwt_secret)
            .replace("{{BASE_DOMAIN}}", base_domain)
            .replace("{{REQUIRE_IDP_CLAIM}}",
                     config.get("SiteBuilder", "require_idp_claim",
                                "APP_REQUIRE_IDP_CLAIM"))
            .replace("{{TRUSTED_IDPS}}",
                     config.get("SiteBuilder", "trusted_idps",
                                "APP_TRUSTED_IDPS")))
```

`router/config.ini.example` 的 `[SiteBuilder]` 段加：

```ini
# spec §3.5：会话必须来自可信企业 IdP。存量会话没有 idp claim，
# 所以首次部署配 false；切到平台专用 pool 且全体用户重新登录后置 true
# （M1 的完成条件——停在 false 等于这道防线没生效）。
require_idp_claim = false
# Cognito 里 IdP 的 provider name，逗号分隔（如 Feishu 或 Okta,Feishu）。
# 必须与 site-builder/config.ini [IdP] provider_name 一致。
trusted_idps =
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: PASS（既有用例 + 新增 7 条）

- [ ] **Step 6: 确认 synth 能注入（不部署）**

Run:
```bash
cd router/infrastructure && PATH=.venv/bin:$PATH npx -y aws-cdk@latest synth 2>/dev/null \
  | grep -c 'REQUIRE_IDP_CLAIM\|TRUSTED_IDPS'
```
Expected: `0`——占位符已被替换掉，模板里不该再出现它们的字面量。若为非 0，
说明 config 键名拼错或替换链漏了，此时部署出去开关值是字面量字符串
（`"{{REQUIRE_IDP_CLAIM}}".lower() == "true"` 为 False，等于静默关闭防线）。

- [ ] **Step 7: 提交**

```bash
# AGENTS.md 要求：commit 前扫 staged diff
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN .*PRIVATE KEY|password[[:space:]]*=' || echo "secret scan: clean"
git add router/infrastructure/lambda/origin_request.py \
  router/infrastructure/lambda/test_edge_auth.py \
  router/infrastructure/stack.py router/config.ini.example
git commit -m "feat(edge): 校验会话的 idp claim（org 语义的执行点，带迁移开关)"
```

---


## Task 9: 部署 Edge 与 deployer，真机验证权限投影

**Files:**
- 无代码改动——这是部署与真机验证任务
- Modify: `site-builder/DEPLOY.md`（记录本次部署顺序约束与踩到的坑）

**Interfaces:**
- Consumes: Task 3/5/8 的代码
- Produces: 生产环境的 Edge 与 deployer 已支持权限真源；一条真实站点的路由 item 是二期形态

- [ ] **Step 1: 部署路由层（Edge 先上）**

Run:
```bash
cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```
Expected: 部署成功。**检查输出里没有 `SYNTH-ONLY-PLACEHOLDER` 警告**——出现即说明 SSM 读取失败，此时部署出去所有会话验签失败，必须先修好 SSM 参数再重部署。

- [ ] **Step 2: 部署执行器**

Run:
```bash
cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```
Expected: 部署成功；输出含 `AdminsTable = site-admins`。

- [ ] **Step 3: [真机] 确认 GSI 与新表存在**

Run:
```bash
aws dynamodb describe-table --table-name site-sites --region us-east-1 \
  --query 'Table.GlobalSecondaryIndexes[].{Name:IndexName,Status:IndexStatus}'
aws dynamodb describe-table --table-name site-admins --region us-east-1 \
  --query 'Table.{Name:TableName,Status:TableStatus}'
```
Expected: `owner-index` 状态 `ACTIVE`；`site-admins` 状态 `ACTIVE`。

- [ ] **Step 4: [真机] 种子管理员**

先在 `site-builder/config.ini` 的 `[Platform]` 填 `admin_seed = <你的邮箱>`，然后：

Run:
```bash
cd site-builder && python3 -c "
import configparser, os, sys
from pathlib import Path
cfg = configparser.ConfigParser(); cfg.read('config.ini')
sys.path.insert(0, 'deployer/functions')
os.environ['ADMINS_TABLE'] = cfg['Deployer']['admins_table']
os.environ['AWS_DEFAULT_REGION'] = cfg['Platform']['region']
import permissions
seed = cfg['Platform']['admin_seed']
assert seed, 'config.ini [Platform] admin_seed 为空'
permissions.add_admin(seed, added_by='seed')
# 存量表（sentinel 引入前建的）或曾经中断过的 add 会让计数漂移，
# 种子后重建一次即可对齐
print('admins:', permissions.list_admins(), 'count:', permissions.rebuild_admin_count())
"
```
Expected: 打印含你的邮箱的名单。

**注意**：这段种子逻辑在 M3 会并入 `deploy_panel.py`；此处手动执行只为让 M2 的真机验证有 admin 可用。

- [ ] **Step 5: [真机] 跑迁移脚本 dry-run**

Run: `python3 site-builder/scripts/migrate_permissions.py`
Expected: 报告列出存量站点（一期部署过 `team-reading-list-*`、`team-kudos-wall-*`）。确认 migrated 名单符合预期、errors 为空。

- [ ] **Step 6: [真机] 执行迁移**

Run: `python3 site-builder/scripts/migrate_permissions.py --apply`
Expected: 迁移条数与 dry-run 一致。

Run（抽查一个站点）:
```bash
aws dynamodb get-item --table-name site-sites --region us-east-1 \
  --key '{"site_id":{"S":"<某个真实 site_id>"}}' \
  --query 'Item.{login:require_login,allowed:allowed_users,collab:collaborators}'
```
Expected: 三个字段都在，值与路由表现值一致。

- [ ] **Step 7: [真机] 验证存量站点访问行为未变**

Run:
```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" https://app-<真实 site_id>.<base_domain>/
```
Expected: 与迁移前一致（鉴权站点 302 到 `https://auth.<base_domain>/login?redirect=...`）。

- [ ] **Step 8: [真机] 重部署一个站点，确认路由 item 变成二期形态**

用一期的 fixture 部署脚本重部署一个已有站点（`site-builder/scripts/deploy_fixture.py`，或直接经 MCP 走一次），然后：

Run:
```bash
aws dynamodb get-item --table-name "$(python3 -c "
import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")" \
  --region us-east-1 --key '{"subdomain":{"S":"app-<site_id>"}}' \
  --query 'Item.{allowed:allowed_users,collab:collaborators,auth:require_auth}'
```
Expected: `allowed` 是 `{"S":"org"}` 或 `{"L":[...]}`；`collab` 是 `{"L":[]}`；站点仍可正常访问。

- [ ] **Step 9: 更新 DEPLOY.md**

在 `site-builder/DEPLOY.md` 里加一节（放在路由层/执行器阶段之后）：

```markdown
## 二期 M2：权限真源迁移（一次性）

权限真源从"site.json + 路由表"迁到 sites 表。**部署顺序有硬约束**：

1. 先部署路由层（Edge 支持 DynamoDB `L` 类型）：
   `cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never`
   —— 顺序颠倒会让 Edge 把名单读成 `False`，等于全员放行。
2. 再部署执行器（`register_route` 从 sites 表取权限并写 `L` 投影）。
3. `config.ini [Platform] admin_seed` 填首个管理员邮箱。
4. 迁移存量站点：先 `python3 site-builder/scripts/migrate_permissions.py`
   看报告，确认无误后 `--apply`。已有 `require_login` 字段的站点会被跳过
   （不会覆盖在线修改）。
5. 验证：存量站点访问行为不变；重部署一个站点后路由 item 的
   `allowed_users` 变成 `L`（或 `S:"org"`）、多出 `collaborators`。

迁移期间无中断窗口：Edge 兼容 JSON 字符串与 `L` 两种形态。
```

- [ ] **Step 10: 提交**

```bash
git add site-builder/DEPLOY.md
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "docs(deploy): 二期 M2 权限真源迁移步骤与部署顺序约束"
```

---

## Task 10: MCP 换用角色判定 + `list_my_sites` 走 GSI

**Files:**
- Modify: `site-builder/mcp/server.py`
- Modify: `site-builder/mcp/Dockerfile:12`
- Modify: `site-builder/mcp/deploy_agentcore.py`（复制 `permissions.py`；IAM 加 admins 表）
- Modify: `site-builder/mcp/tests/test_tools.py`

**依赖**：**Task 5a 必须先合并**——放开 collaborator 部署的同时若 `mark_job`
还在把 job 发起者写成站点 owner，collaborator 部署一次就会夺取所有权
（spec §3.3.1）。

**Interfaces:**
- Consumes: `permissions.role_of/can/assert_can/is_admin/PermissionDenied`、`common.list_sites_for_user`
- Produces: `server.py` 里 `_assert_permission(email, site_id, action, what) -> dict`（返回 site 记录）；`do_list_sites` 返回项多一个 `role` 字段

- [ ] **Step 1: 写失败测试**

在 `site-builder/mcp/tests/test_tools.py` 末尾追加：

```python
def test_collaborator_can_deploy_update(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"],
                       require_login=True, allowed_users="org")
    out = server.do_deploy_site("c@x.com", "app", "app-abc123")
    assert out["site_id"] == "app-abc123"


def test_outsider_cannot_deploy_update(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    with pytest.raises(server.NotOwner):
        server.do_deploy_site("x@x.com", "app", "app-abc123")


def test_collaborator_cannot_undeploy(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_undeploy("c@x.com", "app-abc123")


def test_owner_can_undeploy(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    out = server.do_undeploy("o@x.com", "app-abc123")
    assert out["job_id"]


def test_admin_can_undeploy_others_site(aws):
    import common
    import permissions
    import server
    permissions.add_admin("adm@x.com", added_by="seed")
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    out = server.do_undeploy("adm@x.com", "app-abc123")
    assert out["job_id"]


def test_collaborator_deploy_does_not_change_owner(aws):
    """与 Task 5a 配套的回归：collaborator 走部署入口后 owner 不变。

    完整 SFN 后的断言在 Task 12 的真机 E2E；这里锁住 MCP 侧入口不会自己
    改 owner。
    """
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    server.do_deploy_site("c@x.com", "app", "app-abc123")
    assert common.get_site("app-abc123")["owner"] == "o@x.com"


def test_collaborator_can_read_status(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=["c@x.com"])
    job_id = common.create_job("o@x.com", "app-abc123")
    out = server.do_get_status("c@x.com", job_id)
    assert "status" in out


def test_outsider_cannot_read_status(aws):
    import common
    import server
    common.upsert_site("app-abc123", owner="o@x.com", collaborators=[])
    job_id = common.create_job("o@x.com", "app-abc123")
    with pytest.raises(server.NotOwner):
        server.do_get_status("x@x.com", job_id)


def test_list_sites_includes_collaborations_with_role(aws):
    import common
    import server
    common.upsert_site("mine-abc123", owner="me@x.com", name="mine",
                       status="ACTIVE", tier="static", collaborators=[])
    common.upsert_site("theirs-abc123", owner="o@x.com", name="theirs",
                       status="ACTIVE", tier="static", collaborators=["me@x.com"])
    common.upsert_site("hidden-abc123", owner="o@x.com", name="hidden",
                       status="ACTIVE", tier="static", collaborators=[])
    got = {s["site_id"]: s["role"] for s in server.do_list_sites("me@x.com")}
    assert got == {"mine-abc123": "owner", "theirs-abc123": "collaborator"}
```

在该文件顶部确认已 `import pytest`（若无则加）。

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/mcp && python3 -m pytest tests/test_tools.py -q`
Expected: FAIL — collaborator 被 `_assert_owner` 拒；`do_list_sites` 无 `role` 字段

- [ ] **Step 2b: `_caller_email` 校验 `idp` claim（MCP 侧的同一道防线）**

Edge 侧（Task 8b）拦住了 Web 访问，但**MCP 是另一条入口**：AgentCore 的
authorizer 只验 issuer 与 `allowedClients`，`_caller_email()` 只读 `email`。
所以一个 issuer/client 合法但**没有 `idp`** 的 access token（过渡期的本地
用户、之前签发的 refresh token 换出来的、将来 client auth-flow 漂移）仍能
调 MCP 部署站点、改权限、下线站点——站点侧被拦住了，管理面没有。
spec §3.5 说的是"身份必须来自企业 IdP"，两条入口都要执行。

先写测试，在 `site-builder/mcp/tests/test_agentcore_contract.py` 末尾追加：

```python
def _token(claims: dict) -> str:
    import base64
    import json as _json
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return (b64(_json.dumps({"alg": "RS256"}).encode()) + "." +
            b64(_json.dumps(claims).encode()) + ".sig")


def _with_auth(monkeypatch, token: str):
    """伪造 FastMCP 的请求上下文，只提供 Authorization 头。"""
    import server

    class _Req:
        headers = {"authorization": f"Bearer {token}"}

    class _Ctx:
        class request_context:
            request = _Req()

    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx())


def test_caller_email_accepts_trusted_idp(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu,Okta")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu"}))
    assert server._caller_email() == "a@x.com"


def test_caller_email_rejects_token_without_idp(monkeypatch):
    """本地用户/旧 token 没有 idp——必须拒，否则管理面绕过了 §3.5。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "local@x.com"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_rejects_untrusted_idp(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "EvilCorp"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_skips_idp_check_when_unconfigured(monkeypatch):
    """TRUSTED_IDPS 为空 = 迁移宽限期（与 Edge 的开关对齐），放行但不推荐。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "")
    _with_auth(monkeypatch, _token({"email": "a@x.com"}))
    assert server._caller_email() == "a@x.com"
```

Run: `cd site-builder/mcp && python3 -m pytest tests/test_agentcore_contract.py -q`
Expected: FAIL — 现实现不看 `idp`

然后改 `site-builder/mcp/server.py` 的 `_caller_email()`：把取到 email 后的
`return email` 换成先校验来源。在文件顶部常量区加：

```python
# spec §3.5：身份必须来自企业 IdP。Edge 管住站点访问，这里管住管理面
# （AgentCore authorizer 只验 issuer/client_id，不看 idp）。
# 空值 = 迁移宽限期放行，与 Edge 的 REQUIRE_IDP_CLAIM 开关对齐；
# 切完 pool、全员重新登录后必须配上。
TRUSTED_IDPS = tuple(x.strip() for x in
                     os.environ.get("TRUSTED_IDPS", "").split(",") if x.strip())
```

`_caller_email()` 里：

```python
            email = claims.get("email", "")
            if email:
                if TRUSTED_IDPS and claims.get("idp") not in TRUSTED_IDPS:
                    raise NotOwner(
                        "身份来源不被信任（缺少或非法的 idp claim）——"
                        "请用企业账号重新登录")
                return email
```

注意 `except Exception: pass` 会吞掉这个 `NotOwner`——把它改成只吞解码异常：

```python
        except NotOwner:
            raise
        except Exception:
            pass
```

`deploy_agentcore.py` 的 `environmentVariables` 加：

```python
            "TRUSTED_IDPS": CFG["IdP"]["provider_name"] if CFG.has_section("IdP") else "",
```

Run: `cd site-builder/mcp && python3 -m pytest tests -q`
Expected: PASS

- [ ] **Step 3: 改 server.py**

在 `site-builder/mcp/server.py` 里，`import common` 之后加：

```python
import permissions  # noqa: E402  deployer/functions/permissions.py（同 common 的解析路径）
```

把 `_assert_owner`（57-61 行）替换为：

```python
def _assert_permission(email: str, site_id: str, action: str, what: str) -> dict:
    """按二期角色模型判定（owner / collaborator / admin）。

    权限真源是 sites 表，判定逻辑全在 permissions.py——控制台与 MCP 共用
    同一模块，两边语义不会漂移。
    """
    # 强一致读：撤权/转移必须立刻生效。最终一致读会留下"权限已撤销但旧请求
    # 仍读到旧名单"的窗口。写路径不用本函数（授权在事务内做，见下方注释）。
    site = common.get_site_consistent(site_id)
    try:
        permissions.assert_can(email, site, action,
                               is_admin=permissions.is_admin(email), what=what)
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e))
    return site or {}
```

把 `do_deploy_site` 里的 owner 校验（71 行）替换为：

```python
        _assert_permission(owner, site_id, "deploy", f"站点 {site_id}")
```

`do_confirm_upload`（88 行）与 `do_get_status`（122 行）的校验替换为——两处都是先取 job、再按 job 的 site_id 判权限：

```python
    job = common.get_job(job_id)
    if not job:
        raise NotOwner(f"任务 {job_id} 不存在")
    _assert_permission(owner, job["site_id"], "read", f"任务 {job_id}")
```

（`do_confirm_upload` 用 `"deploy"` 而非 `"read"`：确认上传会启动部署。）

`do_undeploy`（140 行）替换为：

```python
    site = _assert_permission(owner, site_id, "undeploy", f"站点 {site_id}")
```

并把该函数后续用到的 `site` 变量保持不变（原本是 `common.get_site(site_id)` 的结果，现在由 `_assert_permission` 返回）。

`do_list_sites`（126-135 行）整体替换为：

```python
def do_list_sites(owner: str) -> list[dict]:
    """我 owner 的 ∪ 我是 collaborator 的站点。"""
    base = os.environ["BASE_DOMAIN"]
    out = []
    for s in common.list_sites_for_user(owner):
        role = permissions.role_of(owner, s)
        out.append({"site_id": s["site_id"], "name": s.get("name", ""),
                    "url": f"https://{s.get('subdomain', 'app-' + s['site_id'])}.{base}",
                    "status": s.get("status", ""), "tier": s.get("tier", ""),
                    "role": role})
    return out
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd site-builder/mcp && python3 -m pytest tests -q`
Expected: PASS

- [ ] **Step 5: 改 Dockerfile 与部署脚本**

`site-builder/mcp/Dockerfile` 第 12 行改为：

```dockerfile
COPY server.py common.py permissions.py ./
```

`site-builder/mcp/deploy_agentcore.py` 的 `build_and_push`，把单个 `shutil.copyfile` 替换为循环：

```python
def build_and_push(image_uri: str) -> None:
    # common.py / permissions.py 必须进构建上下文：server.py 按同目录解析它们
    copied = []
    for name in ("common.py", "permissions.py"):
        shutil.copyfile(HERE.parent / "deployer" / "functions" / name, HERE / name)
        copied.append(HERE / name)
    try:
        token = ecr.get_authorization_token()["authorizationData"][0]
        user, pwd = base64.b64decode(token["authorizationToken"]).decode().split(":", 1)
        _run(["docker", "login", "--username", user, "--password-stdin",
              token["proxyEndpoint"]], input=pwd.encode())
        # --platform linux/arm64：AgentCore 只接受 ARM64（Graviton）。
        # --provenance=false 必需：buildx 默认往 manifest list 里加一条
        # os=unknown/arch=unknown 的 attestation manifest，CreateAgentRuntime
        # 校验镜像时会失败，且报错文案误导为
        # "Access denied while validating ECR URI ... requires permissions for
        #  ecr:GetAuthorizationToken, ecr:BatchGetImage, ..."
        # ——实际与 IAM 权限无关（权限齐全时同样报这个）。
        _run(["docker", "buildx", "build", "--platform", "linux/arm64",
              "--provenance=false",
              "-t", image_uri, "--push", str(HERE)])
    finally:
        for p in copied:
            p.unlink(missing_ok=True)
```

`deploy_agentcore.py` 的 `ensure_role()` 里，DynamoDB 语句的 `Resource` 列表加两项：

```python
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-sites/index/*",
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-admins",
```

同一语句的 `Action` 列表加 `"dynamodb:DeleteItem"`（`remove_admin` 需要；控制台 M3 也用同一路径）。

`deploy_runtime()` 的 `environmentVariables` 加：

```python
            "ADMINS_TABLE": CFG["Deployer"]["admins_table"],
```

- [ ] **Step 6: 确认 MCP 契约测试仍过**

Run: `cd site-builder/mcp && python3 -m pytest tests -q`
Expected: PASS（工具数仍是 5，本任务未加新工具）

- [ ] **Step 7: 提交**

```bash
git add site-builder/mcp/server.py site-builder/mcp/Dockerfile site-builder/mcp/deploy_agentcore.py site-builder/mcp/tests/test_tools.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(mcp): 换用 permissions 角色判定；list_my_sites 走 GSI 并含协作站点"
```

---

## Task 11: MCP 新增 3 个权限工具

**Files:**
- Modify: `site-builder/mcp/server.py`
- Modify: `site-builder/mcp/tests/test_tools.py`
- Modify: `site-builder/mcp/tests/test_agentcore_contract.py:70-78`（工具数 5 → 8）

**Interfaces:**
- Consumes: Task 2 的 `permissions.set_access_policy` / `set_collaborators` / `transfer_owner`（三者内部走 `write_permissions` 事务）、`permissions.PermissionConflict`、Task 10 的 `_assert_permission`
- Produces:
  - `do_update_permissions(caller, site_id, require_login=None, allowed_users=None) -> dict`
  - `do_manage_collaborators(caller, site_id, add=None, remove=None, transfer_owner=None) -> dict`
  - `do_get_permissions(caller, site_id) -> dict`
  - MCP 工具：`update_site_permissions`、`manage_collaborators`、`get_site_permissions`

**说明**：spec §5.4 的第三个工具是 `get_site_stats`，但统计表在 M5 才建。本任务用 `get_site_permissions`（读当前权限，面板与 Agent 都需要）占第三个位置，`get_site_stats` 在 M5 加——那时工具数 8 → 9，同步改契约断言。

- [ ] **Step 1: 写失败测试**

在 `site-builder/mcp/tests/test_tools.py` 末尾追加：

在该文件里，站点 id 统一用 `demo-abc123`（与既有测试同风格），路由子域一律经
`common.subdomain_for()` 计算——**不要手拼**，`subdomain_for("demo-abc123")`
是 `app-demo-abc123`，手拼容易错位导致投影断言查不到 item：

```python
SITE_ID = "demo-abc123"


def _route_item(site_id=SITE_ID):
    import boto3
    import common
    return boto3.client("dynamodb").get_item(
        TableName="routing",
        Key={"subdomain": {"S": common.subdomain_for(site_id)}}).get("Item")


def _seed_site_and_route(site_id=SITE_ID, owner="o@x.com", collaborators=None):
    import boto3
    import common
    common.upsert_site(site_id, owner=owner, name="demo", status="ACTIVE",
                       tier="static", require_login=True, allowed_users="org",
                       collaborators=collaborators or [])
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": common.subdomain_for(site_id)},
        "site_id": {"S": site_id}, "route_mode": {"S": "split"},
        "static_prefix": {"S": f"sites/{site_id}/j"}, "api_target": {"S": ""},
        "require_auth": {"BOOL": True}, "allowed_users": {"S": "org"},
        "collaborators": {"L": []}, "owner": {"S": owner}})


def test_update_permissions_writes_both_tables(aws):
    import common
    import server
    _seed_site_and_route()
    out = server.do_update_permissions("o@x.com", SITE_ID,
                                       require_login=False,
                                       allowed_users=["a@x.com"])
    assert out["require_login"] is False
    assert out["allowed_users"] == ["a@x.com"]
    assert common.get_site(SITE_ID)["allowed_users"] == ["a@x.com"]
    item = _route_item()
    assert item["require_auth"]["BOOL"] is False
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]


def test_update_permissions_allows_collaborator(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    out = server.do_update_permissions("c@x.com", SITE_ID, require_login=False)
    assert out["require_login"] is False


def test_update_permissions_rejects_outsider(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(server.NotOwner):
        server.do_update_permissions("x@x.com", SITE_ID, require_login=False)


def test_update_permissions_rejects_bad_allowlist(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(ValueError):
        server.do_update_permissions("o@x.com", SITE_ID,
                                     allowed_users=["not-an-email"])


def test_manage_collaborators_add_syncs_route(aws):
    import server
    _seed_site_and_route()
    out = server.do_manage_collaborators("o@x.com", SITE_ID, add=["c@x.com"])
    assert out["collaborators"] == ["c@x.com"]
    assert _route_item()["collaborators"]["L"] == [{"S": "c@x.com"}]


def test_manage_collaborators_rejects_collaborator_caller(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_manage_collaborators("c@x.com", SITE_ID, add=["d@x.com"])


def test_transfer_owner_syncs_route(aws):
    import server
    _seed_site_and_route()
    out = server.do_manage_collaborators("o@x.com", SITE_ID,
                                         transfer_owner="new@x.com")
    assert out["owner"] == "new@x.com"
    assert out["collaborators"] == ["o@x.com"]
    item = _route_item()
    assert item["owner"]["S"] == "new@x.com"
    assert item["collaborators"]["L"] == [{"S": "o@x.com"}]


def test_transfer_owner_rejected_for_collaborator(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    with pytest.raises(server.NotOwner):
        server.do_manage_collaborators("c@x.com", SITE_ID,
                                       transfer_owner="c@x.com")


def test_get_permissions_returns_current_state(aws):
    import server
    _seed_site_and_route(collaborators=["c@x.com"])
    out = server.do_get_permissions("c@x.com", SITE_ID)
    assert out["require_login"] is True
    assert out["allowed_users"] == "org"
    assert out["collaborators"] == ["c@x.com"]
    assert out["owner"] == "o@x.com"
    assert out["my_role"] == "collaborator"


def test_get_permissions_rejects_outsider(aws):
    import server
    _seed_site_and_route()
    with pytest.raises(server.NotOwner):
        server.do_get_permissions("x@x.com", SITE_ID)


def test_update_permissions_surfaces_conflict(aws, monkeypatch):
    """permissions 层的并发冲突必须被转成 MCP 侧的可读异常，不能漏成 500。"""
    import permissions
    import server
    _seed_site_and_route()

    def _boom(*a, **kw):
        raise permissions.PermissionConflict("站点权限已被其他人修改，请刷新后重试")

    monkeypatch.setattr(permissions, "set_access_policy", _boom)
    with pytest.raises(server.PermissionConflict):
        server.do_update_permissions("o@x.com", SITE_ID, require_login=False)


def test_update_permissions_works_before_first_deploy(aws):
    """站点还没部署成功（无路由 item）时改权限不能炸——只更新真源即可。"""
    import common
    import server
    common.upsert_site("nodeploy-abc123", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = server.do_update_permissions("o@x.com", "nodeploy-abc123",
                                       require_login=False)
    assert out["require_login"] is False
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/mcp && python3 -m pytest tests/test_tools.py -q`
Expected: FAIL — `AttributeError: module 'server' has no attribute 'do_update_permissions'`

- [ ] **Step 3: 写实现（纯函数层 + 路由投影）**

在 `site-builder/mcp/server.py` 的 `do_undeploy` 之后追加。两表写入由 Task 2 的
`permissions.write_permissions` 事务完成（`set_access_policy` / `set_collaborators`
/ `transfer_owner` 内部就走它），**这里不再单独同步路由**——否则又变回顺序两写：

```python
class PermissionConflict(Exception):
    """并发修改。MCP 工具把它转成可读文案让 Agent 提示用户重试。"""


# 写路径**不在这里预先鉴权**：授权判定在 permissions.write_permissions 内
# 与 rev 同源完成（分开做会有 TOCTOU——鉴权通过后权限被撤销，写入仍成功）。
# 这里只负责把 permissions 层的异常翻译成 MCP 的错误类型。

def do_update_permissions(caller: str, site_id: str, require_login=None,
                          allowed_users=None) -> dict:
    try:
        out = permissions.set_access_policy(site_id, actor=caller,
                                            require_login=require_login,
                                            allowed_users=allowed_users)
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e)) from e
    except permissions.PermissionConflict as e:
        raise PermissionConflict(str(e)) from e
    out["note"] = "已生效，边缘缓存最多 1 分钟后全网一致"
    return out


def do_manage_collaborators(caller: str, site_id: str, add=None, remove=None,
                            transfer_owner=None) -> dict:
    try:
        if transfer_owner:
            return permissions.transfer_owner(site_id, actor=caller,
                                              new_owner=transfer_owner)
        if not add and not remove:
            raise ValueError("需要指定 add / remove / transfer_owner 之一")
        collaborators = permissions.set_collaborators(site_id, actor=caller,
                                                      add=add, remove=remove)
        site = common.get_site_consistent(site_id) or {}
        return {"owner": site.get("owner", ""), "collaborators": collaborators}
    except permissions.PermissionDenied as e:
        raise NotOwner(str(e)) from e
    except permissions.PermissionConflict as e:
        raise PermissionConflict(str(e)) from e


def do_get_permissions(caller: str, site_id: str) -> dict:
    site = _assert_permission(caller, site_id, "read", f"站点 {site_id}")
    return {"site_id": site_id,
            "owner": site.get("owner", ""),
            "collaborators": list(site.get("collaborators") or []),
            "require_login": bool(site.get("require_login", True)),
            "allowed_users": site.get("allowed_users", "org"),
            "my_role": permissions.role_of(caller, site,
                                           permissions.is_admin(caller))}
```

- [ ] **Step 4: 加 MCP 工具壳**

在 `site-builder/mcp/server.py` 的 `undeploy_site` 工具之后追加：

```python
@mcp.tool()
def update_site_permissions(site_id: str, require_login: bool | None = None,
                            allowed_users: list | str | None = None) -> dict:
    """在线修改站点访问策略——不需要重新部署，约 1 分钟内全网生效。

    require_login: true 需登录后访问，false 公开；不传表示不改。
    allowed_users: "org"（全组织可访问）或邮箱数组；不传表示不改。
    站点 owner 与协作者均可调用。site.json 里的 auth 字段不再生效。"""
    return do_update_permissions(_caller_email(), site_id, require_login,
                                 allowed_users)


@mcp.tool()
def manage_collaborators(site_id: str, add: list | None = None,
                         remove: list | None = None,
                         transfer_owner: str = "") -> dict:
    """管理站点协作者或转移所有权。仅 owner（或平台管理员）可调用。

    add/remove: 协作者邮箱数组。协作者可部署更新、改访问策略、查状态，
      但不能下线站点、不能增删协作者。
    transfer_owner: 新 owner 邮箱。转移后原 owner 自动降级为协作者
      （防转错人失去访问）。此参数与 add/remove 互斥。"""
    return do_manage_collaborators(_caller_email(), site_id, add, remove,
                                   transfer_owner or None)


@mcp.tool()
def get_site_permissions(site_id: str) -> dict:
    """查询站点当前的访问策略、owner、协作者，以及我对它的角色。"""
    return do_get_permissions(_caller_email(), site_id)
```

- [ ] **Step 5: 改契约测试的工具清单**

`site-builder/mcp/tests/test_agentcore_contract.py` 现有的
`test_all_five_tools_registered` 用 `asyncio.run(server.mcp.list_tools())`
拿真实注册结果（不是读源码文本）。**沿用这个机制**，把它替换为：

```python
EXPECTED_TOOLS = ["deploy_site", "confirm_upload", "get_deploy_status",
                  "list_my_sites", "undeploy_site", "update_site_permissions",
                  "manage_collaborators", "get_site_permissions"]


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_all_tools_registered(tool):
    import asyncio

    import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert tool in names


def test_no_unexpected_tools_registered():
    """工具面是对外契约：多出未登记的工具（比如调试残留）要在这里被拦。"""
    import asyncio

    import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert names == set(EXPECTED_TOOLS)
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cd site-builder/mcp && python3 -m pytest tests -q`
Expected: PASS

- [ ] **Step 7: 加 IAM 与环境变量**

`site-builder/mcp/deploy_agentcore.py` 的 `ensure_role()` 里，DynamoDB 语句的 `Resource` 加路由表（MCP 现在要写它做投影）：

```python
             f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/"
             + CFG["Platform"]["routing_table"],
```

`deploy_runtime()` 的 `environmentVariables` 加：

```python
            "ROUTING_TABLE": CFG["Platform"]["routing_table"],
```

- [ ] **Step 8: 提交**

```bash
git add site-builder/mcp/server.py site-builder/mcp/tests/test_tools.py site-builder/mcp/tests/test_agentcore_contract.py site-builder/mcp/deploy_agentcore.py
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(mcp): 新增 update_site_permissions / manage_collaborators / get_site_permissions"
```

---

## Task 12: 部署 MCP 并真机验证在线改权限

**Files:**
- Modify: `site-builder/skills/site-builder/SKILL.md`（把新工具写进 Skill 工作流说明）
- Modify: `site-builder/DEPLOY.md`（MCP 阶段补新工具与新增 IAM）

**Interfaces:**
- Consumes: Task 10/11 的代码
- Produces: 生产 MCP runtime 提供 8 个工具；一条真实站点完成"在线改权限并生效"验证

- [ ] **Step 1: 部署 MCP**

Run:
```bash
cd site-builder/mcp && python3 deploy_agentcore.py
```
Expected: 构建推送成功（ARM64 + `--provenance=false`），runtime 更新成功。

- [ ] **Step 2: [真机] 确认 8 个工具可列出**

用一期 client-setup 文档里的 Claude Code OAuth 方式连上 MCP（`--client-id` + `--callback-port 18765`），或用 inspector。

Expected: 工具列表含 8 个；`list_my_sites` 返回的项带 `role` 字段且 owner 是你的邮箱。

- [ ] **Step 3: [真机] 在线改权限并验证生效**

对一个真实鉴权站点（如一期的 `team-reading-list-*`），调用 `update_site_permissions(site_id, allowed_users=["<你的邮箱>"])`。

然后：

Run:
```bash
# 记录时间，等 60s 让 Edge 路由缓存过期
sleep 65
aws dynamodb get-item --table-name "$(python3 -c "
import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")" \
  --region us-east-1 --key '{"subdomain":{"S":"app-<site_id>"}}' \
  --query 'Item.allowed_users'
```
Expected: `{"L":[{"S":"<你的邮箱>"}]}`

用浏览器访问该站点：你自己应能访问（名单内）。**再用一个不在名单里的邮箱**（或临时把名单改成别人的邮箱后自己访问）验证 403。

- [ ] **Step 4: [真机] 验证重部署不回滚在线修改**

重部署同一个站点（Agent 里说"部署"，site.json 的 `auth` 保持原来的 `"org"`）。

Run（部署成功后）:
```bash
aws dynamodb get-item --table-name site-sites --region us-east-1 \
  --key '{"site_id":{"S":"<site_id>"}}' --query 'Item.allowed_users'
```
Expected: 仍是你在线改的名单（不是 `"org"`）——这是 Task 5 的核心保证。

- [ ] **Step 4b: [真机] 在线翻转 require_login 后重部署（两个方向）**

这条覆盖 Task 5b 的 smoke_test 取值路径——改前必失败。

1. 对一个 `require_login=true` 的站点调
   `update_site_permissions(site_id, require_login=False)`；
2. 等 65s 后确认站点公开可访问（`curl` 直接 200，不再 302）；
3. 重部署该站点（site.json 里 `auth.require_login` 仍是 `true`）；
4. Expected: 部署 **SUCCEEDED**（改前会因 smoke 按 manifest 期待 302 而
   FAILED），且站点仍是公开的；
5. 反方向再来一次：`update_site_permissions(site_id, require_login=True)`
   → 等 65s → 确认 302 → 重部署 → 仍 SUCCEEDED。

Run（部署后查 job 状态与线上行为）:
```bash
curl -s -o /dev/null -w "%{http_code}\n" https://app-<site_id>.<base_domain>/
```

- [ ] **Step 4c: [真机] collaborator 完整部署后 owner 不变（P0 验收）**

这是 spec §3.3.1 的核心回归，**必须跑完整 SFN**，不能只测"拿到 upload_url"。

1. 给站点加一个协作者（用你的第二个账号，或临时把自己设为协作者、
   另一个邮箱设为 owner）；
2. 以 **collaborator 身份**走完整部署（deploy_site → 上传 → confirm_upload
   → 轮询到 SUCCEEDED）；
3. 验证两张表的 owner 都没变：

Run:
```bash
SID=<site_id>
aws dynamodb get-item --table-name site-sites --region us-east-1 \
  --key "{\"site_id\":{\"S\":\"$SID\"}}" \
  --query 'Item.{owner:owner.S,collab:collaborators.L[*].S}'
aws dynamodb get-item --region us-east-1 \
  --table-name "$(python3 -c "
import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")" \
  --key "{\"subdomain\":{\"S\":\"app-$SID\"}}" --query 'Item.owner.S'
```
Expected: 两处 owner 都是**原 owner**，不是发起部署的协作者；且两处一致
（不出现 sites=B / 路由=A 的分裂）。改前这里会看到 sites.owner 变成协作者。

- [ ] **Step 5: [真机] 验证协作者权限边界**

用 `manage_collaborators(site_id, add=["<同事邮箱>"])` 加一个协作者，然后请对方（或用对方的 token）验证：

- `list_my_sites` 能看到该站点、`role` 为 `collaborator`；
- `get_site_permissions` 可读；
- `update_site_permissions` 可改；
- `undeploy_site` 被拒（错误文案含"无权执行 undeploy"）；
- `manage_collaborators` 被拒。

Expected: 全部符合。若无同事配合，用 `permissions.role_of` 的单测覆盖 + 直接构造另一个 Cognito 用户登录验证。

- [ ] **Step 6: [真机] 验证所有权转移**

`manage_collaborators(site_id, transfer_owner="<同事邮箱>")`，然后确认：

Run:
```bash
aws dynamodb get-item --table-name site-sites --region us-east-1 \
  --key '{"site_id":{"S":"<site_id>"}}' \
  --query 'Item.{owner:owner,collab:collaborators}'
```
Expected: owner 是对方；你在 collaborators 里。再调 `undeploy_site` 应被拒（你现在只是协作者）。

**验证完把 owner 转回自己**（用对方的 token，或用 admin 身份）。

- [ ] **Step 7: 更新 Skill 文档**

在 `site-builder/skills/site-builder/SKILL.md` 的工具列表/工作流部分加入三个新工具的说明：

```markdown
### 权限管理（不需要重新部署）

站点建好后，访问策略、协作者、所有权都在平台侧管理，**改这些不需要重新
部署，也不要去改 `site.json`**（重部署时 `auth` 字段会被忽略）：

- `get_site_permissions(site_id)` — 查当前策略、owner、协作者、我的角色
- `update_site_permissions(site_id, require_login=?, allowed_users=?)` —
  改访问策略（owner 与协作者均可），约 1 分钟内全网生效
- `manage_collaborators(site_id, add=?, remove=?, transfer_owner=?)` —
  管理协作者 / 转移所有权（仅 owner）

用户说"让某某也能改这个站点" → `manage_collaborators(add=[...])`；
说"只让这几个人看" → `update_site_permissions(allowed_users=[...])`；
说"这个站点交给某某负责" → `manage_collaborators(transfer_owner=...)`（转移后
原 owner 自动变协作者，需向用户说明）。

用户也可以在控制台 `https://console.<域名>` 自助完成同样的操作。
```

- [ ] **Step 8: 更新 DEPLOY.md**

在 `site-builder/DEPLOY.md` 的 MCP 阶段补一段：

```markdown
二期 M2 后 MCP 有 8 个工具（新增 `update_site_permissions` /
`manage_collaborators` / `get_site_permissions`）。runtime 角色新增权限：
路由表写（权限投影）、`site-sites/index/*`（owner-index）、`site-admins`
读写。镜像多打包 `permissions.py`（与 `common.py` 同为构建时从
`deployer/functions/` 复制）。
```

- [ ] **Step 9: 提交**

```bash
git add site-builder/skills/site-builder/SKILL.md site-builder/DEPLOY.md
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "docs: 权限管理工具写进 Skill 与部署手册"
```

---

## Task 13: auth 服务加 PKCE + nonce

**Files:**
- Modify: `site-builder/auth/login_handler.py`
- Create: `site-builder/auth/tests/test_pkce.py`
- Modify: `site-builder/auth/tests/test_login_handler.py`（现有 callback 测试需适配新 state 结构）

**Interfaces:**
- Consumes: 无（auth 服务内部）
- Produces:
  - `_pkce_pair() -> tuple[str, str]`（verifier, challenge）
  - `_encode_state(redirect: str) -> str`（state 只含 redirect+exp）
  - `_decode_state(state: str) -> str | None`（返回 redirect）
  - `_pkce_cookie(verifier, nonce, base) -> str`、`_read_pkce_cookie(event) -> dict | None`、`PKCE_COOKIE = "__Host-sb_pkce"`
  - `_exchange_code(code: str, verifier: str, nonce: str) -> dict`（多两个参数，校验 id_token 的 nonce；返回 `{email, name, idp}`）
  - `session.mint_session_jwt(email, name, secret, ttl_seconds=86400, idp="", scope="")`（payload 增 `idp`/`scope`，仅在非空时写入）

- [ ] **Step 1: 写失败测试**

创建 `site-builder/auth/tests/test_pkce.py`：

```python
"""PKCE（S256）+ nonce：防授权码注入与 id_token 重放。"""
import base64
import hashlib
from unittest.mock import patch

import pytest

import login_handler as lh

ENV = {"JWT_SECRET": "s3cret",
       "COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test"}


def _event(path, qs=None, cookies=None):
    return {"rawPath": path, "queryStringParameters": qs or {},
            "cookies": cookies or [],
            "requestContext": {"http": {"method": "GET"}}}


def test_pkce_pair_challenge_is_s256_of_verifier():
    verifier, challenge = lh._pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


def test_pkce_verifier_length_within_rfc7636():
    verifier, _ = lh._pkce_pair()
    assert 43 <= len(verifier) <= 128


def test_pkce_pair_is_random():
    assert lh._pkce_pair()[0] != lh._pkce_pair()[0]


@patch.dict(lh.os.environ, ENV)
def test_login_includes_code_challenge_and_nonce():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    loc = r["headers"]["Location"]
    assert "code_challenge=" in loc
    assert "code_challenge_method=S256" in loc
    assert "nonce=" in loc


@patch.dict(lh.os.environ, ENV)
def test_state_carries_only_redirect():
    """verifier/nonce 绝不能进 state（会经 URL/Referer/日志/历史泄漏）。"""
    import base64 as b64mod
    import json as jsonmod
    state = lh._encode_state("https://app-x.example.com/")
    assert lh._decode_state(state) == "https://app-x.example.com/"
    body = state.rpartition(".")[0]
    payload = jsonmod.loads(b64mod.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert set(payload) == {"r", "exp"}


@patch.dict(lh.os.environ, ENV)
def test_tampered_state_rejected():
    state = lh._encode_state("https://app-x.example.com/")
    body, _, sig = state.rpartition(".")
    assert lh._decode_state(f"{body}x.{sig}") is None


@patch.dict(lh.os.environ, ENV)
def test_login_sets_host_only_pkce_cookie():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    cookie = next(c for c in r["cookies"] if c.startswith(lh.PKCE_COOKIE))
    assert "Domain=" not in cookie          # __Host- 要求无 Domain
    assert "Secure" in cookie and "HttpOnly" in cookie
    assert "Path=/" in cookie and "Max-Age=300" in cookie
    # authorize URL 里不得出现 verifier
    assert "code_challenge=" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_callback_takes_verifier_from_cookie():
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    state = [q.split("state=")[1] for q in [r_login["headers"]["Location"]]
             if "state=" in q][0]
    import urllib.parse as up
    state = up.unquote(state.split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A",
                                    "idp": "Feishu"}) as ex:
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce_cookie]), None)
    assert r["statusCode"] == 302
    # verifier 来自 cookie，不是 state
    args = ex.call_args[0]
    assert args[0] == "abc" and args[1] and args[2]


@patch.dict(lh.os.environ, ENV)
def test_callback_without_pkce_cookie_is_rejected():
    """cookie 丢失时必须让用户重登，不能静默降级成无 PKCE 交换。"""
    state = lh._encode_state("https://app-x.example.com/")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_forged_pkce_cookie():
    state = lh._encode_state("https://app-x.example.com/")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[f"{lh.PKCE_COOKIE}=forged.sig"]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_clears_pkce_cookie():
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A", "idp": "Okta"}):
        r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                              cookies=[pkce_cookie]), None)
    assert any(c.startswith(lh.PKCE_COOKIE) and "Max-Age=0" in c
               for c in r["cookies"])


@patch.dict(lh.os.environ, ENV)
def test_callback_passes_idp_into_session():
    """idp 必须进会话 JWT，否则 Edge 的校验会把合法用户全拦住。"""
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce_cookie = next(c for c in r_login["cookies"]
                       if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    with patch.object(lh, "_exchange_code",
                      return_value={"email": "a@x.com", "name": "A",
                                    "idp": "Feishu"}), \
         patch.object(lh, "mint_session_jwt", return_value="tok") as mint:
        lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce_cookie]), None)
    assert mint.call_args.kwargs.get("idp") == "Feishu"


@patch.dict(lh.os.environ, ENV)
def test_exchange_code_rejects_nonce_mismatch():
    """id_token 的 nonce 与 state 里的不一致 → 拒绝（防 id_token 重放）。"""
    fake_tokens = {"id_token": "header.payload.sig"}

    class _Key:
        key = "k"

    with patch.object(lh, "_post_token", return_value=fake_tokens), \
         patch.object(lh, "_get_jwks_client") as jwks, \
         patch.object(lh.pyjwt, "decode",
                      return_value={"token_use": "id", "email": "a@x.com",
                                    "nonce": "WRONG"}):
        jwks.return_value.get_signing_key_from_jwt.return_value = _Key()
        with pytest.raises(ValueError, match="nonce"):
            lh._exchange_code("code", "ver123", "expected-nonce")


@patch.dict(lh.os.environ, ENV)
def test_exchange_code_accepts_matching_nonce():
    fake_tokens = {"id_token": "header.payload.sig"}

    class _Key:
        key = "k"

    with patch.object(lh, "_post_token", return_value=fake_tokens), \
         patch.object(lh, "_get_jwks_client") as jwks, \
         patch.object(lh.pyjwt, "decode",
                      return_value={"token_use": "id", "email": "a@x.com",
                                    "name": "Alice", "nonce": "good-nonce"}):
        jwks.return_value.get_signing_key_from_jwt.return_value = _Key()
        out = lh._exchange_code("code", "ver123", "good-nonce")
    assert out == {"email": "a@x.com", "name": "Alice"}


@patch.dict(lh.os.environ, ENV)
def test_post_token_body_includes_code_verifier():
    captured = {}

    def _fake_urlopen(req, timeout=None):
        captured["body"] = req.data.decode()

        class _R:
            def read(self):
                return b'{"id_token":"x"}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return _R()

    with patch.object(lh.urllib.request, "urlopen", _fake_urlopen):
        lh._post_token("thecode", "theverifier")
    assert "code_verifier=theverifier" in captured["body"]
    assert "grant_type=authorization_code" in captured["body"]
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_pkce.py -q`
Expected: FAIL — `AttributeError: module 'login_handler' has no attribute '_pkce_pair'`

- [ ] **Step 2b: 让 `session.mint_session_jwt` 带 `idp` / `scope` claim**

`idp` 是 spec §3.5 的主防线在会话侧的载体；`scope` 供 M3 的面板会话复用同一
函数。两者都只在非空时写入 payload——**空值不写**，这样现有 token 的字节形态
不变，Edge 的验签逻辑无需改动即可兼容。

先写测试 `site-builder/auth/tests/test_session.py`（在现有文件末尾追加）：

```python
def test_mint_includes_idp_when_given():
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret", idp="Feishu")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert payload["idp"] == "Feishu"
    assert payload["email"] == "a@x.com"


def test_mint_omits_idp_when_empty():
    """空值不写入：保持与一期 token 的字节形态兼容。"""
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert "idp" not in payload
    assert "scope" not in payload


def test_mint_includes_scope_for_console_session():
    import json, base64
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret",
                                   ttl_seconds=14400, scope="console")
    payload = json.loads(base64.urlsafe_b64decode(
        tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
    assert payload["scope"] == "console"


def test_verify_still_accepts_token_with_extra_claims():
    tok = session.mint_session_jwt("a@x.com", "Alice", "s3cret", idp="Okta")
    claims = session.verify_session_jwt(tok, "s3cret")
    assert claims["idp"] == "Okta"
```

（文件顶部若无 `import session` 则加上；沿用该文件既有的导入风格。）

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_session.py -q`
Expected: FAIL — `mint_session_jwt() got an unexpected keyword argument 'idp'`

然后改 `site-builder/auth/session.py`：

```python
def mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400,
                     idp: str = "", scope: str = "") -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"email": email, "name": name, "exp": int(time.time()) + ttl_seconds}
    # 只在非空时写入：保持与一期已签发 token 的形态兼容，Edge 侧无需改验签。
    if idp:
        claims["idp"] = idp        # spec §3.5：Edge 据此确认身份来自企业 IdP
    if scope:
        claims["scope"] = scope    # M3 面板会话用（Edge 不校验 scope）
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"
```

**注意**：`json.dumps` 的 key 顺序即 dict 插入顺序，`email`/`name`/`exp` 三个
仍在最前，新 claim 追加在后——与 Edge 的 `_verify_session_jwt` 仍字节级兼容
（它只按 key 取值，不依赖顺序，但保持顺序稳定便于人工比对）。

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`
Expected: PASS


- [ ] **Step 3: 改 login_handler.py**

在 `site-builder/auth/login_handler.py` 里：

顶部 import 区加 `import secrets`。

`_encode_state` / `_decode_state` 替换为：

```python
PKCE_COOKIE = "__Host-sb_pkce"


def _encode_state(redirect: str) -> str:
    """state 只放 redirect 与过期时间，**不放 code_verifier / nonce**。

    RFC 7636 的分工是授权请求只发 code_challenge、令牌请求才发 code_verifier。
    把明文 verifier 放进随 authorize URL 传输的 state（state 有 HMAC 签名，
    但内容是 base64 明文）会让它经浏览器地址栏、Referer、IdP 侧日志与浏览器
    历史各暴露一遍，PKCE 本应提供的"授权码被截获也换不到 token"的独立防护
    就没了；更要紧的是它不再绑定浏览器——攻击者把自己登录产生的 callback URL
    发给受害者，verifier 跟在 URL 里，后端就能替受害者完成交换并种下攻击者
    账户的会话（login CSRF / account confusion）。verifier 放 host-only
    cookie 才与浏览器绑定。见 spec §7.2。
    """
    body = base64.urlsafe_b64encode(json.dumps(
        {"r": redirect, "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
    return f"{body}.{_state_sig(body)}"


def _decode_state(state: str) -> str | None:
    """验签 + 验期，失败返回 None；成功返回 redirect。"""
    try:
        body, _, sig = state.rpartition(".")
        if not hmac.compare_digest(sig, _state_sig(body)):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return payload["r"]
    except Exception:
        return None


def _pkce_cookie(verifier: str, nonce: str, base: str) -> str:
    """把 verifier/nonce 装进 auth 子域的 host-only 短期 cookie。

    __Host- 前缀是浏览器强制的：必须 Secure、必须 Path=/、**必须无 Domain**，
    因此它只回发给 auth.{base}（/login 与 /callback 同域，读得到）。
    5 分钟过期，用完即清。
    """
    payload = base64.urlsafe_b64encode(
        json.dumps({"v": verifier, "n": nonce}).encode()).decode().rstrip("=")
    sig = _state_sig(payload)
    return (f"{PKCE_COOKIE}={payload}.{sig}; Path=/; Max-Age=300; "
            f"Secure; HttpOnly; SameSite=Lax")


def _read_pkce_cookie(event) -> dict | None:
    """从 callback 请求里取回 verifier/nonce；验签失败或缺失返回 None。"""
    for raw in (event.get("cookies") or []):
        name, _, value = raw.partition("=")
        if name.strip() != PKCE_COOKIE:
            continue
        body, _, sig = value.rpartition(".")
        if not hmac.compare_digest(sig, _state_sig(body)):
            return None
        try:
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except Exception:
            return None
        return {"v": data.get("v", ""), "n": data.get("n", "")}
    return None


def _pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256：返回 (code_verifier, code_challenge)。"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge
```

`_exchange_code` 拆成 `_post_token` + `_exchange_code`：

```python
def _post_token(code: str, verifier: str) -> dict:
    domain = os.environ["COGNITO_DOMAIN"]
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": os.environ["CLIENT_ID"],
        "redirect_uri": f"https://auth.{os.environ['BASE_DOMAIN']}/callback",
        "code_verifier": verifier,
    }).encode()
    basic = base64.b64encode(
        f"{os.environ['CLIENT_ID']}:{os.environ['CLIENT_SECRET']}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token", data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _exchange_code(code: str, verifier: str, nonce: str) -> dict:
    """code → Cognito token → JWKS 验签 + nonce 校验 → {email, name}"""
    tokens = _post_token(code, verifier)
    signing_key = _get_jwks_client().get_signing_key_from_jwt(tokens["id_token"])
    claims = pyjwt.decode(
        tokens["id_token"], signing_key.key, algorithms=["RS256"],
        audience=os.environ["CLIENT_ID"],
        issuer=f"https://cognito-idp.us-east-1.amazonaws.com/{os.environ['USER_POOL_ID']}")
    if claims.get("token_use") != "id":
        raise ValueError("token_use != id")
    # nonce 绑定本次 /login：缺失或不匹配都拒绝，防他人的 id_token 被重放进
    # 这个 callback（PKCE 保护授权码，nonce 保护 id_token）。
    if claims.get("nonce") != nonce:
        raise ValueError("id_token nonce 与本次登录不匹配")
    # idp 由 pre-token 触发器注入 id token（两个容器都写，见 Task 14 Step 4b）。
    # 本地用户没有它——会话里就不会有，Edge 据此拦截（spec §3.5）。
    return {"email": claims["email"], "name": claims.get("name", claims["email"]),
            "idp": claims.get("idp", "")}
```

`handler` 的 `/login` 与 `/callback` 分支替换为：

```python
    if path == "/login":
        redirect = qs.get("redirect", f"https://{base}/")
        if not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid redirect"}
        verifier, challenge = _pkce_pair()
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
        auth_url = (f"{os.environ['COGNITO_DOMAIN']}/oauth2/authorize?"
                    + urllib.parse.urlencode({
                        "response_type": "code", "client_id": os.environ["CLIENT_ID"],
                        "redirect_uri": f"https://auth.{base}/callback",
                        "scope": "openid email profile",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "nonce": nonce,
                        "state": _encode_state(redirect)}))
        # verifier/nonce 走 host-only cookie（与浏览器绑定），不进 URL
        return {"statusCode": 302, "headers": {"Location": auth_url},
                "cookies": [_pkce_cookie(verifier, nonce, base)], "body": ""}

    if path == "/callback":
        redirect = _decode_state(qs.get("state", ""))
        if redirect is None or not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid or expired state"}
        pkce = _read_pkce_cookie(event)
        if pkce is None:
            # cookie 丢失（换了浏览器、被清、超过 5 分钟）——比静默降级到
            # 无 PKCE 安全：让用户重新走一次登录。
            return {"statusCode": 400,
                    "body": "登录状态已过期，请重新登录"}
        user = _exchange_code(qs["code"], pkce["v"], pkce["n"])
        token = mint_session_jwt(user["email"], user["name"],
                                 os.environ["JWT_SECRET"], idp=user.get("idp", ""))
        cookie = (f"sb_session={token}; Domain=.{base}; Path=/; Max-Age=86400; "
                  f"Secure; HttpOnly; SameSite=Lax")
        clear_pkce = f"{PKCE_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        return {"statusCode": 302, "headers": {"Location": redirect},
                "cookies": [cookie, clear_pkce], "body": ""}
```

- [ ] **Step 4: 修既有测试**

`_encode_state` 仍是单参数（只放 redirect），所以 `test_login_handler.py` 里
既有的 `lh._encode_state("https://...")` 调用**不需要改签名**。但两处 callback
测试现在会因缺 PKCE cookie 而返回 400，需要补上 cookie：

```python
@patch.dict(lh.os.environ, ENV)
@patch.object(lh, "_exchange_code", return_value={"email": "a@x.com", "name": "Alice",
                                                  "idp": "Feishu"})
def test_callback_sets_cookie_and_redirects(mock_ex):
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/page?tab=2"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "https://app-x.example.com/page?tab=2"
    cookie = next(c for c in r["cookies"] if c.startswith("sb_session="))
    assert "Domain=.example.com" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie
```

`test_callback_rejects_tampered_state` 与 `test_callback_rejects_expired_state`
断言的是 400，改前改后都成立（现在也可能因缺 cookie 而 400——但它们验的是
state 校验，为避免断言到错误原因，给它们也补上有效的 pkce cookie，
或改成直接断言 `lh._decode_state(...) is None`）。该文件的 `_event` helper
已支持 `cookies` 参数（一期就有）。

- [ ] **Step 5: 运行测试确认通过**

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`
Expected: PASS（原 11 + 新增 10）

- [ ] **Step 6: 提交**

```bash
git add site-builder/auth/login_handler.py site-builder/auth/tests/
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(auth): OAuth PKCE(S256) + nonce 校验"
```

---

## Task 14: 平台专用 user pool 部署脚本

**Files:**
- Create: `site-builder/scripts/deploy_pool.py`
- Modify: `site-builder/auth/deploy_auth.py`（`ensure_pre_token_trigger` 支持传入 pool_id，供新脚本复用）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`（纯逻辑部分：client 配置生成、回调 URL 组装）

**Interfaces:**
- Consumes: `site-builder/config.ini`
- Produces:
  - `deploy_pool.pool_config(base_domain: str) -> dict`（CreateUserPool 参数）
  - `deploy_pool.client_configs(base_domain: str, extra_mcp_callbacks: list[str]) -> dict`（三个 client 的 CreateUserPoolClient 参数，键为 `site` / `mcp` / `machine`）
  - CLI：`python3 site-builder/scripts/deploy_pool.py [--idp oidc|none]`，幂等；结束时打印要回填 config.ini 的值

**说明**：IdP 联邦配置（飞书适配器 / Okta）用参数化的 OIDC provider 配置，脚本只负责"如果 config 里给了 IdP 参数就创建/更新 OIDC provider"，不写死任何 IdP。真机联邦验证在 Task 15。

- [ ] **Step 1: 写失败测试**

创建 `site-builder/deployer/tests/test_deploy_pool.py`：

```python
"""平台专用 user pool 的配置生成（纯逻辑，不连 AWS）。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

import deploy_pool as dp


def test_pool_config_requires_essentials_tier():
    # pre-token V2（access token 定制）要求 Essentials+
    assert dp.pool_config("example.com")["UserPoolTier"] == "ESSENTIALS"


def test_pool_config_has_email_attribute():
    cfg = dp.pool_config("example.com")
    assert "email" in cfg["AutoVerifiedAttributes"]


def test_pool_config_disables_self_signup():
    """P0：允许自注册会让 allowed_users="org" 失去"组织"语义。

    Edge 对 org 的判定只是"持有有效平台会话"，不查邮箱域；若任何人能自注册，
    就等于所有 org 站点对整个互联网开放（spec §3.5）。
    """
    cfg = dp.pool_config("example.com")
    assert cfg["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True


def test_production_clients_exclude_local_cognito_users(idp_name="Okta"):
    """生产 client 不能放 COGNITO——否则托管登录仍暴露本地登录/注册入口。"""
    clients = dp.client_configs("example.com", [], idp_name=idp_name)
    for key in ("site", "mcp"):
        assert clients[key]["SupportedIdentityProviders"] == [idp_name]
        assert "COGNITO" not in clients[key]["SupportedIdentityProviders"]


def test_clients_fall_back_to_cognito_only_without_idp():
    """未配 IdP 时（首次部署、联邦还没接）允许 COGNITO，但脚本要显式告警。"""
    clients = dp.client_configs("example.com", [], idp_name=None)
    assert clients["site"]["SupportedIdentityProviders"] == ["COGNITO"]


def test_site_client_callback_is_auth_subdomain():
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    assert clients["site"]["CallbackURLs"] == ["https://auth.example.com/callback"]


def test_site_client_is_confidential():
    clients = dp.client_configs("example.com", [])
    assert clients["site"]["GenerateSecret"] is True


def test_site_client_flows():
    site = dp.client_configs("example.com", [], idp_name="Okta")["site"]
    assert site["AllowedOAuthFlows"] == ["code"]
    assert set(site["AllowedOAuthScopes"]) == {"openid", "email", "profile"}


def test_mcp_client_includes_localhost_callback():
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    # 18765：8765/8766 被 Quick Desktop 常驻占用（一期实测）
    assert "http://localhost:18765/callback" in clients["mcp"]["CallbackURLs"]


def test_mcp_client_accepts_extra_callbacks():
    clients = dp.client_configs("example.com",
                                ["https://agentcore.example/identities/cb"],
                                idp_name="Okta")
    assert "https://agentcore.example/identities/cb" in clients["mcp"]["CallbackURLs"]


def test_mcp_client_is_public():
    # MCP 客户端（Claude Code 等）无法安全保存 secret
    assert dp.client_configs("example.com", [], idp_name="Okta")["mcp"]["GenerateSecret"] is False


def test_machine_client_uses_client_credentials():
    machine = dp.client_configs("example.com", [], idp_name="Okta")["machine"]
    assert machine["AllowedOAuthFlows"] == ["client_credentials"]
    assert machine["GenerateSecret"] is True
    assert machine["CallbackURLs"] == []


def test_client_configs_have_no_managed_login_version():
    """ManagedLoginVersion 属于 domain API，混进 client 参数会 ParamValidationError。

    断言 dict 不够——必须让 botocore 真正校验参数名（见下一个测试）。
    """
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    for key in ("site", "mcp", "machine"):
        assert "ManagedLoginVersion" not in clients[key]


def test_client_configs_pass_botocore_param_validation():
    """用 Stubber 让 botocore 按真实 service model 校验参数名与类型。

    纯 dict 断言抓不到"参数放错 API"这类错误——本计划上一版就把
    ManagedLoginVersion 放进了 client 参数，dict 测试全绿，真实调用必失败。
    """
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    clients = dp.client_configs("example.com", [], idp_name="Okta")
    with Stubber(cog) as stub:
        for key in ("site", "mcp", "machine"):
            params = {"UserPoolId": "us-east-1_test", **clients[key]}
            stub.add_response("create_user_pool_client",
                              {"UserPoolClient": {"ClientId": "c"}}, params)
            cog.create_user_pool_client(**params)   # 参数非法会在此抛


def test_domain_creation_requests_managed_login_v2():
    """domain 必须显式带 ManagedLoginVersion=2，否则默认 classic hosted UI。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {}},
                          {"UserPoolId": "us-east-1_test"})
        stub.add_response("create_user_pool_domain", {},
                          {"Domain": "pfx", "UserPoolId": "us-east-1_test",
                           "ManagedLoginVersion": 2})
        assert dp._ensure_domain(cog, "us-east-1_test", "pfx") == "pfx"


def test_existing_domain_with_v1_is_upgraded():
    """已存在但停在 v1 的 domain 要被纠正——幂等重跑得能修配错的资源。"""
    import boto3
    from botocore.stub import Stubber

    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {"Domain": "old"}},
                          {"UserPoolId": "us-east-1_test"})
        stub.add_response("describe_user_pool_domain",
                          {"DomainDescription": {"ManagedLoginVersion": 1}},
                          {"Domain": "old"})
        stub.add_response("update_user_pool_domain", {},
                          {"Domain": "old", "UserPoolId": "us-east-1_test",
                           "ManagedLoginVersion": 2})
        assert dp._ensure_domain(cog, "us-east-1_test", "pfx") == "old"


def test_machine_client_has_no_user_flows():
    machine = dp.client_configs("example.com", [], idp_name="Okta")["machine"]
    assert "code" not in machine["AllowedOAuthFlows"]
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'deploy_pool'`

- [ ] **Step 3: 写实现**

创建 `site-builder/scripts/deploy_pool.py`：

```python
#!/usr/bin/env python3
"""部署平台专用 Cognito user pool（与上游 Quick SSO 的 pool 解耦）。幂等可重跑。

为什么要专用 pool：一期平台复用了 feishu-quick-sso 的 pool，平台侧配置
（pre-token 触发器、app client、token 形态）与 Quick SSO 相互牵制。二期
把平台身份独立出来，之后改平台配置不再影响别的消费方。

**IdP 无关**：本脚本只建 pool + 三个 app client + pre-token 触发器。
联邦哪个 IdP 由 config.ini [IdP] 段决定——飞书适配器（feishu-quick-sso 的
OIDC 适配器）与标准 IdP（Okta、Azure AD 等）走同一条 OIDC provider 路径，
平台其余部分只消费 email/name claim。

三个 app client：
- site：auth 服务用（confidential，authorization_code）
- mcp：MCP 客户端 OAuth 用（public，需预注册回调——Cognito 无 dynamic
  client registration）
- machine：key-proxy 用（client_credentials；M4 才消费，这里一并建好）

用法：
    python3 site-builder/scripts/deploy_pool.py
    python3 site-builder/scripts/deploy_pool.py --domain-prefix my-site-builder
"""
import argparse
import configparser
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent

POOL_NAME = "site-builder-users"
MCP_LOCALHOST_CALLBACK = "http://localhost:18765/callback"


def pool_config(base_domain: str) -> dict:
    """CreateUserPool 参数。

    UserPoolTier=ESSENTIALS 是硬要求：pre-token-generation V2（往 access
    token 注入 email）只在 Essentials+ 可用，而 MCP 网关只收 access token
    ——LITE 档会让 owner 识别整条链断掉（一期实测）。
    """
    return {
        "PoolName": POOL_NAME,
        "UserPoolTier": "ESSENTIALS",
        "AutoVerifiedAttributes": ["email"],
        "UsernameAttributes": ["email"],
        "Schema": [{"Name": "email", "AttributeDataType": "String",
                    "Required": True, "Mutable": True}],
        # AllowAdminCreateUserOnly=True 关闭自注册。这是 allowed_users="org"
        # 的安全前提：Edge 对 org 的判定只是"持有有效平台会话"，不查邮箱域，
        # 所以 pool 里绝不能有非企业身份（spec §3.5）。
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "UserPoolTags": {"project": "site-builder", "managed_by": "deploy_pool.py"},
    }


def client_configs(base_domain: str, extra_mcp_callbacks: list[str],
                   idp_name: str | None = None) -> dict:
    """三个 app client 的参数。

    idp_name 给出时，site/mcp 的 SupportedIdentityProviders **只列该 IdP**，
    不含 COGNITO——否则托管登录页仍暴露本地用户登录/注册入口，
    allowed_users="org" 的语义就被击穿（spec §3.5）。未给出时回落
    ["COGNITO"]（首次部署、联邦还没接），main() 会显式告警。
    """
    providers = [idp_name] if idp_name else ["COGNITO"]
    site = {
        "ClientName": "site-builder-site",
        "GenerateSecret": True,
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": [f"https://auth.{base_domain}/callback"],
        "LogoutURLs": [f"https://auth.{base_domain}/logout"],
        "SupportedIdentityProviders": providers,
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
    }
    mcp = {
        "ClientName": "site-builder-mcp",
        "GenerateSecret": False,   # Claude Code 等客户端无法安全保存 secret
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": [MCP_LOCALHOST_CALLBACK] + list(extra_mcp_callbacks),
        "SupportedIdentityProviders": providers,
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
    }
    machine = {
        "ClientName": "site-builder-machine",
        "GenerateSecret": True,
        "AllowedOAuthFlows": ["client_credentials"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": [],   # 建 resource server 后回填（M4）
        "CallbackURLs": [],
        # machine 走 client_credentials，与用户身份无关
        "SupportedIdentityProviders": ["COGNITO"],
    }
    return {"site": site, "mcp": mcp, "machine": machine}


def _cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(HERE.parent / "config.ini")
    return cfg


def _find_pool(cog, name: str) -> str | None:
    token = None
    while True:
        kw = {"NextToken": token} if token else {}
        resp = cog.list_user_pools(MaxResults=60, **kw)
        for p in resp.get("UserPools", []):
            if p["Name"] == name:
                return p["Id"]
        token = resp.get("NextToken")
        if not token:
            return None


# update_user_pool 是整体替换语义（一期实测坑）：只回传已知可变字段，
# 避免误清其他配置。与 deploy_auth.py 的 _POOL_MUTABLE 同源。
_POOL_MUTABLE = ("Policies", "DeletionProtection", "AutoVerifiedAttributes",
                 "MfaConfiguration", "EmailConfiguration", "AdminCreateUserConfig",
                 "AccountRecoverySetting", "UserAttributeUpdateSettings",
                 "VerificationMessageTemplate", "UserPoolTier", "LambdaConfig")


def _ensure_pool(cog, base_domain: str) -> str:
    """幂等：已有 pool 也要把关键配置纠正回来，不能直接 return。

    否则"幂等重跑"修不了已经建错的 pool——尤其
    AllowAdminCreateUserOnly（自注册开着就等于全部 org 站点对公网开放，
    spec §3.5）。
    """
    existing = _find_pool(cog, POOL_NAME)
    if not existing:
        pool_id = cog.create_user_pool(**pool_config(base_domain))["UserPool"]["Id"]
        print(f"  新建 pool {pool_id}")
        return pool_id

    print(f"  已存在 pool {existing}，核对关键配置")
    pool = cog.describe_user_pool(UserPoolId=existing)["UserPool"]
    kwargs = {k: pool[k] for k in _POOL_MUTABLE if k in pool}
    # describe 回传的废弃字段，与 PasswordPolicy.TemporaryPasswordValidityDays
    # 同传会被 update-user-pool 拒绝（一期实测）
    kwargs.get("AdminCreateUserConfig", {}).pop("UnusedAccountValidityDays", None)
    desired = pool_config(base_domain)
    kwargs["AdminCreateUserConfig"] = desired["AdminCreateUserConfig"]
    kwargs["UserPoolTier"] = desired["UserPoolTier"]
    cog.update_user_pool(UserPoolId=existing, **kwargs)

    # 复验：update 是整体替换，静默漂移过一次就够致命，必须读回确认
    after = cog.describe_user_pool(UserPoolId=existing)["UserPool"]
    only_admin = after.get("AdminCreateUserConfig", {}).get(
        "AllowAdminCreateUserOnly")
    if only_admin is not True:
        raise SystemExit(
            f"pool {existing} 的 AllowAdminCreateUserOnly={only_admin!r}，"
            "自注册未关闭——allowed_users=\"org\" 会对公网开放，中止")
    if after.get("UserPoolTier") != "ESSENTIALS":
        raise SystemExit(
            f"pool {existing} 的 tier={after.get('UserPoolTier')!r}，"
            "pre-token V2 需要 ESSENTIALS+，中止")
    print("  ✓ 自注册已关闭、tier=ESSENTIALS")
    return existing


MANAGED_LOGIN_V2 = 2


def _ensure_domain(cog, pool_id: str, prefix: str) -> str:
    """建/纠正托管域名。

    **`ManagedLoginVersion` 属于 domain API，不是 client API**：
    `CreateUserPoolClient` / `UpdateUserPoolClient` 没有这个参数，传进去会
    `ParamValidationError: Unknown parameter`（已用仓库当前 botocore 的
    service model 实测：client 两个 False、domain 两个 True）。
    不显式指定时 domain 默认 classic hosted UI（version 1），而
    `CreateManagedLoginBranding` 给的是 managed login 的 style——两者不匹配
    时登录页仍不可用。
    """
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    existing = pool.get("Domain")
    if not existing:
        cog.create_user_pool_domain(Domain=prefix, UserPoolId=pool_id,
                                    ManagedLoginVersion=MANAGED_LOGIN_V2)
        print(f"  域名前缀 {prefix}（managed login v{MANAGED_LOGIN_V2}）")
        return prefix

    # 已存在：核对版本，漂移了就纠回来（幂等重跑要能修配错的 domain）
    desc = cog.describe_user_pool_domain(Domain=existing)
    version = desc.get("DomainDescription", {}).get("ManagedLoginVersion")
    if version != MANAGED_LOGIN_V2:
        cog.update_user_pool_domain(Domain=existing, UserPoolId=pool_id,
                                    ManagedLoginVersion=MANAGED_LOGIN_V2)
        print(f"  域名 {existing}: managed login v{version} → v{MANAGED_LOGIN_V2}")
    else:
        print(f"  域名 {existing}（managed login v{version}）")
    return existing


def _ensure_clients(cog, pool_id: str, base_domain: str,
                    extra_mcp_callbacks: list[str],
                    idp_name: str | None = None) -> dict:
    existing = {}
    token = None
    while True:
        kw = {"NextToken": token} if token else {}
        resp = cog.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60, **kw)
        for c in resp.get("UserPoolClients", []):
            existing[c["ClientName"]] = c["ClientId"]
        token = resp.get("NextToken")
        if not token:
            break

    out = {}
    for key, params in client_configs(base_domain, extra_mcp_callbacks,
                                      idp_name).items():
        name = params["ClientName"]
        if name in existing:
            client_id = existing[name]
            update = {k: v for k, v in params.items() if k != "GenerateSecret"}
            cog.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id,
                                        **update)
            print(f"  更新 client {name} = {client_id}")
        else:
            client_id = cog.create_user_pool_client(
                UserPoolId=pool_id, **params)["UserPoolClient"]["ClientId"]
            print(f"  新建 client {name} = {client_id}")
        out[key] = client_id
    return out


def _ensure_branding(cog, pool_id: str, clients: dict) -> None:
    """给 API 创建的 app client 套 branding style。

    AWS 明确：经 CreateUserPoolClient 建的 client **不会**自动获得 branding
    style，套上之前 managed login 与 classic hosted UI 页面都不可用
    （控制台建的会自动有，所以这个坑只在脚本化部署时出现）。不做这步，
    后面所有登录验证会在 /oauth2/authorize 第一步就失败。
    用 Cognito 默认样式（UseCognitoProvidedValues=True），不做定制。
    前提是 domain 已是 managed login v2（见 _ensure_domain）——style 与
    domain 版本不匹配时登录页依然不可用。
    """
    for key in ("site", "mcp"):
        try:
            cog.create_managed_login_branding(
                UserPoolId=pool_id, ClientId=clients[key],
                UseCognitoProvidedValues=True)
            print(f"  {key}: 已套默认 branding")
        except cog.exceptions.ManagedLoginBrandingExistsException:
            print(f"  {key}: branding 已存在")


def _ensure_oidc_idp(cog, pool_id: str, idp: dict) -> None:
    """联邦一个 OIDC IdP。飞书适配器与标准 IdP（Okta 等）走同一条路径。"""
    name = idp["provider_name"]
    details = {
        "client_id": idp["client_id"],
        "client_secret": idp["client_secret"],
        "attributes_request_method": "GET",
        "oidc_issuer": idp["issuer"],
        "authorize_scopes": idp.get("scopes", "openid email profile"),
    }
    mapping = {"email": "email", "name": "name"}
    try:
        cog.describe_identity_provider(UserPoolId=pool_id, ProviderName=name)
        cog.update_identity_provider(UserPoolId=pool_id, ProviderName=name,
                                     ProviderDetails=details,
                                     AttributeMapping=mapping)
        print(f"  更新 IdP {name}")
    except cog.exceptions.ResourceNotFoundException:
        cog.create_identity_provider(UserPoolId=pool_id, ProviderName=name,
                                     ProviderType="OIDC",
                                     ProviderDetails=details,
                                     AttributeMapping=mapping)
        print(f"  新建 IdP {name}")


def _store_client_secrets(cog, pool_id: str, clients: dict, region: str) -> None:
    """client secret 直接写 SSM SecureString，**不打印明文**。

    不要改成打印 `aws ssm put-parameter --value '<secret>'` 让人手敲：
    那会把凭证留在 shell history、终端回滚缓冲与 agent transcript 里，
    执行时还会出现在进程参数（ps 可见）。
    """
    import boto3
    ssm = boto3.client("ssm", region_name=region)
    for key, param in (("site", "/site-builder/site-client-secret"),
                       ("machine", "/site-builder/machine-client-secret")):
        secret = cog.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=clients[key])["UserPoolClient"].get(
                "ClientSecret", "")
        if not secret:
            print(f"  {param}: 该 client 无 secret（public client），跳过")
            continue
        ssm.put_parameter(Name=param, Value=secret, Type="SecureString",
                          Overwrite=True)
        print(f"  {param}: 已写入（长度 {len(secret)}）")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain-prefix", default="site-builder-auth",
                    help="Cognito 托管域名前缀（全局唯一）")
    ap.add_argument("--mcp-callback", action="append", default=[],
                    help="额外的 MCP 回调 URL（如 AgentCore identities 回调），可重复")
    args = ap.parse_args()

    import boto3
    cfg = _cfg()
    region = cfg["Platform"]["region"]
    base_domain = cfg["Platform"]["base_domain"]
    cog = boto3.client("cognito-idp", region_name=region)

    print("① user pool（禁自注册）")
    pool_id = _ensure_pool(cog, base_domain)

    print("② 托管域名")
    domain_prefix = _ensure_domain(cog, pool_id, args.domain_prefix)

    # IdP 必须先建：client 的 SupportedIdentityProviders 要引用它的名字，
    # 且生产 client 不放 COGNITO（spec §3.5）——顺序颠倒会因 provider
    # 不存在而 InvalidParameterException。
    idp_name = None
    if cfg.has_section("IdP") and cfg["IdP"].get("provider_name"):
        print("③ OIDC IdP 联邦")
        idp = dict(cfg["IdP"])
        _ensure_oidc_idp(cog, pool_id, idp)
        idp_name = idp["provider_name"]
    else:
        print("③ 跳过 IdP 联邦（config.ini 无 [IdP] 段）")
        print("   ⚠️  未接企业 IdP：site/mcp client 暂时只能用 COGNITO 本地用户。")
        print("      此状态下 allowed_users=\"org\" 不代表\"全组织\"——")
        print("      接上 IdP 后重跑本脚本，client 会切成仅该 IdP。")

    print("④ app clients")
    clients = _ensure_clients(cog, pool_id, base_domain, args.mcp_callback, idp_name)

    print("⑤ managed login branding（API 建的 client 必须显式套）")
    _ensure_branding(cog, pool_id, clients)

    print("⑥ pre-token 触发器（注入 email + idp claim）")
    sys.path.insert(0, str(HERE.parent / "auth"))
    import deploy_auth
    role_arn = deploy_auth.ensure_lambda_role()
    deploy_auth.ensure_pre_token_trigger(role_arn, pool_id=pool_id)

    print("⑦ client secret → SSM")
    _store_client_secrets(cog, pool_id, clients, region)

    print("\n回填 site-builder/config.ini：")
    print(f"  [Cognito] user_pool_id = {pool_id}")
    print(f"  [Cognito] domain = https://{domain_prefix}.auth.{region}.amazoncognito.com")
    print(f"  [Cognito] site_client_id = {clients['site']}")
    print(f"  [Cognito] mcp_client_id = {clients['mcp']}")
    print(f"  [Cognito] machine_client_id = {clients['machine']}")
    if idp_name:
        print(f"\n在 IdP（{idp_name}）侧把这个回调加进白名单：")
        print(f"  https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 改 deploy_auth.ensure_pre_token_trigger：支持 pool_id + 按 pool 区分 StatementId**

修改 `site-builder/auth/deploy_auth.py` 的 `ensure_pre_token_trigger` 签名与首行：

```python
def ensure_pre_token_trigger(role_arn: str, pool_id: str | None = None) -> None:
    """部署 pre-token-generation V2 Lambda 并挂到用户池。

    真机钉死（2026-07-29，AGENTCORE-SPIKE.md §7）：部署 MCP 网关只接受
    access token，而 Cognito access token 默认不含 email——owner 识别全靠
    这个触发器把 email 注入 access token。要求用户池 Essentials+ tier。

    pool_id 显式传入时用它（deploy_pool.py 建新 pool 后立即挂载）；
    默认取 config.ini 的当前 pool。
    """
    fn = "site-auth-pre-token"
    pool_id = pool_id or CFG["Cognito"]["user_pool_id"]
```

**同一函数里把 `add_permission` 的 StatementId 改为按 pool 区分**（这是 M1
切换能否成功的关键——见下方说明）：

```python
    # StatementId 必须带 pool 标识：固定 id + 吞掉 ResourceConflictException
    # 会让新 pool 的授权永远加不上（旧语句已占用该 id，但它的 SourceArn 绑的是
    # 旧 pool）→ 新 pool 调用触发器被拒 → email/idp claim 注入失败，
    # MCP 的 owner 识别整条链断掉，token 签发本身也可能报 trigger 错误。
    # 迁移期新旧两条语句并存，验证通过后再删旧的。
    sid = "cognito-invoke-" + re.sub(r"[^A-Za-z0-9-]", "-", pool_id)
    try:
        lam.add_permission(FunctionName=fn, StatementId=sid,
                           Action="lambda:InvokeFunction",
                           Principal="cognito-idp.amazonaws.com",
                           SourceArn=f"arn:aws:cognito-idp:{REGION}:"
                                     f"{CFG['Platform']['account_id']}:userpool/{pool_id}")
        print(f"  已授权 {pool_id} 调用 {fn}（{sid}）")
    except lam.exceptions.ResourceConflictException:
        pass  # 同一 pool 重复运行，幂等
```

文件顶部 import 区加 `import re`。**保留**历史的 `cognito-invoke` 语句不动
（旧 pool 仍在用），M1 验证通过后由 Task 15 Step 9 显式删除。

- [ ] **Step 4b: 扩展 pre-token 触发器注入 `idp` claim**

`allowed_users="org"` 的主防线需要 Edge 能判断会话来自哪个 IdP
（spec §3.5）。改 `site-builder/auth/pre_token_email.py`：

```python
def handler(event, context):
    attrs = event["request"]["userAttributes"]
    claims = {}
    email = attrs.get("email", "")
    if email:
        claims["email"] = email
    # 联邦用户的 identities 是 JSON 字符串（Cognito 传参形态），
    # 本地用户没有该属性——没有 idp claim 正是 Edge 要拦的信号。
    idp = _provider_name(attrs.get("identities", ""))
    if idp:
        claims["idp"] = idp
    if claims:
        # idTokenGeneration 与 accessTokenGeneration 是**两个独立容器**，
        # 只写一个不会同步到另一个（官方文档明示）。两处都要写：
        #   - id token：auth 服务 /callback 验签后从它取 email/idp 签会话
        #   - access token：MCP 网关只收 access token，owner 识别靠它
        # 少写 id token 那份 → 会话 JWT 永远没有 idp → Edge 开关一开
        # 全部合法用户被 302 拦死。
        override = {"claimsToAddOrOverride": claims}
        event["response"]["claimsAndScopeOverrideDetails"] = {
            "idTokenGeneration": dict(override),
            "accessTokenGeneration": dict(override)}
    return event


def _provider_name(identities) -> str:
    """从 identities 属性取 providerName。形态在真机 spike 确认（Task 15）。"""
    import json
    if not identities:
        return ""
    try:
        parsed = json.loads(identities) if isinstance(identities, str) else identities
    except Exception:
        return ""
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        if isinstance(first, dict):
            return str(first.get("providerName", ""))
    return ""
```

配套单测 `site-builder/auth/tests/test_pre_token.py`：

```python
import pre_token_email as pt


def _event(attrs):
    return {"request": {"userAttributes": attrs}, "response": {}}


import pytest


def _claims(ev, container):
    return ev["response"]["claimsAndScopeOverrideDetails"][container][
        "claimsToAddOrOverride"]


@pytest.mark.parametrize("container", ["idTokenGeneration",
                                       "accessTokenGeneration"])
def test_injects_email_and_idp_into_both_containers(container):
    """两个容器都要写：id token 供 auth 签会话，access token 供 MCP 网关。

    只写 accessTokenGeneration 会让会话 JWT 永远没有 idp——Edge 的
    REQUIRE_IDP_CLAIM 一开，全部合法用户被 302 拦死（spec §3.5）。
    """
    ev = pt.handler(_event({
        "email": "a@x.com",
        "identities": '[{"providerName":"Feishu","userId":"u1"}]'}), None)
    assert _claims(ev, container) == {"email": "a@x.com", "idp": "Feishu"}


def test_local_user_gets_no_idp_claim():
    """本地用户没有 idp claim——这正是 Edge 要拦的信号（spec §3.5）。"""
    ev = pt.handler(_event({"email": "local@x.com"}), None)
    for container in ("idTokenGeneration", "accessTokenGeneration"):
        claims = _claims(ev, container)
        assert claims == {"email": "local@x.com"}
        assert "idp" not in claims


def test_malformed_identities_does_not_raise():
    ev = pt.handler(_event({"email": "a@x.com", "identities": "{not json"}), None)
    assert _claims(ev, "idTokenGeneration") == {"email": "a@x.com"}
    assert _claims(ev, "accessTokenGeneration") == {"email": "a@x.com"}


def test_no_attributes_leaves_response_untouched():
    ev = pt.handler(_event({}), None)
    assert ev["response"] == {}
```

Run: `cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_pre_token.py -q`
Expected: PASS（5 passed——参数化的两个容器各算一条）

**注意**：`identities` 属性的确切形态（是 JSON 字符串还是已解析的 list、
首次登录时是否就位）列为 Task 15 的真机 spike——`_provider_name` 对两种形态
都容错，spike 后按实测收紧或补注释。

- [ ] **Step 5: 运行测试确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS（10 passed）

- [ ] **Step 6: 加 config.ini.example 的 [IdP] 段**

在 `site-builder/config.ini.example` 末尾追加：

```ini
# 可选：给平台专用 user pool 联邦一个 OIDC IdP。
# 平台对 IdP 无感——只要 IdP 能给 email claim 即可（飞书适配器与
# Okta/Azure AD 等标准 IdP 走同一条配置路径，见 DEPLOY.md ①）。
# 留空则只建 pool 与 client，联邦另行手工配置。
[IdP]
provider_name =
issuer =
client_id =
client_secret =
scopes = openid email profile
```

- [ ] **Step 7: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/auth/deploy_auth.py \
  site-builder/auth/pre_token_email.py site-builder/auth/tests/test_pre_token.py \
  site-builder/deployer/tests/test_deploy_pool.py site-builder/config.ini.example
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "feat(scripts): 平台专用 user pool 部署脚本（IdP 无关，三个 app client）"
```

---

## Task 15: 真机切换到专用 pool

**Files:**
- Modify: `site-builder/config.ini`（本地，gitignored）
- Modify: `site-builder/DEPLOY.md`（① 阶段改写为 IdP 无关两分支 + 切换步骤）
- Modify: `docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md`（若 spike 结论与 spec 不符则更新）

**Interfaces:**
- Consumes: Task 13/14
- Produces: 生产环境跑在专用 pool 上；旧 pool 的平台配置已清理；标准 IdP 分支已真机验证

**这是 M1 的验收任务，含两个 spike。**

- [ ] **Step 1: [真机] 建 pool 与 client**

先在 `site-builder/config.ini` 填好 `[IdP]` 段（飞书适配器的 issuer / client_id / client_secret，从一期部署记录取），然后：

Run:
```bash
python3 site-builder/scripts/deploy_pool.py --domain-prefix <全局唯一前缀>
```
Expected: 打印新 pool id、三个 client id，以及"已写入"两条 SSM 参数
（脚本内部直接 `put_parameter`，**不打印 secret 明文**）。同时打印要在 IdP 侧
加白名单的 `/oauth2/idpresponse` 回调地址。

- [ ] **Step 1b: [真机] 验证自注册确实被关闭（P0 验收）**

**必须用 `mcp_client_id`（无 client secret）做这条负测**：`site` client 是
confidential，带 secret 的 client 调 `SignUp` 少传 `SecretHash` 也会返回
`NotAuthorizedException`——用它测会把"缺 SecretHash"误判成"自注册已禁用"，
形成假通过（自注册其实还开着也照样绿）。

Run:
```bash
CLIENT=<mcp_client_id>   # 无 secret 的 public client
aws cognito-idp sign-up --region us-east-1 --client-id "$CLIENT" \
  --username "probe-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')@example.com" \
  --password 'ProbeOnly!2026x' 2>&1 | tail -3
```
Expected: 失败，且错误文案含 **`SignUp is not permitted`**（关自注册的确切
表现）。**若返回 `UserSub`/`CodeDeliveryDetails` 即注册成功——立刻停下**：
`AllowAdminCreateUserOnly` 没生效，`allowed_users="org"` 已对公网开放
（spec §3.5），修好再继续。

只看到笼统的 `NotAuthorizedException` 而没有 `SignUp is not permitted` 时，
用 `aws cognito-idp describe-user-pool` 直接读配置复核：
```bash
aws cognito-idp describe-user-pool --user-pool-id <新 pool id> --region us-east-1 \
  --query 'UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly'
```
Expected: `true`。

Run（确认 authorize 端点真的能起飞，且直接跳 IdP 而非渲染本地表单）:
```bash
CLIENT=<site_client_id>
curl -s -o /dev/null -w "status=%{http_code}\nlocation=%{redirect_url}\n" \
  "https://<domain-prefix>.auth.us-east-1.amazoncognito.com/oauth2/authorize\
?response_type=code&client_id=$CLIENT\
&redirect_uri=https://auth.<base_domain>/callback&scope=openid+email+profile&state=probe"
```
Expected: `status=302` 且 `location` 指向 IdP 的授权端点（飞书适配器或 Okta
的域名）。

**不要用 `curl | grep -c 'signup'` 判断**——那个写法会把"空响应"和"错误页"
一起判成"没有本地登录表单"（假通过）。按状态码与 Location 判断：
- `status=400/500` 或 location 空：很可能是 **branding style 未套**
  （API 建的 client 不会自动获得 style，套上前 managed login 页面不可用），
  回去确认 `deploy_pool.py` 的 `_ensure_branding` 跑过；
- `status=200` 且响应体里有 `name="username"` 输入框：说明 client 里还留着
  `COGNITO`，本地登录入口暴露。

- [ ] **Step 2: [真机 spike] IdP 回调 URL 追加**

新 pool 的 Cognito 域名变了，IdP 侧需要把新的 `https://<domain-prefix>.auth.us-east-1.amazoncognito.com/oauth2/idpresponse` 加进回调白名单。

- 飞书适配器路线：**注意一期实测坑**——飞书后台注册的是 SSO 适配器的 `/callback` 而非 Cognito 域名（错误码 20029）。检查适配器的配置里是否有需要更新的 Cognito 回调地址。
- 标准 IdP（Okta 等）：在 IdP 的 application 里加该 redirect URI。

Run（验证 Hosted UI 能起飞）:
```bash
open "https://<domain-prefix>.auth.us-east-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=<site_client_id>&redirect_uri=https://auth.<base_domain>/callback&scope=openid+email+profile&state=probe"
```
Expected: 跳到 IdP 登录页（不是错误页）。**把实际结论记进 DEPLOY.md**——这是 spec 里标记的实施 spike ②。

- [ ] **Step 3: 回填 config 并重部署 auth 服务**

把 Step 1 打印的值填进 `site-builder/config.ini` 的 `[Cognito]`，然后：

Run:
```bash
cd site-builder/auth && python3 deploy_auth.py
```
Expected: 部署成功。

- [ ] **Step 4: [真机] 端到端登录验证（含 PKCE/nonce）**

浏览器访问一个鉴权站点 `https://app-<site_id>.<base_domain>/`。

Expected: 302 到 `auth.<base_domain>/login` → Hosted UI → IdP 登录 → 回跳站点并可访问。

Run（确认 PKCE 参数真的发出去了）:
```bash
curl -s -D- -o /dev/null "https://auth.<base_domain>/login?redirect=https%3A%2F%2Fapp-<site_id>.<base_domain>%2F" | grep -i location
```
Expected: Location 里含 `code_challenge=`、`code_challenge_method=S256`、`nonce=`。

- [ ] **Step 5: [真机] 更新 AgentCore authorizer 到新 pool**

Run:
```bash
cd site-builder/mcp && python3 deploy_agentcore.py --skip-build
```
Expected: runtime 更新成功（`_discovery_url()` 与 `allowedClients` 已指向新 pool 的值，因为它们从 config.ini 读）。

- [ ] **Step 6: [真机] MCP 重新 OAuth 并验证 email claim**

用 Claude Code 重新连 MCP（`--client-id <新 mcp_client_id>` + `--callback-port 18765`；回调 URL 已由 `deploy_pool.py` 预注册）。

Expected: OAuth 成功；`list_my_sites` 返回的站点 owner 是你的邮箱——证明 pre-token 触发器在新 pool 上生效（access token 带 email）。

若报 401 `Claim 'client_id' value mismatch`：确认客户端发的是 access token 而非 id_token（一期钉死的约束，不要改 `allowedAudience`）。

- [ ] **Step 6b: [真机 spike] 确认 access token 里有 `idp` claim**

登录后从 MCP 侧或用 CLI 拿一个 access token，解开 payload：

Run:
```bash
python3 -c "
import base64, json, sys
tok = sys.argv[1].split('.')[1]
print(json.dumps(json.loads(base64.urlsafe_b64decode(tok + '=' * (-len(tok) % 4))),
                 indent=2, ensure_ascii=False))" '<access_token>'
```
Expected: payload 含 `email` 与 **`idp`**（值为 IdP provider 名，如 `Feishu`
或 `Okta`）。这条是 spec §3.5 主防线的数据来源。

若 `idp` 缺失：确认 `identities` 属性在 pre-token event 里的实际形态
（在 `pre_token_email.py` 里临时 `print(json.dumps(event["request"]["userAttributes"]))`
后看 CloudWatch 日志），按实测调 `_provider_name`。**把结论写进 DEPLOY.md**
——这是 spec §10 的 spike 4。

- [ ] **Step 6c: [真机] Edge 的 `idp` 校验与开关翻转**

`REQUIRE_IDP_CLAIM` 的翻转属于本模块的验收项（Edge 侧代码在 M1 的 Edge 改动
里一并部署，占位符默认 `false`）：

1. 确认全部用户已重新登录（旧会话 cookie 里没有 `idp` claim）：距切换
   ≥24h（会话 TTL 86400s）即可保证旧 cookie 全部过期；
2. 把 `router/config.ini` 的 `require_idp_claim` 置 `true`，重部署路由层
   （`rm -rf cdk.out` 后 deploy）；
3. 验证：正常登录仍可访问鉴权站点；用 `JWT_SECRET` 手工 mint 一个**不含
   `idp` claim** 的会话 cookie，访问 org 站点应被 302 回登录（而不是放行）。

Run（手工 mint 无 idp 的 cookie 做负向验证）:

**secret 走环境变量，不进命令行参数**——argv 对同机所有进程可见（`ps`），
还会留在 shell history 与本次会话记录里。签出的 token 也别打到终端：直接管进
curl 的 header。

**必须做正负一对**：只断言"无 idp → 302"证明不了什么——secret 取空、签名用错
密钥、token 过期、格式错都会给出同一个 302。要用**同一次读到的同一个 secret**
签两个 token（一个带可信 idp、一个不带），带 idp 的必须 200、不带的必须 302，
才能隔离出"仅因缺 idp 被拒"。

```bash
SITE_URL="https://app-<site_id>.<base_domain>/"    # 一个 require_login=true 的站点
TRUSTED_IDP="Feishu"                                # 与 router/config.ini 的 trusted_idps 一致

SB_JWT_SECRET="$(aws ssm get-parameter --name /site-builder/jwt-secret \
  --with-decryption --region us-east-1 --query Parameter.Value --output text)"
# 先断言 secret 非空——取空会让两个 token 都签错，负测假通过
test -n "$SB_JWT_SECRET" || { echo "FAIL: JWT secret 为空"; return 1 2>/dev/null || exit 1; }

eval "$(SB_JWT_SECRET="$SB_JWT_SECRET" TRUSTED_IDP="$TRUSTED_IDP" python3 - <<'PYEOF'
import base64, hashlib, hmac, json, os, time
secret = os.environ["SB_JWT_SECRET"]          # 从 env 读，不从 argv
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def mint(extra):
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"email": "probe@x.com", "name": "probe",
              "exp": int(time.time()) + 300, **extra}
    p = b64(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{p}." + b64(hmac.new(secret.encode(), f"{h}.{p}".encode(),
                                      hashlib.sha256).digest())

print(f"SB_TOK_GOOD={mint({'idp': os.environ['TRUSTED_IDP']})}")
print(f"SB_TOK_NOIDP={mint({})}")
PYEOF
)"

echo -n "带可信 idp（应 200）: "
curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: sb_session=$SB_TOK_GOOD" "$SITE_URL"
echo -n "无 idp（应 302）:      "
curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: sb_session=$SB_TOK_NOIDP" "$SITE_URL"

unset SB_JWT_SECRET SB_TOK_GOOD SB_TOK_NOIDP
```

Expected: 第一行 `200`、第二行 `302`。

判读：
- 两行都 302 → secret 或签名不对（不是 idp 校验生效），先查 secret 与
  `router/config.ini` 的 `[SiteBuilder] base_domain`；
- 两行都 200 → `require_idp_claim` 还是 `false`（或 synth 时占位符没替换成功，
  见 Task 8b Step 6）；
- 第一行 302、第二行 200 → `trusted_idps` 配的值与 token 里的 idp 不一致。

probe token 5 分钟内自然过期；跑完 `unset` 三个变量。

- [ ] **Step 7: [真机 spike] 标准 IdP 分支验证**

在新 pool 上加一个标准 IdP（Okta 试用租户或 Azure AD），只需 `[IdP]` 段换成它的参数重跑 `deploy_pool.py`，然后用该 IdP 的账号走一次站点登录。

Expected: 登录成功，会话 JWT 的 email 是 IdP 给的 email，站点可访问。**这条覆盖需求清单 B 组"标准 IdP 路径真机验证"**。

若无法获得测试租户，把阻塞原因与已验证到哪一步写进 DEPLOY.md，不要宣称已验证。

- [ ] **Step 8: 重生成 onboarding 并通告**

Run:
```bash
python3 site-builder/scripts/gen_onboarding.py
```
Expected: 生成的 ONBOARDING.md 含新 pool 的 client-id 与域名。

用户影响：一次性重新登录（站点会话 cookie 仍是旧 JWT_SECRET 签的、仍有效，但 MCP 需重新 OAuth）。发一句话公告。

- [ ] **Step 9: [真机] 清理旧 pool 的平台配置**

**确认新 pool 全链路可用后**再做。旧 pool 上：解除 pre-token 触发器指向（若旧 pool 还被 Quick SSO 使用，只需确认它不再被平台依赖，**不要删旧 pool**）；删掉平台建的 site/mcp 两个 app client。

Run（先确认旧 pool 上哪些 client 是平台建的）:
```bash
aws cognito-idp list-user-pool-clients --user-pool-id <旧 pool id> \
  --region us-east-1 --query 'UserPoolClients[].{Name:ClientName,Id:ClientId}'
```
Expected: 能区分出平台的两个 client。删除前**与 Quick SSO 的使用方确认**——这一步不可逆。若不确定，跳过删除，只在文档里记录"旧 pool 的平台 client 已废弃"。

同时清掉 pre-token Lambda 上绑旧 pool 的那条历史授权语句（Task 14 Step 4
保留它是为了迁移期两 pool 并存）：

Run（先看现有语句）:
```bash
aws lambda get-policy --function-name site-auth-pre-token --region us-east-1 \
  --query Policy --output text | python3 -m json.tool | grep -A2 '"Sid"'
```
Expected: 能看到 `cognito-invoke`（旧，绑旧 pool）与
`cognito-invoke-<新 pool id>`。确认新 pool 那条在、且新 pool 登录已验证通过后：
```bash
aws lambda remove-permission --function-name site-auth-pre-token \
  --region us-east-1 --statement-id cognito-invoke
```
Expected: 无输出即成功。**顺序不能反**——先删后验证会让旧 pool 的登录立刻失败
（若还有人在用旧 pool）。

- [ ] **Step 10: 改写 DEPLOY.md ① 阶段**

把 `site-builder/DEPLOY.md` 的 ① 身份层一节改成 IdP 无关的两分支结构：

```markdown
## ① 身份层（平台专用 Cognito user pool）

平台用自己的 user pool（`site-builder-users`），与上游 Quick SSO 的 pool
解耦——平台侧配置（pre-token 触发器、app client、token 形态）不再影响
其他消费方。

**平台对 IdP 无感**：只要 IdP 能给 email claim 即可。下面两条分支产出
同样的结果，后续阶段完全一样。

### 通用步骤

1. `site-builder/config.ini` 填 `[Platform]`（base_domain / account_id /
   region）与 `[IdP]`（见下面分支）。
2. `python3 site-builder/scripts/deploy_pool.py --domain-prefix <全局唯一前缀>`
   —— 幂等，建 pool（Essentials 档，pre-token V2 必需）+ 三个 app client
   （site / mcp / machine）+ 托管域名 + pre-token 触发器。
3. 按脚本输出回填 `[Cognito]`，并执行它打印的两条 SSM 写入命令
   （client secret 只进 SSM，不写文件）。
4. 在 IdP 侧把 `https://<前缀>.auth.us-east-1.amazoncognito.com/oauth2/idpresponse`
   加进回调白名单。
5. 验证 Hosted UI 能跳到 IdP 登录页。

### 分支 A：飞书（经 feishu-quick-sso 的 OIDC 适配器）

`[IdP]` 填适配器的 issuer / client_id / client_secret。注意一期实测坑：
飞书后台注册的是**适配器的 `/callback`**，不是 Cognito 域名（否则错误码
20029）；且用户通讯录必须有邮箱、应用需 `contact:user.email:readonly`
权限（否则回调 500）。

### 分支 B：标准 IdP（Okta / Azure AD 等）

`[IdP]` 填 IdP 的 OIDC 参数（issuer 用 discovery 文档所在的 issuer）。
AWS 官方指引见本节末尾链接。属性映射固定 `email → email`、`name → name`。

### 三个 app client 的用途

| client | 用途 | 形态 |
|---|---|---|
| site | auth 服务换 token | confidential + code |
| mcp | MCP 客户端 OAuth | public + code，回调含 `http://localhost:18765/callback`（8765/8766 被 Quick Desktop 占用） |
| machine | key-proxy 换机器 token（M4） | confidential + client_credentials |
```

在该节末尾把一期已有的 AWS 官方链接与旧内容保留在"分支 A/B"下对应位置。

- [ ] **Step 11: 提交**

```bash
git add site-builder/DEPLOY.md
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "docs(deploy): ① 身份层改写为 IdP 无关双分支 + 专用 pool 切换步骤"
```

---

## Task 16: M1+M2 全量回归与文档收尾

**Files:**
- Modify: `CLAUDE.md`（测试命令与架构图补二期新增项）
- Modify: `docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md`（若实施中发现 spec 有误，回写）

**Interfaces:**
- Consumes: Task 1-15 全部
- Produces: 全套测试通过；文档与实际一致；M1+M2 可交付

- [ ] **Step 1: 五个包全量测试**

Run:
```bash
cd site-builder/contract && .venv/bin/pytest tests -q
cd site-builder/auth && ../contract/.venv/bin/pytest tests -q
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q
cd site-builder/deployer && .venv/bin/pytest tests -q
cd site-builder/mcp && python3 -m pytest tests -q
```
Expected: 全部 PASS。记录每个包的测试数（contract 应仍是 67；其余各有增长）。

- [ ] **Step 1a: [真机] idp claim 全链路（P0 验收）**

四段缺一即断（spec §3.5 的表），逐段确认：

1. **注入**：access token 与 **id token** 都有 `idp`（Task 15 Step 6b 已验
   access token；id token 这份用 auth 服务的 CloudWatch 日志确认——在
   `_exchange_code` 里临时打印 `claims.keys()`，或直接看会话 cookie 有没有
   `idp`，有即说明 id token 那份到位了）；
2. **签发**：解开浏览器里的 `sb_session` cookie，payload 含 `idp`；
3. **校验**：`require_idp_claim=true` 部署后，正常登录可访问、手工 mint 的
   无 `idp` 会话被 302（Task 15 Step 6c 的两个方向）；
4. **开关状态**：`grep require_idp_claim router/config.ini` 是 `true`
   ——**停在 false 等于这道防线没生效，M1 不算完成**。

- [ ] **Step 1b: [真机] 两表事务的失败路径**

验证 spec §3.2 承诺的"不会留下 sites 私有 / Edge 公开"：临时给 MCP runtime
角色（或本地跑 `permissions.write_permissions` 用的身份）拒掉路由表
`UpdateItem`，然后对一个**当前公开**的站点执行"改成需登录"。

Expected: 调用报错；`site-sites` 的 `require_login` **仍为 false**（真源没被
单边改动），路由表也没变。验完恢复 IAM。

若不便改 IAM，退一步用单测里的 `_ALLOW_ROUTE_ABSENT=False` 路径已覆盖同一
不变量（Task 2 的 `test_write_permissions_rolls_back_when_route_write_fails`）
——那时在这里记录"以单测覆盖，未做真机注入"，不要写成已真机验证。

- [ ] **Step 1c: [真机] register_route 与在线改权限并发**

验 spec §3.2 的条件事务：部署进行中（validate/package 阶段，还没到第 6 步）
用控制台或 MCP 把该站点权限收紧，然后等部署完成。

Expected: 部署 SUCCEEDED 且路由表最终是**收紧后**的策略（`require_auth=true` /
新名单），不是部署开始时的旧策略；或部署 FAILED 且错误文案含"权限被并发
修改"（重试 3 次仍冲突）。**绝不允许**出现 sites 私有而路由公开。

Run（部署完成后核对两处）:
```bash
SID=<site_id>
aws dynamodb get-item --table-name site-sites --region us-east-1 \
  --key "{\"site_id\":{\"S\":\"$SID\"}}" \
  --query 'Item.{login:require_login.BOOL,rev:permissions_rev.N}'
aws dynamodb get-item --region us-east-1 \
  --table-name "$(python3 -c "
import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")" \
  --key "{\"subdomain\":{\"S\":\"app-$SID\"}}" \
  --query 'Item.{auth:require_auth.BOOL,rev:permissions_rev.N}'
```
Expected: 两处的 `login`/`auth` 一致，`rev` 也一致。

- [ ] **Step 2: [真机] 冒烟路由层**

Run: `bash site-builder/scripts/smoke_router.sh`
Expected: PASS（会写测试数据并清理）。若脚本因权限字段形态变化而失败，修脚本里的路由 item 构造（加 `collaborators` 与 `L` 形态的 `allowed_users`）。

- [ ] **Step 3: [真机] E2E fixture 彩排**

Run:
```bash
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q
```
Expected: 4 passed（约 6 分钟）。这条验证权限真源改造没有破坏部署主链。

- [ ] **Step 4: 更新 CLAUDE.md**

在 `CLAUDE.md` 的架构图后追加二期 M1+M2 的变化说明，并在"高频坑"里加两条：

```markdown
- **权限真源是 sites 表**（二期 M2 起）：`require_login` / `allowed_users` /
  `collaborators` 以 `site-sites` 为准，路由表只是给 Edge 读的投影。
  `site.json` 的 `auth` 只在首次部署时作初始值，重部署忽略它。改权限走
  MCP 的 `update_site_permissions` 或控制台，约 1 分钟生效（Edge 路由缓存 60s）。
  判定逻辑全在 `deployer/functions/permissions.py`（MCP 与控制台共用，
  构建时复制，同 `common.py`）。
- **路由表新增 DynamoDB `L` 类型字段**（`allowed_users` 名单、
  `collaborators`）：Edge 的 `_deser` 必须先支持 `L` 才能部署写侧——
  顺序颠倒会让名单读成 `False`（等于全员放行）。加新字段类型时同理。
- **权限写入只走 `permissions.write_permissions`**（两表 `TransactWriteItems`）。
  别在别处写"先改 sites 再同步路由"：收紧权限时第二步失败会留下 sites 已私有、
  Edge 仍公开的安全状态错误。
- **`allowed_users="org"` 依赖 pool 侧两道约束**：关自注册
  （`AllowAdminCreateUserOnly=True`）+ 生产 client 只列企业 IdP（不含
  `COGNITO`）。Edge 对 org 只检查"有有效会话"，不查邮箱域——放宽这两条等于
  把全部 org 站点对公网开放——AWS 明确说移除 `COGNITO` **不阻止** SDK 经
  user pools API 认证本地用户。**唯一的执行点是会话/token 的 `idp` claim
  校验**：Web 侧在 Edge（`REQUIRE_IDP_CLAIM` 开关），MCP 侧在
  `_caller_email()`（`TRUSTED_IDPS` 环境变量）。两处都要配上，
  否则管理面绕过了这道防线。
- **jobs 表的 `owner` 是发起者**（requested_by 语义），不参与授权；站点 owner
  只由 `permissions.transfer_owner` 与首次部署写。`mark_job` **不写 owner**
  ——写了会让 collaborator 部署一次就夺权。
- **`register_route` 也是条件事务**（ConditionCheck `permissions_rev` + Put
  route）：它是"读 sites → 写整条路由"，与在线改权限并发时用旧快照
  `put_item` 会把路由写回公开。冲突重读重试 ≤3 次，仍冲突让部署失败。
- **API 建的 Cognito app client 必须显式套 branding**
  （`CreateManagedLoginBranding`）：控制台建的会自动有，脚本建的不会——
  没套之前 managed login / hosted UI 页面不可用，`/oauth2/authorize` 直接失败。
- **自注册负测要用无 secret 的 client**：带 client secret 的 client 调
  `SignUp` 少传 `SecretHash` 也返回 `NotAuthorizedException`，会把"缺
  SecretHash"误判成"自注册已禁用"。
```

并在测试命令一节补一句：

```markdown
`deployer` 的测试里新增了 CDK 模板断言（`test_infra_tables.py`）——需要
`site-builder/config.ini` 存在，否则整文件 skip。
```

- [ ] **Step 5: 核对 spec 与实现**

逐条读 spec 的 §3（权限模型）与 §7.1-7.2（pool + PKCE），确认实现与之一致。**任何实施中改掉的决定都回写 spec**（例如：`get_site_stats` 推到 M5、第三个工具改为 `get_site_permissions`；`site-admins` 表用 `RemovalPolicy.RETAIN`；`_ROUTE_CACHE` 无失效机制导致的 60s 生效窗口写法）。

在 spec §5.4 的工具表后加一句：

```markdown
> 实施说明（M2）：`get_site_stats` 依赖 M5 的统计表，M2 阶段第三个新工具
> 是 `get_site_permissions`（读当前策略与我的角色）。M5 加 stats 工具时
> MCP 工具数 8 → 9，同步改 `test_agentcore_contract.py` 的期望列表。
```

- [ ] **Step 6: 提交**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-30-quick-site-builder-phase2-design.md
# AGENTS.md：commit 前扫 staged diff（命中先确认，不自动清洗）
git diff --cached | grep -nE 'AKIA|ASIA|ghp_|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|aws_secret|password[[:space:]]*=' || echo "secret scan: clean"
# 命中就停下给用户看，确认是故意的 fixture 后再继续
git commit -m "docs: M1+M2 收尾——CLAUDE.md 补权限真源与 L 类型顺序约束，spec 回写实施差异"
```

- [ ] **Step 7: 推送**

```bash
git push --no-verify
```
Expected: 推送成功。

---

## 附：M3-M6 概要（本计划不含，后续单独出计划）

| 模块 | 内容 | 前置 |
|---|---|---|
| M3 控制台 | `site-builder/panel/`（panel Lambda + 静态前端）、`deploy_panel.py`、会话升级（auth 发一次性 code → **console host 自己**签发 `__Host-sb_console`，见 spec §4.5）+ Origin/Content-Type CSRF 三闸、`site-session-codes` 表、Edge 保留 cookie 名单、`site-ops-log` 审计表、admin 种子并入部署脚本 | M2 ✅ |
| M4 API Key | `site-api-keys` 表、`sk-` + 16 位 Key、key-proxy Lambda（`mcp.{base_domain}`）、machine client 的 resource server 与 scope、AgentCore spike（client_credentials token + `X-SB-On-Behalf-Of` 头透传） | M1 ✅（machine client 已建） |
| M5 统计 | Edge 访问日志行、聚合 Lambda + EventBridge、`site-access-stats` / `site-access-audit` 表、面板图表、MCP `get_site_stats`、平台 Lambda 日志组补 30 天保留 | M2、M3 |
| M6 收尾 | 全量 E2E、DEPLOY.md 新阶段、onboarding 重生成、文档同步 | 全部 |
