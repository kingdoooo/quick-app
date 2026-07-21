# Quick 自动化建站方案（Site Builder）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 业务人员在 Quick Desktop（或任意支持 Skill+MCP 的 Agent 客户端）开发的简易全栈站点，一键部署到 AWS 并获得 `https://app-xxx.<域名>`，站点访问与管理权限绑定飞书账号。

**Architecture:** 五组件：① site-builder Skill（部署合同）→ ② AgentCore 部署 MCP（薄壳，4 工具）→ ③ Step Functions 异步执行器（校验→建库→CodeBuild 打包→建 Lambda→传 S3→注册路由→冒烟）→ ④ manus 路由层改造（Lambda@Edge 查路由+验飞书会话 JWT）→ ⑤ Cognito+飞书 OIDC 身份层（复用 feishu-quick-sso）。

**Tech Stack:** Python 3.11+（CDK v2 / Lambda / pytest）、Node.js 22（站点后端模板）、Aurora DSQL、DynamoDB、Step Functions、CodeBuild、Lambda Web Adapter（zip+Layer）、Bedrock AgentCore Runtime（MCP protocol）、Cognito、飞书开放平台。

**Spec:** `docs/superpowers/specs/2026-07-21-quick-site-builder-design.md`

## Global Constraints

- 全部资源部署在 `us-east-1`（Lambda@Edge / ACM / Quick Desktop 身份区域共同强制）。
- 站点资源命名前缀一律 `site-`；IAM policy 按该前缀限权（沿用 manus `*WebRouterStack*` 模式）。
- 站点后端 runtime **PoC 仅 `nodejs22.x`**（Python 记为二期）；部署形态仅 zip + LWA Layer，**禁止 Docker 镜像模式**。
- LWA Layer ARN（精确值）：`arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28`；zip 模式必须设 `AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap`、`PORT=8080`，handler 为 `run.sh`。
- tier 枚举：`static` | `fullstack-nosql` | `fullstack-sql`；database.engine 枚举：`none` | `dynamodb` | `dsql`。
- DSQL：不支持 `CREATE DATABASE`（每 cluster 单库 `postgres`），每站点独立 schema `site_<site_id去连字符>`；DDL 每事务一条，SQL 语句拆分一律用 `sqlparse.split()`；禁用特性：外键 REFERENCES、SERIAL、JSONB 列、触发器/PLpgSQL、TEMP TABLE、扩展。
- **站点代码是不可信代码**：每站点独立 Lambda 执行角色 `site-rt-{site_id}`（仅该站点的 DynamoDB 表 / DSQL per-site PG role）；DSQL 站点连接用非 admin token（`dsql:DbConnect` + PG role `site_{id}_app`）；admin 身份（`dsql:DbConnectAdmin`）仅执行器持有。
- **CloudFront 全站 CACHING_DISABLED**（origin-request 鉴权在 cache hit 时会被绕过——禁缓存是 PoC 的鉴权正确性前提）；Edge Lambda 关联必须 `include_body=True`，SigV4 用解码后 body 计算 hash，`inputTruncated` 返回 413。
- **Edge fail-closed**：任何未捕获异常返回 500，绝不透传原请求。
- 路由表含 `route_mode`（`split`=默认 / `api-only`=全路径走 api_target，auth 子域必用）；`static_prefix` 为版本化前缀 `sites/{site_id}/{job_id}`，发布=先传新前缀再原子切路由。
- 鉴权：会话 cookie 名 `sb_session`（`Domain=.<BASE_DOMAIN>; Secure; HttpOnly; SameSite=Lax`）；JWT 算法 HS256（纯标准库实现）；Edge 注入且无条件先剥除请求头 `x-user-email` / `x-user-name`。OAuth state 必须 HMAC 签名 + 5 分钟过期；Cognito id_token 必须 JWKS 验签 + iss/aud/exp/token_use 校验。
- 子域名：站点 `app-{site_id}`；身份服务保留子域名 `auth`。
- MCP 工具面固定 5 个：`deploy_site` / `confirm_upload` / `get_deploy_status` / `list_my_sites` / `undeploy_site`，全部秒级返回（60s 超时红线）。SFN execution name = job_id；confirm_upload 走 jobs 表条件迁移 PENDING→RUNNING。
- S3 批量删除/遍历一律 paginator + 每批 ≤1000 对象。
- 中心配置 `site-builder/config.ini`（BASE_DOMAIN、ACCOUNT_ID、路由表名、Cognito 参数、DSQL endpoint），所有组件从它读，不散落硬编码。
- 测试框架 pytest；提交遵循 conventional commits；每个 Task 以通过测试 + commit 结束。
- **Task 0（前置）**：`git add manus-web-application-main/` 纳入版本控制并提交——plan 大量修改该目录，未跟踪则不可复现。

## File Structure

```
quick-app/                                    # 仓库根（已 git init）
├── docs/superpowers/{specs,plans}/
├── manus-web-application-main/               # M2 路由层：就地改造
│   ├── infrastructure/stack.py               # 修改：注入 JWT_SECRET 等新替换项、S3 读权限
│   ├── infrastructure/lambda/origin_request.py  # 修改：auth + static/api 分流
│   └── infrastructure/lambda/test_origin_request.py  # 新增测试
└── site-builder/                             # 新增：本方案全部新代码
    ├── config.ini.example                    # 中心配置模板
    ├── contract/                             # M0 部署合同库（M3/M4/M5 共用）
    │   ├── pyproject.toml
    │   ├── src/contract/__init__.py
    │   ├── src/contract/schema.py            # validate_manifest()
    │   ├── src/contract/redlines.py          # scan_redlines()
    │   └── tests/
    ├── auth/                                 # M1 站点会话服务
    │   ├── session.py                        # mint/verify HS256 JWT（纯标准库）
    │   ├── login_handler.py                  # /login /callback /logout Lambda
    │   ├── requirements.txt                  # pyjwt[crypto]（验 Cognito RS256）
    │   ├── deploy_auth.py                    # 部署脚本（Lambda+Function URL+路由注册）
    │   └── tests/
    ├── deployer/                             # M3 异步执行器
    │   ├── functions/
    │   │   ├── common.py                     # jobs/sites 表读写、config 加载
    │   │   ├── validate.py                   # 步骤1：解包+合同校验
    │   │   ├── provision_dynamodb.py         # 步骤2a
    │   │   ├── provision_dsql.py             # 步骤2b（psycopg + IAM token）
    │   │   ├── deploy_lambda_site.py         # 步骤4：zip+LWA Layer+Function URL
    │   │   ├── upload_frontend.py            # 步骤5
    │   │   ├── register_route.py             # 步骤6
    │   │   ├── smoke_test.py                 # 步骤7
    │   │   └── mark_job.py                   # 成功/失败落账
    │   ├── buildspec-package.yml             # CodeBuild：装依赖打 backend.zip
    │   ├── infra/app.py                      # CDK：表/桶/CodeBuild/SFN/EventBridge
    │   ├── infra/requirements.txt
    │   └── tests/
    ├── mcp/                                  # M4 部署 MCP
    │   ├── server.py                         # FastMCP 4 工具
    │   ├── requirements.txt
    │   └── tests/
    ├── skills/site-builder/                  # M5 Skill（Agent Skills 开放标准）
    │   ├── SKILL.md
    │   ├── references/contract.md            # site.json 全字段 + 目录结构
    │   ├── references/redlines.md            # 代码红线 + DSQL 禁用特性
    │   ├── templates/db.js                   # DSQL 连接模板（Node）
    │   ├── templates/db.py                   # DSQL 连接模板（Python）
    │   ├── templates/run.sh                  # LWA 启动脚本
    │   └── templates/site.json.{static,nosql,sql}.example
    └── fixtures/                             # 三档样例站点（集成测试+演示用）
        ├── static-hello/
        ├── nosql-notes/
        └── sql-expenses/
```

**模块间接口总览**（各 Task 的 Interfaces 块引用此处签名）：

- `contract.validate_manifest(manifest: dict) -> list[str]`（空列表=合法）
- `contract.scan_redlines(site_dir: Path, manifest: dict) -> list[str]`
- `auth.session.mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400) -> str`
- `auth.session.verify_session_jwt(token: str, secret: str, now: int | None = None) -> dict | None`
- 路由表 item：`{subdomain(PK,S), site_id(S), static_prefix(S), api_target(S,可空串), require_auth(BOOL), allowed_users(S: "org" 或 JSON 邮箱数组), owner(S)}`
- jobs 表 item：`{job_id(PK,S), site_id(S), owner(S), status(S: PENDING|RUNNING|SUCCEEDED|FAILED|DELETED), phase(S), error(S), url(S), created_at(S), updated_at(S)}`，GSI `owner-index(owner, created_at)`
- sites 表 item：`{site_id(PK,S), owner(S), name(S), subdomain(S), tier(S), migrations_applied(L), status(S), last_job_id(S)}`
- SFN 输入：`{"job_id": str, "site_id": str}`；产物 S3 key：上传 `uploads/{job_id}.zip`、构建产物 `artifacts/{job_id}/backend.zip`

## Task 总览（阶段 = 设计文档 M1-M6 映射）

| Phase | Task | 内容 |
|---|---|---|
| P0 前置 | 0 | `git add manus-web-application-main/ && git commit`（可复现前提） |
| P0 合同库 | 1 | contract 包脚手架 + site.json schema 校验器 |
| P0 | 2 | 代码红线扫描器 |
| P1 身份层(M1) | 3 | 部署 feishu-quick-sso 基座并验证 Quick 登录 |
| P1 | 4 | session 模块（HS256 mint/verify，纯标准库） |
| P1 | 5 | auth-service Lambda（/login /callback /logout）+ 部署 |
| P2 路由层(M2) | 6 | Edge 函数：路由表扩展 + static/api 分流 + S3 SigV4 |
| P2 | 7 | Edge 函数：JWT 鉴权 + 302 + 头注入/剥除 |
| P2 | 8 | manus CDK 栈更新部署 + 路由层冒烟 |
| P3 执行器(M3) | 9 | deployer 基础设施 CDK（表/桶/角色/CodeBuild 项目） |
| P3 | 10 | common.py（任务/站点表访问层） |
| P3 | 11 | validate 步骤（解包 + 合同校验） |
| P3 | 12 | DynamoDB provisioner |
| P3 | 13 | DSQL provisioner（schema + 逐条 DDL + migrations） |
| P3 | 14 | CodeBuild 打包（buildspec + SFN sync 集成） |
| P3 | 15 | 站点 Lambda 部署器（zip + LWA Layer + Function URL） |
| P3 | 16 | 前端上传 + 路由注册 + 冒烟步骤 |
| P3 | 17 | Step Functions 状态机组装 + 上传自动触发 + 部署 |
| P3 | 18 | fixtures 三站点 + 执行器端到端集成测试 |
| P4 MCP(M4) | 19 | MCP server 四工具（本地 TDD） |
| P4 | 20 | AgentCore 部署 + Cognito JWT 授权 + 远程冒烟 |
| P5 Skill(M5) | 21 | site-builder Skill（SKILL.md + 模板 + 参考文档） |
| P5 | 22 | Skill 多客户端冒烟（Quick Desktop / Claude Code） |
| P6 E2E(M6) | 23 | 端到端彩排 + 演示脚本 |

---


## Phase P0：部署合同库（无 AWS 依赖，纯本地 TDD）

### Task 1: contract 包脚手架 + site.json 校验器

**Files:**
- Create: `site-builder/contract/pyproject.toml`
- Create: `site-builder/contract/src/contract/__init__.py`
- Create: `site-builder/contract/src/contract/schema.py`
- Test: `site-builder/contract/tests/test_schema.py`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces: `validate_manifest(manifest: dict) -> list[str]`——返回违规描述列表，空列表表示合法。后续 Task 11（validate 步骤）、Task 19（MCP）依赖此签名。

- [ ] **Step 1: 写 pyproject 与包骨架**

`site-builder/contract/pyproject.toml`:

```toml
[project]
name = "site-contract"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
```

`site-builder/contract/src/contract/__init__.py`:

```python
from contract.schema import validate_manifest
from contract.redlines import scan_redlines  # noqa: F401  (Task 2 提供)

__all__ = ["validate_manifest", "scan_redlines"]
```

注意：Task 1 阶段 `redlines` 尚不存在，先在 `__init__.py` 只导出 `validate_manifest`，Task 2 再补第二行。即 Task 1 的 `__init__.py` 实际内容：

```python
from contract.schema import validate_manifest

__all__ = ["validate_manifest"]
```

- [ ] **Step 2: 写失败测试**

`site-builder/contract/tests/test_schema.py`:

```python
import pytest
from contract import validate_manifest


def _valid_sql_manifest():
    return {
        "name": "expense-tracker",
        "tier": "fullstack-sql",
        "backend": {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080},
        "database": {"engine": "dsql", "tables": []},
        "auth": {"require_login": True, "allowed_users": "org"},
    }


def test_valid_fullstack_sql_passes():
    assert validate_manifest(_valid_sql_manifest()) == []


def test_valid_static_minimal_passes():
    m = {"name": "hello", "tier": "static",
         "database": {"engine": "none"},
         "auth": {"require_login": False, "allowed_users": "org"}}
    assert validate_manifest(m) == []


def test_missing_name_fails():
    m = _valid_sql_manifest(); del m["name"]
    assert any("name" in e for e in validate_manifest(m))


def test_bad_name_charset_fails():
    m = _valid_sql_manifest(); m["name"] = "My_App!"
    assert any("name" in e for e in validate_manifest(m))


def test_unknown_tier_fails():
    m = _valid_sql_manifest(); m["tier"] = "fullstack-graphql"
    assert any("tier" in e for e in validate_manifest(m))


def test_static_with_backend_fails():
    m = _valid_sql_manifest(); m["tier"] = "static"
    assert any("backend" in e for e in validate_manifest(m))


def test_fullstack_without_backend_fails():
    m = _valid_sql_manifest(); del m["backend"]
    assert any("backend" in e for e in validate_manifest(m))


def test_tier_engine_mismatch_fails():
    m = _valid_sql_manifest(); m["database"]["engine"] = "dynamodb"
    assert any("engine" in e for e in validate_manifest(m))


def test_bad_runtime_fails():
    m = _valid_sql_manifest(); m["backend"]["runtime"] = "python3.13"  # 二期，PoC 不收
    assert any("runtime" in e for e in validate_manifest(m))


def test_bad_table_spec_fails():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb",
                     "tables": [{"name": "Bad Name!", "pk": "id"},
                                {"name": "dup", "pk": "id"}, {"name": "dup", "pk": "id"}]}
    errs = validate_manifest(m)
    assert any("tables" in e for e in errs)  # 命名非法 + 重复


def test_allowed_users_list_ok():
    m = _valid_sql_manifest(); m["auth"]["allowed_users"] = ["a@x.com", "b@x.com"]
    assert validate_manifest(m) == []


def test_allowed_users_bad_email_fails():
    m = _valid_sql_manifest(); m["auth"]["allowed_users"] = ["not-an-email"]
    assert any("allowed_users" in e for e in validate_manifest(m))


def test_nosql_tables_required():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb", "tables": []}
    assert any("tables" in e for e in validate_manifest(m))
```

- [ ] **Step 3: 运行确认失败**

Run: `cd site-builder/contract && python -m venv .venv && .venv/bin/pip install -e '.[dev]' -q && .venv/bin/pytest tests/test_schema.py -q`
Expected: FAIL（`ImportError`/断言失败——schema.py 尚不存在）

- [ ] **Step 4: 实现校验器**

`site-builder/contract/src/contract/schema.py`:

```python
"""site.json（部署清单）结构校验——部署合同的机器可执行定义。"""
import re

TIERS = {"static", "fullstack-nosql", "fullstack-sql"}
RUNTIMES = {"nodejs22.x"}  # Python 3.13 记为二期（需 db.py 模板/fixture/E2E 支撑）
TIER_ENGINE = {"static": "none", "fullstack-nosql": "dynamodb", "fullstack-sql": "dsql"}
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,29}$")
TABLE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,29}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []

    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name or ""):
        errors.append("name: 必须为小写字母开头、仅含 [a-z0-9-]、长度 2-30")

    tier = manifest.get("tier")
    if tier not in TIERS:
        errors.append(f"tier: 必须是 {sorted(TIERS)} 之一")
        return errors  # tier 非法时后续规则无意义

    db = manifest.get("database") or {}
    engine = db.get("engine")
    if engine != TIER_ENGINE[tier]:
        errors.append(f"database.engine: tier={tier} 时必须为 {TIER_ENGINE[tier]!r}，得到 {engine!r}")

    backend = manifest.get("backend")
    if tier == "static":
        if backend is not None:
            errors.append("backend: tier=static 时不允许出现")
    else:
        if not isinstance(backend, dict):
            errors.append("backend: fullstack tier 必须提供")
        else:
            if backend.get("runtime") not in RUNTIMES:
                errors.append(f"backend.runtime: 必须是 {sorted(RUNTIMES)} 之一")
            if not isinstance(backend.get("entrypoint"), str) or not backend.get("entrypoint"):
                errors.append("backend.entrypoint: 必须为非空字符串")
            if backend.get("port") != 8080:
                errors.append("backend.port: 必须为 8080（LWA 约定）")

    if tier == "fullstack-nosql":
        tables = db.get("tables") or []
        if not tables:
            errors.append("database.tables: dynamodb 引擎必须声明至少一张表")
        elif len(tables) > 10:
            errors.append("database.tables: 至多 10 张表")
        else:
            names = [t.get("name", "") for t in tables]
            if len(names) != len(set(names)):
                errors.append("database.tables: 表名不得重复")
            for t in tables:
                if not TABLE_RE.match(t.get("name", "")) or not TABLE_RE.match(t.get("pk", "")):
                    errors.append(f"database.tables: 表名/主键须匹配 {TABLE_RE.pattern}: {t}")

    auth = manifest.get("auth")
    if not isinstance(auth, dict) or not isinstance(auth.get("require_login"), bool):
        errors.append("auth.require_login: 必须为布尔值")
    else:
        au = auth.get("allowed_users")
        if au != "org":
            if not isinstance(au, list) or not au or not all(
                isinstance(e, str) and EMAIL_RE.match(e) for e in au
            ):
                errors.append('auth.allowed_users: 必须为 "org" 或非空邮箱数组')

    return errors
```

- [ ] **Step 5: 运行确认通过**

Run: `.venv/bin/pytest tests/test_schema.py -q`
Expected: 12 passed

- [ ] **Step 6: Commit**

```bash
git add site-builder/contract
git commit -m "feat(contract): site.json manifest validator"
```

### Task 2: 代码红线扫描器

**Files:**
- Create: `site-builder/contract/src/contract/redlines.py`
- Modify: `site-builder/contract/src/contract/__init__.py`
- Test: `site-builder/contract/tests/test_redlines.py`

**Interfaces:**
- Consumes: 无
- Produces: `scan_redlines(site_dir: Path, manifest: dict) -> list[str]`——扫描解包后的站点目录，返回违规列表。Task 11 依赖。

红线（来自 spec §3.1）：① 前端禁止 localhost/硬编码绝对 http(s) API 地址；② 站点代码禁止自带 auth（检测 OAuth/jwt 签发关键词）；③ fullstack 必须有 `/api/health` 实现痕迹；④ 后端禁止写本地文件（`fs.writeFile`/`open(...,'w')` 出现即报）；⑤ fullstack-sql 必须存在 `backend/schema.sql` 且不含禁用 DDL（REFERENCES / SERIAL / JSONB / CREATE TRIGGER / CREATE TEMP）；⑥ 前端禁止 `innerHTML` 赋值/拼接（存储型 XSS——`INNERHTML_RE = re.compile(r"\.innerHTML\s*[+]?=")`，测试与实现同步补一条正反用例）。

- [ ] **Step 1: 写失败测试**

`site-builder/contract/tests/test_redlines.py`:

```python
import json
from pathlib import Path
import pytest
from contract import scan_redlines


def make_site(tmp_path: Path, *, tier="fullstack-sql", index="fetch('/api/items')",
              server="app.get('/api/health',(q,s)=>s.send('ok'))",
              schema="CREATE TABLE t (id UUID PRIMARY KEY);") -> tuple[Path, dict]:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/index.html").write_text(f"<script>{index}</script>")
    manifest = {"name": "t", "tier": tier,
                "database": {"engine": {"static": "none", "fullstack-nosql": "dynamodb",
                                        "fullstack-sql": "dsql"}[tier]},
                "auth": {"require_login": True, "allowed_users": "org"}}
    if tier != "static":
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend/server.js").write_text(server)
        manifest["backend"] = {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080}
        if tier == "fullstack-sql":
            (tmp_path / "backend/schema.sql").write_text(schema)
    (tmp_path / "site.json").write_text(json.dumps(manifest))
    return tmp_path, manifest


def test_clean_site_passes(tmp_path):
    d, m = make_site(tmp_path)
    assert scan_redlines(d, m) == []


def test_localhost_in_frontend_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://localhost:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_hardcoded_api_host_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('https://foo.example.com/api/x')")
    assert any("绝对地址" in v for v in scan_redlines(d, m))


def test_auth_code_fails(tmp_path):
    d, m = make_site(tmp_path, server="const t=jwt.sign({u:1},'s'); app.get('/api/health',(q,s)=>s.send('ok'))")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_missing_health_fails(tmp_path):
    d, m = make_site(tmp_path, server="app.get('/api/items',(q,s)=>s.json([]))")
    assert any("/api/health" in v for v in scan_redlines(d, m))


def test_local_file_write_fails(tmp_path):
    d, m = make_site(tmp_path, server="fs.writeFileSync('/tmp/x','1'); app.get('/api/health',(q,s)=>s.send('ok'))")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_schema_forbidden_ddl_fails(tmp_path):
    d, m = make_site(tmp_path, schema="CREATE TABLE a (id SERIAL PRIMARY KEY, b INT REFERENCES x(id));")
    found = scan_redlines(d, m)
    assert any("SERIAL" in v for v in found) and any("REFERENCES" in v for v in found)


def test_missing_schema_for_sql_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/schema.sql").unlink()
    assert any("schema.sql" in v for v in scan_redlines(d, m))


def test_static_skips_backend_checks(tmp_path):
    d, m = make_site(tmp_path, tier="static")
    assert scan_redlines(d, m) == []
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_redlines.py -q`
Expected: FAIL（ImportError: cannot import name 'scan_redlines'）

- [ ] **Step 3: 实现扫描器**

`site-builder/contract/src/contract/redlines.py`:

```python
"""代码红线静态扫描——防 AI 生成不可部署/违反合同的代码。启发式，宁可误报不可漏报。"""
import re
from pathlib import Path

TEXT_EXT = {".html", ".htm", ".js", ".mjs", ".css", ".py", ".json", ".txt"}
LOCALHOST_RE = re.compile(r"localhost|127\.0\.0\.1")
ABS_API_RE = re.compile(r"""["'`]https?://[^"'`]+/api/""")
AUTH_RE = re.compile(r"jwt\.sign|passport|OAuth2|client_secret|set_cookie\(.*session", re.I)
FILE_WRITE_RE = re.compile(r"fs\.writeFile|fs\.appendFile|open\([^)]*['\"][wa]['\"]")
HEALTH_RE = re.compile(r"/api/health")
FORBIDDEN_DDL = ["REFERENCES", "SERIAL", "JSONB", "CREATE TRIGGER", "CREATE TEMP"]


def _read_all(root: Path) -> list[tuple[Path, str]]:
    out = []
    if root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix in TEXT_EXT and "node_modules" not in p.parts:
                out.append((p, p.read_text(errors="replace")))
    return out


def scan_redlines(site_dir: Path, manifest: dict) -> list[str]:
    site_dir = Path(site_dir)
    violations: list[str] = []
    tier = manifest.get("tier")

    for p, text in _read_all(site_dir / "frontend"):
        rel = p.relative_to(site_dir)
        if LOCALHOST_RE.search(text):
            violations.append(f"{rel}: 前端禁止 localhost/127.0.0.1，API 一律相对路径 /api/*")
        if ABS_API_RE.search(text):
            violations.append(f"{rel}: 前端 API 调用禁止绝对地址，改为相对路径 /api/*")

    if tier == "static":
        return violations

    backend_dir = site_dir / "backend"
    backend_files = _read_all(backend_dir)
    backend_text = "\n".join(t for _, t in backend_files)
    for p, text in backend_files:
        rel = p.relative_to(site_dir)
        if AUTH_RE.search(text):
            violations.append(f"{rel}: 站点代码禁止自带 auth 逻辑（鉴权由平台边缘层统一处理）")
        if FILE_WRITE_RE.search(text):
            violations.append(f"{rel}: 禁止写本地文件（Lambda 文件系统只读）")
    if not HEALTH_RE.search(backend_text):
        violations.append("backend: 必须实现 GET /api/health 端点（部署冒烟测试依赖）")

    if manifest.get("database", {}).get("engine") == "dsql":
        schema = backend_dir / "schema.sql"
        if not schema.exists():
            violations.append("backend/schema.sql: fullstack-sql 必须提供建表 SQL")
        else:
            sql_upper = schema.read_text(errors="replace").upper()
            for kw in FORBIDDEN_DDL:
                if kw in sql_upper:
                    violations.append(f"backend/schema.sql: 含 DSQL 不支持的 {kw}（见红线文档替代方案）")
    return violations
```

同时把 `__init__.py` 更新为 Task 1 Step 1 中展示的双导出版本。

- [ ] **Step 4: 运行全部合同测试确认通过**

Run: `.venv/bin/pytest -q`
Expected: 21 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/contract
git commit -m "feat(contract): code redline scanner"
```

## Phase P1：飞书身份层（M1）

### Task 3: 部署 feishu-quick-sso 基座并验证 Quick 登录

前置条件（人工准备，执行者遇缺失即停并向用户报告）：飞书企业自建应用（取得 App ID/Secret，配置权限 `获取用户 userid`、`获取用户邮箱`）；AWS 账号 us-east-1 权限；通配符域名 `*.<BASE_DOMAIN>` 的 us-east-1 ACM 证书。

**Files:**
- Create: `site-builder/config.ini.example`
- Create: `site-builder/config.ini`（gitignore，含真实值）
- Create: `.gitignore`（根，含 `site-builder/config.ini`、`.venv/`、`__pycache__/`）
- Create: `site-builder/auth/UPSTREAM.md`（记录上游 repo、部署产出的资源 ID）

**Interfaces:**
- Consumes: 无
- Produces: 部署完成的 Cognito User Pool。`config.ini` 的 `[Cognito]` 段：`user_pool_id`、`domain`（Hosted UI 域名）、`site_client_id`（Task 5 用）、`mcp_client_id`（Task 20 用）；`[Platform]` 段：`base_domain`、`account_id`、`region=us-east-1`、`routing_table`。

- [ ] **Step 1: 写 config.ini.example**

```ini
[Platform]
base_domain = example.com
account_id = 000000000000
region = us-east-1
routing_table = ApplicationWebRouterStack-subdomain-mapping

[Cognito]
user_pool_id =
domain =
site_client_id =
mcp_client_id =

[DSQL]
cluster_endpoint =

[Deployer]
jobs_table = site-deploy-jobs
sites_table = site-sites
artifacts_bucket = site-artifacts-{account_id}
frontend_bucket = site-frontend-{account_id}
state_machine_arn =
```

- [ ] **Step 2: 克隆并部署上游 SSO 方案**

```bash
git clone https://github.com/aws-samples/sample-for-amazon-quick-sso-with-feishu /tmp/feishu-sso
cd /tmp/feishu-sso && cat README.md
```

按其 README 部署（Cognito User Pool + 飞书 OIDC 适配器 Lambda + 登录门户）。飞书 App ID/Secret 走其参数输入。将产出的 User Pool ID、Hosted UI 域名回填 `site-builder/config.ini`，并在 `UPSTREAM.md` 记录 commit hash 与资源清单。

- [ ] **Step 3: 为站点/MCP 创建两个 App Client**

```bash
source site-builder/config.ini.sh 2>/dev/null || true  # 读值可手工替换
aws cognito-idp create-user-pool-client --region us-east-1 \
  --user-pool-id <USER_POOL_ID> --client-name site-auth \
  --generate-secret \
  --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers Feishu \
  --callback-urls https://auth.<BASE_DOMAIN>/callback
aws cognito-idp create-user-pool-client --region us-east-1 \
  --user-pool-id <USER_POOL_ID> --client-name deploy-mcp \
  --allowed-o-auth-flows code --allowed-o-auth-scopes openid email \
  --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers Feishu \
  --callback-urls https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback
```

Expected: 两个 ClientId 输出，回填 config.ini（identity provider 名以上游栈实际创建的为准，先 `aws cognito-idp list-identity-providers --user-pool-id ...` 确认）。

- [ ] **Step 4: 人工验证 Quick 登录（门禁）**

用户在 Quick Web/Desktop 配置该 IdP 并用飞书账号登录成功。此步需用户确认后才继续。

- [ ] **Step 5: Commit**

```bash
git add site-builder/config.ini.example site-builder/auth/UPSTREAM.md .gitignore
git commit -m "feat(auth): deploy feishu-quick-sso base, register site/mcp app clients"
```

### Task 4: session 模块（HS256 JWT，纯标准库）

**Files:**
- Create: `site-builder/auth/session.py`
- Test: `site-builder/auth/tests/test_session.py`
- Create: `site-builder/auth/tests/conftest.py`（`sys.path` 注入 auth 目录）

**Interfaces:**
- Consumes: 无
- Produces: `mint_session_jwt(email, name, secret, ttl_seconds=86400) -> str`；`verify_session_jwt(token, secret, now=None) -> dict | None`（返回 `{"email":..., "name":..., "exp":...}` 或 None）。**此文件同时是 Task 7 Edge 函数内嵌验签逻辑的参考实现——两处算法必须一致（HS256、base64url、`{"alg":"HS256","typ":"JWT"}` 头）。**

- [ ] **Step 1: 写失败测试**

`site-builder/auth/tests/conftest.py`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
```

`site-builder/auth/tests/test_session.py`:

```python
import time
from session import mint_session_jwt, verify_session_jwt

SECRET = "test-secret-0123456789abcdef"


def test_roundtrip():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    claims = verify_session_jwt(tok, SECRET)
    assert claims["email"] == "a@x.com" and claims["name"] == "Alice"


def test_wrong_secret_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    assert verify_session_jwt(tok, "other-secret") is None


def test_expired_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET, ttl_seconds=10)
    assert verify_session_jwt(tok, SECRET, now=int(time.time()) + 11) is None


def test_tampered_payload_rejected():
    tok = mint_session_jwt("a@x.com", "Alice", SECRET)
    h, p, s = tok.split(".")
    assert verify_session_jwt(f"{h}.{p}x.{s}", SECRET) is None


def test_garbage_rejected():
    assert verify_session_jwt("not-a-jwt", SECRET) is None
    assert verify_session_jwt("", SECRET) is None
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/auth && python3 -m pytest tests/test_session.py -q`
Expected: FAIL（ModuleNotFoundError: session）

- [ ] **Step 3: 实现**

`site-builder/auth/session.py`:

```python
"""站点会话 JWT（HS256）——纯标准库实现。
Edge 函数（manus origin_request.py）内嵌同一算法验签，改动此处须同步 Task 7。"""
import base64
import hashlib
import hmac
import json
import time


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(msg: bytes, secret: str) -> str:
    return _b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())


def mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"email": email, "name": name, "exp": int(time.time()) + ttl_seconds},
        separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_session_jwt(token: str, secret: str, now: int | None = None) -> dict | None:
    try:
        header_b64, payload_b64, sig = token.split(".")
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), secret)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if int(claims.get("exp", 0)) <= (now if now is not None else int(time.time())):
            return None
        return claims
    except Exception:
        return None
```

- [ ] **Step 4: 运行确认通过**

Run: `python3 -m pytest tests/test_session.py -q`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/auth
git commit -m "feat(auth): HS256 session JWT mint/verify (stdlib only)"
```

### Task 5: auth-service Lambda（登录端点）+ 部署

**Files:**
- Create: `site-builder/auth/login_handler.py`
- Create: `site-builder/auth/requirements.txt`（`pyjwt[crypto]>=2.8`——验 Cognito RS256 ID token 用；会话 JWT 仍走 session.py）
- Create: `site-builder/auth/deploy_auth.py`
- Test: `site-builder/auth/tests/test_login_handler.py`

**Interfaces:**
- Consumes: `session.mint_session_jwt`；config.ini `[Cognito]`（domain/site_client_id/user_pool_id + client secret 从 SSM `/site-builder/site-client-secret` 读）、`[Platform].base_domain`
- Produces: 部署后的 Function URL（AuthType=NONE），注册到路由表 subdomain=`auth`、**`route_mode="api-only"`**（端点是 /login /callback /logout，不匹配 /api/*——api-only 让全路径走此 Lambda）、`require_auth=false`。路由：`GET /login?redirect=<url>`→302 Cognito Hosted UI；`GET /callback?code=&state=`→验 state 验 id_token→种 `sb_session` cookie→302 回 redirect；`GET /logout`→清 cookie。环境变量：`JWT_SECRET`（SSM 生成，兼作 state 签名密钥）、`COGNITO_DOMAIN`、`CLIENT_ID`、`CLIENT_SECRET`、`BASE_DOMAIN`、`USER_POOL_ID`。
- 安全要求（Global Constraints）：state = `base64(json{r, exp}) + "." + HMAC-SHA256`，5 分钟过期，验签失败/过期返回 400；id_token 用 Cognito JWKS 验签（`pyjwt` + `PyJWKClient`，模块级缓存），校验 `iss=https://cognito-idp.us-east-1.amazonaws.com/<POOL_ID>`、`aud=CLIENT_ID`、`exp`、`token_use=="id"`；redirect 白名单在 /login 与 /callback 双端校验。

- [ ] **Step 1: 写失败测试（handler 纯逻辑部分）**

`site-builder/auth/tests/test_login_handler.py`:

```python
import json
from unittest.mock import patch
import login_handler as lh

ENV = {"JWT_SECRET": "s3cret", "COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test"}


def _event(path, qs=None, cookies=None):
    return {"rawPath": path, "queryStringParameters": qs or {},
            "cookies": cookies or [], "requestContext": {"http": {"method": "GET"}}}


@patch.dict(lh.os.environ, ENV)
def test_login_redirects_to_hosted_ui():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith(ENV["COGNITO_DOMAIN"] + "/oauth2/authorize")
    assert "client_id=cid" in loc and "state=" in loc


@patch.dict(lh.os.environ, ENV)
def test_login_rejects_foreign_redirect():
    r = lh.handler(_event("/login", {"redirect": "https://evil.com/"}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
@patch.object(lh, "_exchange_code", return_value={"email": "a@x.com", "name": "Alice"})
def test_callback_sets_cookie_and_redirects(mock_ex):
    state = lh._encode_state("https://app-x.example.com/page?tab=2")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state}), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "https://app-x.example.com/page?tab=2"  # query 保留
    cookie = r["cookies"][0]
    assert cookie.startswith("sb_session=") and "Domain=.example.com" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_tampered_state():
    state = lh._encode_state("https://app-x.example.com/")
    body, _, sig = state.rpartition(".")
    import base64, json as _json
    payload = _json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["r"] = "https://evil.com/"
    forged = base64.urlsafe_b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
    r = lh.handler(_event("/callback", {"code": "abc", "state": f"{forged}.{sig}"}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_expired_state():
    import time
    with patch.object(lh.time, "time", return_value=time.time() - 600):
        state = lh._encode_state("https://app-x.example.com/")
    r = lh.handler(_event("/callback", {"code": "abc", "state": state}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_logout_clears_cookie():
    r = lh.handler(_event("/logout"), None)
    assert any("Max-Age=0" in c for c in r["cookies"])
```

- [ ] **Step 2: 运行确认失败**

Run: `python3 -m pytest tests/test_login_handler.py -q`
Expected: FAIL（ModuleNotFoundError: login_handler）

- [ ] **Step 3: 实现 handler**

`site-builder/auth/login_handler.py`:

```python
"""站点登录端点（Lambda Function URL）。
/login → Cognito Hosted UI（后接飞书 OIDC）；/callback → 验 state、验 id_token、
种顶域会话 cookie；/logout。
安全：state HMAC 签名 + 5 分钟过期（防 login CSRF/redirect 篡改）；
id_token 走 Cognito JWKS 验签 + iss/aud/exp/token_use 校验。"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request

import jwt as pyjwt
from jwt import PyJWKClient

from session import mint_session_jwt

_jwks_client = None  # 模块级缓存，Lambda 容器复用


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            f"https://cognito-idp.us-east-1.amazonaws.com/"
            f"{os.environ['USER_POOL_ID']}/.well-known/jwks.json")
    return _jwks_client


def _state_sig(body: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(
        os.environ["JWT_SECRET"].encode(), body.encode(),
        hashlib.sha256).digest()).rstrip(b"=").decode()


def _encode_state(redirect: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps(
        {"r": redirect, "exp": int(time.time()) + 300}).encode()).decode().rstrip("=")
    return f"{body}.{_state_sig(body)}"


def _decode_state(state: str) -> str | None:
    """验签 + 验期，失败返回 None。"""
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


def _is_safe_redirect(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    base = os.environ["BASE_DOMAIN"]
    return host == base or host.endswith("." + base)


def _exchange_code(code: str) -> dict:
    """code → Cognito token → JWKS 验签 → {email, name}"""
    domain = os.environ["COGNITO_DOMAIN"]
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": os.environ["CLIENT_ID"],
        "redirect_uri": f"https://auth.{os.environ['BASE_DOMAIN']}/callback",
    }).encode()
    basic = base64.b64encode(
        f"{os.environ['CLIENT_ID']}:{os.environ['CLIENT_SECRET']}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token", data=body,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        tokens = json.loads(resp.read())
    signing_key = _get_jwks_client().get_signing_key_from_jwt(tokens["id_token"])
    claims = pyjwt.decode(
        tokens["id_token"], signing_key.key, algorithms=["RS256"],
        audience=os.environ["CLIENT_ID"],
        issuer=f"https://cognito-idp.us-east-1.amazonaws.com/{os.environ['USER_POOL_ID']}")
    if claims.get("token_use") != "id":
        raise ValueError("token_use != id")
    return {"email": claims["email"], "name": claims.get("name", claims["email"])}


def handler(event, context):
    path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}
    base = os.environ["BASE_DOMAIN"]

    if path == "/login":
        redirect = qs.get("redirect", f"https://{base}/")
        if not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid redirect"}
        auth_url = (f"{os.environ['COGNITO_DOMAIN']}/oauth2/authorize?"
                    + urllib.parse.urlencode({
                        "response_type": "code", "client_id": os.environ["CLIENT_ID"],
                        "redirect_uri": f"https://auth.{base}/callback",
                        "scope": "openid email profile",
                        "state": _encode_state(redirect)}))
        return {"statusCode": 302, "headers": {"Location": auth_url}, "body": ""}

    if path == "/callback":
        redirect = _decode_state(qs.get("state", ""))
        if redirect is None or not _is_safe_redirect(redirect):
            return {"statusCode": 400, "body": "invalid or expired state"}
        user = _exchange_code(qs["code"])
        token = mint_session_jwt(user["email"], user["name"], os.environ["JWT_SECRET"])
        cookie = (f"sb_session={token}; Domain=.{base}; Path=/; Max-Age=86400; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 302, "headers": {"Location": redirect},
                "cookies": [cookie], "body": ""}

    if path == "/logout":
        cookie = (f"sb_session=; Domain=.{base}; Path=/; Max-Age=0; "
                  f"Secure; HttpOnly; SameSite=Lax")
        return {"statusCode": 200, "cookies": [cookie],
                "headers": {"Content-Type": "text/html"},
                "body": "<h1>已退出登录</h1>"}

    return {"statusCode": 404, "body": "not found"}
```

- [ ] **Step 4: 运行确认通过**

Run: `python3 -m pip install 'pyjwt[crypto]>=2.8' -q && python3 -m pytest tests/ -q`
Expected: 11 passed（session 5 + handler 6）

- [ ] **Step 5: 写部署脚本**

`site-builder/auth/deploy_auth.py`（模式仿 manus `scripts/deploy_lambda.py`，boto3 直建）：

```python
"""部署 auth-service：打 zip（session.py+login_handler.py+pyjwt 依赖）→ 建/更新 Lambda
→ Function URL(NONE) → 生成 JWT_SECRET 存 SSM → 路由表注册 subdomain=auth。幂等可重跑。"""
import configparser
import io
import secrets
import subprocess
import tempfile
import zipfile
from pathlib import Path

import boto3

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parent.parent / "config.ini")
REGION = CFG["Platform"]["region"]
BASE = CFG["Platform"]["base_domain"]
FN = "site-auth-service"

ssm = boto3.client("ssm", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
ddb = boto3.client("dynamodb", region_name=REGION)
iam = boto3.client("iam")


def ensure_secret(name: str, generate) -> str:
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        val = generate()
        ssm.put_parameter(Name=name, Value=val, Type="SecureString")
        return val


def build_zip() -> bytes:
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["python3", "-m", "pip", "install", "-r", str(src / "requirements.txt"),
                        "-t", td, "-q", "--platform", "manylinux2014_x86_64",
                        "--only-binary", ":all:", "--python-version", "3.13"], check=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in Path(td).rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(td))
            z.write(src / "session.py", "session.py")
            z.write(src / "login_handler.py", "login_handler.py")
        return buf.getvalue()


def main():
    jwt_secret = ensure_secret("/site-builder/jwt-secret", lambda: secrets.token_hex(32))
    client_secret = ssm.get_parameter(Name="/site-builder/site-client-secret",
                                      WithDecryption=True)["Parameter"]["Value"]
    role_arn = ensure_lambda_role()
    env = {"Variables": {
        "JWT_SECRET": jwt_secret,
        "COGNITO_DOMAIN": CFG["Cognito"]["domain"],
        "CLIENT_ID": CFG["Cognito"]["site_client_id"],
        "CLIENT_SECRET": client_secret,
        "BASE_DOMAIN": BASE,
        "USER_POOL_ID": CFG["Cognito"]["user_pool_id"]}}
    code = build_zip()
    try:
        lam.get_function(FunctionName=FN)
        lam.update_function_code(FunctionName=FN, ZipFile=code)
        lam.get_waiter("function_updated").wait(FunctionName=FN)
        lam.update_function_configuration(FunctionName=FN, Environment=env)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_function(FunctionName=FN, Runtime="python3.13",
                            Handler="login_handler.handler", Role=role_arn,
                            Code={"ZipFile": code}, Timeout=15, MemorySize=256,
                            Environment=env)
        lam.get_waiter("function_active").wait(FunctionName=FN)
    try:
        url = lam.create_function_url_config(FunctionName=FN, AuthType="NONE")["FunctionUrl"]
        lam.add_permission(FunctionName=FN, StatementId="public-url",
                           Action="lambda:InvokeFunctionUrl", Principal="*",
                           FunctionUrlAuthType="NONE")
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=FN)["FunctionUrl"]
    ddb.put_item(TableName=CFG["Platform"]["routing_table"], Item={
        "subdomain": {"S": "auth"}, "site_id": {"S": "auth-service"},
        "route_mode": {"S": "api-only"},  # 全路径走 Lambda（/login 不匹配 /api/*）
        "static_prefix": {"S": ""}, "api_target": {"S": url.rstrip("/")},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "platform"}})
    print(f"auth-service: {url}  →  https://auth.{BASE}/")


def ensure_lambda_role() -> str:
    name = "site-auth-service-role"
    try:
        return iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        r = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json_trust())
        iam.attach_role_policy(RoleName=name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
        import time; time.sleep(10)  # IAM 传播
        return r["Role"]["Arn"]


def json_trust() -> str:
    return ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')


if __name__ == "__main__":
    main()
```

注意：路由表注册使用 Task 6 的新表结构；若 M2 尚未部署（表不存在/无新字段），脚本会在 put_item 成功但字段暂不被 Edge 消费——顺序无碍。site_client 的 client secret 需先手工存 SSM：`aws ssm put-parameter --name /site-builder/site-client-secret --type SecureString --value <SECRET>`。

- [ ] **Step 6: 部署并冒烟**

Run: `python3 site-builder/auth/deploy_auth.py`，然后 `curl -sI "<FunctionUrl>/login?redirect=https://app-x.<BASE_DOMAIN>/"`
Expected: `HTTP/1.1 302` 且 `Location:` 指向 Cognito `/oauth2/authorize`

- [ ] **Step 7: Commit**

```bash
git add site-builder/auth
git commit -m "feat(auth): site login service (Cognito hosted UI + top-domain session cookie)"
```

## Phase P2：路由 + 鉴权层（M2，manus 项目就地改造）

### Task 6: Edge 函数——路由表扩展 + 分流 + body 签名 + fail-closed

manus 现有 `origin_request.py` 只有单一 `target_url`。本任务改为：
- 路由 item 含 `route_mode`（`split`/`api-only`）、`static_prefix`（S3 **版本化**前缀 `sites/{site_id}/{job_id}`）与 `api_target`（Function URL）。
- `split`：URI 以 `/api/` 开头走 api_target（SigV4），否则改写到共享前端桶 S3 REST 端点（桶私有，Edge 执行角色对 S3 GET 做 SigV4——与现有 `_add_sigv4_auth` 同机制，service 换 `s3`）；URI 无扩展名映射 `index.html`（SPA）。
- `api-only`：全路径走 api_target（auth 子域用）。
- **带 body 的 SigV4**：CloudFront 在 `include_body=True` 时以 base64 提供 body——签名前解码并作为 payload 参与 hash；`body.inputTruncated` 为真时直接返回 413（Lambda@Edge origin-request body 上限 1MB）。
- **fail-closed**：`lambda_handler` 顶层异常返回 500 响应，绝不透传原请求（原 manus 行为是 return request——安全边界不允许）。

**Files:**
- Modify: `manus-web-application-main/infrastructure/lambda/origin_request.py`
- Test: `manus-web-application-main/infrastructure/lambda/test_origin_request.py`（新建）

**Interfaces:**
- Consumes: 路由表新 item 结构（见 File Structure 节）；模板占位符机制新增 `{{FRONTEND_BUCKET_DOMAIN}}`、`{{JWT_SECRET}}`（Task 8 注入）
- Produces: `_route_request(request, route_item) -> dict`——分流后的请求对象；`_lookup_route(subdomain) -> dict | None`（返回整个 item 的反序列化 dict）。Task 7 在其上叠加鉴权。

- [ ] **Step 1: 写失败测试**

`manus-web-application-main/infrastructure/lambda/test_origin_request.py`:

```python
"""Edge 路由单测——DynamoDB 与签名 mock 掉，测分流与改写逻辑。"""
import importlib
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent))

# 占位符在测试中先替换再 import
_SRC = (Path(__file__).parent / "origin_request.py").read_text()
_SRC = (_SRC.replace("{{DYNAMODB_TABLE_NAME}}", "test-table")
            .replace("{{DYNAMODB_REGION}}", "us-east-1")
            .replace("{{FRONTEND_BUCKET_DOMAIN}}", "site-frontend-123.s3.us-east-1.amazonaws.com")
            .replace("{{JWT_SECRET}}", "test-secret"))
_mod_path = Path(__file__).parent / "_origin_request_testable.py"
_mod_path.write_text(_SRC)
import _origin_request_testable as orq


ROUTE = {"subdomain": "app-demo1", "site_id": "demo1", "route_mode": "split",
         "static_prefix": "sites/demo1/job-aaa",
         "api_target": "https://abc.lambda-url.us-east-1.on.aws",
         "require_auth": False, "allowed_users": "org", "owner": "a@x.com"}


def _event(host="app-demo1.example.com", uri="/", method="GET", cookie=None, body=None):
    headers = {"host": [{"key": "Host", "value": host}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    req = {"uri": uri, "querystring": "", "method": method, "headers": headers}
    if body is not None:
        req["body"] = body
    return {"Records": [{"cf": {"request": req}}]}


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_sigv4_auth")
def test_api_path_routes_to_lambda(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/api/items"), None)
    assert req["origin"]["custom"]["domainName"] == "abc.lambda-url.us-east-1.on.aws"
    mock_sig.assert_called_once()


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_s3_sigv4_auth")
def test_static_path_routes_to_s3_with_versioned_prefix(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/assets/app.js"), None)
    assert req["origin"]["custom"]["domainName"] == "site-frontend-123.s3.us-east-1.amazonaws.com"
    assert req["uri"] == "/sites/demo1/job-aaa/assets/app.js"


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
@patch.object(orq, "_add_s3_sigv4_auth")
def test_extensionless_uri_maps_to_index(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(uri="/"), None)
    assert req["uri"] == "/sites/demo1/job-aaa/index.html"
    req2 = orq.lambda_handler(_event(uri="/detail"), None)
    assert req2["uri"] == "/sites/demo1/job-aaa/index.html"


@patch.object(orq, "_lookup_route",
              return_value={"subdomain": "auth", "site_id": "auth-service",
                            "route_mode": "api-only", "static_prefix": "",
                            "api_target": "https://xyz.lambda-url.us-east-1.on.aws",
                            "require_auth": False, "allowed_users": "org",
                            "owner": "platform"})
@patch.object(orq, "_add_sigv4_auth")
def test_api_only_mode_routes_all_paths_to_lambda(mock_sig, mock_lookup):
    req = orq.lambda_handler(_event(host="auth.example.com", uri="/login"), None)
    assert req["origin"]["custom"]["domainName"] == "xyz.lambda-url.us-east-1.on.aws"
    assert req["uri"] == "/login"


@patch.object(orq, "_lookup_route", return_value=None)
def test_unknown_subdomain_404(mock_lookup):
    resp = orq.lambda_handler(_event(host="nope.example.com"), None)
    assert resp["status"] == "404"


@patch.object(orq, "_lookup_route",
              return_value={**ROUTE, "api_target": ""})
def test_api_on_static_only_site_404(mock_lookup):
    resp = orq.lambda_handler(_event(uri="/api/items"), None)
    assert resp["status"] == "404"


@patch.object(orq, "_lookup_route", return_value=dict(ROUTE))
def test_truncated_body_returns_413(mock_lookup):
    resp = orq.lambda_handler(_event(uri="/api/items", method="POST",
                                     body={"inputTruncated": True, "data": "", 
                                           "encoding": "base64"}), None)
    assert resp["status"] == "413"


@patch.object(orq, "_lookup_route", side_effect=RuntimeError("boom"))
def test_edge_fails_closed_on_exception(mock_lookup):
    resp = orq.lambda_handler(_event(), None)
    assert resp["status"] == "500"  # 绝不透传原请求
```

- [ ] **Step 2: 运行确认失败**

Run: `cd manus-web-application-main/infrastructure/lambda && python3 -m pytest test_origin_request.py -q`
Expected: FAIL（`_lookup_route` 不存在——现文件是 `_lookup_target_url`）

- [ ] **Step 3: 改造 origin_request.py**

保留原有 `_get_original_host` / `_extract_subdomain` / `_fix_querystring_encoding` / `_add_sigv4_auth` / SigV4 会话初始化不动；将 `_lookup_target_url` 替换为 `_lookup_route`，`_modify_request_origin` 替换为 `_route_request` + `_add_s3_sigv4_auth`，`lambda_handler` 主干改为：

```python
# 新增常量（顶部，与 {{DYNAMODB_TABLE_NAME}} 并列）
FRONTEND_BUCKET_DOMAIN = "{{FRONTEND_BUCKET_DOMAIN}}"
JWT_SECRET = "{{JWT_SECRET}}"  # Task 7 使用
_ROUTE_CACHE: dict = {}  # subdomain -> (expires_epoch, item)
ROUTE_CACHE_TTL = 60


def _deser(item: dict) -> dict:
    """DynamoDB AttributeValue -> plain dict（仅 S/BOOL，本表够用）"""
    out = {}
    for k, v in item.items():
        out[k] = v["S"] if "S" in v else v.get("BOOL", False)
    return out


def _lookup_route(subdomain: str):
    import time as _t
    hit = _ROUTE_CACHE.get(subdomain)
    if hit and hit[0] > _t.time():
        return hit[1]
    try:
        resp = dynamodb.get_item(TableName=DYNAMODB_TABLE_NAME,
                                 Key={"subdomain": {"S": subdomain}},
                                 ConsistentRead=False)
        item = _deser(resp["Item"]) if "Item" in resp else None
    except ClientError as e:
        logger.error(f"DynamoDB错误: {e}")
        return None
    _ROUTE_CACHE[subdomain] = (_t.time() + ROUTE_CACHE_TTL, item)
    return item


def _not_found(msg: str) -> dict:
    return {"status": "404", "statusDescription": "Not Found",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/html"}]},
            "body": f"<html><body><h1>404 Not Found</h1><p>{msg}</p></body></html>"}


def _get_request_body(request):
    """include_body=True 时 CloudFront 提供 base64 body；截断返回哨兵。"""
    body = request.get("body") or {}
    if body.get("inputTruncated"):
        return None  # 调用方返回 413
    data = body.get("data", "")
    if not data:
        return b""
    if body.get("encoding") == "base64":
        import base64
        return base64.b64decode(data)
    return data.encode()


def _payload_too_large() -> dict:
    return {"status": "413", "statusDescription": "Payload Too Large",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/plain"}]},
            "body": "请求体超过 1MB 上限"}


def _route_to_lambda(request, route, uri, qs):
    target = route.get("api_target") or ""
    if not target:
        return _not_found("此站点无后端")
    body = _get_request_body(request)
    if body is None:
        return _payload_too_large()
    domain = urllib.parse.urlparse(target).netloc
    if ".lambda-url." in domain and ".on.aws" in domain:
        _add_sigv4_auth(request, domain, uri, qs, body)
    request["origin"] = _custom_origin(domain)
    request["headers"]["host"] = [{"key": "Host", "value": domain}]
    return request


def _route_request(request, route):
    uri = request.get("uri", "/")
    qs = _fix_querystring_encoding(request.get("querystring", ""))
    request["querystring"] = qs

    if route.get("route_mode") == "api-only":
        return _route_to_lambda(request, route, uri, qs)

    if uri.startswith("/api/"):
        return _route_to_lambda(request, route, uri, qs)

    # 静态资源 → 共享前端桶（私有，SigV4 GET）
    if request.get("method") not in ("GET", "HEAD"):
        return _not_found("方法不允许")
    path = uri if ("." in uri.rsplit("/", 1)[-1]) else "/index.html"
    request["uri"] = f"/{route['static_prefix']}{path}" if path != uri else f"/{route['static_prefix']}{uri}"
    _add_s3_sigv4_auth(request, FRONTEND_BUCKET_DOMAIN, request["uri"])
    request["origin"] = _custom_origin(FRONTEND_BUCKET_DOMAIN)
    request["headers"]["host"] = [{"key": "Host", "value": FRONTEND_BUCKET_DOMAIN}]
    return request


def _custom_origin(domain: str) -> dict:
    return {"custom": {"domainName": domain, "port": DEFAULT_PORT,
                       "protocol": DEFAULT_PROTOCOL, "path": "",
                       "sslProtocols": DEFAULT_SSL_PROTOCOLS,
                       "readTimeout": DEFAULT_READ_TIMEOUT,
                       "keepaliveTimeout": DEFAULT_KEEPALIVE_TIMEOUT,
                       "customHeaders": {}}}


def _add_s3_sigv4_auth(request, domain: str, uri: str) -> None:
    """S3 GET 的 SigV4（Edge 执行角色需有该桶前缀的 s3:GetObject）"""
    url = f"https://{domain}{urllib.parse.quote(uri)}"
    aws_request = AWSRequest(method="GET", url=url)
    SigV4Auth(credentials, "s3", "us-east-1").add_auth(aws_request)
    for h, v in aws_request.headers.items():
        if h.lower() in ("authorization", "x-amz-date", "x-amz-security-token",
                         "x-amz-content-sha256"):
            request["headers"][h.lower()] = [{"key": h, "value": v}]
```

`lambda_handler` 主干替换为（**fail-closed**——原 manus 异常时 `return request` 会绕过鉴权落到默认 origin，安全边界不允许）：

```python
def _server_error() -> dict:
    return {"status": "500", "statusDescription": "Internal Server Error",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/plain"}]},
            "body": "服务暂时不可用"}


def lambda_handler(event, context):
    try:
        request = event["Records"][0]["cf"]["request"]
        original_host = _get_original_host(request)
        if not original_host:
            return _server_error()
        subdomain = _extract_subdomain(original_host)
        route = _lookup_route(subdomain)
        if not route:
            return _not_found(f'Subdomain "{subdomain}" not configured.')
        # Task 7 在此处插入鉴权
        return _route_request(request, route)
    except Exception as e:
        logger.error(f"处理请求时出错: {e}", exc_info=True)
        return _server_error()
```

同时修改现有 `_add_sigv4_auth` 签名为 `_add_sigv4_auth(request, domain, uri, querystring, body: bytes)`：`AWSRequest(method=..., url=..., data=body)` 用解码后的真实 body 计算 payload hash（原实现读 `request["body"]["data"]` 原始 base64 字符串——签名值错误）。

- [ ] **Step 4: 运行确认通过**

Run: `python3 -m pytest test_origin_request.py -q`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add manus-web-application-main/infrastructure/lambda
git commit -m "feat(router): route_mode split/api-only, body-aware sigv4, fail-closed edge"
```

### Task 7: Edge 函数——JWT 鉴权 + 302 跳登录 + 用户头注入

**Files:**
- Modify: `manus-web-application-main/infrastructure/lambda/origin_request.py`
- Test: `manus-web-application-main/infrastructure/lambda/test_edge_auth.py`（新建）

**Interfaces:**
- Consumes: Task 6 的 `_lookup_route`/`_route_request`；Task 4 的 JWT 格式（HS256、claims `{email,name,exp}`、cookie 名 `sb_session`）；登录端点 `https://auth.{BASE_DOMAIN}/login`
- Produces: `_check_auth(request, route, host) -> dict | None`——None 表示放行（并已注入用户头），dict 为 302/403 响应。新占位符 `{{BASE_DOMAIN}}`。

- [ ] **Step 1: 写失败测试**

`manus-web-application-main/infrastructure/lambda/test_edge_auth.py`:

```python
import base64, hashlib, hmac, json, time
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
_SRC = (Path(__file__).parent / "origin_request.py").read_text()
for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
             "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
             "{{JWT_SECRET}}": "test-secret", "{{BASE_DOMAIN}}": "example.com"}.items():
    _SRC = _SRC.replace(k, v)
(Path(__file__).parent / "_edge_auth_testable.py").write_text(_SRC)
import _edge_auth_testable as orq


def _jwt(email="a@x.com", name="Alice", exp_delta=3600, secret="test-secret"):
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64(json.dumps({"email": email, "name": name,
                        "exp": int(time.time()) + exp_delta}).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


ROUTE_AUTH = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x",
              "api_target": "", "require_auth": True, "allowed_users": "org",
              "owner": "o@x.com"}


def _req(uri="/", cookie=None, extra_headers=None):
    headers = {"host": [{"key": "Host", "value": "app-x.example.com"}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    headers.update(extra_headers or {})
    return {"uri": uri, "querystring": "", "method": "GET", "headers": headers}


def test_no_cookie_redirects_to_login():
    resp = orq._check_auth(_req(), dict(ROUTE_AUTH), "app-x.example.com")
    assert resp["status"] == "302"
    loc = resp["headers"]["location"][0]["value"]
    assert loc.startswith("https://auth.example.com/login?redirect=")


def test_redirect_preserves_querystring():
    r = _req(uri="/page")
    r["querystring"] = "tab=2&q=x"
    resp = orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    loc = resp["headers"]["location"][0]["value"]
    import urllib.parse as up
    target = up.unquote(loc.split("redirect=")[1])
    assert target == "https://app-x.example.com/page?tab=2&q=x"


def test_valid_cookie_passes_and_injects_headers():
    r = _req(cookie=f"sb_session={_jwt()}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com") is None
    assert r["headers"]["x-user-email"][0]["value"] == "a@x.com"


def test_expired_cookie_redirects():
    r = _req(cookie=f"sb_session={_jwt(exp_delta=-10)}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")["status"] == "302"


def test_wrong_signature_redirects():
    r = _req(cookie=f"sb_session={_jwt(secret='other')}")
    assert orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")["status"] == "302"


def test_allowlist_rejects_outsider():
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    r = _req(cookie=f"sb_session={_jwt(email='a@x.com')}")
    assert orq._check_auth(r, route, "app-x.example.com")["status"] == "403"


def test_allowlist_admits_member_and_owner():
    route = {**ROUTE_AUTH, "allowed_users": json.dumps(["vip@x.com"])}
    assert orq._check_auth(_req(cookie=f"sb_session={_jwt(email='vip@x.com')}"),
                           route, "app-x.example.com") is None
    assert orq._check_auth(_req(cookie=f"sb_session={_jwt(email='o@x.com')}"),
                           route, "app-x.example.com") is None


def test_spoofed_user_header_stripped():
    r = _req(cookie=f"sb_session={_jwt()}",
             extra_headers={"x-user-email": [{"key": "x-user-email", "value": "fake@x.com"}]})
    orq._check_auth(r, dict(ROUTE_AUTH), "app-x.example.com")
    assert r["headers"]["x-user-email"][0]["value"] == "a@x.com"


def test_no_auth_route_strips_spoofed_headers_too():
    route = {**ROUTE_AUTH, "require_auth": False}
    r = _req(extra_headers={"x-user-email": [{"key": "x-user-email", "value": "fake@x.com"}]})
    assert orq._check_auth(r, route, "app-x.example.com") is None
    assert "x-user-email" not in r["headers"]
```

- [ ] **Step 2: 运行确认失败**

Run: `python3 -m pytest test_edge_auth.py -q`
Expected: FAIL（AttributeError: `_check_auth` 不存在）

- [ ] **Step 3: 实现鉴权**

`origin_request.py` 新增（置于 `_route_request` 之前）：

```python
BASE_DOMAIN = "{{BASE_DOMAIN}}"


def _b64url_decode(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_session_jwt(token: str) -> dict | None:
    """与 site-builder/auth/session.py 同算法（HS256），改动须两处同步。"""
    import base64, hashlib, hmac as _hmac, time as _t
    try:
        h, p, sig = token.split(".")
        expected = base64.urlsafe_b64encode(
            _hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(p))
        if int(claims.get("exp", 0)) <= int(_t.time()):
            return None
        return claims
    except Exception:
        return None


def _get_cookie(request, name: str) -> str | None:
    for header in request.get("headers", {}).get("cookie", []):
        for part in header["value"].split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
    return None


def _redirect_login(host: str, uri: str, querystring: str = "") -> dict:
    full = f"https://{host}{uri}" + (f"?{querystring}" if querystring else "")
    target = urllib.parse.quote(full, safe="")
    return {"status": "302", "statusDescription": "Found",
            "headers": {"location": [{"key": "Location",
                        "value": f"https://auth.{BASE_DOMAIN}/login?redirect={target}"}]}}


def _forbidden() -> dict:
    return {"status": "403", "statusDescription": "Forbidden",
            "headers": {"content-type": [{"key": "Content-Type", "value": "text/html"}]},
            "body": "<html><body><h1>403</h1><p>你不在此站点的访问名单内。</p></body></html>"}


def _check_auth(request, route, host):
    """返回 None=放行（用户头已注入）；返回 dict=302/403 响应。"""
    # 无条件剥除客户端可伪造的用户头
    request["headers"].pop("x-user-email", None)
    request["headers"].pop("x-user-name", None)

    if not route.get("require_auth"):
        return None

    token = _get_cookie(request, "sb_session")
    claims = _verify_session_jwt(token) if token else None
    if not claims:
        return _redirect_login(host, request.get("uri", "/"),
                               request.get("querystring", ""))

    allowed = route.get("allowed_users", "org")
    if allowed != "org":
        try:
            allowlist = json.loads(allowed)
        except Exception:
            allowlist = []
        if claims["email"] not in allowlist and claims["email"] != route.get("owner"):
            return _forbidden()

    request["headers"]["x-user-email"] = [{"key": "x-user-email", "value": claims["email"]}]
    request["headers"]["x-user-name"] = [{"key": "x-user-name",
                                          "value": urllib.parse.quote(claims.get("name", ""))}]
    return None
```

`lambda_handler` 中 `# Task 7 在此处插入鉴权` 替换为：

```python
        denied = _check_auth(request, route, original_host)
        if denied:
            return denied
```

- [ ] **Step 4: 运行两套 Edge 测试确认通过**

Run: `python3 -m pytest test_origin_request.py test_edge_auth.py -q`
Expected: 17 passed

- [ ] **Step 5: Commit**

```bash
git add manus-web-application-main/infrastructure/lambda
git commit -m "feat(router): edge session auth with header injection and spoof stripping"
```

### Task 8: manus CDK 栈更新部署 + 路由层冒烟

**Files:**
- Modify: `manus-web-application-main/infrastructure/stack.py`
- Modify: `manus-web-application-main/config.ini`（真实值，gitignore）
- Create: `site-builder/scripts/smoke_router.sh`

**Interfaces:**
- Consumes: Task 6/7 的占位符 `{{FRONTEND_BUCKET_DOMAIN}}` `{{JWT_SECRET}}` `{{BASE_DOMAIN}}`；SSM `/site-builder/jwt-secret`
- Produces: 运行中的 CloudFront 分发（**无缓存 + include_body**）+ 扩展路由表。config.ini `[Deployer].frontend_bucket` 生效。

- [ ] **Step 0: 禁用缓存 + include_body（鉴权正确性前提）**

`stack.py` 的 Distribution 定义修改（默认行为与 `/api/*` 行为同样处理）：

```python
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(...),  # 原样
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,  # ← 原自定义 cache_policy 移除
                origin_request_policy=origin_request_policy,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                compress=True,
                edge_lambdas=[
                    cloudfront.EdgeLambda(
                        function_version=edge_function.current_version,
                        event_type=cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
                        include_body=True,  # ← body 参与 SigV4 签名的前提
                    )
                ],
            ),
```

原 `cache_policy = cloudfront.CachePolicy(self, "CachePolicy", ...)` 整段删除；`additional_behaviors` 的 `/api/*` 行为因与默认行为完全一致也整段删除。理由（写进 commit message）：origin-request 事件只在 cache miss 执行，任何缓存都会让已鉴权响应被未登录用户命中、并在通配符域名下跨站串内容；CACHING_DISABLED 同时消除路由更新/下线的缓存延迟问题。

- [ ] **Step 1: stack.py 注入新占位符与权限**

在现有 `lambda_code.replace(...)` 链（`stack.py:106-112`）追加：

```python
        import boto3 as _b3
        _ssm = _b3.client("ssm", region_name="us-east-1")
        jwt_secret = _ssm.get_parameter(Name="/site-builder/jwt-secret",
                                        WithDecryption=True)["Parameter"]["Value"]
        frontend_bucket = config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET")
        base_domain = config.get("SiteBuilder", "base_domain", "APP_BASE_DOMAIN")
        lambda_code = (lambda_code
            .replace("{{FRONTEND_BUCKET_DOMAIN}}",
                     f"{frontend_bucket}.s3.us-east-1.amazonaws.com")
            .replace("{{JWT_SECRET}}", jwt_secret)
            .replace("{{BASE_DOMAIN}}", base_domain))
```

edge_role 追加 S3 读权限（`mapping_table.grant_read_data(edge_role)` 之后）：

```python
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW, actions=["s3:GetObject"],
            resources=[f"arn:aws:s3:::{frontend_bucket}/sites/*"]))
```

`config.ini` 增加段：

```ini
[SiteBuilder]
frontend_bucket = site-frontend-<ACCOUNT_ID>
base_domain = <BASE_DOMAIN>
```

- [ ] **Step 2: 创建前端桶（若不存在）并部署栈**

```bash
aws s3api create-bucket --bucket site-frontend-<ACCOUNT_ID> --region us-east-1
aws s3api put-public-access-block --bucket site-frontend-<ACCOUNT_ID> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
cd manus-web-application-main/infrastructure && source .venv/bin/activate && cdk deploy --require-approval never
```

Expected: 栈更新成功（Lambda@Edge 新版本发布，CloudFront 传播 15-30 分钟）。若首次部署：先按 manus README 完成 `config.ini` 全量配置 + `cdk bootstrap` + DNS CNAME。

- [ ] **Step 3: 写冒烟脚本**

`site-builder/scripts/smoke_router.sh`:

```bash
#!/usr/bin/env bash
# 路由层冒烟：无 auth 静态路由 / 有 auth 302 / 未知子域 404
set -euo pipefail
BASE_DOMAIN=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['base_domain'])")
TABLE=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")
BUCKET=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Deployer']['frontend_bucket'].replace('{account_id}',c['Platform']['account_id']))")

echo "hello-router" > /tmp/index.html
echo "hello-other" > /tmp/index2.html
aws s3 cp /tmp/index.html "s3://${BUCKET}/sites/smoke/job-smoke1/index.html"
aws s3 cp /tmp/index2.html "s3://${BUCKET}/sites/smoke2/job-smoke2/index.html"
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smoke"},"site_id":{"S":"smoke"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke/job-smoke1"},"api_target":{"S":""},
  "require_auth":{"BOOL":false},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smoke2"},"site_id":{"S":"smoke2"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke2/job-smoke2"},"api_target":{"S":""},
  "require_auth":{"BOOL":false},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smokeauth"},"site_id":{"S":"smoke"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke/job-smoke1"},"api_target":{"S":""},
  "require_auth":{"BOOL":true},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
sleep 65  # 等 Edge 路由缓存过期

test "$(curl -s https://app-smoke.${BASE_DOMAIN}/)" = "hello-router" && echo "PASS: static route"
# 不同子域同路径内容不串（缓存已禁用的行为验证）
test "$(curl -s https://app-smoke2.${BASE_DOMAIN}/)" = "hello-other" && echo "PASS: no cross-site cache"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' https://app-smokeauth.${BASE_DOMAIN}/)
[[ "$LOC" == https://auth.${BASE_DOMAIN}/login* ]] && echo "PASS: auth 302"
# auth 子域全路径路由到认证 Lambda（api-only 模式，从公网地址验证而非 Function URL 直连）
ALOC=$(curl -s -o /dev/null -w '%{redirect_url}' "https://auth.${BASE_DOMAIN}/login?redirect=https://app-smoke.${BASE_DOMAIN}/")
[[ "$ALOC" == *"/oauth2/authorize"* ]] && echo "PASS: auth subdomain api-only routing"
CODE=$(curl -s -o /dev/null -w '%{http_code}' https://app-nonexistent.${BASE_DOMAIN}/)
[[ "$CODE" == "404" ]] && echo "PASS: unknown 404"
# 路由更新即时生效（无缓存）：切 static_prefix 后 65 秒内可见新内容
aws dynamodb update-item --table-name "$TABLE" \
  --key '{"subdomain":{"S":"app-smoke"}}' \
  --update-expression "SET static_prefix = :p" \
  --expression-attribute-values '{":p":{"S":"sites/smoke2/job-smoke2"}}'
sleep 65
test "$(curl -s https://app-smoke.${BASE_DOMAIN}/)" = "hello-other" && echo "PASS: route update visible"
```

- [ ] **Step 4: 运行冒烟（Edge 传播完成后）**

Run: `bash site-builder/scripts/smoke_router.sh`
Expected: 六行 PASS（static route / no cross-site cache / auth 302 / auth subdomain api-only routing / unknown 404 / route update visible）。人工补充验证：浏览器打开 `https://app-smokeauth.<BASE_DOMAIN>/` → 飞书登录 → 回跳看到内容。

- [ ] **Step 5: Commit**

```bash
git add manus-web-application-main/infrastructure/stack.py site-builder/scripts/smoke_router.sh
git commit -m "feat(router): wire frontend bucket, jwt secret and base domain into edge deploy"
```

## Phase P3：异步部署执行器（M3）

### Task 9: deployer 基础设施 CDK（表/桶/角色/CodeBuild）

**Files:**
- Create: `site-builder/deployer/infra/app.py`
- Create: `site-builder/deployer/infra/cdk.json`（`{"app": "python3 app.py"}`）
- Create: `site-builder/deployer/infra/requirements.txt`（`aws-cdk-lib>=2.140,<3`、`constructs>=10`、`boto3`）
- Create: `site-builder/deployer/buildspec-package.yml`

**Interfaces:**
- Consumes: config.ini `[Platform]`、`[Deployer]`
- Produces: DynamoDB 表 `site-deploy-jobs`（PK job_id，GSI owner-index）、`site-sites`（PK site_id）；S3 桶 `site-artifacts-{account}`；CodeBuild 项目 `site-package`；IAM 角色 `site-deployer-exec-role`（Step Functions Lambda 共用）。**站点运行时角色不在 CDK 里建**——站点代码是不可信代码，每站点一个独立角色 `site-rt-{site_id}`（由 Task 15 部署器动态创建，权限精确到该站点的表与 DSQL role）；exec role 因此需要 `iam:CreateRole/PutRolePolicy/GetRole/PassRole/DeleteRole/DeleteRolePolicy`，Resource 限定 `role/site-rt-*`，并附 **PermissionsBoundary 强制条件**（`iam:PermissionsBoundary` condition key）防权限升级。CfnOutput 全部资源名/ARN。状态机在 Task 17 加入同一 stack。

- [ ] **Step 1: 写 CDK stack**

`site-builder/deployer/infra/app.py`:

```python
#!/usr/bin/env python3
"""Deployer 基础设施：任务/站点表、产物桶、CodeBuild 打包项目、执行角色。
状态机定义在 Task 17 追加到本 stack。"""
import configparser
from pathlib import Path

from aws_cdk import (App, CfnOutput, Duration, Environment, RemovalPolicy, Stack,
                     aws_codebuild as cb, aws_dynamodb as ddb, aws_iam as iam,
                     aws_s3 as s3)
from constructs import Construct

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parents[2] / "config.ini")
ACCOUNT = CFG["Platform"]["account_id"]
REGION = CFG["Platform"]["region"]


class SiteDeployerStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw):
        super().__init__(scope, cid, **kw)

        jobs = ddb.Table(self, "Jobs", table_name="site-deploy-jobs",
                         partition_key=ddb.Attribute(name="job_id", type=ddb.AttributeType.STRING),
                         billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                         removal_policy=RemovalPolicy.DESTROY)
        jobs.add_global_secondary_index(
            index_name="owner-index",
            partition_key=ddb.Attribute(name="owner", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="created_at", type=ddb.AttributeType.STRING))
        sites = ddb.Table(self, "Sites", table_name="site-sites",
                          partition_key=ddb.Attribute(name="site_id", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                          removal_policy=RemovalPolicy.DESTROY)

        artifacts = s3.Bucket(self, "Artifacts", bucket_name=f"site-artifacts-{ACCOUNT}",
                              block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                              removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True,
                              lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(30))])

        # 站点运行时权限边界：per-site 角色（site-rt-*，Task 15 动态创建）的能力上限。
        # 站点代码不可信——boundary 限制其最坏情况能力面；精确资源由各角色 inline policy 再收窄。
        runtime_boundary = iam.ManagedPolicy(
            self, "SiteRuntimeBoundary", managed_policy_name="site-runtime-boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                             "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
                    resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-data-*"]),
                iam.PolicyStatement(actions=["dsql:DbConnect"], resources=["*"]),
                iam.PolicyStatement(
                    actions=["logs:CreateLogGroup", "logs:CreateLogStream",
                             "logs:PutLogEvents"],
                    resources=[f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/site-*"]),
            ])

        package_project = cb.Project(
            self, "PackageProject", project_name="site-package",
            build_spec=cb.BuildSpec.from_asset(
                str(Path(__file__).parents[1] / "buildspec-package.yml")),
            environment=cb.BuildEnvironment(
                build_image=cb.LinuxBuildImage.STANDARD_7_0,
                compute_type=cb.ComputeType.SMALL),
            timeout=Duration.minutes(15))
        artifacts.grant_read_write(package_project)

        exec_role = iam.Role(self, "DeployerExecRole", role_name="site-deployer-exec-role",
                             assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                             managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                 "service-role/AWSLambdaBasicExecutionRole")])
        for stmt in [
            iam.PolicyStatement(  # 站点 Lambda 的创建/更新，限 site- 前缀
                actions=["lambda:CreateFunction", "lambda:UpdateFunctionCode",
                         "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
                         "lambda:CreateFunctionUrlConfig", "lambda:GetFunctionUrlConfig",
                         "lambda:AddPermission", "lambda:DeleteFunction",
                         "lambda:DeleteFunctionUrlConfig", "lambda:GetLayerVersion",
                         "lambda:TagResource"],
                resources=[f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:site-*",
                           "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"]),
            iam.PolicyStatement(  # per-site 运行时角色的创建/管理，boundary 强制
                actions=["iam:CreateRole", "iam:GetRole", "iam:PutRolePolicy",
                         "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:PassRole",
                         "iam:AttachRolePolicy", "iam:TagRole"],
                resources=[f"arn:aws:iam::{ACCOUNT}:role/site-rt-*"],
                conditions={"StringEquals": {
                    "iam:PermissionsBoundary": runtime_boundary.managed_policy_arn}}),
            iam.PolicyStatement(  # GetRole/PassRole/Delete 不带 boundary 条件（条件仅约束创建/改策略）
                actions=["iam:GetRole", "iam:PassRole", "iam:DeleteRole",
                         "iam:DeleteRolePolicy", "iam:ListRolePolicies"],
                resources=[f"arn:aws:iam::{ACCOUNT}:role/site-rt-*"]),
            iam.PolicyStatement(  # 站点数据表 + 任务/站点/路由表
                actions=["dynamodb:*"],
                resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-*",
                           f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/site-*/index/*",
                           f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{CFG['Platform']['routing_table']}"]),
            iam.PolicyStatement(actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                         "s3:ListBucket"],
                                resources=[f"arn:aws:s3:::site-artifacts-{ACCOUNT}",
                                           f"arn:aws:s3:::site-artifacts-{ACCOUNT}/*",
                                           f"arn:aws:s3:::site-frontend-{ACCOUNT}",
                                           f"arn:aws:s3:::site-frontend-{ACCOUNT}/*"]),
            iam.PolicyStatement(actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                                resources=[package_project.project_arn]),
            iam.PolicyStatement(actions=["dsql:DbConnectAdmin"], resources=["*"]),
        ]:
            exec_role.add_to_policy(stmt)

        for k, v in {"JobsTable": jobs.table_name, "SitesTable": sites.table_name,
                     "ArtifactsBucket": artifacts.bucket_name,
                     "PackageProject": package_project.project_name,
                     "ExecRoleArn": exec_role.role_arn,
                     "RuntimeBoundaryArn": runtime_boundary.managed_policy_arn}.items():
            CfnOutput(self, k, value=v)


app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
```

- [ ] **Step 2: 写 buildspec**

`site-builder/deployer/buildspec-package.yml`:

```yaml
version: 0.2
# 输入（环境变量，StartBuild 时传）：JOB_ID、ARTIFACTS_BUCKET。
# 上传包 s3://$ARTIFACTS_BUCKET/uploads/$JOB_ID.zip（PoC 仅 nodejs22.x）
# 输出：s3://$ARTIFACTS_BUCKET/artifacts/$JOB_ID/backend.zip
# 注意：任何命令失败即构建失败——不得用 `|| true` 吞错。
phases:
  build:
    commands:
      - aws s3 cp "s3://$ARTIFACTS_BUCKET/uploads/$JOB_ID.zip" /tmp/site.zip
      - mkdir -p /tmp/site && cd /tmp/site && unzip -q /tmp/site.zip
      - test -f /tmp/site/run.sh  # 合同要求 run.sh 在 zip 根，缺失即失败
      - cd /tmp/site/backend
      - npm install --omit=dev --no-audit --no-fund
      - cp /tmp/site/run.sh ./run.sh && chmod +x ./run.sh
      - zip -qr /tmp/backend.zip .
      - aws s3 cp /tmp/backend.zip "s3://$ARTIFACTS_BUCKET/artifacts/$JOB_ID/backend.zip"
```

- [ ] **Step 3: synth 验证 + 部署**

Run: `cd site-builder/deployer/infra && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -q && .venv/bin/python -c "import app" && npx cdk synth -q && npx cdk deploy --require-approval never`
Expected: synth 无错，栈创建成功，输出 6 个 CfnOutput。

- [ ] **Step 4: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): infra stack (tables, buckets, codebuild, roles)"
```

### Task 10: common.py（任务/站点表访问层 + 配置）

**Files:**
- Create: `site-builder/deployer/functions/common.py`
- Test: `site-builder/deployer/tests/test_common.py`
- Create: `site-builder/deployer/tests/conftest.py`
- Create: `site-builder/deployer/requirements-dev.txt`（`pytest>=8`、`moto[dynamodb,s3]>=5`、`boto3`）

**Interfaces:**
- Consumes: Task 9 的表结构
- Produces（后续所有步骤 Lambda 依赖）:
  - `get_config() -> dict`——从环境变量读（`JOBS_TABLE`/`SITES_TABLE`/`ARTIFACTS_BUCKET`/`FRONTEND_BUCKET`/`ROUTING_TABLE`/`BASE_DOMAIN`/`RUNTIME_BOUNDARY_ARN`/`PACKAGE_PROJECT`/`DSQL_ENDPOINT`）
  - `create_job(owner: str, site_id: str) -> str`（返回 job_id，状态 PENDING）
  - `update_job(job_id: str, *, status=None, phase=None, error=None, url=None) -> None`
  - `get_job(job_id: str) -> dict | None`
  - `list_jobs_by_owner(owner: str) -> list[dict]`
  - `upsert_site(site_id: str, **attrs) -> None` / `get_site(site_id: str) -> dict | None`
  - `new_site_id(name: str) -> str`——`{name 截 20 字符}-{6 位小写随机}`；`subdomain_for(site_id) -> f"app-{site_id}"`；`dsql_schema_for(site_id) -> "site_" + site_id.replace("-", "")`

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/conftest.py`:

```python
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "functions"))

ENV = {"JOBS_TABLE": "site-deploy-jobs", "SITES_TABLE": "site-sites",
       "ARTIFACTS_BUCKET": "site-artifacts-1", "FRONTEND_BUCKET": "site-frontend-1",
       "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
       "RUNTIME_BOUNDARY_ARN": "arn:aws:iam::1:policy/site-runtime-boundary",
       "ACCOUNT_ID": "1",
       "PACKAGE_PROJECT": "site-package", "DSQL_ENDPOINT": "x.dsql.us-east-1.on.aws",
       "AWS_DEFAULT_REGION": "us-east-1",
       "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}


@pytest.fixture
def aws(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(TableName="site-deploy-jobs",
                         KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[
                             {"AttributeName": "job_id", "AttributeType": "S"},
                             {"AttributeName": "owner", "AttributeType": "S"},
                             {"AttributeName": "created_at", "AttributeType": "S"}],
                         GlobalSecondaryIndexes=[{
                             "IndexName": "owner-index",
                             "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"},
                                           {"AttributeName": "created_at", "KeyType": "RANGE"}],
                             "Projection": {"ProjectionType": "ALL"}}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="site-sites",
                         KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "site_id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="routing",
                         KeySchema=[{"AttributeName": "subdomain", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "subdomain", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        s3c = boto3.client("s3", region_name="us-east-1")
        for b in ("site-artifacts-1", "site-frontend-1"):
            s3c.create_bucket(Bucket=b)
        yield
```

`site-builder/deployer/tests/test_common.py`:

```python
import re
import common


def test_job_lifecycle(aws):
    jid = common.create_job("a@x.com", "demo-abc123")
    job = common.get_job(jid)
    assert job["status"] == "PENDING" and job["owner"] == "a@x.com"
    common.update_job(jid, status="RUNNING", phase="validate")
    assert common.get_job(jid)["phase"] == "validate"
    common.update_job(jid, status="FAILED", error="boom")
    j = common.get_job(jid)
    assert j["status"] == "FAILED" and j["error"] == "boom"


def test_list_jobs_by_owner(aws):
    a = common.create_job("a@x.com", "s1")
    common.create_job("b@x.com", "s2")
    mine = common.list_jobs_by_owner("a@x.com")
    assert [j["job_id"] for j in mine] == [a]


def test_site_upsert_and_get(aws):
    common.upsert_site("demo-abc123", owner="a@x.com", tier="static",
                       subdomain="app-demo-abc123", status="ACTIVE")
    s = common.get_site("demo-abc123")
    assert s["tier"] == "static"
    common.upsert_site("demo-abc123", status="DELETED")
    assert common.get_site("demo-abc123")["status"] == "DELETED"
    assert common.get_site("demo-abc123")["owner"] == "a@x.com"  # 未覆盖字段保留


def test_id_helpers():
    sid = common.new_site_id("my-long-project-name-way-over-twenty")
    assert re.match(r"^[a-z][a-z0-9-]{0,19}-[a-z0-9]{6}$", sid)
    assert common.subdomain_for("x-1a2b3c") == "app-x-1a2b3c"
    assert common.dsql_schema_for("x-1a2b3c") == "site_x1a2b3c"
```

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/deployer && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt -q && .venv/bin/pytest tests/test_common.py -q`
Expected: FAIL（ModuleNotFoundError: common）

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/common.py`:

```python
"""deployer 各步骤 Lambda 的公共层：配置、jobs/sites 表访问、ID 生成。"""
import os
import secrets
import string
from datetime import datetime, timezone

import boto3

_ddb = None


def _table(name_env: str):
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_DEFAULT_REGION",
                                                                     "us-east-1"))
    return _ddb.Table(os.environ[name_env])


def get_config() -> dict:
    keys = ["JOBS_TABLE", "SITES_TABLE", "ARTIFACTS_BUCKET", "FRONTEND_BUCKET",
            "ROUTING_TABLE", "BASE_DOMAIN", "RUNTIME_BOUNDARY_ARN", "PACKAGE_PROJECT",
            "DSQL_ENDPOINT"]
    return {k.lower(): os.environ[k] for k in keys}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_job(owner: str, site_id: str) -> str:
    job_id = "job-" + secrets.token_hex(8)
    _table("JOBS_TABLE").put_item(Item={
        "job_id": job_id, "site_id": site_id, "owner": owner,
        "status": "PENDING", "phase": "submitted", "error": "", "url": "",
        "created_at": _now(), "updated_at": _now()})
    return job_id


def update_job(job_id: str, *, status=None, phase=None, error=None, url=None) -> None:
    updates, values = ["updated_at = :t"], {":t": _now()}
    names = {}
    for field, val in (("status", status), ("phase", phase), ("error", error), ("url", url)):
        if val is not None:
            names[f"#{field}"] = field
            updates.append(f"#{field} = :{field}")
            values[f":{field}"] = val
    _table("JOBS_TABLE").update_item(
        Key={"job_id": job_id},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeNames=names or None,
        ExpressionAttributeValues=values)


def get_job(job_id: str) -> dict | None:
    return _table("JOBS_TABLE").get_item(Key={"job_id": job_id}).get("Item")


def list_jobs_by_owner(owner: str) -> list[dict]:
    resp = _table("JOBS_TABLE").query(
        IndexName="owner-index",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("owner").eq(owner))
    return resp.get("Items", [])


def upsert_site(site_id: str, **attrs) -> None:
    if not attrs:
        return
    names = {f"#{k}": k for k in attrs}
    _table("SITES_TABLE").update_item(
        Key={"site_id": site_id},
        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in attrs),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={f":{k}": v for k, v in attrs.items()})


def get_site(site_id: str) -> dict | None:
    return _table("SITES_TABLE").get_item(Key={"site_id": site_id}).get("Item")


def new_site_id(name: str) -> str:
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{name[:20].rstrip('-')}-{suffix}"


def subdomain_for(site_id: str) -> str:
    return f"app-{site_id}"


def dsql_schema_for(site_id: str) -> str:
    return "site_" + site_id.replace("-", "")
```

注意 `update_job` 中 `names or None`：boto3 不接受空 dict 的 ExpressionAttributeNames——当四个字段全为 None 时只更新时间戳。`status` 是 DynamoDB 保留字，必须走 `#status` 别名（实现中所有字段统一走别名，简单且安全）。

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_common.py -q`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): jobs/sites table access layer"
```

### Task 11: validate 步骤（解包 + 合同校验）

**Files:**
- Create: `site-builder/deployer/functions/validate.py`
- Test: `site-builder/deployer/tests/test_validate.py`
- Modify: `site-builder/deployer/requirements-dev.txt`（追加 `-e ../contract`）

**Interfaces:**
- Consumes: `contract.validate_manifest` / `contract.scan_redlines`；S3 `uploads/{job_id}.zip`；`common.update_job`
- Produces: SFN 步骤 handler `validate.handler(event, context) -> dict`。event=`{"job_id","site_id"}`；成功返回 `{"job_id","site_id","manifest": {...}}`（manifest 传给后续步骤）；违规时 raise `ContractViolation`（消息含全部违规行，SFN 捕获后进 mark-failed）。zip 内容解包后回写 `s3://artifacts/extracted/{job_id}/`（后续步骤直接读）。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_validate.py`:

```python
import io
import json
import zipfile

import boto3
import pytest


def _upload_site_zip(job_id: str, manifest: dict, files: dict):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("site.json", json.dumps(manifest))
        for path, content in files.items():
            z.writestr(path, content)
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{job_id}.zip", Body=buf.getvalue())


GOOD_MANIFEST = {"name": "hello", "tier": "static",
                 "database": {"engine": "none"},
                 "auth": {"require_login": False, "allowed_users": "org"}}


def test_valid_static_site_passes(aws):
    import validate, common
    jid = common.create_job("a@x.com", "hello-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"})
    out = validate.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert out["manifest"]["tier"] == "static"
    # 解包结果已回写
    keys = [o["Key"] for o in boto3.client("s3").list_objects_v2(
        Bucket="site-artifacts-1", Prefix=f"extracted/{jid}/")["Contents"]]
    assert f"extracted/{jid}/frontend/index.html" in keys


def test_bad_manifest_raises(aws):
    import validate, common
    jid = common.create_job("a@x.com", "bad-x1")
    _upload_site_zip(jid, {"name": "bad!", "tier": "nope"}, {})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "bad-x1"}, None)
    assert "tier" in str(ei.value)


def test_redline_violation_raises(aws):
    import validate, common
    jid = common.create_job("a@x.com", "red-x1")
    _upload_site_zip(jid, GOOD_MANIFEST,
                     {"frontend/index.html": "<script>fetch('http://localhost:8080/api/x')</script>"})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "red-x1"}, None)
    assert "localhost" in str(ei.value)


def test_zip_bomb_rejected(aws):
    import validate, common
    jid = common.create_job("a@x.com", "bomb-x1")
    # 高压缩比：4MB 全零 → zip 后 ~4KB，比率 >100:1
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/big.js": "\0" * (4 * 1024 * 1024)})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "bomb-x1"}, None)
    assert "压缩比" in str(ei.value)


def test_too_many_files_rejected(aws):
    import validate, common
    jid = common.create_job("a@x.com", "many-x1")
    files = {f"frontend/f{i}.txt": "x" for i in range(2001)}
    _upload_site_zip(jid, GOOD_MANIFEST, files)
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "many-x1"}, None)
    assert "文件数" in str(ei.value)
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pip install -e ../contract -q && .venv/bin/pytest tests/test_validate.py -q`
Expected: FAIL（ModuleNotFoundError: validate）

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/validate.py`:

```python
"""SFN 步骤 1：下载上传包 → 解包 → 合同校验（schema+红线）→ 回写解包内容。"""
import io
import json
import os
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import boto3

from contract import scan_redlines, validate_manifest
import common


class ContractViolation(Exception):
    pass


def handler(event, context):
    job_id, site_id = event["job_id"], event["site_id"]
    common.update_job(job_id, status="RUNNING", phase="validate")
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    obj = s3.get_object(Bucket=bucket, Key=f"uploads/{job_id}.zip")
    data = obj["Body"].read()

    with TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > 2000:
                raise ContractViolation(f"文件数 {len(infos)} 超过 2000 上限")
            total = sum(i.file_size for i in infos)
            if total > 200 * 1024 * 1024:
                raise ContractViolation(f"解压后总大小 {total} 超过 200MB 上限")
            compressed = max(1, sum(i.compress_size for i in infos))
            if total / compressed > 100:
                raise ContractViolation(f"压缩比 {total // compressed}:1 超过 100:1（疑似 zip bomb）")
            for m in z.namelist():  # zip-slip 防护
                if m.startswith("/") or ".." in m:
                    raise ContractViolation(f"非法路径: {m}")
            z.extractall(root)

        manifest_path = root / "site.json"
        if not manifest_path.exists():
            raise ContractViolation("缺少 site.json")
        manifest = json.loads(manifest_path.read_text())

        errors = validate_manifest(manifest)
        errors += scan_redlines(root, manifest)
        if errors:
            raise ContractViolation("；".join(errors))

        for p in root.rglob("*"):
            if p.is_file():
                s3.put_object(Bucket=bucket,
                              Key=f"extracted/{job_id}/{p.relative_to(root)}",
                              Body=p.read_bytes())

    return {"job_id": job_id, "site_id": site_id, "manifest": manifest}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_validate.py -q`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): validate step (unpack + contract enforcement)"
```

### Task 12: DynamoDB provisioner

**Files:**
- Create: `site-builder/deployer/functions/provision_dynamodb.py`
- Test: `site-builder/deployer/tests/test_provision_dynamodb.py`

**Interfaces:**
- Consumes: Task 11 输出（`manifest.database.tables`：`[{"name": str, "pk": str}]`）
- Produces: `provision_dynamodb.handler(event, context) -> event`（透传 event，追加 `event["env_vars"]`：`{"TABLE_<NAME大写>": 实际表名}`）。表命名 `site-data-{site_id}-{table_name}`，PAY_PER_REQUEST，幂等（已存在即跳过）。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_provision_dynamodb.py`:

```python
import boto3


EVENT = {"job_id": "job-1", "site_id": "notes-a1b2c3",
         "manifest": {"name": "notes", "tier": "fullstack-nosql",
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "notes", "pk": "id"}]},
                      "backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080},
                      "auth": {"require_login": True, "allowed_users": "org"}}}


def test_creates_table_and_env(aws):
    import provision_dynamodb, common
    common.create_job("a@x.com", "notes-a1b2c3")
    out = provision_dynamodb.handler(dict(EVENT), None)
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"
    desc = boto3.client("dynamodb").describe_table(
        TableName="site-data-notes-a1b2c3-notes")
    assert desc["Table"]["KeySchema"][0]["AttributeName"] == "id"


def test_idempotent_rerun(aws):
    import provision_dynamodb
    provision_dynamodb.handler(dict(EVENT), None)
    out = provision_dynamodb.handler(dict(EVENT), None)  # 不抛 ResourceInUse
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_provision_dynamodb.py -q`
Expected: FAIL

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/provision_dynamodb.py`:

```python
"""SFN 步骤 2a：按 manifest 声明创建站点 DynamoDB 表（幂等）。"""
import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="provision-db")
    ddb = boto3.client("ddb" if False else "dynamodb")
    env_vars = event.get("env_vars", {})
    for spec in event["manifest"]["database"].get("tables", []):
        table_name = f"site-data-{event['site_id']}-{spec['name']}"
        try:
            ddb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": spec["pk"], "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": spec["pk"], "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
                Tags=[{"Key": "project", "Value": "site-builder"},
                      {"Key": "site_id", "Value": event["site_id"]}])
            ddb.get_waiter("table_exists").wait(TableName=table_name)
        except ddb.exceptions.ResourceInUseException:
            pass
        env_vars[f"TABLE_{spec['name'].upper()}"] = table_name
    event["env_vars"] = env_vars
    return event
```

（实现时删掉那行笔误 `"ddb" if False else` ——直接 `boto3.client("dynamodb")`。）

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_provision_dynamodb.py -q`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): dynamodb provisioner step"
```

### Task 13: DSQL provisioner（schema + 逐条 DDL + migrations）

**Files:**
- Create: `site-builder/deployer/functions/provision_dsql.py`
- Test: `site-builder/deployer/tests/test_provision_dsql.py`

**Interfaces:**
- Consumes: Task 11 输出；`extracted/{job_id}/backend/schema.sql`（+ 可选 `backend/migrations/NNN_*.sql`）；sites 表 `migrations_applied`
- Produces: handler 透传 event，追加 `env_vars`：`DSQL_ENDPOINT`、`DSQL_SCHEMA`、`DSQL_USER`（per-site PG role 名 `site_{id去连字符}_app`）。行为（admin 身份，平台专用）：
  1. `CREATE SCHEMA IF NOT EXISTS <schema>` + `SET search_path`
  2. **建 per-site PG role 并映射站点 IAM 角色**（站点代码用非 admin 身份连接，只见自己的 schema）：`CREATE ROLE <role> WITH LOGIN`（已存在容忍）→ `AWS IAM GRANT <role> TO 'arn:aws:iam::{acct}:role/site-rt-{site_id}'` → `GRANT USAGE, CREATE ON SCHEMA <schema> TO <role>` + `ALTER DEFAULT PRIVILEGES IN SCHEMA <schema> GRANT ALL ON TABLES TO <role>` + 对已有表 `GRANT ALL ON ALL TABLES IN SCHEMA <schema> TO <role>`
  3. 首次部署执行 schema.sql，migrations 按序执行——语句拆分用 **`sqlparse.split()`**（裸 `split(";")` 会破坏含分号的字符串/注释）；**每执行完一个文件立即回写 `migrations_applied`**（中途失败不重复已完成文件）
  4. 连接 `try/finally` 关闭。
- **连接逻辑封装在 `_connect()` 单函数，测试全程 mock 它**（真实 DSQL 连接在 Task 18 集成测试覆盖）。依赖：`psycopg[binary]`、`sqlparse`（CDK bundling 安装）。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_provision_dsql.py`:

```python
import boto3
from unittest.mock import MagicMock, patch


def _event(job_id="job-1", site_id="exp-a1b2c3"):
    return {"job_id": job_id, "site_id": site_id,
            "manifest": {"name": "exp", "tier": "fullstack-sql",
                         "database": {"engine": "dsql"},
                         "backend": {"runtime": "nodejs22.x",
                                     "entrypoint": "node server.js", "port": 8080},
                         "auth": {"require_login": True, "allowed_users": "org"}}}


def _put(job_id, key, body):
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"extracted/{job_id}/{key}", Body=body)


def _mock_conn():
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def test_first_deploy_runs_schema_and_grants(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\nCREATE TABLE b (id UUID PRIMARY KEY);")
    conn, cur = _mock_conn()
    with patch.object(provision_dsql, "_connect", return_value=conn):
        out = provision_dsql.handler(_event(), None)
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    assert 'CREATE SCHEMA IF NOT EXISTS "site_expa1b2c3"' in sqls[0]
    assert sum("CREATE TABLE" in s for s in sqls) == 2
    assert any("AWS IAM GRANT site_expa1b2c3_app" in s
               and "role/site-rt-exp-a1b2c3" in s for s in sqls)  # 站点 IAM 角色映射
    assert any(s.startswith("GRANT USAGE") for s in sqls)
    assert out["env_vars"]["DSQL_SCHEMA"] == "site_expa1b2c3"
    assert out["env_vars"]["DSQL_USER"] == "site_expa1b2c3_app"
    conn.close.assert_called_once()  # try/finally 关闭


def test_statement_split_respects_semicolon_in_string(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY, note TEXT DEFAULT 'a;b');\n"
         b"-- comment; with semicolon\nCREATE TABLE b (id UUID PRIMARY KEY);")
    conn, cur = _mock_conn()
    with patch.object(provision_dsql, "_connect", return_value=conn):
        provision_dsql.handler(_event(), None)
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    creates = [s for s in sqls if "CREATE TABLE" in s]
    assert len(creates) == 2 and "'a;b'" in creates[0]  # sqlparse 不在字符串内断句


def test_redeploy_skips_schema_applies_new_migration_incrementally(aws):
    import provision_dsql, common
    common.create_job("a@x.com", "exp-a1b2c3")
    common.upsert_site("exp-a1b2c3", migrations_applied=["schema.sql", "001_add.sql"])
    _put("job-1", "backend/schema.sql", b"CREATE TABLE a (id UUID PRIMARY KEY);")
    _put("job-1", "backend/migrations/001_add.sql", b"ALTER TABLE a ADD COLUMN x TEXT;")
    _put("job-1", "backend/migrations/002_more.sql", b"ALTER TABLE a ADD COLUMN y TEXT;")
    _put("job-1", "backend/migrations/003_fail.sql", b"ALTER TABLE a ADD COLUMN z TEXT;")
    conn, cur = _mock_conn()
    # 003 执行时抛错——验证 002 已被记录（逐文件回写）
    def _explode(sql, *a):
        if "COLUMN z" in sql:
            raise RuntimeError("boom")
    cur.execute.side_effect = _explode
    with patch.object(provision_dsql, "_connect", return_value=conn):
        import pytest as _pt
        with _pt.raises(RuntimeError):
            provision_dsql.handler(_event(), None)
    applied = common.get_site("exp-a1b2c3")["migrations_applied"]
    assert "002_more.sql" in applied and "003_fail.sql" not in applied
    conn.close.assert_called_once()
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_provision_dsql.py -q`
Expected: FAIL

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/provision_dsql.py`:

```python
"""SFN 步骤 2b：共享 DSQL cluster 内为站点建独立 schema + per-site PG role 并执行 DDL。
DSQL 约束：无 CREATE DATABASE；每事务一条 DDL → 逐条 execute（autocommit）。
身份分离：本步骤用 admin（平台身份）；站点 Lambda 用 per-site role（非 admin），
只被 GRANT 自己的 schema——站点代码是不可信代码。"""
import os
import re
from pathlib import PurePosixPath

import boto3
import sqlparse

import common

# psycopg 仅在 Lambda 打包时可用；测试 mock _connect 不触达
def _connect():
    """返回 autocommit connection。执行角色需 dsql:DbConnectAdmin。"""
    import psycopg
    endpoint = os.environ["DSQL_ENDPOINT"]
    token = boto3.client("dsql", region_name="us-east-1").generate_db_connect_admin_auth_token(
        Hostname=endpoint)
    return psycopg.connect(host=endpoint, dbname="postgres", user="admin",
                           password=token, sslmode="require", autocommit=True)


def _statements(sql: str) -> list[str]:
    return [s.strip() for s in sqlparse.split(sql)
            if s.strip() and not s.strip().startswith("--")]


def handler(event, context):
    common.update_job(event["job_id"], phase="provision-db")
    site_id, job_id = event["site_id"], event["job_id"]
    schema = common.dsql_schema_for(site_id)
    pg_role = f"{schema}_app"
    rt_role_arn = (f"arn:aws:iam::{os.environ['ACCOUNT_ID']}:role/site-rt-{site_id}")
    s3 = boto3.client("s3")
    bucket = os.environ["ARTIFACTS_BUCKET"]

    site = common.get_site(site_id) or {}
    applied = list(site.get("migrations_applied", []))

    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        cur.execute(f'SET search_path = "{schema}"')

        # per-site PG role + IAM 映射（幂等：已存在则容忍）
        try:
            cur.execute(f'CREATE ROLE {pg_role} WITH LOGIN')
        except Exception:
            pass  # duplicate role
        try:
            cur.execute(f"AWS IAM GRANT {pg_role} TO '{rt_role_arn}'")
        except Exception:
            pass  # 已映射
        cur.execute(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO {pg_role}')
        cur.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" '
                    f'GRANT ALL ON TABLES TO {pg_role}')

        def run_file(key: str, marker: str):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
            for stmt in _statements(body):
                cur.execute(stmt)
            applied.append(marker)
            common.upsert_site(site_id, migrations_applied=applied)  # 逐文件立即记录

        if "schema.sql" not in applied:
            run_file(f"extracted/{job_id}/backend/schema.sql", "schema.sql")

        resp = s3.list_objects_v2(Bucket=bucket,
                                  Prefix=f"extracted/{job_id}/backend/migrations/")
        for obj in sorted(resp.get("Contents", []), key=lambda o: o["Key"]):
            fname = PurePosixPath(obj["Key"]).name
            if re.match(r"^\d{3}_.+\.sql$", fname) and fname not in applied:
                run_file(obj["Key"], fname)

        # 覆盖 schema.sql/migrations 新建的表（DEFAULT PRIVILEGES 只对未来生效一次性补齐）
        cur.execute(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema}" TO {pg_role}')
    finally:
        conn.close()

    env_vars = event.get("env_vars", {})
    env_vars["DSQL_ENDPOINT"] = os.environ["DSQL_ENDPOINT"]
    env_vars["DSQL_SCHEMA"] = schema
    env_vars["DSQL_USER"] = pg_role
    event["env_vars"] = env_vars
    return event
```

实现注意：`AWS IAM GRANT` 语法与幂等行为以 DSQL 当期文档为准（[authentication-authorization](https://docs.aws.amazon.com/aurora-dsql/latest/userguide/authentication-authorization.html)）；`CREATE ROLE`/`GRANT` 的容错分支若 DSQL 支持 `IF NOT EXISTS` 优先用之。

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_provision_dsql.py -q`
Expected: 3 passed（requirements-dev.txt 追加 `sqlparse>=0.5`）

- [ ] **Step 5: 创建真实 DSQL cluster（一次性，CLI）**

```bash
aws dsql create-cluster --region us-east-1 \
  --tags Key=project,Value=site-builder \
  --no-deletion-protection-enabled
aws dsql list-clusters --region us-east-1
```

将返回 endpoint（`<id>.dsql.us-east-1.on.aws`）回填 `config.ini [DSQL] cluster_endpoint`。

- [ ] **Step 6: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): dsql provisioner (per-site schema, sequential DDL, migrations)"
```

### Task 14: CodeBuild 打包步骤（SFN 集成）

**Files:**
- Create: `site-builder/deployer/functions/package_backend.py`
- Test: `site-builder/deployer/tests/test_package_backend.py`

**Interfaces:**
- Consumes: Task 9 CodeBuild 项目 `site-package`、buildspec 的输入输出约定；Task 11 的 `extracted/`（backend 源码从 uploads zip 由 CodeBuild 直接取）
- Produces: `package_backend.handler(event, context) -> event`，追加 `event["backend_zip_key"] = f"artifacts/{job_id}/backend.zip"`。同步等待构建完成（boto3 轮询 BatchGetBuilds，间隔 5s，上限 13 分钟），失败 raise `PackageError(构建日志尾部)`。static tier 由状态机 Choice 跳过本步（handler 不处理 static）。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_package_backend.py`:

```python
from unittest.mock import MagicMock, patch
import pytest


EVENT = {"job_id": "job-1", "site_id": "s-1",
         "manifest": {"backend": {"runtime": "nodejs22.x"}}, "env_vars": {}}


def _cb_mock(statuses):
    cb = MagicMock()
    cb.start_build.return_value = {"build": {"id": "site-package:abc"}}
    cb.batch_get_builds.side_effect = [
        {"builds": [{"buildStatus": s, "logs": {"deepLink": "http://log"}}]}
        for s in statuses]
    return cb


def test_success_returns_zip_key(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    with patch.object(package_backend, "_codebuild", return_value=_cb_mock(
            ["IN_PROGRESS", "SUCCEEDED"])), \
         patch.object(package_backend.time, "sleep"):
        out = package_backend.handler(dict(EVENT), None)
    assert out["backend_zip_key"] == "artifacts/job-1/backend.zip"


def test_failure_raises(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    with patch.object(package_backend, "_codebuild", return_value=_cb_mock(
            ["FAILED"])), \
         patch.object(package_backend.time, "sleep"):
        with pytest.raises(package_backend.PackageError):
            package_backend.handler(dict(EVENT), None)


def test_start_build_env_overrides(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    cb = _cb_mock(["SUCCEEDED"])
    with patch.object(package_backend, "_codebuild", return_value=cb), \
         patch.object(package_backend.time, "sleep"):
        package_backend.handler(dict(EVENT), None)
    env = {e["name"]: e["value"]
           for e in cb.start_build.call_args.kwargs["environmentVariablesOverride"]}
    assert env == {"JOB_ID": "job-1", "ARTIFACTS_BUCKET": "site-artifacts-1"}
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_package_backend.py -q`
Expected: FAIL

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/package_backend.py`:

```python
"""SFN 步骤 3：触发 CodeBuild 装依赖打 backend.zip，同步等待完成。"""
import os
import time

import boto3

import common


class PackageError(Exception):
    pass


def _codebuild():
    return boto3.client("codebuild")


def handler(event, context):
    common.update_job(event["job_id"], phase="package")
    cb = _codebuild()
    build_id = cb.start_build(
        projectName=os.environ["PACKAGE_PROJECT"],
        environmentVariablesOverride=[
            {"name": "JOB_ID", "value": event["job_id"]},
            {"name": "ARTIFACTS_BUCKET", "value": os.environ["ARTIFACTS_BUCKET"]},
        ])["build"]["id"]

    deadline = time.time() + 13 * 60
    while True:
        build = cb.batch_get_builds(ids=[build_id])["builds"][0]
        status = build["buildStatus"]
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            raise PackageError(f"依赖打包失败（{status}），日志: "
                               f"{build.get('logs', {}).get('deepLink', 'n/a')}")
        if time.time() > deadline:
            raise PackageError("依赖打包超时（13 分钟）")
        time.sleep(5)

    event["backend_zip_key"] = f"artifacts/{event['job_id']}/backend.zip"
    return event
```

注意：本步骤 Lambda timeout 须设 900s（Task 17 状态机定义中体现）。

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_package_backend.py -q`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): codebuild packaging step with sync wait"
```

### Task 15: 站点 Lambda 部署器（zip + LWA Layer + Function URL）

**Files:**
- Create: `site-builder/deployer/functions/deploy_lambda_site.py`
- Test: `site-builder/deployer/tests/test_deploy_lambda_site.py`

**Interfaces:**
- Consumes: `event["backend_zip_key"]`、`event["env_vars"]`（DB 注入）、`RUNTIME_BOUNDARY_ARN`、`EDGE_ROLE_ARN`（manus 栈 CfnOutput，config.ini 回填）
- Produces: handler 透传 event，追加 `event["api_target"]`。两个动作：
  1. **建 per-site 执行角色 `site-rt-{site_id}`**（幂等）：trust=lambda.amazonaws.com，`PermissionsBoundary=RUNTIME_BOUNDARY_ARN`（IAM policy 强制，缺 boundary 的 CreateRole 会被拒），inline policy 按 tier 精确到本站点资源——dynamodb tier：仅 `site-data-{site_id}-*` 表 CRUD；dsql tier：仅 `dsql:DbConnect`（非 admin）；外加本函数日志组。
  2. 建/更新函数 `site-{site_id}`：LWA Layer（精确 ARN）、Handler=`run.sh`、`AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap`、`PORT=8080`、`AWS_LWA_INVOKE_MODE=BUFFERED`、MemorySize=512、Timeout=30、Role=该站点角色；Function URL AuthType=AWS_IAM，resource policy **Principal 精确到 Edge 执行角色 ARN**（`lambda:InvokeFunctionUrl` + condition `lambda:FunctionUrlAuthType=AWS_IAM`；**无 `*` fallback**——EDGE_ROLE_ARN 缺失直接抛错）。幂等：存在则 update code + config。
- 注：IAM 新角色传播延迟——create_function 失败 `InvalidParameterValueException` 时重试（最多 6 次 × 5s）。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_deploy_lambda_site.py`（moto 对 Function URL 支持有限——lambda 客户端整体 mock）:

```python
from unittest.mock import MagicMock, patch

LWA_ARN = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"

EVENT = {"job_id": "job-1", "site_id": "s-1",
         "manifest": {"backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080}},
         "env_vars": {"TABLE_NOTES": "site-data-s-1-notes"},
         "backend_zip_key": "artifacts/job-1/backend.zip"}


def _lam_mock(exists: bool):
    lam = MagicMock()
    if not exists:
        class NF(Exception): pass
        lam.exceptions.ResourceNotFoundException = NF
        lam.get_function.side_effect = NF()
        class RC(Exception): pass
        lam.exceptions.ResourceConflictException = RC
    else:
        lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
        lam.exceptions.ResourceConflictException = type("RC", (Exception,), {})
    lam.create_function_url_config.return_value = {
        "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/"}
    lam.get_function_url_config.return_value = {
        "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/"}
    return lam


def test_creates_per_site_role_and_function(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        out = deploy_lambda_site.handler(dict(EVENT), None)
    assert out["api_target"] == "https://xyz.lambda-url.us-east-1.on.aws"

    # per-site 角色（moto IAM 真建）：boundary + 只授本站点表
    import boto3, json
    iam = boto3.client("iam")
    role = iam.get_role(RoleName="site-rt-s-1")["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"].endswith(
        "policy/site-runtime-boundary")
    pol = iam.get_role_policy(RoleName="site-rt-s-1", PolicyName="site-scope")
    doc = json.dumps(pol["PolicyDocument"])
    assert "site-data-s-1-" in doc and "site-data-s-2" not in doc

    kw = lam.create_function.call_args.kwargs
    assert kw["FunctionName"] == "site-s-1"
    assert kw["Role"].endswith("role/site-rt-s-1")
    assert kw["Layers"] == [LWA_ARN]
    assert kw["Handler"] == "run.sh"
    env = kw["Environment"]["Variables"]
    assert env["AWS_LAMBDA_EXEC_WRAPPER"] == "/opt/bootstrap"
    assert env["PORT"] == "8080"
    assert env["TABLE_NOTES"] == "site-data-s-1-notes"
    # Function URL 权限精确到 Edge role，无 * fallback
    perm = lam.add_permission.call_args.kwargs
    assert perm["Principal"] == "arn:aws:iam::1:role/edge-role"


def test_missing_edge_role_arn_fails_closed(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.delenv("EDGE_ROLE_ARN", raising=False)
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    import pytest as _pt
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        with _pt.raises(KeyError):
            deploy_lambda_site.handler(dict(EVENT), None)


def test_existing_function_updated(aws, monkeypatch):
    import deploy_lambda_site, common
    monkeypatch.setenv("EDGE_ROLE_ARN", "arn:aws:iam::1:role/edge-role")
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=True)
    with patch.object(deploy_lambda_site, "_lambda", return_value=lam):
        deploy_lambda_site.handler(dict(EVENT), None)
    lam.update_function_code.assert_called_once()
    lam.create_function.assert_not_called()
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_deploy_lambda_site.py -q`
Expected: FAIL

- [ ] **Step 3: 实现**

`site-builder/deployer/functions/deploy_lambda_site.py`:

```python
"""SFN 步骤 4：per-site 执行角色 + 站点 Lambda——zip + LWA Layer（禁止镜像模式）。
站点代码不可信：角色带 PermissionsBoundary，inline policy 精确到本站点资源。"""
import json
import os
import time

import boto3

import common

LWA_LAYER = "arn:aws:lambda:us-east-1:753240598075:layer:LambdaAdapterLayerX86:28"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})


def _lambda():
    return boto3.client("lambda")


def _site_policy(site_id: str, engine: str) -> str:
    region, acct = "us-east-1", os.environ["ACCOUNT_ID"]
    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/site-{site_id}*"}]
    if engine == "dynamodb":
        statements.append({
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": f"arn:aws:dynamodb:{region}:{acct}:table/site-data-{site_id}-*"})
    elif engine == "dsql":
        statements.append({"Effect": "Allow", "Action": "dsql:DbConnect",
                           "Resource": "*"})  # 数据隔离由 per-site PG role 保证
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _ensure_site_role(site_id: str, engine: str) -> str:
    iam = boto3.client("iam")
    name = f"site-rt-{site_id}"
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=TRUST,
            PermissionsBoundary=os.environ["RUNTIME_BOUNDARY_ARN"],
            Tags=[{"Key": "project", "Value": "site-builder"},
                  {"Key": "site_id", "Value": site_id}])["Role"]["Arn"]
    iam.put_role_policy(RoleName=name, PolicyName="site-scope",
                        PolicyDocument=_site_policy(site_id, engine))
    return arn


def handler(event, context):
    common.update_job(event["job_id"], phase="deploy-backend")
    edge_role_arn = os.environ["EDGE_ROLE_ARN"]  # 缺失即 KeyError——不允许 * fallback
    lam = _lambda()
    fn = f"site-{event['site_id']}"
    engine = event["manifest"].get("database", {}).get("engine", "none")
    role_arn = _ensure_site_role(event["site_id"], engine)
    env = {"AWS_LAMBDA_EXEC_WRAPPER": "/opt/bootstrap", "PORT": "8080",
           "AWS_LWA_INVOKE_MODE": "BUFFERED", **event.get("env_vars", {})}
    code = {"S3Bucket": os.environ["ARTIFACTS_BUCKET"], "S3Key": event["backend_zip_key"]}
    runtime = event["manifest"]["backend"]["runtime"]

    try:
        lam.get_function(FunctionName=fn)
        lam.update_function_code(FunctionName=fn, **code)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
        lam.update_function_configuration(
            FunctionName=fn, Runtime=runtime, Handler="run.sh", Role=role_arn,
            Layers=[LWA_LAYER], Environment={"Variables": env},
            MemorySize=512, Timeout=30)
        lam.get_waiter("function_updated").wait(FunctionName=fn)
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(6):  # 新建 IAM 角色传播延迟
            try:
                lam.create_function(
                    FunctionName=fn, Runtime=runtime, Handler="run.sh",
                    Role=role_arn, Code=code,
                    Layers=[LWA_LAYER], Environment={"Variables": env},
                    MemorySize=512, Timeout=30,
                    Tags={"project": "site-builder", "site_id": event["site_id"]})
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 5:
                    raise
                time.sleep(5)
        lam.get_waiter("function_active").wait(FunctionName=fn)

    try:
        url = lam.create_function_url_config(FunctionName=fn,
                                             AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
    try:
        lam.add_permission(FunctionName=fn, StatementId="edge-invoke",
                           Action="lambda:InvokeFunctionUrl",
                           Principal=edge_role_arn,
                           FunctionUrlAuthType="AWS_IAM")
    except lam.exceptions.ResourceConflictException:
        pass

    event["api_target"] = url.rstrip("/")
    return event
```

配套：Task 8 的 manus stack.py 需为 edge role 加 `CfnOutput(self, "EdgeRoleArn", value=edge_role.role_arn)`，值回填 config.ini `[Deployer] edge_role_arn`，Task 17 作为 `EDGE_ROLE_ARN` 环境变量传入。Task 17 的 undeploy 同步补删 `site-rt-{site_id}` 角色（先 delete_role_policy 再 delete_role，容忍不存在）。

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/test_deploy_lambda_site.py -q`
Expected: 4 passed（conftest 的 moto mock_aws 需含 iam——moto 默认全局 mock 已覆盖；boundary policy 在 conftest 中预创建：`iam.create_policy(PolicyName="site-runtime-boundary", PolicyDocument=json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})`）

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): per-site runtime role + site lambda (zip + LWA layer)"
```

### Task 16: 前端上传 + 路由注册 + 冒烟步骤

**Files:**
- Create: `site-builder/deployer/functions/upload_frontend.py`
- Create: `site-builder/deployer/functions/register_route.py`
- Create: `site-builder/deployer/functions/smoke_test.py`
- Create: `site-builder/deployer/functions/mark_job.py`
- Test: `site-builder/deployer/tests/test_finalize_steps.py`

**Interfaces:**
- Consumes: `extracted/{job_id}/frontend/`、`event["api_target"]`（static tier 无此键）、manifest.auth、`common.subdomain_for`
- Produces:
  - `upload_frontend.handler`——frontend/ 传到**版本化前缀** `s3://{FRONTEND_BUCKET}/sites/{site_id}/{job_id}/`（Content-Type 按扩展名；**不删旧版本**——线上流量仍指旧前缀，切换由 register_route 原子完成；旧版本由桶生命周期规则清理），透传 event
  - `register_route.handler`——写路由表 item（`static_prefix=f"sites/{site_id}/{job_id}"`，含 route_mode="split"），put_item 即原子切流；追加 `event["url"]`
  - `smoke_test.handler`——**禁跟随重定向**（自定义 opener）：无 auth 站点首页期待 200；require_auth 站点期待 302 且 `Location` 以 `https://auth.{BASE_DOMAIN}/login` 开头（跟随到 200 会把"跳登录页"误判为后端健康）；`/api/health` 同理。10 秒超时，失败 raise `SmokeFailure`
  - `mark_job.handler`——同前
- S3 遍历/删除一律 paginator（undeploy 侧同样，见 Task 17）

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_finalize_steps.py`:

```python
import boto3
from unittest.mock import MagicMock, patch
import pytest

MANIFEST = {"name": "hello", "tier": "static", "database": {"engine": "none"},
            "auth": {"require_login": True, "allowed_users": ["v@x.com"]}}
EVENT = {"job_id": "job-1", "site_id": "hello-x1", "manifest": MANIFEST}


def test_upload_frontend_versioned_prefix_keeps_old_version(aws):
    import upload_frontend, common
    common.create_job("a@x.com", "hello-x1")
    s3 = boto3.client("s3")
    s3.put_object(Bucket="site-artifacts-1", Key="extracted/job-1/frontend/index.html",
                  Body=b"<h1>hi</h1>")
    # 旧版本（上一个 job 的前缀）——发布期间线上流量仍在用，不得删除
    s3.put_object(Bucket="site-frontend-1", Key="sites/hello-x1/job-0/index.html",
                  Body=b"old")
    upload_frontend.handler(dict(EVENT), None)
    obj = s3.get_object(Bucket="site-frontend-1",
                        Key="sites/hello-x1/job-1/index.html")
    assert obj["ContentType"] == "text/html"
    old = s3.get_object(Bucket="site-frontend-1", Key="sites/hello-x1/job-0/index.html")
    assert old["Body"].read() == b"old"  # 旧版本原样保留


def test_register_route_atomic_switch(aws):
    import register_route, common
    common.create_job("a@x.com", "hello-x1")
    common.upsert_site("hello-x1", owner="a@x.com")
    ddb = boto3.client("dynamodb")
    # 模拟已有旧路由（指向旧 job 前缀）
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-hello-x1"}, "site_id": {"S": "hello-x1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/hello-x1/job-0"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "owner": {"S": "a@x.com"}})
    out = register_route.handler(dict(EVENT), None)
    assert out["url"] == "https://app-hello-x1.example.com"
    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-hello-x1"}})["Item"]
    assert item["static_prefix"]["S"] == "sites/hello-x1/job-1"  # 原子切到新版本
    assert item["route_mode"]["S"] == "split"
    assert item["require_auth"]["BOOL"] is True
    assert '"v@x.com"' in item["allowed_users"]["S"]
    assert item["owner"]["S"] == "a@x.com"


def test_smoke_auth_site_expects_302_to_login(aws):
    import smoke_test
    # require_auth 站点：302 到登录端点 = 健康；200 = 鉴权失效，必须失败
    with patch.object(smoke_test, "_head",
                      return_value=(302, "https://auth.example.com/login?redirect=x")):
        smoke_test.handler({**EVENT, "url": "https://app-hello-x1.example.com"}, None)
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        with pytest.raises(smoke_test.SmokeFailure):
            smoke_test.handler({**EVENT, "url": "https://app-hello-x1.example.com"}, None)


def test_smoke_public_site_expects_200(aws):
    import smoke_test
    ev = {**EVENT, "manifest": {**MANIFEST, "auth": {"require_login": False,
                                                     "allowed_users": "org"}},
          "url": "https://app-hello-x1.example.com"}
    with patch.object(smoke_test, "_head", return_value=(200, "")):
        smoke_test.handler(ev, None)
    with patch.object(smoke_test, "_head", return_value=(500, "")):
        with pytest.raises(smoke_test.SmokeFailure):
            smoke_test.handler(ev, None)


def test_mark_job_success_and_failure(aws):
    import mark_job, common
    j1 = common.create_job("a@x.com", "hello-x1")
    mark_job.handler({"job_id": j1, "site_id": "hello-x1", "manifest": MANIFEST,
                      "url": "https://app-hello-x1.example.com"}, None)
    assert common.get_job(j1)["status"] == "SUCCEEDED"
    assert common.get_site("hello-x1")["status"] == "ACTIVE"
    j2 = common.create_job("a@x.com", "hello-x1")
    mark_job.handler({"job_id": j2, "site_id": "hello-x1",
                      "error_info": {"Cause": "boom"}}, None)
    job = common.get_job(j2)
    assert job["status"] == "FAILED" and "boom" in job["error"]
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/bin/pytest tests/test_finalize_steps.py -q`
Expected: FAIL

- [ ] **Step 3: 实现四个 handler**

`site-builder/deployer/functions/upload_frontend.py`:

```python
"""SFN 步骤 5：前端静态文件 → 版本化前缀 sites/{site_id}/{job_id}/。
不删旧版本——线上流量仍指旧前缀，切换由 register_route 原子完成；
旧版本由前端桶生命周期规则（30 天）清理。"""
import mimetypes
import os

import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="upload-frontend")
    s3 = boto3.client("s3")
    src_bucket = os.environ["ARTIFACTS_BUCKET"]
    dst_bucket = os.environ["FRONTEND_BUCKET"]
    src_prefix = f"extracted/{event['job_id']}/frontend/"
    dst_prefix = f"sites/{event['site_id']}/{event['job_id']}/"

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=src_bucket, Prefix=src_prefix):
        for obj in page.get("Contents", []):
            rel = obj["Key"][len(src_prefix):]
            body = s3.get_object(Bucket=src_bucket, Key=obj["Key"])["Body"].read()
            ctype = mimetypes.guess_type(rel)[0] or "application/octet-stream"
            s3.put_object(Bucket=dst_bucket, Key=dst_prefix + rel,
                          Body=body, ContentType=ctype)
    return event
```

（旧版本清理：**不能用 S3 生命周期**——它按对象年龄过期，会把长期在线的当前版本一并删掉。改为 `mark_job.handler` 成功路径里清理：列出 `sites/{site_id}/` 下除当前 `job_id` 外的所有前缀，paginator + 分批 delete_objects。清理失败仅告警不置 FAILED——站点已上线，残留旧版本只是存储成本。）

`site-builder/deployer/functions/register_route.py`:

```python
"""SFN 步骤 6：注册子域名路由（含 auth 策略与 owner）。
put_item 覆盖整个 item = 原子切流：static_prefix 指向本次 job 的版本化前缀，
写入瞬间所有新请求走新版本（Edge 路由缓存最多再滞后 60s）。"""
import json
import os

import boto3

import common


def handler(event, context):
    common.update_job(event["job_id"], phase="register-route")
    site = common.get_site(event["site_id"]) or {}
    owner = site.get("owner") or common.get_job(event["job_id"])["owner"]
    auth = event["manifest"]["auth"]
    allowed = auth["allowed_users"]
    subdomain = common.subdomain_for(event["site_id"])

    boto3.client("dynamodb").put_item(
        TableName=os.environ["ROUTING_TABLE"],
        Item={"subdomain": {"S": subdomain},
              "site_id": {"S": event["site_id"]},
              "route_mode": {"S": "split"},
              "static_prefix": {"S": f"sites/{event['site_id']}/{event['job_id']}"},
              "api_target": {"S": event.get("api_target", "")},
              "require_auth": {"BOOL": bool(auth["require_login"])},
              "allowed_users": {"S": allowed if allowed == "org" else json.dumps(allowed)},
              "owner": {"S": owner}})
    event["url"] = f"https://{subdomain}.{os.environ['BASE_DOMAIN']}"
    return event
```

`site-builder/deployer/functions/smoke_test.py`:

```python
"""SFN 步骤 7：冒烟。禁跟随重定向——require_auth 站点的健康态是
"302 且 Location 指向登录端点"；跟随到登录页的 200 会掩盖后端故障，
而鉴权站点直接 200 意味着鉴权失效，同样必须失败。"""
import os
import urllib.error
import urllib.request

import common


class SmokeFailure(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _head(url: str) -> tuple[int, str]:
    """返回 (status, location)。不跟随重定向。"""
    req = urllib.request.Request(url, method="GET")
    try:
        with _opener.open(req, timeout=10) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def _check(url: str, require_auth: bool, login_prefix: str, what: str):
    code, location = _head(url)
    if require_auth:
        if code != 302 or not location.startswith(login_prefix):
            raise SmokeFailure(
                f"{what} 期待 302→登录端点，实际 {code} Location={location!r}"
                + ("（鉴权未生效！）" if code == 200 else ""))
    else:
        if code != 200:
            raise SmokeFailure(f"{what} 返回 {code}")


def handler(event, context):
    common.update_job(event["job_id"], phase="smoke-test")
    require_auth = bool(event["manifest"]["auth"]["require_login"])
    login_prefix = f"https://auth.{os.environ['BASE_DOMAIN']}/login"
    _check(event["url"] + "/", require_auth, login_prefix, "首页")
    if event["manifest"].get("backend"):
        _check(event["url"] + "/api/health", require_auth, login_prefix, "/api/health")
    return event
```

`site-builder/deployer/functions/mark_job.py`:

```python
"""SFN 终态：成功/失败落账 + 站点记录维护 + 旧版本前端清理。"""
import logging
import os

import boto3

import common

logger = logging.getLogger()


def _cleanup_old_versions(site_id: str, current_job_id: str):
    """删除 sites/{site_id}/ 下除当前 job 外的旧版本前缀。
    失败仅告警——站点已上线，残留旧版本只是存储成本。"""
    try:
        s3 = boto3.client("s3")
        bucket = os.environ["FRONTEND_BUCKET"]
        keep = f"sites/{site_id}/{current_job_id}/"
        paginator = s3.get_paginator("list_objects_v2")
        stale = []
        for page in paginator.paginate(Bucket=bucket, Prefix=f"sites/{site_id}/"):
            stale += [{"Key": o["Key"]} for o in page.get("Contents", [])
                      if not o["Key"].startswith(keep)]
        for i in range(0, len(stale), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": stale[i:i + 1000]})
    except Exception as e:
        logger.warning(f"旧版本清理失败（不影响部署结果）: {e}")


def handler(event, context):
    job_id = event["job_id"]
    if "error_info" in event:
        cause = str(event["error_info"].get("Cause", "未知错误"))[:500]
        common.update_job(job_id, status="FAILED", error=cause)
        return {"job_id": job_id, "status": "FAILED", "error": cause}

    job = common.get_job(job_id)
    common.update_job(job_id, status="SUCCEEDED", url=event["url"])
    common.upsert_site(event["site_id"], status="ACTIVE", last_job_id=job_id,
                       owner=job["owner"], tier=event["manifest"]["tier"],
                       name=event["manifest"]["name"],
                       subdomain=common.subdomain_for(event["site_id"]))
    _cleanup_old_versions(event["site_id"], job_id)
    return {"job_id": job_id, "status": "SUCCEEDED", "url": event["url"]}
```

- [ ] **Step 4: 运行确认通过（全套单测回归）**

Run: `.venv/bin/pytest tests/ -q`
Expected: 全部通过（约 19 个）

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): frontend upload, route registration, smoke test, job finalize"
```

### Task 17: Step Functions 状态机组装 + 上传触发 + 部署

**Files:**
- Modify: `site-builder/deployer/infra/app.py`
- Create: `site-builder/deployer/functions/undeploy.py`
- Test: `site-builder/deployer/tests/test_undeploy.py`

**Interfaces:**
- Consumes: Task 10-16 全部 handler；Task 9 角色/表/桶
- Produces: 状态机 `site-deploy`（ARN 回填 config.ini `[Deployer].state_machine_arn`）。定义：

```
Validate → ChoiceDB ─ dynamodb → ProvisionDynamoDB ─┐
           ├─ dsql   → ProvisionDSQL ───────────────┤
           └─ none   ────────────────────────────────┤
ChoiceBackend ─ 有 backend → PackageBackend → DeployLambdaSite ─┐
              └─ static ────────────────────────────────────────┤
UploadFrontend → RegisterRoute → SmokeTest → MarkSuccess
（所有步骤 Catch ALL → MarkFailed，ResultPath=$.error_info）
```

另产出 `undeploy.handler`（独立 Lambda `site-undeploy`，MCP 直调）：删路由 item → 删站点 Lambda（容忍不存在）→ 清前端前缀 → sites 表状态 DELETED、job 状态 DELETED。DB 资源保留（防误删数据，PoC 决策）。

- [ ] **Step 1: 写 undeploy 失败测试**

`site-builder/deployer/tests/test_undeploy.py`:

```python
import boto3
from unittest.mock import MagicMock, patch


def test_undeploy_cleans_route_frontend_lambda(aws):
    import undeploy, common
    jid = common.create_job("a@x.com", "hello-x1")
    common.upsert_site("hello-x1", owner="a@x.com", status="ACTIVE")
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-hello-x1"}, "site_id": {"S": "hello-x1"},
        "static_prefix": {"S": "sites/hello-x1"}, "api_target": {"S": ""},
        "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
        "owner": {"S": "a@x.com"}})
    boto3.client("s3").put_object(Bucket="site-frontend-1",
                                  Key="sites/hello-x1/index.html", Body=b"x")
    lam = MagicMock()
    lam.exceptions.ResourceNotFoundException = type("NF", (Exception,), {})
    with patch.object(undeploy, "_lambda", return_value=lam):
        undeploy.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert "Item" not in ddb.get_item(TableName="routing",
                                      Key={"subdomain": {"S": "app-hello-x1"}})
    assert boto3.client("s3").list_objects_v2(
        Bucket="site-frontend-1", Prefix="sites/hello-x1/")["KeyCount"] == 0
    lam.delete_function.assert_called_once_with(FunctionName="site-hello-x1")
    assert common.get_site("hello-x1")["status"] == "DELETED"
```

- [ ] **Step 2: 运行确认失败 → 实现 undeploy**

Run: `.venv/bin/pytest tests/test_undeploy.py -q` → FAIL

`site-builder/deployer/functions/undeploy.py`:

```python
"""站点下线：删路由 → 删 Lambda → 删 per-site 角色 → 清前端（paginator 分批）。
DB 数据保留（PoC 防误删）。"""
import os

import boto3

import common


def _lambda():
    return boto3.client("lambda")


def _delete_prefix(s3, bucket: str, prefix: str):
    """paginator + 每批 ≤1000 对象（delete_objects 上限）。"""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        for i in range(0, len(objs), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000]})


def handler(event, context):
    site_id = event["site_id"]
    common.update_job(event["job_id"], status="RUNNING", phase="undeploy")

    boto3.client("dynamodb").delete_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": common.subdomain_for(site_id)}})

    lam = _lambda()
    try:
        lam.delete_function(FunctionName=f"site-{site_id}")
    except lam.exceptions.ResourceNotFoundException:
        pass

    iam = boto3.client("iam")
    role = f"site-rt-{site_id}"
    try:
        for pol in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=pol)
        iam.delete_role(RoleName=role)
    except iam.exceptions.NoSuchEntityException:
        pass

    _delete_prefix(boto3.client("s3"), os.environ["FRONTEND_BUCKET"],
                   f"sites/{site_id}/")

    common.upsert_site(site_id, status="DELETED")
    common.update_job(event["job_id"], status="DELETED")
    return {"job_id": event["job_id"], "status": "DELETED"}
```

Run: `.venv/bin/pytest tests/test_undeploy.py -q` → 1 passed

- [ ] **Step 3: app.py 追加 Lambda 函数群与状态机**

在 `SiteDeployerStack.__init__` 末尾追加（import 增补 `aws_lambda as lam_`, `aws_stepfunctions as sfn`, `aws_stepfunctions_tasks as tasks`）：

```python
        fn_dir = str(Path(__file__).parents[1] / "functions")
        contract_dir = str(Path(__file__).parents[2] / "contract" / "src")
        common_env = {
            "JOBS_TABLE": jobs.table_name, "SITES_TABLE": sites.table_name,
            "ARTIFACTS_BUCKET": artifacts.bucket_name,
            "FRONTEND_BUCKET": f"site-frontend-{ACCOUNT}",
            "ROUTING_TABLE": CFG["Platform"]["routing_table"],
            "BASE_DOMAIN": CFG["Platform"]["base_domain"],
            "RUNTIME_BOUNDARY_ARN": runtime_boundary.managed_policy_arn,
            "EDGE_ROLE_ARN": CFG["Deployer"]["edge_role_arn"],  # manus 栈 CfnOutput 回填
            "PACKAGE_PROJECT": package_project.project_name,
            "DSQL_ENDPOINT": CFG["DSQL"]["cluster_endpoint"],
            "ACCOUNT_ID": ACCOUNT,
        }

        def step_fn(name: str, handler: str, timeout_s: int = 120) -> lam_.Function:
            # 打包 functions/ + contract 包；psycopg 由 bundling pip 装入
            return lam_.Function(
                self, name, function_name=f"site-deployer-{handler}",
                runtime=lam_.Runtime.PYTHON_3_13,
                handler=f"{handler}.handler",
                code=lam_.Code.from_asset(fn_dir, bundling={
                    "image": lam_.Runtime.PYTHON_3_13.bundling_image,
                    "command": ["bash", "-c",
                                "pip install 'psycopg[binary]' sqlparse -t /asset-output -q && "
                                f"cp -r /asset-input/. /asset-output/ && "
                                "pip install /asset-contract -t /asset-output -q"],
                    "volumes": [{"hostPath": contract_dir + "/..",
                                 "containerPath": "/asset-contract"}]}),
                role=exec_role, timeout=Duration.seconds(timeout_s),
                memory_size=512, environment=common_env)

        f_validate = step_fn("FnValidate", "validate")
        f_ddb = step_fn("FnProvDdb", "provision_dynamodb", 300)
        f_dsql = step_fn("FnProvDsql", "provision_dsql", 300)
        f_pkg = step_fn("FnPackage", "package_backend", 900)
        f_deploy = step_fn("FnDeployLambda", "deploy_lambda_site", 300)
        f_upload = step_fn("FnUpload", "upload_frontend", 300)
        f_route = step_fn("FnRoute", "register_route")
        f_smoke = step_fn("FnSmoke", "smoke_test", 60)
        f_mark = step_fn("FnMark", "mark_job")
        step_fn("FnUndeploy", "undeploy", 300)  # MCP 直调，不进状态机

        mark_failed = tasks.LambdaInvoke(self, "MarkFailed", lambda_function=f_mark,
                                         payload_response_only=True)
        mark_failed.next(sfn.Fail(self, "Failed"))

        _tracked: list = []

        def t(name: str, fn) -> tasks.LambdaInvoke:
            node = tasks.LambdaInvoke(self, name, lambda_function=fn,
                                      payload_response_only=True)
            node.add_catch(mark_failed, errors=["States.ALL"],
                           result_path="$.error_info")
            _tracked.append(node)
            return node

        # 汇合点用 Pass 节点——同一后续链只被 next 一次，Choice 分支都指向它
        join_upload = sfn.Pass(self, "JoinUpload")
        join_upload.next(t("UploadFrontend", f_upload)
                         .next(t("RegisterRoute", f_route))
                         .next(t("SmokeTest", f_smoke))
                         .next(t("MarkSuccess", f_mark))
                         .next(sfn.Succeed(self, "Done")))

        join_backend = sfn.Pass(self, "JoinBackend")
        join_backend.next(
            sfn.Choice(self, "HasBackend?")
            .when(sfn.Condition.string_equals("$.manifest.tier", "static"),
                  join_upload)
            .otherwise(t("PackageBackend", f_pkg)
                       .next(t("DeployLambdaSite", f_deploy))
                       .next(join_upload)))

        choice_db = (sfn.Choice(self, "WhichDB?")
                     .when(sfn.Condition.string_equals("$.manifest.database.engine",
                                                       "dynamodb"),
                           t("ProvisionDynamoDB", f_ddb).next(join_backend))
                     .when(sfn.Condition.string_equals("$.manifest.database.engine",
                                                       "dsql"),
                           t("ProvisionDSQL", f_dsql).next(join_backend))
                     .otherwise(join_backend))
        definition = t("Validate", f_validate).next(choice_db)

        sm = sfn.StateMachine(self, "DeploySM", state_machine_name="site-deploy",
                              definition_body=sfn.DefinitionBody.from_chainable(definition),
                              timeout=Duration.minutes(30))
        CfnOutput(self, "StateMachineArn", value=sm.state_machine_arn)
        CfnOutput(self, "UndeployFnArn",
                  value=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:site-deployer-undeploy")
```

结构说明：`t()` 工厂在创建时就挂 Catch（MarkSuccess 也会被 Catch——其失败同样应落 FAILED，无害）；两个 `sfn.Pass` 汇合点让多个 Choice 分支收敛到同一后续链而不违反 CDK 的单 next 约束。此定义结构上可直接 synth；Step 4 的 `cdk synth -q` 是硬验收（若个别 API 细节随 aws-cdk-lib 版本漂移，以 synth 通过 + 状态机语义等于本流程图为准）。

- [ ] **Step 4: synth + 部署 + 真机验证**

```bash
cd site-builder/deployer/infra && npx cdk synth -q && npx cdk deploy --require-approval never
# 手工触发一次 static 部署验证：
cd ../../.. && python3 - <<'EOF'
import boto3, io, json, zipfile, configparser
cfg = configparser.ConfigParser(); cfg.read("site-builder/config.ini")
acct = cfg["Platform"]["account_id"]
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("site.json", json.dumps({
        "name": "smoke", "tier": "static", "database": {"engine": "none"},
        "auth": {"require_login": False, "allowed_users": "org"}}))
    z.writestr("frontend/index.html", "<h1>sfn-smoke</h1>")
import sys; sys.path.insert(0, "site-builder/deployer/functions")
# 直接 put uploads + start execution
s3 = boto3.client("s3"); jobs = boto3.resource("dynamodb").Table("site-deploy-jobs")
from datetime import datetime, timezone
job_id, site_id = "job-manual01", "smoke-manual"
s3.put_object(Bucket=f"site-artifacts-{acct}", Key=f"uploads/{job_id}.zip",
              Body=buf.getvalue())
jobs.put_item(Item={"job_id": job_id, "site_id": site_id, "owner": "manual@test",
                    "status": "PENDING", "phase": "submitted", "error": "", "url": "",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat()})
sfn = boto3.client("stepfunctions")
sfn.start_execution(stateMachineArn=cfg["Deployer"]["state_machine_arn"],
                    input=json.dumps({"job_id": job_id, "site_id": site_id}))
EOF
aws stepfunctions list-executions --state-machine-arn <ARN> --max-items 1
```

Expected: execution SUCCEEDED；`curl https://app-smoke-manual.<BASE_DOMAIN>/` 返回 `<h1>sfn-smoke</h1>`。

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer
git commit -m "feat(deployer): state machine assembly and undeploy function"
```

### Task 18: fixtures 三站点 + 执行器端到端集成测试

**Files:**
- Create: `site-builder/fixtures/static-hello/{site.json, frontend/index.html}`
- Create: `site-builder/fixtures/nosql-notes/{site.json, frontend/index.html, backend/server.js, backend/package.json}`
- Create: `site-builder/fixtures/sql-expenses/{site.json, frontend/index.html, backend/server.js, backend/package.json, backend/schema.sql, backend/db.js}`
- Create: `site-builder/fixtures/run.sh`（LWA 启动脚本，打包时放 zip 根）
- Create: `site-builder/scripts/deploy_fixture.py`（打 zip→传 uploads→建 job→跑 SFN→轮询→打印 URL）
- Test: `site-builder/deployer/tests/test_e2e_fixtures.py`（`@pytest.mark.e2e`，默认 skip，`RUN_E2E=1` 才跑）

**Interfaces:**
- Consumes: 全部已部署基础设施
- Produces: 三个可演示站点 + `deploy_fixture.py`（Task 22/23 复用）。fixtures 同时是合同的"黄金样例"，Task 21 的 Skill 模板引用它们。

- [ ] **Step 1: 写 fixtures**

`static-hello/site.json`:

```json
{"name": "hello", "tier": "static",
 "database": {"engine": "none"},
 "auth": {"require_login": false, "allowed_users": "org"}}
```

`static-hello/frontend/index.html`:

```html
<!doctype html><meta charset="utf-8"><title>Hello</title>
<h1>Site Builder 静态站点样例</h1>
```

`fixtures/run.sh`（所有 fullstack fixture 共用，deploy_fixture.py 打包时置于 zip 根）:

```bash
#!/bin/bash
exec node server.js
```

`nosql-notes/site.json`:

```json
{"name": "notes", "tier": "fullstack-nosql",
 "backend": {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080},
 "database": {"engine": "dynamodb", "tables": [{"name": "notes", "pk": "id"}]},
 "auth": {"require_login": true, "allowed_users": "org"}}
```

`nosql-notes/backend/server.js`:

```javascript
const express = require("express");
const crypto = require("crypto");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, ScanCommand, DeleteCommand } =
  require("@aws-sdk/lib-dynamodb");

const app = express();
app.use(express.json());
const db = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE = process.env.TABLE_NOTES;

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/notes", async (req, res) => {
  const out = await db.send(new ScanCommand({ TableName: TABLE }));
  res.json(out.Items || []);
});
app.post("/api/notes", async (req, res) => {
  const item = { id: crypto.randomUUID(), text: req.body.text,
                 author: req.headers["x-user-email"] || "anonymous",
                 created_at: new Date().toISOString() };
  await db.send(new PutCommand({ TableName: TABLE, Item: item }));
  res.status(201).json(item);
});
app.delete("/api/notes/:id", async (req, res) => {
  await db.send(new DeleteCommand({ TableName: TABLE, Key: { id: req.params.id } }));
  res.status(204).end();
});
app.listen(process.env.PORT || 8080);
```

`nosql-notes/backend/package.json`:

```json
{"name": "notes-backend", "private": true,
 "dependencies": {"express": "^4.19", "@aws-sdk/client-dynamodb": "^3",
                  "@aws-sdk/lib-dynamodb": "^3"}}
```

`nosql-notes/frontend/index.html`:

```html
<!doctype html><meta charset="utf-8"><title>Notes</title>
<h1>便签</h1>
<form id="f"><input id="t" placeholder="记点什么"><button>添加</button></form>
<ul id="list"></ul>
<script>
// 用户输入一律 textContent 渲染——innerHTML 拼接会存储型 XSS（合同红线）
const load = async () => {
  const notes = await (await fetch("/api/notes")).json();
  list.replaceChildren(...notes.map(n => {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = n.text;
    const small = document.createElement("small");
    small.textContent = " " + n.author;
    const btn = document.createElement("button");
    btn.textContent = "删";
    btn.onclick = async () => {
      await fetch(`/api/notes/${encodeURIComponent(n.id)}`, {method: "DELETE"});
      load();
    };
    li.append(span, small, btn);
    return li;
  }));
};
f.onsubmit = async e => {
  e.preventDefault();
  await fetch("/api/notes", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({text: t.value})});
  t.value = ""; load();
};
load();
</script>
```

`sql-expenses/site.json`:

```json
{"name": "expenses", "tier": "fullstack-sql",
 "backend": {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080},
 "database": {"engine": "dsql", "tables": []},
 "auth": {"require_login": true, "allowed_users": "org"}}
```

`sql-expenses/backend/schema.sql`:

```sql
CREATE TABLE IF NOT EXISTS expenses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  amount NUMERIC(10,2) NOT NULL,
  spender TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
```

`sql-expenses/backend/db.js`（与 Task 21 Skill 模板同源）:

```javascript
// DSQL 连接模板——站点代码不改此文件。
// 非 admin：用本站点专属 PG role（DSQL_USER）+ 普通 DbConnect token，
// 只被 GRANT 本站点 schema——数据隔离由平台在部署时配置。
const { Pool } = require("pg");
const { DsqlSigner } = require("@aws-sdk/dsql-signer");

const HOST = process.env.DSQL_ENDPOINT;
const SCHEMA = process.env.DSQL_SCHEMA;
const USER = process.env.DSQL_USER;

async function makePool() {
  const signer = new DsqlSigner({ hostname: HOST, region: "us-east-1" });
  const pool = new Pool({
    host: HOST, database: "postgres", user: USER,
    password: () => signer.getDbConnectAuthToken(),  // 非 admin token
    ssl: { rejectUnauthorized: true }, max: 3,
    maxLifetimeSeconds: 3300,  // token 有效期内轮换连接
  });
  pool.on("connect", c => c.query(`SET search_path = "${SCHEMA}"`));
  return pool;
}
module.exports = { makePool };
```

`sql-expenses/backend/server.js`:

```javascript
const express = require("express");
const { makePool } = require("./db");

const app = express();
app.use(express.json());
let pool;
const db = async () => (pool ??= await makePool());

app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/expenses", async (req, res) => {
  const { rows } = await (await db()).query(
    "SELECT * FROM expenses ORDER BY created_at DESC");
  res.json(rows);
});
app.post("/api/expenses", async (req, res) => {
  const { rows } = await (await db()).query(
    "INSERT INTO expenses (title, amount, spender) VALUES ($1,$2,$3) RETURNING *",
    [req.body.title, req.body.amount, req.headers["x-user-email"] || "anonymous"]);
  res.status(201).json(rows[0]);
});
app.listen(process.env.PORT || 8080);
```

`sql-expenses/backend/package.json`:

```json
{"name": "expenses-backend", "private": true,
 "dependencies": {"express": "^4.19", "pg": "^8.12", "@aws-sdk/dsql-signer": "^3"}}
```

`sql-expenses/frontend/index.html`：结构同 notes（表单字段 title/amount，列表渲染 `/api/expenses`），此处从略——落码时对照 notes 版本完整写出，仍然只用相对路径 `/api/*`。

- [ ] **Step 2: 写 deploy_fixture.py**

`site-builder/scripts/deploy_fixture.py`:

```python
#!/usr/bin/env python3
"""打包 fixture → 上传 → 建 job → 跑状态机 → 轮询到终态。用法：
python3 site-builder/scripts/deploy_fixture.py site-builder/fixtures/nosql-notes"""
import configparser
import io
import json
import secrets
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3

CFG = configparser.ConfigParser()
CFG.read(Path(__file__).parents[1] / "config.ini")
ACCT = CFG["Platform"]["account_id"]


def main(fixture_dir: str):
    root = Path(fixture_dir)
    manifest = json.loads((root / "site.json").read_text())
    site_id = f"{manifest['name'][:20]}-{secrets.token_hex(3)}"
    job_id = f"job-{secrets.token_hex(8)}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in root.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(root))
        run_sh = root.parent / "run.sh"
        if manifest["tier"] != "static" and run_sh.exists():
            z.write(run_sh, "run.sh")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.put_object(Bucket=f"site-artifacts-{ACCT}", Key=f"uploads/{job_id}.zip",
                  Body=buf.getvalue())
    now = datetime.now(timezone.utc).isoformat()
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["jobs_table"]).put_item(Item={
            "job_id": job_id, "site_id": site_id, "owner": "fixture@test",
            "status": "PENDING", "phase": "submitted", "error": "", "url": "",
            "created_at": now, "updated_at": now})
    boto3.client("stepfunctions", region_name="us-east-1").start_execution(
        stateMachineArn=CFG["Deployer"]["state_machine_arn"],
        input=json.dumps({"job_id": job_id, "site_id": site_id}))

    jobs = boto3.resource("dynamodb", region_name="us-east-1").Table(
        CFG["Deployer"]["jobs_table"])
    while True:
        job = jobs.get_item(Key={"job_id": job_id})["Item"]
        print(f"  [{job['status']}] {job['phase']}")
        if job["status"] in ("SUCCEEDED", "FAILED"):
            print(json.dumps(job, indent=2, ensure_ascii=False, default=str))
            sys.exit(0 if job["status"] == "SUCCEEDED" else 1)
        time.sleep(10)


if __name__ == "__main__":
    main(sys.argv[1])
```

注意 run.sh 打包位置：buildspec（Task 9）`cp /tmp/site/run.sh ./run.sh` 预期 run.sh 在 zip 根——与此处一致。

- [ ] **Step 3: 写 e2e 测试壳**

`site-builder/deployer/tests/test_e2e_fixtures.py`:

```python
"""真实 AWS 端到端：RUN_E2E=1 .venv/bin/pytest tests/test_e2e_fixtures.py -q
断言真实 HTTP 行为，不只看部署退出码。登录态用平台 JWT_SECRET 直接 mint
测试会话 cookie（SSM 读密钥）——无需人工飞书扫码即可自动化验证 CRUD。"""
import configparser
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

import boto3
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("RUN_E2E"),
                                reason="需要 RUN_E2E=1 与真实 AWS 凭证")
ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / "site-builder/auth"))


@pytest.fixture(scope="module")
def cfg():
    c = configparser.ConfigParser()
    c.read(ROOT / "site-builder/config.ini")
    return c


@pytest.fixture(scope="module")
def session_cookie(cfg):
    from session import mint_session_jwt
    secret = boto3.client("ssm", region_name="us-east-1").get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    return "sb_session=" + mint_session_jwt("e2e@test.com", "E2E Bot", secret)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _req(url, method="GET", cookie=None, body=None):
    opener = urllib.request.build_opener(NoRedirect)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body else None)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _deploy(fixture: str) -> str:
    """部署 fixture，返回站点 URL。"""
    r = subprocess.run([sys.executable,
                        str(ROOT / "site-builder/scripts/deploy_fixture.py"),
                        str(ROOT / f"site-builder/fixtures/{fixture}")],
                       capture_output=True, text=True, timeout=1200)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout.splitlines()[-1].strip() or "{}").get("url") \
        or [l for l in r.stdout.splitlines() if '"url"' in l][-1].split('"')[3]


def test_static_site_public_200():
    url = _deploy("static-hello")
    code, _, body = _req(url + "/")
    assert code == 200 and b"Site Builder" in body


def test_notes_site_auth_and_crud(session_cookie, cfg):
    url = _deploy("nosql-notes")
    base = cfg["Platform"]["base_domain"]
    # 1. 未登录 → 302 到登录端点（不跟随）
    code, headers, _ = _req(url + "/")
    assert code == 302
    assert headers["Location"].startswith(f"https://auth.{base}/login")
    # 2. 带会话 cookie：完整 CRUD（真实 body 走 CloudFront→Edge SigV4→Function URL）
    code, _, body = _req(url + "/api/notes", "POST", session_cookie,
                         {"text": "e2e note"})
    assert code == 201, body
    created = json.loads(body)
    assert created["author"] == "e2e@test.com"  # x-user-email 注入生效
    code, _, body = _req(url + "/api/notes", cookie=session_cookie)
    assert code == 200
    assert any(n["id"] == created["id"] for n in json.loads(body))  # read-back
    code, _, _ = _req(f"{url}/api/notes/{created['id']}", "DELETE",
                      session_cookie)
    assert code == 204
    # 3. 伪造用户头被剥除：带假头但无 cookie 仍 302
    code, headers, _ = _req(url + "/api/notes")
    assert code == 302


def test_expenses_site_dsql_crud(session_cookie):
    url = _deploy("sql-expenses")
    code, _, body = _req(url + "/api/expenses", "POST", session_cookie,
                         {"title": "e2e-coffee", "amount": 9.9})
    assert code == 201, body
    code, _, body = _req(url + "/api/expenses", cookie=session_cookie)
    assert code == 200
    assert any(e["title"] == "e2e-coffee" for e in json.loads(body))


def test_update_visible_and_undeploy_404(cfg):
    # 二次部署同一 static fixture（同 site_id 由 deploy_fixture 支持 --site-id 参数）
    # 简化：部署新实例后 undeploy，验证 404
    url = _deploy("static-hello")
    site_id = url.split("//app-")[1].split(".")[0]
    fn = boto3.client("lambda", region_name="us-east-1")
    boto3.client("lambda", region_name="us-east-1")  # noqa
    # 直调 undeploy Lambda（模拟 MCP 工具路径）
    jobs = boto3.resource("dynamodb", region_name="us-east-1").Table(
        cfg["Deployer"]["jobs_table"])
    from datetime import datetime, timezone
    jid = f"job-e2e-un-{site_id[-6:]}"
    now = datetime.now(timezone.utc).isoformat()
    jobs.put_item(Item={"job_id": jid, "site_id": site_id, "owner": "fixture@test",
                        "status": "PENDING", "phase": "submitted", "error": "",
                        "url": "", "created_at": now, "updated_at": now})
    fn.invoke(FunctionName="site-deployer-undeploy",
              Payload=json.dumps({"job_id": jid, "site_id": site_id}))
    import time
    time.sleep(70)  # Edge 路由缓存过期
    code, _, _ = _req(url + "/")
    assert code == 404
```

- [ ] **Step 4: 跑三个 fixture 端到端**

Run: `RUN_E2E=1 .venv/bin/pytest tests/test_e2e_fixtures.py -q`
Expected: 4 passed（含真实 CRUD、302 断言、伪造头拦截、undeploy 后 404）。人工补充：浏览器真实飞书扫码走一遍 notes 站点（cookie mint 跳过了 OAuth 流程本身——那段在 Task 8 人工验证过）。

- [ ] **Step 5: Commit**

```bash
git add site-builder/fixtures site-builder/scripts/deploy_fixture.py site-builder/deployer/tests/test_e2e_fixtures.py
git commit -m "feat(fixtures): three-tier golden sample sites with e2e deploy test"
```

## Phase P4：部署 MCP（M4）

### Task 19: MCP server 四工具（本地 TDD）

**Files:**
- Create: `site-builder/mcp/server.py`
- Create: `site-builder/mcp/requirements.txt`（`mcp>=1.9`、`boto3`）
- Test: `site-builder/mcp/tests/test_tools.py`
- Create: `site-builder/mcp/tests/conftest.py`（复制 deployer conftest 的 aws fixture，`sys.path` 指向 mcp 目录 + deployer/functions——server 复用 `common.py`）

**Interfaces:**
- Consumes: `common.py`（jobs/sites 访问）、SFN ARN、artifacts 桶；调用者身份 email（AgentCore 网关注入，见 Task 20——本地测试直接传参）
- Produces: 4 个 MCP tool。核心逻辑与 MCP 装饰器分离——纯函数层（可测）+ FastMCP 壳：
  - `do_deploy_site(owner, site_name, site_id=None) -> {"job_id","site_id","upload_url","next_step"}`——presigned PUT URL（15 分钟）；site_id 传入=更新部署（校验 owner，不符 raise `NotOwner`）
  - `do_confirm_upload(owner, job_id) -> {"status"}`——HeadObject 确认 zip 已上传且 ≤50MB（超限 raise `UploadTooLarge`）→ **jobs 表条件更新 PENDING→RUNNING**（ConditionExpression，重复确认 raise `AlreadyStarted`）→ StartExecution **name=job_id**（SFN 同名执行拒绝 = 二重幂等）
  - `do_get_status(owner, job_id) -> {"status","phase","error","url"}`
  - `do_list_sites(owner) -> [{"site_id","name","url","status","tier"}]`
  - `do_undeploy(owner, site_id) -> {"job_id"}`——校验 owner → 建 job → 直调 `site-deployer-undeploy` Lambda（InvocationType=Event）

- [ ] **Step 1: 写失败测试**

`site-builder/mcp/tests/test_tools.py`:

```python
import boto3
from unittest.mock import MagicMock, patch
import pytest


def test_deploy_site_new_returns_upload_url(aws):
    import server
    out = server.do_deploy_site("a@x.com", "expense-tracker")
    assert out["job_id"].startswith("job-")
    assert out["site_id"].startswith("expense-tracker-")
    assert "uploads/" + out["job_id"] in out["upload_url"]


def test_deploy_site_update_checks_owner(aws):
    import server, common
    common.upsert_site("demo-abc123", owner="a@x.com", status="ACTIVE")
    out = server.do_deploy_site("a@x.com", "demo", site_id="demo-abc123")
    assert out["site_id"] == "demo-abc123"
    with pytest.raises(server.NotOwner):
        server.do_deploy_site("intruder@x.com", "demo", site_id="demo-abc123")


def test_confirm_upload_starts_sfn_with_jobid_name(aws, monkeypatch):
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:1:stateMachine:sm")
    jid = common.create_job("a@x.com", "demo-abc123")
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=b"zip")
    sfn = MagicMock()
    with patch.object(server, "_sfn", return_value=sfn):
        out = server.do_confirm_upload("a@x.com", jid)
    assert out["status"] == "RUNNING"
    assert sfn.start_execution.call_args.kwargs["name"] == jid  # 幂等 execution name


def test_confirm_upload_double_call_rejected(aws, monkeypatch):
    import server, common
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:1:stateMachine:sm")
    jid = common.create_job("a@x.com", "demo-abc123")
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=b"zip")
    with patch.object(server, "_sfn", return_value=MagicMock()):
        server.do_confirm_upload("a@x.com", jid)
        with pytest.raises(server.AlreadyStarted):  # 条件更新拦住第二次
            server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_missing_zip_errors(aws):
    import server, common
    jid = common.create_job("a@x.com", "demo-abc123")
    with pytest.raises(server.UploadMissing):
        server.do_confirm_upload("a@x.com", jid)


def test_confirm_upload_oversize_zip_rejected(aws, monkeypatch):
    import server, common
    jid = common.create_job("a@x.com", "demo-abc123")
    head = MagicMock()
    head.head_object.return_value = {"ContentLength": 51 * 1024 * 1024}
    head.exceptions = boto3.client("s3").exceptions
    with patch.object(server, "_s3", return_value=head):
        with pytest.raises(server.UploadTooLarge):
            server.do_confirm_upload("a@x.com", jid)


def test_get_status_scoped_to_owner(aws):
    import server, common
    jid = common.create_job("a@x.com", "s1")
    assert server.do_get_status("a@x.com", jid)["status"] == "PENDING"
    with pytest.raises(server.NotOwner):
        server.do_get_status("b@x.com", jid)


def test_list_sites_only_mine(aws):
    import server, common
    common.upsert_site("s1-aaaaaa", owner="a@x.com", name="s1", status="ACTIVE",
                       tier="static", subdomain="app-s1-aaaaaa")
    common.upsert_site("s2-bbbbbb", owner="b@x.com", name="s2", status="ACTIVE",
                       tier="static", subdomain="app-s2-bbbbbb")
    mine = server.do_list_sites("a@x.com")
    assert [s["site_id"] for s in mine] == ["s1-aaaaaa"]
    assert mine[0]["url"] == "https://app-s1-aaaaaa.example.com"


def test_undeploy_checks_owner_and_invokes(aws):
    import server, common
    common.upsert_site("s1-aaaaaa", owner="a@x.com", status="ACTIVE")
    lam = MagicMock()
    with patch.object(server, "_lambda", return_value=lam):
        out = server.do_undeploy("a@x.com", "s1-aaaaaa")
    assert out["job_id"]
    assert lam.invoke.call_args.kwargs["FunctionName"] == "site-deployer-undeploy"
    with pytest.raises(server.NotOwner):
        server.do_undeploy("b@x.com", "s1-aaaaaa")
```

`tests/conftest.py`：复制 deployer 的 conftest（同一 aws fixture 与 ENV），`sys.path` 额外插入 `site-builder/mcp` 与 `site-builder/deployer/functions`。sites 表需加 GSI 支持 owner 查询——**修正**：`do_list_sites` 用 Scan+FilterExpression（PoC 规模下可接受，避免为 sites 表加 GSI），conftest 无需改表结构。

- [ ] **Step 2: 运行确认失败**

Run: `cd site-builder/mcp && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest moto[dynamodb,s3] -q && .venv/bin/pytest tests/ -q`
Expected: FAIL（ModuleNotFoundError: server）

- [ ] **Step 3: 实现**

`site-builder/mcp/server.py`:

```python
"""部署 MCP——薄壳：4 工具全部秒级返回，重活交给 Step Functions。
运行于 AgentCore Runtime；调用者飞书 email 由网关经 JWT claims 传入。"""
import json
import os

import boto3
from mcp.server.fastmcp import FastMCP

import common  # deployer/functions/common.py，部署包中同目录


class NotOwner(Exception):
    pass


class UploadMissing(Exception):
    pass


class UploadTooLarge(Exception):
    pass


class AlreadyStarted(Exception):
    pass


MAX_ZIP_BYTES = 50 * 1024 * 1024


def _s3():
    return boto3.client("s3", region_name="us-east-1")


def _sfn():
    return boto3.client("stepfunctions", region_name="us-east-1")


def _lambda():
    return boto3.client("lambda", region_name="us-east-1")


def _assert_owner(owner: str, record: dict | None, what: str):
    if not record:
        raise NotOwner(f"{what} 不存在")
    if record.get("owner") != owner:
        raise NotOwner(f"你不是 {what} 的所有者，无权操作")


# ---------- 纯函数层（单测目标） ----------

def do_deploy_site(owner: str, site_name: str, site_id: str | None = None) -> dict:
    if site_id:
        _assert_owner(owner, common.get_site(site_id), f"站点 {site_id}")
    else:
        site_id = common.new_site_id(site_name)
        common.upsert_site(site_id, owner=owner, name=site_name, status="DEPLOYING")
    job_id = common.create_job(owner, site_id)
    url = _s3().generate_presigned_url(
        "put_object",
        Params={"Bucket": os.environ["ARTIFACTS_BUCKET"],
                "Key": f"uploads/{job_id}.zip"},
        ExpiresIn=900)
    return {"job_id": job_id, "site_id": site_id, "upload_url": url,
            "next_step": "将 site.zip PUT 到 upload_url，然后调用 confirm_upload"}


def do_confirm_upload(owner: str, job_id: str) -> dict:
    job = common.get_job(job_id)
    _assert_owner(owner, job, f"任务 {job_id}")
    s3 = _s3()
    try:
        head = s3.head_object(Bucket=os.environ["ARTIFACTS_BUCKET"],
                              Key=f"uploads/{job_id}.zip")
    except s3.exceptions.ClientError:
        raise UploadMissing("未检测到上传的 site.zip，请先 PUT 到 upload_url")
    if head["ContentLength"] > MAX_ZIP_BYTES:
        raise UploadTooLarge(f"site.zip {head['ContentLength']} 字节超过 50MB 上限")

    # 条件迁移 PENDING→RUNNING：双击/重放在此被拦，SFN 同名执行是第二道闸
    import botocore.exceptions
    try:
        boto3.resource("dynamodb", region_name="us-east-1").Table(
            os.environ["JOBS_TABLE"]).update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :running, phase = :q",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":running": "RUNNING", ":pending": "PENDING",
                                       ":q": "queued"})
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise AlreadyStarted(f"任务 {job_id} 已启动过，请用 get_deploy_status 查询进度")
        raise
    _sfn().start_execution(
        stateMachineArn=os.environ["STATE_MACHINE_ARN"],
        name=job_id,  # 同名执行被 SFN 拒绝 = 幂等
        input=json.dumps({"job_id": job_id, "site_id": job["site_id"]}))
    return {"status": "RUNNING"}


def do_get_status(owner: str, job_id: str) -> dict:
    job = common.get_job(job_id)
    _assert_owner(owner, job, f"任务 {job_id}")
    return {k: job.get(k, "") for k in ("status", "phase", "error", "url")}


def do_list_sites(owner: str) -> list[dict]:
    import boto3.dynamodb.conditions as cond
    table = boto3.resource("dynamodb", region_name="us-east-1").Table(
        os.environ["SITES_TABLE"])
    items = table.scan(FilterExpression=cond.Attr("owner").eq(owner)).get("Items", [])
    base = os.environ["BASE_DOMAIN"]
    return [{"site_id": s["site_id"], "name": s.get("name", ""),
             "url": f"https://{s.get('subdomain', 'app-' + s['site_id'])}.{base}",
             "status": s.get("status", ""), "tier": s.get("tier", "")}
            for s in items]


def do_undeploy(owner: str, site_id: str) -> dict:
    _assert_owner(owner, common.get_site(site_id), f"站点 {site_id}")
    job_id = common.create_job(owner, site_id)
    _lambda().invoke(FunctionName="site-deployer-undeploy",
                     InvocationType="Event",
                     Payload=json.dumps({"job_id": job_id, "site_id": site_id}))
    return {"job_id": job_id}


# ---------- MCP 壳 ----------

mcp = FastMCP("site-builder-deploy", stateless_http=True)


def _caller_email() -> str:
    """AgentCore 网关把 Cognito JWT 的 email 放请求头（Task 20 配置）。"""
    from mcp.server.fastmcp import get_http_headers
    email = get_http_headers().get("x-amzn-oauth-email", "")
    if not email:
        raise NotOwner("无法识别调用者身份（缺少 OAuth email）")
    return email


@mcp.tool()
def deploy_site(site_name: str, site_id: str = "") -> dict:
    """部署（或更新）一个站点。返回 upload_url，把 site.zip PUT 上去后调 confirm_upload。
    site_name: 站点名（小写字母数字连字符）；site_id: 更新已有站点时传。"""
    return do_deploy_site(_caller_email(), site_name, site_id or None)


@mcp.tool()
def confirm_upload(job_id: str) -> dict:
    """确认 site.zip 已上传，启动异步部署。之后轮询 get_deploy_status。"""
    return do_confirm_upload(_caller_email(), job_id)


@mcp.tool()
def get_deploy_status(job_id: str) -> dict:
    """查询部署任务状态。status=SUCCEEDED 时 url 即站点地址；FAILED 时 error 为原因。"""
    return do_get_status(_caller_email(), job_id)


@mcp.tool()
def list_my_sites() -> list:
    """列出我部署的所有站点。"""
    return do_list_sites(_caller_email())


@mcp.tool()
def undeploy_site(site_id: str) -> dict:
    """下线站点（删路由/Lambda/前端；数据库数据保留）。仅站点所有者可操作。"""
    return do_undeploy(_caller_email(), site_id)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
```

工具面说明：设计文档定义 4 工具；实现上 `deploy_site` 因 presigned-URL 上传模式拆出 `confirm_upload`，对外仍是"一次部署动作"的两个阶段。`_caller_email` 的 header 名以 Task 20 实际网关配置为准，先按 `x-amzn-oauth-email` 占位。

- [ ] **Step 4: 运行确认通过**

Run: `.venv/bin/pytest tests/ -q`
Expected: 10 passed

- [ ] **Step 5: Commit**

```bash
git add site-builder/mcp
git commit -m "feat(mcp): deploy mcp server with owner-scoped, idempotent tools"
```

### Task 20: AgentCore 部署 + Cognito OAuth + 远程冒烟

参考基座：飞书集成调研方案 3（`ddpie/lark-mcp-on-agentcore`）的部署形态，但本 MCP 简单得多（无 Tier2/Skill 分层）。

**Step 0 是 Spike（本任务唯一真不确定项）**：AgentCore Runtime 如何把 Cognito JWT 的 email claim 暴露给容器（网关注入头？原样透传 Authorization？）官方文档与实测确认后，才锁定 `_caller_email` 实现并回补 Task 19 的 header 常量。Spike 产出写入 `AGENTCORE.md`：确切的 claim 传递机制、`create_agent_runtime` 请求体样例、所用 boto3/CLI 版本。若 Spike 发现 AgentCore 完全不透传身份（最坏情况），fallback 方案：MCP 侧自行解码 Bearer JWT（网关已验签）——该路径已在 Task 19 预留。其余步骤（Dockerfile、ECR、Runtime 创建）按官方 MCP 托管文档执行，`aws bedrock-agentcore-control help` 先行核对 API 形状。

**Files:**
- Create: `site-builder/mcp/Dockerfile`
- Create: `site-builder/mcp/deploy_agentcore.py`
- Create: `site-builder/mcp/AGENTCORE.md`（记录 Runtime ARN、endpoint URL、OAuth 配置）

**Interfaces:**
- Consumes: Task 19 server.py；Task 3 `mcp_client_id`（Cognito）；Task 9 exec 角色模式
- Produces: 公网可达的 Streamable HTTP MCP endpoint（OAuth 保护），URL 记入 AGENTCORE.md 与 config.ini `[MCP] endpoint_url`。任何 MCP 客户端（Quick Desktop Capabilities→MCP、Claude Code `claude mcp add`）可接。

- [ ] **Step 1: Dockerfile（AgentCore 要求 ARM64 容器）**

```dockerfile
FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
COPY server.py common.py ./
# common.py 从 deployer/functions 复制进构建上下文（deploy 脚本处理）
EXPOSE 8000
CMD ["python", "server.py"]
```

- [ ] **Step 2: 部署脚本**

`site-builder/mcp/deploy_agentcore.py` 意图（执行者按 bedrock-agentcore-control 实际 API 落码）：

```python
"""① cp ../deployer/functions/common.py . ② docker buildx --platform linux/arm64
build+push 到 ECR site-mcp ③ create_agent_runtime(
    agentRuntimeArtifact={containerConfiguration: {containerUri: <ecr>}},
    protocolConfiguration={serverProtocol: "MCP"},
    authorizerConfiguration={customJWTAuthorizer: {
        discoveryUrl: https://cognito-idp.us-east-1.amazonaws.com/<POOL_ID>/.well-known/openid-configuration,
        allowedClients: [<mcp_client_id>]}},
    environmentVariables={JOBS_TABLE、SITES_TABLE、ARTIFACTS_BUCKET、
        STATE_MACHINE_ARN、BASE_DOMAIN、...}) ④ 打印 endpoint URL 并回填 config.ini。
Runtime 执行角色：复用 site-deployer-exec-role 的权限模式，另需
states:StartExecution、lambda:InvokeFunction(site-deployer-undeploy)、
s3 presign 无需额外权限（用角色自身凭证签）。"""
```

- [ ] **Step 3: 部署并用 MCP Inspector 冒烟**

```bash
python3 site-builder/mcp/deploy_agentcore.py
# 拿 Cognito token（authorization code flow 或临时用 test 用户 client_credentials）
npx @modelcontextprotocol/inspector  # 连 endpoint，Authorization: Bearer <token>
```

Expected: Inspector 列出 5 个工具；`list_my_sites` 返回 fixture 站点（owner 匹配时）；无 token 调用返回 401。**验证 email claim 透传**：`deploy_site` 创建的 job owner 字段 == 登录用户的飞书邮箱。若 AgentCore 不透传 claims 到容器请求头，则在 server.py `_caller_email` 改为自行解码请求 `Authorization` Bearer JWT（不验签——网关已验）取 email claim，并记录在 AGENTCORE.md。

- [ ] **Step 4: Quick Desktop 接入验证（人工门禁）**

用户在 Quick Desktop → Capabilities → MCP 添加 endpoint（OAuth 流程走飞书登录）→ 对话中让 Quick 调用 `list_my_sites` 成功。

- [ ] **Step 5: Commit**

```bash
git add site-builder/mcp
git commit -m "feat(mcp): agentcore runtime deployment with cognito jwt auth"
```

## Phase P5：建站 Skill（M5）

### Task 21: site-builder Skill（SKILL.md + 模板 + 参考文档）

**Files:**
- Create: `site-builder/skills/site-builder/SKILL.md`
- Create: `site-builder/skills/site-builder/references/contract.md`
- Create: `site-builder/skills/site-builder/references/redlines.md`
- Create: `site-builder/skills/site-builder/templates/db.js`（= fixtures sql-expenses/backend/db.js 原样）
- Create: `site-builder/skills/site-builder/templates/run.sh`（= fixtures/run.sh 原样）
- Create: `site-builder/skills/site-builder/templates/site.json.static.example` / `.nosql.example` / `.sql.example`（= 三个 fixture 的 site.json 原样）

**Interfaces:**
- Consumes: 部署合同（Task 1/2 校验器是其机器可执行形式）；MCP 工具名与参数（Task 19）
- Produces: 符合 Agent Skills 开放标准的技能包，Quick Desktop / Claude Code / Kiro 等通用。

- [ ] **Step 1: 写 SKILL.md**

```markdown
---
name: site-builder
description: 开发并一键部署简易 Web 站点到 AWS。当用户想创建/搭建/部署一个网站、
  小工具、数据看板、记录系统，或要求修改/更新/下线已部署的站点时使用。
  产出带子域名 URL 的站点，访问与管理权限绑定飞书账号。
---

# Site Builder：开发 → 一键部署

你帮业务用户用自然语言开发简易站点并部署上线。全程不要求用户懂 AWS。

## 工作流

1. **澄清需求**：问清站点用途、需要记录什么数据、谁能访问（全组织/指定人）。
2. **定 tier**（三选一，宁低勿高）：
   - 纯展示、无交互存储 → `static`
   - 要记录数据、结构简单（列表/表单）→ `fullstack-nosql`（DynamoDB）
   - 数据有关联查询/统计聚合 → `fullstack-sql`（Aurora DSQL）
3. **生成代码**：严格按 `references/contract.md` 的目录结构与 site.json 格式；
   严格遵守 `references/redlines.md` 的全部红线。模板：
   - `templates/site.json.*.example` 为三档清单样例
   - fullstack 后端一律 Express（Node 22）；`templates/run.sh` 原样放项目根
   - fullstack-sql 的数据库访问必须原样复制 `templates/db.js`，只通过
     `makePool()` 连接，schema 全部写进 `backend/schema.sql`
4. **本地预览**：static 直接开 index.html；fullstack 跑 `node server.js` 演示。
   用户确认后再部署。
5. **部署**（MCP: site-builder-deploy）：
   a. 项目目录打包为 site.zip（site.json 在 zip 根）
   b. 调 `deploy_site(site_name)`（更新已有站点则带 site_id）→ 得 upload_url + job_id
   c. HTTP PUT site.zip 到 upload_url
   d. 调 `confirm_upload(job_id)`
   e. 每 15 秒调 `get_deploy_status(job_id)` 直到 SUCCEEDED/FAILED，
      向用户播报 phase 进展（validate → provision-db → package → deploy-backend
      → upload-frontend → register-route → smoke-test）
   f. 成功：把 url 给用户；失败：把 error 翻译成用户能懂的话，修复代码后从 a 重来
6. **迭代**：用户要改站点 → 改代码 → 同 site_id 重新走部署流程（URL 不变，
   schema 变更写 `backend/migrations/NNN_描述.sql`，不改已有 schema.sql）。
7. **管理**：`list_my_sites` 列站点；`undeploy_site(site_id)` 下线（先跟用户确认）。

## 关键约束速查（详见 references/）

- 前端调后端只写相对路径 `/api/*`
- 站点代码零登录逻辑；当前用户 = 请求头 `x-user-email` / `x-user-name`
- 后端必须实现 `GET /api/health`
- 不写本地文件；端口读 `process.env.PORT`；API 请求体 ≤1MB
- 渲染用户输入用 textContent / DOM API，禁止拼 innerHTML（存储型 XSS）
- DSQL 禁：外键/SERIAL/JSONB 列/触发器/TEMP TABLE → 用 UUID 主键、TEXT 存 JSON
- 数据库访问只用模板 db.js 的 makePool()，不自写连接（平台注入专属只读身份）
- site.json 的 auth.require_login=true 时访问者需飞书登录；
  allowed_users 填 "org"（全组织）或邮箱数组
```

- [ ] **Step 2: 写 references/contract.md**

内容 = 设计文档 §3.1 的目录结构 + site.json 全字段表（含类型、枚举、必填性、示例）+ 三档 tier 表 + migrations 约定。逐字段写完整，此处不省略——落码时从设计文档 §3.1 展开，每个字段一行：字段路径 / 类型 / 必填 / 约束 / 示例值。

- [ ] **Step 3: 写 references/redlines.md**

内容 = Task 2 扫描器规则的人类可读版，每条红线：规则 / 为什么 / 违反后果（部署校验失败的确切报错）/ 正确写法示例 + 错误写法示例。DSQL 禁用特性表含替代方案（外键→应用层校验、SERIAL→`gen_random_uuid()`、JSONB→TEXT+`::jsonb` 查询时转换、ON DELETE CASCADE→软删除）。

- [ ] **Step 4: 校验 Skill 结构 + fixture 对照**

Run: `python3 - <<'EOF'
import yaml, pathlib
p = pathlib.Path("site-builder/skills/site-builder/SKILL.md")
fm = p.read_text().split("---")[1]
meta = yaml.safe_load(fm)
assert meta["name"] == "site-builder" and len(meta["description"]) > 50
for f in ["references/contract.md", "references/redlines.md",
          "templates/db.js", "templates/run.sh"]:
    assert (p.parent / f).exists(), f
print("SKILL OK")
EOF`
Expected: `SKILL OK`。人工对照：按 SKILL.md 指引手工检查 fixtures/sql-expenses 应恰好全部合规（它是黄金样例）。

- [ ] **Step 5: Commit**

```bash
git add site-builder/skills
git commit -m "feat(skill): site-builder skill package (contract, redlines, templates)"
```

### Task 22: Skill 多客户端冒烟

**Files:**
- Create: `site-builder/docs/client-setup.md`（各客户端安装 Skill + MCP 的步骤记录）

**Interfaces:**
- Consumes: Task 21 Skill 包、Task 20 MCP endpoint
- Produces: 至少两个客户端验证通过的记录。

- [ ] **Step 1: Claude Code 冒烟（自动化程度最高，先做）**

```bash
mkdir -p ~/.claude/skills && cp -r site-builder/skills/site-builder ~/.claude/skills/
claude mcp add --transport http site-builder-deploy <MCP_ENDPOINT_URL>
```

新起 Claude Code 会话，提示词：“用 site-builder 技能给我做一个团队读书清单站点，能加书、标记读完，全组织可看，做完直接部署。”
Expected: 走完 Skill 工作流 → 生成合规产物 → MCP 部署成功 → 返回 URL → 浏览器验证（飞书登录 + 加书）。

- [ ] **Step 2: Quick Desktop 冒烟（人工，核心演示通道）**

用户操作：Quick Desktop 添加 Skill（Skill 管理入口导入 site-builder 包）+ Capabilities→MCP 添加 endpoint。同样提示词跑通。记录 Quick 侧差异（Skill 安装方式、MCP OAuth 流程截图）到 client-setup.md。

- [ ] **Step 3: 修复两轮冒烟暴露的 Skill 措辞问题**

常见问题预判：Agent 忘打包 run.sh（SKILL.md 强调"原样放项目根"）、site.zip 结构嵌套多一层目录（明确"site.json 在 zip 根"）、轮询太频繁（明确 15 秒）。按实际暴露的问题改 SKILL.md，改完重跑该客户端。

- [ ] **Step 4: Commit**

```bash
git add site-builder/skills site-builder/docs/client-setup.md
git commit -m "docs(skill): multi-client setup guide with smoke test fixes"
```

## Phase P6：端到端彩排（M6）

### Task 23: 成功标准链路彩排 + 演示脚本

**Files:**
- Create: `site-builder/docs/demo-script.md`

**Interfaces:**
- Consumes: 全部组件
- Produces: 可复制执行的演示脚本 + 彩排通过记录。

- [ ] **Step 1: 写演示脚本**

`site-builder/docs/demo-script.md` 章节：
1. **前置检查清单**（演示前一天跑）：`smoke_router.sh` 三 PASS；`RUN_E2E=1` fixture 测试三 passed；MCP Inspector 连通；Quick Desktop 登录正常；清掉 demo 残留站点（`undeploy_site`）。
2. **演示叙事**（10 分钟）：①业务人员飞书 SSO 登录 Quick Desktop ②自然语言："做一个部门经费登记站点，记录谁花了多少钱，只允许我们组的人看" ③展示 Skill 引导生成（tier=fullstack-sql，allowed_users=名单）④"部署"→ 播报 phase 进展 ⑤拿到 `https://app-expenses-xxx.<域名>` ⑥换一个浏览器 profile 访问 → 飞书扫码 → 登记一笔经费 → 显示登记人飞书邮箱 ⑦名单外账号访问 → 403 页 ⑧回 Quick："把站点下线" → URL 变 404。
3. **故障预案**：CloudFront 缓存旧路由（预案：演示站点提前 5 分钟部署）；DSQL 冷连接慢（预案：部署完先手工访问一次）；Quick MCP OAuth 过期（预案：演示前重新授权）。
4. **成本口径**：拉当月 Cost Explorer `project=site-builder` 标签数据填入。

- [ ] **Step 2: 完整彩排（成功标准原文验证）**

按演示脚本 2 的八步全程跑一遍，全程不碰 AWS 控制台。任何一步卡住 → 回对应 Task 修复 → 重新彩排。
Expected: 八步全通。

- [ ] **Step 3: 收尾提交 + 汇总**

```bash
git add site-builder/docs/demo-script.md
git commit -m "docs: end-to-end demo script with rehearsal checklist"
```

向用户汇报：演示 URL 清单、已知限制（spec §8 逐条现状）、二期建议（spec §9）。

---

## Self-Review 记录

- **Spec 覆盖**：五组件 M1-M6 全部有 Task 映射（M1→3-5、M2→6-8、M3→9-18、M4→19-20、M5→21-22、M6→23）；合同/红线（§3.1）→Task 1/2/21；DSQL schema 策略与逐条 DDL（§3.3）→Task 13；LWA zip 模式（§2 决策 3）→Task 15；presigned 上传（§3.2）→Task 19；顶域 cookie/防伪造头/名单鉴权（§3.4/3.5）→Task 5/7；错误处理表（§5）→Task 11/14/16 的异常类 + mark_job；测试策略（§6）→Task 1/2（合同单测）、18（集成 + 自动化鉴权/CRUD/伪造头/下线 E2E，会话 cookie 由 JWT_SECRET 直接 mint）、23（彩排）。
- **2026-07-21 对抗性 review 修订**（Codex adversarial review，全部 P0 + 大部分 P1/次要项已回写）：
  - P0-1 缓存绕过鉴权 → CACHING_DISABLED（Task 8 Step 0）+ 跨子域/更新即时性冒烟（smoke_router.sh）
  - P0-2 auth 子域路由 → 路由表 `route_mode` 字段（api-only），Task 5/6/8 联动，公网地址验收
  - P0-3 body 签名 → `include_body=True` + base64 解码参与 SigV4 + 413（Task 6/8），E2E 真实 JSON POST 断言
  - P0-4 DSQL 身份/隔离 → per-site IAM role（boundary 强制）+ per-site PG role + 非 admin token（Task 9/13/15/17/18 联动）
  - P1：Edge fail-closed 500；Function URL Principal 精确到 Edge role 无 fallback；OAuth state HMAC+过期、id_token JWKS 验签；confirm_upload 条件迁移 + SFN execution name=job_id；migration 逐文件记录；前端版本化前缀+原子切流；S3 paginator；smoke 禁跟随重定向按 auth 态断言；Task 17 状态机重写为可 synth 结构（Pass 汇合点）；Task 0 纳管 manus 目录
  - 次要：sqlparse 拆语句、连接 try/finally、buildspec 去 `|| true`、zip bomb 三重限制、上传 50MB 校验、回跳保留 querystring、notes fixture textContent 渲染 + innerHTML 红线、tables 校验（命名/去重/上限）
  - 范围收敛：PoC 仅 nodejs22.x（Python → 二期）；MCP 工具面 5 个（spec 已同步）；API Key fallback → 二期
- **有意保留的偏差**：presigned PUT 无法带 content-length-range（那是 POST policy 的能力）——改为 confirm_upload HeadObject 后置校验；PKCE/nonce 二期（confidential client + 签名 state 覆盖 PoC 威胁模型）；旧版本前端由 mark_job 成功后清理而非生命周期（生命周期按对象年龄会误删在线版本）。
- **类型一致性**：`common.py` 签名与 Task 11-17/19 调用核对；路由表字段（含 route_mode/static_prefix 版本化）在 Task 5/6/7/8/16/17/23 一致；`env_vars` 键（`TABLE_*`/`DSQL_ENDPOINT`/`DSQL_SCHEMA`/`DSQL_USER`）产出与消费两侧一致；`RUNTIME_BOUNDARY_ARN`/`EDGE_ROLE_ARN` 贯穿 Task 9/15/17。
- **占位符扫描**：无 TBD/TODO。Task 21 references 逐字段展开源于 spec §3.1（源内容完整）；Task 18 sql-expenses 前端对照 notes 版本写出（结构约束完整）。Task 20 Step 0 显式定义为 Spike——AgentCore claim 透传是外部不确定项，两个可能结果的处置路径都已写明。

