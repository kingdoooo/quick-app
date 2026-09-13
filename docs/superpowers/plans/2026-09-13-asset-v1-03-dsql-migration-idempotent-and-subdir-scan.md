# DSQL 迁移幂等 + migrations 子目录扫描（asset-v1 工单 03，M03+M16）Implementation Plan

> **决策记录，不是操作指引。** 本文含单账号实测数据与当时的取舍过程，按写下的那一刻为准；
> 采用者要的操作步骤真源是 `site-builder/DEPLOY.md`，还剩什么没做看 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** DSQL 建库/迁移半途失败后同输入重试要么幂等成功、要么在 provision-db 响亮失败并给出补救办法，且 `migrations/` 子目录里的 SQL 不再能绕过红线扫描。

**Architecture:** 处方分两层落地。**合同层（validate 之前，最便宜的拦截点）**：新增一条"可重放"红线，用**白名单**只放行 AWS 文档确认幂等的 DDL/DML 形态，其余一律拒；`migrations/` 下出现子目录即拒；`FORBIDDEN_DDL` 的扫描面从只扫 `schema.sql` 扩到全部被执行的 `.sql` 文件。**执行层（provision-db）**：列举迁移对象时加 `Delimiter="/"`（不再递归看子目录，与合同层口径一致）；admin 引导连接上加一次 catalog 探测，在"schema 已证明为空但 marker 非空"这个可自愈的失配上自愈并写审计行；marker 读取改强一致；`run_file` 失败时抛出含文件名/语句序号/SQLSTATE/已提交对象/补救办法的富错误。下线的 `purge_data` 路径补上清 marker（今天 5 条让 marker 失效的路径只覆盖了 1 条，catalog 守卫兜住其余 4 条）。

**Tech Stack:** Python 3.12、pytest、moto（`mock_aws`）、`unittest.mock`（连接层 mock + 有状态 fake cursor）、boto3（DynamoDB/S3）、sqlparse（**仅执行器侧** `provision_dsql._statements`；合同层不引入 sqlparse——见 Task 3 的口径说明）。

**Spec:**
- `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`：M03（:284-329）、M16（:956-978）、§9 第 7 行（:1221）、处方裁决表（:28-34）。
- 工单：`.scratch/asset-v1/issues/03-dsql-migration-idempotent-and-subdir-scan.md`。
- AWS 文档（本计划的白名单依据，已核）：
  - 支持的 SQL 子集 `https://docs.aws.amazon.com/aurora-dsql/latest/userguide/working-with-postgresql-compatibility-supported-sql-features.html`
  - 一事务一条 DDL、DDL 与 DML 不能同事务 `https://docs.aws.amazon.com/aurora-dsql/latest/userguide/working-with-ddl.html`
  - `CREATE VIEW` 支持 `OR REPLACE`（幂等形态）`https://docs.aws.amazon.com/aurora-dsql/latest/userguide/create-view.html`

## Global Constraints

以下每条对每个 task 都隐含生效，值逐字照抄，不要改写：

- **不并行跑七套件。** `contract/tests/test_redlines.py` 有一条墙钟哨兵（3000 组 decode，10 秒内），对机器争用敏感。看到它红先单独重跑一次再判断。
- **本票至少要 `contract` 与 `deployer` 两侧全绿。** 当前基线：contract 174 / deployer 1752+52s。测试命令照抄根 `CLAUDE.md`「测试命令」：
  - `(cd site-builder/contract && .venv/bin/pytest tests -q)`
  - `(cd site-builder/deployer && .venv/bin/pytest tests -q)`
- **改 `contract/` 的红线必须同步四处**（根 `CLAUDE.md` 跨组件矩阵）：校验器 `contract/src/contract/redlines.py`、Skill references（`skills/site-builder/references/{redlines,contract}.md`）、`site-builder/fixtures/`、生成模板（本仓库 `skills/.../templates/` 下**没有** `.sql` 模板，Task 5 已核；只需核 fixtures）。
- **校验器与执行器的命名/列举口径必须一致。** `_dsql_sql_files` 的 docstring 明写"多扫或少扫都会与真实行为不符"。改了执行器的匹配/列举规则就必须同步校验器，反之亦然。本票两侧同时改：校验器拒子目录 ⇔ 执行器 `Delimiter="/"`。
- **`references/{contract,redlines}.md` 与 `DEPLOY.md` 在 `_STATUS_FREE_DOCS` 里**：新写的散文不许有日期、commit SHA 或「已部署／尚未／待做／已于／ticket N 起」这类状态词。证据强度写"实测过"，不写具体日期。
- **`git commit` 绝不带 `--no-verify`**（根 `CLAUDE.md` Git 段）。提交前 `git add` 后单独跑 `bash site-builder/scripts/scan_staged_secrets.sh` 并看 `$?`（经管道退出码会被吞）。
- **默认不跑真机。** 证据强度如实标"mock 层 + AWS 文档核实"。白名单红线的正确性不依赖 `CREATE SCHEMA`/`DROP TABLE` 的 IF 形态到底行不行（选白名单的全部好处）；两条反例都能在 mock 层证明。

## DML 子决策（本计划裁定，理由留痕）

**裁定：采纳处方倾向的 (b) —— `schema.sql`/migrations 里的 DML（`INSERT` 种子数据）必须带 `ON CONFLICT DO NOTHING`，否则红线拒。**

- **为什么不选 (a) 禁止 DML**：种子数据是站点作者的真实需求（枚举表、初始配置行）。禁掉会逼作者把种子塞进应用启动代码，那既绕开了合同层的可重放保证，又让"数据初始化"散落到不可信站点代码里。
- **为什么不选 (c) 只警告**：本票的完成判据是"同输入重试幂等"。裸 `INSERT` 重放会重复插入，是本票要消灭的不幂等来源之一，只警告等于留着它。
- **为什么 (b) 自洽**：`ON CONFLICT DO NOTHING` 需要一个唯一约束（PK 或 UNIQUE）作冲突目标，而 fixture/文档里的建表约定本就是每表带 `PRIMARY KEY`（`sql-expenses` 的 `id UUID PRIMARY KEY`）。要求 `ON CONFLICT DO NOTHING` 与这条既有约定同向，不引入新约束。
- **F1 不阻碍 (b)**：DSQL 禁止 DDL 与 DML 同事务、每事务一条 DDL——但执行器是 **autocommit**，每条语句各自一个事务，`INSERT` 独立成事务合法。禁的是 `BEGIN; DDL; DML; COMMIT;` 这种包裹（合同层与文档本就禁 `BEGIN`/`COMMIT`）。

## 处方与裁定的映射（六条，别重新论证）

| 裁定 | 落在哪个 Task |
|---|---|
| 1. 子目录**拒**（校验器加红线 + 执行器 `Delimiter="/"`）；M16「marker 键含相对路径」因此无事可做 | Task 1（校验器）+ Task 6（执行器） |
| 2. `schema.sql` 与 `migrations/*.sql` 同等对待（可重放红线两者都管） | Task 2、Task 3 |
| 3. 幂等按 merged review 组合方案：① 白名单可重放 + ④ 富失败信息 + ② 降级为红线白名单，不做语句级 marker；③ 单独开票 | Task 3（①②）、Task 8（④） |
| 4. `undeploy(purge_data=True)` 清 marker + catalog 守卫 | Task 9（守卫）+ Task 10（purge 清 marker） |
| 5. catalog 守卫失配时**自愈 + 写审计行**（非 fail closed） | Task 9 |
| 6. `provision_dsql` 的 `get_site` 换 `get_site_consistent` | Task 7 |

**M16 的「marker 键含相对路径」为什么无事可做（写明以免有人以为漏做）**：一旦拒了 `migrations/` 子目录，所有被执行的迁移文件都在 `migrations/` 直下，basename 就是相对路径（相对 `migrations/`），跨目录同名 basename 撞车问题从根上不存在。所以不需要把 marker 从 basename 改成含相对路径——那是"对齐两处递归规则"的做法，本票选的是"消灭递归"。

---

### Task 1: 校验器拒绝 `migrations/` 子目录（M16 校验器半边 A）

**Files:**
- Modify: `site-builder/contract/src/contract/redlines.py`（`scan_redlines` 的 dsql 段，约 `:441-461`）
- Test: `site-builder/contract/tests/test_redlines.py`

**Interfaces:**
- Consumes: `scan_redlines(site_dir: Path, manifest: dict) -> list[str]`（既有签名不变）；`_dsql_sql_files(backend_dir) -> list[Path]`（既有，非递归 `glob("*.sql")`）。
- Produces: 当 `manifest.database.engine == "dsql"` 且 `backend/migrations/` 下存在任何子目录时，`scan_redlines` 返回里含一条以 `backend/migrations/` 开头、含"不允许子目录"的违规串。

- [ ] **Step 1: 写失败测试**

在 `test_redlines.py` 末尾追加（沿用文件里既有的建站点目录 helper；若没有就用 `tmp_path` 直接铺文件）：

```python
def _dsql_site(tmp_path, *, schema="CREATE TABLE IF NOT EXISTS t (id UUID PRIMARY KEY);\n",
               migrations=None, subdirs=None):
    """铺一个最小 fullstack-sql 站点目录，返回 (site_dir, manifest)。"""
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "index.html").write_text("<!doctype html><h1>ok</h1>")
    be = tmp_path / "backend"
    be.mkdir()
    (be / "schema.sql").write_text(schema)
    (be / "server.js").write_text("app.get('/api/health',(q,r)=>r.json({ok:1}))")
    (be / "package.json").write_text('{"dependencies":{}}')
    (be / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{}}}}')
    for name, body in (migrations or {}).items():
        (be / "migrations").mkdir(exist_ok=True)
        (be / "migrations" / name).write_text(body)
    for sub, files in (subdirs or {}).items():
        d = be / "migrations" / sub
        d.mkdir(parents=True)
        for name, body in files.items():
            (d / name).write_text(body)
    manifest = {"name": "t", "tier": "fullstack-sql",
                "database": {"engine": "dsql"}}
    return tmp_path, manifest


def test_migrations_subdirectory_is_rejected(tmp_path):
    from contract.redlines import scan_redlines
    site_dir, manifest = _dsql_site(
        tmp_path,
        subdirs={"nested": {"001_x.sql": "CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"}})
    v = scan_redlines(site_dir, manifest)
    assert any("backend/migrations/" in s and "子目录" in s for s in v), v
```

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py::test_migrations_subdirectory_is_rejected -q)`
Expected: FAIL（当前无子目录检查，`v` 里没有该违规）。

- [ ] **Step 3: 加子目录检查**

在 `redlines.py` 的 dsql 段（`if manifest.get("database", {}).get("engine") == "dsql":` 块内，`_dsql_sql_files` 循环**之前**）插入：

```python
        # M16 裁定 1：migrations/ 只允许直下的 NNN_*.sql，**拒绝子目录**。
        # 执行器侧同步加了 Delimiter="/"（provision_dsql.list 不再递归），两处口径
        # 一致——这是消灭"执行器扫的 ⊋ 校验器扫的"这个不一致，不是对齐它。
        migrations_dir = backend_dir / "migrations"
        if migrations_dir.is_dir():
            for child in sorted(migrations_dir.iterdir()):
                if child.is_dir():
                    violations.append(
                        f"backend/migrations/{child.name}/: 不允许子目录——迁移文件"
                        "必须直接放在 backend/migrations/ 下（执行器只扫直下层，"
                        "子目录里的 SQL 会被执行却不被红线扫描）")
```

- [ ] **Step 4: 跑测试确认通过**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py::test_migrations_subdirectory_is_rejected -q)`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/contract/src/contract/redlines.py site-builder/contract/tests/test_redlines.py
git commit -m "feat(contract/03): 拒绝 migrations/ 子目录（M16 校验器半边）"
```

---

### Task 2: `FORBIDDEN_DDL` 扫描面扩到全部被执行的 `.sql` 文件（M16 校验器半边 B，F6）

**Files:**
- Modify: `site-builder/contract/src/contract/redlines.py`（dsql 段 `:441-461`）
- Test: `site-builder/contract/tests/test_redlines.py`

**Interfaces:**
- Consumes: `_dsql_sql_files(backend_dir)`（Task 1 未改其行为）、`FORBIDDEN_DDL`（既有常量）、`CREATE_INDEX_RE`（既有）。
- Produces: `migrations/NNN_*.sql` 里含 `FORBIDDEN_DDL` 关键词时 `scan_redlines` 返回对应违规（此前只 `schema.sql` 报）。

**动机（写进提交信息）**：`FORBIDDEN_DDL` 今天只扫 `schema.sql`（`:441-449`），索引规则两者都扫（`:454-460`）。migration 文件里的禁用 DDL 在 validate 抓不到、只在执行时半途炸——这正是 M03 永久 brick 的触发条件（F6）。

- [ ] **Step 1: 写失败测试**

```python
def test_forbidden_ddl_scanned_in_migration_files(tmp_path):
    from contract.redlines import scan_redlines
    site_dir, manifest = _dsql_site(
        tmp_path,
        migrations={"001_bad.sql": "ALTER TABLE IF EXISTS t ADD COLUMN IF NOT EXISTS n SERIAL;\n"})
    v = scan_redlines(site_dir, manifest)
    assert any("migrations/001_bad.sql" in s and "SERIAL" in s for s in v), v
```

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py::test_forbidden_ddl_scanned_in_migration_files -q)`
Expected: FAIL（`FORBIDDEN_DDL` 目前只看 `schema.sql`）。

- [ ] **Step 3: 把 `FORBIDDEN_DDL` 检查移进 `_dsql_sql_files` 循环**

把 dsql 段里"只对 `schema.sql` 做 `FORBIDDEN_DDL`"那段（`:441-449` 的 `schema = backend_dir / "schema.sql"` … `for kw in FORBIDDEN_DDL:`）删掉，改为：`schema.sql` 缺失的检查单独留下（它是 fullstack-sql 的硬性要求），`FORBIDDEN_DDL` 与 `CREATE_INDEX_RE` 都在 `_dsql_sql_files` 循环里对每个文件跑。替换后的 dsql 段（Task 1 的子目录检查之后）：

```python
        schema = backend_dir / "schema.sql"
        if not schema.exists():
            violations.append("backend/schema.sql: fullstack-sql 必须提供建表 SQL")

        # 禁用特性 + 索引 ASYNC 对 schema.sql 与 migrations/*.sql **一视同仁**：
        # provision_dsql.py 用同一个 migrator 连接、同样逐条 execute 两者，所以
        # 禁用 DDL / 同步建索引在哪个文件里都会在 provision-db 阶段失败。只扫
        # schema.sql 会让"写进 migrations 就绕过"——绕过的结果是部署半途炸（M03）。
        for sql_file in _dsql_sql_files(backend_dir):
            rel = sql_file.relative_to(backend_dir.parent).as_posix()
            body = sql_file.read_text(errors="replace")
            # FORBIDDEN_DDL 是大写后子串匹配（注释里出现也命中，与既有口径一致）
            body_upper = body.upper()
            for kw in FORBIDDEN_DDL:
                if kw in body_upper:
                    violations.append(
                        f"{rel}: 含 DSQL 不支持的 {kw}（见红线文档替代方案）")
            if CREATE_INDEX_RE.search(body):
                violations.append(
                    f"{rel}: DSQL 建索引必须写 CREATE INDEX ASYNC"
                    "（同步建索引报 unsupported mode，站点会部署失败）")
```

（注意 `_dsql_sql_files` 已含 `schema.sql`，所以 `schema.sql` 的禁用特性检查也走这个循环——`rel` 会是 `backend/schema.sql`，与旧文案兼容。旧的 `test_redlines.py` 里断言 `backend/schema.sql: 含 DSQL 不支持的 …` 的用例仍绿。）

- [ ] **Step 4: 跑测试确认通过 + 既有 dsql 用例不回归**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py -q -k "dsql or forbidden or index or schema or migration")`
Expected: PASS（含旧的 `schema.sql` 禁用特性用例）。

- [ ] **Step 5: 提交**

```bash
git add site-builder/contract/src/contract/redlines.py site-builder/contract/tests/test_redlines.py
git commit -m "feat(contract/03): FORBIDDEN_DDL/索引扫描面扩到 migrations（M16 校验器半边）"
```

---

### Task 3: 可重放白名单红线（裁定 3①②；DML 采纳 (b)）

**Files:**
- Modify: `site-builder/contract/src/contract/redlines.py`（新增 `_sql_statements`、`_REPLAYABLE_FORMS`、`_check_sql_replayable`；接进 Task 2 的 `_dsql_sql_files` 循环）
- Test: `site-builder/contract/tests/test_redlines.py`

**Interfaces:**
- Consumes: 各文件的 SQL 文本。
- Produces: 新函数 `_check_sql_replayable(sql_text: str, rel: str) -> list[str]`；`scan_redlines` 对每个 `_dsql_sql_files` 文件追加它的返回。

**白名单判据（AWS 文档已核；`schema.sql` 与 migrations 一视同仁）**——只放行以下幂等形态，其余一律拒（选白名单而非黑名单：`CREATE SCHEMA`/`DROP TABLE`/`CREATE SEQUENCE` 等的 IF 形态文档未确认幂等，直接拒、不需真机验证）：

1. `CREATE TABLE IF NOT EXISTS …`
2. `CREATE [UNIQUE] INDEX ASYNC IF NOT EXISTS <name> …`（用 IF NOT EXISTS 时索引名必填）
3. `ALTER TABLE [IF EXISTS] … ADD COLUMN IF NOT EXISTS …`
4. `ALTER TABLE [IF EXISTS] … DROP COLUMN IF EXISTS …`
5. `ALTER TABLE [IF EXISTS] … DROP CONSTRAINT IF EXISTS …`
6. `CREATE OR REPLACE VIEW …`（DSQL 文档确认支持 `OR REPLACE`，重放即替换、不报错）
7. `INSERT INTO … ON CONFLICT DO NOTHING …`（DML，见上「DML 子决策」(b)）

**口径说明（写进 docstring，Global Constraints 第 4 条）**：合同层**不引入 sqlparse**（执行器侧用的 sqlparse 有 0.6.0/0.5.5 生产/测试版本偏斜，见 F2；给合同再加一份只会放大偏斜面）。合同层用一个**保守的**切分器：先把 `--`/`/* */` 注释与单引号字符串抹白，再按 `;` 切。字符串里的 `;`（如 `DEFAULT 'a;b'`）因已抹白不会误切。切完对每条判白名单——切法与执行器不必字节一致，因为本检查偏保守（宁可误报）：切碎产生的非关键词片段会落到"不在白名单"分支被拒，方向安全。

- [ ] **Step 1: 写失败测试（正例放行 + 每类反例被拒）**

```python
import pytest
from contract.redlines import _check_sql_replayable


@pytest.mark.parametrize("sql", [
    "CREATE TABLE IF NOT EXISTS t (id UUID PRIMARY KEY);",
    "CREATE INDEX ASYNC IF NOT EXISTS idx_t ON t (id);",
    "CREATE UNIQUE INDEX ASYNC IF NOT EXISTS uq_t ON t (id);",
    "ALTER TABLE IF EXISTS t ADD COLUMN IF NOT EXISTS c TEXT;",
    "ALTER TABLE t ADD COLUMN IF NOT EXISTS c TEXT;",
    "ALTER TABLE IF EXISTS t DROP COLUMN IF EXISTS c;",
    "ALTER TABLE IF EXISTS t DROP CONSTRAINT IF EXISTS ck;",
    "CREATE OR REPLACE VIEW v AS SELECT id FROM t;",
    "INSERT INTO t (id) VALUES (gen_random_uuid()) ON CONFLICT DO NOTHING;",
    "CREATE TABLE IF NOT EXISTS t (id UUID PRIMARY KEY, note TEXT DEFAULT 'a;b');",  # 串内分号
    "-- 只是注释 DROP TABLE t;\nCREATE TABLE IF NOT EXISTS t (id UUID PRIMARY KEY);",  # 注释里的坏词不算
])
def test_replayable_forms_pass(sql):
    assert _check_sql_replayable(sql, "backend/schema.sql") == []


@pytest.mark.parametrize("sql", [
    "CREATE TABLE t (id UUID PRIMARY KEY);",                 # 缺 IF NOT EXISTS
    "CREATE SCHEMA foo;",                                    # 白名单外
    "DROP TABLE t;",                                         # 白名单外
    "ALTER TABLE t ADD COLUMN c TEXT;",                      # ADD COLUMN 缺 IF NOT EXISTS
    "ALTER TABLE t ALTER COLUMN c TYPE INT;",               # ALTER COLUMN 不在白名单
    "CREATE VIEW v AS SELECT 1;",                            # 缺 OR REPLACE
    "INSERT INTO t (id) VALUES (gen_random_uuid());",        # DML 缺 ON CONFLICT DO NOTHING
    "UPDATE t SET c = '1';",                                 # 白名单外
    "DELETE FROM t;",                                        # 白名单外
    "CREATE INDEX ASYNC ON t (id);",                         # 缺 IF NOT EXISTS（幂等）
])
def test_non_replayable_forms_flagged(sql):
    out = _check_sql_replayable(sql, "backend/schema.sql")
    assert out and "backend/schema.sql" in out[0], out
```

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py -q -k replayable)`
Expected: FAIL（`_check_sql_replayable` 尚不存在，import 即 error）。

- [ ] **Step 3: 实现切分器 + 白名单**

在 `redlines.py`（`CREATE_INDEX_RE` 附近，方便一处读懂 DSQL 相关正则）加：

```python
# 可重放白名单（M03 裁定 3①②）：只放行 AWS 文档确认幂等的 DDL/DML 形态。
# 判据是白名单——文档未确认 IF 形态幂等的（CREATE SCHEMA / DROP TABLE / CREATE
# SEQUENCE / CREATE STATISTICS / CREATE FUNCTION 等）一律拒，不需真机验证。
# 每条正则锚在**规范化后**（注释/字符串抹白、空白折叠为单空格）的语句串开头。
_REPLAYABLE_FORMS = (
    re.compile(r"^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b", re.I),
    # CREATE [UNIQUE] INDEX ASYNC IF NOT EXISTS <name>：用 IF NOT EXISTS 时名字必填
    re.compile(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\s+ASYNC\s+IF\s+NOT\s+EXISTS\s+\S+", re.I),
    # ALTER TABLE [IF EXISTS] … <幂等动作>。要求出现幂等动作、且不出现任何非幂等动作
    re.compile(r"^ALTER\s+TABLE\b(?:\s+IF\s+EXISTS)?\b.*"
               r"\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\b", re.I | re.S),
    re.compile(r"^ALTER\s+TABLE\b(?:\s+IF\s+EXISTS)?\b.*"
               r"\bDROP\s+COLUMN\s+IF\s+EXISTS\b", re.I | re.S),
    re.compile(r"^ALTER\s+TABLE\b(?:\s+IF\s+EXISTS)?\b.*"
               r"\bDROP\s+CONSTRAINT\s+IF\s+EXISTS\b", re.I | re.S),
    re.compile(r"^CREATE\s+OR\s+REPLACE\s+(?:RECURSIVE\s+)?VIEW\b", re.I),
    # DML：种子 INSERT 必须带 ON CONFLICT DO NOTHING（DML 子决策 (b)），否则重放重复插入
    re.compile(r"^INSERT\s+INTO\b.*\bON\s+CONFLICT\b.*\bDO\s+NOTHING\b", re.I | re.S),
)
_REPLAYABLE_HINT = (
    "迁移/建表 SQL 必须可重放（DSQL 无原子事务，半途失败重试会重跑本文件）。"
    "允许的形态：CREATE TABLE IF NOT EXISTS；CREATE [UNIQUE] INDEX ASYNC IF NOT "
    "EXISTS <名>；ALTER TABLE 的 ADD COLUMN IF NOT EXISTS / DROP COLUMN IF EXISTS "
    "/ DROP CONSTRAINT IF EXISTS；CREATE OR REPLACE VIEW；INSERT … ON CONFLICT DO "
    "NOTHING。其余（CREATE SCHEMA/DROP TABLE/裸 CREATE TABLE/裸 INSERT/UPDATE/"
    "DELETE 等）一律拒")


def _sql_statements(text: str) -> list[str]:
    """把 SQL 抹掉注释/字符串后按 `;` 切成规范化语句串（大小写不变、空白折叠）。

    **保守切分，偏误报**（redlines 一贯口径）：不引入 sqlparse（执行器侧那份有
    0.6.0/0.5.5 版本偏斜，见 F2，合同层不再放大它）。字符串内的 `;` 因先被抹白
    不会误切；切碎产生的非关键词片段会在白名单里落到"不匹配"分支被拒——方向安全。
    """
    text = re.sub(r"--[^\n]*", " ", text)          # 行注释
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)  # 块注释
    text = re.sub(r"'(?:''|[^'])*'", "''", text)   # 单引号字符串（含 '' 转义）→ 空串占位
    out = []
    for raw in text.split(";"):
        s = re.sub(r"\s+", " ", raw).strip()
        if s:
            out.append(s)
    return out


def _check_sql_replayable(sql_text: str, rel: str) -> list[str]:
    """每条语句必须落在 _REPLAYABLE_FORMS 白名单里，否则报违规。"""
    out = []
    for stmt in _sql_statements(sql_text):
        if not any(p.match(stmt) for p in _REPLAYABLE_FORMS):
            snippet = stmt[:60] + ("…" if len(stmt) > 60 else "")
            out.append(f"{rel}: 不可重放的语句 `{snippet}`——{_REPLAYABLE_HINT}")
    return out
```

- [ ] **Step 4: 接进 `_dsql_sql_files` 循环**

在 Task 2 那个 `for sql_file in _dsql_sql_files(backend_dir):` 循环体内、索引检查之后追加：

```python
            violations += _check_sql_replayable(body, rel)
```

- [ ] **Step 5: 跑测试确认通过**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py -q -k replayable)`
Expected: PASS

- [ ] **Step 6: 全量 contract 套件（确认没误伤既有 dsql/fixture 用例）**

Run: `(cd site-builder/contract && .venv/bin/pytest tests -q)`
Expected: PASS（174 起步；本票新增用例后计数增加）。若 `test_redlines.py` 里既有的"正确 schema.sql 样例"用例因新红线变红，说明样例本身不可重放——按 Task 5 的口径核对后修样例，不要放宽红线。

- [ ] **Step 7: 提交**

```bash
git add site-builder/contract/src/contract/redlines.py site-builder/contract/tests/test_redlines.py
git commit -m "feat(contract/03): 可重放白名单红线（M03 强制幂等 DDL/DML）"
```

---

### Task 4: 同步 Skill references（修自相矛盾 + 补新红线说明）

**Files:**
- Modify: `site-builder/skills/site-builder/references/redlines.md`
- Modify: `site-builder/skills/site-builder/references/contract.md`
- Test: 无新单测（文档）；由 `deployer/tests/test_delivery_docs_current.py` 的状态守卫与 Task 11 的全量跑核对。

**裁定（contract.md `:126-128` 的「已应用文件不可再修改」要不要收紧）**：**不收紧，保持原文**。理由：那条规则约束的是"marker 会跳过已应用文件"，与"文件内容是否可重放"正交——即便内容现在必须可重放，marker 仍按文件名跳过，改已应用文件也不会重跑。收紧它（比如"允许改，因为可重放了"）反而会误导站点作者以为改了会自动重跑。只在该条附近加一句点出"可重放是为了自愈/purge 重跑时安全"，不改其语义。

- [ ] **Step 1: 修 `redlines.md` 的自相矛盾**

`redlines.md` 现有两处冲突（红线 7 段内）：`:146` 说索引规则"对 `schema.sql` 与 `migrations/*.sql` 一视同仁"（与代码一致，保留），而 JSONB 段后那句"migrations 文件不做静态扫描，但同样的禁用特性会在 provision-db 执行时直接报 SQL 错误"（与 Task 2 后的代码矛盾——migrations **现在被扫**）。把后一句改为：

```markdown
  禁用特性表与索引 ASYNC 规则对 `schema.sql` 与 `migrations/*.sql` **一视同仁**，
  在 validate 阶段静态扫描——写 migrations 时同样遵守本表。
```

- [ ] **Step 2: 在 `redlines.md` 加"可重放"红线说明**

在红线 7 之后、红线 8 之前新增一节（编号顺延为红线 8，原红线 8「后端依赖锁定」顺延为红线 9；**全文替换该文件里所有 `红线 8` 引用**为 `红线 9`——用 grep 核对 `grep -n "红线 8" redlines.md` 只剩新节自己）：

```markdown
## 红线 8：DSQL 建表/迁移必须可重放（仅 fullstack-sql）

- **规则**：`schema.sql` 与 `migrations/*.sql` 里每条语句都必须是下列**可重放**形态之一，否则 validate 拒：
  - `CREATE TABLE IF NOT EXISTS …`
  - `CREATE [UNIQUE] INDEX ASYNC IF NOT EXISTS <索引名> …`（用 `IF NOT EXISTS` 时索引名必填）
  - `ALTER TABLE [IF EXISTS] … ADD COLUMN IF NOT EXISTS …` / `DROP COLUMN IF EXISTS …` / `DROP CONSTRAINT IF EXISTS …`
  - `CREATE OR REPLACE VIEW …`
  - `INSERT INTO … ON CONFLICT DO NOTHING …`（种子数据）
- **为什么**：DSQL 每条语句 autocommit、且 DSQL 与平台元数据之间**没有原子事务**。一条迁移文件跑到一半失败（typo 或超时），前面的语句已提交、"这个文件跑过了"的标记却没写——重试会从头重跑本文件。不可重放的语句（裸 `CREATE TABLE`、裸 `INSERT`）第二次撞上"已存在/重复插入"而失败，站点卡在"同一份产物再也部署不上去"，直到 SQL 被改成可重放。
- **`migrations/` 子目录被拒**：迁移文件必须直接放在 `backend/migrations/` 下（执行器只扫直下层）。
- **违反后果**：`backend/schema.sql: 不可重放的语句 \`…\`——…` / `backend/migrations/xxx/: 不允许子目录……`
- **正确**：见下面的样例；**错误**：裸 `CREATE TABLE orders (…)`、`INSERT INTO seed …`（无 `ON CONFLICT DO NOTHING`）、`CREATE VIEW v …`（无 `OR REPLACE`）。
```

- [ ] **Step 3: 更新 `redlines.md` 的样例，确保示范全部可重放**

现有"正确 schema.sql 样例"（`CREATE TABLE IF NOT EXISTS` + `CREATE INDEX ASYNC IF NOT EXISTS`）已可重放，保留。在"错误写法"块里，`CREATE TABLE orders (…)`（无 `IF NOT EXISTS`）现在**又多一条**违规（不可重放），在该块注释里点明：

```sql
CREATE TABLE orders (          -- 违规：缺 IF NOT EXISTS（不可重放）+ 下面三处
  id SERIAL PRIMARY KEY,       -- 违规：SERIAL
  ...
```

- [ ] **Step 4: 更新 `contract.md` 的 migrations 约定**

在 `contract.md`「migrations 约定」段（`:119-131`）补两条，并在"已应用文件不可再修改"那条后加一句（不改语义）：

```markdown
- **子目录被拒**：迁移文件必须直接放在 `backend/migrations/` 下，`migrations/` 里
  不允许再建子目录（执行器只扫直下层的 `NNN_*.sql`，子目录里的 SQL 会被静态扫描拒绝）。
- **每条语句必须可重放**：见 `references/redlines.md` 红线 8。半途失败的迁移会整文件重试，
  不可重放的语句第二次会撞"已存在/重复插入"而卡死部署。
```

在"已应用过的文件内容**不可再修改**"那句后追加：

```markdown
  （可重放不改变这条：marker 仍按文件名跳过已应用文件，可重放只是保证自愈/下线
  重跑 `schema.sql` 时安全。）
```

- [ ] **Step 5: 核对状态守卫词表**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q)`
Expected: PASS（新写散文无日期/SHA/状态词）。若红，检查新增文字里有没有触发词。

- [ ] **Step 6: 提交**

```bash
git add site-builder/skills/site-builder/references/redlines.md site-builder/skills/site-builder/references/contract.md
git commit -m "docs(03): references 修 migrations 扫描口径矛盾 + 可重放红线说明"
```

---

### Task 5: 核对 fixtures 与模板符合新红线（跨组件矩阵第 3 处）

**Files:**
- 只读核对：`site-builder/fixtures/**/backend/{schema.sql,migrations/*.sql}`、`site-builder/skills/site-builder/templates/`
- Test: `site-builder/deployer/tests/`（fixture 一致性用例，若存在）、Task 11 的全量跑

- [ ] **Step 1: 枚举所有 fixture/模板里的 SQL**

Run:
```bash
cd "$(git rev-parse --show-toplevel)"
find site-builder/fixtures -name '*.sql'
find site-builder/skills/site-builder/templates -name '*.sql'   # 预期为空（本仓库无 SQL 模板）
```
Expected: 只 `site-builder/fixtures/sql-expenses/backend/schema.sql`；templates 无 `.sql`（已核）。

- [ ] **Step 2: 用真校验器验 fixture**

写一次性核对（可放临时脚本或 python -c）——**用生产校验器本体**，不手抄判定：
```bash
cd site-builder/contract
.venv/bin/python -c "
from pathlib import Path
from contract.redlines import _check_sql_replayable, _dsql_sql_files
be = Path('../fixtures/sql-expenses/backend')
for f in _dsql_sql_files(be):
    rel = f.relative_to(be.parent).as_posix()
    print(rel, _check_sql_replayable(f.read_text(), rel) or 'OK')
"
```
Expected: `backend/schema.sql OK`（F11：单条 `CREATE TABLE IF NOT EXISTS`、无 DML，已符合）。

- [ ] **Step 3: 若有 fixture 一致性/黄金样例用例，跑它**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests -q -k "fixture or golden or template")`
Expected: PASS。若某 fixture 因新红线变红，**修 fixture 使其可重放**（不放宽红线）；模板与 fixture 字节一致的约定由既有守卫保证。

- [ ] **Step 4: 提交（仅当有 fixture 改动）**

```bash
git add -A site-builder/fixtures
git commit -m "test(03): fixture SQL 核对符合可重放红线"
```
（若无改动，跳过提交，在 Task 11 的工单 Comments 记"fixtures 已符合，无需改动"。）

---

### Task 6: 执行器列举迁移加 `Delimiter="/"` + paginator（裁定 1 执行器半边；M16 分页边界）

**Files:**
- Modify: `site-builder/deployer/functions/provision_dsql.py`（`:156-161`）
- Test: `site-builder/deployer/tests/test_provision_dsql.py`

**Interfaces:**
- Consumes: S3 `extracted/{job_id}/backend/migrations/` 前缀下的对象。
- Produces: 执行器只列举 `migrations/` **直下**、basename 匹配 `^\d{3}_.+\.sql$` 的对象；子目录对象（`migrations/sub/…`）不再被列举执行。

**动机**：与 Task 1 的校验器口径一致（消灭"执行器扫的 ⊋ 校验器扫的"）。`Delimiter="/"` 让子目录对象落到 `CommonPrefixes`、不进 `Contents`。顺带用 paginator 关掉 merged review 给 M16 补的"`list_objects_v2` 无 paginator"边界（§9 :34）。

- [ ] **Step 1: 写失败测试**

```python
def test_migrations_in_subdirectory_are_not_executed(aws):
    import common
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql", b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    _put("job-1", "backend/migrations/001_ok.sql", b"ALTER TABLE IF EXISTS a ADD COLUMN IF NOT EXISTS x TEXT;")
    # 子目录里的迁移：加 Delimiter 后不应被列举/执行（校验器已在 validate 拒掉这类站点）
    _put("job-1", "backend/migrations/nested/002_bad.sql", b"ALTER TABLE IF EXISTS a ADD COLUMN IF NOT EXISTS y TEXT;")
    _, _, mig_sqls, _, _ = _run()
    applied = common.get_site("exp-a1b2c3")["migrations_applied"]
    assert "001_ok.sql" in applied
    assert "002_bad.sql" not in applied
    assert not any("COLUMN y" in s for s in mig_sqls)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py::test_migrations_in_subdirectory_are_not_executed -q)`
Expected: FAIL（当前 `list_objects_v2` 无 Delimiter，`PurePosixPath(key).name` 把 `nested/002_bad.sql` 取成 `002_bad.sql` 并执行）。

- [ ] **Step 3: 改列举逻辑**

把 `provision_dsql.py:156-161` 的 `resp = s3.list_objects_v2(...)` + `for obj in sorted(...)` 段替换为：

```python
        # Delimiter="/"：只列 migrations/ 直下的对象，子目录（CommonPrefixes）不递归——
        # 与校验器 _dsql_sql_files 的非递归 glob 口径一致（校验器已在 validate 拒子目录）。
        # paginator：迁移文件理论上可超 1000（M16 分页边界，merged review §9），逐页取。
        paginator = s3.get_paginator("list_objects_v2")
        objs = []
        for page in paginator.paginate(
                Bucket=bucket,
                Prefix=f"extracted/{job_id}/backend/migrations/",
                Delimiter="/"):
            objs.extend(page.get("Contents", []))
        for obj in sorted(objs, key=lambda o: o["Key"]):
            fname = PurePosixPath(obj["Key"]).name
            if re.match(r"^\d{3}_.+\.sql$", fname) and fname not in applied:
                run_file(obj["Key"], fname)
```

- [ ] **Step 4: 跑测试确认通过 + 既有迁移用例不回归**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py -q)`
Expected: PASS（含 `test_redeploy_skips_schema_applies_new_migration_incrementally`——moto 的 `list_objects_v2` paginator 支持 Delimiter）。

- [ ] **Step 5: 提交**

```bash
git add site-builder/deployer/functions/provision_dsql.py site-builder/deployer/tests/test_provision_dsql.py
git commit -m "feat(deployer/03): 迁移列举加 Delimiter + paginator（M16 执行器半边）"
```

---

### Task 7: `provision_dsql` marker 读取改强一致（裁定 6）

**Files:**
- Modify: `site-builder/deployer/functions/provision_dsql.py:105`
- Test: `site-builder/deployer/tests/test_provision_dsql.py`

**Interfaces:**
- Consumes: `common.get_site_consistent(site_id) -> dict | None`（既有，`common.py:211-215`）。
- Produces: `provision_dsql.handler` 读 `migrations_applied` 用强一致读。

**动机**：marker 一旦成为正确性不变量（catalog 守卫、purge 清 marker 都依赖它），最终一致读会把 Task 9/10 刚关上的窗口重新打开一次——一个刚被 purge 清空 marker 的站点，最终一致读可能仍读到旧的非空 marker，于是跳过 `schema.sql`、建出空 schema。

- [ ] **Step 1: 写失败测试（断言用的是强一致读）**

```python
def test_marker_read_is_consistent(aws, monkeypatch):
    import common, provision_dsql
    common.create_job("a@x.com", "exp-a1b2c3")
    _put("job-1", "backend/schema.sql", b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    calls = {"consistent": 0, "eventual": 0}
    real_c = common.get_site_consistent
    real_e = common.get_site
    monkeypatch.setattr(common, "get_site_consistent",
                        lambda s: (calls.__setitem__("consistent", calls["consistent"] + 1), real_c(s))[1])
    monkeypatch.setattr(common, "get_site",
                        lambda s: (calls.__setitem__("eventual", calls["eventual"] + 1), real_e(s))[1])
    monkeypatch.setattr(provision_dsql.common, "get_site_consistent", common.get_site_consistent)
    monkeypatch.setattr(provision_dsql.common, "get_site", common.get_site)
    _run()
    assert calls["consistent"] >= 1  # marker 读走强一致
```

（注：`provision_dsql` 里是 `import common` 后 `common.get_site(...)`，所以打 `common` 上的属性即可；上面双保险同时打 `provision_dsql.common`。若 helper `_run` 里已 patch 了连接，本用例只关心读路径，连接 mock 不影响。）

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py::test_marker_read_is_consistent -q)`
Expected: FAIL（当前用 `get_site`，`consistent` 计数为 0）。

- [ ] **Step 3: 改读取**

`provision_dsql.py:105`：
```python
    site = common.get_site_consistent(site_id) or {}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py::test_marker_read_is_consistent -q)`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/deployer/functions/provision_dsql.py site-builder/deployer/tests/test_provision_dsql.py
git commit -m "feat(deployer/03): provision_dsql 的 marker 读改强一致（裁定 6）"
```

---

### Task 8: `run_file` 富失败信息 + M03 有状态 fake 反例（裁定 3④；反例先红后绿，Global 第 7 条）

**Files:**
- Modify: `site-builder/deployer/functions/provision_dsql.py`（`run_file`，`:146-154`）
- Test: `site-builder/deployer/tests/test_provision_dsql.py`

**Interfaces:**
- Consumes: 无新依赖。
- Produces: `run_file` 逐条 execute 时若某条抛错，重新抛出一个 `RuntimeError`，消息含：文件名、第几条语句（1-based）、SQLSTATE（若有）、本文件内此前已成功执行（已提交）的语句序号、以及补救办法一行。

- [ ] **Step 1: 写反例（有状态 fake，证明"不可重放 ⇒ 重放炸；可重放 ⇒ 重放安全"）**

```python
class _StatefulCur:
    """记得住已建对象的 fake cursor：重放非幂等 CREATE TABLE 抛 42P07，
    带 IF NOT EXISTS 则无害。用来证明 M03 的失败形态与修复方向（不 mock execute）。"""
    def __init__(self):
        self.tables = set()
        self.executed = []
        self.fail_once = None      # 设成某子串则该语句第一次执行时抛 transient

    def execute(self, sql, params=None):
        self.executed.append(sql)
        norm = " ".join(sql.split())
        if self.fail_once and self.fail_once in norm:
            self.fail_once = None
            raise RuntimeError("transient boom")   # 无 sqlstate：非 duplicate
        m = re.match(r"CREATE TABLE(?: IF NOT EXISTS)? (\w+)", norm, re.I)
        if m:
            name = m.group(1)
            if name in self.tables:
                if "IF NOT EXISTS" in norm.upper():
                    return
                err = type("Dup", (Exception,), {"sqlstate": "42P07"})
                raise err(f'relation "{name}" already exists')
            self.tables.add(name)
    def fetchone(self):
        return (len(self.tables),)


def _stateful_conn():
    conn = MagicMock()
    cur = _StatefulCur()
    conn.cursor.return_value = cur
    return conn, cur


def test_m03_non_replayable_bricks_on_retry_but_if_not_exists_recovers(aws):
    import common, pytest
    # ---- 非幂等：schema.sql 三条裸 CREATE TABLE，第 3 条首次 transient 失败 ----
    common.create_job("a@x.com", "exp-nonidem")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE c (id UUID PRIMARY KEY);")
    admin1, mig1 = _stateful_conn()
    mig1.fail_once = "CREATE TABLE c"
    with pytest.raises(Exception):
        _run(event=_event(job_id="job-1", site_id="exp-nonidem"), mig=(admin1[0], mig1))
    # 第 3 条失败 ⇒ 文件 marker 未写 ⇒ a、b 已提交
    assert common.get_site("exp-nonidem").get("migrations_applied", []) == []
    # 重试（新 job）：从第 1 条重跑 ⇒ 撞 a already exists（42P07）——这就是 M03 的 brick
    admin2, mig2 = _stateful_conn()
    mig2.tables = set(mig1.tables)      # 同一个"库"：a、b 还在
    with pytest.raises(Exception) as ei:
        _run(event=_event(job_id="job-2", site_id="exp-nonidem"), mig=(admin2[0], mig2))
    assert "42P07" in str(ei.value) or "already exists" in str(ei.value)

    # ---- 幂等：同样的三张表带 IF NOT EXISTS，重放安全 ----
    common.create_job("a@x.com", "exp-idem")
    _put("job-3", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS b (id UUID PRIMARY KEY);\n"
         b"CREATE TABLE IF NOT EXISTS c (id UUID PRIMARY KEY);")
    admin3, mig3 = _stateful_conn()
    mig3.fail_once = "CREATE TABLE IF NOT EXISTS c"
    with pytest.raises(Exception):
        _run(event=_event(job_id="job-3", site_id="exp-idem"), mig=(admin3[0], mig3))
    admin4, mig4 = _stateful_conn()
    mig4.tables = set(mig3.tables)
    _run(event=_event(job_id="job-4", site_id="exp-idem"), mig=(admin4[0], mig4))   # 不抛
    assert "schema.sql" in common.get_site("exp-idem")["migrations_applied"]
```

（`_event` 已在文件顶部，接受 `job_id`/`site_id`。`_run` 的 `mig=` 传 `(conn, cur)`；本用例把 stateful cur 同时用于 admin 与 mig——admin 只跑引导 SQL，`_StatefulCur` 对非 CREATE-TABLE 语句无副作用，`fetchone` 返回真实表数供 Task 9 的守卫用。若 `_run` 对 admin/mig 分开取 cur，按其签名传两套。）

- [ ] **Step 2: 跑反例确认失败方向（此时无富信息，断言 SQLSTATE 文案可能不全）**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py::test_m03_non_replayable_bricks_on_retry_but_if_not_exists_recovers -q)`
Expected: 大概率 PASS（这条反例证明的是"现状不幂等"，不依赖富信息）——它是 Global 第 7 条要求的"反例先写"。若因 `_run` 签名不匹配而 error，先对齐 helper 再跑。**记录**：本步确认了 M03 的失败形态在有状态 fake 上可复现。

- [ ] **Step 3: 加富失败信息**

改 `provision_dsql.py` 的 `run_file`（`:146-154`）：

```python
        def run_file(key: str, marker: str):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
            stmts = _statements(body)
            for idx, stmt in enumerate(stmts, start=1):
                try:
                    cur.execute(stmt)
                except Exception as e:
                    sqlstate = getattr(e, "sqlstate", None) or getattr(e, "pgcode", None)
                    committed = idx - 1   # 本文件内此前逐条 autocommit 已提交的条数
                    raise RuntimeError(
                        f"{marker} 第 {idx}/{len(stmts)} 条语句执行失败"
                        f"（SQLSTATE={sqlstate}）：{str(e)[:200]}。"
                        f"本文件此前 {committed} 条已提交（不可回滚，DSQL 每条 autocommit）。"
                        f"补救：把该 SQL 改成可重放形态（CREATE TABLE IF NOT EXISTS / "
                        f"ALTER TABLE … ADD COLUMN IF NOT EXISTS / CREATE OR REPLACE VIEW / "
                        f"INSERT … ON CONFLICT DO NOTHING），重新部署即从头安全重跑；"
                        f"合同层红线 8 会在下次 validate 拦下不可重放语句。语句：{stmt[:120]}"
                    ) from e
            applied.append(marker)
            common.upsert_site(site_id, migrations_applied=applied)  # 逐文件立即记录
```

- [ ] **Step 4: 加富信息断言的用例**

```python
def test_run_file_failure_reports_file_stmt_sqlstate_and_remedy(aws):
    import common, pytest
    common.create_job("a@x.com", "exp-rich")
    _put("job-1", "backend/schema.sql",
         b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);\n"
         b"ALTER TABLE a ADD COLUMN z TEXT;")   # 第 2 条：模拟 42701
    mig_conn, mig_cur = _mock_conn()
    def _boom(sql, *a):
        if "COLUMN z" in sql:
            err = type("Dup", (Exception,), {"sqlstate": "42701"})
            raise err("column already exists")
    mig_cur.execute.side_effect = _boom
    with pytest.raises(RuntimeError) as ei:
        _run(event=_event(job_id="job-1", site_id="exp-rich"), mig=(mig_conn, mig_cur))
    msg = str(ei.value)
    assert "schema.sql" in msg and "第 2/2 条" in msg
    assert "42701" in msg and "1 条已提交" in msg and "可重放" in msg
```

- [ ] **Step 5: 跑两条用例确认通过**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py -q -k "rich or m03_non_replayable")`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add site-builder/deployer/functions/provision_dsql.py site-builder/deployer/tests/test_provision_dsql.py
git commit -m "feat(deployer/03): run_file 富失败信息 + M03 有状态 fake 反例（裁定 3④）"
```

---

### Task 9: catalog 守卫（schema 空 + marker 非空 ⇒ 自愈 + 审计行；裁定 4/5/10）

**Files:**
- Modify: `site-builder/deployer/functions/provision_dsql.py`（admin 引导块，`CREATE SCHEMA` 之后，`:116` 附近；顶部 `import ops_log`）
- Test: `site-builder/deployer/tests/test_provision_dsql.py`

**Interfaces:**
- Consumes: `ops_log.record(actor, action, target, result, detail)`（既有，`ops_log.py:74`）；`common.get_job(job_id)`（取 actor）；`common.upsert_site(site_id, migrations_applied=[])`（SET-only，F7）。
- Produces: 当 `applied` 非空且 admin 连接对本 schema 的 `information_schema.tables` 计数为 0 时，把 `applied` 重置为 `[]`、`upsert_site` 落库、写一条 `action="dsql-marker-self-heal"` 审计行；`applied` 局部变量同步清空，后续 `run_file` 因此重跑 `schema.sql`。

**效力边界（写进注释）**：**schema 空 + marker 非空 = 已证明的失配**（空 schema 上重跑不可能覆盖数据）；schema **非空**则什么都证明不了（不知道哪些文件跑过），此时守卫不动。**必须用 admin 连接**（此时已在 admin 块内、`CREATE SCHEMA IF NOT EXISTS` 之后就绪）——mig role 能否读 `pg_catalog`/`information_schema` 未验证（merged review :1147-1151），不赌它。用参数化 `SELECT`（不受 F1 的一事务一 DDL 约束，SELECT 非 DDL）。

**为什么自愈而非 fail closed（裁定 5）**：判据是"schema 已证明为空"，自愈只可能重跑到一个空 schema 上，不可能删数据；而 fail closed 会把一个可自动修复的状态变成人工工单，且 DEPLOY.md 自己教的手工 `DROP SCHEMA CASCADE` 之后必然撞上这个失配（F9①）。审计行让"平台替你重跑了 schema.sql"留痕。

- [ ] **Step 1: 写失败测试**

```python
def test_catalog_guard_self_heals_empty_schema_with_stale_marker(aws):
    import common
    common.create_job("a@x.com", "exp-heal")
    common.upsert_site("exp-heal", migrations_applied=["schema.sql"])  # 陈旧 marker
    _put("job-1", "backend/schema.sql", b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    admin_conn, admin_cur = _mock_conn()
    admin_cur.fetchone.return_value = (0,)     # schema 里 0 张表 ⇒ 已证明失配
    out, admin_sqls, mig_sqls, _, _ = _run(
        event=_event(job_id="job-1", site_id="exp-heal"), admin=(admin_conn, admin_cur))
    # 自愈：marker 清空后 schema.sql 被重跑
    assert any("CREATE TABLE" in s for s in mig_sqls)
    assert common.get_site("exp-heal")["migrations_applied"] == ["schema.sql"]  # 重跑后重新追加
    # 审计行落库
    import boto3
    rows = boto3.resource("dynamodb").Table("site-ops-log").scan()["Items"]
    assert any(r["action"] == "dsql-marker-self-heal" and r["target"] == "site:exp-heal"
               for r in rows)


def test_catalog_guard_leaves_nonempty_schema_alone(aws):
    import common
    common.create_job("a@x.com", "exp-keep")
    common.upsert_site("exp-keep", migrations_applied=["schema.sql"])
    _put("job-1", "backend/schema.sql", b"CREATE TABLE IF NOT EXISTS a (id UUID PRIMARY KEY);")
    admin_conn, admin_cur = _mock_conn()
    admin_cur.fetchone.return_value = (3,)     # schema 非空 ⇒ 证明不了失配，不动
    _, _, mig_sqls, _, _ = _run(
        event=_event(job_id="job-1", site_id="exp-keep"), admin=(admin_conn, admin_cur))
    assert not any("CREATE TABLE" in s for s in mig_sqls)   # schema.sql 仍被跳过
    assert common.get_site("exp-keep")["migrations_applied"] == ["schema.sql"]
```

- [ ] **Step 2: 跑测试确认失败**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py -q -k catalog_guard)`
Expected: FAIL（无守卫，第一条 schema.sql 被跳过、无审计行）。

- [ ] **Step 3: 实现守卫**

`provision_dsql.py` 顶部 `import common` 旁加 `import ops_log`。在 admin 块 `cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')`（`:116`）之后插入：

```python
        # catalog 守卫（裁定 4/5/10）：marker 非空却查到 schema 空 = 已证明的失配
        # （schema 被手工 DROP、cluster 重建、站点自己 DROP TABLE、purge 时 tier 未知
        # 跳过 DSQL……见 F9 的 4 条路径）。空 schema 上重跑不可能覆盖数据 ⇒ 自愈：
        # 清 marker + 审计留痕，而非 fail closed（那会把可自动修复的状态变人工工单，
        # 且手册教的手工 DROP SCHEMA 之后必然撞上它）。用 admin 连接读——mig role 能否
        # 读 information_schema 未验证。schema 非空则什么都证明不了，不动。
        if applied:
            cur.execute("SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = %s", (schema,))
            row = cur.fetchone()
            table_count = row[0] if row else 0
            if table_count == 0:
                stale = list(applied)
                applied = []
                common.upsert_site(site_id, migrations_applied=applied)
                job = common.get_job(job_id) or {}
                ops_log.record(actor=job.get("owner", ""),
                               action="dsql-marker-self-heal",
                               target=f"site:{site_id}", result="ok",
                               detail={"schema": schema, "cleared_marker": stale,
                                       "reason": "schema 已证明为空、marker 非空——"
                                                 "重置 marker 以重跑建库 SQL"})
                logger.warning("catalog 守卫自愈 site=%s schema=%s 清空 marker=%s",
                               site_id, schema, stale)
```

**注意变量作用域**：`applied` 在 `handler` 顶部（`:106`）定义，admin 块里对它重新赋值 `applied = []` 会需要它在同一函数作用域——它确实在 `handler` 内，直接赋值即可（不是嵌套函数写外层变量，无需 `nonlocal`）。`run_file`（嵌套函数）里 `applied.append(...)` 是对同一 list 对象操作，重置成新 `[]` 后 `run_file` 闭包读的是 `handler` 局部名 `applied`——**因为 `run_file` 在 admin 块之后才定义/调用，闭包捕获的是重置后的名字**，安全。（若 `run_file` 定义在 admin 块之前，需确认闭包引用的是名字而非旧对象；Python 闭包按名字查找，重置后一致。）

- [ ] **Step 4: 跑测试确认通过**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py -q -k catalog_guard)`
Expected: PASS

- [ ] **Step 5: 修既有 redeploy 用例的 admin fetchone（若受影响）**

`test_redeploy_skips_schema_applies_new_migration_incrementally`（`:99`）现在 `applied` 非空 ⇒ 守卫会对 admin cursor 发 `SELECT count`。默认 `_mock_conn` 的 `fetchone()` 返回 MagicMock，`MagicMock() == 0` 为 False ⇒ 守卫不自愈（安全）。但为消除对 MagicMock 比较行为的隐式依赖，在该用例里显式设非零：给它传 admin，`admin_cur.fetchone.return_value = (5,)`。改动最小：在该测试构造 admin 连接并传入 `_run(admin=(admin_conn, admin_cur), mig=...)`。

- [ ] **Step 6: 跑全 provision_dsql 套件**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_provision_dsql.py -q)`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add site-builder/deployer/functions/provision_dsql.py site-builder/deployer/tests/test_provision_dsql.py
git commit -m "feat(deployer/03): catalog 守卫自愈空 schema 陈旧 marker + 审计行（裁定 4/5/10）"
```

---

### Task 10: `undeploy` 的 purge 路径清 marker（裁定 4 purge 半边；F7）

**Files:**
- Modify: `site-builder/deployer/functions/undeploy.py`（`_purge_dsql`，`:125-131`）
- Test: `site-builder/deployer/tests/test_undeploy.py`

**Interfaces:**
- Consumes: `common.upsert_site(site_id, migrations_applied=[])`（SET-only，把 marker 置空；唯一读者 `provision_dsql:106` 对 `[]` 与缺失同处理，F7）。
- Produces: `_purge_dsql` 在 `DROP SCHEMA … CASCADE` 之后、`DROP ROLE` 循环之前把 marker 清空；该 upsert 若抛异常，冒到 `handler` 的 `except` → `purged["dsql_error"]` → job `PURGE_FAILED`（**不给它单独包 try/except**，F7）。

**落点与理由（F7）**：清 marker 必须在 `DROP SCHEMA`（`:125`）**之后**（schema 真的没了才清 marker，否则清了 marker 但 DROP 失败会造出反向坏状态）、`DROP ROLE` 循环（`:126-130`）**之前**（role 的 drop 是 warn-only，放后面会被一次 role 失败跳过）。反向坏状态（marker 清了、schema 还在）在 provision-db 会响亮失败（F8），不是静默——但正确落点直接避免它。

- [ ] **Step 1: 写反例（Q4：purge 后 marker 仍在 ⇒ 重部跳过 schema.sql ⇒ 空 schema）**

`test_undeploy.py` 的 DSQL 用例全部 mock `psycopg` 只检查发出的 SQL 串。追加：

```python
def test_purge_clears_migration_marker(aws):
    import common, undeploy
    from unittest.mock import MagicMock, patch
    common.create_job("a@x.com", "exp-purge")
    common.create_site_record("exp-purge", owner="a@x.com", name="x")
    common.upsert_site("exp-purge", tier="fullstack-sql",
                       migrations_applied=["schema.sql", "001_add.sql"])
    fake = MagicMock()                      # psycopg.connect() → conn
    cur = MagicMock()
    fake.cursor.return_value = cur
    cur.fetchall.return_value = []          # 无 IAM 映射
    with patch("undeploy.boto3"), \
         patch.object(undeploy, "_lambda"), \
         patch("psycopg.connect", return_value=fake):
        # 直接调 _purge_dsql 更聚焦（handler 会另删路由/Lambda/角色，本用例只验 marker）
        undeploy._purge_dsql("exp-purge")
    assert common.get_site("exp-purge")["migrations_applied"] == []
    # 清 marker 在 DROP SCHEMA 之后、DROP ROLE 之前
    sqls = [c.args[0] for c in cur.execute.call_args_list]
    assert any("DROP SCHEMA" in s for s in sqls)
```

（注：`_purge_dsql` 内部 `import psycopg` 并 `boto3.client("dsql")` 取 token。`patch("undeploy.boto3")` 让 `boto3.client(...)` 返回 MagicMock，token 调用无害；`patch("psycopg.connect")` 拦真实连接。若既有 DSQL 用例已有更贴合的 mock 骨架，沿用它的写法，别新造一套。先按现有 `test_undeploy.py` 里 DSQL 用例的 patch 方式对齐。）

- [ ] **Step 2: 跑反例确认失败**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_undeploy.py::test_purge_clears_migration_marker -q)`
Expected: FAIL（当前 `_purge_dsql` 不清 marker，`migrations_applied` 仍是两项）。

- [ ] **Step 3: 在 `_purge_dsql` 落点清 marker**

`undeploy.py`，把 `:125-126` 之间（`DROP SCHEMA` 之后、`for role in (...)` DROP ROLE 循环之前）插入：

```python
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        # marker 清空必须在 DROP SCHEMA 之后（schema 真没了才清）、DROP ROLE 之前
        # （role drop 是 warn-only，放后面会被一次 role 失败跳过）。**不单独包 try**：
        # 让它抛到 handler 的 except → purged["dsql_error"] → job PURGE_FAILED，
        # 残留状态被报告而非静默（F7）。唯一读者 provision_dsql 对 [] 与缺失同处理。
        common.upsert_site(site_id, migrations_applied=[])
        for role in (f"{schema}_app", f"{schema}_mig"):
```

（删掉原来重复的那行 `cur.execute(f'DROP SCHEMA ...`——只保留一处；上面的替换块已含它。）

- [ ] **Step 4: 跑反例确认通过 + 全 undeploy 套件**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_undeploy.py -q)`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/deployer/functions/undeploy.py site-builder/deployer/tests/test_undeploy.py
git commit -m "feat(deployer/03): purge_data 路径清 DSQL 迁移 marker（裁定 4/F7）"
```

---

### Task 11: 收口——命名口径一致用例、全量套件、code-review、工单与 §9

**Files:**
- Test: `site-builder/contract/tests/test_redlines.py`（口径一致用例）
- Modify: `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`（§9 第 7 行划掉）
- Modify: `.scratch/asset-v1/NEXT.md`、`.scratch/asset-v1/issues/03-*.md`（**gitignored**，不提交）

- [ ] **Step 1: 写"校验器拒子目录 ⇔ 执行器不递归"口径一致用例**

在 `test_redlines.py` 加一条把两侧口径钉在一起的元测试（Global 第 4 条）：

```python
def test_validator_and_executor_agree_on_migration_scope():
    """校验器只认 migrations/ 直下的 NNN_*.sql（拒子目录）；执行器 provision_dsql
    也只列直下层（Delimiter='/'）。两处口径必须一致——任一处改了另一处会漂移。
    这里用静态断言把契约钉住：校验器有子目录拒绝逻辑，执行器列举带 Delimiter。"""
    import inspect
    from contract import redlines
    src_v = inspect.getsource(redlines.scan_redlines)
    assert "migrations" in src_v and "子目录" in inspect.getsource(redlines)
    # 执行器侧：读 provision_dsql 源码断言 Delimiter（跨包，用文件路径读）
    from pathlib import Path
    pv = (Path(redlines.__file__).parents[4] / "deployer" / "functions"
          / "provision_dsql.py").read_text()
    assert 'Delimiter="/"' in pv, "执行器列举迁移必须带 Delimiter='/' 与校验器口径一致"
```

（路径推导按实际仓库布局校准：`contract/src/contract/redlines.py` → 上溯到 `site-builder/`，再进 `deployer/functions/`。若 `parents[N]` 层数不对，跑一次打印 `Path(redlines.__file__)` 校准 N。此用例只做静态存在性断言，不引 deployer venv。）

- [ ] **Step 2: 跑该用例**

Run: `(cd site-builder/contract && .venv/bin/pytest tests/test_redlines.py::test_validator_and_executor_agree_on_migration_scope -q)`
Expected: PASS

- [ ] **Step 3: 全量 contract + deployer（不并行）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/contract && .venv/bin/pytest tests -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
```
Expected: 两侧全绿（contract ≥174+新增；deployer ≥1752+新增）。看到 `test_redlines.py` 的墙钟哨兵红先单独重跑一次再判断（Global 约束）。

- [ ] **Step 4: 提交口径用例**

```bash
git add site-builder/contract/tests/test_redlines.py
git commit -m "test(03): 钉住校验器/执行器迁移扫描口径一致"
```

- [ ] **Step 5: `/code-review` 本票 diff，处理 finding**

对本票所有提交跑 `/code-review`（或 `superpowers:requesting-code-review`）。逐条处理 finding：真问题就修（每修一条补一条测试），误报就在工单 Comments 记原因。修完重跑 Step 3 的全量。

- [ ] **Step 6: 划掉 merged review §9 第 7 行**

`docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` 第 7 行（`| 7 | **M03 + M16** | 必须一起做…`）按该文件既有"做完加删除线"的形态改（如 `| ~~7~~ | ~~**M03 + M16**~~ … **✅ 已修** |`，照抄第 10 行的风格）。**只标做完，不写具体日期/SHA**（该文件是否在状态守卫内需确认——它在 `docs/reviews/`，不在 `_STATUS_FREE_DOCS` 的 references/DEPLOY 列表；但为安全用删除线+✅ 即可，不加日期）。

```bash
git add docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md
git commit -m "docs(03): merged review §9 第 7 行（M03+M16）收口"
```

- [ ] **Step 7: 更新工单与接手点（gitignored，不提交）**

- `.scratch/asset-v1/issues/03-dsql-migration-idempotent-and-subdir-scan.md`：`Status: done`，Comments 记：六条裁定落点、DML 采纳 (b) 的裁定与理由、`CREATE OR REPLACE VIEW` 的文档依据、证据强度（mock 层 + AWS 文档核实，未跑真机）、后续候选（③ reconcile 单独开票 / sqlparse 版本偏斜无人守 / sites 行不记 DSQL 身份 / migrate_permissions.py 脚手架清理）。
- `.scratch/asset-v1/NEXT.md`：顶部更新为"工单 03 完成"，下一张票 14。

- [ ] **Step 8: 最终校验（暂存后单独跑，看 `$?`）**

```bash
cd "$(git rev-parse --show-toplevel)"
git add -A
bash site-builder/scripts/scan_staged_secrets.sh; echo "scan exit=$?"
```
Expected: `scan exit=0`。确认没有 `.scratch/` 或 `docs/design/`、`.superpowers/` 被 `git add -f` 混入（它们 gitignored）。

---

## Self-Review

**Spec coverage（六条裁定 + M16 分页边界 + DML 子决策）：**
- 裁定 1 → Task 1（校验器拒子目录）+ Task 6（执行器 Delimiter）；「marker 键含相对路径无事可做」在处方映射段写明。✅
- 裁定 2 → Task 2 + Task 3（两文件同扫）。✅
- 裁定 3 → Task 3（①白名单②降级为红线）+ Task 8（④富失败信息）；③ 单独开票记进 Comments（Task 11 Step 7）。✅
- 裁定 4 → Task 9（catalog 守卫）+ Task 10（purge 清 marker）。✅
- 裁定 5 → Task 9（自愈 + 审计，非 fail closed）。✅
- 裁定 6 → Task 7（get_site_consistent）。✅
- M16 分页边界（§9 :34）→ Task 6（paginator）。✅
- DML 子决策 → 专节裁定 (b)，Task 3 白名单第 7 条实现。✅
- 反例先红后绿（Global 7）→ Task 8（M03 有状态 fake）+ Task 10（Q4 purge 反例）。✅
- 命名口径一致用例 → Task 11 Step 1。✅
- 跨组件矩阵四处同步 → Task 1-3（校验器）、Task 4（references）、Task 5（fixtures/模板核对）。✅

**Placeholder scan：** 每个代码步骤都给了可粘贴的实现/测试；文档步骤给了逐字文案。无 TODO/TBD。

**Type consistency：** `_check_sql_replayable(sql_text, rel)`、`_sql_statements(text)`、`_dsql_sql_files(backend_dir)`、`common.get_site_consistent`、`ops_log.record(actor=,action=,target=,result=,detail=)`、`common.upsert_site(site_id, migrations_applied=[])` 全与既有源码签名核对一致。`_StatefulCur.fetchone` 返回 `(count,)` 与 Task 9 守卫的 `row[0]` 一致。

**已知启发式边界（写进相应 docstring，非缺陷）：** 可重放白名单是保守启发式——多动作 `ALTER TABLE`（其一为 `ADD COLUMN IF NOT EXISTS`、另一为非幂等动作）可能整条放行；合同层切分器与执行器 sqlparse 不字节一致（偏误报，方向安全）。这与 `redlines.py` 一贯的"宁可误报"口径一致。

**执行环节风险提示（给 executor）：** Task 8/9 依赖 `_run` helper 的 `admin=`/`mig=` 签名与 `_event(job_id=, site_id=)`——两者已在 `test_provision_dsql.py` 顶部（本计划已核）。Task 9 的 `applied` 重置涉及嵌套 `run_file` 闭包，按名字查找安全（注释已说明）；若 executor 发现 `run_file` 定义早于 admin 块导致闭包捕获旧 list，改为在 admin 块把 `applied[:] = []`（原地清空）而非重新赋值即可，两种写法都能让闭包看到清空后的 list。
