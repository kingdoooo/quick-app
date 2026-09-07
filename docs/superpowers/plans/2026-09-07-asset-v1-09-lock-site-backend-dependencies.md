# asset-v1 / 09 · 锁定站点后端依赖（合同强制 lockfile + `npm ci`）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让每一次站点部署装出的依赖树由上传的字节唯一决定：合同要求 fullstack 站点带 `backend/package-lock.json`，校验器在 `validate` 阶段拒无锁文件、未钉住（非公共 registry / 无 `integrity` / 与 `package.json` 不一致）的产物，CodeBuild 用 `npm ci --ignore-scripts` 而不是 `npm install`；Skill 文档与两个黄金 fixture 同步。

**Architecture:** 不新增组件、不新增存储。改动落在三层已有的"合同锚点"上：① `contract/redlines.py` 新增红线 8（lockfile 存在性 + 内容 + `package.json` 依赖规格）；② `deployer/buildspec-package.yml` 的那一条 npm 命令换成 `npm ci`，`tests/security_contracts.py` 的精确命令 allowlist 跟着换；③ `skills/site-builder/` 的 references / SKILL.md 与 `fixtures/` 同步（两个 fullstack fixture 各加一份由公共 registry 解析出的 `package-lock.json`）。校验器与构建器看到的是**同一份字节**（validate 用 `IfMatch` 钉住上传、`_pack_build_input` 从已扫描的树重新打包），所以 lockfile 的 registry / integrity 检查只需在合同层做一道。

**Tech Stack:** Python 3.12（contract / deployer 的 venv）、pytest、npm ≥ 7 的 lockfileVersion 2/3 格式、CodeBuild `npm ci`。

**Spec:** 工单 `.scratch/asset-v1/issues/09-lock-site-backend-dependencies.md`（gitignored，只在主 worktree；"What to build"一段是本计划的范围）；缺陷原文 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` 的 **M14**（§4 那一节 + §9 第 10 行）；合同三处同步的规则在 `CLAUDE.md`「部署合同是锚点」与「跨组件改动矩阵」第一行；CodeBuild 隔断的两层模型在 `CLAUDE.md` 开头那段与 `docs/security/account-trust-boundary.md` 的攻击路径表。

**证据分级**（本文件用词）：**static** = 读代码/文档；**fake-unit** = pytest（含 moto）；**sandbox** = 本机对公共 npm registry 或验证环境 AWS 的实测；**production** = 无（本资产没有生产环境，见 `CONTEXT.md`「验证环境」）。

---

## 决策门（coordinator 裁定后 implement worker 才开工）

计划按每条的**推荐项**写。若裁定不同，受影响的 Task 在括号里。

**D1 · 处方：合同强制 lockfile，还是 merged review 的"持久化解析结果并复用"？** —— **推荐：强制 lockfile（工单原文）**。
merged review M14 的合并结论是"不要在合同里强制 `package-lock.json`，改为把 `npm install` 解析结果持久化并按 package.json hash / Node / npm / registry / lockfile hash 绑定复用"（两位复审方一致，§9 第 10 行）。工单在 asset-v1 框架下反过来选了强制 lockfile，理由成立且更强：
- 复审方反对的前提"生成方是 Agent，无法凭空产出 lockfile"**不成立**：SKILL.md 第 4/5a 步已经要求 Agent 在本地 `node server.js` 预览并打包时**排除 node_modules**——即 Agent 本来就在本地跑过 `npm install`，`package-lock.json` 是它的副产品，只是现在被丢掉了。
- "持久化并复用"是一个新设计面（不可变存储、五键绑定、`artifacts/*` PutObject 收窄、首次解析审计），复审自己列出的实现约束就有四条；对采用者而言它还引入一个跨部署的状态。强制 lockfile 是零状态方案。
- 采用者角度（工单"资产检查"行）：每次部署可复现、可事后回答"当时装的是哪棵树"，两个方案都给；强制 lockfile 额外把 `file:` / `git+` / 任意 URL 依赖在 validate 就拒掉（本机实测 `npm ci` **不会**拒 `file:` link 依赖，见 Task 1）。
**代价**：既有的、没带 lockfile 的站点在下一次重部时会被 validate 拒（报错文案给出一行修法）。验证环境的存量站点属于"验证环境的中间状态"，不进资产。
**若裁定持久化方案**：本计划整体作废，需要另写 spec（新存储 + IAM + 绑定键），不是改几个 Task 的事。
**coordinator 还要做一件事**：§9 第 10 行 M14 的处方与本次落地相反，标记完成时要在该行**写明反转的理由**（上面第一点），否则下一个读 merged review 的人会以为落地错了。

**D2 · registry 主机 allowlist 只认 `https://registry.npmjs.org/`？** —— **推荐：是**，做成 `redlines.py` 的模块常量 `NPM_REGISTRY_URL_PREFIXES`，采用者用私有镜像时改常量并同步 `references/redlines.md`（红线 8 的文档同步测试会逼着改）。
理由：lockfile 的 `resolved` 是 `npm ci` 实际下载的地址，buildspec 删 `.npmrc` 管不到它（merged review M14 的"相邻观测"）；allowlist + 必带 sha512 `integrity` 两条一起才构成"这份字节 ⇒ 这棵树"。企业镜像生成的 lockfile 会被拒，报错文案给出 `--registry=https://registry.npmjs.org/` 的重生成命令。
**被否的替代**：不查主机、改在 buildspec 加 `--replace-registry-host=always`——它把镜像主机改写回 npmjs 能救镜像用户，但 `git+` / `file:` 协议不受它管，且把一道能在 validate 给出可读报错的检查推迟到 provision-db 之后的 CodeBuild 才失败。**（影响 Task 1 的常量与报错文案、Task 4 的文档）**

**D3 · 三条配套的严格规则一起上？** —— **推荐：三条都上**，每条各堵一个绕过 lockfile 要求的口子，且各有一条会红的用例：
1. **`backend/package.json` 也成为必需**（今天可选）。`npm ci` 没有它直接 EUSAGE 失败（本机实测），而那是在 provision-db 之后；无依赖的后端照样要放一对最小文件（`npm install --package-lock-only` 对空依赖也能生成）。
2. **拒 `backend/npm-shrinkwrap.json`**。`npm ci` 有它就**优先读它、忽略 `package-lock.json`**，于是被校验的 lockfile 与被安装的不是同一份。
3. **`package.json` 的依赖规格禁 `file:` / `git+…` / `github:u/r` / `u/r` / URL / `npm:alias`**（判据：规格串含 `:` 或 `/`），四个依赖段都查。它们要么装本地字节（lockfile 里是 `link: true`，不可复现），要么绕开 registry allowlist。semver 范围与 dist-tag 都不含这两个字符。
**（去掉任一条：删 Task 1 对应的用例与实现分支、Task 4 对应的文档句）**

**D4 · 三份非 Skill 文档要不要跟着改？** —— **推荐：改**。`CLAUDE.md` 开头那段、`site-builder/DEPLOY.md` 威胁表那一行、`docs/security/account-trust-boundary.md` 攻击路径表都把 CodeBuild 的命令写成 `npm install`，且后两者断言"`_scan_package_json` 从不检查 `dependencies`（`file:` 规格一概不限）"——本次之后这句是错的。改法只换命令名与那一句事实，**不写日期、不写"已部署"**（CLAUDE.md 守卫）。**（不改：删 Task 4 的第 4–6 步）**

**D5 · 两个 fixture 的 lockfile 由实施者本机对公共 registry 生成并 tracked？** —— **推荐：是**。每份约 47–49 KB、只含包名 / 版本 / npmjs URL / 哈希，`scan_staged_secrets.sh` 实测 clean；`.gitignore` 不忽略它们。生成命令钉死 `--registry=https://registry.npmjs.org/`，否则实施者机器上的私有 registry 配置会让 fixture 自己过不了红线 8（Task 2 的 parity 用例会红）。**没有替代**：手写 lockfile 等于伪造 `integrity`。

---

## Global Constraints

- **每条守卫先写会红的用例**，实际跑红再写实现；每组负向用例配**正向对照**（一份合法 lockfile 必须过），否则负向全绿证明不了任何东西（merged review §9 末尾「共同要求」）。
- **测试命令照抄，不要猜 venv**（CLAUDE.md「测试命令」）：
  - `(cd site-builder/contract && .venv/bin/pytest tests -q)`
  - `(cd site-builder/deployer && .venv/bin/pytest tests -q)`（**必须带 `tests/`**）
  - 本票不碰 auth / panel / key-proxy / mcp / router，那五套由 coordinator 在集成泳道跑。
- **两套顺序跑，不并行**：`contract/tests/test_redlines.py::test_scanner_is_not_quadratic_on_large_files` 是墙钟哨兵，争用下假红；看到它红先单独重跑一次。
- **worker 不部署、不提交、不 push、不动 AWS**。改动留在工作树；coordinator 负责合并、七套件、`cdk deploy`、`verify_*`、提交。本计划最后一节列出 coordinator 要做的事。
- **资产检查**（工单那一行）：每处改动问"全新用户在全新账号 clone 这个仓库，这次改动对他有意义吗"。本票全部改动都是合同 / 构建器 / 文档的最终状态，全部 tracked；**验证环境存量站点怎么补 lockfile 不写进任何 tracked 文件**。
- **CLAUDE.md 守卫**：不写日期、commit SHA、"已部署 / 尚未 / 待做"。
- **不把真实账号 ID / 域名 / site_id / 邮箱写进任何被跟踪的文件。** 测试里的 lockfile 字面量用 `registry.npmjs.org` 的真实 URL 形态 + 假哈希。
- **buildspec 的守卫是精确 token 等值**（`tests/security_contracts.py`），改命令**必须**同步 `EXPECTED_COMMANDS`；`--ignore-scripts` 一个字都不能动（CLAUDE.md 开头：依赖里的生命周期脚本只有它一道）。
- **合同三处同步**（CLAUDE.md 改动矩阵第一行）：校验器、`skills/site-builder/references/`、`fixtures/`。本计划每一处都有用例锁住：红线本体（Task 1）、fixture parity（Task 2）、文档同步（Task 4）。
- **`verify_deployed_components.py` 按文件哈希核对线上 validate Lambda 里的 `redlines.py`**：本票改了它 ⇒ deployer 栈必须重部（coordinator），在那之前该闸门会红，那是**预期的**。
- **多命令 shell 块以 `set -euo pipefail` 开头**；回仓库根用 `cd "$(git rev-parse --show-toplevel)"`；不写绝对主机路径。
- 进度与证据写到 `.superpowers/sdd/2026-09-07-asset-v1-09-lock-site-backend-dependencies/progress.md`（gitignored），每个 Task 标明证据级别。

---

## 文件结构（先定边界再拆 Task）

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/contract/src/contract/redlines.py` | 红线 8 的唯一实现：`_scan_package_lock`、`_scan_dependency_specs`、常量 `NPM_REGISTRY_URL_PREFIXES` / `LOCKFILE_VERSIONS` / `LOCKFILE_REGEN_HINT`；`scan_redlines` 里的存在性检查与 lockfile 分流 | 修改（不拆新模块：`verify_deployed_components.py` 的 `CONTRACT_GUARDED` 按文件名核对 `redlines.py` / `schema.py`，新模块会落在守卫之外） |
| `site-builder/contract/tests/test_redlines.py` | `make_site` 默认带最小 `package.json` + lockfile；红线 8 的正/负用例；fixture parity；文档同步 | 修改 |
| `site-builder/fixtures/nosql-notes/backend/package-lock.json`、`site-builder/fixtures/sql-expenses/backend/package-lock.json` | 黄金样例的锁文件（对公共 registry 解析） | 新建 |
| `site-builder/deployer/buildspec-package.yml` | `npm install …` → `npm ci …`（其余 11 条命令不动） | 修改 |
| `site-builder/deployer/tests/security_contracts.py` | 命令 allowlist：`EXPECT_NPM_INSTALL` → `EXPECT_NPM_CI`，判据从 `["npm","install"]` 改 `["npm","ci"]` | 修改 |
| `site-builder/deployer/tests/test_security_contracts.py` | 反例集加"退回 `npm install`"；锚点从 `npm install` 改 `npm ci` | 修改 |
| `site-builder/deployer/tests/test_validate.py` | `GOOD_BACKEND` 加最小 `package.json` + lockfile；两处 `namelist` 断言 | 修改 |
| `site-builder/skills/site-builder/references/contract.md`、`references/redlines.md`、`SKILL.md` | 给 Agent 的合同文档：目录树、红线 8、工作流第 3/5a 步、速查 | 修改 |
| `CLAUDE.md`、`site-builder/DEPLOY.md`、`docs/security/account-trust-boundary.md` | 描述 CodeBuild 命令与合同校验范围的句子 | 修改（D4） |

**不动的**：`deployer/functions/validate.py`（`_pack_build_input` 已把 `backend/` 整目录打进构建输入，lockfile 自动随行）、`deployer/infra/app.py`（buildspec 逐字节内联，改文件即改模板）、`mcp/`（不校验 zip 内容）、`scripts/deploy_fixture.py`（打整棵树）、`tests/test_e2e_fixtures.py`（`_variant` 复制整个 fixture，只覆盖 `server.js`）。

---

### Task 1：红线 8 —— lockfile 存在、钉住、与 package.json 一致

**Files:**
- Modify: `site-builder/contract/src/contract/redlines.py`
- Test: `site-builder/contract/tests/test_redlines.py`
- Modify: `site-builder/deployer/tests/test_validate.py`（`GOOD_BACKEND` 与两处 `namelist`——不改它 deployer 套件在本 Task 之后就红，所以归本 Task）

**Interfaces:**
- Produces（Task 2/4 依赖这些名字）：
  - `contract.redlines.NPM_REGISTRY_URL_PREFIXES: tuple[str, ...] = ("https://registry.npmjs.org/",)`
  - `contract.redlines.LOCKFILE_VERSIONS: tuple[int, ...] = (2, 3)`
  - `contract.redlines.LOCKFILE_REGEN_HINT: str`（报错文案尾巴，含 `npm install --package-lock-only`）
  - `contract.redlines._scan_package_lock(text: str, rel: Path, pkg_text: str | None) -> list[str]`
  - `contract.redlines._scan_dependency_specs(pkg: dict, rel: Path) -> list[str]`
  - 报错文案的稳定片段（文档同步测试按它们断言）：`package-lock.json 缺失`、`package.json 缺失`、`npm-shrinkwrap.json`、`.resolved 必须以`、`.integrity 缺少 sha512`、`lockfileVersion 必须是 [2, 3]`、`与 package.json 不一致`、`不是 registry 依赖`、`不是从 registry 安装的包`
- 测试侧常量（Task 2 复用）：`MINIMAL_PACKAGE_JSON`、`MINIMAL_LOCK`、`ONE_DEP_PACKAGE_JSON`、`ONE_DEP_LOCK`

**sandbox 事实（本机 npm 12.0.2 / node 24 对公共 registry 实测，写进注释时标"单机实测"）**：
- `npm install --package-lock-only` 对两个 fixture 的 `package.json` 生成 lockfileVersion **3**，`packages[""]` 含 `name` + `dependencies` 且与 `package.json` 的 `dependencies` **逐键相等**；99 / 106 个条目全部 `resolved` 在 `https://registry.npmjs.org/`、`integrity` 全是 `sha512-`；`package.json` 字节**未被改写**。
- `npm ci`：无 lockfile → `EUSAGE`；`package.json` 多加一个依赖而 lockfile 未更新 → `EUSAGE`（"…are in sync"）；空依赖的最小配对 → 成功；**`file:./dep` 依赖（lockfile 里 `"dep": {...}` + `"node_modules/dep": {"resolved": "dep", "link": true}`）→ 成功装出 symlink**。最后一条就是校验器必须自己拒 `link` / 非 `node_modules/` 键的原因。

- [ ] **Step 1：改 `make_site`，让"合法 fullstack 站点"默认带最小 `package.json` + lockfile**

`site-builder/contract/tests/test_redlines.py` 顶部（`make_site` 之前）加常量，并给 `make_site` 加两个可置 `None` 的参数：

```python
# 红线 8 之后"合法 fullstack 站点"必须带这一对；无依赖的最小形态（npm 对空依赖生成的就是它）。
MINIMAL_PACKAGE_JSON = '{"name": "t", "private": true}'
MINIMAL_LOCK = json.dumps({"name": "t", "lockfileVersion": 3, "requires": True,
                           "packages": {"": {"name": "t"}}})
# 带一个 registry 依赖的配对：负向用例在它上面做单点变形，正向对照就是它本身。
# 哈希是假的（校验器只看 SRI 形态，不算哈希——算哈希是 npm ci 的事）。
ONE_DEP_PACKAGE_JSON = '{"name": "t", "private": true, "dependencies": {"express": "^4.19"}}'
ONE_DEP_LOCK = {
    "name": "t", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "t", "dependencies": {"express": "^4.19"}},
        "node_modules/express": {
            "version": "4.21.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz",
            "integrity": "sha512-" + "A" * 86 + "==",
            "license": "MIT"},
    }}


def make_site(tmp_path: Path, *, tier="fullstack-sql", index="fetch('/api/items')",
              server="app.get('/api/health',(q,s)=>s.send('ok'))",
              schema="CREATE TABLE t (id UUID PRIMARY KEY);",
              package_json: str | None = MINIMAL_PACKAGE_JSON,
              lockfile: str | None = MINIMAL_LOCK) -> tuple[Path, dict]:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/index.html").write_text(f"<script>{index}</script>")
    manifest = {"name": "t", "tier": tier,
                "database": {"engine": {"static": "none", "fullstack-nosql": "dynamodb",
                                        "fullstack-sql": "dsql"}[tier]},
                "auth": {"require_login": True, "allowed_users": "org"}}
    if tier != "static":
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend/server.js").write_text(server)
        if package_json is not None:
            (tmp_path / "backend/package.json").write_text(package_json)
        if lockfile is not None:
            (tmp_path / "backend/package-lock.json").write_text(lockfile)
        manifest["backend"] = {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080}
        if tier == "fullstack-sql":
            (tmp_path / "backend/schema.sql").write_text(schema)
    (tmp_path / "site.json").write_text(json.dumps(manifest))
    return tmp_path, manifest
```

- [ ] **Step 2：写红线 8 的用例（先红）**，追加到 `test_redlines.py` 末尾：

```python
# ── 红线 8：后端依赖必须锁定（合同强制 lockfile，构建用 npm ci）──────────────
#
# 为什么在合同层而不是只靠 npm ci：npm ci 对"无 lockfile"/"与 package.json 不一致"确实会
# 失败，但那发生在 package 阶段——provision-db 之后，用户已经等了两个 phase，且报错是 npm 的
# 原文。更要紧的是 npm ci **不拒** `file:` link 依赖（单机实测：装出 symlink 并成功），也不管
# `resolved` 指向哪个主机——这两条只能由校验器拒。
import copy


def _lock_mutations() -> dict[str, dict]:
    """在 ONE_DEP_LOCK 上做**单点**变形；每条都必须让校验器红。"""
    base = ONE_DEP_LOCK
    k = "node_modules/express"
    muts: dict[str, dict] = {}

    def mut(label):
        m = copy.deepcopy(base)
        muts[label] = m
        return m

    mut("resolved 指向别的主机")["packages"][k]["resolved"] = "https://evil.example/x.tgz"
    mut("resolved 用 http")["packages"][k]["resolved"] = "http://registry.npmjs.org/x.tgz"
    mut("主机后缀伪装")["packages"][k]["resolved"] = \
        "https://registry.npmjs.org.evil.example/x.tgz"
    del mut("没有 integrity")["packages"][k]["integrity"]
    mut("integrity 只有 sha1")["packages"][k]["integrity"] = "sha1-deadbeef"
    mut("lockfileVersion 1")["lockfileVersion"] = 1
    mut("link 依赖")["packages"]["node_modules/local"] = {"resolved": "local", "link": True}
    mut("workspace 键（不在 node_modules/ 下）")["packages"]["libs/x"] = {"version": "1.0.0"}
    del mut("没有根条目")["packages"][""]
    mut("根条目依赖漂移")["packages"][""]["dependencies"]["lodash"] = "^4"
    return muts


def test_one_dep_lockfile_is_the_positive_control(tmp_path):
    """负向用例全部建立在这一份能过的 lockfile 上；它不过，下面的红都没有意义。"""
    d, m = make_site(tmp_path, package_json=ONE_DEP_PACKAGE_JSON,
                     lockfile=json.dumps(ONE_DEP_LOCK))
    assert scan_redlines(d, m) == []


@pytest.mark.parametrize("label", list(_lock_mutations()))
def test_each_lockfile_mutation_is_rejected(tmp_path, label):
    mutated = _lock_mutations()[label]
    assert mutated != ONE_DEP_LOCK, f"变形没生效：{label}"
    d, m = make_site(tmp_path, package_json=ONE_DEP_PACKAGE_JSON,
                     lockfile=json.dumps(mutated))
    v = scan_redlines(d, m)
    assert any("package-lock.json" in x for x in v), f"**没红**：{label}: {v}"


def test_missing_lockfile_is_a_violation(tmp_path):
    d, m = make_site(tmp_path, lockfile=None)
    v = scan_redlines(d, m)
    assert any("package-lock.json 缺失" in x for x in v), v
    assert any("npm install --package-lock-only" in x for x in v), "报错没给可执行的修法"


def test_missing_package_json_is_a_violation(tmp_path):
    """npm ci 没有 package.json 直接 EUSAGE——今天它是可选的，红线 8 起必需。"""
    d, m = make_site(tmp_path, package_json=None)
    assert any("package.json 缺失" in x for x in scan_redlines(d, m))


def test_shrinkwrap_is_rejected(tmp_path):
    """npm ci 有 npm-shrinkwrap.json 就优先读它、忽略被校验的 package-lock.json。"""
    d, m = make_site(tmp_path)
    (d / "backend/npm-shrinkwrap.json").write_text(MINIMAL_LOCK)
    assert any("npm-shrinkwrap.json" in x for x in scan_redlines(d, m))


def test_lockfile_out_of_sync_with_package_json_is_rejected(tmp_path):
    """改了 package.json 忘了重生成 lockfile：npm ci 会在 package 阶段才失败，这里提前。"""
    pkg = json.loads(ONE_DEP_PACKAGE_JSON)
    pkg["dependencies"]["lodash"] = "^4"
    d, m = make_site(tmp_path, package_json=json.dumps(pkg), lockfile=json.dumps(ONE_DEP_LOCK))
    assert any("与 package.json 不一致" in x for x in scan_redlines(d, m))


def test_lockfile_that_is_not_json_is_rejected(tmp_path):
    d, m = make_site(tmp_path, lockfile="not json")
    assert any("package-lock.json" in x for x in scan_redlines(d, m))
    sub = tmp_path / "arr"          # 第二个站点要一个还没有 frontend/ 的目录
    sub.mkdir()
    d2, m2 = make_site(sub, lockfile="[]")
    assert any("package-lock.json" in x for x in scan_redlines(d2, m2))


def test_bundled_entry_needs_no_resolved_or_integrity(tmp_path):
    """inBundle 的包随父 tarball 分发，npm 不给它单独的 resolved/integrity——放行是刻意的。"""
    lock = copy.deepcopy(ONE_DEP_LOCK)
    lock["packages"]["node_modules/express/node_modules/b"] = {"version": "1.0.0", "inBundle": True}
    d, m = make_site(tmp_path, package_json=ONE_DEP_PACKAGE_JSON, lockfile=json.dumps(lock))
    assert scan_redlines(d, m) == []


@pytest.mark.parametrize("spec", [
    "file:./dep", "git+ssh://git@github.com/a/b.git", "github:a/b", "a/b",
    "https://example.test/y.tgz", "npm:lodash-es@^4", "link:../x",
])
def test_non_registry_dependency_specs_are_rejected(tmp_path, spec):
    """规格含 ':' 或 '/' 的都不是 registry 依赖：装本地字节或绕开主机 allowlist。"""
    pkg = {"name": "t", "private": True, "dependencies": {"d": spec}}
    d, m = make_site(tmp_path, package_json=json.dumps(pkg))
    assert any("不是 registry 依赖" in x for x in scan_redlines(d, m)), spec


def test_registry_specs_in_every_section_pass(tmp_path):
    pkg = {"name": "t", "private": True,
           "dependencies": {"express": "^4.19", "x": "latest", "y": "1.0.0 || 2.x"},
           "devDependencies": {"z": "~1"}, "optionalDependencies": {"o": "*"},
           "peerDependencies": {"p": ">=1 <3"}}
    lock = {"name": "t", "lockfileVersion": 3, "requires": True,
            "packages": {"": {"name": "t", **{s: pkg[s] for s in (
                "dependencies", "devDependencies", "optionalDependencies", "peerDependencies")}}}}
    d, m = make_site(tmp_path, package_json=json.dumps(pkg), lockfile=json.dumps(lock))
    assert scan_redlines(d, m) == []


def test_dev_dependency_spec_is_also_checked(tmp_path):
    pkg = {"name": "t", "private": True, "devDependencies": {"d": "file:./tool"}}
    d, m = make_site(tmp_path, package_json=json.dumps(pkg))
    assert any("devDependencies.d" in x for x in scan_redlines(d, m))


def test_lockfile_is_not_scanned_by_the_code_redlines(tmp_path):
    """lockfile 不是站点代码：里面出现 `cookie-session` 这种**包名**不该触发 auth 红线。

    站点自己若真依赖它，package.json 文本里就有这个词，那一处照样被 AUTH_RE 拦。
    """
    lock = copy.deepcopy(ONE_DEP_LOCK)
    lock["packages"]["node_modules/cookie-session"] = {
        "version": "2.1.0",
        "resolved": "https://registry.npmjs.org/cookie-session/-/cookie-session-2.1.0.tgz",
        "integrity": "sha512-" + "B" * 86 + "=="}
    d, m = make_site(tmp_path, package_json=ONE_DEP_PACKAGE_JSON, lockfile=json.dumps(lock))
    assert not any("auth" in x.lower() for x in scan_redlines(d, m))


def test_static_tier_needs_no_lockfile(tmp_path):
    d, m = make_site(tmp_path, tier="static")
    assert scan_redlines(d, m) == []
```

- [ ] **Step 3：跑，确认红**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests/test_redlines.py -q -k "lockfile or lock_mutation or shrinkwrap or dependency_spec or registry_specs or bundled or package_json_is_a_violation or static_tier_needs" 2>&1 | tail -5
```

预期：正向对照 `test_one_dep_lockfile_is_the_positive_control`、`test_registry_specs_in_every_section_pass`、`test_bundled_entry_…`、`test_lockfile_is_not_scanned_…`、`test_static_tier_needs_no_lockfile` **绿**（今天没有红线 8，合法站点当然过）；其余全部 **红**（`assert any(...)` 失败）。红的用例数 ≥ 10（变形）+ 7（规格）+ 5。这一步的红是"守卫能失败"的证据，记进 progress.md。

- [ ] **Step 4：实现**（候选实现，已在本机对两份真实 lockfile + 上面全部变形跑过；落盘后仍以 Step 5 为准）

`redlines.py` 的 `NPM_LIFECYCLE_KEYS` 之后加常量：

```python
# ── 红线 8：后端依赖锁定 ─────────────────────────────────────────────────
# buildspec 用 `npm ci`：没有 lockfile、或 lockfile 与 package.json 不一致，它直接失败——
# 但那发生在 provision-db 之后。合同层在 validate 就要求 backend/package-lock.json 存在、
# 可解析、且每一个包都钉到 registry + integrity，并把报错写成一行修法。
#
# 为什么要看 `resolved` 的主机：它是 npm ci 实际下载的地址，删 `.npmrc` 管不到它——指向任意
# tarball 的 lockfile 是另一条"改 registry 拉恶意包"的路。allowlist 主机 + 必带 sha512
# `integrity` 两条一起才构成"这份字节 ⇒ 这棵依赖树"。采用者用私有镜像时改这个常量，并同步
# `skills/site-builder/references/redlines.md`（有用例按本常量核对文档）。
NPM_REGISTRY_URL_PREFIXES = ("https://registry.npmjs.org/",)
# npm 7+ 写的 v2/v3 都带 `packages` 映射（键是 node_modules/… 路径）；v1（npm 6）只有嵌套
# 的 `dependencies` 树，字段形态不同，不支持——让用户用新 npm 重新生成比再写一套解析器可靠。
LOCKFILE_VERSIONS = (2, 3)
_SRI_SHA512_RE = re.compile(r"\bsha512-[A-Za-z0-9+/]+={0,2}")
# package.json 的依赖规格只许 semver 范围 / dist-tag。`file:` / `git+ssh://` / `github:u/r` /
# `u/r` / `https://…tgz` / `npm:alias@x` / `link:` 都含 `:` 或 `/`，一条判据全拒：它们要么装
# 本地字节（lockfile 里是 link，不可复现），要么绕开 registry allowlist。
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LOCKFILE_REGEN_HINT = ("（在 backend/ 下用 npm ≥ 7 跑 "
                       "`npm install --package-lock-only --registry=https://registry.npmjs.org/`"
                       " 重新生成）")
```

`_scan_package_json` 改成也查依赖规格（生命周期脚本那条文案**逐字不变**——`account-trust-boundary.md` 与 DEPLOY.md 都引用它）：

```python
def _dep_map(pkg: dict, section: str) -> dict:
    v = pkg.get(section)
    return v if isinstance(v, dict) else {}


def _scan_dependency_specs(pkg: dict, rel: Path) -> list[str]:
    """package.json 四个依赖段的规格只许 registry 形态（semver 范围 / dist-tag）。"""
    out: list[str] = []
    for section in _DEP_SECTIONS:
        for name, spec in _dep_map(pkg, section).items():
            if not isinstance(spec, str) or ":" in spec or "/" in spec:
                out.append(f"{rel}: {section}.{name} 的规格 {spec!r} 不是 registry 依赖"
                           "（禁止 file:/git/URL/别名规格——它们绕开锁定与 registry 校验）")
    return out


def _scan_package_json(text: str, rel: Path) -> list[str]:
    """拦 npm 生命周期脚本（在构建容器内以 CodeBuild 角色凭证执行）与非 registry 依赖规格。"""
    try:
        pkg = json.loads(text)
    except ValueError:
        return [f"{rel}: package.json 不是合法 JSON"]
    if not isinstance(pkg, dict):
        return [f"{rel}: package.json 顶层必须为对象"]
    out: list[str] = []
    scripts = pkg.get("scripts")
    if isinstance(scripts, dict):
        found = sorted(k for k in scripts if k.lower() in NPM_LIFECYCLE_KEYS)
        if found:
            out.append(f"{rel}: 禁止 npm 生命周期脚本 {found}（依赖安装阶段会执行任意命令）")
    return out + _scan_dependency_specs(pkg, rel)


def _scan_package_lock(text: str, rel: Path, pkg_text: str | None) -> list[str]:
    """package-lock.json 必须钉住每一个包：registry 主机 allowlist + sha512 integrity，
    且与同目录 package.json 的依赖声明一致。

    只看 v2/v3 的 `packages` 映射；根条目 `""` 是 package.json 的镜像（npm 原样写入四个
    依赖段），拿它做一致性比对。`inBundle` 的包随父 tarball 分发、没有自己的 resolved /
    integrity，是唯一放行的缺省形态。
    """
    try:
        lock = json.loads(text)
    except ValueError:
        return [f"{rel}: package-lock.json 不是合法 JSON{LOCKFILE_REGEN_HINT}"]
    if not isinstance(lock, dict):
        return [f"{rel}: package-lock.json 顶层必须为对象{LOCKFILE_REGEN_HINT}"]
    if lock.get("lockfileVersion") not in LOCKFILE_VERSIONS:
        return [f"{rel}: lockfileVersion 必须是 {list(LOCKFILE_VERSIONS)} 之一，"
                f"得到 {lock.get('lockfileVersion')!r}{LOCKFILE_REGEN_HINT}"]
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        return [f'{rel}: package-lock.json 缺少 packages[""] 根条目{LOCKFILE_REGEN_HINT}']
    out: list[str] = []
    for key, entry in sorted(packages.items()):
        if key == "":
            continue
        if not isinstance(entry, dict):
            out.append(f"{rel}: packages[{key!r}] 必须为对象")
            continue
        if not key.startswith("node_modules/") or entry.get("link") is True:
            out.append(f"{rel}: packages[{key!r}] 不是从 registry 安装的包"
                       "（workspace / file: / link 依赖不可复现，禁止）")
            continue
        if entry.get("inBundle") is True:
            continue
        resolved = entry.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(NPM_REGISTRY_URL_PREFIXES):
            out.append(f"{rel}: packages[{key!r}].resolved 必须以 "
                       f"{' / '.join(NPM_REGISTRY_URL_PREFIXES)} 开头，得到 {resolved!r}"
                       "（其它 registry/镜像/任意 URL 一律拒绝）")
        integrity = entry.get("integrity")
        if not isinstance(integrity, str) or not _SRI_SHA512_RE.search(integrity):
            out.append(f"{rel}: packages[{key!r}].integrity 缺少 sha512{LOCKFILE_REGEN_HINT}")
    if pkg_text is None:
        out.append(f"{rel}: 同目录没有 package.json——npm ci 需要两者同在")
        return out
    try:
        pkg = json.loads(pkg_text)
    except ValueError:
        return out      # package.json 自己那条已由 _scan_package_json 报
    if isinstance(pkg, dict):
        root = packages[""]
        for section in _DEP_SECTIONS:
            if _dep_map(pkg, section) != _dep_map(root, section):
                out.append(f'{rel}: packages[""].{section} 与 package.json 不一致——'
                           f"改了 package.json 之后要重新生成 lockfile{LOCKFILE_REGEN_HINT}")
    return out
```

`scan_redlines` 的 backend 段改成（只贴改动的那一段；`AUTH_RE` / `FILE_WRITE_RE` / `_check_user_name_decoded` / `.npmrc` / `HEALTH_RE` 各行不动）：

```python
    backend_dir = site_dir / "backend"
    backend_files = _read_all(backend_dir)
    texts = {p: t for p, t in backend_files}
    # lockfile 不是站点代码：不进 HEALTH_RE 的合并文本，也不走下面的泛用正则（几十 KB 的
    # 包名 / URL 上那些正则只会制造误报，且对 auth / 写文件红线没有信息量——站点自己依赖了
    # 什么，package.json 文本里就有）。它只走 _scan_package_lock。
    backend_text = "\n".join(t for p, t in backend_files if p.name != "package-lock.json")
    for p, text in backend_files:
        rel = p.relative_to(site_dir)
        if p.name == "package-lock.json":
            violations += _scan_package_lock(text, rel, texts.get(p.parent / "package.json"))
            continue
        if AUTH_RE.search(text):
            violations.append(f"{rel}: 站点代码禁止自带 auth 逻辑（鉴权由平台边缘层统一处理）")
        if FILE_WRITE_RE.search(text):
            violations.append(f"{rel}: 禁止写本地文件（Lambda 文件系统只读）")
        violations += _check_user_name_decoded(text, rel)
        if p.name == "package.json":
            violations += _scan_package_json(text, rel)
    # npm ci 的两个前提：package.json 与 package-lock.json 同在 backend/ 根。缺任一它在
    # package 阶段才失败（provision-db 之后）；这里提前到 validate 并给出修法。
    for name in ("package.json", "package-lock.json"):
        if not (backend_dir / name).is_file():
            violations.append(f"backend/{name} 缺失：后端依赖必须锁定，构建用 npm ci"
                              f"{LOCKFILE_REGEN_HINT}")
    if (backend_dir / "npm-shrinkwrap.json").exists():
        violations.append("backend/npm-shrinkwrap.json: 禁止——npm ci 会优先读它、跳过"
                          "被校验的 package-lock.json")
    if (backend_dir / ".npmrc").exists():
        violations.append("backend/.npmrc: 禁止自带 .npmrc（可改 registry 拉入恶意包）")
    if not HEALTH_RE.search(backend_text):
        violations.append("backend: 必须实现 GET /api/health 端点（部署冒烟测试依赖）")
```

- [ ] **Step 5：跑 contract 全套，确认全绿（含墙钟哨兵）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests -q 2>&1 | tail -3
```

预期：全部 passed（改动前基线 142 passed；本 Task 净增 28 条 ⇒ 170 passed）。哨兵若红，单独重跑一次再判断。

- [ ] **Step 6：deployer 的"合法 fullstack 站点"补上这一对**

`site-builder/deployer/tests/test_validate.py`：`GOOD_BACKEND` 之前加两个常量、字典加两项；两处 `namelist` 断言（`test_validation_failure_writes_no_build_artifact` 末尾与流式上传那条）改成四项：

```python
# 红线 8：fullstack 后端必须带 package.json + package-lock.json（contract/redlines.py），
# "合法站点"的 fixture 必须带上——无依赖的最小配对。
MINIMAL_PACKAGE_JSON = '{"name": "t", "private": true}'
MINIMAL_LOCK = json.dumps({"name": "t", "lockfileVersion": 3, "requires": True,
                           "packages": {"": {"name": "t"}}})
GOOD_BACKEND = {"run.sh": "#!/bin/sh\nnode app.js\n",
                "backend/app.js": "// GET /api/health\nok()",
                "backend/package.json": MINIMAL_PACKAGE_JSON,
                "backend/package-lock.json": MINIMAL_LOCK,
                # index.html 是合同要求（缺失 = 首页永久 403，见
                # contract/redlines.py）——"合法站点"的 fixture 必须带上
                "frontend/index.html": "<h1>hi</h1>"}
```

```python
        assert sorted(z.namelist()) == ["backend/app.js", "backend/package-lock.json",
                                        "backend/package.json", "run.sh"]  # 前端不进构建容器
```

（第二处同形，把原来的 `["backend/app.js", "run.sh"]` 换成同一个四项列表。）

- [ ] **Step 7：跑 deployer 全套**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q 2>&1 | tail -3
```

预期：除两条之外全绿。`test_deploy_fixture_flags.py` 里对 fixture 副本跑合同的两条（`test_e2e_bad_boot_backend_passes_the_contract`、`test_e2e_smoke_poison_backend_passes_the_contract_and_flips_to_public`）此刻会**红**在 `_contract_errors(tree) == []`（fixture 还没有 lockfile）——那是 Task 2 的输入；若只有这两条红，进入 Task 2。其它任何红都是本 Task 的问题。

**证据级别**：fake-unit（两套 pytest）+ sandbox（Step 4 注释引用的 npm 实测）。

---

### Task 2：黄金 fixture 补 lockfile，并用 parity 用例锁住

**Files:**
- Create: `site-builder/fixtures/nosql-notes/backend/package-lock.json`
- Create: `site-builder/fixtures/sql-expenses/backend/package-lock.json`
- Test: `site-builder/contract/tests/test_redlines.py`（追加 parity 用例）

**Interfaces:**
- Consumes：Task 1 的 `scan_redlines` 行为与 `contract.schema.validate_manifest`。
- Produces：两个 tracked 的 lockfile；`test_golden_fixture_passes_the_contract[<fixture>]`（三个参数：`nosql-notes` / `sql-expenses` / `static-hello`）。

- [ ] **Step 1：先写 parity 用例（红）**，追加到 `test_redlines.py`：

```python
# ── 黄金 fixture 与合同的 parity ─────────────────────────────────────────────
# 改合同要同步三处（CLAUDE.md）：校验器、references、fixtures。这条锁 fixtures：三个黄金样例
# 必须原样过 schema + 红线；fullstack 的两个必须带 lockfile（红线 8）。fixture 的 run.sh 在
# fixtures/ 父目录，不在扫描范围内（校验器不查它，打包器才查）。
FIXTURES = Path(__file__).parents[2] / "fixtures"


@pytest.mark.parametrize("fixture", sorted(
    p.name for p in FIXTURES.iterdir() if (p / "site.json").is_file()))
def test_golden_fixture_passes_the_contract(fixture):
    from contract.schema import validate_manifest
    tree = FIXTURES / fixture
    manifest = json.loads((tree / "site.json").read_text(encoding="utf-8"))
    assert validate_manifest(manifest) == []
    assert scan_redlines(tree, manifest) == [], f"黄金样例 {fixture} 过不了自己的合同"
    if manifest["tier"] != "static":
        assert (tree / "backend/package-lock.json").is_file(), \
            f"{fixture} 没有 lockfile——Agent 照着它生成的站点会被红线 8 拒"
```

- [ ] **Step 2：跑，确认两个 fullstack fixture 红、static 绿**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests/test_redlines.py -q -k golden_fixture 2>&1 | tail -5
```

预期：`[static-hello]` 绿；`[nosql-notes]`、`[sql-expenses]` 红在 `scan_redlines(...) == []`（报 `backend/package-lock.json 缺失`）。

- [ ] **Step 3：生成两份 lockfile（需要访问公共 registry；不装 node_modules）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
for f in nosql-notes sql-expenses; do
  (cd "site-builder/fixtures/$f/backend" \
   && npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
        --registry=https://registry.npmjs.org/ \
   && test ! -d node_modules)
done
git status --short site-builder/fixtures
```

预期：`git status` **只**多出两个 `?? …/backend/package-lock.json`；`package.json` 未被改写（单机实测 `--package-lock-only` 不改它；若出现 `M …/package.json`，`git checkout -- <file>` 还原——parity 用例比的是依赖映射，不比格式）。`--ignore-scripts` 在这里是习惯性防御（`--package-lock-only` 本来不执行脚本）；`--registry` **必须带**：实施者机器上的私有 registry 配置会让 `resolved` 指向镜像、fixture 自己过不了红线 8。

- [ ] **Step 4：跑 parity 与全套**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests -q 2>&1 | tail -3
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q 2>&1 | tail -3
```

预期：两套全绿（Task 1 Step 7 里 `test_deploy_fixture_flags.py` 那两条现在绿——它们复制的就是这两个 fixture）。

- [ ] **Step 5：secret 扫描新文件**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh --files \
  site-builder/fixtures/nosql-notes/backend/package-lock.json \
  site-builder/fixtures/sql-expenses/backend/package-lock.json
```

预期：`secret scan: clean`（单机实测如此；sha512 的 base64 不在它的模式里）。

**证据级别**：fake-unit + sandbox（对公共 registry 解析）。lockfile 的具体版本号会随 registry 漂移，**不写进任何文档**。

---

### Task 3：buildspec 改 `npm ci`，命令 allowlist 与反例同步

**Files:**
- Modify: `site-builder/deployer/buildspec-package.yml:20-22`
- Modify: `site-builder/deployer/tests/security_contracts.py:28-57`、`:115-131`
- Test: `site-builder/deployer/tests/test_security_contracts.py:75-131`

**Interfaces:**
- Produces：`security_contracts.EXPECT_NPM_CI = ["npm", "ci", "--omit=dev", "--no-audit", "--no-fund", "--ignore-scripts"]`（替换 `EXPECT_NPM_INSTALL`，全仓库只有这两个文件引用它）。
- 不变：`EXPECTED_COMMANDS` 仍是 12 条；`EXPECT_NPMRC_DELETE` 与它在 `npm ci` 之前的顺序不变；`buildspec_template_violations`（逐字节内联）与 `test_validate.py::test_buildspec_and_iam_name_the_validated_prefix_only` 不需要改。

- [ ] **Step 1：先给反例集加"退回 `npm install`"，并把锚点改成 `npm ci`（红）**

`test_security_contracts.py`：

```python
def _npm_line(src):
    return next(l for l in src.splitlines()
                if "npm ci" in l and l.strip().startswith("-"))
```

`_buildspec_counterexamples` 里 `j = next(...)` 那行的 `"npm install" in l` 改为 `"npm ci" in l`；字典末尾追加：

```python
        # 红线 8 的另一半：合同强制 lockfile，构建器就不能再用会**忽略** lockfile 漂移、
        # 会**改写** lockfile 的 npm install——退回去等于把可复现性交还给 registry 当天的解析
        "退回 npm install（不认 lockfile）": good.replace("npm ci ", "npm install "),
        "npm ci 后追加 npm install":
            "\n".join(lines[:i_n + 1] + ["      - npm install --ignore-scripts"] + lines[i_n + 1:]) + "\n",
```

- [ ] **Step 2：跑，确认红的形态正确**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_security_contracts.py -q -k "buildspec or command_contract" 2>&1 | tail -8
```

预期：`_npm_line` 找不到 `npm ci` ⇒ 整个反例参数化在**收集期**以 `StopIteration` 报错（这是"锚点没找到"的既定表现），或 `test_real_buildspec_satisfies_the_command_contract` 红。两种都算红；不要为了让它"红得好看"去改测试。

- [ ] **Step 3：改 buildspec（只动 npm 那一条与它的注释）**

`buildspec-package.yml` 第 20–22 行改为：

```yaml
      # --ignore-scripts 必需：站点 package.json 由 AI 生成、owner 可任意改，
      # preinstall/postinstall 会在本构建容器内以 CodeBuild 角色凭证任意执行。
      # npm ci 而不是 npm install：合同要求 backend/package-lock.json（红线 8），ci 只装
      # lockfile 里那棵树、与 package.json 不一致直接失败、不改写 lockfile ——
      # 同一份上传字节在任何时间装出同一棵依赖树。
      - npm ci --omit=dev --no-audit --no-fund --ignore-scripts
```

其余 11 条命令与文件头注释**一个字不动**（文件头有一条守卫按整份文本断言 `uploads/{job_id}` 变量形态不出现）。

- [ ] **Step 4：改 `security_contracts.py`**

```python
# **精确 token 列表**，不是"含某个子串"：加一个 `--ignore-scripts=false` 或
# `--no-ignore-scripts` 都能把语义翻过来，而"含 --ignore-scripts"照样绿。
# `ci` 而不是 `install`：合同强制 lockfile（红线 8），只有 ci 会拒 lockfile 漂移、不改写它。
EXPECT_NPM_CI = ["npm", "ci", "--omit=dev", "--no-audit", "--no-fund",
                 "--ignore-scripts"]
```

`EXPECTED_COMMANDS` 里 `EXPECT_NPM_INSTALL` → `EXPECT_NPM_CI`；它上方那段注释的「两条隔断（`EXPECT_NPMRC_DELETE` 在 `EXPECT_NPM_INSTALL` **之前**）」也改名（这一处最容易漏，Step 5 的 grep 会抓）；`build_container_interlock_violations` 里：

```python
    installs = [(i, c) for i, c in enumerate(cmds)
                if c[:2] == ["npm", "ci"]]
    if len(installs) != 1:
        out.append(f"buildspec 里有 {len(installs)} 条 `npm ci`（必须恰好 1 条）")
    else:
        i_npm, install = installs[0]
        if install != EXPECT_NPM_CI:
            out.append(f"`npm ci` 的 token 不是预期的精确列表。\n"
                       f"      期望: {EXPECT_NPM_CI}\n      实际: {install}\n"
                       f"      （精确比对是刻意的：`--ignore-scripts=false` 与 "
                       f"`--no-ignore-scripts` 都能把语义翻过来，而「含这个子串」照样绿）")
        finds = [i for i, c in enumerate(cmds) if c == EXPECT_NPMRC_DELETE]
        if not finds:
            got = [c for c in cmds if c and c[0] == "find" and ".npmrc" in c]
            out.append(f"找不到精确的删 .npmrc 命令 {EXPECT_NPMRC_DELETE}"
                       f"（近似的有 {got or '无'}——删错目录等于没删）")
        elif min(finds) > i_npm:
            out.append(f"删 .npmrc 发生在 `npm ci` **之后**（第 {min(finds)} 条 vs "
                       f"第 {i_npm} 条）——装依赖时 registry 已经被它改过了")
```

文件顶部 docstring 与 `EXPECTED_COMMANDS` 上方注释里提到 `npm install` 的地方改成 `npm ci`（`grep -n "npm install\|EXPECT_NPM_INSTALL" tests/security_contracts.py` 应为空）。

- [ ] **Step 5：跑 deployer 全套**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q 2>&1 | tail -3
grep -rn "npm install" buildspec-package.yml tests/security_contracts.py tests/test_security_contracts.py | grep -v "退回 npm install\|追加 npm install\|npm install --ignore-scripts\"\]" || echo "no stray 'npm install' mentions"
```

预期：全绿；`test_command_contract_rejects_each_counterexample` 从 11 个参数变成 13 个（`--collect-only -q | grep -c` 核对），两条新反例各自红过。CDK 模板断言 `test_infra_tables.py` 默认 skip，**不必**为本票开 `SB_CDK_TESTS=1`——它比的是逐字节内联，文件变了模板就跟着变，由 coordinator 部署时的 synth 证明。

**证据级别**：fake-unit。`npm ci` 在 CodeBuild `STANDARD_7_0` 镜像里真跑一次是 sandbox 证据，归 coordinator（见末节）。

---

### Task 4：文档同步（Skill references / SKILL.md，加 D4 的三份）

**Files:**
- Modify: `site-builder/skills/site-builder/references/contract.md:9-30`
- Modify: `site-builder/skills/site-builder/references/redlines.md`（在 `## 运行时约束` 之前插入 `## 红线 8`）
- Modify: `site-builder/skills/site-builder/SKILL.md:19-29`、`:98-111`
- Modify（D4）: `CLAUDE.md`（开头「CodeBuild 那道隔断分两层」那段）、`site-builder/DEPLOY.md:3181`、`docs/security/account-trust-boundary.md`（攻击路径表与其后一段）
- Test: `site-builder/contract/tests/test_redlines.py`（文档同步用例）

**Interfaces:**
- Consumes：Task 1 的 `NPM_REGISTRY_URL_PREFIXES`、`LOCKFILE_VERSIONS`、报错文案片段。

- [ ] **Step 1：先写文档同步用例（红）**，追加到 `test_redlines.py`：

```python
def test_lockfile_redline_is_documented_in_the_agent_facing_docs():
    """红线 8 的三处同步里的"文档"这一处：校验器拦了、文档没写 ⇒ Agent 只能靠报错自解释。

    期望值从代码真源推导（registry 前缀、lockfileVersion 列表），不在测试里抄第二份——
    否则"改了常量忘了改文档"这个唯一有价值的信号就没了（同表名字符集那条守卫的理由）。
    切到 `## 红线 8` 那一节内判，不做全文 substring。
    """
    from contract.redlines import LOCKFILE_VERSIONS, NPM_REGISTRY_URL_PREFIXES
    skill = Path(__file__).parents[2] / "skills" / "site-builder"
    redlines_doc = (skill / "references" / "redlines.md").read_text(encoding="utf-8")
    anchor = "## 红线 8"
    assert anchor in redlines_doc, "redlines.md 里找不到红线 8 那一节——本条已空转"
    section = redlines_doc.split(anchor, 1)[1].split("\n## ", 1)[0]
    for needle in ("package-lock.json", "npm-shrinkwrap.json", "npm install --package-lock-only",
                   f"lockfileVersion 必须是 {list(LOCKFILE_VERSIONS)}",
                   *NPM_REGISTRY_URL_PREFIXES, "file:"):
        assert needle in section, f"红线 8 那一节没写 {needle!r}"
    contract_doc = (skill / "references" / "contract.md").read_text(encoding="utf-8")
    assert "package-lock.json" in contract_doc and "npm ci" in contract_doc, \
        "contract.md 的目录树没把 lockfile 与 npm ci 写进去"
    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8")
    assert "package-lock.json" in skill_md, "SKILL.md 的打包步骤没提 lockfile 要随包上传"
```

- [ ] **Step 2：跑，确认红**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests/test_redlines.py -q -k documented_in_the_agent_facing_docs 2>&1 | tail -4
```

预期：`test_lockfile_redline_is_documented_in_the_agent_facing_docs` 红在 `anchor in redlines_doc`；另两条既有文档用例绿。

- [ ] **Step 3：改 `references/contract.md`**

目录树里 `package.json` 那一行换成两行：

```
    ├── package.json       # 依赖清单（只写 registry 依赖：semver 范围 / dist-tag）
    ├── package-lock.json  # 依赖锁定（必须；本地 npm install 生成后随包上传，部署时 npm ci --omit=dev）
```

`run.sh` 那条 bullet 之后加一条：

```markdown
- **`backend/package.json` 与 `backend/package-lock.json` 必须同在**（fullstack 两档，
  校验器强制，见 `references/redlines.md` 红线 8）。lockfile 由本地 `npm install`
  生成（也是本地预览的前提），打包时**不要排除它**；改过 `package.json` 之后要重新
  `npm install`，否则校验器会报两者不一致。依赖只能来自公共 npm registry。
```

- [ ] **Step 4：改 `references/redlines.md`**，在 `## 运行时约束` 之前插入：

```markdown
## 红线 8：后端依赖必须锁定（仅 fullstack）

- **规则**：`backend/package.json` 与 `backend/package-lock.json` 必须同时存在；
  lockfile 的 `lockfileVersion 必须是 [2, 3]` 之一（npm ≥ 7 生成的就是），每个包的
  `resolved` 必须以 `https://registry.npmjs.org/` 开头且带 `sha512` 的 `integrity`；
  lockfile 根条目的依赖声明必须与 `package.json` 一致；禁止 `backend/npm-shrinkwrap.json`；
  `package.json` 四个依赖段（`dependencies` / `devDependencies` / `optionalDependencies` /
  `peerDependencies`）的规格只许 semver 范围或 dist-tag——禁止 `file:`、`git+…`、
  `github:user/repo`、`user/repo`、URL、`npm:alias`（判据：规格里不能有 `:` 或 `/`）。
- **为什么**：部署时用 `npm ci` 按 lockfile 安装，同一份上传在任何时间装出同一棵依赖树，
  事后能回答"当时线上跑的是哪些包"。没有 lockfile 的话 `npm ci` 会在 provision-db 之后
  才失败；`resolved` 指向别的主机等于绕开平台的 registry 限制；`file:` / `link` 依赖装的是
  本地字节，`npm ci` 不会拒它，所以由校验器拒。
- **怎么做**：在 `backend/` 下跑一次 `npm install`（本地预览本来就要跑），会生成
  `package-lock.json`；打包时排除 `node_modules`、**保留** `package-lock.json`。
  只想生成锁文件不装依赖、或机器上配了私有镜像时用：
  ```bash
  cd backend && npm install --package-lock-only --registry=https://registry.npmjs.org/
  ```
  改过 `package.json` 之后重跑同一条命令。
- **违反后果**（按命中分别出现，报错尾巴都带上面那条重生成命令）：
  - `backend/package.json 缺失：后端依赖必须锁定，构建用 npm ci（…）`
  - `backend/package-lock.json 缺失：后端依赖必须锁定，构建用 npm ci（…）`
  - `backend/npm-shrinkwrap.json: 禁止——npm ci 会优先读它、跳过被校验的 package-lock.json`
  - `backend/package-lock.json: lockfileVersion 必须是 [2, 3] 之一，得到 1（…）`
  - `backend/package-lock.json: packages['node_modules/x'].resolved 必须以 https://registry.npmjs.org/ 开头，得到 '…'（其它 registry/镜像/任意 URL 一律拒绝）`
  - `backend/package-lock.json: packages['node_modules/x'].integrity 缺少 sha512（…）`
  - `backend/package-lock.json: packages['libs/x'] 不是从 registry 安装的包（workspace / file: / link 依赖不可复现，禁止）`
  - `backend/package-lock.json: packages[""].dependencies 与 package.json 不一致——改了 package.json 之后要重新生成 lockfile（…）`
  - `backend/package.json: dependencies.dep 的规格 'file:./dep' 不是 registry 依赖（禁止 file:/git/URL/别名规格——它们绕开锁定与 registry 校验）`
- **正确**：
  ```json
  { "name": "notes-backend", "private": true,
    "dependencies": { "express": "^4.19", "@aws-sdk/lib-dynamodb": "^3" } }
  ```
  加上 `npm install` 生成的 `package-lock.json`，两者一起进 zip。
- **错误**：
  ```json
  { "dependencies": { "helper": "file:../helper", "tool": "github:someone/tool" } }
  ```
  或者 zip 里只有 `package.json` 没有 `package-lock.json`。
- 黄金样例：`fixtures/nosql-notes/backend/` 与 `fixtures/sql-expenses/backend/` 各带一份
  lockfile。无依赖的后端同样要放这一对（对空依赖的 `package.json` 跑同一条命令即可）。
```

**报错样例里的 `（…）`** 是省略的 `LOCKFILE_REGEN_HINT` 全文；文档同步用例只按片段核对，样例不必逐字。

- [ ] **Step 5：改 `SKILL.md`**

工作流第 3 步 `templates/run.sh` 那一 bullet 之后加：

```markdown
   - fullstack 后端在 `backend/` 下跑一次 `npm install`（本地预览要它，**生成的
     `package-lock.json` 是合同要求的一部分**，见 `references/redlines.md` 红线 8）；
     依赖只写公共 registry 的包，不用 `file:` / git / URL 规格
```

第 5a 步改为：

```markdown
   a. 项目目录打包为 site.zip（site.json 在 zip 根；**排除 node_modules、保留
      backend/package-lock.json**——lockfile 缺失或与 package.json 不一致会在 validate 被拒）
```

「关键约束速查」加一行：

```markdown
- 后端依赖必须锁定：`backend/package-lock.json` 随包上传，只用公共 registry 的依赖
```

`<!-- tool-list:begin -->` … `<!-- tool-list:end -->` 区域**不动**（`mcp/tests/test_doc_tool_surface.py` 按它核对工具面）。

- [ ] **Step 6（D4）：`CLAUDE.md` 开头那段**

把「**依赖里**的生命周期脚本**只有** `buildspec-package.yml` 的 `npm install --ignore-scripts` 一道——`_scan_package_json` 从不检查 `dependencies`，而 `.tgz` 依赖根本不在扫描后缀里（实测：…）」改为：

```markdown
**依赖里**的生命周期脚本**只有** `buildspec-package.yml` 的 `npm ci --ignore-scripts` 一道——合同的红线 8 拒的是 `file:` / git / URL 规格与非公共 registry 的 lockfile 条目（可复现性），registry 上的依赖照样能带 `preinstall`，所以那条 flag 不能去（实测：带 `preinstall` 的包打成本地 `.tgz` 作依赖，`npm install` 会执行它，加上 `--ignore-scripts` 不会；今天这种 `file:` 规格在 validate 就被拒，但结论对 registry 依赖同样成立）。
```

同一段前半句「站点**自己的** `package.json` 生命周期脚本与 `backend/.npmrc` 由合同校验器在 CodeBuild **之前**就拒（`contract/redlines.py` 的 `NPM_LIFECYCLE_KEYS`）」不动。**不加日期、不写"已部署"。**

- [ ] **Step 7（D4）：`site-builder/DEPLOY.md` 威胁表那一行**

`| \`npm install\` 执行站点 preinstall 脚本（CodeBuild 内任意代码执行） | …` 里：第一格 `npm install` → `npm ci`；第二格开头 `--ignore-scripts` 之后插入 `+ 红线 8（lockfile 必须存在且只含公共 registry 条目、package.json 禁 file:/git/URL 规格）`。表格其它行与对齐空格随意，Markdown 不要求对齐。

- [ ] **Step 8（D4）：`docs/security/account-trust-boundary.md`**

攻击路径表（「站点**自己的** `package.json` 里写 preinstall …」那张）加一行：

```markdown
| lockfile 的 `resolved` 指向任意 tarball、`file:` / git / URL 规格的依赖 | **合同校验器一道**（红线 8）：`backend/package-lock.json` 必须存在，每个条目 `resolved` 在 registry allowlist 且带 sha512 `integrity`，`package.json` 四个依赖段禁非 registry 规格；构建器用 `npm ci` 只装 lockfile 里那棵树 |
```

表下那段「第三行才是要紧的那一行：`_scan_package_json` **只看站点自己的 `scripts` 段，从不检查 `dependencies`**（registry、版本范围、`git+`、`file:` 规格一概不限），而扫描器只读 `TEXT_EXT` 里的后缀 ⇒ **`.tgz` 依赖根本不被打开**。」改为：

```markdown
第三行才是要紧的那一行：红线 8 之后 `file:` / git / URL 规格在 validate 就被拒、lockfile 条目必须来自 registry allowlist，但那是**可复现性**约束——registry 上的包照样可以带生命周期脚本，校验器不打开任何 tarball。
```

紧接着的实测句（「实测（npm 10.9.8 / node 22）：把一个带 `preinstall` 的包 `npm pack` 成本地 `.tgz`…」）保留，它记录的是 `--ignore-scripts` 的必要性实验，结论未变。`<!-- baseline:… -->` 标记一个都不碰。

- [ ] **Step 9：跑 contract 全套 + mcp 的文档面守卫**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/contract"
.venv/bin/pytest tests -q 2>&1 | tail -3
cd "$(git rev-parse --show-toplevel)"
grep -n "npm install" CLAUDE.md site-builder/DEPLOY.md docs/security/account-trust-boundary.md \
  site-builder/skills/site-builder/SKILL.md site-builder/skills/site-builder/references/*.md
```

预期：contract 全绿；grep 剩下的 `npm install` 只应是"本地生成 lockfile"语境（SKILL.md 第 3 步、redlines.md 的重生成命令、trust-boundary 的历史实验句），**不再有任何一处把它写成 CodeBuild 的命令**。SKILL.md 的工具表守卫在 mcp 包（`run_locked_tests.sh`），本票没改那个区域，由 coordinator 的七套件覆盖。

**证据级别**：static + fake-unit。

---

### Task 5：收尾闸门（worker 最后一步）

- [ ] **Step 1：两套顺序跑**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/contract && .venv/bin/pytest tests -q 2>&1 | tail -2)
(cd site-builder/deployer && .venv/bin/pytest tests -q 2>&1 | tail -2)
```

预期：两套全绿。墙钟哨兵红则单独重跑 `tests/test_redlines.py::test_scanner_is_not_quadratic_on_large_files`。

- [ ] **Step 2：改动面自查**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git status --short
git diff --stat
bash site-builder/scripts/scan_staged_secrets.sh --files $(git status --short | awk '{print $2}')
```

预期：改动**只**落在「文件结构」那张表列出的文件；两个新 lockfile 是唯一的新文件；secret scan clean。`git diff CLAUDE.md` 里没有日期 / SHA / "已部署"字样。

- [ ] **Step 3：写 progress.md 并 worker_done**

`.superpowers/sdd/2026-09-07-asset-v1-09-lock-site-backend-dependencies/progress.md` 记：每个 Task 的红→绿证据（用例名 + 红时的断言）、两套件最终计数、生成 lockfile 时的 npm 版本（`npm --version`）与 `git status` 输出。worker_done 的 body 列出改动文件、套件结果、下面那节交给 coordinator 的事。

---

## 交给 coordinator 的事（worker 不做）

1. **合并后跑七套件**（顺序）。本票没碰 auth / panel / key-proxy / mcp / router，但 mcp 的 `test_doc_tool_surface.py` 读 SKILL.md、deployer 的 `test_delivery_docs_current.py` 读 CLAUDE.md / DEPLOY.md，要看它们仍绿。
2. **部署 deployer 栈**（`cd site-builder/deployer/infra && rm -rf cdk.out && … cdk deploy`）：两处改动都在这个栈里——validate Lambda 的 bundle 里 cp 进去的 `contract/` 与 CodeBuild 项目逐字节内联的 buildspec。**部署前** `verify_deployed_components.py` 对 `redlines.py` 的哈希核对会红，那是预期的；**部署后**必须绿。
3. **sandbox 证明 `npm ci` 在 CodeBuild 里真的能跑**：`python3 site-builder/scripts/deploy_fixture.py nosql-notes`（或整段 E2E），看 CodeBuild 日志里是 `npm ci` 且 SUCCEEDED。`STANDARD_7_0` 镜像的默认 npm ≥ 9，读 lockfileVersion 3 没有问题，但"应该没问题"不是证据。
4. **验证环境的存量站点**下一次重部会被红线 8 拒（没有 lockfile）——这是验证环境的中间状态，怎么补不进 tracked 文件；给站点作者的话就是报错里那一行命令。
5. **标记**：工单 Status → done；merged review §9 第 10 行 M14 划掉，并**写明处方反转的理由**（决策门 D1 第一点）——否则该行仍在说"不要强制 lockfile"。
6. `verify_deployed_components.py` 之外的四个 `verify_*` 与信任边界闸门与本票无关（没改 IAM、没改密钥、没改路由）。

---

## 自审记录（写完计划后对着工单与 M14 复核）

- **工单四项**：合同要求 lockfile → Task 1；`buildspec` 用 `npm ci --ignore-scripts` → Task 3；红线校验器拒无锁文件产物 → Task 1；Skill references 与 fixtures 同步 → Task 4 / Task 2。**M14 相邻观测**（`resolved` 可指向任意 tarball，"届时应校验 registry 主机"）→ Task 1 的 `NPM_REGISTRY_URL_PREFIXES`。
- **占位符扫描**：无 TBD / "补充测试" / "类似 Task N"；每段代码都是完整候选实现。
- **机械校验（写计划时做的，证据级别 fake-unit + sandbox；工作树未动）**：把本文件全部 ```python 块按 Task 1–4 的说明拼进 `site-builder/{contract,fixtures,skills,deployer}` 的一份 `/tmp` 副本，用仓库的两个 venv 跑：
  - contract 副本（`PYTHONPATH` 指向副本的 `src`，确认 `contract.redlines.__file__` 是副本）：**174 收集、171 绿、恰好 3 红**——`test_golden_fixture_passes_the_contract[nosql-notes]` / `[sql-expenses]`（fixture 还没有 lockfile）与 `test_lockfile_redline_is_documented_in_the_agent_facing_docs`（文档还没改），即 Task 2 / Task 4 的"先红"；把 Task 2 Step 3 那条命令生成的两份 lockfile 放进副本 fixtures 后 parity 三条全绿。墙钟哨兵 5.45 s 内跑完。
  - deployer 副本（同一 `PYTHONPATH`）：`test_security_contracts.py` 74 绿（命令合同反例 11 → 13 个参数；真 buildspec 换成 `npm ci` 后 `test_real_buildspec_satisfies_the_command_contract` 绿）；`test_validate.py` 93 绿、2 红——那两条读 `mcp/server.py` 与 `scripts/`，副本里没有这两个目录，是副本的路径伪影，不是改动引起的（在真工作树里它们读得到）。`test_deploy_fixture_flags.py` 在副本里因缺 `scripts/deploy_fixture.py` 收集失败，同一原因。
  - `npm ci` 的四种形态（空依赖 / 无 lockfile / 不一致 / `file:` link）与两份 lockfile 的结构在本机 npm 12.0.2 上实测，结论写在 Task 1 开头。
- **名字一致性**：`NPM_REGISTRY_URL_PREFIXES` / `LOCKFILE_VERSIONS` / `LOCKFILE_REGEN_HINT` / `_scan_package_lock(text, rel, pkg_text)` / `_scan_dependency_specs(pkg, rel)` / `EXPECT_NPM_CI` / `MINIMAL_PACKAGE_JSON` / `MINIMAL_LOCK` / `ONE_DEP_PACKAGE_JSON` / `ONE_DEP_LOCK` 在 Task 1–4 之间拼写一致；报错文案片段与 Task 4 文档样例、Step 1 用例的断言一致。
- **相邻面**（CLAUDE.md「Spec / Plan / Review Fix Discipline」）：调用方——`validate.py` 不改（打整目录）；既有状态——验证环境存量站点会被拒（归 coordinator 第 4 条）；兼容——静态 tier 不受影响（有用例）；部署顺序——只有 deployer 一个栈；回滚——`git revert` 本票 + 重部 deployer 栈即可，无数据迁移；验收——`verify_deployed_components.py` 的哈希核对会把"没重部"点出来。
