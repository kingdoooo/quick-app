# S1 · 隔离与鉴权加固 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把四条被绕过的鉴权/隔离不变量（M01/M02/M05/M06）各收敛到一处定义，每处配一条先会红的守卫。

**Architecture:** 不新增组件。新增或改签名 5 个「唯一定义」：`common.site_table_name`（表名格式）、`common.site_policy`（精确 ARN）、`permissions.effective_policy`（严格解析权限字段）、`session.verify_session_jwt(*, expected_typ)`（token 用途）、`origin_request._get_cookies`（同名 cookie 全取）。所有既有调用方改为调用它们，并用 AST 断言锁死"不许再手抄一份"。

**Tech Stack:** Python 3.12/3.13、boto3、pytest、moto（deployer/panel 测试）、AWS IAM/DynamoDB/Lambda@Edge/CDK

**Spec:** `docs/superpowers/specs/2026-08-22-s1-isolation-and-auth-hardening-spec.md`

## Global Constraints

- **每条修复必须先写一条会红的用例**，并实际运行确认它红了再写实现。本仓库教训：安全闸门的测试若没反向验证过，"加了守卫"与"守卫不生效"在 CI 上长得一模一样。
- **测试命令按包照抄，不要猜 venv**：
  - `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests/`**，裸 pytest 会误收集 `infra/cdk.out` 里的 asset 副本）
  - `cd site-builder/auth && ../contract/.venv/bin/pytest tests -q`（auth 无自己的 venv，借 contract 的）
  - `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`（router 的 venv 只有 CDK 依赖，借 deployer 的）
  - `cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q`（panel 无自己的 venv，借 deployer 的）
- **`permissions.py` 被复制进三个产物**（panel / key-proxy / MCP）⇒ 改它之后这三个都要重部，验收必须包含 `verify_deployed_components.py`。
- **`site-builder/auth/session.py` 与 `router/infrastructure/lambda/origin_request.py` 里的 HS256 实现必须保持算法字节等价**；改一处必须同步另一处。
- **部署顺序不可变**：deployer 栈 → panel/key-proxy/MCP 重部 → **存量角色 backfill**
  → auth → router → **等 CloudFront `Status == Deployed`** → 真机验收。
  **等待在 router 之后，不是之前**：真正触发 Lambda@Edge 传播的是 router 部署本身，
  在它之前等待不会等到任何新版本。完整序列见 Task 10 Step 3–5。
- **回滚严格逆序：先 router，再 auth。** 反过来（先回滚 auth 使其重新签发不带 `typ`
  的 token，而 Edge 仍要求 `typ`）会让所有新会话被 302，用户陷入登录循环。
  **backfill 不是纯代码部署**，它的恢复方式见 spec §7.3。
- **不把真实账号 ID / 域名 / site_id / 邮箱写进任何被跟踪的文件。** 测试固定用 `111111111111`、`example.test`、`foo-k3d9x1` 这类占位值。
- `router/infrastructure/lambda/_*_testable.py` 是测试期由测试文件从 `origin_request.py` 现生成的副本（gitignored），**不要手工编辑它们**。
- **secret scan 的调用形态有三条硬要求**（`~/AGENTS.md` 的全局提交纪律；
  脚本支持 `--files` / `--range` / `--allow-hits`，已核）：
  1. **新文件在 `git add` 之前**先单独扫：
     `bash site-builder/scripts/scan_staged_secrets.sh --files <新文件…> || exit 1`；
  2. `git add` 之后、`git commit` 之前再扫一次 staged diff：
     `bash site-builder/scripts/scan_staged_secrets.sh || exit 1`；
  3. **两处都必须带 `|| exit 1`**。裸写一行 `bash …scan…` 换行 `git commit` 时，
     扫描退非 0 **不会阻断** 后面的 commit——那正是这个脚本的文件头批评的形态
     （原先内联的 `git diff --cached | grep && echo` 命中也只 echo）。
     我在 v2 里恰好又犯了一次。
  - 命中时**不要自动清洗**：逐条确认是故意的 fixture/占位符/公开值，
    展示给人确认后再显式 `--allow-hits` 放行。
  - 它的模式里包含 `/Users/<name>/` 与 `/home/<name>/`，所以下一条不是可选项。
- **命令块里不写绝对主机路径。** 需要回仓库根用
  `cd "$(git rev-parse --show-toplevel)"`。绝对家目录路径对别人无意义，
  且会被上面那个扫描拦下。
- **多条 `cd` 必须各自套子 shell**：`(cd X && …)`。连写
  `cd a && …` 换行 `cd b && …` 时，第二条已经在 `a` 里执行，必然找不到 `b`。
- **所有多命令 bash 块一律以 `set -euo pipefail` 开头。** 不加的话，块里任何
  一条命令失败都不会阻止后面的命令，且块的退出码取**最后一条**——v2 的
  Task 10 正是这个形态：`backfill --apply` 退 1 后 auth/router 照常部署，
  Step 3 整块退 0；`--check` 退 1 后 `smoke_router.sh` 成功，Step 5 又是 0，
  于是「M01 闸门失败」与「S1 全绿」在执行记录上无法区分（Codex 指出的 P1
  假绿）。**测试块、部署块、验收块、commit 块全部适用**；backfill 的
  dry-run / `--apply` / `--check` 是硬停止点，失败必须立即中断整块。

---

### Task 1: 行形态只读体检脚本（**执行顺序：放在 Task 4 之后**）

> **依赖 Task 4。** 本脚本**不允许**自己实现一套解析——它必须调用
> `permissions.effective_policy`。v1 版本手抄了第二套"只看 AttributeValue 顶层
> 类型字母"的判据，结果 `allowed_users = {"L": [{"N": "7"}]}` 被判成"没问题"，
> 而 `effective_policy` 会拒（Codex 复核实测的假绿）。体检报绿、部署后站点卡住，
> 正是这条修复要消除的形态——而我在体检脚本里自己犯了一次。
> 编号保留不动，只调整执行次序，以免打乱后续任务的交叉引用。

**Files:**
- Create: `site-builder/scripts/audit_policy_rows.py`
- Test: `site-builder/deployer/tests/test_audit_policy_rows.py`

**Interfaces:**
- Consumes: `permissions.effective_policy` 与 `permissions.PolicyDataInvalid`（Task 4）
- Produces: `audit(rows) -> (active_count, [(site_id, reason)])`，以及可重跑的
  命令行入口。Task 10 在部署前重跑它。

- [ ] **Step 1: 写脚本**

```python
#!/usr/bin/env python3
"""只读体检：sites 表里有没有会被 S1 的严格解析拒绝的行。

**判据 100% 委托给 `permissions.effective_policy`，本文件不实现第二套。**
理由是实测过的假绿：只看 AttributeValue 顶层类型字母时，
`allowed_users = {"L": [{"N": "7"}]}` 会被判成"没问题"（L 是合法类型），
而 effective_policy 会拒（成员不是字符串、过不了 EMAIL_RE）。
体检报绿、部署后那个站点既不能改权限也不能部署。

**从仓库根跑，用系统 python3**（不要借 deployer/.venv/bin/python3——那个解释器的
CA 信任库是空的，每次 HTTPS 都 CERTIFICATE_VERIFY_FAILED，症状像网络故障）：

    python3 site-builder/scripts/audit_policy_rows.py

只读：只做 Scan，不写任何东西。部署 S1 之前必须重跑一次——行形态可能已变。
"""
import configparser
import pathlib
import sys

import boto3
from boto3.dynamodb.types import TypeDeserializer

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))

import permissions  # noqa: E402  与运行时**同一份**严格解析

_DESER = TypeDeserializer()


def _cfg():
    c = configparser.ConfigParser(interpolation=None)
    c.read(ROOT / "site-builder" / "config.ini")
    return c


def _plain(item: dict) -> dict:
    """AttributeValue dict → 普通 dict。

    `{"N": "0"}` 会反序列化成 `Decimal("0")` —— 正是 effective_policy 要拒的
    那个形态（`bool(Decimal(0))` 是 False，会被洗成"站主声明公开"）。
    """
    return {k: _DESER.deserialize(v) for k, v in item.items()}


def audit(rows: list) -> tuple:
    """→ (ACTIVE 行数, [(site_id, 拒绝原因)])。判据全部来自 effective_policy。"""
    active = [r for r in rows if r.get("status", {}).get("S") == "ACTIVE"]
    bad = []
    for raw in active:
        site = _plain(raw)
        try:
            permissions.effective_policy(site)
        except permissions.PolicyDataInvalid as exc:
            bad.append((site.get("site_id", "<unknown>"), str(exc)))
    return len(active), bad


def main() -> int:
    cfg = _cfg()
    ddb = boto3.client("dynamodb", region_name=cfg["Platform"]["region"].strip())
    rows, kw = [], {"TableName": cfg["Deployer"]["sites_table"].strip()}
    while True:
        resp = ddb.scan(**kw)
        rows += resp.get("Items", [])
        if "LastEvaluatedKey" not in resp:
            break
        kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    n_active, bad = audit(rows)
    print(f"sites 表共 {len(rows)} 行，其中 ACTIVE {n_active} 行")
    print(f"严格解析会拒绝的 ACTIVE 行：{len(bad)}")
    for site_id, reason in bad:
        print(f"  !! {site_id}: {reason}")
    if bad:
        print("\n上线 S1 会让上述站点既不能改权限也不能部署。先修这些行。")
        return 1
    print("  无 —— S1 上线不会卡住任何现有站点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: 给 `audit()` 写单测**

Create `site-builder/deployer/tests/test_audit_policy_rows.py`：

```python
"""体检脚本的单测。**必须有**：它是 S1 发布闸门之一，而它上一版是假绿的。"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "scripts"))
import audit_policy_rows as apr  # noqa: E402


def _row(**over):
    row = {"site_id": {"S": "s-1"}, "status": {"S": "ACTIVE"},
           "owner": {"S": "o@example.test"}, "require_login": {"BOOL": True},
           "allowed_users": {"S": "org"}, "collaborators": {"L": []}}
    row.update(over)
    return row


def test_clean_row_passes():
    assert apr.audit([_row()]) == (1, [])


def test_deleted_rows_are_not_audited():
    assert apr.audit([_row(status={"S": "DELETED"},
                           require_login={"N": "0"})]) == (0, [])


@pytest.mark.parametrize("field,value", [
    ("require_login", {"N": "0"}),                    # 会被 bool() 洗成 False
    ("allowed_users", {"L": [{"N": "7"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("allowed_users", {"L": []}),                     # 空名单 ← v1 假绿点
    ("allowed_users", {"L": [{"S": "not-an-email"}]}),  # 过不了 EMAIL_RE ← v1 假绿点
    ("collaborators", {"L": [{"N": "9"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("owner", {"S": ""}),                             # 空 owner
])
def test_bad_shapes_are_reported(field, value):
    n, bad = apr.audit([_row(**{field: value})])
    assert n == 1 and len(bad) == 1, f"{field}={value} 应被报出来"


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_missing_ambiguous_field_is_reported(field):
    row = _row()
    del row[field]
    assert len(apr.audit([row])[1]) == 1


def test_missing_collaborators_is_fine():
    row = _row()
    del row["collaborators"]
    assert apr.audit([row]) == (1, [])
```

- [ ] **Step 3: 运行单测**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_audit_policy_rows.py -q)`
Expected: PASS。**四条标了"v1 假绿点"的用例是本次修正的核心**——它们在 v1 的
实现下会失败（那版会说"没问题"）

- [ ] **Step 4: 真跑一次**

Run: `cd "$(git rev-parse --show-toplevel)" && python3 site-builder/scripts/audit_policy_rows.py`
Expected: 退出码 0，打印 `无 —— S1 上线不会卡住任何现有站点`（spec §8.1 已实测为 0）

- [ ] **Step 5: 扫描 + Commit**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash site-builder/scripts/scan_staged_secrets.sh \
     --files site-builder/scripts/audit_policy_rows.py \
             site-builder/deployer/tests/test_audit_policy_rows.py || exit 1
git add site-builder/scripts/audit_policy_rows.py \
        site-builder/deployer/tests/test_audit_policy_rows.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "chore(s1): sites 行形态体检——判据委托给 effective_policy，不手抄第二套"
```

---

### Task 2: `site_table_name` 表名格式唯一定义

**Files:**
- Modify: `site-builder/deployer/functions/common.py`（在 `site_prefix_for` 附近新增函数）
- Modify: `site-builder/deployer/functions/provision_dynamodb.py:12`
- Modify: `site-builder/deployer/functions/undeploy.py:43`
- Modify: `site-builder/deployer/functions/common.py:592`（顺带把授权那处也切过去，T3 会重写这段）
- Test: `site-builder/deployer/tests/test_common.py`

**Interfaces:**
- Produces: `common.site_table_name(site_id: str, logical: str) -> str`，返回 `f"site-data-{site_id}-{logical}"`。Task 3 用它拼精确 ARN。

- [ ] **Step 1: 写会红的用例**

加到 `site-builder/deployer/tests/test_common.py`：

```python
def test_table_name_format_has_a_single_definition():
    """`site-data-…` 这个格式只允许在 common.site_table_name 里出现一次。

    用 AST 取 f-string 的字面量片段，所以**文档字符串与注释不参与**——
    它们提及格式是好事，代码里手写格式才是问题。

    为什么值得一条守卫：M01 的修复要求建表 / 授权 / 删表三处对同一格式达成一致，
    而它现在被手抄了三份（provision_dynamodb 建、common.site_policy 授权、
    undeploy 删）。不收敛就等于在三处各写一遍新格式。
    """
    import ast
    import pathlib
    root = pathlib.Path(__file__).parents[1] / "functions"
    offenders = []
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.JoinedStr):
                continue
            literal = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if "site-data-" in literal:
                offenders.append(f"{path.name}:{node.lineno}")
    assert len(offenders) == 1 and offenders[0].startswith("common.py"), (
        f"表名格式应只在 common.site_table_name 出现一次，实际出现在: {offenders}")
```

- [ ] **Step 2: 运行确认它红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_common.py::test_table_name_format_has_a_single_definition -q`
Expected: FAIL，`offenders` 有 3 项（`common.py`、`provision_dynamodb.py`、`undeploy.py` 各一处）

- [ ] **Step 3: 加唯一定义**

在 `common.py` 的 `site_prefix_for` 上方插入：

```python
def site_table_name(site_id: str, logical: str) -> str:
    """站点数据表名的**唯一定义**。三处共用：建表（provision_dynamodb）、
    授权（site_policy）、删除（undeploy._purge_dynamodb）。

    **分隔符是 `-`，而 site_id 自身可以含 `-`**（形态 `<name>-<6位随机>`，
    且 name 允许内部连字符）⇒ 这个格式对**前缀匹配**是有歧义的：站点 A
    （id `foo-k3d9x1`）的 `site-data-foo-k3d9x1-*` 会匹配站点 B
    （id `foo-k3d9x1-…`）的表。正因如此 `site_policy` 必须逐表枚举精确 ARN，
    不得用通配（M01）。改这个格式要同时改三处调用方——
    `test_table_name_format_has_a_single_definition` 会在漂移时变红。
    """
    return f"site-data-{site_id}-{logical}"
```

- [ ] **Step 4: 三处调用方切过去**

`provision_dynamodb.py:12`：

```python
        table_name = common.site_table_name(event["site_id"], spec["name"])
```

`undeploy.py:43`：

```python
        name = common.site_table_name(site_id, t)
```

`common.py:592`（`site_policy` 里的 DynamoDB 资源，T3 会重写整段，这里先消除手写格式）：

```python
            "Resource": f"arn:aws:dynamodb:{region}:{acct}:table/{site_table_name(site_id, '')}*"})
```

> 注意：`undeploy.py` 顶部需要 `import common`——确认它已经有（`_purge_dynamodb` 所在文件已 import common 用于其他调用）；若没有则加上。

- [ ] **Step 5: 运行确认它绿，且全包不回归**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS，`offenders` 只剩 `common.py` 那一处

- [ ] **Step 6: Commit**

```bash
set -euo pipefail
git add site-builder/deployer/functions/common.py \
        site-builder/deployer/functions/provision_dynamodb.py \
        site-builder/deployer/functions/undeploy.py \
        site-builder/deployer/tests/test_common.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "refactor(s1/m01): 表名格式提成 common.site_table_name 唯一定义 + AST 守卫"
```

---

### Task 3: `site_policy` 改精确 ARN + 收窄日志组

**Files:**
- Modify: `site-builder/deployer/functions/common.py`（`site_policy`、`ensure_site_role`）
- Modify: `site-builder/deployer/functions/deploy_lambda_site.py:164`
- Modify: `site-builder/deployer/functions/provision_dsql.py:109`
- Test: `site-builder/deployer/tests/test_common.py`

**Interfaces:**
- Consumes: `common.site_table_name(site_id, logical)`（Task 2）
- Produces: `common.site_policy(site_id: str, engine: str, *, tables: list[str]) -> str`；`common.ensure_site_role(site_id: str, engine: str, *, tables: list[str]) -> str`

- [ ] **Step 1: 写三条会红的用例**

加到 `site-builder/deployer/tests/test_common.py`：

```python
def test_site_policy_never_matches_a_nested_sites_tables(monkeypatch):
    """A 的策略绝不能匹配 B 的表——即使 B 的 site_id 以 A 的 site_id 开头。

    这一对是关键（Codex 复审给出的绕过变体，已实测）：B 的**名字**
    `foo-k3d9x1-longname` 是合法站点名、且**不** fullmatch SITE_ID_RE，
    所以"拒绝像 site_id 的名字"那类修法拦不住它——只有精确 ARN 能。
    用这一对而不是 `foo-k3d9x1-ab12cd`，正是为了证明修的是 ARN 本身。
    """
    import fnmatch
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    a, b = "foo-k3d9x1", "foo-k3d9x1-longname-abc123"
    doc = json.loads(common.site_policy(a, "dynamodb", tables=["notes"]))
    resources = []
    for stmt in doc["Statement"]:
        res = stmt["Resource"]
        resources += res if isinstance(res, list) else [res]
    b_table = ("arn:aws:dynamodb:us-east-1:111111111111:table/"
               + common.site_table_name(b, "notes"))
    assert not any(fnmatch.fnmatchcase(b_table, r) for r in resources), (
        f"站点 {a} 的策略匹配到了站点 {b} 的表；资源集合: {resources}")


def test_log_group_resources_are_exact_not_a_bare_prefix(monkeypatch):
    """日志组资源必须是精确名 + stream 层两条，不多不少。

    裸前缀 `/aws/lambda/site-{site_id}*` 同样会匹配到 site_id 以本站点为前缀的
    其他站点的日志组（可写别人的日志流 = 审计伪造）。给两条是因为
    CreateLogStream / PutLogEvents 作用在 stream 层，只给 group ARN 会 403。
    """
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    doc = json.loads(common.site_policy("s-1", "none", tables=[]))
    logs = [s for s in doc["Statement"]
            if any(a.startswith("logs:") for a in s["Action"])]
    assert len(logs) == 1
    assert logs[0]["Resource"] == [
        "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/site-s-1",
        "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/site-s-1:*"]


def test_dynamodb_engine_without_tables_is_rejected(monkeypatch):
    """engine=dynamodb 但没声明表 ⇒ 抛错，不许退回通配。

    空 Resource 列表本身是非法 IAM，而合同要求 dynamodb 站点至少一张表。
    """
    import pytest
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with pytest.raises(ValueError, match="没有声明表"):
        common.site_policy("s-1", "dynamodb", tables=[])


def test_no_gsi_support_yet_so_index_arns_are_not_needed():
    """GSI 触发器：当前站点表没有 GSI，所以 policy 不含 index ARN。

    **这条是真的触发器，不是"精确 ARN 断言顺带覆盖"**（v1 的覆盖表那么写是错的
    ——那三条断言压根不看索引 ARN，将来加了 GSI 它们仍会全绿，而运行时访问索引
    会因缺 `table/.../index/*` 而 403）。谁将来给站点表加 GSI 支持，这条会红，
    强制他同步 `site_policy`。
    """
    import pathlib
    root = pathlib.Path(__file__).parents[1]
    provisioner = (root / "functions" / "provision_dynamodb.py").read_text()
    assert "GlobalSecondaryIndex" not in provisioner, (
        "provision_dynamodb 开始建 GSI 了 —— site_policy 必须同步加 "
        "table/<name>/index/* 资源，否则站点访问索引会 403")
    schema = (root.parents[0] / "contract" / "src" / "contract" / "schema.py").read_text()
    assert "index" not in schema.lower(), (
        "contract schema 开始接受索引声明了 —— 同上，site_policy 要同步")
```

- [ ] **Step 2: 运行确认它们红**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_common.py -k "nested_sites_tables or log_group_resources or without_tables or no_gsi_support" -q)`
Expected: 前三条 FAIL——两条因为当前是通配、一条因为当前 `site_policy` 只收两个位置参数（`TypeError: unexpected keyword argument 'tables'`）。第四条（GSI 触发器）**现在就应该 PASS**——它是防将来的哨兵，不是本次要修的缺陷

- [ ] **Step 3: 重写 `site_policy`**

替换 `common.py` 里整个 `site_policy` 函数：

```python
def site_policy(site_id: str, engine: str, *, tables: list[str]) -> str:
    """per-site 运行时角色的 inline policy。

    **DynamoDB 资源逐表枚举精确 ARN，不得用 `site-data-{site_id}-*` 通配**（M01）：
    site_id 自身可含 `-`，所以站点 A（id `foo-k3d9x1`）的通配会匹配站点 B
    （id `foo-k3d9x1-…`）的全部表 ⇒ 跨租户读写。PermissionsBoundary 放开的是
    整个 `site-data-*`（它只封顶最坏能力面），**per-tenant 隔离完全依赖本函数**。

    `tables` 是**必填关键字参数**——迫使调用方表态，而不是靠默认值悄悄退回通配。
    engine 为 `dsql` / `none` 时忽略它；engine 为 `dynamodb` 而它为空则抛错。
    """
    import json
    region, acct = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"), os.environ["ACCOUNT_ID"]
    fn = f"site-{site_id}"
    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        # 精确日志组名（函数名就是 site-{site_id}）+ stream 层两条。
        # 原来是裸前缀 `…/site-{site_id}*`，会匹配到 id 以本站点为前缀的其他站点。
        "Resource": [f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{fn}",
                     f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{fn}:*"]}]
    if engine == "dynamodb":
        if not tables:
            raise ValueError(
                f"站点 {site_id} 的 engine 是 dynamodb 但没有声明表——"
                "空 Resource 列表是非法 IAM，且合同要求至少一张表")
        statements.append({
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": [
                f"arn:aws:dynamodb:{region}:{acct}:table/{site_table_name(site_id, t)}"
                for t in tables]})
    elif engine == "dsql":
        statements.append({"Effect": "Allow", "Action": "dsql:DbConnect",
                           "Resource": "*"})  # 数据隔离由 per-site PG role 保证
    return json.dumps({"Version": "2012-10-17", "Statement": statements})
```

- [ ] **Step 4: `ensure_site_role` 透传 + 两个调用点**

`common.py` 的 `ensure_site_role`：

```python
def ensure_site_role(site_id: str, engine: str, *, tables: list[str]) -> str:
    """幂等创建 per-site 运行时角色（带 PermissionsBoundary）并刷新 inline policy。

    `tables` 透传给 site_policy（必填，理由见那里）。**每次部署都刷新 policy**
    ——这也是 M01 存量收敛的机制：站点下一次部署时自动换成精确 ARN。
    """
    iam = boto3.client("iam")
    name = site_role_name(site_id)
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=TRUST_POLICY,
            PermissionsBoundary=os.environ["RUNTIME_BOUNDARY_ARN"],
            Tags=[{"Key": "project", "Value": "site-builder"},
                  {"Key": "site_id", "Value": site_id}])["Role"]["Arn"]
    iam.put_role_policy(RoleName=name, PolicyName="site-scope",
                        PolicyDocument=site_policy(site_id, engine, tables=tables))
    return arn
```

`deploy_lambda_site.py:164`（`engine` 已在 `:163` 从 manifest 取好）：

```python
    tables = [t["name"] for t in
              event["manifest"].get("database", {}).get("tables", [])]
    role_arn = _ensure_site_role(event["site_id"], engine, tables=tables)
```

`provision_dsql.py:109`：

```python
    common.ensure_site_role(site_id, "dsql", tables=[])
```

- [ ] **Step 5: 运行确认全绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS（三条新用例转绿，既有用例不回归）

- [ ] **Step 6: Commit**

```bash
set -euo pipefail
git add site-builder/deployer/functions/common.py \
        site-builder/deployer/functions/deploy_lambda_site.py \
        site-builder/deployer/functions/provision_dsql.py \
        site-builder/deployer/tests/test_common.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m01): per-site IAM 改逐表精确 ARN + 日志组收窄——通配会匹配到嵌套 site_id 的其他站点"
```

---

### Task 3b: `tier_engine` 唯一定义

**Files:**
- Modify: `site-builder/deployer/functions/common.py`（新增 `tier_engine`）
- Modify: `site-builder/deployer/functions/undeploy.py:179-180`
- Test: `site-builder/deployer/tests/test_common.py`

**Interfaces:**
- Produces: `common.tier_engine(tier: str) -> str`，返回 `"none" | "dynamodb" | "dsql"`。Task 3c 的 backfill 用它从存量行推出 engine。

> 为什么 S1 要动这个：Task 3c 的 backfill 必须从 sites 行的 `tier` 推出 engine
> （拿不到 manifest），而这个映射**已经被手抄了两份**——真源
> `contract.schema.TIER_ENGINE:6`，与 `undeploy.py:180` 的内联版。
> backfill 再抄第三份就是本轮要消除的那个形态。这是本轮发现的第 6 个"手抄多份"。

- [ ] **Step 1: 写会红的用例**

加到 `site-builder/deployer/tests/test_common.py`：

```python
def test_tier_engine_agrees_with_the_contract():
    """`common.tier_engine` 必须与 contract 的 TIER_ENGINE 逐项一致。

    真源是合同（tier→engine 是合同语义），deployer 侧只能有一个派生实现。
    两处漂移的症状：backfill 给 DSQL 站点算出 engine="dynamodb"，
    于是重写 policy 时丢掉 `dsql:DbConnect` —— **站点当场连不上库**。
    """
    from contract.schema import TIER_ENGINE
    for tier, engine in TIER_ENGINE.items():
        assert common.tier_engine(tier) == engine, tier


def test_tier_engine_rejects_an_unknown_tier():
    """未知 tier 必须抛错，不许猜。

    backfill 会因此跳过该角色并计入"需人工"，而不是给它算出一个可能错的 engine。
    """
    import pytest
    with pytest.raises(ValueError, match="未知 tier"):
        common.tier_engine("fullstack-graph")


def test_undeploy_does_not_hand_roll_the_tier_mapping():
    """undeploy 不许再内联 tier→engine（它现在有第二份）。"""
    import pathlib
    src = (pathlib.Path(__file__).parents[1] / "functions" / "undeploy.py").read_text()
    assert "fullstack-sql" not in src, (
        "undeploy 仍在内联 tier→engine，应改调 common.tier_engine")
```

- [ ] **Step 2: 运行确认它们红**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_common.py -k tier_engine -q)`
Expected: FAIL，`AttributeError: module 'common' has no attribute 'tier_engine'`

- [ ] **Step 3: 加 `tier_engine`**

在 `common.py` 的 `site_table_name` 附近插入：

```python
# tier → 数据引擎。**真源是 `contract.schema.TIER_ENGINE`**，本函数是 deployer 侧
# 的唯一派生实现（运行时不 import contract 包：那是 validate 步骤才装的依赖）。
# 两处一致性由 test_tier_engine_agrees_with_the_contract 锁死。
_TIER_ENGINE = {"static": "none", "fullstack-nosql": "dynamodb",
                "fullstack-sql": "dsql"}


def tier_engine(tier: str) -> str:
    """tier → engine。未知 tier **抛错，不猜**。

    猜错的代价不对称：把 DSQL 站点算成 dynamodb 会让重写 policy 时丢掉
    `dsql:DbConnect`，站点当场连不上库。调用方（backfill）应把抛错的站点
    计入"需人工"并跳过。
    """
    if tier not in _TIER_ENGINE:
        raise ValueError(f"未知 tier {tier!r}（已知：{sorted(_TIER_ENGINE)}）")
    return _TIER_ENGINE[tier]
```

- [ ] **Step 4: `undeploy` 切过去**

`undeploy.py:179-180` 替换为：

```python
        engine = event.get("engine") or common.tier_engine(site.get("tier", "static"))
```

> 行为差异写明：旧版把 `static` 算成 `"dynamodb"`（`"dsql" if tier ==
> "fullstack-sql" else "dynamodb"`），新版按合同算成 `"none"`。实际无影响
> ——static 站点没有 `data_tables`，`_purge_dynamodb` 拿到空列表什么都不删。
> 缺 `tier` 的稀疏行回落 `"static"`（最保守：不删任何东西）。

- [ ] **Step 5: 运行确认绿**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests -q)`
Expected: PASS

- [ ] **Step 6: 扫描 + Commit**

```bash
set -euo pipefail
git add site-builder/deployer/functions/common.py \
        site-builder/deployer/functions/undeploy.py \
        site-builder/deployer/tests/test_common.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "refactor(s1/m01): tier→engine 提成 common.tier_engine 唯一定义 + 与合同一致性守卫"
```

---

### Task 3c: 存量角色 backfill + 「不合格角色数 == 0」硬闸门

**Files:**
- Create: `site-builder/scripts/backfill_site_role_policies.py`
- Test: `site-builder/deployer/tests/test_backfill_site_role_policies.py`

**Interfaces:**
- Consumes: `common.ensure_site_role(site_id, engine, *, tables)`（Task 3）、`common.tier_engine(tier)`（Task 3b）
- Produces: `check_roles(iam) -> list[(role, reason)]`（闸门用，判据四层：site-scope 完整文档等值、角色上**只许有 site-scope 一条 policy**、ACTIVE 站点角色反向存在、功能模拟另见 simulate_active_sites；多余 policy 与缺失角色都按 reason 前缀分流**需人工**，不自动修）、`verify_access(iam, site_id, tables)`（IAM 模拟器验收，动作清单从期望 policy 现取——**全部** DynamoDB 数据动作，读写都验）、`simulate_active_sites(iam)`（--check 对全部 dynamodb 站点跑功能模拟）、`plan_for(site_id, site)`、`_load_env(config_path=None)`（含 STS 账号核对；path 可注入是给单测的，生产不传参）、`apply_plans(iam, todo)`（先备份后写）、`_persist_backup(iam, role_names)`（第一笔 IAM 写入前原子落盘、合并不覆盖、带账号元数据且不一致拒绝合并）、`active_fullstack_site_ids()`、命令行 `--apply` / `--check`

> **为什么必须做而不是等下次部署**（这是 v1 的设计错误，Codex 复核指出）：
> `table/site-data-{A}-*` 是**向前看的**通配——它覆盖所有以 A 的 id 为前缀的
> site_id，**包括本次上线之后才创建的**。所以懒收敛不是"旧风险留在原地"，
> 而是把每个存量站点留成对未来嵌套站点生效的陷阱。
> 实测：旧 policy `table/site-data-foo-k3d9x1-*` 匹配将来的
> `site-data-foo-k3d9x1-longname-abc123-notes`。
> 实测存量：**7 个角色全部带通配**（2 个带 DynamoDB 通配、7 个带日志组裸前缀）。

- [ ] **Step 1: 写会红的用例**

Create `site-builder/deployer/tests/test_backfill_site_role_policies.py`：

```python
"""backfill 的单测。

闸门的判据是「实际 policy == 从当前 sites 行推导的期望 policy」，
所以这里的重点用例是那些**不含通配却依然不可用**的形态
（错账号、漏表、孤儿角色）——只查 `*` 的闸门会放过它们。
"""
import json
import os
import pathlib
import sys

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "scripts"))
import backfill_site_role_policies as bf  # noqa: E402


class _FakeIam:
    """只实现 backfill 用到的调用。

    get_role_policy 缺失时抛真形态的 NoSuchEntity ClientError——
    `_actual_policy` 只把这一种判为"policy 不存在"，其他错误原样抛出。
    """

    def __init__(self, policies, extra_inline=None, attached=None):
        self._policies = policies                  # {role_name: site-scope 文档}
        self._extra_inline = extra_inline or {}    # {role_name: [policy 名…]}
        self._attached = attached or {}            # {role_name: [policy ARN…]}

    def get_paginator(self, name):
        if name == "list_roles":
            pages = [{"Roles": [{"RoleName": r} for r in self._policies]}]
            return type("P", (), {"paginate": lambda _s, **_k: pages})()
        if name == "list_role_policies":
            def _pg(_s, *, RoleName, **_k):
                names = ["site-scope"] if RoleName in self._policies else []
                return [{"PolicyNames":
                         names + self._extra_inline.get(RoleName, [])}]
            return type("P", (), {"paginate": _pg})()
        if name == "list_attached_role_policies":
            def _pg(_s, *, RoleName, **_k):
                return [{"AttachedPolicies": [
                    {"PolicyArn": a}
                    for a in self._attached.get(RoleName, [])]}]
            return type("P", (), {"paginate": _pg})()
        raise AssertionError(f"_FakeIam 不认识 paginator {name}")

    def get_role_policy(self, RoleName, PolicyName):
        if RoleName not in self._policies:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
                "GetRolePolicy")
        return {"PolicyDocument": self._policies[RoleName]}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # 反向存在性检查默认打空桩——check_roles 的每条用例只关心手上那个角色，
    # 不该顺带去扫真实 sites 表。要测反向缺失的用例自己覆盖它。
    monkeypatch.setattr(bf, "active_fullstack_site_ids", lambda: [])
    return monkeypatch


def _nosql_site(*tables):
    return {"tier": "fullstack-nosql", "data_tables": list(tables)}


def test_norm_is_insensitive_to_iam_normalization():
    """IAM 会把单元素列表回成字符串、也不保证语句顺序 ⇒ 不能比 JSON 字符串。"""
    a = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:1"},
                       {"Effect": "Allow", "Action": ["logs:Put"],
                        "Resource": ["arn:2", "arn:3"]}]}
    b = {"Statement": [{"Effect": "Allow", "Action": ["logs:Put"],
                        "Resource": ["arn:3", "arn:2"]},
                       {"Effect": "Allow", "Action": ["s3:GetObject"],
                        "Resource": ["arn:1"]}]}
    assert bf._norm(a) == bf._norm(b)


def test_norm_keeps_condition_and_other_statement_fields():
    """「精确 ARN + 额外 Condition」不能被判成合格（Codex 指出）。

    v2 的 `_norm` 只比 (Effect, Action, Resource) 三元组——Condition /
    NotAction / NotResource 被静默丢弃。带限区 Condition 的角色文本上
    "逐项相等"，于是不进 targets、不跑功能模拟，--check 绿而站点不可用。
    """
    base = {"Statement": [{"Effect": "Allow",
                           "Action": ["dynamodb:GetItem"],
                           "Resource": ["arn:aws:dynamodb:r:1:table/x"]}]}
    conditioned = {"Statement": [{
        **base["Statement"][0],
        "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}]}
    assert bf._norm(base) != bf._norm(conditioned)


def test_check_roles_passes_when_actual_equals_expected(env):
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    assert bf.check_roles(_FakeIam({"site-rt-a-abc123": good})) == []


def test_check_roles_flags_a_wrong_account_policy_that_has_no_wildcard(env):
    """**闸门判的是"等于期望"，不是"没有 `*`"。**

    这条构造一个**除了账号号码全对、且没有任何通配**的 policy——它正是 v2 那版
    只查 `*` 的闸门会放过、而站点访问自己的表会全部 AccessDenied 的形态
    （Codex 复核指出）。错 region、漏表同理。
    """
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    env.setenv("ACCOUNT_ID", "999999999999")            # 先用错账号造"实际"
    actual = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    env.setenv("ACCOUNT_ID", "111111111111")            # 期望按正确账号算
    # 前提断言**只看 DynamoDB 表 ARN**：日志资源按设计带 stream 层通配
    # `log-group:…:*`，那不是 M01 的危险表前缀——对整文档查 `*` 会让这条
    # 用例在 policy 形态完全正确时也必然失败（Codex 指出的确定性 Blocker：
    # v4 就是整文档断言，Step 4 永远不能全绿）。
    ddb_resources = [
        r for stmt in actual["Statement"]
        if any(str(a).startswith("dynamodb:") for a in
               (stmt["Action"] if isinstance(stmt["Action"], list)
                else [stmt["Action"]]))
        for r in (stmt["Resource"] if isinstance(stmt["Resource"], list)
                  else [stmt["Resource"]])]
    assert ddb_resources and all("*" not in r for r in ddb_resources), \
        "这条用例的前提：DynamoDB 表 ARN 精确、不含通配"
    bad = bf.check_roles(_FakeIam({"site-rt-a-abc123": actual}))
    assert len(bad) == 1 and "不一致" in bad[0][1]


def test_check_roles_flags_a_missing_table(env):
    """漏表同样不合格——新加的表会 AccessDenied，而 policy 里没有通配。"""
    import common
    env.setattr(common, "get_site_consistent",
                lambda sid: _nosql_site("notes", "tags"))
    stale = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam({"site-rt-a-abc123": stale}))
    assert len(bad) == 1


def test_check_roles_flags_an_extra_inline_policy(env):
    """site-scope 完全等于期望、但角色上还挂着第二条 inline ⇒ 不合格且需人工。

    boundary 对全部 DynamoDB 数据动作放行整个 site-data-*（infra/app.py 的
    SiteRuntimeBoundary），残留的"PutItem on site-data-*"调试 policy 与它
    取交集就是有效跨租户写权限——只比 site-scope 的闸门对它失明，只模拟
    GetItem 的功能验收也测不出（Codex 指出的 P1）。
    """
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam(
        {"site-rt-a-abc123": good},
        extra_inline={"site-rt-a-abc123": ["debug-put"]}))
    assert len(bad) == 1 and bad[0][1].startswith(bf.EXTRA_POLICY_REASON)


def test_check_roles_flags_an_attached_managed_policy(env):
    """attached managed policy 同理——角色上只许有 site-scope 这一条。"""
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam(
        {"site-rt-a-abc123": good},
        attached={"site-rt-a-abc123":
                  ["arn:aws:iam::111111111111:policy/debug"]}))
    assert len(bad) == 1 and bad[0][1].startswith(bf.EXTRA_POLICY_REASON)


def test_check_roles_flags_an_orphan_role(env):
    """sites 表里没有对应行的角色（下线清理失败留下的）也要报出来。"""
    import common
    env.setattr(common, "get_site_consistent", lambda sid: None)
    iam = _FakeIam({"site-rt-gone-abc123": {"Statement": []}})
    bad = bf.check_roles(iam)
    assert len(bad) == 1 and "孤儿" in bad[0][1]


def test_check_roles_flags_an_active_site_whose_role_is_missing(env):
    """反向也要查：ACTIVE fullstack 站点的角色**不存在**同样不合格。

    v2 只从现存 site-rt-* 角色出发反查 sites 行——"角色整个缺失"
    （误删/清理脚本写错）完全不可见，IAM 里一个角色都没有时闸门反而
    全绿（Codex 指出）。理由必须是 MISSING_ROLE_REASON 原文——main 按
    这个前缀把它分流到需人工（不自动重建：异常要先查根因，且这保证了
    备份里 null 不会混入"角色本身不存在"态，见 _persist_backup docstring）。
    """
    env.setattr(bf, "active_fullstack_site_ids", lambda: ["a-abc123"])
    bad = bf.check_roles(_FakeIam({}))
    assert bad == [("site-rt-a-abc123", bf.MISSING_ROLE_REASON)]


def _min_config(tmp_path, account="111111111111"):
    """最小可用 config。**不读真实 config.ini**：它是 gitignored 的，干净
    clone / CI 里不存在——依赖它的测试会以"读不到 config"失败，与被测行为
    无关（Codex 指出，与上一轮 parents[3] 同型的"本机能过、clone 必挂"）。"""
    p = tmp_path / "config.ini"
    p.write_text(f"[Platform]\naccount_id = {account}\nregion = us-east-1\n"
                 "[Deployer]\nsites_table = sb-sites-test\n")
    return p


def test_load_env_refuses_a_mismatched_account(monkeypatch, tmp_path):
    """**凭证账号 ≠ config 目标账号 ⇒ 拒绝执行。**

    不核对的话：凭证指向别的账号 ⇒ 那里没有 site-rt-* ⇒ 闸门看到"0 个不合格"
    ⇒ dry-run/--apply/--check 全退 0，而目标账号里的旧通配角色一个都没动，
    发布记录却显示 M01 已闭环（Codex 复核指出的 P1）。
    """
    class _Sts:
        def get_caller_identity(self):
            return {"Account": "999999999999"}
    monkeypatch.setattr(bf.boto3, "client", lambda name, **kw: _Sts())
    with pytest.raises(SystemExit, match="拒绝执行"):
        bf._load_env(_min_config(tmp_path))


def test_load_env_overrides_stale_shell_values(monkeypatch, tmp_path):
    """config 值必须**直接覆盖**，不能让 shell 残留胜出（不用 setdefault）。

    仓库既有的两个迁移脚本 docstring 都明写了这条理由。
    """
    class _Sts:
        def get_caller_identity(self):
            return {"Account": "111111111111"}
    monkeypatch.setattr(bf.boto3, "client", lambda name, **kw: _Sts())
    monkeypatch.setenv("SITES_TABLE", "wrong-sites-table")
    bf._load_env(_min_config(tmp_path))
    assert os.environ["SITES_TABLE"] == "sb-sites-test"


def test_no_iam_mutation_happens_if_the_backup_cannot_be_persisted(env, tmp_path):
    """**先留档，后动生产**：备份写失败 ⇒ `ensure_site_role` 一次都没调。

    v2 把备份攒在内存字典、循环结束才写文件——第 2 个角色写入抛异常
    （IAM 限流最常见）时，第 1 个已被改而备份文件不存在，spec §7.3 承诺的
    回滚材料落空（Codex 用窄复现证实过）。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role",
                lambda *a, **k: calls.append((a, k)))
    env.setattr(bf, "BACKUP_PATH", tmp_path / "no-such-dir" / "backup.json")
    iam = _FakeIam({"site-rt-a-abc123": {"Statement": []}})
    with pytest.raises(FileNotFoundError):
        bf.apply_plans(iam, [("site-rt-a-abc123", "a-abc123",
                              "dynamodb", ["notes"])])
    assert calls == []


def _backup_doc(roles, account="111111111111", region="us-east-1"):
    return {"schema_version": 1, "account_id": account,
            "region": region, "roles": roles}


def test_backup_never_overwrites_an_existing_snapshot(env, tmp_path):
    """重跑合并、绝不覆盖：已收敛的角色不再是 target，无条件覆盖备份文件会
    丢掉它们的原始通配 policy——回滚要的恰是**第一份**快照（Codex 指出）。"""
    path = tmp_path / "backup.json"
    path.write_text(json.dumps(_backup_doc({"site-rt-done-abc123": {"orig": 1},
                                            "site-rt-a-abc123": {"orig": 1}})))
    env.setattr(bf, "BACKUP_PATH", path)
    bf._persist_backup(_FakeIam({"site-rt-a-abc123": {"now": 2}}),
                       ["site-rt-a-abc123"])
    roles = json.loads(path.read_text())["roles"]
    assert roles["site-rt-done-abc123"] == {"orig": 1}   # 不在本次 targets，不丢
    assert roles["site-rt-a-abc123"] == {"orig": 1}      # 在本次 targets，不覆盖


def test_backup_refuses_to_merge_a_snapshot_from_another_account(env, tmp_path):
    """备份带账号元数据，合并前核对：A 账号的旧快照不能被"绝不覆盖"保留成
    B 账号同名 role 的回滚材料——回滚时会把 A 的资源 ARN 写进 B
    （Codex 指出）。不一致就拒绝执行，绝不静默合并。"""
    path = tmp_path / "backup.json"
    path.write_text(json.dumps(_backup_doc(
        {"site-rt-a-abc123": {"orig": 1}}, account="999999999999")))
    env.setattr(bf, "BACKUP_PATH", path)
    with pytest.raises(SystemExit, match="拒绝合并"):
        bf._persist_backup(_FakeIam({"site-rt-a-abc123": {"now": 2}}),
                           ["site-rt-a-abc123"])
    # 文件必须原封不动
    assert json.loads(path.read_text())["account_id"] == "999999999999"


def test_a_transient_read_error_during_backup_stops_before_any_mutation(env, tmp_path):
    """备份阶段读 policy 限流 ⇒ 原样抛出且零 IAM 写入。

    v3 的 `_actual_policy` 裸吞一切异常返回 None，`_persist_backup` 把它
    落盘成"原本没有 policy"且永不覆盖——一次限流就把回滚材料**永久**记成
    null（Codex 复现过）。只有 NoSuchEntity 才是"不存在"。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role", lambda *a, **k: calls.append(a))
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")

    class _ThrottledIam(_FakeIam):
        def get_role_policy(self, RoleName, PolicyName):
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "rate exceeded"}},
                "GetRolePolicy")

    with pytest.raises(ClientError):
        bf.apply_plans(_ThrottledIam({"site-rt-a-abc123": {}}),
                       [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert calls == []
    assert not (tmp_path / "backup.json").exists()


def test_engine_and_tables_come_from_the_site_row():
    site = {"tier": "fullstack-nosql", "data_tables": ["notes", "tags"]}
    assert bf.plan_for("a-abc123", site) == ("dynamodb", ["notes", "tags"])
    assert bf.plan_for("b-abc123", {"tier": "fullstack-sql"}) == ("dsql", [])


def test_dynamodb_site_without_data_tables_is_skipped_not_guessed():
    """缺 data_tables 而 engine 是 dynamodb ⇒ 需人工，不猜表清单。"""
    with pytest.raises(bf.NeedsManualReview, match="data_tables"):
        bf.plan_for("a-abc123", {"tier": "fullstack-nosql"})


def test_unknown_tier_is_skipped_not_guessed():
    with pytest.raises(bf.NeedsManualReview, match="tier"):
        bf.plan_for("a-abc123", {"tier": "fullstack-graph"})
```

- [ ] **Step 2: 运行确认它红**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_backfill_site_role_policies.py -q)`
Expected: FAIL，`ModuleNotFoundError: No module named 'backfill_site_role_policies'`

- [ ] **Step 3: 写脚本**

Create `site-builder/scripts/backfill_site_role_policies.py`：

```python
#!/usr/bin/env python3
"""一次性 backfill：把存量 per-site 运行时角色的 policy 重写成精确 ARN。

**为什么不能等下次部署**：`table/site-data-{A}-*` 是**向前看的**通配，覆盖所有
以 A 的 id 为前缀的 site_id，包括本次上线之后才创建的。懒收敛等于把每个存量
站点留成对未来嵌套站点生效的陷阱（M01 的修复对它们等于没生效）。

**枚举 IAM 角色而不是遍历 sites 行**：下线清理失败留下的孤儿角色恰恰最该收。

重写走**同一个** `common.ensure_site_role`，不另开策略构造路径。

从仓库根跑，用系统 python3：
    python3 site-builder/scripts/backfill_site_role_policies.py           # dry-run
    python3 site-builder/scripts/backfill_site_role_policies.py --apply   # 真写
    python3 site-builder/scripts/backfill_site_role_policies.py --check   # 只跑闸门
"""
import argparse
import configparser
import json
import os
import pathlib
import sys
import urllib.parse

import boto3
from botocore.exceptions import ClientError

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))

ROLE_PREFIX = "site-rt-"
POLICY_NAME = "site-scope"
BACKUP_PATH = ROOT / "site-builder" / "scripts" / "backfill-old-policies.json"
# check_roles 用这两个前缀标记"闸门红但不能自动修"的角色；main 据此分流到
# 需人工清单而不是 todo（自动删未知 policy、自动重建消失的角色，都违反
# "判不出就不猜"）
EXTRA_POLICY_REASON = "site-scope 之外还有别的 policy（需人工移除，不自动删）"
MISSING_ROLE_REASON = "ACTIVE 站点的角色缺失（sites 行在、IAM 角色不在，需人工查根因）"


class NeedsManualReview(Exception):
    """这个角色的 engine / 表清单判不出来——跳过并计数，绝不猜。"""


def _load_env(config_path=None):
    """从 config.ini 下发环境变量，并**核对当前凭证就是目标账号**。

    **`config_path` 可注入是给单测用的**：真实 config.ini 是 gitignored 的，
    干净 clone / CI 里不存在——读它的测试会以"读不到 config"失败，与被测行为
    无关（Codex 指出）。生产调用不传参，仍以仓库根的 config.ini 为唯一取值
    来源（CLAUDE.md 口径不变）。

    **直接赋值，不用 setdefault**：config.ini 是部署脚本的唯一取值来源
    （CLAUDE.md），setdefault 会让 shell 里残留的旧值静默改写写入目标。
    `migrate_permissions._load_config` 与 `migrate_sites_to_blue_green._load_config`
    的 docstring 都明写了这条，本脚本必须一致。

    **STS 账号核对是硬要求**：若操作者的 AWS_PROFILE / 临时凭证指向另一个账号，
    那里没有 `site-rt-*` 角色 ⇒ 闸门看到"0 个不合格"⇒ dry-run / --apply / --check
    全部退 0，而**目标账号里的旧通配角色一个都没动**，发布记录却显示 M01 已闭环。
    仅 ACCOUNT_ID 残留错误时更隐蔽：policy 会被写成指向错误账号的精确 ARN，
    没有任何 `*`、闸门照样绿，而站点访问自己的表全部 AccessDenied。
    """
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(config_path or ROOT / "site-builder" / "config.ini"):
        raise SystemExit("读不到 site-builder/config.ini")
    acct = cfg["Platform"]["account_id"].strip()
    actual = boto3.client("sts").get_caller_identity()["Account"]
    if actual != acct:
        raise SystemExit(
            f"当前凭证属于账号 {actual}，而 config.ini 的目标账号是 {acct}——"
            "拒绝执行。切换 AWS_PROFILE / 凭证后重试。")
    os.environ["ACCOUNT_ID"] = acct
    os.environ["AWS_DEFAULT_REGION"] = cfg["Platform"]["region"].strip()
    os.environ["SITES_TABLE"] = cfg["Deployer"]["sites_table"].strip()
    os.environ["RUNTIME_BOUNDARY_ARN"] = (
        f"arn:aws:iam::{acct}:policy/site-runtime-boundary")
    return cfg


def _norm(doc: dict):
    """policy 文档 → 可比较形态。**完整递归等值，不丢任何字段**。

    **不能直接比 JSON 字符串**：IAM 会做自己的归一（单元素列表可能回来变成
    字符串，语句顺序不保证）。**也不能只比 (Effect, Action, Resource)**——
    v2 那样会丢掉 Condition / NotAction / NotResource：「精确 ARN + 额外限区
    Condition」的角色被判合格、不进 targets、不跑功能模拟，--check 绿而站点
    不可用（Codex 指出）。所以递归规范化整个文档：dict 保留全部键、标量与
    单元素列表同形、多元素列表按规范 JSON 串排序。
    """
    def _c(v):
        if isinstance(v, dict):
            return {k: _c(x) for k, x in v.items()}
        if isinstance(v, list):
            out = [_c(x) for x in v]
            if len(out) == 1:
                return out[0]
            return sorted(out, key=lambda x: json.dumps(
                x, sort_keys=True, ensure_ascii=False))
        return v
    return _c(doc)


def _actual_policy(iam, role_name: str):
    """角色的 site-scope inline policy。**只有 NoSuchEntity 返回 None**。

    v3 是裸 `except Exception: return None`——限流/断网/AccessDenied 都被
    解释成"原本没有 policy"，`_persist_backup` 把这个 None 落盘且"绝不覆盖
    已有快照"，于是一次限流就把回滚材料**永久**记成 null（Codex 复现过）。
    其他错误必须原样抛出：抛在备份阶段 ⇒ 零 IAM 写入（先备份后写保证的）；
    抛在 --check ⇒ 退非 0，本来就是 fail-closed。
    """
    try:
        raw = iam.get_role_policy(
            RoleName=role_name, PolicyName=POLICY_NAME)["PolicyDocument"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise
    return raw if isinstance(raw, dict) else json.loads(urllib.parse.unquote(raw))


def _extra_policies(iam, role_name: str) -> list:
    """site-scope 之外的一切 policy：多余的 inline + 全部 attached。

    只比 site-scope 那一条是不够的（Codex 指出的 P1）：boundary 对全部
    DynamoDB 数据动作放行整个 site-data-*，角色上任何一条残留 identity
    policy（比如调试期的 PutItem on site-data-*）与 boundary 取交集就是
    有效的跨租户写权限——而 site-scope 本身可以完全等于期望。
    """
    extra = []
    for page in iam.get_paginator("list_role_policies").paginate(
            RoleName=role_name):
        extra += [p for p in page["PolicyNames"] if p != POLICY_NAME]
    for page in iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name):
        extra += [p["PolicyArn"] for p in page["AttachedPolicies"]]
    return extra


def site_role_names(iam) -> list:
    names = []
    for page in iam.get_paginator("list_roles").paginate():
        names += [r["RoleName"] for r in page["Roles"]
                  if r["RoleName"].startswith(ROLE_PREFIX)]
    return sorted(names)


def check_roles(iam) -> list:
    """→ [(role_name, 原因)]。**S1 的硬发布闸门**：必须为空。判据四层：

    1. **实际 site-scope 与期望 policy 完整文档等值**，不是"没有 `*`"
       （错账号/错 region/漏表都不含通配，却同样不可用；Codex 复核指出）。
       期望值由 `common.site_policy` 现算——与运行时同一份定义。
    2. **角色上只许有 site-scope 这一条 policy**：多余 inline / 任何
       attached 都不合格。site-scope 全对时残留的调试 policy 与 boundary
       取交集仍是有效跨租户权限（Codex 指出的 P1），只比 site-scope 对它失明。
    3. **反向存在性**：ACTIVE 非 static 站点的角色必须存在
       （缺失分流需人工，不自动重建——见下面反向段的注释）。
    4. 功能模拟在 `simulate_active_sites`（--check 专属，全动作）。
    """
    import common
    bad = []
    for name in site_role_names(iam):
        site_id = name[len(ROLE_PREFIX):]
        actual = _actual_policy(iam, name)
        if actual is None:
            bad.append((name, "没有 site-scope inline policy（不合格）"))
            continue
        site = common.get_site_consistent(site_id) or {}
        if not site:
            bad.append((name, "sites 表里没有对应行（孤儿角色，需人工确认后删除）"))
            continue
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            bad.append((name, f"算不出期望 policy：{exc}"))
            continue
        extra = _extra_policies(iam, name)
        if extra:
            bad.append((name, f"{EXTRA_POLICY_REASON}：{extra}"))
            continue
        expected = json.loads(common.site_policy(site_id, engine, tables=tables))
        if _norm(actual) != _norm(expected):
            bad.append((name, f"policy 与期望不一致（engine={engine} tables={tables}）"))
    # 反向：ACTIVE 非 static 站点的角色必须**存在**。只从现存 site-rt-* 出发
    # 是单向的——"角色整个缺失"（误删/清理脚本写错）完全不可见，IAM 里一个
    # 角色都没有时闸门反而全绿（Codex 指出）。
    # 缺失**不自动重建**（v5 曾写"进 targets 由 ensure_site_role 重建"，撤回）：
    # ① ACTIVE 站点的角色凭空消失本身是异常，自动重建会盖掉根因；
    # ② 自动建会让备份出现"角色原本不存在"这一态——GetRolePolicy 的
    #    NoSuchEntity 分不出它和"角色在、只缺 policy"，回滚就得会删整个角色
    #    （Codex 指出的 null 歧义）。分流需人工后，todo 里的角色只能来自
    #    list_roles 枚举 ⇒ 备份里 null 的语义唯一：角色在、site-scope 不在。
    have = set(site_role_names(iam))
    for site_id in active_fullstack_site_ids():
        name = ROLE_PREFIX + site_id
        if name not in have:
            bad.append((name, MISSING_ROLE_REASON))
    return bad


def active_fullstack_site_ids() -> list:
    """ACTIVE 且需要运行时角色（engine != none）的 site_id。扫 sites 表，只读。

    未知 tier 不猜、也不跳过——按"需要角色"对待：角色若在，per-role 检查会以
    NeedsManualReview 报它；角色若缺，反向检查报缺失。两边都 fail-closed。
    """
    import common
    out = []
    for row in common._paginate(common._table("SITES_TABLE").scan):
        if row.get("status") != "ACTIVE":
            continue
        try:
            if common.tier_engine(row.get("tier", "")) == "none":
                continue                      # static 站点没有运行时角色
        except ValueError:
            pass
        out.append(row["site_id"])
    return sorted(out)


def verify_access(iam, site_id: str, tables: list) -> list:
    """用 IAM 策略模拟器做功能验收 → [问题…]。只读。

    比"policy 文本对不对"更直接：断言该站点的角色对**每个数据动作**都能
    访问自己的每张表、且对邻居表**每个动作都被拒**。模拟器会算 permissions
    boundary 与角色上的**全部** identity policy——所以它连 check_roles 的
    结构检查漏掉的形态都能兜住。

    **动作清单从期望 policy 现取，不手抄第二份**（Codex 指出的 P1：只模拟
    GetItem 时，一条残留的"PutItem on site-data-*"调试 policy 在读模拟下
    照样"拒绝"，闸门绿而跨租户**写**仍然可行——M01 的修复等于只验了读）。
    """
    import common
    problems = []
    arn = common.site_role_arn(site_id)
    region = os.environ["AWS_DEFAULT_REGION"]
    acct = os.environ["ACCOUNT_ID"]
    expected = json.loads(common.site_policy(site_id, "dynamodb", tables=tables))
    actions = sorted({a for stmt in expected["Statement"]
                      for a in (stmt["Action"] if isinstance(stmt["Action"], list)
                                else [stmt["Action"]])
                      if a.startswith("dynamodb:")})
    assert actions, "期望 policy 里没有任何 dynamodb 动作——动作清单推导坏了"

    def _decisions(table_name):
        res = f"arn:aws:dynamodb:{region}:{acct}:table/{table_name}"
        out = iam.simulate_principal_policy(
            PolicySourceArn=arn, ActionNames=actions, ResourceArns=[res])
        return {r["EvalActionName"]:
                r["ResourceSpecificResults"][0]["EvalResourceDecision"]
                for r in out["EvaluationResults"]}

    for logical in tables:
        got = _decisions(common.site_table_name(site_id, logical))
        denied = sorted(a for a, d in got.items() if d != "allowed")
        if denied:
            problems.append(
                f"访问自己的表 {logical} 被拒（{denied}）——backfill 写坏了")
    # 构造一个"以本 site_id 为前缀"的邻居：**任何一个动作** allowed 都算
    # 失败（这正是 M01 的形态，读写都算）
    neighbour = common.site_table_name(f"{site_id}-probe-abc123", "notes")
    got = _decisions(neighbour)
    leaked = sorted(a for a, d in got.items() if d == "allowed")
    if leaked:
        problems.append(
            f"仍能访问嵌套邻居的表 {neighbour}（{leaked}）——残留权限没收干净")
    return problems


def plan_for(site_id: str, site: dict) -> tuple:
    """→ (engine, tables)。判不出即抛 NeedsManualReview。"""
    import common
    tier = site.get("tier")
    if not tier:
        raise NeedsManualReview(f"{site_id}: sites 行没有 tier，判不出 engine")
    try:
        engine = common.tier_engine(tier)
    except ValueError as exc:
        raise NeedsManualReview(f"{site_id}: {exc}") from exc
    if engine != "dynamodb":
        return engine, []
    tables = list(site.get("data_tables") or [])
    if not tables:
        raise NeedsManualReview(
            f"{site_id}: engine 是 dynamodb 但 sites 行没有 data_tables，"
            "判不出表清单。请人工确认该站点的表后手工重写它的 policy")
    return engine, tables


def _persist_backup(iam, role_names) -> None:
    """把全部 target 的旧 policy **原子落盘**（spec §7.3 的"覆盖前留档"）。

    v2 在这里犯过错（Codex 指出）：备份攒在内存字典、循环结束才写文件——
    第 2 个角色写入抛异常（IAM 限流最常见）时，第 1 个已被改而备份文件
    不存在，承诺的回滚材料落空。所以四条纪律：
    - **先备份后写**：本函数必须在任何 put_role_policy 之前完成；
    - **临时文件 + os.replace**：崩溃不会留下半个 JSON；
    - **合并、绝不覆盖已有快照**：重跑时已收敛的角色不再是 target，
      无条件覆盖会丢掉它们的原始通配 policy——回滚要的恰是第一份快照。
      roles 值为 null = 备份时该角色没有 site-scope inline policy
      （`_actual_policy` 只把 NoSuchEntity 判为不存在，其他读错误直接
      抛出 ⇒ 此时零 IAM 写入；且缺失角色分流需人工、不进 todo ⇒
      本函数只会收到 list_roles 枚举出的**真实存在**的角色，null 不会
      再混入"角色本身不存在"这一态，回滚动作唯一：`delete_role_policy`
      删掉新写的 site-scope）；
    - **带账号元数据，合并前核对**：格式 {schema_version, account_id,
      region, roles}。没有元数据时，切到另一个账号后"绝不覆盖"会把
      A 账号同名 role 的旧快照保留成 B 账号的回滚材料（Codex 指出）——
      不一致就拒绝执行，提示把旧文件移走，绝不静默合并。
    """
    meta = {"schema_version": 1,
            "account_id": os.environ["ACCOUNT_ID"],
            "region": os.environ["AWS_DEFAULT_REGION"]}
    roles = {}
    if BACKUP_PATH.exists():
        saved = json.loads(BACKUP_PATH.read_text())
        for key, want in meta.items():
            if saved.get(key) != want:
                raise SystemExit(
                    f"已有备份 {BACKUP_PATH.name} 的 {key}={saved.get(key)!r} "
                    f"与当前 {want!r} 不一致——拒绝合并（它可能属于另一个账号的"
                    "同名角色）。把旧文件移走后重试。")
        roles = saved["roles"]
    for name in role_names:
        if name not in roles:
            roles[name] = _actual_policy(iam, name)
    tmp = BACKUP_PATH.parent / (BACKUP_PATH.name + ".tmp")
    tmp.write_text(json.dumps({**meta, "roles": roles},
                              ensure_ascii=False, indent=2))
    os.replace(tmp, BACKUP_PATH)
    print(f"旧 policy 已备份到 {BACKUP_PATH.name}（回滚用；**它不进 git**）")


def apply_plans(iam, todo) -> list:
    """真写。→ [失败原因…]。**备份未落盘前，一笔 IAM 修改都不会发生。**"""
    if not todo:
        return []
    import common
    _persist_backup(iam, [name for name, _sid, _e, _t in todo])
    failed = []
    for name, site_id, engine, tables in todo:
        common.ensure_site_role(site_id, engine, tables=tables)

        # **写后复核**：backfill 与在线部署之间存在"读完→写入"的竞态
        # （用户并发部署新增了一张表，我们会把它覆盖掉）。这里重读一次 sites 行，
        # 若期间变过就按新值重算重写一次，然后逐项比对落地结果。
        fresh = common.get_site_consistent(site_id) or {}
        try:
            engine2, tables2 = plan_for(site_id, fresh)
        except NeedsManualReview as exc:
            failed.append(f"{site_id}: 写入期间 sites 行变得判不出来：{exc}")
            continue
        if (engine2, tables2) != (engine, tables):
            print(f"  站点 {site_id} 在写入期间被改动过，按新值重写：{tables2}")
            common.ensure_site_role(site_id, engine2, tables=tables2)
            engine, tables = engine2, tables2
        expected = json.loads(common.site_policy(site_id, engine, tables=tables))
        if _norm(_actual_policy(iam, name) or {}) != _norm(expected):
            failed.append(f"{site_id}: 落地的 policy 与期望不一致")
            continue
        problems = verify_access(iam, site_id, tables) if engine == "dynamodb" else []
        if problems:
            failed.append(f"{site_id}: {problems}")
            continue
        print(f"  已重写并验证 {site_id}: engine={engine} tables={tables}")
    return failed


def simulate_active_sites(iam) -> list:
    """--check 的功能模拟段：对**全部** ACTIVE dynamodb 站点跑 verify_access。

    文本等值（check_roles）之外的第二层：模拟器会算 permissions boundary，
    反映真实判定而不是文本比较。v2 只对本次被重写的 targets 跑模拟——
    判成"合格"的角色一次功能验证都没有（Codex 指出）。只读，站点个位数。
    """
    import common
    problems = []
    for site_id in active_fullstack_site_ids():
        site = common.get_site_consistent(site_id) or {}
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            problems.append((ROLE_PREFIX + site_id, f"算不出期望 policy：{exc}"))
            continue
        if engine != "dynamodb":
            continue
        found = verify_access(iam, site_id, tables)
        if found:
            problems.append((ROLE_PREFIX + site_id, f"功能模拟失败：{found}"))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="真写（默认 dry-run）")
    parser.add_argument("--check", action="store_true", help="只跑闸门，不改任何东西")
    args = parser.parse_args()
    _load_env()
    import common
    iam = boto3.client("iam")

    if args.check:
        bad = check_roles(iam)
        # 文本已不一致时不叠加模拟结果（那些角色本来就要重写）；
        # 文本全绿才值得追问"真实判定也对吗"。
        if not bad:
            bad = simulate_active_sites(iam)
        print(f"不合格的 site-rt-* 角色：{len(bad)}")
        for name, reason in bad:
            print(f"  !! {name}: {reason}")
        return 1 if bad else 0

    targets = check_roles(iam)
    print(f"待收敛的角色：{len(targets)}")
    todo, manual = [], []
    for name, reason in targets:
        if reason.startswith((EXTRA_POLICY_REASON, MISSING_ROLE_REASON)):
            # 多余 policy：重写 site-scope 修不掉，自动删未知 policy 违反
            # "判不出就不猜"。角色缺失：先查为什么没了，不自动重建
            # （也保证 todo 里只有真实存在的角色，备份 null 语义唯一）。
            manual.append(f"{name}: {reason}")
            print(f"  跳过（需人工） {name}: {reason}")
            continue
        site_id = name[len(ROLE_PREFIX):]
        # **强一致读**：授权判定与 read-modify-write 都基于它
        site = common.get_site_consistent(site_id) or {}
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            manual.append(str(exc))
            print(f"  跳过（需人工） {site_id}: {exc}")
            continue
        if not args.apply:
            print(f"  计划 {site_id}: engine={engine} tables={tables}（当前：{reason}）")
            continue
        todo.append((name, site_id, engine, tables))

    failed = apply_plans(iam, todo) if args.apply else []

    if manual:
        print(f"\n需人工处理 {len(manual)} 个：")
        for line in manual:
            print(f"  - {line}")
    if failed:
        print(f"\n验证失败 {len(failed)} 个：")
        for line in failed:
            print(f"  - {line}")

    if args.apply:
        left = check_roles(iam)
        print(f"\n闸门：不合格的角色 {len(left)}")
        if left:
            for name, reason in left:
                print(f"  !! {name}: {reason}")
            print("  未收敛完，S1 不算交付完成")
            return 1
        print("  0 —— 已全部收敛并通过功能验收")
    return 1 if (manual or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: 运行单测**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_backfill_site_role_policies.py -q)`
Expected: PASS

> **一处覆盖边界说明白**：`verify_access` 没有单测——它靠 IAM 策略模拟器，
> 用 fake 去模拟模拟器只能测出"我怎么调它"，测不出"判定对不对"。
> 它在 Task 10 Step 3 的 `--apply` 与 Step 5 的 `--check`（对**全部** dynamodb
> 站点的功能模拟段）里被真机执行，那才是它有意义的地方。
> 这是有意的取舍，不是遗漏。

- [ ] **Step 5: dry-run 真机**

Run: `cd "$(git rev-parse --show-toplevel)" && python3 site-builder/scripts/backfill_site_role_policies.py`
Expected: 先通过 STS 账号核对（账号不符会直接 `SystemExit`），然后打印
`待收敛的角色：7` 与 7 行"计划"，且**没有**"需人工处理"。
**不要在这一步加 `--apply`**——真写属于 Task 10 的部署序列（必须在 deployer 栈部署之后）。

> 若这一步打印的待收敛数不是 7，先停下核对：实测基线是 7 个角色全部不合格
> （2 个 DynamoDB 通配 + 7 个日志组裸前缀）。数字变小可能意味着凭证指向了别的账号
> ——但 STS 核对应该已经先拦住那种情况。

- [ ] **Step 6: 扫描 + Commit**

先把备份文件加进 `.gitignore`（`--apply` 会把旧 policy 写到
`site-builder/scripts/backfill-old-policies.json` 供回滚，它含账号 ARN，**不能进 git**）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# 带 * 是为了连 os.replace 之前的 .json.tmp 一起忽略
printf 'site-builder/scripts/backfill-old-policies.json*\n' >> .gitignore

bash site-builder/scripts/scan_staged_secrets.sh \
     --files site-builder/scripts/backfill_site_role_policies.py \
             site-builder/deployer/tests/test_backfill_site_role_policies.py || exit 1
git add .gitignore \
        site-builder/scripts/backfill_site_role_policies.py \
        site-builder/deployer/tests/test_backfill_site_role_policies.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "feat(s1/m01): 存量角色 backfill + 「实际==期望」硬闸门 + STS 账号核对"
```

---

### Task 4: `effective_policy` 严格解析

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py`（新增异常与函数，放在 `normalize_allowed_users` 之后）
- Test: `site-builder/deployer/tests/test_permissions.py`

**Interfaces:**
- Produces: `permissions.PolicyDataInvalid`（异常）；`permissions.effective_policy(site: dict) -> dict`，返回 `{"require_login": bool, "allowed_users": "org" | list[str], "collaborators": list[str], "owner": str}`。Task 5 的三个投影 writer、Task 6 的错误映射都依赖这两个名字。

- [ ] **Step 1: 写四条会红的用例**

加到 `site-builder/deployer/tests/test_permissions.py`。
**注意该文件把模块 import 成 `perm`**（`import permissions as perm`，见其首行），
所以下面一律用 `perm.` 而不是 `permissions.`：

```python
def test_wrong_typed_require_login_is_rejected_not_laundered():
    """`Decimal(0)` 不得被 bool() 洗成 False。

    这是 M02 的核心：`bool(Decimal(0))` 是 False，于是它被写成字面
    `{"BOOL": false}`，而 Edge 的判定正是 "require_auth is False ⇒ 公开"
    ——坏数据被洗成"站主显式声明公开"，Edge 2026-08-06 加的 fail-closed
    哨兵被整个抵消。私有站点变成全公网可读。
    """
    from decimal import Decimal
    import pytest
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid, match="require_login"):
        perm.effective_policy(site)


def test_missing_collaborators_means_empty_list():
    """collaborators 是**唯一**允许缺失的字段：缺失有唯一安全解释（没有协作者）。"""
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": True, "allowed_users": "org"}
    assert perm.effective_policy(site)["collaborators"] == []


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_missing_ambiguous_field_is_rejected(field):
    """这三个字段缺失都没有唯一安全解释，所以一律拒绝、不猜方向。

    require_login 缺失：True 还是 False？allowed_users 缺失：org 还是空名单？
    改 "org" 是静默扩权，改 [] 是静默收紧——两者都在猜历史意图。
    """
    import pytest
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    del site[field]
    with pytest.raises(perm.PolicyDataInvalid, match=field):
        perm.effective_policy(site)


def test_rejection_message_names_the_site_and_the_repair():
    """文案必须点名 site_id 与坏字段并给出修法。

    否则这条"响亮失败"会变成一个查不出原因的 409，等于第二个 M03
    （那条的教训正是：只抛原始 SQLSTATE 而不给补救办法，
    "理论上可恢复"就不等于"实际上可恢复"）。
    """
    from decimal import Decimal
    import pytest
    site = {"site_id": "s-abc", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid) as excinfo:
        perm.effective_policy(site)
    msg = str(excinfo.value)
    assert "s-abc" in msg, "文案没点名 site_id"
    assert "require_login" in msg, "文案没点名坏字段"
    assert "BOOL" in msg, "文案没给出修法（正确类型）"
```

- [ ] **Step 2: 运行确认它们红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -k "require_login_is_rejected or missing_collaborators or missing_ambiguous or rejection_message" -q`
Expected: 全 FAIL，`AttributeError: module 'permissions' has no attribute 'PolicyDataInvalid'`

- [ ] **Step 3: 加异常与函数**

在 `permissions.py` 的 `PermissionConflict` 之后加异常：

```python
class PolicyDataInvalid(Exception):
    """sites 行的权限字段形态不合法，拒绝投影到路由表。

    **不猜方向**：把未知值当 "org" 是静默扩权，当空名单是静默收紧，
    两者都在猜历史意图。判不出就拒绝，让人去修那一行。
    调用方转 409（panel）或可读工具错误（MCP）。
    """
```

在 `normalize_allowed_users` 之后加函数：

```python
def effective_policy(site: dict) -> dict:
    """从 sites 行解出可投影的策略。**三个投影 writer 的唯一入口。**

    判据只有一条：**每个字段要么类型明确，要么它的「缺失」有唯一安全解释**；
    两者都不成立即抛 PolicyDataInvalid。

    | 字段          | 合法形态                    | 缺失时 |
    |---------------|-----------------------------|--------|
    | require_login | 真 bool                     | 抛错   |
    | allowed_users | "org" 或非空邮箱 list       | 抛错   |
    | collaborators | list[str]                   | []     |
    | owner         | 非空 str                    | 抛错   |

    为什么不能沿用 `bool(site.get("require_login", True))` 与
    `site.get("allowed_users", "org")`：读路径（Edge）对坏数据 fail-closed，
    而这两个默认值让**写路径**把坏数据洗成合法的 `{"BOOL": false}` / `"org"`
    ——两侧对坏数据的语义相反，Edge 的加固被写入侧抵消（M02）。
    """
    site_id = site.get("site_id", "<unknown>")
    repair = ('请把 sites 表该行修正为正确类型后重试（require_login: BOOL；'
              'allowed_users: S="org" 或 L=邮箱数组；owner: 非空 S）。')

    def reject(field, value):
        raise PolicyDataInvalid(
            f"站点 {site_id} 的 {field} 形态不合法"
            f"（{type(value).__name__}={value!r}），已拒绝投影权限。{repair}")

    require_login = site.get("require_login")
    if not isinstance(require_login, bool):
        reject("require_login", require_login)

    if "allowed_users" not in site:
        reject("allowed_users", None)
    try:
        allowed = normalize_allowed_users(site["allowed_users"])
    except ValueError as exc:
        raise PolicyDataInvalid(
            f"站点 {site_id} 的 allowed_users 形态不合法（{exc}），"
            f"已拒绝投影权限。{repair}") from exc

    collaborators = site.get("collaborators", [])
    if not isinstance(collaborators, list) or not all(
            isinstance(e, str) for e in collaborators):
        reject("collaborators", collaborators)

    owner = site.get("owner")
    if not isinstance(owner, str) or not owner:
        reject("owner", owner)

    return {"require_login": require_login, "allowed_users": allowed,
            "collaborators": list(collaborators), "owner": owner}


def effective_policy_audited(site: dict, *, actor: str) -> dict:
    """`effective_policy` + 拒绝时落一条审计。**三个投影 writer 都调这个。**

    审计做成**一处包装**而不是在三个 writer 各写一份 try/except：后者就是本轮
    要消除的形态（同一段处理抄多份）。纯解析留在 `effective_policy` 里，
    因为体检脚本也要调它，而那条路径没有 ops_log 表、也不该写任何东西。

    **不加告警**：这是"数据脏了"而不是"正在被攻击"，当前 0 例，
    拿告警叫醒人不成比例（要告警归 S4）。
    """
    try:
        return effective_policy(site)
    except PolicyDataInvalid:
        ops_log.record(actor=actor, action="reject_policy_projection",
                       target=f"site:{site.get('site_id', '')}", result="rejected")
        raise
```

- [ ] **Step 4: 运行确认它们绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
set -euo pipefail
git add site-builder/deployer/functions/permissions.py \
        site-builder/deployer/tests/test_permissions.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "feat(s1/m02): 新增 effective_policy 严格解析 + 带审计的包装——坏数据一律拒绝投影，不猜方向"
```

---

### Task 5: 三个投影 writer 切到 `effective_policy_audited` + AST 守卫

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py:507-511`（`write_permissions`）
- Modify: `site-builder/deployer/functions/permissions.py:760-772`（`resync_route`）
- Modify: `site-builder/deployer/functions/register_route.py:118-131`（`_route_item`）
- Modify: `site-builder/scripts/migrate_permissions.py:55-82`（`_parse_allowed`）
- Test: `site-builder/deployer/tests/test_permissions.py`、`site-builder/deployer/tests/test_seed_permissions.py`

**Interfaces:**
- Consumes: `permissions.effective_policy(site)` 与 `permissions.PolicyDataInvalid`（Task 4）

- [ ] **Step 1: 写两条会红的用例**

加到 `site-builder/deployer/tests/test_seed_permissions.py`：

```python
def test_deploy_path_refuses_to_launder_a_wrong_typed_row(monkeypatch):
    """部署路径（register_route）遇到错类型行必须拒绝，不能洗成公开。

    这是两轮审查都漏掉的**第四个** writer：`_seed_permissions` 用
    `if_not_exists(...)` **只补缺失字段、不碰错类型字段**，所以
    `require_login = Decimal(0)` 会穿过种子逻辑，在 `_route_item` 被 bool()
    洗成字面 `BOOL False` 写进路由——**每次部署都重洗一遍**。
    """
    from decimal import Decimal
    import pytest
    import permissions
    import register_route
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    event = {"site_id": "s-1", "job_id": "job-1", "api_target": ""}
    with pytest.raises(permissions.PolicyDataInvalid, match="require_login"):
        register_route._route_item(event, site, "o@example.test", "app-s-1")


def test_known_projection_writers_do_not_read_policy_fields_directly():
    """三个已知投影 writer 不许再自己从 site 行取权限字段。

    **这是一条针对已知名单的 tripwire，不会自动发现新 writer**
    ——它只匹配 `site.get("require_login"…)` 这一种形态，直接下标、别名、
    helper 都能绕过。自动发现那件事由下一条用例负责。
    （v1 的 docstring 声称"防的是将来的第五个 writer"，那是假话。）
    """
    import ast
    import pathlib
    root = pathlib.Path(__file__).parents[1]
    targets = {
        "functions/permissions.py": {"write_permissions", "resync_route"},
        "functions/register_route.py": {"_route_item"},
    }
    policy_fields = {"require_login", "allowed_users"}
    offenders = []
    for rel, fns in targets.items():
        tree = ast.parse((root / rel).read_text())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name in fns):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call)
                        and isinstance(sub.func, ast.Attribute)
                        and sub.func.attr == "get"
                        and sub.args
                        and isinstance(sub.args[0], ast.Constant)
                        and sub.args[0].value in policy_fields):
                    offenders.append(f"{rel}::{node.name}:{sub.lineno}")
    assert not offenders, (
        "这些 writer 仍在直接从 site 行取权限字段，应改走 "
        f"permissions.effective_policy: {offenders}")


def _docstring_ids(tree) -> set:
    """module/class/function 的 docstring Constant 节点 id 集合。

    docstring 也是 AST 字符串常量——不排除它，"文档里提到 require_auth"与
    "代码在投影 require_auth"就分不开。当前仓库有三处这种纯说明
    （api_key_config:101 / deploy_lambda_site:92 / mark_job:85 的 docstring），
    按"任意字符串常量"扫会把三个全报成 offender 且永远修不绿（Codex 指出）。
    """
    import ast
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef,
                             ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                out.add(id(body[0].value))
    return out


def _projects_require_auth(fn_node, doc_ids) -> bool:
    """写投影的**行为特征**，不是"出现过字面量"。

    投影只有两种真实形态（三个 writer 实测）：item dict 里的键
    `"require_auth": {...}`，或 UpdateExpression 里的赋值目标
    `SET require_auth = :a`。只出现字面量不算——`_finish` 从
    committed_route **读** `require_auth` 反推 effective_auth，是这两个文件里
    第四个含字面量的函数，但它不投影；按"出现即投影"判会让守卫在三个真
    writer 修完后**永远红**（这一处 Codex 也没抓到，与 docstring 假阳性同类：
    把"字面量出现"当成了"写行为"）。
    """
    import ast
    import re
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Dict):
            if any(isinstance(k, ast.Constant) and k.value == "require_auth"
                   for k in sub.keys):
                return True
        if (isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                and id(sub) not in doc_ids
                and re.search(r"require_auth\s*=", sub.value)):
            return True
    return False


def test_every_route_permission_writer_calls_effective_policy():
    """**自动发现版**：任何往路由投影 `require_auth` 的函数都必须调
    effective_policy_audited。

    判据不是函数名单，而是写行为特征（见 `_projects_require_auth`）
    ——**新增第 N 个 writer 会自动被这条抓到**，这才是 v1 声称、但当时并
    不存在的那道守卫。

    只扫这两个文件：mark_job（整条恢复上一版路由）与 undeploy（删路由）
    不投影权限字段，不该被这条约束。
    """
    import ast
    import pathlib
    root = pathlib.Path(__file__).parents[1]
    offenders = []
    for rel in ("functions/permissions.py", "functions/register_route.py"):
        tree = ast.parse((root / rel).read_text())
        doc_ids = _docstring_ids(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not _projects_require_auth(node, doc_ids):
                continue
            # **只接受带审计的那个入口。** 接受纯 effective_policy 会让
            # "某个 writer 绕过审计包装"照样通过守卫（Codex 复核指出）。
            calls_it = any(
                isinstance(c, ast.Call)
                and (getattr(c.func, "id", None) == "effective_policy_audited"
                     or getattr(c.func, "attr", None) == "effective_policy_audited")
                for c in ast.walk(node))
            if not calls_it:
                offenders.append(f"{rel}::{node.name}:{node.lineno}")
    assert not offenders, (
        "这些函数在投影 require_auth 但没走 effective_policy_audited："
        f"{offenders}。新增路由权限 writer 必须调它（带审计的那个）")


def test_no_other_module_projects_require_auth():
    """上一条只扫两个文件 —— 这一条保证不会有**第三个模块**偷偷开始投影。

    上一条的扫描边界是 permissions.py + register_route.py（路由权限投影的
    两个归属地）。若有人把新的投影 writer 放进第三个模块，上一条不会发现它
    （Codex 复核指出的边界问题）。所以这里断言 `functions/` 下**只有**这两个
    文件（外加 smoke_test 的白名单例外）出现**非 docstring** 的 `require_auth`
    字面量：谁在别处引入它，这条就红，逼他要么挪位置、要么把上一条的边界
    一起扩。

    **docstring 不算，但也不给那三个文件开整文件白名单**——整文件豁免会让
    第三模块的新 writer 藏进被豁免的文件里（Codex 明确反对那种修法）。
    这条故意比上一条**宽**（读取也报），错在"多咬"而不是"漏咬"：
    第三模块合法读取该字段的场景要显式进白名单并说明理由。

    smoke_test.py 是显式例外：它那里的 `require_auth` 是个**局部变量名**，
    用来决定冒烟该断言 302 还是 200，不是往路由写投影。
    """
    import pathlib
    allowed = {"permissions.py", "register_route.py", "smoke_test.py"}
    root = pathlib.Path(__file__).parents[1] / "functions"
    offenders = _require_auth_offenders(root, allowed)
    assert not offenders, (
        f"这些模块出现了 require_auth 字面量（docstring 除外）：{offenders}。"
        "若它们在投影路由权限，必须走 effective_policy_audited 并把上一条守卫的"
        "扫描边界一起扩；若只是读取，请加进本用例的白名单并说明理由")


def _require_auth_offenders(root, allowed=frozenset()) -> list:
    """root 下所有 .py 里非 docstring 的 `require_auth` 字面量 → [file:line…]。

    提成 helper 是为了让"守卫会咬"能用 tmp 目录里的探针文件**常驻**验证
    （下一条 meta-test）——不是往真实 tracked 文件注入再 `git checkout --`
    还原：那会把文件上未提交的修改一并丢掉，执行中断时探针还会残留在
    仓库里（Codex 指出）。
    """
    import ast
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name in allowed:
            continue
        tree = ast.parse(path.read_text())
        doc_ids = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in doc_ids
                    and "require_auth" in node.value):
                offenders.append(f"{path.name}:{node.lineno}")
    return offenders


def test_sentinel_scan_bites_a_probe_file(tmp_path):
    """哨兵的反向验证，**常驻**：守卫在当前代码上是绿的，而绿的守卫必须
    持续证明它能红——否则"加了守卫"与"守卫不生效"在 CI 上长得一模一样
    （Global Constraints 第 1 条对 pass-now 守卫的形态）。

    探针写进 tmp_path，同一份扫描逻辑（`_require_auth_offenders`），
    一条用例同时验两个方向：第 1 行 docstring 不误伤、第 2 行字面量必须咬住。
    """
    (tmp_path / "probe.py").write_text(
        '"""docstring 里提到 require_auth 不算数。"""\n'
        '_PROBE = {"require_auth": True}\n')
    assert _require_auth_offenders(tmp_path) == ["probe.py:2"]
```

加到 `site-builder/deployer/tests/test_permissions.py`（**spec §6.1 第 1 条**，
端到端走写路径，与上面那条走部署路径的互补）：

```python
def test_an_unrelated_permission_change_does_not_flip_a_wrong_typed_row_public(aws):
    """改协作者这种**无关**操作，不得把错类型的 require_login 洗成"公开"。

    `effective` 在每次权限写入时都从存量行**重算**，与本次改的是哪个字段无关
    ——所以"只加了个协作者"会顺带把 require_auth 重投影一遍。这是 M02 触发面
    比想象大的原因，也是这条端到端用例存在的理由（上一条只覆盖部署路径）。
    """
    import os
    import pytest
    import common
    common.upsert_site("s-1", owner="o@example.test", name="s",
                       status="ACTIVE", allowed_users="org",
                       collaborators=[], permissions_rev=1)
    # 直接把行改坏（模拟迁移脚本 / 人工修库 / 旧 writer 留下的形态）。
    # 低层 client 走 perm._ddb_client()——common 没有 _ddb()。
    perm._ddb_client().update_item(
        TableName=os.environ["SITES_TABLE"],
        Key={"site_id": {"S": "s-1"}},
        UpdateExpression="SET require_login = :bad",
        ExpressionAttributeValues={":bad": {"N": "0"}})
    with pytest.raises(perm.PolicyDataInvalid, match="require_login"):
        perm.set_collaborators("s-1", actor="o@example.test",
                               add=["c@example.test"])
```

> `aws` 是 deployer 测试里既有的 moto fixture（`test_permissions.py` 已在用）。
> `set_collaborators` 是 `permissions.py` 里既有的公开入口，内部走 `write_permissions`。

- [ ] **Step 2: 运行确认它们红**

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_seed_permissions.py tests/test_permissions.py -k "refuses_to_launder or do_not_read_policy_fields_directly or calls_effective_policy or unrelated_permission_change or no_other_module_projects" -q)`
Expected: 前四条 FAIL——两条行为用例因为当前不抛错而是洗成 False；两条 AST 用例因为三个 writer 都还在直接取值/都没调 `effective_policy_audited`（自动发现版的 offender 应恰好是 `write_permissions` / `resync_route` / `_route_item` 三个——`_finish` 不该在册，它是读取；已在当前代码上实测过这个判据）。
**第五条（第三模块边界哨兵）现在就应该 PASS**——它防的是将来，不是本次要修的缺陷。
v2 的哨兵在这里就红（三个既有 docstring 被当成 offender），且三个 writer 修完后**仍然红**——若见到这种形态，说明用的还是"任意字符串常量"旧判据。

> **每次改了测试名就回来核一遍 `-k`。** v1 在这里、Task 8 与 Task 9 都留下了
> 选不中新测试的过滤器（Task 9 那个还是改了测试名忘了改过滤器的陈旧串），
> 于是"确认会红"这一步实际上一条都没跑到——违反本 plan 自己的 Global Constraint。

- [ ] **Step 2b: 反向验证哨兵真的会咬（常驻 meta-test，不碰仓库文件）**

哨兵在当前代码上是绿的——绿的守卫必须证明它**能**红。验证方式是
`test_sentinel_scan_bites_a_probe_file`：往 **tmp_path** 写探针文件、调用
同一个扫描 helper。**v3 的做法（往 mark_job.py 追加再 `git checkout --`
还原）是错的**：该文件如有未提交修改会被一并丢弃，执行中断时探针还会
永久残留（Codex 指出）。meta-test 常驻后，"守卫会咬"每次全量回归都在验，
而不是一次性人工动作。

Run: `(cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -k sentinel_scan_bites -q)`
Expected: PASS（探针第 2 行被咬住、第 1 行 docstring 不误伤——两个方向一条用例全验）

- [ ] **Step 3: 改 `write_permissions`**

`permissions.py:507-511` 整块替换为（用**带审计**的那个入口）：

```python
    effective = effective_policy_audited(site, actor=actor)
```

- [ ] **Step 4: 改 `resync_route`**

把 `permissions.py:760-772` 的 `raw_allowed` / `allowed` / `effective` 三段替换为：

```python
    # 坏数据一律拒绝投影，不猜方向（M02）。**注意与旧注释的差别**：
    # 这里曾用 `normalize_allowed_users(raw) if raw else "org"` 并论证
    # 「让一个修复工具在最需要它的脏数据上抛异常，等于没有这个工具」。
    # 那个论证已被推翻——修复**投影漂移** ≠ 修复**源数据损坏**，
    # 后者必须由人判定意图，工具替他选方向（扩权或收紧）都是错的。
    effective = effective_policy_audited(site, actor=actor)
```

- [ ] **Step 5: 改 `register_route._route_item`**

`register_route.py:118-131`，在函数体开头取一次策略，然后用它：

```python
def _route_item(event, site: dict, owner: str, subdomain: str) -> dict:
    # 坏数据一律拒绝（M02 的部署路径 writer）。抛错发生在**提交点之前**
    # ⇒ 线上零影响，同 upload_frontend 空产物即拒的模式。
    pol = permissions.effective_policy_audited(site, actor=owner)
    return {"subdomain": {"S": subdomain},
            "site_id": {"S": event["site_id"]},
            "route_mode": {"S": "split"},
            # 格式的唯一定义在 common（尾斜杠是一条实测红线，见该函数 docstring）。
            # mark_job 的补偿要按**同一个**值做条件，两处各手写一份就没有任何东西
            # 保证它们同义。
            "static_prefix": {"S": common.static_prefix_for(event["site_id"],
                                                           event["job_id"])},
            "api_target": {"S": event.get("api_target", "")},
            "require_auth": {"BOOL": pol["require_login"]},
            "allowed_users": permissions.allowed_users_av(pol["allowed_users"]),
            "collaborators": {"L": [{"S": e} for e in pol["collaborators"]]},
            "owner": {"S": owner},
```

> `owner` 仍用传入的参数（不改成 `pol["owner"]`）：调用点 `:239` 传的是本次生效的 owner，与 site 行里的值可能在转移场景下不同。这是有意保留的现状。

- [ ] **Step 6: 改 `migrate_permissions._parse_allowed`**

> **它不调 `effective_policy`**（spec v2 更正了这一点）：它的输入是路由表的原始
> AttributeValue，不是一行 sites 记录，签名不匹配。它的收紧方式是把
> allowed_users 的规则**委托给同一个底层原语 `normalize_allowed_users`**
> ——规则仍只有一处定义，只是入口不同。

删掉「属性整体缺失 ⇒ `"org"`」那条回落与它的过时论证（它引用的 Edge 默认
`route.get("allowed_users", "org")` 已改成缺失即空名单），改为一并抛错：

```python
    if not raw:                          # 属性整体缺失
        raise UnparsableAllowlist(
            "allowed_users 属性整体缺失——**不回落 \"org\"**。"
            "旧注释说 Edge 的默认就是 org，那个推导已过时："
            "现行 Edge 是 `route.get(\"allowed_users\") if \"allowed_users\" in route "
            "else []`，缺失即空名单。此处回落 org 会是静默扩权。"
            "请人工判定原意后手工修该行。")
```

- [ ] **Step 7: 反转那条断言旧回落行为的用例**

`site-builder/deployer/tests/test_migrate_permissions.py:134` 有一条
`test_absent_allowed_users_attribute_falls_back_to_org`，它**明确断言"属性缺失 →
`"org"`"**，docstring 的理由是「与 Edge 的默认一致」。Step 6 改掉了这个行为，
所以这条用例必须反转（这是有意的行为变更，改用例是对的）：

```python
def test_absent_allowed_users_attribute_is_rejected_not_widened_to_org(aws):
    """属性整体缺失**不再**回落 "org"。

    旧版本回落 org，理由是"与 Edge 的默认一致"——**那个理由已过时**：
    现行 Edge 是 `route.get("allowed_users") if "allowed_users" in route else []`，
    缺失即空名单（fail-closed）。继续回落 org 就是静默扩权，
    而且是在一次"数据修复"动作里扩权。判不出原意就报错，让人来定。
    """
    import pytest
    with pytest.raises(migrate_permissions.UnparsableAllowlist, match="缺失"):
        migrate_permissions._parse_allowed({})
```

- [ ] **Step 8: 运行确认全绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests -q`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
set -euo pipefail
git add site-builder/deployer/functions/permissions.py \
        site-builder/deployer/functions/register_route.py \
        site-builder/scripts/migrate_permissions.py \
        site-builder/deployer/tests/test_permissions.py \
        site-builder/deployer/tests/test_seed_permissions.py \
        site-builder/deployer/tests/test_migrate_permissions.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m02): 三个投影 writer 统一走 effective_policy + 自动发现新 writer 的守卫"
```

---

### Task 6: `PolicyDataInvalid` 的对外映射与审计

**Files:**
- Modify: `site-builder/panel/handler.py:197-208`（异常分支）
- Modify: `site-builder/mcp/server.py`（`do_update_permissions` / `do_manage_collaborators` 的 except 链）
- Modify: `site-builder/deployer/functions/permissions.py`（拒绝时落 ops_log）
- Test: `site-builder/panel/tests/test_handler.py`

**Interfaces:**
- Consumes: `permissions.PolicyDataInvalid`（Task 4）

- [ ] **Step 1: 写会红的用例**

加到 `site-builder/panel/tests/test_handler.py`：

```python
def test_policy_data_invalid_maps_to_409_not_a_generic_500(monkeypatch):
    """坏数据必须给 409 + 可判读文案，不能被兜底吞成 500「服务内部错误」。

    不给专门分支的话，这条修复的"响亮失败"就变成一个查不出原因的 500
    ——运维会往平台故障方向查，而实际是某一行数据脏了。
    409 的选择理由：它确实是"资源当前状态阻止本次操作"，
    且 panel 里 409 已用于 PermissionConflict，语义相邻。
    """
    import permissions
    monkeypatch.setattr(
        api, "do_set_collaborators",
        lambda *a, **k: (_ for _ in ()).throw(
            permissions.PolicyDataInvalid("站点 s-1 的 require_login 形态不合法")))
    resp = handler.handler(_write_ev("/api/sites/s-1/collaborators",
                                     method="PUT",
                                     body={"add": ["x@example.test"]}), None)
    assert resp["statusCode"] == 409
    assert "require_login" in resp["body"]
```

> `_write_ev(path, **kw)`（`test_handler.py:54`）是本文件既有的辅助，
> 它在 `_ev`（:27）之上补齐 Edge 头 + CSRF 头 + 面板会话 cookie（`_cookie`，:49）。
> 参数按该文件既有用例的调用形态传。

- [ ] **Step 2: 运行确认它红**

Run: `cd site-builder/panel && ../deployer/.venv/bin/pytest tests/test_handler.py::test_policy_data_invalid_maps_to_409_not_a_generic_500 -q`
Expected: FAIL，实际 `statusCode` 是 500

- [ ] **Step 3: panel 加分支**

`site-builder/panel/handler.py`，在 `except permissions.PermissionConflict` 之后插入：

```python
    except permissions.PolicyDataInvalid as e:
        # 坏源数据阻止了投影。**必须有独立分支**：落到下面的兜底会变成
        # 500「服务内部错误」，而这既不是平台故障、也让运维查不到原因。
        # 文案原样透出——它已经点名 site_id、坏字段与修法（见 effective_policy）。
        return _json(409, {"error": str(e)})
```

- [ ] **Step 4: MCP 加映射**

`site-builder/mcp/server.py` 的 `do_update_permissions` 与 `do_manage_collaborators`，在 `except permissions.PermissionConflict` 之后各加：

```python
    except permissions.PolicyDataInvalid as e:
        # 与 panel 的 409 同义，转成 Agent 可读的文案（同 NotOwner 的处理形态）
        raise NotOwner(str(e)) from e
```

- [ ] **Step 5: 断言三个 writer 的拒绝都留下审计**

审计本身已在 Task 4 的 `effective_policy_audited` 里实现、Task 5 已让三个 writer
都走它（v1 只包了写路径，另两个的拒绝路径没有记录——Codex 指出）。这一步只补断言：

加到 `site-builder/deployer/tests/test_permissions.py`：

```python
def test_write_path_rejection_is_audited_and_writes_nothing(aws, monkeypatch):
    """走**真实 writer**（写路径）：拒绝时落一条审计，且零写副作用。

    v1 这条只调 `effective_policy_audited` 自己 ⇒ 是循环论证，
    "某个 writer 绕过包装"时照样绿（Codex 复核指出）。现在它通过
    `set_collaborators` 走完整写路径。
    """
    import os
    import common
    import ops_log
    import pytest
    common.upsert_site("s-1", owner="o@example.test", name="s", status="ACTIVE",
                       allowed_users="org", collaborators=[], permissions_rev=1)
    perm._ddb_client().update_item(
        TableName=os.environ["SITES_TABLE"], Key={"site_id": {"S": "s-1"}},
        UpdateExpression="SET require_login = :bad",
        ExpressionAttributeValues={":bad": {"N": "0"}})
    before = common.get_site_consistent("s-1")["permissions_rev"]

    actions = []
    monkeypatch.setattr(ops_log, "record", lambda **kw: actions.append(kw["action"]))
    with pytest.raises(perm.PolicyDataInvalid):
        perm.set_collaborators("s-1", actor="o@example.test",
                               add=["c@example.test"])
    assert actions == ["reject_policy_projection"], "拒绝没有留下审计"
    assert common.get_site_consistent("s-1")["permissions_rev"] == before, \
        "拒绝之后 rev 变了 —— 说明拒绝发生在写入之后，位置错了"


def test_deploy_path_rejection_is_audited(aws, monkeypatch):
    """走**真实 writer**（部署路径）：`_route_item` 的拒绝也要落审计。"""
    from decimal import Decimal
    import ops_log
    import pytest
    import register_route
    actions = []
    monkeypatch.setattr(ops_log, "record", lambda **kw: actions.append(kw["action"]))
    bad = {"site_id": "s-1", "owner": "o@example.test",
           "require_login": Decimal(0), "allowed_users": "org", "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid):
        register_route._route_item({"site_id": "s-1", "job_id": "job-1",
                                    "api_target": ""},
                                   bad, "o@example.test", "app-s-1")
    assert actions == ["reject_policy_projection"]
```

> **覆盖边界说清楚**：这两条端到端覆盖写路径与部署路径。第三个 writer
> `resync_route` 的"走了带审计的入口"由 Task 5 的 AST 守卫保证
> （它现在**只接受** `effective_policy_audited`，调纯函数会红），
> 不再为它单独搭一套 admin 夹具。这是有意的取舍，不是遗漏。

- [ ] **Step 6: 运行三个包**

Run:
```
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/panel    && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/mcp      && python3 -m pytest tests -q)
```
Expected: 三个都 PASS

- [ ] **Step 7: Commit**

```bash
set -euo pipefail
git add site-builder/panel/handler.py site-builder/mcp/server.py \
        site-builder/deployer/functions/permissions.py \
        site-builder/deployer/tests/test_permissions.py \
        site-builder/panel/tests/test_handler.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m02): PolicyDataInvalid → panel 409 / MCP 可读错误 + 三个 writer 的拒绝审计断言"
```

---

### Task 7: `session.py` 加 `typ` 与必填 `expected_typ`（含 panel 调用方，同一任务）

**Files:**
- Modify: `site-builder/auth/session.py`
- Modify: `site-builder/auth/login_handler.py:491`
- Modify: `site-builder/panel/console_session.py:131`
- Test: `site-builder/auth/tests/test_session.py`、`site-builder/auth/tests/test_upgrade_code.py`

**Interfaces:**
- Produces: `session.SESSION_TYP = "session"`；`session.mint_session_jwt(...)` 的 claims 含 `typ`；`session.verify_session_jwt(token, secret, now=None, *, expected_typ) -> dict | None`

> **这三个文件必须在同一个任务里改完。** panel 测试期是从 `auth/` 直接 import `session.py` 的（部署时才由 `deploy_panel.py` 复制），所以改了 `session.py` 不同步改 `console_session.py:131`，panel 单测会红。拆成两个任务会留一个必然失败的中间状态。

- [ ] **Step 1: 写三条会红的用例**

加到 `site-builder/auth/tests/test_upgrade_code.py`：

```python
def test_upgrade_code_is_not_accepted_as_a_session():
    """一次性升级码不得当普通会话用。

    两者用**同一个密钥**签名、线格式相同，而升级码的 claims 是
    {typ, email, jti, exp}——旧的 verify_session_jwt 只查签名与 exp，
    于是一个 60s 的升级码就是一个有效会话（M05）。
    """
    code = session.mint_upgrade_code("v@example.test", "secret")
    assert session.verify_session_jwt(
        code, "secret", expected_typ=session.SESSION_TYP) is None


def test_session_token_is_not_accepted_as_an_upgrade_code():
    """反方向也要挡住（这一半原本就已生效，加用例锁死）。"""
    token = session.mint_session_jwt("v@example.test", "V", "secret")
    assert session.verify_upgrade_code(token, "secret") is None


def test_verify_session_jwt_requires_expected_typ():
    """`expected_typ` 必须是必填参数。

    给默认值等于允许调用方忘记传，而"忘记传"恰好退化成本次修复之前的行为
    ——本仓库已记过这个形态（console_session.consume_code 的 expected_email 同理）。
    """
    import pytest
    token = session.mint_session_jwt("v@example.test", "V", "secret")
    with pytest.raises(TypeError):
        session.verify_session_jwt(token, "secret")
```

加到 `site-builder/auth/tests/test_login_handler.py`：

```python
def test_console_session_refuses_an_upgrade_code_as_the_cookie():
    """把升级码当 sb_session 递进 /console-session 不得换出新码。

    这是链式续期的修复点（M05）：`/console-session` 用的就是通用 verifier，
    不查 typ 时递一个升级码进去即可换出**新的** 60s 升级码，无限续期
    ——「60 秒 + 一次性」两个属性同时失效。已实测连续续期成功 3 轮。

    注意这一半**与 `require_idp_claim` 无关**：`auth` 子域注册为
    `require_auth=False`，Edge 根本不 gate 这个端点，是 auth 服务自己验 cookie。
    """
    code = session.mint_upgrade_code("v@example.test", "test-secret")
    resp = login_handler.handler(
        _event("/console-session", cookies=[f"sb_session={code}"]), None)
    assert resp["statusCode"] == 302
    assert "/login?redirect=" in resp["headers"]["Location"], (
        "应被当成无有效会话、引导去登录，而不是换出新的升级码")
```

> `_event(path, qs=None, cookies=None)`（`test_login_handler.py:10`）是本文件既有的
> 事件辅助；环境变量由 `site-builder/auth/tests/conftest.py` 提供
> （既有用例如 `test_console_session_issues_code_and_redirects_to_console` 也不自己设环境）。

- [ ] **Step 2: 运行确认它们红**

Run:
```
(cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_upgrade_code.py tests/test_login_handler.py -q)
```
Expected: 四条 FAIL（`TypeError: unexpected keyword argument 'expected_typ'` 与"换出了新码"）

- [ ] **Step 3: 改 `session.py`**

加常量、改 mint、改 verify：

```python
SESSION_TYP = "session"


def mint_session_jwt(email: str, name: str, secret: str, ttl_seconds: int = 86400,
                     idp: str = "", scope: str = "", auth_via: str = "") -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    # 载荷里的 `typ` 与 JOSE 头里的 `typ: JWT` 是两回事：前者是**用途**标记，
    # 用来断开会话 token 与 console 一次性升级码之间的跨上下文复用
    # （两者同密钥、同线格式，见 verify_session_jwt）。
    claims = {"typ": SESSION_TYP, "email": email, "name": name,
              "exp": int(time.time()) + ttl_seconds}
    if idp:
        claims["idp"] = idp        # spec §3.5：Edge 据此确认身份来自企业 IdP
    if scope:
        claims["scope"] = scope    # M3 面板会话用（Edge 不校验 scope）
    if auth_via:
        claims["auth_via"] = auth_via   # spec §3.5：本次 token 的来源
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_session_jwt(token: str, secret: str, now: int | None = None, *,
                       expected_typ: str) -> dict | None:
    """→ claims 或 None。`expected_typ` 是**必填关键字参数**。

    为什么必填而不给默认值 `SESSION_TYP`：给默认值等于允许调用方忘记传，
    而"忘记传"恰好退化成本次修复之前的行为（不查 typ）——那时一个 60s 的
    console 升级码就是一个有效会话，且能在 `/console-session` 无限续期（M05）。

    **改这里必须同步 `router/infrastructure/lambda/origin_request.py` 的
    `_verify_session_jwt`**：两处算法必须字节等价。
    """
    try:
        header_b64, payload_b64, sig = token.split(".")
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), secret)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        # typ 先查：这是"不能跨上下文复用"的唯一技术保证
        if claims.get("typ") != expected_typ:
            return None
        if int(claims.get("exp", 0)) <= (now if now is not None else int(time.time())):
            return None
        return claims
    except Exception:
        return None
```

- [ ] **Step 4: 改两个调用方**

`login_handler.py` 顶部 import 加 `SESSION_TYP`：

```python
from session import SESSION_TYP, mint_session_jwt, mint_upgrade_code, verify_session_jwt
```

`login_handler.py:491`：

```python
        claims = verify_session_jwt(session_token, _secret("JWT_SECRET"),
                                    expected_typ=SESSION_TYP)
```

`site-builder/panel/console_session.py:131`：

```python
    claims = session.verify_session_jwt(token, _secret(),
                                        expected_typ=session.SESSION_TYP)
```

- [ ] **Step 5: 迁移既有测试里的 8 处旧调用**

必填参数会让**所有**旧调用变成 `TypeError`。仓库里确切有 8 处（已逐一核过）：

`site-builder/auth/tests/test_session.py` 的 7 处 —— 第 `10`、`16`、`21`、`27`、
`31`、`32`、`65` 行，每处补 `expected_typ=SESSION_TYP`（文件顶部相应加进 import）。
它们的断言语义不变，例如：

```python
    claims = verify_session_jwt(tok, SECRET, expected_typ=SESSION_TYP)
    ...
    assert verify_session_jwt(tok, "other-secret", expected_typ=SESSION_TYP) is None
    ...
    assert verify_session_jwt(tok, SECRET, now=int(time.time()) + 11,
                              expected_typ=SESSION_TYP) is None
```

`site-builder/auth/tests/test_upgrade_code.py:98` 的 1 处**不是补参数，而是收紧**
——那条用例 `test_upgrade_code_is_not_accepted_as_a_console_session`
**把脆弱行为写成了预期**：注释明说「同密钥同算法，所以签名会过」，
只断言 `claims is None or claims.get("scope") != "console"`。
修复后它靠 `or` 侥幸仍绿，但它断言的不是现在成立的那个性质。改成：

```python
def test_upgrade_code_is_not_accepted_as_a_console_session():
    """反向也不行——否则 60 秒 code 能当 4 小时面板会话用。

    **M05 之后这条比原来强**：原来只能断言"它没有 scope=console"
    （因为同密钥同算法、签名确实会过，注释也这么写的）；
    现在 typ 检查先拒，所以可以直接断言 None。
    """
    code = session.mint_upgrade_code("u@x.com", SECRET)
    assert session.verify_session_jwt(
        code, SECRET, expected_typ=session.SESSION_TYP) is None
```

- [ ] **Step 6: 运行 auth 与 panel 两个包**

Run:
```bash
set -euo pipefail
(cd site-builder/auth  && ../contract/.venv/bin/pytest tests -q)
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
```
Expected: 两个都 PASS。**若 panel 侧还冒出 `TypeError`，说明那里也有漏改的调用
——照 Step 5 的方式补上，这正是必填参数在起作用**

- [ ] **Step 7: 扫描 + Commit**

```bash
set -euo pipefail
git add site-builder/auth/session.py site-builder/auth/login_handler.py \
        site-builder/panel/console_session.py \
        site-builder/auth/tests/test_session.py \
        site-builder/auth/tests/test_upgrade_code.py \
        site-builder/auth/tests/test_login_handler.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m05): 会话 token 加 typ + verify 必填 expected_typ——切断升级码当会话用与无限续期"
```

> `test_session.py` 必须在这个清单里。v1 漏了它（既没写要改、git add 也没有），
> 而它有 7 处旧调用 ⇒ 照 v1 执行 `pytest tests -q` 必然一片 `TypeError`。

---

### Task 8: Edge 内嵌 verifier 要求 `typ`

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py:452-470`
- Test: `router/infrastructure/lambda/test_edge_auth.py`

**Interfaces:**
- Consumes: Task 7 已让 auth 签发带 `typ: "session"` 的 token

> Edge 改动会**自动流入**测试：`test_edge_auth.py` 读 `origin_request.py` 现做占位符替换再 import，所以不需要手工同步 `_*_testable.py`（那些是生成物且 gitignored）。

- [ ] **Step 1: 写两条会红的用例**

加到 `router/infrastructure/lambda/test_edge_auth.py`：

```python
def test_edge_rejects_a_token_without_typ():
    """缺 typ 的旧会话被拒（走 302，不是 403）。

    302 而非 403 的理由与既有的 idp/auth_via 检查一致：引导用户去登录，
    而不是让他以为"没权限"去找站点 owner 加名单。
    这一条也是"全员重登一次"的技术表现。
    """
    import base64
    import hashlib
    import hmac
    import json
    import time
    claims = {"email": "v@example.test", "name": "V",
              "exp": int(time.time()) + 600}          # 故意不带 typ
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64(hmac.new(b"test-secret", f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    assert orq._verify_session_jwt(f"{header}.{payload}.{sig}") is None


def test_edge_rejects_a_console_upgrade_code_as_a_site_session():
    """console 升级码不得当站点会话用（M05 在 Edge 侧的那一半）。"""
    import sys
    sys.path.insert(0, "../../../site-builder/auth")
    from session import mint_upgrade_code
    code = mint_upgrade_code("v@example.test", "test-secret")
    assert orq._verify_session_jwt(code) is None


def test_check_auth_redirects_a_typeless_token_to_login():
    """缺 typ 走到 `_check_auth` 是 **302 到登录端点**，不是 403。

    口径与既有的 idp / auth_via 检查一致：引导用户去登录，
    而不是让他以为"没权限"去找站点 owner 加名单。
    """
    token = _jwt(email="v@example.test")          # Step 4 之前它不带 typ
    request = _req(cookie=f"sb_session={token}")
    denied = orq._check_auth(request, ROUTE_AUTH, "app-x.example.test")
    assert denied is not None and denied["status"] == "302"
    assert "/login?redirect=" in denied["headers"]["location"][0]["value"]


def test_a_real_auth_token_verifies_at_the_edge():
    """**跨组件正向向量**：auth 真签出来的 token 必须能过 Edge 的 verifier。

    这是唯一能发现 `auth/session.py` 的 `SESSION_TYP` 与 Edge 里硬编码的
    `"session"` 漂移的东西——两处按设计必须字节等价，但 Edge 拿不到那个常量
    （Lambda@Edge 不能 import auth 包）。只有负向用例的话，把 auth 改成
    `typ="sess"` 而 Edge 仍查 `"session"`，全部负向用例照样绿，
    而线上所有会话失效。
    """
    import sys
    sys.path.insert(0, "../../../site-builder/auth")
    from session import mint_session_jwt
    token = mint_session_jwt("v@example.test", "V", "test-secret",
                             idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    claims = orq._verify_session_jwt(token)
    assert claims is not None, "auth 签的 token 在 Edge 侧被拒——两处 typ 漂移了"
    assert claims["email"] == "v@example.test"
```

> `test-secret` 是测试期占位符替换给 `{{JWT_SECRET}}` 的值（见本文件顶部的 `_SUBS`），
> 所以两侧用同一个密钥，签名会过。

- [ ] **Step 2: 运行确认它们红**

Run: `(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_auth.py -k "without_typ or upgrade_code_as_a_site_session or typeless_token or real_auth_token" -q)`
Expected: 前三条 FAIL（当前 verifier 不查 typ，两个不该过的 token 都被接受、302 那条也不成立）。**第四条（跨组件正向）现在就应该 PASS**——它是防漂移的哨兵，不是本次要修的缺陷

> v1 的过滤器只写了 `without_typ or upgrade_code_as_a_site_session`，
> 选不中 `typeless_token` 那条（Codex 指出）。改了测试名就回来核 `-k`。

- [ ] **Step 3: 改 Edge verifier**

`origin_request.py` 的 `_verify_session_jwt`，在 exp 检查之前插入 typ 检查并更新 docstring：

```python
def _verify_session_jwt(token: str) -> dict | None:
    """与 site-builder/auth/session.py 同算法（HS256），改动须两处同步。

    **必须查 `typ`**（M05）：会话 token 与 console 一次性升级码用**同一个密钥**
    签名、线格式也相同。不查 typ 时一个 60s 的升级码就是一个有效站点会话，
    而它还能在 auth 的 `/console-session` 无限续期。
    """
    import base64, hashlib, hmac as _hmac, time as _t
    try:
        h, p, sig = token.split(".")
        expected = base64.urlsafe_b64encode(
            _hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(p))
        # typ 先查：这是"不能跨上下文复用"的唯一技术保证。字面量与
        # auth/session.py 的 SESSION_TYP 必须一致（Edge 拿不到那个常量）。
        if claims.get("typ") != "session":
            return None
        if int(claims.get("exp", 0)) <= int(_t.time()):
            return None
        email = claims.get("email")
        if not isinstance(email, str) or not email:
            return None  # 缺 email 的 token 视为无效，_check_auth 依赖 claims["email"]
        return claims
    except Exception:
        return None
```

- [ ] **Step 4: 两个造 token 的测试辅助各加一行 `typ`**

改完 verifier，**既有的 edge 鉴权用例会大面积变红**——因为它们自造的 token 都不带
`typ`。修法是在两个辅助里各加一个键（两者是**各自独立的实现**，不是一个复用另一个）：

`router/infrastructure/lambda/test_edge_auth.py:22`（`_jwt`）：

```python
    payload = {"typ": "session", "name": name, "exp": int(time.time()) + exp_delta}
```

同文件 `:260`（`_jwt_idp`）：

```python
    payload = {"typ": "session", "email": email, "name": "Alice",
               "exp": int(time.time()) + exp_delta}
```

> 上面 Step 1 的 `test_edge_rejects_a_token_without_typ` 与
> `test_check_auth_redirects_a_typeless_token_to_login` **不能**用 `_jwt`
> ——它们要的正是"不带 typ"。前者已自己手搓 token；后者在 Step 4 之后要改成
> 手搓（把 `_jwt(...)` 换成该文件里那段手搓 b64/hmac 的三行），否则它会因为
> 辅助带上 typ 而失去意义。

- [ ] **Step 5: 运行 router 全包**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
set -euo pipefail
git add router/infrastructure/lambda/origin_request.py \
        router/infrastructure/lambda/test_edge_auth.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m05): Edge verifier 要求 typ=session + 跨组件正向向量——与 auth/session.py 同步"
```

---

### Task 9: Edge 取全部同名 cookie 并逐个验签

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py:473-479`（`_get_cookie` → `_get_cookies`）
- Modify: `router/infrastructure/lambda/origin_request.py:597-601`（`_check_auth` 的取 token 段）
- Test: `router/infrastructure/lambda/test_edge_auth.py`

**Interfaces:**
- Produces: `origin_request._get_cookies(request, name) -> list`；`origin_request.MAX_SESSION_COOKIE_CANDIDATES = 8`

- [ ] **Step 1: 写三条会红的用例**

加到 `router/infrastructure/lambda/test_edge_auth.py`：

```python
def test_a_garbage_cookie_in_front_does_not_lock_the_user_out():
    """两条同名 sb_session、第一条是垃圾 ⇒ 仍放行。

    M06：`sb_session` 是顶域 cookie（`Domain=.{base}`），而 HttpOnly 只阻止
    `document.cookie` 覆盖**同 (name, domain, path)** 的那一条。站点页面 JS 写
    `sb_session=garbage; domain=.{base}; path=/api` 是**新建第二条**，浏览器不拦；
    RFC 6265 §5.4.2 规定路径更长的先发 ⇒ 垃圾值先被取到 ⇒ 全平台 /api/* 持久 302，
    且重新登录（写 path=/）不会清掉遮蔽项。已本地复现。
    """
    good = _jwt(email="v@example.test")
    request = _req(cookie=f"sb_session=garbage; sb_session={good}")
    assert orq._get_cookies(request, "sb_session") == ["garbage", good]
    # 放行 = _check_auth 返回 None，并注入了真身份
    assert orq._check_auth(request, ROUTE_AUTH, "app-x.example.test") is None
    assert request["headers"]["x-user-email"][0]["value"] == "v@example.test"


def test_only_the_first_candidates_are_tried():
    """上限是**行为**约束而不是一个常量断言——第 9 条之后不再尝试。

    防的是"注入 N 条 cookie 压 HMAC"这种放大。把好 token 放在第 9 位，
    断言它**不**被放行；这样上限被调大或调没了，这条都会红。
    """
    good = _jwt(email="v@example.test")
    garbage = "; ".join(f"sb_session=x{i}" for i in range(8))
    request = _req(cookie=f"{garbage}; sb_session={good}")
    assert len(orq._get_cookies(request, "sb_session")) == 9
    assert orq._check_auth(request, ROUTE_AUTH, "app-x.example.test") is not None, \
        "第 9 条候选不应被尝试（上限失效了）"


def test_reserved_cookies_are_still_stripped_in_full():
    """回归：改 _get_cookies 时不要顺手动坏"剥掉全部同名保留 cookie"。"""
    request = _req(cookie="sb_session=a; sb_session=b; site_own=keep")
    orq._strip_reserved_cookies(request)
    assert request["headers"]["cookie"][0]["value"] == "site_own=keep"
```

> 用的是 `test_edge_auth.py` 既有的两个辅助：`_jwt(email=…)`（:18，Task 8 之后它
> 签出的 token 带 `typ: "session"`）与 `_req(uri="/", cookie=None, …)`（:39），
> 以及模块级的 `ROUTE_AUTH`（:34，`require_auth=True` + `allowed_users="org"`）。

- [ ] **Step 2: 运行确认它们红**

Run: `(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_auth.py -k "garbage_cookie_in_front or only_the_first_candidates or still_stripped_in_full" -q)`
Expected: 前两条 FAIL（`_get_cookies` / `MAX_SESSION_COOKIE_CANDIDATES` 不存在）；第三条应已 PASS（是回归保护）

> v1 这里写的是 `candidate_count_is_capped`——**那是我改了测试名之后忘了改的
> 陈旧串，匹配不到任何用例**（Codex 指出），于是"上限"这条关键安全用例
> 在"确认会红"这一步压根没跑到。

- [ ] **Step 3: 换成复数版**

替换 `origin_request.py` 的 `_get_cookie`：

```python
# 同名 sb_session 的候选上限。正常 1 条、病态 2 条，8 留足余量又不给放大空间。
# 每次验签是一次 SHA256 HMAC（微秒级），且单条 Cookie 头受浏览器/CloudFront
# 约 8KB 限制、N 本就有界——显式上限便宜，且把意图写进代码。
MAX_SESSION_COOKIE_CANDIDATES = 8


def _get_cookies(request, name: str) -> list:
    """同名 cookie 的**全部**值，按 header 顺序。

    **为什么不能只取第一条**（M06，已本地复现）：`sb_session` 是顶域 cookie
    （`Domain=.{base}`），HttpOnly 只阻止 `document.cookie` 覆盖
    **同 (name, domain, path)** 的那一条。站点页面 JS 写
    `sb_session=garbage; domain=.{base}; path=/api` 是**新建第二条**，浏览器不拦；
    RFC 6265 §5.4.2 规定路径更长的先发 ⇒ 只取第一条就会取到垃圾值 ⇒
    全平台（含 console）的 /api/* 持久 302，且重新登录不会清掉遮蔽项。

    **这只关掉 DoS，不关身份混淆**：攻击者若持有另一个**合法** token，
    注入后它仍会先被取到并验签通过。根治是 host-only 会话（独立成包）。
    """
    out = []
    for header in request.get("headers", {}).get("cookie", []):
        for part in header["value"].split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                out.append(v)
    return out
```

- [ ] **Step 4: 改 `_check_auth` 的取 token 段**

`origin_request.py:597-601` 替换为：

```python
    # 逐个尝试同名候选，任一验签通过即放行（M06）。取上限防放大。
    claims = None
    for token in _get_cookies(request, "sb_session")[:MAX_SESSION_COOKIE_CANDIDATES]:
        claims = _verify_session_jwt(token)
        if claims:
            break
    if not claims:
        return _redirect_login(host, request.get("uri", "/"),
                               request.get("querystring", ""))
```

- [ ] **Step 5: 运行 router 全包**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
set -euo pipefail
git add router/infrastructure/lambda/origin_request.py \
        router/infrastructure/lambda/test_edge_auth.py
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "fix(s1/m06): Edge 取全部同名 sb_session 逐个验签 + 候选上限——关掉 cookie 遮蔽 DoS"
```

---

### Task 10: 全量回归、按序部署、真机验收

**Files:**
- Modify: `site-builder/DEPLOY.md`（补 S1 的部署顺序与两波重登说明）
- Test: 全部包 + 真机验收脚本

**Interfaces:**
- Consumes: Task 1–9 的全部产出

- [ ] **Step 1: 七个包全量回归**

每条各自套子 shell，否则第二条起工作目录已经不在仓库根：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/contract  && .venv/bin/pytest tests -q)
(cd site-builder/auth      && ../contract/.venv/bin/pytest tests -q)
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
(cd site-builder/deployer  && .venv/bin/pytest tests -q)
(cd site-builder/mcp       && python3 -m pytest tests -q)
(cd site-builder/panel     && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```
Expected: 全部 PASS，0 failed。基线是 1881 passed / 54 skipped / 1935 collected；新增用例会让 passed 上升

- [ ] **Step 2: 部署前重跑行形态体检**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/audit_policy_rows.py
```
Expected: 退出码 0。**若非 0 就停下**——先修那些行，否则 S1 上线会让对应站点既不能改权限也不能部署

- [ ] **Step 3: 按序部署（顺序不可变）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# ① deployer 栈（M01 + M02）
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)

# ② permissions.py 被复制进三个产物，都要重部
(cd site-builder/panel     && python3 deploy_panel.py)
(cd site-builder/key-proxy && python3 deploy_key_proxy.py)
(cd site-builder/mcp       && python3 deploy_agentcore.py)

# ③ 存量角色 backfill —— 必须在 ① 之后（它调的是新版 ensure_site_role/site_policy）
python3 site-builder/scripts/backfill_site_role_policies.py            # 先看计划
python3 site-builder/scripts/backfill_site_role_policies.py --apply    # 真写 + 自带闸门

# ④ auth（M05 上半）—— 第一波重登：控制台用户此刻起被要求重新登录
(cd site-builder/auth && python3 deploy_auth.py)

# ⑤ router（M05 下半 + M06）
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
```

- [ ] **Step 4: 等 CloudFront 传播完成（在 ⑤ 之后，不是之前）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
"""等分发状态回到 Deployed。第二波重登在这期间发生。

**位置很重要**：v1 把"等 Edge 全球复制"放在 router 部署**之前**，
那时压根还没有新的 Edge 版本要传播，纯属无意义等待（Codex 指出）。
真正触发传播的是 router 部署本身。
判据用 Status 而不是盲等 10–20 分钟；也不用 aws CLI（它的退出码不可靠）。
"""
import configparser, time
import boto3
cfg = configparser.ConfigParser(interpolation=None)
cfg.read("site-builder/config.ini")
base = cfg["Platform"]["base_domain"].strip()
cf = boto3.client("cloudfront")
dist = None
for page in cf.get_paginator("list_distributions").paginate():
    for d in page["DistributionList"].get("Items", []):
        if any(a.endswith(base) for a in d.get("Aliases", {}).get("Items", [])):
            dist = d["Id"]
            break
    if dist:
        break
assert dist, f"找不到别名匹配 {base} 的 CloudFront 分发"
while True:
    status = cf.get_distribution(Id=dist)["Distribution"]["Status"]
    print(f"CloudFront {dist} status={status}")
    if status == "Deployed":
        break
    time.sleep(30)
PY
```
Expected: 最终打印 `status=Deployed`

- [ ] **Step 5: 硬闸门 + 真机验收**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# 硬闸门：不合格角色数 == 0（site-scope 完整等值 + 角色上唯一 policy +
# 反向存在 + 全动作功能模拟）。非 0 就不算 S1 交付完成。
# set -e 保证它失败时后面的验收一条都不会跑。
python3 site-builder/scripts/backfill_site_role_policies.py --check

python3 site-builder/scripts/verify_deployed_components.py   # ② 之后必跑：唯一能发现产物陈旧的闸门
python3 site-builder/scripts/verify_permission_matrix.py     # M02 之后唯一覆盖权限矩阵端到端的闸门
python3 site-builder/scripts/verify_console_e2e.py           # 跑之前先在浏览器登录一次（两波重登让 token 失效）
bash    site-builder/scripts/smoke_router.sh                 # 路由层冒烟（含 65s 等 Edge 缓存）
```
Expected: 闸门打印 `不合格的 site-rt-* 角色：0` 且退出码 0；其余全部通过。
`verify_console_e2e.py` 若报 token 过期，先 `node site-builder/clients/quick-desktop-proxy/auth.js` 重新登录

- [ ] **Step 6: 补 DEPLOY.md**

在 `site-builder/DEPLOY.md` 里加一节：

```markdown
### S1 加固（M01/M02/M05/M06）的部署顺序

**顺序不可变**：
1. deployer 栈
2. panel / key-proxy / MCP 重部（`permissions.py` 被复制进这三个产物）
3. `backfill_site_role_policies.py --apply`（**必须在 1 之后**——它调的是新版
   `ensure_site_role`）
4. auth
5. router
6. 等 CloudFront `Status == Deployed`
7. 真机验收（含硬闸门）

**等待放在 5 之后而不是之前**：真正触发 Lambda@Edge 传播的是 router 部署本身，
在它之前等待不会等到任何新版本。判据用分发的 `Status`（传播中 `InProgress`、
完成 `Deployed`），不要盲等固定分钟数。

**会有两波强制重新登录，这是预期行为不是故障**：
1. auth 部署完成那一刻——`/console-session` 开始拒绝不带 `typ` 的旧会话，
   控制台用户先被弹一次；
2. CloudFront 传播完成那一刻——站点访问的旧会话失效，第二波。

**回滚严格逆序：先 router，再 auth。** 反过来（先回滚 auth 使其重新签发不带 `typ`
的 token，而 Edge 仍要求 `typ`）会让所有新签发的会话被 302，用户陷入登录循环。

**两个部署前/后的硬闸门**：
- 部署前 `python3 site-builder/scripts/audit_policy_rows.py` —— sites 表里有没有会被
  严格解析拒绝的行。非 0 就先修那些行，否则上线后对应站点既不能改权限也不能部署。
- 部署后 `python3 site-builder/scripts/backfill_site_role_policies.py --check` ——
  **不合格的 per-site 角色数必须为 0**（判据四层：site-scope 与期望**完整
  等值**、角色上**只许有 site-scope 一条 policy**（多余 inline / attached
  都不合格，需人工移除）、ACTIVE 站点的角色反向存在（缺失需人工查根因，
  不自动重建）、且全部 dynamodb 站点通过 IAM 模拟器**全动作**功能验证
  ——只测 GetItem 验不出"邻居表可写"）。
  非 0 意味着 M01 对那些站点等于没生效，而带通配的仍是对未来嵌套 site_id
  生效的陷阱（通配是向前看的）。
  `--apply` 会先把全部旧 policy 备份到
  `site-builder/scripts/backfill-old-policies.json`（**第一笔 IAM 写入之前**
  原子落盘；带 account_id/region 元数据，不一致拒绝合并；重跑合并、不覆盖
  已有快照），回滚方式见 spec §7.3。
```

- [ ] **Step 7: 扫描 + Commit**

```bash
set -euo pipefail
git add site-builder/DEPLOY.md
bash site-builder/scripts/scan_staged_secrets.sh || exit 1
git commit -m "docs(s1): 部署顺序、两波重登、回滚逆序、两个硬闸门"
```

---

## 附：本计划覆盖 spec 的对照

| spec 章节 | 覆盖任务 |
|---|---|
| §4.1 M02 `effective_policy` 判据表 | T4 Step 3 |
| §4.1 三个投影 writer + 一个迁移入口 | T5 Step 3–6（迁移入口见 Step 6，它不调 effective_policy） |
| §4.1 `resync_route` docstring 论证重写 | T5 Step 4 |
| §4.2 `site_table_name` | T2 |
| §4.2 `site_policy` 精确 ARN / `tables` 接口约定 / 日志组 | T3 |
| §4.2 GSI 触发器 | T3 Step 1 的 `test_no_gsi_support_yet_so_index_arns_are_not_needed`。**v1 把这条记成"精确 ARN 断言顺带覆盖"是错的**——那三条压根不看索引 ARN |
| §4.2.1 存量角色 backfill | T3c |
| §4.2.1 `tier_engine` 唯一定义 | T3b |
| §7.2 「不合格角色数 == 0」硬闸门 | T3c（脚本自带）+ T10 Step 5（`--check`） |
| §7.1 CloudFront 传播等待（在 router 之后） | T10 Step 4 |
| §4.3 `expected_typ` 必填 + 两个调用方 | T7 |
| §4.3 Edge 侧 | T8 |
| §4.3 两波重登写进运维说明 | T10 Step 5 |
| §4.4 `_get_cookies` + 上限 + 残留说明 | T9 |
| §5.2 409 / MCP / ops_log | T6 |
| §6 全部 15 条用例 | T2–T9 的 Step 1 |
| §7.1 部署顺序 | T10 Step 3 |
| §7.2 真机验收 | T10 Step 4 |
| §7.3 回滚逆序 | T10 Step 5 |
| §8.1 上线前体检 | T1、T10 Step 2 |
