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
- **部署顺序不可变**：deployer 栈 → panel/key-proxy/MCP 重部 → auth → 等 Edge 全球复制（10–20 分钟）→ router。
- **回滚严格逆序：先 router，再 auth。** 反过来（先回滚 auth 使其重新签发不带 `typ` 的 token，而 Edge 仍要求 `typt`）会让所有新会话被 302，用户陷入登录循环。
- **不把真实账号 ID / 域名 / site_id / 邮箱写进任何被跟踪的文件。** 测试固定用 `111111111111`、`example.test`、`foo-k3d9x1` 这类占位值。
- `router/infrastructure/lambda/_*_testable.py` 是测试期由测试文件从 `origin_request.py` 现生成的副本（gitignored），**不要手工编辑它们**。

---

### Task 1: 行形态只读体检脚本

**Files:**
- Create: `site-builder/scripts/audit_policy_rows.py`
- Test: 无单测（真机只读脚本，靠 `--help` 与一次真跑验证）

**Interfaces:**
- Produces: 可重跑的只读体检，输出"严格解析会拒绝的 ACTIVE 行数"。Task 10 在部署前重跑它。

- [ ] **Step 1: 写脚本**

```python
#!/usr/bin/env python3
"""只读体检：sites 表里有没有会被 S1 的严格解析拒绝的行。

**从仓库根跑，用系统 python3**（不要借 deployer/.venv/bin/python3——那个解释器的
CA 信任库是空的，每次 HTTPS 都 CERTIFICATE_VERIFY_FAILED，症状像网络故障）。

    python3 site-builder/scripts/audit_policy_rows.py

只读：只做 Scan，不写任何东西。部署 S1 之前必须重跑一次——行形态可能已变。
"""
import configparser
import pathlib
import sys

import boto3

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _cfg():
    c = configparser.ConfigParser(interpolation=None)
    c.read(ROOT / "site-builder" / "config.ini")
    return c


def _shape(av):
    """DynamoDB AttributeValue 的类型字母；缺失返回哨兵。"""
    if av is None:
        return "<缺失>"
    return next(iter(av.keys()))


def audit(rows):
    """→ (ACTIVE 行数, [(site_id, [问题…])])。判据与 permissions.effective_policy 同义。"""
    active = [r for r in rows if r.get("status", {}).get("S") == "ACTIVE"]
    bad = []
    for r in active:
        probs = []
        if _shape(r.get("require_login")) != "BOOL":
            probs.append(f"require_login={_shape(r.get('require_login'))}")
        au = _shape(r.get("allowed_users"))
        if au not in ("L", "S"):
            probs.append(f"allowed_users={au}")
        elif au == "S" and r["allowed_users"]["S"] != "org":
            probs.append('allowed_users 是 S 但不是 "org"（一期 JSON 字符串遗留？）')
        if _shape(r.get("collaborators")) not in ("L", "<缺失>"):
            probs.append(f"collaborators={_shape(r.get('collaborators'))}")
        if _shape(r.get("owner")) != "S" or not r.get("owner", {}).get("S"):
            probs.append("owner 缺失或为空")
        if probs:
            bad.append((r["site_id"]["S"], probs))
    return len(active), bad


def main():
    cfg = _cfg()
    ddb = boto3.client("dynamodb", region_name=cfg["Platform"]["region"].strip())
    table = cfg["Deployer"]["sites_table"].strip()
    rows, kw = [], {"TableName": table}
    while True:
        resp = ddb.scan(**kw)
        rows += resp.get("Items", [])
        if "LastEvaluatedKey" not in resp:
            break
        kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    n_active, bad = audit(rows)
    print(f"sites 表共 {len(rows)} 行，其中 ACTIVE {n_active} 行")
    print(f"严格解析会拒绝的 ACTIVE 行：{len(bad)}")
    for site_id, probs in bad:
        print(f"  !! {site_id}: {probs}")
    if bad:
        print("\n上线 S1 会让上述站点既不能改权限也不能部署。先修这些行。")
        return 1
    print("  无 —— S1 上线不会卡住任何现有站点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: 真跑一次**

Run: `cd $(git rev-parse --show-toplevel) && python3 site-builder/scripts/audit_policy_rows.py`
Expected: 退出码 0，打印 `无 —— S1 上线不会卡住任何现有站点`（spec §8.1 已实测过一次为 0）

- [ ] **Step 3: Commit**

```bash
git add site-builder/scripts/audit_policy_rows.py
git commit -m "chore(s1): sites 行形态只读体检脚本——判断严格解析会不会拒绝现有行"
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
git add site-builder/deployer/functions/common.py \
        site-builder/deployer/functions/provision_dynamodb.py \
        site-builder/deployer/functions/undeploy.py \
        site-builder/deployer/tests/test_common.py
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
```

- [ ] **Step 2: 运行确认它们红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_common.py -k "nested_sites_tables or log_group_resources or without_tables" -q`
Expected: 三条全 FAIL——前两条因为当前是通配、第三条因为当前 `site_policy` 只收两个位置参数（`TypeError: unexpected keyword argument 'tables'`）

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
git add site-builder/deployer/functions/common.py \
        site-builder/deployer/functions/deploy_lambda_site.py \
        site-builder/deployer/functions/provision_dsql.py \
        site-builder/deployer/tests/test_common.py
git commit -m "fix(s1/m01): per-site IAM 改逐表精确 ARN + 日志组收窄——通配会匹配到嵌套 site_id 的其他站点"
```

---

### Task 4: `effective_policy` 严格解析

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py`（新增异常与函数，放在 `normalize_allowed_users` 之后）
- Test: `site-builder/deployer/tests/test_permissions.py`

**Interfaces:**
- Produces: `permissions.PolicyDataInvalid`（异常）；`permissions.effective_policy(site: dict) -> dict`，返回 `{"require_login": bool, "allowed_users": "org" | list[str], "collaborators": list[str], "owner": str}`。Task 5 的四个 writer、Task 6 的错误映射都依赖这两个名字。

- [ ] **Step 1: 写四条会红的用例**

加到 `site-builder/deployer/tests/test_permissions.py`：

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
    with pytest.raises(permissions.PolicyDataInvalid, match="require_login"):
        permissions.effective_policy(site)


def test_missing_collaborators_means_empty_list():
    """collaborators 是**唯一**允许缺失的字段：缺失有唯一安全解释（没有协作者）。"""
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": True, "allowed_users": "org"}
    assert permissions.effective_policy(site)["collaborators"] == []


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
    with pytest.raises(permissions.PolicyDataInvalid, match=field):
        permissions.effective_policy(site)


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
    with pytest.raises(permissions.PolicyDataInvalid) as excinfo:
        permissions.effective_policy(site)
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
    """从 sites 行解出可投影的策略。**四个 writer 的唯一入口。**

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
```

- [ ] **Step 4: 运行确认它们绿**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_permissions.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add site-builder/deployer/functions/permissions.py \
        site-builder/deployer/tests/test_permissions.py
git commit -m "feat(s1/m02): 新增 effective_policy 严格解析——坏数据一律拒绝投影，不猜方向"
```

---

### Task 5: 四个 writer 切到 `effective_policy` + AST 守卫

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


def test_all_policy_projection_writers_go_through_effective_policy():
    """四个 writer 都不许再自己从 site 行取权限字段。

    锁的是形态：`site.get("require_login"…)` / `site.get("allowed_users"…)`
    这类直接取值。**防的是"将来的第五个 writer"**——M02 本身就是因为同一段
    判定被手抄了四份才成立的（其中第四份还在部署路径上，两轮审查都没数到）。
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
    from decimal import Decimal
    import pytest
    import common
    common.upsert_site("s-1", owner="o@example.test", name="s",
                       status="ACTIVE", allowed_users="org",
                       collaborators=[], permissions_rev=1)
    # 直接把行改坏（模拟迁移脚本 / 人工修库 / 旧 writer 留下的形态）
    common._ddb().update_item(
        TableName=os.environ["SITES_TABLE"],
        Key={"site_id": {"S": "s-1"}},
        UpdateExpression="SET require_login = :bad",
        ExpressionAttributeValues={":bad": {"N": "0"}})
    with pytest.raises(permissions.PolicyDataInvalid, match="require_login"):
        permissions.set_collaborators("s-1", actor="o@example.test",
                                      add=["c@example.test"])
```

> `aws` 是 deployer 测试里既有的 moto fixture（`test_permissions.py` 已在用）。
> `set_collaborators` 是 `permissions.py` 里既有的公开入口，内部走 `write_permissions`。

- [ ] **Step 2: 运行确认它们红**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_seed_permissions.py tests/test_permissions.py -k "refuses_to_launder or go_through_effective_policy or unrelated_permission_change" -q`
Expected: 三条都 FAIL——前两条因为当前不抛错而是洗成 False；AST 那条 `offenders` 有 4 项

- [ ] **Step 3: 改 `write_permissions`**

`permissions.py:507-511` 整块替换为：

```python
    effective = effective_policy(site)
```

- [ ] **Step 4: 改 `resync_route`**

把 `permissions.py:760-772` 的 `raw_allowed` / `allowed` / `effective` 三段替换为：

```python
    # 坏数据一律拒绝投影，不猜方向（M02）。**注意与旧注释的差别**：
    # 这里曾用 `normalize_allowed_users(raw) if raw else "org"` 并论证
    # 「让一个修复工具在最需要它的脏数据上抛异常，等于没有这个工具」。
    # 那个论证已被推翻——修复**投影漂移** ≠ 修复**源数据损坏**，
    # 后者必须由人判定意图，工具替他选方向（扩权或收紧）都是错的。
    effective = effective_policy(site)
```

- [ ] **Step 5: 改 `register_route._route_item`**

`register_route.py:118-131`，在函数体开头取一次策略，然后用它：

```python
def _route_item(event, site: dict, owner: str, subdomain: str) -> dict:
    # 坏数据一律拒绝（M02 的第四个 writer）。抛错发生在**提交点之前**
    # ⇒ 线上零影响，同 upload_frontend 空产物即拒的模式。
    pol = permissions.effective_policy(site)
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

`migrate_permissions.py` 的 `_parse_allowed`：删掉「属性整体缺失 ⇒ `"org"`」那条回落与它的过时论证（它引用的 Edge 默认 `route.get("allowed_users", "org")` 已改成缺失即空名单），改为一并抛错：

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
git add site-builder/deployer/functions/permissions.py \
        site-builder/deployer/functions/register_route.py \
        site-builder/scripts/migrate_permissions.py \
        site-builder/deployer/tests/test_seed_permissions.py \
        site-builder/deployer/tests/test_migrate_permissions.py
git commit -m "fix(s1/m02): 四个 writer 统一走 effective_policy + AST 守卫防第五个"
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

- [ ] **Step 5: 拒绝时落审计**

`permissions.py` 的 `write_permissions`，把 `effective = effective_policy(site)` 改成带审计：

```python
    try:
        effective = effective_policy(site)
    except PolicyDataInvalid:
        # 坏数据是"存在即需要人修"的状态，要留可判读记录。**不加告警**：
        # 这是"数据脏了"而不是"正在被攻击"，拿告警叫醒人不成比例（归 S4 按需）。
        ops_log.record(actor=actor, action="reject_policy_projection",
                       target=f"site:{site_id}", result="rejected")
        raise
```

- [ ] **Step 6: 运行三个包**

Run:
```
cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q
cd site-builder/deployer && .venv/bin/pytest tests -q
cd site-builder/mcp && python3 -m pytest tests -q
```
Expected: 三个都 PASS

- [ ] **Step 7: Commit**

```bash
git add site-builder/panel/handler.py site-builder/mcp/server.py \
        site-builder/deployer/functions/permissions.py \
        site-builder/panel/tests/test_handler.py
git commit -m "fix(s1/m02): PolicyDataInvalid → panel 409 / MCP 可读错误 + ops_log 审计"
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
cd site-builder/auth && ../contract/.venv/bin/pytest tests/test_upgrade_code.py tests/test_login_handler.py -q
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

- [ ] **Step 5: 运行 auth 与 panel 两个包**

Run:
```
cd site-builder/auth && ../contract/.venv/bin/pytest tests -q
cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q
```
Expected: 两个都 PASS。panel 那侧若有用例直接调 `verify_session_jwt` 而没传 `expected_typ`，一并补上——它会以 `TypeError` 形式暴露，这是守卫在起作用

- [ ] **Step 6: Commit**

```bash
git add site-builder/auth/session.py site-builder/auth/login_handler.py \
        site-builder/panel/console_session.py \
        site-builder/auth/tests/test_upgrade_code.py \
        site-builder/auth/tests/test_login_handler.py
git commit -m "fix(s1/m05): 会话 token 加 typ + verify 必填 expected_typ——切断升级码当会话用与无限续期"
```

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
```

- [ ] **Step 2: 运行确认它们红**

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_auth.py -k "without_typ or upgrade_code_as_a_site_session" -q`
Expected: 两条 FAIL（当前 verifier 不查 typ，两个 token 都被接受）

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
git add router/infrastructure/lambda/origin_request.py \
        router/infrastructure/lambda/test_edge_auth.py
git commit -m "fix(s1/m05): Edge verifier 要求 typ=session——与 auth/session.py 同步"
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

Run: `cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest test_edge_auth.py -k "garbage_cookie_in_front or candidate_count_is_capped or still_stripped_in_full" -q`
Expected: 前两条 FAIL（`_get_cookies` / `MAX_SESSION_COOKIE_CANDIDATES` 不存在）；第三条应已 PASS（是回归保护）

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
git add router/infrastructure/lambda/origin_request.py \
        router/infrastructure/lambda/test_edge_auth.py
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

Run:
```bash
cd site-builder/contract  && .venv/bin/pytest tests -q
cd site-builder/auth      && ../contract/.venv/bin/pytest tests -q
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q
cd site-builder/deployer  && .venv/bin/pytest tests -q
cd site-builder/mcp       && python3 -m pytest tests -q
cd site-builder/panel     && ../deployer/.venv/bin/pytest tests -q
cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q
```
Expected: 全部 PASS，0 failed。基线是 1881 passed / 54 skipped / 1935 collected；新增用例会让 passed 上升

- [ ] **Step 2: 部署前重跑行形态体检**

Run: `cd $(git rev-parse --show-toplevel) && python3 site-builder/scripts/audit_policy_rows.py`
Expected: 退出码 0。**若非 0 就停下**——先修那些行，否则 S1 上线会让对应站点既不能改权限也不能部署

- [ ] **Step 3: 按序部署（顺序不可变）**

```bash
# ① deployer 栈（M01 + M02）
cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never

# ② permissions.py 被复制进三个产物，都要重部
cd site-builder/panel     && python3 deploy_panel.py
cd site-builder/key-proxy && python3 deploy_key_proxy.py
cd site-builder/mcp       && python3 deploy_agentcore.py

# ③ auth（M05 上半）—— 第一波重登：控制台用户此刻起被要求重新登录
cd site-builder/auth && python3 deploy_auth.py

# ④ 等 Edge 全球复制窗口（10–20 分钟），不要并行做 ⑤

# ⑤ router（M05 下半 + M06）—— 第二波重登：站点访问的老会话此刻失效
cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

- [ ] **Step 4: 真机验收**

```bash
python3 site-builder/scripts/verify_deployed_components.py   # ② 之后必跑：唯一能发现产物陈旧的闸门
python3 site-builder/scripts/verify_permission_matrix.py     # M02 之后唯一覆盖权限矩阵端到端的闸门
python3 site-builder/scripts/verify_console_e2e.py           # 跑之前先在浏览器登录一次（两波重登让 token 失效）
bash    site-builder/scripts/smoke_router.sh                 # 路由层冒烟（含 65s 等 Edge 缓存）
```
Expected: 全部通过。`verify_console_e2e.py` 若报 token 过期，先 `node site-builder/clients/quick-desktop-proxy/auth.js` 重新登录

- [ ] **Step 5: 补 DEPLOY.md**

在 `site-builder/DEPLOY.md` 里加一节：

```markdown
### S1 加固（M01/M02/M05/M06）的部署顺序

**顺序不可变**：deployer 栈 → panel/key-proxy/MCP 重部（`permissions.py` 被复制进
这三个产物）→ auth → 等 Edge 全球复制 10–20 分钟 → router。

**会有两波强制重新登录，这是预期行为不是故障**：
1. auth 部署完成那一刻——`/console-session` 开始拒绝不带 `typ` 的旧会话，
   控制台用户先被弹一次；
2. Edge 全球复制生效那一刻——站点访问的旧会话失效，第二波。

**回滚严格逆序：先 router，再 auth。** 反过来（先回滚 auth 使其重新签发不带 `typ`
的 token，而 Edge 仍要求 `typ`）会让所有新签发的会话被 302，用户陷入登录循环。

**部署前必跑** `python3 site-builder/scripts/audit_policy_rows.py`：它判断 sites 表里
有没有会被严格解析拒绝的行。非 0 退出就先修那些行——上线后对应站点会既不能改权限
也不能部署。
```

- [ ] **Step 6: Commit**

```bash
git add site-builder/DEPLOY.md
git commit -m "docs(s1): 部署顺序、两波重登、回滚逆序与部署前体检"
```

---

## 附：本计划覆盖 spec 的对照

| spec 章节 | 覆盖任务 |
|---|---|
| §4.1 M02 `effective_policy` 判据表 | T4 Step 3 |
| §4.1 四个 writer | T5 Step 3–6 |
| §4.1 `resync_route` docstring 论证重写 | T5 Step 4 |
| §4.2 `site_table_name` | T2 |
| §4.2 `site_policy` 精确 ARN / `tables` 接口约定 / 日志组 | T3 |
| §4.2 GSI 守卫（将来加 GSI 要变红） | T3 Step 1 的精确 ARN 断言（新增索引 ARN 不在集合里即红） |
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
