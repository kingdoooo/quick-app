"""首次部署 seed 与"预部署期在线改权限"的交互回归。

背景（Codex review P0，已用 moto 实证）：seed 曾用
attribute_not_exists(require_login) 当"整套权限是否已初始化"的 sentinel，
而在线接口只写调用方显式传入的字段——只改 allowed_users 的调用留下
require_login 缺失的稀疏行，sentinel 判定"未初始化"，seed 就用 manifest 的
值把 allowed_users 从指定名单盖回 "org"（静默扩权）。

所以 seed 必须逐字段 if_not_exists 补缺，不能把任一字段当整套的 sentinel。
"""


def test_seed_does_not_widen_allowlist_on_sparse_row(aws):
    """只设过 allowed_users 的稀疏行：首次部署不得把名单盖回 org。

    **稀疏行现在直接造，不再用 `set_access_policy` 造**（M02）：写路径改走
    `effective_policy` 严格解析后会**拒绝**缺字段的行，所以在线接口已经不可能
    再生产出这个形态。它的来源变成"存量遗留行"（M02 之前的在线写只持久化
    调用方显式传入的字段）。要守的性质没变——seed 遇到这种行只补缺失字段、
    绝不用 manifest 的值盖掉已设的名单，所以照原样造出该形态即可。
    """
    import common
    import register_route

    # 形态与 M02 之前 `set_access_policy(allowed_users=[...])` 留下的行一致：
    # 名单与 rev 都在，require_login 缺失
    common.upsert_site("s-p0", owner="o@x.com", name="n", status="DEPLOYING",
                       allowed_users=["only@example.com"], permissions_rev=1)
    site = common.get_site_consistent("s-p0")
    assert site.get("allowed_users") == ["only@example.com"]
    assert "require_login" not in site      # 稀疏行前提成立

    job_id = common.create_job("o@x.com", "s-p0")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p0", "api_target": "",
         "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}},
        None)

    after = common.get_site_consistent("s-p0")
    # 在线设的名单必须保留；缺失的 require_login 由 manifest 补上
    assert after.get("allowed_users") == ["only@example.com"]
    assert after.get("require_login") is True

    import boto3
    route = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-p0"}})["Item"]
    assert route["allowed_users"]["L"] == [{"S": "only@example.com"}]


def test_seed_fills_missing_allowed_users_when_require_login_present(aws):
    """反向稀疏：只改过 require_login 的行，allowed_users 必须被 manifest 补上。

    旧实现在这里是另一种失败：sentinel 存在 → 整个 seed 被跳过 →
    allowed_users 一直缺失 → _route_item 回落 "org"，同样是扩权，
    且真源与投影都停在"缺字段"状态。

    稀疏行直接造，理由同上一条用例（M02 起在线接口不再产出该形态）。
    """
    import common
    import register_route

    common.upsert_site("s-p1", owner="o@x.com", name="n", status="DEPLOYING",
                       require_login=True, permissions_rev=1)
    site = common.get_site_consistent("s-p1")
    assert site.get("require_login") is True
    assert "allowed_users" not in site     # 反向稀疏前提成立

    job_id = common.create_job("o@x.com", "s-p1")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p1", "api_target": "",
         "manifest": {"auth": {"require_login": True,
                               "allowed_users": ["from-manifest@x.com"]}}},
        None)

    after = common.get_site_consistent("s-p1")
    assert after.get("require_login") is True                  # 在线值保留
    assert after.get("allowed_users") == ["from-manifest@x.com"]  # 缺字段被补上

    import boto3
    route = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-p1"}})["Item"]
    assert route["allowed_users"]["L"] == [{"S": "from-manifest@x.com"}]


def test_seed_is_noop_when_both_fields_present(aws):
    """两个字段都在的完整行：seed 完全不改真源（也不推进 rev）。

    这里仍走在线接口 `set_access_policy` 造这一行——它同时给出两个字段，
    结果是**完整**行，正是 M02 之后写路径唯一还允许的形态。
    """
    import common
    import permissions
    import register_route

    common.upsert_site("s-p2", owner="o@x.com", name="n", status="DEPLOYING",
                       require_login=True, allowed_users="org")
    permissions.set_access_policy("s-p2", actor="o@x.com", require_login=False,
                                  allowed_users=["a@x.com"])
    before = common.get_site_consistent("s-p2")

    job_id = common.create_job("o@x.com", "s-p2")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p2", "api_target": "",
         "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}},
        None)

    after = common.get_site_consistent("s-p2")
    assert after.get("require_login") is False
    assert after.get("allowed_users") == ["a@x.com"]
    assert after.get("permissions_rev") == before.get("permissions_rev")


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

    **接收者必须叫 `site`**（三个 writer 里那行 sites 记录的变量名）。不能放宽成
    "任意 `.get("require_login")`"：`write_permissions` 里
    `overrides.get("require_login", require_login)` 读的是 mutate 回调返回的
    **本次要写的值**，不是存量行——把它算成 offender 会让这条守卫在三个 writer
    都修对之后**永远红**（与自动发现版不能按"字面量出现过"判是同一个错误形状：
    判据比要抓的行为宽）。已实测：收窄后在修复前仍报 6 个真 offender
    （每个 writer 两个），只少掉那两个假阳性。
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
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id == "site"
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
    按"任意字符串常量"扫会把三个全报成 offender 且永远修不绿。
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
    writer 修完后**永远红**（与 docstring 假阳性同类：把"字面量出现"当成了
    "写行为"）。
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
    ——**新增第 N 个 writer 会自动被这条抓到**。

    只扫这两个文件：mark_job（整条恢复上一版路由）与 undeploy（删路由）
    不投影权限字段，不该被这条约束。第三个模块偷偷开始投影由下一条负责。
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
            # "某个 writer 绕过审计包装"照样通过守卫。
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
    两个归属地）。若有人把新的投影 writer 放进第三个模块，上一条不会发现它。
    所以这里断言 `functions/` 下**只有**这两个文件（外加 smoke_test 的白名单
    例外）出现**非 docstring** 的 `require_auth` 字面量：谁在别处引入它，这条
    就红，逼他要么挪位置、要么把上一条的边界一起扩。

    **docstring 不算，但也不给那三个文件开整文件白名单**——整文件豁免会让
    第三模块的新 writer 藏进被豁免的文件里。
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
    仓库里。
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
    持续证明它能红——否则"加了守卫"与"守卫不生效"在 CI 上长得一模一样。

    探针写进 tmp_path，同一份扫描逻辑（`_require_auth_offenders`），
    一条用例同时验两个方向：第 1 行 docstring 不误伤、第 2 行字面量必须咬住。
    """
    (tmp_path / "probe.py").write_text(
        '"""docstring 里提到 require_auth 不算数。"""\n'
        '_PROBE = {"require_auth": True}\n')
    assert _require_auth_offenders(tmp_path) == ["probe.py:2"]
