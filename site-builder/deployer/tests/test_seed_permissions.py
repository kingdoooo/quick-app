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

    **绕开在线写入口在这里是正当的，请不要"顺手改回" `set_access_policy`**：
    本用例的被测对象是 **seed 路径**，在线写只是原来用来把行造成稀疏的手段。
    改回去的后果是用例在 setup 阶段就抛 `PolicyDataInvalid`，于是这条 P0 回归
    （seed 不得把在线设的名单放大成 org）**根本跑不到**——守卫看着还在，实际
    已经不再守任何东西。
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
    allowed_users 一直缺失 → `_route_item` **拒绝投影**（`PolicyDataInvalid`），
    本次部署在提交点之前失败，真源与投影都停在"缺字段"状态。
    M02 之前这里是回落 "org" 的静默扩权；方向变了，但"seed 必须补上这个字段"
    这个结论没变——补不上，站点就部署不了。

    稀疏行直接造，理由同上一条用例（M02 起在线接口不再产出该形态；被测对象是
    seed 路径而不是在线写路径，所以绕开它是正当的——**别改回
    `set_access_policy`**，改回去这条 P0 回归会在 setup 就抛错、等于失效）。
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


def test_seeded_fields_match_the_deploy_path():
    """`permissions._SEEDED_BY_FIRST_DEPLOY` 必须等于 seed **真正**写的那几个字段。

    "字段缺失 ⇒ 成功部署一次就会补上"这条建议的真假只由本文件下面那段
    UpdateExpression 决定，而给出建议的代码在另一个模块里。两处漂移的后果是
    用户收到一条**不可执行**的指引：照它去部署，`_route_item` 撞上同一条拒绝，
    没有出口（S1 最终复核抓到的就是 `owner` 这一处——文案说部署会补，
    seed 的 if_not_exists 里根本没有它）。
    所以名单按 `_seed_permissions_if_absent` 的源码现取，不在文案侧手抄第二份。
    """
    import ast
    import pathlib
    import re

    import permissions
    src = (pathlib.Path(__file__).parents[1] / "functions"
           / "register_route.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef)
              and n.name == "_seed_permissions_if_absent")
    seeded = set(re.findall(r"if_not_exists\((\w+),",
                            ast.get_source_segment(src, fn)))
    assert seeded, ("取不到 seed 的 if_not_exists 字段清单——判据跟不上代码，"
                    "本条正在空转。**先修判据**，不要改下面的期望集合")
    assert seeded == set(permissions._SEEDED_BY_FIRST_DEPLOY), (
        f"seed 实际初始化 {sorted(seeded)}，而 permissions 的文案按 "
        f"{sorted(permissions._SEEDED_BY_FIRST_DEPLOY)} 给建议——"
        "两边不一致就意味着某个字段的缺失会收到一条错的修法")
    assert "owner" not in seeded, (
        "seed 开始写 owner 了：缺 owner 的行现在**确实**能靠部署一次修好，"
        "于是 REPAIR_ABSENT_UNSEEDED 那一支该跟着改（把 owner 移进 seed 名单）")


def test_deploy_path_refuses_to_launder_a_wrong_typed_row(monkeypatch):
    """部署路径（register_route）遇到错类型行必须拒绝，不能洗成公开。

    这是两轮审查都漏掉的**第四个** writer：`_seed_permissions` 用
    `if_not_exists(...)` **只补缺失字段、不碰错类型字段**，所以
    `require_login = Decimal(0)` 会穿过种子逻辑，在 `_route_item` 被 bool()
    洗成字面 `BOOL False` 写进路由——**每次部署都重洗一遍**。

    这里只断言"抛错"、没有"什么都没写"那一半：`_route_item` 是个**纯构造函数**，
    它不持有任何 client、不发任何请求（本用例连 `aws` 夹具都不需要），
    没有东西可动。端到端的"拒绝且路由未被写"由
    `test_finalize_steps.py::test_missing_require_login_is_refused_not_defaulted`
    覆盖。
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


# 投影赋值的形态判据，**全文件唯一一处定义**：`_hoisted_projection_names` 与
# `_projects_require_auth` 都用它。各写一份正则就是本轮在修的那个毛病。
_PROJECTION_ASSIGN_RE = r"require_auth\s*="


def _hoisted_projection_names(tree) -> set:
    """模块级常量里含 `require_auth =` 的**名字**集合。

    为什么需要：把那条 UpdateExpression 提成模块级常量是一次**自然的重构**
    ——`write_permissions` 与 `resync_route` 现在各持一份逐字节相同的副本，
    合并它们是任何人都会做的清理。可一旦提走，函数体里就不再有字面量，
    `_projects_require_auth` 会对**所有**函数返回 False，于是 offenders 恒为空、
    守卫静默变成一条什么都不约束的绿灯。所以把"引用了这类常量"也算成投影特征：
    **这是把那个重构直接封住，而不是只在事后报警**。

    只看模块顶层赋值（`X = "..."` 与 `X: str = "..."`）。拼接、f-string、
    从别的模块 import 进来的常量都跟不到——那部分残留缺口由
    `test_every_route_permission_writer_calls_effective_policy` 里的
    "三个已知 writer 必须仍被发现"断言兜住（它会红并指出判据需要更新）。
    """
    import ast
    import re
    out = set()
    for node in tree.body:
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if (isinstance(value, ast.Constant) and isinstance(value.value, str)
                and re.search(_PROJECTION_ASSIGN_RE, value.value)):
            out.update(t.id for t in targets if isinstance(t, ast.Name))
    return out


def _projects_require_auth(fn_node, doc_ids, hoisted=frozenset()) -> bool:
    """写投影的**行为特征**，不是"出现过字面量"。

    投影的真实形态（三个 writer 实测）：item dict 里的键
    `"require_auth": {...}`，或 UpdateExpression 里的赋值目标
    `SET require_auth = :a`——后者既算内联字面量，也算引用了
    `hoisted` 里那种模块级常量。只出现字面量不算——`_finish` 从
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
                and re.search(_PROJECTION_ASSIGN_RE, sub.value)):
            return True
        if isinstance(sub, ast.Name) and sub.id in hoisted:
            return True
    return False


def _projection_writers(path) -> dict:
    """扫一个模块 → `{函数名: 是否调了 effective_policy_audited}`。

    提成 helper 的理由与 `_require_auth_offenders` 相同：让"守卫会咬"能用
    tmp_path 探针**常驻**验证，而不是靠人偶尔手工试一次。
    """
    import ast
    import pathlib
    tree = ast.parse(pathlib.Path(path).read_text())
    doc_ids = _docstring_ids(tree)
    hoisted = _hoisted_projection_names(tree)
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if not _projects_require_auth(node, doc_ids, hoisted):
            continue
        # **只接受带审计的那个入口。** 接受纯 effective_policy 会让
        # "某个 writer 绕过审计包装"照样通过守卫。
        out[node.name] = any(
            isinstance(c, ast.Call)
            and (getattr(c.func, "id", None) == "effective_policy_audited"
                 or getattr(c.func, "attr", None) == "effective_policy_audited")
            for c in ast.walk(node))
    return out


# 已知的三个投影 writer。**这个集合是断言的一部分，不是文档**：见下面用例里
# 「发现集必须恰好等于它」那条。
_KNOWN_PROJECTION_WRITERS = {"write_permissions", "resync_route", "_route_item"}


def test_every_route_permission_writer_calls_effective_policy():
    """**自动发现版**：任何往路由投影 `require_auth` 的函数都必须调
    effective_policy_audited。

    判据不是函数名单，而是写行为特征（见 `_projects_require_auth`）
    ——新增第 N 个 writer 会被自动发现，前提是它的投影形态在判据覆盖范围内。

    只扫这两个文件：mark_job（整条恢复上一版路由）与 undeploy（删路由）
    不投影权限字段，不该被这条约束。第三个模块偷偷开始投影由下一条负责。

    **第二条断言（发现集恰好等于已知三个）是防"静默变空"的**：
    第一条断言 `not offenders` 在发现集为空时**恒真**——判据一旦跟不上代码
    （投影串被提成常量、被拼接、字段改名），守卫就从"约束三个 writer"退化成
    一条永远绿的空转，而这与"守卫生效"在 CI 上长得一模一样。这正是 Step 2b
    给哨兵配反向验证的同一个理由，那条守卫也是"当前就绿"。
    """
    import pathlib
    root = pathlib.Path(__file__).parents[1]
    found = {}
    for rel in ("functions/permissions.py", "functions/register_route.py"):
        for name, calls_audited in _projection_writers(root / rel).items():
            found[f"{rel}::{name}"] = calls_audited
    offenders = sorted(k for k, calls in found.items() if not calls)
    assert not offenders, (
        "这些函数在投影 require_auth 但没走 effective_policy_audited："
        f"{offenders}。新增路由权限 writer 必须调它（带审计的那个）")

    discovered = {k.split("::", 1)[1] for k in found}
    assert discovered == _KNOWN_PROJECTION_WRITERS, (
        f"自动发现的投影 writer 集合变了：发现 {sorted(discovered)}，"
        f"期望 {sorted(_KNOWN_PROJECTION_WRITERS)}。\n"
        "· **少了**（尤其是空集）⇒ 判据已经跟不上代码，本守卫正在空转："
        "最可能是那条 `SET require_auth = ...` 被提成了模块级常量之外的形式"
        "（拼接/f-string/跨模块 import），或字段被改名。**先修判据**"
        "（`_projects_require_auth` / `_hoisted_projection_names`），不要改这个集合。\n"
        "· **多了** ⇒ 真的新增了投影 writer。确认它调了 effective_policy_audited"
        "（上一条断言已经在管），然后把它加进 _KNOWN_PROJECTION_WRITERS。"
        "这一步故意需要人点头：新增一个能改站点访问策略的写入点，值得有人看一眼。")


# 允许出现 `require_auth` 字面量的位置，**按相对 `site-builder/` 的路径写**。
# 不能按文件名写：按名字豁免 `permissions.py` 会连带豁免 `panel/permissions.py`
# ——那恰恰是本轮要盯住的那一个（部署期副本，或者一份真的手抄）。
_REQUIRE_AUTH_ALLOWED = {
    "deployer/functions/permissions.py",
    "deployer/functions/register_route.py",
    # smoke_test.py：那里的 `require_auth` 是个**局部变量名**，用来决定冒烟该
    # 断言 302 还是 200，不是往路由写投影。
    "deployer/functions/smoke_test.py",
}


def test_no_other_module_projects_require_auth():
    """上一条只扫两个文件 —— 这一条保证不会有**第三个模块**偷偷开始投影。

    上一条的扫描边界是 permissions.py + register_route.py（路由权限投影的
    两个归属地）。若有人把新的投影 writer 放进第三个模块，上一条不会发现它。
    所以这里断言那两个文件（外加 smoke_test 的白名单例外）之外**没有**
    **非 docstring** 的 `require_auth` 字面量：谁在别处引入它，这条就红，
    逼他要么挪位置、要么把上一条的边界一起扩。

    **扫描范围是 `deployer/functions` + `panel` + `mcp` + `key-proxy`，不是只有
    `functions/`**（S1 最终复核指出）：`permissions.py` 被复制进那三个包的产物，
    而 panel 与 MCP 的 Lambda 环境里**已经**有 `ROUTING_TABLE`
    （deploy_panel.py / deploy_agentcore.py），所以往 `panel/api.py` 加一个投影
    writer 是真的能跑通的——而"panel 不许自己手写投影"此前只以散文形式写在
    `permissions.resync_route` 的 docstring 里，没有任何守卫。M01 的表名守卫与
    tier 守卫都已按同一理由扫整个 `site-builder/`，M02 这一条漏了。

    **`deploy_*.py` 与 `tests/` 的排除是判据的一部分，不是图省事，别"顺手收紧"**：
    `deploy_panel.py` 与 `deploy_key_proxy.py` 合法地写**平台**路由 item
    （console / mcp 子域的 `require_auth: True/False`）。那两条路由**没有 sites
    行**，根本不能过 `effective_policy`（它要的 owner / allowed_users 那几个字段
    对平台子域不存在）。把它们收进来只会得到两个永远修不掉的假阳性，
    而假阳性的下一步是有人给守卫加路径豁免——那才是真的把洞开出来。

    **docstring 不算，但也不给白名单里的文件开整文件豁免**（白名单是路径级、
    逐文件的）——整目录豁免会让新 writer 藏进被豁免的目录里。
    这条故意比上一条**宽**（读取也报），错在"多咬"而不是"漏咬"：
    合法读取该字段的场景要显式进 `_REQUIRE_AUTH_ALLOWED` 并说明理由。
    """
    import pathlib
    sb = pathlib.Path(__file__).parents[2]           # site-builder/
    offenders = _require_auth_offenders(
        sb / "deployer" / "functions", sb / "panel", sb / "mcp", sb / "key-proxy",
        allowed=_REQUIRE_AUTH_ALLOWED, base=sb)
    assert not offenders, (
        f"这些模块出现了 require_auth 字面量（docstring 除外）：{offenders}。"
        "若它们在投影路由权限，必须走 effective_policy_audited 并把上一条守卫的"
        "扫描边界一起扩；若只是读取，请加进 _REQUIRE_AUTH_ALLOWED 并说明理由")


# 扫描时一律跳过的目录名。`tests` 在内：测试里出现这个字面量是正常的
# （断言路由 item 长什么样），它们不是投影 writer。
_SCAN_SKIP_DIRS = (".venv", "cdk.out", "__pycache__", "build", "node_modules",
                   "tests")


def _require_auth_offenders(*roots, allowed=frozenset(), base=None) -> list:
    """roots 下所有 .py 里非 docstring 的 `require_auth` 字面量 → [路径:行…]。

    · **递归**（rglob）：`glob("*.py")` 只看目录第一层，`panel/lib/x.py` 这种写法
      对它等于不存在——扩了扫描范围却仍只看一层，等于把新洞留在子目录里；
    · `allowed` 与返回值都是**相对 `base`**（默认第一个 root）的路径，理由见
      `_REQUIRE_AUTH_ALLOWED` 上方；
    · `deploy_*.py` 跳过（写的是平台路由，见调用处 docstring）；
    · 部署窗口里逐字节相同的副本按**内容**豁免（`is_transient_deploy_copy`）：
      三个部署脚本会把共享模块复制进自己的包目录再在 finally 删掉，MCP 那次的
      窗口是分钟级的。**不按路径豁免**——理由写在那个 helper 上方。

    提成 helper 是为了让"守卫会咬"能用 tmp 目录里的探针文件**常驻**验证
    （下面两条 meta-test）——不是往真实 tracked 文件注入再 `git checkout --`
    还原：那会把文件上未提交的修改一并丢掉，执行中断时探针还会残留在
    仓库里。
    """
    import ast
    from conftest import is_transient_deploy_copy
    base = base or roots[0]
    offenders = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(base).as_posix()
            if any(part in _SCAN_SKIP_DIRS for part in path.parts):
                continue
            if rel in allowed or path.name.startswith("deploy_"):
                continue
            if is_transient_deploy_copy(path):
                continue
            tree = ast.parse(path.read_text())
            doc_ids = _docstring_ids(tree)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in doc_ids
                        and "require_auth" in node.value):
                    offenders.append(f"{rel}:{node.lineno}")
    return sorted(offenders)


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


def test_sentinel_scan_reaches_the_other_three_packages(tmp_path):
    """扩了范围的那条守卫的**反向验证**，常驻：探针放进 panel/mcp 也要被咬住。

    一次把五件事一起钉住，因为它们各自失效的样子都是"守卫还在、但不咬了"：
      · `panel/api.py` 里的投影字面量被发现——这条守卫此前完全看不到它；
      · `mcp/lib/nested.py` 被发现 ⇒ 扫描是**递归**的（`glob("*.py")` 会漏掉它）；
      · `panel/deploy_panel.py` **不**被发现 ⇒ 平台路由那两处合法写入不会变成
        修不掉的假阳性（它是"别顺手收紧"的那一半）；
      · `panel/tests/` 下的不被发现 ⇒ 测试里出现这个字面量是正常的；
      · `panel/permissions.py` 若与 `deployer/functions/permissions.py` **逐字节
        相同**则不被发现 ⇒ 部署窗口里的临时副本不会把守卫变成假红。
        这里刻意用**真实**的那份文件做副本，所以它验的是默认豁免源，
        而不是一个测试自己编出来的形态。
    """
    import pathlib
    real = (pathlib.Path(__file__).parents[1] / "functions" / "permissions.py")
    literal = '_X = {"require_auth": True}\n'
    for rel in ("deployer/functions/permissions.py", "panel/api.py",
                "panel/deploy_panel.py", "panel/tests/test_x.py",
                "mcp/lib/nested.py"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(literal)
    copy = tmp_path / "panel" / "permissions.py"
    copy.write_bytes(real.read_bytes())          # 部署窗口里的那一份
    assert _require_auth_offenders(
        tmp_path / "deployer" / "functions", tmp_path / "panel", tmp_path / "mcp",
        allowed=_REQUIRE_AUTH_ALLOWED, base=tmp_path) == [
            "mcp/lib/nested.py:1", "panel/api.py:1"]


def test_projection_writer_scan_bites_probe_modules(tmp_path):
    """自动发现守卫的反向验证，**常驻**（与上面哨兵那条同一形态、同一理由）。

    上面那条用例保证的是"发现集不为空"，这条保证的是**扫描本身真的会咬**：
    发现一个不调审计入口的投影函数、并且不误伤只读函数。探针一律写进
    tmp_path，绝不往被跟踪的文件里注入、也绝不 `git checkout --` 还原
    （那会把该文件上未提交的修改一并丢掉，中断时探针还会残留在仓库里）。
    """
    inline = tmp_path / "inline.py"
    inline.write_text(
        '"""模块 docstring 里的 require_auth = :a 不算投影。"""\n'
        'def _writes_without_audit(site):\n'
        '    return {"require_auth": {"BOOL": site.get("require_login")}}\n'
        'def _only_reads(committed_route):\n'
        '    return bool(committed_route["require_auth"]["BOOL"])\n')
    # 只有 _writes_without_audit 被发现，且被记成"没调审计入口"（False）；
    # `_only_reads` 是 `_finish` 的形态——**读**不是投影，不该进结果。
    assert _projection_writers(inline) == {"_writes_without_audit": False}

    # 提成模块级常量的那次重构：两个函数体里都没有字面量了。
    # 判据仍然认得出它们（`_hoisted_projection_names` 跟到了那个名字），
    # 所以"守卫静默变空"这条路被封住，而不是只在事后报警。
    hoisted = tmp_path / "hoisted.py"
    hoisted.write_text(
        '_EXPR = "SET require_auth = :a, allowed_users = :u"\n'
        'def _good(site):\n'
        '    pol = permissions.effective_policy_audited(site, actor="x")\n'
        '    return _upd(UpdateExpression=_EXPR, v=pol)\n'
        'def _bad(site):\n'
        '    return _upd(UpdateExpression=_EXPR,\n'
        '                v=bool(site.get("require_login", True)))\n')
    assert _projection_writers(hoisted) == {"_good": True, "_bad": False}

    # **判据跟不到的形态**（如实记录当前限制，不假装覆盖）：字符串拼出来的
    # UpdateExpression，AST 里没有任何一个常量含 `require_auth =`。
    # 这条留在这里当文档：它是为什么上一条用例还需要那句"发现集必须恰好等于
    # 已知三个"——真出现这种重构时，是那句断言把它拦下来，不是这里。
    concatenated = tmp_path / "concatenated.py"
    concatenated.write_text(
        'def _writes(site):\n'
        '    expr = "SET require_auth" + " = :a"\n'
        '    return _upd(UpdateExpression=expr, v=site)\n')
    assert _projection_writers(concatenated) == {}
