"""panel 不得手写权限逻辑——AST 断言，注释/docstring 里出现字样不算违规。

为什么必须 AST 而不是文本 grep：本文件断言的正是"panel 里没有
UpdateExpression"，而 api.py 的 docstring 里就写着这个词。文本匹配会把
说明文字当违规（假红），更糟的是有人为了让它变绿去删注释（真问题仍在）。
本仓库还栽过反向的一次：断言的字样只留在注释里，改错代码测试照样绿。
"""
import ast
from pathlib import Path

PANEL = Path(__file__).parents[1]
RAW_WRITES = {"put_item", "update_item", "delete_item", "transact_write_items"}
ADMIN_HELPERS = {"add_admin", "remove_admin", "rebuild_admin_count"}
# panel 自己的表：审计与一次性 code 标记。直写它们是本来的设计
# （ops-log append-only、session-codes 的 jti 原子消费）。
OWN_TABLES = {"OPS_LOG_TABLE", "SESSION_CODES_TABLE"}


def _panel_modules():
    """panel 的运行时模块。deploy_panel.py 是部署脚本（跑在开发机上，
    要建 IAM/Lambda/S3），不受"禁止直写"约束。"""
    return sorted(p for p in PANEL.glob("*.py") if p.name != "deploy_panel.py")


def test_there_are_panel_modules_to_check():
    """守卫的守卫：glob 空掉时下面每条都会假绿。"""
    assert _panel_modules(), "没找到任何 panel 模块——下面的断言全是空转"


def _own_table_accessors(tree) -> set[str]:
    """返回"取本模块自有表"的函数名集合（函数体里引用了 OWN_TABLES 的环境变量）。

    为什么要这一步：真实代码里表访问会封成 `_codes_table()` 这类小函数，
    于是写调用处的源码片段里**看不到表名**。按片段字符串判断会把合法的
    自有表写入误判成违规（我第一版就是这样），或者反过来——有人把
    `_sites_table()` 也写成同样形态就绕过了检查。
    """
    out = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        body = ast.unparse(fn)
        if any(t in body for t in OWN_TABLES):
            out.add(fn.name)
    return out


def _write_target_is_own_table(node, own_accessors: set[str]) -> bool:
    """写调用的目标表是否是 panel 自有表。

    形如 `_codes_table().put_item(...)`：node.func.value 是对访问器的 Call。
    也接受把表名直接写在同一表达式里的形态。
    """
    seg = ast.unparse(node)
    if any(t in seg for t in OWN_TABLES):
        return True
    recv = node.func.value
    if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name):
        return recv.func.id in own_accessors
    return False


def test_panel_never_writes_dynamodb_update_expressions():
    """panel 里**一个 UpdateExpression 都不该有**。

    比"禁止对某些表用表达式"更强也更简单：panel 对自有表只做 PutItem
    （ops-log append-only、session-codes 一次性标记），对 sites/admins/routing
    的一切修改都必须经 permissions.py 的事务。所以 panel 根本没有正当理由
    出现 UpdateExpression——出现即违规，无需再判目标表。
    """
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                names = {kw.arg for kw in node.keywords}
                assert "UpdateExpression" not in names, (
                    f"{path.name} 手写了 UpdateExpression：{ast.unparse(node)[:120]}"
                    "——权限/站点写入只能走 permissions.py 的高层函数")


def test_condition_expressions_only_guard_panel_own_tables():
    """ConditionExpression 只允许出现在对自有表的写入上。

    **不能一概禁止**：session-codes 的 jti 原子消费必须是
    `attribute_not_exists(jti)` 条件写（"先查再写"在并发重放下两边都会通过，
    等于没有一次性语义）。要禁的是"panel 自己发明 sites/admins 的权限守卫"，
    那种条件表达式必须来自 permissions.snapshot_condition。
    """
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        own = _own_table_accessors(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and "ConditionExpression" in {kw.arg for kw in node.keywords}):
                continue
            assert isinstance(node.func, ast.Attribute), ast.unparse(node)[:120]
            assert _write_target_is_own_table(node, own), (
                f"{path.name} 在非自有表上手写条件表达式："
                f"{ast.unparse(node)[:160]}"
                "——sites/admins 的快照守卫只能来自 permissions.snapshot_condition")


def test_no_raw_writes_to_sites_or_admins_tables():
    """panel 只允许对自己的表（ops-log / session-codes）直写。"""
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        own = _own_table_accessors(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in RAW_WRITES):
                continue
            assert _write_target_is_own_table(node, own), (
                f"{path.name} 对非自有表做了 {node.func.attr}："
                f"{ast.unparse(node)[:120]}"
                "——sites/admins/routing 的写入必须经 permissions.py")


def test_admin_mutations_only_via_permissions_helpers():
    """admin 增删只能命中 permissions.add_admin / remove_admin。

    它们维护 __count__ sentinel，而 remove_admin 的"不能删到名单为空"条件
    依赖它。panel 若 raw 写 admins 表，sentinel 会与实际 item 数漂移，那道
    守卫随之失效（能把管理员删空 = 平台失去管理入口）。

    **按端点逐个断言，不是"整个文件里存在至少一次 helper 调用"**：
    后者在"do_add_admin 改成 raw put_item、而 do_remove_admin 仍调 helper"时
    照样绿（实测——我第一版就是这样，靠隔壁的 raw-write 用例才抓住）。
    每个端点必须各自命中它对应的那个 helper。
    """
    tree = ast.parse((PANEL / "api.py").read_text())
    fns = {n.name: n for n in ast.walk(tree)
           if isinstance(n, ast.FunctionDef)}
    for endpoint, helper in (("do_add_admin", "add_admin"),
                             ("do_remove_admin", "remove_admin")):
        assert endpoint in fns, f"缺少端点 {endpoint}"
        calls = [n for n in ast.walk(fns[endpoint])
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        matched = [n for n in calls
                   if n.func.attr == helper
                   and isinstance(n.func.value, ast.Name)
                   and n.func.value.id == "permissions"]
        assert matched, (
            f"{endpoint} 没有调用 permissions.{helper}——"
            "__count__ sentinel 会与实际 item 数漂移，remove_admin 的"
            "'不能删到名单为空'守卫随之失效")
    # 全文件层面：凡是这些名字的调用都必须挂在 permissions 上
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ADMIN_HELPERS):
            assert (isinstance(n.func.value, ast.Name)
                    and n.func.value.id == "permissions"), (
                f"admin 增删没走 permissions.*：{ast.unparse(n)[:120]}")


def test_no_role_string_comparisons_outside_permissions():
    """panel 不得自己判角色（如 `if role == "owner"`）——授权走 assert_can。"""
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            seg = ast.unparse(node)
            if "role_of" in seg:        # 取角色用于展示，不是判权
                continue
            for lit in ("'owner'", "'collaborator'", "'admin'"):
                assert lit not in seg, (
                    f"{path.name} 手写角色判定：{seg[:120]}"
                    "——授权判定只能走 permissions.assert_can / CAPABILITIES")


def test_no_capabilities_reimplementation():
    """panel 不得自建"哪个角色能做什么"的映射——CAPABILITIES 是唯一真源。"""
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                seg = ast.unparse(node)
                if "CAPABILITIES" in seg and "permissions." not in seg:
                    raise AssertionError(
                        f"{path.name} 自己定义了 CAPABILITIES：{seg[:120]}")
