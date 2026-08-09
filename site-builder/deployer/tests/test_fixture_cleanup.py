"""fixture 自动清理的纪律（spec §11-pre.3）。

两个清理方在这里一起盯：
  · `scripts/smoke_router.sh`（bash，结构性断言 + shell 语法检查）
  · `tests/test_e2e_fixtures.py` 的 finalizer（真机行为，用 moto 验逻辑）

**为什么清理失败必须让测试红**：静默泄漏资源比测试失败更糟——没人会去看
"绿了但留下 7 个站点"，而下一轮跑测试时这些残留会互相干扰（本项目的
verify 脚本已经因为残留探针数据自我否定过一次）。
"""
import ast
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[3]
SMOKE = ROOT / "site-builder/scripts/smoke_router.sh"
E2E = Path(__file__).parent / "test_e2e_fixtures.py"


# ---------- smoke_router.sh ----------

def test_smoke_script_is_valid_bash():
    r = subprocess.run(["bash", "-n", str(SMOKE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_smoke_uses_random_suffix_not_fixed_names():
    """固定名字（app-smoke）会让并发/重叠运行互相踩，也让"只删本次"无从判定。"""
    src = SMOKE.read_text()
    assert re.search(r"SUF=.*(token_hex|RANDOM|uuid)", src), (
        "没有随机后缀——两次运行会共用 app-smoke 这类固定子域")
    # 固定子域名不得再出现在**可执行行**里（注释里说明历史可以）
    code_lines = [l for l in src.splitlines() if not l.strip().startswith("#")]
    for fixed in ('"app-smoke"', "'app-smoke'", "app-smoke.", "app-smoke2"):
        assert not any(fixed in l for l in code_lines), (
            f"可执行代码里仍有固定名 {fixed}")


def test_smoke_has_trap_covering_abnormal_exits():
    """trap 必须覆盖 EXIT 以及中断信号——Ctrl-C 走了就不清理是常见泄漏源。"""
    src = SMOKE.read_text()
    m = re.search(r"^\s*trap\s+\S+\s+(.+)$", src, re.M)
    assert m, "没有 trap——异常退出会留下路由/对象"
    signals = m.group(1).split()
    assert "EXIT" in signals, f"trap 不含 EXIT: {signals}"
    for sig in ("INT", "TERM"):
        assert sig in signals, f"trap 不含 {sig}（Ctrl-C / 被 kill 时不清理）"


def test_smoke_deletes_only_this_runs_resources():
    """禁止任何形式的批量删除：按前缀 scan-and-delete 会连别人的资源一起删。"""
    src = SMOKE.read_text()
    code = "\n".join(l for l in src.splitlines()
                     if not l.strip().startswith("#"))
    # 删除动作必须逐个 key 指名，不得出现 scan/query 驱动的删除
    assert "dynamodb scan" not in code, (
        "出现 dynamodb scan——清理不得靠扫表找目标（会删到别人的路由）")
    assert not re.search(r"s3\s+rm\s+.*--recursive.*\$\{?BUCKET", code), (
        "出现 s3 rm --recursive 指向整桶前缀——只能删本次上传的 key")
    # 删除目标必须**可溯源到本次后缀**。实际写法是遍历几个由 $SUF 派生的变量
    # （SUB_A/SUB_B/SUB_AUTH），所以不能按"delete-item 那一行里有没有 $SUF"判定
    # ——那样会把正确的循环写法误判为违规（我第一版就是这样）。
    # 改为：所有出现在删除语句里的变量，都必须是从 $SUF 派生出来的。
    suf_derived = set(re.findall(r"^\s*([A-Z_]+)=.*\$\{?SUF\}?", code, re.M))
    assert suf_derived, "没有任何变量从 $SUF 派生——无法判定'只删本次'"
    # 找出删除语句（含其续行）里引用的变量
    del_vars = set()
    lines = code.splitlines()
    for i, line in enumerate(lines):
        if "delete-item" not in line and "s3 rm" not in line:
            continue
        chunk = line
        j = i
        while chunk.rstrip().endswith("\\") and j + 1 < len(lines):
            j += 1
            chunk += lines[j]
        # 循环变量（for sub in ...）视为其迭代集合
        del_vars |= set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", chunk))
    # 表名/桶名等基础设施变量不必派生自 SUF
    infra = {"TABLE", "BUCKET", "ACCOUNT", "BASE_DOMAIN", "sub", "arg"}
    unexplained = {v for v in del_vars if v not in infra
                   and v not in suf_derived and not v.islower()}
    assert not unexplained, (
        f"删除语句引用了既非基础设施、也非 $SUF 派生的变量: {sorted(unexplained)}"
        "——无法保证只删本次资源")
    # 循环变量 `sub` 的迭代集合必须全是 SUF 派生的
    for m in re.finditer(r"for\s+sub\s+in\s+(.+?);\s*do", code):
        iterated = set(re.findall(r"\$\{?([A-Z_]+)\}?", m.group(1)))
        assert iterated <= suf_derived, (
            f"for sub 迭代了非本次的变量: {sorted(iterated - suf_derived)}")


def test_smoke_reads_back_after_delete_with_consistent_read():
    """删完要强一致读回核对——`delete-item` 返回 0 不等于真删掉了。"""
    src = SMOKE.read_text()
    assert "--consistent-read" in src, (
        "清理后没有强一致读回核对——最终一致读会让『已删』看起来还在或反之")


def test_smoke_has_minimum_check_floor():
    """断言脚本必须有下限：崩在中途时"跑了 0 项"读起来像成功。"""
    src = SMOKE.read_text()
    assert re.search(r"MIN_CHECKS=\d+", src), "缺 MIN_CHECKS 下限"
    assert re.search(r"CHECKS[+=]|CHECKS=\$\(\(", src), "没有累加检查计数"


def test_smoke_supports_keep_on_failure():
    """排查现场要留得住：失败时可选跳过清理。"""
    src = SMOKE.read_text()
    assert "--keep-on-failure" in src


def test_smoke_uses_raise_equivalent_not_bare_test_chains():
    """`test ... && echo PASS` 在失败时**不会**让脚本退出（set -e 对 && 链无效）。

    原脚本每条断言都是这个形态：断言失败只是不打印 PASS，退出码仍是 0，
    整个冒烟"通过"。必须改成显式的失败分支。
    """
    code = "\n".join(l for l in SMOKE.read_text().splitlines()
                     if not l.strip().startswith("#"))
    bad = [l for l in code.splitlines()
           if re.match(r"^\s*(test|\[\[).*&&\s*echo\s+.?PASS", l)]
    assert not bad, ("这些断言失败时不会让脚本退出（set -e 对 && 链无效）:\n"
                     + "\n".join(bad))


def test_smoke_has_no_bare_var_before_fullwidth_punctuation():
    """`$VAR）` 会把全角括号首字节吃进变量名，set -u 下当场中断（已踩两次）。"""
    code = [l for l in SMOKE.read_text().splitlines()
            if not l.strip().startswith("#")]
    bad = [l for l in code
           if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*[（）「」，。：、]", l)]
    assert not bad, "裸 $VAR 紧跟全角标点:\n" + "\n".join(bad)


# ---------- test_e2e_fixtures.py 的 finalizer ----------

def _e2e_ast():
    return ast.parse(E2E.read_text())


def test_e2e_has_a_cleanup_fixture_that_is_autouse():
    """清理必须是 autouse——靠每个用例记得调用一定会漏。"""
    tree = _e2e_ast()
    fixtures = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for dec in fn.decorator_list:
            seg = ast.unparse(dec)
            if "fixture" in seg:
                fixtures.append((fn.name, seg, ast.unparse(fn)))
    cleanup = [f for f in fixtures if "autouse=True" in f[1]]
    assert cleanup, "没有 autouse 的清理 fixture"
    assert any("undeploy" in f[2] for f in cleanup), (
        "autouse fixture 里没有 undeploy 逻辑")


def test_e2e_cleanup_tracks_this_runs_ids_explicitly():
    """必须记录本次创建的 site_id，**不得按 owner 批量删**。

    按 owner 删会连试点环境里那些长期存在的真站点一起下线——它们的 owner
    正好也是跑测试的那个人。
    """
    src = E2E.read_text()
    assert re.search(r"(_created|CREATED|_deployed)\b", src), (
        "没有记录本次创建资源的容器")
    code = "\n".join(l for l in src.splitlines()
                     if not l.strip().lstrip("#").startswith(("#",)))
    assert "list_sites_by_owner" not in code, (
        "出现按 owner 列站点——清理绝不能按 owner 批量删")
    assert "scan(" not in code or "purge" not in code, (
        "疑似扫表批量清理")


def test_e2e_cleanup_purges_data_by_default():
    """默认 purge_data=True：留下 DynamoDB 表/DSQL schema 会持续计费并污染。

    **按 AST 取实际字面量**，不是 regex 找 "purge_data.*True"：
    把值改成 False 时，`"purge_data": False` 仍然匹配 `purge_data["\']?\\s*[:=]`
    再加个宽松的尾部——我第一版就是这样，mutation（改成 False）全绿。
    """
    tree = _e2e_ast()
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "purge_data"
                        and isinstance(v, ast.Constant)):
                    values.append(v.value)
    assert values, "清理里找不到 purge_data 字面量"
    assert all(v is True for v in values), (
        f"purge_data 不是 True: {values}——数据表/DSQL schema 会留下来")


def test_e2e_cleanup_failure_fails_the_test_run():
    """清理失败必须让测试红——静默泄漏比失败更糟。"""
    tree = _e2e_ast()
    autouse = [fn for fn in ast.walk(tree)
               if isinstance(fn, ast.FunctionDef)
               and any("autouse=True" in ast.unparse(d) for d in fn.decorator_list)]
    assert autouse, "没有 autouse fixture"
    # **失败信号必须是可达的**，不能只是"源码里出现了 raise"。
    # 实测教训：把守卫改成 `if False: raise ...` 时，基于文本/存在性的断言
    # 全绿——raise 还在，只是永远走不到。所以这里检查 raise 的每个祖先
    # 条件语句都不是常量假。
    found_reachable = False
    for fn in autouse:
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Raise, ast.Assert)):
                continue
            # 找出包住它的所有 if，判断 test 是否恒假
            dead = False
            for parent in ast.walk(fn):
                if not isinstance(parent, ast.If):
                    continue
                if node not in list(ast.walk(parent)):
                    continue
                t = parent.test
                if isinstance(t, ast.Constant) and not t.value:
                    dead = True
            if not dead:
                found_reachable = True
    assert found_reachable, (
        "清理里没有**可达**的失败信号（raise/assert 被恒假条件挡住，或只打印"
        "警告）——资源会静默泄漏")
    body = "\n".join(ast.unparse(fn) for fn in autouse)
    assert "except Exception:\n        pass" not in body, "吞掉了清理异常"


def test_e2e_cleanup_reads_back_to_confirm_deletion():
    """强一致读回确认真的删了（delete 调用成功 ≠ 资源没了）。"""
    src = E2E.read_text()
    assert re.search(r"get_site_consistent|ConsistentRead", src), (
        "清理后没有强一致读回核对")
