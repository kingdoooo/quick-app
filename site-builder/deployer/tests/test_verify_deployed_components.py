"""components 闸门（`scripts/verify_deployed_components.py`）比对判定的反向验证。

Codex deployed-state 复审（2026-08-24）指出的 false-green 缺口：闸门只逐包比
守卫三件套（permissions/register_route/common）与 validate 的 redlines.py，
**不比各函数自己的 handler、也不比 contract/schema.py**——于是"common.py 已部署、
provision_dynamodb.py / undeploy.py / schema.py 仍是旧版"这种半量部署照样 73/73。
判定抽成纯函数后在这里喂坏形态：每一种半量部署都必须被咬住。
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT = (Path(__file__).parents[2] / "scripts"
           / "verify_deployed_components.py")


def _gate():
    spec = importlib.util.spec_from_file_location("_vdc", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vdc"] = mod
    spec.loader.exec_module(mod)
    return mod


# 哈希值本身无意义，只要能表达"同/不同/缺失"
FRESH = {"common.py": "c1", "permissions.py": "p1", "register_route.py": "r1",
         "provision_dynamodb.py": "h1"}


def test_all_matching_is_green():
    """正对照：全部一致 ⇒ 零问题——否则下面的红证明不了什么。"""
    g = _gate()
    assert g.deployer_fn_mismatches(
        "site-deployer-provision_dynamodb", "provision_dynamodb.py",
        dict(FRESH), dict(FRESH)) == []


def test_stale_handler_with_fresh_shared_modules_is_caught():
    """**Codex 点名的反向用例**：common.py 新、handler 旧 ⇒ 必须红。

    这正是旧判定的 false-green 形态：三件套都比对通过，而本轮安全行为
    （ResourceInUse 归属核验 / purge 三态）全在 handler 里。
    """
    g = _gate()
    zip_hashes = dict(FRESH, **{"provision_dynamodb.py": "OLD"})
    problems = g.deployer_fn_mismatches(
        "site-deployer-provision_dynamodb", "provision_dynamodb.py",
        zip_hashes, dict(FRESH))
    assert problems, "handler 陈旧却判成一致"
    assert any("provision_dynamodb.py" in p for p in problems), problems


def test_stale_shared_module_is_still_caught():
    """既有语义不许丢：handler 新、common.py 旧 ⇒ 仍红。"""
    g = _gate()
    zip_hashes = dict(FRESH, **{"common.py": "OLD"})
    problems = g.deployer_fn_mismatches(
        "site-deployer-undeploy", "undeploy.py",
        dict(zip_hashes, **{"undeploy.py": "u1"}),
        dict(FRESH, **{"undeploy.py": "u1"}))
    assert any("common.py" in p for p in problems), problems


def test_handler_missing_from_package_is_caught():
    """包里连自己的 handler 都没有 ⇒ 红（打包方式变了/半量部署）。"""
    g = _gate()
    problems = g.deployer_fn_mismatches(
        "site-deployer-undeploy", "undeploy.py",
        dict(FRESH), dict(FRESH, **{"undeploy.py": "u1"}))
    assert any("undeploy.py" in p and "缺失" in p for p in problems), problems


def test_handler_missing_locally_is_caught():
    """线上 handler 在本地找不到对应源文件 ⇒ 红（改名/删除后闸门不许静默跳过）。"""
    g = _gate()
    problems = g.deployer_fn_mismatches(
        "site-deployer-ghost", "ghost.py",
        dict(FRESH, **{"ghost.py": "g1"}), dict(FRESH))
    assert any("ghost.py" in p for p in problems), problems


def test_absent_shared_module_stays_tolerated():
    """共享守卫模块不在某个包里是正常打包差异——既有语义，别顺手收紧。"""
    g = _gate()
    zip_hashes = {"common.py": "c1", "undeploy.py": "u1"}   # 没有 permissions.py
    assert g.deployer_fn_mismatches(
        "site-deployer-undeploy", "undeploy.py",
        zip_hashes, dict(FRESH, **{"undeploy.py": "u1"})) == []


# ── validate 包的 contract 文件 ────────────────────────────────────────────


def test_contract_files_all_matching_is_green():
    g = _gate()
    z = {"redlines.py": "a", "schema.py": "b"}
    assert g.contract_mismatches(z, dict(z)) == []


def test_stale_schema_with_fresh_redlines_is_caught():
    """**Codex 点名的反向用例**：redlines 新、schema 旧 ⇒ 必须红。

    碰撞 manifest 的拒绝规则（TABLE_NAME_RE）住在 schema.py——只比 redlines
    等于没验 validate 这一轮的主体。
    """
    g = _gate()
    problems = g.contract_mismatches(
        {"redlines.py": "a", "schema.py": "OLD"},
        {"redlines.py": "a", "schema.py": "b"})
    assert any("schema.py" in p for p in problems), problems


def test_schema_missing_from_package_is_caught():
    """contract 文件在 validate 包里缺失 ⇒ 红，不是"打包差异"可豁免的。"""
    g = _gate()
    problems = g.contract_mismatches(
        {"redlines.py": "a"}, {"redlines.py": "a", "schema.py": "b"})
    assert any("schema.py" in p and "缺失" in p for p in problems), problems


# ── 函数集合等值（Codex deployed-state 复审的后续 P3）────────────────────────
#
# 逐包核验只看**已发现**的函数——某个函数整个消失时它根本不进循环，聚合检查
# 平凡全绿。期望集合来自 infra/app.py 的 PLATFORM_FUNCTION_NAMES（它自身的
# 新鲜度由 test_platform_function_name_list_matches_what_creates_them 从 CDK
# 模板与部署脚本双向核对，不是手抄第二份）。


FLEET = {"site-deployer-validate", "site-deployer-undeploy",
         "site-deployer-provision_dynamodb"}


def test_fleet_all_present_is_green():
    """正对照：集合相等 ⇒ 零问题。"""
    g = _gate()
    assert g.deployer_fleet_problems(set(FLEET), set(FLEET)) == []


def test_a_vanished_function_is_caught():
    """**Codex 点名的形态**：函数整个消失 ⇒ 必须红。

    之前它连逐包循环都进不去——"12 个函数逐包一致"对着 11 个函数照样成立。
    """
    g = _gate()
    problems = g.deployer_fleet_problems(
        set(FLEET), FLEET - {"site-deployer-undeploy"})
    assert problems and "site-deployer-undeploy" in " ".join(problems), problems
    assert any("没有" in p for p in problems), problems


def test_a_rogue_function_is_caught():
    """线上多出预期外的 site-deployer-* ⇒ 也红——控制面异物。"""
    g = _gate()
    problems = g.deployer_fleet_problems(
        set(FLEET), FLEET | {"site-deployer-backdoor"})
    assert problems and "多出" in " ".join(problems), problems
    assert "site-deployer-backdoor" in " ".join(problems), problems


def test_expected_set_comes_from_the_cdk_app_constant():
    """对真实 app.py 的抽取：已知成员在、全员带前缀、非 deployer 平台函数被滤掉。"""
    g = _gate()
    exp = g.expected_deployer_functions()
    assert {"site-deployer-undeploy",
            "site-deployer-provision_dynamodb"} <= exp, exp
    assert all(n.startswith("site-deployer-") for n in exp), exp
    assert "site-panel" not in exp, "过滤方向反了——平台函数混进了 deployer 集合"
