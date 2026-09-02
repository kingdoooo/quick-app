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


def test_panel_branch_compares_the_whole_environment_to_the_local_derivation():
    """3c-1A code-review：panel 漏发 SESSION_KEYS_JSON / LEGACY_ENTRY 此前无人能抓（只查明文）。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    panel = src[src.index("def run_panel"):src.index("\ndef ", src.index("def run_panel") + 10)]
    assert "lambda_environment(" in panel and "环境变量 == 本地" in panel


def test_auth_branch_checks_every_declared_package_module_not_two_hand_picked_files():
    """2026-09-02：漏 verifier_env.py 时这里仍绿，因为只核对 login_handler/session 两个点名文件。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    auth = src[src.index("线上 auth 服务是否加载了这份代码"):src.index("def run_panel")]
    assert "AUTH_PACKAGE_MODULES" in auth
    assert 'for base in ("login_handler.py", "session.py")' not in auth


# ── 3c-1B：环境变量的"无明文密钥"判据必须覆盖新变量名（spec §11.3 的部署侧后果）──
#
# 闸门对 auth 的环境变量做两件事：整体 == 本地 lambda_env() 推导值（新变量自动入闸），
# 以及这条"无明文密钥"。第二条是唯一能抓住"有人把值而不是参数名下发了"的地方，而它按
# **键名**判断——所以新加一个 `*_SECRET` 家族的变量时必须确认它被覆盖，而不是假定。

def _env_check(env, param_key):
    """跑一次 _check_env_has_no_plaintext_secret，返回 [(ok, name, detail), ...]。"""
    g = _gate()
    g.results.clear()
    g._check_env_has_no_plaintext_secret(env, "site-auth-service", param_key)
    return g.results


AUTH_PARAM_KEYS = ("JWT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM")
GOOD_ENV = {"JWT_SECRET_PARAM": "/site-builder/jwt-secret",
            "LOGIN_FLOW_SECRET_PARAM": "/site-builder/login-flow-secret",
            "CLIENT_SECRET_PARAM": "/site-builder/site-client-secret",
            "BASE_DOMAIN": "example.test"}


def test_param_name_only_env_is_green_for_both_secret_params():
    """正对照：两个参数名都在、都是路径 ⇒ 全绿（否则下面的红证明不了什么）。"""
    assert all(ok for ok, _, _ in _env_check(GOOD_ENV, AUTH_PARAM_KEYS))


def test_plaintext_login_flow_secret_in_env_is_caught():
    """把值下发成 `LOGIN_FLOW_SECRET` 而不是 `LOGIN_FLOW_SECRET_PARAM` ⇒ 必须红。"""
    bad = dict(GOOD_ENV, LOGIN_FLOW_SECRET="0123456789abcdef0123456789abcdef")
    del bad["LOGIN_FLOW_SECRET_PARAM"]
    assert any(not ok for ok, _, _ in _env_check(bad, AUTH_PARAM_KEYS))


def test_missing_login_flow_param_is_caught():
    """整个变量漏下发 ⇒ 必须红。漏它的症状是**所有 /login 500**（_secret 抛 RuntimeError），
    与 1A 那次 502 同形，而单测有 ENV 兜着看不出来。"""
    bad = {k: v for k, v in GOOD_ENV.items() if k != "LOGIN_FLOW_SECRET_PARAM"}
    assert any(not ok for ok, _, _ in _env_check(bad, AUTH_PARAM_KEYS))


def test_login_flow_param_holding_a_value_instead_of_a_path_is_caught():
    """名字对但值不是 SSM 路径（有人把明文塞进 `*_PARAM` 里绕过键名判据）⇒ 必须红。"""
    bad = dict(GOOD_ENV, LOGIN_FLOW_SECRET_PARAM="0123456789abcdef0123456789abcdef")
    assert any(not ok for ok, _, _ in _env_check(bad, AUTH_PARAM_KEYS))


def _auth_plaintext_check_param_keys() -> set:
    """闸门里 auth 那处 `_check_env_has_no_plaintext_secret(...)` **实参**里的键名集合。

    **必须按 AST 读实参，不能在源码文本里 grep 字面量**：本文件第一版就是 grep 一段源码里有没有
    `"LOGIN_FLOW_SECRET_PARAM"`，而它在**同一段的注释里**也出现——实测把调用改回单键之后，
    这条守卫照样绿。那正是本仓库栽过的"断言的字样只活在注释里"（闸门自己对 SSM TTL 就写着
    要按行首赋值断言，理由相同）。`ast` 不解析注释，所以这条只能被真实实参满足。
    """
    import ast
    tree = ast.parse(_SCRIPT.read_text())
    found = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "_check_env_has_no_plaintext_secret"):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        # 第二个实参是 label；只认 auth 那一处调用
        labels = [a.value for a in args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if "site-auth-service" not in labels:
            continue
        for a in args:
            if isinstance(a, (ast.Tuple, ast.List)):
                found |= {e.value for e in a.elts
                          if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            elif isinstance(a, ast.Constant) and isinstance(a.value, str) \
                    and a.value.endswith("_PARAM"):
                found.add(a.value)
    return found


def test_the_gate_passes_both_auth_param_keys_not_just_jwt():
    """结构守卫：auth 那处必须把两个键都**当实参**交给这条检查，否则上面几条只是理论上有效。"""
    keys = _auth_plaintext_check_param_keys()
    assert keys == {"JWT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM"}, (
        f"闸门实际交给「无明文密钥」判据的键是 {sorted(keys)}——"
        "LOGIN_FLOW_SECRET_PARAM 漏下发时它不会红")


def test_that_structural_guard_is_not_satisfied_by_a_comment():
    """自测：证明上一条读的是实参而不是注释。

    喂一段"注释里有、实参里没有"的源码给同一个抽取器（这正是第一版守卫的假绿形态）。
    """
    import ast
    src = ('# 3c-1B：两个 *_PARAM 都核（LOGIN_FLOW_SECRET_PARAM 漏下发会 500）\n'
           '_check_env_has_no_plaintext_secret(got_env, "site-auth-service", "JWT_SECRET_PARAM")\n')
    found = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == \
                "_check_env_has_no_plaintext_secret":
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and a.value.endswith("_PARAM"):
                    found.add(a.value)
    assert found == {"JWT_SECRET_PARAM"}, found
    assert "LOGIN_FLOW_SECRET_PARAM" in src, "本条的前提是注释里确实有那个字面量"
