"""components 闸门（`scripts/verify_deployed_components.py`）比对判定的反向验证。

Codex deployed-state 复审（2026-08-24）指出的 false-green 缺口：闸门只逐包比
守卫三件套（permissions/register_route/common）与 validate 的 redlines.py，
**不比各函数自己的 handler、也不比 contract/schema.py**——于是"common.py 已部署、
provision_dynamodb.py / undeploy.py / schema.py 仍是旧版"这种半量部署照样 73/73。
判定抽成纯函数后在这里喂坏形态：每一种半量部署都必须被咬住。
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = (Path(__file__).parents[2] / "scripts"
           / "verify_deployed_components.py")
# 三套件共用的 RS256 测试密钥 + FakeKms（panel/tests/upgrade_code_vectors.py 的文件头解释了为什么共用
# 一份）。**在这里 insert 而不是在 conftest 里**：auth / router 两侧也是各自 test 文件自己 insert，
# 往 deployer 的 conftest 里塞会让各包的同名 conftest 撞车。
sys.path.insert(0, str(Path(__file__).parents[2] / "panel" / "tests"))


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


# 3c-final：会话签名密钥进 KMS，`JWT_SECRET_PARAM` 整个键不存在了 ⇒ auth 只剩 login-flow 这一个
# 会话相关的 `*_PARAM`（`CLIENT_SECRET_PARAM` 是 Cognito client secret，与会话签名无关）。
AUTH_PARAM_KEYS = ("LOGIN_FLOW_SECRET_PARAM",)
GOOD_ENV = {"LOGIN_FLOW_SECRET_PARAM": "/site-builder/login-flow-secret",
            "CLIENT_SECRET_PARAM": "/site-builder/site-client-secret",
            "SESSION_KEYS_JSON": '{"site":[],"console":[]}',
            "BASE_DOMAIN": "example.test"}


def test_param_name_only_env_is_green_for_the_secret_param():
    """正对照：参数名在、是路径 ⇒ 全绿（否则下面的红证明不了什么）。"""
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


def _auth_plaintext_check_param_keys(src: str | None = None) -> set:
    """闸门里 auth 那处 `_check_env_has_no_plaintext_secret(...)` **实参**里的键名集合。

    **必须按 AST 读实参，不能在源码文本里 grep 字面量**：本文件第一版就是 grep 一段源码里有没有
    `"LOGIN_FLOW_SECRET_PARAM"`，而它在**同一段的注释里**也出现——实测把调用改回单键之后，
    这条守卫照样绿。那正是本仓库栽过的"断言的字样只活在注释里"（闸门自己对 SSM TTL 就写着
    要按行首赋值断言，理由相同）。`ast` 不解析注释，所以这条只能被真实实参满足。

    `src` 只给自测用（默认读线上那份闸门源码）。**自测必须喂给这个函数本身，不许另抄一个
    简化版抽取器**：抄出来的那份只走 `node.args`、只认 `ast.Constant`，缺 `ast.Tuple` 与
    keyword 两个分支——于是"自测绿"证明的是那个副本不看注释，而不是**真正跑的这一份**不看注释
    （用户全局 CLAUDE.md：测试里优先用生产助手，不维护未验证平价的简化副本）。
    """
    import ast
    tree = ast.parse(_SCRIPT.read_text() if src is None else src)
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


def test_the_gate_passes_the_login_flow_param_key():
    """结构守卫：auth 那处必须把 login-flow 那个键交给这条检查，否则上面几条只是理论上有效。

    **清单不是调用点的字面元组**：意图清单在常量 `AUTH_SESSION_PARAM_KEYS`，调用点用
    `_present(want_env, …)` 按本地推导值取交集。守卫随之分两半：① 常量里那个键在、且
    3c-final 删掉的 `JWT_SECRET_PARAM` **不在**；② 调用点确实经 `_present` 把那个常量传进去
    （不是另抄一份）。

    `JWT_SECRET_PARAM` 留在常量里不会红成一条断言——`_present` 会把它交集掉 ⇒ 那条核对静默
    消失、`_min_param_checks()` 同步缩水，闸门总数与下限一起降，**什么都不红**（Task 8 复审 I1）。
    所以这里正面断言它不在。
    """
    g = _gate()
    assert set(g.AUTH_SESSION_PARAM_KEYS) == {"LOGIN_FLOW_SECRET_PARAM"}, (
        f"意图清单是 {list(g.AUTH_SESSION_PARAM_KEYS)}——"
        "LOGIN_FLOW_SECRET_PARAM 漏下发时它不会红")
    assert "JWT_SECRET_PARAM" not in g.AUTH_SESSION_PARAM_KEYS, \
        "3c-final 没有这个键；留着它 = 一条被 _present 静默交集掉的空检查"
    names = _auth_plaintext_check_call_names()
    assert {"_present", "AUTH_SESSION_PARAM_KEYS"} <= names, (
        f"auth 那处没有经 _present 传那个常量：{sorted(names)}")
    assert "want_env" in names, "取交集用的不是**本地推导**值（用线上值会让漏下发变成少核一条）"


def _auth_plaintext_check_call_names(src: str | None = None) -> set:
    """auth 那处调用的第三个实参里出现的**名字**（函数名 + 参数名），按 AST 读。

    与 `_auth_plaintext_check_param_keys` 同一条纪律（不 grep 文本、注释不算），只是现在
    要证明的是"经 `_present` 传那个常量"而不是"字面元组里有哪两个键"。
    """
    import ast
    tree = ast.parse(_SCRIPT.read_text() if src is None else src)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "_check_env_has_no_plaintext_secret"):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        labels = [a.value for a in args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if "site-auth-service" not in labels:
            continue
        names = set()
        for a in args:
            for leaf in ast.walk(a):
                if isinstance(leaf, ast.Name):
                    names.add(leaf.id)
        return names
    return set()


def test_present_narrows_the_intent_list_by_what_is_actually_shipped():
    """`_present` 的两个方向：键在 ⇒ 进清单；键不在 ⇒ 不进（3c-final 的 auth env 里必然有 login-flow）。"""
    g = _gate()
    shipped = {"LOGIN_FLOW_SECRET_PARAM": "/b", "SESSION_KEYS_JSON": "{}"}
    assert g._present(shipped, g.AUTH_SESSION_PARAM_KEYS) == ("LOGIN_FLOW_SECRET_PARAM",)
    assert g._present({"SESSION_KEYS_JSON": "{}"}, g.AUTH_SESSION_PARAM_KEYS) == ()


def test_the_floor_is_derived_at_runtime_not_a_constant():
    """下限必须真的按 `*_PARAM` 条数补——写死会让 L3 每次核对都差两条而红。
    具体的 L2/L3 数字在 test_the_floor_tracks_state_instead_of_being_a_constant。"""
    src = _SCRIPT.read_text()
    assert "MIN_DEPLOYED_CHECKS + _min_param_checks()" in src


# 自测的语料：每条都喂给**真正那个**抽取器（不是简化副本），故意覆盖它的三个分支。
_EXTRACTOR_CASES = {
    # 第一版守卫的假绿形态：字面量只活在注释里
    "注释里有、实参里没有": (
        '# 3c-final：核 LOGIN_FLOW_SECRET_PARAM（漏下发会让所有 /login 500）\n'
        '_check_env_has_no_plaintext_secret(got_env, "site-auth-service", ("CLIENT_SECRET_PARAM",))\n',
        {"CLIENT_SECRET_PARAM"}),
    # 元组分支（线上就是这一种）
    "元组实参": (
        '_check_env_has_no_plaintext_secret(e, "site-auth-service",\n'
        '                                   ("CLIENT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM"))\n',
        {"CLIENT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM"}),
    # keyword 分支：改成关键字传参不能让抽取器瞎掉
    "keyword 实参": (
        '_check_env_has_no_plaintext_secret(e, "site-auth-service",\n'
        '                                   param_keys=("CLIENT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM"))\n',
        {"CLIENT_SECRET_PARAM", "LOGIN_FLOW_SECRET_PARAM"}),
    # 别的 label 那两处调用（panel / key-proxy）不能被算进 auth 的集合
    "只认 auth 那一处": (
        '_check_env_has_no_plaintext_secret(e, "panel", ("CLIENT_SECRET_PARAM",))\n'
        '_check_env_has_no_plaintext_secret(e, "site-auth-service", ("LOGIN_FLOW_SECRET_PARAM",))\n',
        {"LOGIN_FLOW_SECRET_PARAM"}),
}


@pytest.mark.parametrize("label", sorted(_EXTRACTOR_CASES))
def test_the_structural_guards_extractor_reads_arguments_not_comments(label):
    """自测：上一条守卫读的是实参而不是注释，且三个分支都真的在工作。

    **喂给 `_auth_plaintext_check_param_keys` 本身**，不另抄一个简化版——否则证明的是副本的行为
    （用户全局 CLAUDE.md 的"不维护未验证平价的简化副本"，以及"pass-now 的守卫必须有证明它会红的
    用例"两条）。
    """
    src, expected = _EXTRACTOR_CASES[label]
    assert _auth_plaintext_check_param_keys(src) == expected, label


def test_extractor_self_test_corpus_really_contains_the_comment_trap():
    """前提自查：第一条语料的注释里确实有那个字面量，否则那条用例是空转。"""
    src, expected = _EXTRACTOR_CASES["注释里有、实参里没有"]
    assert "LOGIN_FLOW_SECRET_PARAM" in src.splitlines()[0], "注释里没有那个字面量"
    assert "LOGIN_FLOW_SECRET_PARAM" not in expected


# ---- 3c-1B ticket 07：panel 那处也要按状态取交集，下限随状态走 -----------------------------

def test_the_panel_plaintext_check_also_intersects_with_the_local_env():
    """3c-final：panel 一个会话相关的 `*_PARAM` 都不持有（它永不持 login-flow，会话密钥在 KMS）
    ⇒ 清单是**空元组**，而调用点仍必须经 `_present` 传那个常量。

    **为什么空元组也要断言**（Task 8 复审 I1）：清单曾停在 `("JWT_SECRET_PARAM",)`，而 `_present`
    会把它交集掉 ⇒ panel 那条 `*_PARAM` 核对变成**零条断言**、`_min_param_checks()` 同步缩水，
    闸门总数与下限一起降 ⇒ 什么都不红。所以意图必须显式写成"零个"，不能靠交集去演。
    """
    g = _gate()
    assert tuple(g.PANEL_SESSION_PARAM_KEYS) == ()
    assert "JWT_SECRET_PARAM" not in g.PANEL_SESSION_PARAM_KEYS
    src = _SCRIPT.read_text()
    assert '_check_env_has_no_plaintext_secret(env, "panel", ("JWT_SECRET_PARAM",))' not in src, \
        "panel 那处仍写死清单"
    names = _plaintext_check_call_names(src, label="panel")
    assert {"_present", "PANEL_SESSION_PARAM_KEYS", "want_env"} <= names, sorted(names)


def _plaintext_check_call_names(src: str, *, label: str) -> set:
    """某个 label 那处 `_check_env_has_no_plaintext_secret(...)` 实参里出现的名字（按 AST）。"""
    import ast
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "_check_env_has_no_plaintext_secret"):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        labels = [a.value for a in args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if label not in labels:
            continue
        return {leaf.id for a in args for leaf in ast.walk(a) if isinstance(leaf, ast.Name)}
    return set()


def test_the_floor_tracks_the_shipped_env_instead_of_being_a_constant():
    """下限仍必须**按本地推导的 env** 算，不是写死——只是 3c-final 之后那个数恒为 1。

    `MIN_DEPLOYED_CHECKS` 的算式（每一项都是本轮真的会出的 check）：
      上一版 23（③ 4 + ④ 4 + ⑤ 6 + ⑥ 3 + ⑦ 6）
      + ④ 三方对账 2（site / console 各至少一把 current）+ FIXTURE_ISSUER 1 + verifier 角色 1
      + ⑤ 三方对账 1（console 至少一把 current）
      + Edge 公钥 3（含每把 site / 不含 console / RS256 形态）
      = 31
    三方对账那三条是**保守下限**：配了 previous 的 family 会多出一条，实际数只会更多。
    """
    g = _gate()
    auth_env = {"LOGIN_FLOW_SECRET_PARAM": "/b", "SESSION_KEYS_JSON": "{}"}
    panel_env = {"SESSION_KEYS_JSON": "{}"}
    n = (len(g._present(auth_env, g.AUTH_SESSION_PARAM_KEYS))
         + len(g._present(panel_env, g.PANEL_SESSION_PARAM_KEYS)))
    assert n == 1, n
    assert g.MIN_DEPLOYED_CHECKS == 31
    assert g.MIN_DEPLOYED_CHECKS + n == 32
    # 算式必须写在常量旁边（下一个人改 check 条数时要能核对，不然 31 是个来历不明的数）
    src = _SCRIPT.read_text()
    head = src[:src.index("def check(")]
    for part in ("三方对账", "FIXTURE_ISSUER", "Edge 公钥"):
        assert part in head, f"MIN_DEPLOYED_CHECKS 的算式注释里没有 {part} 这一项"


def test_min_param_checks_counts_both_sections_from_the_same_source_as_the_checks():
    """下限的来源必须与真正传给检查的清单同一个（否则两者会分叉，差值成了噪音）。"""
    src = _SCRIPT.read_text()
    body = src[src.index("def _min_param_checks"):src.index("def _check_env_has_no_plaintext")]
    assert "AUTH_SESSION_PARAM_KEYS" in body and "PANEL_SESSION_PARAM_KEYS" in body, \
        "下限只数了一段——另一段的 *_PARAM 条数不会被补上"
    assert "lambda_env()" in body and "lambda_environment(" in body, \
        "下限没按**本地推导**值数（用线上值会让漏下发变成少核一条而不是红）"


# ---- M07：三条平台 Function URL 的授权闸门（auth 此前完全没有）----------------------------------
#
# 判定与部署脚本共用 `function_url_policy.drift`；这里只证明闸门把它接对了：三种真实漂移各红在正确的那一条，
# 正对照全绿，policy 整个不存在按"两条都缺"记红而不是崩。evidence: fake/unit。

import fake_lambda_policy as flp

FUP_EDGE = "arn:aws:iam::000000000000:role/site-edge-role"


def _authz(lam, edge=FUP_EDGE):
    g = _gate()
    g.results.clear()
    g._check_function_url_authz(lam, "site-auth-service", "auth", edge)
    return g.results


def test_function_url_authz_is_all_green_on_the_documented_shape():
    """正对照：与 AWS 文档形态逐字节相同 ⇒ 恰好三条 PASS。"""
    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE)))
    assert len(res) == 3 and all(ok for ok, _, _ in res), res


def test_function_url_authz_catches_a_principal_rewritten_to_a_deleted_role():
    """M07 的核心形态：edge role 重建后 Principal 成了 AROA…——只有"逐条内容"那条红，集合那条绿。"""
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    lam = flp.FakeLambdaPolicy([
        flp.rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
        flp.rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)])
    res = _authz(lam)
    assert [ok for ok, _, _ in res] == [True, True, False], res
    assert "AROA" in res[2][2], "detail 里要能看到线上的 principal 形态"


def test_function_url_authz_catches_a_stray_statement():
    lam = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE) + [
        flp.rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
    res = _authz(lam)
    assert [ok for ok, _, _ in res] == [True, False, True], res
    assert "public-url" in res[1][2]


def test_function_url_authz_catches_a_missing_statement():
    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE)[:1]))
    assert [ok for ok, _, _ in res] == [True, False, True], res
    assert "edge-invoke-function" in res[1][2]


def test_function_url_authz_catches_auth_type_none():
    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE), auth_type="NONE"))
    assert [ok for ok, _, _ in res] == [False, True, True], res


def test_function_url_authz_reports_an_absent_policy_as_failures_not_a_crash():
    """policy 整个不存在（被安全扫描删光的实测形态）⇒ 两条 policy check 红，脚本不崩成"执行中断"。"""
    res = _authz(flp.FakeLambdaPolicy())
    assert [ok for ok, _, _ in res] == [True, False, True], res
    assert "edge-invoke" in res[1][2] and "edge-invoke-function" in res[1][2]


def _function_url_authz_targets(src: str) -> set:
    """源码里每处 `_check_function_url_authz(...)` 调用的**字符串常量实参**集合（按 AST，注释不算）。

    与 `_auth_plaintext_check_param_keys` 同一条纪律：不 grep 文本。panel / key-proxy 那两处用的是变量 `fn`，
    所以常量集合里只会出现 auth 那处的 "site-auth-service"（以及三处的 label）。
    """
    import ast as _ast
    found = set()
    for node in _ast.walk(_ast.parse(src)):
        if isinstance(node, _ast.Call) and getattr(node.func, "id", None) == "_check_function_url_authz":
            for a in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(a, _ast.Constant) and isinstance(a.value, str):
                    found.add(a.value)
    return found


def _function_url_authz_targets_in(src: str, function_name: str) -> set:
    """同上，但只看某个函数体内的调用（按 AST 定位函数，不切源码文本——④ 段的 print 里有框线字符，切片会不可解析）。"""
    import ast as _ast
    tree = _ast.parse(src)
    fn = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef) and n.name == function_name)
    return _function_url_authz_targets(_ast.unparse(fn))


def test_the_auth_section_asserts_the_function_url_policy():
    """结构守卫：④ 段（run_deployed）里必须有一处对 `site-auth-service` 的 `_check_function_url_authz` 调用。"""
    src = _SCRIPT.read_text()
    assert "site-auth-service" in _function_url_authz_targets_in(src, "run_deployed"), "auth 的 Function URL 仍然没有闸门"
    assert {"auth", "panel", "key-proxy"} <= _function_url_authz_targets(src), "三条平台 Function URL 没有全覆盖"


def test_the_auth_target_extractor_reads_arguments_not_comments():
    """自测：喂给**同一个**抽取器，注释里的字面量不算、实参里的才算。"""
    assert _function_url_authz_targets(
        '# 该给 site-auth-service 也加 _check_function_url_authz\n'
        '_check_function_url_authz(lam, fn, "panel", edge_role)\n') == {"panel"}
    assert _function_url_authz_targets(
        '_check_function_url_authz(lam, "site-auth-service", "auth", edge)\n') == {"site-auth-service", "auth"}


def test_the_gate_uses_the_shared_drift_judgement_not_its_own():
    """`_check_function_url_authz` 里必须调用 `function_url_policy.drift`——闸门与部署脚本对"对的形态"只能有一个定义。"""
    import ast as _ast
    tree = _ast.parse(_SCRIPT.read_text())
    fn = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef) and n.name == "_check_function_url_authz")
    calls = {_ast.unparse(n.func) for n in _ast.walk(fn) if isinstance(n, _ast.Call)}
    assert any(c == "drift" or c.endswith(".drift") for c in calls), sorted(calls)


# ---- 3c-final：三方公钥对账 / Edge 产物公钥 / verifier 的 Function URL 两条 --------------------
#
# spec §11.6 的第 3 层：`SESSION_KEYS_JSON` 只是**引用**（kid / key_arn / spki_sha256），没有密钥材料。
# 于是"线上下发的引用"与"config 里写的引用"与"KMS 里那把 key 的真实公钥"三者必须同时相等——
# 只比前两者时，config 里 spki_sha256 抄错（换 key 时改了 ARN 没改指纹）会让 auth 在**运行时**
# 拒绝加载 allowlist（verifier_env 的自检），而部署与闸门双双全绿。
# evidence: fake/unit（FakeKms 按同一组 RS 测试密钥回答，与 auth / panel / router 三侧共用）。

import upgrade_code_vectors as v  # noqa: E402


def test_three_way_key_check_is_green_when_env_config_and_kms_agree_and_red_on_any_disagreement(monkeypatch):
    g = _gate(); g.results.clear()
    env_json = v.session_keys_json((v.SITE_KID, "current"), (v.CONSOLE_KID, "current"))
    monkeypatch.setattr(g, "_config_key_rows", lambda families: json.loads(env_json))
    g._check_session_keys_three_way(v.FakeKms(), env_json, "auth", ("site", "console"))
    assert [ok for ok, _, _ in g.results] == [True, True]
    g.results.clear()
    kms = v.FakeKms(); kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    g._check_session_keys_three_way(kms, env_json, "auth", ("site", "console"))
    assert [ok for ok, _, _ in g.results] == [True, False]


def test_three_way_key_check_reds_when_the_deployed_env_row_drifts_from_config(monkeypatch):
    """线上 env 与 config 同 kid 但**内容**不同（改了 config 没重部 auth）⇒ 必须红。

    正对照在上一条；这里证明第三方（KMS）一致时那条比较仍在做——否则"env == config"这半
    可以被 KMS 那半的绿掩盖。
    """
    g = _gate(); g.results.clear()
    cfg_rows = json.loads(v.session_keys_json((v.SITE_KID, "current")))
    stale = json.loads(v.session_keys_json((v.SITE_KID, "current")))
    stale["site"][0]["role"] = "previous"          # 线上还停在轮转前的角色
    monkeypatch.setattr(g, "_config_key_rows", lambda families: cfg_rows)
    g._check_session_keys_three_way(v.FakeKms(), json.dumps(stale), "auth", ("site",))
    assert [ok for ok, _, _ in g.results] == [False]


def test_three_way_key_check_reds_when_a_config_kid_is_missing_from_the_deployed_env(monkeypatch):
    """config 里有两把、线上只下发一把（轮转的第一步做了 config、没重部）⇒ 缺的那把红，不是少一条 check。"""
    g = _gate(); g.results.clear()
    cfg_rows = json.loads(v.session_keys_json((v.SITE_KID, "current"), (v.SITE_PREV_KID, "previous")))
    monkeypatch.setattr(g, "_config_key_rows", lambda families: cfg_rows)
    g._check_session_keys_three_way(v.FakeKms(), v.session_keys_json((v.SITE_KID, "current")),
                                    "auth", ("site",))
    assert [ok for ok, _, _ in g.results] == [True, False]


def test_three_way_key_check_reds_instead_of_crashing_when_kms_is_unreachable(monkeypatch):
    """`kms.get_public_key` 抛异常（AccessDenied / 限流 / key 被删）⇒ 那条红，脚本不崩成"执行中断"。"""
    g = _gate(); g.results.clear()
    env_json = v.session_keys_json((v.SITE_KID, "current"))
    monkeypatch.setattr(g, "_config_key_rows", lambda families: json.loads(env_json))

    class _Denied:
        def get_public_key(self, KeyId):
            raise RuntimeError("AccessDeniedException")

    g._check_session_keys_three_way(_Denied(), env_json, "auth", ("site",))
    assert [ok for ok, _, _ in g.results] == [False]
    assert "RuntimeError" in g.results[0][2], g.results


def test_edge_public_key_check_requires_every_site_key_and_forbids_console_keys():
    g = _gate()
    src = 'SITE_ALLOWLIST_JSON = \'\'\'{"site-rs-v1": {"alg": "RS256", "spki_b64": "U0lURQ==", "role": "current"}}\'\'\'\nRS256_GOLDEN = {}\n'
    g.results.clear(); g._check_edge_public_keys(src, ["U0lURQ=="], ["Q09OU09MRQ=="])
    assert all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src, ["T1RIRVI="], ["Q09OU09MRQ=="])
    assert not all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src.replace("U0lURQ==", "Q09OU09MRQ=="), ["Q09OU09MRQ=="], ["Q09OU09MRQ=="])
    assert not all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_edge_public_keys(src + 'JWT_SECRET = "x"\n', ["U0lURQ=="], [])
    assert not all(ok for ok, _, _ in g.results)


def test_edge_public_key_check_reds_on_a_hs_or_legacy_remnant_and_on_a_missing_golden():
    """RS256 形态那条的**每一种**破法都要红：没有黄金预热、留着 JWT_SECRET、留着 LEGACY_ENTRY。

    三个条件写在一条 check 里，所以必须逐个证明它会红——否则其中两个可能是装饰。
    """
    g = _gate()
    base = 'SITE_ALLOWLIST_JSON = \'\'\'{"site-rs-v1": {"spki_b64": "U0lURQ=="}}\'\'\'\n'
    for broken, why in ((base, "没有 RS256_GOLDEN"),
                        (base + 'RS256_GOLDEN = {}\nJWT_SECRET = ""\n', "留着 JWT_SECRET"),
                        (base + 'RS256_GOLDEN = {}\nLEGACY_ENTRY = "off"\n', "留着 LEGACY_ENTRY")):
        g.results.clear()
        g._check_edge_public_keys(broken, ["U0lURQ=="], [])
        assert not all(ok for ok, _, _ in g.results), why


def test_edge_public_key_check_is_not_fooled_by_a_console_key_outside_the_allowlist():
    """console 公钥出现在**产物任何地方**（注释、别的常量）都算漏，不只在 SITE_ALLOWLIST_JSON 里。"""
    g = _gate(); g.results.clear()
    src = ('SITE_ALLOWLIST_JSON = \'\'\'{"site-rs-v1": {"spki_b64": "U0lURQ=="}}\'\'\'\n'
           'RS256_GOLDEN = {}\n'
           '# 顺手记一下 console 那把：Q09OU09MRQ==\n')
    g._check_edge_public_keys(src, ["U0lURQ=="], ["Q09OU09MRQ=="])
    assert not all(ok for ok, _, _ in g.results)


def test_function_url_authz_expects_the_verifier_pair_only_when_the_component_is_on():
    g = _gate()
    ver = "arn:aws:iam::000000000000:role/site-builder-verifier"
    lam = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE))
    g.results.clear(); g._check_function_url_authz(lam, "site-auth-service", "auth", FUP_EDGE, extra_principals={"verifier": ver})
    assert not all(ok for ok, _, _ in g.results), "开着组件却没有 verifier 两条 ⇒ 红"
    lam2 = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE) + flp.good_pair(ver, label="verifier"))
    g.results.clear(); g._check_function_url_authz(lam2, "site-auth-service", "auth", FUP_EDGE, extra_principals={"verifier": ver})
    assert all(ok for ok, _, _ in g.results)
    g.results.clear(); g._check_function_url_authz(lam2, "site-auth-service", "auth", FUP_EDGE)
    assert not all(ok for ok, _, _ in g.results), "关了组件而语句还在 ⇒ 野 Sid 红"


def test_function_url_authz_still_emits_exactly_three_checks_with_extra_principals():
    """条数不许随 `extra_principals` 变——`MIN_DEPLOYED_CHECKS` 把 Function URL 记成恒定的三条。"""
    g = _gate()
    ver = "arn:aws:iam::000000000000:role/site-builder-verifier"
    lam = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE) + flp.good_pair(ver, label="verifier"))
    g.results.clear(); g._check_function_url_authz(lam, "site-auth-service", "auth", FUP_EDGE, extra_principals={"verifier": ver})
    assert len(g.results) == 3, g.results
    # 通过时的 detail 要说出**全部**期望 Sid（含 verifier 两条），否则读报告的人以为只授了 edge
    assert "verifier-invoke" in g.results[1][2], g.results[1]


def test_the_auth_section_passes_extra_principals_derived_from_the_verification_section():
    """结构守卫：auth 那处必须把 `extra_principals` 交给 `_check_function_url_authz`，且它来自
    `[Verification]` 的判定（不是写死 None，也不是无条件传）。

    写死 None 的后果：开着夹具组件时线上那两条语句成了"野 Sid"，闸门每次都红；无条件传的后果：
    关掉组件后残留的两条不会被报成野 Sid（spec §11.7 要求它们被删掉）。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    tree = _ast.parse(src)
    fn = next(n for n in _ast.walk(tree)
              if isinstance(n, _ast.FunctionDef) and n.name == "run_deployed")
    call = next(n for n in _ast.walk(fn)
                if isinstance(n, _ast.Call)
                and getattr(n.func, "id", None) == "_check_function_url_authz")
    kw = {k.arg: _ast.unparse(k.value) for k in call.keywords}
    assert "extra_principals" in kw, "auth 那处没传 extra_principals"
    assert kw["extra_principals"] != "None", "写死 None ⇒ 开着夹具组件时闸门每次都红"
    assert "fixture_on" in kw["extra_principals"], kw["extra_principals"]


def test_the_auth_section_asserts_fixture_issuer_and_the_verifier_role_agree_with_config():
    """结构守卫：④ 段必须另出两条 check——`FIXTURE_ISSUER` env 与 `[Verification]` 一致、
    `site-builder-verifier` 角色的**存在与否**与 `[Verification]` 一致。

    只比 env 是不够的：关掉组件而角色还在 = 一条仍可被 assume 的冒充路径（Function URL 的
    resource policy 那两条已被删，但角色本身的 inline policy 还在，且它是账号内可 assume 的）。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_deployed")
    body = _ast.unparse(fn)
    assert "FIXTURE_ISSUER" in body, "FIXTURE_ISSUER 与配置的一致性没有闸门"
    assert "fixture_on" in body and "role_exists" in body, \
        "verifier 角色的存在性没有与 [Verification] 对账"


def test_the_panel_section_reconciles_the_console_family_only():
    """结构守卫：⑤ 段的三方对账只要 console family——panel 永不持有 site 的任何引用（spec §4.1）。"""
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_panel")
    call = next(n for n in _ast.walk(fn)
                if isinstance(n, _ast.Call)
                and getattr(n.func, "id", None) == "_check_session_keys_three_way")
    families = _ast.unparse(call.args[3])
    assert families == "('console',)", families


def test_the_config_rows_come_from_session_keys_not_a_second_parser():
    """`_config_key_rows` 必须用 `session_keys.env_json` / `load_session_keys`——config 的形态只能有一个解析器。"""
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "_config_key_rows")
    body = _ast.unparse(fn)
    assert "env_json" in body and "load_session_keys" in body, body


def test_the_edge_public_key_section_runs_before_the_console_route_early_return():
    """结构守卫：Edge 公钥那三条必须在 ⑦ 之前。

    ⑦ 在 console route 缺失时 `return`——放在它之后的检查一条都不会跑，而"缺 route"是个
    常见的中间状态（先部 auth 后部 panel）。那时 Edge 公钥对账会**静默消失**，只留下
    "只跑了 N 项"这一个含糊的信号。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_mcp_and_route")
    body = _ast.unparse(fn)
    assert "_check_edge_public_keys" in body, "⑥b 整段不在 run_mcp_and_route 里"
    assert body.index("_check_edge_public_keys") < body.index("console route 存在"), \
        "Edge 公钥对账排在 ⑦ 的 early return 之后 —— 缺 console route 时它整段不跑"


def test_the_edge_public_keys_come_from_kms_not_from_the_config_fingerprint():
    """结构守卫：期望的 b64 公钥必须由 `kms.get_public_key` 的 DER 现算，不能拿 config 的 `spki_sha256`。

    `spki_sha256` 是**指纹**不是公钥本体：拿它去 grep 产物永远匹配不上 ⇒ "含每把 site 公钥"那条
    恒红（或判据一放宽就恒绿）。两种都是假检查，而它守的是"全员 302"这种全站故障。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_mcp_and_route")
    body = _ast.unparse(fn)
    assert "get_public_key" in body and "b64encode" in body, body[-800:]
    assert "spki_sha256" not in body, "拿指纹当公钥去比 —— 那条检查永远不会真的成立"


def test_the_edge_section_reds_instead_of_crashing_when_the_artifact_is_unreachable():
    """读不到产物 / 取不到公钥时必须出一条 `check(False, …)`，不能让异常冒出去。

    冒出去的后果不是"这一段红"而是**整个脚本崩成"执行中断"**，⑦⑧⑨ 一起丢掉——而那三段里
    有 M5 统计管道与 key-proxy 的全部断言。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_mcp_and_route")
    handler = next(h for n in _ast.walk(fn) if isinstance(n, _ast.Try)
                   for h in n.handlers
                   if "_check_edge_public_keys" in _ast.unparse(n))
    text = _ast.unparse(handler)
    assert "check(False" in text, text


def test_the_fixture_flag_is_read_through_deploy_auths_own_parser():
    """结构守卫：`[Verification]` 的判定必须走 `deploy_auth.read_verification`，不在闸门里再解析一遍 flag。

    另写一份的后果不是"多几行"：`read_verification` 对 `fixture_issuer = yes` 这类坏值 SystemExit
    （deploy_auth 那时也拒绝部署），而一份 `== "true"` 的复制品会把它读成 off ⇒ 闸门拿一个
    deploy 根本不会产出的期望值去比对，两侧结论不同。同 `_check_function_url_authz` 用共享
    `drift` 的理由：对"什么算开着"只能有一个定义。
    """
    import ast as _ast
    src = _SCRIPT.read_text()
    fn = next(n for n in _ast.walk(_ast.parse(src))
              if isinstance(n, _ast.FunctionDef) and n.name == "run_deployed")
    body = _ast.unparse(fn)
    assert "read_verification" in body, "闸门自己解析 [Verification] 的 flag —— 两侧会分叉"
    assert "VERIFIER_ROLE_NAME" in body, "角色名写死了字面量，不是 deploy_auth 的常量"
