"""结构性：授权数据不得进任何跨请求存活的容器。

**为什么需要结构断言而不只靠行为断言**：行为断言（test_every_lookup_hits_
the_database 等）能抓住今天的缺陷；这条抓的是"下一个人为了性能加缓存"。
Lambda 的模块级变量跨请求存活，所以缓存可以在不改任何函数签名的情况下引入。

**边界（这两条不是万能的）**：本文件只看**容器与缓存装饰器**。用一个标量全局
（`_cached_email = None`）攒缓存它抓不到——那一侧由 test_keystore.py 的
`test_every_lookup_hits_the_database` 数读次数兜住。两层互补，别指望其中一层
单独够用。

**handler.py / machine_token.py 由 Task 5 / Task 4 创建。** 文件不存在时对应
参数化用例 **skip 并说明原因**，绝不静默通过——"文件不在"与"文件干净"必须是
两个可区分的结果（M3-FINDINGS §2.10：分不清这两者的守卫等于没有守卫）。
**逐模块参数化**而不是在一个用例里循环，正是为了这一点：keystore.py 今天就在，
它必须报成实打实的 PASS；若整条用例末尾统一 skip，keystore 侧检查通过时也会
显示 skipped，看起来像"什么都没查"。
"""
import ast
import pathlib

import pytest

# **两个模块住在不同的包里**（控制器 pre-flight 修正 2026-08-11）：
# keystore.py 在 deployer/functions/（panel 与 key-proxy 共用，见补充 E），
# handler.py 在 key-proxy/。按 parents[1] 拼 keystore.py 会指向
# key-proxy/keystore.py —— 那个文件不存在，用例会 error 而不是 fail
# （又一处"模块搬家后引用没跟着改"，同 Codex P1-4 的形态）。
#
# **`parents[1]` 是错的，实测过**（2026-08-11 实施期发现）：`KP` 已经是
# `site-builder/key-proxy`，所以 `KP.parents[1]` 是 `quick-app/`，拼出来的
# `quick-app/deployer/functions` 根本不存在。正确的是 `KP.parent`
# （== `site-builder/`，与 `tests/conftest.py:13` 的既有写法一致）。
# 症状值得记住：**用例不会 error 也不会 fail，而是 skip**——"文件不存在"的
# 分支把"我找错了地方"伪装成了"Task 5 还没做"。所以下面对**目录**用 assert
# （找不到目录是本文件自己的 bug），只对**文件**用 skip。
KP = pathlib.Path(__file__).parents[1]                      # site-builder/key-proxy
FN = KP.parent / "deployer" / "functions"                   # deployer/functions
MODULES = {"keystore.py": FN, "handler.py": KP}

# 唯一允许缓存的模块（Task 4）。它**不在** MODULES 里，且有一条反向用例确认它
# 确实有缓存——防止"为了让上面两条绿而把缓存全删了"。
MACHINE_TOKEN = KP / "machine_token.py"

# **白名单：keystore.LAST_READ_CONSISTENCY**。它记录的是"最后一次 GetItem 用没用
# 强一致读"这两个布尔，**不是授权数据**——里面既没有 key_hash 也没有 email，
# 拿到它推不出任何 Key 的状态。它存在的唯一目的是让
# test_both_reads_are_strongly_consistent 能观察到请求形态（ConsistentRead 是
# 传给 boto3 的参数，行为上看不见）。**加白名单项必须写清理由**：这张白名单
# 本身就是本文件唯一的绕过通道。
ALLOWED_MODULE_LEVEL_CONTAINERS = {"keystore.py": {"LAST_READ_CONSISTENCY"}}

# 授权判定函数：这些**绝不能**被任何缓存装饰器包住。
AUTHORIZATION_FUNCTIONS = {"lookup", "_get_switch_row", "_get_key_row",
                           "switch_state"}

# 缓存装饰器的各种写法。`functools.lru_cache` / `lru_cache` / 带参调用
# `@lru_cache(maxsize=1)` 三种形态都要命中。
CACHE_DECORATORS = {"lru_cache", "cache", "cached_property", "cached",
                    "ttl_cache", "memoize"}


def _tree(name):
    directory = MODULES[name]
    # 目录写错时必须 fail（这是本文件自己的 bug），不能走到下面的 skip 分支去
    # ——那正是 parents[1] 那个错误当初的伪装方式。
    assert directory.is_dir(), f"{name} 的搜索目录不存在: {directory}"
    path = directory / name
    if not path.exists():
        pytest.skip(f"{name} 尚未创建（Task 4/5 建）——"
                    "文件缺失不等于「已检查通过」，故 skip 而非 pass")
    return ast.parse(path.read_text())


def _module_level_statements(tree):
    """模块顶层语句，**穿透顶层的 if / try / with**（不进函数与类）。

    穿透是必要的：`try: _CACHE = {} except: pass` 一样是模块级缓存，只看
    `tree.body` 的直接子节点会漏掉它。
    """
    out, stack = [], list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        out.append(node)
        for field in ("body", "orelse", "finalbody"):
            stack.extend(getattr(node, field, None) or [])
        for h in getattr(node, "handlers", None) or []:
            stack.extend(h.body)
    return out


def _assigned_names(node):
    targets = getattr(node, "targets", None) or (
        [node.target] if isinstance(node, ast.AnnAssign) else [])
    names = []
    for t in targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            names += [e.id for e in t.elts if isinstance(e, ast.Name)]
    return names


def _is_mutable_container(value) -> bool:
    """dict / list / set 字面量与推导式，以及 `dict()` / `list()` / `set()` /
    `defaultdict(...)` / `OrderedDict(...)` / `TTLCache(...)` 调用。

    **tuple 与 frozenset 刻意放过**：它们不可变，装不下"跨请求攒起来的"东西，
    正是头白名单这类常量该用的形态。把白名单写成 set 字面量会被这条拦下，
    改成 tuple/frozenset 即可——那是更准确的表达，不是让步。
    """
    if isinstance(value, (ast.Dict, ast.List, ast.Set,
                          ast.DictComp, ast.ListComp, ast.SetComp)):
        return True
    if isinstance(value, ast.Call):
        f = value.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        return name in {"dict", "list", "set", "defaultdict", "OrderedDict",
                        "TTLCache", "LRUCache"}
    return False


def _decorator_names(fn):
    out = set()
    for d in fn.decorator_list:
        node = d.func if isinstance(d, ast.Call) else d
        if isinstance(node, ast.Attribute):
            out.add(node.attr)
        elif isinstance(node, ast.Name):
            out.add(node.id)
    return out


@pytest.mark.parametrize("name", sorted(MODULES))
def test_no_module_level_mutable_containers(name):
    """模块顶层不得有 dict/list/set 赋值（白名单见
    ALLOWED_MODULE_LEVEL_CONTAINERS，每一项都写了为什么它不是授权数据）。"""
    tree = _tree(name)
    allowed = ALLOWED_MODULE_LEVEL_CONTAINERS.get(name, set())
    for node in _module_level_statements(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if not _is_mutable_container(getattr(node, "value", None)):
            continue
        for n in _assigned_names(node):
            assert n in allowed, (
                f"{name}:{node.lineno} 模块级可变容器 {n!r} 不在白名单里"
                "——Lambda 的模块级变量跨请求存活，这是缓存的入口")


@pytest.mark.parametrize("name", sorted(MODULES))
def test_no_lru_cache_on_authorization_functions(name):
    """授权查询不得被任何缓存装饰器包住。

    两个方向都查：① 这些模块里**任何**函数都不许带缓存装饰器（连 `_table()`
    也不行——缓存 boto3 resource 用 `global` 就够，装饰器会给后人"这里可以
    缓存"的错误示范）；② AUTHORIZATION_FUNCTIONS 里的名字必须**真的找到**，
    否则改名会让这条守卫静默变空（同 §2.10：分不清"没找到"与"干净"）。
    """
    tree = _tree(name)
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        found.add(node.name)
        hit = _decorator_names(node) & CACHE_DECORATORS
        assert not hit, (f"{name}:{node.lineno} {node.name} 被缓存装饰器 "
                         f"{sorted(hit)} 包住——授权判定不得缓存")
    if name == "keystore.py":
        assert AUTHORIZATION_FUNCTIONS <= found, (
            f"keystore.py 里找不到 {sorted(AUTHORIZATION_FUNCTIONS - found)}"
            "——函数改名后本守卫就扫不到它，请同步 AUTHORIZATION_FUNCTIONS")


def test_machine_token_is_the_only_module_allowed_to_cache():
    """反向：machine_token.py **必须确实有缓存**。

    这条防的是"为了让上面两条绿而把缓存全删了"。machine token 不是授权判定，
    是 key-proxy 向 AgentCore 证明自己身份的凭证，作用域是整个组件；不缓存
    会让每次 MCP 调用多一次 Cognito 往返并撞频率限制（plan Task 4）。
    """
    if not MACHINE_TOKEN.exists():
        pytest.skip("machine_token.py 尚未创建（Task 4 建）——"
                    "文件缺失不等于「缓存已就位」，故 skip 而非 pass")
    tree = ast.parse(MACHINE_TOKEN.read_text())
    cached = []
    for node in _module_level_statements(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        names = _assigned_names(node)
        if _is_mutable_container(getattr(node, "value", None)):
            cached += names
        # `_CACHE = None` / `_token = None` 这类标量占位也算缓存槽位
        cached += [n for n in names
                   if "cache" in n.lower() or "token" in n.lower()]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and _decorator_names(node) & CACHE_DECORATORS:
            cached.append(node.name)
    assert cached, ("machine_token.py 没有任何缓存槽位——每次调用都换 token 会"
                    "撞 Cognito 频率限制。上面两条结构守卫不该以删掉它为代价变绿")
