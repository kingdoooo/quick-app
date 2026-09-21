"""stack policy 的 **guard 语义谓词**。

**为什么不能用 `router/infrastructure/stack_policy.py` 的 `policy_problems()`**：
那个函数判的是"线上策略是否与本项目规定的形态**等价**"（`verify_deployed_edge.sh` ⑤ 用它），
它的 `covered` 只收 Deny 语句里**字面**的 Resource 串。一份**更严格**的
`Deny Update:* on "*"` 会让 `want - covered` 非空（want 是精确的 LogicalResourceId/<id>）
⇒ 报"没有 Deny 语句覆盖 X"，还会再报一条"Resource 含通配"。
⇒ **`policy_problems() != [] 推不出 guard == "open"`。**

所以闸门用本模块这个目的单一的谓词。两个谓词的职责在各自的 docstring 里互相点名，
防止后来者"统一"掉。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_MODULE = _ROOT / "site-builder" / "scripts" / "_stack_policy_guard.py"
_STACK_POLICY = _ROOT / "router" / "infrastructure" / "stack_policy.py"
IDS = ["OriginRequestFunctionABC", "OriginResponseFunctionDEF",
       "DistributionGHI", "SubdomainMappingTableJKL"]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def g():
    return _load(_MODULE, "_stack_policy_guard")


@pytest.fixture()
def sp():
    return _load(_STACK_POLICY, "_stack_policy_shape")


def _deny(resources, actions=("Update:*",), **extra):
    return {"Statement": [
        {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": list(actions), "Principal": "*",
         "Resource": list(resources), **extra}]}


def test_no_policy_is_open(g):
    assert g.guard_for(None, IDS) == g.GUARD_OPEN


def test_exact_logical_ids_are_protected(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS])
    assert g.guard_for(policy, IDS) == g.GUARD_PROTECTED


def test_stricter_deny_all_is_also_protected(g):
    """这正是 `policy_problems()` 会判成"有问题"的那一份——**它更严格，不是更松**。"""
    assert g.guard_for(_deny(["*"]), IDS) == g.GUARD_PROTECTED
    assert g.guard_for(_deny(["LogicalResourceId/*"]), IDS) == g.GUARD_PROTECTED


def test_prefix_wildcard_must_actually_cover_the_id(g):
    assert g.guard_for(_deny(["LogicalResourceId/OriginRequest*",
                              "LogicalResourceId/OriginResponse*",
                              "LogicalResourceId/Distribution*",
                              "LogicalResourceId/Subdomain*"]), IDS) == g.GUARD_PROTECTED
    # 少一个就不是 protected：漏掉的那个资源照样能被直接更新。
    assert g.guard_for(_deny(["LogicalResourceId/OriginRequest*"]), IDS) == g.GUARD_OPEN


def test_missing_one_id_is_open(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS[:-1]])
    assert g.guard_for(policy, IDS) == g.GUARD_OPEN


def test_narrower_action_set_is_open(g):
    """ADR 0007：Edge 换码是 `Update:Modify`。只拒 Replace/Delete 拦不住它。"""
    assert g.guard_for(_deny([f"LogicalResourceId/{i}" for i in IDS],
                             actions=("Update:Replace", "Update:Delete")),
                       IDS) == g.GUARD_OPEN


def test_modify_replace_delete_triple_is_protected(g):
    """三个都点名 = 与 `Update:*` 语义等效（CFN stack policy 里 Update 只有这三个动作）。"""
    assert g.guard_for(_deny([f"LogicalResourceId/{i}" for i in IDS],
                             actions=("Update:Modify", "Update:Replace", "Update:Delete")),
                       IDS) == g.GUARD_PROTECTED


def test_condition_makes_it_unknown(g):
    """带 Condition 的 Deny 要求求值 ⇒ 本谓词不猜，返回 unknown。"""
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS],
                   Condition={"StringEquals": {"ResourceType": "AWS::Lambda::Function"}})
    assert g.guard_for(policy, IDS) == g.GUARD_UNKNOWN


def test_non_star_principal_is_unknown(g):
    policy = _deny([f"LogicalResourceId/{i}" for i in IDS])
    policy["Statement"][1]["Principal"] = {"AWS": "arn:aws:iam::123456789012:root"}
    assert g.guard_for(policy, IDS) == g.GUARD_UNKNOWN


def test_unparseable_policy_is_unknown(g):
    assert g.guard_for({"Statement": "not-a-list"}, IDS) == g.GUARD_UNKNOWN
    assert g.guard_for({}, IDS) == g.GUARD_UNKNOWN


def test_empty_logical_ids_is_unknown(g):
    """要保护的逻辑 ID 一个都没推出来时，"protected"是无意义的断言。"""
    assert g.guard_for(_deny(["*"]), []) == g.GUARD_UNKNOWN


def test_the_projects_own_policy_is_judged_protected(g, sp):
    """**跨谓词对账**：本项目 `build_policy()` 产出的那份策略必须被判成 `protected`。

    这比"两个文件里的 DENIED_ACTIONS 相等"更强也更对——那两个常量是**不同的东西**
    （`stack_policy.DENIED_ACTIONS` 是我们**写进**策略的动作列表，本模块的
    `CONCRETE_UPDATE_ACTIONS` 是"什么算拒绝 Update"的判据）。这条用例咬住的是它们
    语义相容：哪天 `build_policy` 改了写法而 guard 认不出来，闸门会把自己的保护读成
    "没保护"（`open`），于是一批 principal 凭空进冒充面。
    """
    logical = {cid: lid for (cid, _), lid in zip(sp.PROTECTED_CONSTRUCTS, IDS)}
    assert g.guard_for(sp.build_policy(logical), IDS) == g.GUARD_PROTECTED


def test_policy_problems_cannot_be_used_as_the_guard_predicate(g, sp):
    """把上面那条"更严格的 Deny-all"喂给 `policy_problems()`：它**非空**。
    这条用例把两个谓词的差别钉死——将来有人想"统一"就会在这里红。"""
    expected = sp.build_policy({cid: lid for (cid, _), lid
                                in zip(sp.PROTECTED_CONSTRUCTS, IDS)})
    problems = sp.policy_problems(_deny(["*"]), expected)
    assert problems, "policy_problems 认为 Deny-all 没问题？那两个谓词就该合并了"
    assert g.guard_for(_deny(["*"]), IDS) == g.GUARD_PROTECTED


def test_open_policy_from_the_project_is_judged_open(g, sp):
    """`router_stack_policy.py open` 写的那份（等于没有保护）必须判成 `open`——
    忘了 `apply` 的那个窗口里，闸门应当看到保护是开着的。"""
    assert g.guard_for(sp.OPEN_POLICY, IDS) == g.GUARD_OPEN
