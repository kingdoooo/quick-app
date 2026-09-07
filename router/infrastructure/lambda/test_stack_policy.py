"""`stack_policy.py`（router 栈 stack policy 的声明 / 推导 / 比较）与 stack.py 的接线。

stack.py import aws_cdk（本 venv 没有），所以 synth 期守卫在这里用**假栈对象**验行为，
接线用源码 / AST 断言（与 test_stack_static.py 同一套做法）。模板 fixture 的资源清单照
`python3 stack.py` 离线 synth 出来的形态，哈希是假的。
"""
import ast
import importlib.util
import json
import re
from pathlib import Path

import pytest

INFRA = Path(__file__).parents[1]
STACK_SRC = (INFRA / "stack.py").read_text()


def _load():
    spec = importlib.util.spec_from_file_location("_stack_policy_under_test", INFRA / "stack_policy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load()
H = "AAAAAAAA"   # 假的 8 位路径哈希


def _template(**overrides):
    res = {
        f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::Table"},
        f"EdgeFunctionRole{H}": {"Type": "AWS::IAM::Role"},
        f"EdgeFunctionRoleDefaultPolicy{H}": {"Type": "AWS::IAM::Policy"},
        f"OriginRequestFunction{H}": {"Type": "AWS::Lambda::Function"},
        f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40: {"Type": "AWS::Lambda::Version"},
        f"OriginResponseFunction{H}": {"Type": "AWS::Lambda::Function"},
        f"OriginResponseFunctionCurrentVersion{H}" + "c" * 40: {"Type": "AWS::Lambda::Version"},
        f"OriginRequestPolicy{H}": {"Type": "AWS::CloudFront::OriginRequestPolicy"},
        f"Distribution{H}": {"Type": "AWS::CloudFront::Distribution"},
    }
    res.update(overrides)
    return {"Resources": {k: v for k, v in res.items() if v is not None}}


EXPECTED_IDS = {"OriginRequestFunction": f"OriginRequestFunction{H}",
                "OriginResponseFunction": f"OriginResponseFunction{H}",
                "Distribution": f"Distribution{H}",
                "SubdomainMappingTable": f"SubdomainMappingTable{H}"}


# ---- 推导 ----------------------------------------------------------------------------------

def test_protected_logical_ids_picks_exactly_the_four_l1_resources():
    assert sp.protected_logical_ids(_template()) == EXPECTED_IDS


@pytest.mark.parametrize("mutate, needle", [
    ({f"Distribution{H}": None}, "Distribution: 期望恰好 1"),
    ({f"Distribution{'B' * 8}": {"Type": "AWS::CloudFront::Distribution"}}, "Distribution: 期望恰好 1"),
    ({f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::GlobalTable"}}, "Type 是 'AWS::DynamoDB::GlobalTable'"),
    ({"OriginRequestFunction": {"Type": "AWS::Lambda::Function"}, f"OriginRequestFunction{H}": None},
     "OriginRequestFunction: 期望恰好 1"),
], ids=["missing", "ambiguous", "wrong-type", "no-hash"])
def test_missing_ambiguous_or_mistyped_protected_resource_is_named(mutate, needle):
    with pytest.raises(sp.StackPolicyError, match=re.escape(needle)):
        sp.protected_logical_ids(_template(**mutate))


def test_version_resources_never_match_the_function_pattern():
    """`…CurrentVersion<8hex><40hex>` 与 `OriginRequestFunction<8hex>` 前缀相同——不锚 `$` 就多义。"""
    pat = sp.logical_id_pattern("OriginRequestFunction")
    assert pat.match(f"OriginRequestFunction{H}")
    assert not pat.match(f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40)
    assert not pat.match(f"OriginRequestFunction{H.lower()}"), "CDK 的路径哈希是大写"


# ---- 策略体 --------------------------------------------------------------------------------

def test_build_policy_allows_everything_then_denies_only_exact_ids():
    pol = sp.build_policy(EXPECTED_IDS)
    allows = [s for s in pol["Statement"] if s["Effect"] == "Allow"]
    denies = [s for s in pol["Statement"] if s["Effect"] == "Deny"]
    assert allows == [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}], \
        "stack policy 默认全拒：缺 Allow 会冻住整栈"
    assert len(denies) == 1 and denies[0]["Principal"] == "*"
    assert denies[0]["Action"] == list(sp.DENIED_ACTIONS)
    assert sorted(denies[0]["Resource"]) == sorted(f"LogicalResourceId/{v}" for v in EXPECTED_IDS.values())
    assert not any("*" in r for r in denies[0]["Resource"])
    json.dumps(pol)


def test_build_policy_refuses_a_partial_id_map():
    with pytest.raises(sp.StackPolicyError, match="Distribution"):
        sp.build_policy({k: v for k, v in EXPECTED_IDS.items() if k != "Distribution"})


def test_denied_actions_pin_the_d1_ruling():
    """决策门 D1：`Update:*`（含 Modify）。只拒 Replace/Delete 拦不住 Edge 换码，改这里必须是刻意的。"""
    assert sp.DENIED_ACTIONS == ("Update:*",)


# ---- 比较 ----------------------------------------------------------------------------------

def test_policy_problems_positive_control_accepts_reordered_equivalents():
    exp = sp.build_policy(EXPECTED_IDS)
    same = {"Statement": [exp["Statement"][1], {**exp["Statement"][0], "Action": ["Update:*"]}]}
    assert sp.policy_problems(exp, exp) == []
    assert sp.policy_problems(same, exp) == []


_ALL = [f"LogicalResourceId/{v}" for v in EXPECTED_IDS.values()]


@pytest.mark.parametrize("actual, needle", [
    (None, "没有 stack policy"),
    (sp.OPEN_POLICY, f"覆盖 LogicalResourceId/Distribution{H}"),
    ({"Statement": [dict(sp.ALLOW_ALL_STATEMENT),
                    {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}, "通配"),
    ({"Statement": [{"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": _ALL}]}, "没有 Allow 语句"),
    ({"Statement": [dict(sp.ALLOW_ALL_STATEMENT),
                    {"Effect": "Deny", "Action": ["Update:Replace", "Update:Delete"], "Principal": "*", "Resource": _ALL}]},
     "覆盖 LogicalResourceId/OriginRequestFunction"),
], ids=["none", "open", "wildcard", "deny-only", "replace-delete-only"])
def test_policy_problems_negative_controls_name_the_defect(actual, needle):
    problems = sp.policy_problems(actual, sp.build_policy(EXPECTED_IDS))
    assert problems and any(needle in p for p in problems), problems


# ---- synth 期守卫（假栈对象；真 CDK 对象上的行为由 stack.py 每次 synth 顺带证明）------------------

class _Node:
    def __init__(self, children=None, default_child=None):
        self._children, self.default_child = children or {}, default_child

    def try_find_child(self, cid):
        return self._children.get(cid)


class _Cfn:
    def __init__(self, rtype, lid):
        self.cfn_resource_type, self.lid = rtype, lid


class _Construct:
    def __init__(self, cfn):
        self.node = _Node(default_child=cfn)


class _Stack:
    def __init__(self, table):   # cid -> (rtype, logical id)
        self.node = _Node({cid: _Construct(_Cfn(rt, lid)) for cid, (rt, lid) in table.items()})

    def get_logical_id(self, cfn):
        return cfn.lid


def _good():
    return {cid: (rt, f"{cid}{H}") for cid, rt in sp.PROTECTED_CONSTRUCTS}


def test_synth_guard_accepts_a_matching_stack_and_returns_the_ids():
    assert sp.assert_protected_constructs(_Stack(_good())) == EXPECTED_IDS


@pytest.mark.parametrize("mutate, needle", [
    (lambda t: t.pop("Distribution"), "Distribution: 栈里没有这个 construct"),
    (lambda t: t.__setitem__("SubdomainMappingTable", ("AWS::DynamoDB::GlobalTable", f"SubdomainMappingTable{H}")),
     "L1 类型是 'AWS::DynamoDB::GlobalTable'"),
    (lambda t: t.__setitem__("OriginRequestFunction", ("AWS::Lambda::Function", "OriginRequestFunction")), "不符合"),
], ids=["renamed", "wrong-type", "overridden-id"])
def test_synth_guard_fails_loudly_on_each_drift(mutate, needle):
    t = _good()
    mutate(t)
    with pytest.raises(sp.StackPolicyError, match=re.escape(needle)):
        sp.assert_protected_constructs(_Stack(t))


def test_stack_policy_module_is_stdlib_only():
    """三处调用方里两处没有 aws_cdk，宿主 python3 那处 import 期也不该需要 boto3。"""
    tree = ast.parse((INFRA / "stack_policy.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= {"json", "re", "typing", "__future__"}, names


# ---- stack.py 的接线（源码 / AST）--------------------------------------------------------------

def test_stack_imports_and_calls_the_synth_guard_after_the_distribution_exists():
    assert "from stack_policy import assert_protected_constructs" in STACK_SRC
    body = STACK_SRC[STACK_SRC.index("class WebRouterStack"):]
    call = body.index("assert_protected_constructs(self)")
    assert body.index('"Distribution",') < call, "守卫跑在分发创建之前 = 永远报缺"
    assert call < body.index("# Outputs"), "守卫放在写 Outputs 之前（Outputs 不是资源，晚了没意义）"


def test_every_protected_construct_id_is_a_constructor_id_in_stack_py():
    """PROTECTED_CONSTRUCTS 里的 construct ID 必须与 stack.py 构造时传的第二个位置参数逐字相同。"""
    tree = ast.parse(STACK_SRC)
    ids = {n.args[1].value for n in ast.walk(tree)
           if isinstance(n, ast.Call) and len(n.args) >= 2
           and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)}
    missing = [cid for cid, _ in sp.PROTECTED_CONSTRUCTS if cid not in ids]
    assert not missing, f"stack.py 里没有这些 construct ID：{missing}（AST 找到的：{sorted(ids)}）"
