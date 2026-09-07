"""`functions/function_url_policy.py`：期望集合、漂移判定、等值收敛（merged review M07）。

每条守卫先有正对照（一致 ⇒ 零写入）再有反例；反例覆盖 M07 点名的三种真实漂移：edge role 重建后
Principal 变成 `AROA…`、config 改错后修正、别的 Sid 下的额外授权。evidence: fake/unit。
"""
import ast
import json
from pathlib import Path

import pytest

import function_url_policy as fup
from fake_lambda_policy import FakeLambdaPolicy, good_pair, rendered

EDGE = "arn:aws:iam::000000000000:role/site-edge-role"
OTHER = "arn:aws:iam::000000000000:role/someone-else"
FN = "site-auth-service"


# ── 期望集合 ────────────────────────────────────────────────────────────────

def test_expected_statements_are_the_two_url_grants_bound_to_the_exact_edge_role():
    stmts = fup.expected_statements(EDGE)
    assert [s["StatementId"] for s in stmts] == list(fup.EXPECTED_SIDS) == ["edge-invoke", "edge-invoke-function"]
    by_action = {s["Action"]: s for s in stmts}
    assert set(by_action) == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}
    assert all(s["Principal"] == EDGE for s in stmts)
    assert by_action["lambda:InvokeFunctionUrl"]["FunctionUrlAuthType"] == "AWS_IAM" == fup.FUNCTION_URL_AUTH_TYPE
    assert by_action["lambda:InvokeFunction"]["InvokedViaFunctionUrl"] is True


@pytest.mark.parametrize("bad", ["", None, "   ", "*", "arn:aws:iam::000000000000:role/*", "site-edge-role"])
def test_missing_or_wildcard_edge_role_raises_instead_of_widening(bad):
    with pytest.raises(ValueError):
        fup.expected_statements(bad)


def test_rendered_condition_matches_the_aws_documented_shape():
    """`InvokedViaFunctionUrl` 渲染成 **Bool** 操作符 + 字符串 "true"（不是 StringEquals）——文档所述。"""
    proj = fup.expected_projection(EDGE)
    assert proj["edge-invoke"][3] == (("StringEquals", "lambda:FunctionUrlAuthType", "AWS_IAM"),)
    assert proj["edge-invoke-function"][3] == (("Bool", "lambda:InvokedViaFunctionUrl", "true"),)


# ── 漂移判定（纯函数）──────────────────────────────────────────────────────

def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def test_exact_policy_has_no_drift():
    """正对照：与文档形态逐字节相同 ⇒ ok。没有它，下面的红证明不了什么。"""
    d = fup.drift(_policy(*good_pair(EDGE)), EDGE)
    assert d.ok and d.summary() == "一致"


def test_string_equals_value_is_compared_case_sensitively():
    """IAM 的 StringEquals 大小写敏感：策略里若是 `aws_iam`，Edge 的调用会 403——判定不能把它折叠成一致（那是 fail-open）。
    Bool 那条仍按 AWS 的小写渲染归一（`True` 与 "true" 是同一个值）。"""
    ok, _ = good_pair(EDGE)
    bad = rendered("edge-invoke", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="aws_iam")
    d = fup.drift(_policy(bad, good_pair(EDGE)[1]), EDGE)
    assert tuple(d.mismatched) == ("edge-invoke",) and not d.missing and not d.stray
    upper_bool = rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url="True")
    assert fup.drift(_policy(ok, upper_bool), EDGE).ok


def test_no_policy_at_all_means_both_missing():
    d = fup.drift(None, EDGE)
    assert d.missing == fup.EXPECTED_SIDS and not d.mismatched and not d.stray


def test_principal_rewritten_to_a_deleted_role_id_is_a_mismatch():
    """edge role 被删后重建：IAM 把 Principal 改写成旧角色的唯一 ID——同名 Sid、内容已错。M07 的核心形态。"""
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    bad = [rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
           rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)]
    d = fup.drift(_policy(*bad), EDGE)
    assert d.mismatched == fup.EXPECTED_SIDS and not d.missing and not d.stray


@pytest.mark.parametrize("variant", [
    "other-principal", "account-root", "star", "no-condition", "wrong-auth-type", "deny",
    "string-equals-instead-of-bool", "missing-invoked-via",
])
def test_each_content_deviation_is_a_mismatch(variant):
    url = rendered("edge-invoke", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM")
    fn = rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True)
    if variant == "other-principal":
        url["Principal"] = {"AWS": OTHER}
    elif variant == "account-root":
        url["Principal"] = {"AWS": "arn:aws:iam::000000000000:root"}
    elif variant == "star":
        url["Principal"] = "*"
    elif variant == "no-condition":
        url.pop("Condition")
    elif variant == "wrong-auth-type":
        url["Condition"] = {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}
    elif variant == "deny":
        url["Effect"] = "Deny"
    elif variant == "string-equals-instead-of-bool":
        fn["Condition"] = {"StringEquals": {"lambda:InvokedViaFunctionUrl": "true"}}
    elif variant == "missing-invoked-via":
        fn.pop("Condition")
    d = fup.drift(_policy(url, fn), EDGE)
    assert d.mismatched and not d.missing and not d.stray, (variant, d)


def test_extra_statement_under_another_sid_is_stray():
    """只替换自己那两条清不掉别的 Sid 下塞进来的 `Principal:*`。"""
    d = fup.drift(_policy(*good_pair(EDGE), rendered("public-url", "lambda:InvokeFunctionUrl", "*",
                                                    function_url_auth_type="NONE")), EDGE)
    assert d.stray == ("public-url",) and not d.missing and not d.mismatched


def test_old_sid_names_are_stray_and_new_ones_missing():
    """panel / key-proxy 原来的 Sid（edge-invoke-url）：内容对、名字不对 ⇒ 一条野、一条缺（改名走"先加后删"）。"""
    old = [rendered("edge-invoke-url", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM"),
           rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True)]
    d = fup.drift(_policy(*old), EDGE)
    assert d.missing == ("edge-invoke",) and d.stray == ("edge-invoke-url",) and not d.mismatched


def test_a_statement_without_sid_is_reported_under_the_no_sid_marker():
    s = rendered("x", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")
    del s["Sid"]
    d = fup.drift(_policy(*good_pair(EDGE), s), EDGE)
    assert d.stray == (fup.NO_SID,)


def test_single_element_action_list_compares_equal_to_the_string():
    good = good_pair(EDGE)
    good[0]["Action"] = ["lambda:InvokeFunctionUrl"]
    assert fup.drift(_policy(*good), EDGE).ok


# ── 等值收敛 ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(fup, "_sleep", lambda s: None)


def test_matching_policy_is_read_once_and_never_written():
    """**重跑零写入**：幂等重部不得动线上任何一条语句（这是三个部署脚本天天跑的路径）。"""
    lam = FakeLambdaPolicy(good_pair(EDGE))
    before = fup.converge(lam, FN, EDGE)
    assert before.ok
    assert lam.calls == [("get_policy", None, None)]


def test_empty_policy_gets_both_statements_and_reads_back_clean():
    lam = FakeLambdaPolicy()
    before = fup.converge(lam, FN, EDGE)
    assert before.missing == fup.EXPECTED_SIDS
    assert [c[1] for c in lam.writes()] == ["edge-invoke", "edge-invoke-function"]
    assert fup.drift(json.loads(lam.get_policy(FunctionName=FN)["Policy"]), EDGE).ok


def test_deleted_role_principal_is_replaced_remove_then_add():
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    lam = FakeLambdaPolicy([
        rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
        rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)])
    before = fup.converge(lam, FN, EDGE)
    assert before.mismatched == fup.EXPECTED_SIDS
    removed = [c for c in lam.calls if c[0] == "remove_permission"]
    added = [c for c in lam.calls if c[0] == "add_permission"]
    assert {c[1] for c in removed} == set(fup.EXPECTED_SIDS) == {c[1] for c in added}
    assert lam.calls.index(removed[0]) < lam.calls.index(added[0]), "同名语句必须先删再加"
    principals = {s["Principal"]["AWS"] for s in lam.statements}
    assert principals == {EDGE}


def test_rename_adds_the_new_statement_before_removing_the_old_one():
    """改 Sid 名零窗口：新语句已生效才删旧的（先加后删）。同时 `Principal:*` 的野语句被清掉。"""
    lam = FakeLambdaPolicy([
        rendered("edge-invoke-url", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM"),
        rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True),
        rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
    before = fup.converge(lam, FN, EDGE)
    assert before.missing == ("edge-invoke",) and set(before.stray) == {"edge-invoke-url", "public-url"}
    writes = lam.writes()
    assert writes[0] == ("add_permission", "edge-invoke", None)
    assert {c[1] for c in writes[1:]} == {"edge-invoke-url", "public-url"}
    assert all(c[0] == "remove_permission" for c in writes[1:])
    assert {s["Sid"] for s in lam.statements} == set(fup.EXPECTED_SIDS)


def test_statement_without_sid_aborts_before_any_write():
    s = rendered("x", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")
    del s["Sid"]
    lam = FakeLambdaPolicy(good_pair(EDGE) + [s])
    with pytest.raises(fup.PolicyDriftError, match="没有 Sid"):
        fup.converge(lam, FN, EDGE)
    assert lam.writes() == []


def test_a_conflict_that_survives_one_replace_is_not_swallowed():
    """删了再加还冲突 ⇒ 抛（有别的东西在同时写这份 policy）。

    替身：add 永远冲突、remove 只记录不改状态——模拟"另一个 writer 在我删掉之后又立刻写回同名语句"。
    """
    class AlwaysConflict(FakeLambdaPolicy):
        def add_permission(self, **kw):
            self.calls.append(("add_permission", kw["StatementId"], kw.get("Qualifier")))
            raise self.exceptions.ResourceConflictException(kw["StatementId"])

        def remove_permission(self, FunctionName, StatementId, Qualifier=None):
            self.calls.append(("remove_permission", StatementId, Qualifier))
    lam = AlwaysConflict(good_pair(EDGE)[:1])          # 第二条缺 ⇒ 要加
    with pytest.raises(lam.exceptions.ResourceConflictException):
        fup.converge(lam, FN, EDGE)
    adds = [c for c in lam.calls if c[0] == "add_permission"]
    assert len(adds) == 2, "必须恰好尝试两次（加 → 删 → 再加），不多不少"


def test_readback_mismatch_after_writing_raises_instead_of_reporting_success():
    """**读回核对是 fail-closed 的落点**：AWS 渲染形态与假设不同时第一次真机部署就要在这里响亮失败。"""
    lam = FakeLambdaPolicy(drop_condition_on_add=True)
    with pytest.raises(fup.PolicyDriftError, match="读回仍不一致"):
        fup.converge(lam, FN, EDGE)
    assert len([c for c in lam.calls if c[0] == "get_policy"]) == 1 + fup._READBACK_ATTEMPTS


def test_qualifier_is_carried_on_every_call():
    """给将来 deploy_lambda_site 复用留的口：带 qualifier 时读、加、删都要带（授在函数上 ≠ 授在颜色上）。"""
    lam = FakeLambdaPolicy()
    fup.converge(lam, "site-s-1", EDGE, qualifier="blue")
    assert lam.calls and all(c[2] == "blue" for c in lam.calls), lam.calls


# ── 模块自身的边界 ──────────────────────────────────────────────────────────

def test_module_imports_no_boto3_and_reads_no_environment():
    """client 由调用方传入；本模块能在 auth 借用的 venv 里、也能在闸门脚本里 import 而不带任何 AWS 依赖。"""
    tree = ast.parse(Path(fup.__file__).read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert "boto3" not in imported and "botocore" not in imported and "os" not in imported, imported
