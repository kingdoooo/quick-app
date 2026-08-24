"""账号信任边界闸门（`scripts/verify_account_trust_boundary.py`）的纯函数部分。

这个闸门盯的是 M09：账号里**除 Edge 与部署器之外**还有谁能 direct invoke 平台/
站点 Lambda、谁能读到 HS256 会话密钥、谁能替换平台代码。集合本身**关不掉**
（见 `docs/security/account-trust-boundary.md`），闸门的职责是"别再长"——
所以它的正确性全在四件事上，每件都要能红：

① **逐资源判定**。`SimulatePrincipalPolicy` 传多个 `ResourceArns` 时，顶层
   `EvalDecision` 是聚合项、顶层 `EvalResourceName` 是 `${Region}` 这样的 ARN
   模板；真值在 `ResourceSpecificResults` 里。只读顶层会把"对哪个函数 allowed"
   读成"对所有函数 allowed"——2026-08-25 首次实测就踩了这个坑，本轮把它入仓。
② **新增即红**。新 principal、或已知 principal 长出新能力，都必须红。
③ **正向控制丢失也要红**。Edge 角色必须仍能 invoke（丢了 = 全站 403）、
   部署器 exec 角色必须仍能 invoke 站点函数（丢了 = blue/green 健康门每次都断）。
   这条防的是"收窄"把平台自己锁死——那种失败只在真机部署时才看得见。
④ **基线文件不许含账号值**。仓库红线：真实账号 ID / 角色名不进被跟踪文件。
   基线只存 ARN 的指纹，所以 3 个 CDK cfn-exec 角色（名字里嵌着账号 ID）
   也能被盯住而不泄值。
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_SCRIPT = _ROOT / "site-builder" / "scripts" / "verify_account_trust_boundary.py"
_BASELINE = _ROOT / "site-builder" / "scripts" / "account_trust_baseline.json"
_DOC = _ROOT / "docs" / "security" / "account-trust-boundary.md"


def _gate():
    spec = importlib.util.spec_from_file_location("_vatb", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vatb"] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# ① 逐资源判定
# --------------------------------------------------------------------------

def _multi_resource_response(action="lambda:InvokeFunction"):
    """一条真实形态的多资源响应：顶层是聚合项（`allowed` + ARN 模板），
    逐资源里一个 allowed 一个 implicitDeny。"""
    return [{
        "EvalActionName": action,
        "EvalResourceName": "arn:aws:lambda:${Region}:${Account}:${ResourceType}:${ResourceId}",
        "EvalDecision": "allowed",
        "ResourceSpecificResults": [
            {"EvalResourceName": "arn:aws:lambda:us-east-1:1:function:site-panel",
             "EvalResourceDecision": "implicitDeny"},
            {"EvalResourceName": "arn:aws:lambda:us-east-1:1:function:site-notes-aaa",
             "EvalResourceDecision": "allowed"},
        ],
    }]


def test_decisions_are_read_per_resource_not_from_the_aggregate():
    """顶层说 allowed、逐资源说 site-panel 是 implicitDeny —— 必须以逐资源为准。

    只读顶层的实现会让这条红：它会给出「对 site-panel allowed」。
    """
    g = _gate()
    decisions = g.decisions_from_simulation(_multi_resource_response())
    assert decisions == {
        "lambda:InvokeFunction|arn:aws:lambda:us-east-1:1:function:site-panel": "implicitDeny",
        "lambda:InvokeFunction|arn:aws:lambda:us-east-1:1:function:site-notes-aaa": "allowed",
    }, "读的不是 ResourceSpecificResults —— 「对哪个函数 allowed」会被读错"


def test_arn_template_never_becomes_a_decision_key():
    """`${Region}` 那个模板串不能进结果——它一旦进去，后面按 ARN 归类的
    每一步都会拿到一个不存在的资源，且看起来像「对全部资源 allowed」。"""
    g = _gate()
    decisions = g.decisions_from_simulation(_multi_resource_response())
    assert not any("${" in k for k in decisions), decisions


def test_single_resource_response_still_works():
    """单资源时 AWS 也照样给 ResourceSpecificResults；但即便某天只给顶层，
    也不能静默丢掉这条判定。"""
    g = _gate()
    decisions = g.decisions_from_simulation([{
        "EvalActionName": "ssm:GetParameter",
        "EvalResourceName": "arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret",
        "EvalDecision": "allowed",
    }])
    assert decisions == {
        "ssm:GetParameter|arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret": "allowed"
    }


# --------------------------------------------------------------------------
# ② 新增即红 / ⑤ 改善不算失败
# --------------------------------------------------------------------------

def _observed(**principals):
    """{name: caps} → 闸门内部形态 {fingerprint: {name, caps}}。"""
    g = _gate()
    out = {}
    for name, caps in principals.items():
        arn = f"arn:aws:iam::1:role/{name}"
        out[g.principal_fingerprint(arn)] = {"name": name, "arn": arn,
                                            "capabilities": sorted(caps)}
    return out


def _baseline_of(observed):
    return {"schema": 1,
            "principals": {fp: {"category": "unrelated-workload",
                                "capabilities": p["capabilities"]}
                           for fp, p in observed.items()}}


REQUIRED = {"edge": "EdgeRole", "deployer": "site-deployer-exec-role"}


def _with_required(observed):
    """把两条正向控制补进 observed，让用例只测想测的那一条。"""
    return {**observed,
            **_observed(EdgeRole=["invoke-platform", "invoke-site"]),
            **_observed(**{"site-deployer-exec-role": ["invoke-site"]})}


def test_new_principal_is_a_failure():
    g = _gate()
    base = _with_required(_observed(WorkloadA=["invoke-platform"]))
    now = _with_required(_observed(WorkloadA=["invoke-platform"],
                                   WorkloadB=["invoke-platform"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert "WorkloadB" in rep.render()


def test_known_principal_gaining_a_capability_is_a_failure():
    """同一个 principal 从「只能 invoke」变成「还能读会话密钥」——这一步
    把读面失守升级成写面失守（同一个 `/site-builder/jwt-secret` 也签
    `__Host-sb_console`），所以不能只比 principal 集合。"""
    g = _gate()
    base = _with_required(_observed(WorkloadA=[g.CAP_INVOKE_PLATFORM]))
    now = _with_required(_observed(
        WorkloadA=[g.CAP_INVOKE_PLATFORM, g.CAP_READ_EDGE_CODE]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert g.CAP_READ_EDGE_CODE in rep.render()


def test_two_secret_paths_are_separate_capabilities():
    """读密钥的两条路必须分开记：`lambda:GetFunction` 拿到的是 Edge 产物里的
    **明文**（不经 KMS），`ssm:GetParameter` 是另一条。合成一项就看不出
    「只给了只读权限的身份也能拿到密钥」这件事。"""
    g = _gate()
    t = g.Targets(platform_functions=("arn:fn:panel",), site_functions=("arn:fn:site",),
                  edge_function="arn:fn:edge", jwt_parameter="arn:param:jwt",
                  any_role="arn:role:*")
    only_code = g.capabilities_from_decisions(
        {"lambda:GetFunction|arn:fn:edge": "allowed"}, t)
    only_param = g.capabilities_from_decisions(
        {"ssm:GetParameter|arn:param:jwt": "allowed"}, t)
    assert only_code == {g.CAP_READ_EDGE_CODE}
    assert only_param == {g.CAP_READ_JWT_PARAM}


def test_shrinking_is_reported_but_not_a_failure():
    g = _gate()
    base = _with_required(_observed(WorkloadA=["invoke-platform"],
                                    WorkloadB=["invoke-platform"]))
    now = _with_required(_observed(WorkloadA=["invoke-platform"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert rep.ok, rep.render()
    assert rep.improvements, "集合缩小了却没被报出来——那基线永远不会被更新"


# --------------------------------------------------------------------------
# ③ 正向控制
# --------------------------------------------------------------------------

@pytest.mark.parametrize("lost", ["edge", "deployer"])
def test_losing_a_required_allow_is_a_failure(lost):
    """收窄动作把 Edge 或部署器一起砍掉时必须红。

    这两条的真机症状分别是「全站 403」与「每次部署在健康门失败」，
    都不会在任何单测里出现。
    """
    g = _gate()
    keep = dict(REQUIRED)
    base = _with_required({})
    now = _with_required({})
    del now[g.principal_fingerprint(f"arn:aws:iam::1:role/{keep[lost]}")]
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert keep[lost] in rep.render()


def test_required_principal_present_but_without_invoke_is_a_failure():
    """Edge 角色还在、但 invoke 被收掉了——比「角色消失」更常见的形态
    （收窄改的是策略，不是角色）。"""
    g = _gate()
    base = _with_required({})
    now = {**_observed(EdgeRole=["read-session-secret"]),
           **_observed(**{"site-deployer-exec-role": ["invoke-site"]})}
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert "EdgeRole" in rep.render()


# --------------------------------------------------------------------------
# ④ 基线文件不许含账号值
# --------------------------------------------------------------------------

def test_baseline_carries_no_account_values():
    """仓库红线：真实账号 ID / 角色名不进被跟踪文件。

    基线里 3 个 CDK cfn-exec 角色的名字**内嵌账号 ID**，所以这条不是形式主义:
    照抄角色名就会把账号值提交进仓库。
    """
    raw = _BASELINE.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{12}\b", raw), "基线里出现了 12 位账号 ID"
    for forbidden in ("arn:aws:", "role/", "cdk-hnb659fds", "Isengard"):
        assert forbidden not in raw, f"基线里出现了 {forbidden!r}——那是账号内的真实标识"
    data = json.loads(raw)
    for fp in data["principals"]:
        assert re.fullmatch(r"[0-9a-f]{16}", fp), f"{fp!r} 不是指纹形态"


def test_fingerprint_is_one_way_and_stable():
    g = _gate()
    # 占位账号用 000000000000（仓库既有约定，secret scanner 的预期命中之一），
    # 形态刻意照抄那类**名字里嵌着账号 ID** 的角色——它正是基线不能存原名的原因。
    arn = "arn:aws:iam::000000000000:role/cdk-hnb659fds-cfn-exec-role-000000000000-us-east-1"
    fp = g.principal_fingerprint(arn)
    assert re.fullmatch(r"[0-9a-f]{16}", fp)
    assert "000000000000" not in fp
    assert fp == g.principal_fingerprint(arn), "指纹不稳定，基线每次跑都会全量漂移"
    assert fp != g.principal_fingerprint(arn.replace("us-east-1", "us-west-2"))


# --------------------------------------------------------------------------
# 文档与基线不许各说一套
# --------------------------------------------------------------------------

def test_doc_counts_come_from_the_baseline():
    """风险模型文档里的四个数必须与基线文件算出来的一致。

    这条防的是文档腐烂：基线更新了而文档还写着旧数字时，读文档的人会以为
    集合没变——而"集合别再长"正是这个闸门存在的唯一理由。

    断言的形态是 `<数字> <!-- baseline:标签=<数字> -->`：**正文里显示的那个数字
    必须紧挨着标记**。只校验标记的话，标记与正文可以各写一个数，那就白防了。
    """
    g = _gate()
    principals = json.loads(_BASELINE.read_text(encoding="utf-8"))["principals"]
    secret_caps = set(g.SECRET_CAPS)
    invoke = {g.CAP_INVOKE_PLATFORM, g.CAP_INVOKE_SITE}

    def count(pred):
        return sum(1 for p in principals.values() if pred(p))

    expected = {
        "总数": len(principals),
        "可读密钥": count(lambda p: secret_caps & set(p["capabilities"])),
        "非平台可直调": count(lambda p: p["category"] != "platform"
                              and invoke & set(p["capabilities"])),
        "无关工作负载": count(lambda p: p["category"] == "unrelated-workload"),
    }
    doc = _DOC.read_text(encoding="utf-8")
    for label, n in expected.items():
        needle = f"{n} <!-- baseline:{label}={n} -->"
        assert needle in doc, (
            f"文档里 {label} 与基线不符（基线算出 {n}，期望正文出现 {needle!r}）"
            f"——更新基线时必须同步文档，否则两处各说一套")


def test_no_unclassified_principal_in_baseline():
    """基线里不许留 unclassified：类别决定了「这条是既定信任模型还是暴露面」，
    留空就等于把判断推给下一个读文档的人，而上面那条文档计数会跟着失真。"""
    principals = json.loads(_BASELINE.read_text(encoding="utf-8"))["principals"]
    unlabeled = [fp for fp, p in principals.items()
                 if p.get("category") in (None, "", "unclassified")]
    assert not unlabeled, f"这些指纹还没标 category：{unlabeled}"
