"""账号信任边界闸门（`scripts/verify_account_trust_boundary.py`）的纯函数部分。

这个闸门盯的是 M09：账号里**除 Edge 与部署器之外**还有谁能 direct invoke 平台/
站点 Lambda、谁能取得 HS256 会话密钥、谁能替换平台代码。集合本身**关不掉**
（见 `docs/security/account-trust-boundary.md`），闸门的职责是"别再长"——
所以它的正确性全在下面这些能红的用例上：

① **逐资源判定**。`SimulatePrincipalPolicy` 传多个 `ResourceArns` 时，顶层
   `EvalDecision` 是聚合项、顶层 `EvalResourceName` 是 `${Region}` 这样的 ARN
   模板；真值在 `ResourceSpecificResults` 里。只读顶层会把"对哪个函数 allowed"
   读成"对所有函数 allowed"——2026-08-25 首次实测就踩了这个坑。
② **授权不能压成布尔标签**。`invoke-platform:site-panel` 与
   `invoke-platform:site-deployer-undeploy` 必须是两条不同的 grant：压成一个
   `invoke-platform` 布尔时，「原来只能调 undeploy、现在还能调 panel」这种
   **资源扩权**会静静地绿，而那正是 panel 读面失守的分界（Codex 复审 P1-2）。
③ **resource policy 是另一条授权通道**。`SimulatePrincipalPolicy` 不自动纳入它，
   而同账号 resource-based Allow 单独即可授权 ⇒ 新增一条 `AddPermission`
   必须被咬住。**alias 上那份不能漏**：M7 之后站点的 Function URL 与其授权语句都
   挂在 `blue` 上，只读未限定那份等于没看见真实的 invoke 授权面。站点函数用
   「一组合法形态 + 偏离项」覆盖（两种部署形态都合法），新建站点不产生漂移。
④ **正向控制丢失也要红**。Edge 角色必须仍能 invoke（丢了 = 全站 403）、
   部署器 exec 角色必须仍能 invoke 站点函数（丢了 = blue/green 健康门每次都断）。
   这条防的是"收窄"把平台自己锁死——那种失败只在真机部署时才看得见。
⑤ **基线文件不许含账号值**。仓库红线：真实账号 ID / 角色名不进被跟踪文件。
   基线只存指纹，所以 CDK bootstrap 那几个**名字里嵌着账号 ID**的角色
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

# 指纹形态：每 4 位十六进制一组。分组是**必需的**——裸 16 位十六进制里会偶然出现
# 12 位连续数字，而 `scan_staged_secrets.sh` 按 `[0-9]{12}` 找账号 ID，于是每次更新
# 基线都命中一次假阳性；反复的假阳性会训练出无脑 `--allow-hits`。
_FP_RE = r"[0-9a-f]{4}(-[0-9a-f]{4}){3}"


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
    g = _gate()
    decisions = g.decisions_from_simulation([{
        "EvalActionName": "ssm:GetParameter",
        "EvalResourceName": "arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret",
        "EvalDecision": "allowed",
    }])
    assert decisions == {
        "ssm:GetParameter|arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret": "allowed"
    }


def test_missing_context_is_surfaced_not_swallowed():
    """带 Condition 的策略缺上下文时，判定只是**下界**。

    脚本不补 `ContextEntries`（补不全），但必须把"这里有不确定"报出来——
    把未知静默压成"没有权限"就不能叫安全闸门了。
    """
    g = _gate()
    assert g.missing_context_in([{"EvalActionName": "s3:GetObject",
                                  "EvalDecision": "implicitDeny",
                                  "MissingContextValues": ["aws:SourceVpc"]}])
    assert not g.missing_context_in([{"EvalActionName": "s3:GetObject",
                                      "EvalDecision": "allowed",
                                      "MissingContextValues": []}])


# --------------------------------------------------------------------------
# grant 粒度（Codex 复审 P1-2 的三个反例）
# --------------------------------------------------------------------------

def _targets(g, *, platform=("site-panel", "site-deployer-undeploy"),
             sites=("site-a", "site-b"), asset="arn:aws:s3:::assets/edge.zip"):
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    return g.Targets(
        platform_functions=tuple(fn(n) for n in platform),
        site_functions=tuple(fn(n) for n in sites),
        edge_function=fn("edge"),
        edge_asset=asset,
        jwt_parameter="arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret",
        any_role="arn:aws:iam::1:role/*")


def test_invoke_grants_name_the_platform_function():
    """**Codex 构造的那个最小变形**：某角色原来只能 invoke undeploy，
    现在还能 invoke panel。压成布尔 `invoke-platform` 时两次都是同一个标签、
    闸门全绿；按函数名记才会红。"""
    g = _gate()
    t = _targets(g)
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    before = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-deployer-undeploy')}": "allowed"}, t)
    after = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-deployer-undeploy')}": "allowed",
         f"lambda:InvokeFunction|{fn('site-panel')}": "allowed"}, t)
    assert before == {"invoke-platform:site-deployer-undeploy"}
    assert after - before == {"invoke-platform:site-panel"}, \
        "扩权没有产生新 grant——基线会把资源扩权读成「没变化」"


def test_gaining_invoke_on_another_platform_function_is_a_failure():
    """同一个变形走完整条比对链：必须红，且报文里点出 panel。"""
    g = _gate()
    base = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-deployer-undeploy"]))
    now = _with_required(g, _observed(g, WorkloadA=[
        "invoke-platform:site-deployer-undeploy", "invoke-platform:site-panel"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert "site-panel" in rep.render()


def test_site_grants_are_aggregated_so_new_sites_do_not_drift():
    """站点函数按类聚合：全量就是 `all`，加一个站点不改变这条 grant。

    逐个记站点函数名会让每次建站都把基线拽红，于是基线被迫频繁重写——
    那等于让"新增即红"这条失效。
    """
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    t2 = _targets(g, sites=("site-a", "site-b"))
    t3 = _targets(g, sites=("site-a", "site-b", "site-c"))
    all2 = {f"lambda:InvokeFunction|{fn(n)}": "allowed" for n in ("site-a", "site-b")}
    all3 = {f"lambda:InvokeFunction|{fn(n)}": "allowed"
            for n in ("site-a", "site-b", "site-c")}
    assert g.grants_from_decisions(all2, t2) == {"invoke-site:all"}
    assert g.grants_from_decisions(all3, t3) == {"invoke-site:all"}


def test_site_subset_records_the_count_so_widening_reds():
    """子集形态记数量：从 1 个站点扩到 2 个必须是不同的 grant。"""
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    t = _targets(g, sites=("site-a", "site-b", "site-c"))
    one = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-a')}": "allowed"}, t)
    two = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-a')}": "allowed",
         f"lambda:InvokeFunction|{fn('site-b')}": "allowed"}, t)
    assert one == {"invoke-site:some(1)"}
    assert two == {"invoke-site:some(2)"}
    assert one != two


def test_three_secret_paths_are_separate_grants():
    """读密钥的三条路必须分开记：Edge 函数产物、**CDK bootstrap S3 asset**、
    SSM 参数。合成一项就看不出「只给了 S3 只读的身份也能拿到密钥」这件事
    ——那正是 2026-08-25 复审补上的第三条路（21 个 principal 只在这条路上）。"""
    g = _gate()
    t = _targets(g)
    only_code = g.grants_from_decisions(
        {f"lambda:GetFunction|{t.edge_function}": "allowed"}, t)
    only_asset = g.grants_from_decisions(
        {f"s3:GetObject|{t.edge_asset}": "allowed"}, t)
    only_param = g.grants_from_decisions(
        {f"ssm:GetParameter|{t.jwt_parameter}": "allowed"}, t)
    assert only_code == {g.G_READ_EDGE_CODE}
    assert only_asset == {g.G_READ_EDGE_ASSET}
    assert only_param == {g.G_READ_JWT_PARAM}
    assert len({g.G_READ_EDGE_CODE, g.G_READ_EDGE_ASSET, g.G_READ_JWT_PARAM}) == 3


def test_asset_grant_disappears_when_the_asset_no_longer_carries_the_key():
    """根治之后（asset 里不再有明文密钥），这条 grant 必须自己消失。

    `Targets.edge_asset=None` 表示"实测过、那份产物已不含活密钥"。
    这条保证闸门是在**测事实**而不是复读一个写死的假设。
    """
    g = _gate()
    t = _targets(g, asset=None)
    grants = g.grants_from_decisions({"s3:GetObject|arn:aws:s3:::assets/edge.zip": "allowed"}, t)
    assert g.G_READ_EDGE_ASSET not in grants


def test_secret_detection_reads_python_inside_the_zip():
    """`secret_in_zip_bytes` 是"产物里还有没有活密钥"的判据本体。

    正对照 + 负对照都要有：只有正对照时，一个永远返回 True 的实现也会绿，
    于是"根治了闸门自己知道"这条性质是假的。
    """
    import io
    import zipfile
    g = _gate()

    def zbytes(src: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("index.py", src)
        return buf.getvalue()

    live = "a" * 64
    assert g.secret_in_zip_bytes(zbytes(f'JWT_SECRET = "{live}"'), live)
    assert not g.secret_in_zip_bytes(zbytes('JWT_SECRET = "{{JWT_SECRET}}"'), live)
    assert not g.secret_in_zip_bytes(b"not a zip at all", live)


# --------------------------------------------------------------------------
# ③ resource policy
# --------------------------------------------------------------------------

_EDGE_STMT = {"Sid": "edge-invoke", "Effect": "Allow",
              "Principal": {"AWS": "arn:aws:iam::000000000000:role/EdgeRole"},
              "Action": "lambda:InvokeFunctionUrl",
              "Resource": "arn:aws:lambda:us-east-1:000000000000:function:{fn}"}


def _policies(fns, extra_on=None, qualifier=None):
    """`{函数名: [(qualifier, 语句)…]}`——真机形态：M7 之后语句挂在 alias 上。"""
    out = {}
    for fn in fns:
        res = _EDGE_STMT["Resource"].format(fn=fn)
        if qualifier:
            res = f"{res}:{qualifier}"
        stmts = [(qualifier, {**_EDGE_STMT, "Resource": res})]
        if extra_on == fn:
            stmts.append((qualifier, {
                "Sid": "oops", "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:role/Rogue"},
                "Action": "lambda:InvokeFunction", "Resource": res}))
        out[fn] = stmts
    return out


def _snap(g, sites=(), platform=(), extra_on=None, qualifier=None):
    return g.resource_policy_snapshot(
        _policies(tuple(sites) + tuple(platform), extra_on=extra_on,
                  qualifier=qualifier),
        account="000000000000", platform=tuple(platform), sites=tuple(sites))


def test_site_resource_policies_share_one_canonical_fingerprint():
    """每个站点函数的 `edge-invoke` 语句只在"函数自己的 ARN"上不同 ⇒
    归一化后必须得到**同一个**指纹，否则规范形态无从建立、每建一个站点都漂移。"""
    g = _gate()
    sites = ("site-a", "site-b", "site-c")
    snap = _snap(g, sites=sites)
    assert len({tuple(v) for v in snap["sites"].values()}) == 1
    assert len(g.site_policy_shapes(snap["sites"])) == 1


def test_shapes_are_enumerated_not_unioned():
    """形态是**枚举**出来的，不是并起来的。

    并集会把最宽松的那个站点当成"规范"（于是规矩的站点被报成偏离——早先版本的
    真实缺陷）。这里三个站点里有一个多一条语句 ⇒ 必须得到**两种**形态，
    且干净那种排在前面（出现次数多）。
    """
    g = _gate()
    snap = _snap(g, sites=("site-a", "site-b", "site-c"), extra_on="site-c")
    shapes = g.site_policy_shapes(snap["sites"])
    assert len(shapes) == 2, f"形态没被分开：{shapes}"
    assert len(shapes[0]) == 1 and len(shapes[1]) == 2, shapes
    assert set(shapes[0]) < set(shapes[1]), "干净形态不是脏形态的子集，归一化有问题"


def test_both_deployment_shapes_are_accepted_together():
    """M7 之后两种站点形态都合法：迁移来的站点有未限定 policy，新建的只有 alias。
    基线记下两种形态，两类站点都不该被报成偏离——否则闸门首跑就红在架构差异上。"""
    g = _gate()
    legacy = _snap(g, sites=("site-old",))["sites"]
    modern = _snap(g, sites=("site-new",), qualifier="blue")["sites"]
    both = {**legacy, **modern}
    shapes = g.site_policy_shapes(both)
    assert len(shapes) == 2, f"两种部署形态没被分别记下：{shapes}"
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {}, "site_shapes": shapes}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies={"platform": {}, "sites": both})
    assert rep.ok, rep.render()


def test_alias_scoped_statement_is_not_the_same_as_unqualified():
    """挂在 `blue` 上与挂在未限定函数上是两种**不同宽度**的授权，
    指纹必须不同——归一化时把 alias 名抹掉就会把它们混成一个。"""
    g = _gate()
    unqualified = _snap(g, sites=("site-a",))["sites"]["site-a"]
    on_alias = _snap(g, sites=("site-a",), qualifier="blue")["sites"]["site-a"]
    assert unqualified != on_alias


def test_extra_statement_on_one_site_function_is_an_outlier():
    """某个站点函数多出一条语句（有人手工 `AddPermission`）→ 必须红并点名它。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"))
    dirty = _snap(g, sites=("site-a", "site-b"), extra_on="site-b")
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {},
                    "site_shapes": g.site_policy_shapes(clean["sites"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=dirty)
    assert not rep.ok
    assert "site-b" in rep.render() and "多出语句" in rep.render()


def test_site_missing_a_known_statement_is_also_flagged():
    """反方向：某个站点函数**少**了规范语句——它已经无法经 Edge 访问了。
    这条不是安全扩权而是功能损坏，但同样属于"投影与真源不一致"，要红。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"))
    stripped = {"platform": {}, "sites": {**clean["sites"], "site-b": []}}
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {},
                    "site_shapes": g.site_policy_shapes(clean["sites"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=stripped)
    assert not rep.ok
    assert "缺语句" in rep.render()


def test_new_site_with_the_standard_policy_does_not_drift():
    """新建站点若是标准形态，必须**不**红——否则每次建站都要改基线，
    而"新增即红"这条就被迫失效了。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"))
    grown = _snap(g, sites=("site-a", "site-b", "site-c"))
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {},
                    "site_shapes": g.site_policy_shapes(clean["sites"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=grown)
    assert rep.ok, rep.render()


def test_new_statement_on_a_platform_function_is_a_failure():
    """给 panel 的 resource policy 新加一条 Allow —— `SimulatePrincipalPolicy`
    看不见这条通道（AWS 契约：它不自动纳入 resource policy，且对 role 根本不支持
    模拟 resource policy），所以只有这份快照能咬住它。"""
    g = _gate()
    before = _snap(g, platform=("site-panel",))
    after = _snap(g, platform=("site-panel",), extra_on="site-panel")
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": before["platform"],
                                      "site_shapes": []}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=after)
    assert not rep.ok
    assert "site-panel" in rep.render()


# --------------------------------------------------------------------------
# ② 新增即红 / 改善不算失败
# --------------------------------------------------------------------------

def _observed(g, **principals):
    """{name: grants} → 闸门内部形态 {fingerprint: {name, grants}}。"""
    out = {}
    for name, grants in principals.items():
        arn = f"arn:aws:iam::1:role/{name}"
        out[g.principal_fingerprint(arn)] = {"name": name, "arn": arn,
                                             "kind": "role",
                                             "grants": sorted(grants)}
    return out


def _baseline_of(observed):
    return {"schema": 2,
            "principals": {fp: {"category": "unrelated-workload",
                                "grants": p["grants"]}
                           for fp, p in observed.items()}}


REQUIRED = {"edge": "EdgeRole", "deployer": "site-deployer-exec-role"}


def _with_required(g, observed):
    """把两条正向控制补进 observed，让用例只测想测的那一条。"""
    return {**observed,
            **_observed(g, EdgeRole=["invoke-platform:site-panel", "invoke-site:all"]),
            **_observed(g, **{"site-deployer-exec-role": ["invoke-site:all"]})}


def test_new_principal_is_a_failure():
    g = _gate()
    base = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel"]))
    now = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel"],
                                      WorkloadB=["invoke-platform:site-panel"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert "WorkloadB" in rep.render()


def test_known_principal_gaining_secret_read_is_a_failure():
    """从「只能 invoke」变成「还能读会话密钥」——这一步把读面失守升级成写面失守
    （同一个 `/site-builder/jwt-secret` 也签 `__Host-sb_console`）。"""
    g = _gate()
    base = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel"]))
    now = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel",
                                                    g.G_READ_EDGE_ASSET]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert g.G_READ_EDGE_ASSET in rep.render()


def test_shrinking_is_reported_but_not_a_failure():
    g = _gate()
    base = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel"],
                                       WorkloadB=["invoke-platform:site-panel"]))
    now = _with_required(g, _observed(g, WorkloadA=["invoke-platform:site-panel"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert rep.ok, rep.render()
    assert rep.improvements, "集合缩小了却没被报出来——那基线永远不会被更新"


# --------------------------------------------------------------------------
# ④ 正向控制
# --------------------------------------------------------------------------

@pytest.mark.parametrize("lost", ["edge", "deployer"])
def test_losing_a_required_allow_is_a_failure(lost):
    g = _gate()
    base = _with_required(g, {})
    now = _with_required(g, {})
    del now[g.principal_fingerprint(f"arn:aws:iam::1:role/{REQUIRED[lost]}")]
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert REQUIRED[lost] in rep.render()


def test_required_principal_present_but_without_invoke_is_a_failure():
    """Edge 角色还在、但 invoke 被收掉了——比「角色消失」更常见的形态
    （收窄改的是策略，不是角色）。"""
    g = _gate()
    base = _with_required(g, {})
    now = {**_observed(g, EdgeRole=[g.G_READ_JWT_PARAM]),
           **_observed(g, **{"site-deployer-exec-role": ["invoke-site:all"]})}
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert "EdgeRole" in rep.render()


# --------------------------------------------------------------------------
# ⑤ 基线文件不许含账号值
# --------------------------------------------------------------------------

def test_baseline_carries_no_account_values():
    """仓库红线：真实账号 ID / 角色名不进被跟踪文件。

    基线里 CDK bootstrap 那几个角色的名字**内嵌账号 ID**，所以这条不是形式主义:
    照抄角色名就会把账号值提交进仓库。resource policy 的 Principal 同理
    （它是带账号 ID 的角色 ARN），所以那边也只存指纹。
    """
    raw = _BASELINE.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{12}\b", raw), "基线里出现了 12 位账号 ID"
    for forbidden in ("arn:aws:", "role/", "cdk-hnb659fds", "Isengard"):
        assert forbidden not in raw, f"基线里出现了 {forbidden!r}——那是账号内的真实标识"
    data = json.loads(raw)
    for fp in data["principals"]:
        assert re.fullmatch(_FP_RE, fp), f"{fp!r} 不是指纹形态"
    rp = data["resource_policies"]
    for fps in list(rp["platform"].values()) + list(rp["site_shapes"]):
        for fp in fps:
            assert re.fullmatch(_FP_RE, fp), f"{fp!r} 不是指纹形态"


def test_fingerprint_is_one_way_and_stable():
    g = _gate()
    # 占位账号用 000000000000（仓库既有约定，secret scanner 的预期命中之一），
    # 形态刻意照抄那类**名字里嵌着账号 ID** 的角色——它正是基线不能存原名的原因。
    arn = "arn:aws:iam::000000000000:role/cdk-hnb659fds-cfn-exec-role-000000000000-us-east-1"
    fp = g.principal_fingerprint(arn)
    assert re.fullmatch(_FP_RE, fp)
    assert "000000000000" not in fp
    assert not re.search(r"[0-9]{12}", fp), (
        "指纹里出现了 12 位连续数字——它会被 secret scanner 当成账号 ID，"
        "而反复的假阳性会训练出无脑 --allow-hits")
    assert fp == g.principal_fingerprint(arn), "指纹不稳定，基线每次跑都会全量漂移"
    assert fp != g.principal_fingerprint(arn.replace("us-east-1", "us-west-2"))


def test_statement_fingerprint_normalizes_account_and_self():  # noqa: D401
    """语句指纹要把账号 ID 与函数自身归一化掉，否则站点函数之间没有可比性；
    但**不能**把 Principal 归一化掉——换个 Principal 必须是不同的指纹。"""
    g = _gate()
    a = g.statement_fingerprint(
        {**_EDGE_STMT, "Resource": _EDGE_STMT["Resource"].format(fn="site-a")},
        account="000000000000", function="site-a")
    b = g.statement_fingerprint(
        {**_EDGE_STMT, "Resource": _EDGE_STMT["Resource"].format(fn="site-b")},
        account="000000000000", function="site-b")
    assert a == b
    rogue = g.statement_fingerprint(
        {**_EDGE_STMT, "Principal": {"AWS": "arn:aws:iam::000000000000:role/Rogue"},
         "Resource": _EDGE_STMT["Resource"].format(fn="site-a")},
        account="000000000000", function="site-a")
    assert rogue != a, "换了 Principal 却是同一个指纹——新增授权会静静地绿"


# --------------------------------------------------------------------------
# 文档与基线不许各说一套
# --------------------------------------------------------------------------

def test_doc_counts_come_from_the_baseline():
    """风险模型文档里的数字必须与基线文件算出来的一致。

    这条防的是文档腐烂：基线更新了而文档还写着旧数字时，读文档的人会以为
    集合没变——而"集合别再长"正是这个闸门存在的唯一理由。

    断言的形态是 `<数字> <!-- baseline:标签=<数字> -->`：**正文里显示的那个数字
    必须紧挨着标记**。只校验标记的话，标记与正文可以各写一个数，那就白防了。
    """
    g = _gate()
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    principals = data["principals"]
    secret_grants = set(g.SECRET_GRANTS)

    def count(pred):
        return sum(1 for p in principals.values() if pred(p))

    def has_prefix(p, prefix):
        return any(x.startswith(prefix) for x in p["grants"])

    expected = {
        "总数": len(principals),
        "可读密钥": count(lambda p: secret_grants & set(p["grants"])),
        "非平台可直调": count(
            lambda p: p["category"] != "platform"
            and (has_prefix(p, f"{g.G_INVOKE_PLATFORM}:")
                 or has_prefix(p, f"{g.G_INVOKE_SITE}:"))),
        "无关工作负载": count(lambda p: p["category"] == "unrelated-workload"),
        "带活密钥的asset": data["facts"]["edge_assets_carrying_live_key"],
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


def test_baseline_schema_is_current():
    """基线 schema 与脚本必须同版本：schema 1 只有布尔能力标签，
    拿它当基线跑 schema 2 的脚本会把每个 principal 都报成"新增"。"""
    g = _gate()
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert data["schema"] == g.BASELINE_SCHEMA
    assert "resource_policies" in data and "facts" in data
