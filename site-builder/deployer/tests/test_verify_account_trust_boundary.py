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
import fnmatch
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
# 基线红线的**第二层**：结构化递归类型检查。
#
# 第一层是 `test_baseline_carries_no_account_values` 里的整文件 raw 禁用模式扫描
# （12 位账号 ID / `arn:aws:` / `role/` / …）——它管"值本身不泄密"。
# 这一层管"值出现在正确的结构位置、且是正确的类型"。**两层都要保留**：
# `note` / `categories[]` / `category` 是自由文本，这一层刻意不校验它们的形态，
# 若有人把真实账号 ID 或内部角色名写进 `note`，只有第一层会抓。
#
# 旧版把形态检查写成"硬编码 resource_policies 下的四个列表键"⇒ 新加任何子键都自动
# 绕过。这一层反过来：**默认拒绝**，没有专门类型校验的位置一律必须是指纹形态。
# --------------------------------------------------------------------------

def _is_version_id(value: str) -> bool:
    return bool(re.fullmatch(r"v[0-9]+", value))


# 值的**类型分流**：路径模式 → 校验函数。命中这里的位置不做指纹形态检查，
# 而是按它自己的类型校验 —— **这不是放行**。
_TYPED_VALUE_PATHS = (
    # VersionId 形如 v1/v2/…：既不是指纹，也不能是任意字符串（写成角色名或占位
    # "?" 都必须红）。放成"任意字符串"就等于不检查；要求它是指纹又会把合法的 v3 报红。
    ("managed_policy_versions.*", _is_version_id),
)
# **自由文本**：说明性字段，这一层不校验形态；泄密由第一层的整文件 raw 扫描兜。
_FREE_TEXT_PATHS = (
    "note", "categories[]",                 # 说明文字与类别词表
    "principals.*.category",                # 类别名
    # grant 串：等基线不再含 legacy `iam-policy-write:*` 之后，移进
    # `_TYPED_VALUE_PATHS` 并按 grant 文法校验。
    "principals.*.grants[]",
)
# 字典**键**里允许非指纹的位置（结构键名、以及平台函数名）。
_NON_FP_KEY_PATHS = (
    "",                                     # 顶层结构键（schema/note/facts/…）
    "facts",                                # fact 名
    "principals.*",                         # 每个 principal 条目内的 category/grants
    "resource_policies",                    # 结构键（platform/site_*/bootstrap_bucket）
    "resource_policies.platform",           # 键是平台函数名（app.py 里就有，不是账号值）
    "coverage",                             # 结构键（undecided_items）
    "permissions_boundaries.*",             # 结构键（policy_fp/stmt_fps）
)


def _walk_baseline(node, path=""):
    """产出 (path, kind, value)，kind ∈ {"key", "value"}；只产出字符串。"""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, "key", k
            yield from _walk_baseline(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_baseline(item, f"{path}[]")
    elif isinstance(node, str):
        yield path, "value", node


def _non_fingerprint_leaves(data):
    """基线树里所有"形态不对"的位置：默认必须是指纹，除非有专门的类型校验。"""
    for path, kind, value in _walk_baseline(data):
        if kind == "key":
            if any(fnmatch.fnmatchcase(path, p) for p in _NON_FP_KEY_PATHS):
                continue
        else:
            typed = [ok for pat, ok in _TYPED_VALUE_PATHS
                     if fnmatch.fnmatchcase(path, pat)]
            if typed:
                if not all(ok(value) for ok in typed):
                    yield f"{path}/类型不符={value!r}"
                continue
            if any(fnmatch.fnmatchcase(path, p) for p in _FREE_TEXT_PATHS):
                continue
        if not re.fullmatch(_FP_RE, value):
            yield f"{path or '<root>'}/{kind}={value!r}"


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
             sites=("site-a", "site-b"),
             assets=("arn:aws:s3:::assets/edge.zip",),
             aliases=None, versions=None):
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    return g.Targets(
        platform_functions=tuple(fn(n) for n in platform),
        site_functions=tuple(fn(n) for n in sites),
        edge_code_arns=(fn("edge"),),
        edge_assets=tuple(assets),
        jwt_parameter="arn:aws:ssm:us-east-1:1:parameter/site-builder/jwt-secret",
        alias_arns=dict(aliases or {}),
        version_arns=dict(versions or {}))


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
    assert len(one) == len(two) == 1
    assert next(iter(one)).startswith("invoke-site:some(1):")
    assert next(iter(two)).startswith("invoke-site:some(2):")
    assert one != two


def test_three_secret_paths_are_separate_grants():
    """读密钥的三条路必须分开记：Edge 函数产物、**CDK bootstrap S3 asset**、
    SSM 参数。合成一项就看不出「只给了 S3 只读的身份也能拿到密钥」这件事
    ——那正是 2026-08-25 复审补上的第三条路（21 个 principal 只在这条路上）。"""
    g = _gate()
    t = _targets(g)
    only_code = g.grants_from_decisions(
        {f"lambda:GetFunction|{t.edge_code_arns[0]}": "allowed"}, t)
    only_asset = g.grants_from_decisions(
        {f"s3:GetObject|{t.edge_assets[0]}": "allowed"}, t)
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
    t = _targets(g, assets=())
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
    fns = tuple(sites) + tuple(platform)
    aliases = {fn: (qualifier,) for fn in fns} if qualifier else {}
    return g.resource_policy_snapshot(
        _policies(fns, extra_on=extra_on, qualifier=qualifier),
        account="000000000000", platform=tuple(platform), sites=tuple(sites),
        aliases=aliases)


def test_site_resource_policies_share_one_fingerprint_after_normalization():
    """每个站点函数的 `edge-invoke` 语句只在"函数自己的 ARN"上不同 ⇒
    归一化后必须得到**同一个**指纹，否则规范形态无从建立、每建一个站点都漂移。"""
    g = _gate()
    snap = _snap(g, sites=("site-a", "site-b", "site-c"), qualifier="blue")
    alias_sets = {tuple(v["alias"]["blue"]) for v in snap["sites"].values()}
    assert len(alias_sets) == 1, alias_sets
    canon = g.site_shape_canonicals(snap["sites"])
    assert len(canon["site_alias_canonical"]) == 1
    assert canon["site_legacy_exempt"] == [], "alias-only 站点不该进 legacy 豁免名单"


def test_canonical_alias_shape_is_the_mode_not_the_union():
    """规范形态取**众数**：并集会把最宽松的那个站点当成规范（于是规矩的站点
    被报成偏离——首版的真实缺陷）。"""
    g = _gate()
    snap = _snap(g, sites=("site-a", "site-b", "site-c"), qualifier="blue",
                 extra_on="site-c")
    canon = g.site_shape_canonicals(snap["sites"])
    assert len(canon["site_alias_canonical"]) == 1, canon
    assert set(canon["site_alias_canonical"]) < set(snap["sites"]["site-c"]["alias"]["blue"])


def test_legacy_sites_land_in_the_exempt_list_not_a_global_shape():
    """有未限定 policy 的站点（M7 迁移来的）应当进**点名豁免名单**，
    而不是把 legacy 变成人人可用的合法形态。"""
    g = _gate()
    legacy = _snap(g, sites=("site-old",))["sites"]          # 只有未限定语句
    modern = _snap(g, sites=("site-new",), qualifier="blue")["sites"]
    canon = g.site_shape_canonicals({**legacy, **modern})
    assert canon["site_legacy_exempt"] == [g.site_fingerprint("site-old")]
    assert canon["site_legacy_canonical"], "legacy 的未限定语句形态没被记下来"


def test_extra_alias_statement_on_one_site_is_flagged():
    """某个站点函数 alias 上多出一条语句（有人手工 `AddPermission`）→ 红并点名。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"), qualifier="blue")["sites"]
    dirty = _snap(g, sites=("site-a", "site-b"), qualifier="blue",
                  extra_on="site-b")["sites"]
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {}, **g.site_shape_canonicals(clean)}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies={"platform": {}, "sites": dirty})
    assert not rep.ok
    assert "site-b" in rep.render() and "多出语句" in rep.render()


def test_site_missing_its_alias_statement_is_also_flagged():
    """反方向：某个站点函数**少**了 alias 语句——它已无法经 Edge 访问。
    这不是安全扩权而是功能损坏，但同属"投影与真源不一致"，要红。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"), qualifier="blue")["sites"]
    stripped = {**clean, "site-b": {"alias": {"blue": []}, "version": [],
                                    "unqualified": []}}
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {}, **g.site_shape_canonicals(clean)}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies={"platform": {}, "sites": stripped})
    assert not rep.ok
    assert "缺语句" in rep.render()


def test_new_alias_only_site_does_not_drift():
    """新建站点若是 modern（alias-only）形态，必须**不**红——否则每次建站都要
    改基线，而"新增即红"这条就被迫失效了。"""
    g = _gate()
    clean = _snap(g, sites=("site-a", "site-b"), qualifier="blue")["sites"]
    grown = _snap(g, sites=("site-a", "site-b", "site-c"), qualifier="blue")["sites"]
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {}, **g.site_shape_canonicals(clean)}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies={"platform": {}, "sites": grown})
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
            **_observed(g, **{"site-deployer-exec-role": ["invoke-site@alias:all"]})}


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
           **_observed(g, **{"site-deployer-exec-role": ["invoke-site@alias:all"]})}
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
    fp_lists = (list(rp["platform"].values())
                + [rp["site_alias_canonical"], rp["site_version_canonical"],
                   rp["site_legacy_canonical"], rp["site_legacy_exempt"]])
    for fps in fp_lists:
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
    集合没变——而"集合别再长"正是这个闸门存在的唯一理由。这一轮它就抓住了
    两次：41→62（补上 CDK asset 那条路）、62→63（补上 `ssm:GetParameters`）。

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
        "带活密钥的Edge代码目标": data["facts"]["edge_code_targets_carrying_live_key"],
        "持有IAM策略变更动作": count(
            lambda p: any(x.startswith(g.G_IAM_POLICY_WRITE) for x in p["grants"])),
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
    for key in ("platform", "site_alias_canonical", "site_version_canonical",
                "site_legacy_canonical", "site_legacy_exempt"):
        assert key in data["resource_policies"], f"基线缺 {key}"


# ==========================================================================
# Codex 第二轮复审（2026-08-25）：五条 finding 各自的会红用例
#
# 五条的**共同根因**是同一个建模错误犯了第三次：把一种「能力」写成**单个 API
# 动作 / 单个资源**，于是等价的其它动作、限定符、历史对象全部落在视野外。
# 所以下面这些用例不只钉住五条修复，也钉住「能力 = 动作等价类 × 资源等价类」
# 这个形状本身——任何把它压回单个动作/单个资源的改动都会红。
# ==========================================================================

def test_ssm_read_is_an_action_class_not_one_action():
    """`ssm:GetParameter` 之外还有三个动作能读到同一个明文值。

    实测（2026-08-25）：账号里有一个角色**只**被授予 `ssm:GetParameters`
    （复数）on `Resource:*`、没有单数那个，于是首版闸门把它整个漏掉了。
    AWS 另外明确警告 `GetParameterHistory` 即使在拒绝 `GetParameter` 时也可能
    读到当前值。四个动作**任一**命中都必须产生 read-jwt-param。
    """
    g = _gate()
    t = _targets(g)
    assert len(g.A_READ_PARAM) >= 4, f"动作等价类被缩回去了：{g.A_READ_PARAM}"
    for action in g.A_READ_PARAM:
        grants = g.grants_from_decisions({f"{action}|{t.jwt_parameter}": "allowed"}, t)
        assert g.G_READ_JWT_PARAM in grants, f"{action} 单独命中时没产生 grant"


def test_iam_write_is_an_action_class_too():
    """IAM 策略变更同理：`PutRolePolicy` 只是其中一个动作。

    这条最初不是 Codex 点的（是同一个错误类型的同类项），但第三轮它指出我**资源**
    那一侧仍然写错——四个动作统统对着字面量 `role/*` 模拟。资源侧的用例在下面。
    """
    g = _gate()
    t = _targets(g)
    assert len(g.IAM_WRITE_ACTIONS) >= 4, f"动作等价类太窄：{g.IAM_WRITE_ACTIONS}"
    for action in g.IAM_WRITE_ACTIONS:
        cand = g.iam_write_candidates_from_statements(
            [{"Effect": "Allow", "Action": action, "Resource": "*"}])
        assert g.iam_write_grants(cand), f"{action} 单独命中时没产生 grant"
    # 每个动作都必须有资源类型映射，否则又会拿错类型的 ARN 去问
    for action in g.IAM_WRITE_ACTIONS:
        assert g.iam_write_resource_kind(action) in ("role", "user", "policy")


def test_every_live_key_asset_is_probed_not_only_the_current_one():
    """历史 asset 也带着**当前有效**的密钥（实测 9 个，因为旧 asset 不删、
    密钥从未轮转）。只探"当前 CloudFormation 模板指向的那一个"时，
    「只能读旧对象」的 principal 完全不可见。"""
    g = _gate()
    t = _targets(g, assets=("arn:aws:s3:::b/new.zip", "arn:aws:s3:::b/old.zip"))
    only_old = g.grants_from_decisions({"s3:GetObject|arn:aws:s3:::b/old.zip": "allowed"}, t)
    assert g.G_READ_EDGE_ASSET in only_old, "只能读旧 asset 的 principal 被漏掉了"


def test_object_version_read_is_in_the_same_class():
    """桶开着版本控制（noncurrent 保留 30 天），而 `s3:GetObjectVersion` 是
    **另一个** IAM 动作 ⇒ 删掉对象之后仍可按 version ID 读到旧版本。"""
    g = _gate()
    t = _targets(g, assets=("arn:aws:s3:::b/new.zip",))
    assert "s3:GetObjectVersion" in g.A_READ_OBJECT
    grants = g.grants_from_decisions(
        {"s3:GetObjectVersion|arn:aws:s3:::b/new.zip": "allowed"}, t)
    assert g.G_READ_EDGE_ASSET in grants


def test_alias_and_unqualified_invoke_are_distinct_grants():
    """`function:foo` 与 `function:foo:blue` 在 IAM 里是两个资源。

    首版把它们并成一个 `invoke-platform:<fn>`，于是「原来只能调 `:blue`、
    现在还能调未限定」这种扩权全绿——文档里写着两者是两个资源，代码却在
    落基线前把区别抹掉了（Codex 复审 P1-3）。
    """
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:site-panel"
    t = _targets(g, aliases={fn: (f"{fn}:blue",)})
    alias_only = g.grants_from_decisions({f"lambda:InvokeFunction|{fn}:blue": "allowed"}, t)
    unqualified = g.grants_from_decisions({f"lambda:InvokeFunction|{fn}": "allowed"}, t)
    assert alias_only and unqualified
    assert alias_only != unqualified, "限定符维度被压平了"
    both = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn}": "allowed",
         f"lambda:InvokeFunction|{fn}:blue": "allowed"}, t)
    assert both == alias_only | unqualified


def test_version_scoped_invoke_is_visible():
    """版本级授权同样要能看见：AWS 支持把 permission 限定到具体 version。"""
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:site-panel"
    t = _targets(g, versions={fn: (f"{fn}:9",)})
    grants = g.grants_from_decisions({f"lambda:InvokeFunction|{fn}:9": "allowed"}, t)
    assert grants, "版本级 invoke 授权完全不可见"
    assert any("@version" in x for x in grants), grants


def test_platform_principal_losing_a_grant_is_a_failure():
    """**Codex 的最小反例**：Edge 丢掉 `invoke-platform:site-panel`、保留
    key-proxy，前缀检查照样过 ⇒ 首版绿。平台角色的授权是精确且必需的，
    必须按**集合等值**比，任一方向的差异都红。"""
    g = _gate()
    base = _observed(g, EdgeRole=["invoke-platform:site-panel",
                                  "invoke-platform:site-key-proxy", "invoke-site:all"],
                     **{"site-deployer-exec-role": ["invoke-site@alias:all"]})
    baseline = {"schema": 2,
                "principals": {fp: {"category": "platform", "grants": p["grants"]}
                               for fp, p in base.items()}}
    now = _observed(g, EdgeRole=["invoke-platform:site-key-proxy", "invoke-site:all"],
                    **{"site-deployer-exec-role": ["invoke-site@alias:all"]})
    rep = g.compare_to_baseline(now, baseline, required=REQUIRED)
    assert not rep.ok, rep.render()
    assert "site-panel" in rep.render()


def test_overbroad_platform_grant_shrinking_is_still_an_improvement():
    """反向的正对照：`platform-overbroad` 这一类**就是**要缩小的，
    它丢掉授权必须算改善而不是红。否则"集合等值"会把我们想要的修复判成故障。"""
    g = _gate()
    base = _observed(g, BuildRole=[g.G_READ_EDGE_ASSET])
    baseline = {"schema": 2,
                "principals": {fp: {"category": "platform-overbroad",
                                    "grants": p["grants"]}
                               for fp, p in base.items()}}
    baseline["principals"].update(
        {fp: {"category": "platform", "grants": p["grants"]}
         for fp, p in _with_required(g, {}).items()})
    now = _with_required(g, {})
    rep = g.compare_to_baseline(now, baseline, required=REQUIRED)
    assert rep.ok, rep.render()
    assert rep.improvements


def test_platform_resource_policy_loss_is_a_failure():
    """平台函数少一条 resource policy 语句 = 控制台/站点入口断掉，
    首版把它写成"改善"（Codex 复审 P1-4）。必须红。"""
    g = _gate()
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {"site-panel": ["aaaa-bbbb-cccc-dddd",
                                                "eeee-ffff-0000-1111"]},
                    "site_alias_canonical": [], "site_legacy_exempt": [],
                    "site_legacy_canonical": []}}
    now_rp = {"platform": {"site-panel": ["aaaa-bbbb-cccc-dddd"]}, "sites": {}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=now_rp)
    assert not rep.ok, rep.render()
    assert "site-panel" in rep.render()


def _site_shape(alias_fps, unqualified_fps=(), color="blue"):
    return {"alias": {color: sorted(alias_fps)}, "version": [],
            "unqualified": sorted(unqualified_fps)}


def _rp_baseline(observed, *, exempt=()):
    return {**_baseline_of(observed),
            "resource_policies": {"platform": {},
                                  "site_alias_canonical": ["alias-fp00-0000-0000"],
                                  "site_legacy_canonical": ["unqu-alfp-0000-0000"],
                                  "site_legacy_exempt": list(exempt)}}


def test_new_site_may_not_regress_to_legacy_shape():
    """「存量迁移站点需要兼容 legacy」不等于「今后新站点也可以再产生 legacy」。

    首版把两种形态都设成全局白名单，于是一个**全新**站点带着未限定 policy
    也全绿（Codex 复审 P1-3③）。legacy 只能是**点名豁免**，且集合只能缩小。
    """
    g = _gate()
    observed = _with_required(g, {})
    legacy_fp = g.principal_fingerprint("site:site-old")
    baseline = _rp_baseline(observed, exempt=[legacy_fp])
    rp = {"platform": {}, "sites": {
        "site-old": _site_shape(["alias-fp00-0000-0000"], ["unqu-alfp-0000-0000"]),
        "site-new": _site_shape(["alias-fp00-0000-0000"], ["unqu-alfp-0000-0000"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=rp)
    assert not rep.ok, rep.render()
    assert "site-new" in rep.render()
    assert "site-old" not in rep.render(), "被豁免的存量站点不该被报出来"


def test_modern_alias_only_site_is_compliant():
    g = _gate()
    observed = _with_required(g, {})
    baseline = _rp_baseline(observed)
    rp = {"platform": {}, "sites": {
        "site-new": _site_shape(["alias-fp00-0000-0000"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=rp)
    assert rep.ok, rep.render()


def test_migrated_legacy_site_reports_as_improvement():
    """豁免名单里的站点改成 modern 形态 ⇒ 绿，且把"豁免可以去掉"报出来。
    没有这条，豁免名单只会越来越长。"""
    g = _gate()
    observed = _with_required(g, {})
    legacy_fp = g.principal_fingerprint("site:site-old")
    baseline = _rp_baseline(observed, exempt=[legacy_fp])
    rp = {"platform": {}, "sites": {
        "site-old": _site_shape(["alias-fp00-0000-0000"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=rp)
    assert rep.ok, rep.render()
    assert any("豁免" in x for x in rep.improvements), rep.improvements


def test_missing_context_is_read_from_resource_specific_results():
    """真实响应里 `MissingContextValues` 会**只**出现在
    `ResourceSpecificResults` 的条目上；只看顶层会把它读成"没有不确定"
    （Codex 复审 P2）。"""
    g = _gate()
    nested = [{"EvalActionName": "s3:GetObject", "EvalDecision": "implicitDeny",
               "ResourceSpecificResults": [
                   {"EvalResourceName": "x", "EvalResourceDecision": "implicitDeny",
                    "MissingContextValues": ["aws:ResourceTag/Allow"]}]}]
    assert g.missing_context_in(nested)


def test_missing_context_growth_is_reported_with_a_delta():
    """不确定的部分变多时要有**明确的 delta**。

    刻意**不**红：这个数会随账号里任何一条带 Condition 的新策略变动，
    让它决定退出码就会训练出无脑更新基线。但它必须被算出来并打印。
    """
    g = _gate()
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "facts": {"principals_with_missing_context": 162,
                          "edge_assets_carrying_live_key": 9}}
    rep = g.compare_to_baseline(
        observed, baseline, required=REQUIRED,
        facts={"principals_with_missing_context": 200,
               "edge_assets_carrying_live_key": 9})
    assert rep.ok, "这条不该影响退出码"
    joined = rep.render()
    assert "162" in joined and "200" in joined and "+38" in joined, joined


def test_edge_functions_are_in_the_platform_set():
    """两个 Edge 函数必须进平台集合。

    它们属于 **router 栈**，而 `platform_function_names()` 读的是 deployer 栈
    `infra/app.py` 的 `PLATFORM_FUNCTION_NAMES` ⇒ 结构上不可能含它们。
    漏掉一次的实测后果：Edge 的 9 个已发布版本一个都没被枚举，于是
    「谁能读旧版本 Edge 代码（里面是明文密钥）」与「谁能 UpdateFunctionCode
    换掉 Edge」两条完全在视野外。
    """
    g = _gate()
    assert g.EDGE_ORIGIN_REQUEST_FN in g.EDGE_FUNCTIONS
    assert g.EDGE_ORIGIN_RESPONSE_FN in g.EDGE_FUNCTIONS
    from_app_py = g.platform_function_names()
    assert not (set(g.EDGE_FUNCTIONS) & set(from_app_py)), (
        "Edge 函数出现在 app.py 的清单里了——那说明这两处的分工变了，"
        "本条与 measure() 里的拼接都要重新想")


# ==========================================================================
# Codex 第三轮复审（2026-08-25）：三条 finding
#
# P1 又是同一个建模错误的第四次现身，只是这次错在**资源**那一侧：
# `self-escalate` 的四个动作统统只对着 `arn:aws:iam::<acct>:role/*` 这个
# **字面量**模拟。IAM 里请求资源是具体 ARN，policy 的 `role/ExactRole` 不会匹配
# 字面量 `role/*` ⇒ 精确授权全部隐形；而 `iam:CreatePolicyVersion` 的资源类型
# 根本是 **policy** 不是 role，对着 role ARN 模拟等于永远问不到。
# 实测：22 个 principal 持有这些动作，其中 3 个在基线里缺这条 grant、
# 3 个完全不在基线里。
# ==========================================================================

def test_iam_write_action_patterns_expand():
    """动作通配要展开：`*` / `iam:*` / `iam:Put*` 都能命中。"""
    g = _gate()
    assert g.expand_iam_write_actions(["*"]) == set(g.IAM_WRITE_ACTIONS)
    assert g.expand_iam_write_actions(["iam:*"]) == set(g.IAM_WRITE_ACTIONS)
    assert g.expand_iam_write_actions(["iam:Put*"]) == {
        a for a in g.IAM_WRITE_ACTIONS if a.startswith("iam:Put")}
    assert g.expand_iam_write_actions(["s3:GetObject"]) == set()
    assert g.expand_iam_write_actions(["iam:AttachRolePolicy"]) == {"iam:AttachRolePolicy"}


def test_exact_arn_grant_is_discovered():
    """**Codex 的核心反例**：`PutRolePolicy` 精确授在一个角色上。

    对着字面量 `role/*` 模拟时它返回 implicitDeny ⇒ 首版完全看不见。
    静态解析必须把它找出来（再由模拟器对**具体** ARN 确认）。
    """
    g = _gate()
    st = [{"Effect": "Allow", "Action": "iam:PutRolePolicy",
           "Resource": "arn:aws:iam::000000000000:role/ExactRole"}]
    cand = g.iam_write_candidates_from_statements(st)
    assert cand["actions"] == {"iam:PutRolePolicy"}
    assert cand["targets"] == ["arn:aws:iam::000000000000:role/ExactRole"]
    assert not cand["unrestricted"]


def test_create_policy_version_targets_a_policy_not_a_role():
    """`iam:CreatePolicyVersion` 的资源类型是 **policy**。

    把它和 `PutRolePolicy` 混在同一个 role ARN 上模拟，是"资源等价类"写错的
    另一种形态——那个组合永远不会 allowed（除了 `Resource:*`）。
    """
    g = _gate()
    assert g.iam_write_resource_kind("iam:CreatePolicyVersion") == "policy"
    assert g.iam_write_resource_kind("iam:PutRolePolicy") == "role"
    assert g.iam_write_resource_kind("iam:PutUserPolicy") == "user"


def test_unrestricted_target_is_marked_and_scoped_is_not():
    g = _gate()
    wide = g.iam_write_candidates_from_statements(
        [{"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}])
    narrow = g.iam_write_candidates_from_statements(
        [{"Effect": "Allow", "Action": "iam:AttachRolePolicy",
          "Resource": "arn:aws:iam::000000000000:role/site-rt-*"}])
    assert wide["unrestricted"] and not narrow["unrestricted"]
    assert g.iam_write_grants(wide) == {f"{g.G_IAM_POLICY_WRITE}:any"}
    assert g.iam_write_grants(narrow) == {f"{g.G_IAM_POLICY_WRITE}:scoped"}
    assert g.iam_write_grants({"actions": set(), "targets": [], "unrestricted": False}) == set()


def test_not_action_allow_counts_as_a_hit():
    """`Allow` + `NotAction` 基本等于"除了这些之外全给"，必须保守算命中，
    不能因为解析不出具体动作就当没有。"""
    g = _gate()
    cand = g.iam_write_candidates_from_statements(
        [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}])
    assert cand["actions"] == set(g.IAM_WRITE_ACTIONS)
    assert cand["unrestricted"]


def test_deny_statements_do_not_create_candidates():
    g = _gate()
    cand = g.iam_write_candidates_from_statements(
        [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}])
    assert not cand["actions"]


def test_url_encoded_policy_document_is_decoded():
    """`GetAccountAuthorizationDetails` 有时把文档作为 **URL 编码的字符串**返回
    （实测踩到过）。不解码就会静默漏掉整份策略。"""
    g = _gate()
    import json as _json
    import urllib.parse
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PutRolePolicy",
                          "Resource": "*"}]}
    encoded = urllib.parse.quote(_json.dumps(doc))
    assert g.policy_statements(encoded) == doc["Statement"]
    assert g.policy_statements(doc) == doc["Statement"]
    # 单条语句不是 list 的形态也要吃下
    assert g.policy_statements({"Statement": doc["Statement"][0]}) == doc["Statement"]


def test_concrete_target_makes_a_simulatable_arn():
    """模拟器要的是**具体** ARN：`role/site-rt-*` 这种模式要落成一个具体名字，
    否则又变成拿字面量去问。"""
    g = _gate()
    got = g.concrete_target("arn:aws:iam::000000000000:role/site-rt-*", "role",
                            account="000000000000")
    assert "*" not in got and got.startswith("arn:aws:iam::000000000000:role/site-rt-")
    wide = g.concrete_target("*", "policy", account="000000000000")
    assert wide.startswith("arn:aws:iam::000000000000:policy/")


# ---- P2a：alias 类内部的成员变化 -----------------------------------------

def _alias_shape(members, version=(), unqualified=()):
    return {"alias": {k: sorted(v) for k, v in members.items()},
            "version": sorted(version), "unqualified": sorted(unqualified)}


def test_each_alias_member_must_carry_the_canonical_statements():
    """**Codex 的 P2a 反例**：站点有 blue + green，其中 active 那个丢了授权语句。

    按成员并集比时两者相加仍等于规范集合 ⇒ 绿。必须**逐成员**比。
    （事实前提已核：blue/green 切换后旧颜色的 alias / Function URL / 两条语句
    都保留，没有任何代码删它们，所以"每个 alias 都完整"不会误报。）
    """
    g = _gate()
    observed = _with_required(g, {})
    canon = ["aaaa-bbbb-cccc-dddd", "eeee-ffff-0000-1111"]
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {},
                                      "site_alias_canonical": canon,
                                      "site_version_canonical": [],
                                      "site_legacy_canonical": [],
                                      "site_legacy_exempt": []}}
    rp = {"platform": {}, "sites": {
        "site-a": _alias_shape({"blue": [], "green": canon})}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=rp)
    assert not rep.ok, rep.render()
    assert "blue" in rep.render()


def test_two_complete_colors_do_not_drift():
    """两个颜色都完整 ⇒ 绿。切一次颜色不该把基线拽红。"""
    g = _gate()
    observed = _with_required(g, {})
    canon = ["aaaa-bbbb-cccc-dddd", "eeee-ffff-0000-1111"]
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {},
                                      "site_alias_canonical": canon,
                                      "site_version_canonical": [],
                                      "site_legacy_canonical": [],
                                      "site_legacy_exempt": []}}
    rp = {"platform": {}, "sites": {
        "site-a": _alias_shape({"blue": canon, "green": canon})}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=rp)
    assert rep.ok, rep.render()


def test_version_statements_are_compared_as_a_subset():
    """版本级语句只做**子集**检查：AWS 的 replicator 语句只出现在当前 Edge 版本上，
    旧版本合法地没有它——逐成员等值会把 1..8 全报成缺语句。"""
    g = _gate()
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "resource_policies": {"platform": {}, "site_alias_canonical": [],
                                      "site_version_canonical": ["repl-icat-0000-0000"],
                                      "site_legacy_canonical": [],
                                      "site_legacy_exempt": []}}
    ok_rp = {"platform": {}, "sites": {"site-a": _alias_shape({}, version=[])}}
    assert g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                 resource_policies=ok_rp).ok
    bad_rp = {"platform": {}, "sites": {
        "site-a": _alias_shape({}, version=["repl-icat-0000-0000", "surp-rise-0000-0000"])}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                resource_policies=bad_rp)
    assert not rep.ok, rep.render()


# ---- P2b：站点子集换租户 --------------------------------------------------

def test_site_subset_records_member_identity_not_just_count():
    """**Codex 的 P2b 反例**：失去 site-a、新增 site-b，数量仍是 1。

    只记数量时前后都是 `some(1)` ⇒ 受影响租户换了一批而闸门不动。
    """
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    t = _targets(g, sites=("site-a", "site-b", "site-c"))
    only_a = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-a')}": "allowed"}, t)
    only_b = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn('site-b')}": "allowed"}, t)
    assert only_a and only_b
    assert only_a != only_b, "同数量换租户没有产生不同的 grant"
    # 数量仍要在 grant 里可读
    assert all("some(1)" in x for x in only_a | only_b)


def test_site_all_stays_a_stable_aggregate():
    """`all` 必须保持稳定聚合——否则每建一个站点都把基线拽红。"""
    g = _gate()
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    t2 = _targets(g, sites=("site-a", "site-b"))
    t3 = _targets(g, sites=("site-a", "site-b", "site-c"))
    a2 = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn(n)}": "allowed" for n in ("site-a", "site-b")}, t2)
    a3 = g.grants_from_decisions(
        {f"lambda:InvokeFunction|{fn(n)}": "allowed"
         for n in ("site-a", "site-b", "site-c")}, t3)
    assert a2 == a3 == {"invoke-site:all"}


# ---- IAM 写的确认有**三种**结果，不是两种 -------------------------------

def test_iam_write_probe_outcomes_are_three_valued():
    """确认步骤必须区分「确认有」「判不出」「确认没有」。

    实测现场：一个角色的 `AttachRolePolicy` 被 `iam:PolicyARN` 的 ArnEquals 限定到
    两个无害的 AWS 托管策略，模拟器返回 `implicitDeny` **且带
    `MissingContextValues`**——那是"判不出"。首版把它静默当成"没有"，
    于是这个 principal 连基线都进不去，而它的条件哪天被放宽也没人会看见。
    """
    g = _gate()
    allowed_wide = g.iam_write_grants_from_probes(
        [{"pattern": "*", "decision": "allowed", "missing_context": False}])
    allowed_narrow = g.iam_write_grants_from_probes(
        [{"pattern": "arn:aws:iam::000000000000:role/X", "decision": "allowed",
          "missing_context": False}])
    undecided = g.iam_write_grants_from_probes(
        [{"pattern": "arn:aws:iam::000000000000:role/X", "decision": "implicitDeny",
          "missing_context": True}])
    denied = g.iam_write_grants_from_probes(
        [{"pattern": "arn:aws:iam::000000000000:role/X", "decision": "implicitDeny",
          "missing_context": False}])
    assert allowed_wide == {f"{g.G_IAM_POLICY_WRITE}:any"}
    assert allowed_narrow == {f"{g.G_IAM_POLICY_WRITE}:scoped"}
    assert undecided == {f"{g.G_IAM_POLICY_WRITE}:condition-gated"}
    assert denied == set()


def test_confirmed_allow_wins_over_undecided():
    """同一个 principal 既有确认的授权、又有判不出的条件语句时，
    以**确认**的为准——不能被"判不出"降级。"""
    g = _gate()
    got = g.iam_write_grants_from_probes([
        {"pattern": "arn:aws:iam::000000000000:role/X", "decision": "implicitDeny",
         "missing_context": True},
        {"pattern": "*", "decision": "allowed", "missing_context": False}])
    assert got == {f"{g.G_IAM_POLICY_WRITE}:any"}


def test_condition_gated_widening_shows_up_as_a_new_grant():
    """条件被放宽（`condition-gated` → `scoped`/`any`）必须是**新** grant ⇒ 红。
    这是"判不出"这个状态存在的全部理由。"""
    g = _gate()
    base = _with_required(g, _observed(
        g, WorkloadA=[f"{g.G_IAM_POLICY_WRITE}:condition-gated"]))
    now = _with_required(g, _observed(
        g, WorkloadA=[f"{g.G_IAM_POLICY_WRITE}:any"]))
    rep = g.compare_to_baseline(now, _baseline_of(base), required=REQUIRED)
    assert not rep.ok
    assert f"{g.G_IAM_POLICY_WRITE}:any" in rep.render()


def test_concrete_target_normalizes_a_wildcard_account_segment():
    """跨账号模式（`arn:aws:iam::*:role/datazone*`）的**账号段**也要落成本账号。

    不换的话喂给模拟器的是 `arn:aws:iam::*:role/...`——字面量 `*` 恰好会被模式里的
    `*` 匹配上，于是答案**碰巧**是对的。碰巧对的判据下一次就可能碰巧错。
    """
    g = _gate()
    got = g.concrete_target("arn:aws:iam::*:role/datazone*", "role",
                            account="000000000000")
    assert got.startswith("arn:aws:iam::000000000000:role/datazone")
    assert "*" not in got
    pol = g.concrete_target("arn:aws:iam::*:policy/connector-*", "policy",
                            account="000000000000")
    assert pol.startswith("arn:aws:iam::000000000000:policy/connector-")
    assert "*" not in pol


# ==========================================================================
# 步 0（闸门收缩轮）：红判据与基线红线的**元守卫**
#
# 这一节测的不是"账号里有谁"，而是"闸门自己会不会漏红"。加它的理由：红判据原先散在
# `Report.ok` / `render()` / `main()` **三处**，加字段忘改 `ok` 就是一个新的
# false-green，而当时 62 条用例**没有一条会红**。
# ==========================================================================

def test_every_red_field_alone_flips_report_ok():
    """每个红字段**单独**出现时都必须让 ok 变 False 且在 render() 里露出标签。

    这条防的是"加了红字段但忘了接进 ok"——那种缺陷跑起来是绿的，
    和"确实没有漂移"在输出上一模一样。
    """
    g = _gate()
    for name, label, _key in g.RED_FIELDS:
        rep = g.Report(**{name: ["造出来的一行"]})
        assert not rep.ok, f"{name} 单独出现时 Report.ok 仍是 True——这是一个新的 false-green"
        assert label in rep.render(), f"{name} 有内容，但 render() 里没有它的标签"


def test_report_fields_are_all_classified():
    """`Report` 的每个字段都必须被 RED_FIELDS 或 GREEN_FIELDS 声明。

    不然新字段既不参与退出码也不打印——写进去了却完全没有作用。
    """
    import dataclasses
    g = _gate()
    declared = {n for n, _, _ in g.RED_FIELDS} | {n for n, _ in g.GREEN_FIELDS}
    actual = {f.name for f in dataclasses.fields(g.Report)}
    assert actual == declared, f"未被分类的 Report 字段：{actual ^ declared}"


def test_main_red_message_covers_every_red_field():
    """每个红字段都要有一条处置文案，否则闸门红了但不告诉人该怎么办。"""
    g = _gate()
    for name, _label, key in g.RED_FIELDS:
        assert key in g.RED_MESSAGES, f"{name} 的处置提示 key {key!r} 没有对应文案"


def test_baseline_redline_scan_walks_unknown_keys():
    """红线检查必须**递归走整棵树**，不能只看写死的几个键。

    旧版硬编码 resource_policies 下的四个列表键；收缩轮要加四个新分节
    （bootstrap_bucket / coverage / iam_write_statements / permissions_boundaries），
    照旧写法它们全部自动绕过"必须是指纹形态"这条。
    """
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    bad = list(_non_fingerprint_leaves(data))
    assert not bad, f"这些位置出现了形态不对的字符串：{bad}"


def test_all_facts_are_integers():
    """`facts` 的每个值都必须是整数。

    留成"任意字符串"的话，哪天某个 fact 改成资源名/ARN，递归红线会自动放行
    （`_walk_baseline` 只产出字符串，整数走不到检查）。
    """
    facts = json.loads(_BASELINE.read_text(encoding="utf-8"))["facts"]
    for k, v in facts.items():
        assert isinstance(v, int), f"facts.{k} 不是整数而是 {type(v).__name__}: {v!r}"


def test_baseline_redline_scan_catches_an_injected_new_subkey():
    """**元用例**：往基线树里注入新子键，必须被抓到。

    没有这条的话，上面那条在"递归实现其实没递归"时同样是绿的。
    """
    raw = _BASELINE.read_text(encoding="utf-8")
    data = json.loads(raw)
    data["resource_policies"]["brand_new_subkey"] = ["arn:aws:iam::000000000000:role/Sneaky"]
    assert list(_non_fingerprint_leaves(data)), \
        "注入了一个含 ARN 的新子键却没被抓到——递归红线检查是假的"
    data2 = json.loads(raw)
    data2["coverage"] = {"undecided_items": ["not-a-fingerprint"]}
    assert list(_non_fingerprint_leaves(data2)), "非指纹形态的新分节没被抓到"
    data3 = json.loads(raw)
    data3["principals"]["not-a-fingerprint-key"] = {"category": "admin", "grants": []}
    assert list(_non_fingerprint_leaves(data3)), "非指纹形态的 principal **键**没被抓到"


def test_version_id_position_is_type_checked_not_waved_through():
    """`managed_policy_versions` 的值按 **VersionId 形态**校验，不是"任意字符串放行"。

    放行的话，这个位置写成角色名或占位 `"?"` 都过——而它正是用来解释红的那个字段。
    反过来，合法的 `v3` 也必须**不**被当成"非指纹"报红（不装类型分支时它会）。
    """
    ok = {"managed_policy_versions": {"aaaa-bbbb-cccc-dddd": "v3"}}
    assert not list(_non_fingerprint_leaves(ok)), "合法 VersionId 被误报了"
    for bad in ("site-deployer-exec-role", "?", "", "3", "latest"):
        tree = {"managed_policy_versions": {"aaaa-bbbb-cccc-dddd": bad}}
        assert list(_non_fingerprint_leaves(tree)), f"VersionId 位置写成 {bad!r} 却没被抓到"


def test_raw_forbidden_pattern_scan_still_covers_free_text_fields():
    """**两层缺一不可**：`note` / `categories[]` / `category` 是自由文本，
    结构化递归检查刻意不校验它们的形态 ⇒ 只有整文件 raw 扫描能抓住写进 `note` 的
    真实账号 ID 或内部角色名。这条钉住"raw 那层没被递归检查替换掉"。
    """
    raw = _BASELINE.read_text(encoding="utf-8")
    # 第一层：整文件（与 test_baseline_carries_no_account_values 同一组判据）
    for forbidden in ("arn:aws:", "role/", "cdk-hnb659fds", "Isengard"):
        assert forbidden not in raw, f"基线里出现了 {forbidden!r}"
    assert not re.search(r"\b\d{12}\b", raw), "基线里出现了 12 位账号 ID"
    # 第二层对自由文本确实放行 —— 所以第一层不能省
    leaked = json.loads(raw)
    leaked["note"] = "note 里塞一个 arn:aws:iam::000000000000:role/Leak"
    assert not list(_non_fingerprint_leaves(leaked)), (
        "结构化检查竟然抓住了 note —— 那这条用例的前提变了，"
        "重新想一遍两层的分工再改")
