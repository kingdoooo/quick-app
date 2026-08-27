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
import ast
import copy
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


# grant 的**文法**。`principals.*.grants[]` 不整体放行——放行的话，grant 构造失误把
# 完整 ARN / 角色名 / 账号值拼进串里，这一层不会抓。
# `invoke-*` / `replace-*` 后面是平台函数名（`app.py` 里就有，不是账号值）；
# 站点子集带成员指纹 `some(k):<fp>`。
#
# **`some(k)` 那一支本账号当前没有实例**（所有能调站点函数的都是 `:all`），它只由
# `test_site_subset_records_the_count_so_widening_reds` 覆盖——**别因为"基线里没见过"
# 就把它从文法里删掉**，删了之后第一个子集授权出现时会被报成"grant 不合文法"
# 而不是"新增授权"。
_GRANT_RE = re.compile(
    r"(?:invoke-platform|replace-platform-code)(?:@alias|@version)?:[A-Za-z0-9._-]+"
    r"|invoke-site(?:@alias|@version)?:(?:all|some\(\d+\):" + _FP_RE + r")"
    r"|read-edge-code|read-edge-asset|read-jwt-param")


def _is_grant(value: str) -> bool:
    return bool(_GRANT_RE.fullmatch(value))


# 值的**类型分流**：路径模式 → 校验函数。命中这里的位置不做指纹形态检查，
# 而是按它自己的类型校验 —— **这不是放行**。
_TYPED_VALUE_PATHS = (
    # VersionId 形如 v1/v2/…：既不是指纹，也不能是任意字符串（写成角色名或占位
    # "?" 都必须红）。放成"任意字符串"就等于不检查；要求它是指纹又会把合法的 v3 报红。
    ("managed_policy_versions.*", _is_version_id),
    ("principals.*.grants[]", _is_grant),
)
# **自由文本**：说明性字段，这一层不校验形态；泄密由第一层的整文件 raw 扫描兜。
_FREE_TEXT_PATHS = (
    "note", "categories[]",                 # 说明文字与类别词表
    "principals.*.category",                # 类别名
)
# 字典**键**里允许非指纹的位置（结构键名、以及平台函数名）。
_NON_FP_KEY_PATHS = (
    "",                                     # 顶层结构键（schema/note/facts/…）
    "facts",                                # fact 名
    "principals.*",                         # 每个 principal 条目内的 category/grants
    "resource_policies",                    # 结构键（platform/site_*/bootstrap_bucket）
    "resource_policies.platform",           # 键是平台函数名（app.py 里就有，不是账号值）
    # 平台函数按 qualifier 分桶存（扁平集合会让"语句从 alias 挪到 version"与
    # "两个 alias 有相同语句、删掉一个"都不可见）⇒ 多两层结构键。
    "resource_policies.platform.*",         # 结构键（unqualified/alias/version）
    "resource_policies.platform.*.alias",   # 键是 alias 名（blue/green，不是账号值）
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
    """仓库红线**第一层**：整文件 raw 禁用模式扫描——真实账号 ID / 角色名 / ARN
    不进被跟踪文件。

    基线里 CDK bootstrap 那几个角色的名字**内嵌账号 ID**，所以这条不是形式主义：
    照抄角色名就会把账号值提交进仓库。resource policy 的 Principal 同理
    （它是带账号 ID 的角色 ARN），所以那边也只存指纹。

    **只管"值本身不泄密"**。"值出现在正确的结构位置、且是正确的类型"由第二层
    （`_non_fingerprint_leaves`，见 `test_baseline_redline_scan_walks_unknown_keys`）
    负责——原先那半在这里硬编码了 `resource_policies` 的四个列表键，于是新加任何
    子键都自动绕过形态检查，而收缩轮加了四个新分节、平台还改成了按 qualifier 分桶。
    **两层缺一不可**：`note` / `category` 是自由文本，第二层刻意放行，只有这一层能抓
    住写进 `note` 的账号值。
    """
    raw = _BASELINE.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{12}\b", raw), "基线里出现了 12 位账号 ID"
    for forbidden in ("arn:aws:", "role/", "cdk-hnb659fds", "Isengard"):
        assert forbidden not in raw, f"基线里出现了 {forbidden!r}——那是账号内的真实标识"


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

    # 类别名 → 标记里的 slug（标记名不能带连字符以外的怪字符，统一成下划线）
    category_slugs = {"platform": "platform", "platform-overbroad": "platform_overbroad",
                      "admin": "admin", "break-glass": "break_glass",
                      "cdk-admin": "cdk_admin", "cdk-readonly": "cdk_readonly",
                      "unrelated-workload": "unrelated"}
    expected = {
        # ---- A：直接失守（headline）----
        "A总数": len(principals),
        "可读密钥": count(lambda p: secret_grants & set(p["grants"])),
        "非平台可直调": count(
            lambda p: p["category"] != "platform"
            and (has_prefix(p, f"{g.G_INVOKE_PLATFORM}:")
                 or has_prefix(p, f"{g.G_INVOKE_SITE}:"))),
        "带活密钥的asset": data["facts"]["edge_assets_carrying_live_key"],
        "带活密钥的Edge代码目标": data["facts"]["edge_code_targets_carrying_live_key"],
        # ---- B：IAM 写观察。**不进 A 的人数**——"持有一条未证明可提权的 IAM 写语句"
        #      与"现在就能拿密钥"是两种风险，相加当成一个数字正是这一轮要消掉的错误。
        "B持有IAM写语句": len(data["iam_write_statements"]),
        "仅IAM写": len(set(data["iam_write_statements"]) - set(principals)),
        # ---- 按类别：原先是**裸数字**（`无关工作负载` 那个曾经是 38，A 收缩后成了 36），
        #      这一轮全部加上标记，让文档腐烂测得出来。
        **{f"类别_{slug}": count(lambda p, c=cat: p["category"] == c)
           for cat, slug in category_slugs.items()},
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
    """基线 schema 与脚本必须同版本：schema 1 只有布尔能力标签、schema 2 把 IAM 写
    混在 A 的 grant 里，拿它们当基线跑 schema 3 的脚本会把每个 principal 都报成"新增"。

    分节清单也在这里钉死：**少任何一节都等于那一层的检查静默消失**。
    """
    g = _gate()
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert data["schema"] == g.BASELINE_SCHEMA
    for key in ("resource_policies", "facts", "coverage", "principals",
                "iam_write_statements", "permissions_boundaries",
                "managed_policy_versions"):
        assert key in data, f"基线缺顶层分节 {key}"
    for key in ("platform", "site_alias_canonical", "site_version_canonical",
                "site_legacy_canonical", "site_legacy_exempt", "bootstrap_bucket"):
        assert key in data["resource_policies"], f"基线缺 resource_policies.{key}"
    assert "undecided_items" in data["coverage"], "基线缺 coverage.undecided_items"


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
    # 平台形状按 qualifier 分桶（unqualified / alias 逐成员 / version）——
    # 扁平集合下"语句从 alias 挪到 version"与"两个 alias 有相同语句、删掉一个"都不变。
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {"site-panel": {
                        "unqualified": ["aaaa-bbbb-cccc-dddd", "eeee-ffff-0000-1111"],
                        "alias": {}, "version": []}},
                    "site_alias_canonical": [], "site_legacy_exempt": [],
                    "site_legacy_canonical": []}}
    now_rp = {"platform": {"site-panel": {"unqualified": ["aaaa-bbbb-cccc-dddd"],
                                          "alias": {}, "version": []}},
              "sites": {}}
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


# ==========================================================================
# A.2：bootstrap 桶的 bucket policy 静态快照
#
# 这是唯一影响「62 个 principal / 57 个能拿密钥」可信度的洞：
# `SimulatePrincipalPolicy` **对 role 不纳入 resource-based policy**，而 S3 bucket
# policy 单独就能授权读 asset（桶里有 9 个仍带活密钥的对象）。有人往桶上加一条 Allow，
# A 那一层会全绿而实际多了能读签名密钥的人。**丢掉现有的 TLS Deny 同样要红。**
# ==========================================================================

# 刻意不写成 12 位数字**字面量**：`scan_staged_secrets.sh` 按 `[0-9]{12}` 找账号 ID，
# 多一个字面量就多一次要人工解释的"预期命中"，而反复的假阳性会训练出无脑 --allow-hits。
_ACCT = "0" * 12          # 仓库既有的占位账号
_OTHER_ACCT = "9" * 12    # 另一个账号，用来证明**外部**账号 ID 不被归一化

_BUCKET_TLS_DENY = {
    "Sid": "AllowSSLRequestsOnly", "Effect": "Deny", "Principal": "*",
    "Action": "s3:*",
    "Resource": [f"arn:aws:s3:::cdk-assets-{_ACCT}-us-east-1",
                 f"arn:aws:s3:::cdk-assets-{_ACCT}-us-east-1/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}
_BUCKET_ROGUE_ALLOW = {
    "Sid": "oops", "Effect": "Allow",
    "Principal": {"AWS": f"arn:aws:iam::{_ACCT}:role/Rogue"},
    "Action": "s3:GetObject",
    "Resource": f"arn:aws:s3:::cdk-assets-{_ACCT}-us-east-1/*",
}


def _bucket_baseline(g, observed, statements):
    fps = sorted({g.canonical_statement_fp(s, account=_ACCT) for s in statements})
    return {**_baseline_of(observed),
            "resource_policies": {"platform": {}, "site_alias_canonical": [],
                                  "site_version_canonical": [], "site_legacy_canonical": [],
                                  "site_legacy_exempt": [], "bootstrap_bucket": fps}}


def _bucket_rp(g, statements, texts=None):
    return {"platform": {}, "sites": {},
            "bootstrap_bucket": sorted({g.canonical_statement_fp(s, account=_ACCT)
                                        for s in statements}),
            "bootstrap_bucket_texts": texts or {}}


def test_bootstrap_bucket_policy_added_allow_is_a_failure():
    """往 bootstrap 桶上加一条 Allow —— 模拟器这条通道完全看不见（AWS 契约：
    它不自动纳入 resource policy，对 role 更是不支持模拟），只有这份快照能咬住。"""
    g = _gate()
    observed = _with_required(g, {})
    rep = g.compare_to_baseline(
        observed, _bucket_baseline(g, observed, [_BUCKET_TLS_DENY]), required=REQUIRED,
        resource_policies=_bucket_rp(g, [_BUCKET_TLS_DENY, _BUCKET_ROGUE_ALLOW]))
    assert not rep.ok, rep.render()
    assert "bootstrap" in rep.render()


def test_bootstrap_bucket_policy_losing_the_tls_deny_is_a_failure():
    """**消失也红**：删掉那条 TLS Deny 是实实在在的扩权。

    只比"新增"的实现会让这条绿——而整条 bucket policy 被删掉时症状也是"少了语句"。
    """
    g = _gate()
    observed = _with_required(g, {})
    rep = g.compare_to_baseline(
        observed, _bucket_baseline(g, observed, [_BUCKET_TLS_DENY]), required=REQUIRED,
        resource_policies=_bucket_rp(g, []))
    assert not rep.ok, rep.render()


def test_bootstrap_bucket_policy_condition_change_is_a_failure():
    """`Condition` 变了（`SecureTransport false` → `true`，语义整个反过来）必须红。"""
    g = _gate()
    observed = _with_required(g, {})
    flipped = {**_BUCKET_TLS_DENY, "Condition": {"Bool": {"aws:SecureTransport": "true"}}}
    rep = g.compare_to_baseline(
        observed, _bucket_baseline(g, observed, [_BUCKET_TLS_DENY]), required=REQUIRED,
        resource_policies=_bucket_rp(g, [flipped]))
    assert not rep.ok, rep.render()


def test_canonical_statement_fp_ignores_sid_and_array_order():
    """改个 `Sid` 不是授权变化（留着只制造噪音）；数组顺序也不是。"""
    g = _gate()
    a = g.canonical_statement_fp(_BUCKET_TLS_DENY, account=_ACCT)
    b = g.canonical_statement_fp({**_BUCKET_TLS_DENY, "Sid": "renamed"}, account=_ACCT)
    c = g.canonical_statement_fp(
        {**_BUCKET_TLS_DENY, "Resource": list(reversed(_BUCKET_TLS_DENY["Resource"]))},
        account=_ACCT)
    assert a == b == c
    assert re.fullmatch(_FP_RE, a)


def test_current_account_id_is_normalized():
    """**当前**账号 ID 必须归一化掉：否则换个账号跑同一份基线会全量漂移，
    而且账号原值会进指纹的输入。"""
    g = _gate()
    here = g.canonical_statement_fp(_BUCKET_TLS_DENY, account=_ACCT)
    # 同一条语句整体搬到另一个账号，并以那个账号为"当前账号"归一化 ⇒ 同指纹
    moved = json.loads(json.dumps(_BUCKET_TLS_DENY).replace(_ACCT, _OTHER_ACCT))
    there = g.canonical_statement_fp(moved, account=_OTHER_ACCT)
    assert here == there, "当前账号 ID 没被归一化——换账号跑就会全量漂移"
    assert _ACCT not in here and _OTHER_ACCT not in here


def test_changing_to_an_external_account_changes_the_fingerprint():
    """**只归一化当前账号**：语句里出现**另一个**账号的 principal 是重要漂移，必须改指纹。

    把所有 12 位数字都替换成 `<acct>` 的写法，会让"授权给外部账号"与"授权给本账号"
    变成同一个指纹——而跨账号信任被引入的那一刻，正是这道闸门最该红的时候。
    """
    g = _gate()
    here = g.canonical_statement_fp(_BUCKET_ROGUE_ALLOW, account=_ACCT)
    external = {**_BUCKET_ROGUE_ALLOW,
                "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCT}:role/Rogue"}}
    assert g.canonical_statement_fp(external, account=_ACCT) != here, \
        "换成外部账号的 principal 却是同一个指纹——跨账号信任的引入会静静地绿"


def test_fingerprint_and_text_share_one_canonicalization():
    """指纹相同的两条语句，人读原文也必须相同。

    两边各自归一化时，「只排顶层键」的文本会随 AWS 返回的数组顺序变化 ⇒
    双跑 `--dump-observed` 的 `texts` 出现无意义 diff，而确定性检查会误报
    「快照不确定」，把人引去查根本不存在的不确定性。
    """
    g = _gate()
    a = {"Effect": "Allow", "Action": ["iam:PutRolePolicy", "iam:AttachRolePolicy"],
         "Resource": "*"}
    b = {"Effect": "Allow", "Action": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
         "Resource": "*"}
    assert g.canonical_statement_fp(a, account=_ACCT) \
        == g.canonical_statement_fp(b, account=_ACCT)
    assert g.canonical_statement_text(a, account=_ACCT) \
        == g.canonical_statement_text(b, account=_ACCT), \
        "指纹相同而文本不同 ⇒ 双跑 dump 的 texts 会漂移，确定性检查会误报"


def test_report_prints_normalized_statement_for_each_diff():
    """报文要打印**归一化后的语句原文**（运行时 stdout，不落仓库），
    否则人拿到一串指纹无从判断该不该更新基线——那就会训练出无脑更新。"""
    g = _gate()
    observed = _with_required(g, {})
    rogue_fp = g.canonical_statement_fp(_BUCKET_ROGUE_ALLOW, account=_ACCT)
    rp = _bucket_rp(g, [_BUCKET_TLS_DENY, _BUCKET_ROGUE_ALLOW],
                    texts={rogue_fp: g.canonical_statement_text(_BUCKET_ROGUE_ALLOW,
                                                                account=_ACCT)})
    rep = g.compare_to_baseline(
        observed, _bucket_baseline(g, observed, [_BUCKET_TLS_DENY]), required=REQUIRED,
        resource_policies=rp)
    assert "s3:GetObject" in rep.render(), "报文里没有语句原文"
    assert _ACCT not in rep.render(), "报文里出现了当前账号 ID 原值"


# ==========================================================================
# A.3：coverage 从 principal 级降到 **item 级**
#
# 反例（必须钉住）：P 原本只对 site-a 的 Invoke 判不出，后来对 jwt-secret 的
# `GetParameters` 也判不出 —— 按 **principal 集合**前后都是 `{P}` ⇒ 绿，
# 而**新增的密钥读取不确定面没被发现**。
#
# 这**不是** `facts.principals_with_missing_context`（162 那个笼统计数）：那个继续
# 只报 delta、不参与红绿，因为它会随账号里任何一条带 Condition 的新策略变动。
# ==========================================================================

def test_undecided_pairs_is_a_superset_of_the_old_boolean():
    """**正对照（带前提）**：旧 `missing_context_in` 为真、**且存在至少一个非 allowed
    的结果**时，新的 item 级集合不得为空。

    前提是必需的，不能写成无条件的超集性质：顶层带 `MissingContextValues` 而逐资源
    **全是 allowed** 时，旧 bool 为真而新集合**正确地**为空（每个资源都已经有答案，
    不属于"判不出"）。见下面那条反例用例。把性质写得过强，下一位维护者会照它去
    "修" coverage，把已判定的资源也收进来，于是 coverage 变成纯噪音。

    另一头也踩过：细化成 (动作, 资源) 时若只在 `ResourceSpecificResults` 为空时才看
    顶层，「顶层带、逐资源条目自己不带」这一形态会返回空集，而旧 bool 返回 True
    ⇒ 判据相对现状**倒退**。
    """
    g = _gate()
    shapes = [
        # ① 只有顶层带（无逐资源结果）
        [{"EvalActionName": "s3:GetObject", "EvalDecision": "implicitDeny",
          "MissingContextValues": ["aws:SourceVpc"]}],
        # ② 只有逐资源带
        [{"EvalActionName": "s3:GetObject", "EvalDecision": "implicitDeny",
          "ResourceSpecificResults": [
              {"EvalResourceName": "a", "EvalResourceDecision": "implicitDeny",
               "MissingContextValues": ["aws:ResourceTag/x"]}]}],
        # ③ **顶层带 + 有逐资源结果但逐资源自己不带** ← 最容易漏的就是这个
        [{"EvalActionName": "iam:PutRolePolicy", "EvalDecision": "implicitDeny",
          "MissingContextValues": ["aws:PrincipalTag/x"],
          "ResourceSpecificResults": [
              {"EvalResourceName": "target-a", "EvalResourceDecision": "implicitDeny"}]}],
    ]

    def has_non_allowed(shape):
        return any(rr.get("EvalResourceDecision") != "allowed"
                   for r in shape for rr in (r.get("ResourceSpecificResults") or [])) \
            or any(not r.get("ResourceSpecificResults")
                   and r.get("EvalDecision") != "allowed" for r in shape)

    for i, shape in enumerate(shapes, 1):
        assert g.missing_context_in(shape), f"形态 {i} 的正对照前提不成立（旧 bool 该为真）"
        assert has_non_allowed(shape), f"形态 {i} 的前提不成立（该有非 allowed 的结果）"
        assert g.undecided_pairs(shape), \
            f"形态 {i}：旧 bool 说有不确定、且存在非 allowed 结果，新的 item 级集合却是空 " \
            f"⇒ 判据相对现状倒退了"


def test_all_allowed_resources_are_not_undecided_even_with_top_level_missing_context():
    """**上一条那个前提的反例**：顶层带 `MissingContextValues`，但逐资源**全是 allowed**
    ⇒ 新集合正确地为空，而旧 bool 为真。

    这条把"超集性质有前提"钉成可执行的：没有它，有人会照上一条的名字去掉前提，
    把已判定的资源也收进 coverage，于是每次跑都新增一堆成员、闸门变成纯噪音。
    """
    g = _gate()
    shape = [{"EvalActionName": "s3:GetObject", "EvalDecision": "allowed",
              "MissingContextValues": ["aws:SourceVpc"],
              "ResourceSpecificResults": [
                  {"EvalResourceName": "a", "EvalResourceDecision": "allowed"},
                  {"EvalResourceName": "b", "EvalResourceDecision": "allowed"}]}]
    assert g.missing_context_in(shape), "反例的前提是旧 bool 为真"
    assert g.undecided_pairs(shape) == set(), \
        "已经 allowed 的资源被算进了「判不出」⇒ coverage 变成噪音"


def test_differing_missing_keys_keep_the_resource_dimension():
    """键集在资源之间**不同**时，资源维度确实带信息 ⇒ 逐资源记。

    例如 `aws:ResourceTag/x` 这种真正按资源取值的条件键：只有某个资源缺它，
    折叠掉就会把"只对这一个资源判不出"与"对全部资源判不出"混成一件事。
    """
    g = _gate()
    pairs = g.undecided_pairs([{
        "EvalActionName": "lambda:InvokeFunction", "EvalDecision": "implicitDeny",
        "ResourceSpecificResults": [
            {"EvalResourceName": "target-a", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:ResourceTag/env"]},
            {"EvalResourceName": "target-b", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:ResourceTag/env", "aws:ResourceTag/tier"]},
        ]}])
    assert pairs == {("lambda:InvokeFunction", "target-a"),
                     ("lambda:InvokeFunction", "target-b")}, pairs


def test_allowed_resources_never_enter_even_when_others_are_undecided():
    """allowed 的资源不算"判不出"，哪怕同一 action 下别的资源判不出。"""
    g = _gate()
    pairs = g.undecided_pairs([{
        "EvalActionName": "lambda:InvokeFunction", "EvalDecision": "implicitDeny",
        "ResourceSpecificResults": [
            {"EvalResourceName": "yes", "EvalResourceDecision": "allowed",
             "MissingContextValues": ["aws:ResourceTag/env"]},
            {"EvalResourceName": "no-a", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:ResourceTag/env"]},
            {"EvalResourceName": "no-b", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:ResourceTag/env", "x:y"]},
        ]}])
    assert ("lambda:InvokeFunction", "yes") not in pairs, "allowed 的资源被算成判不出"
    assert pairs == {("lambda:InvokeFunction", "no-a"), ("lambda:InvokeFunction", "no-b")}


def test_undecided_pairs_ignores_decided_resources():
    """判据是"非 allowed **且**（自己带 或 顶层带）MissingContextValues"。

    allowed 的项不是"判不出"；两边都不带 MissingContextValues 的 implicitDeny
    是"确认没有"。把这两类收进来会让 coverage 变成噪音。
    """
    g = _gate()
    pairs = g.undecided_pairs([{
        "EvalActionName": "ssm:GetParameters", "EvalDecision": "implicitDeny",
        "EvalResourceName": "arn:aws:ssm:${Region}:${Account}:parameter",
        "ResourceSpecificResults": [
            {"EvalResourceName": "p1", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:PrincipalTag/x"]},
            {"EvalResourceName": "p2", "EvalResourceDecision": "implicitDeny"},
            {"EvalResourceName": "p3", "EvalResourceDecision": "allowed",
             "MissingContextValues": ["aws:PrincipalTag/y"]},
        ]}])
    assert pairs == {("ssm:GetParameters", "p1")}, pairs


def test_undecided_pairs_never_emits_an_arn_template():
    """顶层的 `${Region}` 模板归不到具体资源 ⇒ 老实记 unattributed，
    不要硬塞一个不存在的 ARN（那会造出一个永远存在的假成员）。"""
    g = _gate()
    pairs = g.undecided_pairs([{
        "EvalActionName": "s3:GetObject",
        "EvalResourceName": "arn:aws:s3:::${BucketName}",
        "EvalDecision": "implicitDeny",
        "MissingContextValues": ["aws:SourceVpc"]}])
    assert pairs == {("s3:GetObject", "")}
    assert not any("${" in r for _a, r in pairs)


def test_same_principal_gaining_a_second_undecided_target_is_a_failure():
    """同一个 principal 多出一项判不出的目标必须红。

    按 principal 集合比时前后都是 {P} ⇒ 绿，而新增的那项恰好是**密钥读取**。
    """
    g = _gate()
    observed = _with_required(g, {})
    arn = "arn:aws:iam::1:role/WorkloadA"
    before = [g.undecided_item_fp(arn, "invoke", "sites")]
    after = before + [g.undecided_item_fp(arn, "read-param", "jwt-param")]
    baseline = {**_baseline_of(observed), "coverage": {"undecided_items": sorted(before)}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                coverage={"undecided_items": sorted(after)})
    assert not rep.ok, rep.render()


def test_undecided_item_swap_is_a_failure_even_when_principal_set_is_unchanged():
    """成员换了但数量与 principal 集合都没变 ⇒ 仍要红。"""
    g = _gate()
    observed = _with_required(g, {})
    arn = "arn:aws:iam::1:role/WorkloadA"
    before = [g.undecided_item_fp(arn, "invoke", "sites")]
    after = [g.undecided_item_fp(arn, "read-object", "edge-asset")]
    assert len(before) == len(after), "这条用例的前提是数量不变"
    baseline = {**_baseline_of(observed), "coverage": {"undecided_items": before}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                coverage={"undecided_items": after})
    assert not rep.ok, rep.render()


def test_undecided_item_disappearing_is_an_improvement_not_a_failure():
    g = _gate()
    observed = _with_required(g, {})
    arn = "arn:aws:iam::1:role/WorkloadA"
    baseline = {**_baseline_of(observed),
                "coverage": {"undecided_items": [g.undecided_item_fp(arn, "invoke", "sites")]}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                coverage={"undecided_items": []})
    assert rep.ok, rep.render()
    assert rep.improvements


def test_undecided_count_is_only_a_doc_summary():
    """`principals_with_missing_context`（162 那个）继续只报 delta、不参与红绿。

    它会随账号里任何一条带 Condition 的新策略变动 ⇒ 让它决定退出码就会训练出
    无脑更新基线。红绿由 item 级集合负责。
    """
    g = _gate()
    observed = _with_required(g, {})
    baseline = {**_baseline_of(observed),
                "facts": {"principals_with_missing_context": 162},
                "coverage": {"undecided_items": []}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED,
                                facts={"principals_with_missing_context": 200},
                                coverage={"undecided_items": []})
    assert rep.ok, "这个数不该影响退出码"
    assert "+38" in rep.render()


def test_undecided_resource_class_folds_sites_but_not_platform_functions():
    """站点函数折叠成 `sites`（逐站点会让每次建站都改基线）；
    平台函数保留精确名字——「对 site-panel 判不出」与「对 undeploy 判不出」不是一回事。

    限定符（alias/version）刻意折叠掉：版本号每次部署都变，带上它会让 coverage
    每次部署漂移。
    """
    g = _gate()
    t = _targets(g)
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    assert g.undecided_resource_class(fn("site-a"), t) == "sites"
    assert g.undecided_resource_class(fn("site-b"), t) == "sites"
    assert g.undecided_resource_class(fn("site-panel"), t) == "fn:site-panel"
    assert g.undecided_resource_class(fn("site-panel") + ":blue", t) == "fn:site-panel"
    assert g.undecided_resource_class(t.jwt_parameter, t) == "jwt-param"
    assert g.undecided_resource_class(t.edge_assets[0], t) == "edge-asset"
    assert g.undecided_resource_class("", t) == "unattributed"


def test_undecided_item_fp_carries_no_principal_name():
    g = _gate()
    fp = g.undecided_item_fp(f"arn:aws:iam::{_ACCT}:role/Secret", "invoke", "sites")
    assert re.fullmatch(_FP_RE, fp)
    assert "Secret" not in fp and _ACCT not in fp


# ==========================================================================
# A.1 + B（**一个原子提交**）
#
# A.1：`iam-policy-write` 从 A 的 grant 词表移除。
# B：IAM 写改成**纯静态文本快照**——收 role/user/group 的 inline + attached 托管 +
#    permissions boundary，Allow 与 Deny 都收，任何 added/removed/changed 都红。
#
# 为什么必须同一个提交：移除 grant 而 B 还没上线 = 静默丢掉 22 个 principal 的覆盖，
# 那是一个自己造出来的 false-green。
#
# B **明确不声称**：某条语句是否生效、是否构成提权链、变化方向是收紧还是放宽。
# 原先那套「静态发现候选 → 模拟器对具体 ARN 确认 → 三值分类」已删除：它要求闸门回答
# "谁能提权"，而那等于要造一个 IAM 权限分析器（statement 归因、Condition 语义、
# NotResource 集合代数、policy variable、SourcePolicyType 碰撞——每修一维下一维才暴露），
# 这是这道闸门被前五轮复审反复点名的根因。
# ==========================================================================

def test_no_grant_path_produces_iam_policy_write():
    """**行为断言**（不是 grep）：把所有探测资源都设成 allowed，
    grant 生成路径的最大输出里也不许出现 `iam-policy-write`。"""
    g = _gate()
    t = _targets(g)
    everything = {f"{a}|{r}": "allowed" for a in g.ACTIONS
                  for r in (t.function_resources() + t.other_resources())}
    grants = g.grants_from_decisions(everything, t)
    assert grants, "正对照失效：全 allowed 却没产生任何 grant"
    assert not any(x.startswith("iam-policy-write") for x in grants), sorted(grants)
    assert not hasattr(g, "G_IAM_POLICY_WRITE"), "A 的 grant 常量还在"


def test_the_legacy_grant_string_exists_only_for_migration():
    """迁移代码**必须**能识别旧 grant 串，所以不能断言全文不含它——
    但这个字面量只许出现在那一个 legacy 常量上。

    用 AST 而不是 grep：注释与"提到它"的 docstring 不该让这条红。
    """
    import ast
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    holders = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and node.value.value == "iam-policy-write"):
            holders |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    assert holders == {"LEGACY_IAM_POLICY_WRITE_PREFIX"}, holders
    exact = [n for n in ast.walk(tree)
             if isinstance(n, ast.Constant) and n.value == "iam-policy-write"]
    assert len(exact) == 1, f"这个字面量出现了 {len(exact)} 次，只许在 legacy 常量上"


# ---- B 的红绿：任何 added / removed / changed 都红 ------------------------

def _iam_stmt(effect="Allow", action="iam:PutRolePolicy", resource="*", **extra):
    return {"Effect": effect, "Action": action, "Resource": resource, **extra}


def _fps(g, statements):
    return sorted({g.canonical_statement_fp(s, account=_ACCT) for s in statements})


def _b_baseline(g, observed, per_principal, *, boundaries=None, versions=None):
    return {**_baseline_of(observed),
            "iam_write_statements": {fp: sorted(v) for fp, v in per_principal.items()},
            "permissions_boundaries": boundaries or {},
            "managed_policy_versions": versions or {}}


def _b_now(statements=None, boundaries=None, versions=None, texts=None):
    return {"statements": statements or {}, "boundaries": boundaries or {},
            "managed_versions": versions or {}, "texts": texts or {}}


def test_new_iam_write_statement_is_a_failure():
    g = _gate()
    observed = _with_required(g, {})
    base = {"aaaa-bbbb-cccc-dddd": _fps(g, [_iam_stmt()])}
    now = {"aaaa-bbbb-cccc-dddd": _fps(g, [_iam_stmt(),
                                           _iam_stmt(action="iam:AttachUserPolicy")])}
    rep = g.compare_to_baseline(observed, _b_baseline(g, observed, base),
                                required=REQUIRED, iam_write=_b_now(now))
    assert not rep.ok, rep.render()


def test_removing_a_relevant_deny_statement_is_a_failure():
    """**这条是 B 存在的核心理由**：`Allow iam:* on *` + `Deny PutRolePolicy on EdgeRole`，
    删掉那条 Deny 之后 **Allow 集合完全没变** ⇒ 只收 Allow 的旧设计全绿，
    而那是实实在在的扩权。"""
    g = _gate()
    observed = _with_required(g, {})
    allow = _iam_stmt(action="iam:*")
    deny = _iam_stmt(effect="Deny", resource=f"arn:aws:iam::{_ACCT}:role/EdgeRole")
    rep = g.compare_to_baseline(
        observed, _b_baseline(g, observed, {"aaaa-bbbb-cccc-dddd": _fps(g, [allow, deny])}),
        required=REQUIRED,
        iam_write=_b_now({"aaaa-bbbb-cccc-dddd": _fps(g, [allow])}))
    assert not rep.ok, rep.render()


def test_removing_an_allow_statement_is_also_a_failure_not_an_improvement():
    """Allow **消失**也红。它不等于收紧：语句可能被拆成两条更宽的、可能从 inline 挪到
    另一份 policy，也可能是**解析器漏收了**。把"旧指纹消失"自动判成改善，
    正好会把解析器退化显示成好消息。"""
    g = _gate()
    observed = _with_required(g, {})
    base = {"aaaa-bbbb-cccc-dddd": _fps(g, [_iam_stmt(),
                                            _iam_stmt(action="iam:AttachRolePolicy")])}
    rep = g.compare_to_baseline(
        observed, _b_baseline(g, observed, base), required=REQUIRED,
        iam_write=_b_now({"aaaa-bbbb-cccc-dddd": _fps(g, [_iam_stmt()])}))
    assert not rep.ok, rep.render()
    assert not rep.improvements, "语句消失被判成了改善"


def test_new_deny_statement_is_visible_in_snapshot():
    g = _gate()
    deny = _iam_stmt(effect="Deny", action="iam:PutRolePolicy")
    assert g.relevant_iam_statements([deny]) == [deny], "Deny 没进快照"


def test_changing_a_deny_condition_is_a_failure():
    g = _gate()
    observed = _with_required(g, {})
    d1 = _iam_stmt(effect="Deny", Condition={"StringEquals": {"aws:PrincipalTag/env": "prod"}})
    d2 = _iam_stmt(effect="Deny", Condition={"StringEquals": {"aws:PrincipalTag/env": "dev"}})
    rep = g.compare_to_baseline(
        observed, _b_baseline(g, observed, {"aaaa-bbbb-cccc-dddd": _fps(g, [d1])}),
        required=REQUIRED, iam_write=_b_now({"aaaa-bbbb-cccc-dddd": _fps(g, [d2])}))
    assert not rep.ok, rep.render()


def test_statement_fingerprint_is_sensitive_to_not_resource_membership():
    """`NotResource` 成员**增或减都是新指纹 ⇒ 都红**。

    不做方向推断（"NotResource 变少 = 收紧"这类判断需要集合代数 + Condition 语义，
    正是本轮删掉的那套）。宁可两个方向都红。
    """
    g = _gate()
    base = {"Effect": "Allow", "Action": "iam:*"}          # 刻意不带 Resource
    one = {**base, "NotResource": [f"arn:aws:iam::{_ACCT}:role/A"]}
    two = {**base, "NotResource": [f"arn:aws:iam::{_ACCT}:role/A",
                                   f"arn:aws:iam::{_ACCT}:role/B"]}
    assert g.canonical_statement_fp(one, account=_ACCT) \
        != g.canonical_statement_fp(two, account=_ACCT), \
        "NotResource 成员被排除出指纹 ⇒ 增删都不会红"


def test_boundary_removal_is_a_failure():
    """**per-site 隔离整个建立在 boundary 上** ⇒ boundary 消失必须红，不是收紧。"""
    g = _gate()
    observed = _with_required(g, {})
    b = {"aaaa-bbbb-cccc-dddd": {"policy_fp": "eeee-ffff-0000-1111",
                                 "stmt_fps": ["1111-2222-3333-4444"]}}
    rep = g.compare_to_baseline(observed, _b_baseline(g, observed, {}, boundaries=b),
                                required=REQUIRED, iam_write=_b_now())
    assert not rep.ok, rep.render()


def test_boundary_statement_change_is_a_failure():
    g = _gate()
    observed = _with_required(g, {})
    b = {"aaaa-bbbb-cccc-dddd": {"policy_fp": "eeee-ffff-0000-1111",
                                 "stmt_fps": ["1111-2222-3333-4444"]}}
    now = {"aaaa-bbbb-cccc-dddd": {"policy_fp": "eeee-ffff-0000-1111",
                                   "stmt_fps": ["1111-2222-3333-5555"]}}
    rep = g.compare_to_baseline(observed, _b_baseline(g, observed, {}, boundaries=b),
                                required=REQUIRED, iam_write=_b_now(boundaries=now))
    assert not rep.ok, rep.render()


def test_managed_policy_version_change_is_reported_with_the_version_id():
    """AWS 更新托管策略这类红要**自解释**，否则人只看到一串指纹变了就会无脑更新基线。"""
    g = _gate()
    observed = _with_required(g, {})
    base = _b_baseline(g, observed, {"aaaa-bbbb-cccc-dddd": ["1111-2222-3333-4444"]},
                       versions={"eeee-ffff-0000-1111": "v3"})
    rep = g.compare_to_baseline(
        observed, base, required=REQUIRED,
        iam_write=_b_now({"aaaa-bbbb-cccc-dddd": ["1111-2222-3333-5555"]},
                         versions={"eeee-ffff-0000-1111": "v4"}))
    assert not rep.ok
    assert "v3" in rep.render() and "v4" in rep.render(), "版本变化没被打出来，红不自解释"


def test_iam_write_snapshot_does_not_call_the_simulator():
    """守住"B 是纯静态"：任何人日后把模拟器塞回来，归因/三态那一整套问题就回来了。"""
    g = _gate()
    src = _SCRIPT.read_text(encoding="utf-8")
    for gone in ("confirm_iam_write", "iam_write_grants_from_probes", "concrete_target",
                 "_PROBE_SUFFIX", "IAM_WRITE_RESOURCE_KIND",
                 "iam_write_candidates_from_statements"):
        assert gone not in src, f"{gone} 还在——B 应该是纯静态的"
    # 按**调用点**计数，不按字符串出现次数（注释里提一句不该让这条红）。
    # 实测：改动前这个 regex 命中 2 处（confirm_iam_write 的直调 + simulate() 的分页器），
    # 删掉前者之后只剩 A 的 simulate() 那一处。
    calls = re.findall(r'(?:get_paginator\("|\.)simulate_principal_policy', src)
    assert len(calls) == 1, f"模拟器调用点有 {len(calls)} 处 —— B 里塞回模拟器了？"


# ---- fail-closed：托管策略文档/版本不许静默跳过 --------------------------

def test_missing_attached_managed_policy_document_hard_fails():
    """attached 托管策略的文档缺席时**必须硬失败**。

    静默跳过整份 policy 的输出，与"这份 policy 里没有相关 IAM 写语句"**一模一样**
    ⇒ B 的快照 false-green。boundary 已经按这条规则办，普通 attached 不能两套宽严。
    """
    g = _gate()
    arn = f"arn:aws:iam::{_ACCT}:policy/Gone"
    detail = {"RoleName": "R", "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
              "RolePolicyList": [], "AttachedManagedPolicies": [{"PolicyArn": arn}]}
    with pytest.raises(SystemExit) as exc:
        g.statements_for_entity(detail, "RolePolicyList", managed={}, versions={})
    assert arn in str(exc.value)


def test_missing_managed_policy_version_hard_fails():
    """版本未知时不许拿 "?" 兜底写进基线——那等于把"不知道"记成一个值。"""
    g = _gate()
    arn = f"arn:aws:iam::{_ACCT}:policy/NoVersion"
    detail = {"RoleName": "R", "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
              "RolePolicyList": [], "AttachedManagedPolicies": [{"PolicyArn": arn}]}
    with pytest.raises(SystemExit):
        g.statements_for_entity(detail, "RolePolicyList",
                                managed={arn: {"Statement": []}}, versions={})


def test_statements_carry_their_source_policy_arn():
    """语句必须带来源，`managed_policy_versions` 才能只记**贡献了相关语句**的那几份。

    账号里实测有 300 份托管策略；全记进基线的话，AWS 每更新任意一份都会红一次，
    而那种噪音会训练出无脑更新基线。
    """
    g = _gate()
    arn = f"arn:aws:iam::{_ACCT}:policy/Contributing"
    other = f"arn:aws:iam::{_ACCT}:policy/Irrelevant"
    detail = {"RoleName": "R", "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
              "RolePolicyList": [{"PolicyName": "p",
                                  "PolicyDocument": {"Statement": [_iam_stmt()]}}],
              "AttachedManagedPolicies": [{"PolicyArn": arn}, {"PolicyArn": other}]}
    managed = {arn: {"Statement": [_iam_stmt(action="iam:AttachRolePolicy")]},
               other: {"Statement": [_iam_stmt(action="s3:GetObject")]}}
    versions = {arn: "v2", other: "v1"}
    got = g.statements_for_entity(detail, "RolePolicyList", managed=managed,
                                  versions=versions)
    contributing = {src for src, st in got if g.is_relevant_iam_statement(st)}
    assert contributing == {None, arn}, f"贡献者应只有 inline 与 {arn}，实际 {contributing}"


# ---- F4：动作 glob（B 唯一的漏报入口）------------------------------------

def test_middle_wildcard_action_expands():
    """**实测**：旧实现只处理尾部 `*`，`iam:*RolePolicy` 返回**空集**
    ⇒ 那条语句整个漏不进快照，闸门跑绿。"""
    g = _gate()
    assert g.expand_relevant_actions(["iam:*RolePolicy"]) == {
        a for a in g.IAM_WRITE_ACTIONS if a.endswith("RolePolicy")}
    assert g.expand_relevant_actions(["iam:*PolicyVersion"]) == {
        a for a in g.IAM_WRITE_ACTIONS if a.endswith("PolicyVersion")}
    assert g.expand_relevant_actions(["iam:Attach?olePolicy"]) == {"iam:AttachRolePolicy"}


def test_action_glob_is_case_insensitive_both_ways():
    """模式与动作名的大小写都不该影响匹配（IAM 的动作名是大小写不敏感的）。

    期望值**从动作类推导**而不是写死：`iam:putrole*` 现在同时命中 `PutRolePolicy` 与
    `PutRolePermissionsBoundary`，写死一个就会在往类里加成员时红在无关的地方。
    """
    g = _gate()
    assert g.expand_relevant_actions(["IAM:PUTROLEPOLICY"]) == {"iam:PutRolePolicy"}
    assert g.expand_relevant_actions(["iam:putrole*"]) == {
        a for a in g.IAM_WRITE_ACTIONS if a.lower().startswith("iam:putrole")}
    assert len(g.expand_relevant_actions(["iam:putrole*"])) >= 2, \
        "前缀通配只命中一个？动作类里该有 PutRolePolicy 与 PutRolePermissionsBoundary"


def test_action_expansion_is_a_superset_of_an_independent_oracle():
    """**独立 oracle**：历史上测试复刻了实现的假设，于是实现和测试一起绿。

    这条不复用 fnmatch——它把 IAM 的通配语义直接翻成正则（`*`→`.*`、`?`→`.`），
    再断言实现是它的**超集**。欠匹配（= 语句漏进快照 = false-green）会被抓住；
    过匹配（fnmatch 把 `[seq]` 当字符类）是安全方向，允许。
    """
    g = _gate()

    def oracle(pattern):
        rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                     for c in pattern)
        return {a for a in g.IAM_WRITE_ACTIONS
                if re.fullmatch(rx, a, flags=re.IGNORECASE)}

    for pattern in ("*", "iam:*", "iam:Put*", "iam:*RolePolicy", "iam:*PolicyVersion",
                    "iam:*PermissionsBoundary", "iam:Set*", "*Policy", "iam:?ut*",
                    "IAM:*ROLE*", "s3:GetObject", "iam:PutRolePolicy"):
        got, want = g.expand_relevant_actions([pattern]), oracle(pattern)
        assert got >= want, f"{pattern!r} 欠匹配：漏了 {sorted(want - got)}"


def test_not_action_excluding_iam_write_yields_nothing():
    """`Allow NotAction iam:*` 明确排除了全部 IAM 写动作 ⇒ 不该进快照。

    旧实现对任何 `NotAction` 一律保守算全命中，把"明确排除了 iam:*"也拖进来——
    噪音换不来信号。补集算得出来时就算准的。
    """
    g = _gate()
    assert g.relevant_iam_statements(
        [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]) == []
    wide = {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}
    assert g.relevant_iam_statements([wide]) == [wide], "NotAction s3:* 命中全部 IAM 写动作"


# ---- F6：group 策略 -------------------------------------------------------

def test_group_inline_policy_enters_the_snapshot():
    """用户经 group 拿到的 IAM 写语句必须进 B 的快照。

    **只影响 B**：A 走 `SimulatePrincipalPolicy(PolicySourceArn=user)`，
    模拟器本来就评估 group 策略。**实测账号内 0 个 group ⇒ 基线不变**，
    但缺了这一层，哪天建了 group 就是一个静默的漏报口。
    """
    g = _gate()
    detail = {"UserName": "U", "Arn": f"arn:aws:iam::{_ACCT}:user/U",
              "GroupList": ["Admins"], "UserPolicyList": [], "AttachedManagedPolicies": []}
    groups = {"Admins": {"GroupName": "Admins",
                         "GroupPolicyList": [{"PolicyName": "p",
                                              "PolicyDocument": {"Statement": [_iam_stmt()]}}],
                         "AttachedManagedPolicies": []}}
    got = g.statements_for_user(detail, groups=groups, managed={}, versions={})
    assert (None, _iam_stmt()) in got, "group 的 inline 策略没被并进用户语句"


def test_group_managed_policy_enters_the_snapshot():
    g = _gate()
    arn = f"arn:aws:iam::{_ACCT}:policy/GroupManaged"
    detail = {"UserName": "U", "Arn": f"arn:aws:iam::{_ACCT}:user/U",
              "GroupList": ["Admins"], "UserPolicyList": [], "AttachedManagedPolicies": []}
    groups = {"Admins": {"GroupName": "Admins", "GroupPolicyList": [],
                         "AttachedManagedPolicies": [{"PolicyArn": arn}]}}
    got = g.statements_for_user(detail, groups=groups,
                                managed={arn: {"Statement": [_iam_stmt()]}},
                                versions={arn: "v1"})
    assert (arn, _iam_stmt()) in got, "group 附加的托管策略没被并进用户语句"


# ---- 三个新动作各一条只命中该新成员的用例 --------------------------------

@pytest.mark.parametrize("action", ["iam:SetDefaultPolicyVersion",
                                    "iam:PutRolePermissionsBoundary",
                                    "iam:DeleteRolePermissionsBoundary"])
def test_new_iam_write_action_is_in_the_class(action):
    """往动作等价类里加成员时，同时加一条**只命中该新成员**的用例。

    `SetDefaultPolicyVersion`：不改任何语句就能把托管策略切到另一个版本。
    `Put/DeleteRolePermissionsBoundary`：**per-site 隔离整个建立在 boundary 上**，
    能改 boundary 就等于能拆掉那道隔离。
    """
    g = _gate()
    assert action in g.IAM_WRITE_ACTIONS
    assert g.expand_relevant_actions([action]) == {action}
    st = _iam_stmt(action=action)
    assert g.relevant_iam_statements([st]) == [st]


# ==========================================================================
# schema 3：loader / 一次性迁移 / dump 纯观测，以及红线的收紧
#
# **时序是这一步最容易搞错的地方**（第 1 版计划就死在这里）：
# 新版本校验 + 旧数据 + 用旧数据生成新数据，三者同时在场。所以
# `--dump-observed` 必须是**纯观测**——不读基线、不比较，否则迁移期第一次跑它就会被
# 自己的 schema 校验挡死，**而那次 dump 正是迁移的输入**。
# ==========================================================================

def test_dump_mode_does_not_require_an_existing_current_schema_baseline():
    """`--dump-observed` 单独用时是**纯观测**：不读基线。

    迁移期第一次跑它时，仓库里的基线还是旧 schema；若在发 AWS 调用前就硬校验，
    dump 根本产不出来——而 dump 正是迁移的输入。这是第 1 版计划里的死锁。
    """
    import argparse
    g = _gate()
    pure_dump = argparse.Namespace(dump_observed="/tmp/x.json", update_baseline=False)
    assert not g.wants_baseline(pure_dump), \
        "纯 dump 模式仍去读基线 ⇒ 迁移期第一次 dump 会被旧 schema 挡死"
    assert g.wants_baseline(argparse.Namespace(dump_observed=None, update_baseline=False)), \
        "出闸门结论时必须读基线"
    assert g.wants_baseline(argparse.Namespace(dump_observed="/tmp/x.json",
                                              update_baseline=True)), \
        "要写基线时必须先读（category 要沿用）"


def test_old_baseline_schema_hard_fails(tmp_path):
    """拿 schema 2 的基线跑 schema 3 的脚本必须**硬失败**，不能开跑。

    没有运行时校验时，版本不对的症状是"每个 principal 都报成新增"——一屏红，
    而真因只是版本不匹配。
    """
    g = _gate()
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"schema": 2, "principals": {}}), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        g.load_baseline(p)
    assert "--migrate-from-schema" in str(exc.value)


def test_migration_only_accepts_schema_2_to_3(tmp_path):
    g = _gate()
    assert g.BASELINE_SCHEMA == 3, "这条用例的前提是脚本已经是 schema 3"
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"schema": 1, "principals": {}}), encoding="utf-8")
    with pytest.raises(SystemExit):
        g.load_baseline(p, migrate_from=1)          # 1→3 不支持
    p.write_text(json.dumps({"schema": 2, "principals": {}}), encoding="utf-8")
    with pytest.raises(SystemExit):
        g.load_baseline(p, migrate_from=3)          # 声明的版本与文件里的不一致
    assert g.load_baseline(p, migrate_from=2)["schema"] == 3


def test_migration_strips_iam_policy_write_and_drops_empty_entries():
    """迁移必须剥掉 `iam-policy-write:*`，并删掉只剩空 grants 的条目。

    **实测前提**：旧基线里有 1 个 `platform` 类 principal 持有 `iam-policy-write:scoped`。
    不剥的话它"丢了一条 grant"，而 platform 类按集合等值比 ⇒ `missing_required` 红。
    另有恰好 4 个 principal 只有这条 grant，它们整条退出 A。
    """
    g = _gate()
    old = {"schema": 2,
           "facts": {"principals_with_missing_context": 162, "iam_write_candidates": 22},
           "principals": {
               "aaaa-bbbb-cccc-dddd": {"category": "platform",
                                       "grants": ["iam-policy-write:scoped",
                                                  "invoke-site:all"]},
               "eeee-ffff-0000-1111": {"category": "break-glass",
                                       "grants": ["iam-policy-write:any"]}}}
    new = g.migrate_baseline_2_to_3(old)
    assert new["schema"] == 3
    assert new["principals"]["aaaa-bbbb-cccc-dddd"]["grants"] == ["invoke-site:all"]
    assert new["principals"]["aaaa-bbbb-cccc-dddd"]["category"] == "platform", "category 要保留"
    assert "eeee-ffff-0000-1111" not in new["principals"], \
        "只有 IAM 写那条 grant 的条目该整条退出 A"
    assert not any(k.startswith("iam_write_") for k in new["facts"]), "旧 iam_write_* facts 没清"
    assert new["facts"]["principals_with_missing_context"] == 162, "环境事实要留着"


def test_from_dump_rejects_a_stale_schema(tmp_path):
    """`--from-dump` 的快照也带 schema：旧快照缺新分节，
    拿它当闸门结果会把"这些分节都空"当成"没有漂移"。"""
    g = _gate()
    p = tmp_path / "dump.json"
    p.write_text(json.dumps({"schema": 2, "principals": {}}), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        g.load_dump(p)
    assert "schema" in str(exc.value)


# ---- 红线收紧：grant 文法 / VersionId 形态 -------------------------------

def test_grant_strings_follow_the_grant_grammar():
    """grant 串按**文法**校验，不是"任意字符串放行"。

    放行的话，grant 构造失误把完整 ARN / 角色名 / 账号值拼进串里，递归红线不会抓。
    """
    grants = [x for p in json.loads(_BASELINE.read_text(encoding="utf-8"))["principals"]
              .values() for x in p["grants"]]
    assert grants, "基线里一条 grant 都没有？"
    for x in grants:
        assert _GRANT_RE.fullmatch(x), f"grant {x!r} 不符合文法"


def test_a_grant_carrying_an_arn_is_caught():
    """**元用例**：往 grant 里注入 ARN / 拼接垃圾 / legacy 串，都必须被文法拒绝。"""
    for bad in (f"invoke-platform:arn:aws:iam::{_ACCT}:role/X",
                "read-jwt-param-and-then-some",
                "iam-policy-write:any",
                "invoke-site:some(1):notafingerprint",
                "invoke-site:some(1)"):
        assert not _GRANT_RE.fullmatch(bad), f"文法放过了 {bad!r}"
    # 正对照：真实形态必须过
    for ok in ("invoke-platform:site-panel", "invoke-platform@version:site-access-rollup",
               "invoke-site:all", "invoke-site@alias:all", "read-edge-asset",
               "invoke-site:some(2):aaaa-bbbb-cccc-dddd"):
        assert _GRANT_RE.fullmatch(ok), f"文法误拒了 {ok!r}"


def test_a_grant_carrying_an_arn_is_caught_by_the_tree_scan():
    """注入到基线树里也要被递归红线抓到（不只是文法函数本身能判）。"""
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    fp = next(iter(data["principals"]))
    data["principals"][fp]["grants"] = [f"invoke-platform:arn:aws:iam::{_ACCT}:role/X"]
    assert list(_non_fingerprint_leaves(data)), "grant 里的 ARN 没被递归红线抓到"


def test_managed_policy_versions_are_version_ids():
    versions = json.loads(_BASELINE.read_text(encoding="utf-8"))["managed_policy_versions"]
    for fp, ver in versions.items():
        assert re.fullmatch(r"v[0-9]+", ver), f"{fp} 的版本 {ver!r} 不是 VersionId 形态"


def test_baseline_has_no_iam_policy_write_grants():
    """A 的基线不许再带 `iam-policy-write:*`——那会把 B 的观察算进 A 的人数。"""
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    for fp, p in data["principals"].items():
        assert not any(x.startswith("iam-policy-write") for x in p["grants"]), \
            f"基线 {fp} 还带着 iam-policy-write"


def test_statement_text_never_enters_the_baseline():
    """B 的三个分节只许存指纹：语句原文里 Principal 是带账号 ID 的角色 ARN。"""
    data = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert "texts" not in json.dumps(data), "语句原文（texts）漏进基线了"
    for fp, fps in data["iam_write_statements"].items():
        assert re.fullmatch(_FP_RE, fp)
        for s in fps:
            assert re.fullmatch(_FP_RE, s), f"{s!r} 不是指纹形态"
    for fp, b in data["permissions_boundaries"].items():
        assert re.fullmatch(_FP_RE, fp)
        assert re.fullmatch(_FP_RE, b["policy_fp"])
        for s in b["stmt_fps"]:
            assert re.fullmatch(_FP_RE, s)


def test_bucket_policy_statement_fingerprints_are_in_the_baseline():
    """bootstrap 桶的快照必须真的落进基线（否则那一层等于没有）。"""
    fps = json.loads(_BASELINE.read_text(encoding="utf-8"))["resource_policies"]["bootstrap_bucket"]
    assert fps, "基线里 bootstrap_bucket 是空的——那一层没落地"
    for fp in fps:
        assert re.fullmatch(_FP_RE, fp), f"{fp!r} 不是指纹形态"


def test_authorization_details_filter_includes_group():
    """`GetAccountAuthorizationDetails` 的 `Filter` 必须含 `Group`。

    漏掉它的后果**只在真机可见**（实测账号内 0 个 group，所以基线不变），而症状是
    "用户经 group 拿到的 IAM 写语句整个不可见"——与"这些用户没有相关语句"在输出上
    一模一样。所以这里用桩把那次调用的实参钉死，而不是等真机哪天建了 group 才发现。

    只影响 B：A 走 `SimulatePrincipalPolicy(PolicySourceArn=user)`，模拟器本来就
    评估 group 策略。
    """
    g = _gate()
    seen = {}

    class _Paginator:
        def paginate(self, **kw):
            seen.update(kw)
            return [{"RoleDetailList": [], "UserDetailList": [],
                     "GroupDetailList": [], "Policies": []}]

    class _Iam:
        def get_paginator(self, name):
            assert name == "get_account_authorization_details", name
            return _Paginator()

    out = g.list_principals(_Iam())
    assert out == {"principals": [], "policy_docs": {}, "managed_versions": {}}
    assert "Group" in seen.get("Filter", []), \
        f"Filter 里没有 Group ⇒ 经 group 的 IAM 写语句整个不可见：{seen.get('Filter')}"
    for required in ("User", "Role", "LocalManagedPolicy", "AWSManagedPolicy"):
        assert required in seen["Filter"], f"Filter 里少了 {required}"


# ==========================================================================
# Codex 第五轮复审（2026-08-26，闸门收缩轮的 No-Go）：六条 finding 各自的会红用例
#
# 六条**全部实测复现过**，所以这一节的每条用例都对应一个已发生的 false-green，
# 不是理论风险。共同教训：**"不完整的观测"必须硬失败，不能变成一个权威的绿。**
# ==========================================================================

def _complete_bundle(g) -> dict:
    """一份**形状完整**的观测，值取最小合法值。

    刻意**手写**而不是从 `BUNDLE_SHAPE` 生成：从规格生成的样例必然满足规格，
    拿它当正向控制是同义反复。代价是 `measure()` 新增分节时这里会红——那正是要的
    （逼一次自觉更新，而不是让新分节悄悄地没人校验）。
    """
    return {
        "schema": g.BASELINE_SCHEMA,
        "asset_scan_complete": True,
        "principals": {"0000-1111-2222-3333": {
            "name": "SomeRole", "arn": "arn:aws:iam::1:role/SomeRole",
            "kind": "role", "grants": ["invoke-platform:site-panel"]}},
        # platform / sites 各带**一个成员**：`*` 通配层的内层规格只有在样例里真的
        # 有成员时才会被 `_required_paths` 展开到，空 dict 下那一层等于没验。
        "resource_policies": {
            "platform": {"site-panel": {"alias": {"live": []}, "version": [],
                                        "unqualified": []}},
            "sites": {"site-fn": {"alias": {"blue": []}, "version": [],
                                  "unqualified": []}},
            "bootstrap_bucket": [], "bootstrap_bucket_texts": {}},
        "facts": {"edge_code_targets_carrying_live_key": 0,
                  "edge_assets_carrying_live_key": 0,
                  "principals_with_missing_context": 0},
        "coverage": {"undecided_items": []},
        "iam_write": {"statements": {}, "boundaries": {},
                      "managed_versions": {}, "texts": {}},
        "required": {"edge": "EdgeRole", "deployer": "DeployerRole"},
    }

def test_insecure_tls_warning_is_fatal():
    """"这次请求没校验服务端证书"必须是**致命错误**，不许只打印后继续退出 0。

    实测现场：`measure()` 把**同一个** IAM client 交给 4 个 worker 并发用，于是 400 个
    principal 的模拟里有十几次是在未校验证书的连接上完成的（同一批请求顺序执行 0 次、
    每线程独立 client 0 次——是共享 client 的并发形态触发的）。
    闸门的答案要是能被 MITM 伪造，那次"绿"就不能当安全证据。
    """
    import warnings as _w
    from urllib3.exceptions import InsecureRequestWarning
    g = _gate()
    with _w.catch_warnings():
        g.harden_tls_warnings()
        with pytest.raises(InsecureRequestWarning):
            _w.warn("unverified", InsecureRequestWarning)


def test_each_worker_gets_its_own_iam_client():
    """每个 worker 一个独立 IAM client：共享 client + 并发会让一部分请求跳过证书校验。"""
    import threading
    g = _gate()
    got = {}

    def grab(tag):
        got[tag] = id(g.thread_iam_client("us-east-1"))

    t1, t2 = threading.Thread(target=grab, args=("a",)), threading.Thread(target=grab, args=("b",))
    t1.start(); t1.join(); t2.start(); t2.join()
    assert got["a"] != got["b"], "两个线程拿到了同一个 client —— 那正是触发未校验 TLS 的形态"
    # 同一线程内要复用，否则 400 个 principal 会建 400 个 client
    assert id(g.thread_iam_client("us-east-1")) == id(g.thread_iam_client("us-east-1"))


def test_no_asset_scan_may_not_produce_a_verdict_or_rewrite_the_baseline():
    """`--no-asset-scan` 只看当前 asset，带活密钥的**历史对象**整个不进目标集合
    ⇒ 只能读到那批对象的 principal 会从 observed 消失，而比较器把它报成
    「集合缩小（绿）」，asset 数 9→1 只是一条不影响退出码的 note。实测 rep.ok = True。

    所以它最多只能用于**纯观测**，不得出闸门结论、更不得改写基线。
    """
    import argparse
    g = _gate()
    ok = argparse.Namespace(no_asset_scan=True, dump_observed="/tmp/x.json",
                            update_baseline=False)
    g.check_flag_combination(ok)          # 纯观测：允许
    for bad in (
        argparse.Namespace(no_asset_scan=True, dump_observed=None, update_baseline=False),
        argparse.Namespace(no_asset_scan=True, dump_observed="/tmp/x.json",
                           update_baseline=True),
    ):
        with pytest.raises(SystemExit) as exc:
            g.check_flag_combination(bad)
        assert "no-asset-scan" in str(exc.value)


def test_incomplete_asset_scan_cannot_be_replayed_as_a_verdict(tmp_path):
    """`--no-asset-scan` 产出的快照要带标记，`--from-dump` 必须拒绝它。

    否则绕一步就回到权威绿：先用 --no-asset-scan 产出快照（允许），再 --from-dump 它。
    """
    g = _gate()
    p = tmp_path / "partial.json"
    # 除 `asset_scan_complete` 外一切完整——好让这条用例只验扫描完整性这一维，
    # 不会因为别的分节缺失而"因为另一个原因红"。
    p.write_text(json.dumps({**_complete_bundle(g), "asset_scan_complete": False}),
                 encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        g.load_dump(p)
    assert "asset" in str(exc.value)


def test_bundle_missing_a_section_hard_fails(tmp_path):
    """同 schema 但**缺分节**的快照必须硬失败。

    实测：一个只缺 `coverage` 与 `iam_write` 的 schema-3 dump 被 load_dump 接受，
    而 `main()` 用 `.get()` 传给比较器 ⇒ 那两层整个跳过。基线里明明有 B 语句与
    undecided items，闸门仍输出「与基线一致」、退出码 0。
    缺一节的症状与「那一层没有漂移」**一模一样**，这是最坏的一种 false-green。
    """
    g = _gate()
    full = _complete_bundle(g)
    g.check_bundle_complete(full, where="test")          # 完整：放行
    for drop in ("coverage", "iam_write", "resource_policies", "principals", "facts"):
        partial = {k: v for k, v in full.items() if k != drop}
        with pytest.raises(SystemExit) as exc:
            g.check_bundle_complete(partial, where="test")
        assert drop in str(exc.value), f"报文里没点出缺的是 {drop}"
    # 类型不对也要拒（空列表冒充空字典这类）
    with pytest.raises(SystemExit):
        g.check_bundle_complete({**full, "iam_write": []}, where="test")


def test_from_dump_rejects_a_bundle_missing_sections(tmp_path):
    g = _gate()
    p = tmp_path / "d.json"
    bundle = {k: v for k, v in _complete_bundle(g).items()
              if k not in ("coverage", "iam_write")}
    p.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        g.load_dump(p)
    assert "coverage" in str(exc.value) or "iam_write" in str(exc.value)


# ==========================================================================
# Codex 第六轮复审（2026-08-26）：顶层合同只封住了顶层，**内层缺失照样权威绿**
#
# 上一轮把"缺分节"封成硬失败，但合同只要求 `coverage` / `resource_policies` /
# `iam_write` **是 dict**，不要求它们内部有东西。实测两个 false-green：
#
#   ① `coverage = {}`        → `coverage.get("undecided_items")` 是 None ⇒ 基线里
#      774 项判不出的全被当成"已能判定"记进 improvements，`rep.ok == True`。
#   ② `resource_policies` 缺 `sites` → 逐站点那一层**一个站点都没检查**，
#      `red={}` 且**连一条 note 都没有** —— 输出与"真的没漂移"逐字相同。
#
# 为什么恰好是这两层：它们的比较器是**单向**的（消失=改善）。双向的那些
# （B 的语句、boundary、bucket policy：消失也红）内层缺失会自己红出来——实测
# `iam_write = {}` 是 44+7 条红、`principals = {}` 是 missing_required 红。
# **所以规律是：单向比较器的层必须由合同兜住下限。** 合同做成递归默认拒绝，
# 就不必逐层去记哪个方向了。
# ==========================================================================

def _required_paths(spec: dict, value: dict, prefix: tuple = ()):
    """（规格, 样例）→ 所有必需路径。`*` 通配层按样例里的实际成员展开。"""
    for key, sub in spec.items():
        if key == "*":
            for member, mv in value.items():
                if isinstance(mv, dict):
                    yield from _required_paths(sub, mv, prefix + (member,))
            continue
        yield prefix + (key,)
        if isinstance(sub, dict) and isinstance(value.get(key), dict):
            yield from _required_paths(sub, value[key], prefix + (key,))


def _drop_path(bundle: dict, path: tuple) -> dict:
    out = copy.deepcopy(bundle)
    node = out
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return out


def test_bundle_missing_an_inner_key_hard_fails():
    """顶层齐了但**内层**缺键，同样不许变成一个权威的绿。

    走 `BUNDLE_SHAPE` 枚举每条必需路径：规格声明"必需"，这条用例验证**检查器真的
    执行了**它。枚举规格证明不了规格自己没被削弱——那由下面 coverage / sites
    两条**点名**用例守（删掉规格里那一项，它们就红）。
    """
    g = _gate()
    full = _complete_bundle(g)
    paths = list(_required_paths(g.BUNDLE_SHAPE, full))
    assert len(paths) > len(g.BUNDLE_SHAPE), \
        f"只枚举到顶层 {len(paths)} 条路径——递归规格没生效，这条用例什么也没验"
    for path in paths:
        with pytest.raises(SystemExit) as exc:
            g.check_bundle_complete(_drop_path(full, path), where="test")
        assert ".".join(path) in str(exc.value), \
            f"缺 {'.'.join(path)} 时报文里没点出是哪条路径：{exc.value}"


def test_coverage_items_are_required_because_losing_them_reads_as_all_clear():
    """`coverage` 在、内层 `undecided_items` 没了 ⇒ 每一项判不出的都变成"改善"。"""
    g = _gate()
    items = ["1111-1111-1111-1111", "2222-2222-2222-2222"]
    baseline = {"schema": g.BASELINE_SCHEMA, "principals": {},
                "coverage": {"undecided_items": items}}
    rep = g.compare_to_baseline({}, baseline, required={}, resource_policies=None,
                                facts=None, coverage={}, iam_write=None)
    assert rep.ok and len(rep.improvements) == len(items), (
        "前提变了：coverage 内层缺失现在会自己红了 ⇒ 这条用例要按新形态重写，"
        "别直接删——它是合同存在的理由")
    with pytest.raises(SystemExit) as exc:
        g.check_bundle_complete({**_complete_bundle(g), "coverage": {}}, where="test")
    assert "coverage.undecided_items" in str(exc.value)


def test_sites_section_is_required_because_losing_it_disables_the_whole_layer():
    """`resource_policies` 缺 `sites` ⇒ 逐站点 resource policy **一个都不检查**。

    三段：① 正向控制（这一层平时真的会红）② 删掉 sites 后全绿且无 note
    ③ 所以合同必须在比较器之前就拒掉它。
    """
    g = _gate()
    canon = ["1111-1111-1111-1111", "2222-2222-2222-2222"]
    baseline = {"schema": g.BASELINE_SCHEMA, "principals": {},
                "resource_policies": {"platform": {}, "bootstrap_bucket": [],
                                      "site_alias_canonical": canon,
                                      "site_version_canonical": [],
                                      "site_legacy_canonical": [],
                                      "site_legacy_exempt": []}}
    base_rp = {"platform": {}, "bootstrap_bucket": [], "bootstrap_bucket_texts": {}}
    # ① active 色少一条规范语句 = 该站点整站 403，必须红
    bad = {"site-x": {"alias": {"blue": canon[1:]}, "version": [], "unqualified": []}}
    rep = g.compare_to_baseline({}, baseline, required={},
                                resource_policies={**base_rp, "sites": bad},
                                facts=None, coverage=None, iam_write=None)
    assert rep.site_policy_outliers and not rep.ok, "正向控制失效：这一层已经不会红了"
    # ② 同一份观测删掉 sites ⇒ 全绿，且没有任何提及站点的 note
    rep2 = g.compare_to_baseline({}, baseline, required={}, resource_policies=base_rp,
                                 facts=None, coverage=None, iam_write=None)
    assert rep2.ok, ("前提变了：sites 缺失现在会自己红了 ⇒ 按新形态重写这条用例")
    # ③ 合同拒
    rp = {k: v for k, v in _complete_bundle(g)["resource_policies"].items()
          if k != "sites"}
    with pytest.raises(SystemExit) as exc:
        g.check_bundle_complete({**_complete_bundle(g), "resource_policies": rp},
                                where="test")
    assert "resource_policies.sites" in str(exc.value)


def test_a_truncated_per_site_shape_hard_fails():
    """同一个洞往下一层：`sites` 键在，但**某个站点**的 shape 截断成 `{}`。

    比较器逐站点取 `shape.get("alias") or {}`，于是那个站点一条 alias 都不比、
    `version` / `unqualified` 也都当空 ⇒ 该站点整个不参与检查。实测（本用例第②段）
    `ok=True`、`site_policy_outliers=[]`、**零 note**——与"这个站点没问题"逐字相同。
    所以 `sites` 不能只声明"是 dict"，逐成员的三个桶也要在合同里。

    这条的存在理由与上一条同源，但**不是同一个检查**：上一条守的是 `sites` 这个键，
    删掉 `_POLICY_SHAPE` 时它照样绿。
    """
    g = _gate()
    canon = ["1111-1111-1111-1111", "2222-2222-2222-2222"]
    baseline = {"schema": g.BASELINE_SCHEMA, "principals": {},
                "resource_policies": {"platform": {}, "bootstrap_bucket": [],
                                      "site_alias_canonical": canon,
                                      "site_version_canonical": [],
                                      "site_legacy_canonical": [],
                                      "site_legacy_exempt": []}}
    base_rp = {"platform": {}, "bootstrap_bucket": [], "bootstrap_bucket_texts": {}}
    # ① 正向控制：形状完整、blue 缺一条规范语句 ⇒ 红
    full_shape = {"site-x": {"alias": {"blue": canon[1:]}, "version": [],
                             "unqualified": []}}
    rep = g.compare_to_baseline({}, baseline, required={},
                                resource_policies={**base_rp, "sites": full_shape},
                                facts=None, coverage=None, iam_write=None)
    assert rep.site_policy_outliers and not rep.ok, "正向控制失效：这一层已经不会红了"
    # ② 同一个站点的 shape 截断成 {} ⇒ 全绿、零 outlier
    rep2 = g.compare_to_baseline({}, baseline, required={},
                                 resource_policies={**base_rp, "sites": {"site-x": {}}},
                                 facts=None, coverage=None, iam_write=None)
    assert rep2.ok and not rep2.site_policy_outliers, (
        "前提变了：per-site shape 截断现在会自己红了 ⇒ 按新形态重写这条用例，"
        "别直接删——它是 _POLICY_SHAPE 存在的理由")
    # ③ 合同在比较器之前就拒：三个桶逐个删一次都要红，且报文点出是哪条路径
    full = _complete_bundle(g)
    for bucket in ("alias", "version", "unqualified"):
        shape = {k: v for k, v in full["resource_policies"]["sites"]["site-fn"].items()
                 if k != bucket}
        rp = {**full["resource_policies"], "sites": {"site-fn": shape}}
        with pytest.raises(SystemExit) as exc:
            g.check_bundle_complete({**full, "resource_policies": rp}, where="test")
        assert f"resource_policies.sites.site-fn.{bucket}" in str(exc.value)
    # ④ 桶的类型也要判：alias 是 `{颜色: [指纹…]}`，压成一个扁平 list 就丢了颜色维
    rp = {**full["resource_policies"],
          "sites": {"site-fn": {"alias": [], "version": [], "unqualified": []}}}
    with pytest.raises(SystemExit) as exc:
        g.check_bundle_complete({**full, "resource_policies": rp}, where="test")
    assert "resource_policies.sites.site-fn.alias" in str(exc.value)


def test_asset_scan_complete_must_be_a_true_bool():
    """`if not bundle.get(...)` 下字符串 `"false"` 是 truthy ⇒ 不完整观测照样出结论。"""
    g = _gate()
    full = _complete_bundle(g)
    for bad in ("false", "true", "yes", 1, 0, None, [], {}):
        with pytest.raises(SystemExit) as exc:
            g.check_bundle_complete({**full, "asset_scan_complete": bad}, where="test")
        assert "asset" in str(exc.value), f"{bad!r} 被拒了但报文没说是扫描完整性"
    with pytest.raises(SystemExit):
        g.check_bundle_complete(
            {k: v for k, v in full.items() if k != "asset_scan_complete"}, where="test")


def test_an_unknown_bundle_section_hard_fails():
    """`measure()` 新增分节必须同时进 `BUNDLE_SHAPE`。

    默认拒绝的理由和这一整节一样：新分节要是没人校验，它就是下一个"截断了也看不出"
    的层。放行未知键 = 把同一个 bug 类留给下一轮。
    """
    g = _gate()
    for extra in ({"brand_new_layer": {}},
                  {"resource_policies": {**_complete_bundle(g)["resource_policies"],
                                         "brand_new_layer": {}}}):
        with pytest.raises(SystemExit) as exc:
            g.check_bundle_complete({**_complete_bundle(g), **extra}, where="test")
        assert "brand_new_layer" in str(exc.value)


def test_gaining_a_second_undecided_platform_function_is_a_failure():
    """**Codex 第五轮的核心反例**：某 principal 原本只对 site-panel 判不出，
    后来对 site-deployer-undeploy 也判不出——两者缺的是同一个键。

    上一版按 action 全局折叠成 `(action, unattributed)` ⇒ 前后同一个成员、闸门全绿。
    缺失键相同只说明**不确定的成因**与资源无关，**不说明后果与资源无关**——
    后果就是"还有哪些资源没被排除"，那正是安全边界。
    """
    g = _gate()
    t = _targets(g, platform=("site-panel", "site-deployer-undeploy"))
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    arn = "arn:aws:iam::1:role/WorkloadA"

    def members(names):
        pairs = {("lambda:InvokeFunction", fn(n)) for n in names}
        return g.undecided_members(arn, pairs, t)

    one, two = members(["site-panel"]), members(["site-panel", "site-deployer-undeploy"])
    assert one and two
    assert one != two, "多出一个精确平台函数却是同一批成员 —— 扩大不可见"


def test_undecided_members_are_bounded_by_action_class():
    """成员数按「principal × 动作等价类」封顶，不随资源数膨胀。

    逐资源各记一项实测是 **9985** 条（基线涨 10 倍），而"新增一个带 Condition 的
    principal 一次冒出几十条红"会训练出无脑更新基线。摘要把上界压回 5 条/principal，
    同时集合一变摘要就变 ⇒ 扩大照样红（见上一条）。
    """
    g = _gate()
    t = _targets(g, platform=tuple(f"p{i}" for i in range(19)))
    fn = "arn:aws:lambda:us-east-1:1:function:{}".format
    pairs = {(a, fn(f"p{i}")) for i in range(19)
             for a in ("lambda:InvokeFunction", "lambda:UpdateFunctionCode",
                       "lambda:GetFunction")}
    members = g.undecided_members("arn:aws:iam::1:role/W", pairs, t)
    assert len(members) == 3, f"19 个资源 × 3 个动作类应折成 3 条成员，实际 {len(members)}"


def test_platform_statement_fingerprint_separates_alias_from_version():
    """平台函数的 resource policy 也要保留 **qualifier 类**。

    实测：挂在 `site-panel:blue` 与挂在 `site-panel:9` 的同一条语句指纹**完全相同**
    （都被归一化成 `<self>:<alias>`）⇒ 语句从 alias 挪到 version、或反过来，
    比较结果是"与基线一致"。站点那边已经按颜色逐成员比修过，平台这条路还留着。
    """
    g = _gate()
    A = "0" * 12
    base = f"arn:aws:lambda:us-east-1:{A}:function:site-panel"
    st = lambda res: {"Sid": "x", "Effect": "Allow",
                      "Principal": {"AWS": f"arn:aws:iam::{A}:role/Edge"},
                      "Action": "lambda:InvokeFunctionUrl", "Resource": res}
    u = g.statement_fingerprint(st(base), account=A, function="site-panel", qualifier=None)
    b = g.statement_fingerprint(st(base + ":blue"), account=A, function="site-panel",
                                qualifier="blue", qualifier_class="alias")
    gr = g.statement_fingerprint(st(base + ":green"), account=A, function="site-panel",
                                 qualifier="green", qualifier_class="alias")
    v = g.statement_fingerprint(st(base + ":9"), account=A, function="site-panel",
                                qualifier="9", qualifier_class="version")
    assert b != v, "alias 与 version 同指纹 —— 语句在两者之间搬家不可见"
    assert u != v and u != b
    assert b == gr, "blue 与 green 必须同指纹：颜色不该产生漂移（站点那边的既定选择）"


def test_platform_policy_keeps_qualifier_buckets():
    """平台快照按 qualifier 分桶存，不再压成一个扁平集合。

    扁平集合的第二个 false-green：两个 alias 有相同语句时，删掉其中一个而另一个还在，
    集合不变 ⇒ 绿。这正是站点 alias 已经修过的"成员并集"问题。
    """
    g = _gate()
    A = "0" * 12
    st = lambda res: {"Sid": "x", "Effect": "Allow",
                      "Principal": {"AWS": f"arn:aws:iam::{A}:role/Edge"},
                      "Action": "lambda:InvokeFunctionUrl", "Resource": res}
    base = f"arn:aws:lambda:us-east-1:{A}:function:site-panel"
    policies = {"site-panel": [(None, st(base)), ("blue", st(base + ":blue")),
                               ("green", st(base + ":green")), ("9", st(base + ":9"))]}
    snap = g.resource_policy_snapshot(policies, account=A, platform=("site-panel",),
                                      sites=(), aliases={"site-panel": ("blue", "green")})
    shape = snap["platform"]["site-panel"]
    assert set(shape) == {"unqualified", "alias", "version"}, shape
    assert set(shape["alias"]) == {"blue", "green"}, "alias 没有逐成员存"
    assert shape["unqualified"] and shape["version"]


def test_platform_alias_losing_a_statement_is_a_failure():
    """某个 alias 上的语句消失、相同语句仍存在于另一个 alias ⇒ 必须红。"""
    g = _gate()
    observed = _with_required(g, {})
    canon = ["aaaa-bbbb-cccc-dddd"]
    baseline = {**_baseline_of(observed),
                "resource_policies": {
                    "platform": {"site-panel": {"unqualified": [], "version": [],
                                                "alias": {"blue": canon, "green": canon}}},
                    "site_alias_canonical": [], "site_version_canonical": [],
                    "site_legacy_canonical": [], "site_legacy_exempt": [],
                    "bootstrap_bucket": []}}
    now = {"platform": {"site-panel": {"unqualified": [], "version": [],
                                       "alias": {"blue": [], "green": canon}}},
           "sites": {}, "bootstrap_bucket": [], "bootstrap_bucket_texts": {}}
    rep = g.compare_to_baseline(observed, baseline, required=REQUIRED, resource_policies=now)
    assert not rep.ok, rep.render()
    assert "blue" in rep.render()


def test_unresolvable_group_hard_fails():
    """`GroupList` 引用了一个不在 `GroupDetailList` 里的 group ⇒ **硬失败**。

    实测静默返回 `[]`：那个 group 里的 IAM 写语句从 B 快照消失，而输出与
    "该 group 没有相关语句"一模一样。这与 attached 托管策略"文档缺失必须硬失败"
    是同一条原则；IAM 的最终一致性窗口或并发变更都可能撞上。
    """
    g = _gate()
    A = "0" * 12
    detail = {"UserName": "U", "Arn": f"arn:aws:iam::{A}:user/U", "GroupList": ["Ghost"],
              "UserPolicyList": [], "AttachedManagedPolicies": []}
    with pytest.raises(SystemExit) as exc:
        g.statements_for_user(detail, groups={}, managed={}, versions={})
    assert "Ghost" in str(exc.value)


def test_deploy_doc_does_not_describe_the_deleted_two_step_model():
    """部署手册是运维真源，不能还把已删除的「模拟器三值确认」当成现状描述——
    否则后续维护者会照它把被否掉的模型重新引进来。

    判据分两半：① 旧模型**专有**的词不许出现；② 必须写着现在的口径。
    `发现候选 + 模拟器` 这类词组**允许**出现在明确的禁止句里（"不要重新引进来"），
    所以不能只做黑名单 grep —— 那会把警告本身也判成违规。
    """
    doc = (_ROOT / "site-builder" / "DEPLOY.md").read_text(encoding="utf-8")
    for gone in ("三值", "测四层"):
        assert gone not in doc, f"DEPLOY.md 里还留着已删除模型的专有说法：{gone!r}"
    for required in ("纯静态文本快照", "两层"):
        assert required in doc, f"DEPLOY.md 没写现在的口径：{required!r}"
    # 旧模型只许以"别再引进来"的形式出现
    idx = doc.find("发现候选")
    if idx != -1:
        window = doc[max(0, idx - 200):idx + 200]
        assert "不要" in window or "已删除" in window, \
            "DEPLOY.md 提到了旧模型，但没写明它是被删掉的/不要重新引入"


def test_baseline_platform_shape_matches_what_the_snapshot_produces():
    """基线里 `resource_policies.platform` 的**形状**必须与 `resource_policy_snapshot()`
    现在产出的形状一致。

    这条补的是一个实测出来的盲区：改了平台快照的形状（扁平集合 → 按 qualifier 分桶）
    而**忘记重写基线**时，全部单测仍然绿——形状不匹配只在真机跑那一次才暴露（表现为
    一屏红）。逐提交回归验证时就撞到过这个：那个提交代码已是新形状、基线还是旧形状，
    992 条全绿。

    只比形状不比内容：内容变化本来就该由闸门自己报红。
    """
    g = _gate()
    A = "0" * 12
    fn = "probe-fn"
    st = {"Sid": "x", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:role/E"},
          "Action": "lambda:InvokeFunctionUrl",
          "Resource": f"arn:aws:lambda:us-east-1:{A}:function:{fn}"}
    produced = g.resource_policy_snapshot({fn: [(None, st)]}, account=A,
                                          platform=(fn,), sites=(), aliases={})
    want_keys = set(produced["platform"][fn])

    platform = json.loads(_BASELINE.read_text(encoding="utf-8"))["resource_policies"]["platform"]
    assert platform, "基线里 platform 是空的"
    for name, shape in platform.items():
        assert isinstance(shape, dict), (
            f"{name} 的形状是 {type(shape).__name__}，而快照现在产出 dict"
            f"——改了快照形状但没重写基线？")
        assert set(shape) == want_keys, (
            f"{name} 的桶是 {sorted(shape)}，快照产出的是 {sorted(want_keys)}"
            f"——两者必须一致，否则形状不匹配只在真机那一次才暴露")
        assert isinstance(shape["alias"], dict)
        for bucket in ("unqualified", "version"):
            assert isinstance(shape[bucket], list)


# ==========================================================================
# Codex 第七轮复审（2026-08-27，3b 推送前的 No-Go）：观测的**原子性**
#
# 闸门先 `GetAccountAuthorizationDetails` 拿全量名单（T1），再逐个
# `SimulatePrincipalPolicy`（T2），两者之间约 10 分钟。B 组的语句抄自 T1、A 组的判定
# 来自 T2 ⇒ 窗口内 IAM 变过的话，一份快照同时描述两个时刻的账号。
#
# 旧文档把这个窗口定性成"硬失败，所以只是可用性问题"。那句话是错的：`NoSuchEntity`
# 只咬住"模拟时角色已经不在了"这一种 churn，下面四类它一种都咬不住。
#
# **三条实测事实**（都从生产 CloudTrail 查得，不是构造的场景）：
#   ① 同名重建在本账号是常态：2026-08-27 有两个**固定名字**的角色各被重建 4 次，
#      拿到 4 个不同的 RoleId、同一个 ARN ⇒ "同 ARN 不同代"不是理论情形。
#   ② 那次写基线的运行（枚举 14:38:44–14:40:12、产物 14:47:05）窗口内有两条
#      `PutRolePolicy` ⇒ 那一份快照**确实**混了两个时刻。只是恰好落在既不进 A
#      也不进 B 的角色上，所以值没错——闸门当时无从知道这一点。
#   ③ 7 天里 96.6% 的 10 分钟窗口是干净的 ⇒ 作废本轮不会把闸门变成永远红。
# ==========================================================================

def _principal(name, *, uid, statements=(), boundary=None, kind="role",
               boundary_statements=(), policy_versions=None):
    """一个 `list_principals()` 形态的 principal。`statements` 是 `(来源, 语句)` 对。

    假 `uid` **刻意不长得像真的 IAM 唯一 ID**（真的形如 `AROA…` / `AIDA…` 加 16 位大写
    字母数字）。两道闸门都会咬住那种形态，而且咬得有道理：提交钩子的密钥检测按
    `(AKIA|ASIA|AROA|AIDA)+16` 判成 AWS access key（实测 23 条 blocking finding），
    `scan_staged_secrets.sh` 按 `[0-9]{12}` 找账号 ID。给测试 fixture 去放行这两道
    （`secrets.allowed` / `--allow-hits`）是拿真闸门换一点像真度——不值得，而且
    `uid` 是纯字符串比较，形态对判据毫无影响。真值也永远不会进仓库：它不进快照、
    不进基线，只在进程内当判据。
    """
    return {"kind": kind, "name": name, "arn": f"arn:aws:iam::{_ACCT}:role/{name}",
            "uid": uid, "statements": list(statements), "boundary_arn": boundary,
            "boundary_statements": list(boundary_statements),
            "policy_versions": dict(policy_versions or {})}


def test_identical_listings_are_atomic():
    """正向控制：两次枚举一模一样 ⇒ 零漂移。

    少了这条，下面几条"应该红"的用例无法区分"检查器有效"与"检查器无条件红"。
    """
    g = _gate()
    listing = [_principal("EdgeRole", uid="uid-edge-1",
                          statements=[(None, _iam_stmt())]),
               _principal("Kent", uid="uid-user-1", kind="user")]
    assert g.enumeration_drift(listing, copy.deepcopy(listing)) == {}


def test_same_arn_new_generation_is_refused():
    """**Codex 反例①**：同 ARN、不同 RoleId，新一代还多一条 B-only 的 IAM 写语句。

    这一类的危险在于 A 与 B 各自都"正常"：A 模拟的是新一代（模拟器按 ARN 找，
    找到的就是新角色），B 抄的是旧一代的语句 ⇒ 新加的 IAM 写权限归 B 管而 B 没看见，
    闸门可以退出 0。
    """
    g = _gate()
    before = [_principal("Patrol", uid="uid-patrol-gen1",
                         statements=[(None, _iam_stmt(action="logs:PutLogEvents"))])]
    after = [_principal("Patrol", uid="uid-patrol-gen2",
                        statements=[(None, _iam_stmt(action="logs:PutLogEvents")),
                                    (None, _iam_stmt(action="iam:PutRolePolicy"))])]
    drift = g.enumeration_drift(before, after)
    assert "changed" in drift, drift
    assert "Patrol" in drift["changed"][0]
    assert "换代" in drift["changed"][0], f"没说清是换代：{drift['changed']}"


def test_policy_mutated_on_existing_principal_is_refused():
    """**这一类是 2026-08-27 真实发生的那一类**：uid 一字未变，只是窗口内被
    `PutRolePolicy` 改了 inline 策略。

    生产实据：14:41:28 与 14:43:17 两条 `PutRolePolicy` 落在那次运行的窗口内，
    而这两个角色从头到尾没被删过 ⇒ 只比 uid 的检查器对这一类完全失明。
    """
    g = _gate()
    before = [_principal("Logger", uid="uid-logger-unchanged",
                         statements=[(None, _iam_stmt(action="s3:PutObject",
                                                      resource="arn:aws:s3:::old/*"))])]
    after = [_principal("Logger", uid="uid-logger-unchanged",
                        statements=[(None, _iam_stmt(action="s3:PutObject",
                                                     resource="arn:aws:s3:::new/*"))])]
    drift = g.enumeration_drift(before, after)
    assert "changed" in drift, drift
    assert "Logger" in drift["changed"][0]


def test_generation_id_alone_would_not_catch_the_policy_mutation():
    """元测试：钉住"为什么摘要必须含语句，而不是只比 uid"。

    这条是对上面那条的**反向**断言——两侧 uid 相等，所以任何只看 uid 的实现都会
    判成"没变"。它会在有人把 `principal_auth_digest` 简化成"只比 uid"时变红。
    """
    g = _gate()
    before = [_principal("Logger", uid="uid-logger-unchanged",
                         statements=[(None, _iam_stmt(action="s3:PutObject"))])]
    after = [_principal("Logger", uid="uid-logger-unchanged",
                        statements=[(None, _iam_stmt(action="s3:PutObject")),
                                    (None, _iam_stmt(action="iam:PutRolePolicy"))])]
    assert before[0]["uid"] == after[0]["uid"], "前提搞错了：这条要的是 uid 相同"
    assert g.enumeration_drift(before, after), "只比 uid 会漏掉这一类"


def test_boundary_change_is_refused():
    """boundary 换了也算授权输入变了——per-site 隔离整个建立在 boundary 上。"""
    g = _gate()
    before = [_principal("SiteRole", uid="uid-generic",
                         boundary=f"arn:aws:iam::{_ACCT}:policy/Boundary")]
    after = [_principal("SiteRole", uid="uid-generic", boundary=None)]
    assert "changed" in g.enumeration_drift(before, after)


def test_principal_created_after_enumeration_is_refused():
    """**Codex 反例②**：T1 之后新建的 principal 整轮没被模拟 ⇒ 覆盖不全。

    它可能带着新 grant，而"没模拟过"与"模拟过、没有权限"在输出上一模一样。
    """
    g = _gate()
    before = [_principal("EdgeRole", uid="uid-edge-1")]
    after = before + [_principal("site-rt-notes-abc123", uid="uid-site-rt-new")]
    drift = g.enumeration_drift(before, copy.deepcopy(after))
    assert drift.get("appeared") == ["site-rt-notes-abc123"], drift


def test_principal_vanishing_after_simulation_is_refused():
    """模拟完成后才消失的 principal 也作废本轮。

    方向上这是**多报**（快照里留着一个已经不存在的 principal，藏不住新权限），
    但仍然不放行：一轮观测要么描述一个时刻，要么不算权威。给"缩小是安全的"开口子
    正是历次 false-green 的共同形状。
    """
    g = _gate()
    before = [_principal("EdgeRole", uid="uid-edge-1"),
              _principal("site-rt-gone-1", uid="uid-site-rt-gone")]
    after = [_principal("EdgeRole", uid="uid-edge-1")]
    assert g.enumeration_drift(before, after).get("vanished") == ["site-rt-gone-1"]


def test_digest_ignores_statement_order():
    """语句顺序抖动**不算**漂移。

    AWS 不保证两次返回同一份策略的语句顺序一致。把顺序判成漂移会让闸门随机红，
    而反复的假红会训练出"红了就重跑到绿为止"——那时真漂移也会被重跑掉。
    """
    g = _gate()
    a = _iam_stmt(action="iam:PutRolePolicy")
    b = _iam_stmt(action="s3:GetObject")
    p1 = _principal("R", uid="uid-generic", statements=[(None, a), (None, b)])
    p2 = _principal("R", uid="uid-generic", statements=[(None, b), (None, a)])
    assert g.principal_auth_digest(p1) == g.principal_auth_digest(p2)
    assert g.enumeration_drift([p1], [p2]) == {}


def test_statement_source_is_part_of_the_digest():
    """同一条语句从 inline 挪进托管策略（或反之）也算变化——来源决定它由哪份
    policy 的版本解释，B 的 `managed_versions` 会跟着变。"""
    g = _gate()
    st = _iam_stmt()
    inline = _principal("R", uid="uid-generic", statements=[(None, st)])
    managed = _principal("R", uid="uid-generic",
                         statements=[(f"arn:aws:iam::{_ACCT}:policy/P", st)])
    assert g.principal_auth_digest(inline) != g.principal_auth_digest(managed)


def test_list_principals_records_uid_for_roles_and_users():
    """`uid` 必须真的被填上。

    漏填的后果是**静默的**：两侧都是 `None`（或都缺键）时换代检测永远说"没变"，
    而输出与"账号真的很安静"一模一样。所以这里钉住 `list_principals` 的产出。
    """
    g = _gate()

    class _Paginator:
        def paginate(self, **kw):
            return [{"RoleDetailList": [
                        {"RoleName": "R", "RoleId": "uid-role-1",
                         "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
                         "RolePolicyList": [], "AttachedManagedPolicies": []}],
                     "UserDetailList": [
                        {"UserName": "U", "UserId": "uid-user-2",
                         "Arn": f"arn:aws:iam::{_ACCT}:user/U", "Path": "/",
                         "UserPolicyList": [], "AttachedManagedPolicies": [],
                         "GroupList": []}],
                     "GroupDetailList": [], "Policies": []}]

    class _Iam:
        def get_paginator(self, name):
            return _Paginator()

    out = g.list_principals(_Iam())
    uids = {p["name"]: p["uid"] for p in out["principals"]}
    assert uids == {"R": "uid-role-1", "U": "uid-user-2"}


def test_uid_never_reaches_the_baseline():
    """`uid` 是**进程内**的判据，不进快照也不进基线。

    合法重建每天都发生（实测两个角色名当天各 4 次），把 uid 写进基线等于每天红一次
    而没有任何安全含义——那种噪音会训练出无脑 `--update-baseline`。
    两条断言：① 基线文件里没有 `uid` 这个键；② 快照合同 `BUNDLE_SHAPE` 也不接受它
    （递归默认拒绝，所以只要没写进合同就一定进不去）。
    """
    g = _gate()
    raw = _BASELINE.read_text(encoding="utf-8")
    assert '"uid"' not in raw, "基线里出现了 uid ——它会随合法重建每天变一次"
    assert "uid" not in g.BUNDLE_SHAPE["principals"]["*"], \
        "uid 进了快照合同——那条路会把它带进基线"


def test_measure_refuses_a_non_atomic_round():
    """**接线测试**：纯函数存在但没人调用，是这类闸门最经典的 false-green。

    按 AST 钉住 `measure()` 里三件事：① 复查真的又枚举了一次（`list_principals`
    出现 ≥2 次）；② 调了 `enumeration_drift`；③ 它的返回值为真时**抛 SystemExit**，
    而不是打印一条警告继续走。

    这条只证明**接线**，不证明语义——语义由上面那些用例证明。两层都要。
    """
    g = _gate()
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "measure")
    calls = [c.func.id for c in ast.walk(fn)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]
    assert calls.count("list_principals") >= 2, \
        f"measure() 只枚举了 {calls.count('list_principals')} 次——没有复查这一次"
    assert "enumeration_drift" in calls, "measure() 没调 enumeration_drift"

    # 找 `<名字> = enumeration_drift(...)`，再确认 `if <名字>:` 的分支里有 raise
    target = None
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "enumeration_drift"
                and isinstance(node.targets[0], ast.Name)):
            target = node.targets[0].id
    assert target, "enumeration_drift 的返回值没被赋给任何变量（结果被丢掉了？）"
    guarded = [n for n in ast.walk(fn)
               if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
               and n.test.id == target]
    assert guarded, f"没有 `if {target}:` 分支——漂移检测的结果没被判断"
    raises = [r for n in guarded for r in ast.walk(n)
              if isinstance(r, ast.Raise) and isinstance(r.exc, ast.Call)
              and isinstance(r.exc.func, ast.Name) and r.exc.func.id == "SystemExit"]
    assert raises, "检测到漂移后没有 raise SystemExit——那是 fail-open"


# --------------------------------------------------------------------------
# Codex 第八轮：**boundary 的文档内容原先不在原子性摘要里**（同一个"枚举范围比声称的
# 主语窄"）。摘要的 docstring 写着"全部授权输入"，而 principal dict 里只有
# `boundary_arn` —— boundary 那份托管策略换了默认版本、ARN 不变时，摘要的输入一个字
# 都不变 ⇒ 复查看不见，**而且这个变化是持久的**（不需要 ABA 那种巧合）。
#
# 两层都受影响，不只是 B：
#   - B 的 `boundaries[fp].stmt_fps` 是 T1 抄的 boundary 语句；
#   - A 走 `SimulatePrincipalPolicy(PolicySourceArn=...)`，而 AWS 文档明确
#     `permissionsBoundaryPolicyInputList` 是**覆盖**"已附加到实体上的 boundary"
#     ⇒ 不传它时用的就是实体当前那份 ⇒ T2 的判定按新 boundary 算。
# 于是 A 与 B 各自都"正常"，拼出来的快照描述两个时刻。
# --------------------------------------------------------------------------

_BOUNDARY = f"arn:aws:iam::{_ACCT}:policy/Boundary"


def test_boundary_document_change_with_same_arn_is_refused():
    """boundary ARN 不变、**文档内容**变了 ⇒ 必须作废本轮。

    这是复审给的反例①，实测复现过：修复前 `enumeration_drift` 返回 `{}`。
    """
    g = _gate()
    before = [_principal("SiteRole", uid="uid-site-1", boundary=_BOUNDARY,
                         boundary_statements=[_iam_stmt(effect="Deny", action="iam:*")],
                         policy_versions={_BOUNDARY: "v3"})]
    after = [_principal("SiteRole", uid="uid-site-1", boundary=_BOUNDARY,
                        boundary_statements=[_iam_stmt(effect="Deny",
                                                       action="iam:PutRolePolicy")],
                        policy_versions={_BOUNDARY: "v3"})]
    drift = g.enumeration_drift(before, after)
    assert "changed" in drift, f"boundary 文档变化没被咬住：{drift}"
    assert "SiteRole" in drift["changed"][0]


def test_boundary_default_version_change_is_refused():
    """boundary ARN 与语句都不变、只有 `DefaultVersionId` 变了 ⇒ 也作废本轮。

    这是复审给的反例②。为什么连"语句逐字相同"也要红：B 把 boundary 的版本号
    **持久化进基线**（`iam_write.managed_versions`），T1 记的版本与 T3 的现实不一致时，
    快照里那个值就是错的——而"版本号错一轮"与"权限面没动"是两件事。
    """
    g = _gate()
    st = [_iam_stmt(effect="Deny", action="iam:*")]
    before = [_principal("SiteRole", uid="uid-site-1", boundary=_BOUNDARY,
                         boundary_statements=st, policy_versions={_BOUNDARY: "v3"})]
    after = [_principal("SiteRole", uid="uid-site-1", boundary=_BOUNDARY,
                        boundary_statements=st, policy_versions={_BOUNDARY: "v4"})]
    assert "changed" in g.enumeration_drift(before, after)


def test_attached_managed_policy_version_change_is_refused():
    """attached 托管策略换默认版本（语句相同）**也**红。

    这条刻意与上一条同构：早先的实现把"只换版本号不换语句"写成一条**不声称**
    （"下一轮自己会红"）。那是个carve-out，而这个仓库被推翻的历次都是carve-out——
    `managed_versions` 同样进基线，同样的staleness，没有理由两套宽严。
    实测代价为零：7 天 CloudTrail 里 `CreatePolicyVersion` / `SetDefaultPolicyVersion`
    都是 **0** 次。
    """
    g = _gate()
    pol = f"arn:aws:iam::{_ACCT}:policy/Attached"
    st = [(pol, _iam_stmt())]
    before = [_principal("R", uid="uid-r-1", statements=st,
                         policy_versions={pol: "v1"})]
    after = [_principal("R", uid="uid-r-1", statements=st,
                        policy_versions={pol: "v2"})]
    assert "changed" in g.enumeration_drift(before, after)


def test_list_principals_records_boundary_statements_and_versions():
    """`list_principals` 必须真的把 boundary 语句与版本收进 principal。

    漏收的后果是**静默的**：两侧都是空 list / 空 dict ⇒ 摘要恒等 ⇒ 复查永远说"没变"，
    输出与"账号真的很安静"逐字相同。所以钉住产出，而不是只钉住摘要函数。
    """
    g = _gate()
    boundary_doc = {"Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "iam:*",
                                   "Resource": "*"}]}
    attached = f"arn:aws:iam::{_ACCT}:policy/Attached"

    class _Paginator:
        def paginate(self, **kw):
            return [{"RoleDetailList": [
                        {"RoleName": "R", "RoleId": "uid-role-1",
                         "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
                         "RolePolicyList": [],
                         "AttachedManagedPolicies": [{"PolicyArn": attached}],
                         "PermissionsBoundary": {
                             "PermissionsBoundaryArn": _BOUNDARY}}],
                     "UserDetailList": [], "GroupDetailList": [],
                     "Policies": [
                        {"Arn": _BOUNDARY, "PolicyVersionList": [
                            {"IsDefaultVersion": True, "VersionId": "v7",
                             "Document": boundary_doc}]},
                        {"Arn": attached, "PolicyVersionList": [
                            {"IsDefaultVersion": True, "VersionId": "v2",
                             "Document": {"Version": "2012-10-17",
                                          "Statement": [{"Effect": "Allow",
                                                         "Action": "s3:GetObject",
                                                         "Resource": "*"}]}}]}]}]

    class _Iam:
        def get_paginator(self, name):
            return _Paginator()

    (p,) = g.list_principals(_Iam())["principals"]
    assert p["boundary_arn"] == _BOUNDARY
    assert p["boundary_statements"] == boundary_doc["Statement"], \
        f"boundary 语句没收进来：{p.get('boundary_statements')}"
    assert p["policy_versions"] == {_BOUNDARY: "v7", attached: "v2"}, \
        f"策略版本没收全：{p.get('policy_versions')}"


# --------------------------------------------------------------------------
# 已接受的三个盲区（Codex 第八轮：原先"窗口内 IAM 变过就作废本轮 / 观测原子性"过宽）
#
# 下面这几条**断言的是限制本身**，不是能力。它们的作用有两个：
#   ① 把"这道复查只保证窗口两端相等"钉住，防止文档措辞再次悄悄放大成"原子";
#   ② 哪天真的实现了事件屏障，这几条会**变红**——那正是要的信号：能力变了，
#      `enumeration_drift` 的 docstring 与 `account-trust-boundary.md` 的口径必须同时改。
# --------------------------------------------------------------------------

def test_change_then_revert_is_a_known_blind_spot():
    """ABA：T1 有授权 → 窗口内撤掉（A 的模拟看到的是这个）→ T3 恢复成与 T1 逐字相同。

    两点比较必然报无漂移。要关掉它需要独立的单调事件源，而 CloudTrail 有投递延迟
    （分钟级、无上界保证），拿它当同步屏障要么阻塞不确定的时间、要么给虚假保证。
    """
    g = _gate()
    t1 = [_principal("R", uid="uid-r-1", statements=[(None, _iam_stmt())])]
    t3 = copy.deepcopy(t1)
    assert g.enumeration_drift(t1, t3) == {}, \
        "如果这条红了，说明复查已经不只是两端比较——去改 docstring 与文档口径"


def test_created_then_deleted_between_enumerations_is_a_known_blind_spot():
    """枚举后新建、复查前删除：两端都不存在 ⇒ 整轮不知道它来过。"""
    g = _gate()
    t1 = [_principal("R", uid="uid-r-1")]
    t3 = [_principal("R", uid="uid-r-1")]
    # 中间那个 `site-rt-ephemeral` 在 t1 与 t3 里都没有身影
    assert g.enumeration_drift(t1, t3) == {}


def test_pagination_window_is_a_known_blind_spot():
    """**单次枚举自己也不是一个时刻**：角色详情与它 attached 托管策略的**文档**可以来自
    不同的分页。

    `GetAccountAuthorizationDetails` 的 `RoleDetailList` 与 `Policies` 是同一趟分页遍历
    里的两个分节，整趟实测跨约 90 秒。策略在翻页之间被改，组装出来的 principal 就把
    「先到那页的角色」与「后到那页的策略文档」拼在一起——这两个状态**从未同时存在过**，
    而 `list_principals` 不做跨页一致性检查（拿到的分页里也没有能做的信息）。

    这条断言的是**限制本身**：拼出来的语句取自后到的那一页，而且整个过程无声。
    """
    g = _gate()
    attached = f"arn:aws:iam::{_ACCT}:policy/Attached"
    before_change = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    after_change = {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"}

    class _Paginator:
        def paginate(self, **kw):
            # 第 1 页：角色（此刻 attached 策略还是 before_change）
            yield {"RoleDetailList": [
                       {"RoleName": "R", "RoleId": "uid-role-1",
                        "Arn": f"arn:aws:iam::{_ACCT}:role/R", "Path": "/",
                        "RolePolicyList": [],
                        "AttachedManagedPolicies": [{"PolicyArn": attached}]}],
                   "UserDetailList": [], "GroupDetailList": [], "Policies": []}
            # 第 2 页：翻页期间那份策略被改了，于是文档分节带回来的是新版本
            yield {"RoleDetailList": [], "UserDetailList": [], "GroupDetailList": [],
                   "Policies": [{"Arn": attached, "PolicyVersionList": [
                       {"IsDefaultVersion": True, "VersionId": "v2",
                        "Document": {"Version": "2012-10-17",
                                     "Statement": [after_change]}}]}]}

    class _Iam:
        def get_paginator(self, name):
            return _Paginator()

    (principal,) = g.list_principals(_Iam())["principals"]
    assert principal["statements"] == [(attached, after_change)], (
        "如果这条红了，说明枚举已经能识别跨页不一致——"
        "去改 enumeration_drift 的 docstring 与文档口径")
    assert before_change not in [st for _, st in principal["statements"]]


# 三份文档的口径守卫 + 数量自查。**判据为什么要覆盖三份**（Codex 第八轮）：
# 上一版只读 `account-trust-boundary.md`，于是 `CLAUDE.md` 里残留的「原子性复查」
# 整整过了一轮没被抓到——而 CLAUDE.md 恰恰是 Agent 的操作入口，那句话会让后续执行者
# 把「窗口两端一致」重新读成原子保证。**守卫的主语必须与声明出现的范围一样宽。**
_ATOMIC_OVERCLAIMS = ("原子性复查", "观测原子性", "本轮观测是原子的",
                      "整轮都原子", "原子快照", "原子性检查")
# 三个盲区各自的点名判据。**逐个列出**而不是只查"盲区"两个字：实测把盲区②整段删掉，
# 只查"改回 / 分页"的旧守卫仍然 1 passed。
# 判据取每个盲区**独有的机制描述**，不取单个词。实测教训：第一版用的是「改回」与
# 「分页」这种短词，而文档别处也在说这两件事（boundary 那段就写着"不需要'改了又改回来'
# 那种巧合"）⇒ 把盲区①整段删掉，守卫照样 2 passed。**判据比主语弱和比主语窄一样危险。**
_BLIND_SPOTS = (("恢复成与 T1 逐字相同", "①改了又改回来（ABA）"),
                ("复查前删除", "②枚举后新建、复查前删除"),
                ("翻页期间的变化不可见", "③单次枚举自己不是一个时刻"))


def test_docs_do_not_claim_atomic_observation():
    """三份 tracked 文档都不许把这道复查说成"原子"；结论真源必须点名全部三个盲区。

    判据是**成对的**：既不许出现过宽说法，也必须写着收窄后的口径与三个盲区——
    只做黑名单 grep 的话，把整段删掉也能过。
    """
    claude_md = (_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    truth = _DOC.read_text(encoding="utf-8")
    spec = (_ROOT / "docs" / "superpowers" / "specs"
            / "2026-08-27-codebuild-bootstrap-read-narrowing-spec.md"
            ).read_text(encoding="utf-8")
    for label, text in (("CLAUDE.md", claude_md),
                        ("account-trust-boundary.md", truth),
                        ("3b spec", spec)):
        for overclaim in _ATOMIC_OVERCLAIMS:
            assert overclaim not in text, \
                f"{label} 里还留着过宽的说法：{overclaim!r}"
    # 结论真源要写清收窄后的口径，并逐个点名三个盲区
    assert "两端" in truth, "风险文档没写收窄后的口径（窗口两端一致）"
    for needle, what in _BLIND_SPOTS:
        assert needle in truth, f"风险文档没点名这个盲区：{what}（找不到 {needle!r}）"
    # CLAUDE.md 是操作入口：至少要让读者知道这道复查的口径是"两端"，而不是原子
    assert "两端" in claude_md, "CLAUDE.md 没写这道复查的口径是「两端一致」"


def test_blind_spot_test_count_matches_the_documented_claim():
    """文档写"三个盲区各有一条用例"——这里数一遍实际有几条。

    上一轮这句话与现实差了一条（只有两条，缺分页那个）而没人抓到。
    **数量声明本身也要有守卫**：它和"14 个由基线断言的数字"是同一类，
    写下一个计数就等于开了一张需要兑现的支票。
    """
    src = Path(__file__).read_text(encoding="utf-8")
    n = len(re.findall(r"def test_\w+_is_a_known_blind_spot\(", src))
    assert n == len(_BLIND_SPOTS), (
        f"盲区用例实际 {n} 条，而 `_BLIND_SPOTS` 与文档都写着 {len(_BLIND_SPOTS)} 个盲区"
        f"——两者必须同时改")
