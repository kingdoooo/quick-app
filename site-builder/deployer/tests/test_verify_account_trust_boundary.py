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


def test_uniform_missing_keys_collapse_the_resource_dimension():
    """所有非 allowed 资源缺的是**同一组**键时，资源那一维零信息量 ⇒ 折叠成 unattributed。

    **实测依据**（40 个 principal / 78 条 EvaluationResults）：AWS 把顶层缺的键机械地
    复制进每一个逐资源条目，键集完全相同，而缺的是 `aws:ResourceAccount` /
    `aws:CalledViaLast` / `iam:PassedToService` 这类**请求上下文**键——与具体资源无关。
    照"每个非 allowed 资源各记一项"扇开，实测产生 **9985** 条成员（基线涨 10 倍），
    而新增一个带 Condition 的 principal 会一次冒出几十条 ⇒ 红被噪音淹没。
    """
    g = _gate()
    pairs = g.undecided_pairs([{
        "EvalActionName": "iam:PutRolePolicy", "EvalDecision": "implicitDeny",
        "MissingContextValues": ["aws:ResourceAccount"],
        "ResourceSpecificResults": [
            {"EvalResourceName": "target-a", "EvalResourceDecision": "implicitDeny",
             "MissingContextValues": ["aws:ResourceAccount"]},
            {"EvalResourceName": "target-b", "EvalResourceDecision": "allowed"},
            {"EvalResourceName": "target-c", "EvalResourceDecision": "explicitDeny",
             "MissingContextValues": ["aws:ResourceAccount"]},
        ]}])
    assert pairs == {("iam:PutRolePolicy", "")}, pairs


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
# 这是这道闸门被复审五轮的根因。
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
