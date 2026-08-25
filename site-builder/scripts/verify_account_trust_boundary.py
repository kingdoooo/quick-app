#!/usr/bin/env python3
"""账号信任边界的漂移闸门（M09 第 2 步的可执行部分）。

**它不是 M09 的修复，也不假装是。** M09 那条缺陷——同账号持有
`lambda:InvokeFunction` 的 principal 可以直接 invoke panel 与站点 Lambda、
在合成 event 里伪造 `x-user-email`——在**本账号里关不掉**：

- SCP 对 Organizations 管理账号无效，而本部署就在管理账号（`policies/README.md` 边界①）；
- Lambda 的 resource policy 没有写 Deny 的 API（`AddPermission` 只能写 Allow）；
- 应用层给 Edge 加签名也不成立：能读到那把 HS256 密钥的 principal 远多于能 invoke 的，
  于是签名与被签名的东西都在攻击者手里。

**只收窄 `lambda:InvokeFunction` 是假修复**：同一批 principal 还握着密钥读取、
`lambda:UpdateFunctionCode` 与 `iam:PutRolePolicy`，边界一寸也没有移动。
更要紧的是——**冒充任意用户根本不需要 invoke**：拿到密钥就能签任意 email 的会话
cookie 与 `scope=console` 的 `__Host-sb_console`（同一个 `/site-builder/jwt-secret`）。
完整风险模型与实测证据见 `docs/security/account-trust-boundary.md`。

在那之前，本脚本承担唯一还能自动化的职责：**这个集合别再长**。

## 它测三层，每层的粒度都是刻意选的

① **identity 授权**（`iam:SimulatePrincipalPolicy`，枚举全部非 service-linked 角色
   与 IAM 用户）。授权记成 `grant` 字符串而**不是布尔标签**：
   `invoke-platform:site-panel` 与 `invoke-platform:site-deployer-undeploy` 是两条
   不同的 grant。压成一个 `invoke-platform` 布尔时，「某角色原来只能调 undeploy，
   现在还能调 panel」这种**安全相关的资源扩权**会静静地绿——那正是 panel 读面
   失守与否的分界。站点函数按类聚合（`invoke-site:all` / `invoke-site:some(k)`），
   否则每建一个站点都会把基线拽红。

② **resource policy**（`lambda:GetPolicy`，**含每个 alias**）。
   `SimulatePrincipalPolicy` **不会**自动纳入 resource policy（AWS 契约：它只能
   为 IAM user 选择性地带一份，对 role 根本不支持），而同账号 resource-based
   Allow 单独即可授权 ⇒ 只测 ① 会漏掉「给某个角色新加一条 `AddPermission`」。
   平台函数逐个记；站点函数记下**全部合法形态**（M7 之后两种都合法：迁移来的
   站点残留一份未限定 policy，新建的只有 alias 那一份），匹配任一形态即合规，
   于是新建站点不产生漂移、而多一条或少一条语句的站点被点名。

   **alias 不能漏**：M7 之后站点的 Function URL 与其授权语句都挂在 `blue` 上，
   只读未限定那份会把整条 invoke 授权面看漏——实测 M7 后新建的站点未限定
   policy 根本不存在。identity 侧同理：`function:foo` 与 `function:foo:blue`
   在 IAM 里是两个资源，所以 ① 也把 alias ARN 一起探。

③ **密钥物化位置的事实**。密钥有三处明文副本，本脚本每次都**实测**而不是假设：
   Edge 函数产物（`lambda:GetFunction`）、**CDK bootstrap S3 asset**
   （`s3:GetObject`；asset ARN 从**已部署的 CloudFormation 模板**推导，不手抄
   对象 key）、以及 SSM 参数本身。三处都比对 SHA-256；某处不再含活密钥时，
   对应的 grant 会自动消失并报成改善——根治了它，闸门自己就知道。

## 它**不**证明什么（别把它当"暴露面已穷尽"）

- `SimulatePrincipalPolicy` 对带 Condition 的策略需要调用方补 `ContextEntries`；
  本脚本不补，于是那些 principal 的判定是**下界**。带 `MissingContextValues`
  的响应数被记进基线并打印，涨了就说明"不确定的部分变多了"。
- 它只看 IAM 与 Lambda resource policy 两条通道，不看 KMS grants、
  VPC endpoint policy、以及其它服务的 resource policy。
- 它不看跨账号 principal（本账号内的暴露面已经足够大）。

用法（**用系统 python3 跑**，deployer/.venv 的 CA 信任库是空的）：

    python3 site-builder/scripts/verify_account_trust_boundary.py
    python3 site-builder/scripts/verify_account_trust_boundary.py --update-baseline
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures as cf
import configparser
import hashlib
import io
import json
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SITE_BUILDER = _HERE.parent
BASELINE_PATH = _HERE / "account_trust_baseline.json"
CONFIG_PATH = _SITE_BUILDER / "config.ini"
APP_PY = _SITE_BUILDER / "deployer" / "infra" / "app.py"

BASELINE_SCHEMA = 2
JWT_PARAM_NAME = "/site-builder/jwt-secret"
DEPLOYER_EXEC_ROLE = "site-deployer-exec-role"

# Edge 函数名：router 栈的两个 Lambda@Edge 里，**origin-request 那个**才内联着
# 会话密钥（`stack.py` 把 `{{JWT_SECRET}}` 替换进它）。origin-response 不验签。
EDGE_ORIGIN_REQUEST_FN = "ApplicationWebRouterStack-application-web-router"
# 产物里密钥的形态：`JWT_SECRET = "<64 hex>"`。只用来**定位**，不打印取到的值。
_SECRET_ASSIGN_RE = re.compile(r"""JWT_SECRET\s*=\s*["']([^"']*)["']""")

# ---- grant 词表 ----------------------------------------------------------
# grant 是 `种类[:资源]` 形态的字符串，进基线文件。改词表等于基线全量漂移。
G_INVOKE_PLATFORM = "invoke-platform"      # + ":<函数名>"
G_INVOKE_SITE = "invoke-site"              # + ":all" / ":some(k)"
G_REPLACE_CODE = "replace-platform-code"   # + ":<函数名>"
# 读密钥的三条路**必须分开记**：严重度与修法都不同。
#  · read-edge-code：`lambda:GetFunction` 下载 Edge 产物，密钥是**明文**在
#    `index.py` 里（Lambda@Edge 不支持环境变量，只能部署时字符串替换）。
#    不经 KMS、不需 invoke。AWS 托管的 `ReadOnlyAccess` 就带这个动作。
#  · read-edge-asset：同一份产物在 **CDK bootstrap S3 桶**里还有一份（asset）。
#    每次 Edge 部署留一个新对象，旧对象不会被删 ⇒ 密钥不轮转的话，**历次**
#    asset 都带着当前有效的密钥。桶策略只 Deny 非 TLS；对象用 `alias/aws/s3`，
#    该托管键的策略是 `Principal:*` + `ViaService=s3` 的**直接授权**，所以
#    identity policy 里的 `s3:GetObject` 单独就够。
#  · read-jwt-param：`ssm:GetParameter` 读 SecureString。KMS 那道同样是虚的
#    （`alias/aws/ssm` 的 key policy 是同一种直接授权形态）。
G_READ_EDGE_CODE = "read-edge-code"
G_READ_EDGE_ASSET = "read-edge-asset"
G_READ_JWT_PARAM = "read-jwt-param"
G_SELF_ESCALATE = "self-escalate"
SECRET_GRANTS = (G_READ_EDGE_CODE, G_READ_EDGE_ASSET, G_READ_JWT_PARAM)

# 两条正向控制：这两个 principal **必须**保留下列 grant（按前缀命中即可）。
# 丢了的真机症状分别是「全站 403」与「每次部署在健康门失败」，两者都不会在
# 任何单测里出现——所以收窄动作把平台自己锁死时，只有这条会红。
REQUIRED_GRANT_PREFIXES = {
    "edge": (f"{G_INVOKE_PLATFORM}:", f"{G_INVOKE_SITE}:"),
    "deployer": (f"{G_INVOKE_SITE}:",),
}

ACTIONS = ("lambda:InvokeFunction", "lambda:UpdateFunctionCode",
           "lambda:GetFunction", "ssm:GetParameter", "iam:PutRolePolicy",
           "s3:GetObject")


# ---------------------------------------------------------------- 纯函数部分

def _group(hex_digest: str, size: int = 4) -> str:
    return "-".join(hex_digest[i:i + size] for i in range(0, len(hex_digest), size))


def principal_fingerprint(arn: str) -> str:
    """ARN → 16 位指纹。

    基线文件里**只能**出现指纹：账号内若干角色的名字内嵌账号 ID（CDK bootstrap
    那几个），照抄角色名就把账号值提交进了仓库（仓库红线）。指纹单向、稳定，
    足够回答"这个 principal 之前在不在基线里"。

    **每 4 位分组**（`a1b2-c3d4-…`）不是为了好看：裸 16 位十六进制里会偶然出现
    12 位连续数字，而 `scripts/scan_staged_secrets.sh` 按 `[0-9]{12}` 找账号 ID
    ⇒ 每次更新基线都命中一次假阳性。假阳性反复出现的代价是有人开始无脑
    `--allow-hits`，那时真的账号值就进去了。分组让最长数字串等于 4，结构上不可能命中。
    """
    return _group(hashlib.sha256(arn.encode("utf-8")).hexdigest()[:16])


def decisions_from_simulation(evaluation_results: list[dict]) -> dict[str, str]:
    """`SimulatePrincipalPolicy` 的结果 → `{"action|resource_arn": decision}`。

    **必须读 `ResourceSpecificResults`。** 传多个 `ResourceArns` 时，顶层
    `EvalDecision` 是聚合项、顶层 `EvalResourceName` 是
    `arn:aws:lambda:${Region}:${Account}:${ResourceType}:${ResourceId}` 这样的
    ARN 模板。只读顶层会把「对某一个函数 allowed」读成「对全部资源 allowed」，
    而且模板串会作为一个不存在的资源混进结果里。
    """
    out: dict[str, str] = {}
    for res in evaluation_results:
        action = res["EvalActionName"]
        per_resource = res.get("ResourceSpecificResults") or []
        if not per_resource:
            # 单资源（或未传 ResourceArns）时 AWS 只给顶层。此时顶层就是真值，
            # 但要挡住 ARN 模板混进来。
            name = res.get("EvalResourceName", "*")
            if "${" not in name:
                out[f"{action}|{name}"] = res["EvalDecision"]
            continue
        for rr in per_resource:
            out[f"{action}|{rr['EvalResourceName']}"] = rr["EvalResourceDecision"]
    return out


def missing_context_in(evaluation_results: list[dict]) -> bool:
    """这批判定里有没有"因为缺 Condition 上下文而不确定"的部分。

    有的话，该 principal 的 grant 集合只是**下界**。本脚本不补
    `ContextEntries`（补不全），但必须把"不确定"这件事记下来，
    不能把未知静默压成"没有权限"。
    """
    return any(res.get("MissingContextValues") for res in evaluation_results)


@dataclass(frozen=True)
class Targets:
    """模拟的目标资源（ARN 形态，由调用方按真实账号拼好）。

    `edge_asset` 可以为 None——那表示已部署的 asset 里**不再**含活密钥
    （根治之后的正常状态），此时不产生 `read-edge-asset` grant。

    `alias_arns` 把未限定 ARN 映射到它的 alias ARN。**必须有这一层**：M7 之后
    站点的 Function URL 与 resource policy 都挂在 `blue`/`green` alias 上，而
    IAM 里 `function:foo` 与 `function:foo:blue` 是两个不同的资源。只探未限定
    ARN 时，「只在 alias 上被授权」的 principal 会被读成"没有权限"。
    """
    platform_functions: tuple[str, ...]
    site_functions: tuple[str, ...]
    edge_function: str | None
    edge_asset: str | None
    jwt_parameter: str
    any_role: str
    alias_arns: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def all_invoke_resources(self) -> list[str]:
        out = list(self.platform_functions) + list(self.site_functions)
        for arns in self.alias_arns.values():
            out.extend(arns)
        return out


def _fn_name(arn: str) -> str:
    return arn.rsplit(":function:", 1)[-1]


def grants_from_decisions(decisions: dict[str, str], t: Targets) -> set[str]:
    """逐资源判定 → grant 集合。

    **平台函数逐个记名字**：`invoke-platform` 压成一个布尔时，
    「只能调 undeploy」与「还能调 panel」在基线里长得一样，而后者才是
    panel 读面失守的入口。
    **站点函数按类聚合**：逐个记名字会让每次建站/下线都把基线拽红。
    **invoke 取未限定 ARN 与 alias ARN 的并**：能碰到这份代码就算能碰到，
    走 `foo` 还是 `foo:blue` 不改变后果。
    """
    def allowed(action: str, resource: str) -> bool:
        return decisions.get(f"{action}|{resource}") == "allowed"

    def can_invoke(arn: str) -> bool:
        return allowed("lambda:InvokeFunction", arn) or any(
            allowed("lambda:InvokeFunction", a)
            for a in t.alias_arns.get(arn, ()))

    grants = set()
    for arn in t.platform_functions:
        if can_invoke(arn):
            grants.add(f"{G_INVOKE_PLATFORM}:{_fn_name(arn)}")
        # UpdateFunctionCode 只作用于未限定函数（alias 没有自己的代码）。
        if allowed("lambda:UpdateFunctionCode", arn):
            grants.add(f"{G_REPLACE_CODE}:{_fn_name(arn)}")

    if t.site_functions:
        n = sum(1 for arn in t.site_functions if can_invoke(arn))
        if n == len(t.site_functions):
            grants.add(f"{G_INVOKE_SITE}:all")
        elif n:
            # 子集形态记数量：从 1 个涨到 2 个必须红。数量随站点增删变化时也会红
            # ——那是安全方向的误报，且当前没有任何 principal 处于子集形态。
            grants.add(f"{G_INVOKE_SITE}:some({n})")

    if t.edge_function and allowed("lambda:GetFunction", t.edge_function):
        grants.add(G_READ_EDGE_CODE)
    if t.edge_asset and allowed("s3:GetObject", t.edge_asset):
        grants.add(G_READ_EDGE_ASSET)
    if allowed("ssm:GetParameter", t.jwt_parameter):
        grants.add(G_READ_JWT_PARAM)
    if allowed("iam:PutRolePolicy", t.any_role):
        grants.add(G_SELF_ESCALATE)
    return grants


def statement_fingerprint(statement: dict, *, account: str, function: str,
                          qualifier: str | None = None) -> str:
    """Lambda resource policy 的单条语句 → 指纹。

    归一化掉账号 ID、**函数自身**的名字、以及 alias 名，这样不同站点函数的
    `edge-invoke` 语句会得到同一个指纹 ⇒ 可以用少数几份"形态"覆盖全部站点函数，
    新建站点不产生漂移，而多出一条语句的站点会被咬住。

    **alias 名归一化成 `<alias>` 而不是抹掉**：挂在 `blue` 上与挂在未限定函数上
    是两种不同宽度的授权（后者更宽），抹掉会让两者变成同一个指纹。

    只存指纹：语句里的 Principal 是带账号 ID 的角色 ARN（仓库红线）。
    """
    raw = json.dumps(statement, sort_keys=True, ensure_ascii=False)
    raw = raw.replace(account, "<acct>")
    if qualifier:
        raw = raw.replace(f"{function}:{qualifier}", "<self>:<alias>")
    raw = raw.replace(function, "<self>")
    return _group(hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16])


def resource_policy_snapshot(policies: dict[str, list[tuple[str | None, dict]]], *,
                             account: str, platform: tuple[str, ...],
                             sites: tuple[str, ...]) -> dict:
    """`{函数名: [(qualifier, 语句)…]}` → 逐函数的指纹快照。**这里不做任何判断。**

    形态由基线定（见 `site_policy_shapes` 与 `compare_to_baseline`）。
    早先版本在这里用**并集**算规范形态，结果最宽松的那个站点函数反而成了规范、
    规矩的那个被报成偏离——判断和观测混在一处就会这样。
    """
    def fps(fn: str) -> list[str]:
        return sorted({statement_fingerprint(s, account=account, function=fn,
                                             qualifier=q)
                       for q, s in policies.get(fn, [])})

    return {"platform": {fn: fps(fn) for fn in platform},
            "sites": {fn: fps(fn) for fn in sites}}


def site_policy_shapes(sites: dict[str, list[str]]) -> list[list[str]]:
    """站点函数 resource policy 的**全部形态**（去重后按出现次数降序）。

    为什么是"一组形态"而不是"一份规范"：M7 之后两种形态都合法——
    从旧结构迁移过来的站点残留一份未限定 policy（其未限定 Function URL 已删），
    而 M7 之后新建的站点只有 alias 上那一份。用众数会把其中一类整体报成偏离；
    用并集会把最宽松的当规范。所以基线记下所有形态，比对时"匹配任一形态即合规"。
    """
    counts: dict[tuple[str, ...], int] = {}
    for fps in sites.values():
        key = tuple(sorted(fps))
        counts[key] = counts.get(key, 0) + 1
    return [list(k) for k, _ in sorted(counts.items(),
                                       key=lambda kv: (-kv[1], kv[0]))]


@dataclass
class Report:
    new_principals: list[str] = field(default_factory=list)
    new_grants: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    new_statements: list[str] = field(default_factory=list)
    site_policy_outliers: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.new_principals or self.new_grants
                    or self.missing_required or self.new_statements
                    or self.site_policy_outliers)

    def render(self) -> str:
        lines = []
        for label, rows in (
                ("新增 principal（红）", self.new_principals),
                ("已知 principal 长出新授权（红）", self.new_grants),
                ("必需授权丢失（红）", self.missing_required),
                ("新增 resource policy 语句（红）", self.new_statements),
                ("站点函数的 resource policy 偏离规范形态（红）",
                 self.site_policy_outliers),
                ("基线里未分类（请标注 category）", self.unclassified),
                ("集合缩小（绿；可更新基线）", self.improvements),
                ("事实与口径（不参与红绿）", self.notes)):
            if rows:
                lines.append(f"{label}：")
                lines.extend(f"  - {r}" for r in rows)
        if not lines:
            lines.append("与基线一致。")
        return "\n".join(lines)


def compare_to_baseline(observed: dict[str, dict], baseline: dict, *,
                        required: dict[str, str],
                        resource_policies: dict | None = None) -> Report:
    """observed = {fingerprint: {"name", "arn", "grants"}}。

    `required` 把标签映射到**角色名**（Edge 的角色名来自 config.ini，
    所以不能写死在这里）；每个标签要求哪些 grant 前缀由
    `REQUIRED_GRANT_PREFIXES` 定。
    """
    base = baseline.get("principals", {})
    rep = Report()

    for fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        grants = set(p["grants"])
        if fp not in base:
            rep.new_principals.append(f"{p['name']}  [{fp}]  {sorted(grants)}")
            continue
        gained = grants - set(base[fp].get("grants", []))
        if gained:
            rep.new_grants.append(f"{p['name']}  [{fp}]  +{sorted(gained)}")
        if base[fp].get("category") in (None, "", "unclassified"):
            rep.unclassified.append(f"{p['name']}  [{fp}]")

    for fp, b in sorted(base.items()):
        if fp not in observed:
            rep.improvements.append(
                f"[{fp}] 不再具备任何敏感授权（原 {b.get('category', '?')}："
                f"{sorted(b.get('grants', []))}）")

    by_name = {p["name"]: set(p["grants"]) for p in observed.values()}
    for label, role_name in required.items():
        prefixes = REQUIRED_GRANT_PREFIXES[label]
        have = by_name.get(role_name)
        if have is None:
            rep.missing_required.append(
                f"{role_name}（{label}）不在结果里——它必须保留 {list(prefixes)}")
            continue
        for prefix in prefixes:
            if not any(g.startswith(prefix) for g in have):
                rep.missing_required.append(
                    f"{role_name}（{label}）缺 {prefix}*（现有 {sorted(have)}）")

    if resource_policies is not None:
        base_rp = baseline.get("resource_policies") or {}
        base_platform = base_rp.get("platform", {})
        for fn, fps in sorted(resource_policies.get("platform", {}).items()):
            gained = set(fps) - set(base_platform.get(fn, []))
            if gained:
                rep.new_statements.append(f"{fn}: +{sorted(gained)}")
            lost = set(base_platform.get(fn, [])) - set(fps)
            if lost:
                rep.improvements.append(f"{fn} 少了 resource policy 语句 {sorted(lost)}")
        # 站点函数：逐个与**基线里记下的那几种形态**对齐。新建站点只要落在已知
        # 形态里就不产生漂移；多一条或少一条语句的站点匹配不上任何形态，被点名。
        shapes = [set(s) for s in base_rp.get("site_shapes", [])]
        for fn, fps in sorted((resource_policies.get("sites") or {}).items()):
            if any(set(fps) == s for s in shapes):
                continue
            nearest = min(shapes, key=lambda s: len(s ^ set(fps)), default=set())
            extra = sorted(set(fps) - nearest)
            missing = sorted(nearest - set(fps))
            detail = []
            if extra:
                detail.append(f"多出语句 {extra}")
            if missing:
                detail.append(f"缺语句 {missing}（该站点可能已无法经 Edge 访问）")
            rep.site_policy_outliers.append(
                f"{fn}: " + "；".join(detail or [f"形态 {sorted(fps)} 不在基线里"]))

    facts = baseline.get("facts") or {}
    if facts:
        rep.notes.append(
            f"基线记录的事实：带 MissingContextValues 的 principal "
            f"{facts.get('principals_with_missing_context', '?')} 个"
            f"（他们的 grant 只是下界）；bootstrap 桶里带当前有效密钥的 asset "
            f"{facts.get('edge_assets_carrying_live_key', '?')} 个")
    return rep


def platform_function_names(app_py: Path = APP_PY) -> tuple[str, ...]:
    """`infra/app.py` 的 `PLATFORM_FUNCTION_NAMES`（AST 取，不 import——
    app.py 顶层 import aws_cdk，普通解释器里没有）。

    手抄一份平台函数名清单就会与栈漂移：新加一个平台函数时，
    它会被当成"用户站点"，于是逐函数的 grant 少记一条。
    """
    src = app_py.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == "PLATFORM_FUNCTION_NAMES"):
            return tuple(e.value for e in node.value.elts)  # type: ignore[attr-defined]
    raise SystemExit(f"{app_py} 里找不到 PLATFORM_FUNCTION_NAMES——闸门会空转")


def read_config(path: Path = CONFIG_PATH) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(path, encoding="utf-8")
    if not cfg.sections():
        raise SystemExit(
            f"{path} 读不到任何段——configparser 对缺失文件是静默的，"
            f"再往下跑会拿空值拼出假结论。先确认路径与 cwd。")
    return cfg


def secret_in_zip_bytes(blob: bytes, secret: str) -> bool:
    """zip 里的 .py 是否含 `secret` 这个字面量。**不打印、不返回密钥本身。**"""
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        src = b"".join(z.read(n) for n in z.namelist()
                       if n.endswith(".py")).decode("utf-8", "ignore")
    except (zipfile.BadZipFile, KeyError):
        return False
    return any(m == secret for m in _SECRET_ASSIGN_RE.findall(src)) or secret in src


# ---------------------------------------------------------------- 真机部分

def _aws_clients(region: str):
    import boto3
    from botocore.config import Config
    cfg = Config(retries={"max_attempts": 12, "mode": "adaptive"})
    return {n: boto3.client(n, region_name=region, config=cfg)
            for n in ("iam", "lambda", "sts", "s3", "ssm", "cloudformation")}


def list_principals(iam) -> list[dict]:
    """非 service-linked 角色 + 全部 IAM 用户。

    **用户不能漏**：账号 owner 的 IAM 用户同样是一个 principal，只数角色会漏掉它。
    """
    out = []
    for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["User", "Role"]):
        for r in page.get("RoleDetailList", []):
            if r["Path"].startswith("/aws-service-role/"):
                continue
            out.append({"kind": "role", "name": r["RoleName"], "arn": r["Arn"]})
        for u in page.get("UserDetailList", []):
            out.append({"kind": "user", "name": u["UserName"], "arn": u["Arn"]})
    return out


def site_function_names(lam, platform: tuple[str, ...]) -> tuple[str, ...]:
    names = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            n = fn["FunctionName"]
            if n.startswith("site-") and n not in platform:
                names.append(n)
    return tuple(sorted(names))


def edge_asset_location(clients, function_name: str) -> tuple[str, str]:
    """已部署 Edge 函数的 CDK asset 在哪（bucket, key）。

    **从函数自己的 CloudFormation tag 推栈名、再读已部署模板**——不手抄栈名、
    也不手抄对象 key。手抄 key 的闸门在下一次 Edge 部署后就在测一个旧对象。
    """
    tags = clients["lambda"].get_function(FunctionName=function_name).get("Tags", {})
    stack = tags.get("aws:cloudformation:stack-name")
    if not stack:
        raise SystemExit(f"{function_name} 没有 CloudFormation stack tag——"
                         f"推不出 asset 位置，闸门会漏掉 read-edge-asset 这条路")
    body = clients["cloudformation"].get_template(
        StackName=stack, TemplateStage="Processed")["TemplateBody"]
    if isinstance(body, str):
        body = json.loads(body)
    for res in body.get("Resources", {}).values():
        if res.get("Type") != "AWS::Lambda::Function":
            continue
        if res.get("Properties", {}).get("FunctionName") != function_name:
            continue
        code = res["Properties"].get("Code", {})
        if "S3Bucket" in code and "S3Key" in code:
            return code["S3Bucket"], code["S3Key"]
    raise SystemExit(f"{stack} 的模板里找不到 {function_name} 的 S3 asset——"
                     f"它可能改成了内联代码，这条路要重新判定")


def count_assets_carrying_key(clients, bucket: str, secret: str,
                              max_size: int = 200 * 1024) -> int:
    """bootstrap 桶里有多少个 asset 仍带着**当前有效**的密钥。

    每次 Edge 部署留一个新对象、旧对象不删 ⇒ 这个数只会涨。它是"轮转密钥
    需要连带清理什么"的度量，也是"根治没做完"的度量。不参与红绿。
    """
    n = 0
    for page in clients["s3"].get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            if not obj["Key"].endswith(".zip") or obj["Size"] > max_size:
                continue
            blob = clients["s3"].get_object(
                Bucket=bucket, Key=obj["Key"])["Body"].read()
            if secret_in_zip_bytes(blob, secret):
                n += 1
    return n


def function_aliases(lam, names) -> dict[str, tuple[str, ...]]:
    """`{函数名: (alias 名…)}`。M7 之后站点函数都有 `blue`/`green`。"""
    out = {}
    for name in names:
        aliases = []
        for page in lam.get_paginator("list_aliases").paginate(FunctionName=name):
            aliases.extend(a["Name"] for a in page["Aliases"])
        if aliases:
            out[name] = tuple(sorted(aliases))
    return out


def function_policy_statements(lam, name: str,
                              aliases: tuple[str, ...]) -> list[tuple[str | None, dict]]:
    """未限定函数 + 每个 alias 的 resource policy 语句。

    **不能只读未限定的那份**：M7 之后站点的 Function URL 与它的授权语句都挂在
    alias 上，只读未限定会把整条 invoke 授权面看漏（实测：M7 之后新建的站点
    未限定 policy 根本不存在）。
    """
    out: list[tuple[str | None, dict]] = []
    for qualifier in (None, *aliases):
        kw = {"FunctionName": name}
        if qualifier:
            kw["Qualifier"] = qualifier
        try:
            doc = json.loads(lam.get_policy(**kw)["Policy"])
        except lam.exceptions.ResourceNotFoundException:
            continue
        out.extend((qualifier, s) for s in doc.get("Statement", []))
    return out


def simulate(iam, principal_arn: str, t: Targets) -> tuple[dict[str, str], bool]:
    resources = [r for r in (t.all_invoke_resources()
                             + [t.edge_function, t.edge_asset, t.jwt_parameter,
                                t.any_role]) if r]
    out: dict[str, str] = {}
    missing = False
    for page in iam.get_paginator("simulate_principal_policy").paginate(
            PolicySourceArn=principal_arn, ActionNames=list(ACTIONS),
            ResourceArns=resources):
        out.update(decisions_from_simulation(page["EvaluationResults"]))
        missing = missing or missing_context_in(page["EvaluationResults"])
    return out, missing


def measure(region: str, *, workers: int = 4, scan_assets: bool = True) -> dict:
    clients = _aws_clients(region)
    iam, lam = clients["iam"], clients["lambda"]
    cfg = read_config()
    account = clients["sts"].get_caller_identity()["Account"]

    edge_role_arn = cfg.get("Deployer", "edge_role_arn").split("#")[0].strip()
    cfg_account = edge_role_arn.split(":")[4]
    if cfg_account != account:
        raise SystemExit(
            f"账号不匹配：当前凭证在 {account}，而 config.ini 的 edge_role_arn 属于 "
            f"{cfg_account}。闸门会对着另一个账号出结论——先切凭证或改 config。")
    edge_role_name = edge_role_arn.rsplit("/", 1)[-1]

    platform = platform_function_names()
    sites = site_function_names(lam, platform)

    def fn_arn(n: str) -> str:
        return f"arn:aws:lambda:{region}:{account}:function:{n}"

    # ---- 密钥的三处副本：**实测**它们现在是否还含活密钥 ----
    live_key = clients["ssm"].get_parameter(
        Name=JWT_PARAM_NAME, WithDecryption=True)["Parameter"]["Value"]
    facts: dict[str, object] = {}

    edge_code_arn = fn_arn(EDGE_ORIGIN_REQUEST_FN)
    import urllib.request
    code_url = lam.get_function(
        FunctionName=EDGE_ORIGIN_REQUEST_FN)["Code"]["Location"]
    with urllib.request.urlopen(code_url) as fh:      # noqa: S310 (AWS 预签名 URL)
        code_has_key = secret_in_zip_bytes(fh.read(), live_key)
    if not code_has_key:
        edge_code_arn = None  # type: ignore[assignment]
        facts["edge_code_carries_live_key"] = False

    asset_bucket, asset_key = edge_asset_location(clients, EDGE_ORIGIN_REQUEST_FN)
    asset_blob = clients["s3"].get_object(
        Bucket=asset_bucket, Key=asset_key)["Body"].read()
    asset_arn: str | None = f"arn:aws:s3:::{asset_bucket}/{asset_key}"
    if not secret_in_zip_bytes(asset_blob, live_key):
        asset_arn = None
        facts["edge_asset_carries_live_key"] = False
    facts["edge_assets_carrying_live_key"] = (
        count_assets_carrying_key(clients, asset_bucket, live_key)
        if scan_assets else "未扫描（--no-asset-scan）")

    aliases = function_aliases(lam, list(platform) + list(sites))
    targets = Targets(
        platform_functions=tuple(fn_arn(n) for n in platform),
        site_functions=tuple(fn_arn(n) for n in sites),
        edge_function=edge_code_arn,
        edge_asset=asset_arn,
        jwt_parameter=f"arn:aws:ssm:{region}:{account}:parameter{JWT_PARAM_NAME}",
        any_role=f"arn:aws:iam::{account}:role/*",
        alias_arns={fn_arn(n): tuple(f"{fn_arn(n)}:{a}" for a in al)
                    for n, al in aliases.items()},
    )

    # ---- resource policy 快照（SimulatePrincipalPolicy 不覆盖这条通道）----
    policies = {name: function_policy_statements(lam, name, aliases.get(name, ()))
                for name in list(platform) + list(sites)}
    rp = resource_policy_snapshot(policies, account=account,
                                 platform=platform, sites=sites)

    principals = list_principals(iam)
    print(f"账号 {account} / 区 {region}：平台函数 {len(platform)}、站点函数 "
          f"{len(sites)}（带 alias 的 {len(aliases)} 个）、"
          f"待模拟 principal {len(principals)}；"
          f"Edge 产物含活密钥={code_has_key}、asset 含活密钥={asset_arn is not None}",
          file=sys.stderr)

    observed: dict[str, dict] = {}
    failures: list[str] = []
    n_missing = 0

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(simulate, iam, p["arn"], targets): p for p in principals}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            p = futs[fut]
            try:
                decisions, missing = fut.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{p['name']}: {type(exc).__name__}: {exc}")
                continue
            n_missing += bool(missing)
            grants = grants_from_decisions(decisions, targets)
            if grants:
                observed[principal_fingerprint(p["arn"])] = {
                    "name": p["name"], "arn": p["arn"], "kind": p["kind"],
                    "grants": sorted(grants)}
            if i % 100 == 0:
                print(f"  已模拟 {i}/{len(principals)}", file=sys.stderr)

    if failures:
        # 静默丢一个 principal 就等于"没看见"，而没看见与"不具备权限"在输出上
        # 一模一样。这里必须硬失败。
        raise SystemExit(f"{len(failures)} 个 principal 模拟失败，结果不完整："
                         f"{failures[:3]}")

    facts["principals_with_missing_context"] = n_missing
    return {"principals": observed, "resource_policies": rp, "facts": facts,
            "required": {"edge": edge_role_name, "deployer": DEPLOYER_EXEC_ROLE}}


def write_baseline(bundle: dict, baseline: dict, path: Path) -> None:
    old = baseline.get("principals", {})
    principals = {}
    # **指纹从 ARN 重算，不沿用 bundle 的键**：`--from-dump` 读的快照可能是旧格式
    # 生成的（指纹编码改过一次），沿用键就会把整份基线写成旧形态而单测才发现。
    for p in sorted(bundle["principals"].values(), key=lambda x: x["arn"]):
        fp = principal_fingerprint(p["arn"])
        principals[fp] = {
            # `--classify` 传进来的标注优先；否则沿用基线里已有的；都没有才 unclassified。
            "category": p.get("category")
            or old.get(fp, {}).get("category", "unclassified"),
            "grants": p["grants"],
        }
    path.write_text(json.dumps(
        {"schema": BASELINE_SCHEMA,
         "note": ("account trust boundary baseline —— 只存 ARN 与策略语句的指纹"
                  "（仓库红线：真实账号值/角色名不进被跟踪文件）。见 "
                  "docs/security/account-trust-boundary.md 与 "
                  "scripts/verify_account_trust_boundary.py。"),
         # platform-overbroad：平台自己的角色，但这条授权它并不需要
         # （当前唯一一个：跑不可信站点依赖安装的 CodeBuild 角色，CDK 自动给了它
         #  整个 bootstrap 桶的读权限 ⇒ 它能读到 Edge asset 里的明文密钥）。
         "categories": ["platform", "platform-overbroad", "admin", "break-glass",
                        "cdk-admin", "cdk-readonly", "unrelated-workload",
                        "unclassified"],
         "facts": bundle["facts"],
         "principals": principals,
         # 站点函数只落**形态集合**，不落逐站点条目：逐站点会让每次建站/下线
         # 都改基线，而"新增即红"依赖基线是稳定的。
         "resource_policies": {
             "platform": bundle["resource_policies"]["platform"],
             "site_shapes": site_policy_shapes(
                 bundle["resource_policies"]["sites"]),
         }},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--update-baseline", action="store_true",
                    help="把当前实测写回基线（category 保留已有标注，新条目为 "
                         "unclassified，需人工标注）")
    ap.add_argument("--dump-observed", metavar="PATH",
                    help="把带**真实名字**的实测清单写到 PATH（分类基线时要看名字）。"
                         "产物含账号内标识，**不要提交进仓库**——写到 /tmp。")
    ap.add_argument("--from-dump", metavar="PATH",
                    help="不发 AWS 调用，直接读 --dump-observed 的产物。"
                         "用于分类/复核，省掉重跑模拟。"
                         "**注意它是快照**：拿旧快照当闸门结果会得出过期结论。")
    ap.add_argument("--classify", metavar="PATH",
                    help="从 PATH 读 {角色名: category} 映射，据此标注基线的 "
                         "category（配合 --update-baseline）。映射文件同样"
                         "含真实名字，**不要提交**。")
    ap.add_argument("--no-asset-scan", action="store_true",
                    help="跳过「bootstrap 桶里有多少 asset 带活密钥」那一遍扫描"
                         "（默认做；它要读几十个小对象）")
    args = ap.parse_args()

    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) \
        if BASELINE_PATH.exists() else {"schema": BASELINE_SCHEMA, "principals": {}}

    if args.from_dump:
        bundle = json.loads(Path(args.from_dump).read_text(encoding="utf-8"))
        print(f"（--from-dump：读的是快照 {args.from_dump}，未发 AWS 调用）",
              file=sys.stderr)
    else:
        bundle = measure(args.region, workers=args.workers,
                        scan_assets=not args.no_asset_scan)

    observed = bundle["principals"]
    print(f"\n具备至少一项敏感授权的 principal：{len(observed)}")
    for _fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        print(f"  [{p['kind'][0]}] {p['name']:62} {sorted(p['grants'])}")
    print(f"\n事实：{json.dumps(bundle['facts'], ensure_ascii=False)}")

    if args.dump_observed:
        Path(args.dump_observed).write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n实测清单（含真实名字，勿提交）已写入 {args.dump_observed}")

    if args.update_baseline:
        classify = json.loads(Path(args.classify).read_text(encoding="utf-8")) \
            if args.classify else {}
        if classify:
            for p in observed.values():
                if p["name"] in classify:
                    p["category"] = classify[p["name"]]
        write_baseline(bundle, baseline, BASELINE_PATH)
        print(f"\n已写入 {BASELINE_PATH}（新条目 category=unclassified，请人工标注）")
        return 0

    rep = compare_to_baseline(observed, baseline, required=bundle["required"],
                              resource_policies=bundle["resource_policies"])
    print("\n" + rep.render())
    if rep.new_principals or rep.new_grants or rep.new_statements \
            or rep.site_policy_outliers:
        print("\n闸门红：账号里能冒充任意用户的授权面**变大了**。这不是"
              "又出了一个新缺陷，而是既有暴露面扩张。"
              "处理方式见 docs/security/account-trust-boundary.md。")
    if rep.missing_required:
        print("\n闸门红：平台自己的必需 invoke 权限丢了。"
              "真机症状是全站 403（Edge）或每次部署在健康门失败（deployer）——"
              "**先确认是不是刚做过一次收窄**，别去查网络。")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
