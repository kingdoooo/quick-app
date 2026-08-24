#!/usr/bin/env python3
"""账号信任边界的漂移闸门（M09 第 2 步的可执行部分）。

**它不是 M09 的修复，也不假装是。** M09 那条缺陷——同账号持有
`lambda:InvokeFunction` 的 principal 可以直接 invoke panel 与站点 Lambda、
在合成 event 里伪造 `x-user-email`——在**本账号里关不掉**：

- SCP 对 Organizations 管理账号无效，而本部署就在管理账号（`policies/README.md` 边界①）；
- Lambda 的 resource policy 没有写 Deny 的 API（`AddPermission` 只能写 Allow）；
- 应用层给 Edge 加签名也不成立：2026-08-25 实测，能 direct invoke 的 principal
  里绝大多数**同时能读到那把 HS256 密钥**（Edge 代码里字符串替换过它，
  且 SSM 参数本身可读），于是签名与被签名的东西都在攻击者手里。

**只收窄 `lambda:InvokeFunction` 是假修复**：同一批 principal 还握着密钥读取、
`lambda:UpdateFunctionCode` 与 `iam:PutRolePolicy`，边界一寸也没有移动。
更要紧的是 2026-08-25 实测出的一件事——**冒充任意用户根本不需要 invoke**：
拿到那把 HS256 密钥就能签任意 email 的会话 cookie，以及 `scope=console` 的
`__Host-sb_console`（同一个 `/site-builder/jwt-secret`），于是 M09 里
「写面还被一道 HMAC 挡住」这句话对**能读到密钥的 principal** 不成立。
真正的修复只有一条：把平台迁到独立的 Organizations 成员账号。
完整风险模型与实测证据见 `docs/security/account-trust-boundary.md`。

在那之前，本脚本承担唯一还能自动化的职责：**这个集合别再长**。
它枚举账号内全部非 service-linked 角色与 IAM 用户，用只读的
`iam:SimulatePrincipalPolicy` 算出每个 principal 的敏感能力，与仓库里的
基线（`account_trust_baseline.json`，只存 ARN 指纹，不含任何账号值）比对：

- 新 principal，或已知 principal 长出新能力 → **红**；
- Edge 角色或部署器 exec 角色丢掉必需的 invoke → **红**
  （真机症状分别是「全站 403」与「每次部署在健康门失败」，两者都不会在单测里出现）；
- 集合缩小 → 绿，但打印出来，提示更新基线。

纯函数部分由 `deployer/tests/test_verify_account_trust_boundary.py` 覆盖，
其中第一条锁的是本脚本最容易写错的地方：多资源模拟必须读
`ResourceSpecificResults`，顶层 `EvalDecision` 是聚合项。

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
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SITE_BUILDER = _HERE.parent
BASELINE_PATH = _HERE / "account_trust_baseline.json"
CONFIG_PATH = _SITE_BUILDER / "config.ini"
APP_PY = _SITE_BUILDER / "deployer" / "infra" / "app.py"

JWT_PARAM_NAME = "/site-builder/jwt-secret"
DEPLOYER_EXEC_ROLE = "site-deployer-exec-role"

# Edge 函数名：router 栈的两个 Lambda@Edge 里，**origin-request 那个**才内联着
# 会话密钥（`stack.py` 把 `{{JWT_SECRET}}` 替换进它）。origin-response 不验签。
EDGE_ORIGIN_REQUEST_FN = "ApplicationWebRouterStack-application-web-router"

# 敏感能力。名字进基线文件，改名等于基线全量漂移——改的时候连基线一起改。
CAP_INVOKE_PLATFORM = "invoke-platform"
CAP_INVOKE_SITE = "invoke-site"
# 读密钥的两条路**必须分开记**：严重度与修法都不同。
#  · read-edge-code：`lambda:GetFunction` 下载 Edge 产物，密钥是**明文**在
#    `index.py` 里（Lambda@Edge 不支持环境变量，只能部署时字符串替换）。
#    不经 KMS、不需 invoke。AWS 托管的 `ReadOnlyAccess` 就带这个动作
#    （2026-08-25 实测：MatchedStatements 直接指向 ReadOnlyAccess）。
#  · read-jwt-param：`ssm:GetParameter` 读 SecureString。看起来还有 KMS 一道，
#    实际没有——参数用 `alias/aws/ssm`，该托管密钥的策略是
#    `Principal:{"AWS":"*"}` + `kms:CallerAccount` + `kms:ViaService=ssm`
#    的**直接授权**，所以 identity policy 里无需任何 kms 动作（已读该 key policy 核实）。
CAP_READ_EDGE_CODE = "read-edge-code"
CAP_READ_JWT_PARAM = "read-jwt-param"
CAP_REPLACE_CODE = "replace-platform-code"
CAP_SELF_ESCALATE = "self-escalate"
SECRET_CAPS = (CAP_READ_EDGE_CODE, CAP_READ_JWT_PARAM)

# 两条正向控制：这两个 principal **必须**保留下列能力。
REQUIRED_CAPABILITIES = {
    "edge": {CAP_INVOKE_PLATFORM, CAP_INVOKE_SITE},
    "deployer": {CAP_INVOKE_SITE},
}


# ---------------------------------------------------------------- 纯函数部分

def principal_fingerprint(arn: str) -> str:
    """ARN → 16 位指纹。

    基线文件里**只能**出现指纹：账号内 3 个 CDK cfn-exec 角色的名字内嵌账号 ID，
    照抄角色名就把账号值提交进了仓库（仓库红线）。指纹单向、稳定，
    足够回答"这个 principal 之前在不在基线里"。
    """
    return hashlib.sha256(arn.encode("utf-8")).hexdigest()[:16]


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


@dataclass(frozen=True)
class Targets:
    """模拟的目标资源集合（ARN 形态，由调用方按真实账号拼好）。"""
    platform_functions: tuple[str, ...]
    site_functions: tuple[str, ...]
    edge_function: str
    jwt_parameter: str
    any_role: str


def capabilities_from_decisions(decisions: dict[str, str], t: Targets) -> set[str]:
    """逐资源判定 → 四项敏感能力。"""
    def allowed(action: str, resources) -> bool:
        return any(decisions.get(f"{action}|{r}") == "allowed" for r in resources)

    caps = set()
    if allowed("lambda:InvokeFunction", t.platform_functions):
        caps.add(CAP_INVOKE_PLATFORM)
    if allowed("lambda:InvokeFunction", t.site_functions):
        caps.add(CAP_INVOKE_SITE)
    if allowed("lambda:GetFunction", [t.edge_function]):
        caps.add(CAP_READ_EDGE_CODE)
    if allowed("ssm:GetParameter", [t.jwt_parameter]):
        caps.add(CAP_READ_JWT_PARAM)
    if allowed("lambda:UpdateFunctionCode", t.platform_functions):
        caps.add(CAP_REPLACE_CODE)
    if allowed("iam:PutRolePolicy", [t.any_role]):
        caps.add(CAP_SELF_ESCALATE)
    return caps


@dataclass
class Report:
    new_principals: list[str] = field(default_factory=list)
    new_capabilities: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.new_principals or self.new_capabilities
                    or self.missing_required)

    def render(self) -> str:
        lines = []
        for label, rows in (("新增 principal（红）", self.new_principals),
                            ("已知 principal 长出新能力（红）", self.new_capabilities),
                            ("必需能力丢失（红）", self.missing_required),
                            ("基线里未分类（请标注 category）", self.unclassified),
                            ("集合缩小（绿；可更新基线）", self.improvements)):
            if rows:
                lines.append(f"{label}：")
                lines.extend(f"  - {r}" for r in rows)
        if not lines:
            lines.append("与基线一致：没有新增 principal、没有新增能力、"
                         "两条正向控制都在。")
        return "\n".join(lines)


def compare_to_baseline(observed: dict[str, dict], baseline: dict,
                        *, required: dict[str, str]) -> Report:
    """observed = {fingerprint: {"name", "arn", "capabilities"}}。

    `required` 把标签映射到**角色名**（Edge 的角色名来自 config.ini，
    所以不能写死在这里）；每个标签需要哪些能力由 `REQUIRED_CAPABILITIES` 定。
    """
    base = baseline.get("principals", {})
    rep = Report()

    for fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        caps = set(p["capabilities"])
        if fp not in base:
            rep.new_principals.append(f"{p['name']}  [{fp}]  {sorted(caps)}")
            continue
        gained = caps - set(base[fp].get("capabilities", []))
        if gained:
            rep.new_capabilities.append(f"{p['name']}  [{fp}]  +{sorted(gained)}")
        if base[fp].get("category") in (None, "", "unclassified"):
            rep.unclassified.append(f"{p['name']}  [{fp}]")

    for fp, b in sorted(base.items()):
        if fp not in observed:
            rep.improvements.append(
                f"[{fp}] 不再具备任何敏感能力（原 {b.get('category', '?')}："
                f"{sorted(b.get('capabilities', []))}）")

    by_name = {p["name"]: set(p["capabilities"]) for p in observed.values()}
    for label, role_name in required.items():
        need = REQUIRED_CAPABILITIES[label]
        have = by_name.get(role_name)
        if have is None:
            rep.missing_required.append(
                f"{role_name}（{label}）不在结果里——它必须保留 {sorted(need)}")
        elif not need <= have:
            rep.missing_required.append(
                f"{role_name}（{label}）缺 {sorted(need - have)}（现有 {sorted(have)}）")
    return rep


def platform_function_names(app_py: Path = APP_PY) -> tuple[str, ...]:
    """`infra/app.py` 的 `PLATFORM_FUNCTION_NAMES`（AST 取，不 import——
    app.py 顶层 import aws_cdk，普通解释器里没有）。

    手抄一份平台函数名清单就会与栈漂移：新加一个平台函数时，
    它会被当成"用户站点"，于是 `invoke-platform` 这项能力少算一个资源。
    """
    src = app_py.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == "PLATFORM_FUNCTION_NAMES"):
            return tuple(e.value for e in node.value.elts)
    raise SystemExit(f"{app_py} 里找不到 PLATFORM_FUNCTION_NAMES——闸门会空转")


def read_config(path: Path = CONFIG_PATH) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(path, encoding="utf-8")
    if not cfg.sections():
        raise SystemExit(
            f"{path} 读不到任何段——configparser 对缺失文件是静默的，"
            f"再往下跑会拿空值拼出假结论。先确认路径与 cwd。")
    return cfg


# ---------------------------------------------------------------- 真机部分

def _aws_clients(region: str):
    import boto3
    from botocore.config import Config
    cfg = Config(retries={"max_attempts": 12, "mode": "adaptive"})
    return (boto3.client("iam", region_name=region, config=cfg),
            boto3.client("lambda", region_name=region, config=cfg),
            boto3.client("sts", region_name=region, config=cfg))


def list_principals(iam) -> list[dict]:
    """非 service-linked 角色 + 全部 IAM 用户。

    **用户不能漏**：账号 owner 的 IAM 用户同样是一个能 direct invoke 的
    principal，只数角色会漏掉它。
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


ACTIONS = ("lambda:InvokeFunction", "lambda:UpdateFunctionCode",
           "lambda:GetFunction", "ssm:GetParameter", "iam:PutRolePolicy")


def simulate(iam, principal_arn: str, t: Targets) -> dict[str, str]:
    resources = list(t.platform_functions) + list(t.site_functions) + \
        [t.edge_function, t.jwt_parameter, t.any_role]
    out: dict[str, str] = {}
    for page in iam.get_paginator("simulate_principal_policy").paginate(
            PolicySourceArn=principal_arn, ActionNames=list(ACTIONS),
            ResourceArns=resources):
        out.update(decisions_from_simulation(page["EvaluationResults"]))
    return out


def measure(region: str, *, workers: int = 4) -> tuple[dict[str, dict], Targets, dict[str, str]]:
    iam, lam, sts = _aws_clients(region)
    cfg = read_config()
    account = sts.get_caller_identity()["Account"]

    edge_role_arn = cfg.get("Deployer", "edge_role_arn").split("#")[0].strip()
    cfg_account = edge_role_arn.split(":")[4]
    if cfg_account != account:
        raise SystemExit(
            f"账号不匹配：当前凭证在 {account}，而 config.ini 的 edge_role_arn 属于 "
            f"{cfg_account}。闸门会对着另一个账号出结论——先切凭证或改 config。")
    edge_role_name = edge_role_arn.rsplit("/", 1)[-1]

    platform = platform_function_names()
    sites = site_function_names(lam, platform)

    def fn(n: str) -> str:
        return f"arn:aws:lambda:{region}:{account}:function:{n}"

    targets = Targets(
        platform_functions=tuple(fn(n) for n in platform),
        site_functions=tuple(fn(n) for n in sites),
        edge_function=fn(EDGE_ORIGIN_REQUEST_FN),
        jwt_parameter=f"arn:aws:ssm:{region}:{account}:parameter{JWT_PARAM_NAME}",
        any_role=f"arn:aws:iam::{account}:role/*",
    )

    principals = list_principals(iam)
    print(f"账号 {account} / 区 {region}：平台函数 {len(platform)}、站点函数 "
          f"{len(sites)}、待模拟 principal {len(principals)}", file=sys.stderr)

    observed: dict[str, dict] = {}
    failures: list[str] = []

    def one(p):
        return p, simulate(iam, p["arn"], targets)

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, p) for p in principals]
        for i, fut in enumerate(cf.as_completed(futs), 1):
            try:
                p, decisions = fut.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            caps = capabilities_from_decisions(decisions, targets)
            if caps:
                observed[principal_fingerprint(p["arn"])] = {
                    "name": p["name"], "arn": p["arn"], "kind": p["kind"],
                    "capabilities": sorted(caps)}
            if i % 100 == 0:
                print(f"  已模拟 {i}/{len(principals)}", file=sys.stderr)

    if failures:
        # 静默丢一个 principal 就等于"没看见"，而没看见与"不具备能力"在输出上
        # 一模一样。这里必须硬失败。
        raise SystemExit(f"{len(failures)} 个 principal 模拟失败，结果不完整："
                         f"{failures[:3]}")

    return observed, targets, {"edge": edge_role_name, "deployer": DEPLOYER_EXEC_ROLE}


def write_baseline(observed: dict[str, dict], baseline: dict, path: Path) -> None:
    old = baseline.get("principals", {})
    principals = {}
    for fp, p in sorted(observed.items(), key=lambda kv: kv[0]):
        principals[fp] = {
            # `--classify` 传进来的标注优先；否则沿用基线里已有的；都没有才 unclassified。
            "category": p.get("category")
            or old.get(fp, {}).get("category", "unclassified"),
            "capabilities": p["capabilities"],
        }
    path.write_text(json.dumps(
        {"schema": 1,
         "note": ("account trust boundary baseline — 只存 ARN 指纹（仓库红线："
                  "真实账号值/角色名不进被跟踪文件）。见 "
                  "docs/security/account-trust-boundary.md 与 "
                  "scripts/verify_account_trust_boundary.py。"),
         "categories": ["platform", "admin", "break-glass", "cdk-admin",
                        "cdk-readonly", "unrelated-workload", "unclassified"],
         "principals": principals}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")


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
                         "用于分类/复核，省掉重跑 400 次模拟。"
                         "**注意它是快照**：拿旧快照当闸门结果会得出过期结论。")
    ap.add_argument("--classify", metavar="PATH",
                    help="从 PATH 读 {角色名: category} 映射，据此标注基线的 "
                         "category（配合 --update-baseline）。映射文件同样"
                         "含真实名字，**不要提交**。")
    args = ap.parse_args()

    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")) \
        if BASELINE_PATH.exists() else {"schema": 1, "principals": {}}

    if args.from_dump:
        observed = json.loads(Path(args.from_dump).read_text(encoding="utf-8"))
        cfg = read_config()
        edge_role_name = cfg.get("Deployer", "edge_role_arn").split("#")[0] \
            .strip().rsplit("/", 1)[-1]
        required = {"edge": edge_role_name, "deployer": DEPLOYER_EXEC_ROLE}
        print(f"（--from-dump：读的是快照 {args.from_dump}，未发 AWS 调用）",
              file=sys.stderr)
    else:
        observed, _targets, required = measure(args.region, workers=args.workers)

    print(f"\n具备至少一项敏感能力的 principal：{len(observed)}")
    for _fp, p in sorted(observed.items(), key=lambda kv: kv[1]["name"]):
        print(f"  [{p['kind'][0]}] {p['name']:62} {sorted(p['capabilities'])}")

    if args.dump_observed:
        Path(args.dump_observed).write_text(
            json.dumps(observed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n实测清单（含真实名字，勿提交）已写入 {args.dump_observed}")

    if args.update_baseline:
        classify = json.loads(Path(args.classify).read_text(encoding="utf-8")) \
            if args.classify else {}
        if classify:
            for p in observed.values():
                if p["name"] in classify:
                    p["category"] = classify[p["name"]]
        write_baseline(observed, baseline, BASELINE_PATH)
        print(f"\n已写入 {BASELINE_PATH}（新条目 category=unclassified，请人工标注）")
        return 0

    rep = compare_to_baseline(observed, baseline, required=required)
    print("\n" + rep.render())
    if rep.new_principals or rep.new_capabilities:
        print("\n闸门红：账号里能冒充任意用户的身份集合**变大了**。这不是"
              "又出了一个新缺陷，而是既有暴露面扩张。"
              "处理方式见 docs/security/account-trust-boundary.md。")
    if rep.missing_required:
        print("\n闸门红：平台自己的必需 invoke 权限丢了。"
              "真机症状是全站 403（Edge）或每次部署在健康门失败（deployer）——"
              "**先确认是不是刚做过一次收窄**，别去查网络。")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
