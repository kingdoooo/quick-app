#!/usr/bin/env python3
"""3c 的冒充面探针：**迁到非对称签名之后**，账号内谁还能冒充任意用户。

**这不是闸门。** 闸门是 `verify_*`（漂移检测、有基线、会红）。本脚本是 3c 的
**量测工具**：它回答"3c 的收益边界在哪"，产出进
`docs/security/3c-impersonation-surface.json`（tracked，只有计数与指纹）与一份
可选的原始名字 dump（**gitignored**）。`docs/superpowers/specs/2026-08-28-
asymmetric-session-signing-spec.md` §1 的数字由本脚本产生。

## 为什么要单独有它（而不是直接读闸门基线）

闸门是**漂移**闸门（有基线、会红、覆盖 IAM 写与 resource policy 等层）；本脚本回答
一个不同的问题："今天到底有多少 principal 能冒充任意用户，关掉某一组路径能少几个"。
它没有基线、不会红，产出的是聚合计数。

**判定本身两边共用同一份**（3g，2026-09-21）：`_impersonation_model.py`。此前闸门与
本脚本各有一套，两套都失真——闸门把"能替换平台代码"压成 `lambda:UpdateFunctionCode`
一个动作（对 Edge 过度声称、对 CFN 少算），本脚本把代码更新与配置更新合成一类
（`UpdateFunctionConfiguration` 没有 `Publish`，而 Lambda@Edge **不支持 Layer**）、
CFN 前提停在 ADR 0007 之前（router 栈**现在有** stack policy，门槛是
`cloudformation:SetStackPolicy`）、还把 `PublishVersion` 当成"新建函数再关联"的必需
前提（`CreateFunction` 自带 `Publish`）。共享模型的反例集在
`deployer/tests/test_impersonation_model.py`，形状与前提三值见那个模块的 docstring。

## 只读

只发 `sts:GetCallerIdentity`、`iam:ListRoles`/`ListUsers`、
`iam:SimulatePrincipalPolicy`、`lambda:GetFunction`、`cloudfront:ListDistributions`
/`GetDistributionConfig`。**不发任何写调用。**

## 三条实测坑（都花过时间）

1. **产物不要只放 `/tmp`。** 第一版的探针输出、人工核对过的 dump、RS256 原型全放
   `/tmp`，隔天被系统清理，spec 引的数字一度失去可复跑依据。**但"搬到 gitignored
   目录"只解决了 /tmp 清理，没解决可复现**——新 clone / 别的机器 / 外部复审都拿不到。
   所以本脚本自己是 tracked 的，脱敏聚合结果也是 tracked 的，只有名字留在 gitignored。
2. **别用闸门的 `list_principals` 做轻量枚举。** 它走
   `GetAccountAuthorizationDetails`，要把账号里 ~300 份托管策略的**完整文档**拉回来
   （B 层需要，本脚本不需要）：实测单页最慢 94 秒。只要 principal ARN 就用
   `ListRoles`+`ListUsers`（秒级）。
3. **`read_timeout` 不能取小值。** 30 秒会把 GAAD 变成超时→重试的死循环，
   表现与挂死一模一样（0% CPU、输出 0 字节）。"加超时防挂死"与"超时取太小造成假
   挂死"是同一枚硬币的两面。这里取 120 秒，并且 `python3 -u` + 逐步打点。

## 用法

**系统 `python3`**（`deployer/.venv` 的 CA 信任库是空的，每次 HTTPS 都会
`CERTIFICATE_VERIFY_FAILED`，症状读起来像网络故障）：

    # 反例自检，不碰 AWS、秒级——改过 classify() 必须先跑这个
    python3 site-builder/scripts/probe_impersonation_surface.py --self-test

    # 真机量测（只读，实测约 4-6 分钟），写 tracked 聚合 + gitignored 名字 dump
    python3 -u site-builder/scripts/probe_impersonation_surface.py \
        --write-evidence \
        --dump-observed docs/design/3c-spike/observed-impersonation-surface.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import configparser
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent                      # 仓库根（**不写绝对路径**）
GATE = _HERE / "verify_account_trust_boundary.py"
ROUTER_CONFIG = _ROOT / "router" / "config.ini"
SITE_CONFIG = _ROOT / "site-builder" / "config.ini"      # [SessionKeys]：两把 CMK 的 key ARN
EVIDENCE = _ROOT / "docs" / "security" / "3c-impersonation-surface.json"


# ---------------------------------------------------------------- 判定不在本文件
#
# `classify()`、能力标签与聚合口径住在 `_impersonation_model.py`（**闸门 import 同一份**），
# 反例集在 `deployer/tests/test_impersonation_model.py`。本文件只做两件事：
# **观测**（真机拼出 `Surface`）与**报告**（聚合计数落 tracked 证据）。
#
# 两边各抄一份判定正是 3g 的成因：闸门那份对 Edge 过度声称、对 CFN 少算，本文件那份
# 把代码更新与配置更新合成一类、CFN 前提停在 ADR 0007 之前、还多要了一个 PublishVersion。
if str(_HERE) not in sys.path:      # 测试用 spec_from_file_location 加载本文件时本目录不在 sys.path
    sys.path.insert(0, str(_HERE))
import _impersonation_model as model              # noqa: E402

classify = model.classify
summarize = model.summarize
MITIGATIONS = model.MITIGATIONS
ALL_LABELS = model.ALL_LABELS


def print_marginal_report(agg: dict, out=None) -> None:
    """边际收益那一段的**终端报告**。独立成函数是为了让守卫断言**真实 stdout**。

    **三个数都要打印**（R2-L5）：只打 surface_after / principals_removed 时，
    "还剩未分析路径所以不定论"这第三种结论在默认报告里完全消失——JSON 里有
    `principals_uncertain`，看终端的人却分不清"已知残留"与"待核实"。

    **范围声明必须说到"初始已建模并集"为止**（R3-b）：`summarize` 的反事实只遍历
    `surface`（= 初始并集），所以只持未分析路径的人根本不进 `remaining`/`uncertain`。
    上一版把范围写成"本轮观测到的群体"，于是出现过这种读数：两个 principal、其中一个
    只持 `edge:cfn-template-unanalyzed`，报告却是「面 1 → ≤0（确定离场 ≥1，待核实 0）」
    ——看起来像"关掉 KMS 那组就没人了"，而账号里明明还有一个没定论的人。差额就是
    `unanalyzed_outside_union`，所以这里把它**连数字一起**打出来。

    上一版的守卫是 grep 源码关键词（CLAUDE.md 明确点过这个病），因此看不见这个问题。
    """
    def p(line: str) -> None:
        print(line, file=out or sys.stdout)

    p("\n===== 关掉某一组路径的边际收益 =====")
    p("  收益（removed）是**下界**、剩余（after）是**上界**；uncertain = 已建模路径都关了"
      "但仍持未分析路径、因而不定论的人数。")
    p(f"  上界的范围**仅限初始已建模并集内的成员**"
      f"（本轮 {agg['impersonation_surface_union']} 人）："
      f"并集外只持未分析路径的 {agg.get('unanalyzed_outside_union', 0)} 人"
      f"**未计入任何一行的 after**——措施关不掉他们，他们也从没被算进去。")
    for name, m in agg["marginal_value_if_closed"].items():
        p(f"  {name:32} 面 {agg['impersonation_surface_union']:>3}"
          f" → ≤{m['surface_after']:<3}（确定离场 ≥{m['principals_removed']}，"
          f"待核实 {m.get('principals_uncertain', 0)}）")


def self_test() -> int:
    """跑**判定层**共享反例 + 聚合口径断言，都不碰 AWS。

    **判定层那一半必须真的调用 `classify`**（R1-L5）：上一版只把手写标签喂 `summarize`，
    于是把 `classify` 换成"必抛异常"也照样退出 0——CLI 帮助宣称的"classify 反例自检"
    是空的。现在用共享模型的 `run_cases()`，与 pytest 共用同一份数据；完整反例集
    （44 条，含 6 条变形）仍在 `deployer/tests/test_impersonation_model.py`。
    """
    print("判定与聚合来自共享模型 _impersonation_model.py"
          "（完整反例集：deployer/tests/test_impersonation_model.py）")
    failures = model.run_cases()
    print(f"  {'ok  ' if not failures else 'FAIL'} 判定层共享反例"
          f"（{len(model._case_rows(model.fake_surface()))} 条）")
    for f in failures:
        print(f"       {f}", file=sys.stderr)
    agg = summarize({
        "p-sign": {model.S_HIJACK_AUTH},
        "p-edge": {model.E_CFN_UPDATE_STACK},
        "p-both": {model.S_KMS_DIRECT, model.E_CFN_CHANGE_SET},
        "p-fixture": {model.S_FIXTURE_ISSUER},
        "p-unanalyzed": {model.E_CFN_TEMPLATE_UNANALYZED},
    })
    want = {"can_sign": 2, "can_replace_edge_verifier": 2,
            "impersonation_surface_union": 3, "both": 1,
            "fixture_issuer_holders": 1, "non_surface_only_holders": 2,
            # R3-b：边际收益那层上界的**差额**（并集外还持未分析路径的人）。
            # 这里就是 `p-unanalyzed` 那一个。
            "unanalyzed_outside_union": 1}
    bad = {k: (agg[k], v) for k, v in want.items() if agg[k] != v}
    print(f"  {'ok  ' if not bad else 'FAIL'} 聚合：两类进并集，受限/未分析单列不进")
    if bad:
        print(f"       {bad}", file=sys.stderr)
    return 1 if (failures or bad) else 0


# ---------------------------------------------------------------- 真机部分

def load_gate():
    """复用闸门的真源助手（平台函数名 AST 解析、TLS 加固、每线程 client、指纹），
    不维护第二份副本——CLAUDE.md「优先用生产 helper，不留简化副本」。"""
    spec = importlib.util.spec_from_file_location("_gate", GATE)
    assert spec is not None and spec.loader is not None, GATE
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


def session_key_arns() -> tuple[str, ...]:
    """`[SessionKeys]` 声明的全部会话签名 key ARN（两个 family 的 current + previous）。

    经 `session_keys.load_session_keys` 读，**不自己解析 config**：kid → 小节 → key_arn 的
    形态校验只有一份实现（auth 拥有它）。轮转中途 previous 有值时是 3–4 把，全部计入——
    "任一把能签"就是完整冒充，少算一把就少报一条路。

    读不到就 SystemExit：**不再回落占位 ARN**。占位 ARN 下 `kms:Sign|<占位>` 谁都不会有，
    于是整条 KMS 路径静默变成 0，而报告长得和"这条路已经关掉了"一模一样。
    """
    sys.path.insert(0, str(_ROOT / "site-builder" / "auth"))
    from session_keys import SessionKeysError, key_refs, load_session_keys
    try:
        keys = load_session_keys(SITE_CONFIG)
    except SessionKeysError as exc:
        raise SystemExit(
            f"{SITE_CONFIG} 的 [SessionKeys] 读不出两把 CMK：{exc}\n"
            "本探针量的就是「谁能用那两把 key 签名」——拿不到真 ARN 时不出结论。") from None
    return tuple(dict.fromkeys(r.key_arn for r in key_refs(keys, ("site", "console"))))


# 栈发现**直接用闸门那一份**（`gate.router_and_deployer_stacks`）：两个采集方各写一份的
# 后果不是"实现重复"，而是同一个账号事实在两个入口得出不同结论（R1-L3 实测过候选函数名
# 那一处）。闸门那份按物理资源反查归属，不依赖任何函数的 CloudFormation tag
# （auth 是裸 create_function 建的，根本没有那个 tag）。

def sim_groups(s, gate) -> tuple:
    """按服务分组批量模拟 → `(actions, resources, contexts)` 三元组。跨服务混在一条调用里
    会产生大量无意义的 action×resource 组合（都是 implicitDeny），既慢又难读。

    第三项是要**轮换**的 `ContextEntries` 列表（`None` = 这一组不喂上下文）。

    **KMS 那组必须喂上下文**：`deploy_auth` / `deploy_panel` 把 spec §11.5 的签名合同
    钉进了 IAM，signer 角色的 `kms:Sign` 语句带
    `StringEquals {kms:SigningAlgorithm, kms:MessageType}`。不喂上下文时模拟器把这两条
    评估成 **implicitDeny**——不是"缺上下文"，所以连 `missing_context_in` 都看不见，
    持有者被干干净净地报成"不能签"。
    **实测（2026-09-23，真机复盘）**：因为少了这一步，本探针的 `can_sign` 比闸门少 2 个
    （`site-auth-service-role` / `site-panel-role`），headline 报 17 而闸门报 19；
    逐条核对确认 `kms:MessageType=RAW` 那一腿才是 `allowed`。探针的数字进 spec §1 与
    ADR 0001，所以这是**低报冒充面**。

    取值与上下文构造一律用**闸门那一份**（`gate.KMS_MESSAGE_TYPES` / `gate.kms_context`），
    判定取并集——「任一取值下能签」就是能签。两边各抄一份判定正是 3g 的成因。
    """
    fns = [s.edge.arn, s.auth.arn, s.panel.arn, *s.new_candidates]
    stacks = [st.resource for st in s.stacks]
    # **两个来源都要取**：`Surface.service_roles`（闸门填的那份）与各栈自己观测到的
    # `RoleARN`。只取其中一个的症状是 `pass-role:cfn-service` 恒为"没有"——而"没问"
    # 与"不允许"在报告上一模一样。
    roles = list(dict.fromkeys(
        [s.edge_role, *s.service_roles,
         *(st.service_role for st in s.stacks if st.service_role)]))
    kms_contexts = [gate.kms_context(mt) for mt in gate.KMS_MESSAGE_TYPES]
    groups = [
        (list(model.A_KMS_SIGN + model.A_KMS_SELF_AUTHORIZE), list(s.kms_keys), kms_contexts),
        (list(model.A_UPDATE_CODE + model.A_UPDATE_CONFIG + model.A_PUBLISH_VERSION
              + model.A_CREATE_FUNCTION + model.A_INVOKE), fns, [None]),
        (list(model.A_CF_WRITE), [s.distribution], [None]),
        (list(model.A_CFN_UPDATE + model.A_CFN_CREATE_CHANGESET
              + model.A_CFN_EXECUTE_CHANGESET + model.A_CFN_SET_POLICY), stacks, [None]),
        (list(model.A_PASSROLE), roles, [None]),
    ]
    return tuple((a, r, c) for a, r, c in groups if r)


def sim_legs(groups) -> int:
    """真正会发出的模拟调用数（KMS 那组每个 MessageType 一腿）。
    **不写死字面量**：加/减一个 MessageType 时写死的数字会静静地说谎。"""
    return sum(len(contexts) for _, _, contexts in groups)


def discover(gate, clients, region: str, account: str):
    """从 config + 真机状态推出资源集合。**不接受硬编码的 distribution ID。**"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(ROUTER_CONFIG, encoding="utf-8")
    if not cfg.sections():
        raise SystemExit(
            f"{ROUTER_CONFIG} 读不到任何段——configparser 对缺失文件是静默的，"
            f"再往下会拿空值拼出假结论。")
    wildcard = cfg["CloudFront"]["domain_name"].strip()
    stack_name = cfg["CDK"]["stack_name"].strip()

    platform = set(gate.platform_function_names())
    for want in ("site-auth-service", "site-panel"):
        if want not in platform:
            raise SystemExit(f"平台函数清单里没有 {want}——探针会漏掉一条 signer 路径")
    edge_fn = gate.EDGE_ORIGIN_REQUEST_FN

    def fn(n: str) -> str:
        return f"arn:aws:lambda:{region}:{account}:function:{n}"

    # distribution：按 router/config.ini 的通配域名找，**ID 不进源码**。
    cfn = clients["cloudfront"]
    dist_id = ""
    for page in cfn.get_paginator("list_distributions").paginate():
        for d in (page["DistributionList"].get("Items") or ()):
            if wildcard in (d.get("Aliases", {}).get("Items") or ()):
                dist_id = d["Id"]
                break
        if dist_id:
            break
    if not dist_id:
        raise SystemExit(f"找不到别名含 {wildcard} 的 distribution")

    # **载荷性前提**：association 真的挂在编号版本上。若哪天变成 alias/$LATEST，
    # 「单动作证明不了能替换正在运行的代码」这条推理就不成立 ⇒ 响亮失败。
    dcfg = cfn.get_distribution_config(Id=dist_id)["DistributionConfig"]
    quals = {a["LambdaFunctionARN"].rsplit(":", 1)[-1]
             for a in (dcfg["DefaultCacheBehavior"]
                       .get("LambdaFunctionAssociations", {}).get("Items") or ())
             if f":function:{edge_fn}:" in a["LambdaFunctionARN"]}
    numbered = sorted(q for q in quals if q.isdigit())
    if not numbered:
        raise SystemExit(
            f"{edge_fn} 的 association 限定符不是编号版本（实得 {sorted(quals)}）"
            f"——本探针的 Edge 路径建模前提不成立，先核对再改模型")

    # Edge 函数的执行角色：给"新建函数再关联"那条路做 PassRole 的资源。
    edge_role = clients["lambda"].get_function(
        FunctionName=edge_fn)["Configuration"]["Role"]

    keys = session_key_arns()
    stacks = gate.router_and_deployer_stacks(
        clients, edge_fn_arn=fn(edge_fn), cmk_arns=keys)
    print(f"Edge association 限定符 = 编号版本 {','.join(numbered)}"
          f"（单动作模型不成立的前提，已实测）；"
          f"栈 guard：{', '.join(f'{st.label}={st.guard}' for st in stacks)}",
          flush=True)

    return model.Surface(
        kms_keys=keys,
        # 入口类型**观测**，且用闸门那一份自包含的观测（R2-L3 ③：它自己枚举 alias 并验
        # URL，两个调用方只传 (lam, name) ⇒ 构造上不可能给出不同答案）。
        auth=model.FnFact(fn("site-auth-service"),
                          entry=gate.observed_entry(clients["lambda"], "site-auth-service"),
                          layers_supported=True),
        panel=model.FnFact(fn("site-panel"),
                           entry=gate.observed_entry(clients["lambda"], "site-panel"),
                           layers_supported=True),
        # `entry` 由上面那段 association 观测**硬保证**是编号版本。
        # Lambda@Edge **不支持 Layer**（AWS 文档）⇒ 改配置不等于任意代码执行。
        edge=model.FnFact(fn(edge_fn), entry=model.ENTRY_VERSION,
                          layers_supported=False),
        # 候选名字规则**住在共享模型里**，闸门调的是同一份（R1-L3）。
        new_candidates=model.new_function_candidates(fn, stack_name),
        distribution=f"arn:aws:cloudfront::{account}:distribution/{dist_id}",
        edge_role=edge_role,
        stacks=stacks,
        service_roles=tuple(st.service_role for st in stacks if st.service_role))


def list_principals(iam) -> list[dict[str, str]]:
    """`ListRoles`+`ListUsers`（**不是** GAAD——见模块 docstring 的坑 2）。
    service-linked 角色按 path 排除，与闸门同一条判据。"""
    out: list[dict[str, str]] = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if not r["Path"].startswith("/aws-service-role/"):
                out.append({"arn": r["Arn"], "name": r["RoleName"]})
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            out.append({"arn": u["Arn"], "name": u["UserName"]})
    return out


def simulate_all(gate, s, principals: list[dict[str, str]],
                 workers: int, region: str) -> dict[str, frozenset[str]]:
    """每个 principal → 允许的 `"action|resource"` 集合。

    **必须保留资源维度。** 折叠成"动作集合"会让"能换 auth 的码"与"能换 Edge 的码"
    变成同一件事——那正是闸门里犯过的那一类建模错。
    """
    got: dict[str, frozenset[str]] = {}
    failures: list[str] = []
    groups = sim_groups(s, gate)

    def probe(arn: str) -> frozenset[str]:
        cl = gate.thread_iam_client(region)
        allowed: set[str] = set()
        for actions, resources, contexts in groups:
            # 同一组按 contexts **逐腿**模拟，判定取并集（见 `sim_groups` 的文档：
            # 「任一取值下能签」就是能签）。`None` = 这一组不喂上下文。
            for ctx in contexts:
                kw = {"PolicySourceArn": arn, "ActionNames": actions,
                      "ResourceArns": resources}
                if ctx:
                    kw["ContextEntries"] = ctx
                r = cl.simulate_principal_policy(**kw)
                for res in r["EvaluationResults"]:
                    act = res["EvalActionName"]
                    rsr = res.get("ResourceSpecificResults") or ()
                    if rsr:
                        for rr in rsr:
                            if rr.get("EvalResourceDecision") == "allowed":
                                allowed.add(f"{act}|{rr['EvalResourceName']}")
                    elif res.get("EvalDecision") == "allowed":
                        # 单资源组时 IAM 可能不返回 ResourceSpecificResults。
                        for one in resources:
                            allowed.add(f"{act}|{one}")
        return frozenset(allowed)

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, p["arn"]): p for p in principals}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            p = futs[fut]
            try:
                got[p["arn"]] = fut.result()
            except Exception as exc:                       # noqa: BLE001
                failures.append(f"{p['name']}: {type(exc)}: {exc}")
            if i % 50 == 0:
                print(f"  {i}/{len(principals)}", flush=True)
    if failures:
        # 部分失败 ⇒ 集合不完整 ⇒ **交集/并集全部作废**，不出结论。
        raise SystemExit(f"{len(failures)} 个 principal 模拟失败，结果不完整，"
                         f"不出结论：{failures[:3]}")
    return got


def head_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                             capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=_ROOT,
                               capture_output=True, text=True, check=True)
        return out.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true",
                    help="只跑 classify() 的反例，不碰 AWS")
    ap.add_argument("--write-evidence", action="store_true",
                    help=f"写 tracked 聚合证据到 {EVIDENCE.relative_to(_ROOT)}")
    ap.add_argument("--dump-observed", metavar="PATH",
                    help="把**名字**写到这里（必须是 gitignored 路径）")
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    # 名字不许进被跟踪的文件（仓库红线）。**在发第一个请求之前就检查**——
    # 跑 5 分钟再拒绝写等于白跑一趟。
    dump = Path(args.dump_observed).resolve() if args.dump_observed else None
    if dump is not None:
        r = subprocess.run(["git", "check-ignore", "-q", str(dump)], cwd=_ROOT)
        if r.returncode != 0:
            raise SystemExit(
                f"--dump-observed 指向的 {dump} 不是 gitignored 路径。"
                f"内部角色名不进被跟踪的文件——换到 docs/design/ 下。")

    gate = load_gate()
    gate.harden_tls_warnings()
    import boto3
    from botocore.config import Config

    # `read_timeout` 取 120 秒：见模块 docstring 的坑 3。
    cfg = Config(retries={"max_attempts": 6, "mode": "standard"},
                 connect_timeout=10, read_timeout=120)
    region = "us-east-1"           # Lambda@Edge + CloudFront 证书的硬约束
    account = boto3.client("sts", region_name=region,
                           config=cfg).get_caller_identity()["Account"]
    clients = {n: boto3.client(n, region_name=region, config=cfg)
               for n in ("iam", "lambda", "cloudfront", "cloudformation")}
    print(f"区 {region}（账号值不打印）", flush=True)

    s = discover(gate, clients, region, account)

    print("枚举 principal（ListRoles+ListUsers，不拉策略文档）…", flush=True)
    principals = list_principals(clients["iam"])
    _groups = sim_groups(s, gate)
    print(f"待模拟 {len(principals)} 个 × {len(_groups)} 组 / {sim_legs(_groups)} 腿"
          f"（KMS 那组每个 kms:MessageType 各一腿，见 sim_groups）", flush=True)

    names = {p["arn"]: p["name"] for p in principals}
    decisions = simulate_all(gate, s, principals, args.workers, region)
    # 名字也进判定：`site-builder-verifier` 角色本身即持有夹具签发器那条 URL 入口。
    by_principal = {arn: classify(a, s, names.get(arn, ""))
                    for arn, a in decisions.items()}
    agg = summarize(by_principal)
    sets = agg.pop("_sets")
    raw = {
        "can_sign": sorted(names[a] for a in sets["can_sign"]),
        "can_replace_edge_verifier": sorted(names[a] for a in sets["can_edge"]),
        "sign_only": sorted(names[a] for a in sets["can_sign"] - sets["can_edge"]),
        "edge_only": sorted(names[a] for a in sets["can_edge"] - sets["can_sign"]),
        "per_label": {lb: sorted(names[a] for a, ls in by_principal.items()
                                 if lb in ls) for lb in ALL_LABELS},
    }
    raw_blob = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    raw_hash = hashlib.sha256(raw_blob.encode("utf-8")).hexdigest()

    print("\n===== 每条能力路径的持有者数 =====")
    for lb in ALL_LABELS:
        print(f"  {lb:38} {agg['per_label'][lb]:>4}")
    print("\n===== 冒充面 =====")
    for k in ("can_sign", "can_replace_edge_verifier",
              "impersonation_surface_union", "both", "sign_only", "edge_only"):
        print(f"  {k:32} {agg[k]:>4}")
    print_marginal_report(agg)
    print("\n提醒：`sign:kms-*` 是 identity policy 的**上界**；KMS 的 key policy 是"
          "权威的，\n真实可签名集合 = 该上界 ∩ key policy 放行的集合。"
          "\n`sign:hijack-*` 与 key policy 无关——恶意代码是**以 signer 角色身份**调用的。")

    evidence = {
        "_what": "3c（会话签名迁非对称）之后的冒充面量测。**不是闸门**，没有基线，"
                 "不会红。产生者：site-builder/scripts/probe_impersonation_surface.py",
        "_privacy": "只存计数与指纹；principal 名字在 --dump-observed 的 "
                    "gitignored 产物里，其 sha256 记在 raw_observed_sha256。",
        "commit": head_sha(),
        "probed_at_utc": dt.datetime.now(dt.timezone.utc)
                           .replace(microsecond=0).isoformat(),
        "region": region,
        # 等价类来自共享模型（3g）。**代码更新与配置更新是两类**：后者的任意代码执行
        # 靠挂 Layer，而 Lambda@Edge 不支持 Layer ⇒ 在 Edge 上它什么都不构成。
        "action_equivalence_classes": {
            "kms_sign": list(model.A_KMS_SIGN),
            "kms_self_authorize": list(model.A_KMS_SELF_AUTHORIZE),
            "lambda_update_code": list(model.A_UPDATE_CODE),
            "lambda_update_config": list(model.A_UPDATE_CONFIG),
            "lambda_publish": list(model.A_PUBLISH_VERSION),
            "lambda_create": list(model.A_CREATE_FUNCTION),
            "lambda_invoke": list(model.A_INVOKE),
            "cloudfront_write": list(model.A_CF_WRITE),
            "cfn_update": list(model.A_CFN_UPDATE),
            "cfn_change_set": list(model.A_CFN_CREATE_CHANGESET
                                   + model.A_CFN_EXECUTE_CHANGESET),
            "cfn_set_stack_policy": list(model.A_CFN_SET_POLICY),
            "iam_passrole": list(model.A_PASSROLE),
        },
        # 每个栈的 guard（观测值，三值）。逻辑标签不含账号值，可以进 tracked 证据。
        "stack_guards": {st.label: st.guard for st in s.stacks},
        "stack_premises_verified": {st.label: st.premises_verified for st in s.stacks},
        # **只写等价类的名字，不写 ARN**：ARN 带 12 位账号 ID，而这份证据是 tracked 的
        # （`test_evidence_file_carries_no_account_id_or_role_names` 会咬）。
        "resource_equivalence_classes": [
            f"kms:session-signing-keys({len(s.kms_keys)} 把，来自 [SessionKeys] "
            "的 site + console 两个 family 的 current/previous)",
            "lambda:edge-origin-request", "lambda:site-auth-service",
            "lambda:site-panel", "lambda:placeholder-new-function",
            "cloudfront:wildcard-distribution", "cloudformation:router-stack",
            "cloudformation:deployer-stack(owns the two session CMKs)",
            "iam:edge-execution-role(PassRole)", "iam:cfn-service-role(PassRole)",
        ],
        "edge_association_qualifier_is_numbered_version": True,
        "aggregate": agg,
        "raw_observed_sha256": raw_hash,
        "known_gaps": [
            "IAM 自助提权（iam:PutRolePolicy 等）没有折进 can_sign：默认 key policy "
            "委派给账号 root 时，任何能给自己加 kms:Sign 的 principal 都进冒充面。"
            "那一层由闸门 B 组（IAM 写的静态文本快照）单独覆盖，口径不同不合并。",
            "kms:Sign 的真实集合还要 ∩ key policy；本探针只量 identity policy 上界。",
            "lambda:UpdateFunctionConfiguration 计为代码执行是**上界口径**："
            "还需要能发布/读到一个 Layer，本探针不追那一步。**只在支持 Layer 的函数上**"
            "才计入——Lambda@Edge 不支持 Layer（AWS 文档），所以它在 Edge 上不构成路径。",
            "UpdateFunctionCode / CreateFunction 是否在 IAM 上额外要求 "
            "lambda:PublishVersion，AWS 文档未明确说明；两者的输入都含 Publish"
            "（botocore 服务模型实测），本探针按**不要求**建模（取上界）。"
            "要证实只能做写调用，超出只读范围。",
            "guard=protected 只表示**受保护资源的直接更新**被 stack policy 挡住"
            "（ADR 0007/0008）。service role 权限足够高时，改模板新增 IAM 授权类资源等"
            "路径未必需要碰那四个资源 ⇒ 这类持有者落 edge:cfn-template-unanalyzed，"
            "**单列、不进并集**，也不得据此算确定收益。",
            "deployer 栈那条签名路径的前提（这次更新以谁的身份执行、那个身份是否真能改"
            "key policy）**尚未核实** ⇒ 一律落 sign:cfn-session-key-stack-unanalyzed。"
            "拥有 CMK、且该栈缺少 stack policy，都还不足以推出能改 key policy。",
            "CreateFunction 只对**两个**候选 ARN 有判定（一个中性名、一个与 router 栈"
            "同前缀）。按名字前缀授权的策略可能在别的名字上成立 ⇒ 这条是下界。",
            "只覆盖会话签名这一族。Cognito 的 site-auth-pre-token（注入 email "
            "claim）是另一条 MCP 侧冒充路径，不在 3c 范围。",
            "site-deployer-* 等平台角色是否在 3c 后持 kms:Sign 取决于实现；"
            "本探针按 spec §4.1 只算 auth 与 panel。",
            "sign:fixture-issuer 只把**角色本身**与**直接 invoke auth 函数**这两个入口计入；"
            "「能 assume site-builder-verifier 的链」不建模——那要做信任策略分析"
            "（角色的 trust policy × 各 principal 的 sts:AssumeRole），本探针只发"
            "identity policy 的模拟。⇒ 这个计数是该条路径持有者的**下界**。",
        ],
    }
    if args.write_evidence:
        EVIDENCE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False)
                            + "\n", encoding="utf-8")
        print(f"\n已写 {EVIDENCE.relative_to(_ROOT)}")
    if dump is not None:
        dump.parent.mkdir(parents=True, exist_ok=True)
        dump.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        print(f"已写名字 dump（gitignored）{dump}")
    if not args.write_evidence:
        print("\n（未加 --write-evidence，聚合证据没有落盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
