#!/usr/bin/env python3
"""账号信任边界闸门的**变形测试**：逐条改一行 → 跑指定用例 → 必须红 → 改回。

## 为什么这个脚本要进仓库

守卫套件全绿只说明"当前实现让这些断言通过"，**不说明那些断言真的能红**。这道闸门被
外部复审五轮，每一轮都至少有一条"加了守卫但守卫不生效"。所以每条关键守卫都要有一次
可复跑的反向验证。

原先这套变形只在 `/tmp` 里跑过一次、结果靠转述——复审据此指出"没有可复跑的
manifest/result artifact，无法独立认证"。那条成立：**验证证据不可复跑就等于没有证据。**

## 用法

    python3 site-builder/scripts/metamorphic_trust_boundary.py            # 全跑
    python3 site-builder/scripts/metamorphic_trust_boundary.py --only 3 7 # 只跑某几条
    python3 site-builder/scripts/metamorphic_trust_boundary.py --list     # 只列清单

退出码 0 = 每条变形都让对应守卫红了。非 0 = 有守卫是假的（脚本会点出是哪条）。

**它会临时改工作树里的文件**，跑完（含异常与 Ctrl-C）都会还原；开跑前要求工作树对这
两个文件是干净的，避免把你未提交的改动一起还原掉。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "site-builder/scripts/verify_account_trust_boundary.py"
TESTS = ROOT / "site-builder/deployer/tests/test_verify_account_trust_boundary.py"
PYTEST = ROOT / "site-builder/deployer/.venv/bin/pytest"

# (编号, 说明, 目标文件, 原文, 改成, 期望红的用例 -k 表达式)
#
# 加变形时的纪律：**先确认它在当前实现下真的红**。一条"改了却仍然绿"的变形要么是变形
# 本身写错（改在单测到不了的路径上、或把检查改得更严而非更松），要么是守卫真的假——
# 两者都必须查清楚，不许"大概是变形写错了"就跳过。
MUTATIONS: list[tuple] = [
    (1, "B 的指纹里排除 Condition", SCRIPT,
     '    body = {k: norm(v) for k, v in sorted(statement.items()) if k != "Sid"}',
     '    body = {k: norm(v) for k, v in sorted(statement.items())\n'
     '            if k not in ("Sid", "Condition")}',
     "changing_a_deny_condition or bootstrap_bucket_policy_condition "
     "or sensitive_to_condition"),
    (2, "B 的指纹里排除 NotResource", SCRIPT,
     '    body = {k: norm(v) for k, v in sorted(statement.items()) if k != "Sid"}',
     '    body = {k: norm(v) for k, v in sorted(statement.items())\n'
     '            if k not in ("Sid", "NotResource")}',
     "not_resource_membership"),
    (3, "is_relevant_iam_statement 只收 Allow", SCRIPT,
     '    if st.get("Effect") not in ("Allow", "Deny"):',
     '    if st.get("Effect") != "Allow":',
     "removing_a_relevant_deny or new_deny_statement_is_visible"),
    (4, "_compare_iam_write 不比 boundary", SCRIPT,
     '    base_b, now_b = base.get("permissions_boundaries") or {}, '
     'now.get("boundaries") or {}',
     '    base_b, now_b = {}, {}',
     "boundary_removal or boundary_statement_change"),
    (5, "GetAccountAuthorizationDetails 的 Filter 去掉 Group", SCRIPT,
     '            Filter=["User", "Role", "Group", "LocalManagedPolicy", '
     '"AWSManagedPolicy"]):',
     '            Filter=["User", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]):',
     "authorization_details_filter"),
    (6, "statements_for_user 不并 group 语句", SCRIPT,
     '    for name in detail.get("GroupList", []):',
     '    for name in []:',
     "group_inline_policy or group_managed_policy"),
    (7, "动作 glob 换回 endswith('*')", SCRIPT,
     '    return {a for a in IAM_WRITE_ACTIONS for p in pats\n'
     '            if fnmatch.fnmatchcase(a.lower(), str(p).lower())}',
     '    hit = set()\n'
     '    for raw in pats:\n'
     '        pat = str(raw).lower()\n'
     '        if pat in ("*", "iam:*"):\n'
     '            return set(IAM_WRITE_ACTIONS)\n'
     '        if pat.endswith("*"):\n'
     '            hit |= {a for a in IAM_WRITE_ACTIONS if a.lower().startswith(pat[:-1])}\n'
     '        else:\n'
     '            hit |= {a for a in IAM_WRITE_ACTIONS if a.lower() == pat}\n'
     '    return hit',
     "middle_wildcard or superset_of_an_independent_oracle"),
    (8, "B 的语句消失判成改善", SCRIPT,
     '            rep.iam_write_drift.append(\n                f"[{fp}] -语句 [{s}]——**消失也红**',
     '            rep.improvements.append(\n                f"[{fp}] -语句 [{s}]——**消失也红**',
     "removing_an_allow_statement_is_also_a_failure"),
    (9, "把模拟器塞回 B", SCRIPT,
     '        if fps:\n            iam_stmts[fp] = sorted(fps)',
     '        if fps:\n'
     '            iam.simulate_principal_policy(PolicySourceArn=p["arn"],\n'
     '                                         ActionNames=["iam:PutRolePolicy"])\n'
     '            iam_stmts[fp] = sorted(fps)',
     "does_not_call_the_simulator"),
    (10, "coverage 退回 principal 级", SCRIPT,
     '    return principal_fingerprint(\n'
     '        f"undecided:{principal_arn}|{action_class}|{resource_class}")',
     '    return principal_fingerprint(f"undecided:{principal_arn}")',
     "second_undecided_target or undecided_item_swap "
     "or second_undecided_platform_function"),
    (11, "undecided_pairs 丢掉顶层 MissingContextValues", SCRIPT,
     '                if frozenset(rr.get("MissingContextValues") or ()) | top:',
     '                if frozenset(rr.get("MissingContextValues") or ()):',
     "superset_of_the_old_boolean"),
    (12, "undecided_pairs 不跳过 allowed 资源", SCRIPT,
     '                if rr.get("EvalResourceDecision") == "allowed":\n'
     '                    continue        # 已经有答案了，不是"判不出"',
     '                if False:\n                    continue',
     "all_allowed_resources_are_not_undecided or allowed_resources_never_enter"),
    (13, "coverage 成员按 action 全局折叠（丢掉资源类集合）", SCRIPT,
     '    return {undecided_item_fp(principal_arn, cls, "|".join(sorted(classes)))\n'
     '            for cls, classes in by_action.items()}',
     '    return {undecided_item_fp(principal_arn, cls, "unattributed")\n'
     '            for cls in by_action}',
     "second_undecided_platform_function"),
    (14, "bucket policy 不快照", SCRIPT,
     '    _compare_bucket_policy(rep, base_rp.get("bootstrap_bucket"),',
     '    _compare_bucket_policy(rep, base_rp.get("bootstrap_bucket") and None,',
     "bootstrap_bucket_policy"),
    (15, "把所有 12 位数字都当成本账号归一化", SCRIPT,
     '    return json.dumps(body, sort_keys=True, ensure_ascii=False)'
     '.replace(account, "<acct>")\n\n\ndef canonical_statement_fp',
     '    _raw = json.dumps(body, sort_keys=True, ensure_ascii=False)\n'
     '    return re.sub(r"[0-9]{12}", "<acct>", _raw)\n\n\ndef canonical_statement_fp',
     "external_account_changes_the_fingerprint"),
    (16, "attached 托管策略文档缺失时 continue", SCRIPT,
     '        if arn not in managed:\n            raise SystemExit(',
     '        if arn not in managed:\n            continue\n        if False:\n'
     '            raise SystemExit(',
     "missing_attached_managed_policy_document_hard_fails"),
    (17, "托管策略版本未知时拿占位值兜底", SCRIPT,
     '        if arn not in versions:\n            raise SystemExit(',
     '        if arn not in versions:\n            versions[arn] = "?"\n'
     '        if False:\n            raise SystemExit(',
     "missing_managed_policy_version_hard_fails or managed_policy_versions_are_version_ids"),
    (18, "GroupList 解析不到时静默跳过", SCRIPT,
     '        if gr is None:\n            # **硬失败，不静默跳过**',
     '        if gr is None:\n            continue\n        if False:\n'
     '            # **硬失败，不静默跳过**',
     "unresolvable_group_hard_fails"),
    (19, "新红字段不接进 RED_FIELDS", SCRIPT,
     '    boundary_drift: list[str] = field(default_factory=list)',
     '    boundary_drift: list[str] = field(default_factory=list)\n'
     '    sneaky_new_red: list[str] = field(default_factory=list)',
     "report_fields_are_all_classified"),
    (20, "wants_baseline 恒真（纯 dump 也读基线）", SCRIPT,
     '    return not (args.dump_observed and not args.update_baseline)',
     '    return True',
     "dump_mode_does_not_require"),
    (21, "canonical_statement_text 自己归一化（只排顶层键）", SCRIPT,
     '    return canonicalize_statement(statement, account=account)',
     '    body = {k: v for k, v in sorted(statement.items()) if k != "Sid"}\n'
     '    return json.dumps(body, sort_keys=True, ensure_ascii=False)'
     '.replace(account, "<acct>")',
     "fingerprint_and_text_share_one_canonicalization"),
    (22, "TLS 未校验只警告不致命", SCRIPT,
     '    warnings.simplefilter("error", InsecureRequestWarning)',
     '    warnings.simplefilter("always", InsecureRequestWarning)',
     "insecure_tls_warning_is_fatal"),
    (23, "所有线程共享一个 IAM client", SCRIPT,
     '    if not hasattr(_TLS_LOCAL, "iam"):',
     '    if not hasattr(thread_iam_client, "_shared"):',
     "own_iam_client"),
    (24, "--no-asset-scan 不再限制用途", SCRIPT,
     '    if not getattr(args, "no_asset_scan", False):\n        return',
     '    return\n    if not getattr(args, "no_asset_scan", False):\n        return',
     "no_asset_scan_may_not_produce_a_verdict"),
    (25, "bundle 缺分节不再硬失败", SCRIPT,
     '    missing = [k for k in BUNDLE_SECTIONS if k not in bundle]',
     '    missing = []',
     "bundle_missing_a_section or from_dump_rejects_a_bundle_missing"),
    (26, "不完整的 asset 扫描可以当权威结果", SCRIPT,
     '    if not bundle.get("asset_scan_complete"):',
     '    if False:',
     "incomplete_asset_scan_cannot_be_replayed"),
    (27, "平台 resource policy 压回扁平集合（qualifier 类丢失）", SCRIPT,
     '        raw = raw.replace(f"{function}:{qualifier}", f"<self>:<{qualifier_class}>")',
     '        raw = raw.replace(f"{function}:{qualifier}", "<self>:<alias>")',
     "separates_alias_from_version"),
    (28, "平台快照不按 qualifier 分桶", SCRIPT,
     '    flat = {fn: bucketed(fn) for fn in platform}',
     '    flat = {fn: sorted({fp(fn, q, st) for q, st in policies.get(fn, [])})\n'
     '            for fn in platform}',
     "platform_policy_keeps_qualifier_buckets or platform_alias_losing_a_statement "
     "or baseline_platform_shape_matches"),
    (29, "基线红线检查回退成硬编码键", TESTS,
     '        if kind == "key":\n'
     '            if any(fnmatch.fnmatchcase(path, p) for p in _NON_FP_KEY_PATHS):\n'
     '                continue',
     '        if kind == "key":\n            continue',
     "catches_an_injected_new_subkey"),
    # 两处一起改才是真的"放行"：只删类型分流的话 grant 会落回"必须是指纹形态"，
    # 那是更严而不是更松（第一版变形就栽在这里，守卫照样红、什么也没证明）。
    (30, "grant 串回到整体放行（删类型分流 + 进自由文本）", TESTS,
     ('    ("principals.*.grants[]", _is_grant),\n',
      '    "principals.*.category",                # 类别名\n)'),
     ('',
      '    "principals.*.category",\n    "principals.*.grants[]",\n)'),
     "grant_carrying_an_arn_is_caught_by_the_tree_scan"),
    (31, "VersionId 位置改成任意字符串放行", TESTS,
     '    ("managed_policy_versions.*", _is_version_id),',
     '',
     "version_id_position_is_type_checked"),
]


def run_tests(k: str) -> tuple[int, str]:
    r = subprocess.run(
        [str(PYTEST), "tests/test_verify_account_trust_boundary.py", "-q", "-k", k,
         "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT / "site-builder/deployer", capture_output=True, text=True)
    return r.returncode, (r.stdout.strip().splitlines() or [""])[-1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", type=int, metavar="N", help="只跑这几条")
    ap.add_argument("--list", action="store_true", help="只列清单，不跑")
    args = ap.parse_args()

    todo = [m for m in MUTATIONS if not args.only or m[0] in args.only]
    if args.list:
        for num, desc, path, *_ in todo:
            print(f"  {num:>3}  [{path.name:38}] {desc}")
        return 0

    dirty = subprocess.run(["git", "status", "--porcelain", "--", str(SCRIPT), str(TESTS)],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if dirty:
        # 变形会临时改这两个文件再还原；带着未提交改动跑，一旦中途被杀就分不清
        # 哪些是你的改动、哪些是变形残留。
        raise SystemExit(f"这两个文件有未提交改动，先提交或 stash：\n{dirty}")

    print(f"共 {len(todo)} 条变形。每条都必须让对应守卫**红**——不红即守卫是假的。\n")
    fails = []
    for num, desc, path, old, new, k in todo:
        src = path.read_text(encoding="utf-8")
        # 一条变形可能需要**改两处**才真正削弱守卫。例如"grant 串回到整体放行"：
        # 只从类型分流里删掉它的话，grant 会落回"必须是指纹形态"那条默认规则 ——
        # 那是**变得更严**，不是放行，于是守卫照样红、变形什么也没证明。
        edits = list(zip(old, new)) if isinstance(old, tuple) else [(old, new)]
        mutated, missing = src, None
        for a, b in edits:
            if a not in mutated:
                missing = a
                break
            mutated = mutated.replace(a, b, 1)
        if missing is not None:
            print(f"  {num:>3}  {desc:46} 锚点没找到（实现变了？变形要同步更新）")
            fails.append((num, desc, f"锚点没找到: {missing[:40]!r}"))
            continue
        path.write_text(mutated, encoding="utf-8")
        try:
            code, last = run_tests(k)
        finally:
            path.write_text(src, encoding="utf-8")
        ok = code != 0
        print(f"  {num:>3}  {desc:46} {'红' if ok else '**仍然绿**'}   {last[:44]}")
        if not ok:
            fails.append((num, desc, last))

    print()
    if fails:
        print(f"{len(fails)} 条变形没让守卫红——那些守卫证明不了它声称的东西：")
        for num, desc, why in fails:
            print(f"   {num}: {desc}  ({why})")
        return 1
    print(f"全部 {len(todo)} 条变形都让对应守卫红了。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
