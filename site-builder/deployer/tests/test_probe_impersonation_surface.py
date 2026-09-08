"""3c 冒充面探针（`scripts/probe_impersonation_surface.py`）的纯判定部分。

那个探针**不是闸门**（没有基线、不会红），但 spec §1 的 headline 数字由它产生，
而 headline 直接决定"3c 值不值得做""限制性 key policy 值不值得做"。所以它的
`classify()` 必须自己有反例，且**那些反例必须被 CI 真的跑到**——只放在脚本的
`--self-test` 里等于等人想起来跑。

这份文件盯三件事：

① **探针自带的那一屏反例 + 聚合/边际断言全过**（`test_script_self_test_passes`）；
   条数不写死——新增等价路径就要新增一条反例，写死的数字只会变成过时的注释。
② **反例本身能红**（`test_*_mutation_*`）。探针的反例与被测代码在同一个文件里，
   最容易退化成"改判定顺手改期望"⇒ 这里从外面把动作等价类改窄，断言自检**转红**。
   这一条防的正是本仓库反复吃到的那类：守卫看着绿，其实什么都没证明。
③ **判定不许折叠资源维度**（`test_resource_dimension_is_not_collapsed`）。
   "能换 auth 的码"与"能换 Edge 的码"是两种不同能力；压成"有没有
   `lambda:UpdateFunctionCode`"会让 signer 劫持与 Edge 替换互相冒充对方的证据。
   这个建模错误在 `verify_account_trust_boundary.py` 里犯过三次（见那份的 `A_*` 注释）。

**这里刻意不做的事**：不连 AWS、不校验真机数字。真机部分的产物是
`docs/security/3c-impersonation-surface.json`（tracked，只有计数与指纹）。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_SCRIPT = _ROOT / "site-builder" / "scripts" / "probe_impersonation_surface.py"


def _probe():
    spec = importlib.util.spec_from_file_location("_probe", _SCRIPT)
    assert spec is not None and spec.loader is not None, _SCRIPT
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_probe"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def probe():
    return _probe()


def test_script_exists_and_is_tracked():
    """探针必须是 tracked 的。上一轮它住在 gitignored 的 `docs/design/3c-spike/`，
    于是 tracked 的 spec 引着一份新 clone 里不存在的证据。"""
    import subprocess
    assert _SCRIPT.exists(), _SCRIPT
    out = subprocess.run(["git", "ls-files", "--error-unmatch", str(_SCRIPT)],
                         cwd=_ROOT, capture_output=True, text=True)
    assert out.returncode == 0, f"{_SCRIPT} 不是 tracked 的——证据又只活在本机了"


def test_script_self_test_passes(probe, capsys):
    assert probe.self_test() == 0
    capsys.readouterr()


def test_self_test_goes_red_when_action_class_is_narrowed(probe, capsys):
    """**变形测试**：把"代码执行"这一类收窄成只有 `UpdateFunctionCode`，
    自检必须转红——`UpdateFunctionConfiguration`（挂 Layer 遮蔽模块）那条就漏了。

    这是元测试：它证明上面那条 `self_test() == 0` 不是一个恒真的摆设。
    """
    probe.LAMBDA_CODE_EXEC = ("lambda:UpdateFunctionCode",)
    assert probe.self_test() == 1
    capsys.readouterr()


def test_self_test_goes_red_when_changeset_chain_is_dropped(probe, capsys):
    """同上，换一个维度：删掉 change-set 那条等价路径必须转红。

    `CreateChangeSet`+`ExecuteChangeSet` 与 `UpdateStack` 等价（router 栈已关联
    CFN service role 且无 stack policy ⇒ 调用方自己不需要 `iam:PassRole`）。
    """
    probe.CFN_CHANGESET = ("cloudformation:ThisActionDoesNotExist",)
    assert probe.self_test() == 1
    capsys.readouterr()


def test_self_test_goes_red_when_key_policy_is_credited_for_signer_hijack(probe,
                                                                         capsys):
    """把"限制性 key policy"说成能收掉劫持 signer 那条路，必须转红。

    这是上一轮 headline 出错的根因：拿"能签名但不能替换 Edge"当 key policy 的收益
    判据。劫持 signer 的恶意代码是**以 signer 角色的身份**调 KMS 的 ⇒ key policy
    必须放行它 ⇒ 收不掉。
    """
    probe.MITIGATIONS = dict(probe.MITIGATIONS,
                             **{"restrictive-kms-key-policy":
                                (probe.S_KMS_DIRECT, probe.S_KMS_SELF,
                                 probe.S_HIJACK_AUTH)})
    assert probe.self_test() == 1
    capsys.readouterr()


def test_resource_dimension_is_not_collapsed(probe):
    """**独立于脚本自带用例**再断言一次：同一个动作打在不同资源上是不同能力。

    只靠脚本里那张 `cases` 表的话，"改判定顺手改期望"就没人拦。
    """
    s = probe._fake_surface()
    auth_only = probe.classify(frozenset({"lambda:UpdateFunctionCode|AUTH"}), s)
    edge_only = probe.classify(frozenset({"lambda:UpdateFunctionCode|EDGE"}), s)
    assert auth_only == {probe.S_HIJACK_AUTH}
    # Edge 上的换码权限单独**不构成**任何能力：CloudFront 关联的是编号版本，
    # 而 `UpdateFunctionCode` 只改 `$LATEST`（实测 association 限定符 = 编号版本）。
    assert edge_only == set()


def test_single_action_is_not_a_capability_for_edge(probe):
    """正向控制：闸门今天的 `replace-platform-code`（只模拟 `UpdateFunctionCode`）
    对 Edge 是**过度声称**。这条用例把那个差别钉死。"""
    s = probe._fake_surface()
    assert probe.classify(frozenset({"lambda:UpdateFunctionCode|EDGE",
                                     "lambda:PublishVersion|EDGE"}), s) == set()
    assert probe.classify(frozenset({"lambda:UpdateFunctionCode|EDGE",
                                     "cloudfront:UpdateDistribution|DIST"}), s) \
        == {probe.E_PUBLISH_INLINE}


def test_publish_inline_does_not_require_publish_version(probe):
    """`UpdateFunctionCode(Publish=True)` 一次调用即改码即发版本 ⇒ 把
    `lambda:PublishVersion` 当**必需**会少算 principal（外部复审第十四轮 P1-1）。"""
    s = probe._fake_surface()
    labels = probe.classify(frozenset({"lambda:UpdateFunctionCode|EDGE",
                                       "cloudfront:UpdateDistribution|DIST"}), s)
    assert probe.E_PUBLISH_INLINE in labels
    assert probe.E_PUBLISH_THEN_ASSOCIATE not in labels


def test_every_label_is_covered_by_a_mitigation_or_declared_uncovered(probe):
    """每个能力标签都必须落在某个候选缓解措施里。

    漏一个的后果是：spec 讨论"关掉哪条路值不值得"时，那条路**根本不在讨论范围内**，
    而 headline 里它还在。新增标签时这条会红，逼着同步 `MITIGATIONS`。
    """
    covered = {lb for group in probe.MITIGATIONS.values() for lb in group}
    missing = set(probe.ALL_LABELS) - covered
    assert not missing, f"这些能力路径没有对应的候选措施：{sorted(missing)}"


def test_evidence_file_carries_no_account_id_or_role_names():
    """tracked 的聚合证据里不许出现 12 位账号 ID。

    仓库红线（`CLAUDE.md`）：真实账号 ID / 内部角色名 / distribution ID 不进被跟踪
    文件。这条在**文件存在时**才有意义；不存在就跳过（还没跑过真机探测）。
    """
    import json
    import re
    ev = _ROOT / "docs" / "security" / "3c-impersonation-surface.json"
    if not ev.exists():
        pytest.skip("还没跑过真机探测")
    text = ev.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{12}\b", text), "聚合证据里出现了 12 位数字（账号 ID？）"
    data = json.loads(text)
    assert "raw_observed_sha256" in data, "没有原始输出的 hash ⇒ 无法回指 gitignored 产物"
    assert data["known_gaps"], "没有已知盲区清单 ⇒ 这份证据会被读成完整上界"


# ---- 3c-final：真 key ARN + 夹具签发器那条受限冒充路 --------------------------------

def test_the_two_real_cmks_come_from_config_not_a_placeholder_arn(probe):
    """占位 ARN 时代量的是"对本账号**任意** key 的 identity 上界"；两把 CMK 真的存在之后，
    继续用占位 ARN 会把 key policy 维度整条抹掉（`kms:Sign|<占位>` 谁都不会有）⇒
    `sign:kms-direct` 恒为 0，读起来像"这条路已经关掉了"。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "placeholder-key" not in src, "还在用占位 key ARN"
    s = probe._fake_surface()
    assert isinstance(s.kms_keys, tuple) and len(s.kms_keys) >= 2, s.kms_keys
    # 两把都要进模拟的资源集合，否则只量到 site 那把
    resources = {r for _, rs in s.groups() for r in rs}
    assert set(s.kms_keys) <= resources, resources


def test_sign_on_either_key_counts(probe):
    """**任一把**成立即标：console 那把能签面板会话，site 那把能签站点会话——
    折成"只看 site"会漏掉一整个 family 的冒充面。"""
    s = probe._fake_surface()
    for key in s.kms_keys:
        assert probe.classify(frozenset({f"kms:Sign|{key}"}), s) == {probe.S_KMS_DIRECT}, key
        assert probe.classify(frozenset({f"kms:CreateGrant|{key}"}), s) == {probe.S_KMS_SELF}, key


def test_fixture_issuer_is_a_label_and_has_a_candidate_mitigation(probe):
    assert probe.S_FIXTURE_ISSUER == "sign:fixture-issuer"
    assert probe.S_FIXTURE_ISSUER in probe.ALL_LABELS
    covered = {lb for group in probe.MITIGATIONS.values() for lb in group}
    assert probe.S_FIXTURE_ISSUER in covered


def test_direct_invoke_of_the_auth_function_is_the_fixture_issuer_entry(probe):
    """`POST /fixture-session` 走 auth 的 Function URL；能直接 `lambda:InvokeFunction`
    的 principal 不需要 assume verifier 角色就能拿到夹具会话（spec §11.7 / ADR 0002）。"""
    s = probe._fake_surface()
    assert probe.classify(frozenset({f"lambda:InvokeFunction|{s.auth_fn}"}), s) \
        == {probe.S_FIXTURE_ISSUER}
    # 资源维度不许折叠：打在 panel / Edge 上的 invoke 不是夹具签发入口
    assert probe.classify(frozenset({f"lambda:InvokeFunction|{s.panel_fn}"}), s) == set()
    assert probe.classify(frozenset({f"lambda:InvokeFunction|{s.edge_fn}"}), s) == set()


def test_the_verifier_role_itself_is_the_url_entry(probe):
    """URL 入口：`site-builder-verifier` 角色的 inline policy 就是那两条 invoke 语句 ⇒
    角色本身即持有这条路，不需要在模拟结果里出现任何动作。"""
    s = probe._fake_surface()
    assert probe.classify(frozenset(), s, probe.VERIFIER_ROLE_NAME) == {probe.S_FIXTURE_ISSUER}
    assert probe.classify(frozenset(), s, "some-other-role") == set()


def test_read_only_kms_is_still_not_a_capability(probe):
    """反例：只有 `kms:GetPublicKey` 的 principal 既不能签，也拿不到夹具会话。
    公钥不是秘密——把它算进冒充面会让 headline 虚高一大截。"""
    s = probe._fake_surface()
    for key in s.kms_keys:
        assert probe.classify(frozenset({f"kms:GetPublicKey|{key}",
                                         f"kms:DescribeKey|{key}"}), s) == set()


def test_fixture_issuer_is_reported_separately_from_can_sign(probe):
    """夹具签发器是**受限**冒充（只签夹具域邮箱、TTL ≤ 30 分钟、Edge 只在夹具站点认）
    ⇒ 单列，不并进 `can_sign`。并进去会让"3c 之后还有多少人能冒充任意用户"这个数字
    把验收工具的持有者也算进来。
    """
    agg = probe.summarize({"p-fixture-only": {probe.S_FIXTURE_ISSUER},
                           "p-real-sign": {probe.S_KMS_DIRECT}})
    assert agg["can_sign"] == 1, "夹具签发器被并进了 can_sign"
    assert agg["impersonation_surface_union"] == 1
    assert agg["fixture_issuer_holders"] == 1


def test_no_mitigation_can_report_a_negative_marginal_value(probe):
    """边际收益 = 冒充面里离开的人数，**分母是冒充面**。拿全体 principal 做分母时，
    只持夹具入口的人会让 `principals_removed` 变成负数（面 1 → remaining 2）。
    """
    agg = probe.summarize({"p-fixture-only": {probe.S_FIXTURE_ISSUER},
                           "p-cfn-only": {probe.E_CFN_UPDATE_STACK}})
    for name, m in agg["marginal_value_if_closed"].items():
        assert 0 <= m["principals_removed"] <= agg["impersonation_surface_union"], (name, m)
        assert m["surface_after"] <= agg["impersonation_surface_union"], (name, m)
    assert agg["marginal_value_if_closed"]["fixture-issuer-verifier-boundary"][
        "principals_removed"] == 0, "关掉验收工具不该被记成冒充面收益"


def test_self_test_goes_red_when_the_fixture_issuer_entry_is_dropped(probe, capsys):
    """变形测试：把"直接 invoke auth"这条入口从动作等价类里去掉，自检必须转红。
    否则上面那些 `classify` 断言可能只是在复述一个恒真的实现。"""
    probe.LAMBDA_INVOKE = ("lambda:ThisActionDoesNotExist",)
    assert probe.self_test() == 1
    capsys.readouterr()


def test_the_known_gaps_admit_the_assume_role_chain_is_not_modelled(probe):
    """能 assume `site-builder-verifier` 的链要靠信任策略分析，本探针不做 ⇒ 必须写进盲区，
    否则那个计数会被读成"夹具入口的完整持有者集合"。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "assume" in src and "信任策略" in src


def test_a_principal_left_with_only_the_fixture_label_has_left_the_surface(probe):
    """**修复轮 I1**：`{sign:kms-direct, sign:fixture-issuer}` 的 principal 在 KMS 那一组关掉后
    只剩受限入口（只能签夹具域邮箱）⇒ 它**真的离开了冒充面**，必须计入收益。

    旧口径拿"还有标签没被关掉"当判据，于是它留在 `remaining` 里，
    `restrictive-kms-key-policy` 的 `principals_removed` 少报一个——而那个数字就是
    "限制性 key policy 值不值得做"的唯一依据。单标签的反例照不出这个错：两个标签才行。
    """
    agg = probe.summarize({
        "p-kms-and-fixture": {probe.S_KMS_DIRECT, probe.S_FIXTURE_ISSUER},
        "p-kms-and-hijack": {probe.S_KMS_DIRECT, probe.S_HIJACK_AUTH},
    })
    assert agg["impersonation_surface_union"] == 2
    m = agg["marginal_value_if_closed"]["restrictive-kms-key-policy"]
    assert m["principals_removed"] == 1, m       # 只有 p-kms-and-fixture 离开
    assert m["surface_after"] == 1, m            # p-kms-and-hijack 还剩劫持 signer
    # 反向：关掉劫持那一组时，p-kms-and-fixture 一个都不动（它没有那条路）
    assert agg["marginal_value_if_closed"]["harden-signer-code-update"][
        "principals_removed"] == 0


def test_the_same_membership_criterion_decides_entering_and_leaving_the_surface(probe):
    """进面与离面必须用**同一个**判据（`is_surface_label`）。

    两套判据的症状不是崩，而是一个安静地算错的数字：受限标签既不让人进面，
    就不能在离面时把人留住。
    """
    assert probe.is_surface_label(probe.S_KMS_DIRECT)
    assert probe.is_surface_label(probe.E_CFN_UPDATE_STACK)
    assert not probe.is_surface_label(probe.S_FIXTURE_ISSUER)
    # 全部标签都要有明确归属：要么进面，要么是被单列的那一个
    for lb in probe.ALL_LABELS:
        assert probe.is_surface_label(lb) or lb == probe.S_FIXTURE_ISSUER, lb


def test_the_verifier_role_name_is_pinned_to_the_deploy_auth_constant(probe):
    """**修复轮 I2**：探针里那份 `VERIFIER_ROLE_NAME` 是第四份手写字面量，必须有东西钉住它。

    改了角色名而漏改探针的症状是**静默**的：名字判据不再命中任何 principal，
    `sign:fixture-issuer` 的计数少掉 URL 入口那一半，而探针照样 exit 0。

    这里按 AST 从 `auth/deploy_auth.py`（生产真源）读那个常量，**不 import 它**——
    探针刻意不依赖 boto3，`--self-test` 那条路必须一个 AWS 依赖都没有。
    同一条纪律见 `test_verify_deployed_components.py` 里"角色名写死了字面量"那条。
    """
    import ast
    src = (_ROOT / "site-builder" / "auth" / "deploy_auth.py").read_text(encoding="utf-8")
    found = [n.value.value for n in ast.parse(src).body
             if isinstance(n, ast.Assign) and len(n.targets) == 1
             and getattr(n.targets[0], "id", None) == "VERIFIER_ROLE_NAME"
             and isinstance(n.value, ast.Constant)]
    assert len(found) == 1, f"deploy_auth.py 里的 VERIFIER_ROLE_NAME 不是唯一的字面量赋值：{found}"
    assert probe.VERIFIER_ROLE_NAME == found[0], (
        f"探针写的是 {probe.VERIFIER_ROLE_NAME!r}，deploy_auth.py 是 {found[0]!r}"
        "——名字判据已经命不中任何 principal 了")
