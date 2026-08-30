"""3c 冒充面探针（`scripts/probe_impersonation_surface.py`）的纯判定部分。

那个探针**不是闸门**（没有基线、不会红），但 spec §1 的 headline 数字由它产生，
而 headline 直接决定"3c 值不值得做""限制性 key policy 值不值得做"。所以它的
`classify()` 必须自己有反例，且**那些反例必须被 CI 真的跑到**——只放在脚本的
`--self-test` 里等于等人想起来跑。

这份文件盯三件事：

① **探针自带的 18 条反例 + 2 条聚合/边际断言全过**（`test_script_self_test_passes`）；
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
