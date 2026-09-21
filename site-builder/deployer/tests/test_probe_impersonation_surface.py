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

def test_the_known_gaps_admit_the_assume_role_chain_is_not_modelled(probe):
    """能 assume `site-builder-verifier` 的链要靠信任策略分析，本探针不做 ⇒ 必须写进盲区，
    否则那个计数会被读成"夹具入口的完整持有者集合"。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "assume" in src and "信任策略" in src


# ---- 3g：探针只剩"观测 + 报告"，判定归共享模型 ----------------------------------

def test_probe_does_not_carry_its_own_judgement(probe):
    """判定必须来自共享模型：探针里不许再有第二份 `classify`。

    这条防的是"对齐"退化成"复制"——复制之后两边会各自漂移，而漂移的那一边正是
    给假绿的那一边（3g 的成因）。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "def classify(" not in src, "探针里又有一份 classify 定义"
    assert "_impersonation_model" in src, "探针没有 import 共享模型"
    assert probe.classify is probe.model.classify
    assert probe.summarize is probe.model.summarize


def test_self_test_delegates_to_the_shared_model(probe, capsys):
    """`--self-test` 的判定来自共享模块 ⇒ 改模型只会改一处，两个消费方都会红。"""
    assert probe.self_test() == 0
    assert "共享模型" in capsys.readouterr().out


def test_the_stale_no_stack_policy_premise_is_gone(probe):
    """ADR 0007 之后"router 栈**没有** stack policy"是过期前提。

    探针现在**不自己判** guard：栈发现整段委派给闸门的 `router_and_deployer_stacks`
    （R1-L3——两个采集方各写一份会让同一个账号事实在两个入口得出不同结论）。
    所以这条断言的是"过期前提不在了"+"确实委派了"，而不是"探针自己调了 guard_for"。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "且**无 stack policy**" not in src, "过期前提还在源码里"
    assert "gate.router_and_deployer_stacks(" in src, "探针没有委派给闸门的栈发现"
    assert "def _stack_facts(" not in src, "探针又自己写了一份栈发现"


def test_probe_does_not_derive_the_stack_from_a_function_tag(probe):
    """**R1-L3 blocker 的回归守卫**：`auth/deploy_auth.py` 用裸 `create_function` 建
    auth、不传 Tags、不经 CFN ⇒ 任何"从函数的 aws:cloudformation:stack-name 推导栈名"
    的写法在正常部署里都会失败。探针与闸门都不许再走那条路。
    """
    for rel in ("probe_impersonation_surface.py", "verify_account_trust_boundary.py"):
        src = (_ROOT / "site-builder" / "scripts" / rel).read_text(encoding="utf-8")
        assert "aws:cloudformation:stack-name" not in src or "edge_asset_location" in src, \
            f"{rel} 还在按函数 tag 推导栈名"


def test_sim_groups_covers_every_action_class_the_model_consumes(probe):
    """模型会读的每个动作等价类都必须真的被模拟到，否则那条路径恒为"不能"
    ——而"没问"与"不允许"在报告上一模一样。"""
    s = probe.model.Surface(
        kms_keys=("K1", "K2"),
        auth=probe.model.FnFact("AUTH", entry=probe.model.ENTRY_LATEST),
        panel=probe.model.FnFact("PANEL", entry=probe.model.ENTRY_LATEST),
        edge=probe.model.FnFact("EDGE", entry=probe.model.ENTRY_VERSION,
                                layers_supported=False),
        new_candidates=("NEW1", "NEW2"), distribution="DIST", edge_role="EDGEROLE",
        stacks=(probe.model.fake_stack("router",
                                       controls=frozenset({probe.model.CONTROLS_EDGE}),
                                       guard=probe.model.GUARD_OPEN),),
        service_roles=("CFNROLE",))
    asked = {a for actions, _ in probe.sim_groups(s) for a in actions}
    consumed = set()
    for name, value in vars(probe.model).items():
        if name.startswith("A_") and isinstance(value, tuple):
            consumed |= set(value)
    # 只读类（GetPublicKey/DescribeKey）刻意不进任何等价类，所以 consumed 就是全集
    missing = consumed - asked
    assert not missing, f"模型会读但探针没问：{sorted(missing)}"


def test_sim_groups_probes_both_keys_and_both_stacks(probe):
    """资源维度同理：两把 CMK、两个栈、两个候选 ARN 都要进模拟集合。"""
    s = probe.model.Surface(
        kms_keys=("K1", "K2"),
        auth=probe.model.FnFact("AUTH"), panel=probe.model.FnFact("PANEL"),
        edge=probe.model.FnFact("EDGE"),
        new_candidates=("NEW1", "NEW2"), distribution="DIST", edge_role="EDGEROLE",
        stacks=(probe.model.fake_stack("router", controls=frozenset({"x"})),
                probe.model.fake_stack("deployer", controls=frozenset({"y"}))),
        service_roles=("CFNROLE",))
    resources = {r for _, rs in probe.sim_groups(s) for r in rs}
    for want in ("K1", "K2", "NEW1", "NEW2", "DIST", "EDGEROLE", "CFNROLE",
                 "STACK_ROUTER", "STACK_DEPLOYER"):
        assert want in resources, want


def test_sim_groups_drops_empty_resource_groups(probe):
    """资源为空的组不发（IAM 会拒空 ResourceArns）——但**不能**因此少问动作。"""
    s = probe.model.Surface(
        kms_keys=(), auth=probe.model.FnFact("AUTH"), panel=probe.model.FnFact("PANEL"),
        edge=probe.model.FnFact("EDGE"), new_candidates=(), distribution="",
        edge_role="", stacks=(), service_roles=())
    for actions, resources in probe.sim_groups(s):
        assert resources, actions


def test_evidence_records_the_observed_guards(probe):
    """guard 是能力结论的前提 ⇒ 必须进 tracked 证据，否则"为什么这轮数字变了"无从对账。
    逻辑标签（router/deployer）不含账号值，可以进。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert '"stack_guards"' in src and '"stack_premises_verified"' in src


def test_the_two_real_cmks_come_from_config_not_a_placeholder_arn(probe):
    """占位 ARN 时代量的是"对本账号**任意** key 的 identity 上界"；两把 CMK 真的存在之后，
    继续用占位 ARN 会把 key policy 维度整条抹掉（`kms:Sign|<占位>` 谁都不会有）⇒
    `sign:kms-direct` 恒为 0，读起来像"这条路已经关掉了"。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "placeholder-key" not in src, "还在用占位 key ARN"
    assert "session_key_arns()" in src, "没有从 config 读真 key ARN"
