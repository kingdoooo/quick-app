"""`scripts/session_key_fingerprint.py`：把两把 CMK 变成可粘贴的 `[SessionKey:<kid>]` 小节（spec §11.6）。

这个脚本是**部署链的第一步与 config 之间唯一的桥**：deployer 栈建出 key → 本脚本算指纹 →
人把两个小节粘进 `config.ini` → 三个部署脚本的部署前核对才可能通过。所以被守的失败面有两类：

① **算错却照样打印**。指纹抄错的症状是 auth / panel / router 在**第一次写之前**拒绝部署
   （`session_kms.precheck_keys`），读起来像权限问题；形态不对（KeySpec / KeyUsage /
   SigningAlgorithms / SPKI 任一项）更是要在这里就拒，而不是打一个"看着像指纹"的 64 位 hex
   出去让人粘进 config。
② **打印出来的东西粘不进 config**。小节名、键名、值形态必须正好过 `load_session_keys`——
   本文件直接把输出拼成一份配置喂给真加载器，而不是逐行比对字符串。

`FakeKms` 与三套件（auth / panel / router）共用同一组 RS256 测试密钥（`panel/tests/
upgrade_code_vectors.py` 的文件头解释了为什么共用一份）。evidence: fake/unit。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_SCRIPT = _ROOT / "site-builder" / "scripts" / "session_key_fingerprint.py"
# **在这里 insert 而不是在 conftest 里**：auth / router 两侧也是各自 test 文件自己 insert，
# 往 deployer 的 conftest 里塞会让各包的同名 conftest 撞车（同 test_verify_deployed_components.py）。
sys.path.insert(0, str(_ROOT / "site-builder" / "panel" / "tests"))
sys.path.insert(0, str(_ROOT / "site-builder" / "auth"))

import upgrade_code_vectors as v  # noqa: E402


def _mod():
    spec = importlib.util.spec_from_file_location("_skfp", _SCRIPT)
    assert spec is not None and spec.loader is not None, _SCRIPT
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_skfp"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def fp():
    return _mod()


def _pairs():
    return [(v.SITE_KID, v.KEY_ARN[v.SITE_KID]), (v.CONSOLE_KID, v.KEY_ARN[v.CONSOLE_KID])]


def test_two_pasteable_sections_carry_alg_arn_and_the_real_fingerprint(fp):
    kms = v.FakeKms()
    out = fp.sections(kms, _pairs())
    for kid in (v.SITE_KID, v.CONSOLE_KID):
        assert f"[SessionKey:{kid}]" in out
        assert f"key_arn = {v.KEY_ARN[kid]}" in out
        assert f"spki_sha256 = {v.spki_hex(v.PRIVATE[kid])}" in out
    assert out.count("alg = RS256") == 2
    assert out.count("[SessionKey:") == 2, "多打或漏打了小节"


def test_the_printed_sections_actually_load_under_the_real_loader(fp, tmp_path):
    """"可粘贴"不是靠肉眼：把输出拼进一份 `[SessionKeys]` 里喂真加载器。

    这条盯的是"键名/值形态漂移但输出看着对"——`ssm_param` 时代的键名、alias 而不是完整
    key ARN、大写 hex，三种都会在这里被 `load_session_keys` 咬住。
    """
    from session_keys import load_session_keys
    cfg = tmp_path / "config.ini"
    cfg.write_text(
        "[SessionKeys]\n"
        f"site_current = {v.SITE_KID}\nsite_previous =\n"
        f"console_current = {v.CONSOLE_KID}\nconsole_previous =\n"
        "login_flow_secret_param = /site-builder/login-flow-secret\n\n"
        + fp.sections(v.FakeKms(), _pairs()), encoding="utf-8")
    keys = load_session_keys(cfg)
    site = keys.families["site"]["current"]
    assert site.kid == v.SITE_KID and site.key_arn == v.KEY_ARN[v.SITE_KID]
    assert site.spki_sha256 == v.spki_hex(v.SITE_KEY)


def test_it_only_reads_kms_never_signs(fp):
    """只读（DescribeKey + GetPublicKey）。一次 `Sign` 都不许发——那会消耗一次真实签名，
    也说明它走的不是 `describe_public_key` 那条只读路径。"""
    kms = v.FakeKms()
    fp.sections(kms, _pairs())
    kinds = {c[0] for c in kms.calls}
    assert kinds == {"describe_key", "get_public_key"}, kms.calls


def test_it_goes_through_session_kms_describe_public_key_not_a_second_implementation(fp,
                                                                                    monkeypatch):
    """四项校验只有一份实现（`session_kms.describe_public_key`）。手抄第二份的症状是
    形态检查在这里悄悄放宽，而部署脚本那侧仍然拒绝——两边不一致。"""
    seen = []

    def fake(kms, arn):
        seen.append(arn)
        return b"der", "f" * 64

    monkeypatch.setattr(fp.session_kms, "describe_public_key", fake)
    out = fp.sections(object(), _pairs())
    assert seen == [v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.CONSOLE_KID]]
    assert out.count("spki_sha256 = " + "f" * 64) == 2


def test_a_kid_that_does_not_match_the_contract_is_refused_before_any_call(fp):
    kms = v.FakeKms()
    with pytest.raises(SystemExit, match="不是合法 kid"):
        fp.sections(kms, [("site-hs-v1", v.KEY_ARN[v.SITE_KID])])
    assert kms.calls == [], "kid 不合法却已经打了 KMS"
    with pytest.raises(SystemExit):
        fp.sections(kms, [("nonsense", v.KEY_ARN[v.SITE_KID])])


@pytest.mark.parametrize("override", [
    {"KeySpec": "RSA_4096"},
    {"KeyUsage": "ENCRYPT_DECRYPT"},
    {"SigningAlgorithms": ["RSASSA_PSS_SHA_256"]},
    {"KeyState": "PendingDeletion"},
])
def test_a_key_of_the_wrong_shape_gets_no_fingerprint_printed(fp, override):
    """形态四项任一不符 ⇒ 退出，**不打印任何指纹**。

    打印了会被粘进 config，而"config 里那把 key 形态不对"要到三个部署脚本的部署前核对
    才暴露——那时错误文案说的是"与 [SessionKeys] 声明不符"，指向的却是这一步。
    """
    kms = v.FakeKms()
    kms.describe_overrides[v.KEY_ARN[v.SITE_KID]] = override
    with pytest.raises(SystemExit) as ei:
        fp.sections(kms, _pairs())
    assert "spki_sha256" not in str(ei.value), "错误消息里带上了指纹"


def test_a_tampered_public_key_still_prints_its_own_fingerprint(fp):
    """正向控制：`describe_public_key` **不与任何配置值比对**（config 里还没有指纹可比）。
    换了公钥就该给出换过之后的那个指纹——那正是"重算并回填"这个用法。"""
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    out = fp.sections(kms, [(v.SITE_KID, v.KEY_ARN[v.SITE_KID])])
    assert f"spki_sha256 = {v.spki_hex(v.CONSOLE_KEY)}" in out


def test_kid_and_arn_must_come_in_pairs_and_that_is_checked_before_touching_aws(fp):
    """`--kid` 与 `--arn` 数量不齐时 `zip` 会**静默丢掉**多出来的那个 ⇒ 少打一个小节，
    而人只会发现少了一节、不会发现是自己漏了参数。"""
    with pytest.raises(SystemExit, match="成对"):
        fp.main(["--kid", v.SITE_KID])
    with pytest.raises(SystemExit, match="成对"):
        fp.main(["--arn", v.KEY_ARN[v.SITE_KID]])


def test_no_argument_at_all_is_refused(fp):
    with pytest.raises(SystemExit, match="--from-stack"):
        fp.main([])


def test_from_stack_reads_both_cfn_outputs(fp):
    class Cfn:
        def describe_stacks(self, StackName):
            assert StackName == "TheStack"
            return {"Stacks": [{"Outputs": [
                {"OutputKey": "SiteSessionKeyRsV1Arn", "OutputValue": v.KEY_ARN[v.SITE_KID]},
                {"OutputKey": "ConsoleSessionKeyRsV1Arn", "OutputValue": v.KEY_ARN[v.CONSOLE_KID]},
                {"OutputKey": "StateMachineArn", "OutputValue": "arn:aws:states:x"}]}]}

    assert fp.from_stack(Cfn(), "TheStack") == _pairs()


def test_from_stack_refuses_when_the_stack_has_no_key_outputs(fp):
    """栈还没部（或部的是没有 CMK 的旧版）⇒ 响亮失败。缺 Outputs 时 `.get` 回空 dict，
    `zip` 会拼出零个小节 ⇒ 脚本 exit 0 打印空白，人会以为"没有 key 要回填"。"""
    class Cfn:
        def describe_stacks(self, StackName):
            return {"Stacks": [{}]}

    with pytest.raises(SystemExit, match="SiteSessionKeyRsV1Arn"):
        fp.from_stack(Cfn(), "TheStack")


def test_the_two_stack_output_names_match_the_cdk_stack():
    """CfnOutput 的名字是本脚本与 `infra/app.py` 之间的唯一契约（Task 18 的 `--from-stack`
    这一步照抄它们）。任一侧改名都必须在这里红。"""
    mod = _mod()
    app = (_ROOT / "site-builder" / "deployer" / "infra" / "app.py").read_text(encoding="utf-8")
    assert set(mod.STACK_OUTPUTS) == {"site-rs-v1", "console-rs-v1"}, mod.STACK_OUTPUTS
    for out in mod.STACK_OUTPUTS.values():
        assert f'"{out}"' in app, f"app.py 里没有 CfnOutput {out}"


def test_the_script_never_writes_config_or_ssm():
    """它只打印可粘贴文本，回填是人做的（spec §11.6）。自动改写 config 会让"部署前核对"
    这道闸门失去意义——那时 config 与 KMS 天然一致，而人并没有确认过换的是哪把 key。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("write_text", "put_parameter", "update_", "create_", ".sign("):
        assert forbidden not in src, f"脚本里出现了写操作 {forbidden}"
