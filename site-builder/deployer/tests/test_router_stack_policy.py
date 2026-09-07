"""`scripts/router_stack_policy.py`（open / apply / check）对着假 CloudFormation client 的行为。

纯逻辑（逻辑 ID 推导、策略体、比较）在 router 套件的 `lambda/test_stack_policy.py`；这里只管 CLI 的
副作用契约：什么时候写、什么时候拒绝、读回不一致算失败、check 一个写调用都不许发。
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "site-builder" / "scripts" / "router_stack_policy.py"
H = "AAAAAAAA"
ACCT = "000000000000"     # 与 cfg fixture 里的 [AWS] account_id 一致；凭据账号在测试里显式注入
TEMPLATE = {"Resources": {
    f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::Table"},
    f"OriginRequestFunction{H}": {"Type": "AWS::Lambda::Function"},
    f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40: {"Type": "AWS::Lambda::Version"},
    f"OriginResponseFunction{H}": {"Type": "AWS::Lambda::Function"},
    f"Distribution{H}": {"Type": "AWS::CloudFront::Distribution"},
}}


def _load():
    spec = importlib.util.spec_from_file_location("_router_stack_policy", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_router_stack_policy"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def cli():
    return _load()


class _ClientError(Exception):
    def __init__(self, code, msg):
        super().__init__(f"{code}: {msg}")
        self.response = {"Error": {"Code": code, "Message": msg}}


class _FakeCfn:
    """只实现脚本会碰的四个调用；`writes` 记下每一次写。"""

    def __init__(self, *, exists=True, status="UPDATE_COMPLETE", template=TEMPLATE, policy=None,
                 corrupt_writes=False):
        self.exists, self.status, self.template, self.policy = exists, status, template, policy
        self.corrupt_writes = corrupt_writes
        self.reads, self.writes = [], []

    def describe_stacks(self, StackName):
        self.reads.append("describe_stacks")
        if not self.exists:
            raise _ClientError("ValidationError", f"Stack with id {StackName} does not exist")
        return {"Stacks": [{"StackStatus": self.status}]}

    def get_template(self, StackName, TemplateStage):
        self.reads.append("get_template")
        return {"TemplateBody": self.template}

    def get_stack_policy(self, StackName):
        self.reads.append("get_stack_policy")
        return {"StackPolicyBody": json.dumps(self.policy)} if self.policy is not None else {}

    def set_stack_policy(self, StackName, StackPolicyBody):
        self.writes.append(json.loads(StackPolicyBody))
        self.policy = {"Statement": []} if self.corrupt_writes else json.loads(StackPolicyBody)


@pytest.fixture()
def cfg(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text("[AWS]\naccount_id = 000000000000\nregion = us-east-1\n"
                 "[CDK]\nstack_name = ApplicationWebRouterStack\n")
    return p


def _expected(cli):
    return cli.build_policy(cli.protected_logical_ids(TEMPLATE))


def test_import_has_no_side_effects(cli):
    assert callable(cli.main) and set(cli.COMMANDS) == {"open", "apply", "check"}


def test_apply_sets_the_derived_policy_and_reads_it_back(cli, cfg, capsys):
    fake = _FakeCfn()
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert fake.writes == [_expected(cli)]
    out = capsys.readouterr().out
    assert "PASS" in out and f"LogicalResourceId/Distribution{H}" in out


def test_apply_reasserts_even_when_already_correct(cli, cfg):
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert len(fake.writes) == 1, "重申是刻意的：有人手工 open 过而没人知道时，下一次部署把它关回去"


@pytest.mark.parametrize("status", ["UPDATE_IN_PROGRESS", "CREATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS"])
@pytest.mark.parametrize("verb", ["apply", "open"])
def test_apply_and_open_refuse_while_the_stack_is_in_progress(cli, cfg, status, verb):
    fake = _FakeCfn(status=status)
    assert cli.main([verb, "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert fake.writes == []


def test_apply_fails_when_the_readback_does_not_match(cli, cfg, capsys):
    fake = _FakeCfn(corrupt_writes=True)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert "读回" in capsys.readouterr().err


def test_apply_fails_when_the_stack_does_not_exist(cli, cfg):
    fake = _FakeCfn(exists=False)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert fake.writes == []


def test_apply_fails_when_a_protected_resource_cannot_be_derived(cli, cfg, capsys):
    tpl = {"Resources": {k: v for k, v in TEMPLATE["Resources"].items() if not k.startswith("Distribution")}}
    fake = _FakeCfn(template=tpl)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert fake.writes == [], "推不出 ID 时绝不能写一份缺项的策略"
    assert "Distribution" in capsys.readouterr().err


def test_open_skips_on_a_missing_stack_and_writes_allow_all_otherwise(cli, cfg, capsys):
    fake = _FakeCfn(exists=False)
    assert cli.main(["open", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert fake.writes == [] and "SKIP" in capsys.readouterr().out
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["open", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert fake.writes == [cli.OPEN_POLICY]
    assert "apply" in capsys.readouterr().out, "open 的输出必须提醒 apply"


def test_check_is_read_only_and_passes_on_the_expected_policy(cli, cfg):
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["check", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert fake.writes == []
    assert set(fake.reads) == {"describe_stacks", "get_template", "get_stack_policy"}


@pytest.mark.parametrize("kind", ["none", "open", "partial", "wildcard"])
def test_check_fails_on_every_defective_policy_and_stays_read_only(cli, cfg, kind, capsys):
    exp = _expected(cli)
    deny = exp["Statement"][1]
    bad = {"none": None, "open": cli.OPEN_POLICY,
           "partial": {"Statement": [exp["Statement"][0], {**deny, "Resource": deny["Resource"][1:]}]},
           "wildcard": {"Statement": [exp["Statement"][0], {**deny, "Resource": "*"}]}}[kind]
    fake = _FakeCfn(policy=bad)
    assert cli.main(["check", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert fake.writes == []
    assert "apply" in capsys.readouterr().err, "check 红了要告诉操作者怎么修"


def test_template_body_may_arrive_as_a_json_string(cli, cfg):
    fake = _FakeCfn(template=json.dumps(TEMPLATE), policy=_expected(cli))
    assert cli.main(["check", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0


def test_unreadable_config_is_a_hard_failure_not_an_empty_stack_name(cli, tmp_path):
    with pytest.raises(SystemExit, match="读不到"):
        cli.main(["check", "--config", str(tmp_path / "missing.ini")], cfn=_FakeCfn())
    half = tmp_path / "half.ini"
    half.write_text("[AWS]\nregion = us-east-1\n")
    with pytest.raises(SystemExit, match="CDK"):
        cli.main(["check", "--config", str(half)], cfn=_FakeCfn())


def test_other_describe_errors_are_not_mistaken_for_a_missing_stack(cli, cfg):
    class _Denied(_FakeCfn):
        def describe_stacks(self, StackName):
            raise _ClientError("AccessDenied", "not authorized")

    with pytest.raises(_ClientError):
        cli.main(["open", "--config", str(cfg)], cfn=_Denied(), caller_account=ACCT)


def test_the_edge_gate_runs_check_before_its_verdict():
    """⑤ 必须在总判定之前、且红了要走 fail()（计入 FAILURES）——只 echo 的红进不了退出码。"""
    gate = (ROOT / "site-builder" / "scripts" / "verify_deployed_edge.sh").read_text(encoding="utf-8")
    call = gate.index('router_stack_policy.py" check')
    assert call < gate.index('if [ "$FAILURES" -gt 0 ]'), "⑤ 放在总判定之后 = 它的红进不了退出码"
    assert 'fail "router 栈的 stack policy' in gate, "check 红了必须走 fail()，不能只 echo"


# ---- 目标账号核对：第一次写之前 ----------------------------------------------------------------

@pytest.mark.parametrize("verb", ["open", "apply", "check"])
def test_wrong_caller_account_is_refused_before_any_call(cli, cfg, verb, capsys):
    """AWS_PROFILE 指错时同名栈可能在别的账号里：open 会剥掉**那个**账号的保护并打印 PASS。
    所以凭据账号 != config 账号 ⇒ 退 1，且一个 CloudFormation 调用（读或写）都不发。"""
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main([verb, "--config", str(cfg)], cfn=fake, caller_account="111111111111") == 1
    assert fake.writes == [] and fake.reads == []
    err = capsys.readouterr().err
    assert "111111111111" in err and "000000000000" in err


def test_config_without_account_id_is_a_hard_failure(cli, tmp_path):
    p = tmp_path / "config.ini"
    p.write_text("[AWS]\nregion = us-east-1\n[CDK]\nstack_name = S\n")
    with pytest.raises(SystemExit) as ei:
        cli.main(["check", "--config", str(p)], cfn=_FakeCfn(), caller_account=ACCT)
    assert "account_id" in str(ei.value)


# ---- 恢复状态：被覆盖的策略体必须先打出来 ------------------------------------------------------

def test_open_prints_the_outgoing_policy_before_overwriting(cli, cfg, capsys):
    custom = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
                            {"Effect": "Deny", "Action": "Update:Delete", "Principal": "*",
                             "Resource": "LogicalResourceId/HandEditedAAAAAAAA"}]}
    fake = _FakeCfn(policy=custom)
    assert cli.main(["open", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    out = capsys.readouterr().out
    assert "HandEditedAAAAAAAA" in out and "恢复用" in out, "open 覆盖前没把旧策略体打出来"
    assert out.index("恢复用") < out.index("PASS"), "恢复信息要在写之前（PASS 之前）出现"


def test_apply_prints_a_foreign_policy_it_replaces_but_not_the_expected_or_open_ones(cli, cfg, capsys):
    foreign = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
                             {"Effect": "Deny", "Action": "Update:Delete", "Principal": "*",
                              "Resource": "LogicalResourceId/OldDeclarationAAAAAAAA"}]}
    fake = _FakeCfn(policy=foreign)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
    assert "OldDeclarationAAAAAAAA" in capsys.readouterr().out
    for quiet in (cli.OPEN_POLICY, _expected(cli)):
        fake = _FakeCfn(policy=quiet)
        assert cli.main(["apply", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 0
        assert "恢复用" not in capsys.readouterr().out, "open 留下的 Allow-all 与已是期望的策略不是需要恢复的东西"


def test_review_in_progress_gets_its_own_message(cli, cfg, capsys):
    fake = _FakeCfn(status="REVIEW_IN_PROGRESS")
    assert cli.main(["open", "--config", str(cfg)], cfn=fake, caller_account=ACCT) == 1
    assert fake.writes == [] and "change set" in capsys.readouterr().err

