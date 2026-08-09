"""reconciler/sweeper 的 CDK 模板断言。

与 test_infra_tables.py 同机制：默认 skip，要真跑需
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1
（aws_cdk 只装在 infra/.venv；不带 PYTHONPATH 会报错而非静默 skip）
"""
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("SB_CDK_TESTS"),
                                reason="需要 SB_CDK_TESTS=1 与 infra/.venv 的 aws_cdk")


@pytest.fixture(scope="module")
def template():
    sys.path.insert(0, str(Path(__file__).parents[1] / "infra"))
    from aws_cdk import App, Environment
    from aws_cdk.assertions import Template
    import app as infra_app
    a = App()
    stack = infra_app.SiteDeployerStack(
        a, "T", env=Environment(account="000000000000", region="us-east-1"))
    return Template.from_stack(stack)


def _resources(template, kind):
    return template.find_resources(kind)


def test_rule_matches_only_terminal_statuses_of_this_state_machine(template):
    rules = _resources(template, "AWS::Events::Rule")
    terminal = [r for r in rules.values()
                if "TIMED_OUT" in str(r["Properties"].get("EventPattern", ""))]
    assert len(terminal) == 1, "应有且仅有一条终态 rule"
    pattern = terminal[0]["Properties"]["EventPattern"]
    detail = pattern["detail"]
    assert set(detail["status"]) == {"TIMED_OUT", "ABORTED"}, \
        "只匹配 TIMED_OUT/ABORTED——FAILED 已由 add_catch→MarkFailed 覆盖，" \
        "重复收敛会把 mark_job 写的真实错因覆盖成通用文案"
    assert "stateMachineArn" in detail, "必须按状态机 ARN 过滤，不能收全账号事件"
    assert pattern["source"] == ["aws.states"]


def test_rule_target_has_dlq_and_retry(template):
    rules = _resources(template, "AWS::Events::Rule")
    terminal = [r for r in rules.values()
                if "TIMED_OUT" in str(r["Properties"].get("EventPattern", ""))][0]
    targets = terminal["Properties"]["Targets"]
    assert len(targets) == 1
    t = targets[0]
    assert "DeadLetterConfig" in t, "投递失败必须进 DLQ，否则事件静默丢失"
    retry = t.get("RetryPolicy", {})
    assert retry.get("MaximumRetryAttempts", 0) >= 2


def test_sweeper_schedule_is_every_30_minutes(template):
    rules = _resources(template, "AWS::Events::Rule")
    sched = [r for r in rules.values()
             if "rate(30 minutes)" == r["Properties"].get("ScheduleExpression")]
    assert len(sched) == 1, "sweeper 必须有 30 分钟定时触发"


def _narrow_policy(template):
    policies = _resources(template, "AWS::IAM::Policy")
    recon = [p for p in policies.values()
             if "states:DescribeExecution" in str(p["Properties"])]
    assert len(recon) == 1, "reconciler 应有独立的 inline policy"
    return recon[0]


def test_reconciler_functions_actually_use_the_narrow_role(template):
    """光有窄角色不算数——两个函数必须真的挂在它上面。

    只断言"存在一条窄 policy"会漏掉最可能发生的退化：角色留着但
    `role=recon_role` 被改回 `role=exec_role`（实测过——那样改 6 个断言全绿）。
    所以从窄 policy 反查它绑定的角色逻辑 ID，再断言两个函数的 Role 指向它。
    """
    role_refs = _narrow_policy(template)["Properties"]["Roles"]
    assert len(role_refs) == 1, "窄 policy 只应绑定 reconciler 一个角色"
    role_lid = role_refs[0]["Ref"]
    fns = {f["Properties"].get("FunctionName"): f["Properties"]["Role"]
           for f in _resources(template, "AWS::Lambda::Function").values()}
    for name in ("site-deployer-reconcile-job", "site-deployer-sweep-jobs"):
        assert fns.get(name) == {"Fn::GetAtt": [role_lid, "Arn"]}, \
            f"{name} 没有用窄角色（很可能被改回了 exec_role）"


def test_reconciler_role_is_narrow(template):
    """不得复用 exec_role：只允许 jobs 表条件更新 + DescribeExecution + 日志。"""
    doc = str(_narrow_policy(template)["Properties"]["PolicyDocument"])
    for forbidden in ("iam:CreateRole", "iam:PutRolePolicy",
                      "lambda:CreateFunction", "codebuild:StartBuild",
                      "dsql:DbConnectAdmin", "s3:PutObject",
                      "dynamodb:DeleteItem", "dynamodb:PutItem"):
        assert forbidden not in doc, f"reconciler 角色不得有 {forbidden}"
    assert "dynamodb:UpdateItem" in doc and "dynamodb:GetItem" in doc
    assert "site-sites" not in doc, "reconciler 不需要 sites 表"


def test_reconciler_functions_exist_with_right_handlers(template):
    fns = _resources(template, "AWS::Lambda::Function")
    handlers = {f["Properties"].get("FunctionName"): f["Properties"]["Handler"]
                for f in fns.values() if isinstance(
                    f["Properties"].get("FunctionName"), str)}
    assert handlers.get("site-deployer-reconcile-job") == "reconcile_job.handler"
    assert handlers.get("site-deployer-sweep-jobs") == "reconcile_job.sweeper_handler"


def test_dlq_exists(template):
    assert _resources(template, "AWS::SQS::Queue"), "必须有 DLQ"
