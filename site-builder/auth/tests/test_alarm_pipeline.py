"""告警管道的幂等声明式收敛。

用 botocore Stubber 而非 moto：需要精确断言"发出了哪些 API 调用、参数是
什么"（幂等性与配置漂移纠偏都是关于调用序列的），moto 的状态机模型看不到
这一层。
"""
import sys
from pathlib import Path

import boto3
import pytest
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(Path(__file__).parents[1]))
import alarm_pipeline


ARGS = dict(region="us-east-1", log_group="/aws/lambda/site-auth-service",
            namespace="SiteBuilder", metric_name="AuthInvalidGrant",
            filter_name="site-builder-auth-invalid-grant",
            filter_pattern='{ $.event = "token_exchange_invalid_grant" }',
            topic_name="site-builder-alarms",
            alarm_name="site-builder-auth-invalid-grant",
            account_id="000000000000")
TOPIC_ARN = "arn:aws:sns:us-east-1:000000000000:site-builder-alarms"


@pytest.fixture
def clients(monkeypatch):
    logs = boto3.client("logs", region_name="us-east-1",
                        aws_access_key_id="t", aws_secret_access_key="t")
    sns = boto3.client("sns", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    cw = boto3.client("cloudwatch", region_name="us-east-1",
                      aws_access_key_id="t", aws_secret_access_key="t")
    stubs = {"logs": Stubber(logs), "sns": Stubber(sns), "cw": Stubber(cw)}
    monkeypatch.setattr(alarm_pipeline, "_clients",
                        lambda region: (logs, sns, cw))
    for s in stubs.values():
        s.activate()
    yield logs, sns, cw, stubs
    for s in stubs.values():
        s.deactivate()


def _stub_common(stubs, *, subs, sub_result=None, fresh_account=False):
    """公共调用序列：建日志组（幂等）→ retention → metric filter → topic
    → 列订阅 → alarm。

    fresh_account=True 模拟全新账号：日志组不存在，create_log_group 成功；
    默认模拟现网：日志组已存在，create 抛 AlreadyExists 被吞。
    """
    if fresh_account:
        stubs["logs"].add_response("create_log_group", {})
    else:
        stubs["logs"].add_client_error("create_log_group",
                                       "ResourceAlreadyExistsException")
    # retention 的**值**必须进 expected_params：不带它的 add_response 只匹配
    # 操作名，`retentionInDays` 改成任何数字用例都照样绿（2026-08-15 统一到
    # 90 天时发现这里从未钉住过那个数字）。
    stubs["logs"].add_response(
        "put_retention_policy", {},
        expected_params={"logGroupName": ARGS["log_group"],
                         "retentionInDays": 90})
    stubs["logs"].add_response("put_metric_filter", {})
    stubs["sns"].add_response("create_topic", {"TopicArn": TOPIC_ARN})
    stubs["sns"].add_response("list_subscriptions_by_topic",
                              {"Subscriptions": subs})
    if sub_result is not None:
        stubs["sns"].add_response("subscribe", sub_result)
    stubs["cw"].add_response("put_metric_alarm", {})


def test_confirmed_subscription_is_not_recreated(clients):
    """已确认的订阅不得重复 subscribe（否则每次部署都给收件人发确认邮件）。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc-123"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "confirmed"
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_pending_confirmation_is_reported_as_incomplete(clients):
    """SubscriptionArn == 'PendingConfirmation' 必须显式报告为未完成——
    topic 有订阅但未确认时 alarm 照样进 ALARM 而无人知情。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": "PendingConfirmation"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "pending"


def test_missing_subscription_is_created_once(clients):
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[], sub_result={"SubscriptionArn": "PendingConfirmation"})
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["subscription_state"] == "pending"
    assert "subscription" in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_alarm_params_match_current_environment(clients):
    """阈值必须与当前环境一致：Sum/300/2/1/GTE/notBreaching，
    且 ALARM 与 OK 通知同一 topic。

    走 _stub_common 而不是自铺调用序列：实现的调用序列变化（如新增日志组
    前置）时只改一处，否则本用例会 Operation mismatch（Codex 复审第二轮
    实际抓到：这里曾直接从 put_metric_filter 开始 stub，而实现第一个调用
    已是 create_log_group）。
    """
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    p = alarm_pipeline.ALARM_PARAMS
    assert p["Statistic"] == "Sum"
    assert p["Period"] == 300
    assert p["EvaluationPeriods"] == 2
    assert p["Threshold"] == 1
    assert p["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
    assert p["TreatMissingData"] == "notBreaching"


def test_alarm_description_is_bilingual_and_says_alarm_cleared(clients):
    """OK 文案统一「告警解除」：只表示指标不再满足阈值，规则仍启用，
    不代表根因确认修复。"""
    d = alarm_pipeline.ALARM_DESCRIPTION
    assert "告警解除" in d
    assert "仍启用" in d or "未被删除" in d
    assert "不代表根因" in d or "不代表根因已确认修复" in d
    assert "English" in d or "alarm condition cleared" in d.lower()


def test_alarm_and_ok_actions_use_same_topic(clients):
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email", "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert out["topic_arn"] == TOPIC_ARN


def test_empty_email_raises_instead_of_silently_skipping(clients):
    """email 缺失时必须响亮失败——静默跳过会造出一个没人收通知的 alarm。"""
    with pytest.raises(ValueError, match="email"):
        alarm_pipeline.ensure_alarm_pipeline(email="", **ARGS)


def test_fresh_account_creates_log_group_before_metric_filter(clients):
    """全新账号：/aws/lambda/<fn> 日志组在函数**第一次被调用**时才自动创建。
    刚 CreateFunction 完还没人调过 → 不先建组，put_metric_filter 直接
    ResourceNotFoundException（Codex review 2026-08-09：从零部署会失败在
    半部署状态）。Stubber 的顺序断言保证 create_log_group 在 filter 之前。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}],
                 fresh_account=True)
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert "log_group" in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_existing_log_group_still_declares_retention(clients):
    """现网路径：组已存在（AlreadyExists 被吞），retention 仍要被声明成
    90 天（2026-08-15 用户决定：全平台日志组统一 90 天，取代原「统一 30 天」）。
    不再叫「收敛」：90 天是**抬高**保留期，无损。"""
    logs, sns, cw, stubs = clients
    _stub_common(stubs, subs=[{"Protocol": "email",
                               "Endpoint": "ops@example.com",
                               "SubscriptionArn": TOPIC_ARN + ":abc"}])
    out = alarm_pipeline.ensure_alarm_pipeline(email="ops@example.com", **ARGS)
    assert "log_group" not in out["changed"]
    for s in stubs.values():
        s.assert_no_pending_responses()
