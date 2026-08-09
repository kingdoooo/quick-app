"""登录失败告警管道的**唯一配置真源**（幂等声明式 provisioning）。

注意用词：这**不是 IaC**——没有状态文件、没有漂移检测、没有依赖图。它是一个
每次运行都把四样资源收敛到声明值的幂等脚本，与 deploy_auth.py 的其余部分同
模式。

为什么归 deploy_auth.py 而不是 CDK：告警监控的就是本脚本部署的那个 Lambda
的日志组，同一脚本声明全部配套资源、生命周期一致；CDK 要跨体系引用已存在的
日志组，email 还得新开 context 通道并且会进 cdk.out 模板。

为什么必须自动化：现网这套是**手工建的**——只跑部署脚本不会收敛出它，
"从零部署得到相同配置"这个要求不成立。收编方式是同名 upsert，从此
**只有一个 writer**。

`invalid_grant` 为什么值得告警：它既表示"用户重放授权码"（无害），也表示
"app client 缺少 scope 所需的属性读取权限"（**每个用户每次登录都失败**的
配置事故），两者在响应里无法可靠区分。唯一的发现手段是频率告警。
"""
import logging

import boto3

logger = logging.getLogger(__name__)

# 当前环境的阈值。改这里就是改线上——它是唯一真源。
ALARM_PARAMS = {
    "Statistic": "Sum",
    "Period": 300,
    "EvaluationPeriods": 2,
    "Threshold": 1.0,
    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
    "TreatMissingData": "notBreaching",
}

# 中英双语。**OK 一律称「告警解除」**：只表示指标不再满足阈值，告警规则仍然
# 启用，不代表根因已确认修复（notBreaching 意味着"没有数据"也会转 OK）。
ALARM_DESCRIPTION = (
    "【中文】Site Builder 登录授权码交换持续失败。触发条件：连续 2 个 5 分钟"
    "周期，每个周期 AuthInvalidGrant >= 1。可能影响：用户可能无法登录。"
    "常见原因：授权码过期/重放、Cognito App Client 属性读取权限或 "
    "OAuth client/grant/redirect URI 配置错误。ALARM=告警触发；"
    "OK=告警解除（仅表示指标不再满足阈值，告警规则仍启用，"
    "不代表根因已确认修复；缺失数据按 notBreaching 处理）。"
    "【English】Site Builder OAuth authorization-code exchanges are failing "
    "continuously. Threshold: AuthInvalidGrant >= 1 in each of 2 consecutive "
    "5-minute periods. ALARM=condition breached; OK=alarm condition cleared. "
    "The alarm remains enabled, and OK does not confirm root-cause resolution "
    "because missing data is treated as notBreaching.")


def _clients(region):
    return (boto3.client("logs", region_name=region),
            boto3.client("sns", region_name=region),
            boto3.client("cloudwatch", region_name=region))


def ensure_alarm_pipeline(*, region, log_group, namespace, metric_name,
                          filter_name, filter_pattern, topic_name, alarm_name,
                          email, account_id) -> dict:
    """把 metric filter / topic / subscription / alarm 收敛到声明值。

    返回 {"topic_arn", "subscription_state", "alarm_name", "changed"}。
    subscription_state ∈ {"confirmed", "pending", "absent"}——**pending 必须
    被调用方当作"未完成"报告**：topic 有未确认订阅时 alarm 照样进 ALARM
    而无人知情，那正是这套告警要防的盲区。
    """
    if not (email or "").strip():
        raise ValueError(
            "缺少告警通知 email——配置 [Alerting] email 或环境变量 "
            "SB_ALERT_EMAIL。不允许静默跳过：那会造出一个没人收通知的 alarm，"
            "比没有 alarm 更危险（会让人以为已有监控）。")
    logs, sns, cw = _clients(region)
    changed = []

    # ⓪ 日志组必须先存在：Lambda 的 /aws/lambda/<fn> 日志组在**函数第一次被
    # 调用**时才自动创建，不是 CreateFunction 时。全新账号跑 deploy_auth.py
    # 时函数刚建好还没被调过 → put_metric_filter 直接
    # ResourceNotFoundException，B2 部署失败且 auth Lambda 已被改动（半部署）。
    try:
        logs.create_log_group(logGroupName=log_group)
        changed.append("log_group")
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    # retention 收敛到 30 天（spec §6.3：平台日志组统一 30 天）。
    # ⚠️ 这是**有意的数据修剪**，不是无害配置：现网若是更长保留期（曾是
    # 90 天），超过 30 天的日志会被标记删除、约 72 小时内物理删除，事后调回
    # 也找不回。首次在存量环境运行前，部署方必须确认历史日志无保留需要
    # （deploy 门禁项，见 plan Task 4 Step 4）。
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=30)

    # ① metric filter：put 是 upsert 语义，直接声明即可
    logs.put_metric_filter(
        logGroupName=log_group, filterName=filter_name,
        filterPattern=filter_pattern,
        metricTransformations=[{"metricName": metric_name,
                                "metricNamespace": namespace,
                                "metricValue": "1",
                                "defaultValue": 0.0}])
    changed.append("metric_filter")

    # ② topic：create_topic 对已存在的同名 topic 返回其 ARN（幂等）
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]

    # ③ subscription：**先 list 再 subscribe**。无条件 subscribe 会在每次
    # 部署给收件人发一封确认邮件（已确认的订阅也会被再创建一条 pending）。
    state = "absent"
    paginator = sns.get_paginator("list_subscriptions_by_topic")
    existing = []
    for page in paginator.paginate(TopicArn=topic_arn):
        existing.extend(page.get("Subscriptions", []))
    mine = [s for s in existing
            if s.get("Protocol") == "email" and s.get("Endpoint") == email]
    if any(s.get("SubscriptionArn", "").startswith("arn:") for s in mine):
        state = "confirmed"
    elif mine:
        state = "pending"
    else:
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email,
                      ReturnSubscriptionArn=True)
        changed.append("subscription")
        state = "pending"    # email 订阅**必须由收件人手工点确认链接**

    # ④ alarm：put_metric_alarm 是 upsert。ALARM 与 OK 通知同一 topic。
    cw.put_metric_alarm(
        AlarmName=alarm_name, AlarmDescription=ALARM_DESCRIPTION,
        Namespace=namespace, MetricName=metric_name,
        ActionsEnabled=True,
        AlarmActions=[topic_arn], OKActions=[topic_arn],
        **ALARM_PARAMS)
    changed.append("alarm")

    return {"topic_arn": topic_arn, "subscription_state": state,
            "alarm_name": alarm_name, "changed": changed}
