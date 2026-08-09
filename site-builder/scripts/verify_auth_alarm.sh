#!/usr/bin/env bash
# 登录失败告警 —— 真机端到端验收（alarm 必须真的进 ALARM）。
#
# 为什么"日志打了/metric 有点了"不算验收完成：`invalid_grant` 既表示"用户重放
# 授权码"，也表示"app client 缺少 scope 所需的属性读取权限"——后者是**每个用户
# 每次登录都失败**的配置事故，而两者在响应里无法可靠区分，代码统一返回 400。
# 唯一的发现手段是频率告警，所以必须证明 alarm 会进 ALARM 且通知送达。
#
# 用法（cookie 与 state 从 stdin 读，不进 argv）：
#   ./verify_auth_alarm.sh
#   SNS_TOPIC_ARN=arn:aws:sns:... ./verify_auth_alarm.sh   # 一并验证通知送达
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$HERE/../config.ini"
ROUTER_CFG="$HERE/../../router/config.ini"
[ -f "$CFG" ] || { echo "找不到 $CFG"; exit 1; }

read_cfg() {
  python3 - "$1" "$2" "$3" <<'PY'
import configparser, sys
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1])
print(c[sys.argv[2]][sys.argv[3]].split("#")[0].strip())
PY
}
REGION="$(read_cfg "$CFG" Platform region)"
BASE_DOMAIN="$(read_cfg "$CFG" Platform base_domain)"
ACCOUNT_ID="$(read_cfg "$CFG" Platform account_id)"
LOG_GROUP="/aws/lambda/site-auth-service"
AUTH_DIR="$HERE/../auth"
# 探针 alarm 名带 TEST 前缀 + 随机后缀：邮件收件人第一眼就能分辨验收探针，
# 不会把它误认成生产事故。固定名另有两个坑（Codex 审查 2026-08-06 P1）：
# ① PutMetricAlarm 更新现有 alarm 时**保留当前状态**，上次残留的若是 ALARM，
#    本轮第一次查询就 PASS —— 而本轮的事件可能根本没触发过它；
# ② 两个人同时跑会互相覆盖配置、并在清理时删掉对方的 alarm。
PROBE_ALARM="TEST-site-builder-auth-invalid-grant-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')"
PROBE_DESCRIPTION='【验收测试 / TEST ONLY】这是 verify_auth_alarm.sh 创建的一次性探针，不代表生产事故。触发条件：1 个 60 秒周期内 AuthInvalidGrant >= 1。目的：验证 Logs → Metric Filter → CloudWatch Alarm → SNS → Email 全链路；脚本结束后自动删除。ALARM=测试条件触发；OK=告警解除（仅表示指标不再满足条件，告警规则未被删除）。This is a temporary acceptance-test alarm, not a production incident. Threshold: AuthInvalidGrant >= 1 in one 60-second period.'

COOKIE_JAR="$(mktemp -t sbjar.XXXXXX)"
chmod 600 "$COOKIE_JAR"
CLEANED=0
FAILURES=0
# 与 FAILURES 分开计：见 cleanup 里 MIN_CHECKS 的说明。
CHECKS=0

cleanup() {
  local rc=$?
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  echo
  echo "── 清理 ─────────────────────────────"
  # PKCE cookie 含 code_verifier 与 nonce，是凭证：尽量覆写而非仅 unlink
  if command -v shred >/dev/null 2>&1; then
    shred -u "$COOKIE_JAR" 2>/dev/null || rm -f "$COOKIE_JAR"
  else
    dd if=/dev/urandom of="$COOKIE_JAR" bs=1k count=4 conv=notrunc 2>/dev/null || true
    rm -f "$COOKIE_JAR"
  fi
  aws cloudwatch delete-alarms --region "$REGION" \
    --alarm-names "$PROBE_ALARM" 2>/dev/null || true
  # **"状态未知"必须与"已删除"分开**（Codex 复审 2026-08-07）：原写法把
  # describe 的输出喂给 `grep -qv '^None$'`，凭证/网络失败时 stdout 为空、
  # grep 无匹配行返回 1 → 判定"已删除"，而探针 alarm 可能还在。
  # 只有显式读到 False 才算确认删除；其余（True/空/Unknown）一律要人工确认。
  local present
  present="$(aws cloudwatch describe-alarms --region "$REGION" \
               --alarm-names "$PROBE_ALARM" \
               --query 'MetricAlarms[0] != null' --output text 2>/dev/null \
             || echo Unknown)"
  if [ "$present" != "False" ]; then
    echo "⚠️  探针 alarm 未确认删除（present=${present:-空}）：$PROBE_ALARM"
    echo "    手工核对并删除：aws cloudwatch delete-alarms --alarm-names $PROBE_ALARM"
    exit 1
  fi
  echo "探针 alarm 与 cookie 文件已清理"
  if [ "$FAILURES" -gt 0 ]; then
    echo "结果：$FAILURES 项未达预期"
    exit 1
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # **检查数下限**：FAILURES=0 有两种来源——真的全过，或者中途 `exit` 掉了
  # 一批检查（探针名撞车、粘贴的 cookie 为空、set -e 撞上意外非零）。后者
  # 走的也是这个 trap，此时 FAILURES 仍是 0，不设下限就会打印"全部通过"。
  # 6 项 = ①(1) + ①b 声明值比对(1) + ①c 声明收件人订阅(1)
  #        + ②(/callback 400、token_exchange_invalid_grant 日志 = 2)
  #        + ③(探针进 ALARM = 1)。
  # 计数点就在每项判定处 CHECKS=$((CHECKS + 1))，所以这个数是数出来的、
  # 不是估的；新增检查项时必须同步加计数与本下限。
  MIN_CHECKS=6
  if [ "$CHECKS" -lt "$MIN_CHECKS" ]; then
    # **`${VAR}` 的花括号在这里是必需的，不是风格**：紧跟变量名的是全角破折号，
    # bash 会把它的首字节当成变量名的一部分（实测 `$MIN_CHECKS—` 报
    # `MIN_CHECKS\xe2: unbound variable`），而 set -u 让 cleanup 当场中断。
    echo "结果：只跑了 ${CHECKS} 项（预期 ≥${MIN_CHECKS}）—— 验收**未完成**，"
    echo "      状态不可信：没有 FAIL 不等于全部通过（中途退出也会到这里）。"
    exit 1
  fi
  # **不能笼统说"端到端可用"**：未给 SNS_TOPIC_ARN 时，探针 alarm 没有通知动作，
  # 这一轮只证明了"状态机会进 ALARM"，没证明有人被通知到（Codex 审查 P1）。
  if [ -n "${SNS_TOPIC_ARN:-}" ]; then
    echo "结果：状态机与通知动作均已验证 —— 仍需人工确认订阅端收到消息"
  else
    echo "结果：alarm 状态机可用；**通知送达未验证**"
    echo "      （未给 SNS_TOPIC_ARN；正式验收请带上它，并去订阅端确认收到消息）"
  fi
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL  $1"; FAILURES=$((FAILURES + 1)); }

echo "⚠️  这是一次性验收探针。若在相邻两个正式 5 分钟周期内重复执行，"
echo "    可能同时触发正式 site-builder-auth-invalid-grant 告警；这是阈值的预期行为。"
echo
echo "── ① 正式配置核对 ────────────────────────────────"
# **逐字段核对，不只看"存在"**：原来只取 Threshold/EvaluationPeriods/
# AlarmActions[0] 且不比对期望值，于是正式 alarm 即使监控的是拼错的
# metric name（永远不会有数据点），只要"存在一个 action"就 PASS，而临时
# probe alarm 用的是硬编码的正确 metric，照样能进 ALARM —— 整套验收通过，
# 线上告警其实是死的（Codex 审查 2026-08-06 P1）。
# 用 Python 做比对：多字段结构化对比 + 精确退出码，shell 里做这个已经踩过
# 一轮陷阱（见 check_permissions_state.py 的 docstring）。
if python3 - "$REGION" "$LOG_GROUP" <<'PYCHK'
import json, os, subprocess, sys
region, log_group = sys.argv[1], sys.argv[2]
NS, METRIC = "SiteBuilder", "AuthInvalidGrant"
ALARM = "site-builder-auth-invalid-grant"
bad = []

def aws(*a):
    p = subprocess.run(["aws", *a, "--output", "json"], capture_output=True, text=True)
    # 不能只看 returncode：本机 CLI 在 API 错误时也可能返回 0
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        raise SystemExit(f"FAIL  AWS 调用失败: {(p.stderr or p.stdout).strip()[:200]}")

mf = aws("logs", "describe-metric-filters", "--region", region,
         "--log-group-name", log_group,
         "--filter-name-prefix", "auth-invalid-grant").get("metricFilters", [])
if not mf:
    bad.append("metric filter 不存在 —— 见 DEPLOY.md「决定安全边界的几项配置」")
else:
    f = mf[0]
    tr = (f.get("metricTransformations") or [{}])[0]
    # metric name/namespace 必须与 alarm 监控的完全一致，否则 filter 有数据
    # 而 alarm 看的是另一个 metric（或反之），两边都"存在"但链路断开
    if tr.get("metricName") != METRIC or tr.get("metricNamespace") != NS:
        bad.append(f"metric filter 写的是 {tr.get('metricNamespace')}/"
                   f"{tr.get('metricName')}，与 alarm 监控的 {NS}/{METRIC} 不一致")
    if "$.event" not in f.get("filterPattern", ""):
        bad.append(f"filterPattern 不像结构化匹配: {f.get('filterPattern')!r}")
    if not bad:
        print(f"PASS  metric filter → {NS}/{METRIC}，pattern 正确")

al = aws("cloudwatch", "describe-alarms", "--region", region,
         "--alarm-names", ALARM).get("MetricAlarms", [])
if not al:
    bad.append(f"正式 alarm {ALARM} 不存在")
else:
    a = al[0]
    checks = {"Namespace": NS, "MetricName": METRIC, "Statistic": "Sum",
              "ComparisonOperator": "GreaterThanOrEqualToThreshold"}
    for k, want in checks.items():
        if a.get(k) != want:
            bad.append(f"正式 alarm 的 {k}={a.get(k)!r}，期望 {want!r}")
    if not a.get("AlarmActions"):
        bad.append("正式 alarm 没有 AlarmActions —— 进 ALARM 也没人被通知到")
    # 第一阶段通知可读性约束：Description 必须同时解释中英文阈值与 OK 语义；
    # OKActions 必须通知同一条 SNS 链路，让操作者知道"告警条件解除"，而不是
    # 误以为规则被删除或根因已经确认修复。
    desc = a.get("AlarmDescription", "")
    for marker in ("【中文】", "【English】", "告警解除",
                   "alarm condition cleared"):
        if marker not in desc:
            bad.append(f"正式 alarm 的 AlarmDescription 缺少 {marker!r}")
    sns_alarm = [x for x in a.get("AlarmActions", []) if ":sns:" in x]
    sns_ok = [x for x in a.get("OKActions", []) if ":sns:" in x]
    if not sns_ok:
        bad.append("正式 alarm 没有 SNS OKActions —— 告警解除时不会通知")
    elif sns_alarm and not set(sns_alarm).intersection(sns_ok):
        bad.append("正式 alarm 的 ALARM/OK 通知没有使用同一个 SNS topic")
    # **灵敏度参数必须核**（Codex 复审 2026-08-07）：metric/namespace/action 全对
    # 但 Threshold=1000000 或 ActionsEnabled=false 时，这个 alarm 永远不会通知，
    # 而下面的 probe alarm 用自己那套正确参数照样进 ALARM —— 整套验收 PASS，
    # 线上告警是死的。这正是本脚本要防的那类"成功但没证明目标成立"。
    if a.get("ActionsEnabled") is not True:
        bad.append(f"正式 alarm 的 ActionsEnabled={a.get('ActionsEnabled')!r}"
                   " —— 动作被禁用，进 ALARM 也不会发通知")
    # 期望值可按环境覆盖（低流量环境 DEPLOY.md 建议 1/300/2）。
    # 上限而非等值比较：把阈值调**低**、周期调**短**只会更灵敏，不是缺陷。
    limits = [
        ("Threshold", "EXPECT_THRESHOLD", "1",
         "阈值过高则事故凑不满数量，告警永不触发"),
        ("Period", "EXPECT_PERIOD", "300", "周期过长则发现太慢"),
        ("EvaluationPeriods", "EXPECT_EVAL_PERIODS", "2",
         "评估周期过多则发现太慢"),
    ]
    for key, envvar, default, why in limits:
        want = float(os.environ.get(envvar, default))
        got = a.get(key)
        if got is None or float(got) > want:
            bad.append(f"正式 alarm 的 {key}={got!r} 超过期望上限 {want!r}"
                       f"（{why}）；预期不同请设 {envvar}")
    # **Period 还有下限，不是"越短越安全"**（Codex 复审 2026-08-07 第二轮）：
    # AuthInvalidGrant 来自 logs metric filter，PutMetricFilter 没有
    # StorageResolution 参数，所以它是标准分辨率 metric。官方对 Period 的说明：
    # 合法值是 10/20/30 与 60 的倍数，但 10/20/30 只应用于 StorageResolution=1
    # 的 metric——用在标准分辨率上"alarm 会经常落入 INSUFFICIENT_DATA"
    # （还会按高分辨率 alarm 计费）。配合 EvaluationPeriods=2 + notBreaching，
    # Period=10 可能永远凑不满连续 breaching 数据点，而只查上限时照样 PASS。
    period = a.get("Period")
    if period is not None:
        if float(period) < 60:
            bad.append(f"正式 alarm 的 Period={period!r} < 60 —— 该 metric 由 logs "
                       "metric filter 产生（标准分辨率，无 StorageResolution=1），"
                       "亚分钟周期会让 alarm 常驻 INSUFFICIENT_DATA 而不告警")
        elif float(period) % 60 != 0:
            bad.append(f"正式 alarm 的 Period={period!r} 不是 60 的倍数 —— "
                       "标准分辨率 metric 只支持 60 的倍数")
    # DatapointsToAlarm 省略时等于 EvaluationPeriods（M-of-N 未启用）；
    # 显式设了就不能大于它，否则永远凑不满。
    dp = a.get("DatapointsToAlarm")
    if dp is not None and float(dp) > float(a.get("EvaluationPeriods") or 0):
        bad.append(f"DatapointsToAlarm={dp!r} > EvaluationPeriods="
                   f"{a.get('EvaluationPeriods')!r} —— 永远无法满足")
    if a.get("TreatMissingData") != "notBreaching":
        bad.append(f"TreatMissingData={a.get('TreatMissingData')!r}，"
                   "低流量环境应为 notBreaching，否则长期 INSUFFICIENT_DATA")
    if not [x for x in bad if "正式 alarm" in x]:
        print(f"PASS  正式 alarm：{a['Namespace']}/{a['MetricName']} "
              f"{a['Statistic']} 阈值 {a.get('Threshold')} × "
              f"{a.get('EvaluationPeriods')} 周期 → {len(a['AlarmActions'])} 个动作")
        # **必须至少有一条 SNS action**：本平台的验收目标是"邮件通知真的送达"。
        # 原来只在遇到 SNS action 时才查订阅，于是 action 全是 Lambda/SSM 时
        # 整个循环空转、脚本仍 PASS —— 而没有任何人会收到邮件
        # （Codex 复审 2026-08-07 第二轮）。
        if not [x for x in a["AlarmActions"] if ":sns:" in x]:
            bad.append(f"正式 alarm 的 AlarmActions 里没有 SNS topic"
                       f"（当前 {a['AlarmActions']}）—— 本平台靠 SNS 邮件通知，"
                       "没有 SNS action 就没人会被通知到")
        # 订阅确认状态：topic 无已确认订阅时 alarm 进 ALARM 也没人知情
        for arn in a["AlarmActions"]:
            if ":sns:" not in arn:
                continue
            subs = aws("sns", "list-subscriptions-by-topic", "--region", region,
                       "--topic-arn", arn).get("Subscriptions", [])
            ok = [x for x in subs if x.get("SubscriptionArn", "").startswith("arn:")]
            if not ok:
                bad.append(f"{arn.rsplit(':', 1)[-1]} 没有**已确认**的订阅"
                           f"（共 {len(subs)} 条，均未确认）—— 告警形同虚设")
            else:
                print(f"PASS  SNS {arn.rsplit(':', 1)[-1]}："
                      f"{len(ok)} 条已确认订阅 {[x['Protocol'] for x in ok]}")

for b in bad:
    print(f"FAIL  {b}")
sys.exit(1 if bad else 0)
PYCHK
then :; else fail "配置核对未通过（见上面 FAIL 行）"; fi
CHECKS=$((CHECKS + 1))

echo
echo "── ①b 线上配置 == alarm_pipeline.py 声明值 ────────"
# 为什么要比对而不只看"存在"：手工改过的 alarm 与脚本声明的可能已漂移，
# 而上面的"存在 + 上限"检查会全绿。真源只有一份，线上必须等于它。
#
# 声明值**从源码 AST 读，不 import**：alarm_pipeline 顶层 import boto3，而本
# 脚本要能在没装 boto3 的环境跑（auth 借用 contract 的 venv，见 CLAUDE.md）；
# 且 AST 路径用绝对路径，不依赖调用者的 CWD——sys.path.insert("site-builder/auth")
# 那种相对写法只在仓库根目录跑时成立，从 scripts/ 里跑会 ModuleNotFound，
# 而那会被下面的"读不到声明值"判成 FAIL（假红）。
DECLARED="$(python3 - "$AUTH_DIR" <<'PY' || echo ''
import ast, json, sys

auth = sys.argv[1]

def parse(name):
    with open(f"{auth}/{name}", encoding="utf-8") as f:
        return ast.parse(f.read())

decl = {}
for node in parse("alarm_pipeline.py").body:
    if (isinstance(node, ast.Assign)
            and getattr(node.targets[0], "id", "") in ("ALARM_PARAMS",
                                                       "ALARM_DESCRIPTION")):
        decl[node.targets[0].id] = ast.literal_eval(node.value)

# deploy_auth.py 里那次调用的字面量实参就是"声明的资源名/维度"。
kw = {}
for node in ast.walk(parse("deploy_auth.py")):
    if (isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "ensure_alarm_pipeline"):
        for k in node.keywords:
            if isinstance(k.value, ast.Constant):
                kw[k.arg] = k.value.value

alarm = dict(decl["ALARM_PARAMS"])
alarm["AlarmDescription"] = decl["ALARM_DESCRIPTION"]
alarm["Namespace"] = kw["namespace"]
alarm["MetricName"] = kw["metric_name"]
print(json.dumps({"alarm": alarm, "alarm_name": kw["alarm_name"],
                  "topic_name": kw["topic_name"],
                  "filter_name": kw["filter_name"]}, sort_keys=True))
PY
)"
CHECKS=$((CHECKS + 1))
if [ -z "$DECLARED" ]; then
  fail "读不到 alarm_pipeline.py / deploy_auth.py 的声明值——无法比对线上配置"
  DECLARED_TOPIC_NAME=""
else
  PROD_ALARM="$(printf '%s' "$DECLARED" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["alarm_name"])')"
  DECLARED_TOPIC_NAME="$(printf '%s' "$DECLARED" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["topic_name"])')"
  LIVE="$(aws cloudwatch describe-alarms --region "$REGION" \
            --alarm-names "$PROD_ALARM" --output json 2>/dev/null || echo '')"
  # **aws CLI 在 API 错误时也可能 exit 0**（实测）——所以必须校验输出是合法 JSON
  if ! printf '%s' "$LIVE" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    fail "无法读取线上 alarm（输出非合法 JSON，可能是凭证/网络问题）"
  else
    # $LIVE 作为 argv 传入复用——**不要在 python 里重新调 aws CLI**：那次重查
    # 不带 --region，会打到默认 region（与 config.ini 不同时报 0 个 alarm 的
    # 假失败，或比较到另一区域的同名 alarm）。
    # （不用 stdin 传：heredoc 已占用 stdin。）
    if python3 - "$DECLARED" "$LIVE" "$ACCOUNT_ID" <<'PY'
import json, sys
declared = json.loads(sys.argv[1])
live = json.loads(sys.argv[2])["MetricAlarms"]
account_id = sys.argv[3]
if len(live) != 1:
    print(f"  线上 alarm 数量为 {len(live)}，期望 1")
    sys.exit(1)
a = live[0]
bad = []
for k, v in declared["alarm"].items():
    got = a.get(k)
    if k in ("Threshold", "Period", "EvaluationPeriods"):
        ok = got is not None and float(got) == float(v)
    else:
        ok = got == v
    if not ok:
        bad.append(f"{k}: 线上={got!r} 声明={v!r}")
# **AlarmActions/OKActions 必须等于声明的 topic ARN**——只验"两者相等且非空"
# 会漏掉"同时漂移到另一个 topic"的假绿：actions 指向 topic-B，而下面的订阅
# 检查在查声明的 topic-A，两段各自 PASS 但互不相干。
#
# ARN 从 **alarm 自己的 ARN** 取 region/account（而不是拼 config.ini 的值）：
# 这样比对的是"这个 alarm 所在账号里那个声明名字的 topic"，跨账号凭证错配时
# 不会因为账号号码来源不同而假绿。同时核对它确实是本平台账号。
region, acct = a["AlarmArn"].split(":")[3], a["AlarmArn"].split(":")[4]
if acct != account_id:
    bad.append(f"alarm 所在账号 {acct} != config.ini 的 {account_id}"
               "——比对的可能不是本平台的资源")
expected_topic = f"arn:aws:sns:{region}:{acct}:{declared['topic_name']}"
if a.get("AlarmActions") != [expected_topic]:
    bad.append(f"AlarmActions={a.get('AlarmActions')} 期望=[{expected_topic}]")
if a.get("OKActions") != [expected_topic]:
    bad.append(f"OKActions={a.get('OKActions')} 期望=[{expected_topic}]")
if bad:
    print("  线上 alarm 与声明值漂移：")
    for b in bad:
        print(f"          {b}")
    sys.exit(1)
print("PASS  线上 alarm 配置 == alarm_pipeline.py 声明值"
      "（含双语描述、Alarm/OK actions == 声明 topic）")
PY
    then :; else fail "线上 alarm 与 alarm_pipeline.py 声明值不一致（见上面明细）"; fi
  fi
fi

echo
echo "── ①c 声明收件人的 SNS 订阅必须已确认 ────────────"
# 只查"存在任意 confirmed email"有假绿：告警邮箱从 old@ 换成 new@ 后，
# old 仍 confirmed、new 还在 PendingConfirmation——"存在 1 个 confirmed"
# 照样 PASS，而声明的新收件人收不到任何通知。必须绑定 Endpoint == 声明值。
DECLARED_EMAIL="$(python3 - "$CFG" <<'PY' || echo ''
import configparser, os, sys
env = os.environ.get("SB_ALERT_EMAIL", "").strip()
if env:
    print(env)
    sys.exit(0)
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1])
raw = c["Alerting"].get("email", "") if c.has_section("Alerting") else ""
print(raw.split("#")[0].split(";")[0].strip())
PY
)"
# **topic ARN 自己拼，不调 `aws sns create-topic`**：那个调用虽然对已存在的
# topic 是幂等的，但在 topic 不存在时会**真的建一个**——验收脚本必须只读，
# 否则"topic 缺失"这个应当 FAIL 的状态会被脚本自己顺手修好并判 PASS。
if [ -n "$DECLARED_TOPIC_NAME" ]; then
  DECLARED_TOPIC_ARN="arn:aws:sns:${REGION}:${ACCOUNT_ID}:${DECLARED_TOPIC_NAME}"
else
  DECLARED_TOPIC_ARN=""
fi
CHECKS=$((CHECKS + 1))
if [ -z "$DECLARED_EMAIL" ]; then
  fail "无法读取声明的告警邮箱（config.ini [Alerting] email 或 SB_ALERT_EMAIL）"
elif [ -z "$DECLARED_TOPIC_ARN" ]; then
  fail "无法解析声明的 SNS topic ARN（上一段没读到 topic_name）"
else
  # 分页完整：list-subscriptions-by-topic 单页 100 条，aws cli 不加
  # --no-paginate 时自动翻页，但 --query 的 length() 只作用于合并结果——
  # 用 json 输出交给 python 数，顺带把"状态"算清楚。
  SUBS_JSON="$(aws sns list-subscriptions-by-topic --region "$REGION" \
                 --topic-arn "$DECLARED_TOPIC_ARN" --output json 2>/dev/null || echo '')"
  # email 与订阅 JSON **都走 argv**，两个各有理由：
  # ① email 不做 shell 插值进 python 源码——邮箱里的引号或换行会把脚本拼坏；
  # ② 订阅 JSON 不能用管道喂 stdin——**heredoc 已经占用了 stdin**（python 的
  #    脚本正是从它读的），管道进来的内容永远不会被 json.load 看到，于是这项
  #    检查恒为 error。这是本文件里第二次踩同一个坑，写法统一成 argv。
  SUB_STATE="$(python3 - "$DECLARED_EMAIL" "$SUBS_JSON" <<'PY' 2>/dev/null || echo error
import json, sys
declared = sys.argv[1].strip()
subs = json.loads(sys.argv[2]).get("Subscriptions", [])
mine = [s for s in subs
        if s.get("Protocol") == "email" and s.get("Endpoint") == declared]
if any(s.get("SubscriptionArn", "").startswith("arn:") for s in mine):
    print("confirmed")
elif mine:
    print("pending")
else:
    print("absent")
PY
)"
  case "$SUB_STATE" in
    confirmed)
      echo "PASS  声明收件人（[Alerting] email）在声明 topic 下的订阅已确认" ;;
    pending)
      fail "声明收件人的订阅还在 PendingConfirmation——必须点确认链接"
      echo "      （其他历史收件人是否 confirmed 与本项无关：换邮箱后旧的"
      echo "       仍 confirmed 会造成假绿，所以只认声明的那一个）" ;;
    absent)
      fail "声明 topic 下没有声明收件人的订阅——先跑 deploy_auth.py" ;;
    *)
      fail "订阅状态查询失败（凭证/网络/topic 不存在），不能当作通过" ;;
  esac
fi

echo
echo "── ② 触发一次真实 invalid_grant ──────────────────"
echo "先在浏览器正常走到登录页，从 devtools 复制 __Host-sb_pkce 的值与 state。"
echo "（用 read -rs 读入，不回显、不进 argv、不进 shell history）"
printf '粘贴 __Host-sb_pkce 值: '
read -rs PKCE; echo
printf '粘贴 state 值: '
read -rs STATE; echo
[ -n "$PKCE" ] && [ -n "$STATE" ] || { echo "两个值都不能为空"; exit 1; }

# **必须写成 Netscape cookie jar**：curl 的 `--cookie <文件>` 按 jar 解析，
# 单行 `name=value` 不是合法 jar —— 实测服务端收到的 Cookie 头是 None，于是
# callback 在 _read_pkce_cookie() 处直接返回"登录状态已过期"400，**根本不会
# 调用 Cognito token endpoint**，metric 不动、alarm 不变，却因为状态码恰好也是
# 400 而看起来通过了。
#
# secure 字段（第 4 列）**必须是 TRUE**：`__Host-` 前缀的 cookie curl 只在
# secure 且 HTTPS 时才发送。实测 FALSE 时同样发不出来（这一点比 jar 格式本身
# 更容易漏——格式对了但标记错了，症状与格式错完全相同）。
{
  printf '# Netscape HTTP Cookie File\n'
  printf 'auth.%s\tFALSE\t/\tTRUE\t0\t__Host-sb_pkce\t%s\n' "$BASE_DOMAIN" "$PKCE"
} > "$COOKIE_JAR"
unset PKCE

# **先记下起点时刻**，日志检索只看这之后的事件（Codex 复审 2026-08-07）：
# 原来固定搜"最近 5 分钟"，于是同一窗口内**别人**留下的一条 invalid_grant
# 就能让检查通过——而本次 cookie 可能已过期、根本没走到 token 交换分支。
# 那正是这段检查要排除的情况，用旧事件满足它等于没检查。
# 扣 5 秒容忍本机与 Lambda 的时钟偏差（日志时间戳由 Lambda 侧生成）；
# 窗口从 300 秒收到约 5 秒，误判概率随之下降两个数量级。
START_MS="$(python3 -c 'import time;print(int((time.time()-5)*1000))')"

# code 给垃圾值 → Cognito 返回 invalid_grant → auth 打结构化日志
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  --cookie-jar /dev/null --cookie "$COOKIE_JAR" \
  --get --data-urlencode "code=GARBAGE-PROBE" --data-urlencode "state=$STATE" \
  "https://auth.$BASE_DOMAIN/callback")"
unset STATE
echo "  /callback 返回 $CODE"
CHECKS=$((CHECKS + 1))
[ "$CODE" = "400" ] || fail "期望 400（不是 502），实际 $CODE"

# 关键判读：400 有两种来源，必须区分。cookie 没送到时是"登录状态已过期"分支，
# 那条路径不碰 Cognito，也就不会有 token_exchange_invalid_grant 日志。
echo "  等日志落盘后确认走的是 token 交换分支（而非 cookie 缺失分支）…"
sleep 20
CHECKS=$((CHECKS + 1))
if aws logs filter-log-events --region "$REGION" --log-group-name "$LOG_GROUP" \
     --start-time "$START_MS" \
     --filter-pattern '{ $.event = "token_exchange_invalid_grant" }' \
     --query 'events[-1].message' --output text 2>/dev/null | grep -q invalid_grant; then
  echo "PASS  本次请求之后出现 token_exchange_invalid_grant"
  echo "      （证明真的走到了 Cognito 换 token，不是 cookie 缺失分支）"
else
  fail "本次请求之后没有 token_exchange_invalid_grant 日志 —— cookie 可能没送到，"
  echo "      当前测到的是 cookie 缺失分支的 400，不是目标逻辑。"
  echo "      检查 cookie 值是否已过期（Max-Age=300）或 jar 格式/secure 标记。"
fi

echo
echo "── ③ 让 alarm 真的进 ALARM ───────────────────────"
# 正式阈值是 10/2 周期，一条合成事件永远达不到——临时建一个 1/1 周期的探针
# alarm（不改正式那个，避免验证期间正式告警失灵）。
ALARM_ARGS=(--region "$REGION" --alarm-name "$PROBE_ALARM"
  --alarm-description "$PROBE_DESCRIPTION"
  --namespace SiteBuilder --metric-name AuthInvalidGrant
  --statistic Sum --period 60 --evaluation-periods 1
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold
  --treat-missing-data notBreaching)
if [ -n "${SNS_TOPIC_ARN:-}" ]; then
  ALARM_ARGS+=(--alarm-actions "$SNS_TOPIC_ARN")
  echo "  探针 alarm 会通知 $SNS_TOPIC_ARN"
else
  echo "  ⚠️  未给 SNS_TOPIC_ARN：只验证状态机，不验证通知送达。"
  echo "     topic 没有订阅（或订阅未确认）时 alarm 照样进 ALARM 而无人知情，"
  echo "     这正是「告警形同虚设」最常见的形态——正式验收请带上这个变量。"
fi
# **名字未被占用要在创建前查**（Codex 复审 2026-08-07）。
# 原来靠"创建后第一次 describe 必须是 INSUFFICIENT_DATA"来发现名字撞车，
# 但那不是 AWS 的保证：PutMetricAlarm 只承诺新 alarm **先**置
# INSUFFICIENT_DATA，随后立即评估并转到相应状态。数据点已经存在（上一步刚造）
# 时评估可能快于我们的 describe，于是一条**成功**的链路被误判成"撞上残留
# alarm，结果不可信"。改成创建前查存在性：这是确定性的。
EXISTS="$(aws cloudwatch describe-alarms --region "$REGION" \
  --alarm-names "$PROBE_ALARM" --query 'MetricAlarms[0] != null' \
  --output text 2>/dev/null || echo Unknown)"
if [ "$EXISTS" != "False" ]; then
  echo "探针 alarm 名已被占用或状态未知（present=${EXISTS:-空}）：$PROBE_ALARM"
  echo "本轮不创建、不改动任何 alarm——换一次运行（名字带随机后缀）或手工清理。"
  exit 1
fi
aws cloudwatch put-metric-alarm "${ALARM_ARGS[@]}"

# 初始状态仅打印，**不作断言**（理由见上）：ALARM 在这里是合法的中间结果。
INIT_STATE="$(aws cloudwatch describe-alarms --region "$REGION" \
  --alarm-names "$PROBE_ALARM" --query 'MetricAlarms[0].StateValue' \
  --output text 2>/dev/null || echo "?")"
echo "  初始状态 ${INIT_STATE}（INSUFFICIENT_DATA 或 ALARM 都正常——"
echo "   AWS 只保证先置 INSUFFICIENT_DATA，随后立即评估，我们可能只看到评估后的值）"

echo "  轮询状态（最多 3 分钟）…"
STATE_VAL=""
for _ in $(seq 1 12); do
  STATE_VAL="$(aws cloudwatch describe-alarms --region "$REGION" \
    --alarm-names "$PROBE_ALARM" --query 'MetricAlarms[0].StateValue' \
    --output text 2>/dev/null || echo "?")"
  echo "    StateValue=$STATE_VAL"
  [ "$STATE_VAL" = "ALARM" ] && break
  sleep 15
done
CHECKS=$((CHECKS + 1))
if [ "$STATE_VAL" = "ALARM" ]; then
  echo "PASS  alarm 进入 ALARM"
  [ -n "${SNS_TOPIC_ARN:-}" ] && \
    echo "      → 现在去 SNS 订阅端（邮箱/webhook）确认**真的收到通知**；"
  [ -n "${SNS_TOPIC_ARN:-}" ] && \
    echo "        只看 StateValue 证明不了有人被通知到。"
else
  fail "alarm 未进入 ALARM（最终 $STATE_VAL）"
  echo "      metric filter 的 pattern 与日志实际字段不匹配是最常见原因："
  echo "      aws logs filter-log-events --log-group-name $LOG_GROUP \\"
  echo "        --filter-pattern '{ \$.event = \"token_exchange_invalid_grant\" }'"
fi
