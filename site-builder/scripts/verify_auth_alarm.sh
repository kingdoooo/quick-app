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
LOG_GROUP="/aws/lambda/site-auth-service"
# 探针 alarm 名带随机后缀。固定名有两个坑（Codex 审查 2026-08-06 P1）：
# ① PutMetricAlarm 更新现有 alarm 时**保留当前状态**，上次残留的若是 ALARM，
#    本轮第一次查询就 PASS —— 而本轮的事件可能根本没触发过它；
# ② 两个人同时跑会互相覆盖配置、并在清理时删掉对方的 alarm。
PROBE_ALARM="site-builder-auth-invalid-grant-probe-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')"

COOKIE_JAR="$(mktemp -t sbjar.XXXXXX)"
chmod 600 "$COOKIE_JAR"
CLEANED=0
FAILURES=0

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
  if aws cloudwatch describe-alarms --region "$REGION" \
       --alarm-names "$PROBE_ALARM" --query 'MetricAlarms[0]' \
       --output text 2>/dev/null | grep -qv '^None$'; then
    echo "⚠️  探针 alarm 仍存在：$PROBE_ALARM —— 手工删除"
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

echo "── ① 正式配置核对 ────────────────────────────────"
# **逐字段核对，不只看"存在"**：原来只取 Threshold/EvaluationPeriods/
# AlarmActions[0] 且不比对期望值，于是正式 alarm 即使监控的是拼错的
# metric name（永远不会有数据点），只要"存在一个 action"就 PASS，而临时
# probe alarm 用的是硬编码的正确 metric，照样能进 ALARM —— 整套验收通过，
# 线上告警其实是死的（Codex 审查 2026-08-06 P1）。
# 用 Python 做比对：多字段结构化对比 + 精确退出码，shell 里做这个已经踩过
# 一轮陷阱（见 check_permissions_state.py 的 docstring）。
if python3 - "$REGION" "$LOG_GROUP" <<'PYCHK'
import json, subprocess, sys
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
    if a.get("TreatMissingData") != "notBreaching":
        bad.append(f"TreatMissingData={a.get('TreatMissingData')!r}，"
                   "低流量环境应为 notBreaching，否则长期 INSUFFICIENT_DATA")
    if not [x for x in bad if "正式 alarm" in x]:
        print(f"PASS  正式 alarm：{a['Namespace']}/{a['MetricName']} "
              f"{a['Statistic']} 阈值 {a.get('Threshold')} × "
              f"{a.get('EvaluationPeriods')} 周期 → {len(a['AlarmActions'])} 个动作")
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

# code 给垃圾值 → Cognito 返回 invalid_grant → auth 打结构化日志
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  --cookie-jar /dev/null --cookie "$COOKIE_JAR" \
  --get --data-urlencode "code=GARBAGE-PROBE" --data-urlencode "state=$STATE" \
  "https://auth.$BASE_DOMAIN/callback")"
unset STATE
echo "  /callback 返回 $CODE"
[ "$CODE" = "400" ] || fail "期望 400（不是 502），实际 $CODE"

# 关键判读：400 有两种来源，必须区分。cookie 没送到时是"登录状态已过期"分支，
# 那条路径不碰 Cognito，也就不会有 token_exchange_invalid_grant 日志。
echo "  等日志落盘后确认走的是 token 交换分支（而非 cookie 缺失分支）…"
sleep 20
if aws logs filter-log-events --region "$REGION" --log-group-name "$LOG_GROUP" \
     --start-time "$(python3 -c 'import time;print(int((time.time()-300)*1000))')" \
     --filter-pattern '{ $.event = "token_exchange_invalid_grant" }' \
     --query 'events[-1].message' --output text 2>/dev/null | grep -q invalid_grant; then
  echo "PASS  日志里有 token_exchange_invalid_grant（证明真的走到了 Cognito 换 token）"
else
  fail "没有 token_exchange_invalid_grant 日志 —— cookie 可能没送到，"
  echo "      当前测到的是 cookie 缺失分支的 400，不是目标逻辑。"
  echo "      检查 cookie 值是否已过期（Max-Age=300）或 jar 格式/secure 标记。"
fi

echo
echo "── ③ 让 alarm 真的进 ALARM ───────────────────────"
# 正式阈值是 10/2 周期，一条合成事件永远达不到——临时建一个 1/1 周期的探针
# alarm（不改正式那个，避免验证期间正式告警失灵）。
ALARM_ARGS=(--region "$REGION" --alarm-name "$PROBE_ALARM"
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
aws cloudwatch put-metric-alarm "${ALARM_ARGS[@]}"

# 新建的 alarm 初始必须是 INSUFFICIENT_DATA。若一上来就是 ALARM，说明这个名字
# 撞上了残留 alarm（随机后缀已极大降低概率，但仍要断言而不是假设）。
INIT_STATE="$(aws cloudwatch describe-alarms --region "$REGION" \
  --alarm-names "$PROBE_ALARM" --query 'MetricAlarms[0].StateValue' \
  --output text 2>/dev/null || echo "?")"
if [ "$INIT_STATE" = "ALARM" ]; then
  fail "探针 alarm 刚建好就是 ALARM —— 撞上了残留 alarm，本轮结果不可信"
fi
echo "  初始状态 $INIT_STATE（期望 INSUFFICIENT_DATA）"

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
