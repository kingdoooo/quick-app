#!/usr/bin/env bash
# 路由层冒烟：无 auth 静态路由 / 有 auth 302 / 未知子域 404 / 路由更新即时生效。
#
# 会写真实测试数据（S3 对象 + 路由表 item），跑完自动清理。
#
# 三条纪律（都是本项目栽过的坑，改动前先读）：
#
# ① **断言失败必须让脚本退出**。原版每条断言都是
#      test "$(curl ...)" = "hello-router" && echo "PASS: static route"
#    `set -e` 对 `&&` 链左侧的失败**不生效**——断言不成立时只是不打印 PASS，
#    退出码仍是 0，整个冒烟"通过"。现在统一走 check()，失败即计入并最终非零退出。
#
# ② **只删本次创建的资源**。所有资源名带一次性随机后缀 ${SUF}，清理时逐个
#    指名删除；禁止 scan 找目标或 `s3 rm --recursive` 整前缀——试点环境里
#    有长期存在的真站点，批量删会连它们一起清掉。
#
# ③ **清理要读回核对**，且 trap 覆盖 EXIT/INT/TERM（Ctrl-C 也要清）。
#    `delete-item` 返回 0 不等于真删掉了。
#
# 用法：
#     bash site-builder/scripts/smoke_router.sh
#     bash site-builder/scripts/smoke_router.sh --keep-on-failure   # 失败时保留现场
set -euo pipefail

KEEP_ON_FAILURE=0
for arg in "$@"; do
  case "$arg" in
    --keep-on-failure) KEEP_ON_FAILURE=1 ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

CFG() { python3 -c "
import configparser,sys
c=configparser.ConfigParser(interpolation=None)
c.read('site-builder/config.ini')
v=c[sys.argv[1]][sys.argv[2]].split('#')[0].split(';')[0].strip()
print(v)" "$1" "$2"; }

BASE_DOMAIN=$(CFG Platform base_domain)
TABLE=$(CFG Platform routing_table)
ACCOUNT=$(CFG Platform account_id)
BUCKET=$(CFG Deployer frontend_bucket)
BUCKET=${BUCKET//\{account_id\}/$ACCOUNT}

# 一次性后缀：两次运行互不干扰，且清理时能判定"哪些是本次的"
SUF=$(python3 -c "import secrets;print(secrets.token_hex(4))")
SUB_A="app-smk${SUF}"
SUB_B="app-smk${SUF}b"
SUB_AUTH="app-smkauth${SUF}"
PREFIX_A="sites/smk${SUF}/job-smk${SUF}"
PREFIX_B="sites/smk${SUF}b/job-smk${SUF}b"

FAILURES=0
CHECKS=0
# 全绿运行的实际断言条数。**不是估的**：低于它说明脚本中途崩了或分支被跳过，
# 而"跑了 3 项全过"读起来跟"6 项全过"一样像成功。
MIN_CHECKS=6

check() {   # check <描述> <实际> <期望>
  CHECKS=$((CHECKS + 1))
  if [ "$2" = "$3" ]; then
    echo "PASS  $1"
  else
    echo "FAIL  $1（期望 $3，实际 $2）"
    FAILURES=$((FAILURES + 1))
  fi
}

check_prefix() {   # check_prefix <描述> <实际> <期望前缀>
  CHECKS=$((CHECKS + 1))
  case "$2" in
    "$3"*) echo "PASS  $1" ;;
    *) echo "FAIL  $1（期望以 $3 开头，实际 $2）"; FAILURES=$((FAILURES + 1)) ;;
  esac
}

cleanup() {
  local rc=$?
  if [ "$KEEP_ON_FAILURE" = "1" ] && { [ "$rc" -ne 0 ] || [ "$FAILURES" -gt 0 ]; }; then
    echo
    echo "⚠️  --keep-on-failure：保留本次资源以便排查（后缀 ${SUF}）"
    echo "    路由: $SUB_A $SUB_B $SUB_AUTH"
    echo "    对象: s3://$BUCKET/$PREFIX_A/ 与 /$PREFIX_B/"
    return $rc
  fi
  echo
  echo "── 清理（只删后缀 $SUF 的资源）──"
  # 逐个指名删除。**不 scan、不 --recursive**（见文件头纪律 ②）
  for sub in "$SUB_A" "$SUB_B" "$SUB_AUTH"; do
    aws dynamodb delete-item --table-name "$TABLE" \
      --key "{\"subdomain\":{\"S\":\"$sub\"}}" >/dev/null 2>&1 || true
  done
  aws s3 rm "s3://$BUCKET/$PREFIX_A/index.html" >/dev/null 2>&1 || true
  aws s3 rm "s3://$BUCKET/$PREFIX_B/index.html" >/dev/null 2>&1 || true

  # 强一致读回核对：delete-item 返回 0 不等于真删了
  local leaked=0
  for sub in "$SUB_A" "$SUB_B" "$SUB_AUTH"; do
    local got
    got=$(aws dynamodb get-item --table-name "$TABLE" --consistent-read \
            --key "{\"subdomain\":{\"S\":\"$sub\"}}" \
            --query 'Item.subdomain.S' --output text 2>/dev/null || echo "None")
    if [ "$got" != "None" ] && [ -n "$got" ]; then
      echo "⚠️  路由 $sub 仍然存在——请手工删除"
      leaked=1
    fi
  done
  if [ "$leaked" = "1" ]; then
    echo "清理未完成：残留资源会干扰下一次运行"
    return 1
  fi
  echo "清理完成并已读回核对"
  return $rc
}
trap cleanup EXIT INT TERM

echo "── 准备探针（后缀 ${SUF}）──"
printf 'hello-router\n' > "/tmp/smk-$SUF-a.html"
printf 'hello-other\n' > "/tmp/smk-$SUF-b.html"
aws s3 cp "/tmp/smk-$SUF-a.html" "s3://$BUCKET/$PREFIX_A/index.html" >/dev/null
aws s3 cp "/tmp/smk-$SUF-b.html" "s3://$BUCKET/$PREFIX_B/index.html" >/dev/null
rm -f "/tmp/smk-$SUF-a.html" "/tmp/smk-$SUF-b.html"

put_route() {   # put_route <subdomain> <site_id> <static_prefix> <require_auth>
  aws dynamodb put-item --table-name "$TABLE" --item "{
    \"subdomain\":{\"S\":\"$1\"},\"site_id\":{\"S\":\"$2\"},
    \"route_mode\":{\"S\":\"split\"},\"static_prefix\":{\"S\":\"$3\"},
    \"api_target\":{\"S\":\"\"},\"require_auth\":{\"BOOL\":$4},
    \"allowed_users\":{\"S\":\"org\"},\"owner\":{\"S\":\"smoke@test\"}}" >/dev/null
}
put_route "$SUB_A" "smk$SUF" "$PREFIX_A" false
put_route "$SUB_B" "smk${SUF}b" "$PREFIX_B" false
put_route "$SUB_AUTH" "smk$SUF" "$PREFIX_A" true

echo "等 Edge 路由缓存过期（65s）"
sleep 65

echo
echo "── 断言 ──"
check "静态路由返回本站内容" \
  "$(curl -s "https://$SUB_A.$BASE_DOMAIN/")" "hello-router"
# 不同子域同路径内容不串（CloudFront 禁缓存的行为验证）
check "不同子域内容不串（无跨站缓存）" \
  "$(curl -s "https://$SUB_B.$BASE_DOMAIN/")" "hello-other"
check_prefix "require_auth 站点未登录 302 到登录端点" \
  "$(curl -s -o /dev/null -w '%{redirect_url}' "https://$SUB_AUTH.$BASE_DOMAIN/")" \
  "https://auth.$BASE_DOMAIN/login"
# auth 子域全路径路由到认证 Lambda（api-only 模式，从公网验证而非直连 Function URL）
ALOC=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "https://auth.$BASE_DOMAIN/login?redirect=https://$SUB_A.$BASE_DOMAIN/")
CHECKS=$((CHECKS + 1))
case "$ALOC" in
  *"/oauth2/authorize"*) echo "PASS  auth 子域 api-only 路由到 Hosted UI" ;;
  *) echo "FAIL  auth 子域路由（实际 ${ALOC}）"; FAILURES=$((FAILURES + 1)) ;;
esac
check "未知子域 404" \
  "$(curl -s -o /dev/null -w '%{http_code}' "https://app-nx$SUF.$BASE_DOMAIN/")" "404"

# 路由更新即时生效（无缓存）：切 static_prefix 后应能看到新内容
aws dynamodb update-item --table-name "$TABLE" \
  --key "{\"subdomain\":{\"S\":\"$SUB_A\"}}" \
  --update-expression "SET static_prefix = :p" \
  --expression-attribute-values "{\":p\":{\"S\":\"$PREFIX_B\"}}" >/dev/null
sleep 65
check "路由更新 65 秒内可见（无缓存）" \
  "$(curl -s "https://$SUB_A.$BASE_DOMAIN/")" "hello-other"

echo
if [ "$CHECKS" -lt "$MIN_CHECKS" ]; then
  echo "结果：只跑了 $CHECKS 项（预期 >= ${MIN_CHECKS}）—— 冒烟**未完成**，状态不可信"
  exit 1
fi
if [ "$FAILURES" -gt 0 ]; then
  echo "结果：$CHECKS 项中 $FAILURES 项失败"
  exit 1
fi
echo "结果：$CHECKS/$CHECKS 项通过"
