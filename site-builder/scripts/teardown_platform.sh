#!/usr/bin/env bash
# 把平台从一个账号里拆掉。**幂等、fail-closed、可分阶段。**
#
# 为什么这是一个脚本而不是 DEPLOY.md 里的一段 Markdown：拆除是**程序**，不是散文。
# 它此前作为围栏块存在时连续三轮复审各发现一个 P1，根因都是同一类——
# "存在性判断"被写成"命令失败就当不存在"，于是 AccessDenied / 限流被当成 ABSENT，
# 脚本继续往下做破坏性操作并最终退 0。散文形态既没法测，也没法保证"我写下的 = 我跑过的"。
#
# ── 核心不变量（本文件存在的唯一理由）─────────────────────────────────────
#   每一步在动手之前先探测，结果只有三种：PRESENT / ABSENT / UNKNOWN。
#   **UNKNOWN 一律 hard-stop**（非零退出），并且**不执行任何后续破坏性调用**。
#   "命令失败" ≠ "东西不存在"：只有服务明确说 NotFound 才算 ABSENT。
#   这条不变量由 deployer/tests/test_teardown_platform.py 按阶段注入故障来断言，
#   断言的形态是"注入点之后日志里没有任何破坏性调用"，不是"某个例子的输出对不对"。
# ────────────────────────────────────────────────────────────────────────
#
# 它**不做**的三件事（都需要人的判断，留在 DEPLOY.md 里）：
#   · 站点下线（要 MCP / owner 判断、要不要 purge_data）——本脚本只**核对**站点已清空，
#     没清空就拒绝往下走；
#   · Route53 记录（要 zone id 与记录内容）；
#   · CDKToolkit 栈与它的 assets 桶（"确认不再往这个账号部署了"才做）。
#
# 用法：
#   site-builder/scripts/teardown_platform.sh --dry-run            # 只打印会做什么
#   site-builder/scripts/teardown_platform.sh --yes                # 全部阶段
#   site-builder/scripts/teardown_platform.sh --yes --stage dsql   # 只跑一个阶段
#   阶段顺序：preflight → scripts → dsql → stacks → orphans
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SB="$(dirname "$HERE")"
ROOT="$(dirname "$SB")"

DRY_RUN=0
ASSUME_YES=0
# 轮询参数。默认 60 × 10s = 10 分钟（生产值）。测试把它们压小以便验超时分支——
# **不要在真机上调小**：DSQL 删除本来就要几分钟。
POLL_TRIES="${TEARDOWN_POLL_TRIES:-60}"
POLL_SLEEP="${TEARDOWN_POLL_SLEEP:-10}"
ONLY_STAGE=""
STAGES=(preflight scripts dsql stacks orphans)

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    --stage)   ONLY_STAGE="${2:?--stage 要一个阶段名}"; shift ;;
    -h|--help) sed -n '1,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  {
  printf '\n拒绝继续：%s\n' "$*" >&2
  printf '本脚本幂等——解决上面的原因之后重跑即可，已经删掉的不会重复删。\n' >&2
  exit 1
}

# ---------------------------------------------------------------- 配置读取
cfg() {   # cfg <文件> <段> <键>；读不到返回空
  python3 - "$1" "$2" "$3" <<'PY'
import configparser, sys
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1], encoding="utf-8")
print((c.get(sys.argv[2], sys.argv[3], fallback="") or "").split("#")[0].strip())
PY
}

SB_CFG="$SB/config.ini"
RT_CFG="$ROOT/router/config.ini"
[ -f "$SB_CFG" ] || die "找不到 $SB_CFG —— 拆除同样以 config.ini 为唯一取值来源"

ACCOUNT="$(cfg "$SB_CFG" Platform account_id)"
REGION="$(cfg "$SB_CFG" Platform region)"
[ -n "$ACCOUNT" ] && [ -n "$REGION" ] || die "config.ini 里 [Platform] account_id / region 为空"
ROUTER_STACK="$(cfg "$RT_CFG" CDK stack_name)"; ROUTER_STACK="${ROUTER_STACK:-ApplicationWebRouterStack}"
DEPLOYER_STACK="SiteDeployerStack"

# ---------------------------------------------------------------- 三值探测
# **这里是整个脚本的安全核心。** 只有服务明确说的 NotFound 才算 ABSENT；
# 其余任何失败（AccessDenied、限流、参数错误、网络）都是 UNKNOWN，而 UNKNOWN 会 hard-stop。
_is_absent_err() {
  case "$1" in
    *ResourceNotFoundException*|*ResourceNotFound*|*NotFoundException*|*NoSuchEntity*|\
    *NoSuchBucket*|*ParameterNotFound*|*RepositoryNotFoundException*|*ClusterNotFound*|\
    *UserPoolTaggingException*|*"does not exist"*|*"Function not found"*|*"Unable to find"*)
      return 0 ;;
  esac
  return 1
}

# probe <描述> <命令...> —— 往 stdout 打 PRESENT/ABSENT/UNKNOWN，报文进 stderr。
# **本函数自己从不 die**（它跑在 $( ) 子 shell 里，die 只会杀掉子 shell）。
probe() {
  local desc="$1"; shift
  local err rc=0
  err="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then echo PRESENT; return 0; fi
  if _is_absent_err "$err"; then echo ABSENT; return 0; fi
  printf '  探测 %s 失败，而且**不是** NotFound：\n%s\n' "$desc" "$err" >&2
  echo UNKNOWN
  return 0
}

# need_delete <描述> <探测命令...> —— 0=要删；1=跳过；UNKNOWN 直接 hard-stop。
need_delete() {
  local desc="$1"; shift
  local state; state="$(probe "$desc" "$@")"
  case "$state" in
    PRESENT) return 0 ;;
    ABSENT)  log "  跳过（不存在）: $desc"; return 1 ;;
    *)       die "「${desc}」的状态未知（见上面的报文）。UNKNOWN 不等于 ABSENT——
在状态未知的账号上继续跑破坏性步骤，可能把该删的留下、也可能对错的目标动手。
先解决凭据 / 限流，再重跑。" ;;
  esac
}

run() {   # 真正的破坏性调用都经这里；--dry-run 只打印
  if [ "$DRY_RUN" -eq 1 ]; then log "  [dry-run] $*"; return 0; fi
  log "  $*"
  "$@" >/dev/null
}

confirm() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ "$ASSUME_YES" -eq 1 ] && return 0
  die "这是破坏性操作。确认要拆掉账号 $ACCOUNT / $REGION 的平台后加 --yes 重跑（或先 --dry-run 看一遍）。"
}

want_stage() { [ -z "$ONLY_STAGE" ] || [ "$ONLY_STAGE" = "$1" ]; }

# ============================================================== preflight
stage_preflight() {
  step "preflight：凭据、账号、以及"站点是否已经清空""
  local live
  live="$(aws sts get-caller-identity --query Account --output text)"
  [ "$live" = "$ACCOUNT" ] || die "凭据指向账号 ${live}，而 config.ini 写的是 ${ACCOUNT}。
拆错账号是不可逆的——先切凭据或改 config。"
  log "  账号一致: $ACCOUNT / $REGION"

  # 站点资源（per-site 角色 / 数据表 / DSQL schema / 前端对象）**都不在任何栈里**，
  # 栈删了只会变孤儿。所以这里 fail-closed：sites 表里还有非 DELETED 的行就拒绝往下走。
  local sites_state
  sites_state="$(probe "sites 表" aws dynamodb describe-table --table-name site-sites --region "$REGION")"
  case "$sites_state" in
    UNKNOWN) die "读不到 sites 表的状态（见报文）。它决定了"站点是否已清空"，读不到就不能往下走。" ;;
    ABSENT)  log "  sites 表已不存在 ⇒ 站点侧无从核对，按已清理处理" ;;
    PRESENT)
      local remaining
      remaining="$(aws dynamodb scan --table-name site-sites --region "$REGION" \
        --filter-expression '#s <> :d' \
        --expression-attribute-names '{"#s":"status"}' \
        --expression-attribute-values '{":d":{"S":"DELETED"}}' \
        --query 'Items[].site_id.S' --output text)"
      if [ -n "$remaining" ] && [ "$remaining" != "None" ]; then
        die "还有站点没下线：$remaining
先按 DEPLOY.md「把平台从账号里拆掉」第 ① 步把它们 undeploy（**带 purge_data**），
再回来跑本脚本。站点的 IAM 角色 / 数据表 / DSQL schema 都不在栈里，
直接删栈只会把它们变成孤儿。" ;
      fi
      log "  站点侧已清空（sites 表里没有非 DELETED 的行）" ;;
  esac
}

# ================================================================ scripts
stage_scripts() {
  step "scripts：脚本建的平台件（一个都不会跟着栈走）"
  confirm

  # MCP runtime：id 从 [MCP] endpoint_url 里那个 URL-encoded ARN 取
  local rt_id
  rt_id="$(python3 - "$SB_CFG" <<'PY'
import configparser, sys, urllib.parse
c = configparser.ConfigParser(interpolation=None); c.read(sys.argv[1], encoding="utf-8")
url = c.get("MCP", "endpoint_url", fallback="")
arn = urllib.parse.unquote(url.split("/runtimes/", 1)[1].split("/invocations", 1)[0]) if "/runtimes/" in url else ""
print(arn.rsplit("/", 1)[-1] if arn else "")
PY
)"
  if [ -n "$rt_id" ]; then
    if need_delete "AgentCore runtime $rt_id" \
        aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id "$rt_id" --region "$REGION"; then
      run aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id "$rt_id" --region "$REGION"
    fi
  else
    log "  跳过 AgentCore runtime（config.ini 的 [MCP] endpoint_url 为空）"
  fi

  if need_delete "ECR 仓库 site-builder-mcp" \
      aws ecr describe-repositories --repository-names site-builder-mcp --region "$REGION"; then
    run aws ecr delete-repository --repository-name site-builder-mcp --region "$REGION" --force
  fi

  # Lambda。site-key-proxy 无条件列出：没启用 ⑤c 时它 ABSENT。
  # site-auth-pre-token 是 Cognito 触发器、**没有 Function URL** ⇒ 那条单独探测。
  local fn
  for fn in site-panel site-auth-service site-auth-pre-token site-key-proxy; do
    if need_delete "Function URL($fn)" \
        aws lambda get-function-url-config --function-name "$fn" --region "$REGION"; then
      run aws lambda delete-function-url-config --function-name "$fn" --region "$REGION"
    fi
    if need_delete "Lambda $fn" aws lambda get-function --function-name "$fn" --region "$REGION"; then
      run aws lambda delete-function --function-name "$fn" --region "$REGION"
    fi
  done

  # IAM 角色：必须先清 inline、detach 托管策略，否则 DeleteConflict
  local role p a
  for role in site-panel-role site-auth-service-role site-mcp-runtime-role \
              site-key-proxy-role site-builder-verifier; do
    if need_delete "IAM 角色 $role" aws iam get-role --role-name "$role"; then
      for p in $(aws iam list-role-policies --role-name "$role" --query 'PolicyNames' --output text); do
        [ "$p" = "None" ] && continue
        run aws iam delete-role-policy --role-name "$role" --policy-name "$p"
      done
      for a in $(aws iam list-attached-role-policies --role-name "$role" \
                   --query 'AttachedPolicies[].PolicyArn' --output text); do
        [ "$a" = "None" ] && continue
        run aws iam detach-role-policy --role-name "$role" --policy-arn "$a"
      done
      run aws iam delete-role --role-name "$role"
    fi
  done

  # 告警 + SNS。m5-* 两条属于 deployer 栈，**不在这里删**（stacks 阶段带走）。
  local alarm="site-builder-auth-invalid-grant"
  local found
  found="$(aws cloudwatch describe-alarms --alarm-names "$alarm" --region "$REGION" \
             --query 'MetricAlarms[].AlarmName' --output text)"
  if [ -n "$found" ] && [ "$found" != "None" ]; then
    run aws cloudwatch delete-alarms --alarm-names "$alarm" --region "$REGION"
  else
    log "  跳过（不存在）: 告警 $alarm"
  fi
  local topic="arn:aws:sns:$REGION:$ACCOUNT:site-builder-alarms"
  if need_delete "SNS topic site-builder-alarms" \
      aws sns get-topic-attributes --topic-arn "$topic" --region "$REGION"; then
    run aws sns delete-topic --topic-arn "$topic" --region "$REGION"
  fi

  # Cognito 两个池：**托管域名要先删才能删池**
  local pool
  for pool in "$(cfg "$SB_CFG" Cognito user_pool_id)" "$(idp_pool_id)"; do
    [ -n "$pool" ] || continue
    if need_delete "Cognito 池 $pool" \
        aws cognito-idp describe-user-pool --user-pool-id "$pool" --region "$REGION"; then
      local dom
      dom="$(aws cognito-idp describe-user-pool --user-pool-id "$pool" --region "$REGION" \
               --query 'UserPool.Domain' --output text)"
      if [ -n "$dom" ] && [ "$dom" != "None" ]; then
        run aws cognito-idp delete-user-pool-domain --domain "$dom" --user-pool-id "$pool" --region "$REGION"
      fi
      run aws cognito-idp delete-user-pool --user-pool-id "$pool" --region "$REGION"
    fi
  done

  # SSM：前两个总有；第三个只有启用过 ⑤c 才有
  local param
  for param in /site-builder/site-client-secret /site-builder/login-flow-secret \
               /site-builder/machine-client-secret; do
    if need_delete "SSM $param" aws ssm get-parameter --name "$param" --region "$REGION"; then
      run aws ssm delete-parameter --name "$param" --region "$REGION"
    fi
  done
}

idp_pool_id() {   # 内置 IdP 池按名字找；没配 cognito-admin 模式时返回空
  local name; name="$(cfg "$SB_CFG" IdP cognito_user_pool_name)"
  [ -n "$name" ] || { echo ""; return 0; }
  aws cognito-idp list-user-pools --max-results 60 --region "$REGION" \
    --query "UserPools[?Name=='$name'].Id | [0]" --output text 2>/dev/null | sed 's/^None$//'
}

# =================================================================== dsql
stage_dsql() {
  step "dsql：③ 手工建的 cluster（不属于任何栈）"
  confirm
  local endpoint cid
  endpoint="$(cfg "$SB_CFG" DSQL cluster_endpoint)"
  cid="${endpoint%%.*}"
  if [ -z "$cid" ]; then log "  跳过（config.ini 的 [DSQL] cluster_endpoint 为空）"; return 0; fi

  if need_delete "DSQL cluster $cid" aws dsql get-cluster --identifier "$cid" --region "$REGION"; then
    run aws dsql delete-cluster --identifier "$cid" --region "$REGION"
    [ "$DRY_RUN" -eq 1 ] && return 0
    # 轮询到服务明确说 NotFound。**超时与 UNKNOWN 都必须 hard-stop**——
    # 只 break 的话后面的 stacks 阶段照跑，那就是 fail-open。
    local i state
    for i in $(seq 1 "$POLL_TRIES"); do
      state="$(probe "DSQL cluster $cid" aws dsql get-cluster --identifier "$cid" --region "$REGION")"
      case "$state" in
        ABSENT)  log "  cluster 已删除（等了约 $((i * POLL_SLEEP)) 秒）"; return 0 ;;
        UNKNOWN) die "删 cluster 之后读不到它的状态，而且不是 NotFound（见报文）。
不能当成已删除——后面还有删栈这种不可逆操作，先查清楚凭据 / 限流。" ;;
      esac
      sleep "$POLL_SLEEP"
    done
    die "等 DSQL cluster $cid 消失超时（约 $((POLL_TRIES * POLL_SLEEP)) 秒）。它可能仍在删除中。
**没有确认删掉就不继续往下删栈**——过几分钟重跑本脚本（幂等）。"
  fi
}

# ================================================================= stacks
stage_stacks() {
  step "stacks：两个 CFN 栈"
  confirm
  local st
  for st in "$ROUTER_STACK" "$DEPLOYER_STACK"; do
    if need_delete "栈 $st" aws cloudformation describe-stacks --stack-name "$st" --region "$REGION"; then
      run aws cloudformation delete-stack --stack-name "$st" --region "$REGION"
    fi
  done
  cat <<EOF

  两点必须知道（都不是你做错了）：
  · deployer 栈约 10 分钟走完；site-artifacts-* 桶由自定义资源自动清空删除。
  · **router 栈第一次一定 DELETE_FAILED**：分发已删，但两个 Edge 函数的已发布版本
    因为 "replicated function" 删不掉，AWS 要几个小时清完全球副本。
    过几小时**重跑本脚本的 stacks 阶段**即可（幂等）：
      $0 --yes --stage stacks
EOF
}

# ================================================================ orphans
stage_orphans() {
  step "orphans：RETAIN 资源与其余手工件（**这一步一半是无声的**）"
  confirm

  # 四张 RETAIN 表。update-table 是**异步**的：表会进 UPDATING，而 UPDATING 期间
  # DeleteTable 返回 ResourceInUseException ⇒ "关保护紧接着删"是确定的竞态。
  local t prot
  for t in site-access-daily site-admins site-api-keys site-ops-log; do
    if need_delete "表 $t" aws dynamodb describe-table --table-name "$t" --region "$REGION"; then
      prot="$(aws dynamodb describe-table --table-name "$t" --region "$REGION" \
                --query 'Table.DeletionProtectionEnabled' --output text)"
      if [ "$prot" = "True" ]; then
        run aws dynamodb update-table --table-name "$t" --no-deletion-protection-enabled --region "$REGION"
        [ "$DRY_RUN" -eq 1 ] || aws dynamodb wait table-exists --table-name "$t" --region "$REGION"
      fi
      run aws dynamodb delete-table --table-name "$t" --region "$REGION"
      [ "$DRY_RUN" -eq 1 ] || aws dynamodb wait table-not-exists --table-name "$t" --region "$REGION"
    fi
  done

  # 两把会话签名 CMK：**别指望按 alias 找**——alias 不是 RETAIN，已经随栈删掉了。
  # 只能按 description 认。不收它们的代价是每把 $1/月永久 + 账号里躺着能签会话的 key。
  local k desc
  for k in $(aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text); do
    [ "$k" = "None" ] && continue
    desc="$(aws kms describe-key --key-id "$k" --region "$REGION" \
              --query 'KeyMetadata.[KeyState,Description]' --output text)"
    case "$desc" in
      *"site-builder session signing key"*)
        case "$desc" in
          PendingDeletion*) log "  已在排期删除: $k" ;;
          *) run aws kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 --region "$REGION" ;;
        esac ;;
    esac
  done

  # 前端桶（② 步骤 1 手工建的，不在栈里）
  local bucket="site-frontend-$ACCOUNT"
  if need_delete "前端桶 $bucket" aws s3api head-bucket --bucket "$bucket"; then
    run aws s3 rm "s3://$bucket" --recursive
    run aws s3api delete-bucket --bucket "$bucket" --region "$REGION"
  fi

  # 日志组
  local lg
  for lg in $(aws logs describe-log-groups --region "$REGION" \
                --query 'logGroups[].logGroupName' --output text); do
    [ "$lg" = "None" ] && continue
    case "$lg" in
      /aws/lambda/site-*|/aws/lambda/us-east-1.ApplicationWebRouterStack-*|\
      /aws/codebuild/site-*|/aws/bedrock-agentcore/runtimes/*)
        run aws logs delete-log-group --log-group-name "$lg" --region "$REGION" ;;
    esac
  done

  cat <<EOF

  还剩两件**要你自己判断**的（本脚本刻意不做）：
  · Route53 里 *.{base_domain} 那条记录（DELETE 时要把 AliasTarget 原样写回去）；
  · CDKToolkit 栈与 cdk-hnb659fds-assets-* 桶 —— 只在"确认不再往这个账号部署"时删。
  收尾核对见 DEPLOY.md 同一节的「收尾核对」。
EOF
}

# =================================================================== main
if [ -n "$ONLY_STAGE" ]; then
  printf '%s\n' "${STAGES[@]}" | grep -qx "$ONLY_STAGE" \
    || die "--stage 只能是: ${STAGES[*]}"
fi

log "拆除目标：账号 $ACCOUNT / 区 $REGION$([ "$DRY_RUN" -eq 1 ] && echo '  [dry-run]')"
for s in "${STAGES[@]}"; do
  want_stage "$s" || continue
  "stage_$s"
done
step "完成（$([ -n "$ONLY_STAGE" ] && echo "阶段 $ONLY_STAGE" || echo '全部阶段')）"
