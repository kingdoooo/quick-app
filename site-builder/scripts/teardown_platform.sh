#!/usr/bin/env bash
# 把平台从一个账号里拆掉。**幂等、fail-closed、可分阶段。**
#
# 为什么这是一个脚本而不是 DEPLOY.md 里的一段 Markdown：拆除是**程序**，不是散文。
# 它此前作为围栏块存在时连续三轮复审各发现一个 P1，根因都是同一类——
# "存在性判断"被写成"命令失败就当不存在"，于是 AccessDenied / 限流被当成 ABSENT，
# 脚本继续往下做破坏性操作并最终退 0。散文形态既没法测，也没法保证"我写下的 = 我跑过的"。
#
# ── 核心不变量（本文件存在的唯一理由）─────────────────────────────────────
#   ① 每一次**读** AWS，结果只有三种：PRESENT / ABSENT / UNKNOWN。
#      **UNKNOWN 一律 hard-stop**（非零退出），并且**不执行任何后续破坏性调用**。
#      "命令失败" ≠ "东西不存在"：只有服务明确说 NotFound 才算 ABSENT。
#      **每一个读点都算**，包括列举（list-* / describe-*）——见下面 `checked`。
#   ② 只删**证明得了归属**的资源。资产支持共享账号（DEPLOY.md §0），所以
#      `site-*` 不是平台独占命名空间；按通配删日志组会删掉别人的数据。
#   ③ 破坏性步骤前的闸门（账号一致 + 站点已清空）**无条件执行**，--stage 也不能绕。
#   ④ 异步操作要等到**服务说完成**才算完成；等不到就非零退出，不打印"完成"。
#   四条都由 deployer/tests/test_teardown_platform.py 注入故障来断言。射程按**调用点**
#   枚举（不是按 API 去重——同一个 API 在多个阶段各有调用点，去重会只打到最先到达的那处），
#   断言形态是"注入点之后日志里没有任何破坏性调用"，不是"某个例子的输出对不对"。
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
#   阶段顺序：scripts → dsql → stacks → orphans
#   **preflight 不是阶段，是闸门**：不论 --stage 给的是哪个，它都先跑（见不变量 ③）。
#
# 退出码：
#   0  做完了，没有已知残留
#   1  拒绝继续（UNKNOWN 状态 / 账号不符 / 站点没清空 / 超时）——修掉原因重跑，幂等
#   3  **已尽力，但还没完**：router 栈第一次删除必定 DELETE_FAILED（Lambda@Edge 全球
#      副本要几小时清完）。这不是你做错了，但也**不是完成**——几小时后重跑。
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
# 栈删除另有预算：deployer 栈实测约 10 分钟，跟 DSQL 共用 10 分钟上限会假超时。
STACK_POLL_TRIES="${TEARDOWN_STACK_POLL_TRIES:-120}"
STACK_POLL_SLEEP="${TEARDOWN_STACK_POLL_SLEEP:-15}"
ONLY_STAGE=""
# preflight 刻意**不在**这张表里——它是闸门，无条件先跑。`--stage preflight`
# 仍然接受（只跑闸门、什么都不删），所以合法取值比这张表多一个。
STAGES=(scripts dsql stacks orphans)
# 整轮是否留下了"要等 AWS、几小时后重跑"的部分。非空 ⇒ 收尾退 3 而不是 0。
INCOMPLETE=()

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
# **这张表里只许放"服务在说这东西不存在"的形态。** 放错一条的代价是单向的：
# 一个存在的资源被判成 ABSENT ⇒ 静默漏删 ⇒ 整轮仍退 0。
# 曾经错放过 `UserPoolTaggingException`（我自己加的，Codex 第五轮 P2-4 抓到）：
# 它在 Cognito 的服务模型里是「a user pool tag can't be set or updated」，
# DescribeUserPool 明确会返回它，而那个池**是存在的** —— 于是标签读取出问题的池会被
# 当成不存在、直接跳过。DescribeUserPool 的"不存在"是 ResourceNotFoundException，已在表内。
_is_absent_err() {
  case "$1" in
    *ResourceNotFoundException*|*ResourceNotFound*|*NotFoundException*|*NoSuchEntity*|\
    *NoSuchBucket*|*ParameterNotFound*|*RepositoryNotFoundException*|*ClusterNotFound*|\
    *"does not exist"*|*"Function not found"*|*"Unable to find"*)
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

# checked <描述> <读命令...> —— **所有列举/查询类读取的唯一出口**，结果放全局 CHECKED_OUT。
#
# 为什么必须有这个函数（Codex 第四轮 P1-3，实测复现过）：
#   `for x in $(aws ... )` 与 `$(...)` 出现在 for 的词表里时，**命令替换的失败状态会被丢掉**，
#   `set -e` 不触发、`pipefail` 也管不到（它只管管道内部）。实测注入 AccessDenied：
#   `list-user-pools` / `list-keys` / `list-role-policies` / `list-attached-role-policies`
#   四处全部**退 0 并继续发破坏性调用**（例如 list-keys 失败后照样删前端桶和日志组）。
#   于是"UNKNOWN 一律 hard-stop"这条不变量在列举点上整片失效——而那是本脚本存在的理由。
#
# 用法上有两条硬纪律：
#   · **不要**写成 `x="$(checked ...)"` 或 `for x in $(checked ...)`。`die` 在 `$( )`
#     的子 shell 里只杀得掉子 shell（`probe` 头上那条注释是同一个坑）。要当普通命令调。
#   · 调完**立刻**读 CHECKED_OUT，下一次 checked 会覆盖它。
CHECKED_OUT=""
checked() {
  local desc="$1"; shift
  local ef rc=0
  ef="$(mktemp "${TMPDIR:-/tmp}/teardown-err.XXXXXX")"
  # 分开接 stdout / stderr：报文绝不能混进返回值（混进去会被当成资源名去删）
  CHECKED_OUT="$("$@" 2>"${ef}")" || rc=$?
  local err; err="$(cat "${ef}")"; rm -f "${ef}"
  if [ "${rc}" -eq 0 ]; then return 0; fi
  # 明确的 NotFound ⇒ 就是"没有"，返回空清单继续
  if _is_absent_err "${err}"; then CHECKED_OUT=""; return 0; fi
  # 注意：报文里不要用 ASCII 双引号——它会在这条双引号字符串里提前收尾。
  # 靠"相邻字符串自动拼接"侥幸成立过，但只要片段里出现空格或 * 就会当场炸。用 「」。
  die "读取「${desc}」失败，而且**不是** NotFound：
${err}
读不到就不能往下做破坏性操作——「列举失败」看起来和「一个都没有」一模一样，
而后者会让本该删的东西被静默留下、或者让后面的步骤在错误的前提上动手。"
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

# wait_gone <描述> <探测命令...> —— 轮询到**服务明确说 NotFound** 才返回（不变量 ④）。
#   ABSENT → 0；UNKNOWN → die；次数耗尽 → die。
# 删除类 API 普遍是异步的（返回 202 / 状态 DELETING），"请求发出去了"不等于"删完了"，
# 而后面还有别的破坏性步骤要在这个前提上动手。所有异步删除都必须过这个函数。
wait_gone() {
  local desc="$1"; shift
  local i state
  for i in $(seq 1 "${POLL_TRIES}"); do
    state="$(probe "${desc}" "$@")"
    case "${state}" in
      ABSENT)  log "  ${desc} 已消失（等了约 $((i * POLL_SLEEP)) 秒）"; return 0 ;;
      UNKNOWN) die "删除 ${desc} 之后读不到它的状态，而且不是 NotFound（见报文）。
不能当成已删除——后面还有不可逆的操作，先查清楚凭据 / 限流。" ;;
    esac
    sleep "${POLL_SLEEP}"
  done
  die "等 ${desc} 消失超时（约 $((POLL_TRIES * POLL_SLEEP)) 秒）。它可能仍在删除中。
**没有确认删掉就不继续往下做**——过几分钟重跑本脚本（幂等）。"
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
  step "preflight（闸门，--stage 不能绕）：凭据、账号、站点是否真的清空、归属清单"
  local live
  live="$(aws sts get-caller-identity --query Account --output text)"
  [ "${live}" = "${ACCOUNT}" ] || die "凭据指向账号 ${live}，而 config.ini 写的是 ${ACCOUNT}。
拆错账号是不可逆的——先切凭据或改 config。"
  log "  账号一致: ${ACCOUNT} / ${REGION}"

  # ── 站点是否清空：**按资源核对，不看 status 列** ──────────────────────────
  # 为什么不能只看 sites 行的 status（Codex 第四轮 P1-2）：`undeploy` 在数据清理
  # 失败时**仍然**把 site 写成 DELETED，只把 job 写成 PURGE_FAILED
  # （deployer/functions/undeploy.py 那段注释解释了为什么它必须这样做）。
  # 于是"没有非 DELETED 的行"证明不了"数据清干净了"。而且 sites 表本身可能已经
  # 被人先删掉（先删栈再想起拆除），那时按 status 核对连输入都没有。
  #
  # 直接看**真正会变成孤儿的东西**：per-site 的 IAM 角色与数据表。这两个前缀
  # 只有 per-site 资源用（common.py: `site-rt-{site_id}` / `site-data-{site_id}-{logical}`），
  # 不与任何平台件同名，所以判据没有歧义。
  # DSQL schema 刻意不查：它随 stage_dsql 删掉整个 cluster 一起消失，不会变孤儿。
  local orphans=()
  checked "per-site IAM 角色" aws iam list-roles \
    --query 'Roles[?starts_with(RoleName, `site-rt-`)].RoleName' --output text
  [ -n "${CHECKED_OUT}" ] && [ "${CHECKED_OUT}" != "None" ] && orphans+=("IAM 角色: ${CHECKED_OUT}")
  checked "per-site 数据表" aws dynamodb list-tables --region "${REGION}" \
    --query 'TableNames[?starts_with(@, `site-data-`)]' --output text
  [ -n "${CHECKED_OUT}" ] && [ "${CHECKED_OUT}" != "None" ] && orphans+=("数据表: ${CHECKED_OUT}")

  if [ "${#orphans[@]}" -gt 0 ]; then
    die "站点侧还有资源没清掉：
$(printf '  · %s\n' "${orphans[@]}")
它们**不在任何栈里**，直接删栈只会把它们变成永久孤儿（还会继续计费）。
先按 DEPLOY.md「把平台从账号里拆掉」第 ① 步把对应站点 undeploy（**带 purge_data**）。
注意：控制台显示「已下线」**不等于**数据已清除——purge 失败时 site 仍写 DELETED，
只有 job 会是 PURGE_FAILED。所以这里按资源核对，不看 status。"
  fi
  log "  站点侧已清空（没有 site-rt-* 角色、没有 site-data-* 表）"

  build_ownership_inventory

  # 跨区清理 Lambda@Edge 日志组要用的区列表。**在 preflight 就取**，不在 orphans 里现取
  # （Codex 第六轮 P1-1 的后半）：那一步在 orphans 末尾，等它失败时表、CMK、前端桶
  # 都已经删掉了。fail-closed 是对的，但应该 fail 得**早**。
  #
  # `--region` 不能省：EC2 是区域性服务，没有 CLI 默认区时它报
  # `An error occurred (NoRegion): You must specify a region.`（实测 aws-cli 2.36.34）。
  # 那条报文不在 NotFound 表里 ⇒ 会被正确判成 UNKNOWN 并 hard-stop，
  # 但在原来的位置上，hard-stop 发生在删完一堆东西之后。
  checked "本账号已启用的区" aws ec2 describe-regions --region "${REGION}" \
    --query 'Regions[].RegionName' --output text
  ENABLED_REGIONS="${CHECKED_OUT}"
  case "${ENABLED_REGIONS}" in
    ""|None) die "枚举不到任何已启用的区（返回为空）。
它决定了跨区那一路要扫哪些区，而「读到空清单」和「没有别的区」看起来一模一样
——后者会让其它区的 Edge 日志组被静默留下，所以这里不往下走。" ;;
  esac
  log "  已启用的区: $(printf '%s' "${ENABLED_REGIONS}" | wc -w | tr -d ' ') 个"
}

# preflight 取到的区列表，orphans 跨区清理时用
ENABLED_REGIONS=""

# ── 归属清单：只删证明得了是自己的东西（不变量 ②）────────────────────────────
# 为什么需要（Codex 第四轮 P1-4，实测复现过）：日志组清理原先按 `/aws/lambda/site-*`
# 与 `/aws/codebuild/site-*` 通配删。资产**明确支持共享账号**（DEPLOY.md §0：
# 「资产在共享账号里也站得住」），而 `site-*` 不是平台独占命名空间——实测让 stub 返回
# `/aws/lambda/site-unrelated-payments`，脚本真的发出了 delete-log-group。
# `/aws/bedrock-agentcore/runtimes/*` 更宽：那是账号里**所有** AgentCore runtime。
#
# 清单分两类，两类都能讲清凭什么算自己的：
#   · 精确名：本脚本自己创建/删除的那些名字、config 里的 runtime id、CodeBuild 项目名，
#     以及从 sites 表读出来的每一个 site_id。
#   · 受栈名限定的前缀：CFN 栈名在一个账号+区里**唯一**，所以 `{栈名}-` 开头的
#     资源按构造就是本平台的。
# 两类都不匹配、但长得像平台件的 ⇒ **报出来、不删**（少删是留个空日志组，误删是别人的数据）。
OWNED_EXACT=()
OWNED_PREFIX=()

build_ownership_inventory() {
  local n
  # 五个平台 Lambda（就是 stage_scripts 里点名删的那些）+ deployer 栈里显式命名的两类
  for n in site-panel site-auth-service site-auth-pre-token site-key-proxy site-access-rollup; do
    OWNED_EXACT+=("/aws/lambda/${n}")
  done
  # `site-deployer-` 是 deployer 栈显式赋的名（infra/app.py 的 function_name=f"site-deployer-{handler}"）
  OWNED_PREFIX+=("/aws/lambda/site-deployer-")
  # 两个栈名限定的前缀（Edge 副本在别区叫 /aws/lambda/{区}.{函数名}）
  OWNED_PREFIX+=("/aws/lambda/${REGION}.${ROUTER_STACK}-" "/aws/lambda/${DEPLOYER_STACK}-")
  # CodeBuild 只有一个项目，名字是精确的（infra/app.py: project_name="site-package"）
  OWNED_EXACT+=("/aws/codebuild/site-package")

  # AgentCore：日志组是 /aws/bedrock-agentcore/runtimes/{runtimeId}-{endpoint}
  local rt_id; rt_id="$(mcp_runtime_id)"
  if [ -n "${rt_id}" ]; then
    OWNED_PREFIX+=("/aws/bedrock-agentcore/runtimes/${rt_id}-")
  fi

  # per-site Lambda 是 site-{site_id}（common.py）。site_id 只能从 sites 表拿——
  # 拿不到（表已删）就**不删任何 per-site 日志组**，改为报出来让人看一眼。
  local sites_state
  sites_state="$(probe "sites 表" aws dynamodb describe-table --table-name site-sites --region "${REGION}")"
  case "${sites_state}" in
    UNKNOWN) die "读不到 sites 表的状态（见报文）。它是 per-site 资源归属的唯一来源。" ;;
    ABSENT)  log "  sites 表已不存在 ⇒ 无法枚举 site_id，per-site 日志组只报告不删除" ;;
    PRESENT)
      # 全部行（含 DELETED）：日志组在站点下线后仍然留着，正是要删的
      checked "sites 表里的 site_id 清单" aws dynamodb scan --table-name site-sites \
        --region "${REGION}" --query 'Items[].site_id.S' --output text
      local sid count=0
      for sid in ${CHECKED_OUT}; do
        [ "${sid}" = "None" ] && continue
        OWNED_EXACT+=("/aws/lambda/site-${sid}")
        count=$((count + 1))
      done
      log "  归属清单：${count} 个历史 site_id + 平台件" ;;
  esac
}

# 长得像平台件、但没能证明归属的东西（用于"报告但不删"）
_looks_platformish() {
  case "$1" in
    /aws/lambda/site-*|/aws/codebuild/site-*|/aws/bedrock-agentcore/runtimes/*) return 0 ;;
  esac
  return 1
}

_is_ours() {
  local name="$1" x
  for x in ${OWNED_EXACT[@]+"${OWNED_EXACT[@]}"}; do
    [ "${name}" = "${x}" ] && return 0
  done
  for x in ${OWNED_PREFIX[@]+"${OWNED_PREFIX[@]}"}; do
    case "${name}" in "${x}"*) return 0 ;; esac
  done
  return 1
}

mcp_runtime_id() {   # 从 [MCP] endpoint_url 里那个 URL-encoded ARN 取 runtime id；读不到返回空
  python3 - "${SB_CFG}" <<'PY'
import configparser, sys, urllib.parse
c = configparser.ConfigParser(interpolation=None); c.read(sys.argv[1], encoding="utf-8")
url = c.get("MCP", "endpoint_url", fallback="")
arn = urllib.parse.unquote(url.split("/runtimes/", 1)[1].split("/invocations", 1)[0]) if "/runtimes/" in url else ""
print(arn.rsplit("/", 1)[-1] if arn else "")
PY
}

# ================================================================ scripts
stage_scripts() {
  step "scripts：脚本建的平台件（一个都不会跟着栈走）"
  confirm

  local rt_id; rt_id="$(mcp_runtime_id)"
  if [ -n "${rt_id}" ]; then
    if need_delete "AgentCore runtime $rt_id" \
        aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id "$rt_id" --region "$REGION"; then
      run aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id "$rt_id" --region "$REGION"
      # **DeleteAgentRuntime 是异步的**：AWS 文档写明返回 `HTTP/1.1 202`，响应里的
      # status 取值含 `DELETING`（Codex 第五轮 P1-3）。原先发完就往下删 ECR 仓库和
      # site-mcp-runtime-role —— 那是把 runtime 正在用的镜像与执行角色从它脚下抽走，
      # 而且整轮会在 runtime 还在的时候退 0。
      [ "$DRY_RUN" -eq 1 ] || wait_gone "AgentCore runtime ${rt_id}" \
        aws bedrock-agentcore-control get-agent-runtime --agent-runtime-id "$rt_id" --region "$REGION"
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
      # 这两个列举必须走 checked：读失败时若当成"没有策略"，下面的 delete-role 会
      # DeleteConflict，而在真机上那是一条含义完全不同的报错。
      checked "角色 ${role} 的 inline 策略" aws iam list-role-policies \
        --role-name "${role}" --query 'PolicyNames' --output text
      for p in ${CHECKED_OUT}; do
        [ "$p" = "None" ] && continue
        run aws iam delete-role-policy --role-name "$role" --policy-name "$p"
      done
      checked "角色 ${role} 的托管策略" aws iam list-attached-role-policies \
        --role-name "${role}" --query 'AttachedPolicies[].PolicyArn' --output text
      for a in ${CHECKED_OUT}; do
        [ "$a" = "None" ] && continue
        run aws iam detach-role-policy --role-name "$role" --policy-arn "$a"
      done
      run aws iam delete-role --role-name "$role"
    fi
  done

  # 告警 + SNS。m5-* 两条属于 deployer 栈，**不在这里删**（stacks 阶段带走）。
  local alarm="site-builder-auth-invalid-grant"
  checked "告警 ${alarm}" aws cloudwatch describe-alarms --alarm-names "${alarm}" \
    --region "${REGION}" --query 'MetricAlarms[].AlarmName' --output text
  local found="${CHECKED_OUT}"
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

  # 内置 IdP 池按名字找。**必须在循环外、用 checked 解析**：原先它住在 idp_pool_id()
  # 里、被 `for pool in ... "$(idp_pool_id)"` 调用，而那条命令带着 `2>/dev/null`——
  # AccessDenied 下静默返回空池名，池被漏删、整轮照样退 0（实测复现）。
  # 放进 $( ) 里也救不了：checked 的 die 在子 shell 里只杀得掉子 shell。
  # （list-user-pools 的 --max-results 是页大小，CLI 会自动翻页，所以过滤是全量的。）
  local idp_pool="" idp_name
  idp_name="$(cfg "${SB_CFG}" IdP cognito_user_pool_name)"
  if [ -n "${idp_name}" ]; then
    checked "内置 IdP 池 ${idp_name}" aws cognito-idp list-user-pools --max-results 60 \
      --region "${REGION}" --query "UserPools[?Name=='${idp_name}'].Id | [0]" --output text
    idp_pool="${CHECKED_OUT}"
    [ "${idp_pool}" = "None" ] && idp_pool=""
  fi

  # Cognito 两个池：**托管域名要先删才能删池**
  local pool
  for pool in "$(cfg "$SB_CFG" Cognito user_pool_id)" "${idp_pool}"; do
    [ -n "$pool" ] || continue
    if need_delete "Cognito 池 $pool" \
        aws cognito-idp describe-user-pool --user-pool-id "$pool" --region "$REGION"; then
      checked "池 ${pool} 的托管域名" aws cognito-idp describe-user-pool \
        --user-pool-id "${pool}" --region "${REGION}" --query 'UserPool.Domain' --output text
      local dom="${CHECKED_OUT}"
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
    # 轮询到服务明确说 NotFound。**超时与 UNKNOWN 都必须 hard-stop**——
    # 只 break 的话后面的 stacks 阶段照跑，那就是 fail-open。
    # 与 AgentCore 走**同一个** wait_gone：两处曾各写一遍，其中一处（AgentCore）
    # 干脆忘了轮询。同一条不变量不该有两份实现。
    [ "$DRY_RUN" -eq 1 ] || wait_gone "DSQL cluster ${cid}" \
      aws dsql get-cluster --identifier "$cid" --region "$REGION"
  fi
}

# ================================================================= stacks
stage_stacks() {
  step "stacks：两个 CFN 栈"
  confirm
  # 两个栈之间没有 CFN 依赖，先都发起删除再分别等，省一半墙钟。
  local st issued=()
  for st in "$ROUTER_STACK" "$DEPLOYER_STACK"; do
    if need_delete "栈 $st" aws cloudformation describe-stacks --stack-name "$st" --region "$REGION"; then
      run aws cloudformation delete-stack --stack-name "$st" --region "$REGION"
      issued+=("${st}")
    fi
  done
  [ "${#issued[@]}" -eq 0 ] && return 0
  [ "$DRY_RUN" -eq 1 ] && return 0

  # **必须等到服务说完成**（Codex 第四轮 P1-5）。原先只发异步 delete-stack 就往下走，
  # 于是"完成"这两个字与栈的真实状态无关：router 栈第一次**必定** DELETE_FAILED，
  # 而整轮照样退 0。异步调用发出去 ≠ 做完了。
  for st in "${issued[@]}"; do
    wait_stack_deleted "${st}"
  done
}

# wait_stack_deleted <栈名> —— 轮询到栈真的消失。
#   消失（describe-stacks 报不存在）→ 返回
#   DELETE_FAILED 且原因是 Lambda@Edge 副本 → 记进 INCOMPLETE 并返回（收尾退 3）
#   其它 DELETE_FAILED / 其它状态 / 轮询耗尽 → die
wait_stack_deleted() {
  local st="$1" i state last="(没读到)"
  for i in $(seq 1 "${STACK_POLL_TRIES}"); do
    # checked 已经把三值分好了：NotFound ⇒ 空（栈删完就查不到了，那是**成功**信号）；
    # 非 NotFound 的失败 ⇒ 它自己 die。所以这里一次调用就够。
    checked "栈 ${st} 的状态" aws cloudformation describe-stacks --stack-name "${st}" \
      --region "${REGION}" --query 'Stacks[0].StackStatus' --output text
    state="${CHECKED_OUT}"
    if [ -z "${state}" ] || [ "${state}" = "None" ]; then
      log "  栈 ${st} 已删除（等了约 $((i * STACK_POLL_SLEEP)) 秒）"; return 0
    fi
    case "${state}" in
      DELETE_IN_PROGRESS) ;;
      DELETE_FAILED)
        # **不能只问"有没有一条原因提到 replicated function"**（Codex 第五轮 P1-2）：
        # 混合失败（Edge 副本 + 桶非空）里那条 Edge 原因会把真正的阻塞藏起来，实测退 3。
        # 两处改动：
        #  · 数据源从 describe-stack-events（**历史**，含前几次尝试的 DELETE_FAILED）
        #    换成 describe-stack-resources（**现状**）；
        #  · 判据从"任一条匹配"换成"当前**所有** DELETE_FAILED 资源都必须是那两个 Edge
        #    函数、且原因都匹配"，逻辑 ID 也一起核（构造 ID 见 router 的 PROTECTED_CONSTRUCTS）。
        # 交给 JMESPath 数数，不在 bash 里切多行文本——原因串里带空格，切错就又是一次误判。
        local q_all q_edge n_all n_edge
        q_all="length(StackResources[?ResourceStatus=='DELETE_FAILED'])"
        q_edge="length(StackResources[?ResourceStatus=='DELETE_FAILED'"
        q_edge="${q_edge} && ResourceStatusReason != null"
        q_edge="${q_edge} && contains(ResourceStatusReason, 'replicated function')"
        q_edge="${q_edge} && (starts_with(LogicalResourceId, 'OriginRequestFunction')"
        q_edge="${q_edge} || starts_with(LogicalResourceId, 'OriginResponseFunction'))])"
        checked "栈 ${st} 当前 DELETE_FAILED 的资源数" aws cloudformation describe-stack-resources \
          --stack-name "${st}" --region "${REGION}" --query "${q_all}" --output text
        n_all="${CHECKED_OUT}"
        checked "栈 ${st} 里属于 Edge 副本的失败资源数" aws cloudformation describe-stack-resources \
          --stack-name "${st}" --region "${REGION}" --query "${q_edge}" --output text
        n_edge="${CHECKED_OUT}"
        if [ -n "${n_all}" ] && [ "${n_all}" != "0" ] && [ "${n_all}" = "${n_edge}" ]; then
          # 这一条是**预期**的：Lambda@Edge 的已发布版本要等全球副本清完才删得掉。
          # 但"预期"不等于"完成"——所以记账，收尾退 3。
          log "  栈 ${st} DELETE_FAILED，${n_all} 个失败资源**全部**是 Lambda@Edge 副本（预期）"
          INCOMPLETE+=("栈 ${st}：Edge 副本未清完，几小时后重跑 --stage stacks")
          return 0
        fi
        checked "栈 ${st} 的失败明细" aws cloudformation describe-stack-resources \
          --stack-name "${st}" --region "${REGION}" \
          --query "StackResources[?ResourceStatus=='DELETE_FAILED'].[LogicalResourceId,ResourceStatusReason]" \
          --output text
        die "栈 ${st} 删除失败，而且**不只是** Edge 副本那种预期情况：
当前 ${n_all} 个 DELETE_FAILED 资源里只有 ${n_edge} 个是 Edge 副本。明细：
${CHECKED_OUT}
先到 CloudFormation 控制台处理掉真正的阻塞资源再重跑。**别把这一轮当成"预期失败"放过**。" ;;
      *)
        # 别在这里 die：`delete-stack` 是**异步**的，紧接着的第一次轮询完全可能还读到
        # 删除前的状态（CREATE_COMPLETE / UPDATE_COMPLETE …）。那时 die 是一条假红。
        # 真正卡住的状态由**超时**兜住（下面那条 die 会带上最后看到的状态），
        # 所以这条分支只是"再等等"，不是放过。
        log "  栈 ${st} 当前 ${state}，等它进入删除流程…" ;;
    esac
    last="${state}"
    sleep "${STACK_POLL_SLEEP}"
  done
  die "等栈 ${st} 删除完成超时（约 $((STACK_POLL_TRIES * STACK_POLL_SLEEP)) 秒），最后看到的状态是 ${last}。
它可能仍在删除中，也可能卡在这个状态上。**没确认删完就不继续往下删**——
过几分钟重跑本脚本（幂等）；如果状态一直不是 DELETE_*，去 CloudFormation 控制台看事件。"
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
      checked "表 ${t} 的删除保护状态" aws dynamodb describe-table --table-name "${t}" \
        --region "${REGION}" --query 'Table.DeletionProtectionEnabled' --output text
      prot="${CHECKED_OUT}"
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
  checked "账号里的 KMS key 清单" aws kms list-keys --region "${REGION}" \
    --query 'Keys[].KeyId' --output text
  for k in ${CHECKED_OUT}; do
    [ "$k" = "None" ] && continue
    checked "KMS key ${k} 的状态与描述" aws kms describe-key --key-id "${k}" \
      --region "${REGION}" --query 'KeyMetadata.[KeyState,Description]' --output text
    desc="${CHECKED_OUT}"
    case "$desc" in
      *"site-builder session signing key"*)
        case "$desc" in
          PendingDeletion*) log "  已在排期删除: $k" ;;
          *) run aws kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 --region "$REGION" ;;
        esac ;;
    esac
  done

  # 前端桶（② 步骤 1 手工建的，不在栈里）
  # **探测用 get-bucket-location 而不是 head-bucket**：HeadBucket 没有响应体，
  # 桶不存在时 CLI 报的是 `An error occurred (404) ... : Not Found`（实测 aws-cli 2.36.34），
  # 里面没有任何 NotFound 关键字 ⇒ 会被分类成 UNKNOWN，把"已经清干净的账号重跑一遍"
  # 变成 hard-stop（Codex 第四轮 P2）。GetBucketLocation 报的是
  # `(NoSuchBucket) ... The specified bucket does not exist`，两条现成规则都能认。
  # 别名不存在的桶仍然会 403 Forbidden ⇒ 正确地落进 UNKNOWN。
  local bucket="site-frontend-$ACCOUNT"
  if need_delete "前端桶 $bucket" aws s3api get-bucket-location --bucket "$bucket"; then
    run aws s3 rm "s3://$bucket" --recursive
    run aws s3api delete-bucket --bucket "$bucket" --region "$REGION"
  fi

  # ── 日志组：**只删归属清单里的**（不变量 ②）──────────────────────────────
  # 原先是 `/aws/lambda/site-*` / `/aws/codebuild/site-*` / `.../runtimes/*` 通配。
  # 资产支持共享账号，那三条都不是平台独占命名空间：实测 stub 返回
  # `/aws/lambda/site-unrelated-payments` 时脚本真的发出了 delete-log-group。
  # 现在按 preflight 建的清单精确匹配；像平台件但证明不了归属的**只报告不删除**
  # ——少删是留个空日志组（$0），误删是别人的可观测数据。
  local lg unowned=()
  checked "日志组清单" aws logs describe-log-groups --region "${REGION}" \
    --query 'logGroups[].logGroupName' --output text
  for lg in ${CHECKED_OUT}; do
    [ "$lg" = "None" ] && continue
    if _is_ours "${lg}"; then
      run aws logs delete-log-group --log-group-name "$lg" --region "$REGION"
    elif _looks_platformish "${lg}"; then
      unowned+=("${lg}")
    fi
  done
  # Lambda@Edge 的日志组在**每个执行区**都有一份，名字全都叫
  # `/aws/lambda/{归属区}.{函数名}`（归属区恒为 Edge 函数所在的 us-east-1，与执行区无关）。
  # 只扫本区会把其它区的副本日志永久留下（Codex 第五轮 P2-5）。
  # 区列表**动态枚举、不硬编码** —— 别的部署不知道自己的 POP 落在哪些区，
  # 这跟 access_rollup 跨区扫描当初的设计理由是同一条（DEPLOY.md 那一节）。
  # 只按 Edge 前缀查，而且**仍然只删归属清单内的**：那个前缀会把账号里别人的 Edge
  # 函数一起列出来（DEPLOY.md 记过实测见到的 `us-east-1.redirectEdge`），
  # 对只读的聚合器那是可接受的代价，对**删除**则是事故。
  # 区列表在 preflight 就取好了（见那里的注释：失败要发生在删任何东西之前）
  local other elg
  for other in ${ENABLED_REGIONS}; do
    [ "${other}" = "None" ] && continue
    [ "${other}" = "${REGION}" ] && continue
    checked "区 ${other} 里的 Edge 日志组" aws logs describe-log-groups --region "${other}" \
      --log-group-name-prefix "/aws/lambda/${REGION}." \
      --query 'logGroups[].logGroupName' --output text
    for elg in ${CHECKED_OUT}; do
      [ "${elg}" = "None" ] && continue
      if _is_ours "${elg}"; then
        run aws logs delete-log-group --log-group-name "${elg}" --region "${other}"
      fi
    done
  done

  if [ "${#unowned[@]}" -gt 0 ]; then
    log ""
    log "  以下日志组名字像平台件，但**证明不了归属**，所以没有删（请自己看一眼）："
    printf '    · %s\n' "${unowned[@]}"
    log "  常见原因：sites 表已经先被删掉 ⇒ 枚举不出 site_id；或者这是共享账号里"
    log "  别人的资源恰好也叫 site-*。确认是自己的再手工删。"
  fi

  cat <<EOF

  还剩两件**要你自己判断**的（本脚本刻意不做）：
  · Route53 里 *.{base_domain} 那条记录（DELETE 时要把 AliasTarget 原样写回去）；
  · CDKToolkit 栈与 cdk-hnb659fds-assets-* 桶 —— 只在"确认不再往这个账号部署"时删。
  收尾核对见 DEPLOY.md 同一节的「收尾核对」。
EOF
}

# =================================================================== main
if [ -n "$ONLY_STAGE" ]; then
  printf '%s\n' preflight "${STAGES[@]}" | grep -qx "$ONLY_STAGE" \
    || die "--stage 只能是: preflight ${STAGES[*]}"
fi

log "拆除目标：账号 $ACCOUNT / 区 $REGION$([ "$DRY_RUN" -eq 1 ] && echo '  [dry-run]')"

# **preflight 无条件先跑**（不变量 ③）。它曾经是 STAGES 里的一员，于是
# `--stage stacks`（本脚本自己在 stacks 收尾里推荐的 router 重试命令）整个绕过了
# 账号核对：实测在**错误账号**上 get-caller-identity 一次都没调用，照发两条
# delete-stack 并退 0。preflight 全是只读的，无条件跑没有代价。
stage_preflight
if [ "$ONLY_STAGE" = "preflight" ]; then
  step "完成（只跑了闸门，什么都没删）"
  exit 0
fi

for s in "${STAGES[@]}"; do
  want_stage "$s" || continue
  "stage_$s"
done

if [ "${#INCOMPLETE[@]}" -gt 0 ]; then
  step "**还没完**（$([ -n "$ONLY_STAGE" ] && echo "阶段 $ONLY_STAGE" || echo '全部阶段')）"
  printf '  · %s\n' "${INCOMPLETE[@]}"
  cat <<EOF

  这不是你做错了：Lambda@Edge 的已发布版本要等 AWS 清完全球副本才删得掉，
  通常几个小时。**但它也不是完成**，所以退出码是 3 而不是 0——脚本幂等，
  过几小时重跑即可：
      $0 --yes --stage stacks
EOF
  exit 3
fi
step "完成（$([ -n "$ONLY_STAGE" ] && echo "阶段 $ONLY_STAGE" || echo '全部阶段')）"
