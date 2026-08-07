#!/usr/bin/env bash
# MCP runtime 角色的 IAM 属性闸门 —— 真机负向验收。
#
# 为什么必须真机：属性白名单是否真的**拦住**越权字段，moto 与 Stubber 都验不了
# （前者不执行 IAM 授权，后者只校验请求参数形态）。只跑正向用例等于没验这道闸门
# ——白名单写错、Null 检查漏掉、或 dynamodb:Attributes 收到别名而非真实属性名，
# 正向路径全都照样通过。
#
# 为什么要影子角色：site-mcp-runtime-role 的 trust 只允许
# bedrock-agentcore.amazonaws.com，部署者 assume 不了（身份 policy 再宽也会被
# role trust 拒），而 AgentCore managed runtime 没有交互式 shell。所以造一个
# 一次性等价身份：**只复制待验的 DynamoDB statements**，不复制整份 runtime
# 策略（那会连 S3/SFN/undeploy Lambda 权限一起复制，一旦残留就是完整后门）。
#
# 用法：
#   ./verify_mcp_iam_scope.sh                      # 用当前凭证建/删探针资源
#   ADMIN_PROFILE=myadmin ./verify_mcp_iam_scope.sh   # 建/删用该 profile，
#                                                     # 避免覆盖调用者的环境凭证
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$HERE/../config.ini"
[ -f "$CFG" ] || { echo "找不到 $CFG"; exit 1; }

read_cfg() {  # $1=section $2=key
  python3 - "$CFG" "$1" "$2" <<'PY'
import configparser, sys
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1])
print(c[sys.argv[2]][sys.argv[3]].split("#")[0].strip())
PY
}

REGION="$(read_cfg Platform region)"
SITES_TABLE="$(read_cfg Deployer sites_table)"
ROUTING_TABLE="$(read_cfg Platform routing_table)"
RUNTIME_ROLE="site-mcp-runtime-role"

# 建/删探针资源用的凭证：显式 profile 时不动调用者的环境变量。
# 后面 assume 出的临时凭证只注入探针子进程（见 run_probe），不 export 到本 shell
# ——原实现用 eval export 覆盖环境，之后的 unset 无法恢复调用者原本通过环境变量
# 提供的凭证，清理命令可能因此没权限。
# 注意别写成 `aws "${ADMIN[@]}"`：macOS 自带的 bash 3.2 在 set -u 下把空数组
# 展开当成未绑定变量而报错（Linux 的 bash 4+ 不会）。
aws_admin() {
  if [ -n "${ADMIN_PROFILE:-}" ]; then
    aws --profile "$ADMIN_PROFILE" --region "$REGION" "$@"
  else
    aws --region "$REGION" "$@"
  fi
}

ACCOUNT="$(aws_admin sts get-caller-identity --query Account --output text)"
ME="$(aws_admin sts get-caller-identity --query Arn --output text)"

# 唯一后缀：固定角色名在"上次跑挂了没清理"时会让 create-role 失败，
# 而后续命令仍可能给那个已存在的角色附加策略。
SUFFIX="$(python3 -c 'import uuid; print(uuid.uuid4().hex[:10])')"
PROBE_ROLE="site-mcp-iamprobe-$SUFFIX"
SITE="iamprobe-$SUFFIX"
SCOPE_FILE="$(mktemp -t mcp-scope.XXXXXX)"
NARROW_FILE="$(mktemp -t mcp-narrow.XXXXXX)"

FAILURES=0
CLEANED=0

cleanup() {
  local rc=$?
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  echo
  echo "── 清理 ─────────────────────────────"
  # 每条都容错：清理必须尽力做完，不能因为前一条失败就留下后面的资源
  aws_admin iam delete-role-policy --role-name "$PROBE_ROLE" \
    --policy-name ddb-scope >/dev/null 2>&1 || true
  aws_admin iam delete-role --role-name "$PROBE_ROLE" >/dev/null 2>&1 || true
  aws_admin dynamodb delete-item --table-name "$SITES_TABLE" \
    --key "{\"site_id\":{\"S\":\"$SITE\"}}" >/dev/null 2>&1 || true
  aws_admin dynamodb delete-item --table-name "$ROUTING_TABLE" \
    --key "{\"subdomain\":{\"S\":\"app-$SITE\"}}" >/dev/null 2>&1 || true
  rm -f "$SCOPE_FILE" "$NARROW_FILE"

  # 残留检查：影子角色留着等于留了一条"指定 principal 可 assume 的站点管理权限"
  local leftover=0
  if aws_admin iam get-role --role-name "$PROBE_ROLE" >/dev/null 2>&1; then
    echo "⚠️  影子角色仍存在：$PROBE_ROLE —— 立即手工删除"
    leftover=1
  fi
  # 用 `Item != null` 判断，不要拿 `--query Item --output text` 的输出去 grep：
  # 上面的 delete-item 若成功，get-item 返回的是**没有 Item 键**的空对象，
  # text 输出为空字符串——但 delete 失败时输出也可能不含可 grep 的内容，
  # 两种情况分不开（实测过：明明已删却报"仍存在"）。
  for spec in "$SITES_TABLE|{\"site_id\":{\"S\":\"$SITE\"}}|$SITE" \
              "$ROUTING_TABLE|{\"subdomain\":{\"S\":\"app-$SITE\"}}|app-$SITE"; do
    local tbl key label present
    tbl="${spec%%|*}"; key="${spec#*|}"; label="${key#*|}"; key="${key%|*}"
    present="$(aws_admin dynamodb get-item --table-name "$tbl" --key "$key" \
                 --query 'Item != null' --output text 2>/dev/null || echo Unknown)"
    if [ "$present" != "False" ]; then
      echo "⚠️  fixture 仍存在（或状态未知）：$tbl / $label（present=$present）"
      leftover=1
    fi
  done
  [ "$leftover" = 0 ] && echo "影子角色与 fixture 均已删除"

  if [ "$leftover" != 0 ]; then
    exit 1
  elif [ "$FAILURES" -gt 0 ]; then
    echo
    echo "结果：$FAILURES 条探针未达预期 —— 见上面的 FAIL 行"
    exit 1
  elif [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  echo "结果：全部探针通过"
}
trap cleanup EXIT INT TERM

# **先确认真实角色没有旁路授权**（Codex 审查 2026-08-06 P1）。
# 本脚本验的是 mcp-scope 这一份 inline policy 的收窄效果，而 IAM 是把**所有**
# 适用策略求并集的：真实角色上若还挂着 AmazonDynamoDBFullAccess 或另一条宽泛
# inline policy，影子角色（只带 mcp-scope）的两条负向 probe 照样 deny、脚本报
# "全部通过"，而线上 runtime 仍能改 api_target / data_tables。
# deploy_agentcore.py 只 put_role_policy，不会检查或清掉遗留策略，所以这里必须查。
echo "── ⓪ 真实角色的策略全集 ─────────────────────────"
ATTACHED="$(aws_admin iam list-attached-role-policies --role-name "$RUNTIME_ROLE" \
  --query 'AttachedPolicies[].PolicyName' --output json)"
INLINE="$(aws_admin iam list-role-policies --role-name "$RUNTIME_ROLE" \
  --query 'PolicyNames' --output json)"
echo "  attached: $ATTACHED"
echo "  inline:   $INLINE"
if [ "$ATTACHED" != "[]" ]; then
  echo "FAIL  真实角色挂着 managed policy —— 本脚本只验 mcp-scope，"
  echo "      有旁路授权时下面的 PASS **不代表线上收窄有效**"
  FAILURES=$((FAILURES + 1))
fi
if ! printf '%s' "$INLINE" | python3 -c "
import json,sys
names = json.load(sys.stdin)
extra = [n for n in names if n != 'mcp-scope']
if extra:
    print(f'FAIL  除 mcp-scope 外还有 inline policy: {extra} —— 同上，存在旁路')
    sys.exit(1)
print('PASS  真实角色只有 mcp-scope 一条策略，无旁路授权')
"; then
  FAILURES=$((FAILURES + 1))
fi

# **表上的 resource-based policy 同样是旁路**（Codex 复审 2026-08-07）。
# 影子角色是**另一个 principal**，拿不到写给 site-mcp-runtime-role 的 resource
# policy —— 于是真实 runtime 有额外 Allow、而两条负向 probe 仍然 deny，脚本
# 报"全部通过"。身份策略与资源策略是求并集的，只查前者不够。
# 现网核对过：这几张表当前都没有 resource policy，所以这是防未来假通过。
echo "── ⓪b 表上的 resource-based policy ───────────────"
# **jobs 表也要查**：它现在同样参与安全事务（undeploy 的 create_job、
# confirm_upload 的状态迁移都在事务里），"真实角色的完整 DynamoDB 授权并集"
# 这个断言必须覆盖全部参与表，否则结论推得比证据宽。
#
# **必须查两次**：GetResourcePolicy 是**最终一致**读，官方明示
# "PutResourcePolicy 之后立刻查可能返回 PolicyNotFoundException，等几秒重试"。
# 单次读到 PolicyNotFound 就报无策略的话，刚附加上宽泛策略的那几秒里本脚本
# 会假绿，而策略随后就生效（Codex 复审 2026-08-07 第二轮 P2）。
probe_resource_policy() {  # $1=表名 → 0 无策略 / 1 有策略或查不了
  local tbl="$1" out rc
  out="$(aws_admin dynamodb get-resource-policy \
           --resource-arn "arn:aws:dynamodb:$REGION:$ACCOUNT:table/$tbl" 2>&1)" \
    && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL  $tbl 上存在 resource-based policy —— 它可能给 runtime 角色额外"
    echo "      授权，而影子角色（另一个 principal）拿不到，下面的 PASS 不可信。"
    echo "      内容：$(printf '%s' "$out" | head -c 400)"
    return 1
  fi
  if ! grep -q "PolicyNotFoundException" <<<"$out"; then
    echo "FAIL  $tbl 的 resource policy 查不出来（不是'没有策略'）：$(head -1 <<<"$out")"
    echo "      需要 dynamodb:GetResourcePolicy 权限；查不了就不能断言无旁路。"
    return 1
  fi
  return 0
}

for TBL in "$SITES_TABLE" "$ROUTING_TABLE" \
           "$(read_cfg Deployer admins_table)" \
           "$(read_cfg Deployer jobs_table)"; do
  if ! probe_resource_policy "$TBL"; then
    FAILURES=$((FAILURES + 1)); continue
  fi
  # 第一次读到"无策略"——因最终一致性，隔几秒再确认一次
  sleep 6
  if ! probe_resource_policy "$TBL"; then
    echo "      （第二次读才发现——正是最终一致性窗口，单次读会假绿）"
    FAILURES=$((FAILURES + 1)); continue
  fi
  echo "PASS  $TBL 无 resource-based policy（间隔 6s 两次确认）"
done

echo "── ① 影子角色（只复制 DynamoDB statements）────────"
# --output json 显式指定：操作者的 AWS CLI 默认输出若是 text/table/yaml，
# 拿到的就不是可用的 policy JSON。
aws_admin iam get-role-policy --role-name "$RUNTIME_ROLE" \
  --policy-name mcp-scope --query PolicyDocument --output json > "$SCOPE_FILE"

# 从线上真策略里**筛出** DynamoDB 相关 statement，不手抄（手抄验的就不是同一套
# 约束了），也不整份复制（避免影子角色持有 S3/SFN/undeploy 权限）。
python3 - "$SCOPE_FILE" "$NARROW_FILE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
keep = []
for st in doc["Statement"]:
    actions = st.get("Action")
    actions = [actions] if isinstance(actions, str) else (actions or [])
    if any(a.startswith("dynamodb:") for a in actions):
        keep.append(st)
if not keep:
    sys.exit("线上策略里没有 dynamodb statement——策略结构变了，先核对再跑")
json.dump({"Version": "2012-10-17", "Statement": keep}, open(sys.argv[2], "w"))
print(f"  复制 {len(keep)} 条 DynamoDB statement（共 {len(doc['Statement'])} 条）")
PY

aws_admin iam create-role --role-name "$PROBE_ROLE" \
  `# description 只接受 ASCII（ -~ 等），中文会 ValidationError` \
  --description "Ephemeral IAM probe; auto-deleted on script exit" \
  --assume-role-policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"$ME\"},\"Action\":\"sts:AssumeRole\"}]}" \
  >/dev/null
aws_admin iam put-role-policy --role-name "$PROBE_ROLE" \
  --policy-name ddb-scope --policy-document "file://$NARROW_FILE"
echo "  $PROBE_ROLE 已建，等待 IAM 传播…"
sleep 12

echo "── ② 一次性 fixture（不碰真实站点）────────────────"
aws_admin dynamodb put-item --table-name "$SITES_TABLE" \
  --item "{\"site_id\":{\"S\":\"$SITE\"},\"owner\":{\"S\":\"probe@example.com\"}}"
aws_admin dynamodb put-item --table-name "$ROUTING_TABLE" \
  --item "{\"subdomain\":{\"S\":\"app-$SITE\"},\"site_id\":{\"S\":\"$SITE\"},\"require_auth\":{\"BOOL\":true},\"owner\":{\"S\":\"probe@example.com\"}}"
echo "  site_id=$SITE / subdomain=app-$SITE"

echo "── ③ 取影子角色凭证 ──────────────────────────────"
CREDS="$(aws_admin sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/$PROBE_ROLE" \
  --role-session-name iamprobe --query Credentials --output json)"
export PROBE_AK PROBE_SK PROBE_ST
PROBE_AK="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["AccessKeyId"])' <<<"$CREDS")"
PROBE_SK="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["SecretAccessKey"])' <<<"$CREDS")"
PROBE_ST="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["SessionToken"])' <<<"$CREDS")"

# 临时凭证只进探针子进程的环境，不污染本 shell——否则清理会用错身份。
probe() {  # $1=说明 $2=期望(deny|allow) 剩余=aws 参数
  local desc="$1" want="$2"; shift 2
  local out rc got
  # 用 env -u 取消 AWS_PROFILE，**不要写 AWS_PROFILE=**：CLI 会把空串当成
  # "名为空的 profile" 并以 `The config profile () could not be found` 失败
  # ——那样每条探针都在触及 IAM 之前就死了，结果全是 OTHER，等于没验。
  out="$(env -u AWS_PROFILE \
            AWS_ACCESS_KEY_ID="$PROBE_AK" AWS_SECRET_ACCESS_KEY="$PROBE_SK" \
            AWS_SESSION_TOKEN="$PROBE_ST" \
            aws --region "$REGION" "$@" 2>&1)" && rc=0 || rc=$?
  if grep -q "AccessDeniedException" <<<"$out"; then got=deny
  elif grep -q "ValidationException" <<<"$out"; then got=INVALID
  elif [ "$rc" -eq 0 ]; then got=allow
  # 凭证/配置问题必须与 IAM 结论区分开：它们说明探针没跑到判定点。
  elif grep -qE "could not be found|Unable to locate credentials|ExpiredToken|InvalidClientTokenId" <<<"$out"; then
    got="SETUP-ERROR:$(head -1 <<<"$out")"
  else got="OTHER:$(head -1 <<<"$out")"; fi

  if [ "$got" = "$want" ]; then
    printf 'PASS  %-32s (%s)\n' "$desc" "$got"
  else
    printf 'FAIL  %-32s 期望=%s 实际=%s\n' "$desc" "$want" "$got"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "── ④ 四条探针 ───────────────────────────────────"
# ① 越权改 sites 的部署链字段 —— 必须被拒
probe "sites.data_tables 越权" deny \
  dynamodb update-item --table-name "$SITES_TABLE" \
    --key "{\"site_id\":{\"S\":\"$SITE\"}}" \
    --update-expression 'SET data_tables = :v' \
    --expression-attribute-values '{":v":{"L":[{"S":"evil"}]}}'
# ② 越权改路由指向 —— 必须被拒
probe "routing.api_target 越权" deny \
  dynamodb update-item --table-name "$ROUTING_TABLE" \
    --key "{\"subdomain\":{\"S\":\"app-$SITE\"}}" \
    --update-expression 'SET api_target = :v' \
    --expression-attribute-values '{":v":{"S":"https://evil.example"}}'
# ③ 正常权限投影 —— 必须成功（证明闸门没过紧）
probe "routing.require_auth 正常投影" allow \
  dynamodb update-item --table-name "$ROUTING_TABLE" \
    --key "{\"subdomain\":{\"S\":\"app-$SITE\"}}" \
    --update-expression 'SET require_auth = :v' \
    --expression-attribute-values '{":v":{"BOOL":false}}'
# ④ 读路径没被闸门误伤 —— 必须成功。
#    owner 是 DynamoDB 保留字，KeyConditionExpression 里必须用别名，
#    否则报 ValidationException（那验的是命令语法而非 IAM 结果 → 标 INVALID）。
probe "owner-index Query 未被误伤" allow \
  dynamodb query --table-name "$SITES_TABLE" --index-name owner-index \
    --key-condition-expression '#o = :o' \
    --expression-attribute-names '{"#o":"owner"}' \
    --expression-attribute-values '{":o":{"S":"probe@example.com"}}'

echo
echo "判读："
echo "  INVALID          → 命令写错（保留字/JSON 转义），修命令重跑，**不是** IAM 结论"
echo "  ① 或 ② = allow   → P0：闸门没生效，runtime 可篡改部署状态与路由指向"
echo "  ③ = deny         → 白名单少字段（报 AccessDenied 而非 TransactionCanceled，"
echo "                     别误判成并发冲突）；对照 ROUTE_PROJECTION_ATTRIBUTES 补齐"
echo "  ④ = deny         → 读侧被加了 Attributes/Null 条件；读写必须是两个独立 statement"
echo
echo "注意 owner 在白名单内是**有意的**（建站与 transfer_owner 都要写它），"
echo "所以\"改 owner 接管站点\"这条路径 IAM 关不掉——由应用层与 runtime 完整性负责。"
echo "不要因为本脚本而把 owner 从白名单删掉：那会让建站在线上直接 AccessDenied。"
