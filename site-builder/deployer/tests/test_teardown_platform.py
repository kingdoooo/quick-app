"""`scripts/teardown_platform.sh` 的故障注入 harness。

**为什么这份测试必须存在。** 拆除流程此前是 DEPLOY.md 里的几段 Markdown，连续三轮
复审各发现一个 P1，根因每次都一样：某处"存在性判断"被写成「命令失败就当不存在」，
于是 AccessDenied / 限流被当成 ABSENT，脚本继续做破坏性操作并最终退 0。
`bash -n` 只能证明语法；"跑一遍看输出对不对"只验证例子。所以这里验的是**不变量**。

**第四轮又漏了四条 P1，而且是同一类。** 上一版 harness 按"每阶段挑一个代表性 probe"
建模，于是列举点（`list-keys` / `list-user-pools` / `list-role-policies` /
`list-attached-role-policies` / `describe-log-groups`）整片没进射程——实测注入
AccessDenied，五处全部退 0，其中四处还继续发出了破坏性调用。

**第五轮又指出射程仍有偏差**：按 (服务, 动词) 去重，同一 API 出现在多个阶段时只注入到
最先到达的那一处。改成按完整参数串枚举。

**第六轮指出这还不够**：删除前的探测与删除后的轮询是**完全相同的命令串**（AgentCore 与
DSQL 各一对），按串去重仍然只打第一次 ⇒ `wait_gone` 的 UNKNOWN 分支从没被打过。
证据是一次存活的变形：把那条 UNKNOWN 改成 `return 0`，当时 104 条**全绿**。
所以射程的键现在是 **(完整参数串, 第几次命中)**，stub 侧对应 `FAKE_FAIL_ON_NTH`。

四条不变量（与脚本头部一一对应）：

    ① 每一个**读**点：非 NotFound 故障 ⇒ 非零退出，且注入点之后没有任何破坏性调用
    ② 只删证明得了归属的资源（共享账号里 `site-*` 不是平台独占命名空间）
    ③ 破坏性步骤前的闸门（账号 + 站点已清空）无条件执行，`--stage` 不能绕
    ④ 异步操作等到服务说完成才算完成；等不到就非零退出、不打印"完成"

harness 用一个假的 `aws` 顶在 PATH 前面，把每次调用记进日志，并按 `FAKE_*` 注入故障。
判"破坏性"是 **fail-closed** 的：只读动词（get-/describe-/list-/head-/scan/wait/ls）
显式列举，**其余一切默认破坏性**。所以将来加了新的删除动作会自动进射程；
忘了登记也只会让它多被管一层，不会让它逃出去。
"""
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_SCRIPT = _ROOT / "site-builder" / "scripts" / "teardown_platform.sh"

# ── 只读 / 破坏性的判定：**fail-closed** ────────────────────────────────────
# 原来是一张人工维护的"破坏性关键词表"（`delete-` / `schedule-key-deletion` / …）。
# 它的失效方式是单向且无声的：**没进表的动作自动脱离射程**，于是
# `lambda remove-permission` / `s3api abort-multipart-upload` / `iam put-role-policy`
# 全都被判成"非破坏性"，"注入点之后没有破坏性调用"那条断言对它们形同不存在
# （Codex 第十轮 P1-3；这与第四轮列举点脱靶是同一形状）。
#
# 改成反过来：**只读动词显式列举，其余一切默认破坏性**。新增一种删除动作不必回来改表，
# 忘了改也只会让它进射程（安全方向），不会让它逃出去。
_READONLY_PREFIXES = ("get-", "describe-", "list-", "head-")
_READONLY_EXACT = ("scan", "wait", "ls")      # `aws s3 ls` 也是只读


def _verb_of(call):
    """call 可以是日志里的一行文本，也可以是 argv 列表。"""
    parts = call.split() if isinstance(call, str) else list(call)
    return parts[1] if len(parts) >= 2 else ""


def _is_readonly(call) -> bool:
    v = _verb_of(call)
    return v.startswith(_READONLY_PREFIXES) or v in _READONLY_EXACT


def _is_destructive(call) -> bool:
    return bool(_verb_of(call)) and not _is_readonly(call)


_ACCOUNT = "000000000000"
_PRIMARY_REGION = "us-east-1"
_ROUTER_STACK = "ApplicationWebRouterStack"
_SITE_IDS = ("demo-a1b2c3", "shop-d4e5f6")
# Edge 日志组在**每个执行区**都有一份；这里造三个区（含本区）来验跨区清理。
_REGIONS = ("us-east-1", "us-west-2", "ap-northeast-1")
# 归属清单内的 Edge 副本日志组（名字里的区是**归属区**，恒为 us-east-1）
_OWNED_EDGE_LG = f"/aws/lambda/{_PRIMARY_REGION}.{_ROUTER_STACK}-application-web-router"
# 账号里别人的 Edge 函数：DEPLOY.md 实测记过这种（redirectEdge），**删它是事故**
_FOREIGN_EDGE_LG = f"/aws/lambda/{_PRIMARY_REGION}.redirectEdge"
# 账号里的 KMS key：两把真的会话签名 key（site / console 两个 family）、
# 一把外来 key、一把已经在排期删除的。只有前两把该被 schedule-key-deletion。
# 自己的 AgentCore runtime 日志组：/aws/bedrock-agentcore/runtimes/{runtimeId}-{endpoint}
_OWNED_AGENTCORE_LG = "/aws/bedrock-agentcore/runtimes/site_builder_deploy-AAAA-DEFAULT"
_KMS_KEYS = ("key-site-1", "key-site-2", "key-foreign", "key-pending")
_KMS_SHOULD_SCHEDULE = {"key-site-1", "key-site-2"}

_SB_CONFIG = """\
[Platform]
base_domain = example.com
account_id = {account}
region = {region}
admin_seed = admin@example.com

[Cognito]
user_pool_id = us-east-1_platform

[DSQL]
cluster_endpoint = abcdefghij0123456789abcdef.dsql.us-east-1.on.aws

[Deployer]
jobs_table = site-deploy-jobs
sites_table = site-sites
admins_table = site-admins

[MCP]
endpoint_url = https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A{account}%3Aruntime%2Fsite_builder_deploy-AAAA/invocations?qualifier=DEFAULT

[IdP]
mode = cognito-admin
cognito_user_pool_name = site-builder-idp
""".format(account=_ACCOUNT, region=_PRIMARY_REGION)

_ROUTER_CONFIG = """\
[AWS]
account_id = %s
region = us-east-1

[CDK]
stack_name = %s
""" % (_ACCOUNT, _ROUTER_STACK)

# ---------------------------------------------------------------------------
# 假 aws。**报文形态照抄真 CLI**（见 test_stub_uses_real_cli_error_shapes）：
# 上一版 stub 把 head-bucket 的"不存在"编成 ResourceNotFoundException，而真 CLI 报的是
# `(404) ... : Not Found`（里面一个 NotFound 关键字都没有）⇒ 幂等那条测试是假绿，
# 真机上重跑一个已清空的账号会在前端桶处 hard-stop（Codex 第四轮 P2）。
#
# 开关：
#   FAKE_FAIL_ON / FAKE_FAIL_CODE  命中子串的调用按该错误码失败
#   FAKE_ALL_ABSENT                所有存在性探测报 NotFound（= 已经清干净的账号）
#   FAKE_ORPHAN_ROLES/_TABLES      preflight 的孤儿扫描发现残留
#   FAKE_UNOWNED_LOG_GROUP         日志组清单里混进一个共享账号里的无关 site-*
#   FAKE_ROUTER_DELETE_FAILED      router 栈删除失败（默认原因 = Edge 副本）
#   FAKE_DELETE_FAILED_REASON      改成别的失败原因
#   FAKE_MIXED_DELETE_FAILURE      Edge 副本 + 另一个真阻塞同时失败（不许被当成预期）
#   FAKE_STACK_NEVER_GONE          栈永远 DELETE_IN_PROGRESS（验轮询超时）
#   FAKE_STATUS_STALE_ONCE/_STUCK  删除尚未登记 / 卡在非 DELETE_* 状态
#   FAKE_DSQL_NEVER_GONE           cluster 删了但一直读得到（验轮询超时）
#   FAKE_RUNTIME_NEVER_GONE        AgentCore runtime 一直删不完（同上）
# ---------------------------------------------------------------------------
_FAKE_AWS = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_LOG"
# 再写一份**真实 argv**（\t 分隔，一行一次调用）。`$*` 把引号拍平了：
# 用它判 `--region` 会被行尾注释之类的东西骗过，也没法把带空格的 `--query` 原样取回来
# （Codex 第八轮 P1-2 / P2-3 都是这么绕过去的）。argv 日志是"实际执行了什么"的唯一真源。
{ printf '%s\t' "$@"; printf '\n'; } >> "$FAKE_LOG.argv"

# 退出码要能注入（Codex 第九轮 P1-1）。真实 aws-cli 2.36.34 本地实测：
#   服务返回错误 -> 254    waiter 失败 -> 255    CLI 解析失败 -> 252
# 原来恒 254 ⇒ `waited` 对 255 的处理从没被打过：在它里面加一条
# 「rc=255 直接成功返回」，waiter 专测加全读点注入共 76 条仍然全绿。
fail() { echo "aws: [ERROR]: An error occurred ($1) when calling the operation: injected" >&2
         exit "${FAKE_FAIL_RC:-254}"; }

# 各 API "不存在"时**真 CLI 的报文形态**。别改成统一的 ResourceNotFoundException——
# 那会把分类器的漏洞盖住（P2 就是这么漏的）。
absent() {
  case "$*" in
    *get-bucket-location*|*head-bucket*)
      echo "aws: [ERROR]: An error occurred (NoSuchBucket) when calling the GetBucketLocation operation: The specified bucket does not exist" >&2 ;;
    *describe-stacks*|*describe-stack-resources*)
      echo "aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id X does not exist" >&2 ;;
    *get-role*)
      echo "aws: [ERROR]: An error occurred (NoSuchEntity) when calling the GetRole operation: The role with name X cannot be found." >&2 ;;
    *get-parameter*)
      echo "aws: [ERROR]: An error occurred (ParameterNotFound) when calling the GetParameter operation: " >&2 ;;
    *describe-repositories*)
      echo "aws: [ERROR]: An error occurred (RepositoryNotFoundException) when calling the DescribeRepositories operation: The repository does not exist in the registry" >&2 ;;
    *get-function*)
      echo "aws: [ERROR]: An error occurred (ResourceNotFoundException) when calling the GetFunction operation: Function not found: arn:aws:lambda:x" >&2 ;;
    *get-topic-attributes*)
      # **真实 wire code 是 NotFound**（botocore 模型 error.code），不是异常类型名
      echo "aws: [ERROR]: An error occurred (NotFound) when calling the GetTopicAttributes operation: Topic does not exist" >&2 ;;
    *describe-user-pool*)
      echo "aws: [ERROR]: An error occurred (ResourceNotFoundException) when calling the DescribeUserPool operation: User pool does not exist." >&2 ;;
    *)
      echo "aws: [ERROR]: An error occurred (ResourceNotFoundException) when calling the operation: Requested resource not found" >&2 ;;
  esac
  exit 254
}

# FAKE_FAIL_ON_NTH：**第几次**命中才失败（默认 1 = 第一次）。
# 为什么需要它：删除前的探测与删除后的轮询是**完全相同的命令串**
# （AgentCore 与 DSQL 各一对），只按串注入永远打在第一次上，
# `wait_gone` 里那条 UNKNOWN 分支于是从没被打过——实测把它改成 `return 0`
# 全部 104 条仍然全绿（Codex 第六轮 P1-2）。
if [ -n "${FAKE_FAIL_ON:-}" ] && [[ "$*" == *"$FAKE_FAIL_ON"* ]]; then
  _cf="$FAKE_LOG.match-count"
  _n=$(( $(cat "$_cf" 2>/dev/null || echo 0) + 1 ))
  echo "$_n" > "$_cf"
  if [ "$_n" -eq "${FAKE_FAIL_ON_NTH:-1}" ]; then
    fail "${FAKE_FAIL_CODE:-AccessDeniedException}"
  fi
fi

if [ -n "${FAKE_ALL_ABSENT:-}" ]; then
  case "$*" in
    *get-caller-identity*) echo "$FAKE_ACCOUNT" ;;
    *describe-regions*)    echo "$FAKE_REGIONS" ;;
    *describe-table*|*get-function*|*get-role*|*get-parameter*|*describe-stacks*|\
    *describe-repositories*|*get-agent-runtime*|*get-cluster*|*describe-user-pool*|\
    *get-topic-attributes*|*get-bucket-location*) absent "$*" ;;
    *) echo "None" ;;
  esac
  exit 0
fi

# 一点点真实状态：删过之后再读就该报 NotFound
case "$*" in
  *"dsql delete-cluster"*)  : > "$FAKE_LOG.dsql-deleted" ;;
  *"dsql get-cluster"*)
      if [ -z "${FAKE_DSQL_NEVER_GONE:-}" ] && [ -f "$FAKE_LOG.dsql-deleted" ]; then absent "$*"; fi ;;
  *"delete-agent-runtime"*) : > "$FAKE_LOG.runtime-deleted" ;;
  *"get-agent-runtime"*)
      # DeleteAgentRuntime 是异步的（202 / status=DELETING）：删过之后 get 仍读得到，
      # 直到真的删完。FAKE_RUNTIME_NEVER_GONE 模拟"一直删不完"（验超时 hard-stop）。
      if [ -z "${FAKE_RUNTIME_NEVER_GONE:-}" ] && [ -f "$FAKE_LOG.runtime-deleted" ]; then absent "$*"; fi ;;
  *"cloudformation delete-stack"*) : > "$FAKE_LOG.stack-deleted" ;;
esac

# 栈状态查询（--query Stacks[0].StackStatus）必须排在通用 describe-stacks 之前
case "$*" in
  *StackStatus*)
      if [ -n "${FAKE_STATUS_STUCK:-}" ]; then echo "$FAKE_STATUS_STUCK"; exit 0; fi
      # 删除还没登记进 CFN 的那一瞬间：第一次查还是删除前的状态
      if [ -n "${FAKE_STATUS_STALE_ONCE:-}" ] && [ ! -f "$FAKE_LOG.stale-served" ]; then
        : > "$FAKE_LOG.stale-served"; echo "CREATE_COMPLETE"; exit 0
      fi
      if [ -n "${FAKE_STACK_NEVER_GONE:-}" ]; then echo "DELETE_IN_PROGRESS"; exit 0; fi
      if [ -n "${FAKE_ROUTER_DELETE_FAILED:-}" ] && [[ "$*" == *"$FAKE_ROUTER_STACK"* ]]; then
        echo "DELETE_FAILED"; exit 0
      fi
      if [ -f "$FAKE_LOG.stack-deleted" ]; then absent "$*"; fi
      echo "DELETE_IN_PROGRESS"; exit 0 ;;
  # 失败分类现在按**现状**（describe-stack-resources），不按事件历史。
  # 两个 length(...) 查询各自返回一个数；明细查询返回逐行的 逻辑ID<TAB>原因。
  *describe-stack-resources*)
      _edge=1; _all=1
      if [ -n "${FAKE_MIXED_DELETE_FAILURE:-}" ]; then _all=2; fi   # Edge 副本 + 另一个真阻塞
      if [ -n "${FAKE_DELETE_FAILED_REASON:-}" ]; then _edge=0; fi  # 原因不是 Edge 副本
      case "$*" in
        *"length(StackResources[?ResourceStatus=='DELETE_FAILED'])"*) echo "$_all"; exit 0 ;;
        *length*) echo "$_edge"; exit 0 ;;
      esac
      # 明细（只在 die 那条路上被调用）
      printf 'OriginRequestFunction1A2B\t%s\n' \
        "Lambda was unable to delete arn:…:function:y:1 because it is a replicated function."
      if [ -n "${FAKE_MIXED_DELETE_FAILURE:-}" ]; then
        printf 'ArtifactsBucket9Z\t%s\n' "The bucket you tried to delete is not empty"
      fi
      if [ -n "${FAKE_DELETE_FAILED_REASON:-}" ]; then
        printf 'SomeOtherResource7Q\t%s\n' "${FAKE_DELETE_FAILED_REASON}"
      fi
      exit 0 ;;
esac

# 默认：平台件全在，站点侧已清空
case "$*" in
  *get-caller-identity*)                 echo "$FAKE_ACCOUNT" ;;
  # preflight 的孤儿扫描：默认没有残留
  *"starts_with(RoleName"*)
      if [ -n "${FAKE_ORPHAN_ROLES:-}" ]; then echo "site-rt-demo-a1b2c3"; else echo "None"; fi ;;
  *"starts_with(@,"*)
      if [ -n "${FAKE_ORPHAN_TABLES:-}" ]; then echo "site-data-demo-a1b2c3-notes"; else echo "None"; fi ;;
  *"scan --table-name site-sites"*)      echo "$FAKE_SITE_IDS" ;;
  *"Table.DeletionProtectionEnabled"*)   echo "True" ;;
  # 回真的策略名，否则下面两条清理循环体永远不执行 ⇒ delete-role-policy /
  # detach-role-policy 不在射程内（新加的可达性守卫抓到的）
  *list-role-policies*)                  echo "inline-1" ;;
  *list-attached-role-policies*)         echo "arn:aws:iam::aws:policy/Managed1" ;;
  *describe-alarms*)                     echo "site-builder-auth-invalid-grant" ;;
  *list-user-pools*)                     echo "us-east-1_idp" ;;
  *"UserPool.Domain"*)                   echo "some-prefix" ;;
  # 真实部署里**至少两把** CMK（site / console 两个 key family）。夹具必须能区分
  # "两把都删了"和"删了第一把就 break"（Codex 第十一轮 P1-2）。
  # 另外放一把外来 key 与一把已排期的，验"不该动的不动"。
  *list-keys*)                           echo "$FAKE_KMS_KEYS" ;;
  *describe-key*)
      case "$*" in
        *key-site-1*) echo -e "Enabled\tsite-builder session signing key site-rs-v1" ;;
        *key-site-2*) echo -e "Enabled\tsite-builder session signing key console-rs-v1" ;;
        *key-pending*) echo -e "PendingDeletion\tsite-builder session signing key site-rs-v0" ;;
        *)            echo -e "Enabled\tsomebody elses key" ;;
      esac ;;
  *describe-regions*)                    echo "$FAKE_REGIONS" ;;
  # 带 --log-group-name-prefix 的那次是**跨区扫 Edge 副本**：只回 Edge 形态的名字，
  # 其中一个是别人的（DEPLOY.md 实测见过 redirectEdge）——它必须不被删。
  *--log-group-name-prefix*)
      echo "$FAKE_OWNED_EDGE_LG $FAKE_FOREIGN_EDGE_LG" ;;
  *describe-log-groups*)
      # 本区：平台自己的 + 每个 site_id 的 + 本区那份 Edge 副本；
      # FAKE_UNOWNED_LOG_GROUP 再混进一个别人的
      # 每一条归属规则都要有正例，否则那条规则拼错了也看不出来（Codex 第十三轮 P2-4）：
      #   精确名 / CodeBuild 精确名 / AgentCore runtime 前缀 / deployer 栈前缀 /
      #   site-deployer- 前缀 / Edge 副本 / per-site
      out="/aws/lambda/site-panel /aws/codebuild/site-package $FAKE_OWNED_EDGE_LG"
      out="$out $FAKE_OWNED_AGENTCORE_LG /aws/lambda/site-deployer-validate"
      out="$out /aws/lambda/site-access-rollup"
      for s in $FAKE_SITE_IDS; do out="$out /aws/lambda/site-$s"; done
      if [ -n "${FAKE_UNOWNED_LOG_GROUP:-}" ]; then out="$out ${FAKE_UNOWNED_LOG_GROUP}"; fi
      echo "$out" ;;
  *)                                     echo "None" ;;
esac
exit 0
"""


_FAKE_ENV_KEYS = (
    "FAKE_FAIL_ON", "FAKE_FAIL_ON_NTH", "FAKE_FAIL_CODE", "FAKE_FAIL_RC", "FAKE_ALL_ABSENT",
    "FAKE_ORPHAN_ROLES", "FAKE_ORPHAN_TABLES", "FAKE_UNOWNED_LOG_GROUP",
    "FAKE_ROUTER_DELETE_FAILED", "FAKE_DELETE_FAILED_REASON",
    "FAKE_MIXED_DELETE_FAILURE", "FAKE_STACK_NEVER_GONE", "FAKE_DSQL_NEVER_GONE",
    "FAKE_RUNTIME_NEVER_GONE", "FAKE_STATUS_STALE_ONCE", "FAKE_STATUS_STUCK",
)


def _split_argv(line: str) -> list:
    """把 argv 日志的一行切回参数表，**保留空参数**。

    `printf '%s\t' "$@"` 会在末尾多出一个空元素，只丢那一个。原来用 `if a` 过滤掉
    全部空串，于是 `--region ""` 这种形态根本看不出来（Codex 第九轮 P1-2 的后半）。
    参数本身含 `\t` 的情况本脚本不存在。
    """
    parts = line.split("\t")
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def _build_sandbox(root: Path):
    """在 root 下搭一个假仓库（config.ini + 假 aws），返回 runner。

    模块级的射程收集与 `harness` fixture 共用它——收集用的沙箱必须和测试用的
    完全一样，否则"射程"和"实际跑的东西"会悄悄分叉。
    """
    sb = root / "site-builder"
    (sb / "scripts").mkdir(parents=True)
    (root / "router").mkdir()
    (sb / "config.ini").write_text(_SB_CONFIG, encoding="utf-8")
    (root / "router" / "config.ini").write_text(_ROUTER_CONFIG, encoding="utf-8")
    shutil.copy(_SCRIPT, sb / "scripts" / "teardown_platform.sh")
    os.chmod(sb / "scripts" / "teardown_platform.sh", 0o755)

    bin_dir = root / "fakebin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(_FAKE_AWS, encoding="utf-8")
    os.chmod(aws, 0o755)
    log = root / "aws-calls.log"
    log.write_text("", encoding="utf-8")

    def run(*args, env=None):
        log.write_text("", encoding="utf-8")
        for marker in root.glob("aws-calls.log.*"):
            marker.unlink()
        e = dict(os.environ)
        e["PATH"] = f"{bin_dir}{os.pathsep}{os.path.dirname(sys.executable)}{os.pathsep}{e['PATH']}"
        e["FAKE_LOG"] = str(log)
        e["FAKE_ACCOUNT"] = _ACCOUNT
        e["FAKE_ROUTER_STACK"] = _ROUTER_STACK
        e["FAKE_SITE_IDS"] = " ".join(_SITE_IDS)
        e["FAKE_REGIONS"] = " ".join(_REGIONS)
        e["FAKE_KMS_KEYS"] = " ".join(_KMS_KEYS)
        e["FAKE_OWNED_EDGE_LG"] = _OWNED_EDGE_LG
        e["FAKE_OWNED_AGENTCORE_LG"] = _OWNED_AGENTCORE_LG
        e["FAKE_FOREIGN_EDGE_LG"] = _FOREIGN_EDGE_LG
        for k in _FAKE_ENV_KEYS:
            e.pop(k, None)
        # 默认把轮询压掉：这些用例不验时间，只验状态机。验超时的那条自己覆盖回来。
        e.setdefault("TEARDOWN_POLL_TRIES", "2")
        e.setdefault("TEARDOWN_POLL_SLEEP", "0")
        e.setdefault("TEARDOWN_STACK_POLL_TRIES", "3")
        e.setdefault("TEARDOWN_STACK_POLL_SLEEP", "0")
        e.update(env or {})
        proc = subprocess.run(
            ["bash", str(sb / "scripts" / "teardown_platform.sh"), *args],
            capture_output=True, text=True, env=e, cwd=str(root))
        calls = [l for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
        argv_log = Path(f"{log}.argv")
        run.argv = [_split_argv(l)
                    for l in (argv_log.read_text(encoding="utf-8").splitlines()
                              if argv_log.exists() else []) if l.strip()]
        return proc, calls

    run.argv = []
    return run


@pytest.fixture
def harness(tmp_path):
    return _build_sandbox(tmp_path)


def _destructive(calls):
    return [c for c in calls if _is_destructive(c)]


# ---------------------------------------------------------------------------
# 射程：**按调用点枚举**，不按 (服务, 动词) 去重
#
# 第四轮改成扫源码，把列举点纳进来了，但按 (service, verb) 去重仍有偏差
# （Codex 第五轮指出）：同一个 API 出现在多个阶段时，故障只注入到**最先到达**的那一处。
# 例如 `dynamodb describe-table` 在 preflight（sites 表）与 orphans（四张 RETAIN 表）
# 各有调用点，去重后只有 preflight 那处进了射程。
#
# 现在改成：先跑几个场景，把**每一条实际发出的读调用（完整参数串）**收集下来逐个注入。
# 完整参数串天然区分了 `--table-name site-sites` 与 `--table-name site-admins`，
# 于是每个调用点各被打一次。源码扫描保留为**覆盖率交叉核对**——它负责抓
# "源码里有、但任何场景都到不了"的读点（那种读点的故障行为完全没被验证过，
# 而它看起来和"已覆盖"一模一样）。
# ---------------------------------------------------------------------------
# `wait` 必须在里面（Codex 第八轮 P1-1）：`aws dynamodb wait table-not-exists` 是
# 一次**读**（轮询状态），漏掉它等于两个 waiter 都不在故障注入射程内——
# 给其中一个加 `|| true` 时全部 123 条照样全绿。
_READ_VERB = re.compile(r"^(get|describe|list|head)-|^scan$|^wait$")
_AWS_CALL = re.compile(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)")

# 收集射程用的场景：default 覆盖绝大多数，另两个把只在特定状态下才走到的读点造出来。
_COLLECT_SCENARIOS = {
    "default": {},
    "router-delete-failed": {"FAKE_ROUTER_DELETE_FAILED": "1"},
    "sites-table-gone": {"FAKE_ALL_ABSENT": "1"},
    # 这两条走的是**死路**（栈分类判定为"不只是 Edge 副本"⇒ hard-stop）。
    # 加它们是因为"失败明细"那第三次 describe-stack-resources 只在死路上被调用，
    # 之前整个不在射程里，而源码交叉核对按 (服务, 动词) 被前两次计数查询掩盖了
    # （Codex 第八轮 P2-4）。
    "mixed-delete-failure": {"FAKE_ROUTER_DELETE_FAILED": "1",
                             "FAKE_MIXED_DELETE_FAILURE": "1"},
    "unexpected-delete-failure": {"FAKE_ROUTER_DELETE_FAILED": "1",
                                  "FAKE_DELETE_FAILED_REASON": "bucket is not empty"},
}


def _is_read_call(call: str) -> bool:
    parts = call.split()
    return len(parts) >= 2 and bool(_READ_VERB.match(parts[1]))


def _collect_read_points():
    """跑几个场景，收集**每一次**读调用 → (完整参数串, 第几次命中) → 需要哪个场景。

    **为什么键里必须带"第几次"**（Codex 第六轮 P1-2）：删除前的探测与删除后的轮询
    是完全相同的命令串（AgentCore 与 DSQL 各一对），只按串去重就只会打到第一次，
    于是 `wait_gone` 里那条 UNKNOWN 分支从没被打过——实测把它改成 `return 0`，
    当时全部 104 条仍然全绿。带上次序之后，删除后那一次是独立的注入点。
    """
    tmp = Path(tempfile.mkdtemp(prefix="teardown-scope-"))
    try:
        run = _build_sandbox(tmp)
        points = {}
        for name, env in _COLLECT_SCENARIOS.items():
            _, calls = run("--yes", env=env)
            seen = {}
            for c in calls:
                if not _is_read_call(c):
                    continue
                seen[c] = seen.get(c, 0) + 1
                points.setdefault((c, seen[c]), name)
        return points
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_ALL_EXECUTED_ARGV: list = []


def _collect_all_argv():
    """把所有收集场景里**实际执行过的 argv** 汇总一份（可达性守卫用）。"""
    tmp = Path(tempfile.mkdtemp(prefix="teardown-argv-"))
    try:
        run = _build_sandbox(tmp)
        out = []
        for env in _COLLECT_SCENARIOS.values():
            run("--yes", env=env)
            out.extend(run.argv)
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_READ_POINTS = _collect_read_points()
_ALL_EXECUTED_ARGV = _collect_all_argv()
_READ_POINT_IDS = sorted(_READ_POINTS)


def _short_id(point) -> str:
    """短 id：服务 动词 + 第一个具体取值 + 第几次。"""
    call, nth = point
    parts = call.split()
    tail = next((p for p in parts[2:] if not p.startswith("--")), "")
    base = "-".join(p for p in (parts[0], parts[1], tail) if p)[:64]
    return f"{base}#{nth}"


def test_scope_collection_actually_found_the_call_points():
    """元测试：射程收集不能悄悄收空——否则下面那个参数化会**零用例通过**。

    另外钉住"同一 API 的多个调用点各自单独在射程里"这件事本身：
    `describe-table` 至少 5 处（sites 表 + 四张 RETAIN 表），`get-role` 至少 5 处。
    """
    assert len(_READ_POINTS) >= 40, f"只收到 {len(_READ_POINTS)} 个调用点:\n{_READ_POINT_IDS}"
    calls = [c for (c, _n) in _READ_POINTS]
    tables = [c for c in calls if "dynamodb describe-table" in c]
    assert len(tables) >= 5, f"describe-table 的调用点没被分开:\n{tables}"
    roles = [c for c in calls if "iam get-role " in c]
    assert len(roles) >= 5, f"get-role 的调用点没被分开:\n{roles}"


def test_source_scan_has_no_read_point_outside_the_range():
    """交叉核对：源码里每个 (服务, 动词) 都必须至少有一个调用点进了射程。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    in_source = {(s, v) for s, v in _AWS_CALL.findall(src) if _READ_VERB.match(v)}
    assert len(in_source) >= 15, in_source
    calls = [c for (c, _n) in _READ_POINTS]
    missing = [f"{s} {v}" for s, v in sorted(in_source)
               if not any(f"{s} {v}" in c for c in calls)]
    assert missing == [], (
        "这些读点在源码里，但任何场景都没跑到 ⇒ 它们的故障行为没被验证过。"
        "给 _COLLECT_SCENARIOS 加个能到达它的场景，或确认它是死代码：\n  "
        + "\n  ".join(missing))


@pytest.mark.parametrize("point", _READ_POINT_IDS, ids=_short_id)
def test_every_read_point_hard_stops_on_non_notfound(harness, point):
    """不变量 ①：**每一个调用点（含删除后轮询那一次）**上的非 NotFound 故障都必须
    非零退出，且注入点之后没有任何破坏性调用。

    **只打一种错误码**（AccessDenied），不是省事：错误码唯一起作用的地方是
    `_is_absent_err`，它对码的分类由 `test_probe_classifies_only_notfound_as_absent`
    在最小单位上逐码断言，`test_non_notfound_error_stops_later_stages_too` 再跑一遍四种码。
    在这里乘以码数只会把套件墙钟翻倍（实测 2 分钟 → 4 分半），不增加任何覆盖。
    """
    needle, nth = point
    env = {"FAKE_FAIL_ON": needle, "FAKE_FAIL_ON_NTH": str(nth),
           "FAKE_FAIL_CODE": "AccessDeniedException"}
    env.update(_COLLECT_SCENARIOS[_READ_POINTS[point]])
    proc, calls = harness("--yes", env=env)
    hits = [i for i, c in enumerate(calls) if needle in c]
    assert len(hits) >= nth, (
        f"第 {nth} 次命中没发生（只命中 {len(hits)} 次）:\n" + "\n".join(calls))
    idx = hits[nth - 1]
    assert proc.returncode != 0, (
        f"{needle}（第 {nth} 次）遇到 AccessDenied 却退 0 —— UNKNOWN 被当成了 ABSENT\n{proc.stdout}")
    after = _destructive(calls[idx:])
    assert after == [], f"{needle}（第 {nth} 次）之后仍发出破坏性调用: {after}"


@pytest.mark.parametrize("needle,stage", [
    ("bedrock-agentcore-control get-agent-runtime", "scripts"),
    ("dsql get-cluster", "dsql"),
])
def test_unknown_after_delete_is_a_hard_stop(harness, needle, stage):
    """点名钉住 `wait_gone` 的 UNKNOWN 分支：**删除请求已经发出之后**读不到状态，
    必须 hard-stop，不能当成"删成功了"。

    这两处是删除前探测与删除后轮询用同一条命令的地方，所以只按命令串注入打不到
    第二次——那正是这条不变量长期没被验证的原因。
    """
    proc, calls = harness("--yes", "--stage", stage,
                          env={"FAKE_FAIL_ON": needle, "FAKE_FAIL_ON_NTH": "2",
                               "FAKE_FAIL_CODE": "AccessDeniedException"})
    assert proc.returncode != 0, (
        f"删除后读不到 {needle} 的状态却退 0 —— 那是把 UNKNOWN 当成删成功\n{proc.stdout}")
    # 删除请求本身应该已经发出（否则这条测的不是"删除后"）
    assert any("delete-" in c for c in calls), calls
    # 而且命中的确实是第二次
    assert len([c for c in calls if needle in c]) >= 2, calls


def test_die_path_calls_are_in_range():
    """元测试：只在**死路**上才发生的读调用也必须进射程。

    栈分类的第三次 `describe-stack-resources`（失败明细）只在"不只是 Edge 副本 ⇒
    hard-stop"那条路上被调用。之前它整个不在 `_READ_POINTS` 里，而源码交叉核对按
    (服务, 动词) 被前两次计数查询掩盖了（Codex 第八轮 P2-4）。
    所以这里按**调用点数量**核对：两条计数 + 一条明细 = 至少 3 个不同调用点。
    """
    dsr = {c for (c, _n) in _READ_POINTS if "describe-stack-resources" in c}
    assert len(dsr) >= 3, (
        "describe-stack-resources 只收到 %d 个调用点（应 ≥3：两条计数 + 一条失败明细）。"
        "很可能是 _COLLECT_SCENARIOS 里少了走死路的场景：\n  %s"
        % (len(dsr), "\n  ".join(sorted(dsr))))


def test_post_delete_polls_are_separately_in_range():
    """元测试：那两对"删除前/删除后同一条命令"必须各自以第 2 次出现在射程里。

    少了这条，射程一旦退回按命令串去重，`wait_gone` 的 UNKNOWN 分支会再次静默失守。
    """
    seconds = {c for (c, n) in _READ_POINTS if n >= 2}
    for must in ("bedrock-agentcore-control get-agent-runtime", "dsql get-cluster"):
        assert any(must in c for c in seconds), (
            f"{must} 的删除后轮询没作为独立注入点进射程:\n{sorted(seconds)}")


# ---------------------------------------------------------------------------
# 基线：两种"正常"形态
# ---------------------------------------------------------------------------

def test_dry_run_makes_no_destructive_call(harness):
    """--dry-run 一条破坏性调用都不该真发出去（否则"先看一眼"是个陷阱）。"""
    proc, calls = harness("--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert _destructive(calls) == [], _destructive(calls)


def test_refuses_without_yes(harness):
    """不带 --yes 必须拒绝，且拒绝发生在任何破坏性调用之前。"""
    proc, calls = harness()
    assert proc.returncode != 0
    assert _destructive(calls) == []


def test_already_clean_account_is_idempotent(harness):
    """全 NotFound（= 重跑一个已经清干净的账号）：退 0、无破坏性调用、跑完所有阶段。

    stub 用的是**真 CLI 的报文形态**（尤其桶那条），所以这条现在真的能证明幂等。
    """
    proc, calls = harness("--yes", env={"FAKE_ALL_ABSENT": "1"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _destructive(calls) == [], _destructive(calls)
    for stage in ("preflight", "scripts", "dsql", "stacks", "orphans"):
        assert stage in proc.stdout, f"{stage} 没跑到:\n{proc.stdout}"


def test_happy_path_deletes_things(harness):
    """正对照：一切 PRESENT 时**确实**发出了破坏性调用。
    少了这条，上面那些"没有破坏性调用"的断言可以靠"脚本什么都不做"通过。"""
    proc, calls = harness("--yes")
    assert proc.returncode == 0, proc.stderr
    d = " ".join(_destructive(calls))
    for expected in ("delete-function", "delete-user-pool", "delete-parameter",
                     "delete-stack", "delete-table", "schedule-key-deletion",
                     "delete-log-group"):
        assert expected in d, f"没发出 {expected}:\n{d}"


def test_stub_emits_the_real_cli_error_prefix():
    """假 aws 的每条报文都必须带真 CLI 的 `aws: [ERROR]: ` 前缀（实测 aws-cli 2.36.34）。

    这是**整套测试的射程前提**，也是第十九轮那条真回归的根：stub 之前直接从
    `An error occurred (` 起写，于是"把外层前缀锚死在行首"这个改动**在 300 条里全绿**，
    而真机 stderr 是

        aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id X does not exist

    ⇒ 真的"栈不存在"被判 UNKNOWN ⇒ 已清空的账号在 stacks 阶段 hard-stop（幂等回归）。
    前缀留在 stub 里，任何"按行首锚定"的写法都会在这套测试里立刻红。
    """
    emits = [l for l in _FAKE_AWS.splitlines() if "An error occurred (" in l]
    assert len(emits) >= 10, f"stub 里的报文点只找到 {len(emits)} 处，射程可疑"
    missing = [l.strip()[:90] for l in emits if "aws: [ERROR]: An error occurred (" not in l]
    assert missing == [], (
        "假 aws 有报文没带真 CLI 前缀 —— 会让「按行首锚定」的分类器假绿：\n  "
        + "\n  ".join(missing))


def test_stub_uses_real_cli_error_shapes():
    """把真 CLI 的两条报文形态钉住（实测 aws-cli 2.36.34）。

    · `s3api head-bucket` 桶不存在 ⇒ `An error occurred (404) ... : Not Found`
      —— 里面**没有**任何 NotFound 关键字，所以脚本改用 get-bucket-location。
    · `s3api get-bucket-location` 桶不存在 ⇒ `(NoSuchBucket) ... does not exist`

    这条是 P2 的回归守卫：stub 一旦又把桶的"不存在"编成 ResourceNotFoundException，
    分类器的漏洞就再看不见了。
    """
    # 判的是**实际调用**，不是全文——那条注释里必须能提到 head-bucket 讲清为什么不用它
    assert "aws s3api head-bucket" not in _SCRIPT.read_text(encoding="utf-8"), (
        "脚本又用回 head-bucket 了：它的 404 报文不含 NotFound 关键字，"
        "会把「已清空账号重跑」变成 hard-stop")
    assert "NoSuchBucket" in _FAKE_AWS and "does not exist" in _FAKE_AWS


# ---------------------------------------------------------------------------
# 不变量 ③：preflight 是闸门，--stage 不能绕
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stage", ["scripts", "dsql", "stacks", "orphans"])
def test_wrong_account_blocks_every_stage(harness, stage):
    """**任何**破坏性阶段在账号不符时都必须拒绝。

    第四轮 P1-1：preflight 曾是 STAGES 里的一员，于是 `--stage stacks`
    （脚本自己在收尾里推荐的 router 重试命令）整个绕过账号核对——实测在错误账号上
    get-caller-identity 一次都没调用，照发两条 delete-stack 并退 0。
    """
    proc, calls = harness("--yes", "--stage", stage,
                          env={"FAKE_ACCOUNT": "999999999999"})
    assert proc.returncode != 0, f"错误账号下 --stage {stage} 竟然退 0:\n{proc.stdout}"
    assert any("get-caller-identity" in c for c in calls), "根本没核对账号"
    assert _destructive(calls) == [], _destructive(calls)


@pytest.mark.parametrize("stage", ["scripts", "dsql", "stacks", "orphans"])
def test_orphan_sites_block_every_stage(harness, stage):
    """站点侧有残留时，**任何**破坏性阶段都必须拒绝（同样不能靠 --stage 绕过）。"""
    proc, calls = harness("--yes", "--stage", stage, env={"FAKE_ORPHAN_ROLES": "1"})
    assert proc.returncode != 0, proc.stdout
    assert "站点侧还有资源没清掉" in proc.stderr, proc.stderr
    assert _destructive(calls) == [], _destructive(calls)


def test_preflight_only_deletes_nothing(harness):
    """`--stage preflight` 是"只体检"：跑完退 0，什么都不删。"""
    proc, calls = harness("--yes", "--stage", "preflight")
    assert proc.returncode == 0, proc.stderr
    assert _destructive(calls) == [], _destructive(calls)
    for later in ("scripts：", "dsql：", "stacks：", "orphans："):
        assert later not in proc.stdout


# ---------------------------------------------------------------------------
# 不变量 ①（补充）：早阶段的 UNKNOWN 必须挡住后面所有阶段
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException",
                                  "RequestTimeout", "ValidationException"])
def test_non_notfound_error_stops_later_stages_too(harness, code):
    """整轮跑时，早阶段的 UNKNOWN 必须挡住**后面所有阶段**。
    只 break / 只打印提示都不算——那是 fail-open。"""
    proc, calls = harness("--yes", env={"FAKE_FAIL_ON": "get-agent-runtime",
                                        "FAKE_FAIL_CODE": code})
    assert proc.returncode != 0
    assert _destructive(calls) == [], _destructive(calls)
    for later in ("dsql：", "stacks：", "orphans："):
        assert later not in proc.stdout, f"{code} 之后仍进入了 {later}\n{proc.stdout}"


# ---------------------------------------------------------------------------
# 不变量 ②：只删证明得了归属的资源
# ---------------------------------------------------------------------------

def test_unowned_log_group_is_reported_not_deleted(harness):
    """共享账号里别人的 `site-*` 日志组**必须不被删**（第四轮 P1-4，实测复现过）。

    资产明确支持共享账号（DEPLOY.md §0），`/aws/lambda/site-*` 不是平台独占命名空间。
    """
    foreign = "/aws/lambda/site-unrelated-payments"
    proc, calls = harness("--yes", env={"FAKE_UNOWNED_LOG_GROUP": foreign})
    assert proc.returncode == 0, proc.stderr
    deleted = [c for c in calls if "delete-log-group" in c]
    assert not any(foreign in c for c in deleted), f"删了别人的日志组: {deleted}"
    assert foreign in proc.stdout, "既没删也没报告 —— 那就是无声地漏掉了"
    # 正对照：自己的照删（否则"没删别人的"可以靠"谁的都不删"通过）
    assert any("/aws/lambda/site-panel" in c for c in deleted), deleted
    assert any(f"/aws/lambda/site-{_SITE_IDS[0]}" in c for c in deleted), deleted


def test_agentcore_log_groups_are_not_wildcarded(harness):
    """`/aws/bedrock-agentcore/runtimes/*` 是账号里**所有** runtime，不能整片删。"""
    foreign = "/aws/bedrock-agentcore/runtimes/someone-elses-runtime-DEFAULT"
    proc, calls = harness("--yes", env={"FAKE_UNOWNED_LOG_GROUP": foreign})
    assert proc.returncode == 0, proc.stderr
    assert not any(foreign in c for c in calls if "delete-log-group" in c)
    assert foreign in proc.stdout


def test_per_site_log_groups_need_the_sites_table(harness):
    """sites 表没了 ⇒ 枚举不出 site_id ⇒ per-site 日志组只报告不删除。

    "表不存在就按已清理处理"曾经是个假绿（第四轮 P1-2 的前半）。
    """
    proc, calls = harness("--yes", env={"FAKE_ALL_ABSENT": "1",
                                        "FAKE_UNOWNED_LOG_GROUP": ""})
    assert proc.returncode == 0, proc.stderr
    assert "无法枚举 site_id" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# 不变量 ④：异步操作要等到服务说完成
# ---------------------------------------------------------------------------

def test_dsql_poll_timeout_is_a_hard_stop(harness):
    """cluster 删了但一直读得到（轮询耗尽）⇒ 必须非零退出，**不能**接着去删栈。"""
    proc, calls = harness("--yes", "--stage", "dsql",
                          env={"TEARDOWN_POLL_TRIES": "3", "TEARDOWN_POLL_SLEEP": "0",
                               "FAKE_DSQL_NEVER_GONE": "1"})
    assert proc.returncode != 0, f"轮询耗尽却退 0:\n{proc.stdout}\n{proc.stderr}"
    assert "超时" in proc.stdout + proc.stderr, proc.stdout + proc.stderr


def test_stacks_are_waited_for_not_fired_and_forgotten(harness):
    """删栈之后必须**核对状态**，不能发完异步调用就往下走（第四轮 P1-5）。"""
    proc, calls = harness("--yes", "--stage", "stacks")
    assert proc.returncode == 0, proc.stderr
    for st in (_ROUTER_STACK, "SiteDeployerStack"):
        del_idx = next(i for i, c in enumerate(calls)
                       if "delete-stack" in c and st in c)
        assert any("StackStatus" in c and st in c for c in calls[del_idx:]), (
            f"{st}: delete-stack 之后没有任何状态核对")
        assert f"栈 {st} 已删除" in proc.stdout, proc.stdout


def test_router_expected_failure_is_incomplete_not_success(harness):
    """router 栈第一次必定 DELETE_FAILED（Edge 副本）。**预期 ≠ 完成**：整轮必须退 3。"""
    proc, calls = harness("--yes", env={"FAKE_ROUTER_DELETE_FAILED": "1"})
    assert proc.returncode == 3, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    assert "还没完" in proc.stdout, proc.stdout
    assert "== 完成" not in proc.stdout, "既然没删完就不能打印完成"
    # orphans 仍然要跑完（孤儿 CMK 是能签会话的 key，值得当轮清掉）
    assert "orphans：" in proc.stdout, proc.stdout
    assert any("schedule-key-deletion" in c for c in calls), calls


def test_mixed_delete_failure_is_not_excused_as_edge_replicas(harness):
    """**混合失败必须 hard-stop**（Codex 第五轮 P1-2，实测复现过）。

    Edge 副本 + 桶非空同时存在时，原先只要"任一条原因提到 replicated function"
    就退 3，把真正的阻塞藏了起来。判据现在是"当前**所有** DELETE_FAILED 资源
    都必须是那两个 Edge 函数、且原因都匹配"。
    """
    proc, calls = harness("--yes", env={"FAKE_ROUTER_DELETE_FAILED": "1",
                                        "FAKE_MIXED_DELETE_FAILURE": "1"})
    assert proc.returncode == 1, f"rc={proc.returncode}（3 = 又被当成预期失败放过了）\n{proc.stdout}"
    assert "不只是" in proc.stderr, proc.stderr
    # 明细要打出来，否则运维不知道真正的阻塞是什么
    assert "not empty" in proc.stderr, proc.stderr
    assert "orphans：" not in proc.stdout, "未查清的失败之后不该继续删东西"


def test_classification_uses_current_state_not_event_history(harness):
    """判据必须来自**现状**（describe-stack-resources），不能来自事件历史。

    describe-stack-events 含前几次尝试留下的 DELETE_FAILED，用它分类会把
    "上次失败、这次成功"与"这次仍失败"混为一谈。
    """
    proc, calls = harness("--yes", env={"FAKE_ROUTER_DELETE_FAILED": "1"})
    assert any("describe-stack-resources" in c for c in calls), calls
    assert not any("describe-stack-events" in c for c in calls), (
        "又回去读事件历史了：" + str([c for c in calls if "describe-stack-events" in c]))


def test_unexpected_stack_failure_is_a_hard_stop(harness):
    """DELETE_FAILED 但原因**不是** Edge 副本 ⇒ hard-stop。"""
    proc, calls = harness("--yes", env={
        "FAKE_ROUTER_DELETE_FAILED": "1",
        "FAKE_DELETE_FAILED_REASON": "The bucket you tried to delete is not empty"})
    assert proc.returncode == 1, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    assert "orphans：" not in proc.stdout, "未知原因的失败之后不该继续删东西"


def test_stack_poll_timeout_is_a_hard_stop(harness):
    """栈一直 DELETE_IN_PROGRESS（轮询耗尽）⇒ 非零退出，不进 orphans。"""
    proc, calls = harness("--yes", env={"FAKE_STACK_NEVER_GONE": "1",
                                        "TEARDOWN_STACK_POLL_TRIES": "2",
                                        "TEARDOWN_STACK_POLL_SLEEP": "0"})
    assert proc.returncode != 0
    assert "超时" in proc.stdout + proc.stderr
    assert "DELETE_IN_PROGRESS" in proc.stderr, "超时报文要带上最后看到的状态才可诊断"
    assert "orphans：" not in proc.stdout


def test_status_read_before_delete_registers_is_not_a_hard_stop(harness):
    """`delete-stack` 是异步的：紧接着的第一次轮询可能还读到删除前的状态。

    那**不能**当成硬错误——否则真机上会随机假红。这里让第一次轮询报 CREATE_COMPLETE，
    之后才进入删除流程，脚本必须等下去并正常收尾。
    """
    proc, calls = harness("--yes", env={"FAKE_STATUS_STALE_ONCE": "1"})
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert "等它进入删除流程" in proc.stdout, proc.stdout
    assert "orphans：" in proc.stdout


def test_stuck_non_delete_status_still_times_out(harness):
    """反面：状态**一直**不是 DELETE_*（真卡住）时，必须由超时兜住并带上那个状态。

    少了这条，上面那条"再等等"就等于把未知状态永久放过。
    """
    proc, calls = harness("--yes", env={"FAKE_STATUS_STUCK": "UPDATE_ROLLBACK_FAILED",
                                        "TEARDOWN_STACK_POLL_TRIES": "2",
                                        "TEARDOWN_STACK_POLL_SLEEP": "0"})
    assert proc.returncode != 0
    assert "UPDATE_ROLLBACK_FAILED" in proc.stderr, proc.stderr
    assert "orphans：" not in proc.stdout


# ---------------------------------------------------------------------------
# 最小单位：probe 的分类
# ---------------------------------------------------------------------------

def _run_is_absent(svc, op, errtext):
    """把脚本里的 `_absent_codes` + `_is_absent_err` 切出来跑一次，返回是否判 ABSENT。"""
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_absent_codes() {"):script.index("# probe <描述>")]
    prog = textwrap.dedent("""
        set -uo pipefail
        %s
        if _is_absent_err "$1" "$2" "$3"; then echo ABSENT; else echo NOT_ABSENT; fi
    """) % body
    out = subprocess.run(["bash", "-c", prog, "_", svc, op, errtext],
                         capture_output=True, text=True)
    assert out.stdout.strip() in ("ABSENT", "NOT_ABSENT"), out.stderr
    return out.stdout.strip() == "ABSENT"


def _err(code, op="TheOperation"):
    # 带真 CLI 前缀（实测 aws-cli 2.36.34 的 stderr 是 `aws: [ERROR]: An error occurred (…`）
    return f"aws: [ERROR]: An error occurred ({code}) when calling the {op} operation: something"


# (service, operation, 该操作真正的 NotFound 报文) —— 必须判 ABSENT
_ABSENT_CASES = [
    ("dynamodb", "describe-table", _err("ResourceNotFoundException")),
    ("dynamodb", "scan", _err("ResourceNotFoundException")),
    ("iam", "get-role", _err("NoSuchEntity")),
    ("lambda", "get-function", _err("ResourceNotFoundException")),
    ("lambda", "get-function-url-config", _err("ResourceNotFoundException")),
    ("ecr", "describe-repositories", _err("RepositoryNotFoundException")),
    ("bedrock-agentcore-control", "get-agent-runtime", _err("ResourceNotFoundException")),
    ("dsql", "get-cluster", _err("ResourceNotFoundException")),
    ("cognito-idp", "describe-user-pool", _err("ResourceNotFoundException")),
    ("sns", "get-topic-attributes", _err("NotFound")),   # wire code，不是类型名
    ("ssm", "get-parameter", _err("ParameterNotFound")),
    ("s3api", "get-bucket-location", _err("NoSuchBucket")),
    # CloudFormation 是唯一的无类型消息规则
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation: Stack with id X does not exist"),
    # ARN 形态的栈标识符也必须认（收紧不能把真的"不存在"挡掉）
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "Stack with id arn:aws:cloudformation:us-east-1:1:stack/S/abc-123 does not exist"),
    ("cloudformation", "describe-stack-resources",
     "An error occurred (ValidationError) when calling the DescribeStackResources "
     "operation: Stack with id SiteDeployerStack does not exist"),
    # ── botocore 在重试用尽时把 ` (reached max retries: N)` 插在 `operation` 与 `: ` 之间
    #    （`ClientError.MSG_TEMPLATE` 的 `{retry_info}`）。standard 重试模式（AWS CLI v2 默认）
    #    下 `MaxAttemptsChecker` 先被求值，于是 `AWS_MAX_ATTEMPTS=1` 时**连 ValidationError**
    #    也带这个后缀。第十四轮把前缀收成只认 `operation: ` ⇒ 这条真实报文判 UNKNOWN ⇒
    #    已清空的账号 hard-stop（Codex 第十五轮 P2-1，实测；父提交的旧 glob 反而是对的）。
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id X does not exist"),
    ("cloudformation", "describe-stack-resources",
     "An error occurred (ValidationError) when calling the DescribeStackResources "
     "operation (reached max retries: 2): "
     "Stack with id arn:aws:cloudformation:us-east-1:1:stack/S/abc-123 does not exist"),
    # ── 第十九轮：**真机 aws-cli 2.36.34 的 stderr 原文**（带 `aws: [ERROR]: ` 前缀）。
    #    第十七轮把外层前缀锚死在行首，于是这两条真报文被判 UNKNOWN ⇒ 已清空的账号在
    #    stacks 阶段 hard-stop。手写字符串（不带前缀）看不出来，所以这里照抄真机输出。
    ("cloudformation", "describe-stacks",
     "aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks "
     "operation: Stack with id ReviewStack does not exist"),
    ("cloudformation", "describe-stacks",
     "aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id ReviewStack does not exist"),
    # 非 CFN 的路径靠 `_outer_code` 取码，本来就不看 `operation: `——钉住它，别在
    # 将来"顺手"把外层码解析也收成必须紧跟 `operation: `。
    ("iam", "get-role",
     "An error occurred (NoSuchEntity) when calling the GetRole "
     "operation (reached max retries: 0): The role with name X cannot be found."),
]


@pytest.mark.parametrize("svc,op,err", _ABSENT_CASES, ids=lambda x: x if isinstance(x, str) and len(x) < 30 else "")
def test_real_notfound_is_absent(svc, op, err):
    assert _run_is_absent(svc, op, err), f"{svc} {op}: {err!r} 应判 ABSENT"


# **误收面**：同样的报文出现在**别的操作**上、或换成非 NotFound 的码，都不许判 ABSENT。
_NOT_ABSENT_CASES = [
    # AccessDenied 文案里恰好含 "does not exist" —— 旧版全局子串会误收（这是 Codex 的核心担忧）
    ("iam", "get-role",
     "An error occurred (AccessDenied) when calling the GetRole operation: "
     "role does not exist in your permission scope"),
    # UserPoolTaggingException：池是存在的，只是读标签失败（第五轮那条，现在结构上挡住）
    ("cognito-idp", "describe-user-pool", _err("UserPoolTaggingException")),
    # SNS 的**异常类型名**不是 wire code，不许认
    ("sns", "get-topic-attributes", _err("NotFoundException")),
    # 一个操作的 NotFound 码用在**另一个**操作上：不认（按操作限定）
    ("iam", "get-role", _err("ResourceNotFoundException")),      # iam 的是 NoSuchEntity
    ("s3api", "get-bucket-location", _err("AccessDenied")),
    ("dynamodb", "describe-table", _err("ThrottlingException")),
    # 非 NotFound 的常见失败
    ("lambda", "get-function", _err("TooManyRequestsException")),
    # CFN 的 ValidationError 但不是"不存在"（比如别的校验错）
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation: Template format error"),
    # 未登记的操作：无法证明"不存在"⇒ 一律 NOT_ABSENT（hard-stop，安全方向）
    ("cloudwatch", "describe-alarms", _err("SomeError")),
    # ── 以下两条是 Codex 第十三轮 P1-1 的形状。**修完代码但没加这两条用例时，
    #    把 CFN 判据退回 `*ValidationError*does not exist*`、或把外层码解析退回贪婪，
    #    121 条仍然全绿**——所以它们必须在这里。
    # (a) 外层是 AccessDenied，消息里恰好同时含 ValidationError 与 does not exist
    ("cloudformation", "describe-stacks",
     "An error occurred (AccessDenied) when calling the DescribeStacks operation: "
     "ValidationError: resource does not exist in permission scope"),
    # (b) 外层 AccessDeniedException，消息里**嵌了**另一条 An error occurred (NoSuchEntity)
    #     —— 贪婪匹配会取到内层那个码
    ("iam", "get-role",
     "An error occurred (AccessDeniedException) when calling the GetRole operation: "
     "upstream said An error occurred (NoSuchEntity) nested"),
    # (c) 同样的嵌套，但内层是该操作真正的 NotFound 码：仍然必须看**外层**
    ("dynamodb", "describe-table",
     "An error occurred (ThrottlingException) when calling the DescribeTable operation: "
     "retry later; earlier attempt said An error occurred (ResourceNotFoundException)"),
    # (d) CFN 外层码对，但消息不是"栈不存在"那个完整形状
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "role does not exist for this operation"),
    # ── 以下四条是 Codex 第十四轮 P1-1 的形状。**修完 _cfn_msg_is_stack_absent 但没加
    #    这些用例时，把判据退回 `*"Stack with id "*"does not exist"*` 仍然 129 条全绿。**
    #    中间那个 `*` 能跨过任意文字，所以"栈存在、只是角色没了"也会被判 ABSENT ⇒ 漏删整个栈。
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "Stack with id X exists, but its role does not exist"),
    # 尾部还有别的话 ⇒ 不是那一句
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "Stack with id X does not exist, retry later"),
    # 被引述在别的话里 ⇒ 不是那一句
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "upstream said \"Stack with id X does not exist\" while checking"),
    # 标识符位置是多个词 ⇒ 不是合法栈标识符
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "Stack with id my stack does not exist"),
    # ── 放行重试说明不能变成"括号里随便写"：只认 `(reached max retries: <数字>)`，
    #    且消息本体仍要整体匹配、外层码仍要是 ValidationError。
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: many): Stack with id X does not exist"),
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id X exists, but its role does not exist"),
    ("cloudformation", "describe-stacks",
     "An error occurred (AccessDenied) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id X does not exist"),
    # ── 第十六轮 P1-1：**放宽前缀与锚定前缀必须同时做**。上一轮只加了重试分支，而普通
    #    分支还是整行搜 `*"operation: "*`；带重试后缀时外层前缀里没有 `operation: `，
    #    于是它去匹配**正文里**的同名片段，把消息截成 `Stack with id Y does not exist`
    #    ⇒ 判 ABSENT ⇒ 漏删整个 router 栈（实测：跳过该栈、继续 23 次破坏性调用、退 0）。
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id X exists, but nested "
     "operation: Stack with id Y does not exist"),
    # 带真 CLI 前缀的劫持形态（真机 stderr 形状 + 正文里再塞一个 `operation: `）
    ("cloudformation", "describe-stacks",
     "aws: [ERROR]: An error occurred (ValidationError) when calling the DescribeStacks "
     "operation (reached max retries: 0): Stack with id X exists, but nested "
     "operation: Stack with id Y does not exist"),
    # 同样的正文、没有重试后缀时也必须拒（这条在旧版就是绿的，留着当正对照）
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks operation: "
     "Stack with id X exists, but nested operation: Stack with id Y does not exist"),
    # 前缀里**有括号**就不认（安全方向）——这样"第一个 ( 必属于外层错误码"仍然成立
    ("cloudformation", "describe-stacks",
     "upstream(1): An error occurred (ValidationError) when calling the DescribeStacks "
     "operation: Stack with id X does not exist"),
]


@pytest.mark.parametrize("svc,op,err", _NOT_ABSENT_CASES)
def test_non_notfound_or_wrong_operation_is_not_absent(svc, op, err):
    assert not _run_is_absent(svc, op, err), (
        f"{svc} {op}: {err!r} 被误判成 ABSENT —— 那正是「误收」，会导致漏删")


def test_absent_classifier_is_scoped_per_operation():
    """结构断言：分类必须**按操作限定**，不是全局子串。

    同一条报文（含 does-not-exist 文案 + 非匹配码）在任何操作上都不该被当成 ABSENT，
    除非它是该操作真正建模的 NotFound 码。这条钉住"不能退回全局子串规则"。
    """
    msg = ("An error occurred (AccessDenied) when calling the X operation: "
           "resource does not exist / not found / unable to find it")
    for svc, op in [("iam", "get-role"), ("lambda", "get-function"),
                    ("s3api", "get-bucket-location"), ("dynamodb", "describe-table")]:
        assert not _run_is_absent(svc, op, msg), f"{svc} {op} 把全局文案误收成 ABSENT"


# ---------------------------------------------------------------------------
# 防回归：DEPLOY.md 的拆除一节**不许**再出现可照抄的破坏性命令
# ---------------------------------------------------------------------------
_DEPLOY_MD = _ROOT / "site-builder" / "DEPLOY.md"
_SECTION = "## 把平台从账号里拆掉"


def _teardown_section() -> str:
    t = _DEPLOY_MD.read_text(encoding="utf-8")
    start = t.index(_SECTION)
    end = t.index("\n## ", start + len(_SECTION))
    return t[start:end]


# ── 围栏提取：**八层守卫的输入口，也是最致命的一处**（第二十轮 P2-3，六种形态实测）─────
#
# 旧实现是 `re.findall(r"```bash\n(.*?)```", text, re.S)`。三种绕过：
#   · 块**内部**任意位置的三个反引号（例如一行 bash 注释 `# ``` `）会让非贪婪匹配提前收尾，
#     后面那些**仍在代码块里、仍可照抄执行**的命令**一层都看不到**（实测：藏一条
#     `export AWS_PROFILE=…` + 另一个函数的 invoke，8/8 全绿，真 CLI 打到 review-other）。
#   · `~~~bash` 围栏压根不匹配。
#   · `sh` / `zsh` / `console` 标签被**静默忽略**，而它们一样可照抄执行。
# 加守卫层数救不了这个——**输入没了，后面几层再多也是零**。
#
# 所以按 CommonMark 的围栏规则真正地解析：开栏 ≤3 空格缩进 + ≥3 个 ` 或 ~ + info string
# （反引号栏的 info 里不许再有反引号）；闭栏必须**独占一行**、同种字符、长度 ≥ 开栏。
# 然后由 `test_teardown_section_fences_are_bash_only` 要求本节所有围栏都是 `bash` 标签
# ——不支持的标签**显式报错**，不静默跳过。
# 开栏：≤3 空格缩进 + ≥3 个 ` 或 ~ + info string（**整行剩余**，lang 取第一个词）。
# 三处都是拿 markdown-it-py 当参考实现差分出来的**真漏块**（第二十一轮自测），
# 漏一个块 = 那段命令脱离全部九层守卫：
#   · info 带额外词（```bash foo=1）—— 旧写法要求剩余部分是单个 `\S*`，于是整块不匹配；
#     CommonMark 只取第一个词当语言，块照样渲染、照样可照抄。
#   · CRLF —— `rstrip("\n")` 留下 `\r`，`[ \t]*$` 匹配不上 ⇒ 整块消失。
#     未来有人用 CRLF 编辑器改一次 DEPLOY.md 就会**静默**关掉九层。
#   · 引用块里的围栏（`> ```bash`）—— 行首有 `>`，不匹配。这一种不在解析器里支持，
#     而是由「受支持形态完备规则」（`_FENCE_RUN` / `_FENCE_SUPPORTED_LINE`）显式拒。
_FENCE_OPEN = re.compile(r"^( {0,3})(`{3,}|~{3,})[ \t]*(.*)$")
# 解析器**只认顶层、空格缩进 ≤3** 的围栏。别的形态（引用块里、缩进 ≥4、tab 缩进、
# 列表里的相对缩进…）参考实现认得、它看不见 ⇒ 那段命令会脱离全部守卫。
#
# 上一版是**枚举不支持的形态**（两条正则）。r22 的差分证明那条路走不通（tab 缩进、
# 空格+tab、列表内更深位置的 `>` 都不命中）。现在的方向是**约束文档**：只允许一种
# 扫描器能可靠处理的写法，其余一律红。
#
# **不再声称这是"完备"的**（r23 / r24 两轮各否掉我一次，这里如实记下）：
#   · r23：只检查"行形状"不能证明那一行在顶层、也不能证明扫描器的块状态对。反例是
#     列表项里一个未闭合的围栏把后面的独立块并进来（参考 2 块 / 扫描器 1 块）。
#   · r24：补的"围栏行数 == 2×块数"也不充分。两个反例：① 列表内未闭合围栏 + HTML 块里
#     的三反引号被当成闭栏 ⇒ **块数相同（各 1）、围栏行恰好 2 条、计数通过**，而正文边界
#     不同；② 合并块（3 行/1 块）与末尾未闭合块（1 行/1 块）**相互抵消** ⇒ 4 == 2×2 通过。
# 所以判据换成三条**可逐条验证**的文档约束（都由下面那个守卫断言），它们把上述全部
# 反例杀掉，但**不等于**"扫描器等价于 CommonMark 解析器"：
#   ① 围栏行必须在**第 0 列**（两个反例的第一个开栏都在列表里缩进 2 ⇒ 红）；
#   ② 每个块都必须**显式闭合**（杀掉抵消那一类，也让"未闭合吞后文"不可能）；
#   ③ 本节不许出现 HTML 块起始行（以 `<` 开头）——那是剩下唯一已知的上下文混淆源。
# 零缩进还顺带消掉了 r22/r23 的正文 tab 保真差异：开栏缩进为 0 时不剥任何东西。
# 发现这些的方法是**拿参考实现差分**（markdown-it-py，不在锁定依赖里，一次性跑）；
# 判据换代不代表以后不用再差分。
_FENCE_RUN = re.compile(r"`{3,}|~{3,}")
_FENCE_SUPPORTED_LINE = re.compile(r"^(`{3,}|~{3,})[ \t]*")
_HTML_BLOCK_START = re.compile(r"^ {0,3}<")

# CommonMark §2.1：行结束**只有** LF / CR / CRLF。`str.splitlines()` 还会在
# U+000B、U+001C、U+0085、U+2028、U+2029 上断行 —— 参考实现差分实测 5/5 漏：
# 正文里写 `a<U+2028>``` ` 时，参考实现看成**一行**（不闭栏），而按 splitlines()
# 它是两行 ⇒ 提前闭栏 ⇒ 后面那条 `aws lambda invoke …` 脱离全部九层守卫。
# 所以这里只按 `\n` 切。
def _md_lines(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "":               # 末尾换行不产生一个空行（同 splitlines）
        lines.pop()
    return lines


def _strip_fence_indent(line, n):
    """按 CommonMark §4.5 去缩进：最多移除 n 个**空格**，别的一概不动。

    旧写法是"前 n 个字符全是 `isspace()` 就切掉 n 个字符"，有三处偏差（r21 静态审计）：
    只有 k<n 个空格时一个都不切；空行的换行会被一起切掉；tab 与 Unicode 空白按**字符**
    而不是按 §2.2 的 4 列制表位算。这里只吃空格 ⇒ 永远不会切掉正文或行结束符。
    """
    k = 0
    while k < n and k < len(line) and line[k] == " ":
        k += 1
    return line[k:]


def _fenced_blocks_detailed(text):
    """按 CommonMark 围栏规则切出 `(语言, 块体, 是否显式闭合)`。"""
    # 末尾有无行结束符要在**规范化之后**判断：裸 CR 结尾时 `text.endswith("\n")`
    # 为假，会少保留一个 LF（r23 §3）。CommonMark 的行结束是 LF / CR / CRLF 三种。
    ends_with_newline = text.endswith(("\n", "\r"))
    lines = _md_lines(text)
    out, i, n = [], 0, len(lines)
    while i < n:
        m = _FENCE_OPEN.match(lines[i])
        # 反引号栏的 info string 里不许有反引号（CommonMark），否则不是开栏
        if not m or (m.group(2)[0] == "`" and "`" in m.group(3)):
            i += 1
            continue
        # CommonMark：info string 的**第一个词**是语言，后面的词随便
        indent, fence = len(m.group(1)), m.group(2)
        info = m.group(3).strip()
        lang = info.split()[0] if info else ""
        close = re.compile(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
        body, i, closed = [], i + 1, False
        while i < n:
            if close.match(lines[i]):
                closed = True
                break
            body.append(_strip_fence_indent(lines[i], indent))
            i += 1
        i += 1                                  # 跳过闭栏（没有闭栏时越过末尾，循环结束）
        # 未闭合、且原文末尾没有换行时，最后一行**不补**换行（参考实现如此；r22 §1）
        if body and not closed and not ends_with_newline:
            text_body = "".join(l + "\n" for l in body[:-1]) + body[-1]
        else:
            text_body = "".join(l + "\n" for l in body)
        out.append((lang, text_body, closed))
    return out


def _fenced_blocks(text):
    """`(语言, 块体)`——`_fenced_blocks_detailed` 去掉 `closed` 的视图。"""
    return [(lang, body) for lang, body, _closed in _fenced_blocks_detailed(text)]


def _fenced_bash(text):
    return [body for lang, body in _fenced_blocks(text) if lang == "bash"]


def test_teardown_section_delegates_to_the_script():
    """那一节必须点名脚本，并给出 --dry-run。"""
    sec = _teardown_section()
    assert "scripts/teardown_platform.sh" in sec
    assert "--dry-run" in sec, "没告诉采用者可以先空跑一遍"


def test_teardown_section_documents_exit_code_3():
    """退出码 3（还没完）必须写在手册里：不然采用者会把它当失败去查。"""
    sec = _teardown_section()
    assert "3" in sec and "还没完" in sec, "没交代「退 3 = 几小时后重跑」这件事"


# 第 ① 步"站点下线"是**人的判断**，刻意留在手册里：它用 put-item 建 job 行 + invoke
# 调 undeploy Lambda。fail-closed 分类下这两个动词也算"破坏性"（对的——它们确实会改状态），
# 所以这里必须**显式**豁免，而不是像以前那样靠"它们恰好不在关键词表里"蒙过去。
#
# 判据是**整条 argv 逐 token 相等**，不是 (服务, 动词, 目标旗标, 目标值)。
# 按"关键字段对得上"判是一条追不完的路（每轮都在追）：
#   · 第十一轮 —— 只按 (服务, 动词) ⇒ 再塞一条 invoke site-panel 照过；
#   · 第十四轮 —— `--function-name=x` / `"--function-name" x` 骗过重复检测；
#   · 第十五轮 —— `$'--function-name'` 骗过 shlex；
#   · 第十六轮 —— **AWS CLI 接受长选项的唯一前缀缩写**（argparse 默认 `allow_abbrev`）：
#     `--function-n site-panel` 追加在后面，三条守卫全绿，而 aws-cli 2.36.34 打向本机
#     HTTP 服务的路径实测是 `/2015-03-31/functions/site-panel/invocations`。
# 逐 token 等值一次把这一族全关掉，而且顺带关掉同族的 `--endpoint-url` / `--profile`
# 改向（那两个原本也能悄悄骑上一条"关键字段都对"的命令）。代价是改 runbook 的这两条
# 命令必须同步改这张表——**那正是想要的**：它们是唯一两条可照抄的破坏性命令。
_DOC_ALLOWED_ARGV = {
    ("aws", "dynamodb", "put-item",
     "--table-name", "site-deploy-jobs",
     "--region", "us-east-1",
     "--item", '{"job_id":{"S":"$JOB"},"site_id":{"S":"e2e-probe"},'
               '"owner":{"S":"probe@e2e.invalid"},"status":{"S":"PENDING"}}'): 1,
    ("aws", "lambda", "invoke",
     "--function-name", "site-deployer-undeploy",
     "--region", "us-east-1",
     "--cli-binary-format", "raw-in-base64-out",
     "--payload", '{"site_id":"e2e-probe","job_id":"$JOB","purge_data":true}',
     "/tmp/undeploy.json"): 1,
}


# 围栏块里**唯一**允许的命令替换。精确到整条，不做"体里含 aws 就拒"那种拼法追逐——
# Codex 第十四轮 P2-3 用 `$($'a''ws' s3 rm …)` 绕过了那种判据（体里没有连续的字面 aws，
# bash 实测先执行内层删除）。可照抄的 runbook 只需要这一条，所以白名单化。
_DOC_ALLOWED_SUBST = {"git rev-parse --show-toplevel"}


# ── 围栏块的**语法白名单**（第十七轮起的主判据）──────────────────────────────
#
# 前几轮的形状完全一样：我按 bash 语义补一块解析，下一轮就找到我没覆盖的另一块——
# 第十四轮 `$'…'`；第十五轮 `\'` 与带引号的 `"aws"`；第十六轮跨行引号、子 shell、
# 续行补空格、长选项缩写；第十七轮 `${UNSET:-$(…)}`、`{#`、brace expansion、heredoc、
# `aws --profile <值> <服务> <动词>`、前置 `VAR=v aws …`。**"写一个够用的 bash 词法器"
# 是追不完的**，而每次追漏都是"守卫全绿 + bash 真的执行"。
#
# 所以这里换方向：先把围栏块**可以使用的语法收成一个可穷举的子集**，子集之外一律红。
# 三条文档守卫是 AND 关系 ⇒ 任何依赖上面那族构造的绕过都过不了这一条，`_lex_block`
# 只需要在这个子集上正确。子集就是 runbook 真正用得到的东西：
#
#   · 裸词：只含 `[A-Za-z0-9_@%+=:,./^-]`，**没有任何 shell 元字符**
#     （于是 `<<` heredoc、`(`、`{`、`;`、`&`、`|`、`*`、`~`、裸 `$VAR` 全进不来）
#   · 单引号串 `'…'`：里面一切字面（JMESPath 的反引号/方括号/圆括号都住这里）
#   · 双引号串：只允许 `\\` `\"` `\$` `` \` `` 这几个转义与**简单** `$VAR`；
#     裸 `$(`、`${`、裸反引号一律不允许 ⇒ 命令替换只能以下面那一个白名单形态出现
#   · 唯一允许的命令替换：`"$(git rev-parse --show-toplevel)"`
#   · 行尾可以有一个续行 `\`，或一个前面带空白的 `# 注释`
#
# 每一物理行必须被这条文法**整行**吃掉。有个关键副产物：**引号必须在同一物理行闭合**，
# 于是"按物理行剥注释"这件事重新变成可靠的（那正是第十六轮 P2-2 的根）。
_G_BARE = r"[A-Za-z0-9_@%+=:,./^-]+"
# 引号内排除 **NUL 与其它 C0 控制字符**：bash 会把 NUL 从参数里**丢掉**，而两条分词路径
# 都原样保留（r23 §4：`'alpha<NUL>beta'` 我给 `alpha\x00beta`、bash 给 `alphabeta`）。
# runbook 不需要控制字符，所以按字符域拒掉，而不是去建模 bash 的丢弃行为。
_G_SQ = r"'[^'\x00-\x08\x0b-\x1f\x7f]*'"
# 双引号内的转义**只允许** `\\` 与 `\"`。刻意不允许 `\$` 与 `` \` ``：shlex 会**保留**
# 那个反斜杠、bash 会去掉（r22 §3 用真 bash 量到：`"price=\$RATE"` shlex 给
# `price=\$RATE`、bash 给 `price=$RATE`）。允许它等于让 `"…\$JOB…"` 在我这里"看着是一个
# 展开"（EXPAND 层要求 JOB 已绑定、JSON 层还会把它替换掉），而 bash 发出去的是**字面量**
# —— 与第二十轮 P2-1B 同一族的洞。去掉之后，本子集内 shlex 值与 bash 值**只差变量展开
# 这一件事**，而那件事由 EXPAND / JSON 两层显式建模（见 test_word_values_match_real_bash）。
_G_DQ = r'"(?:\\[\\"]|\$[A-Za-z_][A-Za-z0-9_]*|[^"\\$`\x00-\x08\x0b-\x1f\x7f])*"'
_G_SUBST = re.escape('"$(git rev-parse --show-toplevel)"')
_G_WORD = f"(?:{_G_SUBST}|{_G_SQ}|{_G_DQ}|{_G_BARE})"
_DOC_LINE_GRAMMAR = re.compile(rf"[ \t]*(?:{_G_WORD}(?:[ \t]+{_G_WORD})*)?[ \t]*")

# 再加一条**行级**规则：赋值形态的词只许**独占一行**。`VAR=v cmd …` 这种前置赋值
# 能整套换掉凭据/账号而不改服务与动词（第十七轮 P2-4，真机确认换到了另一组凭据），
# 而它在词法上完全合法 —— 所以只能按结构拒。`--table-name=x` / `'a=b'` 不是赋值形态
# （不以标识符起头），不受这条影响。
_G_PREFIX_ASSIGN = re.compile(r"[ \t]*[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+\S")


def _doc_line_ok(line):
    """这一物理行是否落在语法白名单里。

    先按整行试；不成再按"词首的 `#`"逐个切一次当行尾注释重试（`#` 必须前面是空白，
    与 bash 的"注释只在词首起"一致）。整行优先保证了 `"…# …"` 这种**引号内**的 `#`
    不会被当注释——那种情况整行就已经匹配上了。
    """
    for cand in [line] + [line[:m.start()] for m in re.finditer(r"(?<=[ \t])#", line)]:
        cand = cand.rstrip()
        if cand.endswith("\\"):                 # 行尾续行
            cand = cand[:-1]
        if _G_PREFIX_ASSIGN.match(cand):        # `VAR=v cmd …` —— 前置赋值，拒
            continue
        if _DOC_LINE_GRAMMAR.fullmatch(cand):
            return True
    return False


def _doc_grammar_offenders():
    """拆除一节的围栏块里所有不在语法白名单内的物理行。"""
    return [line.strip()[:110] for block in _fenced_bash(_teardown_section())
            for line in block.splitlines()
            if line.strip() and not line.lstrip().startswith("#") and not _doc_line_ok(line)]


def test_teardown_section_uses_only_the_allowed_shell_subset():
    """围栏块只许用语法白名单里的写法。

    这是第十七轮起的**主判据**：它不去理解 bash，而是把 bash 里那些"我理解不全"的
    构造（heredoc、`${…}` 参数展开、brace expansion、子 shell / 分组、管道 / 分隔符、
    前置 `VAR=v`、`aws --global-opt … ` 之外的花样）**在语法层挡掉**。
    真要往 runbook 里加新写法时这条会红——那时该做的是想清楚它能不能被安全解析，
    而不是给词法器再补一块。
    """
    offenders = _doc_grammar_offenders()
    assert offenders == [], (
        "拆除一节的围栏块出现了语法白名单之外的写法（见 _G_WORD 的注释）：\n  "
        + "\n  ".join(offenders))


# bash 的词法状态**跨物理行**。按物理行去剥注释 / 判引号 / 拼续行，会同时开出三个洞
# （Codex 第十六轮 P2-2 / P2-3 / P2-4 是同一个根，三条都实测复现过）：
#
#   · **双引号跨行，而 `#` 在引号内不是注释。** 于是
#         JOB2="{
#         # '$(aws s3 rm s3://other --recursive)'
#         }"
#     在 bash 里照样执行内层删除（那对单引号在双引号内是**字面量**），而三条守卫
#     都先"以 # 开头就 continue"⇒ **全绿**。这是一条完整绕过。
#   · **`\` + 换行是行继续：两个字符都消失、不补空格。** 旧实现把 `\` 换成一个空格，
#     于是
#         --function-\
#           name site-panel
#     bash 拼成生效的 `--function-name`，守卫却拼成 `--function-` `name` 两个词
#     ⇒ 重复目标检测失效。真正的分隔来自**下一行的缩进**，所以也不能先 strip 再拼。
#   · **`( ) { }` 也是命令分隔/分组符。** 只按 `; && || | &` 切时，
#     `("aws" lambda invoke --function-name site-panel /tmp/e.json)` 分词得到 `(aws`，
#     token 检测与正则同时落空 ⇒ 整条脱离射程，而 bash 确实执行它。
#
# 所以这里只留**一个**词法器，整块扫一遍，三条文档守卫共用它。
def _lex_block(text):
    """按 bash 词法把一个围栏块切开。

    返回 `(commands, subs, unterminated)`：

      · `commands` —— 逻辑命令原文：注释按词法状态剥掉、续行按 bash 语义拼好
        （不补空格）、在**未引用**的 `; & | ( ) { }` 与换行处切开。
      · `subs` —— 会被 bash 展开的命令替换体（`$( )` 与反引号）。单引号内的不算：
        `--query 'Roles[?starts_with(RoleName,`site-`)]'` 里的反引号是 JMESPath
        的字面量，当成替换会假红。
      · `unterminated` —— 扫完仍在引号 / 替换内 ⇒ 调用方一律当可疑。

    反斜杠**先于**引号处理：裸的 `\\'` 是一个**字面**单引号、不开引号段，于是
    `/tmp/undeploy.json\\'$(aws s3 rm …)` 在 bash 里照样执行内层替换（第十五轮 P2-3）。
    双引号内 bash 只对 ``$ ` " \\`` 与换行做转义，其余反斜杠是字面量（`\\"` 这种在本节的
    `--item "{\\"job_id\\":…}"` 里真实出现，弄错会把 dq 状态翻反）。
    """
    cmds, subs, cur = [], [], []
    sq = dq = unterminated = False
    prev_ws = True                              # 上一个字符是否空白/行首 ⇒ `#` 是否起注释
    i, n = 0, len(text)

    def flush():
        s = "".join(cur).strip()
        if s:
            cmds.append(s)
        cur.clear()

    while i < n:
        c = text[i]
        if c == "\\" and not sq:                # 单引号内反斜杠是字面量，不转义
            if i + 1 < n and text[i + 1] == "\n":
                i += 2; continue                # 行继续：两个字符都消失，**不补空格**
            if dq and i + 1 < n and text[i + 1] not in '$`"\\':
                cur.append(c); i += 1; prev_ws = False; continue
            cur.append(text[i:i + 2]); i += 2; prev_ws = False; continue
        if c == "'" and not dq:
            sq = not sq; cur.append(c); i += 1; prev_ws = False; continue
        if c == '"' and not sq:
            dq = not dq; cur.append(c); i += 1; prev_ws = False; continue
        if sq:                                  # 单引号内：原样保留，换行也不断句
            cur.append(c); i += 1; prev_ws = False; continue
        if c == "#" and not dq and prev_ws:     # 只有**未引用**时 `#` 才是注释
            j = text.find("\n", i)
            i = n if j < 0 else j               # 换行留给下一轮去断句
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j] == "(": depth += 1
                elif text[j] == ")": depth -= 1
                j += 1
            if depth:
                unterminated = True; break
            subs.append(text[i + 2:j - 1])
            cur.append(text[i:j]); i = j; prev_ws = False; continue
        # **不要**在这里加"`${…}` 整段跳过"那种分支：`${UNSET:-$(aws s3 rm …)}` 在变量
        # 未设置时会真的执行内层替换（第十七轮 P2-1，实测），跳过等于把它藏起来。
        # 让 `$` 与 `{` 当普通字符走下去 ⇒ 内层 `$(` 照样被取出来（fail-closed）。
        # `${…}` 本身已由语法白名单在更前面挡掉。
        if c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                unterminated = True; break
            subs.append(text[i + 1:j])
            cur.append(text[i:j + 1]); i = j + 1; prev_ws = False; continue
        # `{` / `}` **不在**这张表里：bash 只在它们**独立成词**时才当分组关键字，
        # 而无条件断句会反过来开洞 —— `echo {# $(aws s3 rm …)` 里 bash 把 `{#` 当普通词，
        # 断句后 `#` 落到词首就被当成注释、把整条替换吞掉（第十七轮 P2-2，实测）。
        # 分组 / brace expansion 由语法白名单挡掉，这里不猜。
        if not dq and c in ";&|\n()":           # 命令分隔 / 子 shell
            flush(); i += 1; prev_ws = True; continue
        cur.append(c); i += 1; prev_ws = c in " \t"
    flush()
    return cmds, subs, unterminated or sq or dq


def _command_substitutions(line):
    """单行版（给下面那组单元用例用）：会被 bash 展开的命令替换体。"""
    return _lex_block(line)[1]


# shlex **不认** bash 的 ANSI-C / locale 引用：它把 `$'--function-name'` 分成
# `$--function-name`，于是往豁免命令尾部再塞一个 `$'--function-name' site-panel`
# 时三条守卫全绿，而 bash 展开后真实 CLI 打的是 site-panel（Codex 第十五轮 P2-2，实测）。
# 追 shlex 与 bash 的语义差不如**拒掉这种写法**：可照抄的 runbook 没有理由需要它，
# 这与命令替换那条白名单是同一个取舍。`test_teardown_section_rejects_ansi_c_quoting`
# 另外把它钉在整节上（含非 aws 行）。
_ANSI_C_QUOTE = re.compile(r"\$['\"]")


def _shlex_words(cmd):
    """shlex 的原始分词（**不做** `--flag=value` 拆分）；分不了词返回空表。

    只用来和 `_raw_words` 对数：两者词数不等说明这条命令不在语法子集里
    （例如 `a''b` 那种相邻引号拼接），一律当可疑。
    """
    import shlex
    if _ANSI_C_QUOTE.search(cmd):
        return []
    try:
        return shlex.split(cmd)
    except ValueError:
        return []


def _shell_tokens(cmd):
    """按 shell 引号规则分词，并把 `--flag=value` 统一成 `--flag` `value` 两个 token。

    分不了词（引号不闭合、或出现 `$'…'` / `$"…"`）时返回 `None`，交给调用方当**可疑**
    处理——不是当"没有 aws 调用"跳过。

    `seg.split()` 不认引号也不认 `--flag=value`，于是
    `--function-name=site-panel` 与 `"--function-name" site-panel` 都能骗过重复检测
    （Codex 第十四轮 P2-2，真实 CLI 对 localhost 的请求确实打到 site-panel）。
    """
    import shlex
    if _ANSI_C_QUOTE.search(cmd):
        return None
    try:
        raw = shlex.split(cmd)
    except ValueError:                      # 引号不闭合等 —— 交给调用方当可疑处理
        return None
    out = []
    for tok in raw:
        if tok.startswith("--") and "=" in tok:
            flag, _, val = tok.partition("=")
            out += [flag, val]
        else:
            out.append(tok)
    return out


def _doc_aws_commands():
    """围栏块里每一条 aws 命令：`(服务, 动词, 规范化 argv, 原文)`。

    `argv` 为 `None` 表示"分不了词 / 两套解析不一致"⇒ 调用方一律当可疑。
    """
    out = []
    for block in _fenced_bash(_teardown_section()):
        cmds, _subs, unterminated = _lex_block(block)
        if unterminated:
            out.append(("?", "?", None, "块扫完仍在引号/替换内：" + block.strip()[:90]))
        for cmd in cmds:
            parts = _shell_tokens(cmd)
            if parts is None:
                # 分不了词：只要这段沾 aws 就当可疑（宁可假红也不放过）
                if "aws" in cmd:
                    out.append(("?", "?", None, cmd))
                continue
            # **按 token 找 aws，不按正则**：`"aws" lambda invoke …` 里 `aws` 被引号
            # 包着，`\baws\s+` 匹配不到（第十五轮 P2-2）。带路径的 `/usr/bin/aws` 也算。
            idxs = [j for j, t in enumerate(parts) if t == "aws" or t.endswith("/aws")]
            if not idxs:
                # 正则看见了、分词没看见 ⇒ 两套解析不一致，当可疑处理
                if _AWS_CALL.search(cmd):
                    out.append(("?", "?", None, cmd))
                continue
            i = idxs[0]
            svc = parts[i + 1] if i + 1 < len(parts) else ""
            verb = parts[i + 2] if i + 2 < len(parts) else ""
            # 只有"形状规整"的调用才准按 (服务, 动词) 去走只读豁免。两条实测教训：
            #   · `aws --profile list-prod lambda invoke --function-name site-panel …`
            #     被解析成 (服务=`--profile`, 动词=`list-prod`)，`list-` 前缀让**整条**
            #     当只读跳过（第十七轮 P2-3；配好那个临时 profile 后真实 CLI 确实打到
            #     了 site-panel）。所以服务/动词都不许以 `-` 开头。
            #   · `aws` 前面有东西（`AWS_PROFILE=other-account aws …`、包装器）时，
            #     前置赋值能整套换掉凭据/账号而**不改**服务与动词（第十七轮 P2-4，
            #     真机确认换到了另一组凭据）。所以 `aws` 必须是这条命令的第一个词。
            wellformed = (i == 0 and svc and verb
                          and not svc.startswith("-") and not verb.startswith("-"))
            # argv 取**整条**命令，不是 `parts[i:]`：从 `aws` 起截会把前置赋值/包装器
            # 丢掉，于是 `AWS_PROFILE=other aws lambda invoke …` 与豁免表逐 token 相等。
            out.append((svc if wellformed else "?", verb if wellformed else "?",
                        tuple(parts), cmd))
    return out


# ── 语句白名单（第十八轮起的主判据）────────────────────────────────────────
#
# 第十七轮那条**字符级**语法白名单只管"词长什么样"，不管"允许执行哪些语句"。
# 于是三类东西照样进得来（第十八轮，五种形态全部真机复现，见下面的 bypass 表）：
#
#   · **命令名不是字面量**：`REVIEW_CMD=aws` + `"$REVIEW_CMD" lambda invoke …`，
#     或 `bash -c '"aws" lambda invoke …'`。两者都不含 `aws` 这个 token，正则也被
#     引号挡住 ⇒ 整条脱离射程，而假 aws 记到的 `--function-name` 是 site-panel。
#   · **独占一行的环境改写**：`export AWS_PROFILE=other-account`（或裸
#     `AWS_PROFILE=other-account`——重新赋值不清除已有的 export 属性）。豁免命令的
#     token 一个字没变，但假 aws 记到的 `AWS_PROFILE` 已经是另一组凭据。
#     上一轮只禁了**同一条命令**的前置赋值，独立一行的没管住。
#   · **变量值改掉业务语义**：`JOB=\` 续行接 `'job-teardown-e2e-probe","site_id":"victim'`。
#     豁免的 invoke 一字不改、argv 逐 token 相等，但 `$JOB` 插进 payload 后多出一个
#     `site_id`，Python 的 json 取**后**一个 ⇒ 目标从夹具站点变成 `victim`，
#     `purge_data=true` 还在。
#
# 所以判据再上一层：**每条逻辑语句必须落进一张点名的形状表**，命令位置只能是固定
# 字面量，变量绑定只能是点名的那一条。"再去补 `$VAR` / `bash` / `eval` 的黑名单"是
# 上一轮那条路的重演，不做。
_STMT_SCRIPT = "site-builder/scripts/teardown_platform.sh"
_STMT_CD = ("cd", "$(git rev-parse --show-toplevel)")
# 唯一允许的变量绑定：名字、值、次数都点名。放宽任何一维都会把 P2-3 那条放回来。
_DOC_ALLOWED_ASSIGN = {"JOB=job-teardown-e2e-probe": 1}
_STMT_BARE_ARG = re.compile(r"[A-Za-z0-9_.:/-]+")


_Stmt = collections.namedtuple("_Stmt", "block kind parts raws cmd")


def _aligned_words(cmd):
    """`(parts, raws)`——**逐下标对齐**的去引号值与原始词；对不齐返回 `([], [])`。

    r21 静态审计指出的独立一致性问题：`_shell_tokens` 会把 `--flag=value` **拆成两个**
    `parts`，而 `_raw_words` 给的是**一个**原始词。上一版只校验
    `len(raws) == len(_shlex_words(cmd))`（两边都没拆），所以
    `--region=us-east-1` 这种全裸值形态**校验通过而下标从此错位**（实测：
    `zip(raws, parts)` 从那个词起整体偏一位，`raws[parts.index(flag)+1]` 取到的是隔壁的词）。
    错位的后果是"单引号里的 `$` 不展开"那条检查作用在**错误的词**上 ⇒ P2-1B 重新打开。

    这里改成拆分时**同步复制原始词**，于是两张表永远等长同序。
    """
    raws0 = _raw_words(cmd)
    vals0 = _shlex_words(cmd)
    if raws0 is None or not vals0 or len(raws0) != len(vals0):
        return [], []
    parts, raws = [], []
    for raw, val in zip(raws0, vals0):
        if val.startswith("--") and "=" in val:
            flag, _, v = val.partition("=")
            parts += [flag, v]; raws += [raw, raw]
        else:
            parts.append(val); raws.append(raw)
    # 与 `_shell_tokens` 必须给出同一串（`_doc_aws_commands` 用的是后者）
    if parts != (_shell_tokens(cmd) or []):
        return [], []
    return parts, raws


def _raw_value_segment(raw):
    """`--flag=value` 形态的原始词里，取 `=` 之后那段的原始形态；其余原样返回。

    拆分后两个 `parts` 共用同一个原始词，而"是不是单引号"要看**值**那一段
    （`--payload='{…}'` 的整词以 `-` 开头、看着像裸词，值却是单引号）。
    """
    m = re.match(r"--[A-Za-z0-9-]*=", raw)
    return raw[m.end():] if m else raw


def _raw_words(cmd):
    """把一条逻辑命令切成**保留引用形态**的原始词；切不干净返回 `None`。

    为什么必须保留引用（第二十轮 P2-1，两种形态实测）：`_shell_tokens` 走 shlex，会把
    引号**去掉**，于是两处 bash 语义丢失且守卫全绿——
      · `'JOB=job-teardown-e2e-probe'` 去引号后与裸赋值同形，语句层记作一次合法绑定；
        而 bash 把**整体被引用的词**当**命令名**（`command not found`），JOB 压根没赋上。
      · `--payload '{…"$JOB"…}'` 去引号后与双引号版逐 token 相等；而单引号里 `$JOB`
        **不展开**，真 CLI 发出去的 job_id 就是字面量 `$JOB`（与 put-item 的主键不是一个）。
    语法白名单保证每个词恰好是 `_G_WORD` 的一个匹配，所以这里能反过来用它切词，
    并要求匹配之间只有空白（切不干净就 `None` ⇒ 调用方当可疑）。
    """
    words, pos = [], 0
    for m in re.finditer(_G_WORD, cmd):
        # 间隙只允许**空格/tab**（不用 Unicode 的 strip：语法里的分隔符就是这两个）
        if m.start() > pos and cmd[pos:m.start()].strip(" \t"):
            return None
        if m.start() == pos and words:          # 相邻两词之间必须有分隔符
            return None
        words.append(m.group(0)); pos = m.end()
    return None if cmd[pos:].strip(" \t") else words


def _word_kind(raw):
    """原始词的引用形态：`subst` / `sq` / `dq` / `bare`。"""
    if raw == '"$(git rev-parse --show-toplevel)"':
        return "subst"
    if raw.startswith("'"):
        return "sq"
    if raw.startswith('"'):
        return "dq"
    return "bare"


def _doc_statements():
    """围栏块里每条逻辑语句（**按出现顺序**）：`_Stmt(块号, 种类, tokens, 原始词, 原文)`。

    种类 `?` = 不在形状表里。带块号是因为每个围栏块都可以被**单独**照抄，所以变量绑定
    不能跨块生效（第二十轮 P2-2 的一半）。
    """
    out = []
    for bi, block in enumerate(_fenced_bash(_teardown_section())):
        cmds, _subs, unterminated = _lex_block(block)
        if unterminated:
            out.append(_Stmt(bi, "?", None, None,
                             "块扫完仍在引号/替换内：" + block.strip()[:90]))
        for cmd in cmds:
            parts, raws = _aligned_words(cmd)
            if not parts:
                out.append(_Stmt(bi, "?", None, None, cmd)); continue
            if tuple(parts) == _STMT_CD:
                kind = "cd"
            elif parts[0] == _STMT_SCRIPT and all(
                    _STMT_BARE_ARG.fullmatch(a) for a in parts[1:]):
                kind = "script"
            # **赋值必须是裸词**：整体被引用的 `'JOB=…'` 在 bash 里是命令名，不是赋值
            elif (len(parts) == 1 and parts[0] in _DOC_ALLOWED_ASSIGN
                    and _word_kind(raws[0]) == "bare"):
                kind = "assign"
            elif parts[0] == "aws" and _word_kind(raws[0]) in ("bare", "sq", "dq"):
                kind = "aws"
            else:
                kind = "?"
            out.append(_Stmt(bi, kind, tuple(parts), tuple(raws), cmd))
    return out


def _json_no_dupes(pairs):
    """`json.loads` 的 `object_pairs_hook`：同一层出现重复键就红。

    默认行为是**静默取后者**，第十八轮 P2-3 正是靠它把 `site_id` 换成 `victim` 而
    argv 一字不差。不同层的同名键是合法的，只查同一层。
    """
    keys = [k for k, _ in pairs]
    assert len(keys) == len(set(keys)), f"JSON 里出现重复键 {keys} —— 解码会取后者"
    return dict(pairs)


_ASSIGN_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)


def _doc_env_timeline():
    """按**语句顺序**回放围栏块，产出 `(语句, 该语句执行前的 env)`。

    两条纪律都来自实测（第二十轮 P2-2）：
      · **顺序**——上一版把整节的赋值先汇总成最终字典再套给所有命令，于是把唯一那条
        `JOB=…` 挪到 invoke **之后**照样 8/8 全绿；而运行时 invoke 处的 `$JOB` 是继承值
        或空串（真机复现：site_id 变成 review-victim）。
      · **不跨块**——每个围栏块都可以被单独照抄，A 块里的赋值不能替 B 块背书。
    只收**裸词**形态的赋值（`'JOB=…'` 在 bash 里是命令名，不是赋值）；刻意也收白名单
    之外的名字/值，好让下游守卫能独立看见"文档里把绑定换了"。
    """
    out, env, block = [], {}, None
    for st in _doc_statements():
        if st.block != block:
            env, block = {}, st.block          # 换块 ⇒ 清空
        out.append((st, dict(env)))
        if (st.raws and len(st.raws) == 1 and _word_kind(st.raws[0]) == "bare"
                and _ASSIGN_WORD.fullmatch(st.parts[0])):
            name, val = st.parts[0].split("=", 1)
            env[name] = val
    return out


def _doc_variable_bindings():
    """整节最终的变量绑定（顺序无关的那份，只给分类器对照表用）。"""
    env = {}
    for st, _before in _doc_env_timeline():
        if (st.raws and len(st.raws) == 1 and _word_kind(st.raws[0]) == "bare"
                and _ASSIGN_WORD.fullmatch(st.parts[0])):
            name, val = st.parts[0].split("=", 1)
            env[name] = val
    return env


def test_teardown_section_uses_only_the_allowed_statements():
    """围栏块里每条语句都必须落进点名的形状表，变量绑定连**次数**都要对。

    这条管的是"允许执行什么"，上一条（语法白名单）管的是"词长什么样"——两条都要。
    命令位置只认字面量 `cd` / 拆除脚本 / `aws`：`"$VAR" …`、`bash -c '…'`、`export …`
    以及任何别的赋值一律红。
    """
    offenders, assigns = [], {}
    for _bi, kind, parts, _raws, cmd in _doc_statements():
        if kind == "?":
            offenders.append(cmd[:130])
        elif kind == "assign":
            assigns[parts[0]] = assigns.get(parts[0], 0) + 1
    assert offenders == [], (
        "拆除一节的围栏块出现了形状表之外的语句（命令位置只能是 cd / 拆除脚本 / aws，"
        "变量绑定只能是 _DOC_ALLOWED_ASSIGN 里那条）：\n  " + "\n  ".join(offenders))
    assert assigns == _DOC_ALLOWED_ASSIGN, (
        f"变量绑定不对：实得 {assigns}，期望 {_DOC_ALLOWED_ASSIGN}")


# 本节允许的围栏语言（正向表）。不支持的标签**显式报错**，不静默跳过——
# `sh` / `~~~bash` / 块内三反引号截断这三种都让整段命令脱离全部八层（第二十轮 P2-3）。
# `bash` = 要过后面七层的可执行块；`text` = 展示 AWS 输出的块，**不**当 shell 解析，
# 但也不能藏可照抄的命令（下面第二条断言）。无标签与 `sh` / `zsh` / `console` 一律拒。
_DOC_ALLOWED_FENCE_LANGS = {"bash", "text"}
_DOC_SHELL_FENCE_LANGS = {"bash"}


def test_teardown_section_fences_are_tagged_and_only_bash_is_shell():
    """拆除一节的围栏：标签必须在正向表里，且**非 shell 块不许藏可运行命令**。

    这一条守的是**后面七层守卫的输入口**：提取器漏掉的块，加多少层都看不到。
    实测三种漏法（第二十轮 P2-3，每种都真机执行过）——块内一行 bash 注释 `# ``` `
    让旧的 `(.*?)` 正则提前收尾、`~~~bash` 压根不匹配、`sh` 标签被静默忽略。
    加新标签必须先想清楚"它要不要过那七层"，所以按正向表拒；`text` 块只放 AWS 输出，
    所以额外断言里面没有 `aws <服务> <动词>` 也没有拆除脚本调用——**标签不会阻止
    任何人照抄**，能阻止的只有"里面没有可抄的东西"。
    """
    sec = _teardown_section()
    lines = _md_lines(sec)
    # ① 围栏行必须在第 0 列（见 _FENCE_RUN 上面那段：两个 r24 反例的第一个开栏
    #    都在列表里缩进 2；零缩进还消掉了正文 tab 的去缩进差异）
    unsupported = [l[:90] for l in lines
                   if _FENCE_RUN.search(l) and not _FENCE_SUPPORTED_LINE.match(l)]
    assert unsupported == [], (
        "拆除一节的围栏行必须在第 0 列（缩进 / 引用块 / 列表内的围栏扫描器处理不了，"
        "参考实现却认得 —— 那段命令会脱离全部守卫）：\n  " + "\n  ".join(unsupported))
    # ③ 不许有 HTML 块起始行：HTML 块里的三反引号会被扫描器当成闭栏（r24 反例 ①）
    html = [l[:80] for l in lines if _HTML_BLOCK_START.match(l)]
    assert html == [], (
        "拆除一节出现了 HTML 块起始行 —— HTML 原文里的三反引号会被本提取器当成闭栏，"
        "块边界就不是参考实现认的那个：\n  " + "\n  ".join(html))
    detailed = _fenced_blocks_detailed(sec)
    blocks = [(lang, body) for lang, body, _c in detailed]
    assert blocks, "拆除一节里没解析出任何围栏块 —— 提取器坏了或那一节被删了"
    # ② 每个块都必须显式闭合（**逐块**判，不是总量——总量会互相抵消，r24 反例 ②）
    unclosed = [f"{lang or '(无标签)'}: {body.strip()[:60]}" for lang, body, c in detailed if not c]
    assert unclosed == [], (
        "拆除一节有围栏没显式闭合 —— 它会把后面的内容（含后面的块）一起吞进来：\n  "
        + "\n  ".join(unclosed))
    # 交叉核对：围栏行数应恰好是 2×块数。这条**只是诊断**，不是充分不变量
    # （r24 证明它会被抵消），留着是因为它能一眼指出"有多余的围栏行"。
    fence_lines = [l for l in lines if _FENCE_RUN.search(l)]
    assert len(fence_lines) == 2 * len(blocks), (
        f"围栏行 {len(fence_lines)} 条、块 {len(blocks)} 个 —— 不是 1:2，有多余的围栏行：\n  "
        + "\n  ".join(l[:80] for l in fence_lines))
    bad = [l or "(无标签)" for l, _b in blocks if l not in _DOC_ALLOWED_FENCE_LANGS]
    assert bad == [], (
        f"拆除一节出现了正向表之外的围栏语言 {bad}；允许的是 "
        f"{sorted(_DOC_ALLOWED_FENCE_LANGS)}（不支持的标签必须显式处理，不能静默忽略）")
    runnable = [f"[{lang}] {line.strip()[:100]}"
                for lang, body in blocks if lang not in _DOC_SHELL_FENCE_LANGS
                for line in body.splitlines()
                if _AWS_CALL.search(line) or _STMT_SCRIPT in line]
    assert runnable == [], (
        "非 shell 围栏块里出现了可照抄的命令 —— 它不过那七层守卫：\n  "
        + "\n  ".join(runnable))


# aws 语句里允许出现的旗标（正向表，就是现节实际用到的那 9 个）。
#
# 为什么连**只读**命令也要管：③ 的 argv 等值只作用在破坏性命令上，只读命令整条不受约束。
# 而 `--endpoint-url http://…` / `--profile <别的账号>` / `--no-verify-ssl` 加在一条
# `list-*` 上不会被任何别的层看见——那会把一条 SigV4 签名请求发往别处（凭据外泄面），
# 或者让"体检"读的是另一个账号从而给出假结论。按正向表管旗标一次关掉这一族，
# 且不必去追 `--endpoint-url` 这种名字（追名字就是黑名单，前几轮的老路）。
_DOC_ALLOWED_AWS_FLAGS = {
    "--region", "--query", "--output", "--max-results",
    "--table-name", "--function-name", "--item", "--payload", "--cli-binary-format",
}


def test_teardown_section_aws_flags_are_allowlisted():
    """围栏块里每条 aws 语句的旗标都必须在正向表里（**含只读命令**）。"""
    offenders = []
    for _bi, kind, parts, _raws, cmd in _doc_statements():
        if kind != "aws":
            continue
        bad = [t for t in parts if t.startswith("-") and t not in _DOC_ALLOWED_AWS_FLAGS]
        if bad:
            offenders.append(f"{cmd[:100]}   <- 旗标不在正向表里：{bad}")
    assert offenders == [], (
        "拆除一节的 aws 命令用了正向表之外的旗标（见 _DOC_ALLOWED_AWS_FLAGS 的注释）：\n  "
        + "\n  ".join(offenders))


def test_every_expansion_in_the_section_is_a_bound_variable():
    """每个 `$NAME` 都必须**在它之前、同一个围栏块里**已经被点名绑定过。

    ④ 只把 `--item` / `--payload` 两个 JSON 参数解出来核对；别的参数只受 ③ 的 token
    等值约束，而 token 等值看不见"这个 `$X` 运行时展开成什么"（未绑定 ⇒ 展开成**空串**，
    静默改掉请求内容）。第二十轮又补了两条实测教训：

      · **顺序**：绑定必须在使用**之前**（P2-2）。
      · **引用形态**：单引号里的 `$JOB` 是**字面量**、不展开（P2-1B）——真 CLI 发出去的
        `job_id` 就是 `$JOB` 这五个字符，和 put-item 写的主键不是一个。所以这里对
        单引号词里的 `$` 一律红，而不是当成"用了一个绑定过的变量"。
    唯一例外是白名单里那条命令替换本身。
    """
    offenders = []
    for st, env in _doc_env_timeline():
        for raw, tok in zip(st.raws or (), st.parts or ()):
            kind = _word_kind(_raw_value_segment(raw))
            if kind == "subst":
                continue
            if kind == "sq" and "$" in raw:
                offenders.append(f"{st.cmd[:90]}   <- 单引号里的 {raw[:40]!r} 不展开，是字面量")
                continue
            if "$" not in tok:
                continue
            for m in re.finditer(r"\$(\{?)([A-Za-z_][A-Za-z0-9_]*)?", tok):
                brace, name = m.group(1), m.group(2)
                if brace or not name:
                    offenders.append(f"{st.cmd[:90]}   <- 不支持的展开形态 {m.group(0)!r}")
                elif name not in env:
                    offenders.append(
                        f"{st.cmd[:90]}   <- ${name} 在此处还没绑定（同块内、本语句之前）")
    assert offenders == [], (
        "拆除一节里出现了未按顺序绑定 / 形态不支持 / 被单引号挡住的展开：\n  "
        + "\n  ".join(offenders))


def test_exempted_commands_decode_to_the_expected_requests():
    """两条豁免写命令**展开变量后**的 JSON 必须解码成预期的请求。

    "源文本 token 相等"不等于"真实请求相等"（第十八轮 P2-3）：`$JOB` 的值里塞进
    `","site_id":"victim` 时 argv 逐 token 一模一样，而 payload 解出来的 `site_id`
    变成了 `victim`（json 对重复键取后者），`purge_data` 还是 true。所以这里把
    **围栏块里真实绑定的值**代进去、按**拒绝重复键**解码，再逐字段核对。取的是文档里
    那条绑定而不是 `_DOC_ALLOWED_ASSIGN`——否则这条只是在核对一个常量，对"文档里换了
    绑定值"这种变形一无所知。
    """
    import json
    expected = {
        "--item": {"job_id": {"S": "job-teardown-e2e-probe"},
                   "site_id": {"S": "e2e-probe"},
                   "owner": {"S": "probe@e2e.invalid"},
                   "status": {"S": "PENDING"}},
        "--payload": {"site_id": "e2e-probe", "job_id": "job-teardown-e2e-probe",
                      "purge_data": True},
    }
    seen = {}
    for st, env in _doc_env_timeline():
        # 用**该语句执行前**的 env，不是整节汇总（第二十轮 P2-2：把绑定挪到 invoke 之后
        # 也能让"汇总版"绿，而运行时那里的 `$JOB` 是继承值或空串）
        if st.kind != "aws" or _is_readonly(f"{st.parts[1] if len(st.parts) > 1 else ''} "
                                            f"{st.parts[2] if len(st.parts) > 2 else ''}"):
            continue
        for flag, want in expected.items():
            if flag not in st.parts:
                continue
            idx = st.parts.index(flag) + 1
            value, raw = st.parts[idx], st.raws[idx] if idx < len(st.raws) else ""
            # 只有**双引号 / 裸词**里的 `$NAME` 才会被 bash 展开；单引号里是字面量
            seg = _raw_value_segment(raw)
            assert _word_kind(seg) != "sq" or "$" not in seg, (
                f"{flag} 用了单引号，里面的 `$` 不会展开（真 CLI 发出去的是字面量）：{raw[:70]}")
            for name, val in env.items():
                value = value.replace(f"${name}", val)
            assert "$" not in value, (
                f"{flag} 里还有没解析的展开：{value!r}（本语句之前没给它绑定值 ⇒ "
                f"运行时会展开成空串）")
            got = json.loads(value, object_pairs_hook=_json_no_dupes)
            assert got == want, f"{flag} 展开后是 {got}，期望 {want}"
            seen[flag] = seen.get(flag, 0) + 1
    assert seen == {"--item": 1, "--payload": 1}, (
        f"两条豁免写命令的 JSON 参数没都核对到：{seen}")


def test_teardown_section_has_no_copyable_destructive_commands():
    """围栏块里的写操作必须**逐条整条**在豁免表里，且出现次数也对得上。

    判定用与 harness 同一套 fail-closed 分类：只读动词之外一律算破坏性。
    """
    seen, offenders = {}, []
    for svc, verb, argv, cmd in _doc_aws_commands():
        if _is_readonly(f"{svc} {verb}"):
            continue
        if argv is None or argv not in _DOC_ALLOWED_ARGV:
            offenders.append(cmd[:130])
            continue
        seen[argv] = seen.get(argv, 0) + 1
    assert offenders == [], (
        "拆除一节的围栏块里出现了豁免表之外的写操作，请改为调用 "
        "scripts/teardown_platform.sh：\n  " + "\n  ".join(offenders))
    assert seen == _DOC_ALLOWED_ARGV, (
        f"豁免命令的出现次数不对：实得 {seen}，期望 {_DOC_ALLOWED_ARGV}")


def test_doc_exemption_list_stays_minimal():
    """豁免清单必须只有那两条命令的**逐 token argv**（含次数）。

    多一条就等于又开了一个可照抄的口子，而那正是前几轮 P1 的长发地。
    """
    assert _DOC_ALLOWED_ARGV == {
        ("aws", "dynamodb", "put-item",
         "--table-name", "site-deploy-jobs",
         "--region", "us-east-1",
         "--item", '{"job_id":{"S":"$JOB"},"site_id":{"S":"e2e-probe"},'
                   '"owner":{"S":"probe@e2e.invalid"},"status":{"S":"PENDING"}}'): 1,
        ("aws", "lambda", "invoke",
         "--function-name", "site-deployer-undeploy",
         "--region", "us-east-1",
         "--cli-binary-format", "raw-in-base64-out",
         "--payload", '{"site_id":"e2e-probe","job_id":"$JOB","purge_data":true}',
         "/tmp/undeploy.json"): 1,
    }, _DOC_ALLOWED_ARGV


def test_teardown_section_still_documents_the_two_unavoidable_pits():
    """两处必然撞到的坑不能在改写中丢掉：Lambda@Edge 副本、以及 alias 已随栈删除的孤儿 CMK。"""
    sec = _teardown_section()
    assert "replicated function" in sec, "丢了 router 栈第一次必失败那条"
    assert "alias 不是" in sec and "description" in sec, "丢了孤儿 CMK 只能按 description 认那条"


def test_agentcore_runtime_delete_is_waited_for(harness):
    """`DeleteAgentRuntime` 是异步的（AWS 文档：`HTTP/1.1 202`，status 含 `DELETING`）。

    删完必须轮询到它真的消失，**才能**去删 ECR 镜像与 site-mcp-runtime-role
    ——那两样正是 runtime 删除过程本身要用的（Codex 第五轮 P1-3）。
    """
    proc, calls = harness("--yes", "--stage", "scripts")
    assert proc.returncode == 0, proc.stderr
    del_idx = next(i for i, c in enumerate(calls) if "delete-agent-runtime" in c)
    after = calls[del_idx + 1:]
    assert any("get-agent-runtime" in c for c in after), "删完没有轮询确认它消失"
    # 顺序：确认消失**在**删 ECR / 删角色之前
    gone_idx = del_idx + 1 + next(i for i, c in enumerate(after) if "get-agent-runtime" in c)
    for later in ("ecr delete-repository", "iam delete-role --role-name site-mcp-runtime-role"):
        idx = next((i for i, c in enumerate(calls) if later in c), None)
        if idx is not None:
            assert idx > gone_idx, f"{later} 发生在确认 runtime 消失之前"


def test_agentcore_wait_timeout_is_a_hard_stop(harness):
    """runtime 一直删不完（轮询耗尽）⇒ 非零退出，且不去动它还在用的 ECR / 角色。"""
    proc, calls = harness("--yes", "--stage", "scripts",
                          env={"FAKE_RUNTIME_NEVER_GONE": "1",
                               "TEARDOWN_POLL_TRIES": "2", "TEARDOWN_POLL_SLEEP": "0"})
    assert proc.returncode != 0, proc.stdout
    assert "超时" in proc.stdout + proc.stderr
    assert not any("ecr delete-repository" in c for c in calls), calls


def test_edge_log_groups_are_cleaned_in_every_region(harness):
    """Edge 日志组在**每个执行区**都有一份；只清本区会永久留下其余区（第五轮 P2-5）。

    区列表动态枚举（`ec2:DescribeRegions`），不硬编码——别的部署不知道自己的 POP
    落在哪些区，这跟 access_rollup 跨区扫描是同一条设计理由。
    """
    proc, calls = harness("--yes")
    assert proc.returncode == 0, proc.stderr
    assert any("ec2 describe-regions" in c for c in calls), "没有动态枚举区列表"
    deleted = [c for c in calls if "delete-log-group" in c]
    for region in _REGIONS:
        assert any(_OWNED_EDGE_LG in c and f"--region {region}" in c for c in deleted), (
            f"{region} 的 Edge 副本日志组没被删:\n" + "\n".join(deleted))


def test_foreign_edge_log_group_is_never_deleted(harness):
    """账号里别人的 Edge 函数日志组（实测见过 redirectEdge）**一个区都不许删**。

    跨区扫描用的前缀 `/aws/lambda/us-east-1.` 会把它们一起列出来——对只读的聚合器
    那是可接受的代价，对删除则是事故。所以跨区那一路仍然只删归属清单内的。
    """
    proc, calls = harness("--yes")
    assert proc.returncode == 0, proc.stderr
    offenders = [c for c in calls if "delete-log-group" in c and _FOREIGN_EDGE_LG in c]
    assert offenders == [], f"删了别人的 Edge 日志组: {offenders}"


def test_tagging_exception_is_not_treated_as_absent(harness):
    """`UserPoolTaggingException` **不是** NotFound（Cognito 服务模型：标签读写失败）。

    把它当 ABSENT 会让一个**存在**的用户池被静默跳过，而整轮仍退 0（第五轮 P2-4）。
    """
    proc, calls = harness("--yes", env={"FAKE_FAIL_ON": "cognito-idp describe-user-pool",
                                        "FAKE_FAIL_CODE": "UserPoolTaggingException"})
    assert proc.returncode != 0, (
        "标签异常被当成了「池不存在」 ⇒ 池漏删而整轮退 0\n" + proc.stdout)
    assert not any("delete-user-pool" in c for c in calls), calls


# ---------------------------------------------------------------------------
# 静态守卫：区域性服务的每一次调用都必须显式带 --region
#
# 假 aws 不关心 --region，所以这条缺陷**注入不出来**，只能静态查。
# `ec2 describe-regions` 曾漏掉它：没有 CLI 默认区的合法环境里真 CLI 报
# `An error occurred (NoRegion): You must specify a region.`（实测 aws-cli 2.36.34）。
# 那条报文不在 NotFound 表里 ⇒ 会被正确判成 UNKNOWN 并 hard-stop，
# 但漏在 orphans 里就意味着表、CMK、前端桶都已经删完了才失败（Codex 第六轮 P1-1）。
# ---------------------------------------------------------------------------
# **不再维护"哪些服务不需要区"的白名单。** 上一轮那张表（iam/sts/s3/s3api）是我在
# 自己这台机器、当前 endpoint 配置下实测出来的，而它是**环境性结论**：
# 打开 `AWS_USE_FIPS_ENDPOINT=true` 且无默认区时，`sts get-caller-identity` 实测解析到
#   Could not connect to the endpoint URL: "https://sts-fips.aws-global.amazonaws.com/"
# 加 `--region us-east-1` 后立刻正常（Codex 第七轮 P1-1）。
# 所以规则改成最简单也最强的一条：**这个脚本里每一次 aws 调用都必须显式带 --region**。
# 对全局服务带上它是无害的，换来的是不依赖任何 endpoint 配置。


def _logical_aws_lines():
    """把续行拼起来、去掉注释，返回每条含 aws 调用的逻辑行。

    **用正则 search，不能用 `" aws " in line`**：后者漏掉 `$(aws …)` 这种形态
    （`aws` 前面是 `(` 不是空格）。上一版就是这么漏掉 `live="$(aws sts …)"` 的
    ——Codex 把那一行变形成无区的 `$(aws ec2 describe-regions …)`，静态测试仍然全绿，
    直接证明了扫描洞（第七轮 P1-1）。
    """
    out, buf = [], ""
    for raw in _SCRIPT.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        buf += raw[:-1] + " " if raw.rstrip().endswith("\\") else raw
        if raw.rstrip().endswith("\\"):
            continue
        if _AWS_CALL.search(buf):
            out.append(buf)
        buf = ""
    return out


# 跨区那一路是**唯一**允许打到非主区的：Edge 日志组在每个执行区各有一份。
#   · `logs describe-log-groups --log-group-name-prefix …`（枚举别区的 Edge 日志）
#   · `logs delete-log-group`（主区与别区都有）
# 其余每一次调用都必须精确打在 config 的区上。
def _is_cross_region_call(argv):
    sv = tuple(argv[:2])
    if sv == ("logs", "delete-log-group"):
        return True
    return sv == ("logs", "describe-log-groups") and "--log-group-name-prefix" in argv


def _regions_in(argv):
    return [argv[i + 1] if i + 1 < len(argv) else None
            for i, a in enumerate(argv) if a == "--region"]


def test_every_executed_call_targets_the_configured_region(harness):
    """**按真实 argv 验目标区**：每一次调用恰好一个非空 `--region`，且值必须正确。

    上一版只验"带没带 --region"，于是把 preflight 的 `dynamodb list-tables` 改成
    `us-west-2` 时 139 条全绿（Codex 第九轮 P1-2，我复现过）。真机上那意味着
    preflight 去**错误的区**找 site-data-*，找不到就放行后续拆除 —— 目标区的站点数据
    表会被留成孤儿，而脚本一路退 0。

    判据三条：
      · 恰好一个 `--region`（多个的话谁生效取决于 CLI 解析顺序，不能靠猜）；
      · 值非空（`--region ""` 会退化成"用默认区"）；
      · 除跨区 Edge 日志那一路外，必须等于 config 的区；跨区那一路只允许
        `DescribeRegions` 返回过的区。
    """
    offenders = []
    for name, env in _COLLECT_SCENARIOS.items():
        harness("--yes", env=env)
        for argv in harness.argv:
            regions = _regions_in(argv)
            head = f"[{name}] {' '.join(argv)[:100]}"
            if len(regions) != 1:
                offenders.append(f"{head}  -> {len(regions)} 个 --region")
                continue
            got = regions[0]
            if not got:
                offenders.append(f"{head}  -> --region 的值是空的")
            elif _is_cross_region_call(argv):
                if got not in _REGIONS:
                    offenders.append(f"{head}  -> 跨区目标 {got!r} 不在 DescribeRegions 结果里")
            elif got != _PRIMARY_REGION:
                offenders.append(f"{head}  -> 打到了 {got!r}，应为 {_PRIMARY_REGION!r}")
    assert offenders == [], (
        "这些**实际执行**的调用没有精确打在配置的区上：\n  " + "\n  ".join(sorted(set(offenders))))


def test_cross_region_calls_really_hit_other_regions(harness):
    """正对照：跨区那一路确实打到了**别的**区。

    少了这条，上面那条可以靠"所有调用都在主区"（= 跨区清理根本没发生）通过。
    """
    harness("--yes")
    others = {r for argv in harness.argv if _is_cross_region_call(argv)
              for r in _regions_in(argv) if r and r != _PRIMARY_REGION}
    assert others, "没有任何调用打到非主区 ⇒ 跨区 Edge 日志清理没真的发生"
    assert others <= set(_REGIONS), others


def test_every_source_aws_call_is_actually_exercised():
    """可达性：源码里每个 (服务, 动词) 都必须至少被某个场景真的执行过。

    上一条只看得见"执行过的"调用，所以这条负责堵另一半：一个从没被执行到的调用，
    argv 守卫看不见它，它也就没有任何证据说明自己是对的。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    in_source = set()
    for line in _logical_aws_lines():
        for m in _AWS_CALL.finditer(line):
            in_source.add((m.group(1), m.group(2)))
    executed = {(a[0], a[1]) for a in _ALL_EXECUTED_ARGV if len(a) >= 2}
    missing = sorted(f"{s} {v}" for s, v in in_source - executed)
    assert missing == [], (
        "这些调用在源码里，但任何收集场景都没真的执行到它 ⇒ 它们的参数与故障行为都没被验证：\n  "
        + "\n  ".join(missing))


def test_the_scanner_actually_sees_command_substitution():
    """元测试：扫描器必须看得见 `$(aws …)` 形态。

    这条是上一版扫描洞的直接守卫——它一旦退回 `" aws " in line`，本条先红。
    """
    lines = _logical_aws_lines()
    assert any("$(aws sts" in l for l in lines), (
        "扫描器看不见 $(aws …)：那正是上一轮漏掉 sts 那一行的原因\n"
        + "\n".join(lines[:5]))


def test_region_enumeration_happens_in_preflight(harness):
    """区列表必须在 preflight 就取到——失败要发生在删任何东西**之前**。"""
    proc, calls = harness("--yes", "--stage", "preflight")
    assert proc.returncode == 0, proc.stderr
    assert any("ec2 describe-regions" in c for c in calls), (
        "preflight 没枚举区列表 ⇒ 它又回到 orphans 里现取，那时表/CMK/桶已经删了")
    assert _destructive(calls) == []


def test_region_enumeration_failure_blocks_all_deletion(harness):
    """区列表读不到 ⇒ 一条破坏性调用都不许发出。"""
    proc, calls = harness("--yes", env={"FAKE_FAIL_ON": "ec2 describe-regions",
                                        "FAKE_FAIL_CODE": "AccessDeniedException"})
    assert proc.returncode != 0
    assert _destructive(calls) == [], _destructive(calls)


# ---------------------------------------------------------------------------
# 两条 JMESPath 查询：语法 + 语义都要验（Codex 第七轮 P2-3）
#
# 假 aws **不解析 JMESPath**，所以给 Q_EDGE_FAILED 多加一个 `]` 也照样全绿——
# 语法错要到真机上才炸，而那时栈已经在删了。这里用真的 jmespath 库压住形状。
#
# 形状取自真机实测（Codex）：真实栈 10 个资源**全部没有** ResourceStatusReason 字段，
# 两条原样查询在 `--output text` 下都返回 `0`。所以"缺字段"是常态而非边角。
# ---------------------------------------------------------------------------
_Q_RE = re.compile(r'^(Q_ALL_FAILED|Q_EDGE_FAILED)="(.*)"$', re.M)


def _queries():
    qs = dict(_Q_RE.findall(_SCRIPT.read_text(encoding="utf-8")))
    assert set(qs) == {"Q_ALL_FAILED", "Q_EDGE_FAILED"}, (
        f"抓不到那两条查询（它们必须各占一行、形如 Q_XXX=\"...\"）: {sorted(qs)}")
    return qs


_EDGE_REASON = ("Lambda was unable to delete arn:aws:lambda:us-east-1:1:function:f:1 "
                "because it is a replicated function.")


def test_both_queries_are_valid_jmespath():
    """语法：两条查询必须能被 jmespath 编译。"""
    import jmespath
    for name, q in _queries().items():
        try:
            jmespath.compile(q)
        except Exception as e:            # noqa: BLE001 - 要把 name 带进报文
            raise AssertionError(f"{name} 不是合法 JMESPath: {e}\n{q}") from e


@pytest.mark.parametrize("resources,want_all,want_edge,why", [
    ([], 0, 0, "空栈"),
    # 真机形状：资源在但都不是 DELETE_FAILED，且**没有** ResourceStatusReason 字段
    ([{"ResourceStatus": "DELETE_COMPLETE", "LogicalResourceId": "X"}] * 10,
     0, 0, "10 个资源、无失败、无 Reason 字段（Codex 真机实测的形状）"),
    # 预期情况：两个 Edge 函数都因副本删不掉
    ([{"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "OriginRequestFunction1A",
       "ResourceStatusReason": _EDGE_REASON},
      {"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "OriginResponseFunction2B",
       "ResourceStatusReason": _EDGE_REASON}],
     2, 2, "只有 Edge 副本 ⇒ 全等 ⇒ 记 INCOMPLETE 退 3"),
    # 混合失败：那条 Edge 原因**不能**把桶非空盖过去
    ([{"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "OriginRequestFunction1A",
       "ResourceStatusReason": _EDGE_REASON},
      {"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "ArtifactsBucket9Z",
       "ResourceStatusReason": "The bucket you tried to delete is not empty"}],
     2, 1, "混合 ⇒ 不等 ⇒ 必须 hard-stop"),
    # **承重用例**：DELETE_FAILED 但完全没有 Reason 字段
    ([{"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "OriginRequestFunction1A"}],
     1, 0, "失败但无 Reason ⇒ 不许算成 Edge，且查询不能抛异常"),
    # 逻辑 ID 不是 Edge 函数，但原因恰好含那句话 ⇒ 不算
    ([{"ResourceStatus": "DELETE_FAILED", "LogicalResourceId": "SomethingElse7Q",
       "ResourceStatusReason": _EDGE_REASON}],
     1, 0, "原因像 Edge 但逻辑 ID 不是 ⇒ 不许算成 Edge"),
])
def test_query_semantics_on_real_shapes(resources, want_all, want_edge, why):
    """语义：两条查询在各种真实形状上必须数对。

    `want_all == want_edge != 0` 才是"预期的 Edge 副本失败"（退 3），其余一律 hard-stop。
    """
    import jmespath
    qs = _queries()
    data = {"StackResources": resources}
    got_all = jmespath.search(qs["Q_ALL_FAILED"], data)
    got_edge = jmespath.search(qs["Q_EDGE_FAILED"], data)
    assert (got_all, got_edge) == (want_all, want_edge), (
        f"{why}: 期望 (all={want_all}, edge={want_edge}) 实得 (all={got_all}, edge={got_edge})")


def test_reason_null_guard_is_load_bearing():
    """`ResourceStatusReason != null` 是**承重的**，不是防御性冗余。

    真实栈里大量资源没有这个字段；jmespath 的 `&&` 短路，去掉守卫后
    `contains(null, …)` 直接抛 JMESPathTypeError（jmespath 1.1.0 实测）。
    这条把"守卫存在"和"去掉就炸"同时钉住——否则将来有人当冗余删掉，
    上面那批用例里"无 Reason"那条会以异常而不是断言失败的形式暴露，读起来像测试坏了。
    """
    import jmespath
    q = _queries()["Q_EDGE_FAILED"]
    assert "ResourceStatusReason != null" in q, "承重守卫被删了"
    data = {"StackResources": [{"ResourceStatus": "DELETE_FAILED",
                                "LogicalResourceId": "OriginRequestFunction1A"}]}
    assert jmespath.search(q, data) == 0          # 有守卫：正常返回 0
    with pytest.raises(jmespath.exceptions.JMESPathTypeError):
        jmespath.search(q.replace("ResourceStatusReason != null && ", ""), data)


def test_single_stage_runs_do_not_need_describe_regions(harness):
    """`ec2:DescribeRegions` 被拒时，不做跨区日志清理的单阶段仍必须能跑。

    `--stage stacks` 是 runbook 推荐的 router 重试路径，它跟跨区日志毫无关系；
    让它被一个用不到的权限卡住是过度耦合（Codex 第七轮 P2-2）。
    """
    for stage in ("scripts", "dsql", "stacks"):
        proc, calls = harness("--yes", "--stage", stage,
                              env={"FAKE_FAIL_ON": "ec2 describe-regions",
                                   "FAKE_FAIL_CODE": "AccessDeniedException"})
        assert proc.returncode == 0, (
            f"--stage {stage} 被一个它用不到的权限卡住了:\n{proc.stdout}\n{proc.stderr}")
        assert not any("ec2 describe-regions" in c for c in calls), (
            f"--stage {stage} 仍然去枚举了区")


def test_orphans_still_requires_describe_regions(harness):
    """反面：`--stage orphans` 与完整运行**仍然**必须要求区列表可读，
    否则其它区的 Edge 日志组会被静默留下。"""
    for args in (("--yes", "--stage", "orphans"), ("--yes",)):
        proc, calls = harness(*args, env={"FAKE_FAIL_ON": "ec2 describe-regions",
                                          "FAKE_FAIL_CODE": "AccessDeniedException"})
        assert proc.returncode != 0, f"{args} 竟然退 0:\n{proc.stdout}"
        assert _destructive(calls) == [], _destructive(calls)


# ---------------------------------------------------------------------------
# 实际执行的 --query 必须就是顶部那两个常量（Codex 第八轮 P2-3）
#
# 上一版只验"顶部常量"是合法 JMESPath。把**实际调用**改成 `--query "length("`，
# 11 条查询/栈分类测试照样全绿——常量于是退化成没人用的"证据摆件"。
# 所以判据要落在 argv 上：真正传给 CLI 的那个字符串，必须等于常量、且能编译。
# ---------------------------------------------------------------------------

def _executed_queries(argv_rows, service_verb):
    """从 argv 里取出某个操作实际用的 --query 值（原样，不经 `$*` 拍平）。"""
    out = []
    for argv in argv_rows:
        if argv[:2] != service_verb.split():
            continue
        if "--query" in argv:
            out.append(argv[argv.index("--query") + 1])
    return out


def test_executed_stack_queries_are_exactly_the_constants(harness):
    """栈分类实际执行的 --query 必须**逐字**等于 Q_ALL_FAILED / Q_EDGE_FAILED，且可编译。"""
    import jmespath
    qs = _queries()
    harness("--yes", env={"FAKE_ROUTER_DELETE_FAILED": "1", "FAKE_MIXED_DELETE_FAILURE": "1"})
    executed = _executed_queries(harness.argv, "cloudformation describe-stack-resources")
    assert executed, "一次 describe-stack-resources 都没执行到，这条测试就没在测东西"
    known = set(qs.values())
    # 第三次是"失败明细"查询：它不是那两个常量，但同样必须可编译
    for q in executed:
        jmespath.compile(q)          # 语法：编译不过直接抛
    counts = [q for q in executed if q in known]
    assert len(counts) >= 2, (
        "实际执行的计数查询不是顶部那两个常量 —— 常量成了没人用的摆件：\n"
        + "\n".join(f"  executed: {q}" for q in executed)
        + "\n" + "\n".join(f"  constant: {q}" for q in sorted(known)))


def test_all_executed_queries_compile(harness):
    """兜底：**任何**操作实际用的 --query 都必须是合法 JMESPath。

    这条不点名具体查询，所以将来新增带 --query 的调用会自动进射程。
    """
    import jmespath
    bad = []
    for name, env in _COLLECT_SCENARIOS.items():
        harness("--yes", env=env)
        for argv in harness.argv:
            if "--query" not in argv:
                continue
            q = argv[argv.index("--query") + 1]
            try:
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    jmespath.compile(q)
                # 弃用告警也算失败：反引号字面量（`foo`）是 JMESPath 的**已弃用**写法，
                # 标准写法是 raw string `'foo'`。留着它等于赌 CLI 自带的 jmespath 版本
                # 永远不移除它；而查询一旦编译失败，preflight 的孤儿扫描就整块过不去。
                for c in caught:
                    bad.append(f"[{name}] {q}  -> {c.category.__name__}: {c.message}")
            except Exception as e:                      # noqa: BLE001
                bad.append(f"[{name}] {q}  -> {e}")
    assert bad == [], "这些实际执行的 --query 不是合法 JMESPath:\n  " + "\n  ".join(bad)


# ---------------------------------------------------------------------------
# 两个 DynamoDB waiter（Codex 第八轮 P1-1）
# ---------------------------------------------------------------------------

# 真实 aws-cli 的退出码（本地实测 2.36.34）：
#   254 服务返回错误   255 waiter 失败 / 一般 CLI 错误   252 命令解析失败
# **waiter 超时走的是 255，而 stub 原来恒 254** ⇒ `waited` 对 255 的处理从没被打过
# （Codex 第九轮 P1-1：在 waited 里加一条「rc=255 直接成功返回」，76 条仍全绿）。
# 控制流只依赖"非零"，所以三种码都要能打进来；英文报文不必精确模拟。
# **只有这一张表**（Codex 第十一轮 P2-4）：上一版参数化写 255/254/252/1，元测试又另写了
# 一遍值，于是我实测出来的 252 只进了参数化、没进元测试——把请求的 252 偷换成实际 254 时
# 252 相关的 4 条仍然全绿。两张表必然漂移，所以合成一张。
_FAIL_RC_VALUES = ("255", "254", "252", "1")
_FAIL_RC_MEANING = {"255": "waiter-failure", "254": "service-error",
                    "252": "cli-parse-error", "1": "generic-nonzero"}
_FAIL_RCS = [pytest.param(rc, id=f"rc{rc}-{_FAIL_RC_MEANING[rc]}") for rc in _FAIL_RC_VALUES]


@pytest.mark.parametrize("waiter", ["table-exists", "table-not-exists"])
@pytest.mark.parametrize("rc", _FAIL_RCS)
def test_waiter_failure_is_a_hard_stop(harness, waiter, rc):
    """waiter 失败（**任何**非零退出码）必须 hard-stop，且之后不再发任何破坏性调用。

    这两处原先是裸 `[ "$DRY_RUN" -eq 1 ] || aws dynamodb wait …`。靠 set -e 恰好能停下来
    （实测退 1），但 `_READ_VERB` 里没有 `wait` ⇒ 两个 waiter 都不在射程内，
    给其中一个加 `|| true` 时 123 条全绿。现在走 `waited`，并且逐个退出码都打一遍。
    """
    proc, calls = harness("--yes", "--stage", "orphans",
                          env={"FAKE_FAIL_ON": f"dynamodb wait {waiter}",
                               "FAKE_FAIL_RC": rc,
                               "FAKE_FAIL_CODE": "Waiter failed: Max attempts exceeded"})
    assert proc.returncode != 0, f"waiter 以 rc={rc} 失败却退 0:\n{proc.stdout}"
    idx = next(i for i, c in enumerate(calls) if f"wait {waiter}" in c)
    after = _destructive(calls[idx:])
    assert after == [], f"waiter 失败之后仍发出破坏性调用: {after}"
    assert "== 完成" not in proc.stdout, "waiter 没等到却打印了完成"


@pytest.mark.parametrize("rc", _FAIL_RCS)
def test_read_failure_hard_stops_regardless_of_exit_code(harness, rc):
    """读取失败的分类只看**报文**，不看退出码——但那件事本身要有测试压住。

    抽一个删除前的探测点打三种码：任何一种都必须 hard-stop。
    """
    proc, calls = harness("--yes", env={"FAKE_FAIL_ON": "iam list-roles",
                                        "FAKE_FAIL_RC": rc,
                                        "FAKE_FAIL_CODE": "AccessDeniedException"})
    assert proc.returncode != 0, f"rc={rc} 时退 0:\n{proc.stdout}"
    assert _destructive(calls) == [], _destructive(calls)


def test_harness_can_actually_inject_each_exit_code(tmp_path):
    """元测试：`FAKE_FAIL_RC` 真的改变了假 aws 的退出码。

    **直接调假 aws**，不经脚本——脚本自己 die 时一律退 1，从它的退出码看不出注入有没有生效。
    少了这条，上面两批用例可能只是把同一个 254 打了三遍，而那正是这一轮的缺陷本身。
    """
    aws = tmp_path / "aws"
    aws.write_text(_FAKE_AWS, encoding="utf-8")
    os.chmod(aws, 0o755)
    # **每次换一个 FAKE_LOG**：nth-match 的计数落在 `$FAKE_LOG.match-count` 上，
    # 复用同一个 log 会让第 2 次之后的调用不再命中（n≠1）。
    for i, want in enumerate(_FAIL_RC_VALUES):
        proc = subprocess.run(["bash", str(aws), "iam", "list-roles"],
                              capture_output=True, text=True,
                              env={**os.environ, "FAKE_LOG": str(tmp_path / f"log{i}"),
                                   "FAKE_FAIL_ON": "iam list-roles",
                                   "FAKE_FAIL_RC": want})
        assert proc.returncode == int(want), (
            f"注入 rc={want} 但假 aws 退了 {proc.returncode} —— FAKE_FAIL_RC 没生效")
    # 不给 FAKE_FAIL_RC 时默认 254（服务错误，最常见的一种）
    proc = subprocess.run(["bash", str(aws), "iam", "list-roles"],
                          capture_output=True, text=True,
                          env={**os.environ, "FAKE_LOG": str(tmp_path / "log-default"),
                               "FAKE_FAIL_ON": "iam list-roles"})
    assert proc.returncode == 254, proc.returncode


def test_both_waiters_are_in_range():
    """元测试：两个 waiter 都必须作为独立调用点进射程。

    `_READ_VERB` 一旦漏掉 `wait`，本条先红。
    """
    waits = {c for (c, _n) in _READ_POINTS if " wait " in f" {c} "}
    for w in ("table-exists", "table-not-exists"):
        assert any(w in c for c in waits), (
            f"waiter {w} 不在射程内:\n{sorted(waits)}")


def test_argv_splitter_preserves_empty_arguments():
    """`_split_argv` 必须保住空参数，只丢 printf 尾部那一个哨兵空元素。

    这条是独立守卫：只靠"某处真的传了 `--region ''`"来间接发现它是不够的——
    变形实测过，单独把切分改回 `[a for a in parts if a]` 时其余用例全绿。
    """
    assert _split_argv("iam\tlist-roles\t--region\t\t") == ["iam", "list-roles", "--region", ""]
    assert _split_argv("a\tb\t") == ["a", "b"]
    assert _split_argv("\t") == [""]        # 单个空参数
    assert _split_argv("a\t\t\tb\t") == ["a", "", "", "b"]


def test_argv_log_round_trips_an_empty_argument(tmp_path):
    """端到端：假 aws 写出的 argv 日志里，空参数必须能被原样读回。

    光测切分函数不够——写入侧（`printf '%s\t' "$@"`）也可能把空参数吃掉。
    """
    aws = tmp_path / "aws"
    aws.write_text(_FAKE_AWS, encoding="utf-8")
    os.chmod(aws, 0o755)
    log = tmp_path / "log"
    subprocess.run(["bash", str(aws), "iam", "list-roles", "--region", ""],
                   capture_output=True, text=True,
                   env={**os.environ, "FAKE_LOG": str(log)})
    rows = [_split_argv(l) for l in
            Path(f"{log}.argv").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows == [["iam", "list-roles", "--region", ""]], rows


# ---------------------------------------------------------------------------
# 目标标识符必须**精确**（Codex 第十轮 P1-2）
#
# region 那一轮的教训是"验参数存在不等于验值正确"，但当时只把它落到了 --region 上。
# 把 `site-panel` 拼成 `site-pnael` 时 150 条全绿：stub 对任何名字都回 PRESENT，
# 于是错名被删、真正的 panel 静默留下，真机上 get-function 会 NotFound ⇒ 跳过 ⇒ 退 0。
#
# 下面这张表是"脚本应该动哪些固定资源"的**独立陈述**：它不从脚本抽取，
# 所以脚本改名时会红——那正是想要的。动态资源（日志组 / KMS key / site_id）
# 由后面几条按"来源与删除目标一致"来验。
# ---------------------------------------------------------------------------
_EXPECTED_TARGETS = {
    "--function-name": {"site-panel", "site-auth-service", "site-auth-pre-token",
                        "site-key-proxy"},
    "--role-name": {"site-panel-role", "site-auth-service-role", "site-mcp-runtime-role",
                    "site-key-proxy-role", "site-builder-verifier"},
    "--table-name": {"site-sites", "site-access-daily", "site-admins",
                     "site-api-keys", "site-ops-log"},
    "--stack-name": {_ROUTER_STACK, "SiteDeployerStack"},
    "--repository-name": {"site-builder-mcp"},
    "--repository-names": {"site-builder-mcp"},
    "--bucket": {f"site-frontend-{_ACCOUNT}"},
    "--alarm-names": {"site-builder-auth-invalid-grant"},
    "--topic-arn": {f"arn:aws:sns:{_PRIMARY_REGION}:{_ACCOUNT}:site-builder-alarms"},
    "--user-pool-id": {"us-east-1_platform", "us-east-1_idp"},
    "--name": {"/site-builder/site-client-secret", "/site-builder/login-flow-secret",
               "/site-builder/machine-client-secret"},
    "--identifier": {"abcdefghij0123456789abcdef"},          # DSQL cluster（config 里那个）
    "--agent-runtime-id": {"site_builder_deploy-AAAA"},
}


def test_fixed_resource_targets_are_exact(harness):
    """每一次调用打的固定资源标识符都必须在预期集合里。"""
    offenders = []
    for name, env in _COLLECT_SCENARIOS.items():
        harness("--yes", env=env)
        for argv in harness.argv:
            for i, a in enumerate(argv):
                if a not in _EXPECTED_TARGETS or i + 1 >= len(argv):
                    continue
                got = argv[i + 1]
                if got not in _EXPECTED_TARGETS[a]:
                    offenders.append(f"[{name}] {a} {got!r}  <-  {' '.join(argv)[:90]}")
    assert offenders == [], (
        "这些调用打在了预期之外的目标上（名字拼错的症状：真机上判成「不存在」⇒ 静默留下真货）：\n  "
        + "\n  ".join(sorted(set(offenders))))


def test_s3_rm_only_empties_the_frontend_bucket(harness):
    """`aws s3 rm` 的目标是**位置参数**（argv[2]），不带 --bucket，所以逃过了
    `_EXPECTED_DESTRUCTIVE_TARGETS` 那套按旗标的校验（Codex 第十二轮 P1-1）：
    把清空目标改成别的桶时 193 条全绿，而 `s3 rm --recursive` 会递归删光别人的对象。
    """
    harness("--yes")
    rm_targets = [argv[2] for argv in harness.argv
                  if tuple(argv[:2]) == ("s3", "rm") and len(argv) > 2]
    assert rm_targets, "一次 s3 rm 都没发生 ⇒ 这条测试没在测东西"
    for tgt in rm_targets:
        assert tgt == f"s3://site-frontend-{_ACCOUNT}", (
            f"s3 rm 打在了 {tgt!r}，不是前端桶 —— --recursive 会递归误删别人的对象")


def test_every_expected_target_is_actually_touched(harness):
    """正对照：预期集合里的每一个固定资源都必须真的被碰过。

    少了这条，上面那条可以靠"脚本少删一堆东西"通过（漏删同样是缺陷）。
    """
    touched = {k: set() for k in _EXPECTED_TARGETS}
    for env in _COLLECT_SCENARIOS.values():
        harness("--yes", env=env)
        for argv in harness.argv:
            for i, a in enumerate(argv):
                if a in touched and i + 1 < len(argv):
                    touched[a].add(argv[i + 1])
    missing = {k: sorted(v - touched[k]) for k, v in _EXPECTED_TARGETS.items()
               if v - touched[k]}
    assert not missing, f"这些预期资源一次都没被碰过（漏删？）: {missing}"


def _expected_log_deletions():
    """脚本应发出的 (region, log-group) 删除，各恰好一次。

    本区（describe-log-groups）删归属清单里的全部：平台件 + 每个 site_id + 本区 Edge 副本。
    每个非主区（prefix 查询）只删那一份 Edge 副本。外来的（redirectEdge / unrelated）永不删。
    """
    from collections import Counter
    c = Counter()
    c[(_PRIMARY_REGION, "/aws/lambda/site-panel")] += 1
    c[(_PRIMARY_REGION, "/aws/codebuild/site-package")] += 1
    c[(_PRIMARY_REGION, _OWNED_EDGE_LG)] += 1
    c[(_PRIMARY_REGION, _OWNED_AGENTCORE_LG)] += 1
    c[(_PRIMARY_REGION, "/aws/lambda/site-deployer-validate")] += 1
    c[(_PRIMARY_REGION, "/aws/lambda/site-access-rollup")] += 1
    for sid in _SITE_IDS:
        c[(_PRIMARY_REGION, f"/aws/lambda/site-{sid}")] += 1
    for r in _REGIONS:
        if r != _PRIMARY_REGION:
            c[(r, _OWNED_EDGE_LG)] += 1
    return c


def test_log_group_deletions_match_discovery_exactly(harness):
    """日志组删除的 (region, name) 多重集必须与预期**逐条相等**（Codex 第十二轮 P1-2）。

    上一版只查"非主区删的是不是 Edge 形态"（防误删），不查完整性：把某个已发现的
    归属日志（如 CodeBuild）在 stub 里换成别的名字时，那条日志静默不被删、守卫仍全绿。
    完整性 + 次数一起钉，才同时挡住"漏删"和"发错区/删两次"。
    """
    from collections import Counter
    harness("--yes")
    got = Counter()
    for argv in harness.argv:
        if tuple(argv[:2]) != ("logs", "delete-log-group"):
            continue
        name = argv[argv.index("--log-group-name") + 1]
        got[(_regions_in(argv)[0], name)] += 1
    expected = _expected_log_deletions()
    assert got == expected, (
        f"多删/发错区: {sorted((got - expected).elements())}\n"
        f"漏删: {sorted((expected - got).elements())}")


def test_foreign_edge_logs_are_never_deleted_in_any_region(harness):
    """负向：账号里别人的 Edge 日志（redirectEdge）任何区都不许删。"""
    harness("--yes", env={"FAKE_UNOWNED_LOG_GROUP": _FOREIGN_EDGE_LG})
    for argv in harness.argv:
        if tuple(argv[:2]) == ("logs", "delete-log-group"):
            assert argv[argv.index("--log-group-name") + 1] != _FOREIGN_EDGE_LG, argv


def test_kms_keys_are_scheduled_exactly_and_completely(harness):
    """四把 key 逐把断言结果：**两把签名 key 都要排期**，外来的与已排期的都不许动。

    上一版夹具只有一把 key，断言又只是 `deleted <= listed`（只防误删、不防少删）——
    在循环首轮后加个 `break`，5 条相关测试全绿，而真机上那会把第二把
    "能签会话的 key" 静默留在账号里（Codex 第十一轮 P1-2）。
    """
    harness("--yes")
    from collections import Counter
    scheduled = Counter(argv[argv.index("--key-id") + 1] for argv in harness.argv
                        if tuple(argv[:2]) == ("kms", "schedule-key-deletion"))
    # **用 Counter，不是 set**（Codex 第十二轮 P2）：每把活动 CMK 连续排期两次时
    # set 相等仍绿；这里断言两把签名 key **各恰好一次**、外来 / PendingDeletion **零次**。
    expected = Counter({k: 1 for k in _KMS_SHOULD_SCHEDULE})
    assert scheduled == expected, (
        f"排期次数不对：实得 {dict(scheduled)}，期望 {dict(expected)}")
    for k in set(_KMS_KEYS) - _KMS_SHOULD_SCHEDULE:
        assert scheduled[k] == 0, f"{k} 不该被排期却排了 {scheduled[k]} 次"
    # 每把都必须被 describe 过（否则"漏排期"可能只是压根没看）
    described = {argv[argv.index("--key-id") + 1] for argv in harness.argv
                 if tuple(argv[:2]) == ("kms", "describe-key")}
    assert described == set(_KMS_KEYS), f"没逐把看过: {set(_KMS_KEYS) - described}"


def test_kms_deletion_targets_come_from_the_listing(harness):
    """动态资源：排期删除的 key 必须来自 list-keys 的输出，不能凭空出现。"""
    harness("--yes")
    assert any(tuple(argv[:2]) == ("kms", "list-keys") for argv in harness.argv)
    scheduled = {argv[argv.index("--key-id") + 1] for argv in harness.argv
                 if tuple(argv[:2]) == ("kms", "schedule-key-deletion")}
    assert scheduled <= set(_KMS_KEYS), f"删了没列举到的 key: {scheduled - set(_KMS_KEYS)}"


# ---------------------------------------------------------------------------
# 破坏性 API 的目标**全集与次数**（Codex 第十一轮 P1-1）
#
# 上一版按参数名把所有读写调用汇总起来验"值在合法集合里"，于是把四次
# `delete-function` 全改成删 `site-panel` 时 172 条全绿：`site-panel` 在合法集合里，
# 而"每个目标都被碰过"那条正对照被**读探测**替所有目标满足了。
# 真机后果：panel 被删四次，另外三个平台 Lambda 静默留下，整轮退 0。
#
# 所以判据必须绑在**具体的破坏性 API** 上，并且验的是多重集（含次数），不是子集。
# ---------------------------------------------------------------------------
_LAMBDAS = ["site-auth-pre-token", "site-auth-service", "site-key-proxy", "site-panel"]
_ROLES = ["site-auth-service-role", "site-builder-verifier", "site-key-proxy-role",
          "site-mcp-runtime-role", "site-panel-role"]
_RETAIN_TABLES = ["site-access-daily", "site-admins", "site-api-keys", "site-ops-log"]
_SSM_PARAMS = ["/site-builder/login-flow-secret", "/site-builder/machine-client-secret",
               "/site-builder/site-client-secret"]
_POOLS = ["us-east-1_idp", "us-east-1_platform"]

_EXPECTED_DESTRUCTIVE_TARGETS = {
    ("lambda", "delete-function-url-config"): ("--function-name", _LAMBDAS),
    ("lambda", "delete-function"): ("--function-name", _LAMBDAS),
    ("iam", "delete-role"): ("--role-name", _ROLES),
    ("iam", "delete-role-policy"): ("--role-name", _ROLES),
    ("iam", "detach-role-policy"): ("--role-name", _ROLES),
    ("dynamodb", "delete-table"): ("--table-name", _RETAIN_TABLES),
    ("dynamodb", "update-table"): ("--table-name", _RETAIN_TABLES),
    ("ssm", "delete-parameter"): ("--name", _SSM_PARAMS),
    ("cognito-idp", "delete-user-pool"): ("--user-pool-id", _POOLS),
    ("cognito-idp", "delete-user-pool-domain"): ("--user-pool-id", _POOLS),
    ("cloudformation", "delete-stack"): ("--stack-name",
                                         sorted([_ROUTER_STACK, "SiteDeployerStack"])),
    ("ecr", "delete-repository"): ("--repository-name", ["site-builder-mcp"]),
    ("cloudwatch", "delete-alarms"): ("--alarm-names", ["site-builder-auth-invalid-grant"]),
    ("sns", "delete-topic"): ("--topic-arn",
                              [f"arn:aws:sns:{_PRIMARY_REGION}:{_ACCOUNT}:site-builder-alarms"]),
    ("s3api", "delete-bucket"): ("--bucket", [f"site-frontend-{_ACCOUNT}"]),
    ("bedrock-agentcore-control", "delete-agent-runtime"): ("--agent-runtime-id",
                                                           ["site_builder_deploy-AAAA"]),
    ("dsql", "delete-cluster"): ("--identifier", ["abcdefghij0123456789abcdef"]),
}


@pytest.mark.parametrize("api", sorted(_EXPECTED_DESTRUCTIVE_TARGETS),
                         ids=lambda a: "-".join(a))
def test_destructive_api_targets_are_exact_and_complete(harness, api):
    """每个破坏性 API 打的目标**多重集**必须与预期逐字相等（含次数）。

    子集不够：全删同一个目标是子集，漏删也是子集。
    """
    flag, expected = _EXPECTED_DESTRUCTIVE_TARGETS[api]
    harness("--yes")
    got = sorted(argv[argv.index(flag) + 1] for argv in harness.argv
                 if tuple(argv[:2]) == api and flag in argv)
    assert got == sorted(expected), (
        f"{' '.join(api)} 的目标不对\n  实得: {got}\n  期望: {sorted(expected)}")


# ---------------------------------------------------------------------------
# fail-closed 分类的元测试
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("call", [
    "lambda remove-permission --function-name x",
    "s3api abort-multipart-upload --bucket x",
    "iam put-role-policy --role-name x",
    "dynamodb update-table --table-name x",
    "cloudfront update-distribution --id x",
    "kms disable-key --key-id x",
])
def test_unknown_write_verbs_default_to_destructive(call):
    """未登记的写操作必须**默认**算破坏性（Codex 第十轮 P1-3 点名的三个都在里面）。

    人工关键词表的失效方式是单向且无声的：没进表的动作自动脱离射程。
    """
    assert _is_destructive(call), f"{call} 被判成非破坏性 ⇒ 它脱离了射程"


@pytest.mark.parametrize("call", [
    "iam get-role --role-name x", "dynamodb describe-table --table-name x",
    "kms list-keys", "s3api head-bucket --bucket x", "dynamodb scan --table-name x",
    "dynamodb wait table-not-exists --table-name x", "s3 ls",
])
def test_readonly_verbs_are_classified_readonly(call):
    """反面：只读动词不能被误判成破坏性，否则"注入点之后无破坏性调用"会永远假红。"""
    assert not _is_destructive(call), call


def test_destructive_operations_actually_executed_are_the_expected_set(harness):
    """脚本实际发出的破坏性操作集合必须**逐字**等于预期。

    fail-closed 保证新动作不会脱离射程；这条再加一层：新增一种删除动作会让本条红，
    强迫作者**有意识地**把它登记进来（而不是悄悄多删一样东西）。
    """
    got = set()
    for env in _COLLECT_SCENARIOS.values():
        harness("--yes", env=env)
        for argv in harness.argv:
            if _is_destructive(argv):
                got.add(f"{argv[0]} {argv[1]}")
    expected = {
        "bedrock-agentcore-control delete-agent-runtime",
        "ecr delete-repository",
        "lambda delete-function-url-config", "lambda delete-function",
        "iam delete-role-policy", "iam detach-role-policy", "iam delete-role",
        "cloudwatch delete-alarms", "sns delete-topic",
        "cognito-idp delete-user-pool-domain", "cognito-idp delete-user-pool",
        "ssm delete-parameter",
        "dsql delete-cluster",
        "cloudformation delete-stack",
        "dynamodb update-table", "dynamodb delete-table",
        "kms schedule-key-deletion",
        "s3 rm", "s3api delete-bucket",
        "logs delete-log-group",
    }
    assert got == expected, (
        f"多出来的: {sorted(got - expected)}\n少掉的: {sorted(expected - got)}")


def test_teardown_section_rejects_shell_substitution():
    """围栏块里**不许**出现命令替换 / 反引号。

    它们能把第二条命令藏在参数里：把输出路径写成
    `/tmp/undeploy.json$(aws lambda invoke --function-name site-panel /tmp/e.json)`
    时，按分隔符切分的解析器只看到外层命令，而 bash 会**先**执行内层那条
    （Codex 第十三轮 P2-3，实测）。可照抄的 runbook 命令没有任何理由需要它们，
    所以这里直接拒绝，而不是去写一个懂 shell 结构的解析器。

    **必须按整块扫**（Codex 第十六轮 P2-2，实测）：按物理行时引号状态每行归零，而
    `#` 在双引号内不是注释，于是

        JOB2="{
        # '$(aws s3 rm s3://other --recursive)'
        }"

    被当成"一行注释"整行跳过，bash 却执行了内层删除。
    """
    offenders = []
    for block in _fenced_bash(_teardown_section()):
        # **白名单**，不是黑名单：`$($'a''ws' …)` 这种拼法没有连续的字面 aws，
        # 追它的拼法追不完（Codex 第十四轮 P2-3 实测绕过了"体里含 aws 就拒"）。
        # runbook 只需要 `$(git rev-parse --show-toplevel)` 这一条。
        _cmds, subs, unterminated = _lex_block(block)
        if unterminated:
            offenders.append(f"{block.strip()[:90]}   <- 块扫完仍在引号/替换内")
        for body in subs:
            if body.strip() not in _DOC_ALLOWED_SUBST:
                offenders.append(f"命令替换 $({body.strip()[:60]}) 不在白名单")
    assert offenders == [], (
        "拆除一节的围栏块里出现了命令替换——它可以把额外的 aws 调用藏进参数里：\n  "
        + "\n  ".join(offenders))


def test_teardown_section_rejects_ansi_c_quoting():
    """围栏块里**不许**出现 `$'…'` / `$"…"`。

    `shlex` 不认它们（`$'--function-name'` → `$--function-name`），而 bash 展开后是
    一个**生效的旗标**：往豁免命令尾部塞 `$'--function-name' site-panel` 时三条守卫
    全绿、真实 CLI 打的却是 site-panel（Codex 第十五轮 P2-2，实测）。可照抄的 runbook
    不需要这种引用，所以按写法拒掉，而不是去追 shlex 与 bash 的语义差。

    注释同样要按**词法状态**剥（第十六轮 P2-2）：所以扫的是 `_lex_block` 切出来的
    逻辑命令，不是物理行。
    """
    offenders = [c[:110] for block in _fenced_bash(_teardown_section())
                 for c in _lex_block(block)[0] if _ANSI_C_QUOTE.search(c)]
    assert offenders == [], (
        "拆除一节的围栏块里出现了 ANSI-C / locale 引用（$'…' / $\"…\"），"
        "解析器与 bash 对它的理解不一致：\n  " + "\n  ".join(offenders))


# (脚本里的 service, operation) -> botocore 的 (service_id, OperationName)。
#
# **两个模型守卫必须共用这一张表**（Codex 第十五轮 P2-4，实测）：分成两份写时，
# 补集那份少了 `dynamodb scan` 与 `lambda get-function-url-config`，于是给
# Scan 的 `InternalServerError` 开一条 ABSENT 后门（声明表保持不变）时 242 条全绿，
# 注入后脚本继续删、退 0。覆盖范围由
# `test_model_probe_map_covers_every_declared_operation` 钉在脚本的 `_absent_codes` 上。
_MODEL_PROBE = {
    ("dynamodb", "describe-table"): ("dynamodb", "DescribeTable"),
    ("dynamodb", "scan"): ("dynamodb", "Scan"),
    ("iam", "get-role"): ("iam", "GetRole"),
    ("lambda", "get-function"): ("lambda", "GetFunction"),
    ("lambda", "get-function-url-config"): ("lambda", "GetFunctionUrlConfig"),
    ("ecr", "describe-repositories"): ("ecr", "DescribeRepositories"),
    ("cognito-idp", "describe-user-pool"): ("cognito-idp", "DescribeUserPool"),
    ("sns", "get-topic-attributes"): ("sns", "GetTopicAttributes"),
    ("ssm", "get-parameter"): ("ssm", "GetParameter"),
    ("kms", "describe-key"): ("kms", "DescribeKey"),
    ("dsql", "get-cluster"): ("dsql", "GetCluster"),
    ("bedrock-agentcore-control", "get-agent-runtime"):
        ("bedrock-agentcore-control", "GetAgentRuntime"),
}

# 唯一允许缺席模型守卫的操作，必须**显式**列出并说明依据：
# `GetBucketLocation` 在本地模型里 error_shapes 为空（S3 不走 typed error 那套），
# 它的 `NoSuchBucket` 依据是真机实测（见 test_stub_uses_real_cli_error_shapes 的注释），
# 不是服务模型。誤收面由 `_NOT_ABSENT_CASES` 里那条 `s3api get-bucket-location`+
# `AccessDenied` 守着。
_MODEL_PROBE_EXEMPT = {("s3api", "get-bucket-location")}


def _declared_absent_operations():
    """脚本 `_absent_codes` 里登记过的全部 (service, operation)。"""
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_absent_codes() {"):script.index("# _outer_code <errtext>")]
    return set(re.findall(r'"([a-z0-9-]+) ([a-z0-9-]+)"\)?', body))


def test_model_probe_map_covers_every_declared_operation():
    """脚本登记的每个操作都必须进两张核对表，缺席只能走显式豁免。

    这条是上一轮那个洞的根：漏一个操作时，"该操作声明之外的码一律 NOT_ABSENT"
    这条补集断言对它形同不存在（Codex 第十五轮 P2-4）。加新操作时它会红。
    """
    declared = _declared_absent_operations()
    assert declared, "没从脚本里解析出任何登记操作——解析器该修了"
    missing = declared - set(_MODEL_PROBE) - _MODEL_PROBE_EXEMPT
    assert missing == set(), (
        f"这些操作登记在脚本里，却没进 _MODEL_PROBE（也没显式豁免）：{sorted(missing)}")
    stale = (set(_MODEL_PROBE) | _MODEL_PROBE_EXEMPT) - declared
    assert stale == set(), f"这些操作在核对表里，脚本里却没登记：{sorted(stale)}"


def test_absent_codes_match_botocore_wire_codes():
    """表里每个码都必须是该操作真正的 **wire code**（对着 botocore 服务模型核对）。

    `NotFoundException` 这种**异常类型名**不等于 wire code：SNS 的那个 shape
    `error.code` 是 `NotFound`。写成类型名的后果不是报错而是**幂等回归**——真的没有
    topic 时判 UNKNOWN，重跑一个已清空的账号就在这里 hard-stop（Codex 第十三轮 P2-2）。
    有了这条，表就不会再凭"看起来像"去写码。
    """
    import botocore.session
    sess = botocore.session.get_session()
    probe = _MODEL_PROBE
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_absent_codes() {"):script.index("# _outer_code <errtext>")]
    problems = []
    for (svc, op), (bsvc, bop) in probe.items():
        prog = "set -uo pipefail\n" + body + '\n_absent_codes "$1" "$2"\n'
        out = subprocess.run(["bash", "-c", prog, "_", svc, op],
                             capture_output=True, text=True)
        declared = set(out.stdout.split())
        assert declared, f"表里 {svc} {op} 没有任何码（应至少一条）: {out.stderr}"
        model = sess.get_service_model(bsvc).operation_model(bop)
        wire = {sh.metadata.get("error", {}).get("code", sh.name) for sh in model.error_shapes}
        shapes = {sh.name: sh.metadata.get("error", {}).get("code", sh.name)
                  for sh in model.error_shapes}
        for code in declared:
            if code in wire:
                continue
            hint = f"（它是异常类型名，wire code 应为 {shapes[code]!r}）" if code in shapes else ""
            problems.append(f"{svc} {op}: 声明了 {code}，不在该操作的 wire code 集合里{hint}")
    assert problems == [], "\n  ".join(problems)


def test_own_agentcore_log_group_is_deleted(harness):
    """自己的 AgentCore runtime 日志组必须被删（Codex 第十三轮 P2-4 的正例）。

    只有别人的 runtime 那条负例时，把归属前缀 `runtimes/` 拼成 `runtime/`
    也全绿——因为完整性 Counter 的输入里压根没有这个资源。
    """
    harness("--yes")
    deleted = {argv[argv.index("--log-group-name") + 1] for argv in harness.argv
               if tuple(argv[:2]) == ("logs", "delete-log-group")}
    assert _OWNED_AGENTCORE_LG in deleted, (
        f"自己的 AgentCore 日志组没被删:\n{sorted(deleted)}")


@pytest.mark.parametrize("line,want", [
    # 单引号内的反引号是 JMESPath 字面量，不是命令替换
    ("""aws iam list-roles --query 'Roles[?starts_with(RoleName,`site-`)].RoleName'""", []),
    # 双引号内的 $( ) 会展开
    ('cd "$(git rev-parse --show-toplevel)"', ["git rev-parse --show-toplevel"]),
    # 裸 $( ) 会展开
    ("echo $(date)", ["date"]),
    # 双引号内的反引号会展开
    ('echo "`id`"', ["id"]),
    # 嵌套括号要配对取完整体
    ("x=$(foo $(bar) baz)", ["foo $(bar) baz"]),
    # Codex 的绕过形态：体里没有连续的字面 aws，但仍是命令替换 ⇒ 必须被取出来
    ("""echo /tmp/x$($'a''ws' s3 rm s3://other --recursive)""",
     ["""$'a''ws' s3 rm s3://other --recursive"""]),
    # 第十五轮 P2-3：裸 `\'` 是**字面**单引号、不开引号段，bash 照样执行内层替换。
    # 不认转义的扫描器会以为进了单引号 ⇒ 返回空表 ⇒ 三条守卫全绿。
    ("""echo /tmp/undeploy.json\\'$(aws s3 rm s3://other --recursive)""",
     ["aws s3 rm s3://other --recursive"]),
    # 双引号内 `\"` 转义的是引号本身，不许把 dq 状态翻反（本节的 --item 真实用到这种拼法）
    ('''aws dynamodb put-item --item "{\\"S\\":\\"x\\"}" && echo $(id)''', ["id"]),
    # 单引号内的反斜杠是**字面量**，不转义后面那个引号 ⇒ 引号段在此结束，`$( )` 会展开
    ("""echo 'a\\'$(id)""", ["id"]),
    # 双引号内 `\\$` 转义掉了 `$` ⇒ 那不是命令替换
    ('''echo "\\$(id)"''', []),
])
def test_command_substitution_extractor_respects_quotes(line, want):
    """提取器必须区分引号状态：单引号内不展开、双引号内展开。

    弄错任一侧都有代价：把单引号内的 JMESPath 反引号当替换 ⇒ 假红；
    漏掉双引号内的替换 ⇒ 藏在参数里的第二条命令逃出守卫。
    """
    assert _command_substitutions(line) == want


@pytest.mark.parametrize("cmd,want_dup", [
    ("aws lambda invoke --function-name a --function-name=b out.json", True),
    ('aws lambda invoke --function-name a "--function-name" b out.json', True),
    ("aws lambda invoke --function-name=a out.json", False),
    ("aws lambda invoke --function-name a out.json", False),
])
def test_doc_tokenizer_detects_duplicate_targets_in_both_syntaxes(cmd, want_dup):
    """`--flag=value` 与带引号的 `"--flag"` 都必须归一到同一个 token（第十四轮 P2-2）。

    这条验的是分词的**规范化**：`_DOC_ALLOWED_ARGV` 按 token 逐项等值比，两种写法
    必须落到同一串，否则"整条 argv 相等"这个判据自己就有两种写法的缝。
    """
    parts = _shell_tokens(cmd)
    assert parts is not None
    idxs = [j for j, a in enumerate(parts) if a == "--function-name"]
    assert (len(idxs) > 1) is want_dup, parts


# ── 历轮的守卫缺口：都用"往围栏块里塞一段"的形态钉住 ────────────────────────
# 每条都给出**bash 的真实语义**与**当时解析器的看法**，两者不一致就是洞。
_ANCHOR_INVOKE = "aws lambda invoke --function-name site-deployer-undeploy"
_DOC_BYPASS_CASES = [
    # P2-2：双引号跨行 + 引号内的 `#` 不是注释 ⇒ 整段被当注释跳过
    ("跨行引用把命令替换藏进注释里", "aws dsql list-clusters --region us-east-1",
     'JOB2="{\n# \'$(aws s3 rm s3://other --recursive)\'\n}"\naws dsql list-clusters --region us-east-1'),
    # P2-3：子 shell 分组符不在分隔符表里 ⇒ 分词得到 `(aws`，token 与正则同时落空
    ("子 shell 里的带引号 aws", "aws dsql list-clusters --region us-east-1",
     'aws dsql list-clusters --region us-east-1\n'
     '("aws" lambda invoke --function-name site-panel /tmp/e.json)'),
    # P2-4：`\`+换行是行继续，两个字符都消失；补空格会把生效的旗标拆成两个词
    ("续行拼出第二个 --function-name",
     "--payload \"{\\\"site_id\\\":\\\"e2e-probe\\\",\\\"job_id\\\":\\\"$JOB\\\",\\\"purge_data\\\":true}\" /tmp/undeploy.json",
     "--payload \"{\\\"site_id\\\":\\\"e2e-probe\\\",\\\"job_id\\\":\\\"$JOB\\\",\\\"purge_data\\\":true}\" "
     "--function-\\\n  name site-panel /tmp/undeploy.json"),
    # P2-5：AWS CLI 接受长选项的唯一前缀缩写（实测 aws-cli 2.36.34 打到 site-panel）
    ("缩写旗标 --function-n",
     "--payload \"{\\\"site_id\\\":\\\"e2e-probe\\\",\\\"job_id\\\":\\\"$JOB\\\",\\\"purge_data\\\":true}\" /tmp/undeploy.json",
     "--payload \"{\\\"site_id\\\":\\\"e2e-probe\\\",\\\"job_id\\\":\\\"$JOB\\\",\\\"purge_data\\\":true}\" "
     "--function-n site-panel /tmp/undeploy.json"),
    # ── 第十七轮 ────────────────────────────────────────────────────────────
    # P2-1：`${VAR:-默认}` 里的默认值会被展开；未设置时内层替换真的执行（实测 R1）
    ("参数展开的默认值里藏替换", "aws dsql list-clusters --region us-east-1",
     'echo "${UNSET:-$("aws" s3 rm s3://other --recursive)}"\n'
     'aws dsql list-clusters --region us-east-1'),
    # P2-2a：bash 把 `{#` 当普通词（实测 `echo {#` 打出 `{#`）；无条件在 `{` 断句会让
    #        `#` 落到词首、被当注释，把整条替换吞掉（实测 R2 照样执行）
    ("{# 让后半行被当成注释", "aws dsql list-clusters --region us-east-1",
     'echo {# $("aws" s3 rm s3://other --recursive)\n'
     'aws dsql list-clusters --region us-east-1'),
    # P2-2b：brace expansion —— `{aws,}` 展开出一个字面 `aws`
    ("brace expansion 拼出 aws", "aws dsql list-clusters --region us-east-1",
     '{aws,} s3 rm s3://other --recursive\n'
     'aws dsql list-clusters --region us-east-1'),
    # P2-3：前置全局参数把 (服务, 动词) 挪位 ⇒ `list-` 前缀让整条当只读跳过
    ("前置 --profile 顶掉服务/动词位", "aws dsql list-clusters --region us-east-1",
     'aws dsql list-clusters --region us-east-1\n'
     'aws --profile list-prod lambda invoke --function-name site-panel /tmp/e.json'),
    # P2-4：前置环境赋值换掉整套凭据/账号，而服务与动词一个字都没变
    ("前置 AWS_PROFILE= 换账号",
     "aws lambda invoke --function-name site-deployer-undeploy",
     "AWS_PROFILE=other-account aws lambda invoke --function-name site-deployer-undeploy"),
    # P2-5：未引用 delimiter 的 heredoc 里，单引号**不阻止**命令替换（实测 R5 执行了）
    ("heredoc 里单引号不挡替换", "aws dsql list-clusters --region us-east-1",
     "cat <<EOF\n'$(\"aws\" s3 rm s3://other --recursive)'\nEOF\n"
     "aws dsql list-clusters --region us-east-1"),
    # ── 第十八轮：都在假 aws 上真机确认过实际效果（见 REVIEW 里那张表）────────
    # P2-1a：命令名藏在变量里 ⇒ 源文本里没有 `aws` 这个 token（实测打到 site-panel）
    ("变量当命令名", _ANCHOR_INVOKE,
     'REVIEW_CMD=aws\n"$REVIEW_CMD" lambda invoke --function-name site-panel '
     '--region us-east-1 /tmp/review.json\n' + _ANCHOR_INVOKE),
    # P2-1b：内层 shell 把字符串再解释一遍；单引号只挡外层展开，不挡 `bash -c`
    ("bash -c 里再解释一遍", _ANCHOR_INVOKE,
     "bash -c '\"aws\" lambda invoke --function-name site-panel "
     "--region us-east-1 /tmp/review.json'\n" + _ANCHOR_INVOKE),
    # P2-2a：独占一行的 export 改掉后续命令继承的凭据（实测 AWS_PROFILE=other-account）
    ("独占一行的 export 换凭据", _ANCHOR_INVOKE,
     "export AWS_PROFILE=other-account\n" + _ANCHOR_INVOKE),
    # P2-2b：裸赋值也行 —— 重新赋值不会清除变量已有的 export 属性
    ("独占一行的裸赋值换凭据", _ANCHOR_INVOKE,
     "AWS_PROFILE=other-account\n" + _ANCHOR_INVOKE),
    # P2-3：豁免命令一字不改，靠 $JOB 的值往 payload 里多塞一个 site_id
    #      （json 取后者 ⇒ 目标变成 victim，purge_data 还是 true）
    ("$JOB 的值改掉 payload 语义", _ANCHOR_INVOKE,
     "JOB=\\\n'job-teardown-e2e-probe\",\"site_id\":\"victim'\n" + _ANCHOR_INVOKE),
    # ── 第十九轮（我自己这轮对抗补的两条，见交接件里的弱点 1 与 4）───────────────
    # 只读命令整条不受 argv 等值约束 ⇒ `--endpoint-url` / `--profile` 能把一条签名过的
    # 请求发往别处、或让"体检"读的是另一个账号。旗标正向表关掉这一族。
    ("只读命令上的 --endpoint-url", "aws dsql list-clusters --region us-east-1",
     "aws dsql list-clusters --region us-east-1 --endpoint-url http://127.0.0.1:1"),
    ("只读命令上的 --profile", "aws kms list-keys --region us-east-1",
     "aws kms list-keys --region us-east-1 --profile other-account"),
    # `$X` 没绑定时运行时展开成**空串**，静默改掉请求内容；token 等值看不见这件事
    ("未绑定的展开", "aws cognito-idp list-user-pools --max-results 20 --region us-east-1",
     'aws cognito-idp list-user-pools --max-results 20 --region "$LIMIT"'),
    # ── 第二十轮（Codex），六种都真机执行过；根因是三处：引用信息丢失、绑定无顺序、
    #    以及**围栏提取**（后者最致命：输入没了，后面七层是零）────────────────────────
    # P2-1A：整体被引用的赋值词在 bash 里是**命令名**（command not found），JOB 没赋上
    #        ⇒ `$JOB` 用的是继承值（真机复现：invoke 的 site_id 变成 review-victim）
    ("整体引用的赋值不是赋值", "JOB=job-teardown-e2e-probe",
     "'JOB=job-teardown-e2e-probe'"),
    # P2-1B：单引号里 `$JOB` **不展开**；去引号后与双引号版逐 token 相等，而真 CLI 发出去的
    #        job_id 就是字面量 `$JOB`（和 put-item 写的主键不是一个）
    ("单引号 payload 挡住展开",
     '--payload "{\\"site_id\\":\\"e2e-probe\\",\\"job_id\\":\\"$JOB\\",\\"purge_data\\":true}"',
     '--payload \'{"site_id":"e2e-probe","job_id":"$JOB","purge_data":true}\''),
    # 绑定被删掉（P2-2 的退化形态）：`$JOB` 运行时展开成空串，token 等值看不见
    ("绑定被删掉", "JOB=job-teardown-e2e-probe\n", ""),
    # r22 §3：双引号内的 `\$JOB` —— shlex 留反斜杠、bash 去掉 ⇒ 我这边"看着是展开"、
    #         bash 发出去是字面量（与第二十轮 P2-1B 同族）。现由 _G_DQ 直接拒。
    ("双引号内转义的 $",
     '--payload "{\\"site_id\\":\\"e2e-probe\\",\\"job_id\\":\\"$JOB\\",\\"purge_data\\":true}"',
     '--payload "{\\"site_id\\":\\"e2e-probe\\",\\"job_id\\":\\"\\$JOB\\",\\"purge_data\\":true}"'),
    # P2-3a：块内一行 bash 注释里的三个反引号让旧的非贪婪正则提前收尾
    ("注释里的三反引号截断围栏", "aws dsql list-clusters --region us-east-1",
     "# ```\nexport AWS_PROFILE=review-other\n"
     "aws lambda invoke --function-name review-other --region us-east-1 /tmp/review.json\n"
     "aws dsql list-clusters --region us-east-1"),
]

# 有两条变形不是"就地替换一段"能表达的（要动围栏本身或语句顺序），单列。
_DOC_BYPASS_EXTRA = [
    # P2-2 的另一半：把唯一那条绑定挪到 invoke 之后
    ("绑定移到 invoke 之后", lambda sec: sec.replace("JOB=job-teardown-e2e-probe\n", "", 1)
     .replace("/tmp/undeploy.json\n", "/tmp/undeploy.json\nJOB=job-teardown-e2e-probe\n", 1)),
    # P2-3b：`sh` 标签的围栏——旧提取器只认 ```bash，静默忽略它
    ("新增 sh 围栏", lambda sec: sec + "\n```sh\nexport AWS_PROFILE=review-other\n"
     "aws lambda invoke --function-name review-other --region us-east-1 /tmp/review.json\n```\n"),
    # r22 §2：列表项里 tab 缩进的围栏 —— 参考实现认得、扫描器漏掉、旧的两条正则不命中
    ("列表里 tab 缩进的围栏", lambda sec: sec + "\n1. step\n\n\t```bash\n\texport AWS_PROFILE=review-other\n"
     "\taws lambda invoke --function-name review-other --region us-east-1 /tmp/review.json\n\t```\n"),
    # r23 §1：列表项里未闭合的围栏把后面的独立块并进来（参考 2 块 / 扫描器 1 块，
    #         而每条围栏行都"合规"）—— 由"围栏行数 == 2×块数"这条不变量拒
    ("列表内未闭合围栏合并后块", lambda sec: sec + "\n- item\n\n  ```bash\n  alpha\n\nomega\n\n"
     "```bash\naws lambda invoke --function-name review-other --region us-east-1 /tmp/review.json\n```\n"),
    # P2-3c：`~~~bash` 围栏——旧提取器的正则压根不匹配波浪线
    ("新增波浪线 bash 围栏", lambda sec: sec + "\n~~~bash\nexport AWS_PROFILE=review-other\n"
     "aws lambda invoke --function-name review-other --region us-east-1 /tmp/review.json\n~~~\n"),
]


@pytest.mark.parametrize("name,mutate", _DOC_BYPASS_EXTRA, ids=[c[0] for c in _DOC_BYPASS_EXTRA])
def test_doc_guards_catch_structural_bypasses(name, mutate, monkeypatch):
    """要动围栏结构 / 语句顺序的那几种变形，同样至少让一条守卫红。"""
    sec = _teardown_section()
    mutated = mutate(sec)
    assert mutated != sec, f"{name}：变形没生效，用例需要更新"
    monkeypatch.setattr(sys.modules[__name__], "_teardown_section", lambda: mutated)
    reds = [g.__name__ for g in _DOC_GUARDS if _guard_reds(g)]
    assert reds, f"{name}：全部文档守卫全绿，等于这条绕过还开着"


def _guard_reds(guard):
    try:
        guard(); return False
    except AssertionError:
        return True


@pytest.mark.parametrize("name,old,new", _DOC_BYPASS_CASES, ids=[c[0] for c in _DOC_BYPASS_CASES])
def test_doc_guards_catch_known_bypasses(name, old, new, monkeypatch):
    """四种绕过写法**至少**要让一条文档守卫红。

    这组是元测试：它们盯的不是 DEPLOY.md 的当前内容，而是解析器的**射程**。
    前几轮的教训是"修了代码但没留这种用例，退回旧解析器仍然全绿"。
    第十七轮起，大多数会由语法白名单那条先拦下——**这正是想要的**：判据从
    "认识每一种绕过"换成了"只认识一小撮允许的写法"。
    """
    sec = _teardown_section()
    assert old in sec, f"锚点不在拆除一节里了，用例需要更新：{old[:60]}"
    monkeypatch.setattr(sys.modules[__name__], "_teardown_section",
                        lambda: sec.replace(old, new, 1))
    reds = []
    for guard in _DOC_GUARDS:
        try:
            guard()
        except AssertionError:
            reds.append(guard.__name__)
    assert reds, f"{name}：四条文档守卫全绿，等于这条绕过还开着"


# 文档守卫（AND 关系），四层各管一件事：
#   ① 语法白名单  —— 词长什么样（挡 heredoc / `${}` / brace / 分组 / 管道 / 裸 $VAR …）
#   ② 语句白名单  —— 允许执行哪些语句（命令位置只认字面量，变量绑定点名）
#   ③ argv 等值    —— 破坏性命令整条逐 token 相等（挡缩写、多余旗标、前置赋值）
#   ④ 真实请求     —— 变量展开后的 JSON 解码结果（挡"token 相等但语义变了"）
# 再加两条形态守卫：命令替换白名单、拒 ANSI-C 引用。
# `test_doc_guards_catch_known_bypasses` 按这张表逐个跑。
_DOC_GUARDS = (
    test_teardown_section_fences_are_tagged_and_only_bash_is_shell,
    test_teardown_section_uses_only_the_allowed_shell_subset,
    test_teardown_section_uses_only_the_allowed_statements,
    test_teardown_section_aws_flags_are_allowlisted,
    test_every_expansion_in_the_section_is_a_bound_variable,
    test_teardown_section_has_no_copyable_destructive_commands,
    test_exempted_commands_decode_to_the_expected_requests,
    test_teardown_section_rejects_shell_substitution,
    test_teardown_section_rejects_ansi_c_quoting,
)


@pytest.mark.parametrize("line,ok", [
    # 现节里真实出现的写法必须全部通过（正对照，防止把白名单收得太死）
    ('cd "$(git rev-parse --show-toplevel)"', True),
    ("site-builder/scripts/teardown_platform.sh --yes --stage preflight  # 只跑一个阶段", True),
    ("JOB=job-teardown-e2e-probe", True),
    ("aws dynamodb put-item --table-name site-deploy-jobs --region us-east-1 --item \\", True),
    (r'  "{\"job_id\":{\"S\":\"$JOB\"},\"status\":{\"S\":\"PENDING\"}}"', True),
    ("aws iam list-roles --query 'Roles[?starts_with(RoleName,`site-`)].RoleName' --output text", True),
    ('aws s3 ls                       # 无 site-frontend-*', True),
    # 引号内的 `#` 不是注释，整行仍要能过
    ('aws x y --item "{\\"a\\": \\"#1\\"}"', True),
    # ↓ 白名单之外：每一条都是前几轮真绕过去过的构造
    ('echo "${UNSET:-$(id)}"', False),                     # `${…}` 参数展开
    ("echo {# $(id)", False),                              # brace / 词内 `#`
    ("{aws,} s3 rm s3://x --recursive", False),            # brace expansion
    ("cat <<EOF", False),                                  # heredoc
    ("AWS_PROFILE=other aws lambda invoke --function-name x out.json", False),  # 前置赋值
    ('("aws" lambda invoke --function-name x out.json)', False),                # 子 shell
    ("aws dsql list-clusters; aws lambda invoke --function-name x out.json", False),  # 分隔符
    ("echo `id`", False),                                  # 裸反引号
    ("echo $'--function-name'", False),                    # ANSI-C 引用
    ("echo $(date)", False),                               # 白名单外的命令替换
    ("aws s3 rm s3://x --recursive | tee log", False),      # 管道
    ("echo *", False),                                     # 通配
    ("aws lambda invoke --payload $PAYLOAD out.json", False),  # 裸 $VAR（不在引号里）
])
def test_doc_syntax_allowlist_accepts_only_the_subset(line, ok):
    """语法白名单的正/负对照。

    负例这一半是**判据本身**的射程证明：把 `_G_BARE` 放宽成含 shell 元字符、或把
    `_G_DQ` 放宽成允许 `$(`，这里立刻红。正例那一半防止白名单收到连现节都过不去
    （那会变成"没人敢改 runbook"而不是安全）。
    """
    assert _doc_line_ok(line) is ok, line


@pytest.mark.parametrize("line,kind", [
    # 现节里真实出现的四种语句（正对照）
    ('cd "$(git rev-parse --show-toplevel)"', "cd"),
    ("site-builder/scripts/teardown_platform.sh --yes --stage preflight", "script"),
    ("JOB=job-teardown-e2e-probe", "assign"),
    ("aws dsql list-clusters --region us-east-1", "aws"),
    # ↓ 第十八轮那五种：命令位置不是字面量 / 环境改写 / 换了绑定值
    ('"$REVIEW_CMD" lambda invoke --function-name site-panel out.json', "?"),
    ("bash -c '\"aws\" lambda invoke --function-name site-panel out.json'", "?"),
    ("export AWS_PROFILE=other-account", "?"),
    ("AWS_PROFILE=other-account", "?"),
    ("REVIEW_CMD=aws", "?"),
    ("JOB=something-else", "?"),
    # 同族的其它入口：eval / 别名 / 带引号的命令名 / 拆除脚本参数里塞展开
    ("eval \"$X\"", "?"),
    # 带引号的命令名**是**合法的 `aws`（shlex 与 bash 都去引号），所以这里判 aws；
    # 拦它的是下一层 argv 等值（site-panel 不在豁免表里）。分层就该这样，别在这条
    # 里假装它是"?"。
    ('"aws" lambda invoke --function-name site-panel out.json', "aws"),
    ('site-builder/scripts/teardown_platform.sh "$STAGE"', "?"),
    ("/usr/local/bin/aws lambda invoke --function-name site-panel out.json", "?"),
])
def test_doc_statement_allowlist_classifies_only_the_named_shapes(line, kind):
    """语句形状表的正/负对照。

    负例这一半钉住"命令位置只认字面量、绑定只认点名那条"：把 `parts[0] == "aws"` 放宽成
    "含 aws"、或把绑定判据放宽成"任何 NAME=值"，这里立刻红。
    """
    T = _teardown_section
    try:
        globals()["_teardown_section"] = lambda: "```bash\n" + line + "\n```\n## x\n"
        got = [st.kind for st in _doc_statements()]
    finally:
        globals()["_teardown_section"] = T
    assert got == [kind], (line, got)


def test_request_decoder_rejects_duplicate_json_keys():
    """真实请求那条守卫的核心断言：重复键必须直接红（用**同一个** hook，不是复制品）。

    `json.loads` 默认对重复键取**后者**，静默得很——第十八轮 P2-3 正是靠这一点把
    `site_id` 从夹具站点改成 `victim`，而 argv 一字不差。
    """
    import json
    src = '{"site_id":"e2e-probe","site_id":"victim"}'
    assert json.loads(src)["site_id"] == "victim", "前提变了：json 不再对重复键取后者"
    with pytest.raises(AssertionError, match="重复键"):
        json.loads(src, object_pairs_hook=_json_no_dupes)
    assert json.loads('{"a":1,"b":{"a":2}}', object_pairs_hook=_json_no_dupes) == \
        {"a": 1, "b": {"a": 2}}, "同名键在**不同层**是合法的，不该误红"


# 围栏解析器的语料。**期望值来自参考实现** markdown-it-py 4.2.0（`MarkdownIt('commonmark')`）
# 逐条对过，不是我手写的直觉——第二十一轮就是靠这条差分抓出三个真漏块
# （info 带额外词、CRLF、引用块里的围栏）。参考实现不在本仓库的锁定依赖里，所以差分是
# **一次性方法**、结论固化成下面这张表；要重跑：另建 venv 装 markdown-it-py，对每条输入比
# `_fenced_blocks` 与参考实现的 fence token，**只允许"我漏的那个块会被别的守卫显式拒"**。
_FENCE_CASES = [
    ("```bash\na\n```\n", [("bash", "a\n")]),
    # 波浪线栏：里面的三反引号不是闭栏
    ("~~~bash\na\n```\nb\n~~~\n", [("bash", "a\n```\nb\n")]),
    # 块内一行注释里的三反引号**不**闭栏（旧正则就死在这里）
    ("```bash\na\n# ```\nb\n```\n", [("bash", "a\n# ```\nb\n")]),
    # 闭栏长度必须 ≥ 开栏
    ("````bash\na\n```\nb\n````\n", [("bash", "a\n```\nb\n")]),
    # info string 只取第一个词，后面的词随便（第二十一轮差分：旧写法整块漏掉）
    ("```bash foo=1\na\n```\n", [("bash", "a\n")]),
    # CRLF（同上，旧写法整块漏掉）
    ("```bash\r\na\r\n```\r\n", [("bash", "a\n")]),
    # 缩进 ≤3 是开栏；正文按开栏缩进量剥前导空白
    ("   ```bash\n   a\n   ```\n", [("bash", "a\n")]),
    # 闭栏后面还有别的字 ⇒ 不是闭栏
    ("```bash\na\n``` x\nb\n```\n", [("bash", "a\n``` x\nb\n")]),
    # 未闭合 ⇒ 延伸到末尾
    ("```bash\na\nb\n", [("bash", "a\nb\n")]),
    # 反引号栏的 info 里有反引号 ⇒ 那一行不是开栏；结尾那行 ``` 才是开栏（未闭合空块）。
    # **r22 更正**：上一版注释说"参考实现给 []、这里刻意多收一个块"——那是我凭假设写的、
    # 没跑过参考实现。实测参考实现同样给 `[("", "")]`，两边一致，不存在刻意差异。
    ("```ba`sh\na\n```\n", [("", "")]),
    # 无标签块要能解析出来（好让标签正向表拒它）
    ("```\na\n```\n", [("", "a\n")]),
    # 列表项里的围栏
    ("- item\n\n  ```bash\n  a\n  ```\n", [("bash", "a\n")]),
]


@pytest.mark.parametrize("md,want", _FENCE_CASES, ids=range(len(_FENCE_CASES)))
def test_fence_parser_matches_commonmark_reference(md, want):
    """围栏解析器必须与 CommonMark 参考实现一致（漏块 = 命令脱离全部九层守卫）。"""
    assert _fenced_blocks(md) == want, md


@pytest.mark.parametrize("sep", ["", "", "", " ", " "])
def test_fence_parser_only_breaks_lines_on_lf(sep):
    """CommonMark §2.1 的行结束只有 LF / CR / CRLF —— `splitlines()` 认的比这多。

    参考实现差分实测 5/5 漏：正文写 `a<SEP>``` ` 时参考实现看成**一行**（不闭栏），
    而 `splitlines()` 把它当两行 ⇒ 提前闭栏 ⇒ 后面那条命令脱离全部九层守卫。
    """
    hidden = "aws lambda invoke --function-name hidden out.json"
    md = f"```bash\na{sep}```\n{hidden}\n```\n"
    blocks = _fenced_blocks(md)
    assert len(blocks) == 1 and blocks[0][0] == "bash", blocks
    assert hidden in blocks[0][1], f"{sep!r} 被当成行结束 ⇒ 隐藏命令漏掉了"


@pytest.mark.parametrize("line,rejected", [
    ("    ```bash", True),                      # 缩进 ≥4
    ("     ~~~bash", True),
    ("> ```bash", True),                        # 引用块
    (">> ```bash", True),
    ("\t```bash", True),                        # tab 缩进（r22：旧的两条正则漏掉它）
    (" \t```bash", True),                       # 空格+tab（同上）
    ("    > ```bash", True),                    # 列表内 4 空格后再 `>`（同上）
    ("\t> ```bash", True),                      # 列表内 tab 后再 `>`（同上）
    ("x ```bash", True),                        # 行中间
    ("   ```bash", True),                       # r24：缩进 1–3 也拒（见下面那段说明）
    (" ```bash", True),
    ("```bash", False),                         # 只有第 0 列是受支持形态
    ("~~~bash", False),
    ("``` ", False),                            # 闭栏
    ("a `code` b", False),                      # 单反引号不是围栏
])
def test_unsupported_fence_shapes_are_explicitly_rejected(line, rejected):
    """只允许**第 0 列**的围栏行，其余含围栏字符的行一律红。

    判据换过两次，两次都是被差分否掉的：
      · r22 前：枚举不支持的形态（引用块 + 缩进 ≥4 两条正则）—— tab 缩进、空格+tab、
        列表内更深位置的 `>` 四种参考实现都认得、两条正则一条都不命中。
      · r23/r24：放宽到"缩进 ≤3"也不行 —— 列表项里缩进 2 的开栏会被当成顶层，配上
        未闭合 / HTML 块里的三反引号，就出现"块数相同而边界不同"和"总量抵消"两类反例。
    所以收到第 0 列。**这不是"完备"**（见 `_FENCE_RUN` 上面那段），是一条可逐条验证的
    文档约束，配合"逐块显式闭合"与"无 HTML 块起始行"两条一起用。
    """
    hit = bool(_FENCE_RUN.search(line) and not _FENCE_SUPPORTED_LINE.match(line))
    assert hit is rejected, line


def test_fence_indent_stripping_never_eats_content_or_newlines():
    """去缩进只吃**空格**、最多 n 个：不许吞正文、不许吞换行、不许按字符算 tab。

    旧写法是"前 n 个字符全是 isspace() 就切掉 n 个字符"，三处偏差（r21 静态审计）：
    只有 k<n 个空格时一个都不切；空行的换行被一起切掉；tab 与 Unicode 空白按字符算。
    """
    assert _strip_fence_indent(" a", 3) == "a", "只有 1 个空格时也要剥掉"
    assert _strip_fence_indent("", 3) == "", "空行不该变成别的东西"
    assert _strip_fence_indent("\ta", 3) == "\ta", "tab 不按空格剥（§2.2 是列宽，不是字符）"
    assert _strip_fence_indent("    a", 3) == " a", "最多剥 n 个"
    assert _strip_fence_indent("a", 3) == "a"
    # 缩进块里的空行必须仍然是一行（不能被吞掉）
    assert _fenced_blocks("   ```bash\n   a\n\n   b\n   ```\n") == [("bash", "a\n\nb\n")]


# 语法子集里允许的词形。**期望值由真 bash 给**（见下面那条测试），不是手写的。
_BASH_WORD_CASES = [
    "bare", "a/b.c-d:e", "JOB=x", "--flag", "--flag=value",
    "''", "'sp ace'", "'$JOB'", "'`id`'", "'a\\b'",
    '""', '"sp ace"', '"$JOB"', '"a\\\\b"', '"q\\"q"',
    '"{\\"k\\":\\"$JOB\\"}"',
]


def test_word_values_match_real_bash():
    r"""`_shell_tokens` 的词值必须与**真 bash** 交给进程的 argv 一致（变量展开除外）。

    r22 §4 指出 `test_lexer_regression_assertions_on_the_bypass_shapes` 不启动 bash、
    名字 overclaim。这一条是它认可的最小差分形态：临时 PATH 里只放一个用 bash 内建
    `printf` 写的记录器，`/bin/bash --noprofile --norc` 启动，环境最小化，输入只取
    语法子集里允许的中性词形。

    契约：本子集内 shlex 值与 bash 值**只差变量展开这一件事**（`$NAME` 在双引号/裸词里
    会被 bash 展开，shlex 原样保留），别的必须逐字节相等。`\$` 与 `` \` `` 已被
    `_G_DQ` 拒掉，正是因为它们在这两者之间不一致（r22 §3 量到的那条）。
    """
    import os
    import subprocess
    import tempfile
    from pathlib import Path
    bash = "/bin/bash"
    if not os.path.exists(bash):
        pytest.skip("没有 /bin/bash")
    with tempfile.TemporaryDirectory(prefix="wordval-") as td:
        rec = Path(td) / "record"
        rec.write_text('#!' + bash + '\nprintf "%s\\0" "$@"\n', encoding="utf-8")
        rec.chmod(0o755)
        env = {"PATH": td, "LC_ALL": "C", "JOB": "JOBVALUE"}
        mismatches = []
        for word in _BASH_WORD_CASES:
            # 每个词都必须在语法子集里，否则这条用例本身没意义
            assert _DOC_LINE_GRAMMAR.fullmatch("record " + word), word
            proc = subprocess.run([bash, "--noprofile", "--norc", "-c", "record " + word],
                                  capture_output=True, text=True, env=env, timeout=10)
            assert proc.returncode == 0, (word, proc.stderr)
            actual = proc.stdout.split("\0")[:-1]
            # **契约的两条显式约定**（都不是缺陷，是本套件刻意的建模）：
            #   ① `--flag=value` 我刻意拆成两个 token（好让它与 `--flag value` 在 argv
            #      等值层比得相等），所以对 bash 的 argv 施加同一次规范化再比；
            #   ② `$NAME` 只在**双引号/裸词**里展开；单引号里是字面量（EXPAND 层就是
            #      按这条判的）。所以按原始词的引用形态决定要不要代值。
            norm = []
            for a in actual:
                if a.startswith("--") and "=" in a:
                    f, _, v = a.partition("=")
                    norm += [f, v]
                else:
                    norm.append(a)
            parts, raws = _aligned_words("record " + word)
            expected = [p if _word_kind(_raw_value_segment(r)) == "sq"
                        else p.replace("$JOB", env["JOB"])
                        for p, r in zip(parts[1:], raws[1:])]
            if norm != expected:
                mismatches.append(f"{word!r}: bash={norm!r} 解析={expected!r}")
        assert mismatches == [], (
            "shlex 与真 bash 的词值不一致（除变量展开外必须逐字节相等）：\n  "
            + "\n  ".join(mismatches))


def test_raw_words_and_parts_stay_index_aligned():
    """原始词与规范化 token 必须**逐下标对齐**（r21 §2 的核心发现）。

    `_shell_tokens` 会把 `--flag=value` 拆成两个 token，而原始词只有一个。上一版只校验
    "原始词数 == shlex 词数"（两边都没拆），于是 `--region=us-east-1` 这种全裸值形态
    **校验通过而下标从此错位**，`raws[parts.index(flag)+1]` 取到隔壁的词 ⇒
    "单引号里的 `$` 不展开"那条检查作用在错误的词上。
    """
    parts, raws = _aligned_words("aws x y --region=us-east-1 out.json")
    assert len(parts) == len(raws) and parts[4] == "us-east-1"
    assert raws[3] == raws[4] == "--region=us-east-1", "拆分时原始词要同步复制"
    assert parts == _shell_tokens("aws x y --region=us-east-1 out.json")
    # 值那一段的引用形态要单独取：整词以 `-` 开头看着像裸词，值却可能是单引号
    assert _word_kind(_raw_value_segment("--payload='{\"a\":1}'")) == "sq"
    assert _word_kind(_raw_value_segment("--region=us-east-1")) == "bare"
    # 相邻引号拼接（`a''b`）不在语法子集里 ⇒ 一律当可疑
    assert _aligned_words("a''b") == ([], [])


def test_fence_block_state_invariant_catches_merged_blocks():
    """围栏行数 == 2×块数：没有这条，未闭合的围栏会把后面的独立块**并进来**。

    r23 的中性反例（正文只有占位文字）：列表项里一个未闭合的 bash 栏，按 CommonMark
    随列表结束而结束、后面那个顶层栏是**第二个**块；扫描器却一路收到底，
    参考实现 2 个块 vs 扫描器 1 个块，**而每条围栏行都符合"受支持形态"**。
    所以"每行形状合规"不等于"块边界对"——这条不变量补的正是那一步。
    """
    F = "`" * 3
    merged = "- item\n\n  " + F + "bash\n  alpha\n\nomega\n\n" + F + "bash\nbeta\n" + F + "\n"
    blocks = _fenced_blocks(merged)
    assert len(blocks) == 1, "反例前提变了：扫描器现在不再合并了？"
    fence_lines = [l for l in _md_lines(merged) if _FENCE_RUN.search(l)]
    assert len(fence_lines) != 2 * len(blocks), "不变量抓不到这个反例了"
    # 未闭合的围栏（最简形态）同样违反不变量
    unclosed = F + "bash\nalpha\n"
    assert len(_fenced_blocks(unclosed)) == 1
    assert len([l for l in _md_lines(unclosed) if _FENCE_RUN.search(l)]) == 1
    # 正对照：本节与"两个都闭合"的样本都满足 1:2
    for ok in (_teardown_section(), F + "bash\na\n" + F + "\n" + F + "text\nb\n" + F + "\n"):
        assert len([l for l in _md_lines(ok) if _FENCE_RUN.search(l)]) == 2 * len(_fenced_blocks(ok))


def test_zero_indent_fences_need_no_body_dedent():
    """零缩进围栏下正文**不需要去缩进**，于是 tab 保真差异不可构造。

    r22/r23 的差异是"开栏有缩进 + 正文裸 tab"时参考按 §2.2 的 4 列制表位展开、我只吃空格。
    r24 指出上一版"拒正文前导 tab"这条**过度拒绝**（零缩进围栏下两边正文其实完全一致，
    却把合法的 tab 缩进 JSON 也拒了），而且报错文案说"两者解析出的正文不同"并不成立。
    现在靠"围栏必须在第 0 列"消掉整个差异来源：indent=0 ⇒ 一个字符都不剥。
    """
    F = "`" * 3
    md = F + "bash\n\talpha\n  beta\n" + F + "\n"
    assert _fenced_blocks(md) == [("bash", "\talpha\n  beta\n")], "零缩进下正文必须原样"
    assert _strip_fence_indent("\talpha", 0) == "\talpha"
    # 带缩进的开栏现在由守卫拒（解析器本身仍会剥，那条路走不到）
    assert not _FENCE_SUPPORTED_LINE.match(" " + F + "bash")


def test_fence_guard_rejects_the_r24_counterexamples():
    """r24 的两个反例：计数判据都过，而边界/归属不对 —— 必须由别的约束拒。

    ① 列表内未闭合围栏 + HTML 块里的三反引号被当成闭栏 ⇒ **双方各 1 块、围栏行恰好 2 条**
       （计数 `2 == 2×1` 通过），正文却从 `alpha\n\n` 变成含 `<div>` `omega` 的一大块。
    ② 合并块（3 行/1 块）与末尾未闭合块（1 行/1 块）**相互抵消** ⇒ `4 == 2×2` 通过。
    现在 ① 被"围栏必须第 0 列"+"无 HTML 块起始行"拒，② 被"第 0 列"+"逐块显式闭合"拒。
    """
    F = "`" * 3
    a = "- item\n\n  " + F + "bash\n  alpha\n\n<div>\nomega\n" + F + "\n</div>\n"
    b = ("- item\n\n  " + F + "bash\n  alpha\n\nomega\n\n" + F + "bash\nbeta\n" + F + "\n"
         + "\n" + F + "bash\ngamma\n")
    for name, md in (("HTML 吞并", a), ("抵消", b)):
        fl = [l for l in _md_lines(md) if _FENCE_RUN.search(l)]
        blocks = _fenced_blocks(md)
        # 前提：计数判据确实看不见它（反例失效时这条会红，而不是静默变成空跑）
        assert len(fl) == 2 * len(blocks), f"{name}：反例前提变了，计数已经能抓到它"
        # 而三条约束里至少一条要拒
        rejected = (any(not _FENCE_SUPPORTED_LINE.match(l) for l in fl)
                    or any(_HTML_BLOCK_START.match(l) for l in _md_lines(md))
                    or any(not c for _l, _b, c in _fenced_blocks_detailed(md)))
        assert rejected, f"{name}：三条约束都没拒它"


def test_allowed_command_substitution_matches_real_bash():
    r"""唯一允许的命令替换 `"$(git rev-parse --show-toplevel)"` 的 bash 语义差分。

    r24 建议给这个分支单独差分（它不是普通变量替换，不能套进"字符串替换"模型）。
    形态照 r24 给的：临时 PATH 里只放**假 git** 与参数记录器（都只用 bash 内建），
    `/bin/bash --noprofile --norc`、最小环境、超时；期望值来自假 git 的固定输出与
    已声明的替换契约。**不调用真实 git。**

    契约（每条都由下面的样本实测）：末尾 LF 全部去掉、内部 LF 保留、整体是**一个**参数
    （不分词、不通配）、stdout 为空 ⇒ 一个空参数、**git 失败时外层仍可退 0**
    （所以测试必须把两者状态分开看 —— 这也是 r24 点出的那条）。
    """
    import os
    import shlex
    import subprocess
    import tempfile
    from pathlib import Path
    bash = "/bin/bash"
    if not os.path.exists(bash):
        pytest.skip("没有 /bin/bash")
    NL = chr(10)
    cases = [
        ("/tmp/repo" + NL, 0, ["/tmp/repo"]),
        ("/tmp/re po/*" + NL, 0, ["/tmp/re po/*"]),
        ("/tmp/repo" + NL * 3, 0, ["/tmp/repo"]),
        ("/tmp/a" + NL + "b" + NL, 0, ["/tmp/a" + NL + "b"]),
        ("", 0, [""]),
        ("", 1, [""]),
        ("/tmp/repo" + NL, 1, ["/tmp/repo"]),
    ]
    rec_src = "#!" + bash + NL + 'printf "%s\\0" "$@"' + NL
    with tempfile.TemporaryDirectory(prefix="subst-") as td:
        d = Path(td)
        (d / "record").write_text(rec_src, encoding="utf-8")
        (d / "record").chmod(0o755)
        gitlog = d / "gitargv"
        for out, rc, want in cases:
            git_src = ("#!" + bash + NL
                       + 'printf "%s\\0" "$@" >> "$GITLOG"' + NL
                       + "printf '%s' " + shlex.quote(out) + NL
                       + "exit " + str(rc) + NL)
            (d / "git").write_text(git_src, encoding="utf-8")
            (d / "git").chmod(0o755)
            gitlog.write_text("", encoding="utf-8")
            proc = subprocess.run(
                [bash, "--noprofile", "--norc", "-c",
                 'record "$(git rev-parse --show-toplevel)"'],
                capture_output=True, text=True, timeout=10,
                env={"PATH": str(d), "LC_ALL": "C", "GITLOG": str(gitlog)})
            # git 失败不等于外层失败 —— r24 点出的就是这条，必须分开看
            assert proc.returncode == 0, (out, rc, proc.stderr)
            assert proc.stdout.split("\0")[:-1] == want, (out, rc, proc.stdout)
            assert gitlog.read_text().split("\0")[:-1] == ["rev-parse", "--show-toplevel"]
    # 本套件对它的处理：语句层按**精确字面量**放行，不进变量替换模型
    assert _word_kind('"$(git rev-parse --show-toplevel)"') == "subst"
    assert _STMT_CD == ("cd", "$(git rev-parse --show-toplevel)")


def test_fence_bodies_preserve_trailing_newlines_for_every_line_ending():
    """末尾行结束符的保真：LF / CRLF / 裸 CR 三种都要与参考一致（r23 §3）。

    上一版用**原始** `text.endswith("\n")` 判断，裸 CR 结尾时为假 ⇒ 少保留一个 LF。
    """
    F = "`" * 3
    assert _fenced_blocks(F + "bash\nalpha")[0][1] == "alpha", "无尾结束符时不该补"
    for end in ("\n", "\r\n", "\r"):
        assert _fenced_blocks(F + "bash" + end + "alpha" + end)[0][1] == "alpha\n", end
        assert _fenced_blocks(F + "bash" + end + "alpha" + end + end)[0][1] == "alpha\n\n", end


@pytest.mark.parametrize("word", ["'a\x00b'", '"a\x00b"', "'a\x1fb'", "a\x00b"])
def test_control_characters_are_outside_the_word_grammar(word):
    """NUL 与其它 C0 控制字符不在词法子集里：bash 会**丢掉** NUL，两条分词路径都保留。

    r23 §4 实测：`'alpha<NUL>beta'` 我给 `alpha\x00beta`、bash 给 `alphabeta`。
    runbook 不需要控制字符，所以按字符域拒，而不是去建模 bash 的丢弃行为。
    """
    assert not _DOC_LINE_GRAMMAR.fullmatch("record " + word), word


def test_container_fences_the_scanner_misses_are_all_rejected():
    """凡是参考实现认得、而 `_fenced_blocks` 漏掉的布局，完备规则都必须拒。

    钉住 r22 差分实测的那批：引用块、嵌套引用块、tab 缩进、空格+tab、
    列表内 4 空格后再 `>`、列表内 tab 后再 `>`；以及本节自己不许出现它们。
    """
    F = "`" * 3
    for md in ("> " + F + "bash\n> a\n> " + F + "\n",
               "> > " + F + "bash\n> > a\n> > " + F + "\n",
               F + "bash\na\n" + F + "\n> " + F + "bash\n> b\n> " + F + "\n",
               "1. s\n\n\t" + F + "bash\n\ta\n\t" + F + "\n",
               "- s\n\n \t" + F + "bash\n \ta\n \t" + F + "\n",
               "1. s\n\n    > " + F + "bash\n    > a\n    > " + F + "\n",
               "- s\n\n\t> " + F + "bash\n\t> a\n\t> " + F + "\n"):
        assert any(_FENCE_RUN.search(l) and not _FENCE_SUPPORTED_LINE.match(l)
                   for l in _md_lines(md)), md
    assert not any(_FENCE_RUN.search(l) and not _FENCE_SUPPORTED_LINE.match(l)
                   for l in _md_lines(_teardown_section())), "本节里有不受支持的围栏形态"


def test_doc_syntax_allowlist_is_load_bearing_for_the_whole_section():
    """整节现有内容必须**逐行**过白名单——这条与上面那条正例互为补充。

    上面那条只抽了几行；这条保证不是"抽到的几行刚好能过"。
    """
    lines = [l for block in _fenced_bash(_teardown_section())
             for l in block.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert len(lines) >= 15, f"拆除一节的围栏块只剩 {len(lines)} 行命令，是不是被删了"
    assert _doc_grammar_offenders() == []


def test_lexer_regression_assertions_on_the_bypass_shapes():
    """词法器在这些形态上的**静态回归断言**。

    **这条不启动 bash**（r22 指出旧名字 overclaim）：期望值是我按 bash 语义手写的，
    能挡住已知回归，但不是独立差分证据。真差分在 `test_word_values_match_real_bash`。

    第十七轮补两条**反向**要求：`${…}` 不许整段跳过（跳过等于把内层替换藏起来），
    `{` 不许无条件当分组符（bash 只在它独立成词时才是关键字）。
    """
    # `${VAR:-默认}` 的默认值里那条替换必须被取出来（实测 bash 会执行它）
    assert _command_substitutions('echo "${UNSET:-$(id)}"') == ["id"], \
        "`${…}` 被整段跳过了 —— 内层替换会被藏起来"
    # `{#` 是普通词 ⇒ 不许在 `{` 断句、把 `#` 变成注释开头
    assert _command_substitutions("echo {# $(id)") == ["id"], \
        "在 `{` 处断了句，`#` 落到词首被当成注释"
    # ① 引号内的 `#` 不是注释 ⇒ 替换必须被取出来
    cmds, subs, unterm = _lex_block('JOB2="{\n# \'$(id)\'\n}"\necho done')
    assert subs == ["id"], subs
    assert not unterm
    # ② `( … )` 是分组符 ⇒ 里面的命令要单独成条，且 aws 是一个 token
    cmds, _s, _u = _lex_block('echo a\n("aws" lambda invoke --function-name site-panel out.json)')
    assert 'aws lambda invoke --function-name site-panel out.json' in [
        " ".join(_shell_tokens(c) or []) for c in cmds], cmds
    # ③ `\`+换行**不补空格**，缩进才是分隔符 —— 两种写法都要与 bash 一致
    assert _shell_tokens(_lex_block("x --function-\\\nname v")[0][0]) == ["x", "--function-name", "v"]
    assert _shell_tokens(_lex_block("x --item \\\n  v")[0][0]) == ["x", "--item", "v"]
    # ④ 块结束时仍在引号内 ⇒ unterminated
    assert _lex_block('echo "unclosed')[2]


def test_only_notfound_codes_classify_as_absent(harness):
    """**合法 wire code ≠「资源不存在」**（Codex 第十四轮 P2-4）。

    上一条模型守卫只验"声明的码属于该操作的 error_shapes"，而那里面还有内部故障、
    限流、参数校验。把 `KMSInternalException` 加进 KMS 的 absent 白名单时，
    224 条全绿——随后注入它，脚本漏掉第一把签名 key、继续删 S3、退 0。

    所以这里验**补集**：枚举每个操作已建模的全部 wire code，声明之外的**一律**
    必须 NOT_ABSENT。新增一条无关的码就会让本条红。

    **射程与上一条共用 `_MODEL_PROBE`**：这里曾经自带一份少了两个操作的副本，于是
    给 `dynamodb scan` 开一条 ABSENT 后门时全绿（Codex 第十五轮 P2-4）。
    """
    import botocore.session
    sess = botocore.session.get_session()
    probe = _MODEL_PROBE
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_absent_codes() {"):script.index("# _outer_code <errtext>")]
    problems = []
    for (svc, op), (bsvc, bop) in probe.items():
        prog = "set -uo pipefail\n" + body + '\n_absent_codes "$1" "$2"\n'
        declared = set(subprocess.run(["bash", "-c", prog, "_", svc, op],
                                      capture_output=True, text=True).stdout.split())
        model = sess.get_service_model(bsvc).operation_model(bop)
        wire = {sh.metadata.get("error", {}).get("code", sh.name) for sh in model.error_shapes}
        assert wire, f"{svc} {op}: 模型里没有 error_shapes，这条 probe 该移出去"
        assert declared <= wire, f"{svc} {op}: 声明了不在模型里的码 {declared - wire}"
        for code in sorted(wire - declared):
            if _run_is_absent(svc, op, _err(code)):
                problems.append(
                    f"{svc} {op}: {code} 不在声明的 NotFound 里，却被判成 ABSENT "
                    f"—— 那会让一个**存在**的资源被静默跳过")
    assert problems == [], "\n  ".join(problems)


def test_declared_notfound_codes_are_the_expected_minimum(harness):
    """正对照：每个操作声明的 NotFound 码集合必须**逐字**等于预期。

    上一条验"声明之外的都不算 ABSENT"，这条验"声明的就是这些"——合起来才把
    "多收一个码"和"悄悄换掉一个码"都挡住。

    这张表也必须**覆盖脚本登记的全部操作**：只按自己的 key 去查的话，脚本里新加一个
    操作时本条照绿（与 Codex 第十五轮 P2-4 同一形状）。
    """
    expected = {
        ("dynamodb", "describe-table"): {"ResourceNotFoundException"},
        ("dynamodb", "scan"): {"ResourceNotFoundException"},
        ("iam", "get-role"): {"NoSuchEntity"},
        ("lambda", "get-function"): {"ResourceNotFoundException"},
        ("lambda", "get-function-url-config"): {"ResourceNotFoundException"},
        ("ecr", "describe-repositories"): {"RepositoryNotFoundException"},
        ("bedrock-agentcore-control", "get-agent-runtime"): {"ResourceNotFoundException"},
        ("dsql", "get-cluster"): {"ResourceNotFoundException"},
        ("cognito-idp", "describe-user-pool"): {"ResourceNotFoundException"},
        ("sns", "get-topic-attributes"): {"NotFound"},
        ("ssm", "get-parameter"): {"ParameterNotFound"},
        ("kms", "describe-key"): {"NotFoundException"},
        ("s3api", "get-bucket-location"): {"NoSuchBucket"},
    }
    assert set(expected) == _declared_absent_operations(), (
        "预期表与脚本登记的操作集合不一致："
        f"脚本多出 {sorted(_declared_absent_operations() - set(expected))}，"
        f"表里多出 {sorted(set(expected) - _declared_absent_operations())}")
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_absent_codes() {"):script.index("# _outer_code <errtext>")]
    got = {}
    for svc, op in expected:
        prog = "set -uo pipefail\n" + body + '\n_absent_codes "$1" "$2"\n'
        got[(svc, op)] = set(subprocess.run(["bash", "-c", prog, "_", svc, op],
                                            capture_output=True, text=True).stdout.split())
    assert got == expected, (
        "\n".join(f"  {k}: 实得 {sorted(got[k])} 期望 {sorted(v)}"
                  for k, v in expected.items() if got.get(k) != v))
