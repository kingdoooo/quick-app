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
fail() { echo "An error occurred ($1) when calling the operation: injected" >&2
         exit "${FAKE_FAIL_RC:-254}"; }

# 各 API "不存在"时**真 CLI 的报文形态**。别改成统一的 ResourceNotFoundException——
# 那会把分类器的漏洞盖住（P2 就是这么漏的）。
absent() {
  case "$*" in
    *get-bucket-location*|*head-bucket*)
      echo "An error occurred (NoSuchBucket) when calling the GetBucketLocation operation: The specified bucket does not exist" >&2 ;;
    *describe-stacks*)
      echo "An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id X does not exist" >&2 ;;
    *get-role*)
      echo "An error occurred (NoSuchEntity) when calling the GetRole operation: The role with name X cannot be found." >&2 ;;
    *get-parameter*)
      echo "An error occurred (ParameterNotFound) when calling the GetParameter operation: " >&2 ;;
    *describe-repositories*)
      echo "An error occurred (RepositoryNotFoundException) when calling the DescribeRepositories operation: The repository does not exist in the registry" >&2 ;;
    *get-function*)
      echo "An error occurred (ResourceNotFoundException) when calling the GetFunction operation: Function not found: arn:aws:lambda:x" >&2 ;;
    *get-topic-attributes*)
      echo "An error occurred (NotFoundException) when calling the GetTopicAttributes operation: Topic does not exist" >&2 ;;
    *describe-user-pool*)
      echo "An error occurred (ResourceNotFoundException) when calling the DescribeUserPool operation: User pool does not exist." >&2 ;;
    *)
      echo "An error occurred (ResourceNotFoundException) when calling the operation: Requested resource not found" >&2 ;;
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
      out="/aws/lambda/site-panel /aws/codebuild/site-package $FAKE_OWNED_EDGE_LG"
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
    return f"An error occurred ({code}) when calling the {op} operation: something"


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
    ("sns", "get-topic-attributes", _err("NotFoundException")),
    ("ssm", "get-parameter", _err("ParameterNotFound")),
    ("s3api", "get-bucket-location", _err("NoSuchBucket")),
    # CloudFormation 是唯一的无类型消息规则
    ("cloudformation", "describe-stacks",
     "An error occurred (ValidationError) when calling the DescribeStacks "
     "operation: Stack with id X does not exist"),
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


def _fenced_bash(text):
    return re.findall(r"```bash\n(.*?)```", text, re.S)


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
# 要钉到**目标与次数**（Codex 第十一轮 P1-3）：上一版只按 (服务, 动词) 豁免，于是往围栏块里
# 再塞一条 `aws lambda invoke --function-name site-panel` 也照样通过——那等于给
# "任意 invoke / 任意 put-item"开了口子。
_DOC_ALLOWED_EXACT = {
    ("dynamodb", "put-item", "--table-name", "site-deploy-jobs"): 1,
    ("lambda", "invoke", "--function-name", "site-deployer-undeploy"): 1,
}


def _doc_aws_commands():
    """围栏块里每一条（拼好续行的）aws 命令 -> (服务, 动词, 目标旗标, 目标值, 原文)。"""
    out = []
    for block in _fenced_bash(_teardown_section()):
        joined, buf = [], ""
        for line in block.splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            buf += s[:-1] + " " if s.endswith("\\") else s
            if s.endswith("\\"):
                continue
            joined.append(buf)
            buf = ""
        for cmd in joined:
            # **一行里可能被塞进多条命令**（Codex 第十二轮 P1-3）：合法 invoke 后追加
            # `; aws lambda invoke --function-name site-panel` 时旧版只看第一条就漏了。
            # 按命令分隔符切开，每段单独查——分隔符本身也不该出现在可照抄的 runbook 命令里。
            for seg in re.split(r"(?:;|&&|\|\||\||&)", cmd):
                m = _AWS_CALL.search(seg)
                if not m:
                    continue
                parts = seg.split()
                flag = val = None
                for f in ("--table-name", "--function-name"):
                    if f in parts:
                        flag, val = f, parts[parts.index(f) + 1]
                        break
                out.append((m.group(1), m.group(2), flag, val, seg.strip()))
    return out


def test_teardown_section_has_no_copyable_destructive_commands():
    """围栏块里的写操作必须**逐条**在豁免表里，且目标与次数都对得上。

    判定用与 harness 同一套 fail-closed 分类：只读动词之外一律算破坏性。
    """
    seen, offenders = {}, []
    for svc, verb, flag, val, cmd in _doc_aws_commands():
        if _is_readonly(f"{svc} {verb}"):
            continue
        key = (svc, verb, flag, val)
        if key not in _DOC_ALLOWED_EXACT:
            offenders.append(cmd[:110])
        else:
            seen[key] = seen.get(key, 0) + 1
    assert offenders == [], (
        "拆除一节的围栏块里出现了豁免表之外的写操作，请改为调用 "
        "scripts/teardown_platform.sh：\n  " + "\n  ".join(offenders))
    assert seen == _DOC_ALLOWED_EXACT, (
        f"豁免命令的出现次数不对：实得 {seen}，期望 {_DOC_ALLOWED_EXACT}")


def test_doc_exemption_list_stays_minimal():
    """豁免清单必须只有那两条**具体命令**（含目标与次数）。

    多一条就等于又开了一个可照抄的口子，而那正是前三轮 P1 的长发地。
    """
    assert _DOC_ALLOWED_EXACT == {
        ("dynamodb", "put-item", "--table-name", "site-deploy-jobs"): 1,
        ("lambda", "invoke", "--function-name", "site-deployer-undeploy"): 1,
    }, _DOC_ALLOWED_EXACT


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
