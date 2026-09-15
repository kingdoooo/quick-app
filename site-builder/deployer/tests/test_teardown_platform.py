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
判"破坏性"用动词白名单（`_DESTRUCTIVE`），不是某条具体命令——将来加了新的删除动作
也会自动进射程。
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[3]
_SCRIPT = _ROOT / "site-builder" / "scripts" / "teardown_platform.sh"

# 破坏性动词。**按动词判而不是按整条命令**：新增一种删除动作时不必回来改这张表，
# 漏改的后果恰恰是"新动作不在射程内"，而那正是这份测试要防的。
_DESTRUCTIVE = (
    "delete-", "schedule-key-deletion", "batch-delete-image",
    "--no-deletion-protection-enabled", "detach-role-policy", " rm ",
)

_ACCOUNT = "000000000000"
_ROUTER_STACK = "ApplicationWebRouterStack"
_SITE_IDS = ("demo-a1b2c3", "shop-d4e5f6")
# Edge 日志组在**每个执行区**都有一份；这里造三个区（含本区）来验跨区清理。
_REGIONS = ("us-east-1", "us-west-2", "ap-northeast-1")
# 归属清单内的 Edge 副本日志组（名字里的区是**归属区**，恒为 us-east-1）
_OWNED_EDGE_LG = f"/aws/lambda/us-east-1.{_ROUTER_STACK}-application-web-router"
# 账号里别人的 Edge 函数：DEPLOY.md 实测记过这种（redirectEdge），**删它是事故**
_FOREIGN_EDGE_LG = "/aws/lambda/us-east-1.redirectEdge"

_SB_CONFIG = """\
[Platform]
base_domain = example.com
account_id = {account}
region = us-east-1
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
""".format(account=_ACCOUNT)

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

fail() { echo "An error occurred ($1) when calling the operation: injected" >&2; exit 254; }

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
  *list-role-policies*)                  echo "None" ;;
  *list-attached-role-policies*)         echo "None" ;;
  *describe-alarms*)                     echo "site-builder-auth-invalid-grant" ;;
  *list-user-pools*)                     echo "us-east-1_idp" ;;
  *"UserPool.Domain"*)                   echo "some-prefix" ;;
  *list-keys*)                           echo "key-1" ;;
  *describe-key*)                        echo -e "Enabled\tsite-builder session signing key site-rs-v1" ;;
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
    "FAKE_FAIL_ON", "FAKE_FAIL_ON_NTH", "FAKE_FAIL_CODE", "FAKE_ALL_ABSENT",
    "FAKE_ORPHAN_ROLES", "FAKE_ORPHAN_TABLES", "FAKE_UNOWNED_LOG_GROUP",
    "FAKE_ROUTER_DELETE_FAILED", "FAKE_DELETE_FAILED_REASON",
    "FAKE_MIXED_DELETE_FAILURE", "FAKE_STACK_NEVER_GONE", "FAKE_DSQL_NEVER_GONE",
    "FAKE_RUNTIME_NEVER_GONE", "FAKE_STATUS_STALE_ONCE", "FAKE_STATUS_STUCK",
)


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
        return proc, calls

    return run


@pytest.fixture
def harness(tmp_path):
    return _build_sandbox(tmp_path)


def _destructive(calls):
    return [c for c in calls if any(v in f" {c} " for v in _DESTRUCTIVE)]


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
_READ_VERB = re.compile(r"^(get|describe|list|head)-|^scan$")
_AWS_CALL = re.compile(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)")

# 收集射程用的场景：default 覆盖绝大多数，另两个把只在特定状态下才走到的读点造出来。
_COLLECT_SCENARIOS = {
    "default": {},
    "router-delete-failed": {"FAKE_ROUTER_DELETE_FAILED": "1"},
    "sites-table-gone": {"FAKE_ALL_ABSENT": "1"},
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


_READ_POINTS = _collect_read_points()
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

def test_probe_classifies_only_notfound_as_absent():
    """直接对 `probe` 的分类做单元级断言：NotFound → ABSENT，其余 → UNKNOWN。"""
    script = _SCRIPT.read_text(encoding="utf-8")
    body = script[script.index("_is_absent_err() {"):script.index("# checked <描述>")]
    prog = textwrap.dedent("""
        set -uo pipefail
        %s
        fail() { echo "An error occurred ($1) when calling the operation" >&2; return 254; }
        probe ok true
        probe nf fail ResourceNotFoundException
        probe dn fail AccessDeniedException
        probe th fail ThrottlingException
        probe to fail RequestTimeout
        probe hb bash -c 'echo "An error occurred (404) when calling the HeadBucket operation: Not Found" >&2; exit 254'
    """) % body
    out = subprocess.run(["bash", "-c", prog], capture_output=True, text=True)
    states = [l for l in out.stdout.split() if l in ("PRESENT", "ABSENT", "UNKNOWN")]
    # 最后一条是 head-bucket 的真实报文：它**不该**被认成 ABSENT（P2 的最小单位断言）
    assert states == ["PRESENT", "ABSENT", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"], (
        f"分类错了: {states}\n{out.stdout}\n{out.stderr}")


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


def test_teardown_section_has_no_copyable_destructive_commands():
    """围栏块里不许再有破坏性动词——那些必须走脚本（脚本有三值探测 + hard-stop）。"""
    offenders = []
    for block in _fenced_bash(_teardown_section()):
        for line in block.splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            for verb in _DESTRUCTIVE:
                if verb in f" {s} ":
                    offenders.append(s)
                    break
    assert offenders == [], (
        "拆除一节的围栏块里又出现了可照抄的破坏性命令，请改为调用 "
        "scripts/teardown_platform.sh：\n  " + "\n  ".join(offenders))


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
# 不带区也能用的服务。**每一条都是清空 AWS_REGION / AWS_DEFAULT_REGION / 配置文件后
# 实测过的**（aws-cli 2.36.34），不是凭"听说是全局服务"：
#   iam    全局端点 iam.amazonaws.com
#   sts    有全局端点回退，实测正常返回身份
#   s3/s3api 实测正常解析（get-bucket-location 正确报 NoSuchBucket）
_REGIONLESS_OK = {"iam", "sts", "s3", "s3api"}


def _logical_aws_lines():
    """把续行拼起来、去掉注释，返回每条含 aws 调用的逻辑行。"""
    out, buf = [], ""
    for raw in _SCRIPT.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        buf += raw[:-1] + " " if raw.rstrip().endswith("\\") else raw
        if raw.rstrip().endswith("\\"):
            continue
        if " aws " in f" {buf} ":
            out.append(buf)
        buf = ""
    return out


def test_every_regional_call_passes_region():
    """区域性服务的每一次调用都必须显式带 `--region`。"""
    offenders = []
    for line in _logical_aws_lines():
        for m in re.finditer(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)", line):
            service = m.group(1)
            if service in _REGIONLESS_OK:
                continue
            if "--region" not in line:
                offenders.append(f"{service} {m.group(2)}  <-  {line.strip()[:100]}")
    assert offenders == [], (
        "这些区域性服务调用没带 --region；没有 CLI 默认区的环境里它们会报 NoRegion，"
        "而那会在**删过东西之后**才 hard-stop：\n  " + "\n  ".join(offenders))


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
