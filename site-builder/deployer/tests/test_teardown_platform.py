"""`scripts/teardown_platform.sh` 的故障注入 harness。

**为什么这份测试必须存在。** 拆除流程此前是 DEPLOY.md 里的几段 Markdown，连续三轮
复审各发现一个 P1，根因每次都一样：某处"存在性判断"被写成「命令失败就当不存在」，
于是 AccessDenied / 限流被当成 ABSENT，脚本继续做破坏性操作并最终退 0。
`bash -n` 只能证明语法；"跑一遍看输出对不对"只验证例子。所以这里验的是**不变量**：

    对每个阶段、每种非 NotFound 故障：脚本必须非零退出，
    且**从注入点开始，日志里不能再出现任何破坏性调用**。

harness 用一个假的 `aws` 可执行文件顶在 PATH 前面，把每次调用记进日志，并按
`FAKE_FAIL_ON` / `FAKE_FAIL_CODE` 注入故障。判"破坏性"用的是动词白名单
（见 `_DESTRUCTIVE`），不是某个具体命令——将来加了新的删除动作也会自动进射程。
"""
import os
import shutil
import subprocess
import sys
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
stack_name = ApplicationWebRouterStack
""" % _ACCOUNT

# 假 aws：默认一切 PRESENT 且调用成功。
#   FAKE_FAIL_ON   —— 命中这个子串的调用按 FAKE_FAIL_CODE 失败
#   FAKE_ABSENT    —— 命中这个子串的调用报 NotFound
#   FAKE_ALL_ABSENT—— 所有"读"类调用都报 NotFound（模拟已经清干净的账号）
_FAKE_AWS = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_LOG"

emit_fail() { echo "An error occurred ($1) when calling the operation" >&2; exit 254; }

if [ -n "${FAKE_FAIL_ON:-}" ] && [[ "$*" == *"$FAKE_FAIL_ON"* ]]; then
  emit_fail "${FAKE_FAIL_CODE:-AccessDeniedException}"
fi
if [ -n "${FAKE_ABSENT:-}" ] && [[ "$*" == *"$FAKE_ABSENT"* ]]; then
  emit_fail "ResourceNotFoundException"
fi
if [ -n "${FAKE_ALL_ABSENT:-}" ]; then
  case "$*" in
    *get-caller-identity*) echo "$FAKE_ACCOUNT" ;;
    *describe-table*|*get-function*|*get-role*|*get-parameter*|*describe-stacks*|\
    *describe-repositories*|*get-agent-runtime*|*get-cluster*|*describe-user-pool*|\
    *get-topic-attributes*|*head-bucket*|*get-function-url-config*) emit_fail "ResourceNotFoundException" ;;
    *list-keys*|*describe-log-groups*|*describe-alarms*|*list-user-pools*|*list-role-policies*|\
    *list-attached-role-policies*) echo "None" ;;
    *) echo "None" ;;
  esac
  exit 0
fi

# 让 stub 有一点真实的状态：delete-cluster 之后 get-cluster 就该报 NotFound
# （否则"一切 PRESENT"意味着轮询永远等不到 ABSENT，而脚本**正确地**超时 hard-stop）。
case "$*" in
  *"dsql delete-cluster"*) : > "$FAKE_LOG.dsql-deleted" ;;
  *"dsql get-cluster"*)
      # FAKE_DSQL_NEVER_GONE：模拟"删了但一直读得到"（验超时 hard-stop 那条）
      if [ -z "${FAKE_DSQL_NEVER_GONE:-}" ] && [ -f "$FAKE_LOG.dsql-deleted" ]; then
        emit_fail "ResourceNotFoundException"
      fi ;;
esac

# 默认：PRESENT + 各种查询返回可用值
case "$*" in
  *get-caller-identity*)                 echo "$FAKE_ACCOUNT" ;;
  *"scan --table-name site-sites"*)
      if [ -n "${FAKE_SITES_REMAIN:-}" ]; then echo "still-alive-site"; else echo "None"; fi ;;
  *"Table.DeletionProtectionEnabled"*)   echo "True" ;;
  *list-role-policies*)                  echo "None" ;;
  *list-attached-role-policies*)         echo "None" ;;
  *describe-alarms*)                     echo "site-builder-auth-invalid-grant" ;;
  *list-user-pools*)                     echo "us-east-1_idp" ;;
  *"UserPool.Domain"*)                   echo "some-prefix" ;;
  *list-keys*)                           echo "key-1" ;;
  *describe-key*)                        echo -e "Enabled\tsite-builder session signing key site-rs-v1" ;;
  *describe-log-groups*)                 echo "/aws/lambda/site-panel" ;;
  *)                                     echo "None" ;;
esac
exit 0
"""


@pytest.fixture
def harness(tmp_path):
    """在 tmp 下搭一个假仓库（config.ini + 假 aws），返回一个跑脚本的 runner。"""
    sb = tmp_path / "site-builder"
    (sb / "scripts").mkdir(parents=True)
    (tmp_path / "router").mkdir()
    (sb / "config.ini").write_text(_SB_CONFIG, encoding="utf-8")
    (tmp_path / "router" / "config.ini").write_text(_ROUTER_CONFIG, encoding="utf-8")
    shutil.copy(_SCRIPT, sb / "scripts" / "teardown_platform.sh")
    os.chmod(sb / "scripts" / "teardown_platform.sh", 0o755)

    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(_FAKE_AWS, encoding="utf-8")
    os.chmod(aws, 0o755)
    log = tmp_path / "aws-calls.log"
    log.write_text("", encoding="utf-8")

    def run(*args, env=None):
        e = dict(os.environ)
        e["PATH"] = f"{bin_dir}{os.pathsep}{os.path.dirname(sys.executable)}{os.pathsep}{e['PATH']}"
        e["FAKE_LOG"] = str(log)
        e["FAKE_ACCOUNT"] = _ACCOUNT
        for k in ("FAKE_FAIL_ON", "FAKE_FAIL_CODE", "FAKE_ABSENT", "FAKE_ALL_ABSENT",
                  "FAKE_SITES_REMAIN", "FAKE_DSQL_NEVER_GONE"):
            e.pop(k, None)
        # 默认把轮询压掉：这些用例不验时间，只验状态机。验超时的那条自己覆盖回来。
        e.setdefault("TEARDOWN_POLL_TRIES", "2")
        e.setdefault("TEARDOWN_POLL_SLEEP", "0")
        e.update(env or {})
        proc = subprocess.run(
            ["bash", str(sb / "scripts" / "teardown_platform.sh"), *args],
            capture_output=True, text=True, env=e, cwd=str(tmp_path))
        calls = [l for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
        return proc, calls

    return run


def _destructive(calls):
    return [c for c in calls if any(v in f" {c} " for v in _DESTRUCTIVE)]


# --------------------------------------------------------------------------
# 基线：脚本本身能跑通两种"正常"形态
# --------------------------------------------------------------------------

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
    """全 NotFound（= 重跑一个已经清干净的账号）：退 0、无破坏性调用、跑完所有阶段。"""
    proc, calls = harness("--yes", env={"FAKE_ALL_ABSENT": "1"})
    assert proc.returncode == 0, proc.stderr
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
                     "delete-stack", "delete-table", "schedule-key-deletion"):
        assert expected in d, f"没发出 {expected}:\n{d}"


# --------------------------------------------------------------------------
# 核心不变量：任何非 NotFound 故障都必须阻止**所有后续**破坏性调用
#
# 这是前三轮反复失守的那一条。按**阶段**逐个注入，因为"入口就退出"不代表后面也退出
# ——上一轮我拿"全 AccessDenied"跑端到端，它在第一条命令就退出了，②b 与 ④ 根本没被覆盖。
# --------------------------------------------------------------------------

# (阶段, 该阶段第一个探测会命中的子串)
_STAGE_PROBE = [
    ("preflight", "describe-table --table-name site-sites"),
    ("scripts",   "get-agent-runtime"),
    ("dsql",      "get-cluster"),
    ("stacks",    "describe-stacks"),
    ("orphans",   "describe-table --table-name site-access-daily"),
]


@pytest.mark.parametrize("stage,needle", _STAGE_PROBE, ids=[s for s, _ in _STAGE_PROBE])
@pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException",
                                  "RequestTimeout", "ValidationException"])
def test_non_notfound_error_hard_stops_the_stage(harness, stage, needle, code):
    """在某阶段的第一个探测上注入非 NotFound 故障 ⇒ 非零退出，且**该点之后没有破坏性调用**。"""
    proc, calls = harness("--yes", "--stage", stage,
                          env={"FAKE_FAIL_ON": needle, "FAKE_FAIL_CODE": code})
    assert proc.returncode != 0, (
        f"{stage} 遇到 {code} 却退 0 —— UNKNOWN 被当成了 ABSENT\n{proc.stdout}")
    # 注入点之后一条破坏性调用都不许有
    idx = next((i for i, c in enumerate(calls) if needle in c), None)
    assert idx is not None, f"注入点没被调用到:\n{calls}"
    after = _destructive(calls[idx:])
    assert after == [], f"{stage} 在 {code} 之后仍发出破坏性调用: {after}"


@pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException"])
def test_non_notfound_error_stops_later_stages_too(harness, code):
    """整轮跑（不限阶段）时，早阶段的 UNKNOWN 必须挡住**后面所有阶段**。
    只 break / 只打印提示都不算——那是 fail-open。"""
    proc, calls = harness("--yes", env={"FAKE_FAIL_ON": "get-agent-runtime",
                                        "FAKE_FAIL_CODE": code})
    assert proc.returncode != 0
    assert _destructive(calls) == [], _destructive(calls)
    # 后面的阶段一个都不该开始
    for later in ("dsql：", "stacks：", "orphans："):
        assert later not in proc.stdout, f"{code} 之后仍进入了 {later}\n{proc.stdout}"


def test_dsql_poll_timeout_is_a_hard_stop(harness, monkeypatch):
    """cluster 删了但一直读得到（轮询耗尽）⇒ 必须非零退出，**不能**接着去删栈。
    原先那版只 break，于是超时之后照样删栈。"""
    # get-cluster 一直 PRESENT ⇒ 轮询永远读不到 ABSENT。把轮询参数压到 3×0 秒，
    # 只为让超时分支在测试里可达（生产默认仍是 60×10s）。
    proc, calls = harness("--yes", "--stage", "dsql",
                          env={"TEARDOWN_POLL_TRIES": "3", "TEARDOWN_POLL_SLEEP": "0",
                               "FAKE_DSQL_NEVER_GONE": "1"})
    assert proc.returncode != 0, f"轮询耗尽却退 0:\n{proc.stdout}\n{proc.stderr}"
    assert "超时" in proc.stdout + proc.stderr, proc.stdout + proc.stderr


def test_preflight_refuses_when_sites_remain(harness):
    """站点没下线完就拒绝往下走——站点资源不在任何栈里，删栈只会把它们变成孤儿。"""
    proc, calls = harness("--yes", env={"FAKE_SITES_REMAIN": "1"})
    assert proc.returncode != 0, proc.stdout
    assert "还有站点没下线" in proc.stderr, proc.stderr
    # 关键：拒绝发生在**任何**破坏性调用之前
    assert _destructive(calls) == [], _destructive(calls)
    # 而且后面的阶段一个都没开始
    for later in ("scripts：", "dsql：", "stacks：", "orphans："):
        assert later not in proc.stdout


def test_probe_classifies_only_notfound_as_absent(harness):
    """直接对 `probe` 的分类做单元级断言：NotFound → ABSENT，其余 → UNKNOWN。

    这条把不变量钉在**最小单位**上，不依赖任何阶段的具体命令。
    """
    script = _SCRIPT.read_text(encoding="utf-8")
    # 只取 _is_absent_err + probe 两个函数来跑，避免执行整个脚本
    body = script[script.index("_is_absent_err() {"):script.index("# need_delete <描述>")]
    prog = textwrap.dedent("""
        set -uo pipefail
        %s
        fail() { echo "An error occurred ($1) when calling the operation" >&2; return 254; }
        probe ok true
        probe nf fail ResourceNotFoundException
        probe dn fail AccessDeniedException
        probe th fail ThrottlingException
        probe to fail RequestTimeout
    """) % body
    out = subprocess.run(["bash", "-c", prog], capture_output=True, text=True)
    states = [l for l in out.stdout.split() if l in ("PRESENT", "ABSENT", "UNKNOWN")]
    assert states == ["PRESENT", "ABSENT", "UNKNOWN", "UNKNOWN", "UNKNOWN"], (
        f"分类错了: {states}\n{out.stdout}\n{out.stderr}")


# --------------------------------------------------------------------------
# 防回归：DEPLOY.md 的拆除一节**不许**再出现可照抄的破坏性命令
#
# 前三轮的 P1 全部长在那一节的围栏块里。只要那些命令还能被照抄，同一类缺陷就会再长出来
# （而且照抄的人不会跑本文件的测试）。所以这里把"必须委派给脚本"钉住。
# --------------------------------------------------------------------------
_DEPLOY_MD = _ROOT / "site-builder" / "DEPLOY.md"
_SECTION = "## 把平台从账号里拆掉"


def _teardown_section() -> str:
    t = _DEPLOY_MD.read_text(encoding="utf-8")
    start = t.index(_SECTION)
    end = t.index("\n## ", start + len(_SECTION))
    return t[start:end]


def _fenced_bash(text):
    import re
    return re.findall(r"```bash\n(.*?)```", text, re.S)


def test_teardown_section_delegates_to_the_script():
    """那一节必须点名脚本，并给出 --dry-run。"""
    sec = _teardown_section()
    assert "scripts/teardown_platform.sh" in sec
    assert "--dry-run" in sec, "没告诉采用者可以先空跑一遍"


def test_teardown_section_has_no_copyable_destructive_commands():
    """围栏块里不许再有破坏性动词——那些必须走脚本（脚本有三值探测 + hard-stop）。

    唯一允许的例外：第 ① 步"站点下线"是**人的判断**，它用 put-item / lambda invoke，
    本身不含删除动词，所以这条断言对它天然成立，不需要开豁免口子。
    """
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
