"""`scripts/verify_deployed_edge.sh` 里 3c-final 新增两段的守卫（静态 + 用替身 `aws` **真跑那两段**）。

同形先例：`test_router_stack_policy.py::test_the_edge_gate_runs_check_before_its_verdict`——那条也是
读这个 shell 脚本的文本下断言。这里做两件先例没做的事：

① **把段落从脚本里切出来真跑**，不手抄。手抄的副本证明的是副本的行为（用户全局 CLAUDE.md：
   "不维护未验证平价的简化副本"）。切片按注释标记定位，找不到就 `ValueError` ⇒ 段被删/改名时
   这个文件整批红，而不是静默变成空转。
② 每条负例都配正对照：负例红了但正例也红，那证明的只是"这段总是红"。

**为什么必须有这个文件**（Task 14 复审 I1）：新增两段此前只靠 `bash -n` 与一份未提交的 harness。
`bash -n` 只查语法，抓不到两个承重细节：
  · `while read` 的喂入方式——换成 `... | while read` 会把循环体放进子 shell，`fail()` 里的
    `FAILURES++` 落在子 shell 里，于是**每条红都打印出来而脚本仍然 exit 0**；
  · 三个负向分支里 `fail(` 的可达性——写成 `echo` 的红进不了退出码。
另外 Task 14 实测栽过一次：`$KID（` 里变量紧跟全角括号，bash 把 `KID（` 读成变量名，`set -u`
下 `unbound variable` **当场中断整个脚本**，而那个分支本该只是一条红。第 5 组用例守这一条。

evidence: static（文本断言）+ fake/unit（替身 `aws` / `python3`，全程无网络、无 AWS 凭证）。
真机证据只能来自部署后跑一次真的 `verify_deployed_edge.sh`。
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "site-builder" / "scripts" / "verify_deployed_edge.sh"
SRC = GATE.read_text(encoding="utf-8")

# 段落定位用的注释标记。**改这两个标记就要改这里**——切不出来时下面每条用例都会 ValueError，
# 那正是想要的：段被删掉或改名时守卫响亮失败，不会静默通过。
ARTIFACT_START = "# ---- 3c-final / ADR 0003："
ARTIFACT_END = 'echo "── ③'
KEYS_START = "# ---- 3c-final：site family 的**公钥精确对账**"
KEYS_END = "\nROWS\n"          # 逐把对账那个 while 的 here-doc 终止符
M05_START = "# ---- S1：M05（token 用途混用）与 M06（同名 cookie 遮蔽）----"
M05_END = KEYS_START           # M05 段紧挨着公钥对账段
# 工单 10（M17）：前端桶域名那一段。END 用紧跟其后那段的标记（同 M05_END 的做法）——
# 中间被插进新代码时切片会带上它、用例随之变化，而段被删/改名时 `_slice` 直接 ValueError。
FB_START = "# ---- 工单 10（M17）：前端桶域名"
FB_END = "# ---- M3：console 平台子域"


def _slice(start: str, end: str, *, keep_end: bool) -> str:
    i = SRC.index(start)                    # 找不到 ⇒ ValueError（段没了）
    j = SRC.index(end, i)
    return SRC[i:j + (len(end) if keep_end else 0)]


ARTIFACT_BLOCK = _slice(ARTIFACT_START, ARTIFACT_END, keep_end=False)
KEYS_BLOCK = _slice(KEYS_START, KEYS_END, keep_end=True)
M05_BLOCK = _slice(M05_START, M05_END, keep_end=False)
FB_BLOCK = _slice(FB_START, FB_END, keep_end=False)
# 前导里要用到脚本自己的 `read_cfg`（读 router/config.ini）。**从脚本里切出来、不手抄**：
# 手抄的副本证明的是副本的行为（用户全局 CLAUDE.md：不维护未验证平价的简化副本）。
CFG_LINE = next(ln for ln in SRC.splitlines() if ln.startswith("CFG="))
READ_CFG = CFG_LINE + "\n" + _slice("read_cfg() {", "\nPY\n}\n", keep_end=True)
EDGE_SRC = (ROOT / "router" / "infrastructure" / "lambda" / "origin_request.py").read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """丢掉**整行注释**，保留代码行（含行尾注释）。

    必须这么做，否则下面两条守卫会被脚本自己的注释绊倒：那些注释里**故意**写着反例
    （"换成 `... | while read` 会把循环体放进子 shell"、"`$KID（` 会被读成变量名"）——
    把教训写下来是对的，守卫不该因此失效。行尾注释仍在扫描范围内（更严，且今天没有反例）。
    """
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


CODE = _code_only(SRC)


# ---- ① 静态：承重细节 ---------------------------------------------------------------------------

def test_the_per_key_loop_is_fed_by_a_here_doc_not_a_pipe():
    """`... | while read` 会把循环体放进子 shell ⇒ 每条红都打印却进不了退出码，整脚本 exit 0。

    这是本文件全部断言共同依赖的前提，所以两个方向都断：这一段确实用 here-doc 喂，
    **且整个脚本里没有任何** `| while read`。
    """
    assert "done <<ROWS" in KEYS_BLOCK, KEYS_BLOCK[-200:]
    assert re.search(r"\|\s*\\?\s*\n?\s*while\s+read", CODE) is None, \
        "有地方用管道喂 while —— 那个循环里的 fail() 进不了退出码"


def test_the_loop_body_mutates_failures_in_the_current_shell():
    """正对照：循环体里真的有 `fail`（否则上一条守的是一个空循环）。"""
    body = KEYS_BLOCK[KEYS_BLOCK.index("while read -r"):]
    assert body.count("fail ") >= 3, body


def _case_arms(block: str) -> dict:
    """`case ... esac` 里 `模式) 动作 ;;` 的映射（只取本段那个 case）。"""
    seg = block[block.index("case "):block.index("esac")]
    return {m.group(1): m.group(2)
            for m in re.finditer(r"^\s{4}(\S+?)\)\s+(.*?);;\s*$", seg, re.M)}


EXPECTED_ARMS = {"site:yes": "pass", "site:no": "fail",
                 "console:no": "pass", "console:yes": "fail"}


def test_the_per_key_case_covers_all_four_combinations():
    """四个组合一个都不能少：漏掉一个 ⇒ 那种形态既不 PASS 也不 FAIL，静默通过。"""
    assert set(_case_arms(KEYS_BLOCK)) == set(EXPECTED_ARMS), sorted(_case_arms(KEYS_BLOCK))


@pytest.mark.parametrize("arm", sorted(a for a, k in EXPECTED_ARMS.items() if k == "fail"))
def test_every_negative_arm_reaches_fail(arm):
    """`site:no`（Edge 拿的是另一把公钥）与 `console:yes`（console 公钥混进 Edge）必须走 `fail`。

    写成 `echo "FAIL …"` 的话报告里照样显眼，但 `FAILURES` 不动 ⇒ 退出码 0 ⇒ 自动化闸门放行。
    """
    action = _case_arms(KEYS_BLOCK)[arm]
    assert action.startswith("fail "), f"{arm} 分支不是 fail(): {action[:80]}"


@pytest.mark.parametrize("arm", sorted(a for a, k in EXPECTED_ARMS.items() if k == "pass"))
def test_every_positive_arm_is_a_plain_echo(arm):
    """正对照：两个正向分支必须是 `echo PASS` 而不是 `fail`——否则上面两条只是在守一段恒红的代码。"""
    action = _case_arms(KEYS_BLOCK)[arm]
    assert action.startswith('echo "PASS'), f"{arm} 分支不是 echo PASS: {action[:80]}"


def test_the_unavailable_key_branch_reaches_fail_and_does_not_skip_the_rest():
    """取不到 KMS 公钥时：`fail` + `continue`（不当通过、也不因为一把取不到就漏判后面几把）。"""
    seg = KEYS_BLOCK[KEYS_BLOCK.index('B64="$('):KEYS_BLOCK.index("if grep -qF")]
    assert "fail " in seg and "未验成" in seg, seg
    assert "continue" in seg, "取不到公钥后没有 continue —— 后面几把不判了"


def test_no_variable_is_followed_by_a_full_width_paren_without_braces():
    """`$VAR（` 会被 bash 读成变量名 `VAR（`，`set -u` 下 `unbound variable` **中断整个脚本**。

    Task 14 实测栽过：`fail "取不到 $KID（$ARN）…"` 把"一条红"变成"执行中断"。本文件头部的
    注释与脚本 ② 段的注释记的是同一条坑。整脚本扫，不只扫新增段。
    """
    bad = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*[（【《]", CODE)
    assert not bad, f"变量后紧跟全角括号且没加花括号: {bad}"


@pytest.mark.parametrize("bad_line,pattern,why", [
    ('printf x | while read -r a; do fail "$a"; done', r"\|\s*\\?\s*\n?\s*while\s+read", "管道喂 while"),
    ('fail "取不到 $KID（$ARN）"', r"\$[A-Za-z_][A-Za-z0-9_]*[（【《]", "变量紧跟全角括号"),
])
def test_the_two_shape_guards_would_actually_catch_the_bad_shape(bad_line, pattern, why):
    """**自测**：上面两条守卫扫的是代码行，而它们真的能咬住坏形态。

    没有这一条时，`_code_only` 只要把范围过滤成空串，那两条守卫就变成恒绿——而它们守的正是
    "红进不了退出码"与"整脚本中断"两个最坏形态。同一条语料的两个方向：作为整行注释时不算，
    作为代码行时必须算。
    """
    assert re.search(pattern, _code_only(bad_line)), f"守卫抓不住{why}"
    assert not re.search(pattern, _code_only("  # " + bad_line)), f"整行注释里的{why}不该算"


def test_the_code_only_filter_keeps_the_load_bearing_lines():
    """前提自查：过滤之后代码还在（否则上面两条守卫扫的是空串，恒绿）。"""
    assert "done <<ROWS" in CODE and "while read -r FAM KID ARN" in CODE
    assert len(CODE.splitlines()) > 100, len(CODE.splitlines())


def test_the_artifact_block_checks_vendored_deps_the_sentinel_and_the_golden():
    """产物三件：`cryptography/` 目录、`^RS256_GOLDEN = `、**没有**离线 synth 哨兵文件。

    前两条与哨兵那条**由构造互斥**（`stack.py` 走离线降级时不 vendoring、且放哨兵），
    所以三条一起才证明"这是个可部署的产物"。
    """
    assert 'test -d' in ARTIFACT_BLOCK or '[ -d "$TMP/cryptography" ]' in ARTIFACT_BLOCK, ARTIFACT_BLOCK
    assert "'^RS256_GOLDEN = '" in ARTIFACT_BLOCK
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt" in ARTIFACT_BLOCK
    # 哨兵那条的方向必须是"在即红"，不是"在即过"
    sentinel = ARTIFACT_BLOCK[ARTIFACT_BLOCK.index('SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt"'):]
    assert sentinel.index("fail ") < sentinel.index('echo "PASS'), sentinel[:200]


def test_the_hs_and_legacy_assertions_are_gone_from_the_gate():
    """3c-final：HS/legacy 的三处断言必须**删掉而不是留着永久红**（永久红会被当噪音忽略）。

    同时确认它们的**反向**断言在：产物里出现 `JWT_SECRET` / `LEGACY_ENTRY` 赋值即红。
    """
    assert 'if claims\\.get\\("typ"\\)' not in SRC, "legacy 的 typ 断言还在 —— 那段代码已删，它会永久红"
    assert "LEGACY_SWITCH" not in SRC and "JWT_EMPTY" not in SRC, "legacy 开关 × JWT_SECRET 的 case 还在"
    assert "k.legacy_param" not in SRC, "还在读 session_keys 已删掉的 legacy_param"
    assert "'^JWT_SECRET = |^LEGACY_ENTRY = '" in ARTIFACT_BLOCK, "缺 HS/legacy 残留的反向断言"


def test_the_gate_reconciles_public_keys_not_just_kids():
    """判据必须落在公钥字节上。只比 kid 集合时"Edge 拿的是另一把公钥"全绿而线上全员 302。"""
    assert "kms get-public-key" in KEYS_BLOCK
    assert "grep -qF" in KEYS_BLOCK, "没有按字节 grep 公钥"
    assert "spki_sha256" not in KEYS_BLOCK, \
        "拿指纹当公钥去 grep 产物 —— 永远匹配不上，是条恒红的假检查"
    # kid 集合等值那条也要留着（"不多不少"）
    assert "SITE_KIDS_EXPECTED" in KEYS_BLOCK and "SITE_KIDS_DEPLOYED" in KEYS_BLOCK


# ---- ② 端到端：用替身 aws / python3 真跑那两段（无网络）------------------------------------------

CONFIG = """\
[SessionKeys]
site_current = site-rs-v1
site_previous = site-rs-v0
console_current = console-rs-v1
console_previous =
login_flow_secret_param = /site-builder/login-flow-secret

[SessionKey:site-rs-v1]
alg = RS256
key_arn = arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-00000000000a
spki_sha256 = %s

[SessionKey:site-rs-v0]
alg = RS256
key_arn = arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-00000000000b
spki_sha256 = %s

[SessionKey:console-rs-v1]
alg = RS256
key_arn = arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-00000000000c
spki_sha256 = %s
""" % ("a" * 64, "b" * 64, "c" * 64)

# 工单 10（M17）：闸门从 router/config.ini 的 [AWS] account_id 推出期望的桶域名。
FB_ACCOUNT = "111122223333"
OTHER_ACCOUNT = "000000000000"
ROUTER_CONFIG = f"[AWS]\naccount_id = {FB_ACCOUNT}\nregion = us-east-1\n"

# 替身 aws 按 key ARN 的末字符造一个可预期的"公钥"。真实值是 base64(DER SPKI)，
# 这里只需要"每把不同、可放进 index.py 比对"。
PUB = {"site-rs-v1": "PUBKEY-AAAA", "site-rs-v0": "PUBKEY-BBBB", "console-rs-v1": "PUBKEY-CCCC"}
ARN_SUFFIX = {"site-rs-v1": "a", "site-rs-v0": "b", "console-rs-v1": "c"}

# 失败开关走**环境变量**而不是往 ARN 里塞记号：`session_keys` 的 uuid 正则是 `[0-9a-f-]{36}`，
# `DENY` 这种记号会在**加载 config 时**就被拒掉 ⇒ 测的就不是"KMS 拒了"那条路径了（实测踩过）。
AWS_STUB = """#!/bin/bash
# 替身：只认 `kms get-public-key --key-id <arn>`。$AWS_STUB_DENY 非空且是 ARN 的子串时按
# AccessDenied 失败（缺省值 __never__ 保证空值不会匹配一切）。
arn=""
while [ $# -gt 0 ]; do case "$1" in --key-id) arn="$2"; shift 2;; *) shift;; esac; done
case "$arn" in *"${AWS_STUB_DENY:-__never__}"*) echo "AccessDeniedException" >&2; exit 255;; esac
case "${arn##*-}" in
  *a) echo "PUBKEY-AAAA";;
  *b) echo "PUBKEY-BBBB";;
  *c) echo "PUBKEY-CCCC";;
  *)  echo "None";;
esac
"""


def _allowlist_json(kids) -> str:
    import json
    return json.dumps({k: {"alg": "RS256", "spki_b64": PUB[k], "role": "current"} for k in kids})


def _index_py(kids_in_allowlist, *, extra_lines="") -> str:
    return ("SITE_ALLOWLIST_JSON = '''" + _allowlist_json(kids_in_allowlist) + "'''\n"
            "RS256_GOLDEN = {\n    'spki_b64': 'x',\n}\n" + extra_lines)


@pytest.fixture
def env(tmp_path):
    """一棵最小的 `$ROOT` 树 + 一个 `$TMP` 产物目录 + PATH 上的替身 `aws` / `python3`。

    `python3` 也换成替身（转发到当前解释器）：切片里写的是裸 `python3`，而宿主那个可能是
    macOS 自带的 3.9（跑不了本仓库的脚本）。这样这条用例不依赖宿主工具链。
    """
    root = tmp_path / "root"
    (root / "site-builder" / "auth").mkdir(parents=True)
    (root / "site-builder" / "config.ini").write_text(CONFIG, encoding="utf-8")
    (root / "router").mkdir(parents=True)
    (root / "router" / "config.ini").write_text(ROUTER_CONFIG, encoding="utf-8")
    shutil.copy(ROOT / "site-builder" / "auth" / "session_keys.py",
                root / "site-builder" / "auth" / "session_keys.py")
    art = tmp_path / "art"
    art.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "aws").write_text(AWS_STUB, encoding="utf-8")
    (bin_dir / "python3").write_text(f'#!/bin/bash\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for f in ("aws", "python3"):
        (bin_dir / f).chmod(0o755)
    return {"root": root, "art": art, "bin": bin_dir}


def _run(block: str, env: dict, *, prelude: str = "", **extra_env) -> tuple:
    """把切片装进最小前导里跑一遍 → (rc, 输出)。

    前导只提供脚本自己提供的那几样（`fail` / `FAILURES` / `ROOT` / `TMP` / `REGION`），
    结尾按脚本的总判定退出（`FAILURES > 0` ⇒ 非 0）。`prelude` 给需要脚本里别的助手的段
    （工单 10 那段要 `read_cfg`），内容同样是**从脚本里切出来的**，不是手抄。
    """
    script = (
        'set -euo pipefail\n'
        'ROOT="$1"; TMP="$2"; REGION=us-east-1\n'
        'FAILURES=0\n'
        'fail() { echo "FAIL  $1"; FAILURES=$((FAILURES + 1)); }\n'
        + prelude + "\n"
        + block +
        '\necho "FAILURES=$FAILURES"\n'
        '[ "$FAILURES" -eq 0 ]\n')
    proc = subprocess.run(
        ["bash", "-c", script, "bash", str(env["root"]), str(env["art"])],
        capture_output=True, text=True,
        env={**os.environ, "PATH": f"{env['bin']}:{os.environ['PATH']}", **extra_env})
    return proc.returncode, proc.stdout + proc.stderr


# ---- 公钥对账段：正对照 + 四种红 ---------------------------------------------------------------

def test_keys_block_exits_zero_when_every_key_reconciles(env):
    """**正对照**：site 两把都在产物里、console 那把不在 ⇒ 零红、退 0。

    下面四条红没有这一条就证明不了什么。
    """
    (env["art"] / "index.py").write_text(_index_py(["site-rs-v1", "site-rs-v0"]), encoding="utf-8")
    rc, out = _run(KEYS_BLOCK, env)
    assert rc == 0, out
    assert "FAILURES=0" in out, out
    assert out.count("PASS") >= 4, out          # kid 集合 1 + 三把各 1


def test_keys_block_reds_when_a_console_public_key_is_in_the_artifact(env):
    """console 公钥混进 Edge 产物（spec §4.1 的红线）⇒ 必须退非 0 并点名那个 kid。"""
    (env["art"] / "index.py").write_text(
        _index_py(["site-rs-v1", "site-rs-v0"],
                  extra_lines=f'# 顺手记一下：{PUB["console-rs-v1"]}\n'), encoding="utf-8")
    rc, out = _run(KEYS_BLOCK, env)
    assert rc != 0, out
    assert "console-rs-v1" in out and "console family 的公钥不得进 Edge" in out, out


def test_keys_block_reds_when_a_site_public_key_is_a_different_key(env):
    """kid 名字对、公钥是另一把（换 key 没重部 / 陈旧 cdk.out）⇒ 必须红。

    这正是"只比 kid 集合"看不见的形态：allowlist 的 kid 集合完全正确。
    """
    import json
    tampered = json.dumps({"site-rs-v1": {"alg": "RS256", "spki_b64": "PUBKEY-WRONG", "role": "current"},
                           "site-rs-v0": {"alg": "RS256", "spki_b64": PUB["site-rs-v0"], "role": "previous"}})
    (env["art"] / "index.py").write_text(
        "SITE_ALLOWLIST_JSON = '''" + tampered + "'''\nRS256_GOLDEN = {}\n", encoding="utf-8")
    rc, out = _run(KEYS_BLOCK, env)
    assert rc != 0, out
    assert "site-rs-v1" in out and "不在**产物里" in out, out
    assert "kid 集合 == config" in out, "kid 集合那条本该仍然是 PASS（证明这条红来自公钥比对）"


def test_keys_block_reds_when_the_deployed_kid_set_differs(env):
    """产物少一个 kid（config 有两把、注入只有一把）⇒ kid 集合那条红。"""
    (env["art"] / "index.py").write_text(_index_py(["site-rs-v1"]), encoding="utf-8")
    rc, out = _run(KEYS_BLOCK, env)
    assert rc != 0, out
    assert "kid 集合与 config 不一致" in out, out


def test_keys_block_reds_and_keeps_going_when_kms_denies(env):
    """一把取不到公钥（AccessDenied）⇒ 那条记红、**不崩**、后面几把继续判。

    这条同时是"`$KID（` 不加花括号会中断整个脚本"的回归：中断的话下面两把不会出现在输出里。
    """
    (env["art"] / "index.py").write_text(_index_py(["site-rs-v1", "site-rs-v0"]), encoding="utf-8")
    rc, out = _run(KEYS_BLOCK, env, AWS_STUB_DENY="0000000000a")
    assert rc != 0, out
    assert "未验成" in out, out
    assert "site-rs-v0" in out and "console-rs-v1" in out, \
        f"取不到公钥之后没继续判后面几把（脚本可能整个中断了）：{out}"
    assert "FAILURES=" in out, "脚本中断了 —— 走不到结尾"


# ---- 产物形态段：正对照 + 三种红 ---------------------------------------------------------------

def _good_artifact(art: Path) -> None:
    (art / "index.py").write_text(_index_py(["site-rs-v1"]), encoding="utf-8")
    (art / "cryptography").mkdir(exist_ok=True)


def test_artifact_block_exits_zero_on_a_deployable_artifact(env):
    """**正对照**：有 `cryptography/`、有 `RS256_GOLDEN`、无哨兵、无 HS 残留 ⇒ 退 0。"""
    _good_artifact(env["art"])
    rc, out = _run(ARTIFACT_BLOCK, env)
    assert rc == 0, out
    assert "FAILURES=0" in out, out


def test_artifact_block_reds_without_the_vendored_dependency(env):
    """缺 `cryptography/` ⇒ Edge **每次**冷启动 import 失败（整站不可用）⇒ 必须红。"""
    (env["art"] / "index.py").write_text(_index_py(["site-rs-v1"]), encoding="utf-8")
    rc, out = _run(ARTIFACT_BLOCK, env)
    assert rc != 0, out
    assert "cryptography" in out, out


def test_artifact_block_reds_on_the_offline_synth_sentinel(env):
    """哨兵文件在 ⇒ 部署的是离线 synth 的占位产物（Task 11 复审追加的那条）⇒ 必须红。"""
    _good_artifact(env["art"])
    (env["art"] / "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt").write_text("x", encoding="utf-8")
    rc, out = _run(ARTIFACT_BLOCK, env)
    assert rc != 0, out
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt" in out, out


def test_artifact_block_reds_on_an_hs_remnant(env):
    """产物里还有 `JWT_SECRET` / `LEGACY_ENTRY` 赋值 ⇒ 必须红（两个名字各一条用例的两个方向）。"""
    for line in ('JWT_SECRET = "x"\n', 'LEGACY_ENTRY = "off"\n'):
        _good_artifact(env["art"])
        (env["art"] / "index.py").write_text(_index_py(["site-rs-v1"], extra_lines=line),
                                             encoding="utf-8")
        rc, out = _run(ARTIFACT_BLOCK, env)
        assert rc != 0, (line, out)
        assert "HS/legacy 残留" in out, (line, out)


def test_artifact_block_reds_without_the_golden_warmup(env):
    """缺 `RS256_GOLDEN` ⇒ 部署的是 3c-final 之前的代码 ⇒ 必须红。"""
    (env["art"] / "cryptography").mkdir()
    (env["art"] / "index.py").write_text(
        "SITE_ALLOWLIST_JSON = '''{}'''\n", encoding="utf-8")
    rc, out = _run(ARTIFACT_BLOCK, env)
    assert rc != 0, out
    assert "RS256_GOLDEN" in out, out


# ---- M05 段：**用真源码跑**（正对照）+ 两个方向的红 -------------------------------------------
#
# 为什么必须用真源码：这段是本分支之前就有的旧断言，Task 10 把 Edge 的判定行从
# `!= "site-session":` 改成 `!= token_use:`（局部名钉用途，好让那段与 auth 逐字相同），
# 而这条断言的 grep 没跟着改；两个 Task 的单测各自全绿，直到切换后第一次真机跑闸门才假红。
# 下面第一条就是缺的那道链：闸门的判据必须能在 HEAD 的 origin_request.py 上过。

def test_m05_block_passes_on_the_real_edge_source(env):
    """**正对照**：HEAD 的 origin_request.py 原样当产物 ⇒ M05 段零红。"""
    (env["art"] / "index.py").write_text(EDGE_SRC, encoding="utf-8")
    rc, out = _run(M05_BLOCK, env)
    assert rc == 0, out
    assert "PASS  查 token_use" in out, out


def test_m05_block_reds_when_the_check_line_is_removed(env):
    """删掉判定行 ⇒ 任何用途的 token 都当站点会话 ⇒ 必须红。"""
    mutated = EDGE_SRC.replace('    if claims.get("token_use") != token_use:\n        return None, "wrong_token_use"\n', "")
    assert mutated != EDGE_SRC, "变形没生效——源码里的判定行形态变了，先改这里再改闸门"
    (env["art"] / "index.py").write_text(mutated, encoding="utf-8")
    rc, out = _run(M05_BLOCK, env)
    assert rc != 0, out
    assert "M05 未生效" in out, out


def test_m05_block_reds_when_the_local_pin_is_retargeted(env):
    """局部名改钉成别的用途（判定行原样）⇒ Edge 会接受 console 升级码当站点会话 ⇒ 必须红。

    这是"两行都在"里第二行存在的理由：只查判定行看不见这一种改法。
    """
    mutated = EDGE_SRC.replace('    token_use = "site-session"', '    token_use = "console-upgrade"', 1)
    assert mutated != EDGE_SRC, "变形没生效——源码里的用途钉形态变了，先改这里再改闸门"
    (env["art"] / "index.py").write_text(mutated, encoding="utf-8")
    rc, out = _run(M05_BLOCK, env)
    assert rc != 0, out
    assert "M05 未生效" in out, out


# ---- 前端桶域名段（工单 10 / M17）：真源码 + 合成产物各一条正对照 + 四种红 -----------------------
#
# 这一段抓的是"两份 config.ini 指向不同的桶"在**已部署产物**上的投影。synth 期已经有两道
# （`resolve_frontend_bucket` 的约定校验、`assert_frontend_bucket_matches_site_builder` 的跨 config
# 对账），但那两道都只看**本地**：换账号没重部、陈旧 cdk.out、绕过 CloudFormation 直接改 Lambda
# 代码，都只有在产物上比才看得见。症状是每个静态资源 403，而私有桶上「没权限」与「没这个对象」
# 都是 403 ⇒ 最难诊断的那一类。


def _fb_domain(account: str) -> str:
    return f"site-frontend-{account}.s3.us-east-1.amazonaws.com"


def _substituted_edge_src(account: str) -> str:
    """真源码按 `stack.py` 的替换链把 `{{FRONTEND_BUCKET_DOMAIN}}` 换掉。

    **必须用真源码**：这一段的判据是个 grep，而 grep 与源码行形态的漂移正是 M05 那条栽过的坑
    （两个 Task 的单测各自全绿，直到真机跑闸门才假红）。
    """
    out = EDGE_SRC.replace("{{FRONTEND_BUCKET_DOMAIN}}", _fb_domain(account))
    assert out != EDGE_SRC, "真源码里没有 {{FRONTEND_BUCKET_DOMAIN}} 注入点了 —— 先改这里再改闸门"
    return out


def test_the_frontend_bucket_block_derives_the_expected_name_from_config():
    """静态：期望值必须从 `read_cfg AWS account_id` 推，不许写死账号（写死了换账号就验错对象）。"""
    assert "read_cfg AWS account_id" in FB_BLOCK, FB_BLOCK
    assert re.search(r"(?<!\d)\d{12}(?!\d)", FB_BLOCK) is None, "闸门里写死了一个 12 位账号"
    assert "fail " in FB_BLOCK and 'echo "PASS' in FB_BLOCK, FB_BLOCK


def test_the_frontend_bucket_block_runs_before_the_verdict():
    """段落必须在总判定之前，否则它的红进不了退出码。"""
    assert SRC.index(FB_START) < SRC.index('if [ "$FAILURES" -gt 0 ]')


def test_frontend_bucket_block_passes_on_the_real_edge_source(env):
    """**正对照 ①**：HEAD 的 origin_request.py 按替换链注入后当产物 ⇒ 零红、退 0。"""
    (env["art"] / "index.py").write_text(_substituted_edge_src(FB_ACCOUNT), encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc == 0, out
    assert "FAILURES=0" in out and _fb_domain(FB_ACCOUNT) in out, out


def test_frontend_bucket_block_passes_on_a_synthetic_artifact(env):
    """**正对照 ②**：只有那一行的合成产物同样过——证明上一条不是靠源码里别的东西过的。"""
    (env["art"] / "index.py").write_text(
        f'FRONTEND_BUCKET_DOMAIN = "{_fb_domain(FB_ACCOUNT)}"\n', encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc == 0, out
    assert "FAILURES=0" in out, out


def test_frontend_bucket_block_reds_on_another_accounts_bucket(env):
    """产物里是另一个账号的桶（换账号没重部 / 陈旧 cdk.out / 两份 config 写了两个桶）⇒ 必须红。"""
    (env["art"] / "index.py").write_text(_substituted_edge_src(OTHER_ACCOUNT), encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc != 0, out
    assert _fb_domain(OTHER_ACCOUNT) in out and _fb_domain(FB_ACCOUNT) in out, out


def test_frontend_bucket_block_reds_when_the_assignment_is_missing(env):
    """注入点被删/改名 ⇒ 必须红，而不是"取到空串再和空串比"那种静默通过。"""
    (env["art"] / "index.py").write_text(
        _substituted_edge_src(FB_ACCOUNT).replace("FRONTEND_BUCKET_DOMAIN = ", "FB_DOMAIN = ", 1),
        encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc != 0, out
    assert "找不到 FRONTEND_BUCKET_DOMAIN" in out, out


def test_frontend_bucket_block_hard_fails_when_the_account_id_key_is_missing(env):
    """`read_cfg` 的纪律：键缺失硬失败、不回落空串（否则期望值成了 `site-frontend-.s3…`，恒红且无解释）。"""
    (env["root"] / "router" / "config.ini").write_text("[AWS]\nregion = us-east-1\n", encoding="utf-8")
    (env["art"] / "index.py").write_text(
        f'FRONTEND_BUCKET_DOMAIN = "{_fb_domain(FB_ACCOUNT)}"\n', encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc != 0, out
    assert "缺少 [AWS] account_id" in out, out


def test_frontend_bucket_block_strips_an_inline_comment_from_the_account_id(env):
    """bash 侧**剥**行内注释（`read_cfg` 原有行为），而 synth 期**拒**（`normalize_account_id`）。
    这个不对称是刻意的，且**不会**掩盖任何真实的不一致：

    带注释的 config **不可能**产出过一次部署——`normalize_account_id` 会让那次 synth 直接失败、
    什么都不部。所以闸门在这一侧剥完得到的，正是当初构建那个产物时用的账号；按它比才是对的答案。
    反过来在 shell 里再造一份"拒"的判定，就是多一处会与 Python 侧漂开的手抄判据。
    """
    (env["root"] / "router" / "config.ini").write_text(
        f"[AWS]\naccount_id = {FB_ACCOUNT}  # 我的账号\n", encoding="utf-8")
    (env["art"] / "index.py").write_text(
        f'FRONTEND_BUCKET_DOMAIN = "{_fb_domain(FB_ACCOUNT)}"\n', encoding="utf-8")
    rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
    assert rc == 0, out


def test_frontend_bucket_block_reds_with_an_accurate_message_when_the_account_is_malformed(env):
    """账号为空 / 被整行注释吞掉时，期望值会变成 `site-frontend-.s3…`——照样红，但原先的文案说的是
    「换了账号没重部」，指错方向。现在先断 12 位数字形态，消息直指 config。"""
    for bad in ("account_id = # 111122223333", "account_id ="):
        (env["root"] / "router" / "config.ini").write_text(f"[AWS]\n{bad}\n", encoding="utf-8")
        (env["art"] / "index.py").write_text(
            f'FRONTEND_BUCKET_DOMAIN = "{_fb_domain(FB_ACCOUNT)}"\n', encoding="utf-8")
        rc, out = _run(FB_BLOCK, env, prelude=READ_CFG)
        assert rc != 0, (bad, out)
        assert "12 位数字" in out and "换了账号没重部" not in out, (bad, out)
