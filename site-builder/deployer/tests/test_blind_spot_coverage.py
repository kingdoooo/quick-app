"""「三个已接受盲区各有一条真的会跑的用例」这个声明的守卫。

**为什么独立成一个模块**：它守的对象是 `test_verify_account_trust_boundary.py`。守卫住在
被守的文件里时，那份文件整个被关掉（模块级 `pytestmark = pytest.mark.skip`、conftest 里
`collect_ignore`）会让守卫自己也一起消失 —— 一个不会跑的守卫和一个通过的守卫在输出上
没有区别。放在外面才能自我保住。

## 这道守卫被绕过四次，每次都是判据停在比"最终会执行"更浅的一层

| 版本 | 判据 | 绕法（都实测复现过） |
|---|---|---|
| v1 | 源码正则数 `def test_..._is_a_known_blind_spot(` 的条数 | 改名 + 补一行注释形态的假 `def` |
| v2 | `globals()` 里有名字、callable、无 skip/xfail 标记 | `test_x.__test__ = False`（pytest 原生关法）|
| v3 | 本进程内 `pytest_collection_modifyitems(tryfirst)` 存下的**过滤前**快照 | 同一个 hook 存完快照再 `items[:] = [...]`；任何更晚的 hook / 插件 deselect 同理 |
| v4（现在）| **子进程里 pytest 自己走完整条收集流程后的最终结果** | —— |

v3 那一层的病根值得单独记：为了不受外层 `-k` 影响，它刻意取"过滤之前"的清单，
于是**同时**看不见过滤之后的一切删除 —— 而"`-k` 的 deselect"与"别的 hook 把 item 删掉"
在那份快照里根本无法区分。**一个为了躲开噪音而后退的判据，会把信号一起躲掉。**

v4 换成问 pytest 本身：子进程不继承外层的 `-k`/`-m`，所以噪音问题不存在；而它拿到的就是
最终清单，`__test__ = False`、`collect_ignore`、后置 hook 删除、插件 deselect 全都反映在里面
—— **不必再逐个去猜有几种关法**，这正是前三版反复失手的原因。

## 一条实测坑：不要看 `--collect-only` 的汇总计数

hook 删掉一条 item 之后，汇总行照样打印 `156 tests collected`，而 `::` 那些行里那条**确实
已经不在了**。我第一次复现 v3 的漏洞时正是被这个汇总数骗过，误判成"漏洞不存在"。
**判据只认 `::` 行。**
"""
import os
import re
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TARGET = _HERE / "test_verify_account_trust_boundary.py"

# 三个已接受盲区：（文档里必须点名的**机制描述**, 人类可读标签）。
#
# 判据取每个盲区**独有的机制描述**，不取单个词。实测教训：早先用「改回」「分页」这种短词，
# 而文档别处也在说同一件事（boundary 那段就写着"不需要'改了又改回来'那种巧合"）⇒
# 把盲区①整段删掉，守卫照样绿。**判据比主语弱和比主语窄一样危险。**
#
# **这个模块是唯一 owner**：`test_verify_account_trust_boundary.py` 的文档口径守卫从这里
# import。两处各写一份必然悄悄不同步，而"三个盲区"这句话与现实脱钩过一次了。
_BLIND_SPOTS = (("恢复成与 T1 逐字相同", "①改了又改回来（ABA）"),
                ("复查前删除", "②枚举后新建、复查前删除"),
                ("翻页期间的变化不可见", "③单次枚举自己不是一个时刻"))

_BLIND_SPOT_TESTS = ("test_change_then_revert_is_a_known_blind_spot",
                     "test_created_then_deleted_between_enumerations_is_a_known_blind_spot",
                     "test_pagination_window_is_a_known_blind_spot")

_COUNT_RE = re.compile(r"(\d+) (passed|failed|error|errors|skipped|xfailed|xpassed|deselected)")


def _run_pytest(*args: str) -> subprocess.CompletedProcess:
    """在**干净的子进程**里跑 pytest。

    **必须洗掉 `PYTEST_ADDOPTS`**：它会把外层的 `-k` 之类偷偷带进子进程，而变形 harness
    每条变形都用 `-k` 跑 —— 那样判据又会随外层的调用方式变化，正是 v3 想躲又躲错的那个问题。
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--no-header", "-p", "no:cacheprovider", *args],
        cwd=_HERE.parent, capture_output=True, text=True, env=env)


def _counts(stdout: str) -> dict[str, int]:
    tail = (stdout.strip().splitlines() or [""])[-1]
    return {k.rstrip("s") if k == "errors" else k: int(n)
            for n, k in _COUNT_RE.findall(tail)}


def _final_collected_names() -> set[str]:
    """目标文件里 pytest **最终**会跑的用例名（子进程、无外层过滤）。"""
    r = _run_pytest("--collect-only", "-q", str(_TARGET))
    assert r.returncode == 0, (
        f"子进程 --collect-only 自己就失败了，无法判断（拒绝放行）：\n{r.stdout[-800:]}")
    # 只认 `::` 行 —— 汇总计数会报删除前的总数（见模块 docstring 的那条实测坑）
    names = {line.rsplit("::", 1)[1].split("[", 1)[0].strip()
             for line in r.stdout.splitlines() if "::" in line}
    assert names, "子进程一条用例都没收集到 —— 判据失效，拒绝放行"
    return names


def test_blind_spot_tests_are_collected_and_none_stray():
    """三条盲区用例都在**最终**收集清单里，且没有名单外的第四条游离着。

    盖住：改名、注释掉、`__test__ = False`、`collect_ignore`、任何 hook / 插件在收集阶段
    把 item 删掉。
    """
    assert len(_BLIND_SPOT_TESTS) == len(_BLIND_SPOTS), \
        "盲区名单与用例名单不同长 —— 两者必须同时改"
    collected = _final_collected_names()
    missing = [n for n in _BLIND_SPOT_TESTS if n not in collected]
    assert not missing, (
        f"pytest 最终不会跑这些盲区用例：{missing}"
        f"（被改名 / 注释掉 / `__test__ = False` / 被某个 hook 从 items 里删掉？）"
        f"—— 而文档写着 {len(_BLIND_SPOTS)} 个盲区各有一条用例")
    stray = {n for n in collected
             if n.startswith("test_") and n.endswith("_is_a_known_blind_spot")
             } - set(_BLIND_SPOT_TESTS)
    assert not stray, f"有盲区用例不在名单里：{sorted(stray)} —— 名单与文档要同时更新"


def test_blind_spot_tests_actually_execute():
    """按 nodeid 显式跑那三条，必须**恰好 3 passed 且零 skipped / xfailed**。

    **收集到 ≠ 会执行**：`skip` / `skipif` / `xfail` 的用例照样出现在收集清单里，
    所以上一条守卫盖不住标记这一类，必须真跑一次看结果。
    """
    ids = [f"{_TARGET}::{n}" for n in _BLIND_SPOT_TESTS]
    r = _run_pytest("-q", *ids)
    counts = _counts(r.stdout)
    assert r.returncode == 0, (
        f"那三条盲区用例没能干净跑过（rc={r.returncode}，counts={counts}）："
        f"\n{r.stdout[-800:]}")
    assert counts.get("passed") == len(_BLIND_SPOT_TESTS), (
        f"期望恰好 {len(_BLIND_SPOT_TESTS)} 条 passed，实际 {counts}"
        f"—— 少一条就意味着有盲区没有真的被断言")
    for bad in ("skipped", "xfailed", "xpassed", "failed", "error", "deselected"):
        assert not counts.get(bad), (
            f"那三条里出现了 {bad}={counts[bad]}（{counts}）"
            f"—— 被收集但不执行等于没有断言")
