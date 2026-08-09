"""前端**启动序列**的行为测试——在 node 里真正执行 boot()。

与 `test_frontend_contract.py` 的分工：那边是静态断言（"代码里有没有这个东西"），
这边是行为（"跑起来会不会崩"）。两者都不可替代——本轮的教训是**HTTP 层 E2E
61/61 全绿、30 条静态断言全绿，仍然漏了一个必崩的路径**：

  升级跳转回来那一次，boot() 里 `location.replace('#/sites')` 之后 `return`。
  改 hash 是**同文档导航**：浏览器不重新执行脚本 → boot 不再继续 →
  `state.me` 永远是 null → 紧随的 hashchange → render() → pageSites() 在
  `state.me.is_admin` 上抛 TypeError → 用户看到骨架屏卡死。

  接口全是 200，所以 E2E 看不见；代码里该有的字样都在，所以静态断言看不见。

node 不在时 skip（CI 里可能没有），但**本地必须能跑**——skip 与 pass 要能区分，
所以 skip 理由写明是环境缺 node，不是用例通过。
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PANEL = Path(__file__).parents[1]
HARNESS = Path(__file__).parent / "boot_harness.js"
APP = PANEL / "frontend" / "app.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="环境里没有 node —— 本用例未执行（不是通过）")


def run_boot(scenario: str, app: Path | None = None) -> tuple[int, dict]:
    proc = subprocess.run(
        ["node", str(HARNESS), str(app or APP), scenario],
        capture_output=True, text=True, timeout=60)
    line = (proc.stdout or "").strip().splitlines()
    assert line, f"harness 没有输出 JSON（stderr: {proc.stderr[:400]}）"
    return proc.returncode, json.loads(line[-1])


# ── 正向：两个场景都必须取到身份且不抛 ────────────────────────────────

def test_first_visit_fetches_identity_then_upgrades():
    """首次进入：取身份 → 没有面板会话标记 → 跳 /console-session 升级。"""
    code, out = run_boot("first-visit")
    assert out["fetched_me"], f"首次进入没有请求 /api/me: {out}"
    assert not out["errors"], f"启动时抛异常: {out['errors']}"
    assert any("/console-session" in u for u in out["assigned"]), (
        f"没有跳去升级面板会话: {out['assigned']}")
    assert code == 0


def test_coming_back_from_upgrade_still_loads_identity_and_renders():
    """**回归用例**：从升级跳转回来那一次必须继续走完 boot。

    这是那个真实缺陷的形态。修法有两处，各自都是必需的：
      ① boot() 里恢复 hash 之后**不 return**；
      ② 恢复 hash 用 history.replaceState（不派发 hashchange），
         而不是 location.replace（会派发）。
    """
    code, out = run_boot("came-back")
    assert out["fetched_me"], (
        f"从升级回来后没有请求 /api/me —— boot 提前 return 了: {out}")
    assert not out["errors"], (
        f"从升级回来时抛异常（用户会看到骨架屏卡死）: {out['errors']}")
    assert out["hash_after"] == "#/sites", (
        f"没有回到升级前的位置: {out['hash_after']!r}")
    assert not any("/console-session" in u for u in out["assigned"]), (
        "回来之后又跳了一次升级——无限跳转")
    assert code == 0


def test_coming_back_renders_the_restored_route_not_just_the_default():
    """回到的必须是**升级前那个路由**，而且真的渲染了它。

    只断言 hash 不够：hash 对但没渲染（boot 提前 return）时页面仍是空的。
    这里用"有没有去取该路由的数据"当证据——#/sites 会请求 /api/sites。
    """
    _, out = run_boot("came-back")
    assert any(u.rstrip("/").endswith("/api/sites") or "/api/sites?" in u
               for u in out["fetched"]), (
        f"没有为恢复后的路由取数据，页面会是空的: {out['fetched']}")


# ── 反向：把两处修复分别改回缺陷，必须变红 ────────────────────────────

def _mutated(tmp_path: Path, old: str, new: str) -> Path:
    src = APP.read_text()
    assert old in src, f"注入点找不到（代码改过？）: {old[:60]!r}"
    out = tmp_path / "app.js"
    out.write_text(src.replace(old, new, 1))
    return out


def test_harness_catches_early_return_after_restoring_hash(tmp_path):
    """反向验证 ①：恢复 hash 后提前 return —— 就是原缺陷。

    没有这条，上面的正向用例可能只是"恰好绿"。M3-FINDINGS §2.1 的纪律：
    把要防的缺陷真的注入一次，确认变红。
    """
    app = _mutated(tmp_path,
                   "    restoreAfterUpgrade();      // 只摆正 hash，**不 return**",
                   "    if (restoreAfterUpgrade()) return;")
    code, out = run_boot("came-back", app)
    assert code != 0 and not out["fetched_me"], (
        f"注入了原缺陷但 harness 仍然绿——它什么都没盯: {out}")


def test_harness_catches_hashchange_firing_before_identity_is_loaded(tmp_path):
    """反向验证 ②：用 location.hash 赋值（会派发 hashchange）且去掉 render 兜底。

    这条证明"render() 里的 `if (!state.me) return`"是承重墙而不是装饰：
    去掉它并让 hashchange 在身份到位前触发，必须抛 TypeError。
    """
    src = APP.read_text()
    src = src.replace("      history.replaceState(null, '', back);",
                      "      location.hash = back;", 1)
    assert "  if (!state.me) return;\n  renderNav();" in src, "兜底那行找不到"
    src = src.replace("  if (!state.me) return;\n  renderNav();",
                      "  renderNav();", 1)
    app = tmp_path / "app.js"
    app.write_text(src)
    code, out = run_boot("came-back", app)
    assert code != 0 and out["errors"], (
        f"去掉 state.me 兜底后仍然不抛——那条兜底或本用例是空转的: {out}")


def test_harness_models_hash_assignment_as_firing_hashchange(tmp_path):
    """反向验证 ③：**harness 自身**的建模必须忠于浏览器。

    如果 harness 把"给 location.hash 赋值"建模成不派发 hashchange，那么上面
    那条反向验证会假绿，整组用例的可信度就没了（M3-FINDINGS §2.16：工具本身
    需要被验证）。这里直接断言 harness 源码里两条语义都在。
    """
    h = HARNESS.read_text()
    assert "Object.defineProperty(loc, 'hash'" in h, (
        "harness 没有把 location.hash 建模成 setter —— 赋值不会派发 hashchange，"
        "反向验证 ② 会假绿")
    assert "for (const fn of hashListeners)" in h, "setter 里没有派发 hashchange"
    # 只取 replaceState 的**函数体**（到它自己的右花括号为止）。
    # 固定字符数的窗口会溢出到后面的函数里（第一版取 200 字符，把
    # `addEventListener('hashchange', …)` 也框进来了，于是本用例假红）。
    after = h.split("replaceState(_state, _title, url)", 1)[1]
    body, depth = [], 0
    for ch in after:
        body.append(ch)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
    replace_state = "".join(body)
    assert "hashListeners" not in replace_state, (
        "harness 让 replaceState 也派发了 hashchange —— 与真实浏览器不符，"
        f"会把正确的修复判成缺陷。函数体: {replace_state!r}")
