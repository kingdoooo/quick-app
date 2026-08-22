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
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PANEL = Path(__file__).parents[1]
HARNESS = Path(__file__).parent / "boot_harness.js"
APP = PANEL / "frontend" / "app.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="环境里没有 node —— 本用例未执行（不是通过）")


def run_boot(scenario: str, app: Path | None = None,
             cases: Path | None = None) -> tuple[int, dict]:
    argv = ["node", str(HARNESS), str(app or APP), scenario]
    if cases is not None:
        argv.append(str(cases))     # 只有 report-error 场景认这个参数
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
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


# ── 站点状态文案：DEPLOYING 的两种含义必须分开说 ──────────────────────

def _probe() -> list[dict]:
    code, out = run_boot("probe")
    assert out["cases"], "probe 场景没有产出判定表"
    return out["cases"]


def _case(desc_part: str) -> dict:
    hit = [c for c in _probe() if desc_part in c["desc"]]
    assert len(hit) == 1, f"判定表里找不到唯一匹配 {desc_part!r}"
    return hit[0]


def test_never_live_decision_table_matches_expectations():
    """`site.status == 'DEPLOYING'` 有两种含义，判定表逐行锁定。

    真源侧：status 只有三个写入点（建站 DEPLOYING / mark_job 成功 ACTIVE /
    undeploy DELETED），**没有任何地方把它从 DEPLOYING 改回去**。所以首次部署
    失败的站点永久停在 DEPLOYING。真机上 27 个站点里有 2 个是这样
    （无 route、URL 404）。照字面显示"部署中"会让用户一直等一个不会来的结果。
    """
    for c in _probe():
        assert c["got"] == c["want"], (
            f"{c['desc']}: neverLive={c['got']} 期望 {c['want']}")


def test_a_site_still_deploying_is_not_called_never_live_in_the_ui():
    """**首次部署仍在跑**时不得显示"未上线"、更不得说"失败"。

    这条是判定表发现的我自己的缺陷：neverLive 只判"还没有可访问版本"，
    首次部署进行中同样满足它——若徽章直接按 neverLive 显示，一个正在正常部署
    的站点会被说成未上线/失败。所以文案层还要用 isDeployFailed 分流。
    """
    c = _case("首次部署仍在跑")
    assert c["running"] is True and c["failed"] is False
    assert c["badge_text"] == "部署中", (
        f"正在部署却显示 {c['badge_text']!r} —— 用户会以为部署已经没戏了")
    assert c["callout_has_failed_wording"] is False, "对正在部署的站点说了「失败」"


def test_first_deploy_failure_says_never_live_not_last_deploy_failed():
    """首次部署失败要说"从未成功上线"，**不能**说"最近一次部署失败"。

    后者暗示"原本有个好版本"，而这种站点一次都没成过、URL 是 404。
    我的第一版对两种情况用了同一句话（按重部署那个假设写的）。
    """
    c = _case("首次失败·job 全 FAILED")
    assert c["badge_text"] == "未上线", f"徽章是 {c['badge_text']!r}"
    assert "从未成功上线" in c["hint_text"], f"提示是 {c['hint_text']!r}"
    assert "最近一次部署失败" not in c["hint_text"], (
        "对从未上线的站点说「最近一次部署失败」——暗示存在一个好版本")
    assert c["callout_has_failed_wording"] is True, "该说明失败原因却没说"


def test_redeploy_failure_still_reassures_that_the_old_version_serves():
    """重部署失败要明确"线上仍是上一版"——这才是真源不写 site=FAILED 的原因。"""
    c = _case("重部署失败·曾成功")
    assert c["got"] is False, "曾成功上线过的站点不该被判成「从未上线」"
    assert "线上仍是上一版" in c["hint_text"], f"提示是 {c['hint_text']!r}"


def test_list_page_uses_neutral_wording_because_it_has_no_job_data():
    """列表页拿不到 job，分不出"失败"还是"在跑"，所以只能中性陈述。

    列表接口只返回 site（含后端派生的 ever_live），没有 job。断言失败会在
    "正在首次部署"的站点上说错话，所以文案必须是中性的"未上线"。
    """
    c = _case("首次失败·仅 ever_live")
    assert c["badge_text"] == "未上线"
    assert "失败" not in c["badge_text"], "列表页无 job 数据却断言失败"


# ── API Key 页面：features.api_key 的三态都要真跑一遍 ────────────────────
#
# 为什么这组必须在 harness 里跑而不能只做静态断言：判据是**跑起来做了什么**
# ——零请求 / 发了列表请求 / 渲染出了开关。M3 的教训是"30 条静态断言 + 61/61
# HTTP E2E 全绿，页面仍然崩"，因为缺陷在执行顺序上。这里同形：门禁写成
# `enabled` 时代码里该有的字样一个不少，但"已部署+关闸"这一格会变成空页面。

BANNER = "已被管理员全局关闸"       # 关闸提示的**唯一**特征串（app.js 的常量）
SWITCH_ID = 'id="sw-apikey"'         # admin 开关控件


def test_keys_page_sends_zero_requests_when_component_not_deployed():
    """`deployed=false` → 页面 disabled 且**一个请求都不发**。

    组件没部署时 `site-api-keys` 表不存在，`/api/keys` 会 500；请求它只会把
    "平台没启用这个功能"翻译成一串看不懂的错误。而这个事实 `/api/me` 已经
    给了，不需要再去问。
    """
    code, out = run_boot("keys-admin-undeployed")
    html = out["html"]
    assert not out["errors"], f"未部署态渲染就抛异常: {out['errors']}"
    extra = [u for u in out["fetched"] if "/api/me" not in u]
    assert extra == [], f"deployed=false 时还发了请求: {extra}"
    # 页面自己必须说明原因。**不能只断言 html 里有 aria-disabled**：未部署时
    # 导航项也带 aria-disabled，于是页面压根没渲染时这条依然是绿的（用例只
    # 覆盖了它自己设想的那部分世界）。所以绑到页面独有的那句说明上。
    assert "平台尚未启用 API Key" in html, (
        f"未部署时页面没有说明原因（用户只看到空白）: {html[-400:]!r}")
    assert 'class="card coming-later" aria-disabled="true"' in html, (
        "未部署的卡片缺 aria-disabled —— 只靠视觉变灰对读屏用户等于没禁用")
    assert 'id="key-create"' not in html, "未部署却渲染了创建按钮（点了必报错）"
    assert code == 0


def test_keys_page_is_usable_when_deployed_but_globally_disabled():
    """**部署自锁的闸门**：`deployed=true, enabled=false` 必须是**可用**页面。

    首次部署故意把哨兵行建成 `enabled=false`，所以这一格是部署后的**正常
    状态**。按单布尔（或按 `enabled`）做门禁时：页面 disabled、零请求、开关
    不渲染 —— 管理员无处点开闸，部署流程自锁，而且线上表现是"功能上线了但
    永远打不开"。
    """
    code, out = run_boot("keys-admin-gated")
    html = out["html"]
    assert not out["errors"], f"关闸态渲染抛异常: {out['errors']}"
    assert any("/api/keys" in u for u in out["fetched"]), (
        f"关闸态没去取 Key 列表 —— 页面被门禁挡住了: {out['fetched']}")
    assert 'id="key-create"' in html, "关闸态看不到创建按钮 —— 页面不可用"
    assert not re.search(r'id="key-create"[^>]*\sdisabled', html), (
        "关闸态把创建按钮禁掉了 —— 关闸只影响 Key 能不能调用，不影响管理")
    assert SWITCH_ID in html, (
        "admin 在关闸态看不到开关控件 —— 他没有任何地方能把闸开回来")
    assert BANNER in html, "关闸态没有说明「当前已被管理员全局关闸」"
    assert code == 0


def test_keys_page_renders_and_hides_the_banner_when_fully_enabled():
    """两者都 true：正常页面，且不再显示关闸提示。"""
    code, out = run_boot("keys-admin-live")
    html = out["html"]
    assert not out["errors"], f"正常态渲染抛异常: {out['errors']}"
    assert any("/api/keys" in u for u in out["fetched"])
    assert SWITCH_ID in html, "admin 看不到开关"
    assert BANNER not in html, "开着闸却显示「已被管理员全局关闸」"
    assert code == 0


def test_non_admin_sees_no_switch_and_never_calls_the_admin_only_endpoint():
    """开关只对 admin 渲染；`GET /api/settings/api-key` 也只有 admin 才请求。

    后端 `_require_admin` 会拒（403），所以非 admin 请求它只会在控制台里留一条
    错误；而一个**看得见但一点就 403** 的开关是照着来的 bug 报告。
    """
    code, out = run_boot("keys-user-gated")
    assert not out["errors"], f"非 admin 渲染抛异常: {out['errors']}"
    assert SWITCH_ID not in out["html"], "非 admin 也渲染了平台开关"
    assert not any("/api/settings/api-key" in u for u in out["fetched"]), (
        f"非 admin 请求了 admin 专属端点（必 403）: {out['fetched']}")
    # 页面本身照常可用（关闸不等于对普通人禁用管理界面）
    assert any("/api/keys" in u for u in out["fetched"])
    assert BANNER in out["html"], "普通用户也该知道 Key 此刻调不通"
    assert code == 0


def test_user_supplied_key_name_is_escaped_at_render_time():
    """Key 的备注名是用户填的，进 DOM 前必须转义。

    这条与静态的 esc() 扫描互补：那边依赖扫描器把每一处插值都切对，这边直接
    看渲染出来的字符串——漏了 esc 就会出现可执行的 `<img onerror=...>`。
    """
    _, out = run_boot("keys-user-live")
    html = out["html"]
    assert "&lt;img src=x" in html, (
        "渲染结果里找不到转义后的备注名 —— 列表可能根本没渲染（用例空转）")
    assert "<img src=x" not in html, (
        "Key 备注名未转义就进了 innerHTML —— 控制台里的存储型 XSS")


def test_harness_catches_gating_the_page_on_enabled_instead_of_deployed(tmp_path):
    """反向验证：把门禁判据换成 `enabled` —— 就是部署自锁那个缺陷。

    没有这条，上面"关闸态可用"可能只是恰好绿（比如页面压根没按 features 分支）。
    注入后必须看得见地退化：不取列表、不渲染开关。
    """
    app = _mutated(tmp_path, "if (!feat.deployed) {", "if (!feat.enabled) {")
    _, out = run_boot("keys-admin-gated", app)
    assert not any("/api/keys" in u for u in out["fetched"]) \
        and SWITCH_ID not in out["html"], (
        "把门禁换成 enabled 之后页面居然还可用 —— 说明上面那条正向用例"
        f"没盯住任何东西: {out['fetched']}")


def test_frontend_falls_back_to_jobs_when_backend_omits_ever_live():
    """后端漏给 `ever_live` 时用 job 历史兜底，不误报"未上线"。

    两个来源不一致时取更保守的那个，但"job 里明明有 SUCCEEDED"是强证据——
    站点确实上线过，此时不能因为字段缺失就说它没上线。
    """
    c = _case("后端漏给 ever_live 但 job 成功过")
    assert c["got"] is False, "字段缺失导致误报「从未上线」"


# ── 访问统计页：三条渲染路径都要真跑一遍（M5 Task 9）─────────────────────
#
# 为什么这组必须在 harness 里：`renderAnalyticsTab` 的成功 / 空态 / 失败三条路径
# 此前**在任何地方都没有执行过**。静态断言（test_frontend_contract）只能证明源码
# 里"提到了" uv_exact、"提到了" catch —— 而本项目栽过的正是这个形态
# （"30 条静态断言 + 61/61 HTTP E2E 全绿，页面仍然崩"，见本文件顶部那段）。
#
# 判据一律取**最后一次** innerHTML 写入（`html_writes[-1]`）而不是 `html`：
# 后者是所有写入的并集，"加载中…"的占位与上一次渲染都还在里面，在它上面断言
# "页面上没有 X"是不精确的。三态的判据恰恰全是"最终渲染出了什么"。

UV_NOTE = "该区间已超出 90 天明细留存窗口"     # uvCell 标注分支的唯一特征串
ERR_SENTINEL = "PROBE-E500-SENTINEL"           # harness 注入的 500 错误文案


def _last_write(scenario: str, app: Path | None = None) -> tuple[dict, str]:
    _, out = run_boot(scenario, app)
    writes = out["html_writes"]
    assert writes, f"一次 innerHTML 写入都没有 —— 场景 {scenario} 空转了"
    return out, writes[-1]


def test_analytics_page_renders_both_tables_from_live_data():
    """正向：两个端点都有数据 → 趋势表与明细表都渲染出来，且不抛异常。

    同时钉住**请求参数**：页面固定要近 30 天的日桶与近 7 天的明细，参数漂了
    （比如 n 变成 7）用户看到的时间范围就和标题写的不一样，而两侧单测都不会红。
    """
    out, last = _last_write("analytics-live")
    assert not out["errors"], f"统计页渲染时抛异常: {out['errors']}"
    assert "/api/sites/s-probe/analytics?period=day&n=30" in out["fetched"], (
        f"趋势请求的参数不对（标题说近 30 天）: {out['fetched']}")
    assert "/api/sites/s-probe/visitors?days=7&limit=50" in out["fetched"], (
        f"明细请求的参数不对（标题说近 7 天）: {out['fetched']}")
    assert "访问趋势" in last and "访问明细" in last, f"两张表没都渲染: {last[:300]!r}"
    # 数据真的落进了单元格（不是渲染了两张空表）
    assert "2026-08-12" in last and "1,234" in last, (
        f"趋势表里看不到夹具数据 —— 表渲染了但没填数: {last[:400]!r}")
    assert last.count("<tr>") >= 6, (
        f"行数不对（3 个桶 + 3 条明细 + 2 个表头）: {last.count('<tr>')}")


def test_analytics_translates_every_decision_and_names_anonymous_visitors():
    """三个 decision 都要翻成人话；`email` 空串必须显示成"（未登录）"。

    这是 DECISION_LABEL 存在的全部意义。缺词条时用户看到的是 `denied_403`；
    而空串照原样渲染就是一个**空白格**——看起来像数据丢了，实际是未登录访问。
    """
    _, last = _last_write("analytics-live")
    for label in ("放行", "不在名单", "未登录"):
        assert label in last, f"decision 词表缺 {label}（会显示原始英文串）"
    assert "（未登录）" in last, (
        "email 为空串的行没有显示「（未登录）」—— 那一格会是空白，"
        "读起来像数据丢失（Edge 的 redirect_login 契约就是给空串）")
    assert "denied_403" not in last and "redirect_login" not in last, (
        f"页面上出现了原始 decision 值: {last!r}")


def test_analytics_annotates_the_inexact_uv_bucket_instead_of_printing_null():
    """`uv_exact: false` / `uv: null` 的桶渲染成标注，**不是** null 也不是 0。

    这条是 uvCell 那个分支唯一真跑一遍的地方。静态断言只查了源码里有
    "uv_exact"这个词——它证明不了渲染结果。
    """
    _, last = _last_write("analytics-live")
    assert UV_NOTE in last, f"超窗口的桶没有标注: {last!r}"
    assert "null" not in last, (
        f"页面上出现了 null —— uv 为 null 的桶被直接拼进了 HTML: {last!r}")
    # 标注必须落在**那一个**桶上（而不是标错行），也不能被 `|| 0` 兜成数字
    inexact_row = last.split("2026-08-14")[1].split("</tr>")[0]
    assert UV_NOTE in inexact_row, (
        f"标注不在超窗口那一行里（标到别的桶上了）: {inexact_row!r}")


def test_analytics_empty_visitor_list_says_so_instead_of_an_empty_table():
    """空态：明细为空时给一句话，而不是一张只有表头的表。

    **两张表分别为空**是有意的夹具设计（趋势有数据、明细没有）：一起空的话
    分不出是哪一半的空态写错了，而"0 次访问"与"读取失败"在用户那边完全不同。
    """
    out, last = _last_write("analytics-empty")
    assert not out["errors"], f"空态渲染抛异常: {out['errors']}"
    assert "近 7 天没有访问记录" in last, f"明细空态没有说明: {last!r}"
    # 趋势表照常渲染 —— 证明空态是**局部**的，不是整页退化
    assert "1,234" in last, "趋势表跟着一起空了 —— 空态判据串到了另一半"
    assert last.count("<table") == 1, (
        "明细空态仍然渲染了一张表（只有表头的表读起来像加载失败）: "
        f"{last.count('<table')} 张表")


def test_analytics_shows_the_error_instead_of_half_a_page_when_one_call_fails():
    """失败态：两个请求里任一失败 → 整屏报错，**不渲染半张页面**。

    半屏（趋势画出来了、明细没有且不说原因）比整屏报错更难排查：用户以为
    "这个站点没有访客明细"，而真相是那次请求 500 了。
    """
    out, last = _last_write("analytics-failed")
    assert not out["errors"], (
        f"失败态把异常漏出去了（catch 没接住）: {out['errors']}")
    assert "访问统计读取失败" in last, f"失败态没有报错文案: {last!r}"
    assert ERR_SENTINEL in last, (
        "后端给的错误原文没显示出来 —— 用户只看到一句通用的「读取失败」，"
        f"排查时问不出是 403 还是 500: {last!r}")
    assert "访问趋势" not in last and "访问明细" not in last, (
        f"失败时仍然渲染了半张页面: {last!r}")


def test_visitor_supplied_path_is_escaped_at_render_time():
    """`path` 是**匿名访问者可控**的，渲染前必须转义。

    攻击面是真的：任何人 curl 一个带 HTML 元字符的路径 → Edge 原样写进 events
    表 → 它出现在**站点所有者的控制台**里，而控制台是能改权限的管理界面。
    与静态的 esc() 扫描互补：那边依赖扫描器把每一处插值都切对
    （而它的覆盖面还挂在循环变量名上），这边直接看渲染出来的字符串。
    """
    _, last = _last_write("analytics-live")
    # 顺序有意：**先**断言原始形态不在（那是安全结论），再断言转义形态在
    # （那是"本用例没空转"）。反过来写的话，路径没转义时先红的是后者，
    # 而它的失败文案说的是"表可能没渲染"——把 XSS 报成解析问题。
    assert "<img src=x" not in last, (
        f"访问路径未转义就进了 innerHTML —— 匿名访问者可写的控制台 XSS: {last!r}")
    assert "&lt;img src=x" in last, (
        "渲染结果里找不到转义后的路径 —— 明细表可能根本没渲染（用例空转）")


def test_danger_zone_stays_off_non_overview_tabs():
    """危险区域只属于概览：访问统计页的**任何一次**渲染都不得带下线按钮。

    回归背景：它原先拼在 tab 外壳上（tabpanel 外面），四个 tab 每屏都拖着
    两个破坏性按钮。绝对断言配正向对照——dangerZone 必须仍在 overview 的
    渲染路径里，否则"到处都没有"也能让本用例假绿。
    """
    out, _ = _last_write("analytics-live")
    for html in out["html_writes"]:
        assert "危险区域" not in html and "purge-btn" not in html, (
            "危险区域渲染到了访问统计页 —— 它挂回 tab 外壳上了")
    src = APP.read_text(encoding="utf-8")
    m = re.search(r"function renderOverviewTab[\s\S]*?\n\}", src)
    assert m and "dangerZone(site)" in m.group(0), (
        "正向对照失败：renderOverviewTab 里找不到 dangerZone —— "
        "上面的绝对断言可能因功能整体消失而假绿")


def test_analytics_defaults_to_a_chart_and_keeps_the_table_view():
    """趋势卡默认渲染 SVG 折线图，同时**表格仍在 DOM 里**（默认 hidden）。

    表格不是装饰：aqua series 对白底 2.82:1（<3:1），色彩规范要求的缓解通道
    就是"可达的表格视图"。图表替代表格 = 把缓解通道一起删掉。
    三条序列各自的 polyline 带 data-series，图例文字与色标分离（文字不穿
    序列色，身份靠旁边的色块线）。
    """
    _, last = _last_write("analytics-live")
    assert "<svg" in last, f"默认视图不是图表: {last[:300]!r}"
    for s in ("pv", "uv", "denied"):
        assert f'data-series="{s}"' in last, f"缺 {s} 序列的折线"
    for label in ("PV", "独立访客", "被拒"):
        assert label in last, f"图例缺 {label}（≥2 序列必须有图例）"
    assert "<table" in last, "表格视图从 DOM 里消失了 —— 低对比序列失去缓解通道"
    assert "折线图" in last and "表格" in last, "找不到 折线图/表格 视图切换"


def test_analytics_trend_table_is_newest_first():
    """趋势表格倒序：最近的日期在最前面（图表仍按时间轴正序画）。

    只在**趋势表**范围内断言——访问明细的 ts 也含 2026-08-14，整页 find
    会两处都命中，表格没倒序时用例照样绿（字样碰撞假绿，与 ERR_SENTINEL
    的教训同族）。
    """
    _, last = _last_write("analytics-live")
    m = re.search(r'trend-table[\s\S]*?</table>', last)
    assert m, "找不到趋势表容器（trend-table）"
    tbl = m.group(0)
    assert tbl.find("2026-08-14") < tbl.find("2026-08-12") != -1, (
        "趋势表不是倒序 —— 最近的日期应该在最前面")


def test_analytics_uv_gap_is_a_break_not_a_zero():
    """uv 为 null 的桶在折线图上是**断线**，不是画成 0。

    表格里那格是「—」标注（uvCell），图上等价的语义是缺口：夹具 3 个桶里
    uv 只有 2 个非空值 → uv 恰好 2 个数据点，pv 3 个。null 被 Number()
    成 0 或 NaN 进坐标的话，点数会是 3 或者产物里出现 NaN。
    """
    _, last = _last_write("analytics-live")
    assert "NaN" not in last, "SVG 坐标里出现 NaN —— null 进了数值管道"
    uv_dots = len(re.findall(r'class="trend-dot[^"]*" data-series="uv"', last))
    pv_dots = len(re.findall(r'class="trend-dot[^"]*" data-series="pv"', last))
    assert pv_dots == 3, f"pv 应有 3 个数据点，实际 {pv_dots}"
    assert uv_dots == 2, (
        f"uv 应恰好 2 个数据点（null 桶断线），实际 {uv_dots} —— "
        "3 说明 null 被画成了 0")


def test_analytics_range_presets_pin_their_query_params():
    """时间档位以 data-q 携带**真实查询参数**，点击处理器只读这个属性。

    渲染出的 data-q 就是发出去的参数（单一真源）——断言它等于断言换档后
    的请求形态，harness 不用真点按钮。默认档（近 30 天）要有选中态。
    """
    _, last = _last_write("analytics-live")
    for q, label in (("period=day&n=7", "近 7 天"), ("period=day&n=30", "近 30 天"),
                     ("period=day&n=90", "近 90 天"), ("period=month&n=12", "近 12 个月")):
        assert f'data-q="{q}"' in last, f"缺时间档位 {label}（data-q={q}）"
        assert label in last, f"缺时间档位文字 {label}"
    m = re.search(r'<button[^>]*data-q="period=day&n=30"[^>]*>', last)
    assert m and 'aria-pressed="true"' in m.group(0), (
        "默认档「近 30 天」没有选中态（aria-pressed）")


# ── 反向验证：把三条路径各自的实现改坏，必须变红 ──────────────────────
#
# 用 `_mutated`（写一份改坏的 app.js 到 tmp_path）而不是改仓库里的 app.js：
# 被测文件从头到尾没被动过，也就没有"还原漏了"的风险。

def test_harness_catches_uv_cell_fabricating_a_zero(tmp_path):
    """反向 ①：uvCell 不再看 uv_exact → 那一格变成**凭空的 0**。

    **实测修正过预期**：我原本以为退化形态是"页面显示 null"，注入后实际渲染的是
    `0` —— 因为 fallthrough 走的是 `esc(fmt(row.uv))`，而 `fmt` 是
    `Number(n).toLocaleString()`，`Number(null)` 就是 0。也就是说这个实现的退化
    方向正好是两种里**更糟的那个**：null 至少看得出是 bug，一个 0 会被读成
    "这段时间没有独立访客"，而真相是"我们不知道"。
    所以断言绑到"那一行的 UV 格是 0"，不是绑到 "null" 这个字样。
    """
    app = _mutated(
        tmp_path,
        "  if (row.uv_exact === false || row.uv === null || row.uv === undefined) {",
        "  if (false) {")
    _, last = _last_write("analytics-live", app)
    assert UV_NOTE not in last, (
        f"注入了「不看 uv_exact」但标注还在 —— 注入点没生效: {last!r}")
    inexact_row = last.split("2026-08-14")[1].split("</tr>")[0]
    assert '<td class="num-col">0</td>' in inexact_row, (
        "预期那一格退化成凭空的 0（fmt(null) === '0'），实际不是 —— "
        f"上面那条正向用例可能没盯住东西: {inexact_row!r}")


def test_harness_catches_a_missing_catch_on_the_analytics_promise(tmp_path):
    """反向 ②：把 `.catch(...)` 换成 `.then(...)` → 失败态变成未捕获的 rejection。

    这条证明"失败态显示错误"不是恰好绿：没有 catch 时页面**停在"正在加载…"**，
    错误只出现在 DevTools 里——用户看到一个永远转不完的加载态。
    """
    app = _mutated(tmp_path, "  }).catch((err) => {", "  }).then((err) => {")
    out, last = _last_write("analytics-failed", app)
    assert out["errors"], (
        "去掉 catch 之后居然没有未捕获的 rejection —— 失败态那条正向用例"
        f"证明不了 catch 是承重墙: {out}")
    assert "正在加载访问统计" in last, (
        f"页面没有停在加载态（预期：错误没人接手，占位一直留着）: {last!r}")


def test_harness_catches_the_empty_state_rendering_a_headers_only_table(tmp_path):
    """反向 ③：去掉明细的空态守卫 → 落到建表分支，渲染出一张只有表头的表。

    注入的是**守卫条件**而不是它的返回值：第一版把 `return '<p>…'` 换成
    `return ''`，那只是"空态什么都不说"（渲染出一张空卡片），并没有产生要防的
    那个形态。改成让守卫永不成立，代码才真的落进建表分支——一张有表头、
    `<tbody>` 为空的表，读起来像"加载失败"。
    """
    app = _mutated(tmp_path, "  if (!rows.length) {", "  if (false) {")
    _, last = _last_write("analytics-empty", app)
    assert "近 7 天没有访问记录" not in last, "注入点没生效（空态文案还在）"
    assert last.count("<table") == 2, (
        f"预期渲染出两张表（第二张只有表头），实际 {last.count('<table')} 张: {last!r}")
    assert "<tbody></tbody>" in last, (
        f"第二张表的 tbody 不是空的 —— 注入的退化形态与预期不同: {last!r}")


# ── 站点列表的 PV 迷你趋势：真渲染一遍（M5 Task 9b）─────────────────────
#
# 静态侧只有一条 `"max === 0" in blob`。它便宜，但**证不了正确性**
# （M5-FINDINGS §4.8）：那个字样在源码里，函数却可能压根没人调用；全 0 的站点
# 真渲染出什么坐标，只有跑一遍才知道。这一组就是跑一遍。

def _cards(scenario: str, app: Path | None = None) -> tuple[dict, str]:
    out, last = _last_write(scenario, app)
    assert "site-card" in last, (
        f"最后一次渲染里没有站点卡片 —— 场景 {scenario} 空转了: {last[:300]!r}")
    return out, last


def _card_of(html: str, site_id: str) -> str:
    """只取某一张卡片的 HTML。

    不按 polyline 出现的顺序取：顺序对了也可能是"两张卡片画了同一份数据"，
    而按 site_id 定位能让"标错卡片"这种缺陷显出来。
    """
    marker = 'href="#/sites/' + site_id + '"'
    assert marker in html, f"渲染结果里没有 {site_id} 这张卡片"
    return html.split(marker, 1)[1].split("</a>", 1)[0]


COORD = re.compile(r"^\d+(?:\.\d+)?,\d+(?:\.\d+)?$")


def _points(card: str) -> list[str]:
    m = re.search(r'<polyline points="([^"]*)"', card)
    assert m, f"这张卡片里没有 sparkline 的 polyline: {card[:300]!r}"
    return m.group(1).split(" ")


def test_site_list_draws_one_sparkline_per_card_from_pv7():
    """正向：每张卡片一条趋势线，画的是 pv7 里的数（不是一条恒定平线）。"""
    out, last = _cards("sites-list")
    assert not out["errors"], f"站点列表渲染时抛异常: {out['errors']}"
    assert last.count('class="spark"') == 2, (
        f"两个站点却画了 {last.count('class=\"spark\"')} 条趋势线")
    pts = _points(_card_of(last, "s-busy"))
    assert len(pts) == 7, f"pv7 有 7 个点，画出来 {len(pts)} 个: {pts}"
    ys = {p.split(",")[1] for p in pts}
    assert len(ys) > 1, (
        f"有访问量的站点画成了平线 —— 数据没进坐标: {pts}")
    # 总数也要是真数（S_BUSY 之和 = 56），否则"画了线但读的是别的数组"看不出来
    assert "近 7 天 56 PV" in _card_of(last, "s-busy"), (
        f"卡片上的近 7 天总数不对: {_card_of(last, 's-busy')[-200:]!r}")


def test_all_zero_pv7_renders_a_flat_line_not_nan_coordinates():
    """**除零那条路径**：全 0 的站点必须画出一条合法的平线。

    `max` 为 0 时 `v / max` 是 `0/0 = NaN`，`NaN.toFixed(1)` 是字符串 `'NaN'`
    —— 它会原样进 `points` 属性，浏览器把整条 polyline 判为非法后**什么都不画**
    （不是画错，是消失），而控制台里不会有任何报错。所以断言的是坐标本身合法，
    不是"页面没崩"。
    """
    out, last = _cards("sites-list")
    assert not out["errors"], f"全 0 的站点渲染时抛异常: {out['errors']}"
    card = _card_of(last, "s-quiet")
    pts = _points(card)
    assert len(pts) == 7, f"全 0 的站点画出 {len(pts)} 个点: {pts}"
    assert all(COORD.match(p) for p in pts), (
        f"全 0 的站点产出了非法坐标（NaN / 空 / 残缺）: {pts}")
    assert len({p.split(",")[1] for p in pts}) == 1, (
        f"全 0 却不是平线: {pts}")
    assert "近 7 天 0 PV" in card, (
        "全 0 的卡片没有明说「0 PV」—— 0 次访问是一个事实，不该看起来像没数据")
    assert "NaN" not in last, f"整页渲染里出现了 NaN: {last!r}"


PLACEHOLDER = "访问趋势暂时读不到"      # 形状守卫的占位（app.js 里的唯一特征串）


def test_sparkline_cannot_emit_a_string_its_caller_passed_in():
    """`sparkline(` 被登记进 XSS 扫描的 SAFE_WRAPPERS —— 这里证明那条豁免成立。

    不证明就是循环论证：静态扫描靠"这个函数产不出调用方的字符串"豁免了
    `sparkline(item.pv7)` 这个插值点，那么这个前提本身必须被盯住（同
    test_frontend_contract 里 toast/openModal 的那条）。

    pv7 的值域由后端契约保证是整数，所以这一格**不是**真实攻击面的建模，而是
    豁免前提的实证：塞一个可执行串进去，产物里不得出现标签。

    **两层挡着它，顺序要说清**：形状守卫（`Number.isFinite`）先把非数字整个挡掉，
    `fmt()` 是第二层（`reduce` 的加法对字符串是拼接，`0 + '<img …>'` 就是那个串）。
    所以本用例观察到的是守卫的效果；`fmt` 那一层由
    test_harness_catches_the_total_not_going_through_fmt 用**复合注入**证明
    ——单独去掉 fmt 时守卫仍然挡住，这正说明它是"深度"而不是唯一防线。
    """
    _, last = _cards("sites-list-unknown")
    card = _card_of(last, "s-hostile")
    assert "<img src=x" not in last, (
        f"pv7 里的可执行串原样进了 innerHTML —— SAFE_WRAPPERS 那条豁免是错的: {last!r}")
    # 正对照：这张卡片确实渲染了、且走到了守卫（不是"场景空转"）
    assert PLACEHOLDER in card, (
        f"污染值那张卡片没有占位 —— 本用例可能空转: {card[-300:]!r}")
    assert "<polyline" not in card, f"非数字的 pv7 居然画出了线: {card!r}"


def test_unknown_or_malformed_pv7_draws_nothing_instead_of_a_wrong_line():
    """后端给"未知"（`[]`）、长度不对、或压根没给这个字段时：**什么都不画**。

    判别力是这条的全部意义，逐个说明退化形态（都实测过，见反向那两条）：
      · `[]` —— 后端 `_pv7_or_unknown` 的降级值。**不能兜成 `[0]*7`**：那是一条
        与"真的零访问"无法区分的平线，也就是一句假数据（同 uv_exact 的口径）。
        没有守卫时它会被画成"近 7 天 0 PV"，比不画更糟；
      · `[1,2,3]` —— 没有守卫时画出一张**看起来像真数据的错图**（3 个点铺满整宽，
        标"近 7 天 6 PV"），界面上完全看不出是错的；
      · 字段缺失 —— 后端回滚 / 前端先上线。没有守卫时 `undefined` 进不了
        `.length`，**整个站点列表崩掉**。
    """
    out, last = _cards("sites-list-unknown")
    assert not out["errors"], f"降级形状渲染时抛异常: {out['errors']}"
    for site_id in ("s-unknown", "s-short", "s-hostile"):
        card = _card_of(last, site_id)
        assert PLACEHOLDER in card, f"{site_id} 没有显示「读不到」占位: {card!r}"
        assert "<polyline" not in card, f"{site_id} 画出了趋势线: {card!r}"
        assert "近 7 天" not in card, (
            f"{site_id} 仍然报了一个总数 —— 读不到就不该给数字: {card!r}")
    assert 'class="spark"' not in last, "降级形状里画出了 svg 趋势线"
    assert "NaN" not in last, f"页面上出现了 NaN: {last!r}"

    # 字段整个缺失的那一格单独一个场景（去掉守卫时它崩整页，混在一起看不到上面
    # 三种图形），但**必须一样什么都不画**
    out2, last2 = _cards("sites-list-missing")
    assert not out2["errors"], (
        f"后端没给 pv7 时渲染抛异常 —— 守卫没接住 undefined: {out2['errors']}")
    assert PLACEHOLDER in _card_of(last2, "s-missing"), "字段缺失没有走占位"
    assert "<polyline" not in last2 and "NaN" not in last2


# ── 反向验证：把迷你趋势的三处实现分别改坏 ──────────────────────────────

def test_harness_catches_removing_the_all_zero_guard(tmp_path):
    """反向 ①：去掉 `max === 0` 分支 —— 全 0 的站点产出 NaN 坐标。

    这条是上面那条行为断言的存在理由。静态侧那条 `"max === 0" in blob` 注入后
    同样会红，但它红的是"字样不见了"；只有这条能说出**渲染结果**坏成了什么。
    """
    app = _mutated(tmp_path,
                   "    var y = max === 0 ? h - 1 : h - 1 - (v / max) * (h - 2);",
                   "    var y = h - 1 - (v / max) * (h - 2);")
    _, last = _cards("sites-list", app)
    pts = _points(_card_of(last, "s-quiet"))
    assert not all(COORD.match(p) for p in pts), (
        f"去掉除零分支后坐标居然还是合法的 —— 那条正向断言没盯住东西: {pts}")
    assert "NaN" in last, f"预期出现 NaN 坐标，实际: {pts}"


def test_harness_catches_the_card_never_calling_sparkline(tmp_path):
    """反向 ②：`siteCard` 不再调 `sparkline` —— 函数还在，卡片上什么都没有。

    这是"存在性检查从写下那天起就是死的"那个形态：静态侧的
    `"max === 0" in blob` 在这个注入下**照样是绿的**（源码里那行还在），
    而用户一条趋势线也看不到。

    注入点带上整行而不是只写 `sparkline(item.pv7)`：那个片段在 app.js 里出现
    两次（调用点，以及**说明它为什么必须留在这一行的那句注释**），而
    `_mutated` 只替换第一处 —— 于是被改掉的是注释，页面照旧渲染，本用例第一版
    因此假红。真实踩到过，写在这里以免有人"简化"回去。
    """
    app = _mutated(
        tmp_path,
        "'<div class=\"row\" style=\"margin-top:12px\">' + sparkline(item.pv7)",
        "'<div class=\"row\" style=\"margin-top:12px\">' + ''")
    _, last = _cards("sites-list", app)
    assert 'class="spark"' not in last, (
        "去掉调用之后页面上仍然有趋势线 —— 注入点没生效")
    # 同时说明静态那条为什么不够：它在这个注入下仍然绿
    assert "max === 0" in app.read_text(), (
        "本注入不该动 sparkline 的实现（否则证不了静态断言的盲区）")


GUARD = "  if (!ok) {"           # sparkline 的形状守卫（恰好 7 个有限数字）
FMT_TOTAL = "    fmt(pv7.reduce(function (a, b) { return a + b; }, 0)) +"


def _mutated_all(tmp_path: Path, *pairs: tuple[str, str]) -> Path:
    """多处注入。防御**层次**的验证需要同时拆掉两层，单处注入证不了。

    比 `_mutated` 多一条 `count == 1`：文本锚点必须在全文件唯一，而"解释这行
    代码"的注释天生会破坏唯一性（本 Task 真踩过——注入改掉的是注释而不是代码，
    页面照旧渲染，用例假红）。把这条断言写在这里，下一次会红在注入点上而不是
    红在一句不相干的断言上。
    """
    src = APP.read_text()
    for old, new in pairs:
        assert src.count(old) == 1, (
            f"注入点在全文件里出现 {src.count(old)} 次（0=代码改过，"
            f">1=有注释抄了它）: {old[:60]!r}")
        src = src.replace(old, new, 1)
    out = tmp_path / "app.js"
    out.parent.mkdir(parents=True, exist_ok=True)   # 同一条用例要两份注入版本
    out.write_text(src)
    return out


def test_harness_catches_removing_the_shape_guard(tmp_path):
    """反向 ③：去掉形状守卫 —— 三种降级形状各自坏成什么样，逐个钉住。

    实测过的退化形态（不是推测）：`[]` → `近 7 天 0 PV` 的空线（**凭空的 0**，
    正是"平的 0 线是假数据"那条要防的）；`[1,2,3]` → 3 个点铺满整宽的错图，
    标"近 7 天 6 PV"；污染值 → 一串 NaN 坐标。
    """
    app = _mutated_all(tmp_path, (GUARD, "  if (false) {"))
    _, last = _cards("sites-list-unknown", app)
    short = _card_of(last, "s-short")
    assert len(_points(short)) == 3, (
        f"预期长度不对的 pv7 被画成 3 个点的错图，实际: {_points(short)}")
    assert "近 7 天 6 PV" in short, f"错图没有配一个错总数: {short!r}"
    assert "近 7 天 0 PV" in _card_of(last, "s-unknown"), (
        "「未知」没有退化成凭空的 0 —— 那条正向断言可能没盯住东西")
    assert "NaN" in _card_of(last, "s-hostile"), "污染值没有退化成 NaN 坐标"


def test_harness_catches_the_guard_not_covering_a_missing_field(tmp_path):
    """反向 ④：守卫去掉后，后端**没给** pv7 会崩掉整个站点列表。

    这是本轮最该防的形态：它不是"少一条趋势线"，而是首页整屏挂掉——而后端
    回滚、或前端先上线，都会造出这一格。
    """
    app = _mutated_all(tmp_path, (GUARD, "  if (false) {"))
    code, out = run_boot("sites-list-missing", app)
    assert out["errors"] and code != 0, (
        f"字段缺失且无守卫却没崩 —— 说明这个场景没渲染卡片（空转）: {out}")
    assert any("undefined" in e for e in out["errors"]), (
        f"崩的原因不是 undefined —— 与预期的退化形态不同: {out['errors']}")


def test_harness_catches_the_total_not_going_through_fmt(tmp_path):
    """反向 ⑤：**复合注入**——同时拆掉形状守卫与 `fmt()`，可执行串才进 HTML。

    为什么必须是复合：`fmt` 是第二层。单独去掉它，形状守卫仍然把非数字整个挡在
    外面（实测：`<img src=x` 不出现），于是"单处注入"会得出"fmt 无所谓"的错
    结论。两层一起拆掉时实测渲染出
    `近 7 天 0<img src=x onerror=alert(1)>000000 PV` —— 也就是说一旦哪天有人放宽
    守卫（比如只判长度不判类型），`fmt` 就是 pv7 与 innerHTML 之间**唯一**的东西。
    """
    only_fmt = _mutated_all(
        tmp_path / "a",
        (FMT_TOTAL, "    pv7.reduce(function (a, b) { return a + b; }, 0) +"))
    _, last = _cards("sites-list-unknown", only_fmt)
    assert "<img src=x" not in last, (
        "只去掉 fmt 就注入成功了 —— 那说明形状守卫没在挡非数字，"
        f"上面那条正向断言的结论是错的: {last!r}")

    both = _mutated_all(
        tmp_path / "b",
        (GUARD, "  if (false) {"),
        (FMT_TOTAL, "    pv7.reduce(function (a, b) { return a + b; }, 0) +"))
    _, last2 = _cards("sites-list-unknown", both)
    assert "<img src=x" in last2, (
        "两层都拆了可执行串仍然没进 HTML —— 那 fmt 那条豁免证明是空转的")


def test_harness_catches_the_tab_not_being_handed_the_site(tmp_path):
    """反向 ④：调用点退回 `renderAnalyticsTab(panel)` → 页面直接崩。

    这是 Task 9 改的那一行。没有这条时，"两张表渲染出来了"可能只是因为
    harness 恰好没走到这个分支。
    """
    app = _mutated(
        tmp_path,
        "  else if (tab === 'analytics') renderAnalyticsTab(panel, site);",
        "  else if (tab === 'analytics') renderAnalyticsTab(panel);")
    code, out = run_boot("analytics-live", app)
    assert out["errors"] and code != 0, (
        f"不传 site 也没崩 —— 说明统计页压根没被渲染（用例空转）: {out}")


# ── 409 的下一步提示必须按错误类型分开（S1 / M02）─────────────────────
#
# reportError 原来对**所有** 409 追加"（刷新后重试即可）"。坏策略数据
# （PolicyDataInvalid → 409）刷新一万次都不会变，而"字段缺失"那支要的动作是
# **部署一次**——后端把修法写进文案是 spec §4.1 接受"拒绝"这个代价的唯一前提，
# UI 追加一句反向指示等于把它抵消掉。判据用后端给的 `code`，不去猜正文里的字。

RETRY_HINT = "刷新后重试即可"          # reportError 追加的那句（唯一特征串）


def _report_error_cases() -> dict:
    code, out = run_boot("report-error")
    assert code == 0, f"report-error 场景自身抛异常: {out}"
    return {c["name"]: c["toast"] for c in out["cases"]}


def test_policy_data_409_does_not_tell_the_user_to_refresh_and_retry():
    """坏数据 409：文案原样显示，**不**追加"刷新后重试即可"。"""
    cases = _report_error_cases()
    assert "BAD-DATA-SENTINEL" in cases["policy-409"], (
        f"后端文案没到页面上——那是这条修复唯一的价值: {cases['policy-409']}")
    assert RETRY_HINT not in cases["policy-409"], (
        f"对坏数据说「刷新后重试即可」——刷新永远修不好它: {cases['policy-409']}")


def test_a_real_conflict_409_still_tells_the_user_to_retry():
    """**对照**：并发冲突那条必须还留着提示。

    没有这条时，"整段追加逻辑被删掉"与"只对坏数据跳过"无法区分——而前者会把
    一个该重试的提示也一起删掉（那才是 409 最常见的那一类）。
    """
    cases = _report_error_cases()
    assert RETRY_HINT in cases["conflict-409"], (
        f"并发冲突不再提示重试，追加逻辑被整段删了: {cases['conflict-409']}")
    assert "CONFLICT-SENTINEL" in cases["conflict-409"]


def test_403_is_untouched_by_the_code_branch():
    cases = _report_error_cases()
    assert cases["denied-403"].count("DENIED-SENTINEL") == 1
    assert RETRY_HINT not in cases["denied-403"]


def test_harness_catches_the_hint_being_appended_to_bad_data_again(tmp_path):
    """反向验证：把判据去掉（退回"所有 409 都追加"）必须变红。

    没有这条，上面那两条可能只是因为 harness 压根没跑到 reportError。
    """
    # 只改**比较那一处**，不改常量声明（连声明一起换会造出
    # `const 'x' = …` 的语法错，那时红的是解析而不是被测行为——假红）
    old = "err.payload.code === POLICY_DATA_INVALID_CODE"
    src = APP.read_text()
    assert old in src, f"注入点找不到（代码改过？）: {old}"
    out = tmp_path / "app.js"
    # 让判据恒不成立 ⇒ 坏数据又落回"追加提示"那一支
    out.write_text(src.replace(old, "err.payload.code === 'never-matches'", 1))
    code, res = run_boot("report-error", out)
    assert code == 0, res
    cases = {c["name"]: c["toast"] for c in res["cases"]}
    assert RETRY_HINT in cases["policy-409"], (
        f"注入了原缺陷但 harness 仍然绿——它什么都没盯: {cases}")


# ── 跨层绑定：后端**真正生成的**两段文案，逐字渲染到 toast 上 ─────────────
#
# 上面那三条用哨兵串，证明的是"追加的那句在不在"。这一条不同：它把
# `permissions.effective_policy` 真正抛出的文案灌进前端，断言用户读到的就是
# 那段**能照着做**的字。两个分支的修法相反（缺字段 ⇒ 部署一次；类型不对 ⇒
# 改那一行），所以各断言"有自己那句"且"没有另一句"——把两句合成一句大杂烩、
# 或者把 UI 的建议盖在上面，都会在这里红。
#
# **前端不许自己拥有"修法"的措辞**：断言方向是"后端那段字原样出现在 toast 上"，
# 而不是"toast 上有某句关于修法的话"。前者做不到时只能去改后端文案（唯一真源），
# 后者会诱使人在 app.js 里补一句自己的建议——那就是第五份拷贝。

def _permissions():
    """本文件不靠 conftest 的 sys.path（它跑的是 node，不需要 AWS 夹具）。"""
    import sys
    sys.path.insert(0, str(PANEL))
    sys.path.insert(0, str(PANEL.parent / "deployer" / "functions"))
    import permissions
    return permissions


def _real_policy_messages() -> dict[str, str]:
    """从**真源**取两段文案（不手抄）：effective_policy 自己抛出来的那两句。"""
    permissions = _permissions()

    ok = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
          "allowed_users": "org", "collaborators": []}
    out = {}
    for name, site in (("absent", {**ok}), ("wrong-typed", {**ok})):
        if name == "absent":
            del site["require_login"]           # 从没成功部署过的行
        else:
            site["require_login"] = 0           # 那一行存着个用不了的值
        try:
            permissions.effective_policy(site)
        except permissions.PolicyDataInvalid as e:
            out[name] = str(e)
    assert set(out) == {"absent", "wrong-typed"}, out
    return out


def _render_real_messages(tmp_path: Path, app: Path | None = None) -> dict:
    import html
    msgs = _real_policy_messages()
    cases = [{"name": n, "status": 409,
              "payload": {"error": m, "code": "policy_data_invalid"}}
             for n, m in msgs.items()]
    f = tmp_path / "cases.json"
    f.write_text(json.dumps(cases, ensure_ascii=False))
    code, out = run_boot("report-error", app, cases=f)
    assert code == 0, out
    # esc() 会把 `"` 变成 `&quot;`（allowed_users 的 `S="org"`）。浏览器解析 HTML
    # 时又变回来，所以断言前要 unescape——否则断言的是渲染管线的中间态。
    return {c["name"]: html.unescape(c["toast"]) for c in out["cases"]}


def test_absent_branch_reaches_the_toast_telling_the_user_to_deploy_once(tmp_path):
    # 措辞从 permissions 的常量取，**不手抄片段**（S1 fix round 2）。
    perm = _permissions()
    rendered = _render_real_messages(tmp_path)["absent"]
    assert perm.REPAIR_ABSENT in rendered, rendered
    assert perm.REPAIR_WRONG_TYPE not in rendered, rendered
    assert RETRY_HINT not in rendered, (
        f"UI 在「去部署一次」后面又追加了「刷新后重试即可」: {rendered}")


def test_wrong_typed_branch_reaches_the_toast_telling_the_user_to_fix_the_row(tmp_path):
    perm = _permissions()
    rendered = _render_real_messages(tmp_path)["wrong-typed"]
    assert perm.REPAIR_WRONG_TYPE in rendered, rendered
    assert perm.REPAIR_ABSENT not in rendered, rendered
    assert RETRY_HINT not in rendered, rendered


def test_both_real_messages_survive_verbatim(tmp_path):
    """整段逐字到达，不只是几个关键词——中间任何截断/改写都在这里红。

    **断言方向刻意是"后端那段字出现在 toast 上"**，不是"toast 上有某句关于修法
    的话"。后者会诱使人在 app.js 里补一句自己的建议来让用例变绿，而"修法"的措辞
    只能有一份、在后端（`effective_policy` 的 `repair_*`）。这里做不到时该改的是
    那一份，不是往前端加第二份。
    """
    msgs = _real_policy_messages()
    rendered = _render_real_messages(tmp_path)
    for name, msg in msgs.items():
        assert msg in rendered[name], (
            f"{name} 的后端文案没有逐字到达 toast\n后端: {msg}\n"
            f"页面: {rendered[name]}")


def test_harness_catches_the_real_message_getting_the_hint_appended(tmp_path):
    """反向验证：判据失效时，**真文案**这一路也必须红。"""
    old = "err.payload.code === POLICY_DATA_INVALID_CODE"
    src = APP.read_text()
    assert old in src, f"注入点找不到（代码改过？）: {old}"
    app = tmp_path / "mutated.js"
    app.write_text(src.replace(old, "err.payload.code === 'never-matches'", 1))
    rendered = _render_real_messages(tmp_path, app)
    assert RETRY_HINT in rendered["absent"], (
        f"注入了原缺陷但真文案这一路仍然绿——它什么都没盯: {rendered['absent']}")
