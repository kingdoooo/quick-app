"""前端与后端的契约：路径、方法名、各种词表、disabled 语义、无真实值。

**判据一律从真源推导，不留手写清单**：路径核对唯一判据是 `handler.ROUTES`，
词表核对唯一判据是写入方的源码。本文件历史上有过两份手写清单（M4/M5 的
"禁止路径"与临时豁免），它们的共同结局是"端点真实存在之后变成永远绿的死断言"，
两份都已随对应里程碑的前端落地删除。

**为什么是静态解析而不是跑浏览器**：这些断言要在 CI/单测里挡住"改了后端路由
忘了改前端"这类漂移，必须无依赖、秒级、可无人值守。真实交互行为由 Task 14
Step 3 的真机 E2E 覆盖，两者互补不重叠。

写本文件时踩过的坑（M3-FINDINGS §2.10）：第一版把真实账号 ID 与真实域名当
"禁用值清单"写死在这里——那正是计划明令禁止的（本文件被 git 跟踪）。现在改为
按**形态**判定 + 从 gitignored 的 config.ini 读当前环境真实值来比对。
"""
import ast
import configparser
import re
import types
from pathlib import Path

import pytest

PANEL = Path(__file__).parents[1]
FE = PANEL / "frontend"
REPO = PANEL.parents[1]


def _strip_js_comments(src: str) -> str:
    """去掉 JS 注释，**但不破坏字符串字面量**。

    为什么需要它：本文件第一版直接在原文上做文本断言，结果三条用例被我自己
    写的注释命中而假红（注释里写了"不要请求 /api/analytics"、"tier 字段没有"、
    "`<script src="/app">` 会取回 HTML"）。这正是 M3-FINDINGS §2 检查清单第 4
    条说的"源码里出现某字样 ≠ 该逻辑生效"——只不过这次方向相反：**注释让
    断言假红**，而假红同样会被下一个人用 `# noqa` 之类的方式绕过，然后断言
    就永久失效了。

    不能用 `re.sub(r"//.*", "")`：代码里有 `'https://'`、`replace(/^https:\\/\\//, '')`
    这样的内容，粗暴剥离会把字符串切断，反而制造新的假绿。

    **必须识别正则字面量**：第一版只跟踪字符串，结果被 `esc()` 里的
    `/[&<>"']/g` 打败——扫描器把那个 `"` 当成字符串开头，从此错位，后面的
    块注释一个都没剥掉，于是三条用例继续假红。修它时才意识到：一个"剥注释"
    的工具本身就需要被验证，见下面的 test_comment_stripper_*。
    """
    # 这些字符之后出现的 `/` 是正则字面量的开头，而不是除号
    REGEX_OK_AFTER = set("(,=:[!&|?{};+-*%~^<>\n\r\t ")
    out = []
    i, n = 0, len(src)
    prev = ""           # 上一个有意义的字符（用于区分正则与除法）
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "*":                     # 块注释
            end = src.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append("\n")
            continue
        if ch == "/" and nxt == "/":                     # 行注释
            end = src.find("\n", i)
            i = n if end < 0 else end
            continue

        if ch in "'\"`":                                 # 字符串字面量
            out.append(ch)
            i += 1
            while i < n:
                c = src[i]
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
                i += 1
                if c == ch:
                    break
            prev = ch
            continue

        if ch == "/" and (prev == "" or prev in REGEX_OK_AFTER):
            # 正则字面量：整体照抄，内部的引号/斜杠都不参与状态机
            out.append(ch)
            i += 1
            in_class = False
            while i < n:
                c = src[i]
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
                i += 1
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    break
                elif c == "\n":
                    break        # 未闭合：当普通字符处理，别把后文全吃掉
            prev = "/"
            continue

        out.append(ch)
        if not ch.isspace():
            prev = ch
        elif ch == "\n":
            prev = "\n"
        i += 1
    return "".join(out)


# ── 剥注释器自身的验证 ────────────────────────────────────────────────
# "一个只会说 clean 的检测器比没有更糟"（M3-FINDINGS §2.11）。剥注释器是本文件
# 每条文本断言的前置，它坏掉的表现是**假红**（第一版）或**假绿**（把代码当注释
# 吃掉）。两个方向都要证明。

def test_comment_stripper_removes_comments():
    src = 'a();\n/* 不要请求 /api/analytics */\nb(); // tier 说明\nc();'
    out = _strip_js_comments(src)
    assert "/api/analytics" not in out, "块注释没剥掉"
    assert "tier" not in out, "行注释没剥掉"
    for kept in ("a()", "b()", "c()"):
        assert kept in out, f"把代码 {kept} 也吃掉了"


def test_comment_stripper_keeps_regex_and_string_literals():
    """带引号的正则、含 // 的字符串都不能被当成注释。

    这两条正是第一版栽的地方：`/[&<>"']/g` 让扫描器错位，后续块注释全部残留。
    """
    src = (
        'const esc = (s) => s.replace(/[&<>"\']/g, (c) => M[c]);\n'
        "const u = 'https://example.com/x';\n"
        "const t = `a//b`;\n"
        '/* 这段注释里有 /api/analytics 和 tier */\n'
        "const v = a / b; // 除法不是正则\n"
    )
    out = _strip_js_comments(src)
    assert '/[&<>"\']/g' in out, "正则字面量被破坏"
    assert "https://example.com/x" in out, "字符串里的 // 被当成注释"
    assert "`a//b`" in out, "模板字符串里的 // 被当成注释"
    assert "a / b" in out, "除法被当成正则吞掉了后文"
    assert "/api/analytics" not in out and "tier" not in out, (
        "有正则/字符串在前时块注释没被剥掉——正是第一版的故障形态")
    assert "除法不是正则" not in out, "行注释没剥掉"


def _js(strip_comments: bool = True) -> str:
    """全部前端 JS 拼一起（默认已剥注释）。

    **空结果要报错**——解析失败必须是红的，否则下面每条
    `assert forbidden not in blob` 都会在空串上"通过"（一个只会说 clean 的
    检测器比没有更糟，M3-FINDINGS §2.11）。
    """
    raw = "\n".join(p.read_text() for p in sorted(FE.rglob("*.js")))
    assert raw.strip(), f"{FE} 下没有 JS——解析口径坏了，本文件的断言全部失效"
    if not strip_comments:
        return raw
    code = _strip_js_comments(raw)
    # 剥注释后仍必须留下实质代码；比例异常说明扫描器坏了（宁可红不要静默）
    assert len(code.strip()) > 0.25 * len(raw), (
        "剥注释后代码剩得太少——扫描器可能把字符串当注释吃掉了")
    assert "function esc(" in code, "剥注释后连 esc() 都不见了，扫描器坏了"
    return code


def _all_text() -> str:
    """全部前端文件的原文（含注释）。

    用于"不得残留真实值"这类**必须连注释一起查**的断言：把真实域名写进
    HTML 注释同样是泄漏。
    """
    blob = "\n".join(p.read_text(errors="replace")
                     for p in sorted(FE.rglob("*")) if p.is_file())
    assert blob.strip(), f"{FE} 下没有任何文件"
    return blob


def _markup_without_comments() -> str:
    """HTML/JS 的实质内容（剥掉 <!-- --> 与 JS 注释）。

    用于"不得出现某字样"的断言——注释里解释"为什么不这么做"不该让用例变红。
    """
    html = "\n".join(p.read_text() for p in sorted(FE.rglob("*.html")))
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    return html + "\n" + _js()


# ── ① 不得残留真实值 ────────────────────────────────────────────────────

def test_no_real_values_in_frontend():
    """前端不得残留原型里的真实值（账号 ID / 域名 / 本机路径）。

    禁用值**不写死在本文件里**：把真实账号 ID / 域名写进被 git 跟踪的测试就
    等于泄漏它们。按形态判定 + 从 config.ini（gitignored）读真实值比对。
    """
    blob = _all_text()
    assert not re.search(r"\b\d{12}\b", blob), "疑似 12 位 AWS 账号 ID"
    assert "/Users/" not in blob and "/home/" not in blob, "残留本机绝对路径"
    assert ".lambda-url." not in blob, (
        "残留 Function URL——前端只能走同源 /api/*，直连 Function URL 会 403")

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(PANEL.parent / "config.ini")
    checked = 0
    for section, key in (("Platform", "account_id"), ("Platform", "base_domain"),
                         ("Auth", "cognito_domain")):
        if not cfg.has_section(section):
            continue
        val = (cfg[section].get(key) or "").split("#")[0].strip()
        if val:
            checked += 1
            assert val not in blob, f"前端残留真实 {section}.{key}"
    # config.ini 不存在时（干净 clone）上面一条都不会跑——如实说明，
    # 而不是让"0 项检查"看起来像通过。形态判定仍然有效。
    if checked == 0:
        pytest.skip("config.ini 缺失，仅完成形态判定（真实值比对未执行）")


def test_base_domain_is_derived_from_location_not_hardcoded():
    """站点 URL 由后端给（site.url），域名不在前端硬编码。

    硬编码域名意味着换环境（不同 base_domain）就要改前端代码，且极易把生产
    域名留在仓库里。

    **反向验证发现的缺陷**：第一版只查 `https://` 开头的串，于是把
    `baseDomain()` 的实现整体换成 `return 'internal.corp.net';` 之后**仍然
    是绿的**——最典型的硬编码形态恰好不带协议头。现在同时查裸域名字面量。
    """
    blob = _js()
    allowed = {"https://example.com", "example.com"}   # 占位符示例
    bad = {h for h in re.findall(r"https://(?!\$\{)[a-z0-9.-]*\.[a-z]{2,}", blob)
           if h not in allowed}
    # 裸域名字面量：'a.b.cc' 形态的字符串（至少两段 + 顶级域）。
    # 例外：`name@example.com` 这类 placeholder、以及 CSS/JS 文件名。
    for lit in re.findall(r"""['"]([a-z0-9][a-z0-9.-]*\.[a-z]{2,})['"]""", blob):
        if lit in allowed or lit.endswith((".js", ".css", ".html", ".json",
                                           ".svg", ".ico")):
            continue
        bad.add(lit)
    assert not bad, (
        f"前端硬编码了域名: {sorted(bad)} —— 域名必须从 location 推导"
        "（baseDomain()）或由后端返回")


# ── ② 每个 /api 路径都必须在 handler.ROUTES 里 ──────────────────────────

def _path_argument(expr: str) -> str:
    """从实参区里切出**第一个参数**（路径表达式），丢掉后面的 body。

    必须按括号/花括号深度找顶层逗号：请求体是对象字面量，里面自带逗号与
    字符串（`{ require_login: x, allowed_users: 'org' }`）。第一版直接把整个
    实参区当路径，于是 body 里的 `'org'` 被拼进了路径，得到
    `/api/sites/s-abc123/permissionsorgorg` 这种东西——症状是"前端请求了
    handler 没有的路由"，指向的却是解析器的缺陷。
    """
    depth = 0
    for i, ch in enumerate(expr):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return expr[:i]          # 实参区结束（api(...) 的右括号）
            depth -= 1
        elif ch == "," and depth == 0:
            return expr[:i]
    return expr


def _normalize_path(expr: str) -> str:
    """把 JS 里拼出来的路径表达式还原成一条可匹配的具体路径。

    真实代码是字符串拼接：
        '/api/sites/' + encodeURIComponent(site.site_id) + '/jobs'
    所以不能只取第一个字面量（那样得到 `/api/sites/`，既匹配不上 handler
    的路由，也让"前端接了哪些端点"的反向核对全部落空——第一版就是这样，
    两条用例一起红了，但红的原因是解析器太弱而不是代码有问题）。

    做法：把非字面量片段一律替换成一个合法的 site_id 占位，再拼起来。
    """
    parts = re.findall(r"""'([^']*)'|"([^"]*)"|`([^`]*)`""", _path_argument(expr))
    out = []
    for single, double, tick in parts:
        lit = single or double or tick
        # 模板字符串里的 ${...} 同样是动态段
        out.append(re.sub(r"\$\{[^}]*\}", "s-abc123", lit))
    joined = "".join(out)
    # 拼接里被替换掉的动态段（encodeURIComponent(...) 等）在字面量之间留下空缺，
    # 表现为 '/api/sites/' 直接接 '/jobs' → '/api/sites//jobs'。补上占位。
    joined = joined.replace("//", "/s-abc123/")
    if joined.endswith("/"):
        joined += "s-abc123"
    return joined.split("?")[0]


def test_path_parser_handles_concatenation_and_ignores_request_bodies():
    """路径解析器自身的验证（两个真实故障形态各一条）。

    解析器是"前端只请求存在的端点"这条断言的前置。它太弱会假红（认不出拼接
    路径），太贪会假绿/错红（把 body 里的字符串拼进路径）。两者都实际发生过。
    """
    assert _normalize_path(
        "'/api/sites/' + encodeURIComponent(id) + '/jobs'") == "/api/sites/s-abc123/jobs"
    assert _normalize_path(
        "'/api/sites/' + encodeURIComponent(x) + '/permissions', "
        "{ require_login: true, allowed_users: 'org' }"
    ) == "/api/sites/s-abc123/permissions", "body 里的字符串被拼进了路径"
    assert _normalize_path("'/api/admins', { email: val }") == "/api/admins"
    assert _normalize_path("all ? '/api/sites?all=1' : '/api/sites'") == "/api/sites"


def _frontend_calls() -> set[tuple[str, str]]:
    """(method, 具体化后的 path) 集合。

    只解析 `api(METHOD, <路径表达式>...)` 与 `apiGet(<路径表达式>)` 两种形态
    ——它们是本前端**唯一**的两个出网口（fetch 只在 api() 里出现一次，由
    test_all_network_calls_go_through_the_api_helper 锁定）。

    **每个调用点都要被解释清楚**：解析不出字面量路径的调用点必须是那唯一的
    `apiGet = (path) => api('GET', path)` 转发（它的路径来自调用方，不是自己
    的），其余一律报错。第一版对解析失败的调用点直接 assert 全局形态，结果被
    这条转发弄红了——但"静默跳过解析不出的调用点"更糟：那等于给动态拼路径
    开了一个不受检查的后门。
    """
    blob = _js()
    calls = set()
    forwarders = 0
    for m in re.finditer(r"\bapi(Get)?\(", blob):
        is_get_helper = bool(m.group(1))
        # 取到该调用的实参区（到分号或行尾为止，够覆盖跨行拼接）
        tail = blob[m.end():m.end() + 400]
        arg_region = tail.split(";")[0]
        if is_get_helper:
            method, expr = "GET", arg_region
        else:
            head = re.match(r"""\s*['"]([A-Z]+)['"]\s*,(.*)""", arg_region, re.S)
            if not head:
                continue            # `async function api(method, path, body)` 定义本身
            method, expr = head.group(1), head.group(2)
        path = _normalize_path(expr)
        if not path.startswith("/api/"):
            forwarders += 1
            continue
        calls.add((method, path))

    assert calls, "解析不到任何 API 调用——调用形态变了，本用例必须同步更新"
    assert forwarders == 1, (
        f"有 {forwarders} 个调用点解析不出字面量路径（预期恰好 1 个，即 apiGet 转发）。"
        "动态拼出的路径无法被本文件检查——请改成字面量，或在这里说明为什么不能")
    return calls


def test_all_network_calls_go_through_the_api_helper():
    """fetch 只能出现在 api() 里。

    否则上面的路径解析就只看到了一部分请求，而"前端不得请求不存在的接口"
    这条断言会在它没解析到的调用上完全失效——一个只覆盖一半出网口的检测器
    给出的"clean"是假的。
    """
    blob = _js()
    assert blob.count("fetch(") == 1, (
        f"fetch 出现 {blob.count('fetch(')} 次——所有请求必须走 api() 这个唯一出口，"
        "否则契约断言覆盖不到")
    assert "XMLHttpRequest" not in blob and "navigator.sendBeacon" not in blob, (
        "出现了绕过 api() 的出网方式")


def test_every_api_path_exists_in_handler_routes():
    """前端请求的每个路径都必须在 handler.ROUTES 里（拼错会 404 且难查）。

    **唯一判据是 handler.ROUTES，不是任何手写清单**。本文件的第 ③ 组曾经另有
    一份手写的"禁止路径"清单（`/api/analytics`、`/api/visitors`、`/api/stats`、
    `/api/pv`）替这条做一半的事。M5 落地时那份清单会变成**永远绿的死断言**：
    真实路由是 `/api/sites/{id}/analytics`，与清单里的裸路径不是同一个字符串，
    所以它既抓不到问题也不会红——正是 M4-FINDINGS §3.6 说的死重量，与 §3.2 的
    "枚举什么还不存在"是同一个病（M4 的 `/api/keys` 已经栽过一次：端点真实存在
    之后那一条只能靠人记得回来删）。

    从真源推导的这条在下一个里程碑加路由时既不假红也不假绿，所以 Task 9 把
    清单删了；它唯一还有价值的那一半（"扫描器不许漏出网口"）改成
    test_path_extractor_sees_every_api_literal_in_the_source。
    """
    import handler
    for method, path in sorted(_frontend_calls()):
        assert any(m == method and rx.match(path)
                   for m, rx in handler.ROUTES), (
            f"前端请求了 handler 没有的路由: {method} {path}")


# 二期 M4 的 Key 路由（`GET/POST /api/keys`、`POST /api/keys/revoke`、
# `GET/PUT /api/settings/api-key`）
# 曾经在这里有一份 `M4_PENDING_FRONTEND` 临时豁免：Task 6 落了后端、前端还没接，
# 而当时紧邻的"M4 入口不得发请求"那条守卫与"handler 的端点都要有人接"互斥。
# **Task 9 接完前端后豁免已删除**（连同盯着它的那条用例），五条 Key 路由现在
# 由下面的可达性核对正常覆盖。留这段注释是因为"临时豁免变永久"是本项目记录过
# 的形态——它这次确实被收回了。

# 二期 M5 的两条读路由（`GET /api/sites/{id}/analytics`、
# `GET /api/sites/{id}/visitors`）走过**完全相同的一轮**：Task 8 落后端时加了
# `M5_PENDING_FRONTEND` 临时豁免 + 一条盯着它的用例，**Task 9 接完前端后两者
# 一起删除**（那条用例正是被"前端已经接了 /analytics"判红的——红本身就是豁免
# 到期的信号）。两个里程碑各一次收回，"临时豁免变永久"这个形态目前 0 例存量。


def test_every_handler_route_is_reachable_or_explicitly_unused():
    """反向核对：handler 的路由要么被前端用到，要么在豁免名单里。

    没有这条时，后端删掉一个端点、前端还在调它，只有上面那条会红；而后端
    **新增**端点后前端漏接则完全无人发现。豁免名单必须逐条写明原因。
    """
    import handler
    exempt = {
        # 浏览器直接跳转（Location），不是 fetch，所以前端 JS 里没有它
        (r"^/api/session-callback$", "auth 302 过来的升级回调，由浏览器发起"),
        # 管理员手工修复口，控制台不暴露入口（spec §8：人工排障用）
        (r"^/api/admin/resync/(?P<site_id>[a-z][a-z0-9-]{1,63})$",
         "人工修复投影用，不做 UI 入口"),
    }
    exempt_patterns = {p for p, _ in exempt}
    calls = _frontend_calls()
    unreached = []
    for method, rx in handler.ROUTES:
        if rx.pattern in exempt_patterns:
            continue
        if not any(m == method and rx.match(p) for m, p in calls):
            unreached.append(f"{method} {rx.pattern}")
    assert not unreached, (
        f"handler 有端点前端没接（漏接或该加豁免说明）: {unreached}")


# ── ③ 扫描器自身不许漏出网口；disabled 入口的无障碍语义 ────────────────

def test_path_extractor_sees_every_api_literal_in_the_source():
    """源码里的 `/api` 字面量不能比解析出的路径多。

    这才是那份被删掉的"禁止路径"清单唯一在替人做的事，也是本文件真正的风险
    面：`_frontend_calls()` 是上面**每一条**路径断言的前置，它漏掉一个出网口
    时那些断言全部在一个子集上说 clean（"一个只会说 clean 的检测器比没有更糟"，
    M3-FINDINGS §2.11）。清单的做法只覆盖几个**猜出来的**字符串；这条覆盖
    源码里真实存在的每一个。

    判据是前缀：字面量是拼接的头段（`'/api/sites/'`），解析出的是具体化后的
    完整路径（`/api/sites/s-abc123/jobs`）。
    """
    import re as _re
    blob = _js()
    literals = {m.group(1) for m in
                _re.finditer(r"""['"](/api/[A-Za-z0-9_\-/]*)['"]""", blob)}
    assert literals, "源码里一个 /api 字面量都没有——调用形态变了，本用例必须同步更新"
    parsed_prefixes = {p for _, p in _frontend_calls()}
    for lit in literals:
        head = lit.rstrip("/")
        assert any(p.startswith(head) for p in parsed_prefixes), (
            f"源码里有 /api 字面量 {lit!r} 但解析器没把它算成一次调用"
            "——扫描器漏了一个出网口，本文件的其它断言对它全部失效")


def test_frontend_flags_inexact_uv_instead_of_printing_a_number():
    """超出 90 天明细窗口的桶：`uv` 是 **null 而不是 0**，前端必须读 uv_exact。

    后端契约（Task 8）：区间没有完整落在明细留存窗口里时无法去重，`uv` 给
    null。不读 uv_exact 就会把 null 直接拼进 HTML（页面显示 "null"），或者被
    `|| 0` 兜成 0——后者更糟，"0 个独立访客"是一句错的事实陈述。
    """
    blob = _js()
    assert "uv_exact" in blob, "前端没有读 uv_exact——超窗口的桶会显示 null 或 0"


def test_disabled_entries_are_visibly_disabled_in_markup():
    """产出 disabled 外观的每一处都必须同时带 `aria-disabled`。

    spec §4.1 要求未启用/不可用的入口**看得见地**禁用而不是悄悄删掉：删掉的话
    用户既不知道平台有这个能力，也不知道为什么自己没有。而只给视觉（变灰的
    `is-disabled` / `coming-later`）对读屏用户等于没禁用。

    **Task 9 改过判据**。上一版是两句 blob 级的"字样存在"断言，其中一句还带
    `or`（`"coming-later" in blob or "规划中" in blob`）：M5 的访问统计落地后
    "规划中"这个词从前端消失，而那条**仍然是绿的**——它被另一处不相干的标记
    （从未上线站点的"打开站点"按钮）满足了。同形的还有 `aria-disabled in blob`：
    整份 JS 里有一处带就绿，第二处忘了写它看不见。
    所以改成**逐处配对**：这是"修那一类"而不是"再列一遍现在有哪几类"——下一个
    里程碑新加占位入口时，忘了无障碍属性会被指名。
    """
    blob = _markup_without_comments()
    marks = list(re.finditer(r"""class=["'][^"']*\b(?:is-disabled|coming-later)\b""",
                             blob))
    assert marks, ("找不到任何 disabled 外观的标记 —— 未启用的入口被删掉了？"
                   "（API Key 组件未部署时必须留一个看得见的 disabled 项）")
    for m in marks:
        # 标签的属性区到它的第一个 `>` 为止。拼接跨行不影响：`+`、引号与
        # `'title="…"'` 里都没有 `>`，所以第一个 `>` 就是这个标签的收尾。
        end = blob.find(">", m.end())
        assert end > 0, f"标签没有闭合: {blob[m.start():m.start() + 120]!r}"
        tag = blob[m.start():end]
        assert "aria-disabled" in tag, (
            "有 disabled 外观但缺 aria-disabled —— 只靠视觉变灰对读屏用户等于"
            f"没禁用: {tag!r}")


def test_decision_label_matches_what_the_edge_writes():
    """访问明细的 `decision` 词表必须等于 Edge 真正写入的三个字面量。

    与 PHASE_LABEL 那条同一个纪律（"手抄清单必须能被真源打假"）：词表在前端，
    真源在 `origin_request.py` 里赋给 `decision` 的三个常量。Edge 改了取值
    （或加了第四种）而前端没跟，"结果"列会显示原始英文串——用户看到
    `denied_403`，而这一列的全部意义就是把它翻成人话。
    """
    src = (REPO / "router" / "infrastructure" / "lambda"
           / "origin_request.py").read_text()
    real = set()
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "decision"
                   for t in node.targets):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            real.add(node.value.value)
    assert real == {"allow", "denied_403", "redirect_login"}, (
        f"Edge 写入的 decision 取值变了: {sorted(real)}"
        "——前端 DECISION_LABEL 与本用例的预期都要同步")
    m = re.search(r"const DECISION_LABEL\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 DECISION_LABEL"
    keys = set(re.findall(r"""['"]?([a-z_0-9]+)['"]?\s*:""", m.group(1)))
    assert keys == real, (
        f"DECISION_LABEL 的键 {sorted(keys)} ≠ Edge 写入的 {sorted(real)}")


# ── ④ PHASE_LABEL 用真实小写 phase 词表 ────────────────────────────────

# compensating：MarkFailed 在补偿路由期间的过渡 phase（R4 P1-1 之后终态在
# 补偿完成后才写——这段时间用户在部署历史里看到的就是它）。
REAL_PHASES = {"submitted", "queued", "validate", "provision-db", "package",
               "deploy-backend", "upload-frontend", "register-route",
               "smoke-test", "compensating", "undeploy"}


def _phase_label_keys() -> set[str]:
    """用 AST 取 PHASE_LABEL 的**实际键**，不用 regex。

    M3-FINDINGS §2.1 #7 的教训：regex 断言在文本层面容易被骗过（注释、
    docstring、相似字样都会命中）。这里解析 JS 对象字面量的键名。
    """
    m = re.search(r"const PHASE_LABEL\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 PHASE_LABEL 定义"
    body = m.group(1)
    # 去掉行注释再取键，避免注释里的字样被当成键
    body = re.sub(r"//[^\n]*", "", body)
    keys = set(re.findall(r"""['"]([^'"]+)['"]\s*:""", body))
    assert keys, "PHASE_LABEL 解析不出键"
    return keys


def test_phase_label_matches_real_job_phases():
    """PHASE_LABEL 的 key 必须是 jobs 表真实的小写 phase，不是 SFN 节点名。

    原型里写的是 SFN 状态机节点名（Validate / PackageBackend / …），而 jobs
    表里存的是 common.update_job(phase=...) 写入的小写串。照搬会让每一行
    部署历史都显示原始值，用户看到的是内部节点名。
    """
    keys = _phase_label_keys()
    extra = keys - REAL_PHASES
    assert not extra, f"PHASE_LABEL 含非真实 phase: {sorted(extra)}"
    assert "smoke-test" in keys, "SUCCEEDED 的 job phase 停在 smoke-test，必须有词条"
    for sfn_node in ("Validate", "PackageBackend", "RegisterRoute",
                     "MarkSuccess", "ProvisionDynamoDB", "DeployLambdaSite"):
        assert sfn_node not in keys, f"残留 SFN 节点名 {sfn_node}"


def test_phase_label_is_derived_from_the_real_writers_in_deployer():
    """从 deployer 源码解析真实 phase 写入点，与 REAL_PHASES 交叉核对。

    没有这条时，deployer 改了 phase 字面量（比如 package → build），
    上面那条仍然全绿——它只拿 REAL_PHASES 这份**手抄清单**比对。
    手抄清单必须能被真源打假，否则它自己就是漂移源
    （M3-FINDINGS "别打地鼠，修那一类"）。
    """
    fn_dir = REPO / "site-builder" / "deployer" / "functions"
    found = set()
    for py in sorted(fn_dir.glob("*.py")):
        for node in ast.walk(ast.parse(py.read_text())):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "phase" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    found.add(kw.value.value)
    # common.create_job 里的 phase 是 dict 字面量，不是关键字参数
    for node in ast.walk(ast.parse((fn_dir / "common.py").read_text())):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "phase"
                        and isinstance(v, ast.Constant)):
                    found.add(v.value)
    assert found, "解析不到任何 phase 写入点——解析口径坏了"
    unknown = found - REAL_PHASES
    assert not unknown, (
        f"deployer 写入了 REAL_PHASES 未登记的 phase: {sorted(unknown)}"
        "——前端词表与本用例的清单都要同步更新")


# ── ⑤ 401 升级只重放一次 ───────────────────────────────────────────────

def test_401_triggers_session_upgrade_then_single_replay():
    """401+need=console-session → 跳升级 → **只重放一次**（防无限循环）。

    无守卫时的故障形态：升级后仍 401（比如 cookie 被浏览器拒了）会让页面
    在 /console-session 与 /api/* 之间无限跳转，用户看到白屏闪烁。
    """
    blob = _js()
    assert "console-session" in blob, "看不到面板会话升级入口"
    assert re.search(r"_?retried|_retry|onlyOnce|replayed", blob), (
        "看不到「只重放一次」的守卫——升级失败会变成无限跳转")


def test_upgrade_redirect_goes_to_auth_console_session_not_panel():
    """升级必须跳 auth 的 /console-session（顶域会话在那里）。

    跳 console 自己的 /api/session-callback 是错的：那个入口要一个**已签发
    的 code**，直接访问只会 401，用户卡死。
    """
    blob = _js()
    assert re.search(r"/console-session", blob)
    assert not re.search(r"location\.(href|assign)[^\n]*session-callback", blob), (
        "不要直接跳 session-callback——它需要 auth 先签发 code")


# ── ⑥ 写请求形态与 CSRF 前置 ───────────────────────────────────────────

def test_write_requests_send_json_content_type_and_same_origin_credentials():
    """写请求必须带 application/json 且 same-origin 凭证。

    panel 的 check_csrf 要求 Content-Type 精确是 application/json；
    缺 credentials 则 __Host-sb_console 不会被发出去，全部写请求 401。

    **反向验证发现的缺陷**：第一版只断言 `"application/json" in blob`，
    而这个串还出现在 `accept` 头里——删掉设置 **content-type** 的那一行之后
    用例仍然是绿的。与 M3-FINDINGS §2.1 #2 同形："一个缺陷被两处字样覆盖，
    于是每处看起来都是承重墙，实际一处都不是。"
    现在按"给 content-type 赋值 application/json"这个**具体动作**断言。
    """
    blob = _js()
    assert re.search(
        r"""['"]?content-type['"]?\s*\]?\s*=\s*['"]application/json['"]""",
        blob, re.I), (
        "看不到给 content-type 赋 application/json 的语句 —— "
        "panel 的 check_csrf 会以 403 拒掉所有写请求")
    assert re.search(r"""credentials\s*:\s*['"]same-origin['"]""", blob), (
        "fetch 缺 credentials: 'same-origin' —— cookie 不会发出，写请求全 401")
    # 声明了 application/json 就得真的序列化 body
    assert "JSON.stringify" in blob, "声明了 application/json 却没有序列化 body"


def test_frontend_never_sets_origin_or_reads_cookie():
    """Origin 由浏览器设置，cookie 是 HttpOnly——前端碰这两样说明设计错了。"""
    blob = _js()
    assert not re.search(r"""headers[^\n]*['"]Origin['"]""", blob), (
        "前端手设 Origin 头：浏览器会忽略它，说明对 CSRF 校验的理解有误")
    assert "document.cookie" not in blob, (
        "__Host-sb_console 是 HttpOnly，读不到；读得到就说明它没设 HttpOnly")


# ── ⑦ 站点字段口径必须与 api._shape_site 一致 ──────────────────────────

def _shape_site_fields() -> set[str]:
    """从 api.py 解析后端**真实返回**的站点字段名。

    **两个函数都要解析**：`_shape_site` 是列表与详情共用的形态，而
    `do_list_sites` 在它之上多给一个 `pv7`（M5 Task 9b 的迷你趋势；只有列表
    需要，详情页不为它多打两次 Query）。只解析 `_shape_site` 的话，列表独有的
    字段会被判成"后端不返回"，前端读它就是误报——而误报会被当成"前端写错了"
    去改前端。
    """
    src = (PANEL / "api.py").read_text()
    tree = ast.parse(src)
    fields = set()
    for name in ("_shape_site", "do_list_sites"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == name)
        for node in ast.walk(fn):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    # `{**_shape_site(...), "pv7": ...}` 的展开项 key 是 None
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        fields.add(k.value)
    assert fields, "解析 api.py 的站点形态失败"
    return fields


def test_frontend_only_reads_site_fields_the_backend_returns():
    """前端读的 site 字段必须是后端真给的。

    原型依赖 tier / pv7 / last_deploy / my_role / auth.require_login 等字段，
    **sites 表里没有 tier，也不返回 last_deploy**，照搬会让页面显示 undefined。
    这条用例把口径钉在 api.py 的真实返回形态上（`pv7` 从 M5 Task 9b 起是真有
    的，由 `do_list_sites` 给——所以它在 `_shape_site_fields()` 里）。
    """
    backend = _shape_site_fields() | {"subdomain"}   # /api/sites/{id} 多这个
    blob = _js()
    # 只看 site.xxx / s.xxx 这种成员访问
    used = set(re.findall(r"\bsite\.([a-z_][a-z0-9_]*)", blob))
    used |= set(re.findall(r"\bs\.([a-z_][a-z0-9_]*)", blob))
    # 前端自己派生的展示字段（不来自后端），逐个说明来源
    derived = {"site_id", "js", "css", "length", "map", "filter", "slice",
               "includes", "concat", "replace", "split", "trim", "value",
               "dataset", "classList", "textContent", "innerHTML", "disabled",
               "focus", "style", "forEach", "reduce", "push", "pop", "join",
               "toLowerCase", "setAttribute", "addEventListener", "remove",
               "hasAttribute", "closest", "querySelector", "sort", "indexOf",
               "then", "catch", "finally", "message", "status", "ok", "json",
               "text", "headers", "get", "has", "set", "keys", "entries"}
    unknown = used - backend - derived
    assert not unknown, (
        f"前端读了后端不返回的 site 字段: {sorted(unknown)} "
        f"（后端字段: {sorted(backend)}）")


def test_frontend_does_not_use_tier_which_sites_table_lacks():
    """`tier` 是原型独有：sites 表不存它，_shape_site 也不返回。

    单独立一条是因为它是原型里出现频率最高的字段（每张卡片一个徽章），
    照搬的话每个站点都显示 undefined，而这条能直接指出原因。
    """
    assert "tier" not in _shape_site_fields(), (
        "后端已经返回 tier 了——那本用例过时，删掉它并让前端用真字段")
    # 剥注释后再查：注释里说明"为什么去掉了 tier"是有价值的，不该让用例变红
    assert "tier" not in _js(), (
        "前端用了 tier，但 sites 表里没有这个字段（原型遗留）")


# ── ⑧ 跨层：S3 前缀与 Edge 的静态改写必须能拼出真实 key ────────────────

def _edge_module():
    """把真实的 origin_request.py 替换占位符后在内存里 import。

    **必须用真实 Edge 代码**而不是在测试里重写拼接逻辑：M3-FINDINGS §2.7
    记过三处"以为的 vs 实际的"，自己重写等于把假设复制一份，两边一起错时
    断言仍然是绿的。
    """
    src = (REPO / "router" / "infrastructure" / "lambda"
           / "origin_request.py").read_text()
    for k, v in {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
                 "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
                 "{{JWT_SECRET}}": "s", "{{BASE_DOMAIN}}": "example.com",
                 "{{REQUIRE_IDP_CLAIM}}": "true",
                 "{{TRUSTED_IDPS}}": "Feishu"}.items():
        src = src.replace(k, v)
    assert "{{" not in src.split("\n# ")[0], "还有未替换的占位符"
    mod = types.ModuleType("_edge_for_frontend_contract")
    exec(compile(src, "origin_request.py", "exec"), mod.__dict__)
    return mod


@pytest.mark.parametrize("uri,rel", [("/", "index.html"),
                                     ("/app.js", "app.js"),
                                     ("/app.css", "app.css")])
def test_edge_static_key_matches_what_deploy_panel_uploads(uri, rel):
    """Edge 拼出的 S3 key 必须**逐字符等于** deploy_panel 上传的 key。

    这条是真机 403 的唯一静态防线：Edge 用
    `f"/{static_prefix}{path}"` 且 path 以 `/` 开头，所以 static_prefix
    **带尾斜杠就会拼出双斜杠**（`platform/console/v1//index.html`），
    与上传的 `platform/console/v1/index.html` 不是同一个对象 —— 控制台
    整站 403，且两边单测各自都是绿的。实测确认过这个形态。
    """
    from unittest.mock import patch
    import deploy_panel as dp
    orq = _edge_module()

    # upload_frontend 的 key 算法：frontend_prefix() + "/" + 相对路径。
    # **必须与它逐字符一致**——这里自己拼一遍是有意的：如果 upload_frontend
    # 改了拼法而本用例没改，本用例就应该红（它是两边形态的仲裁者）。
    # **不写死 "v1"**：版本段现在是前端内容指纹（P2-2），写死会让这条用例
    # 在每次前端改动后变红，而它要盯的是"两边 key 逐字符相等"，不是版本值。
    uploaded = dp.frontend_prefix() + "/" + rel
    route = {"subdomain": "console", "route_mode": "split",
             "static_prefix": dp.console_route_item(
                 "https://x.lambda-url.us-east-1.on.aws")["static_prefix"],
             "api_target": "https://x.lambda-url.us-east-1.on.aws",
             "require_auth": False, "allowed_users": "org", "owner": "platform"}
    event = {"Records": [{"cf": {"request": {
        "uri": uri, "querystring": "", "method": "GET",
        "headers": {"host": [{"key": "Host", "value": "console.example.com"}]}}}}]}

    with patch.object(orq, "_lookup_route", return_value=dict(route)), \
            patch.object(orq, "_add_s3_sigv4_auth"):
        req = orq.lambda_handler(event, None)
    edge_key = req["uri"].lstrip("/")
    assert "//" not in edge_key, f"Edge 拼出双斜杠: {edge_key!r}"
    assert edge_key == uploaded, (
        f"Edge 取 {edge_key!r} 但上传的是 {uploaded!r} —— 控制台会整站 403")


def test_frontend_has_no_extensionless_asset_requests():
    """所有静态资源必须带扩展名。

    Edge 把"最后一段不含 `.`"的 URI 一律改写成 `/index.html`（SPA 兜底），
    所以 `<script src="/app">` 会取回 HTML 而不是 JS——症状是控制台报
    "Unexpected token '<'"，很难联想到路由层。
    """
    html = "\n".join(p.read_text() for p in sorted(FE.rglob("*.html")))
    assert html.strip(), "找不到 index.html"
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)   # 注释里的示例不算引用
    refs = re.findall(r"""(?:src|href)=["'](/[^"']*)["']""", html)
    assert refs, "解析不到任何绝对路径资源引用——index.html 的引用形态变了？"
    for attr in refs:
        last = attr.rstrip("/").rsplit("/", 1)[-1]
        assert "." in last, (
            f"无扩展名的资源引用 {attr!r} 会被 Edge 改写成 index.html")


def test_declares_a_favicon_so_the_browser_stops_requesting_favicon_ico():
    """必须声明 rel="icon"，否则浏览器自动请求 /favicon.ico → 必然 403。

    Edge 把带扩展名的路径当静态资源去 S3 取（不改写成 index.html），
    `platform/console/{v}/favicon.ico` 不存在，私有桶返回 **403**。
    症状：每次打开控制台 DevTools 都记一条错误——真机截图里看到过。
    内联 data URI 而不是放个 .ico 到 S3：少一个二进制产物、少一次请求。
    """
    html = "\n".join(p.read_text() for p in sorted(FE.rglob("*.html")))
    html_nc = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    m = re.search(r"""<link[^>]*rel=["']icon["'][^>]*>""", html_nc, re.I)
    assert m, ("没有 <link rel=\"icon\"> —— 浏览器会自动请求 /favicon.ico，"
               "而 Edge 取不到该对象会返回 403")
    tag = m.group(0)
    assert "data:" in tag, (
        "favicon 不是内联 data URI —— 指向一个 URL 就又多一次请求，"
        "且该对象必须真的上传到 S3，否则还是 403")


def test_index_html_exists_because_edge_rewrites_bare_paths_to_it():
    """Edge 对无扩展名路径一律改写到 `{prefix}index.html`。

    这个文件名不是约定俗成而是**硬依赖**：改名会让首页 403，且 Edge 侧
    没有任何提示。
    """
    assert (FE / "index.html").exists(), (
        "缺 index.html —— Edge 对 `/` 的改写目标写死是 index.html")


# ── ⑨ 前端不得自行判定权限 ─────────────────────────────────────────────

def test_frontend_does_not_reimplement_authorization():
    """前端可以按 role 隐藏按钮（体验），但不得成为唯一防线。

    真实判定在 permissions.py（服务端同快照事务）。这里禁止前端出现
    "把角色算出来"的逻辑——那会漂移，且给人"前端拦住了"的错觉。
    role 由后端 _shape_site 直接给出，前端只读不算。
    """
    blob = _js()
    assert not re.search(r"collaborators\.includes\([^)]*\)\s*\?", blob), (
        "前端在自己算角色——role 由后端返回，直接读 site.role")
    assert "role" in blob, "前端应读后端给的 site.role 来决定按钮可用性"


def test_role_vocabulary_matches_permissions_module():
    """前端认的 role 词表必须与 permissions.py 的 ROLE_* 常量一致。

    后端 role_of 返回 owner/collaborator/admin/none 四种；原型里用的是
    `admin_view` 这个不存在的值，照搬会让管理员视图的角色标签显示为空。
    """
    src = (REPO / "site-builder" / "deployer" / "functions"
           / "permissions.py").read_text()
    real = set(re.findall(r"^ROLE_[A-Z]+ = \"([a-z]+)\"", src, re.M))
    assert real == {"owner", "collaborator", "admin", "none"}, (
        f"permissions.py 的角色词表变了: {sorted(real)}")
    m = re.search(r"const ROLE_LABEL\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 ROLE_LABEL"
    keys = set(re.findall(r"""['"]?([a-z_]+)['"]?\s*:""", m.group(1)))
    extra = keys - real
    assert not extra, f"ROLE_LABEL 含后端不存在的角色: {sorted(extra)}"


# ── ⑩ 状态词表与 undeploy 的异步语义 ───────────────────────────────────

def test_status_label_covers_every_status_the_backend_writes():
    """site.status 的四个真实取值都要有词条，否则徽章显示为空。"""
    fn_dir = REPO / "site-builder" / "deployer" / "functions"
    real = set()
    for py in sorted(fn_dir.glob("*.py")):
        for node in ast.walk(ast.parse(py.read_text())):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (kw.arg == "status" and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                            and kw.value.value.isupper()):
                        real.add(kw.value.value)
    assert real, "解析不到 status 写入点"
    m = re.search(r"const STATUS_LABEL\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 STATUS_LABEL"
    labeled = set(re.findall(r"""['"]?([A-Z]+)['"]?\s*:""", m.group(1)))
    # jobs 与 sites 共用部分状态；这里只要求 sites 的四态齐全
    for st in {"ACTIVE", "DELETED", "FAILED"} & real:
        assert st in labeled, f"STATUS_LABEL 缺 {st}"
    assert "DEPLOYING" in labeled, "缺 DEPLOYING（create_site_record 的初始态）"


def test_undeploy_is_treated_as_async_with_polling():
    """undeploy 是异步的（返回 job_id + PENDING），前端必须轮询。

    原型把它当同步（`await undeploySite()` 后立刻显示"已下线"）。真实后端
    只是**提交**了一个 job：立刻刷新会看到站点仍是 ACTIVE，用户以为失败。

    **反向验证发现的缺陷**：第一版断言 `re.search(r"poll|setTimeout|setInterval")`
    ——而 `setTimeout` 在 toast 自动关闭、搜索框防抖里都有，把真正的轮询函数
    整体去掉之后用例**仍然是绿的**。这正是 M3-FINDINGS §2.1 #7 说的"regex 太松"：
    断言必须绑定到**这个功能特有**的东西，不能绑定到通用 API 名。
    现在要求：存在一个会自我递归的轮询函数、它读 jobs 接口、且有次数上限。
    """
    blob = _js()
    assert "job_id" in blob, "undeploy 的返回里有 job_id，前端要用它轮询"
    m = re.search(r"function\s+(poll[A-Za-z]*)\s*\(([^)]*)\)\s*\{(.*?)\n\}",
                  blob, re.S)
    assert m, "找不到轮询函数（约定命名 poll*）——undeploy 是异步的，必须跟进 job 状态"
    name, body = m.group(1), m.group(3)
    assert name + "(" in body, (
        f"{name} 不自我递归——只查一次不叫轮询，慢一点的下线就永远显示不出结果")
    assert "/jobs" in body, f"{name} 没有去读 jobs 接口，它在轮询什么？"
    # 上限必须是一条**会拦住递归的比较**，不能只是"提到了某个常量名"：
    # 第一版写 `re.search(r"POLL_MAX|MAX_TRIES|tries", body)`，而函数签名里就有
    # 形参 `tries`——把 `if (n + 1 >= POLL_MAX_TRIES)` 改成 `if (false)` 之后
    # 用例仍然是绿的（M3-FINDINGS §2.1 #2 同形：字样在，语义不在）。
    assert re.search(r"(>=|>|<|<=)\s*[A-Z_]*MAX[A-Z_]*", body) or \
        re.search(r"[A-Z_]*MAX[A-Z_]*\s*(<=|<|>|>=)", body), (
        "轮询没有「与上限比较」的语句——后台任务卡住时会无限打接口")
    # 必须**延时**再递归：同步自递归是死循环（会卡死页面并瞬间打爆接口）。
    assert re.search(r"setTimeout|setInterval|requestIdleCallback", body), (
        f"{name} 里没有延时原语——自递归而不延时会同步死循环")
    rest = blob.replace(m.group(0), "")
    assert name + "(" in rest, f"{name} 定义了但没有任何地方调用它"
    # 调用点必须在下线提交之后（不然轮的不是这次下线）
    assert re.search(r"/undeploy['\"][^;]*;?[\s\S]{0,400}?" + name + r"\(",
                     rest), (
        f"{name} 不是在 undeploy 提交后被调用的——下线结果不会被跟进")


def test_deploying_site_derives_failure_badge_from_latest_job():
    """站点 status=DEPLOYING 且最新 job FAILED → **展示层**派生失败徽章。

    真源不写 site=FAILED 是有意的（重部署失败时站点仍在线服务旧版本，
    mark_job.py 只把 job 标 FAILED）。所以"部署失败"这个信息只能在前端
    由 jobs 派生，后端不会给。
    """
    blob = _js()
    assert re.search(r"DEPLOYING", blob), "看不到 DEPLOYING 分支"
    assert re.search(r"FAILED", blob), "看不到 FAILED 派生"


# ── ⑪ XSS：所有插值都要转义 ────────────────────────────────────────────

def test_all_interpolated_values_go_through_esc():
    """innerHTML 拼接里的动态值必须过 esc()。

    站点名 / 邮箱 / 错误串都来自用户或其他用户，未转义就是存储型 XSS，
    而控制台是**管理界面**——在这里执行脚本能改权限。

    **反向验证发现的缺陷**：第一版只检查 `${...}` 模板插值——而本前端全部用
    `+` 字符串拼接，模板插值一次都没用。也就是说它在检查一种**不存在的形态**，
    是一条空转的断言（注入 `` `<h2>${site.name}</h2>` `` 之后仍然绿，因为那行
    既没有 innerHTML 也没有 `+ '`）。两种形态现在都查。
    """
    blob = _js()
    assert "function esc(" in blob or "const esc =" in blob, "没有 esc 实现"

    # 自身会转义的包装：esc 之外，这些函数内部只产出受控内容或自己调 esc
    SAFE_WRAPPERS = ("esc(", "fmt(", "dur(", "when(", "initials(",
                     "statusBadge(", "jobBadge(", "roleTag(", "phaseText(",
                     "avatarStack(", "policySummary(",
                     # M5 Task 9b：`sparkline(item.pv7)` 的插值**全是数字**
                     # （宽高、`.toFixed(1)` 的坐标、`fmt()` 过的总数），产不出
                     # 调用方给的字符串。这条豁免不是白给的——
                     # test_frontend_boot 的 `sites-list-hostile` 场景往 pv7 里
                     # 塞可执行串真跑一遍，证明它渲染不出标签（同 toast/
                     # openModal 那条：被豁免的前提必须自己被盯住）。
                     "sparkline(",
                     # URL 段：进的是 href/fetch 路径，且本身就是编码函数
                     "encodeURIComponent(")
    # 前端自造、不含用户数据的片段（图标常量、已拼好的 HTML 变量、计数）
    SAFE_NAMES = r"^(ICON|html|out|opts|scopeToggle|searchBox|tabs|refs)\b"
    # 三元的两个分支都是字符串字面量 → 取值恒为字面量，用户数据进不来
    LITERAL_TERNARY = re.compile(
        r"""\?\s*(['"]).*?\1\s*:\s*(['"]).*?\2\s*\)?\s*$""", re.S)

    def unsafe(expr: str) -> bool:
        e = expr.strip()
        if not e or any(w in e for w in SAFE_WRAPPERS):
            return False
        if re.match(SAFE_NAMES, e) or LITERAL_TERNARY.search(e):
            return False
        # `.length` 是数字，`.map(esc)` 已逐项转义 —— 都进不去标记
        if re.search(r"\.length\b", e) and "esc(" not in e:
            return False
        if re.search(r"\.map\(\s*esc\s*\)", e):
            return False
        # 跨行拼接被切成的片段（自身还带着未闭合的三元/括号）无法在单行上判定；
        # 这些片段的内层表达式会在它们各自所在的行被单独检查，所以跳过而不是
        # 误报。判据：片段里含 `?` 但没有对应的 `:`，或括号明显不平衡。
        if e.count("(") != e.count(")") or ("?" in e and ":" not in e):
            return False
        # 只关心"读了某个对象的字段"这种形态——它才可能承载用户数据。
        # `row` 是 Key 列表的行（M4）：备注名 `row.name` 是用户自己填的，
        # 漏在这个清单外就等于新页面完全不在本条断言的覆盖面里。
        return bool(re.search(r"\b(site|job|admins?|item|row|v|d|res|err|state)\."
                              r"[a-z_]", e))

    def builds_html(line: str) -> bool:
        """这一行是否在拼 HTML。

        没有这个门槛的话，`toast('任务 ' + res.job_id + ' 正在执行')` 与
        `title: '转移「' + site.name + '」…'` 都会被误判——它们进的是 toast /
        openModal，那两个函数**内部**已经 esc 过（把参数在调用点再 esc 一次
        会变成双重转义，用户看到 `&amp;quot;`）。真正的风险面是直接拼标签。
        """
        return bool(re.search(r"<\s*/?[a-zA-Z]", line))

    def split_top_level_plus(line: str) -> list[str]:
        """按**顶层** `+` 切分（不进字符串、不进括号）。

        不能用 `re.findall(r"\\+\\s*([^+;]+?)\\s*\\+")`：那要求表达式**两侧都有**
        `+`，于是续行开头的表达式（前一行以 `+` 结尾）永远被跳过。实测就是这样
        漏掉的——`esc(job.error || '…')` 改成 `(job.error)` 之后用例仍然绿，
        而那正是把他人 job 的错误串未转义塞进 innerHTML 的形态。
        """
        parts, buf, depth, quote = [], [], 0, ""
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                buf.append(ch)
                if ch == "\\" and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in "'\"`":
                quote = ch
                buf.append(ch)
            elif ch in "([{":
                depth += 1
                buf.append(ch)
            elif ch in ")]}":
                depth -= 1
                buf.append(ch)
            elif ch == "+" and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
            i += 1
        parts.append("".join(buf))
        return parts

    bad = set()
    for raw_line in blob.splitlines():
        line = raw_line.strip()
        if not builds_html(line):
            continue
        # 形态 A：模板字符串插值
        for expr in re.findall(r"\$\{([^}]+)\}", line):
            if unsafe(expr):
                bad.add(expr.strip())
        # 形态 B：字符串拼接（本前端实际用的形态）
        if "+" in line:
            for expr in split_top_level_plus(line):
                e = expr.strip().rstrip(",;")
                if not e or e.startswith(("'", '"', "`")):
                    continue                    # 字面量片段
                if unsafe(e):
                    bad.add(e)
    assert not bad, (
        f"未转义就进 HTML（存储型 XSS，控制台里执行脚本能改权限）: "
        f"{sorted(bad)[:8]}")


def test_toast_and_modal_escape_their_text_arguments():
    """上一条把 toast/openModal 的**文本参数**当作安全的，这里证明它成立。

    不证明就是循环论证：上面靠"这些函数内部会 esc"来豁免调用点，如果哪天
    有人把 `esc(title)` 改成 `title`，上面那条不会红，而每个调用点都成了
    XSS 入口——豁免的前提必须自己被盯住。
    """
    blob = _js()
    toast_fn = re.search(r"function toast\([^)]*\)\s*\{(.*?)\n\}", blob, re.S)
    assert toast_fn, "找不到 toast 实现"
    assert re.search(r"esc\(\s*title\s*\)", toast_fn.group(1)), (
        "toast 的 title 没过 esc —— 每个 toast 调用点都变成 XSS 入口")
    assert re.search(r"esc\(\s*body\s*\)", toast_fn.group(1)), (
        "toast 的 body 没过 esc")

    modal_fn = re.search(r"function openModal\([^)]*\)\s*\{(.*?)\n\}", blob, re.S)
    assert modal_fn, "找不到 openModal 实现"
    for field in ("opts.title", "opts.desc"):
        assert re.search(r"esc\(\s*" + re.escape(field) + r"\s*\)",
                         modal_fn.group(1)), f"openModal 的 {field} 没过 esc"
    # body / footer 是**有意**的原始 HTML（调用方自己拼 + 自己 esc）。
    # 这不是漏洞而是契约，写在这里让后人不要"顺手补一个 esc"——那会把整段
    # 标记转义成可见的字符串。
    assert "opts.body" in modal_fn.group(1) and \
        not re.search(r"esc\(\s*opts\.body", modal_fn.group(1)), (
        "openModal 的 body 被 esc 了：它是调用方拼好的 HTML，转义后弹窗会显示源码")


# ── ⑪ purge 失败不得被显示成"永久删除完成"（Codex 审查 2026-08-10 P1-3）──

def test_job_label_covers_purge_failed():
    """PURGE_FAILED 是 undeploy 新增的真实终态，缺词条会显示成空徽章。"""
    m = re.search(r"const JOB_LABEL\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 JOB_LABEL"
    labeled = set(re.findall(r"""['"]?([A-Z_]+)['"]?\s*:""", m.group(1)))
    assert "PURGE_FAILED" in labeled, (
        "JOB_LABEL 缺 PURGE_FAILED——undeploy 在数据清理失败时写这个状态")


def test_purge_failed_is_registered_in_job_class():
    """徽章样式同样要有，否则状态可见但没有失败色（读起来像成功）。"""
    m = re.search(r"const JOB_CLASS\s*=\s*\{(.*?)\n\}", _js(), re.S)
    assert m, "找不到 JOB_CLASS"
    assert "PURGE_FAILED" in m.group(1), "JOB_CLASS 缺 PURGE_FAILED"


def test_polling_does_not_report_success_on_purge_failed():
    """轮询看到 PURGE_FAILED 时**不得**走"站点已下线"的成功分支。

    这是 P1-3 的用户可见面：用户勾了"下线并清除数据"，数据没清掉却看到
    删除成功。断言绑定到 PURGE_FAILED 在轮询函数里被单独处理。
    """
    blob = _js()
    m = re.search(r"function\s+pollUndeploy\s*\([^)]*\)\s*\{(.*?)\n\}",
                  blob, re.S)
    assert m, "找不到 pollUndeploy"
    body = m.group(1)
    assert "PURGE_FAILED" in body, (
        "pollUndeploy 没有分辨 PURGE_FAILED——它会落到 DELETED 的成功分支，"
        "把「数据没清干净」显示成「站点已下线」")
    # 成功分支不能把 PURGE_FAILED 一起收进去
    ok_branch = re.search(r"if\s*\(job\s*&&\s*\((.*?)\)\)", body)
    assert ok_branch, "找不到成功分支的条件"
    assert "PURGE_FAILED" not in ok_branch.group(1), (
        "PURGE_FAILED 被并进了成功分支")


# ── ⑫ API Key 页面（二期 M4，Task 9）────────────────────────────────────
#
# 这一组的每条都绑到**本功能特有**的东西上（M3-FINDINGS §2.17：绑 setTimeout /
# application/json 这类通用字样的断言删掉实现照样绿）。行为面（三态渲染、零请求、
# 转义）在 test_frontend_boot.py，线上通不通在 Task 11 的真机脚本，三层不可互相
# 替代。

def _fn_body(name: str, blob: str | None = None) -> str:
    """按大括号配平取出一个函数的**完整函数体**（字符串字面量不参与配平）。

    为什么不用本文件既有的 `function X\\([^)]*\\)\\s*\\{(.*?)\\n\\}`：那条靠"行首
    右花括号"收尾，遇到内嵌函数（pageKeys 里有两个内嵌 async 函数）会在第一个
    行首 `}` 处**提前截断**，于是所有断言只看了函数的前半段——看起来在查，
    实际查不到后半段里的东西。这正是"假绿"的一种。
    """
    src = _js() if blob is None else blob
    m = re.search(r"(?:async\s+)?function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{",
                  src)
    assert m, f"找不到函数 {name}() —— 实现改名了？本组断言会全部失效"
    i, depth, quote, out = m.end(), 1, "", []
    while i < len(src) and depth:
        ch = src[i]
        if quote:
            if ch == "\\":
                out.append(src[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if not depth:
                break
        out.append(ch)
        i += 1
    assert depth == 0, f"{name}() 的花括号没有配平——提取器坏了"
    return "".join(out)


def test_function_body_extractor_stops_at_the_matching_brace():
    """提取器自身的验证：不能在内嵌 `}` 处提前收尾，也不能溢出到下一个函数。

    两个方向都要证（M3-FINDINGS §2.11：一个只会说 clean 的检测器比没有更糟）。
    """
    src = ('function a() {\n  const o = { x: 1 };\n'
           '  function inner() { return "}"; }\n  return o;\n}\n'
           'function b() { return 2; }\n')
    body = _fn_body("a", src)
    assert "inner" in body and "return o;" in body, "在内嵌花括号处提前截断了"
    assert "return 2" not in body, "溢出到了下一个函数里"


def _keys_blob() -> str:
    """Key 页面全部函数体拼一起（作用域内查找用，避免与站点页的同名变量串味）。"""
    blob = _js()
    return "\n".join(_fn_body(n, blob) for n in
                     ("pageKeys", "keyRow", "keySwitchCard", "showNewKey",
                      "keysUndeployedCard", "apiKeyFeature"))


def test_api_key_feature_has_exactly_one_derivation_and_fails_closed():
    """`features.api_key` 只能有**一处**读法，且缺字段一律按 false。

    两处读法必然漂移，而这个不变量的漂移方向恰好是"某一处把 undefined 当成了
    开着"。`=== true` 而不是真值判断：后端换形态（比如给回字符串）时展示层
    宁可少给入口。
    """
    blob = _js()
    body = _fn_body("apiKeyFeature", blob)
    outside = blob.replace(body, "")
    assert ".features" not in outside, (
        "apiKeyFeature() 之外还有地方直接读 state.me.features —— "
        "这个判定必须只有一处（本仓库栽过几次「同一不变量被手抄多份」）")
    assert body.count("=== true") == 2, (
        "deployed / enabled 必须各自 `=== true` 判定（缺字段按 false），"
        f"实际只找到 {body.count('=== true')} 处")


def test_key_page_is_gated_on_deployed_never_on_enabled():
    """门禁判据是 `deployed`。用 `enabled` 做门禁 = **部署自锁**（Codex P1-5）。

    首次部署把哨兵行建成 `enabled=false`，此时若页面 disabled 且零请求，
    管理员就没有任何地方能把闸开回来。所以：`enabled` 不得出现在"第一个请求
    之前"的那段代码里。
    """
    body = _fn_body("pageKeys")
    first_call = min([body.index(t) for t in ("apiGet(", "api(") if t in body],
                     default=-1)
    assert first_call > 0, "pageKeys 里找不到任何请求 —— 页面还是占位的？"
    head = body[:first_call]
    assert re.search(r"if\s*\(!feat\.deployed\)\s*\{[^{}]*return", head, re.S), (
        "pageKeys 的开头没有「未部署就直接返回」的守卫")
    assert "enabled" not in head, (
        "请求之前就读了 enabled —— 这是把关闸当成未部署的形态，"
        "管理员会无处开闸（部署自锁）")


def test_nav_entry_is_gated_on_deployed_and_stays_visible_when_undeployed():
    """导航项同样按 deployed 分流；未部署时是**看得见的** disabled，不是删掉。"""
    body = _fn_body("renderNav")
    assert re.search(r"\.deployed", body), "导航没有按 deployed 分流"
    assert "enabled" not in body, (
        "导航读了 enabled —— 关闸时入口会消失，管理员进不去开关页面")
    assert "aria-disabled" in body, "未部署态的导航项缺 aria-disabled"
    assert re.search(r"""item\(\s*['"]#/keys['"]""", body), (
        "已部署时导航项必须是真链接（走 item()），否则页面进不去")


def test_keys_page_requests_nothing_when_component_is_not_deployed():
    """静态侧的"零请求"：守卫在**任何**请求之前，且守卫分支自己也不发请求。

    行为侧由 test_frontend_boot 的 keys-admin-undeployed 场景真跑一遍
    （间谍 fetch）。两条都要：静态的能指出是哪一行，行为的不依赖解析器正确。

    **第二段是反向验证逼出来的**：第一版只比"守卫的位置早于第一个请求"，于是
    把一次 `await apiGet('/api/keys')` 塞进守卫**分支内部**之后本用例仍然是绿的
    （只有 boot 那条真跑的用例红了）。这正是"守卫只覆盖了它自己设想的那个世界"
    ——顺序对了不等于那条分支干净。
    """
    body = _fn_body("pageKeys")
    anchor = "if (!feat.deployed) {"
    assert anchor in body, (
        f"pageKeys 里找不到 {anchor!r} —— 门禁形态变了，本用例的两段都失效")
    guard = body.index(anchor)
    for token in ("apiGet(", "api("):
        if token in body:
            assert body.index(token) > guard, (
                f"{token} 出现在 deployed 守卫之前 —— 未部署时也会打接口")
    # 守卫分支自身（到配平的右花括号为止）不得出现任何请求
    i, depth = body.index("{", guard), 0
    branch = []
    while i < len(body):
        branch.append(body[i])
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if not depth:
                break
        i += 1
    assert depth == 0, "守卫分支的花括号没配平"
    inner = "".join(branch)
    for token in ("apiGet(", "api(", "fetch("):
        assert token not in inner, (
            f"未部署的分支里有 {token} —— 组件没部署时那些端点可能 404/500，"
            f"请求它们只会把「平台没启用」翻译成一串看不懂的错误。分支: {inner!r}")
    # 未部署那张卡片是纯静态的（它渲染的是说明，不是数据）
    undeployed = _fn_body("keysUndeployedCard")
    assert "api" not in undeployed.replace("API Key", ""), (
        "未部署卡片里出现了请求")


def test_revoke_sends_key_id_and_never_the_plaintext():
    """吊销走 **`POST /api/keys/revoke`**，请求体只带 `key_id`。

    带明文等于把一个凭证放进请求体，沿途每一层日志都可能留下它；而 key_id 是
    刻意设计成"非秘密标识符"的（keygen 的注释）。

    **为什么是 POST 而不是 DELETE**（2026-08-13 真机隔离，见 `handler.ROUTES`
    下方注释）：CloudFront 不把 DELETE 的请求体转发到源站，而 Edge 已经按真实
    body 签了 SigV4 → Function URL 按空 body 校验 → 403，前端点"吊销"只会拿到
    一个与功能无关的签名错误。参数也不能搬进查询串——`key_id` 会因此进 CloudFront
    的访问日志。
    """
    blob = _js()
    m = re.search(
        r"""api\(\s*['"]POST['"]\s*,\s*['"]/api/keys/revoke['"]\s*,\s*\{([^}]*)\}""",
        blob)
    assert m, ("找不到 POST /api/keys/revoke 的调用 —— 吊销没接上？"
               "（若改回了 DELETE：那条路在 CloudFront 上必 403）")
    fields = set(re.findall(r"([a-z_]+)\s*:", m.group(1)))
    assert fields == {"key_id"}, (
        f"吊销请求体的字段是 {sorted(fields)}，必须**恰好**是 key_id")
    assert "plaintext" not in m.group(1), "吊销请求体里带了明文"


def test_create_shows_the_plaintext_once_with_a_will_not_show_again_warning():
    """创建结果里明文**完整显示一次** + 复制按钮 + "不再显示"警告。

    警告绑到一个常量上（而不是随手写在模板里）：这句话是这个功能的**契约**
    ——服务端只在创建响应里给一次明文，用户没抄下来就只能吊销重发。
    """
    blob = _js()
    warn = re.search(r"const\s+(KEY_[A-Z_]+)\s*=\s*'([^']*不再显示[^']*)'", blob)
    assert warn, "找不到含「不再显示」文案的常量 —— 用户不知道这是唯一一次"
    body = _fn_body("showNewKey", blob)
    assert warn.group(1) in body, (
        f"{warn.group(1)} 定义了但没用在明文展示区")
    assert re.search(r"esc\(\s*row\.plaintext\s*\)", body), (
        "明文没过 esc() 就进 innerHTML（明文是 base62，但形态一变就是注入点）")
    assert re.search(r"clipboard\.writeText\(\s*row\.plaintext\s*\)", body), (
        "明文展示区没有复制按钮 —— 手抄 19 个字符是错误率最高的一步")


def test_the_list_path_never_touches_the_plaintext():
    """列表渲染**不碰** plaintext：GET 根本不返回它（api._shape_key 的白名单）。

    列表里读一个永远 undefined 的字段，症状是页面显示 "undefined"，而更糟的
    版本是有人为了"让列表也能看 Key"去后端把明文加进 `_shape_key`。
    """
    for fn in ("keyRow", "pageKeys"):
        assert "plaintext" not in _fn_body(fn), (
            f"{fn}() 里出现了 plaintext —— 明文只在创建响应里存在一次")


def test_plaintext_is_never_persisted_and_never_put_in_a_url():
    """明文不进 localStorage / sessionStorage / URL。

    做法是**白名单**而不是"查 plaintext 有没有出现在 setItem 旁边"：后者被
    一个中间变量（`const pt = res.plaintext; sessionStorage.setItem(k, pt)`）
    就绕过了。把全部持久化点与全部 URL 写入点逐个列举，新增任何一处都会红，
    必须由人解释——这才是"这一类"缺陷的守卫（不是打地鼠）。
    """
    blob = _js()
    stored = {k.strip() for _, k in
              re.findall(r"(localStorage|sessionStorage)\.setItem\(\s*([^,]+),", blob)}
    assert stored == {"UPGRADE_MARK", "UPGRADE_ONCE", "UPGRADE_BACK"}, (
        f"持久化的键变了: {sorted(stored)} —— 只允许面板会话升级用的那三个常量。"
        "新增一处请在这里说明它存的是什么，并确认不含任何凭证")
    # 白名单只盖住了 setItem 这一条路。`localStorage['k'] = v` 与
    # `localStorage.k = v` 同样能落盘，而且上面那条完全看不见它们
    # （反向验证时确认过：注入 `localStorage['sb_last_key'] = row.plaintext`
    # 时白名单与下面的语句扫描**都**是绿的）。所以这里把访问形态也钉住。
    assert not re.search(r"(localStorage|sessionStorage)\s*\[", blob), (
        "用下标写 storage —— 绕过了本用例的键白名单，请改成 setItem 并登记键名")
    methods = set(re.findall(r"(?:localStorage|sessionStorage)\.(\w+)", blob))
    assert methods <= {"getItem", "setItem", "removeItem"}, (
        f"storage 上出现了别的访问形态: {sorted(methods - {'getItem', 'setItem', 'removeItem'})}"
        " —— 属性赋值同样会落盘，且不受键白名单约束")
    urls = {u.rstrip(") ;").strip() for u in re.findall(
        r"location\.(?:hash\s*=|href\s*=|assign\(|replace\()\s*([^;\n]*)", blob)}
    assert urls == {"hash", "back", "authOrigin() + '/console-session'",
                    "authOrigin() + '/logout'"}, (
        f"写入地址栏的表达式变了: {sorted(urls)} —— URL 会进浏览器历史、"
        "Referer 与代理日志，任何凭证都不能出现在这里")
    # 直指具体错法的一条（白名单已经能兜住，这条给出可读的失败原因）
    for stmt in re.split(r"[;\n]", blob):
        if "plaintext" not in stmt:
            continue
        assert not re.search(r"setItem|location\.|history\.|\bgo\(", stmt), (
            f"明文进了存储或地址栏: {stmt.strip()!r}")


def test_admin_switch_is_rendered_only_for_admins():
    """开关 UI 只在 `state.me.is_admin` 时渲染，admin 专属端点也只有 admin 请求。

    后端 `_require_admin` 会拒，所以这不是安全边界；但一个**看得见却一点就
    403** 的开关是照着来的 bug 报告，而且它会让非管理员以为自己能关闸。
    """
    blob = _js()
    card = _fn_body("keySwitchCard", blob)
    outside = blob.replace(card, "")
    # 区分**产出标记**（`id="sw-apikey"`）与**选取元素**（`#sw-apikey`）：
    # 绑定与写入路径当然要选它，那不是第二个渲染点。第一版没分清，于是被
    # `$('#sw-apikey')` 判红——假红要修断言而不是放宽它（M3-FINDINGS §2.16）。
    assert 'id="sw-apikey"' in card, "keySwitchCard() 没有产出开关控件"
    assert 'id="sw-apikey"' not in outside, (
        "开关控件的标记出现在 keySwitchCard() 之外 —— 它必须只有一个产出点，"
        "否则「只对 admin 渲染」这个判据要在多处各写一遍")
    assert re.search(r"state\.me\.is_admin\s*\?\s*keySwitchCard\(", blob), (
        "keySwitchCard() 的调用点没有被 state.me.is_admin 守住")
    page = _fn_body("pageKeys", blob)
    assert re.search(r"if\s*\(state\.me\.is_admin\)\s*\{[^}]*?"
                     r"/api/settings/api-key", page, re.S), (
        "GET /api/settings/api-key 不在 is_admin 分支里 —— 普通用户会吃一个 403")


def test_switch_note_says_closing_the_gate_kills_every_key_immediately():
    """开关旁必须写明"关闸后所有 Key 立即失效"（spec §4.3 第 4 条）。

    这是**平台级**动作：闸门在网关，关掉之后已经发出去的 Key 全部 401。
    管理员点它之前必须知道影响面不只是"新建的 Key"。
    """
    blob = _js()
    m = re.search(r"const\s+(KEY_[A-Z_]+)\s*=\s*'([^']*立即失效[^']*)'", blob)
    assert m, "找不到含「立即失效」的说明常量"
    card = _fn_body("keySwitchCard", blob)
    assert m.group(1) in card, f"{m.group(1)} 定义了但没显示在开关旁边"
    # 写入路径上必须有二次确认：一次误点让全平台的 Key 立刻不可用
    write = _fn_body("setKeySwitch", blob)
    assert re.search(r"window\.confirm|openModal\(", write), (
        "关闸没有二次确认 —— 一次误点会让全平台的 Key 立刻不可用")


def test_switch_write_sends_a_real_json_boolean():
    """`PUT /api/settings/api-key` 的 `enabled` 必须是真布尔。

    后端 `keystore.set_switch` 对 `"false"` / `0` / `null` 一律 400，正是因为
    `bool("false") is True` 这个陷阱（提交 `44aef8d` 的 P1-2）。前端别去试探它：
    发字符串会得到一个 400，而发 `"false"` 在任何放宽了的后端上都意味着"以为
    关了其实开着"。
    """
    blob = _js()
    m = re.search(r"""api\(\s*['"]PUT['"]\s*,\s*['"]/api/settings/api-key['"]\s*,\s*\{([^}]*)\}""",
                  blob)
    assert m, "找不到 PUT /api/settings/api-key 的调用"
    arg = m.group(1)
    assert re.search(r"enabled\s*:\s*(!|next\b|true\b|false\b|Boolean\()", arg), (
        f"enabled 的取值形态可疑（必须是布尔表达式）: {arg.strip()!r}")
    assert not re.search(r"""enabled\s*:\s*['"]""", arg), (
        "enabled 发的是字符串 —— 后端 400，且这正是「以为关了其实开着」的形态")
    assert "String(" not in arg, "enabled 被 String() 包了"


def _shape_key_fields() -> set[str]:
    """从 api.py 的 `_shape_key` 解析它真实返回的字段（同 _shape_site 的做法）。"""
    src = (PANEL / "api.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_shape_key")
    fields = {k.value for node in ast.walk(fn) if isinstance(node, ast.Dict)
              for k in node.keys
              if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    assert fields, "解析 _shape_key 失败"
    return fields


def test_frontend_reads_exactly_the_key_fields_the_backend_returns():
    """Key 的字段口径钉在 `_shape_key` 上：不多读（显示 undefined），不少读。

    "不少读"是功能要求的另一半（spec §4.3 第 4 条：备注名 / 前缀 / 创建时间 /
    最后使用 / 状态）——少一列就是用户分不清哪把 Key 该吊销。
    """
    backend = _shape_key_fields()
    used = set(re.findall(r"\brow\.([a-z_][a-z0-9_]*)", _keys_blob()))
    unknown = used - backend - {"plaintext"}
    assert not unknown, (
        f"前端读了 _shape_key 不返回的字段: {sorted(unknown)}（后端: {sorted(backend)}）")
    for must in ("name", "prefix", "created_at", "last_used_at", "revoked",
                 "key_id"):
        assert must in used, (
            f"列表没有用到 {must} —— 五列信息缺一列，用户分不清该吊销哪把")


def test_key_name_limit_matches_keystore_name_max():
    """前端的备注长度上限必须等于 `keystore.NAME_MAX`。

    前端放得更宽 → 用户填完才拿到 400（他刚想好的名字被吞掉）；前端更严 →
    平台能力被前端悄悄削掉。两侧都不该手抄一个数字，所以这里从真源核对。
    """
    src = (REPO / "site-builder" / "deployer" / "functions" / "keystore.py").read_text()
    m = re.search(r"^NAME_MAX = (\d+)", src, re.M)
    assert m, "keystore.py 里找不到 NAME_MAX"
    fe = re.search(r"const\s+KEY_NAME_MAX\s*=\s*(\d+)", _js())
    assert fe, "前端没有 KEY_NAME_MAX 常量"
    assert fe.group(1) == m.group(1), (
        f"前端上限 {fe.group(1)} ≠ keystore.NAME_MAX {m.group(1)}")


def test_globally_disabled_banner_text_exists_and_is_not_a_gate():
    """关闸提示是一句**说明**，不是门禁：它不得出现在任何 return / disabled 判据里。"""
    blob = _js()
    m = re.search(r"const\s+(KEY_[A-Z_]+)\s*=\s*'([^']*已被管理员全局关闸[^']*)'",
                  blob)
    assert m, "找不到「已被管理员全局关闸」的提示常量"
    page = _fn_body("pageKeys", blob)
    assert m.group(1) in page or m.group(1) in _keys_blob(), (
        f"{m.group(1)} 定义了但没有任何地方显示它")
    assert not re.search(r"if\s*\([^)]*\benabled\b[^)]*\)\s*\{[^{}]*return",
                         _keys_blob(), re.S), (
        "有以 enabled 为条件的提前返回 —— 关闸不该让页面不可用")


# ── ⑬ 站点列表的 PV 迷你趋势（二期 M5，Task 9b）──────────────────────────
#
# 这一节只有**源码存在性**这一条，它的分量有限：M5-FINDINGS §4.8 记的就是
# "整文件存在性检查证不了正确性，还可能从写下那天起就是死的"。真正的判据在
# test_frontend_boot 的 `sites-list*` 三个场景——那里真跑 siteCard + sparkline，
# 断言全 0 时渲染不出 NaN、且 pv7 里的可执行串渲染不出标签。
# 留着这一条是因为它便宜且指向明确（能直接说出"除零分支没了"）。

def test_sparkline_handles_all_zero_without_dividing_by_zero():
    blob = _js()
    assert "max === 0" in blob, "sparkline 没处理全 0（会产出 NaN 坐标）"


# ── ⑭ 409 的两类（S1 / M02）───────────────────────────────────────────
#
# `code` 是唯一横跨两端的判据，而两端 import 不了对方（Python Lambda / 浏览器
# JS）。所以字面量必然有两份——这一条把它们绑在一起，漂了当场红。
# 行为本身（追加的那句到底还在不在）由 test_frontend_boot 的 report-error 场景
# 真跑一遍；这里只锁"两份是同一个值"。

def test_policy_data_invalid_code_matches_the_backend_literal():
    import handler
    blob = _js()
    m = re.search(r"const\s+POLICY_DATA_INVALID_CODE\s*=\s*'([^']*)'", blob)
    assert m, "前端没有 POLICY_DATA_INVALID_CODE 常量"
    assert m.group(1) == handler.POLICY_DATA_INVALID_CODE, (
        f"前后端的 code 漂了：前端 {m.group(1)!r} / "
        f"后端 {handler.POLICY_DATA_INVALID_CODE!r}")
