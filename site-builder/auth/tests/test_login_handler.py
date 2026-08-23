import json
from unittest.mock import patch
import login_handler as lh

ENV = {"JWT_SECRET": "s3cret", "COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test"}


def _event(path, qs=None, cookies=None):
    return {"rawPath": path, "queryStringParameters": qs or {},
            "cookies": cookies or [], "requestContext": {"http": {"method": "GET"}}}


@patch.dict(lh.os.environ, ENV)
def test_login_redirects_to_hosted_ui():
    r = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith(ENV["COGNITO_DOMAIN"] + "/oauth2/authorize")
    assert "client_id=cid" in loc and "state=" in loc


@patch.dict(lh.os.environ, ENV)
def test_login_rejects_foreign_redirect():
    r = lh.handler(_event("/login", {"redirect": "https://evil.com/"}), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
@patch.object(lh, "_exchange_code", return_value={"email": "a@x.com", "name": "Alice",
                                                  "idp": "Feishu"})
def test_callback_sets_cookie_and_redirects(mock_ex):
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/page?tab=2"}),
                         None)
    import urllib.parse as up
    state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "https://app-x.example.com/page?tab=2"
    cookie = next(c for c in r["cookies"] if c.startswith("sb_session="))
    assert "Domain=.example.com" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_tampered_state():
    state = lh._encode_state("https://app-x.example.com/")
    body, _, sig = state.rpartition(".")
    import base64, json as _json
    payload = _json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["r"] = "https://evil.com/"
    forged = base64.urlsafe_b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
    # 补一个有效的 PKCE cookie：确保 400 是 state 验签失败导致的，而非缺 cookie
    pkce = lh._pkce_cookie("v", "n").split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": f"{forged}.{sig}"},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_callback_rejects_expired_state():
    import time
    with patch.object(lh.time, "time", return_value=time.time() - 600):
        state = lh._encode_state("https://app-x.example.com/")
    # 同上：补有效 cookie，锁定 400 的原因是 state 过期
    pkce = lh._pkce_cookie("v", "n").split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 400


@patch.dict(lh.os.environ, ENV)
def test_logout_clears_cookie():
    r = lh.handler(_event("/logout"), None)
    assert any("Max-Age=0" in c for c in r["cookies"])


# ---- M3: /console-session（面板会话升级入口）----

@patch.dict(lh.os.environ, ENV)
def test_console_session_issues_code_and_redirects_to_console():
    """有效顶域会话 → 302 带 code 到 console callback。"""
    import session
    token = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session",
                          cookies=[f"sb_session={token}"]), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith("https://console.example.com/api/session-callback?code=")
    import urllib.parse
    code = urllib.parse.unquote(loc.split("code=", 1)[1])
    claims = session.verify_upgrade_code(code, ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_without_session_goes_to_login_with_redirect_back():
    r = lh.handler(_event("/console-session"), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith("https://auth.example.com/login?redirect=")
    # 登录完必须回到 /console-session：指回 console 首页的话，用户登录后
    # 仍然没有面板会话，面板还是 401（死循环的用户体验）
    assert "console-session" in loc


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_tampered_session_cookie():
    """签名不过的 sb_session 不得换出 code（否则等于伪造任意身份）。"""
    import session
    bad = session.mint_session_jwt("u@x.com", "U", "wrong-secret")
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={bad}"]), None)
    assert r["statusCode"] == 302
    assert "/login" in r["headers"]["Location"], "篡改的会话竟然换出了 code"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_expired_session_cookie():
    import session
    old = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"],
                                   ttl_seconds=-10)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={old}"]), None)
    assert "/login" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_console_session_does_not_set_cookies_or_body():
    """code 只出现在 Location，不进 Set-Cookie / body（缩小泄漏面）。"""
    import session
    token = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session",
                          cookies=[f"sb_session={token}"]), None)
    assert not r.get("cookies"), "升级码流程不该设任何 cookie"
    assert not r.get("body")
    assert r["headers"].get("cache-control") == "no-store"


@patch.dict(lh.os.environ, ENV)
def test_console_session_login_redirect_passes_its_own_safety_check():
    """构造出的 redirect 必须能通过 _is_safe_redirect，否则用户拿到 400。"""
    r = lh.handler(_event("/console-session"), None)
    import urllib.parse
    target = urllib.parse.unquote(
        r["headers"]["Location"].split("redirect=", 1)[1])
    assert lh._is_safe_redirect(target), f"{target} 会被 /login 判为非法"


@patch.dict(lh.os.environ, ENV)
def test_console_session_refuses_an_upgrade_code_as_the_cookie():
    """把升级码当 sb_session 递进 /console-session 不得换出新码。

    这是链式续期的修复点（M05）：`/console-session` 用的就是通用 verifier，
    不查 typ 时递一个升级码进去即可换出**新的** 60s 升级码，无限续期
    ——「60 秒 + 一次性」两个属性同时失效。已实测连续续期成功 3 轮。

    注意这一半**与 `require_idp_claim` 无关**：`auth` 子域注册为
    `require_auth=False`，Edge 根本不 gate 这个端点，是 auth 服务自己验 cookie。

    密钥必须用 ENV["JWT_SECRET"]：换个密钥的话签名检查就先拦下了，
    这条用例即便在缺陷仍在时也会绿——那是假绿，证明不了 typ 检查生效。
    """
    import session
    code = session.mint_upgrade_code("v@example.test", ENV["JWT_SECRET"])
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={code}"]), None)
    assert r["statusCode"] == 302
    assert "/login?redirect=" in r["headers"]["Location"], (
        "应被当成无有效会话、引导去登录，而不是换出新的升级码")


# ---- M06 的 auth 侧一半：同名 sb_session 遮蔽（/console-session）----
#
# Edge 的 `_get_cookies` 逐个验，但 `auth` 子域注册为 `require_auth=False`，
# Edge 根本不 gate `/console-session`——那一侧的修复覆盖不到这里。
# 缺陷形态：站点 JS 写 `sb_session=garbage; domain=.{base}; path=/console-session`
# 新建第二条 cookie（HttpOnly 只护住同 path 的那条），RFC 6265 §5.4.2 让它先发。
# 只取第一条 ⇒ 控制台写操作持久 302 登录循环（重新登录只重写 Path=/ 那条）。

SHADOW = "garbage.garbage.garbage"


def _console_session(cookies):
    return lh.handler(_event("/console-session", cookies=cookies), None)


def _issued_code(r) -> str:
    """→ Location 里的升级码；不是"换出了 code"的响应则返回 ""。"""
    loc = r["headers"]["Location"]
    if "/api/session-callback?code=" not in loc:
        return ""
    import urllib.parse
    return urllib.parse.unquote(loc.split("code=", 1)[1])


@patch.dict(lh.os.environ, ENV)
def test_console_session_survives_a_shadowing_cookie_sent_first():
    """垃圾值排在合法会话**之前**时仍须换出 code（M06 回归）。

    这是本用例组的核心：修复前 handler 取到第一条就 break，于是 302 去登录，
    而登录回调只重写 `Path=/` 的那条 ⇒ 回到本入口继续失败，死循环。
    """
    import session
    good = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={SHADOW}", f"sb_session={good}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com", (
        "遮蔽 cookie 排在前面就换不出 code —— 控制台写操作会陷入登录循环")


@patch.dict(lh.os.environ, ENV)
def test_console_session_still_works_when_shadow_is_sent_last():
    """正序（合法在前）的正对照：证明上一条不是靠"顺序反了"才绿的。"""
    import session
    good = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={good}", f"sb_session={SHADOW}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_when_every_candidate_is_invalid():
    """负对照：逐个验不等于放宽——全部无效时仍须去登录。

    没有这一条，"把所有候选都当通过"的实现也会让上面两条绿。
    """
    import session
    wrong_secret = session.mint_session_jwt("u@x.com", "U", "wrong-secret")
    r = _console_session([f"sb_session={SHADOW}",
                          f"sb_session={wrong_secret}",
                          "sb_session="])
    assert r["statusCode"] == 302
    assert "/login?redirect=" in r["headers"]["Location"]
    assert not _issued_code(r)


@patch.dict(lh.os.environ, ENV)
def test_console_session_shadowed_by_an_upgrade_code_picks_the_real_session():
    """M05 + M06 合起来：遮蔽项是**验签通过的升级码**时，胜出者必须是真会话。

    升级码与会话用同一密钥、同一线格式，所以它是"签名合法但 typ 不对"的候选。
    逐个验的判据若写成"第一个验签通过的"（漏了 typ），这里会拿升级码的身份
    换出新码 —— 正是 M05 那条无限续期。
    """
    import session
    good = session.mint_session_jwt("owner@x.com", "O", ENV["JWT_SECRET"])
    code = session.mint_upgrade_code("attacker@x.com", ENV["JWT_SECRET"])
    r = _console_session([f"sb_session={code}", f"sb_session={good}"])
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "owner@x.com", (
        "升级码被当成会话了 —— typ 检查没生效")


@patch.dict(lh.os.environ, ENV)
def test_session_cookie_candidates_returns_every_same_name_value():
    """机制层断言：helper 必须返回**全部**同名值，且保持 header 顺序。

    调用方的正确性依赖"拿到的是全集"；只断言端点行为的话，一个"取最后一条"
    的实现也能让上面几条绿，而按位置挑仍然是把缺陷换个方向。
    """
    ev = _event("/console-session",
                cookies=[f"sb_session={SHADOW}", "other=x",
                         "sb_session=second", " sb_session=third"])
    assert lh._session_cookie_candidates(ev) == [SHADOW, "second", "third"]
    assert lh._session_cookie_candidates(_event("/console-session")) == []

# ---- auth 侧也不许截断候选（与 Edge 那半边同一条不变量）----
#
# Codex 复审第二轮就提过这一半，我上一轮**只修了 Edge**：给 Edge 加了 AST 截断
# 守卫和按传输层预算生成的行为用例，auth 这边仍然只有三枚候选的用例。实测在
# `/console-session` 的循环上加 `[:8]`，155 条 auth 用例**全绿**。
# 这恰好又犯了 M06 本身那个毛病——同一条不变量存在两份实现，只修了一份。
#
# **为什么不共用 Edge 那份检测器**：Edge 是 Lambda@Edge 的**单文件注入产物**
# （不支持环境变量、配置靠 CDK 字符串替换），它没法 import 任何共享模块——这也
# 正是会话验签在两边各写一份、并靠"必须字节级同步"的注释约束的原因。所以这里
# 是刻意的第二份**检测器**，两边的失败信息都点名对侧，避免只改一边。

# CloudFront 对整个请求（请求行 + 全部 header）的上限，AWS 文档给的是 32,768 字节。
_MAX_REQUEST_BYTES = 32 * 1024
_HEADROOM_BYTES = 2048


def _max_candidate_burst(good: str) -> tuple:
    """总请求不超限的前提下塞进最多枚遮蔽候选 → (cookies 列表, 遮蔽条数)。

    **用最短合法形态 `sb_session=`**（空值）：换成带值的形态只塞得下一半多，
    于是一个 2000 的上限能从底下溜过去（Edge 那半边实测过）。
    """
    fixed = len("GET /console-session HTTP/1.1\r\nHost: auth.example.com\r\n"
                "Cookie: ") + len(f"; sb_session={good}") + _HEADROOM_BYTES
    n = (_MAX_REQUEST_BYTES - fixed) // (len("sb_session=") + 2)
    return ["sb_session="] * n + [f"sb_session={good}"], n


@patch.dict(lh.os.environ, ENV)
def test_console_session_tries_every_candidate_that_can_physically_arrive():
    """真会话排在**能到达的最后一枚**时仍须换出 code（auth 侧的无上限行为断言）。

    规模按传输层预算推、不写魔数：任何低于它的有限上限都会让这条红。
    """
    import session
    good = session.mint_session_jwt("u@x.com", "U", ENV["JWT_SECRET"])
    cookies, n = _max_candidate_burst(good)
    assert n > 2000, f"只造出 {n} 枚遮蔽候选，压不过一个 2000 的上限"

    assert len(lh._session_cookie_candidates(_event("/console-session", cookies=cookies))) \
        == n + 1, "_session_cookie_candidates 没返回全部候选——截断可能藏在它内部"
    r = _console_session(cookies)
    claims = session.verify_upgrade_code(_issued_code(r), ENV["JWT_SECRET"])
    assert claims and claims["email"] == "u@x.com", (
        f"第 {n + 1} 枚候选没被尝试——有人在 auth 侧引入了条数上限，M06 复活了")


def _auth_truncation_offenders(src: str) -> list:
    """auth 侧候选被截断的全部形态 → 原因列表；空列表 = 没有截断。

    三个位置与 Edge 那份一一对应：`/console-session` 的循环迭代对象、循环体里的
    计数式提前退出、以及 `_session_cookie_candidates` 本体内部的 break/提前 return。
    """
    import ast

    tree = ast.parse(src)
    bad = []

    def is_source_call(node) -> bool:
        return (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "_session_cookie_candidates")

    handler = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "handler")
    aliases = {t.id for node in ast.walk(handler) if isinstance(node, ast.Assign)
               and is_source_call(node.value)
               for t in node.targets if isinstance(t, ast.Name)}
    # 候选别名在任何地方被下标/切片都算截断（`del cands[20:]` 这一族发生在调用与
    # 循环**之间**，只查迭代对象时看不见）。与 Edge 的 `_candidate_alias_subscripts`
    # 对称。
    for node in ast.walk(handler):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                and node.value.id in aliases):
            bad.append(f"候选别名被下标/切片：{ast.unparse(node)[:60]}")

    loops = [n for n in ast.walk(handler) if isinstance(n, ast.For)
             and any(is_source_call(x) or (isinstance(x, ast.Name) and x.id in aliases)
                     for x in ast.walk(n.iter))]
    assert loops, ("在 handler 里找不到遍历 sb_session 候选的 for 循环"
                   "——本条空转（循环被改写成别的形态了？）")
    for loop in loops:
        it = loop.iter
        if isinstance(it, ast.Subscript):
            bad.append(f"循环迭代对象被切片：{ast.unparse(it)[:60]}")
        elif not (isinstance(it, ast.Name) or is_source_call(it)):
            bad.append(f"循环迭代对象被包了一层：{ast.unparse(it)[:60]}")
        for sub in ast.walk(loop):
            if isinstance(sub, ast.Compare) and any(
                    isinstance(c, ast.Constant) and isinstance(c.value, int)
                    and not isinstance(c.value, bool) for c in sub.comparators):
                bad.append(f"循环体里按计数提前退出：{ast.unparse(sub)[:60]}")

    # 来源函数四条，与 Edge 的 `_source_fn_offenders` 一一对应。第 ③ ④ 条是第四轮
    # 复审的绕过：`return out[:N] if ... else out` 与 `if k == name and len(out) < N`
    # 都满足"无 break、单 return、在末尾"，前两条全过。
    label = "_session_cookie_candidates"
    src_fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == label)
    for sub in ast.walk(src_fn):
        if isinstance(sub, ast.Break):
            bad.append(f"{label} 内部有 break —— 截断藏在来源函数里")
        if isinstance(sub, ast.Compare) and any(
                isinstance(c, ast.Constant) and isinstance(c.value, int)
                and not isinstance(c.value, bool) for c in sub.comparators):
            bad.append(f"{label} 内部按计数判断：{ast.unparse(sub)[:60]}"
                       " —— 计数守卫就是截断")

    # 累积变量名**推导**，不写死 `out`（写死会在改名后静默失效）
    accumulators = {n.func.value.id for n in ast.walk(src_fn)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "append"
                    and isinstance(n.func.value, ast.Name)}
    assert accumulators, (f"在 {label} 里找不到任何 `X.append(...)` —— 本条空转"
                          "（累积方式被改写了？）")

    returns = [n for n in ast.walk(src_fn) if isinstance(n, ast.Return)]
    if len(returns) != 1:
        bad.append(f"{label} 有 {len(returns)} 个 return（应恰好 1 个、在末尾）")
        return bad
    ret = returns[0]
    if src_fn.body[-1] is not ret:
        bad.append(f"{label} 的 return 不在末尾 —— 提前 return 即截断")
    if not isinstance(ret.value, ast.Name):
        bad.append(
            f"{label} 的返回表达式不是裸的累积变量，而是 "
            f"{ast.unparse(ret.value)[:70]} —— 切片/条件表达式/包装一层都可能丢掉"
            "候选。要改返回表达式，先证明它保持全集，别放宽这条断言。")
    elif ret.value.id not in accumulators:
        bad.append(f"{label} 返回的 `{ret.value.id}` 不是 append 的接收者"
                   f"（累积变量是 {sorted(accumulators)}）—— 中间变量可能已被截断")
    return bad


def test_console_session_candidates_are_not_truncated_anywhere():
    """结构断言：auth 侧候选在消费侧与来源侧都不得被截断。

    与 Edge 的 `test_candidates_are_not_truncated_anywhere` 对称。行为断言只能
    证明"上限不低于当前造得出的量级"；这条与规模无关，且直接说出截断在哪。
    """
    import inspect

    offenders = _auth_truncation_offenders(inspect.getsource(lh))
    assert not offenders, (
        "auth 侧候选被截断了：\n  " + "\n  ".join(offenders)
        + "\n界应由 Cookie 头体积给，不由条数常量给；Edge 那半边有一条对称的守卫。")


def test_auth_truncation_detector_bites_each_known_bypass():
    """**常驻反向验证**：三种绕过形态，auth 侧检测器必须逐个咬住。"""
    import inspect

    src = inspect.getsource(lh)
    assert not _auth_truncation_offenders(src), "当前源码本该干净——本条前提不成立"

    bypasses = {
        "直接切片": (
            "        for candidate in _session_cookie_candidates(event):",
            "        for candidate in _session_cookie_candidates(event)[:8]:"),
        "中间变量切片": (
            "        claims = None\n"
            "        for candidate in _session_cookie_candidates(event):",
            "        cands = _session_cookie_candidates(event)\n"
            "        claims = None\n        for candidate in cands[:64]:"),
        "来源函数内部计数 return": (
            "        if name.strip() == \"sb_session\":\n            out.append(value)",
            "        if name.strip() == \"sb_session\":\n            out.append(value)\n"
            "            if len(out) >= 2000:\n                return out"),
        # 下面两种是第四轮复审的绕过：都满足"无 break、单 return、在末尾"
        "来源函数末尾切片 return": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    return out[:2400]"),
        "计数守卫挪到 append 处": (
            "        if name.strip() == \"sb_session\":\n            out.append(value)",
            "        if name.strip() == \"sb_session\" and len(out) < 20:\n"
            "            out.append(value)"),
        "del 别名切片": (
            "        claims = None\n"
            "        for candidate in _session_cookie_candidates(event):",
            "        cands = _session_cookie_candidates(event)\n        del cands[20:]\n"
            "        claims = None\n        for candidate in cands:"),
    }
    for name, (old, new) in bypasses.items():
        assert old in src, f"变异锚点找不到（{name}）——本条空转"
        assert _auth_truncation_offenders(src.replace(old, new, 1)), \
            f"auth 侧检测器没咬住这种绕过：{name}"
