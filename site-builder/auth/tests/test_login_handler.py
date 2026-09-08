import json
from unittest.mock import patch

import pytest
import login_handler as lh
import session
import upgrade_code_vectors as v

ENV = {"COGNITO_DOMAIN": "https://sso.auth.us-east-1.amazoncognito.com",
       "CLIENT_ID": "cid", "CLIENT_SECRET": "csec", "BASE_DOMAIN": "example.com",
       "USER_POOL_ID": "us-east-1_test",
       # state 与 pkce cookie 的 HMAC 用 auth 私有的 login-flow secret（只下发参数名，值在 conftest 的假 SSM）
       "LOGIN_FLOW_SECRET_PARAM": "/site-builder/login-flow-secret",
       # 3c-final：两个 family 的 RS 行（kid / alg / role / key_arn / spki_sha256，**没有密钥材料**）；
       # 公钥由 conftest 的假 KMS 按 key_arn 给，私钥只在 upgrade_code_vectors 里。
       "SESSION_KEYS_JSON": v.session_keys_json((v.SITE_KID, "current"), (v.CONSOLE_KID, "current")),
       # 夹具签发器默认关（/fixture-session 在 ENV 下必须 404）；开着那一侧在 test_fixture_session.py
       "FIXTURE_ISSUER": "off"}


def _use_fake_ssm(monkeypatch):
    """autouse 夹具已经装好假 SSM；这里只清缓存，保留调用点以示意图。"""
    del monkeypatch
    lh._secret_cache.clear()


def _site_session(email="u@x.com", name="U", *, key=v.SITE_KEY, kid=v.SITE_KID, ttl=600, **kw):
    return session.mint_token(kid=kid, sign=v.signer(key), token_use="site-session", email=email,
                              ttl_seconds=ttl, name=name, idp="Feishu", auth_via="TokenGeneration_HostedAuth", **kw)


def _upgrade_claims(code: str) -> dict:
    claims, outcome = session.verify_token(code, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert claims, outcome
    return claims


def _upgrade_code_under_the_site_key(email="v@example.test") -> str:
    """一枚 `console-upgrade` token，但用 **site** family 的 kid 与私钥签。

    `/console-session` 只能靠 `token_use` 拒它（M05 的链式续期）。用真的 console family key 签的话，
    site allowlist 里没有那个 kid ⇒ 先被 unknown_kid 拦下，即便 `token_use` 检查整个没了这条也绿——假绿。
    """
    return session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY),
                              token_use="console-upgrade", email=email, ttl_seconds=60)


def _last_verify_outcome(capsys) -> str:
    """最后一行 `session_verify` 埋点的 outcome（spec §8 的固定词表）。"""
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{") and '"session_verify"' in line]
    assert rows, "没有 session_verify 埋点"
    return rows[-1]["outcome"]


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


def _login_state(login_response) -> str:
    """从 /login 的 302 Location 里取出原始 state 串（URL 解码后）。"""
    import urllib.parse as up
    return up.unquote(login_response["headers"]["Location"].split("state=")[1].split("&")[0])


def _state_redirect(login_response) -> str:
    """解签 /login 发出的 state，返回它承载的 redirect（只用生产解码器，不自己拼）。"""
    decoded = lh._decode_state(_login_state(login_response))
    assert decoded is not None, "state 解签失败"
    return decoded


@patch.dict(lh.os.environ, ENV)
def test_login_without_redirect_defaults_to_the_console():
    """直接打开 /login（不带 redirect）时，缺省落点是控制台，不是 apex。

    平台分发的 alias 与 DNS 都只有 `*.{base}` 通配，通配不匹配 apex ⇒ apex 在本平台上
    不存在。缺省指向它会让"登录成功"在浏览器里看起来像连接被关闭（merged review §9 3h）。
    """
    r = lh.handler(_event("/login"), None)
    assert r["statusCode"] == 302
    assert _state_redirect(r) == "https://console.example.com/"


@patch.dict(lh.os.environ, ENV)
def test_login_with_an_explicit_redirect_keeps_it_verbatim():
    """带 redirect 时缺省值不参与：state 里就是调用方给的那个 URL，一个字节不变。"""
    target = "https://app-x.example.com/page?tab=2"
    r = lh.handler(_event("/login", {"redirect": target}), None)
    assert r["statusCode"] == 302
    assert _state_redirect(r) == target


@pytest.mark.parametrize("bad", [
    "https://console.example.com.evil.com/",   # 后缀伪装：以平台域开头、落在别人域上
    "https://evil.com/?next=console.example.com",
    "http://console.example.com/",             # 非 https
    "https://console.example.com\\@evil.com/",  # 反斜杠：urlparse 与浏览器分歧
    "https://notexample.com/",                  # 后缀比较丢了点（endswith(base)）时会放行
], ids=["suffix-lookalike", "host-in-query", "plain-http", "backslash", "dropped-dot"])
@patch.dict(lh.os.environ, ENV)
def test_login_redirect_allowlist_is_unchanged_by_the_console_default(bad):
    """缺省值改到 console 不放宽白名单：显式 redirect 仍只许 https + 平台域。"""
    r = lh.handler(_event("/login", {"redirect": bad}), None)
    assert r["statusCode"] == 400


@pytest.mark.parametrize("login_qs,landing", [
    ({"redirect": "https://app-x.example.com/page?tab=2"}, "https://app-x.example.com/page?tab=2"),
    # 用户可见的那一跳：不带 redirect 走完整流程，/callback 的 302 落在控制台首页（§9 3h）
    (None, "https://console.example.com/"),
], ids=["explicit-redirect", "bare-login-lands-on-console"])
@patch.dict(lh.os.environ, ENV)
@patch.object(lh, "_exchange_code", return_value={"email": "a@x.com", "name": "Alice",
                                                  "idp": "Feishu"})
def test_callback_sets_cookie_and_redirects(mock_ex, login_qs, landing):
    r_login = lh.handler(_event("/login", login_qs), None)
    state = _login_state(r_login)
    pkce = next(c for c in r_login["cookies"]
                if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    r = lh.handler(_event("/callback", {"code": "abc", "state": state},
                          cookies=[pkce]), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == landing
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
    token = _site_session("u@x.com", "U")
    r = lh.handler(_event("/console-session",
                          cookies=[f"sb_session={token}"]), None)
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc.startswith("https://console.example.com/api/session-callback?code=")
    import urllib.parse
    code = urllib.parse.unquote(loc.split("code=", 1)[1])
    claims = _upgrade_claims(code)
    assert claims["email"] == "u@x.com"


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
    bad = _site_session(key=v.SITE_PREV_KEY)      # kid 在 allowlist 里，签名是第三把 key
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={bad}"]), None)
    assert r["statusCode"] == 302
    assert "/login" in r["headers"]["Location"], "篡改的会话竟然换出了 code"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_expired_session_cookie():
    old = _site_session(ttl=-10)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={old}"]), None)
    assert "/login" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_console_session_does_not_set_cookies_or_body():
    """code 只出现在 Location，不进 Set-Cookie / body（缩小泄漏面）。"""
    token = _site_session("u@x.com", "U")
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

    kid 与私钥必须都用 site family 的：换成 console family 的话 kid 查表就先拦下了，
    这条用例即便在缺陷仍在时也会绿——那是假绿，证明不了 token_use 检查生效。
    """
    code = _upgrade_code_under_the_site_key("v@example.test")
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
    good = _site_session()
    r = _console_session([f"sb_session={SHADOW}", f"sb_session={good}"])
    claims = _upgrade_claims(_issued_code(r))
    assert claims["email"] == "u@x.com", (
        "遮蔽 cookie 排在前面就换不出 code —— 控制台写操作会陷入登录循环")


@patch.dict(lh.os.environ, ENV)
def test_console_session_still_works_when_shadow_is_sent_last():
    """正序（合法在前）的正对照：证明上一条不是靠"顺序反了"才绿的。"""
    good = _site_session()
    r = _console_session([f"sb_session={good}", f"sb_session={SHADOW}"])
    assert _upgrade_claims(_issued_code(r))["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_when_every_candidate_is_invalid():
    """负对照：逐个验不等于放宽——全部无效时仍须去登录。

    没有这一条，"把所有候选都当通过"的实现也会让上面两条绿。
    """
    wrong_key = _site_session(key=v.SITE_PREV_KEY)
    r = _console_session([f"sb_session={SHADOW}",
                          f"sb_session={wrong_key}",
                          "sb_session="])
    assert r["statusCode"] == 302
    assert "/login?redirect=" in r["headers"]["Location"]
    assert not _issued_code(r)


@patch.dict(lh.os.environ, ENV)
def test_console_session_shadowed_by_an_upgrade_code_picks_the_real_session():
    """M05 + M06 合起来：遮蔽项是**验签通过的升级码**时，胜出者必须是真会话。

    这里的升级码用 site family 的 kid 与私钥签，所以它是"kid 认得、签名过得去、token_use 不对"的
    候选。逐个验的判据若写成"第一个验签通过的"（漏了 token_use），这里会拿升级码的身份换出新码
    —— 正是 M05 那条无限续期。
    """
    good = _site_session("owner@x.com", "O")
    code = _upgrade_code_under_the_site_key("attacker@x.com")
    r = _console_session([f"sb_session={code}", f"sb_session={good}"])
    assert _upgrade_claims(_issued_code(r))["email"] == "owner@x.com", (
        "升级码被当成会话了 —— token_use 检查没生效")


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
    good = _site_session()
    cookies, n = _max_candidate_burst(good)
    assert n > 2000, f"只造出 {n} 枚遮蔽候选，压不过一个 2000 的上限"

    assert len(lh._session_cookie_candidates(_event("/console-session", cookies=cookies))) \
        == n + 1, "_session_cookie_candidates 没返回全部候选——截断可能藏在它内部"
    r = _console_session(cookies)
    claims = _upgrade_claims(_issued_code(r))
    assert claims["email"] == "u@x.com", (
        f"第 {n + 1} 枚候选没被尝试——有人在 auth 侧引入了条数上限，M06 复活了")


def _accumulator_offenders(fn, label: str) -> list:
    """累积变量的**能力白名单**：只允许三种用法，其余一律是截断嫌疑。

    这是判据的第六版，也是第一次不再枚举"截断长什么样"。前五版都在拉黑具体写法
    （切片 → islice → 整数比较 → return 的位置 → `len`/`+=`/重绑），每一版都被下一种
    拼写绕过；最后一轮漏的是**原地变异**：

        if request.get("uri", "").startswith("/api/private"):
            del out[20:]
        return out

    它没有 `len`、没有 `+=`、没有 break、累积变量只赋值一次、return 恰好一个且在末尾、
    返回的还是裸 `out` —— 上一版六条检查一条都不命中，而 `/api/private/...` + 30 条
    同名 cookie 已经恢复 302。同族还有 `out[:] = out[:20]`、`out.clear()`、`out.pop()`、
    `_cap(out)`（把 out 交给别人去截）。

    所以反过来写：**列出允许的三件事，其余全红**。
      ① 作为初始化赋值的目标（`out = []`），且全函数只赋值这一次；
      ② 作为 `.append(...)` 的接收者；
      ③ 作为**最终那个** return 的值（裸变量，不带任何包装）。
    读长度、取下标、删元素、就地赋值、传给别的函数、参与条件表达式……全部不在白名单
    里。要新增一种合法用法，得先证明它保持全集，再往白名单里加一条并说明理由。
    """
    import ast

    accumulators = {n.func.value.id for n in ast.walk(fn)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "append"
                    and isinstance(n.func.value, ast.Name)}
    assert accumulators, (f"在 {label} 里找不到任何 `X.append(...)` —— 本条空转"
                          "（累积方式被改写了？）")

    parents = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    final_ret = returns[0] if len(returns) == 1 else None

    bad = []
    for acc in sorted(accumulators):
        inits = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == acc for t in n.targets)]
        if len(inits) != 1:
            bad.append(f"{label} 的累积变量 `{acc}` 被赋值 {len(inits)} 次"
                       "（应只有初始化那一次）—— 重绑同名变量同样是截断")
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Name) and node.id == acc):
                continue
            parent = parents.get(id(node))
            # ① 初始化赋值的目标
            if (isinstance(parent, ast.Assign) and parent in inits
                    and any(t is node for t in parent.targets)):
                continue
            # ② `.append(...)` 的接收者
            if (isinstance(parent, ast.Attribute) and parent.attr == "append"
                    and parent.value is node
                    and isinstance(parents.get(id(parent)), ast.Call)
                    and parents[id(parent)].func is parent):
                continue
            # ③ 最终 return 的值（必须是裸变量）
            if final_ret is not None and parent is final_ret and final_ret.value is node:
                continue
            bad.append(
                f"{label} 的累积变量 `{acc}` 出现在白名单之外的位置："
                f"{ast.unparse(parent)[:70]} —— 只允许"
                "「初始化一次 / .append() 的接收者 / 最终裸 return」三种用法，"
                "其余都可能丢掉候选")
    return bad


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
        # 禁"计数"本身（`+=` 与 `len()`），不是"与整数字面量比较"——后者用
        # 命名常量就绕过去了。与 Edge 侧同法。
        for sub in ast.walk(loop):
            if isinstance(sub, ast.AugAssign):
                bad.append(f"循环体里有计数器自增：{ast.unparse(sub)[:60]}")
            if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "len":
                bad.append(f"循环体里调用了 len()：{ast.unparse(sub)[:60]}")

    # 来源函数四条，与 Edge 的 `_source_fn_offenders` 一一对应。第 ③ ④ 条是第四轮
    # 复审的绕过：`return out[:N] if ... else out` 与 `if k == name and len(out) < N`
    # 都满足"无 break、单 return、在末尾"，前两条全过。
    label = "_session_cookie_candidates"
    src_fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == label)
    for sub in ast.walk(src_fn):
        if isinstance(sub, ast.Break):
            bad.append(f"{label} 内部有 break —— 截断藏在来源函数里")
        # 禁 `len(...)` 本身（命名常量上限会绕过"整数字面量比较"那种写法）
        if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "len":
            bad.append(f"{label} 内部调用了 len()：{ast.unparse(sub)[:60]}"
                       " —— 收集函数不需要数自己收了多少")
        # **来源函数内不得出现任何切片**。丢元素这件事在机制上只有三条路：切片、
        # 计数、按位置跳过（也要计数）。计数已经被上面两条禁掉，这里补上切片——
        # 而且**不只是切累积变量**：切"解析源"一样丢候选，且完全不碰累积变量，
        # 因此能整块绕过累积变量白名单（自查实测三种）：
        #     for part in header["value"].split(";")[:20]:        # 切 split 结果
        #     for header in request.get(...).get("cookie", [])[:1]:  # 切外层头列表
        #     header["value"] = ";".join(header["value"].split(";")[:20])
        # 这个函数的职责是"逐个取出并累积"，它没有任何理由切任何东西。
        # `header["value"]` 这类**常量下标**不是切片，不受影响。
        if isinstance(sub, ast.Slice):
            bad.append(f"{label} 内出现切片 —— 收集函数不需要切任何东西"
                       "（切解析源与切累积变量同样丢候选）")
        # 就地改写入参结构（`header["value"] = ...`）同样是在源头丢候选
        if (isinstance(sub, ast.Subscript)
                and isinstance(sub.ctx, (ast.Store, ast.Del))):
            bad.append(f"{label} 内通过下标赋值/删除：{ast.unparse(sub)[:60]}"
                       " —— 就地改写解析源就是在源头截断")

    # 累积变量名**推导**，不写死 `out`（写死会在改名后静默失效）
    accumulators = {n.func.value.id for n in ast.walk(src_fn)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "append"
                    and isinstance(n.func.value, ast.Name)}
    assert accumulators, (f"在 {label} 里找不到任何 `X.append(...)` —— 本条空转"
                          "（累积方式被改写了？）")

    # 累积变量的能力白名单（与 Edge 侧 `_accumulator_offenders` 同法）
    bad += _accumulator_offenders(src_fn, label)

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

    **它证明语法，不证明语义。** 能力白名单管的是"`out` 怎么被使用"，管不到"每个
    匹配元素是否都执行了 append"——在 append 的**准入谓词**里按 rawPath 或按候选内容
    过滤就能绕过它（复审在 Edge 那半边实测过，auth 这边同构）。补它的是本文件末尾
    那三条**变形测试**（请求无关性 / 逐元素完整性 / 追加单调性），不是再加 AST 规则。
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
            "        claims, outcome = None, \"bad_signature\"\n"
            "        for candidate in _session_cookie_candidates(event):",
            "        cands = _session_cookie_candidates(event)\n"
            "        claims, outcome = None, \"bad_signature\"\n        for candidate in cands[:64]:"),
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
            "        claims, outcome = None, \"bad_signature\"\n"
            "        for candidate in _session_cookie_candidates(event):",
            "        cands = _session_cookie_candidates(event)\n        del cands[20:]\n"
            "        claims, outcome = None, \"bad_signature\"\n        for candidate in cands:"),
        # 三种用**命名常量**而非整数字面量的形态（Edge 侧同步补的同一批）
        "命名常量上限": (
            "        if name.strip() == \"sb_session\":\n            out.append(value)",
            "        if name.strip() == \"sb_session\" and len(out) < _LIMIT:\n"
            "            out.append(value)"),
        "循环体手写计数器 + 命名常量": (
            "        claims, outcome = None, \"bad_signature\"\n"
            "        for candidate in _session_cookie_candidates(event):",
            "        claims, outcome = None, \"bad_signature\"\n        _n = 0\n"
            "        for candidate in _session_cookie_candidates(event):\n"
            "            _n += 1\n            if _n > _LIMIT:\n                break"),
        "返回前重绑同名累积变量": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    out = out[:_LIMIT]\n    return out"),
        # 五种原地变异（Edge 侧同一批）：无 len / += / break / 重绑，return 仍是裸变量
        "条件化 del out[20:]": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n"
            '    if event.get("rawPath", "").startswith("/console"):\n'
            "        del out[20:]\n    return out"),
        "out[:] = out[:20]": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    out[:] = out[:20]\n    return out"),
        "out.clear()": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    out.clear()\n    return out"),
        "out.pop()": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    out.pop()\n    return out"),
        "把累积变量交给别的函数去截": (
            "            out.append(value)\n    return out",
            "            out.append(value)\n    _cap(out)\n    return out"),
        # 切**解析源**：完全不碰累积变量，绕过白名单（Edge 侧同一批）
        "切 cookies 列表": (
            '    for raw in (event.get("cookies") or []):',
            '    for raw in (event.get("cookies") or [])[:20]:'),
    }
    for name, (old, new) in bypasses.items():
        assert old in src, f"变异锚点找不到（{name}）——本条空转"
        assert _auth_truncation_offenders(src.replace(old, new, 1)), \
            f"auth 侧检测器没咬住这种绕过：{name}"


# ── 候选收集的**语义**性质（变形测试，与 Edge 侧对称）───────────────────────
#
# 理由与 Edge 那组完全相同：能力白名单限制的是"`out` 怎么用"，证明不了"每个匹配元素
# 都会执行 append"。复审用一条 append 准入谓词打穿过 Edge 那半边，auth 这半边同构。
# 三条性质各杀一类过滤：按请求属性 / 按候选内容 / 按位置。

_PROP_VALUES = [
    "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig",
    "",
    "x",
    "A" * 300,
    "has-dash_and.dot~tilde",
    "eyJ",
]


@patch.dict(lh.os.environ, ENV)
def test_auth_candidate_collection_ignores_every_event_attribute():
    """性质①：同一组 cookies，换 rawPath / 查询串 / 方法 / 其他字段，结果必须逐字相同。"""
    cookies = [f"sb_session={_PROP_VALUES[0]}", "other=keep",
               f"sb_session={_PROP_VALUES[1]}", f"sb_session={_PROP_VALUES[3]}"]
    baseline = lh._session_cookie_candidates({"cookies": cookies})
    assert baseline == [_PROP_VALUES[0], _PROP_VALUES[1], _PROP_VALUES[3]], \
        f"基线本身就不对：{baseline}"

    variants = {
        "rawPath=/console-session": {"rawPath": "/console-session"},
        "rawPath=/callback": {"rawPath": "/callback"},
        "rawPath 很深": {"rawPath": "/" + "/".join(f"s{i}" for i in range(25))},
        "带查询串": {"queryStringParameters": {"code": "x", "private": "1"}},
        "POST": {"requestContext": {"http": {"method": "POST"}}},
        "带 headers": {"headers": {"user-agent": "probe", "host": "auth.example.com"}},
    }
    for label, extra in variants.items():
        got = lh._session_cookie_candidates({"cookies": cookies, **extra})
        assert got == baseline, (
            f"候选列表随 event 属性变化了（{label}）：{got} != {baseline}"
            " —— 收集候选不得看 rawPath/查询串/方法/任何其他字段")


@patch.dict(lh.os.environ, ENV)
def test_auth_every_name_matching_cookie_becomes_a_candidate():
    """性质②：结果必须恰好等于每一枚同名 cookie 的值、顺序一致，一枚都不许少。"""
    cookies, expected = [], []
    for i, v in enumerate(_PROP_VALUES):
        cookies.append(f"noise{i}=n")
        cookies.append(f"sb_session={v}")
        expected.append(v)
    cookies += ["sb_sessionx=不该算同名", "xsb_session=同理"]
    got = lh._session_cookie_candidates({"cookies": cookies})
    assert got == expected, f"候选不是全集或顺序变了\n  得到 {got}\n  期望 {expected}"


@patch.dict(lh.os.environ, ENV)
def test_auth_appending_one_candidate_appends_exactly_one():
    """性质③：再追加一枚 `sb_session=X`，结果必须只在末尾多出 X。"""
    base = ["sb_session=a", "other=o", "sb_session=b"]
    before = lh._session_cookie_candidates({"cookies": base})
    for extra in _PROP_VALUES:
        after = lh._session_cookie_candidates({"cookies": base + [f"sb_session={extra}"]})
        assert after == before + [extra], (
            f"追加 {extra[:16]!r} 后结果不是「原样 + 新值」：{after} 期望 {before + [extra]}")


# ---- /console-session 的 kid allowlist 入口（3c-final：**只有** site family 的 kid，没有 legacy）----

@patch.dict(lh.os.environ, ENV)
def test_console_session_accepts_kid_form_site_session(monkeypatch):
    import urllib.parse
    _use_fake_ssm(monkeypatch)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={_site_session()}"]), None)
    assert r["statusCode"] == 302, r
    loc = r["headers"]["Location"]
    assert loc.startswith("https://console.example.com/api/session-callback?code=")
    code = urllib.parse.unquote(loc.split("code=", 1)[1])
    # 换出来的升级码是 console family 的 kid 签的（形态断言在下面那两条）
    assert _upgrade_claims(code)["email"] == "u@x.com"


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_console_kid_token_as_site_session(monkeypatch):
    _use_fake_ssm(monkeypatch)
    tok = _site_session(key=v.CONSOLE_KEY, kid=v.CONSOLE_KID)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={tok}"]), None)
    assert "/login" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_console_session_rejects_an_unknown_kid(monkeypatch, capsys):
    """allowlist 里没有的 kid 一律拒——3c-final 起没有任何回落路径（legacy 入口整个不存在了）。

    第二段是"第三把 key 冒充已知 kid"：`site-rs-v1` **在** allowlist 里，但签名来自另一把私钥
    ⇒ outcome 必须是 `bad_signature` 而不是 `unknown_kid`。两种拒绝的排查方向完全不同
    （前者是"这个 kid 没下发/退役了"，后者是"密钥材料对不上"），埋点混了就查错方向。
    """
    _use_fake_ssm(monkeypatch)
    unknown = _site_session(kid="site-rs-v9", key=v.SITE_PREV_KEY)
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={unknown}"]), None)
    assert "/login" in r["headers"]["Location"], "未知 kid 竟然换出了升级码"
    assert _last_verify_outcome(capsys) == "unknown_kid"

    forged = _site_session(key=v.SITE_PREV_KEY)          # kid=site-rs-v1，签名是第三把 key
    r = lh.handler(_event("/console-session", cookies=[f"sb_session={forged}"]), None)
    assert "/login" in r["headers"]["Location"], "签名不对的已知 kid 竟然换出了升级码"
    assert _last_verify_outcome(capsys) == "bad_signature"


@patch.dict(lh.os.environ, ENV)
def test_console_session_shadow_cookie_before_kid_form_session_still_exchanges(monkeypatch):
    """M06 不退化：遮蔽项排在前面时仍逐个验。"""
    _use_fake_ssm(monkeypatch)
    r = lh.handler(_event("/console-session",
                          cookies=["sb_session=garbage.garbage.garbage", f"sb_session={_site_session()}"]), None)
    assert "session-callback?code=" in r["headers"]["Location"]


@patch.dict(lh.os.environ, ENV)
def test_console_session_logs_verify_outcome_without_token(monkeypatch, capsys):
    _use_fake_ssm(monkeypatch)
    tok = _site_session()
    lh.handler(_event("/console-session", cookies=[f"sb_session={tok}"]), None)
    out = capsys.readouterr().out
    rows = [json.loads(l) for l in out.splitlines() if l.startswith("{") and "session_verify" in l]
    assert rows and rows[-1]["outcome"] == "accepted_current" and rows[-1]["verifier"] == "auth"
    assert tok.split(".")[1] not in out


# ---- 签发形态（3c-final，spec §11.4）------------------------------------------------------
#
# 断言的是**外部可见形态**：Set-Cookie 里 token 的 JOSE 头与 payload 的**精确 claim 集合**、
# Location 里升级码的头与 claims。不数内部调用次数。
# 只有一种形态了（RS256 + family kid，签名经 KMS）：signer 开关与 legacy 分支在 3c-final 一起删掉，
# 所以这一组不再需要"两侧都测"。

def _b64d(seg: str) -> dict:
    import base64
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _session_cookie(r) -> str:
    return next(c for c in r["cookies"] if c.startswith("sb_session=")).split(";")[0][len("sb_session="):]


def _login_leg():
    """真的走一遍 /login，取回 (state, PKCE cookie)。**必须在目标 env 的 patch 之内调用**
    ——state 的 HMAC 与 pkce cookie 都由那份 env 里的 login-flow secret 签。"""
    r_login = lh.handler(_event("/login", {"redirect": "https://app-x.example.com/"}), None)
    state = _login_state(r_login)
    pkce = next(c for c in r_login["cookies"] if c.startswith(lh.PKCE_COOKIE)).split(";")[0]
    return state, pkce


def _do_callback(env, *, email="a@x.com", name="Alice", idp="Feishu",
                 auth_via="TokenGeneration_HostedAuth"):
    """走真的 /login → /callback（state 与 PKCE cookie 都是真的），只 patch code 交换。"""
    user = {"email": email, "name": name, "idp": idp, "auth_via": auth_via}
    with patch.dict(lh.os.environ, env), patch.object(lh, "_exchange_code", return_value=user):
        state, pkce = _login_leg()
        return lh.handler(_event("/callback", {"code": "abc", "state": state}, cookies=[pkce]), None)


def test_callback_signs_the_site_session_with_the_site_current_kid():
    r = _do_callback(ENV)
    header, payload, _ = _session_cookie(r).split(".")
    assert _b64d(header) == {"alg": "RS256", "typ": "JWT", "kid": "site-rs-v1"}
    claims = _b64d(payload)
    # §11.4 的站点会话表：**精确**这 8 个键，不多不少（多出 typ/scope 说明混了旧合同）
    assert set(claims) == {"token_use", "aud", "email", "name", "idp", "auth_via", "exp", "iat"}
    assert claims["token_use"] == "site-session" and claims["aud"] == "site-edge"
    assert (claims["email"], claims["name"]) == ("a@x.com", "Alice")
    assert (claims["idp"], claims["auth_via"]) == ("Feishu", "TokenGeneration_HostedAuth")
    assert claims["exp"] - claims["iat"] == lh.SESSION_TTL_SECONDS


def test_callback_cookie_max_age_matches_the_token_exp():
    """cookie 比 token 短会莫名重登，长会 302 回登录看起来像"会话丢了"——同一个常量供两处。"""
    r = _do_callback(ENV)
    cookie = next(c for c in r["cookies"] if c.startswith("sb_session="))
    assert f"Max-Age={lh.SESSION_TTL_SECONDS}" in cookie
    payload = _b64d(_session_cookie(r).split(".")[1])
    assert payload["exp"] - payload["iat"] == lh.SESSION_TTL_SECONDS


def test_callback_signature_is_the_site_family_key_not_the_console_key():
    """负向：站点会话必须用 site family 的 key 签。投给 console 的 allowlist 必 unknown_kid。"""
    token = _session_cookie(_do_callback(ENV))
    claims, outcome = session.verify_token(token, allowlist=v.SITE_ALLOWLIST, token_use="site-session")
    assert claims and outcome == "accepted_current"
    assert session.verify_token(token, allowlist=v.CONSOLE_ALLOWLIST,
                                token_use="site-session") == (None, "unknown_kid")


def test_console_session_signs_the_upgrade_code_with_the_console_current_kid():
    with patch.dict(lh.os.environ, ENV):
        r = _console_session([f"sb_session={_site_session()}"])
    code = _issued_code(r)
    assert code, "有效站点会话竟然没换出升级码"
    header, payload, _ = code.split(".")
    # console family——**不是** site：升级码投给 Edge 必拒，这正是拆 family 想要的性质
    assert _b64d(header) == {"alg": "RS256", "typ": "JWT", "kid": "console-rs-v1"}
    claims = _b64d(payload)
    # §11.4 的升级码表：精确这 6 个键；jti 少了就拆掉 panel 的原子消费与并发重放保护
    assert set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"}
    assert claims["token_use"] == "console-upgrade" and claims["aud"] == "console-exchange"
    assert claims["email"] == "u@x.com" and claims["jti"]
    assert 0 < claims["exp"] - claims["iat"] <= 60


def test_console_session_upgrade_code_verifies_under_the_console_family_key_only():
    with patch.dict(lh.os.environ, ENV):
        code = _issued_code(_console_session([f"sb_session={_site_session()}"]))
    claims, outcome = session.verify_token(code, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert claims and outcome == "accepted_current"
    assert session.verify_token(code, allowlist=v.SITE_ALLOWLIST,
                                token_use="console-upgrade") == (None, "unknown_kid")


def test_only_the_site_family_key_ever_signs_a_site_session(_fake_platform_clients):
    """签发面断言：走一遍 /callback，KMS 只被要求用 site family 那把 key 签。

    签错 family 的症状是"登录成功但每个人立刻被踢回登录页"（Edge 的 allowlist 只有 site），
    而两侧单测各自都会绿——所以这里直接看打给 KMS 的 KeyId。
    """
    kms = _fake_platform_clients
    _do_callback(ENV)
    signs = [c for c in kms.calls if c[0] == "sign"]
    assert signs and all(c[1] == v.KEY_ARN[v.SITE_KID] for c in signs), signs


# ---- ticket 20：取签发材料必须发生在烧掉一次性授权码之前 --------------------------------
#
# 判据是 **`_exchange_code` 一次都没被调用**，不是状态码：授权码只要递给 Cognito 的 token
# 端点就已经被消费，之后无论返回 500 还是 400，用户都得从 `/login` 重来一遍。3c-final 的失败面是
# SESSION_KEYS_JSON 缺失/非 JSON/family 缺 current、`kms:GetPublicKey` AccessDenied、公钥指纹与
# 配置不符（KmsSigner.self_check）——都比"环境变量漏下发"常见，而配置修好之前**每一次**登录都这样。

# 三种真实配置事故，都不 patch 内部函数（只动环境 / 假 KMS 的应答），所以证明的是生产会走的那条路。
_KEY_FAILURES = (
    # SESSION_KEYS_JSON 整个漏下发
    pytest.param({k: val for k, val in ENV.items() if k != "SESSION_KEYS_JSON"},
                 False, "SESSION_KEYS_JSON", id="missing-keys-json"),
    # site family 只有 previous 行（就位期把两个槽位写反了）⇒ signing_ref 硬失败
    pytest.param(dict(ENV, SESSION_KEYS_JSON=v.session_keys_json(
        (v.SITE_PREV_KID, "previous"), (v.CONSOLE_KID, "current"))),
        False, "role=current", id="site-has-no-current"),
    # config.ini 里的 spki_sha256 指的不是这把 key（或 key 被换过）⇒ KmsSigner.self_check 拒签
    pytest.param(ENV, True, "指纹", id="public-key-fingerprint-mismatch"),
)


@pytest.mark.parametrize("env, tamper, match", _KEY_FAILURES)
def test_callback_fetches_the_signing_key_before_burning_the_authorization_code(
        env, tamper, match, _fake_platform_clients):
    """签发材料取不到时，那枚一次性授权码必须**还没被交换**（用户重试 callback 即可）。"""
    if tamper:
        _fake_platform_clients.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    with patch.dict(lh.os.environ, env), patch.object(lh, "_exchange_code") as mock_ex:
        state, pkce = _login_leg()
        with pytest.raises(RuntimeError, match=match):
            lh.handler(_event("/callback", {"code": "abc", "state": state}, cookies=[pkce]), None)
        mock_ex.assert_not_called()


def test_callback_does_exchange_the_code_when_the_signing_key_is_fine():
    """正对照：上面那条不是靠"永远不交换"通过的——同一条装置在配置正常时**必须**交换一次。

    判据与负向严格对称（`assert_called_once` ⇄ `assert_not_called`），所以那条守卫不可能
    因为"这套装置根本走不到交换"而假绿。形态断言不在这里（见上面按 claim 集合逐字节比对的两条）。
    """
    user = {"email": "a@x.com", "name": "Alice", "idp": "Feishu", "auth_via": "x"}
    with patch.dict(lh.os.environ, ENV), \
            patch.object(lh, "_exchange_code", return_value=user) as mock_ex:
        state, pkce = _login_leg()
        r = lh.handler(_event("/callback", {"code": "abc", "state": state}, cookies=[pkce]), None)
    mock_ex.assert_called_once()
    assert r["statusCode"] == 302 and _session_cookie(r).count(".") == 2
