"""`scripts/verify_kid_entry_live.py` 的判定逻辑（纯函数）与自测：正向控制必须分得清"放行"与"站点坏了"。"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
import verify_kid_entry_live as probe  # noqa: E402  —— import 期不得碰 AWS


def _responder(table):
    def get(url, cookie_header):
        return table[(url.split("//")[1].split("/")[0].split(".")[0], cookie_header.split("=")[1][:6] if "=" in cookie_header else "")]
    return get


def test_import_has_no_side_effects():
    assert callable(probe.main) and callable(probe.run_checks)


def test_allow_path_requires_200_not_merely_non_302():
    """`st != 302` 在 403/500/502 上也过——那分不清放行与站点故障。"""
    checks = probe.run_checks(lambda url, cookie: (500, {}) if "sb_session=SITE" in cookie else (302, {"location": "https://auth.example.test/login"}),
                              tokens=probe.Tokens(legacy="LEGACY.x.y", site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                                                  unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y"),
                              site_url="https://app-x.example.test/", auth_host="auth.example.test")
    failed = [c.name for c in checks if not c.ok]
    assert any("site-hs" in n or "站点会话放行" in n for n in failed), failed


def test_self_test_is_green_on_the_ideal_responder_and_red_on_a_broken_one():
    assert probe.self_test() == 0
    assert probe.self_test(break_allow_path=True) != 0


# ---- 3c-1B ticket 01：--role 正向与 --retired-token 负向 ------------------------------------

def _t(**kw):
    base = dict(legacy="LEGACY.x.y", site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y")
    base.update(kw)
    return probe.Tokens(**base)


def test_legacy_positive_control_is_omitted_when_legacy_entry_is_closed():
    """L3 之后 legacy_param 为空：没有 legacy token 可 mint，正对照那条不该假绿也不该假红，而是不出现。"""
    checks = probe.run_checks(probe._ideal_responder(), _t(legacy=None),
                              site_url="https://app-x.example.test/", auth_host="auth.example.test")
    assert not any("legacy 会话" in c.name for c in checks)
    assert all(c.ok for c in checks)


def test_role_checks_require_200_at_edge_and_a_console_cookie_from_panel():
    rt = probe.RoleTokens(role="previous", site="PREVS.x.y", upgrade="PREVC.x.y", site_current="SITE.x.y")
    ok = probe.run_role_checks(probe._ideal_responder(), rt, site_url="https://app-x.example.test/",
                               console_host="console.example.test")
    assert ok and all(c.ok for c in ok) and len(ok) == 2
    # 放行路径 500（站点坏了）不能算"previous 可用"
    bad = probe.run_role_checks(probe._ideal_responder(break_role_path=True), rt,
                                site_url="https://app-x.example.test/", console_host="console.example.test")
    assert [c.ok for c in bad] == [False, False]


def test_retired_checks_are_red_on_200_and_green_on_explicit_rejections():
    retired = [("site-session", "RETIRED-S.x.y"), ("console-upgrade", "RETIRED-C.x.y")]
    good = probe.run_retired_checks(probe._ideal_responder(), retired, site_current="SITE.x.y",
                                    site_url="https://app-x.example.test/", auth_host="auth.example.test",
                                    console_host="console.example.test")
    assert all(c.ok for c in good) and len(good) == 4     # 正对照 + Edge + auth + panel
    bad = probe.run_retired_checks(probe._ideal_responder(break_retired_path=True), retired,
                                   site_current="SITE.x.y", site_url="https://app-x.example.test/",
                                   auth_host="auth.example.test", console_host="console.example.test")
    assert any(not c.ok for c in bad)
    # 500 也不是"被拒"：退役 key 必须是明确的 302/401，不是站点故障
    five = probe.run_retired_checks(lambda u, c: (500, {}), retired, site_current="SITE.x.y",
                                    site_url="https://app-x.example.test/", auth_host="auth.example.test",
                                    console_host="console.example.test")
    assert not any(c.ok for c in five)


def test_retired_console_session_records_are_refused_because_panel_only_checks_them_on_writes():
    with pytest.raises(SystemExit, match="console-upgrade"):
        probe.run_retired_checks(probe._ideal_responder(), [("console-session", "X.y.z")], site_current="SITE.x.y",
                                 site_url="https://app-x.example.test/", auth_host="auth.example.test",
                                 console_host="console.example.test")


def test_self_test_covers_role_and_retired_branches():
    assert probe.self_test() == 0
    assert probe.self_test(break_allow_path=True) != 0
    assert probe.self_test(break_role_path=True) != 0
    assert probe.self_test(break_retired_path=True) != 0


# ---- ticket 17 第 14 条（/code-review 2026-09-04）---------------------------------------------
#
# 三个 break 旗标只覆盖 12 条断言里的 4 条：`CONSOLE` / `UNKNOWN` / `WRONG` 三种 token 在理想
# 应答器里**永远**落到 `return 302, login`，没有任何配置能让它们变绿 ⇒ 那四条负向断言
# （console kid 被拒、未知 kid 不回落、wrong token_use 被拒、console kid 换不出升级码）
# 在自测里**不可能红**。而它们恰好是"新 kid 入口"区别于旧代码的全部性质：一个会在未知 kid 上
# 回落 legacy、或两个 family 共用一份 allowlist 的 verifier，自测照样全绿。

def test_self_test_can_fail_on_the_kid_entry_negatives(monkeypatch):
    """`break_family=True` 让三种本该被拒的 token 全被放行，自测必须红。"""
    assert probe.self_test(break_family=True) != 0


def test_break_family_targets_exactly_the_four_kid_entry_assertions():
    """把红的那几条点出来：必须**恰好**是四条负向断言，不多不少。

    多了说明这个旗标顺手破坏了别的路径（那样它就不能证明这四条了）；少了说明还有断言没覆盖。
    """
    site, auth, console = "https://app-x.example.test/", "auth.example.test", "console.example.test"
    get = probe._ideal_responder(break_family=True)
    checks = probe.run_checks(get, probe.Tokens(legacy=None, site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                                                unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y"),
                              site_url=site, auth_host=auth)
    red = [c.name for c in checks if not c.ok]
    assert len(red) == 4, red
    assert all(k in " ".join(red) for k in ("console kid", "未知 kid", "token_use")), red


def test_every_default_assertion_has_some_break_path_that_makes_it_red():
    """元用例：`run_checks` 的每一条断言都必须至少被一个 break 旗标打红。

    这条是给"以后再加一条负向断言却忘了给它 break 路径"设的闸——那种断言在自测里是装饰。
    """
    site, auth = "https://app-x.example.test/", "auth.example.test"
    toks = probe.Tokens(legacy=None, site_kid="SITE.x.y", console_kid="CONSOLE.x.y",
                        unknown_kid="UNKNOWN.x.y", wrong_use="WRONG.x.y")
    names = [c.name for c in probe.run_checks(probe._ideal_responder(), toks, site_url=site, auth_host=auth)]
    ever_red = set()
    for flags in ({"break_allow_path": True}, {"break_family": True}):
        get = probe._ideal_responder(**flags)
        ever_red |= {c.name for c in probe.run_checks(get, toks, site_url=site, auth_host=auth) if not c.ok}
    never = [n for n in names if n not in ever_red and "负对照" not in n]
    assert not never, f"这些断言没有任何 break 路径能让它们红（自测证明不了它们）: {never}"


# ---- 3c-1B-G A1：把"探针能红"从断言变成证明 ----------------------------------------------
#
# 这两条用**真源 Edge verifier**（占位符替换后 import 的 origin_request.py）回答一个问题：
# 「如果 console key 真的漏进了 site allowlist，闸门会红吗？」
#
# 结论分两半，正是本票要修的东西：
#   · 跨 family **同形态** token（console kid + token_use=site-session）会被**接受**
#     ⇒ 探针断言的 302 变成 200 ⇒ 闸门红。**这才是隔离了 allowlist 这一个变量的判据。**
#   · 旧探针那一枚（console kid + token_use=console-session）仍被拒（`wrong_token_use`）
#     ⇒ 302 照旧 ⇒ **闸门在真的失守时全绿**。
# 所以"两个变量一起改"不是风格问题，它让这条闸门失去了证明力。

def _edge_with(allowlist: dict):
    """真源 Edge 模块，site allowlist 由入参决定（不手抄替换表，见 ticket 22）。"""
    sys.path.insert(0, str(Path(__file__).parents[3] / "router" / "infrastructure" / "lambda"))
    import edge_substitutions as es
    return es.load_edge_module("_edge_for_family_leak", SITE_ALLOWLIST_JSON=json.dumps(allowlist),
                               LEGACY_ENTRY="off")


SITE_KID, CONSOLE_KID = "site-hs-v9", "console-hs-v9"
SITE_SECRET, CONSOLE_SECRET = "site-secret-9", "console-secret-9"
_ENTRY = {"alg": "HS256", "role": "current"}
GOOD_ALLOWLIST = {SITE_KID: {**_ENTRY, "secret": SITE_SECRET}}
LEAKED_ALLOWLIST = {**GOOD_ALLOWLIST, CONSOLE_KID: {**_ENTRY, "secret": CONSOLE_SECRET}}


def _mint(kid, secret, token_use):
    sys.path.insert(0, str(Path(__file__).parents[2] / "auth"))
    import session as sess
    return sess.mint_token(kid=kid, secret=secret, token_use=token_use, email="o@example.test",
                           ttl_seconds=600, name="O", idp="Feishu",
                           auth_via="TokenGeneration_HostedAuth")


def test_edge_accepts_the_cross_family_token_once_the_console_kid_leaks_in():
    """漏进 allowlist ⇒ 跨 family 同形态 token 被接受 ⇒ 重建后的探针必然转红。"""
    leaked = _edge_with(LEAKED_ALLOWLIST)
    tok = _mint(CONSOLE_KID, CONSOLE_SECRET, "site-session")
    claims, outcome = leaked._verify_site_session(tok)
    assert claims and outcome == "accepted_current", outcome
    # 前提自查：allowlist 正常时同一枚必被拒，否则上面那条什么都没证明
    ok = _edge_with(GOOD_ALLOWLIST)
    assert ok._verify_site_session(tok) == (None, "unknown_kid")


def test_the_old_two_variable_probe_shape_stays_green_on_the_same_leak():
    """同一次失守下，旧形态（console kid + console-session）仍被拒 ⇒ 闸门看不见它。

    这条是**反面证明**：它必须一直绿，用来说明"为什么必须换成跨 family 同形态"。
    拒绝理由是 `wrong_token_use` 而不是 `unknown_kid`——签名已经验过了，
    也就是说 allowlist 这道门当时已经放行。
    """
    leaked = _edge_with(LEAKED_ALLOWLIST)
    old_shape = _mint(CONSOLE_KID, CONSOLE_SECRET, "console-session")
    assert leaked._verify_site_session(old_shape) == (None, "wrong_token_use")
