"""`scripts/verify_kid_entry_live.py` 的判定逻辑（纯函数）与自测：正向控制必须分得清"放行"与"站点坏了"。

3c-final 起判据按新形态收缩：登录态来自夹具签发器（ADR 0002），跨 family / 用途混用两组反例造不出来了
（没有任何组件能带外签 console family），它们的证据搬到 auth 与 Edge 的单测 + 产物公钥对账上。
"""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
import verify_kid_entry_live as probe  # noqa: E402  —— import 期不得碰 AWS

SITE, AUTH, CONSOLE = ("https://app-e2e-probe.example.test/", "auth.example.test", "console.example.test")


def _t(**kw):
    base = dict(site_kid="SITE.x.y", unknown_kid="UNKNOWN.x.y")
    base.update(kw)
    return probe.Tokens(**base)


def _names(get=None):
    return [c.name for c in probe.run_checks(get or probe._ideal_responder(), _t(),
                                             site_url=SITE, auth_host=AUTH)]


def test_import_has_no_side_effects():
    assert callable(probe.main) and callable(probe.run_checks)


def test_only_two_tokens_and_neither_needs_a_key():
    """`Tokens` 恰好两枚：夹具签发器只签站点会话，未知 kid 那枚本地造（KMS 之后本地没有私钥）。"""
    assert set(probe.Tokens.__dataclass_fields__) == {"site_kid", "unknown_kid"}


def test_allow_path_requires_200_not_merely_non_302():
    """`st != 302` 在 403/500/502 上也过——那分不清放行与站点故障。"""
    checks = probe.run_checks(
        lambda url, cookie: (500, {}) if "sb_session=SITE" in cookie
        else (302, {"location": f"https://{AUTH}/login"}),
        tokens=_t(), site_url=SITE, auth_host=AUTH)
    failed = [c.name for c in checks if not c.ok]
    assert any("站点放行" in n for n in failed), failed


def test_default_criteria_are_three_plus_one_negative_control():
    names = _names()
    assert len(names) == 4, names
    assert sum("对照" in n for n in names) == 1, names
    # 跨 family / 用途混用不该再出现在判据里（它们已经造不出来，留着就是空转的装饰）
    assert not any(("console kid" in n) or ("token_use" in n) for n in names), names


def test_self_test_is_green_on_the_ideal_responder_and_red_on_a_broken_one():
    assert probe.self_test() == 0
    assert probe.self_test(break_allow_path=True) != 0


def test_role_checks_require_200_at_edge_and_a_console_cookie_from_the_real_chain():
    rt = probe.RoleTokens(role="previous", site="PREVS.x.y", console_cookie="COOKIE.x.y")
    ok = probe.run_role_checks(probe._ideal_responder(), rt, site_url=SITE)
    assert ok and all(c.ok for c in ok) and len(ok) == 2
    # 放行路径 500（站点坏了）不能算"previous 可用"；换取链路没换出 cookie 同样不算
    bad = probe.run_role_checks(probe._ideal_responder(break_role_path=True),
                                probe.RoleTokens(role="previous", site="PREVS.x.y", console_cookie=None),
                                site_url=SITE)
    assert [c.ok for c in bad] == [False, False]


def test_retired_checks_are_red_on_200_and_green_on_explicit_rejections():
    retired = [("site-session", "RETIRED-S.x.y"), ("console-upgrade", "RETIRED-C.x.y")]
    good = probe.run_retired_checks(probe._ideal_responder(), retired, site_current="SITE.x.y",
                                    site_url=SITE, auth_host=AUTH, console_host=CONSOLE)
    assert all(c.ok for c in good) and len(good) == 4     # 正对照 + Edge + auth + panel
    bad = probe.run_retired_checks(probe._ideal_responder(break_retired_path=True), retired,
                                   site_current="SITE.x.y", site_url=SITE, auth_host=AUTH,
                                   console_host=CONSOLE)
    assert any(not c.ok for c in bad)
    # 500 也不是"被拒"：退役 key 必须是明确的 302/401，不是站点故障
    five = probe.run_retired_checks(lambda u, c: (500, {}), retired, site_current="SITE.x.y",
                                    site_url=SITE, auth_host=AUTH, console_host=CONSOLE)
    assert not any(c.ok for c in five)


def test_retired_console_session_records_are_refused_because_panel_only_checks_them_on_writes():
    with pytest.raises(SystemExit, match="console-upgrade"):
        probe.run_retired_checks(probe._ideal_responder(), [("console-session", "X.y.z")], site_current="SITE.x.y",
                                 site_url=SITE, auth_host=AUTH, console_host=CONSOLE)


def test_self_test_covers_every_branch_including_the_kid_negative():
    """四个旗标都必须能把自测弄红。

    `break_unknown_kid` 是从前 `break_family` 那条的替身：`UNKNOWN` 在理想应答器里永远落到
    `302, login`，没有专门的旗标时"未知 kid 不回落"这条负向断言在自测里**不可能红**——
    而它正是新 kid 入口区别于旧代码的性质（一个会在未知 kid 上回落的 verifier，自测照样全绿）。
    """
    assert probe.self_test() == 0
    assert probe.self_test(break_allow_path=True) != 0
    assert probe.self_test(break_unknown_kid=True) != 0
    assert probe.self_test(break_role_path=True) != 0
    assert probe.self_test(break_retired_path=True) != 0


def test_break_unknown_kid_targets_exactly_the_kid_negative():
    """把红的那条点出来：必须**恰好**是"未知 kid"那一条，不多不少。

    多了说明这个旗标顺手破坏了别的路径（那样它就不能证明这一条了）；少了说明断言没被覆盖。
    """
    get = probe._ideal_responder(break_unknown_kid=True)
    red = [c.name for c in probe.run_checks(get, _t(), site_url=SITE, auth_host=AUTH) if not c.ok]
    assert len(red) == 1 and "未知 kid" in red[0], red


def test_every_default_assertion_has_some_break_path_that_makes_it_red():
    """元用例：`run_checks` 的每一条断言都必须至少被一个 break 旗标打红。

    这条是给"以后再加一条断言却忘了给它 break 路径"设的闸——那种断言在自测里是装饰。
    """
    ever_red = set()
    for flags in ({"break_allow_path": True}, {"break_unknown_kid": True}):
        get = probe._ideal_responder(**flags)
        ever_red |= {c.name for c in probe.run_checks(get, _t(), site_url=SITE, auth_host=AUTH) if not c.ok}
    never = [n for n in _names() if n not in ever_red and "负对照" not in n]
    assert not never, f"这些断言没有任何 break 路径能让它们红（自测证明不了它们）: {never}"


def test_the_unknown_kid_token_is_well_formed_and_needs_no_key():
    """本地造那一枚：三段、header 是未知 kid、签名段是 RSA-2048 签名的长度且每次不同。"""
    tok = probe._unknown_kid_token("probe@e2e.invalid")
    h, p, sig = tok.split(".")

    def unb64(seg):
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

    assert json.loads(unb64(h)) == {"alg": "RS256", "typ": "JWT", "kid": probe.UNKNOWN_KID}
    assert json.loads(unb64(p))["email"] == "probe@e2e.invalid"
    assert len(unb64(sig)) == 256 and probe._unknown_kid_token("probe@e2e.invalid") != tok


def test_the_unknown_kid_is_not_a_configured_kid_shape_used_by_the_asset():
    """`site-rs-v9` 不许撞上 config.ini.example 里配置的任何 kid——撞上这条判据就变成
    "已配置的 key 被拒"（假红，且排查方向完全错）。"""
    example = (ROOT / "site-builder" / "config.ini.example").read_text()
    assert f"[SessionKey:{probe.UNKNOWN_KID}]" not in example, probe.UNKNOWN_KID
