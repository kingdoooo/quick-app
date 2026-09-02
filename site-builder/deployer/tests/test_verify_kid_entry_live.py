"""`scripts/verify_kid_entry_live.py` 的判定逻辑（纯函数）与自测：正向控制必须分得清"放行"与"站点坏了"。"""
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
