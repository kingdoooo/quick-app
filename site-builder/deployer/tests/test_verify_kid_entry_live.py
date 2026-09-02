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
