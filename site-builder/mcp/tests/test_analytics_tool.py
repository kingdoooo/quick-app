"""M5 MCP 工具单测。

**返回单个 dict，不返回裸列表**——M4-FINDINGS §3.4 实测：线上这台 server 不发
`structuredContent`，返回列表会被拆成多个 text 块，调用方"取 content[0].text
解析"会**静默只拿到第一个元素**。错的时候不抛异常，只是数据少了。
"""
import inspect

import pytest


def test_tool_returns_a_dict_not_a_bare_list():
    import server
    sig = inspect.signature(server.get_site_analytics)
    assert sig.return_annotation is dict, (
        "返回类型必须是 dict——裸列表会被拆成多个 text 块并被静默截断（§3.4）")


def test_tool_delegates_authorization_to_view_analytics(monkeypatch):
    import server
    seen = {}
    monkeypatch.setattr(server, "_assert_permission",
                        lambda email, site_id, action, what: seen.update(
                            {"action": action, "site": site_id}) or
                        server.Authz({}, "owner", 0, True, email))
    monkeypatch.setattr(server, "_analytics_payload",
                        lambda site_id, period, days: {"series": []})
    server.do_get_analytics("me@x.co", "s1", "day", 30)
    assert seen == {"action": "view_analytics", "site": "s1"}


def test_series_and_visitors_are_fields_of_one_dict(monkeypatch):
    import server
    monkeypatch.setattr(server, "_assert_permission",
                        lambda *a, **k: server.Authz({}, "owner", 0, True, "e"))
    monkeypatch.setattr(server, "_analytics_payload",
                        lambda site_id, period, days: {
                            "series": [{"bucket": "2026-08-13", "pv": 1,
                                        "uv": 1, "pv_denied": 0,
                                        "uv_exact": True}],
                            "recent_visitors": [{"ts": "t", "email": "a@x.co",
                                                 "path": "/", "decision": "allow"}]})
    out = server.do_get_analytics("me@x.co", "s1", "day", 30)
    assert isinstance(out, dict)
    assert isinstance(out["series"], list) and isinstance(out["recent_visitors"], list)


@pytest.mark.parametrize("period", ["hour", "", "DAY"])
def test_invalid_period_is_rejected(monkeypatch, period):
    import server
    monkeypatch.setattr(server, "_assert_permission",
                        lambda *a, **k: server.Authz({}, "owner", 0, True, "e"))
    with pytest.raises(ValueError):
        server.do_get_analytics("me@x.co", "s1", period, 30)
