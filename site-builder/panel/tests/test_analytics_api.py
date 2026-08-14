"""两个读端点的授权用例（端点层）。

读取层本身（分桶、uv_exact、游标）的用例在
`deployer/tests/test_analytics.py`——`analytics.py` 落在 `deployer/functions/`，
那是共享模块的既有位置，也是 MCP 传递闭包守卫唯一会扫的目录。

**这两条是新端点唯一的授权覆盖**：`test_authz.py` 的能力矩阵虽然从
`permissions.CAPABILITIES[action]` 推导期望值，但它 parametrize 的是一份手写的
`WRITE_CALLS`（只有三个写动作），不是 `CAPABILITIES.keys()`。所以新登记的
`view_analytics` **不会**自动被那张矩阵覆盖。
"""
import pytest

# ── 端点层：授权 ─────────────────────────────────────────────────
# **fixture 用 panel conftest 的 `aws`，不是 deployer 那个 `env`**（Codex 复审
# 2026-08-14 P2-1）：`env` 只定义在 deployer 的 test_analytics.py 里，在这里写
# 它会直接 `fixture 'env' not found`。而 `aws` 已经 `with mock_aws()` 并建好了
# jobs/sites/routing/admins——**再嵌一层 mock_aws 是错的**，正确做法是往
# conftest 的 `aws` 里补这两张表 + 两个环境变量（见 conftest.py）。


def test_endpoints_require_view_analytics(monkeypatch, aws):
    """无权者必须 403，且走 CAPABILITIES 的判定，不在 api.py 另写角色子句。"""
    import api
    import permissions
    monkeypatch.setattr("common.get_site_consistent",
                        lambda sid: {"site_id": sid, "owner": "other@x.co",
                                     "collaborators": []})
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    with pytest.raises(permissions.PermissionDenied):
        api.do_get_analytics("nobody@x.co", "s1", period="day", n=7)
    with pytest.raises(permissions.PermissionDenied):
        api.do_get_visitors("nobody@x.co", "s1", days=7, limit=10, cursor=None)


def test_owner_may_read_both_endpoints(monkeypatch, aws):
    """正对照：不能只验"拒"——头压根没到达也会让负测全绿（§3.5）。"""
    import api
    import permissions
    monkeypatch.setattr("common.get_site_consistent",
                        lambda sid: {"site_id": sid, "owner": "me@x.co",
                                     "collaborators": []})
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    assert "series" in api.do_get_analytics("me@x.co", "s1", period="day", n=7)
    assert "rows" in api.do_get_visitors("me@x.co", "s1", days=7, limit=10,
                                         cursor=None)
