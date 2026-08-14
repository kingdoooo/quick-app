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


def test_list_sites_carries_pv7(monkeypatch, aws):
    """站点列表的迷你趋势（母 spec §11-clarify 的 M5 项）。"""
    import api
    import permissions
    monkeypatch.setattr("common.list_sites_for_user",
                        lambda e: [{"site_id": "s1", "owner": e,
                                    "status": "ACTIVE", "collaborators": []}])
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    out = api.do_list_sites("me@x.co")
    assert len(out[0]["pv7"]) == 7, out[0]


# ── 降级：迷你趋势读不到，不得放大成"控制台首页打不开" ────────────────────
#
# `/api/sites` 是控制台的首页接口。pv7 让它开始依赖两张访问表，于是"表没建 /
# IAM 少 Query / 表名环境变量没下发"会从"统计页签空着"升级成"整个站点列表
# 打不开"——连改权限、下线这些恢复手段都进不去。同 `_api_key_feature()` 对
# `/api/me` 的既有判例（那里的 docstring 有完整理由）。

def _one_site(monkeypatch, permissions):
    monkeypatch.setattr("common.list_sites_for_user",
                        lambda e: [{"site_id": "s1", "owner": e, "name": "站一",
                                    "status": "ACTIVE", "collaborators": [],
                                    "last_job_id": "j1",
                                    "created_at": "2026-08-01T00:00:00"}])
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)


def _client_error():
    import botocore.exceptions
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceNotFoundException",
                   "Message": "Requested resource not found"}}, "Query")


def test_list_sites_survives_an_unreadable_access_table(monkeypatch, aws, caplog):
    """趋势读失败 → 该站点 `pv7` 为 `[]`，**其余字段一个不少**，且有 warning。

    降级值刻意是 `[]` 而不是 `[0] * 7`：一条平的 0 线与"真的零访问"在界面上
    无法区分，那是一句假数据（同 uv_exact 的口径）。`[]` 的含义是"未知"，
    前端据此什么都不画。
    """
    import logging
    import analytics
    import api
    import permissions
    _one_site(monkeypatch, permissions)
    healthy = api.do_list_sites("me@x.co")[0]        # 先取一份正常形态做对照

    monkeypatch.setattr(analytics, "pv7",
                        lambda sid: (_ for _ in ()).throw(_client_error()))
    with caplog.at_level(logging.WARNING):
        out = api.do_list_sites("me@x.co")
    assert len(out) == 1, out
    assert out[0]["pv7"] == [], f"降级值必须是「未知」而不是零填充: {out[0]['pv7']}"
    # **其余字段逐个与正常形态相同**：只丢趋势，不丢站点信息
    assert {k: v for k, v in out[0].items() if k != "pv7"} == \
           {k: v for k, v in healthy.items() if k != "pv7"}, out[0]
    # warning 不是可选的——静默吞异常是本轮 §4.2 踩过的形态
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warns, "读失败却没有任何 warning —— 降级变成了静默吞异常"
    msg = warns[0].getMessage()
    assert "s1" in msg, f"warning 没有点出是哪个站点: {msg!r}"
    assert "ResourceNotFoundException" in msg, (
        f"warning 没有带上底层错误，排查时看不出是表没建还是没权限: {msg!r}")


def test_list_sites_returns_200_when_the_trend_cannot_be_read(monkeypatch, aws,
                                                              secret):
    """端点层的同一件事：**HTTP 仍然是 200**，不是 500。

    `do_list_sites` 不抛不等于端点 200——真正决定用户看到什么的是 handler。
    这条走完整 handler（含 Edge 身份校验），因为"首页 500"才是要防的那个症状。
    """
    import json
    import analytics
    import handler
    import permissions
    from test_handler import _ev                     # 同 test_handler 借用 _seed
    _one_site(monkeypatch, permissions)
    monkeypatch.setattr(analytics, "pv7",
                        lambda sid: (_ for _ in ()).throw(_client_error()))
    r = handler.handler(_ev("GET", "/api/sites", email="me@x.co"), None)
    assert r["statusCode"] == 200, f"趋势读不到把首页打成了 {r['statusCode']}"
    sites = json.loads(r["body"])["sites"]
    assert [s["site_id"] for s in sites] == ["s1"], sites
    assert sites[0]["pv7"] == [] and sites[0]["status"] == "ACTIVE", sites[0]


@pytest.mark.parametrize("state,want_status", [
    # ① 闸门 verify_analytics_e2e ⑦ 段那条"分区键被改成别的站点"的游标。
    #    实测行为一直是 **500**（真实 DynamoDB 的 ValidationException），闸门
    #    因此写成「≥400 且响应体里没有 rows」而不是 `== 500`（M5-FINDINGS §4.21）。
    #    绑定校验之后它是干净的 400——闸门那条断言仍然成立，这里逐字复算一遍。
    ("cross-site", 400),
    ("garbage", 400),                     # 闸门同段的 `cursor=not-a-cursor`
    ("legit", 200),                       # 正对照：合法游标照常 200
])
def test_the_gates_cursor_cases_map_to_stable_status_codes(monkeypatch, aws,
                                                           state, want_status):
    """把闸门里那三个游标输入接到**完整 handler** 上算一遍状态码与响应体。

    读取层单测只看 `visitors()` 抛不抛 `ValueError`；"那到底是 400 还是 500"
    由 handler 的异常映射决定（只有 `ValueError` → 400），所以这一层必须单独钉。
    """
    import base64
    import json
    import handler
    import permissions
    from datetime import datetime, timezone
    from test_handler import _ev
    monkeypatch.setattr("common.get_site_consistent",
                        lambda sid: {"site_id": sid, "owner": "me@x.co",
                                     "collaborators": []})
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if state == "garbage":
        cur = "not-a-cursor"
    else:
        site = "s1" if state == "legit" else "nosuch-site"
        cur = base64.urlsafe_b64encode(json.dumps(
            {"day": day, "key": {"site_date": {"S": f"{site}#{day}"},
                                 "ts_id": {"S": f"{day}T00:00:00+00:00#000"}}}
        ).encode()).decode()
    r = handler.handler(_ev("GET", "/api/sites/s1/visitors", email="me@x.co",
                            qs={"days": "1", "limit": "5", "cursor": cur}), None)
    assert r["statusCode"] == want_status, f"{state}: {r}"
    if want_status != 200:
        # 闸门断言的那半：不返回任何数据。
        assert '"rows"' not in r["body"], r["body"]


def test_the_home_page_does_not_traverse_todays_detail_rows(monkeypatch, aws,
                                                            caplog):
    """P1 回归（端点这一侧）：明细分区多大，首页都只打**一次**明细 Query。

    上一版 `pv7` 对今天走 `while True` 全量分页，而 Edge 给**每一个页面级请求**
    都记一行明细、**包括未登录的 302**——即"今天有多少行"是匿名方可控的输入，
    首页（同时是改权限、下线的入口）的耗时因此被外部决定。`_pv7_or_unknown` 的
    兜底**接不住超时**（进程被杀，没有异常），所以上界必须在读取那侧。

    断言盯的是**做了多少活**（Query 次数），不是墙上时间：耗时断言在系统健康时
    会偶发变红（M5-FINDINGS §4.20），也证明不了"没翻页"。
    读取层自己的用例在 `deployer/tests/test_analytics.py`（含 Limit/BETWEEN
    是否真进了 Query），这条只证明首页这条完整路径确实拿到了那个上界。
    """
    import logging
    import analytics
    import api
    import permissions
    _one_site(monkeypatch, permissions)
    calls, real = [], analytics._client()

    class _Spy:
        """明细表永远"还有下一页"——无上界的读法会翻到抛错（红）。"""

        def query(self, **kw):
            calls.append(kw["TableName"])
            if kw["TableName"] == "site-access-events":
                n = calls.count("site-access-events")
                if n > 5:
                    raise RuntimeError(f"首页翻了 {n} 页明细——读取没有上界")
                return {"Items": [{"email": {"S": "a@x.co"},
                                   "decision": {"S": "allow"}}],
                        "LastEvaluatedKey": {"site_date": {"S": "x#y"},
                                             "ts_id": {"S": f"p{n}"}}}
            return real.query(**kw)

    monkeypatch.setattr(analytics, "_client", lambda: _Spy())
    with caplog.at_level(logging.WARNING):
        out = api.do_list_sites("me@x.co")
    assert calls.count("site-access-events") == 1, (
        f"首页打了 {calls.count('site-access-events')} 次明细 Query: {calls}")
    assert out[0]["pv7"] == [], f"读不完整时必须给「未知」: {out[0]['pv7']}"
    assert out[0]["status"] == "ACTIVE", "趋势未知不该影响站点本身的字段"
    assert any("s1" in r.getMessage() for r in caplog.records
               if r.levelno == logging.WARNING), \
        "行数超上界却没有任何 warning —— 变成了静默降级"


@pytest.mark.parametrize("exc", [
    ValueError("n 必须在 1..400，收到 0"),               # series 的参数校验
    TypeError("unsupported operand"),                    # 纯代码缺陷
])
def test_pv7_failures_that_are_not_infrastructure_still_propagate(
        monkeypatch, aws, exc):
    """兜底范围收窄的证明：**只**接基础设施读失败。

    没有这条，`except Exception` 与收窄版的行为完全一样绿，而前者会把代码缺陷
    吞成"这个站点没有趋势"——本轮 §4.2 记的就是这个形态（吞掉一切的埋点让单测
    静默往生产表写）。
    """
    import analytics
    import api
    import permissions
    _one_site(monkeypatch, permissions)
    monkeypatch.setattr(analytics, "pv7",
                        lambda sid: (_ for _ in ()).throw(exc))
    with pytest.raises(type(exc)):
        api.do_list_sites("me@x.co")


def test_the_swallow_cannot_hide_an_authorization_failure(monkeypatch, aws):
    """兜底**盖不住授权失败**：PermissionDenied 必须继续外溢。

    授权在取趋势之前就做完了（`_require_admin` / `list_sites_for_user` 决定哪些
    站点进列表），这条把"将来有人把 try 的范围扩大到包住授权"钉住：那时这条会红。
    """
    import analytics
    import api
    import permissions
    _one_site(monkeypatch, permissions)
    monkeypatch.setattr(analytics, "pv7", lambda sid: (_ for _ in ()).throw(
        permissions.PermissionDenied("不该被吞掉")))
    with pytest.raises(permissions.PermissionDenied):
        api.do_list_sites("me@x.co")
