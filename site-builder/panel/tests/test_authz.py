"""panel 授权矩阵：owner / collaborator / admin / outsider × 各端点。

**为什么要整矩阵而不是抽查**：CAPABILITIES 里 collaborator 有
set_access_policy 但**没有** manage_collaborators / transfer_owner /
undeploy。这个不对称是 M2 三轮审查的结论（transfer_owner 把旧 owner 降为
collaborator 后不能再下线站点），panel 必须继承它而不是自己发明一套。

期望矩阵**从 permissions.CAPABILITIES 推导**，不手抄第二份：手抄的那份会与
真源漂移，而漂移方向通常是"放宽"（本仓库既有教训）。
"""
import pytest

import api
import common
import permissions

# action 名 → 触发该 action 的 api 调用。写操作都带副作用，
# 便于顺带断言"被拒时什么都没写"。
WRITE_CALLS = {
    "set_access_policy": lambda who: api.do_set_access(who, "s-1",
                                                       require_login=False),
    "manage_collaborators": lambda who: api.do_set_collaborators(
        who, "s-1", add=["new@x.com"]),
    "transfer_owner": lambda who: api.do_transfer_owner(who, "s-1",
                                                        new_owner="new@x.com"),
}


def _seed(site_id="s-1", owner="owner@x.com", collaborators=("collab@x.com",)):
    common._table("SITES_TABLE").put_item(Item={
        "site_id": site_id, "owner": owner, "name": "s",
        "status": "ACTIVE", "collaborators": list(collaborators),
        "require_login": True, "allowed_users": "org", "permissions_rev": 1,
        "created_at": "2026-07-01T00:00:00+00:00"})
    common._table("ROUTING_TABLE").put_item(Item={
        "subdomain": common.subdomain_for(site_id), "site_id": site_id,
        "owner": owner, "require_auth": True, "allowed_users": "org",
        "collaborators": list(collaborators), "permissions_rev": 1})


@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
@pytest.mark.parametrize("who,role", [("owner@x.com", "owner"),
                                      ("collab@x.com", "collaborator"),
                                      ("nobody@x.com", "none")])
def test_write_matrix_matches_capabilities(aws, action, who, role):
    _seed()
    allowed = role in permissions.CAPABILITIES[action]
    if allowed:
        WRITE_CALLS[action](who)          # 不抛即通过
    else:
        before = common.get_site("s-1")
        with pytest.raises(permissions.PermissionDenied):
            WRITE_CALLS[action](who)
        # 被拒时不得有任何写入落地
        assert common.get_site("s-1") == before


def test_collaborator_can_set_access_but_not_manage_or_transfer(aws):
    """把上面那张矩阵里最要命的一格单独写出来，读代码的人一眼能看到。"""
    _seed()
    api.do_set_access("collab@x.com", "s-1", require_login=False)   # 允许
    for call in (lambda: api.do_set_collaborators("collab@x.com", "s-1",
                                                  add=["x@x.com"]),
                 lambda: api.do_transfer_owner("collab@x.com", "s-1",
                                               new_owner="x@x.com"),
                 lambda: api.do_undeploy("collab@x.com", "s-1")):
        with pytest.raises(permissions.PermissionDenied):
            call()


def test_admin_gets_owner_grade_powers_on_others_site(aws):
    """admin 代管：CAPABILITIES 里 admin 与 owner 同集合。"""
    _seed()
    permissions.add_admin("boss@x.com", "seed")
    api.do_transfer_owner("boss@x.com", "s-1", new_owner="new@x.com")
    assert common.get_site("s-1")["owner"] == "new@x.com"


def test_admin_beats_collaborator_role_not_the_other_way(aws):
    """admin 兼任协作者时必须拿 admin 的能力（role_of 的判定顺序）。

    若返回 collaborator，他就拿不到 undeploy / transfer_owner——等于被自己的
    协作者身份降权（permissions.role_of 的 docstring 记录了这个坑）。
    """
    _seed(collaborators=("boss@x.com",))
    permissions.add_admin("boss@x.com", "seed")
    assert api.do_get_site("boss@x.com", "s-1")["role"] == "admin"
    api.do_transfer_owner("boss@x.com", "s-1", new_owner="new@x.com")


def test_outsider_cannot_even_read_and_message_hides_existence(aws):
    """"存在但无权"与"不存在"必须给**同一句话**（否则是站点枚举探测器）。

    比较时把各自的 site_id 抠掉：文案里回显调用方自己传进来的 site_id 不是
    泄漏（他本来就知道自己查了什么），泄漏的是**存在性**。所以断言的是
    "去掉 site_id 后两句完全相同"，而不是两个字符串逐字相等——后者会因为
    回显而永远失败，是我第一版写错的地方。
    """
    _seed()
    with pytest.raises(permissions.PermissionDenied) as a:
        api.do_get_site("nobody@x.com", "s-1")
    with pytest.raises(permissions.PermissionDenied) as b:
        api.do_get_site("nobody@x.com", "s-doesnotexist")
    assert str(a.value).replace("s-1", "{id}") == \
        str(b.value).replace("s-doesnotexist", "{id}")
    # 且不得出现任何存在性词汇的分叉
    for msg in (str(a.value), str(b.value)):
        assert "不存在" in msg and "无权访问" in msg


def test_list_sites_all_requires_admin(aws):
    _seed()
    with pytest.raises(permissions.PermissionDenied):
        api.do_list_sites("owner@x.com", all_sites=True)
    permissions.add_admin("boss@x.com", "seed")
    assert api.do_list_sites("boss@x.com", all_sites=True)


def test_list_sites_mine_excludes_others(aws):
    _seed()
    _seed("s-2", owner="other@x.com", collaborators=())
    got = {s["site_id"] for s in api.do_list_sites("owner@x.com")}
    assert got == {"s-1"}


def test_list_sites_includes_sites_i_collaborate_on(aws):
    _seed()
    got = {s["site_id"] for s in api.do_list_sites("collab@x.com")}
    assert got == {"s-1"}


def test_admin_endpoints_require_admin(aws):
    for call in (lambda: api.do_list_admins("owner@x.com"),
                 lambda: api.do_add_admin("owner@x.com", "x@x.com"),
                 lambda: api.do_remove_admin("owner@x.com", "x@x.com")):
        with pytest.raises(permissions.PermissionDenied):
            call()


def test_me_reports_admin_flag(aws):
    assert api.do_me("owner@x.com", "Owner")["is_admin"] is False
    permissions.add_admin("boss@x.com", "seed")
    assert api.do_me("boss@x.com", "Boss")["is_admin"] is True


def test_resync_requires_admin_and_rebuilds_route_from_sites(aws):
    """resync 以 sites 表为准重投影——被人为改脏的 route 必须被纠正。"""
    _seed()
    permissions.add_admin("boss@x.com", "seed")
    # 人为把投影改脏：require_auth 改成 False（等于站点被公开）
    common._table("ROUTING_TABLE").update_item(
        Key={"subdomain": common.subdomain_for("s-1")},
        UpdateExpression="SET require_auth = :f",
        ExpressionAttributeValues={":f": False})
    with pytest.raises(permissions.PermissionDenied):
        api.do_resync("owner@x.com", "s-1")     # 非 admin 不行
    api.do_resync("boss@x.com", "s-1")
    route = common._table("ROUTING_TABLE").get_item(
        Key={"subdomain": common.subdomain_for("s-1")})["Item"]
    assert route["require_auth"] is True, "resync 没有把投影纠回 sites 表的值"


def test_resync_does_not_bump_rev(aws):
    """rev 虚增会让下一次**合法**部署误判成"权限被并发修改"。"""
    _seed()
    permissions.add_admin("boss@x.com", "seed")
    api.do_resync("boss@x.com", "s-1")
    site = common.get_site("s-1")
    route = common._table("ROUTING_TABLE").get_item(
        Key={"subdomain": common.subdomain_for("s-1")})["Item"]
    assert int(site["permissions_rev"]) == 1
    assert int(route["permissions_rev"]) == 1


def test_jobs_history_is_newest_first_and_derives_duration(aws):
    _seed()
    for jid, c, u in [("job-1", "2026-06-01T00:00:00+00:00",
                       "2026-06-01T00:01:40+00:00"),
                      ("job-2", "2026-07-01T00:00:00+00:00",
                       "2026-07-01T00:00:30+00:00")]:
        common._table("JOBS_TABLE").put_item(Item={
            "job_id": jid, "site_id": "s-1", "owner": "owner@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": c, "updated_at": u})
    jobs = api.do_list_jobs("owner@x.com", "s-1")
    assert [j["job_id"] for j in jobs] == ["job-2", "job-1"]
    assert jobs[0]["duration_s"] == 30 and jobs[1]["duration_s"] == 100
    assert jobs[0]["by"] == "owner@x.com"      # requested_by 语义


def test_jobs_history_requires_read_permission(aws):
    _seed()
    with pytest.raises(permissions.PermissionDenied):
        api.do_list_jobs("nobody@x.com", "s-1")


def test_jobs_duration_survives_missing_or_bad_timestamps(aws):
    """派生字段不能因脏数据抛异常——控制台整页会挂。"""
    _seed()
    common._table("JOBS_TABLE").put_item(Item={
        "job_id": "job-bad", "site_id": "s-1", "owner": "owner@x.com",
        "status": "FAILED", "phase": "validate", "error": "x", "url": "",
        "created_at": "not-a-date", "updated_at": ""})
    assert api.do_list_jobs("owner@x.com", "s-1")[0]["duration_s"] == 0


def test_site_shape_exposes_created_at_even_when_absent(aws):
    """Task 5 回填对"无 job 的站点"不猜，所以 created_at 可能为空字符串。"""
    _seed()
    common._table("SITES_TABLE").update_item(
        Key={"site_id": "s-1"}, UpdateExpression="REMOVE created_at")
    assert api.do_get_site("owner@x.com", "s-1")["created_at"] == ""
