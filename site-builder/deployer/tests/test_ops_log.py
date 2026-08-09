"""ops-log：高层写函数 + undeploy 各落一条，且不记敏感字段。

落点在 permissions.write_permissions（唯一出口）而不是各 setter，也不在 panel
handler——放 handler 会让 MCP 侧的同一动作漏记（spec §5.5）。
"""
import boto3
import pytest

import common
import ops_log
import permissions


def _logs():
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-ops-log").scan()["Items"]


def _seed(site_id="s-1", owner="owner@x.com"):
    common._table("SITES_TABLE").put_item(Item={
        "site_id": site_id, "owner": owner, "name": "s", "status": "ACTIVE",
        "collaborators": [], "require_login": True, "allowed_users": "org",
        "permissions_rev": 1})
    common._table("ROUTING_TABLE").put_item(Item={
        "subdomain": common.subdomain_for(site_id), "site_id": site_id,
        "owner": owner, "require_auth": True, "allowed_users": "org",
        "collaborators": [], "permissions_rev": 1})


def test_set_access_policy_records(aws):
    _seed()
    permissions.set_access_policy("s-1", actor="owner@x.com", require_login=False)
    rows = _logs()
    assert len(rows) == 1
    assert rows[0]["action"] == "set_access_policy"
    assert rows[0]["actor"] == "owner@x.com"
    assert rows[0]["target"] == "site:s-1"
    assert rows[0]["result"] == "ok"
    assert int(rows[0]["expires_at"]) > 0        # TTL 必须有


def test_collaborators_and_transfer_record(aws):
    _seed()
    permissions.set_collaborators("s-1", actor="owner@x.com", add=["c@x.com"])
    permissions.transfer_owner("s-1", actor="owner@x.com", new_owner="new@x.com")
    actions = {r["action"] for r in _logs()}
    assert {"manage_collaborators", "transfer_owner"} <= actions


def test_admin_add_and_remove_record(aws):
    permissions.add_admin("a@x.com", "seed")
    permissions.add_admin("b@x.com", "seed")
    permissions.remove_admin("b@x.com")
    rows = {r["action"]: r for r in _logs()}
    assert "add_admin" in rows and "remove_admin" in rows
    assert rows["add_admin"]["target"].startswith("admins:")


def test_denied_write_also_records(aws):
    """失败操作也要有可判读记录（spec §5.5）。"""
    _seed()
    with pytest.raises(permissions.PermissionDenied):
        permissions.set_access_policy("s-1", actor="nobody@x.com",
                                      require_login=False)
    rows = [r for r in _logs() if r["result"] != "ok"]
    assert rows and rows[0]["action"] == "set_access_policy"
    assert rows[0]["actor"] == "nobody@x.com"


def test_denied_record_does_not_leak_the_exception_text(aws):
    """拒绝原文含"或该站点不存在"的存在性提示，不得进审计表。

    审计表的读者与被拒者不是同一批人，把原文落库等于开一条侧信道。
    """
    _seed()
    with pytest.raises(permissions.PermissionDenied):
        permissions.set_access_policy("s-1", actor="nobody@x.com",
                                      require_login=False)
    import json
    blob = json.dumps(_logs(), default=str)
    assert "不存在" not in blob and "无权访问" not in blob


def test_undeploy_records(aws, monkeypatch):
    """下线路径落一条，并记下 purge_data（不可恢复动作要能审计）。"""
    import undeploy
    _seed()
    jid = common.create_job("owner@x.com", "s-1")
    undeploy.handler({"site_id": "s-1", "job_id": jid}, None)
    rows = [r for r in _logs() if r["action"] == "undeploy"]
    assert rows, "下线没有落审计"
    assert rows[0]["target"] == "site:s-1"
    assert "purge_data" in rows[0]["detail"]


def test_log_failure_does_not_break_a_succeeded_business_action(aws, monkeypatch):
    """落日志失败**不得**把已成功的业务动作变成未知状态。"""
    _seed()

    def boom(**kw):
        raise RuntimeError("ops-log 表挂了")

    monkeypatch.setattr(ops_log, "_put", boom)
    permissions.set_access_policy("s-1", actor="owner@x.com", require_login=False)
    # 业务动作必须已落地
    assert common.get_site("s-1")["require_login"] is False


def test_no_secrets_recorded(aws):
    """不记 token / cookie / secret / 完整 key / 上游错误原文。

    **按整行断言而非逐字段**：逐字段检查漏掉未来新增的字段，而"整行不含这些
    字样"对新增字段自动生效（本项目既有教训）。
    """
    import json
    _seed()
    permissions.set_access_policy("s-1", actor="owner@x.com",
                                  allowed_users=["a@x.com"])
    blob = json.dumps(_logs(), default=str).lower()
    for bad in ("authorization", "bearer ", "cookie", "secret", "__host-",
                "eyj", "aws_access", "sessiontoken", "password"):
        assert bad not in blob, f"ops-log 里出现敏感字样 {bad!r}"


def test_scrub_drops_sensitive_keys_from_detail(aws):
    """detail 里带敏感键时整键丢弃（调用方一时疏忽也不会落库）。"""
    ops_log.record(actor="a@x.com", action="probe", target="site:s-1",
                   result="ok",
                   detail={"role": "owner", "jwt_secret": "hunter2",
                           "session_token": "abc", "api_key": "k"})
    row = _logs()[0]
    assert "owner" in row["detail"]
    for bad in ("hunter2", "abc", "api_key", "session_token", "jwt_secret"):
        assert bad not in row["detail"], f"敏感键 {bad} 落库了"


def test_detail_is_length_capped(aws):
    """上游错误原文可能极长——审计行不该被一条巨型 detail 撑爆。"""
    ops_log.record(actor="a@x.com", action="probe", target="site:s-1",
                   result="ok", detail={"note": "x" * 5000})
    assert len(_logs()[0]["detail"]) <= 1024


def test_sort_key_is_ts_then_actor(aws):
    _seed()
    permissions.set_access_policy("s-1", actor="owner@x.com", require_login=False)
    row = _logs()[0]
    ts, sep, actor = row["ts_actor"].partition("#")
    assert sep == "#" and actor == "owner@x.com" and ts.startswith("20")


def test_two_actions_on_same_site_do_not_collide(aws):
    """同一 target 下多条记录必须都留存（SK 含 ts+actor，不是只有 actor）。"""
    _seed()
    permissions.set_access_policy("s-1", actor="owner@x.com", require_login=False)
    permissions.set_access_policy("s-1", actor="owner@x.com", require_login=True)
    assert len(_logs()) == 2, "第二条覆盖了第一条——审计是 append-only"


def test_record_is_put_only_never_update(aws):
    """审计不可改写：ops_log 模块里不得出现 update/delete 调用。"""
    import ast
    from pathlib import Path
    src = (Path(ops_log.__file__)).read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("update_item", "delete_item"), (
                f"ops_log 出现了 {node.func.attr}——审计必须 append-only")
