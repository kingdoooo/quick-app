"""碰撞 E2E 闸门（`scripts/verify_table_collision_e2e.py`）纯函数部分的验证。

E2E 主体只能在真实 AWS 上跑；这里锁它的**前提**：构造出来的 A/B 两个站点
必须真的拼出同一个物理表名——这个等式垮了，整个探针在测一个不存在的碰撞。
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT = (Path(__file__).parents[2] / "scripts"
           / "verify_table_collision_e2e.py")


def _gate():
    spec = importlib.util.spec_from_file_location("_vtc", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vtc"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_pair_actually_collides():
    """A 的 site_id+logical 与 B 的 site_id+"notes" 必须拼出同一张物理表。"""
    g = _gate()
    pair = g.collision_pair("1a2b3c", "4d5e6f")
    assert pair.site_a == "clsn-1a2b3c"
    assert pair.site_b == "clsn-1a2b3c-4d5e6f"
    assert pair.logical_a == "4d5e6f-notes"
    a_physical = f"site-data-{pair.site_a}-{pair.logical_a}"
    b_physical = f"site-data-{pair.site_b}-notes"
    assert a_physical == b_physical == pair.physical, \
        f"探针前提垮了：{a_physical} != {b_physical}"


def test_logical_a_is_exactly_what_the_contract_forbids():
    """A 的逻辑表名必须含连字符——那正是 TABLE_NAME_RE 要拒的形态。
    有人把构造改成合法名，探针会测"合法名被拒"这种假阴性。"""
    g = _gate()
    pair = g.collision_pair("1a2b3c", "4d5e6f")
    assert "-" in pair.logical_a
    sys.path.insert(0, str(Path(__file__).parents[2] / "contract" / "src"))
    from contract.schema import TABLE_NAME_RE
    assert not TABLE_NAME_RE.fullmatch(pair.logical_a), \
        "A 的逻辑表名竟然合法——探针测不到拒绝路径"


def test_snapshot_tags_go_through_the_paginated_helper(monkeypatch):
    """tag 快照必须走 `common.table_tags`（分页 + 读不到即抛），不许裸调
    `list_tags_of_resource`——裸 API 不翻页，tag 多于一页时快照拿到不完整集合，
    "前后一致"的比较就退化成"前后同样不完整"。

    分页算法本身由 test_common.py::test_table_tags_paginates 钉住；这条钉的是
    **接线**：改动前 helper 测试本来就绿、真机只有 2 个 tag 一页返回——没有这条，
    调用点换回裸 API 时所有测试与真机闸门照样全绿（Codex 复审本计划时指出）。
    """
    g = _gate()
    calls = {}

    def _fake_table_tags(ddb, arn, *, read_attempts=3):
        calls["args"] = (arn, read_attempts)
        return {"b": "2", "a": "1"}          # 乱序，顺带断言排序行为

    class _NoRawApi:
        def list_tags_of_resource(self, **kw):
            raise AssertionError("裸 list_tags_of_resource 被调用——没走分页 helper")

    monkeypatch.setattr(g.sb_common, "table_tags", _fake_table_tags)
    out = g.snapshot_table_tags(_NoRawApi(),
                                "arn:aws:dynamodb:us-east-1:1:table/x")
    assert calls["args"] == ("arn:aws:dynamodb:us-east-1:1:table/x", 1), \
        f"helper 没被调用或 read_attempts 不是 1：{calls}"
    assert out == [("a", "1"), ("b", "2")], out
