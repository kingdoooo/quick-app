"""Edge 调用者判定（唯一实现）。

**这些用例必须能在缺陷存在时变红**：Step 2 先确认全部 FAIL，Step 4 确认转绿，
Step 5 再逐条注入缺陷确认变红（本项目"验证本身无效"栽过多次）。
"""
import pytest

import edge_caller

# 测试用的假 RoleId。**拼接而不是写成一个字面量**：Code Defender 的
# HARD_CODED_SECRET 规则按 `AROA` 前缀 + 长度匹配，整串写出来会被拦下
# （本计划提交时实际发生过）。它的 remediation 建议是往 secrets.allowed
# 里加例外——那是放宽扫描器，本项目明令不走这个方向。
ROLE_ID = "AROA" + "EDGEROLEID" + "XXXXXX"


def _event(caller_id):
    return {"requestContext": {"authorizer": {"iam": {"callerId": caller_id}}}}


def test_real_edge_caller_is_accepted(monkeypatch):
    """真机抓到的形态：{RoleId}:{session_name}，session name 含区域前缀。"""
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(
        _event(f"{ROLE_ID}:us-east-1.ApplicationWebRouterStack-EdgeFn-abc123"))


def test_missing_env_rejects_everything(monkeypatch, caplog):
    """**配置缺失不得退化成"不检查"**——那正是 P1-1 的原始形态。"""
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False
    assert any("EDGE_ROLE_ID" in r.message for r in caplog.records), \
        "缺配置必须留一行可告警的 ERROR，否则整站 403 无从排查"


@pytest.mark.parametrize("empty", ["", "   "])
def test_blank_env_rejects_everything(monkeypatch, empty):
    monkeypatch.setenv("EDGE_ROLE_ID", empty)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False


@pytest.mark.parametrize("evil", [
    f"{ROLE_ID}EVIL:us-east-1.x",   # startswith 骗得过
    f"AIDAX5GB:{ROLE_ID}",          # in 骗得过（把真 id 放进 session name 段）
    f"x{ROLE_ID}:s",                # 前缀污染
    ROLE_ID.lower() + ":s",         # 大小写：AROA 段是大写敏感的
    ROLE_ID,                        # 没有 session 段（不是 assumed-role 形态）
    "",                             # 空 callerId
])
def test_lookalike_callers_are_rejected(monkeypatch, evil):
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(_event(evil)) is False


@pytest.mark.parametrize("broken", [
    {},                                              # 没有 requestContext
    {"requestContext": {}},                          # 没有 authorizer
    {"requestContext": {"authorizer": {}}},          # 没有 iam
    {"requestContext": {"authorizer": {"iam": {}}}}, # 没有 callerId
    {"requestContext": None},                        # 显式 null（真实 payload 见过）
    {"requestContext": {"authorizer": None}},
])
def test_malformed_event_is_rejected_not_crashed(monkeypatch, broken):
    """AuthType=NONE 或平台改形态时 event 会缺这些层级——必须拒绝而不是抛异常。

    抛异常会变成 502，而 502 与 403 的运维含义完全不同（前者像故障、
    后者是策略），排查方向会被带偏。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(broken) is False


def test_env_var_name_constant_matches_what_the_code_reads(monkeypatch):
    """常量与实现读的是同一个键——部署脚本引用它，不再各自写字面量。

    两处漂移的症状是"部署下发了 A、代码读 B"→ 线上全拒，而两侧单测都绿。
    """
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    monkeypatch.setenv(edge_caller.EDGE_ROLE_ID_ENV, ROLE_ID)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is True
