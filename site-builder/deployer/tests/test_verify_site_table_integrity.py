"""表名归属完整性闸门的**反向验证**。

那个闸门在真机上永远是绿的（生产状态正确时），所以它必须能证明自己会红。要害判定
（`role_arn_problems`）被抽成纯函数正是为了这个：这里喂进三种坏形态，各自必须被咬住。

**最要紧的是第三条**：判据若写成"role 里的 ARN 指向某张存在且 tag 正确的表"，A 的角色
指向 B 的表会被判绿——别的站点的表当然也"存在且 tag 正确"。那正是本闸门要抓的越权
形态，也是这一整轮 P1 落地后的样子。
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = (Path(__file__).parents[2] / "scripts"
           / "verify_site_table_integrity.py")


def _gate():
    """按路径加载那个脚本（它不是包的一部分，且 import 时不该触发 main）。"""
    spec = importlib.util.spec_from_file_location("_vsti", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vsti"] = mod
    spec.loader.exec_module(mod)
    return mod


A, B = "aa-en3d3a", "bb-x9y8z7"
ARN_A = f"arn:aws:dynamodb:us-east-1:1:table/site-data-{A}-notes"
ARN_B = f"arn:aws:dynamodb:us-east-1:1:table/site-data-{B}-notes"
OWNED = {A: {ARN_A}, B: {ARN_B}}


def test_correct_state_is_green():
    """正对照：状态正确时必须没有任何问题——否则下面几条红了也证明不了什么。"""
    g = _gate()
    assert g.role_arn_problems(A, "dynamodb", {ARN_A}, OWNED) == []
    assert g.role_arn_problems(B, "dynamodb", {ARN_B}, OWNED) == []
    assert g.role_arn_problems("dsql-site-x1", "dsql", set(), OWNED) == []


def test_a_role_pointing_at_another_sites_table_is_caught():
    """**要害**：A 的角色指向 B 的表 ⇒ 必须红，且报文要点出"属于别的站点"。

    这是 P1 落地后的形态。判据写成"ARN 指向某张有效的表"时这里会绿。
    """
    g = _gate()
    problems = g.role_arn_problems(A, "dynamodb", {ARN_A, ARN_B}, OWNED)
    assert problems, "A 的角色拿到了 B 的表 ARN 却判成了合规"
    joined = " ".join(problems)
    assert ARN_B in joined
    assert "属于别的站点" in joined, f"没点出越权性质：{problems}"


def test_a_role_pointing_only_at_another_sites_table_is_caught():
    """更纯粹的形态：A 的角色**只**有 B 的表（自己的那张都没有）。"""
    g = _gate()
    problems = g.role_arn_problems(A, "dynamodb", {ARN_B}, OWNED)
    joined = " ".join(problems)
    assert "属于别的站点" in joined and "缺少" in joined, problems


def test_wildcard_in_a_table_arn_is_caught():
    """通配回来了 ⇒ 红。那是 M01 本身，禁掉表名连字符不能变成放回通配的理由。"""
    g = _gate()
    wild = f"arn:aws:dynamodb:us-east-1:1:table/site-data-{A}-*"
    problems = g.role_arn_problems(A, "dynamodb", {wild}, OWNED)
    assert any("通配" in p for p in problems), problems


def test_a_dsql_role_with_a_dynamodb_table_is_caught():
    """DSQL 站点的角色不该有任何 DynamoDB 表 ARN。"""
    g = _gate()
    problems = g.role_arn_problems("dsql-x1", "dsql", {ARN_B}, OWNED)
    assert problems and "不该有" in " ".join(problems), problems


def test_a_missing_table_arn_is_caught():
    """少了自己的表 ⇒ 也红（站点运行时会 AccessDenied，是另一个方向的故障）。"""
    g = _gate()
    problems = g.role_arn_problems(A, "dynamodb", set(), OWNED)
    assert any("缺少" in p for p in problems), problems


def test_a_nosql_site_with_no_verified_table_is_caught():
    """NoSQL 站点一张经 tag 验证的表都没有 ⇒ 无法核对，按失败处理。

    **不能当成"集合都空所以相等"**——那是本闸门最容易平凡成立的方式
    （空账号里一切集合相等）。
    """
    g = _gate()
    problems = g.role_arn_problems("ghost-x1", "dynamodb", set(), OWNED)
    assert problems and "无法核对" in " ".join(problems), problems


def test_owned_map_must_be_global_not_just_this_site():
    """判"多出来的是不是别站的表"必须看全局 map。

    只传本站那一份时，越权仍会被报成"多出"，但**丢掉了"属于别的站点"这个定性**
    ——而那句话是运维看一眼就知道严重性的唯一线索。
    """
    g = _gate()
    only_mine = {A: {ARN_A}}
    problems = g.role_arn_problems(A, "dynamodb", {ARN_A, ARN_B}, only_mine)
    assert problems, "仍应报出多余 ARN"
    assert "属于别的站点" not in " ".join(problems), (
        "只传本站 map 时不该凭空断言归属——这条锁住 main() 必须传全局 map")
