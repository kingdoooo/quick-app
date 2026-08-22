"""体检脚本的单测。**必须有**：它是 S1 发布闸门之一，而它上一版是假绿的。"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "scripts"))
import audit_policy_rows as apr  # noqa: E402


def _row(**over):
    row = {"site_id": {"S": "s-1"}, "status": {"S": "ACTIVE"},
           "owner": {"S": "o@example.test"}, "require_login": {"BOOL": True},
           "allowed_users": {"S": "org"}, "collaborators": {"L": []}}
    row.update(over)
    return row


def test_clean_row_passes():
    assert apr.audit([_row()]) == (1, [])


def test_deleted_rows_are_not_audited():
    assert apr.audit([_row(status={"S": "DELETED"},
                           require_login={"N": "0"})]) == (0, [])


@pytest.mark.parametrize("field,value", [
    ("require_login", {"N": "0"}),                    # 会被 bool() 洗成 False
    ("allowed_users", {"L": [{"N": "7"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("allowed_users", {"L": []}),                     # 空名单 ← v1 假绿点
    ("allowed_users", {"L": [{"S": "not-an-email"}]}),  # 过不了 EMAIL_RE ← v1 假绿点
    ("collaborators", {"L": [{"N": "9"}]}),           # L 成员不是字符串 ← v1 假绿点
    ("owner", {"S": ""}),                             # 空 owner
])
def test_bad_shapes_are_reported(field, value):
    n, bad = apr.audit([_row(**{field: value})])
    assert n == 1 and len(bad) == 1, f"{field}={value} 应被报出来"


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_missing_ambiguous_field_is_reported(field):
    row = _row()
    del row[field]
    assert len(apr.audit([row])[1]) == 1


def test_missing_collaborators_is_fine():
    row = _row()
    del row["collaborators"]
    assert apr.audit([row]) == (1, [])
