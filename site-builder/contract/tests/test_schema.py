from contract import validate_manifest


def _valid_sql_manifest():
    return {
        "name": "expense-tracker",
        "tier": "fullstack-sql",
        "backend": {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080},
        "database": {"engine": "dsql", "tables": []},
        "auth": {"require_login": True, "allowed_users": "org"},
    }


def test_valid_fullstack_sql_passes():
    assert validate_manifest(_valid_sql_manifest()) == []


def test_valid_static_minimal_passes():
    m = {"name": "hello", "tier": "static",
         "database": {"engine": "none"},
         "auth": {"require_login": False, "allowed_users": "org"}}
    assert validate_manifest(m) == []


def test_missing_name_fails():
    m = _valid_sql_manifest(); del m["name"]
    assert any("name" in e for e in validate_manifest(m))


def test_bad_name_charset_fails():
    m = _valid_sql_manifest(); m["name"] = "My_App!"
    assert any("name" in e for e in validate_manifest(m))


def test_unknown_tier_fails():
    m = _valid_sql_manifest(); m["tier"] = "fullstack-graphql"
    assert any("tier" in e for e in validate_manifest(m))


def test_static_with_backend_fails():
    m = _valid_sql_manifest(); m["tier"] = "static"
    assert any("backend" in e for e in validate_manifest(m))


def test_fullstack_without_backend_fails():
    m = _valid_sql_manifest(); del m["backend"]
    assert any("backend" in e for e in validate_manifest(m))


def test_tier_engine_mismatch_fails():
    m = _valid_sql_manifest(); m["database"]["engine"] = "dynamodb"
    assert any("engine" in e for e in validate_manifest(m))


def test_bad_runtime_fails():
    m = _valid_sql_manifest(); m["backend"]["runtime"] = "python3.13"  # 二期，PoC 不收
    assert any("runtime" in e for e in validate_manifest(m))


def test_bad_table_name_fails():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb",
                     "tables": [{"name": "Bad Name!", "pk": "id"}]}
    assert any("tables" in e for e in validate_manifest(m))


def test_duplicate_table_names_fail():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb",
                     "tables": [{"name": "dup", "pk": "id"}, {"name": "dup", "pk": "id"}]}
    assert any("重复" in e for e in validate_manifest(m))


def test_database_as_string_returns_errors_not_exception():
    m = _valid_sql_manifest()
    m["database"] = "oops"
    errs = validate_manifest(m)
    assert isinstance(errs, list) and any("database" in e for e in errs)


def test_tables_item_as_string_returns_errors_not_exception():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb", "tables": ["str"]}
    errs = validate_manifest(m)
    assert isinstance(errs, list) and any("tables" in e for e in errs)


def test_table_name_non_string_returns_errors_not_exception():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb", "tables": [{"name": 123, "pk": "id"}]}
    errs = validate_manifest(m)
    assert isinstance(errs, list) and any("tables" in e for e in errs)


def test_name_trailing_newline_fails():
    m = _valid_sql_manifest()
    m["name"] = "myapp\n"
    assert any("name" in e for e in validate_manifest(m))


def test_email_trailing_newline_fails():
    m = _valid_sql_manifest()
    m["auth"]["allowed_users"] = ["a@x.com\n"]
    assert any("allowed_users" in e for e in validate_manifest(m))


def test_sql_with_nonempty_tables_fails():
    m = _valid_sql_manifest()
    m["database"]["tables"] = [{"name": "expenses", "pk": "id"}]
    assert any("tables" in e for e in validate_manifest(m))


def test_allowed_users_list_ok():
    m = _valid_sql_manifest(); m["auth"]["allowed_users"] = ["a@x.com", "b@x.com"]
    assert validate_manifest(m) == []


def test_allowed_users_bad_email_fails():
    m = _valid_sql_manifest(); m["auth"]["allowed_users"] = ["not-an-email"]
    assert any("allowed_users" in e for e in validate_manifest(m))


def test_nosql_tables_required():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb", "tables": []}
    assert any("tables" in e for e in validate_manifest(m))


# ── 表名禁连字符：跨站点物理表名碰撞的构造性消除 ────────────────────────────
#
# 物理表名是 `site-data-{site_id}-{表名}`（common.site_table_name），而 site_id 自身
# 可含 `-`。表名也允许 `-` 时，两个**不同**站点能拼出同一张表：
#   A（id `aa-en3d3a`）声明 `b-rd8fhn-notes`  ⎫
#   B（id `aa-en3d3a-b-rd8fhn`）声明 `notes`  ⎭ → site-data-aa-en3d3a-b-rd8fhn-notes
# 于是 A 的 per-site IAM 精确 ARN 就是 B 的数据表。禁掉表名里的 `-` 之后碰撞不可能：
# 若 `A + "-" + la == B + "-" + lb` 且 A≠B，下标较大的那个 `-` 必落在 `la` 内部。
#
# 属性名（pk）不参与任何资源名，所以**刻意不跟着收紧**——下面那条正对照就是防止
# 有人"顺手统一"两个字符集。

import pytest

from contract.schema import ATTRIBUTE_NAME_RE, TABLE_NAME_RE


def _nosql(name, pk="id"):
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb", "tables": [{"name": name, "pk": pk}]}
    return m


@pytest.mark.parametrize("name", ["notes", "n", "my_notes", "t0", "a" * 30,
                                  "notes_2024"])
def test_legal_table_names_pass(name):
    assert validate_manifest(_nosql(name)) == [], f"{name!r} 本该合法"


@pytest.mark.parametrize("name", [
    "b-rd8fhn-notes",   # 碰撞用的那一种
    "my-notes",         # 最普通的连字符写法
    "-notes",           # 以连字符开头
    "notes-",           # 以连字符结尾
    "Bad Name!",
    "0notes",           # 必须字母开头
    "",
    "a" * 31,           # 超长
])
def test_illegal_table_names_fail(name):
    errs = validate_manifest(_nosql(name))
    assert any("表名" in e for e in errs), f"{name!r} 本该被拒，得到 {errs}"


def test_hyphen_is_legal_in_pk_but_not_in_table_name():
    """**同一个字符串**作 pk 合法、作表名非法——这条锁住"只收紧该收紧的那一半"。

    pk 是 DynamoDB 属性名，不参与任何资源名，DynamoDB 本身也接受 `-`。为了修物理
    表名碰撞而顺带禁掉历史 pk 的字符集，是与该安全性质无关的合同收窄。
    """
    s = "my-key"
    assert validate_manifest(_nosql("notes", pk=s)) == [], \
        f"pk={s!r} 本该合法（属性名允许连字符）"
    assert any("表名" in e for e in validate_manifest(_nosql(s))), \
        f"表名={s!r} 本该被拒"


def test_table_name_and_pk_errors_are_distinguishable():
    """两个字段各出一条可区分的信息。

    原来是**合成一条**（"表名/主键须匹配 …"），于是一个误伤 pk 的回归与"表名不合法"
    长得一模一样，而既有用例都只断言 `any("tables" in e ...)`，分辨不出来。
    """
    only_name = validate_manifest(_nosql("my-notes", pk="id"))
    only_pk = validate_manifest(_nosql("notes", pk="Bad Key!"))
    both = validate_manifest(_nosql("my-notes", pk="Bad Key!"))

    assert any("表名" in e for e in only_name)
    assert not any("主键" in e for e in only_name), "误报了 pk"
    assert any("主键" in e for e in only_pk)
    assert not any("表名" in e for e in only_pk), "误报了表名"
    assert any("表名" in e and "主键" in e for e in both), \
        "两者都非法时应同时点出两个字段"


def test_table_name_message_says_how_to_fix_not_just_the_regex():
    """文案必须自解释，不能只回显正则。

    Skill 的合同文档是用户 `cp -r` 出去的快照，没有版本标记也没有漂移检测——升级后
    一段时间内他手里的文档仍写着 `-` 合法，而他唯一能看到的就是这条文案。
    """
    err = " ".join(validate_manifest(_nosql("my-notes")))
    assert "连字符" in err, "没说清是连字符的问题"
    assert "_" in err, "没告诉用户用下划线代替"


def test_the_two_charsets_are_not_the_same_object():
    """结构断言：两个正则不许被"统一"回一条。

    行为断言只覆盖当前这批样例；这条防的是有人把 ATTRIBUTE_NAME_RE 直接指向
    TABLE_NAME_RE（那样 pk 会被无理由收紧，而上面的正对照也会红——但先红在这里
    信息更直接）。
    """
    # **按行为判，不按 pattern 源文本判**：`[a-z]` 里的 `-` 是范围符，
    # `"-" in TABLE_NAME_RE.pattern` 恒为真（第一版就这么写、当场红）。
    assert TABLE_NAME_RE.fullmatch("a-b") is None, "表名正则又允许连字符了"
    assert ATTRIBUTE_NAME_RE.fullmatch("a-b") is not None, "属性名正则被顺带收紧了"
    assert TABLE_NAME_RE.pattern != ATTRIBUTE_NAME_RE.pattern
