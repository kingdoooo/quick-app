import pytest
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


def test_bad_table_spec_fails():
    m = _valid_sql_manifest()
    m["tier"] = "fullstack-nosql"
    m["database"] = {"engine": "dynamodb",
                     "tables": [{"name": "Bad Name!", "pk": "id"},
                                {"name": "dup", "pk": "id"}, {"name": "dup", "pk": "id"}]}
    errs = validate_manifest(m)
    assert any("tables" in e for e in errs)  # 命名非法 + 重复


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
