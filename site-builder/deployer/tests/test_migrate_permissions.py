"""迁移脚本：路由表现值 → sites 表权限字段。"""
import sys
from pathlib import Path

import boto3
import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))


def _put_route(subdomain, site_id, *, require_auth=True, allowed="org",
               owner="o@x.com"):
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": subdomain}, "site_id": {"S": site_id},
        "route_mode": {"S": "split"}, "static_prefix": {"S": f"sites/{site_id}/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": require_auth},
        "allowed_users": {"S": allowed}, "owner": {"S": owner}})


def test_migrates_org_route(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-1", owner="o@x.com", name="one")
    _put_route("app-s-1", "s-1")

    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == ["s-1"]
    site = common.get_site("s-1")
    assert site["require_login"] is True
    assert site["allowed_users"] == "org"
    assert site["collaborators"] == []


def test_migrates_json_string_allowlist(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-2", owner="o@x.com")
    _put_route("app-s-2", "s-2", require_auth=True, allowed='["b@x.com","a@x.com"]')

    mig.migrate("routing", dry_run=False)
    # 迁移时顺带规范化：去重 + 排序
    assert common.get_site("s-2")["allowed_users"] == ["a@x.com", "b@x.com"]


def test_dry_run_writes_nothing(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-3", owner="o@x.com")
    _put_route("app-s-3", "s-3")

    out = mig.migrate("routing", dry_run=True)
    assert out["migrated"] == ["s-3"]          # 报告"会迁移"
    assert "require_login" not in common.get_site("s-3")   # 但没写


def test_skips_already_migrated(aws):
    import common
    import migrate_permissions as mig
    common.upsert_site("s-4", owner="o@x.com", require_login=False,
                       allowed_users=["keep@x.com"], collaborators=[])
    _put_route("app-s-4", "s-4", require_auth=True, allowed="org")

    out = mig.migrate("routing", dry_run=False)
    assert out["skipped"] == ["s-4"]
    # 已迁移的站点不被路由表值覆盖
    assert common.get_site("s-4")["allowed_users"] == ["keep@x.com"]


def test_skips_platform_routes(aws):
    import migrate_permissions as mig
    _put_route("auth", "auth-service", owner="platform")
    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == [] and out["skipped"] == []
    assert out["scanned"] == 1


def test_malformed_allowlist_errors_and_does_not_widen(aws):
    """损坏的名单必须进 errors 并跳过——绝不能被写成 "org"（扩权）。"""
    import common
    import migrate_permissions as mig
    common.upsert_site("s-bad", owner="o@x.com")
    _put_route("app-s-bad", "s-bad", allowed="{not json")

    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == []
    assert out["errors"] and "s-bad" in out["errors"][0]
    # 真源没被写入任何权限字段，Edge 继续按现行 fail-closed 行为工作
    assert "allowed_users" not in common.get_site("s-bad")


def test_reports_route_without_site_record(aws):
    import migrate_permissions as mig
    _put_route("app-ghost", "ghost")     # sites 表没有对应记录
    out = mig.migrate("routing", dry_run=False)
    assert out["errors"] and "ghost" in out["errors"][0]
