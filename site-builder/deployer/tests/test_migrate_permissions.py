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
    # 真源没被写入**任何**权限字段（只查 allowed_users 抓不到"写了一半"——
    # 比如只写了 require_login，下游 get 的默认值照样把名单放大成 org）
    assert not (PERMISSION_FIELDS & set(common.get_site("s-bad")))


def test_reports_route_without_site_record(aws):
    import migrate_permissions as mig
    _put_route("app-ghost", "ghost")     # sites 表没有对应记录
    out = mig.migrate("routing", dry_run=False)
    assert out["errors"] and "ghost" in out["errors"][0]


PERMISSION_FIELDS = {"require_login", "allowed_users", "collaborators",
                     "permissions_updated_at", "permissions_updated_by",
                     "permissions_rev"}


@pytest.mark.parametrize("av", [
    {"SS": ["vip@x.com", "boss@x.com"]},   # 人在控制台修名单最容易选的类型
    {"NULL": True},
    {"N": "0"},
    {"BOOL": False},
])
def test_unknown_attribute_type_errors_and_does_not_widen(aws, av):
    """SS/NULL/N/BOOL 形态的 allowed_users 必须进 errors，绝不落成 "org"。

    raw.get("S", "org") 的写法会让这些类型双双错过 S/L 分支、静默扩权成
    全组织放行——而 spec §3.4 的救济流程（人工手修路由表）恰好会产出 SS。
    Edge 对这些类型的现行为是 fail-closed（读成 False → 空名单），迁移
    绝不能比 Edge 更宽。
    """
    import boto3
    import common
    import migrate_permissions as mig
    common.upsert_site("s-odd", owner="o@x.com")
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-odd"}, "site_id": {"S": "s-odd"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-odd/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": av, "owner": {"S": "o@x.com"}})
    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == []
    assert out["errors"] and "s-odd" in out["errors"][0]
    # 一个权限字段都不许写（半套写入照样把下游默认放大成 org）
    assert not (PERMISSION_FIELDS & set(common.get_site("s-odd")))


def test_absent_allowed_users_attribute_is_rejected_not_widened_to_org(aws):
    """属性整体缺失**不再**回落 "org"。

    旧版本回落 org，理由是"与 Edge 的默认一致"——**那个理由已过时**：
    现行 Edge 是 `route.get("allowed_users") if "allowed_users" in route else []`，
    缺失即空名单（fail-closed）。继续回落 org 就是静默扩权，
    而且是在一次"数据修复"动作里扩权。判不出原意就报错，让人来定。
    """
    import migrate_permissions
    with pytest.raises(migrate_permissions.UnparsableAllowlist, match="缺失"):
        migrate_permissions._parse_allowed({})


def test_dry_run_writes_no_permission_field_at_all(aws):
    """dry-run 必须一个权限字段都不写——只断言 require_login 抓不到
    "漏写了一半"的 bug（比如只把 allowed_users 写成了 org）。"""
    import common
    import migrate_permissions as mig
    common.upsert_site("s-3", owner="o@x.com")
    _put_route("app-s-3", "s-3")
    out = mig.migrate("routing", dry_run=True)
    assert out["migrated"] == ["s-3"]
    # 完全空的行：两个字段都会写，没有任何在线值需要保留
    assert out["planned"]["s-3"] == {"require_login": True,
                                     "allowed_users": "org",
                                     "kept_from_online": []}
    assert not (PERMISSION_FIELDS & set(common.get_site("s-3")))


def test_one_malformed_route_does_not_abort_scan(aws):
    """一条畸形路由（L 里混 NULL）不得中止扫描——apply 中止 = 半套迁移 + 无报告。"""
    import boto3
    import common
    import migrate_permissions as mig
    common.upsert_site("s-good1", owner="o@x.com")
    common.upsert_site("s-bad", owner="o@x.com")
    common.upsert_site("s-good2", owner="o@x.com")
    _put_route("app-s-good1", "s-good1")
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-bad"}, "site_id": {"S": "s-bad"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-bad/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"L": [{"S": "a@x.com"}, {"NULL": True}]},
        "owner": {"S": "o@x.com"}})
    _put_route("app-s-good2", "s-good2")
    out = mig.migrate("routing", dry_run=False)
    assert sorted(out["migrated"]) == ["s-good1", "s-good2"]   # 两条好的都完成
    assert out["errors"] and "s-bad" in out["errors"][0]
    assert "require_login" in common.get_site("s-good2")       # 真的写进去了


def test_concurrent_seed_wins_over_migration(aws, monkeypatch):
    """迁移读快照后、写入前，部署把权限 seed 进来了 → 迁移必须让位。

    upsert_site 式的无条件写会用路由表旧值（org）盖掉刚 seed 的更紧名单；
    条件写 attribute_not_exists(require_login) 失败时按 skipped 处理。
    """
    import common
    import migrate_permissions as mig
    common.upsert_site("s-race", owner="o@x.com")
    _put_route("app-s-race", "s-race", allowed="org")
    real_get_site = common.get_site

    def _seed_after_read(site_id):
        site = real_get_site(site_id)
        if site_id == "s-race" and site is not None:
            # 部署链的 seed 抢在迁移写入之前落库（更紧的名单 + rev=1）
            common.upsert_site(site_id, require_login=True,
                               allowed_users=["vip@x.com"], permissions_rev=1)
        return site

    # migrate() 在函数体内 import common——拿到的是 sys.modules 里同一个模块
    # 对象，patch common.get_site 即可命中
    monkeypatch.setattr(common, "get_site", _seed_after_read)
    out = mig.migrate("routing", dry_run=False)
    assert out["migrated"] == []
    assert out["skipped"] == ["s-race"]
    # seed 的名单毫发无损，没被路由表的 "org" 盖掉
    assert common.get_site("s-race")["allowed_users"] == ["vip@x.com"]


def test_migrated_row_advances_rev_to_one(aws):
    """迁移写入的行必须带 permissions_rev=1，与两个 organic seeder 同构——
    缺失会让 register_route 的 ConditionCheck 察觉不到这次初始化。"""
    import common
    import migrate_permissions as mig
    common.upsert_site("s-rev", owner="o@x.com")
    _put_route("app-s-rev", "s-rev")
    mig.migrate("routing", dry_run=False)
    assert int(common.get_site("s-rev")["permissions_rev"]) == 1


def test_sparse_row_keeps_online_allowlist(aws):
    """只在线改过 allowed_users 的稀疏行：迁移不得用路由表旧值覆盖它。

    旧实现只看 require_login 当 sentinel，判成"未迁移"后无条件 SET 两个字段，
    把在线设的私有名单盖回路由表里的 "org"——而报告显示为 migrated 成功
    （moto 实证）。这是数据修复动作变成静默扩权。

    **稀疏行直接造，不再用 `set_access_policy` 造**（M02，本文件三条同理）：
    写路径改走 `effective_policy` 严格解析后会拒绝缺字段的行，在线接口不再
    产出该形态；而迁移脚本要处理的恰恰是**存量遗留**的这种行，所以照原样造。
    """
    import common
    import migrate_permissions as mig

    common.upsert_site("s-sparse", owner="o@x.com", name="n",
                       allowed_users=["only@example.com"], permissions_rev=1)
    assert "require_login" not in common.get_site_consistent("s-sparse")
    _put_route("app-s-sparse", "s-sparse", require_auth=True, allowed="org")

    out = mig.migrate("routing", dry_run=False)
    site = common.get_site_consistent("s-sparse")
    assert site["allowed_users"] == ["only@example.com"]   # 在线值保留
    assert site["require_login"] is True                    # 缺字段被补上
    # 报告只能宣称写了真正写的那个字段
    assert out["planned"]["s-sparse"]["kept_from_online"] == ["allowed_users"]
    assert "allowed_users" not in out["planned"]["s-sparse"]


def test_sparse_row_keeps_online_require_login(aws):
    """反向稀疏：只改过 require_login 的行，allowed_users 由路由表补上。"""
    import common
    import migrate_permissions as mig

    common.upsert_site("s-sparse2", owner="o@x.com", name="n",
                       require_login=False, permissions_rev=1)
    assert "allowed_users" not in common.get_site_consistent("s-sparse2")
    _put_route("app-s-sparse2", "s-sparse2", require_auth=True,
               allowed='["from-route@x.com"]')

    mig.migrate("routing", dry_run=False)
    site = common.get_site_consistent("s-sparse2")
    assert site["require_login"] is False                     # 在线值保留
    assert site["allowed_users"] == ["from-route@x.com"]      # 缺字段被补上


def test_dry_run_report_renders_for_sparse_rows(aws, capsys):
    """main() 的打印不得假定 planned 两个键都在（稀疏行只有一个）。"""
    import common
    import migrate_permissions as mig

    common.upsert_site("s-sparse3", owner="o@x.com", name="n",
                       allowed_users=["x@example.com"], permissions_rev=1)
    _put_route("app-s-sparse3", "s-sparse3")
    report = mig.migrate("routing", dry_run=True)
    # 复用 main 的渲染逻辑：planned 缺键时不能 KeyError
    for sid in report["migrated"]:
        p = dict(report["planned"][sid])
        kept = p.pop("kept_from_online", [])
        assert kept == ["allowed_users"]
        assert "require_login" in p
