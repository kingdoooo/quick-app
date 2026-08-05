"""首次部署 seed 与"预部署期在线改权限"的交互回归。

背景（Codex review P0，已用 moto 实证）：seed 曾用
attribute_not_exists(require_login) 当"整套权限是否已初始化"的 sentinel，
而在线接口只写调用方显式传入的字段——只改 allowed_users 的调用留下
require_login 缺失的稀疏行，sentinel 判定"未初始化"，seed 就用 manifest 的
值把 allowed_users 从指定名单盖回 "org"（静默扩权）。

所以 seed 必须逐字段 if_not_exists 补缺，不能把任一字段当整套的 sentinel。
"""


def test_seed_does_not_widen_allowlist_on_sparse_row(aws):
    """只改过 allowed_users 的稀疏行：首次部署不得把名单盖回 org。"""
    import common
    import permissions
    import register_route

    # do_deploy_site 首次创建站点时只写 owner/name/status（无权限字段）
    common.upsert_site("s-p0", owner="o@x.com", name="n", status="DEPLOYING")
    # 部署前用在线接口只改 allowed_users → require_login 仍缺失
    permissions.set_access_policy("s-p0", actor="o@x.com",
                                  allowed_users=["only@example.com"])
    site = common.get_site_consistent("s-p0")
    assert site.get("allowed_users") == ["only@example.com"]
    assert "require_login" not in site      # 稀疏行前提成立

    job_id = common.create_job("o@x.com", "s-p0")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p0", "api_target": "",
         "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}},
        None)

    after = common.get_site_consistent("s-p0")
    # 在线设的名单必须保留；缺失的 require_login 由 manifest 补上
    assert after.get("allowed_users") == ["only@example.com"]
    assert after.get("require_login") is True

    import boto3
    route = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-p0"}})["Item"]
    assert route["allowed_users"]["L"] == [{"S": "only@example.com"}]


def test_seed_fills_missing_allowed_users_when_require_login_present(aws):
    """反向稀疏：只改过 require_login 的行，allowed_users 必须被 manifest 补上。

    旧实现在这里是另一种失败：sentinel 存在 → 整个 seed 被跳过 →
    allowed_users 一直缺失 → _route_item 回落 "org"，同样是扩权，
    且真源与投影都停在"缺字段"状态。
    """
    import common
    import permissions
    import register_route

    common.upsert_site("s-p1", owner="o@x.com", name="n", status="DEPLOYING")
    permissions.set_access_policy("s-p1", actor="o@x.com", require_login=True)
    site = common.get_site_consistent("s-p1")
    assert site.get("require_login") is True
    assert "allowed_users" not in site     # 反向稀疏前提成立

    job_id = common.create_job("o@x.com", "s-p1")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p1", "api_target": "",
         "manifest": {"auth": {"require_login": True,
                               "allowed_users": ["from-manifest@x.com"]}}},
        None)

    after = common.get_site_consistent("s-p1")
    assert after.get("require_login") is True                  # 在线值保留
    assert after.get("allowed_users") == ["from-manifest@x.com"]  # 缺字段被补上

    import boto3
    route = boto3.client("dynamodb").get_item(
        TableName="routing", Key={"subdomain": {"S": "app-s-p1"}})["Item"]
    assert route["allowed_users"]["L"] == [{"S": "from-manifest@x.com"}]


def test_seed_is_noop_when_both_fields_present(aws):
    """两个字段都在的完整行：seed 完全不改真源（也不推进 rev）。"""
    import common
    import permissions
    import register_route

    common.upsert_site("s-p2", owner="o@x.com", name="n", status="DEPLOYING")
    permissions.set_access_policy("s-p2", actor="o@x.com", require_login=False,
                                  allowed_users=["a@x.com"])
    before = common.get_site_consistent("s-p2")

    job_id = common.create_job("o@x.com", "s-p2")
    register_route.handler(
        {"job_id": job_id, "site_id": "s-p2", "api_target": "",
         "manifest": {"auth": {"require_login": True, "allowed_users": "org"}}},
        None)

    after = common.get_site_consistent("s-p2")
    assert after.get("require_login") is False
    assert after.get("allowed_users") == ["a@x.com"]
    assert after.get("permissions_rev") == before.get("permissions_rev")
