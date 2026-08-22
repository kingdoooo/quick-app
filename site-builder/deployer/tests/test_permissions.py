import pytest

import permissions as perm


SITE = {"site_id": "s-1", "owner": "o@x.com", "collaborators": ["c@x.com"]}


def test_role_of_owner():
    assert perm.role_of("o@x.com", SITE) == perm.ROLE_OWNER


def test_role_of_collaborator():
    assert perm.role_of("c@x.com", SITE) == perm.ROLE_COLLABORATOR


def test_role_of_outsider():
    assert perm.role_of("x@x.com", SITE) == perm.ROLE_NONE


def test_admin_flag_wins_over_outsider():
    assert perm.role_of("adm@x.com", SITE, is_admin=True) == perm.ROLE_ADMIN


def test_owner_is_not_downgraded_by_admin_flag():
    # owner 本人同时是 admin 时报 owner——审计与文案更准确，权限集相同
    assert perm.role_of("o@x.com", SITE, is_admin=True) == perm.ROLE_OWNER


def test_admin_who_is_also_collaborator_gets_admin():
    """判定顺序必须 owner→admin→collaborator。

    若 collaborator 先匹配，这个平台管理员会失去 undeploy / 转移所有权的
    能力——admin 身兼某站点协作者很常见（先是协作者、后被提为管理员），
    不能因此被降权。
    """
    assert perm.role_of("c@x.com", SITE, is_admin=True) == perm.ROLE_ADMIN


def test_admin_collaborator_can_undeploy():
    role = perm.role_of("c@x.com", SITE, is_admin=True)
    assert perm.can(role, "undeploy") is True


def test_role_of_missing_site_is_none():
    assert perm.role_of("o@x.com", None) == perm.ROLE_NONE


def test_missing_collaborators_field_defaults_empty():
    assert perm.role_of("c@x.com", {"site_id": "s", "owner": "o@x.com"}) == perm.ROLE_NONE


@pytest.mark.parametrize("action,expected", [
    ("read", True), ("deploy", True), ("set_access_policy", True),
    ("manage_collaborators", False), ("transfer_owner", False), ("undeploy", False)])
def test_collaborator_capabilities(action, expected):
    assert perm.can(perm.ROLE_COLLABORATOR, action) is expected


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_owner_can_everything(action):
    assert perm.can(perm.ROLE_OWNER, action) is True


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_admin_can_everything(action):
    assert perm.can(perm.ROLE_ADMIN, action) is True


@pytest.mark.parametrize("action", [
    "read", "deploy", "set_access_policy", "manage_collaborators",
    "transfer_owner", "undeploy"])
def test_none_can_nothing(action):
    assert perm.can(perm.ROLE_NONE, action) is False


def test_unknown_action_denied_for_everyone():
    # 未知动作一律拒绝（fail-closed）：新增动作忘记登记时不会被静默放行
    assert perm.can(perm.ROLE_OWNER, "launch_missiles") is False


def test_assert_can_returns_role():
    assert perm.assert_can("c@x.com", SITE, "deploy") == perm.ROLE_COLLABORATOR


def test_assert_can_raises_for_outsider():
    with pytest.raises(perm.PermissionDenied):
        perm.assert_can("x@x.com", SITE, "read", what="站点 s-1")


def test_assert_can_raises_for_missing_site():
    with pytest.raises(perm.PermissionDenied):
        perm.assert_can("o@x.com", None, "read", what="站点 s-9")


def test_denied_message_does_not_leak_site_existence():
    """站点不存在与确实无权**必须报同一句话**。

    区分开就成了枚举探测器：site_id 形如 `{name}-{6位hex}`，可猜；能区分
    存在性就能扫出全部站点。所以 role_of 对 site=None 返回 ROLE_NONE、
    与"外人访问已存在站点"走同一分支——这是有意的，不要"修"。
    """
    missing = outsider = None
    try:
        perm.assert_can("o@x.com", None, "read", what="站点 s-9")
    except perm.PermissionDenied as e:
        missing = str(e)
    try:
        perm.assert_can("x@x.com", SITE, "read", what="站点 s-9")
    except perm.PermissionDenied as e:
        outsider = str(e)
    assert missing == outsider, (
        f"两种拒绝的文案必须一致，否则可据此枚举站点：\n"
        f"  不存在: {missing}\n  无权:   {outsider}")


def test_denied_message_hints_to_check_the_id():
    """文案要提示"也可能是站点不存在"，否则打错一个字符的人会去找 owner 加名单。

    这不泄漏信息——两种情况仍然返回同一句话，只是让使用者知道该先查拼写。
    """
    try:
        perm.assert_can("x@x.com", SITE, "read", what="站点 s-1")
    except perm.PermissionDenied as e:
        msg = str(e)
    assert "不存在" in msg, f"应提示可能是站点不存在，实际：{msg}"


def test_is_admin_false_when_absent(aws):
    assert perm.is_admin("nobody@x.com") is False


def test_add_and_list_admins(aws):
    perm.add_admin("adm@x.com", added_by="seed")
    assert perm.is_admin("adm@x.com") is True
    assert perm.list_admins() == ["adm@x.com"]


def test_add_admin_is_idempotent(aws):
    perm.add_admin("adm@x.com", added_by="seed")
    perm.add_admin("adm@x.com", added_by="other")
    assert perm.list_admins() == ["adm@x.com"]


def test_remove_admin(aws):
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    perm.remove_admin("a@x.com")
    assert perm.list_admins() == ["b@x.com"]


def test_remove_last_admin_is_refused(aws):
    perm.add_admin("only@x.com", added_by="seed")
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("only@x.com")
    assert perm.is_admin("only@x.com") is True


def test_remove_nonexistent_admin_is_idempotent_even_with_one_admin(aws):
    """删不存在的邮箱要幂等成功——即便当前只剩一名管理员。

    这两个条件同时成立时事务的两项**都**会 ConditionalCheckFailed
    （Delete 的 attribute_exists 不成立、sentinel 的 n>1 也不成立），
    所以异常分流必须先看 Delete 那项。先看 sentinel 会把"目标不存在"
    误报成"不能删除最后一个管理员"，违反 remove_admin 的幂等契约。
    """
    perm.add_admin("only@x.com", added_by="seed")
    perm.remove_admin("ghost@x.com")            # 不得抛异常
    assert perm.list_admins() == ["only@x.com"]  # 真管理员没被动过


def test_remove_nonexistent_admin_is_idempotent_with_many_admins(aws):
    """同上的对照组：管理员多于一个时本来就该幂等（sentinel 条件成立）。"""
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    perm.remove_admin("ghost@x.com")
    assert perm.list_admins() == ["a@x.com", "b@x.com"]


def test_remove_admin_rejects_sentinel_and_garbage(aws):
    """__count__ 是调用方可达输入（控制台/MCP 参数直通）。

    不拦的话：事务的 Delete 与 Update 同落 __count__ 一个 item——DynamoDB 抛
    ValidationException（不是 TransactionCanceledException），穿过分流变成
    不可读 500；侥幸执行则删掉计数 sentinel 本身。与 add_admin 的入口校验对称。
    """
    perm.add_admin("a@x.com", added_by="seed")
    with pytest.raises(ValueError):
        perm.remove_admin("__count__")
    with pytest.raises(ValueError):
        perm.remove_admin("not-an-email")
    assert perm.list_admins() == ["a@x.com"]   # sentinel 与名单都毫发无损


def _conflict_injecting_client(monkeypatch, fail_times: int):
    """让前 fail_times 次 transact_write_items 抛 TransactionConflict。

    覆盖 add_admin 的退避重试与 remove_admin 的冲突转 409——这两个分支
    若绕开 _ddb_client hook 就永远注入不了（错误实现照样全绿）。
    """
    import botocore.exceptions
    state = {"n": 0}
    real_factory = perm._ddb_client

    def _factory():
        client = real_factory()
        real = client.transact_write_items

        def _wrapped(**kw):
            if state["n"] < fail_times:
                state["n"] += 1
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "TransactionCanceledException",
                               "Message": "cancelled"},
                     "CancellationReasons": [
                         {"Code": "TransactionConflict"},
                         {"Code": "TransactionConflict"}]},
                    "TransactWriteItems")
            return real(**kw)

        client.transact_write_items = _wrapped
        return client

    monkeypatch.setattr(perm, "_ddb_client", _factory)
    return state


def test_add_admin_retries_through_transaction_conflict(aws, monkeypatch):
    """并发写 __count__ 的 TransactionConflict：退避重试后成功，不吞不炸。"""
    state = _conflict_injecting_client(monkeypatch, fail_times=2)
    perm.add_admin("a@x.com", added_by="seed")
    assert state["n"] == 2                      # 确实经历了两次冲突
    assert perm.is_admin("a@x.com") is True     # 第三次成功落库


def test_remove_admin_conflict_becomes_permission_conflict(aws, monkeypatch):
    """remove_admin 遇 TransactionConflict 必须转成可读的 PermissionConflict。"""
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    _conflict_injecting_client(monkeypatch, fail_times=1)
    with pytest.raises(perm.PermissionConflict):
        perm.remove_admin("a@x.com")
    assert perm.is_admin("a@x.com") is True     # 冲突时未删成，如实报告


def test_normalize_allowed_users_org():
    assert perm.normalize_allowed_users("org") == "org"


def test_normalize_allowed_users_dedups_and_sorts():
    assert perm.normalize_allowed_users(
        ["b@x.com", "a@x.com", "b@x.com"]) == ["a@x.com", "b@x.com"]


def test_normalize_allowed_users_rejects_bad_email():
    with pytest.raises(ValueError):
        perm.normalize_allowed_users(["not-an-email"])


def test_normalize_allowed_users_rejects_empty_list():
    with pytest.raises(ValueError):
        perm.normalize_allowed_users([])


def test_set_access_policy_writes_sites_table(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = perm.set_access_policy("s-1", actor="o@x.com", require_login=False,
                                 allowed_users=["a@x.com"])
    assert out["require_login"] is False
    assert out["allowed_users"] == ["a@x.com"]
    site = common.get_site("s-1")
    assert site["allowed_users"] == ["a@x.com"]
    assert site["permissions_updated_by"] == "o@x.com"
    assert site["permissions_updated_at"]


def test_set_access_policy_partial_update_keeps_other_field(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users=["keep@x.com"], collaborators=[])
    perm.set_access_policy("s-1", actor="o@x.com", require_login=False)
    site = common.get_site("s-1")
    assert site["require_login"] is False
    assert site["allowed_users"] == ["keep@x.com"]


def test_set_collaborators_add_and_remove(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    assert perm.set_collaborators("s-1", actor="o@x.com",
                                  add=["c@x.com", "d@x.com"]) == ["c@x.com", "d@x.com"]
    assert perm.set_collaborators("s-1", actor="o@x.com", remove=["c@x.com"]) == ["d@x.com"]


def test_set_collaborators_refuses_owner_as_collaborator(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    with pytest.raises(ValueError):
        perm.set_collaborators("s-1", actor="o@x.com", add=["o@x.com"])


def test_transfer_owner_demotes_previous_owner(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"])
    out = perm.transfer_owner("s-1", actor="o@x.com", new_owner="new@x.com")
    assert out["owner"] == "new@x.com"
    site = common.get_site("s-1")
    assert site["owner"] == "new@x.com"
    assert "o@x.com" in site["collaborators"]
    # 新 owner 不应同时留在 collaborators 里
    assert "new@x.com" not in site["collaborators"]


def test_transfer_owner_from_collaborator_position(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"])
    perm.transfer_owner("s-1", actor="o@x.com", new_owner="c@x.com")
    site = common.get_site("s-1")
    assert site["owner"] == "c@x.com"
    assert site["collaborators"] == ["o@x.com"]


def test_transfer_owner_rejects_bad_email(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=[])
    with pytest.raises(ValueError):
        perm.transfer_owner("s-1", actor="o@x.com", new_owner="oops")


def test_allowed_users_av_org_is_string():
    assert perm.allowed_users_av("org") == {"S": "org"}


def test_allowed_users_av_list_is_L():
    assert perm.allowed_users_av(["a@x.com"]) == {"L": [{"S": "a@x.com"}]}


def test_write_permissions_updates_both_tables_atomically(aws):
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": "https://fn.lambda-url.us-east-1.on.aws"},
        "require_auth": {"BOOL": True}, "allowed_users": {"S": "org"},
        "collaborators": {"L": []}, "owner": {"S": "o@x.com"}})

    out = perm.write_permissions("s-1", actor="o@x.com",
                                 action="set_access_policy",
                                 require_login=False,
                                 allowed_users=["a@x.com"])
    assert out["route_synced"] is True

    site = common.get_site("s-1")
    assert site["require_login"] is False
    assert site["allowed_users"] == ["a@x.com"]
    assert int(site["permissions_rev"]) == 1

    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is False
    assert item["allowed_users"]["L"] == [{"S": "a@x.com"}]
    # 投影只动权限字段：部署态字段必须原样保留（否则会踩掉原子切流）
    assert item["static_prefix"]["S"] == "sites/s-1/j"
    assert item["api_target"]["S"] == "https://fn.lambda-url.us-east-1.on.aws"


def test_write_permissions_degrades_when_route_absent(aws):
    """站点尚未首次部署成功：只写真源，显式返回 route_synced=False。"""
    import common
    common.upsert_site("nodeploy", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    out = perm.write_permissions("nodeploy", actor="o@x.com",
                                action="set_access_policy",
                                require_login=False)
    assert out["route_synced"] is False
    assert common.get_site("nodeploy")["require_login"] is False


def test_write_permissions_rolls_back_when_route_write_fails(aws, monkeypatch):
    """路由表写失败时 sites 表不能留下"已收紧"的假象。

    这是 spec §3.2 的核心保证：顺序两写会产生 sites 私有 / Edge 公开的
    安全状态错误。用事务后，注入失败应让两边都不变。
    """
    import boto3
    import botocore.exceptions
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[])
    # 故意不建路由 item，同时强制关闭降级分支——模拟"路由本该存在但写失败"
    monkeypatch.setattr(perm, "_ALLOW_ROUTE_ABSENT", False)
    with pytest.raises(botocore.exceptions.ClientError):
        perm.write_permissions("s-1", actor="o@x.com",
                               action="set_access_policy", require_login=True)
    # 真源未被改动：仍是公开
    assert common.get_site("s-1")["require_login"] is False


def test_write_permissions_retries_when_route_appears_during_fallback(aws, monkeypatch):
    """降级路径的递归重试分支（write_permissions 四条路径里唯一没被覆盖的一条）。

    交错：① 双表事务因"路由 item 不存在"被取消 → ② 走只写 sites 的降级事务，
    但降级里那条 attribute_not_exists(subdomain) 的 ConditionCheck 发现
    route **在这期间被 register_route 创建了** → ③ 必须回到正常双表事务重试，
    否则就会留下 sites 私有 / Edge 公开（正是事务要消除的状态）。

    用 side effect 精确制造这个时序：第一次读快照后不建路由（让双表事务失败），
    降级事务提交前把路由建出来（让降级的 not_exists 条件也失败）。
    """
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    ddb = boto3.client("dynamodb")
    state = {"n": 0}
    real_transact = ddb.transact_write_items

    def _create_route():
        ddb.put_item(TableName="routing", Item={
            "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
            "route_mode": {"S": "split"},
            "static_prefix": {"S": "sites/s-1/j"}, "api_target": {"S": ""},
            "require_auth": {"BOOL": False}, "allowed_users": {"S": "org"},
            "collaborators": {"L": []}, "owner": {"S": "o@x.com"},
            "permissions_rev": {"N": "0"}})

    orig_client = perm._ddb_client

    def _patched_client():
        client = orig_client()
        real = client.transact_write_items

        def _wrapped(**kw):
            state["n"] += 1
            # 第 2 次调用 = 降级事务：在它执行之前把 route 建出来，
            # 于是 attribute_not_exists(subdomain) 失败 → 触发递归重试
            if state["n"] == 2:
                _create_route()
            return real(**kw)

        client.transact_write_items = _wrapped
        return client

    monkeypatch.setattr(perm, "_ddb_client", _patched_client)
    out = perm.write_permissions("s-1", actor="o@x.com",
                                 action="set_access_policy", require_login=True)

    # 递归重试后必须落到"两表都写成功"，而不是只写了 sites
    assert out["route_synced"] is True
    assert common.get_site("s-1")["require_login"] is True
    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["require_auth"]["BOOL"] is True      # Edge 侧也收紧了
    assert state["n"] >= 3          # 双表失败 → 降级失败 → 重试，至少三次


def test_write_permissions_fallback_recursion_is_bounded(aws, monkeypatch):
    """route 反复"刚好在降级前出现"时不能无限递归（栈溢出 = 500）。

    真实场景不会一直这样，但 write_permissions 的递归没有深度上限，
    一个持续制造该时序的并发流会把它打穿。要求实现带 _attempt 上限并在
    耗尽后抛 PermissionConflict（可读的 409），而不是 RecursionError。
    """
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", require_login=False,
                       allowed_users="org", collaborators=[], permissions_rev=0)
    ddb = boto3.client("dynamodb")
    orig_client = perm._ddb_client

    def _patched_client():
        client = orig_client()
        real = client.transact_write_items

        def _wrapped(**kw):
            # 每次降级事务前都把 route 建出来、双表事务前又删掉：
            # 让两条路径永远互相错过
            has_check = any("ConditionCheck" in i and
                            i["ConditionCheck"]["ConditionExpression"].startswith(
                                "attribute_not_exists") for i in kw["TransactItems"])
            if has_check:
                ddb.put_item(TableName="routing",
                             Item={"subdomain": {"S": "app-s-1"},
                                   "site_id": {"S": "s-1"}})
            else:
                ddb.delete_item(TableName="routing",
                                Key={"subdomain": {"S": "app-s-1"}})
            return real(**kw)

        client.transact_write_items = _wrapped
        return client

    monkeypatch.setattr(perm, "_ddb_client", _patched_client)
    with pytest.raises(perm.PermissionConflict):
        perm.write_permissions("s-1", actor="o@x.com",
                               action="set_access_policy", require_login=True)


def test_write_permissions_detects_concurrent_modification(aws, monkeypatch):
    """两个人同时改：后到者必须失败而不是静默覆盖。

    rev 由 write_permissions 自己那次强一致读取得（不再由调用方传入），
    所以这里模拟"读完之后、提交之前别人先写成功"的交错。
    """
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["b@x.com"],
                       require_login=True, allowed_users="org",
                       permissions_rev=0)
    real = perm._site_or_raise

    def _bump_after_read(site_id, *, consistent=False):
        site = real(site_id, consistent=consistent)
        common.upsert_site(site_id, allowed_users=["a@x.com"],
                           permissions_rev=1)      # 别人先提交了
        return site

    monkeypatch.setattr(perm, "_site_or_raise", _bump_after_read)
    with pytest.raises(perm.PermissionConflict):
        perm.write_permissions("s-1", actor="b@x.com",
                               action="set_access_policy",
                               allowed_users=["b@x.com"])
    assert common.get_site("s-1")["allowed_users"] == ["a@x.com"]


def test_revocation_between_authz_and_commit_is_blocked(aws, monkeypatch):
    """授权读与事务提交之间被撤权 → 写入必须失败（授权 TOCTOU 回归）。

    这是把 actor/action 收进 write_permissions 的原因：分开做（调用方先
    assert_can、setter 再读 rev 写入）时，刚被移除的 collaborator 仍能完成
    一次写。
    """
    import boto3
    import common
    common.upsert_site("s-1", owner="o@x.com", collaborators=["c@x.com"],
                       require_login=True, allowed_users="org",
                       permissions_rev=0)
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": [{"S": "c@x.com"}]},
        "owner": {"S": "o@x.com"}, "permissions_rev": {"N": "0"}})

    real = perm._site_or_raise

    def _revoke_after_read(site_id, *, consistent=False):
        site = real(site_id, consistent=consistent)
        # 授权判定用的就是这个快照；判定通过后 owner 把他移除并推进 rev
        common.upsert_site(site_id, collaborators=[], permissions_rev=1)
        return site

    monkeypatch.setattr(perm, "_site_or_raise", _revoke_after_read)
    with pytest.raises(perm.PermissionConflict):
        perm.set_access_policy("s-1", actor="c@x.com", require_login=False)
    # 撤权后的写入没有生效
    assert common.get_site("s-1")["require_login"] is True


def test_admin_removed_mid_write_is_blocked(aws, monkeypatch):
    """admin 代管路径同理：名单里被移除后不得完成写入。"""
    import boto3
    import common
    perm.add_admin("adm@x.com", added_by="seed")
    perm.add_admin("keep@x.com", added_by="seed")   # 留一个，避免删空被拦
    common.upsert_site("s-1", owner="o@x.com", collaborators=[],
                       require_login=True, allowed_users="org", permissions_rev=0)
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": []},
        "owner": {"S": "o@x.com"}, "permissions_rev": {"N": "0"}})

    real_is_admin = perm.is_admin

    def _admin_then_revoked(email):
        result = real_is_admin(email)
        if email == "adm@x.com" and result:
            perm.remove_admin("adm@x.com")     # 判定后立刻被撤
        return result

    monkeypatch.setattr(perm, "is_admin", _admin_then_revoked)
    with pytest.raises(perm.PermissionDenied):
        perm.set_access_policy("s-1", actor="adm@x.com", require_login=False)
    assert common.get_site("s-1")["require_login"] is True


def test_duplicate_add_admin_keeps_count_consistent(aws):
    """并发/重复添加同一邮箱不得把计数加两次（否则删除时可能删空）。"""
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("a@x.com", added_by="again")
    perm.add_admin("b@x.com", added_by="seed")
    assert perm.list_admins() == ["a@x.com", "b@x.com"]
    # 计数与实际一致：删掉一个后仍能删（n=2 → 1），再删被拦
    perm.remove_admin("a@x.com")
    assert perm.list_admins() == ["b@x.com"]
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("b@x.com")


def test_rebuild_admin_count_repairs_drift(aws):
    """存量表/中间失败导致的计数漂移可修。"""
    import boto3
    perm.add_admin("a@x.com", added_by="seed")
    perm.add_admin("b@x.com", added_by="seed")
    # 人为把计数改错
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-admins").put_item(Item={"email": "__count__", "n": 99})
    assert perm.rebuild_admin_count() == 2
    perm.remove_admin("a@x.com")
    with pytest.raises(perm.PermissionDenied):
        perm.remove_admin("b@x.com")


def test_write_permissions_transfers_owner_to_both_tables(aws):
    import boto3
    import common
    common.upsert_site("s-1", owner="old@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    ddb = boto3.client("dynamodb")
    ddb.put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"}, "site_id": {"S": "s-1"},
        "route_mode": {"S": "split"}, "static_prefix": {"S": "sites/s-1/j"},
        "api_target": {"S": ""}, "require_auth": {"BOOL": True},
        "allowed_users": {"S": "org"}, "collaborators": {"L": []},
        "owner": {"S": "old@x.com"}})
    perm.write_permissions("s-1", actor="old@x.com", action="transfer_owner",
                           new_owner="new@x.com", collaborators=["old@x.com"])
    assert common.get_site("s-1")["owner"] == "new@x.com"
    item = ddb.get_item(TableName="routing",
                        Key={"subdomain": {"S": "app-s-1"}})["Item"]
    assert item["owner"]["S"] == "new@x.com"
    assert item["collaborators"]["L"] == [{"S": "old@x.com"}]


# ---- 守卫必须只有一份定义（Codex 2026-08-08 P1 的结构性修复）----
# 同一个不变量原来手抄在三处（mcp/server.py、write_permissions、register_route），
# 于是"审查指出一处 → 只修一处 → 另外两处照旧"重复了三轮。这两个用例把
# "唯一定义"变成可执行约束：再有人手抄第四份就会红。

def test_no_handwritten_rev_guard_outside_permissions_module():
    """除 permissions.py 自己，任何源码都不得手写 permissions_rev 条件表达式。"""
    import ast
    import re
    from pathlib import Path
    root = Path(__file__).parents[3]        # 仓库根
    canonical = (root / "site-builder" / "deployer" / "functions"
                 / "permissions.py").resolve()
    offenders = []
    for py in list((root / "site-builder").rglob("*.py")) + \
            list((root / "router").rglob("*.py")):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        if py.resolve() == canonical:
            continue
        text = py.read_text()
        # 只看代码，不看注释与 docstring：解释这个表达式为什么危险是允许的
        # （也是必要的）。用 ast 剥 docstring，再按行剥 # 注释——比正则可靠。
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    body[0].value.value = ""      # 清掉 docstring 内容
        # **不要再按 `#` 截断**：ast.unparse 已经把注释全部丢掉了，而这一行
        # 反而会在第一个 `#` 处截断——`#o` / `#ro` 正是本仓库给保留字 owner 写
        # ExpressionAttributeNames 的方式，于是"别名在前、条件在后"的字典会被
        # 砍得只剩前半段，本用例要找的表达式刚好被藏起来（独立审查实测：
        # 把原始脆弱条件重排字段顺序即可逃过检测）。
        code = ast.unparse(tree)
        # 两类都要认，缺一不可（两个 P1 各对应一类）：
        #   ① rev 相等比较——"拿快照 rev 做守卫"的手抄。
        #      注意 `attribute_not_exists(permissions_rev)` 单独出现**不算**：
        #      那是 register_route 的初始化条件（"rev 缺失就补上"），语义与守卫
        #      相反且是 rev 存在性的唯一保证点，必须允许。
        #   ② 角色事实子句——"无 rev 时按 owner/collaborator 放行"的手抄。
        #      第一版只查①，于是defect#2（把 owner 与 collaborator 合并）那种
        #      形态完全查不到，而它恰是危害更大的一类（被降级的旧 owner 仍能
        #      purge 数据）。
        hits = []
        if re.search(r'permissions_rev\s*=\s*:\w+', code):
            hits.append("rev 相等比较")
        if (re.search(r'contains\(collaborators,\s*:\w+\)', code)
                or re.search(r'#\w+\s*=\s*:me\b', code)):
            hits.append("角色事实子句")
        if hits:
            offenders.append(f"{py.relative_to(root)}（{'、'.join(hits)}）")
    assert not offenders, (
        "这些文件手写了 permissions_rev 守卫条件，必须改用 "
        f"permissions.sites_snapshot_guard()：{offenders}\n"
        "手抄第二份的代价见 permissions.snapshot_condition 的注释（两个 P1）。")


def test_snapshot_condition_role_clauses_follow_capabilities():
    """无-rev 分支的角色子句必须由 CAPABILITIES 推导，不能另写一套。

    逐个受控动作比对：CAPABILITIES 说某角色无权，条件里就不该出现对应子句。
    undeploy 不含 collaborator 是最要紧的一条——合并两者会让被降级的旧 owner
    仍能 purge 掉新 owner 的数据。
    """
    import permissions as p
    for action, roles in p.CAPABILITIES.items():
        expr, _, _ = p.snapshot_condition(
            rev=0, had_rev=False, actor="me@x.com", action=action,
            role=p.ROLE_OWNER)
        assert "attribute_exists(site_id)" in expr, action
        owner_ok = p.ROLE_OWNER in roles
        collab_ok = p.ROLE_COLLABORATOR in roles
        assert ("#o = :me" in expr) == owner_ok, (
            f"{action}: owner 子句与 CAPABILITIES 不一致")
        assert ("contains(collaborators, :me)" in expr) == collab_ok, (
            f"{action}: collaborator 子句与 CAPABILITIES 不一致"
            f"（CAPABILITIES 允许的角色={sorted(roles)}）")
    # 具体钉死这一条：undeploy 绝不能放 collaborator 进来
    expr, _, _ = p.snapshot_condition(rev=0, had_rev=False, actor="me@x.com",
                                      action="undeploy", role=p.ROLE_OWNER)
    assert "contains(collaborators" not in expr


def test_snapshot_condition_always_requires_item_exists():
    """所有分支都必须要求 item 存在——否则"删除后同 site_id 重建"可绕过。"""
    import permissions as p
    variants = [
        dict(rev=7, had_rev=True),
        dict(rev=0, had_rev=False, actor="me@x.com", action="deploy",
             role=p.ROLE_OWNER),
        dict(rev=0, had_rev=False, actor="me@x.com", action="deploy",
             role=p.ROLE_ADMIN),
        dict(rev=0, had_rev=False),                     # 系统写入者
        dict(rev=0, had_rev=False, actor="me@x.com", action="nonexistent-action",
             role=p.ROLE_OWNER),
    ]
    for kw in variants:
        expr, _, _ = p.snapshot_condition(**kw)
        assert "attribute_exists(site_id)" in expr, kw
        assert "attribute_not_exists(permissions_rev)" not in expr, kw


def test_snapshot_condition_system_writer_is_fail_closed():
    """没有 actor/action 的系统写入者遇上无-rev 记录时必须 fail-closed。"""
    import permissions as p
    expr, _, _ = p.snapshot_condition(rev=0, had_rev=False)
    # 要求 rev 属性存在 → 本次必然失败 → 调用方重读重试，而不是被放行
    assert "attribute_exists(permissions_rev)" in expr


def test_legacy_sparse_row_without_rev_self_heals_on_first_write(aws):
    """存量稀疏行（有 auth 字段、缺 permissions_rev）必须能被正常写入并补上 rev。

    为什么要钉住：register_route 的 seed 现在**要求** rev 存在（守卫 fail-closed），
    而 migrate_permissions 对这种行是 skip 的（两个 auth 字段都在）。所以"这种行
    靠首次在线写入自愈"是整条链的前提——它一旦不成立，这批站点会被永久卡死。
    """
    import common
    common.upsert_site("legacy-1", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=[])
    assert "permissions_rev" not in common.get_site("legacy-1")
    perm.set_access_policy("legacy-1", actor="o@x.com", require_login=False)
    assert int(common.get_site("legacy-1")["permissions_rev"]) == 1


def test_legacy_sparse_row_still_rejects_outsider(aws):
    """自愈路径不能顺带放宽鉴权：无 rev 的行上外人仍必须被拒。"""
    import common
    common.upsert_site("legacy-2", owner="o@x.com", require_login=True,
                       allowed_users="org", collaborators=["c@x.com"])
    with pytest.raises(perm.PermissionDenied):
        perm.set_access_policy("legacy-2", actor="x@x.com", require_login=False)
    # 对照：协作者有 set_access_policy 能力，必须放行
    perm.set_access_policy("legacy-2", actor="c@x.com", require_login=False)


def test_resync_projects_exactly_the_same_route_fields_as_write_permissions():
    """两处投影字段必须一致；否则 resync"修完还是脏的"。

    从源码解析实际的 UpdateExpression 取值再比对——手抄第二份清单时，
    write_permissions 加字段这里不会失败（本仓库的既有教训）。
    """
    import ast
    import re
    from pathlib import Path
    src = (Path(__file__).parents[1] / "functions" / "permissions.py").read_text()
    tree = ast.parse(src)

    def route_fields(fn_name):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == fn_name)
        body = ast.unparse(fn)
        # 只取投影到路由表的那条 UpdateExpression（以 require_auth 开头）
        exprs = re.findall(r"'SET require_auth = [^']*'", body)
        assert exprs, f"{fn_name} 里找不到路由投影表达式"
        return set(re.findall(r"(#?\w+) = :", exprs[0]))

    a = route_fields("write_permissions")
    b = route_fields("resync_route")
    assert a == b, f"投影字段漂移：write_permissions={sorted(a)} resync={sorted(b)}"
    # 别名（#ro → owner）也必须两处一致，否则"字段名相同、指向不同"
    assert "#ro" in a, "投影表达式里应有 owner 的别名 #ro"


def test_resync_requires_route_item_to_exist():
    """resync 是纠正投影，不是补建路由。

    路由 item 不存在说明站点没成功部署过（或已下线）——无中生有地建一条
    会让一个不该可达的 subdomain 变成可路由。
    """
    import ast
    import re
    from pathlib import Path
    src = (Path(__file__).parents[1] / "functions" / "permissions.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "resync_route")
    body = ast.unparse(fn)
    assert "attribute_exists(subdomain)" in body, (
        "resync_route 缺 attribute_exists(subdomain) 条件——会无中生有建路由")


def test_view_analytics_is_a_registered_action_for_the_three_roles():
    """访问明细含**其他访问者的邮箱**，是与站点元数据不同的敏感度等级。

    单独一个动作名（而不是复用 read）让"以后要收紧成只有 owner+admin"变成改
    一个字典项，且不牵动其它读路径。
    """
    from permissions import (CAPABILITIES, ROLE_ADMIN, ROLE_COLLABORATOR,
                             ROLE_NONE, ROLE_OWNER, can)
    assert CAPABILITIES["view_analytics"] == {
        ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN}
    assert can(ROLE_OWNER, "view_analytics")
    assert can(ROLE_COLLABORATOR, "view_analytics")
    assert can(ROLE_ADMIN, "view_analytics")
    assert not can(ROLE_NONE, "view_analytics")


def test_unregistered_analytics_typo_is_denied_to_everyone():
    """未登记动作对所有人拒绝（fail-closed）——拼错动作名不会变成放行。"""
    from permissions import ROLE_OWNER, can
    assert not can(ROLE_OWNER, "view_analytic")


# ---- effective_policy：坏数据一律拒绝投影，不猜方向（S1 / M02）----
# 读路径（Edge）对坏数据 fail-closed，而**写路径**原来用
# `bool(site.get("require_login", True))` + `site.get("allowed_users", "org")`
# 把坏数据洗成合法的 `{"BOOL": false}` / `"org"` 再投影给 Edge——两侧对坏数据的
# 语义相反，于是 Edge 的加固被写入侧整个抵消。判据只有一条：**每个字段要么类型
# 明确，要么它的「缺失」有唯一安全解释**，两者都不成立即拒绝。

def test_policy_data_invalid_is_not_a_valueerror():
    """基类是有承载力的：**不能**继承 ValueError。

    panel/handler.py 的 `except ValueError` 分支返回 400，且排在通用 500 之前；
    继承 ValueError 会让专门给这条路径的 409 分支变成永远到不了的死代码，
    而两侧用例照样全绿——线上答 400、"刷新重试"的提示不出现。
    """
    assert issubclass(perm.PolicyDataInvalid, Exception)
    assert not issubclass(perm.PolicyDataInvalid, ValueError), (
        "PolicyDataInvalid 不得继承 ValueError（panel 的 400 分支会抢先命中）")


def test_wrong_typed_require_login_is_rejected_not_laundered():
    """`Decimal(0)` 不得被 bool() 洗成 False。

    这是 M02 的核心：`bool(Decimal(0))` 是 False，于是它被写成字面
    `{"BOOL": false}`，而 Edge 的判定正是 "require_auth is False ⇒ 公开"
    ——坏数据被洗成"站主显式声明公开"，Edge 2026-08-06 加的 fail-closed
    哨兵被整个抵消。私有站点变成全公网可读。
    """
    from decimal import Decimal
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid, match="require_login"):
        perm.effective_policy(site)


def test_effective_policy_returns_the_projection_shape_verbatim():
    """返回的**形态**本身是契约：Task 5 的三个投影 writer 与 Task 6 都按它取值。

    **整字典相等**而不是四条独立断言：这样多一个键、少一个键、改一个键名都会红。
    只断言单个字段时，把 `owner` 从返回值里删掉、或把 `allowed_users` 改名成
    `allowed`、或返回未规范化的原值——三种都能让全部拒绝类用例照样绿，而投影出去
    的路由表是错的。

    顺带覆盖两处别处没有的东西：`allowed_users` 的**名单分支**（去重排序正是
    Task 5 要投影进路由表的那个值，之前每个 happy-path 夹具都用 "org"，
    这条分支从没被 effective_policy 驱动过），以及 `require_login: False`
    作为**站主显式声明的合法值**——它必须能正常通过，M02 拒的是坏类型，
    不是"公开"这个决定本身。
    """
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": False,
            "allowed_users": ["b@example.test", "a@example.test", "a@example.test"],
            "collaborators": ["c@example.test"]}
    assert perm.effective_policy(site) == {
        "require_login": False, "owner": "o@example.test",
        "allowed_users": ["a@example.test", "b@example.test"],   # 去重排序后
        "collaborators": ["c@example.test"]}


def test_missing_collaborators_means_empty_list():
    """collaborators 是**唯一**允许缺失的字段：缺失有唯一安全解释（没有协作者）。"""
    site = {"site_id": "s-1", "owner": "o@example.test",
            "require_login": True, "allowed_users": "org"}
    assert perm.effective_policy(site)["collaborators"] == []


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_missing_ambiguous_field_is_rejected(field):
    """这三个字段缺失都没有唯一安全解释，所以一律拒绝、不猜方向。

    require_login 缺失：True 还是 False？allowed_users 缺失：org 还是空名单？
    改 "org" 是静默扩权，改 [] 是静默收紧——两者都在猜历史意图。
    """
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    del site[field]
    with pytest.raises(perm.PolicyDataInvalid, match=field):
        perm.effective_policy(site)


def test_rejection_message_names_the_site_and_the_repair():
    """文案必须点名 site_id 与坏字段并给出修法。

    否则这条"响亮失败"会变成一个查不出原因的 409，等于第二个 M03
    （那条的教训正是：只抛原始 SQLSTATE 而不给补救办法，
    "理论上可恢复"就不等于"实际上可恢复"）。
    """
    from decimal import Decimal
    site = {"site_id": "s-abc", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid) as excinfo:
        perm.effective_policy(site)
    msg = str(excinfo.value)
    assert "s-abc" in msg, "文案没点名 site_id"
    assert "require_login" in msg, "文案没给出坏字段"
    assert "BOOL" in msg, "文案没给出修法（正确类型）"


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_rejection_names_the_field_that_is_actually_broken(field):
    """点名的必须是**真正坏掉的那个**字段。

    上面 `match=field` 那三条参数化用例单独还不够：补救文案里本来就列着全部
    三个字段名（"require_login: BOOL；allowed_users: …；owner: 非空 S"），
    所以一个"永远只报 owner"的实现照样能让它们三条全绿。这里按句式断言——
    坏字段那句在，另两个字段的同句式不在。点错字段的代价是让人去修没坏的
    那一行，而这条路径的全部价值就在"人照着文案能修好"。
    """
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    del site[field]
    with pytest.raises(perm.PolicyDataInvalid) as excinfo:
        perm.effective_policy(site)
    msg = str(excinfo.value)
    assert f"的 {field} 形态不合法" in msg, f"没点名坏字段 {field}：{msg}"
    for other in ("require_login", "allowed_users", "owner"):
        if other != field:
            assert f"的 {other} 形态不合法" not in msg, (
                f"坏的是 {field}，文案却点名了 {other}：{msg}")


@pytest.mark.parametrize("field", ["require_login", "allowed_users", "owner"])
def test_rejection_says_missing_when_the_field_is_missing(field):
    """缺失要报成"字段缺失"，不能报成 `NoneType=None`。

    DynamoDB 有真正的 NULL 型（`{"NULL": true}` 读出来就是 None），两者是**两种
    不同的行**。把缺失也写成 `NoneType=None` 会让人拿着这句话去表里找一个根本
    不存在的 null 值——而"先认出那一行到底哪里坏了"这一步全靠这句话。
    """
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    del site[field]
    with pytest.raises(perm.PolicyDataInvalid) as excinfo:
        perm.effective_policy(site)
    msg = str(excinfo.value)
    assert "字段缺失" in msg, f"缺失没被报成缺失：{msg}"
    assert "NoneType" not in msg, f"缺失被报成了 null：{msg}"


@pytest.mark.parametrize("field,bad", [
    ("require_login", "true"),          # 字符串 "true"，不是 BOOL
    ("allowed_users", 7),               # 既不是 "org" 也不是名单
    ("collaborators", "c@example.test"),  # 单个字符串而非 L
    ("owner", ""),                      # 空字符串
])
def test_repair_hint_covers_every_field_it_can_reject(field, bad):
    """**能拒的每个字段都要给出它自己的合法形态**，否则这条路径就没有价值。

    整个"响亮失败"的代价是站点在人工修好之前既不能改权限也不能部署；
    换来的东西只有一样——文案让人知道该把哪一行改成什么。少写一个字段的
    形态（collaborators 原来就漏了）时，那个字段的拒绝就是一个不可行动的
    409，等于把数据问题变成一张工单。
    """
    site = {"site_id": "s-1", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    site[field] = bad
    with pytest.raises(perm.PolicyDataInvalid) as excinfo:
        perm.effective_policy(site)
    msg = str(excinfo.value)
    assert f"的 {field} 形态不合法" in msg, f"没点名坏字段 {field}：{msg}"
    assert f"{field}: " in msg, (
        f"补救文案没给出 {field} 的合法形态，用户无法照着修：{msg}")


def test_effective_policy_audited_records_the_rejection(aws):
    """拒绝要留下可查的一行，且**审计只有这一处包装**。

    三个投影 writer 各写一份 try/except 就是本轮要消除的形态（同一段处理抄
    多份，漏一处即静默拒绝）。所以纯解析留在 effective_policy（体检脚本要调
    它，而那条路径不该写任何东西），落审计的包装只此一份。
    """
    from decimal import Decimal

    import boto3
    site = {"site_id": "s-abc", "owner": "o@example.test",
            "require_login": Decimal(0), "allowed_users": "org",
            "collaborators": []}
    with pytest.raises(perm.PolicyDataInvalid):
        perm.effective_policy_audited(site, actor="who@example.test")
    items = boto3.client("dynamodb").scan(TableName="site-ops-log")["Items"]
    assert len(items) == 1, f"应恰好落一条审计，实际 {items}"
    row = items[0]
    assert row["target"]["S"] == "site:s-abc"
    assert row["actor"]["S"] == "who@example.test"
    assert row["action"]["S"] == "reject_policy_projection"
    assert row["result"]["S"] == "rejected"


def test_effective_policy_audited_is_silent_on_success(aws):
    """解析成功不落审计。

    三个 writer 的每次部署与每次改权限都会过这里，成功也记就是把审计表变成
    流水日志——真正要查的那几行拒绝会被埋掉，而权限变更本身已由
    write_permissions 的 _audit 记过了。
    """
    import boto3
    site = {"site_id": "s-ok", "owner": "o@example.test", "require_login": True,
            "allowed_users": "org", "collaborators": []}
    out = perm.effective_policy_audited(site, actor="who@example.test")
    assert out["require_login"] is True
    assert boto3.client("dynamodb").scan(
        TableName="site-ops-log")["Items"] == [], "成功路径不该写审计"
