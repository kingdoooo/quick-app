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
        code = ast.unparse(tree)
        code = "\n".join(l.split("#")[0] for l in code.splitlines())
        # 只认**守卫语法**：`permissions_rev = :x`（拿快照 rev 做相等比较）。
        # 单纯读属性（site["permissions_rev"]）不算；
        # `attribute_not_exists(permissions_rev)` 单独出现也不算——那是
        # register_route 的**初始化**条件（"rev 缺失就补上"），语义与守卫相反，
        # 是 rev 存在性的唯一保证点，必须允许。危险的是把它**当放行分支**用，
        # 即与 rev 相等比较并成 OR，所以只要出现相等比较就算手抄。
        if re.search(r'permissions_rev\s*=\s*:\w+', code):
            offenders.append(str(py.relative_to(root)))
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
