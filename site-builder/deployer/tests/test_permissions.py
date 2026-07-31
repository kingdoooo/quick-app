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
