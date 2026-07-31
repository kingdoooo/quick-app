"""站点权限的唯一判定与写入模块。

真源是 sites 表（site-sites）：owner / collaborators / require_login /
allowed_users 全部以此为准；路由表只是给 Edge 读的投影（见 write_permissions）。
MCP（site-builder/mcp/）与控制台（site-builder/panel/）都引入本模块，
两处的授权语义因此不会漂移——新增受控动作时只改 CAPABILITIES。
"""

ROLE_OWNER = "owner"
ROLE_COLLABORATOR = "collaborator"
ROLE_ADMIN = "admin"
ROLE_NONE = "none"

# 动作 → 允许的角色集合。未登记的动作对所有人拒绝（fail-closed）。
CAPABILITIES = {
    "read": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "deploy": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "set_access_policy": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
    "manage_collaborators": {ROLE_OWNER, ROLE_ADMIN},
    "transfer_owner": {ROLE_OWNER, ROLE_ADMIN},
    "undeploy": {ROLE_OWNER, ROLE_ADMIN},
}


class PermissionDenied(Exception):
    pass


class PermissionConflict(Exception):
    """并发修改：读到的 permissions_rev 已被别人推进。调用方转 409 提示重试。"""
    pass


def role_of(email: str, site: dict | None, is_admin: bool = False) -> str:
    """判定顺序 owner → admin → collaborator。

    admin 必须排在 collaborator 之前：管理员身兼某站点协作者时若返回
    collaborator，他就拿不到 undeploy / transfer_owner（CAPABILITIES 里
    collaborator 没有这两项）——等于被自己的协作者身份降权。
    审计要区分"owner 本人"与"admin 代管"时用单独的 is_admin 标志，
    不要从角色字符串反推。
    """
    if not site:
        return ROLE_NONE
    if email and email == site.get("owner"):
        return ROLE_OWNER
    if is_admin:
        return ROLE_ADMIN
    if email and email in (site.get("collaborators") or []):
        return ROLE_COLLABORATOR
    return ROLE_NONE


def can(role: str, action: str) -> bool:
    return role in CAPABILITIES.get(action, frozenset())


def assert_can(email: str, site: dict | None, action: str, *,
               is_admin: bool = False, what: str = "") -> str:
    role = role_of(email, site, is_admin)
    if not can(role, action):
        target = what or "该站点"
        if role == ROLE_NONE:
            raise PermissionDenied(f"你无权访问 {target}")
        raise PermissionDenied(f"{target}：{role} 角色无权执行 {action}")
    return role
