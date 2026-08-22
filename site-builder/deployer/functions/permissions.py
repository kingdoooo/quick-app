"""站点权限的唯一判定与写入模块。

真源是 sites 表（site-sites）：owner / collaborators / require_login /
allowed_users 全部以此为准；路由表只是给 Edge 读的投影（见 write_permissions）。
MCP（site-builder/mcp/）与控制台（site-builder/panel/）都引入本模块，
两处的授权语义因此不会漂移——新增受控动作时只改 CAPABILITIES。
"""
import os
import re
from datetime import datetime, timezone

import boto3

import common
import ops_log

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
    # M5：看访问统计与访问明细。**不复用 read**——明细含其他访问者的邮箱，
    # 是另一个敏感度等级。单独动作名让"收紧成只有 owner+admin"是改一个字典项。
    "view_analytics": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
}


class PermissionDenied(Exception):
    pass


class PermissionConflict(Exception):
    """并发修改：读到的 permissions_rev 已被别人推进。调用方转 409 提示重试。"""
    pass


class PolicyDataInvalid(Exception):
    """sites 行的权限字段形态不合法，拒绝投影到路由表。

    **不猜方向**：把未知值当 "org" 是静默扩权，当空名单是静默收紧，
    两者都在猜历史意图。判不出就拒绝，让人去修那一行。
    调用方转 409（panel）或可读工具错误（MCP）。

    **不继承 ValueError**：panel/handler.py 的 `except ValueError` 分支返回 400
    且排在通用 500 之前，继承它会让专门的 409 分支变成死代码——两侧用例照样
    全绿，而线上永远答 400。
    """


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


# ---- 权限快照守卫：**全仓库唯一定义**，所有写入者必须用它 ----
#
# 背景（三轮审查都在同一个不变量上翻车，2026-08-07/08）：
# "鉴权所依据的权限快照此刻仍然有效"这个条件，原来被**手抄在三处**
# （mcp/server.py、本文件的 write_permissions、register_route.py），
# 各自用 DynamoDB 条件表达式独立写了一遍。后果连着出现两次：
#   ① 审查指出一处漏洞 → 只修那一处，另外两处照旧（P1 重复出现）；
#   ② 手写的角色判定与 CAPABILITIES 漂移——手抄版把 owner 与 collaborator
#      合并成"二者之一即可"，而 CAPABILITIES 里 undeploy **不给** collaborator。
#      于是 transfer_owner 把旧 owner 降级为 collaborator 后，他仍能下线站点
#      （purge_data 不可恢复）。
# 所以这里只留一份，且**角色子句从 CAPABILITIES 推导**而不是另写一套：
# 两者不可能再漂移，新增动作也自动获得正确的守卫。
def snapshot_condition(*, rev: int, had_rev: bool, actor: str = "",
                       action: str = "", role: str = "") -> tuple[str, dict, dict]:
    """→ (ConditionExpression, ExpressionAttributeValues, ExpressionAttributeNames)

    调用方把这三样合并进自己的 Update / ConditionCheck。

    **任何分支都以 `attribute_exists(site_id)` 开头**：item 被删除、或被
    "同 site_id 重建"时，`attribute_not_exists(permissions_rev)` 这类兼容分支
    会静默成立，旧主体的写入照样落地（实测可覆盖新 owner 的站点）。

    两种模式：
      · had_rev=True —— 精确匹配 rev。存量记录之外的一切都走这条（系统写入者
        如 register_route 也走它：seed 保证 rev 必存在，真缺了就条件失败重读，
        fail-closed）。
      · had_rev=False —— 一期存量记录没有 rev 可比，退回断言**角色事实**。
        允许哪些角色由 `CAPABILITIES[action]` 决定，不在这里另写。
    """
    if had_rev:
        return ("attribute_exists(site_id) AND permissions_rev = :rev",
                {":rev": {"N": str(rev)}}, {})
    # --- 无 rev 的存量记录 ---
    if not actor or not action:
        # 系统写入者（register_route 等）没有 actor/action 可断言：稀疏存量行
        # 可能两个 auth 字段都在、rev 却缺失，此时 seed 被跳过，确实会走到这里。
        # 退回"要求 rev 属性存在"——本次条件必然失败 → 调用方重读重试，
        # 下一轮 seed/在线写补上 rev 后即通过。**fail-closed 而不是放行**：
        # 系统写入者没有身份信息，放行等于让守卫消失。
        return ("attribute_exists(site_id) AND attribute_exists(permissions_rev)",
                {}, {})
    if role == ROLE_ADMIN:
        # admin 既不是 owner 也未必在 collaborators 里，角色事实无从断言；
        # 它的时效性由调用方另加的 admins ConditionCheck 负责。
        return ("attribute_exists(site_id)", {}, {})
    allowed = CAPABILITIES.get(action, frozenset())
    clauses = []
    if ROLE_OWNER in allowed:
        clauses.append("#o = :me")
    if ROLE_COLLABORATOR in allowed:
        clauses.append("contains(collaborators, :me)")
    if not clauses:
        # 未登记动作，或只有 admin 能做：fail-closed（条件恒不成立）
        return ("attribute_exists(site_id) AND attribute_not_exists(site_id)",
                {}, {})
    return ("attribute_exists(site_id) AND (" + " OR ".join(clauses) + ")",
            {":me": {"S": actor}}, {"#o": "owner"} if "#o = :me" in clauses else {})


def committed_route_condition(*, static_prefix: str,
                              rev: int) -> tuple[str, dict]:
    """→ (ConditionExpression, ExpressionAttributeValues)：**路由 item 还是我这次
    部署提交进去的那一份吗**。

    与 `snapshot_condition` 的区别是锚点选在哪一端，这个区别就是它存在的理由：

      · `snapshot_condition` 锚"我**读到**的世界"（快照 rev）——用于提交之前的
        守卫（register_route 的事务）。
      · 本函数锚"我**写出去**的那份"（本次的 static_prefix + 本次写入的 rev）——
        用于提交之后的补偿（mark_job 的失败分支）。

    补偿必须用后者，两条实测缺陷各对应一半：

      ① **同站点并发部署**：两个 job 可以同时在跑（部署租约挡的是新执行的
         **创建**——common.plan_deploy_lease；存量在跑的执行仍可能交错）。期间没人
         改权限时两个 job 看到的 rev 相同，于是"线上 rev 还等于我的快照 rev"对
         **旧** job 同样成立 —— 旧 job 的 smoke 失败后会把**新** job 刚提交成功
         的路由整条覆盖回更早的版本（而新 job 的成功分支已经在清理旧前缀了，
         于是覆盖出来的那条指向一个可能已不存在的前缀）。
         `static_prefix` 带 job_id ⇒ 天然唯一 ⇒ 旧 job 的条件必然失败 ⇒ 放弃。
      ② **存量路由没有 rev**（M3 之前写入的：实测生产 6 条站点路由里 5 条如此）。
         锚快照时"快照里没有 rev"就无从比较，只能放弃恢复 —— 那 5 个站点第一次
         更新若 smoke 失败便无法回滚。而锚提交端不受影响：register_route **总会**
         写 rev，所以"我写出去的那份"永远有 rev 可比，rev-less 的快照照样能整值
         写回。

    仍然带 rev 这一项、不能只比 static_prefix：在线改权限
    （`write_permissions` 的两表事务）**不动** static_prefix，只推进 rev 并改权限
    字段。只比前缀会让"smoke 期间有人收紧权限"通过条件，于是把收紧**之前**的
    allowed_users 写回去 = 静默扩权。两项都要。

    不需要另加 `attribute_exists`：item 不存在时属性比较一律为假，条件自动失败
    ——已下线站点的路由不会被复活（`test_restore_does_not_resurrect_a_route_
    deleted_during_smoke` 钉住）。
    """
    return ("static_prefix = :csp AND permissions_rev = :crev",
            {":csp": {"S": static_prefix}, ":crev": {"N": str(int(rev))}})


def sites_snapshot_guard(site_id: str, **kw) -> dict:
    """把 snapshot_condition 包成 sites 表上的 TransactItems ConditionCheck。"""
    expr, vals, names = snapshot_condition(**kw)
    out = {"TableName": os.environ["SITES_TABLE"],
           "Key": {"site_id": {"S": site_id}},
           "ConditionExpression": expr}
    if vals:
        out["ExpressionAttributeValues"] = vals
    if names:
        out["ExpressionAttributeNames"] = names
    return {"ConditionCheck": out}


def assert_can(email: str, site: dict | None, action: str, *,
               is_admin: bool = False, what: str = "") -> str:
    role = role_of(email, site, is_admin)
    if not can(role, action):
        target = what or "该站点"
        if role == ROLE_NONE:
            # **两种情况共用这一句**：站点不存在（role_of 对 site=None 返回
            # ROLE_NONE）与"存在但你不在名单里"。区分开就是枚举探测器——
            # site_id 形如 {name}-{6位hex}，可猜，能区分存在性就能扫出全部站点。
            # 但文案要点出"或不存在"：打错一个字符时，只说"无权访问"会让人
            # 去找 owner 加名单，而真正该做的是查拼写。提示它不泄漏任何信息，
            # 因为两种情况返回的仍是同一句话。
            raise PermissionDenied(f"你无权访问 {target}（或该站点不存在）")
        raise PermissionDenied(f"{target}：{role} 角色无权执行 {action}")
    return role


# 与 contract.schema.EMAIL_RE 同 pattern：权限入口与合同校验对邮箱的判定必须一致
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

_ddb = None


def _admins_table():
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb",
                              region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _ddb.Table(os.environ["ADMINS_TABLE"])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_admin(email: str) -> bool:
    if not email or email == "__count__":
        return False
    # 强一致读：撤权后必须立刻生效，最终一致读会留下代管窗口
    return "Item" in _admins_table().get_item(Key={"email": email},
                                              ConsistentRead=True)


def list_admins() -> list[str]:
    """列管理员。用强一致读——撤权/新增后要立刻可见。

    注意：即便强一致，Scan 也没有跨分页快照隔离，所以**不要用它做安全判定**
    （存在性判定用 is_admin 的强一致 Get，计数约束交给事务条件）。
    这里只服务于"展示名单"与停写维护。
    """
    items = common._paginate(_admins_table().scan, ProjectionExpression="email",
                             ConsistentRead=True)
    # __count__ 是 remove_admin 的并发 sentinel，不是管理员
    return sorted(i["email"] for i in items if i["email"] != "__count__")


def add_admin(email: str, added_by: str) -> None:
    """幂等新增管理员，并维护 __count__ sentinel（remove_admin 的条件依赖它）。

    Put 与计数递增必须在**同一事务**里：三步顺序写（读→put→加计数）有两个
    坏结局——① 两个相同邮箱并发添加都看到"不存在"，计数被加两次而表里只有
    一个管理员（计数虚高 → 两人并发删除时 n > 1 都通过 → 表被删空）；
    ② put 成功但计数未加就崩，重试看到"已存在"直接返回，计数永久偏低
    （正常删除被误拦）。条件 attribute_not_exists 让重复添加走幂等分支。
    """
    import time as _time

    import botocore.exceptions
    if not EMAIL_RE.fullmatch(email or ""):
        raise ValueError(f"非法邮箱: {email!r}")
    # 经 _ddb_client() 取 client（而不是就地 boto3.client）：测试要能注入
    # TransactionConflict 才能覆盖下面的退避重试分支——绕开这个 hook 会让
    # 冲突分支永远测不到（错误实现照样全绿）。
    ddb = _ddb_client()
    table = os.environ["ADMINS_TABLE"]
    items = [
        {"Put": {"TableName": table,
                 "Item": {"email": {"S": email},
                          "added_by": {"S": added_by},
                          "added_at": {"S": now_iso()}},
                 "ConditionExpression": "attribute_not_exists(email)"}},
        {"Update": {"TableName": table,
                    "Key": {"email": {"S": "__count__"}},
                    "UpdateExpression": "SET n = if_not_exists(n, :zero) + :one",
                    "ExpressionAttributeValues": {":zero": {"N": "0"},
                                                  ":one": {"N": "1"}}}}]
    # _cancel_reasons 在本文件后面（"权限写入"一节）定义——模块级函数在调用时
    # 才解析，位置不影响；按本任务给的顺序追加即可，不要为此重排。
    # TransactionCanceledException 是个笼统的伞：ConditionalCheckFailed（重复
    # 添加，幂等）、TransactionConflict（另一笔事务在改同一 item，该退避重试）、
    # ProvisionedThroughputExceeded、ValidationError… 一律当"已存在"吞掉，会把
    # 真失败报成成功——管理员没建上，调用方以为建好了。必须按 reason 分流。
    for attempt in range(3):
        try:
            ddb.transact_write_items(TransactItems=items)
            # 审计 admin 名单变化（spec §5.5 要求覆盖）。target 用
            # admins:{email} 而不是 site:*——被改的对象是名单，不是站点。
            ops_log.record(actor=added_by, action="add_admin",
                           target=f"admins:{email}", result="ok")
            return
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            reasons = _cancel_reasons(e)
            # 下标与 items 的构造绑定（本文件的 AST 守卫禁止整数字面量下标）：
            # 关心的是 Put（items 里唯一带 attribute_not_exists 的那项）。
            put_idx = next(i for i, it in enumerate(items) if "Put" in it)
            put_reason = reasons[put_idx] if len(reasons) > put_idx else ""
            if put_reason == "ConditionalCheckFailed":
                # 该邮箱已是管理员：幂等成功，计数不动。**仍然落审计**，
                # 但 result 区分开——"谁在什么时候尝试提权"本身就是审计线索，
                # 而把它记成 ok 会让名单人数与 add_admin 条数对不上。
                ops_log.record(actor=added_by, action="add_admin",
                               target=f"admins:{email}", result="noop")
                return
            if "TransactionConflict" in reasons and attempt < 2:
                _time.sleep(0.05 * (2 ** attempt))   # 并发写 __count__，退避重试
                continue
            raise               # 容量/校验等其他原因：如实抛出


def rebuild_admin_count() -> int:
    """按实际 item 数重建 __count__。**停写维护操作，不要放进正常流程。**

    DynamoDB 的 Scan 即便加 ConsistentRead 也**不提供跨分页的快照隔离**：
    与在线增删并发时会把不同时点的结果混在一起写进 sentinel。计数偏高 →
    最后一个管理员可能通过 `n > 1` 被删掉（表被删空）；偏低 → 正常删除被
    永久误拦。所以它只用于：
      - 存量表首次引入 sentinel（sentinel 之前建的表）；
      - 事务中途失败后确认计数漂移，人工修复。
    调用前先确认没有并发的 add/remove（例如临时收回控制台写权限）。
    正常路径的计数由 add_admin / remove_admin 的事务维护，**不要覆盖它**。
    """
    n = len(list_admins())
    _admins_table().put_item(Item={"email": "__count__", "n": n})
    return n


def remove_admin(email: str, removed_by: str = "") -> None:
    """删管理员。名单删空 = 平台永久失去管理入口，因此硬拦。

    removed_by 是审计用的操作者（spec §5.5 要求覆盖 admin 名单变化）。
    **可选参数**：一期的种子脚本等既有调用方不传它，审计里记空 actor 也比
    改动它们的签名安全；panel / MCP 这些有身份的入口必须传。

    **不做 Scan 前置判断**：`list_admins()` 是最终一致 Scan，刚添加的管理员
    可能扫不到 → 前置检查认为"不存在"直接 return 成功，而 `is_admin()` 的强
    一致 Get 仍看得到该 item，用户实际保留着管理员权限（静默失败）。
    存在性与"不是最后一个"全部交给事务条件判定：
      - Delete 带 attribute_exists(email)：不存在 → 条件失败 → 幂等成功；
      - sentinel 带 n > 1：删到只剩一个 → 条件失败 → 拒绝。

    **入口必须验邮箱格式**（与 add_admin 对称）：`__count__` 是调用方可达输入
    （M3 控制台 / MCP 工具的参数），而 email="__count__" 时事务的 Delete 与
    Update 落在同一个 item 上——DynamoDB 对"同一事务多次操作同一 item"抛的是
    **ValidationException 而非 TransactionCanceledException**，会穿过下面的
    分流变成不可读的 500；更糟的是若它侥幸执行，删掉的是计数 sentinel 本身。
    """
    import botocore.exceptions
    if not EMAIL_RE.fullmatch(email or ""):
        raise ValueError(f"非法邮箱: {email!r}")
    ddb = _ddb_client()   # 同 add_admin：走 hook，冲突分支才可注入测试
    table = os.environ["ADMINS_TABLE"]
    items = [
        {"Delete": {"TableName": table,
                    "Key": {"email": {"S": email}},
                    "ConditionExpression": "attribute_exists(email)"}},
        # sentinel 记录当前管理员数；条件保证递减后仍 ≥1
        {"Update": {"TableName": table,
                    "Key": {"email": {"S": "__count__"}},
                    "UpdateExpression": "SET n = n - :one",
                    "ConditionExpression": "n > :one",
                    "ExpressionAttributeValues": {":one": {"N": "1"}}}}]
    # 下标与构造绑定（AST 守卫禁止整数字面量下标读 reasons）
    delete_idx = next(i for i, it in enumerate(items) if "Delete" in it)
    sentinel_idx = next(i for i, it in enumerate(items)
                        if "Update" in it and "__count__" in str(it))
    try:
        ddb.transact_write_items(TransactItems=items)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        reasons = _cancel_reasons(e)
        if "TransactionConflict" in reasons:
            raise PermissionConflict(
                "管理员名单正被他人修改，请重试") from e
        # 逐项分辨，**顺序必须是 Delete 先、sentinel 后**：
        #   第 0 项 Delete —— attribute_exists 失败 = 目标本就不是管理员
        #   第 1 项 sentinel —— n > 1 失败 = 目标是最后一个管理员
        # 删一个不存在的邮箱、而当前恰好只有一名管理员时，**两项会同时
        # ConditionalCheckFailed**（已用 moto 实测：reasons ==
        # ['ConditionalCheckFailed', 'ConditionalCheckFailed']）。
        # 先看 sentinel 就会把"目标不存在"误报成"不能删除最后一个管理员"，
        # 与本函数承诺的幂等语义相反。所以先判 Delete 项。
        if (len(reasons) > delete_idx
                and reasons[delete_idx] == "ConditionalCheckFailed"):
            # 该邮箱本就不是管理员：幂等成功（无论剩几个）。
            # 仍落审计但 result=noop，理由同 add_admin 的幂等分支。
            ops_log.record(actor=removed_by, action="remove_admin",
                           target=f"admins:{email}", result="noop")
            return
        if (len(reasons) > sentinel_idx
                and reasons[sentinel_idx] == "ConditionalCheckFailed"):
            # 目标确实存在，只是它是最后一个
            ops_log.record(actor=removed_by, action="remove_admin",
                           target=f"admins:{email}", result="denied")
            raise PermissionDenied("不能删除最后一个管理员") from e
        raise               # 容量/校验等：如实抛出，不要伪装成权限问题
    ops_log.record(actor=removed_by, action="remove_admin",
                   target=f"admins:{email}", result="ok")


def normalize_allowed_users(value):
    """校验并规范化 allowed_users：返回 "org" 或去重排序后的邮箱 list。"""
    if value == "org":
        return "org"
    if not isinstance(value, list) or not value:
        raise ValueError('allowed_users 必须为 "org" 或非空邮箱数组')
    for e in value:
        if not isinstance(e, str) or not EMAIL_RE.fullmatch(e):
            raise ValueError(f"allowed_users 含非法邮箱: {e!r}")
    return sorted(set(value))


# "该字段不在这一行里"的哨兵。**不能用 None 代替**：DynamoDB 有真正的 NULL 型
# （`{"NULL": true}` 读出来就是 None），把缺失也报成 `NoneType=None` 会让人拿着
# 文案去表里找一个不存在的 null 值。两种行的修法相同，但认出坏在哪靠的是文案。
_ABSENT = object()


# ---- 三段补救文案：**全仓库唯一定义**，测试也从这里取 ----
#
# 补救文案必须覆盖**能拒的每个字段**（由
# test_repair_hint_covers_every_field_it_can_reject 钉住）：拒绝的代价是站点
# 在人工修好之前既不能改权限也不能部署，换来的只有"人照着文案能把那一行改
# 回来"这一样东西。少一个字段的形态，那个字段的拒绝就是一张工单。
#
# **文案分三种，因为三种坏法的修法完全不同**（spec §4.1 把"拒绝"这个代价的
# 可接受前提写成「错误文案直接给出修法」）：
#   · 类型不对 ⇒ 那一行存着一个用不了的值，只能人工改对。再部署一百次也
#     不会把它改好。
#   · **会被部署初始化的字段**缺失 ⇒ 绝大多数是"这个站点还没成功部署过"：
#     create_site_record 只写 owner/name/status，权限字段由首次部署的
#     register_route._seed_permissions_if_absent 补齐。对这种行说"请修正为
#     正确类型"是**不可执行的**——那一行没有任何坏数据，用户会被指去手改
#     DynamoDB。
#   · **不会被部署初始化的字段**（当前只有 owner）缺失 ⇒ 只能人工补。见下面
#     `_SEEDED_BY_FIRST_DEPLOY` 上方那段。
# 三条都带类型清单：缺失的另一种可能是**已部署行被人为删过字段**，那种确实
# 要照类型补。
#
# **为什么是模块级常量而不是 `effective_policy` 的局部变量**（S1 fix round 2）：
# 三个包的测试要断言"这条消息带的是**哪一支**修法"（panel 的 409、MCP 的工具
# 错误、控制台 toast 各一套）。局部变量拿不到，于是那些断言只能把措辞片段
# **手抄进测试**——实测抄了 12 处、跨 3 个测试文件、2 个包。那正是本轮
# （Task 2 / 3b / 5）一直在消除的形态：同一个不变量被抄成多份，改措辞的人
# 会倾向于删掉其中一处，而不是想清楚新措辞还能不能区分两支。
# 提到模块级之后测试写 `assert permissions.REPAIR_ABSENT in msg`，
# 措辞变成**派生**的：改这里，测试跟着变，不需要同步任何副本。
#
# **"部署一次就好"只对首次部署真的会初始化的那几个字段成立**（S1 最终复核）：
# `register_route._seed_permissions_if_absent` 的 if_not_exists 写的是下面这四个，
# **`owner` 不在其中**。对缺 owner 的行说"部署一次就好"是把人指进一条死路——
# 部署走到 `_route_item` 会撞上同一条拒绝，没有出口。而 spec §4.1 接受"坏行让站点
# 既不能改权限也不能部署"这个代价的前提**只有一条**：文案给出真实的修法。
# 所以缺失分两支，判据是"这个字段会不会被部署初始化"而不是"它是不是 owner"：
# 将来加第五个字段时，默认走"人工补"那一支（准确），要走"部署会补"那一支得先
# 真的把它加进 seed —— 这个方向的默认值不会再产出一条不可执行的建议。
# 名单与文案共用同一个元组，`test_seeded_fields_match_the_deploy_path` 按
# register_route 的源码钉住它。
_SEEDED_BY_FIRST_DEPLOY = ("require_login", "allowed_users", "collaborators",
                           "permissions_rev")
_TYPES = ('require_login: BOOL；allowed_users: S="org" 或 L=邮箱数组；'
          'collaborators: L=邮箱数组（可缺省）；owner: 非空 S')
REPAIR_WRONG_TYPE = f'请把 sites 表该行修正为正确类型后重试（{_TYPES}）。'
REPAIR_ABSENT = (
    '这通常表示该站点**尚未成功部署过**——权限字段由首次成功部署自动初始化，'
    '所以成功部署一次之后就能正常改权限，不需要手改库。'
    f'若该站点确实已成功部署过，则是这一行被人为删过字段，请按类型补齐（{_TYPES}）。')
REPAIR_ABSENT_UNSEEDED = (
    '**这个字段不会被部署初始化**（首次部署只补 '
    f'{" / ".join(_SEEDED_BY_FIRST_DEPLOY)}），所以再部署一次也不会有出口——'
    f'请人工把 sites 表该行缺的字段按类型补齐（{_TYPES}）。'
    # 括号里的话**只对 owner 成立**，所以显式写出字段名：将来多出第五个不被
    # seed 的字段时，这句话对它不会变成一条假事实。
    '（`owner` 在建站时就已写入、之后没有任何代码会删它，所以它缺失意味着'
    '这一行被人为改过。）')


def effective_policy(site: dict) -> dict:
    """从 sites 行解出可投影的策略。**三个投影 writer 的唯一入口。**

    判据只有一条：**每个字段要么类型明确，要么它的「缺失」有唯一安全解释**；
    两者都不成立即抛 PolicyDataInvalid。

    | 字段          | 合法形态                    | 缺失时 |
    |---------------|-----------------------------|--------|
    | require_login | 真 bool                     | 抛错   |
    | allowed_users | "org" 或非空邮箱 list       | 抛错   |
    | collaborators | list[str]                   | []     |
    | owner         | 非空 str                    | 抛错   |

    为什么不能沿用 `bool(site.get("require_login", True))` 与
    `site.get("allowed_users", "org")`：读路径（Edge）对坏数据 fail-closed，
    而这两个默认值让**写路径**把坏数据洗成合法的 `{"BOOL": false}` / `"org"`
    ——两侧对坏数据的语义相反，Edge 的加固被写入侧抵消（M02）。

    异常文案分三种（**类型不对**要人工改那一行；**会被部署初始化的字段缺失**
    通常只是还没成功部署过、部署一次就会初始化；**owner 这类部署不初始化的字段
    缺失**只能人工补）——三段文案是模块级常量 `REPAIR_WRONG_TYPE` /
    `REPAIR_ABSENT` / `REPAIR_ABSENT_UNSEEDED`，理由与措辞都写在它们上方。
    拒绝的语义与拒绝的输入集合三者都不因此改变。
    """
    site_id = site.get("site_id", "<unknown>")

    def reject(field, value):
        absent = value is _ABSENT
        found = "字段缺失" if absent else f"{type(value).__name__}={value!r}"
        if not absent:
            repair = REPAIR_WRONG_TYPE
        elif field in _SEEDED_BY_FIRST_DEPLOY:
            repair = REPAIR_ABSENT
        else:
            # owner 这一支：部署补不了它，说"部署一次就好"就是一条死路
            repair = REPAIR_ABSENT_UNSEEDED
        raise PolicyDataInvalid(
            f"站点 {site_id} 的 {field} 形态不合法"
            f"（{found}），已拒绝投影权限。{repair}")

    # 四个字段一律用 `site.get(key, _ABSENT)` 这**同一个**写法探"缺失"。
    # 不混用 `key not in site` 与 `site.get(key, 默认值)`：三种写法并存时，
    # 加第五个字段的人有三个样板可抄、却没有任何信号指出哪个才是安全的那个。
    # 统一之后"缺失可以有默认值"只在下面 collaborators 那一处出现，是显式的例外。
    require_login = site.get("require_login", _ABSENT)
    if not isinstance(require_login, bool):
        reject("require_login", require_login)

    allowed_users = site.get("allowed_users", _ABSENT)
    if allowed_users is _ABSENT:
        reject("allowed_users", _ABSENT)
    try:
        allowed = normalize_allowed_users(allowed_users)
    except ValueError as exc:
        # 带上读到的**类型**：`必须为 "org" 或非空邮箱数组` 这一句对 `7`、`"ORG"`、
        # `[]` 三种坏值一模一样，而三者的修法各不相同。只带类型不带整值——名单可能
        # 很长，而"含非法邮箱"那条 ValueError 本身已经点出坏的是哪一个。
        raise PolicyDataInvalid(
            f"站点 {site_id} 的 allowed_users 形态不合法"
            f"（读到 {type(allowed_users).__name__}：{exc}），"
            # 走到这里字段一定**在**（_ABSENT 已在上面被 reject 掉），所以是
            # "类型不对"那条文案——不能建议去部署，部署不会改好一个坏值。
            f"已拒绝投影权限。{REPAIR_WRONG_TYPE}") from exc

    # **全函数唯一一处「缺失有默认值」**——其余三个字段的缺失一律 reject。
    # 这个例外只在这一个字段上站得住：没有 collaborators 键，唯一的读法就是
    # "没有协作者"。而 require_login 缺失是 True 还是 False、allowed_users 缺失是
    # "org" 还是空名单，都答不出来——往任一方向兜底都是替站主做一次静默的安全决定
    # （猜 "org" 是静默扩权，猜空名单是静默收紧）。
    collaborators = site.get("collaborators", _ABSENT)
    if collaborators is _ABSENT:
        collaborators = []
    if not isinstance(collaborators, list) or not all(
            isinstance(e, str) for e in collaborators):
        reject("collaborators", collaborators)

    owner = site.get("owner", _ABSENT)
    if not isinstance(owner, str) or not owner:
        reject("owner", owner)

    return {"require_login": require_login, "allowed_users": allowed,
            "collaborators": list(collaborators), "owner": owner}


def effective_policy_audited(site: dict, *, actor: str) -> dict:
    """`effective_policy` + 拒绝时落一条审计。**三个投影 writer 都调这个。**

    审计做成**一处包装**而不是在三个 writer 各写一份 try/except：后者就是本轮
    要消除的形态（同一段处理抄多份）。纯解析留在 `effective_policy` 里，
    因为体检脚本也要调它，而那条路径没有 ops_log 表、也不该写任何东西。

    **不加告警**：这是"数据脏了"而不是"正在被攻击"，当前 0 例，
    拿告警叫醒人不成比例（要告警归 S4）。
    """
    try:
        return effective_policy(site)
    except PolicyDataInvalid:
        ops_log.record(actor=actor, action="reject_policy_projection",
                       target=f"site:{site.get('site_id', '')}", result="rejected")
        raise


def _site_or_raise(site_id: str, *, consistent: bool = False) -> dict:
    """取站点记录。

    consistent=True 用强一致读：授权判定与 read-modify-write 都基于它，
    最终一致读会放大"权限刚被撤销但旧请求仍读到旧名单"的窗口。
    """
    site = (common.get_site_consistent(site_id) if consistent
            else common.get_site(site_id))
    if not site:
        raise PermissionDenied(f"站点 {site_id} 不存在")
    return site


# ---- 权限写入：唯一入口，两表原子提交 ----
# 真源是 sites 表，路由表是给 Edge 读的投影。两者必须一起成功或一起失败：
# 顺序两写在"收紧权限"场景下会留下 sites 已私有、Edge 仍公开放行的状态
# （安全状态错误，不是最终一致性）。见 spec §3.2。
#
# 测试钩子：站点尚未首次部署成功时路由 item 不存在，此时降级为只写 sites。
# 该降级是显式分支——把它关掉才能测"路由本该存在却写失败"的回滚路径。
_ALLOW_ROUTE_ABSENT = True


def allowed_users_av(allowed) -> dict:
    """allowed_users 的 DynamoDB AttributeValue：字面量 org 用 S，名单用 L。

    Edge 的 _deser 必须已支持 L——否则名单会被读成 False，名单站点变成
    "仅 owner 可访问"（json.loads(False) 抛异常 → 空名单，fail-closed）：
    合法名单成员全部 403，等于鉴权站点大面积宕机。部署顺序：Edge 先上，
    写侧后上——顺序颠倒是可用性事故（锁死），不是数据暴露；应急处置是
    先部署 Edge 的 L 支持，而不是回滚 Edge。
    """
    if allowed == "org":
        return {"S": "org"}
    return {"L": [{"S": e} for e in allowed]}


def _ddb_client():
    return boto3.client("dynamodb",
                        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def _cancel_reasons(err) -> list[str]:
    """TransactionCanceledException 的逐项取消原因（与 TransactItems 同序）。

    可能的值：ConditionalCheckFailed / TransactionConflict /
    ItemCollectionSizeLimitExceeded / ProvisionedThroughputExceeded /
    ThrottlingError / ValidationError / None（该项本身没问题）。
    **不要把整个异常当成"条件失败"**——那会把容量与校验错误报成业务结果。
    """
    return [r.get("Code", "") for r in
            err.response.get("CancellationReasons", [])]


MAX_WRITE_ATTEMPTS = 3


def write_permissions(site_id: str, *, actor: str, action: str,
                      require_login=None, allowed_users=None,
                      collaborators=None, new_owner=None,
                      mutate=None, _attempt: int = 0) -> dict:
    """权限写入的唯一入口：授权判定 + sites 表（真源）+ 路由表（投影）原子提交。

    **授权与写入必须绑定同一个快照**，这是本函数把 actor/action 收进来的原因。
    分离写法（调用方先 assert_can、再调 setter）有 TOCTOU：
      旧 owner/collaborator 通过鉴权 → 另一请求把他移除、rev 前进 →
      setter 重新读到新 rev → 用新 rev 成功写入
    结果是刚被撤销权限的人仍能完成一次写。所以：一次强一致读同时得出角色与
    rev，rev 进事务条件，角色由该次读的 owner/collaborators 判定——两者要么
    一起成立，要么事务被 rev 条件挡下。

    mutate: 可选回调 `(site) -> dict`，在同一快照上计算要写的字段
    （collaborators 这类 read-modify-write 用它，避免调用方再读一次）。
    返回的 dict 会覆盖同名的显式参数。

    抛 PermissionDenied（无权）、PermissionConflict（并发修改，调用方转 409）
    或原始 ClientError。
    """
    import botocore.exceptions

    site = _site_or_raise(site_id, consistent=True)
    caller_is_admin = is_admin(actor)
    # 与 rev 同源的授权判定——不要在调用方另做一次
    try:
        role = assert_can(actor, site, action, is_admin=caller_is_admin,
                          what=f"站点 {site_id}")
    except PermissionDenied:
        # 失败操作也要有可判读记录（spec §5.5）。**不记异常原文**——它含
        # "或该站点不存在"的存在性提示，而审计表的读者与被拒者不是同一批人，
        # 落库等于开一条侧信道。只记结构化的 result。
        ops_log.record(actor=actor, action=action, target=f"site:{site_id}",
                       result="denied")
        raise
    rev = int(site.get("permissions_rev", 0))
    if mutate is not None:
        overrides = mutate(site) or {}
        require_login = overrides.get("require_login", require_login)
        allowed_users = overrides.get("allowed_users", allowed_users)
        collaborators = overrides.get("collaborators", collaborators)
        new_owner = overrides.get("new_owner", new_owner)

    # 坏数据一律拒绝投影，不猜方向（M02）。位置是硬要求：**读到 site 行之后、
    # 构造事务之前** ⇒ 抛错时事务根本不发起，零副作用。
    effective = effective_policy_audited(site, actor=actor)
    sets = ["permissions_updated_at = :t", "permissions_updated_by = :by",
            "permissions_rev = :nrev"]
    vals = {":t": {"S": now_iso()}, ":by": {"S": actor},
            ":nrev": {"N": str(rev + 1)}, ":rev": {"N": str(rev)}}
    names = {}

    if require_login is not None:
        if not isinstance(require_login, bool):
            raise ValueError("require_login 必须为布尔值")
        effective["require_login"] = require_login
        sets.append("require_login = :rl")
        vals[":rl"] = {"BOOL": require_login}
    if allowed_users is not None:
        effective["allowed_users"] = normalize_allowed_users(allowed_users)
        sets.append("allowed_users = :au")
        vals[":au"] = allowed_users_av(effective["allowed_users"])
    if collaborators is not None:
        effective["collaborators"] = list(collaborators)
        sets.append("collaborators = :co")
        vals[":co"] = {"L": [{"S": e} for e in effective["collaborators"]]}
    if new_owner is not None:
        effective["owner"] = new_owner
        sets.append("#o = :ow")
        names["#o"] = "owner"
        vals[":ow"] = {"S": new_owner}
    if len(sets) == 3:
        raise ValueError("没有要更新的字段")

    # 守卫条件走唯一定义（见 snapshot_condition）：手抄第二份就是三轮审查里
    # 反复出问题的根因。这里的 actor/action/role 让"无 rev 存量记录"也能按
    # CAPABILITIES 的角色事实守住，而不是无条件放行。
    guard_expr, guard_vals, guard_names = snapshot_condition(
        rev=rev, had_rev=("permissions_rev" in site),
        actor=actor, action=action, role=role)
    vals.update(guard_vals)
    names.update(guard_names)
    # :rev 只服务于守卫条件（SET 子句用的是 :nrev）。无-rev 分支不引用它，
    # 而 DynamoDB 会拒绝未被任何表达式使用的 ExpressionAttributeValues。
    if ":rev" not in guard_vals:
        vals.pop(":rev", None)
    site_update = {
        "TableName": os.environ["SITES_TABLE"],
        "Key": {"site_id": {"S": site_id}},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ConditionExpression": guard_expr,
        "ExpressionAttributeValues": vals,
    }
    if names:
        site_update["ExpressionAttributeNames"] = names

    # 路由表只 update 权限字段，不整条覆盖——register_route 是整条 put_item
    # （原子切流），两者都整写会踩掉 static_prefix / api_target。
    route_update = {
        "TableName": os.environ["ROUTING_TABLE"],
        "Key": {"subdomain": {"S": common.subdomain_for(site_id)}},
        "UpdateExpression": ("SET require_auth = :a, allowed_users = :u, "
                             "collaborators = :c, #ro = :o, permissions_rev = :rv"),
        "ConditionExpression": "attribute_exists(subdomain)",
        "ExpressionAttributeNames": {"#ro": "owner"},
        "ExpressionAttributeValues": {
            ":a": {"BOOL": effective["require_login"]},
            ":u": allowed_users_av(effective["allowed_users"]),
            ":c": {"L": [{"S": e} for e in effective["collaborators"]]},
            ":o": {"S": effective["owner"]},
            # 投影带上 rev：register_route 用它判断"我读到的策略是否还是最新"
            # （见 register_route 的条件事务）。
            ":rv": {"N": str(rev + 1)}},
    }

    items = [{"Update": site_update}, {"Update": route_update}]
    # 下标与构造绑定（AST 守卫禁止整数字面量下标读 reasons）：admin 项是条件
    # 追加的，写死 [2] 的话"非 admin 且有人往中间插项"时会把原因对错。
    site_idx, route_idx = 0, 1
    admin_idx = None
    if role == ROLE_ADMIN:
        admin_idx = len(items)
        # admin 代管路径：把"调用者此刻仍是管理员"也放进同一事务。
        # 否则 admin 被移出名单与本次写入之间同样有 TOCTOU 窗口。
        items.append({"ConditionCheck": {
            "TableName": os.environ["ADMINS_TABLE"],
            "Key": {"email": {"S": actor}},
            "ConditionExpression": "attribute_exists(email)"}})

    def _audit(route_synced: bool) -> None:
        """事务提交成功后落审计。

        **两条成功路径都要落**（正常双表事务、以及 route 不存在时的降级路径）
        ——只在其中一处落会让降级场景静默漏记，而降级恰恰是更值得审计的情形。
        detail 只放结构化小字段：role / 新 rev / 是否同步了路由投影。
        """
        ops_log.record(actor=actor, action=action, target=f"site:{site_id}",
                       result="ok",
                       detail={"role": role, "rev": rev + 1,
                               "route_synced": route_synced})

    ddb = _ddb_client()
    try:
        ddb.transact_write_items(TransactItems=items)
        _audit(True)
        return {**effective, "route_synced": True}
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        reasons = _cancel_reasons(e)
        def _failed(idx):
            return (idx is not None and len(reasons) > idx
                    and reasons[idx] == "ConditionalCheckFailed")
        site_failed = _failed(site_idx)
        route_failed = _failed(route_idx)
        admin_failed = _failed(admin_idx)
        if admin_failed:
            # 管理员身份在鉴权与提交之间被撤销
            raise PermissionDenied("你的管理员权限已被撤销") from e
        if site_failed:
            raise PermissionConflict(
                "站点权限已被其他人修改，请刷新后重试") from e
        if route_failed and _ALLOW_ROUTE_ABSENT:
            # 站点还没首次部署成功（无路由 item）：只写真源。
            # **仍然走事务**，不能裸 update_item——裸写会重开两个窗口：
            #   ① route 在两次写之间被 register_route 创建（用它读到的旧策略，
            #      公开），fallback 只把 sites 改成私有 → sites 私有 / Edge
            #      公开，正是事务本该消除的状态；
            #   ② 首个事务里的 admin ConditionCheck 已随取消一起失效，
            #      此时 admin 若被撤权，裸写不再校验（admin 变更不推进站点 rev）。
            # 所以 fallback = sites Update + route "确实不存在" 的
            # ConditionCheck（+ admin 路径保留 admin ConditionCheck）。
            fallback = [
                {"Update": site_update},
                {"ConditionCheck": {
                    "TableName": os.environ["ROUTING_TABLE"],
                    "Key": {"subdomain": {"S": common.subdomain_for(site_id)}},
                    "ConditionExpression": "attribute_not_exists(subdomain)"}},
            ]
            if role == ROLE_ADMIN:
                fallback.append({"ConditionCheck": {
                    "TableName": os.environ["ADMINS_TABLE"],
                    "Key": {"email": {"S": actor}},
                    "ConditionExpression": "attribute_exists(email)"}})
            try:
                ddb.transact_write_items(TransactItems=fallback)
            except botocore.exceptions.ClientError as inner:
                if (inner.response["Error"]["Code"]
                        != "TransactionCanceledException"):
                    raise
                inner_reasons = _cancel_reasons(inner)
                if len(inner_reasons) > 1 and inner_reasons[1] == "ConditionalCheckFailed":
                    # route 在这期间被创建了 → 回到正常双表事务重试。
                    # **必须带递归上限**：持续制造"降级前 route 刚好出现"这个
                    # 时序的并发流会让它无限递归成 RecursionError（用户看到 500，
                    # 且栈里没有任何业务信息）。耗尽后按并发冲突返回可读的 409。
                    if _attempt + 1 >= MAX_WRITE_ATTEMPTS:
                        raise PermissionConflict(
                            "站点权限正被并发修改（路由状态反复变化），请重试"
                        ) from inner
                    return write_permissions(
                        site_id, actor=actor, action=action,
                        require_login=require_login, allowed_users=allowed_users,
                        collaborators=collaborators, new_owner=new_owner,
                        mutate=mutate, _attempt=_attempt + 1)
                if len(inner_reasons) > 2 and inner_reasons[2] == "ConditionalCheckFailed":
                    raise PermissionDenied("你的管理员权限已被撤销") from inner
                raise PermissionConflict(
                    "站点权限已被其他人修改，请刷新后重试") from inner
            _audit(False)
            return {**effective, "route_synced": False}
        raise


# 三个 setter 都不自己鉴权、不自己读快照——全部交给 write_permissions，
# 保证"授权判定"与"写入条件"用同一次强一致读（见其 docstring 的 TOCTOU 说明）。
# read-modify-write 的计算通过 mutate 回调在同一快照上做。

def set_access_policy(site_id: str, *, actor: str, require_login=None,
                      allowed_users=None) -> dict:
    """改访问策略（owner / collaborator / admin 均可）。"""
    out = write_permissions(site_id, actor=actor, action="set_access_policy",
                            require_login=require_login,
                            allowed_users=allowed_users)
    return {"require_login": out["require_login"],
            "allowed_users": out["allowed_users"]}


def set_collaborators(site_id: str, *, actor: str, add=None, remove=None) -> list[str]:
    """增删协作者（仅 owner / admin）。"""
    def _mutate(site):
        current = list(site.get("collaborators") or [])
        for e in (add or []):
            if not EMAIL_RE.fullmatch(e or ""):
                raise ValueError(f"非法邮箱: {e!r}")
            if e == site.get("owner"):
                raise ValueError("owner 已隐式拥有全部权限，不能同时作为协作者")
            if e not in current:
                current.append(e)
        for e in (remove or []):
            if e in current:
                current.remove(e)
        return {"collaborators": current}

    return write_permissions(site_id, actor=actor,
                             action="manage_collaborators",
                             mutate=_mutate)["collaborators"]


def transfer_owner(site_id: str, *, actor: str, new_owner: str) -> dict:
    """转移所有权：原 owner 自动降级为 collaborator（防转错人即失联）。"""
    if not EMAIL_RE.fullmatch(new_owner or ""):
        raise ValueError(f"非法邮箱: {new_owner!r}")
    captured = {}

    def _mutate(site):
        old_owner = site.get("owner", "")
        if new_owner == old_owner:
            raise ValueError("新 owner 与当前 owner 相同")
        collaborators = [e for e in (site.get("collaborators") or [])
                         if e != new_owner]
        if old_owner and old_owner not in collaborators:
            collaborators.append(old_owner)
        captured["previous_owner"] = old_owner
        return {"new_owner": new_owner, "collaborators": collaborators}

    out = write_permissions(site_id, actor=actor, action="transfer_owner",
                            mutate=_mutate)
    return {"owner": out["owner"], "collaborators": out["collaborators"],
            "previous_owner": captured.get("previous_owner", "")}


def resync_route(site_id: str, *, actor: str) -> dict:
    """以 sites 表为准重投影路由表（仅 admin；phase2 spec §8 的人工修复口）。

    与 write_permissions 的区别：**不改 sites 表、不推进 rev**——它修的是
    投影漂移（人为改库、迁移中断），真源本身没问题。所以这里只写 route，
    且投影字段集合必须与 write_permissions 的 route_update **完全一致**
    （少一个字段就等于"修完还是脏的"）；由
    test_resync_projects_exactly_the_same_route_fields_as_write_permissions
    从两处的 UpdateExpression 解析比对锁定，不靠人记得同步。

    **真源坏了它就拒绝**（M02）：修复投影漂移 ≠ 修复源数据损坏。后者要人判定
    意图，工具替他选方向（扩权还是收紧）都是猜。

    rev 用 sites 表当前值**原样**投影（不 +1）：register_route 用 route.rev 与
    sites.rev 比对判断"我读到的策略是否最新"，这里若虚增会让下一次**合法**
    部署误判成"权限被并发修改"。

    这个函数放在 permissions.py 而不是 panel：panel 禁止手写路由投影
    （投影字段与守卫语义必须单一真源），而 resync 的本质就是投影。
    """
    if not is_admin(actor):
        raise PermissionDenied("仅平台管理员可重投影路由")
    site = _site_or_raise(site_id, consistent=True)
    rev = int(site.get("permissions_rev", 0))
    # 坏数据一律拒绝投影，不猜方向（M02）。**注意与旧注释的差别**：
    # 这里曾用 `normalize_allowed_users(raw) if raw else "org"` 并论证
    # 「让一个修复工具在最需要它的脏数据上抛异常，等于没有这个工具」。
    # 那个论证已被推翻——修复**投影漂移** ≠ 修复**源数据损坏**，
    # 后者必须由人判定意图，工具替他选方向（扩权或收紧）都是错的。
    effective = effective_policy_audited(site, actor=actor)
    _ddb_client().update_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": common.subdomain_for(site_id)}},
        UpdateExpression=("SET require_auth = :a, allowed_users = :u, "
                          "collaborators = :c, #ro = :o, permissions_rev = :rv"),
        # 路由 item 必须已存在：本函数是"纠正投影"，不是"补建路由"。
        # 不存在说明站点没部署成功过（或已下线），此时无中生有地建一条
        # 会让一个不该可达的 subdomain 变成可路由。
        ConditionExpression="attribute_exists(subdomain)",
        ExpressionAttributeNames={"#ro": "owner"},
        ExpressionAttributeValues={
            ":a": {"BOOL": effective["require_login"]},
            ":u": allowed_users_av(effective["allowed_users"]),
            ":c": {"L": [{"S": e} for e in effective["collaborators"]]},
            ":o": {"S": effective["owner"]},
            ":rv": {"N": str(rev)}})
    return {"site_id": site_id, "permissions_rev": rev, **effective}
