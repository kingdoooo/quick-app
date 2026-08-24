#!/usr/bin/env python3
"""权限快照守卫的**真机**验收：条件表达式在真实 DynamoDB 上的行为。

为什么必须真机：本仓库所有守卫用例都跑在 moto 上。moto 与真实 DynamoDB 在
条件表达式求值、`contains()` 的类型语义、事务取消原因的顺序与强一致读上都可能
有差异——而这几轮反复出问题的恰恰是这些细节。审查方明确把"只在 moto 上验过"
标为未证实项，本脚本就是来关掉这一项的。

**只碰一次性 site_id**（`permprobe-<8hex>`），跑完删除并核对删除结果。
真实站点一个都不动。

**admins 表用临时表而不是生产表**：往生产管理员名单里插探针即便随后删掉，
中途失败就留下一个真管理员——那是安全事故，不是数据噪音。sites/routing 用真表
（守卫条件就是在它们上面求值的），admins 只用于"调用者仍是管理员"这一条
ConditionCheck，换张同构的表不影响被验的语义。

用法：
    ./verify_permission_matrix.py            # 全矩阵
    ./verify_permission_matrix.py --keep     # 失败时保留探针数据便于排查
"""
import argparse
import configparser
import os
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/deployer/functions"))

CFG_PATH = HERE.parent / "config.ini"


def read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


SUFFIX = uuid.uuid4().hex[:8]
OWNER = f"probe-owner-{SUFFIX}@example.invalid"
COLLAB = f"probe-collab-{SUFFIX}@example.invalid"
OUTSIDER = f"probe-outsider-{SUFFIX}@example.invalid"
ADMIN = f"probe-admin-{SUFFIX}@example.invalid"
NEW_OWNER = f"probe-newowner-{SUFFIX}@example.invalid"

results: list[tuple[bool, str, str]] = []
# **一项都没跑完 ≠ 通过**：曾在连接异常中断时打印"0/0 项通过"，读起来像验收成功。
# 下限必须跟上实际检查项数（当前 26，含 G/H 两节）：停在旧值 20 的话，把 G/H
# 整段误删后旧的 21 项照样 >= 20，闸门重新报绿（Codex 复审 8f8b0c6 的 P3-1）。
# `tests/test_verify_permission_matrix.py` 锁住 >= 26。
MIN_CHECKS = 26
created_sites: set[str] = set()
created_routes: set[str] = set()
TMP_ADMINS = f"site-admins-permprobe-{SUFFIX}"
TMP_OPS_LOG = f"site-ops-log-permprobe-{SUFFIX}"


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="失败时保留探针数据（默认总是清理）")
    args = ap.parse_args()

    region = read_cfg("Platform", "region")
    os.environ.setdefault("AWS_DEFAULT_REGION", region)
    os.environ["SITES_TABLE"] = read_cfg("Deployer", "sites_table")
    os.environ["ROUTING_TABLE"] = read_cfg("Platform", "routing_table")
    os.environ["ADMINS_TABLE"] = TMP_ADMINS      # 临时表，见模块 docstring
    # **OPS_LOG_TABLE 从前没设**：`ops_log.record()` 于是每次抛 KeyError，
    # 被它刻意的 `except Exception` 吞掉，而本脚本仍报 21/21 全过——也就是说
    # 它证明了条件表达式/rev/快照/TOCTOU 正确，却**没有**证明审计写入成功。
    # 真出审计回归它看不见。同样用临时表：往生产 ops-log 里插探针行即便随后
    # 删掉，中途失败就污染了审计流水。
    os.environ["OPS_LOG_TABLE"] = TMP_OPS_LOG
    os.environ["BASE_DOMAIN"] = read_cfg("Platform", "base_domain")

    import boto3
    import botocore.exceptions
    from botocore.config import Config

    # 本机到 DynamoDB 偶发 ConnectionClosedError（实测跑一次就撞上）。默认重试
    # 不覆盖这类连接层错误，而**验收脚本因网络抖动失败会被当成"守卫坏了"**去查
    # 半天。adaptive 模式带连接重试，把噪音挡在结论之外。
    #
    # 用默认 session 兜住**所有**客户端：common / permissions / register_route
    # 各自 boto3.client(...)，只配本脚本这一个 client 的话它们仍是裸默认值。
    _RETRY = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    boto3.setup_default_session(region_name=region)
    _orig_client, _orig_resource = boto3.client, boto3.resource

    def _client(*a, **kw):
        kw.setdefault("config", _RETRY)
        return _orig_client(*a, **kw)

    def _resource(*a, **kw):
        kw.setdefault("config", _RETRY)
        return _orig_resource(*a, **kw)

    boto3.client, boto3.resource = _client, _resource

    import common
    import permissions as perm

    ddb = boto3.client("dynamodb", region_name=region)
    sites_t, route_t = os.environ["SITES_TABLE"], os.environ["ROUTING_TABLE"]

    print(f"探针后缀 {SUFFIX}；sites={sites_t} routing={route_t} "
          f"admins={TMP_ADMINS}(临时) ops-log={TMP_OPS_LOG}(临时)")

    # ---- 临时 admins 表 ----
    ddb.create_table(TableName=TMP_ADMINS,
                     KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "email",
                                            "AttributeType": "S"}],
                     BillingMode="PAY_PER_REQUEST")
    ddb.get_waiter("table_exists").wait(TableName=TMP_ADMINS)

    # ---- 临时 ops-log 表 ----
    # **schema 必须与真表同构**（PK `target`、SK `ts_actor`、TTL `expires_at`），
    # 否则写入会因主键不匹配失败，而那种失败与"审计逻辑没调用"长得一样。
    ddb.create_table(TableName=TMP_OPS_LOG,
                     KeySchema=[{"AttributeName": "target", "KeyType": "HASH"},
                                {"AttributeName": "ts_actor", "KeyType": "RANGE"}],
                     AttributeDefinitions=[
                         {"AttributeName": "target", "AttributeType": "S"},
                         {"AttributeName": "ts_actor", "AttributeType": "S"}],
                     BillingMode="PAY_PER_REQUEST")
    ddb.get_waiter("table_exists").wait(TableName=TMP_OPS_LOG)
    try:
        ddb.update_time_to_live(
            TableName=TMP_OPS_LOG,
            TimeToLiveSpecification={"Enabled": True,
                                     "AttributeName": "expires_at"})
    except Exception as exc:            # noqa: BLE001 TTL 不是被验语义，失败只记一声
        print(f"  （临时 ops-log 表未开 TTL：{exc}——不影响本轮断言）")

    def sid(tag: str) -> str:
        s = f"permprobe{tag}-{SUFFIX}"
        created_sites.add(s)
        return s

    def put_site(site_id: str, **attrs) -> None:
        common.upsert_site(site_id, **attrs)

    def put_route(site_id: str, owner: str) -> None:
        sub = common.subdomain_for(site_id)
        created_routes.add(sub)
        ddb.put_item(TableName=route_t, Item={
            "subdomain": {"S": sub}, "site_id": {"S": site_id},
            "route_mode": {"S": "split"}, "static_prefix": {"S": ""},
            "api_target": {"S": ""}, "require_auth": {"BOOL": True},
            "allowed_users": {"S": "org"}, "collaborators": {"L": []},
            "owner": {"S": owner}, "permissions_rev": {"N": "1"}})

    # 事务的"载荷"写到一个**独立的哨兵行**上，不碰被测站点。
    # DynamoDB 禁止"同一事务对同一 item 多次操作"（会抛 ValidationException 而非
    # 条件失败），所以载荷不能落在被测的那个 site_id 上——否则守卫的
    # ConditionCheck 与载荷 Update 撞在一行，整个事务连求值都到不了。
    SENTINEL = f"permprobe-sentinel-{SUFFIX}"
    created_sites.add(SENTINEL)

    def guard_admits(site_id: str, *, actor: str, action: str, role: str,
                     rev: int, had_rev: bool) -> bool:
        """把守卫单独放进一个事务里求值——真实 DynamoDB 说了算。

        配一个落在哨兵行上的 Update 作为载荷：事务合法、不改被测站点的任何字段，
        于是"守卫是否放行"是唯一被测的东西。
        """
        items = [perm.sites_snapshot_guard(site_id, rev=rev, had_rev=had_rev,
                                           actor=actor, action=action, role=role),
                 {"Update": {"TableName": sites_t,
                             "Key": {"site_id": {"S": SENTINEL}},
                             "UpdateExpression": "SET probe_touch = :v",
                             "ExpressionAttributeValues": {":v": {"N": "1"}}}}]
        if role == perm.ROLE_ADMIN:
            items.append({"ConditionCheck": {
                "TableName": TMP_ADMINS, "Key": {"email": {"S": actor}},
                "ConditionExpression": "attribute_exists(email)"}})
        try:
            ddb.transact_write_items(TransactItems=items)
            return True
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise

    # ================= A. had_rev=True =================
    print("\n── A 有 rev：只接受精确相等 ──────────────────────")
    a = sid("a")
    put_site(a, owner=OWNER, name="probe", status="ACTIVE",
             require_login=True, allowed_users="org", collaborators=[],
             permissions_rev=7)
    check(guard_admits(a, actor=OWNER, action="deploy", role=perm.ROLE_OWNER,
                       rev=7, had_rev=True),
          "rev 未变 → 放行")
    check(not guard_admits(a, actor=OWNER, action="deploy",
                           role=perm.ROLE_OWNER, rev=6, had_rev=True),
          "rev 已被推进 → 拒绝")
    # 删除后用同 site_id 重建且无 rev：had_rev=True 的快照必须被拒
    ddb.delete_item(TableName=sites_t, Key={"site_id": {"S": a}})
    put_site(a, owner=NEW_OWNER, name="probe", status="ACTIVE")
    check(not guard_admits(a, actor=OWNER, action="deploy",
                           role=perm.ROLE_OWNER, rev=7, had_rev=True),
          "删除后同 id 重建（无 rev）→ 旧 owner 被拒",
          "这条曾是 P1：attribute_not_exists 兼容分支会放行")

    # ================= B. had_rev=False（存量）=================
    print("\n── B 无 rev（一期存量）：按 CAPABILITIES 的角色事实 ──")
    b = sid("b")
    put_site(b, owner=OWNER, name="probe", status="ACTIVE",
             require_login=True, allowed_users="org", collaborators=[COLLAB])
    matrix = [
        (OWNER, "deploy", perm.ROLE_OWNER, True, "owner deploy"),
        (OWNER, "undeploy", perm.ROLE_OWNER, True, "owner undeploy"),
        (COLLAB, "deploy", perm.ROLE_COLLABORATOR, True, "collaborator deploy"),
        (COLLAB, "set_access_policy", perm.ROLE_COLLABORATOR, True,
         "collaborator 改访问策略"),
        (COLLAB, "undeploy", perm.ROLE_COLLABORATOR, False,
         "collaborator undeploy → 必须拒（CAPABILITIES 不给）"),
        (COLLAB, "manage_collaborators", perm.ROLE_COLLABORATOR, False,
         "collaborator 管协作者 → 必须拒"),
        (COLLAB, "transfer_owner", perm.ROLE_COLLABORATOR, False,
         "collaborator 转移所有权 → 必须拒"),
        (OUTSIDER, "deploy", perm.ROLE_NONE, False, "外人 deploy → 必须拒"),
    ]
    for actor, action, role, want, label in matrix:
        got = guard_admits(b, actor=actor, action=action, role=role,
                           rev=0, had_rev=False)
        check(got is want, label, f"实际{'放行' if got else '拒绝'}")

    # ================= C. 转移所有权后的降级 =================
    print("\n── C 鉴权后 transfer_owner：旧 owner 降级为 collaborator ──")
    c = sid("c")
    put_site(c, owner=OWNER, name="probe", status="ACTIVE",
             require_login=True, allowed_users="org", collaborators=[])
    put_route(c, OWNER)
    perm.transfer_owner(c, actor=OWNER, new_owner=NEW_OWNER)
    site_after = common.get_site_consistent(c) or {}
    check(site_after.get("owner") == NEW_OWNER
          and OWNER in (site_after.get("collaborators") or []),
          "transfer_owner 把旧 owner 降级为 collaborator",
          f"owner={site_after.get('owner')}")
    check(not perm.can(perm.role_of(OWNER, site_after), "undeploy"),
          "降级后的旧 owner 依 CAPABILITIES 无 undeploy 权")
    # 关键：用**降级前**的无-rev 快照去 undeploy，必须被拒
    check(not guard_admits(c, actor=OWNER, action="undeploy",
                           role=perm.ROLE_OWNER, rev=0, had_rev=False),
          "旧 owner 拿降级前快照 undeploy → 拒绝",
          "这条曾是 P1：合并 owner/collaborator 会放行，可 purge 新 owner 数据")

    # ================= D. admin 代管 =================
    print("\n── D admin 代管：名单时效性进同一事务 ──────────────")
    d = sid("d")
    put_site(d, owner=OWNER, name="probe", status="ACTIVE",
             require_login=True, allowed_users="org", collaborators=[])
    perm.add_admin(ADMIN, added_by="permprobe")
    check(guard_admits(d, actor=ADMIN, action="undeploy",
                       role=perm.ROLE_ADMIN, rev=0, had_rev=False),
          "在册 admin → 放行")
    # 直接删（remove_admin 会拦"最后一个管理员"，这里是临时表、语义无关）
    ddb.delete_item(TableName=TMP_ADMINS, Key={"email": {"S": ADMIN}})
    check(not guard_admits(d, actor=ADMIN, action="undeploy",
                           role=perm.ROLE_ADMIN, rev=0, had_rev=False),
          "已被移出名单的 admin → 拒绝")

    # ================= E. 稀疏存量行自愈 =================
    print("\n── E 稀疏存量行（有 auth 字段、缺 rev）自愈但不扩权 ──")
    e = sid("e")
    put_site(e, owner=OWNER, name="probe", status="ACTIVE",
             require_login=True, allowed_users="org")   # 无 rev、无 collaborators
    check("permissions_rev" not in (common.get_site_consistent(e) or {}),
          "前置：该行确实没有 permissions_rev")
    perm.set_access_policy(e, actor=OWNER, require_login=False)
    healed = common.get_site_consistent(e) or {}
    check(int(healed.get("permissions_rev", 0)) >= 1,
          "首次在线写入补上 rev（否则这批站点会被守卫永久卡死）",
          f"rev={healed.get('permissions_rev')}")
    try:
        perm.set_access_policy(e, actor=OUTSIDER, require_login=True)
        check(False, "自愈路径不得放宽鉴权：外人应被拒")
    except perm.PermissionDenied:
        check(True, "自愈后外人仍被拒")

    # ================= F. register_route 的 seed 不得凭空建行 =================
    print("\n── F seed 不得凭空创建 sites 行（守卫后门）──────────")
    import register_route
    f = f"permprobef-{SUFFIX}"          # 故意**不**建 sites 行
    created_sites.add(f)
    os.environ.setdefault("JOBS_TABLE", read_cfg("Deployer", "jobs_table"))
    job_id = common.create_job(f"stale-{SUFFIX}@example.invalid", f)
    try:
        register_route.handler(
            {"job_id": job_id, "site_id": f, "api_target": "",
             "manifest": {"auth": {"require_login": False,
                                   "allowed_users": "org"}}}, None)
        check(False, "sites 行不存在时 seed 竟然成功了")
    except RuntimeError as exc:
        check("不存在" in str(exc), "sites 行不存在 → 拒绝写路由",
              str(exc)[:40])
    check(common.get_site_consistent(f) is None,
          "seed 没有凭空创建 sites 行",
          "这条曾是 P1：update_item 会创建缺失的 item")
    created_routes.add(common.subdomain_for(f))
    # 清掉探针 job
    try:
        boto3.resource("dynamodb", region_name=region).Table(
            os.environ["JOBS_TABLE"]).delete_item(Key={"job_id": job_id})
    except Exception as exc:            # noqa: BLE001 清理尽力而为
        print(f"  ⚠️  探针 job {job_id} 未删除: {exc}")

    print("\n── G 坏数据行拒绝投影（M02），并留下审计 ───────────")
    # 这条路径此前**没有任何真机验证**：`effective_policy_audited` 只在
    # `PolicyDataInvalid` 时落 `reject_policy_projection`，而 A–F 的场景都用的是
    # 类型正确的行。用 `resync_route`（admin-only，docstring 明写"真源坏了它就拒绝"）
    # 作为触发点：它不改 sites 表、不推进 rev，副作用最小。
    g = sid("g")
    # require_login 写成数字 —— 正是 M02 要拒的"坏类型"形态（moto 侧的同类用例用
    # Decimal(0)；这里直接写 0，DynamoDB 存成 N）
    put_site(g, owner=OWNER, name="probe", status="ACTIVE",
             require_login=0, allowed_users="org", collaborators=[])
    perm.add_admin(ADMIN, added_by="permprobe")     # D 节把它删了，这里重新加回
    try:
        perm.resync_route(g, actor=ADMIN)
        check(False, "坏类型的 require_login 竟然被投影了",
              "M02 的核心不变量失效")
    except perm.PolicyDataInvalid as exc:
        check(True, "坏类型的 require_login → 拒绝投影", str(exc)[:60])
    except Exception as exc:                        # noqa: BLE001
        check(False, "拒绝投影时抛的不是 PolicyDataInvalid",
              f"{type(exc).__name__}: {str(exc)[:50]}")

    print("\n── H 审计写入真的落库了 ────────────────────────────")
    # 为什么这一节非有不可：`ops_log.record()` 刻意吞掉一切异常
    # （"业务动作已经成功，审计失败不能改变它的结果"），所以**审计完全写不进去**时
    # 上面 A–F 全部照样 PASS。本脚本从前就是这样：没设 `OPS_LOG_TABLE`，每次
    # `KeyError` 被吞，21/21 全过。断言"有没有落库"是唯一能关掉这个证据缺口的方式。
    #
    # 三类分别对应三条不同的代码路径，缺任一条都说明那条路径的审计没接上：
    #   ok       —— 成功的权限写入
    #   denied   —— 鉴权失败被拒
    #   rejected —— 坏数据行拒绝投影（reject_policy_projection）
    rows = ddb.scan(TableName=TMP_OPS_LOG)["Items"]
    by_action: dict[str, set] = {}
    for it in rows:
        by_action.setdefault(it.get("action", {}).get("S", "?"), set()).add(
            it.get("result", {}).get("S", "?"))
    check(bool(rows), "临时 ops-log 表里有审计行",
          f"{len(rows)} 行，actions={sorted(by_action)}")
    check(any("ok" in v for v in by_action.values()),
          "成功的权限写入留下了 result=ok 的审计行", str(by_action)[:90])
    check(any("denied" in v for v in by_action.values()),
          "被拒的操作留下了 result=denied 的审计行", str(by_action)[:90])
    # 断言到 result 一级，不止 action 键存在：G 节真拒了投影时 result 必须是
    # rejected——只查键存在的话，一条 result 写错的行也能让闸门绿。
    check("rejected" in by_action.get("reject_policy_projection", set()),
          "坏数据行拒绝投影留下了 result=rejected 的审计行",
          str(sorted(by_action))[:90])

    return 0


def cleanup(region: str, keep: bool) -> int:
    """删除全部探针数据并**核对删除结果**（只报"已删"不算，要读回确认）。"""
    import boto3
    leftover = 0
    ddb = boto3.client("dynamodb", region_name=region)
    print("\n── 清理 ──────────────────────────────────────────")
    if keep:
        print(f"  --keep：保留探针数据（后缀 {SUFFIX}），请手工清理")
        return 0
    for s in sorted(created_sites):
        try:
            ddb.delete_item(TableName=os.environ["SITES_TABLE"],
                            Key={"site_id": {"S": s}})
        except Exception as exc:        # noqa: BLE001
            print(f"  ⚠️  删除 sites 表的 {s} 失败: {exc}")
    for sub in sorted(created_routes):
        try:
            ddb.delete_item(TableName=os.environ["ROUTING_TABLE"],
                            Key={"subdomain": {"S": sub}})
        except Exception as exc:        # noqa: BLE001
            print(f"  ⚠️  删除 routing/{sub} 失败: {exc}")
    # 读回核对：只有显式确认不存在才算删掉（"调用没报错"证明不了）
    for s in sorted(created_sites):
        got = ddb.get_item(TableName=os.environ["SITES_TABLE"],
                           Key={"site_id": {"S": s}}, ConsistentRead=True)
        if "Item" in got:
            print(f"  ⚠️  sites 表的 {s} 仍存在 —— 手工删除")
            leftover += 1
    for sub in sorted(created_routes):
        got = ddb.get_item(TableName=os.environ["ROUTING_TABLE"],
                           Key={"subdomain": {"S": sub}}, ConsistentRead=True)
        if "Item" in got:
            print(f"  ⚠️  routing/{sub} 仍存在 —— 手工删除")
            leftover += 1
    for tmp in (TMP_ADMINS, TMP_OPS_LOG):
        try:
            ddb.delete_table(TableName=tmp)
            ddb.get_waiter("table_not_exists").wait(TableName=tmp)
        except Exception as exc:        # noqa: BLE001
            print(f"  ⚠️  临时表 {tmp} 未删除: {exc} —— 手工删除")
            leftover += 1
    print("  探针数据已清理并核对" if not leftover
          else f"  {leftover} 项残留，见上面的 ⚠️")
    return leftover


if __name__ == "__main__":
    _keep = "--keep" in sys.argv
    _region = read_cfg("Platform", "region")
    rc = 1
    try:
        rc = main()
    except Exception:                   # noqa: BLE001 保证走到 cleanup
        import traceback
        traceback.print_exc()
        rc = 1
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        left = cleanup(_region, _keep and failed > 0)
        print()
        # 下限常量在模块顶部（单测锁住 >= 26）——少于预期项数一律不可信。
        if len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）—— "
                  "验收**未完成**，状态不可信，不要当成通过")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else "")
                  + (f"，{left} 项数据残留" if left else ""))
            if failed or left:
                rc = 1
    sys.exit(rc)
