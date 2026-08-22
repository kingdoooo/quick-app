"""deployer 各步骤 Lambda 的公共层：配置、jobs/sites 表访问、ID 生成。"""
import os
import re
import secrets
import string
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

_ddb = None


def _table(name_env: str):
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_DEFAULT_REGION",
                                                                     "us-east-1"))
    return _ddb.Table(os.environ[name_env])


def get_config() -> dict:
    keys = ["JOBS_TABLE", "SITES_TABLE", "ARTIFACTS_BUCKET", "FRONTEND_BUCKET",
            "ROUTING_TABLE", "BASE_DOMAIN", "RUNTIME_BOUNDARY_ARN", "PACKAGE_PROJECT",
            "DSQL_ENDPOINT"]
    return {k.lower(): os.environ[k] for k in keys}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# jobs 表的 owner 字段是**发起者**（requested_by 语义）：谁按下了这次部署。
# 它不参与任何授权判定——授权一律走 permissions.py 对 sites 表的角色判定。
# 保留 owner 这个字段名是为了兼容存量数据与 owner-index GSI。
def new_job_id() -> str:
    """生成 job_id。独立出来是因为**有的调用方要在建 job 之前就拿到它**：
    undeploy 把"拿部署租约（holder = 本 job）"与建 job 绑成同一笔事务，
    而租约条目里要写的就是这个还没落库的 job_id。"""
    return "job-" + secrets.token_hex(8)


def create_job(owner: str, site_id: str, guard_items: list | None = None,
               *, job_id: str | None = None, status: str = "PENDING",
               kind: str | None = None) -> str:
    """建任务记录。

    guard_items: 可选的 TransactItems 条目（ConditionCheck 等）。给了就走事务，
    把"建任务"与这些条件绑成一次提交。MCP 的 undeploy 用它把"鉴权时的权限快照
    仍然有效"绑进来——鉴权与副作用之间的撤权窗口否则会让旧请求照样落地
    （见 mcp/server.py 的 _rev_condition_check）。
    条目形态用低层 client 的 AttributeValue 写法，所以这条路径**不能**走
    resource.Table：两套 API 的 item 形态不同，混用会 ValidationException。

    `status` / `kind`：undeploy 的 job 要以 **RUNNING + kind="undeploy"** 落库，
    两个字段各堵一个实测过的洞：
      · 部署租约判"持有者还在跑吗"看的是 RUNNING——建成 PENDING 的话，从建 job
        到 undeploy Lambda 自己把状态改成 RUNNING 之间有一个窗口，窗口里租约形同
        虚设（PENDING 持有者会被当成陈旧顶掉）；
      · kind 原先由 undeploy Lambda 运行时才写。异步 invoke 的事件被丢弃时
        （重试耗尽进 DLQ）Lambda 根本没跑，job 就没有 kind ⇒ sweeper 把它当
        deploy 去 DescribeExecution ⇒ 永远 orphan。建库时就写上，sweeper 的
        20 分钟 undeploy 阈值才管得到它。
    """
    job_id = job_id or new_job_id()
    now = _now()
    item = {"job_id": job_id, "site_id": site_id, "owner": owner,
            "status": status, "phase": "submitted", "error": "", "url": "",
            "created_at": now, "updated_at": now}
    if kind:
        item["kind"] = kind
    if not guard_items:
        _table("JOBS_TABLE").put_item(Item=item)
        return job_id
    boto3.client("dynamodb",
                 region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
                 ).transact_write_items(TransactItems=[
                     {"Put": {"TableName": os.environ["JOBS_TABLE"],
                              "Item": {k: {"S": v} for k, v in item.items()}}},
                     *guard_items])
    return job_id


def update_job(job_id: str, *, status=None, phase=None, error=None, url=None,
               kind=None) -> None:
    """更新 job 字段。

    `kind`（"deploy"/"undeploy"）：收敛逻辑要按类型分流——deploy 的 job 有
    SFN execution 可以 DescribeExecution 核对，undeploy 是独立异步 Lambda
    没有 execution。缺这个字段时 sweeper 只能把后者当孤儿放着（Codex 审查
    2026-08-10 P1-4）。
    """
    updates, values = ["updated_at = :t"], {":t": _now()}
    names = {}
    for field, val in (("status", status), ("phase", phase), ("error", error),
                       ("url", url), ("kind", kind)):
        if val is not None:
            names[f"#{field}"] = field
            updates.append(f"#{field} = :{field}")
            values[f":{field}"] = val
    kwargs = dict(Key={"job_id": job_id},
                  UpdateExpression="SET " + ", ".join(updates),
                  ExpressionAttributeValues=values)
    if names:
        kwargs["ExpressionAttributeNames"] = names
    _table("JOBS_TABLE").update_item(**kwargs)


def get_job(job_id: str, *, consistent: bool = False) -> dict | None:
    """读任务记录。

    `consistent=True` 走强一致读——只在"这条记录是刚刚写的、读到旧副本会造成硬失败"
    时才需要（`validate` 读 `upload_etag` 是唯一这样的调用方，见那里的注释）。
    **默认仍是最终一致**：其余调用方读的都是早已写定的字段，让它们一起翻倍成本没有
    收益。
    """
    kwargs = {"Key": {"job_id": job_id}}
    if consistent:
        kwargs["ConsistentRead"] = True
    return _table("JOBS_TABLE").get_item(**kwargs).get("Item")


def list_jobs_by_owner(owner: str) -> list[dict]:
    resp = _table("JOBS_TABLE").query(
        IndexName="owner-index",
        KeyConditionExpression=Key("owner").eq(owner))
    return resp.get("Items", [])


def list_jobs_by_site(site_id: str, limit: int = 50) -> list[dict]:
    """某站点的部署历史，**最新在前**（控制台"部署历史"标签页）。

    用 site-index 而非 owner-index：后者是**发起者**维度
    （jobs.owner = requested_by），协作者发起的部署 owner 是协作者，
    按 owner 查不出"这个站点的所有部署"。
    """
    resp = _table("JOBS_TABLE").query(
        IndexName="site-index",
        KeyConditionExpression=Key("site_id").eq(site_id),
        ScanIndexForward=False,    # created_at 倒序
        Limit=limit,
        # 只取控制台展示要用的字段：job 行上如今挂着 route_commit（两份内嵌的
        # 完整路由 item，与提交同一笔事务落库的补偿状态），不投影的话每页历史
        # 白拉 50×2 条路由 item——控制台不需要也不该拿到它们。
        # #s/#e/#u：status / error / url 里有 DynamoDB 保留字，统一走别名。
        # owner = requested_by（控制台"由谁发起"列）。
        ProjectionExpression=("job_id, #s, phase, #e, #u, #o, "
                              "created_at, updated_at"),
        ExpressionAttributeNames={"#s": "status", "#e": "error", "#u": "url",
                                  "#o": "owner"})
    return resp.get("Items", [])


def upsert_site(site_id: str, **attrs) -> None:
    if not attrs:
        return
    names = {f"#{k}": k for k in attrs}
    _table("SITES_TABLE").update_item(
        Key={"site_id": site_id},
        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in attrs),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={f":{k}": v for k, v in attrs.items()})


class SiteIdCollision(Exception):
    """site_id 已被占用。建站路径捕获它并重新生成 ID。"""


def create_site_record(site_id: str, *, owner: str, name: str,
                       status: str = "DEPLOYING") -> None:
    """**首次**建站：单次条件 UpdateItem 写整条记录，已存在即抛 SiteIdCollision。

    条件必须是 `attribute_not_exists(site_id)` 且**一次写完整条**——不能拆成
    "条件写 created_at + 无条件 upsert_site(owner/name/…)"两步：第一步条件
    失败被吞后，第二步会把**已有站点**的 owner/name/status 覆盖成本次调用者，
    随机 ID 碰撞就变成误接管（Codex review 2026-08-09 P1，moto 已复现；
    一期的 upsert_site 建站路径本就有此行为，本函数一并修掉）。

    **用 UpdateItem 而非 PutItem**（Codex 复审第二轮 P1）：MCP runtime 的
    IAM 对 sites 表**故意不给 PutItem**（挡"整条覆盖改站点归属"，
    `test_sites_table_has_no_putitem` 全表扫描锁定这一点），只有带属性白名单
    的 UpdateItem。UpdateItem + attribute_not_exists(site_id) 条件在语义上
    等价于条件 PutItem：item 不存在 → 条件通过并创建；已存在 → 条件失败，
    **原子性相同**。用 PutItem 会本地 moto 全绿、部署后真实 IAM 全部拒绝。
    代价：本函数写的字段必须在 deploy_agentcore.py 的
    SITE_WRITABLE_ATTRIBUTES 白名单内（created_at 需新增）。

    created_at 只在建站这一刻写；碰撞由调用方重新生成 ID 重试，
    **绝不对已有行继续写**。
    """
    import botocore.exceptions
    try:
        _table("SITES_TABLE").update_item(
            Key={"site_id": site_id},
            UpdateExpression="SET #o = :o, #n = :n, #s = :s, created_at = :t",
            ConditionExpression="attribute_not_exists(site_id)",
            ExpressionAttributeNames={"#o": "owner", "#n": "name",
                                      "#s": "status"},
            ExpressionAttributeValues={":o": owner, ":n": name,
                                       ":s": status, ":t": _now()})
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise SiteIdCollision(site_id) from e
        raise


def get_site(site_id: str) -> dict | None:
    return _table("SITES_TABLE").get_item(Key={"site_id": site_id}).get("Item")


def get_site_consistent(site_id: str) -> dict | None:
    """强一致读。授权判定与 read-modify-write 用它：最终一致读会放大
    "权限刚被撤销但旧请求仍读到旧名单"的窗口。"""
    return _table("SITES_TABLE").get_item(
        Key={"site_id": site_id}, ConsistentRead=True).get("Item")


def _paginate(method, **kwargs) -> list[dict]:
    """DynamoDB query/scan 分页汇总。

    单次 query/scan 最多返回 1MB，**超出会静默截断**——不翻页就会出现
    "站点列表少了几个"、"管理员名单看起来只剩一个"这类难查的问题。
    """
    items, start_key = [], None
    while True:
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = method(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            return items


def list_sites_by_owner(owner: str) -> list[dict]:
    table = _table("SITES_TABLE")
    return _paginate(table.query, IndexName="owner-index",
                     KeyConditionExpression=Key("owner").eq(owner))


def list_sites_for_user(email: str) -> list[dict]:
    """我 owner 的 ∪ 我是 collaborator 的站点，按 site_id 去重。

    collaborator 维度没有索引（DynamoDB 不能对 List 建 GSI），用 Scan +
    contains 过滤。站点规模到数百时改为维护反向索引表。
    """
    from boto3.dynamodb.conditions import Attr
    table = _table("SITES_TABLE")
    items = {s["site_id"]: s for s in list_sites_by_owner(email)}
    for s in _paginate(table.scan,
                       FilterExpression=Attr("collaborators").contains(email)):
        items.setdefault(s["site_id"], s)
    return list(items.values())


class InvalidSiteName(ValueError):
    pass


# 与 contract.schema.NAME_RE 一致：site_name 会成为 DSQL schema/PG role 名、
# Lambda 函数名、IAM 角色名、S3 前缀与子域名，必须在入口就收窄字符集。
SITE_NAME_RE = re.compile(r"[a-z][a-z0-9-]{1,29}")

# 平台自己的 Lambda 也叫 site-*（site-panel / site-auth-service / site-deployer-* …），
# 与用户站点函数 site-{site_id} 共用一个命名空间。留出这些词，`site-{平台名}*`
# 这类通配才可判定——否则站点名 `auth-tool` 会产出 site-auth-tool-x1y2z3，
# 被 `site-auth-*` 命中，进而被平台自己的 IAM Deny/SCP 误伤（M7-SPEC §2.1）。
# `rt` 同理但方向相反：per-site 角色叫 site-rt-{site_id}（`site_role_name`），IAM 里
# 已有 role/site-rt-* 通配，而站点名 `rt` 会产出**函数** site-rt-x1y2z3——同一个词在
# 两种资源类型上指不同的东西。目前没有策略通配 function:site-rt-*，所以这是**潜在**
# 危险而非现存缺陷；留出它是为了让"site-rt-* 指什么"始终只有一个答案。
# 与 `runtime` 不互相包含（判定是"整词或 词- 起头"），两个都要留。
RESERVED_SITE_NAME_PREFIXES = ("panel", "auth", "key-proxy", "access",
                               "deployer", "runtime", "rt")


def validate_site_name(name: str) -> str:
    """校验站点名。放行非法字符会导致 DSQL DDL 注入与 IAM/Lambda 命名失败。"""
    if not isinstance(name, str) or not SITE_NAME_RE.fullmatch(name):
        raise InvalidSiteName(
            "站点名必须以小写字母开头，仅含小写字母、数字与连字符，长度 2-30")
    for p in RESERVED_SITE_NAME_PREFIXES:
        if name == p or name.startswith(p + "-"):
            raise InvalidSiteName(
                f"站点名不能是保留词 {p!r} 或以 {p + '-'!r} 开头"
                "（与平台自身的 Lambda 命名空间冲突）")
    return name


def new_site_id(name: str) -> str:
    validate_site_name(name)
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{name[:20].rstrip('-')}-{suffix}"


def subdomain_for(site_id: str) -> str:
    return f"app-{site_id}"


# **这里故意没有"终态集合"常量**（独立评审 2026-08-18 Important-3 删掉了它）：
# 曾有一个 TERMINAL_JOB_STATUSES，注释声称部署租约按它判"持有者还活着吗"——
# 那是假的。租约判的是 `status == "RUNNING"`（见 plan_deploy_lease，那里解释了
# 为什么终态集合在租约上是**错误**判据：PENDING 既非终态也不该算忙）。留着一个
# 带错误因果链的常量，将来有人"统一"过去就会复活永久锁死的洞。
# 终态词表如今只有一个读者（reconcile_job 的注释与用例），定义在那边。


# ── per-site 部署租约（M7 加固，Codex 2026-08-17 P1-3）──────────────────────
# 目的：同一站点同时只允许一次部署 execution。不加这道闸门时两次部署会**算出同一个
# 空闲色**，各自把那个 alias 指向自己的版本、各自过健康门，最后线上可能变成
# "前端来自 A、后端来自 B"——M7 的"前后端在同一个提交点切换"这条不变量被破坏，
# 而两个 job 都不会触发补偿（一个成功、一个在提交点之前就失败）。
#
# **租约没有释放路径，这是刻意的设计**：判据是**推导**出来的——
#   「本站点忙 ⟺ 租约持有者那条 job 的 status == RUNNING」
# （**不是**"还不是终态"——那是被废弃的旧因果链，PENDING 既非终态也不该算忙，
# 按它判会把 start 失败回滚后的站点永久锁死；正确判据的完整论证见
# plan_deploy_lease。undeploy 结束后对租约行的条件删除是垃圾清理，不是释放。）
# 于是"忘了释放"这个失败模式不存在。若改成显式释放，就必须由 mark_job /
# reconcile_job / undeploy 三处共同维护同一个不变量，那正是本仓库反复踩过的
# "同一不变量被手抄多份"（见 CLAUDE.md 与历次审查）。
#
# 卡死的兜底同样是推导来的：持有者若被杀而没写终态，它会停在 RUNNING，此时
# `reconcile_job` 的两层收敛（EventBridge 实时 + sweeper ≤45 分钟）把它推成
# FAILED，租约随即可被抢。**不设 TTL**：TTL 是第二个真源，会与 job 状态漂移。
#
# 租约行**故意不带** site_id / owner / status / created_at：
#   · 带 site_id 或 owner 就会进 jobs 表的两个 GSI（稀疏索引），污染控制台的
#     "部署历史"（那是 site-index 的 Query）与 list_jobs_by_owner；
#   · 带 status 就会被 sweeper 的 `#s = :running` 过滤器捞到，被当成一条卡住的 job。

def deploy_lease_key(site_id: str) -> str:
    """租约行在 jobs 表里的主键。

    **放 jobs 表而不是 sites 表**：MCP runtime 对 sites 表的 `UpdateItem` 受
    `dynamodb:Attributes` 白名单约束（那道白名单正是为了挡住它改 permissions_rev /
    owner）。把租约写进 sites 行就得把 sites 的条件事务项从 ConditionCheck 改成
    Update，于是条件里引用的 `permissions_rev` / `owner` 也要进白名单——等于为了一个
    可用性闸门去拆一道权限闸门。jobs 表上 MCP 本来就有无属性限制的 UpdateItem。
    """
    return f"site-lease#{site_id}"


def read_deploy_lease(site_id: str) -> str | None:
    """当前持有本站点部署租约的 job_id（无人持有则 None）。

    **强一致读**：这是"要不要放行这次部署"的控制点，读到旧副本会放行第二次并发部署
    ——正是本闸门要挡的那件事。
    """
    item = boto3.client("dynamodb", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).get_item(
        TableName=os.environ["JOBS_TABLE"],
        Key={"job_id": {"S": deploy_lease_key(site_id)}},
        ConsistentRead=True).get("Item") or {}
    return item.get("holder_job_id", {}).get("S") or None


def deploy_lease_acquire_item(site_id: str, job_id: str,
                              *, stale_holder: str | None = None) -> dict:
    """拿租约的 TransactItems `Update` 条目（也可单独拿来发一次 update_item）。

    `stale_holder`：调用方**已经确认过**其 job 处于终态（或不存在）的那个持有者。
    只有它被允许被顶掉，所以条件里写的是具体 job_id 而不是任何宽松形态——
    "无人持有 **或** 持有者是我刚看到的那个陈旧持有者"。

    这一步把 check-then-act 收成一次条件写：两个请求同时读到"空闲"时，
    DynamoDB 只会让其中一个的条件成立，另一个被取消 ⇒ 调用方报"该站点正在部署"。
    """
    expr = "attribute_not_exists(holder_job_id)"
    values = {":h": {"S": job_id}, ":t": {"S": _now()}}
    if stale_holder:
        expr += " OR holder_job_id = :stale"
        values[":stale"] = {"S": stale_holder}
    return {"Update": {
        "TableName": os.environ["JOBS_TABLE"],
        "Key": {"job_id": {"S": deploy_lease_key(site_id)}},
        "UpdateExpression": "SET holder_job_id = :h, acquired_at = :t",
        "ConditionExpression": expr,
        "ExpressionAttributeValues": values}}


class DeployInProgress(Exception):
    """该站点已有一次部署在跑。调用方转成对用户可读的拒绝。"""


def plan_deploy_lease(site_id: str, job_id: str) -> list:
    """读一次租约、判定能不能拿，返回可直接放进事务的 TransactItems **列表**
    （租约 `Update`，顶替陈旧持有者时再多一条对持有者 job 的 `ConditionCheck`）。

    **判据是"持有者的 job 还是 RUNNING 吗"，而不是"是不是还没到终态"。**
    只有 RUNNING 才可能有一条活着的 execution：租约与 `status = RUNNING` 是
    **同一笔事务**写下的（confirm_upload / undeploy 的 create_job）。

    这个方向的选择不是措辞问题，它修掉一个会把站点**永久锁死**的洞：
    `start_execution` 失败时 `_rollback_job_to_pending` 会把 job 退回 PENDING
    （好让用户重试），而 PENDING 既不是终态、也不会被 reconcile 的 sweeper 收敛
    （它只扫 RUNNING）。判据若写成"非终态即忙"，这个 job 就会永远持有租约 ⇒
    该站点再也无法部署。按 RUNNING 判则自动放行，且**仍然不需要任何释放路径**。

    **"我读到的状态"必须进最终事务，读一下是不够的**（Codex 2026-08-18 P1-1，
    实测复现）：本函数读到持有者 H 是 PENDING、判它陈旧，但调用方拿着这份计划去
    提交之间，H 可以重试成功（它自己的事务：`#s = :pending → RUNNING` + 续上
    `holder_job_id = H` 的租约）。此刻租约行仍写着 H，于是只按
    `holder_job_id = :stale` 判的顶替照样成立——从一个**已经 RUNNING** 的持有者
    手里把租约抢走，两次部署并行。所以顶替**别人**时多附一条对 H 的
    ConditionCheck：`attribute_not_exists(job_id) OR #s <> :running`，
    与租约切换同一笔提交。两笔事务都写租约行 ⇒ DynamoDB 把它们串行化：
    H 先提交则本方的 ConditionCheck 失败，本方先提交则 H 的租约条件失败，
    恰好一个赢。

    "状态说没跑、实际在跑"的那类窗口已被入口侧关掉（Codex 2026-08-18 R4 P1-2）：
    `start_execution` / 异步 invoke 只在**服务端确定拒绝**（ClientError）时才回滚
    PENDING / 写 FAILED；网络错误等**结果不确定**的失败一律保持 RUNNING（租约
    继续挡新部署），由 sweeper 按确定性 execution name 查证后收敛——
    ExecutionDoesNotExist 是"start 从未发生"的权威证词（name == job_id，记录保留
    90 天），所以那条收敛不是猜。于是 PENDING 持有者恒无活执行，顶替是安全的。

    持有者仍在 RUNNING ⇒ 抛 `DeployInProgress`（**早失败、零副作用**：此刻还没启动
    execution，也没动过任何站点资源）。

    持有者就是我自己 ⇒ 允许，且**不加** ConditionCheck——同一笔事务里本来就有
    对自己 job 的写（confirm_upload 的 `#s = :pending`），DynamoDB 不允许同一个
    item 在一笔事务里出现两次。
    """
    holder = read_deploy_lease(site_id)
    stale = None
    if holder and holder != job_id:
        held = get_job(holder, consistent=True)
        status = (held or {}).get("status")
        if status == "RUNNING":
            raise DeployInProgress(
                f"站点 {site_id} 已有一次部署/下线正在进行（任务 {holder}）。"
                "请等它结束后再操作；若它已经卡住，系统会在最多 45 分钟内自动"
                "收敛，届时可重试。")
        # 持有者已终态 / 退回了 PENDING / job 记录根本不存在 ⇒ 租约陈旧，可顶掉。
        stale = holder
    elif holder == job_id:
        stale = holder
    items = [deploy_lease_acquire_item(site_id, job_id, stale_holder=stale)]
    if stale and stale != job_id:
        items.append({"ConditionCheck": {
            "TableName": os.environ["JOBS_TABLE"],
            "Key": {"job_id": {"S": stale}},
            "ConditionExpression": ("attribute_not_exists(job_id) OR "
                                    "#s <> :running"),
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":running": {"S": "RUNNING"}}}})
    return items


def clear_deploy_lease(site_id: str, holder_job_id: str) -> None:
    """删掉租约行——**带条件：持有者还是我**。只在站点被彻底下线时调用
    （undeploy），那之后这个 site_id 的租约行只是一条垃圾。

    条件不可省（Codex 2026-08-18 P1-2）：无条件删除会把**别人**正持有的租约
    顺手清掉——一次晚到的 undeploy 重试、或一条与部署交错的下线，都能借此放进
    第三次并发操作。条件失败 = 租约已被别的 job 合法接管 ⇒ 不是我们的，不动。

    这不是"释放"路径：正常结束靠"持有者已终态"自动让租约可抢（见 plan 那段）。
    """
    ddb = boto3.client("dynamodb", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1"))
    try:
        ddb.delete_item(
            TableName=os.environ["JOBS_TABLE"],
            Key={"job_id": {"S": deploy_lease_key(site_id)}},
            ConditionExpression="holder_job_id = :me",
            ExpressionAttributeValues={":me": {"S": holder_job_id}})
    except Exception:      # noqa: BLE001
        pass               # 条件失败/读写失败：留下的行要么归别人、要么无害


# ── 路由提交记录（M7 加固，Codex 2026-08-17 P1-1）──────────────────────────
# Step Functions 给每个 Task 都配了默认重试（`Lambda.ClientExecutionTimeoutException`
# / `ServiceException` / `AWSLambdaException` / `SdkClientException`，MaxAttempts=6），
# 这四种都属于"函数可能已经执行完，只是响应没回来"。于是 register_route 可能
# **提交成功之后被重试**，而重试用的是这个 Task 的**原始输入**——第一次放进返回值里的
# `previous_route` 就此丢失，第二次拍到的"切换前快照"其实是自己刚写进去的新路由。
# 后果有两条，都静默：
#   · 补偿变成写回新路由的 no-op，日志还说"已恢复到切换前"；
#   · mark_job 拿到的 previous_prefix 等于当前前缀 ⇒ 真正的上一版前缀被删 ⇒
#     Edge 缓存未收敛的那 60s 回到 403（本轮刚修掉的那个窗口又开了）。
# 所以补偿状态必须**与路由提交同一笔事务落库**，不能只活在 Lambda 返回值里。

def read_route_commit(job_id: str) -> dict | None:
    """这条 job 是否已经提交过路由；提交过就返回当时落库的那份记录。"""
    item = boto3.client("dynamodb", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).get_item(
        TableName=os.environ["JOBS_TABLE"], Key={"job_id": {"S": job_id}},
        ConsistentRead=True).get("Item") or {}
    return item.get("route_commit", {}).get("M")


def route_commit_item(job_id: str, previous_route: dict | None,
                      committed_route: dict) -> dict:
    """把补偿所需的整套状态写进 job 记录的 TransactItems `Update` 条目。

    `attribute_not_exists(route_commit)` ⇒ **只有第一次提交会写**。重试落到这里时
    整笔事务被取消，调用方据此识别"我已经提交过了"，改走幂等回放。
    """
    return {"Update": {
        "TableName": os.environ["JOBS_TABLE"],
        "Key": {"job_id": {"S": job_id}},
        "UpdateExpression": "SET route_commit = :rc",
        "ConditionExpression": "attribute_not_exists(route_commit)",
        "ExpressionAttributeValues": {":rc": {"M": {
            # 三态里的"值是 None"（首次部署）落成 NULL，与"键不在"区分开——
            # mark_job 的三态契约依赖这个区分。
            "previous_route": ({"M": previous_route} if previous_route is not None
                               else {"NULL": True}),
            "committed_route": {"M": committed_route}}}}}}


def site_table_name(site_id: str, logical: str) -> str:
    """站点数据表名的**唯一定义**。三处共用：建表（provision_dynamodb）、
    授权（site_policy）、删除（undeploy._purge_dynamodb）。

    **分隔符是 `-`，而 site_id 自身可以含 `-`**（形态 `<name>-<6位随机>`，
    且 name 允许内部连字符）⇒ 这个格式对**前缀匹配**是有歧义的：站点 A
    （id `foo-k3d9x1`）的 `site-data-foo-k3d9x1-*` 会匹配站点 B
    （id `foo-k3d9x1-…`）的表。正因如此 `site_policy` 必须逐表枚举精确 ARN，
    不得用通配（M01）。改这个格式要同时改三处调用方——
    `test_table_name_format_has_a_single_definition` 会在漂移时变红。
    """
    return f"site-data-{site_id}-{logical}"


def site_prefix_for(site_id: str) -> str:
    """这个站点在前端桶里的根前缀，**带**尾斜杠（列举/整站删除用）。"""
    return f"sites/{site_id}/"


def static_prefix_for(site_id: str, job_id: str) -> str:
    """这次部署的前端版本前缀，**不带**尾斜杠——路由表 `static_prefix` 的形态。

    **尾斜杠的有无是一条实测过的红线**：Edge 的静态改写是
    `f"/{static_prefix}{path}"` 而 `path` 已以 `/` 开头，带尾斜杠会拼出双斜杠，
    与上传的 key 不是同一个对象 ⇒ 整站 403，而两侧单测各自都会绿。

    **本函数是这个格式的唯一定义**：曾经 register_route（写路由）、
    upload_frontend（写对象）、mark_job（按前缀清理）各手写一份 f-string，
    三份必须逐字节同义却没有任何约束保证——而它们不一致的后果分别是整站 403、
    上传到没人读的位置、以及**删掉线上正在服务的前端**。
    `tests/test_common.py::test_static_prefix_format_has_a_single_definition`
    按源码钉死"别处不许再手写"。
    """
    return f"{site_prefix_for(site_id)}{job_id}"


def route_api_target(site_id: str) -> str:
    """路由表里这个站点当前对外的 `api_target`（不存在返回 `""`）。

    blue/green 的"当前是哪个颜色在服务"由它推导——**不另存第二份 live_color**。
    两份状态必然漂移，而漂移的后果是往正在服务的那个颜色上部署。

    用 client 而不是 `_table()` 的 resource 接口：路由表由 `register_route`
    以 client + 显式类型描述符写入（`{"S": ...}`），读侧保持同一套 API 才不会
    在类型转换上出分歧。

    **必须强一致读**（Codex 2026-08-17 P1-4）：这个返回值不是拿来展示的，它决定
    `_idle_color()` 算出哪个 alias "可以安全地改"。读到上一次切换之前的旧副本 ⇒
    把**正在服务**的那一色当成空闲色 ⇒ `update_alias` 直接把未经健康门的新版本
    推到线上流量上。同一条理由让 `register_route` 读 sites 表也用强一致
    （见那里的注释）：凡是"决定能不能动某个东西"的读，最终一致都不够。
    """
    item = boto3.client("dynamodb").get_item(
        TableName=os.environ["ROUTING_TABLE"],
        Key={"subdomain": {"S": subdomain_for(site_id)}},
        ConsistentRead=True).get("Item") or {}
    return item.get("api_target", {}).get("S", "")


def dsql_schema_for(site_id: str) -> str:
    return "site_" + site_id.replace("-", "")


# ---- per-site 运行时 IAM 角色（provision_dsql 与 deploy_lambda_site 共用） ----
# DSQL 的 AWS IAM GRANT 要求 IAM 角色先存在（官方流程：建 IAM role → 建 DB role
# → AWS IAM GRANT），因此建库步骤也要能保证该角色就位，不能等到部署函数那一步。

TRUST_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')


def site_role_name(site_id: str) -> str:
    return f"site-rt-{site_id}"


def site_role_arn(site_id: str) -> str:
    return f"arn:aws:iam::{os.environ['ACCOUNT_ID']}:role/{site_role_name(site_id)}"


def site_policy(site_id: str, engine: str, *, tables: list[str]) -> str:
    """per-site 运行时角色的 inline policy。

    **DynamoDB 资源逐表枚举精确 ARN，不得用 `site-data-{site_id}-*` 通配**（M01）：
    site_id 自身可含 `-`，所以站点 A（id `foo-k3d9x1`）的通配会匹配站点 B
    （id `foo-k3d9x1-…`）的全部表 ⇒ 跨租户读写。PermissionsBoundary 放开的是
    整个 `site-data-*`（它只封顶最坏能力面），**per-tenant 隔离完全依赖本函数**。

    `tables` 是**必填关键字参数**——迫使调用方表态，而不是靠默认值悄悄退回通配。
    engine 为 `dsql` / `none` 时忽略它；engine 为 `dynamodb` 而它为空则抛错。
    """
    import json
    region, acct = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"), os.environ["ACCOUNT_ID"]
    fn = f"site-{site_id}"
    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        # 精确日志组名（函数名就是 site-{site_id}）+ stream 层两条。
        # 原来是裸前缀 `…/site-{site_id}*`，会匹配到 id 以本站点为前缀的其他站点。
        "Resource": [f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{fn}",
                     f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/{fn}:*"]}]
    if engine == "dynamodb":
        if not tables:
            raise ValueError(
                f"站点 {site_id} 的 engine 是 dynamodb 但没有声明表——"
                "空 Resource 列表是非法 IAM，且合同要求至少一张表")
        statements.append({
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": [
                f"arn:aws:dynamodb:{region}:{acct}:table/{site_table_name(site_id, t)}"
                for t in tables]})
    elif engine == "dsql":
        statements.append({"Effect": "Allow", "Action": "dsql:DbConnect",
                           "Resource": "*"})  # 数据隔离由 per-site PG role 保证
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def ensure_site_role(site_id: str, engine: str, *, tables: list[str]) -> str:
    """幂等创建 per-site 运行时角色（带 PermissionsBoundary）并刷新 inline policy。

    `tables` 透传给 site_policy（必填，理由见那里）。**每次部署都刷新 policy**
    ——这也是 M01 存量收敛的机制：站点下一次部署时自动换成精确 ARN。
    """
    iam = boto3.client("iam")
    name = site_role_name(site_id)
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=TRUST_POLICY,
            PermissionsBoundary=os.environ["RUNTIME_BOUNDARY_ARN"],
            Tags=[{"Key": "project", "Value": "site-builder"},
                  {"Key": "site_id", "Value": site_id}])["Role"]["Arn"]
    iam.put_role_policy(RoleName=name, PolicyName="site-scope",
                        PolicyDocument=site_policy(site_id, engine, tables=tables))
    return arn
