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
def create_job(owner: str, site_id: str, guard_items: list | None = None) -> str:
    """建任务记录。

    guard_items: 可选的 TransactItems 条目（ConditionCheck 等）。给了就走事务，
    把"建任务"与这些条件绑成一次提交。MCP 的 undeploy 用它把"鉴权时的权限快照
    仍然有效"绑进来——鉴权与副作用之间的撤权窗口否则会让旧请求照样落地
    （见 mcp/server.py 的 _rev_condition_check）。
    条目形态用低层 client 的 AttributeValue 写法，所以这条路径**不能**走
    resource.Table：两套 API 的 item 形态不同，混用会 ValidationException。
    """
    job_id = "job-" + secrets.token_hex(8)
    now = _now()
    item = {"job_id": job_id, "site_id": site_id, "owner": owner,
            "status": "PENDING", "phase": "submitted", "error": "", "url": "",
            "created_at": now, "updated_at": now}
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
        Limit=limit)
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


def site_policy(site_id: str, engine: str) -> str:
    import json
    region, acct = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"), os.environ["ACCOUNT_ID"]
    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/lambda/site-{site_id}*"}]
    if engine == "dynamodb":
        statements.append({
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                       "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            "Resource": f"arn:aws:dynamodb:{region}:{acct}:table/site-data-{site_id}-*"})
    elif engine == "dsql":
        statements.append({"Effect": "Allow", "Action": "dsql:DbConnect",
                           "Resource": "*"})  # 数据隔离由 per-site PG role 保证
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def ensure_site_role(site_id: str, engine: str) -> str:
    """幂等创建 per-site 运行时角色（带 PermissionsBoundary）并刷新 inline policy。"""
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
                        PolicyDocument=site_policy(site_id, engine))
    return arn
