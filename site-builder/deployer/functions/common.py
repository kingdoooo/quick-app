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


def create_job(owner: str, site_id: str) -> str:
    job_id = "job-" + secrets.token_hex(8)
    _table("JOBS_TABLE").put_item(Item={
        "job_id": job_id, "site_id": site_id, "owner": owner,
        "status": "PENDING", "phase": "submitted", "error": "", "url": "",
        "created_at": _now(), "updated_at": _now()})
    return job_id


def update_job(job_id: str, *, status=None, phase=None, error=None, url=None) -> None:
    updates, values = ["updated_at = :t"], {":t": _now()}
    names = {}
    for field, val in (("status", status), ("phase", phase), ("error", error), ("url", url)):
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


def get_job(job_id: str) -> dict | None:
    return _table("JOBS_TABLE").get_item(Key={"job_id": job_id}).get("Item")


def list_jobs_by_owner(owner: str) -> list[dict]:
    resp = _table("JOBS_TABLE").query(
        IndexName="owner-index",
        KeyConditionExpression=Key("owner").eq(owner))
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


def validate_site_name(name: str) -> str:
    """校验站点名。放行非法字符会导致 DSQL DDL 注入与 IAM/Lambda 命名失败。"""
    if not isinstance(name, str) or not SITE_NAME_RE.fullmatch(name):
        raise InvalidSiteName(
            "站点名必须以小写字母开头，仅含小写字母、数字与连字符，长度 2-30")
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
