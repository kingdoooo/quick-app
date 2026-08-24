#!/usr/bin/env python3
"""per-site 数据表的**归属完整性**闸门：只读，跑在部署之后。

它证明的核心不变量是**按角色、按站点的集合相等**：

    role(site_id) 授权到的 DynamoDB 表 ARN 集合
      ==  该 site_id 自己、经表 tag 验证过的表 ARN 集合

**这条判据的写法是要害。** 写成"role 里的 ARN 指向某张存在且 tag 正确的表"就会重新
变成 false-green——别的站点的表当然也是"存在且 tag 正确"的表，于是 A 的角色指向 B 的
表会被判绿，而那正是本闸门要抓的越权形态。所以两边必须是**同一个 site_id**的精确集合
相等：不多、不少、不含通配、不含别站的表。

为什么现有闸门不够：`backfill_site_role_policies.py --check` 做的是"实际 policy ==
按代码推导的期望 policy"，而期望值是从 sites 行的 `data_tables` 推出来的——两边**同源**。
`data_tables` 被污染时两边一致，闸门照样全绿。本脚本引入「**表自己的 tag**」作为独立
信源，那是 `data_tables` 之外的第二个事实来源。

范围：只看**当前 ACTIVE** 站点。历史/DELETED 行不做全量对账（它们不被服务，且表可能
已删），但它们的 `data_tables` 若含连字符仍会被报出来——那种值是跨站点碰撞的载体。

用法：
    python3 site-builder/scripts/verify_site_table_integrity.py
"""
import configparser
import json
import os
import sys
from pathlib import Path

import boto3

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))

FAILURES = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global FAILURES
    FAILURES += (not ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def _load_config() -> tuple[str, str, str]:
    """→ (region, sites_table, account_id)。**直接赋值不用 setdefault**：config.ini 是
    唯一取值来源，setdefault 会让 shell 里残留的旧 SITES_TABLE 静默改掉核对目标。"""
    path = HERE.parent / "config.ini"
    if not path.exists():
        raise SystemExit(f"找不到 {path}——从 config.ini.example 复制并填好再跑")
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(path)
    try:
        region = cfg["Platform"]["region"].split("#")[0].strip()
        account_id = cfg["Platform"]["account_id"].split("#")[0].strip()
        sites_table = cfg["Deployer"]["sites_table"].split("#")[0].strip()
    except KeyError as e:
        raise SystemExit(f"config.ini 缺少 {e}") from e
    os.environ["AWS_DEFAULT_REGION"] = region
    os.environ["SITES_TABLE"] = sites_table
    return region, sites_table, account_id


def _assert_target_account(region: str, expected_account_id: str) -> str:
    """当前凭证必须**严格等于** `[Platform] account_id`（backfill 同款读法）。

    没有这一条时，把闸门跑在另一个账号上会得到一串"表不存在"的 FAIL，读起来像
    生产故障；更糟的是**全绿**——空账号里零个站点、零个角色，集合相等平凡成立。

    不许用"账号号出现在 config.ini 任意位置"的全文 substring（Codex 复审指出）：
    文件里任何位置恰好出现另一个账号号（ARN/注释/历史值）都会让闸门在错误账号上
    继续跑，而那正是上面要防的假绿。
    """
    ident = boto3.client("sts", region_name=region).get_caller_identity()
    acct = ident["Account"]
    if acct != expected_account_id:
        raise SystemExit(
            f"当前凭证的账号（…{acct[-4:]}）不是 config.ini 的 [Platform] "
            f"account_id（…{expected_account_id[-4:]}）——本闸门会核错对象，中止。"
            "先确认 AWS_PROFILE / 凭证。")
    return acct


def _scan_sites(ddb_res, table: str) -> list[dict]:
    """全量分页 scan sites 表。"""
    out, kw = [], {}
    t = ddb_res.Table(table)
    while True:
        page = t.scan(**kw)
        out.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return out
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _role_table_arns(iam, role_name: str) -> set:
    """→ 该角色 inline policy 里全部 DynamoDB 表 ARN 的集合。

    inline policy 名与 policy 文档都分页取。通配的判定交给 `role_arn_problems`。
    """
    arns = set()
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for pol_name in page["PolicyNames"]:
            doc = iam.get_role_policy(RoleName=role_name,
                                      PolicyName=pol_name)["PolicyDocument"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            for st in doc.get("Statement", []):
                res = st.get("Resource")
                for a in ([res] if isinstance(res, str) else (res or [])):
                    if ":table/" not in a:
                        continue
                    arns.add(a)
    return arns


def role_arn_problems(site_id: str, engine: str, role_arns,
                      owned_by_site: dict) -> list:
    """判定一个 per-site 角色的表 ARN 集合是否合规 → 问题描述列表（空 = 合规）。

    **抽成纯函数是为了能反向验证**：这里是整个闸门最要紧、也最容易写成 false-green
    的一段，而它在真机上永远是绿的（生产状态正确时）。绿的守卫必须能证明自己会红，
    所以判定逻辑不能只活在读 AWS 的 `main()` 里——
    `deployer/tests/test_verify_site_table_integrity.py` 喂三种坏形态给它。

    `role_arns=None` 表示**角色不存在**。角色存在性按 engine 分流（决策收在这里，
    不散在 main()）：static（engine=`none`）契约上就没有 `site-rt-*` 运行时角色
    （`ensure_site_role` 只被 deploy_lambda_site / provision_dsql 调用，backfill
    也按此跳过），角色缺失是合法态；dynamodb / dsql 站点角色缺失则是故障。
    角色**存在**的 static 站点不豁免：表 ARN 集合必须为空（tier 变迁残留的能力面）。

    `owned_by_site`: `{site_id: 经表 tag 验证过的表 ARN 集合}`。**必须整个传进来**，
    不能只传本站那一份：判"多出来的 ARN 是不是属于别的站点"需要看全局，而那正是
    本闸门要抓的越权形态。

    判据是**同一个 site_id 的精确集合相等**，不是"每个 ARN 都指向某张有效的表"——
    后者会把 A 的角色指向 B 的表判成绿（别站的表当然也"有效"）。
    """
    if role_arns is None:
        if engine == "none":
            return []                # static 无运行时角色，符合契约
        return [f"ACTIVE 站点没有 per-site 角色（engine={engine} 必须有）"]

    problems = []
    wild = [a for a in sorted(role_arns) if "*" in a.split(":table/", 1)[-1]]
    if wild:
        problems.append(f"表 ARN 含通配：{wild}")

    if engine != "dynamodb":
        if role_arns:
            problems.append(
                f"engine={engine} 的角色不该有任何 DynamoDB 表 ARN，却有 "
                f"{sorted(role_arns)}")
        return problems

    want = set(owned_by_site.get(site_id, set()))
    if not want:
        problems.append("NoSQL 站点没有任何经 tag 验证的表，无法核对")
        return problems
    extra = sorted(role_arns - want)
    missing = sorted(want - role_arns)
    if extra:
        foreign = sorted(a for a in extra
                         if any(a in v for k, v in owned_by_site.items()
                                if k != site_id))
        problems.append(
            f"多出 {extra}"
            + (f"，其中**属于别的站点** {foreign}" if foreign else ""))
    if missing:
        problems.append(f"缺少 {missing}")
    return problems


def main() -> int:
    import common
    sys.path.insert(0, str(HERE.parent / "contract" / "src"))
    from contract.schema import TABLE_NAME_RE

    region, sites_table, account_id = _load_config()
    acct = _assert_target_account(region, account_id)
    ddb = boto3.client("dynamodb", region_name=region)
    ddb_res = boto3.resource("dynamodb", region_name=region)
    iam = boto3.client("iam")
    print(f"账号 …{acct[-4:]} / {region} / sites={sites_table}\n")

    rows = _scan_sites(ddb_res, sites_table)
    active = [r for r in rows if r.get("status") == "ACTIVE"]
    print(f"sites 行 {len(rows)}，其中 ACTIVE {len(active)}")

    # ── ① 逻辑表名的字符集（含非 ACTIVE 行）────────────────────────────
    print("\n── ① data_tables 里的逻辑表名不得含连字符 ──────────")
    bad_names = []
    for r in rows:
        for t in (r.get("data_tables") or []):
            if not isinstance(t, str) or not TABLE_NAME_RE.fullmatch(t):
                bad_names.append(f"{r['site_id']}/{t!r}({r.get('status')})")
    check(not bad_names,
          "全部 data_tables 逻辑名都符合 TABLE_NAME_RE",
          f"违规：{bad_names}" if bad_names
          else f"共 {sum(len(r.get('data_tables') or []) for r in rows)} 条名字")
    if bad_names:
        print("     含连字符的逻辑名是跨站点物理表名碰撞的载体：它会让两个不同站点"
              "拼出同一张表。需人工修那些行。")

    # ── ② ACTIVE NoSQL 站点的表：存在 + tag 归属正确 ───────────────────
    print("\n── ② ACTIVE NoSQL 站点的表存在且 tag 归属正确 ───────")
    owned_arns: dict[str, set] = {}      # site_id -> 经 tag 验证的表 ARN 集合
    engine_of: dict[str, str] = {}
    tier_problems = []
    for r in active:
        site_id = r["site_id"]
        try:
            engine = common.tier_engine(str(r.get("tier") or ""))
        except ValueError as exc:
            tier_problems.append(f"{site_id}: {exc}")
            continue
        engine_of[site_id] = engine
        owned_arns[site_id] = set()
        if engine != "dynamodb":
            continue
        logicals = list(r.get("data_tables") or [])
        if not logicals:
            check(False, f"{site_id} 是 NoSQL 站点但 data_tables 为空",
                  "无法核对它该有哪些表")
            continue
        for logical in logicals:
            try:
                arn = common.assert_table_owned_by_site(ddb, site_id, logical,
                                                        read_attempts=1)
            except Exception as exc:      # noqa: BLE001 归属核不出来一律算失败
                check(False, f"{site_id}/{logical} 表归属核验",
                      f"{type(exc).__name__}: {str(exc)[:90]}")
                continue
            owned_arns[site_id].add(arn)
            check(True, f"{site_id}/{logical} 表存在且 tag 归属正确",
                  arn.split(":table/")[-1])
    check(not tier_problems, "全部 ACTIVE 行的 tier 都可解析",
          f"{tier_problems}" if tier_problems else "")

    # ── ③ 按角色、按站点的集合相等 ────────────────────────────────────
    print("\n── ③ role 的表 ARN 集合 == 同一站点自己的表（精确相等）──")
    for site_id, engine in sorted(engine_of.items()):
        role = common.site_role_name(site_id)
        try:
            role_arns = _role_table_arns(iam, role)
        except iam.exceptions.NoSuchEntityException:
            role_arns = None         # 角色不存在——是否合法由纯函数按 engine 判
        problems = role_arn_problems(site_id, engine, role_arns, owned_arns)
        check(not problems,
              f"{role}（engine={engine}）的表 ARN 集合与本站点自己的表精确相等",
              "；".join(problems) if problems
              else ("static 站点无运行时角色（符合契约）" if role_arns is None
                    else f"{len(owned_arns.get(site_id, ()))} 张"))

    print()
    if FAILURES:
        print(f"结果：{FAILURES} 项未达预期 —— 先排查再继续")
        return 1
    print("结果：per-site 数据表的归属完整性全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
