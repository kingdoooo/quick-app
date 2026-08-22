#!/usr/bin/env python3
"""一次性 backfill：把存量 per-site 运行时角色的 policy 重写成精确 ARN。

**为什么不能等下次部署**：`table/site-data-{A}-*` 是**向前看的**通配，覆盖所有
以 A 的 id 为前缀的 site_id，包括本次上线之后才创建的。懒收敛等于把每个存量
站点留成对未来嵌套站点生效的陷阱（M01 的修复对它们等于没生效）。

**枚举 IAM 角色而不是遍历 sites 行**：下线清理失败留下的孤儿角色恰恰最该收。

重写走**同一个** `common.ensure_site_role`，不另开策略构造路径。

从仓库根跑，用系统 python3：
    python3 site-builder/scripts/backfill_site_role_policies.py           # dry-run
    python3 site-builder/scripts/backfill_site_role_policies.py --apply   # 真写
    python3 site-builder/scripts/backfill_site_role_policies.py --check   # 只跑闸门
"""
import argparse
import configparser
import json
import os
import pathlib
import sys
import time
import urllib.parse

import boto3
from botocore.exceptions import ClientError

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))

ROLE_PREFIX = "site-rt-"
POLICY_NAME = "site-scope"
BACKUP_PATH = ROOT / "site-builder" / "scripts" / "backfill-old-policies.json"
# check_roles 用这两个前缀标记"闸门红但不能自动修"的角色；main 据此分流到
# 需人工清单而不是 todo（自动删未知 policy、自动重建消失的角色，都违反
# "判不出就不猜"）
EXTRA_POLICY_REASON = "site-scope 之外还有别的 policy（需人工移除，不自动删）"
MISSING_ROLE_REASON = "ACTIVE 站点的角色缺失（sites 行在、IAM 角色不在，需人工查根因）"

# 裸 dry-run 打印计划、**退出码恒为 0**（除需人工项），所以把这条最顺手的命令
# 接进发布检查就得到一条恒绿的假闸门——正是 S1 要消灭的形态。
# 退出码不能改：Task 10 Step 3 在 `set -euo pipefail` 块里先跑裸 dry-run 再
# `--apply`，而 backfill 之前 targets 必然非空（那正是要跑它的理由），退非 0
# 会让那个块每次都在 `--apply` 之前中止，部署序列不可跑。于是用一行显式警告顶上。
DRY_RUN_NOT_A_GATE = ("  >> 以上只是计划预览（这不是闸门；闸门命令是 --check）"
                      "——dry-run 即使有待收敛角色也退 0，别把它接进发布检查")

# 写后复核的重试退避（秒）：首次尝试之外再试 3 次，共 4 次读，最坏多等 14 秒。
# IAM 是最终一致的，策略模拟器尤其会滞后一次写入若干秒——不重试的话，一次
# **完全正确**的 --apply 会把传播延迟记成"落地的 policy 与期望不一致"并退 1，
# 操作者会合理地读成"迁移把生产 IAM 改坏了"。上限是硬的：不做无限等待。
_VERIFY_RETRY_BACKOFF = (2, 4, 8)


class NeedsManualReview(Exception):
    """这个角色的 engine / 表清单判不出来——跳过并计数，绝不猜。"""


def _load_env(config_path=None):
    """从 config.ini 下发环境变量，并**核对当前凭证就是目标账号**。

    **`config_path` 可注入是给单测用的**：真实 config.ini 是 gitignored 的，
    干净 clone / CI 里不存在——读它的测试会以"读不到 config"失败，与被测行为
    无关（Codex 指出）。生产调用不传参，仍以仓库根的 config.ini 为唯一取值
    来源（CLAUDE.md 口径不变）。

    **直接赋值，不用 setdefault**：config.ini 是部署脚本的唯一取值来源
    （CLAUDE.md），setdefault 会让 shell 里残留的旧值静默改写写入目标。
    `migrate_permissions._load_config` 与 `migrate_sites_to_blue_green._load_config`
    的 docstring 都明写了这条，本脚本必须一致。

    **STS 账号核对是硬要求**：若操作者的 AWS_PROFILE / 临时凭证指向另一个账号，
    那里没有 `site-rt-*` 角色 ⇒ 闸门看到"0 个不合格"⇒ dry-run / --apply / --check
    全部退 0，而**目标账号里的旧通配角色一个都没动**，发布记录却显示 M01 已闭环。
    仅 ACCOUNT_ID 残留错误时更隐蔽：policy 会被写成指向错误账号的精确 ARN，
    没有任何 `*`、闸门照样绿，而站点访问自己的表全部 AccessDenied。
    """
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(config_path or ROOT / "site-builder" / "config.ini"):
        raise SystemExit("读不到 site-builder/config.ini")
    acct = cfg["Platform"]["account_id"].strip()
    actual = boto3.client("sts").get_caller_identity()["Account"]
    if actual != acct:
        raise SystemExit(
            f"当前凭证属于账号 {actual}，而 config.ini 的目标账号是 {acct}——"
            "拒绝执行。切换 AWS_PROFILE / 凭证后重试。")
    os.environ["ACCOUNT_ID"] = acct
    os.environ["AWS_DEFAULT_REGION"] = cfg["Platform"]["region"].strip()
    os.environ["SITES_TABLE"] = cfg["Deployer"]["sites_table"].strip()
    os.environ["RUNTIME_BOUNDARY_ARN"] = (
        f"arn:aws:iam::{acct}:policy/site-runtime-boundary")
    return cfg


def _norm(doc: dict):
    """policy 文档 → 可比较形态。**完整递归等值，不丢任何字段**。

    **不能直接比 JSON 字符串**：IAM 会做自己的归一（单元素列表可能回来变成
    字符串，语句顺序不保证）。**也不能只比 (Effect, Action, Resource)**——
    v2 那样会丢掉 Condition / NotAction / NotResource：「精确 ARN + 额外限区
    Condition」的角色被判合格、不进 targets、不跑功能模拟，--check 绿而站点
    不可用（Codex 指出）。所以递归规范化整个文档：dict 保留全部键、标量与
    单元素列表同形、多元素列表按规范 JSON 串排序。
    """
    def _c(v):
        if isinstance(v, dict):
            return {k: _c(x) for k, x in v.items()}
        if isinstance(v, list):
            out = [_c(x) for x in v]
            if len(out) == 1:
                return out[0]
            return sorted(out, key=lambda x: json.dumps(
                x, sort_keys=True, ensure_ascii=False))
        return v
    return _c(doc)


def _actual_policy(iam, role_name: str):
    """角色的 site-scope inline policy。**只有 NoSuchEntity 返回 None**。

    v3 是裸 `except Exception: return None`——限流/断网/AccessDenied 都被
    解释成"原本没有 policy"，`_persist_backup` 把这个 None 落盘且"绝不覆盖
    已有快照"，于是一次限流就把回滚材料**永久**记成 null（Codex 复现过）。
    其他错误必须原样抛出：抛在备份阶段 ⇒ 零 IAM 写入（先备份后写保证的）；
    抛在 --check ⇒ 退非 0，本来就是 fail-closed。
    """
    try:
        raw = iam.get_role_policy(
            RoleName=role_name, PolicyName=POLICY_NAME)["PolicyDocument"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise
    return raw if isinstance(raw, dict) else json.loads(urllib.parse.unquote(raw))


def _extra_policies(iam, role_name: str) -> list:
    """site-scope 之外的一切 policy：多余的 inline + 全部 attached。

    只比 site-scope 那一条是不够的（Codex 指出的 P1）：boundary 对全部
    DynamoDB 数据动作放行整个 site-data-*，角色上任何一条残留 identity
    policy（比如调试期的 PutItem on site-data-*）与 boundary 取交集就是
    有效的跨租户写权限——而 site-scope 本身可以完全等于期望。
    """
    extra = []
    for page in iam.get_paginator("list_role_policies").paginate(
            RoleName=role_name):
        extra += [p for p in page["PolicyNames"] if p != POLICY_NAME]
    for page in iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name):
        extra += [p["PolicyArn"] for p in page["AttachedPolicies"]]
    return extra


def site_role_names(iam) -> list:
    names = []
    for page in iam.get_paginator("list_roles").paginate():
        names += [r["RoleName"] for r in page["Roles"]
                  if r["RoleName"].startswith(ROLE_PREFIX)]
    return sorted(names)


def check_roles(iam) -> list:
    """→ [(role_name, 原因)]。**S1 的硬发布闸门**：必须为空。判据四层：

    1. **实际 site-scope 与期望 policy 完整文档等值**，不是"没有 `*`"
       （错账号/错 region/漏表都不含通配，却同样不可用；Codex 复核指出）。
       期望值由 `common.site_policy` 现算——与运行时同一份定义。
    2. **角色上只许有 site-scope 这一条 policy**：多余 inline / 任何
       attached 都不合格。site-scope 全对时残留的调试 policy 与 boundary
       取交集仍是有效跨租户权限（Codex 指出的 P1），只比 site-scope 对它失明。
    3. **反向存在性**：ACTIVE 非 static 站点的角色必须存在
       （缺失分流需人工，不自动重建——见下面反向段的注释）。
    4. 功能模拟在 `simulate_active_sites`（--check 专属，全动作）。
    """
    import common
    bad = []
    for name in site_role_names(iam):
        site_id = name[len(ROLE_PREFIX):]
        actual = _actual_policy(iam, name)
        if actual is None:
            bad.append((name, "没有 site-scope inline policy（不合格）"))
            continue
        site = common.get_site_consistent(site_id) or {}
        if not site:
            bad.append((name, "sites 表里没有对应行（孤儿角色，需人工确认后删除）"))
            continue
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            bad.append((name, f"算不出期望 policy：{exc}"))
            continue
        extra = _extra_policies(iam, name)
        if extra:
            bad.append((name, f"{EXTRA_POLICY_REASON}：{extra}"))
            continue
        expected = json.loads(common.site_policy(site_id, engine, tables=tables))
        if _norm(actual) != _norm(expected):
            bad.append((name, f"policy 与期望不一致（engine={engine} tables={tables}）"))
    # 反向：ACTIVE 非 static 站点的角色必须**存在**。只从现存 site-rt-* 出发
    # 是单向的——"角色整个缺失"（误删/清理脚本写错）完全不可见，IAM 里一个
    # 角色都没有时闸门反而全绿（Codex 指出）。
    # 缺失**不自动重建**（v5 曾写"进 targets 由 ensure_site_role 重建"，撤回）：
    # ① ACTIVE 站点的角色凭空消失本身是异常，自动重建会盖掉根因；
    # ② 自动建会让备份出现"角色原本不存在"这一态——GetRolePolicy 的
    #    NoSuchEntity 分不出它和"角色在、只缺 policy"，回滚就得会删整个角色
    #    （Codex 指出的 null 歧义）。分流需人工后，todo 里的角色只能来自
    #    list_roles 枚举 ⇒ 备份里 null 的语义唯一：角色在、site-scope 不在。
    have = set(site_role_names(iam))
    for site_id in active_fullstack_site_ids():
        name = ROLE_PREFIX + site_id
        if name not in have:
            bad.append((name, MISSING_ROLE_REASON))
    return bad


def active_fullstack_site_ids() -> list:
    """ACTIVE 且需要运行时角色（engine != none）的 site_id。扫 sites 表，只读。

    未知 tier 不猜、也不跳过——按"需要角色"对待：角色若在，per-role 检查会以
    NeedsManualReview 报它；角色若缺，反向检查报缺失。两边都 fail-closed。
    """
    import common
    out = []
    for row in common._paginate(common._table("SITES_TABLE").scan):
        if row.get("status") != "ACTIVE":
            continue
        try:
            if common.tier_engine(row.get("tier", "")) == "none":
                continue                      # static 站点没有运行时角色
        except ValueError:
            pass
        out.append(row["site_id"])
    return sorted(out)


def verify_access(iam, site_id: str, tables: list) -> list:
    """用 IAM 策略模拟器做功能验收 → [问题…]。只读。

    比"policy 文本对不对"更直接：断言该站点的角色对**每个数据动作**都能
    访问自己的每张表、且对邻居表**每个动作都被拒**。模拟器会算 permissions
    boundary 与角色上的**全部** identity policy——所以它连 check_roles 的
    结构检查漏掉的形态都能兜住。

    **动作清单从期望 policy 现取，不手抄第二份**（Codex 指出的 P1：只模拟
    GetItem 时，一条残留的"PutItem on site-data-*"调试 policy 在读模拟下
    照样"拒绝"，闸门绿而跨租户**写**仍然可行——M01 的修复等于只验了读）。
    """
    import common
    problems = []
    arn = common.site_role_arn(site_id)
    region = os.environ["AWS_DEFAULT_REGION"]
    acct = os.environ["ACCOUNT_ID"]
    expected = json.loads(common.site_policy(site_id, "dynamodb", tables=tables))
    actions = sorted({a for stmt in expected["Statement"]
                      for a in (stmt["Action"] if isinstance(stmt["Action"], list)
                                else [stmt["Action"]])
                      if a.startswith("dynamodb:")})
    assert actions, "期望 policy 里没有任何 dynamodb 动作——动作清单推导坏了"

    def _decisions(table_name):
        res = f"arn:aws:dynamodb:{region}:{acct}:table/{table_name}"
        out = iam.simulate_principal_policy(
            PolicySourceArn=arn, ActionNames=actions, ResourceArns=[res])
        return {r["EvalActionName"]:
                r["ResourceSpecificResults"][0]["EvalResourceDecision"]
                for r in out["EvaluationResults"]}

    for logical in tables:
        got = _decisions(common.site_table_name(site_id, logical))
        denied = sorted(a for a, d in got.items() if d != "allowed")
        if denied:
            problems.append(
                f"访问自己的表 {logical} 被拒（{denied}）——backfill 写坏了")
    # 构造一个"以本 site_id 为前缀"的邻居：**任何一个动作** allowed 都算
    # 失败（这正是 M01 的形态，读写都算）
    neighbour = common.site_table_name(f"{site_id}-probe-abc123", "notes")
    got = _decisions(neighbour)
    leaked = sorted(a for a, d in got.items() if d == "allowed")
    if leaked:
        problems.append(
            f"仍能访问嵌套邻居的表 {neighbour}（{leaked}）——残留权限没收干净")
    return problems


def plan_for(site_id: str, site: dict) -> tuple:
    """→ (engine, tables)。判不出即抛 NeedsManualReview。"""
    import common
    tier = site.get("tier")
    if not tier:
        raise NeedsManualReview(f"{site_id}: sites 行没有 tier，判不出 engine")
    try:
        engine = common.tier_engine(tier)
    except ValueError as exc:
        raise NeedsManualReview(f"{site_id}: {exc}") from exc
    if engine != "dynamodb":
        return engine, []
    tables = list(site.get("data_tables") or [])
    if not tables:
        raise NeedsManualReview(
            f"{site_id}: engine 是 dynamodb 但 sites 行没有 data_tables，"
            "判不出表清单。请人工确认该站点的表后手工重写它的 policy")
    return engine, tables


def _persist_backup(iam, role_names) -> None:
    """把全部 target 的旧 policy **原子落盘**（spec §7.3 的"覆盖前留档"）。

    v2 在这里犯过错（Codex 指出）：备份攒在内存字典、循环结束才写文件——
    第 2 个角色写入抛异常（IAM 限流最常见）时，第 1 个已被改而备份文件
    不存在，承诺的回滚材料落空。所以六条纪律：
    - **先备份后写**：本函数必须在任何 put_role_policy 之前完成；
    - **临时文件 + os.replace**：崩溃不会留下半个 JSON；
    - **fsync 内容、再 fsync 父目录**：replace 的原子性是文件系统层面的，不等于
      持久性——replace 返回后内容可能只在 page cache 里，此时掉电就是"IAM 已改、
      回滚文件 0 字节"。见写盘那段注释；
    - **O_EXCL 临时文件兼作跨进程锁，且必须在读之前拿到**：无锁的
      read-modify-write 会让两个并发跑互相覆盖快照，而两边都已改过 IAM。
      锁盖住读-改-写全程，由 `os.replace`（成功）或 finally 的 unlink（失败）
      释放；只有崩在写窗口里才会留下 .tmp，那种残留需人工确认，不自动删。
      放晚一步就等于没有锁——见下面拿锁那段注释里复现出的形态；
    - **合并、绝不覆盖已有快照**：重跑时已收敛的角色不再是 target，
      无条件覆盖会丢掉它们的原始通配 policy——回滚要的恰是第一份快照。
      roles 值为 null = 备份时该角色没有 site-scope inline policy
      （`_actual_policy` 只把 NoSuchEntity 判为不存在，其他读错误直接
      抛出 ⇒ 此时零 IAM 写入；且缺失角色分流需人工、不进 todo ⇒
      本函数只会收到 list_roles 枚举出的**真实存在**的角色，null 不会
      再混入"角色本身不存在"这一态，回滚动作唯一：`delete_role_policy`
      删掉新写的 site-scope。「角色存在」不止靠分流保证——枚举后被带外
      删除的 TOCTOU 由循环内的 GetRole 复核兜住，见那段注释）；
    - **带账号元数据，合并前核对**：格式 {schema_version, account_id,
      region, roles}。没有元数据时，切到另一个账号后"绝不覆盖"会把
      A 账号同名 role 的旧快照保留成 B 账号的回滚材料（Codex 指出）——
      不一致就拒绝执行，提示把旧文件移走，绝不静默合并。
    """
    # **锁必须在读之前拿到**：O_EXCL 创建临时文件，兼作跨进程互斥锁。
    # 第一版把它放在读-改-写**之后**，而 `os.replace` 会 unlink tmp、即**释放**锁
    # ——于是锁只活微秒级，既没盖住别人的读阶段也没盖住自己写 IAM 的阶段。
    # 复核用单线程 fake 确定性复现过：A 的整个 _persist_backup 在 B 的读循环中间
    # 跑完，A 的原始 policy 就从回滚文件里消失，而 A 的 O_EXCL 从未撞上——此时 A
    # 已经在 put_role_policy 循环里，等于"原始不可恢复 + 还要继续改"。
    # 放到最前面之后：读-改-写对其他跑是原子的；持锁期间来的跑中止，
    # 在赢家 replace 之后来的跑读到已合并的文件再往上合并，谁都不丢。
    tmp = BACKUP_PATH.parent / (BACKUP_PATH.name + ".tmp")
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # 注意：这条出口在 try/finally **之外**——不能顺手删掉别人的锁文件，
        # 也不能删掉上一次崩在写窗口里留下的那个（它要人工确认内容后再删）。
        raise SystemExit(
            f"临时备份文件 {tmp} 已存在——判为另一个 backfill 正在运行，中止，"
            "此时一笔 IAM 写入都没发生。若确认没有别的进程在跑（上一次崩溃留下的"
            "残留），人工确认内容后删掉它再重跑；本脚本不自动删。")
    handle, replaced = os.fdopen(fd, "w"), False
    try:
        meta = {"schema_version": 1,
                "account_id": os.environ["ACCOUNT_ID"],
                "region": os.environ["AWS_DEFAULT_REGION"]}
        roles = {}
        if BACKUP_PATH.exists():
            saved = json.loads(BACKUP_PATH.read_text())
            for key, want in meta.items():
                if saved.get(key) != want:
                    raise SystemExit(
                        f"已有备份 {BACKUP_PATH.name} 的 {key}={saved.get(key)!r} "
                        f"与当前 {want!r} 不一致——拒绝合并（它可能属于另一个账号的"
                        "同名角色）。把旧文件移走后重试。")
            roles = saved["roles"]
        for name in role_names:
            if name not in roles:
                policy = _actual_policy(iam, name)
                if policy is None:
                    # null 的语义必须唯一：「角色在、site-scope 不在」。角色在
                    # check_roles 枚举之后被带外删除（TOCTOU 窗口）时，
                    # GetRolePolicy 的 NoSuchEntity 与"只缺 policy"分不出来——
                    # 这里补一次 GetRole，把「角色存在」从运维假设变成技术保证
                    # （Codex 签核附带项）。角色没了 ⇒ 在第一笔 IAM 写入前中止。
                    try:
                        iam.get_role(RoleName=name)
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchEntity":
                            raise SystemExit(
                                f"{name} 在枚举后消失（并发删除？）——中止 backfill，"
                                "此时一笔 IAM 写入都没发生。查明根因后重跑。")
                        raise
                roles[name] = policy
        payload = json.dumps({**meta, "roles": roles},
                             ensure_ascii=False, indent=2)
        # **fsync 两次**：`os.replace` 只给文件系统层面的原子性，不给持久性——
        # replace 返回后目标内容仍可能只在 page cache 里。要命的窗口是：replace
        # 成功 → put_role_policy 全部成功 → 机器掉电 → 生产 IAM 已改而回滚文件
        # 是 0 字节。第一次 fsync 让**内容**落盘；replace 之后 fsync **父目录**
        # 让**改名**落盘。两次都必需，少哪一次都留下"IAM 已改、回滚材料没了"的窗口。
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(tmp, BACKUP_PATH)
        replaced = True
        dir_fd = os.open(BACKUP_PATH.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        # close 也要包起来：它若抛（缓冲区刷盘失败）会既盖掉原始异常、又让下面的
        # unlink 根本执行不到，于是锁文件留下而真正的错因不见了。
        try:
            handle.close()      # 幂等；成功路径上已经关过
        except OSError:
            pass
        if not replaced:
            # **锁必须释放**，否则循环里的两个中止出口（限流重抛、"枚举后消失"）
            # 会把锁文件留在原地 ⇒ 一次瞬时限流就让之后每次重跑都被挡住，
            # 直到人工删文件——把自愈故障变成阻塞运维的故障。
            # replace 成功后 tmp 已经不存在，所以用标志判断而不是 exists()。
            # unlink 自身的异常必须吞掉：绝不能盖掉正在传播的原始异常。
            try:
                os.unlink(tmp)
            except OSError:
                pass
    print(f"旧 policy 已备份到 {BACKUP_PATH.name}（回滚用；**它不进 git**）")


def _verify_landed(iam, role_name, site_id, engine, tables):
    """写后复核（读回 + 功能模拟），**带上限重试**。→ 失败原因；全绿返回 None。

    **为什么要重试**：IAM 是最终一致的，策略模拟器尤其会滞后一次写入若干秒。
    不重试的话，一次**完全正确**的 --apply 会把传播延迟记成"落地的 policy 与
    期望不一致"（或模拟器拒绝）并退 1 —— 一次好跑却报红闸门，操作者会合理地
    读成"迁移把生产 IAM 改坏了"。

    **只重试读侧，绝不重发 `put_role_policy`**：它本来就幂等，重发只会把画面
    搅浑（分不清"传播慢"还是"写没生效"）。上限是硬的（`_VERIFY_RETRY_BACKOFF`），
    不做无限等待；用尽后按**原文**记失败，真正的不一致仍以同样方式报出来。
    """
    import common
    expected = json.loads(common.site_policy(site_id, engine, tables=tables))
    reason = None
    for delay in (None,) + _VERIFY_RETRY_BACKOFF:
        if delay is not None:
            time.sleep(delay)
        if _norm(_actual_policy(iam, role_name) or {}) != _norm(expected):
            reason = "落地的 policy 与期望不一致"
            continue
        problems = verify_access(iam, site_id, tables) if engine == "dynamodb" else []
        if problems:
            reason = f"{problems}"
            continue
        return None
    return reason


def apply_plans(iam, todo) -> list:
    """真写。→ [失败原因…]。**备份未落盘前，一笔 IAM 修改都不会发生。**"""
    if not todo:
        return []
    import common
    _persist_backup(iam, [name for name, _sid, _e, _t in todo])
    failed = []
    for name, site_id, engine, tables in todo:
        common.ensure_site_role(site_id, engine, tables=tables)

        # **写后复核**：backfill 与在线部署之间存在"读完→写入"的竞态
        # （用户并发部署新增了一张表，我们会把它覆盖掉）。这里重读一次 sites 行，
        # 若期间变过就按新值重算重写一次，然后逐项比对落地结果。
        fresh = common.get_site_consistent(site_id) or {}
        try:
            engine2, tables2 = plan_for(site_id, fresh)
        except NeedsManualReview as exc:
            failed.append(f"{site_id}: 写入期间 sites 行变得判不出来：{exc}")
            continue
        if (engine2, tables2) != (engine, tables):
            print(f"  站点 {site_id} 在写入期间被改动过，按新值重写：{tables2}")
            common.ensure_site_role(site_id, engine2, tables=tables2)
            engine, tables = engine2, tables2
        # 读回与功能模拟都带上限重试（IAM 最终一致，见 _verify_landed）。
        # 失败文案与加重试之前逐字一致。
        reason = _verify_landed(iam, name, site_id, engine, tables)
        if reason:
            failed.append(f"{site_id}: {reason}")
            continue
        print(f"  已重写并验证 {site_id}: engine={engine} tables={tables}")
    return failed


def simulate_active_sites(iam) -> list:
    """--check 的功能模拟段：对**全部** ACTIVE dynamodb 站点跑 verify_access。

    文本等值（check_roles）之外的第二层：模拟器会算 permissions boundary，
    反映真实判定而不是文本比较。v2 只对本次被重写的 targets 跑模拟——
    判成"合格"的角色一次功能验证都没有（Codex 指出）。只读，站点个位数。
    """
    import common
    problems = []
    for site_id in active_fullstack_site_ids():
        site = common.get_site_consistent(site_id) or {}
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            problems.append((ROLE_PREFIX + site_id, f"算不出期望 policy：{exc}"))
            continue
        if engine != "dynamodb":
            continue
        found = verify_access(iam, site_id, tables)
        if found:
            problems.append((ROLE_PREFIX + site_id, f"功能模拟失败：{found}"))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="真写（默认 dry-run）")
    parser.add_argument("--check", action="store_true", help="只跑闸门，不改任何东西")
    args = parser.parse_args()
    _load_env()
    import common
    iam = boto3.client("iam")

    if args.check:
        bad = check_roles(iam)
        # 文本已不一致时不叠加模拟结果（那些角色本来就要重写）；
        # 文本全绿才值得追问"真实判定也对吗"。
        if not bad:
            bad = simulate_active_sites(iam)
        print(f"不合格的 site-rt-* 角色：{len(bad)}")
        for name, reason in bad:
            print(f"  !! {name}: {reason}")
        return 1 if bad else 0

    targets = check_roles(iam)
    print(f"待收敛的角色：{len(targets)}")
    if not args.apply:
        # 紧跟计数打印，读到数字的人不可能漏掉。只在 dry-run 打：`--apply`
        # 结尾自己会跑一遍闸门并按结果决定退出码，那时这句话是错的。
        print(DRY_RUN_NOT_A_GATE)
    todo, manual = [], []
    for name, reason in targets:
        if reason.startswith((EXTRA_POLICY_REASON, MISSING_ROLE_REASON)):
            # 多余 policy：重写 site-scope 修不掉，自动删未知 policy 违反
            # "判不出就不猜"。角色缺失：先查为什么没了，不自动重建
            # （也保证 todo 里只有真实存在的角色，备份 null 语义唯一）。
            manual.append(f"{name}: {reason}")
            print(f"  跳过（需人工） {name}: {reason}")
            continue
        site_id = name[len(ROLE_PREFIX):]
        # **强一致读**：授权判定与 read-modify-write 都基于它
        site = common.get_site_consistent(site_id) or {}
        try:
            engine, tables = plan_for(site_id, site)
        except NeedsManualReview as exc:
            manual.append(str(exc))
            print(f"  跳过（需人工） {site_id}: {exc}")
            continue
        if not args.apply:
            print(f"  计划 {site_id}: engine={engine} tables={tables}（当前：{reason}）")
            continue
        todo.append((name, site_id, engine, tables))

    failed = apply_plans(iam, todo) if args.apply else []

    if manual:
        print(f"\n需人工处理 {len(manual)} 个：")
        for line in manual:
            print(f"  - {line}")
    if failed:
        print(f"\n验证失败 {len(failed)} 个：")
        for line in failed:
            print(f"  - {line}")

    if args.apply:
        left = check_roles(iam)
        print(f"\n闸门：不合格的角色 {len(left)}")
        if left:
            for name, reason in left:
                print(f"  !! {name}: {reason}")
            print("  未收敛完，S1 不算交付完成")
            return 1
        print("  0 —— 已全部收敛并通过功能验收")
    return 1 if (manual or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
