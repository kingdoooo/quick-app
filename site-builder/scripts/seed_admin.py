#!/usr/bin/env python3
"""把 config.ini [Platform] admin_seed 写进 site-admins 表。幂等可重跑。

为什么需要这个脚本：CDK 只建 site-admins 表（infra/app.py 的 Admins），
**建表不等于有管理员**。`permissions.add_admin` 在二期之前只有测试在调，
生产路径无人调用 → 表部署出来是空的 → 谁都不是 admin：
  · 任何站点的 owner 离职/误删自己的权限后，平台没有代管入口；
  · M3 控制台的管理员视图空着，且无法从 UI 添加第一个（添加管理员本身要
    admin 权限，是个死锁）。
所以第一个管理员必须由部署时的带凭证操作注入，这就是本脚本。

之后的管理员增删走控制台（M3），不需要改 config.ini 重部署。

用法：
    python3 site-builder/scripts/seed_admin.py           # dry-run，只报告
    python3 site-builder/scripts/seed_admin.py --apply
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))


def _load_config() -> configparser.ConfigParser:
    """从 config.ini 填好 permissions 需要的环境变量。

    **直接赋值，不用 setdefault**：config.ini 是部署脚本的唯一取值来源
    （CLAUDE.md），setdefault 会让 shell 里残留的旧 ADMINS_TABLE 静默改写
    写入目标——把管理员种进另一张表，而输出显示成功。
    """
    path = HERE.parent / "config.ini"
    if not path.exists():
        raise SystemExit(f"找不到 {path}——从 config.ini.example 复制并填好再跑")
    cfg = configparser.ConfigParser()
    cfg.read(path)
    # 一期就存在的 config.ini 没有二期新增的键（admins_table 是其中之一）。
    # 裸 KeyError('admins_table') 对操作者毫无指向性，明确告诉他补哪一行。
    # 平台自己的审计表**不是配置项**：deployer 栈按字面量建 `site-ops-log`、
    # `deploy_panel` 按同一字面量下发，所以这里也只能是同一个字面量
    # （与 ensure_fixture_site._ENV_LITERALS 同源；那边的注释是这条约定的说明）。
    # **不给它的后果是静默的**：`permissions.add_admin` 里的 ops-log 写入是
    # best-effort（异常被吞、只打 traceback、退 0），于是"第一个管理员"——平台上
    # 权限最大的那一次授予——**写成了却没有审计行**，而操作者看到的是一条
    # KeyError traceback，读起来像失败。同样用直接赋值，理由见上面。
    os.environ["OPS_LOG_TABLE"] = "site-ops-log"
    try:
        os.environ["ADMINS_TABLE"] = cfg["Deployer"]["admins_table"]
        os.environ["SITES_TABLE"] = cfg["Deployer"]["sites_table"]
        os.environ["AWS_DEFAULT_REGION"] = cfg["Platform"]["region"]
    except KeyError as e:
        raise SystemExit(
            f"config.ini 缺少 {e}——二期新增的键，一期建的 config.ini 里没有。"
            "\n对照 config.ini.example 补齐 [Deployer] admins_table "
            "（默认 site-admins）与 [Platform] admin_seed。") from e
    return cfg


def seed(email: str, *, dry_run: bool = True) -> dict:
    """校验 → 幂等写入。返回给调用方/测试断言的报告。"""
    import permissions

    if not email:
        raise SystemExit(
            "config.ini [Platform] admin_seed 为空——填第一个平台管理员邮箱再跑。"
            "\n没有管理员意味着 owner 失联的站点无人可代管，且 M3 控制台无法"
            "从 UI 添加第一个管理员（添加管理员本身需要 admin 权限）。")
    # 与 add_admin 同一个校验；提前做是为了 dry-run 也能报错，
    # 而不是 --apply 时才发现邮箱拼错
    if not permissions.EMAIL_RE.fullmatch(email):
        raise SystemExit(f"admin_seed 不是合法邮箱: {email!r}")

    already = permissions.is_admin(email)
    if dry_run:
        return {"email": email, "already_admin": already, "written": False}
    # **写之前**先记下已有的审计行主键：`add_admin` 的审计 target 是
    # `admins:{email}`，而同一个邮箱完全可能**历史上**被加过又删过
    # （加第二个管理员 → 删第一个 → 再加回来）。只问"这个邮箱有没有 add_admin 行"
    # 会把那条历史行当成本次的 ⇒ 审计其实没落却报 audited=True。
    before = _audit_keys(email)
    # add_admin 本身幂等（条件写 + __count__ 事务），重复跑不会让计数虚高
    permissions.add_admin(email, added_by="seed_admin.py")
    audited = _audit_row_landed(email, before) if not already else None
    return {"email": email, "already_admin": already, "written": not already,
            "audited": audited}


# 审计行的排序键。`ops_log` 用 `{ts}#{actor}#{4 字节随机}` ⇒ 同一秒的两条也不同键，
# 所以"写前快照 → 写后差集"能精确指认**本次**那一行，不必改 `ops_log.record` 的签名
# （它是共享的平台函数，被很多调用点用；为了这一处改它的返回值会波及全部调用方）。
_AUDIT_SORT_KEY = "ts_actor"


def _audit_keys(email: str) -> set | None:
    """`admins:{email}` 这个分区下现有审计行的排序键集合；读不出来返回 None。

    None 与 `set()` 是两种不同的状态，不能混：前者是"我没法判定"，
    后者是"确实一条都没有"。混掉会让"读不出来"变成"新写了一行"的假绿。
    """
    table = os.environ.get("OPS_LOG_TABLE")
    if not table:
        return None
    try:
        import boto3
        from boto3.dynamodb.conditions import Key
        rows = boto3.resource("dynamodb").Table(table).query(
            KeyConditionExpression=Key("target").eq(f"admins:{email}"),
            ConsistentRead=True)["Items"]
    except Exception:                      # noqa: BLE001 —— 判不了就说判不了
        return None
    return {r.get(_AUDIT_SORT_KEY) for r in rows}


def _audit_row_landed(email: str, before: set | None) -> bool:
    """**本次**这一条 `add_admin` 审计行是否真的落了。

    为什么不能只靠"没抛异常"：`ops_log.record` 是刻意 best-effort 的
    （异常吞掉、只打 traceback、不 re-raise —— 平台级裁定：业务动作已经成功，
    审计失败不该改变它的结果）。缺 `OPS_LOG_TABLE` 只是它失败的**一个**原因；
    表不存在、`AccessDenied`、被限流都会走同一条静默路径。
    而"第一个管理员"是平台上权限最大的一次授予，**它没有审计行 = 从审计上看它从未发生**。

    判据是**写前/写后的差集**里有没有一条本次形态的行：`action == "add_admin"`
    且 `actor == "seed_admin.py"`。只看"这个邮箱有没有 add_admin 行"是不够的
    —— 同一邮箱被加过又删过时那条历史行会冒充本次（Codex 复审复现过）。

    任一侧读不出来（None）⇒ 返回 False：判不了就当没有，方向是保守的。
    """
    if before is None:
        return False
    after = _audit_keys(email)
    if after is None:
        return False
    new_keys = after - before
    if not new_keys:
        return False
    table = os.environ["OPS_LOG_TABLE"]
    try:
        import boto3
        from boto3.dynamodb.conditions import Key
        rows = boto3.resource("dynamodb").Table(table).query(
            KeyConditionExpression=Key("target").eq(f"admins:{email}"),
            ConsistentRead=True)["Items"]
    except Exception:                      # noqa: BLE001
        return False
    return any(r.get(_AUDIT_SORT_KEY) in new_keys
               and r.get("action") == "add_admin"
               and r.get("actor") == "seed_admin.py"
               for r in rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写入（默认只报告）")
    args = ap.parse_args()
    cfg = _load_config()
    report = seed(cfg["Platform"].get("admin_seed", "").strip(),
                  dry_run=not args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    if report["already_admin"]:
        print(f"[{mode}] {report['email']} 已是管理员，无需写入")
    elif report["written"]:
        print(f"[{mode}] 已添加管理员 {report['email']}")
    else:
        print(f"[{mode}] 将添加管理员 {report['email']}（加 --apply 实际写入）")

    import permissions
    print(f"  当前管理员名单: {permissions.list_admins()}")

    # **审计缺失要响亮**：`ops_log.record` 是 best-effort（异常吞掉、不 re-raise），
    # 所以"授权成功"与"审计落了"是两件独立的事。第一个管理员是平台上权限最大的一次
    # 授予——它没有审计行就等于从审计上看它从未发生。这里不让脚本失败（管理员**确实**
    # 已经写进去了，退非零会把操作者引向"重跑"，而重跑只会走幂等分支、不补那条行），
    # 而是把它作为一条必须处置的告警打出来。
    if report["written"] and report.get("audited") is False:
        print(f"  ⚠️  管理员已写入，但 site-ops-log 里读不到**本次**的 add_admin 审计行。"
              f"\n      授权本身有效（上面的名单就是证据），缺的只是审计留痕。"
              f"\n      常见原因：ops-log 表还不存在（④ 的栈没部完）、本机凭据缺该表的"
              f" dynamodb:PutItem、或被限流。"
              f"\n      **补录不能靠重跑本脚本**（它会走幂等分支，不补审计行），也**不能**"
              f"靠「删掉再加回来」——"
              f"\n      第一个管理员通常是唯一管理员，而 remove_admin 明确拒绝删除最后一个。"
              f"\n      处置：先修好上面那个原因，然后从控制台**再加一个**管理员"
              f"（那一次会留下审计行、且能证明管道已通）；"
              f"\n      本次这条缺失属于既成事实，记进你自己的变更记录即可。")
    return 0


if __name__ == "__main__":
    main()
