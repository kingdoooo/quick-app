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
    # add_admin 本身幂等（条件写 + __count__ 事务），重复跑不会让计数虚高
    permissions.add_admin(email, added_by="seed_admin.py")
    audited = _audit_row_present(email) if not already else None
    return {"email": email, "already_admin": already, "written": not already,
            "audited": audited}


def _audit_row_present(email: str) -> bool:
    """写完之后**读回**确认审计行真的落了。

    为什么不能只靠"没抛异常"：`ops_log.record` 是刻意 best-effort 的
    （异常吞掉、只打 traceback、不 re-raise —— 平台级裁定：业务动作已经成功，
    审计失败不该改变它的结果）。缺 `OPS_LOG_TABLE` 只是它失败的**一个**原因；
    表不存在、`AccessDenied`、被限流都会走同一条静默路径。
    而"第一个管理员"是平台上权限最大的一次授予，**它没有审计行 = 从审计上看它从未发生**。

    所以这里不改 `ops_log` 的全局语义（那会让每个调用点都变成"审计挂了就整件事失败"），
    只在**这一处**把结果读回来，让调用方能响亮地报告"授权成功但审计缺失"。
    读回本身失败也返回 False —— 判不了就当没有，方向是保守的。
    """
    table = os.environ.get("OPS_LOG_TABLE")
    if not table:
        return False
    try:
        import boto3
        from boto3.dynamodb.conditions import Key
        rows = boto3.resource("dynamodb").Table(table).query(
            KeyConditionExpression=Key("target").eq(f"admins:{email}"),
            ConsistentRead=True)["Items"]
    except Exception:                      # noqa: BLE001 —— 读不出来就当没有
        return False
    return any(r.get("action") == "add_admin" for r in rows)


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
        print(f"  ⚠️  管理员已写入，但 site-ops-log 里读不到 add_admin 审计行。"
              f"\n      授权本身有效（上面的名单就是证据），缺的是审计留痕。"
              f"\n      常见原因：ops-log 表还不存在（④ 的栈没部完）、本机凭据缺"
              f"该表的 dynamodb:PutItem、或被限流。"
              f"\n      处置：修好之后在控制台把该管理员删掉再重新添加一次"
              f"（重跑本脚本只会走幂等分支，不会补这条审计行）。")
        return 0
    return 0


if __name__ == "__main__":
    main()
