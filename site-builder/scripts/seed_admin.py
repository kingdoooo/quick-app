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
    return {"email": email, "already_admin": already, "written": not already}


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


if __name__ == "__main__":
    main()
