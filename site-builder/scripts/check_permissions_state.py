#!/usr/bin/env python3
"""核对 sites 表（权限真源）与路由表（Edge 读的投影）是否一致。只读，不写数据。

为什么需要它：MCP 工具的返回值是它自己说的，证明不了数据真写对了。权限写入是
双表原子写，失败形态常是"工具返回成功、投影没跟上"，表现为 UI 显示改了但实际
访问没变——只看工具返回值发现不了。

**退出码（验收编排只看这个）**：
  0 = 鉴权字段两表一致
  1 = AWS 调用失败 / 站点不存在 / 内部错误 —— **状态不可信，不是"检查通过"**
  2 = 确实发现鉴权字段不一致

为什么是 Python 而不是 shell：这段逻辑要精确控制退出码并区分三种结果，用 bash
写时连续踩了四个陷阱（子 shell 里的变量赋值传不回父 shell、`set -u` 下
`[ "$RC" -ne 0 ]` 的短路求值、**本机 aws CLI 在 API 错误时也可能返回 exit 0**、
失败检测与调用的先后顺序）。每修一个又冒出下一个，说明选错了工具而不是写错了
代码（2026-08-06）。

用法：
    ./check_permissions_state.py <site_id>
    ./check_permissions_state.py <site_id> --watch    # 每 5 秒刷新，看投影生效
"""
import argparse
import configparser
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
CFG_PATH = HERE.parent / "config.ini"

# 影响鉴权的字段对：(sites 表字段, 路由表字段)。
# 这几项不一致意味着"真源说私有、Edge 仍按公开放行"这类实际越权/误拦。
ENFORCING_PAIRS = [("owner", "owner"), ("collaborators", "collaborators"),
                   ("require_login", "require_auth"),
                   ("allowed_users", "allowed_users")]


class AwsError(RuntimeError):
    pass


def read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].strip()


def aws_json(*args: str) -> dict:
    """跑一条 aws CLI 并解析 JSON。任何异常都抛 AwsError。

    **不能只看 returncode**：本机 aws CLI 实测在 API 错误时也可能返回 0
    （UnrecognizedClientException 那次就是），所以同时校验 stdout 是合法 JSON。
    这一条对任何用 `|| echo '{}'` 或 `$? -ne 0` 判 AWS 失败的脚本都成立。
    """
    import json
    proc = subprocess.run(["aws", *args, "--output", "json"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise AwsError(f"exit {proc.returncode}: "
                       f"{(proc.stderr or proc.stdout).strip().splitlines()[-1:]}")
    # **空 stdout 是错误，不是"空结果"**：本函数用到的三条命令都不会返回空输出
    # ——get-item 找不到 key 时返回的是 `{}` 这三个字符，scan 返回带 Items 的对象。
    # 真正的空 stdout 只在 CLI 出错时出现（而它可能仍 exit 0）。原来的
    # `proc.stdout or "{}"` 兜底正好把这种情况解析成合法空对象，于是"读路由表
    # 失败"被报成"路由确实不存在"→ report() 返回 0 说检查通过
    # （Codex 复审 2026-08-07）。这与本函数开头那条"不能只看 returncode"是同一
    # 个陷阱的两半：既要校验输出是 JSON，也不能给失败凑一个合法 JSON 出来。
    if not proc.stdout.strip():
        raise AwsError("stdout 为空但 exit 0（CLI 出错的典型形态）: "
                       f"{(proc.stderr or '').strip()[:200]!r}")
    try:
        return json.loads(proc.stdout)
    except ValueError:
        head = (proc.stdout or proc.stderr).strip().splitlines()
        raise AwsError(f"输出不是 JSON: {head[:1]}") from None


def unwrap(av):
    """DynamoDB AttributeValue → 普通值。只处理本表用到的类型。"""
    if av is None:
        return None
    for k, v in av.items():
        if k == "S":
            return v
        if k == "N":
            return int(v) if "." not in v else float(v)
        if k == "BOOL":
            return v
        if k == "L":
            return [unwrap(x) for x in v]
        if k == "SS":
            return list(v)
        if k == "NULL":
            return None
        if k == "M":
            return {kk: unwrap(vv) for kk, vv in v.items()}
    return av


def unwrap_item(raw: dict) -> dict:
    """整条 DynamoDB item → 普通 dict（顶层一定是 M，收窄类型便于静态检查）。"""
    out = unwrap({"M": raw})
    return out if isinstance(out, dict) else {}


def fetch(site_id: str, region: str, sites_t: str, route_t: str, admins_t: str):
    # ConsistentRead：投影延迟与"读到旧副本"是两件事，混在一起没法判断
    site = unwrap_item(aws_json(
        "dynamodb", "get-item", "--table-name", sites_t, "--region", region,
        "--consistent-read", "--key",
        '{"site_id":{"S":"%s"}}' % site_id).get("Item", {}))
    route = unwrap_item(aws_json(
        "dynamodb", "get-item", "--table-name", route_t, "--region", region,
        "--consistent-read", "--key",
        '{"subdomain":{"S":"app-%s"}}' % site_id).get("Item", {}))
    admins_raw = aws_json("dynamodb", "scan", "--table-name", admins_t,
                          "--region", region).get("Items", [])
    emails = [unwrap_item(i).get("email") for i in admins_raw]
    admins = sorted(e for e in emails
                    if isinstance(e, str) and e and e != "__count__")
    return site, route, admins


def report(site: dict, route: dict, admins: list) -> int:
    """打印状态并返回退出码（0 一致 / 1 不可信 / 2 不一致）。"""
    if not site:
        print("  ✗ sites 表里没有这个 site_id —— 站点不存在，或用 deploy_fixture 建的"
              "旧站点漏写了 sites 记录")
        return 1
    print("  sites 表（权限真源）")
    for k in ("owner", "collaborators", "require_login", "allowed_users",
              "permissions_rev", "permissions_updated_by", "permissions_updated_at",
              "status"):
        if k in site:
            print(f"    {k:24s} = {site[k]!r}")

    if not route:
        # **"无 route" 的对错取决于 status**（Codex 复审 2026-08-07）：
        #   DEPLOYING/未部署 —— 正常，权限写入走 fallback 只改真源；
        #   DELETED         —— 正常，undeploy 就是删路由 + 置 DELETED；
        #   ACTIVE          —— 事故：Edge 对它一律 404，任何访问策略都无从执行
        #                      （路由被误删、或 register_route 失败而 status 已置）。
        # 原来一律返回 0，把最后那种情况报成"检查通过"。
        status = site.get("status", "")
        print(f"  路由表：无 item（sites.status={status!r}）")
        print(f"  平台管理员名单: {admins}")
        if status == "ACTIVE":
            print("    ✗ status=ACTIVE 却没有路由 item —— Edge 对该站点只会 404，"
                  "鉴权策略无从执行（不是'尚未部署'，是路由丢了）")
            return 2
        print("    （尚未首次部署成功或已下线，无 route 属正常）")
        return 0

    print("  路由表（Edge 实际读的投影）")
    for k in ("owner", "collaborators", "require_auth", "allowed_users",
              "permissions_rev", "route_mode", "api_target", "static_prefix"):
        if k in route:
            v = route[k]
            if k in ("api_target", "static_prefix"):
                v = f"<已设置 {len(str(v))} 字符>"
            print(f"    {k:24s} = {v!r}")

    print("  一致性")
    bad = 0
    for sk, rk in ENFORCING_PAIRS:
        sv, rv = site.get(sk), route.get(rk)
        if sk == "collaborators":
            sv, rv = sv or [], rv or []
        if sk == "require_login":
            sv = True if sv is None else sv
        if sv != rv:
            print(f"    ✗ {sk}={sv!r} 但路由表 {rk}={rv!r}  ← 影响鉴权")
            bad += 1
    if bad:
        print(f"    {bad} 项不一致 —— Edge 与真源看到的策略不同（实际越权/误拦）")
    else:
        print("    ✓ 鉴权字段两表一致")

    s_rev, r_rev = site.get("permissions_rev"), route.get("permissions_rev")
    if s_rev != r_rev:
        # 仅信息性：并发条件只查 sites 表那份，Edge 不读路由表的 rev。
        # migrate_permissions.py 只写 sites 侧，所以刚迁移过的站点必然如此。
        print(f"    ⓘ permissions_rev: sites={s_rev!r} 路由表={r_rev!r}"
              "（仅信息性，不影响鉴权；迁移过的站点会这样，下次权限写入即补齐）")

    print(f"  平台管理员名单: {admins}")
    return 2 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("site_id")
    ap.add_argument("--watch", action="store_true",
                    help="每 5 秒刷新（观察边缘投影生效）；此模式不用退出码表达结果")
    a = ap.parse_args()

    region = read_cfg("Platform", "region")
    tables = (read_cfg("Deployer", "sites_table"),
              read_cfg("Platform", "routing_table"),
              read_cfg("Deployer", "admins_table"))

    while True:
        if a.watch:
            print("\033[2J\033[H", end="")
        print(f"site_id={a.site_id}"
              + (f"  ({time.strftime('%H:%M:%S')})" if a.watch else ""))
        try:
            rc = report(*fetch(a.site_id, region, *tables), )
        except AwsError as e:
            print(f"  ✗ AWS 调用失败: {e}")
            print("结果：AWS 调用失败 —— 状态不可信，请检查凭证与表名")
            if not a.watch:
                return 1
            rc = 1
        else:
            if not a.watch:
                print({0: "结果：两表鉴权字段一致",
                       1: "结果：检查未能完成 —— 状态不可信",
                       2: "结果：发现鉴权字段不一致"}[rc])
                return rc
        time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
