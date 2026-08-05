#!/usr/bin/env bash
# 权限三件套真机验证的**服务端核对**工具（只读，不写任何数据）。
#
# 为什么需要它：MCP 工具的返回值是它自己说的，不能作为"数据真的写对了"的证据。
# 权限写入是 sites 表（真源）+ 路由表（投影）的原子双写，判断成功要看两张表是否
# 一致、permissions_rev 是否推进——工具返回 200 但投影没跟上时，症状是"UI 显示
# 改了、实际访问没变"，只看返回值发现不了。
#
# 用法：
#   ./check_permissions_state.sh <site_id>          # 打印两表状态
#   ./check_permissions_state.sh <site_id> --watch  # 每 5 秒刷新，观察投影生效
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$HERE/../config.ini"
SITE="${1:-}"
[ -n "$SITE" ] || { echo "用法: $0 <site_id> [--watch]"; exit 1; }

read_cfg() {
  python3 - "$CFG" "$1" "$2" <<'PY'
import configparser, sys
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1])
print(c[sys.argv[2]][sys.argv[3]].split("#")[0].strip())
PY
}
REGION="$(read_cfg Platform region)"
SITES_TABLE="$(read_cfg Deployer sites_table)"
ROUTING_TABLE="$(read_cfg Platform routing_table)"
ADMINS_TABLE="$(read_cfg Deployer admins_table)"

show() {
  # ConsistentRead：投影延迟与"读到旧副本"是两件事，混在一起没法判断
  local site route
  site="$(aws dynamodb get-item --table-name "$SITES_TABLE" --region "$REGION" \
    --consistent-read --key "{\"site_id\":{\"S\":\"$SITE\"}}" --output json 2>/dev/null || echo '{}')"
  route="$(aws dynamodb get-item --table-name "$ROUTING_TABLE" --region "$REGION" \
    --consistent-read --key "{\"subdomain\":{\"S\":\"app-$SITE\"}}" --output json 2>/dev/null || echo '{}')"
  admins="$(aws dynamodb scan --table-name "$ADMINS_TABLE" --region "$REGION" \
    --output json 2>/dev/null || echo '{}')"

  SITE_JSON="$site" ROUTE_JSON="$route" ADMINS_JSON="$admins" python3 <<'PY'
import json, os

def unwrap(av):
    if av is None: return None
    for k, v in av.items():
        if k == "S": return v
        if k == "N": return int(v) if "." not in v else float(v)
        if k == "BOOL": return v
        if k == "L": return [unwrap(x) for x in v]
        if k == "NULL": return None
        if k == "SS": return list(v)
        if k == "M": return {kk: unwrap(vv) for kk, vv in v.items()}
    return av

site = unwrap({"M": json.loads(os.environ["SITE_JSON"]).get("Item", {})}) or {}
route = unwrap({"M": json.loads(os.environ["ROUTE_JSON"]).get("Item", {})}) or {}
admins = [unwrap({"M": i}).get("email")
          for i in json.loads(os.environ["ADMINS_JSON"]).get("Items", [])]
admins = sorted(a for a in admins if a and a != "__count__")

if not site:
    print("  sites 表里没有这个 site_id")
else:
    print("  sites 表（权限真源）")
    for k in ("owner", "collaborators", "require_login", "allowed_users",
              "permissions_rev", "permissions_updated_by", "permissions_updated_at",
              "status"):
        if k in site:
            print(f"    {k:24s} = {site[k]!r}")

if not route:
    print("  路由表：无 item（站点未首次部署成功，写入走 fallback 只改真源）")
else:
    print("  路由表（Edge 实际读的投影）")
    for k in ("owner", "collaborators", "require_auth", "allowed_users",
              "permissions_rev", "route_mode", "api_target", "static_prefix"):
        if k in route:
            v = route[k]
            # api_target/static_prefix 只看有无，避免打印内部地址
            if k in ("api_target", "static_prefix"):
                v = f"<已设置 {len(str(v))} 字符>"
            print(f"    {k:24s} = {v!r}")

# 一致性判定。**只有前四对影响鉴权正确性**——Edge 读的就是路由表这几个字段，
# 不一致意味着"真源说私有、Edge 仍按公开放行"这类实际越权。
# permissions_rev 单独看：并发条件只查 sites 表那份（permissions.py 的
# ConditionExpression），路由表的 rev 是信息性投影，Edge 不读。
# migrate_permissions.py 只写了 sites 侧的 rev，所以刚迁移过的存量站点这里
# 会缺失——不是缺陷，下一次任何权限写入就会补上。
print("  一致性")
enforcing = [("owner", "owner"), ("collaborators", "collaborators"),
             ("require_login", "require_auth"), ("allowed_users", "allowed_users")]
if site and route:
    bad = 0
    for sk, rk in enforcing:
        sv, rv = site.get(sk), route.get(rk)
        # 空 list 与缺失等价；require_login 默认 True
        if sk == "collaborators":
            sv, rv = sv or [], rv or []
        if sk == "require_login":
            sv = True if sv is None else sv
        if sv != rv:
            print(f"    ✗ {sk}={sv!r} 但路由表 {rk}={rv!r}  ← 影响鉴权")
            bad += 1
    print("    ✓ 鉴权字段两表一致" if not bad
          else f"    {bad} 项不一致 —— Edge 与真源看到的策略不同（实际越权/误拦）")
    s_rev, r_rev = site.get("permissions_rev"), route.get("permissions_rev")
    if s_rev != r_rev:
        print(f"    ⓘ permissions_rev: sites={s_rev!r} 路由表={r_rev!r}"
              "（仅信息性投影，不影响鉴权；迁移过的站点会这样，下次权限写入即补齐）")
elif site:
    print("    （无路由 item，跳过比对）")

print(f"  平台管理员名单: {admins}")
PY
}

if [ "${2:-}" = "--watch" ]; then
  while true; do
    printf '\033[2J\033[H'
    echo "site_id=$SITE  ($(date +%H:%M:%S))"
    show
    sleep 5
  done
else
  echo "site_id=$SITE"
  show
fi
