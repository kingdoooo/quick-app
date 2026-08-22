#!/usr/bin/env python3
"""只读体检：sites 表里有没有会被 S1 的严格解析拒绝的行。

**判据 100% 委托给 `permissions.effective_policy`，本文件不实现第二套。**
理由是实测过的假绿：只看 AttributeValue 顶层类型字母时，
`allowed_users = {"L": [{"N": "7"}]}` 会被判成"没问题"（L 是合法类型），
而 effective_policy 会拒（成员不是字符串、过不了 EMAIL_RE）。
体检报绿、部署后那个站点既不能改权限也不能部署。

**从仓库根跑，用系统 python3**（不要借 deployer/.venv/bin/python3——那个解释器的
CA 信任库是空的，每次 HTTPS 都 CERTIFICATE_VERIFY_FAILED，症状像网络故障）：

    python3 site-builder/scripts/audit_policy_rows.py

只读：只做 Scan，不写任何东西。部署 S1 之前必须重跑一次——行形态可能已变。
"""
import configparser
import pathlib
import sys

import boto3
from boto3.dynamodb.types import TypeDeserializer

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "deployer" / "functions"))

import permissions  # noqa: E402  与运行时**同一份**严格解析

_DESER = TypeDeserializer()


def _cfg():
    c = configparser.ConfigParser(interpolation=None)
    c.read(ROOT / "site-builder" / "config.ini")
    return c


def _plain(item: dict) -> dict:
    """AttributeValue dict → 普通 dict。

    `{"N": "0"}` 会反序列化成 `Decimal("0")` —— 正是 effective_policy 要拒的
    那个形态（`bool(Decimal(0))` 是 False，会被洗成"站主声明公开"）。
    """
    return {k: _DESER.deserialize(v) for k, v in item.items()}


def audit(rows: list) -> tuple:
    """→ (ACTIVE 行数, [(site_id, 拒绝原因)])。判据全部来自 effective_policy。"""
    active = [r for r in rows if r.get("status", {}).get("S") == "ACTIVE"]
    bad = []
    for raw in active:
        site = _plain(raw)
        try:
            permissions.effective_policy(site)
        except permissions.PolicyDataInvalid as exc:
            bad.append((site.get("site_id", "<unknown>"), str(exc)))
    return len(active), bad


def main() -> int:
    cfg = _cfg()
    ddb = boto3.client("dynamodb", region_name=cfg["Platform"]["region"].strip())
    rows, kw = [], {"TableName": cfg["Deployer"]["sites_table"].strip()}
    while True:
        resp = ddb.scan(**kw)
        rows += resp.get("Items", [])
        if "LastEvaluatedKey" not in resp:
            break
        kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    n_active, bad = audit(rows)
    print(f"sites 表共 {len(rows)} 行，其中 ACTIVE {n_active} 行")
    print(f"严格解析会拒绝的 ACTIVE 行：{len(bad)}")
    for site_id, reason in bad:
        print(f"  !! {site_id}: {reason}")
    if bad:
        print("\n上线 S1 会让上述站点既不能改权限也不能部署。先修这些行。")
        return 1
    print("  无 —— S1 上线不会卡住任何现有站点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
