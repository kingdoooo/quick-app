#!/usr/bin/env python3
"""只读体检：sites 表里有没有会被 S1 的严格解析拒绝的行。

**判据 100% 委托给 `permissions.effective_policy`，本文件不实现第二套。**
理由是实测过的假绿：只看 AttributeValue 顶层类型字母时，
`allowed_users = {"L": [{"N": "7"}]}` 会被判成"没问题"（L 是合法类型），
而 effective_policy 会拒（成员不是字符串、过不了 EMAIL_RE）。
体检报绿、部署后那个站点既不能改权限也不能部署。

**退出码只由 ACTIVE 行决定**（闸门该拦的是"正在被服务的站点会不会卡住"）。
非 ACTIVE 行同样逐行判定，但报成**警告**：它们没有路由、当前不被服务，
只在被重新部署时才相关。两者的判据是同一处（`_refusals`）。
不要把退出码 0 读成"整张表都干净"——它的意思是"没有 ACTIVE 站点会被卡住"。

**从仓库根跑，用系统 python3**（不要借 deployer/.venv/bin/python3——那个解释器的
CA 信任库是空的，每次 HTTPS 都 CERTIFICATE_VERIFY_FAILED，症状像网络故障）：

    python3 site-builder/scripts/audit_policy_rows.py

只读：只做 Scan，不写任何东西。部署 S1 之前必须重跑一次——行形态可能已变。
"""
import collections
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


def _refusals(rows: list) -> list:
    """→ [(site_id, status, 拒绝原因)]。**全脚本唯一的判定处。**

    ACTIVE 闸门与非 ACTIVE 警告都从这里取结论，所以两条报告路径不可能给出
    互相矛盾的判据——本脚本存在的理由就是"判据只有一份"，报告分两路时尤其
    不能在这里破功。
    """
    bad = []
    for raw in rows:
        site = _plain(raw)
        try:
            permissions.effective_policy(site)
        except permissions.PolicyDataInvalid as exc:
            bad.append((site.get("site_id", "<unknown>"),
                        site.get("status", ""), str(exc)))
    return bad


def audit(rows: list) -> tuple:
    """→ (ACTIVE 行数, [(site_id, 拒绝原因)])。判据全部来自 effective_policy。

    **只看 ACTIVE，且退出码只由它驱动**：闸门该拦的是"正在被服务的站点会不会
    卡住"。把不在服务的行算进退出码，就是用一堆已下线的历史行去拦发布。
    非 ACTIVE 行的拒绝由 `audit_non_active` 单独报告成警告——不进闸门，
    但必须可见（原先它们既不进闸门也不可见，于是绿字承诺了证据覆盖不到的范围）。
    """
    active = [r for r in rows if r.get("status", {}).get("S") == "ACTIVE"]
    return len(active), [(sid, why) for sid, _st, why in _refusals(active)]


def audit_non_active(rows: list) -> list:
    """→ [(site_id, status, 拒绝原因)]：非 ACTIVE 行里会被严格解析拒绝的。

    **故意不进退出码。** 这些行没有路由、当前不被服务，所以"会被拒"不等于
    "现在坏了"。它们只在被重新部署时才相关，见 main 打印的说明。
    """
    return _refusals([r for r in rows
                      if r.get("status", {}).get("S") != "ACTIVE"])


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
    by_status = collections.Counter(
        r.get("status", {}).get("S", "<无 status>") for r in rows)
    print(f"sites 表共 {len(rows)} 行，其中 ACTIVE {n_active} 行")
    # 按 status 全量报数，而不是只挑几个类名硬编码：sites 行的 status 只有三个
    # 写入点（建站 DEPLOYING、mark_job 成功 ACTIVE、undeploy DELETED），
    # 但把类名写死在这里的话，将来多一个 status 就会静默漏报。
    print("各 status 行数：" + "、".join(
        f"{s} {n}" for s, n in sorted(by_status.items())))
    # DEPLOYING 这一类值得单独点出来：这些行还没被 register_route 的
    # `_seed_permissions_if_absent` 补过权限字段（建站只写 owner/name/status/
    # created_at），所以**形态上必然**会被严格解析拒绝。它为 0 只说明此刻没有
    # 在途的首次部署，不是"这一类不会出现"——绿字不能被读成对这个窗口的承诺。
    print(f"  （其中 DEPLOYING {by_status.get('DEPLOYING', 0)} 行：尚未 seed 过"
          "权限字段，形态上必然被拒；为 0 只代表此刻没有在途首次部署）")

    # ACTIVE 段的结论紧跟自己的计数打印，**不要挪到警告块之后**：那样操作员
    # 会在十几行非 ACTIVE 明细之后读到一句缩进的"无 ——"，看起来像是在给那些
    # 明细下结论，而它回答的是上面这个 ACTIVE 计数。
    print(f"严格解析会拒绝的 ACTIVE 行：{len(bad)}")
    for site_id, reason in bad:
        print(f"  !! {site_id}: {reason}")
    if bad:
        print("  上线 S1 会让上述站点既不能改权限也不能部署。先修这些行。")
    else:
        # 绿字只承诺被检查过的范围。原先写的是"任何现有站点"，而证据只覆盖
        # ACTIVE 行——真机 77 行里 70 行没被评价，其中 15 行会被拒，那句是错的。
        print("  无 —— S1 上线不会卡住任何 ACTIVE 站点")

    # ---- 非 ACTIVE 行：报成警告，不进退出码 ----
    # 它们必须出现在 stdout 里。Task 10 的操作员读到的就只有这段输出
    # （本仓库的 markdown 报告是 gitignored 的，那时不存在），所以"绿"字旁边
    # 没有这段的话，他不可能知道有 15 行没被评价过。
    others = audit_non_active(rows)
    if others:
        per_status = collections.Counter(st for _sid, st, _why in others)
        detail = "、".join(f"{s} {n}" for s, n in sorted(per_status.items()))
        print(f"\n非 ACTIVE 行中会被拒绝的：{len(others)}（{detail}）")
        print("  这些行当前**不被服务**（没有路由），所以现在没有任何东西是坏的。"
              "它们只在被**重新部署**时才相关，而一次成功的重新部署会把该行写回"
              " ACTIVE（mark_job 无条件写 status=ACTIVE）。")
        print("  其中「字段缺失」这类不会拦住部署：register_route 先 seed 再投影"
              "（`_seed_permissions_if_absent` 逐字段 if_not_exists 补缺，之后才"
              "强一致重读并调 effective_policy），缺的字段会被补上并继续。")
        print("  「类型写错」这类 seed 补不了（if_not_exists 不覆盖已有值），"
              "那种拒绝是故意的，必须人工修那一行。逐行原因如下：")
        for site_id, status, reason in others:
            print(f"  -- {site_id} ({status}): {reason}")

    # **退出码只看 ACTIVE**（`others` 故意不参与）：把已下线的历史行算进闸门，
    # 就是用一堆不被服务的行去拦发布。判定集中在这一处，不散在上面的分支里。
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
