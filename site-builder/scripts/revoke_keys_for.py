#!/usr/bin/env python3
"""离职 offboarding：吊销某个 email 的全部 API Key（带审计）。

**为什么需要它**（Codex 审查 2026-08-13 P1-2）：API Key 绑的是 email 字符串，
**不联动 IdP 账号状态**。所以员工离职、IdP 账号被禁用之后，OAuth 那条路走不通了，
但他手里的 Key 仍然有效——还能建新站点、重新部署、改自己仍有权限站点的策略，
并持续产生 AWS 费用。

而控制台**给不了**这个能力：`api.do_list_keys` 只查调用者自己的 email 分区，
`keystore.revoke` 硬性要求 `row.email == actor`，管理员手里只有一个全局总开关
（关掉会同时中断所有正常用户，不能当常规 offboarding 手段）。
DEPLOY.md 曾写"控制台按 owner 列得出来"——**那是错的**，本脚本是那句话的落地。

**为什么是脚本而不是控制台端点**："能吊销任意人的 Key"放进公网端点会多出一整套
授权面（谁算 admin、CSRF、防枚举）；而 offboarding 本来就是带 AWS 凭证的运维动作。
本脚本要凭证，因此攻击面是 IAM 而不是 HTTP。

**默认 dry-run**：不带 `--yes` 只打印将要吊销哪些，不做任何写入。吊销**不删行**
（置 `revoked`），所以审计痕迹留着；每一把单独落一条 ops_log，action 是
`revoke_api_key_offboard`（与自助吊销分开，事后能区分"本人吊销"与"离职被吊销"）。

**不打印明文**——明文服务端根本不存（表里只有 hash），这里能看到的只有 key_id
与备注名，两者都不是秘密。

用法（**从仓库根跑**）：
    python3 site-builder/scripts/revoke_keys_for.py someone@example.com          # dry-run
    python3 site-builder/scripts/revoke_keys_for.py someone@example.com --yes    # 真吊销
"""
import argparse
import configparser
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CFG_PATH = HERE.parent / "config.ini"
sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="吊销某个 email 的全部 API Key（离职 offboarding，带审计）")
    ap.add_argument("email", help="要吊销的用户邮箱")
    ap.add_argument("--yes", action="store_true",
                    help="真的执行；不带它只做 dry-run")
    ap.add_argument("--actor", default="",
                    help="审计里记的操作者（默认取当前 AWS 身份）")
    args = ap.parse_args()

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(CFG_PATH)
    if not cfg.sections():
        # configparser 对缺失文件是静默的——不断言就会拿着空配置往下跑
        sys.exit(f"{CFG_PATH} 读不到任何段，请从仓库根用绝对路径跑")
    region = cfg["Platform"]["region"].split("#")[0].strip()

    import api_key_config
    if not api_key_config.api_key_enabled(cfg):
        sys.exit("config.ini 无 [ApiKey] 段 = API Key 组件未启用，没有 Key 可吊销")

    # keystore / ops_log 的表名靠环境变量（它们本来跑在 Lambda 里）
    os.environ.setdefault("AWS_DEFAULT_REGION", region)
    os.environ.setdefault("API_KEYS_TABLE", "site-api-keys")
    os.environ.setdefault("OPS_LOG_TABLE", "site-ops-log")

    import boto3
    import keystore

    actor = args.actor
    if not actor:
        # 审计里署名"当前 AWS 身份"而不是一个写死的字符串：谁跑的就记谁
        actor = boto3.client("sts").get_caller_identity()["Arn"].rsplit("/", 1)[-1]
        actor = f"offboard-cli:{actor}"

    rows = keystore.list_for(args.email)
    if not rows:
        print(f"{args.email} 名下没有任何 Key（含已吊销的）——无需操作")
        return 0

    live = [r for r in rows if not r.get("revoked")]
    print(f"{args.email} 名下 {len(rows)} 把 Key，其中 {len(live)} 把仍然有效：")
    for r in rows:
        state = "已吊销" if r.get("revoked") else "**有效**"
        print(f"  {r.get('key_id')}  {state}  备注={r.get('name','')!r}  "
              f"创建={str(r.get('created_at',''))[:19]}  "
              f"最后使用={str(r.get('last_used_at') or '从未')[:19]}")

    if not live:
        print("\n全部已经是吊销状态，无需操作")
        return 0
    if not args.yes:
        print(f"\n【dry-run】未做任何写入。确认后加 --yes 执行。")
        return 0

    print(f"\n吊销中（actor={actor}）…")
    out = keystore.revoke_all_for(args.email, actor=actor)
    print(f"  已吊销: {out['revoked']}")
    if out["already_revoked"]:
        print(f"  本来就已吊销: {out['already_revoked']}")

    # 读回核对：不信返回值，重新查一遍表
    after = keystore.list_for(args.email)
    still_live = [r.get("key_id") for r in after if not r.get("revoked")]
    if out["failed"] or still_live:
        # **部分吊销是真实存在的中间态**，绝不能静默当成成功——那等于报告
        # "已 offboard"而实际还有活着的 Key
        print(f"\n❌ 未完成：失败 {out['failed']}，读回仍有效 {still_live}")
        print("   请重跑本脚本（吊销是幂等的）；持续失败请检查当前身份对 "
              "site-api-keys 的 UpdateItem 权限")
        return 1
    print(f"\n✅ {args.email} 名下已无有效 Key（读回核对通过）")
    print("   注意：这不影响他已部署站点的存在，只断掉用 Key 调部署 MCP 的通道。"
          "\n   站点的所有权转移/下线是另一件事（控制台或 MCP 工具）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
