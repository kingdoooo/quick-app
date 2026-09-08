#!/usr/bin/env python3
"""把 deployer 栈建出来的会话签名 CMK 变成可粘贴进 config.ini 的 `[SessionKey:<kid>]` 小节（spec §11.6）。

    site-builder/deployer/.venv/bin/python3 site-builder/scripts/session_key_fingerprint.py --from-stack
    site-builder/deployer/.venv/bin/python3 site-builder/scripts/session_key_fingerprint.py \
        --kid site-rs-v1 --arn arn:aws:kms:…:key/…

只读（DescribeKey + GetPublicKey），不写 config；形态四项（KeySpec / KeyUsage / SigningAlgorithms / SPKI）
在这里就校验——指纹算错的症状是三个部署脚本的 precheck 全部拒绝部署。

**解释器是这一族 `scripts/*.py` 里的例外**：它经 `session_kms` → `session` 用到 `cryptography`
（第 4 项就是"这段 DER 真的是一个合规的 RSA-2048 SPKI"），而 CLAUDE.md 给宿主 `python3` 装的
只有 boto3 + pip-system-certs ⇒ 裸 `python3` 跑会 `ModuleNotFoundError: cryptography`。
用上面那个 venv 解释器（实测可跑），或给宿主 `python3` 补上 cryptography。

**回填是人做的**，这个脚本只打印。自动改写 config 会让"部署前核对"这道闸门失去意义：那时 config
与 KMS 天然一致，而没人确认过换的是哪一把 key。
"""
from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
try:
    import session_kms  # noqa: E402
except ModuleNotFoundError as exc:      # 多半是 cryptography（见文件头「解释器」那段）
    raise SystemExit(
        f"缺依赖 {exc.name}：本脚本要做形态四项校验，其中公钥侧经 session_kms → session 用到 "
        "cryptography，而宿主 python3 默认只有 boto3。\n"
        "改用 site-builder/deployer/.venv/bin/python3 跑，或给宿主 python3 补上 cryptography。"
    ) from None
from session_keys import KID_RE  # noqa: E402

STACK_OUTPUTS = {"site-rs-v1": "SiteSessionKeyRsV1Arn", "console-rs-v1": "ConsoleSessionKeyRsV1Arn"}


def sections(kms, pairs) -> str:
    out = []
    for kid, arn in pairs:
        if not KID_RE.match(kid):
            raise SystemExit(f"{kid!r} 不是合法 kid（形态 site-rs-v<n> / console-rs-v<n>）")
        try:
            _, fp = session_kms.describe_public_key(kms, arn)
        except session_kms.KeyMaterialMismatch as exc:
            # **形态不符时一个指纹都不打**：打出来会被粘进 config，而那时错误要到三个部署脚本的
            # 部署前核对才暴露，文案说的是"与 [SessionKeys] 声明不符"、指向的却是这一步。
            raise SystemExit(f"{kid}: 这把 key 不符合 RS256 会话签名合同，不输出小节：{exc}") from None
        out.append(f"[SessionKey:{kid}]\nalg = RS256\nkey_arn = {arn}\nspki_sha256 = {fp}\n")
    return "\n".join(out)


def from_stack(cfn, stack_name: str) -> list:
    outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])}
    missing = [k for k in STACK_OUTPUTS.values() if k not in outs]
    if missing:
        raise SystemExit(f"栈 {stack_name} 缺 CfnOutput {missing}——先部 deployer 栈")
    return [(kid, outs[key]) for kid, key in STACK_OUTPUTS.items()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kid", action="append", default=[])
    ap.add_argument("--arn", action="append", default=[])
    ap.add_argument("--from-stack", action="store_true", help="从 deployer 栈的 CfnOutput 读两把 key 的 ARN")
    args = ap.parse_args(argv)
    # **两个纯参数错误都在 import boto3 之前拒**：数量不齐时 `zip` 会静默丢掉多出来的那个
    # ⇒ 少打一个小节，而人只会发现少了一节、不会发现是自己漏了参数。
    if len(args.kid) != len(args.arn):
        raise SystemExit("--kid 与 --arn 必须成对出现")
    pairs = list(zip(args.kid, args.arn))
    if not pairs and not args.from_stack:
        raise SystemExit("给 --from-stack 或至少一对 --kid/--arn")
    import boto3
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(ROOT / "site-builder" / "config.ini")
    region = (cfg.get("Platform", "region", fallback="us-east-1") or "us-east-1").split("#")[0].strip()
    if args.from_stack:
        stack = (cfg.get("Deployer", "stack_name", fallback="SiteDeployerStack") or "SiteDeployerStack").split("#")[0].strip()
        pairs += from_stack(boto3.client("cloudformation", region_name=region), stack)
    print(sections(boto3.client("kms", region_name=region), pairs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
