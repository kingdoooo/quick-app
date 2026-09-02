#!/usr/bin/env python3
"""按 `site-builder/config.ini` 的 [SessionKeys] HS 行幂等创建 SSM SecureString（3c-1A Task 1）。

- 路径**只**来自 config（session_keys.load_session_keys），不接受命令行路径：接受路径等于允许
  随手建第三把密钥，而 verifier 的 allowlist 只认 config 里的那几把。
- 只创建，不覆盖，不打印值。legacy_param（今天的 /site-builder/jwt-secret）不在本脚本职责内，
  它由 deploy_auth.py 维护。RS 行没有 SSM secret，跳过。
- 用不带路径的 `python3` 跑（≥ 3.10，boto3 + pip-system-certs），见 CLAUDE.md。

    python3 site-builder/scripts/ensure_session_keys.py
"""
from __future__ import annotations

import argparse
import configparser
import secrets
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site-builder" / "auth"))
from secrets_util import ensure_secret      # noqa: E402
from session_keys import load_session_keys  # noqa: E402

CONFIG_PATH = ROOT / "site-builder" / "config.ini"


def _region(config_path: Path) -> str:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    return cfg.get("Platform", "region", fallback="us-east-1").split("#")[0].strip() or "us-east-1"


def ensure_session_keys(config_path: Path, *, ssm=None) -> dict[str, str]:
    """→ {kid: "created" | "exists"}。配置错误在任何写之前就抛 SessionKeysError。"""
    keys = load_session_keys(config_path)
    ssm = ssm or boto3.client("ssm", region_name=_region(config_path))
    result: dict[str, str] = {}
    for fam in ("site", "console"):
        for ref in keys.allowlist(fam):
            if ref.alg != "HS256":
                continue
            created = {"flag": False}

            def gen():
                created["flag"] = True
                return secrets.token_hex(32)

            ensure_secret(ref.ssm_param, gen, ssm=ssm)
            result[ref.kid] = "created" if created["flag"] else "exists"
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    return ap.parse_args(argv)     # 没有任何参数：路径来自 config


def main(argv: list[str] | None = None) -> int:
    parse_args(sys.argv[1:] if argv is None else argv)
    for kid, status in ensure_session_keys(CONFIG_PATH).items():
        print(f"{status:8s} {kid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
