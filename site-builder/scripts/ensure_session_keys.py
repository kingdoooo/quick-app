#!/usr/bin/env python3
"""按 `site-builder/config.ini` 的 [SessionKeys] 幂等创建 SSM SecureString（3c-1A Task 1；3c-1B 扩）。

- 路径**只**来自 config（session_keys.load_session_keys），不接受命令行路径：接受路径等于允许
  随手建第三把密钥，而 verifier 的 allowlist 只认 config 里的那几把。
- 只创建，不覆盖，不打印值。legacy_param（今天的 /site-builder/jwt-secret）不在本脚本职责内，
  它由 deploy_auth.py 维护。RS 行没有 SSM secret，跳过。
- 3c-1B 起除 HS 行外也建 `login_flow_secret_param`（spec §11.8.6：部署序列第①步一次建齐 config
  声明的所有密钥）。它**不是 kid**、不属于任何 family，所以在返回值里用闸门的那个 LABEL
  `login-flow`（`--new-key login-flow`），不会与任何 kid 撞名。`deploy_auth.py` 对它保留一条
  `ensure_secret` **缺省补建**（spec §11.8.6 把这条叫「兜底」）——两处都只创建不覆盖，
  所以先跑哪个都一样。
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
# login-flow secret 在返回值/打印里的标签。与闸门的 `--new-key login-flow` 同一个字面量，
# 且**永不匹配** session_keys.KID_RE（它不是 kid）。
LOGIN_FLOW_LABEL = "login-flow"


def _region(config_path: Path) -> str:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(config_path)
    return cfg.get("Platform", "region", fallback="us-east-1").split("#")[0].strip() or "us-east-1"


def ensure_session_keys(config_path: Path, *, ssm=None) -> dict[str, str]:
    """→ {kid 或 "login-flow": "created" | "exists"}。配置错误在任何写之前就抛 SessionKeysError。"""
    keys = load_session_keys(config_path)
    ssm = ssm or boto3.client("ssm", region_name=_region(config_path))
    result: dict[str, str] = {}

    def _ensure(label: str, param: str) -> None:
        created = False

        def gen():
            nonlocal created
            created = True
            return secrets.token_hex(32)

        ensure_secret(param, gen, ssm=ssm)
        result[label] = "created" if created else "exists"

    for fam in ("site", "console"):
        for ref in keys.allowlist(fam):
            if ref.alg != "HS256":
                continue
            _ensure(ref.kid, ref.ssm_param)
    # login-flow secret（3c-1B）：auth 私有、不是 kid、不属于任何 family。每把密钥各自
    # `secrets.token_hex(32)`，所以它与两把 family 密钥的值天然不同——同值就等于没迁移。
    _ensure(LOGIN_FLOW_LABEL, keys.login_flow_secret_param)
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
