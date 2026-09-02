"""SSM SecureString 的幂等创建（deploy_auth.py 与 scripts/ensure_session_keys.py 共用）。

只在参数**不存在**时生成并写入；存在则原样返回，**绝不覆盖**（覆盖 = 换密钥 = 全员会话失效，
见 DEPLOY.md「轮转 jwt-secret」）。
"""
from __future__ import annotations

import boto3


def ensure_secret(name: str, generate, *, ssm=None, region: str = "us-east-1") -> str:
    ssm = ssm or boto3.client("ssm", region_name=region)
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        val = generate()
        ssm.put_parameter(Name=name, Value=val, Type="SecureString")
        return val
