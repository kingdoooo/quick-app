"""SSM SecureString 的幂等创建与部署前核对（deploy_auth.py / deploy_panel.py / scripts/ensure_session_keys.py 共用）。

- ensure_secret：只在参数**不存在**时生成并写入；存在则原样返回，**绝不覆盖**（覆盖 = 换密钥 = 全员会话
  失效，见 DEPLOY.md「轮转会话密钥」）。
- precheck_parameters（3c-1B，spec §11.8.12）：部署脚本在**第一次写之前**核对它要读的每个参数存在。
  只读、不解密、不打印值；缺任一个 ⇒ SystemExit。auth/panel 的密钥值在运行时才按参数名读，参数缺失的
  症状是全部登录 500 而部署脚本 exit 0（与 1A 那次 502 同形）；就位新 key 时忘跑 ensure_session_keys.py
  就会撞上。这也是 spec §11.6 第 1 层"部署前校验"的落点，2B 在同一个钩子里加 KMS 四项。
"""
from __future__ import annotations

import boto3


def precheck_parameters(names, *, ssm, hint: str = "") -> None:
    """每个参数 GetParameter 一次（不带 WithDecryption：只看存在性，不取明文）。缺任一个即 SystemExit，
    信息里列全部缺失项与补救提示；不打印任何值。"""
    missing = []
    for name in dict.fromkeys(names):
        try:
            ssm.get_parameter(Name=name)
        except ssm.exceptions.ParameterNotFound:
            missing.append(name)
    if missing:
        raise SystemExit("部署前核对失败：这些 SSM 参数不存在，拒绝部署（任何写都未发生）：\n  "
                         + "\n  ".join(missing)
                         + f"\n{hint or '会话密钥由 scripts/ensure_session_keys.py 按 [SessionKeys] 幂等创建；先跑它。'}")


def ensure_secret(name: str, generate, *, ssm=None, region: str = "us-east-1") -> str:
    """参数不存在时生成并写入，存在则原样返回。**创建时打一行（只有参数名，没有值）。**

    为什么创建必须有声音（3c-1B 复审）：本函数创建的那几把密钥都**不在**部署前核对清单里
    （它们由本脚本自己创建，核对它们等于让创建永远走不到；见
    `docs/adr/0004-login-flow-secret-outside-the-pre-write-precheck.md`）。于是"参数被删了、
    脚本默默重造一把"没有任何信号——事后只看到一轮失败的登录，无从判断发生过什么。

    对 legacy 的 `jwt-secret` 这一行更要紧：它有**第二个**消费方（Edge 那份是 CDK 部署时
    字符串替换注入的）。成熟部署里它被删之后，auth 造一把新的而 Edge 还拿着旧的 ⇒ 正是
    全员登录循环。在成熟部署上看到它被 created，就该停下来查，而不是继续部署。

    存在时保持安静：幂等重跑是常态，每次刷一行会把"创建"这个信号淹掉。
    """
    ssm = ssm or boto3.client("ssm", region_name=region)
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        val = generate()
        ssm.put_parameter(Name=name, Value=val, Type="SecureString")
        # 只有名字。值绝不进 stdout/日志（本仓库的闸门也按"不打印值"断言）。
        print(f"  已**新建** SecureString {name}"
              "（若这是成熟部署而非首次部署，先停下来查为什么它不存在）")
        return val
