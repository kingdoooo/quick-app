"""upgrade code 的契约向量：auth 侧签、panel 侧验，两个包各跑一遍。

为什么要共用一份：panel 构建时**复制** session.py，于是部署后仓库里会有两份
（`auth/session.py` 与打包进 panel 的副本）。复制品漂移是本项目已知的风险
类型（Edge 与 session.py 的 HS256 就靠字节级同步测试盯着）。同一组向量在
两侧都跑，漂移当场暴露。
"""
SECRET = "test-secret-not-a-real-one"


def _tamper_payload(code: str) -> str:
    """替换 payload 段但保留原签名——签名校验必须先失败。"""
    h, _, rest = code.partition(".")
    _, _, sig = rest.partition(".")
    return f"{h}.eyJhIjoxfQ.{sig}"


def _drop_sig(code: str) -> str:
    h, p, _ = code.split(".")
    return f"{h}.{p}."


# (名字, 变换函数, 期望被拒)
MUTATIONS = [
    ("完好", lambda c: c, False),
    ("签名被截断", lambda c: c[:-4], True),
    ("签名整段删除", _drop_sig, True),
    ("篡改 payload 保留旧签名", _tamper_payload, True),
    ("整段替换成 login state 形态", lambda c: "abc.def.ghi", True),
    ("段数不足", lambda c: c.rsplit(".", 1)[0], True),
    ("空串", lambda c: "", True),
]


# ---- 3c-1A：新形态（带 kid）的 console family 向量，两侧各跑一遍 ----
# auth 侧用 session.verify_with_legacy 验，panel 侧经 console_session.consume_code 验：
# 同一组 MUTATIONS 施加在 mint_token 签出的升级码上，接受/拒绝结果两侧必须一致。
CONSOLE_KID = "console-hs-v1"
CONSOLE_KID_SECRET = "console-secret-v1-not-a-real-one"
CONSOLE_ALLOWLIST = {CONSOLE_KID: {"alg": "HS256", "secret": CONSOLE_KID_SECRET, "role": "current"}}
SITE_KID = "site-hs-v1"
SITE_KID_SECRET = "site-secret-v1-not-a-real-one"
