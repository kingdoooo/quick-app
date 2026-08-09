"""CDK 断言：Edge role 的 S3 资源集合必须恰好是 {sites/*, platform/*}。

为什么要"不多不少"：
  · 少了 platform/*（M3 前的现状）→ console 前端 AccessDenied 加载不出来，
    而 /api/* 一切正常，症状极具误导性；
  · 多了（整桶 /*）→ 站点前缀与平台前缀的隔离失效。

**opt-in（默认 skip）**：要 synth 整个 router 栈。需要时显式开：

    cd router/infrastructure/lambda && \\
      PYTHONPATH="$PWD/../.venv/lib/python3.13/site-packages" SB_CDK_TESTS=1 \\
      ../../../site-builder/deployer/.venv/bin/pytest test_stack_edge_iam.py -q

（python3.x 目录名按实际 venv 调整；桥接不上时本文件会 fail 而不是 skip——
静默 skip 等于这次运行什么都没验证。）
"""
import os
import sys
from pathlib import Path

import pytest

INFRA = Path(__file__).parents[1]
# stack.py 的 ConfigLoader 读的是 `Path(stack.py).parent.parent / "config.ini"`
# = router/config.ini（**不是** router/infrastructure/config.ini）。
# 路径写错的症状是本文件静默 skip，看起来和"没开 SB_CDK_TESTS"一样。
CONFIG = INFRA.parent / "config.ini"

pytestmark = [
    pytest.mark.skipif(os.environ.get("SB_CDK_TESTS") != "1",
                       reason="需 SB_CDK_TESTS=1（synth 整个 router 栈）"),
    pytest.mark.skipif(not CONFIG.exists(),
                       reason="需要 router/config.ini"),
]


@pytest.fixture(scope="module")
def template():
    # 显式 opt-in 了就不许再静默 skip：importorskip 会把"aws_cdk 装错 venv"
    # 伪装成 skip，和默认不跑长得一样。
    try:
        import aws_cdk
        from aws_cdk import assertions
    except ImportError:
        pytest.fail("SB_CDK_TESTS=1 但 aws_cdk 不可用——用 docstring 里的 "
                    "PYTHONPATH 桥接命令跑，否则这次运行什么都没验证")
    sys.path.insert(0, str(INFRA))
    import stack as st

    app = aws_cdk.App()
    # **类名是 WebRouterStack**（stack.py:86），不是 RouterStack
    s = st.WebRouterStack(app, "TestRouterStack")
    return assertions.Template.from_stack(s)


def _s3_get_object_resources(template) -> set[str]:
    out = set()
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            acts = stmt["Action"]
            acts = acts if isinstance(acts, list) else [acts]
            if "s3:GetObject" not in acts:
                continue
            res = stmt["Resource"]
            for r in (res if isinstance(res, list) else [res]):
                out.add(str(r))
    return out


def test_edge_role_s3_prefixes_are_exactly_sites_and_platform(template):
    resources = _s3_get_object_resources(template)
    assert resources, "找不到 Edge role 的 s3:GetObject 语句——解析逻辑坏了"
    prefixes = set()
    for r in resources:
        # 形如 arn:aws:s3:::{bucket}/sites/*
        tail = r.split(":::", 1)[-1]
        if "/" not in tail:
            raise AssertionError(f"Edge role 拿到了整桶权限（无前缀）: {r}")
        prefix = tail.split("/", 1)[1].rstrip("*").rstrip("/")
        assert prefix, f"Edge role 拿到了整桶权限: {r}"
        prefixes.add(prefix.split("/")[0])
    assert prefixes == {"sites", "platform"}, (
        f"S3 前缀集合不对: {sorted(prefixes)}——"
        "缺 platform 则 console 白屏，多了则前缀隔离失效")
