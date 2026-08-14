"""CDK 断言：Edge role 的 S3 资源集合必须恰好是 {sites/*, platform/*}。

为什么要"不多不少"：
  · 少了 platform/*（M3 前的现状）→ console 前端 AccessDenied 加载不出来，
    而 /api/* 一切正常，症状极具误导性；
  · 多了（整桶 /*）→ 站点前缀与平台前缀的隔离失效。

**opt-in（默认 skip）**：要 synth 整个 router 栈。需要时显式开：

    cd router/infrastructure/lambda && \\
      PYTHONPATH="$PWD/../.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \\
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


def _ddb_statements(template) -> list[dict]:
    out = []
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            acts = stmt["Action"]
            acts = acts if isinstance(acts, list) else [acts]
            if any(str(a).startswith("dynamodb:") for a in acts):
                out.append(stmt)
    return out


def test_edge_role_may_only_put_items_into_the_access_events_table(template):
    """埋点权限必须恰好是「三个副本 ARN 上的 PutItem」。

    · 漏一个副本 ARN → 那个区的埋点全部 AccessDenied，而 _record_access 会把
      异常吞掉 ⇒ **该区静默零数据**（正是本项目反复栽的失效形状）；
    · 多给 UpdateItem/DeleteItem → 公网组件获得改写访问历史的能力；
    · 资源集合**从副本清单推导**，不手抄——手抄的清单每加一个区就漏一个
      （M4-FINDINGS §3.9）。

    本条锁的是「清单 → IAM 资源集合」与「清单 → Edge 的
    ACCESS_REPLICA_REGIONS」这两条腿（真源都是 router/config.ini）。第三条腿
    ——deployer 栈 TableV2 的 replicas——钉在另一个包里：
    `site-builder/deployer/tests/test_infra_tables.py::
     test_access_events_table_is_a_three_region_global_table` 用字面量集合
    {us-east-1, ap-southeast-1, ap-northeast-1}，它看不见 router/config.ini。
    所以「只往 router/config.ini 加一个区」这种跨包漂移**两个包的单测都会绿**，
    而 Edge 会往一个不存在的副本写（异常被吞 ⇒ 该区静默零数据）。这个漂移由
    Task 13 的真机 describe_table Replicas 检查兜住，不是单测能覆盖的范围。
    """
    import configparser
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(CONFIG)
    assert cfg.sections(), f"{CONFIG} 读空了——configparser 对缺失文件是静默的"
    table = cfg["SiteBuilder"]["access_table"]
    regions = [r.strip() for r in
               cfg["SiteBuilder"]["access_replica_regions"].split(",") if r.strip()]
    assert len(regions) >= 2, f"副本清单至少要有主区+1: {regions}"

    account = cfg["AWS"]["account_id"].strip()
    puts = [s for s in _ddb_statements(template)
            if "dynamodb:PutItem" in (s["Action"] if isinstance(s["Action"], list)
                                      else [s["Action"]])]
    assert puts, "找不到 Edge role 的 dynamodb:PutItem 语句"
    got = set()
    for s in puts:
        res = s["Resource"]
        for r in (res if isinstance(res, list) else [res]):
            # **必须是字符串**。若是 dict（Fn::Join / Fn::GetAtt）说明实现用了
            # self.account 或 table_arn，那种形态没法逐字比（2026-08-14 实测）
            assert isinstance(r, str), (
                f"Resource 渲染成了 {type(r).__name__} 而不是字符串: {r}"
                "——实现里应该用 config 的账号字面量，不是 self.account")
            got.add(r)
    expected = {f"arn:aws:dynamodb:{rg}:{account}:table/{table}" for rg in regions}
    assert got == expected, (
        f"PutItem 资源集合不对（**逐字比**，漏一个区 = 该区静默零数据）"
        f"\n  实际: {sorted(got)}\n  期望: {sorted(expected)}")


def test_edge_role_has_no_write_actions_beyond_put_item(template):
    """写权限只许 PutItem——UpdateItem/DeleteItem 是"能改写历史"。"""
    forbidden = {"dynamodb:UpdateItem", "dynamodb:DeleteItem",
                 "dynamodb:BatchWriteItem", "dynamodb:*"}
    for s in _ddb_statements(template):
        acts = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        bad = forbidden & set(map(str, acts))
        assert not bad, f"Edge role 拿到了 {sorted(bad)}"


def test_distribution_caching_stays_disabled(template):
    """全站禁缓存是**两件事**的前提，而它此前只有注释、没有任何断言。

    · 鉴权正确性：origin-request 只在 cache miss 执行；
    · 统计完整性（M5 新增）：缓存命中 ⇒ 不执行 ⇒ **静默漏计**。
    两个理由指向同一条配置，所以只加这一个守卫、不加第二处定义。
    CACHING_DISABLED 的托管策略 ID 是 AWS 固定值。
    """
    CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    dists = template.find_resources("AWS::CloudFront::Distribution")
    assert dists, "模板里找不到 CloudFront 分发"
    for d in dists.values():
        beh = d["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]
        assert beh.get("CachePolicyId") == CACHING_DISABLED, (
            f"默认行为的 cache policy 不是 CACHING_DISABLED: {beh.get('CachePolicyId')}"
            "——加缓存会同时破坏鉴权正确性与统计完整性")
