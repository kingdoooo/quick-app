"""M19：Edge 的路由缓存必须有上界。

`_ROUTE_CACHE` 的键是**请求 host 的第一段**，而分发挂的是 `*.{base_domain}` 通配别名
⇒ 键由攻击者选。缓存原本是无上界的 dict，且 miss 也写入 ⇒ 随机子域打一轮就能把
一个 Edge 实例（128 MB）的内存撑满，每个新标签还附带一次 DynamoDB GetItem。

本文件钉住四件事：
1. **上界**：1 万个不同 host 查完，缓存条目数仍 ≤ `ROUTE_CACHE_MAX_ENTRIES`
   （正对照：那 1 万次确实都到了 DynamoDB，不是因为没插进去才不超）；
2. **淘汰是 LRU 不是 FIFO**：刚被访问过的热条目不会因为有新 host 进来就被挤掉；
3. **未命中照样缓存**（刻意保留）：不缓存 miss 的话，一个被反复打的**同一个**不存在
   host 就变成 DynamoDB 的热键——同一分区上真实站点的查询会一起被限流成 404。
   随机 host 洪水本来每个都要打一次 GetItem，缓存 miss 与否对它没有影响；
4. TTL 与 ClientError 路径不因为改成 LRU 而变（过期重查；出错不缓存、下次重试）。

判据都在真源 `origin_request.py` 上（经 `edge_substitutions` 做与 CDK 同一套替换）。
"""
import time
import types

import pytest
from botocore.exceptions import ClientError

import edge_substitutions as es


class _FakeDdb:
    """记录每次 GetItem 的 subdomain；`present` 里的返回一条 route item，其余返回空。"""

    def __init__(self, present=(), *, fail=False):
        self.present = set(present)
        self.fail = fail
        self.calls: list[str] = []

    def get_item(self, *, TableName, Key, ConsistentRead):
        sub = Key["subdomain"]["S"]
        self.calls.append(sub)
        if self.fail:
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException",
                                         "Message": "hot partition"}}, "GetItem")
        if sub in self.present:
            return {"Item": {"subdomain": {"S": sub}, "site_id": {"S": sub[4:]},
                             "route_mode": {"S": "split"}}}
        return {}


@pytest.fixture
def edge() -> types.ModuleType:
    """每条用例一个**独立**模块实例：缓存是模块级状态，绝不能在用例间串。"""
    return es.load_edge_module("_edge_route_cache_under_test")


def _patch_ddb(edge, fake):
    edge._ddb = lambda: fake
    return fake


# ---- ① 上界 ------------------------------------------------------------------------------

@pytest.mark.parametrize("all_present", [False, True], ids=["all-miss", "all-hit"])
def test_ten_thousand_distinct_hosts_leave_cache_within_bound(edge, all_present):
    hosts = [f"app-{i:05d}" for i in range(10_000)]
    fake = _patch_ddb(edge, _FakeDdb(present=hosts if all_present else ()))

    for h in hosts:
        edge._lookup_route(h)

    # 正对照：1 万个 host 每个都真的查了一次——不是"没插进去所以不超"。
    assert len(fake.calls) == 10_000
    assert isinstance(edge.ROUTE_CACHE_MAX_ENTRIES, int) and edge.ROUTE_CACHE_MAX_ENTRIES > 0
    assert edge.ROUTE_CACHE_MAX_ENTRIES < 10_000, "上界比用例的 host 数还大，本用例什么都没证明"
    assert len(edge._ROUTE_CACHE) <= edge.ROUTE_CACHE_MAX_ENTRIES


def test_bound_leaves_headroom_for_a_real_fleet_but_stays_small_against_128mb(edge):
    """量级守卫：太小会让正常站点互相挤（真实站点数是几十到几百），太大就没有上界的意义。"""
    assert 256 <= edge.ROUTE_CACHE_MAX_ENTRIES <= 8192


# ---- ② LRU，不是 FIFO ----------------------------------------------------------------------

def _fill_to_capacity(edge):
    """把缓存正好灌到上界（每个 host 都在路由表里），另备一个 "app-newcomer" 用来逼出淘汰。
    返回 (fill 顺序, 替身)。调用方若要改时间，先 monkeypatch 再调它。"""
    cap = edge.ROUTE_CACHE_MAX_ENTRIES
    fill = [f"app-fill-{i}" for i in range(cap)]
    fake = _patch_ddb(edge, _FakeDdb(present=fill + ["app-newcomer"]))
    for h in fill:
        edge._lookup_route(h)
    assert len(edge._ROUTE_CACHE) == cap
    return fill, fake


def test_recently_used_entry_survives_eviction_while_stale_one_goes(edge):
    cap = edge.ROUTE_CACHE_MAX_ENTRIES
    fill, fake = _fill_to_capacity(edge)

    # 触碰最老的那条 ⇒ 它变成最新；然后塞进一个新 host 逼出一次淘汰。
    edge._lookup_route(fill[0])
    before = len(fake.calls)
    edge._lookup_route("app-newcomer")
    assert len(edge._ROUTE_CACHE) == cap

    edge._lookup_route(fill[0])           # 热条目：仍在缓存里，不打 DynamoDB
    assert len(fake.calls) == before + 1  # 只有 newcomer 那一次
    edge._lookup_route(fill[1])           # 次老的那条：已被淘汰，要重查
    assert len(fake.calls) == before + 2
    # FIFO 的反例：FIFO 会把 fill[0] 淘汰、留下 fill[1]，上面两条断言恰好反过来。


# ---- ③ 未命中也缓存（刻意） -------------------------------------------------------------------

def test_a_miss_is_cached_so_a_hammered_unknown_host_costs_one_get_item(edge):
    fake = _patch_ddb(edge, _FakeDdb())
    for _ in range(50):
        assert edge._lookup_route("app-nope") is None
    assert fake.calls == ["app-nope"]


def test_a_hit_is_cached(edge):
    fake = _patch_ddb(edge, _FakeDdb(present=["app-real"]))
    first = edge._lookup_route("app-real")
    second = edge._lookup_route("app-real")
    assert first == second and first["site_id"] == "real"
    assert fake.calls == ["app-real"]


# ---- ④ TTL 与出错路径不变 ---------------------------------------------------------------------

def test_expired_entry_is_refetched(edge, monkeypatch):
    fake = _patch_ddb(edge, _FakeDdb(present=["app-real"]))
    base = time.time()
    monkeypatch.setattr(time, "time", lambda: base)
    edge._lookup_route("app-real")
    edge._lookup_route("app-real")
    assert fake.calls == ["app-real"]
    monkeypatch.setattr(time, "time", lambda: base + edge.ROUTE_CACHE_TTL + 1)
    edge._lookup_route("app-real")
    assert fake.calls == ["app-real", "app-real"]


def test_client_error_is_not_cached_and_next_call_retries(edge):
    fake = _patch_ddb(edge, _FakeDdb(fail=True))
    assert edge._lookup_route("app-real") is None
    assert "app-real" not in edge._ROUTE_CACHE
    assert edge._lookup_route("app-real") is None
    assert fake.calls == ["app-real", "app-real"]


def test_entry_refetched_after_expiry_counts_as_most_recent(edge, monkeypatch):
    """OrderedDict 对已存在的键赋值**不动位置**：过期重查后若不先删再插，那条刚刷新的热条目
    仍排在队首，下一次淘汰第一个就轮到它。"""
    base = time.time()
    monkeypatch.setattr(time, "time", lambda: base)
    fill, fake = _fill_to_capacity(edge)

    monkeypatch.setattr(time, "time", lambda: base + edge.ROUTE_CACHE_TTL + 1)
    edge._lookup_route(fill[0])           # 过期 ⇒ 重查并刷新，应成为最新
    edge._lookup_route("app-newcomer")    # 逼出一次淘汰
    before = len(fake.calls)
    edge._lookup_route(fill[0])           # 刚刷新的：不该被淘汰
    assert len(fake.calls) == before
    edge._lookup_route(fill[1])           # 次老且已过期：无论如何都要重查
    assert len(fake.calls) == before + 1
    assert fill[0] in edge._ROUTE_CACHE and fill[1] in edge._ROUTE_CACHE
