"""Edge 单测的公共护栏：**任何用例都不许让埋点走到真的 DynamoDB client。**

M5 给 `lambda_handler` 接上 `_maybe_record` 之后，任何走完整 handler 且 host 是
`app-*`、路径又判为页面级的既有用例，都会落进 `_record_access` 里那个真实的
`put_item`。而 `_record_access` 按设计吞掉一切异常（统计不是安全控制），所以
**失败是静默的，测试照样全绿**。

实测证据（2026-08-14，加本文件之前）：`test_origin_request.py::
test_extensionless_uri_maps_to_index` 有两次调用（`/` 与 `/detail` 的 SPA 回退）
用真实凭证向 us-east-1 的 `site-access-events` 发出了签名 PutItem，回来的是
`ResourceNotFoundException`——service 级异常，说明请求真的出了网络。表还没建所以
只是报错；**Task 15 把表建出来之后，同一批单测就会往生产表里写 `site_id=demo1`
的垃圾行**，污染 PV/UV，且因为异常被吞掉，没有任何信号提示这件事正在发生。

按区缓存的 client 让这件事更隐蔽：`_ACCESS_CLIENTS` 是模块级 dict，一旦某个用例
把真 client 建出来，后面的用例就直接复用它。

## 为什么是"抛 + teardown 断言"，不是"静默返回 {}"

第一版把 `put_item` 写成静默返回 `{}`。**那是错的**（审查 2026-08-14 指出）：
静默 no-op 会让"这条用例其实根本没在写"看起来和"写成功了"一模一样，等于用一个
新的静默失败替换掉旧的静默失败。所以现在有两道：
  1. `put_item` **抛** `_LiveAccessWriteBlocked`——绝不可能被误认为成功；
  2. fixture 在 teardown **断言一次都没被拦过**——把它变成用例失败，而不是只在
     `-s` 输出里留一行 WARN（`_record_access` 会把异常吞掉，光抛不断言仍然是静默）。

于是不变量是硬的：**没有任何用例可以走到真 client**。要观察写入形态的用例
（`test_written_item_shape` 等）自己 `monkeypatch.setattr` 一个会捕获参数的
fake；只关心路由、不关心埋点的用例（`test_extensionless_uri_maps_to_index`）
自己 patch 掉 `_record_access`，把"我不写"这件事写明。两者都不会碰到本护栏。
autouse fixture 先生效、用例内的替换后生效，覆盖顺序正确。
"""
import sys

import pytest


class _LiveAccessWriteBlocked(RuntimeError):
    """埋点走到了真 client。单测绝不许出网——见本文件顶部的实测证据。"""


class _BlockingAccessClient:
    """拦住写入并**留痕**，绝不静默成功。"""

    def __init__(self, blocked: list):
        self._blocked = blocked

    def put_item(self, **kwargs):
        self._blocked.append(kwargs.get("TableName"))
        raise _LiveAccessWriteBlocked(
            f"用例试图对 {kwargs.get('TableName')!r} 真的发 PutItem。"
            "要么自己 patch _access_client 观察写入形态，要么 patch "
            "_record_access 表明本用例不写。")


@pytest.fixture(autouse=True)
def _no_live_access_writes(monkeypatch):
    """给所有已加载的 `_*_testable` 副本装上会抛的埋点 client，并在 teardown 追责。

    按"有没有 `_access_client` 这个属性"筛，而不是按文件名硬编码模块清单——
    新增测试文件会自动被护住，不需要谁记得来这里登记。
    """
    blocked: list = []
    for name, mod in list(sys.modules.items()):
        if name.endswith("_testable") and hasattr(mod, "_access_client"):
            monkeypatch.setattr(mod, "_access_client",
                                lambda region: _BlockingAccessClient(blocked))
            # 清掉按区缓存，避免上一个用例建出来的真 client 被后面复用
            getattr(mod, "_ACCESS_CLIENTS", {}).clear()
    yield
    assert not blocked, (
        f"本用例让埋点走到了真 DynamoDB client（表={blocked}）。"
        "_record_access 会吞掉异常，所以这在生产上是静默写入——"
        "见 conftest.py 顶部的实测证据。")
