"""Edge 单测的公共护栏。

**单测绝不许把埋点真的打到 AWS。** M5 给 `lambda_handler` 接上 `_maybe_record`
之后，任何走完整 handler 且 host 是 `app-*`、路径又判为页面级的既有用例，都会
落进 `_record_access` 里那个真实的 `put_item`。而 `_record_access` 按设计吞掉
一切异常（统计不是安全控制），所以**失败是静默的，测试照样全绿**。

实测证据（2026-08-14，加本文件之前）：`test_origin_request.py` 有两条用例
（`/` 与 `/detail` 的 SPA 回退）用真实凭证向 us-east-1 的 `site-access-events`
发出了签名 PutItem，回来的是 `ResourceNotFoundException`——service 级异常，
说明请求真的出了网络。表还没建所以只是报错；**Task 15 把表建出来之后，同一批
单测就会往生产表里写 `site_id=demo1` 的垃圾行**，污染 PV/UV 统计，且因为异常
被吞掉，没有任何信号提示这件事正在发生。

按区缓存的 client 让这件事更隐蔽：`_ACCESS_CLIENTS` 是模块级 dict，
一旦某个用例把真 client 建出来，后面的用例就直接复用它。

所以在这里统一断掉：把每个 testable 副本的 `_access_client` 换成不出网的假
client。需要观察写入形态的用例（`test_written_item_shape` 等）自己再
`monkeypatch.setattr` 一个会捕获参数的 fake——autouse fixture 先生效、用例内
的替换后生效，覆盖顺序正确，两者不冲突。
"""
import sys

import pytest


class _NoNetworkAccessClient:
    """吞掉写入、绝不出网。返回值形状与真 client 的 put_item 一致（空 dict）。"""

    def put_item(self, **kwargs):
        return {}


@pytest.fixture(autouse=True)
def _no_live_access_writes(monkeypatch):
    """给所有已加载的 `_*_testable` 副本装上不出网的埋点 client。

    按"有没有 `_access_client` 这个属性"筛，而不是按文件名硬编码模块清单——
    新增测试文件会自动被护住，不需要谁记得来这里登记。
    """
    for name, mod in list(sys.modules.items()):
        if name.endswith("_testable") and hasattr(mod, "_access_client"):
            monkeypatch.setattr(mod, "_access_client",
                                lambda region: _NoNetworkAccessClient())
            # 清掉按区缓存，避免上一个用例建出来的真 client 被后面复用
            getattr(mod, "_ACCESS_CLIENTS", {}).clear()
