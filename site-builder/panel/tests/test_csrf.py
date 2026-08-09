"""CSRF 五步前置校验里的 Origin / Content-Type / 方法三项。

会话校验（__Host-sb_console）在 test_console_session.py；
"副作用前置"的顺序断言在 test_handler.py（Task 9）——那里才有完整请求路径。
"""
import pytest

import console_session

GOOD = {"origin": "https://console.example.com",
        "content-type": "application/json"}


@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE"])
def test_accepts_wellformed_write(aws, method):
    console_session.check_csrf(method, GOOD)      # 不抛


@pytest.mark.parametrize("headers,why", [
    ({**GOOD, "origin": "https://evil.example.com"}, "Origin 不匹配"),
    ({"content-type": "application/json"}, "缺 Origin"),
    ({**GOOD, "content-type": "text/plain"}, "Content-Type 不是 json"),
    ({**GOOD, "origin": "http://console.example.com"}, "http 而非 https"),
    ({**GOOD, "origin": "https://console.example.com.evil.com"}, "后缀拼接"),
    ({**GOOD, "origin": "https://evil.console.example.com"}, "前缀拼接"),
    ({**GOOD, "origin": ""}, "Origin 空串"),
])
def test_rejects(aws, headers, why):
    with pytest.raises(console_session.CsrfRejected):
        console_session.check_csrf("PUT", headers)


def test_missing_origin_does_not_fall_back_to_referer(aws):
    """spec §5.4 第 3 步：缺 Origin 直接拒绝，**不回退 Referer**。

    Referer 会被代理/隐私设置改写，拿它当同源证据等于给出一条绕过路径。
    """
    with pytest.raises(console_session.CsrfRejected):
        console_session.check_csrf(
            "POST", {"referer": "https://console.example.com/x",
                     "content-type": "application/json"})


@pytest.mark.parametrize("method", ["GET", "HEAD", "PATCH", "OPTIONS", "", "put"])
def test_only_declared_write_methods_pass(aws, method):
    """写方法白名单：小写 put 也要能被识别成写方法（大小写归一）。"""
    if method.upper() in console_session.WRITE_METHODS:
        console_session.check_csrf(method, GOOD)
    else:
        with pytest.raises(console_session.CsrfRejected):
            console_session.check_csrf(method, GOOD)


def test_content_type_with_charset_is_accepted(aws):
    """浏览器常发 application/json;charset=UTF-8——不能因此拒绝合法请求。"""
    console_session.check_csrf(
        "PUT", {**GOOD, "content-type": "application/json;charset=UTF-8"})


def test_none_headers_do_not_crash(aws):
    """畸形事件不得变成 500——必须是明确的拒绝。"""
    with pytest.raises(console_session.CsrfRejected):
        console_session.check_csrf("PUT", None)
