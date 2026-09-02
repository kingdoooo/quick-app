import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

SITE_KID_SECRET = "site-secret-v1"          # 两把 family 假密钥的唯一定义（test_login_handler 从这里 import）
CONSOLE_KID_SECRET = "console-secret-v1"
# 3c-1B：登录流程（state 与 pkce cookie）的 HMAC 密钥。**与上面两把、与 legacy 的 JWT_SECRET
# 全都不同** —— 测试要能区分"用哪把签的"，三者相同的话本票的核心断言会假绿。
LOGIN_FLOW_SECRET = "login-flow-secret-v1"
LOGIN_FLOW_PARAM = "/site-builder/login-flow-secret"


@pytest.fixture(autouse=True)
def _fake_session_key_params(monkeypatch):
    """3c-1A：login_handler 会按 SESSION_KEYS_JSON 里的参数名读两把 family 密钥。
    3c-1B 起还会按 LOGIN_FLOW_SECRET_PARAM 读登录流程那把（同一条 `{name}_PARAM` 约定）。

    测试里不碰真 SSM：把 `_ssm` 换成只认下面那三个参数名的假件（两把 family 密钥的值与
    test_login_handler 的 SITE_KID_SECRET / CONSOLE_KID_SECRET 一致，第三把是 login-flow）。legacy 的 JWT_SECRET 仍走各测试 ENV 里的
    明文（_secret 对本地测试保留这条路，见 test_secret_loading）。需要别的 SSM 行为的测试
    自己再 monkeypatch `_ssm`，后设的覆盖本夹具。
    """
    import login_handler as lh
    values = {"/site-builder/session-keys/site-hs-v1": SITE_KID_SECRET,
              "/site-builder/session-keys/console-hs-v1": CONSOLE_KID_SECRET,
              # 3c-1B：login-flow secret 也按 `{name}_PARAM` 约定从 SSM 读（生产只下发参数名）
              LOGIN_FLOW_PARAM: LOGIN_FLOW_SECRET}

    class _SSM:
        @staticmethod
        def get_parameter(Name, WithDecryption=False):
            if Name in values:
                return {"Parameter": {"Value": values[Name]}}
            raise RuntimeError(f"测试里意外读了 SSM 参数 {Name}")

    lh._secret_cache.clear()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    yield
    lh._secret_cache.clear()
