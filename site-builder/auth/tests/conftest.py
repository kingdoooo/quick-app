import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "panel" / "tests"))   # upgrade_code_vectors（三套件共用）

import pytest

import upgrade_code_vectors as vectors  # noqa: E402

LOGIN_FLOW_SECRET = "login-flow-secret-v1"
LOGIN_FLOW_PARAM = "/site-builder/login-flow-secret"


@pytest.fixture(autouse=True)
def _fake_platform_clients(monkeypatch):
    """login_handler 的两个 AWS 边界都换成替身：SSM 只认 login-flow 那一把；KMS 按 vectors 的三把私钥
    回答 DescribeKey / GetPublicKey / Sign。任何别的参数名 / KeyId 都响亮失败。"""
    values = {LOGIN_FLOW_PARAM: LOGIN_FLOW_SECRET}

    class _SSM:
        @staticmethod
        def get_parameter(Name, WithDecryption=False):
            if Name in values:
                return {"Parameter": {"Value": values[Name]}}
            raise RuntimeError(f"测试里意外读了 SSM 参数 {Name}")

    kms = vectors.FakeKms()
    # Task 5 之前 login_handler 尚未切 RS：import 失败即不打补丁；需要它的测试模块自己 import 会响亮失败
    try:
        import login_handler as lh
        lh._secret_cache.clear()
        lh._reset_signers()
        monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
        monkeypatch.setattr(lh, "_kms", lambda: kms)
    except (ImportError, AttributeError):
        yield None
        return
    yield kms
    lh._secret_cache.clear()
    lh._reset_signers()
