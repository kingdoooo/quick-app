"""AgentCore Runtime 契约的回归锁定。

这些不变量违反后症状都是"部署上去才发现连不上/身份识别不了"，单测不锁住
就会在真机反复踩。契约来源：AgentCore MCP protocol contract + header allowlist
官方文档（见 AGENTCORE-SPIKE.md）。
"""
import re
from pathlib import Path

import pytest

MCP_DIR = Path(__file__).parents[1]


def test_server_binds_agentcore_host_port_path():
    """必须 0.0.0.0:8000 + /mcp：FastMCP 默认 127.0.0.1，平台探测不到。"""
    import server
    s = server.mcp.settings
    assert s.host == "0.0.0.0"
    assert s.port == 8000
    assert s.streamable_http_path == "/mcp"


def test_server_is_stateless_http():
    """平台为每个请求注入 Mcp-Session-Id，stateful 服务会拒掉它。"""
    import server
    assert server.mcp.settings.stateless_http is True


def test_common_importable_without_test_path_injection():
    """容器里 server.py 与 common.py 同目录；此前裸启动会 ModuleNotFoundError。"""
    src = (MCP_DIR / "server.py").read_text()
    assert "sys.path.insert" in src, "server.py 必须自己保证 common 可导入"
    import common  # noqa: F401  经 server.py 的 sys.path 处理后可用


def test_dockerfile_pins_arm64_and_expected_layout():
    """AgentCore 只接受 ARM64 镜像；x86 镜像运行时 exec format error。"""
    df = (MCP_DIR / "Dockerfile").read_text()
    assert "--platform=linux/arm64" in df
    assert re.search(r"COPY\s+server\.py\s+common\.py", df), \
        "common.py 必须与 server.py 同目录进镜像"
    assert "8000" in df


def test_requirements_floor_supports_request_context():
    """request_context.request 自 mcp 1.10.0 引入；>=1.9 会让身份识别静默失效。"""
    req = (MCP_DIR / "requirements.txt").read_text()
    m = re.search(r"^mcp>=(\d+)\.(\d+)", req, re.M)
    assert m, "requirements.txt 必须钉 mcp 下限"
    major, minor = int(m.group(1)), int(m.group(2))
    assert (major, minor) >= (1, 10)


def test_deploy_script_sets_authorization_allowlist_and_jwt_authorizer():
    """Authorization 不进 allowlist 就到不了容器，_caller_email 必失败；
    而 Authorization 透传又要求 runtime 配 customJWTAuthorizer。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    assert '"requestHeaderAllowlist": ["Authorization"]' in src
    assert "customJWTAuthorizer" in src
    assert '"serverProtocol": "MCP"' in src
    assert "linux/arm64" in src


def test_runtime_name_matches_api_pattern():
    """agentRuntimeName 只允许 [a-zA-Z][a-zA-Z0-9_]{0,47}（连字符会被 API 拒）。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    name = re.search(r'^RUNTIME_NAME\s*=\s*"([^"]+)"', src, re.M).group(1)
    assert re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,47}", name), name


@pytest.mark.parametrize("tool", ["deploy_site", "confirm_upload", "get_deploy_status",
                                  "list_my_sites", "undeploy_site"])
def test_all_five_tools_registered(tool):
    import asyncio

    import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert tool in names


def test_caller_email_rejects_missing_and_malformed_authorization(monkeypatch):
    """无 token / 无 email claim 一律拒绝——不得回退成匿名或空 owner。"""
    import server
    with pytest.raises(server.NotOwner):
        server._caller_email()  # 无请求上下文

    import base64
    import json as _json

    class _Req:
        def __init__(self, auth):
            self.headers = {"authorization": auth} if auth else {}

    class _Ctx:
        def __init__(self, auth):
            self.request_context = type("R", (), {"request": _Req(auth)})()

    def _b64(d):
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()

    # 合法：带 email claim
    tok = f"h.{_b64({'email': 'user@example.com'})}.sig"
    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx(f"Bearer {tok}"))
    assert server._caller_email() == "user@example.com"

    # 非法：token 有效但没有 email claim（Cognito access token 默认就是这样）
    tok2 = f"h.{_b64({'sub': 'abc', 'client_id': 'x'})}.sig"
    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx(f"Bearer {tok2}"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def _token(claims: dict) -> str:
    import base64
    import json as _json
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return (b64(_json.dumps({"alg": "RS256"}).encode()) + "." +
            b64(_json.dumps(claims).encode()) + ".sig")


def _with_auth(monkeypatch, token: str):
    """伪造 FastMCP 的请求上下文，只提供 Authorization 头。"""
    import server

    class _Req:
        headers = {"authorization": f"Bearer {token}"}

    class _Ctx:
        class request_context:
            request = _Req()

    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx())


def test_caller_email_accepts_trusted_idp(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu,Okta")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth"}))
    assert server._caller_email() == "a@x.com"


def test_caller_email_rejects_token_without_idp(monkeypatch):
    """本地用户/旧 token 没有 idp——必须拒，否则管理面绕过了 §3.5。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "local@x.com"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_rejects_untrusted_idp(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "EvilCorp",
                                    "auth_via": "TokenGeneration_HostedAuth"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_rejects_native_auth_source(monkeypatch):
    """idp 合法但走原生 InitiateAuth（linked 用户/设过密码的联邦用户）。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_Authentication"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_accepts_refresh_token_source(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_RefreshTokens"}))
    assert server._caller_email() == "a@x.com"


def test_caller_email_skips_idp_check_when_unconfigured(monkeypatch):
    """TRUSTED_IDPS 为空 = 迁移宽限期（与 Edge 的开关对齐），放行但不推荐。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "")
    _with_auth(monkeypatch, _token({"email": "a@x.com"}))
    assert server._caller_email() == "a@x.com"


def test_trusted_idps_read_per_call_not_at_import(monkeypatch):
    """配置必须每次调用时读——固化成模块常量会让上面的拒绝用例假通过。

    server 在本文件更早的用例里已被导入，若 TRUSTED_IDPS 是模块级 tuple，
    这里的 setenv 不会改变它。
    """
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    assert server._trusted_idps() == ("Feishu",)
    monkeypatch.setenv("TRUSTED_IDPS", "Okta,Feishu")
    assert server._trusted_idps() == ("Okta", "Feishu")
