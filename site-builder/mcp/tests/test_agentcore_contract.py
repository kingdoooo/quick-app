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


EXPECTED_TOOLS = ["deploy_site", "confirm_upload", "get_deploy_status",
                  "list_my_sites", "undeploy_site", "update_site_permissions",
                  "manage_collaborators", "get_site_permissions"]


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_all_tools_registered(tool):
    import asyncio

    import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert tool in names


def test_no_unexpected_tools_registered():
    """工具面是对外契约：多出未登记的工具（比如调试残留）要在这里被拦。"""
    import asyncio

    import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert names == set(EXPECTED_TOOLS)


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


# --- 路由表写权限的字段级闸门（Codex review P1） ---
# 背景：不给 PutItem **不足以**限制可写字段——UpdateItem 本身就能改任意属性。
# 唯一的字段级闸门是 dynamodb:Attributes 条件键。这两个测试锁住两端：
# 白名单必须覆盖实现真正会碰的字段（少了 → 线上 AccessDenied），
# 且不得包含路由指向类字段（多了 → runtime 被攻破即可劫持流量）。

def test_routing_projection_allowlist_matches_permissions_writer():
    """白名单必须与 permissions.write_permissions 的 route_update 精确对齐。

    从实现源码里把字段解析出来比对，而不是手写第二份清单——手写两份的话
    permissions.py 加字段时这里不会失败，症状是线上改权限报 AccessDenied。
    """
    import deploy_agentcore

    src = (MCP_DIR.parent / "deployer" / "functions" / "permissions.py").read_text()
    # 截取 route_update 定义块
    start = src.index("route_update = {")
    block = src[start:src.index("items = [{\"Update\": site_update}", start)]

    update_expr = re.search(r'"UpdateExpression":\s*\((.*?)\),\n', block, re.S).group(1)
    # SET a = :x, b = :y → 取等号左侧的属性名（#ro 这类别名后面单独解析）
    written = set(re.findall(r"([#\w]+)\s*=\s*:", update_expr))
    aliases = dict(re.findall(r'"(#\w+)":\s*"(\w+)"',
                              re.search(r'"ExpressionAttributeNames":\s*\{([^}]*)\}',
                                        block).group(1)))
    # 别名换成真实属性名：dynamodb:Attributes 收的是解析后的名字
    resolved = {aliases.get(name, name) for name in written}
    # 条件表达式与 Key 引用的属性同样计入 dynamodb:Attributes
    resolved |= set(re.findall(r"attribute_exists\((\w+)\)", block))
    resolved |= {"subdomain"}   # 分区键，官方要求主键必列

    allowlist = set(deploy_agentcore.ROUTE_PROJECTION_ATTRIBUTES)
    assert resolved <= allowlist, (
        f"实现会写/读但白名单没有的字段: {sorted(resolved - allowlist)}"
        "——线上会 AccessDenied（不是事务取消，别误判成条件冲突）")
    assert allowlist <= resolved, (
        f"白名单多出实现并不需要的字段: {sorted(allowlist - resolved)}"
        "——每一个多余字段都是 runtime 被攻破后的可写攻击面")
    # 别名不能漏进白名单（放 #ro 而非 owner 时闸门形同虚设）
    assert not any(a.startswith("#") for a in allowlist)


def test_routing_projection_cannot_write_traffic_fields():
    """route_mode / static_prefix / api_target / site_id 绝不能进白名单。

    这四个决定"流量去哪"。owner 也在闸门内但必须保留（权限投影要写它）——
    它的风险由 Edge 侧 _is_platform_route 承担，见 deploy_agentcore 的注释。
    """
    import deploy_agentcore
    forbidden = {"route_mode", "static_prefix", "api_target", "site_id"}
    leaked = forbidden & set(deploy_agentcore.ROUTE_PROJECTION_ATTRIBUTES)
    assert not leaked, f"路由指向字段进了 MCP 可写白名单: {sorted(leaked)}"


def test_routing_policy_has_null_guard_and_no_putitem():
    """三个易错点的源码级锁定（每一个都会让闸门静默失效）。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    stmt_start = src.index('"Sid": "RoutingProjection"')
    stmt = src[stmt_start:stmt_start + 2000]
    # ① ForAllValues 在键缺失时为 true —— 必须有 Null 兜底
    assert '"Null": {"dynamodb:Attributes": "false"}' in stmt
    # ② UpdateItem 的隐式读能通过 ReturnValues 带回完整 item
    assert '"dynamodb:ReturnValues"' in stmt
    # ③ 路由表整条覆盖只能由部署链做
    assert "PutItem" not in stmt and "DeleteItem" not in stmt


def test_sites_table_has_no_putitem():
    """sites 表不得有 PutItem：整条覆盖可绕过 owner 判定重写站点归属。

    与 jobs 表分开成独立 statement 就是为了这个——合在一条里时 sites
    会因为 create_job 需要 PutItem 而顺带获得整条写权限。
    """
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    stmt_start = src.index('"Sid": "Sites"')
    stmt = src[stmt_start:src.index("},", stmt_start)]
    assert "PutItem" not in stmt
    assert "site-sites" in stmt
