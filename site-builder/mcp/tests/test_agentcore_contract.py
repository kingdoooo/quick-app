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
    """request_context.request 自 mcp 1.10.0 引入；>=1.9 会让身份识别静默失效。

    下限声明在 requirements.in（范围真源），锁定产物在 requirements.txt。
    """
    req = (MCP_DIR / "requirements.in").read_text()
    m = re.search(r"^mcp>=(\d+)\.(\d+)", req, re.M)
    assert m, "requirements.in 必须钉 mcp 下限"
    major, minor = int(m.group(1)), int(m.group(2))
    assert (major, minor) >= (1, 10)


def test_deploy_script_sets_authorization_allowlist_and_jwt_authorizer():
    """Authorization 不进 allowlist 就到不了容器，_caller_email 必失败；
    而 Authorization 透传又要求 runtime 配 customJWTAuthorizer。

    断言**构造出来的真实参数**而不是源码字符串：allowlist 自 M4 起是从配置派生
    的（多一个 on-behalf 头，见 test_component_gate.py），字符串匹配那种写法会
    在派生化的当天变红，而它本来要守的不变量（Authorization 恒在）没变。
    """
    import configparser

    import deploy_agentcore as da
    cfg = configparser.ConfigParser()
    cfg.read_string("[Platform]\nregion = us-east-1\n"
                    "[Cognito]\nuser_pool_id = us-east-1_x\nmcp_client_id = c\n")
    assert da.request_header_allowlist(cfg) == ["Authorization"]
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
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
    tok = f"h.{_b64({'email': 'user@example.com', 'email_verified': True})}.sig"
    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx(f"Bearer {tok}"))
    assert server._caller_email() == "user@example.com"

    # 非法：token 有效但没有 email claim（Cognito access token 默认就是这样）
    tok2 = f"h.{_b64({'sub': 'abc', 'client_id': 'x'})}.sig"
    monkeypatch.setattr(server.mcp, "get_context", lambda: _Ctx(f"Bearer {tok2}"))
    with pytest.raises(server.NotOwner):
        server._caller_email()


# token / 请求上下文的构造在 conftest（**一份实现**）：on-behalf 那组用例
# （test_tools.py）需要同样的构造再多一个头，两边各抄一份的话，其中一份
# 忘记小写化头名就会让拒绝类用例假通过。
from conftest import make_token as _token, with_auth as _with_auth  # noqa: E402


def test_caller_email_accepts_trusted_idp(monkeypatch):
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu,Okta")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth",
                                    "email_verified": True}))
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
                                    "auth_via": "TokenGeneration_RefreshTokens",
                                    "email_verified": True}))
    assert server._caller_email() == "a@x.com"


def test_caller_email_skips_idp_check_when_unconfigured(monkeypatch):
    """TRUSTED_IDPS 为空 = 迁移宽限期（与 Edge 的开关对齐），放行但不推荐。"""
    import server
    monkeypatch.setenv("TRUSTED_IDPS", "")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "email_verified": True}))
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
    """sites 表在**任何** statement 里都不得出现 PutItem/DeleteItem。

    整条覆盖可绕过 owner 判定重写站点归属。按生成的 policy 全表扫描，
    不按单个 Sid——早先版本写死了 Sid 名，Sid 一改名测试就报
    ValueError 而不是真正校验（改名时确实发生了）。
    """
    import json
    from unittest.mock import MagicMock

    import deploy_agentcore as da

    captured = {}
    fake = MagicMock()
    fake.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::1:role/r"}}
    fake.put_role_policy.side_effect = lambda **kw: captured.update(kw)
    real_iam, da.iam = da.iam, fake
    try:
        da.ensure_role()
    finally:
        da.iam = real_iam
    policy = json.loads(captured["PolicyDocument"])

    for stmt in policy["Statement"]:
        resources = stmt["Resource"]
        resources = [resources] if isinstance(resources, str) else resources
        if not any("table/site-sites" in r for r in resources):
            continue
        actions = stmt["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        assert "dynamodb:PutItem" not in actions, stmt.get("Sid")
        assert "dynamodb:DeleteItem" not in actions, stmt.get("Sid")


def _statement(da, sid: str) -> dict:
    """跑 ensure_role() 抓真正下发的 policy，按 Sid 取 statement。

    **断言生成结果而不是源码文本**：源码里出现 "Null" 字样不等于它进了下发的
    JSON（拼错键名、放错嵌套层级、被后面的 dict 覆盖，源码搜索全都看不出来）。
    """
    import json
    from unittest.mock import MagicMock

    captured = {}
    fake = MagicMock()
    fake.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::1:role/r"}}
    fake.put_role_policy.side_effect = lambda **kw: captured.update(kw)
    real_iam, da.iam = da.iam, fake
    try:
        da.ensure_role()
    finally:
        da.iam = real_iam
    policy = json.loads(captured["PolicyDocument"])
    return next(s for s in policy["Statement"] if s.get("Sid") == sid)


# --- sites 表写权限也要字段级闸门（Codex re-review P0） ---
# 上一轮只给 routing 加了 dynamodb:Attributes，sites 仍是无条件 UpdateItem
# ——而"不给 PutItem"挡不住 UpdateItem 改任意属性。

def test_sites_write_has_attribute_gate():
    import deploy_agentcore as da
    stmt = _statement(da, "SitesWrite")
    cond = stmt["Condition"]
    assert cond["ForAllValues:StringEquals"]["dynamodb:Attributes"] == \
        list(da.SITE_WRITABLE_ATTRIBUTES)
    assert cond["Null"] == {"dynamodb:Attributes": "false"}
    assert stmt["Action"] == "dynamodb:UpdateItem"


def test_sites_write_excludes_deploy_chain_fields():
    """部署链自己的字段不得进 MCP 白名单——被攻破的 runtime 可篡改部署状态。"""
    import deploy_agentcore as da
    forbidden = {"data_tables", "migrations_applied", "last_job_id",
                 "dsql_schema", "api_target", "static_prefix"}
    leaked = forbidden & set(da.SITE_WRITABLE_ATTRIBUTES)
    assert not leaked, f"部署链字段进了 MCP 可写白名单: {sorted(leaked)}"


def _create_site_record_src(common_path) -> str:
    """common.create_site_record 的函数体源码（**不含 docstring**）。

    用 AST 定位而不是文本切片：该函数的 docstring 里就写着
    `attribute_not_exists(site_id)`、`UpdateItem`、`PutItem` 这些字样，
    按文本找会把解释性文字当成实现。本仓库栽过一次同类
    （断言命中的字样其实只留在注释里，改了代码测试照样绿）。
    """
    import ast
    tree = ast.parse(common_path.read_text())
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "create_site_record")
    body = [n for n in fn.body
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                    and isinstance(n.value.value, str))]
    assert body, "create_site_record 只有 docstring，没有实现"
    return "\n".join(ast.unparse(n) for n in body)


def test_sites_write_covers_every_reachable_mcp_write():
    """白名单必须覆盖 MCP 真正会写的字段，否则线上 AccessDenied。

    从实现源码解析：write_permissions 的 site_update + 建站路径
    common.create_site_record 实际写的字段。手抄第二份清单的话，
    permissions.py 加字段时这里不会失败。
    """
    import re

    import deploy_agentcore as da

    fn_dir = MCP_DIR.parent / "deployer" / "functions"
    perm = (fn_dir / "permissions.py").read_text()
    block = perm[perm.index("sets = ["):perm.index("site_update = {")]
    fields = set(re.findall(r'"(\w+) = :', block))
    aliases = dict(re.findall(r'names\["(#\w+)"\]\s*=\s*"(\w+)"', block))
    fields |= {aliases.get(a, a) for a in re.findall(r'"(#\w+) = :', block)}

    # 建站路径：解析 create_site_record 的 UpdateExpression **实际取值**，
    # 而不是 server.py 那行调用的 kwargs 名。
    #   · kwargs 名不等于落库字段名（status 是默认参数，调用方根本不传，
    #     按 kwargs 解析会漏掉它；created_at 更是只在函数体里生成）；
    #   · 早先版本 regex 匹配 `common.upsert_site(site_id, ...)`，
    #     改名成 create_site_record 后 re.search 返回 None，测试以
    #     AttributeError 报错而不是真正校验白名单——正是"源码文本断言锚点
    #     跟着重构漂移"这一类。锚在被断言的那条写语句上最稳。
    # 注：_create_site_record_src 返回 ast.unparse 的结果，字符串一律单引号。
    cm = _create_site_record_src(fn_dir / "common.py")
    expr = re.search(r"UpdateExpression='([^']*)'", cm).group(1)
    cm_aliases = dict(re.findall(r"'(#\w+)':\s*'(\w+)'", cm))
    for tok in re.findall(r"(#?\w+) = :", expr):
        fields.add(cm_aliases.get(tok, tok))
    assert not any(f.startswith("#") for f in fields), (
        f"create_site_record 的别名没解析全: {sorted(fields)}")
    assert "created_at" in fields, (
        "没从 create_site_record 解析出 created_at——解析器与实现脱钩了")
    fields |= {"site_id"}          # 分区键，官方要求主键必列

    allow = set(da.SITE_WRITABLE_ATTRIBUTES)
    assert fields <= allow, (
        f"MCP 会写但白名单缺失: {sorted(fields - allow)}——线上 AccessDenied")
    assert not any(a.startswith("#") for a in allow)


def test_sites_read_has_no_attribute_condition():
    """读侧绝不能带 Attributes/Null 条件。

    Query/Scan 不带 ProjectionExpression 时请求上下文没有 dynamodb:Attributes,
    Null 检查会把 list_my_sites 直接拒掉——这是"收紧策略反而弄挂功能"的典型。
    """
    import deploy_agentcore as da
    stmt = _statement(da, "SitesRead")
    assert "Condition" not in stmt
    assert "dynamodb:Query" in stmt["Action"]
    assert "dynamodb:UpdateItem" not in stmt["Action"]


def test_routing_projection_has_no_getitem():
    """MCP 无读路由表的代码；留着 GetItem 会被同 statement 的 Null 检查拒。"""
    import deploy_agentcore as da
    stmt = _statement(da, "RoutingProjection")
    assert "dynamodb:GetItem" not in stmt["Action"]


# --- email_verified 必须真的参与授权判定（Codex re-review P1） ---
# 上一轮只把它映射进用户档案，没有任何一处校验它——"只映射不检查"没有形成
# 技术防线。当前飞书适配器实测会发 email_verified=true，所以严格检查可实施。

def test_caller_email_rejects_unverified_email(monkeypatch):
    import server
    monkeypatch.delenv("REQUIRE_EMAIL_VERIFIED", raising=False)
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth",
                                    "email_verified": "false"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


def test_caller_email_rejects_missing_email_verified(monkeypatch):
    """缺 claim 也要拒（fail-closed）——否则拿旧 token 就能绕过。"""
    import server
    monkeypatch.delenv("REQUIRE_EMAIL_VERIFIED", raising=False)
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth"}))
    with pytest.raises(server.NotOwner):
        server._caller_email()


@pytest.mark.parametrize("verified", [True, "true", "True"])
def test_caller_email_accepts_verified_forms(monkeypatch, verified):
    """id_token 给 JSON 布尔，pre-token 注入的是字符串——两种都要认。"""
    import server
    monkeypatch.delenv("REQUIRE_EMAIL_VERIFIED", raising=False)
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth",
                                    "email_verified": verified}))
    assert server._caller_email() == "a@x.com"


def test_email_verified_check_can_be_disabled_for_idp_without_claim(monkeypatch):
    """接入不发该 claim 的 IdP 时可关（代价是这道防线消失）。"""
    import server
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFIED", "false")
    monkeypatch.setenv("TRUSTED_IDPS", "Feishu")
    _with_auth(monkeypatch, _token({"email": "a@x.com", "idp": "Feishu",
                                    "auth_via": "TokenGeneration_HostedAuth"}))
    assert server._caller_email() == "a@x.com"


def test_email_verified_default_is_enforcing(monkeypatch):
    """默认必须是"要求已验证"——默认关掉等于没修。"""
    import server
    monkeypatch.delenv("REQUIRE_EMAIL_VERIFIED", raising=False)
    assert server._require_email_verified() is True


def test_sites_write_comment_states_trust_boundary_honestly():
    """注释不得声称 IAM 能阻止 owner takeover（它不能）。

    上一轮的提交消息说攻击链被"两处独立封堵"，实际 sites/routing 都仍允许写
    owner，真正阻断跨站 cookie 的只有 Edge 一道。这类过度声称比缺少防护更
    危险：后来的人会据此以为 runtime 被攻破也丢不了站点归属。
    """
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    start = src.index('"Sid": "SitesWrite"')
    block = src[max(0, start - 2600):start]
    assert "TCB" in block or "可信计算基" in block, \
        "SitesWrite 上方必须写明 runtime 属于 TCB"
    assert "LeadingKeys" in block, "必须写明为何 IAM 关不掉这条路径"


def test_owner_stays_writable_by_design():
    """owner 必须留在白名单里——这是功能需求，不是遗漏。

    锁住这一点是为了防止有人"为了安全"把它删掉：删掉会让建站与
    transfer_owner 在线上 AccessDenied，而真正的封堵点不在这里。
    """
    import deploy_agentcore as da
    assert "owner" in da.SITE_WRITABLE_ATTRIBUTES
    assert "owner" in da.ROUTE_PROJECTION_ATTRIBUTES


# --- TCB 供应链必须可复现、不可变（Codex re-review P1） ---
# runtime 被攻破 = 任意站点 owner 可被接管（见 SitesWrite 注释）。既然如此，
# "runtime 跑的是哪份字节"就是安全边界本身，不能依赖可变 tag / 浮动依赖。

def test_ecr_repo_is_created_immutable():
    """imageTagMutability 省略时 AWS 默认 MUTABLE——任何有 push 权限的主体
    都能覆盖同名 tag，静默换掉 TCB。必须显式 IMMUTABLE，且对已存在的仓库
    也要纠正回来。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    block = src[src.index("def ensure_repo"):src.index("def image_tag")]
    assert '"IMMUTABLE"' in block
    assert "put_image_tag_mutability" in block, "已存在的仓库也要纠正"


def test_no_latest_tag_anywhere():
    """`latest` 在 IMMUTABLE 仓库下第二次就 push 不上去，且让"线上跑哪份代码"
    无法回答。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    assert 'IMAGE_TAG = "latest"' not in src
    assert '"latest"' not in src


def test_image_tag_is_traceable_to_a_commit():
    """tag 必须能对回提交；输入未提交时用 wip-<内容 hash> 区分（且唯一）。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    block = src[src.index("def image_tag"):src.index("def find_image_digest")]
    assert "rev-parse" in block
    assert "wip-" in block and "git-" in block


def test_runtime_is_deployed_by_digest_not_tag():
    """tag 是名字、digest 是内容。runtime 必须引用 digest。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    assert "resolve_digest" in src
    main = src[src.index("def main()"):]
    assert "pinned_uri" in main and "@{digest}" in main
    # 不得把 tag 形态的 uri 交给 deploy_runtime
    assert "deploy_runtime(pinned_uri" in main


def test_base_image_pinned_by_digest():
    """`python:3.13-slim` 这个 tag 上游随时会重新指向新镜像。"""
    df = (MCP_DIR / "Dockerfile").read_text()
    m = re.search(r"^FROM .*python:3\.13-slim@sha256:[0-9a-f]{64}$", df, re.M)
    assert m, "基础镜像必须钉 digest"
    assert "--platform=linux/arm64" in df      # 平台约束不能因此丢掉


def test_dependencies_are_hash_locked():
    """--require-hashes：任何依赖（含传递依赖）少 hash 或对不上即构建失败。"""
    df = (MCP_DIR / "Dockerfile").read_text()
    assert "--require-hashes" in df
    lock = (MCP_DIR / "requirements.txt").read_text()
    pkgs = re.findall(r"^([A-Za-z0-9._-]+)==", lock, re.M)
    assert len(pkgs) >= 20, f"锁定清单只有 {len(pkgs)} 个包，像是没含传递依赖"
    # 每个包都必须至少带一个 hash
    for pkg in pkgs:
        seg = lock[lock.index(f"\n{pkg}=="):]
        seg = seg[:seg.index("\n# via") if "\n# via" in seg[:4000] else 400]
        assert "--hash=sha256:" in seg, f"{pkg} 没有 hash"


def test_mcp_pinned_within_tested_major_version():
    """锁定的目的是"部署的就是验证过的"。

    全部测试跑在 mcp 1.x 上；让 pip-compile 自由解析到 2.0（主版本跃迁，
    FastMCP / request_context 无兼容承诺）与这个目的相反。
    """
    src = (MCP_DIR / "requirements.in").read_text()
    assert re.search(r"^mcp>=1\.\d+,<2", src, re.M), "mcp 必须钉上界 <2"
    lock = (MCP_DIR / "requirements.txt").read_text()
    m = re.search(r"^mcp==(\d+)\.", lock, re.M)
    assert m and m.group(1) == "1", f"锁定到了未验证的主版本: {m and m.group(0)}"


# --- IMMUTABLE 仓库下的幂等性（Codex re-review P1） ---
# 上一版用 `git status --porcelain` 判全仓库脏，于是任何无关改动（本仓库长期
# 保留未跟踪的 docs/design/）都让 tag 变成固定的 `-dirty`——而 IMMUTABLE 仓库
# 不允许覆盖同名 tag，第二次运行必然 ImageTagAlreadyExistsException，
# 脚本 docstring 承诺的"幂等可重跑"随之失效。

def test_dirty_detection_only_considers_build_inputs():
    """无关文件（文档、别的包、未跟踪目录）不得影响 tag。"""
    import deploy_agentcore as da
    for rel in da._BUILD_INPUTS:
        assert rel.startswith(("mcp/", "deployer/functions/")), rel
    # Dockerfile 真正 COPY 的东西必须都在清单里
    df = (MCP_DIR / "Dockerfile").read_text()
    for name in ("requirements.txt", "server.py"):
        assert f"mcp/{name}" in da._BUILD_INPUTS, name
        assert name in df
    # 复制进上下文的两个外部文件同样是输入
    assert "deployer/functions/common.py" in da._BUILD_INPUTS
    assert "deployer/functions/permissions.py" in da._BUILD_INPUTS
    # 不得再用全仓库 status 判脏
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    fn = src[src.index("def build_inputs_fingerprint"):src.index("def image_tag")]
    assert "status" not in fn, "dirty 判定不能用 git status（会被无关文件污染）"


def test_wip_tag_varies_with_content_not_a_fixed_suffix():
    """固定的 `-dirty` 后缀会让两次不同改动共用一个 tag → 撞 IMMUTABLE。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    fn = src[src.index("def build_inputs_fingerprint"):src.index("def image_tag")]
    assert "sha256" in fn, "dirty 后缀必须是输入内容 hash"
    tag_fn = src[src.index("def image_tag"):src.index("def find_image_digest")]
    assert '"-dirty"' not in tag_fn


def test_existing_tag_is_reused_instead_of_repushed():
    """同一份输入重跑必须复用已有镜像，不能再 push。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    main = src[src.index("def main()"):]
    assert "find_image_digest(tag)" in main
    # 复用分支必须在 build_and_push 之前判掉
    assert main.index("elif existing") < main.index("build_and_push(image_uri)")


def test_reused_tag_must_match_running_digest_or_fail_closed():
    """tag 从 commit SHA 可预测，而 ECR push 权限尚未收敛到 CI（DEPLOY.md
    「仍未做」）——任何有 push 权限的主体可抢先 push `git-<sha>`，IMMUTABLE
    反而保护抢占者的镜像不被覆盖。所以"tag 已存在就复用"必须先证明这是
    **真正的重跑**：当前 runtime 已指向同一 digest。否则 fail closed，
    显式逃生口 --trust-existing-image。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    assert "--trust-existing-image" in src
    assert "def runtime_current_digest" in src
    main = src[src.index("def main()"):]
    # 守卫必须在"把 digest 部署为 TCB"（resolve_digest）之前
    guard = main[main.index("runtime_current_digest"):main.index("resolve_digest(tag)")]
    assert "sys.exit(" in guard, "digest 不匹配必须拒绝部署，不能只警告"
    # --skip-build 同样复用已有镜像，守卫必须覆盖两条复用路径：
    # 写成分支后的统一检查（在 elif existing 之后、resolve 之前）
    assert main.index("elif existing") < main.index("runtime_current_digest")


def test_find_image_digest_tolerates_missing_tag_and_repo():
    """查不到不是异常路径——首次部署时仓库和 tag 都不存在。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    fn = src[src.index("def find_image_digest"):src.index("def resolve_digest")]
    assert "ImageNotFoundException" in fn
    assert "RepositoryNotFoundException" in fn
    assert "return None" in fn


def test_dirty_build_is_refused_by_default():
    """TCB 的镜像默认必须能对回提交；联调要显式 --allow-dirty。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    assert "--allow-dirty" in src
    main = src[src.index("def main()"):]
    assert "sys.exit(" in main[main.index('tag.startswith("wip-")'):]


def test_skip_build_fails_loudly_when_tag_absent():
    """改过构建输入后加 --skip-build 会指向不存在的 tag，必须明确失败。"""
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    main = src[src.index("def main()"):]
    seg = main[main.index("if args.skip_build"):main.index("elif existing")]
    assert "sys.exit(" in seg


def test_locked_runner_rebuilds_on_lock_change_and_verifies_versions():
    """旧 venv 里只要有可执行 pytest 就被复用——lock 更新后"锁定测试"跑的仍是
    旧依赖（Codex 探针实证：宿主 mcp 1.26.0 下自称 locked 且 88 passed）。
    修复契约：
      · venv 带 requirements.txt+Python 版本指纹，不匹配 --clear 重建；
      · 测试依赖（pytest/moto）受 lock 约束（-c），不得升级已锁定的运行依赖；
      · 安装后程序化比对已装版本 == lock，不一致必须非零退出，不能只打印。
    """
    sh = (MCP_DIR / "run_locked_tests.sh").read_text()
    assert ".lock-stamp" in sh, "必须有 lock 指纹文件"
    assert "sha256" in sh, "指纹必须含 requirements.txt 内容 hash"
    assert "--clear" in sh, "指纹不匹配必须整个重建,不做增量修补"
    assert re.search(r"pip.*install.*-c\b", sh), "测试依赖必须受 lock 约束(-c)"
    assert "sys.exit" in sh, "版本比对失败必须非零退出"
    import subprocess
    assert subprocess.run(["bash", "-n", str(MCP_DIR / "run_locked_tests.sh")],
                          capture_output=True).returncode == 0


def test_container_runs_as_non_root():
    """TCB 容器持有能管理全部站点的角色凭证，不该以 root 跑（AgentCore 安全指引）。

    真机已验证：uid=10001(appuser)，且仍能绑 0.0.0.0:8000
    （8000 > 1024，非特权用户可直接绑定——这是能降权的前提）。
    """
    df = (MCP_DIR / "Dockerfile").read_text()
    assert re.search(r"^USER\s+10001", df, re.M), "必须显式降权到非 root"
    assert "useradd" in df and "10001" in df
    # 降权必须发生在 COPY 之后（否则应用文件会以非 root 属主进镜像层）
    assert df.index("COPY server.py") < df.index("USER 10001")


def test_app_dir_is_not_writable_by_runtime_user():
    """降权的意义是"进程内漏洞 ≠ 容器内任意写"。/app 若归运行用户所有
    （chown -R appuser /app），被攻破的进程可改写 server.py/permissions.py,
    后门在容器重启前对所有后续请求生效——这否定了降权本身。
    代码保持 root:root、运行用户只读执行;server 不写 /app
    (PYTHONDONTWRITEBYTECODE 已设,工具全部无状态)。
    """
    df = (MCP_DIR / "Dockerfile").read_text()
    assert not re.search(r"chown[^\n]*/app", df), \
        "/app 不得 chown 给运行用户——代码必须对运行用户只读"


# --- 事务路径需要的 ConditionCheckItem（Codex 复审 2026-08-07 P1 的配套）---
# do_confirm_upload 与 do_undeploy 现在把"权限快照未变"作为 ConditionCheck 绑进
# 最终动作的事务。IAM 里没有 dynamodb:TransactWriteItems 这个 action：事务内
# Put/Update 由同名 action 授权，**ConditionCheck 由 ConditionCheckItem 授权**。
# 缺这条的表现是"改权限/下线在线上一律 AccessDenied"，而单测用 moto 不做 IAM
# 授权，永远发现不了 —— 所以必须在这里锁住。

def test_transaction_paths_have_condition_check_permission():
    import deploy_agentcore as da
    for sid, why in (("SitesRead", "confirm_upload/undeploy 的 rev ConditionCheck"),
                     ("AdminsReadOnly", "admin 代管路径的 admin ConditionCheck"),
                     ("Jobs", "undeploy 的 create_job 事务 Put + confirm 的 Update")):
        actions = _statement(da, sid)["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        assert "dynamodb:ConditionCheckItem" in actions, (
            f"{sid} 缺 ConditionCheckItem（{why}）——线上该路径必 AccessDenied")


def test_mcp_delegates_snapshot_guard_and_passes_action():
    """MCP **不得**自己拼守卫条件，必须委托 permissions.sites_snapshot_guard，
    并把 action 传进去。

    条件表达式本身的正确性由 deployer/tests/test_permissions.py 断言（那里是
    唯一定义）。这里只钉住"MCP 侧确实在用那一份、且带上了 action"——action
    决定无-rev 分支允许哪些角色：漏传就会退化成"owner/collaborator 二者之一"，
    而 undeploy 本不该给 collaborator（旧 owner 被降级后仍能 purge 数据）。
    """
    import re
    srv = (MCP_DIR / "server.py").read_text()
    rev_block = srv[srv.index("def _rev_condition_check"):
                    srv.index("def _admin_condition_check")]
    assert "permissions.sites_snapshot_guard" in rev_block, (
        "MCP 没有委托 permissions.sites_snapshot_guard——手抄第二份守卫是"
        "三轮审查反复出 P1 的根因")
    # 不得自己写条件表达式
    assert '"ConditionExpression"' not in rev_block, (
        "MCP 又开始自己拼 ConditionExpression 了——守卫只能有一份定义")
    # 两个调用点都必须显式传 action，且与该工具真实执行的动作一致
    for call, action in (("deploy", "deploy"), ("undeploy", "undeploy")):
        assert re.search(
            r'_rev_condition_check\([^)]*"%s"\)' % re.escape(action), srv), (
            f"_rev_condition_check 的调用点没传 action={action!r}——"
            "无 rev 的存量站点会按错误的角色集放行")
    # undeploy 的 action 必须真是 "undeploy"（若误传 "deploy"，collaborator
    # 会被放进来，这正是复现过的那个 P1）
    undeploy_fn = srv[srv.index("def do_undeploy"):srv.index("class PermissionConflict")]
    assert '_rev_condition_check(authz, site_id, "undeploy")' in undeploy_fn, (
        "do_undeploy 必须以 action=\"undeploy\" 取守卫——传 deploy 会让"
        "被降级为 collaborator 的旧 owner 仍能 purge 掉新 owner 的数据")
    admin_block = srv[srv.index("def _admin_condition_check"):
                      srv.index("# ---------- 纯函数层")]
    assert re.search(r'os\.environ\["ADMINS_TABLE"\]', admin_block), \
        "admin 守卫没有打在 ADMINS_TABLE 上"


def test_ops_log_is_append_only_for_mcp_runtime():
    """审计表只能 PutItem——给 Update/Delete 就等于允许篡改审计历史。

    也不给读：runtime 没有读审计的业务需要，Scan 权限等于多一条"谁改过谁的
    权限"的泄漏面。断言动作集**恰好**是 {PutItem}，不是"包含 PutItem"。
    """
    import json
    from unittest.mock import MagicMock

    import deploy_agentcore as da

    captured = {}
    fake = MagicMock()
    fake.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::1:role/r"}}
    fake.put_role_policy.side_effect = lambda **kw: captured.update(kw)
    real_iam, da.iam = da.iam, fake
    try:
        da.ensure_role()
    finally:
        da.iam = real_iam
    policy = json.loads(captured["PolicyDocument"])

    ops_stmts = []
    for stmt in policy["Statement"]:
        resources = stmt["Resource"]
        resources = [resources] if isinstance(resources, str) else resources
        if any("table/site-ops-log" in r for r in resources):
            ops_stmts.append(stmt)
    assert ops_stmts, (
        "MCP runtime role 缺 ops-log 权限——permissions.write_permissions 跑在 "
        "runtime 里，每次改权限都会在审计写入处 AccessDenied")
    actions = set()
    for stmt in ops_stmts:
        a = stmt["Action"]
        actions |= set(a if isinstance(a, list) else [a])
    assert actions == {"dynamodb:PutItem"}, f"ops-log 权限过宽: {sorted(actions)}"


def test_image_carries_every_local_module_the_server_chain_imports():
    """镜像里必须有 server.py 传递 import 到的**每个**本地模块。

    这条是实测踩出来的：M3 给 permissions.py 加了 `import ops_log` 之后，
    Dockerfile 的 `COPY server.py common.py permissions.py ./` 与
    build_and_push 的复制清单都没跟着改——单测全绿（宿主机上
    deployer/functions/ 在 sys.path 里），但**容器起来后每次改权限都
    ImportError**。逐个文件枚举的复制清单必须有机器来核对。

    做法：从 server.py 出发做传递闭包，凡是能在 deployer/functions/ 里找到
    同名 .py 的 import 都算"必须进镜像"，然后与 Dockerfile 的 COPY 行
    以及 build_and_push 的复制元组比对。
    """
    import ast

    fn_dir = MCP_DIR.parent / "deployer" / "functions"

    def local_imports(path: Path) -> set[str]:
        names = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        return names

    needed, queue, seen = set(), ["server.py"], set()
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        path = MCP_DIR / cur if (MCP_DIR / cur).exists() else fn_dir / cur
        if not path.exists():
            continue
        for name in local_imports(path):
            candidate = fn_dir / f"{name}.py"
            if candidate.exists():
                needed.add(f"{name}.py")
                queue.append(f"{name}.py")

    assert "ops_log.py" in needed, (
        "传递闭包没算出 ops_log.py——本用例的解析逻辑坏了（permissions.py "
        "确实 import 它）")

    dockerfile = (MCP_DIR / "Dockerfile").read_text()
    copy_line = next(l for l in dockerfile.splitlines()
                     if l.startswith("COPY") and "server.py" in l)
    src = (MCP_DIR / "deploy_agentcore.py").read_text()
    copy_tuple = re.search(r'for name in \(([^)]*)\)', src).group(1)

    for mod in sorted(needed):
        assert mod in copy_line, (
            f"Dockerfile 的 COPY 缺 {mod}——容器里会 ImportError（{copy_line}）")
        assert mod in copy_tuple, (
            f"build_and_push 的复制清单缺 {mod}，构建上下文里不会有它")
        # 指纹也要覆盖：漏了它，改 ops_log.py 不会让镜像标记为 dirty，
        # tag 仍指向旧内容
        assert f"functions/{mod}" in src, (
            f"_BUILD_INPUTS 缺 {mod}——改它不会触发新 tag，会部署出陈旧镜像")
