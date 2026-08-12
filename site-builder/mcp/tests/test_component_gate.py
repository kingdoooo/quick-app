"""三处组件门禁的纯函数层（二期 M4，spec §5.1.1）。

API Key 是**可选组件**。"没配 `[ApiKey]` 段 = 只允许 OAuth"这件事由三道门禁
共同成立：

  ① `allowedClients` 不含 machine client → 机器 token 在**网关层**就被拒，
     不经过我们任何代码（这是最强的一道，也是 spike 实证过 fail-closed 的那条）；
  ② `requestHeaderAllowlist` 不含 `X-SB-On-Behalf-Of` → 头到不了容器；
  ③ 容器的 `MACHINE_CLIENT_ID` 为空 → `server._caller_email()` 拒掉所有
     on-behalf 请求。

**本文件的重点不是"全关"能过，而是"半开"必须被拦**：一道开、另一道关是比全关
更危险的状态（①开②③关 → 网关放行、容器拒绝，症状是 HTTP 200 加一句业务错误
文案，最难排查）。所以下面的断言形态是**当且仅当**，不是"各自都对"。
"""
import ast
import configparser
import subprocess
import sys
from pathlib import Path

import pytest

MCP_DIR = Path(__file__).parents[1]
SB_DIR = MCP_DIR.parent
FUNCTIONS = SB_DIR / "deployer" / "functions"

MACHINE_ID = "machine1234567890abcdef"
MCP_ID = "mcpclient1234567890abcd"

# 三个部署脚本（DEPLOY.md 里的真实执行形态：脚本路径 + 工作目录）。
# deploy_key_proxy.py 由 Task 8 创建——**不在这里预留占位**，下面的用例按
# "存在即必须合规"处理，并显式断言至少覆盖到了已有的两个（避免哪天列表被清空
# 而测试仍然全绿）。
DEPLOY_SCRIPTS = {
    "deploy_pool.py": (SB_DIR / "scripts" / "deploy_pool.py", SB_DIR),
    "deploy_agentcore.py": (MCP_DIR / "deploy_agentcore.py", MCP_DIR),
    "deploy_key_proxy.py": (SB_DIR / "key-proxy" / "deploy_key_proxy.py",
                            SB_DIR / "key-proxy"),
}


def _cfg(with_api_key: bool = False, *, machine_client_id: str = MACHINE_ID,
         api_key_extra: str = "") -> configparser.ConfigParser:
    """一份与真实 config.ini 同形态的配置（值都是示例值，不含真实账号）。"""
    text = f"""
[Platform]
base_domain = example.com
account_id = 000000000000
region = us-east-1
routing_table = ApplicationWebRouterStack-subdomain-mapping

[Cognito]
user_pool_id = us-east-1_example
domain = https://site-builder-auth.auth.us-east-1.amazoncognito.com
site_client_id = siteclient1234567890abc
mcp_client_id = {MCP_ID}
machine_client_id = {machine_client_id}

[Deployer]
jobs_table = site-deploy-jobs
sites_table = site-sites
admins_table = site-admins
state_machine_arn = arn:aws:states:us-east-1:000000000000:stateMachine:site-deploy

[IdP]
provider_name = Okta
require_email_verified = true
"""
    if with_api_key:
        text += "\n[ApiKey]\nkeys_table = site-api-keys\n" + api_key_extra
    cfg = configparser.ConfigParser()
    cfg.read_string(text)
    return cfg


# ── ① api_key_enabled 是唯一判定 ──────────────────────────────────────

def test_api_key_disabled_without_the_section():
    import api_key_config
    assert api_key_config.api_key_enabled(_cfg()) is False


def test_api_key_enabled_with_the_section():
    import api_key_config
    assert api_key_config.api_key_enabled(_cfg(True)) is True


def test_minimal_section_is_a_complete_component():
    """只写一行 `[ApiKey]` 也要得到齐全的派生值（其余键都有默认）。"""
    import api_key_config
    cfg = configparser.ConfigParser()
    cfg.read_string("[ApiKey]\n")
    assert api_key_config.machine_scope(cfg) == "site-builder-mcp/invoke"
    assert api_key_config.mcp_subdomain(cfg) == "mcp"


def test_derived_values_are_empty_when_component_is_off():
    """未启用时派生值必须是空串，不能给出"看起来能用"的默认值。

    拿默认值去建 resource server / 注册子域，就等于"没配也部署了半套"。
    """
    import api_key_config
    cfg = _cfg()
    assert api_key_config.machine_scope(cfg) == ""
    assert api_key_config.mcp_subdomain(cfg) == ""
    assert api_key_config.resource_server_id(cfg) == ""
    assert api_key_config.scope_name(cfg) == ""


def test_scope_is_composed_in_exactly_one_place():
    """`{identifier}/{scope}` 的拼接只在 machine_scope 里做。"""
    import api_key_config
    cfg = _cfg(True, api_key_extra="resource_server_id = my-rs\nscope = call\n")
    assert api_key_config.machine_scope(cfg) == "my-rs/call"
    assert api_key_config.machine_scope(cfg) == (
        f"{api_key_config.resource_server_id(cfg)}/"
        f"{api_key_config.scope_name(cfg)}")


def test_inline_comments_are_stripped_from_values():
    """configparser 默认保留行内注释；带进 scope 会换出一个不存在的 scope。"""
    import api_key_config
    cfg = _cfg(True, api_key_extra=(
        "resource_server_id = site-builder-mcp   # 基本不改\n"
        "scope = invoke  ; 同上\n"
        "mcp_subdomain = mcp    # 交换层子域\n"))
    assert api_key_config.machine_scope(cfg) == "site-builder-mcp/invoke"
    assert api_key_config.mcp_subdomain(cfg) == "mcp"


# ── ② 网关侧的两处派生（allowedClients / requestHeaderAllowlist）────────

def test_machine_client_absent_from_allowed_clients_without_section():
    """**组件门禁的第一层**：没配 [ApiKey] 时机器 token 在网关层就被拒。"""
    import deploy_agentcore as da
    assert da.allowed_clients(_cfg()) == [MCP_ID]


def test_machine_client_present_in_allowed_clients_with_section():
    import deploy_agentcore as da
    assert da.allowed_clients(_cfg(True)) == [MCP_ID, MACHINE_ID]


def test_empty_machine_client_id_aborts_instead_of_silently_skipping():
    """[ApiKey] 段存在但 machine_client_id 为空 → 中止。

    静默跳过会得到"以为部署了 API Key，其实网关不认"的状态，而排查方向会指向
    server 端（那里什么都没错）。
    """
    import deploy_agentcore as da
    for empty in ("", "   "):
        with pytest.raises(SystemExit, match="machine_client_id"):
            da.allowed_clients(_cfg(True, machine_client_id=empty))


def test_on_behalf_header_not_allowlisted_without_section():
    import deploy_agentcore as da
    assert da.request_header_allowlist(_cfg()) == ["Authorization"]


def test_on_behalf_header_allowlisted_with_section():
    import api_key_config
    import deploy_agentcore as da
    allowlist = da.request_header_allowlist(_cfg(True))
    assert allowlist == ["Authorization", api_key_config.ON_BEHALF_HEADER]


def test_authorization_is_always_allowlisted():
    """Authorization 不在 allowlist 里就到不了容器，所有工具当场失效。"""
    import deploy_agentcore as da
    for cfg in (_cfg(), _cfg(True)):
        assert "Authorization" in da.request_header_allowlist(cfg)


# ── ③ 三道门禁必须同向：半开状态要被拦住 ──────────────────────────────

def _gate_state(cfg) -> dict:
    """从**真实构造出来的 runtime 参数**读三道门禁的状态。

    刻意不各自调纯函数：漂移恰好发生在"纯函数对了，但 deploy_runtime 没把它用
    进去"（例如 environmentVariables 漏了 MACHINE_CLIENT_ID）。
    """
    import api_key_config
    import deploy_agentcore as da
    kwargs = da.runtime_kwargs(cfg, "repo@sha256:abc", "arn:aws:iam::0:role/r")
    authz = kwargs["authorizerConfiguration"]["customJWTAuthorizer"]
    return {
        "machine_in_allowed_clients": MACHINE_ID in authz["allowedClients"],
        "machine_env_non_empty": bool(
            kwargs["environmentVariables"][da.MACHINE_CLIENT_ID_ENV]),
        "header_allowlisted": api_key_config.ON_BEHALF_HEADER in
        kwargs["requestHeaderConfiguration"]["requestHeaderAllowlist"],
    }


@pytest.mark.parametrize("with_api_key", [False, True])
def test_three_gates_are_all_on_or_all_off(with_api_key):
    """**当且仅当**：三道门禁同开同关，不存在"一道开一道关"。

    ①（网关 allowedClients）与 ③（容器环境变量）来自两个完全不同的地方，
    分别写就会漂移，而漂移的那一半正是最难排查的状态。②（头 allowlist）同理。
    """
    state = _gate_state(_cfg(with_api_key))
    assert set(state.values()) == {with_api_key}, state


def test_machine_env_var_is_the_exact_client_id():
    """容器里的值必须逐字符等于 allowedClients 里那个 id（不是别名/前缀）。"""
    import deploy_agentcore as da
    kwargs = da.runtime_kwargs(_cfg(True), "img", "arn:role")
    assert kwargs["environmentVariables"][da.MACHINE_CLIENT_ID_ENV] == MACHINE_ID
    assert (kwargs["authorizerConfiguration"]["customJWTAuthorizer"]
            ["allowedClients"] == [MCP_ID, MACHINE_ID])


def test_runtime_kwargs_keeps_the_existing_agentcore_contract():
    """顺带锁住既有契约：MCP 协议 + customJWTAuthorizer + discovery URL。"""
    import deploy_agentcore as da
    kwargs = da.runtime_kwargs(_cfg(), "img", "arn:role")
    assert kwargs["protocolConfiguration"]["serverProtocol"] == "MCP"
    authz = kwargs["authorizerConfiguration"]["customJWTAuthorizer"]
    assert authz["discoveryUrl"].endswith("/.well-known/openid-configuration")
    assert "us-east-1_example" in authz["discoveryUrl"]


# ── ④ 头名与环境变量名：三处一致 ──────────────────────────────────────

def test_on_behalf_header_name_agrees_across_all_three_components():
    """网关 allowlist（原样大小写）、MCP server（小写）、key-proxy 出站（小写）
    必须是同一个头名。

    三处漂移的症状分别是"所有 Key 调用被拒""上游收不到身份""身份识别不了"，
    都不指向名字本身——所以用 real-value 断言把它们绑在一起。
    """
    import api_key_config
    import server
    canonical = api_key_config.ON_BEHALF_HEADER
    assert server.ON_BEHALF_HEADER == canonical.lower()
    handler = (SB_DIR / "key-proxy" / "handler.py").read_text()
    # key-proxy 出站时**加**的头（不是透传）。它在 handler 里是字面量，
    # 这条断言就是那份字面量与本真源之间的约束。
    assert f'out["{canonical.lower()}"] = email' in handler, \
        "key-proxy 加的 on-behalf 头名与 api_key_config.ON_BEHALF_HEADER 不一致"


def test_machine_client_env_var_name_agrees_between_gateway_and_container():
    """下发方（deploy_agentcore）与读取方（server）用同一个变量名。

    名字漂移的后果不是报错，而是网关放行、容器读到空值 → 全部 on-behalf 请求
    被拒（HTTP 200 + 业务错误文案）。
    """
    import deploy_agentcore as da
    import server
    assert da.MACHINE_CLIENT_ID_ENV == server.MACHINE_CLIENT_ID_ENV
    assert da.MACHINE_CLIENT_ID_ENV == "MACHINE_CLIENT_ID"


# ── ⑤ 判定只有一处：AST 扫字面量 ──────────────────────────────────────

def _string_constants(path: Path) -> set:
    """源码里的字符串字面量（注释与 docstring 不算——解释门禁是允许的）。"""
    tree = ast.parse(path.read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docstrings}


def test_only_api_key_config_knows_the_section_name():
    """三个部署脚本都不得自己判"有没有 [ApiKey] 段"。

    各写一次 `cfg.has_section("ApiKey")` 就是三个判定点，漏改一处即部分部署。
    扫的是**段名字面量**而不是 `has_section` 调用：`cfg["ApiKey"]`、
    `cfg.has_option("ApiKey", …)` 都是同一类第二判定点。
    """
    checked = []
    for name, (path, _cwd) in sorted(DEPLOY_SCRIPTS.items()):
        if not path.exists():
            continue        # deploy_key_proxy.py 由 Task 8 创建，届时自动纳管
        checked.append(name)
        assert "ApiKey" not in _string_constants(path), (
            f"{name} 自己判 [ApiKey] 段——判定必须只在 "
            f"deployer/functions/api_key_config.py")
    assert {"deploy_pool.py", "deploy_agentcore.py"} <= set(checked), \
        f"该扫的脚本没扫到: {checked}"


def test_api_key_config_is_the_one_that_owns_the_section_name():
    """反向：真源里必须**有**这个字面量（否则上面那条会因"谁都没有"而假通过）。"""
    assert "ApiKey" in _string_constants(FUNCTIONS / "api_key_config.py")


def test_resource_server_is_created_only_when_component_is_enabled():
    """deploy_pool.main 只在 api_key_enabled 成立的分支里建 resource server。

    无条件建的话，"没配 [ApiKey]"仍会在 Cognito 里留下 resource server 与
    machine client——组件门禁的第一层（allowedClients）就形同虚设了。
    """
    sys.path.insert(0, str(SB_DIR / "scripts"))
    src = (SB_DIR / "scripts" / "deploy_pool.py").read_text()
    main = next(n for n in ast.walk(ast.parse(src))
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    gated, total = 0, 0
    for node in ast.walk(main):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == \
                "ensure_resource_server":
            total += 1
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        if not any(isinstance(t, ast.Call)
                   and getattr(t.func, "id", "") == "api_key_enabled"
                   for t in ast.walk(node.test)):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and getattr(inner.func, "id", "") \
                    == "ensure_resource_server":
                gated += 1
    assert total == 1, f"main 里 ensure_resource_server 的调用点有 {total} 处"
    assert gated == 1, "ensure_resource_server 不在 api_key_enabled 的分支里"


# ── ⑥ 按 DEPLOY.md 的真实 CLI 形态执行 ────────────────────────────────
# pytest 的 sys.path 与真实执行目录不同：`import api_key_config` 在 pytest 里
# 恒可用（conftest 把 deployer/functions 插进了 sys.path），而真机上脚本从
# site-builder/mcp/ 与 site-builder/key-proxy/ 执行，那两个目录看不到 scripts/。
# Codex P1-3 就是这样的缺陷——只在真实调用形态下暴露。

def _run_cli(script: Path, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, script.name, "--help"], cwd=cwd,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("name", sorted(DEPLOY_SCRIPTS))
def test_deploy_scripts_import_the_gate_from_their_real_working_directory(name):
    """从 DEPLOY.md 写的那个目录跑 `--help`：不得出现 ModuleNotFoundError。

    `deploy_pool.py` 的真实形态是 `cd site-builder && python3 scripts/…`，
    所以 cwd 与脚本目录**不同**——这正是 sys.path 相对路径写错时的暴露点。

    **按 DEPLOY_SCRIPTS 全量参数化**（Task 8 起三个脚本都在）：手写清单会漏掉
    新脚本，而漏掉的那个正好是没人验过 import 路径的那个（Task 7 报告 §4-E 的
    交接项）。文件缺失时**断言失败而不是 skip**——"文件不在"与"import 路径没问题"
    必须是两个可区分的结果。
    """
    path, cwd = DEPLOY_SCRIPTS[name]
    assert path.exists(), (
        f"{name} 不存在于 {path}——脚本被删/搬家了就必须同步 DEPLOY_SCRIPTS，"
        "否则本条守卫会静默变成空转")
    # 真实命令是 `python3 scripts/deploy_pool.py`：按 cwd 的相对路径调用
    rel = path.relative_to(cwd)
    proc = subprocess.run([sys.executable, str(rel), "--help"], cwd=cwd,
                          capture_output=True, text=True, timeout=120)
    assert "ModuleNotFoundError" not in proc.stderr, proc.stderr
    assert "api_key_config" not in proc.stderr, proc.stderr
    if (SB_DIR / "config.ini").exists():
        # deploy_agentcore 在模块级读 config.ini（既有行为），没有它时
        # 退出码本来就非 0——那与本条要查的 import 路径无关。
        assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
        assert "usage" in proc.stdout.lower()
    else:                                   # pragma: no cover - 本机有 config.ini
        pytest.skip("本机无 config.ini：只校验了 import 路径")
