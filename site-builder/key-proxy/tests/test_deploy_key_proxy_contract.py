"""deploy_key_proxy.py 的部署契约——不实际部署，断言它会构造出什么。

形态照 `panel/tests/test_deploy_panel_contract.py`（同一套判据在 M3 抓过真机
500：moto 不校验 IAM，权限漏项在单测这一侧完全看不出来）。三处刻意的加强：

  ① 哨兵行的幂等语义用 **moto 真表**验证，而不是只看 kwargs：本 Task 最容易
     写错的地方是"已存在时把它收敛成配置里的值"，那种实现在 kwargs 层面看着
     完全正常（也是一次 PutItem），只有拿一行**已经被开过**的哨兵行去跑才会
     暴露；
  ② `require_auth` 既断言 Python 侧是布尔，也**读回 DynamoDB 的原始类型**：
     `{"S": "false"}` 会让 Edge 落进"按需要登录处理"→ 302 到登录页，而
     Python 侧 `bool("false")` 那类写法在 `is False` 之外的断言里看不出来；
  ③ 环境变量清单与"代码实际读了哪些环境变量"做**双向**相等断言（不只查缺），
     多下发一项意味着某个模块已经不读它了，而那通常是接线漂移的第一个症状。
"""
import ast
import io
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import boto3
import pytest

import deploy_key_proxy as dkp
import api_key_config
import edge_caller
import keygen
import keystore

KP = Path(__file__).parents[1]                       # site-builder/key-proxy
SB = KP.parent                                       # site-builder
FUNCTIONS = SB / "deployer" / "functions"
AUTH = SB / "auth"
SCRIPT = KP / "deploy_key_proxy.py"

EDGE_ROLE = "arn:aws:iam::000000000000:role/site-edge-role"
ENDPOINT = ("https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/"
            "arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A000000000000%3A"
            "runtime%2Fsite_builder_deploy-abc/invocations?qualifier=DEFAULT")
MACHINE_ID = "machineclient1234567890"


def _cfg(with_api_key: bool = True, *, api_key_extra: str = "",
         machine_client_id: str = MACHINE_ID, endpoint: str = ENDPOINT,
         edge_role_arn: str = EDGE_ROLE):
    """一份与真实 config.ini 同形态的配置（示例值，无真实账号/域名）。

    **测试一律显式传 cfg，不用模块级 CFG**：那份读的是本机 config.ini，
    而本机现在**没有** `[ApiKey]` 段——依赖它会让"组件启用"的用例在别人的机器上
    行为不同，更糟的是让"门禁关闭"的用例在有 [ApiKey] 段的机器上**真的去调
    AWS**。
    """
    import configparser
    text = f"""
[Platform]
base_domain = example.com
account_id = 000000000000
region = us-east-1
routing_table = routing

[Cognito]
user_pool_id = us-east-1_example
domain = https://site-builder-auth.auth.us-east-1.amazoncognito.com
site_client_id = siteclient1234567890abc
mcp_client_id = mcpclient1234567890abcd
machine_client_id = {machine_client_id}

[Deployer]
edge_role_arn = {edge_role_arn}

[MCP]
endpoint_url = {endpoint}
"""
    if with_api_key:
        text += "\n[ApiKey]\nkeys_table = site-api-keys\n" + api_key_extra
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_string(text)
    return cfg


def _actions(stmt):
    a = stmt.get("Action", [])
    return a if isinstance(a, list) else [a]


def _resources(stmt):
    r = stmt.get("Resource", [])
    return r if isinstance(r, list) else [r]


def _string_constants(path: Path) -> set:
    """源码里的字符串字面量（docstring 不算——解释门禁是允许的）。"""
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


# ── ① 组件门禁：无 [ApiKey] 段 → 返回 0 且零 AWS 调用 ────────────────────

class _NoAws:
    """boto3 间谍：任何 client/resource 调用都当场炸。

    "什么都没发生"这种断言假通过时没有任何症状，所以另有一条正对照
    （test_the_boto3_spy_actually_intercepts）证明这个间谍装得上。
    """

    def __init__(self):
        self.calls = []

    def __call__(self, *a, **kw):
        self.calls.append((a, kw))
        raise AssertionError(f"门禁关闭时不该有任何 AWS 调用: {a} {kw}")


@pytest.fixture
def no_aws(monkeypatch):
    spy = _NoAws()
    monkeypatch.setattr(dkp.boto3, "client", spy)
    monkeypatch.setattr(dkp.boto3, "resource", spy)
    return spy


def test_the_boto3_spy_actually_intercepts(no_aws):
    """正对照：间谍确实拦得住（否则下面两条会静默变成空转）。"""
    with pytest.raises(AssertionError):
        dkp.boto3.client("iam")
    with pytest.raises(AssertionError):
        dkp.boto3.resource("dynamodb", region_name="us-east-1")


def test_no_api_key_section_returns_zero_without_touching_aws(monkeypatch,
                                                             no_aws, capsys):
    """"没配置"是合法默认状态（OAuth-only）：返回 0，不是报错、不是异常。

    部署全平台的脚本链不该因为"平台没启用 API Key"而中断（spec §5.1.1）。
    """
    monkeypatch.setattr(dkp, "CFG", _cfg(with_api_key=False))
    assert dkp.main([]) == 0
    assert no_aws.calls == [], f"门禁关闭却发了 AWS 调用: {no_aws.calls}"
    out = capsys.readouterr().out
    assert "[ApiKey]" in out and "OAuth" in out, out


def test_no_api_key_section_creates_no_route_and_no_switch_row(monkeypatch, aws):
    """行为层复核：跑完之后 routing 表没有 mcp 记录、凭证表没有哨兵行。

    与上一条互补——上一条查"没发调用"，这一条查"线上没变"。门禁被绕开时这条
    会以别的形态红（moto 里 get_role 找不到 Edge 角色），仍然红。
    """
    monkeypatch.setattr(dkp, "CFG", _cfg(with_api_key=False))
    assert dkp.main([]) == 0
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    assert "Item" not in ddb.get_item(TableName="routing",
                                      Key={"subdomain": {"S": "mcp"}})
    assert "Item" not in ddb.get_item(
        TableName="site-api-keys",
        Key={"key_hash": {"S": keygen.SWITCH_PK}}, ConsistentRead=True)


def test_gate_comes_from_the_shared_module_not_this_script():
    """判定必须来自 `deployer/functions/api_key_config.py`。

    三个部署脚本各写一次 `has_section("ApiKey")` 就是三个判定点，漏改一处得到
    的是**部分部署**（网关放行、容器拒绝，症状是 HTTP 200 + 业务错误文案）。
    扫**段名字面量**而不是 `has_section` 调用：`cfg["ApiKey"]` 是同一类第二判定点。
    """
    src = SCRIPT.read_text()
    assert "from api_key_config import" in src
    assert api_key_config.API_KEY_SECTION not in _string_constants(SCRIPT), (
        "deploy_key_proxy.py 自己写了段名字面量——判定必须只在 api_key_config")
    assert dkp.api_key_enabled is api_key_config.api_key_enabled


# ── ② Function URL：恰好两条语句、Principal 逐字符 ──────────────────────

def test_function_url_auth_type_is_iam():
    """AuthType=NONE + Principal:* 实测会被安全扫描自动处置（删光 policy）。"""
    assert dkp.FUNCTION_URL_AUTH_TYPE == "AWS_IAM"
    src = SCRIPT.read_text()
    assert 'AuthType="NONE"' not in src and "AuthType='NONE'" not in src


def test_resource_policy_is_exactly_two_statements_bound_to_edge_role():
    stmts = dkp.function_url_statements(EDGE_ROLE)
    assert len(stmts) == 2, "2025-10 起缺任一条即 403"
    by_action = {s["Action"]: s for s in stmts}
    assert set(by_action) == {"lambda:InvokeFunctionUrl",
                              "lambda:InvokeFunction"}
    for s in stmts:
        # 逐字符 exact，不做前缀匹配、不用账号根、绝不 *
        assert s["Principal"] == EDGE_ROLE, f"Principal 不是 exact edge role: {s}"
    assert by_action["lambda:InvokeFunctionUrl"]["FunctionUrlAuthType"] == "AWS_IAM"
    assert by_action["lambda:InvokeFunction"]["InvokedViaFunctionUrl"] is True
    assert len({s["StatementId"] for s in stmts}) == 2, "两条 StatementId 撞了"


@pytest.mark.parametrize("bad", ["", None, "   ", "*",
                                 "arn:aws:iam::000000000000:role/*"])
def test_missing_or_wildcard_edge_role_aborts_instead_of_widening(bad):
    """缺配置必须抛错——fallback 到 `Principal:*` 会让 Function URL 全网可调。

    对 key-proxy 而言绕过 Edge 不等于绕过认证（还得有一把有效 Key），但 Edge 是
    限流与可观测性的唯一位置：绕过它意味着 Key 暴力尝试不留任何可告警痕迹。
    """
    with pytest.raises((KeyError, ValueError)):
        dkp.function_url_statements(bad)


# ── ③ 执行角色：只够跑 lookup + touch_last_used ─────────────────────────

def _api_keys_statements():
    return [s for s in dkp.role_statements(_cfg())
            if any(dkp.API_KEYS_TABLE in r for r in _resources(s))]


def test_api_keys_role_is_getitem_and_updateitem_only():
    """凭证表**只有** GetItem + UpdateItem。

      · 无 `BatchGetItem`——开关与 Key 是两次独立 GetItem（合并会让"关闸期间零
        Key 查询"这条短路不成立，Codex P2-6）；
      · 无 `PutItem`——发 Key 在 panel。包里带着 `keystore.create` 是有意接受的
        纵深（代码在但权限不在）；
      · 无 `DeleteItem`——吊销是置 `revoked`，删行就没有审计痕迹；
      · 无 `Scan`——等于能读全表凭证行。
    """
    stmts = _api_keys_statements()
    assert stmts, f"role 里找不到 {dkp.API_KEYS_TABLE} 的任何授权"
    granted = set()
    for s in stmts:
        granted |= set(_actions(s))
    assert granted == {"dynamodb:GetItem", "dynamodb:UpdateItem"}, (
        f"key-proxy 对凭证表的权限不是"
        f"「只有 GetItem + UpdateItem」: {sorted(granted)}")


def test_api_keys_role_has_no_index_resource():
    """**不给 `index/*`**：本组件两条路径都按主键走，GSI 查询是 panel 的事。

    单独一条是因为上面那条按 action 判，给了 `index/*` 但 action 不变时它不会红
    （而 GSI 上的 Query 恰好是 panel 侧最容易漏权限的那个，反过来这里就是最容易
    多给的那个）。
    """
    for s in _api_keys_statements():
        for res in _resources(s):
            assert "/index/" not in res, f"给了索引资源: {res}"


def _keystore_ops_of(functions: set) -> set:
    """从 keystore.py 的 AST 取出指定函数里对 `_table()` 做的 DynamoDB 操作。

    两种形态都要认：`_table().get_item(...)` 是直接调用，而
    `common._paginate(_table().query, IndexName=…)` 把方法本身当参数传出去
    （节点是 Attribute 而不是 Call）——按"属性挂在 `_table()` 调用上"判就能一条
    规则覆盖两种。
    """
    method_to_action = {
        "get_item": "dynamodb:GetItem", "put_item": "dynamodb:PutItem",
        "update_item": "dynamodb:UpdateItem",
        "delete_item": "dynamodb:DeleteItem", "query": "dynamodb:Query",
        "scan": "dynamodb:Scan", "batch_get_item": "dynamodb:BatchGetItem"}
    tree = ast.parse((FUNCTIONS / "keystore.py").read_text())
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            acts = set()
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Attribute)
                        and inner.attr in method_to_action
                        and isinstance(inner.value, ast.Call)
                        and isinstance(inner.value.func, ast.Name)
                        and inner.value.func.id == "_table"):
                    acts.add(method_to_action[inner.attr])
            found[node.name] = acts
    missing = functions - set(found)
    assert not missing, (f"keystore.py 里找不到 {sorted(missing)}"
                         "——函数改名后本推导会静默变空，请同步本用例")
    out = set()
    for name in functions:
        out |= found[name]
    return out


def test_role_grants_exactly_what_the_key_proxy_paths_need():
    """从 keystore 的**代码**推导 key-proxy 走的两条路径需要什么，再交叉核对。

    手抄一份"需要哪些 action"的清单本身就是下一个漂移源（M3-FINDINGS §2.18：
    panel 曾漏 `ConditionCheckItem`，144 个单测全绿而真机所有写操作 500）。
    **相等断言而不是包含**：少给 → 真机 AccessDenied（moto 不校验 IAM，这一侧
    看不出来）；多给 → 把 panel 的创建/吊销能力白送给一个公网组件。

    key-proxy 只调 `keystore.lookup`（→ `_get_switch_row` / `_get_key_row`）与
    `keystore.touch_last_used`（→ `_update_last_used`），见 handler 的 ③ 与 ⑤ 步。
    """
    needed = _keystore_ops_of({"_get_switch_row", "_get_key_row",
                               "_update_last_used"})
    assert needed == {"dynamodb:GetItem", "dynamodb:UpdateItem"}, (
        f"推导口径坏了（或 keystore 的读写路径变了）: {sorted(needed)}")
    granted = set()
    for s in _api_keys_statements():
        granted |= set(_actions(s))
    assert granted == needed, (
        f"role 授权 {sorted(granted)} 与代码实际需要 {sorted(needed)} 不一致")


def test_key_proxy_never_calls_the_management_side_of_keystore():
    """反向：handler 不得调 keystore 的管理端（那些操作角色故意没有权限）。

    只查 role 的话，将来 handler 里冒出一个 `keystore.create` 会以真机
    AccessDenied → 500 的形态出现（而单测有 moto 兜着，全绿）。
    """
    tree = ast.parse((KP / "handler.py").read_text())
    used = {node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "keystore"}
    assert used == {"lookup", "touch_last_used"}, (
        f"handler 用了 keystore 的 {sorted(used)}——管理端（create/revoke/"
        "set_switch）在 key-proxy 的角色里没有权限")


def test_ssm_resource_is_the_exact_machine_secret_param():
    """**精确参数 ARN，不用 `parameter/site-builder/*` 前缀。**

    拿前缀等于被攻破时顺带交出 `jwt-secret`（能伪造任意用户会话）与 site client
    secret。auth 用前缀是它自己要读多个参数的业务需要，不是可以照抄的形态。
    """
    ssm = [s for s in dkp.role_statements(_cfg())
           if any(a.startswith("ssm:") for a in _actions(s))]
    assert ssm, "缺 SSM 读取权限——machine client secret 读不出来"
    for s in ssm:
        assert set(_actions(s)) == {"ssm:GetParameter"}, sorted(_actions(s))
        for res in _resources(s):
            assert res.endswith(dkp.MACHINE_SECRET_PARAM), (
                f"SSM 资源不是精确的 machine-client-secret ARN: {res}")
            assert "*" not in res, f"出现通配前缀: {res}"


def test_kms_decrypt_is_scoped_via_ssm():
    kms = [s for s in dkp.role_statements(_cfg())
           if "kms:Decrypt" in _actions(s)]
    assert kms, "缺 kms:Decrypt——SecureString 读不出来"
    for s in kms:
        cond = s.get("Condition", {}).get("StringEquals", {})
        assert "kms:ViaService" in cond, f"kms:Decrypt 没有 ViaService 限定: {s}"


def test_role_has_no_wildcards_and_no_iam_lambda_or_bedrock():
    """这个函数不建资源、不调别的函数，也**不需要任何 bedrock 权限**。

    AgentCore 的 invocations 端点只认 Bearer JWT，不走 SigV4
    （`handler._endpoint` 的 docstring）——给了 bedrock 权限说明有人在用错的
    机制转发。
    """
    for s in dkp.role_statements(_cfg()):
        acts = _actions(s)
        assert "*" not in acts, f"出现 Action:* : {s}"
        for a in acts:
            assert not a.startswith(("iam:", "lambda:", "bedrock:",
                                     "bedrock-agentcore:")), f"{a} 不该有: {s}"
            assert a != "dynamodb:*" and a != "ssm:*", f"过宽: {a}"


def test_machine_secret_param_agrees_with_deploy_pool():
    """secret 的**写入者**是 `scripts/deploy_pool.py`，这里只是读取方。

    两处必须同名。从 deploy_pool 的源码推导（参数前缀的默认值 + 名字字面量）
    而不是手抄——手抄的第二份真源会漂移，症状是 `TokenUnavailable: 无法读取
    machine client secret`，而排查方向会指向 Cognito 配置。
    """
    tree = ast.parse((SB / "scripts" / "deploy_pool.py").read_text())
    prefixes = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        names = [a.arg for a in args.posonlyargs + args.args]
        for name, default in zip(names[len(names) - len(args.defaults):],
                                 args.defaults):
            if name == "param_prefix" and isinstance(default, ast.Constant):
                prefixes.add(default.value)
    assert len(prefixes) == 1, (
        f"在 deploy_pool 里找到 {prefixes} 个 param_prefix 默认值——"
        "推导口径坏了，本用例什么都没断言")
    prefix = prefixes.pop()
    assert "machine-client-secret" in _string_constants(
        SB / "scripts" / "deploy_pool.py"), "deploy_pool 不再写这个参数名了？"
    assert dkp.MACHINE_SECRET_PARAM == f"{prefix}/machine-client-secret", (
        f"读取方用 {dkp.MACHINE_SECRET_PARAM}，而 deploy_pool 写的是 "
        f"{prefix}/machine-client-secret")


def test_api_keys_table_name_matches_the_cdk_table():
    """表名与**唯一创建者**（`deployer/infra/app.py` 的 CDK 定义）同名。

    漂移的症状不是报错而是"读一张空表"：所有 Key 都 `unknown-key` → 401，
    而控制台（写的是另一张表）看起来一切正常。
    """
    src = (SB / "deployer" / "infra" / "app.py").read_text()
    assert f'table_name="{dkp.API_KEYS_TABLE}"' in src, (
        f"CDK 里找不到 table_name=\"{dkp.API_KEYS_TABLE}\"")


# ── ④ 环境变量：无明文密钥、MACHINE_SCOPE 从 config 派生 ────────────────

def test_environment_has_no_plaintext_secret():
    """环境变量只下发**参数名**。

    `lambda:GetFunctionConfiguration` 会原样回显环境变量，而那是个常见的只读
    权限（44aef8d 之前的 auth 就踩过明文密钥进环境变量）。
    """
    env = dkp.lambda_environment("AROAEXAMPLE", _cfg())
    for k, v in env.items():
        assert "SECRET" not in k or k.endswith("_PARAM"), (
            f"环境变量 {k} 看起来在下发明文密钥")
    assert env["MACHINE_SECRET_PARAM"].startswith("/"), "应是 SSM 参数名"
    src = SCRIPT.read_text()
    assert "get_parameter" not in src or "WithDecryption" not in src, (
        "部署脚本不该读出明文密钥再塞进环境变量")


def test_environment_carries_edge_role_id_under_the_shared_env_name():
    """名字取自 `edge_caller.EDGE_ROLE_ID_ENV`（读取侧的真源），不写字面量。

    下发了 A、代码读 B 时两侧单测都绿而线上**拒绝所有请求**
    （`caller_is_edge` 缺配置即全拒，刻意 fail-closed）。
    """
    env = dkp.lambda_environment("AROAEXAMPLE", _cfg())
    assert env[edge_caller.EDGE_ROLE_ID_ENV] == "AROAEXAMPLE"
    assert dkp.EDGE_ROLE_ID_ENV is edge_caller.EDGE_ROLE_ID_ENV


@pytest.mark.parametrize("extra,expected", [
    ("", "site-builder-mcp/invoke"),
    ("resource_server_id = my-mcp\n", "my-mcp/invoke"),
    ("scope = call\n", "site-builder-mcp/call"),
    ("resource_server_id = my-mcp\nscope = call\n", "my-mcp/call"),
    ("resource_server_id = my-mcp  # 改过\nscope = call ; 也改过\n",
     "my-mcp/call"),
])
def test_machine_scope_is_derived_from_config_not_hardcoded(extra, expected):
    """`MACHINE_SCOPE` 必须跟着 config 走（Codex 审查 2026-08-11 P1-2a）。

    硬编码 `site-builder-mcp/invoke` 会绕开"config.ini 是唯一取值来源"；
    而拼接只在 `api_key_config.machine_scope` 发生一次，运行时只读不拼——
    两处各拼一次会出现"建的 scope 与换 token 用的 scope 不是同一个"，
    Cognito 报 `invalid_scope` 而文案指向 client 配置。
    """
    cfg = _cfg(api_key_extra=extra)
    env = dkp.lambda_environment("AROAEXAMPLE", cfg)
    assert env["MACHINE_SCOPE"] == expected
    # 与真源逐字符相同（不是"看起来像"）
    assert env["MACHINE_SCOPE"] == api_key_config.machine_scope(cfg)
    assert "/" in env["MACHINE_SCOPE"], "scope 必须是 {resource_server}/{scope}"


def test_machine_scope_default_literal_is_not_in_the_deploy_script():
    """反向：拼好的默认串不得作为字面量出现在本脚本里。

    上一条用自定义值证明"跟着 config 走"，这一条挡住"既读 config 又留一份
    硬编码兜底"——那种写法在默认配置下永远绿。
    """
    assert "site-builder-mcp/invoke" not in _string_constants(SCRIPT)


def _env_vars_read(path: Path) -> set:
    """某个模块**实际读了哪些环境变量**（AST，不是正则）。

    必须认三种形态：`os.environ["X"]`、`os.environ.get("X")`、
    `machine_token._env("X")`；而且键**可以是模块级常量**
    （`os.environ.get(AGENTCORE_ENDPOINT_ENV)` 就是——正则那一套会整条漏掉它，
    于是"漏下发 AGENTCORE_ENDPOINT"这个缺陷会在守卫全绿的情况下上线）。
    """
    tree = ast.parse(path.read_text())
    consts = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    consts[t.id] = node.value.value

    def resolve(arg):
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        if isinstance(arg, ast.Name):
            return consts.get(arg.id)
        return None

    def is_environ(node):
        return isinstance(node, ast.Attribute) and node.attr == "environ"

    out = set()
    for node in ast.walk(tree):
        value = None
        if isinstance(node, ast.Subscript) and is_environ(node.value):
            value = resolve(node.slice)
        elif isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Attribute) and f.attr == "get"
                    and is_environ(f.value) and node.args):
                value = resolve(node.args[0])
            elif isinstance(f, ast.Name) and f.id == "_env" and node.args:
                value = resolve(node.args[0])
        if value:
            out.add(value)
    return out


def test_environment_is_exactly_what_the_runtime_reads():
    """下发的环境变量与运行时读的**双向**相等。

    · 少一项 → 运行时 `KeyError` / `TokenUnavailable`，而单测有 conftest 的 ENV
      兜着完全看不出来；
    · 多一项 → 说明某个模块已经不读它了（接线漂移的第一个症状），或者有人往
      环境里塞了不该在那儿的东西。

    扫的范围：key-proxy 自己的模块（handler / machine_token）+ **它真正会调的**
    两个共享模块（keystore、edge_caller）。**不扫整条复制闭包**：permissions.py
    与 common.py 会读 `SITES_TABLE` / `ACCOUNT_ID` 等，那些是 panel 与建站路径的
    表，key-proxy 永不调用——要求下发它们等于把无关配置塞进本函数
    （panel 的同名用例出于同样理由只扩展到 keystore）。
    """
    read = set()
    for py in sorted(KP.glob("*.py")):
        if py.name == SCRIPT.name:
            continue
        read |= _env_vars_read(py)
    for name in ("keystore.py", "edge_caller.py"):
        read |= _env_vars_read(FUNCTIONS / name)
    # AWS 运行时自带的
    read -= {"AWS_DEFAULT_REGION", "AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME"}

    # 守卫的守卫：这两个键只有"能解析模块级常量"的实现才找得到
    assert {"AGENTCORE_ENDPOINT", "EDGE_ROLE_ID"} <= read, (
        f"解析口径坏了（常量形态的键没解析出来）: {sorted(read)}")
    assert "MACHINE_SCOPE" in read and "API_KEYS_TABLE" in read, sorted(read)

    env = set(dkp.lambda_environment("AROAEXAMPLE", _cfg()))
    assert read - env == set(), f"代码会读但没下发: {sorted(read - env)}"
    assert env - read == set(), (
        f"下发了但没人读: {sorted(env - read)}——删掉它，"
        "或者把读它的模块加进本用例的扫描范围")


@pytest.mark.parametrize("endpoint", ["", "   ", "http://insecure.example.com",
                                      "wss://x.example.com"])
def test_endpoint_must_be_present_and_https(endpoint):
    """空端点 = 每次转发都 502（"部署成功"而组件全挂）；http = 机器 token 明文上路。"""
    with pytest.raises(SystemExit):
        dkp.lambda_environment("AROAEXAMPLE", _cfg(endpoint=endpoint))


@pytest.mark.parametrize("mid", ["", "   "])
def test_empty_machine_client_id_aborts_instead_of_deploying_blank(mid):
    """段存在但 client id 为空必须中止。

    静默下发空值会得到"以为部署了 API Key，其实换不到 token"的状态，而
    machine_token 报的是 `invalid_client`——排查方向会指向 Cognito 配置。
    """
    with pytest.raises(SystemExit):
        dkp.lambda_environment("AROAEXAMPLE", _cfg(machine_client_id=mid))


# ── ⑤ mcp route ────────────────────────────────────────────────────────

def test_mcp_route_is_api_only_public_platform_record():
    route = dkp.mcp_route_item("https://abc.lambda-url.us-east-1.on.aws/",
                               _cfg())
    assert route["route_mode"] == "api-only"
    assert route["static_prefix"] == ""
    assert route["owner"] == "platform"
    assert route["subdomain"] == api_key_config.mcp_subdomain(_cfg()) == "mcp"


def test_route_require_auth_is_boolean_false_not_a_string():
    """Edge 的判定是 `require_auth is False`。

    字符串 `"false"` 会落进"按需要登录处理"→ 302 到登录页，而 key-proxy 的调用方
    是只能配静态 Header 的 MCP 客户端（没有平台会话）——客户端拿到的是一坨 HTML。
    """
    route = dkp.mcp_route_item("https://x.lambda-url.us-east-1.on.aws/", _cfg())
    assert route["require_auth"] is False
    assert isinstance(route["require_auth"], bool)


@pytest.mark.parametrize("url", [
    "https://abc.lambda-url.us-east-1.on.aws/",
    "https://abc.lambda-url.us-east-1.on.aws",
    "https://abc.lambda-url.us-east-1.on.aws///",
])
def test_api_target_has_no_trailing_slash(url):
    """尾斜杠会让 Edge 拼出双斜杠（M3-FINDINGS §2.15 的整站 403 成因）。"""
    target = dkp.mcp_route_item(url, _cfg())["api_target"]
    assert not target.endswith("/"), target
    assert "//" not in target[len("https://"):], target


def test_route_written_to_dynamo_keeps_require_auth_as_a_bool_attribute(aws):
    """读回 **DynamoDB 的原始类型**：必须是 `{"BOOL": false}`。

    Python 侧断言看不出"写进去变成了字符串"这一类问题（`json.dumps` / 序列化层
    都可能改类型），而 Edge 读到 `{"S": "false"}` 时按"需要登录"处理。
    """
    cfg = _cfg()
    dkp.register_route("https://abc.lambda-url.us-east-1.on.aws/", cfg)
    raw = boto3.client("dynamodb", region_name="us-east-1").get_item(
        TableName="routing", Key={"subdomain": {"S": "mcp"}},
        ConsistentRead=True)["Item"]
    assert raw["require_auth"] == {"BOOL": False}, raw["require_auth"]
    assert raw["route_mode"] == {"S": "api-only"}
    assert raw["static_prefix"] == {"S": ""}
    assert not raw["api_target"]["S"].endswith("/")


def test_mcp_subdomain_is_deliberately_not_a_platform_subdomain():
    """决定 9：`mcp` **不进** Edge 的 `PLATFORM_SUBDOMAINS`。

    key-proxy 只认 `X-API-Key`，不需要平台 cookie；进白名单只会让一个公网组件
    白拿一个顶域会话 JWT。这里按**真实 Edge 源码**断言，不看注释。
    """
    edge = (SB.parent / "router" / "infrastructure" / "lambda"
            / "origin_request.py")
    assert edge.exists(), f"找不到 Edge 源码: {edge}"
    tree = ast.parse(edge.read_text())
    platform = None
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", "") == "PLATFORM_SUBDOMAINS"
                        for t in node.targets)):
            platform = {e.value for e in node.value.elts}
    assert platform, "Edge 里找不到 PLATFORM_SUBDOMAINS——本用例已失效"
    assert api_key_config.mcp_subdomain(_cfg()) not in platform, (
        f"mcp 子域进了平台白名单: {sorted(platform)}")


# ── ⑥ 哨兵行：不存在才建（关），已存在一字不改 ─────────────────────────

def _raw_switch_row():
    return boto3.client("dynamodb", region_name="us-east-1").get_item(
        TableName="site-api-keys", Key={"key_hash": {"S": keygen.SWITCH_PK}},
        ConsistentRead=True).get("Item")


def test_switch_row_is_created_disabled_the_first_time(aws):
    """首次部署建成**关**（fail-closed），且 `enabled` 是 DynamoDB BOOL。

    建成开的话，部署脚本自己就把通道打开了——发 Key 之前先有一个谁都不知道
    已经开着的入口。而字符串 `"false"` 会被 `keystore.lookup` 拒
    （`enabled is not True`），症状是"控制台显示开着但全部 401"。
    """
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_CREATED_DISABLED
    raw = _raw_switch_row()
    assert raw is not None, "哨兵行没建出来"
    assert raw["enabled"] == {"BOOL": False}, raw["enabled"]


def test_created_switch_row_has_no_email_or_key_id(aws):
    """行里只有固定四个字段：带上 `email` / `key_id` 就会冒进两个 GSI。

    那两个字段是 `email-index` / `keyid-index` 的分区键——平台开关行一旦进了
    `email-index`，就会出现在某个人的 Key 列表里。
    """
    dkp.ensure_switch_row(_cfg())
    assert set(_raw_switch_row()) == {"key_hash", "enabled", "updated_at",
                                     "updated_by"}


def test_rerun_leaves_an_enabled_switch_row_untouched(aws):
    """**本 Task 最容易写错的地方**：已存在时一个字都不改。

    绝不"收敛成配置里的值"——关闸开关故意不在 config.ini 里（决定 6），带上收敛
    语义的话下一次重跑部署会把管理员的关闸**静默覆盖成开**（或反过来把开着的
    打回关）。按**整行**断言而不是逐字段：逐字段会漏掉"顺手多写了个字段"。
    """
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    before = {"key_hash": {"S": keygen.SWITCH_PK}, "enabled": {"BOOL": True},
              "updated_at": {"S": "2026-08-11T00:00:00+00:00"},
              "updated_by": {"S": "admin@example.com"}}
    ddb.put_item(TableName="site-api-keys", Item=before)
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_EXISTING_ENABLED
    assert _raw_switch_row() == before, "重跑部署改了哨兵行"


def test_rerun_leaves_a_disabled_switch_row_untouched(aws):
    """已存在且是关的：同样一个字都不改（连 `updated_at` 都不许刷新）。

    刷新 `updated_at` 会把审计线索改成"最后一次改动是这次部署"，而真正关闸的
    那个人与时间就查不出来了。
    """
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    before = {"key_hash": {"S": keygen.SWITCH_PK}, "enabled": {"BOOL": False},
              "updated_at": {"S": "2026-08-11T00:00:00+00:00"},
              "updated_by": {"S": "admin@example.com"}}
    ddb.put_item(TableName="site-api-keys", Item=before)
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_EXISTING_DISABLED
    assert _raw_switch_row() == before, "重跑部署改了哨兵行"


def test_ensure_switch_row_is_idempotent_across_repeated_runs(aws):
    """连跑三次：第一次建，后两次都报"已存在且是关的"，行内容不变。"""
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_CREATED_DISABLED
    after_create = _raw_switch_row()
    for _ in range(2):
        assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_EXISTING_DISABLED
    assert _raw_switch_row() == after_create


def test_switch_row_put_is_a_conditional_write(monkeypatch):
    """条件写 `attribute_not_exists(key_hash)`——并发部署不会互相覆盖。

    行为层（上面三条）已经能抓住"无条件覆盖"，这一条按**真实 kwargs** 钉住条件
    本身：将来若有人改成"先 GetItem 看看再 Put"，行为用例在串行的测试里仍然全绿，
    而并发下两个部署会都看到"没有"、都 Put。
    """
    seen = []

    class _Recorder:
        def put_item(self, **kw):
            seen.append(kw)
            return {}

        def get_item(self, **kw):      # pragma: no cover - 条件写成功时走不到
            raise AssertionError("首次创建成功时不该再去读")

    monkeypatch.setattr(dkp, "_api_keys_table", lambda cfg=None: _Recorder())
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_CREATED_DISABLED
    assert len(seen) == 1, seen
    assert seen[0]["ConditionExpression"] == "attribute_not_exists(key_hash)"
    assert seen[0]["Item"]["enabled"] is False
    assert seen[0]["Item"]["key_hash"] == keygen.SWITCH_PK


def test_switch_pk_is_imported_from_keygen_not_retyped():
    """哨兵行主键只有一个定义（`keygen.SWITCH_PK`，keystore 再导出）。

    再写一份字符串字面量就是第二份真源：改了一处的症状是"部署脚本建的行"与
    "keystore 读的行"不是同一行 → 永远 `switch-row-missing` → 全部 401。
    """
    assert dkp.SWITCH_PK is keygen.SWITCH_PK is keystore.SWITCH_PK
    assert keygen.SWITCH_PK not in _string_constants(SCRIPT)


def test_switch_row_read_back_uses_a_strongly_consistent_read(monkeypatch):
    """已存在时读回的那一次必须强一致——要打印给运维看的结论不能是旧值。"""
    seen = []

    class _Recorder:
        def put_item(self, **kw):
            raise _conditional_failure()

        def get_item(self, **kw):
            seen.append(kw)
            return {"Item": {"key_hash": keygen.SWITCH_PK, "enabled": True}}

    monkeypatch.setattr(dkp, "_api_keys_table", lambda cfg=None: _Recorder())
    assert dkp.ensure_switch_row(_cfg()) == dkp.SWITCH_EXISTING_ENABLED
    assert seen and seen[0]["ConsistentRead"] is True, seen


def _conditional_failure():
    import botocore.exceptions
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException",
                   "Message": "the conditional request failed"}}, "PutItem")


def test_switch_row_propagates_unexpected_write_failures(monkeypatch):
    """只有"条件未通过"才继续读回；别的失败必须冒出去。

    把所有异常都当成"已存在"会让一次 AccessDenied / 限流被报成"哨兵行已存在且
    是关的"——部署脚本打印一切正常，而线上根本没有那一行（`switch-row-missing`
    → 全部 401，且没人知道为什么）。
    """
    class _Boom:
        def put_item(self, **kw):
            raise RuntimeError("AccessDeniedException")

        def get_item(self, **kw):      # pragma: no cover
            raise AssertionError("不该在写失败后去读")

    monkeypatch.setattr(dkp, "_api_keys_table", lambda cfg=None: _Boom())
    with pytest.raises(RuntimeError):
        dkp.ensure_switch_row(_cfg())


# ── ⑦ main 的顺序与"开关是关的"提示 ────────────────────────────────────

@pytest.fixture
def stub_deploy(monkeypatch):
    """把所有碰 AWS 的步骤换成记录器，只保留 main 的编排与打印。"""
    calls = []
    monkeypatch.setattr(dkp, "CFG", _cfg())
    monkeypatch.setattr(dkp, "edge_role_id",
                        lambda arn: calls.append("edge_role_id") or "AROAEXAMPLE")
    monkeypatch.setattr(dkp, "ensure_role",
                        lambda cfg=None: calls.append("ensure_role")
                        or "arn:aws:iam::000000000000:role/site-key-proxy-role")
    monkeypatch.setattr(dkp, "_build_zip", lambda: b"zip")
    monkeypatch.setattr(dkp, "ensure_function",
                        lambda *a, **k: calls.append("ensure_function")
                        or "https://abc.lambda-url.us-east-1.on.aws/")
    monkeypatch.setattr(dkp, "register_route",
                        lambda *a, **k: calls.append("register_route"))
    return calls


def test_main_creates_the_switch_row_before_registering_the_route(monkeypatch,
                                                                  stub_deploy):
    """顺序：哨兵行在 route 之前。

    反过来的话有一个时间窗口：子域已经指向 Lambda 而哨兵行还不存在。此时
    `keystore.lookup` 返回 `switch-row-missing`（fail-closed，仍然 401），
    所以这不是安全缺陷——但它是**可避免的**不一致状态，而"部署到一半"的状态
    最难排查。
    """
    monkeypatch.setattr(dkp, "ensure_switch_row",
                        lambda cfg=None: stub_deploy.append("switch")
                        or dkp.SWITCH_CREATED_DISABLED)
    assert dkp.main([]) == 0
    assert stub_deploy.index("switch") < stub_deploy.index("register_route"), \
        stub_deploy


@pytest.mark.parametrize("state,loud", [
    (dkp.SWITCH_CREATED_DISABLED, True),
    (dkp.SWITCH_EXISTING_DISABLED, True),
    (dkp.SWITCH_EXISTING_ENABLED, False),
])
def test_main_reports_the_current_switch_state(monkeypatch, stub_deploy, capsys,
                                               state, loud):
    """部署完必须把开关状态说全。

    "组件已部署"≠"通道已打开"：哨兵行是关的时候任何 Key 直连都 401，现场若不
    知道这一点会以为部署失败，然后开始查 Function URL / route / 网关——那条路
    每一步都是对的。
    """
    monkeypatch.setattr(dkp, "ensure_switch_row", lambda cfg=None: state)
    assert dkp.main([]) == 0
    out = capsys.readouterr().out
    assert state in out, out
    if loud:
        assert "关" in out and "401" in out and "控制台" in out, out
        assert "不会" in out, "没说明本脚本不会替人打开开关"
    else:
        assert "401" not in out, out


def test_main_does_not_flip_the_switch_itself():
    """本脚本里不得出现"打开开关"的写路径（AST，不是字符串匹配——注释里解释
    `keystore.set_switch` 为什么归 panel 是允许的）。

    `set_switch` 是控制台（panel）的入口，那条路有审计（ops_log）与 admin 判定；
    部署脚本调它等于绕开两者，而且会把重跑变成"静默开闸"。
    """
    tree = ast.parse(SCRIPT.read_text())
    called = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "set_switch" not in called, "部署脚本不该调 keystore.set_switch"
    seen_enabled = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "enabled":
                seen_enabled += 1
                assert isinstance(v, ast.Constant) and v.value is False, (
                    f"第 {node.lineno} 行往 enabled 写了 {ast.dump(v)}——"
                    "哨兵行只能由部署脚本建成关")
    assert seen_enabled == 1, (
        f"源码里对 enabled 的字面赋值有 {seen_enabled} 处（预期 1，"
        "即 ensure_switch_row 的创建）——本用例的定位口径可能坏了")


# ── ⑧ 复制清单：传递闭包 ───────────────────────────────────────────────

def test_copy_files_contains_the_four_modules_the_runtime_cannot_start_without():
    """恒定集合的快照：漏任一个都是"单测全绿、部署后 ImportError"。

    与隔壁那条闭包断言互补——闭包只查"被 import 的都在清单里"，多出一个不存在
    的文件名它不会红（那会在真机部署时 `sys.exit`）。
    """
    assert {"edge_caller.py", "keystore.py", "keygen.py",
            "api_key_config.py"} <= set(dkp.COPY_FILES)


def test_every_copied_module_actually_exists_on_disk():
    """查找顺序与 `_build_zip` 一致（`deployer/functions` → `auth`）。"""
    for name in dkp.COPY_FILES:
        assert (FUNCTIONS / name).exists() or (AUTH / name).exists(), (
            f"复制清单里的 {name} 在 {FUNCTIONS} 与 {AUTH} 都找不到——"
            "部署时 _build_zip 会 sys.exit")


def test_copy_files_covers_every_local_module_the_package_imports():
    """按传递闭包核对复制清单，而不是靠记性。

    只改代码不改清单时，单测全绿而部署产物缺文件——这在 MCP 的 Dockerfile 与
    panel 的清单上都真实发生过。搜索目录与 panel 的同名断言一致
    （`deployer/functions` → `auth`），所以两个组件的"部署产物里有什么"由同一
    套判据回答。

    `keystore.py` 会把 `permissions.py` / `common.py` / `ops_log.py` 一起牵进来
    ——那是**对的**：它借 `permissions.EMAIL_RE` 判邮箱形态（不再写第二条正则），
    而 permissions 又用 common 与 ops_log。
    """
    external = {"os", "json", "re", "time", "logging", "boto3", "botocore",
                "urllib", "datetime", "hmac", "hashlib", "base64", "secrets",
                "string", "configparser", "argparse", "sys", "shutil",
                "subprocess", "zipfile", "io", "pathlib", "typing",
                "collections", "functools", "itertools"}

    def local_imports(path):
        names = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 \
                    and node.module:
                names.add(node.module.split(".")[0])
        return names

    own = {p.stem for p in KP.glob("*.py")}
    needed, queue, seen = set(), [p for p in KP.glob("*.py")
                                 if p.name != SCRIPT.name], set()
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for name in local_imports(cur):
            if name in external or name in own:
                continue
            for d in (FUNCTIONS, AUTH):
                cand = d / f"{name}.py"
                if cand.exists():
                    needed.add(f"{name}.py")
                    queue.append(cand)
                    break

    assert {"keystore.py", "edge_caller.py", "permissions.py"} <= needed, (
        f"传递闭包解析坏了：{sorted(needed)}")
    missing = needed - set(dkp.COPY_FILES)
    assert not missing, f"这些模块被 import 但不在复制清单: {sorted(missing)}"


def test_build_zip_contains_the_handler_every_copy_and_not_the_deploy_script():
    """真的打一次包：产物里有 handler + machine_token + 全部复制模块。

    形态断言（清单对不对）与产物断言（打进去了没有）是两件事：`_build_zip` 里
    一个 `continue` 写错就能让某个文件不进 zip，而清单那几条仍然全绿。
    部署脚本本身**不能**进包（它 import 了 argparse/configparser 之外还读
    config.ini，进包只会让运行时多一份不该在那儿的配置读取代码）。
    """
    
    names = set(zipfile.ZipFile(io.BytesIO(dkp._build_zip())).namelist())
    assert {"handler.py", "machine_token.py"} <= names
    assert set(dkp.COPY_FILES) <= names, sorted(set(dkp.COPY_FILES) - names)
    assert SCRIPT.name not in names
    # 复制来的文件必须清理干净（残留会被下次 zip 再打一遍，也会污染 git 状态）
    for name in dkp.COPY_FILES:
        assert not (KP / name).exists(), f"{name} 残留在 {KP}"


def test_build_zip_modules_are_byte_identical_to_their_sources():
    """产物里的共享模块与源文件**逐字节**相同（不是"名字对上就行"）。"""
    
    z = zipfile.ZipFile(io.BytesIO(dkp._build_zip()))
    for name in dkp.COPY_FILES:
        src = FUNCTIONS / name
        if not src.exists():
            src = AUTH / name
        assert z.read(name) == src.read_bytes(), f"{name} 与源文件不一致"


# ── ⑨ 按 DEPLOY.md 的真实 CLI 形态执行 ─────────────────────────────────

def test_help_runs_from_the_real_working_directory():
    """`cd site-builder/key-proxy && python3 deploy_key_proxy.py --help`。

    pytest 的 `sys.path` 与真实执行目录不同（conftest 把 `deployer/functions`
    插进去了），所以"import 路径写错"这类缺陷只在真实调用形态下暴露——
    Codex P1-3 就是这样的：`import deploy_pool` 在 pytest 里恒可用，而真机上
    key-proxy 目录看不到 `scripts/`，脚本会在任何 AWS 调用**之前**崩。
    """
    proc = subprocess.run([sys.executable, SCRIPT.name, "--help"], cwd=KP,
                          capture_output=True, text=True, timeout=120)
    assert "ModuleNotFoundError" not in proc.stderr, proc.stderr
    assert "api_key_config" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert "usage" in proc.stdout.lower(), proc.stdout


def test_no_real_account_values_in_the_script():
    """跟踪文件里不许出现真实账号 / 域名（仓库红线）。"""
    src = SCRIPT.read_text()
    for m in re.finditer(r"\b\d{12}\b", src):
        assert m.group(0) == "000000000000", f"疑似真实账号 ID: {m.group(0)}"
