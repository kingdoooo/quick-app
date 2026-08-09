"""deploy_panel.py 的部署契约——不实际部署，断言它会构造出什么。"""
import ast
import json
import re
from pathlib import Path

import pytest

import deploy_panel as dp

PANEL = Path(__file__).parents[1]
EDGE_ROLE = "arn:aws:iam::000000000000:role/site-edge-role"


def _actions(stmt):
    a = stmt.get("Action", [])
    return a if isinstance(a, list) else [a]


def _resources(stmt):
    r = stmt.get("Resource", [])
    return r if isinstance(r, list) else [r]


def test_build_copies_session_py_too():
    """复制清单必须含 session.py——它是 upgrade code 的单一实现。

    漏了它 panel 运行时 ImportError（测试期能 import 是因为 conftest 把
    auth 目录加进了 sys.path，那**不代表部署产物里有这个文件**）。
    Task 8 已经在 MCP 镜像上真踩过一次同类问题。
    """
    assert set(dp.COPY_FILES) == {"common.py", "permissions.py", "ops_log.py",
                                  "session.py"}


def test_copy_files_covers_every_local_module_panel_imports():
    """按传递闭包核对复制清单，而不是靠记性。

    只改代码不改清单时，单测全绿而部署产物缺文件——这是 Task 8 在 MCP
    Dockerfile 上真实发生过的失败模式。
    """
    fn_dir = PANEL.parent / "deployer" / "functions"
    auth_dir = PANEL.parent / "auth"
    external = {"os", "json", "re", "time", "logging", "boto3", "botocore",
                "urllib", "datetime", "hmac", "hashlib", "base64", "secrets",
                "configparser", "argparse", "sys", "shutil", "subprocess",
                "pathlib", "typing", "collections", "functools", "itertools"}

    def local_imports(path):
        names = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        return names

    panel_own = {p.stem for p in PANEL.glob("*.py")}
    needed, queue, seen = set(), [p for p in PANEL.glob("*.py")
                                 if p.name != "deploy_panel.py"], set()
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for name in local_imports(cur):
            if name in external or name in panel_own:
                continue
            for d in (fn_dir, auth_dir):
                cand = d / f"{name}.py"
                if cand.exists():
                    needed.add(f"{name}.py")
                    queue.append(cand)
                    break

    assert "session.py" in needed and "ops_log.py" in needed, (
        f"传递闭包解析坏了：{sorted(needed)}")
    missing = needed - set(dp.COPY_FILES)
    assert not missing, f"这些模块被 import 但不在复制清单: {sorted(missing)}"


def test_function_url_auth_type_is_iam():
    """AuthType=NONE + Principal:* 实测会被安全扫描自动处置（删光 policy）。"""
    assert dp.FUNCTION_URL_AUTH_TYPE == "AWS_IAM"
    src = (PANEL / "deploy_panel.py").read_text()
    assert 'AuthType="NONE"' not in src and "AuthType='NONE'" not in src


def test_resource_policy_is_exactly_two_statements_bound_to_edge_role():
    stmts = dp.function_url_statements(EDGE_ROLE)
    assert len(stmts) == 2, "2025-10 起缺任一条即 403"
    by_action = {s["Action"]: s for s in stmts}
    assert set(by_action) == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}
    for s in stmts:
        # 逐字符 exact，不做前缀匹配、不用账号根、绝不 *
        assert s["Principal"] == EDGE_ROLE, f"Principal 不是 exact edge role: {s}"
    u = by_action["lambda:InvokeFunctionUrl"]
    assert u["FunctionUrlAuthType"] == "AWS_IAM"
    i = by_action["lambda:InvokeFunction"]
    assert i["InvokedViaFunctionUrl"] is True


@pytest.mark.parametrize("bad", ["", None, "   ", "*"])
def test_missing_or_wildcard_edge_role_aborts_instead_of_widening(bad):
    """缺配置必须抛错——fallback 到 Principal:* 会让 Function URL 全网可调。"""
    with pytest.raises((KeyError, ValueError)):
        dp.function_url_statements(bad)


def test_panel_role_ssm_resource_is_exact_jwt_secret_arn():
    """**不照抄 auth 的 parameter/site-builder/* 前缀**。

    auth 用前缀是它自己还要读 site-client-secret；panel 拿前缀等于被攻破时
    顺带交出 Cognito client secret 与该前缀下未来的一切秘密。
    """
    ssm = [s for s in dp.role_statements()
           if any(a.startswith("ssm:") for a in _actions(s))]
    assert ssm, "panel role 缺 SSM 读取权限"
    for s in ssm:
        for res in _resources(s):
            assert res.endswith("parameter/site-builder/jwt-secret"), (
                f"SSM 资源不是精确 jwt-secret ARN: {res}")
            assert not res.endswith("*"), "出现通配前缀——会顺带拿到别的秘密"


def test_kms_decrypt_is_scoped_via_ssm():
    """kms:Decrypt 必须带 ViaService 条件，否则这个角色能直接拿 key 干别的。"""
    kms = [s for s in dp.role_statements() if "kms:Decrypt" in _actions(s)]
    assert kms, "缺 kms:Decrypt——SecureString 读不出来"
    for s in kms:
        cond = s.get("Condition", {}).get("StringEquals", {})
        assert "kms:ViaService" in cond, f"kms:Decrypt 没有 ViaService 限定: {s}"


def test_panel_role_has_no_putitem_on_sites_or_admins():
    """panel 的站点写入必须经 permissions 的事务；整条覆盖权会绕过守卫。"""
    for s in dp.role_statements():
        res = json.dumps(_resources(s))
        acts = _actions(s)
        if "site-sites" in res:
            assert "dynamodb:PutItem" not in acts, f"sites 表给了 PutItem: {s}"
            assert "dynamodb:*" not in acts, f"过宽: {s}"


def test_panel_role_routing_table_is_update_only():
    """路由表**仅** UpdateItem（spec §2）——Put 能整条切流、Delete 能摘掉站点。

    表名必须**从 role_statements 用的同一个源**（config.ini）取，不能用测试
    环境变量里的 "routing"：两者不同名时 `if` 永不成立，用例什么都没断言。
    实测踩过——给路由表加 PutItem 后本用例仍然全绿（mutation 5）。
    所以这里先按 Sid 定位那条语句，再交叉核对它的资源确实是路由表。
    """
    stmts = [s for s in dp.role_statements()
             if s.get("Sid") == "RoutingProjectionUpdateOnly"]
    assert len(stmts) == 1, (
        "找不到路由表那条语句（Sid 改名了？）——改名时必须同步本用例，"
        "否则它会静默变成空转")
    routing = dp._cfg("Platform", "routing_table")
    assert any(routing in r for r in _resources(stmts[0])), (
        f"Sid 对上了但资源不是路由表: {_resources(stmts[0])}")
    acts = set(_actions(stmts[0]))
    assert acts <= {"dynamodb:UpdateItem", "dynamodb:GetItem",
                    "dynamodb:Query"}, f"路由表权限过宽: {sorted(acts)}"
    # 另外全表扫一遍：路由表不得在**任何**语句里拿到 Put/Delete
    for s in dp.role_statements():
        if any(routing in r for r in _resources(s)):
            bad = {"dynamodb:PutItem", "dynamodb:DeleteItem",
                   "dynamodb:*"} & set(_actions(s))
            assert not bad, f"路由表拿到了 {sorted(bad)}（Sid={s.get('Sid')}）"


def test_ops_log_is_putitem_only():
    for s in dp.role_statements():
        if any("site-ops-log" in r for r in _resources(s)):
            assert set(_actions(s)) == {"dynamodb:PutItem"}, (
                "审计表只能 PutItem——给 Update/Delete 等于允许篡改审计")


def test_no_wildcard_dynamodb_actions_anywhere():
    for s in dp.role_statements():
        assert "dynamodb:*" not in _actions(s), f"出现 dynamodb:* : {s}"


def test_environment_has_no_plaintext_secret():
    """环境变量只下发**参数名**。

    GetFunctionConfiguration 会原样回显环境变量，拿到 JWT_SECRET 即可伪造
    任意用户会话（deploy_auth.py 已记录该原因）。
    """
    env = dp.lambda_environment()
    assert env["JWT_SECRET_PARAM"].startswith("/"), "应是 SSM 参数名"
    for k, v in env.items():
        assert "SECRET" not in k or k.endswith("_PARAM"), (
            f"环境变量 {k} 看起来在下发明文密钥")
    src = (PANEL / "deploy_panel.py").read_text()
    assert "get_parameter" not in src or "WithDecryption" not in src, (
        "部署脚本不该读出明文密钥再塞进环境变量")


def test_environment_covers_every_env_var_the_code_reads():
    """代码里 os.environ[...] 读到的键必须都在环境变量里下发。

    少一个的症状是运行时 KeyError → 500，而单测有 conftest 兜着看不出来。
    """
    env = set(dp.lambda_environment())
    read = set()
    for py in PANEL.glob("*.py"):
        if py.name == "deploy_panel.py":
            continue
        src = py.read_text()
        read |= set(re.findall(r'os\.environ\[[\'"]([A-Z_]+)[\'"]\]', src))
        read |= set(re.findall(r'os\.environ\.get\([\'"]([A-Z_]+)[\'"]', src))
    # AWS 运行时自带的
    read -= {"AWS_DEFAULT_REGION", "AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME"}
    missing = read - env
    assert not missing, f"代码会读但部署没下发的环境变量: {sorted(missing)}"


def test_console_route_is_split_mode_with_platform_prefix():
    """console route 必须 split 模式：/api/* 走 Function URL，其余走 S3。"""
    route = dp.console_route_item("https://abc.lambda-url.us-east-1.on.aws/")
    assert route["route_mode"] == "split"
    assert route["require_auth"] is True
    assert route["static_prefix"].startswith("platform/console/")
    assert "/api" not in route["static_prefix"]
    assert route["subdomain"] == "console"


def test_frontend_prefix_is_versioned():
    """版本化前缀：旧版本保留以便回滚（与站点前端同模式）。"""
    p1 = dp.frontend_prefix("v1")
    p2 = dp.frontend_prefix("v2")
    assert p1 != p2 and p1.startswith("platform/console/")
