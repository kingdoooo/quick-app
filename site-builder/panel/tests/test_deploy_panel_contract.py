"""deploy_panel.py 的部署契约——不实际部署，断言它会构造出什么。"""
import ast
import json
import re
from pathlib import Path

import pytest
from unittest.mock import patch

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

    edge_caller.py 同理：它是"调用者真是 Edge"的唯一判定，漏复制 = handler
    的第 ⓪ 步 ImportError → 整个面板 500（比放行安全，但同样是线上故障）。

    keystore.py / keygen.py（二期 M4）：api.py **顶层** import keystore，所以
    漏复制不是"Key 功能挂了"，而是 api.py import 失败 → **所有**控制台 API 500。
    keygen.py 是 keystore.py 的传递依赖（明文/哈希的唯一算法）。
    这条是**恒定集合**的快照，隔壁那条按传递闭包推导——两条一起才既挡住
    "改了代码忘了改清单"，也挡住"往清单里塞了不存在的文件"（后者会让
    `_build_zip` 在真机上 `sys.exit`，而闭包断言不看这个方向）。
    """
    assert set(dp.COPY_FILES) == {"common.py", "permissions.py", "ops_log.py",
                                  "session.py", "edge_caller.py",
                                  "keystore.py", "keygen.py"}


def test_every_copied_module_actually_exists_on_disk():
    """清单里的每个文件都必须真能找到源——`_build_zip` 找不到就 `sys.exit`。

    为什么单独一条：闭包断言只查"被 import 的都在清单里"（少了会红），
    多出一个不存在的文件名它不会红，而那会在**真机部署时**才炸。
    计划里原本要求加一个 Task 7 才创建的 `api_key_config.py`，就是这个方向。
    查找顺序与 `_build_zip` 一致（`deployer/functions` → `auth`）。
    """
    fn_dir = PANEL.parent / "deployer" / "functions"
    auth_dir = PANEL.parent / "auth"
    for name in dp.COPY_FILES:
        assert (fn_dir / name).exists() or (auth_dir / name).exists(), (
            f"复制清单里的 {name} 在 {fn_dir} 与 {auth_dir} 都找不到——"
            "部署时 _build_zip 会 sys.exit")


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
    # ConditionCheckItem 在白名单里：它是降级事务的 attribute_not_exists 检查
    # 所必需的（见 deploy_panel 里那条注释），且**不能**写数据。
    assert acts <= {"dynamodb:UpdateItem", "dynamodb:GetItem",
                    "dynamodb:Query", "dynamodb:ConditionCheckItem"}, \
        f"路由表权限过宽: {sorted(acts)}"
    # 另外全表扫一遍：路由表不得在**任何**语句里拿到 Put/Delete
    for s in dp.role_statements():
        if any(routing in r for r in _resources(s)):
            bad = {"dynamodb:PutItem", "dynamodb:DeleteItem",
                   "dynamodb:*"} & set(_actions(s))
            assert not bad, f"路由表拿到了 {sorted(bad)}（Sid={s.get('Sid')}）"


def test_role_grants_every_dynamodb_action_the_transactions_actually_need():
    """从 permissions.py 的**事务构造代码**推导所需 action，与 role 交叉核对。

    为什么必须有这条：panel 的 role 原来只给路由表 GetItem+UpdateItem，而
    `write_permissions` 的降级路径（站点还没首次部署成功、无 route item）对
    路由表做的是 `ConditionCheck`。**moto 不校验 IAM**，所以 144 个单测全绿，
    真机上"对任何无 route 的站点做写操作"一律 500
    （Task 14 Step 3 真机验收实测，AccessDeniedException on
    dynamodb:ConditionCheckItem）。

    手抄一份"需要哪些 action"的清单没有用——那份清单本身会漂移。这里按
    **AST 解析 permissions.py 里每个事务项用了哪张表的哪种操作**：
    TransactItems 元素的 key 是 "Update" / "Put" / "Delete" / "ConditionCheck"，
    表名来自 `os.environ["<X>_TABLE"]`，与 lambda_environment() 的映射对得上。
    """
    perm_src = (PANEL.parent / "deployer" / "functions" / "permissions.py").read_text()
    tree = ast.parse(perm_src)

    op_to_action = {"Update": "dynamodb:UpdateItem",
                    "Put": "dynamodb:PutItem",
                    "Delete": "dynamodb:DeleteItem",
                    "ConditionCheck": "dynamodb:ConditionCheckItem"}

    def env_key(node):
        """从 `os.environ["X_TABLE"]` 取出 X_TABLE。"""
        if (isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "environ"
                and isinstance(node.slice, ast.Constant)):
            return node.slice.value
        return None

    # (env 变量名 → 需要的 action 集合)
    needed: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value in op_to_action):
                continue
            if not isinstance(v, ast.Dict):
                continue
            for ik, iv in zip(v.keys, v.values):
                if isinstance(ik, ast.Constant) and ik.value == "TableName":
                    key = env_key(iv)
                    if key:
                        needed.setdefault(key, set()).add(op_to_action[k.value])

    assert needed, "AST 解析不到任何事务项——解析口径坏了，本用例什么都没断言"
    # 必须真的解析到了路由表的 ConditionCheck（就是漏掉的那条）
    assert "dynamodb:ConditionCheckItem" in needed.get("ROUTING_TABLE", set()), (
        f"解析结果里路由表没有 ConditionCheck，可疑: {needed}")

    env = dp.lambda_environment()
    granted: dict[str, set[str]] = {}
    for s in dp.role_statements():
        for res in _resources(s):
            for env_name, table in env.items():
                if not env_name.endswith("_TABLE"):
                    continue
                if res.endswith(f"/{table}") or f"/{table}/" in res:
                    granted.setdefault(env_name, set()).update(_actions(s))

    missing = {}
    for env_name, actions in needed.items():
        if env_name not in env:        # permissions.py 里有 panel 用不到的表
            continue
        gap = actions - granted.get(env_name, set())
        if gap:
            missing[f"{env_name}({env[env_name]})"] = sorted(gap)
    assert not missing, (
        f"事务需要但 panel role 没给的 DynamoDB 权限: {missing} "
        "—— 真机会以 AccessDeniedException → 500 的形态出现，而 moto 测不出来")


# ── api-keys 表的权限从 keystore.py 的操作推导（二期 M4）────────────────
# 手抄一份"需要哪些 action"就是下一个漂移源（M3-FINDINGS §2.18）：panel 曾漏
# ConditionCheckItem，144 个单测全绿而真机上所有写操作 500。这里沿用隔壁那条
# 事务断言的形态，扩展到"keystore 对 api-keys 表做的每个操作 + 每个 IndexName"。

KEYSTORE_SRC = PANEL.parent / "deployer" / "functions" / "keystore.py"

DDB_METHOD_TO_ACTION = {
    "get_item": "dynamodb:GetItem", "put_item": "dynamodb:PutItem",
    "update_item": "dynamodb:UpdateItem", "delete_item": "dynamodb:DeleteItem",
    "query": "dynamodb:Query", "scan": "dynamodb:Scan",
    "batch_get_item": "dynamodb:BatchGetItem",
    "batch_write_item": "dynamodb:BatchWriteItem",
    "transact_get_items": "dynamodb:TransactGetItems",
    "transact_write_items": "dynamodb:TransactWriteItems"}


def _keystore_table_ops() -> tuple[set[str], set[str]]:
    """(keystore 需要的 action, 它用到的 IndexName)，全部从源码 AST 推导。

    两种调用形态都要认：`_table().get_item(...)` 是直接调用，而
    `common._paginate(_table().query, IndexName=...)` 把**方法本身**当参数传出去
    （节点是 Attribute 而不是 Call）。按"属性挂在 `_table()` 调用上"来判就能一条
    规则覆盖两种——只认 `ast.Call` 会漏掉全部 Query，而 Query 恰好是本表最容易
    漏权限的那个（GSI 要的是索引 ARN）。
    """
    tree = ast.parse(KEYSTORE_SRC.read_text())
    actions, indexes = set(), set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute)
                and node.attr in DDB_METHOD_TO_ACTION
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "_table"):
            actions.add(DDB_METHOD_TO_ACTION[node.attr])
        if (isinstance(node, ast.keyword) and node.arg == "IndexName"
                and isinstance(node.value, ast.Constant)):
            indexes.add(node.value.value)
    return actions, indexes


def _api_keys_table() -> str:
    """表名取自**下发给 Lambda 的环境变量**，不写字面量。

    keystore 读 `os.environ["API_KEYS_TABLE"]`，所以"role 授权的那张表"与
    "代码实际访问的那张表"同名才成立；两处漂移时本文件所有断言会一起变红。
    """
    return dp.lambda_environment()["API_KEYS_TABLE"]


def test_keystore_op_parser_is_not_vacuous():
    """守卫的守卫：解析口径一坏，下面两条会静默变成空转。"""
    actions, indexes = _keystore_table_ops()
    assert {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
            "dynamodb:Query"} <= actions, (
        f"解析不到 keystore 的基本操作，口径坏了: {sorted(actions)}")
    assert indexes == {"email-index", "keyid-index"}, (
        f"解析出的 GSI 不是那两个: {sorted(indexes)}")


def test_role_grants_every_api_keys_action_keystore_needs():
    """keystore 会做的每个操作、用到的每个 GSI，role 都必须授权。

    **GSI 上的 Query 要的是索引 ARN**（`table/T/index/I`），不是表 ARN。
    漏 `index/*` 时列 Key 与吊销都会 AccessDenied → 500，而 moto 不校验 IAM，
    单测这一侧看不出任何异常。
    """
    actions, indexes = _keystore_table_ops()
    table = _api_keys_table()

    base_granted: set[str] = set()
    index_grants: list[tuple[str, set[str]]] = []
    for s in dp.role_statements():
        for res in _resources(s):
            if res.endswith(f"/{table}"):
                base_granted |= set(_actions(s))
            if f"/{table}/index/" in res:
                index_grants.append((res, set(_actions(s))))

    assert base_granted, f"role 里找不到 {table} 的任何授权"
    missing = actions - base_granted
    assert not missing, (
        f"keystore 会做但 panel role 没给的权限: {sorted(missing)} "
        "—— 真机以 AccessDeniedException → 500 出现，moto 测不出来")
    for idx in sorted(indexes):
        covered = any("dynamodb:Query" in acts
                      and (res.endswith(f"/index/{idx}")
                           or res.endswith("/index/*"))
                      for res, acts in index_grants)
        assert covered, (
            f"GSI {idx} 上的 Query 没有被授权（现有索引资源: "
            f"{[r for r, _ in index_grants]}）——GSI 查询要的是索引 ARN")


def test_api_keys_role_has_no_deleteitem_and_no_scan():
    """吊销是置 `revoked` 而**不删行**（保留审计痕迹），所以不给 DeleteItem；
    也不给 Scan（按人列 Key 走 email-index，Scan 等于能读全表凭证行）。

    两个方向都查：role 里没给，keystore 里也确实没用——只查 role 时，
    将来 keystore 里冒出一个 `scan` 会以真机 AccessDenied 的形态出现；
    只查代码时，role 多给的宽权限没人管。
    """
    table = _api_keys_table()
    for s in dp.role_statements():
        if not any(f"/{table}" in r for r in _resources(s)):
            continue
        bad = ({"dynamodb:DeleteItem", "dynamodb:Scan", "dynamodb:*"}
               & set(_actions(s)))
        assert not bad, f"api-keys 表拿到了 {sorted(bad)}（Sid={s.get('Sid')}）"
    actions, _ = _keystore_table_ops()
    over = {"dynamodb:DeleteItem", "dynamodb:Scan"} & actions
    assert not over, (
        f"keystore 里出现了 {sorted(over)}——真机会 AccessDenied。"
        "该改的是 keystore（吊销必须置 revoked、列 Key 必须走 GSI），不是放宽 role")


def test_environment_covers_every_env_var_keystore_reads():
    """keystore 读的环境变量必须都下发。

    为什么隔壁 `test_environment_covers_every_env_var_the_code_reads` 覆盖不到：
    它只 glob `panel/*.py`，而 keystore.py 住在 `deployer/functions/`，只在
    部署时被复制进包——漏下发 `API_KEYS_TABLE` 的症状是真机 KeyError → 500，
    而单测有 conftest 兜着看不出来。
    这里**只**扩展到 keystore：整条复制闭包不适用，common.py 会读
    `ACCOUNT_ID` / `RUNTIME_BOUNDARY_ARN`，那是 panel 永不调用的建站路径，
    要求下发它们等于把无关配置塞进 panel。
    """
    env = set(dp.lambda_environment())
    src = KEYSTORE_SRC.read_text()
    read = set(re.findall(r'os\.environ\[[\'"]([A-Z_]+)[\'"]\]', src))
    read |= set(re.findall(r'os\.environ\.get\([\'"]([A-Z_]+)[\'"]', src))
    read -= {"AWS_DEFAULT_REGION", "AWS_REGION"}
    assert "API_KEYS_TABLE" in read, f"解析口径坏了: {sorted(read)}"
    missing = read - env
    assert not missing, f"keystore 会读但部署没下发的环境变量: {sorted(missing)}"


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


# ── EDGE_ROLE_ID 必须下发（Codex 审查 2026-08-10 P1-1）──────────────────

def test_lambda_environment_carries_edge_role_id():
    """handler 靠它确认调用者是 Edge；不下发 = 线上拒绝所有请求。"""
    env = dp.lambda_environment("AROAEXAMPLE")
    assert env["EDGE_ROLE_ID"] == "AROAEXAMPLE"


def test_edge_role_id_is_resolved_from_iam_not_hand_copied():
    """RoleId 由 get_role 现查，**不许在 config 里再抄一份**。

    手抄的第二份真源会漂移（本项目记录过"不变量被手抄多份"这一类缺陷）。
    """
    import re
    src = (PANEL / "deploy_panel.py").read_text()
    assert "get_role" in src, "没有现查 RoleId"
    m = re.search(r"def edge_role_id\(.*?\n(?=\ndef )", src, re.S)
    assert m, "找不到 edge_role_id"
    assert "_cfg(" not in m.group(0), (
        "edge_role_id 从 config 取值——那是第二份真源，会与 IAM 漂移")


def test_edge_role_id_rejects_non_role_id_shapes():
    """解析结果必须是 AROA 形态；拿到别的东西要抛错而不是照发。"""
    import types
    class FakeIam:
        def __init__(self, rid): self._r = rid
        def get_role(self, RoleName): return {"Role": {"RoleId": self._r}}

    for bad in ("AIDANOTAROLE", "", "arn:aws:iam::1:role/x"):
        with patch.object(dp.boto3, "client", lambda *a, **k: FakeIam(bad)):
            with pytest.raises(ValueError):
                dp.edge_role_id("arn:aws:iam::1:role/EdgeRole")
    with patch.object(dp.boto3, "client",
                      lambda *a, **k: FakeIam("AROAGOOD123")):
        assert dp.edge_role_id("arn:aws:iam::1:role/EdgeRole") == "AROAGOOD123"


def test_empty_edge_role_arn_aborts_before_calling_iam():
    with pytest.raises(ValueError):
        dp.edge_role_id("")


# ── 前端真版本化（Codex 审查 2026-08-10 P2-2）───────────────────────────
# 原状：所有前端修复都传到 platform/console/v1/，桶未开版本控制，旧内容被
# 原地覆盖。真机核对过：platform/console/ 下只有 v1 的三个对象。
# 所以 docstring 里的"旧版本保留以便回滚"是**假的**——只是接口能力。

def test_frontend_prefix_derives_from_content_not_a_fixed_literal():
    """默认前缀必须由**内容**决定：改了前端就是新前缀。"""
    v1 = dp.frontend_content_version()
    assert re.fullmatch(r"[0-9a-f]{8,}", v1), f"版本段形态不对: {v1}"
    # 改一个字节 → 版本必须变
    target = PANEL / "frontend" / "app.js"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n/* probe */\n")
        v2 = dp.frontend_content_version()
    finally:
        target.write_bytes(original)
    assert v1 != v2, "前端内容变了但版本前缀没变——旧版本会被原地覆盖"
    assert dp.frontend_content_version() == v1, "还原后版本必须回到原值"


def test_frontend_prefix_is_stable_across_calls():
    """同样的内容必须得到同样的前缀（否则每次部署都换前缀、白占空间）。"""
    assert dp.frontend_prefix() == dp.frontend_prefix()


def test_frontend_prefix_still_has_no_trailing_slash():
    """尾斜杠会让 Edge 拼出双斜杠 → 整站 403（既有实测坑，不能回归）。"""
    p = dp.frontend_prefix()
    assert not p.endswith("/"), p
    assert p.startswith("platform/console/")
    assert "//" not in p


def test_upload_refuses_to_overwrite_a_different_build(monkeypatch):
    """同前缀下已有**不同内容**时必须中止，不能静默覆盖。

    这是"可回滚"的技术前提：一个版本前缀一旦发布就不可变。
    """
    calls = []

    class FakeS3:
        def list_objects_v2(self, **kw):
            # 该前缀已存在对象，且 ETag 与将要上传的不同
            return {"KeyCount": 1, "Contents": [
                {"Key": kw["Prefix"] + "index.html", "ETag": '"deadbeef"'}]}

        def head_object(self, **kw):
            return {"ETag": '"deadbeef"'}

        def put_object(self, **kw):
            calls.append(kw["Key"])

    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: FakeS3())
    with pytest.raises(SystemExit):
        dp.upload_frontend()
    assert calls == [], f"中止前已经写了对象: {calls}"


def test_upload_is_idempotent_when_content_matches(monkeypatch):
    """同前缀同内容 = 重跑部署脚本，必须放行（幂等是本脚本的既有契约）。"""
    import hashlib

    src = PANEL / "frontend"
    etags = {}
    for p in sorted(src.rglob("*")):
        if p.is_file():
            key = dp.frontend_prefix() + "/" + str(p.relative_to(src))
            etags[key] = '"%s"' % hashlib.md5(p.read_bytes()).hexdigest()

    class FakeS3:
        def list_objects_v2(self, **kw):
            items = [{"Key": k, "ETag": v} for k, v in etags.items()]
            return {"KeyCount": len(items), "Contents": items}

        def head_object(self, **kw):
            return {"ETag": etags[kw["Key"]]}

        def put_object(self, **kw):
            return {}

    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: FakeS3())
    assert dp.upload_frontend() >= 0      # 不抛错即可


def test_docstring_no_longer_claims_rollback_it_cannot_do():
    """`frontend_prefix` 的注释不得再声称"旧版本保留以便回滚"除非确有其事。

    M3-FINDINGS 的教训：文档写了做不到的事比没写更糟（审查时会被当成已有能力）。
    """
    src = (PANEL / "deploy_panel.py").read_text()
    m = re.search(r"def frontend_prefix\(.*?\n(?=\ndef )", src, re.S)
    assert m, "找不到 frontend_prefix"
    body = m.group(0)
    if "回滚" in body:
        assert "不可变" in body or "immutable" in body.lower(), (
            "仍然声称可回滚，但没说明是靠「前缀不可变」实现的——"
            "桶没开版本控制，覆盖式部署下这句话是假的")
