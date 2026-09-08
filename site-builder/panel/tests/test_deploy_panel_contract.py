"""deploy_panel.py 的部署契约——不实际部署，断言它会构造出什么。

**`[SessionKeys]` 一律从 `rs_config` 夹具那份临时 config 读，不读真 config.ini**（理由见
conftest 里 `RS_SESSION_KEYS` 上面那段）。`_cfg`（region / account / routing_table 等非密钥项）
仍走模块级那份真 config——那些值本文件不逐字断言。
"""
import ast
import json
import sys
import re
from pathlib import Path

import boto3
import pytest
from unittest.mock import patch

import deploy_panel as dp
import upgrade_code_vectors as v

PANEL = Path(__file__).parents[1]
EDGE_ROLE = "arn:aws:iam::000000000000:role/site-edge-role"

@pytest.fixture(autouse=True)
def _use_rs_config(rs_config):
    """本文件每条用例都按 RS 形态的临时 config 判（实现在 conftest.rs_config）。"""
    return rs_config


def _live_keys():
    """夹具那份 config 的 `[SessionKeys]`，**按加载器解析**（别把值写死在断言里）。"""
    sys.path.insert(0, str(PANEL.parent / "auth"))
    from session_keys import load_session_keys
    return load_session_keys(dp.CFG_PATH)


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

    analytics.py / access_rollup.py（二期 M5）：形态与 M4 那对完全一样——api.py
    顶层 import analytics（漏它 = 所有控制台 API 500，不只统计页），而
    access_rollup.py 是它的传递依赖（pv/uv 口径的唯一定义，读取层 import 而不是
    另写一份）。**位置是 `deployer/functions/` 而不是 `panel/`**，正是为了让
    这条与隔壁的闭包断言能看见它们。

    verifier_env.py（3c-1A）：console_session 顶层 import 它（allowlist 装配 / 观测日志的
    唯一实现，auth 拥有）。漏它 = 面板会话全部 500。

    session_kms.py（3c-final）：KMS 边界的唯一实现——公钥加载器（验签）与 KmsSigner（签发）
    都在里面。漏它 = console_session 顶层 import 失败 = 面板会话与升级码全部 500。

    这条是**恒定集合**的快照，隔壁那条按传递闭包推导——两条一起才既挡住
    "改了代码忘了改清单"，也挡住"往清单里塞了不存在的文件"（后者会让
    `_build_zip` 在真机上 `sys.exit`，而闭包断言不看这个方向）。
    """
    assert set(dp.COPY_FILES) == {"common.py", "permissions.py", "ops_log.py",
                                  "session.py", "verifier_env.py", "session_kms.py",
                                  "edge_caller.py", "keystore.py", "keygen.py",
                                  "analytics.py", "access_rollup.py"}


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


def test_environment_session_keys_json_has_only_the_console_family():
    env = dp.lambda_environment()
    keys = json.loads(env["SESSION_KEYS_JSON"])
    assert set(keys) == {"console"}, "panel 的 SESSION_KEYS_JSON 只能有 console family"
    for row in keys["console"]:
        # 3c-final：只有引用（kid / alg / role / key_arn / spki_sha256），**没有任何密钥材料**
        assert set(row) == {"kid", "alg", "role", "key_arn", "spki_sha256"}, row
        assert row["kid"].startswith("console-")


# ── 3c-final：panel 的 IAM 面从 SSM 换成 KMS（spec §11.2 / §11.5 / ADR 0001）────────
#
# 两条一对：① 一处 SSM / kms:Decrypt 都不许剩（对称密钥"读到就能签"这条路整个删掉）；
# ② KMS 的两个动作精确到 console family 的 key ARN，且 kms:Sign 带算法与 MessageType 两个条件
#    ——那两个条件把 §11.5 的合同钉进 IAM，缺了它们这个角色能用同一把 key 签 PSS / DIGEST 形态。

def test_panel_has_no_ssm_statement_at_all():
    assert not [s for s in dp.role_statements() if any(a.startswith("ssm:") or a == "kms:Decrypt"
                                                      for a in _actions(s))], \
        "panel 不再读任何 SSM 参数；会话签名密钥在 KMS"


def test_panel_role_signs_and_reads_public_key_for_the_console_key_only():
    by_sid = {s["Sid"]: s for s in dp.role_statements()}
    sign, pub = by_sid["SignConsoleTokens"], by_sid["ReadConsolePublicKeys"]
    assert sign["Action"] == "kms:Sign" and sign["Resource"] == [v.KEY_ARN[v.CONSOLE_KID]]
    assert sign["Condition"] == {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                                 "kms:MessageType": "RAW"}}
    assert pub["Action"] == "kms:GetPublicKey" and pub["Resource"] == [v.KEY_ARN[v.CONSOLE_KID]]
    # 配置里**有** site family 的那把（见 RS_SESSION_KEYS），所以这条不是空转：
    # 拿到 site 的 key = panel 被攻破时能伪造站点会话（spec §4.3）。
    assert v.KEY_ARN[v.SITE_KID] not in sign["Resource"] + pub["Resource"]
    assert not any("site" in r for r in sign["Resource"] + pub["Resource"])


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


# ── 统计表的权限从 analytics.py 的操作推导（二期 M5）────────────────────
# 为什么必须单独有这一组（Task 8 报告 §8.4 点出的缺口）：隔壁两条 IAM 推导断言
# 都看不见这张表——一条解析 permissions.py 的**事务项**（TransactItems 的
# "Update"/"ConditionCheck" 字典），一条解析 keystore.py 挂在 `_table()` 上的
# **资源级方法**。analytics.py 用的是低阶 client 的 `_client().query(**kwargs)`，
# 表名在 kwargs 里，两个解析器的词汇表都不认。于是 `AccessTablesQueryOnly`
# 整条缺失、或被放宽到 Scan，**没有任何单测会红**，而真机是 AccessDenied → 500
# （moto 不校验 IAM，这一类本仓库已被咬过多次）。

ANALYTICS_SRC = PANEL.parent / "deployer" / "functions" / "analytics.py"


def _analytics_ddb_actions() -> set[str]:
    """analytics.py 对 DynamoDB 做的每个操作 → IAM action，全从 AST 推导。

    判据是"方法挂在 `_client()` 调用上"：`_client().query(**kwargs)` 是低阶
    client 形态，与 keystore 那条的 `_table()` 同形不同名。手抄一份"需要哪些
    action"的清单本身就是下一个漂移源。
    """
    actions = set()
    for node in ast.walk(ast.parse(ANALYTICS_SRC.read_text())):
        if (isinstance(node, ast.Attribute)
                and node.attr in DDB_METHOD_TO_ACTION
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "_client"):
            actions.add(DDB_METHOD_TO_ACTION[node.attr])
    return actions


def _analytics_env_keys() -> set[str]:
    """analytics.py 读的环境变量键名（AST），用来找出它访问的是哪两张表。

    **只扫 analytics.py**，不扫 access_rollup.py：读取层只 import 它的
    `day_stats`（纯函数），那些 `os.environ[...]` 属于 rollup Lambda 的 handler
    路径。整文件一刀切会要求 panel 下发 rollup 专用配置——与上面那段
    可达性归属的理由是同一个。
    """
    keys = set()
    for node in ast.walk(ast.parse(ANALYTICS_SRC.read_text())):
        if (isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "environ"
                and isinstance(node.slice, ast.Constant)):
            keys.add(node.slice.value)
    return keys


def _access_tables() -> dict[str, str]:
    """analytics.py 读的 `*_TABLE` 键 → **下发给 Lambda 的**表名。

    表名不写字面量：analytics 读 `os.environ["ACCESS_EVENTS_TABLE"]`，所以
    "role 授权的那张表"与"代码实际访问的那张表"同名才成立；两处漂移时本组
    断言会一起变红。形态照隔壁 `_api_keys_table()`。
    """
    env = dp.lambda_environment()
    return {k: env[k] for k in sorted(_analytics_env_keys())
            if k.endswith("_TABLE") and k in env}


def test_analytics_op_parser_is_not_vacuous():
    """守卫的守卫：解析口径一坏，下面三条会静默变成空转。"""
    assert "dynamodb:Query" in _analytics_ddb_actions(), (
        f"解析不到 analytics.py 的 Query: {sorted(_analytics_ddb_actions())}")
    assert set(_analytics_env_keys()) >= {"ACCESS_EVENTS_TABLE",
                                         "ACCESS_DAILY_TABLE"}, (
        f"解析不到 analytics.py 读的表名环境变量: {sorted(_analytics_env_keys())}")
    assert len(_access_tables()) == 2, (
        f"两张统计表没有都在环境变量里: {_access_tables()}")


def test_role_grants_every_access_table_action_analytics_needs():
    """analytics.py 会做的每个操作，panel role 都必须授权。

    缺 Query 的症状是 AccessDeniedException → 统计端点 500，而 moto 不校验
    IAM，`test_analytics_api.py` 那一侧全绿也说明不了什么。
    没有 GSI，所以**不需要** `index/*`（与 api-keys 那条刻意不同）。
    """
    needed = _analytics_ddb_actions()
    for key, table in _access_tables().items():
        granted = set()
        for s in dp.role_statements():
            for res in _resources(s):
                if res.endswith(f"/{table}") or f"/{table}/" in res:
                    granted |= set(_actions(s))
        assert granted, (
            f"panel role 里找不到 {table}（{key}）的任何授权——真机 AccessDenied → 500")
        missing = needed - granted
        assert not missing, (
            f"{table} 上 analytics.py 需要但没授权的动作: {sorted(missing)} "
            "—— 真机以 AccessDeniedException → 500 出现，moto 测不出来")


def test_access_tables_are_query_only_no_scan_no_writes():
    """统计表对 panel **只读**：不给任何写动作，也不给 Scan。

    不给写：明细的唯一写入者是 Edge、聚合的唯一写入者是 rollup Lambda——控制台
    能改数就等于统计可被伪造（还包括抹掉自己的访问记录）。
    不给 Scan：Scan 能跨站点读出别人站点的访问明细（**含访问者邮箱**），而读取层
    每个查询都带 site_id 分区键，压根不需要它。
    两个方向都查（形态照 api-keys 那条）：只查 role 时，将来 analytics 里冒出一个
    `scan` 会以真机 AccessDenied 出现；只查代码时，role 多给的宽权限没人管。
    """
    forbidden = {"dynamodb:PutItem", "dynamodb:UpdateItem",
                 "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
                 "dynamodb:Scan", "dynamodb:*"}
    for key, table in _access_tables().items():
        for s in dp.role_statements():
            if not any(f"/{table}" in r for r in _resources(s)):
                continue
            bad = forbidden & set(_actions(s))
            assert not bad, (
                f"{table}（{key}）拿到了 {sorted(bad)}（Sid={s.get('Sid')}）"
                "——统计表对 panel 只能 Query")
    over = forbidden & _analytics_ddb_actions()
    assert not over, (
        f"analytics.py 里出现了 {sorted(over)}——真机会 AccessDenied。"
        "该改的是 analytics.py（读取层不写数、查询都带分区键），不是放宽 role")


def test_access_table_names_match_the_tables_the_stack_creates():
    """下发的表名必须是 CDK 栈真建出来的那两张（真值锚点）。

    三个部署目标各写一份字面量（deployer 栈建表、panel 下发、MCP 下发），改名时
    只改一处的症状是真机 ResourceNotFoundException，而各包单测都绿。
    MCP 那份钉在
    `mcp/tests/test_agentcore_contract.py::test_runtime_table_names_match_the_tables_the_stack_creates`。
    """
    app_src = (PANEL.parent / "deployer" / "infra" / "app.py").read_text()
    tables = _access_tables()
    assert tables, "没解析到任何统计表——本用例会静默空转"
    for key, table in tables.items():
        assert f'table_name="{table}"' in app_src, (
            f"{key}={table!r} 在 infra/app.py 里找不到对应的建表语句——"
            "表名漂移了，真机 ResourceNotFoundException")


def test_environment_covers_every_env_var_keystore_reads():
    """keystore 读的环境变量必须都下发。

    keystore.py 住在 `deployer/functions/`，只在部署时被复制进包——漏下发
    `API_KEYS_TABLE` 的症状是真机 KeyError → 500，而单测有 conftest 兜着
    看不出来。
    2026-08-12 起隔壁 `test_environment_covers_every_env_var_the_code_reads`
    已经加宽到整个进包清单（含本模块），本条**保留**为直读式的兜底：它不依赖
    那边的可达性闭包，闭包解析哪天坏了，keystore 这张表的键仍然有人盯。
    （那边为什么不能整文件一刀切扫 common.py：见它上面那段注释。）
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
    """环境变量里没有任何密钥材料。

    GetFunctionConfiguration 会原样回显环境变量，拿到会话签名密钥即可伪造任意用户会话
    （docs/security/account-trust-boundary.md 的整条理由）。3c-final 起 panel 的会话签名 key
    在 KMS 里，环境变量只有 kid / key_arn / spki_sha256 这类**引用**。
    """
    env = dp.lambda_environment()
    for k, val in env.items():
        assert "SECRET" not in k or k.endswith("_PARAM"), (
            f"环境变量 {k} 看起来在下发明文密钥")
    src = (PANEL / "deploy_panel.py").read_text()
    # panel 不再读任何 SSM 参数——不是"读了但不解密"，是一处都不读
    assert "get_parameter" not in src, "panel 又开始读 SSM 参数了（会话密钥在 KMS）"


# ── 环境变量扫描跟随"真正进包的那批文件"（2026-08-12 加宽，故意的）────────
# 原状：只 glob `panel/*.py`。但 zip 里还有 COPY_FILES 复制进来的模块，它们也读
# 环境变量（keystore.py 读 `API_KEYS_TABLE`、ops_log.py 读 `OPS_LOG_TABLE`）。
# 那些键当时恰好都已下发，所以没出故障——但守卫在它们**没**下发时同样是绿的
# （实测过：把 API_KEYS_TABLE 从 lambda_environment() 里删掉，本用例照样 pass），
# 下一个复制进来的模块读一个新键时也照样绿。症状是运行时 KeyError → 500。
# 文件集**从 COPY_FILES 推导**，查找顺序与 `_build_zip` 一致：手抄第二份清单
# 就是下一个漂移源（M3-FINDINGS §2.18，本仓库已被这一类咬过多次）。
#
# 加宽后必须按**可达性**归属，不能整文件一刀切：common.py 的 `site_role_arn` /
# `site_policy` / `ensure_site_role` 读 `ACCOUNT_ID` / `RUNTIME_BOUNDARY_ARN`，
# 那是建站路径，panel 的任何入口都到不了（整文件扫描实测会把这两个键报成
# "缺下发"，而真去下发它们等于把无关配置塞进 panel——那才是错的方向）。
# 所以从 panel 自己的模块出发算传递闭包，只对**可达**的单元收环境变量读取。
# 判"可达"看的是**引用**而不是"调用"：`common._paginate(_table().query)` 把方法
# 本身当参数传出去（节点是 Attribute 而不是 Call），只认 `ast.Call` 会漏掉这类。


def _shipped_modules() -> dict[str, Path]:
    """会进 Lambda zip 的模块名 → 源文件。

    查找顺序与 `_build_zip` 一致（`deployer/functions` → `auth`）；复制来的那份
    后放是因为 `_build_zip` 先把它们 copy 进 panel 目录再 glob，同名时复制的
    那份覆盖 panel 自己的。
    """
    mods = {p.stem: p for p in PANEL.glob("*.py") if p.name != "deploy_panel.py"}
    fn_dir, auth_dir = PANEL.parent / "deployer" / "functions", PANEL.parent / "auth"
    for name in dp.COPY_FILES:
        src = next((d / name for d in (fn_dir, auth_dir) if (d / name).exists()),
                   None)
        assert src, f"复制清单里的 {name} 找不到源文件"
        mods[src.stem] = src
    return mods


def _env_keys_read(node: ast.AST, consts: dict[str, str]) -> set[str]:
    """一段 AST 里 `os.environ` 读到的键名。

    `os.environ["X"]` 与 `os.environ.get("X", ...)` 两种形态都认；键是**模块级
    字符串常量**时按常量表解析——edge_caller 读的是
    `os.environ.get(EDGE_ROLE_ID_ENV, "")`，只认字面量会漏掉 `EDGE_ROLE_ID`，
    而缺它线上拒绝所有请求（P1-1 的原始形态）。
    """
    keys: set[str] = set()

    def resolve(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.Name):
            return consts.get(n.id)     # 模块级常量；解析不了就返回 None
        return None

    for n in ast.walk(node):
        if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute)
                and n.value.attr == "environ"):
            keys.add(resolve(n.slice))
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get"
                and isinstance(n.func.value, ast.Attribute)
                and n.func.value.attr == "environ" and n.args):
            keys.add(resolve(n.args[0]))
    return keys - {None}


def _reachable_env_reads() -> tuple[set[str], set[tuple[str, str]]]:
    """(进包代码在 panel 可达路径上读的环境变量, 走到过的 `(模块, 单元)`)。

    单元 = 模块顶层的一个 def/class，或 `<module>`（import 就会执行的顶层代码）。
    入口取 panel **自己**模块的全部单元（都在包里、都是 panel 的代码，不去解析
    handler 的路由分发表）+ 每个进包模块的 `<module>`。函数内的 import 也记进
    模块级别名表——那只会让可达集偏大，方向是安全的（宁可多要一个键）。
    """
    mods = _shipped_modules()
    panel_own = {p.stem for p in PANEL.glob("*.py") if p.name != "deploy_panel.py"}

    units: dict[tuple[str, str], ast.AST] = {}
    # 模块 → {本地名 → (目标模块, 属性名或 None)}；None 表示 `import mod` 形态
    imports: dict[str, dict[str, tuple[str, str | None]]] = {}
    consts: dict[str, dict[str, str]] = {}
    for mod, path in mods.items():
        imports[mod], consts[mod], top = {}, {}, []
        for st in ast.parse(path.read_text()).body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                units[(mod, st.name)] = st
            else:
                top.append(st)
            if (isinstance(st, ast.Assign) and isinstance(st.value, ast.Constant)
                    and isinstance(st.value.value, str)):
                consts[mod].update({t.id: st.value.value for t in st.targets
                                    if isinstance(t, ast.Name)})
            for n in ast.walk(st):
                if isinstance(n, ast.Import):
                    for a in n.names:
                        if a.name in mods:
                            imports[mod][a.asname or a.name] = (a.name, None)
                elif (isinstance(n, ast.ImportFrom) and n.level == 0
                        and n.module in mods):
                    for a in n.names:
                        imports[mod][a.asname or a.name] = (n.module, a.name)
        units[(mod, "<module>")] = ast.Module(body=top, type_ignores=[])

    reached: set[tuple[str, str]] = set()
    queue = [u for u in units if u[0] in panel_own]
    queue += [(m, "<module>") for m in mods]
    while queue:
        cur = queue.pop()
        if cur in reached or cur not in units:
            continue
        reached.add(cur)
        mod = cur[0]
        for n in ast.walk(units[cur]):
            if isinstance(n, ast.Name):
                queue.append((mod, n.id))               # 同模块内的引用
                tgt = imports[mod].get(n.id)
                if tgt and tgt[1]:
                    queue.append((tgt[0], tgt[1]))      # from X import f
            elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
                tgt = imports[mod].get(n.value.id)
                if tgt and tgt[1] is None:
                    queue.append((tgt[0], n.attr))      # X.f
    keys: set[str] = set()
    for mod, name in reached:
        keys |= _env_keys_read(units[(mod, name)], consts[mod])
    return keys, reached


def test_shipped_env_scan_is_not_vacuous():
    """守卫的守卫：闭包解析一坏，下面那条会静默变成空转。

    三个键各验一段传递：`API_KEYS_TABLE` 是 `api.py → keystore.list_keys →
    keystore._table`（跨模块再进模块内私有函数）；`OPS_LOG_TABLE` 是
    `permissions → ops_log.record → ops_log._table`（两个复制模块之间的传递）；
    `EDGE_ROLE_ID` 只以模块级常量的形态出现（见 `_env_keys_read`）。
    单元名也一起断言：只看键集时，"闭包没走到但别处读了同名键"也会绿。
    """
    keys, reached = _reachable_env_reads()
    assert {"API_KEYS_TABLE", "OPS_LOG_TABLE", "EDGE_ROLE_ID"} <= keys, (
        f"环境变量闭包解析坏了，读不到复制模块的键: {sorted(keys)}")
    assert {("keystore", "_table"), ("ops_log", "_table"),
            ("edge_caller", "caller_is_edge")} <= reached, (
        "可达性闭包没走进复制模块的私有函数——解析口径坏了")


def _assert_env_covers_every_read(env_override=None):
    """代码里 os.environ[...] 读到的键必须都在环境变量里下发。

    少一个的症状是运行时 KeyError → 500，而单测有 conftest 兜着看不出来。

    扫描范围是**整个进包清单**（panel 自己的 `*.py` + COPY_FILES 复制进来的），
    按可达性归属——理由见上面那段注释，别改回只 glob `panel/*.py`。

    3c-final 起**没有任何条件豁免**：旧版本对 `JWT_SECRET_PARAM` 有一条（legacy 关闭时那个读
    根本不发生），而那条豁免本身就得再配一个正对照才不至于放水。现在那个键连代码里都没有了，
    豁免与它的正对照一起删掉，只留下面那条"少下发一个必需键必须真的红"的元用例。
    """
    env = set(dp.lambda_environment()) if env_override is None else set(env_override)
    read, _ = _reachable_env_reads()
    # AWS 运行时自带的
    read -= {"AWS_DEFAULT_REGION", "AWS_REGION", "AWS_LAMBDA_FUNCTION_NAME"}
    missing = read - env
    assert not missing, f"代码会读但部署没下发的环境变量: {sorted(missing)}"


def test_environment_covers_every_env_var_the_code_reads():
    """线上配置下的实测（判定体在 `_assert_env_covers_every_read`，正对照复用**同一份**）。"""
    _assert_env_covers_every_read()


def test_environment_key_set_is_exactly_this(monkeypatch):
    """**精确**键集快照——上面那条只查"读到的都下发了"，多下发一个它看不见。

    3c-final 删掉的三个（`JWT_SECRET_PARAM` / `LEGACY_ENTRY` / `SESSION_SIGNER`）就靠这条挡回来：
    多下发一个键不会让任何东西 500，所以只有精确集合能发现"删了代码但 env 里还留着"。
    """
    assert set(dp.lambda_environment("AROATEST")) == {
        "ACCESS_DAILY_TABLE", "ACCESS_EVENTS_TABLE", "ADMINS_TABLE", "API_KEYS_TABLE",
        "BASE_DOMAIN", "CONSOLE_HOST", "EDGE_ROLE_ID", "JOBS_TABLE", "OPS_LOG_TABLE",
        "ROUTING_TABLE", "SESSION_CODES_TABLE", "SESSION_KEYS_JSON", "SITES_TABLE",
        "UNDEPLOY_FN"}


def test_env_coverage_still_catches_a_missing_var():
    """**元用例**：上一条真的会红。

    实现上必须调用被守护的那个函数本身（3c-1B ticket 17 第 12 条）：自己重算一遍判据的
    "正对照"在判据被放水时照样绿。这里拿掉一个**确实被读**的键，覆盖检查必须指名道姓地抛。
    """
    read, _ = _reachable_env_reads()
    victim = "SESSION_KEYS_JSON"
    assert victim in read, f"锚点失效：代码已经不读 {victim} 了"
    with pytest.raises(AssertionError, match=victim):
        _assert_env_covers_every_read(env_override=set(dp.lambda_environment()) - {victim})


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


def test_skip_frontend_must_not_move_route_to_an_unuploaded_prefix():
    """`--skip-frontend` 时 route 必须**保留线上前缀**，不能指向未上传的对象。

    2026-08-13 实测踩到的真机缺陷：前缀是**前端内容的指纹**，所以改过前端之后
    即使这次只部后端，`frontend_prefix()` 也算出一个新值；而 `--skip-frontend`
    跳过了上传，于是 route 指向一个从未上传过的前缀 → 控制台整站 403/404，
    而部署脚本全程打印"成功"。是 verify_deployed_components ⑦ 段的"首页对象存在"
    抓出来的。

    这里锁两件事：`register_route` 接受 `static_prefix` 覆盖；传了就用它，
    不传就用按内容指纹算的那个（正常全量部署的语义）。
    """
    import inspect
    sig = inspect.signature(dp.register_route)
    assert "static_prefix" in sig.parameters, (
        "register_route 没有 static_prefix 参数——--skip-frontend 就只能把 route "
        "挪到新算出来的前缀上，而那个前缀没有对象")
    assert sig.parameters["static_prefix"].default is None, (
        "static_prefix 默认值必须是 None（= 用内容指纹算出的新前缀）")

    captured = {}
    dp.console_route_item  # 触发属性存在性
    item = dp.console_route_item("https://example.invalid")
    assert item["static_prefix"] == dp.frontend_prefix(), (
        "默认路径应当用内容指纹前缀")
    # 覆盖路径：模拟 --skip-frontend 保留线上旧前缀
    import boto3
    real = boto3.resource

    class _T:
        def put_item(self, Item):
            captured.update(Item)

    class _R:
        def Table(self, _name):
            return _T()

    boto3.resource = lambda *a, **k: _R()
    try:
        dp.register_route("https://example.invalid",
                          static_prefix="platform/console/OLD")
    finally:
        boto3.resource = real
    assert captured["static_prefix"] == "platform/console/OLD", (
        f"传了 static_prefix 却没生效: {captured.get('static_prefix')}")


def _login_flow_param():
    return _live_keys().login_flow_secret_param


def test_panel_environment_has_no_login_flow_secret_param():
    env = dp.lambda_environment()
    assert "LOGIN_FLOW_SECRET_PARAM" not in env, "panel 拿到了 auth 私有的 login-flow 参数名"
    assert not any("login-flow" in str(v) for v in env.values()), \
        f"panel 的环境变量里出现了 login-flow 参数路径：{env}"


def test_panel_role_cannot_read_the_login_flow_secret():
    param = _login_flow_param()
    for st in dp.role_statements():
        for res in _resources(st):
            assert param not in res, f"panel role 能读 login-flow secret：{res}"


# ── 3c-final：panel 产物交叉装 cryptography（ADR 0003 / plan D4）────────────────────
#
# panel 是升级码与面板会话的 verifier，RS256 验签必须在本地做（每请求 kms:Verify 的代价见 D4），
# 所以 zip 里要有 cryptography。三包的版本与 hash **与 auth 清单逐字节相同**——两份分叉的症状是
# "auth 签出来的 token panel 验不过"，而那要等真机才看得见。

def test_copy_files_include_the_kms_module_and_the_zip_vendors_cryptography():
    """`_build_zip` 里那条 pip install 的开关——**按 AST 判 argv，不按源码文本**。

    源码文本 substring 是个假守卫：那段源码含注释，我为解释这几个开关写的注释自己就能满足断言
    （auth 那份清单守卫记着这次实测：把 `"--require-hashes",` 从 argv 里整条删掉，四条测试照样
    全绿）。这里解析 `subprocess.run(...)` 第一个实参里的字符串字面量——注释进不了 AST。
    `--python-version` 的值由 `RUNTIME` 推导（不是字面量），所以那一项断言落在 `dp.RUNTIME` 上；
    真正"开关到达 pip"的判据在 `auth/tests/test_requirements_locked.py::
    test_deploy_panel_installs_with_require_hashes`（截获真实 argv）。
    """
    assert "session_kms.py" in dp.COPY_FILES
    tree = ast.parse((PANEL / "deploy_panel.py").read_text())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_build_zip")
    runs = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "run"]
    assert len(runs) == 1, f"_build_zip 里应恰好一条 subprocess.run，实际 {len(runs)}"
    argv = runs[0].args[0]
    literals = [e.value for e in argv.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    for flag in ("--require-hashes", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                 "--python-version", "-r", "-t"):
        assert flag in literals, (flag, literals)
    assert dp.RUNTIME == "python3.13", dp.RUNTIME
    # 清单路径是 REQUIREMENTS（真源常量），且它就是 panel 自己那份
    assert any(isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "str"
               and isinstance(e.args[0], ast.Name) and e.args[0].id == "REQUIREMENTS"
               for e in argv.elts), "pip 的清单不是 REQUIREMENTS 常量"
    assert dp.REQUIREMENTS == PANEL / "requirements.txt" and dp.REQUIREMENTS.exists()


def test_panel_requirements_pin_the_same_cryptography_closure_as_auth():
    def pins(p):
        return dict(re.findall(r"^([a-zA-Z0-9_-]+)==([^ \\]+)", p.read_text(), re.M))
    panel, auth = pins(PANEL / "requirements.txt"), pins(PANEL.parent / "auth" / "requirements.txt")
    assert set(panel) == {"cffi", "cryptography", "pycparser"}
    assert all(auth[k] == vv for k, vv in panel.items()), (panel, {k: auth.get(k) for k in panel})


def test_panel_requirements_hashes_are_byte_identical_to_the_auth_lockfile():
    """版本相同还不够——**hash 集合**才是"装出来的是同一个 wheel"的判据。

    只比 `==` 版本时，panel 清单里少列一个平台的 hash 就会在 pip 的 tag 优先级随版本变化那天
    构建失败（auth 清单头部记着这个坑），而"两份一致"这条断言照样绿。
    """
    def blocks(p):
        out, cur = {}, None
        for line in p.read_text().splitlines():
            m = re.match(r"^([a-zA-Z0-9_-]+)==", line)
            if m:
                cur = m.group(1)
                out[cur] = []
            elif cur and line.strip().startswith("--hash="):
                out[cur].append(line.strip().rstrip(" \\"))
        return out
    panel, auth = blocks(PANEL / "requirements.txt"), blocks(PANEL.parent / "auth" / "requirements.txt")
    assert set(panel) == {"cffi", "cryptography", "pycparser"}
    for name, hashes in panel.items():
        assert hashes, f"{name} 一条 hash 都没有"
        assert hashes == auth[name], f"{name} 的 hash 集合与 auth 清单不同"


def test_required_parameters_is_empty_and_precheck_hits_kms(monkeypatch):
    """3c-final：panel 不读 SSM ⇒ 写前核对的对象只剩 KMS 那四项（session_kms.precheck_keys）。"""
    assert dp.required_parameters() == []
    kms = v.FakeKms()
    monkeypatch.setattr(dp, "_kms", lambda: kms)
    dp.precheck()
    assert {c[1] for c in kms.calls if c[0] == "describe_key"} == {v.KEY_ARN[v.CONSOLE_KID]}


def test_precheck_refuses_a_key_whose_fingerprint_is_not_the_configured_one(monkeypatch):
    """负对照：指纹不符必须 SystemExit（写前拒绝），不是"记个日志继续部"。"""
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    monkeypatch.setattr(dp, "_kms", lambda: kms)
    with pytest.raises(SystemExit, match=v.CONSOLE_KID):
        dp.precheck()


# ── ADR 0002：管理员名单里不许有夹具域邮箱 ─────────────────────────────────
#
# 夹具会话能到 console（Edge 放行平台路由），所以"夹具身份永不是管理员"这条必须由**数据层**保证。
# permissions.add_admin 已经拒（Task 9），本条是部署期的第二道：existing 名单被手工污染过时，
# 下一次部署就停下来——**在任何写之前**。

def test_deploy_refuses_a_fixture_domain_admin_seed_or_admin_row(aws, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    dp.assert_no_fixture_admins(ddb, "site-admins", "ops@example.test")        # 干净：不抛
    with pytest.raises(SystemExit, match="e2e.invalid"):
        dp.assert_no_fixture_admins(ddb, "site-admins", "probe@e2e.invalid")
    ddb.put_item(TableName="site-admins", Item={"email": {"S": "x@e2e.invalid"}})
    with pytest.raises(SystemExit, match="e2e.invalid"):
        dp.assert_no_fixture_admins(ddb, "site-admins", "ops@example.test")


# `main()` 里的调用顺序（precheck → assert_no_fixture_admins → 第一个写助手）由
# `test_deploy_panel_sequence.py::test_main_source_calls_precheck_before_every_write_helper` 守。


# ---- M07：Function URL 的 resource policy 走共享的等值收敛 -------------------------------------------
#
# 三条：① 实现是共享的那一份（`function_url_statements` / `converge_function_url_policy` / `FUNCTION_URL_AUTH_TYPE`
# 都从 function_url_policy 来）；② 本脚本里不再有任何 add_permission / remove_permission；③ ensure_function
# 恰好调用一次 converge，实参是 (lam, FN_NAME, 配置里的 edge_role_arn)。converge 自身的行为在
# deployer/tests/test_function_url_policy.py。evidence: fake/unit。

import function_url_policy as fup


def test_deploy_panel_binds_the_shared_function_url_policy_implementation():
    assert dp.function_url_statements is fup.expected_statements
    assert dp.converge_function_url_policy is fup.converge
    assert dp.FUNCTION_URL_AUTH_TYPE is fup.FUNCTION_URL_AUTH_TYPE
    src = (PANEL / "deploy_panel.py").read_text()
    assert "def function_url_statements" not in src, "本脚本又长出了第二份语句定义"


def test_deploy_panel_has_no_direct_permission_calls():
    """"同名 StatementId 已存在就 pass"回来的唯一途径就是有人在这里又写一遍 add_permission。"""
    tree = ast.parse((PANEL / "deploy_panel.py").read_text())
    direct = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("add_permission", "remove_permission")}
    assert direct == set(), direct


def test_ensure_function_converges_the_policy_once_for_the_configured_edge_role(monkeypatch):
    from unittest.mock import MagicMock
    lam = MagicMock()
    for name in ("ResourceNotFoundException", "ResourceConflictException", "InvalidParameterValueException"):
        setattr(lam.exceptions, name, type(name, (Exception,), {}))
    lam.get_function_url_config.return_value = {"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/",
                                                "AuthType": "AWS_IAM"}
    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: lam)
    monkeypatch.setattr(dp, "_region", lambda: "us-east-1")
    monkeypatch.setattr(dp, "lambda_environment", lambda eid: {})
    monkeypatch.setattr(dp, "_cfg", lambda section, key, default=None:
                        {("Deployer", "edge_role_arn"): EDGE_ROLE}.get((section, key), default or ""))
    calls = []
    monkeypatch.setattr(dp, "converge_function_url_policy",
                        lambda client, fn, arn: calls.append((client, fn, arn)) or fup.Drift())
    dp.ensure_function("arn:aws:iam::000000000000:role/site-panel-role", b"zip", "AROAEXAMPLE")
    assert calls == [(lam, dp.FN_NAME, EDGE_ROLE)]
