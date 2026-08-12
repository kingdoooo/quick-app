"""panel 的 Key 端点与 admin 开关（二期 M4，spec §4.4 / §5.1）。

三条性质是本文件存在的理由，其余用例都是围着它们的护栏：
  ① **明文只出现一次**——创建响应里。列表、日志、异常文案、审计里都不能有；
  ② **响应绝不含 `key_hash`**——它是这张表唯一值得保护的字段（库被读走时
     攻击者只拿到哈希），出口收在 `api._shape_key` 一个函数里，AST 锁定；
  ③ **"不是你的"与"不存在"必须同一句话**——能区分就是 key_id 枚举探测器
     （8 位 base62）。

**表访问全部经 keystore**（同 panel 对 sites 表"只走 permissions.py"的既有
约束）：本文件末尾的结构组用 AST 锁定 panel 不直接碰 `site-api-keys`、
也不直接调 `keygen`。
"""
import ast
import json
import logging
from pathlib import Path

import boto3
import pytest

import api
import common
import keygen
import keystore
import permissions

PANEL = Path(__file__).parents[1]
ADMIN = "boss@x.com"
ME = "owner@x.com"
OTHER = "other@x.com"


# ------------------------------------------------------------------ 夹具工具

def _keys_table():
    return boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys")


def _put_switch(enabled=True):
    """直写哨兵行（模拟"组件已部署"）。

    刻意不用 `keystore.set_switch`：那条路径要 admin 且会落审计，用它做夹具会
    让"改开关落 ops_log"那条用例分不清审计来自被测动作还是来自夹具。
    """
    _keys_table().put_item(Item={"key_hash": keygen.SWITCH_PK,
                                 "enabled": enabled,
                                 "updated_at": "2026-08-11T00:00:00+00:00",
                                 "updated_by": "seed"})


def _ops_rows() -> list[dict]:
    return common._table("OPS_LOG_TABLE").scan().get("Items", [])


def _write_spy(monkeypatch) -> list:
    """记录本进程对 api-keys 表的所有写调用（用于"被拒时零写"断言）。

    盯的是 boto3 层而不是业务结果：结果没变也可能是写了又被改回来。
    """
    seen = []
    real = boto3.resource

    class TableSpy:
        def __init__(self, inner, name):
            self._i, self._n = inner, name

        def __getattr__(self, k):
            if k in ("put_item", "update_item", "delete_item"):
                seen.append((self._n, k))
            return getattr(self._i, k)

    class ResSpy:
        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, k):
            return getattr(self._i, k)

        def Table(self, n):
            return TableSpy(self._i.Table(n), n)

    monkeypatch.setattr(boto3, "resource", lambda *a, **kw: ResSpy(real(*a, **kw)))
    # keystore / ops_log 缓存了 resource 句柄，必须清掉才会重新走上面的间谍
    monkeypatch.setattr(keystore, "_ddb", None)
    import ops_log
    monkeypatch.setattr(ops_log, "_ddb", None)
    return seen


def _strings(obj) -> list[str]:
    """递归收集结构里的**全部字符串**（键与值都算）。

    为什么不用 `"key_hash" not in json.dumps(x)`：brief 明确要求逐 key 检查，
    平铺成一个字符串后嵌套结构（`{"meta": {"key_hash": ...}}`）与巧合子串
    都会把断言骗过去，而"值被换了个键名带出去"更是完全看不见。
    """
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out += _strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            out += _strings(v)
    else:
        out.append(str(obj))
    return out


def _keys_of(obj) -> set[str]:
    """递归收集结构里出现过的**全部字典键名**。"""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out |= _keys_of(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            out |= _keys_of(v)
    return out


def _assert_no_hash_anywhere(payload, plaintext: str) -> None:
    """结构里既不能有 `key_hash` 这个键，也不能有它的**值**（换个键名照样是泄漏）。"""
    assert "key_hash" not in _keys_of(payload), \
        f"响应里出现了 key_hash 键: {payload}"
    digest = keygen.hash_key(plaintext)
    for s in _strings(payload):
        assert digest not in s, f"响应里出现了 key_hash 的值（键名被换了）: {s}"


def _assert_no_plaintext_anywhere(payload, plaintext: str) -> None:
    for s in _strings(payload):
        assert plaintext not in s, f"响应里出现了明文: {s}"


# ------------------------------------------------------------------ 授权组

def test_revoking_someone_elses_key_is_denied_and_changes_nothing(aws):
    """别人的 key_id 吊销不了：`keyid-index` 查到行但 email 不匹配 → 403。"""
    victim = keystore.create(OTHER, name="victim")
    with pytest.raises(permissions.PermissionDenied):
        api.do_revoke_key(ME, key_id=victim["key_id"])
    # 文案一致不等于没生效——必须核对那把 Key 仍然有效
    rows = keystore.list_for(OTHER)
    assert [r for r in rows if r["key_id"] == victim["key_id"]][0]["revoked"] \
        is False


def test_missing_and_someone_elses_key_id_are_indistinguishable(aws):
    """不存在的 key_id 与别人的 key_id：**同一个异常类型、同一句话**。

    区分开就是枚举探测器。这里连异常类型都要一致——只对齐文案而分别抛
    PermissionDenied / KeystoreError 时，HTTP 状态码（403 vs 500）就把两者
    区分开了，而调用方看到的正是状态码。
    """
    victim = keystore.create(OTHER, name="victim")
    with pytest.raises(Exception) as other:
        api.do_revoke_key(ME, key_id=victim["key_id"])
    with pytest.raises(Exception) as missing:
        api.do_revoke_key(ME, key_id="zzzzzzzz")
    assert type(other.value) is type(missing.value), (
        f"两种情形抛了不同异常: {type(other.value)} vs {type(missing.value)}")
    assert str(other.value) == str(missing.value)
    # 且必须是 403 那一类（500 会把"服务故障"与"没权限"混为一谈）
    assert isinstance(other.value, permissions.PermissionDenied)
    # 文案里不得出现能分辨存在性的词
    assert "不属于" in str(other.value) or "不存在" in str(other.value)


def test_i_can_revoke_my_own_key(aws):
    """反面：别把 revoke 写成"永远拒绝"（那样上面两条也全绿，但功能没了）。"""
    mine = keystore.create(ME, name="mine")
    assert api.do_revoke_key(ME, key_id=mine["key_id"])["revoked"] is True
    assert keystore.list_for(ME)[0]["revoked"] is True


def test_revoke_response_carries_nothing_but_the_outcome(aws):
    """吊销响应的键集是**恰好**两个：它不经 `_shape_key`（返回的不是行），
    所以这里直接把形态钉死——将来 keystore.revoke 改成回整行时本条会红。"""
    mine = keystore.create(ME, name="mine")
    out = api.do_revoke_key(ME, key_id=mine["key_id"])
    assert set(out) == {"key_id", "revoked"}, out
    _assert_no_hash_anywhere(out, mine["plaintext"])
    _assert_no_plaintext_anywhere(out, mine["plaintext"])


def test_switch_read_and_write_require_admin(aws, monkeypatch):
    """非 admin 读/写开关一律 PermissionDenied，且写路径**零副作用**。"""
    _put_switch(False)
    seen = _write_spy(monkeypatch)
    with pytest.raises(permissions.PermissionDenied):
        api.do_get_key_switch(ME)
    with pytest.raises(permissions.PermissionDenied):
        api.do_set_key_switch(ME, enabled=True)
    assert seen == [], f"非 admin 被拒却发生了写: {seen}"
    assert _keys_table().get_item(
        Key={"key_hash": keygen.SWITCH_PK})["Item"]["enabled"] is False


def test_admin_can_read_and_write_the_switch(aws):
    permissions.add_admin(ADMIN, "seed")
    _put_switch(False)
    assert api.do_get_key_switch(ADMIN) == {"deployed": True, "enabled": False}
    assert api.do_set_key_switch(ADMIN, enabled=True)["enabled"] is True
    assert api.do_get_key_switch(ADMIN)["enabled"] is True


def test_list_keys_only_returns_my_own(aws):
    keystore.create(ME, name="mine")
    keystore.create(OTHER, name="theirs")
    mine = api.do_list_keys(ME)["keys"]
    assert [k["name"] for k in mine] == ["mine"]


def test_switch_sentinel_row_never_appears_in_anyones_list(aws):
    """哨兵行不得冒进任何人的 Key 列表（Task 3 有 GSI 层断言，这里是 API 层）。

    API 层看不到 key_hash，所以判据是"每一项都有非空 key_id"——哨兵行没有
    key_id 属性，一旦它进了列表就会以 `key_id == ""` 的形态露出来。
    """
    _put_switch(True)
    keystore.create(ME, name="mine")
    keys = api.do_list_keys(ME)["keys"]
    assert len(keys) == 1, f"列表里多了东西: {keys}"
    assert all(k["key_id"] and k["prefix"] for k in keys), keys
    # 没有任何 Key 的人也看不到它
    assert api.do_list_keys(OTHER) == {"keys": []}


# ------------------------------------------------------------------ 泄漏组

def test_list_items_never_contain_key_hash(aws):
    """**逐 key 检查每一项**，不是在平铺的 JSON 里找子串。"""
    k = keystore.create(ME, name="mine")
    out = api.do_list_keys(ME)
    for item in out["keys"]:
        assert "key_hash" not in item, f"列表项含 key_hash: {item}"
    _assert_no_hash_anywhere(out, k["plaintext"])


def test_create_returns_plaintext_but_list_never_does(aws):
    out = api.do_create_key(ME, name="笔记本")
    assert out["plaintext"].startswith("sk-"), out
    _assert_no_hash_anywhere(out, out["plaintext"])
    listed = api.do_list_keys(ME)
    assert all("plaintext" not in item for item in listed["keys"]), listed
    _assert_no_hash_anywhere(listed, out["plaintext"])


def test_plaintext_does_not_appear_in_any_list_field(aws):
    """创建后再列表：明文不得出现在**任何**字段里（包括 name / prefix）。"""
    out = api.do_create_key(ME, name="笔记本")
    plaintext = out["plaintext"]
    listed = api.do_list_keys(ME)
    _assert_no_plaintext_anywhere(listed, plaintext)
    _assert_no_hash_anywhere(listed, plaintext)
    # prefix 是明文的前 7 个字符，**这是有意的展示值**（spec §4.3）：
    # 断言它确实只有前缀那么长，别把整条明文当"前缀"存了。
    assert len(listed["keys"][0]["prefix"]) == 3 + keygen.PREFIX_RANDOM_LEN
    assert plaintext.startswith(listed["keys"][0]["prefix"])


# 本项目自己的 logger（含 handler.py 用的根 logger）。**不含 botocore**——
# 见下面那条用例的注释：它的 DEBUG 会 dump 每个 DynamoDB 请求体。
OUR_LOGGERS = {"root", "api", "handler", "keystore", "ops_log", "permissions",
               "console_session", "keygen", "edge_caller"}


def _our_log_text(caplog) -> str:
    parts = []
    for r in caplog.records:
        if r.name.split(".")[0] not in OUR_LOGGERS:
            continue
        parts.append(r.getMessage())
        if r.exc_info:
            parts.append(logging.Formatter().formatException(r.exc_info))
    return "\n".join(parts)


def test_plaintext_never_reaches_logs_or_the_audit_trail(aws, caplog):
    """caplog 与 ops_log 里都不出现明文；审计记的是 `key_id`。

    **只把自己的 logger 开到 DEBUG**：`caplog.set_level(DEBUG)` 不带 logger 名
    会把**根** logger 打开，于是 botocore 的 DEBUG 把每个 DynamoDB 请求体原样
    dump 进来——那里面合法地含 key_hash（PutItem 的 Item 就是它），断言随即变成
    在检查 AWS SDK 的线缆日志而不是我们的代码。实测：第一版因此假红。

    过滤之后有个新风险——如果一个字都没抓到，"没出现明文"就成了空转。所以
    先用 canary 证明这条通道真的能看到本项目 logger 的输出（本项目反复出现的
    假绿形态就是"闸门只覆盖它自己夹具造出来的那个世界"）。
    """
    for name in sorted(OUR_LOGGERS):
        caplog.set_level(logging.DEBUG, logger="" if name == "root" else name)
    permissions.add_admin(ADMIN, "seed")
    out = api.do_create_key(ME, name="笔记本")
    plaintext = out["plaintext"]
    api.do_list_keys(ME)
    api.do_revoke_key(ME, key_id=out["key_id"])
    api.do_set_key_switch(ADMIN, enabled=True)

    api.logger.info("canary-%s", out["key_id"])
    keystore.logger.info("canary-%s", out["key_id"])
    ours = _our_log_text(caplog)
    assert ours.count(f"canary-{out['key_id']}") == 2, (
        "抓不到本项目 logger 的输出——下面两条断言是空转，"
        f"抓到的是: {sorted({r.name for r in caplog.records})}")

    assert plaintext not in ours, "明文进了日志"
    assert keygen.hash_key(plaintext) not in ours, "key_hash 进了日志"
    rows = _ops_rows()
    assert rows, "一条审计都没有——本用例什么都没验"
    blob = json.dumps(rows, default=str, ensure_ascii=False)
    assert plaintext not in blob, "明文进了审计"
    assert keygen.hash_key(plaintext) not in blob, "key_hash 进了审计"
    # 正面：创建那条审计必须能定位到这把 Key（记 key_id）
    create_rows = [r for r in rows if "create" in str(r.get("action", ""))]
    assert create_rows, f"没有创建审计: {rows}"
    assert any(out["key_id"] in str(r.get("detail", "")) for r in create_rows), (
        f"创建审计里没有 key_id，出问题时无从定位是哪把 Key: {create_rows}")


def test_the_funnel_drops_every_field_it_does_not_know(aws, monkeypatch):
    """行为层的出口断言：库里多出来的字段一律不出网。

    为什么不能只靠 AST：AST 证明"调用了 `_shape_key`"，证明不了它**挡住了**
    什么。这里给一行塞上 key_hash 与一个未来才会有的内部字段，断言响应的键集
    恰好是 `_shape_key` 白名单里的那些——**期望集从 `_shape_key` 自己推导**，
    不手抄第二份。
    """
    expected = set(api._shape_key({}))
    assert "key_hash" not in expected, "白名单自己就带了 key_hash"
    monkeypatch.setattr(keystore, "list_for", lambda email: [{
        "key_id": "abcd1234", "email": email, "name": "n", "prefix": "sk-abcd",
        "created_at": "2026-08-11T00:00:00+00:00", "last_used_at": "",
        "revoked": False,
        "key_hash": "f" * 64, "internal_future_field": "leak-me"}])
    for item in api.do_list_keys(ME)["keys"]:
        assert set(item) == expected, f"出口没有收口: {sorted(item)}"


# ---- `_shape_key` 是唯一出口（AST）----------------------------------------

# 取原始行的那两个入口。任何"从库里拿到的行"都只能经 `_shape_key` 出网。
RAW_SOURCES = {"create", "list_for"}
# 允许直接从原始行取的字段：只有明文，且只在创建路径上（它进不了 `_shape_key`，
# 因为那个形态是列表与创建共用的——见 api._shape_key 的注释）。
ALLOWED_RAW_FIELDS = {"plaintext"}
FUNNEL = "_shape_key"
KEY_ENDPOINTS = ("do_list_keys", "do_create_key")


def _api_tree():
    src = (PANEL / "api.py").read_text()
    return ast.parse(src), src


def _parent_map(tree):
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def _is_raw_source(node) -> bool:
    """`keystore.create(...)` / `keystore.list_for(...)`。"""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in RAW_SOURCES
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "keystore")


def _is_funnel_call(node) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == FUNNEL)


def test_shape_key_is_the_only_exit_for_key_rows(aws):
    """每一条返回 Key 数据的路径都必须经 `_shape_key`。

    做法不是"函数里出现过 `_shape_key` 就算过"（那样
    `return {"keys": keystore.list_for(e), "x": _shape_key(r)}` 也能蒙过去），
    而是**跟着原始行走**：
      · 每个 `keystore.create/list_for(...)` 调用只能落在赋值、推导式的 `iter`、
        或直接作为 `_shape_key(...)` 的实参上；
      · 每个持有原始行的变量只能出现在 `_shape_key(...)` 的实参里，或者被下标
        取白名单字段（只有 `plaintext`）。
    其余形态一律违规——包括"复制一份 row 再删几个键"这种看着无害的写法。
    """
    tree, src = _api_tree()
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for name in KEY_ENDPOINTS:
        assert name in fns, f"缺少端点 {name}——本用例会变成空转"
    assert FUNNEL in fns, f"没有 {FUNNEL} 函数"

    checked = 0
    for name in KEY_ENDPOINTS:
        fn = fns[name]
        parents = _parent_map(fn)
        raw_vars, raw_calls = set(), []
        for node in ast.walk(fn):
            if not _is_raw_source(node):
                continue
            raw_calls.append(node)
            parent = parents.get(node)
            if isinstance(parent, ast.Assign):
                for t in parent.targets:
                    if isinstance(t, ast.Name):
                        raw_vars.add(t.id)
            elif isinstance(parent, ast.comprehension):
                if isinstance(parent.target, ast.Name):
                    raw_vars.add(parent.target.id)
            elif _is_funnel_call(parent):
                pass            # 直接喂给出口，最干净的形态
            else:
                raise AssertionError(
                    f"{name}: keystore 的原始行流向了 {type(parent).__name__}"
                    f"——只能经 {FUNNEL} 出网：{ast.unparse(node)}")
        assert raw_calls, (
            f"{name} 里找不到 keystore.create/list_for 调用——"
            "取行的形态变了，本用例已经变成空转，必须同步更新")
        assert any(_is_funnel_call(n) for n in ast.walk(fn)), \
            f"{name} 没有调用 {FUNNEL}"

        for node in ast.walk(fn):
            if not (isinstance(node, ast.Name) and node.id in raw_vars
                    and isinstance(node.ctx, ast.Load)):
                continue
            parent = parents.get(node)
            if _is_funnel_call(parent):
                continue
            if isinstance(parent, ast.Subscript):
                field = getattr(parent.slice, "value", None)
                assert field in ALLOWED_RAW_FIELDS, (
                    f"{name}: 直接从原始行取了 {field!r}——"
                    f"除 {sorted(ALLOWED_RAW_FIELDS)} 外都必须经 {FUNNEL}")
                continue
            raise AssertionError(
                f"{name}: 原始行 {node.id!r} 被用在 "
                f"{type(parent).__name__} 上而没有经过 {FUNNEL}："
                f"{ast.unparse(parent)[:120]}")
        checked += 1
    assert checked == len(KEY_ENDPOINTS)


def test_shape_key_never_returns_key_hash(aws):
    """出口函数自身：不管喂进去什么，`key_hash` 都不能出来。"""
    out = api._shape_key({"key_hash": "f" * 64, "key_id": "abcd1234",
                          "email": ME, "name": "n", "prefix": "sk-abcd",
                          "created_at": "t", "last_used_at": "", "revoked": False})
    assert "key_hash" not in out
    assert "f" * 64 not in _strings(out)
    # email 也不必出网（调用方就是本人），但重点是 hash：这里只钉 hash
    assert out["revoked"] is False and isinstance(out["revoked"], bool)


# ------------------------------------------------------------------ 开关组

@pytest.mark.parametrize("bad", ["false", "0", "true", "", 0, 1, [], {},
                                 ["yes"], None])
def test_non_boolean_enabled_is_rejected_with_zero_writes(aws, monkeypatch, bad):
    """`bool("false") is True`——非布尔必须 ValueError（→400），且不落库。

    这是 `44aef8d`（P1-2）那个陷阱的同形：`{"enabled": "false"}` 被当成 True
    就是"以为关了其实开着"。显式 `null` 同样拒——那说明客户端表达了一个不是
    布尔的东西（通常是把 undefined 序列化进去了），报 400 能让 bug 当场暴露。
    """
    permissions.add_admin(ADMIN, "seed")
    _put_switch(False)
    seen = _write_spy(monkeypatch)
    with pytest.raises(ValueError):
        api.do_set_key_switch(ADMIN, enabled=bad)
    assert seen == [], f"enabled={bad!r} 被拒却写了库: {seen}"
    assert _keys_table().get_item(
        Key={"key_hash": keygen.SWITCH_PK})["Item"]["enabled"] is False


@pytest.mark.parametrize("good", [True, False])
def test_real_booleans_are_accepted(aws, good):
    """别把校验写成"什么都拒"——两个真布尔都必须放行并落库。"""
    permissions.add_admin(ADMIN, "seed")
    assert api.do_set_key_switch(ADMIN, enabled=good) == {"deployed": True,
                                                          "enabled": good}
    row = _keys_table().get_item(Key={"key_hash": keygen.SWITCH_PK})["Item"]
    assert row["enabled"] is good, f"落库的值形态不对: {row}"
    assert row["updated_by"] == ADMIN


def test_switch_change_is_audited_with_actor_and_direction(aws):
    """落 ops_log：`actor` 是操作者，`action` 能区分开闸与关闸。"""
    permissions.add_admin(ADMIN, "seed")
    api.do_set_key_switch(ADMIN, enabled=True)
    api.do_set_key_switch(ADMIN, enabled=False)
    rows = [r for r in _ops_rows() if "switch" in str(r.get("action", ""))]
    assert len(rows) == 2, f"开关审计不是两条: {rows}"
    assert {r["actor"] for r in rows} == {ADMIN}
    assert len({r["action"] for r in rows}) == 2, (
        f"开闸与关闸记成了同一个 action，审计分不出方向: {rows}")


def test_me_reports_deployed_true_even_when_the_switch_is_off(aws):
    """**部署自锁的闸门**（Codex P1-5）：哨兵行存在且 `enabled=false` 时，
    `do_me` 必须报 `deployed=true`，且 admin 仍能读写开关。

    首次部署强制把哨兵行建成关；若只有一个布尔、前端据它 disabled 且零请求，
    管理员就无处点开闸。按单布尔实现时本条必红。
    """
    permissions.add_admin(ADMIN, "seed")
    _put_switch(False)
    feat = api.do_me(ADMIN, "Boss")["features"]["api_key"]
    assert feat == {"deployed": True, "enabled": False}, feat
    # 同一状态下开关端点必须可用（这才是"已部署但关闸"的完整含义）
    assert api.do_get_key_switch(ADMIN)["deployed"] is True
    assert api.do_set_key_switch(ADMIN, enabled=True)["enabled"] is True


def test_me_reports_not_deployed_when_the_sentinel_row_is_missing(aws):
    feat = api.do_me(ME, "Owner")["features"]["api_key"]
    assert feat == {"deployed": False, "enabled": False}, feat


def test_me_features_are_real_booleans(aws):
    """前端按 `=== true` 判；Decimal / 字符串会让判定悄悄变成 falsy。"""
    _put_switch(True)
    feat = api.do_me(ME, "Owner")["features"]["api_key"]
    for k, v in feat.items():
        assert isinstance(v, bool), f"features.api_key.{k} 不是布尔: {v!r}"


def test_me_survives_an_unreachable_api_keys_table(aws, monkeypatch):
    """`/api/me` 是控制台的启动请求：Key 表读不出来时它**不能** 500。

    否则 M4 一没部署好（或表被限流），整个控制台连站点管理都打不开——
    把一个功能开关的故障放大成了全站故障。
    """
    def boom():
        raise RuntimeError("ResourceNotFoundException（注入）")
    monkeypatch.setattr(keystore, "switch_state", boom)
    me = api.do_me(ME, "Owner")
    assert me["features"]["api_key"] == {"deployed": False, "enabled": False}
    assert me["email"] == ME and me["is_admin"] is False


def test_switch_read_failure_is_not_disguised_as_not_deployed_for_admin(aws,
                                                                       monkeypatch):
    """admin 端点相反：读失败要抛出去（→500），不能报成"未部署"。

    报成未部署会让管理员以为平台没这功能而不再追查，而故障期间恰恰需要他能
    分辨"没部署"与"读不出来"。这条与上一条方向刻意相反，别"统一"它们。
    """
    permissions.add_admin(ADMIN, "seed")

    def boom():
        raise RuntimeError("throttled（注入）")
    monkeypatch.setattr(keystore, "switch_state", boom)
    with pytest.raises(RuntimeError):
        api.do_get_key_switch(ADMIN)


# ------------------------------------------------------------------ 创建组

@pytest.mark.parametrize("bad", ["", "   ", None, 123, [], "x" * 65])
def test_create_rejects_bad_name(aws, bad):
    with pytest.raises(ValueError):
        api.do_create_key(ME, name=bad)
    assert api.do_list_keys(ME) == {"keys": []}, "被拒的创建落库了"


def test_create_accepts_a_name_at_the_length_limit(aws):
    """上限是"不超过"而不是"小于"——边界值必须能用。"""
    out = api.do_create_key(ME, name="x" * keystore.NAME_MAX)
    assert out["name"] == "x" * keystore.NAME_MAX


def test_one_person_can_hold_multiple_keys(aws):
    a = api.do_create_key(ME, name="笔记本")
    b = api.do_create_key(ME, name="台式机")
    assert a["key_id"] != b["key_id"]
    assert a["plaintext"] != b["plaintext"]
    assert {k["name"] for k in api.do_list_keys(ME)["keys"]} == {"笔记本", "台式机"}


def test_created_row_has_the_expected_shape(aws):
    """落库的行：`key_id` / `email` / `prefix` / `created_at` 齐备，
    `revoked=False`，`last_used_at=""`。"""
    out = api.do_create_key(ME, name="笔记本")
    row = _keys_table().get_item(
        Key={"key_hash": keygen.hash_key(out["plaintext"])})["Item"]
    assert row["key_id"] == out["key_id"]
    assert row["email"] == ME
    assert row["prefix"] == out["prefix"]
    assert row["created_at"] and row["created_at"] == out["created_at"]
    assert row["revoked"] is False
    assert row["last_used_at"] == ""
    # 库里存的是哈希，**不是明文**（这张表被读走时攻击者只拿到哈希）
    assert out["plaintext"] not in _strings(row)


def test_created_key_is_immediately_listed_and_shaped(aws):
    out = api.do_create_key(ME, name="笔记本")
    listed = api.do_list_keys(ME)["keys"]
    assert len(listed) == 1
    assert set(listed[0]) == set(api._shape_key({}))
    assert listed[0]["key_id"] == out["key_id"]
    assert listed[0]["revoked"] is False


# ------------------------------------------------------------------ 结构组
# panel 只经 keystore 访问 api-keys 表（同它对 sites 表"只走 permissions.py"的
# 既有约束，见 test_no_handwritten_guards.py 的同类断言）。

def _panel_modules():
    return sorted(p for p in PANEL.glob("*.py") if p.name != "deploy_panel.py")


def test_panel_never_touches_the_api_keys_table_directly():
    """panel 的运行时模块里不得出现这张表的表名/环境变量。

    直连的后果不是"多一份代码"，而是把"哨兵行 enabled 必须是布尔 True"这条
    不变量抄成两份——写入侧写成字符串、读取侧按布尔判，症状是"控制台显示
    开着但所有 Key 都 401"，而两侧单测各自都绿（keystore 模块 docstring）。
    """
    assert _panel_modules(), "glob 空了——本用例是空转"
    for path in _panel_modules():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value != "API_KEYS_TABLE", (
                    f"{path.name} 自己读了 API_KEYS_TABLE——表访问必须经 keystore")
                assert node.value != "site-api-keys", (
                    f"{path.name} 出现了 api-keys 表名字面量")


def test_panel_never_calls_keygen_directly():
    """明文/哈希只在 `keystore.create` 里生成一次。

    panel 自己调 keygen 就意味着可能出现第二条"生成 Key"的路径——那条路径不会
    经过 keystore 的 key_id 唯一性重试与 `attribute_not_exists(key_hash)` 条件写。
    """
    for path in _panel_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name != "keygen" for a in node.names), \
                    f"{path.name} import 了 keygen"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "keygen", f"{path.name} from keygen import"
            elif (isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute)
                  and isinstance(node.func.value, ast.Name)
                  and node.func.value.id == "keygen"):
                raise AssertionError(
                    f"{path.name} 直接调 keygen.{node.func.attr}——"
                    "发 Key 只能走 keystore.create")
