"""keystore：开关 + Key 的单次强一致查询。

**核心不变量是"不缓存"**（spec §5.1：缓存了"即时吊销"就不成立）。
Lambda 的模块级变量跨请求存活，所以"没写缓存代码"不等于没缓存——
本文件有专门的行为用例（test_revocation_takes_effect_on_next_call 等）
把这一点钉住，test_no_module_level_cache.py 从结构上再钉一次。
"""
import pytest

import keygen
import keystore


def _put_switch(enabled=True):
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item={
            "key_hash": keygen.SWITCH_PK, "enabled": enabled,
            "updated_at": "2026-08-10T00:00:00+00:00", "updated_by": "seed"})


def _put_key(email="u@x.com", revoked=False, **extra):
    import boto3
    k = keygen.new_key()
    item = {"key_hash": k.key_hash, "key_id": k.key_id, "email": email,
            "name": "笔记本", "prefix": k.prefix, "revoked": revoked,
            "created_at": "2026-08-10T00:00:00+00:00", "last_used_at": ""}
    item.update(extra)
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item=item)
    return k


# ---------- happy path ----------

def test_valid_key_with_switch_on_resolves_email(aws):
    _put_switch(True)
    k = _put_key(email="alice@x.com")
    v = keystore.lookup(k.plaintext)
    assert v.ok and v.email == "alice@x.com" and v.key_id == k.key_id


# ---------- 开关优先于 Key ----------

def test_switch_off_rejects_even_a_valid_key(aws):
    _put_switch(False)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is False


def test_switch_off_does_not_write_last_used(aws, monkeypatch):
    """关闸期间不得产生任何写——否则审计看起来像"关闸没生效"。"""
    calls = []
    monkeypatch.setattr(keystore, "touch_last_used",
                        lambda *a, **kw: calls.append(a))
    _put_switch(False)
    k = _put_key()
    keystore.lookup(k.plaintext)
    assert calls == []


def test_switch_missing_row_rejects(aws):
    """哨兵行不存在 = 表刚建好还没部署 → 必须是关。"""
    _put_key()      # 有 Key，没有哨兵行
    assert keystore.lookup(_put_key().plaintext).ok is False


@pytest.mark.parametrize("bad", [None, "true", "True", 1, 0, "", [], {}])
def test_switch_non_boolean_true_rejects(aws, bad):
    """照 Edge require_auth 的既有形态：必须显式布尔 True。

    M3 实测过四种非布尔形态都能骗过 `if not x`（{"NULL":true}、
    {"N":"0"}、{"L":[]}、未识别类型），所以这里用 `is not True`。
    """
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").put_item(Item={"key_hash": keygen.SWITCH_PK,
                                        "enabled": bad})
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is False


def test_switch_read_failure_rejects(aws, monkeypatch):
    """读不到就不知道开关状态——此时放行等于开关形同虚设。

    **相对 brief 加强过（实施期实测）**：brief 原版查的是
    `lookup("sk-" + "a"*16)`，那把 Key **表里根本没有**。于是把"开关读失败就
    假定开着"这个缺陷注进去后，它照样绿——因为拒绝来自 `unknown-key`，与开关
    压根无关。这是一条"缺陷在场仍然通过"的闸门（本项目反复出现的形态）。
    现在用一把**有效的** Key，并断言 `reason`：只有开关那一侧真的 fail-closed
    才可能红。
    """
    _put_switch(True)           # 哨兵行是开的：拒绝只能来自"读失败"本身
    k = _put_key()

    def boom(*a, **kw):
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, "_get_switch_row", boom)
    v = keystore.lookup(k.plaintext)
    assert v.ok is False
    assert v.reason == "switch-read-failed", v.reason


def test_switch_read_failure_does_not_even_look_at_the_key(aws, monkeypatch):
    """开关读失败时**不查 Key**：不知道开关状态就该立刻停，别继续往下走。"""
    _put_switch(True)
    k = _put_key()
    key_reads = []
    rk = keystore._get_key_row
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: (key_reads.append(1), rk(*a, **kw))[1])

    def boom(*a, **kw):
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, "_get_switch_row", boom)
    assert keystore.lookup(k.plaintext).ok is False
    assert key_reads == [], "开关状态未知时仍查了 Key"


def test_key_read_failure_rejects(aws, monkeypatch):
    """开关读到了、Key 读失败 —— 同样必须拒（不能"开关是开的就放行"）。"""
    _put_switch(True)

    def boom(*a, **kw):
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, "_get_key_row", boom)
    assert keystore.lookup(_put_key().plaintext).ok is False


def test_neither_read_is_retried(aws, monkeypatch):
    """两个读都**不重试**：重试会把一次限流放大成多次，而转发本身有超时预算。

    **注意这条只覆盖成功路径**（每个读恰好一次）。真正的"重试"缺陷长在**失败**
    路径上——`except: 再读一次`，成功时那行代码根本不执行，本用例看不见它。
    实测确认过：给两个读各包一层 `except → 重读`，本用例仍然全绿。
    失败路径由下面 test_a_failed_read_is_not_retried 覆盖，两条缺一不可。
    """
    n = {"switch": 0, "key": 0}
    rs, rk = keystore._get_switch_row, keystore._get_key_row
    monkeypatch.setattr(keystore, "_get_switch_row",
                        lambda *a, **kw: (n.__setitem__("switch", n["switch"] + 1),
                                          rs(*a, **kw))[1])
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: (n.__setitem__("key", n["key"] + 1),
                                          rk(*a, **kw))[1])
    _put_switch(True)
    keystore.lookup(_put_key().plaintext)
    assert n == {"switch": 1, "key": 1}


@pytest.mark.parametrize("which", ["switch", "key"])
def test_a_failed_read_is_not_retried(aws, monkeypatch, which):
    """**读失败后不得再读一次**——这是"不重试"真正要防的形态。

    为什么单独一条（实施期实测发现的缺口）：上面那条在成功路径上数读次数，
    而 `except Exception: 再读一次` 只在抛异常时执行，成功路径上是死代码。
    把重试注入进去后上面那条**全绿**——所以这里直接让读抛异常再数次数。

    重试的危害是把一次限流放大成多次：DynamoDB 限流时每个请求都变两个请求，
    正好在最不该加压的时候加压，而转发侧本来就有超时预算兜着。
    """
    _put_switch(True)
    k = _put_key()
    n = {"switch": 0, "key": 0}

    def boom(*a, **kw):
        n[which] += 1
        raise RuntimeError("throttled")
    monkeypatch.setattr(keystore, f"_get_{which}_row", boom)
    assert keystore.lookup(k.plaintext).ok is False
    assert n[which] == 1, f"{which} 读失败后又读了 {n[which]} 次——不得重试"


# ---------- Key 侧的 fail-closed ----------

def test_unknown_key_rejects(aws):
    _put_switch(True)
    assert keystore.lookup(keygen.new_key().plaintext).ok is False


@pytest.mark.parametrize("revoked", [True, "true", 1, "yes", ["x"]])
def test_revoked_truthy_rejects(aws, revoked):
    """吊销侧方向与开关**相反**：只要像真就拒。两个方向都取最严。"""
    _put_switch(True)
    k = _put_key(revoked=revoked)
    assert keystore.lookup(k.plaintext).ok is False


@pytest.mark.parametrize("email", [None, "   ", "notanemail", "a@b"])
def test_dirty_email_rejects(aws, email):
    """脏数据不能变成"以空身份调用"——下游 _caller_email 会拿到空串。

    brief 的参数里还有 `""`，它**在这张表里写不进去**（email 是
    email-index 的分区键，DynamoDB 拒绝把索引键属性设成空串——实测报
    ValidationException，moto 与真机同行为）。为了不把"写不进去"混淆成
    "已经验过"，空串单独一条用例、用注入的方式覆盖，见下。
    """
    _put_switch(True)
    k = _put_key()
    import boto3
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    if email is None:
        t.update_item(Key={"key_hash": k.key_hash},
                      UpdateExpression="REMOVE email")
    else:
        t.update_item(Key={"key_hash": k.key_hash},
                      UpdateExpression="SET email = :e",
                      ExpressionAttributeValues={":e": email})
    assert keystore.lookup(k.plaintext).ok is False


@pytest.mark.parametrize("email", ["", 123, None, ["a@x.com"]])
def test_non_string_or_empty_email_rejects_by_injection(aws, monkeypatch, email):
    """空串与非字符串 email：**绕过表约束**直接注入行，验判定本身。

    为什么必须绕过：email 是 GSI 分区键，空串写不进去（见上一条）；非字符串
    形态（数字 / 列表）能写进 item 但写不进索引键，也一样被拒。于是"表拦住了"
    这件事会掩盖"判定有没有拦"——今天判定即使全删掉，上一条也照样绿。

    **表约束不能当判定用**：将来某次改动去掉 email-index（或换成 sparse 索引），
    约束就消失了，而那时判定必须仍然拦得住。这一条钉的是判定本身。
    """
    _put_switch(True)
    k = _put_key()
    row = {"key_hash": k.key_hash, "key_id": k.key_id, "revoked": False}
    if email is not None:
        row["email"] = email
    monkeypatch.setattr(keystore, "_get_key_row", lambda kh: row)
    v = keystore.lookup(k.plaintext)
    assert v.ok is False
    assert v.email == "", "拒绝时 email 必须是空串，否则下游可能拿它当身份"


@pytest.mark.parametrize("bad", ["", "sk-", "sk-short", "SK-" + "a" * 16,
                                "sk-" + "a" * 17, "sk_" + "a" * 16,
                                "sk-" + "a" * 15 + "-", "x" * 500])
def test_malformed_plaintext_rejects_without_db_read(aws, bad, monkeypatch):
    """形态不对时**不查库**：省一次读，也防止把任意长串当 key 去 hash。

    **2026-08-12 连开关读一起数（独立审查发现的盲区）**：原版只数 `_get_key_row`,
    于是把形态校验挪到**开关读之后**（`switch → 形态 → key`）仍然全绿——而不变量
    是"非法输入不产生任何一次库读"。开关读是一次真实的 DynamoDB 强一致读，且这条
    路径任何人都能免费触发（一串垃圾就够），少数一个入口就少一半覆盖。
    """
    reads = []
    monkeypatch.setattr(keystore, "_get_switch_row",
                        lambda *a, **kw: reads.append("switch") or {"enabled": True})
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: reads.append("key") or None)
    assert keystore.lookup(bad).ok is False
    assert reads == [], f"形态校验必须在任何一次库读之前，实际读了 {reads}"


# ---------- 不缓存（行为层） ----------

def test_revocation_takes_effect_on_next_call(aws):
    """**同一进程内**：第一次成功后吊销，第二次必须立刻失败。

    这是"禁止缓存 hash→email"的行为断言。加任何缓存都会让它变红。
    """
    _put_switch(True)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is True
    import boto3
    boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").update_item(
            Key={"key_hash": k.key_hash},
            UpdateExpression="SET revoked = :t",
            ExpressionAttributeValues={":t": True})
    assert keystore.lookup(k.plaintext).ok is False, \
        "吊销未即时生效——检查是否引入了缓存"


def test_switch_flip_takes_effect_on_next_call(aws):
    """开关同形：进程内翻转必须立刻生效。"""
    _put_switch(True)
    k = _put_key()
    assert keystore.lookup(k.plaintext).ok is True
    _put_switch(False)
    assert keystore.lookup(k.plaintext).ok is False, \
        "关闸未即时生效——检查是否缓存了开关"


def test_every_lookup_hits_the_database(aws, monkeypatch):
    """计数断言：N 次 lookup 必须有 N 次开关读 + N 次 Key 读。

    上面两条能抓住"永久缓存"，抓不住"带 TTL 的缓存"（TTL 内的第二次调用
    仍是旧值，但用例里两次调用间隔远小于 TTL 时也会红——不可靠）。
    这条直接数读次数，任何缓存都会让它红。
    """
    _put_switch(True)
    k = _put_key()
    n = {"switch": 0, "key": 0}
    rs, rk = keystore._get_switch_row, keystore._get_key_row

    def cs(*a, **kw):
        n["switch"] += 1
        return rs(*a, **kw)

    def ck(*a, **kw):
        n["key"] += 1
        return rk(*a, **kw)
    monkeypatch.setattr(keystore, "_get_switch_row", cs)
    monkeypatch.setattr(keystore, "_get_key_row", ck)
    for _ in range(5):
        keystore.lookup(k.plaintext)
    assert n == {"switch": 5, "key": 5}, f"存在缓存: {n}"


def test_both_reads_are_strongly_consistent(aws):
    """两个读都必须 ConsistentRead=True：最终一致读会留下"吊销后仍放行"、
    "关闸后仍放行"的窗口。

    断言方式：读 keystore 记录的最后一次请求参数（模块暴露
    LAST_READ_CONSISTENCY 供测试观察，它不是授权数据，见
    test_no_module_level_cache 的白名单说明）。
    """
    _put_switch(True)
    keystore.lookup(_put_key().plaintext)
    assert keystore.LAST_READ_CONSISTENCY == {"switch": True, "key": True}


def test_switch_is_read_before_key_and_short_circuits(aws, monkeypatch):
    """顺序断言：开关先读；关闸时**根本没有** Key 读。

    这条替代了原方案的"两者必须来自同一次 BatchGetItem"（Codex P2-6：
    BatchGetItem 不提供跨项原子快照，且一次 BatchGet 必然把 Key 行一起
    请求了——与"关闸时不查 Key"自相矛盾）。
    """
    order = []
    rs, rk = keystore._get_switch_row, keystore._get_key_row
    monkeypatch.setattr(keystore, "_get_switch_row",
                        lambda *a, **kw: (order.append("switch"), rs(*a, **kw))[1])
    monkeypatch.setattr(keystore, "_get_key_row",
                        lambda *a, **kw: (order.append("key"), rk(*a, **kw))[1])
    _put_switch(True)
    k = _put_key()
    keystore.lookup(k.plaintext)
    assert order == ["switch", "key"], "开关必须先读"
    order.clear()
    _put_switch(False)
    keystore.lookup(k.plaintext)
    assert order == ["switch"], f"关闸时仍查了 Key: {order}"


# ---------- key_id 唯一性（Codex P2-7）----------

def test_create_retries_on_key_id_collision(aws, monkeypatch):
    """GSI 不提供唯一约束，唯一性必须由创建路径保证。"""
    _put_switch(True)
    first = keystore.create("a@x.com", name="one")
    # 强迫下一次生成撞上已有的 key_id 一次，然后恢复随机
    seq = [first["key_id"]]
    real_new = keygen.new_key

    def rigged():
        k = real_new()
        return k._replace(key_id=seq.pop(0)) if seq else k
    monkeypatch.setattr(keygen, "new_key", rigged)
    second = keystore.create("b@x.com", name="two")
    assert second["key_id"] != first["key_id"], "碰撞未被检测与重试"


def test_revoke_fails_closed_when_index_returns_multiple_rows(aws, monkeypatch):
    """**≥2 行绝不能"取第一行删掉"**——那会误吊销别人的 Key。

    **相对 brief 加强过（实施期实测）**：brief 原版是 `pytest.raises(Exception)`。
    把缺陷（"多行时取第一行"）注进去后它**照样绿**——因为第一行的 email 恰好
    是调用者，`update_item` 打在一个不存在的 `key_hash="h1"` 上，条件
    `attribute_exists` 不成立 → 抛 `KeyNotFound`，也是 `Exception` 的子类。
    "抓到了异常"不等于"抓到了对的异常"。
    现在断言**具体异常类型**，并断言那两行**一个都没被改**（真实缺陷的危害是
    改错行，不是抛不抛）。
    """
    _put_switch(True)
    a = keystore.create("a@x.com", name="one")
    b = keystore.create("b@x.com", name="two")
    dup = a["key_id"]
    # 两行都真实存在，且**第一行属于调用者**——这正是"取第一行"最容易蒙过去的
    # 摆法：那样连 email 比对都能过，缺陷会静默把 a 的 Key 吊销掉。
    rows = [{"key_hash": keygen.hash_key(a["plaintext"]), "email": "a@x.com",
             "key_id": dup},
            {"key_hash": keygen.hash_key(b["plaintext"]), "email": "b@x.com",
             "key_id": dup}]
    monkeypatch.setattr(keystore, "_query_by_key_id", lambda kid: rows)
    with pytest.raises(keystore.AmbiguousKeyId):
        keystore.revoke(dup, actor="a@x.com")
    import boto3
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    for r in rows:
        got = t.get_item(Key={"key_hash": r["key_hash"]})["Item"]
        assert got["revoked"] is False, f"歧义未 fail-closed，{r['email']} 的 Key 被改了"


def test_revoke_of_someone_elses_key_is_indistinguishable_from_missing(aws):
    """吊销别人的 Key 与"不存在"必须是**同一个异常同一句话**。

    区分开就是枚举探测器：key_id 只有 8 位 base62，能区分"不是你的"与"不存在"
    就能拿它扫出别人的 key_id。同 permissions.require 对"站点不存在/无权访问"
    的既有处理。
    """
    _put_switch(True)
    victim = keystore.create("b@x.com", name="victim")
    with pytest.raises(keystore.KeyNotFound) as other:
        keystore.revoke(victim["key_id"], actor="a@x.com")
    with pytest.raises(keystore.KeyNotFound) as missing:
        keystore.revoke("zzzzzzzz", actor="a@x.com")
    assert str(other.value) == str(missing.value)
    # 且**真的没吊销**（文案一致不等于没生效）
    assert [k for k in keystore.list_for("b@x.com")
            if k["key_id"] == victim["key_id"]][0]["revoked"] is False


def test_revoke_marks_revoked_without_deleting_the_row(aws):
    """正常吊销：置 `revoked` 而**不删行**——删了就没有审计痕迹了。

    这条是上面两条 fail-closed 用例的反面。缺了它，把 revoke 写成"永远抛
    KeyNotFound"也能让那两条全绿（"什么都不做"总是安全的，但也没用）。
    """
    _put_switch(True)
    k = keystore.create("a@x.com", name="one")
    assert keystore.revoke(k["key_id"], actor="a@x.com")["revoked"] is True
    rows = keystore.list_for("a@x.com")
    assert len(rows) == 1, "行被删了——吊销必须保留审计痕迹"
    assert rows[0]["revoked"] is True
    # 吊销后立刻失效（与 test_revocation_takes_effect_on_next_call 同源，
    # 这里走的是真实的 revoke 路径而不是手写 update_item）
    assert keystore.lookup(k["plaintext"]).ok is False


def _condition_attribute_names(fn_name: str) -> set[str]:
    """`keystore.<fn_name>` 里每个 `update_item` 的条件表达式**实际断言的属性名**。

    取的是**值**而不是源码文本：解析 `ConditionExpression` 字面量，把 `#别名`
    经 `ExpressionAttributeNames` 解析回真实属性名，`:值占位符` 不算（它是被
    比较的那一侧，不是被断言的属性）。改名、换顺序、增删别名都跟得住。
    """
    import ast
    import pathlib
    import re
    src = pathlib.Path(keystore.__file__).read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == fn_name)
    calls = [n for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "update_item"]
    # 自查：找不到调用说明本守卫已与源码脱节（同 §2.10「分不清没找到与干净」）。
    assert calls, f"{fn_name} 里找不到 update_item 调用——先修本守卫"
    names = set()
    for call in calls:
        kw = {k.arg: k.value for k in call.keywords}
        assert "ConditionExpression" in kw, \
            f"{fn_name} 的 update_item 没有 ConditionExpression"
        try:
            expr = ast.literal_eval(kw["ConditionExpression"])
            alias = ast.literal_eval(kw["ExpressionAttributeNames"]) \
                if "ExpressionAttributeNames" in kw else {}
        except ValueError as e:      # 拼出来的（变量/f-string）——读不到值就红
            raise AssertionError(
                f"{fn_name} 的条件表达式不是字面量，本守卫读不到它的值: {e}") from e
        for tok in re.findall(r"(?<![:\w#])(#?[A-Za-z_][A-Za-z0-9_]*)", expr):
            if tok.startswith("#"):
                assert tok in alias, f"{tok} 没有对应的 ExpressionAttributeNames"
                names.add(alias[tok])
            else:
                names.add(tok)
    return names


def test_revoke_update_carries_key_id_and_email_condition(aws):
    """Query 与 Update 之间有窗口，且 GSI 是最终一致的——落地的那一步
    必须重新断言两个字段（同 sites_snapshot_guard 的既有理由）。

    **2026-08-12 重写：原版是假绿（独立审查发现，已实测确认）**。原版对
    `ast.get_source_segment(revoke)` 做 `"key_id" in body and "email" in body`
    子串检查，而 revoke 的 **docstring 本身**就把这两个词各写了好几次——于是把
    `ConditionExpression="#kid = :kid AND #em = :em"` 改成 `"#kid = :kid"`
    并删掉随之无用的 `#em` 别名与 `:em` 值（开发者真会这么改），53 条用例
    **全绿**；只有把 `ConditionExpression=` 整个删掉才会红，也就是计划恰好
    预测到的那一种形态。子串匹配源码永远有这个问题：注释与文档也在里面。
    现在断言解析后的属性名集合，行为面另有下面那条参数化用例。
    """
    assert {"key_id", "email"} <= _condition_attribute_names("revoke"), \
        "落地的 UpdateItem 必须同时重新断言 key_id 与 email"


@pytest.mark.parametrize("stale", ["email", "key_id"])
def test_revoke_fails_closed_when_the_index_projection_is_stale(
        aws, monkeypatch, stale):
    """上一条的**行为面**：GSI 给旧投影时一个字段都不能被改。

    摆法（这是唯一能让条件表达式成为**唯一**防线的摆法）：表里的真行属于
    b@x.com，而注入的"投影"声称它属于调用者 a@x.com（`stale="email"`）；或真行
    的 key_id 是别的值，投影声称它就是调用者要吊销的那一个（`stale="key_id"`）。
    两种摆法下 Query 之后的每一步判断都会通过——`len(rows)==1` 成立、
    `row["email"] == actor` 也成立——只有 UpdateItem 的条件能拦住它。
    少了 email 那半个条件，一次陈旧投影就等于"用别人的 Key 换自己的吊销"；
    少了 key_id 那半个，被改的会是同一行上完全另一把 Key。
    """
    _put_switch(True)
    victim = keystore.create("b@x.com", name="victim")
    key_hash = keygen.hash_key(victim["plaintext"])
    if stale == "email":
        # 真行 email=b@x.com，投影谎称 a@x.com；key_id 是真的。
        row = {"key_hash": key_hash, "email": "a@x.com",
               "key_id": victim["key_id"]}
        target = victim["key_id"]
    else:
        # 真行 key_id 是 victim 的，投影谎称是 "zzzzzzzz"；email 用真行的。
        row = {"key_hash": key_hash, "email": "b@x.com", "key_id": "zzzzzzzz"}
        target = "zzzzzzzz"
    actor = row["email"]
    monkeypatch.setattr(keystore, "_query_by_key_id", lambda kid: [row])
    with pytest.raises(keystore.KeyNotFound):
        keystore.revoke(target, actor=actor)
    import boto3
    got = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-api-keys").get_item(Key={"key_hash": key_hash})["Item"]
    assert got["revoked"] is False, \
        f"陈旧的 {stale} 投影让吊销落地了——UpdateItem 的条件没拦住"


# ---------- 哨兵行不得出现在 GSI ----------

def test_switch_row_never_appears_in_email_index(aws):
    """哨兵行没有 email/key_id 属性 → 天然不进 GSI（按人列 Key 时不出现）。

    **这条不是"显然成立"**：将来有人给哨兵行加个 email 字段（比如想记
    "谁改的"而误用 email 而不是 updated_by），它就会出现在某人的 Key 列表里。
    """
    import boto3
    _put_switch(True)
    _put_key(email="alice@x.com")
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    for idx, key, val in (("email-index", "email", "alice@x.com"),):
        rows = t.query(IndexName=idx,
                       KeyConditionExpression=boto3.dynamodb.conditions.Key(key).eq(val))["Items"]
        assert all(r["key_hash"] != keygen.SWITCH_PK for r in rows)
    # 全量扫 GSI 也不该有它
    assert all(r["key_hash"] != keygen.SWITCH_PK
               for r in t.scan(IndexName="email-index")["Items"])
    assert all(r["key_hash"] != keygen.SWITCH_PK
               for r in t.scan(IndexName="keyid-index")["Items"])


# ---------- last_used_at 节流 ----------

def test_touch_last_used_throttles_to_once_per_hour(aws):
    """每 Key 每小时至多一次写（spec §5.2）。"""
    _put_switch(True)
    k = _put_key()
    keystore.touch_last_used(k.key_hash, k.key_id)
    import boto3
    t = boto3.resource("dynamodb", region_name="us-east-1").Table("site-api-keys")
    first = t.get_item(Key={"key_hash": k.key_hash})["Item"]["last_used_at"]
    assert first
    keystore.touch_last_used(k.key_hash, k.key_id)      # 立刻再来一次
    second = t.get_item(Key={"key_hash": k.key_hash})["Item"]["last_used_at"]
    assert second == first, "节流失效——每次调用都写"


def test_touch_last_used_failure_does_not_raise(aws, monkeypatch):
    """更新失败不得影响转发（它是遥测，不是授权）。"""
    def boom(*a, **kw):
        raise RuntimeError("nope")
    monkeypatch.setattr(keystore, "_update_last_used", boom)
    keystore.touch_last_used("deadbeef", "abc12345")    # 不抛即通过
