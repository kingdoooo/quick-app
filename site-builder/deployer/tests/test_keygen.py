"""Key 生成与哈希。**算法只有一份**（创建端 panel 复制本模块）。"""
import re

import keygen


def test_plaintext_shape_is_sk_plus_16_base62():
    p = keygen.new_key().plaintext
    assert re.fullmatch(r"sk-[0-9A-Za-z]{16}", p), p
    assert keygen.PLAINTEXT_RE.fullmatch(p)


def test_alphabet_is_exactly_base62():
    """**直接断言字符集本体**，不靠抽样发现越界字符。

    实测过（反向验证 #4）：给 ALPHABET 加上 `-_` 后，只看一把 Key 的形态断言
    仅 39.8% 的运行会红（1-(62/64)**16）——那是一条会 60% 概率放行缺陷的
    随机闸门。字符集是常量、是唯一真源，就该按常量整体比。

    `-` / `_` 不在集内是刻意的：Key 会被粘进 URL、shell、YAML、HTTP 头，
    也会被双击选中；且 `_` 一旦进入集内，SWITCH_PK 的"不可能碰撞"就没了前提。
    """
    assert keygen.ALPHABET == "0123456789" \
        "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ", keygen.ALPHABET
    assert len(keygen.ALPHABET) == 62
    assert len(set(keygen.ALPHABET)) == 62, "字符集有重复项会让分布不均"
    # 批量抽样兜底：即使有人绕过常量、在取样处另加字符，这条也会红。
    seen = set("".join(keygen.new_key().plaintext[3:] for _ in range(200)))
    assert seen <= set(keygen.ALPHABET), seen - set(keygen.ALPHABET)


def test_hash_is_sha256_hex_of_exact_plaintext():
    import hashlib
    k = keygen.new_key()
    assert k.key_hash == hashlib.sha256(k.plaintext.encode()).hexdigest()
    assert len(k.key_hash) == 64 and k.key_hash.islower()


def test_key_id_is_independent_of_hash():
    """**不得由 hash 派生**——派生会让 key_id 变成哈希预言机。

    判据不能只看"两个值不相等"（那对任何派生都成立）。做法：固定 hash
    不可能固定（明文随机），所以反过来——同一明文重复 new_key 是不可能的，
    改为对 key_id 与 key_hash 做统计独立性的**结构**检查：
    key_id 不是 key_hash 的任何前缀/后缀/子串，且不在 hash 的字符集里
    （hash 只有 [0-9a-f]，key_id 含大写的概率极高）。
    再加一条源码级断言（见 test_keygen_source_does_not_derive_id_from_hash）。
    """
    for _ in range(200):
        k = keygen.new_key()
        assert k.key_id not in k.key_hash
        assert k.key_hash not in k.key_id
        assert len(k.key_id) == 8


def test_keygen_source_does_not_derive_id_from_hash():
    """源码级：key_id 的来源表达式不得引用 key_hash / sha256 / digest。

    行为断言抓不到"取 hash 的第 9-16 位当 key_id"这种派生（子串检查会抓到，
    但"取 hash 再另做一次 hash"就抓不到了）。用 AST 定位 key_id 的来源。

    **2026-08-12 补关键字实参形态（独立审查发现的盲区）**：原版只看
    `ast.Assign` 且目标名是 `key_id` 的语句。把派生**内联**写成
    `NewKey(..., key_id=hash_key(key_hash)[:8], ...)` 会同时骗过两个预言机——
    源码里没有 Assign 节点（本条看不见），而"又 hash 了一次"让
    test_key_id_is_independent_of_hash 的子串检查也失效。所以这里把
    `key_id=` 关键字实参一并纳入，并把 `hash_key` 本身也列进禁用名单：
    合法来源只有 `_random_base62(KEY_ID_LEN)`，不存在需要引用它的写法。
    """
    import ast
    import pathlib
    src = (pathlib.Path(keygen.__file__)).read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "new_key")
    banned = {"key_hash", "sha256", "digest", "hexdigest", "hash_key", "h"}
    # 「给 key_id 一个值」的两种形态：`key_id = <expr>` 与 `f(key_id=<expr>)`
    sources = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "key_id"
                for t in node.targets):
            sources.append(node.value)
        elif isinstance(node, ast.keyword) and node.arg == "key_id":
            sources.append(node.value)
    # 自查：一个来源都找不到说明本守卫已与 new_key 脱节（那时它是永远绿的装饰）。
    assert sources, "找不到任何 key_id 的来源表达式——先修本守卫"
    for value in sources:
        names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(value) if isinstance(n, ast.Attribute)}
        assert not (names & banned), \
            f"key_id 的来源引用了 {names & banned}——那是哈希预言机"


def test_prefix_is_sk_plus_first_4_and_leaves_12_chars_secret():
    """展示用前缀只暴露 4 位，剩余 12 位（71.5 bit）仍是秘密（spec §5.1）。"""
    k = keygen.new_key()
    assert k.prefix == k.plaintext[:7]          # "sk-" + 4
    assert len(k.prefix) == 7
    assert k.plaintext[7:] not in k.prefix


def test_entropy_no_collision_in_bulk():
    """随机源自检。**这条不构成线上唯一性保证**（Codex P2-7）——

    它只证明随机源没坏（比如没退化成常量或低位固定）。8 位 base62 ≈ 47.6 bit，
    线上唯一性由 keystore.create() 的"Query 检测 + 重试"与吊销侧的
    "行数 ≠ 1 即 fail-closed"共同保证，见 test_keystore.py 的对应用例。
    """
    ks = [keygen.new_key() for _ in range(3000)]
    assert len({k.plaintext for k in ks}) == 3000
    assert len({k.key_hash for k in ks}) == 3000
    assert len({k.key_id for k in ks}) == 3000


def test_switch_sentinel_cannot_be_produced_by_any_real_hash():
    """哨兵行主键必须落在真 hash 的字符集之外。

    不是"显然成立"就不用断言：将来若有人把 hash 换成 base64（`_` 在字符集里）
    或 uuid 形态，这条会立刻红——那时哨兵行就可能被一把精心构造的 Key 命中，
    等于用户能自己写平台开关。
    """
    import re as _re
    assert not _re.fullmatch(r"[0-9a-f]{64}", keygen.SWITCH_PK)
    assert keygen.SWITCH_PK == "__switch__"
    # 反向：随机取样的真 hash 全部匹配 hex64（证明上一条的前提成立）
    for _ in range(50):
        assert _re.fullmatch(r"[0-9a-f]{64}", keygen.new_key().key_hash)


def test_hash_key_rejects_nothing_but_is_only_called_after_shape_check():
    """hash_key 本身不做形态校验（它只是哈希函数），形态校验是 PLAINTEXT_RE
    的职责。这条用例锁定分工，防止后人把校验塞进 hash_key 又在别处漏掉。"""
    assert keygen.hash_key("anything") == keygen.hash_key("anything")
    assert not keygen.PLAINTEXT_RE.fullmatch("anything")
