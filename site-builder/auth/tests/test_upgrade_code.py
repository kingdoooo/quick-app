"""auth 侧：upgrade code 的签发与验签契约（panel 侧跑同一组向量）。"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "panel" / "tests"))

import session
from upgrade_code_vectors import MUTATIONS, SECRET


def test_payload_shape_is_the_declared_contract():
    code = session.mint_upgrade_code("u@x.com", SECRET)
    claims = session.verify_upgrade_code(code, SECRET)
    assert claims["typ"] == "console-upgrade"    # 上下文标记
    assert claims["email"] == "u@x.com"
    assert claims["jti"] and len(claims["jti"]) >= 16
    assert 0 < claims["exp"] - int(time.time()) <= 60


def test_ttl_is_capped_even_if_caller_asks_for_more():
    """60 秒是上限而不是默认值——调用方传大数不得延长它。

    code 只在 302 跳转的那一瞬间有效；能延长就等于多出一个长期凭证。
    """
    code = session.mint_upgrade_code("u@x.com", SECRET, ttl_seconds=86400)
    claims = session.verify_upgrade_code(code, SECRET)
    assert claims["exp"] - int(time.time()) <= 60


def test_each_code_has_a_distinct_jti():
    """jti 是一次性消费的键——重复就意味着第二个 code 一签发就被判重放。"""
    jtis = {session.verify_upgrade_code(
        session.mint_upgrade_code("u@x.com", SECRET), SECRET)["jti"]
        for _ in range(5)}
    assert len(jtis) == 5


def test_expired_code_is_rejected():
    code = session.mint_upgrade_code("u@x.com", SECRET, ttl_seconds=1)
    assert session.verify_upgrade_code(code, SECRET,
                                      now=int(time.time()) + 5) is None


def test_wrong_secret_is_rejected():
    code = session.mint_upgrade_code("u@x.com", SECRET)
    assert session.verify_upgrade_code(code, "another-secret") is None


def test_session_jwt_cannot_masquerade_as_upgrade_code():
    """拿会话 JWT / login state 冒充 code 必须被拒。

    注意：这条**不足以**证明 typ 检查有效——会话 JWT 没有 jti，会先被 jti
    检查拦下。真正盯住 typ 的是下面那条（实测：删掉 typ 检查，本条仍绿）。
    """
    jwt = session.mint_session_jwt("u@x.com", "U", SECRET, scope="console")
    assert session.verify_upgrade_code(jwt, SECRET) is None


def test_typ_claim_is_what_rejects_a_wellformed_foreign_token():
    """**唯一真正覆盖 typ 检查的用例。**

    构造一个"除了 typ 之外样样齐全"的同密钥 token：有 email、有 jti、
    exp 还很长。除了 typ 检查，没有任何一步能拦住它——而放过它意味着：
      ① 任何用同一 JWT_SECRET 签出的、恰好带这几个字段的凭证都能当升级码；
      ② 它的 exp 由伪造方决定，60 秒上限一并失效（本用例断言 1 小时那个）。
    删掉 verify_upgrade_code 里的 typ 检查，本条会红（已实测）。
    """
    import json
    h = session._b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                                   separators=(",", ":")).encode())
    claims = {"email": "attacker@x.com", "jti": "A" * 22,
              "exp": int(time.time()) + 3600}        # 远超 60 秒上限
    p = session._b64url(json.dumps(claims, separators=(",", ":")).encode())
    forged = f"{h}.{p}.{session._sign(f'{h}.{p}'.encode(), SECRET)}"
    assert session.verify_upgrade_code(forged, SECRET) is None, (
        "缺 typ 的同密钥 token 被当成升级码接受了——"
        "跨上下文冒充与 60 秒上限同时失效")


def test_wrong_typ_value_is_rejected():
    """typ 存在但不是 console-upgrade（比如未来新增的别的 code 类型）。"""
    import json
    h = session._b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                                   separators=(",", ":")).encode())
    claims = {"typ": "password-reset", "email": "u@x.com", "jti": "B" * 22,
              "exp": int(time.time()) + 30}
    p = session._b64url(json.dumps(claims, separators=(",", ":")).encode())
    forged = f"{h}.{p}.{session._sign(f'{h}.{p}'.encode(), SECRET)}"
    assert session.verify_upgrade_code(forged, SECRET) is None


def test_upgrade_code_is_not_accepted_as_a_console_session():
    """反向也不行——否则 60 秒 code 能当 4 小时面板会话用。

    **M05 之后这条比原来强**：原来只能断言"它没有 scope=console"
    （因为同密钥同算法、签名确实会过，注释也这么写的）；
    现在 typ 检查先拒，所以可以直接断言 None。
    """
    code = session.mint_upgrade_code("u@x.com", SECRET)
    assert session.verify_session_jwt(
        code, SECRET, expected_typ=session.SESSION_TYP) is None


def test_upgrade_code_is_not_accepted_as_a_session():
    """一次性升级码不得当普通会话用。

    两者用**同一个密钥**签名、线格式相同，而升级码的 claims 是
    {typ, email, jti, exp}——旧的 verify_session_jwt 只查签名与 exp，
    于是一个 60s 的升级码就是一个有效会话（M05）。
    """
    code = session.mint_upgrade_code("v@example.test", "secret")
    assert session.verify_session_jwt(
        code, "secret", expected_typ=session.SESSION_TYP) is None


def test_session_token_is_not_accepted_as_an_upgrade_code():
    """反方向也要挡住（这一半原本就已生效，加用例锁死）。"""
    token = session.mint_session_jwt("v@example.test", "V", "secret")
    assert session.verify_upgrade_code(token, "secret") is None


def test_verify_session_jwt_requires_expected_typ():
    """`expected_typ` 必须是必填参数。

    给默认值等于允许调用方忘记传，而"忘记传"恰好退化成本次修复之前的行为
    ——本仓库已记过这个形态（console_session.consume_code 的 expected_email 同理）。
    """
    token = session.mint_session_jwt("v@example.test", "V", "secret")
    with pytest.raises(TypeError):
        session.verify_session_jwt(token, "secret")


def test_falsy_expected_typ_does_not_restore_the_unchecked_behaviour():
    """显式传假值也不行——必填关键字只挡住"忘记传"。

    `claims.get("typ")` 对**缺失** typ 的旧 token 返回 None，于是
    `expected_typ=None` 时比较写成 `None != None` 为假，检查直接放过
    ——正好退回本次修复之前的行为（M05）。

    None 是唯一会这样撞上的假值（`""` / `0` 与缺失 claim 不相等，本就会被拒），
    但守卫按"非空 str"整体收口，不去依赖这个巧合。
    **返回 None 而不是抛异常**：与本文件既有的 fail-closed 约定一致
    （见 verify_upgrade_code 的 docstring 与 test_verify_never_raises_on_garbage）。
    """
    import json
    legacy_claims = {"email": "legacy@example.test", "name": "L",
                     "exp": int(time.time()) + 3600}      # 一期形态：没有 typ
    h = session._b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                                   separators=(",", ":")).encode())
    p = session._b64url(json.dumps(legacy_claims, separators=(",", ":")).encode())
    legacy = f"{h}.{p}.{session._sign(f'{h}.{p}'.encode(), SECRET)}"
    for bad in (None, "", 0):
        assert session.verify_session_jwt(legacy, SECRET, expected_typ=bad) is None, (
            f"expected_typ={bad!r} 放过了不带 typ 的旧 token——typ 检查形同虚设")


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_mutation_vectors(name, mutate, expect_reject):
    code = mutate(session.mint_upgrade_code("u@x.com", SECRET))
    got = session.verify_upgrade_code(code, SECRET)
    assert (got is None) is expect_reject, name


def test_verify_never_raises_on_garbage():
    """fail-closed：任何畸形输入都返回 None，不抛异常。

    抛异常会变成 500 + 堆栈，而调用方（Lambda handler）期望的是"拒绝"。
    """
    for junk in (None, "", "...", "a.b", "a.b.c.d", "😀.😀.😀", "x" * 10000):
        assert session.verify_upgrade_code(junk, SECRET) is None
