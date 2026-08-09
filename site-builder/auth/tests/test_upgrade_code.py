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
    """反向也不行——否则 60 秒 code 能当 4 小时面板会话用。"""
    code = session.mint_upgrade_code("u@x.com", SECRET)
    claims = session.verify_session_jwt(code, SECRET)
    # 同密钥同算法，所以签名会过；但它没有 scope=console，
    # panel 的 verify_console_cookie 据此拒绝（见 panel 侧同名用例）。
    assert claims is None or claims.get("scope") != "console"


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
