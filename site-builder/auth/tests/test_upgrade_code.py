"""升级码与面板会话的跨侧向量（auth 这一侧）。同一组向量在 panel/tests/test_console_session.py 再跑一遍。"""
import pytest

import session
import upgrade_code_vectors as v


def _code(email="u@x.com"):
    return session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="console-upgrade",
                              email=email, ttl_seconds=60)


def test_payload_shape_is_the_declared_contract():
    claims, outcome = session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert outcome == "accepted_current" and set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"}


def test_each_code_has_a_distinct_jti():
    jtis = {session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")[0]["jti"]
            for _ in range(5)}
    assert len(jtis) == 5


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_mutation_vectors(name, mutate, expect_reject):
    claims, _ = session.verify_token(mutate(_code()), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade")
    assert (claims is None) == expect_reject, name


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_console_session_cookie_vectors_match_the_panel_side(name, mutate, expect_reject):
    tok = v.console_session_token(session.mint_token)
    claims, _ = session.verify_token(mutate(tok), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session")
    assert (claims is None) == expect_reject, name


def test_upgrade_code_is_not_a_console_session_and_vice_versa():
    assert session.verify_token(_code(), allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session") == (None, "wrong_token_use")
    tok = v.console_session_token(session.mint_token)
    assert session.verify_token(tok, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-upgrade") == (None, "wrong_token_use")


def test_console_session_token_is_rejected_when_verified_as_a_site_session():
    tok = v.console_session_token(session.mint_token)
    assert session.verify_token(tok, allowlist=v.SITE_ALLOWLIST, token_use="site-session") == (None, "unknown_kid")
