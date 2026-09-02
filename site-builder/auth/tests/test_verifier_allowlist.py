"""verifier allowlist 核心（spec §5 验签合同 / §9 反例 / §11.4 claim 表；plan 3c-1A Task 2）。

先于实现写下并跑红。每条反例配一条正向控制，否则负向全绿证明不了任何东西。
两条 meta 用例（文件末）证明关键反例真的钉在它们声称盯住的那一行上。
"""
import base64
import hashlib
import hmac
import json
import time

import pytest

import session

S1, S0, C1, LEGACY = "site-secret-v1", "site-secret-v0", "console-secret-v1", "legacy-secret"
SITE_AL = {"site-hs-v1": {"alg": "HS256", "secret": S1, "role": "current"},
           "site-hs-v0": {"alg": "HS256", "secret": S0, "role": "previous"}}
CONSOLE_AL = {"console-hs-v1": {"alg": "HS256", "secret": C1, "role": "current"}}
SPEC_OUTCOMES = {"accepted_current", "accepted_previous", "accepted_legacy", "unknown_kid",
                 "alg_mismatch", "wrong_audience", "wrong_token_use", "bad_signature", "expired"}


def b64(obj) -> str:
    raw = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def resign(token: str, secret: str, *, header=None, payload=None, raw_header: str | None = None) -> str:
    """改 header / payload 后用给定密钥重签。raw_header 用于塞非规范 JSON（重复键）。"""
    h, p, _ = token.split(".")
    hd = unb64(h) if header is None else header
    pl = unb64(p) if payload is None else payload
    h2 = raw_header if raw_header is not None else b64(hd)
    p2 = b64(pl)
    sig = b64(hmac.new(secret.encode(), f"{h2}.{p2}".encode(), hashlib.sha256).digest())
    return f"{h2}.{p2}.{sig}"


def site_token(**kw) -> str:
    args = dict(kid="site-hs-v1", secret=S1, token_use="site-session", email="v@example.test",
                ttl_seconds=600, name="V", idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    args.update(kw)
    return session.mint_token(**args)


def console_token(**kw) -> str:
    args = dict(kid="console-hs-v1", secret=C1, token_use="console-session",
                email="v@example.test", ttl_seconds=600, name="V")
    args.update(kw)
    return session.mint_token(**args)


def upgrade_code(**kw) -> str:
    args = dict(kid="console-hs-v1", secret=C1, token_use="console-upgrade",
                email="v@example.test", ttl_seconds=60)
    args.update(kw)
    return session.mint_token(**args)


# ---- 正向控制 ------------------------------------------------------------

def test_current_site_token_is_accepted_with_full_claims():
    claims, outcome = session.verify_token(site_token(), allowlist=SITE_AL, token_use="site-session")
    assert outcome == "accepted_current"
    assert claims["email"] == "v@example.test" and claims["idp"] == "Feishu"
    assert claims["token_use"] == "site-session" and claims["aud"] == "site-edge"


def test_previous_key_is_accepted_and_labelled_previous():
    tok = site_token(kid="site-hs-v0", secret=S0)
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "accepted_previous"


def test_console_family_positive_controls():
    assert session.verify_token(console_token(), allowlist=CONSOLE_AL,
                                token_use="console-session")[1] == "accepted_current"
    claims, outcome = session.verify_token(upgrade_code(), allowlist=CONSOLE_AL,
                                           token_use="console-upgrade")
    assert outcome == "accepted_current" and claims["jti"]


def test_legacy_tokens_are_accepted_through_the_legacy_entry():
    site = session.mint_session_jwt("v@example.test", "V", LEGACY, idp="Feishu")
    cons = session.mint_session_jwt("v@example.test", "V", LEGACY, scope="console")
    code = session.mint_upgrade_code("v@example.test", LEGACY)
    kw = dict(legacy_secret=LEGACY)
    assert session.verify_with_legacy(site, allowlist=SITE_AL, token_use="site-session", **kw)[1] == "accepted_legacy"
    assert session.verify_with_legacy(cons, allowlist=CONSOLE_AL, token_use="console-session", **kw)[1] == "accepted_legacy"
    assert session.verify_with_legacy(code, allowlist=CONSOLE_AL, token_use="console-upgrade", **kw)[1] == "accepted_legacy"


def test_new_entry_token_also_passes_verify_with_legacy():
    """verify_with_legacy 是 handler 真正调用的入口：新形态必须从它进新入口。"""
    assert session.verify_with_legacy(site_token(), allowlist=SITE_AL, token_use="site-session",
                                      legacy_secret=LEGACY)[1] == "accepted_current"


# ---- §9 kid 解析 ------------------------------------------------------------

def test_unknown_kid_is_rejected_and_does_not_fall_back_to_legacy():
    """**状态机第 5 条**：有 kid 但不在 allowlist ⇒ 拒，哪怕签名用的是 legacy 密钥且 legacy 开着。"""
    tok = resign(site_token(), LEGACY, header={"alg": "HS256", "typ": "JWT", "kid": "site-hs-v7"})
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "unknown_kid"
    assert session.verify_with_legacy(tok, allowlist=SITE_AL, token_use="site-session",
                                      legacy_secret=LEGACY)[1] == "unknown_kid"


def test_missing_kid_with_legacy_entry_closed_is_unknown_kid():
    legacy_tok = session.mint_session_jwt("v@example.test", "V", LEGACY)
    assert session.verify_with_legacy(legacy_tok, allowlist=SITE_AL, token_use="site-session",
                                      legacy_secret=None)[1] == "unknown_kid"
    assert session.verify_token(legacy_tok, allowlist=SITE_AL, token_use="site-session")[1] == "unknown_kid"


def test_duplicate_kid_keys_in_header_are_rejected():
    raw = b64(b'{"alg":"HS256","typ":"JWT","kid":"site-hs-v0","kid":"site-hs-v1"}')
    tok = resign(site_token(), S1, raw_header=raw)
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "bad_signature"


@pytest.mark.parametrize("alg", ["HS512", "RS256", "none", "None", "NONE", "", None])
def test_right_kid_wrong_alg_is_alg_mismatch(alg):
    hd = {"alg": alg, "typ": "JWT", "kid": "site-hs-v1"}
    if alg is None:
        del hd["alg"]
    tok = resign(site_token(), S1, header=hd)
    if alg in ("none", "None", "NONE"):
        tok = tok.rsplit(".", 1)[0] + "."          # alg=none 攻击的经典形态：空签名
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "alg_mismatch"


def test_site_kid_presented_to_console_allowlist_is_unknown():
    assert session.verify_token(site_token(), allowlist=CONSOLE_AL, token_use="console-session")[1] == "unknown_kid"


def test_console_kid_presented_to_site_allowlist_is_unknown():
    """Edge 的 allowlist 里没有 console 的 kid（spec §4.1）。"""
    assert session.verify_token(console_token(), allowlist=SITE_AL, token_use="site-session")[1] == "unknown_kid"


def test_third_key_signing_under_a_known_kid_is_bad_signature():
    tok = resign(site_token(), "some-third-key")
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "bad_signature"


# ---- 用途与受众 ------------------------------------------------------------

@pytest.mark.parametrize("mint, allowlist, wrong_use", [
    (site_token, SITE_AL, "console-session"),
    (site_token, SITE_AL, "console-upgrade"),
    (console_token, CONSOLE_AL, "console-upgrade"),
    (console_token, CONSOLE_AL, "site-session"),
    (upgrade_code, CONSOLE_AL, "console-session"),
    (upgrade_code, CONSOLE_AL, "site-session"),
])
def test_token_use_matrix_off_diagonal_is_rejected(mint, allowlist, wrong_use):
    """M05 那一类的完整矩阵：升级码当面板会话、面板会话当站点会话……全部 wrong_token_use。"""
    assert session.verify_token(mint(), allowlist=allowlist, token_use=wrong_use)[1] == "wrong_token_use"


def test_aud_mismatch_is_rejected_even_with_right_token_use():
    tok = site_token()
    pl = unb64(tok.split(".")[1]); pl["aud"] = "console-panel"
    tok2 = resign(tok, S1, payload=pl)
    assert session.verify_token(tok2, allowlist=SITE_AL, token_use="site-session")[1] == "wrong_audience"


def test_aud_as_list_is_rejected():
    tok = site_token()
    pl = unb64(tok.split(".")[1]); pl["aud"] = ["site-edge"]
    tok2 = resign(tok, S1, payload=pl)
    assert session.verify_token(tok2, allowlist=SITE_AL, token_use="site-session")[1] == "wrong_audience"


def test_expired_is_rejected():
    tok = site_token(ttl_seconds=1, now=int(time.time()) - 10)
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "expired"


@pytest.mark.parametrize("email", ["", None, 5])
def test_missing_or_empty_email_is_rejected(email):
    tok = site_token()
    pl = unb64(tok.split(".")[1])
    if email is None:
        del pl["email"]
    else:
        pl["email"] = email
    tok2 = resign(tok, S1, payload=pl)
    assert session.verify_token(tok2, allowlist=SITE_AL, token_use="site-session")[1] == "bad_signature"


def test_upgrade_code_without_jti_is_rejected():
    tok = upgrade_code()
    pl = unb64(tok.split(".")[1]); del pl["jti"]
    tok2 = resign(tok, C1, payload=pl)
    assert session.verify_token(tok2, allowlist=CONSOLE_AL, token_use="console-upgrade")[1] == "bad_signature"


def test_tampered_payload_keeps_old_signature_is_bad_signature():
    tok = site_token()
    h, p, s = tok.split(".")
    pl = unb64(p); pl["email"] = "attacker@example.test"
    assert session.verify_token(f"{h}.{b64(pl)}.{s}", allowlist=SITE_AL,
                                token_use="site-session")[1] == "bad_signature"


def test_typ_session_alone_does_not_pass_the_new_entry():
    """新入口只认 token_use + aud；旧合同的 typ=session 在新入口无效（状态机第 3、4 条）。"""
    tok = resign(site_token(), S1, payload={"typ": "session", "email": "v@example.test",
                                            "exp": int(time.time()) + 600})
    assert session.verify_token(tok, allowlist=SITE_AL, token_use="site-session")[1] == "wrong_token_use"


@pytest.mark.parametrize("garbage", ["", "a", "a.b", "a.b.c", "....", "\x00.\x00.\x00",
                                     b64(b"[]") + "." + b64(b"{}") + ".x",
                                     b64(b'{"kid":"site-hs-v1","alg":"HS256"}') + ".notjson.x"])
def test_garbage_never_raises_and_outcome_is_in_vocabulary(garbage):
    claims, outcome = session.verify_token(garbage, allowlist=SITE_AL, token_use="site-session")
    assert claims is None and outcome in SPEC_OUTCOMES
    claims, outcome = session.verify_with_legacy(garbage, allowlist=SITE_AL, token_use="site-session",
                                                 legacy_secret=LEGACY)
    assert claims is None and outcome in SPEC_OUTCOMES


def test_outcome_vocabulary_is_exactly_spec_section_8():
    assert set(session.OUTCOMES) == SPEC_OUTCOMES


# ---- legacy 入口按旧合同、且只在 legacy 入口 -------------------------------------

def test_legacy_console_scoped_session_is_not_a_site_session():
    cons = session.mint_session_jwt("v@example.test", "V", LEGACY, scope="console")
    claims, outcome = session.verify_with_legacy(cons, allowlist=SITE_AL, token_use="site-session",
                                                 legacy_secret=LEGACY)
    assert claims is None and outcome != "accepted_legacy"


def test_legacy_site_session_is_not_a_console_session():
    site = session.mint_session_jwt("v@example.test", "V", LEGACY)
    claims, _ = session.verify_with_legacy(site, allowlist=CONSOLE_AL, token_use="console-session",
                                           legacy_secret=LEGACY)
    assert claims is None


def test_legacy_upgrade_code_is_not_a_console_session_and_vice_versa():
    code = session.mint_upgrade_code("v@example.test", LEGACY)
    cons = session.mint_session_jwt("v@example.test", "V", LEGACY, scope="console")
    kw = dict(allowlist=CONSOLE_AL, legacy_secret=LEGACY)
    assert session.verify_with_legacy(code, token_use="console-session", **kw)[0] is None
    assert session.verify_with_legacy(cons, token_use="console-upgrade", **kw)[0] is None


# ---- mint_token 的合同（spec §11.4）-----------------------------------------------

def test_site_session_claims_are_exactly_the_spec_table():
    assert set(unb64(site_token().split(".")[1])) == {"token_use", "aud", "email", "name", "idp",
                                                       "auth_via", "exp", "iat"}


def test_upgrade_code_claims_are_exactly_the_spec_table_and_ttl_is_capped():
    pl = unb64(upgrade_code(ttl_seconds=999).split(".")[1])
    assert set(pl) == {"token_use", "aud", "email", "jti", "exp", "iat"}
    assert 0 < pl["exp"] - pl["iat"] <= session.UPGRADE_MAX_TTL
    assert len({unb64(upgrade_code().split(".")[1])["jti"] for _ in range(20)}) == 20


def test_console_session_claims_are_exactly_the_spec_table():
    assert set(unb64(console_token().split(".")[1])) == {"token_use", "aud", "email", "name", "exp", "iat"}


def test_header_is_exactly_alg_typ_kid_and_aud_is_a_string():
    tok = site_token()
    assert unb64(tok.split(".")[0]) == {"alg": "HS256", "typ": "JWT", "kid": "site-hs-v1"}
    assert isinstance(unb64(tok.split(".")[1])["aud"], str)


def test_name_is_capped_at_256_chars():
    pl = unb64(site_token(name="N" * 300).split(".")[1])
    assert len(pl["name"]) == 256


def test_oversize_signing_input_is_refused_not_signed():
    with pytest.raises(ValueError):
        site_token(email="a" * 4200 + "@example.test")


def test_mint_token_rejects_unknown_token_use():
    with pytest.raises(KeyError):
        site_token(token_use="session")


# ---- meta：证明关键反例钉在它们声称的那一行 ------------------------------------------

def test_meta_aud_list_case_is_anchored_on_exact_string_compare(monkeypatch):
    """把 aud 比对换成"成员"语义，aud 数组那条必须**转绿**——否则它没盯住那一行。"""
    monkeypatch.setattr(session, "_aud_matches",
                        lambda got, want: (want in got) if isinstance(got, list) else got == want)
    tok = site_token()
    pl = unb64(tok.split(".")[1]); pl["aud"] = ["site-edge"]
    assert session.verify_token(resign(tok, S1, payload=pl), allowlist=SITE_AL,
                                token_use="site-session")[1] == "accepted_current"


def test_meta_no_fallback_case_is_anchored_on_kid_presence(monkeypatch):
    """把"有 kid"判定换成"kid 在 allowlist 里"，未知 kid 就会回落 legacy 并被接受——那条反例必须因此转绿。"""
    monkeypatch.setattr(session, "_has_kid", lambda header: header.get("kid") in SITE_AL)
    tok = resign(site_token(), LEGACY, header={"alg": "HS256", "typ": "JWT", "kid": "site-hs-v7"})
    # legacy 合同要求 typ=session；给它一个旧合同 payload 才能证明"回落后会被接受"
    tok = resign(tok, LEGACY, payload={"typ": "session", "email": "v@example.test",
                                       "exp": int(time.time()) + 600})
    assert session.verify_with_legacy(tok, allowlist=SITE_AL, token_use="site-session",
                                      legacy_secret=LEGACY)[1] == "accepted_legacy"
