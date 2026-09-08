"""RS256 验签核心（spec §5 / §9 / §11.4；3c-final）。每条负例配一条正对照。"""
import base64
import json
import time

import pytest

import session
import upgrade_code_vectors as v

NOW = 1_800_000_000


def _mint(token_use="site-session", *, kid=v.SITE_KID, key=v.SITE_KEY, email="a@x.com", **kw):
    return session.mint_token(kid=kid, sign=v.signer(key), token_use=token_use, email=email,
                              ttl_seconds=600, name="A", idp="Feishu", auth_via="TokenGeneration_HostedAuth",
                              now=NOW, **kw)


def _verify(token, token_use="site-session", allowlist=None):
    return session.verify_token(token, allowlist=allowlist or v.SITE_ALLOWLIST, token_use=token_use, now=NOW + 1)


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def test_current_site_token_is_accepted_with_full_claims():
    claims, outcome = _verify(_mint())
    assert outcome == "accepted_current"
    assert set(claims) == {"token_use", "aud", "email", "name", "idp", "auth_via", "exp", "iat"}
    assert (claims["token_use"], claims["aud"]) == ("site-session", "site-edge")


def test_previous_key_is_accepted_and_labelled_previous():
    al = {**v.SITE_ALLOWLIST, v.SITE_PREV_KID: v.public_entry(v.SITE_PREV_KEY, "previous")}
    _, outcome = _verify(_mint(kid=v.SITE_PREV_KID, key=v.SITE_PREV_KEY), allowlist=al)
    assert outcome == "accepted_previous"


def test_console_family_positive_controls():
    code = _mint("console-upgrade", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)
    claims, outcome = _verify(code, "console-upgrade", v.CONSOLE_ALLOWLIST)
    assert outcome == "accepted_current" and set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"}
    cs = _mint("console-session", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)
    assert _verify(cs, "console-session", v.CONSOLE_ALLOWLIST)[1] == "accepted_current"


def test_header_is_exactly_alg_typ_kid_and_alg_is_rs256():
    hdr = _unb64(_mint().split(".")[0])
    assert hdr == {"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID}


def test_signature_is_exactly_the_modulus_length():
    sig = _mint().split(".")[2]
    assert len(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))) == 256


# ---- kid 解析（spec §9）----

def test_unknown_kid_is_rejected():
    tok = _mint(kid="site-rs-v9")
    assert _verify(tok) == (None, "unknown_kid")


def test_missing_kid_is_unknown_kid():
    h, p, s = _mint().split(".")
    hdr = _unb64(h); hdr.pop("kid")
    assert _verify(f"{_b64(hdr)}.{p}.{s}") == (None, "unknown_kid")


def test_duplicate_kid_keys_in_header_are_rejected():
    _, p, s = _mint().split(".")
    raw = '{"alg":"RS256","typ":"JWT","kid":"site-rs-v1","kid":"site-rs-v9"}'
    h = base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()
    assert _verify(f"{h}.{p}.{s}") == (None, "bad_signature")


@pytest.mark.parametrize("alg", ["HS256", "RS512", "PS256", "none", "None", "NONE", "ES256"])
def test_right_kid_wrong_alg_is_alg_mismatch(alg):
    h, p, s = _mint().split(".")
    hdr = _unb64(h); hdr["alg"] = alg
    assert _verify(f"{_b64(hdr)}.{p}.{s}") == (None, "alg_mismatch")


def test_site_kid_presented_to_console_allowlist_is_unknown():
    assert _verify(_mint(), "console-upgrade", v.CONSOLE_ALLOWLIST) == (None, "unknown_kid")


def test_console_kid_presented_to_site_allowlist_is_unknown():
    tok = _mint(kid=v.CONSOLE_KID, key=v.CONSOLE_KEY)   # console kid 签的 **site-session**：只改 kid family
    assert _verify(tok) == (None, "unknown_kid")


def test_third_key_signing_under_a_known_kid_is_bad_signature():
    tok = _mint(kid=v.SITE_KID, key=v.SITE_PREV_KEY)     # header 声称 v1，签名是别的私钥
    assert _verify(tok) == (None, "bad_signature")


def test_crit_header_is_rejected_even_with_a_valid_signature():
    h, p, _ = _mint().split(".")
    hdr = _unb64(h); hdr["crit"] = ["exp"]
    h2 = _b64(hdr)
    sig = v.signer(v.SITE_KEY)(f"{h2}.{p}".encode())
    tok = f"{h2}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    assert _verify(tok) == (None, "bad_signature")


# ---- JOSE 层：规范 base64url 与签名长度（spec §5）----

@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_rs_mutation_vectors(name, mutate, expect_reject):
    claims, _ = _verify(mutate(_mint()))
    assert (claims is None) == expect_reject, name


def test_non_canonical_trailing_bits_in_signature_are_rejected():
    h, p, s = _mint().split(".")
    last = s[-1]
    # 同一段字节的另一种编码：把末字符换成"解码相同、编码不同"的字符（尾比特非零）。
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    idx = alphabet.index(last)
    alias = alphabet[idx ^ 1]      # 翻最低位：len%4==2 时末字符低 4 位是尾比特，==3 时低 2 位
    if len(s) % 4 == 0:
        pytest.skip("本次签名编码没有尾比特")
    tok = f"{h}.{p}.{s[:-1]}{alias}"
    assert tok != _mint() and _verify(tok) == (None, "bad_signature")


def test_signature_length_check_precedes_rsa_verify(monkeypatch):
    """变形：把长度检查去掉后，一个 255 字节的签名会交给 cryptography（它也会拒）。这里只钉住
    "长度不等即拒且不调 verify"——防将来有人把它换成"补零后再验"。"""
    calls = []
    orig = session._rsa_verify

    def spy(pub, data, sig):
        calls.append(len(sig)); return orig(pub, data, sig)
    monkeypatch.setattr(session, "_rsa_verify", spy)
    _verify(v._short_sig(_mint()))
    assert calls == [255]


def test_rsa_verify_rejects_a_wrong_length_signature_without_calling_the_primitive():
    """长度不等于模长 ⇒ 直接 False，**不调** RSA 原语（spec §5：不许交给 RSA 层"补零"）。
    用一把假公钥：verify() 被调到就抛，所以本用例只在守卫存在时才能过。"""
    class _Key:
        key_size = 2048
        def verify(self, *a, **kw):
            raise AssertionError("长度不符时不许调到 RSA 原语")
    for bad_len in (255, 257, 0):
        assert session._rsa_verify(_Key(), b"x", b"\x00" * bad_len) is False


# ---- 用途与受众 ----

@pytest.mark.parametrize("token_use,allowlist,wrong_use", [
    ("site-session", v.SITE_ALLOWLIST, "console-session"),
    ("site-session", v.SITE_ALLOWLIST, "console-upgrade"),
    ("console-upgrade", v.CONSOLE_ALLOWLIST, "console-session"),
    ("console-session", v.CONSOLE_ALLOWLIST, "console-upgrade"),
])
def test_token_use_matrix_off_diagonal_is_rejected(token_use, allowlist, wrong_use):
    kid, key = (v.SITE_KID, v.SITE_KEY) if token_use == "site-session" else (v.CONSOLE_KID, v.CONSOLE_KEY)
    tok = _mint(wrong_use, kid=kid, key=key)
    assert _verify(tok, token_use, allowlist) == (None, "wrong_token_use")


def test_aud_mismatch_is_rejected_even_with_right_token_use():
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["aud"] = "console-panel"
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_audience")


def test_aud_as_list_is_rejected():
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["aud"] = ["site-edge"]
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_audience")


def test_expired_is_rejected():
    assert session.verify_token(_mint(), allowlist=v.SITE_ALLOWLIST, token_use="site-session",
                                now=NOW + 601) == (None, "expired")


@pytest.mark.parametrize("email", ["", None, 5])
def test_missing_or_empty_email_is_rejected(email):
    h, p, _ = _mint().split(".")
    claims = _unb64(p); claims["email"] = email
    p2 = _b64(claims)
    sig = v.signer(v.SITE_KEY)(f"{h}.{p2}".encode())
    assert _verify(f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "bad_signature")


def test_upgrade_code_without_jti_is_rejected():
    h, p, _ = _mint("console-upgrade", kid=v.CONSOLE_KID, key=v.CONSOLE_KEY).split(".")
    claims = _unb64(p); claims.pop("jti")
    p2 = _b64(claims)
    sig = v.signer(v.CONSOLE_KEY)(f"{h}.{p2}".encode())
    tok = f"{h}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    assert _verify(tok, "console-upgrade", v.CONSOLE_ALLOWLIST) == (None, "bad_signature")


def test_typ_session_alone_does_not_pass_the_new_entry():
    """旧合同（typ=session、无 token_use/aud）用 site key 签出来：新入口必须拒。"""
    h = _b64({"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID})
    p = _b64({"typ": "session", "email": "a@x.com", "exp": NOW + 600})
    sig = v.signer(v.SITE_KEY)(f"{h}.{p}".encode())
    assert _verify(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}") == (None, "wrong_token_use")


@pytest.mark.parametrize("garbage", ["", ".", "..", "a.b", "a.b.c.d", "\x00.\x00.\x00", "ey.ey.ey"])
def test_garbage_never_raises_and_outcome_is_in_vocabulary(garbage):
    claims, outcome = _verify(garbage)
    assert claims is None and outcome in session.OUTCOMES


def test_outcome_vocabulary_is_exactly_spec_section_8_minus_legacy():
    assert session.OUTCOMES == ("accepted_current", "accepted_previous", "unknown_kid", "alg_mismatch",
                                "wrong_audience", "wrong_token_use", "bad_signature", "expired")


# ---- claim 集合（spec §11.4）----

def test_site_session_claims_are_exactly_the_spec_table():
    assert set(_unb64(_mint().split(".")[1])) == {"token_use", "aud", "email", "name", "idp", "auth_via", "exp", "iat"}


def test_upgrade_code_claims_are_exactly_the_spec_table_and_ttl_is_capped():
    tok = session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="console-upgrade",
                             email="a@x.com", ttl_seconds=999, now=NOW)
    claims = _unb64(tok.split(".")[1])
    assert set(claims) == {"token_use", "aud", "email", "jti", "exp", "iat"} and claims["exp"] - claims["iat"] == 60


def test_console_session_claims_are_exactly_the_spec_table():
    tok = v.console_session_token(session.mint_token)
    assert set(_unb64(tok.split(".")[1])) == {"token_use", "aud", "email", "name", "exp", "iat"}


def test_name_is_capped_at_256_chars():
    tok = session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="site-session",
                             email="a@x.com", ttl_seconds=60, name="x" * 300, now=NOW)
    assert len(_unb64(tok.split(".")[1])["name"]) == 256


def test_oversize_signing_input_is_refused_before_sign_is_called():
    called = []

    def sign(data):
        called.append(1); return b"\x00" * 256
    with pytest.raises(ValueError, match="4096"):
        session.mint_token(kid=v.SITE_KID, sign=sign, token_use="site-session", email="a" * 4000 + "@x.com",
                           ttl_seconds=60, now=NOW)
    assert not called, "超长 signing input 不许到 KMS"


def test_mint_token_rejects_unknown_token_use():
    with pytest.raises(KeyError):
        session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="session", email="a@x.com", ttl_seconds=1)


# ---- 公钥侧四项（spec §5）----

def test_load_public_key_der_accepts_the_test_keys():
    for key in (v.SITE_KEY, v.CONSOLE_KEY):
        pub = session.load_public_key_der(v.spki_der(key))
        assert pub.key_size == 2048


def test_load_public_key_der_rejects_non_rsa_and_bad_exponent_and_short_modulus():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa as _rsa
    ec_der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        v.serialization.Encoding.DER, v.serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match="rsaEncryption"):
        session.load_public_key_der(ec_der)
    with pytest.raises(ValueError, match="65537"):
        session.load_public_key_der(v.spki_der(_rsa.generate_private_key(public_exponent=3, key_size=2048)))
    with pytest.raises(ValueError, match="模长"):
        session.load_public_key_der(v.spki_der(_rsa.generate_private_key(public_exponent=65537, key_size=1024)))


def test_load_public_key_der_rejects_non_minimal_der():
    der = v.spki_der(v.SITE_KEY)
    with pytest.raises(ValueError):
        session.load_public_key_der(der + b"\x00")


def test_spki_sha256_is_64_hex_of_the_der():
    assert session.spki_sha256(v.spki_der(v.SITE_KEY)) == v.spki_hex(v.SITE_KEY)


# ---- 黄金三元组（Edge 预热与三处 verifier 共用）----

def test_golden_triple_verifies_and_is_canonical():
    g = session.RS256_GOLDEN
    pub = session.load_public_key_der(base64.b64decode(g["spki_b64"]))
    assert session._rsa_verify(pub, g["signing_input"].encode(), base64.b64decode(g["signature_b64"]))
    assert g["signing_input"].count(".") == 1     # 就是一个 JWS signing input（header.payload）


# ---- 夹具常量（ADR 0002）----

def test_fixture_constants_are_the_adr_literals():
    assert (session.FIXTURE_DOMAIN, session.FIXTURE_IDP, session.FIXTURE_AUTH_VIA, session.FIXTURE_MAX_TTL) == \
        ("e2e.invalid", "fixture", "fixture-issuer", 1800)


def test_fixture_domain_matches_the_permissions_copy():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deployer" / "functions"))
    import permissions
    assert permissions.FIXTURE_DOMAIN == session.FIXTURE_DOMAIN
