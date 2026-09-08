"""Edge 内嵌 verifier 认 site family 的 RS256 allowlist（3c-final）：正向跨组件向量、spec §9 负例矩阵、
夹具边界（ADR 0002）、与 auth/session.py 的字节等价守卫。"""
import base64
import json
import logging
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "auth"))
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import edge_substitutions as es  # noqa: E402
import session as auth_session  # noqa: E402
import upgrade_code_vectors as v  # noqa: E402

SRC = es.EDGE_SRC_PATH.read_text(encoding="utf-8")
ALLOWLIST = {v.SITE_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"},
             v.SITE_PREV_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_PREV_KEY), "role": "previous"}}
orq = es.load_edge_module("_edge_kid_testable", write_to=HERE, SITE_ALLOWLIST_JSON=json.dumps(ALLOWLIST))

ROUTE = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x", "api_target": "",
         "require_auth": True, "allowed_users": "org", "owner": "o@example.test"}
FIXTURE_ROUTE = {**ROUTE, "subdomain": "app-e2e-probe", "site_id": "e2e-probe", "owner": "probe@e2e.invalid",
                 "allowed_users": ["probe@e2e.invalid"]}
CONSOLE_ROUTE = {"subdomain": "console", "site_id": "console", "static_prefix": "platform/console/v",
                 "api_target": "https://p.lambda-url.us-east-1.on.aws", "route_mode": "split",
                 "require_auth": True, "allowed_users": "org", "owner": "platform", orq._PLATFORM_KEY: True}


def _req(token: str, host="app-x.example.com"):
    return {"uri": "/", "querystring": "", "method": "GET",
            "headers": {"host": [{"key": "Host", "value": host}],
                        "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}


def allowed(mod, token: str, route=None, host="app-x.example.com") -> bool:
    return mod._check_auth(_req(token, host), dict(route or ROUTE), host) is None


def site_token(**kw) -> str:
    args = dict(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="site-session", email="v@example.test",
                ttl_seconds=600, name="V", idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    args.update(kw)
    return auth_session.mint_token(**args)


def fixture_token(email="probe@e2e.invalid", **kw) -> str:
    return site_token(email=email, idp="fixture", auth_via="fixture-issuer", **kw)


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def resign(token: str, key, *, header=None, payload=None) -> str:
    h, p, _ = token.split(".")
    h2 = b64(header) if header is not None else h
    p2 = b64(payload) if payload is not None else p
    sig = v.signer(key)(f"{h2}.{p2}".encode())
    return f"{h2}.{p2}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


# ---- 正向 ----

def test_auth_minted_current_kid_token_verifies_at_the_edge():
    claims = orq._verify_session_jwt(site_token())
    assert claims and claims["email"] == "v@example.test"


def test_auth_minted_previous_kid_token_verifies_at_the_edge():
    assert allowed(orq, site_token(kid=v.SITE_PREV_KID, sign=v.signer(v.SITE_PREV_KEY)))


def test_verify_function_keeps_its_contract_for_check_auth():
    assert orq._verify_session_jwt("garbage") is None
    assert isinstance(orq._verify_session_jwt(site_token()), dict)


# ---- spec §9 负例 ----

def test_console_kid_is_not_in_the_edge_allowlist():
    tok = auth_session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY), token_use="site-session",
                                  email="v@example.test", ttl_seconds=600, idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    assert not allowed(orq, tok)


def test_unknown_kid_is_rejected():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": "site-rs-v7"}))


def test_missing_kid_is_rejected():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT"}))


def test_wrong_token_use_is_rejected():
    tok = auth_session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY), token_use="console-session",
                                  email="v@example.test", ttl_seconds=600, name="V")
    assert not allowed(orq, tok)


def test_aud_as_list_is_rejected():
    claims = unb64(site_token().split(".")[1]); claims["aud"] = ["site-edge"]
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, payload=claims))


@pytest.mark.parametrize("alg", ["none", "None", "HS256", "RS512", "PS256"])
def test_alg_other_than_the_allowlisted_one_is_rejected(alg):
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": alg, "typ": "JWT", "kid": v.SITE_KID}))


def test_third_key_under_known_kid_is_rejected():
    assert not allowed(orq, site_token(sign=v.signer(v.CONSOLE_KEY)))     # header 说 site-rs-v1，签名是别的私钥


def test_expired_kid_token_is_rejected():
    assert not allowed(orq, site_token(ttl_seconds=-5))


def test_idp_and_auth_via_are_still_required_on_the_new_entry():
    assert not allowed(orq, site_token(idp="", auth_via=""))
    assert not allowed(orq, site_token(auth_via="TokenGeneration_Authentication"))


@pytest.mark.parametrize("name,mutate,expect_reject", v.RS_MUTATIONS)
def test_rs_mutation_vectors_at_the_edge(name, mutate, expect_reject):
    assert allowed(orq, mutate(site_token())) == (not expect_reject), name


def test_crit_header_is_rejected_even_with_a_valid_signature():
    assert not allowed(orq, resign(site_token(), v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": v.SITE_KID, "crit": ["exp"]}))


def test_outcome_is_logged_as_fixed_vocabulary_without_the_token(caplog):
    with caplog.at_level(logging.INFO):
        tok = site_token()
        orq._verify_session_jwt(tok)
        orq._verify_session_jwt(resign(tok, v.SITE_KEY, header={"alg": "RS256", "typ": "JWT", "kid": "nope"}))
    outcomes = [json.loads(r.getMessage())["outcome"] for r in caplog.records
                if r.getMessage().startswith("{") and '"session_verify"' in r.getMessage()]
    assert outcomes == ["accepted_current", "unknown_kid"]
    assert tok not in caplog.text and "accepted_legacy" not in caplog.text


# ---- 夹具边界（ADR 0002 / D6）----

def test_fixture_session_is_accepted_on_a_fixture_owned_route():
    assert allowed(orq, fixture_token(), FIXTURE_ROUTE, host="app-e2e-probe.example.com")


def test_fixture_session_is_accepted_on_the_console_platform_route():
    assert allowed(orq, fixture_token(), CONSOLE_ROUTE, host="console.example.com")


def test_fixture_session_is_redirected_on_a_real_org_route():
    """`allowed_users = "org"` 的真实站点放行任何可信邮箱——夹具会话必须在这里被 302，否则夹具签发器就是全组织的钥匙。"""
    resp = orq._check_auth(_req(fixture_token()), dict(ROUTE), "app-x.example.com")
    assert resp and resp["status"] == "302"


def test_fixture_session_on_a_real_route_that_lists_the_fixture_email_is_still_redirected():
    route = {**ROUTE, "allowed_users": ["probe@e2e.invalid"]}      # 数据层本该拒绝写入；Edge 独立再拒一次
    assert not allowed(orq, fixture_token(), route)


def test_fixture_marks_must_both_be_present_or_both_absent():
    assert not allowed(orq, site_token(idp="fixture"), FIXTURE_ROUTE, host="app-e2e-probe.example.com")
    assert not allowed(orq, site_token(auth_via="fixture-issuer"), FIXTURE_ROUTE, host="app-e2e-probe.example.com")


def test_a_real_idp_session_still_enters_a_fixture_site_when_listed():
    route = {**FIXTURE_ROUTE, "allowed_users": ["v@example.test"]}
    assert allowed(orq, site_token(), route, host="app-e2e-probe.example.com")


def test_fixture_domain_is_matched_exactly_on_the_owner():
    for owner in ("x@e2e.invalid.evil", "x@evil.e2e.invalid", "platform", "", "probe@E2E.INVALID"):
        assert not allowed(orq, fixture_token(), {**FIXTURE_ROUTE, "owner": owner}, host="app-e2e-probe.example.com"), owner


def test_fixture_literals_match_auth_session():
    assert (orq.FIXTURE_DOMAIN, orq.FIXTURE_IDP, orq.FIXTURE_AUTH_VIA) == \
        (auth_session.FIXTURE_DOMAIN, auth_session.FIXTURE_IDP, auth_session.FIXTURE_AUTH_VIA)


# ---- 与 auth/session.py 的字节等价（CLAUDE.md 不变量）----

def _segment(src: str, start: str, end: str) -> str:
    s = src.index(start)
    return src[s:src.index(end, s + 1)]


def test_edge_verifier_core_is_byte_identical_to_session_py():
    auth_src = (HERE.parents[2] / "site-builder" / "auth" / "session.py").read_text(encoding="utf-8")
    for start, end in (("def _b64url_decode_strict", "def _strict_json"),
                       ("def _strict_json", "def spki_sha256"),
                       ("def load_public_key_der", "def _rsa_verify"),
                       ("def _rsa_verify", "def local_signer")):
        assert _segment(auth_src, start, end).strip() == _segment(SRC, start, end.replace("local_signer", "_aud_matches") if end == "def local_signer" else end).strip(), start
    # verify_token 的判定段：auth 从 `try:` 到 `return claims`；Edge 的 _verify_site_session 同一段，只多 allowlist 取值行
    auth_body = _segment(auth_src, "def verify_token", "# 黄金三元组")
    edge_body = _segment(SRC, "def _verify_site_session", "def _get_cookies")
    a = auth_body[auth_body.index("    try:"):auth_body.rindex("return claims")]
    e = edge_body[edge_body.index("    try:"):edge_body.rindex("return claims")]
    e = e.replace("    allowlist = _site_allowlist()\n", "").replace('"site-session"', "token_use").replace(
        'TOKEN_USES["site-session"]', "TOKEN_USES[token_use]")
    assert a == e, "Edge 的验签判定段与 auth/session.py 分叉了"


def test_golden_triple_matches_auth_session():
    assert orq.RS256_GOLDEN == auth_session.RS256_GOLDEN


# ---- 源码守卫（spec §4.4：kid 不拼资源、allowlist 只按 kid 查表；§11.1：预热在顶层）----

def test_source_indexes_allowlist_only_by_kid_and_parses_it_once():
    verify = SRC[SRC.index("def _verify_site_session"):SRC.index("def _get_cookies")]
    indexes = re.findall(r"\ballowlist\[([^\]]+)\]", verify)
    assert indexes and all(i == "kid" for i in indexes), indexes
    assert "_site_allowlist()" in verify
    assert SRC.count("json.loads(SITE_ALLOWLIST_JSON)") == 1


def test_source_has_no_kid_derived_resource_paths():
    assert not re.search(r"(ssm|kms|s3|arn:)[^\n]*\bkid\b", SRC)


def test_source_has_no_hmac_no_legacy_and_no_shared_secret_left():
    for bad in ("hmac", "JWT_SECRET", "LEGACY_ENTRY", "_verify_legacy_site_session", "accepted_legacy", "HS256"):
        assert bad not in SRC, bad


def test_warmup_verify_happens_at_import_time_with_the_golden_triple():
    top = SRC[:SRC.index("def _site_allowlist")]
    assert "RS256_GOLDEN" in top and ".verify(" in top, "spec §11.1：预热验签必须在模块顶层"
    handler_side = SRC[SRC.index("def lambda_handler"):]
    assert "load_pem_public_key" not in SRC and "RS256_GOLDEN" not in handler_side


def test_public_key_parsing_stays_lazy_so_public_routes_survive_a_bad_injection():
    """D9：解析仍在首次使用（ticket 21）——注入坏掉时只有带 cookie 的私有请求 500。"""
    top = SRC[:SRC.index("def _site_allowlist")]
    assert "json.loads(SITE_ALLOWLIST_JSON)" not in top and "_load_public_key_der(base64" not in top
