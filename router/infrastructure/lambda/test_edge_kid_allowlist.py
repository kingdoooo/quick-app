"""Edge 内嵌 verifier 认 site family 的 kid allowlist + legacy 入口开关（plan 3c-1A Task 3）。

先于实现写下并跑红。Edge 拿不到 auth 包，所以这里 import `auth/session.py` 的**生产 mint**
做跨组件正向向量（新入口一条、legacy 入口一条），负向按 spec §9。
"""
import base64
import hashlib
import hmac
import importlib
import json
import logging
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
_AUTH = HERE.parents[2] / "site-builder" / "auth"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(_AUTH))
import session as auth_session  # noqa: E402

SITE_V1, SITE_V0, CONSOLE_V1, LEGACY = "site-secret-v1", "site-secret-v0", "console-secret-v1", "test-secret"
ALLOWLIST = {"site-hs-v1": {"alg": "HS256", "secret": SITE_V1, "role": "current"},
             "site-hs-v0": {"alg": "HS256", "secret": SITE_V0, "role": "previous"}}
BASE_SUBS = {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
             "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
             "{{JWT_SECRET}}": LEGACY, "{{BASE_DOMAIN}}": "example.com",
             "{{REQUIRE_IDP_CLAIM}}": "true", "{{TRUSTED_IDPS}}": "Feishu,Okta",
             "{{ACCESS_TABLE}}": "site-access-events",
             "{{ACCESS_REPLICA_REGIONS}}": "us-east-1"}
SRC = (HERE / "origin_request.py").read_text()


def _load(name: str, legacy_entry: str):
    src = SRC
    for k, v in dict(BASE_SUBS, **{"{{SITE_ALLOWLIST_JSON}}": json.dumps(ALLOWLIST),
                                   "{{LEGACY_ENTRY}}": legacy_entry}).items():
        src = src.replace(k, v)
    (HERE / f"{name}.py").write_text(src)
    return importlib.import_module(name)


orq = _load("_edge_kid_testable", "on")
orq_off = _load("_edge_kid_legacy_off_testable", "off")

ROUTE = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x", "api_target": "",
         "require_auth": True, "allowed_users": "org", "owner": "o@example.test"}


def _req(token: str):
    return {"uri": "/", "querystring": "", "method": "GET",
            "headers": {"host": [{"key": "Host", "value": "app-x.example.com"}],
                        "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}


def allowed(mod, token: str) -> bool:
    resp = mod._check_auth(_req(token), dict(ROUTE), "app-x.example.com")
    return resp is None


def b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def resign(token: str, secret: str, *, header=None, payload=None) -> str:
    h, p, _ = token.split(".")
    h2 = b64(unb64(h) if header is None else header)
    p2 = b64(unb64(p) if payload is None else payload)
    sig = b64(hmac.new(secret.encode(), f"{h2}.{p2}".encode(), hashlib.sha256).digest())
    return f"{h2}.{p2}.{sig}"


def site_token(**kw) -> str:
    args = dict(kid="site-hs-v1", secret=SITE_V1, token_use="site-session", email="v@example.test",
                ttl_seconds=600, name="V", idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    args.update(kw)
    return auth_session.mint_token(**args)


def legacy_token(**kw) -> str:
    args = dict(email="v@example.test", name="V", secret=LEGACY, idp="Feishu",
                auth_via="TokenGeneration_HostedAuth")
    args.update(kw)
    return auth_session.mint_session_jwt(args.pop("email"), args.pop("name"), args.pop("secret"), **args)


# ---- 跨组件正向向量（auth 真签的 token 必须过 Edge）--------------------------------

def test_auth_minted_current_kid_token_verifies_at_the_edge():
    assert allowed(orq, site_token())
    claims = orq._verify_session_jwt(site_token())
    assert claims and claims["email"] == "v@example.test"


def test_auth_minted_previous_kid_token_verifies_at_the_edge():
    assert allowed(orq, site_token(kid="site-hs-v0", secret=SITE_V0))


def test_auth_minted_legacy_token_verifies_while_legacy_entry_is_on():
    assert allowed(orq, legacy_token())


def test_verify_function_keeps_its_contract_for_check_auth():
    """`_check_auth` 不动：`_verify_session_jwt(token)` 仍返回 claims 或 None。"""
    assert orq._verify_session_jwt("garbage") is None
    assert isinstance(orq._verify_session_jwt(site_token()), dict)


# ---- legacy 入口开关 -----------------------------------------------------------------

def test_legacy_token_is_rejected_when_legacy_entry_is_off():
    assert not allowed(orq_off, legacy_token())
    assert allowed(orq_off, site_token())      # 新入口不受开关影响


def test_legacy_console_scoped_session_is_rejected_at_the_edge():
    """旧合同的 site 会话 = typ=session 且**无 scope**；console 会话即使签名对也不是站点会话。"""
    assert not allowed(orq, legacy_token(scope="console"))


# ---- §9 反例 -----------------------------------------------------------------------------

def test_console_kid_is_not_in_the_edge_allowlist():
    tok = auth_session.mint_token(kid="console-hs-v1", secret=CONSOLE_V1, token_use="site-session",
                                  email="v@example.test", ttl_seconds=600, name="V",
                                  idp="Feishu", auth_via="TokenGeneration_HostedAuth")
    assert not allowed(orq, tok)


def test_console_session_new_form_is_rejected_at_the_edge():
    tok = auth_session.mint_token(kid="console-hs-v1", secret=CONSOLE_V1, token_use="console-session",
                                  email="v@example.test", ttl_seconds=600, name="V")
    assert not allowed(orq, tok)


def test_unknown_kid_does_not_fall_back_to_the_legacy_entry():
    """签名用的是 legacy 密钥、payload 是旧合同、legacy 入口开着：只因 header 带了未知 kid 就必须拒。"""
    tok = resign(legacy_token(), LEGACY, header={"alg": "HS256", "typ": "JWT", "kid": "site-hs-v7"})
    assert not allowed(orq, tok)


def test_wrong_token_use_is_rejected():
    tok = auth_session.mint_token(kid="site-hs-v1", secret=SITE_V1, token_use="console-session",
                                  email="v@example.test", ttl_seconds=600, name="V")
    assert not allowed(orq, tok)


def test_aud_as_list_is_rejected():
    tok = site_token()
    pl = unb64(tok.split(".")[1])
    pl["aud"] = ["site-edge"]
    assert not allowed(orq, resign(tok, SITE_V1, payload=pl))


def test_alg_none_with_known_kid_is_rejected():
    tok = resign(site_token(), SITE_V1, header={"alg": "none", "typ": "JWT", "kid": "site-hs-v1"})
    assert not allowed(orq, tok.rsplit(".", 1)[0] + ".")


def test_third_key_under_known_kid_is_rejected():
    assert not allowed(orq, resign(site_token(), "third-key"))


def test_expired_kid_token_is_rejected():
    assert not allowed(orq, site_token(ttl_seconds=1, now=int(time.time()) - 5))


def test_idp_and_auth_via_are_still_required_on_the_new_entry():
    """新入口验完签名后仍走 REQUIRE_IDP_CLAIM 那段：缺 idp/auth_via 的新形态 token 照样 302。"""
    assert not allowed(orq, site_token(idp="", auth_via=""))
    assert not allowed(orq, site_token(auth_via="TokenGeneration_Authentication"))


# ---- 观测：outcome 进日志，token 不进 ----------------------------------------------------

def test_outcome_is_logged_as_fixed_vocabulary_without_the_token(caplog):
    tok = site_token()
    with caplog.at_level(logging.INFO):
        orq._verify_session_jwt(tok)
        orq._verify_session_jwt(resign(tok, LEGACY, header={"alg": "HS256", "typ": "JWT", "kid": "nope"}))
    events = []
    for rec in caplog.records:
        msg = rec.getMessage()
        for seg in tok.split("."):
            assert seg not in msg, "日志里出现了 token 片段"
        if msg.startswith("{") and '"session_verify"' in msg:
            events.append(json.loads(msg)["outcome"])
    assert events == ["accepted_current", "unknown_kid"]
    assert set(events) <= set(auth_session.OUTCOMES)


# ---- 源码守卫（spec §4.4：kid 不拼资源、allowlist 只按 kid 查表）------------------------------

def test_source_indexes_allowlist_only_by_kid_and_parses_it_once():
    assert SRC.count("json.loads(SITE_ALLOWLIST_JSON)") == 1
    indexes = re.findall(r"_SITE_ALLOWLIST\[([^\]]+)\]", SRC)
    assert indexes and set(indexes) == {"kid"}, indexes
    assert "SITE_ALLOWLIST_JSON = '''{{SITE_ALLOWLIST_JSON}}'''" in SRC
    assert 'LEGACY_ENTRY = "{{LEGACY_ENTRY}}"' in SRC


def test_source_has_no_kid_derived_resource_paths():
    """kid 不得进 f-string / 拼接去构造路径、参数名、ARN。"""
    for m in re.finditer(r"f\"[^\"]*\{kid\}[^\"]*\"|f'[^']*\{kid\}[^']*'", SRC):
        assert False, f"kid 被拼进字符串：{m.group(0)}"
