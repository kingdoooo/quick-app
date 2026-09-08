"""auth 的 `POST /fixture-session`（spec §11.7 / ADR 0002）：只对 site-builder-verifier、只签夹具域、只签站点会话。"""
import json
from unittest.mock import patch

import pytest

import login_handler as lh
import session
import upgrade_code_vectors as v
from test_login_handler import ENV

ON = dict(ENV, FIXTURE_ISSUER="on")
WITH_PREVIOUS = dict(ON, SESSION_KEYS_JSON=v.session_keys_json(
    (v.SITE_KID, "current"), (v.SITE_PREV_KID, "previous"), (v.CONSOLE_KID, "current")))
VERIFIER = "arn:aws:sts::111111111111:assumed-role/site-builder-verifier/probe-1"


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:111111111111:function:site-auth-service"


def _event(body, *, caller=VERIFIER, method="POST"):
    return {"rawPath": "/fixture-session", "queryStringParameters": {}, "cookies": [],
            "body": json.dumps(body) if isinstance(body, dict) else body,
            "requestContext": {"http": {"method": method}, "authorizer": {"iam": {"userArn": caller}}}}


def _call(env, body, **kw):
    with patch.dict(lh.os.environ, env):
        return lh.handler(_event(body, **kw), _Ctx())


def test_is_404_when_the_component_is_not_configured():
    assert _call(ENV, {"email": "p@e2e.invalid"})["statusCode"] == 404


def test_issues_a_site_session_for_a_fixture_email_that_verifies_under_the_site_key():
    r = _call(ON, {"email": "probe@e2e.invalid", "ttl_seconds": 600, "name": "Probe"})
    assert r["statusCode"] == 200 and r["headers"]["cache-control"] == "no-store" and "cookies" not in r
    body = json.loads(r["body"])
    assert body["kid"] == v.SITE_KID and body["ttl_seconds"] == 600
    claims, outcome = session.verify_token(body["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
    assert outcome == "accepted_current"
    assert (claims["email"], claims["name"], claims["idp"], claims["auth_via"]) == \
        ("probe@e2e.invalid", "Probe", "fixture", "fixture-issuer")
    assert claims["exp"] - claims["iat"] == 600


def test_ttl_is_capped_at_thirty_minutes_and_defaults_to_it():
    for body, want in (({"email": "p@e2e.invalid"}, 1800), ({"email": "p@e2e.invalid", "ttl_seconds": 99999}, 1800),
                       ({"email": "p@e2e.invalid", "ttl_seconds": 5}, 5)):
        out = json.loads(_call(ON, body)["body"])
        claims, _ = session.verify_token(out["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
        assert claims["exp"] - claims["iat"] == want and out["ttl_seconds"] == want


@pytest.mark.parametrize("email", ["a@example.com", "a@e2e.invalid.evil.com", "a@evil.e2e.invalid", "e2e.invalid",
                                   "", None, 5, "a@E2E.INVALID"])
def test_non_fixture_emails_are_refused(email):
    r = _call(ON, {"email": email})
    assert r["statusCode"] == 400, email


@pytest.mark.parametrize("caller", [
    "arn:aws:sts::111111111111:assumed-role/site-edge-role/edge",          # Edge role 能调同一个 URL，必须在这里也拒
    "arn:aws:iam::111111111111:user/kent",
    "arn:aws:sts::222222222222:assumed-role/site-builder-verifier/x",       # 别的账号同名角色
    "arn:aws:sts::111111111111:assumed-role/site-builder-verifier-2/x",
    "", None])
def test_only_the_verifier_role_of_this_account_may_call(caller):
    assert _call(ON, {"email": "p@e2e.invalid"}, caller=caller)["statusCode"] == 403


def test_get_is_not_allowed():
    assert _call(ON, {"email": "p@e2e.invalid"}, method="GET")["statusCode"] == 405


def test_garbage_body_is_400_not_500():
    assert _call(ON, "{not json")["statusCode"] == 400
    assert _call(ON, "[]")["statusCode"] == 400


def test_role_previous_signs_with_the_previous_site_kid_or_fails_when_there_is_none():
    out = json.loads(_call(WITH_PREVIOUS, {"email": "p@e2e.invalid", "role": "previous"})["body"])
    assert out["kid"] == v.SITE_PREV_KID
    al = {**v.SITE_ALLOWLIST, v.SITE_PREV_KID: v.public_entry(v.SITE_PREV_KEY, "previous")}
    assert session.verify_token(out["token"], allowlist=al, token_use="site-session")[1] == "accepted_previous"
    assert _call(ON, {"email": "p@e2e.invalid", "role": "previous"})["statusCode"] == 400
    assert _call(ON, {"email": "p@e2e.invalid", "role": "legacy"})["statusCode"] == 400


def test_fixture_session_never_carries_a_real_idp_or_auth_via():
    out = json.loads(_call(ON, {"email": "p@e2e.invalid", "idp": "Feishu", "auth_via": "TokenGeneration_HostedAuth"})["body"])
    claims, _ = session.verify_token(out["token"], allowlist=v.SITE_ALLOWLIST, token_use="site-session")
    assert (claims["idp"], claims["auth_via"]) == ("fixture", "fixture-issuer"), "请求体不许指定来源标记"


def test_fixture_session_is_only_ever_a_site_session(_fake_platform_clients):
    kms = _fake_platform_clients
    _call(ON, {"email": "p@e2e.invalid"})
    signs = [c for c in kms.calls if c[0] == "sign"]
    assert signs and all(c[1] == v.KEY_ARN[v.SITE_KID] for c in signs), "夹具签发只许用 site family 的 key"


def test_issue_is_logged_without_the_token(_fake_platform_clients, capsys):
    out = json.loads(_call(ON, {"email": "p@e2e.invalid"})["body"])
    logs = capsys.readouterr().out
    assert '"event": "fixture_session_issued"' in logs and "p@e2e.invalid" in logs and out["token"] not in logs
