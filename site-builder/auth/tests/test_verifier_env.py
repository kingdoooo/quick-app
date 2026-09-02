"""auth 与 panel 共用的 verifier 运行时装配（3c-1A code-review 修复：两处手写重复 → 一份，panel 复制）。"""
import json

import pytest

import verifier_env as ve

ROWS = {"site": [{"kid": "site-hs-v1", "alg": "HS256", "role": "current", "ssm_param": "/p/site"}],
        "console": [{"kid": "console-hs-v1", "alg": "HS256", "role": "current", "ssm_param": "/p/console"}]}
SECRETS = {"/p/site": "s", "/p/console": "c", "/p/legacy": "l"}


def test_load_allowlist_resolves_secrets_by_param_for_the_requested_family():
    al = ve.load_allowlist(json.dumps(ROWS), "site", SECRETS.__getitem__, allowed_families=("site", "console"))
    assert al == {"site-hs-v1": {"alg": "HS256", "secret": "s", "role": "current"}}


def test_load_allowlist_rejects_families_the_verifier_must_not_hold():
    """panel 只许持 console：SESSION_KEYS_JSON 里出现 site 就是部署配置错了。"""
    with pytest.raises(RuntimeError):
        ve.load_allowlist(json.dumps(ROWS), "console", SECRETS.__getitem__, allowed_families=("console",))


def test_load_allowlist_missing_or_invalid_env_raises_not_empty():
    with pytest.raises(RuntimeError):
        ve.load_allowlist(None, "site", SECRETS.__getitem__, allowed_families=("site",))
    with pytest.raises(RuntimeError):
        ve.load_allowlist("not json", "site", SECRETS.__getitem__, allowed_families=("site",))
    with pytest.raises(RuntimeError):
        ve.load_allowlist(json.dumps({"console": []}), "site", SECRETS.__getitem__, allowed_families=("site", "console"))


@pytest.mark.parametrize("flag,expect", [("on", "l"), ("off", None)])
def test_legacy_secret_follows_the_switch(flag, expect):
    assert ve.legacy_secret(flag, lambda: "l") == expect


@pytest.mark.parametrize("flag", [None, "", "yes", "ON", "1"])
def test_legacy_secret_rejects_anything_but_on_off(flag):
    with pytest.raises(RuntimeError):
        ve.legacy_secret(flag, lambda: "l")


def test_log_verify_prints_fixed_vocabulary_and_swallows_errors(capsys):
    ve.log_verify("auth", "accepted_current")
    row = json.loads(capsys.readouterr().out.strip())
    assert row == {"event": "session_verify", "verifier": "auth", "outcome": "accepted_current"}
    ve.log_verify("auth", object())      # 不可序列化也不能抛
