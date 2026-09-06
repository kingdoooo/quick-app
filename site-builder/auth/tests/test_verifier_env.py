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


# ---- 3c-1B：signer 侧的两件装配 ---------------------------------------------------------

def test_signing_key_returns_the_current_kid_and_its_secret():
    assert ve.signing_key(json.dumps(ROWS), "site", SECRETS.__getitem__,
                          allowed_families=("site", "console")) == ("site-hs-v1", "s")
    assert ve.signing_key(json.dumps(ROWS), "console", SECRETS.__getitem__,
                          allowed_families=("site", "console")) == ("console-hs-v1", "c")


def test_signing_key_ignores_previous_and_never_signs_with_it():
    """就位期（十步的 ⑥）两把都在 allowlist 里；签发只能用 current，否则新 key 一就位就开始签。"""
    rows = {"site": ROWS["site"] + [{"kid": "site-hs-v2", "alg": "HS256", "role": "previous",
                                     "ssm_param": "/p/site2"}]}
    kid, secret = ve.signing_key(json.dumps(rows), "site",
                                 dict(SECRETS, **{"/p/site2": "s2"}).__getitem__,
                                 allowed_families=("site",))
    assert (kid, secret) == ("site-hs-v1", "s")


def test_signing_key_does_not_even_read_the_previous_secret(monkeypatch):
    """**不只是"不用它签"，而是根本不去取它的值**（3c-1B-G B1）。

    `/callback` 每次登录都调 `signing_key`（ticket 20 把它提前到烧授权码之前）。原先它经
    `load_allowlist` 把 family 里**每个** kid 的 secret 都 `get_secret` 一遍 ⇒ 签发硬依赖
    previous 参数可读。两个后果：
      · 十步的 ⑩ 若先删了退役 key 的 SSM 参数、再重部 auth/panel，**每次登录 500**——
        而缺的那把是"没人再用它签"的那一把；
      · 冷缓存下每次登录 2 次 `GetParameter`，而只需要 1 次。
    """
    rows = {"site": ROWS["site"] + [{"kid": "site-hs-v2", "alg": "HS256", "role": "previous",
                                     "ssm_param": "/p/site2"}]}
    asked = []

    def _get(param):
        asked.append(param)
        return dict(SECRETS, **{"/p/site2": "s2"})[param]

    kid, secret = ve.signing_key(json.dumps(rows), "site", _get, allowed_families=("site",))
    assert (kid, secret) == ("site-hs-v1", "s")
    assert asked == ["/p/site"], f"取了不该取的参数：{asked}"


def test_load_allowlist_still_resolves_every_row_because_verifying_needs_them_all():
    """验签侧必须拿到**所有** role 的 secret——B1 只收窄签发那条路，不能顺手收窄验签。"""
    rows = {"site": ROWS["site"] + [{"kid": "site-hs-v2", "alg": "HS256", "role": "previous",
                                     "ssm_param": "/p/site2"}]}
    asked = []

    def _get(param):
        asked.append(param)
        return dict(SECRETS, **{"/p/site2": "s2"})[param]

    al = ve.load_allowlist(json.dumps(rows), "site", _get, allowed_families=("site",))
    assert set(al) == {"site-hs-v1", "site-hs-v2"}
    assert al["site-hs-v2"]["secret"] == "s2"
    assert sorted(asked) == ["/p/site", "/p/site2"]


def test_signing_key_rejects_families_the_component_must_not_sign_for():
    """panel 只持 console：拿 site 去签就是配置错（等于 panel 能伪造站点会话）。"""
    with pytest.raises(RuntimeError):
        ve.signing_key(json.dumps(ROWS), "site", SECRETS.__getitem__, allowed_families=("console",))


@pytest.mark.parametrize("rows, why", [
    ({"site": []}, "family 里没有任何 kid"),
    ({"site": [dict(ROWS["site"][0], role="previous")]}, "只有 previous、没有 current"),
    ({"site": [ROWS["site"][0], {"kid": "site-hs-v2", "alg": "HS256", "role": "current",
                                 "ssm_param": "/p/site"}]}, "两个 current（签哪把成了字典序的副产品）"),
])
def test_signing_key_requires_exactly_one_current(rows, why):
    with pytest.raises(RuntimeError):
        ve.signing_key(json.dumps(rows), "site", SECRETS.__getitem__, allowed_families=("site",))
    del why


@pytest.mark.parametrize("flag", ["legacy", "current"])
def test_signer_mode_passes_through_the_two_legal_values(flag):
    assert ve.signer_mode(flag) == flag


@pytest.mark.parametrize("flag", [None, "", "on", "off", "Current", "LEGACY", "1", "true"])
def test_signer_mode_rejects_anything_else_and_never_defaults(flag):
    """缺失/非法都必须是"部署脚本没下发"，不许回落——回落哪一侧都是静默的错签发形态。"""
    with pytest.raises(RuntimeError, match="SESSION_SIGNER"):
        ve.signer_mode(flag)


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
