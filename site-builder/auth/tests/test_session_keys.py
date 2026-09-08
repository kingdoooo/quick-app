"""`[SessionKeys]` 的加载与校验（RS-only，3c-final）。"""
import json
import textwrap

import pytest

import session_keys as sk
import upgrade_code_vectors as v

RS = textwrap.dedent(f"""
    [SessionKeys]
    site_current = site-rs-v1
    site_previous =
    console_current = console-rs-v1
    console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_KEY)}

    [SessionKey:console-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.CONSOLE_KID]}
    spki_sha256 = {v.spki_hex(v.CONSOLE_KEY)}
""")
RS_WITH_PREVIOUS = RS.replace("site_previous =", "site_previous = site-rs-v0") + textwrap.dedent(f"""
    [SessionKey:site-rs-v0]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_PREV_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_PREV_KEY)}
""")


def _load(tmp_path, text):
    p = tmp_path / "config.ini"
    p.write_text(text)
    return sk.load_session_keys(p)


def test_minimal_config_loads_two_families_with_no_previous(tmp_path):
    keys = _load(tmp_path, RS)
    assert [r.kid for r in keys.allowlist("site")] == ["site-rs-v1"]
    assert [r.kid for r in keys.allowlist("console")] == ["console-rs-v1"]
    ref = keys.allowlist("site")[0]
    assert (ref.alg, ref.role, ref.key_arn, ref.spki_sha256) == ("RS256", "current", v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert keys.login_flow_secret_param == "/site-builder/login-flow-secret"


def test_session_keys_has_no_signer_and_no_legacy_fields(tmp_path):
    keys = _load(tmp_path, RS)
    assert not hasattr(keys, "signer") and not hasattr(keys, "legacy_param")
    assert not hasattr(sk, "legacy_entry") and not hasattr(sk, "SIGNER_MODES") and not hasattr(sk, "HS_PARAM_PREFIX")


def test_previous_is_loaded_and_ordered_after_current(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    assert [(r.kid, r.role) for r in keys.allowlist("site")] == [("site-rs-v1", "current"), ("site-rs-v0", "previous")]


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace("site_current = site-rs-v1", "site_current = site-hs-v1"), "HS kid 不再合法"),
    (lambda t: t.replace("alg = RS256\nkey_arn = " + v.KEY_ARN[v.SITE_KID], "alg = HS256\nkey_arn = " + v.KEY_ARN[v.SITE_KID]), "alg 只许 RS256"),
    (lambda t: t.replace(v.KEY_ARN[v.SITE_KID], "alias/site-builder/session/site-rs-v1"), "alias 不接受"),
    (lambda t: t.replace(v.spki_hex(v.SITE_KEY), "abc"), "spki 必须 64 位 hex"),
    (lambda t: t.replace("[SessionKey:console-rs-v1]", "[SessionKey:console-rs-v2]"), "缺小节"),
    (lambda t: t.replace("site_current = site-rs-v1", "site_current ="), "缺 current"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param ="), "缺 login-flow"),
    (lambda t: t.replace("[SessionKeys]", "[SessionKeys]\nsigner = current"), "signer 键已删——出现即配置错"),
    (lambda t: t.replace("[SessionKeys]", "[SessionKeys]\nlegacy_param = /site-builder/jwt-secret"), "legacy_param 键已删——出现即配置错"),
    (lambda t: t.replace("[SessionKey:site-rs-v1]\nalg = RS256", "[SessionKey:site-rs-v1]\nalg = RS256\nssm_param = /x"), "RS 行不许带 ssm_param"),
])
def test_misconfiguration_raises_instead_of_falling_back(tmp_path, mutate, why):
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, mutate(RS)), why


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace(v.KEY_ARN[v.CONSOLE_KID], v.KEY_ARN[v.SITE_KID]), "两个 kid 指向同一把 CMK"),
    (lambda t: t.replace(v.spki_hex(v.CONSOLE_KEY), v.spki_hex(v.SITE_KEY)), "两个 kid 同一个公钥指纹"),
])
def test_rs_key_material_must_be_unique_across_families(tmp_path, mutate, why):
    with pytest.raises(sk.SessionKeysError, match="同一"):
        _load(tmp_path, mutate(RS)), why


def test_inline_comments_are_stripped_not_folded_into_values(tmp_path):
    keys = _load(tmp_path, RS.replace("site_current = site-rs-v1", "site_current = site-rs-v1   # 当前"))
    assert keys.allowlist("site")[0].kid == "site-rs-v1"


def test_missing_file_is_an_error_not_an_empty_config(tmp_path):
    with pytest.raises(sk.SessionKeysError):
        sk.load_session_keys(tmp_path / "nope.ini")


def test_error_type_is_a_value_error_so_callers_cannot_swallow_it_as_config_missing():
    assert issubclass(sk.SessionKeysError, ValueError)


def test_example_config_in_repo_loads():
    from pathlib import Path
    keys = sk.load_session_keys(Path(__file__).resolve().parents[2] / "config.ini.example")
    assert {r.kid for f in sk.FAMILIES for r in keys.allowlist(f)} == {"site-rs-v1", "console-rs-v1"}


def test_env_json_carries_only_requested_families_and_no_values(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    console = json.loads(sk.env_json(keys, ("console",)))
    assert list(console) == ["console"]
    assert console["console"] == [{"kid": "console-rs-v1", "alg": "RS256", "role": "current",
                                   "key_arn": v.KEY_ARN[v.CONSOLE_KID], "spki_sha256": v.spki_hex(v.CONSOLE_KEY)}]
    both = json.loads(sk.env_json(keys, ("site", "console")))
    assert [r["kid"] for r in both["site"]] == ["site-rs-v1", "site-rs-v0"]
    with pytest.raises(sk.SessionKeysError):
        sk.env_json(keys, ("edge",))


def test_kms_key_arns_is_the_single_builder_for_iam_resources(tmp_path):
    keys = _load(tmp_path, RS_WITH_PREVIOUS)
    assert sk.kms_key_arns(keys, ("site", "console")) == [v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.SITE_PREV_KID], v.KEY_ARN[v.CONSOLE_KID]]
    assert sk.kms_key_arns(keys, ("console",)) == [v.KEY_ARN[v.CONSOLE_KID]]
    assert [r.kid for r in sk.key_refs(keys, ("site",))] == ["site-rs-v1", "site-rs-v0"]


def test_ssm_parameter_names_is_login_flow_and_extras_only(tmp_path):
    keys = _load(tmp_path, RS)
    assert sk.ssm_parameter_names(keys, ("site", "console")) == []
    assert sk.ssm_parameter_names(keys, ("site", "console"), login_flow=True, extra=("/x",)) == \
        ["/site-builder/login-flow-secret", "/x"]
    assert sk.ssm_parameter_arns(keys, ("site",), region="us-east-1", account="1", login_flow=True) == \
        ["arn:aws:ssm:us-east-1:1:parameter/site-builder/login-flow-secret"]


def test_login_flow_secret_is_loaded_but_belongs_to_no_family(tmp_path):
    keys = _load(tmp_path, RS)
    assert "login-flow" not in sk.env_json(keys, ("site", "console"))
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, RS.replace("/site-builder/login-flow-secret", "relative/path"))


def test_synth_placeholder_allowlist_is_valid_json_but_can_never_match_a_kid():
    data = json.loads(sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON)
    (kid, entry), = data.items()
    assert not sk.KID_RE.match(kid) and "SYNTH-ONLY-PLACEHOLDER" in kid
    assert entry["alg"] == "RS256" and set(entry) == {"alg", "spki_b64", "role"}
    assert "\\" not in sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON and "'''" not in sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON
