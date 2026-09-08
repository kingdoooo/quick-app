"""auth 与 panel 共用的 verifier 运行时装配（RS-only）。"""
import json

import pytest

import upgrade_code_vectors as v
import verifier_env as ve

ENV = v.session_keys_json((v.SITE_KID, "current"), (v.SITE_PREV_KID, "previous"), (v.CONSOLE_KID, "current"))
CONSOLE_ONLY = v.session_keys_json((v.CONSOLE_KID, "current"))


def _get(kms=None):
    import session_kms
    return session_kms.public_key_loader(kms or v.FakeKms())


def test_load_allowlist_resolves_public_keys_by_arn_for_the_requested_family():
    al = ve.load_allowlist(ENV, "site", _get(), allowed_families=("site", "console"))
    assert set(al) == {v.SITE_KID, v.SITE_PREV_KID}
    assert al[v.SITE_KID]["alg"] == "RS256" and al[v.SITE_KID]["role"] == "current"
    assert al[v.SITE_KID]["public_key"].public_numbers() == v.SITE_KEY.public_key().public_numbers()
    assert al[v.SITE_PREV_KID]["role"] == "previous"


def test_load_allowlist_rejects_families_the_verifier_must_not_hold():
    with pytest.raises(RuntimeError, match="不该持有"):
        ve.load_allowlist(ENV, "console", _get(), allowed_families=("console",))


def test_load_allowlist_missing_or_invalid_env_raises_not_empty():
    with pytest.raises(RuntimeError):
        ve.load_allowlist(None, "site", _get(), allowed_families=("site",))
    with pytest.raises(RuntimeError):
        ve.load_allowlist("{not json", "site", _get(), allowed_families=("site",))
    with pytest.raises(RuntimeError, match="没有 site"):
        ve.load_allowlist(CONSOLE_ONLY, "site", _get(), allowed_families=("site", "console"))


def test_load_allowlist_fails_closed_when_a_public_key_does_not_match_its_fingerprint():
    import session_kms
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_PREV_KID]] = v.CONSOLE_KEY
    with pytest.raises(session_kms.KeyMaterialMismatch):
        ve.load_allowlist(ENV, "site", _get(kms), allowed_families=("site", "console"))


def test_signing_ref_returns_the_current_row_without_touching_kms():
    kms = v.FakeKms()
    assert ve.signing_ref(ENV, "site", allowed_families=("site", "console")) == \
        (v.SITE_KID, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert kms.calls == []


def test_signing_ref_previous_returns_the_previous_row_or_fails_loudly():
    assert ve.signing_ref(ENV, "site", allowed_families=("site", "console"), role="previous")[0] == v.SITE_PREV_KID
    with pytest.raises(RuntimeError, match="previous"):
        ve.signing_ref(ENV, "console", allowed_families=("site", "console"), role="previous")
    with pytest.raises(RuntimeError, match="role"):
        ve.signing_ref(ENV, "site", allowed_families=("site", "console"), role="legacy")


def test_signing_ref_rejects_families_the_component_must_not_sign_for():
    with pytest.raises(RuntimeError, match="不该持有"):
        ve.signing_ref(ENV, "site", allowed_families=("console",))


@pytest.mark.parametrize("rows,why", [
    ([], "0 个 current"),
    ([{"kid": v.SITE_KID, "alg": "RS256", "role": "current", "key_arn": v.KEY_ARN[v.SITE_KID], "spki_sha256": "0" * 64},
      {"kid": v.SITE_PREV_KID, "alg": "RS256", "role": "current", "key_arn": v.KEY_ARN[v.SITE_PREV_KID], "spki_sha256": "0" * 64}], "2 个 current"),
])
def test_signing_ref_requires_exactly_one_current(rows, why):
    with pytest.raises(RuntimeError, match="恰好 1"):
        ve.signing_ref(json.dumps({"site": rows}), "site", allowed_families=("site",)), why


def test_removed_hs_helpers_are_gone():
    for name in ("signing_key", "signer_mode", "legacy_secret"):
        assert not hasattr(ve, name), name


def test_log_verify_prints_fixed_vocabulary_and_swallows_errors(capsys):
    ve.log_verify("auth", "accepted_current")
    assert json.loads(capsys.readouterr().out) == {"event": "session_verify", "verifier": "auth", "outcome": "accepted_current"}
    ve.log_verify("auth", object())        # json 不可序列化：吞掉，不抛
