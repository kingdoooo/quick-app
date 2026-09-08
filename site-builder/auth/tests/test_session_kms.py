"""`session_kms.py`：部署前四项、verifier 公钥加载、KMS 签名器（spec §11.2 / §11.5 / §11.6）。"""
import pytest

import session
import session_kms as sm
import upgrade_code_vectors as v
from session_keys import KeyRef


def _ref(kid=v.SITE_KID, key=v.SITE_KEY, **kw):
    base = dict(kid=kid, family=kid.split("-")[0], alg="RS256", role="current",
                key_arn=v.KEY_ARN[kid], spki_sha256=v.spki_hex(key))
    base.update(kw)
    return KeyRef(**base)


def test_describe_public_key_returns_der_and_fingerprint_without_needing_a_configured_value():
    der, fp = sm.describe_public_key(v.FakeKms(), v.KEY_ARN[v.SITE_KID])
    assert der == v.spki_der(v.SITE_KEY) and fp == v.spki_hex(v.SITE_KEY)


def test_fetch_verified_public_key_der_passes_the_four_checks_for_a_matching_key():
    assert sm.fetch_verified_public_key_der(v.FakeKms(), _ref()) == v.spki_der(v.SITE_KEY)


@pytest.mark.parametrize("override,why", [
    ({"KeySpec": "RSA_4096"}, "KeySpec 不是 RSA_2048"),
    ({"KeyUsage": "ENCRYPT_DECRYPT"}, "KeyUsage 不是 SIGN_VERIFY"),
    ({"SigningAlgorithms": ["RSASSA_PSS_SHA_256"]}, "不含 RSASSA_PKCS1_V1_5_SHA_256"),
    ({"KeyState": "PendingDeletion"}, "key 不是 Enabled"),
])
def test_each_describe_key_check_fails_loudly(override, why):
    kms = v.FakeKms()
    kms.describe_overrides[v.KEY_ARN[v.SITE_KID]] = override
    with pytest.raises(sm.KeyMaterialMismatch):
        sm.fetch_verified_public_key_der(kms, _ref()), why


def test_fingerprint_mismatch_is_the_fourth_check():
    with pytest.raises(sm.KeyMaterialMismatch, match="spki_sha256"):
        sm.fetch_verified_public_key_der(v.FakeKms(), _ref(spki_sha256="0" * 64))


def test_tampered_public_key_is_caught_by_the_fingerprint_not_by_luck():
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    with pytest.raises(sm.KeyMaterialMismatch, match="spki_sha256"):
        sm.fetch_verified_public_key_der(kms, _ref())


def test_precheck_keys_lists_every_mismatch_and_exits_before_any_write(capsys):
    kms = v.FakeKms()
    kms.describe_overrides[v.KEY_ARN[v.CONSOLE_KID]] = {"KeyUsage": "ENCRYPT_DECRYPT"}
    with pytest.raises(SystemExit) as ei:
        sm.precheck_keys(kms, [_ref(), _ref(v.CONSOLE_KID, v.CONSOLE_KEY, spki_sha256="0" * 64)])
    msg = str(ei.value)
    assert "console-rs-v1" in msg and "KeyUsage" in msg and "spki_sha256" in msg and "site-rs-v1" not in msg


class _GetPublicKeyRaises(v.FakeKms):
    """真 KMS 对 pending-deletion / disabled 的 key 会拒 GetPublicKey；FakeKms 默认不建模 key state，
    这个替身把那条 AWS 行为补上（DescribeKey 照常，GetPublicKey 抛）。"""

    def get_public_key(self, KeyId):
        self.calls.append(("get_public_key", KeyId))
        raise RuntimeError("KMSInvalidStateException: PendingDeletion")


def test_get_public_key_failure_is_folded_into_key_material_mismatch_naming_the_kid():
    kms = _GetPublicKeyRaises()
    with pytest.raises(sm.KeyMaterialMismatch) as ei:
        sm.fetch_verified_public_key_der(kms, _ref())
    msg = str(ei.value)
    assert v.SITE_KID in msg and "GetPublicKey" in msg and "KMSInvalidStateException" in msg


def test_precheck_keys_still_lists_the_kid_when_get_public_key_raises():
    kms = _GetPublicKeyRaises()
    with pytest.raises(SystemExit) as ei:
        sm.precheck_keys(kms, [_ref()])
    assert v.SITE_KID in str(ei.value) and "GetPublicKey" in str(ei.value)


def test_precheck_keys_is_silent_and_read_only_when_everything_matches():
    kms = v.FakeKms()
    sm.precheck_keys(kms, [_ref(), _ref(v.CONSOLE_KID, v.CONSOLE_KEY)])
    assert {c[0] for c in kms.calls} == {"describe_key", "get_public_key"}


def test_public_key_loader_caches_per_arn_and_checks_the_fingerprint():
    kms = v.FakeKms()
    get = sm.public_key_loader(kms)
    pub = get(v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert pub.public_numbers() == v.SITE_KEY.public_key().public_numbers()
    get(v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert [c for c in kms.calls if c[0] == "get_public_key"] == [("get_public_key", v.KEY_ARN[v.SITE_KID])]
    with pytest.raises(sm.KeyMaterialMismatch):
        get(v.KEY_ARN[v.CONSOLE_KID], "f" * 64)


def test_signer_signs_raw_with_the_contract_algorithm_and_the_signature_verifies():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    tok = session.mint_token(kid=v.SITE_KID, sign=signer, token_use="site-session", email="a@x.com", ttl_seconds=60)
    assert session.verify_token(tok, allowlist=v.SITE_ALLOWLIST, token_use="site-session")[1] == "accepted_current"
    sign_calls = [c for c in kms.calls if c[0] == "sign"]
    assert sign_calls and sign_calls[0][2:4] == ("RAW", "RSASSA_PKCS1_V1_5_SHA_256")


def test_signer_self_checks_the_public_key_once_at_first_use_then_only_signs():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    signer(b"a.b"); signer(b"a.c")
    assert [c[0] for c in kms.calls] == ["get_public_key", "sign", "sign"]


def test_signer_refuses_to_sign_when_the_self_check_fails():
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(sm.KeyMaterialMismatch):
        signer(b"a.b")
    assert not [c for c in kms.calls if c[0] == "sign"], "自检失败后不许再调 Sign"


def test_signer_asserts_the_response_key_id_equals_the_configured_arn():
    kms = v.FakeKms()
    kms.wrong_key_id_for[v.KEY_ARN[v.SITE_KID]] = v.KEY_ARN[v.CONSOLE_KID]
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(sm.KeyMaterialMismatch, match="KeyId"):
        signer(b"a.b")


def test_signer_refuses_oversize_input_before_calling_kms():
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    with pytest.raises(ValueError, match="4096"):
        signer(b"x" * 4097)
    assert not [c for c in kms.calls if c[0] == "sign"]


def test_kms_signature_equals_a_local_pkcs1_signature_for_the_same_input():
    """spec §11.5：PKCS1 v1.5 是确定性签名，RAW 与本地实现对同一 signing input 产出同一签名——
    这条让本地私钥能替代 KMS 做单测与跨组件向量。"""
    kms = v.FakeKms()
    signer = sm.KmsSigner(kms, v.KEY_ARN[v.SITE_KID], v.spki_hex(v.SITE_KEY))
    assert signer(b"h.p") == session.local_signer(v.SITE_KEY)(b"h.p")


def test_module_imports_no_boto3_at_import_time():
    import ast
    from pathlib import Path
    tree = ast.parse((Path(sm.__file__)).read_text(encoding="utf-8"))
    top_imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {a.name for n in top_imports if isinstance(n, ast.Import) for a in n.names} | \
            {n.module for n in top_imports if isinstance(n, ast.ImportFrom)}
    assert "boto3" not in names, "client 由调用方传入（与 function_url_policy.py 同一纪律）"
