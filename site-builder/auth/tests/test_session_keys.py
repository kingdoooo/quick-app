"""`[SessionKeys]` 的唯一定义（spec §11.6 / plan 3c-1A Task 0）。

这些用例先于实现写下并跑红过。每条都对应一种"配置写错了但程序照常跑"的形态：
configparser 对缺失是静默的，所以任何缺省都必须由本模块响亮拒绝，不能回落。
"""
import textwrap
from pathlib import Path

import pytest

import session_keys as sk

MINIMAL = textwrap.dedent("""
    [Platform]
    base_domain = example.test

    [SessionKeys]
    site_current = site-hs-v1
    site_previous =
    console_current = console-hs-v1
    console_previous =
    legacy_param = /site-builder/jwt-secret
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/site-hs-v1

    [SessionKey:console-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/console-hs-v1
""")

RS_ROW = textwrap.dedent("""
    [SessionKey:site-rs-v1]
    alg = RS256
    key_arn = arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-555555555555
    spki_sha256 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
""")


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.ini"
    p.write_text(text)
    return p


def _load(tmp_path, text):
    return sk.load_session_keys(_write(tmp_path, text))


def test_minimal_1a_config_loads_two_families_with_no_previous(tmp_path):
    keys = _load(tmp_path, MINIMAL)
    assert [k.kid for k in keys.allowlist("site")] == ["site-hs-v1"]
    assert [k.kid for k in keys.allowlist("console")] == ["console-hs-v1"]
    assert keys.families["site"]["previous"] is None
    assert keys.legacy_param == "/site-builder/jwt-secret"
    site = keys.allowlist("site")[0]
    assert (site.family, site.alg, site.role) == ("site", "HS256", "current")
    assert site.ssm_param == "/site-builder/session-keys/site-hs-v1"
    assert site.key_arn is None and site.spki_sha256 is None


def test_inline_comments_are_stripped_not_folded_into_values(tmp_path):
    """CLAUDE.md 记过的坑：configparser 默认把行内注释并进值。"""
    text = MINIMAL.replace("site_current = site-hs-v1",
                           "site_current = site-hs-v1   # 3c-1B 切到 v2")
    keys = _load(tmp_path, text)
    assert keys.allowlist("site")[0].kid == "site-hs-v1"


def test_previous_is_loaded_and_ordered_after_current(tmp_path):
    text = (MINIMAL.replace("site_previous =", "site_previous = site-hs-v0")
            + "\n[SessionKey:site-hs-v0]\nalg = HS256\n"
              "ssm_param = /site-builder/session-keys/site-hs-v0\n")
    keys = _load(tmp_path, text)
    assert [k.kid for k in keys.allowlist("site")] == ["site-hs-v1", "site-hs-v0"]
    assert keys.allowlist("site")[1].role == "previous"


def test_rs_row_schema_is_accepted_now_so_2b_does_not_change_the_schema(tmp_path):
    text = MINIMAL.replace("site_previous =", "site_previous = site-rs-v1") + RS_ROW
    keys = _load(tmp_path, text)
    rs = keys.allowlist("site")[1]
    assert rs.alg == "RS256" and rs.key_arn.endswith(":key/11111111-2222-3333-4444-555555555555")
    assert rs.spki_sha256.startswith("0123456789abcdef") and rs.ssm_param is None


@pytest.mark.parametrize("mutate, why", [
    (lambda t: t.replace("[SessionKeys]", "[SessionKeyz]"), "缺 [SessionKeys] 段"),
    (lambda t: t.replace("site_current = site-hs-v1\n", ""), "缺 site_current"),
    (lambda t: t.replace("console_current = console-hs-v1\n", ""), "缺 console_current"),
    (lambda t: t.replace("legacy_param = /site-builder/jwt-secret\n", ""), "3c-3 之前 legacy_param 必填"),
    (lambda t: t.replace("legacy_param = /site-builder/jwt-secret", "legacy_param ="), "legacy_param 为空"),
    # 3c-1B：login-flow secret 是 [SessionKeys] 声明的第三种参数——不是 kid、不进 family、只给 auth
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret\n", ""), "缺 login_flow_secret_param（1B 起必填）"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param ="), "login_flow_secret_param 为空"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param = site-builder/login-flow-secret"), "login_flow_secret_param 不是绝对 SSM 路径"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param = /site-builder/session-keys/login-flow"), "login_flow_secret_param 落在 session-keys 前缀下（它不是 kid，不许长得像一把 family 密钥）"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param = /site-builder/jwt-secret"), "login_flow_secret_param 与 legacy_param 同一参数（登录 CSRF 密钥不得复用会话密钥）"),
    (lambda t: t.replace("login_flow_secret_param = /site-builder/login-flow-secret", "login_flow_secret_param = /site-builder/session-keys/site-hs-v1"), "login_flow_secret_param 与某个 HS 行同一参数"),
    (lambda t: t.replace("site_current = site-hs-v1", "site_current = console-hs-v1"), "kid 的 family 前缀与所属 family 不一致"),
    (lambda t: t.replace("site_current = site-hs-v1", "site_current = site-hs-1"), "kid 格式不合法"),
    (lambda t: t.replace("site_current = site-hs-v1", "site_current = Site-HS-v1"), "kid 大小写变形"),
    (lambda t: t.replace("[SessionKey:site-hs-v1]\nalg = HS256\nssm_param = /site-builder/session-keys/site-hs-v1\n", ""), "缺 [SessionKey:<kid>] 小节"),
    (lambda t: t.replace("alg = HS256\nssm_param = /site-builder/session-keys/site-hs-v1", "alg = HS512\nssm_param = /site-builder/session-keys/site-hs-v1"), "alg 不在 {HS256, RS256}"),
    (lambda t: t.replace("alg = HS256\nssm_param = /site-builder/session-keys/site-hs-v1", "alg = RS256\nssm_param = /site-builder/session-keys/site-hs-v1"), "alg 与 kid 的算法段矛盾"),
    (lambda t: t.replace("ssm_param = /site-builder/session-keys/site-hs-v1", "ssm_param = /site-builder/jwt-secret"), "HS 行的 ssm_param 不在 session-keys 前缀下"),
    (lambda t: t.replace("ssm_param = /site-builder/session-keys/site-hs-v1", ""), "HS 行缺 ssm_param"),
    (lambda t: t.replace("ssm_param = /site-builder/session-keys/site-hs-v1",
                         "ssm_param = /site-builder/session-keys/site-hs-v1\nkey_arn = arn:aws:kms:us-east-1:111111111111:key/x"), "HS 行不得带 key_arn"),
    (lambda t: t.replace("site_previous =", "site_previous = site-hs-v1"), "previous 与 current 相同"),
    (lambda t: t.replace("site_previous =", "site_previous = console-hs-v1"), "同一 kid 出现在两个 family（前缀不符先拒）"),
    (lambda t: t.replace("console_current = console-hs-v1", "console_current = console-hs-v1\nconsole_current = console-hs-v1"), "同一节里重复的键（configparser 的 DuplicateOptionError 也要变成本模块的错误）"),
])
def test_misconfiguration_raises_instead_of_falling_back(tmp_path, mutate, why):
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, mutate(MINIMAL))
    del why  # 只用于参数化的可读名


@pytest.mark.parametrize("mutate, why", [
    (lambda t: t.replace("key_arn = arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-555555555555",
                         "key_arn = arn:aws:kms:us-east-1:111111111111:alias/site-session"), "RS 行引用 alias（spec §11.6 禁止）"),
    (lambda t: t.replace("spki_sha256 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                         "spki_sha256 = 0123456789abcdef"), "spki_sha256 不是 64 位 hex"),
    (lambda t: t.replace("spki_sha256 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", ""), "RS 行缺 spki_sha256"),
    (lambda t: t.replace("alg = RS256\n", "alg = RS256\nssm_param = /site-builder/session-keys/site-rs-v1\n"), "RS 行不得带 ssm_param"),
])
def test_rs_row_misconfiguration_raises(tmp_path, mutate, why):
    text = MINIMAL.replace("site_previous =", "site_previous = site-rs-v1") + RS_ROW
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, mutate(text))
    del why


def test_missing_file_is_an_error_not_an_empty_config(tmp_path):
    """configparser.read 对不存在的文件静默返回空——这里必须响亮。"""
    with pytest.raises(sk.SessionKeysError):
        sk.load_session_keys(tmp_path / "does-not-exist.ini")


def test_error_type_is_a_value_error_so_callers_cannot_swallow_it_as_config_missing():
    assert issubclass(sk.SessionKeysError, ValueError)


def test_example_config_in_repo_loads():
    """`config.ini.example` 的 [SessionKeys] 段必须是本模块能加载的形态（占位值即可）。"""
    example = Path(__file__).resolve().parents[2] / "config.ini.example"
    keys = sk.load_session_keys(example)
    assert {k.kid for k in keys.allowlist("site")} == {"site-hs-v1"}
    assert {k.kid for k in keys.allowlist("console")} == {"console-hs-v1"}
    assert keys.login_flow_secret_param == "/site-builder/login-flow-secret", "spec §11.3 字面路径"


def test_env_json_carries_only_requested_families_and_no_values(tmp_path):
    import json
    keys = _load(tmp_path, MINIMAL)
    panel = json.loads(sk.env_json(keys, ("console",)))
    assert set(panel) == {"console"}
    assert panel["console"] == [{"kid": "console-hs-v1", "alg": "HS256", "role": "current",
                                 "ssm_param": "/site-builder/session-keys/console-hs-v1"}]
    auth = json.loads(sk.env_json(keys, ("site", "console")))
    assert set(auth) == {"site", "console"}
    with pytest.raises(sk.SessionKeysError):
        sk.env_json(keys, ("edge",))
    assert sk.legacy_entry(keys) == "on"


def test_ssm_parameter_arns_is_the_single_builder_for_both_deploy_scripts(tmp_path):
    keys = _load(tmp_path, MINIMAL)
    arns = sk.ssm_parameter_arns(keys, ("console",), region="us-east-1", account="111111111111")
    assert arns == ["arn:aws:ssm:us-east-1:111111111111:parameter/site-builder/jwt-secret",
                    "arn:aws:ssm:us-east-1:111111111111:parameter/site-builder/session-keys/console-hs-v1"]
    both = sk.ssm_parameter_arns(keys, ("site", "console"), region="us-east-1", account="111111111111",
                                 extra=("/site-builder/site-client-secret",))
    assert len(both) == 4 and both[1].endswith("site-client-secret")
    assert len(set(both)) == len(both), "去重且保序"


def test_synth_placeholder_allowlist_is_valid_json_but_can_never_match_a_kid():
    import json
    al = json.loads(sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON)
    assert "SYNTH-ONLY-PLACEHOLDER" in sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON
    assert al and all(sk.KID_RE.match(k) is None for k in al), "占位 kid 绝不能长得像真 kid"


# ---- 3c-1B：login-flow secret（spec §11.3 / §11.8.6）——不属于任何 family、没有 kid、只给 auth ----

def test_login_flow_secret_is_loaded_but_belongs_to_no_family(tmp_path):
    keys = _load(tmp_path, MINIMAL)
    assert keys.login_flow_secret_param == "/site-builder/login-flow-secret"
    for fam in sk.FAMILIES:
        assert all(r.ssm_param != keys.login_flow_secret_param for r in keys.allowlist(fam)), \
            "login-flow 出现在 family allowlist 里——它不是会话密钥"


def test_login_flow_secret_never_enters_env_json(tmp_path):
    """SESSION_KEYS_JSON 是 verifier 的 allowlist 形态；login-flow 不签发也不验证会话，写进去就是把
    一把无关密钥的参数名下发给 panel/Edge。"""
    keys = _load(tmp_path, MINIMAL)
    assert "login-flow" not in sk.env_json(keys, ("site", "console"))
    assert "login-flow" not in sk.env_json(keys, ("console",))


def test_ssm_parameter_names_includes_login_flow_only_when_asked(tmp_path):
    """auth 的清单 = login-flow + legacy + 两 family 的 HS 行；panel 默认不带 login-flow（永不持有）。"""
    keys = _load(tmp_path, MINIMAL)
    panel = sk.ssm_parameter_names(keys, ("console",))
    assert "/site-builder/login-flow-secret" not in panel
    auth = sk.ssm_parameter_names(keys, ("site", "console"), login_flow=True,
                                  extra=("/site-builder/site-client-secret",))
    assert auth == ["/site-builder/jwt-secret", "/site-builder/login-flow-secret",
                    "/site-builder/site-client-secret",
                    "/site-builder/session-keys/site-hs-v1", "/site-builder/session-keys/console-hs-v1"]
    arns = sk.ssm_parameter_arns(keys, ("site", "console"), region="us-east-1", account="111111111111",
                                 login_flow=True)
    assert "arn:aws:ssm:us-east-1:111111111111:parameter/site-builder/login-flow-secret" in arns
    assert not any("login-flow" in a for a in
                   sk.ssm_parameter_arns(keys, ("console",), region="us-east-1", account="111111111111"))
