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
    signer = legacy
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


def test_both_legal_signer_values_load(tmp_path):
    """两个合法值都要能加载出来——缺一即开关只能单向（切得过去回不来）。
    "缺/非法必须硬失败"那一半在下面的 test_misconfiguration_raises_instead_of_falling_back。"""
    assert _load(tmp_path, MINIMAL).signer == "legacy"
    assert _load(tmp_path, MINIMAL.replace("signer = legacy", "signer = current")).signer == "current"


def test_signer_current_is_allowed_while_legacy_param_is_still_set(tmp_path):
    """切换期（十步的 ③–④）的实际形态：已按新 kid 签发，legacy 入口仍开着给存量 cookie 用。"""
    keys = _load(tmp_path, MINIMAL.replace("signer = legacy", "signer = current"))
    assert (keys.signer, keys.legacy_param) == ("current", "/site-builder/jwt-secret")
    assert sk.legacy_entry(keys) == "on"


def _with(text: str, *, signer: str, legacy: str) -> str:
    """把 MINIMAL 改成指定的 (signer, legacy_param) 组合。legacy="" 表示写成空值。"""
    return (text.replace("signer = legacy", f"signer = {signer}")
                .replace("legacy_param = /site-builder/jwt-secret",
                         f"legacy_param = {legacy}".rstrip()))


# 3c-1B ticket 07：(signer × legacy_param) 的**六种组合**一次列全。
# 三种合法、三种必拒；`legacy_param` 为空即 legacy 入口关闭（L3），此时只许 signer=current。
LEGAL_COMBOS = [
    ("legacy", "/site-builder/jwt-secret", "L1/L2：入口开着、还在签 legacy 形态"),
    ("current", "/site-builder/jwt-secret", "L2：已切签发，入口仍开着给存量 cookie"),
    ("current", "", "L3：入口已关闭，只能签 current"),
]
ILLEGAL_COMBOS = [
    ("legacy", "", "签一批没人接受的 token（全员登录循环）"),
    ("", "/site-builder/jwt-secret", "缺 signer"),
    ("bogus", "/site-builder/jwt-secret", "signer 非法值"),
]


@pytest.mark.parametrize("signer,legacy,why", LEGAL_COMBOS,
                         ids=[f"{s or 'missing'}+{'set' if l else 'empty'}"
                              for s, l, _ in LEGAL_COMBOS])
def test_the_three_legal_signer_legacy_combinations_load(tmp_path, signer, legacy, why):
    keys = _load(tmp_path, _with(MINIMAL, signer=signer, legacy=legacy))
    assert keys.signer == signer
    assert keys.legacy_param == legacy
    assert sk.legacy_entry(keys) == ("on" if legacy else "off")
    del why


@pytest.mark.parametrize("signer,legacy,why", ILLEGAL_COMBOS,
                         ids=[f"{s or 'missing'}+{'set' if l else 'empty'}"
                              for s, l, _ in ILLEGAL_COMBOS])
def test_the_three_illegal_signer_legacy_combinations_are_rejected(tmp_path, signer, legacy, why):
    with pytest.raises(sk.SessionKeysError):
        _load(tmp_path, _with(MINIMAL, signer=signer, legacy=legacy))
    del why


def test_l3_config_drops_the_legacy_parameter_from_every_role_list(tmp_path):
    """L3 的第二处后果：角色 SSM 精确清单不再含 legacy 参数（auth 与 panel 各自的清单）。"""
    keys = _load(tmp_path, _with(MINIMAL, signer="current", legacy=""))
    auth = sk.ssm_parameter_names(keys, ("site", "console"), login_flow=True)
    panel = sk.ssm_parameter_names(keys, ("console",))
    assert "/site-builder/jwt-secret" not in auth and "/site-builder/jwt-secret" not in panel
    assert "" not in auth and "" not in panel, "空串不得作为参数名混进清单"
    # 仍该有的东西一个不少
    assert "/site-builder/login-flow-secret" in auth
    assert "/site-builder/session-keys/site-hs-v1" in auth
    assert "/site-builder/session-keys/console-hs-v1" in panel
    assert "/site-builder/session-keys/site-hs-v1" not in panel, "panel 不得持 site family"


def test_before_l3_every_role_list_still_carries_the_legacy_parameter(tmp_path):
    """回归：`legacy_param` 非空时一切与今天相同。"""
    keys = _load(tmp_path, MINIMAL)
    assert sk.ssm_parameter_names(keys, ("site", "console"), login_flow=True)[0] \
        == "/site-builder/jwt-secret"
    assert "/site-builder/jwt-secret" in sk.ssm_parameter_names(keys, ("console",))


def test_signer_legacy_with_empty_legacy_param_is_rejected_by_its_own_rule(tmp_path):
    """`signer=legacy` + legacy 入口已关 = 签一批没人接受的 token。

    07 号任务放开了"legacy_param 为空"之后，本条是这个组合**唯一**的防线——所以要断言
    报错来自 signer 规则本身（match），而不是别的检查顺手兜住。
    """
    text = MINIMAL.replace("legacy_param = /site-builder/jwt-secret", "legacy_param =")
    with pytest.raises(sk.SessionKeysError, match="signer=legacy"):
        _load(tmp_path, text)


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


_TWO_RS = (MINIMAL.replace("site_previous =", "site_previous = site-rs-v1")
                  .replace("console_previous =", "console_previous = console-rs-v1")
           + RS_ROW
           + RS_ROW.replace("site-rs-v1", "console-rs-v1")
                   .replace("key/11111111-2222-3333-4444-555555555555", "key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
                   .replace("spki_sha256 = 0123456789abcdef", "spki_sha256 = fedcba9876543210"))


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace("key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "key/11111111-2222-3333-4444-555555555555"),
     "两个 RS kid 共用同一把 KMS key"),
    (lambda t: t.replace("spki_sha256 = fedcba9876543210", "spki_sha256 = 0123456789abcdef"),
     "两个 RS kid 公钥指纹相同（同一把私钥）"),
])
def test_rs_key_material_must_be_unique_across_families(tmp_path, mutate, why):
    """3c-1B-G A4 的 RS 侧兜底（Codex 复审建议补上直接用例）：先证明两行各自不同时能加载，
    再证明 key_arn / spki 任一重复即拒。"""
    keys = _load(tmp_path, _TWO_RS)                       # 正向控制
    assert {r.kid for fam in keys.families.values() for r in fam.values() if r} >= {"site-rs-v1", "console-rs-v1"}
    with pytest.raises(sk.SessionKeysError, match="同一个"):
        _load(tmp_path, mutate(_TWO_RS))
    del why


@pytest.mark.parametrize("mutate, why", [
    (lambda t: t.replace("[SessionKeys]", "[SessionKeyz]"), "缺 [SessionKeys] 段"),
    (lambda t: t.replace("site_current = site-hs-v1\n", ""), "缺 site_current"),
    (lambda t: t.replace("console_current = console-hs-v1\n", ""), "缺 console_current"),
    (lambda t: t.replace("signer = legacy\n", ""), "缺 signer（3c-1B 起必填，不给默认值）"),
    (lambda t: t.replace("signer = legacy", "signer ="), "signer 为空"),
    (lambda t: t.replace("signer = legacy", "signer = Current"), "signer 大小写变形"),
    (lambda t: t.replace("signer = legacy", "signer = on"), "signer 写成 on/off（与 LEGACY_ENTRY 的取值混淆）"),
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
    # ---- 3c-1B-G A4：key material 的全局唯一性。前两条**实测曾被接受**，正是拆 family 想消掉的东西 ----
    (lambda t: t.replace("ssm_param = /site-builder/session-keys/console-hs-v1",
                         "ssm_param = /site-builder/session-keys/site-hs-v1"),
     "两个 family 的 kid 共用同一个 ssm_param（= 跨 family 又共享了一把密钥）"),
    (lambda t: t.replace("legacy_param = /site-builder/jwt-secret",
                         "legacy_param = /site-builder/session-keys/site-hs-v1"),
     "legacy_param 指向某个 HS 行的参数（legacy 与 current 共享密钥）"),
    (lambda t: t.replace("ssm_param = /site-builder/session-keys/site-hs-v1",
                         "ssm_param = /site-builder/session-keys/site-hs-v1-renamed"),
     "HS 行的 ssm_param 不等于前缀 + kid（只校验前缀挡不住共享/错配）"),
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
