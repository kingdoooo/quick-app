"""`scripts/verify_session_token_semantics.py`：判定逻辑（纯函数）与自测。

3c-final 起判据收缩为六条：签发走 auth 的 `/fixture-session`（带外只有一种 token、一个域，
ADR 0002），所以"用途混用"与"跨 family"两组反例造不出来了——它们改由静态证据给，本文件
守住那两个证据文件真的被点名且存在（docstring 是操作者唯一会读到的指路牌）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
import verify_session_token_semantics as gate  # noqa: E402  —— import 期不得碰 AWS（原版在 import 时就读 SSM）

TOKENS = dict(good="GOOD", unknown_kid="UNKNOWN")
SITE, AUTH, ORG = ("https://app-e2e-probe.example.test/", "auth.example.test",
                   "https://app-org.example.test/")


def _checks(get=None, **kw):
    return gate.run_checks(get or gate._ideal_responder(), gate.Tokens(**TOKENS),
                           site_url=SITE, auth_host=AUTH, org_site_url=kw.pop("org", ORG), **kw)


def _names(get=None, **kw):
    return [c.name for c in _checks(get, **kw)]


def test_import_has_no_side_effects():
    assert callable(gate.main) and callable(gate.run_checks)


def test_criteria_are_expressed_in_kid_form_not_old_typ():
    names = _names()
    assert len(names) == 7          # 六条判据，其中"遮蔽"在 Edge 侧有 1 条 + 14 条两次
    assert not any("typ" in n for n in names)


def test_only_two_tokens_are_minted_out_of_band():
    """`Tokens` 恰好两枚：夹具签发器只签站点会话，没有第二种带外 token（ADR 0002）。

    多出一枚就说明有人又找到了带外签发的路（例如给验收角色 `kms:Sign`），那是一条新的
    冒充路径，必须先过 ADR 而不是先加一条判据。
    """
    fields = set(gate.Tokens.__dataclass_fields__)
    assert fields == {"good", "unknown_kid"}, fields


def test_the_docstring_points_at_the_two_static_evidence_files_and_they_exist():
    """跨 family / 用途混用的证据搬去了单测——docstring 必须点名它们，且路径真的存在。

    不点名的话，读闸门报告的人只会看到"判据少了三条"，没有任何线索去核对那三条性质还在被证明。
    """
    paths = re.findall(r"[\w./-]+/tests?/test_[\w./-]*\.py|router/[\w./-]*test_[\w./-]*\.py", gate.__doc__)
    rels = {p for p in paths}
    assert "site-builder/auth/tests/test_verifier_allowlist.py" in rels, rels
    assert any(p.endswith("test_edge_kid_allowlist.py") for p in rels), rels
    for p in rels:
        assert (ROOT / p).exists(), f"docstring 点的 {p} 不存在"


def test_the_fixture_boundary_criterion_is_a_skip_not_a_failure_without_an_org_site():
    """账号里没有 org 站点时那条必须是 skip：报失败会让干净账号上的闸门永远红。"""
    checks = _checks(org=None)
    boundary = [c for c in checks if "org 站点" in c.name]
    assert len(boundary) == 1 and boundary[0].ok and "skip" in boundary[0].detail, boundary
    assert len(checks) == len(_checks()), "skip 那条不许整条消失（消失了就没人注意到它没被验）"


def test_allow_paths_require_200_not_merely_non_302():
    checks = gate.run_checks(
        lambda u, c: (500, {}) if "GOOD" in c else (302, {"location": f"https://{AUTH}/login"}),
        gate.Tokens(**TOKENS), site_url=SITE, auth_host=AUTH, org_site_url=ORG)
    assert [c.ok for c in checks if "放行" in c.name] == [False, False, False]


def test_self_test_is_green_on_ideal_and_red_on_each_broken_path():
    assert gate.self_test() == 0
    assert gate.self_test(break_shadow=True) != 0
    assert gate.self_test(break_unknown_kid=True) != 0
    assert gate.self_test(break_fixture_boundary=True) != 0


def test_the_three_bad_paths_are_separable_not_one_flag():
    """每个旗标只该弄红它自己那一族——合成一个旗标的话，"遮蔽坏了""allowlist 坏了"
    "夹具边界坏了"在报告里分不开，而三者的修法与后果完全不同。"""
    def red(**flags):
        return {c.name for c in _checks(gate._ideal_responder(**flags)) if not c.ok}

    shadow, kid, boundary = red(break_shadow=True), red(break_unknown_kid=True), red(break_fixture_boundary=True)
    assert shadow and all("遮蔽" in n for n in shadow), shadow
    assert kid == {n for n in _names() if "未知 kid" in n}, kid
    assert boundary == {n for n in _names() if "org 站点" in n}, boundary
    assert not (kid & boundary) and not (shadow & kid) and not (shadow & boundary)


def test_every_criterion_has_some_break_path_that_makes_it_red():
    """元用例：除两条对照外，每条判据都必须能被某个 break 旗标弄红——否则它是 pass-now 的。"""
    all_red = set()
    for flags in ({"break_shadow": True}, {"break_unknown_kid": True}, {"break_fixture_boundary": True}):
        all_red |= {c.name for c in _checks(gate._ideal_responder(**flags)) if not c.ok}
    never_red = [n for n in _names() if n not in all_red and "对照" not in n]
    assert not never_red, f"这些判据没有任何 break 路径能让它红：{never_red}"


def test_the_unknown_kid_token_needs_no_key_and_is_well_formed():
    """本地造那一枚：三段、header 里是未知 kid、签名段长度是 RSA-2048 签名的长度。

    它必须**不依赖任何密钥**——KMS 之后本地拿不到私钥，而这条判据要的只是"kid 查表先于验签"。
    """
    import base64
    import json
    tok = gate._unknown_kid_token("probe@e2e.invalid")
    h, p, sig = tok.split(".")

    def unb64(seg):
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

    assert json.loads(unb64(h)) == {"alg": "RS256", "typ": "JWT", "kid": gate.UNKNOWN_KID}
    assert json.loads(unb64(p))["email"] == "probe@e2e.invalid"
    assert len(unb64(sig)) == 256
    assert gate._unknown_kid_token("probe@e2e.invalid") != tok, "签名段应当是随机的"
