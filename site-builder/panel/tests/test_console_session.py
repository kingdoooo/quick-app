"""panel 侧：验 code、jti 原子消费、cookie 形态、cookie↔header 一致性。

3c-final 起只有一种线格式（RS256 + kid），签发经 KMS（`session_kms.KmsSigner`）、验签在本地用
`kms:GetPublicKey` 取来并按 `spki_sha256` 核对过的公钥。`keys` 夹具（conftest）把 `_kms()` 换成
`upgrade_code_vectors.FakeKms`，所以本文件里"签"和"验"用的是同一把测试私钥，且**每次 KMS 调用都被记录**
——形态断言（哪个 ARN、RAW、哪个算法、调了几次）就落在那份记录上。
"""
import base64
import json

import boto3
import pytest

import console_session
import session
import upgrade_code_vectors as v
from upgrade_code_vectors import RS_MUTATIONS as MUTATIONS


def _code(email="u@x.com", *, ttl_seconds=60, **kw):
    """一枚升级码。**测试自己用本地私钥签**（生产是 KMS），两侧的字节形态由 session.mint_token 保证。"""
    return session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY),
                              token_use="console-upgrade", email=email,
                              ttl_seconds=ttl_seconds, **kw)


def _console_cookie_header(email="u@x.com"):
    return f"{console_session.CONSOLE_COOKIE}={v.console_session_token(session.mint_token, email=email)}"


def test_code_is_single_use(aws, keys):
    code = _code()
    assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="u@x.com")  # 重放


def test_replay_is_rejected_by_conditional_write_not_by_a_read_check(aws, keys):
    """并发重放：两个请求同时用同一 code，只有一个能成。

    条件写（attribute_not_exists(jti)）才有这个性质；"先 get 再 put"的写法
    在并发下两边都会看到"没用过"。
    """
    code = _code()
    ok = 0
    for _ in range(2):
        try:
            console_session.consume_code(code, expected_email="u@x.com")
            ok += 1
        except console_session.UpgradeRejected:
            pass
    assert ok == 1


def test_consumed_jti_row_has_ttl(aws, keys):
    """session-codes 是一次性标记——必须带 TTL，否则表无限增长。"""
    console_session.consume_code(_code(), expected_email="u@x.com")
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert len(items) == 1 and int(items[0]["expires_at"]) > 0


def test_expired_code_is_rejected_before_being_consumed(aws, keys):
    """过期 code 不得占用 jti 行——否则攻击者能用过期 code 污染表。"""
    import time
    code = _code(ttl_seconds=1)
    time.sleep(1.1)
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="u@x.com")
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == [], f"过期 code 写进了消费表: {items}"


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_same_vectors_as_auth_side(aws, keys, name, mutate, expect_reject):
    """与 auth 侧 test_upgrade_code.py 的同一组 RS 变形向量配对（panel 的 session.py 是复制来的）。"""
    code = mutate(_code())
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code, expected_email="u@x.com")
    else:
        assert console_session.consume_code(code, expected_email="u@x.com") == "u@x.com"


def test_console_cookie_attributes(aws, keys):
    c = console_session.console_cookie("u@x.com", "U")
    assert c.startswith("__Host-sb_console=")
    for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert attr in c, attr
    assert "Domain=" not in c, "__Host- 前缀下带 Domain 浏览器会整条拒绝"


def test_cookie_email_must_match_edge_header(aws, keys):
    """换人登录后旧 __Host-sb_console 必须失效（spec §5.4 第 1 步）。

    残留 cookie 属 A，Edge 注入的身份是 B —— 必须拒绝并要求重新升级，
    否则 B 会拿着 A 的面板会话操作 A 的站点。
    """
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    assert console_session.verify_console_cookie(
        cookie, x_user_email="a@x.com") == "a@x.com"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(cookie, x_user_email="b@x.com")


def test_empty_edge_header_is_rejected_not_treated_as_match(aws, keys):
    """x-user-email 为空时不得"因为都为空所以相等"而放行。"""
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(cookie, x_user_email="")


def test_upgrade_code_cannot_be_used_as_console_cookie(aws, keys):
    """60 秒 code 不得当 4 小时面板会话用（token_use / aud 都不同）。"""
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(
            f"__Host-sb_console={_code()}", x_user_email="u@x.com")


def test_missing_or_other_cookies_are_rejected(aws, keys):
    for header in ("", "a=1; b=2", "sb_session=xyz", "__Host-sb_pkce=abc"):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(header,
                                                  x_user_email="u@x.com")


def test_console_cookie_is_found_among_other_cookies(aws, keys):
    """真实浏览器会带一串 cookie——解析必须按名字精确取，不能只看第一个。"""
    good = console_session.console_cookie("u@x.com", "U").split(";")[0]
    header = f"a=1; {good}; sb_session=zzz"
    assert console_session.verify_console_cookie(
        header, x_user_email="u@x.com") == "u@x.com"


# ── 3c-final：panel 一处都不读 SSM，会话签名 key 在 KMS ────────────────────────
#
# 旧形态是"环境变量只有参数名 JWT_SECRET_PARAM，运行时从 SSM SecureString 读 + TTL 缓存"。
# 那条路径整条删掉了（对称密钥读到就能签，见 docs/security/account-trust-boundary.md）。
# 本条钉的是**删干净了**：那批名字一个都不许回来，那批环境变量也不许出现。

def test_panel_never_touches_ssm(aws, monkeypatch):
    import os
    from pathlib import Path
    calls = []
    monkeypatch.setattr(boto3, "client", lambda svc, *a, **k: calls.append(svc) or type("C", (), {})())
    for gone in ("_secret", "_secret_by_param", "_legacy_secret", "_signer_mode", "_signing_key",
                 "SECRET_TTL_SECONDS", "_secret_cache", "CONSOLE_SCOPE"):
        assert not hasattr(console_session, gone), gone
    assert "JWT_SECRET_PARAM" not in os.environ and "LEGACY_ENTRY" not in os.environ \
        and "SESSION_SIGNER" not in os.environ
    # 本模块唯一会建的 AWS client 是 KMS（DynamoDB 那两个走 boto3.resource）。
    # `_kms_client` 是模块级缓存，先清掉再看这一次建了什么——不清的话本条会被
    # 前面用例留下的缓存变成空转。
    monkeypatch.setattr(console_session, "_kms_client", None)
    console_session._kms()
    assert calls == ["kms"], calls
    src = Path(console_session.__file__).read_text(encoding="utf-8")
    assert "get_parameter" not in src and "SecureString" not in src, "SSM 读取又回来了"


# ── 身份不符不得消费 jti（Codex 审查 2026-08-10 P2-3）──────────────────
# 原实现：handler 先 consume_code() 原子写 jti，**之后**才比对 code 的 email
# 与 Edge 身份。于是拿别人的 code 提交一次（401）就把它作废了，合法持有者
# 随后再用会得到"升级码已被使用"。实测复现过这个顺序。

def test_mismatched_identity_does_not_consume_jti(aws, keys):
    """错身份提交 → 拒绝，且 code **仍可被正确身份使用**。"""
    code = _code("victim@x.com")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(code, expected_email="attacker@x.com")
    # 表里不得留下消费标记
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == [], f"错身份提交后 jti 已被写入: {items}"
    # 合法持有者仍然能用
    assert console_session.consume_code(
        code, expected_email="victim@x.com") == "victim@x.com"


def test_expected_email_is_required_to_match_exactly(aws, keys):
    """匹配必须逐字符相等，且空值不得视为通过。"""
    code = _code()
    for bad in ("", "U@X.COM", "u@x.com ", "u@x.co"):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.consume_code(code, expected_email=bad)
    assert console_session.consume_code(
        code, expected_email="u@x.com") == "u@x.com"


def test_handler_callback_rejects_mismatch_without_burning_code(aws, keys):
    """走 handler 的真实路径：错身份的 callback 不得作废 code。

    这是用户可见面——单独测 consume_code 不够，handler 里的调用顺序才是
    缺陷所在（它原来先消费再比对）。
    """
    import handler
    from test_handler import EDGE_ROLE_ID
    code = _code("victim@x.com")
    ev = {"requestContext": {
              "http": {"method": "GET"},
              # 合规的 Edge IAM 上下文——本用例测的是 code 消费顺序，
              # 不是 P1-1 的传输层校验（那个由 test_handler 覆盖）。
              "authorizer": {"iam": {
                  "callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
          "rawPath": "/api/session-callback",
          "headers": {"x-user-email": "attacker@x.com"},
          "queryStringParameters": {"code": code}}
    r = handler.handler(ev, None)
    assert r["statusCode"] == 401, r
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(
        "site-session-codes").scan()["Items"]
    assert items == [], f"错身份的 callback 把 code 作废了: {items}"
    # 合法身份随后仍能换到面板会话
    ev["headers"]["x-user-email"] = "victim@x.com"
    r2 = handler.handler(ev, None)
    assert r2["statusCode"] == 302, r2
    assert any(console_session.CONSOLE_COOKIE in c for c in r2.get("cookies", []))


# ---- allowlist 的边界：panel 只持 console family（spec §4.3）----

def test_console_cookie_is_verified(aws, keys):
    assert console_session.verify_console_cookie(
        _console_cookie_header(), x_user_email="u@x.com") == "u@x.com"


def test_site_kid_token_is_not_a_console_cookie(aws, keys):
    """panel 的 allowlist 里没有 site family 的 kid（spec §4.3）。"""
    tok = session.mint_token(kid=v.SITE_KID, sign=v.signer(v.SITE_KEY),
                             token_use="console-session", email="u@x.com",
                             ttl_seconds=3600, name="U")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"{console_session.CONSOLE_COOKIE}={tok}", x_user_email="u@x.com")


def test_site_session_under_the_console_kid_is_not_a_console_cookie(aws, keys):
    tok = session.mint_token(kid=v.CONSOLE_KID, sign=v.signer(v.CONSOLE_KEY),
                             token_use="site-session", email="u@x.com",
                             ttl_seconds=3600, name="U", idp="Feishu", auth_via="x")
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(f"{console_session.CONSOLE_COOKIE}={tok}", x_user_email="u@x.com")


def test_console_cookie_is_not_an_upgrade_code(aws, keys):
    tok = _console_cookie_header().split("=", 1)[1]
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(tok, expected_email="u@x.com")


def test_panel_refuses_a_session_keys_json_that_carries_the_site_family(aws, keys, monkeypatch):
    """每个 verifier 只持自己那份 allowlist：panel 拿到 site family 就是部署配置错了，直接拒。"""
    monkeypatch.setenv("SESSION_KEYS_JSON",
                       v.session_keys_json((v.CONSOLE_KID, "current"), (v.SITE_KID, "current")))
    with pytest.raises(RuntimeError):
        console_session.verify_console_cookie(_console_cookie_header(), x_user_email="u@x.com")


def test_verify_outcome_is_logged_without_the_token(aws, keys, capsys):
    cookie = _console_cookie_header()
    console_session.verify_console_cookie(cookie, x_user_email="u@x.com")
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.splitlines() if l.startswith("{") and "session_verify" in l]
    assert lines and lines[-1]["outcome"] == "accepted_current" and lines[-1]["verifier"] == "panel"
    assert cookie.split("=", 1)[1].split(".")[1] not in out


# ---- 面板会话的线格式（spec §11.4 的面板会话表）与 KMS 边界 --------------------------------


def _seg(token: str, i: int) -> dict:
    s = token.split(".")[i]
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def _cookie_token(c: str) -> str:
    return c.split(";")[0][len(console_session.CONSOLE_COOKIE) + 1:]


def test_console_cookie_uses_the_console_current_kid(aws, keys):
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    assert _seg(token, 0) == {"alg": "RS256", "typ": "JWT", "kid": "console-rs-v1"}
    claims = _seg(token, 1)
    # §11.4 的面板会话表：**精确**这 6 个键。多出 typ/scope 说明混了旧合同；
    # 多出 idp/auth_via 说明误用了站点会话那张表。
    assert set(claims) == {"token_use", "aud", "email", "name", "exp", "iat"}
    assert claims["token_use"] == "console-session" and claims["aud"] == "console-panel"
    assert (claims["email"], claims["name"]) == ("u@x.com", "U")
    assert claims["exp"] - claims["iat"] == console_session.CONSOLE_TTL_SECONDS


def test_console_cookie_keeps_the_host_prefix_trio(aws, keys):
    """`__Host-` 三要素与 Max-Age：任何 Domain= 会让浏览器整条丢弃 cookie。"""
    c = console_session.console_cookie("u@x.com", "U")
    assert c.startswith(f"{console_session.CONSOLE_COOKIE}=")
    for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/",
                 f"Max-Age={console_session.CONSOLE_TTL_SECONDS}"):
        assert attr in c, attr
    assert "Domain=" not in c


def test_public_keys_come_from_kms_by_arn_and_are_fingerprint_checked(aws, keys):
    console_session.verify_console_cookie(
        f"{console_session.CONSOLE_COOKIE}={v.console_session_token(session.mint_token)}", x_user_email="u@x.com")
    assert ("get_public_key", v.KEY_ARN[v.CONSOLE_KID]) in keys.calls
    assert not [c for c in keys.calls if c[0] == "sign"]


def test_verify_fails_closed_when_the_public_key_does_not_match_the_configured_fingerprint(aws, keys):
    import session_kms
    keys.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    console_session._reset_signing()
    with pytest.raises(session_kms.KeyMaterialMismatch):
        console_session.verify_console_cookie(
            f"{console_session.CONSOLE_COOKIE}={v.console_session_token(session.mint_token)}", x_user_email="u@x.com")


def test_console_cookie_is_signed_by_kms_with_the_console_key_only(aws, keys):
    c = console_session.console_cookie("u@x.com", "U")
    signs = [x for x in keys.calls if x[0] == "sign"]
    assert signs == [("sign", v.KEY_ARN[v.CONSOLE_KID], "RAW", "RSASSA_PKCS1_V1_5_SHA_256", signs[0][4])]
    tok = _cookie_token(c)
    assert session.verify_token(tok, allowlist=v.CONSOLE_ALLOWLIST, token_use="console-session")[1] == "accepted_current"


def test_console_cookie_does_not_verify_under_another_family_key(aws, keys):
    """负向：同一个 kid 但公钥换成 site 那把 ⇒ bad_signature。

    没有这一条，上面那条"能验过"可能只是因为 kid 对上了——而 kid 是攻击者可写的 header 字段。
    """
    tok = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    wrong = {v.CONSOLE_KID: v.public_entry(v.SITE_KEY, "current")}
    assert session.verify_token(tok, allowlist=wrong, token_use="console-session") == (None, "bad_signature")


def test_ensure_signing_material_self_checks_without_signing(aws, keys):
    console_session.ensure_signing_material()
    assert [x[0] for x in keys.calls] == ["get_public_key"]
    console_session.console_cookie("u@x.com", "U")
    assert [x[0] for x in keys.calls] == ["get_public_key", "sign"], "自检只做一次，随后直接签"


def test_panel_round_trips_its_own_cookie(aws, keys):
    cookie = console_session.console_cookie("u@x.com", "U").split(";")[0]
    assert console_session.verify_console_cookie(cookie, x_user_email="u@x.com") == "u@x.com"


def test_cookie_still_fails_when_a_different_person_logged_in(aws, keys):
    """换人登录（spec §5.4 第 1 步）——这是 M3 的核心不变量。

    残留 cookie 属 A、Edge 刚验过的身份是 B ⇒ 必须要求重新升级，否则 B 拿着 A 的面板会话
    操作 A 的站点。空 `x-user-email` 也不得"因为都为空所以相等"。
    """
    cookie = console_session.console_cookie("a@x.com", "A").split(";")[0]
    assert console_session.verify_console_cookie(cookie, x_user_email="a@x.com") == "a@x.com"
    for wrong in ("b@x.com", ""):
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(cookie, x_user_email=wrong)


def test_cookie_is_not_accepted_as_an_upgrade_code(aws, keys):
    """跨用途复用：面板会话（4 h）不得当升级码用，否则等于一个可无限续期的长期凭证。"""
    token = _cookie_token(console_session.console_cookie("u@x.com", "U"))
    with pytest.raises(console_session.UpgradeRejected):
        console_session.consume_code(token, expected_email="u@x.com")


@pytest.mark.parametrize("bad", [None, "", "{}", '{"console": []}', "not-json",
                                '{"console": [{"kid": "console-rs-v1", "alg": "RS256", "role": "previous", '
                                '"key_arn": "x", "spki_sha256": "y"}]}'],
                         ids=["missing", "empty-string", "no-console-family", "no-rows",
                              "not-json", "no-current"])
def test_missing_or_broken_session_keys_json_fails_loudly_instead_of_signing(aws, keys, monkeypatch, bad):
    """签发材料缺/坏必须抛（→ /api/session-callback 500，响亮且有意），不许静默签出什么。

    这是旧 `SESSION_SIGNER` 那组"缺/错开关必须抛"用例的替代：3c-final 没有开关了，
    唯一的签发材料真源就是这个 JSON。**同时断言一次 KMS 都没调**——"先签了再发现配置不对"
    在 KMS 形态下等于白付一次 Sign，也说明材料解析没有前置。
    """
    if bad is None:
        monkeypatch.delenv("SESSION_KEYS_JSON")
    else:
        monkeypatch.setenv("SESSION_KEYS_JSON", bad)
    with pytest.raises(RuntimeError, match="SESSION_KEYS_JSON"):
        console_session.console_cookie("u@x.com", "U")
    assert keys.calls == [], keys.calls


@pytest.mark.parametrize("name,mutate,expect_reject", MUTATIONS)
def test_console_session_cookie_vectors_match_the_auth_side(aws, keys, name, mutate, expect_reject):
    """panel 签、两侧各自那份 session.py 验：同一组 RS_MUTATIONS 的接受/拒绝必须一致。

    这条与 auth 侧 test_upgrade_code.py 的同名向量配对——panel 的 session.py 是构建时
    复制来的，漂移的症状是"面板自己验得过、别的组件验不过"。
    """
    cookie = f"{console_session.CONSOLE_COOKIE}={mutate(v.console_session_token(session.mint_token))}"
    if expect_reject:
        with pytest.raises(console_session.UpgradeRejected):
            console_session.verify_console_cookie(cookie, x_user_email="u@x.com")
    else:
        assert console_session.verify_console_cookie(cookie, x_user_email="u@x.com") == "u@x.com"


def _callback_event(code: str, *, email: str, name: str = "U") -> dict:
    from test_handler import EDGE_ROLE_ID
    return {"requestContext": {
                "http": {"method": "GET"},
                "authorizer": {"iam": {"callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
            "rawPath": "/api/session-callback",
            # `name` 仍来自 Edge 注入的头（URL 编码），不是 token 里的——本票不改这条
            "headers": {"x-user-email": email, "x-user-name": name},
            "queryStringParameters": {"code": code}}


def test_handler_callback_sets_a_cookie_end_to_end(aws, keys):
    """走 handler 的真实路径（用户可见面）：升级码换出的 Set-Cookie 必须是 RS 形态。

    单独测 `console_cookie` 不够——handler 才是那个把 Edge 注入的 `name` 递进去的地方，
    也是"cookie 属性写在响应上"的地方。
    """
    import handler
    r = handler.handler(_callback_event(_code("u@x.com"), email="u@x.com",
                                       name="%E5%BC%A0%E4%B8%89%20Ltd"), None)
    assert r["statusCode"] == 302, r
    cookie = next(c for c in r["cookies"] if c.startswith(console_session.CONSOLE_COOKIE))
    token = _cookie_token(cookie)
    assert _seg(token, 0) == {"alg": "RS256", "typ": "JWT", "kid": v.CONSOLE_KID}
    claims = _seg(token, 1)
    assert set(claims) == {"token_use", "aud", "email", "name", "exp", "iat"}
    assert claims["email"] == "u@x.com"
    # `name` 的来源必须仍是 Edge 注入的 x-user-name（URL 编码，handler 负责 unquote）。
    # 不钉住的话，"name 退化成 email"或"漏了 unquote"都会静默通过——控制台顶栏显示的就是这个值。
    assert claims["name"] == "张三 Ltd", claims["name"]
    # 换出来的 cookie 立刻就能用（同一进程内的往返，证明签发与验签口径一致）
    assert console_session.verify_console_cookie(
        cookie.split(";")[0], x_user_email="u@x.com") == "u@x.com"


def test_handler_rejects_a_cookie_from_another_person_with_401(aws, keys):
    """**handler 层**（用户可见面）的换人登录：cookie 属 A、Edge 身份是 B ⇒ 401。

    模块级的 `verify_console_cookie` 用例不够——ticket 要的是响应码，而 401 的形状
    （`{"need": "console-session"}`）是前端据以重新升级的契约。
    """
    import handler
    from test_handler import CONSOLE, EDGE_ROLE_ID
    stale = console_session.console_cookie("a@x.com", "A").split(";")[0]
    ev = {"requestContext": {
              "http": {"method": "PUT"},
              "authorizer": {"iam": {"callerId": f"{EDGE_ROLE_ID}:us-east-1.RouterStack-fn"}}},
          "rawPath": "/api/sites/s-1/permissions",
          "headers": {"x-user-email": "b@x.com", "cookie": stale,
                      "origin": f"https://{CONSOLE}", "content-type": "application/json"},
          "body": json.dumps({"require_login": False})}
    r = handler.handler(ev, None)
    assert r["statusCode"] == 401, r
    assert json.loads(r["body"])["need"] == "console-session"
    # 正对照：同一条路径下身份相符时不会停在 401（否则上面那条可能是别的原因导致的 401）
    ev["headers"]["x-user-email"] = "a@x.com"
    assert handler.handler(ev, None)["statusCode"] != 401


# ---- 变形测试：证明上面那些正向断言真会红 ------------------------------------------------
#
# 用**临时副本**加载改过的 console_session（spec Testing Decisions 的「`git stash` 或临时副本」
# 的后者）：不动仓库里的文件，脏工作树下也能跑，CI 里也能跑。
from module_mutation import mutate_module_segment  # noqa: E402

# 签发段 = `ensure_signing_material` 到 `verify_console_cookie` 之间（即取材料 + console_cookie）。
# `token_use="console-session"` 在本文件里出现两次，另一处是 verify_console_cookie 的**验签**参数
# ——切段就是为了不改到那一处。
_SIGNER_REGION = ("def ensure_signing_material", "def verify_console_cookie")


def _console_session_variant(tmp_path, old: str, new: str, kms):
    mod = mutate_module_segment(console_session.__file__, region=_SIGNER_REGION,
                                old=old, new=new, tmp_path=tmp_path,
                                module_name="_console_session_mutant")
    # 假 KMS 只装在真模块上（conftest 的 keys 夹具）；副本自带一份干净的模块级缓存
    mod._kms = lambda: kms
    mod._reset_signing()
    return mod


def test_mutating_the_signer_token_use_makes_the_cookie_unverifiable(aws, keys, tmp_path):
    """`console-session` → `site-session`：cookie 照样签出、照样种下，但验签必拒。"""
    mod = _console_session_variant(tmp_path, 'token_use="console-session"',
                                   'token_use="site-session"', keys)
    token = _cookie_token(mod.console_cookie("u@x.com", "U"))
    assert _seg(token, 1)["token_use"] == "site-session"
    with pytest.raises(console_session.UpgradeRejected):
        console_session.verify_console_cookie(
            f"{console_session.CONSOLE_COOKIE}={token}", x_user_email="u@x.com")


def test_turning_ensure_signing_material_into_a_noop_skips_the_self_check(aws, keys, tmp_path):
    """把 `ensure_signing_material` 改成什么都不做 ⇒ 那条"自检不签名"的断言必须能看见。

    证明 `test_ensure_signing_material_self_checks_without_signing` 真的依赖那一行，
    而不是"反正 console_cookie 之后总会有一次 GetPublicKey"。3i 的价值全在"**先于**
    consume_code 就把材料取一遍"，退化成 no-op 时用户会丢一枚一次性升级码。
    """
    mod = _console_session_variant(tmp_path, "_signer()[1].self_check()", "return None", keys)
    mod.ensure_signing_material()
    assert [x[0] for x in keys.calls] == [], "改成 no-op 之后仍然打了 KMS——断言在测别的东西"
