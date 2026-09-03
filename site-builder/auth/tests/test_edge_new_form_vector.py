"""auth signer → Edge verifier 的**新形态正向跨组件向量**（3c-1B，spec §11.8.13 / D10）。

**为什么必须存在，且必须在 auth 这一侧**：1A 已有的跨组件向量（
`router/infrastructure/lambda/test_edge_kid_allowlist.py`）用的是测试自己调 `mint_token`——
它证明"生产 mint 的产物 Edge 认"，但**不经过 handler**。于是 handler 里的 `token_use` /
`aud` / kid family / 密钥来源写错一个字，那批向量全绿而线上每一枚会话都验不过（§9 的负向用例
同样全绿：它们本来就期望"拒"）。本文件把链条补齐：真的走 `/login` → `/callback`，把
`Set-Cookie` 里那枚 token 投给 Edge 源码（占位符替换后的 testable 副本）的验签函数。

住在 auth 而不是 router 的原因很实在：`login_handler` import `pyjwt`，router 的测试借
deployer 的 venv（没有 pyjwt），auth 借 contract 的（有）。Edge 那边只依赖 boto3/botocore，
从这边加载它是可行的方向；反过来不行。

末尾两条**变形测试**（spec 的实施纪律：用临时副本，不对含未提交修改的文件 `git checkout --`）
证明这条向量真会红：把 handler 源码里的 `token_use` 字面量改一个字，在临时副本上加载并重跑，
必须转红。
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

import login_handler as lh
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "panel" / "tests"))
from conftest import SITE_KID_SECRET
from module_mutation import mutate_module_segment  # noqa: E402
# 复用 /login → /callback 的完整走法（真 state、真 PKCE cookie，只 patch code 交换），
# 免得这里再写第二份"怎么拿到一枚会话 cookie"——那正是复制品漂移的形状。
from test_login_handler import ENV, ENV_CURRENT, _b64d, _do_callback, _session_cookie

AUTH = Path(__file__).resolve().parents[1]
EDGE_SRC_PATH = AUTH.parents[1] / "router" / "infrastructure" / "lambda" / "origin_request.py"

# Edge 的 allowlist 里**只有 site family**（spec §4.1）；secret 与 conftest 假 SSM 给 auth 的
# 那把是同一个值——跨组件向量的全部意义就在于两侧对同一把 key 达成一致。
EDGE_ALLOWLIST = {"site-hs-v1": {"alg": "HS256", "secret": SITE_KID_SECRET, "role": "current"}}
EDGE_SUBS = {"{{DYNAMODB_TABLE_NAME}}": "t", "{{DYNAMODB_REGION}}": "us-east-1",
             "{{FRONTEND_BUCKET_DOMAIN}}": "b.s3.us-east-1.amazonaws.com",
             "{{JWT_SECRET}}": ENV["JWT_SECRET"], "{{BASE_DOMAIN}}": "example.com",
             "{{REQUIRE_IDP_CLAIM}}": "true", "{{TRUSTED_IDPS}}": "Feishu,Okta",
             "{{ACCESS_TABLE}}": "site-access-events",
             "{{ACCESS_REPLICA_REGIONS}}": "us-east-1",
             "{{SITE_ALLOWLIST_JSON}}": json.dumps(EDGE_ALLOWLIST),
             "{{LEGACY_ENTRY}}": "on"}

ROUTE = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x", "api_target": "",
         "require_auth": True, "allowed_users": "org", "owner": "o@example.test"}


def _load_from_source(name: str, src: str, tmp_path: Path):
    """把一份源码作为独立模块加载（Edge 副本与 handler 变形副本共用）。"""
    path = tmp_path / f"{name}.py"
    path.write_text(src)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def edge(tmp_path):
    src = EDGE_SRC_PATH.read_text()
    for k, v in EDGE_SUBS.items():
        src = src.replace(k, v)
    import re
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", src)))
    assert not left, (
        f"Edge 源码里还有没替换的占位符 {left}：origin_request.py 新增了注入项，"
        "把它加进本文件的 EDGE_SUBS。**不补的后果不是假红而是假绿**——带 {{…}} 的模块照样能 import，"
        "只有验签相关的那几个才会让向量变红。")
    return _load_from_source("_edge_new_form_vector_testable", src, tmp_path)


def _edge_allows(edge_mod, token: str) -> bool:
    req = {"uri": "/", "querystring": "", "method": "GET",
           "headers": {"host": [{"key": "Host", "value": "app-x.example.com"}],
                       "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}
    return edge_mod._check_auth(req, dict(ROUTE), "app-x.example.com") is None


# ---- 正向向量 -----------------------------------------------------------------------------

def test_session_minted_by_the_auth_handler_verifies_at_the_edge(edge):
    token = _session_cookie(_do_callback(ENV_CURRENT, email="a@x.com", name="Alice"))
    claims = edge._verify_session_jwt(token)
    assert claims, "auth 按 current 形态签的会话在 Edge 验不过——线上等于每个人登录后立刻被踢回"
    assert claims["email"] == "a@x.com" and claims["token_use"] == "site-session"
    assert claims["aud"] == "site-edge"
    assert _edge_allows(edge, token), "验签过了但 _check_auth 仍拒（idp/auth_via 那段）"


def test_the_edge_records_it_as_accepted_current_not_accepted_legacy(edge, caplog):
    """④ 观察窗口的判据是"accepted_legacy 三列归零"——记成 legacy 的话那个窗口永远不会到。"""
    import logging
    token = _session_cookie(_do_callback(ENV_CURRENT))
    with caplog.at_level(logging.INFO):
        edge._verify_session_jwt(token)
    rows = [json.loads(r.getMessage()) for r in caplog.records
            if r.getMessage().startswith("{") and '"session_verify"' in r.getMessage()]
    assert rows and rows[-1]["outcome"] == "accepted_current"


def test_the_legacy_form_still_verifies_at_the_edge_while_the_switch_is_legacy(edge):
    """回滚方向的向量：③ 之前与回滚之后 auth 签的是 legacy 形态，Edge 同样必须认。"""
    token = _session_cookie(_do_callback(ENV))
    assert _edge_allows(edge, token)
    assert _b64d(token.split(".")[0]) == {"alg": "HS256", "typ": "JWT"}


def test_the_console_family_upgrade_code_is_rejected_at_the_edge(edge):
    """负向对照：同一次切换里 auth 也在发升级码，它**不得**是一枚站点会话。"""
    with pytest.MonkeyPatch.context() as mp:
        for k, v in ENV_CURRENT.items():
            mp.setenv(k, v)
        r = lh.handler({"rawPath": "/console-session", "queryStringParameters": {},
                        "cookies": [f"sb_session={_session_cookie(_do_callback(ENV_CURRENT))}"],
                        "requestContext": {"http": {"method": "GET"}}}, None)
    code = r["headers"]["Location"].split("code=", 1)[1]
    import urllib.parse
    assert not _edge_allows(edge, urllib.parse.unquote(code))


# ---- 变形测试：证明正向向量真会红 -----------------------------------------------------------

# 变形只允许落在 `//callback` 这一段里：`token_use="site-session"` 在文件里出现两次，另一处是
# `/console-session` 里 `verify_with_legacy` 的**验签**参数——改它测的是另一件事，且会让
# "变形必红"变成假信号。所以锚点先按段落切，再要求段内唯一。
CALLBACK_REGION = ('if path == "/callback"', 'if path == "/console-session"')


def _handler_variant(tmp_path, old: str, new: str, *, region=CALLBACK_REGION):
    """在**临时副本**上改一个字面量再加载（助手与 panel 侧共用，见 module_mutation）。"""
    mod = mutate_module_segment(AUTH / "login_handler.py", region=region, old=old, new=new,
                               tmp_path=tmp_path, module_name="_login_handler_mutant")
    # 假 SSM 只装在真模块上（conftest 的 autouse 夹具）；副本自带一份干净的缓存与 client
    mod._ssm = lh._ssm
    return mod


def _mutant_callback(mod):
    from unittest.mock import patch
    user = {"email": "a@x.com", "name": "Alice", "idp": "Feishu",
            "auth_via": "TokenGeneration_HostedAuth"}
    with patch.dict(mod.os.environ, ENV_CURRENT), patch.object(mod, "_exchange_code", return_value=user):
        r_login = mod.handler({"rawPath": "/login", "queryStringParameters": {"redirect": "https://app-x.example.com/"},
                               "cookies": [], "requestContext": {"http": {"method": "GET"}}}, None)
        import urllib.parse as up
        state = up.unquote(r_login["headers"]["Location"].split("state=")[1].split("&")[0])
        pkce = next(c for c in r_login["cookies"] if c.startswith(mod.PKCE_COOKIE)).split(";")[0]
        return mod.handler({"rawPath": "/callback", "queryStringParameters": {"code": "abc", "state": state},
                            "cookies": [pkce], "requestContext": {"http": {"method": "GET"}}}, None)


def test_mutating_the_signer_token_use_to_another_valid_value_turns_the_vector_red(edge, tmp_path):
    """`site-session` → `console-session`：mint 照样成功、cookie 照样种下，但 Edge 必须拒。"""
    mod = _handler_variant(tmp_path, 'token_use="site-session"', 'token_use="console-session"')
    token = _session_cookie(_mutant_callback(mod))
    assert _b64d(token.split(".")[1])["token_use"] == "console-session"
    assert not _edge_allows(edge, token), "改了 token_use 字面量，正向向量竟然还绿"
    assert edge._verify_session_jwt(token) is None


def test_mutating_the_signer_token_use_by_one_character_fails_before_it_signs(tmp_path):
    """`site-session` → `site-sessio`：不在 TOKEN_USES 表里 ⇒ mint 直接抛，签不出无效 aud 的 token。"""
    mod = _handler_variant(tmp_path, 'token_use="site-session"', 'token_use="site-sessio"')
    with pytest.raises(KeyError):
        _mutant_callback(mod)


def test_mutating_the_signing_family_to_console_turns_the_vector_red(edge, tmp_path):
    """`_signing_key("site")` → `("console")`：Edge 的 allowlist 里没有 console 的 kid ⇒ unknown_kid。"""
    mod = _handler_variant(tmp_path, '_signing_key("site")', '_signing_key("console")')
    token = _session_cookie(_mutant_callback(mod))
    assert _b64d(token.split(".")[0])["kid"] == "console-hs-v1"
    assert not _edge_allows(edge, token)
