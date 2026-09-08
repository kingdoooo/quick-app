"""3c-1B ticket 21：模块级消费注入值 ⇒ 注入失败的爆炸半径是**整个分发**。

`origin_request.py` 里有两处在 **import 期**就消费注入值的语句：
  · `json.loads(SITE_ALLOWLIST_JSON)`  → 占位符未替换时 `JSONDecodeError`
  · `boto3.client(region_name=DYNAMODB_REGION)` → botocore 校验区域名形态，抛 `InvalidRegionError`
两者都在模块顶层，于是 Lambda@Edge **连 handler 都实例化不了**，该分发上所有请求 502
（含 `require_auth=False` 的公开站点、静态资源、console 前端）。1A 之前同样的事故只是
"legacy 密钥是个错字符串" ⇒ 只有已登录会话验签失败、fail-closed 302，公开站点照常。

本文件钉住三件事：
1. **一个替换都不做**也能 import（工具与测试不必维护整张替换表；漏一项的症状原本是
   "import 期一个与占位符毫无关系的异常"）；
2. 首次**使用**时才失败，且报文点名那个注入点、**绝不回显值**（allowlist 里是每个 kid 的密钥）；
3. 爆炸半径真的变小了：公开路由与"没带 cookie"两条路根本不碰 allowlist。

判据都在真源 `origin_request.py` 上（经 `edge_substitutions` 做与 CDK 同一套替换），
不测副本、不测简化件。
"""
import json
import sys
import types
from pathlib import Path

import pytest

import edge_substitutions as es

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import upgrade_code_vectors as v  # noqa: E402  三套件共用的 RS 测试密钥
RAW_SRC = es.EDGE_SRC_PATH.read_text(encoding="utf-8")

# 故意让坏 JSON 带上这个标记，用来断言整份文本不会出现在报文里（3c-final 之后它是公钥、
# 不再是密钥，但"报文只点名注入点"这条不变——回显一整份 JSON 只会淹掉唯一有用的那句）。
LEAK_MARKER = "LEAK-MARKER-THIS-IS-THE-INJECTED-BLOB"
BROKEN_ALLOWLIST_JSON = '{"site-rs-v1": {"alg": "RS256", "spki_b64": "' + LEAK_MARKER + '"'  # 少一个括号


def _load_raw(name: str = "_edge_unsubstituted") -> types.ModuleType:
    """**一个占位符都不替换**地加载真源。内存 exec，不落盘、不进 sys.modules。"""
    mod = types.ModuleType(name)
    mod.__dict__["__file__"] = str(es.EDGE_SRC_PATH)
    exec(compile(RAW_SRC, str(es.EDGE_SRC_PATH), "exec"), mod.__dict__)
    return mod


def _load(**overrides) -> types.ModuleType:
    return es.load_edge_module("_edge_lazy_cfg", **overrides)


# ---- ① 不替换也能 import ---------------------------------------------------------------

def test_the_raw_source_really_still_has_placeholders_in_it():
    """正对照：下面那条"不替换也能 import"必须是在真的没替换的源码上通过的。"""
    assert es.PLACEHOLDER_RE.findall(RAW_SRC), "真源里已经没有占位符了？那下一条什么都没证明"


def test_unsubstituted_source_imports_successfully():
    """核心：占位符原封不动时 import 必须成功——模块顶层不许再消费任何注入值。"""
    mod = _load_raw()
    assert callable(mod.lambda_handler)


def test_every_placeholder_appears_exactly_once_so_comments_never_duplicate_a_secret():
    """注入点之外**不许**再提及 `{{NAME}}` 形态（哪怕在注释/docstring 里）。

    stack.py 的注入是**全文替换**：在注释里写一次 `{{SITE_ALLOWLIST_JSON}}` 就等于把整份
    allowlist（含每个 kid 的密钥）在产物里多印一遍，而所有既有闸门都看不出来
    （逐行比对与残留检查都是替换后做的，两侧一致）。所以用名字指代占位符，别带花括号。
    """
    dupes = {p: RAW_SRC.count(p) for p in set(es.PLACEHOLDER_RE.findall(RAW_SRC))
             if RAW_SRC.count(p) != 1}
    assert not dupes, f"这些占位符在源码里出现了多次（注释里提到了？）：{dupes}"


# ---- ② 首次使用才失败，报文点名注入点且不回显值 ----------------------------------------

def test_the_allowlist_fails_on_first_use_and_names_the_injection_point():
    mod = _load_raw()
    with pytest.raises(RuntimeError, match="SITE_ALLOWLIST_JSON"):
        mod._site_allowlist()


def test_the_allowlist_error_never_echoes_the_value_because_it_holds_the_keys():
    """坏 JSON 的**内容**不许进报文，也不许经 `__cause__`/`__context__` 溜进去。

    `JSONDecodeError` 把整份文本挂在 `.doc` 上。当前 CPython 不把它放进 `args`/`str()`，
    但那不是契约——所以这里要求 `from None`（`__suppress_context__`），别给它机会。
    """
    mod = _load(SITE_ALLOWLIST_JSON=BROKEN_ALLOWLIST_JSON)
    with pytest.raises(RuntimeError) as excinfo:
        mod._site_allowlist()
    rendered = f"{excinfo.value}|{excinfo.value.__cause__}|{excinfo.value.__context__}"
    assert LEAK_MARKER not in rendered, f"密钥进了报文：{rendered[:200]}"
    assert excinfo.value.__cause__ is None and excinfo.value.__suppress_context__


def test_a_non_object_allowlist_is_rejected_instead_of_being_indexed():
    """JSON 合法但不是对象（例如注成了数组）⇒ 明确报错，不要留到 `allowlist[kid]` 才 TypeError。"""
    mod = _load(SITE_ALLOWLIST_JSON='["site-rs-v1"]')
    with pytest.raises(RuntimeError, match="SITE_ALLOWLIST_JSON"):
        mod._site_allowlist()


def test_the_allowlist_is_parsed_once_and_then_memoised():
    """解析一次即缓存：把源字符串换成坏 JSON 之后仍能拿到同一个对象 ⇒ 没有重复解析。

    返回值里 `spki_b64` 已经被换成 **RSAPublicKey 对象**（那一步也在这个函数里、也是惰性的），
    所以判据是"kid 集合 + alg/role 原样 + public_key 已经是对象"，不是与入参 dict 相等。
    """
    allow = {v.SITE_KID: {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"}}
    mod = _load(SITE_ALLOWLIST_JSON=json.dumps(allow))
    first = mod._site_allowlist()
    assert set(first) == {v.SITE_KID}
    assert first[v.SITE_KID]["alg"] == "RS256" and first[v.SITE_KID]["role"] == "current"
    assert first[v.SITE_KID]["public_key"].key_size == 2048
    mod.SITE_ALLOWLIST_JSON = BROKEN_ALLOWLIST_JSON      # 若还会再解析，这一步会让下面炸
    assert mod._site_allowlist() is first


# ---- ③ 爆炸半径：公开路由与无 cookie 的请求根本不碰 allowlist ---------------------------

ROUTE_PUBLIC = {"subdomain": "app-x", "site_id": "x", "static_prefix": "sites/x",
                "api_target": "", "require_auth": False, "owner": "o@x.com"}
ROUTE_PRIVATE = dict(ROUTE_PUBLIC, require_auth=True, allowed_users="org")


def _req(cookie=None):
    headers = {"host": [{"key": "Host", "value": "app-x.example.com"}]}
    if cookie:
        headers["cookie"] = [{"key": "Cookie", "value": cookie}]
    return {"uri": "/", "querystring": "", "method": "GET", "headers": headers}


def _broken():
    return _load(SITE_ALLOWLIST_JSON=BROKEN_ALLOWLIST_JSON)


def _b64(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _kid_token(kid: str = "site-rs-v2") -> str:
    """一枚**带 kid** 的 token。签名对不对无所谓：契约顺序是先取 allowlist 再验签，
    所以它足以走到取 allowlist 那一步（用 `a.b.c` 是不行的——那连 header 都解不出来，
    在 `bad_signature` 就返回了，第一版用例正是这样假绿的）。"""
    import time
    h = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    p = _b64(json.dumps({"token_use": "site-session", "aud": "site-edge", "email": "a@x.com",
                         "exp": int(time.time()) + 600}).encode())
    sig = _b64(b"x" * 256)          # 长度对得上模长，内容是垃圾（走不到验签就够了）
    return f"{h}.{p}.{sig}"


def test_public_routes_are_unaffected_by_a_broken_allowlist():
    """这就是本票买的东西：注入坏了，公开站点照常放行（以前是整个分发 502）。"""
    assert _broken()._check_auth(_req(), dict(ROUTE_PUBLIC), "app-x.example.com") is None


def test_requests_without_a_session_cookie_still_get_the_normal_login_redirect():
    resp = _broken()._check_auth(_req(), dict(ROUTE_PRIVATE), "app-x.example.com")
    assert resp["status"] == "302"


def test_only_a_request_carrying_a_session_cookie_hits_the_broken_allowlist():
    """负向对照：坏配置**必须**在这条路上响亮失败（500），不许静默当成"验签不过"放人走 302。

    静默降级在这里最危险：它会把"配置坏了"表现成"所有人的会话都失效了"。
    """
    mod = _broken()
    with pytest.raises(RuntimeError, match="SITE_ALLOWLIST_JSON"):
        mod._check_auth(_req(cookie=f"sb_session={_kid_token()}"), dict(ROUTE_PRIVATE),
                        "app-x.example.com")


def test_a_malformed_cookie_still_never_needs_the_allowlist():
    """连 header 都解不出来的 cookie 在 `bad_signature` 就返回了 ⇒ 也不碰 allowlist。

    这条同时是上面那条的**边界说明**：判据必须用带 kid 的 token，否则用例根本没走到取 allowlist
    那一步（第一版用 `a.b.c`，于是"坏配置会响亮失败"这件事完全没被证明）。
    """
    resp = _broken()._check_auth(_req(cookie="sb_session=a.b.c"), dict(ROUTE_PRIVATE),
                                 "app-x.example.com")
    assert resp["status"] == "302"


# ---- ④ 路由表 client 同样惰性（它不缩小半径，但决定了"能不能 import"）------------------

def test_route_table_client_is_built_on_first_use_not_at_import():
    mod = _load_raw()
    with pytest.raises(Exception) as excinfo:      # botocore.exceptions.InvalidRegionError
        mod._ddb()
    assert "DYNAMODB_REGION" in str(excinfo.value), str(excinfo.value)


def test_route_table_client_is_cached_after_the_first_build():
    mod = _load(DYNAMODB_REGION="us-east-1")
    assert mod._ddb() is mod._ddb()


def test_route_lookup_goes_through_the_lazy_accessor():
    """源码守卫：不许再出现模块级 client。留一个模块级 `dynamodb = boto3.client(...)`
    就把 import 期的失败带回来了，而两条 lazy 用例仍会绿（它们不看有没有别的 client）。"""
    assert "boto3.client(\"dynamodb\", region_name=DYNAMODB_REGION)" in RAW_SRC
    assert "\ndynamodb = " not in RAW_SRC, "模块级 dynamodb client 又回来了"
    assert "_ddb().get_item(" in RAW_SRC
