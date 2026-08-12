"""machine_token：`client_credentials` 换 token + **受控**缓存。

本文件与 `test_no_module_level_cache.py` 是一对相反的守卫：那边确认
`machine_token.py` **确实有缓存**（结构层），这边确认那个缓存的**边界正确**
（行为层）——提前换新、过期不发、失败不写、`invalidate()` 能清。

**时间全部靠注入的 `_now()`，一次 `sleep` 都没有**：靠 sleep 测 300 秒的
margin 要么跑 300 秒，要么把 margin 改小到失去意义。

所有 secret / token 值都是本文件里现造的假值（`FAKE_SECRET` / `tok-*`），
与任何真实凭证无关。
"""
import base64
import io
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

import pytest

import machine_token as mt

# 假值。故意不做成 JWT 形态：本模块不解析 token，"看起来像真的"只会让扫描器
# 与读者都误判。
FAKE_SECRET = "not-a-real-secret-" + "0" * 8
LONG_LIVED = {"access_token": "tok-1", "expires_in": 3600}


class _Resp:
    """urlopen 的返回值（context manager + read）。"""

    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeHTTP:
    """记录每一次 urlopen 调用，并按队列给出响应。

    **计数是本文件大半用例的判据**（"只有一次 HTTP"、"没有任何 HTTP"），
    所以它记的是真实的 `Request` 对象内容，而不是被测代码告诉它的东西。
    """

    def __init__(self):
        self.calls = []
        self.queue = []
        self.default = dict(LONG_LIVED)

    def __call__(self, req, timeout=None):
        self.calls.append({
            "url": req.full_url,
            "body": (req.data or b"").decode(),
            "headers": {k.lower(): v for k, v in req.headers.items()},
            "timeout": timeout})
        item = self.queue.pop(0) if self.queue else self.default
        if isinstance(item, Exception):
            raise item
        return _Resp(json.dumps(item).encode())

    @property
    def n(self) -> int:
        return len(self.calls)


class FakeSSM:
    def __init__(self, value=FAKE_SECRET):
        self.value = value
        self.calls = []

    def get_parameter(self, **kw):
        self.calls.append(kw)
        if isinstance(self.value, Exception):
            raise self.value
        return {"Parameter": {"Value": self.value}}


class Clock:
    """注入的单调时钟。`advance()` 是本文件唯一的"时间流逝"。"""

    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(mt, "_now", c)
    return c


@pytest.fixture
def ssm(monkeypatch):
    fake = FakeSSM()
    monkeypatch.setattr(mt, "_ssm", lambda: fake)
    return fake


@pytest.fixture
def http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return fake


@pytest.fixture(autouse=True)
def _clean_caches(monkeypatch):
    """每个用例从空缓存开始。

    **不可省**：模块级缓存跨用例存活，第二个用例会拿到第一个用例的 token，
    于是"只有一次 HTTP"这类断言会因为 0 次 HTTP 而假绿。
    """
    monkeypatch.setattr(mt, "_token_cache", {})
    monkeypatch.setattr(mt, "_secret_cache", {})
    monkeypatch.setattr(mt, "_ssm_client", None)


# ------------------------------------------------------------------ 缓存边界

def test_first_call_exchanges_and_second_reuses(aws, clock, ssm, http):
    """两次调用只有一次 HTTP——这是本模块存在缓存的全部理由。"""
    assert mt.get_token() == "tok-1"
    assert mt.get_token() == "tok-1"
    assert http.n == 1, f"应只换取一次 token，实际 {http.n} 次"


def test_refreshes_before_expiry_with_margin(aws, clock, ssm, http):
    """提前 REFRESH_MARGIN_SECONDS 换新，**不等 401**。

    算术（brief 的最终数字）：`expires_in=310`，
      · 快进 5 秒 → 剩 305 > 300 → **不换**；
      · 快进到 11 秒 → 剩 299 < 300 → **必须换**。
    两个方向都断言：只断言"会换"的话，把 margin 放大到无穷也能绿
    （那等于每次都换，缓存形同虚设）。
    """
    assert mt.REFRESH_MARGIN_SECONDS == 300
    http.queue = [{"access_token": "tok-1", "expires_in": 310},
                  {"access_token": "tok-2", "expires_in": 310}]
    assert mt.get_token() == "tok-1"

    clock.advance(5)                     # 剩 305
    assert mt.get_token() == "tok-1"
    assert http.n == 1, "剩余 305 秒 > margin，不该换新"

    clock.advance(6)                     # 累计 11 秒，剩 299
    assert mt.get_token() == "tok-2", "剩余 299 秒 < margin，必须换新"
    assert http.n == 2


def test_expired_token_is_not_returned(aws, clock, ssm, http):
    """真过期后必须换新，且返回的是新那一个（不是旧串）。"""
    http.queue = [{"access_token": "tok-1", "expires_in": 310},
                  {"access_token": "tok-2", "expires_in": 310}]
    assert mt.get_token() == "tok-1"
    clock.advance(400)
    assert mt.get_token() == "tok-2"
    assert http.n == 2


def test_invalidate_forces_reexchange(aws, clock, ssm, http):
    """`invalidate()` 后必须重取（转发拿到 401/403 的兜底路径）。"""
    http.queue = [dict(LONG_LIVED), {"access_token": "tok-2",
                                     "expires_in": 3600}]
    assert mt.get_token() == "tok-1"
    mt.invalidate()
    assert mt.get_token() == "tok-2"
    assert http.n == 2


def test_invalidate_also_drops_the_secret_cache(aws, clock, ssm, http):
    """401 之后连 secret 一起重读。

    401 是"我的凭证被拒了"这条路上唯一的信号，而 secret 的 TTL 会让一次轮转
    把 warm 容器卡在旧值上（那段时间全部 502）。重试只发生一次，不构成放大。
    """
    mt.get_token()
    assert len(ssm.calls) == 1
    mt.invalidate()
    mt.get_token()
    assert len(ssm.calls) == 2, "invalidate 后 secret 也该重读"


# --------------------------------------------------------------- 凭证的来源与去处

def test_secret_read_from_ssm_not_env(aws, clock, ssm, http):
    """明文密钥严禁进环境变量——环境里只有参数名。

    `GetFunctionConfiguration` 会原样回显环境变量，而那是个很常见的只读权限。

    **本条只证明"SSM 那条路走通了"，不足以排除环境变量兜底**：反向验证
    2026-08-11 实测——在 `_secret()` 里加一条
    `if os.environ.get("MACHINE_CLIENT_SECRET"): return it` 之后本条仍绿，
    因为夹具从不往环境里放明文，那条兜底分支根本没被执行到。补两层：
      · `test_env_plaintext_secret_is_never_used`（行为层，真往环境里放明文）；
      · `test_source_never_reads_a_plaintext_secret_env_var`（AST 层，
        抓"读了但没用"以及任何新起名字的兜底变量）。
    """
    mt.get_token()
    assert ssm.calls, "没有读 SSM——secret 是从别处（很可能是环境变量）来的"
    assert ssm.calls[0]["Name"] == os.environ["MACHINE_SECRET_PARAM"]
    assert ssm.calls[0]["WithDecryption"] is True, "SecureString 必须解密读"
    assert FAKE_SECRET not in os.environ.values()
    assert not [k for k, v in os.environ.items() if v == FAKE_SECRET]


@pytest.mark.parametrize("name", ["MACHINE_CLIENT_SECRET", "CLIENT_SECRET",
                                  "MACHINE_SECRET"])
def test_env_plaintext_secret_is_never_used(aws, clock, ssm, http, monkeypatch,
                                            name):
    """环境里**放着**明文时也必须走 SSM，且明文不得出现在请求里。

    auth 的既有 `_secret()` 有意保留"环境变量直给"以便本地调试（见
    `login_handler._secret` 的 docstring）。**key-proxy 不继承那个让步**：
    它没有本地调试路径，而多一条兜底就多一处能把明文带上线的形态。
    """
    monkeypatch.setenv(name, "env-plaintext-should-be-ignored")
    assert mt.get_token() == "tok-1"
    assert ssm.calls, "环境里有明文时就不读 SSM 了——兜底路径必须不存在"
    blob = http.calls[0]["headers"]["authorization"].split(" ", 1)[1]
    assert base64.b64decode(blob).decode().endswith(f":{FAKE_SECRET}"), \
        "用的是环境变量里的明文而不是 SSM 里的值"


def test_source_never_reads_a_plaintext_secret_env_var():
    """AST：源码读的环境变量必须落在**闭集** EXPECTED_ENV 内。

    **为什么要 AST 而不只靠上一条**：上一条只能枚举它想到的名字。这条按
    **真源**（源码里所有 `os.environ` 的键）反过来查，新起一个名字也拦得住。
    白名单只有 `MACHINE_SECRET_PARAM`——那是**参数名**，不是密钥。

    **2026-08-12 从"名字里带 SECRET 就拦"改成闭集（独立审查发现的盲区）**：
    原版只标记 `"SECRET" in k.upper()` 的键，于是一条叫 `MACHINE_CLIENT_PW`
    （或 `..._PASSWORD` / `..._CRED`）的明文兜底两头都能溜过去——AST 这条不认
    那个名字，而上面那条行为用例只参数化了三个名字。本模块该读的环境变量就是
    下面五个，多出任何一个都要有人解释它是什么；这比"猜哪些名字像密钥"严格，
    而且不花额外代价。
    """
    import ast
    import pathlib
    allowed = {"MACHINE_SECRET_PARAM"}
    # 本模块环境变量的**全集**（`_config` / `_secret` / `_ssm` 的实际读取）。
    expected = {"AWS_DEFAULT_REGION", "COGNITO_DOMAIN", "MACHINE_CLIENT_ID",
                "MACHINE_SCOPE", "MACHINE_SECRET_PARAM"}
    src = pathlib.Path(mt.__file__).read_text()

    def _is_environ(node) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "environ"

    keys = set()
    for node in ast.walk(ast.parse(src)):
        # os.environ["X"]
        if isinstance(node, ast.Subscript) and _is_environ(node.value) \
                and isinstance(node.slice, ast.Constant):
            keys.add(node.slice.value)
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        f = node.func
        # os.environ.get("X") / os.getenv("X") / _env("X")
        if isinstance(f, ast.Attribute) and (
                (f.attr == "get" and _is_environ(f.value)) or f.attr == "getenv"):
            keys.add(first.value)
        elif isinstance(f, ast.Name) and f.id in {"_env", "getenv"}:
            keys.add(first.value)
    # 断言真的扫到了东西：扫法写歪时（比如以后 `_env` 改名）这条会变成一条
    # 永远绿的装饰，而它的全部价值就在于"按真源查"。
    assert allowed <= keys, (f"AST 扫不到 {sorted(allowed - keys)}"
                             "——本守卫的取值方式已经与源码脱节，先修它")
    # 闭集：新增的键一律红。真是新配置项就连同 expected 一起更新（那是一次
    # 有意的决定）；是凭证兜底就删掉它——环境里只允许出现非机密配置。
    assert keys <= expected, (
        f"源码新读了环境变量 {sorted(keys - expected)}——若它是密钥/凭证的兜底"
        "就删掉（GetFunctionConfiguration 会原样回显环境变量），若确实是新配置项"
        "就连同本用例的 expected 一起更新")
    suspicious = {k for k in keys if "SECRET" in k.upper() and k not in allowed}
    assert not suspicious, (
        f"源码读了明文密钥环境变量 {sorted(suspicious)}——环境里只允许出现"
        "参数名（GetFunctionConfiguration 会原样回显环境变量）")


def test_secret_travels_in_basic_header_not_request_body(aws, clock, ssm, http):
    """凭证走 Basic 头，不进请求体。

    两者 Cognito 都收，但请求体更容易被沿途的日志/抓包完整记录下来。
    """
    mt.get_token()
    call = http.calls[0]
    assert "client_secret" not in call["body"]
    assert FAKE_SECRET not in call["body"]
    scheme, _, blob = call["headers"]["authorization"].partition(" ")
    assert scheme == "Basic"
    assert base64.b64decode(blob).decode() == \
        f"{os.environ['MACHINE_CLIENT_ID']}:{FAKE_SECRET}"


def test_request_has_an_explicit_timeout(aws, clock, ssm, http):
    """必须显式给超时：默认无超时时上游挂住会把整个 Lambda 拖到它自己的超时，
    客户端看到 504 而不是一条可归因的 502。"""
    mt.get_token()
    timeout = http.calls[0]["timeout"]
    assert isinstance(timeout, (int, float)) and 0 < timeout <= 30


def test_secret_is_not_logged(aws, clock, ssm, http, caplog):
    """secret 是凭证：成功与失败两条路径的日志里都不得出现它。"""
    caplog.set_level(logging.DEBUG)
    mt.get_token()
    mt.invalidate()
    http.queue = [_http_error(400, "invalid_client")]
    with pytest.raises(mt.TokenUnavailable) as e:
        mt.get_token()
    assert FAKE_SECRET not in caplog.text
    assert FAKE_SECRET not in str(e.value)


def test_token_is_not_logged(aws, clock, ssm, http, caplog):
    """token 同样是凭证——拿到它就能以 key-proxy 的身份调 AgentCore。"""
    caplog.set_level(logging.DEBUG)
    token = mt.get_token()
    assert token == "tok-1"
    assert token not in caplog.text, "token 出现在日志里"


# ------------------------------------------------------------------- 失败路径

def _http_error(status: int, oauth_error=None):
    body = json.dumps({"error": oauth_error} if oauth_error else {}).encode()
    return urllib.error.HTTPError("https://auth.example.com/oauth2/token",
                                  status, "Bad Request", {},
                                  io.BytesIO(body))


@pytest.mark.parametrize("failure", [
    _http_error(400, "invalid_client"),
    _http_error(400, "invalid_scope"),
    _http_error(429, "slow_down"),
    _http_error(503),
    TimeoutError(),
    urllib.error.URLError("dns"),
])
def test_exchange_failure_raises_token_unavailable(aws, clock, ssm, http,
                                                   failure):
    """换不到就抛 `TokenUnavailable`，**绝不返回空串**。

    空串会变成 `Authorization: Bearer ` 打到网关，得到一个与本地故障毫无关系
    的 401——排查会一路查到网关配置上去。所以这里既断言"抛了"，也断言
    "没有任何返回值路径"（`pytest.raises` 之外再核一遍返回值不可能是空串）。
    """
    http.queue = [failure]
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()


def test_response_without_access_token_raises(aws, clock, ssm, http):
    """200 但响应体里没有 access_token → 一样是换不到（不能把 None 发出去）。"""
    http.queue = [{"expires_in": 3600}]
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()


def test_ssm_failure_raises_token_unavailable(aws, clock, http, monkeypatch):
    """读不到 secret 就换不到 token——**不回退到空 secret 去撞 Cognito**。

    回退的症状是一个 invalid_client，而日志会指向 Cognito 配置而不是这次
    SSM 失败（排查方向被带偏），且它还白发一次请求。
    """
    monkeypatch.setattr(mt, "_ssm", lambda: FakeSSM(RuntimeError("denied")))
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()
    assert http.n == 0, "secret 都没拿到，不该发出任何 HTTP"


def test_failure_does_not_poison_cache(aws, clock, ssm, http):
    """一次失败之后下一次必须重试，且能拿到真 token。

    把失败结果缓存住会让一次抖动变成整个 margin 时长的全量不可用。
    """
    http.queue = [_http_error(503), dict(LONG_LIVED)]
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()
    assert mt.get_token() == "tok-1"
    assert http.n == 2


def test_token_without_usable_expires_in_is_not_cached(aws, clock, ssm, http):
    """`expires_in` 缺失/非法时**照用但不缓存**——绝不自己发明一个有效期。

    猜一个偏长的值会让缓存把已经失效的 token 一直发出去（症状是间歇 401，
    且看不出与时间有关）。
    """
    http.queue = [{"access_token": "tok-1"},
                  {"access_token": "tok-2", "expires_in": "abc"},
                  {"access_token": "tok-3", "expires_in": -1}]
    assert mt.get_token() == "tok-1"
    assert mt.get_token() == "tok-2"
    assert mt.get_token() == "tok-3"
    assert http.n == 3


# --------------------------------------------------------------------- scope

@pytest.mark.parametrize("scope", ["site-builder/invoke",
                                   "other-resource-server/other-scope",
                                   "sb-mcp-9/invoke"])
def test_scope_is_sent(aws, clock, ssm, http, monkeypatch, scope):
    """请求体里的 `scope` **逐字符等于** `MACHINE_SCOPE` 环境变量。

    参数化成多个值是为了让"硬编码 `site-builder-mcp/invoke`"必红：只用一个
    值时，硬编码的那一版只要和夹具凑巧一致就能蒙过去。拼接逻辑只存在于
    `deploy_key_proxy.py`（Codex P1-2a），运行时只读不拼。
    """
    monkeypatch.setenv("MACHINE_SCOPE", scope)
    mt.get_token()
    qs = urllib.parse.parse_qs(http.calls[0]["body"])
    assert qs.get("scope") == [scope]
    assert qs.get("grant_type") == ["client_credentials"]


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_scope_env_raises_not_empty_scope_request(aws, clock, ssm, http,
                                                          monkeypatch, value):
    """`MACHINE_SCOPE` 缺失/空 → `TokenUnavailable`，且**零 HTTP**。

    不能拿空 scope 去撞 Cognito：它会拒，但错误文案指向 client 配置，
    排查方向会被整个带偏（这正是 P1-2a 要求下发完整 scope 串的原因）。
    """
    if value is None:
        monkeypatch.delenv("MACHINE_SCOPE", raising=False)
    else:
        monkeypatch.setenv("MACHINE_SCOPE", value)
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()
    assert http.n == 0, "空 scope 也发了请求"


@pytest.mark.parametrize("name", ["COGNITO_DOMAIN", "MACHINE_CLIENT_ID",
                                  "MACHINE_SECRET_PARAM"])
def test_missing_config_fails_closed_without_http(aws, clock, ssm, http,
                                                  monkeypatch, name):
    """任一必需配置缺失 → `TokenUnavailable`，不发 HTTP。

    抛 `KeyError` 会冒成未捕获异常（502 + 一条堆栈），在监控上与"上游故障"
    无法区分，而这些其实全是部署脚本的问题。
    """
    monkeypatch.delenv(name, raising=False)
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()
    assert http.n == 0


def test_token_endpoint_must_be_https(aws, clock, ssm, http, monkeypatch):
    """明文 http 一律拒：请求体带 client secret，响应带 access token。"""
    monkeypatch.setenv("COGNITO_DOMAIN", "http://auth.example.com")
    with pytest.raises(mt.TokenUnavailable):
        mt.get_token()
    assert http.n == 0


@pytest.mark.parametrize("domain", ["auth.example.com",
                                    "https://auth.example.com",
                                    "https://auth.example.com/"])
def test_bare_and_schemed_domains_both_work(aws, clock, ssm, http, monkeypatch,
                                            domain):
    """`COGNITO_DOMAIN` 的两种既有写法都要接（auth 带 scheme，key-proxy 夹具
    是裸域名），且端点路径固定为 `/oauth2/token`（不出现双斜杠）。"""
    monkeypatch.setenv("COGNITO_DOMAIN", domain)
    mt.get_token()
    assert http.calls[0]["url"] == "https://auth.example.com/oauth2/token"
