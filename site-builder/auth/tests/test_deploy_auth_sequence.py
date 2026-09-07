"""deploy_auth 的部署顺序合同（3c-1B ticket 02；spec §11.8.3、§11.8.12）。

两条：① **第一次写之前**核对本组件要读的每个外部 SSM 参数存在（只读、不解密、不打印值），缺任一个即拒绝
部署且函数/角色/resource policy/路由表零写入；② 更新 Lambda 时**先** update_function_configuration
**再** update_function_code——1B 的两处 env 变化都是新增变量，旧代码忽略新变量无害，新代码缺新变量会 500。
用假 client 记录调用序列，先于实现写下并跑红。
"""
import ast
import configparser
import json
import textwrap
from pathlib import Path

import pytest

import deploy_auth as da

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.test
    account_id = 111111111111
    routing_table = site-routes

    [Cognito]
    user_pool_id = us-east-1_test
    domain = https://sso.auth.us-east-1.amazoncognito.com
    site_client_id = cid

    [Deployer]
    edge_role_arn = arn:aws:iam::111111111111:role/site-edge-role

    [Alerting]
    email = ops@example.test

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


class _NotFound(Exception):
    pass


class FakeSSM:
    def __init__(self, present):
        self.present = set(present)
        self.calls = []
        self.exceptions = type("E", (), {"ParameterNotFound": _NotFound})

    def get_parameter(self, **kw):
        self.calls.append(("get_parameter", kw))
        if kw["Name"] not in self.present:
            raise _NotFound(kw["Name"])
        return {"Parameter": {"Value": f"value-of-{kw['Name']}"}}

    def put_parameter(self, **kw):
        self.calls.append(("put_parameter", kw))


class Recorder:
    """任何方法调用都记下来；get_function 可按需抛 ResourceNotFound。"""
    def __init__(self, missing_function=False):
        self.calls = []
        self.kwargs = {}          # 方法名 -> 最后一次调用的 kwargs（3c-1B：要看策略文档内容）
        self.missing_function = missing_function
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound,
                                          "ResourceConflictException": type("C", (Exception,), {}),
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        def call(*a, **kw):
            self.calls.append(name)
            self.kwargs[name] = kw
            if name == "get_function" and self.missing_function:
                raise _NotFound()
            if name == "get_waiter":
                return type("W", (), {"wait": lambda s, **k: self.calls.append("wait")})()
            return {"FunctionUrl": "https://x.lambda-url.example/", "Role": {"Arn": "arn:x"}}
        return call


@pytest.fixture
def cfg_files(tmp_path, monkeypatch):
    p = tmp_path / "config.ini"
    p.write_text(CFG)
    c = configparser.ConfigParser()
    c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p)
    monkeypatch.setattr(da, "_CFG", c)
    return p


def test_required_parameters_are_the_externally_provisioned_ones(cfg_files):
    """session-keys 由 ensure_session_keys.py 建、client secret 由 deploy_pool 建——都不是本脚本的，缺了就该停。
    legacy 参数是本脚本自己 ensure 的，不在核对清单里（首次部署它本来就不存在）。"""
    assert set(da.required_parameters()) == {"/site-builder/session-keys/site-hs-v1",
                                             "/site-builder/session-keys/console-hs-v1",
                                             da.CLIENT_SECRET_PARAM}


def test_precheck_reads_without_decryption_and_names_every_missing_parameter(cfg_files, monkeypatch, capsys):
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    monkeypatch.setitem(da._CLIENTS, "ssm", ssm)
    with pytest.raises(SystemExit) as ei:
        da.precheck()
    msg = str(ei.value)
    assert "site-hs-v1" in msg and "console-hs-v1" in msg and "ensure_session_keys" in msg
    assert all(not kw.get("WithDecryption") for _, kw in ssm.calls), "核对只看存在性，不解密"
    assert "value-of-" not in capsys.readouterr().out + msg


def test_deploy_function_updates_configuration_before_code_on_the_update_path():
    lam = Recorder()
    da.deploy_function(lam, role_arn="arn:x", env={"Variables": {}}, code=b"zip")
    assert lam.calls == ["get_function", "update_function_configuration", "get_waiter", "wait",
                         "update_function_code", "get_waiter", "wait"]


def test_deploy_function_create_path_still_creates_then_waits():
    lam = Recorder(missing_function=True)
    da.deploy_function(lam, role_arn="arn:x", env={"Variables": {}}, code=b"zip")
    assert lam.calls == ["get_function", "create_function", "get_waiter", "wait"]


def test_main_aborts_before_any_write_when_a_parameter_is_missing(cfg_files, monkeypatch):
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, "/site-builder/session-keys/site-hs-v1"})   # console 缺
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    with pytest.raises(SystemExit, match="console-hs-v1"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []
    assert not [c for c in ssm.calls if c[0] == "put_parameter"], "缺参时连 ensure_secret 也不该写"


def test_main_source_calls_precheck_before_every_write_helper():
    """结构守卫：main() 里 precheck() 的调用位置在 ensure_secret / ensure_lambda_role / build_zip / deploy_function 之前。"""
    src = Path(da.__file__).read_text()
    tree = ast.parse(src)
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    order = []
    for node in ast.walk(main_fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            order.append((node.lineno, node.func.id))
    order.sort()
    names = [n for _, n in order]
    assert "precheck" in names
    first_write = min(names.index(n) for n in ("ensure_secret", "ensure_lambda_role", "build_zip", "deploy_function") if n in names)
    assert names.index("precheck") < first_write, names


# ── 3c-1B：login-flow secret（spec §11.3 / §11.8.6）──────────────────────────
#
# 三条不变量：① 环境变量下发的是**参数名**（`{name}_PARAM` 约定，`_login_flow_sig` 因此不改取值代码）；
# ② 它进 auth 角色的 SSM 精确清单（否则运行时 AccessDenied ⇒ 所有 /login 500）；
# ③ 它**不进** panel（见 panel 那边的对称用例）。

# 路径字面量在本包里只定义一处（conftest），免得"单一真源"这条断言自己有两份拷贝
from conftest import LOGIN_FLOW_PARAM        # noqa: E402


def test_lambda_env_ships_the_login_flow_param_name_never_the_value(cfg_files):
    env = da.lambda_env()["Variables"]
    assert env["LOGIN_FLOW_SECRET_PARAM"] == LOGIN_FLOW_PARAM
    # 单一真源：值来自 [SessionKeys]，不是脚本里另抄一个字面量
    from session_keys import load_session_keys
    assert env["LOGIN_FLOW_SECRET_PARAM"] == load_session_keys(da.CFG_PATH).login_flow_secret_param
    src = Path(da.__file__).read_text()
    block = src[src.index("def lambda_env"):src.index("def required_parameters")]
    assert '"LOGIN_FLOW_SECRET_PARAM": LOGIN_FLOW' not in block, "参数名硬编码，与 [SessionKeys] 分叉"
    # `_secret("LOGIN_FLOW_SECRET")` 走 {name}_PARAM 约定，所以**不得**有同名的明文变量
    assert "LOGIN_FLOW_SECRET" not in set(env), "环境变量里出现了明文密钥的键名"


def test_login_flow_secret_is_not_in_session_keys_json(cfg_files):
    """SESSION_KEYS_JSON 是 verifier 的 allowlist；login-flow 不签发也不验证会话。"""
    env = da.lambda_env()["Variables"]
    assert "login-flow" not in env["SESSION_KEYS_JSON"]


def test_auth_role_ssm_list_includes_the_login_flow_param_exactly(cfg_files, monkeypatch):
    iam = Recorder()
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    da.ensure_lambda_role()          # get_role 命中 ⇒ created=False ⇒ 不会 sleep(10)
    doc = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])
    ssm_res = [r for st in doc["Statement"] if "ssm:GetParameter" in json.dumps(st.get("Action"))
               for r in (st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]])]
    assert f"arn:aws:ssm:us-east-1:111111111111:parameter{LOGIN_FLOW_PARAM}" in ssm_res
    assert not any(r.endswith("*") for r in ssm_res), "出现通配前缀——会顺带交出别的秘密"


def test_required_parameters_excludes_login_flow_because_this_script_creates_it(cfg_files):
    """**与 spec §11.8.12 的字面清单有意不同**，理由与 legacy 那条完全相同。

    裁定真源：`docs/adr/0004-login-flow-secret-outside-the-pre-write-precheck.md`。

    §11.8.12 把 login-flow 列进 auth 的写前核对清单，但 D5/§11.8.6 同时要求 `deploy_auth` 对它
    保留一条 `ensure_secret` 缺省补建。两者不能同时成立：precheck 在任何写之前，核对它就等于让它
    永远走不到（首次部署必然被自己拒掉）。

    保留缺省补建、不核对它，是因为 precheck 防的那个具体失败在这把密钥上**不存在**：
    核对的意义是"多个消费方必须就同一个值达成一致，所以不能由本脚本随手造一个"。
    login-flow 只有 auth 一个消费方（panel 与 Edge 永不持有），auth 自己造一把随机值完全正确；
    而 §11.8.12 的原始动机（"⑥ 忘跑 ensure_session_keys 就会撞上"）说的是轮转期新增的会话密钥，
    login-flow 在 1B 里只创建一次、不参与轮转演练。
    """
    assert LOGIN_FLOW_PARAM not in da.required_parameters()
    assert set(da.required_parameters()) == {"/site-builder/session-keys/site-hs-v1",
                                             "/site-builder/session-keys/console-hs-v1",
                                             da.CLIENT_SECRET_PARAM}


def _run_main(monkeypatch, ssm):
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline",
                        lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    # M07：Function URL 授权走共享的 converge；这里换成记录器（Recorder 的 get_policy 返回的不是 policy），
    # 它的真实行为由 deployer/tests/test_function_url_policy.py 与下面的端到端用例覆盖。
    monkeypatch.setattr(da, "converge_function_url_policy",
                        lambda client, fn, arn: _CONVERGE_CALLS.append((client, fn, arn)) or _DriftStub())
    _CONVERGE_CALLS.clear()
    da.main()
    return lam, iam, ddb


_CONVERGE_CALLS: list = []


class _DriftStub:
    def summary(self):
        return "一致"


def test_main_creates_the_login_flow_secret_when_it_is_absent(cfg_files, monkeypatch):
    """缺省补建的**正对照**：没有这一条，那条补建就是死代码，而上一条用例正是靠它才成立。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, "/site-builder/session-keys/site-hs-v1",
                           "/site-builder/session-keys/console-hs-v1"})
    _run_main(monkeypatch, ssm)
    written = [kw["Name"] for name, kw in ssm.calls if name == "put_parameter"]
    assert LOGIN_FLOW_PARAM in written, "deploy_auth 没有为 login-flow 缺省补建"
    for name, kw in ssm.calls:
        if name == "put_parameter":
            assert kw.get("Type") == "SecureString"


def test_main_never_overwrites_an_existing_login_flow_secret(cfg_files, monkeypatch):
    """覆盖它 = 所有进行中的登录失败一次。幂等重跑必须什么都不写。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, "/site-builder/session-keys/site-hs-v1",
                           "/site-builder/session-keys/console-hs-v1",
                           LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    _run_main(monkeypatch, ssm)
    assert [kw["Name"] for name, kw in ssm.calls if name == "put_parameter"] == []


def test_config_first_then_code_still_holds_with_the_new_variable(cfg_files, monkeypatch):
    """1B 的 env 新增变量正是"先配置后代码"要保护的场景：旧代码忽略它无害，新代码缺它必 500。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, "/site-builder/session-keys/site-hs-v1",
                           "/site-builder/session-keys/console-hs-v1", LOGIN_FLOW_PARAM,
                           "/site-builder/jwt-secret"})
    lam, _, _ = _run_main(monkeypatch, ssm)
    assert lam.calls.index("update_function_configuration") < lam.calls.index("update_function_code")
    assert "LOGIN_FLOW_SECRET_PARAM" in lam.kwargs["update_function_configuration"]["Environment"]["Variables"]


# ── ensure_secret 创建时必须**说出来**（3c-1B 第二轮复审）─────────────────────
#
# 这是"login-flow 不进写前核对清单"（ADR 0004）的**残余代价**：既然缺参不再被拒绝，
# 那么"参数被删了、脚本默默重造一把"就没有任何信号——症状只是一轮进行中的登录失败，
# 事后无从判断发生过什么。创建分支打一行（**只有参数名，没有值**）把这个信号补回来。
#
# 它同时是 legacy 参数那条更危险的同形缺口的唯一现场信号：jwt-secret 有**第二个**消费方
# （Edge 的那份是 CDK 部署时字符串替换注入的），成熟部署里被删之后 auth 造一把新的而 Edge
# 还拿着旧的 ⇒ 正是 precheck 本要防的全员登录循环。看到它被 created 就该立刻停下。


def _ensure_secret_output(present, capsys):
    from secrets_util import ensure_secret
    ssm = FakeSSM(present=present)
    ensure_secret("/site-builder/login-flow-secret", lambda: "x" * 64, ssm=ssm)
    return capsys.readouterr().out


def test_ensure_secret_announces_a_create_with_the_name_only(capsys):
    out = _ensure_secret_output(set(), capsys)
    assert "/site-builder/login-flow-secret" in out
    assert "x" * 64 not in out, "打印了密钥明文"


def test_ensure_secret_is_silent_when_the_parameter_already_exists(capsys):
    """幂等重跑是常态，不能每次都刷一行——那样"创建"这个信号就淹了。"""
    assert _ensure_secret_output({"/site-builder/login-flow-secret"}, capsys).strip() == ""


# ---- 3c-1B ticket 07：L3（清空 legacy_param）的三处后果 ---------------------------------
#
# 清空**一处**配置，auth 侧要同时收敛：env 不再有 `JWT_SECRET_PARAM`、角色 SSM 精确清单不再含
# legacy ARN、写前核对清单同步、`LEGACY_ENTRY` 变 off。任一处漏改的症状都不一样但都很难查：
# env 漏改 ⇒ 运行时按空参数名读 SSM；角色清单漏改 ⇒ 多留一条本该收掉的读权限（闸门会红，
# 但那是事后）；核对清单漏改 ⇒ 拿一个不存在的参数拒绝部署。

CFG_L3 = CFG.replace("signer = legacy", "signer = current").replace(
    "legacy_param = /site-builder/jwt-secret", "legacy_param =")


@pytest.fixture
def cfg_files_l3(tmp_path, monkeypatch):
    p = tmp_path / "config.ini"
    p.write_text(CFG_L3)
    c = configparser.ConfigParser()
    c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p)
    monkeypatch.setattr(da, "_CFG", c)
    return p


def test_l3_env_drops_the_jwt_secret_param_key_entirely(cfg_files_l3):
    """整个键**不下发**，不是下发空串。

    `_secret("JWT_SECRET")` 走 `{name}_PARAM` 约定：键在而值为空会让它抛"无来源"，
    与"入口已关闭所以谁也不该来取"这个事实对不上；键不在才是 fail-closed 的表达。
    """
    env = da.lambda_env()["Variables"]
    assert "JWT_SECRET_PARAM" not in env
    assert env["LEGACY_ENTRY"] == "off"
    assert env["SESSION_SIGNER"] == "current"
    # 其余键一个不少（L3 只关 legacy，不动别的）
    for still in ("LOGIN_FLOW_SECRET_PARAM", "SESSION_KEYS_JSON", "CLIENT_SECRET_PARAM"):
        assert still in env, still


def test_before_l3_the_jwt_secret_param_is_still_shipped(cfg_files):
    """回归：非空时与今天完全相同。"""
    env = da.lambda_env()["Variables"]
    assert env["JWT_SECRET_PARAM"] == "/site-builder/jwt-secret"
    assert env["LEGACY_ENTRY"] == "on"


def test_l3_role_ssm_list_no_longer_carries_the_legacy_arn(cfg_files_l3, monkeypatch):
    iam = Recorder()
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    da.ensure_lambda_role()
    doc = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])
    ssm_res = [r for st in doc["Statement"] if "ssm:GetParameter" in json.dumps(st.get("Action"))
               for r in (st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]])]
    assert not any(r.endswith("parameter/site-builder/jwt-secret") for r in ssm_res), ssm_res
    assert not any(r.endswith("parameter") or r.endswith(":parameter/") for r in ssm_res), \
        "空参数名拼出了一个畸形 ARN"
    # 该留的还在
    assert any(r.endswith("/session-keys/site-hs-v1") for r in ssm_res)
    assert any(r.endswith("/login-flow-secret") for r in ssm_res)


def test_l3_precheck_list_is_unchanged_because_legacy_was_never_in_it(cfg_files_l3):
    """legacy 本来就被排除在写前核对之外（本脚本自己 ensure 它）——L3 不该让它冒出来。"""
    assert set(da.required_parameters()) == {"/site-builder/session-keys/site-hs-v1",
                                             "/site-builder/session-keys/console-hs-v1",
                                             da.CLIENT_SECRET_PARAM}
    assert "" not in da.required_parameters(), "空参数名混进了核对清单"


def test_l3_main_does_not_try_to_create_a_parameter_with_an_empty_name(cfg_files_l3, monkeypatch):
    """`ensure_secret("")` 会拿空名字去 put_parameter，AWS 侧报一个读不懂的 ValidationException。"""
    created = []
    monkeypatch.setattr(da, "ensure_secret", lambda name, gen: created.append(name))
    ssm = FakeSSM(present=set(da.required_parameters()))
    _run_main(monkeypatch, ssm)
    assert "" not in created, created
    assert "/site-builder/jwt-secret" not in created, "L3 之后不该再碰那把密钥"
    assert "/site-builder/login-flow-secret" in created, "login-flow 的缺省补建不该被一起关掉"


# ---- M07：Function URL 的 resource policy 按期望集合等值收敛（auth 那条此前既不收敛也无闸门）----------
#
# 三条不变量：① 实现是共享的那一份（不在本脚本里另写）；② main() 在 precheck 之后、任何写之前先校验
# edge_role_arn（空 / 通配即拒绝部署）；③ main() 恰好调用一次 converge，本脚本里不再有任何直接的
# add_permission / remove_permission（pre-token 触发器那处除外——那是 Cognito 调 Lambda 的授权，不是 M07 的面）。

import importlib.util as _ilu

import function_url_policy as fup          # deploy_auth import 时已把 deployer/functions 铺进 sys.path


def _fake_policy_module():
    """按路径加载 deployer/tests 的有状态替身，不往 sys.path 塞那个目录（会与本包的 conftest 撞名）。"""
    path = Path(da.__file__).resolve().parents[1] / "deployer" / "tests" / "fake_lambda_policy.py"
    spec = _ilu.spec_from_file_location("fake_lambda_policy", path)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_deploy_auth_binds_the_shared_function_url_policy_implementation():
    assert da.converge_function_url_policy is fup.converge
    assert da.function_url_statements is fup.expected_statements


def test_main_converges_the_function_url_policy_once_with_the_configured_edge_role(cfg_files, monkeypatch):
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, _, _ = _run_main(monkeypatch, ssm)
    assert _CONVERGE_CALLS == [(lam, da.FN, "arn:aws:iam::111111111111:role/site-edge-role")]


@pytest.mark.parametrize("bad", ["", "*", "arn:aws:iam::111111111111:role/*", "site-edge-role"])
def test_main_aborts_before_any_write_when_edge_role_arn_is_unusable(tmp_path, monkeypatch, bad):
    """缺 / 通配 / 非 ARN 一律在 precheck 之后立刻 SystemExit：Lambda、角色、resource policy、路由表零写入。"""
    p = tmp_path / "config.ini"
    p.write_text(CFG.replace("edge_role_arn = arn:aws:iam::111111111111:role/site-edge-role",
                             f"edge_role_arn = {bad}"))
    c = configparser.ConfigParser()
    c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p)
    monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present=set(da.required_parameters()))
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    with pytest.raises(SystemExit, match="edge_role_arn"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []
    assert not [c for c in ssm.calls if c[0] == "put_parameter"]


def test_main_validates_edge_role_after_precheck_and_before_the_first_write():
    """结构守卫：main() 里 edge_role_arn() 排在 precheck() 之后、第一个写助手之前。"""
    tree = ast.parse(Path(da.__file__).read_text())
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    order = sorted((node.lineno, node.func.id) for node in ast.walk(main_fn)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    names = [n for _, n in order]
    first_write = min(names.index(n) for n in ("ensure_secret", "ensure_lambda_role", "build_zip", "deploy_function")
                      if n in names)
    assert names.index("precheck") < names.index("edge_role_arn") < first_write, names


def test_no_direct_permission_calls_outside_the_pre_token_trigger():
    """add_permission / remove_permission 只许出现在 ensure_pre_token_trigger 里：Function URL 那两条全走 converge。
    "同名 StatementId 已存在就 pass"回来的唯一途径就是有人在这里又写一遍。"""
    tree = ast.parse(Path(da.__file__).read_text())
    owners = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("add_permission", "remove_permission"):
                owners.setdefault(node.func.attr, set()).add(fn.name)
    assert owners.get("add_permission", set()) <= {"ensure_pre_token_trigger"}, owners
    # 老 Sid（public-url / public-url-invoke）的点名删除由 converge 的野 Sid 清理覆盖：本脚本零 remove_permission。
    # 按 AST 判，不 grep 文本——注释里提到那两个名字是合法的（本仓库栽过"断言的字样只活在注释里"的反面）。
    assert owners.get("remove_permission", set()) == set(), owners


class _PolicyRecorder(Recorder):
    """Recorder + 真的 resource policy 状态：get_policy / add_permission / remove_permission 交给有状态替身。"""
    def __init__(self, fake):
        super().__init__()
        self.fake = fake
        self.exceptions = type("E", (), {"ResourceNotFoundException": fake.exceptions.ResourceNotFoundException,
                                          "ResourceConflictException": fake.exceptions.ResourceConflictException,
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        if name in ("get_policy", "add_permission", "remove_permission"):
            return getattr(self.fake, name)
        return super().__getattr__(name)


def test_main_end_to_end_replaces_a_deleted_role_principal_and_clears_legacy_public_statements(cfg_files, monkeypatch):
    """端到端（真 converge + 有状态替身）：edge role 重建后的 AROA principal 被换成配置里的 ARN，老版本留下的
    public-url 语句被删，最终 policy 与期望集合逐字节一致。这正是 M07 "重部永不重建 Principal" 的反例。"""
    flp = _fake_policy_module()
    edge = "arn:aws:iam::111111111111:role/site-edge-role"
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    fake = flp.FakeLambdaPolicy([
        flp.rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
        flp.rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True),
        flp.rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
    monkeypatch.setattr(fup, "_sleep", lambda s: None)
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline", lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    da.main()
    assert fup.drift(json.loads(fake.get_policy(FunctionName=da.FN)["Policy"]), edge).ok
    assert {s["Sid"] for s in fake.statements} == set(fup.EXPECTED_SIDS)
    assert {s["Principal"]["AWS"] for s in fake.statements} == {edge}


def test_rerunning_main_on_a_converged_policy_writes_nothing(cfg_files, monkeypatch):
    """幂等重部的正对照：policy 已一致 ⇒ 一次 get_policy、零 add/remove。"""
    flp = _fake_policy_module()
    fake = flp.FakeLambdaPolicy(flp.good_pair("arn:aws:iam::111111111111:role/site-edge-role"))
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline", lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    da.main()
    assert fake.writes() == []
    assert [c for c in fake.calls if c[0] == "get_policy"] == [("get_policy", None, None)]
