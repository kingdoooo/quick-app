"""deploy_auth 的部署顺序合同（3c-final ticket 07；spec §11.6 第 1 层、§11.7、§11.8.3）。

四条不变量：

① **第一次写之前**核对：本组件要读、但不由本脚本创建的外部 SSM 参数必须存在（3c-final 起只剩 client
   secret），且 `[SessionKeys]` 里每个 RS kid 的 KMS 四项校验必须通过（DescribeKey 形态 + 公钥指纹）。
   任一不符即拒绝部署，且函数 / 角色 / resource policy / 路由表零写入。
② 更新 Lambda 时**先** update_function_configuration **再** update_function_code。
③ 执行角色的 `kms:Sign` 精确到两个 family 的 key ARN，并带算法与 `MessageType` 两个条件；
   `kms:GetPublicKey` 同一批 ARN。SSM 只剩 login-flow 与 client secret 两条精确 ARN。
④ `[Verification]`（spec §11.7）开着 ⇒ `site-builder-verifier` 角色被建 / 收敛，并作为
   `extra_principals` 进 Function URL 的期望集合；关着 ⇒ 角色被删、那两条语句在下一次 converge 里
   被当野 Sid 清掉。清单为空 / 含通配 / 跨账号 ⇒ 写前 SystemExit。

用假 client 记录调用序列，先于实现写下并跑红。
"""
import ast
import configparser
import json
import textwrap
from pathlib import Path

import pytest

import deploy_auth as da
import upgrade_code_vectors as v

CFG = textwrap.dedent(f"""
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
    site_current = site-rs-v1
    site_previous =
    console_current = console-rs-v1
    console_previous =
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.SITE_KID]}
    spki_sha256 = {v.spki_hex(v.SITE_KEY)}

    [SessionKey:console-rs-v1]
    alg = RS256
    key_arn = {v.KEY_ARN[v.CONSOLE_KID]}
    spki_sha256 = {v.spki_hex(v.CONSOLE_KEY)}

    [Verification]
    fixture_issuer = false
    verifier_trusted_principals =
""")

# 夹具签发器**开着**的那份（spec §11.7）：清单是本账号的两个精确 ARN（一个 user、一个 role）。
CFG_FIXTURE = CFG.replace("fixture_issuer = false", "fixture_issuer = true").replace(
    "verifier_trusted_principals =",
    "verifier_trusted_principals = arn:aws:iam::111111111111:user/kent, arn:aws:iam::111111111111:role/ci")


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
    """任何方法调用都记下来；get_function / get_role 可按需抛 ResourceNotFound / NoSuchEntity。"""
    def __init__(self, missing_function=False, missing_role=False):
        self.calls = []
        self.kwargs = {}          # 方法名 -> 最后一次调用的 kwargs（要看策略文档内容）
        self.missing_function = missing_function
        self.missing_role = missing_role
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound,
                                          "ResourceConflictException": type("C", (Exception,), {}),
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        def call(*a, **kw):
            self.calls.append(name)
            self.kwargs[name] = kw
            if name == "get_function" and self.missing_function:
                raise _NotFound()
            if name == "get_role" and self.missing_role:
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
    # 3c-final：会话密钥在 KMS 里 ⇒ precheck 与角色清单都按 key ARN 走。替身按 vectors 的三把私钥回答。
    monkeypatch.setitem(da._CLIENTS, "kms", v.FakeKms())
    return p


def test_required_parameters_are_only_the_client_secret(cfg_files):
    """会话密钥在 KMS 里（precheck 走 KMS 四项）；login-flow 由本脚本 ensure（ADR 0004）⇒ 核对清单只剩 deploy_pool 建的 client secret。"""
    assert da.required_parameters() == [da.CLIENT_SECRET_PARAM]


def test_precheck_reads_without_decryption_and_names_the_missing_parameter(cfg_files, monkeypatch, capsys):
    ssm = FakeSSM(present=set())
    monkeypatch.setitem(da._CLIENTS, "ssm", ssm)
    with pytest.raises(SystemExit) as ei:
        da.precheck()
    msg = str(ei.value)
    assert da.CLIENT_SECRET_PARAM in msg and "deploy_pool" in msg
    assert all(not kw.get("WithDecryption") for _, kw in ssm.calls), "核对只看存在性，不解密"
    assert "value-of-" not in capsys.readouterr().out + msg


def test_precheck_checks_every_configured_key_with_kms_before_any_write(cfg_files, monkeypatch):
    kms = v.FakeKms()
    monkeypatch.setitem(da._CLIENTS, "kms", kms)
    monkeypatch.setitem(da._CLIENTS, "ssm", FakeSSM(present={da.CLIENT_SECRET_PARAM}))
    da.precheck()
    assert {c[1] for c in kms.calls if c[0] == "describe_key"} == {v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.CONSOLE_KID]}


def test_precheck_refuses_a_key_whose_fingerprint_is_not_the_configured_one(cfg_files, monkeypatch):
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    monkeypatch.setitem(da._CLIENTS, "kms", kms)
    monkeypatch.setitem(da._CLIENTS, "ssm", FakeSSM(present={da.CLIENT_SECRET_PARAM}))
    with pytest.raises(SystemExit, match="console-rs-v1"):
        da.precheck()


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
    ssm = FakeSSM(present=set())          # client secret 缺（deploy_pool 还没跑）
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, val)
    monkeypatch.setattr(da, "build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    with pytest.raises(SystemExit, match="site-client-secret"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []
    assert not [c for c in ssm.calls if c[0] == "put_parameter"], "缺参时连 ensure_secret 也不该写"


def test_main_aborts_before_any_write_when_a_key_is_not_the_configured_one(cfg_files, monkeypatch):
    """KMS 那一层与 SSM 那一层同一条纪律：指纹不符 = 部署出去会全员 500，所以在第一次写之前就拒。"""
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", kms)):
        monkeypatch.setitem(da._CLIENTS, k, val)
    monkeypatch.setattr(da, "build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    with pytest.raises(SystemExit, match="site-rs-v1"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []
    assert not [c for c in ssm.calls if c[0] == "put_parameter"]


def test_main_source_calls_precheck_before_every_write_helper():
    """结构守卫：main() 里 precheck() 的调用位置在每个写助手之前。"""
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
    first_write = min(names.index(n) for n in ("ensure_secret", "ensure_lambda_role", "ensure_verifier_role",
                                               "build_zip", "deploy_function") if n in names)
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
    """**与 spec §11.8.12 的字面清单有意不同**，裁定真源 `docs/adr/0004-*`。

    §11.8.12 把 login-flow 列进 auth 的写前核对清单，但 D5/§11.8.6 同时要求 `deploy_auth` 对它
    保留一条 `ensure_secret` 缺省补建。两者不能同时成立：precheck 在任何写之前，核对它就等于让它
    永远走不到（首次部署必然被自己拒掉）。

    保留缺省补建、不核对它，是因为 precheck 防的那个具体失败在这把密钥上**不存在**：
    核对的意义是"多个消费方必须就同一个值达成一致，所以不能由本脚本随手造一个"。
    login-flow 只有 auth 一个消费方（panel 与 Edge 永不持有），auth 自己造一把随机值完全正确。
    """
    assert LOGIN_FLOW_PARAM not in da.required_parameters()
    assert da.required_parameters() == [da.CLIENT_SECRET_PARAM]


def _run_main(monkeypatch, ssm):
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline",
                        lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    # M07：Function URL 授权走共享的 converge；这里换成记录器（Recorder 的 get_policy 返回的不是 policy），
    # 它的真实行为由 deployer/tests/test_function_url_policy.py 与下面的端到端用例覆盖。
    # 第四项是 extra_principals（spec §11.7 的 verifier 两条）：None = 组件关着。
    monkeypatch.setattr(da, "converge_function_url_policy",
                        lambda client, fn, arn, **kw: _CONVERGE_CALLS.append((client, fn, arn, kw.get("extra_principals"))) or _DriftStub())
    _CONVERGE_CALLS.clear()
    da.main()
    return lam, iam, ddb


_CONVERGE_CALLS: list = []


class _DriftStub:
    def summary(self):
        return "一致"


def test_main_creates_the_login_flow_secret_when_it_is_absent(cfg_files, monkeypatch):
    """缺省补建的**正对照**：没有这一条，那条补建就是死代码，而上一条用例正是靠它才成立。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    _run_main(monkeypatch, ssm)
    written = [kw["Name"] for name, kw in ssm.calls if name == "put_parameter"]
    assert LOGIN_FLOW_PARAM in written, "deploy_auth 没有为 login-flow 缺省补建"
    for name, kw in ssm.calls:
        if name == "put_parameter":
            assert kw.get("Type") == "SecureString"


def test_main_never_overwrites_an_existing_login_flow_secret(cfg_files, monkeypatch):
    """覆盖它 = 所有进行中的登录失败一次。幂等重跑必须什么都不写。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, LOGIN_FLOW_PARAM})
    _run_main(monkeypatch, ssm)
    assert [kw["Name"] for name, kw in ssm.calls if name == "put_parameter"] == []


def test_config_first_then_code_still_holds_with_the_new_variable(cfg_files, monkeypatch):
    """env 新增变量正是"先配置后代码"要保护的场景：旧代码忽略它无害，新代码缺它必 500。"""
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, LOGIN_FLOW_PARAM})
    lam, _, _ = _run_main(monkeypatch, ssm)
    assert lam.calls.index("update_function_configuration") < lam.calls.index("update_function_code")
    assert "LOGIN_FLOW_SECRET_PARAM" in lam.kwargs["update_function_configuration"]["Environment"]["Variables"]


# ── ensure_secret 创建时必须**说出来**（3c-1B 第二轮复审）─────────────────────
#
# 这是"login-flow 不进写前核对清单"（ADR 0004）的**残余代价**：既然缺参不再被拒绝，
# 那么"参数被删了、脚本默默重造一把"就没有任何信号——症状只是一轮进行中的登录失败，
# 事后无从判断发生过什么。创建分支打一行（**只有参数名，没有值**）把这个信号补回来。


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


# ---- 3c-final：env 与角色的 KMS 形态（spec §11.2 / §11.5 / §11.6）-------------------------
#
# HS 时代那三个键（`JWT_SECRET_PARAM` / `LEGACY_ENTRY` / `SESSION_SIGNER`）必须彻底消失：留着任何一个
# 都会让下一个人以为还能靠改配置回滚到对称签名，而 3c-final 的 handler 里根本没有它们的读取点。


def test_lambda_env_has_no_hs_keys_and_ships_the_fixture_switch(cfg_files):
    env = da.lambda_env()["Variables"]
    for gone in ("JWT_SECRET_PARAM", "LEGACY_ENTRY", "SESSION_SIGNER"):
        assert gone not in env, gone
    assert env["FIXTURE_ISSUER"] == "off"
    rows = json.loads(env["SESSION_KEYS_JSON"])
    assert set(rows) == {"site", "console"}
    assert rows["site"][0] == {"kid": "site-rs-v1", "alg": "RS256", "role": "current",
                               "key_arn": v.KEY_ARN[v.SITE_KID], "spki_sha256": v.spki_hex(v.SITE_KEY)}


def test_lambda_env_key_set_is_exactly_the_documented_one(cfg_files):
    """`verify_deployed_components` 按"线上 env 整体 == lambda_env()"比对 ⇒ 多一项少一项都会在闸门里红。"""
    assert set(da.lambda_env()["Variables"]) == {
        "LOGIN_FLOW_SECRET_PARAM", "CLIENT_SECRET_PARAM", "COGNITO_DOMAIN", "CLIENT_ID", "BASE_DOMAIN",
        "USER_POOL_ID", "REQUIRE_EMAIL_VERIFIED", "SESSION_KEYS_JSON", "FIXTURE_ISSUER"}


def test_role_grants_kms_sign_with_both_conditions_and_get_public_key_on_exact_key_arns(cfg_files, monkeypatch):
    iam = Recorder()
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    da.ensure_lambda_role()
    doc = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])
    by_sid = {s["Sid"]: s for s in doc["Statement"]}
    sign = by_sid["SignSessionTokens"]
    assert sign["Action"] == "kms:Sign"
    assert sorted(sign["Resource"]) == sorted([v.KEY_ARN[v.SITE_KID], v.KEY_ARN[v.CONSOLE_KID]])
    assert sign["Condition"] == {"StringEquals": {"kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
                                                  "kms:MessageType": "RAW"}}
    pub = by_sid["ReadSessionPublicKeys"]
    assert pub["Action"] == "kms:GetPublicKey" and sorted(pub["Resource"]) == sorted(sign["Resource"])
    ssm_res = by_sid["ReadPlatformSecrets"]["Resource"]
    assert ssm_res == [f"arn:aws:ssm:us-east-1:111111111111:parameter{LOGIN_FLOW_PARAM}",
                       f"arn:aws:ssm:us-east-1:111111111111:parameter{da.CLIENT_SECRET_PARAM}"]
    assert not any("*" in r for r in sign["Resource"] + pub["Resource"] + ssm_res)


# ---- spec §11.7：`[Verification]` 与 `site-builder-verifier` -------------------------------
#
# 组件的两个状态都要收敛：开着 ⇒ 角色存在且信任策略恰好是清单里的 ARN、权限只有对 auth 函数的两条
# invoke、Function URL 的期望集合多那两条；关着 ⇒ 角色被删、期望集合回到只有 edge 两条（残留的
# verifier 语句因此在下一次 converge 里被当野 Sid 删掉）。清单坏掉时在任何写之前 SystemExit。


def test_verification_off_means_no_role_no_statements_and_switch_off(cfg_files, monkeypatch):
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, _ = _run_main(monkeypatch, ssm)
    assert _CONVERGE_CALLS == [(lam, da.FN, "arn:aws:iam::111111111111:role/site-edge-role", None)]
    assert "create_role" not in iam.calls or all(kw.get("RoleName") != da.VERIFIER_ROLE_NAME
                                                 for kw in [iam.kwargs.get("create_role", {})])


def test_verification_on_creates_the_verifier_role_and_passes_it_to_converge(tmp_path, monkeypatch):
    p = tmp_path / "config.ini"; p.write_text(CFG_FIXTURE)
    c = configparser.ConfigParser(); c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p); monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, _ = _run_main(monkeypatch, ssm)
    verifier_arn = f"arn:aws:iam::111111111111:role/{da.VERIFIER_ROLE_NAME}"
    assert _CONVERGE_CALLS[-1][3] == {"verifier": verifier_arn}
    trust = json.loads(iam.kwargs["update_assume_role_policy"]["PolicyDocument"]) if "update_assume_role_policy" in iam.kwargs \
        else json.loads(iam.kwargs["create_role"]["AssumeRolePolicyDocument"])
    assert sorted(trust["Statement"][0]["Principal"]["AWS"]) == ["arn:aws:iam::111111111111:role/ci",
                                                                  "arn:aws:iam::111111111111:user/kent"]
    pol = json.loads(iam.kwargs["put_role_policy"]["PolicyDocument"])       # 最后一次 put_role_policy 是 verifier 的
    acts = {s["Action"] for s in pol["Statement"]}
    assert acts == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}
    assert all(s["Resource"] == f"arn:aws:lambda:us-east-1:111111111111:function:{da.FN}" for s in pol["Statement"])
    assert "3600" in json.dumps(iam.kwargs.get("update_role", iam.kwargs.get("create_role", {})))
    assert da.lambda_env()["Variables"]["FIXTURE_ISSUER"] == "on"


@pytest.mark.parametrize("bad", ["", "arn:aws:iam::111111111111:role/*", "*", "kent",
                                 "arn:aws:iam::222222222222:user/kent"])
def test_verification_on_with_a_bad_principal_list_aborts_before_any_write(tmp_path, monkeypatch, bad):
    p = tmp_path / "config.ini"
    p.write_text(CFG.replace("fixture_issuer = false", "fixture_issuer = true")
                 .replace("verifier_trusted_principals =", f"verifier_trusted_principals = {bad}"))
    c = configparser.ConfigParser(); c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p); monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
    with pytest.raises(SystemExit, match="verifier_trusted_principals"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []


def test_verification_turned_off_deletes_an_existing_verifier_role(cfg_files, monkeypatch):
    iam = Recorder()          # get_role 命中 ⇒ 角色"存在"
    monkeypatch.setitem(da._CLIENTS, "iam", iam)
    assert da.ensure_verifier_role(iam, da.Verification(False, ()), account="111111111111", region="us-east-1") is None
    assert "delete_role_policy" in iam.calls and "delete_role" in iam.calls
    assert iam.calls.index("delete_role_policy") < iam.calls.index("delete_role")


def test_verification_off_still_deletes_the_role_when_the_inline_policy_is_already_gone(cfg_files):
    """半失败状态（create_role 成功、put_role_policy 没写成）也要收敛到"角色消失"。

    对不存在的 inline policy 抛 NoSuchEntity 会让"关掉夹具组件"把**整个 auth 部署**堵死——本函数排在
    deploy_function 之前，而这里想要的终态本来就是角色不在。
    """
    class _NoPolicy(Recorder):
        def delete_role_policy(self, **kw):
            self.calls.append("delete_role_policy")
            raise self.exceptions.NoSuchEntityException()

    iam = _NoPolicy()
    assert da.ensure_verifier_role(iam, da.Verification(False, ()), account="111111111111", region="us-east-1") is None
    assert iam.calls == ["get_role", "delete_role_policy", "delete_role"], iam.calls


def test_verification_off_with_no_existing_role_writes_nothing(cfg_files):
    """正对照：角色本来就不存在时不许去删（真 IAM 会 NoSuchEntity 报错，把幂等重跑变成失败）。"""
    iam = Recorder(missing_role=True)
    assert da.ensure_verifier_role(iam, da.Verification(False, ()), account="111111111111", region="us-east-1") is None
    assert iam.calls == ["get_role"], iam.calls


# ---- M07：Function URL 的 resource policy 按期望集合等值收敛 ----------
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
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, LOGIN_FLOW_PARAM})
    lam, _, _ = _run_main(monkeypatch, ssm)
    assert _CONVERGE_CALLS == [(lam, da.FN, "arn:aws:iam::111111111111:role/site-edge-role", None)]


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
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM})
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
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
    first_write = min(names.index(n) for n in ("ensure_secret", "ensure_lambda_role", "ensure_verifier_role",
                                               "build_zip", "deploy_function") if n in names)
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
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, LOGIN_FLOW_PARAM})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
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
    ssm = FakeSSM(present={da.CLIENT_SECRET_PARAM, LOGIN_FLOW_PARAM})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, val in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb), ("kms", v.FakeKms())):
        monkeypatch.setitem(da._CLIENTS, k, val)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline", lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    da.main()
    assert fake.writes() == []
    assert [c for c in fake.calls if c[0] == "get_policy"] == [("get_policy", None, None)]
