"""deploy_auth 的部署顺序合同（3c-1B ticket 02；spec §11.8.3、§11.8.12）。

两条：① **第一次写之前**核对本组件要读的每个外部 SSM 参数存在（只读、不解密、不打印值），缺任一个即拒绝
部署且函数/角色/resource policy/路由表零写入；② 更新 Lambda 时**先** update_function_configuration
**再** update_function_code——1B 的两处 env 变化都是新增变量，旧代码忽略新变量无害，新代码缺新变量会 500。
用假 client 记录调用序列，先于实现写下并跑红。
"""
import ast
import configparser
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

    [SessionKeys]
    site_current = site-hs-v1
    site_previous =
    console_current = console-hs-v1
    console_previous =
    legacy_param = /site-builder/jwt-secret

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
        self.missing_function = missing_function
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound,
                                          "ResourceConflictException": type("C", (Exception,), {}),
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        def call(*a, **kw):
            self.calls.append(name)
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
