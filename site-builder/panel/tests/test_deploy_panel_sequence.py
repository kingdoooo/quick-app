"""deploy_panel 的部署顺序合同（3c-1B ticket 02；spec §11.8.3、§11.8.12）——与 auth 那份同一对纪律。"""
import ast
import re
import sys
from pathlib import Path

import pytest

import deploy_panel as dp


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
        return {"Parameter": {"Value": "v"}}


class Recorder:
    def __init__(self, missing_function=False):
        self.calls = []
        self.missing_function = missing_function
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound,
                                          "ResourceConflictException": type("C", (Exception,), {}),
                                          "InvalidParameterValueException": type("I", (Exception,), {}),
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        def call(*a, **kw):
            self.calls.append(name)
            if name == "get_function" and self.missing_function:
                raise _NotFound()
            if name == "get_waiter":
                return type("W", (), {"wait": lambda s, **k: self.calls.append("wait")})()
            return {"FunctionUrl": "https://x.lambda-url.example/", "Role": {"Arn": "arn:x", "RoleId": "AROA-TEST-ROLE-ID"}}
        return call


def _live_keys():
    """线上 `config.ini` 的 `[SessionKeys]`，按加载器解析。

    别把配置的**当前值**写死：演练每一步都在改它（⑤ 清空 legacy、⑦ 换 console current 到 v2、
    ⑩ 删 v1 两节），写死会让这些用例在部署之后成片假红，而它们要守的性质一条都没变。
    """
    sys.path.insert(0, str(Path(dp.__file__).parents[1] / "auth"))
    from session_keys import load_session_keys
    return load_session_keys(Path(dp.__file__).parents[1] / "config.ini")


def test_required_parameters_are_legacy_plus_console_family_only():
    keys = _live_keys()
    names = dp.required_parameters()
    # legacy **iff 配置里非空**：L3 之后它不该在清单里（那时它已被清空）
    assert ("/site-builder/jwt-secret" in names) == bool(keys.legacy_param), \
        f"legacy 该出现 iff legacy_param 非空；legacy_param={keys.legacy_param!r} names={names}"
    console_current = keys.families["console"]["current"].ssm_param
    assert any(n.endswith(console_current) for n in names), (console_current, names)
    assert not any("/session-keys/site-" in n for n in names), "panel 不得读 site family 的密钥"


def test_ensure_function_updates_configuration_before_code(monkeypatch):
    lam = Recorder()
    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: lam)
    # M07：Function URL 授权走共享的 converge（它要读真 policy，Recorder 给不出来）；本用例只看更新顺序，
    # converge 的行为在 deployer/tests/test_function_url_policy.py，接线在 test_deploy_panel_contract.py。
    monkeypatch.setattr(dp, "converge_function_url_policy",
                        lambda *a, **k: type("D", (), {"summary": lambda self: "一致"})())
    dp.ensure_function("arn:x", b"zip", "AROA-TEST-ROLE-ID")
    head = lam.calls[:7]
    assert head == ["get_function", "update_function_configuration", "get_waiter", "wait",
                    "update_function_code", "get_waiter", "wait"], lam.calls


def test_main_aborts_before_any_write_when_a_parameter_is_missing(monkeypatch):
    # 缺的那个是 console family 的 current（名字从加载器取：⑦ 之后它是 v2）
    console_current = _live_keys().families["console"]["current"].ssm_param
    present = set(dp.required_parameters()) - {console_current}
    ssm = FakeSSM(present=present)
    iam, lam = Recorder(), Recorder()
    made = []

    def client(service, *a, **k):
        made.append(service)
        return {"ssm": ssm, "iam": iam, "lambda": lam}[service]

    monkeypatch.setattr(dp.boto3, "client", client)
    monkeypatch.setattr(dp.boto3, "resource", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不该碰路由表")))
    monkeypatch.setattr(dp, "_build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    monkeypatch.setattr(sys, "argv", ["deploy_panel.py", "--skip-frontend"])
    with pytest.raises(SystemExit, match=re.escape(console_current)):
        dp.main()
    assert iam.calls == [] and lam.calls == []


def test_main_source_calls_precheck_before_every_write_helper():
    tree = ast.parse(Path(dp.__file__).read_text())
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    order = sorted((node.lineno, node.func.id) for node in ast.walk(main_fn)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    names = [n for _, n in order]
    assert "precheck" in names
    first_write = min(names.index(n) for n in ("ensure_role", "ensure_function", "_build_zip", "upload_frontend",
                                              "register_route") if n in names)
    assert names.index("precheck") < first_write, names
