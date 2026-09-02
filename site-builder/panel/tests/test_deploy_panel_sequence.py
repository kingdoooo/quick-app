"""deploy_panel 的部署顺序合同（3c-1B ticket 02；spec §11.8.3、§11.8.12）——与 auth 那份同一对纪律。"""
import ast
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


def test_required_parameters_are_legacy_plus_console_family_only():
    names = dp.required_parameters()
    assert "/site-builder/jwt-secret" in names
    assert any(n.endswith("/console-hs-v1") for n in names)
    assert not any("/session-keys/site-" in n for n in names), "panel 不得读 site family 的密钥"


def test_ensure_function_updates_configuration_before_code(monkeypatch):
    lam = Recorder()
    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: lam)
    dp.ensure_function("arn:x", b"zip", "AROA-TEST-ROLE-ID")
    head = lam.calls[:7]
    assert head == ["get_function", "update_function_configuration", "get_waiter", "wait",
                    "update_function_code", "get_waiter", "wait"], lam.calls


def test_main_aborts_before_any_write_when_a_parameter_is_missing(monkeypatch):
    ssm = FakeSSM(present={"/site-builder/jwt-secret"})       # console-hs-v1 缺
    iam, lam = Recorder(), Recorder()
    made = []

    def client(service, *a, **k):
        made.append(service)
        return {"ssm": ssm, "iam": iam, "lambda": lam}[service]

    monkeypatch.setattr(dp.boto3, "client", client)
    monkeypatch.setattr(dp.boto3, "resource", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不该碰路由表")))
    monkeypatch.setattr(dp, "_build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    monkeypatch.setattr(sys, "argv", ["deploy_panel.py", "--skip-frontend"])
    with pytest.raises(SystemExit, match="console-hs-v1"):
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
