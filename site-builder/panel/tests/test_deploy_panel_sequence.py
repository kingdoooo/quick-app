"""deploy_panel 的部署顺序合同（spec §11.6 第 1 层、§11.8.3）——与 auth 那份同一对纪律。

三条不变量：
① **第一次写之前**核对：`[SessionKeys]` 里 console family 的每个 RS kid 的 KMS 四项校验必须通过
   （3c-final 起 panel 一处 SSM 参数都不读）；不符即拒绝部署，且函数 / 角色 / 路由表零写入；
② 更新 Lambda 时**先** update_function_configuration **再** update_function_code；
③ `main()` 里 `precheck()` 排在每个写助手之前（结构守卫，按 AST 判调用顺序）。

`[SessionKeys]` 从 `rs_config` 夹具那份临时 config 读，不读真 config.ini——理由见 conftest 里
`RS_SESSION_KEYS` 上面那段。
"""
import ast
import re
import sys
from pathlib import Path

import pytest

import deploy_panel as dp
import upgrade_code_vectors as v


@pytest.fixture(autouse=True)
def _use_rs_config(rs_config):
    """本文件每条用例都按 RS 形态的临时 config 判（实现在 conftest.rs_config）。"""
    return rs_config


class _NotFound(Exception):
    pass


class Recorder:
    def __init__(self, missing_function=False, scan_pages=None):
        self.calls = []
        self.missing_function = missing_function
        # `get_paginator("scan")` 的返回：assert_no_fixture_admins 用它扫 admins 表。
        # 默认一页空——"名单干净"是绝大多数用例要的形态。
        self.scan_pages = scan_pages if scan_pages is not None else [{"Items": []}]
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
            if name == "get_paginator":
                pages = self.scan_pages
                return type("P", (), {"paginate": lambda s, **k: iter(pages)})()
            return {"FunctionUrl": "https://x.lambda-url.example/", "Role": {"Arn": "arn:x", "RoleId": "AROA-TEST-ROLE-ID"}}
        return call


def test_panel_reads_no_ssm_parameter_at_all():
    """3c-final：会话签名 key 在 KMS，login-flow 是 auth 私有的 ⇒ panel 的写前核对清单是空的。"""
    assert dp.required_parameters() == []
    src = Path(dp.__file__).read_text()
    assert "get_parameter" not in src and "precheck_parameters" not in src, \
        "panel 又开始读 SSM 参数了（会话密钥在 KMS）"


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


def test_main_aborts_before_any_write_when_a_key_is_not_the_configured_one(monkeypatch):
    """KMS 四项校验不过 ⇒ 写前 SystemExit：角色、Lambda、路由表、打包全部零动作。"""
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.CONSOLE_KID]] = v.SITE_KEY
    iam, lam = Recorder(), Recorder()

    def client(service, *a, **k):
        return {"kms": kms, "iam": iam, "lambda": lam}[service]

    monkeypatch.setattr(dp.boto3, "client", client)
    monkeypatch.setattr(dp.boto3, "resource", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不该碰路由表")))
    monkeypatch.setattr(dp, "_build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    monkeypatch.setattr(sys, "argv", ["deploy_panel.py", "--skip-frontend"])
    with pytest.raises(SystemExit, match=re.escape(v.CONSOLE_KID)):
        dp.main()
    assert iam.calls == [] and lam.calls == []


def test_main_aborts_before_any_write_when_the_admin_list_carries_a_fixture_email(monkeypatch):
    """ADR 0002：夹具域管理员 ⇒ 写前 SystemExit（precheck 已过，但仍在第一个写之前）。"""
    kms = v.FakeKms()
    iam, lam = Recorder(), Recorder()
    ddb = Recorder(scan_pages=[{"Items": [{"email": {"S": "x@e2e.invalid"}}]}])

    def client(service, *a, **k):
        return {"kms": kms, "iam": iam, "lambda": lam, "dynamodb": ddb}[service]

    monkeypatch.setattr(dp.boto3, "client", client)
    monkeypatch.setattr(dp.boto3, "resource", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不该碰路由表")))
    monkeypatch.setattr(dp, "_build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    monkeypatch.setattr(sys, "argv", ["deploy_panel.py", "--skip-frontend"])
    with pytest.raises(SystemExit, match="e2e.invalid"):
        dp.main()
    assert iam.calls == [] and lam.calls == []


def test_main_source_calls_precheck_before_every_write_helper():
    tree = ast.parse(Path(dp.__file__).read_text())
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    order = sorted((node.lineno, node.func.id) for node in ast.walk(main_fn)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    names = [n for _, n in order]
    assert "precheck" in names and "assert_no_fixture_admins" in names, names
    first_write = min(names.index(n) for n in ("ensure_role", "ensure_function", "_build_zip", "upload_frontend",
                                              "register_route") if n in names)
    assert names.index("precheck") < names.index("assert_no_fixture_admins") < first_write, names
