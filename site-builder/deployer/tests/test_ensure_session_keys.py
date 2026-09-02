"""`scripts/ensure_session_keys.py`：按 [SessionKeys] 的 HS 行幂等创建 SecureString（plan 3c-1A Task 1）。

先于实现写下并跑红。路径来自 config，不来自命令行：接受命令行路径等于允许随手建第三把。
"""
import sys
import textwrap
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "auth"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import ensure_session_keys as esk  # noqa: E402

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1

    [SessionKeys]
    site_current = site-hs-v1
    site_previous =
    console_current = console-hs-v1
    console_previous =
    legacy_param = /site-builder/jwt-secret
    login_flow_secret_param = /site-builder/login-flow-secret

    [SessionKey:site-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/site-hs-v1

    [SessionKey:console-hs-v1]
    alg = HS256
    ssm_param = /site-builder/session-keys/console-hs-v1
""")
RS_PREVIOUS = CFG.replace("site_previous =", "site_previous = site-rs-v1") + textwrap.dedent("""
    [SessionKey:site-rs-v1]
    alg = RS256
    key_arn = arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-555555555555
    spki_sha256 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
""")
PARAMS = ("/site-builder/session-keys/site-hs-v1", "/site-builder/session-keys/console-hs-v1")
# 3c-1B：login-flow secret 也由本脚本幂等创建（spec §11.8.6：第①步一次建齐 config 声明的所有密钥）。
# 它不是 kid，所以在结果字典里用闸门的那个 LABEL（`--new-key login-flow`），永不与 KID_RE 撞。
LOGIN_FLOW_PARAM = "/site-builder/login-flow-secret"
LOGIN_FLOW_LABEL = "login-flow"


def _cfg(tmp_path, text=CFG):
    p = tmp_path / "config.ini"
    p.write_text(text)
    return p


def _value(name):
    return boto3.client("ssm", region_name="us-east-1").get_parameter(
        Name=name, WithDecryption=True)["Parameter"]


def test_creates_two_distinct_secure_strings_and_prints_no_values(aws, tmp_path, capsys):
    result = esk.ensure_session_keys(_cfg(tmp_path))
    assert result == {"site-hs-v1": "created", "console-hs-v1": "created",
                      LOGIN_FLOW_LABEL: "created"}
    vals = [_value(p) for p in PARAMS + (LOGIN_FLOW_PARAM,)]
    assert all(v["Type"] == "SecureString" for v in vals)
    assert len({v["Value"] for v in vals}) == len(vals), "三把密钥必须各自独立"
    assert all(len(v["Value"]) == 64 for v in vals)
    out = capsys.readouterr().out + capsys.readouterr().err
    for v in vals:
        assert v["Value"] not in out


def test_second_run_is_idempotent_and_does_not_overwrite(aws, tmp_path):
    """覆盖 = 换密钥 = 全员会话失效（login-flow 那把则是所有进行中的登录失败）。"""
    cfg = _cfg(tmp_path)
    esk.ensure_session_keys(cfg)
    every = PARAMS + (LOGIN_FLOW_PARAM,)
    before = [_value(p)["Value"] for p in every]
    assert esk.ensure_session_keys(cfg) == {"site-hs-v1": "exists", "console-hs-v1": "exists",
                                            LOGIN_FLOW_LABEL: "exists"}
    assert [_value(p)["Value"] for p in every] == before


def test_legacy_param_is_not_its_business(aws, tmp_path):
    esk.ensure_session_keys(_cfg(tmp_path))
    ssm = boto3.client("ssm", region_name="us-east-1")
    with pytest.raises(ssm.exceptions.ParameterNotFound):
        ssm.get_parameter(Name="/site-builder/jwt-secret")


def test_rs_rows_are_skipped_only_hs_rows_are_ssm_secrets(aws, tmp_path):
    result = esk.ensure_session_keys(_cfg(tmp_path, RS_PREVIOUS))
    assert set(result) == {"site-hs-v1", "console-hs-v1", LOGIN_FLOW_LABEL}


def test_cli_takes_no_path_argument():
    with pytest.raises(SystemExit):
        esk.parse_args(["/tmp/somewhere/config.ini"])
    assert esk.parse_args([]) is not None


def test_misconfiguration_aborts_before_any_write(aws, tmp_path):
    from session_keys import SessionKeysError
    bad = CFG.replace("site_current = site-hs-v1", "site_current = console-hs-v1")
    with pytest.raises(SessionKeysError):
        esk.ensure_session_keys(_cfg(tmp_path, bad))
    ssm = boto3.client("ssm", region_name="us-east-1")
    assert ssm.describe_parameters()["Parameters"] == []


# ---- 3c-1B：login-flow secret（spec §11.3 / §11.8.6）----

def test_login_flow_secret_is_created_at_the_path_config_declares(aws, tmp_path):
    """路径只来自 config，与两把 family 密钥同一条纪律；它**不在** session-keys 前缀下。"""
    esk.ensure_session_keys(_cfg(tmp_path))
    v = _value(LOGIN_FLOW_PARAM)
    assert v["Type"] == "SecureString" and len(v["Value"]) == 64
    assert not LOGIN_FLOW_PARAM.startswith("/site-builder/session-keys/"), \
        "它不是 kid，路径不该长得像一把 family 密钥"


def test_login_flow_secret_value_differs_from_every_session_key(aws, tmp_path):
    """同值等于没迁移：登录流程与会话共用一把密钥正是 1B 要消灭的形态。"""
    esk.ensure_session_keys(_cfg(tmp_path))
    session_values = {_value(p)["Value"] for p in PARAMS}
    assert _value(LOGIN_FLOW_PARAM)["Value"] not in session_values


def test_login_flow_secret_is_not_printed(aws, tmp_path, capsys):
    esk.ensure_session_keys(_cfg(tmp_path))
    esk.main([])
    out = capsys.readouterr()
    assert LOGIN_FLOW_LABEL in out.out, "结果里应报告它的状态"
    assert _value(LOGIN_FLOW_PARAM)["Value"] not in out.out + out.err
