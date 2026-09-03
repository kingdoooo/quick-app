"""stack.py 的静态守卫（stack.py import aws_cdk，普通解释器里没有，所以按源码文本断言）。"""
from pathlib import Path

SRC = (Path(__file__).parents[1] / "stack.py").read_text()


def test_stack_uses_shared_session_keys_helpers_not_inline_copies():
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert "legacy_entry(" in body and '"on" if keys.legacy_param else "off"' not in body
    assert "env_json" not in body, "局部名 env_json 与 session_keys.env_json 撞名"


def test_stack_ssm_failure_injects_the_synth_placeholder_not_an_empty_allowlist():
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert 'text = "{}"' not in body, "空 allowlist 看起来合法，synth 与部署前测试都过；要注入带 SYNTH-ONLY 标记的占位"
    assert "SYNTH_PLACEHOLDER_ALLOWLIST_JSON" in body


# ---- 3c-1B ticket 07：legacy 注入的路径来自配置，为空即 L3 -------------------------------
#
# `stack.py` import aws_cdk（普通解释器里没有），所以**行为**用把两个待测函数从源码里切出来
# 单独 exec 的方式验；纯文本断言只用来钉"不许回到硬编码"。

import sys as _sys  # noqa: E402
import textwrap  # noqa: E402
import types  # noqa: E402

import pytest  # noqa: E402

L3_LEGACY = ""
LIVE_LEGACY = "/site-builder/jwt-secret"


def test_legacy_parameter_path_is_not_hardcoded_anymore():
    """硬编码与 `[SessionKeys] legacy_param` 分叉时，闸门盯着一把密钥而 Edge 注入的是另一把，
    **两边都不报错**。所以路径只许来自配置。"""
    body = SRC[SRC.index("def load_jwt_secret"):SRC.index("def load_site_allowlist")]
    assert 'Name="/site-builder/jwt-secret"' not in body, "legacy 参数路径仍硬编码"
    assert "Name=legacy_param" in body, "没有按配置里的路径取"
    assert "def load_jwt_secret(legacy_param: str)" in body, (
        "路径必须是**必填**入参：给默认值或自己再读一次 config 就多了一条可能与 "
        "load_site_allowlist 不一致的取值路径")


def test_session_keys_is_parsed_once_for_both_injected_values():
    """两个注入值必须来自同一份解析——各读一次的话，中途改 config 会让 Edge 拿到
    自相矛盾的 (allowlist, legacy secret) 组合。"""
    body = SRC[SRC.index("class WebRouterStack"):]
    assert "session_keys = _session_keys()" in body
    assert "load_jwt_secret(session_keys.legacy_param)" in body
    assert "load_site_allowlist(session_keys)" in body


def test_session_keys_path_insert_is_unconditional():
    """`sys.path` 的插入必须是每个 `from session_keys import …` 各自调一次的无条件动作。

    早先它藏在 `_session_keys()` 里，于是"调用方传了 keys 就不走 `_session_keys()`"的那条路
    会在 import 时炸——**只因为调用顺序恰好对才没现形**（latent ImportError）。
    """
    assert "def _session_keys_on_path()" in SRC
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert "_session_keys_on_path()" in body, "load_site_allowlist 没自己放路径"
    insert_line = "sys.path.insert(0, str(root / \"site-builder\" / \"auth\"))"
    assert SRC.count(insert_line) == 1, "路径插入有第二份副本，两处会漂移"


def _load_jwt_secret_fn():
    """把 `load_jwt_secret` 从源码里切出来，在一个只有它需要的名字的命名空间里 exec。

    这样能测**行为**而不只是文本，且不需要 aws_cdk。片段刻意只含 `load_jwt_secret` 一个函数
    （结束锚点是下一个 def）：多切进来一个函数就会带进它的模块级依赖，症状是片段里
    `NameError`，读起来像被测函数坏了。
    """
    start = SRC.index("def load_jwt_secret")
    end = SRC.index("def _session_keys_on_path(")   # 片段只含 load_jwt_secret 一个函数
    mod = types.ModuleType("_stack_jwt_fragment")
    mod.__dict__.update(os=__import__("os"), sys=_sys)
    exec(compile(textwrap.dedent(SRC[start:end]), "<stack fragment>", "exec"), mod.__dict__)
    return mod


def test_empty_legacy_param_injects_an_empty_string_and_stays_silent(capsys, monkeypatch):
    """L3：注入空串，**不打 SYNTH 警告**，也不去读 SSM。"""
    mod = _load_jwt_secret_fn()
    monkeypatch.delenv("APP_JWT_SECRET", raising=False)
    assert mod.load_jwt_secret(L3_LEGACY) == ""
    err = capsys.readouterr().err
    assert "SYNTH" not in err and "WARNING" not in err, err


def test_the_empty_string_is_not_the_synth_placeholder():
    """两条产物核对断言看的是 `SYNTH-ONLY-PLACEHOLDER` 字样与未替换的 `{{…}}`——
    空替换两条都不命中，所以 L3 的部署不会被误判成"SSM 读取失败"。"""
    mod = _load_jwt_secret_fn()
    got = mod.load_jwt_secret(L3_LEGACY)
    assert "SYNTH-ONLY-PLACEHOLDER" not in got
    assert "{{" not in got and "}}" not in got


def test_explicit_override_still_wins_when_the_entry_is_open(monkeypatch):
    monkeypatch.setenv("APP_JWT_SECRET", "override-value")
    mod = _load_jwt_secret_fn()
    assert mod.load_jwt_secret(LIVE_LEGACY) == "override-value"


def test_override_is_ignored_once_the_entry_is_closed(monkeypatch):
    """L3 的判断在覆盖之前：入口已关闭时不该因为环境里留着一个 APP_JWT_SECRET 就把密钥注回去。"""
    monkeypatch.setenv("APP_JWT_SECRET", "override-value")
    mod = _load_jwt_secret_fn()
    assert mod.load_jwt_secret(L3_LEGACY) == ""


def test_real_ssm_failure_still_falls_back_to_the_synth_placeholder(capsys, monkeypatch):
    """回归：入口开着而 SSM 真读不到，仍必须落 SYNTH 占位并告警——**这条与"刻意为空"必须分得开**，
    否则 L3 每次部署都被产物核对判红，而真故障反而被当成日常。"""
    monkeypatch.delenv("APP_JWT_SECRET", raising=False)
    mod = _load_jwt_secret_fn()
    # 让 `import boto3` 在片段里失败：注入一个抛异常的假模块
    broken = types.ModuleType("boto3")

    def _boom(*a, **k):
        raise RuntimeError("no credentials in this test")

    broken.client = _boom
    monkeypatch.setitem(_sys.modules, "boto3", broken)
    got = mod.load_jwt_secret(LIVE_LEGACY)
    assert got == "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"
    err = capsys.readouterr().err
    assert "WARNING" in err and LIVE_LEGACY in err


@pytest.mark.parametrize("legacy,expect", [(LIVE_LEGACY, "on"), (L3_LEGACY, "off")])
def test_legacy_entry_follows_the_same_single_switch(legacy, expect):
    """第三处后果的另一半：同一处配置同时决定 `{{LEGACY_ENTRY}}`。取的是共用助手，
    不是本文件的第二份判断（`test_stack_uses_shared_session_keys_helpers_not_inline_copies` 锁死）。"""
    _sys.path.insert(0, str(Path(__file__).parents[3] / "site-builder" / "auth"))
    import session_keys as sk
    keys = types.SimpleNamespace(legacy_param=legacy)
    assert sk.legacy_entry(keys) == expect
