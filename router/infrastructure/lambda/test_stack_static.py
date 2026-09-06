"""stack.py 的静态守卫（stack.py import aws_cdk，普通解释器里没有，所以按源码文本断言）。"""
import re
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
    if "def _synth_offline" in SRC:   # ticket 19：两个注入函数共用的离线开关助手，一并切进来
        hs = SRC.index("def _synth_offline"); he = SRC.index("def ", hs + 1)
        exec(compile(textwrap.dedent(SRC[hs:he]), "<stack helpers>", "exec"), mod.__dict__)
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
    """回归：入口开着而 SSM 真读不到，**显式离线模式下**仍落 SYNTH 占位并告警——**这条与"刻意为空"必须分得开**，
    否则 L3 每次部署都被产物核对判红，而真故障反而被当成日常。（不带 APP_SYNTH_OFFLINE 时的行为见 ticket 19 那组：抛。）"""
    monkeypatch.delenv("APP_JWT_SECRET", raising=False)
    monkeypatch.setenv("APP_SYNTH_OFFLINE", "1")
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


# ---- 3c-1B ticket 19：synth fail-closed（merged review M12）--------------------------------------
#
# 此前两个注入函数整段 `except Exception` ⇒ 非 HS256 的配置错、ParameterNotFound、AccessDenied 都退化成
# SYNTH 占位符 + 一行 stderr WARNING，而 `cdk deploy` 照样 exit 0、把一个 kid 永不匹配的 allowlist 全球
# 复制出去（全员登录循环，直到有人读 cdk 日志或跑 verify_deployed_edge.sh）。现在：**默认任何失败都让
# synth 失败**；占位符路径只在显式 `APP_SYNTH_OFFLINE=1` 下保留（离线 synth / 无凭据的 CI）；配置错误
# 在任何模式下都抛。

OFFLINE_FLAG = "APP_SYNTH_OFFLINE"


def _load_site_allowlist_fn():
    """把 `load_site_allowlist` 切出来 exec；`_session_keys_on_path` 用一个只放路径的替身。"""
    start = SRC.index("def load_site_allowlist")
    end = SRC.index("class WebRouterStack")
    mod = types.ModuleType("_stack_allowlist_fragment")
    root = Path(__file__).parents[3]

    def _on_path():
        _sys.path.insert(0, str(root / "site-builder" / "auth"))
        return root

    mod.__dict__.update(os=__import__("os"), sys=_sys, json=__import__("json"), _session_keys_on_path=_on_path)
    # 片段里若引用了 _synth_offline() 这类同文件助手，也一并切进来（以 def 开头、在 load_jwt_secret 之前）
    helpers_start = SRC.index("def _synth_offline") if "def _synth_offline" in SRC else None
    if helpers_start is not None:
        helpers_end = SRC.index("def ", helpers_start + 1)
        exec(compile(textwrap.dedent(SRC[helpers_start:helpers_end]), "<stack helpers>", "exec"), mod.__dict__)
    exec(compile(textwrap.dedent(SRC[start:end]), "<stack fragment>", "exec"), mod.__dict__)
    return mod


def _ref(kid, alg="HS256", role="current"):
    return types.SimpleNamespace(kid=kid, alg=alg, role=role, ssm_param=f"/site-builder/session-keys/{kid}")


def _keys(site=(), console=(), legacy_param=""):
    fams = {"site": list(site), "console": list(console)}
    return types.SimpleNamespace(legacy_param=legacy_param, allowlist=lambda fam: fams[fam])


def _fake_boto3(monkeypatch, values: dict | None = None, error: Exception | None = None):
    """注入一个假的 boto3：`client("ssm").get_parameter(Name=…)` 按 values 取值，或统一抛 error。"""
    fake = types.ModuleType("boto3")

    class _SSM:
        def get_parameter(self, Name, WithDecryption):
            if error is not None:
                raise error
            if Name not in (values or {}):
                raise RuntimeError(f"ParameterNotFound: {Name}")
            return {"Parameter": {"Value": values[Name]}}

    fake.client = lambda service, region_name: _SSM()
    monkeypatch.setitem(_sys.modules, "boto3", fake)
    return fake


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("APP_SITE_ALLOWLIST_JSON", "APP_JWT_SECRET", OFFLINE_FLAG):
        monkeypatch.delenv(k, raising=False)


def test_allowlist_takes_only_the_site_family_and_reads_each_secret_from_ssm(clean_env, monkeypatch):
    """spec §4.1：console 的 key 永不进 Edge；每行的 secret 按它自己的 ssm_param 取。"""
    _fake_boto3(monkeypatch, {"/site-builder/session-keys/site-hs-v1": "s1", "/site-builder/session-keys/site-hs-v2": "s2",
                              "/site-builder/session-keys/console-hs-v1": "c1"})
    mod = _load_site_allowlist_fn()
    text, entry = mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1"), _ref("site-hs-v2", role="previous")],
                                                console=[_ref("console-hs-v1")], legacy_param=""))
    got = __import__("json").loads(text)
    assert got == {"site-hs-v1": {"alg": "HS256", "secret": "s1", "role": "current"},
                   "site-hs-v2": {"alg": "HS256", "secret": "s2", "role": "previous"}}
    assert "c1" not in text and entry == "off"


@pytest.mark.parametrize("offline", [False, True])
def test_non_hs256_row_is_a_config_error_in_every_mode(clean_env, monkeypatch, offline):
    """配置错不是"SSM 读不到"：无论在线/离线都必须抛，不许被吞成占位符。"""
    if offline:
        monkeypatch.setenv(OFFLINE_FLAG, "1")
    _fake_boto3(monkeypatch, {"/site-builder/session-keys/site-rs-v1": "x"})
    mod = _load_site_allowlist_fn()
    with pytest.raises(ValueError, match="HS256"):
        mod.load_site_allowlist(_keys(site=[_ref("site-rs-v1", alg="RS256")]))


def test_ssm_failure_fails_synth_by_default_instead_of_injecting_the_placeholder(clean_env, monkeypatch, capsys):
    """M12：`cdk deploy` 路径上 ParameterNotFound / AccessDenied 必须让 synth 失败，而不是 exit 0 + 占位符。"""
    _fake_boto3(monkeypatch, error=RuntimeError("AccessDeniedException: ssm:GetParameter"))
    mod = _load_site_allowlist_fn()
    with pytest.raises(Exception) as ei:
        mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1")]))
    msg = str(ei.value)
    assert "AccessDeniedException" in msg and OFFLINE_FLAG in msg, msg
    assert "SYNTH-ONLY-PLACEHOLDER" not in capsys.readouterr().err


def test_ssm_failure_falls_back_to_the_placeholder_only_when_offline_is_explicit(clean_env, monkeypatch, capsys):
    """离线 synth 仍可用，但必须显式声明；占位符带标记且 kid 永不匹配（verify_deployed_edge.sh 会抓）。"""
    monkeypatch.setenv(OFFLINE_FLAG, "1")
    _fake_boto3(monkeypatch, error=RuntimeError("no credentials"))
    mod = _load_site_allowlist_fn()
    text, _ = mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1")]))
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in text
    err = capsys.readouterr().err
    assert "WARNING" in err and "DO NOT deploy" in err


def test_explicit_override_wins_and_is_validated_as_json(clean_env, monkeypatch):
    monkeypatch.setenv("APP_SITE_ALLOWLIST_JSON", '{"site-hs-v1": {"alg": "HS256", "secret": "o", "role": "current"}}')
    _fake_boto3(monkeypatch, error=RuntimeError("must not be called"))
    mod = _load_site_allowlist_fn()
    text, _ = mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1")]))
    assert '"secret": "o"' in text
    monkeypatch.setenv("APP_SITE_ALLOWLIST_JSON", "{not json")
    with pytest.raises(ValueError):
        mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1")]))


@pytest.mark.parametrize("bad", ["a'''b", "a\\b"])
def test_secret_that_would_break_the_injected_source_is_rejected(clean_env, monkeypatch, bad):
    _fake_boto3(monkeypatch, {"/site-builder/session-keys/site-hs-v1": bad})
    mod = _load_site_allowlist_fn()
    with pytest.raises(ValueError, match="三引号|反斜杠"):
        mod.load_site_allowlist(_keys(site=[_ref("site-hs-v1")]))


def test_legacy_secret_ssm_failure_fails_synth_by_default_too(clean_env, monkeypatch):
    """两个注入函数对称：legacy 入口开着而 SSM 读不到，默认也让 synth 失败。"""
    mod = _load_jwt_secret_fn()
    broken = types.ModuleType("boto3")

    def _boom(*a, **k):
        raise RuntimeError("ParameterNotFound")

    broken.client = _boom
    monkeypatch.setitem(_sys.modules, "boto3", broken)
    with pytest.raises(Exception) as ei:
        mod.load_jwt_secret(LIVE_LEGACY)
    assert "ParameterNotFound" in str(ei.value) and OFFLINE_FLAG in str(ei.value)


# ---- 3c-1B ticket 21：注入表漏项必须让 synth 失败（惰性解析只缩小半径，不该让坏产物出得去）----
#
# 运行期改成惰性之后，"占位符没被替换"从"整个分发 502"降级成"带 cookie 的私有请求 500"。
# 但那仍然是故障——根治是**这种产物根本不该被生成**。ticket 19 已经让"SSM 读不到"在 synth
# 失败，这一组补上另一半：`origin_request.py` 新增注入点而上面那条 replace 链漏改。

def _residue_check_fn():
    """把残留检查函数单独切出来（片段只含它一个，结束锚点是下一个 def）。

    片段里要 `sys.path.insert(0, Path(__file__).parent / "lambda")` 再 import
    `edge_substitutions.PLACEHOLDER_RE`（正则的唯一定义），所以 `__file__` 必须注进来
    ——compile 出来的片段没有它，缺了会 NameError 而不是报出真正的问题。
    """
    start = SRC.index("def assert_edge_source_fully_injected")
    end = SRC.index("def ", start + 1)
    mod = types.ModuleType("_stack_residue_fragment")
    mod.__dict__.update(sys=_sys, Path=Path,
                        __file__=str(Path(__file__).parents[1] / "stack.py"))
    exec(compile(textwrap.dedent(SRC[start:end]), "<stack fragment>", "exec"), mod.__dict__)
    return mod


def test_residue_check_uses_the_single_definition_of_the_regex():
    """正则只许有一份可执行定义（外加 shell 闸门那份手抄的，bash 没法 import）。

    抄一份的代价已经真实发生过：ticket 22 给 helper 补上了数字，而 verify_deployed_edge.sh
    里那份停在 `[A-Z_]`，漏掉含数字的注入点名字，直到 ticket 21 才发现。
    """
    body = SRC[SRC.index("def assert_edge_source_fully_injected"):]
    body = body[:body.index("def ", 1)]
    assert "from edge_substitutions import PLACEHOLDER_RE" in body
    assert "A-Z0-9_" not in body, "又抄了一份正则——改用 edge_substitutions.PLACEHOLDER_RE"


def test_residue_check_passes_a_fully_injected_source():
    """正对照：全都替换过的文本必须原样返回（否则下面那条可以靠"永远抛"通过）。"""
    mod = _residue_check_fn()
    src = 'A = "us-east-1"\nB = """{"kid": {}}"""\n'
    assert mod.assert_edge_source_fully_injected(src) == src


@pytest.mark.parametrize("left", ["{{NEW_THING}}", "{{ACCESS_TABLE_V2}}"],
                         ids=["plain", "with-digit"])
def test_residue_check_fails_and_names_what_was_missed(left):
    """含数字的占位符也要抓到——旧的 `[A-Z_]+` 会让 `{{ACCESS_TABLE_V2}}` 悄悄躲过去。"""
    mod = _residue_check_fn()
    with pytest.raises(ValueError, match=left.strip("{}")):
        mod.assert_edge_source_fully_injected(f'X = "{left}"\n')


def test_residue_check_runs_before_the_asset_is_written():
    """顺序是全部：检查必须在写 index.py / from_asset **之前**，否则坏产物已经生成了。"""
    body = SRC[SRC.index("class WebRouterStack"):]
    checked = body.index("assert_edge_source_fully_injected(lambda_code)")
    written = body.index("'index.py'")
    assert checked < written, "残留检查跑在写产物之后 = 什么都没拦住"


def test_residue_check_is_not_bypassed_by_a_second_write_path():
    """产物只许由那一处写出去：多一条写路径就绕过了检查。

    只数 `f.write(lambda_code)` 是不够的——`Path(...).write_text(lambda_code)` 同样能落盘
    而那种写法数不到（审查指出）。所以按**所有**把 lambda_code 送去落盘的形态数。
    """
    body = SRC[SRC.index("class WebRouterStack"):]
    writes = re.findall(r"\.write(?:_text|_bytes)?\(\s*lambda_code", body)
    assert len(writes) == 1, f"lambda_code 有 {len(writes)} 条落盘路径：{writes}"
    assert "from_asset(temp_dir)" in body, "产物目录换了名字？这条守卫的前提要跟着改"
