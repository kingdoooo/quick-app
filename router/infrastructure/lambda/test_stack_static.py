"""stack.py 的静态守卫（stack.py import aws_cdk，普通解释器里没有，所以按源码文本断言）。

3c-final：Edge 注入的是 **site family 的 RS256 公钥 allowlist**（`spki_b64`），来源是 KMS
（`session_kms.fetch_verified_public_key_der` 的四项校验），不再有 `{{JWT_SECRET}}` /
`{{LEGACY_ENTRY}}`。**行为**用把 `load_site_allowlist` … `class WebRouterStack` 之间那段源码
切出来单独 exec 的方式验（stack.py 自己 import aws_cdk，本 venv 没有）；纯文本断言只用来钉
"不许回到旧形态"。
"""
import configparser
import json
import re
import subprocess
import sys as _sys
import tempfile
import textwrap
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SRC = (HERE.parent / "stack.py").read_text()

# 三套件共用的 RS 测试密钥 + FakeKms（panel/tests/upgrade_code_vectors.py 的文件头解释了为什么共用一份），
# 以及 `[SessionKeys]` 的真加载器与 KMS 边界。`RS` / `RS_WITH_PREVIOUS` 两段配置文本从 auth 的套件
# **import**，不在这里抄第二份——抄一份就会与 session_keys 的 schema 各自漂。
_sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "auth"))
_sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "auth" / "tests"))
_sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import session_keys as sk  # noqa: E402
import session_kms  # noqa: E402
import upgrade_code_vectors as v  # noqa: E402
from test_session_keys import RS, RS_WITH_PREVIOUS  # noqa: E402

OFFLINE_FLAG = "APP_SYNTH_OFFLINE"


def test_stack_uses_shared_session_keys_helpers_not_inline_copies():
    """3c-final 删了 legacy 入口：`legacy_entry` 与 `load_jwt_secret` 都不该再出现。

    `legacy_entry` 已经从 `session_keys.py` 删除（Task 2），所以留着那条 import 是 synth 期
    ImportError；`load_jwt_secret` 留着则意味着 Edge 还在被注入一把对称密钥。
    """
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert "legacy_entry(" not in body and "load_jwt_secret" not in SRC
    assert "env_json" not in body, "局部名 env_json 与 session_keys.env_json 撞名"


def test_no_hs_era_placeholder_is_injected_anymore():
    """`{{JWT_SECRET}}` / `{{LEGACY_ENTRY}}` 两个注入点随 Task 10 一起消失。

    多余的 `.replace` **不会**被残留检查抓到（它只看剩下的占位符），所以这条要单独钉：
    留着它们等于 stack.py 还在为一个不存在的注入点准备值。
    """
    assert "{{JWT_SECRET}}" not in SRC and "{{LEGACY_ENTRY}}" not in SRC
    assert "{{SITE_ALLOWLIST_JSON}}" in SRC


def test_stack_key_fetch_failure_injects_the_synth_placeholder_not_an_empty_allowlist():
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert 'text = "{}"' not in body, "空 allowlist 看起来合法，synth 与部署前测试都过；要注入带 SYNTH-ONLY 标记的占位"
    assert "SYNTH_PLACEHOLDER_ALLOWLIST_JSON" in body


def test_session_keys_are_loaded_lazily_for_the_injected_allowlist():
    """`[SessionKeys]` 只有一个消费方（allowlist），且**加载必须是惰性的**（controller R17）。

    离线 synth（`APP_SYNTH_OFFLINE=1`）与显式覆盖（`APP_SITE_ALLOWLIST_JSON`）这两条路都必须在
    **配置根本加载不动**时仍然能出模板——切换窗口里 `site-builder/config.ini` 就是旧形态（HS）。
    在 `__init__` 里写 `session_keys = _session_keys()` 会让 `SessionKeysError` 在进 `load_site_allowlist`
    之前就抛出来，两条路一起失效，所以传进去的是**取值函数**而不是取好的值。
    """
    body = SRC[SRC.index("class WebRouterStack"):]
    assert "session_keys = _session_keys" in body
    assert "session_keys = _session_keys()" not in body, (
        "急加载：配置读不动时离线 synth 与显式覆盖都会先炸在这一行（R17）")
    assert "load_site_allowlist(session_keys)" in body
    assert "load_jwt_secret" not in SRC


def test_session_keys_path_insert_is_unconditional():
    """`sys.path` 的插入必须是每个 `from session_keys import …` 各自调一次的无条件动作。

    早先它藏在 `_session_keys()` 里，于是"调用方传了 keys 就不走 `_session_keys()`"的那条路
    会在 import 时炸——**只因为调用顺序恰好对才没现形**（latent ImportError）。
    """
    assert "def _session_keys_on_path()" in SRC
    body = SRC[SRC.index("def load_site_allowlist"):SRC.index("class WebRouterStack")]
    assert "_session_keys_on_path()" in body, "load_site_allowlist 没自己放路径"
    # 判据是**只有一处会往 sys.path 放 auth 目录**（两处就会漂移），而不是那一行的字面写法。
    # 3c-1B-G A5 把它改成幂等（`if target not in sys.path`）——重复插入会让一次 synth 攒下
    # 3-4 份同样的路径；位置仍是 0，解析顺序没变。
    fn = SRC[SRC.index("def _session_keys_on_path()"):SRC.index("def _session_keys()")]
    assert "sys.path.insert(0, target)" in fn and "not in sys.path" in fn, fn
    assert SRC.count("site-builder\" / \"auth\"") == 1, "放路径的地方有第二份副本，两处会漂移"


# ---- 3c-final：公钥 allowlist 的行为（KMS 四项 + 三种模式）--------------------------------------
#
# 此前是"按 ssm_param 取对称密钥"。现在每把 site key 都要过 spec §11.6 第 1 层的四项校验
# （DescribeKey 三项 + 指纹 == config），公钥以 base64 DER SPKI 注入；console 的公钥永不进 Edge。
# 三种模式（controller R17）：显式覆盖 ⇒ 根本不读 config；离线且读不动 ⇒ 占位 + stderr 警告；
# 部署模式下任何失败（配置 / KMS / 指纹）⇒ synth 响亮失败。


def _cfg_with(text: str) -> Path:
    """把 `[SessionKeys]` 文本写成一份真的 config.ini（`load_session_keys` 只接受文件路径）。"""
    path = Path(tempfile.mkdtemp()) / "config.ini"
    path.write_text(text, encoding="utf-8")
    return path


def _fragment(name: str = "_stack_allowlist_fragment"):
    """把 `load_site_allowlist` … `class WebRouterStack` 之间那段切出来，在一个只有它需要的名字的
    命名空间里 exec（`EDGE_REQUIREMENTS` 与 `vendor_edge_dependencies` 也在这一段里）。

    这样能测**行为**而不只是文本，且不需要 aws_cdk。`_session_keys_on_path` 用一个只放路径的替身；
    `__file__` 必须注进来（compile 出来的片段没有它，缺了会 NameError 而不是报出真正的问题）。
    """
    start = SRC.index("def load_site_allowlist")
    end = SRC.index("class WebRouterStack")
    mod = types.ModuleType(name)
    root = HERE.parents[2]

    def _on_path():
        _sys.path.insert(0, str(root / "site-builder" / "auth"))
        return root

    mod.__dict__.update(os=__import__("os"), sys=_sys, json=json, re=re, configparser=configparser,
                        subprocess=subprocess, Path=Path,
                        __file__=str(HERE.parent / "stack.py"), _session_keys_on_path=_on_path)
    # 片段里引用的同文件助手（`_synth_offline`）也一并切进来
    hs = SRC.index("def _synth_offline")
    exec(compile(textwrap.dedent(SRC[hs:SRC.index("def ", hs + 1)]), "<stack helpers>", "exec"),
         mod.__dict__)
    exec(compile(textwrap.dedent(SRC[start:end]), "<stack fragment>", "exec"), mod.__dict__)
    return mod


def _fragment_vendor():
    """同一段片段——`vendor_edge_dependencies` / `EDGE_REQUIREMENTS` 就在里面（独立模块名，避免串味）。"""
    return _fragment("_stack_vendor_fragment")


def _keys(site=(), console=()):
    """手搭的 `SessionKeys` 替身：只用于"配置加载不出来的形态"（真配置会先被 session_keys 拒掉）。"""
    fams = {"site": list(site), "console": list(console)}
    return types.SimpleNamespace(allowlist=lambda fam: fams[fam])


def _ref(kid, alg="RS256", role="current"):
    return types.SimpleNamespace(kid=kid, alg=alg, role=role, key_arn=v.KEY_ARN.get(kid, "arn:x"),
                                 spki_sha256="0" * 64)


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("APP_SITE_ALLOWLIST_JSON", OFFLINE_FLAG):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture(params=[False, True], ids=["online", "offline"])
def offline_flag(request, monkeypatch):
    """两种模式各跑一遍：判据是"这条在**任何**模式下都抛"，不是"默认模式下抛"。"""
    if request.param:
        monkeypatch.setenv(OFFLINE_FLAG, "1")
    else:
        monkeypatch.delenv(OFFLINE_FLAG, raising=False)
    return request.param


def test_allowlist_takes_only_the_site_family_and_fetches_each_public_key_from_kms(clean_env, monkeypatch):
    """spec §4.1：console 的公钥永不进 Edge；每把 site key 的公钥按 key_arn 从 KMS 取并过四项校验。"""
    mod = _fragment()
    keys = sk.load_session_keys(_cfg_with(RS_WITH_PREVIOUS))
    kms = v.FakeKms()
    text = mod.load_site_allowlist(keys, kms=kms)
    got = json.loads(text)
    assert got == {"site-rs-v1": {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_KEY), "role": "current"},
                   "site-rs-v0": {"alg": "RS256", "spki_b64": v.spki_b64(v.SITE_PREV_KEY), "role": "previous"}}
    assert v.spki_b64(v.CONSOLE_KEY) not in text, "console 的公钥进了 Edge"
    assert {c[0] for c in kms.calls} == {"describe_key", "get_public_key"}
    assert "\\" not in text and "'''" not in text


def test_a_key_whose_fingerprint_differs_from_config_fails_synth_in_every_mode(clean_env, monkeypatch, offline_flag):
    """指纹不符不是"读不到"，是 config.ini 指错了 key（或 key 被换过）——离线模式也不许退成占位。"""
    kms = v.FakeKms()
    kms.tamper_public_key_for[v.KEY_ARN[v.SITE_KID]] = v.CONSOLE_KEY
    with pytest.raises(session_kms.KeyMaterialMismatch):
        _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=kms)


@pytest.mark.parametrize("bad_alg", ["HS256", "RS512"])
def test_a_non_rs256_row_is_a_config_error_in_every_mode(clean_env, offline_flag, bad_alg):
    """Edge 只有 RS256 一条验签路径。已加载成功的行里出现别的 alg 是配置错，任何模式都抛。"""
    with pytest.raises(ValueError, match="RS256"):
        _fragment().load_site_allowlist(_keys(site=[_ref("site-rs-v1", alg=bad_alg)]), kms=v.FakeKms())


def test_kms_failure_fails_synth_by_default_instead_of_injecting_the_placeholder(clean_env, capsys):
    """M12：`cdk deploy` 路径上 AccessDenied / 限流 / 网络失败必须让 synth 失败，而不是 exit 0 + 占位符。"""
    class Boom:
        def describe_key(self, **kw):
            raise RuntimeError("AccessDeniedException")

    with pytest.raises(RuntimeError, match="AccessDeniedException") as ei:
        _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=Boom())
    assert OFFLINE_FLAG in str(ei.value)
    assert "SYNTH-ONLY-PLACEHOLDER" not in capsys.readouterr().err


def test_kms_failure_falls_back_to_the_placeholder_only_when_offline_is_explicit(clean_env, monkeypatch, capsys):
    """离线 synth 仍可用，但必须显式声明；占位符带标记且 kid 永不匹配（verify_deployed_edge.sh 会抓）。"""
    monkeypatch.setenv(OFFLINE_FLAG, "1")

    class Boom:
        def describe_key(self, **kw):
            raise RuntimeError("no network")

    text = _fragment().load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=Boom())
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in text
    assert "DO NOT deploy" in capsys.readouterr().err


def test_a_synth_interpreter_without_the_crypto_closure_fails_loudly_by_default(clean_env, monkeypatch, capsys):
    """四项校验要 `session_kms`（→ session → cryptography）。装不上时不许静默出一份没过校验的模板。

    这条不是假想：`router/infrastructure/.venv` 的 requirements.txt 今天只有 CDK 与 boto3，所以
    `cdk deploy` 那条路会真的走到这个分支——报文必须点名要装什么，而不是"KMS 取不到公钥"。
    离线（只想看模板）才退占位。
    """
    monkeypatch.setitem(_sys.modules, "session_kms", None)   # `import session_kms` ⇒ ImportError
    keys = sk.load_session_keys(_cfg_with(RS))
    with pytest.raises(RuntimeError, match="cryptography") as ei:
        _fragment().load_site_allowlist(keys, kms=v.FakeKms())
    assert OFFLINE_FLAG in str(ei.value)
    monkeypatch.setenv(OFFLINE_FLAG, "1")
    text = _fragment().load_site_allowlist(keys, kms=v.FakeKms())
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in text
    assert "DO NOT deploy" in capsys.readouterr().err


# ---- controller R17：`[SessionKeys]` 本身读不动时的三种模式 --------------------------------------
#
# 切换窗口里 `site-builder/config.ini` 还是旧形态（HS），`load_session_keys` 会抛 SessionKeysError。
# 离线 synth 与显式覆盖这两条"只想看模板"的路必须仍然走得通，而 `cdk deploy` 那条必须响亮失败。


def _unloadable_keys(marker="配置读不动"):
    """一个真的会抛 `SessionKeysError` 的取值函数（走 session_keys 自己的报错，不是假异常）。"""
    def _load():
        return sk.load_session_keys(Path(tempfile.mkdtemp()) / f"{marker}-nope.ini")
    return _load


def test_the_explicit_override_never_reads_the_config(clean_env, monkeypatch):
    """R17 模式 1：`APP_SITE_ALLOWLIST_JSON` 在场时**根本不加载** `[SessionKeys]`，也不碰 KMS。"""
    monkeypatch.setenv("APP_SITE_ALLOWLIST_JSON",
                       '{"site-rs-v1": {"alg": "RS256", "spki_b64": "AA", "role": "current"}}')

    def _must_not_load():
        raise AssertionError("显式覆盖时不该去读 config")

    text = _fragment().load_site_allowlist(_must_not_load, kms=v.FakeKms())
    assert '"spki_b64": "AA"' in text
    monkeypatch.setenv("APP_SITE_ALLOWLIST_JSON", "{not json")
    with pytest.raises(ValueError):
        _fragment().load_site_allowlist(_must_not_load)


def test_offline_synth_survives_a_config_that_cannot_be_loaded(clean_env, monkeypatch, capsys):
    """R17 模式 2：显式离线 + 配置读不动 ⇒ 占位 allowlist + stderr 警告（那份模板不可部署）。"""
    monkeypatch.setenv(OFFLINE_FLAG, "1")
    text = _fragment().load_site_allowlist(_unloadable_keys(), kms=v.FakeKms())
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in text
    err = capsys.readouterr().err
    assert "WARNING" in err and "DO NOT deploy" in err


def test_a_config_that_cannot_be_loaded_fails_synth_by_default(clean_env):
    """R17 模式 3：没有覆盖、也没有显式离线 ⇒ 抛，什么都不部署。

    类型仍是 `SessionKeysError`（"这是配置错，不是环境故障"），原消息一字不改地在最前面，
    后面补上与 KMS 那条同样的出路提示（fix round 1 的 Minor 3）——只报"缺哪个键"的话，
    "我现在只想看模板"没有答案。
    """
    with pytest.raises(sk.SessionKeysError, match=r"SessionKeys") as ei:
        _fragment().load_site_allowlist(_unloadable_keys(), kms=v.FakeKms())
    msg = str(ei.value)
    assert OFFLINE_FLAG in msg and "APP_SITE_ALLOWLIST_JSON" in msg, msg
    assert "缺 [SessionKeys] 段" in msg, "原始消息被包掉了：缺哪个键才是第一要紧的信息"


def test_an_allowlist_that_would_break_the_injected_source_is_rejected(clean_env, monkeypatch):
    """注进三引号字符串的文本里不许有反斜杠或三引号。

    KMS 取来的 base64 天然不含它们，所以这条唯一还能被触发的入口是显式覆盖——**它仍然要拦**：
    坏值进产物的后果是 Edge 源码语法错，而 Edge 回滚要 10-20 分钟全球复制。
    """
    for bad in (r'{"k": {"spki_b64": "a\\b"}}', "{\"k\": {\"spki_b64\": \"a'''b\"}}"):
        monkeypatch.setenv("APP_SITE_ALLOWLIST_JSON", bad)
        with pytest.raises(ValueError, match="三引号|反斜杠"):
            _fragment().load_site_allowlist(_unloadable_keys())


# ---- 3c-final：Edge 依赖的交叉安装（ADR 0003 / spec §11.1）--------------------------------------
#
# Edge 内嵌 verifier 现在 import cryptography，而 Lambda@Edge 没有层、也不能带环境变量 ⇒ 依赖必须
# 在 synth 时按 hash 交叉装进 asset 目录。装的目标是 Lambda@Edge 的 python3.11 / x86_64，**不是**
# 本机——用宿主 wheel 装出来的 cryptography 在运行时 import 失败（deployer 的 bundling 已被咬过）。


def test_vendoring_runs_hash_checked_cross_platform_pip_into_the_asset_dir(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or type("R", (), {"returncode": 0})())
    _fragment_vendor().vendor_edge_dependencies("/tmp/x")
    assert len(calls) == 1, f"应当只调一次 pip，实际 {len(calls)} 次"
    argv = calls[0]
    for flag in ("--require-hashes", "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                 "--python-version", "3.11", "--implementation", "cp", "--target", "/tmp/x"):
        assert flag in argv, flag
    assert argv[argv.index("-r") + 1].endswith("lambda/requirements-edge.txt")
    assert argv.index("--require-hashes") < argv.index("-r"), f"开关位置不对：{argv}"


def test_vendoring_is_skipped_only_when_the_injected_allowlist_carries_the_marker():
    """**判据是注进产物的文本，不是 `_synth_offline()` 旗标**（fix round 1 的 Important 1）。

    按旗标判会开出第四种组合：旗标留在环境里 + config 已是 RS 形态 + KMS 可达 ⇒ 注真 allowlist
    （产物无标记、看起来正常）却跳过 vendoring ⇒ 没有 cryptography/ ⇒ 每次 Edge 冷启动 import
    失败 = 全站 502，回滚要 10-20 分钟全球复制。两支都要在取 asset 之前。
    """
    body = SRC[SRC.index("class WebRouterStack"):]
    vend = body.index("vendor_edge_dependencies(temp_dir)")
    sentinel = body.index("_write_synth_only_sentinel(temp_dir)")
    asset = body.index("lambda_.Code.from_asset(temp_dir)")
    assert vend < asset and sentinel < asset, "vendoring / 哨兵必须在产物被取走之前"
    # **判据落在代码上，注释先剥掉**：这一段的注释里正写着"不是 `_synth_offline()` 那个旗标"，
    # 不剥的话那句解释自己就能把下面这条断言判红（同一个坑的反向形态）。
    seg = body[max(0, sentinel - 800):vend]
    code = "\n".join(ln for ln in seg.splitlines() if not ln.lstrip().startswith("#"))
    assert "_asset_is_synth_only(site_allowlist_json)" in code, code
    assert "_synth_offline()" not in code, (
        "判据回到了旗标：陈旧的 APP_SYNTH_OFFLINE + 可用的 config/KMS = 无标记却缺 cryptography/ "
        f"的产物（部署出去全站 502）：{code}")


def test_the_offline_flag_alone_does_not_skip_vendoring(clean_env, monkeypatch):
    """第四种组合的**行为**判据：旗标在，但 config 能加载、KMS 也能取 ⇒ 注的是真 allowlist ⇒ 必须装依赖。

    上一条按源码结构判分支，这一条按 `load_site_allowlist` 的真实返回值判决策——两条一起才把
    "旗标不参与这个决定"钉死。
    """
    monkeypatch.setenv(OFFLINE_FLAG, "1")
    mod = _fragment()
    text = mod.load_site_allowlist(sk.load_session_keys(_cfg_with(RS)), kms=v.FakeKms())
    assert v.spki_b64(v.SITE_KEY) in text and "SYNTH-ONLY" not in text, "旗标不该改变注入内容"
    assert mod._asset_is_synth_only(text) is False, (
        "这份产物没有标记，所以它必须带 cryptography/ —— 决定不能来自旗标")


def test_skipping_vendoring_marks_the_asset_by_construction(tmp_path):
    """「标记 ⇔ 不可部署」：跳过 vendoring 的那一支一定往 asset 里写带标记的哨兵。"""
    mod = _fragment()
    assert mod._asset_is_synth_only(sk.SYNTH_PLACEHOLDER_ALLOWLIST_JSON) is True
    # 显式覆盖里带上标记同样算"我知道这份不可部署"——离线看模板的正当出路
    assert mod._asset_is_synth_only('{"x": {"n": "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"}}') is True
    path = mod._write_synth_only_sentinel(str(tmp_path))
    assert path.parent == tmp_path and path.name.endswith(".txt")
    body = path.read_text(encoding="utf-8")
    assert "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY" in body and "cryptography" in body
    assert [q.name for q in tmp_path.iterdir()] == [path.name], "哨兵之外不该写别的东西"


def test_the_marker_string_has_a_single_definition():
    """标记只许有一处定义（session_keys 的占位常量）——stack.py 里抄一份就会与闸门的 grep 漂。"""
    fn = SRC[SRC.index("def _synth_only_marker"):SRC.index("def _asset_is_synth_only")]
    assert "SYNTH_PLACEHOLDER_ALLOWLIST_JSON" in fn
    code = "\n".join(ln for ln in fn.splitlines() if not ln.strip().startswith("#"))
    code = code[:code.index('"""')] + code[code.rindex('"""') + 3:]     # 去掉 docstring
    assert "SYNTH-ONLY" not in code, code
    assert _fragment()._synth_only_marker() == "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"


def test_vendoring_targets_the_edge_runtime_not_the_host():
    """交叉装的三个开关与 auth / panel 的产物同款，只有 python-version 不同（Edge 是 3.11）。

    AST 那侧的守卫在 `auth/tests/test_requirements_locked.py`（与 deploy_auth 那条同一套做法）；
    这条钉的是"清单路径与 Edge 运行时版本一致"——`lambda_.Runtime.PYTHON_3_11` 与
    `--python-version 3.11` 分叉的症状是 Edge 冷启动 import 失败（全站 502）。
    """
    fn = SRC[SRC.index("def vendor_edge_dependencies"):SRC.index("class WebRouterStack")]
    assert "3.11" in fn and "3.12" not in fn and "3.13" not in fn
    assert "PYTHON_3_11" in SRC[SRC.index("class WebRouterStack"):]
    assert 'EDGE_REQUIREMENTS = Path(__file__).parent / "lambda" / "requirements-edge.txt"' in SRC


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
    # 正则的取用被抽成 `_edge_placeholder_re()`（A5：不再污染 sys.path），一并切进片段
    hs = SRC.index("def _edge_placeholder_re")
    exec(compile(textwrap.dedent(SRC[hs:SRC.index("def ", hs + 1)]), "<stack helpers>", "exec"),
         mod.__dict__)
    exec(compile(textwrap.dedent(SRC[start:end]), "<stack fragment>", "exec"), mod.__dict__)
    return mod


def test_residue_check_uses_the_single_definition_of_the_regex():
    """正则只许有一份可执行定义（外加 shell 闸门那份手抄的，bash 没法 import）。

    抄一份的代价已经真实发生过：ticket 22 给 helper 补上了数字，而 verify_deployed_edge.sh
    里那份停在 `[A-Z_]`，漏掉含数字的注入点名字，直到 ticket 21 才发现。
    """
    helper = SRC[SRC.index("def _edge_placeholder_re"):]
    helper = helper[:helper.index("def ", 1)]
    assert "PLACEHOLDER_RE" in helper and "edge_substitutions.py" in helper
    # **按路径加载**，不是 sys.path 插入（A5）：那个目录会永久占住 sys.path[0]。
    # 判据只看**代码**——docstring 与注释里都会提到 `sys.path`（它们解释的正是为什么不用它），
    # 所以按 AST 取函数体、去掉 docstring 之后再看（按行 grep 抓不掉 docstring 的续行）。
    assert "spec_from_file_location" in helper
    import ast as _ast
    node = next(n for n in _ast.walk(_ast.parse(SRC))
                if isinstance(n, _ast.FunctionDef) and n.name == "_edge_placeholder_re")
    body = node.body[1:] if _ast.get_docstring(node) else node.body
    dumped = "\n".join(_ast.dump(st) for st in body)
    assert "sys" not in dumped, dumped
    body = SRC[SRC.index("def assert_edge_source_fully_injected"):]
    body = body[:body.index("def ", 1)]
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


# ---- 工单 10（M17）：frontend_bucket 的解析 + 两份 config.ini 的对账 -----------------------------
#
# 起点：两份 `.example` 对**同一个桶**用了两种写法（site-builder 侧是 `{account_id}` 模板、router
# 侧写死一个占位账号），且没有任何交叉校验。症状是**每个静态资源 403**，而私有桶上"没权限"与
# "没这个对象"都是 403 ⇒ 极难诊断（DEPLOY.md 自己就警告过这一类）。
#
# 裁定 D-I10-1：桶名在本资产里是**约定**、不是自由配置。四个生产方把 `site-frontend-<account_id>`
# 写死了——`deployer/infra/app.py` 的 IAM 资源 ARN 与 `FRONTEND_BUCKET` 环境变量、
# `panel/deploy_panel.py` 的前端上传、经那个环境变量取值的 upload/undeploy/mark_job、
# `scripts/verify_deployed_components.py` 的核对。所以插值后**必须等于**约定名：
# **与约定相同的字面量放行，其它字面量一律拒**（"配了另一个桶名"只会让 Edge 去读一个没人写过的桶，
# 而那正是最难诊断的 403）。
# 裁定 D-I10-2：部署模式下再与 `site-builder/config.ini` 对账，抓"错账号"与"手抄漂移"。
#
# **行内注释按拒绝处理、不按剥离处理**：与 20 行之下的兄弟键（`require_idp_claim` / `trusted_idps`）
# 同法。configparser 默认把行内注释并进值，剥掉它等于替采用者猜意图；而共享键本来就不许带注释
# （`deployer/tests/test_example_config_consistency.py` 有一条专门的断言）。

GOOD_ACCOUNT = "111122223333"
OTHER_ACCOUNT = "000000000000"
TEMPLATE = "site-frontend-{account_id}"
CONVENTION = f"site-frontend-{GOOD_ACCOUNT}"


# ---- 正对照：三种被接受的形态 -------------------------------------------------------------------

def test_frontend_bucket_template_is_resolved_from_the_aws_account_id():
    assert _fragment().resolve_frontend_bucket(TEMPLATE, GOOD_ACCOUNT) == CONVENTION


def test_a_literal_equal_to_the_convention_is_accepted():
    """采用者已经把账号手填进去的 config.ini 不用改（D-I10-1：等于约定名即放行）。"""
    assert _fragment().resolve_frontend_bucket(CONVENTION, GOOD_ACCOUNT) == CONVENTION


def test_surrounding_whitespace_is_tolerated_on_the_bucket_value():
    """桶名侧的**前后**空白不改变意图（configparser 已经剥过一层，这里是纵深）。

    账号侧**不**在这里洗——它的契约是"已归一化"（`normalize_account_id` 是唯一归一化点，
    见 `test_resolve_requires_an_already_normalized_account`）。
    """
    assert _fragment().resolve_frontend_bucket(f"  {TEMPLATE}  ", GOOD_ACCOUNT) == CONVENTION


# ---- 每条拒绝各一条负例 -------------------------------------------------------------------------

@pytest.mark.parametrize("raw,fragment,why", [
    ("", "为空", "空值：`site-frontend-` 这种桶名合法但不存在，IAM ARN 照样渲染得出来"),
    ("   ", "为空", "只有空白，同上"),
    ('x"; import os #', "注释字符", "引号 + 注释字符（注入形态；被 `#` 那道拒）"),
    ('site-frontend-111122223333"', "S3 桶名", "裸引号、不带 #（被字符集那道拒——能破坏 Edge 源码字面量的字符）"),
    (TEMPLATE + "  # 别改", "注释字符", "行内注释被 configparser 并进值"),
    (TEMPLATE + " ; 别改", "注释字符", "分号注释同理"),
    ("site-frontend-{acct}", "仍含占位符", "占位符名字写错 ⇒ 会原样进 arn:aws:s3:::…/sites/*"),
    ("Site_Frontend_123", "S3 桶名", "大写 + 下划线"),
    ("site frontend", "S3 桶名", "值里有空格"),
    ("ab", "S3 桶名", "短于 3 字符"),
    ("a" * 70, "S3 桶名", "长于 63 字符"),
    ("site-frontend-111122223333\\", "S3 桶名", "尾随反斜杠"),
    ("site-frontend-111122223333\nsite-frontend-000000000000", "S3 桶名", "值里有换行（两行挤进一个值）"),
    ("bucket/sites/../x", "S3 桶名", "路径穿越形态"),
    ("site..frontend-111122223333", "连续的点", "S3 桶名不允许 `..`"),
    ("192.168.1.1", "像 IP", "S3 桶名不允许 IPv4 形态"),
    ("my-own-bucket", "四个生产方", "合法桶名，但不是约定名（D-I10-1）"),
])
def test_every_rejected_frontend_bucket_shape_fails_synth(raw, fragment, why):
    """注入类与写错类一律在 synth 期抛，不许渲染进 `arn:aws:s3:::{bucket}/sites/*` 或 Edge 源码。"""
    with pytest.raises(ValueError, match=fragment):
        _fragment().resolve_frontend_bucket(raw, GOOD_ACCOUNT)


@pytest.mark.parametrize("account,why", [
    ("", "空账号"),
    ("   ", "只有空白"),
    ("  111122223333  ", "两端空白 = 根本没经过 normalize_account_id（契约违反）"),
    ("111122223333  # 我的账号", "行内注释还在 = 同上"),
    ("1234", "短于 12 位"),
    ("1111222233334", "长于 12 位"),
    ("11112222333a", "含非数字"),
    ("1111-2222-3333", "带分隔符"),
])
def test_resolve_requires_an_already_normalized_account(account, why):
    """契约是「**已归一化**的 account 进、桶名出」（工单 10 item 8）：归一化只在
    `normalize_account_id` 一处做，这里只做契约断言，**刻意不再 `.strip()`**。

    为什么要断言而不是"顺手再洗一遍"：洗第二遍就等于开了第二条归一化路径，两条会漂。
    而账号是垃圾时 `site-frontend-` + 垃圾 是个不存在的桶、IAM ARN 照样渲染出来。
    """
    with pytest.raises(ValueError, match="12 位数字"):
        _fragment().resolve_frontend_bucket(TEMPLATE, account)


# ---- item 8：`[AWS] account_id` 的唯一归一化点 --------------------------------------------------
#
# 本栈有**三个**消费方：前端桶名、埋点明细表的 DynamoDB 资源 ARN、栈的 `Environment`。此前三处
# 各自 `config.get(...)`，只有桶名那条会因为空值/垃圾响亮失败。埋点那条是**静默**的——ARN 渲染成
# `arn:aws:dynamodb:{region}::table/...`，PutItem 全部 AccessDenied，而埋点异常一律吞掉
# （统计不是安全控制）⇒ 那个区静默零数据，没有任何人会知道。


@pytest.mark.parametrize("raw,why", [
    ("111122223333", "本来就干净"),
    ("  111122223333  ", "两端空白"),
    ("111122223333\t", "尾随制表符"),
    ("\n111122223333\n", "两端换行"),
])
def test_normalize_account_id_cleans_the_value(raw, why):
    """归一化只剥**空白**。行内注释走拒绝那条路（见下一组）——account_id / frontend_bucket /
    trusted_idps / require_idp_claim 这四个显式校验的键都是同一条规则：**注释一律拒、绝不替采用者剥**。"""
    assert _fragment().normalize_account_id(raw) == GOOD_ACCOUNT


@pytest.mark.parametrize("raw,fragment,why", [
    ("", "为空", "键留空（`.example` 复制过来没填）"),
    ("   ", "为空", "只有空白"),
    ("111122223333  # 我的账号", "注释字符", "行内注释（裸 ConfigParser 会把它并进值）"),
    ("111122223333 ; 我的账号", "注释字符", "分号注释"),
    ("# 111122223333", "注释字符", "注释把整个值吞了"),
    ("1234", "12 位数字", "短于 12 位"),
    ("1111222233334", "12 位数字", "长于 12 位"),
    ("11112222333a", "12 位数字", "含非数字"),
    ("1111-2222-3333", "12 位数字", "带分隔符"),
    ("111122223333 000000000000", "12 位数字", "两个账号挤进一个值"),
])
def test_normalize_account_id_fails_loudly(raw, fragment, why):
    """`#`/`;` 一律拒，**不剥**——与 `frontend_bucket`、`require_idp_claim`、`trusted_idps`
    三个兄弟键同法（controller 已裁定）。

    剥掉等于替采用者猜意图，而"猜对了"和"猜错了"在 synth 输出里长得一模一样；拒掉的话操作者
    看到的是一句"注释另起一行"。共享键本来就不许带注释
    （`deployer/tests/test_example_config_consistency.py` 有一条专门的断言）。
    """
    with pytest.raises(ValueError, match=fragment):
        _fragment().normalize_account_id(raw)


def test_the_empty_and_comment_branches_raise_distinguishable_messages():
    """两条 `match=` 必须能区分分支：`# 111122223333` 走的是注释那条，不是"为空"那条。"""
    mod = _fragment()
    with pytest.raises(ValueError) as empty:
        mod.normalize_account_id("   ")
    with pytest.raises(ValueError) as swallowed:
        mod.normalize_account_id("# 111122223333")
    assert "为空" in str(empty.value) and "注释字符" not in str(empty.value)
    assert "注释字符" in str(swallowed.value) and "为空" not in str(swallowed.value)


_ACCOUNT_READ_RE = re.compile(r'config\.get\(\s*"AWS"\s*,\s*"account_id"[^)]*\)')


def _account_read_violations(src: str) -> list:
    """`[AWS] account_id` 的读取纪律：只两处（`__init__` 顶部、模块级 `Environment`），
    每处都裹在 `normalize_account_id(` 里，且没有第二条归一化路径（裸 `.strip()`），
    埋点 ARN 用的是归一化后的那个局部名。"""
    out = []
    reads = list(_ACCOUNT_READ_RE.finditer(src))
    if len(reads) != 2:
        out.append(f"读了 {len(reads)} 次（应为 2）：{[m.group(0) for m in reads]}")
    for m in reads:
        if "normalize_account_id(" not in src[max(0, m.start() - 40):m.start()]:
            out.append(f"未经归一化的读取：…{src[max(0, m.start() - 30):m.end()]}")
    if re.search(r'"account_id"[^)]*\)\s*\.strip\(\)', src):
        out.append("裸 .strip() —— 第二条归一化路径")
    if not re.search(r"access_account\s*=\s*account_id\b", src):
        out.append("埋点 ARN 没用 __init__ 顶部那个归一化后的 account_id")
    return out


def test_every_account_id_read_goes_through_the_single_normalizer():
    assert _account_read_violations(SRC) == []


@pytest.mark.parametrize("mutate,why", [
    (lambda s: s.replace(
        "        access_account = account_id",
        '        access_account = config.get("AWS", "account_id", "APP_ACCOUNT_ID").strip()'),
     "埋点 ARN 退回自己读 config（空账号 ⇒ 静默零数据）"),
    (lambda s: s.replace(
        '        account=normalize_account_id(config.get("AWS", "account_id", "APP_ACCOUNT_ID")),',
        '        account=config.get("AWS", "account_id", "APP_ACCOUNT_ID"),'),
     "栈 Environment 退回读原值"),
], ids=["analytics-arn", "stack-environment"])
def test_the_account_normalization_guard_reds_on_each_bypass(mutate, why):
    """**变形测试**：守卫真的能咬住"某一处又自己去读 config"这种回退。"""
    mutated = mutate(SRC)
    assert mutated != SRC, f"变形没生效——那一行的形态变了，先改这里（{why}）"
    assert _account_read_violations(mutated), f"守卫抓不住：{why}"


def test_the_account_and_placeholder_branches_raise_distinguishable_messages():
    """两条 `match=` 必须能区分分支。

    原先一条用 `match="frontend_bucket"`——那个词出现在几乎每条消息里，于是"占位符写错"和
    "账号为空"哪条都能让它绿，断言等于只验了"抛了 ValueError"。
    """
    mod = _fragment()
    with pytest.raises(ValueError) as bad_account:
        mod.resolve_frontend_bucket(TEMPLATE, "")
    with pytest.raises(ValueError) as bad_placeholder:
        mod.resolve_frontend_bucket("site-frontend-{acct}", GOOD_ACCOUNT)
    assert "12 位数字" in str(bad_account.value) and "仍含占位符" not in str(bad_account.value)
    assert "仍含占位符" in str(bad_placeholder.value) and "12 位数字" not in str(bad_placeholder.value)


def test_the_literal_rejection_names_all_four_hardcoding_producers():
    """D-I10-1 的可操作性：拒绝时必须说出"改桶名要同时改哪四处"，否则采用者只会把值改回去再撞一次。"""
    with pytest.raises(ValueError) as exc:
        _fragment().resolve_frontend_bucket("my-own-bucket", GOOD_ACCOUNT)
    msg = str(exc.value)
    for producer in ("app.py", "deploy_panel", "mark_job", "verify_deployed_components"):
        assert producer in msg, f"消息没点到生产方 {producer}：{msg}"


# ---- D-I10-2：与 site-builder/config.ini 对账 ---------------------------------------------------

def _sb_config(tmp_path, *, account=GOOD_ACCOUNT, bucket=TEMPLATE, body=None) -> Path:
    path = tmp_path / "config.ini"
    path.write_text(body if body is not None else
                    f"[Platform]\naccount_id = {account}\n\n[Deployer]\nfrontend_bucket = {bucket}\n",
                    encoding="utf-8")
    return path


def test_the_two_configs_are_reconciled_in_deploy_mode(tmp_path, clean_env):
    """**正对照**：两侧解析出同一个桶 ⇒ 返回那个值、不抛。下面几条红没有这一条证明不了什么。"""
    got = _fragment().assert_frontend_bucket_matches_site_builder(
        CONVENTION, config_path=_sb_config(tmp_path))
    assert got == CONVENTION


@pytest.mark.parametrize("account,bucket,why", [
    (OTHER_ACCOUNT, TEMPLATE, "site-builder 侧填的是另一个账号（AWS_PROFILE 指错 / 抄错）"),
    (OTHER_ACCOUNT, f"site-frontend-{OTHER_ACCOUNT}", "site-builder 侧写死了另一个账号的桶名"),
])
def test_a_site_builder_config_naming_another_bucket_fails_synth(tmp_path, clean_env, account, bucket, why):
    """两份 config.ini 指向不同的桶 ⇒ synth 抛，什么都不部（否则线上每个静态资源 403）。"""
    with pytest.raises(ValueError, match="两份 config.ini"):
        _fragment().assert_frontend_bucket_matches_site_builder(
            CONVENTION, config_path=_sb_config(tmp_path, account=account, bucket=bucket))


def test_a_malformed_site_builder_value_is_a_config_error_not_a_skip(tmp_path, clean_env):
    """site-builder 侧的值本身写错 ⇒ 抛（那不是"读不到"，是写错了；与 `_degrade` 同一条纪律）。"""
    with pytest.raises(ValueError, match="site-builder/config.ini"):
        _fragment().assert_frontend_bucket_matches_site_builder(
            CONVENTION, config_path=_sb_config(tmp_path, bucket="Site_Frontend"))


@pytest.mark.parametrize("body,why", [
    (None, "整个文件不存在"),
    ("[Platform]\naccount_id = 111122223333\n", "缺 [Deployer] frontend_bucket"),
    ("[Deployer]\nfrontend_bucket = site-frontend-{account_id}\n", "缺 [Platform] account_id"),
])
def test_a_not_yet_backfilled_site_builder_config_degrades_to_a_warning(tmp_path, clean_env, capsys, body, why):
    """「还没有」才退化：文件不存在 / 缺段 / 缺键 ⇒ stderr 警告并跳过，**且必须仍然不抛**。

    刻意**不**让它失败：切换窗口/首装顺序里 site-builder/config.ini 可能还没回填到这一段，而 router
    侧自己那份已经够渲染出正确的桶名（四个生产方也不读这个键）。**文件存在但坏了**不在此列——见下一条。
    """
    path = tmp_path / "nope.ini" if body is None else _sb_config(tmp_path, body=body)
    got = _fragment().assert_frontend_bucket_matches_site_builder(CONVENTION, config_path=path)
    assert got is None
    err = capsys.readouterr().err
    assert "skipping" in err and "frontend_bucket" in err, err


@pytest.mark.parametrize("body,why", [
    ("account_id = 111122223333\n", "没有段头（MissingSectionHeaderError）"),
    ("[Deployer]\nfrontend_bucket = site-frontend-{account_id}\nfrontend_bucket = other\n[Platform]\naccount_id = 111122223333\n",
     "重复键（DuplicateOptionError）"),
    ("[Deployer]\nfrontend_bucket = site-frontend-{account_id}\n[Deployer]\n[Platform]\naccount_id = 111122223333\n",
     "重复段（DuplicateSectionError）"),
    ("[Deployer\nfrontend_bucket = x\n", "段头不闭合（ParsingError）"),
])
def test_a_corrupt_site_builder_config_hard_fails_instead_of_skipping(tmp_path, clean_env, body, why):
    """文件**存在但坏了**不许退化：退化只服务"还没回填"，把 INI 语法错误也放过去等于让对账可被任何一处
    手误绕开、router 照样部署（Codex review P2）。抛 ValueError，消息点名"损坏"而不是"缺失"。"""
    path = _sb_config(tmp_path, body=body)
    with pytest.raises(ValueError, match="存在但读不了或不合法") as exc:
        _fragment().assert_frontend_bucket_matches_site_builder(CONVENTION, config_path=path)
    assert "还没回填" in str(exc.value), why


def test_a_site_builder_config_that_exists_but_is_unreadable_hard_fails(tmp_path, clean_env):
    """权限拒绝也是"存在但坏了"（PermissionError ⊂ OSError），不是"还没有"。root 下 chmod 000 挡不住读，跳过。"""
    import os
    if os.geteuid() == 0:
        pytest.skip("root 无视文件权限位")
    path = _sb_config(tmp_path, body="[Deployer]\nfrontend_bucket = site-frontend-{account_id}\n[Platform]\naccount_id = 111122223333\n")
    path.chmod(0)
    try:
        with pytest.raises(ValueError, match="存在但读不了或不合法"):
            _fragment().assert_frontend_bucket_matches_site_builder(CONVENTION, config_path=path)
    finally:
        path.chmod(0o600)


def test_offline_synth_skips_the_cross_config_reconciliation(tmp_path, monkeypatch, capsys):
    """显式离线（只想看模板）⇒ 连读都不读、不抛，哪怕两侧真的不一致（R17 那两条路必须走得通）。"""
    monkeypatch.setenv(OFFLINE_FLAG, "1")
    got = _fragment().assert_frontend_bucket_matches_site_builder(
        CONVENTION, config_path=_sb_config(tmp_path, account=OTHER_ACCOUNT))
    assert got is None
    assert OFFLINE_FLAG in capsys.readouterr().err


def test_the_default_reconciliation_path_is_the_repo_site_builder_config():
    """默认路径必须是仓库里那份 site-builder/config.ini（测试全部显式传 path，所以这条单独钉）。"""
    body = SRC[SRC.index("def assert_frontend_bucket_matches_site_builder"):SRC.index("class WebRouterStack")]
    assert 'parents[2]' in body and '"site-builder" / "config.ini"' in body, body


# ---- 接线守卫（源码文本）+ 两条变形 -------------------------------------------------------------

_WIRING_RE = re.compile(r"frontend_bucket\s*=\s*resolve_frontend_bucket\s*\(")
_RECONCILE_RE = re.compile(r"assert_frontend_bucket_matches_site_builder\s*\(\s*frontend_bucket\s*\)")

# `__init__` 里那三行的**逐字**形态。变形用例按它替换，所以每条都先 `assert mutated != SRC`：
# 形态一改，变形失效 ⇒ 那两条守卫会静默变成"改什么都绿"。
_WIRED_CALL = ('frontend_bucket = resolve_frontend_bucket(\n'
               '            config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET"), account_id)')
_RAW_CALL = 'frontend_bucket = config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET")'


def _init_src(src: str = None) -> str:
    s = SRC if src is None else src
    return s[s.index("class WebRouterStack"):]


def test_stack_init_resolves_the_bucket_template_before_building_s3_resources():
    """判据是**正则**而不是 `"resolve_frontend_bucket(" in body`：后者对"调用了但返回值被丢弃"全绿。"""
    assert _WIRING_RE.search(_init_src()), "__init__ 没把解析结果赋给 frontend_bucket——模板会原样进 IAM ARN"


def test_stack_init_reconciles_the_two_configs():
    assert _RECONCILE_RE.search(_init_src()), (
        "__init__ 没拿解析结果去和 site-builder/config.ini 对账（D-I10-2）")


@pytest.mark.parametrize("mutate,why", [
    (lambda s: s.replace(_WIRED_CALL, _RAW_CALL), "解析器整条被删（config 原值直接进 IAM ARN）"),
    (lambda s: s.replace(_WIRED_CALL,
                         _WIRED_CALL.replace("frontend_bucket = resolve", "resolve")
                         + "\n        " + _RAW_CALL),
     "调用还在、返回值被丢弃（原值仍然进 ARN）"),
], ids=["call-deleted", "return-discarded"])
def test_the_wiring_guard_reds_on_each_bypass(mutate, why):
    """**变形测试**：守卫真的能咬住两种绕过形态，而不只是"这段文本恰好在"。"""
    mutated = mutate(SRC)
    assert mutated != SRC, f"变形没生效——`__init__` 里那几行的形态变了，先改这里（{why}）"
    assert _WIRING_RE.search(_init_src(mutated)) is None, f"守卫抓不住：{why}"


def test_the_reconciliation_guard_reds_when_the_call_is_dropped():
    """同上，对账那条也要有变形——只有正向断言时删掉它一样是静默通过。"""
    call = "\n        assert_frontend_bucket_matches_site_builder(frontend_bucket)"
    assert call in SRC, "对账调用的形态变了，先改这里"
    mutated = SRC.replace(call, "")
    assert mutated != SRC
    assert _RECONCILE_RE.search(_init_src(mutated)) is None
