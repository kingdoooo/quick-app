"""stack.py 的静态守卫（stack.py import aws_cdk，普通解释器里没有，所以按源码文本断言）。

3c-final：Edge 注入的是 **site family 的 RS256 公钥 allowlist**（`spki_b64`），来源是 KMS
（`session_kms.fetch_verified_public_key_der` 的四项校验），不再有 `{{JWT_SECRET}}` /
`{{LEGACY_ENTRY}}`。**行为**用把 `load_site_allowlist` … `class WebRouterStack` 之间那段源码
切出来单独 exec 的方式验（stack.py 自己 import aws_cdk，本 venv 没有）；纯文本断言只用来钉
"不许回到旧形态"。
"""
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

    mod.__dict__.update(os=__import__("os"), sys=_sys, json=json, subprocess=subprocess, Path=Path,
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
