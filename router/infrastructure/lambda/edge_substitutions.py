"""Edge 占位符替换表的**唯一定义**，以及"替换后不许有残留"的断言（3c-1B ticket 22）。

Lambda@Edge 不支持环境变量，所以 `origin_request.py` 的配置由 CDK 在部署时做**字符串替换**
注入（`{{PLACEHOLDER}}` 形态）。测试要跑真实的 Edge 代码，就得自己做同一件事。

**为什么要收成一份**：这张表原先手抄在四处（`deployer/tests/test_migrate_permissions.py`、
`panel/tests/test_frontend_contract.py`、`auth/tests/test_edge_new_form_vector.py`、
`router/…/test_edge_kid_allowlist.py` 的 `BASE_SUBS`），而"无残留占位符"只有一处断言、
那条断言的正则还是 `[A-Z_]+`（**漏掉任何含数字的占位符**）。于是给 `origin_request.py` 新增一个
注入点时，几个**无关**套件会各自以看不出原因的方式失败——3c-1A 加 `{{SITE_ALLOWLIST_JSON}}` 时
真的发生过：模块级 `json.loads` 让未替换的源码在 **import 期**就 `JSONDecodeError`，
而唯一能解释原因的那句提示在第三个文件里。（那个 import 期爆炸已由 ticket 21 拆掉——
顶层不再消费注入值。于是漏项的症状从"难懂的假红"变成了**假绿**，本文件这条断言更重要了。）

**放在这里而不是 `panel/tests/`**（ticket 22 原文写的是后者，理由只是"已有跨包 helper 先例"）：
这张表描述的就是**同目录**那个 `origin_request.py` 的注入点，加占位符的人改的是它、看到的就是本文件。
放心加文件：Edge 产物只含 `index.py`（`stack.py` 把 `origin_request.py` 复制进临时目录再
`Code.from_asset`，2026-09-04 核对过 cdk.out 的 asset 目录只有一个文件），本文件不会被打进去。

用法（三种粒度，都会做残留断言）：

    import edge_substitutions as es
    src  = es.edge_source(TRUSTED_IDPS="Feishu")                    # → 替换后的源码文本
    mod  = es.load_edge_module("_edge_for_x", SITE_ALLOWLIST_JSON=json.dumps(allow))   # → 已 exec 的模块
    text = es.substitute(any_src, BASE_DOMAIN="example.com")        # → 任意源码文本
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
EDGE_SRC_PATH = HERE / "origin_request.py"
sys.path.insert(0, str(HERE.parents[2] / "site-builder" / "panel" / "tests"))
import upgrade_code_vectors as _v  # noqa: E402  三套件共用的 RS 测试密钥（import 期生成）

# **正则必须含数字**：`{{SITE_ALLOWLIST_JSON}}` 没有数字，但下一个注入点未必
# （`{{ACCESS_TABLE_V2}}` 这种），而 `[A-Z_]+` 会让它悄悄躲过残留检查。
PLACEHOLDER_RE = re.compile(r"\{\{[A-Z0-9_]+\}\}")

# 默认值：能让 Edge 代码跑起来的中性取值。**安全开关取的是收紧值**
# （`REQUIRE_IDP_CLAIM=true`、非空 `TRUSTED_IDPS`）——测试的默认态不该比生产松。
# allowlist 的默认值用 `upgrade_code_vectors` 那把 site 私钥的**公钥**（三套件共用同一把，
# 于是"auth 签、Edge 验"的跨组件向量不必各自维护一份密钥）。
DEFAULT_SITE_ALLOWLIST = {_v.SITE_KID: {"alg": "RS256", "spki_b64": _v.spki_b64(_v.SITE_KEY), "role": "current"}}
DEFAULTS: dict[str, str] = {
    "DYNAMODB_TABLE_NAME": "t",
    "DYNAMODB_REGION": "us-east-1",
    "FRONTEND_BUCKET_DOMAIN": "b.s3.us-east-1.amazonaws.com",
    "BASE_DOMAIN": "example.com",
    "SITE_ALLOWLIST_JSON": json.dumps(DEFAULT_SITE_ALLOWLIST),
    "REQUIRE_IDP_CLAIM": "true",
    "TRUSTED_IDPS": "Feishu,Okta",
    "ACCESS_TABLE": "site-access-events",
    "ACCESS_REPLICA_REGIONS": "us-east-1",
}


def substitute(src: str, **overrides: str) -> str:
    """把 `{{NAME}}` 换成值；**替换后仍有占位符即抛**，且拼错的 override 名也抛。

    两个方向都要硬失败：
    - **少替换**（源码新增了注入点而本文件没跟上）⇒ 残留检查抛，报文点名缺哪个；
    - **多给/拼错**（`TRUSTED_IDPSS="Okta"`）⇒ 静默用默认值是最坏的，因为调用方以为自己
      设了开关。所以 override 的名字必须在源码里真的以占位符出现。
    """
    unknown = [k for k in overrides if f"{{{{{k}}}}}" not in src]
    if unknown:
        raise AssertionError(
            f"这些 override 在源码里不是占位符（拼错了？）: {sorted(unknown)}；"
            f"源码里现有的是 {sorted(m[2:-2] for m in set(PLACEHOLDER_RE.findall(src)))}")
    table = {**DEFAULTS, **overrides}
    for name, value in table.items():
        src = src.replace(f"{{{{{name}}}}}", str(value))
    left = sorted(set(PLACEHOLDER_RE.findall(src)))
    if left:
        raise AssertionError(
            f"替换后仍有占位符 {left} —— origin_request.py 新增了注入点，"
            f"把它加进 {Path(__file__).name} 的 DEFAULTS（一处改，四个套件都跟上）。"
            "**不补的后果是假绿**：ticket 21 之后 Edge 顶层不再消费注入值，所以带未替换占位符的"
            "源码照样 import 得动——症状要等到真正用那个值的那一刻才出现（甚至只在某一类请求上）。"
            "这条断言现在是最早的一道。")
    return src


def edge_source(**overrides: str) -> str:
    """真实的 `origin_request.py` 经替换后的源码文本。"""
    return substitute(EDGE_SRC_PATH.read_text(encoding="utf-8"), **overrides)


def load_edge_module(name: str, *, write_to: Path | None = None, **overrides: str) -> types.ModuleType:
    """把替换后的 Edge 源码作为独立模块加载。

    `write_to` 给的是目录：router 那边要把副本落在测试目录里（`conftest.py` 靠
    `_*_testable` 的模块名给埋点装假件，见那边的 autouse 夹具），所以支持落盘；
    其余调用方用内存 exec 就够。
    """
    src = edge_source(**overrides)
    if write_to is None:
        mod = types.ModuleType(name)
        mod.__dict__["__file__"] = str(EDGE_SRC_PATH)
        exec(compile(src, str(EDGE_SRC_PATH), "exec"), mod.__dict__)
        return mod
    path = Path(write_to) / f"{name}.py"
    path.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # **这条登记是刻意留下的，不是泄漏**（3c-1B-G A5 复核过）：`conftest.py` 的 autouse 夹具
    # 遍历 `sys.modules` 找 `_*_testable` 来给埋点装会抛的假 client（那是"任何用例都不许写到
    # 真 DynamoDB"这条不变量的实现方式）。把它清掉，那道护栏就静默失效。
    # 与 `panel/tests/module_mutation.py` 的取舍相反，理由是那边的副本落在用完即删的
    # `tmp_path` 下、且没有任何夹具靠它——这里的副本落在测试目录里，是长期存在的。
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
