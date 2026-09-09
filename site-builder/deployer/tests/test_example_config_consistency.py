"""两份 `config.ini.example` 的共享键必须一致（merged review M17）。

采用者是从 `.example` 复制开始的——这是他们看到的第一份文件。同一个东西在两份文件里有两个
名字（`[Platform] account_id` / `[AWS] account_id`、`[Deployer] frontend_bucket` /
`[SiteBuilder] frontend_bucket`、`[Platform] routing_table` / `[CDK] stack_name` + `[DynamoDB] table_name`……），
两侧写不一致时**运行期的交叉校验只有一处**：`stack.py` 的 `assert_frontend_bucket_matches_site_builder`
（裁定 D-I10-2，只管 `frontend_bucket`）。其余键仍然各说各话——`stack.py` 直接拿 router 侧的值拼
IAM 资源 ARN，`verify_deployed_components.py` 只读 site-builder 侧。症状是每个静态资源 403——正是
DEPLOY.md 自己警告过「私有桶上 403 不等于 404」的难诊断类别。

判据是**按语义配对**而不是按键名相等：两侧的 `frontend_bucket` 都必须是
`site-frontend-{account_id}` 模板（裁定 D-I10-1：桶名是约定不是自由配置，四个生产方写死了它），
不许任何一侧写死一个占位账号。

**解析语义与生产逐字相同**（裸 `ConfigParser`，行内注释留在值里）。这不是细节：`.example` 的
共享键上写行内注释本身就是缺陷（生产读出来的值会带着那句注释），所以本文件既不剥它、也专门
有一条断言把它判红——见 `inline_comment_offenders`。

evidence: static（只读两份 tracked 的 `.example`，不碰 AWS、不读真 config.ini）。
"""
import configparser
import io
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SB_EXAMPLE = ROOT / "site-builder" / "config.ini.example"
ROUTER_EXAMPLE = ROOT / "router" / "config.ini.example"

ACCOUNT_ID_PLACEHOLDER = "{account_id}"
FRONTEND_BUCKET_CONVENTION = "site-frontend-" + ACCOUNT_ID_PLACEHOLDER
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")
_COMMENT_CHARS = ("#", ";")

# 共享键清单（谁, 段, 键）。**两条守卫共用这一张表**：等值配对与"值里不许有行内注释"。
# 各写一份的代价是新增共享键时只有一侧被守到。
SHARED_KEYS = (
    ("site-builder", "Platform", "account_id"),
    ("site-builder", "Platform", "region"),
    ("site-builder", "Platform", "base_domain"),
    ("site-builder", "Platform", "routing_table"),
    ("site-builder", "Deployer", "frontend_bucket"),
    ("site-builder", "IdP", "provider_name"),
    ("router", "AWS", "account_id"),
    ("router", "AWS", "region"),
    ("router", "DynamoDB", "region"),
    ("router", "DynamoDB", "table_name"),
    ("router", "CDK", "stack_name"),
    ("router", "CloudFront", "domain_name"),
    ("router", "SiteBuilder", "frontend_bucket"),
    ("router", "SiteBuilder", "base_domain"),
    ("router", "SiteBuilder", "trusted_idps"),
)


def _parse(text: str) -> configparser.ConfigParser:
    """**裸 `ConfigParser`**——与生产同款（`router/infrastructure/stack.py` 的 `ConfigLoader`）。

    要紧的是 `inline_comment_prefixes` 默认是关的 ⇒ 行内注释**留在值里**。测试若自己先剥一层，
    就永远看不见"`.example` 的共享键带注释"这一类缺陷，而生产会带着那句注释去拼桶名和 ARN。
    """
    cfg = configparser.ConfigParser()
    cfg.read_string(text)
    return cfg


def _val(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    """生产语义：原值。configparser 只剥值两端的空白，行内注释**不剥**。"""
    return cfg.get(section, key)


def _tokens(csv: str) -> set:
    return {t.strip() for t in csv.split(",") if t.strip()}


def inline_comment_offenders(sb_text: str, router_text: str) -> dict:
    """→ `{"<谁>:<段>:<键>": 值}`；共享键的值里出现 `#` 或 `;` 即缺陷（空 dict = 干净）。

    生产读的是裸 `ConfigParser`，所以 `account_id = 000000000000  # 你的账号` 读出来就是
    `000000000000  # 你的账号`。`.example` 是采用者复制的起点，把注释写在共享键那一行等于给每个
    采用者预置一个坑——`stack.py` 的 `require_idp_claim` / `trusted_idps` / `frontend_bucket` 三条
    都因此改成**直接拒**而不是替采用者剥掉。注释要写就写在**上一行**。
    """
    cfgs = {"site-builder": _parse(sb_text), "router": _parse(router_text)}
    out = {}
    for who, section, key in SHARED_KEYS:
        value = _val(cfgs[who], section, key)
        if any(c in value for c in _COMMENT_CHARS):
            out[f"{who}:{section}:{key}"] = value
    return out


def shared_key_mismatches(sb_text: str, router_text: str) -> dict:
    """→ `{标签: (左值, 右值)}`；空 dict = 两份一致。每个标签对应一条采用者会踩的坑。

    左值是 site-builder 侧、右值是 router 侧，两个例外都是 router **内部**的推导：
    · `domain_name` 与 router 自己的 `[SiteBuilder] base_domain` 比（左值 = 按它推出的期望值）——
      两个键在同一份文件里，让它跨文件比会把"一处漂移"报成两条；
    · `routing_table` 的右值是 `[CDK] stack_name` + `[DynamoDB] table_name` 拼出来的表名。

    `trusted_idps` 是**包含**而不是相等：router 的白名单可以更宽（`.example` 明写可以逗号分隔
    多值），不变量只有「site-builder 侧配的那个 IdP 必须在白名单里」。
    """
    sb, rt = _parse(sb_text), _parse(router_text)
    bad = {}
    sb_account, rt_account = _val(sb, "Platform", "account_id"), _val(rt, "AWS", "account_id")
    if sb_account != rt_account:
        bad["account_id"] = (sb_account, rt_account)
    sb_region = _val(sb, "Platform", "region")
    rt_regions = (_val(rt, "AWS", "region"), _val(rt, "DynamoDB", "region"))
    if len({sb_region, *rt_regions}) != 1:
        bad["region"] = (sb_region, " / ".join(rt_regions))
    sb_base, rt_base = _val(sb, "Platform", "base_domain"), _val(rt, "SiteBuilder", "base_domain")
    if sb_base != rt_base:
        bad["base_domain"] = (sb_base, rt_base)
    rt_domain = _val(rt, "CloudFront", "domain_name")
    if rt_domain != f"*.{rt_base}":
        bad["domain_name"] = (f"*.{rt_base}", rt_domain)
    sb_bucket = _val(sb, "Deployer", "frontend_bucket")
    rt_bucket = _val(rt, "SiteBuilder", "frontend_bucket")
    if sb_bucket != rt_bucket:
        bad["frontend_bucket"] = (sb_bucket, rt_bucket)
    derived = f"{_val(rt, 'CDK', 'stack_name')}-{_val(rt, 'DynamoDB', 'table_name')}"
    sb_table = _val(sb, "Platform", "routing_table")
    if sb_table != derived:
        bad["routing_table"] = (sb_table, derived)
    sb_idp, rt_idp = _val(sb, "IdP", "provider_name"), _val(rt, "SiteBuilder", "trusted_idps")
    if _tokens(sb_idp) - _tokens(rt_idp):        # 包含，不是相等（见文件末尾那两组用例）
        bad["trusted_idps"] = (sb_idp, rt_idp)
    return bad


def _sb() -> str:
    return SB_EXAMPLE.read_text(encoding="utf-8")


def _router() -> str:
    return ROUTER_EXAMPLE.read_text(encoding="utf-8")


def test_the_two_example_configs_agree_on_every_shared_key():
    assert shared_key_mismatches(_sb(), _router()) == {}


def test_no_shared_key_value_carries_an_inline_comment():
    """共享键的值里不许有 `#`/`;`——生产不剥它，`stack.py` 见到就拒（注释写在上一行）。"""
    assert inline_comment_offenders(_sb(), _router()) == {}


def test_frontend_bucket_is_the_same_account_id_template_in_both_examples():
    """M17 的原话：一侧是 `site-frontend-{account_id}` 模板、另一侧写死占位账号。

    两侧都必须是模板：router 栈 synth 时按 `[AWS] account_id` 插值（`resolve_frontend_bucket`），
    site-builder 侧由各脚本同法插值，采用者不必在任何一侧手填账号。**写死一个字面量即使两侧相同
    也不行**——那会随着"复制 `.example` 时忘了改账号"一起漂，而占位账号是个别人的账号。
    """
    sb, rt = _parse(_sb()), _parse(_router())
    assert _val(sb, "Deployer", "frontend_bucket") == _val(rt, "SiteBuilder", "frontend_bucket") \
        == FRONTEND_BUCKET_CONVENTION


def test_router_example_carries_only_one_placeholder_account():
    """占位账号只许有一个值，且等于 `[AWS] account_id`——ARN 样例里冒出第二个 12 位数
    就是「AWS 文档的占位账号」又混进来了（M17 的根源）。"""
    rt = _parse(_router())
    own = _val(rt, "AWS", "account_id")
    foreign = {m for m in _TWELVE_DIGITS.findall(_router())} - {own}
    assert not foreign, f"router/config.ini.example 里有第二个占位账号：{sorted(foreign)}"


def _set(text: str, section: str, key: str, value: str) -> str:
    """把 `[section]` 里 `key` 的值换成 `value`（configparser 往返，不做行级正则）。

    往返而不是改行：行级正则要自己处理续行、重复键名、段边界，而这几样正是 configparser 的职责。
    代价是输出丢掉注释——变形样本不需要注释。**键不存在即硬失败**：键被改名时每条变形都会静默
    变成空转，那比没有变形更糟。
    """
    cfg = _parse(text)
    if not (cfg.has_section(section) and cfg.has_option(section, key)):
        raise AssertionError(f"[{section}] {key} 不在样例里——本条变形空转，先改这张表")
    cfg.set(section, key, value)
    buf = io.StringIO()
    cfg.write(buf)
    return buf.getvalue()


def test_the_drift_helper_refuses_a_key_that_no_longer_exists():
    """`_set` 自己的正对照：键被改名/删掉时它硬失败，而不是原样返回让变形静默空转。"""
    with pytest.raises(AssertionError, match="不在样例里"):
        _set(_router(), "AWS", "account_id_typo", "111122223333")
    with pytest.raises(AssertionError, match="不在样例里"):
        _set(_router(), "NoSuchSection", "account_id", "111122223333")


def test_the_drift_helper_changes_exactly_one_value():
    """`_set` 的第二条正对照：往返不许顺带改动别的共享键，否则每条变形都会命中一堆标签。"""
    before, after = _parse(_router()), _parse(_set(_router(), "DynamoDB", "region", "eu-west-1"))
    changed = {(s, k) for s in after.sections() for k in after[s]
               if _val(after, s, k) != _val(before, s, k)}
    assert changed == {("DynamoDB", "region")}, changed


@pytest.mark.parametrize("drift,expected", [
    (lambda sb, rt: (_set(sb, "Platform", "account_id", "111122223333"), rt), "account_id"),
    (lambda sb, rt: (sb, _set(rt, "DynamoDB", "region", "eu-west-1")), "region"),
    (lambda sb, rt: (_set(sb, "Platform", "base_domain", "other.example"), rt), "base_domain"),
    (lambda sb, rt: (sb, _set(rt, "CloudFront", "domain_name", "*.other.example")), "domain_name"),
    (lambda sb, rt: (sb, _set(rt, "SiteBuilder", "base_domain", "other.example")), "domain_name"),
    (lambda sb, rt: (sb, _set(rt, "SiteBuilder", "frontend_bucket",
                              "site-frontend-{account_id}-x")), "frontend_bucket"),
    (lambda sb, rt: (sb, _set(rt, "CDK", "stack_name", "OtherStack")), "routing_table"),
    (lambda sb, rt: (_set(sb, "IdP", "provider_name", "Feishu"), rt), "trusted_idps"),
], ids=["account_id", "region", "base_domain", "domain_name-cloudfront",
        "domain_name-base", "frontend_bucket", "routing_table", "trusted_idps"])
def test_shared_key_guard_fires_on_each_drift_class(drift, expected):
    """变形测试：每一类漂移都必须被点名，否则上面那条绿只说明「没人比过」。"""
    sb, rt = drift(_sb(), _router())
    got = shared_key_mismatches(sb, rt)
    assert expected in got, got


@pytest.mark.parametrize("who,section,key", [
    ("site-builder", "Platform", "account_id"),
    ("router", "AWS", "account_id"),
    ("router", "SiteBuilder", "frontend_bucket"),
    ("router", "SiteBuilder", "trusted_idps"),
])
@pytest.mark.parametrize("comment", ["  # 你的账号", " ;你的账号"])
def test_the_inline_comment_guard_fires_on_each_shared_key(who, section, key, comment):
    """变形测试：行内注释加在**任何**共享键上都必须被点名。

    生产不剥它 ⇒ `stack.py` 会拿带注释的字符串去拼桶名与 IAM ARN（`frontend_bucket` 那条现在直接拒），
    而两份 `.example` 是采用者的起点。
    """
    sb, rt = _sb(), _router()
    cfg = _parse(sb if who == "site-builder" else rt)
    dirty = _val(cfg, section, key) + comment
    if who == "site-builder":
        sb = _set(sb, section, key, dirty)
    else:
        rt = _set(rt, section, key, dirty)
    assert f"{who}:{section}:{key}" in inline_comment_offenders(sb, rt)


def test_the_inline_comment_guard_is_not_vacuous_on_the_real_files():
    """正对照：清单里的每个键在两份 `.example` 里都真的存在（拼错段名会让上一条整批空转）。"""
    cfgs = {"site-builder": _parse(_sb()), "router": _parse(_router())}
    for who, section, key in SHARED_KEYS:
        assert cfgs[who].has_option(section, key), f"{who}:{section}:{key} 不在样例里"


# ---- item 9：`trusted_idps` 的判据是**包含**，不是集合相等 ---------------------------------------
#
# router 的 `.example` 明写 `trusted_idps` 可以逗号分隔多值（`Okta,Feishu`），而 site-builder 侧的
# `[IdP] provider_name` 是**这个平台专用池联邦的那一个** IdP。所以两侧不是对等关系：
# router 的白名单可以更宽（同一个池上还联邦着别的 IdP，或为切换期预留），
# 唯一的不变量是 site-builder 配的那个必须**在**白名单里——不在就等于
# `require_idp_claim=true` 时那个 IdP 的用户全部被 302，而 Edge 回滚要 10-20 分钟全球复制。


@pytest.mark.parametrize("sb_idp,rt_idps,why", [
    ("Feishu", "Feishu", "一对一"),
    ("Feishu", "Okta,Feishu", "router 侧多信任一个（`.example` 明写可以逗号分隔多值）"),
    ("Feishu", " Feishu , Okta ", "多值带空格（`_tokens` 逐项 strip）"),
    ("", "", "都留空：首装形态（require_idp_claim=false）"),
    ("", "Okta", "router 侧先填、site-builder 侧还没接 IdP"),
])
def test_trusted_idps_accepts_a_router_side_superset(sb_idp, rt_idps, why):
    sb = _set(_sb(), "IdP", "provider_name", sb_idp)
    rt = _set(_router(), "SiteBuilder", "trusted_idps", rt_idps)
    assert "trusted_idps" not in shared_key_mismatches(sb, rt)


@pytest.mark.parametrize("sb_idp,rt_idps,why", [
    ("Feishu", "", "router 侧白名单为空 ⇒ require_idp_claim=true 时全站锁死"),
    ("Feishu", "Okta", "两侧各配了一个不同的 IdP"),
    ("Okta,Feishu", "Okta", "site-builder 侧两个、router 侧只信一个 ⇒ 另一个的用户全被 302"),
])
def test_trusted_idps_reds_when_the_router_allowlist_is_missing_one(sb_idp, rt_idps, why):
    """变形反例：**只有 site-builder 侧多出来的项**算漏，反过来不算。"""
    sb = _set(_sb(), "IdP", "provider_name", sb_idp)
    rt = _set(_router(), "SiteBuilder", "trusted_idps", rt_idps)
    got = shared_key_mismatches(sb, rt)
    assert "trusted_idps" in got, got
    assert got["trusted_idps"] == (sb_idp, rt_idps.strip())
