"""M21（merged review §9）：模板 ↔ fixture 字节一致的可执行守卫。

`CLAUDE.md` 把「模板与 fixture 字节一致」列为改合同时的要求，但在此之前**没有任何
测试或脚本引用 `templates/`**——子代理逐对 diff 过当时一致，即无缺陷、只缺守卫。
潜伏方式：改了 `templates/db.js`（Agent 照抄进 sql 站点的那份）却忘了同步
`fixtures/sql-expenses/backend/db.js`（黄金样例 + E2E 打的那份），两者悄悄分叉，
而 E2E 仍绿（它打的是 fixture，不是模板）——直到某个采用者照模板写出来的站点
与文档承诺的行为不一致。

这里把那 5 组配对钉成逐字节相等。配对是**双向枚举**的：多一个模板 example 而没有
对应 fixture、或反过来，都会红——防止"加了模板忘了加 fixture"这半也漏。
"""
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATES = _ROOT / "site-builder" / "skills" / "site-builder" / "templates"
_FIXTURES = _ROOT / "site-builder" / "fixtures"

# (模板文件, fixture 文件)。SKILL.md 明写 db.js「原样复制」、run.sh「原样放项目根」，
# 三个 site.json.*.example 是三档清单样例、与对应 fixture 的 site.json 应逐字节一致。
_PAIRS = [
    ("db.js", "sql-expenses/backend/db.js"),
    ("run.sh", "run.sh"),
    ("site.json.static.example", "static-hello/site.json"),
    ("site.json.nosql.example", "nosql-notes/site.json"),
    ("site.json.sql.example", "sql-expenses/site.json"),
]


@pytest.mark.parametrize("tmpl,fix", _PAIRS, ids=[p[0] for p in _PAIRS])
def test_template_and_fixture_are_byte_identical(tmpl, fix):
    t, f = _TEMPLATES / tmpl, _FIXTURES / fix
    assert t.exists(), f"模板不存在: {t}"
    assert f.exists(), f"fixture 不存在: {f}"
    tb, fb = t.read_bytes(), f.read_bytes()
    assert tb == fb, (
        f"模板与 fixture 已分叉（改了一侧没同步另一侧）：\n"
        f"  模板   {t}  ({len(tb)} B)\n"
        f"  fixture {f}  ({len(fb)} B)\n"
        f"改合同/模板时必须同步 fixture —— fixture 是 E2E 与黄金样例打的那份，"
        f"分叉后 E2E 仍绿但采用者照模板写出来的站点会与文档承诺不符。")


def test_every_manifest_example_has_a_paired_fixture():
    """每个 `site.json.*.example` 都必须在配对表里，反之亦然（防"加了一半"）。

    多一个模板 example 而配对表没收（= 没建对应 fixture），或配对表引用了一个
    已删的 example，这条都会红。
    """
    examples = {p.name for p in _TEMPLATES.glob("site.json.*.example")}
    paired = {t for t, _f in _PAIRS if t.startswith("site.json.")}
    assert examples == paired, (
        f"模板里的清单样例与配对表不一致：\n"
        f"  模板有、配对表没收（忘了建 fixture？）: {sorted(examples - paired)}\n"
        f"  配对表有、模板已没有（该删这条配对？）: {sorted(paired - examples)}")
