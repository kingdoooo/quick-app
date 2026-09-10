"""`.example` 里的每个配置键都得有人读（merged review M22）。

采用者拿到 `site-builder/config.ini.example` 与 `router/config.ini.example`，会把每个键当成
"填了就生效"。一个没有任何代码读取的键是**假的可配置面**：改了静默无效，出问题时排查方向被带偏
（M22 原案：`[Panel] ops_log_table` / `session_codes_table` 与 `[ApiKey] keys_table` 在 `.example`
里有，而部署脚本把表名写成字面量）。本文件把「每个键至少被一处代码读取」变成可执行守卫。

判据（刻意保守、可解释；**它只证明"有人读"，不证明"读它的那个组件就是采用者以为的那个"**——
`[Deployer] jobs_table` 这类"CDK 按字面量建表、脚本按 config 读表名"的半配置态不在它射程内）：
  · **验收脚本也算读者**（`scripts/verify_*`）——所以 `[Deployer] artifacts_bucket` / `frontend_bucket` 这两个只被
    验收脚本读、由 CDK 写死的桶名模板能过本守卫；它们的"填了别的也无效"由脚本侧的模板解析 + 约定名核对与
    `.example` 注释兜住（工单 10 / Codex review），不由本守卫兜。
  · 读者 = `site-builder/` 与 `router/` 下的非测试 Python 源码（tests/、test_*.py、conftest.py、
    .venv、cdk.out、fixtures 排除；测试读了 .example 不算"有人读"）。
  · 键 (S, K) 算被读 ⇔ 存在一个读者文件同时**点名** S 与 K。"点名" = 该字符串是文件里的一个
    字符串常量，或匹配文件里某个 f-string 的形态（`f"SessionKey:{kid}"` 点名每个 `[SessionKey:*]`
    小节、`f"{fam}_current"` 点名 `site_current` / `console_current`）。常量片段不足 4 字符的
    f-string 不算——否则 `f"{x}_"` 会点名一切。
  · 整段读取（`cfg.items("Tags")` / `dict(cfg["IdP"])` / `cfg["IdP"].items()`）算读了该段的每个键
    ——router 的 `[Tags]` 就是这样被原样转成资源标签的。
  · **注释掉的模板段也算**（`# [ApiKey]` 下面的 `# keys_table = …`）：那是给采用者取消注释用的，
    与真键一样会被填、被期待生效。模板块以 `# [Section]` 开头，到第一个空注释行 / 非注释行结束；
    `# # 说明` 这种双井号的 prose 不是键。

读者按字符串常量匹配而不是按 AST 的取值形态：仓库里读 config 的写法至少有六种
（`CFG[s][k]`、`cfg[s].get(k)`、`cfg.get(s, k, fallback=)`、`_cfg(s, k)`、`read_cfg(s, k)`、
`(ENV, s, k, default)` 元组），逐种识别会漏掉下一种。代价是短键名（`region` / `email`）有被无关字符串
撞上的可能——所以本文件同时带反例（合成的死键必须被点出来）证明守卫能红。
"""
import ast
import configparser
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = {
    "site-builder": ROOT / "site-builder" / "config.ini.example",
    "router": ROOT / "router" / "config.ini.example",
}
READER_ROOTS = (ROOT / "site-builder", ROOT / "router")
EXCLUDED_DIRS = {".venv", "cdk.out", "node_modules", "__pycache__", "tests", "fixtures"}
# f-string 至少要有这么多个字面字符才算"点名"了什么（`f"{x}_"` 不算，`f"{fam}_current"` 算）
MIN_FSTRING_LITERAL = 4

_COMMENTED_SECTION = re.compile(r"^#\s*\[([^\]\s]+)\]\s*$")
_COMMENTED_KEY = re.compile(r"^#\s*([A-Za-z][A-Za-z0-9_]*)\s*=")
_EMPTY_COMMENT = re.compile(r"^#\s*$")


# ---- .example 侧：哪些 (section, key) 是"键" -----------------------------------------------

def commented_template_keys(text: str) -> set[tuple[str, str]]:
    """`# [Section]` 开头的注释模板块里的 `# key = value` 行。"""
    out, section = set(), None
    for line in text.splitlines():
        header = _COMMENTED_SECTION.match(line)
        if header:
            section = header.group(1)
            continue
        if section is None:
            continue
        if not line.startswith("#") or _EMPTY_COMMENT.match(line):
            section = None
            continue
        key = _COMMENTED_KEY.match(line)
        if key:
            out.add((section, key.group(1).lower()))
    return out


def example_keys(path: Path) -> set[tuple[str, str]]:
    text = path.read_text(encoding="utf-8")
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_string(text, source=str(path))
    keys = {(s, k) for s in cfg.sections() for k in cfg[s]}
    return keys | commented_template_keys(text)


# ---- 代码侧：一个文件"点名"了哪些字符串 ---------------------------------------------------

def reader_files() -> list[Path]:
    out = []
    for root in READER_ROOTS:
        for p in root.rglob("*.py"):
            parts = p.relative_to(ROOT).parts
            if EXCLUDED_DIRS & set(parts[:-1]):
                continue
            if p.name == "conftest.py" or p.name.startswith("test_"):
                continue
            out.append(p)
    return sorted(out)


def _fstring_pattern(node: ast.JoinedStr):
    parts, literal = [], 0
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(re.escape(v.value))
            literal += len(v.value.strip())
        elif isinstance(v, ast.FormattedValue):
            parts.append(".+")
        else:
            return None
    if literal < MIN_FSTRING_LITERAL:
        return None
    return re.compile("".join(parts))


def _whole_section_read(call: ast.Call):
    """`cfg.items("S")` / `dict(cfg["S"])` / `cfg["S"].items()` → "S"，否则 None。"""
    f = call.func
    if (isinstance(f, ast.Attribute) and f.attr == "items" and call.args
            and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        return call.args[0].value
    target = None
    if isinstance(f, ast.Name) and f.id == "dict" and call.args:
        target = call.args[0]
    elif isinstance(f, ast.Attribute) and f.attr == "items" and not call.args:
        target = f.value
    if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
            and isinstance(target.slice.value, str)):
        return target.slice.value
    return None


class Reader:
    def __init__(self, path: Path):
        self.path = path
        self.consts: set[str] = set()
        self.patterns: list = []
        self.whole_sections: set[str] = set()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.consts.add(node.value)
            elif isinstance(node, ast.JoinedStr):
                pat = _fstring_pattern(node)
                if pat is not None:
                    self.patterns.append(pat)
            elif isinstance(node, ast.Call):
                section = _whole_section_read(node)
                if section:
                    self.whole_sections.add(section)

    def names(self, s: str) -> bool:
        return s in self.consts or any(p.fullmatch(s) for p in self.patterns)

    def reads(self, section: str, key: str) -> bool:
        return self.names(section) and (self.names(key) or section in self.whole_sections)


def unread_keys(example: Path, readers: list) -> list[tuple[str, str]]:
    return [(s, k) for s, k in sorted(example_keys(example))
            if not any(r.reads(s, k) for r in readers)]


@pytest.fixture(scope="module")
def readers():
    return [Reader(p) for p in reader_files()]


# ---- 守卫本体 --------------------------------------------------------------------------

@pytest.mark.parametrize("which", sorted(EXAMPLES))
def test_every_example_key_is_read_by_some_code(which, readers):
    dead = unread_keys(EXAMPLES[which], readers)
    assert dead == [], (
        f"{EXAMPLES[which].relative_to(ROOT)} 里这些键没有任何代码读取——"
        f"接上读取方，或从 .example 删除（采用者会填它并期待生效）：{dead}")


def test_reader_set_covers_the_deploy_scripts_and_excludes_tests(readers):
    """排除规则改坏时（比如把 scripts/ 也排掉、或把 tests/ 放进来）"全绿"会变成空转；
    点名几个必在 / 必不在的文件钉住边界。"""
    rel = {r.path.relative_to(ROOT).as_posix() for r in readers}
    for must in ("site-builder/panel/deploy_panel.py", "site-builder/auth/deploy_auth.py",
                 "site-builder/scripts/deploy_pool.py", "site-builder/scripts/ensure_fixture_site.py",
                 "site-builder/deployer/infra/app.py", "router/infrastructure/stack.py"):
        assert must in rel, f"读者集合里缺 {must}"
    for p in rel:
        assert "/tests/" not in f"/{p}" and Path(p).name != "conftest.py" \
            and not Path(p).name.startswith("test_"), f"测试文件混进了读者集合：{p}"
        assert ".venv" not in p and "cdk.out" not in p, p


# ---- 反例与正对照：证明每条判据真的会动 ------------------------------------------------------

def test_guard_flags_a_synthetic_dead_key(tmp_path, readers):
    real = EXAMPLES["site-builder"].read_text(encoding="utf-8")
    probe = tmp_path / "config.ini.example"
    probe.write_text(real + "\n[Probe]\nunread_probe_key = 1\n", encoding="utf-8")
    assert ("Probe", "unread_probe_key") in unread_keys(probe, readers)


def test_guard_flags_a_synthetic_dead_key_inside_a_commented_template(tmp_path, readers):
    real = EXAMPLES["site-builder"].read_text(encoding="utf-8")
    probe = tmp_path / "config.ini.example"
    probe.write_text(real + "\n# 可选：\n# [Probe]\n# unread_probe_key = 1\n#\n", encoding="utf-8")
    assert ("Probe", "unread_probe_key") in unread_keys(probe, readers)


def test_commented_template_scanner_shape():
    text = ("[Real]\na = 1\n\n# 可选组件：\n# [Opt]\n# first_key = x\n"
            "# # 说明 prose = 不是键\n# second_key = y\n#\n# 后面的 prose = 也不是键\n"
            "# 也不是 = 键\n")
    assert commented_template_keys(text) == {("Opt", "first_key"), ("Opt", "second_key")}


def test_commented_template_scanner_sees_the_real_apikey_block():
    keys = commented_template_keys(EXAMPLES["site-builder"].read_text(encoding="utf-8"))
    assert {("ApiKey", "resource_server_id"), ("ApiKey", "scope"), ("ApiKey", "mcp_subdomain")} <= keys
    # 模板块外的 prose 里也有 `# xxx = …` 形态的句子（`# email_verified=true，…`、`# enabled = false 而…`），
    # 它们不许被当成键——否则守卫会对不存在的键报死。
    assert not any(k in ("email_verified", "enabled", "fixture_issuer") for _, k in keys), keys


def _reader(tmp_path, src: str, name: str = "reader.py") -> Reader:
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return Reader(p)


def test_fstrings_name_computed_keys_but_short_fragments_do_not(tmp_path):
    r = _reader(tmp_path, 'cur = cfg.get("SessionKeys", f"{fam}_current")\n'
                          'sect = f"SessionKey:{kid}"\n'
                          'alg = cfg.get(sect, "alg")\n'
                          'x = f"{a}_"\n')
    assert r.reads("SessionKeys", "site_current")
    assert r.reads("SessionKey:site-rs-v1", "alg")
    assert not r.reads("SessionKeys", "site_previous")
    assert not r.names("anything_"), "`f\"{a}_\"` 的片段不足 4 字符，不该点名任何东西"


def test_whole_section_reads_cover_every_key_of_that_section(tmp_path):
    r = _reader(tmp_path, 'tags = dict(cfg.items("Tags"))\nidp = dict(cfg["IdP"])\n'
                          'for k, v in cfg["Extra"].items():\n    pass\n')
    assert r.whole_sections == {"Tags", "IdP", "Extra"}
    ex = tmp_path / "e.example"
    ex.write_text("[Tags]\nproject = x\n[IdP]\nissuer = y\n[Extra]\nz = 1\n[Other]\nk = z\n",
                  encoding="utf-8")
    assert unread_keys(ex, [r]) == [("Other", "k")]


def test_section_and_key_must_be_named_by_the_same_file(tmp_path):
    """两个文件各点名一半不算：`"Panel"` 在 A、`"ops_log_table"` 在 B，说明没人把它们当一对读。"""
    a = _reader(tmp_path, 'x = cfg["Panel"]["console_version"]\n', "a.py")
    b = _reader(tmp_path, 'y = "ops_log_table"\n', "b.py")
    ex = tmp_path / "e.example"
    ex.write_text("[Panel]\nconsole_version =\nops_log_table = t\n", encoding="utf-8")
    assert unread_keys(ex, [a, b]) == [("Panel", "ops_log_table")]
