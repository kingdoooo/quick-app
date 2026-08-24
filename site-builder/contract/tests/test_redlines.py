import json
from pathlib import Path
import pytest
from contract import scan_redlines


def make_site(tmp_path: Path, *, tier="fullstack-sql", index="fetch('/api/items')",
              server="app.get('/api/health',(q,s)=>s.send('ok'))",
              schema="CREATE TABLE t (id UUID PRIMARY KEY);") -> tuple[Path, dict]:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/index.html").write_text(f"<script>{index}</script>")
    manifest = {"name": "t", "tier": tier,
                "database": {"engine": {"static": "none", "fullstack-nosql": "dynamodb",
                                        "fullstack-sql": "dsql"}[tier]},
                "auth": {"require_login": True, "allowed_users": "org"}}
    if tier != "static":
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend/server.js").write_text(server)
        manifest["backend"] = {"runtime": "nodejs22.x", "entrypoint": "node server.js", "port": 8080}
        if tier == "fullstack-sql":
            (tmp_path / "backend/schema.sql").write_text(schema)
    (tmp_path / "site.json").write_text(json.dumps(manifest))
    return tmp_path, manifest


def test_clean_site_passes(tmp_path):
    d, m = make_site(tmp_path)
    assert scan_redlines(d, m) == []


def test_localhost_in_frontend_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://localhost:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_hardcoded_api_host_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('https://foo.example.com/api/x')")
    assert any("绝对地址" in v for v in scan_redlines(d, m))


def test_auth_code_fails(tmp_path):
    d, m = make_site(tmp_path, server="const t=jwt.sign({u:1},'s'); app.get('/api/health',(q,s)=>s.send('ok'))")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_missing_health_fails(tmp_path):
    d, m = make_site(tmp_path, server="app.get('/api/items',(q,s)=>s.json([]))")
    assert any("/api/health" in v for v in scan_redlines(d, m))


def test_local_file_write_fails(tmp_path):
    d, m = make_site(tmp_path, server="fs.writeFileSync('/tmp/x','1'); app.get('/api/health',(q,s)=>s.send('ok'))")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_schema_forbidden_ddl_fails(tmp_path):
    d, m = make_site(tmp_path, schema="CREATE TABLE a (id SERIAL PRIMARY KEY, b INT REFERENCES x(id));")
    found = scan_redlines(d, m)
    assert any("SERIAL" in v for v in found) and any("REFERENCES" in v for v in found)


def test_missing_schema_for_sql_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/schema.sql").unlink()
    assert any("schema.sql" in v for v in scan_redlines(d, m))


def test_static_skips_backend_checks(tmp_path):
    d, m = make_site(tmp_path, tier="static")
    assert scan_redlines(d, m) == []


def test_innerhtml_assignment_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.innerHTML = userInput")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_textcontent_assignment_passes(tmp_path):
    d, m = make_site(tmp_path, index="el.textContent = x")
    assert scan_redlines(d, m) == []


# --- Critical 1: 写文件 API 覆盖不全 ---

HEALTH_OK = "app.get('/api/health',(q,s)=>s.send('ok'))"


def test_fs_promises_writefile_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"await fs.promises.writeFile('/tmp/x','1'); {HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_fs_promises_require_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"const {{writeFile}} = require('fs/promises'); {HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_fs_promises_import_single_quote_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"import {{ writeFile }} from 'fs/promises';\n{HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_fs_promises_import_double_quote_fails(tmp_path):
    d, m = make_site(tmp_path, server=f'import {{ writeFile }} from "fs/promises";\n{HEALTH_OK}')
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_create_write_stream_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"const s = fs.createWriteStream('/tmp/x'); {HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_append_file_sync_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"fs.appendFileSync('/tmp/x','1'); {HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


# --- Critical 2: Node auth 检测 ---

def test_jsonwebtoken_require_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"const jwt = require('jsonwebtoken'); {HEALTH_OK}")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_res_cookie_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"res.cookie('session', x); {HEALTH_OK}")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_set_cookie_header_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"res.setHeader('Set-Cookie', v); {HEALTH_OK}")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_express_session_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"const session = require('express-session'); {HEALTH_OK}")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


def test_cookie_session_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"app.use(require('cookie-session')({{}})); {HEALTH_OK}")
    assert any("auth" in v.lower() for v in scan_redlines(d, m))


# --- Important 3+4: 大小写与回环变体 ---

def test_localhost_uppercase_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('HTTP://LOCALHOST:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_ipv6_loopback_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://[::1]:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_loopback_127_variant_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://127.0.0.2:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_loopback_127_1_shorthand_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://127.1:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_zero_address_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('http://0.0.0.0:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_abs_api_uppercase_scheme_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('HTTPS://foo.example.com/api/x')")
    assert any("绝对地址" in v for v in scan_redlines(d, m))


def test_abs_api_uppercase_host_fails(tmp_path):
    d, m = make_site(tmp_path, index="fetch('https://FOO.com/api/x')")
    assert any("绝对地址" in v for v in scan_redlines(d, m))


# --- Important 5: XSS sink 补全 ---

def test_outerhtml_assignment_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.outerHTML = x")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_insert_adjacent_html_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.insertAdjacentHTML('beforeend', x)")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_document_write_fails(tmp_path):
    d, m = make_site(tmp_path, index="document.write(x)")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_innerhtml_concat_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.innerHTML += x")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_innerhtml_comparison_passes(tmp_path):
    d, m = make_site(tmp_path, index="if (el.innerHTML === '') { el.textContent = x }")
    assert scan_redlines(d, m) == []


def test_innerhtml_loose_comparison_passes(tmp_path):
    d, m = make_site(tmp_path, index="if (el.innerHTML == '') { el.textContent = x }")
    assert scan_redlines(d, m) == []


def test_node_prefix_fs_promises_import_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"import {{ writeFile }} from 'node:fs/promises';\n{HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_node_prefix_fs_promises_require_fails(tmp_path):
    d, m = make_site(tmp_path, server=f"const {{writeFile}} = require('node:fs/promises'); {HEALTH_OK}")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_document_writeln_fails(tmp_path):
    d, m = make_site(tmp_path, index="document.writeln(x)")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_innerhtml_nullish_assignment_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.innerHTML ??= x")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


def test_innerhtml_logical_or_assignment_fails(tmp_path):
    d, m = make_site(tmp_path, index="el.innerHTML ||= x")
    assert any("innerHTML" in v for v in scan_redlines(d, m))


# --- Important 6: 文件遍历健壮性 ---

def test_uppercase_extension_scanned(tmp_path):
    d, m = make_site(tmp_path)
    (d / "frontend/APP.JS").write_text("fetch('http://localhost:8080/api/x')")
    assert any("localhost" in v for v in scan_redlines(d, m))


def test_cjs_extension_scanned(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.cjs").write_text("const {writeFile} = require('fs/promises')")
    assert any("本地文件" in v for v in scan_redlines(d, m))


# --- Important 7: Python open() 写模式 ---

def test_python_open_wb_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'wb')")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_python_open_x_mode_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'x')")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_python_open_a_plus_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'a+')")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_python_open_wb_plus_fails(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'wb+')")
    assert any("本地文件" in v for v in scan_redlines(d, m))


def test_python_open_read_passes(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'r')\ng = open(path2, 'rb')")
    assert scan_redlines(d, m) == []


# --- x-user-name 必须解码（部署后实测：不解码会把 %E5%BD%AD… 存进数据） ---

def test_raw_x_user_name_without_decode_fails(tmp_path):
    """Edge 注入的 x-user-name 是 URL 编码的（HTTP 头不能携带非 ASCII）。

    站点直接使用会把 `%E5%BD%AD%E9%87%91%E5%86%AC` 这类编码串当成人名显示、
    甚至写进数据库——**症状不是报错而是静默脏数据**，所以必须在部署前拦下，
    不能靠站点作者记得（真实站点 team-kudos-wall 就漏了这一步）。
    """
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));"
        "const name = req.headers['x-user-name'] || '';"))
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_decoded_x_user_name_passes(tmp_path):
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));"
        "const name = decodeURIComponent(req.headers['x-user-name'] || '');"))
    assert scan_redlines(d, m) == []


def test_x_user_email_needs_no_decode(tmp_path):
    """只有 name 需要解码。email 是 ASCII，Edge 不编码它——
    要求解码 email 会制造无意义的红线（且解码 email 也无害，故不检查）。"""
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));"
        "const email = req.headers['x-user-email'] || 'anonymous';"))
    assert scan_redlines(d, m) == []


def test_x_user_name_decode_detected_across_quote_styles(tmp_path):
    """双引号/反引号/中括号换写法都要认得——只认一种等于没拦。"""
    for i, expr in enumerate(('req.headers["x-user-name"]',
                              "req.headers[`x-user-name`]",
                              "req.get('x-user-name')",
                              "headers['X-User-Name']")):
        d = tmp_path / f"case{i}"
        d.mkdir()
        site, m = make_site(d, server=(
            "app.get('/api/health',(q,s)=>s.send('ok'));"
            f"const n = {expr} || '';"))
        assert any("decodeURIComponent" in v for v in scan_redlines(site, m)), expr


def test_frontend_x_user_name_also_checked(tmp_path):
    """前端也可能拿到这个头（经后端透传到页面），同样要解码。"""
    d, m = make_site(tmp_path, index="const n = data['x-user-name'];")
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_commented_out_decode_does_not_satisfy_the_redline(tmp_path):
    """注释里的 decodeURIComponent( 不算解码（Codex 审查 2026-08-06 P2，已复现）。

    文件级判定原本用裸正则找 `decodeURIComponent(`，于是
    `// TODO: decodeURIComponent(raw)` 这行就能让整个文件过关，而实际代码里
    拿到的还是编码串。放宽到文件级是有意的（取值与解码常不在一行），但不能
    连"根本没调用"都放过。
    """
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));\n"
        "// TODO: decodeURIComponent(raw)\n"
        "const raw = req.headers['x-user-name'];\n"
        "store(raw);"))
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_string_literal_decode_does_not_satisfy_the_redline(tmp_path):
    """字符串里的伪调用同样不算——常见于日志文案。"""
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));\n"
        "log('记得 decodeURIComponent(name)');\n"
        "const n = req.headers['x-user-name'];"))
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_block_comment_decode_does_not_satisfy_the_redline(tmp_path):
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));\n"
        "/* decodeURIComponent(x) 见文档 */\n"
        "const n = req.headers['x-user-name'];"))
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_concatenated_header_name_is_detected(tmp_path):
    """拼接出的 header 名也要认出来（实测 `'x-user-' + 'name'` 能绕过）。

    完整的字符串求值不可能用正则做，但**拼接片段**是可穷举的常见写法：
    只要文件里同时出现 `x-user-` 与紧跟的 name 片段，就该要求解码。
    """
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));\n"
        "const h = 'x-user-' + 'name';\n"
        "store(req.headers[h]);"))
    assert any("decodeURIComponent" in v for v in scan_redlines(d, m))


def test_real_decode_still_passes_with_comments_around(tmp_path):
    """真调用 + 周围有注释时不能误报（否则合规站点被挡在部署外）。"""
    d, m = make_site(tmp_path, server=(
        "app.get('/api/health',(q,s)=>s.send('ok'));\n"
        "// x-user-name 是 URL 编码的\n"
        "const n = decodeURIComponent(req.headers['x-user-name'] || '');"))
    assert scan_redlines(d, m) == []


# ---- x-user-name：解码必须与这个头有关联（Codex 复审 2026-08-08 P2）----
# 原规则只要求"同文件存在任意 decodeURIComponent 调用"，于是解码一个**无关**
# 的值（req.query.q）就能让整个文件过关，而头值仍被原样使用——实测可绕过。
# 现在要求：同表达式解码，或解码承接该头的变量。

@pytest.mark.parametrize("desc,code", [
    ("解码的是无关值（Codex 复现）",
     "const raw = req.headers['x-user-name'];\n"
     "const q = decodeURIComponent(req.query.q);\nstore(raw);"),
    ("拼接头名 + 无关解码",
     "const raw = req.headers['x-user-' + 'name'];\n"
     "const q = decodeURIComponent(req.query.q);\nstore(raw);"),
    ("完全没解码", "const name = req.headers['x-user-name'] || '';"),
    ("只在注释里解码",
     "const raw = req.headers['x-user-name'];\n// decodeURIComponent(raw)"),
    ("前端取头未解码",
     "fetch('/api').then(r => r.headers.get('x-user-name'))"),
])
def test_user_name_unrelated_decode_is_rejected(desc, code):
    from contract.redlines import _check_user_name_decoded
    assert _check_user_name_decoded(code, Path("api/index.js")), desc


@pytest.mark.parametrize("desc,code", [
    ("同表达式解码",
     'const name = decodeURIComponent(req.headers["x-user-name"] || "");'),
    ("先存变量再解码（文档承诺支持）",
     "const raw = req.headers['x-user-name'];\n"
     "const name = decodeURIComponent(raw || '');"),
    ("嵌套调用（要求括号配平）",
     "const n = decodeURIComponent(String(req.headers['x-user-name']));"),
    ("拼接头名 + 变量解码",
     "const raw = req.headers['x-user-' + 'name'];\n"
     "const n = decodeURIComponent(raw);"),
    ("req.get 写法",
     "const raw = req.get('x-user-name');\nconst n = decodeURIComponent(raw);"),
    ("既解码无关值也解码了头",
     "const q = decodeURIComponent(req.query.q);\n"
     "const n = decodeURIComponent(req.headers['x-user-name']);"),
    ("头名大写", 'const n = decodeURIComponent(req.headers["X-User-Name"]);'),
])
def test_user_name_related_decode_is_accepted(desc, code):
    """合规写法一个都不能误报——误报会把站点挡在部署外，比漏报更容易被绕过规则。"""
    from contract.redlines import _check_user_name_decoded
    assert _check_user_name_decoded(code, Path("api/index.js")) == [], desc


# ---- 关联判定的误报与漏报（独立代码审查 2026-08-08）----
# 上一版把"解码必须与这个头关联"做出来了，但两头都过紧/过松：
#   · 误报：prettier 在 `=` 后折行、解构、裸赋值、属性存储、helper 封装、
#     实参里带正则字面量——六种**合规**写法被拦。误报会挡住真实用户的部署，
#     比漏报更该避免（还会逼人绕过规则），所以这些必须放行。
#   · 漏报：keep_header 原样保留含头名的注释/字符串，把 a9d4291 刚堵上的
#     注释绕过重新打开；`const q=..., name=头` 的多声明符会锚错变量。

@pytest.mark.parametrize("desc,code", [
    ("prettier 在 = 后折行",
     "const rawUserName =\n  req.headers['x-user-name'] || '';\n"
     "const n = decodeURIComponent(rawUserName);"),
    ("头名字面量独占一行",
     "const raw = req.headers[\n  'x-user-name'\n];\n"
     "const n = decodeURIComponent(raw);"),
    ("解构重命名",
     "const {'x-user-name': raw} = req.headers;\n"
     "const n = decodeURIComponent(raw);"),
    ("解构多个键",
     "const {'x-user-email': e, 'x-user-name': raw} = req.headers;\n"
     "const n = decodeURIComponent(raw);"),
    ("先声明后裸赋值",
     "let raw;\nraw = req.headers['x-user-name'];\n"
     "const n = decodeURIComponent(raw);"),
    ("存进属性",
     "req.userName = req.headers['x-user-name'];\n"
     "const n = decodeURIComponent(req.userName);"),
    ("helper 箭头函数封装解码",
     "const dec = v => decodeURIComponent(v || '');\n"
     "const n = dec(req.headers['x-user-name']);"),
    ("helper function 声明",
     "function dec(v) { return decodeURIComponent(v); }\n"
     "const n = dec(req.headers['x-user-name']);"),
    ("实参里含正则字面量（内含 //）",
     "const n = decodeURIComponent("
     "req.headers['x-user-name'].replace(/https?:\\/\\//g, ''));"),
    ("多声明符且确实解码了头",
     "const q = req.query.q, name = req.headers['x-user-name'];\n"
     "res.json({q, name: decodeURIComponent(name)});"),
])
def test_compliant_patterns_are_not_falsely_rejected(desc, code):
    from contract.redlines import _check_user_name_decoded
    assert _check_user_name_decoded(code, Path("api/index.js")) == [], desc


@pytest.mark.parametrize("desc,code", [
    ("注释里的解码提到了头名（a9d4291 回归）",
     "const raw = req.headers['x-user-name'];\n"
     "// TODO: decodeURIComponent(req.headers['x-user-name'])\n"
     "db.put({name: raw});"),
    ("JSDoc @example 里的解码",
     "const raw = req.headers['x-user-name'];\n"
     "/** @example decodeURIComponent(req.headers['x-user-name']) */\n"
     "db.put({name: raw});"),
    ("字符串里的解码提到了头名",
     "const raw = req.headers['x-user-name'];\n"
     "log(\"记得 decodeURIComponent(req.headers['x-user-name'])\");\n"
     "db.put({name: raw});"),
    ("模板串里的解码提到了头名",
     "const raw = req.headers['x-user-name'];\n"
     "log(`decodeURIComponent(req.headers['x-user-name'])`);\n"
     "db.put({name: raw});"),
    ("整个文件只有注释里的假解码",
     "x = h['x-user-name'];  // decodeURIComponent(h['x-user-name'])"),
    ("多声明符锚错变量：解码的是 q 不是头",
     "const q = req.query.q, name = req.headers['x-user-name'];\n"
     "res.json({q: decodeURIComponent(q), name});"),
])
def test_decode_not_associated_with_header_is_rejected(desc, code):
    from contract.redlines import _check_user_name_decoded
    assert _check_user_name_decoded(code, Path("api/index.js")), desc


def test_scanner_survives_malformed_input():
    """站点代码是不可信输入：畸形内容只能得出判定，不能崩、不能挂。"""
    from contract.redlines import _check_user_name_decoded
    for code in ("", "x-user-name\x00decodeURIComponent(",
                 "/* x-user-name decodeURIComponent(",
                 "decodeURIComponent(req.headers['x-user-name']" * 50,
                 "const n = " + "decodeURIComponent(" * 200
                 + "req.headers['x-user-name']" + ")" * 200,
                 "const raw = req.headers['x-user-name'];\r\n"
                 "const n = decodeURIComponent(raw);\r\n"):
        _check_user_name_decoded(code, Path("f.js"))   # 不抛异常即通过


def test_scanner_is_not_quadratic_on_large_files():
    """实参解析必须提到循环外。

    旧实现在"变量 × decode 调用"双重循环里反复做括号配平（最坏扫到文件末尾），
    3000 组调用要 22 秒；validate 那步 Lambda 超时 120 秒，大文件能把部署拖挂。
    这里用一个宽松上限做回归哨兵——只为抓住"又变成 O(n²)"，不追求精确计时。
    """
    import time
    from contract.redlines import _check_user_name_decoded
    code = ("const raw = req.headers['x-user-name'];\n"
            + "\n".join(f"const v{i} = decodeURIComponent(req.query.a{i});"
                        for i in range(3000)))
    start = time.monotonic()
    _check_user_name_decoded(code, Path("f.js"))
    assert time.monotonic() - start < 10, "疑似退化回 O(n²)"


# ── DSQL 建索引必须 ASYNC（真机踩过：站点因此从未上线）─────────────────

SYNC_INDEX_SQL = ("CREATE TABLE t (id UUID PRIMARY KEY, d DATE);\n"
                  "CREATE INDEX IF NOT EXISTS idx_d ON t (d);")
ASYNC_INDEX_SQL = ("CREATE TABLE t (id UUID PRIMARY KEY, d DATE);\n"
                   "CREATE INDEX ASYNC IF NOT EXISTS idx_d ON t (d);")


def test_sync_create_index_in_schema_fails(tmp_path):
    """同步 CREATE INDEX 必须在 validate 阶段被拦下。

    **这是真实事故的形态**：某站点的 schema.sql 写了三条普通
    `CREATE INDEX IF NOT EXISTS`，provision-db 阶段报
    `unsupported mode. please use CREATE INDEX ASYNC.`（FeatureNotSupported），
    首次部署失败 → 站点永久停在 DEPLOYING、无 route、URL 404。
    校验器当时不认识这条规则，所以平台接受了自己执行不了的 SQL。
    """
    d, m = make_site(tmp_path, schema=SYNC_INDEX_SQL)
    assert any("ASYNC" in v for v in scan_redlines(d, m)), (
        "同步建索引没被拦下——站点会在 provision-db 阶段失败")


def test_async_create_index_passes(tmp_path):
    """正确写法不得误报，否则用户没有可用的建索引方式。

    这条与上一条成对：只有"错的被拦、对的放行"同时成立，规则才是可用的。
    """
    d, m = make_site(tmp_path, schema=ASYNC_INDEX_SQL)
    assert scan_redlines(d, m) == [], (
        f"正确的 CREATE INDEX ASYNC 被误报: {scan_redlines(d, m)}")


@pytest.mark.parametrize("sql,should_fail", [
    ("CREATE INDEX i ON t (c);", True),
    ("CREATE UNIQUE INDEX i ON t (c);", True),
    ("create index i on t (c);", True),                    # 大小写不敏感
    ("CREATE  INDEX   i ON t (c);", True),                 # 多空格
    ("CREATE INDEX ASYNC i ON t (c);", False),
    ("CREATE UNIQUE INDEX ASYNC i ON t (c);", False),
    ("CREATE INDEX ASYNC IF NOT EXISTS i ON t (c);", False),  # DSQL 推荐的幂等写法
    ("create index async i on t (c);", False),
])
def test_index_rule_matrix(tmp_path, sql, should_fail):
    """逐形态锁定：UNIQUE、大小写、空白、IF NOT EXISTS 都要判对。

    只测一种写法的规则很容易被一个变体绕过（比如只认大写、或被 UNIQUE 打断）。
    """
    d, m = make_site(tmp_path,
                     schema="CREATE TABLE t (id UUID PRIMARY KEY, c TEXT);\n" + sql)
    hit = any("ASYNC" in v for v in scan_redlines(d, m))
    assert hit == should_fail, f"{sql!r} 命中={hit} 期望={should_fail}"


def test_sync_create_index_in_migrations_also_fails(tmp_path):
    """migrations/*.sql 与 schema.sql **同等对待**。

    `provision_dsql.py` 用同一个连接、同样逐条 execute 两者，所以同步建索引写在
    migrations 里一样会失败。只扫 schema.sql 会让人以为"挪到 migrations 就行"，
    而结果仍然是部署失败。
    """
    d, m = make_site(tmp_path)
    mig = d / "backend/migrations"
    mig.mkdir()
    (mig / "001_add_index.sql").write_text("CREATE INDEX idx_x ON t (c);")
    v = scan_redlines(d, m)
    assert any("ASYNC" in x and "001_add_index.sql" in x for x in v), (
        f"migrations 里的同步建索引没被拦下: {v}")


def test_migration_file_naming_matches_the_executor(tmp_path):
    """只扫执行器真会跑的文件名形态（`\\d{3}_*.sql`）。

    校验器比执行器多扫会误报（用户放了个 notes.sql 当笔记却被拦），
    少扫会漏（漏的那条到 provision-db 才炸）。两边口径必须一致。
    """
    d, m = make_site(tmp_path)
    mig = d / "backend/migrations"
    mig.mkdir()
    # 不符合命名约定 → 执行器不会跑它 → 校验器也不该报
    (mig / "scratch.sql").write_text("CREATE INDEX idx_x ON t (c);")
    assert not any("ASYNC" in x for x in scan_redlines(d, m)), (
        "执行器不会执行 scratch.sql，校验器却报了它")
    # 符合约定 → 两边都要认
    (mig / "002_real.sql").write_text("CREATE INDEX idx_y ON t (c);")
    assert any("ASYNC" in x for x in scan_redlines(d, m))


def test_missing_index_html_is_a_violation(tmp_path):
    """frontend/index.html 缺失必须被合同拦下（Codex 2026-08-18 P1-5B）。

    Edge 把页面请求固定改写为 /{static_prefix}{path}、对 / 补 index.html——
    缺它则首页**永久** 403（前端桶私有），而下游没有任何一步能发现：健康门只测
    后端，require_auth 站点的冒烟只断言 302。合同层（部署链最早、还没动任何
    资源的一步）是唯一正确的拦截点。
    """
    _, manifest = make_site(tmp_path)
    (tmp_path / "frontend/index.html").unlink()
    # 只放一个 CSS：非空目录 + 无 index.html，正是当时被放过的形态
    (tmp_path / "frontend/style.css").write_text("body{}")
    violations = scan_redlines(tmp_path, manifest)
    assert any("index.html" in v for v in violations), \
        f"只有 CSS、没有 index.html 的前端被放行了：{violations}"


def test_empty_index_html_is_a_violation(tmp_path):
    """空的 index.html 同样拦下：0 字节的首页与缺失只差一个状态码。"""
    _, manifest = make_site(tmp_path)
    (tmp_path / "frontend/index.html").write_text("")
    violations = scan_redlines(tmp_path, manifest)
    assert any("index.html" in v for v in violations)


def test_static_tier_also_requires_index_html(tmp_path):
    """static tier 一样要求：它更依赖 index.html（除了静态文件什么都没有）。"""
    _, manifest = make_site(tmp_path, tier="static")
    (tmp_path / "frontend/index.html").unlink()
    violations = scan_redlines(tmp_path, manifest)
    assert any("index.html" in v for v in violations)


def test_index_html_requirement_is_documented_in_the_agent_facing_contract():
    """校验器拦了、而给生成方 Agent 的合同文档没写 ⇒ Agent 只能靠报错自解释。

    改合同要同步三处（CLAUDE.md）：校验器（本包）、references/contract.md、
    fixtures（三个黄金样例本来就带 index.html）。本条锁文档那一处。
    """
    doc = (Path(__file__).parents[2] / "skills" / "site-builder" / "references"
           / "contract.md").read_text(encoding="utf-8")
    assert "frontend/index.html" in doc and "必须存在且非空" in doc, \
        "index.html 的合同要求没写进给 Agent 的 contract.md"


def test_table_name_charsets_are_documented_in_the_agent_facing_contract():
    """两个字符集必须写进给 Agent 的合同文档，且**期望值从代码真源推导**。

    改合同要同步三处（CLAUDE.md 的改动矩阵）：校验器（本包）、
    `references/contract.md`、fixtures。这条锁文档那一处——在此之前表名规则的文档
    同步纯属约定，没有任何守卫，改了正则而忘了改文档不会有人发现。

    **为什么必须从 `TABLE_NAME_RE.pattern` 推导而不是在测试里抄一份正则**：抄一份
    就失去了"改代码忘改文档会红"这个唯一有价值的性质（同
    `deployer/tests/test_common.py::test_reserved_prefixes_are_documented_…` 的理由）。

    **为什么切到具名小节内判、不做全文 substring**：全文判时 `[a-z][a-z0-9_-]{0,29}`
    会被 pk 那一行满足，于是"表名的正则文档漏了"照样绿——那正是同族守卫记录过的
    实测坑（多项凭空变绿）。

    Skill 文档是用户 `cp -r` 出去的快照、没有更新机制，所以它写错的代价不是"文档不
    好看"，而是 Agent 按旧规则生成、用户只能靠校验器报错自解释。
    """
    from pathlib import Path

    from contract.schema import ATTRIBUTE_NAME_RE, TABLE_NAME_RE

    doc = (Path(__file__).parents[2] / "skills" / "site-builder" / "references"
           / "contract.md").read_text(encoding="utf-8")
    anchor = "## 表名与属性名的字符集为什么不同"
    assert anchor in doc, f"合同文档里找不到 {anchor!r} 这一节——本条已空转"
    section = doc.split(anchor, 1)[1].split("\n## ", 1)[0]

    assert f"`{TABLE_NAME_RE.pattern}`" in section, (
        f"表名正则 {TABLE_NAME_RE.pattern!r} 没写进合同文档的那一节——"
        "改了校验器就要同步这里")
    assert f"`{ATTRIBUTE_NAME_RE.pattern}`" in section, (
        f"属性名正则 {ATTRIBUTE_NAME_RE.pattern!r} 没写进合同文档的那一节")
    # 光贴两个正则不够：Agent 需要知道**怎么改**，而它拿到的报错只有校验器那一条
    assert "_" in section and "连字符" in section, \
        "那一节没写清「用下划线代替连字符」这个可执行的修法"
