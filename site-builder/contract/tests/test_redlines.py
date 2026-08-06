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
