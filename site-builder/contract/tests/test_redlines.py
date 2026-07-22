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


def test_python_open_read_passes(tmp_path):
    d, m = make_site(tmp_path)
    (d / "backend/util.py").write_text("f = open(path, 'r')\ng = open(path2, 'rb')")
    assert scan_redlines(d, m) == []
