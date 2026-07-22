"""代码红线静态扫描——防 AI 生成不可部署/违反合同的代码。启发式，宁可误报不可漏报。"""
import re
from pathlib import Path

TEXT_EXT = {".html", ".htm", ".js", ".mjs", ".cjs", ".css", ".py", ".json", ".txt"}
LOCALHOST_RE = re.compile(
    r"localhost|127\.\d+\.\d+\.\d+|127\.1|0\.0\.0\.0|\[::1\]", re.I)
ABS_API_RE = re.compile(r"""["'`]https?://[^"'`]+/api/""", re.I)
AUTH_RE = re.compile(
    r"jwt\.sign|passport|OAuth2|client_secret|set_cookie\(.*session"
    r"|res\.cookie\(|Set-Cookie|jsonwebtoken|express-session|cookie-session", re.I)
FILE_WRITE_RE = re.compile(
    r"fs\.writeFile|fs\.appendFile|fs\.promises\.\w+|fs\.createWriteStream"
    r"|['\"]fs/promises['\"]"
    r"|open\([^)]*['\"][wax]\+?b?['\"]")
HEALTH_RE = re.compile(r"/api/health")
INNERHTML_RE = re.compile(
    r"(?:inner|outer)HTML\s*[+]?=(?!=)|insertAdjacentHTML\(|document\.write\(")
FORBIDDEN_DDL = ["REFERENCES", "SERIAL", "JSONB", "CREATE TRIGGER", "CREATE TEMP"]


def _read_all(root: Path) -> list[tuple[Path, str]]:
    out = []
    if root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in TEXT_EXT and "node_modules" not in p.parts:
                out.append((p, p.read_text(errors="replace")))
    return out


def scan_redlines(site_dir: Path, manifest: dict) -> list[str]:
    site_dir = Path(site_dir)
    violations: list[str] = []
    tier = manifest.get("tier")

    for p, text in _read_all(site_dir / "frontend"):
        rel = p.relative_to(site_dir)
        if LOCALHOST_RE.search(text):
            violations.append(f"{rel}: 前端禁止 localhost/127.0.0.1，API 一律相对路径 /api/*")
        if ABS_API_RE.search(text):
            violations.append(f"{rel}: 前端 API 调用禁止绝对地址，改为相对路径 /api/*")
        if INNERHTML_RE.search(text):
            violations.append(f"{rel}: 前端禁止 innerHTML 赋值/拼接（存储型 XSS 风险），改用 textContent 或安全模板")

    if tier == "static":
        return violations

    backend_dir = site_dir / "backend"
    backend_files = _read_all(backend_dir)
    backend_text = "\n".join(t for _, t in backend_files)
    for p, text in backend_files:
        rel = p.relative_to(site_dir)
        if AUTH_RE.search(text):
            violations.append(f"{rel}: 站点代码禁止自带 auth 逻辑（鉴权由平台边缘层统一处理）")
        if FILE_WRITE_RE.search(text):
            violations.append(f"{rel}: 禁止写本地文件（Lambda 文件系统只读）")
    if not HEALTH_RE.search(backend_text):
        violations.append("backend: 必须实现 GET /api/health 端点（部署冒烟测试依赖）")

    if manifest.get("database", {}).get("engine") == "dsql":
        schema = backend_dir / "schema.sql"
        if not schema.exists():
            violations.append("backend/schema.sql: fullstack-sql 必须提供建表 SQL")
        else:
            sql_upper = schema.read_text(errors="replace").upper()
            for kw in FORBIDDEN_DDL:
                if kw in sql_upper:
                    violations.append(f"backend/schema.sql: 含 DSQL 不支持的 {kw}（见红线文档替代方案）")
    return violations
