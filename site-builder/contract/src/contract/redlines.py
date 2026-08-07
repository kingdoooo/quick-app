"""代码红线静态扫描——防 AI 生成不可部署/违反合同的代码。启发式，宁可误报不可漏报。"""
import json
import re
from pathlib import Path

TEXT_EXT = {".html", ".htm", ".js", ".mjs", ".cjs", ".css", ".py", ".json", ".txt",
            # 现代前端扩展名必须在列：遗漏会让 XSS/localhost 红线对 .ts/.vue
            # 之类文件完全失效（扫描器只按后缀取文件）
            ".ts", ".tsx", ".jsx", ".mts", ".cts", ".vue", ".svelte", ".sql"}
# npm 生命周期脚本在 CodeBuild 内以构建角色执行——buildspec 已 --ignore-scripts，
# 此处再拦一层并给出可读报错（纵深防御，且让违规在部署前就暴露）。
NPM_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
LOCALHOST_RE = re.compile(
    r"localhost|127\.\d+\.\d+\.\d+|127\.1|0\.0\.0\.0|\[::1\]", re.I)
ABS_API_RE = re.compile(r"""["'`]https?://[^"'`]+/api/""", re.I)
AUTH_RE = re.compile(
    r"jwt\.sign|passport|OAuth2|client_secret|set_cookie\(.*session"
    r"|res\.cookie\(|Set-Cookie|jsonwebtoken|express-session|cookie-session", re.I)
FILE_WRITE_RE = re.compile(
    r"fs\.writeFile|fs\.appendFile|fs\.promises\.\w+|fs\.createWriteStream"
    r"|['\"](?:node:)?fs/promises['\"]"
    r"|open\([^)]*['\"][wax][+b]{0,2}['\"]")
HEALTH_RE = re.compile(r"/api/health")
INNERHTML_RE = re.compile(
    r"(?:inner|outer)HTML\s*(?:[+]=|(?:\?\?|\|\|)=|=(?!=))"
    r"|insertAdjacentHTML\(|document\.write(?:ln)?\(")
FORBIDDEN_DDL = ["REFERENCES", "SERIAL", "JSONB", "CREATE TRIGGER", "CREATE TEMP"]
# Edge 注入的 x-user-name 是 **URL 编码**的（HTTP 头不能携带非 ASCII 字节——
# 不编码会让中文名字直接被 CloudFront 拒掉），站点必须 decodeURIComponent。
# 为什么值得一条红线：漏掉时**不报错**，而是把 `%E5%BD%AD…` 当人名显示、写库，
# 变成静默脏数据（真实站点 team-kudos-wall 就这样存了一批编码串，事后只能清洗）。
# 大小写都认：HTTP 头名不区分大小写，Express 的 req.get() 也不区分。
# 直接字面量，或 `'x-user-' + 'name'` 这类拼接（实测拼接能绕过纯字面量匹配）。
# 完整求值字符串不可能用正则做，但拼接片段是可穷举的常见写法。
X_USER_NAME_RE = re.compile(
    r"x-user-name"
    r"|x-user-['\"`]\s*\+\s*['\"`]name", re.I)
DECODE_RE = re.compile(r"decodeURIComponent\s*\(")
# 行注释 / 块注释 / 字符串字面量——判定解码调用前要先剥掉它们，否则
# `// TODO: decodeURIComponent(raw)` 或 `log('记得 decodeURIComponent(x)')`
# 就能让整个文件过关，而实际代码拿到的还是编码串（实测两种都能绕过）。
_COMMENTS_AND_STRINGS_RE = re.compile(
    r"//[^\n]*"           # 行注释
    r"|/\*.*?\*/"          # 块注释（跨行）
    r"|'(?:\\.|[^'\\\n])*'"   # 单引号字符串
    r'|"(?:\\.|[^"\\\n])*"'   # 双引号字符串
    r"|`(?:\\.|[^`\\])*`",     # 模板字符串（可跨行）
    re.S)


def _strip_comments_and_strings(text: str, keep_header: bool = False) -> str:
    """把注释与字符串字面量替换成等长空白，用于"这里真的有代码调用吗"的判断。

    等长替换（而不是删除）让行列位置不漂移，便于以后要报行号时复用。
    注意这是启发式的：正则解析 JS 不可能完全正确（正则字面量、嵌套模板等），
    但方向是安全的——**误删代码会导致误报（多拦一个站点），不会漏放**。

    keep_header=True：**只保留** x-user-name 这个头名的字符串字面量，其余照旧
    抹掉。判"解码的是不是这个头"必须同时看见代码结构与这个头名，而它总是写在
    字符串里；全抹掉就无从关联（注释里的假解码仍会被抹，所以不放松原有防线）。
    """
    def _blank(m: re.Match) -> str:
        s = m.group(0)
        if keep_header and X_USER_NAME_RE.search(s):
            # 保留这段字面量原样（它只可能是头名，不含可执行代码）
            return s
        return re.sub(r"\S", " ", s)

    if keep_header:
        # 拼接写法（`'x-user-' + 'name'`）的头名**跨两个字面量**，逐段判断时
        # 两段都不匹配，会被抹成 `[  +  ]` → 关联不上承接它的变量 → 合规代码
        # 被误报。所以先把整个拼接式规约成一个等价字面量，再走逐段保留。
        text = re.sub(
            r"['\"`]x-user-['\"`]\s*\+\s*['\"`]name['\"`]",
            lambda m: "'x-user-name'" + " " * (len(m.group(0)) - 14),
            text, flags=re.I)

    return _COMMENTS_AND_STRINGS_RE.sub(_blank, text)


# `const raw = req.headers['x-user-name']` / `let n = req.get("x-user-name")`
# —— 抓住承接头值的变量名，供"先存变量、后解码"这种合法写法放行。
_HEADER_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=[^;\n]*?"
    r"(?:x-user-name|x-user-['\"`]\s*\+\s*['\"`]name)", re.I)


def _balanced_arg(code: str, open_paren: int) -> str | None:
    """取 code[open_paren] 这个 '(' 到其配对 ')' 之间的实参文本。

    用括号配平而不是 `[^)]*`：实参里常有嵌套调用
    （`decodeURIComponent(String(req.headers['x-user-name']))`），非配平写法
    会在第一个 ')' 就截断，把合规代码判成违规。
    """
    depth = 0
    for i in range(open_paren, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1:i]
    return None      # 括号不配平（截断的文件）：交给调用方按未通过处理


def _read_all(root: Path) -> list[tuple[Path, str]]:
    out = []
    if root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in TEXT_EXT and "node_modules" not in p.parts:
                out.append((p, p.read_text(errors="replace")))
    return out


def _scan_package_json(text: str, rel: Path) -> list[str]:
    """拦 npm 生命周期脚本：它们在构建容器内以 CodeBuild 角色凭证执行。"""
    try:
        pkg = json.loads(text)
    except ValueError:
        return [f"{rel}: package.json 不是合法 JSON"]
    if not isinstance(pkg, dict):
        return [f"{rel}: package.json 顶层必须为对象"]
    scripts = pkg.get("scripts")
    if not isinstance(scripts, dict):
        return []
    found = sorted(k for k in scripts if k.lower() in NPM_LIFECYCLE_KEYS)
    if found:
        return [f"{rel}: 禁止 npm 生命周期脚本 {found}（依赖安装阶段会执行任意命令）"]
    return []


def _check_user_name_decoded(text: str, rel: Path) -> list[str]:
    """用了 x-user-name 就必须**对它**调 decodeURIComponent。

    判定分两步（原来只做第一步的"同文件存在任意解码调用"，代价是
    `decodeURIComponent(req.query.q)` 这种**与本头无关**的解码就能让整个文件
    过关，而 x-user-name 仍被原样使用——实测可绕过，Codex 复审 2026-08-08）：

      ① 同一表达式里解码：`decodeURIComponent(req.headers['x-user-name'])`
         （允许中间夹 `|| ""`、`as string`、`?? ''` 等）；
      ② 先存变量再解码：`const raw = req.headers['x-user-name']` 之后出现
         `decodeURIComponent(... raw ...)`。变量名从赋值语句里提取。

    两者都不成立才报错。仍**按文件**判定（解码可以在别处），只是要求解码的
    对象与这个头有可见的关联，而不是文件里随便有个解码调用。
    """
    if not X_USER_NAME_RE.search(text):
        return []
    err = [f"{rel}: 用了 x-user-name 但没有对它 decodeURIComponent —— 该头是 "
           "URL 编码的（HTTP 头不能携带中文），不解码会把 %E5%BD%AD 这类 "
           "编码串当成用户名显示或写库（静默脏数据，不会报错）。"
           "注意：解码别的东西（如 req.query.x）不算——必须解码这个头的值"]
    # 解码调用必须在**剥掉注释与字符串之后**仍然存在，才算真的调用了。
    # 但头名要在原文里找（它总是写在字符串里，剥掉就找不到了），所以这里
    # 用"把字符串内容替换成占位符、保留结构"的方式：既能识别 decode 调用，
    # 也能看到 decode 的实参里有没有这个头 / 这个变量。
    code = _strip_comments_and_strings(text, keep_header=True)
    if not DECODE_RE.search(code):
        return err
    # ① 同表达式：decodeURIComponent( ... x-user-name ... )
    for m in DECODE_RE.finditer(code):
        arg = _balanced_arg(code, m.end() - 1)
        if arg is not None and X_USER_NAME_RE.search(arg):
            return []
    # ② 变量中转：先把头存进变量，再解码那个变量
    for var in _HEADER_ASSIGN_RE.findall(code):
        for m in DECODE_RE.finditer(code):
            arg = _balanced_arg(code, m.end() - 1)
            if arg is not None and re.search(
                    r"\b%s\b" % re.escape(var), arg):
                return []
    return err


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
        violations += _check_user_name_decoded(text, rel)

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
        violations += _check_user_name_decoded(text, rel)
        if p.name == "package.json":
            violations += _scan_package_json(text, rel)
    if (backend_dir / ".npmrc").exists():
        violations.append("backend/.npmrc: 禁止自带 .npmrc（可改 registry 拉入恶意包）")
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
