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
# ── 红线 8：后端依赖锁定 ─────────────────────────────────────────────────
# buildspec 用 `npm ci`：没有 lockfile、或 lockfile 与 package.json 不一致，它直接失败——
# 但那发生在 provision-db 之后。合同层在 validate 就要求 backend/package-lock.json 存在、
# 可解析、且每一个包都钉到 registry + integrity，并把报错写成一行修法。
#
# 为什么要看 `resolved` 的主机：它是 npm ci 实际下载的地址，删 `.npmrc` 管不到它——指向任意
# tarball 的 lockfile 是另一条"改 registry 拉恶意包"的路。allowlist 主机 + 必带 sha512
# `integrity` 两条一起才构成"这份字节 ⇒ 这棵依赖树"。采用者用私有镜像时改这个常量，并同步
# `skills/site-builder/references/redlines.md`（有用例按本常量核对文档）。
NPM_REGISTRY_URL_PREFIXES = ("https://registry.npmjs.org/",)
# npm 7+ 写的 v2/v3 都带 `packages` 映射（键是 node_modules/… 路径）；v1（npm 6）只有嵌套
# 的 `dependencies` 树，字段形态不同，不支持——让用户用新 npm 重新生成比再写一套解析器可靠。
LOCKFILE_VERSIONS = (2, 3)
_SRI_SHA512_RE = re.compile(r"\bsha512-[A-Za-z0-9+/]+={0,2}")
# package.json 的依赖规格只许 semver 范围 / dist-tag。`file:` / `git+ssh://` / `github:u/r` /
# `u/r` / `https://…tgz` / `npm:alias@x` / `link:` 都含 `:` 或 `/`，一条判据全拒：它们要么装
# 本地字节（lockfile 里是 link，不可复现），要么绕开 registry allowlist。
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LOCKFILE_REGEN_HINT = ("（在 backend/ 下用 npm ≥ 7 跑 "
                       "`npm install --package-lock-only --registry=https://registry.npmjs.org/`"
                       " 重新生成）")
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
# 这些在 DSQL 上确实不可用，DDL 会在 provision-db 阶段失败。
#
# **`JSONB` 的理由与其它几项不同**（2026-08-10 真机实测，改动前先读完）：
#   · 数据层**可用**：jsonb 列、`@>` `?` `->>` `#>`、jsonb_set/jsonb_agg 等，
#     以非 admin 的 per-site role 身份也全部通过。所以"DSQL 不支持 JSONB"是错的。
#   · 但 **GIN 索引不支持**：`... USING GIN (col)` 报
#     `USING not supported for CREATE INDEX`；实测 `@>` 查询走**全表扫描 + Filter**。
#   · 即：**可用但不可索引**。禁用它是为了不让站点误以为 jsonb 能加速内容过滤——
#     数据量一大就是全表扫。要按内容过滤的字段应该**提成独立列**（可建普通索引）。
# 若将来要放开：先真机复测 GIN 是否已支持，再同步 skills 的 redlines.md +
# 加一个用 jsonb 的 fixture。别只删这一项——那样文档与校验器会打架。
FORBIDDEN_DDL = ["REFERENCES", "SERIAL", "JSONB", "CREATE TRIGGER", "CREATE TEMP"]
# DSQL **不支持同步建索引**：`CREATE INDEX` 必须写成 `CREATE INDEX ASYNC`，
# 否则 provision-db 阶段报 `unsupported mode. please use CREATE INDEX ASYNC.`
# （FeatureNotSupported）。真机踩过：站点 returns-dashboard 的 schema.sql 写了三条
# 普通 CREATE INDEX，首次部署在 provision-db 失败，站点从未上线。
#
# 为什么单独一条规则而不是塞进 FORBIDDEN_DDL：那份清单是"整个特性不可用"（如
# SERIAL 没有替代语法），而索引是**可用的、只是要换关键字**。两者给用户的
# 提示完全不同——前者要改设计，后者加一个词就行。
#
# 匹配口径：`CREATE [UNIQUE] INDEX` 后面紧跟的必须是 `ASYNC`。允许
# `IF NOT EXISTS`（DSQL 支持且推荐用于幂等），所以 ASYNC 出现在它之前。
CREATE_INDEX_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?!\s+ASYNC\b)", re.IGNORECASE)
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
    # **正则字面量必须排在行注释之前**：`/https?:\/\//g` 里的 `\/\/` 会被
    # `//[^\n]*` 当成行注释、把整行剩余部分抹掉，于是 decode 的实参被截断、
    # 合规代码被误判违规（旧规则只要求"存在解码调用"，感觉不到；新规则要看
    # 实参内容，这个既有的不精确就变成了误报）。
    # 只认"前面紧邻着能让 `/` 起始正则的符号"这种保守形态，避免把除法当正则。
    r"(?<=[=(,:\[!&|?{};+\-*%~^<>])\s*/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+/[a-z]*"
    r"|//[^\n]*"           # 行注释
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

    keep_header=True：含 x-user-name 的注释/字符串**不原样保留**，而是替换成
    "只剩这个头名、其余全为空白"的等长文本。判"解码的是不是这个头"需要看见
    这个头名（它总写在字符串里，全抹掉就无从关联），但**绝不能连带保留同一段
    注释里的代码文本**——原样保留会让
        // TODO: decodeURIComponent(req.headers['x-user-name'])
    整段存活，既满足 DECODE_RE 又满足关联判定，于是文件里没有任何真实解码也能
    过关。那正是上一个提交（a9d4291）刚堵掉的注释绕过，原样保留等于把它重新打开
    （已实测；独立审查发现）。所以只回填头名本身，注释里的假解码照旧被抹掉。
    """
    # 头名字面量的规范形式：只回填它，长度不足的部分补空白（保持等长）
    _HDR = "'x-user-name'"

    def _blank(m: re.Match) -> str:
        s = m.group(0)
        if keep_header and X_USER_NAME_RE.search(s) and len(s) >= len(_HDR):
            # 只留头名，其余（包括同段注释里的 decodeURIComponent 字样）抹白。
            # 保持换行：跨行的块注释/模板串抹平会让行号漂移。
            tail = re.sub(r"[^\n]", " ", s[len(_HDR):])
            return _HDR + tail
        return re.sub(r"[^\n]", " ", s)

    if keep_header:
        # 拼接写法（`'x-user-' + 'name'`）的头名**跨两个字面量**，逐段判断时
        # 两段都不匹配，会被抹成 `[  +  ]` → 关联不上承接它的变量 → 合规代码
        # 被误报。所以先把整个拼接式规约成一个等价字面量，再走逐段处理。
        # 用 len(_HDR) 而不是硬编码数字：写死 14 时实际长度是 13，每处少一个
        # 字符、且会吃掉拼接式里的换行（行号漂移）。
        text = re.sub(
            r"['\"`]x-user-['\"`]\s*\+\s*['\"`]name['\"`]",
            lambda m: _HDR + re.sub(r"[^\n]", " ", m.group(0)[len(_HDR):]),
            text, flags=re.I)

    return _COMMENTS_AND_STRINGS_RE.sub(_blank, text)


# 抓住"承接头值"的名字，供"先存变量、后解码"这种合法写法放行。
# 三种赋值目标都要认，否则合规代码被误拦——**误报比漏报更该避免**：它挡住真实
# 用户的部署，且会逼人绕过规则。实测被旧写法误拦的合规形态见 tests。
#   ① 声明：const/let/var raw = … 'x-user-name'
#   ② 裸赋值 / 属性存储：raw = …  /  req.userName = …
#   ③ 解构重命名：const {'x-user-name': raw} = req.headers
#
# **不能用 `[^;\n]*?`**：prettier 在 `=` 后折行（80 列）会切断关联，而那是最
# 常见的写法。改成允许跨行，用 `;` 与长度上限兜住，不至于蔓延到整个文件。
_HEADER_ASSIGN_PATTERNS = (
    # 解构重命名放最前：它的 `键: 变量` 形态与②的宽松式会互相干扰
    re.compile(r"['\"`]x-user-name['\"`]\s*\]?\s*:\s*([A-Za-z_$][\w$]*)", re.I),
    # **`[^;]` 里要排除逗号**，否则 `const q = req.query.q, name = 头` 会锚在
    # 第一个声明符 `q` 上：解码 q 就被当成解码了这个头，而头值原样使用——与本
    # 规则要修的绕过同形（独立审查发现）。逗号是声明符边界，必须停在那里。
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=[^;,]{0,400}?"
               r"(?:x-user-name|x-user-['\"`]\s*\+\s*['\"`]name)", re.I | re.S),
    # 裸赋值与属性存储：`raw =` / `req.userName =` / `this.name =`
    re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=[^;=,]{0,400}?"
               r"(?:x-user-name|x-user-['\"`]\s*\+\s*['\"`]name)", re.I | re.S),
)


# 把解码包装成工具函数的名字：`const dec = v => decodeURIComponent(...)` /
# `function dec(v) { … decodeURIComponent(…) }` / `const dec = function(v){…}`。
# 只要求"名字与 decodeURIComponent 在同一个短距离窗口内"——不做作用域分析，
# 目的仍是区分"知道要解码"与"完全不知道"。
_DECODING_HELPER_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)"
    r"[^;]{0,200}?decodeURIComponent\s*\(", re.S)


def _decoding_helper_names(code: str) -> set[str]:
    return {n for pair in _DECODING_HELPER_RE.findall(code)
            for n in pair if n}


def _header_holder_names(code: str) -> set[str]:
    """所有承接过 x-user-name 的名字（变量名，或 `a.b` 形态的属性路径）。

    属性路径连末段一起收（`req.userName` → 也收 `userName`）：解码处可能用解构
    后的短名。宁可多收几个名字，也不要把合规写法拦下来——这条红线要防的是
    "完全不知道需要解码"，不是做精确的数据流分析。
    """
    names: set[str] = set()
    for pat in _HEADER_ASSIGN_PATTERNS:
        for m in pat.finditer(code):
            name = m.group(1)
            names.add(name)
            if "." in name:
                names.add(name.rsplit(".", 1)[-1])
    return names


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


def _dep_map(pkg: dict, section: str) -> dict:
    v = pkg.get(section)
    return v if isinstance(v, dict) else {}


def _scan_dependency_specs(pkg: dict, rel: Path) -> list[str]:
    """package.json 四个依赖段的规格只许 registry 形态（semver 范围 / dist-tag）。"""
    out: list[str] = []
    for section in _DEP_SECTIONS:
        for name, spec in _dep_map(pkg, section).items():
            if not isinstance(spec, str) or ":" in spec or "/" in spec:
                out.append(f"{rel}: {section}.{name} 的规格 {spec!r} 不是 registry 依赖"
                           "（禁止 file:/link:/git/URL/别名规格——它们绕开锁定与 registry 校验）")
    return out


def _scan_package_json(text: str, rel: Path) -> list[str]:
    """拦 npm 生命周期脚本（在构建容器内以 CodeBuild 角色凭证执行）与非 registry 依赖规格。"""
    try:
        pkg = json.loads(text)
    except ValueError:
        return [f"{rel}: package.json 不是合法 JSON"]
    if not isinstance(pkg, dict):
        return [f"{rel}: package.json 顶层必须为对象"]
    out: list[str] = []
    scripts = pkg.get("scripts")
    if isinstance(scripts, dict):
        found = sorted(k for k in scripts if k.lower() in NPM_LIFECYCLE_KEYS)
        if found:
            out.append(f"{rel}: 禁止 npm 生命周期脚本 {found}（依赖安装阶段会执行任意命令）")
    return out + _scan_dependency_specs(pkg, rel)


def _scan_package_lock(text: str, rel: Path, pkg_text: str | None) -> list[str]:
    """package-lock.json 必须钉住每一个包：registry 主机 allowlist + sha512 integrity，
    且与同目录 package.json 的依赖声明一致。

    只看 v2/v3 的 `packages` 映射；根条目 `""` 是 package.json 的镜像（npm 原样写入四个
    依赖段），拿它做一致性比对。`inBundle` 的包随父 tarball 分发、没有自己的 resolved /
    integrity，是唯一放行的缺省形态。
    """
    try:
        lock = json.loads(text)
    except ValueError:
        return [f"{rel}: package-lock.json 不是合法 JSON{LOCKFILE_REGEN_HINT}"]
    if not isinstance(lock, dict):
        return [f"{rel}: package-lock.json 顶层必须为对象{LOCKFILE_REGEN_HINT}"]
    if lock.get("lockfileVersion") not in LOCKFILE_VERSIONS:
        return [f"{rel}: lockfileVersion 必须是 {list(LOCKFILE_VERSIONS)} 之一，"
                f"得到 {lock.get('lockfileVersion')!r}{LOCKFILE_REGEN_HINT}"]
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        return [f'{rel}: package-lock.json 缺少 packages[""] 根条目{LOCKFILE_REGEN_HINT}']
    out: list[str] = []
    for key, entry in sorted(packages.items()):
        if key == "":
            continue
        if not isinstance(entry, dict):
            out.append(f"{rel}: packages[{key!r}] 必须为对象")
            continue
        if not key.startswith("node_modules/") or entry.get("link") is True:
            out.append(f"{rel}: packages[{key!r}] 不是从 registry 安装的包"
                       f"（workspace / file: / link 依赖不可复现，禁止）{LOCKFILE_REGEN_HINT}")
            continue
        if entry.get("inBundle") is True:
            continue
        resolved = entry.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(NPM_REGISTRY_URL_PREFIXES):
            out.append(f"{rel}: packages[{key!r}].resolved 必须以 "
                       f"{' / '.join(NPM_REGISTRY_URL_PREFIXES)} 开头，得到 {resolved!r}"
                       f"（其它 registry/镜像/任意 URL 一律拒绝；私有镜像生成的 lockfile 要对公共 registry 重新生成）"
                       f"{LOCKFILE_REGEN_HINT}")
        integrity = entry.get("integrity")
        if not isinstance(integrity, str) or not _SRI_SHA512_RE.search(integrity):
            out.append(f"{rel}: packages[{key!r}].integrity 缺少 sha512{LOCKFILE_REGEN_HINT}")
    if pkg_text is None:
        out.append(f"{rel}: 同目录没有 package.json——npm ci 需要两者同在")
        return out
    try:
        pkg = json.loads(pkg_text)
    except ValueError:
        return out      # package.json 自己那条已由 _scan_package_json 报
    if isinstance(pkg, dict):
        root = packages[""]
        for section in _DEP_SECTIONS:
            if _dep_map(pkg, section) != _dep_map(root, section):
                out.append(f'{rel}: packages[""].{section} 与 package.json 不一致——'
                           f"改了 package.json 之后要重新生成 lockfile{LOCKFILE_REGEN_HINT}")
    return out


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
    # **每个 decode 的实参只解析一次**：原来在"变量 × decode 调用"的双重循环里
    # 反复调 _balanced_arg，而它最坏会扫到文件末尾 → O(n²)。实测 3000 组调用
    # （约 287KB 单文件）要 22 秒，而 validate 这步的 Lambda 超时是 120 秒，
    # 大文件有把整个部署拖到超时的风险。提出来后是线性的。
    args = [a for a in (_balanced_arg(code, m.end() - 1)
                        for m in DECODE_RE.finditer(code)) if a is not None]
    # ① 同表达式：decodeURIComponent( ... x-user-name ... )
    if any(X_USER_NAME_RE.search(a) for a in args):
        return []
    # ② 变量中转：先把头存进某个名字，再解码那个名字
    holders = _header_holder_names(code)
    holder_re = re.compile(
        r"\b(?:%s)\b" % "|".join(sorted(map(re.escape, holders)))
    ) if holders else None
    if holder_re is not None:
        if any(holder_re.search(a) for a in args):
            return []
    # ③ helper 间接：`const dec = v => decodeURIComponent(v)` 之后
    #    `dec(req.headers['x-user-name'])`。把"函数体里调了 decode"的 helper
    #    名字收集起来，再看有没有拿这个头去调它。
    #    合规写法（把解码封装成工具函数）很常见，不放行等于逼人内联。
    for helper in _decoding_helper_names(code):
        for m in re.finditer(r"\b%s\s*\(" % re.escape(helper), code):
            arg = _balanced_arg(code, m.end() - 1)
            if arg is not None and (
                    X_USER_NAME_RE.search(arg)
                    or (holder_re is not None and holder_re.search(arg))):
                return []
    return err


def scan_redlines(site_dir: Path, manifest: dict) -> list[str]:
    site_dir = Path(site_dir)
    violations: list[str] = []
    tier = manifest.get("tier")

    # **frontend/index.html 必须存在且非空**（Codex 2026-08-18 P1-5B）。
    # 这不是风格约定：Edge 把页面请求固定改写为 `/{static_prefix}{path}`、
    # 对 `/` 补 `index.html`，缺它则站点首页**永久** 403（前端桶私有，
    # "没这个对象"就是 403 而不是 404）。而这一缺陷没有任何下游能拦：
    # 健康门只测后端、require_auth 站点的冒烟只断言 302——部署会被标成
    # SUCCEEDED，等 Edge 缓存过期整站才坏。所以在合同层拦下（部署链最早、
    # 还没动任何资源的一步）。三处同步：本校验器、references/contract.md、
    # fixtures（三个黄金样例本来就都带 index.html）。
    index = site_dir / "frontend" / "index.html"
    if not index.is_file() or index.stat().st_size == 0:
        violations.append(
            "frontend/index.html 缺失或为空：站点首页由 Edge 固定取"
            "该文件（/ → /{prefix}/index.html），没有它首页永久 403")

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
    texts = {p: t for p, t in backend_files}
    # lockfile 不是站点代码：不进 HEALTH_RE 的合并文本，也不走下面的泛用正则（几十 KB 的
    # 包名 / URL 上那些正则只会制造误报，且对 auth / 写文件红线没有信息量——站点自己依赖了
    # 什么，package.json 文本里就有）。它只走 _scan_package_lock。
    backend_text = "\n".join(t for p, t in backend_files if p.name != "package-lock.json")
    for p, text in backend_files:
        rel = p.relative_to(site_dir)
        if p.name == "package-lock.json":
            violations += _scan_package_lock(text, rel, texts.get(p.parent / "package.json"))
            continue
        if AUTH_RE.search(text):
            violations.append(f"{rel}: 站点代码禁止自带 auth 逻辑（鉴权由平台边缘层统一处理）")
        if FILE_WRITE_RE.search(text):
            violations.append(f"{rel}: 禁止写本地文件（Lambda 文件系统只读）")
        violations += _check_user_name_decoded(text, rel)
        if p.name == "package.json":
            violations += _scan_package_json(text, rel)
    # npm ci 的两个前提：package.json 与 package-lock.json 同在 backend/ 根。缺任一它在
    # package 阶段才失败（provision-db 之后）；这里提前到 validate 并给出修法。
    for name in ("package.json", "package-lock.json"):
        if not (backend_dir / name).is_file():
            violations.append(f"backend/{name} 缺失：后端依赖必须锁定，构建用 npm ci"
                              f"{LOCKFILE_REGEN_HINT}")
    if (backend_dir / "npm-shrinkwrap.json").exists():
        violations.append("backend/npm-shrinkwrap.json: 禁止——npm ci 会优先读它、跳过"
                          "被校验的 package-lock.json")
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
        # 索引规则对 schema.sql 与 migrations/*.sql **一视同仁**：
        # provision_dsql.py 用同一个连接、同样逐条 execute 两者，所以同步建索引
        # 在哪个文件里都会失败。只扫 schema.sql 会让"写进 migrations 就能绕过"
        # ——而绕过的结果是部署失败，不是绕过成功。
        for sql_file in _dsql_sql_files(backend_dir):
            rel = sql_file.relative_to(backend_dir.parent).as_posix()
            body = sql_file.read_text(errors="replace")
            if CREATE_INDEX_RE.search(body):
                violations.append(
                    f"{rel}: DSQL 建索引必须写 CREATE INDEX ASYNC"
                    "（同步建索引报 unsupported mode，站点会部署失败）")
    return violations


def _dsql_sql_files(backend_dir):
    """schema.sql + migrations/ 下按约定命名的迁移文件。

    命名口径与 `provision_dsql.py` 的 `^\\d{3}_.+\\.sql$` **保持一致**——执行器
    只跑符合该形态的文件，校验器多扫或少扫都会与真实行为不符。
    """
    out = []
    schema = backend_dir / "schema.sql"
    if schema.exists():
        out.append(schema)
    migrations = backend_dir / "migrations"
    if migrations.is_dir():
        out += sorted(p for p in migrations.glob("*.sql")
                      if re.match(r"^\d{3}_.+\.sql$", p.name))
    return out
