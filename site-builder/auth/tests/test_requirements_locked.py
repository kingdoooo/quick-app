"""auth 签发并校验会话 JWT，是身份层的 TCB；MCP 早已 --require-hashes。

本文件守两件事：清单里**每个包**都钉死版本且带 hash；以及装的时候真的
带上 `--require-hashes`——清单有 hash 但装时不校验等于什么都没做。

断言必须**逐包**判，不能判"文件里至少存在一个 hash"：后者对"某个传递依赖
漏了 hash"完全无感，而 `--require-hashes` 是全量语义（任何一个包缺 hash
就整条 pip install 失败），恰恰是漏掉的那个包决定成败。
"""
import ast
import io
import re
import tokenize
from pathlib import Path

# parents: [0]=tests [1]=auth [2]=site-builder（**不是 [3]，那是仓库根**）
AUTH_DIR = Path(__file__).parents[1]
AUTH_REQ = AUTH_DIR / "requirements.txt"
INFRA_DIR = Path(__file__).parents[2] / "deployer" / "infra"
BUNDLING_REQ = INFRA_DIR / "bundling-requirements.txt"
APP_PY = INFRA_DIR / "app.py"


def _strip_comments(src: str) -> str:
    """抹掉 Python 注释，保留其余字符与列位置。

    守卫要判的是**代码**：app.py 的注释里正写着 `/asset-input/../infra/…` 这个
    反面例子（那是本任务踩的坑，值得留在原地）。直接对全文做 substring/regex
    会被自己的说明文字判红，于是下一个人会去删注释而不是修代码。
    """
    cuts: dict[int, int] = {}
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            cuts[row] = min(cuts.get(row, col), col)
    return "\n".join(line[:cuts[i]] if i in cuts else line
                     for i, line in enumerate(src.splitlines(), start=1))


def _requirements(text: str) -> list[tuple[str, str | None, int]]:
    """锁定清单 → [(包名, 钉死的版本或 None, --hash 条数)]。

    **不带 `==` 的行也要收进来**（版本记 None）：只认 `==` 行的解析器会把
    `foo>=1.0` 静默跳过，于是"这个包既没钉版本也没 hash"在逐包断言下反而
    看不见——那正是本任务要防的形态。
    """
    rows: list[list] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.endswith("\\"):
            line = line[:-1].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            assert rows, f"孤立的 hash 行（前面没有 requirement）：{line}"
            rows[-1][2] += 1
        elif line.startswith("-"):
            continue  # --require-hashes / -r xxx 之类的选项行
        else:
            name = re.split(r"[<>=!~\[;]", line, maxsplit=1)[0].strip().lower()
            ver = line.split("==", 1)[1].strip() if "==" in line else None
            rows.append([name, ver, 0])
    return [(n, v, c) for n, v, c in rows]


def _assert_all_pinned_and_hashed(path: Path) -> set[str]:
    rows = _requirements(path.read_text())
    assert rows, f"{path.name} 里没有任何 requirement"
    for name, ver, n_hash in rows:
        assert ver, f"{name} 没有用 == 钉死版本（--require-hashes 会直接失败）"
        assert n_hash > 0, f"{name}=={ver} 没有 --hash（--require-hashes 会直接失败）"
    return {name for name, _, _ in rows}


def test_auth_every_package_is_pinned_and_hashed():
    names = _assert_all_pinned_and_hashed(AUTH_REQ)
    # pyjwt 是直接依赖；cryptography 是 [crypto] extra 必然拉进来的传递依赖
    # ——列它是为了确认清单覆盖了**传递闭包**而不只是顶层那一行。
    assert {"pyjwt", "cryptography"} <= names, f"缺直接/传递依赖：{names}"


def test_bundling_every_package_is_pinned_and_hashed():
    names = _assert_all_pinned_and_hashed(BUNDLING_REQ)
    # 两个都得在：bundling 那条 pip install 装的就是这两个顶层包，
    # 用交集判（"至少有一个"）会漏掉另一个没锁的那个。
    assert {"psycopg", "sqlparse"} <= names, f"缺 bundling 的顶层依赖：{names}"


def test_deploy_auth_installs_with_require_hashes():
    """--require-hashes 必须出现在 build_zip 的 pip 参数里。

    整文件 substring 判会被一行注释骗过，所以按 AST 取 build_zip 的源码段。
    """
    src = (AUTH_DIR / "deploy_auth.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "build_zip")
    body = ast.get_source_segment(src, fn)
    assert "--require-hashes" in body, "清单里有 hash 但装时不校验 = 什么都没做"


def test_bundling_lockfile_is_mounted_not_reached_via_asset_input_parent():
    """清单在容器里的路径必须真的挂进去了。

    `/asset-input` 挂的是 functions/，它在容器里的父目录是 `/`，不是宿主的
    infra/——`/asset-input/../infra/...` 在容器里根本不存在。这里不判具体
    写法，而是把命令里引用的清单路径与 volumes 的 containerPath 对起来：
    引用了没挂载的路径就红。
    """
    app = _strip_comments(APP_PY.read_text())
    mounted = set(re.findall(r'"containerPath":\s*"([^"]+)"', app))
    refs = set(re.findall(r"(/[\w./-]*bundling-requirements\.txt)", app))
    assert refs, "app.py 的 bundling 命令没有引用 bundling-requirements.txt"
    for ref in refs:
        assert any(ref.startswith(m.rstrip("/") + "/") for m in mounted), (
            f"{ref} 不在任何 containerPath({sorted(mounted)}) 之下："
            f"容器里没有这个文件，pip 会直接找不到清单")
    assert "--require-hashes" in app, "bundling 装依赖时没有校验 hash"
