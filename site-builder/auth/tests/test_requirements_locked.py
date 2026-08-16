"""auth 签发并校验会话 JWT，是身份层的 TCB；MCP 早已 --require-hashes。

本文件守两件事：清单里**每个包**都钉死版本且带 hash；以及装的时候真的
带上 `--require-hashes`——清单有 hash 但装时不校验等于什么都没做。

断言必须**逐包**判，不能判"文件里至少存在一个 hash"：后者对"某个传递依赖
漏了 hash"完全无感，而 `--require-hashes` 是全量语义（任何一个包缺 hash
就整条 pip install 失败），恰恰是漏掉的那个包决定成败。
"""
import ast
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

# parents: [0]=tests [1]=auth [2]=site-builder（**不是 [3]，那是仓库根**）
AUTH_DIR = Path(__file__).parents[1]
AUTH_REQ = AUTH_DIR / "requirements.txt"
INFRA_DIR = Path(__file__).parents[2] / "deployer" / "infra"
BUNDLING_REQ = INFRA_DIR / "bundling-requirements.txt"
APP_PY = INFRA_DIR / "app.py"
# deploy_auth 在**模块级**读 config.ini（gitignored），缺它时 import 就 KeyError。
# 只有真要 import 它的那条用例受影响，所以在那条上单独 skip，不影响其余三条。
CONFIG = Path(__file__).parents[2] / "config.ini"


def _str_consts(node: ast.AST) -> list[str]:
    """按源码顺序取出一个节点里的字符串字面量（f-string 的常量段也算）。"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [s for v in node.values for s in _str_consts(v)]
    return []


def _bundling_specs(src: str) -> list[tuple[str, set[str]]]:
    """app.py 里每个 bundling 配置 → (命令串, 挂载的 containerPath 集合)。

    **走 AST 而不是全文 regex**：ast 天生不含注释，所以"命令里有没有那个开关"
    是纯粹的代码事实，注释既不能满足断言也不能把它判红。全文 substring 还有
    第二个毛病——app.py 里任何**别的** pip 调用带上开关都能让断言变绿，而我们
    要判的是它作用在**装锁定清单那一条**上。
    """
    specs = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Dict):
            continue
        pairs = {k.value: v for k, v in zip(node.keys, node.values)
                 if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if not {"command", "volumes"} <= set(pairs):
            continue
        # 元素**之间**用空格接（它们是独立的 argv 项），元素**内部**的相邻字面量
        # 必须直接相连——那是 Python 的隐式拼接语义，中间塞空格会把路径拆坏。
        cmd = " ".join("".join(_str_consts(el)) for el in pairs["command"].elts)
        mounts = set()
        for vol in pairs["volumes"].elts:
            vp = {k.value: v for k, v in zip(vol.keys, vol.values)
                  if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            cp = vp.get("containerPath")
            if isinstance(cp, ast.Constant):
                mounts.add(cp.value)
        specs.append((" ".join(cmd.split()), mounts))
    return specs


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


@pytest.mark.skipif(not CONFIG.exists(),
                    reason="deploy_auth 模块级读 site-builder/config.ini")
def test_deploy_auth_installs_with_require_hashes():
    """开关必须**真的到达 pip**，不是"源码里写着这四个字"。

    截获 build_zip 真正传给 subprocess.run 的 argv 来判。上一版按
    `ast.get_source_segment` 取 build_zip 的源码段做 substring —— 那段源码
    **含注释**，于是我为解释这个开关写的那行注释自己就把断言满足了：把 argv
    里的 `"--require-hashes",` 整条删掉，四条测试照样全绿，而部署会静默地
    不校验 hash 就发出去（M7 fix round 1 实测）。
    """
    import deploy_auth

    captured = []

    def fake_run(argv, *a, **kw):
        captured.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    with patch.object(deploy_auth.subprocess, "run", fake_run):
        deploy_auth.build_zip()
    assert len(captured) == 1, f"build_zip 应当只调一次 pip，实际 {len(captured)} 次"
    argv = captured[0]
    assert "--require-hashes" in argv, (
        f"--require-hashes 不在真正传给 pip 的参数里 = 清单有 hash 也白搭：{argv}")
    # 开关要作用在**这一次** `-r <清单>` 安装上，不是漂在别处
    assert argv.index("--require-hashes") < argv.index("-r"), f"开关位置不对：{argv}"
    assert argv[argv.index("-r") + 1].endswith("requirements.txt"), argv


def test_bundling_lockfile_is_mounted_not_reached_via_asset_input_parent():
    """清单在容器里的路径必须真的挂进去了，且那条 install 真的校验 hash。

    `/asset-input` 挂的是 functions/，它在容器里的父目录是 `/`，不是宿主的
    infra/——`/asset-input/../infra/...` 在容器里根本不存在。这里不判具体
    写法，而是把命令里引用的清单路径与 volumes 的 containerPath 对起来：
    引用了没挂载的路径就红。
    """
    specs = _bundling_specs(APP_PY.read_text())
    assert specs, "app.py 里找不到带 command+volumes 的 bundling 配置"
    checked = 0
    for cmd, mounts in specs:
        refs = set(re.findall(r"(/[\w./-]*bundling-requirements\.txt)", cmd))
        if not refs:
            continue
        checked += 1
        for ref in refs:
            assert any(ref.startswith(m.rstrip("/") + "/") for m in mounts), (
                f"{ref} 不在任何 containerPath({sorted(mounts)}) 之下："
                f"容器里没有这个文件，pip 会直接找不到清单")
            # `&&` 串起来的多条命令里，开关必须落在**装这份清单**那一段上
            seg = next(s for s in cmd.split("&&") if ref in s)
            assert "--require-hashes" in seg, (
                f"装 {ref} 那条命令没有 --require-hashes，清单里的 hash 白列：{seg}")
    assert checked == 1, f"预期恰好一处 bundling 装锁定清单，实际 {checked} 处"
