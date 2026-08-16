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
import sys
from pathlib import Path
from unittest.mock import patch

# parents: [0]=tests [1]=auth [2]=site-builder（**不是 [3]，那是仓库根**）
AUTH_DIR = Path(__file__).parents[1]
AUTH_REQ = AUTH_DIR / "requirements.txt"
DEPLOY_AUTH = AUTH_DIR / "deploy_auth.py"
INFRA_DIR = Path(__file__).parents[2] / "deployer" / "infra"
BUNDLING_REQ = INFRA_DIR / "bundling-requirements.txt"
APP_PY = INFRA_DIR / "app.py"


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


# 模块级出现这些方法调用即等于 import 时读配置 / 建 AWS client。
_CONFIG_OR_CLIENT_ATTRS = ("read", "read_file", "read_string",
                           "client", "resource", "Session")


def _is_main_guard(node: ast.AST) -> bool:
    """`if __name__ == "__main__":` ——这一块 import 时不执行，不在本守卫范围内。"""
    return (isinstance(node, ast.If)
            and any(isinstance(n, ast.Name) and n.id == "__name__"
                    for n in ast.walk(node.test)))


def test_deploy_auth_reads_no_config_at_import_time():
    """deploy_auth 不许在**模块级**读配置或建 client。

    模块级读 config.ini（gitignored）会让上面那条截获真实 pip argv 的守卫在干净
    clone 里被 skip——Codex 复审 P2-e：`git archive` 出来的树实测 3 passed / 1
    skipped，skip 掉的正是唯一真正验证 `--require-hashes` 到达 pip 的那条。

    按 **AST 判模块级语句**，不靠"缺配置时 import 会不会炸"：本机有 config.ini，
    那种判据在本机永远绿，等于没有守卫。

    "谁算可疑"取自这个文件自己的 AST（模块级 `def` 的名字集合），不手抄一份访问器
    清单：新加一个 `def region()` 之后写 `REGION = region()`，这条自动会红。
    """
    tree = ast.parse(DEPLOY_AUTH.read_text(encoding="utf-8"))
    defined = {n.name for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert defined, "deploy_auth.py 里一个模块级函数都没解析出来——本条已空转"
    bad = []
    for node in tree.body:
        # 函数/类体内随便用——懒加载**就是**要这些调用发生在那里
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if _is_main_guard(node):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = sub.func
                if (isinstance(fn, ast.Attribute)
                        and fn.attr in _CONFIG_OR_CLIENT_ATTRS):
                    bad.append(f".{fn.attr}() at line {sub.lineno}")
                if isinstance(fn, ast.Name) and fn.id in defined:
                    bad.append(f"{fn.id}() at line {sub.lineno}")
            if (isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name)
                    and sub.value.id in ("CFG", "_CFG")):
                bad.append(f"{sub.value.id}[...] at line {sub.lineno}")
    assert not bad, ("deploy_auth 在模块级读配置/建 client，会让上面那条 argv 守卫"
                     f"在干净树里被 skip：{bad}")


# 子进程里先把"读配置"和"建 client"换成一调用就抛，再 import deploy_auth。
_IMPORT_PROBE = '''
import configparser
import boto3


def _forbid(what):
    def _boom(*a, **kw):
        raise AssertionError("import 时调用了 " + what)
    return _boom


configparser.ConfigParser.read = _forbid("ConfigParser.read")
configparser.ConfigParser.read_file = _forbid("ConfigParser.read_file")
configparser.ConfigParser.read_string = _forbid("ConfigParser.read_string")
boto3.client = _forbid("boto3.client")
boto3.resource = _forbid("boto3.resource")
boto3.Session = _forbid("boto3.Session")

import deploy_auth  # noqa: E402,F401

print("IMPORT_CLEAN")
'''


def test_importing_deploy_auth_touches_neither_config_nor_boto3():
    """同一条不变量的**行为判据**：import 真的没碰配置、没建 client。

    上面那条按源码形状判（能点出行号），这条按运行时判（换个写法绕过形状也逃不掉，
    比如把读配置藏进一个模块级 import 的副作用里）。两条都在本机会红——"缺配置时
    import 会炸吗"那种判据才是本机永远绿的那种。
    """
    r = subprocess.run([sys.executable, "-c", _IMPORT_PROBE], cwd=AUTH_DIR,
                       capture_output=True, text=True)
    assert "IMPORT_CLEAN" in r.stdout, (
        "import deploy_auth 时读了配置或建了 boto3 client——干净 clone 里"
        f"config.ini 不存在，于是 argv 守卫直接失效：\n{r.stdout}\n{r.stderr}")


def _segments(cmd: str) -> list[str]:
    """`&&` 串起来的 shell 命令 → 逐段。

    判定必须落在**段**上而不是整串：整串 substring 匹配下，只要命令里任何一处
    出现过那个开关，"这条 install 校验了 hash"就成立——而我们要判的是**每一条**
    install 各自带没带。这正是 Ruling 24 那次更正换掉的形态。
    """
    return [s.strip() for s in cmd.split("&&")]


def test_every_pip_install_in_bundling_requires_hashes():
    """bundling 命令里**每一段** pip install 都必须带 --require-hashes。

    A7 只保证了第一条（装 bundling-requirements.txt）。第二条原来是
    `pip install /asset-contract`，而 site-contract 是 PEP 517 项目
    （requires = ["setuptools>=68"]）⇒ 默认 build isolation 会联网下载并**执行**一个
    未锁版本、未锁 hash 的 setuptools，全部 site-deployer-* 产物都受它影响
    （Codex 复审 P1-b；实测 `--no-index` 下报 Could not find a version that satisfies
    the requirement setuptools>=68）。所以判定要落在**每一段**上，不是"命令里出现过
    这个开关"。

    第二条断言堵的是"换个写法把 PEP 517 装回来"：`/asset-contract` 不许与
    `pip install` 同段——那个挂载点是本仓库自己的源码目录，进产物的正确方式是拷贝
    文件，不是让 pip 去 build 它。
    """
    specs = _bundling_specs(APP_PY.read_text())
    assert specs, "app.py 里找不到带 command+volumes 的 bundling 配置"
    n_pip = 0
    for cmd, _ in specs:
        for seg in _segments(cmd):
            if "pip install" not in seg:
                continue
            n_pip += 1
            assert "--require-hashes" in seg, (
                f"这一段 pip install 不校验 hash，装出来的东西没有任何来源保证："
                f"{seg}")
            assert "/asset-contract" not in seg, (
                f"又让 pip 去 build 合同包了（PEP 517 会联网装未锁的 setuptools "
                f"并执行它）：{seg}")
    assert n_pip, "bundling 里一条 pip install 都没解析出来——本条已空转，先查 app.py"


def test_contract_package_lands_in_the_asset_without_pep517():
    """合同包必须以文件形式进产物：断言 cp 段的源路径落在挂载卷的 containerPath
    之下（挂载路径与 cp 源路径不一致时 synth 会 FailedToBundleAsset，但那要跑
    Docker 才看得见，所以这里按配置对齐一次）。

    只拷 `/asset-contract/contract` 这个**包目录**，不拷挂载根——挂载根是
    `contract/src`，还有个 `site_contract.egg-info` 不该进 Lambda 产物。
    """
    specs = _bundling_specs(APP_PY.read_text())
    assert specs, "app.py 里找不到带 command+volumes 的 bundling 配置"
    checked = 0
    for cmd, mounts in specs:
        for seg in _segments(cmd):
            if "/asset-contract" not in seg:
                continue
            checked += 1
            assert seg.startswith("cp "), (
                f"合同包要用 cp 拷进产物，不许再走 pip/PEP 517：{seg}")
            srcs = re.findall(r"(/asset-contract[\w./-]*)", seg)
            assert srcs, seg
            for src in srcs:
                assert any(src.startswith(m.rstrip("/") + "/") for m in mounts), (
                    f"{src} 不在任何 containerPath({sorted(mounts)}) 之下："
                    f"容器里没有这个路径，synth 会 FailedToBundleAsset")
            assert any(s.endswith("/contract") for s in srcs), (
                f"要拷的是包目录 /asset-contract/contract，不是挂载根（会把 "
                f"egg-info 一起塞进产物）：{seg}")
    assert checked == 1, (
        f"预期恰好一段命令引用 /asset-contract，实际 {checked} 段")


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
