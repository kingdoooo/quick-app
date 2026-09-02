"""auth 部署包的模块清单（`deploy_auth.AUTH_PACKAGE_MODULES`）必须覆盖 login_handler 的本地 import 闭包。

2026-09-02 实测事故：login_handler 新 import 了 verifier_env，而 build_zip 按记性只写了两个文件 ⇒
Runtime.ImportModuleError ⇒ **整个 auth 502 约 4 分钟**（登录、/console-session 全断），而
单测全绿、verify_deployed_components 也绿（它只核对被点名的两个文件）。与 panel 的 COPY_FILES 同一
条纪律：清单以闭包断言为准。按源码文本读清单，不 import deploy_auth（它依赖 boto3，auth 借的 venv 没有）。
"""
import ast
import re
from pathlib import Path

AUTH = Path(__file__).resolve().parents[1]
EXTERNAL = {"os", "json", "re", "time", "logging", "boto3", "botocore", "urllib", "datetime", "hmac",
            "hashlib", "base64", "secrets", "configparser", "sys", "typing", "jwt", "dataclasses",
            "collections", "functools", "html", "http", "io", "zipfile", "tempfile", "subprocess"}


def _local_imports(path: Path) -> set:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return {n for n in names if n not in EXTERNAL and (AUTH / f"{n}.py").exists()}


def _closure(entry: str) -> set:
    seen, queue = set(), [entry]
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        queue.extend(_local_imports(AUTH / f"{cur}.py"))
    return {f"{n}.py" for n in seen}


def _declared() -> set:
    src = (AUTH / "deploy_auth.py").read_text()
    m = re.search(r"^AUTH_PACKAGE_MODULES = \((.*?)\)$", src, re.M | re.S)
    assert m, "deploy_auth.py 缺 AUTH_PACKAGE_MODULES"
    return set(re.findall(r'"([^"]+\.py)"', m.group(1)))


def test_package_list_covers_login_handler_import_closure():
    needed = _closure("login_handler")
    assert "verifier_env.py" in needed and "session.py" in needed, f"闭包解析坏了：{sorted(needed)}"
    missing = needed - _declared()
    assert not missing, f"login_handler import 了但不在部署包清单里（部署后 ImportModuleError，auth 全部 502）：{sorted(missing)}"


def test_package_list_has_no_phantom_files():
    for name in _declared():
        assert (AUTH / name).exists(), f"清单里的 {name} 在 auth/ 下不存在——build_zip 会在真机上炸"


def test_build_zip_iterates_the_declared_list_not_hand_picked_names():
    src = (AUTH / "deploy_auth.py").read_text()
    body = src[src.index("def build_zip"):src.index("\ndef ", src.index("def build_zip") + 10)]
    assert "for name in AUTH_PACKAGE_MODULES" in body
    assert 'z.write(src / "login_handler.py"' not in body, "又回到按记性点名写文件了"
