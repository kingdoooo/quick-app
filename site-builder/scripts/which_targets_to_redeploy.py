#!/usr/bin/env python3
"""改了哪些文件 ⇒ 该重部哪些目标。

存在的理由：`deployer/functions/` 下有一批模块被**别的组件复制进自己的产物**
（panel 的 zip、key-proxy 的 zip、mcp 的镜像），所以改一个文件常常要重部好几个
组件，而这个对应关系过去只存在于人的记忆里。同形态漏过两次
（permissions.py 漏 key-proxy、access_rollup.py 漏 panel），原有指引"改共享模块前
先 grep 部署脚本"是人的流程，第二次照样漏——本脚本把它变成一个能问的问题。

三层规则，前两层有真源、第三层没有（所以分开显示）：
  ① 目录归属 —— 用 PurePath.parts 判（不是子串：`"/router/" in p` 对
     `router/...` 这种无前导斜杠的路径永不匹配，v1 就栽在这里）；
  ② vendored 反向映射 —— deployer/functions/*.py 被谁打进了自己的产物，
     从三份复制清单推导（panel 的 COPY_FILES、key-proxy 的 COPY_FILES、
     mcp 的 Dockerfile COPY 行）；
  ③ 手工断言的耦合边（`SEMANTIC_COUPLINGS`）—— 推不出来、靠人维护的那一条。

期望值由 `deployer/tests/test_redeploy_targets.py` 的硬编码快照核对——**不要**让
测试从本模块自己的解析结果生成期望，那样守卫恒真（v1 的 copied_files_not_in_map
就是把"实际"和"期望"都用这三个解析器算出来，差集恒为空）。

只用标准库：这是操作者工具，用系统 python3 直接跑，不该依赖任何 venv。

用法：
    python3 site-builder/scripts/which_targets_to_redeploy.py [PATH ...]
无参时读 `git diff --name-only HEAD`（含已 staged 的改动）。
"""
import ast
import re
import subprocess
import sys
from pathlib import Path, PurePath

ROOT = Path(__file__).resolve().parents[1]      # site-builder/
REPO = ROOT.parent                             # 仓库根
FUNCTIONS = ROOT / "deployer" / "functions"

# 目录 → 重部目标。前缀是仓库根相对的路径段，锚定在开头比较。
DIR_RULES = (
    (("site-builder", "panel"), "panel"),
    (("site-builder", "key-proxy"), "key-proxy"),
    (("site-builder", "mcp"), "mcp"),
    (("site-builder", "auth"), "auth"),
    (("site-builder", "deployer"), "deployer"),
    (("site-builder", "contract"), "deployer"),   # 打进 validate 的 asset
    (("router",), "router"),
)

# vendored 模块的源目录，顺序即优先级：两个 `_build_zip` 都是
# `deployer/functions/<name>` 找不到才退到 `auth/<name>`，所以 auth/ 里的文件
# 同样是 vendored 的（session.py），而 auth/ 里与 functions/ 同名的文件进不了产物。
VENDOR_SRC_DIRS = (
    ("site-builder", "deployer", "functions"),
    ("site-builder", "auth"),
)

# **手工断言的耦合边** —— 与上面两组不同，这里的边**不是从任何真源推导出来的**，
# 所以单独放、单独显示，别混进有清单可查的那些边里。
#
# 唯一一条：`auth/session.py` ↔ `router/infrastructure/lambda/origin_request.py`。
# 那是**两份独立实现靠人手保持一致**的同一套 HS256 会话验签，不是文件复制，因此
# 没有任何复制清单能解析出这条边。两处锚点都写着这件事（按引号里的原文 grep，
# 行号只是写这行时的位置、会漂）：
#   - CLAUDE.md「两处必须字节级同步」（当时 :145）
#   - router/infrastructure/lambda/origin_request.py「改动须两处同步」（当时 :453）
# 改了 session.py 只重部 auth 的后果是**全平台会话验签失败**，这个代价大到值得
# 破一次"只答推导得出的东西"的规矩。
#
# 代价要认：手写的边不会随代码自动更新，**得靠人维护**——上面那两处注释挪走或
# 改写时，这条边可能已经不成立而这里还留着。CLI 因此把它与推导出来的边分开打印，
# 并明说需要人工确认。不要把这里长成配置文件或扫描机制：一条边 + 一段响亮的注释
# 就是全部范围（真发现第二条，先报告，不要顺手加）。
SEMANTIC_COUPLINGS = {
    ("site-builder", "auth", "session.py"): {"router"},
}


def _list_const(py: Path, name: str) -> list[str]:
    """读模块顶层的字符串序列常量。

    用 AST 而不是正则：正则会把注释里提到的文件名一起收进来
    （deploy_key_proxy.py 的注释就逐个解释了每个模块，还提到两个**不在**清单里的
    文件），那样解析出来的"清单"是错的，而守卫会跟着一起错。

    读不动就抛，一律不返回"部分清单"：本工具的失效方式是漏报，而少解析出一个
    文件名和"这个文件确实不用重部"在输出里长得一模一样。找不到常量、值不是
    元组/列表、元素不是字符串字面量——三种情况都要吵。
    """
    for node in ast.parse(py.read_text()).body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == name):
            continue
        if not isinstance(node.value, (ast.Tuple, ast.List)):
            raise RuntimeError(f"{py.name} 的 {name} 不是元组/列表字面量，解析不了")
        out = []
        for e in node.value.elts:
            if not (isinstance(e, ast.Constant) and isinstance(e.value, str)):
                raise RuntimeError(
                    f"{py.name} 的 {name} 里有非字面量元素，解析不出完整清单")
            out.append(e.value)
        return out
    raise RuntimeError(f"{py.name} 里找不到 {name}")


def _panel_files() -> list[str]:
    return _list_const(ROOT / "panel" / "deploy_panel.py", "COPY_FILES")


def _key_proxy_files() -> list[str]:
    return _list_const(ROOT / "key-proxy" / "deploy_key_proxy.py", "COPY_FILES")


def _mcp_files() -> list[str]:
    """Dockerfile 的 COPY 行 —— 真正进入镜像的那一份清单。

    deploy_agentcore.py 里还有两份平行清单（`_BUILD_INPUTS` 与 build_and_push 的
    复制循环）。本脚本**只读 Dockerfile**，故意不重复那个交叉核对——保证三份一致的是
    `mcp/tests/test_agentcore_contract.py::test_image_carries_every_local_module_the_server_chain_imports`
    （按 server.py 的传递闭包核对）。**删掉那条测试，这里只读一份清单的做法就不再
    安全**：复制循环多列一个文件时，那个文件静默不进镜像，而本脚本一样看不出来。
    """
    df = (ROOT / "mcp" / "Dockerfile").read_text()
    return sorted({m for line in df.splitlines()
                   if line.strip().upper().startswith("COPY")
                   for m in re.findall(r"([a-z_]+\.py)", line)})


def vendor_map() -> dict[str, set[str]]:
    """functions/*.py 的文件名 → 需要重部的组件集合。

    deployer 打的是**整个** functions/ 目录（规则，不是清单），所以每个文件先带上
    deployer；三份复制清单再往上加各自的组件。
    """
    out: dict[str, set[str]] = {p.name: {"deployer"} for p in FUNCTIONS.glob("*.py")}
    for comp, files in (("panel", _panel_files()),
                        ("key-proxy", _key_proxy_files()),
                        ("mcp", _mcp_files())):
        for f in files:
            out.setdefault(f, set()).add(comp)
    return out


def _repo_parts(p) -> tuple[str, ...]:
    """路径 → 仓库根相对的路径段。

    绝对路径先转相对：DIR_RULES 的前缀锚定在开头，
    `/Users/.../quick-app/site-builder/...` 一条都匹配不上，而结果会是静默的"无"。
    仓库外的路径返回空元组（谁也不牵连）。
    """
    path = PurePath(p)
    if path.is_absolute():
        try:
            path = PurePath(Path(p).resolve()).relative_to(REPO)
        except ValueError:
            return ()
    return path.parts


def _vendored_name(parts: tuple[str, ...]) -> str | None:
    """路径正好落在某个 vendored 源目录下时返回文件名，否则 None。

    锚定目录而不是判 `"functions" in parts`：反向映射是按**文件名**查的，对任何
    带 functions 段的路径都套一遍，等于哪天别处出现个同名文件就误报重部目标。
    只认直属文件（复制循环是 `fn_dir / name`，不递归）。
    """
    for d in VENDOR_SRC_DIRS:
        if parts[:len(d)] != d or len(parts) != len(d) + 1:
            continue
        name = parts[-1]
        # auth/ 是 fallback：functions/ 有同名文件时复制清单取的是那一份。
        if d[-1] == "auth" and (FUNCTIONS / name).exists():
            return None
        return name
    return None


def _derived_targets(paths) -> set[str]:
    """能从真源推导出来的目标：目录归属 + vendored 复制清单。"""
    vmap, out = vendor_map(), set()
    for p in paths:
        parts = _repo_parts(p)
        for prefix, comp in DIR_RULES:
            if parts[:len(prefix)] == prefix:
                out.add(comp)
        name = _vendored_name(parts)
        if name:
            out |= vmap.get(name, set())
    return out


def coupled_targets(paths) -> set[str]:
    """`SEMANTIC_COUPLINGS` 命中的目标 —— 手工断言、没有真源的那部分。

    单独一个函数是为了让调用方（CLI 与守卫）能把它与推导出来的目标**分开**：
    混在一起看不出哪条需要人维护。
    """
    out = set()
    for p in paths:
        out |= SEMANTIC_COUPLINGS.get(_repo_parts(p), set())
    return out


def targets_for(paths) -> set[str]:
    """全部要重部的目标（推导出来的 + 手工断言的）。"""
    return _derived_targets(paths) | coupled_targets(paths)


def main() -> int:
    paths = sys.argv[1:] or subprocess.run(
        ["git", "diff", "--name-only", "HEAD"], capture_output=True, text=True,
        check=True, cwd=REPO).stdout.split()
    if not paths:
        print("没有改动的文件")
        return 0
    print("改动:", *paths, sep="\n  ")
    # 归不到任何目标的路径要点名：静默的"无"和"确实不用重部"长得一样，
    # 而这个工具的失效方式恰恰是漏报。
    unmatched = [p for p in paths if not targets_for([p])]
    if unmatched:
        print("\n未归类（不在任何目标的目录规则里，请人工确认）:",
              *unmatched, sep="\n  ")
    # 推导出来的边与手工断言的边**分开打印**：前者跟着部署脚本自动更新，后者靠人
    # 维护、可能已经过时，操作者有权知道自己在信哪一种。
    derived = _derived_targets(paths)
    asserted = coupled_targets(paths) - derived
    print("\n需要重部（从部署脚本的复制清单与目录规则推导）:",
          ", ".join(sorted(derived)) or "（无）")
    if asserted:
        print("需要重部（手工断言的耦合边，请人工确认它仍然成立）:",
              ", ".join(sorted(asserted)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
