"""`scripts/verify_*.py` 的退出契约（3c-1B ticket 17 第 7 条的**修正结论**，2026-09-04）。

**先说结论：那条 review 发现是假阳性，本文件不是它的修复，而是给它守边界。**

发现原文说 `verify_analytics_e2e` 会吞掉 `_session_mint` 抛的 `raise SystemExit("解释")`：
理由是 `finally` 里的 `sys.exit(rc)` 会顶掉在飞的异常。**实测不成立**——那个 `sys.exit(rc)`
在 `try/finally` 语句**之后**、不在 `finally` 体内，所以 SystemExit 在飞时它根本执行不到，
解释由解释器默认处理打印出来。等价形状实测（2026-09-04）：

    结果：只跑了 0 项（预期 ≥70）—— 验收**未完成**
    取不到 trusted_idps——签出来的会话 Edge 不认，验收不可信
    exit code = 1

两行都在，退出码 1。**但那个形状只差一次缩进就真的会丢**：把 `sys.exit(rc)` 挪进 `finally`
（或把 `except Exception` 改成 `except BaseException`），解释就会被顶掉，而所有单测照样绿——
操作者只看到一个裸的"验收未完成"。所以这里把"不许出现那个形状"钉住：

- 只要 `__main__` 的 `finally` 体内有 `exit(...)` 调用，就必须显式接住 `SystemExit`；
- 且那条 handler 要排在 `Exception` 之前（顺序与阅读一致；一旦有人改成 `BaseException` 就真的吞了）。

今天**没有**脚本是那个形状（都从 `finally` 外面退出），所以本文件的参数化用例大多走
"没有 finally-exit ⇒ 不适用"这一支；`test_the_guard_can_actually_fail` 用合成源码证明判定逻辑真的会红。
按 AST 判、不按正则：`except (A, B)` 与嵌套 try 都要能看见。
"""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = sorted((ROOT / "site-builder" / "scripts").glob("verify_*.py"))


def _main_block(tree):
    """`if __name__ == "__main__":` 的 body（没有则 None）。"""
    for node in tree.body:
        if isinstance(node, ast.If) and ast.dump(node.test).find("__name__") != -1:
            return node.body
    return None


def _tries(body):
    for node in body:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Try):
                yield sub


def _handled_names(handler):
    t = handler.type
    if t is None:
        return {"<bare>"}
    parts = t.elts if isinstance(t, ast.Tuple) else [t]
    return {p.id if isinstance(p, ast.Name) else ast.unparse(p) for p in parts}


def test_scripts_exist():
    assert len(SCRIPTS) >= 10, [p.name for p in SCRIPTS]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_a_finally_that_exits_must_also_catch_systemexit(script):
    """有 `finally: sys.exit(...)` 就必须接住 `SystemExit`，且要排在 `Exception` 之前。

    顺序也要判：`except Exception` 在前时 `SystemExit` 那条仍然到不了（前者接不住 BaseException，
    所以实际不会被吞——但把它写在后面会让读代码的人以为顺序无关，而一旦有人把它改成
    `except BaseException` 就真的吞了）。这里要求它先出现，语义与阅读一致。
    """
    tree = ast.parse(script.read_text(encoding="utf-8"))
    body = _main_block(tree)
    if body is None:
        pytest.skip("没有 __main__ 块")
    for t in _tries(body):
        exits_in_finally = any(
            isinstance(n, ast.Call) and ast.unparse(n.func).endswith("exit")
            for f in t.finalbody for n in ast.walk(f))
        if not exits_in_finally:
            continue
        names = [_handled_names(h) for h in t.handlers]
        flat = set().union(*names) if names else set()
        assert "SystemExit" in flat, (
            f"{script.name}: `finally` 里 sys.exit 会顶掉在飞的 SystemExit，"
            f"而被调用方（如 _session_mint 的 trusted_idp / Minter.key）用 "
            f"`raise SystemExit('解释')` 报前置条件失败 ⇒ 解释永远不会被打印。"
            f"当前 handlers = {names}")
        idx_se = next(i for i, s in enumerate(names) if "SystemExit" in s)
        idx_ex = next((i for i, s in enumerate(names) if "Exception" in s), len(names))
        assert idx_se < idx_ex, f"{script.name}: SystemExit 那条要排在 Exception 之前（可读性），当前 {names}"


def test_the_guard_can_actually_fail():
    """元用例：把一段"有 finally exit、没接 SystemExit"的源码喂给同一段判定逻辑，必须被抓。"""
    bad = ast.parse('if __name__ == "__main__":\n'
                    '    try:\n        rc = main()\n'
                    '    except Exception:\n        rc = 1\n'
                    '    finally:\n        sys.exit(rc)\n')
    body = _main_block(bad)
    t = next(_tries(body))
    flat = set().union(*[_handled_names(h) for h in t.handlers])
    assert "SystemExit" not in flat        # 这就是被守的形态
    good = ast.parse('if __name__ == "__main__":\n'
                     '    try:\n        rc = main()\n'
                     '    except SystemExit as e:\n        rc = 1\n'
                     '    except Exception:\n        rc = 1\n'
                     '    finally:\n        sys.exit(rc)\n')
    tg = next(_tries(_main_block(good)))
    flatg = set().union(*[_handled_names(h) for h in tg.handlers])
    assert "SystemExit" in flatg
