"""签发面守卫（3c-final）：**每一次 `mint_token` 的 kid 与 sign 都来自 `_signer(...)` 的返回值**，且只有
login_handler.py 与 panel/console_session.py 会签发。替换 3c-1B 的 test_signer_switch_guard.py（signer 开关已删）。

为什么值得一条 AST 守卫：手写一个 kid 字面量、或把别的可调用递给 `sign=`，签出来的是"kid 声称是 A 而签名是 B"
的 token，验签端表现为 bad_signature（不是 unknown_kid），排查方向完全错；多一条不经 `_signer` 的签发路径
则绕开了 KmsSigner 的 KeyId 断言与冷启动自检。自测（test_guard_catches_*）证明检查器本身会红。
"""
import ast
from pathlib import Path

import pytest

AUTH = Path(__file__).resolve().parents[1]
PANEL = AUTH.parent / "panel"
SIGNER_FILES = (AUTH / "login_handler.py", PANEL / "console_session.py")
NON_SIGNER_FILES = (AUTH / "pre_token_email.py", PANEL / "handler.py", PANEL / "api.py")
FORBIDDEN_NAMES = {"mint_session_jwt", "mint_upgrade_code", "verify_session_jwt", "verify_upgrade_code",
                   "verify_with_legacy", "legacy_secret", "signer_mode", "signing_key"}


def _mint_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name == "mint_token":
                yield node


def _signer_bound_names(fn: ast.FunctionDef) -> set:
    """函数体里 `kid, sign = _signer(...)`（或 `kid, sign = self._signer(...)`）绑定出来的名字对。"""
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if fname == "_signer" and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple):
                names = [e.id for e in node.targets[0].elts if isinstance(e, ast.Name)]
                if len(names) == 2:
                    out.add(tuple(names))
    return out


def check_source(src: str) -> list:
    """→ 违规清单（空 = 通过）。"""
    tree = ast.parse(src)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            problems.append(f"line {node.lineno}: 引用了已删除的 HS/legacy 名字 {node.id}")
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_NAMES:
            problems.append(f"line {node.lineno}: 引用了已删除的 HS/legacy 名字 {node.attr}")
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        bound = _signer_bound_names(fn)
        for call in _mint_calls(fn):
            kw = {k.arg: k.value for k in call.keywords}
            if "kid" not in kw or "sign" not in kw:
                problems.append(f"line {call.lineno}: mint_token 缺 kid= 或 sign=")
                continue
            pair = (kw["kid"].id if isinstance(kw["kid"], ast.Name) else None,
                    kw["sign"].id if isinstance(kw["sign"], ast.Name) else None)
            if pair not in bound:
                problems.append(f"line {call.lineno}: mint_token 的 kid/sign 不是同一次 `kid, sign = _signer(...)` 绑定出来的 {pair}")
    return problems


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_every_mint_takes_kid_and_sign_from_the_signer_helper(path):
    assert check_source(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_signer_files_actually_mint_so_the_guard_has_something_to_guard(path):
    assert list(_mint_calls(ast.parse(path.read_text(encoding="utf-8")))), f"{path.name} 里没有 mint_token 调用了？"


@pytest.mark.parametrize("path", NON_SIGNER_FILES, ids=lambda p: p.name)
def test_files_that_must_never_sign_contain_no_mint_at_all(path):
    assert not list(_mint_calls(ast.parse(path.read_text(encoding="utf-8")))), f"{path.name} 多开了一条签发路径"


GOOD = """
def f():
    kid, sign = _signer("site")
    return mint_token(kid=kid, sign=sign, token_use="site-session", email=e, ttl_seconds=1)
"""
BAD = [
    ("kid 字面量", GOOD.replace("kid=kid", 'kid="site-rs-v1"')),
    ("sign 来自别处", GOOD.replace("sign=sign", "sign=other")),
    ("不经 _signer", GOOD.replace("_signer(", "_other(")),
    ("引用已删的 legacy 名", GOOD + "\ndef g():\n    return mint_session_jwt(e, n, s)\n"),
    ("引用已删的 signer 开关", GOOD + "\ndef g():\n    return verifier_env.signer_mode(x)\n"),
]


def test_guard_passes_the_correct_shape():
    assert check_source(GOOD) == []


@pytest.mark.parametrize("why,src", BAD, ids=[b[0] for b in BAD])
def test_guard_catches_every_way_of_bypassing_the_signer_helper(why, src):
    assert check_source(src), why
