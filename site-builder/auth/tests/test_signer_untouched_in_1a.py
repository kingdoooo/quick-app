"""3c-1A 的定义：**signer 不动**（plan Global Constraints）。

verifier 已经认 kid，但没有任何 handler 用 `mint_token` 签发；线上 token 仍是 legacy 形态。
**3c-1B 的第一步就是删掉本文件**（并把 handler 切到 mint_token），在那之前它必须一直绿。
自测那条证明检查器本身能红。
"""
import ast
import base64
import json
from pathlib import Path

import session

AUTH = Path(__file__).resolve().parents[1]
PANEL = AUTH.parent / "panel"
HANDLERS = (AUTH / "login_handler.py", PANEL / "console_session.py",
            PANEL / "handler.py", PANEL / "api.py")


def _calls_mint_token(src: str) -> bool:
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Name) and f.id == "mint_token") or \
               (isinstance(f, ast.Attribute) and f.attr == "mint_token"):
                return True
    return False


def test_no_handler_calls_mint_token_in_1a():
    offenders = [p.name for p in HANDLERS if p.exists() and _calls_mint_token(p.read_text())]
    assert not offenders, f"1A 里 signer 必须不动，这些文件调用了 mint_token: {offenders}（3c-1B 才放开）"


def test_guard_self_test_catches_both_call_shapes():
    assert _calls_mint_token("import session\nsession.mint_token(kid='x')\n")
    assert _calls_mint_token("from session import mint_token\nmint_token()\n")
    assert not _calls_mint_token("import session\nsession.mint_session_jwt('a', 'b', 'c')\n")


def test_legacy_mint_header_has_no_kid():
    def header(tok):
        h = tok.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert header(session.mint_session_jwt("v@example.test", "V", "s")) == {"alg": "HS256", "typ": "JWT"}
    assert header(session.mint_upgrade_code("v@example.test", "s")) == {"alg": "HS256", "typ": "JWT"}
