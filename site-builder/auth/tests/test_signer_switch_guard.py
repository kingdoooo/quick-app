"""签发面守卫（3c-1B，spec §11.8.13 / D10）：**handler 只经 signer 助手签发**。

本文件**替换** 3c-1A 的 `test_signer_untouched_in_1a.py`（那条锁的是"没有任何 handler 调
mint_token"，1B 的第一步就是让它失效）。现在锁的是两条更强的形状：

1. `mint_token`（新形态）只出现在 `_signer_mode() == "current"` 的分支里；
   `mint_session_jwt` / `mint_upgrade_code`（legacy 形态）只出现在另一侧分支里。
   **为什么值得一条 AST 守卫**：多一条不经开关的签发路径不会让任何用例变红——它签出来的 token
   两侧 verifier 都接受（切换期两种形态都在接受集合里），症状要等到 ④ 的观察窗口"accepted_legacy
   三列归零"迟迟不归零，或 ⑤ 关掉 legacy 入口之后才现形，那时已经过了 26 小时。
2. `mint_token` 的 `kid` / `secret` 只能来自 `_signing_key(...)` 的返回值。手写一个 kid 字面量、
   或把 `_secret("JWT_SECRET")` 递给 `secret=`，都会签出"kid 声称是 A 而签名用的是 B"的 token，
   在验签端表现为 `bad_signature`（不是 `unknown_kid`），排查方向完全错。

自测（`test_guard_catches_*`）证明检查器本身会红，且两种调用形态（`mint_token(...)` 与
`session.mint_token(...)`）都抓得住——pass-now 的守卫不算守卫。

**panel 不在本文件的清单里**：05 号任务把 panel 的面板会话切到同一个开关，那一票再把
`panel/console_session.py` 加进 `SIGNER_FILES`。今天 panel 仍无条件用 legacy mint，
现在就加进来会红。
"""
import ast
from pathlib import Path

import pytest

AUTH = Path(__file__).resolve().parents[1]
# 05 号任务在这里加 (AUTH.parent / "panel" / "console_session.py",)
SIGNER_FILES = (AUTH / "login_handler.py",)

LEGACY_MINTS = ("mint_session_jwt", "mint_upgrade_code")
CURRENT_MINTS = ("mint_token",)
SIGNER_MODE_FN = "_signer_mode"
SIGNING_KEY_FN = "_signing_key"


def _func_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _mode_bearing_names(src: str) -> set:
    """`signer = _signer_mode()` 里被绑定的名字——`/callback` 先读开关再烧一次性 code，
    所以分支条件是个局部变量而不是内联调用。两种形状都算"经过开关"。"""
    names: set = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                and _func_name(node.value) == SIGNER_MODE_FN:
            for target in node.targets:
                for leaf in ast.walk(target):
                    if isinstance(leaf, ast.Name):
                        names.add(leaf.id)
    return names


def _branch_modes(test: ast.expr, mode_names: set):
    """`_signer_mode() == "current"` → ("current", "legacy")（if 分支的模式, else 分支的模式）。

    左侧也可以是 `_mode_bearing_names` 认出来的局部变量。只认 `==` / `!=` 与两个合法字面量；
    别的形状返回 None ⇒ 分支不算"经过开关"，里面的 mint 调用会被报成 offender。
    这是有意的保守：看不懂的条件不等于安全的条件。
    """
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], (ast.Eq, ast.NotEq))):
        return None
    sides = [test.left, test.comparators[0]]
    from_switch = [n for n in sides
                   if (isinstance(n, ast.Call) and _func_name(n) == SIGNER_MODE_FN)
                   or (isinstance(n, ast.Name) and n.id in mode_names)]
    consts = [n.value for n in sides
              if isinstance(n, ast.Constant) and n.value in ("legacy", "current")]
    if not from_switch or len(consts) != 1:
        return None
    named, other = consts[0], "legacy" if consts[0] == "current" else "current"
    return (named, other) if isinstance(test.ops[0], ast.Eq) else (other, named)


def mint_calls(src: str) -> list:
    """→ [(被调用的 mint 名, 所处的 signer 模式或 None)]，None = 不在任何 signer 分支里。"""
    found: list = []
    mode_names = _mode_bearing_names(src)

    def walk(node, mode):
        if isinstance(node, ast.If):
            modes = _branch_modes(node.test, mode_names)
            walk(node.test, mode)
            for child in node.body:
                walk(child, modes[0] if modes else mode)
            for child in node.orelse:
                walk(child, modes[1] if modes else mode)
            return
        if isinstance(node, ast.Call) and _func_name(node) in LEGACY_MINTS + CURRENT_MINTS:
            found.append((_func_name(node), mode))
        for child in ast.iter_child_nodes(node):
            walk(child, mode)

    walk(ast.parse(src), None)
    return found


def misplaced_mints(src: str) -> list:
    """→ 不在自己该在的 signer 分支里的签发调用。守卫的判据只写一处。"""
    return [(name, mode) for name, mode in mint_calls(src)
            if mode != ("current" if name in CURRENT_MINTS else "legacy")]


def signing_key_names(src: str) -> set:
    """`kid, secret = _signing_key(...)` 里被绑定的名字集合（元组解包与单名赋值都算）。"""
    names: set = set()
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and _func_name(node.value) == SIGNING_KEY_FN):
            continue
        for target in node.targets:
            for leaf in ast.walk(target):
                if isinstance(leaf, ast.Name):
                    names.add(leaf.id)
    return names


def unsourced_key_args(src: str) -> list:
    """`mint_token` 的 kid/secret 里**不是**来自 `_signing_key` 的那些（→ [(kwarg 名, 形态)]）。"""
    allowed = signing_key_names(src)
    bad = []
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Call) and _func_name(node) in CURRENT_MINTS):
            continue
        seen = set()
        for kw in node.keywords:
            if kw.arg not in ("kid", "secret"):
                continue
            seen.add(kw.arg)
            if not (isinstance(kw.value, ast.Name) and kw.value.id in allowed):
                bad.append((kw.arg, ast.dump(kw.value)))
        for missing in {"kid", "secret"} - seen:
            bad.append((missing, "缺失或按位置传参"))
    return bad


# ---- 真代码上的断言 -------------------------------------------------------------------

@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_every_mint_sits_in_the_branch_its_form_belongs_to(path):
    offenders = misplaced_mints(path.read_text())
    assert not offenders, (
        f"{path.name} 里这些签发调用不在自己该在的 signer 分支里：{offenders}"
        "（mint_token 只许在 _signer_mode() == \"current\" 一侧，legacy mint 只许在另一侧）")


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_both_forms_are_actually_present_so_the_guard_has_something_to_guard(path):
    """正对照：两侧都必须真的有调用，否则上面那条在空集合上假绿。"""
    names = {name for name, _ in mint_calls(path.read_text())}
    assert names & set(CURRENT_MINTS), f"{path.name} 没有任何新形态签发——signer 切换没落地？"
    assert names & set(LEGACY_MINTS), f"{path.name} 没有 legacy 分支（3c-3 之前不删）"


@pytest.mark.parametrize("path", SIGNER_FILES, ids=lambda p: p.name)
def test_mint_token_takes_kid_and_secret_only_from_the_signing_helper(path):
    bad = unsourced_key_args(path.read_text())
    assert not bad, (f"{path.name} 里 mint_token 的 kid/secret 不是来自 {SIGNING_KEY_FN}()：{bad}")


# ---- 自测：证明检查器会红（两种调用形态各一次）----------------------------------------

BARE = "from session import mint_token\n"
DOTTED = "import session\n"

GOOD_BARE = BARE + '''
def h():
    if _signer_mode() == "current":
        kid, secret = _signing_key("site")
        token = mint_token(kid=kid, secret=secret, token_use="site-session")
    else:
        token = mint_session_jwt("e", "n", _secret("JWT_SECRET"))
    return token
'''
GOOD_DOTTED = DOTTED + '''
def h():
    if _signer_mode() == "legacy":
        code = session.mint_upgrade_code("e", _secret("JWT_SECRET"))
    else:
        kid, secret = _signing_key("console")
        code = session.mint_token(kid=kid, secret=secret, token_use="console-upgrade")
    return code
'''
# **已知且有意的限制**：守卫只看 `ast.If` 的 body/orelse，看不懂"早返回 + 落空"
# （`if mode == "legacy": return legacy_mint(...)` 后面跟一个裸的 `mint_token(...)`）。
# 那种写法会被报成 offender，所以本仓库的签发点一律写显式 if/else。这条限制**是可见的**
# （下面 test_guard_is_conservative_about_the_fall_through_idiom 把它钉住），
# 不是静默放过——放过才危险，报错只是要求换个写法。
FALL_THROUGH = BARE + '''
def h():
    if _signer_mode() == "legacy":
        return mint_session_jwt("e", "n", "s")
    kid, secret = _signing_key("site")
    return mint_token(kid=kid, secret=secret, token_use="site-session")
'''


GOOD_HOISTED = BARE + '''
def h():
    signer = _signer_mode()
    if signer == "current":
        kid, secret = _signing_key("site")
        token = mint_token(kid=kid, secret=secret, token_use="site-session")
    else:
        token = mint_session_jwt("e", "n", "s")
    return token
'''


@pytest.mark.parametrize("src", [GOOD_BARE, GOOD_DOTTED, GOOD_HOISTED])
def test_guard_passes_the_two_correct_shapes(src):
    assert not misplaced_mints(src)
    assert not unsourced_key_args(src)


def test_guard_is_conservative_about_the_fall_through_idiom():
    """早返回 + 落空的写法**会被报错**（不是放过）——所以签发点一律写显式 if/else。"""
    assert misplaced_mints(FALL_THROUGH)


@pytest.mark.parametrize("src, why", [
    (BARE + 'def h():\n    return mint_token(kid=k, secret=s)\n',
     "新形态签发根本不经开关"),
    (DOTTED + 'def h():\n    return session.mint_token(kid=k, secret=s)\n',
     "同上，属性调用形态"),
    (BARE + 'def h():\n    if _signer_mode() == "legacy":\n        return mint_token(kid=k, secret=s)\n    return 1\n',
     "新形态签发挂在 legacy 分支里"),
    (BARE + 'def h():\n    if _signer_mode() == "current":\n        return mint_session_jwt("e", "n", "s")\n    return 1\n',
     "legacy mint 挂在 current 分支里"),
    (DOTTED + 'def h():\n    return session.mint_session_jwt("e", "n", "s")\n',
     "legacy mint 不经开关（1A 的形态，1B 之后就是漏改）"),
    (BARE + 'def h():\n    signer = os.environ["SESSION_SIGNER"]\n    if signer == "current":\n        return mint_token(kid=k, secret=s)\n    return 1\n',
     "局部变量绕过 _signer_mode()（直读环境变量 = 没有校验，缺变量时静默按 legacy 签）"),
    (BARE + 'def h():\n    if FLAG == "current":\n        return mint_token(kid=k, secret=s)\n    return 1\n',
     "条件不是 _signer_mode()——看不懂的条件不算经过开关"),
    (BARE + 'def h():\n    if _signer_mode() != "legacy":\n        return mint_session_jwt("e", "n", "s")\n    return 1\n',
     "!= 取反后 legacy mint 落在 current 一侧"),
])
def test_guard_catches_every_way_of_bypassing_the_switch(src, why):
    assert misplaced_mints(src), f"守卫没抓到：{why}"
    del why


@pytest.mark.parametrize("src, why", [
    (BARE + 'def h():\n    if _signer_mode() == "current":\n        return mint_token(kid="site-hs-v1", secret=s)\n    return 1\n',
     "kid 写成字面量"),
    (BARE + 'def h():\n    if _signer_mode() == "current":\n        kid, secret = _signing_key("site")\n        return mint_token(kid=kid, secret=_secret("JWT_SECRET"))\n    return 1\n',
     "secret 递的是 legacy 密钥（签名与声称的 kid 不一致 ⇒ bad_signature，排查方向全错）"),
    (BARE + 'def h():\n    if _signer_mode() == "current":\n        return mint_token(kid=kid, secret=secret)\n    return 1\n',
     "kid/secret 是别处来的名字，不是 _signing_key 解包出来的"),
    (BARE + 'def h():\n    if _signer_mode() == "current":\n        return mint_token(token_use="site-session")\n    return 1\n',
     "根本没传 kid/secret"),
])
def test_guard_catches_keys_that_did_not_come_from_the_signing_helper(src, why):
    assert unsourced_key_args(src), f"守卫没抓到：{why}"
    del why


def test_legacy_mint_still_produces_a_header_without_kid():
    """legacy 分支的字节级形态不许漂移：它是 ④ 观察窗口"accepted_legacy 归零"的判据基础。"""
    import base64
    import json

    import session

    def header(tok):
        h = tok.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))

    assert header(session.mint_session_jwt("v@example.test", "V", "s")) == {"alg": "HS256", "typ": "JWT"}
    assert header(session.mint_upgrade_code("v@example.test", "s")) == {"alg": "HS256", "typ": "JWT"}
