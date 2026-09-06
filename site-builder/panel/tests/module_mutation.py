"""变形测试的共享助手：**在临时副本上改一个字面量再加载**（3c-1B）。

住在 `panel/tests/` 是因为这里已经是本仓库跨包共享测试助手的地方
（`upgrade_code_vectors.py` 同样由 auth 侧 import，见 `auth/tests/test_upgrade_code.py`
顶部那条 `sys.path.insert`）。auth 与 panel 各有一处变形测试，两处要的是**同一条
非显然的安全性质**，所以收成一份：

  ① **按段落切锚点，再要求段内唯一**。`token_use="site-session"` /
     `token_use="console-session"` 这类字面量在同一个文件里既出现在**签发**处也出现在
     **验签**处。不切段就会改到验签那一处——变形测试照样"变红"，但红的是另一件事，
     于是它对"signer 写错"这个缺陷完全失明（pass-now 的假守卫，spec 反复咬住的形状）。
  ② **改的是临时副本，不动仓库里的文件**（spec Testing Decisions 的「`git stash` 或
     临时副本」的后者）。脏工作树下与 CI 里都能跑，也绝不会 `git checkout --` 掉
     别人未提交的修改。

两处各自复制一份的后果不是"多写几行"，而是其中一份被削弱时另一份看不出来——
而被削弱的那份会静默变成空转。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def mutate_module_segment(src_path, *, region: tuple, old: str, new: str,
                          tmp_path, module_name: str):
    """加载一份把 `region` 段内 `old` 换成 `new` 的 `src_path` 副本。

    `region` 是 (起始锚点, 结束锚点) 两个源码片段——通常是签发那个函数的 `def` 行与
    下一个 `def` 行。段内 `old` 必须**恰好出现一次**，否则直接失败（宁可让变形测试
    报"锚点失效"，也不要它悄悄改到别的地方）。

    返回加载好的模块。调用方负责把假 SSM / 假 client 之类挂回副本上——副本自带一份
    干净的模块级缓存，夹具打在真模块上的补丁不会自动生效。

    **副本不会留在 `sys.modules` 里**（3c-1B-G A5）：它的 `__file__` 指向 `tmp_path`，
    那个目录在用例结束后就被删了。留着的话，本次 pytest 会话里后面任何
    `import <module_name>` / `importlib.reload` 都会拿到一个文件已经不存在的陈旧模块。
    exec 期间需要它在 `sys.modules`（模块内的自引用、dataclass 等要能找到自己），
    所以是"放进去 → exec → 还原"。
    """
    src = Path(src_path).read_text()
    start = src.index(region[0])
    # **结束锚点从 start 之后找**（3c-1B-G A5）：`src.index(end)` 从 0 开始搜，
    # 如果结束锚点在文件里更早处也出现（例如 `def _secret` 在 `def console_cookie` 上方），
    # 就会算出 end < start，然后报"锚点顺序反了：源文件结构变了？"——把调用方的锚点选择
    # 问题说成了源文件结构问题，读的人会去找一次根本没发生的重构。
    try:
        end = src.index(region[1], start + len(region[0]))
    except ValueError:
        earlier = region[1] in src
        raise AssertionError(
            f"结束锚点 {region[1]!r} 没有出现在起始锚点 {region[0]!r} **之后**"
            + ("（它只出现在起始锚点之前——两个锚点的顺序给反了）" if earlier
               else "（它在这个文件里根本不存在）")) from None
    seg = src[start:end]
    if seg.count(old) != 1:
        raise AssertionError(
            f"锚点 {old!r} 在 {region[0]!r} 段里出现 {seg.count(old)} 次，必须恰好 1 次"
            "——变形测试会改到别处（或什么都没改），那就成了空转的假守卫")
    path = Path(tmp_path) / f"{module_name}.py"
    path.write_text(src[:start] + seg.replace(old, new) + src[end:])
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    had = module_name in sys.modules
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        if had:
            sys.modules[module_name] = previous
        else:
            sys.modules.pop(module_name, None)
    return mod
