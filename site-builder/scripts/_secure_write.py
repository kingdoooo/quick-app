"""私有文件的**原子**落盘：同目录 0600 临时文件 + `os.replace`（3c-1B-G 复审三轮 P2）。

两个调用方都在写敏感内容——`verify_account_trust_boundary.py --dump-observed` 的快照（真实 principal
名/ARN/IAM 语句原文）与 `_session_mint.save_token` 的会话 cookie。此前两处都是
`os.open(path, O_WRONLY|O_CREAT|O_TRUNC, 0o600)` 再 `chmod`，有两个漏洞（Codex 用 symlink 复现）：

- **覆盖已有文件时 mode 不生效**：O_CREAT 的 mode 只作用于新建；已有的 0644 文件在整段写入期间仍是
  0644，写完的 chmod 也收不回别人已经打开的 fd。
- **`os.open` 跟随 symlink**：`atb.json → /etc/whatever` 会把目标截断改写成我们的内容，再把它 chmod 600。

同目录 `mkstemp`（本身就是 0600、名字不可预测）写完再 `os.replace`：新 inode 从诞生起就是 0600；
`rename(2)` 替换的是路径本身——symlink 被换成普通文件，其目标一个字节不动；持有旧 inode fd 的读者
只会继续看到旧内容。**同目录**是为了 `replace` 不跨文件系统。
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_private_text(path: Path, text: str) -> Path:
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)                     # mkstemp 已是 0600；显式写出来是为了不依赖它的实现细节
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)                    # 替换路径本身：symlink 被换掉而不是被跟随
    finally:
        Path(tmp).unlink(missing_ok=True)        # 成功时已被 replace 走；失败时不留半截临时文件
    os.chmod(path, 0o600)
    return path
