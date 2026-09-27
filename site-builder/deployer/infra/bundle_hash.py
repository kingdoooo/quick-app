"""deployer 步骤函数的 CDK asset hash：覆盖**全部**进包输入（纯标准库，单测不需要 aws_cdk）。

CDK 默认的 SOURCE hash 只看 `/asset-input`（functions/）与 bundling 选项的字符串，**挂载卷的内容
不进 hash**。于是只改 contract/ 或锁定清单时 S3Key 不变 ⇒ `cdk diff` 零差异、`cdk deploy` 什么都
不部；`rm -rf cdk.out` 也救不了——重打的包里是新字节，但同名 key 已在 bootstrap 桶里，上传与
Lambda 更新都被跳过（2026-09-27 实测：改了 `redlines.py`，重打的 bundle 里是新内容，S3Key 不变）。

三条不变量：
  ① 进包的任何输入变了（源码树、每个挂载里被读的文件、命令 / 镜像 / 平台）⇒ hash 变；
  ② 同样的内容在任何位置、任何机器上 hash 相同（只按相对路径 + 字节，跳过宿主机专属的垃圾）；
  ③ 每个挂载都必须声明它被读的是哪些宿主路径——漏一个就在 synth 期抛错，而不是让同一个洞
     换个名字回来。**它保证不了"命令只读了声明的那些"**：那一半靠 `reads` 与命令同处一段代码、
     一起 review。
"""
import hashlib
import json
from pathlib import Path

# 改 hash 的算法本身时加一，强制全部步骤函数重部一次
SCHEME = "sb-bundle-v1"
# 宿主机专属、与部署内容无关：测试留下的字节码、Finder 元数据
_JUNK_DIRS = frozenset({"__pycache__"})
_JUNK_SUFFIXES = (".pyc",)
_JUNK_NAMES = frozenset({".DS_Store"})


def _files(root: Path):
    if root.is_file():
        yield root.name, root
        return
    if not root.is_dir():
        raise FileNotFoundError(f"bundling 输入不存在：{root}")
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if (not p.is_file() or _JUNK_DIRS & set(rel.parts[:-1])
                or p.name in _JUNK_NAMES or p.name.endswith(_JUNK_SUFFIXES)):
            continue
        yield rel.as_posix(), p


def bundle_asset_hash(source_dir, bundling: dict, *, reads: dict) -> str:
    """`reads`：containerPath → 命令实际读的宿主路径（文件或目录）。必须与 `volumes` 一一对应。"""
    mounts = {v["containerPath"]: Path(v["hostPath"]) for v in bundling.get("volumes", [])}
    if set(reads) != set(mounts):
        raise ValueError(
            f"bundling 的挂载 {sorted(mounts)} 与声明的读取 {sorted(reads)} 不一致："
            f"没声明的挂载内容不进 asset hash，改了它 cdk deploy 什么都不部")
    for cp, paths in reads.items():
        for p in paths:
            if not Path(p).resolve().is_relative_to(mounts[cp].resolve()):
                raise ValueError(f"{cp} 声明读取 {p}，但它不在该挂载的 hostPath {mounts[cp]} 之下")
    image = bundling["image"]
    h = hashlib.sha256()
    h.update(json.dumps({"scheme": SCHEME, "command": list(bundling["command"]),
                         "platform": bundling.get("platform"),
                         "image": image if isinstance(image, str) else image.image},
                        sort_keys=True).encode())
    roots = [("/asset-input", Path(source_dir))] + [
        (f"{cp}/{Path(p).relative_to(mounts[cp]).as_posix()}", Path(p))
        for cp in sorted(reads) for p in sorted(reads[cp])]
    for label, root in roots:
        for rel, path in _files(root):
            data = path.read_bytes()
            h.update(f"\0{label}/{rel}\0{len(data)}\0".encode())
            h.update(data)
    return h.hexdigest()
