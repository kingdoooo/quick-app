"""API Key 的生成与哈希。**算法的唯一实现**（二期 M4，spec §5.1）。

**谁用它**：创建端在 panel（`POST /api/keys`）、校验端在 key-proxy（拿明文算
hash 再查库）。算法只能有一份——两份实现里"改对一处、漏改另一处"会让新发的
Key 全部验不过，或更糟：让某种旧形态的 Key 一直能用。

**为什么物理落点在 deployer/functions/**：deployer 自己的 Lambda 打包**整个
functions/ 目录**，panel 与 key-proxy 则在构建时各自复制单个文件出来（panel
见 deploy_panel.COPY_FILES）。放 panel/ 会让 key-proxy 复制不到，放任一侧都
会让另一侧变成"跨包 import"。与 ops_log.py / edge_caller.py 完全相同的理由。

**模块不得 import boto3、也不得读环境变量**：它是纯算法模块，被两侧复制。
带上 I/O 依赖会让两侧的复制清单闭包多牵进无关模块（复制清单的传递闭包断言
会因此变宽，而那条断言正是"部署产物里到底有什么"的唯一守卫）。
"""
import hashlib
import re
import secrets
import string
from typing import NamedTuple

# base62。**刻意不含 `-` / `_`**：Key 会被粘进 URL、shell、YAML、HTTP 头，
# 也会被人工双击选中——base62 在这些场合全部无歧义、无需转义。
ALPHABET = string.digits + string.ascii_letters

# 明文形态：`sk-` + 16 位 base62 = 16 × log2(62) ≈ 95.27 bit。
PLAINTEXT_LEN = 16
# 展示用前缀长度（明文的前 4 位随机字符）。`sk-` + 4 = 7 字符。
PREFIX_RANDOM_LEN = 4
# 非秘密标识符长度。8 × log2(62) ≈ 47.6 bit——够做标识符，且**是给人看/给人粘
# 的**，加长会牺牲那个用途。线上唯一性不靠长度，靠写入侧的"Query 检测 + 重试"
# 与吊销侧的"行数 ≠ 1 即 fail-closed"（Codex P2-7）。
KEY_ID_LEN = 8

# 入口形态校验。**先验形态再查库**：形态不对直接拒，既不产生一次 DynamoDB
# 读（省掉一条免费的探测通道），也避免把任意长字符串当 key 去 hash。
PLAINTEXT_RE = re.compile(rf"^sk-[0-9A-Za-z]{{{PLAINTEXT_LEN}}}$")

# 哨兵行主键值：平台级 Key 总开关那一行的 PK。keystore 与 deploy 脚本共用
# 这一个常量，不各自写字符串字面量（手抄的第二份真源会漂移）。
#
# **它与任何真 hash 都不可能碰撞**：真 hash 是 64 位小写 hex，本值含下划线。
# 这一条有断言而不是靠"显然"——将来若有人把 hash 换成 base64 形态，`_` 就在
# 字符集里了，那时用户能用一把精心构造的 Key 命中哨兵行、自己写平台开关。
SWITCH_PK = "__switch__"


class NewKey(NamedTuple):
    """一次生成的四个值。

    plaintext 只在创建响应里出现这一次，服务端**不落库**（落库的是 key_hash）。
    """
    plaintext: str
    key_hash: str
    key_id: str
    prefix: str


def _random_base62(n: int) -> str:
    """逐位 `secrets.choice`。

    **不用 `secrets.token_urlsafe` 再截断**：那会引入 `-` / `_`（见 ALPHABET
    的理由），而且截断后的熵不可控——token_urlsafe(n) 的字符数不等于 n，
    按字符截断实际保留多少 bit 取决于 base64 的对齐，容易写成比预期少一截。
    """
    return "".join(secrets.choice(ALPHABET) for _ in range(n))


def hash_key(plaintext: str) -> str:
    """SHA-256 hex。**校验端的唯一入口**。

    不做形态校验——它只是哈希函数，形态校验是 `PLAINTEXT_RE` 的职责。分工
    刻意分开：把校验塞进这里，调用方就会以为"hash 过了就等于形态对"，而形态
    校验必须发生在**更早**（查库之前）。

    单向且无盐是有意的：库里存 hash，被读走时攻击者拿不到可用的 Key；而输入
    本身是 95 bit 的均匀随机串，不存在字典攻击面，加盐只会让"拿明文查库"变成
    没法用 PK 直查（每次都要遍历候选盐）。
    """
    return hashlib.sha256(plaintext.encode()).hexdigest()


def new_key() -> NewKey:
    """生成一把新 Key。

    **`key_id` 独立随机，绝不由 `key_hash` 派生**（spec §5.1）：派生会让它
    变成哈希预言机——`key_id` 是**非秘密**（列在控制台里、进日志），拿到它
    就能验证对 `key_hash` 的猜测。这是本模块最重要的性质，除行为断言外还有
    一条 AST 级断言盯着（行为断言抓不到"对 hash 再做一次 hash"这种派生）。
    """
    plaintext = "sk-" + _random_base62(PLAINTEXT_LEN)
    key_hash = hash_key(plaintext)
    # 独立的一次随机取样——上面那行的任何产物都不参与。
    key_id = _random_base62(KEY_ID_LEN)
    prefix = plaintext[:3 + PREFIX_RANDOM_LEN]
    return NewKey(plaintext=plaintext, key_hash=key_hash, key_id=key_id,
                  prefix=prefix)
