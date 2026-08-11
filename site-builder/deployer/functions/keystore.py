"""`site-api-keys` 表的**唯一访问层**（二期 M4，spec §5.1 / §5.2）。

**核心不变量：不缓存。** 授权数据（开关状态、`key_hash → email` 的映射）每次
判定都现读。缓存了"即时吊销"就不成立，而即时吊销正是本设计存在的全部理由
（spec §5.1）。Lambda 的模块级变量**跨请求存活**，所以"我没写缓存"不构成保证
——两层断言盯着它：`deployer/tests/test_keystore.py` 数读次数（行为层），
`key-proxy/tests/test_no_module_level_cache.py` 用 AST 看容器与装饰器（结构层）。
唯一允许缓存的模块是 `key-proxy/machine_token.py`（那是组件自身的凭证，
与"哪个用户在调"无关）。

**谁用它**：key-proxy 用 `lookup` / `touch_last_used`；panel 用 `create` /
`list_for` / `revoke` / `switch_state` / `set_switch`。**两个组件都要**，所以
物理落点在 `deployer/functions/`——panel 与 key-proxy 的复制清单闭包都只搜
`deployer/functions` 与 `auth`（`panel/tests/test_deploy_panel_contract.py`）。
与 `keygen.py` / `ops_log.py` / `edge_caller.py` 完全相同的理由。

**为什么整张表只能有一个访问层**：哨兵行的形态只能有一个定义——panel 写它、
key-proxy 读它。拆成两个模块就等于把"`enabled` 必须是布尔 `True`"这条不变量
写两遍；写入侧写成字符串、读取侧按布尔判，症状是"控制台显示开着但所有 Key
都 401"，而两侧单测各自都绿。这正是本项目反复出现的缺陷形态
（M3-FINDINGS「别打地鼠，修那一类」）。`permissions.py` 当年同理收口。

**key-proxy 的包里会有它不需要的 `create`**：有意接受。key-proxy 的 role
**没有** `PutItem`（Task 8 的断言锁定），那条路径在真机上会 AccessDenied
——代码在但权限不在，是纵深而非缺陷；拆模块的代价（上一段）更大。

**两个方向刻意相反，别"统一"它们**：
  · 开关 `enabled is not True` → 拒（**只有显式布尔 True 才开**）；
  · `revoked` 任何真值 → 拒（**只要像真就关**）。
两边都取最严的那一侧。写成同一个方向就必有一侧变松。
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
import botocore.exceptions
from boto3.dynamodb.conditions import Key

import common
import keygen
import ops_log
# 邮箱形态判定**借 permissions.EMAIL_RE**，不在这里再写一条正则：两条正则
# 迟早会分叉，而分叉的症状是"某个邮箱能建 Key 但建出来的 Key 判不过"。
# 代价是 key-proxy 的部署包要跟着带上 permissions.py（及其闭包 common.py /
# ops_log.py）——Task 8 的复制清单断言会明确要求它，这是清单该有的样子。
import permissions
from keygen import SWITCH_PK        # noqa: F401  （对外再导出，见下）

logger = logging.getLogger(__name__)

# `SWITCH_PK` 从 keygen **再导出**（同一个常量，不重新定义）：调用方
# （panel、deploy_key_proxy.py）只需 import keystore 就够，不必知道哨兵行
# 主键这个细节住在哪个模块；而"再定义一份字符串字面量"就是第二份真源。

# last_used_at 的节流窗口：每 Key 每小时至多一次写（spec §5.2）。
TOUCH_INTERVAL_SECONDS = 3600
# key_id 碰撞的重试上限。GSI **不提供**唯一约束且是最终一致的，唯一性只能由
# 写入路径保证（Codex P2-7）；上限存在是为了不让碰撞（或索引异常）变成死循环。
MAX_KEY_ID_ATTEMPTS = 5
# 备注长度上限。它会进控制台列表与审计 detail，不设上限时一条超长备注能把
# 列表页撑爆（ops_log 侧另有 DETAIL_MAX 截断）。
NAME_MAX = 64

# **测试观察窗，不是缓存**：记录最后一次两个读实际传给 boto3 的
# `ConsistentRead` 值。里面只有两个布尔，既没有 key_hash 也没有 email，拿到它
# 推不出任何 Key 的状态——所以它在 test_no_module_level_cache 的白名单里。
# 记的是**真实 kwargs 的值**而不是常量 True：写死 True 就等于把
# test_both_reads_are_strongly_consistent 变成一条永远绿的装饰。
LAST_READ_CONSISTENCY = {}

_ddb = None


class KeystoreError(Exception):
    """本模块所有写路径失败的基类。panel 侧按子类分流状态码。"""


class KeyNotFound(KeystoreError):
    """吊销目标不存在，**或**存在但不属于调用者。

    **两种情况刻意同一个异常同一句文案**：区分开就是枚举探测器——key_id 是
    8 位 base62，能区分"不存在"与"不是你的"就能扫出别人的 key_id。
    同 permissions.require 对"站点不存在/无权访问"的既有处理。
    """


class AmbiguousKeyId(KeystoreError):
    """`keyid-index` 对同一个 key_id 返回了 ≥2 行 → **一律 fail-closed**。

    绝不能"取第一行改掉"：那会误吊销别人的 Key，而受害者完全无从察觉。
    """


class KeyIdUnavailable(KeystoreError):
    """连续 MAX_KEY_ID_ATTEMPTS 次都撞上已存在的 key_id。

    正常概率下不可能（47.6 bit）；真发生说明随机源坏了或索引在返回垃圾，
    此时**不发 Key** 比发一把与别人 key_id 相同的 Key 安全——后者会让吊销
    命中两行，直接触发上面的 AmbiguousKeyId。
    """


class Verdict(tuple):
    """`lookup` 的结论。`reason` **只进日志**，不回给客户端。

    为什么 reason 不能出网：无效 / 吊销 / 关闸 / 未知 Key 对调用方必须是同一句
    话同一状态码（spec §8），否则调用方能区分"这把 Key 不存在"与"这把 Key
    被吊销了"与"平台关闸了"。
    """
    __slots__ = ()

    def __new__(cls, ok: bool, email: str, key_id: str, reason: str):
        return tuple.__new__(cls, (ok, email, key_id, reason))

    ok = property(lambda self: self[0])
    email = property(lambda self: self[1])
    key_id = property(lambda self: self[2])
    reason = property(lambda self: self[3])


def _table():
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"))
    return _ddb.Table(os.environ["API_KEYS_TABLE"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_conditional_check_failure(e: Exception) -> bool:
    return (isinstance(e, botocore.exceptions.ClientError)
            and e.response.get("Error", {}).get("Code")
            == "ConditionalCheckFailedException")


# ---------------------------------------------------------------- 两个读入口
# 只有这两个函数读授权数据。测试 monkeypatch 它们做计数、顺序与故障注入——
# 所以 lookup 必须**经模块全局**调用它们（不要 `from ... import`，也不要在
# lookup 里内联 get_item，那样注入就落不到实处，用例会变成永远绿）。

def _get_switch_row() -> dict | None:
    """强一致读哨兵行。**不重试**——见 lookup 的 docstring。"""
    kwargs = dict(Key={"key_hash": SWITCH_PK}, ConsistentRead=True)
    LAST_READ_CONSISTENCY["switch"] = kwargs["ConsistentRead"]
    return _table().get_item(**kwargs).get("Item")


def _get_key_row(key_hash: str) -> dict | None:
    """强一致读 Key 行。最终一致读会留下"吊销后仍放行"的窗口。"""
    kwargs = dict(Key={"key_hash": key_hash}, ConsistentRead=True)
    LAST_READ_CONSISTENCY["key"] = kwargs["ConsistentRead"]
    return _table().get_item(**kwargs).get("Item")


def _query_by_key_id(key_id: str) -> list[dict]:
    """`keyid-index` 的**唯一**查询入口（吊销路径用）。

    GSI 读不能 ConsistentRead（DynamoDB 不支持），所以它的结果只是"候选"：
    落地那一步必须由 UpdateItem 的条件表达式重新断言 key_id + email。
    """
    return common._paginate(_table().query, IndexName="keyid-index",
                            KeyConditionExpression=Key("key_id").eq(key_id))


# ------------------------------------------------------------------- 校验端

def lookup(plaintext: str) -> Verdict:
    """明文 → 身份。**先开关后 Key，两次独立的强一致 GetItem。**

    顺序严格是：形态 → 开关（关即 return）→ Key → `revoked` → `email` 形态。

    **不合并成 `BatchGetItem`**：一次 BatchGet 必然把 Key 行一起请求了，
    "关闸期间零 Key 查询、零写"这条短路就不成立（Codex P2-6）。也**不用
    `TransactGetItems`** 去追求原子快照：两个值之间没有需要原子性的不变量
    （开关关了就拒，与 Key 行当时是什么状态无关），那只会带来两倍读容量
    与一条多余的 `dynamodb:TransactGetItems` 权限。

    **两个读都不重试**：重试会把一次限流放大成多次，而转发本身已有超时预算。
    任何读失败、被节流、行不存在、值脏 → 一律拒。绝不出现"开关读失败但 Key
    看着没问题，那就放行"。

    **不在这里更新 last_used_at**：那是遥测，由 key-proxy 在转发成功后单独
    调 `touch_last_used`（plan Task 5 第 ⑤ 步）。放进 lookup 会让关闸/拒绝
    路径也产生写，且与 handler 的调用重复成两次写。
    """
    if not isinstance(plaintext, str) or not keygen.PLAINTEXT_RE.fullmatch(plaintext):
        # **形态不对时不查库**：省一次读（少一条免费的存在性探测通道），
        # 也避免把任意长字符串当 key 去 hash。
        return Verdict(False, "", "", "malformed-plaintext")

    try:
        switch = _get_switch_row()
    except Exception:
        # 读不到就不知道开关状态，此时放行等于开关形同虚设。
        logger.exception("开关读取失败——拒绝本次请求")
        return Verdict(False, "", "", "switch-read-failed")
    if switch is None:
        # 表刚建好还没跑部署脚本 → 默认必须是关（fail-closed）。
        logger.warning("哨兵行不存在——API Key 通道视为未开启")
        return Verdict(False, "", "", "switch-row-missing")
    if switch.get("enabled") is not True:
        # `is not True` 而不是 `not enabled`：M3 实测四种非布尔形态
        # （{"NULL":true}、{"N":"0"}、{"L":[]}、未识别类型）都能骗过后者，
        # 而 Decimal(1) == True 还会让 `"1"` 这种脏值把闸门打开。
        return Verdict(False, "", "", "switch-off")

    key_hash = keygen.hash_key(plaintext)
    if key_hash == SWITCH_PK:
        # 纵深：真 hash 是 64 位小写 hex，SWITCH_PK 含下划线，二者不可能相等
        # （test_keygen 的 test_switch_sentinel_cannot_be_produced_by_any_real_hash
        # 锁定这个前提）。留这一条是因为前提一旦被改动（比如 hash 换 base64
        # 形态），命中哨兵行就等于让用户拿一把构造的 Key 读到平台开关行。
        return Verdict(False, "", "", "sentinel-collision")
    try:
        row = _get_key_row(key_hash)
    except Exception:
        # 不能因为"开关是开的"就放行。
        logger.exception("Key 读取失败——拒绝本次请求")
        return Verdict(False, "", "", "key-read-failed")
    if row is None:
        return Verdict(False, "", "", "unknown-key")

    # key_id 是**非秘密**（列在控制台里、进日志），拒绝时带上它才排查得动。
    # 明文与 key_hash 都不进 Verdict，因此也进不了任何日志。
    key_id = str(row.get("key_id") or "")
    if row.get("revoked"):
        # 这一侧是 `if truthy`——与开关方向相反，见模块 docstring。
        return Verdict(False, "", key_id, "revoked")

    email = row.get("email")
    if not isinstance(email, str) or not permissions.EMAIL_RE.fullmatch(email):
        # 脏数据不能变成"以空身份调用"：下游 `_caller_email` 会拿到空串，
        # 而空串在 permissions 里是"谁都不是"——那会走到很意外的分支上。
        logger.error("Key 行的 email 形态非法 key_id=%s", key_id)
        return Verdict(False, "", key_id, "dirty-email")

    # **拒绝时 email 一律为空串**：这样下游即使误用了一个 ok=False 的 Verdict，
    # 也拿不到一个能冒充别人的身份。
    return Verdict(True, email, key_id, "ok")


def _update_last_used(key_hash: str) -> None:
    """真正的节流写。测试 monkeypatch 它来模拟更新失败。

    节流靠 `ConditionExpression` 而不是"先读再写"：并发下"先读再写"会两边都
    看到旧值、两边都写（每小时一次的承诺就没了，而这张表每次 MCP 调用都要读，
    多余的写直接摊在热路径上）。

    `attribute_exists(key_hash)` **不可省**：UpdateItem 默认会**创建**不存在的
    item，缺这一条时一次针对未知 hash 的 touch 会往凭证表里凭空写一行
    （没有 email / revoked 的半行数据，且它进不了任何 GSI，几乎不可能被发现）。
    """
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=TOUCH_INTERVAL_SECONDS)).isoformat()
    _table().update_item(
        Key={"key_hash": key_hash},
        UpdateExpression="SET #lu = :now",
        ConditionExpression=("attribute_exists(key_hash) AND "
                             "(attribute_not_exists(#lu) OR #lu < :cutoff)"),
        ExpressionAttributeNames={"#lu": "last_used_at"},
        ExpressionAttributeValues={":now": now.isoformat(), ":cutoff": cutoff})


def touch_last_used(key_hash: str, key_id: str) -> None:
    """更新 last_used_at（每 Key 每小时至多一次）。**永不抛异常。**

    它是遥测不是授权：更新失败不得影响转发。所以调用方不需要 try——
    把"最后使用时间没记上"升级成"这次 MCP 调用失败"是明显更坏的交换。
    """
    try:
        _update_last_used(key_hash)
    except Exception as e:
        if _is_conditional_check_failure(e):
            # 条件未通过 = 一小时内已经写过 = 节流**正常生效**，不是错误。
            logger.debug("last_used_at 处于节流窗口内，跳过 key_id=%s", key_id)
            return
        logger.warning("last_used_at 更新失败（不影响转发）key_id=%s: %s",
                       key_id, type(e).__name__)


# --------------------------------------------------------------- 管理端（panel）

def create(email: str, *, name: str) -> dict:
    """发一把新 Key。返回值含 `plaintext`——**服务端唯一一次**出现它。

    `key_id` 唯一性由本路径保证（Codex P2-7）：GSI 没有唯一约束，而吊销侧
    以"行数 == 1"为前提。做法是 Query 探测 + 重试；GSI 最终一致所以这是
    best-effort，真正兜住误吊销的是 revoke 的 fail-closed。

    `PutItem` 带 `attribute_not_exists(key_hash)`：hash 碰撞概率是天文数字，
    但"静默覆盖一行凭证"意味着**把别人的 Key 换成自己的**，宁可报错重试。
    """
    if not isinstance(email, str) or not permissions.EMAIL_RE.fullmatch(email):
        raise ValueError(f"非法邮箱: {email!r}")
    name = name.strip() if isinstance(name, str) else ""
    if not name or len(name) > NAME_MAX:
        raise ValueError(f"备注必须非空且不超过 {NAME_MAX} 字")

    for attempt in range(1, MAX_KEY_ID_ATTEMPTS + 1):
        # 经 `keygen.new_key()` 而不是 `from keygen import new_key`：测试要能
        # 注入一次碰撞才能覆盖重试分支，绕开这个 hook 会让该分支永远测不到。
        k = keygen.new_key()
        if _query_by_key_id(k.key_id):
            # 不打 key_id 以外的任何东西——明文绝不进日志。
            logger.warning("key_id 碰撞，重试 attempt=%d", attempt)
            continue
        item = {"key_hash": k.key_hash, "key_id": k.key_id, "email": email,
                "name": name, "prefix": k.prefix, "revoked": False,
                "created_at": _now_iso(), "last_used_at": ""}
        try:
            _table().put_item(
                Item=item, ConditionExpression="attribute_not_exists(key_hash)")
        except Exception as e:
            if _is_conditional_check_failure(e):
                logger.warning("key_hash 已存在，重新生成 attempt=%d", attempt)
                continue
            raise
        ops_log.record(actor=email, action="create_api_key",
                       target=f"apikey:{email}", result="ok",
                       detail={"key_id": k.key_id, "name": name})
        # **不回 key_hash**：没有任何调用方需要它（吊销走 key_id），而它是
        # 这张表最值得保护的字段。panel 的 `_shape_key` 会再挡一层——两层都
        # 挡不等于其中一层可以省。
        return {"plaintext": k.plaintext, "key_id": k.key_id, "name": name,
                "prefix": k.prefix, "email": email, "revoked": False,
                "created_at": item["created_at"], "last_used_at": ""}
    raise KeyIdUnavailable(f"连续 {MAX_KEY_ID_ATTEMPTS} 次都无法取到唯一 key_id")


def list_for(email: str) -> list[dict]:
    """某人的全部 Key（含已吊销的——控制台要显示吊销状态）。

    走 `email-index`。**哨兵行不会出现在这里**：它没有 email 属性，因此
    天然不进这个 GSI（test_switch_row_never_appears_in_email_index 盯着这条，
    因为"将来有人给哨兵行加个 email 字段"就会让它冒进某个人的列表）。

    `key_hash` **在这里就摘掉**，不留到 panel 再摘：调用方拿不到的东西才是
    真的不会泄漏。panel 的 `_shape_key` 是第二层。
    """
    if not isinstance(email, str) or not permissions.EMAIL_RE.fullmatch(email):
        raise ValueError(f"非法邮箱: {email!r}")
    rows = common._paginate(_table().query, IndexName="email-index",
                            KeyConditionExpression=Key("email").eq(email))
    return [{k: v for k, v in r.items() if k != "key_hash"}
            for r in sorted(rows, key=lambda r: str(r.get("created_at", "")))]


def revoke(key_id: str, *, actor: str) -> dict:
    """吊销一把 Key（置 `revoked`，**不删行**——删了就没有审计痕迹了）。

    `_query_by_key_id` 的结果**行数 ≠ 1 一律 fail-closed**：0 行是不存在，
    ≥2 行是索引里出现了同名 key_id。后者绝不能"取第一行"——那会误吊销别人的
    Key（AmbiguousKeyId 的 docstring 有完整理由）。

    落地的 `UpdateItem` 重新断言 `key_id` + `email`：Query 与 Update 之间有
    窗口，且 GSI 是最终一致的（可能返回一行已经被改过 key_id 的旧投影）。
    同 sites_snapshot_guard 的既有理由——鉴权用的快照必须在写入那一刻再验一次。
    """
    if not isinstance(key_id, str) or not key_id:
        raise KeyNotFound("Key 不存在或不属于你")
    rows = _query_by_key_id(key_id)
    if len(rows) != 1:
        if not rows:
            raise KeyNotFound("Key 不存在或不属于你")
        logger.error("keyid-index 对同一 key_id 返回 %d 行——拒绝吊销 key_id=%s",
                     len(rows), key_id)
        raise AmbiguousKeyId("该 key_id 命中多行，已拒绝吊销")
    row = rows[0]
    email = row.get("email")
    if not isinstance(email, str) or email != actor:
        # 与"不存在"共用同一句文案：区分开就能拿它枚举别人的 key_id。
        raise KeyNotFound("Key 不存在或不属于你")
    try:
        _table().update_item(
            Key={"key_hash": row["key_hash"]},
            UpdateExpression="SET #rv = :t, revoked_at = :n, revoked_by = :a",
            ConditionExpression="#kid = :kid AND #em = :em",
            ExpressionAttributeNames={"#rv": "revoked", "#kid": "key_id",
                                      "#em": "email"},
            ExpressionAttributeValues={":t": True, ":n": _now_iso(),
                                       ":a": actor, ":kid": key_id,
                                       ":em": email})
    except Exception as e:
        if _is_conditional_check_failure(e):
            # 条件失败 = 这一行在 Query 之后变了（或索引给的是旧投影）。
            # 不重试、不放宽条件，让调用方重新拉列表——这一步宁可不做也不能做错。
            raise KeyNotFound("Key 不存在或不属于你") from e
        raise
    ops_log.record(actor=actor, action="revoke_api_key",
                   target=f"apikey:{email}", result="ok",
                   detail={"key_id": key_id})
    return {"key_id": key_id, "revoked": True}


# --------------------------------------------------------------------- 总开关

def switch_state() -> tuple[bool, bool]:
    """`(deployed, enabled)`。**必须是两个值，不是一个 `switch_enabled()`**
    （Codex P1-5）。

    `deployed` = 哨兵行可读（组件跑过部署脚本）；`enabled` = 该行
    `enabled is True`。合成一个布尔时控制台无法区分"未部署"与"已部署但关闸"
    ——而首次部署后正好是后者（哨兵行建成关）。那时页面会 disabled，管理员
    无处点开闸，部署流程自锁。

    **读失败时抛异常，不返回 `(False, False)`**：本函数是展示/派生用，
    **不是**授权闸门（授权闸门是 lookup，它自己 fail-closed）。DynamoDB 抖一下
    就报"未部署"会按 §5.1.1 把控制台的 Key 页面整块 disabled，等于在故障期间
    额外剥掉管理员的关闸能力；让 panel 出 500 是更诚实的表达。
    """
    row = _get_switch_row()
    if row is None:
        return False, False
    return True, row.get("enabled") is True


def set_switch(enabled: bool, *, actor: str) -> None:
    """写哨兵行（整行覆盖，字段固定）并落审计。

    **只接受布尔**：`"false"` / `"0"` / `0` / `1` / `None` / `[]` 全部
    `ValueError`（panel 转 400）。写入侧收紧到布尔，读取侧才有资格用
    `is not True`——两侧一松一紧才是那个"控制台显示开着但全部 401"的经典缺陷。
    `isinstance(1, bool)` 是 False，所以数字 1 也被拦下，这是有意的。

    用 `PutItem` 而不是 `UpdateItem`：哨兵行的字段是固定的三个，整行覆盖能
    保证它**永远不带 `email` / `key_id`**——带了它就会冒进某个人的 Key 列表
    （GSI 的分区键就是这两个字段）。

    审计经 `ops_log.record()`，**不自己拼 SK**：它的 SK 形态
    （`{ts}#{actor}#{uniq}`，含防静默覆盖的随机后缀）已经在那里修好了
    （P2-1），手抄一份就是把那个缺陷再引入一次。
    """
    if not isinstance(enabled, bool):
        raise ValueError(f"enabled 必须是布尔值，收到 {type(enabled).__name__}")
    if not isinstance(actor, str) or not actor:
        raise ValueError("actor 不能为空——关闸/开闸必须记得下是谁做的")
    _table().put_item(Item={"key_hash": SWITCH_PK, "enabled": enabled,
                            "updated_at": _now_iso(), "updated_by": actor})
    ops_log.record(actor=actor,
                   action="enable_api_key_switch" if enabled
                   else "disable_api_key_switch",
                   target="apikey:switch", result="ok",
                   detail={"enabled": enabled})
