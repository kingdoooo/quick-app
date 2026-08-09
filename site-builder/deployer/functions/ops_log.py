"""操作审计（append-only）。**唯一写入点**。

被 permissions.py 的高层写函数与 undeploy 路径调用，因此 MCP 与控制台
自动同轮覆盖（spec §5.5）——落在 panel handler 会让 MCP 侧漏记。

**为什么物理放在 deployer/functions/ 而不是 panel/**：permissions.py 要
import 它，而 deployer 的 Lambda 打包只复制 functions/ 目录。放 panel 会让
deployer 侧运行时 ImportError。panel 侧照 common.py / permissions.py 的
既有模式在构建时复制过来。

两条硬规则：
① **只 PutItem**，不 update/delete——审计记录不可改写（IAM 侧也只给 PutItem，
   由 contract test 锁定）；
② **业务成功 + 落日志失败 → 业务仍算成功**。审计是旁路，不能把一个已经提交
   的权限变更变成"用户不知道成没成"的未知状态。所以 record() 内部吞异常并打
   ERROR 日志，调用方不需要 try。
"""
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
TTL_DAYS = 400
DETAIL_MAX = 1024

# 绝不入库的字段名（大小写不敏感的子串匹配）。detail 里命中即**整键丢弃**。
_SENSITIVE = ("secret", "token", "cookie", "authorization", "password",
              "api_key", "apikey", "credential", "jwt")
_ddb = None


def _table():
    global _ddb
    if _ddb is None:
        _ddb = boto3.resource("dynamodb", region_name=os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"))
    return _ddb.Table(os.environ["OPS_LOG_TABLE"])


def _scrub(detail) -> str:
    """detail 只允许扁平的可 JSON 化小结构：敏感键整体丢弃 + 长度截断。

    截断是必要的：上游错误原文可能极长，一条巨型 detail 会撑爆审计行
    （DynamoDB 单 item 400KB 上限，且审计的价值在可读不在完整转录）。
    """
    if detail is None:
        return ""
    if isinstance(detail, dict):
        detail = {k: v for k, v in detail.items()
                  if not any(s in str(k).lower() for s in _SENSITIVE)}
    try:
        out = json.dumps(detail, default=str, ensure_ascii=False)
    except Exception:
        out = "<unserializable>"
    return out[:DETAIL_MAX]


def _put(**item) -> None:
    """真正的写入。测试用 monkeypatch 替换它来模拟落库失败。"""
    _table().put_item(Item=item)


def record(*, actor: str, action: str, target: str, result: str,
           detail=None, request_id: str = "") -> None:
    """写一条审计。**任何异常都被吞掉**——见模块 docstring 第 ② 条。

    SK 是 `{ts}#{actor}`：带上时间戳才能让同一 target 上的多次操作共存
    （只用 actor 会让后一条覆盖前一条，append-only 就失效了）。
    """
    try:
        now = datetime.now(timezone.utc)
        _put(target=target,
             ts_actor=f"{now.isoformat()}#{actor}",
             actor=actor, action=action, result=result,
             detail=_scrub(detail), request_id=request_id or "",
             expires_at=int(time.time()) + TTL_DAYS * 86400)
    except Exception:
        # 不 re-raise：业务动作已经成功，审计失败不能改变它的结果
        logger.exception("ops-log 写入失败 action=%s target=%s", action, target)
