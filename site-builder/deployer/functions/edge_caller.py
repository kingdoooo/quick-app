"""Function URL 的调用者是否真是 Edge 执行角色。**唯一实现**。

**谁用它**：panel 与 key-proxy 都把它作为第 ⓪ 步传输层校验；两者都在构建时
把本文件复制进部署包（panel 见 deploy_panel.COPY_FILES）。deployer 自己的
Lambda 打包**整个 functions/ 目录**，所以物理落点在这里——放 panel/ 会让
key-proxy 复制不到，放任一侧都会让另一侧变成"跨包 import"（与 ops_log.py
完全相同的理由）。

**为什么必须提成一份**：panel 与 key-proxy 是同一个缺陷面（同账号 principal
能绕开 resource policy 直连）。这份判定有四个易错点（AROA 段、`:` 边界、
大小写、缺配置即拒），同一逻辑存在两处时"改对一处、漏改另一处"正是本项目
反复出现的缺陷形态。

**为什么锚点是 RoleId 而不是 ARN**：见 caller_is_edge 的 docstring——真机抓
到的 callerId 是 STS 形态，与 config.ini 里的 role ARN **永不相等**。

**缺配置即全拒**：`EDGE_ROLE_ID` 未配置/为空时返回 False 并打 ERROR。
"配置缺失就不检查"恰是该缺陷的原始形态——鉴权字段的"默认值"往往正好是
"放宽"。宁可整站拒绝也不留绕过路径；ERROR 日志是这条拒绝唯一的可告警线索。
"""
import logging
import os

logger = logging.getLogger(__name__)

# 环境变量名。部署脚本引用这个常量，不再各自写字符串字面量——手抄的第二份
# 真源会漂移（下发了 A、代码读 B，两侧单测都绿而线上全拒）。
EDGE_ROLE_ID_ENV = "EDGE_ROLE_ID"


def caller_is_edge(event: dict) -> bool:
    """请求的 **IAM 调用者**是否就是 Edge 的执行角色。

    为什么不能只靠 resource policy（Codex 审查 2026-08-10 P1-1，已真机验证）：
    AWS 的规则是"同账号 principal 只要 identity policy 允许
    lambda:InvokeFunctionUrl + lambda:InvokeFunction，**无需命中 resource
    policy** 也能调用"。实测直接签名调用线上 Function URL 并自带
    x-user-email，`/api/me` 返回 200 且识别成管理员、`/api/sites?all=1`
    返回全部站点。所以"x-user-email 存在 ⇒ 来自 Edge"这个推论必须由本函数
    补上，不能只写在注释里。

    **锚点是 callerId 的 AROA 段，不是 config 里的 edge_role_arn**。
    真机抓到的形态（用一次性 probe Function URL 挂在真 Edge 后面测得。
    RoleId 本体按仓库红线打码成 `AROA<20 位大写字母数字>`——形态是这里唯一
    有信息量的部分，真值现查 `aws iam get-role`；写出整串会被 Code Defender
    的 HARD_CODED_SECRET 拦下，而放宽扫描器不是本项目的方向）：
        userArn : arn:aws:sts::<acct>:assumed-role/<EdgeRoleName>/us-east-1.<...>
        callerId: AROA<...>:us-east-1.ApplicationWebRouterStack-<...>
    而 config.ini 里是 `arn:aws:iam::<acct>:role/<EdgeRoleName>`——两者**永不
    相等**，拿它逐字符比会 403 整个控制台。callerId 冒号前那段是角色的
    RoleId（已核对 == `aws iam get-role` 的 Role.RoleId），由 STS 填写，
    调用方不可伪造。session name 段含区域前缀且会变，不参与判定。

    **按 `:` 边界比，不用 startswith/in**：`{id}EVIL:s` 骗得过 startswith，
    `AIDAX:{id}` 骗得过 in。
    """
    expected = os.environ.get(EDGE_ROLE_ID_ENV, "").strip()
    if not expected:
        # **配置缺失不得退化成"不检查"**：本项目记录过这个陷阱形态——
        # 鉴权字段的"默认值"往往正好是"放宽"。宁可整站拒绝也不留绕过路径。
        logger.error("EDGE_ROLE_ID 未配置——无法确认调用者是 Edge，拒绝所有请求")
        return False
    # 每层都 `or {}`：event 里这些层级可能**显式为 null**（真实 payload 见过），
    # 此时 `.get` 会抛 AttributeError → 502。而 502 与 403 的运维含义完全不同
    # （前者像故障、后者是策略），排查方向会被带偏。缺字段必须是"拒绝"。
    iam = ((event.get("requestContext") or {}).get("authorizer") or {})
    caller = (iam.get("iam") or {}).get("callerId") or ""
    if ":" not in caller:
        # 必须是 assumed-role 形态 `{RoleId}:{session_name}`。**这一条比
        # 44aef8d 的 panel 实现更严**：那份只做 `split(":")[0] == expected`，
        # 于是裸 `{RoleId}`（无 session 段）也会被放行。真机 Edge 一定带
        # session 段（见下方抓到的形态），所以收紧它不会 403 控制台。
        return False
    # assumed-role 的 callerId 是 `{RoleId}:{session_name}`；只取角色段比较。
    role_id = caller.split(":", 1)[0]
    return role_id == expected
