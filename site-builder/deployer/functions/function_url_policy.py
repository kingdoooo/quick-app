"""平台 Function URL 的 resource policy——**唯一实现**：期望集合、漂移判定、等值收敛。

**谁用它**：`auth/deploy_auth.py`、`panel/deploy_panel.py`、`key-proxy/deploy_key_proxy.py` 三个部署脚本
在构建期 import（不进它们的产物），`scripts/verify_deployed_components.py` 用同一个 `drift()` 断言线上。
物理落点与 `edge_caller.py` / `api_key_config.py` 同一个理由：三个脚本分别从 `site-builder/auth/`、
`site-builder/panel/`、`site-builder/key-proxy/` 执行，只有 `deployer/functions/` 是三者都能用同一条相对
路径 `sys.path.insert` 找到的目录。

**为什么"同名 StatementId 已存在就 pass"是错的**（merged review M07）：同名只说明有一条语句叫这个名字，
不说明它的内容是对的。三种真实漂移都让 Edge 调用 403 而部署脚本 exit 0：
  · edge role 被删后重建（router 栈重建 / 手工重创）——IAM 会把 resource policy 里的 Principal ARN 改写成
    已删角色的唯一 ID（`AROA…`），新角色同名不同 ID ⇒ 永不匹配；
  · `config.ini [Deployer] edge_role_arn` 改错后修正——旧语句授的是错的 principal；
  · 别的 Sid 下塞进的额外授权（`Principal:*`）——只替换自己那两条清不掉它。
auth 那条一挂 = 全平台登录不可用。

**收敛的写法（顺序是刻意的）**：读回 → 内容不对的同名语句先删再加 → 缺的补上 → 最后删野 Sid → 再读回
核对，仍不一致就抛。**先加后删**让"改 Sid 名"这种漂移零窗口（新语句已生效才删旧的）；同名内容错的那条
只能先删再加（Lambda 不允许两条同 Sid），那个亚秒级窗口本来就在 403 状态，没有可保的东西。
**读回核对是 fail-closed 的落点**：AWS 渲染出的语句形态（下面 `_rendered_condition`）若与本模块的假设
不同，第一次真机部署就会在这里响亮失败，而不是每次重跑都静默删了再加。

**语句的渲染形态（来源：AWS 文档 lambda/latest/dg/urls-auth，"Using the AWS_IAM auth type" 一节的示例）**：
`FunctionUrlAuthType=AWS_IAM` 渲染成 `Condition.StringEquals["lambda:FunctionUrlAuthType"] = "AWS_IAM"`；
`InvokedViaFunctionUrl=True` 渲染成 `Condition.Bool["lambda:InvokedViaFunctionUrl"] = "true"`（**操作符是 Bool
不是 StringEquals**，值是字符串）。比较时操作符、键、值三者都算——放宽任何一个都是在猜。

本模块**不 import boto3、不读配置、不读环境变量**：client 由调用方传入（三个脚本各自缓存 client，
`except lam.exceptions.X` 比对的是那个实例上的异常类）。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

# 与 `deployer/functions/deploy_lambda_site.py` 给站点色授权用的两个 Sid 同名。平台三条与站点函数的
# 语句形态因此一致（`deploy_lambda_site` 自己那段暂不 import 本模块，由 parity 用例钉住两边同形）。
EXPECTED_SIDS = ("edge-invoke", "edge-invoke-function")
FUNCTION_URL_AUTH_TYPE = "AWS_IAM"
# 没有 Sid 的语句：Lambda 的 add_permission 必然写 Sid，所以今天不可达；真出现时 remove_permission 拿不到
# StatementId，删不掉 ⇒ 只能响亮失败。用一个不可能是合法 Sid 的标记表示它。
NO_SID = "<no-sid>"

_READBACK_ATTEMPTS = 3
_READBACK_DELAY_SECONDS = 1.0
_sleep = time.sleep          # 测试可替换


class PolicyDriftError(RuntimeError):
    """收敛后读回仍不一致、或遇到无法收敛的形态（无 Sid 的语句）。调用方不得捕获后继续部署。"""


@dataclass(frozen=True)
class Drift:
    """一次比较的结果。三个字段都是 Sid 元组；`stray` 里可能含 `NO_SID`。"""
    missing: tuple = ()
    mismatched: tuple = ()
    stray: tuple = ()

    @property
    def ok(self) -> bool:
        return not (self.missing or self.mismatched or self.stray)

    def summary(self) -> str:
        if self.ok:
            return "一致"
        parts = []
        if self.missing:
            parts.append(f"缺 {len(self.missing)} 条({', '.join(self.missing)})")
        if self.mismatched:
            parts.append(f"内容不对 {len(self.mismatched)} 条({', '.join(self.mismatched)})")
        if self.stray:
            parts.append(f"非预期 {len(self.stray)} 条({', '.join(self.stray)})")
        return "、".join(parts)


def expected_statements(edge_role_arn: str) -> list[dict]:
    """两条 `add_permission` 的关键字参数（含 `StatementId`）。

    **缺 edge_role_arn 或给通配一律抛错**：fallback 到 `Principal:*` 会让 Function URL 全网可调，而 panel /
    key-proxy 的 handler 把"x-user-email 存在"当作"请求经过 Edge"的证据——两者一起失效意味着任何人都能
    伪造任意身份。
    """
    arn = (edge_role_arn or "").strip()
    if not arn:
        raise ValueError(
            "config.ini [Deployer] edge_role_arn 为空——Function URL 的调用者"
            "必须绑定到 exact edge role，不能放宽。请先部署路由层并回填该值")
    if "*" in arn or not arn.startswith("arn:aws:iam::"):
        raise ValueError(f"edge_role_arn 必须是精确的 IAM role ARN: {arn!r}")
    return [
        {"StatementId": EXPECTED_SIDS[0],
         "Action": "lambda:InvokeFunctionUrl",
         "Principal": arn,
         "FunctionUrlAuthType": FUNCTION_URL_AUTH_TYPE},
        # 2025-10 起 InvokeFunctionUrl 单条不够，缺 InvokeFunction 即 403。
        # InvokedViaFunctionUrl 把它限定为仅经 Function URL 调用。
        {"StatementId": EXPECTED_SIDS[1],
         "Action": "lambda:InvokeFunction",
         "Principal": arn,
         "InvokedViaFunctionUrl": True},
    ]


def _rendered_condition(stmt: dict) -> tuple:
    """`add_permission` 的关键字 → AWS 渲染进 policy 的 Condition（见模块 docstring 的来源）。"""
    # StringEquals 在 IAM 里是**大小写敏感**的：这里也不折叠，否则策略里写成 aws_iam 会被判成一致而实际 403。
    # Bool 的值 AWS 渲染成小写字符串 "true"，而 add_permission 收的是 Python bool ⇒ 只有它做小写归一。
    if "FunctionUrlAuthType" in stmt:
        return (("StringEquals", "lambda:FunctionUrlAuthType", str(stmt["FunctionUrlAuthType"])),)
    if "InvokedViaFunctionUrl" in stmt:
        return (("Bool", "lambda:InvokedViaFunctionUrl", str(stmt["InvokedViaFunctionUrl"]).lower()),)
    return ()


def expected_projection(edge_role_arn: str) -> dict:
    """Sid → (Effect, Action, Principal, Condition 三元组序列)。与 `_project()` 同一形态，可直接相等比较。"""
    return {s["StatementId"]: ("Allow", s["Action"], s["Principal"], _rendered_condition(s))
            for s in expected_statements(edge_role_arn)}


def _project(statement: dict) -> tuple:
    """policy 里的一条语句 → 可比较的投影。忽略 Resource（就是函数 ARN，带不带限定符由调用方决定）。"""
    action = statement.get("Action")
    if isinstance(action, list):
        action = action[0] if len(action) == 1 else tuple(sorted(action))
    principal = statement.get("Principal")
    if isinstance(principal, dict):
        principal = principal.get("AWS")
    if isinstance(principal, list):
        principal = tuple(sorted(principal))
    cond = statement.get("Condition") or {}
    triples = tuple(sorted((op, key, str(val).lower() if op == "Bool" else str(val))
                           for op, kv in cond.items() for key, val in (kv or {}).items()))
    return (statement.get("Effect"), action, principal, triples)


def drift(policy: dict | None, edge_role_arn: str) -> Drift:
    """线上 policy（`get_policy` 的 JSON，或 None = 还没有 policy）与期望集合的差。纯函数。"""
    want = expected_projection(edge_role_arn)
    got: dict = {}
    strays: list = []
    for s in (policy or {}).get("Statement", []):
        sid = s.get("Sid")
        if not sid:
            strays.append(NO_SID)
        elif sid in want:
            got[sid] = _project(s)
        else:
            strays.append(sid)
    return Drift(missing=tuple(sid for sid in EXPECTED_SIDS if sid not in got),
                 mismatched=tuple(sid for sid in EXPECTED_SIDS if sid in got and got[sid] != want[sid]),
                 stray=tuple(strays))


def _read_policy(lam, fn: str, q: dict) -> dict | None:
    try:
        return json.loads(lam.get_policy(FunctionName=fn, **q)["Policy"])
    except lam.exceptions.ResourceNotFoundException:
        return None


def _add_replacing_conflict(lam, fn: str, stmt: dict, q: dict) -> None:
    """加一条；同名冲突就删掉那条再加一次；**第二次仍冲突就抛**（有别的东西在同时写这份 policy）。"""
    kwargs = {k: v for k, v in stmt.items() if k != "StatementId"}
    for attempt in range(2):
        try:
            lam.add_permission(FunctionName=fn, StatementId=stmt["StatementId"], **kwargs, **q)
            return
        except lam.exceptions.ResourceConflictException:
            if attempt == 1:
                raise
            lam.remove_permission(FunctionName=fn, StatementId=stmt["StatementId"], **q)


def converge(lam, fn: str, edge_role_arn: str, *, qualifier: str | None = None, log=print) -> Drift:
    """把 `fn`（或 `fn:qualifier`）的 resource policy 收敛到 `expected_statements(edge_role_arn)`。

    返回**写之前**观察到的漂移（一致时零写入、只读一次）。写之后读回核对，不一致抛 `PolicyDriftError`。
    """
    stmts = {s["StatementId"]: s for s in expected_statements(edge_role_arn)}
    q = {"Qualifier": qualifier} if qualifier else {}
    before = drift(_read_policy(lam, fn, q), edge_role_arn)
    if before.ok:
        return before
    if NO_SID in before.stray:
        raise PolicyDriftError(f"{fn}: resource policy 里有没有 Sid 的语句，remove_permission 删不掉——"
                               "请人工核查这份 policy 是谁写的，再决定怎么处理")
    for sid in before.mismatched:
        log(f"  {fn}: 语句 {sid!r} 内容与期望不同（principal / action / condition 漂移），替换")
        lam.remove_permission(FunctionName=fn, StatementId=sid, **q)
    for sid in EXPECTED_SIDS:
        if sid in before.missing or sid in before.mismatched:
            _add_replacing_conflict(lam, fn, stmts[sid], q)
    for sid in before.stray:
        log(f"  {fn}: resource policy 有非预期语句 {sid!r}，删除")
        lam.remove_permission(FunctionName=fn, StatementId=sid, **q)
    for attempt in range(_READBACK_ATTEMPTS):
        after = drift(_read_policy(lam, fn, q), edge_role_arn)
        if after.ok:
            return before
        if attempt + 1 < _READBACK_ATTEMPTS:
            _sleep(_READBACK_DELAY_SECONDS)
    raise PolicyDriftError(f"{fn}: 收敛后读回仍不一致（{after.summary()}）——"
                           "AWS 渲染的语句形态可能与本模块的假设不同，先核对 get_policy 的原文再改假设")
