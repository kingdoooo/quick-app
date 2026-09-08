"""有状态的 Lambda resource policy 替身（**测试专用**，不是生产代码的副本）。

`add_permission` / `remove_permission` 真的改内部的语句表，`get_policy` 按 AWS 的渲染形态返回
（来源：AWS 文档 lambda/latest/dg/urls-auth 示例——`FunctionUrlAuthType` 渲染成 `StringEquals`、
`InvokedViaFunctionUrl` 渲染成 `Bool` 且值是字符串 `"true"`）。这份形态**只是文档所述**（evidence: static）；
真机第一次跑 converge 时的"写后读回核对"才是它的实测确认。

三个包的测试都用它：deployer（模块本体）、auth（deploy_auth 端到端）、panel / key-proxy 若需要。
非 deployer 的测试按路径 `importlib` 加载，不往 sys.path 里塞 `deployer/tests`（那会让各包自己的
`conftest` 名字撞车）。
"""
import json


class ResourceNotFoundException(Exception):
    pass


class ResourceConflictException(Exception):
    pass


class _Exceptions:
    ResourceNotFoundException = ResourceNotFoundException
    ResourceConflictException = ResourceConflictException


def rendered(sid, action, principal, *, function_url_auth_type=None, invoked_via_function_url=None,
             effect="Allow", resource="arn:aws:lambda:us-east-1:000000000000:function:fn"):
    """按 AWS 形态造一条语句。`principal` 可以是 ARN / `"*"` / 已删角色的 `AROA…` 形态。"""
    s = {"Sid": sid, "Effect": effect,
         "Principal": "*" if principal == "*" else {"AWS": principal},
         "Action": action, "Resource": resource}
    if function_url_auth_type is not None:
        s["Condition"] = {"StringEquals": {"lambda:FunctionUrlAuthType": function_url_auth_type}}
    if invoked_via_function_url is not None:
        s["Condition"] = {"Bool": {"lambda:InvokedViaFunctionUrl": str(invoked_via_function_url).lower()}}
    return s


def good_pair(role_arn, *, label="edge"):
    """与 `function_url_policy.expected_statements` 渲染后完全相同的两条（正对照用）。

    `label` 对应 `_pair(label, arn)` 的 Sid 前缀：默认 `edge`（edge role 那两条），
    `label="verifier"` 造 `[Verification] fixture_issuer = true` 时 `site-builder-verifier` 的那两条。
    """
    return [rendered(f"{label}-invoke", "lambda:InvokeFunctionUrl", role_arn, function_url_auth_type="AWS_IAM"),
            rendered(f"{label}-invoke-function", "lambda:InvokeFunction", role_arn, invoked_via_function_url=True)]


class FakeLambdaPolicy:
    """只实现 resource policy 那四个动作 + Function URL 的 AuthType 读取。其余方法不存在（AttributeError 即
    测试在调用一个本替身没建模的动作——那是测试写错了，不是被测代码错了）。"""

    exceptions = _Exceptions

    def __init__(self, statements=None, *, auth_type="AWS_IAM", drop_condition_on_add=False):
        self.statements = [dict(s) for s in (statements or [])]
        self.auth_type = auth_type
        self.calls = []                    # [(method, StatementId or None, Qualifier or None)]
        self.drop_condition_on_add = drop_condition_on_add   # 模拟"渲染形态与假设不同"

    def get_policy(self, FunctionName, Qualifier=None):
        self.calls.append(("get_policy", None, Qualifier))
        if not self.statements:
            raise ResourceNotFoundException(FunctionName)
        return {"Policy": json.dumps({"Version": "2012-10-17", "Id": "default", "Statement": self.statements})}

    def add_permission(self, FunctionName, StatementId, Action, Principal, Qualifier=None,
                       FunctionUrlAuthType=None, InvokedViaFunctionUrl=None, **_ignored):
        self.calls.append(("add_permission", StatementId, Qualifier))
        if any(s.get("Sid") == StatementId for s in self.statements):
            raise ResourceConflictException(StatementId)
        s = rendered(StatementId, Action, Principal, function_url_auth_type=FunctionUrlAuthType,
                     invoked_via_function_url=InvokedViaFunctionUrl,
                     resource=f"arn:aws:lambda:us-east-1:000000000000:function:{FunctionName}"
                              + (f":{Qualifier}" if Qualifier else ""))
        if self.drop_condition_on_add:
            s.pop("Condition", None)
        self.statements.append(s)
        return {"Statement": json.dumps(s)}

    def remove_permission(self, FunctionName, StatementId, Qualifier=None):
        self.calls.append(("remove_permission", StatementId, Qualifier))
        kept = [s for s in self.statements if s.get("Sid") != StatementId]
        if len(kept) == len(self.statements):
            raise ResourceNotFoundException(StatementId)
        self.statements = kept

    def get_function_url_config(self, FunctionName, Qualifier=None):
        return {"FunctionUrl": f"https://{FunctionName}.lambda-url.us-east-1.on.aws/", "AuthType": self.auth_type}

    def writes(self):
        return [c for c in self.calls if c[0] != "get_policy"]
