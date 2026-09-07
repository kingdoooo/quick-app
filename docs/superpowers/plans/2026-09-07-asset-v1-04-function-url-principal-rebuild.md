# asset-v1 · 04 平台 Function URL 的 Principal 重建（merged review M07）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `deploy_auth.py` / `deploy_panel.py` / `deploy_key_proxy.py` 每次部署都把各自 Function URL 的 resource policy **按期望集合等值写**（恰好两条：`InvokeFunctionUrl` + `InvokeFunction`/`InvokedViaFunctionUrl`，Principal 只有 exact edge role），并让 `verify_deployed_components.py` 对三条 Function URL 都断言——此前三处都是 `except ResourceConflictException: pass`（同名 Sid 存在即当对），auth 那条连闸门都没有。

**Architecture:** 新增一个**唯一实现** `site-builder/deployer/functions/function_url_policy.py`：`expected_statements(edge_role_arn)`（两条语句的单一定义 + ARN 校验）、`drift(policy, edge_role_arn)`（纯函数：缺 / 内容不对 / 非预期三类漂移）、`converge(lam, fn, edge_role_arn)`（读回 → 替换内容不对的同名语句 → 补缺 → 删野 Sid → 写后读回核对，不一致抛 `PolicyDriftError`；一致时零写入）。三个部署脚本删掉各自那段 `add_permission … pass`，改为调用 `converge`；闸门的 `_check_function_url_authz` 改用同一个 `drift` 判定并补上 auth 那一处。`deploy_lambda_site.py`（站点色的授权，M07 点名的"正确形态"）**本票不改**，只加一条 parity 用例钉住两边同形。

**Tech Stack:** Python 3.12（五个 venv）/ 3.13（Lambda 运行时，本票不碰运行时代码）、boto3 Lambda API（`get_policy` / `add_permission` / `remove_permission` / `get_function_url_config`）、pytest；测试用有状态替身 `deployer/tests/fake_lambda_policy.py`（按 AWS 文档的渲染形态），不用 moto（moto 不校验也不渲染 Lambda resource policy 的 Condition）。

**Spec:** 工单 `.scratch/asset-v1/issues/04-function-url-principal-rebuild.md`（gitignored，主 worktree）；缺陷原文 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` **M07** 一节（§9 第 6 行）；正确形态的参照 `site-builder/deployer/functions/deploy_lambda_site.py` 里"清掉这一色 resource policy 里所有非预期语句"到 add_permission 那段。资产框架：`docs/adr/0005-*.md`。

**证据分级（本计划自身）**：下面每个 Task 的代码块都已在一份 `site-builder/` 镜像上按 CLAUDE.md「Spec / Plan / Review Fix Discipline」机械校验过——语法、import、真实路径与接口、测试可收集并**全绿**（deployer 三个文件 93 passed、auth 419、panel 相关三文件 111、key-proxy 164）。级别是 **fake/unit + static**；AWS 渲染出的 policy 语句形态取自 AWS 文档（见 Global Constraints 第 4 条），**没有在真机上核对过**，真机核对由 coordinator 部署时 `converge` 的写后读回完成（见最后一节）。

## Global Constraints

- **asset-v1 规则**：只做工单「What to build」；不部署、不提交、不 push、不动 AWS 资源；改动留在 worktree 工作树，提交 / 七套件 / 部署 / `verify_*` 由 coordinator 在集成泳道做。每个 Task 结尾**不是 commit**，是"该包套件绿 + 证据行写进 `.superpowers/sdd/2026-09-07-asset-v1-04-function-url-principal-rebuild/progress.md`（gitignored）"。
- **TDD**：每条守卫先写、先跑红、再实现、再跑绿；每组反例都配正对照（一致 ⇒ 零写入 / 三条 PASS）。跑红时要看**红的原因**是不是预期的那个（下面每个 Step 2 都写了预期的失败形态）。
- **测试命令按包照抄、顺序跑、不并行**（CLAUDE.md「测试命令」；contract 有墙钟哨兵）：
  - `(cd site-builder/deployer && .venv/bin/pytest tests -q)`（**必须带 `tests/`**）
  - `(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)`
  - `(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)`
  - `(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)`
  - 本票不碰 contract / router / mcp 的源码；最终七套件由 coordinator 跑。
- **AWS 渲染的语句形态（AWS 文档 `lambda/latest/dg/urls-auth`，"Using the AWS_IAM auth type" 一节的示例）**：`add_permission(FunctionUrlAuthType="AWS_IAM")` 渲染成 `Condition.StringEquals["lambda:FunctionUrlAuthType"]="AWS_IAM"`；`add_permission(InvokedViaFunctionUrl=True)` 渲染成 `Condition.Bool["lambda:InvokedViaFunctionUrl"]="true"`——**操作符是 `Bool` 不是 `StringEquals`，值是字符串**。这份知识只住 `function_url_policy._rendered_condition` 与替身 `fake_lambda_policy.rendered` 两处，都注明来源。
- **Sid 统一为 `edge-invoke` / `edge-invoke-function`**（与 `deploy_lambda_site.py` 和 auth 现状同名）。panel / key-proxy 现网的 `edge-invoke-url` 在下一次部署时按"先加新、后删旧"换名，零 403 窗口。`verify_account_trust_boundary.py` 的 `canonicalize_statement` **丢顶层 Sid**（"改名不是授权变化"），所以换名不产生基线漂移、不需要 `--update-baseline`。
- **写顺序是刻意的**：内容不对的同名语句先删再加（Lambda 不允许同 Sid 两条；那条本来就在 403 状态，没有可保的）→ 补缺 → **最后**删野 Sid（含改名前的旧 Sid 与老版本的 `public-url*`）→ 读回核对。**一致时零写入**——这是三个脚本天天跑的幂等路径。
- **fail-closed 三处**：edge_role_arn 空 / 通配 / 非 role ARN ⇒ 三个脚本都在任何写之前中止（auth 此前没有这一步，本票补上）；policy 里出现没有 Sid 的语句 ⇒ `PolicyDriftError`（删不掉，只能人工）；写后读回仍不一致 ⇒ `PolicyDriftError`（AWS 渲染形态与假设不同时第一次真机部署就在这里响亮失败，而不是每次重跑静默删了再加）。
- **不写真实账号 / 域名**：测试一律 `000000000000` / `111111111111` / `example.test`。AROA 形态的假 RoleId 要**拼接**（`"AROA" + "…"`），整串字面量会被 Code Defender 的 HARD_CODED_SECRET 规则拦下（`test_edge_caller.py` 的教训）。
- **闸门下限随之变**：`MIN_DEPLOYED_CHECKS` 20 → 23（④ 多了 AuthType / 语句集合 / 逐条内容三条）；`test_the_floor_tracks_state_instead_of_being_a_constant` 的 23/21 改成 26/24。这是本票**刻意**的变化，不是回归。
- **CLAUDE.md 有状态词守卫**（`test_delivery_docs_current.py::test_status_free_docs_carry_no_environment_status`）：Task 6 的措辞已经用它的 `_status_violations` 预检过（零命中）；改措辞后要再跑一次 deployer 套件。不写日期、SHA、"已部署 / 尚未 / 待做"。
- **资产检查**：每一处改动都过"全新用户在全新账号 clone 有意义吗"——换 edge role 后重跑脚本就收敛、闸门对三条都断言，两者对采用者都成立；panel / key-proxy 的 Sid 换名是验证环境的一次性过程，只在代码注释里解释"先加后删"的顺序，**不进 DEPLOY.md 的操作步骤**。
- 命令块里不写绝对主机路径；回仓库根用 `cd "$(git rev-parse --show-toplevel)"`；多命令块以 `set -euo pipefail` 开头。

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/deployer/functions/function_url_policy.py` | 期望语句集合、漂移判定、等值收敛的**唯一实现**；不 import boto3、不读配置 | 新建 |
| `site-builder/deployer/tests/fake_lambda_policy.py` | 有状态的 Lambda resource policy 替身（按 AWS 渲染形态）；deployer / auth 的测试共用 | 新建 |
| `site-builder/deployer/tests/test_function_url_policy.py` | 模块本体的单测：正对照 + 三类漂移 + 收敛顺序 + fail-closed | 新建 |
| `site-builder/deployer/tests/test_deploy_lambda_site.py` | 追加 parity 用例：站点色授权与平台三条同形 | 修改（追加） |
| `site-builder/auth/deploy_auth.py` | 引入共享实现；`edge_role_arn()` 写前校验；main() 改调 `converge` | 修改 |
| `site-builder/auth/tests/test_deploy_auth_sequence.py` | `_run_main` 接 converge 记录器；追加绑定 / 顺序 / 无直接 add_permission / 端到端用例 | 修改 |
| `site-builder/panel/deploy_panel.py` | 删本地 `function_url_statements` 与 `FUNCTION_URL_AUTH_TYPE` 字面量，改 import；`ensure_function` 改调 `converge` | 修改 |
| `site-builder/panel/tests/test_deploy_panel_sequence.py` | `test_ensure_function_updates_configuration_before_code` 里 stub 掉 converge | 修改 |
| `site-builder/panel/tests/test_deploy_panel_contract.py` | 追加绑定 / 无直接 add_permission / ensure_function 调一次 converge | 修改（追加） |
| `site-builder/key-proxy/deploy_key_proxy.py` | 同 panel | 修改 |
| `site-builder/key-proxy/tests/test_deploy_key_proxy_contract.py` | 同 panel | 修改（追加） |
| `site-builder/scripts/verify_deployed_components.py` | `_check_function_url_authz` 改用 `drift`；④ 段补 auth 那一处；`MIN_DEPLOYED_CHECKS` 23 | 修改 |
| `site-builder/deployer/tests/test_verify_deployed_components.py` | 下限 26/24；追加闸门行为 + 结构守卫 + 抽取器自测 | 修改 |
| `CLAUDE.md`、`site-builder/DEPLOY.md` | 高频坑一条扩写 + 改动矩阵一行；DEPLOY.md 加"换 edge role 之后"一段 | 修改 |

**不改**：`deploy_lambda_site.py`（决策门 ③）、`scripts/migrate_sites_to_blue_green.py`（§9 已裁定删除，归工单 12）、`docs/reviews/*` §9 的勾（coordinator 记）。

---

### Task 1：唯一实现 `function_url_policy.py` + 替身 + 单测 + parity 用例

**Files:**
- Create: `site-builder/deployer/functions/function_url_policy.py`
- Create: `site-builder/deployer/tests/fake_lambda_policy.py`
- Create: `site-builder/deployer/tests/test_function_url_policy.py`
- Modify: `site-builder/deployer/tests/test_deploy_lambda_site.py`（文件末尾追加）

**Interfaces（Produces，后面每个 Task 都靠这些名字）：**
- `EXPECTED_SIDS: tuple[str, str] = ("edge-invoke", "edge-invoke-function")`
- `FUNCTION_URL_AUTH_TYPE: str = "AWS_IAM"`
- `NO_SID: str`（drift 里"没有 Sid 的语句"的标记）
- `class PolicyDriftError(RuntimeError)`
- `@dataclass(frozen=True) class Drift(missing: tuple, mismatched: tuple, stray: tuple)`，属性 `ok: bool`，方法 `summary() -> str`
- `expected_statements(edge_role_arn: str) -> list[dict]`：两条 `add_permission` 关键字（含 `StatementId`）；空 / 通配 / 非 `arn:aws:iam::` 前缀 ⇒ `ValueError`
- `expected_projection(edge_role_arn: str) -> dict[str, tuple]`
- `drift(policy: dict | None, edge_role_arn: str) -> Drift`（纯函数）
- `converge(lam, fn: str, edge_role_arn: str, *, qualifier: str | None = None, log=print) -> Drift`（返回写之前的漂移）
- 替身：`fake_lambda_policy.FakeLambdaPolicy(statements=None, *, auth_type="AWS_IAM", drop_condition_on_add=False)`，方法 `get_policy / add_permission / remove_permission / get_function_url_config / writes()`，属性 `statements / calls / exceptions`；工厂 `rendered(...)`、`good_pair(edge_role_arn)`

- [ ] **Step 1：写替身 `deployer/tests/fake_lambda_policy.py`**（测试基础设施，先于红测试）

```python
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


def good_pair(edge_role_arn):
    """与 `function_url_policy.expected_statements` 渲染后完全相同的两条（正对照用）。"""
    return [rendered("edge-invoke", "lambda:InvokeFunctionUrl", edge_role_arn, function_url_auth_type="AWS_IAM"),
            rendered("edge-invoke-function", "lambda:InvokeFunction", edge_role_arn, invoked_via_function_url=True)]


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
```

- [ ] **Step 2：写红测试 `deployer/tests/test_function_url_policy.py`**

```python
"""`functions/function_url_policy.py`：期望集合、漂移判定、等值收敛（merged review M07）。

每条守卫先有正对照（一致 ⇒ 零写入）再有反例；反例覆盖 M07 点名的三种真实漂移：edge role 重建后
Principal 变成 `AROA…`、config 改错后修正、别的 Sid 下的额外授权。evidence: fake/unit。
"""
import ast
import json
from pathlib import Path

import pytest

import function_url_policy as fup
from fake_lambda_policy import FakeLambdaPolicy, good_pair, rendered

EDGE = "arn:aws:iam::000000000000:role/site-edge-role"
OTHER = "arn:aws:iam::000000000000:role/someone-else"
FN = "site-auth-service"


# ── 期望集合 ────────────────────────────────────────────────────────────────

def test_expected_statements_are_the_two_url_grants_bound_to_the_exact_edge_role():
    stmts = fup.expected_statements(EDGE)
    assert [s["StatementId"] for s in stmts] == list(fup.EXPECTED_SIDS) == ["edge-invoke", "edge-invoke-function"]
    by_action = {s["Action"]: s for s in stmts}
    assert set(by_action) == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}
    assert all(s["Principal"] == EDGE for s in stmts)
    assert by_action["lambda:InvokeFunctionUrl"]["FunctionUrlAuthType"] == "AWS_IAM" == fup.FUNCTION_URL_AUTH_TYPE
    assert by_action["lambda:InvokeFunction"]["InvokedViaFunctionUrl"] is True


@pytest.mark.parametrize("bad", ["", None, "   ", "*", "arn:aws:iam::000000000000:role/*", "site-edge-role"])
def test_missing_or_wildcard_edge_role_raises_instead_of_widening(bad):
    with pytest.raises(ValueError):
        fup.expected_statements(bad)


def test_rendered_condition_matches_the_aws_documented_shape():
    """`InvokedViaFunctionUrl` 渲染成 **Bool** 操作符 + 字符串 "true"（不是 StringEquals）——文档所述。"""
    proj = fup.expected_projection(EDGE)
    assert proj["edge-invoke"][3] == (("StringEquals", "lambda:FunctionUrlAuthType", "aws_iam"),)
    assert proj["edge-invoke-function"][3] == (("Bool", "lambda:InvokedViaFunctionUrl", "true"),)


# ── 漂移判定（纯函数）──────────────────────────────────────────────────────

def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def test_exact_policy_has_no_drift():
    """正对照：与文档形态逐字节相同 ⇒ ok。没有它，下面的红证明不了什么。"""
    d = fup.drift(_policy(*good_pair(EDGE)), EDGE)
    assert d.ok and d.summary() == "一致"


def test_no_policy_at_all_means_both_missing():
    d = fup.drift(None, EDGE)
    assert d.missing == fup.EXPECTED_SIDS and not d.mismatched and not d.stray


def test_principal_rewritten_to_a_deleted_role_id_is_a_mismatch():
    """edge role 被删后重建：IAM 把 Principal 改写成旧角色的唯一 ID——同名 Sid、内容已错。M07 的核心形态。"""
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    bad = [rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
           rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)]
    d = fup.drift(_policy(*bad), EDGE)
    assert d.mismatched == fup.EXPECTED_SIDS and not d.missing and not d.stray


@pytest.mark.parametrize("variant", [
    "other-principal", "account-root", "star", "no-condition", "wrong-auth-type", "deny",
    "string-equals-instead-of-bool", "missing-invoked-via",
])
def test_each_content_deviation_is_a_mismatch(variant):
    url = rendered("edge-invoke", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM")
    fn = rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True)
    if variant == "other-principal":
        url["Principal"] = {"AWS": OTHER}
    elif variant == "account-root":
        url["Principal"] = {"AWS": "arn:aws:iam::000000000000:root"}
    elif variant == "star":
        url["Principal"] = "*"
    elif variant == "no-condition":
        url.pop("Condition")
    elif variant == "wrong-auth-type":
        url["Condition"] = {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}
    elif variant == "deny":
        url["Effect"] = "Deny"
    elif variant == "string-equals-instead-of-bool":
        fn["Condition"] = {"StringEquals": {"lambda:InvokedViaFunctionUrl": "true"}}
    elif variant == "missing-invoked-via":
        fn.pop("Condition")
    d = fup.drift(_policy(url, fn), EDGE)
    assert d.mismatched and not d.missing and not d.stray, (variant, d)


def test_extra_statement_under_another_sid_is_stray():
    """只替换自己那两条清不掉别的 Sid 下塞进来的 `Principal:*`。"""
    d = fup.drift(_policy(*good_pair(EDGE), rendered("public-url", "lambda:InvokeFunctionUrl", "*",
                                                    function_url_auth_type="NONE")), EDGE)
    assert d.stray == ("public-url",) and not d.missing and not d.mismatched


def test_old_sid_names_are_stray_and_new_ones_missing():
    """panel / key-proxy 原来的 Sid（edge-invoke-url）：内容对、名字不对 ⇒ 一条野、一条缺（改名走"先加后删"）。"""
    old = [rendered("edge-invoke-url", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM"),
           rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True)]
    d = fup.drift(_policy(*old), EDGE)
    assert d.missing == ("edge-invoke",) and d.stray == ("edge-invoke-url",) and not d.mismatched


def test_a_statement_without_sid_is_reported_under_the_no_sid_marker():
    s = rendered("x", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")
    del s["Sid"]
    d = fup.drift(_policy(*good_pair(EDGE), s), EDGE)
    assert d.stray == (fup.NO_SID,)


def test_single_element_action_list_compares_equal_to_the_string():
    good = good_pair(EDGE)
    good[0]["Action"] = ["lambda:InvokeFunctionUrl"]
    assert fup.drift(_policy(*good), EDGE).ok


# ── 等值收敵 ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(fup, "_sleep", lambda s: None)


def test_matching_policy_is_read_once_and_never_written():
    """**重跑零写入**：幂等重部不得动线上任何一条语句（这是三个部署脚本天天跑的路径）。"""
    lam = FakeLambdaPolicy(good_pair(EDGE))
    before = fup.converge(lam, FN, EDGE)
    assert before.ok
    assert lam.calls == [("get_policy", None, None)]


def test_empty_policy_gets_both_statements_and_reads_back_clean():
    lam = FakeLambdaPolicy()
    before = fup.converge(lam, FN, EDGE)
    assert before.missing == fup.EXPECTED_SIDS
    assert [c[1] for c in lam.writes()] == ["edge-invoke", "edge-invoke-function"]
    assert fup.drift(json.loads(lam.get_policy(FunctionName=FN)["Policy"]), EDGE).ok


def test_deleted_role_principal_is_replaced_remove_then_add():
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    lam = FakeLambdaPolicy([
        rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
        rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)])
    before = fup.converge(lam, FN, EDGE)
    assert before.mismatched == fup.EXPECTED_SIDS
    removed = [c for c in lam.calls if c[0] == "remove_permission"]
    added = [c for c in lam.calls if c[0] == "add_permission"]
    assert {c[1] for c in removed} == set(fup.EXPECTED_SIDS) == {c[1] for c in added}
    assert lam.calls.index(removed[0]) < lam.calls.index(added[0]), "同名语句必须先删再加"
    principals = {s["Principal"]["AWS"] for s in lam.statements}
    assert principals == {EDGE}


def test_rename_adds_the_new_statement_before_removing_the_old_one():
    """改 Sid 名零窗口：新语句已生效才删旧的（先加后删）。同时 `Principal:*` 的野语句被清掉。"""
    lam = FakeLambdaPolicy([
        rendered("edge-invoke-url", "lambda:InvokeFunctionUrl", EDGE, function_url_auth_type="AWS_IAM"),
        rendered("edge-invoke-function", "lambda:InvokeFunction", EDGE, invoked_via_function_url=True),
        rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
    before = fup.converge(lam, FN, EDGE)
    assert before.missing == ("edge-invoke",) and set(before.stray) == {"edge-invoke-url", "public-url"}
    writes = lam.writes()
    assert writes[0] == ("add_permission", "edge-invoke", None)
    assert {c[1] for c in writes[1:]} == {"edge-invoke-url", "public-url"}
    assert all(c[0] == "remove_permission" for c in writes[1:])
    assert {s["Sid"] for s in lam.statements} == set(fup.EXPECTED_SIDS)


def test_statement_without_sid_aborts_before_any_write():
    s = rendered("x", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")
    del s["Sid"]
    lam = FakeLambdaPolicy(good_pair(EDGE) + [s])
    with pytest.raises(fup.PolicyDriftError, match="没有 Sid"):
        fup.converge(lam, FN, EDGE)
    assert lam.writes() == []


def test_a_conflict_that_survives_one_replace_is_not_swallowed():
    """删了再加还冲突 ⇒ 抛（有别的东西在同时写这份 policy）。

    替身：add 永远冲突、remove 只记录不改状态——模拟"另一个 writer 在我删掉之后又立刻写回同名语句"。
    """
    class AlwaysConflict(FakeLambdaPolicy):
        def add_permission(self, **kw):
            self.calls.append(("add_permission", kw["StatementId"], kw.get("Qualifier")))
            raise self.exceptions.ResourceConflictException(kw["StatementId"])

        def remove_permission(self, FunctionName, StatementId, Qualifier=None):
            self.calls.append(("remove_permission", StatementId, Qualifier))
    lam = AlwaysConflict(good_pair(EDGE)[:1])          # 第二条缺 ⇒ 要加
    with pytest.raises(lam.exceptions.ResourceConflictException):
        fup.converge(lam, FN, EDGE)
    adds = [c for c in lam.calls if c[0] == "add_permission"]
    assert len(adds) == 2, "必须恰好尝试两次（加 → 删 → 再加），不多不少"


def test_readback_mismatch_after_writing_raises_instead_of_reporting_success():
    """**读回核对是 fail-closed 的落点**：AWS 渲染形态与假设不同时第一次真机部署就要在这里响亮失败。"""
    lam = FakeLambdaPolicy(drop_condition_on_add=True)
    with pytest.raises(fup.PolicyDriftError, match="读回仍不一致"):
        fup.converge(lam, FN, EDGE)
    assert len([c for c in lam.calls if c[0] == "get_policy"]) == 1 + fup._READBACK_ATTEMPTS


def test_qualifier_is_carried_on_every_call():
    """给将来 deploy_lambda_site 复用留的口：带 qualifier 时读、加、删都要带（授在函数上 ≠ 授在颜色上）。"""
    lam = FakeLambdaPolicy()
    fup.converge(lam, "site-s-1", EDGE, qualifier="blue")
    assert lam.calls and all(c[2] == "blue" for c in lam.calls), lam.calls


# ── 模块自身的边界 ──────────────────────────────────────────────────────────

def test_module_imports_no_boto3_and_reads_no_environment():
    """client 由调用方传入；本模块能在 auth 借用的 venv 里、也能在闸门脚本里 import 而不带任何 AWS 依赖。"""
    tree = ast.parse(Path(fup.__file__).read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert "boto3" not in imported and "botocore" not in imported and "os" not in imported, imported
```

- [ ] **Step 3：跑红**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests/test_function_url_policy.py -q`
Expected: 收集期 `ModuleNotFoundError: No module named 'function_url_policy'`（整个文件红；替身自己能 import）。

- [ ] **Step 4：写实现 `deployer/functions/function_url_policy.py`**

```python
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
    if "FunctionUrlAuthType" in stmt:
        return (("StringEquals", "lambda:FunctionUrlAuthType", str(stmt["FunctionUrlAuthType"]).lower()),)
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
    triples = tuple(sorted((op, key, str(val).lower())
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
```

- [ ] **Step 5：跑绿**

Run: 同 Step 3
Expected: `32 passed`。逐条看一眼名字：`test_matching_policy_is_read_once_and_never_written`（零写入正对照）、`test_deleted_role_principal_is_replaced_remove_then_add`（M07 核心形态）、`test_rename_adds_the_new_statement_before_removing_the_old_one`（换名先加后删）、`test_readback_mismatch_after_writing_raises_instead_of_reporting_success`（渲染形态假设错 ⇒ 响亮）都在。

- [ ] **Step 6：追加 parity 用例到 `deployer/tests/test_deploy_lambda_site.py` 文件末尾**

```python
# ---- M07：站点色的授权与三个平台脚本授的是同一形态（parity）--------------------------------------
#
# `deploy_lambda_site` 自己那段（清野 Sid + remove→add + 抛出）是 M07 点名的"正确形态"，平台三条改为共用
# `function_url_policy`；两边暂时是两份代码，这条用例把 Sid / Action / Principal / Condition 钉成同一个投影，
# 任一侧改形态另一侧不跟就红。evidence: fake/unit。

def test_site_color_grants_have_the_same_shape_as_the_platform_function_urls(aws, monkeypatch):
    import deploy_lambda_site as d, common
    import function_url_policy as fup
    edge = "arn:aws:iam::1:role/edge-role"
    monkeypatch.setenv("EDGE_ROLE_ARN", edge)
    common.create_job("a@x.com", "s-1")
    lam = _lam_mock(exists=False)
    with patch.object(d, "_lambda", return_value=lam):
        d.handler(dict(EVENT), None)
    granted = {}
    for c in lam.add_permission.call_args_list:
        kw = dict(c.kwargs)
        assert kw.pop("Qualifier") == "blue"
        kw.pop("FunctionName")
        granted[kw.pop("StatementId")] = ("Allow", kw["Action"], kw["Principal"], fup._rendered_condition(kw))
    assert granted == fup.expected_projection(edge), granted
```

- [ ] **Step 7：跑 parity 用例 + 变形自查**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests/test_deploy_lambda_site.py -q`
Expected: 全绿（含新用例）。**变形**：把 `deploy_lambda_site.py` 里 `("edge-invoke", "lambda:InvokeFunctionUrl", …)` 临时改成 `"edge-invoke-x"`，重跑 ⇒ 新用例红且 `granted` 里能看到 `edge-invoke-x`；**改回来**再跑一次绿。这一步证明 parity 用例不是空转。

- [ ] **Step 8：deployer 全套 + 记证据**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests -q`
Expected: 全绿（`test_infra_tables.py` 默认 skip 属正常）。progress.md 记：Task 1 · fake/unit · 32 + 1 新用例 · 变形自查做过。**不提交。**

---

### Task 2：`deploy_auth.py` 改调共享实现 + 写前校验 edge_role_arn

**Files:**
- Modify: `site-builder/auth/deploy_auth.py`（import 段；`precheck()` 之后新增 `edge_role_arn()`；`main()` 里 ⓪ 与授权段）
- Modify: `site-builder/auth/tests/test_deploy_auth_sequence.py`（`_run_main` 加一行 monkeypatch；文件末尾追加）

**Interfaces:**
- Consumes: Task 1 的 `converge` / `expected_statements` / `Drift.summary()`；替身按路径加载（不往 `sys.path` 塞 `deployer/tests`——会与 auth 自己的 `conftest` 撞名）。
- Produces: `deploy_auth.converge_function_url_policy`（== `function_url_policy.converge`）、`deploy_auth.function_url_statements`（== `expected_statements`）、`deploy_auth.edge_role_arn() -> str`（空 / 通配 ⇒ `SystemExit`，消息含 `edge_role_arn`）。闸门按名字 `_load_deploy_module("deploy_auth")` 加载这个模块，它自己把 `deployer/functions` 铺进 `sys.path`。

- [ ] **Step 1：改 `_run_main` 并追加红测试**

`_run_main` 的改动（现有 helper；Recorder 的 `get_policy` 返回的不是 policy，所以这里换成记录器）：

```diff
--- site-builder/auth/tests/test_deploy_auth_sequence.py	2026-09-07 01:32:02
+++ site-builder/auth/tests/test_deploy_auth_sequence.py	2026-09-07 07:59:14
@@ -235,8 +235,21 @@
     monkeypatch.setattr(da, "ensure_alarm_pipeline",
                         lambda **kw: {"changed": [], "subscription_state": "confirmed"})
     monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
+    # M07：Function URL 授权走共享的 converge；这里换成记录器（Recorder 的 get_policy 返回的不是 policy），
+    # 它的真实行为由 deployer/tests/test_function_url_policy.py 与下面的端到端用例覆盖。
+    monkeypatch.setattr(da, "converge_function_url_policy",
+                        lambda client, fn, arn: _CONVERGE_CALLS.append((client, fn, arn)) or _DriftStub())
+    _CONVERGE_CALLS.clear()
     da.main()
     return lam, iam, ddb
+
+
+_CONVERGE_CALLS: list = []
+
+
+class _DriftStub:
+    def summary(self):
+        return "一致"
 
 
 def test_main_creates_the_login_flow_secret_when_it_is_absent(cfg_files, monkeypatch):
```

文件末尾追加：

```python
# ---- M07：Function URL 的 resource policy 按期望集合等值收敛（auth 那条此前既不收敛也无闸门）----------
#
# 三条不变量：① 实现是共享的那一份（不在本脚本里另写）；② main() 在 precheck 之后、任何写之前先校验
# edge_role_arn（空 / 通配即拒绝部署）；③ main() 恰好调用一次 converge，本脚本里不再有任何直接的
# add_permission / remove_permission（pre-token 触发器那处除外——那是 Cognito 调 Lambda 的授权，不是 M07 的面）。

import importlib.util as _ilu

import function_url_policy as fup          # deploy_auth import 时已把 deployer/functions 铺进 sys.path


def _fake_policy_module():
    """按路径加载 deployer/tests 的有状态替身，不往 sys.path 塞那个目录（会与本包的 conftest 撞名）。"""
    path = Path(da.__file__).resolve().parents[1] / "deployer" / "tests" / "fake_lambda_policy.py"
    spec = _ilu.spec_from_file_location("fake_lambda_policy", path)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_deploy_auth_binds_the_shared_function_url_policy_implementation():
    assert da.converge_function_url_policy is fup.converge
    assert da.function_url_statements is fup.expected_statements


def test_main_converges_the_function_url_policy_once_with_the_configured_edge_role(cfg_files, monkeypatch):
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, _, _ = _run_main(monkeypatch, ssm)
    assert _CONVERGE_CALLS == [(lam, da.FN, "arn:aws:iam::111111111111:role/site-edge-role")]


@pytest.mark.parametrize("bad", ["", "*", "arn:aws:iam::111111111111:role/*", "site-edge-role"])
def test_main_aborts_before_any_write_when_edge_role_arn_is_unusable(tmp_path, monkeypatch, bad):
    """缺 / 通配 / 非 ARN 一律在 precheck 之后立刻 SystemExit：Lambda、角色、resource policy、路由表零写入。"""
    p = tmp_path / "config.ini"
    p.write_text(CFG.replace("edge_role_arn = arn:aws:iam::111111111111:role/site-edge-role",
                             f"edge_role_arn = {bad}"))
    c = configparser.ConfigParser()
    c.read(p)
    monkeypatch.setattr(da, "CFG_PATH", p)
    monkeypatch.setattr(da, "_CFG", c)
    ssm = FakeSSM(present=set(da.required_parameters()))
    lam, iam, ddb = Recorder(), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: (_ for _ in ()).throw(AssertionError("不该打包")))
    with pytest.raises(SystemExit, match="edge_role_arn"):
        da.main()
    assert lam.calls == [] and iam.calls == [] and ddb.calls == []
    assert not [c for c in ssm.calls if c[0] == "put_parameter"]


def test_main_validates_edge_role_after_precheck_and_before_the_first_write():
    """结构守卫：main() 里 edge_role_arn() 排在 precheck() 之后、第一个写助手之前。"""
    tree = ast.parse(Path(da.__file__).read_text())
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    order = sorted((node.lineno, node.func.id) for node in ast.walk(main_fn)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    names = [n for _, n in order]
    first_write = min(names.index(n) for n in ("ensure_secret", "ensure_lambda_role", "build_zip", "deploy_function")
                      if n in names)
    assert names.index("precheck") < names.index("edge_role_arn") < first_write, names


def test_no_direct_permission_calls_outside_the_pre_token_trigger():
    """add_permission / remove_permission 只许出现在 ensure_pre_token_trigger 里：Function URL 那两条全走 converge。
    "同名 StatementId 已存在就 pass"回来的唯一途径就是有人在这里又写一遍。"""
    tree = ast.parse(Path(da.__file__).read_text())
    owners = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("add_permission", "remove_permission"):
                owners.setdefault(node.func.attr, set()).add(fn.name)
    assert owners.get("add_permission", set()) <= {"ensure_pre_token_trigger"}, owners
    # 老 Sid（public-url / public-url-invoke）的点名删除由 converge 的野 Sid 清理覆盖：本脚本零 remove_permission。
    # 按 AST 判，不 grep 文本——注释里提到那两个名字是合法的（本仓库栽过"断言的字样只活在注释里"的反面）。
    assert owners.get("remove_permission", set()) == set(), owners


class _PolicyRecorder(Recorder):
    """Recorder + 真的 resource policy 状态：get_policy / add_permission / remove_permission 交给有状态替身。"""
    def __init__(self, fake):
        super().__init__()
        self.fake = fake
        self.exceptions = type("E", (), {"ResourceNotFoundException": fake.exceptions.ResourceNotFoundException,
                                          "ResourceConflictException": fake.exceptions.ResourceConflictException,
                                          "NoSuchEntityException": _NotFound})

    def __getattr__(self, name):
        if name in ("get_policy", "add_permission", "remove_permission"):
            return getattr(self.fake, name)
        return super().__getattr__(name)


def test_main_end_to_end_replaces_a_deleted_role_principal_and_clears_legacy_public_statements(cfg_files, monkeypatch):
    """端到端（真 converge + 有状态替身）：edge role 重建后的 AROA principal 被换成配置里的 ARN，老版本留下的
    public-url 语句被删，最终 policy 与期望集合逐字节一致。这正是 M07 "重部永不重建 Principal" 的反例。"""
    flp = _fake_policy_module()
    edge = "arn:aws:iam::111111111111:role/site-edge-role"
    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
    fake = flp.FakeLambdaPolicy([
        flp.rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
        flp.rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True),
        flp.rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
    monkeypatch.setattr(fup, "_sleep", lambda s: None)
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline", lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    da.main()
    assert fup.drift(json.loads(fake.get_policy(FunctionName=da.FN)["Policy"]), edge).ok
    assert {s["Sid"] for s in fake.statements} == set(fup.EXPECTED_SIDS)
    assert {s["Principal"]["AWS"] for s in fake.statements} == {edge}


def test_rerunning_main_on_a_converged_policy_writes_nothing(cfg_files, monkeypatch):
    """幂等重部的正对照：policy 已一致 ⇒ 一次 get_policy、零 add/remove。"""
    flp = _fake_policy_module()
    fake = flp.FakeLambdaPolicy(flp.good_pair("arn:aws:iam::111111111111:role/site-edge-role"))
    ssm = FakeSSM(present=set(da.required_parameters()) | {LOGIN_FLOW_PARAM, "/site-builder/jwt-secret"})
    lam, iam, ddb = _PolicyRecorder(fake), Recorder(), Recorder()
    for k, v in (("ssm", ssm), ("lambda", lam), ("iam", iam), ("dynamodb", ddb)):
        monkeypatch.setitem(da._CLIENTS, k, v)
    monkeypatch.setattr(da, "build_zip", lambda: b"zip")
    monkeypatch.setattr(da, "ensure_pre_token_trigger", lambda *a, **k: None)
    monkeypatch.setattr(da, "ensure_alarm_pipeline", lambda **kw: {"changed": [], "subscription_state": "confirmed"})
    monkeypatch.setattr(da, "_alert_email", lambda: "ops@example.test")
    da.main()
    assert fake.writes() == []
    assert [c for c in fake.calls if c[0] == "get_policy"] == [("get_policy", None, None)]
```

- [ ] **Step 2：跑红**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/auth" && ../contract/.venv/bin/pytest tests/test_deploy_auth_sequence.py -q`
Expected: 收集期 `ModuleNotFoundError: No module named 'function_url_policy'`（测试模块顶层 `import function_url_policy` 依赖 `deploy_auth` 先把 `deployer/functions` 铺进 `sys.path`——实现前它没铺，整个文件红）。这是预期形态；不要为了让它"部分绿"把 import 挪进函数——绑定用例的意义就是 deploy_auth 负责铺路径。

- [ ] **Step 3：改 `deploy_auth.py`**

```diff
--- site-builder/auth/deploy_auth.py	2026-09-07 01:32:02
+++ site-builder/auth/deploy_auth.py	2026-09-07 07:44:57
@@ -16,8 +16,12 @@
 
 import boto3
 
+# 共享的 Function URL resource policy 实现（三个平台脚本 + 闸门共用；构建期 import，不进 auth 的部署包）
+sys.path.insert(0, str(Path(__file__).parent.parent / "deployer" / "functions"))
 sys.path.insert(0, str(Path(__file__).parent))   # 被 verify_deployed_components 按路径加载时也能找到同目录模块
 from alarm_pipeline import ensure_alarm_pipeline
+from function_url_policy import converge as converge_function_url_policy
+from function_url_policy import expected_statements as function_url_statements
 from secrets_util import ensure_secret as _ensure_secret, precheck_parameters
 from session_keys import (env_json, legacy_entry, load_session_keys, ssm_parameter_arns,
                           ssm_parameter_names)
@@ -195,6 +199,20 @@
     precheck_parameters(required_parameters(), ssm=_ssm())
 
 
+def edge_role_arn() -> str:
+    """`[Deployer] edge_role_arn`，先过 `function_url_statements` 的校验（空 / 通配 / 非 role ARN 即 SystemExit）。
+
+    与 panel / key-proxy 第 ① 步同一条纪律：缺配置**中止**，绝不 fallback 到宽权限。放在 precheck 之后、
+    任何写之前——拿空值往下跑的话 Lambda 与角色都建好了才在授权那一步炸，留下半个部署。
+    """
+    arn = cfg().get("Deployer", "edge_role_arn", fallback="")
+    try:
+        function_url_statements(arn)
+    except ValueError as exc:
+        raise SystemExit(f"config.ini [Deployer] edge_role_arn 不可用，拒绝部署（任何写都未发生）：{exc}")
+    return arn
+
+
 def deploy_function(lam, *, role_arn: str, env: dict, code: bytes) -> None:
     """**先配置、后代码**（spec §11.8.3）：1B 的 env 变化都是新增变量——旧代码忽略新变量无害，而新代码
     缺新变量会 500 几秒（1A 那次 502 的同一窗口形状）。L3 删 JWT_SECRET_PARAM 时旧代码在那几秒里也不会
@@ -214,8 +232,10 @@
 
 
 def main():
-    # ⓪ 任何写之前：本函数要读的外部参数都得在（缺参 = 运行时全部登录 500 而脚本 exit 0）
+    # ⓪ 任何写之前：本函数要读的外部参数都得在（缺参 = 运行时全部登录 500 而脚本 exit 0），
+    #    且 Function URL 要授权的 edge role 必须是一个精确的 role ARN（缺 / 通配即中止）。
     precheck()
+    edge_arn = edge_role_arn()
     # 密钥仍在这里**确保存在**（首次部署要生成 JWT secret），但只写进 SSM，
     # 不进环境变量——运行时由 login_handler._secret() 去读。
     keys = load_session_keys(CFG_PATH)
@@ -246,24 +266,12 @@
         url = url_cfg["FunctionUrl"]
         if url_cfg["AuthType"] != "AWS_IAM":
             lam.update_function_url_config(FunctionName=FN, AuthType="AWS_IAM")
-    # 清掉历史的 Principal:* 语句（老版本部署留下的；已被 mitigate 删除时容忍不存在）
-    for sid in ("public-url", "public-url-invoke"):
-        try:
-            lam.remove_permission(FunctionName=FN, StatementId=sid)
-        except lam.exceptions.ResourceNotFoundException:
-            pass
-    # 2025-10 起 Function URL 需要 InvokeFunctionUrl + InvokeFunction 两条语句
-    # （缺一个就 403）。两条各自幂等；与 deploy_lambda_site.py 的站点授权同模式。
-    edge_role_arn = cfg()["Deployer"]["edge_role_arn"]
-    for sid, action, extra in (
-        ("edge-invoke", "lambda:InvokeFunctionUrl", {"FunctionUrlAuthType": "AWS_IAM"}),
-        ("edge-invoke-function", "lambda:InvokeFunction", {"InvokedViaFunctionUrl": True}),
-    ):
-        try:
-            lam.add_permission(FunctionName=FN, StatementId=sid, Action=action,
-                               Principal=edge_role_arn, **extra)
-        except lam.exceptions.ResourceConflictException:
-            pass
+    # resource policy 按期望集合**等值收敛**（merged review M07）：读回 → 内容不对的同名语句替换（edge role
+    # 重建后 IAM 会把 Principal 改写成已删角色的 AROA 形态，同名 Sid 存在但永不匹配）→ 缺的补上 → 野 Sid
+    # 删除（含老版本留下的 public-url / public-url-invoke）→ 写后读回核对。一致时零写入。
+    # "同名 StatementId 已存在就 pass"是这条缺陷的原始形态：同名只说明有一条语句叫这个名字，不说明内容对。
+    # 唯一实现在 deployer/functions/function_url_policy.py，panel / key-proxy / 闸门共用同一份判定。
+    print(f"  Function URL 授权：{converge_function_url_policy(lam, FN, edge_arn).summary()}")
     _ddb().put_item(TableName=cfg()["Platform"]["routing_table"], Item={
         "subdomain": {"S": "auth"}, "site_id": {"S": "auth-service"},
         "route_mode": {"S": "api-only"},  # 全路径走 Lambda（/login 不匹配 /api/*）
```

- [ ] **Step 4：跑绿**

Run: 同 Step 2
Expected: 全绿，含 `test_main_end_to_end_replaces_a_deleted_role_principal_and_clears_legacy_public_statements`（真 converge + 有状态替身：AROA principal 被换、`public-url` 被删）与 `test_rerunning_main_on_a_converged_policy_writes_nothing`（一次 get_policy、零写）。

- [ ] **Step 5：auth 全套 + 记证据**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/auth" && ../contract/.venv/bin/pytest tests -q`
Expected: 全绿（`test_deploy_auth_package.py` 不受影响：`function_url_policy` 是构建期 import，不在 `login_handler` 的闭包里，也不进 `AUTH_PACKAGE_MODULES`）。**不提交。**

---

### Task 3：`deploy_panel.py` 改调共享实现

**Files:**
- Modify: `site-builder/panel/deploy_panel.py`（模块 docstring 第 9–11 行附近；import 段；删 `FUNCTION_URL_AUTH_TYPE = "AWS_IAM"`；删本地 `def function_url_statements`；`ensure_function` 末尾）
- Modify: `site-builder/panel/tests/test_deploy_panel_sequence.py::test_ensure_function_updates_configuration_before_code`
- Modify: `site-builder/panel/tests/test_deploy_panel_contract.py`（文件末尾追加）

**Interfaces:**
- Consumes: Task 1。panel 的 `conftest.py` 已把 `deployer/functions` 铺进 `sys.path`，测试里可直接 `import function_url_policy`。
- Produces: `deploy_panel.function_url_statements`（re-export，`main()` 第 ① 步与既有用例继续调它）、`deploy_panel.converge_function_url_policy`、`deploy_panel.FUNCTION_URL_AUTH_TYPE`（从共享模块 import，既有 `test_function_url_auth_type_is_iam` 继续成立）。**既有用例不删不改**：`test_resource_policy_is_exactly_two_statements_bound_to_edge_role` 与 `test_missing_or_wildcard_edge_role_aborts_instead_of_widening` 原样通过（共享实现的返回形态与原本地实现一致，只有 Sid 名变了，而那两条用例不断言 Sid 名）。

- [ ] **Step 1：写红测试**

`test_deploy_panel_sequence.py` 里那条顺序用例要 stub 掉 converge（它只看更新顺序）：

```diff
--- site-builder/panel/tests/test_deploy_panel_sequence.py	2026-09-07 01:32:02
+++ site-builder/panel/tests/test_deploy_panel_sequence.py	2026-09-07 07:58:03
@@ -71,6 +71,10 @@
 def test_ensure_function_updates_configuration_before_code(monkeypatch):
     lam = Recorder()
     monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: lam)
+    # M07：Function URL 授权走共享的 converge（它要读真 policy，Recorder 给不出来）；本用例只看更新顺序，
+    # converge 的行为在 deployer/tests/test_function_url_policy.py，接线在 test_deploy_panel_contract.py。
+    monkeypatch.setattr(dp, "converge_function_url_policy",
+                        lambda *a, **k: type("D", (), {"summary": lambda self: "一致"})())
     dp.ensure_function("arn:x", b"zip", "AROA-TEST-ROLE-ID")
     head = lam.calls[:7]
     assert head == ["get_function", "update_function_configuration", "get_waiter", "wait",
```

`test_deploy_panel_contract.py` 文件末尾追加：

```python
# ---- M07：Function URL 的 resource policy 走共享的等值收敛 -------------------------------------------
#
# 三条：① 实现是共享的那一份（`function_url_statements` / `converge_function_url_policy` / `FUNCTION_URL_AUTH_TYPE`
# 都从 function_url_policy 来）；② 本脚本里不再有任何 add_permission / remove_permission；③ ensure_function
# 恰好调用一次 converge，实参是 (lam, FN_NAME, 配置里的 edge_role_arn)。converge 自身的行为在
# deployer/tests/test_function_url_policy.py。evidence: fake/unit。

import function_url_policy as fup


def test_deploy_panel_binds_the_shared_function_url_policy_implementation():
    assert dp.function_url_statements is fup.expected_statements
    assert dp.converge_function_url_policy is fup.converge
    assert dp.FUNCTION_URL_AUTH_TYPE is fup.FUNCTION_URL_AUTH_TYPE
    src = (PANEL / "deploy_panel.py").read_text()
    assert "def function_url_statements" not in src, "本脚本又长出了第二份语句定义"


def test_deploy_panel_has_no_direct_permission_calls():
    """"同名 StatementId 已存在就 pass"回来的唯一途径就是有人在这里又写一遍 add_permission。"""
    tree = ast.parse((PANEL / "deploy_panel.py").read_text())
    direct = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("add_permission", "remove_permission")}
    assert direct == set(), direct


def test_ensure_function_converges_the_policy_once_for_the_configured_edge_role(monkeypatch):
    from unittest.mock import MagicMock
    lam = MagicMock()
    for name in ("ResourceNotFoundException", "ResourceConflictException", "InvalidParameterValueException"):
        setattr(lam.exceptions, name, type(name, (Exception,), {}))
    lam.get_function_url_config.return_value = {"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/",
                                                "AuthType": "AWS_IAM"}
    monkeypatch.setattr(dp.boto3, "client", lambda *a, **k: lam)
    monkeypatch.setattr(dp, "_region", lambda: "us-east-1")
    monkeypatch.setattr(dp, "lambda_environment", lambda eid: {})
    monkeypatch.setattr(dp, "_cfg", lambda section, key, default=None:
                        {("Deployer", "edge_role_arn"): EDGE_ROLE}.get((section, key), default or ""))
    calls = []
    monkeypatch.setattr(dp, "converge_function_url_policy",
                        lambda client, fn, arn: calls.append((client, fn, arn)) or fup.Drift())
    dp.ensure_function("arn:aws:iam::000000000000:role/site-panel-role", b"zip", "AROAEXAMPLE")
    assert calls == [(lam, dp.FN_NAME, EDGE_ROLE)]
```

- [ ] **Step 2：跑红**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/panel" && ../deployer/.venv/bin/pytest tests/test_deploy_panel_contract.py tests/test_deploy_panel_sequence.py -q`
Expected: 三条新用例红——`test_deploy_panel_binds_…` 是 `AssertionError`（`dp.function_url_statements is fup.expected_statements` 为 False：现在是本地那份）；`test_deploy_panel_has_no_direct_permission_calls` 红在 `{'add_permission'}`；`test_ensure_function_converges_…` 红在 `AttributeError: module 'deploy_panel' has no attribute 'converge_function_url_policy'`（monkeypatch 目标不存在）。顺序用例此时同样 `AttributeError`。

- [ ] **Step 3：改 `deploy_panel.py`**

```diff
--- site-builder/panel/deploy_panel.py	2026-09-07 01:32:02
+++ site-builder/panel/deploy_panel.py	2026-09-07 07:44:57
@@ -7,7 +7,9 @@
 
 关键约束（改动前先读）：
 - Function URL **必须** AuthType=AWS_IAM，且 resource policy 恰好两条语句、
-  Principal 是逐字符 exact 的 edge role ARN。2025-10 起需要
+  Principal 是逐字符 exact 的 edge role ARN——由 `function_url_policy.converge`
+  **每次部署按期望集合等值写**（读回、替换内容不对的同名语句、删野 Sid、写后读回核对；
+  不是"同名 Sid 存在就 pass"，见 merged review M07）。2025-10 起需要
   InvokeFunctionUrl + InvokeFunction(InvokedViaFunctionUrl) 两条，缺一即 403；
   `AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（实测删光整个
   resource policy）。**缺 edge_role_arn 一律抛错中止，绝不 fallback 到宽权限**
@@ -42,6 +44,11 @@
 CFG.read(HERE.parent / "config.ini")
 # 3c-1A：[SessionKeys] 的唯一定义在 auth/session_keys.py（构建期 import，不进包——运行时只读环境变量）
 sys.path.insert(0, str(HERE.parent / "auth"))
+# Function URL resource policy 的唯一实现（auth / panel / key-proxy / 闸门共用；构建期 import，不进包）
+sys.path.insert(0, str(HERE.parent / "deployer" / "functions"))
+from function_url_policy import FUNCTION_URL_AUTH_TYPE  # noqa: E402
+from function_url_policy import converge as converge_function_url_policy  # noqa: E402
+from function_url_policy import expected_statements as function_url_statements  # noqa: E402
 from secrets_util import precheck_parameters  # noqa: E402
 from session_keys import (env_json, legacy_entry, load_session_keys,  # noqa: E402
                           ssm_parameter_arns, ssm_parameter_names)
@@ -59,7 +66,6 @@
 
 FN_NAME = "site-panel"
 ROLE_NAME = "site-panel-role"
-FUNCTION_URL_AUTH_TYPE = "AWS_IAM"
 RUNTIME = "python3.13"
 
 # 构建时复制进包的模块。**七个都必需**：
@@ -146,34 +152,6 @@
     # 但默认不再用它——留空即走内容指纹。
     v = version or _cfg("Panel", "console_version", "") or frontend_content_version()
     return f"platform/console/{v}"
-
-
-def function_url_statements(edge_role_arn: str) -> list[dict]:
-    """Function URL 的两条 resource policy 语句。
-
-    **缺 edge_role_arn 或给通配一律抛错**：fallback 到 `Principal:*` 会让
-    Function URL 全网可调，而 handler.py 把"x-user-email 存在"当作"请求经过
-    Edge"的证据——两者一起失效意味着任何人都能伪造任意身份调用面板 API。
-    """
-    arn = (edge_role_arn or "").strip()
-    if not arn:
-        raise ValueError(
-            "config.ini [Deployer] edge_role_arn 为空——Function URL 的调用者"
-            "必须绑定到 exact edge role，不能放宽。请先部署路由层并回填该值")
-    if "*" in arn or not arn.startswith("arn:aws:iam::"):
-        raise ValueError(f"edge_role_arn 必须是精确的 IAM role ARN: {arn!r}")
-    return [
-        {"StatementId": "edge-invoke-url",
-         "Action": "lambda:InvokeFunctionUrl",
-         "Principal": arn,
-         "FunctionUrlAuthType": FUNCTION_URL_AUTH_TYPE},
-        # 2025-10 起 InvokeFunctionUrl 单条不够，缺 InvokeFunction 即 403。
-        # InvokedViaFunctionUrl 把它限定为仅经 Function URL 调用。
-        {"StatementId": "edge-invoke-function",
-         "Action": "lambda:InvokeFunction",
-         "Principal": arn,
-         "InvokedViaFunctionUrl": True},
-    ]
 
 
 def role_statements() -> list[dict]:
@@ -472,13 +450,9 @@
                 FunctionName=FN_NAME, AuthType=FUNCTION_URL_AUTH_TYPE)
         url = cur["FunctionUrl"]
 
-    for stmt in function_url_statements(_cfg("Deployer", "edge_role_arn", "")):
-        kwargs = {k: v for k, v in stmt.items() if k != "StatementId"}
-        try:
-            lam.add_permission(FunctionName=FN_NAME,
-                               StatementId=stmt["StatementId"], **kwargs)
-        except lam.exceptions.ResourceConflictException:
-            pass        # 幂等：同 StatementId 已存在
+    # resource policy 按期望集合等值收敛（merged review M07）：读回、替换内容不对的同名语句（edge role 重建后
+    # Principal 会被 IAM 改写成已删角色的 AROA 形态）、删野 Sid、写后读回核对；一致时零写入。
+    print(f"   Function URL 授权：{converge_function_url_policy(lam, FN_NAME, _cfg('Deployer', 'edge_role_arn', '')).summary()}")
     return url
```

- [ ] **Step 4：跑绿**

Run: 同 Step 2
Expected: 全绿。

- [ ] **Step 5：panel 全套 + 记证据**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/panel" && ../deployer/.venv/bin/pytest tests -q`
Expected: 全绿。特别确认 `test_copy_files_covers_every_local_module_panel_imports` 仍绿——它按传递闭包核对 `COPY_FILES`，但**排除 `deploy_panel.py`**（`if p.name != "deploy_panel.py"`），所以构建期 import 的 `function_url_policy` 不会被要求进包（它也确实不该进包）。**不提交。**

---

### Task 4：`deploy_key_proxy.py` 改调共享实现

**Files:**
- Modify: `site-builder/key-proxy/deploy_key_proxy.py`（模块 docstring 第 26–28 行附近；`import keystore` 之后；删 `FUNCTION_URL_AUTH_TYPE = "AWS_IAM"`；删本地 `def function_url_statements`；`ensure_function` 末尾）
- Modify: `site-builder/key-proxy/tests/test_deploy_key_proxy_contract.py`（文件末尾追加）

**Interfaces:**
- Consumes: Task 1。`deploy_key_proxy.py` 本来就 `sys.path.insert(0, HERE.parent / "deployer" / "functions")`，只加 import。
- Produces: 与 Task 3 对称的三个名字。`ensure_function(role_arn, code, edge_role_id_value, cfg=None)` 签名不变。

- [ ] **Step 1：写红测试**（`test_deploy_key_proxy_contract.py` 文件末尾追加；`_cfg()` 是该文件已有的配置工厂，`EDGE_ROLE` / `SCRIPT` 是已有常量）

```python
# ---- M07：Function URL 的 resource policy 走共享的等值收敛（形态与 panel 那三条一致）-------------------

import function_url_policy as fup


def test_deploy_key_proxy_binds_the_shared_function_url_policy_implementation():
    assert dkp.function_url_statements is fup.expected_statements
    assert dkp.converge_function_url_policy is fup.converge
    assert dkp.FUNCTION_URL_AUTH_TYPE is fup.FUNCTION_URL_AUTH_TYPE
    assert "def function_url_statements" not in SCRIPT.read_text(), "本脚本又长出了第二份语句定义"


def test_deploy_key_proxy_has_no_direct_permission_calls():
    tree = ast.parse(SCRIPT.read_text())
    direct = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("add_permission", "remove_permission")}
    assert direct == set(), direct


def test_ensure_function_converges_the_policy_once_for_the_configured_edge_role(monkeypatch):
    from unittest.mock import MagicMock
    lam = MagicMock()
    for name in ("ResourceNotFoundException", "ResourceConflictException", "InvalidParameterValueException"):
        setattr(lam.exceptions, name, type(name, (Exception,), {}))
    lam.get_function_url_config.return_value = {"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/",
                                                "AuthType": "AWS_IAM"}
    monkeypatch.setattr(dkp.boto3, "client", lambda *a, **k: lam)
    calls = []
    monkeypatch.setattr(dkp, "converge_function_url_policy",
                        lambda client, fn, arn: calls.append((client, fn, arn)) or fup.Drift())
    dkp.ensure_function("arn:aws:iam::000000000000:role/site-key-proxy-role", b"zip", "AROAEXAMPLE", _cfg())
    assert calls == [(lam, dkp.FN_NAME, EDGE_ROLE)]
```

- [ ] **Step 2：跑红**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/key-proxy" && ../deployer/.venv/bin/pytest tests/test_deploy_key_proxy_contract.py -q`
Expected: 三条新用例红，形态与 Task 3 Step 2 相同（`AssertionError` / `{'add_permission'}` / `AttributeError`）。

- [ ] **Step 3：改 `deploy_key_proxy.py`**

```diff
--- site-builder/key-proxy/deploy_key_proxy.py	2026-09-07 01:32:02
+++ site-builder/key-proxy/deploy_key_proxy.py	2026-09-07 07:44:57
@@ -24,7 +24,9 @@
   所有 Key 都 401"（两侧单测各自都绿）。
 
 - Function URL **必须** AuthType=AWS_IAM，且 resource policy 恰好两条语句、
-  Principal 是逐字符 exact 的 edge role ARN。2025-10 起需要 InvokeFunctionUrl
+  Principal 是逐字符 exact 的 edge role ARN——由 `function_url_policy.converge`
+  **每次部署按期望集合等值写**（读回、替换内容不对的同名语句、删野 Sid、写后读回核对；
+  不是"同名 Sid 存在就 pass"，见 merged review M07）。2025-10 起需要 InvokeFunctionUrl
   + InvokeFunction(InvokedViaFunctionUrl) 两条，缺一即 403；`AuthType=NONE` +
   `Principal:*` 会被安全扫描自动处置（实测删光整个 resource policy）。
   **缺 edge_role_arn 一律抛错中止，绝不 fallback 到宽权限**——handler 的第 ⓪ 步
@@ -81,13 +83,16 @@
 from handler import AGENTCORE_ENDPOINT_ENV                    # noqa: E402
 from keygen import SWITCH_PK                                  # noqa: E402
 import keystore                                               # noqa: E402
+# Function URL resource policy 的唯一实现（auth / panel / key-proxy / 闸门共用；构建期 import，不进包）
+from function_url_policy import FUNCTION_URL_AUTH_TYPE        # noqa: E402
+from function_url_policy import converge as converge_function_url_policy  # noqa: E402
+from function_url_policy import expected_statements as function_url_statements  # noqa: E402
 
 CFG = configparser.ConfigParser(interpolation=None)
 CFG.read(HERE.parent / "config.ini")
 
 FN_NAME = "site-key-proxy"
 ROLE_NAME = "site-key-proxy-role"
-FUNCTION_URL_AUTH_TYPE = "AWS_IAM"
 RUNTIME = "python3.13"
 # handler 的转发超时是 25s，Lambda 侧留 30s：反过来的话客户端拿到的是空响应
 # 而不是一条可归因的 504。
@@ -203,34 +208,6 @@
         sys.exit("[ApiKey] 段存在但 [Cognito] machine_client_id 为空——"
                  "先跑 deploy_pool.py 建 machine client 并回填 config.ini")
     return mid
-
-
-def function_url_statements(edge_role_arn: str) -> list[dict]:
-    """Function URL 的两条 resource policy 语句（形态与 panel 一致）。
-
-    **缺 edge_role_arn 或给通配一律抛错**：fallback 到 `Principal:*` 会让
-    Function URL 全网可调。对 key-proxy 而言绕过 Edge 不等于绕过认证（攻击者
-    还得有一把有效 Key），但 **Edge 是限流与可观测性的唯一位置**——绕过它意味着
-    Key 的暴力尝试不留任何可告警痕迹。
-    """
-    arn = (edge_role_arn or "").strip()
-    if not arn:
-        raise ValueError(
-            "config.ini [Deployer] edge_role_arn 为空——Function URL 的调用者"
-            "必须绑定到 exact edge role，不能放宽。请先部署路由层并回填该值")
-    if "*" in arn or not arn.startswith("arn:aws:iam::"):
-        raise ValueError(f"edge_role_arn 必须是精确的 IAM role ARN: {arn!r}")
-    return [
-        {"StatementId": "edge-invoke-url",
-         "Action": "lambda:InvokeFunctionUrl",
-         "Principal": arn,
-         "FunctionUrlAuthType": FUNCTION_URL_AUTH_TYPE},
-        # 2025-10 起 InvokeFunctionUrl 单条不够，缺 InvokeFunction 即 403。
-        {"StatementId": "edge-invoke-function",
-         "Action": "lambda:InvokeFunction",
-         "Principal": arn,
-         "InvokedViaFunctionUrl": True},
-    ]
 
 
 def role_statements(cfg=None) -> list[dict]:
@@ -487,14 +464,9 @@
                 FunctionName=FN_NAME, AuthType=FUNCTION_URL_AUTH_TYPE)
         url = cur["FunctionUrl"]
 
-    for stmt in function_url_statements(_cfg(cfg, "Deployer", "edge_role_arn",
-                                             "")):
-        kwargs = {k: v for k, v in stmt.items() if k != "StatementId"}
-        try:
-            lam.add_permission(FunctionName=FN_NAME,
-                               StatementId=stmt["StatementId"], **kwargs)
-        except lam.exceptions.ResourceConflictException:
-            pass        # 幂等：同 StatementId 已存在
+    # resource policy 按期望集合等值收敛（merged review M07）：读回、替换内容不对的同名语句（edge role 重建后
+    # Principal 会被 IAM 改写成已删角色的 AROA 形态）、删野 Sid、写后读回核对；一致时零写入。
+    print(f"   Function URL 授权：{converge_function_url_policy(lam, FN_NAME, _cfg(cfg, 'Deployer', 'edge_role_arn', '')).summary()}")
     return url
```

- [ ] **Step 4：跑绿**

Run: 同 Step 2
Expected: 全绿。`test_help_runs_from_the_real_working_directory` 是子进程真跑 `python3 deploy_key_proxy.py --help`，它同时证明新 import 在真实 cwd 下能解析。

- [ ] **Step 5：key-proxy 全套 + 记证据**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/key-proxy" && ../deployer/.venv/bin/pytest tests -q`
Expected: 全绿。**不提交。**

---

### Task 5：闸门 `verify_deployed_components.py` 对三条 Function URL 都断言

**Files:**
- Modify: `site-builder/scripts/verify_deployed_components.py`（模块 docstring ④ 行；`sys.path` 段；`MIN_DEPLOYED_CHECKS`；`_check_function_url_authz`；④ 段 `_check_env_has_no_plaintext_secret(got_env, "site-auth-service", …)` 之后）
- Modify: `site-builder/deployer/tests/test_verify_deployed_components.py`（`test_the_floor_tracks_state_instead_of_being_a_constant` 的两处数字；文件末尾追加）

**Interfaces:**
- Consumes: Task 1 的 `drift` / `EXPECTED_SIDS`；替身 `fake_lambda_policy`（同目录，直接 import）。
- Produces: `_check_function_url_authz(lam, fn, label, edge_role)` 仍是三条 check（AuthType / 语句集合 / 逐条内容），签名不变，⑤⑧ 两处调用点不动；④ 段新增一处调用，label 是 `"auth"`；`MIN_DEPLOYED_CHECKS == 23`。

- [ ] **Step 1：写红测试**

```diff
--- site-builder/deployer/tests/test_verify_deployed_components.py	2026-09-07 01:32:02
+++ site-builder/deployer/tests/test_verify_deployed_components.py	2026-09-07 08:00:49
@@ -414,10 +414,11 @@
     l3 = (len(g._present(l3_auth, g.AUTH_SESSION_PARAM_KEYS))
           + len(g._present(l3_panel, g.PANEL_SESSION_PARAM_KEYS)))
     assert (l2, l3) == (3, 1), (l2, l3)
-    # L2 的总下限必须与 3c-1B 之前那个常量一致（本次拆分不改变已部署状态）
-    assert g.MIN_DEPLOYED_CHECKS + l2 == 23
+    # M07 给 ④ 补了 auth 的 Function URL 三条（AuthType / 语句集合 / 逐条内容）：L2 从 23 抬到 26
+    assert g.MIN_DEPLOYED_CHECKS == 23
+    assert g.MIN_DEPLOYED_CHECKS + l2 == 26
     # 且 L3 恰好少两条，不是"少一条"或"不变"
-    assert g.MIN_DEPLOYED_CHECKS + l3 == 21
+    assert g.MIN_DEPLOYED_CHECKS + l3 == 24
 
 
 def test_min_param_checks_counts_both_sections_from_the_same_source_as_the_checks():
@@ -428,3 +429,112 @@
         "下限只数了一段——另一段的 *_PARAM 条数不会被补上"
     assert "lambda_env()" in body and "lambda_environment(" in body, \
         "下限没按**本地推导**值数（用线上值会让漏下发变成少核一条而不是红）"
+
+
+# ---- M07：三条平台 Function URL 的授权闸门（auth 此前完全没有）----------------------------------
+#
+# 判定与部署脚本共用 `function_url_policy.drift`；这里只证明闸门把它接对了：三种真实漂移各红在正确的那一条，
+# 正对照全绿，policy 整个不存在按"两条都缺"记红而不是崩。evidence: fake/unit。
+
+import fake_lambda_policy as flp
+
+FUP_EDGE = "arn:aws:iam::000000000000:role/site-edge-role"
+
+
+def _authz(lam, edge=FUP_EDGE):
+    g = _gate()
+    g.results.clear()
+    g._check_function_url_authz(lam, "site-auth-service", "auth", edge)
+    return g.results
+
+
+def test_function_url_authz_is_all_green_on_the_documented_shape():
+    """正对照：与 AWS 文档形态逐字节相同 ⇒ 恰好三条 PASS。"""
+    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE)))
+    assert len(res) == 3 and all(ok for ok, _, _ in res), res
+
+
+def test_function_url_authz_catches_a_principal_rewritten_to_a_deleted_role():
+    """M07 的核心形态：edge role 重建后 Principal 成了 AROA…——只有"逐条内容"那条红，集合那条绿。"""
+    aroa = "AROA" + "EXAMPLEDELETED" + "XXXX"
+    lam = flp.FakeLambdaPolicy([
+        flp.rendered("edge-invoke", "lambda:InvokeFunctionUrl", aroa, function_url_auth_type="AWS_IAM"),
+        flp.rendered("edge-invoke-function", "lambda:InvokeFunction", aroa, invoked_via_function_url=True)])
+    res = _authz(lam)
+    assert [ok for ok, _, _ in res] == [True, True, False], res
+    assert "AROA" in res[2][2], "detail 里要能看到线上的 principal 形态"
+
+
+def test_function_url_authz_catches_a_stray_statement():
+    lam = flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE) + [
+        flp.rendered("public-url", "lambda:InvokeFunctionUrl", "*", function_url_auth_type="NONE")])
+    res = _authz(lam)
+    assert [ok for ok, _, _ in res] == [True, False, True], res
+    assert "public-url" in res[1][2]
+
+
+def test_function_url_authz_catches_a_missing_statement():
+    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE)[:1]))
+    assert [ok for ok, _, _ in res] == [True, False, True], res
+    assert "edge-invoke-function" in res[1][2]
+
+
+def test_function_url_authz_catches_auth_type_none():
+    res = _authz(flp.FakeLambdaPolicy(flp.good_pair(FUP_EDGE), auth_type="NONE"))
+    assert [ok for ok, _, _ in res] == [False, True, True], res
+
+
+def test_function_url_authz_reports_an_absent_policy_as_failures_not_a_crash():
+    """policy 整个不存在（被安全扫描删光的实测形态）⇒ 两条 policy check 红，脚本不崩成"执行中断"。"""
+    res = _authz(flp.FakeLambdaPolicy())
+    assert [ok for ok, _, _ in res] == [True, False, True], res
+    assert "edge-invoke" in res[1][2] and "edge-invoke-function" in res[1][2]
+
+
+def _function_url_authz_targets(src: str) -> set:
+    """源码里每处 `_check_function_url_authz(...)` 调用的**字符串常量实参**集合（按 AST，注释不算）。
+
+    与 `_auth_plaintext_check_param_keys` 同一条纪律：不 grep 文本。panel / key-proxy 那两处用的是变量 `fn`，
+    所以常量集合里只会出现 auth 那处的 "site-auth-service"（以及三处的 label）。
+    """
+    import ast as _ast
+    found = set()
+    for node in _ast.walk(_ast.parse(src)):
+        if isinstance(node, _ast.Call) and getattr(node.func, "id", None) == "_check_function_url_authz":
+            for a in list(node.args) + [kw.value for kw in node.keywords]:
+                if isinstance(a, _ast.Constant) and isinstance(a.value, str):
+                    found.add(a.value)
+    return found
+
+
+def _function_url_authz_targets_in(src: str, function_name: str) -> set:
+    """同上，但只看某个函数体内的调用（按 AST 定位函数，不切源码文本——④ 段的 print 里有框线字符，切片会不可解析）。"""
+    import ast as _ast
+    tree = _ast.parse(src)
+    fn = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef) and n.name == function_name)
+    return _function_url_authz_targets(_ast.unparse(fn))
+
+
+def test_the_auth_section_asserts_the_function_url_policy():
+    """结构守卫：④ 段（run_deployed）里必须有一处对 `site-auth-service` 的 `_check_function_url_authz` 调用。"""
+    src = _SCRIPT.read_text()
+    assert "site-auth-service" in _function_url_authz_targets_in(src, "run_deployed"), "auth 的 Function URL 仍然没有闸门"
+    assert {"auth", "panel", "key-proxy"} <= _function_url_authz_targets(src), "三条平台 Function URL 没有全覆盖"
+
+
+def test_the_auth_target_extractor_reads_arguments_not_comments():
+    """自测：喂给**同一个**抽取器，注释里的字面量不算、实参里的才算。"""
+    assert _function_url_authz_targets(
+        '# 该给 site-auth-service 也加 _check_function_url_authz\n'
+        '_check_function_url_authz(lam, fn, "panel", edge_role)\n') == {"panel"}
+    assert _function_url_authz_targets(
+        '_check_function_url_authz(lam, "site-auth-service", "auth", edge)\n') == {"site-auth-service", "auth"}
+
+
+def test_the_gate_uses_the_shared_drift_judgement_not_its_own():
+    """`_check_function_url_authz` 里必须调用 `function_url_policy.drift`——闸门与部署脚本对"对的形态"只能有一个定义。"""
+    import ast as _ast
+    tree = _ast.parse(_SCRIPT.read_text())
+    fn = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef) and n.name == "_check_function_url_authz")
+    calls = {_ast.unparse(n.func) for n in _ast.walk(fn) if isinstance(n, _ast.Call)}
+    assert any(c == "drift" or c.endswith(".drift") for c in calls), sorted(calls)
```

- [ ] **Step 2：跑红**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests/test_verify_deployed_components.py -q`
Expected: 这些红——`test_the_floor_tracks_state_instead_of_being_a_constant`（20 ≠ 23）、`test_the_auth_section_asserts_the_function_url_policy`（④ 段没有那处调用）、`test_the_gate_uses_the_shared_drift_judgement_not_its_own`（旧实现自己数集合）、`test_function_url_authz_catches_a_stray_statement`（旧实现的动作集合仍是那两个 ⇒ 第二条绿、第三条红，与新期望 `[True, False, True]` 不同）、`test_function_url_authz_reports_an_absent_policy_as_failures_not_a_crash`（旧实现直接 `get_policy` 抛 `ResourceNotFoundException`）。其余几条（AROA / 缺一条 / AuthType NONE / 正对照）在旧实现下也绿——它们是**正对照与既有语义**，不是本票的判别用例，留着防回归。

- [ ] **Step 3：改 `verify_deployed_components.py`**

```diff
--- site-builder/scripts/verify_deployed_components.py	2026-09-07 01:32:02
+++ site-builder/scripts/verify_deployed_components.py	2026-09-07 08:00:49
@@ -12,7 +12,8 @@
      （①② 是纯本地判定，--local 时只跑这两段。x-user-name 那条红线进过
       "修漏报 → 引入误报 → 再修"的循环，所以正反两侧都要覆盖。）
   ③ 线上 deployer Lambda 群：contract/redlines.py + 守卫三件套逐包核对；
-  ④ 线上 auth 服务：login_handler.py / session.py + SSM TTL 在产物中；
+  ④ 线上 auth 服务：login_handler.py / session.py + SSM TTL 在产物中 + Function URL AuthType 与
+     resource policy 等值（M07 之前这条 Function URL **没有任何闸门**）；
   ⑤ 线上 panel：**进包清单从 `deploy_panel.COPY_FILES` 推导**后逐字节核对
      + Function URL AuthType 与 resource policy 两条语句 + 环境变量**无明文
      密钥** + 非 Edge 的签名直连必须 403；
@@ -64,6 +65,8 @@
 HERE = Path(__file__).parent
 ROOT = HERE.parent.parent
 sys.path.insert(0, str(ROOT / "site-builder/contract/src"))
+# Function URL resource policy 的判定与三个部署脚本同一份（deployer/functions/function_url_policy.py）
+sys.path.insert(0, str(ROOT / "site-builder/deployer/functions"))
 CFG_PATH = HERE.parent / "config.ini"
 # Lambda@Edge 的产物在 router 那一侧（⑧ 要读它的 PLATFORM_SUBDOMAINS）
 ROUTER_CFG_PATH = ROOT / "router" / "config.ini"
@@ -83,9 +86,9 @@
 # ④ 段的 `*_PARAM` 条数**随状态变**：L2 是两个（JWT_SECRET_PARAM + LOGIN_FLOW_SECRET_PARAM），
 # L3 清空 legacy_param 之后只剩一个。所以这里只记**恒定**的那部分，`*_PARAM` 那几条由
 # `_min_param_checks()` 在运行时按本地推导值补上——写死 2 会让 L3 的每次核对都差一条而红。
-MIN_DEPLOYED_CHECKS = 20    # ③ 4 + ④ 1 + ⑤ 6 + ⑥ 3 + ⑦ 6 = 20（④⑤ 都已扣掉 `*_PARAM` 那几条）
-# L2 下 20 + 3 = 23，与 3c-1B 之前的常量一致（本次拆分不改变已部署状态的下限）；
-# L3 下 20 + 1 = 21，正好少掉 auth 与 panel 各一条 legacy 的 `*_PARAM`。
+# ④ 的 Function URL 三条（AuthType / 语句集合 / 逐条内容）是 M07 补的：此前 auth 的 Function URL 完全不在闸门里。
+MIN_DEPLOYED_CHECKS = 23    # ③ 4 + ④ 4 + ⑤ 6 + ⑥ 3 + ⑦ 6 = 23（④⑤ 都已扣掉 `*_PARAM` 那几条）
+# L2 下 23 + 3 = 26；L3 下 23 + 1 = 24，正好少掉 auth 与 panel 各一条 legacy 的 `*_PARAM`。
 # ⑧ 只在 [ApiKey] 段存在（组件启用）时计入：产物 1 + 环境变量 2 + scope 1 +
 # Function URL 3 + EDGE_ROLE_ID 1 + 环境变量整体 1 + route 6 + Edge 白名单 1 +
 # runtime 3 + 哨兵行 2 + role 2 = 23
@@ -497,33 +500,41 @@
 
 
 def _check_function_url_authz(lam, fn: str, label: str, edge_role: str) -> None:
-    """Function URL 的 AuthType + resource policy 恰好两条动作 + Principal 逐字符。
+    """Function URL 的 AuthType + resource policy 与期望集合**等值**（三条 check）。
 
-    2025-10 起需要 `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl)
-    两条，缺一即 403；`AuthType=NONE` + `Principal:*` 会被安全扫描自动处置
-    （实测删光整个 resource policy）。
+    判定不在这里另写一份，用部署脚本写 policy 时的同一个 `function_url_policy.drift`：闸门与部署脚本对
+    "对的形态"只能有一个定义（M07 的教训是部署脚本只管加、闸门只数动作与 principal 集合，于是 Sid 改名、
+    Condition 缺失、多一条同 principal 的语句都是假绿）。2025-10 起需要 `InvokeFunctionUrl` +
+    `InvokeFunction`(InvokedViaFunctionUrl) 两条，缺一即 403；`AuthType=NONE` + `Principal:*` 会被安全扫描
+    自动处置（实测删光整个 resource policy）。policy 整个不存在按"两条都缺"记红，不让脚本崩成"执行中断"。
     """
     import json
 
+    import function_url_policy as fup
+
     url_conf = lam.get_function_url_config(FunctionName=fn)
     check(url_conf["AuthType"] == "AWS_IAM",
           f"{label} Function URL AuthType=AWS_IAM",
           f"实际 {url_conf['AuthType']}"
           + ("" if url_conf["AuthType"] == "AWS_IAM"
              else " —— NONE 等于 endpoint 全网可调"))
-    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
-    actions, principals = set(), set()
-    for s in policy.get("Statement", []):
-        a = s.get("Action")
-        actions |= set(a if isinstance(a, list) else [a])
-        p = s.get("Principal", {})
-        principals.add(p.get("AWS") if isinstance(p, dict) else p)
-    check(actions == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"},
-          f"{label} resource policy 恰好两条动作（2025-10 起缺一即 403）",
-          f"实际 {sorted(actions)}")
-    check(principals == {edge_role},
-          f"{label} Principal 逐字符 == edge role（不是 * 不是账号根）",
-          f"实际 {sorted(principals)}")
+    try:
+        policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
+    except lam.exceptions.ResourceNotFoundException:
+        policy = None
+    d = fup.drift(policy, edge_role)
+    # 只为诊断文案：线上到底授给了谁（AROA… 一眼就能认出是"角色被删过"）
+    principals = sorted({str(p.get("AWS") if isinstance(p, dict) else p)
+                         for p in (s.get("Principal") for s in (policy or {}).get("Statement", []))})
+    check(not d.missing and not d.stray,
+          f"{label} resource policy 恰好是期望的两条语句（Sid 无缺无多；2025-10 起缺一即 403）",
+          f"缺 {list(d.missing)}，非预期 {list(d.stray)}" if (d.missing or d.stray)
+          else f"{list(fup.EXPECTED_SIDS)}")
+    check(not d.mismatched,
+          f"{label} 每条语句的 Principal / Action / Condition 逐字节 == 期望"
+          "（Principal 是 exact edge role，不是 * / 账号根 / 已删角色的 AROA 形态）",
+          f"内容不对 {list(d.mismatched)}；线上 principals={principals}" if d.mismatched
+          else "与部署脚本写入的形态一致")
 
 
 def _check_edge_role_id_env(env: dict, edge_role: str, label: str) -> str:
@@ -707,6 +718,9 @@
     # 且**不会因为线上少了一个键而少核一条**（少了的话整体等值那条先红）。
     _check_env_has_no_plaintext_secret(got_env, "site-auth-service",
                                        _present(want_env, AUTH_SESSION_PARAM_KEYS))
+    # M07：auth 的 Function URL 此前**没有任何闸门**——edge role 重建后 policy 仍授旧 principal ⇒ 全平台登录
+    # 403 而 deploy_auth exit 0。与 ⑤⑧ 同一个判定，三条平台 Function URL 全覆盖。
+    _check_function_url_authz(lam, "site-auth-service", "auth", read_cfg("Deployer", "edge_role_arn"))
 
 
 def run_panel() -> None:
```

- [ ] **Step 4：跑绿**

Run: 同 Step 2
Expected: `39 passed`。

- [ ] **Step 5：deployer 全套 + 记证据**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests -q`
Expected: 全绿。**不提交。**

---

### Task 6：采用者文档（CLAUDE.md 一条扩写 + 矩阵一行；DEPLOY.md 一段）

**Files:**
- Modify: `CLAUDE.md`「高频坑」第一条（`- Function URL 一律 …` 那条）与「跨组件改动矩阵」表（在「验收工具的本地 mint」那行之后加一行）
- Modify: `site-builder/DEPLOY.md`——② 路由层那节"记录 CfnOutput 的 **EdgeRoleArn**，回填 …" 那条列表项之后加一段

**Interfaces:** 无代码。三段措辞都已用 `test_delivery_docs_current._status_violations` 预检为零命中（不含日期 / SHA / 状态词）。

- [ ] **Step 1：CLAUDE.md 高频坑第一条改成**

```markdown
- Function URL 一律 `AuthType=AWS_IAM` + 只授权 edge role，且需要
`InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl) 两条语句，缺一即 403。
`AuthType=NONE` + `Principal:*` 会被安全扫描自动处置（删光 resource policy）。
**三个平台脚本的 resource policy 由 `function_url_policy.converge` 每次部署按期望集合等值写**
（读回、替换内容不对的同名语句、删野 Sid、写后读回核对；一致时零写入）——"同名 StatementId 已存在
就 pass"是假幂等：edge role 被删后重建时 IAM 会把 policy 里的 Principal 改写成已删角色的 AROA 形态，
同名语句存在但永不匹配，症状是重部 exit 0 而 Edge 全 403（auth 那条 = 全平台登录不可用）。
`verify_deployed_components.py` 对 auth / panel / key-proxy 三条都用同一个 `drift` 断言。
```

（原条目里 `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl) 与 `AuthType=NONE` 两句保留原文；只新增后半段。）

- [ ] **Step 2：CLAUDE.md 跨组件改动矩阵加一行**（放在「验收工具的本地 mint」那行之后）

```markdown
| `deployer/functions/function_url_policy.py`（Function URL resource policy 的唯一实现） | 三个部署脚本的 `converge_function_url_policy` 调用（auth 的 `edge_role_arn()` 校验、panel / key-proxy 的 `ensure_function`）、闸门 `_check_function_url_authz` 与 `MIN_DEPLOYED_CHECKS`、`deploy_lambda_site` 的 parity 用例（站点色授权与平台三条同形）、`fake_lambda_policy.py` 的渲染形态 |
```

- [ ] **Step 3：DEPLOY.md ② 节回填 `edge_role_arn` 的列表项之后加一段**

```markdown
**换 edge role 之后**（路由层栈重建、角色重创、或修正写错的 `edge_role_arn`）：重跑 ⑤ `deploy_auth.py`、⑤b `deploy_panel.py`、⑤c `deploy_key_proxy.py` 即可——三个脚本每次都按期望集合等值收敛各自 Function URL 的 resource policy（读回、替换内容不对的同名语句、删野 Sid、写后读回核对；一致时零写入）。IAM 在角色被删时会把 policy 里的 Principal 改写成已删角色的唯一 ID，所以"同名语句已存在"不等于授权还对；`verify_deployed_components.py` 对三条都断言。
```

- [ ] **Step 4：跑文档守卫**

Run: `cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests/test_delivery_docs_current.py -q`
Expected: 全绿（含 `test_status_free_docs_carry_no_environment_status[CLAUDE.md]`）。红了先看是哪个词命中了状态模式，改措辞，**不要**给守卫加豁免。

- [ ] **Step 5：记证据。不提交。**

---

## 交给 coordinator 的部分（本 plan 的 worker 不做）

**合并与全量套件**：按 CLAUDE.md「测试命令」顺序跑七套件（不并行；`test_redlines.py` 的墙钟哨兵红了先单独重跑一次）。`git add` 前后各跑一次 `bash site-builder/scripts/scan_staged_secrets.sh`。

**部署顺序与预期输出（验证环境；evidence: sandbox）**：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/auth && python3 deploy_auth.py)          # 预期打印 "Function URL 授权：一致"，
                                                          #   或 "非预期 N 条(public-url, …)"（老版本残留时）
(cd site-builder/panel && python3 deploy_panel.py)        # 预期 "缺 1 条(edge-invoke)、非预期 1 条(edge-invoke-url)"
(cd site-builder/key-proxy && python3 deploy_key_proxy.py) # 同上（有 [ApiKey] 段时）
```

- **第一次跑**：panel / key-proxy 各换一次 Sid 名（先加 `edge-invoke`、后删 `edge-invoke-url`，零窗口）；auth 若还有 `public-url*` 残留会被删。三个脚本都会在写后读回核对——**这一步就是 AWS 渲染形态假设（`Bool` / `StringEquals`）的真机核对**。若任一脚本抛 `PolicyDriftError: … 收敛后读回仍不一致`，先 `aws lambda get-policy --function-name <fn>` 看原文，再改 `function_url_policy._rendered_condition` 与 `fake_lambda_policy.rendered` 两处（同一处知识），**不要**放宽比较。
- **第二次跑同三条**：三处都应打印 `一致`，且 CloudTrail 里没有 `AddPermission` / `RemovePermission`（零写入的实测证据）。
- `python3 site-builder/scripts/verify_deployed_components.py`：④ 段多出三条 PASS（`auth Function URL AuthType=AWS_IAM` / `auth resource policy 恰好是期望的两条语句…` / `auth 每条语句的 Principal / Action / Condition 逐字节 == 期望…`），总下限比之前 +3。
- `python3 site-builder/scripts/verify_account_trust_boundary.py`（可选，约 11 分钟）：Sid 换名**不应**产生漂移（`canonicalize_statement` 丢 Sid）。红了就是意料之外，停下来看 diff，不要 `--update-baseline`。
- 冒烟：`bash site-builder/scripts/smoke_router.sh` 或直接登录一次 + 打开控制台——auth / panel 的 Function URL 仍只对 Edge 放行。

**决策门（worker_done 里同时列出；实施前裁定）**：

1. **共享模块落点** `deployer/functions/function_url_policy.py`（推荐：三个脚本与闸门都能用同一条相对路径找到，与 `edge_caller.py` / `api_key_config.py` 同理；不进任何产物）vs 放 `auth/`（panel 已从那儿 import 会话相关模块，但 key-proxy 没有，且这不是会话面）。
2. **Sid 统一为 `edge-invoke` / `edge-invoke-function`**（推荐：与 `deploy_lambda_site` 及 auth 现状同名；panel / key-proxy 下次部署换名，先加后删零窗口，信任边界基线不受影响）vs 各脚本保留现名（需要给 `converge` 加每调用方的 Sid 参数，期望集合就不再是一个定义）。
3. **`deploy_lambda_site.py` 本票只加 parity 用例、不改代码**（推荐：改它要重部 deployer 栈（Docker bundling），且它的 remove→add 语义是候选色不在路由上的前提下设计的；共享模块已带 `qualifier=` 口子，将来一次 import 替换即可）vs 本票一并重构成调用 `converge`。
4. 闸门下限 20 → 23（L2 26 / L3 24）——机械后果，告知即可。
5. CLAUDE.md / DEPLOY.md 三段措辞（Task 6）——已过状态词守卫预检，是否按原文落。

## Self-Review

- **Spec coverage**：工单三句——"三个脚本每次都按期望集合等值写 policy" → Task 1–4；"两条语句、只授 edge role" → `expected_statements` + drift 的逐条内容比较（Task 1）；"verify_deployed_components 对三条都断言" → Task 5。资产检查那行 → Task 6 + Global Constraints。M07 原文的"闸门缺口"与"文档声称了但代码不校验"（deploy_panel / deploy_key_proxy 的 docstring）→ Task 3/4 的 docstring 改写 + Task 5。
- **Placeholder scan**：每个代码步骤都是整段可落盘的内容（全部在镜像上跑过）；没有待补字样，也没有用"参见别的 Task"代替代码。
- **Type consistency**：`converge(lam, fn, edge_role_arn)` 的三处调用（Task 2/3/4）与 Task 1 签名一致；`Drift.summary()` 三处 print 调用一致；`_check_function_url_authz(lam, fn, label, edge_role)` 签名未变、④ 段新增调用与 ⑤⑧ 同形；`FUNCTION_URL_AUTH_TYPE` 在 panel / key-proxy 由 import 提供，既有 `update_function_url_config(AuthType=FUNCTION_URL_AUTH_TYPE)` 调用点不动。
