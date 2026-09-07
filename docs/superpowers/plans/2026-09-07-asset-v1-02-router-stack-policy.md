# router 栈的 CloudFormation stack policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 router 栈加一份 CloudFormation stack policy，用**精确逻辑 ID**（不用 `*`）拒绝对 Edge 两个函数、CloudFront 分发与路由表的更新，并把"策略存在且覆盖这四个资源"做成 `verify_deployed_edge.sh` 的一段真机核对。

**Architecture:** CloudFormation 模板与 `cdk deploy` 都表达不了 stack policy，所以策略由一个宿主机脚本在部署**之后**按**已部署模板**推导四个逻辑 ID 并 `SetStackPolicy`，每次部署重申；部署**之前**用同一脚本把策略临时换成 Allow-all（stack policy 设上就删不掉，只能换）。声明（哪四个 construct、什么类型、拒什么动作）与推导 / 比较逻辑住在一个只依赖标准库的模块里，`stack.py` 在 synth 期用它核对"声明与栈一致"，脚本与闸门用它推导与比较——三处一份定义。闸门 `check` 只读。

**Tech Stack:** Python 3.12（`deployer/.venv`，无 aws_cdk）/ aws-cdk-lib 2.100.0（`router/infrastructure/.venv`，只用于离线 synth）/ 宿主机 `python3` ≥ 3.10 + boto3（脚本与闸门）/ CloudFormation `SetStackPolicy` / `GetStackPolicy` / `GetTemplate` / bash（`verify_deployed_edge.sh`）

**Spec:** 工单 `.scratch/asset-v1/issues/02-router-stack-policy.md`（**gitignored，新 clone 里没有**）。tracked 的依据：`docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 第 3f 行（威胁陈述与"−4"的出处）、`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §1「各候选缓解措施的边际收益」表、`docs/adr/0005-*.md`（交付物是资产）。AWS 文档依据（静态证据）：CloudFormation User Guide「Prevent updates to stack resources」与 API Reference `ExecuteChangeSet`——三条原话在下面「威胁模型」里逐字引用。

## Global Constraints

- **每个 shell 块开头 `set -euo pipefail`。** 本机 shell 是 zsh：`${PIPESTATUS[0]}` 展开成空串（zsh 用 `$pipestatus`），不带 `pipefail` 时 `cmd | tee` 的退出码是 tee 的 0。不许用管道尾判命令成败。
- **worker 不部署、不提交、不 push、不动 AWS 资源。** Task 1–5 全部离线（单测 + 离线 synth）；Task 6 是 coordinator 在验证环境手工做的，plan 里只写步骤与判据。
- **不许把真实账号 ID / 分发 ID / 内部角色名写进任何被跟踪的文件**；fixture 一律 `000000000000`、假哈希 `AAAAAAAA`。逻辑 ID 的 8 位哈希**也不硬编码**——它由推导得出。
- **测试命令照抄 CLAUDE.md「测试命令」，顺序跑、不并行**（contract 有墙钟哨兵）。本 plan 只碰两套：
  `(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)` 与
  `(cd site-builder/deployer && .venv/bin/pytest tests -q)`（**必须带 `tests/`**）。
- **`scripts/*.py` 用不带路径的 `python3` 跑**（≥ 3.10，装了 boto3 与 pip-system-certs），不借任何 venv 的解释器。
- **CLAUDE.md 有状态守卫**（`test_delivery_docs_current.py::test_status_free_docs_carry_no_environment_status`）：不写日期、SHA、"已部署 / 尚未 / 待做 / 已于 / ticket N 起"。Task 5 的 CLAUDE.md 文案已经用那条守卫的 `_status_violations` 跑过一遍（0 命中），照抄即可。
- **改 construct ID 就是替换资源**（逻辑 ID 变 ⇒ 新建 + 删旧）。本 plan **不改任何既有 construct ID、不用 `override_logical_id`**——对分发与路由表那是事故不是重构。
- **不读本地 `cdk.out` 推导逻辑 ID**：它可能陈旧，也可能刚被 `rm -rf`；推导只从 `GetTemplate` 拿到的已部署模板来。
- **每个提交都必须是绿的 checkout**（提交由 coordinator 在集成泳道做；worker 只在工作树里改）。

---

## 决策门（coordinator 裁定之后才能执行）

本 plan 按**推荐项**写成可执行代码；选了另一项时按每条后面的「改动清单」改，不需要重写 plan。

### D1：Deny 的动作集合——`Update:*` 还是工单原话的 `Update:Replace` + `Update:Delete`

**推荐 `Update:*`（含 Modify）。** 理由是一个事实：**Edge 换码是 Lambda `Code` 属性的 `Update:Modify`，不是 Replace**（CloudFormation 对 `AWS::Lambda::Function` 的 `Code` 标注 *Update requires: No interruption*）。CDK 每次 Edge 部署的形态是：Function **Modify** + 新建一个 `…CurrentVersion<hash>` 资源 + 删掉旧的 Version 资源 + Distribution **Modify**（关联指向新版本）。所以：

| | `Update:*` | `Update:Replace` + `Update:Delete`（工单原话） |
|---|---|---|
| 拦得住"经 UpdateStack / ExecuteChangeSet 替换 Edge 验签代码"（§9 3f 的威胁陈述） | **是**（对无 `cloudformation:SetStackPolicy` 的 principal） | **否**——Modify 放行，攻击不受影响 |
| §9 3f / spec §1 表里的"−4" | 可以成立（前提见 D2） | **不成立**：那 4 个 principal 仍在冒充面里 |
| 拦得住误删路由表、替换分发（换域名）、重命名 Edge 函数 | 是 | 是 |
| 日常 router 部署 | **每次**三步：`open` → `cdk deploy` → `apply`（忘 open ⇒ 干净失败 + 整栈回滚，Edge 不受影响） | `cdk deploy` 照旧；只需部署后 `apply`（首次之后其实都是重申） |
| 与 CLAUDE.md 那条"别按 M09 第 2 步原话收窄 invoke，那是假修复"的关系 | 真修复的形状 | **同一个假修复形状**：名义上"加了 stack policy"，实际没动威胁路径 |

**若裁定为工单原话**，改动清单：① `stack_policy.DENIED_ACTIONS = ("Update:Replace", "Update:Delete")`；② `test_denied_actions_pin_the_d1_ruling` 的期望值同步；③ `test_policy_problems_negative_controls_name_the_defect` 里 `replace-delete-only` 那条反例变成正对照，另加一条 `update-star-only`（Deny `Update:*` 是超集，`policy_problems` 会因不等价而红——这是想要的）；④ 删掉 `router_stack_policy.py` 的 `open` 子命令与其测试，`COMMANDS` 只剩 `apply` / `check`；⑤ Task 5 的文档只在 router 部署**之后**加 `apply`，docs 守卫只断言 `apply`；⑥ coordinator 要改 §9 3f 与 spec §1 表：那一行的收益要改写成"防误删 / 误替换，不减冒充面"。

### D2：探针与 spec §1 的"−4"要不要在本票里重算

**推荐：不在本票做，但要作为后续项记下。** `probe_impersonation_surface.py` 的 `MITIGATIONS["router-stack-policy"]` 把这项建模成"关掉 `edge:cfn-update-stack` 与 `edge:cfn-change-set` 两条路"，而 stack policy 的真实效果是**只对没有 `cloudformation:SetStackPolicy`（对该栈）的 principal 关掉它们**（AWS 文档原话见下）。正确的建模是给探针加一个动作等价类 `cloudformation:SetStackPolicy|STACK`，并在计算边际收益时只把"持有 CFN 路、不持有 SetStackPolicy"的 principal 算成离开。探针不在工单「What to build」里，改它是另一张票；部署本票之后重跑一次探针（只读、约 20 分钟）才能拿到真实的 −N。

### D3：`EdgeFunctionRole`（及其 DefaultPolicy）要不要一起进受保护集合

**推荐：不进。** 工单点名的是 Edge 函数、分发、路由表三类。角色的 Modify 是每次给 edge role 加权限的正常路径；它不在 §9 3f 的威胁路径上（换角色策略不改变验签代码）。要加的话只是往 `PROTECTED_CONSTRUCTS` 加两行 + fixture 加两个资源，随时可以做。

### D4：DeleteStack 不在 stack policy 的射程内，要不要顺手开 termination protection

**推荐：另开一张小票，不在本票做。** stack policy 只管 UpdateStack / ExecuteChangeSet；`DeleteStack` 归 termination protection。CDK 原生支持（`Stack(..., termination_protection=True)` 一行），但那是另一个控制面，且 `cdk destroy` 的手册路径要跟着改。本 plan 的文档把这条边界写明白（"不防 DeleteStack"），不替它做决定。

### D5：要不要写一份 ADR

**推荐：写。** D1 是一个会长期影响每次 router 部署的取舍（多两步换一个真的威胁缩减），正是 ADR 该记的东西；本 plan 的「威胁模型」一节就是 ADR 的底稿。Task 6 之后由 coordinator 用 `/domain-modeling` 落成 `docs/adr/0007-router-stack-policy-denies-update-star.md`——ADR 由 skill 生成、不由本 plan 预写，避免两份互相漂移。

---

## 威胁模型、不变量与失败分析（这是新的发布闸门面，按 CLAUDE.md 的纪律单独分析）

### 依据（**静态证据：AWS 文档原话**，不是实测）

1. 「Prevent updates to stack resources」：*"To update protected resources, you must have permission to use the CloudFormation SetStackPolicy action."* ⇒ 越过策略的门槛是 `cloudformation:SetStackPolicy`，而不是 `UpdateStack`。
2. API Reference `ExecuteChangeSet`：*"If a stack policy is associated with the stack, CloudFormation enforces the policy during the update. You can't specify a temporary stack policy that overrides the current policy."* ⇒ change set 那条路**根本没有临时覆盖**，只能先 `SetStackPolicy`。CDK CLI 默认就走 change set，且没有传 stack policy 的旗标。
3. 同一页：*"CloudFormation evaluates stack policies against both the logical resource ID and the resource type independently. A default denial blocks an update only when both evaluations result in a denied status."* ⇒ 必须用**显式 `Deny`** 点名逻辑 ID；`NotResource` 那种写法拦不住。另：策略一旦设上，**未被 Allow 的一律拒**，所以策略里必须先有一条 `Allow Update:* on *`。
4. 同一页注记：依赖被更新资源的资源会被 CloudFormation **自动更新**，而且"如果 stack policy 覆盖了它们，你也必须有更新它们的权限" ⇒ Edge 换版本时 Distribution 一定被动 Modify——这正是把分发列进 Deny 的意义，也是每次 Edge 部署必须 `open` 的原因。

### 防什么 / 不防什么

- **防**：持有 `cloudformation:UpdateStack`，或 `CreateChangeSet` + `ExecuteChangeSet`，**但没有** `cloudformation:SetStackPolicy` 的 principal，无法对四个受保护资源做任何 Update 动作（含 Modify）。§9 3f 量到的 17 / 16 个 principal 里有多少落在这个集合，要靠 D2 的探针重算。
- **不防**：持有 `SetStackPolicy` 的人（等于能 `open`）；`DeleteStack`（D4）；绕开 CloudFormation 直接调 Lambda / CloudFront API（spec §1 已证明那条直接链的边际收益是 0，因为持有者同时持有 CFN 路——本策略正是补 CFN 这条）；账号内只读身份读密钥（3c-final 的事）。
- **它不是 IAM 的替代品**（AWS 文档原话），是给 CFN 这条路加的一道必须显式越过的门。

### 不变量

- **I1**：任何时刻栈上的策略要么是 `build_policy(已部署模板)` 的等价物（"关"），要么是 `OPEN_POLICY`（"开"）。没有第三态。`check` 只接受"关"。
- **I2**：`apply` 写入之后必须**读回**并比对等价；写了但读回不等价 ⇒ 退 1，不算成功。
- **I3**：推导不出全部四个逻辑 ID（缺、多义、类型不符）⇒ `apply` **不写任何东西**就退 1。绝不写一份缺项的策略。
- **I4**：`check` 不发任何写调用（测试用假 client 的写日志断言为空）。
- **I5**：`stack.py` 的声明与栈不一致（construct 改名 / L1 类型变 / 逻辑 ID 不符合推导正则）⇒ **synth 失败**，什么都不部署。
- **I6**：Deny 语句的 `Resource` 只含 `LogicalResourceId/<精确 ID>`，任何通配都判红。

### 失败分析

| 场景 | 后果 | 谁发现 | 处置 |
|---|---|---|---|
| 忘了 `open` 就 `cdk deploy`（改动碰到受保护资源） | ExecuteChangeSet 阶段该资源 `UPDATE_FAILED`（原因含 stack policy 拒绝），整栈回滚到原状；**Edge 不受影响** | 部署命令本身非 0 | `open` 后重跑 |
| `open` 之后 deploy 失败 / 中断 | 保护是开着的 | **没有部署输出会说**；只有 `verify_deployed_edge.sh` ⑤ 会红 | 文档与脚本输出都写死"open 之后无论成败都要 apply" |
| 忘了 `apply` | 同上 | 同上 | 同上 |
| 两个人并发：一个 deploy 进行中，另一个 `open` / `apply` | `*_IN_PROGRESS` 时两条都拒绝退 1（`DescribeStacks` 与 `SetStackPolicy` 之间有极小窗口，不做原子承诺） | 脚本 | 等结束再跑 |
| 首次部署（栈不存在） | `open` 打印 SKIP 退 0；`cdk deploy` 建栈；`apply` 设策略 | — | 新账号 runbook 的 ② 就是这个顺序 |
| 有人用 `cloudformation set-stack-policy` 手工打开又忘了关 | 与"忘 apply"同形 | ⑤ 红；下一次正常部署的 `apply` 会把它关回去（重申是刻意的） | — |
| 回滚本功能（撤掉脚本与 stack.py 的守卫） | **策略不会跟着消失**（设上就删不掉）：后续碰到受保护资源的部署会失败 | 部署命令 | 先 `open`（或手工 set-stack-policy 成 Allow-all），再撤代码 |
| CDK 升级改变逻辑 ID 分配规则 | I5 让 synth 失败，I3 让 `apply` 拒写；`check` 会红 | synth / 闸门 | 更新 `logical_id_pattern`，同时改 `stack_policy.py` 与两侧测试 |
| 模板里出现第二个 `Distribution<8hex>`（例如新加一个分发） | 多义 ⇒ I3 / I5 都红 | synth | 给新 construct 起不以 `Distribution` 开头的名字，或扩展声明 |

### 证据等级（按 CLAUDE.md 要求标明）

- **静态（文档）**：上面四条 AWS 原话；`Update:Modify` 对 Lambda `Code` 的分类。
- **假 / 单元**：Task 1、3 的全部测试；Task 5 的 docs 守卫。
- **集成（无 AWS）**：Task 2 的离线 synth——真 aws-cdk-lib 对象上验证 `try_find_child` / `default_child` / `cfn_resource_type` / `get_logical_id` 的行为与正则，含改名反例。**写 plan 时已在临时目录跑过一遍**（router 套件 336 通过、CLI 21 通过、docs 守卫在当前文档上恰好点出 4 处围栏内部署点 + 1 处表格）。
- **验证环境**（Task 6，coordinator）：`open` → `check` 红 → `apply` → `check` 绿；完整 `verify_deployed_edge.sh`。**没有实测的一条**：CloudFormation 拒绝时事件里的确切文案——文档里只写"原因含 stack policy"，不引用未见过的原话。

---

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `router/infrastructure/stack_policy.py` | **唯一定义**：受保护 construct 声明、拒绝动作、逻辑 ID 推导、策略体、等价比较、synth 期守卫。只依赖标准库 | Create（Task 1） |
| `router/infrastructure/lambda/test_stack_policy.py` | 上面那个模块的纯函数测试 + `stack.py` 接线的源码 / AST 守卫。跟 `test_stack_static.py` 同一套件、同一做法 | Create（Task 1）/ Modify（Task 2 追加两条） |
| `router/infrastructure/stack.py` | 一行 import + 一行 `assert_protected_constructs(self)`（在分发创建之后、Outputs 之前） | Modify（Task 2） |
| `site-builder/scripts/router_stack_policy.py` | 宿主机脚本：`open` / `apply` / `check`，config.ini 取栈名与区域，boto3 client 可注入 | Create（Task 3） |
| `site-builder/deployer/tests/test_router_stack_policy.py` | 脚本对假 CloudFormation client 的副作用契约；⑤ 接进闸门的结构守卫 | Create（Task 3）/ Modify（Task 4 追加一条） |
| `site-builder/scripts/verify_deployed_edge.sh` | 新增 ⑤：调 `router_stack_policy.py check`，红则 `fail()` | Modify（Task 4） |
| `site-builder/deployer/tests/test_delivery_docs_current.py` | 新守卫：文档里**每一处** router 的 `cdk deploy` 前有 `open`、后有 `apply`，表格里不许再写 router 部署命令 | Modify（Task 5） |
| `CLAUDE.md` | 部署命令块三步化；跨组件矩阵加一行；高频坑加一条 | Modify（Task 5） |
| `site-builder/DEPLOY.md` | 4 处 router 部署点三步化（L523 轮转 runbook B、L1163 S1 第 5 步、L1904 ② 第 2 步、L2477 M5 表格改引用）；② 加一段"stack policy 防什么"；六个硬闸门表的 `verify_deployed_edge.sh` 行补 ⑤ | Modify（Task 5） |

**为什么模块放 `router/infrastructure/` 而脚本放 `site-builder/scripts/`**：模块要被 `stack.py` 以同目录 `import stack_policy` 拿到（`cdk.json` 的 `app` 是 `python3 stack.py`，cwd 就是那个目录）；脚本则沿用"所有真机脚本都在 `site-builder/scripts/`、都用宿主 `python3`"的既有约定，`verify_deployed_edge.sh` 也在那里。脚本用 `sys.path.insert(0, ROOT/router/infrastructure)` 找模块，与 `verify_deployed_edge.sh` 找 `session_keys` 是同一做法。

**为什么不用栈内自定义资源去 SetStackPolicy**（工单允许的另一条路）：① 多一个 Lambda 与角色，**谁能 `lambda:InvokeFunction` 它谁就能解保护**（AwsCustomResource 的 handler 执行事件里描述的任意 SDK 调用），而 edge role 今天就有 `lambda:InvokeFunction` on `*`——门槛从 `SetStackPolicy` 退化成 `InvokeFunction`；② 属性不变时不会触发 Update，策略不会每次重申；③ aws-cdk-lib 2.100.0 的 AwsCustomResource 默认运行时是 Node.js 18，那个运行时 Lambda 已不再接受新建函数，要么升 CDK 要么手造 Runtime——两者都是本票之外的改动面；④ 在 `*_IN_PROGRESS` 的栈上调 `SetStackPolicy` 是否被接受没有文档保证。脚本方案没有这四条。代价是多两条命令，由文档 + docs 守卫 + ⑤ 闸门三层兜住。

---

## Task 1: `stack_policy.py`——声明、推导、策略体、比较、synth 期守卫（纯函数 + 测试）

**Files:**
- Create: `router/infrastructure/stack_policy.py`
- Create: `router/infrastructure/lambda/test_stack_policy.py`

**Interfaces（Produces，后面三个 task 都靠这些名字）：**
- `PROTECTED_CONSTRUCTS: tuple[tuple[str, str], ...]`——`(construct_id, cfn_type)` 四行
- `DENIED_ACTIONS: tuple[str, ...]`——D1 裁定值
- `ALLOW_ALL_STATEMENT: dict`、`OPEN_POLICY: dict`
- `class StackPolicyError(ValueError)`
- `logical_id_pattern(construct_id: str) -> re.Pattern[str]`
- `protected_logical_ids(template: Mapping) -> dict[str, str]`（construct_id → 逻辑 ID；缺 / 多义 / 类型不符抛 `StackPolicyError`）
- `build_policy(logical_ids: Mapping[str, str]) -> dict`
- `canonical(policy: Mapping) -> str`
- `policy_problems(actual: Mapping | None, expected: Mapping) -> list[str]`（空 = 等价）
- `assert_protected_constructs(stack) -> dict[str, str]`（duck-typed：`stack.node.try_find_child`、`child.node.default_child`、`cfn.cfn_resource_type`、`stack.get_logical_id`）

- [ ] **Step 1: 写失败测试**

`router/infrastructure/lambda/test_stack_policy.py`（本 task 不含 `stack.py` 接线那两条，Task 2 追加）：

```python
"""`stack_policy.py`（router 栈 stack policy 的声明 / 推导 / 比较）与 stack.py 的接线。

stack.py import aws_cdk（本 venv 没有），所以 synth 期守卫在这里用**假栈对象**验行为，
接线用源码 / AST 断言（与 test_stack_static.py 同一套做法）。模板 fixture 的资源清单照
`python3 stack.py` 离线 synth 出来的形态，哈希是假的。
"""
import ast
import importlib.util
import json
import re
from pathlib import Path

import pytest

INFRA = Path(__file__).parents[1]
STACK_SRC = (INFRA / "stack.py").read_text()


def _load():
    spec = importlib.util.spec_from_file_location("_stack_policy_under_test", INFRA / "stack_policy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load()
H = "AAAAAAAA"   # 假的 8 位路径哈希


def _template(**overrides):
    res = {
        f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::Table"},
        f"EdgeFunctionRole{H}": {"Type": "AWS::IAM::Role"},
        f"EdgeFunctionRoleDefaultPolicy{H}": {"Type": "AWS::IAM::Policy"},
        f"OriginRequestFunction{H}": {"Type": "AWS::Lambda::Function"},
        f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40: {"Type": "AWS::Lambda::Version"},
        f"OriginResponseFunction{H}": {"Type": "AWS::Lambda::Function"},
        f"OriginResponseFunctionCurrentVersion{H}" + "c" * 40: {"Type": "AWS::Lambda::Version"},
        f"OriginRequestPolicy{H}": {"Type": "AWS::CloudFront::OriginRequestPolicy"},
        f"Distribution{H}": {"Type": "AWS::CloudFront::Distribution"},
    }
    res.update(overrides)
    return {"Resources": {k: v for k, v in res.items() if v is not None}}


EXPECTED_IDS = {"OriginRequestFunction": f"OriginRequestFunction{H}",
                "OriginResponseFunction": f"OriginResponseFunction{H}",
                "Distribution": f"Distribution{H}",
                "SubdomainMappingTable": f"SubdomainMappingTable{H}"}


# ---- 推导 ----------------------------------------------------------------------------------

def test_protected_logical_ids_picks_exactly_the_four_l1_resources():
    assert sp.protected_logical_ids(_template()) == EXPECTED_IDS


@pytest.mark.parametrize("mutate, needle", [
    ({f"Distribution{H}": None}, "Distribution: 期望恰好 1"),
    ({f"Distribution{'B' * 8}": {"Type": "AWS::CloudFront::Distribution"}}, "Distribution: 期望恰好 1"),
    ({f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::GlobalTable"}}, "Type 是 'AWS::DynamoDB::GlobalTable'"),
    ({"OriginRequestFunction": {"Type": "AWS::Lambda::Function"}, f"OriginRequestFunction{H}": None},
     "OriginRequestFunction: 期望恰好 1"),
], ids=["missing", "ambiguous", "wrong-type", "no-hash"])
def test_missing_ambiguous_or_mistyped_protected_resource_is_named(mutate, needle):
    with pytest.raises(sp.StackPolicyError, match=re.escape(needle)):
        sp.protected_logical_ids(_template(**mutate))


def test_version_resources_never_match_the_function_pattern():
    """`…CurrentVersion<8hex><40hex>` 与 `OriginRequestFunction<8hex>` 前缀相同——不锚 `$` 就多义。"""
    pat = sp.logical_id_pattern("OriginRequestFunction")
    assert pat.match(f"OriginRequestFunction{H}")
    assert not pat.match(f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40)
    assert not pat.match(f"OriginRequestFunction{H.lower()}"), "CDK 的路径哈希是大写"


# ---- 策略体 --------------------------------------------------------------------------------

def test_build_policy_allows_everything_then_denies_only_exact_ids():
    pol = sp.build_policy(EXPECTED_IDS)
    allows = [s for s in pol["Statement"] if s["Effect"] == "Allow"]
    denies = [s for s in pol["Statement"] if s["Effect"] == "Deny"]
    assert allows == [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}], \
        "stack policy 默认全拒：缺 Allow 会冻住整栈"
    assert len(denies) == 1 and denies[0]["Principal"] == "*"
    assert denies[0]["Action"] == list(sp.DENIED_ACTIONS)
    assert sorted(denies[0]["Resource"]) == sorted(f"LogicalResourceId/{v}" for v in EXPECTED_IDS.values())
    assert not any("*" in r for r in denies[0]["Resource"])
    json.dumps(pol)


def test_build_policy_refuses_a_partial_id_map():
    with pytest.raises(sp.StackPolicyError, match="Distribution"):
        sp.build_policy({k: v for k, v in EXPECTED_IDS.items() if k != "Distribution"})


def test_denied_actions_pin_the_d1_ruling():
    """决策门 D1：`Update:*`（含 Modify）。只拒 Replace/Delete 拦不住 Edge 换码，改这里必须是刻意的。"""
    assert sp.DENIED_ACTIONS == ("Update:*",)


# ---- 比较 ----------------------------------------------------------------------------------

def test_policy_problems_positive_control_accepts_reordered_equivalents():
    exp = sp.build_policy(EXPECTED_IDS)
    same = {"Statement": [exp["Statement"][1], {**exp["Statement"][0], "Action": ["Update:*"]}]}
    assert sp.policy_problems(exp, exp) == []
    assert sp.policy_problems(same, exp) == []


_ALL = [f"LogicalResourceId/{v}" for v in EXPECTED_IDS.values()]


@pytest.mark.parametrize("actual, needle", [
    (None, "没有 stack policy"),
    (sp.OPEN_POLICY, f"覆盖 LogicalResourceId/Distribution{H}"),
    ({"Statement": [dict(sp.ALLOW_ALL_STATEMENT),
                    {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}, "通配"),
    ({"Statement": [{"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": _ALL}]}, "没有 Allow 语句"),
    ({"Statement": [dict(sp.ALLOW_ALL_STATEMENT),
                    {"Effect": "Deny", "Action": ["Update:Replace", "Update:Delete"], "Principal": "*", "Resource": _ALL}]},
     "覆盖 LogicalResourceId/OriginRequestFunction"),
], ids=["none", "open", "wildcard", "deny-only", "replace-delete-only"])
def test_policy_problems_negative_controls_name_the_defect(actual, needle):
    problems = sp.policy_problems(actual, sp.build_policy(EXPECTED_IDS))
    assert problems and any(needle in p for p in problems), problems


# ---- synth 期守卫（假栈对象；真 CDK 对象上的行为由 stack.py 每次 synth 顺带证明）------------------

class _Node:
    def __init__(self, children=None, default_child=None):
        self._children, self.default_child = children or {}, default_child

    def try_find_child(self, cid):
        return self._children.get(cid)


class _Cfn:
    def __init__(self, rtype, lid):
        self.cfn_resource_type, self.lid = rtype, lid


class _Construct:
    def __init__(self, cfn):
        self.node = _Node(default_child=cfn)


class _Stack:
    def __init__(self, table):   # cid -> (rtype, logical id)
        self.node = _Node({cid: _Construct(_Cfn(rt, lid)) for cid, (rt, lid) in table.items()})

    def get_logical_id(self, cfn):
        return cfn.lid


def _good():
    return {cid: (rt, f"{cid}{H}") for cid, rt in sp.PROTECTED_CONSTRUCTS}


def test_synth_guard_accepts_a_matching_stack_and_returns_the_ids():
    assert sp.assert_protected_constructs(_Stack(_good())) == EXPECTED_IDS


@pytest.mark.parametrize("mutate, needle", [
    (lambda t: t.pop("Distribution"), "Distribution: 栈里没有这个 construct"),
    (lambda t: t.__setitem__("SubdomainMappingTable", ("AWS::DynamoDB::GlobalTable", f"SubdomainMappingTable{H}")),
     "L1 类型是 'AWS::DynamoDB::GlobalTable'"),
    (lambda t: t.__setitem__("OriginRequestFunction", ("AWS::Lambda::Function", "OriginRequestFunction")), "不符合"),
], ids=["renamed", "wrong-type", "overridden-id"])
def test_synth_guard_fails_loudly_on_each_drift(mutate, needle):
    t = _good()
    mutate(t)
    with pytest.raises(sp.StackPolicyError, match=re.escape(needle)):
        sp.assert_protected_constructs(_Stack(t))


def test_stack_policy_module_is_stdlib_only():
    """三处调用方里两处没有 aws_cdk，宿主 python3 那处 import 期也不该需要 boto3。"""
    tree = ast.parse((INFRA / "stack_policy.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= {"json", "re", "typing", "__future__"}, names
```

- [ ] **Step 2: 跑，确认红**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure/lambda"
../../../site-builder/deployer/.venv/bin/pytest test_stack_policy.py -q
```
Expected: 收集阶段就红——`FileNotFoundError`（`stack_policy.py` 不存在），整个文件 error。

- [ ] **Step 3: 写模块**

`router/infrastructure/stack_policy.py`：

```python
"""router 栈的 CloudFormation stack policy：**声明**受保护资源、从模板**推导**它们的逻辑 ID、
生成并**比较**策略。只依赖标准库——三处调用方里有两处没有 aws_cdk：

  · `stack.py`（synth 期）：`assert_protected_constructs(self)`——声明与栈不一致就让 synth 失败；
  · `site-builder/scripts/router_stack_policy.py`（部署前后 / 闸门）：`protected_logical_ids`
    + `build_policy` + `policy_problems`，用宿主机 `python3` 跑；
  · `lambda/test_stack_policy.py`（router 套件，借 deployer 的 venv，那里没有 aws_cdk）。

## 模型

stack policy 只管 **UpdateStack / ExecuteChangeSet** 路径上的 `Update:Modify|Replace|Delete`。
设了之后**默认全拒**，所以策略里必须先有一条 `Allow Update:* on *`，再用显式 `Deny` 点名资源
（CloudFormation 按逻辑 ID 与资源类型**分别**评估，`NotResource` 那种写法拦不住——AWS 文档原话）。
越过它必须持有 `cloudformation:SetStackPolicy`；`ExecuteChangeSet` 根本不接受临时覆盖策略。
它**不管** DeleteStack（那是 termination protection 的事），也不管绕开 CloudFormation 直接调
Lambda / CloudFront API 的路——那两条由账号信任边界文档另算。

## 逻辑 ID 怎么来

不硬编码哈希。CDK 给顶层 construct 的 L1 分配的逻辑 ID = construct ID + 8 位大写十六进制路径哈希
（`OriginRequestFunction/Resource` → `OriginRequestFunction` + 8 hex）；`Version` 子资源是
`…CurrentVersion` + 8 hex + 40 hex，被 `[0-9A-F]{8}$` 的锚排除。`protected_logical_ids` 按
"construct ID 前缀 + 8 hex + Type 相符 + 恰好命中一个"从**已部署模板**里取；
`assert_protected_constructs` 在 synth 期拿 CDK 自己算出的 ID 核对同一条正则。两边任何一边变了
都是响亮失败，而不是 `apply` 静默保护错对象。刻意不读 `Metadata.aws:cdk:path`：直接
`python3 stack.py` 时模板里没有它（那是 CDK CLI 加的上下文）。
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

# (construct ID, 期望的 CloudFormation 资源类型)。改这张表 = 改 stack.py 的 construct ID，
# 而**改 construct ID 就是替换资源**（逻辑 ID 变）——对分发与路由表那是事故，不是重构。
PROTECTED_CONSTRUCTS: tuple[tuple[str, str], ...] = (
    ("OriginRequestFunction", "AWS::Lambda::Function"),
    ("OriginResponseFunction", "AWS::Lambda::Function"),
    ("Distribution", "AWS::CloudFront::Distribution"),
    ("SubdomainMappingTable", "AWS::DynamoDB::Table"),
)

# 决策门 D1。`Update:*` 含 Modify：Edge 换码是 Lambda `Code` 的 Modify，只拒 Replace/Delete
# 拦不住"经 UpdateStack 替换验签代码"这条路。代价是每次 router 部署都要 open → deploy → apply。
DENIED_ACTIONS: tuple[str, ...] = ("Update:*",)

ALLOW_ALL_STATEMENT = {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}
# `open` 用的临时策略：等于没有保护。stack policy 一旦设上就删不掉，只能换成这个。
OPEN_POLICY: dict[str, Any] = {"Statement": [dict(ALLOW_ALL_STATEMENT)]}


class StackPolicyError(ValueError):
    """声明与模板/栈不一致。调用方应当让 synth / apply / check 失败，而不是继续。"""


def logical_id_pattern(construct_id: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(construct_id)}[0-9A-F]{{8}}$")


def protected_logical_ids(template: Mapping[str, Any]) -> dict[str, str]:
    """construct ID → 模板里的逻辑 ID。任何一项缺失 / 多义 / 类型不符都抛，并点名是哪一项。"""
    resources = template.get("Resources") or {}
    out: dict[str, str] = {}
    problems: list[str] = []
    for cid, rtype in PROTECTED_CONSTRUCTS:
        pat = logical_id_pattern(cid)
        hits = sorted(lid for lid in resources if pat.match(lid))
        if len(hits) != 1:
            problems.append(f"{cid}: 期望恰好 1 个逻辑 ID 匹配 {pat.pattern}，实得 {hits}")
            continue
        got = resources[hits[0]].get("Type")
        if got != rtype:
            problems.append(f"{cid}: {hits[0]} 的 Type 是 {got!r}，期望 {rtype!r}")
            continue
        out[cid] = hits[0]
    if problems:
        raise StackPolicyError("模板里推不出全部受保护资源：\n  " + "\n  ".join(problems))
    return out


def build_policy(logical_ids: Mapping[str, str]) -> dict[str, Any]:
    """先 Allow 全部，再 Deny 点名的精确逻辑 ID。缺了 Allow 整栈会被冻住（stack policy 默认拒）。"""
    missing = [cid for cid, _ in PROTECTED_CONSTRUCTS if cid not in logical_ids]
    if missing:
        raise StackPolicyError(f"build_policy 缺少逻辑 ID：{missing}")
    return {"Statement": [
        dict(ALLOW_ALL_STATEMENT),
        {"Effect": "Deny", "Action": list(DENIED_ACTIONS), "Principal": "*",
         "Resource": [f"LogicalResourceId/{logical_ids[cid]}" for cid, _ in PROTECTED_CONSTRUCTS]},
    ]}


def _as_list(v: Any) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def canonical(policy: Mapping[str, Any]) -> str:
    """语句顺序、Action/Resource 的 str-vs-list 形态都不算差异。"""
    stmts = []
    for s in policy.get("Statement", []):
        d = dict(s)
        for k in ("Action", "NotAction", "Resource", "NotResource"):
            if k in d:
                d[k] = sorted(_as_list(d[k]))
        stmts.append(json.dumps(d, sort_keys=True))
    return json.dumps(sorted(stmts))


def policy_problems(actual: Mapping[str, Any] | None, expected: Mapping[str, Any]) -> list[str]:
    """空列表 = 线上策略与期望**等价**。否则逐条说清差在哪（缺谁的 Deny、用了通配、被 open 着）。"""
    if actual is None:
        return ["栈没有 stack policy"]
    if canonical(actual) == canonical(expected):
        return []
    problems: list[str] = []
    want = {r for s in expected["Statement"] if s["Effect"] == "Deny" for r in _as_list(s["Resource"])}
    covered: set[str] = set()
    for s in actual.get("Statement", []):
        if s.get("Effect") != "Deny":
            continue
        acts = set(_as_list(s.get("Action")))
        if "Update:*" in acts or set(DENIED_ACTIONS) <= acts:
            covered |= set(_as_list(s.get("Resource")))
    for r in sorted(want - covered):
        problems.append(f"没有 Deny 语句以 {list(DENIED_ACTIONS)} 覆盖 {r}")
    if "*" in covered or any(r.endswith("*") for r in covered):
        problems.append("Deny 语句的 Resource 含通配——策略要求精确逻辑 ID")
    if not any(s.get("Effect") == "Allow" for s in actual.get("Statement", [])):
        problems.append("没有 Allow 语句——这份策略会冻住整栈的所有更新")
    if not problems:
        problems.append("策略与期望不等价（多出的语句、Condition，或不同的动作集合）")
    return problems


def assert_protected_constructs(stack) -> dict[str, str]:
    """synth 期守卫（duck-typed，不 import aws_cdk）：四个 construct 都在、L1 类型对、
    CDK 分到的逻辑 ID 符合 `protected_logical_ids` 用的同一条正则。返回 construct ID → 逻辑 ID。"""
    out: dict[str, str] = {}
    problems: list[str] = []
    for cid, rtype in PROTECTED_CONSTRUCTS:
        child = stack.node.try_find_child(cid)
        cfn = child.node.default_child if child is not None else None
        if cfn is None:
            problems.append(f"{cid}: 栈里没有这个 construct（改名了？同步 PROTECTED_CONSTRUCTS）")
            continue
        got = getattr(cfn, "cfn_resource_type", None)
        if got != rtype:
            problems.append(f"{cid}: L1 类型是 {got!r}，期望 {rtype!r}")
            continue
        lid = stack.get_logical_id(cfn)
        if not logical_id_pattern(cid).match(lid):
            problems.append(f"{cid}: CDK 分到的逻辑 ID {lid!r} 不符合 {logical_id_pattern(cid).pattern}"
                            "——router_stack_policy.py 推不出它")
            continue
        out[cid] = lid
    if problems:
        raise StackPolicyError("stack policy 的受保护资源声明与栈不一致：\n  " + "\n  ".join(problems))
    return out
```

- [ ] **Step 4: 跑，确认绿；整个 router 套件也要绿**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure/lambda"
../../../site-builder/deployer/.venv/bin/pytest test_stack_policy.py -q
../../../site-builder/deployer/.venv/bin/pytest . -q
```
Expected: 第一条 **20 passed**；第二条比 Task 开始前多 20（临时目录实测：314 → 334，另 4 skipped 不变）。

---

## Task 2: `stack.py` 接上 synth 期守卫 + 真 CDK 对象上的正 / 反对照

**Files:**
- Modify: `router/infrastructure/stack.py`（第 28 行附近的 import 区；`__init__` 末尾 `# Outputs` 之前）
- Modify: `router/infrastructure/lambda/test_stack_policy.py`（追加两条接线守卫）

**Interfaces：**
- Consumes：`stack_policy.assert_protected_constructs`

- [ ] **Step 1: 追加两条接线守卫（红）**

追加到 `test_stack_policy.py` 末尾：

```python
# ---- stack.py 的接线（源码 / AST）--------------------------------------------------------------

def test_stack_imports_and_calls_the_synth_guard_after_the_distribution_exists():
    assert "from stack_policy import assert_protected_constructs" in STACK_SRC
    body = STACK_SRC[STACK_SRC.index("class WebRouterStack"):]
    call = body.index("assert_protected_constructs(self)")
    assert body.index('"Distribution",') < call, "守卫跑在分发创建之前 = 永远报缺"
    assert call < body.index("# Outputs"), "守卫放在写 Outputs 之前（Outputs 不是资源，晚了没意义）"


def test_every_protected_construct_id_is_a_constructor_id_in_stack_py():
    """PROTECTED_CONSTRUCTS 里的 construct ID 必须与 stack.py 构造时传的第二个位置参数逐字相同。"""
    tree = ast.parse(STACK_SRC)
    ids = {n.args[1].value for n in ast.walk(tree)
           if isinstance(n, ast.Call) and len(n.args) >= 2
           and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)}
    missing = [cid for cid, _ in sp.PROTECTED_CONSTRUCTS if cid not in ids]
    assert not missing, f"stack.py 里没有这些 construct ID：{missing}（AST 找到的：{sorted(ids)}）"
```

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure/lambda"
../../../site-builder/deployer/.venv/bin/pytest test_stack_policy.py -q
```
Expected: **1 failed, 21 passed**——第一条红（`ValueError: substring not found`，还没 import）；第二条在改之前就绿是正常的：它守的是**将来**有人改 construct ID 而不改声明。

- [ ] **Step 2: 改 `stack.py`**

import 区（第 28 行 `from constructs import Construct` 之后）加：

```python
from constructs import Construct

from stack_policy import assert_protected_constructs
```

`WebRouterStack.__init__` 里，`# Outputs` 之前（第 504 行附近）加：

```python
        # stack policy 的声明必须与栈一致（construct ID / L1 类型 / 逻辑 ID 形态），
        # 否则 synth 失败——不让 router_stack_policy.py 在 20 分钟的 Edge 部署之后才发现推不出 ID。
        assert_protected_constructs(self)

        # Outputs
```

不改任何 construct ID，不加 `override_logical_id`。

- [ ] **Step 3: 跑，确认绿；`test_stack_static.py` 那些既有源码守卫也必须仍绿**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure/lambda"
../../../site-builder/deployer/.venv/bin/pytest . -q
```
Expected: 比 Task 1 结束时多 2（临时目录实测 **336 passed, 4 skipped**）。

- [ ] **Step 4: 真 aws-cdk-lib 对象上的正对照——离线 synth（不碰 AWS，不需要 Docker）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure"
OUT="$(mktemp -d)"
APP_SYNTH_OFFLINE=1 APP_JWT_SECRET=offline-x \
APP_SITE_ALLOWLIST_JSON='{"site-hs-v2":{"alg":"HS256","secret":"o","role":"current"}}' \
CDK_OUTDIR="$OUT" .venv/bin/python3 stack.py
python3 - "$OUT" <<'PY'
import glob, json, sys
sys.path.insert(0, ".")          # cwd 是 router/infrastructure，stack_policy.py 就在这里
from stack_policy import protected_logical_ids, build_policy
t = json.load(open(glob.glob(sys.argv[1] + "/*.template.json")[0]))
ids = protected_logical_ids(t)
assert set(ids) == {"OriginRequestFunction", "OriginResponseFunction", "Distribution", "SubdomainMappingTable"}, ids
print("推导到的逻辑 ID：", ids)
print(json.dumps(build_policy(ids), ensure_ascii=False, indent=1))
PY
rm -rf "$OUT"
```
Expected: synth 成功（无 `StackPolicyError`）；打印四个形如 `<construct ID><8 hex>` 的逻辑 ID 与一份两条语句的策略。**不要把打印出来的哈希抄进任何 tracked 文件**（它们由推导得出）。
说明：三个 `APP_*` 是 `stack.py` 既有的离线开关，synth 出来的模板带 SYNTH 标记、不可部署；这里只看资源清单。`CDK_OUTDIR` 指到临时目录，避免污染 `cdk.out`。

- [ ] **Step 5: 反对照——在临时副本里把 `Distribution` 改名，synth 必须失败**

不动仓库里的 `stack.py`；在临时目录复刻布局（`stack.py` 用 `parents[2]` 找仓库根下的 `site-builder/auth`，所以要软链 `site-builder`、复制 `router/config.ini`）：

```bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
NEG="$(mktemp -d)"; mkdir -p "$NEG/router"
cp -R "$ROOT/router/infrastructure" "$NEG/router/infrastructure"
cp "$ROOT/router/config.ini" "$NEG/router/config.ini"
ln -s "$ROOT/site-builder" "$NEG/site-builder"
sed -i '' 's/"Distribution",$/"DistributionV2",/' "$NEG/router/infrastructure/stack.py"
grep -n '"DistributionV2"' "$NEG/router/infrastructure/stack.py"
set +e
(cd "$NEG/router/infrastructure" && APP_SYNTH_OFFLINE=1 APP_JWT_SECRET=x \
   APP_SITE_ALLOWLIST_JSON='{"k":{"alg":"HS256","secret":"o","role":"current"}}' \
   CDK_OUTDIR="$(mktemp -d)" "$ROOT/router/infrastructure/.venv/bin/python3" stack.py 2>&1 | tail -3)
echo "（上面必须是 StackPolicyError，且点名 Distribution）"
set -e
rm -rf "$NEG"
```
Expected: 最后三行含 `stack_policy.StackPolicyError: stack policy 的受保护资源声明与栈不一致：` 与 `Distribution: 栈里没有这个 construct`。

---

## Task 3: `router_stack_policy.py`——`open` / `apply` / `check` + 假 client 测试

**Files:**
- Create: `site-builder/scripts/router_stack_policy.py`
- Create: `site-builder/deployer/tests/test_router_stack_policy.py`

**Interfaces：**
- Consumes：`stack_policy.{OPEN_POLICY, StackPolicyError, build_policy, canonical, policy_problems, protected_logical_ids}`
- Produces：`main(argv: list[str] | None = None, cfn=None) -> int`（`cfn` 可注入，测试用）；`COMMANDS = {"open", "apply", "check"}`；`load_stack_target(cfg_path) -> (stack_name, region)`；模块级 `ROUTER_CFG`。`--config PATH` 只给测试用。

- [ ] **Step 1: 写失败测试**

`site-builder/deployer/tests/test_router_stack_policy.py`：

```python
"""`scripts/router_stack_policy.py`（open / apply / check）对着假 CloudFormation client 的行为。

纯逻辑（逻辑 ID 推导、策略体、比较）在 router 套件的 `lambda/test_stack_policy.py`；这里只管 CLI 的
副作用契约：什么时候写、什么时候拒绝、读回不一致算失败、check 一个写调用都不许发。
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "site-builder" / "scripts" / "router_stack_policy.py"
H = "AAAAAAAA"
TEMPLATE = {"Resources": {
    f"SubdomainMappingTable{H}": {"Type": "AWS::DynamoDB::Table"},
    f"OriginRequestFunction{H}": {"Type": "AWS::Lambda::Function"},
    f"OriginRequestFunctionCurrentVersion{H}" + "b" * 40: {"Type": "AWS::Lambda::Version"},
    f"OriginResponseFunction{H}": {"Type": "AWS::Lambda::Function"},
    f"Distribution{H}": {"Type": "AWS::CloudFront::Distribution"},
}}


def _load():
    spec = importlib.util.spec_from_file_location("_router_stack_policy", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_router_stack_policy"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def cli():
    return _load()


class _ClientError(Exception):
    def __init__(self, code, msg):
        super().__init__(f"{code}: {msg}")
        self.response = {"Error": {"Code": code, "Message": msg}}


class _FakeCfn:
    """只实现脚本会碰的四个调用；`writes` 记下每一次写。"""

    def __init__(self, *, exists=True, status="UPDATE_COMPLETE", template=TEMPLATE, policy=None,
                 corrupt_writes=False):
        self.exists, self.status, self.template, self.policy = exists, status, template, policy
        self.corrupt_writes = corrupt_writes
        self.reads, self.writes = [], []

    def describe_stacks(self, StackName):
        self.reads.append("describe_stacks")
        if not self.exists:
            raise _ClientError("ValidationError", f"Stack with id {StackName} does not exist")
        return {"Stacks": [{"StackStatus": self.status}]}

    def get_template(self, StackName, TemplateStage):
        self.reads.append("get_template")
        return {"TemplateBody": self.template}

    def get_stack_policy(self, StackName):
        self.reads.append("get_stack_policy")
        return {"StackPolicyBody": json.dumps(self.policy)} if self.policy is not None else {}

    def set_stack_policy(self, StackName, StackPolicyBody):
        self.writes.append(json.loads(StackPolicyBody))
        self.policy = {"Statement": []} if self.corrupt_writes else json.loads(StackPolicyBody)


@pytest.fixture()
def cfg(tmp_path):
    p = tmp_path / "config.ini"
    p.write_text("[AWS]\naccount_id = 000000000000\nregion = us-east-1\n"
                 "[CDK]\nstack_name = ApplicationWebRouterStack\n")
    return p


def _expected(cli):
    return cli.build_policy(cli.protected_logical_ids(TEMPLATE))


def test_import_has_no_side_effects(cli):
    assert callable(cli.main) and set(cli.COMMANDS) == {"open", "apply", "check"}


def test_apply_sets_the_derived_policy_and_reads_it_back(cli, cfg, capsys):
    fake = _FakeCfn()
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake) == 0
    assert fake.writes == [_expected(cli)]
    out = capsys.readouterr().out
    assert "PASS" in out and f"LogicalResourceId/Distribution{H}" in out


def test_apply_reasserts_even_when_already_correct(cli, cfg):
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake) == 0
    assert len(fake.writes) == 1, "重申是刻意的：有人手工 open 过而没人知道时，下一次部署把它关回去"


@pytest.mark.parametrize("status", ["UPDATE_IN_PROGRESS", "CREATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS"])
@pytest.mark.parametrize("verb", ["apply", "open"])
def test_apply_and_open_refuse_while_the_stack_is_in_progress(cli, cfg, status, verb):
    fake = _FakeCfn(status=status)
    assert cli.main([verb, "--config", str(cfg)], cfn=fake) == 1
    assert fake.writes == []


def test_apply_fails_when_the_readback_does_not_match(cli, cfg, capsys):
    fake = _FakeCfn(corrupt_writes=True)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake) == 1
    assert "读回" in capsys.readouterr().err


def test_apply_fails_when_the_stack_does_not_exist(cli, cfg):
    fake = _FakeCfn(exists=False)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake) == 1
    assert fake.writes == []


def test_apply_fails_when_a_protected_resource_cannot_be_derived(cli, cfg, capsys):
    tpl = {"Resources": {k: v for k, v in TEMPLATE["Resources"].items() if not k.startswith("Distribution")}}
    fake = _FakeCfn(template=tpl)
    assert cli.main(["apply", "--config", str(cfg)], cfn=fake) == 1
    assert fake.writes == [], "推不出 ID 时绝不能写一份缺项的策略"
    assert "Distribution" in capsys.readouterr().err


def test_open_skips_on_a_missing_stack_and_writes_allow_all_otherwise(cli, cfg, capsys):
    fake = _FakeCfn(exists=False)
    assert cli.main(["open", "--config", str(cfg)], cfn=fake) == 0
    assert fake.writes == [] and "SKIP" in capsys.readouterr().out
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["open", "--config", str(cfg)], cfn=fake) == 0
    assert fake.writes == [cli.OPEN_POLICY]
    assert "apply" in capsys.readouterr().out, "open 的输出必须提醒 apply"


def test_check_is_read_only_and_passes_on_the_expected_policy(cli, cfg):
    fake = _FakeCfn(policy=_expected(cli))
    assert cli.main(["check", "--config", str(cfg)], cfn=fake) == 0
    assert fake.writes == []
    assert set(fake.reads) == {"describe_stacks", "get_template", "get_stack_policy"}


@pytest.mark.parametrize("kind", ["none", "open", "partial", "wildcard"])
def test_check_fails_on_every_defective_policy_and_stays_read_only(cli, cfg, kind, capsys):
    exp = _expected(cli)
    deny = exp["Statement"][1]
    bad = {"none": None, "open": cli.OPEN_POLICY,
           "partial": {"Statement": [exp["Statement"][0], {**deny, "Resource": deny["Resource"][1:]}]},
           "wildcard": {"Statement": [exp["Statement"][0], {**deny, "Resource": "*"}]}}[kind]
    fake = _FakeCfn(policy=bad)
    assert cli.main(["check", "--config", str(cfg)], cfn=fake) == 1
    assert fake.writes == []
    assert "apply" in capsys.readouterr().err, "check 红了要告诉操作者怎么修"


def test_template_body_may_arrive_as_a_json_string(cli, cfg):
    fake = _FakeCfn(template=json.dumps(TEMPLATE), policy=_expected(cli))
    assert cli.main(["check", "--config", str(cfg)], cfn=fake) == 0


def test_unreadable_config_is_a_hard_failure_not_an_empty_stack_name(cli, tmp_path):
    with pytest.raises(SystemExit, match="读不到"):
        cli.main(["check", "--config", str(tmp_path / "missing.ini")], cfn=_FakeCfn())
    half = tmp_path / "half.ini"
    half.write_text("[AWS]\nregion = us-east-1\n")
    with pytest.raises(SystemExit, match="CDK"):
        cli.main(["check", "--config", str(half)], cfn=_FakeCfn())


def test_other_describe_errors_are_not_mistaken_for_a_missing_stack(cli, cfg):
    class _Denied(_FakeCfn):
        def describe_stacks(self, StackName):
            raise _ClientError("AccessDenied", "not authorized")

    with pytest.raises(_ClientError):
        cli.main(["open", "--config", str(cfg)], cfn=_Denied())
```

- [ ] **Step 2: 跑，确认红**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_router_stack_policy.py -q
```
Expected: 每条都 error（`FileNotFoundError`，脚本不存在）。

- [ ] **Step 3: 写脚本**

`site-builder/scripts/router_stack_policy.py`：

```python
#!/usr/bin/env python3
"""router 栈的 CloudFormation stack policy：`open` → `cdk deploy` → `apply`，闸门用 `check`。

为什么是脚本而不是 CDK 里的资源：CloudFormation 模板没有 stack policy 这个概念，`cdk deploy`
也没有传它的旗标；栈内用自定义资源去 SetStackPolicy 要多一个 Lambda 与角色（谁能 Invoke 它谁就能
解保护），而且属性不变时不会在每次部署重申。所以策略由本脚本在部署**之后**按已部署模板推导并写上，
每次部署都重申一遍；`verify_deployed_edge.sh` ⑤ 用 `check` 核对。

三个子命令（精确逻辑 ID 与策略体的推导都在 `router/infrastructure/stack_policy.py`）：

  open    部署前：把策略换成 Allow-all（stack policy 设上就删不掉，只能换）。栈不存在（首次部署）
          打印 SKIP 并退 0；栈 *_IN_PROGRESS 拒绝并退 1。**open 之后不管 deploy 成败都要 apply。**
  apply   部署后：GetTemplate → 推导四个逻辑 ID → SetStackPolicy → GetStackPolicy 读回比对。
          读回与期望不等价即退 1（写了但没生效不算成功）。栈不存在 / *_IN_PROGRESS 退 1。
  check   只读闸门：DescribeStacks + GetTemplate + GetStackPolicy，策略缺失、被 open 着、未覆盖
          任一受保护资源、或 Deny 里带通配都退 1。**不发任何写调用。**

策略防什么：持有 `cloudformation:UpdateStack` 或 `CreateChangeSet`+`ExecuteChangeSet` **但没有**
`cloudformation:SetStackPolicy` 的 principal 改不了 Edge 两函数、分发与路由表（含 Modify——Edge 换码
就是 Lambda `Code` 的 Modify）。不防什么：持有 SetStackPolicy 的人（等于能 open）、DeleteStack
（termination protection 另配）、绕开 CloudFormation 直接调 Lambda / CloudFront API 的那条路。

忘了 open 的症状：`cdk deploy` 在 ExecuteChangeSet 阶段失败，栈事件里该资源 UPDATE_FAILED、原因含
"stack policy"，整栈回滚——**Edge 不受影响**，open 后重跑即可。
忘了 apply 的症状：没有任何部署输出会提示，只有 `verify_deployed_edge.sh` ⑤ 会红。

用法（仓库根，宿主机 `python3` ≥ 3.10 + boto3，与其它 scripts/*.py 相同）：
    python3 site-builder/scripts/router_stack_policy.py open
    (cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
    python3 site-builder/scripts/router_stack_policy.py apply
    python3 site-builder/scripts/router_stack_policy.py check     # 闸门；verify_deployed_edge.sh ⑤ 调它

需要的权限（操作者自己的凭据，不走 CDK bootstrap 的角色——那些角色没有 SetStackPolicy）：
cloudformation:DescribeStacks / GetTemplate / GetStackPolicy（check），外加 SetStackPolicy（open / apply）。
"""
from __future__ import annotations

import argparse
import configparser
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "router" / "infrastructure"))
from stack_policy import (  # noqa: E402
    OPEN_POLICY, StackPolicyError, build_policy, canonical, policy_problems, protected_logical_ids,
)

ROUTER_CFG = ROOT / "router" / "config.ini"


def load_stack_target(cfg_path: Path = ROUTER_CFG) -> tuple[str, str]:
    """(stack_name, region)，都来自 router/config.ini——键缺失必须硬失败、不回落字面量
    （与 verify_deployed_edge.sh 的 read_cfg 同一条纪律）。"""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(cfg_path)
    if not cfg.sections():
        raise SystemExit(f"读不到 {cfg_path} 的任何段——config.ini 没从 .example 复制？")
    try:
        return (cfg["CDK"]["stack_name"].split("#")[0].split(";")[0].strip(),
                cfg["AWS"]["region"].split("#")[0].split(";")[0].strip())
    except KeyError as exc:
        raise SystemExit(f"{cfg_path} 缺少 {exc}（需要 [CDK] stack_name 与 [AWS] region）") from exc


def _is_missing_stack(exc: Exception) -> bool:
    err = getattr(exc, "response", {}).get("Error", {})
    return err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", "")


def stack_status(cfn, stack: str) -> str | None:
    """栈状态；不存在返回 None。其它异常（凭据、限流）照抛——那不是"没有栈"。"""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except Exception as exc:  # noqa: BLE001
        if _is_missing_stack(exc):
            return None
        raise


def current_policy(cfn, stack: str) -> dict | None:
    body = cfn.get_stack_policy(StackName=stack).get("StackPolicyBody")
    return json.loads(body) if body else None


def expected_policy(cfn, stack: str) -> tuple[dict, dict[str, str]]:
    """按**已部署**的模板推导（不读本地 cdk.out：那可能陈旧，也可能刚被 rm -rf）。
    boto3 对 JSON 模板返回 dict、对 YAML 返回 str，两种都接。"""
    body = cfn.get_template(StackName=stack, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else body
    ids = protected_logical_ids(template)
    return build_policy(ids), ids


def _refuse_in_progress(status: str | None, verb: str) -> int:
    if status is not None and status.endswith("_IN_PROGRESS"):
        print(f"FAIL  栈处于 {status}，{verb} 要等它结束（并发部署？）", file=sys.stderr)
        return 1
    return 0


def _print_ids(ids: dict[str, str]) -> None:
    for cid, lid in ids.items():
        print(f"      {cid:24s} LogicalResourceId/{lid}")


def cmd_open(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"SKIP  栈 {stack} 不存在（首次部署）——没有策略可 open；cdk deploy 之后跑 apply")
        return 0
    if _refuse_in_progress(status, "open"):
        return 1
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=json.dumps(OPEN_POLICY))
    got = current_policy(cfn, stack)
    if got is None or canonical(got) != canonical(OPEN_POLICY):
        print("FAIL  open 写入后读回的策略不是 Allow-all", file=sys.stderr)
        return 1
    print(f"PASS  栈 {stack} 的 stack policy 已换成 Allow-all。**部署完成后（无论成败）必须 apply**；"
          "verify_deployed_edge.sh ⑤ 会核对")
    return 0


def cmd_apply(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"FAIL  栈 {stack} 不存在——apply 只在 cdk deploy 之后跑", file=sys.stderr)
        return 1
    if _refuse_in_progress(status, "apply"):
        return 1
    expected, ids = expected_policy(cfn, stack)
    before = current_policy(cfn, stack)
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=json.dumps(expected))
    problems = policy_problems(current_policy(cfn, stack), expected)
    if problems:
        for p in problems:
            print(f"FAIL  写入后读回仍不等价：{p}", file=sys.stderr)
        return 1
    changed = before is None or canonical(before) != canonical(expected)
    print(f"PASS  栈 {stack} 的 stack policy {'已更新' if changed else '未变化（重申）'}；受保护资源：")
    _print_ids(ids)
    return 0


def cmd_check(cfn, stack: str) -> int:
    status = stack_status(cfn, stack)
    if status is None:
        print(f"FAIL  栈 {stack} 不存在", file=sys.stderr)
        return 1
    expected, ids = expected_policy(cfn, stack)
    problems = policy_problems(current_policy(cfn, stack), expected)
    if problems:
        for p in problems:
            print(f"FAIL  {p}", file=sys.stderr)
        print("      修复：python3 site-builder/scripts/router_stack_policy.py apply", file=sys.stderr)
        return 1
    print(f"PASS  栈 {stack} 的 stack policy 覆盖全部受保护资源（Deny {expected['Statement'][1]['Action']}）：")
    _print_ids(ids)
    return 0


COMMANDS = {"open": cmd_open, "apply": cmd_apply, "check": cmd_check}


def main(argv: list[str] | None = None, cfn=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=sorted(COMMANDS))
    ap.add_argument("--config", type=Path, default=ROUTER_CFG, help="router/config.ini 的路径（测试用）")
    args = ap.parse_args(argv)
    stack, region = load_stack_target(args.config)
    if cfn is None:
        import boto3
        cfn = boto3.client("cloudformation", region_name=region)
    try:
        return COMMANDS[args.command](cfn, stack)
    except StackPolicyError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

`chmod +x site-builder/scripts/router_stack_policy.py`（与同目录其它脚本一致）。

- [ ] **Step 4: 跑，确认绿；宿主 `python3` 能加载**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/deployer && .venv/bin/pytest tests/test_router_stack_policy.py -q)
python3 site-builder/scripts/router_stack_policy.py --help | head -3
```
Expected: **21 passed**；`--help` 打出 `usage: router_stack_policy.py [-h] [--config CONFIG] {apply,check,open}`。**不要在这里跑 `check`**——worker 不碰 AWS，那是 Task 6。

---

## Task 4: `verify_deployed_edge.sh` 新增 ⑤ + 接线守卫

**Files:**
- Modify: `site-builder/scripts/verify_deployed_edge.sh`（第 269 行 `fi` 之后、第 271 行 `echo` 之前）
- Modify: `site-builder/deployer/tests/test_router_stack_policy.py`（追加一条）

- [ ] **Step 1: 追加守卫（红）**

```python
def test_the_edge_gate_runs_check_before_its_verdict():
    """⑤ 必须在总判定之前、且红了要走 fail()（计入 FAILURES）——只 echo 的红进不了退出码。"""
    gate = (ROOT / "site-builder" / "scripts" / "verify_deployed_edge.sh").read_text(encoding="utf-8")
    call = gate.index('router_stack_policy.py" check')
    assert call < gate.index('if [ "$FAILURES" -gt 0 ]'), "⑤ 放在总判定之后 = 它的红进不了退出码"
    assert 'fail "router 栈的 stack policy' in gate, "check 红了必须走 fail()，不能只 echo"
```

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_router_stack_policy.py::test_the_edge_gate_runs_check_before_its_verdict -q
```
Expected: FAIL（`ValueError: substring not found`）。

- [ ] **Step 2: 改闸门脚本**

在第 269 行（M06 那段的 `fi`）之后、第 271 行的空 `echo` 之前插入：

```bash

# ---- asset-v1 / §9 3f：router 栈的 stack policy ----
# 四个受保护资源（Edge 两函数、分发、路由表）的**精确逻辑 ID** 必须在一条 Deny 里，且策略里
# 有 Allow-all（否则整栈冻住）。判定与推导都在 router_stack_policy.py（只读子命令 check），
# 这里只把它的退出码计入 FAILURES。红的三种形态：没策略 / 被 open 着（部署后没 apply）/ 缺资源或带通配。
echo "── ⑤ stack policy：Deny 精确覆盖 Edge 两函数、分发、路由表 ─"
if python3 "$HERE/router_stack_policy.py" check; then
  echo "PASS  router 栈的 stack policy 覆盖全部受保护资源"
else
  fail "router 栈的 stack policy 缺失、被 open 着（部署后没 apply）或未覆盖全部受保护资源 —— 修复：python3 site-builder/scripts/router_stack_policy.py apply"
fi
```

`set -u` 下 `$HERE` 已在第 23 行定义；`if cmd; then` 形态在 `set -e` 下允许非 0。

- [ ] **Step 3: 语法与守卫**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
bash -n site-builder/scripts/verify_deployed_edge.sh
(cd site-builder/deployer && .venv/bin/pytest tests/test_router_stack_policy.py -q)
```
Expected: `bash -n` 无输出；**22 passed**。不在本机真跑闸门（要 AWS）。

---

## Task 5: 文档三步化 + docs 守卫

**Files:**
- Modify: `site-builder/deployer/tests/test_delivery_docs_current.py`（文件末尾追加）
- Modify: `CLAUDE.md`（第 183–184 行部署命令；第 305 行矩阵之后；「高频坑」列表末尾、第 349 行 `## 文档地图` 之前）
- Modify: `site-builder/DEPLOY.md`（L521–523、L1117、L1162–1163、L1229、L1904 附近、L2477）

- [ ] **Step 1: 先加 docs 守卫（红）**

追加到 `test_delivery_docs_current.py` 末尾：

```python
# --------------------------------------------------------------------------
# asset-v1 ticket 02：router 栈的 stack policy——每个 router 部署点都要 open → deploy → apply
# --------------------------------------------------------------------------
_CDK_DEPLOY_RE = re.compile(r"aws-cdk@latest deploy")
_ROUTER_CWD_RE = re.compile(r"cd router/infrastructure\b")
_DEPLOYER_CWD_RE = re.compile(r"cd site-builder/deployer/infra\b")


def _fenced_blocks(text: str):
    """(开围栏的行号, 围栏内的行列表)。"""
    lines, inside, start, buf = text.splitlines(), False, 0, []
    for no, ln in enumerate(lines, 1):
        if ln.lstrip().startswith("```"):
            if inside:
                yield start, buf
            inside, start, buf = not inside, no, []
        elif inside:
            buf.append(ln)


def _router_deploy_sites(block: list) -> list:
    """围栏块里哪些行是 **router** 的 `cdk deploy`：同一行或之前最近一次 `cd` 指向 router/infrastructure。
    `(cd … )` 子 shell 闭合后 cwd 归零（一行式当场闭合；带 `\\` 续行的等到以 `)` 结尾的那行）。"""
    sites, cwd, subshell = [], None, False
    for i, ln in enumerate(block):
        s = ln.strip()
        if _ROUTER_CWD_RE.search(ln):
            cwd = "router"
        elif _DEPLOYER_CWD_RE.search(ln):
            cwd = "deployer"
        if _CDK_DEPLOY_RE.search(ln) and cwd == "router":
            sites.append(i)
        if "(cd " in ln and s.endswith(")"):
            cwd = None
        elif "(cd " in ln:
            subshell = True
        elif subshell and s.endswith(")"):
            subshell, cwd = False, None
    return sites


def test_every_router_deploy_site_is_wrapped_by_stack_policy_open_and_apply():
    """stack policy 拒 `Update:*` ⇒ 不先 open 的 router 部署会在 ExecuteChangeSet 阶段失败回滚；
    部署后不 apply 则保护一直开着、只有 verify_deployed_edge.sh ⑤ 会点出来。所以文档里**每一处**
    router 的 `cdk deploy` 都必须在同一个围栏块里前有 open、后有 apply；表格单元格里不许再写
    router 的部署命令（那里放不下三步，改成引用 ② 那一节）。"""
    seen = 0
    for doc in (CLAUDE_MD, DEPLOY):
        text = _read(doc)
        for start, block in _fenced_blocks(text):
            for i in _router_deploy_sites(block):
                seen += 1
                before, after = "\n".join(block[:i]), "\n".join(block[i + 1:])
                assert "router_stack_policy.py open" in before, \
                    f"{doc.name} L{start + 1 + i}：router 的 cdk deploy 之前没有 open"
                assert "router_stack_policy.py apply" in after, \
                    f"{doc.name} L{start + 1 + i}：router 的 cdk deploy 之后没有 apply"
        fenced = {no for start, block in _fenced_blocks(text) for no in range(start, start + len(block) + 2)}
        for no, ln in enumerate(text.splitlines(), 1):
            if no not in fenced and _ROUTER_CWD_RE.search(ln) and _CDK_DEPLOY_RE.search(ln):
                raise AssertionError(f"{doc.name} L{no}：围栏外（表格）写了 router 的部署命令——改成引用 ② 节")
    assert seen >= 4, f"只找到 {seen} 处 router 部署点——判据失效？CLAUDE.md 1 处 + DEPLOY.md 至少 3 处"
```

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_delivery_docs_current.py::test_every_router_deploy_site_is_wrapped_by_stack_policy_open_and_apply -q
```
Expected: FAIL，报文是 `CLAUDE.md L184：router 的 cdk deploy 之前没有 open`（判据在当前文档上实测点出 CLAUDE.md 184 与 DEPLOY.md 523 / 1163 / 1904 四处围栏内部署点，外加 2477 表格一处；断言按顺序遇到第一处就停）。

- [ ] **Step 2: 改 `CLAUDE.md`**

（a）「部署/重部署命令」块，第 183–184 行：

```bash
# 路由层（改过 config.ini 必须先 rm -rf cdk.out，否则用陈旧 asset）
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
```
改成
```bash
# 路由层（改过 config.ini 必须先 rm -rf cdk.out，否则用陈旧 asset）
# router 栈有 stack policy（拒 Update:* 落在 Edge 两函数 / 分发 / 路由表上），所以三步一组：
# open 打开（首次部署栈不存在时打印 SKIP）→ deploy → apply 关回去并读回核对。**open 之后无论 deploy 成败都要 apply。**
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
```

（b）「跨组件改动矩阵」，紧接第 305 行 `origin_request.py` 那一行之后加一行：

```markdown
| router 栈的四个受保护 construct ID（`OriginRequestFunction` / `OriginResponseFunction` / `Distribution` / `SubdomainMappingTable`） | `router/infrastructure/stack_policy.py` 的 `PROTECTED_CONSTRUCTS`（synth 期守卫 `assert_protected_constructs` 会红）、`scripts/router_stack_policy.py`、`verify_deployed_edge.sh` ⑤、DEPLOY.md ② 的 open → deploy → apply。**改 construct ID = 换逻辑 ID = 替换资源**——对分发与路由表那是事故 |
```

（c）「高频坑」列表末尾（`## 文档地图` 之前）加一条：

```markdown
- **router 栈有 stack policy，`cdk deploy` 前后各一步**：`router_stack_policy.py open` → deploy → `apply`。
  忘 open 的症状：`cdk deploy` 在 ExecuteChangeSet 阶段失败、栈事件里该资源 UPDATE_FAILED 且原因含
  "stack policy"、整栈回滚（Edge 不受影响；open 后重跑）。忘 apply **没有任何症状**——保护一直开着，
  只有 `verify_deployed_edge.sh` ⑤ 会红。策略拒的是 `Update:*`（Edge 换码是 Lambda `Code` 的
  Modify，只拒 Replace/Delete 拦不住它），越过它要 `cloudformation:SetStackPolicy`；它不管
  DeleteStack（termination protection 另配），也不管绕开 CloudFormation 直接调 Lambda/CloudFront API。
```

这三段文案已用 `_status_violations` 跑过：0 命中。

- [ ] **Step 3: 改 `site-builder/DEPLOY.md`（六处）**

（a）L521–523，轮转 runbook 的 B 段：

```bash
# ── B. 部署 Edge（**每次都 rm -rf cdk.out**，否则用陈旧 asset；stack policy 三步：open → deploy → apply）
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out \
   && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply   # 无论 deploy 成败都要跑
```

（b）L1117，S1 顺序表第 5 行的「动作」列：`router（Edge）` → `router（Edge）：`open` → deploy → `apply``。

（c）L1162–1163，S1 第 5 步：

```bash
# 5 router / Edge（stack policy 三步：open → deploy → apply；open 之后无论成败都要 apply）
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
```

（d）L1229，「六个硬闸门」表 `verify_deployed_edge.sh` 那一行：「它证明」列末尾追加
`；**⑤ router 栈的 stack policy**：一条 Deny 精确覆盖 Edge 两函数、分发与路由表四个逻辑 ID，且策略带 Allow-all（`router_stack_policy.py check`，只读）`；
「它不证明」列末尾追加 `。也不证明谁持有 `cloudformation:SetStackPolicy`（那是 IAM 层，归探针与信任边界文档）`。

（e）② 节第 2 步（L1897–1905 的代码块）改成：

```bash
   cd router/infrastructure
   # --clear：首次创建与已存在时重建都适用。venv 的 shebang 是绝对路径，
   # 仓库被移动或改名后旧 venv 会报 "bad interpreter"，而不带 --clear 的
   # python3 -m venv 对已存在目录不会重写 shebang（重跑也修不了）
   python3 -m venv --clear .venv                  # 或一次建齐：bash site-builder/scripts/bootstrap_venvs.sh（见 §0 本机工具链）
   .venv/bin/pip install -r requirements.txt -q
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest bootstrap aws://{account_id}/us-east-1   # 首次
   python3 ../../site-builder/scripts/router_stack_policy.py open    # 首次部署栈还不存在 → 打印 SKIP
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
   python3 ../../site-builder/scripts/router_stack_policy.py apply   # 设 stack policy 并读回核对；open 之后无论成败都要跑
```

并在该步既有的引用块（`> **`cdk deploy` 会长时间挂在最后一步**…`那一组）之后新增一个引用块：

```markdown
   > **router 栈带 stack policy，`cdk deploy` 前后各一步。** 策略对 Edge 两函数、CloudFront 分发与
   > 路由表四个资源的**精确逻辑 ID** 拒绝 `Update:*`（含 Modify——Edge 换码就是 Lambda `Code` 的
   > Modify，只拒 Replace/Delete 拦不住它）。效果：持有 `cloudformation:UpdateStack` 或
   > `CreateChangeSet`+`ExecuteChangeSet` **但没有 `cloudformation:SetStackPolicy`** 的 principal 改不了
   > 这四个资源（AWS 文档：越过策略必须有 SetStackPolicy；ExecuteChangeSet 不接受临时覆盖策略）。
   > 所以每次部署是三步：`open`（换成 Allow-all）→ `cdk deploy` → `apply`（按已部署模板推导逻辑 ID、
   > 写回并读回核对）。**stack policy 设上就删不掉，只能换**——"回滚本功能"也是先 `open`。
   > 它**不防** DeleteStack（termination protection 另配）、不防持有 SetStackPolicy 的人、不防绕开
   > CloudFormation 直接调 Lambda / CloudFront API 的那条路（那条的边际收益为 0，见 spec §1）。
   > 忘 open：`cdk deploy` 在 ExecuteChangeSet 阶段失败、事件原因含 "stack policy"、整栈回滚，
   > Edge 不受影响，open 后重跑。忘 apply：**没有任何症状**，只有 `verify_deployed_edge.sh` ⑤ 会红。
   > 需要的权限是操作者自己的 `cloudformation:DescribeStacks / GetTemplate / GetStackPolicy / SetStackPolicy`
   > ——CDK bootstrap 的角色没有 SetStackPolicy，脚本刻意不走它们。
```

（f）L2477，M5 部署目标表的 ② 行「命令」列：`cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never` → `见 ②「路由 + 鉴权层」第 2 步的三步（`open` → `cdk deploy` → `apply`）`。

- [ ] **Step 4: 跑 deployer 全套件（docs 守卫、状态守卫、既有文档守卫都在里面）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
```
Expected: 全绿（含 `test_every_router_deploy_site_is_wrapped_by_stack_policy_open_and_apply`、`test_status_free_docs_carry_no_environment_status[CLAUDE.md]`、`test_migrate_script_has_an_entry_in_both_deploy_and_claude`）。红了先看是不是这三条：前两条红说明文案没照抄；第三条红说明改 CLAUDE.md 部署块时碰掉了 migrate 那两行。

- [ ] **Step 5: 顺序再跑一遍 router 套件收尾**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/router/infrastructure/lambda"
../../../site-builder/deployer/.venv/bin/pytest . -q
```
Expected: 与 Task 2 结束时相同。worker 到此为止；**不提交**，worker_done 里报改动文件与两套件结果。

---

## Task 6（coordinator，验证环境，手工；worker 不做）: 部署并拿到真机证据

**前置**：D1 已裁定、Task 1–5 已合并到主 worktree、七套件顺序全绿。凭据用操作者自己的（需要 `cloudformation:SetStackPolicy`）。

- [ ] **Step 1: 三步部署。** 本次模板**不变**（守卫不加资源），所以 `cdk deploy` 预期报 no changes；`open` 会在一个原本没有策略的栈上写一份 Allow-all（语义上等于没变化）。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
```
Expected: `apply` 打印 `PASS … 已更新` 与四个 `LogicalResourceId/<construct ID><8 hex>`。

- [ ] **Step 2: 闸门的正 / 反对照（只改策略，不动栈）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/router_stack_policy.py check          # 期望 exit 0
python3 site-builder/scripts/router_stack_policy.py open
set +e; python3 site-builder/scripts/router_stack_policy.py check; echo "open 之后 check 退出码=$?（必须是 1）"; set -e
python3 site-builder/scripts/router_stack_policy.py apply
python3 site-builder/scripts/router_stack_policy.py check          # 期望 exit 0
bash site-builder/scripts/verify_deployed_edge.sh                   # ⑤ 必须 PASS，整体 exit 0
```

- [ ] **Step 3（可选，一次即可）: 拒绝的真机证据。** 让一次未 `open` 的部署碰到受保护资源：改 `router/config.ini` `[Tags] environment` 的值（Tags 落在每个资源上 ⇒ 四个受保护资源全部 Modify）→ `rm -rf cdk.out` → `cdk deploy` **不 open** → 期望失败、栈事件里出现受保护资源的 `UPDATE_FAILED`（原因含 stack policy）、栈回到 `UPDATE_ROLLBACK_COMPLETE`；然后**改回配置**、`rm -rf cdk.out`，再按三步部署一次把栈回到 `UPDATE_COMPLETE`。把事件原文（去掉账号值）记进 `.scratch/asset-v1/`（gitignored），并把"确切文案"补进 D1 那行——这是本 plan 唯一没实测的一条。这一步会在验证环境上留下一次回滚记录，做不做由 coordinator 定。

- [ ] **Step 4: 收尾（coordinator）**：`verify_account_trust_boundary.py` **不需要**重跑（本票不改 IAM、不加 principal）；D2 若立项，重跑 `probe_impersonation_surface.py`（只读、约 20 分钟）得到真实 −N 再改 §9 3f 与 spec §1 的数字；§9 3f 行加日期、工单 Status 改 `done`；D5 立项则 `/domain-modeling` 写 ADR 0007。

---

## 自查

**工单覆盖**：

| 工单要求 | 落点 |
|---|---|
| 禁止 Update 动作落在 Edge 函数、CloudFront 分发与路由表上 | `PROTECTED_CONSTRUCTS` 四行（Task 1）；动作集合按 D1 |
| 精确列资源逻辑 ID，不用 `*` | `build_policy` 只产出 `LogicalResourceId/<ID>`；`policy_problems` 与两侧测试都把通配判红（Task 1、3）|
| CDK 里表达（或 deploy 脚本里 SetStackPolicy） | 声明与 synth 期守卫在 CDK 侧（Task 2）；写入在脚本（Task 3）；两边共用一份定义 |
| "策略存在且覆盖这几个资源"的真机核对进 `verify_deployed_edge.sh` | ⑤（Task 4） |
| 资产检查：采用者账号同样有洞、随部署生效 | 新账号 runbook ② 第 2 步就是三步（Task 5）；无账号值；策略按已部署模板推导 |

**占位符扫描**：无 TBD / TODO / "类似 Task N"；每个代码步骤都给了完整代码。

**名字一致性**：`PROTECTED_CONSTRUCTS` / `DENIED_ACTIONS` / `OPEN_POLICY` / `ALLOW_ALL_STATEMENT` / `StackPolicyError` / `logical_id_pattern` / `protected_logical_ids` / `build_policy` / `canonical` / `policy_problems` / `assert_protected_constructs`（Task 1 定义，Task 2–4 引用）；`main(argv, cfn)` / `COMMANDS` / `load_stack_target`（Task 3 定义，Task 4 守卫引用文件路径）；`router_stack_policy.py open|apply|check`（Task 3 定义，Task 4/5 文档与守卫引用同一字面）。

**本 plan 之外、由本次分析暴露的后续项**（不在工单里，交 coordinator 立项）：D2 探针建模与 §9 / spec §1 数字重算；D4 termination protection；deployer 栈（sites 表是真源）是否也要同款 stack policy——模块与脚本按栈名参数化即可复用，但那是另一张票。
