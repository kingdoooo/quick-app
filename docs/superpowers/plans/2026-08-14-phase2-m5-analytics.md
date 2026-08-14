# M5 访问记录 / 统计 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 每站点 PV/UV（按天/周/月）+ 逐请求访问审计（含被拒），面板图表可看、MCP 工具可查。

**Architecture:** Lambda@Edge 的 origin-request 在鉴权判定之后、`return` 之前，向
`site-access-events`（DynamoDB Global Table，3 区副本）写**一行**访问事件；
每日 rollup Lambda 把完整日聚合进 `site-access-daily`（400 天）。面板与 MCP 只读这两张表。
摄取是单一写入点，下游不知道行是谁写的——日后换摄取方式不动 schema。

**Tech Stack:** Lambda@Edge（Python 3.11，单文件 `index.py`，占位符注入）、
DynamoDB（`TableV2` 多区 + `Table`）、CDK（Python）、Step Functions 无关、
panel Function URL（Python 3.13）、FastMCP、pytest。

## Global Constraints

- **命令一律假定 cwd = 仓库根**，路径写仓库相对（对齐 M3/M4 计划；
  绝对路径会把 host-local 信息写进被跟踪文件，且换机器就失效）。
- **spec 是本计划的上级**：`docs/superpowers/specs/2026-08-14-phase2-m5-analytics-spec.md`。冲突以 spec 为准。
- **不 push**。分支 master（用户已批准直接在 master 上做）。commit **不带** `--no-verify`。
- **一切文件操作从仓库根用绝对路径**。`configparser.read()` 读不到文件是静默返回空 → 任何 `has_section`/取值前先 `assert c.sections()`。
- **`site-builder/config.ini` 与 `router/config.ini` 是 gitignored 且含真实值**：不 `git add -f`、不打印全文；真实账号/域名/邮箱不进任何被跟踪文件。
- **每个守卫/断言写完必须注入它要防的缺陷、确认变红、还原后 `diff -q` + `git status` 双证。还原用 `/tmp` 备份，不用 `git checkout --`**（会连未提交的工作一起冲掉）。
- **负测必须配正对照**（M4-FINDINGS §3.5）；**永久 SKIP 的检查是死重量**（§3.6）。
- 说「实测过」之前，确认测的是**真实调用路径算出的参数**，不是手填的。
- **别拿 CFN 的 `StackStatus` 当部署结论**，直接读回被改的那个属性。
- `--skip-X` 类开关要检查「跳过的那步是不是后续步骤的前提」。
- Code Defender 拦 AROA/AIDA 整串字面量时改拼接形态，**不动扫描器配置**。
- **中文字符串里不用全角引号**（要引用就用 `「」`）——曾因此三次 SyntaxError。
- 表名/区域清单等常量：**唯一定义 + 从真源推导**，不手抄第二份。

### 各包的测试命令（照抄，venv 归属不同）

```bash
cd site-builder/contract  && .venv/bin/pytest tests -q
cd site-builder/auth      && ../contract/.venv/bin/pytest tests -q
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q
cd site-builder/deployer  && .venv/bin/pytest tests -q          # 必须带 tests/
cd site-builder/mcp       && python3 -m pytest tests -q
cd site-builder/panel     && ../deployer/.venv/bin/pytest tests -q
cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q
```

CDK 模板断言（默认 skip，需显式开 + PYTHONPATH 桥接，synth 需 Docker）：

```bash
# deployer
cd site-builder/deployer && PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" \
  SB_CDK_TESTS=1 .venv/bin/pytest tests/test_infra_tables.py -q
# router
cd router/infrastructure/lambda && PYTHONPATH="$PWD/../.venv/lib/python3.12/site-packages" \
  SB_CDK_TESTS=1 ../../../site-builder/deployer/.venv/bin/pytest test_stack_edge_iam.py -q
```

---

## File Structure

**新建**

| 文件 | 职责 |
|---|---|
| `site-builder/deployer/functions/access_rollup.py` | 每日聚合：Query 明细分区 → 算 pv/uv/pv_denied → 覆盖写聚合行。纯标准库 + boto3 |
| `site-builder/deployer/tests/test_access_rollup.py` | rollup 的单测（moto） |
| `site-builder/deployer/functions/analytics.py` | **共享**读取层：panel 与 MCP 唯一访问这两张表的模块。**必须落在 `deployer/functions/`**——那是本仓库共享模块的既有位置，也是 MCP 传递闭包守卫**唯一会扫的目录**（`test_agentcore_contract.py` 的 `candidate = fn_dir / f"{name}.py"`）。放在 `panel/` 下会被该守卫静默忽略，容器里则 `ModuleNotFoundError`（Codex 审查 P1-2，已实测 Dockerfile 只 COPY 四个文件） |
| `site-builder/deployer/tests/test_analytics.py` | 读取层单测（模块落 `functions/` ⇒ 单测落 `deployer/tests/`，与 keygen/edge_caller 同惯例） |
| `site-builder/panel/tests/test_analytics_api.py` | 两个端点的授权/参数单测 |
| `site-builder/scripts/verify_analytics_e2e.py` | 真机闸门 |

**改动**

| 文件 | 改什么 |
|---|---|
| `router/infrastructure/lambda/origin_request.py` | 埋点（新增 5 个函数 + 3 个常量 + `lambda_handler`/`_check_auth` 各一处接线） |
| `router/infrastructure/stack.py` | 两个新占位符注入 + edge_role 的 PutItem（3 个副本 ARN） |
| `router/infrastructure/lambda/test_origin_request.py` | 新占位符的替换项 |
| `router/infrastructure/lambda/test_edge_access_log.py` | **新建**（埋点单测，与既有 `test_edge_auth.py` 同机制） |
| `router/infrastructure/lambda/test_stack_edge_iam.py` | DynamoDB 资源集合断言 + cache policy 断言 |
| `router/config.ini.example` | `[SiteBuilder]` 加 `access_table` / `access_replica_regions` |
| `site-builder/deployer/infra/app.py` | 两张表 + rollup Lambda + EventBridge rule + IAM |
| `site-builder/deployer/tests/test_infra_tables.py` | 两张表的 CDK 断言 |
| `site-builder/deployer/functions/permissions.py` | `CAPABILITIES` 加 `view_analytics` |
| `site-builder/panel/handler.py` | ROUTES 两条 + `_dispatch` 两个分支 |
| `site-builder/panel/api.py` | `do_get_analytics` / `do_get_visitors`（授权 + 委派 analytics.py） |
| `site-builder/panel/frontend/app.js` | 真实统计页（删占位与「不发请求」注释） |
| `site-builder/panel/tests/test_frontend_contract.py` | 第 ③ 组守卫改造 |
| `site-builder/panel/deploy_panel.py` | 两张表的环境变量 |
| `site-builder/mcp/server.py` | `get_site_analytics` 工具 |
| `site-builder/mcp/tests/test_analytics_tool.py` | **新建** |
| `site-builder/scripts/verify_console_e2e.py` | ⑪ 段改造 |
| `site-builder/scripts/verify_deployed_components.py` | 新增 ⑨ 段 |
| `site-builder/DEPLOY.md` · `CLAUDE.md` · `docs/design/M4-FINDINGS.md` · HANDOFF | 文档 |

**边界**：`analytics.py` 是 panel 侧唯一碰这两张表的模块（api.py 不出现表名）；
`access_rollup.py` 是唯一写聚合表的代码；Edge 是唯一写明细表的代码。

---

## Task 1: 把 M4-FINDINGS 的两条候选补成正式条目

本轮拿 M4-FINDINGS 当检查清单用，而它缺了两条——那两条**恰好是 M5 要用的判据**
（副本是否真开了、对生产做破坏性调用）。「候选」状态意味着下一个人读清单时看不到。

**Files:**
- Modify: `docs/design/M4-FINDINGS.md`（gitignored，**不要 `git add -f`**）
- 来源: `.superpowers/sdd/2026-08-10-phase2-m4-api-key/progress.md` 的「本轮两条新的方法论记录（已进 M4-FINDINGS 的候选）」

- [ ] **Step 1: 确认现状（该文件到 §3.12 为止）**

```bash
grep -n "^## §3" docs/design/M4-FINDINGS.md | tail -3
```

预期：最后一条是 `## §3.12`。若已有 §3.13 则本 Task 已完成，跳过。

- [ ] **Step 2: 追加两节**

在文件末尾追加（保持既有形态：只记「跑出来才知道」的东西）：

```markdown

---

## §3.13 别拿 `StackStatus` 当部署结论

`rm -rf cdk.out` 后重新 bundling 超过 10 分钟（同样命令上一次只用 133s），CLI 被
超时杀掉，而 CloudFormation **压根没提交 changeset**——栈仍显示上一次的
`UPDATE_COMPLETE`。看一眼会以为部署成功了，实际三张表只有一张生效。

**判据**：部署结论只能来自**直接读回被改的那个属性**（`describe-table` 读
`DeletionProtectionEnabled` / `Replicas`，`get-function-configuration` 读环境变量），
不能来自 `StackStatus`、不能来自 CLI 退出码（那条另见 2026-08-06 轮）。

## §3.14 对生产做破坏性调用要先问

为验证 deletion protection 生效，我真的对**凭证表**发了一次 `delete-table`
（脚本里先 describe 确认保护已开、再删，所以只可能被拒），拿到
`ValidationException`。顺序上是安全的，但那是凭证表——**应该先征得同意再做，
而不是靠自己的排序**。后两张表因此只做读回核对：DeletionProtection 是 DynamoDB
的属性，行为已证一次即可，不必每张表重复一次破坏性调用。

**判据**：破坏性调用的安全性不由「我把顺序排对了」保证，而由「事前得到同意」
保证。前者只在我没算错的时候成立。
```

- [ ] **Step 3: 复核编号与可读性**

```bash
grep -n "^## §3.1[234]" docs/design/M4-FINDINGS.md
```

预期：`§3.12` / `§3.13` / `§3.14` 三行，编号连续无重复。

- [ ] **Step 4: 确认它没被 git 跟踪**

```bash
cd "$(git rev-parse --show-toplevel)" && git status --short && git check-ignore -v docs/design/M4-FINDINGS.md
```

预期：`git status` 里**没有** M4-FINDINGS；`check-ignore` 输出命中规则。本 Task **无提交**。

---

## Task 2: 两张表（deployer CDK）

**Files:**
- Modify: `site-builder/deployer/infra/app.py`（在 `api_keys` 定义之后、`artifacts` 之前）
- Test: `site-builder/deployer/tests/test_infra_tables.py`

**Interfaces:**
- Produces: 表名 `site-access-events`（PK `site_date` S / SK `ts_id` S / TTL `expires_at` / `TableV2` 3 区副本 / DESTROY）与 `site-access-daily`（PK `site_id` S / SK `date` S / TTL `expires_at` / RETAIN + `deletion_protection=True`）。后续 Task 3/5/8/10 按这两个名字与键名取值。

- [ ] **Step 0: 先修测试 fixture——否则本 Task 的测试无法运行**

**`TableV2` + `replicas` 在 region-agnostic 栈里直接 synth 抛错**（2026-08-14
实测）：

```
«ReplicaTablesNotSupportedInRegionAgnosticStack» Replica tables are not
supported in a region agnostic stack
```

而 `site-builder/deployer/tests/test_infra_tables.py:46` 建栈时**没有传 env**：

```python
stack = mod.SiteDeployerStack(app, "TestStack")
```

后果不是「断言无效」而是**整个文件崩**——fixture 一抛异常，连
`test_every_retained_table_has_deletion_protection`（RETAIN 不变量）一起挂。
真实入口 `app.py:419` 是带 env 的，所以这只是测试侧的缺口。

改成（`ACCOUNT`/`REGION` 是 app.py 从 config.ini 读出来的模块级常量）：

```python
    app = aws_cdk.App()
    # **必须传 env**：TableV2 的 replicas 在 region-agnostic 栈里会抛
    # ReplicaTablesNotSupportedInRegionAgnosticStack（2026-08-14 实测），
    # fixture 一抛异常会让本文件所有用例连带失效（含 RETAIN 不变量那条）。
    # 顺带的好处：带 env 后 self.account/region 渲染成字面量而不是
    # Fn::Join + Ref(AWS::AccountId)，模板断言可以直接比字符串。
    stack = mod.SiteDeployerStack(
        app, "TestStack",
        env=aws_cdk.Environment(account=mod.ACCOUNT, region=mod.REGION))
```

跑一次确认既有用例仍全绿（**这一步先于新断言**，否则分不清红的是新表还是
fixture）：

```bash
cd site-builder/deployer && \
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```

- [ ] **Step 1: 写失败的测试**

追加到 `site-builder/deployer/tests/test_infra_tables.py`：

> 实测确认的模板形态（2026-08-14 synth）：资源类型是
> **`AWS::DynamoDB::GlobalTable`**；`Properties.Replicas` **包含主区**
> （实测 `['ap-southeast-1','ap-northeast-1','us-east-1']`）；
> `Properties.TimeToLiveSpecification` 在顶层；`DeletionPolicy` 为 `Delete`。

```python
def test_access_events_table_is_a_three_region_global_table(template):
    """明细表必须是 3 区 Global Table（spec §0.4）。

    漏一个副本区 = 那个区的埋点跨区回落（正确但慢）；而 IAM 少给一个副本 ARN
    = 那个区静默零数据（Task 4 锁 IAM，这里只锁表）。
    """
    tables = template.find_resources("AWS::DynamoDB::GlobalTable")
    hit = [t for t in tables.values()
           if t["Properties"].get("TableName") == "site-access-events"]
    assert len(hit) == 1, f"site-access-events 不是 GlobalTable：{list(tables)}"
    props = hit[0]["Properties"]
    regions = {r["Region"] for r in props["Replicas"]}
    assert regions == {"us-east-1", "ap-southeast-1", "ap-northeast-1"}, (
        f"副本区集合不对: {sorted(regions)}")
    keys = {k["AttributeName"]: k["KeyType"] for k in props["KeySchema"]}
    assert keys == {"site_date": "HASH", "ts_id": "RANGE"}, keys
    assert props["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
    assert props["TimeToLiveSpecification"]["Enabled"] is True


def test_access_daily_table_is_retained_and_protected(template):
    """聚合表 400 天趋势丢了不可重建（明细 90 天就没了）→ RETAIN + 保护。

    RETAIN 那半由 test_every_retained_table_has_deletion_protection 从模板推导，
    本条只钉键与 TTL 属性名——键名错了下游全部 Query 失败。
    """
    for res in template.find_resources("AWS::DynamoDB::Table").values():
        if res["Properties"].get("TableName") != "site-access-daily":
            continue
        keys = {k["AttributeName"]: k["KeyType"] for k in res["Properties"]["KeySchema"]}
        assert keys == {"site_id": "HASH", "date": "RANGE"}, keys
        assert res["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
        assert res["DeletionPolicy"] == "Retain"
        return
    raise AssertionError("模板里找不到 site-access-daily")
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && \
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q -k access
```

预期：两条 FAIL（`site-access-events 不是 GlobalTable：[]` / `找不到 site-access-daily`）。
**若报 skip 或 aws_cdk ImportError，先修桥接**——静默 skip 等于这次什么都没验。

- [ ] **Step 3: 写实现**

`site-builder/deployer/infra/app.py`：`import` 段确认已有 `aws_dynamodb as ddb`（已有）。
在 `api_keys` 的两个 GSI 之后插入：

```python
        # 二期 M5：访问明细。**Global Table（3 区）**——Edge 写它执行区的本地
        # 副本。实测跨区写 229ms / 同区 6ms（spec §0.1、§0.4），97% 的代价是
        # 那条跨太平洋的腿，不是"同步写"本身。副本区集合与
        # router/config.ini 的 access_replica_regions 必须一致，由
        # test_stack_edge_iam.py 从同一份清单推导锁死（漏一个 = 该区静默零数据）。
        #
        # 用 TableV2 而不是给 Table 配 replication_regions：后者是自定义资源。
        # 本表是仓库里唯一的多区表，引入第二种构造类型是有意的局部选择。
        #
        # DESTROY（不同于 daily）：90 天滚动明细，删栈丢掉可接受。所以它**不进**
        # RETAIN⇒deletion_protection 那条不变量的范围。
        access_events = ddb.TableV2(
            self, "AccessEvents", table_name="site-access-events",
            partition_key=ddb.Attribute(name="site_date",
                                        type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="ts_id", type=ddb.AttributeType.STRING),
            billing=ddb.Billing.on_demand(),
            time_to_live_attribute="expires_at",
            replicas=[ddb.ReplicaTableProps(region="ap-southeast-1"),
                      ddb.ReplicaTableProps(region="ap-northeast-1")],
            removal_policy=RemovalPolicy.DESTROY)

        # 二期 M5：日聚合。RETAIN + deletion_protection 与 ops_log/admins 同理
        # ——400 天趋势**一旦丢不可重建**（明细只活 90 天）。写入方只有 rollup。
        access_daily = ddb.Table(
            self, "AccessDaily", table_name="site-access-daily",
            partition_key=ddb.Attribute(name="site_id",
                                        type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="date", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            deletion_protection=True,
            removal_policy=RemovalPolicy.RETAIN)
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/deployer && \
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```

预期：全部 PASS，**包括** `test_every_retained_table_has_deletion_protection`
（它会自动把 `site-access-daily` 纳入并要求保护）。

- [ ] **Step 5: 反向验证（两条守卫各一次）**

```bash
cp site-builder/deployer/infra/app.py /tmp/app.py.bak
```

① 删掉 `ap-northeast-1` 那一行副本 → 重跑 → 预期 `副本区集合不对: ['ap-southeast-1', 'us-east-1']`。
② 把 `access_daily` 的 `deletion_protection=True` 删掉 → 重跑 → 预期
`test_every_retained_table_has_deletion_protection` 点名 `site-access-daily`。

还原并双证：

```bash
cp /tmp/app.py.bak site-builder/deployer/infra/app.py
diff -q /tmp/app.py.bak site-builder/deployer/infra/app.py && \
  cd "$(git rev-parse --show-toplevel)" && git status --short
```

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/infra/app.py site-builder/deployer/tests/test_infra_tables.py
git commit -m "feat(m5): 访问明细表（3 区 Global Table）与日聚合表（RETAIN+保护）

明细 DESTROY/TTL 90 天，聚合 RETAIN+deletion_protection/TTL 400 天。
副本区集合由 CDK 断言锁死——漏一个区 = 该区埋点跨区回落，而 IAM 漏一个
副本 ARN = 该区静默零数据（Task 4 锁后者）。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Edge 埋点

**Files:**
- Modify: `router/infrastructure/lambda/origin_request.py`
- Modify: `router/infrastructure/lambda/test_origin_request.py:11-14`（补两个占位符替换）
- Create: `router/infrastructure/lambda/test_edge_access_log.py`

**Interfaces:**
- Consumes: Task 2 的表名与键名。
- Produces: `_access_region(context) -> str`、`_access_client(region)`、
  `_is_page_request(route, uri) -> bool`、`_record_access(context, site_id, uri, decision, email) -> None`、
  `_maybe_record(context, subdomain, uri, route, denied, sink) -> None`；
  `_check_auth(request, route, host, sink=None)` 新增**可选** out-param。
  占位符 `{{ACCESS_TABLE}}` / `{{ACCESS_REPLICA_REGIONS}}`（Task 4 注入）。

- [ ] **Step 1: 写失败的测试**

新建 `router/infrastructure/lambda/test_edge_access_log.py`：

```python
"""M5 埋点单测。机制同 test_edge_auth.py：把 origin_request.py 读进来做
占位符替换后写成一个 testable 副本再 import（所以改 origin_request.py 会自动
流进本文件，不存在"两份代码漂移"）。
"""
import importlib
import json
from pathlib import Path

import pytest

_SRC = (Path(__file__).parents[0] / "origin_request.py").read_text()
_SUBS = {
    "{{DYNAMODB_TABLE_NAME}}": "test-table",
    "{{DYNAMODB_REGION}}": "us-east-1",
    "{{FRONTEND_BUCKET_DOMAIN}}": "site-frontend-123.s3.us-east-1.amazonaws.com",
    "{{JWT_SECRET}}": "test-secret",
    "{{BASE_DOMAIN}}": "example.test",
    "{{REQUIRE_IDP_CLAIM}}": "false",
    "{{TRUSTED_IDPS}}": "Feishu",
    "{{ACCESS_TABLE}}": "site-access-events",
    "{{ACCESS_REPLICA_REGIONS}}": "us-east-1,ap-southeast-1,ap-northeast-1",
}
for _k, _v in _SUBS.items():
    _SRC = _SRC.replace(_k, _v)
(Path(__file__).parent / "_edge_access_testable.py").write_text(_SRC)
import _edge_access_testable as orq          # noqa: E402


class Ctx:
    def __init__(self, arn=""):
        self.invoked_function_arn = arn


# ── 区域解析与回落（spec §2.3 规矩 5）────────────────────────────────

def test_region_comes_from_env_when_it_is_a_replica(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")
    assert orq._access_region(Ctx()) == "ap-southeast-1"


def test_region_falls_back_to_arn_when_env_missing(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    ctx = Ctx("arn:aws:lambda:ap-northeast-1:111111111111:function:x")
    assert orq._access_region(ctx) == "ap-northeast-1"


def test_unresolvable_region_falls_back_to_primary(monkeypatch):
    """解析不出区域 → 回落 us-east-1 = 正确但慢，**永不丢数据**。"""
    monkeypatch.delenv("AWS_REGION", raising=False)
    assert orq._access_region(Ctx("")) == "us-east-1"


def test_region_without_a_replica_falls_back_to_primary(monkeypatch):
    """解析出一个没有副本的区 → 也必须回落，不能对着不存在的副本发请求。"""
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert orq._access_region(Ctx()) == "us-east-1"


# ── 页面级判定必须与静态改写用同一个条件（spec §2.2）────────────────

# oracle **必须来自真实的 _route_request**，不能复刻它的条件。
# 初版就是复刻的，于是漏了 /api/ 前置分支还全绿（P1-1）。
# 另注：oracle 也不能写成"进了静态桶"——`.css` 也进桶。判据是**被改写成
# index.html**（我第一次写这个 oracle 时就选错了，表格看着对、结论是错的）。
_PAGE_CASES = [
    ("/", True), ("/notes", True), ("/a/b", True), ("/.well-known/x", True),
    ("/app.css", False), ("/x/main.js", False), ("/favicon.ico", False),
    # ↓ P1-1 的回归：split 站点的 /api/* 走后端，**不是页面**
    ("/api/data", False), ("/api/sites/x/jobs", False), ("/api/x.json", False),
]


@pytest.mark.parametrize("uri,is_page", _PAGE_CASES)
def test_page_detection_agrees_with_real_routing(uri, is_page):
    route = {"route_mode": "split", "static_prefix": "sites/x",
             "api_target": "https://f.lambda-url.us-east-1.on.aws/"}
    req = {"uri": uri, "method": "GET", "querystring": "", "headers": {}}
    out = orq._route_request(req, dict(route))
    # 真实判据：被改写成 index.html ⇔ 这是一次页面浏览
    really_a_page = str(out.get("uri", "")).endswith("/index.html")
    assert really_a_page is is_page, f"用例表与真实路由不符: {uri}"
    assert orq._is_page_request(route, uri) is really_a_page, (
        f"_is_page_request 与 _route_request 对 {uri} 判断不一致")


def test_api_only_sites_record_every_request():
    assert orq._is_page_request({"route_mode": "api-only"}, "/x.css") is True


# ── 只记 app- 前缀（spec §2.1）─────────────────────────────────────

@pytest.mark.parametrize("sub,recorded", [
    ("app-notes-abc123", True), ("auth", False),
    ("console", False), ("mcp", False),
])
def test_only_app_prefixed_subdomains_are_recorded(monkeypatch, sub, recorded):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda *a, **k: seen.append(a))
    orq._maybe_record(Ctx(), sub, "/", {"route_mode": "split"}, None, {})
    assert bool(seen) is recorded


def test_site_id_is_the_subdomain_minus_the_app_prefix(monkeypatch):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda ctx, site_id, uri, decision, email:
                        seen.append((site_id, decision, email)))
    orq._maybe_record(Ctx(), "app-notes-01d147", "/", {"route_mode": "split"},
                      None, {"email": "a@b.co"})
    assert seen == [("notes-01d147", "allow", "a@b.co")]


# ── 三种 decision ────────────────────────────────────────────────

@pytest.mark.parametrize("denied,decision", [
    (None, "allow"),
    ({"status": "403"}, "denied_403"),
    ({"status": "302"}, "redirect_login"),
])
def test_decision_covers_allow_and_both_denials(monkeypatch, denied, decision):
    seen = []
    monkeypatch.setattr(orq, "_record_access",
                        lambda ctx, site_id, uri, d, email: seen.append(d))
    orq._maybe_record(Ctx(), "app-x-abc123", "/", {"route_mode": "split"},
                      denied, {"email": "a@b.co"})
    assert seen == [decision]


# ── 埋点绝不能影响路由/鉴权（spec §2.3 规矩 3）──────────────────────

def test_a_throwing_write_does_not_change_the_returned_request(monkeypatch):
    """写穿抛任何异常都不许改变返回值——统计不是安全控制，这里 fail-open。"""
    def boom(*a, **k):
        raise RuntimeError("DynamoDB 挂了")
    monkeypatch.setattr(orq, "_access_client", boom)
    monkeypatch.setattr(orq, "_lookup_route", lambda sub: {
        "require_auth": False, "route_mode": "api-only",
        "api_target": "https://f.lambda-url.us-east-1.on.aws/"})
    event = {"Records": [{"cf": {"request": {
        "uri": "/", "method": "GET", "querystring": "",
        "headers": {"host": [{"key": "Host", "value": "app-x-abc123.example.test"}]}}}}]}
    out = orq.lambda_handler(event, Ctx())
    assert "origin" in out, "埋点异常把请求变成了错误响应"


def test_client_construction_failure_is_also_swallowed(monkeypatch):
    """兜底必须覆盖 client 取用本身，不能只包住 put_item 调用。"""
    monkeypatch.setattr(orq, "_access_region",
                        lambda ctx: (_ for _ in ()).throw(RuntimeError("x")))
    orq._maybe_record(Ctx(), "app-x-abc123", "/", {"route_mode": "split"},
                      None, {"email": "a@b.co"})   # 不抛即通过


# ── 不许往返回的 request 对象加自定义键（spec §2.3 规矩 1）───────────

def test_returned_request_has_no_custom_keys(monkeypatch):
    """CloudFront 会校验 request 对象的形状；多一个键就是 500。

    身份靠独立的 sink dict 带出，不挂在 request 上。
    """
    monkeypatch.setattr(orq, "_record_access", lambda *a, **k: None)
    monkeypatch.setattr(orq, "_lookup_route", lambda sub: {
        "require_auth": False, "route_mode": "api-only",
        "api_target": "https://f.lambda-url.us-east-1.on.aws/"})
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x-abc123.example.test"}]}}
    out = orq.lambda_handler({"Records": [{"cf": {"request": req}}]}, Ctx())
    allowed = {"uri", "method", "querystring", "headers", "origin", "body",
               "clientIp"}
    assert set(out) <= allowed, f"request 对象多了键: {set(out) - allowed}"


# ── 写入形态 ────────────────────────────────────────────────────

def test_written_item_shape(monkeypatch):
    captured = {}

    class FakeClient:
        def put_item(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(orq, "_access_client", lambda rg: FakeClient())
    orq._record_access(Ctx(), "notes-01d147", "/x", "allow", "a@b.co")
    assert captured["TableName"] == "site-access-events"
    item = captured["Item"]
    assert item["site_date"]["S"].startswith("notes-01d147#")
    assert len(item["site_date"]["S"].split("#")[1]) == 10       # YYYY-MM-DD
    assert "#" in item["ts_id"]["S"]
    assert item["email"]["S"] == "a@b.co"
    assert item["decision"]["S"] == "allow"
    assert int(item["expires_at"]["N"]) > 0


def test_unauthenticated_denial_writes_an_empty_email(monkeypatch):
    """302（未登录）没有身份可言 → 空串。DynamoDB 允许**非键**属性为空串。"""
    captured = {}

    class FakeClient:
        def put_item(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(orq, "_access_client", lambda rg: FakeClient())
    orq._record_access(Ctx(), "x-abc123", "/", "redirect_login", "")
    assert captured["Item"]["email"]["S"] == ""


# ── sink：403 也要拿到已验签邮箱 ─────────────────────────────────

def test_sink_carries_email_even_when_access_is_forbidden():
    """被拒记录的价值在于"谁被拒了"，所以 403 分支也要有邮箱。"""
    import base64, hashlib, hmac, time
    payload = base64.urlsafe_b64encode(json.dumps(
        {"email": "out@b.co", "exp": int(time.time()) + 600}).encode()).rstrip(b"=").decode()
    head = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(
        b"test-secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token = f"{head}.{payload}.{sig}"
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x.example.test"}],
                       "cookie": [{"key": "Cookie", "value": f"sb_session={token}"}]}}
    sink = {}
    denied = orq._check_auth(req, {"require_auth": True, "allowed_users": [],
                                   "owner": "someone@else.co"}, "app-x.example.test",
                             sink)
    assert denied and denied["status"] == "403"
    assert sink["email"] == "out@b.co"


def test_untrusted_idp_session_yields_302_without_an_email():
    """P2-1 的回归：签名有效但 idp/auth_via 不可信 → 302 且 sink 里**没有**邮箱。

    这条与上一条是一对：403 必须有邮箱（"谁被拒了"），302 必须没有
    （契约说 redirect_login 的 email 是空串）。只写其中一条都会漏掉 P2-1。
    需要 REQUIRE_IDP_CLAIM=true 的副本，机制照 test_edge_auth.py 的
    `_edge_noidp_testable` 形态：把占位符替换成 true 后重新加载模块。
    """
    import importlib
    src = (Path(__file__).parents[0] / "origin_request.py").read_text()
    subs = dict(_SUBS, **{"{{REQUIRE_IDP_CLAIM}}": "true"})
    for k, v in subs.items():
        src = src.replace(k, v)
    (Path(__file__).parent / "_edge_access_idp_testable.py").write_text(src)
    mod = importlib.import_module("_edge_access_idp_testable")
    import base64, hashlib, hmac, time
    head = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"email": "linked@b.co", "exp": int(time.time()) + 600,
         "idp": "Cognito",
         "auth_via": "TokenGeneration_Authentication"}).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(
        b"test-secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    req = {"uri": "/", "method": "GET", "querystring": "",
           "headers": {"host": [{"key": "Host", "value": "app-x.example.test"}],
                       "cookie": [{"key": "Cookie",
                                   "value": f"sb_session={head}.{payload}.{sig}"}]}}
    sink = {}
    denied = mod._check_auth(req, {"require_auth": True, "allowed_users": "org"},
                             "app-x.example.test", sink)
    assert denied and denied["status"] == "302"
    assert sink.get("email", "") == "", (
        f"302 却带了邮箱: {sink}——违反 spec §1.1 的 redirect_login 契约")
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd router/infrastructure/lambda && \
  ../../../site-builder/deployer/.venv/bin/pytest test_edge_access_log.py -q
```

预期：collection 阶段即 FAIL/ERROR（`_access_region` 等不存在）。

- [ ] **Step 3: 写实现**

`origin_request.py` 顶部 import 段补 `os` 与 `Config`：

```python
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import boto3
from botocore.config import Config
```

在 `dynamodb = boto3.client(...)` 之后插入：

```python
# ── 访问埋点（M5）──────────────────────────────────────────────────
# 只记**页面级**请求，且只记 app- 前缀的用户站点。写本区副本（Global Table）。
ACCESS_TABLE = "{{ACCESS_TABLE}}"
ACCESS_REPLICA_REGIONS = tuple(
    x.strip() for x in "{{ACCESS_REPLICA_REGIONS}}".split(",") if x.strip())
ACCESS_TTL_DAYS = 90
_ACCESS_CLIENTS: dict = {}

# 超时预算经过两次修正，**别收紧**（spec §2.3 规矩 4）：
#   · 初版 0.3/0.5 被实测否掉——跨区冷连接首次 PutItem 要 719ms，于是每个冷
#     容器的首次埋点必然超时并被下面的 except 吞掉 = 静默丢行；
#   · 正常路径是同区副本（实测冷 58ms / 暖 6ms），离这个预算差两个数量级；
#   · 预算的**下限由回落路径**（跨区 719ms）决定，不是由同区 58ms 决定。
#     收紧到"够本区用"就等于让回落路径静默丢行。
# 不给重试：埋点重试的价值低于它带来的延迟方差。
_ACCESS_CFG = Config(connect_timeout=1.0, read_timeout=2.0,
                     retries={"max_attempts": 0})


def _access_region(context) -> str:
    """写哪个副本。

    **解析不出、或解析出一个没有副本的区，都回落主区**——回落 = 跨区写 =
    正确但慢，**永不丢数据**。这条是"加副本"这个优化不会变成故障的唯一保证。
    `AWS_REGION` 在 Lambda@Edge 里是否可用由部署时的日志实测确定（spec §0.4
    第 1 步）；拿不到就退到 ARN 解析，两者都拿不到就回落。
    """
    region = os.environ.get("AWS_REGION") or ""
    if region not in ACCESS_REPLICA_REGIONS:
        arn = getattr(context, "invoked_function_arn", "") or ""
        parts = arn.split(":")
        region = parts[3] if len(parts) > 3 else ""
    if region not in ACCESS_REPLICA_REGIONS:
        return DYNAMODB_REGION
    return region


def _access_client(region: str):
    """按区缓存的 client。**不复用模块级 `dynamodb`**——那个钉在主区，
    而这里要写本区副本，两者不是同一个连接池（spec §2.3 规矩 4 第二版被推翻的
    正是"复用就能蹭到暖连接"这个推论）。"""
    if region not in _ACCESS_CLIENTS:
        _ACCESS_CLIENTS[region] = boto3.client("dynamodb", region_name=region,
                                               config=_ACCESS_CFG)
    return _ACCESS_CLIENTS[region]


def _is_page_request(route: dict, uri: str) -> bool:
    """页面级 ⇔ `_route_request` 会把它改写成 /index.html。

    **必须逐条镜像 `_route_request` 的分支顺序，不只抄"有没有点号"那一条。**
    初版漏了 `/api/` 前置分支（Codex 审查 2026-08-14 P1-1），实测后果：
    split 站点的 `/api/data`、`/api/sites/x/jobs` 没有扩展名 → 被判成页面，
    而它们真实是走后端的。一次 SPA 打开 + 5 个接口调用 = **PV 放大到 6 倍**，
    且 rollup / panel / MCP 会一致地返回同一个错误数字（没有任何一侧会红）。

    分支顺序（与 `_route_request` 一一对应）：
      ① api-only 站点 → 全路径走后端，没有"页面 vs 资源"之分，全记；
      ② `/api/` 前缀 → 走后端，**不是页面**；
      ③ 其余：有扩展名 → 静态资源；无扩展名 → 改写成 /index.html = 页面。
    """
    if route.get("route_mode") == "api-only":
        return True
    if uri.startswith("/api/"):
        return False
    return "." not in uri.rsplit("/", 1)[-1]


def _record_access(context, site_id: str, uri: str, decision: str,
                   email: str) -> None:
    """写一行访问明细。**任何异常都吞掉**——统计不是安全控制，这里 fail-open
    是对的（与本文件其它 fail-closed 判定的区别是有意的，别"统一"掉）。
    兜底覆盖 client 取用本身，不只包住 put_item。
    """
    try:
        now = datetime.now(timezone.utc)
        _access_client(_access_region(context)).put_item(
            TableName=ACCESS_TABLE,
            Item={"site_date": {"S": f"{site_id}#{now.strftime('%Y-%m-%d')}"},
                  # ts 在最前面：读取方式是按分区 Query 再按 SK 排时间线。
                  # 随机后缀不可省——同一微秒两条请求会撞同一主键，第二条
                  # 静默覆盖第一条（ops_log.record 的 docstring 记过实测）。
                  "ts_id": {"S": f"{now.isoformat()}#{secrets.token_hex(3)}"},
                  "site_id": {"S": site_id},
                  # 空串合法（DynamoDB 只禁**键**属性为空）：302 未登录时确实
                  # 没有身份可言，写 "-" 之类的哨兵会污染 distinct email 的计数。
                  "email": {"S": email},
                  "path": {"S": uri[:512]},
                  "decision": {"S": decision},
                  "expires_at": {"N": str(int(now.timestamp())
                                          + ACCESS_TTL_DAYS * 86400)}})
    except Exception as e:      # noqa: BLE001
        print(f"[WARN] 访问埋点失败 site={site_id} decision={decision}: "
              f"{type(e).__name__}: {e}")


def _maybe_record(context, subdomain: str, uri: str, route: dict,
                  denied, sink: dict) -> None:
    """记不记、记什么。

    **判定用分区键前缀**（`app-`），不用 `owner`/`_is_platform_route()`：
      · `owner` 是权限投影字段，能写权限的角色可控（见 PLATFORM_SUBDOMAINS 上方
        那段长注释否掉的同一种推导）；
      · `mcp` 子域**故意**不在 PLATFORM_SUBDOMAINS 里，用它会把 key-proxy 的
        每次调用记成一个"站点"，还给每次调用加一次跨区写。
    `subdomain` 是路由表分区键、由真实 Host 解析，不可伪造。
    """
    try:
        if not subdomain.startswith("app-"):
            return
        if not _is_page_request(route, uri):
            return
        if denied is None:
            decision = "allow"
        elif str(denied.get("status")) == "403":
            decision = "denied_403"
        else:
            decision = "redirect_login"
        _record_access(context, subdomain[4:], uri, decision,
                       sink.get("email", ""))
    except Exception as e:      # noqa: BLE001
        print(f"[WARN] 埋点判定失败 sub={subdomain}: {type(e).__name__}: {e}")
```

`_check_auth` 增加可选 out-param（**返回类型一个字不改**）：

```python
def _check_auth(request, route, host, sink=None):
    """返回 None=放行（用户头已注入）；返回 dict=302/403 响应。

    `sink` 是**可选的 out-param**：验签成功后把邮箱放进去，供埋点使用
    （403 分支也要有——"谁被拒了"是被拒记录的全部价值）。
    **用 out-param 而不是改成返回二元组**：M4-FINDINGS §3.3——因审查从单值改
    多值的函数，调用方最容易按旧签名继续用。也**不往 request 上挂键**：
    CloudFront 会校验 request 对象的形状。
    """
```

插入位置：**IdP 来源检查通过之后、allowlist 检查之前**（不是"验签成功后立刻"）。
即紧接 `if REQUIRE_IDP_CLAIM:` 那个 `if` 块**之后**、`allowed = route.get(...)`
**之前**：

```python
    # 契约（spec §1.1）：403 有邮箱、302 无邮箱。
    # **位置不能提前到验签成功处**（Codex 审查 2026-08-14 P2-1，已实测）：
    # 验签成功与 IdP 来源可信是两道检查，中间那段返回 302。提前赋值会让一个
    # 签名有效但 idp/auth_via 不可信的会话（linked 本地用户、旧会话）产出
    # `decision=redirect_login` 且 email 非空——实测 status=302、
    # sink={'email': ...}，违反契约且扩大 PII 落盘。
    if sink is not None:
        sink["email"] = claims["email"]
```

`lambda_handler` 接线（**`uri` 必须在 `_route_request` 之前取**——它会把 uri
改写成 S3 key）：

```python
        route = {**route, _PLATFORM_KEY: subdomain in PLATFORM_SUBDOMAINS}
        # **在 _route_request 之前抓 uri**：那个函数会把静态请求的 uri 改写成
        # 桶内 key（f"/{static_prefix}{path}"），埋点要记的是用户看到的路径。
        original_uri = request.get("uri", "/")
        sink: dict = {}
        denied = _check_auth(request, route, original_host, sink)
        result = denied if denied else _route_request(request, route)
        _maybe_record(context, subdomain, original_uri, route, denied, sink)
        return result
```

`test_origin_request.py:11-14` 的替换链尾部补两项：

```python
            .replace("{{JWT_SECRET}}", "test-secret")
            .replace("{{ACCESS_TABLE}}", "site-access-events")
            .replace("{{ACCESS_REPLICA_REGIONS}}",
                     "us-east-1,ap-southeast-1,ap-northeast-1"))
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd router/infrastructure/lambda && \
  ../../../site-builder/deployer/.venv/bin/pytest . -q
```

预期：新文件全绿，且**既有 63 项全部仍绿**（`test_origin_request.py` /
`test_edge_auth.py` 都要因为占位符补齐而继续通过）。

- [ ] **Step 5: 反向验证（三条最关键的守卫）**

```bash
cp router/infrastructure/lambda/origin_request.py /tmp/orq.py.bak
```

① 把 `_access_region` 最后那个"不在副本清单就回落"的判断删掉 → 预期
`test_region_without_a_replica_falls_back_to_primary` 变红。
② 把 `_record_access` 的 `try/except` 去掉 → 预期
`test_a_throwing_write_does_not_change_the_returned_request` 变红。
③ 把 `_maybe_record` 的调用挪到 `_route_request` **之后**并改用
`request.get("uri")` → 预期 `test_written_item_shape` 里 `path` 变成
`/sites/...` 形态（**若不红，说明该断言没盯住 path，补断言**）。
④ 把 `_is_page_request` 里 `if uri.startswith("/api/")` 那两行删掉 → 预期
`test_page_detection_agrees_with_real_routing[/api/data-False]` 变红。
**这一条是 P1-1 的回归闸门**：删之前那个实现全绿。
⑤ 把 sink 赋值挪回 `if REQUIRE_IDP_CLAIM:` **之前** → 预期
`test_untrusted_idp_session_yields_302_without_an_email` 变红。

还原并双证：

```bash
cp /tmp/orq.py.bak router/infrastructure/lambda/origin_request.py
diff -q /tmp/orq.py.bak router/infrastructure/lambda/origin_request.py && \
  cd "$(git rev-parse --show-toplevel)" && git status --short
```

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add router/infrastructure/lambda/origin_request.py \
        router/infrastructure/lambda/test_origin_request.py \
        router/infrastructure/lambda/test_edge_access_log.py
git commit -m "feat(m5): Edge 埋点——鉴权判定之后写一行访问明细

只记页面级请求、只记 app- 前缀的用户站点（分区键前缀不可伪造；不用 owner，
那是可写的权限投影字段，也不用 _is_platform_route——mcp 故意不在那个名单里）。
三种 decision（allow / denied_403 / redirect_login）走同一条记录路径；被拒
记录只可能在 origin-request 拿到，因为 302/403 不触发 origin-response。

身份用可选 out-param 带出，_check_auth 返回类型不变（§3.3），也不往 request
对象挂键（CloudFront 校验它的形状）。uri 在 _route_request 之前抓——那个函数
会把静态请求改写成桶内 key。

超时 1.0/2.0 不给重试：0.3/0.5 已被实测否掉（跨区冷连接首次 719ms → 每个冷
容器首次埋点静默丢行）。预算下限由跨区回落决定，不是由同区 58ms 决定。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: router 栈的 IAM 与占位符注入 + cache policy 断言

**Files:**
- Modify: `router/infrastructure/stack.py`
- Modify: `router/config.ini.example`
- Modify: `router/infrastructure/lambda/test_stack_edge_iam.py`
- 手工: `router/config.ini`（gitignored，加两个键）

**Interfaces:**
- Consumes: Task 3 的两个占位符名；Task 2 的表名。
- Produces: `[SiteBuilder] access_table` / `access_replica_regions` 两个配置键。

- [ ] **Step 1: 写失败的测试**

追加到 `test_stack_edge_iam.py`：

```python
def _ddb_statements(template) -> list[dict]:
    out = []
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            acts = stmt["Action"]
            acts = acts if isinstance(acts, list) else [acts]
            if any(str(a).startswith("dynamodb:") for a in acts):
                out.append(stmt)
    return out


def test_edge_role_may_only_put_items_into_the_access_events_table(template):
    """埋点权限必须恰好是「三个副本 ARN 上的 PutItem」。

    · 漏一个副本 ARN → 那个区的埋点全部 AccessDenied，而 _record_access 会把
      异常吞掉 ⇒ **该区静默零数据**（正是本项目反复栽的失效形状）；
    · 多给 UpdateItem/DeleteItem → 公网组件获得改写访问历史的能力；
    · 资源集合**从副本清单推导**，不手抄——手抄的清单每加一个区就漏一个
      （M4-FINDINGS §3.9）。
    """
    import configparser
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(CONFIG)
    assert cfg.sections(), f"{CONFIG} 读空了——configparser 对缺失文件是静默的"
    table = cfg["SiteBuilder"]["access_table"]
    regions = [r.strip() for r in
               cfg["SiteBuilder"]["access_replica_regions"].split(",") if r.strip()]
    assert len(regions) >= 2, f"副本清单至少要有主区+1: {regions}"

    account = cfg["AWS"]["account_id"].strip()
    puts = [s for s in _ddb_statements(template)
            if "dynamodb:PutItem" in (s["Action"] if isinstance(s["Action"], list)
                                      else [s["Action"]])]
    assert puts, "找不到 Edge role 的 dynamodb:PutItem 语句"
    got = set()
    for s in puts:
        res = s["Resource"]
        for r in (res if isinstance(res, list) else [res]):
            # **必须是字符串**。若是 dict（Fn::Join / Fn::GetAtt）说明实现用了
            # self.account 或 table_arn，那种形态没法逐字比（2026-08-14 实测）
            assert isinstance(r, str), (
                f"Resource 渲染成了 {type(r).__name__} 而不是字符串: {r}"
                "——实现里应该用 config 的账号字面量，不是 self.account")
            got.add(r)
    expected = {f"arn:aws:dynamodb:{rg}:{account}:table/{table}" for rg in regions}
    assert got == expected, (
        f"PutItem 资源集合不对（**逐字比**，漏一个区 = 该区静默零数据）"
        f"\n  实际: {sorted(got)}\n  期望: {sorted(expected)}")


def test_edge_role_has_no_write_actions_beyond_put_item(template):
    """写权限只许 PutItem——UpdateItem/DeleteItem 是"能改写历史"。"""
    forbidden = {"dynamodb:UpdateItem", "dynamodb:DeleteItem",
                 "dynamodb:BatchWriteItem", "dynamodb:*"}
    for s in _ddb_statements(template):
        acts = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        bad = forbidden & set(map(str, acts))
        assert not bad, f"Edge role 拿到了 {sorted(bad)}"


def test_distribution_caching_stays_disabled(template):
    """全站禁缓存是**两件事**的前提，而它此前只有注释、没有任何断言。

    · 鉴权正确性：origin-request 只在 cache miss 执行；
    · 统计完整性（M5 新增）：缓存命中 ⇒ 不执行 ⇒ **静默漏计**。
    两个理由指向同一条配置，所以只加这一个守卫、不加第二处定义。
    CACHING_DISABLED 的托管策略 ID 是 AWS 固定值。
    """
    CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    dists = template.find_resources("AWS::CloudFront::Distribution")
    assert dists, "模板里找不到 CloudFront 分发"
    for d in dists.values():
        beh = d["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]
        assert beh.get("CachePolicyId") == CACHING_DISABLED, (
            f"默认行为的 cache policy 不是 CACHING_DISABLED: {beh.get('CachePolicyId')}"
            "——加缓存会同时破坏鉴权正确性与统计完整性")
```

- [ ] **Step 2: 先加配置键，再跑测试确认失败**

`router/config.ini.example` 的 `[SiteBuilder]` 段追加：

```ini
# M5 访问统计：明细表名与它的 Global Table 副本区清单（**含主区**）。
# 这份清单是唯一真源，三处必须一致：deployer 栈的 TableV2 replicas、
# 本栈给 edge_role 的 PutItem 资源集合、Edge 代码里的 ACCESS_REPLICA_REGIONS。
# 漏一个区 = 那个区的埋点 AccessDenied 后被吞掉 = 该区静默零数据。
access_table = site-access-events
access_replica_regions = us-east-1,ap-southeast-1,ap-northeast-1
```

同样两行手工加进 `router/config.ini`（gitignored，**不要 `git add`**）。

```bash
cd router/infrastructure/lambda && \
  PYTHONPATH="$PWD/../.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  ../../../site-builder/deployer/.venv/bin/pytest test_stack_edge_iam.py -q
```

预期：三条新用例 FAIL（找不到 PutItem 语句 / cache policy 断言可能已经绿——
若已绿，**注入验证时必须证明它会红**，见 Step 5）。

- [ ] **Step 3: 写实现**

`stack.py` 在 `edge_role.add_to_policy(...s3:GetObject...)` 之后插入：

```python
        # M5 埋点：只给明细表的 PutItem，且**每个副本区一条资源**。
        # 副本清单是 config.ini 里的唯一真源（deployer 栈的 TableV2 replicas 与
        # Edge 代码的 ACCESS_REPLICA_REGIONS 用同一份），由
        # test_stack_edge_iam.py 从它推导断言。
        # 只给 PutItem：Edge 是公网请求路径上的组件，只该能"追加一行"，
        # 不该能改写或删除访问历史。
        # **账号取自 config，不用 `self.account`**（Codex 审查 2026-08-14 P2-4）：
        # 实测 `self.account` 在无显式 env 的栈里渲染成
        # {"Fn::Join": ["", ["arn:...:", {"Ref": "AWS::AccountId"}, ":table/..."]]}
        # ——一个 **dict**，模板断言没法按字符串比。用 config 的字面量则渲染成
        # 普通字符串，断言可以逐字比。这也更符合 CLAUDE.md 的「config.ini 是
        # 账号/域名的唯一取值来源」。
        access_account = config.get("AWS", "account_id", "APP_ACCOUNT_ID").strip()
        access_table = config.get("SiteBuilder", "access_table",
                                  "APP_ACCESS_TABLE").strip()
        access_regions = [r.strip() for r in
                          config.get("SiteBuilder", "access_replica_regions",
                                     "APP_ACCESS_REPLICA_REGIONS").split(",")
                          if r.strip()]
        if len(access_regions) < 2:
            raise ValueError(
                f"access_replica_regions 至少要有主区+1 个副本（当前 {access_regions}）"
                "——只有一个区时应该直接去掉副本设计，而不是配一个残缺清单")
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["dynamodb:PutItem"],
            resources=[f"arn:aws:dynamodb:{rg}:{access_account}:table/{access_table}"
                       for rg in access_regions]))
```

`lambda_code` 的替换链补两项（紧跟 `{{TRUSTED_IDPS}}` 之后）：

```python
            .replace("{{ACCESS_TABLE}}", access_table)
            .replace("{{ACCESS_REPLICA_REGIONS}}", ",".join(access_regions)))
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd router/infrastructure/lambda && \
  PYTHONPATH="$PWD/../.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  ../../../site-builder/deployer/.venv/bin/pytest test_stack_edge_iam.py -q
```

预期：全部 PASS（含既有的 S3 前缀那条）。

- [ ] **Step 5: 反向验证（三条各一次，cache policy 那条必须证明会红）**

```bash
cp router/infrastructure/stack.py /tmp/stack.py.bak
```

① 把 `resources=[...]` 里的列表推导改成只取 `access_regions[0]` → 预期
`PutItem 资源集合不对` 并列出缺失项。
② `actions` 加上 `"dynamodb:UpdateItem"` → 预期
`test_edge_role_has_no_write_actions_beyond_put_item` 点名它。
③ 把 `cache_policy=cloudfront.CachePolicy.CACHING_DISABLED` 改成
`CACHING_OPTIMIZED` → 预期 `test_distribution_caching_stays_disabled` 变红。
**这一条是新守卫的全部价值**：改之前这个改动不会被任何测试拦住。

还原并双证：

```bash
cp /tmp/stack.py.bak router/infrastructure/stack.py
diff -q /tmp/stack.py.bak router/infrastructure/stack.py && \
  cd "$(git rev-parse --show-toplevel)" && git status --short
```

预期 `git status` 只有 `stack.py`、`config.ini.example`、`test_stack_edge_iam.py`
——**`router/config.ini` 不得出现**（gitignored）。

- [ ] **Step 5b: 顺手修仓库自己写错的 venv 路径**

`test_stack_edge_iam.py` 的 docstring 写 `python3.13`，而实际目录是
`python3.12`（2026-08-14 实测 `ls router/infrastructure/.venv/lib/`）。
照抄那条命令会得到"aws_cdk 不可用"并按该文件的设计**fail 而不是 skip**——
不致命但会浪费下一个人的时间。改成 3.12，并保留原有的"按实际 venv 调整"提示。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add router/infrastructure/stack.py router/config.ini.example \
        router/infrastructure/lambda/test_stack_edge_iam.py
git commit -m "feat(m5): edge_role 的 PutItem（三个副本 ARN，从清单推导）+ 缓存策略的第一条断言

副本清单在 config.ini 里是唯一真源，三处引用它：deployer 的 TableV2 replicas、
本栈的 IAM 资源集合、Edge 的 ACCESS_REPLICA_REGIONS。断言从清单推导而不是
手抄——手抄的清单每加一个区就漏一个（§3.9），而漏一个区的症状是该区静默零
数据（埋点异常被吞掉）。

顺带补上 CACHING_DISABLED 的第一条断言：它此前只有注释。M5 之后禁缓存同时是
鉴权正确性与统计完整性的前提（缓存命中 = origin-request 不执行 = 静默漏计），
两个理由指向同一条配置，所以只加守卫、不加第二处定义。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: rollup 聚合逻辑

**Files:**
- Create: `site-builder/deployer/functions/access_rollup.py`
- Create: `site-builder/deployer/tests/test_access_rollup.py`

**Interfaces:**
- Consumes: Task 2 的两张表与键名。
- Produces: `handler(event, context) -> dict`、`rollup_day(site_id, day) -> dict | None`、
  `day_stats(rows) -> dict`（返回 `{"pv","uv","pv_denied"}`）、常量 `LOOKBACK_DAYS = 7`、`TTL_DAYS = 400`。
  Task 8 的 `analytics.py` 复用 `day_stats` 的**同一份**语义（通过 import 而非重写）。

- [ ] **Step 1: 写失败的测试**

新建 `site-builder/deployer/tests/test_access_rollup.py`：

```python
"""rollup 单测。用 moto 建两张表。

**moto 不校验 IAM**——本文件全绿不代表线上角色有对应权限；IAM 由 Task 6 的
CDK 断言 + Task 13 的真机闸门各自盯（M4 踩过：事务里的 ConditionCheck 漏给
权限时单测全绿、真机 500）。
"""
import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

EVENTS = "site-access-events"
DAILY = "site-access-daily"


@pytest.fixture
def tables(monkeypatch):
    monkeypatch.setenv("ACCESS_EVENTS_TABLE", EVENTS)
    monkeypatch.setenv("ACCESS_DAILY_TABLE", DAILY)
    monkeypatch.setenv("SITES_TABLE", "site-sites")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        d = boto3.client("dynamodb", region_name="us-east-1")
        d.create_table(TableName=EVENTS,
                       KeySchema=[{"AttributeName": "site_date", "KeyType": "HASH"},
                                  {"AttributeName": "ts_id", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_date", "AttributeType": "S"},
                           {"AttributeName": "ts_id", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        d.create_table(TableName=DAILY,
                       KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"},
                                  {"AttributeName": "date", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_id", "AttributeType": "S"},
                           {"AttributeName": "date", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        d.create_table(TableName="site-sites",
                       KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_id", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        yield d


def _ev(d, site, day, email, decision="allow", i=0):
    d.put_item(TableName=EVENTS, Item={
        "site_date": {"S": f"{site}#{day}"},
        "ts_id": {"S": f"{day}T00:00:0{i}+00:00#aa{i:02d}"},
        "site_id": {"S": site}, "email": {"S": email},
        "path": {"S": "/"}, "decision": {"S": decision},
        "expires_at": {"N": "9999999999"}})


def test_pv_counts_rows_and_uv_counts_distinct_emails(tables):
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=0)
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=1)
    _ev(tables, "s1", "2026-08-10", "b@x.co", i=2)
    out = ar.rollup_day("s1", "2026-08-10")
    assert out == {"pv": 3, "uv": 2, "pv_denied": 0}


def test_denied_rows_do_not_enter_pv_or_uv(tables):
    """被拒不进 PV 曲线，但要可查。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co", i=0)
    _ev(tables, "s1", "2026-08-10", "out@x.co", decision="denied_403", i=1)
    _ev(tables, "s1", "2026-08-10", "", decision="redirect_login", i=2)
    assert ar.rollup_day("s1", "2026-08-10") == {"pv": 1, "uv": 1, "pv_denied": 2}


def test_empty_email_is_not_a_unique_visitor(tables):
    """公开站点/未登录的空串不能算成一个访客。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "", i=0)
    _ev(tables, "s1", "2026-08-10", "", i=1)
    assert ar.rollup_day("s1", "2026-08-10") == {"pv": 2, "uv": 0, "pv_denied": 0}


def test_no_rows_writes_no_aggregate_row(tables):
    """23 个 DELETED 站点不该每天各得一行 0。"""
    import access_rollup as ar
    assert ar.rollup_day("gone", "2026-08-10") is None
    got = tables.query(TableName=DAILY,
                       KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "gone"}})
    assert got["Count"] == 0


def test_rerun_is_idempotent(tables):
    """覆盖写 ⇒ 连续几天失败无需人工补跑。"""
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY,
                       KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    assert got["Count"] == 1
    assert got["Items"][0]["pv"]["N"] == "1"


def test_today_is_never_sealed(tables):
    """今天的数由读路径实时算；封口今天会把半天的数字固化成"全天"。"""
    import access_rollup as ar
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert today not in ar.target_days()
    assert len(ar.target_days()) == ar.LOOKBACK_DAYS
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    assert yesterday in ar.target_days()


def test_aggregate_row_carries_a_400_day_ttl(tables):
    import access_rollup as ar
    _ev(tables, "s1", "2026-08-10", "a@x.co")
    ar.handler({"days": ["2026-08-10"], "sites": ["s1"]}, None)
    got = tables.query(TableName=DAILY, KeyConditionExpression="site_id = :s",
                       ExpressionAttributeValues={":s": {"S": "s1"}})
    ttl = int(got["Items"][0]["expires_at"]["N"])
    now = int(datetime.now(timezone.utc).timestamp())
    assert 399 * 86400 < ttl - now <= 401 * 86400, "TTL 不是 400 天"


def test_sites_are_enumerated_from_the_sites_table(tables):
    """DynamoDB 无法枚举分区键，所以 site_id 只能来自 sites 表。"""
    import access_rollup as ar
    tables.put_item(TableName="site-sites",
                    Item={"site_id": {"S": "s1"}, "status": {"S": "ACTIVE"}})
    tables.put_item(TableName="site-sites",
                    Item={"site_id": {"S": "s2"}, "status": {"S": "DELETED"}})
    # DELETED 也要枚举——它的历史趋势仍该被聚合；无行时自然不写（上面那条）
    assert set(ar.all_site_ids()) == {"s1", "s2"}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && \
  PYTHONPATH=functions .venv/bin/pytest tests/test_access_rollup.py -q
```

预期：`ModuleNotFoundError: access_rollup`。

- [ ] **Step 3: 写实现**

新建 `site-builder/deployer/functions/access_rollup.py`：

```python
"""M5 每日聚合：把明细行封口成 site-access-daily 的一行。

**幂等靠覆盖写，不靠水位线**：真源是耐久的明细行（90 天 TTL），每轮重算过去
LOOKBACK_DAYS 个完整日并 PutItem 覆盖。所以 rollup 坏 89 天，重跑即全部恢复
——这正是 spec §0.1 用来否掉"日志侧聚合"的那条差别（那边的真源是会过期的
日志，聚合器坏一个月即永久丢数）。

**只封口完整的 UTC 日**：今天的数由读路径实时算（panel/analytics.py）。
封口今天会把半天的数字固化成"全天"。
"""
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

LOOKBACK_DAYS = 7      # 一轮失败无需人工补跑的余量
TTL_DAYS = 400         # 与 ops_log.TTL_DAYS 对齐（13 个月，够看同月同比）

_ddb = None


def _client():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def target_days() -> list[str]:
    """要封口的日期：过去 LOOKBACK_DAYS 个**完整**日，不含今天。"""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=n)).isoformat()
            for n in range(1, LOOKBACK_DAYS + 1)]


def all_site_ids() -> list[str]:
    """DynamoDB 无法枚举分区键，所以站点清单只能来自 sites 表。

    **DELETED 也要枚举**：下线站点的历史趋势仍该被聚合（它只是不再产生新行，
    于是 rollup_day 返回 None 而不写）。
    """
    table = os.environ["SITES_TABLE"]
    out, kwargs = [], {"TableName": table, "ProjectionExpression": "site_id"}
    while True:
        resp = _client().scan(**kwargs)
        out.extend(i["site_id"]["S"] for i in resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return out
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def day_stats(rows: list[dict]) -> dict:
    """一天的明细行 → {pv, uv, pv_denied}。

    **唯一定义**：panel 的读取层 import 本函数算"今天"，不另写一份
    （两处算法漂移的症状是"面板今天的数与历史曲线口径不同"，没人会立刻发现）。

    · pv/uv 只数 allow——被拒不进 PV 曲线；
    · 空 email 不是一个访客（公开站点与未登录被拒都是空串），写哨兵值会污染
      distinct 计数，所以明细那边存的就是空串。
    """
    pv = uv = 0
    visitors, denied = set(), 0
    for r in rows:
        if r.get("decision", {}).get("S") != "allow":
            denied += 1
            continue
        pv += 1
        email = r.get("email", {}).get("S", "")
        if email:
            visitors.add(email)
    uv = len(visitors)
    return {"pv": pv, "uv": uv, "pv_denied": denied}


def _query_day(site_id: str, day: str) -> list[dict]:
    rows, kwargs = [], {
        "TableName": os.environ["ACCESS_EVENTS_TABLE"],
        "KeyConditionExpression": "site_date = :sd",
        "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
        "ProjectionExpression": "email, decision"}
    while True:
        resp = _client().query(**kwargs)
        rows.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def rollup_day(site_id: str, day: str) -> dict | None:
    """封口一天。**无明细行则返回 None 且不写**——否则 23 个 DELETED 站点
    会每天各得一行 0。"""
    rows = _query_day(site_id, day)
    if not rows:
        return None
    stats = day_stats(rows)
    _client().put_item(
        TableName=os.environ["ACCESS_DAILY_TABLE"],
        Item={"site_id": {"S": site_id}, "date": {"S": day},
              "pv": {"N": str(stats["pv"])}, "uv": {"N": str(stats["uv"])},
              "pv_denied": {"N": str(stats["pv_denied"])},
              "expires_at": {"N": str(int(time.time()) + TTL_DAYS * 86400)}})
    return stats


def handler(event, context) -> dict:
    """EventBridge 每日触发。`event` 里可给 `days` / `sites` 覆盖（供闸门定向重算）。"""
    days = (event or {}).get("days") or target_days()
    sites = (event or {}).get("sites") or all_site_ids()
    written = 0
    for site_id in sites:
        for day in days:
            if rollup_day(site_id, day) is not None:
                written += 1
    logger.info("rollup 完成 sites=%d days=%d 写入=%d",
                len(sites), len(days), written)
    return {"sites": len(sites), "days": len(days), "written": written}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/deployer && \
  PYTHONPATH=functions .venv/bin/pytest tests/test_access_rollup.py -q && \
  .venv/bin/pytest tests -q
```

预期：新文件全绿 + deployer 既有 400 项仍绿。

- [ ] **Step 5: 反向验证**

```bash
cp site-builder/deployer/functions/access_rollup.py /tmp/ar.py.bak
```

① `rollup_day` 的 `if not rows: return None` 删掉 → 预期
`test_no_rows_writes_no_aggregate_row` 变红。
② `day_stats` 里把空 email 也加进 `visitors` → 预期
`test_empty_email_is_not_a_unique_visitor` 变红。
③ `target_days()` 的 `range(1, ...)` 改成 `range(0, ...)` → 预期
`test_today_is_never_sealed` 变红。

还原并双证（同前形态，用 `/tmp/ar.py.bak`）。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/functions/access_rollup.py \
        site-builder/deployer/tests/test_access_rollup.py
git commit -m "feat(m5): 每日聚合——幂等覆盖写 + 7 天回溯，不用水位线

真源是耐久明细行，所以每轮重算过去 7 个完整日并覆盖写即可：rollup 坏 89 天
重跑就全恢复。这正是 spec §0.1 用来否掉日志侧聚合的那条差别（那边真源会过期，
聚合器坏一个月即永久丢数）。

只封口完整 UTC 日（今天由读路径实时算）；无明细行不写聚合行（否则 23 个
DELETED 站点每天各得一行 0）；空 email 不算访客——公开站点与未登录被拒都是
空串，存哨兵值会污染 distinct 计数。day_stats 是 pv/uv 口径的唯一定义，
panel 读取层 import 它而不是另写一份。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: rollup 的 CDK 接线（Lambda + EventBridge + 最小 IAM）

**Files:**
- Modify: `site-builder/deployer/infra/app.py`
- Test: `site-builder/deployer/tests/test_infra_tables.py`

**Interfaces:**
- Consumes: Task 2 的两张表对象（`access_events` / `access_daily`）、Task 5 的
  `access_rollup.handler`、既有的 `dlq` 与 `fn_dir`。
- Produces: Lambda `site-access-rollup`、EventBridge rule `site-access-rollup-daily`。

- [ ] **Step 1: 写失败的测试**

追加到 `test_infra_tables.py`：

```python
def test_rollup_role_can_only_query_events_and_put_daily(template):
    """rollup 是唯一能写聚合表的身份，且对明细表只读。

    给它 PutItem 到明细表 = 聚合器能伪造访问历史；给它 Scan 明细表 = 不必要的
    全表能力（它只按分区 Query）。
    """
    # **不能按 "site-access" 字面量筛策略**（Codex 审查 2026-08-14 P2-4）：
    # `table_arn` 渲染成 {"Fn::GetAtt": ["AccessEvents832F10D1", "Arn"]}（实测），
    # policy 文本里根本没有表名字面量，那样筛会把目标策略全筛掉 → 用例空转。
    # 改成按**逻辑 ID** 对应：先从模板里查出两张表的逻辑 ID，再看语句引用了谁。
    def _logical_id(res_type: str, table_name: str) -> str:
        for lid, res in template.find_resources(res_type).items():
            if res["Properties"].get("TableName") == table_name:
                return lid
        raise AssertionError(f"模板里找不到 {table_name}")

    ev_lid = _logical_id("AWS::DynamoDB::GlobalTable", "site-access-events")
    da_lid = _logical_id("AWS::DynamoDB::Table", "site-access-daily")

    def _refs(resource) -> set[str]:
        """语句 Resource 里引用到的逻辑 ID 集合（Fn::GetAtt / Ref 都算）。"""
        out = set()
        for r in (resource if isinstance(resource, list) else [resource]):
            if isinstance(r, dict):
                for k, v in r.items():
                    if k in ("Fn::GetAtt", "Ref"):
                        out.add(v[0] if isinstance(v, list) else v)
        return out

    events_actions, daily_actions = set(), set()
    for pol in template.find_resources("AWS::IAM::Policy").values():
        for st in pol["Properties"]["PolicyDocument"]["Statement"]:
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            acts = {str(a) for a in acts if str(a).startswith("dynamodb:")}
            if not acts:
                continue
            refs = _refs(st["Resource"])
            if ev_lid in refs:
                events_actions |= acts
            if da_lid in refs:
                daily_actions |= acts
    # **两个都要非空**，否则本用例在筛不到语句时会静默通过（上一版就是这样）
    assert events_actions, "没有任何语句引用明细表——筛选逻辑坏了，本条空转"
    assert daily_actions, "没有任何语句引用聚合表——筛选逻辑坏了，本条空转"
    assert events_actions == {"dynamodb:Query"}, (
        f"明细表的动作集合必须恰好是 Query（给 PutItem = 聚合器能伪造历史）: "
        f"{sorted(events_actions)}")
    assert daily_actions == {"dynamodb:PutItem"}, (
        f"聚合表的动作集合不对: {sorted(daily_actions)}")


def test_rollup_runs_daily_and_has_a_dlq(template):
    rules = template.find_resources("AWS::Events::Rule")
    hit = [r for r in rules.values()
           if r["Properties"].get("Name") == "site-access-rollup-daily"]
    assert len(hit) == 1, f"找不到 site-access-rollup-daily：{list(rules)}"
    props = hit[0]["Properties"]
    assert props["ScheduleExpression"] == "cron(20 0 * * ? *)", props["ScheduleExpression"]
    assert props["State"] == "ENABLED"
    target = props["Targets"][0]
    assert "DeadLetterConfig" in target, "rollup 的 target 没有 DLQ"
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && \
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q -k rollup
```

预期：两条 FAIL。

- [ ] **Step 3: 写实现**

`app.py` 在 `dlq` 定义之后、`events.Rule(... TerminalStatusRule ...)` 之前插入：

```python
        # M5 每日聚合。**独立角色**：它是唯一能写聚合表的身份，而对明细表只读。
        # 给它明细表的 PutItem 就等于让聚合器能伪造访问历史；给它 Scan 也不必要
        # （只按分区 Query）。sites 表只读（枚举 site_id，DynamoDB 无法枚举分区键）。
        rollup_role = iam.Role(
            self, "AccessRollupRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Query"], resources=[access_events.table_arn]))
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem"], resources=[access_daily.table_arn]))
        rollup_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:Scan"], resources=[sites.table_arn]))

        f_rollup = lam_.Function(
            self, "FnAccessRollup", function_name="site-access-rollup",
            runtime=lam_.Runtime.PYTHON_3_13,
            handler="access_rollup.handler",
            code=lam_.Code.from_asset(fn_dir),
            role=rollup_role, timeout=Duration.seconds(300), memory_size=256,
            environment={"ACCESS_EVENTS_TABLE": access_events.table_name,
                         "ACCESS_DAILY_TABLE": access_daily.table_name,
                         "SITES_TABLE": sites.table_name})

        # 每天 00:20 UTC。**只封口完整日**，所以不需要更高频率；一轮失败由
        # 下一轮的 7 天回溯窗口自动补上（access_rollup.LOOKBACK_DAYS）。
        events.Rule(
            self, "AccessRollupRule", rule_name="site-access-rollup-daily",
            schedule=events.Schedule.cron(minute="20", hour="0"),
            targets=[targets.LambdaFunction(
                f_rollup, dead_letter_queue=dlq, retry_attempts=2)])
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/deployer && \
  PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```

- [ ] **Step 5: 反向验证**

把 `rollup_role` 的第二条 policy 的 `resources` 从 `access_daily.table_arn`
改成 `access_events.table_arn` → 预期
`test_rollup_role_can_only_query_events_and_put_daily` 报聚合表动作集合为空。
还原 + 双证（`/tmp/app.py.bak2`）。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/infra/app.py site-builder/deployer/tests/test_infra_tables.py
git commit -m "feat(m5): rollup Lambda + 每日 EventBridge 规则（照 JobSweepRule 形态）

独立角色，最小权限：明细表只 Query、聚合表只 PutItem、sites 表只 Scan。
给聚合器明细表的 PutItem 就等于让它能伪造访问历史。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `CAPABILITIES` 加 `view_analytics`

**Files:**
- Modify: `site-builder/deployer/functions/permissions.py:23-30`
- Test: `site-builder/deployer/tests/`（既有权限测试文件，追加）

**Interfaces:**
- Produces: 动作名 `"view_analytics"`，角色集合 `{owner, collaborator, admin}`。Task 8/10 用它。

- [ ] **Step 1: 写失败的测试**

追加到 `site-builder/deployer/tests/test_permissions.py`（若文件名不同，加到
现有权限测试文件）：

```python
def test_view_analytics_is_a_registered_action_for_the_three_roles():
    """访问明细含**其他访问者的邮箱**，是与站点元数据不同的敏感度等级。

    单独一个动作名（而不是复用 read）让"以后要收紧成只有 owner+admin"变成改
    一个字典项，且不牵动其它读路径。
    """
    from permissions import (CAPABILITIES, ROLE_ADMIN, ROLE_COLLABORATOR,
                             ROLE_NONE, ROLE_OWNER, can)
    assert CAPABILITIES["view_analytics"] == {
        ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN}
    assert can(ROLE_OWNER, "view_analytics")
    assert can(ROLE_COLLABORATOR, "view_analytics")
    assert can(ROLE_ADMIN, "view_analytics")
    assert not can(ROLE_NONE, "view_analytics")


def test_unregistered_analytics_typo_is_denied_to_everyone():
    """未登记动作对所有人拒绝（fail-closed）——拼错动作名不会变成放行。"""
    from permissions import ROLE_OWNER, can
    assert not can(ROLE_OWNER, "view_analytic")
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && \
  .venv/bin/pytest tests -q -k analytics
```

预期：`KeyError: 'view_analytics'`。

- [ ] **Step 3: 写实现**

`permissions.py` 的 `CAPABILITIES` 加一项：

```python
    "undeploy": {ROLE_OWNER, ROLE_ADMIN},
    # M5：看访问统计与访问明细。**不复用 read**——明细含其他访问者的邮箱，
    # 是另一个敏感度等级。单独动作名让"收紧成只有 owner+admin"是改一个字典项。
    "view_analytics": {ROLE_OWNER, ROLE_COLLABORATOR, ROLE_ADMIN},
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/deployer && .venv/bin/pytest tests -q
```

- [ ] **Step 5: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/functions/permissions.py site-builder/deployer/tests/
git commit -m "feat(m5): CAPABILITIES 加 view_analytics（owner/collaborator/admin）

不复用 read：访问明细含其他访问者的邮箱，属另一个敏感度等级。面板与 MCP
共用这一处判定。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: panel 的读取层与两个 GET 端点

**Files:**
- Create: `site-builder/deployer/functions/analytics.py`
- Create: `site-builder/deployer/tests/test_analytics.py`（读取层）
- Create: `site-builder/panel/tests/test_analytics_api.py`（端点层）
- Modify: `site-builder/panel/api.py`
- Modify: `site-builder/panel/handler.py:45-74`（ROUTES + 常量）与 `_dispatch`

**Interfaces:**
- Consumes: Task 5 的 `access_rollup.day_stats`（**import，不重写**）、Task 7 的 `view_analytics`。
- Produces: `analytics.series(site_id, period, n) -> list[dict]`（每项
  `{"bucket","pv","uv","pv_denied","uv_exact"}`）、
  `analytics.visitors(site_id, days, limit, cursor) -> dict`（`{"rows":[...], "next": str|None}`）；
  panel 路由 `GET /api/sites/{site_id}/analytics`、`GET /api/sites/{site_id}/visitors`。
  Task 9 的前端与 Task 10 的 MCP 按这两个形态取值。

- [ ] **Step 1: 写失败的测试**

新建 `site-builder/deployer/tests/test_analytics.py`（读取层）与
`site-builder/panel/tests/test_analytics_api.py`（端点层，即下面「端点层：授权」那两条）：

```python
"""panel 读取层单测。

`uv_exact` 是**契约的一部分**，不是可选字段：周/月 UV 只在区间完整落在 90 天
明细窗口内才精确（日 UV 永远精确，聚合行里就存着）。不显示一个站不住的数字。
"""
import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

EVENTS, DAILY = "site-access-events", "site-access-daily"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ACCESS_EVENTS_TABLE", EVENTS)
    monkeypatch.setenv("ACCESS_DAILY_TABLE", DAILY)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        d = boto3.client("dynamodb", region_name="us-east-1")
        d.create_table(TableName=EVENTS,
                       KeySchema=[{"AttributeName": "site_date", "KeyType": "HASH"},
                                  {"AttributeName": "ts_id", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_date", "AttributeType": "S"},
                           {"AttributeName": "ts_id", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        d.create_table(TableName=DAILY,
                       KeySchema=[{"AttributeName": "site_id", "KeyType": "HASH"},
                                  {"AttributeName": "date", "KeyType": "RANGE"}],
                       AttributeDefinitions=[
                           {"AttributeName": "site_id", "AttributeType": "S"},
                           {"AttributeName": "date", "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")
        yield d


def _daily(d, site, day, pv, uv, denied=0):
    d.put_item(TableName=DAILY, Item={
        "site_id": {"S": site}, "date": {"S": day},
        "pv": {"N": str(pv)}, "uv": {"N": str(uv)},
        "pv_denied": {"N": str(denied)}, "expires_at": {"N": "9999999999"}})


def _event(d, site, day, email, decision="allow", i=0, path="/"):
    d.put_item(TableName=EVENTS, Item={
        "site_date": {"S": f"{site}#{day}"},
        "ts_id": {"S": f"{day}T01:02:0{i}+00:00#bb{i:02d}"},
        "site_id": {"S": site}, "email": {"S": email},
        "path": {"S": path}, "decision": {"S": decision},
        "expires_at": {"N": "9999999999"}})


def test_daily_series_reads_the_aggregate_table(env):
    import analytics
    y = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    _daily(env, "s1", y, pv=5, uv=2, denied=1)
    out = {b["bucket"]: b for b in analytics.series("s1", "day", 3)}
    assert out[y]["pv"] == 5 and out[y]["uv"] == 2 and out[y]["pv_denied"] == 1
    assert out[y]["uv_exact"] is True, "日 UV 永远精确"


def test_today_is_computed_live_from_details(env):
    """今天还没被封口，必须从明细实时算——否则今天永远显示 0。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _event(env, "s1", today, "a@x.co", i=0)
    _event(env, "s1", today, "a@x.co", i=1)
    _event(env, "s1", today, "b@x.co", i=2)
    out = {b["bucket"]: b for b in analytics.series("s1", "day", 1)}
    assert out[today]["pv"] == 3 and out[today]["uv"] == 2


def test_day_series_uses_the_same_stats_definition_as_rollup():
    """口径唯一：读取层 import rollup 的 day_stats，不另写一份。"""
    import analytics
    import access_rollup
    assert analytics.day_stats is access_rollup.day_stats


def test_month_uv_is_null_and_flagged_outside_the_detail_window(env):
    """超出 90 天明细窗口的月份：PV 可加总，UV 给 null + uv_exact=False。"""
    import analytics
    old = (datetime.now(timezone.utc) - timedelta(days=200))
    _daily(env, "s1", old.strftime("%Y-%m-%d"), pv=9, uv=3)
    buckets = {b["bucket"]: b for b in analytics.series("s1", "month", 8)}
    b = buckets[old.strftime("%Y-%m")]
    assert b["pv"] == 9
    assert b["uv"] is None and b["uv_exact"] is False


def test_month_uv_is_exact_inside_the_detail_window(env):
    """正对照：窗口内的月份必须给出精确 UV（跨天去重，不是日 UV 相加）。"""
    import analytics
    now = datetime.now(timezone.utc)
    d1 = (now - timedelta(days=2)).strftime("%Y-%m-%d")
    d2 = (now - timedelta(days=3)).strftime("%Y-%m-%d")
    if d1[:7] != d2[:7]:
        pytest.skip("跨月边界，本条不适用")     # 每月仅约 1/15 的日子会跳过
    _event(env, "s1", d1, "a@x.co", i=0)
    _event(env, "s1", d2, "a@x.co", i=1)
    _daily(env, "s1", d1, pv=1, uv=1)
    _daily(env, "s1", d2, pv=1, uv=1)
    b = {x["bucket"]: x for x in analytics.series("s1", "month", 2)}[d1[:7]]
    assert b["pv"] == 2
    assert b["uv"] == 1, "同一个人跨两天被算成了两个访客（日 UV 不能相加）"
    assert b["uv_exact"] is True


@pytest.mark.parametrize("period,n", [("day", 7), ("week", 1), ("week", 4),
                                      ("month", 1), ("month", 2), ("month", 3)])
def test_series_returns_exactly_n_calendar_aligned_buckets(env, period, n):
    """P2-2 的回归：n 是桶数。上一版用 n×7 / n×31 天回溯，**五种参数全错**
    （month n=1 给 2 个、n=2 给 3 个、week n=4 给 5 个）。"""
    import analytics
    out = analytics.series("s1", period, n)
    assert len(out) == n, f"{period} n={n} 给了 {len(out)} 个桶: {[b['bucket'] for b in out]}"
    keys = [b["bucket"] for b in out]
    assert keys == sorted(keys), "桶没有升序"
    assert len(set(keys)) == n, f"桶键重复: {keys}"


def test_last_bucket_is_the_current_in_progress_one(env):
    """最后一个桶必然是"至今"的当前桶——这是契约，前端据此不给它画完整周期。"""
    import analytics
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).date()
    assert analytics.series("s1", "month", 3)[-1]["bucket"] == today.strftime("%Y-%m")
    assert analytics.series("s1", "day", 3)[-1]["bucket"] == today.isoformat()


def test_visitors_returns_rows_with_decision_and_paginates(env):
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for i in range(3):
        _event(env, "s1", today, f"u{i}@x.co", i=i, path=f"/p{i}")
    page = analytics.visitors("s1", days=1, limit=2, cursor=None)
    assert len(page["rows"]) == 2 and page["next"]
    assert set(page["rows"][0]) == {"ts", "email", "path", "decision"}
    page2 = analytics.visitors("s1", days=1, limit=2, cursor=page["next"])
    assert len(page2["rows"]) == 1 and page2["next"] is None


def test_visitors_includes_denied_attempts(env):
    """被拒记录是本轮明确要的能力。"""
    import analytics
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _event(env, "s1", today, "out@x.co", decision="denied_403", i=0)
    rows = analytics.visitors("s1", days=1, limit=10, cursor=None)["rows"]
    assert [r["decision"] for r in rows] == ["denied_403"]


@pytest.mark.parametrize("days,limit", [(91, 10), (1, 101), (0, 10), (1, 0)])
def test_visitors_rejects_out_of_range_parameters(env, days, limit):
    """days ≤ 90（= 明细留存），limit ≤ 100。越界报 ValueError → 400。"""
    import analytics
    with pytest.raises(ValueError):
        analytics.visitors("s1", days=days, limit=limit, cursor=None)


# ── 端点层：授权 ─────────────────────────────────────────────────

def test_endpoints_require_view_analytics(monkeypatch, env):
    """无权者必须 403，且走 CAPABILITIES 的判定，不在 api.py 另写角色子句。"""
    import api
    import permissions
    monkeypatch.setattr("common.get_site_consistent",
                        lambda sid: {"site_id": sid, "owner": "other@x.co",
                                     "collaborators": []})
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    with pytest.raises(permissions.PermissionDenied):
        api.do_get_analytics("nobody@x.co", "s1", period="day", n=7)
    with pytest.raises(permissions.PermissionDenied):
        api.do_get_visitors("nobody@x.co", "s1", days=7, limit=10, cursor=None)


def test_owner_may_read_both_endpoints(monkeypatch, env):
    """正对照：不能只验"拒"——头压根没到达也会让负测全绿（§3.5）。"""
    import api
    import permissions
    monkeypatch.setattr("common.get_site_consistent",
                        lambda sid: {"site_id": sid, "owner": "me@x.co",
                                     "collaborators": []})
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    assert "series" in api.do_get_analytics("me@x.co", "s1", period="day", n=7)
    assert "rows" in api.do_get_visitors("me@x.co", "s1", days=7, limit=10,
                                         cursor=None)
```

追加到 `site-builder/panel/tests/test_handler.py`：

```python
def test_analytics_routes_are_registered_and_read_only():
    """两个新端点必须是 GET（写路径才需要 CSRF + 面板会话）。"""
    import handler
    pats = {(m, rx.pattern) for m, rx in handler.ROUTES}
    assert ("GET", r"^/api/sites/(?P<site_id>[a-z][a-z0-9-]{1,63})/analytics$") in pats
    assert ("GET", r"^/api/sites/(?P<site_id>[a-z][a-z0-9-]{1,63})/visitors$") in pats


def test_every_route_still_has_a_dispatch_branch():
    """加了 ROUTES 忘了加分发 = 500。这条盯着两个新端点。"""
    import handler
    for m, rx in handler.ROUTES:
        if rx.pattern == handler.CALLBACK:
            continue
        try:
            handler._dispatch(rx.pattern, m, "me@x.co", "me", "s1", {}, {})
        except RuntimeError as e:
            assert "路由已匹配但未分发" not in str(e), f"{m} {rx.pattern} 没有分发分支"
        except Exception:
            pass          # 其它异常（权限/表不存在）说明分支存在，本条不关心
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && PYTHONPATH=functions .venv/bin/pytest tests/test_analytics.py -q
cd site-builder/panel && ../deployer/.venv/bin/pytest tests/test_analytics_api.py -q
```

预期：`ModuleNotFoundError: analytics`。

- [ ] **Step 3: 写实现**

新建 `site-builder/deployer/functions/analytics.py`：

```python
"""访问统计的**唯一**读取层，panel 与 MCP 共用（api.py / server.py 都不出现表名）。

**位置是 `deployer/functions/` 不是 `panel/`**：那是共享模块的既有位置，也是
MCP 传递闭包守卫唯一会扫的目录——放在 panel 下会让守卫静默放过，而容器里
`import analytics` 直接 ModuleNotFoundError（Codex 审查 2026-08-14 P1-2）。

两条契约要点：
  · 今天的数从明细实时算，`date < today` 读聚合表——今天实时、历史耐久；
  · **PV 可相加，UV 不能**。日 UV 永远精确（聚合行里存着，活 400 天）；
    周/月 UV 只在区间**完整落在 90 天明细窗口内**时精确，否则 `uv=None` +
    `uv_exact=False`，由前端显式标注"超出明细留存窗口"。
    不显示一个站不住的数字。
"""
import base64
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone

import boto3

# 口径唯一：pv/uv 的定义只有 access_rollup.day_stats 一份。
# 同目录，所以 panel 的 COPY_FILES 与 MCP 的三份清单都要带上这两个文件。
from access_rollup import day_stats

logger = logging.getLogger(__name__)

DETAIL_DAYS = 90        # = 明细表 TTL，UV 精确窗口的上界
MAX_VISITOR_DAYS = 90
MAX_VISITOR_LIMIT = 100
_ddb = None


def _client():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _day_rows(site_id: str, day: str) -> list[dict]:
    rows, kwargs = [], {
        "TableName": os.environ["ACCESS_EVENTS_TABLE"],
        "KeyConditionExpression": "site_date = :sd",
        "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
        "ProjectionExpression": "email, decision"}
    while True:
        resp = _client().query(**kwargs)
        rows.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _daily_rows(site_id: str, since: str) -> dict:
    out, kwargs = {}, {
        "TableName": os.environ["ACCESS_DAILY_TABLE"],
        "KeyConditionExpression": "site_id = :s AND #d >= :since",
        "ExpressionAttributeNames": {"#d": "date"},
        "ExpressionAttributeValues": {":s": {"S": site_id}, ":since": {"S": since}}}
    while True:
        resp = _client().query(**kwargs)
        for it in resp.get("Items", []):
            out[it["date"]["S"]] = {
                "pv": int(it.get("pv", {}).get("N", 0)),
                "uv": int(it.get("uv", {}).get("N", 0)),
                "pv_denied": int(it.get("pv_denied", {}).get("N", 0))}
        if "LastEvaluatedKey" not in resp:
            return out
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _bucket_of(day: str, period: str) -> str:
    if period == "day":
        return day
    if period == "month":
        return day[:7]
    d = datetime.strptime(day, "%Y-%m-%d").date()
    year, week, _ = d.isocalendar()
    return f"{year}-W{week:02d}"


def _bucket_keys(period: str, n: int, today: date) -> list[str]:
    """最近 n 个**日历桶**的键，升序，长度恒为 n。

    **不能用 `n×7` / `n×31` 天回溯再分桶**（Codex 审查 2026-08-14 P2-2，
    已实测）：那样会返回 **n+1 个残缺桶**——固定 2026-08-14：`month n=1` 得
    `['2026-07','2026-08']`、`n=2` 得 3 个、`week n=4` 得 5 个，**五种参数全错**，
    而边界桶只是部分区间却没有任何标注，用户会当成完整周/月读。
    这里从**当前桶**往回数 n 个，最后一个桶必然是进行中的当前桶
    （"本月至今"），这是统计产品的通行语义。
    """
    if period == "day":
        return [(today - timedelta(days=i)).isoformat()
                for i in range(n - 1, -1, -1)][:n]
    if period == "week":
        monday = today - timedelta(days=today.weekday())
        out = []
        for i in range(n - 1, -1, -1):
            d = monday - timedelta(weeks=i)
            y, w, _ = d.isocalendar()
            out.append(f"{y}-W{w:02d}")
        return out
    out = []
    for i in range(n - 1, -1, -1):
        total = today.year * 12 + (today.month - 1) - i
        out.append(f"{total // 12:04d}-{total % 12 + 1:02d}")
    return out


def _bucket_first_day(period: str, key: str) -> date:
    """桶键 → 它的第一天（用来定 Query 的下界）。"""
    if period == "day":
        return date.fromisoformat(key)
    if period == "month":
        y, m = key.split("-")
        return date(int(y), int(m), 1)
    y, w = key.split("-W")
    return date.fromisocalendar(int(y), int(w), 1)


def series(site_id: str, period: str = "day", n: int = 30) -> list[dict]:
    """时间序列。`period` ∈ day|week|month，`n` = 桶数。"""
    if period not in ("day", "week", "month"):
        raise ValueError(f"period 必须是 day/week/month，收到 {period!r}")
    if not 1 <= n <= 400:
        raise ValueError(f"n 必须在 1..400，收到 {n}")
    today = datetime.now(timezone.utc).date()
    keys = _bucket_keys(period, n, today)      # 恰好 n 个，日历对齐
    start = _bucket_first_day(period, keys[0])
    daily = _daily_rows(site_id, start.isoformat())
    # 今天没被封口（rollup 只处理完整日）→ 实时算
    live = day_stats(_day_rows(site_id, _today()))
    if live["pv"] or live["pv_denied"]:
        daily[_today()] = live

    detail_floor = today - timedelta(days=DETAIL_DAYS - 1)
    # **零填充恰好 n 个桶**：契约是"最近 n 个日历桶"，没有数据的桶要给 0 而不是
    # 消失（前端 sparkline 与 pv7 都依赖长度固定）。
    buckets: dict[str, dict] = {
        k: {"bucket": k, "pv": 0, "uv": 0, "pv_denied": 0, "_days": [],
            "uv_exact": True} for k in keys}
    for day, st in sorted(daily.items()):
        key = _bucket_of(day, period)
        if key not in buckets:
            continue          # 落在区间外（Query 下界是桶首日，可能多带几天）
        b = buckets[key]
        b["pv"] += st["pv"]
        b["pv_denied"] += st["pv_denied"]
        b["_days"].append(day)
        if period == "day":
            b["uv"] = st["uv"]              # 日 UV 直接取，永远精确

    for b in buckets.values():
        if period == "day":
            b.pop("_days")
            continue
        days = b.pop("_days")
        # **UV 不能相加去重**：跨天去重必须回明细。区间任一天掉出明细窗口，
        # 这个桶的 UV 就给不出精确值——此时给 null 而不是给一个上界。
        if any(datetime.strptime(d, "%Y-%m-%d").date() < detail_floor
               for d in days):
            b["uv"], b["uv_exact"] = None, False
            continue
        visitors = set()
        for d in days:
            for r in _day_rows(site_id, d):
                if r.get("decision", {}).get("S") != "allow":
                    continue
                email = r.get("email", {}).get("S", "")
                if email:
                    visitors.add(email)
        b["uv"] = len(visitors)
    return [buckets[k] for k in keys]      # 恒为 n 个，升序


def _encode(key: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


def _decode(cursor: str) -> dict:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except Exception:
        raise ValueError("cursor 不是本接口发出的游标")


def visitors(site_id: str, days: int = 7, limit: int = 50,
             cursor: str | None = None) -> dict:
    """访问明细（最新在前）。含被拒记录。"""
    if not 1 <= days <= MAX_VISITOR_DAYS:
        raise ValueError(f"days 必须在 1..{MAX_VISITOR_DAYS}（= 明细留存），收到 {days}")
    if not 1 <= limit <= MAX_VISITOR_LIMIT:
        raise ValueError(f"limit 必须在 1..{MAX_VISITOR_LIMIT}，收到 {limit}")
    today = datetime.now(timezone.utc).date()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days)]
    state = _decode(cursor) if cursor else {}
    start_at = state.get("day", day_list[0])
    rows: list[dict] = []
    nxt = None
    for day in day_list:
        if day > start_at:
            continue
        kwargs = {"TableName": os.environ["ACCESS_EVENTS_TABLE"],
                  "KeyConditionExpression": "site_date = :sd",
                  "ExpressionAttributeValues": {":sd": {"S": f"{site_id}#{day}"}},
                  "ScanIndexForward": False,
                  "Limit": limit - len(rows)}
        if day == start_at and state.get("key"):
            kwargs["ExclusiveStartKey"] = state["key"]
        resp = _client().query(**kwargs)
        for it in resp.get("Items", []):
            rows.append({"ts": it["ts_id"]["S"].split("#")[0],
                         "email": it.get("email", {}).get("S", ""),
                         "path": it.get("path", {}).get("S", ""),
                         "decision": it.get("decision", {}).get("S", "")})
        if len(rows) >= limit:
            if "LastEvaluatedKey" in resp:
                nxt = _encode({"day": day, "key": resp["LastEvaluatedKey"]})
            else:
                remaining = [d for d in day_list if d < day]
                nxt = _encode({"day": remaining[0]}) if remaining else None
            break
    return {"rows": rows, "next": nxt}
```

`api.py` 追加（**import 段加 `import analytics`**）：

```python
def do_get_analytics(email: str, site_id: str, *, period: str = "day",
                     n: int = 30) -> dict:
    """PV/UV 时间序列。`uv_exact=False` 的桶其 `uv` 为 null（analytics 模块的
    契约），前端要显式标注而不是显示 0。"""
    site = common.get_site_consistent(site_id)
    permissions.assert_can(email, site, "view_analytics",
                           is_admin=permissions.is_admin(email),
                           what=f"站点 {site_id} 的访问统计")
    return {"period": period, "series": analytics.series(site_id, period, n)}


def do_get_visitors(email: str, site_id: str, *, days: int = 7,
                    limit: int = 50, cursor: str | None = None) -> dict:
    """访问明细/审计（含被拒记录）。"""
    site = common.get_site_consistent(site_id)
    permissions.assert_can(email, site, "view_analytics",
                           is_admin=permissions.is_admin(email),
                           what=f"站点 {site_id} 的访问明细")
    return analytics.visitors(site_id, days=days, limit=limit, cursor=cursor)
```

`handler.py`：ROUTES 在 `/jobs` 之后加两条 + 常量 + 分发。

```python
    ("GET", re.compile(rf"^/api/sites/{_SITE}/jobs$")),
    # M5：两个读端点。GET ⇒ 自动免 CSRF 与面板会话（READ_ONLY），
    # 授权走 api 层的 view_analytics。
    ("GET", re.compile(rf"^/api/sites/{_SITE}/analytics$")),
    ("GET", re.compile(rf"^/api/sites/{_SITE}/visitors$")),
```

```python
ANALYTICS = rf"^/api/sites/{_SITE}/analytics$"
VISITORS = rf"^/api/sites/{_SITE}/visitors$"
```

`_dispatch` 在 `/jobs` 分支之后插入：

```python
    if pattern == ANALYTICS:
        return api.do_get_analytics(email, site_id,
                                    period=qs.get("period", "day"),
                                    n=int(qs.get("n", 30)))
    if pattern == VISITORS:
        return api.do_get_visitors(email, site_id,
                                   days=int(qs.get("days", 7)),
                                   limit=int(qs.get("limit", 50)),
                                   cursor=qs.get("cursor") or None)
```

> `int()` 对非数字抛 `ValueError` → handler 已有的 `except ValueError` 转 400。

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/panel && \
  ../deployer/.venv/bin/pytest tests -q
```

预期：新文件全绿 + panel 既有 296 项仍绿（`test_no_handwritten_guards.py`
会检查 api.py 不出现手写表达式——`analytics.py` 是新的访问层，若该 AST 守卫
把它算成违规，**按 keystore.py 的既有豁免形态加同样的说明**，不要放宽守卫）。

- [ ] **Step 5: 反向验证**

① `do_get_analytics` 的 `assert_can` 删掉 → 预期
`test_endpoints_require_view_analytics` 变红。
② `series()` 里"任一天掉出窗口就给 null"的判断删掉 → 预期
`test_month_uv_is_null_and_flagged_outside_the_detail_window` 变红。
③ `series()` 的月桶 UV 改成日 UV 相加 → 预期
`test_month_uv_is_exact_inside_the_detail_window` 报"同一个人跨两天被算成两个"。
④ ROUTES 加了但不加分发分支 → 预期 `test_every_route_still_has_a_dispatch_branch` 变红。

每次还原用 `/tmp` 备份 + `diff -q` + `git status` 双证。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/functions/analytics.py \
        site-builder/deployer/tests/test_analytics.py \
        site-builder/panel/api.py site-builder/panel/handler.py \
        site-builder/panel/tests/
git commit -m "feat(m5): panel 的读取层与两个 GET 端点

analytics.py 落在 deployer/functions/（共享模块的既有位置，也是 MCP 闭包守卫
唯一会扫的目录——放在 panel/ 下守卫会静默放过而容器里 ImportError）。今天从明细实时算、历史读聚合表；pv/uv 的口径 import
access_rollup.day_stats，不另写一份。

uv_exact 是契约的一部分：日 UV 永远精确，周/月 UV 只在区间完整落在 90 天明细
窗口内才精确，否则 uv=null + uv_exact=false 让前端显式标注——不显示一个站不住
的数字。UV 不能相加去重，跨天去重必须回明细。

授权走新的 view_analytics 动作（CAPABILITIES 唯一真源），负测配了正对照。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: 前端统计页 + 前端守卫改造

**Files:**
- Modify: `site-builder/panel/frontend/app.js:1180-1196`（`renderAnalyticsTab`）
- Modify: `site-builder/panel/tests/test_frontend_contract.py:411-431`

**Interfaces:**
- Consumes: Task 8 的两个端点与响应形态（`{period, series:[{bucket,pv,uv,pv_denied,uv_exact}]}`、`{rows:[{ts,email,path,decision}], next}`）。

**关键约束（读过测试文件后确认的）**：
- 请求必须走 `api()` / `apiGet()`（`fetch` 全局只许出现 1 次）；
- 路径必须写成**字面量拼接**，`_normalize_path` 才能具体化；
- `forwarders` 必须**恰好保持 1**（唯一那个 `apiGet` 转发）；
- 加了 ROUTES 就必须真的调用它，否则
  `test_every_handler_route_is_reachable_or_explicitly_unused` 会红。

- [ ] **Step 1: 先改守卫（TDD：守卫先反映新事实，再让前端满足它）**

`test_frontend_contract.py` 第 ③ 组整体替换：

```python
# ── ③ 前端只能请求 handler 真实存在的端点 ──────────────────────────

def test_frontend_only_calls_paths_that_exist_in_handler():
    """前端发出的每个 /api 路径都必须能匹配 handler.ROUTES。

    **本用例的上一版还带一份手写的"禁止路径"清单**
    （`/api/analytics`、`/api/visitors`、`/api/stats`、`/api/pv`）。M5 落地时
    那份清单会变成**永远绿的死断言**：真实路由是
    `/api/sites/{id}/analytics`，与清单里的裸路径不是同一个字符串，所以它既
    抓不到问题也不会红——正是 M4-FINDINGS §3.6 说的死重量，与 §3.2 的
    "枚举什么还不存在"是同一个病（M4 的 `/api/keys` 已经栽过一次）。

    改成**从真源推导**：唯一判据是 handler.ROUTES。下一个里程碑加路由时，
    这条既不假红也不假绿。
    """
    import handler
    calls = _frontend_calls()
    assert calls, "解析不到任何 API 调用——调用形态变了，本用例必须同步更新"
    for method, path in calls:
        assert any(m == method and rx.match(path) for m, rx in handler.ROUTES), (
            f"前端请求了 handler 里不存在的端点: {method} {path}")


def test_path_extractor_sees_every_api_literal_in_the_source():
    """扫描器自身的完整性：源码里的 /api 字面量不能比解析出的路径多。

    这才是真正的风险（一个只会说 clean 的检测器比没有更糟，M3-FINDINGS
    §2.11）——上一版那份"禁止路径"清单其实是在替这条做事，但它只覆盖几个
    猜出来的字符串。
    """
    import re as _re
    blob = _js()
    literals = {m.group(1) for m in
                _re.finditer(r"""['"](/api/[A-Za-z0-9_\-/]*)['"]""", blob)}
    parsed_prefixes = {p for _, p in _frontend_calls()}
    for lit in literals:
        head = lit.rstrip("/")
        assert any(p.startswith(head) for p in parsed_prefixes), (
            f"源码里有 /api 字面量 {lit!r} 但解析器没把它算成一次调用"
            "——扫描器漏了一个出网口，本文件的其它断言对它全部失效")
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/panel && \
  ../deployer/.venv/bin/pytest tests/test_frontend_contract.py -q
```

预期：`test_every_handler_route_is_reachable_or_explicitly_unused` **FAIL**，
点名 `GET ^/api/sites/.../analytics$` 与 `.../visitors$` 前端没接。

- [ ] **Step 3: 写实现**

`app.js` 的 `renderAnalyticsTab` 整体替换（删掉「不发任何请求」那段注释与占位卡片）：

```javascript
/* ── 访问统计（M5）─────────────────────────────────────────────────── */

/* uv_exact=false 的桶其 uv 是 null（后端契约）——显式标注"超出明细留存窗口"，
 * 不显示 0。日 UV 永远精确；周/月 UV 只在区间完整落在 90 天明细窗口内才精确。 */
function uvCell(b) {
  if (b.uv_exact === false || b.uv === null || b.uv === undefined) {
    return '<span class="meta" title="该区间已超出 90 天明细留存窗口，' +
           '独立访客数无法精确去重">—</span>';
  }
  return String(b.uv);
}

function renderAnalyticsTab(panel, site) {
  panel.innerHTML = '<section class="card"><div class="card-body">' +
    '<p class="meta">正在加载访问统计…</p></div></section>';
  var id = encodeURIComponent(site.site_id);
  Promise.all([
    apiGet('/api/sites/' + id + '/analytics?period=day&n=30'),
    apiGet('/api/sites/' + id + '/visitors?days=7&limit=50')
  ]).then(function (res) {
    var series = (res[0] && res[0].series) || [];
    var rows = (res[1] && res[1].rows) || [];
    panel.innerHTML =
      '<section class="card"><div class="card-head"><h2>访问趋势（近 30 天）</h2></div>' +
      '<div class="card-body">' + trendTable(series) + '</div></section>' +
      '<section class="card" style="margin-top:28px">' +
      '<div class="card-head"><h2>访问明细（近 7 天）</h2>' +
      '<span class="tag">含被拒记录</span></div>' +
      '<div class="card-body">' + visitorTable(rows) + '</div></section>';
  }).catch(function (e) {
    panel.innerHTML = '<section class="card"><div class="card-body">' +
      '<p class="meta">访问统计读取失败：' + escapeHtml(String(e && e.message || e)) +
      '</p></div></section>';
  });
}

function trendTable(series) {
  if (!series.length) {
    return '<p class="meta">这段时间没有访问记录。</p>';
  }
  var body = series.map(function (b) {
    return '<tr><td>' + escapeHtml(b.bucket) + '</td><td>' + b.pv +
      '</td><td>' + uvCell(b) + '</td><td>' + (b.pv_denied || 0) + '</td></tr>';
  }).join('');
  return '<table class="tbl"><thead><tr><th>日期</th><th>PV</th>' +
    '<th>独立访客</th><th>被拒</th></tr></thead><tbody>' + body + '</tbody></table>';
}

function visitorTable(rows) {
  if (!rows.length) {
    return '<p class="meta">近 7 天没有访问记录。</p>';
  }
  var label = {allow: '放行', denied_403: '不在名单', redirect_login: '未登录'};
  var body = rows.map(function (r) {
    return '<tr><td>' + escapeHtml(r.ts) + '</td><td>' +
      escapeHtml(r.email || '（未登录）') + '</td><td>' +
      escapeHtml(r.path) + '</td><td>' +
      escapeHtml(label[r.decision] || r.decision) + '</td></tr>';
  }).join('');
  return '<table class="tbl"><thead><tr><th>时间</th><th>访问者</th>' +
    '<th>路径</th><th>结果</th></tr></thead><tbody>' + body + '</tbody></table>';
}
```

调用点改成传 site（`app.js:680`）：

```javascript
  else if (tab === 'analytics') renderAnalyticsTab(panel, site);
```

> 若 `escapeHtml` 在 app.js 里不叫这个名字，用文件里既有的那个转义函数
> （`grep -n "function escape" site-builder/panel/frontend/app.js` 确认）。

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/panel && \
  ../deployer/.venv/bin/pytest tests -q
```

预期：全绿，**且 `forwarders == 1` 那条仍绿**（新代码走 `apiGet`，不新增出网口）。

- [ ] **Step 5: 反向验证（三条）**

① 把一处路径改成 `'/api/analytics?site=' + id` → 预期
`test_frontend_only_calls_paths_that_exist_in_handler` 变红。
② 把 `uvCell` 改成 `return String(b.uv)` → 前端会显示 `null`；补一条断言盯住它：

```python
def test_frontend_flags_inexact_uv_instead_of_printing_a_number():
    blob = _js()
    assert "uv_exact" in blob, "前端没有读 uv_exact——超窗口的桶会显示 null 或 0"
```

③ 用 `fetch(` 直接发一次请求 → 预期
`test_all_network_calls_go_through_the_api_helper` 变红。

还原 + 双证。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/panel/frontend/app.js site-builder/panel/tests/test_frontend_contract.py
git commit -m "feat(m5): 控制台统计页接真实数据 + 前端守卫改成从 ROUTES 推导

守卫的上一版带一份手写"禁止路径"清单（/api/analytics 等）。真实路由是
/api/sites/{id}/analytics，与那些裸路径不是同一个字符串——所以那份清单在 M5
落地后会变成**永远绿的死断言**（§3.6 死重量，与 §3.2 同一个病，M4 的
/api/keys 已栽过一次）。改成唯一判据 = handler.ROUTES，并补一条"扫描器自身
不许漏出网口"的完整性断言（那才是清单在替它做的事）。

超出 90 天明细窗口的桶显示标注而不是数字（uv 为 null，不是 0）。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9b: 站点列表的 PV 迷你趋势（`pv7`）

**为什么在这里**：这不是新增需求，是**被我漏掉的既定范围**（Codex 审查
2026-08-14 P2-3）。母 spec §11-clarify 的 M5 清单与 M3 spec 第 64 行都列了
「站点列表 PV 迷你趋势」，控制台原型里 `pv7` 出现 6 处、`sparkline` 4 处。
**必须排在 Task 15 部署之前。**

**Files:**
- Modify: `site-builder/deployer/functions/analytics.py`（加 `pv7`）
- Modify: `site-builder/panel/api.py`（`do_list_sites` 每站点带 `pv7`）
- Modify: `site-builder/panel/frontend/app.js`（列表里画 sparkline）
- Test: `site-builder/deployer/tests/test_analytics.py` · `site-builder/panel/tests/test_analytics_api.py`

**Interfaces:**
- Consumes: Task 8 的 `series(site_id, "day", 7)`（已零填充、恒 7 个桶）。
- Produces: `analytics.pv7(site_id) -> list[int]`（**长度恒为 7**，升序，缺失日为 0）；
  `GET /api/sites` 每个站点多一个 `pv7` 字段。

- [ ] **Step 1: 写失败的测试**

```python
def test_pv7_is_always_seven_numbers_oldest_first(env):
    """长度恒为 7 且零填充——前端 sparkline 依赖固定长度，缺失日给 0 不是给空。"""
    import analytics
    from datetime import datetime, timedelta, timezone
    y = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    _daily(env, "s1", y, pv=5, uv=2)
    out = analytics.pv7("s1")
    assert isinstance(out, list) and len(out) == 7, out
    assert all(isinstance(x, int) for x in out), out
    assert out[-2] == 5, f"倒数第二个应是昨天的 5: {out}"
    assert out[-1] == 0, f"最后一个是今天（本轮无数据）: {out}"


def test_pv7_of_a_site_without_data_is_seven_zeros(env):
    import analytics
    assert analytics.pv7("never-visited") == [0] * 7


def test_list_sites_carries_pv7(monkeypatch, env):
    """站点列表的迷你趋势（母 spec §11-clarify 的 M5 项）。"""
    import api
    import permissions
    monkeypatch.setattr("common.list_sites_for_user",
                        lambda e: [{"site_id": "s1", "owner": e,
                                    "status": "ACTIVE", "collaborators": []}])
    monkeypatch.setattr(permissions, "is_admin", lambda e: False)
    out = api.do_list_sites("me@x.co")
    assert len(out[0]["pv7"]) == 7, out[0]
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/deployer && PYTHONPATH=functions .venv/bin/pytest tests/test_analytics.py -q -k pv7
cd site-builder/panel && ../deployer/.venv/bin/pytest tests/test_analytics_api.py -q -k pv7
```

预期：`AttributeError: module 'analytics' has no attribute 'pv7'`。

- [ ] **Step 3: 写实现**

`analytics.py` 追加：

```python
def pv7(site_id: str) -> list[int]:
    """近 7 天的日 PV，升序，**长度恒为 7**（缺失日为 0）。

    给站点列表画 sparkline 用（母 spec §11-clarify 的 M5 项）。直接复用
    `series()`——它已经零填充且日历对齐，所以这里不做第二套取数逻辑。
    """
    return [b["pv"] for b in series(site_id, "day", 7)]
```

`api.py` 的 `do_list_sites` 在组装每个站点的返回字段时加：

```python
        # 站点列表的迷你趋势。**成本**：站点数 × 1 次分区 Query
        # （当前 31 个站点，实测规模下可接受）。管理员全局视图同理——
        # 站点数长到三位数时改批量或缓存，届时重评（spec §3.5 已记）。
        "pv7": analytics.pv7(site["site_id"]),
```

`app.js` 的站点列表卡片里加一个 sparkline（用现成的 `pv7` 数组，SVG polyline，
不引任何库；最大值为 0 时画一条平线而不是除零）：

```javascript
/* 站点列表的 PV 迷你趋势。pv7 长度恒为 7（后端契约），所以不做长度兜底；
 * 全 0 时画平线——不能除零，也不该画成"没有数据"（0 次访问是一个事实）。 */
function sparkline(pv7) {
  var max = Math.max.apply(null, pv7);
  var h = 18, w = 56, step = w / (pv7.length - 1);
  var pts = pv7.map(function (v, i) {
    var y = max === 0 ? h - 1 : h - 1 - (v / max) * (h - 2);
    return (i * step).toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="spark" width="' + w + '" height="' + h +
    '" viewBox="0 0 ' + w + ' ' + h + '" aria-hidden="true">' +
    '<polyline points="' + pts + '" fill="none" stroke="currentColor" ' +
    'stroke-width="1.5" stroke-linejoin="round"/></svg>' +
    '<span class="meta" style="margin-left:6px">近 7 天 ' +
    pv7.reduce(function (a, b) { return a + b; }, 0) + ' PV</span>';
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/deployer && .venv/bin/pytest tests -q
cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q
```

预期全绿（前端契约那组也要绿——本 Task **不新增路由**，列表本来就在调
`/api/sites`，所以可达性核对不受影响）。

- [ ] **Step 5: 反向验证**

① `pv7` 改成 `return [b["pv"] for b in series(site_id, "day", 5)]` → 预期
`test_pv7_is_always_seven_numbers_oldest_first` 报长度 5。
② `sparkline` 去掉 `max === 0` 分支 → 全 0 站点会产出 `NaN` 坐标；补一条前端断言：

```python
def test_sparkline_handles_all_zero_without_dividing_by_zero():
    blob = _js()
    assert "max === 0" in blob, "sparkline 没处理全 0（会产出 NaN 坐标）"
```

还原 + 双证。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/functions/analytics.py site-builder/deployer/tests/ \
        site-builder/panel/api.py site-builder/panel/frontend/app.js \
        site-builder/panel/tests/
git commit -m "feat(m5): 站点列表的 PV 迷你趋势（pv7）

不是新增需求——母 spec §11-clarify 与 M3 spec 第 64 行都把它列进 M5，原型里
pv7/sparkline 一直在。我第一版 spec 漏了它，self-review 只核对了新 spec 自己
而没核对母 spec 的 M5 交付边界（Codex 审查 P2-3）。

pv7 直接复用 series(site_id, 'day', 7)——它已零填充且日历对齐，不做第二套
取数逻辑。成本是站点数 × 1 次分区 Query，当前 31 个站点可接受。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: MCP 工具

**Files:**
- Modify: `site-builder/mcp/server.py`
- Create: `site-builder/mcp/tests/test_analytics_tool.py`

**Interfaces:**
- Consumes: Task 7 的 `view_analytics`、Task 8 的 `analytics` 模块形态。
- Produces: MCP 工具 `get_site_analytics(site_id, period="day", days=30) -> dict`
  与 `do_get_analytics(caller, site_id, period, days) -> dict`。

- [ ] **Step 1: 写失败的测试**

```python
"""M5 MCP 工具单测。

**返回单个 dict，不返回裸列表**——M4-FINDINGS §3.4 实测：线上这台 server 不发
`structuredContent`，返回列表会被拆成多个 text 块，调用方"取 content[0].text
解析"会**静默只拿到第一个元素**。错的时候不抛异常，只是数据少了。
"""
import inspect

import pytest


def test_tool_returns_a_dict_not_a_bare_list():
    import server
    sig = inspect.signature(server.get_site_analytics)
    assert sig.return_annotation is dict, (
        "返回类型必须是 dict——裸列表会被拆成多个 text 块并被静默截断（§3.4）")


def test_tool_delegates_authorization_to_view_analytics(monkeypatch):
    import server
    seen = {}
    monkeypatch.setattr(server, "_assert_permission",
                        lambda email, site_id, action, what: seen.update(
                            {"action": action, "site": site_id}) or
                        server.Authz({}, "owner", 0, True, email))
    monkeypatch.setattr(server, "_analytics_payload",
                        lambda site_id, period, days: {"series": []})
    server.do_get_analytics("me@x.co", "s1", "day", 30)
    assert seen == {"action": "view_analytics", "site": "s1"}


def test_series_and_visitors_are_fields_of_one_dict(monkeypatch):
    import server
    monkeypatch.setattr(server, "_assert_permission",
                        lambda *a, **k: server.Authz({}, "owner", 0, True, "e"))
    monkeypatch.setattr(server, "_analytics_payload",
                        lambda site_id, period, days: {
                            "series": [{"bucket": "2026-08-13", "pv": 1,
                                        "uv": 1, "pv_denied": 0,
                                        "uv_exact": True}],
                            "recent_visitors": [{"ts": "t", "email": "a@x.co",
                                                 "path": "/", "decision": "allow"}]})
    out = server.do_get_analytics("me@x.co", "s1", "day", 30)
    assert isinstance(out, dict)
    assert isinstance(out["series"], list) and isinstance(out["recent_visitors"], list)


@pytest.mark.parametrize("period", ["hour", "", "DAY"])
def test_invalid_period_is_rejected(monkeypatch, period):
    import server
    monkeypatch.setattr(server, "_assert_permission",
                        lambda *a, **k: server.Authz({}, "owner", 0, True, "e"))
    with pytest.raises(ValueError):
        server.do_get_analytics("me@x.co", "s1", period, 30)
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/mcp && python3 -m pytest tests/test_analytics_tool.py -q
```

预期：`AttributeError: module 'server' has no attribute 'get_site_analytics'`。

- [ ] **Step 3: 写实现**

`server.py` 在 `do_get_permissions` 之后加：

```python
def _analytics_payload(site_id: str, period: str, days: int) -> dict:
    """读取层。与 panel **共用同一个** deployer/functions/analytics.py。

    该模块必须进镜像（Dockerfile COPY + build_and_push 复制元组 +
    _BUILD_INPUTS 三处，见 Task 11）——容器里只有四个 .py 时这行会
    ModuleNotFoundError，而部署会显示成功（Codex 审查 P1-2 实测）。
    """
    import analytics
    return {"series": analytics.series(site_id, period, days),
            "recent_visitors": analytics.visitors(site_id, days=min(days, 7),
                                                  limit=50)["rows"]}


def do_get_analytics(caller: str, site_id: str, period: str, days: int) -> dict:
    if period not in ("day", "week", "month"):
        raise ValueError(f"period 必须是 day/week/month，收到 {period!r}")
    _assert_permission(caller, site_id, "view_analytics",
                       what=f"站点 {site_id} 的访问统计")
    return _analytics_payload(site_id, period, days)
```

工具定义（放在 `get_site_permissions` 之后）：

```python
@mcp.tool()
def get_site_analytics(site_id: str, period: str = "day",
                       days: int = 30) -> dict:
    """查询站点的访问统计（PV / 独立访客 / 被拒次数）与最近的访问明细。

    period: day|week|month。**返回单个对象**，`series` 与 `recent_visitors`
    是它的字段——不返回裸列表（列表会被拆成多个 text 块并被调用方静默截断）。
    `uv_exact=false` 的桶其 `uv` 为 null：该区间超出 90 天明细留存窗口，
    独立访客数无法精确去重。
    """
    return do_get_analytics(_caller_email(), site_id, period, days)
```

- [ ] **Step 4: 跑测试确认通过**

```bash
cd site-builder/mcp && python3 -m pytest tests -q
```

预期：新文件全绿 + 既有 172 项仍绿。

- [ ] **Step 5: 反向验证**

① `do_get_analytics` 的 `_assert_permission` 删掉 → 预期
`test_tool_delegates_authorization_to_view_analytics` 变红。
② 工具返回类型改成 `list` 并 `return [...]` → 预期
`test_tool_returns_a_dict_not_a_bare_list` 变红。
还原 + 双证。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/mcp/server.py site-builder/mcp/tests/test_analytics_tool.py
git commit -m "feat(m5): MCP 工具 get_site_analytics（返回单个 dict）

不返回裸列表：实测线上这台 server 不发 structuredContent，列表会被拆成多个
text 块，调用方取 content[0].text 会静默只拿到第一个元素（§3.4）——错的时候
不抛异常，只是数据少了。授权委派 view_analytics。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: 表名下发 + **MCP 镜像的三份清单**

**Files:**
- Modify: `site-builder/panel/deploy_panel.py`（环境变量 + `COPY_FILES`）
- Modify: `site-builder/mcp/Dockerfile:21-23`（`COPY` 行）
- Modify: `site-builder/mcp/deploy_agentcore.py`（环境变量 + `_BUILD_INPUTS` + `build_and_push` 复制元组 + IAM）
- Test: `site-builder/mcp/tests/test_agentcore_contract.py`（既有闭包守卫 + 一条新守卫）
- Test: `site-builder/panel/tests/`（既有的复制闭包/环境变量测试）

**这个 Task 是 P1-2 的收口**。MCP 容器现在只有四个文件
（`server.py common.py permissions.py ops_log.py`，Dockerfile 实测），
`import analytics` 会 `ModuleNotFoundError`，**部署成功、工具一调就废**。

两件事要分清：

1. **传递闭包守卫会自动逮住 Dockerfile 与 `build_and_push`**——因为 Task 8 已把
   `analytics.py` 放进 `deployer/functions/`，而该守卫正是从那个目录做闭包
   （`candidate = fn_dir / f"{name}.py"`）。所以这两处漏了会**当场红**，
   不需要新守卫。这是"把模块放到守卫能看见的地方"而不是"再加一个守卫"。
2. **`_BUILD_INPUTS` 不在那个守卫的范围内**（它只比 Dockerfile 的 COPY 行与
   `build_and_push` 的元组）。而 `_BUILD_INPUTS` 决定**内容指纹 tag**——漏了
   它，改 `analytics.py` 不会改 tag，`deploy_agentcore.py` 会复用**旧镜像**
   并打印成功。这是本仓库最熟悉的那种静默失效，所以要**新加一条守卫**。

- [ ] **Step 1: 写失败的测试**

追加到 panel 既有的部署清单测试文件（`grep -rn "COPY_FILES" site-builder/panel/tests/`
定位；若无则加到 `tests/test_handler.py`）：

```python
def test_analytics_modules_are_in_the_deploy_package():
    """analytics.py import access_rollup（pv/uv 口径的唯一定义），
    所以两者都必须进包——漏一个的症状是线上 ImportError 而单测全绿。"""
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "dp", Path(__file__).parents[1] / "deploy_panel.py")
    dp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dp)
    names = {Path(p).name for p in dp.COPY_FILES}
    assert "access_rollup.py" in names, f"access_rollup.py 没进包: {sorted(names)}"


def test_panel_env_carries_both_access_tables():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "dp", Path(__file__).parents[1] / "deploy_panel.py")
    dp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dp)
    env = dp.ENV if hasattr(dp, "ENV") else dp.base_env()
    assert env["ACCESS_EVENTS_TABLE"] == "site-access-events"
    assert env["ACCESS_DAILY_TABLE"] == "site-access-daily"
```

> 先 `grep -n "SESSION_CODES_TABLE" site-builder/panel/deploy_panel.py` 看那个
> 环境变量字典叫什么名字（Task 起手第一步），把上面的 `dp.ENV` 换成真名。

追加到 `site-builder/mcp/tests/test_agentcore_contract.py`：

```python
def test_build_inputs_covers_every_module_that_enters_the_image():
    """`_BUILD_INPUTS` 决定内容指纹 tag，漏一个模块 = 改它不会改 tag =
    deploy_agentcore.py 复用**旧镜像**并打印成功。

    既有的传递闭包守卫只比 Dockerfile 的 COPY 行与 build_and_push 的元组，
    **不管指纹清单**——所以这条是它的补集，从同一份闭包推导，不手抄。
    """
    import ast
    import importlib.util
    from pathlib import Path

    mcp_dir = Path(__file__).parents[1]
    fn_dir = mcp_dir.parent / "deployer" / "functions"

    def local_imports(path):
        names = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        return names

    needed, queue, seen = set(), ["server.py"], set()
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        path = mcp_dir / cur if (mcp_dir / cur).exists() else fn_dir / cur
        if not path.exists():
            continue
        for name in local_imports(path):
            if (fn_dir / f"{name}.py").exists():
                needed.add(f"{name}.py")
                queue.append(f"{name}.py")
    assert "analytics.py" in needed, (
        "闭包没算出 analytics.py——server.py 应该 import 它（解析逻辑坏了）")

    spec = importlib.util.spec_from_file_location(
        "da", mcp_dir / "deploy_agentcore.py")
    da = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(da)
    inputs = {Path(x).name for x in da._BUILD_INPUTS}
    missing = needed - inputs
    assert not missing, (
        f"_BUILD_INPUTS 漏了 {sorted(missing)}——改这些文件不会改镜像 tag，"
        "部署会复用旧镜像并打印成功")
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cd site-builder/panel && \
  ../deployer/.venv/bin/pytest tests -q -k access
```

- [ ] **Step 3: 写实现**

`deploy_panel.py` 的环境变量字典加两项、`COPY_FILES` 加 `access_rollup.py`：

```python
        "API_KEYS_TABLE": "site-api-keys",
        # M5：读取层用。analytics.py import access_rollup.day_stats
        # （pv/uv 口径唯一定义），所以 access_rollup.py 也要进包。
        "ACCESS_EVENTS_TABLE": "site-access-events",
        "ACCESS_DAILY_TABLE": "site-access-daily",
```

panel role 的 IAM 加：明细表 `Query`、聚合表 `Query`（**只读**，不给 PutItem
——panel 不该能改统计）。位置照 `site-api-keys` 那段。

`deploy_agentcore.py` 三处都要改：

```python
# ① 环境变量（照 API_KEYS_TABLE 的位置）
"ACCESS_EVENTS_TABLE": "site-access-events",
"ACCESS_DAILY_TABLE": "site-access-daily",

# ② 内容指纹清单——**漏了它 = 改 analytics.py 不改 tag = 复用旧镜像**
_BUILD_INPUTS = ("mcp/Dockerfile", "mcp/requirements.txt", "mcp/server.py",
                 "deployer/functions/common.py",
                 "deployer/functions/permissions.py",
                 "deployer/functions/ops_log.py",
                 "deployer/functions/analytics.py",
                 "deployer/functions/access_rollup.py")

# ③ build_and_push 的复制元组（server.py 按同目录解析它们）
for name in ("common.py", "permissions.py", "ops_log.py",
             "analytics.py", "access_rollup.py"):
```

`Dockerfile` 的 COPY 行：

```dockerfile
COPY server.py common.py permissions.py ops_log.py analytics.py access_rollup.py ./
```

再加两条只读 IAM（明细表与聚合表各 `dynamodb:Query`，**不给 PutItem**）。

- [ ] **Step 4: 跑测试确认通过 + 全包回归**

```bash
cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q
cd site-builder/mcp && python3 -m pytest tests -q
```

- [ ] **Step 5: 反向验证**

① 把 `access_rollup.py` 从 panel 的 `COPY_FILES` 去掉 → 预期
`test_analytics_modules_are_in_the_deploy_package` 变红。
② 把 `analytics.py` 从 **Dockerfile 的 COPY 行**去掉 → 预期**既有的**
`test_agentcore_contract` 闭包守卫变红（证明"把模块放对位置"确实让既有守卫生效，
而不是靠新守卫）。
③ 把 `analytics.py` 从 **`_BUILD_INPUTS`** 去掉 → 预期只有新加的
`test_build_inputs_covers_every_module_that_enters_the_image` 变红，
**既有闭包守卫仍绿**——这正好证明它是既有守卫的补集，不是重复。
每次还原 + 双证。

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/panel/deploy_panel.py site-builder/mcp/deploy_agentcore.py \
        site-builder/mcp/Dockerfile site-builder/mcp/tests/test_agentcore_contract.py \
        site-builder/panel/tests/
git commit -m "feat(m5): panel/MCP 下发两张表名与只读 IAM

两者对统计表都只有 Query——不给 PutItem，改统计只属于 rollup。
access_rollup.py 一并进包（analytics.py import 它的 day_stats，那是 pv/uv
口径的唯一定义），漏它的症状是线上 ImportError 而单测全绿。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: `verify_console_e2e.py` ⑪ 段改造

**Files:**
- Modify: `site-builder/scripts/verify_console_e2e.py:393-403`

- [ ] **Step 1: 删掉两条会永远绿的死断言，换成真实行为**

把 393-403 行整段替换：

```python
        print("\n── ⑪ M5 统计端点的真实行为 ────────────────────────")
        # **这一段的历史是一条方法论**：M3 写它时枚举了
        # `/api/keys`、`/api/analytics`、`/api/visitors` 三个"还不存在"的路径
        # 并断言 404。M4 落地当天 `/api/keys` 变成假红（它被实现了），已换成
        # 行为断言。M5 落地时另两条**不会变红——会永远绿**：真实路由是
        # `/api/sites/{id}/analytics`，与那两个裸路径不是同一个字符串。
        # 永远绿的断言是死重量（M4-FINDINGS §3.6），且它伪装成"有覆盖"。
        # 所以：**删掉它们**，换成对真实端点的行为断言。
        # "不泄漏路由表"由本段开头那条通用的"未知路由 → 404"继续覆盖。
        st, _, text = request("GET", origin + f"/api/sites/{site_id}/analytics"
                              "?period=day&n=7", cookies=ck_new)
        check(st == 200, "/api/sites/{id}/analytics → 200", f"实际 {st}")
        try:
            body = json.loads(text)
        except Exception:
            body = {}
        check(isinstance(body.get("series"), list),
              "analytics 返回 {series:[...]} 形态", f"实际 keys={list(body)}")
        check(all({"bucket", "pv", "uv", "pv_denied", "uv_exact"} <= set(b)
                  for b in body.get("series", [])) or not body.get("series"),
              "每个桶都带 uv_exact（契约字段，不是可选项）",
              f"实际 {body.get('series')[:1] if body.get('series') else '空序列'}")

        st, _, text = request("GET", origin + f"/api/sites/{site_id}/visitors"
                             "?days=1&limit=5", cookies=ck_new)
        check(st == 200, "/api/sites/{id}/visitors → 200", f"实际 {st}")
        try:
            vbody = json.loads(text)
        except Exception:
            vbody = {}
        check(isinstance(vbody.get("rows"), list),
              "visitors 返回 {rows:[...]} 形态", f"实际 keys={list(vbody)}")
        check(all({"ts", "email", "path", "decision"} == set(r)
                  for r in vbody.get("rows", [])) or not vbody.get("rows"),
              "明细行恰好四个字段（多字段 = 泄漏了内部结构）",
              f"实际 {vbody.get('rows')[:1] if vbody.get('rows') else '空'}")

        # 越界参数必须 400 而不是被静默夹住（days ≤ 90 = 明细留存）
        st, _, _ = request("GET", origin + f"/api/sites/{site_id}/visitors?days=91",
                           cookies=ck_new)
        check(st == 400, "visitors days=91 → 400（不静默夹到 90）", f"实际 {st}")

        # 负测的正对照：无权者必须 403（§3.5——只验"拒"时，"请求压根没到达"
        # 会让负测永远绿）
        st, _, _ = request("GET", origin + f"/api/sites/{outsider_site}/analytics",
                           cookies=ck_new)
        check(st == 403, "无权站点的 analytics → 403", f"实际 {st}")
```

> `outsider_site` 用本脚本已有的"他人站点"变量名（`grep -n "outsider" site-builder/scripts/verify_console_e2e.py` 确认）；
> 若脚本里没有这样的 fixture，改成对一个**不存在**的 site_id 断言 403
> （`assert_can` 对 `site=None` 返回 ROLE_NONE → PermissionDenied → 403，
> 且文案不区分"不存在"与"无权"，这正是防枚举的设计）。

- [ ] **Step 2: 改下限常量**

本段从 2 条变成 7 条 → 找到 `MIN_*_CHECKS` 常量并 +5。

```bash
grep -n "MIN_.*CHECKS" site-builder/scripts/verify_console_e2e.py
```

- [ ] **Step 3: 语法与静态检查（真机跑在 Task 15）**

```bash
cd "$(git rev-parse --show-toplevel)" && python3 -m py_compile site-builder/scripts/verify_console_e2e.py && echo OK
grep -n "／\|“\|”" site-builder/scripts/verify_console_e2e.py || echo "无全角引号"
```

- [ ] **Step 4: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/scripts/verify_console_e2e.py
git commit -m "test(m5): ⑪ 段那两条 404 断言删掉，换成真实端点的行为断言

它们不会像 M4 的 /api/keys 那样变假红——会**永远绿**：真实路由是
/api/sites/{id}/analytics，与裸路径 /api/analytics 不是同一个字符串。永远绿
的断言是死重量（§3.6），而且伪装成"这里有覆盖"。改成断言 200 + 形态 +
uv_exact 契约字段 + 越界参数 400 + 无权者 403（负测配正对照）。
"不泄漏路由表"由本段已有的通用"未知路由 → 404"继续覆盖。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: `verify_deployed_components.py` 新增 ⑨ 段

**Files:**
- Modify: `site-builder/scripts/verify_deployed_components.py`

- [ ] **Step 1: 加一段 + 一个下限常量**

在 `run_key_proxy()` 之后加：

```python
MIN_ANALYTICS_CHECKS = 11


def run_analytics() -> int:
    """⑨ M5 统计管道的线上形态。

    **别拿 CFN 的 StackStatus 当结论**（M4-FINDINGS §3.13）——直接
    describe_table 读回 Replicas / DeletionProtectionEnabled。
    """
    print("\n── ⑨ 线上 M5 统计管道 ──────────────────────────────")
    cfg = _parsed_cfg(ROUTER_CFG_PATH)
    cfg_sb = _parsed_cfg(CFG_PATH)          # site-builder 侧（account_id 在这）
    table = cfg["SiteBuilder"]["access_table"].strip()
    regions = [r.strip() for r in
               cfg["SiteBuilder"]["access_replica_regions"].split(",") if r.strip()]
    check(len(regions) >= 2, f"副本清单至少主区+1（{regions}）", str(regions))

    d = boto3.client("dynamodb", region_name=REGION)
    desc = d.describe_table(TableName=table)["Table"]
    check(desc["TableStatus"] == "ACTIVE", f"{table} ACTIVE", desc["TableStatus"])
    # 读回**被改的那个属性**，不看栈状态（§3.13）。
    # 用**并集**写法：`Replicas` 是否包含被查询的那个区取决于 API 行为，
    # CFN 模板里它**是包含主区的**（2026-08-14 synth 实测
    # `['ap-southeast-1','ap-northeast-1','us-east-1']`），而 DescribeTable
    # 的运行时行为本轮未实测——并集对两种行为都成立。
    # （上一版这里的注释写"主区不出现在 Replicas 里"，是错的。）
    live = {r["RegionName"]: r.get("ReplicaStatus", "?")
            for r in desc.get("Replicas", [])}
    live.setdefault(REGION, "ACTIVE")
    check(set(live) == set(regions),
          f"副本区集合 == 清单（{sorted(regions)}）", f"线上 {sorted(live)}")
    check(all(v == "ACTIVE" for v in live.values()),
          "每个副本都是 ACTIVE", str(live))

    daily = d.describe_table(TableName="site-access-daily")["Table"]
    check(daily.get("DeletionProtectionEnabled") is True,
          "site-access-daily 开着 deletion protection",
          str(daily.get("DeletionProtectionEnabled")))

    # Edge 角色：有且只有明细表的 PutItem，**且资源逐字覆盖每个副本区**。
    # 上一版只累计 action 就报绿（Codex 审查 2026-08-14 P1-4）——那恰好漏掉了
    # 它声称要防的东西：只给 us-east-1 一个 ARN 时 action 仍是 PutItem，闸门
    # 绿灯，而两个亚洲区写入 AccessDenied 后被 _record_access 吞掉
    # ⇒ 按实测流量分布 **96.1% 的数据静默缺失**。
    # 也**必须读 attached policies**：只读 inline 时，把语句搬进托管策略即绕过。
    iam = boto3.client("iam")
    edge_role = cfg["Lambda"]["execution_role_name"].strip()
    account = cfg_sb["Platform"]["account_id"].strip()
    docs = []
    for name in iam.list_role_policies(RoleName=edge_role)["PolicyNames"]:
        docs.append(iam.get_role_policy(RoleName=edge_role,
                                        PolicyName=name)["PolicyDocument"])
    attached = iam.list_attached_role_policies(RoleName=edge_role)["AttachedPolicies"]
    for pol in attached:
        meta = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
        docs.append(iam.get_policy_version(
            PolicyArn=pol["PolicyArn"],
            VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"])
    check(bool(docs), "读到了 Edge 角色的策略（inline + attached）",
          f"inline={len(docs) - len(attached)} attached={len(attached)}")

    put_arns, acts_on_table, extra = set(), set(), set()
    for doc in docs:
        for st in doc["Statement"]:
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            acts = [str(a) for a in acts]
            if not any(a.startswith("dynamodb:") for a in acts):
                continue
            res = st["Resource"]
            hit = [str(r) for r in (res if isinstance(res, list) else [res])
                   if f"table/{table}" in str(r)]
            if hit:
                acts_on_table |= set(acts)
                if "dynamodb:PutItem" in acts:
                    put_arns |= set(hit)
            extra |= {a for a in acts
                      if a in ("dynamodb:UpdateItem", "dynamodb:DeleteItem",
                               "dynamodb:BatchWriteItem", "dynamodb:*")}
    check(acts_on_table == {"dynamodb:PutItem"},
          "Edge 角色对明细表**有且只有** PutItem", str(sorted(acts_on_table)))
    expected_arns = {f"arn:aws:dynamodb:{rg}:{account}:table/{table}"
                     for rg in regions}
    check(put_arns == expected_arns,
          f"PutItem 资源**逐字**覆盖全部 {len(regions)} 个副本区",
          f"缺 {sorted(expected_arns - put_arns)} / 多 {sorted(put_arns - expected_arns)}")
    check(not extra, "Edge 角色没有任何 DynamoDB 写扩权动作", str(sorted(extra)))

    ev = boto3.client("events", region_name=REGION)
    rule = ev.describe_rule(Name="site-access-rollup-daily")
    check(rule["State"] == "ENABLED", "rollup 规则 ENABLED", rule["State"])
    check(rule["ScheduleExpression"] == "cron(20 0 * * ? *)",
          "rollup 每日 00:20 UTC", rule["ScheduleExpression"])
    return MIN_ANALYTICS_CHECKS
```

`main()` 里接上：

```python
        min_expected += run_key_proxy()
        min_expected += run_analytics()
```

> `ROUTER_CFG_PATH` 若脚本里没有，按既有 `CFG_PATH` 的形态加一个指向
> `router/config.ini` 的常量，并复用 `_parsed_cfg`（它读不到段会当场炸，
> 不返回空配置——§3.10）。

- [ ] **Step 2: 语法检查**

```bash
cd "$(git rev-parse --show-toplevel)" && python3 -m py_compile site-builder/scripts/verify_deployed_components.py && echo OK
```

- [ ] **Step 3: Commit**（真机跑在 Task 15）

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/scripts/verify_deployed_components.py
git commit -m "test(m5): ⑨ 段——副本、保护、Edge 权限（逐字比三个 ARN）、rollup 规则

Edge 权限那条**逐字比对资源 ARN 集合**，不只看 action：只累计 action 的写法
恰好漏掉它声称要防的东西——只给 us-east-1 一个 ARN 时 action 仍是 PutItem、
闸门绿灯，而两个亚洲区 AccessDenied 被埋点吞掉 = 按实测流量 96.1% 数据静默
缺失。同时读 inline + attached（只读 inline 时把语句搬进托管策略即可绕过）。

副本集合与清单比对用并集写法：DescribeTable 是否包含被查询区本轮未实测，
而 CFN 模板实测**是包含主区的**——并集对两种行为都成立。读回的是被改的那个
属性，不是 StackStatus（§3.13）。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: `verify_analytics_e2e.py`

**Files:**
- Create: `site-builder/scripts/_mcp_client.py`（从 `verify_api_key_e2e.py:184` 的
  `class Mcp` + token 获取提取出来的共享封装）
- Modify: `site-builder/scripts/verify_api_key_e2e.py`（改成 import 那份）
- Create: `site-builder/scripts/verify_analytics_e2e.py`

- [ ] **Step 0: 先提取 MCP 客户端封装**

`class Mcp` 现在长在 `verify_api_key_e2e.py:184`。本闸门要用它，但**不能复制
一份**——两份 OAuth/token 逻辑必然漂移（本仓库反复记过这个形态）。提到
`site-builder/scripts/_mcp_client.py`，两个闸门都 import。

提取后**必须重跑 `verify_api_key_e2e.py` 确认仍 34/34**（否则这次重构本身就是
一次回归），再继续。

**关键设计（spec §0.4）**：Global Table 复制是异步的（典型 <1s，无 SLA），
所以**必须轮询等待**那一行、有上限、超时即红。发完请求立刻断言 = 做出一个
flaky 闸门，而 flaky 闸门的代价是下一个人学会忽略它。

- [ ] **Step 1: 写脚本**

```python
#!/usr/bin/env python3
"""M5 真机闸门：从一次真实页面请求走到面板与 MCP 的数字。

**从仓库根跑**：`python3 site-builder/scripts/verify_analytics_e2e.py`

设计要点：
  · **轮询等待明细行**（Global Table 复制是异步的，无 SLA）。立刻断言会做出
    一个 flaky 闸门，而 flaky 闸门的代价是下一个人学会忽略它（同 §3.2 的
    假红逻辑）。
  · **每条负测都配正对照**（§3.5）：只验"不该记的没记"时，"埋点压根没部署"
    会让负测全绿。
  · 清理按依赖顺序，且全局状态最先恢复（§3.8）。
"""
import configparser
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
CFG_PATH = ROOT / "site-builder" / "config.ini"
ROUTER_CFG_PATH = ROOT / "router" / "config.ini"
MIN_CHECKS = 24
results = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def cfg(path: Path) -> configparser.ConfigParser:
    c = configparser.ConfigParser(interpolation=None)
    c.read(path)
    # ConfigParser.read() 对缺失文件是**静默**的（§3.10：cwd 漂移曾让我据此
    # 伪造出一个"生产隐患"）。读空必须当场炸，不返回空配置。
    if not c.sections():
        raise SystemExit(f"{path} 读空了——从仓库根跑，别在子目录跑")
    return c


def wait_for_row(ddb, table, site_id, day, want_path, timeout=30):
    """轮询等待那一行出现。返回 (found_item | None, 等了多少秒)。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = ddb.query(TableName=table,
                         KeyConditionExpression="site_date = :sd",
                         ExpressionAttributeValues={":sd": {"S": f"{site_id}#{day}"}},
                         ScanIndexForward=False, Limit=25)
        for it in resp.get("Items", []):
            if it.get("path", {}).get("S") == want_path:
                return it, round(time.time() - (deadline - timeout), 1)
        time.sleep(1)
    return None, timeout


def main() -> int:
    c = cfg(CFG_PATH)
    rc = cfg(ROUTER_CFG_PATH)
    base = c["Platform"]["base_domain"].strip()
    events_table = rc["SiteBuilder"]["access_table"].strip()
    region = rc["DynamoDB"]["region"].strip()
    ddb = boto3.client("dynamodb", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    site_id = input("用一个你有权访问的 ACTIVE 站点 site_id: ").strip()
    if not site_id:
        raise SystemExit("需要一个 site_id")
    cookie = input("粘一个有效的 sb_session cookie 值: ").strip()
    if not cookie:
        raise SystemExit("需要 sb_session")

    import urllib.request
    def get(path, ck=cookie):
        req = urllib.request.Request(f"https://app-{site_id}.{base}{path}")
        if ck:
            req.add_header("Cookie", f"sb_session={ck}")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()[:200]
        except urllib.error.HTTPError as e:
            return e.code, e.read()[:200]

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    probe = f"/m5probe-{int(time.time())}"

    print("\n── ① 页面请求 → 明细行（allow）─────────────────────")
    st, _ = get(probe)
    check(st in (200, 404), f"页面请求发出（HTTP {st}）", str(st))
    row, waited = wait_for_row(ddb, events_table, site_id, day, probe)
    check(row is not None, f"明细行出现（轮询等待 ≤30s，实际 {waited}s）",
          "超时未出现" if row is None else "")
    if row:
        check(row["decision"]["S"] == "allow", "decision == allow",
              row["decision"]["S"])
        check("@" in row["email"]["S"], "email 是已验签的邮箱（非空）",
              row["email"]["S"][:3] + "…")
        check(row["path"]["S"] == probe, "path 是用户看到的路径（不是桶内 key）",
              row["path"]["S"])
        ttl_days = (int(row["expires_at"]["N"])
                    - int(datetime.now(timezone.utc).timestamp())) / 86400
        check(89 < ttl_days <= 91, "TTL 约 90 天", f"{ttl_days:.1f} 天")

    print("\n── ② 负测 + 正对照：静态资源不记 ───────────────────")
    css = f"/m5probe-{int(time.time())}.css"
    get(css)
    row_css, _ = wait_for_row(ddb, events_table, site_id, day, css, timeout=8)
    check(row_css is None, "带扩展名的资源请求**没有**产生明细行", "")
    # 正对照：同一时刻的页面请求确实产生了行 ⇒ 上面那条不是因为埋点没部署
    probe2 = f"/m5probe2-{int(time.time())}"
    get(probe2)
    row2, _ = wait_for_row(ddb, events_table, site_id, day, probe2)
    check(row2 is not None,
          "正对照：同一时刻的页面请求确实产生了行（否则上一条是空转）", "")

    print("\n── ③ 未登录 → redirect_login ──────────────────────")
    probe3 = f"/m5probe3-{int(time.time())}"
    st, _ = get(probe3, ck="")
    check(st in (302, 200), f"未带 cookie 的请求（HTTP {st}）", str(st))
    row3, _ = wait_for_row(ddb, events_table, site_id, day, probe3)
    if row3:
        check(row3["decision"]["S"] == "redirect_login",
              "decision == redirect_login", row3["decision"]["S"])
        check(row3["email"]["S"] == "", "未登录时 email 是空串（不是哨兵值）",
              repr(row3["email"]["S"]))
    else:
        check(False, "未登录请求的明细行出现", "超时未出现")

    print("\n── ④ rollup → 聚合行 ─────────────────────────────")
    yday = (datetime.now(timezone.utc).timestamp() - 86400)
    yday_s = datetime.fromtimestamp(yday, timezone.utc).strftime("%Y-%m-%d")
    resp = lam.invoke(FunctionName="site-access-rollup",
                      Payload=json.dumps({"days": [day, yday_s],
                                          "sites": [site_id]}).encode())
    out = json.loads(resp["Payload"].read())
    check(resp.get("FunctionError") is None,
          "rollup 调用成功", str(out)[:120])
    agg = ddb.get_item(TableName="site-access-daily",
                       Key={"site_id": {"S": site_id}, "date": {"S": day}},
                       ConsistentRead=True).get("Item")
    check(agg is not None, "聚合行出现", "")
    if agg:
        check(int(agg["pv"]["N"]) >= 2, "聚合 pv 覆盖了本轮的页面请求",
              agg["pv"]["N"])
        check(int(agg["pv_denied"]["N"]) >= 1, "聚合 pv_denied 记下了未登录那次",
              agg["pv_denied"]["N"])

    print("\n── ⑤ 不在名单 → denied_403（带已验签邮箱）──────────")
    # 这一段需要一个**有会话但不在该站点名单**的身份。没有第二个身份时不猜、
    # 不伪造——但也不能就这么跳过（永久 SKIP 是死重量，§3.6）：改成换一个
    # **观察量**——用同一身份请求一个自己无权访问的站点。
    other = input("一个你**无权访问**的 ACTIVE 站点 site_id（留空则跳过 ⑤）: ").strip()
    if other:
        probe4 = f"/m5probe4-{int(time.time())}"
        st, _ = get(probe4.replace(probe4, probe4), ck=cookie)  # 同 cookie
        import urllib.request as _u
        req = _u.Request(f"https://app-{other}.{base}{probe4}")
        req.add_header("Cookie", f"sb_session={cookie}")
        try:
            with _u.urlopen(req) as r:
                st4 = r.status
        except urllib.error.HTTPError as e:
            st4 = e.code
        check(st4 == 403, f"无权站点返回 403（实际 {st4}）", str(st4))
        row4, _ = wait_for_row(ddb, events_table, other, day, probe4)
        if row4:
            check(row4["decision"]["S"] == "denied_403",
                  "decision == denied_403", row4["decision"]["S"])
            check("@" in row4["email"]["S"],
                  "被拒记录带**已验签**邮箱（"谁被拒了"是这条记录的全部价值）",
                  row4["email"]["S"][:3] + "…")
        else:
            check(False, "denied_403 的明细行出现", "超时未出现")
    else:
        print("  SKIP  ⑤（没有第二个站点可用）——**这不是通过**，"
              "MIN_CHECKS 会因此不达标而报红")

    print("\n── ⑥ 平台子域不产生记录（负测 + 正对照）──────────")
    import urllib.request as _u2
    cprobe = f"/m5cprobe-{int(time.time())}"
    try:
        rq = _u2.Request(f"https://console.{base}{cprobe}")
        rq.add_header("Cookie", f"sb_session={cookie}")
        with _u2.urlopen(rq) as r:
            pass
    except Exception:
        pass          # 404/403 都无所谓，我们只看有没有产生明细行
    found = False
    for probe_site in ("console", site_id):
        r, _ = wait_for_row(ddb, events_table, probe_site, day, cprobe, timeout=6)
        found = found or (r is not None)
    check(not found, "console 子域的请求**没有**产生任何明细行（app- 前缀判定）", "")
    # 正对照已在 ② 段给过（同一时刻的页面请求确实产生了行），此处复用其结论

    print("\n── ⑦ 面板 API 与 MCP 返回同一个数字（**自动比对**）────")
    # 上一版这里只 print 一行"手工核对"就 return 0（Codex 审查 P1-3）——
    # 于是 spec §5.1 承诺的"面板与 MCP 返回同一数字"从未被闸门验证，
    # 而 MIN_CHECKS 光靠 ①-④ 就能达标 ⇒ MCP 完全不可用时本脚本照样 exit 0。
    agg_pv = int(agg["pv"]["N"]) if agg else -1

    console_cookie = input("粘一个 __Host-sb_console cookie 值（面板会话）: ").strip()
    if console_cookie:
        rq = _u2.Request(f"https://console.{base}/api/sites/{site_id}"
                         "/analytics?period=day&n=2")
        rq.add_header("Cookie", f"sb_session={cookie}; "
                                f"__Host-sb_console={console_cookie}")
        try:
            with _u2.urlopen(rq) as r:
                pbody = json.loads(r.read())
            pv_today = next((b["pv"] for b in pbody.get("series", [])
                             if b["bucket"] == day), None)
            check(pv_today is not None, "面板 analytics 返回了今天的桶",
                  str([b["bucket"] for b in pbody.get("series", [])]))
            check(pv_today == agg_pv,
                  f"面板 PV == 聚合行 PV（{pv_today} vs {agg_pv}）",
                  f"面板 {pv_today} / 聚合 {agg_pv}")
            check(len(pbody.get("series", [])) == 2,
                  "n=2 返回恰好 2 个桶（日历对齐契约）",
                  str(len(pbody.get("series", []))))
        except Exception as e:
            check(False, "面板 analytics 可调用", f"{type(e).__name__}: {e}")
    else:
        check(False, "面板 analytics 已核对",
              "没给面板会话 cookie —— 未验证，不计为通过")

    # MCP：走**真实调用路径**（不手构造参数，§5.4）。
    #
    # 复用 `verify_api_key_e2e.py:184` 的 `class Mcp`——**不要在本文件重写一个**
    # （两份 OAuth/token 逻辑必然漂移）。它的 `call_tool(name, args, *,
    # expect="dict"|"list") -> (ok, payload)`：`expect` **必须由调用方声明**，
    # 因为线上这台 server 不发 `structuredContent`，自动猜返回形态在一半情况下
    # 会静默少数据（M4-FINDINGS §3.4）。
    #
    # 本 Task 的前置一步：把 `class Mcp` 与它的 token 获取从
    # `verify_api_key_e2e.py` 提到 `site-builder/scripts/_mcp_client.py`，
    # 两个闸门都 import 它（提取后 verify_api_key_e2e 必须重跑确认仍 34/34）。
    print("  MCP：调 get_site_analytics 并与聚合行比对")
    try:
        sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
        from _mcp_client import Mcp, user_token, mcp_endpoint
        m = Mcp(mcp_endpoint(), {"authorization": f"Bearer {user_token()}"})
        ok, payload = m.call_tool("get_site_analytics",
                                  {"site_id": site_id, "period": "day",
                                   "days": 2}, expect="dict")
        check(ok, "MCP get_site_analytics 调用成功", str(payload)[:120])
        if ok:
            check(isinstance(payload, dict),
                  "MCP 工具返回单个 dict（不是裸列表，§3.4）",
                  type(payload).__name__)
            mpv = next((b["pv"] for b in payload.get("series", [])
                        if b["bucket"] == day), None)
            check(mpv == agg_pv, f"MCP PV == 聚合行 PV（{mpv} vs {agg_pv}）",
                  f"MCP {mpv} / 聚合 {agg_pv}")
    except Exception as e:
        # 不 SKIP：MCP 不可用正是 P1-2 的症状，必须红
        check(False, "MCP get_site_analytics 可调用", f"{type(e).__name__}: {e}")

    return 0


if __name__ == "__main__":
    rc = 1
    crashed = ""
    try:
        rc = main()
    except Exception as exc:              # noqa: BLE001
        import traceback
        traceback.print_exc()
        # 必须记在 finally 之外：只置 rc=1 会被下面按"项数够了"重算成 0
        # （verify_deployed_components 踩过，2026-08-08 独立审查复现）
        crashed = f"{type(exc).__name__}: {exc}"
        rc = 1
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        print()
        if crashed:
            print(f"结果：执行中断（{crashed}）—— 验收**未完成**，状态不可信")
            rc = 1
        elif len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）"
                  "—— 验收**未完成**，状态不可信")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else ""))
            rc = 1 if failed else 0
    sys.exit(rc)
```

- [ ] **Step 2: 语法与全角引号检查**

```bash
cd "$(git rev-parse --show-toplevel)" && python3 -m py_compile site-builder/scripts/verify_analytics_e2e.py && echo OK
```

- [ ] **Step 3: Commit**（真机跑在 Task 15）

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/scripts/verify_analytics_e2e.py
git commit -m "test(m5): verify_analytics_e2e——走到 panel 与 MCP，自动比数字

初版只到聚合行就 print 一行"手工核对"然后 return 0（Codex 审查 P1-3）：于是
spec §5.1 承诺的"面板与 MCP 返回同一数字"从未被闸门验证，而 MIN_CHECKS 光靠
前四段就能达标 ⇒ **MCP 完全不可用时本脚本照样 exit 0**。现在两侧都自动调用并
与聚合行逐个比对，未能核对一律记 FAIL 而不是 SKIP。

三种 decision 现在真的各验一次（初版只验了 allow 与 redirect_login，而提交
信息声称三种都验——那是一句假话）。另补 console 子域不产生记录的负测。

轮询等待明细行（Global Table 复制异步、无 SLA）：立刻断言会做出 flaky 闸门。
异常记在 finally 之外，避免被"项数够了"重算成 exit 0。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: 部署与真机验收

**Files:** 无代码改动（除 Step 5 可能的回落修正）

**顺序不可换**（spec §2.4）：表必须先于 Edge 存在。反了的话写失败被吞掉，
症状是「部署全绿、零数据」。

- [ ] **Step 1: 部署 deployer 栈（建两张表 + rollup）**

```bash
cd site-builder/deployer/infra && \
  rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

**读回被改的属性，不看 StackStatus**（§3.13）：

```bash
aws dynamodb describe-table --table-name site-access-events \
  --query 'Table.[TableStatus,Replicas[].RegionName]' --output json
aws dynamodb describe-table --table-name site-access-daily \
  --query 'Table.[TableStatus,DeletionProtectionEnabled]' --output json
aws events describe-rule --name site-access-rollup-daily --query '[State,ScheduleExpression]'
```

预期：events 表 ACTIVE 且 Replicas 含 `ap-southeast-1` + `ap-northeast-1`；
daily 表 ACTIVE 且 `DeletionProtectionEnabled=true`；规则 ENABLED。

- [ ] **Step 2: 部署 Edge（版本 8，含区域探测）**

```bash
cd router/infrastructure && \
  rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

**必须 `rm -rf cdk.out`**（改过 config.ini，否则用陈旧 asset）。
等 10-20 分钟全球复制。

- [ ] **Step 3: 读回 `AWS_REGION` 的探测结果（spec §0.4 第 1 步）**

发一次页面请求后，读三个区的 Edge 日志找那行 `[WARN]`／探测输出：

```bash
for rg in ap-southeast-1 ap-northeast-1 us-east-1; do
  echo "== $rg"
  aws logs filter-log-events --region $rg \
    --log-group-name /aws/lambda/us-east-1.ApplicationWebRouterStack-application-web-router \
    --start-time $(( ($(date +%s) - 900) * 1000 )) \
    --filter-pattern '"m5-region"' --query 'events[-3:].message' --output text
done
```

> 探测输出：在 `_access_region` 里加一行
> `print(f"[INFO] m5-region env={os.environ.get('AWS_REGION')!r} arn={getattr(context,'invoked_function_arn','')!r} -> {region}")`
> 部署一次读完后**保留**（它是判断"副本在用还是一直回落"的唯一线上证据，
> 且不含任何敏感值）。

- [ ] **Step 4: 判定并记录**

- 若 `env` 有值且等于执行区 → 副本路径生效，记进 HANDOFF；
- 若 `env` 为 `None` 而 `arn` 能解析出区 → 走的是第二候选，同样生效；
- 若两者都拿不到 → **回落在用**，埋点是跨区 229ms。这不是故障（数据完整），
  但 §0.4 的收益没拿到——**据实记录，不要写成"已优化"**。

- [ ] **Step 5: 部署 panel 与 MCP**

```bash
cd site-builder/panel && python3 deploy_panel.py
cd site-builder/mcp && python3 deploy_agentcore.py
```

> `deploy_panel.py` **不要带 `--skip-frontend`**（本轮改了前端；带上会保留旧
> 前缀 = 统计页不上线）。

- [ ] **Step 6: 跑全部真机闸门**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_analytics_e2e.py          # 新增，≥24 项
python3 site-builder/scripts/verify_deployed_components.py     # 应为 71/71
python3 site-builder/scripts/verify_console_e2e.py             # ⑪ 段 7 条
bash    site-builder/scripts/verify_deployed_edge.sh           # 版本 8
bash    site-builder/scripts/smoke_router.sh
python3 site-builder/scripts/verify_permission_matrix.py
python3 site-builder/scripts/verify_oauth_and_impersonation.py
```

全绿才算过。任一红先修再继续，**不要往下走**。

- [ ] **Step 7: 人工点一次控制台**

打开 `https://console.{base_domain}` → 某站点 → 「访问统计」页签。确认：
趋势表有数、明细表有数、超窗口的桶显示 `—` 而不是 `0` 或 `null`。

> 顺带把 M4 遗留的两项人工核对做掉：「吊销 Key」与「移除管理员」（HANDOFF
> 更新 12 的挂着建议项 3）。

- [ ] **Step 8: Commit**（若 Step 4 需要修回落逻辑）

若无代码改动则跳过；有则单独一个 fix 提交并说明真机判定依据。

---

## Task 16: 日志组保留期（**有损操作，先确认**）

**Files:** 无（AWS 侧操作 + DEPLOY.md 记录）

spec §0.3 的实测清单。**把 90 天收敛到 30 天会标记删除 30-90 天窗口的日志**
——DEPLOY.md 已记过这个坑。

- [ ] **Step 1: 复核现状（数字可能已变）**

```bash
for rg in us-east-1 ap-southeast-1 ap-northeast-1; do
  echo "== $rg"
  aws logs describe-log-groups --region $rg \
    --query "logGroups[?retentionInDays==null].[logGroupName]" --output text | grep -E "site-|ApplicationWebRouter"
done
```

- [ ] **Step 2: 先问用户，再动**

把「未设保留期的」与「90 天要收敛到 30 天的」分成两组报给用户。
**第一组（未设 → 30 天）是纯增益**，无损；**第二组是有损的**，必须先确认
30-90 天窗口内的日志无排查/审计价值。**没得到确认就只做第一组。**

- [ ] **Step 3: 执行（只对已确认的组）**

```bash
aws logs put-retention-policy --region <rg> --log-group-name <name> --retention-in-days 30
```

- [ ] **Step 4: 读回核对**

```bash
aws logs describe-log-groups --region <rg> --log-group-name-prefix <name> \
  --query 'logGroups[].[logGroupName,retentionInDays]' --output text
```

- [ ] **Step 5: 记进 DEPLOY.md**（哪些改了、哪些按用户决定没改、为什么）

---

## Task 17: 文档与全量回归

**Files:**
- Modify: `site-builder/DEPLOY.md`（新增 ⑤d 章节 + 部署顺序）
- Modify: `CLAUDE.md`（架构图 + 高频坑各一条）
- Modify: `docs/design/HANDOFF-2026-08-07.md`（**新增一节**，gitignored）
- Create: `.superpowers/sdd/2026-08-14-phase2-m5-analytics/progress.md`（gitignored）
- Modify: `docs/design/M4-FINDINGS.md` 或新建 `M5-FINDINGS.md`（gitignored）

- [ ] **Step 1: 七包 + 锁定依赖全量回归**

```bash
cd site-builder/contract  && .venv/bin/pytest tests -q
cd site-builder/auth      && ../contract/.venv/bin/pytest tests -q
cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q
cd site-builder/deployer  && .venv/bin/pytest tests -q
cd site-builder/mcp       && python3 -m pytest tests -q
cd site-builder/panel     && ../deployer/.venv/bin/pytest tests -q
cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q
bash site-builder/mcp/run_locked_tests.sh
```

记下每包的项数（HANDOFF 用）。

- [ ] **Step 2: `DEPLOY.md` 加 ⑤d**

内容要点：两张表由 deployer 栈建；**顺序 = 表先于 Edge**（反了的症状是"部署
全绿、零数据"，因为写失败被吞掉）；Edge 改动要 10-20 分钟全球复制；
`deploy_panel.py` 改了前端**不能带 `--skip-frontend`**；副本清单三处一致
（config.ini / CDK / Edge 常量）；`verify_analytics_e2e.py` 的跑法。

- [ ] **Step 3: `CLAUDE.md` 两处**

架构图的 ④ 层补一行「origin-request 顺带写一行访问明细（只页面级、只 `app-` 前缀）」；
高频坑加一条：

```markdown
- **统计埋点的超时预算不能按同区算**：Edge 写本区副本是 6ms（冷 58ms），但
  回落路径是跨区 229ms（冷 **719ms**，实测）。预算的下限由回落决定；收紧到
  「够本区用」就等于让回落路径静默丢行。埋点异常一律吞掉（统计不是安全控制），
  所以丢行是**无声的**。
```

- [ ] **Step 4: HANDOFF 新增一节**

写：M5 完成状态、闸门数字（**本文件是这些数字的真源**）、线上现状（副本区、
`AWS_REGION` 探测结论、Edge 版本 8、panel 前端前缀）、提交计数与范围、
遗留项。

- [ ] **Step 5: 一致性核对（有没有回退）**

```bash
cd "$(git rev-parse --show-toplevel)"
git log --oneline 4302a15..HEAD | wc -l          # M5 的提交数
git status --short                                # 必须干净
# 八个真实值逐一确认不在被跟踪文件里（按 M4 的收尾形态）
```

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/DEPLOY.md CLAUDE.md
git commit -m "docs(m5): 部署顺序、埋点超时预算的坑、架构图补埋点

顺序是硬依赖：表必须先于 Edge，反了的症状是"部署全绿、零数据"（写失败被
吞掉）。超时预算那条记进高频坑——它的下限由跨区回落的 719ms 决定，不是由
同区 58ms 决定，而丢行是无声的。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Codex 审查（2026-08-14）的处置记录

审查锚定 `4302a15..d6397ee`。**9 条：接受 8 条、部分接受 1 条；另有 3 条是
它没发现、我实测出来的。** 每条都实测核实过，不是照单全收。

| # | 判定 | 落在哪 | 实测依据 |
|---|---|---|---|
| P1-1 `/api/*` 被当页面 | 完全接受 | Task 3（+ 3 条回归用例 + 反向验证 ④） | 用**真实 `_route_request`** 跑对照：错 2 条；加 `/api/` 守卫后 10 条全对 |
| P1-2 MCP 无 `analytics.py` | 完全接受 | Task 8（迁到 `deployer/functions/`）+ Task 11（三份清单 + 新守卫） | Dockerfile 实测只 COPY 四个文件 |
| P1-3 E2E 不调 panel/MCP | 完全接受 | Task 14（自动比数字，MIN_CHECKS 14→24） | 17 个 `check(` 全在 ①-④，下限可在零个 panel/MCP 断言下达标 |
| P1-4 IAM 闸门不比 ARN | 完全接受 | Task 13（逐字比 + 读 attached） | 原实现只 `puts |= set(acts)`，从未比对资源 |
| P2-1 sink 时机 → 302 带 email | 完全接受 | Task 3（+ 一条 302 无邮箱的负测） | 按计划插入后实测 `status=302, sink={'email': ...}` |
| P2-2 week/month 给 n+1 桶 | 完全接受 | Task 8（日历对齐 + 零填充 + 2 条用例） | 五种参数**全错**：`month n=1`→2 个、`n=2`→3 个、`week n=4`→5 个 |
| P2-3 漏了列表迷你趋势 | 完全接受 | **新增 Task 9b** | 母 spec §11-clarify **与** M3 spec 第 64 行都列了；原型里 `pv7`×6、`sparkline`×4 |
| P2-4 两组 CDK 断言无效 | 完全接受 | Task 4（config 账号字面量）+ Task 6（按逻辑 ID 匹配、删恒真式） | 实测 `self.account`→`Fn::Join` dict；`table_arn`→`Fn::GetAtt`，policy 里无表名字面量 |
| P2-5 host-local 路径 | **部分接受** | 全局改成仓库相对 / `git rev-parse` | 接受要改：M3/M4 计划里 `/Users/kentpeng` 各 **0** 次，我 69 次破坏惯例。**驳回它的定性**——那不是凭证，且它引的「本轮 AGENTS.md」在本仓库**不存在**（`ls AGENTS.md` → No such file）。按惯例改，不按 secret-scan 改 |

### Codex 没发现的三条（我实测出来的）

1. **`TableV2` + `replicas` 在 region-agnostic 栈里直接 synth 抛错**
   （`ReplicaTablesNotSupportedInRegionAgnosticStack`），而
   `test_infra_tables.py:46` 建栈**没传 env**。后果比 P2-4 更重：不是"断言无效"，
   是**整个文件连 RETAIN 不变量一起崩**，且 Task 2 的 Step 4 永远不可能通过。
   → Task 2 加了 **Step 0** 先修 fixture。
2. **Task 13 的注释「主区不出现在 `Replicas` 里」是错的**——模板实测
   `Replicas` **包含** `us-east-1`。并集写法本身没错，注释错了（而下一个人会
   照注释改）。→ 改成并集 + 写明"运行时行为本轮未实测"。
3. **Task 4 的命令写 `python3.13`，router venv 实际是 `python3.12`**
   （仓库自己的 docstring 也是这个错）→ 三处已改，并加 Step 5b 顺手修仓库。

另外**我自己引入的一处假引用**：Task 14 里写 `from mcp_call import call_tool`
——那个模块**不存在**，真实封装是 `verify_api_key_e2e.py:184` 的 `class Mcp`
（方法签名 `call_tool(name, args, *, expect) -> (ok, payload)`）。已改成先提取
到 `_mcp_client.py` 再两处共用，并要求提取后重跑 `verify_api_key_e2e` 确认
仍 34/34。

### 这轮审查暴露的一个方法论问题（记进 M5-FINDINGS）

我的 self-review 声称「spec 21 个小节逐条映射、无遗漏」——**核对的只是我自己
那份 spec**。P2-3 恰好落在它的盲区：一个上级文档已经划定的交付边界，不在我
自己的小节清单里，所以"逐条映射"全绿而范围少了一块。
**判据**：范围核对的基准必须是**上级文档的交付清单**，不能是自己写的那份
spec 的目录——后者天然自洽。

---

## Self-Review 记录

**1. spec 覆盖核对**

| spec 小节 | 落在哪个 Task |
|---|---|
| §0.4 三步落地顺序 | Task 3（回落逻辑）· Task 4（IAM/占位符）· Task 15 Step 2-4（探测与判定） |
| §0.3 日志组保留期 | Task 16 |
| §1.1 明细表 | Task 2 |
| §1.2 聚合表 | Task 2 |
| §1.3 保留期 | Task 3（90d TTL）· Task 5（400d TTL） |
| §1.4 跨月 UV 边界 | Task 8（`uv_exact`）· Task 9（前端标注） |
| §2.1 `app-` 前缀 | Task 3 |
| §2.2 页面级判定 | Task 3 |
| §2.3 六条规矩 | Task 3（1/2/3/4/5/6 全部） |
| §2.4 IAM 与跨栈 | Task 4 |
| §3.1 面板 API | Task 8 |
| §3.2 权限 | Task 7 |
| §3.3 rollup | Task 5（逻辑）· Task 6（接线） |
| §3.4 MCP 工具 | Task 10 · Task 11（进镜像） |
| §3.6 端点命名偏移（申报） | 已记入 spec，无需 Task |
| §3.5 前端（含列表 `pv7` 迷你趋势） | Task 9 · **Task 9b** |
| §4.1 ⑪ 段 | Task 12 |
| §4.2 前端守卫 | Task 9 Step 1 |
| §4.3 缓存断言 | Task 4 |
| §5.1 闸门 | Task 13 · Task 14 · Task 15 Step 6 |
| §5.2 单测 | Task 2/3/5/6/7/8/9/10/11 各自的 Step 1 |
| §5.3 反向验证 | 每个 Task 的 Step 5 |
| §6 资源清单 | Task 11（部署脚本）· Task 17（文档） |

**无遗漏**。M4-FINDINGS 补条目（spec §5.4 提到的）= Task 1。
**另核对上级文档**（这次才补上的一步）：母 spec §11-clarify 的 M5 清单
= stats/audit 数据（Task 2/3/5）· 两个端点（Task 8）· 图表（Task 9）·
**站点列表 PV 迷你趋势（Task 9b）**；端点命名偏移已在 spec §3.6 申报。

**2. 占位符扫描**：无 TBD/TODO。三处「先 grep 确认真名」是**明确的一步动作**
（`ENV` 字典名、`escapeHtml` 函数名、`outsider_site` 变量名），不是"自行斟酌"。

**3. 类型一致性**

- `day_stats(rows) -> {"pv","uv","pv_denied"}`：Task 5 定义，Task 8 `import` 同一份（有断言 `analytics.day_stats is access_rollup.day_stats`）。
- `series(...) -> list[{"bucket","pv","uv","pv_denied","uv_exact"}]`：Task 8 定义 → Task 9 前端 → Task 10 MCP → Task 12 闸门断言，四处字段名一致。
- `visitors(...) -> {"rows":[{"ts","email","path","decision"}], "next"}`：Task 8 定义 → Task 9/12 一致（Task 12 断言"恰好四个字段"）。
- `decision` 三个字面量 `allow`/`denied_403`/`redirect_login`：Task 3 产生 → Task 5 聚合 → Task 9 中文标签 → Task 14 闸门，四处一致。
- 表名 `site-access-events`/`site-access-daily`：Task 2 定义，Task 4/5/6/11/13/14 引用，一致。
- 副本清单：**唯一真源在 `router/config.ini`**，Task 2（CDK）与 Task 3（Edge 常量）各自引用，Task 4 的断言从它推导比对——三处一致由测试锁死。
