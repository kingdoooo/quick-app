# 3g：信任边界闸门的 `replace-platform-code` 模型对齐（共享判定模型 + schema 7）

状态：spec 已冻结，待实施。来源条目：`docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 第 3g 行。
本 spec 随仓库分发（tracked）：它冻结的是**资产**里的判定模型与迁移协议，不是本验证环境的操作记录。

## 1. 缺陷与本轮核验后的修正

§9 3g 的原始条目说：闸门 `site-builder/scripts/verify_account_trust_boundary.py` 把"谁能替换平台代码"
只建模成 `lambda:UpdateFunctionCode` 一个动作（`A_REPLACE`），两个方向都错，修法是"判据与
`scripts/probe_impersonation_surface.py` 的 `classify()` 一致"。

**逐项核验的结果（2026-09-20，静态读码 + botocore 服务模型 + AWS 文档；真机计数未重测）**：

| §9 的说法 | 核验结论 |
|---|---|
| 闸门只模拟 `UpdateFunctionCode` | **成立**。`A_REPLACE = ("lambda:UpdateFunctionCode",)`，grant 在 `grants_from_decisions` 里对**每个**平台函数发出，而 `platform = platform_function_names() + EDGE_FUNCTIONS` ⇒ `replace-platform-code:<edge fn>` 确实会被记 |
| 对 Edge 过度声称 | **成立**（CloudFront 关联编号版本，该动作只改 `$LATEST`） |
| 对**站点函数**过度声称 | **不成立于闸门**：闸门只对 `t.platform_functions` 发 `replace-platform-code`，站点函数只记 invoke 类 grant。站点函数被 alias 钉住这件事是对的，但闸门今天没有那条 grant 可错。**照抄这条去"修"会改错地方** |
| 少算 `UpdateStack` / change-set / `Publish=True` | **成立**（闸门的 `ACTIONS` 里没有任何 CFN / CloudFront / `PassRole` / `UpdateFunctionConfiguration` 动作） |
| 修法 = 对齐 `probe.classify()` | **不成立于现状**：probe 的模型自己有两处已过期/失真（§1.1），"复制当前 probe 即正确"是错的。不变量必须写成**两边共用同一份经反例验证的模型** |

### 1.1 probe 现有模型的三处缺陷（对齐之前必须先修）

1. **CFN 前提已过期。** `classify()` 把 `cloudformation:UpdateStack|<stack>` 单动作直接判成
   `edge:cfn-update-stack`，源码注释写着"router 栈已关联 CFN service role 且**无 stack policy**"。
   ADR 0007（accepted 2026-09-07）记录 router 栈**已**设 stack policy，对四个精确逻辑 ID（Edge 两函数、
   CloudFront 分发、路由表）`Deny Update:*`，越过它的门槛变成 `cloudformation:SetStackPolicy`。
   ADR 0007 的 Consequences 自己就写了："§9 3f 与 spec §1 表里的'−4'要在冒充面探针加上
   `cloudformation:SetStackPolicy` 这个等价类之后重算"——那一步至今没做。
2. **代码更新与配置更新不等价。** `LAMBDA_CODE_EXEC` 把 `UpdateFunctionCode` 与
   `UpdateFunctionConfiguration` 合成一类，于是"只有 `UpdateFunctionConfiguration(Edge)` +
   `UpdateDistribution`"会产出 `edge:code(Publish=True)+associate`。两条独立证据都否掉它：
   - **API 形态**：`UpdateFunctionCode` 的输入含 `Publish`，`UpdateFunctionConfiguration` **没有**
     （botocore 1.43.53 服务模型实测）⇒ 配置更新不具备"一次调用即改码即发版本"的能力；
   - **Lambda@Edge 不支持 Layers**（AWS 文档《Restrictions on Lambda@Edge》原文列出
     "Lambda functions with layers"为不支持）⇒ auth/panel 那条"改配置挂 Layer 遮蔽模块 = 任意代码执行"
     的理由**不能**平移到 Edge。对 Edge 而言 `UpdateFunctionConfiguration` 改的是 `$LATEST` 的配置，
     而 CloudFront 服务的是编号版本 ⇒ 单独持有它**不产生任何标签**。

3. **"新建函数再关联"那条路的前提过严。** `classify()` 要求 `CreateFunction` **且**
   `PublishVersion` 都在候选 ARN 上成立。但 `CreateFunction` 的输入**含 `Publish`**
   （botocore 1.43.53 服务模型实测，与 `UpdateFunctionCode` 同形）⇒ 一次调用即建即发版本，
   不需要单独的 `PublishVersion`。这是一处**少算**：只持 `CreateFunction` + `PassRole` +
   `UpdateDistribution` 的 principal 今天不会被记上任何标签。

### 1.2 两边都漏的一条：deployer 栈

probe 只把 router 栈当 CFN 路径。**deployer 栈是第二条，且今天没有 stack policy**：两把会话签名 CMK
由它创建（`site-builder/deployer/infra/app.py` 的 `kms.Key(self, "SiteSessionKeyRsV1", …)` /
`…ConsoleSessionKeyRsV1`，`removal_policy=RETAIN`），栈还直接管理 PermissionsBoundary 与执行器角色。
**措辞必须准确**：per-site 运行时角色是 `deployer/functions/common.py` 的 `ensure_site_role()` 在运行期用
boto3 幂等创建的，**不由 CFN 拥有**；栈拥有的是 boundary、执行器角色与两把 CMK。

"拥有 CMK ∧ 无 stack policy"**还不足以**推出"能改 key policy"：要看这次 UpdateStack 以谁的身份执行
（`DescribeStacks[].RoleARN` 关联的 service role，或调用方自己）以及那个身份是否真能
`kms:PutKeyPolicy`。**前提未核实时不给确定结论**（§4.3 的三值规则）。

## 2. 冻结的不变量

1. **一种能力 = 一个动作等价类 × 一个资源等价类**（闸门与 probe 的既有不变量，本轮继续）。
2. **两边共用同一份经反例验证的模型**，由各自的采集层提供观测数据。不是"闸门复制 probe"，
   也不是"probe 复制闸门"。
3. **grant 层表达"持有哪些授权"，能力层表达"这些授权能组成哪些路径"。** 两层都进基线、都参与红绿；
   grant 层**不得**被能力层取代（压平成布尔标签的错误已经犯过三次，每次都产生一个当时看不出的
   false-green）。
4. **前提未核实 ⇒ 不出确定结论。** 模型的每条路径都有可观测前提；前提是三值的
   （已确认 / 已确认相反 / 未知），未知不得按"否"解释。
5. **裁剪掉的资源是"未覆盖"，不是 deny。** 模拟不问的 (动作, 资源) 组合不得进入任何"他不能"的结论。
6. **采集层的既有硬保证不得为了对齐而放弃**：分页、`kms:MessageType` 的 RAW/DIGEST 两腿与合同值
   上下文、`merge_allowed` 取并集、模拟失败即硬失败、枚举—模拟窗口两端一致性复查、
   观测分节缺失即拒（`BUNDLE_SHAPE` 递归默认拒绝）。

## 3. 非目标（写进代码注释，防止下一轮"顺手统一"）

- **不造 IAM 权限分析器**：不求值 Condition、不做 statement 归因、不算 `NotResource` 集合代数、
  不追 AssumeRole/PassRole 传递闭包。模型只把**已模拟出的 (动作, 资源) 判定**与**已观测的资源事实**
  组合成命名路径。B 层（IAM 写静态快照）的承诺不变。
- **不声称冒充面已穷尽**。A 组的判定是**下界**，本轮新增两块明确的未分析范围（§9）。
- **不主张任何"收益 −N"的数字**（ADR 0007 已经要求不主张，本 spec 不撤销）。
- 不改 3e（站点 alias / 活跃色完整性）——它归部署验收，单独排期，且本轮不给 3e 打完成勾。

## 4. 共享判定模型

新建 `site-builder/scripts/_impersonation_model.py`：**纯函数模块，零 AWS 依赖、零 config 读取**
（`probe --self-test` 与闸门的纯函数路径都必须能在没有 boto3 / cryptography 的解释器上 import）。
probe 与闸门都 import 它。

> **为什么不是"闸门 import probe"**：probe 已经用 `importlib` 动态加载闸门模块
> （`probe_impersonation_surface.py` 的 `GATE` / `spec_from_file_location`）⇒ 反向 import 成环。

### 4.1 输入：观测事实，不是假设

```python
FnEntry   = Literal["latest", "alias", "version", "unknown"]
StackGuard = Literal["protected", "open", "unknown"]

@dataclass(frozen=True)
class FnFact:
    arn: str
    entry: FnEntry            # 入口服务的是 $LATEST / alias / 编号版本 / 观测不到
    layers_supported: bool    # Lambda@Edge 为 False（AWS 文档）

@dataclass(frozen=True)
class StackFact:
    resource: str             # 真实 StackId（模拟用；不落基线、不落文档）
    label: str                # "router" / "deployer"，逻辑标签，进 grant 串
    guard: StackGuard         # 见 §4.3
    service_role: str | None  # DescribeStacks[].RoleARN；None = 以调用方身份执行
    controls: frozenset[str]  # 观测得到的受控对象：{"edge-verifier"} / {"session-key"} …
    premises_verified: bool   # 该栈那条路径的全部前提是否都已核实
```

`entry` **不得**默认成 `latest`：查不到 alias、查不到 CloudFront association 都是 `unknown`。
`controls` 由 `DescribeStackResources` 观测（Edge 两函数 / 分发 / 两把 CMK 的物理 ID 是否属于该栈），
不由栈名或代码推断。

### 4.2 标签词表

签名侧（`sign:`）与 verifier 替换侧（`edge:`）两类都是冒充，冒充面 = 并集。

| 标签 | 成立条件 | 进冒充面 |
|---|---|---|
| `sign:kms-direct` | `kms:Sign` on 任一把 CMK | ✅ |
| `sign:kms-self-authorize` | `kms:PutKeyPolicy` / `kms:CreateGrant` on 任一把 CMK | ✅ |
| `sign:hijack-auth-signer` | `UpdateFunctionCode` on auth，**或** `UpdateFunctionConfiguration` on auth 且 `layers_supported` | ✅ |
| `sign:hijack-panel-signer` | 同上，panel | ✅ |
| `sign:fixture-issuer` | `InvokeFunction` on auth，或角色名 == 夹具签发器 | ❌ 单列（受限冒充，沿用既有待遇） |
| `sign:cfn-session-key-stack` | 拥有 CMK 的栈上（`controls ∋ session-key`）持 CFN 更新链 ∧ `guard == "open"` ∧ `premises_verified` | ✅ |
| `sign:cfn-session-key-stack-unanalyzed` | 同上但 `premises_verified` 为假，或 `guard == "unknown"` | ❌ 单列 |
| `edge:code(Publish=True)+associate` | `UpdateFunctionCode` on Edge ∧ `UpdateDistribution`（**不含** `UpdateFunctionConfiguration`） | ✅ |
| `edge:code+publish+associate` | 上一条 ∧ `PublishVersion` on Edge | ✅ |
| `edge:new-function+associate` | `CreateFunction` on 候选 ARN ∧ `PassRole` on edge role ∧ `UpdateDistribution`。**`PublishVersion` 不是前提**——`CreateFunction` 自带 `Publish`（§1.1 第 3 条） | ✅ |
| `edge:cfn-update-stack` | `UpdateStack` on 控制 Edge 的栈 ∧（`guard == "open"` ∨ 持 `SetStackPolicy` 同栈）∧ `premises_verified` | ✅ |
| `edge:cfn-change-set` | `CreateChangeSet` **且** `ExecuteChangeSet` 同栈 ∧ 同上的 guard 条件 | ✅ |
| `edge:cfn-template-unanalyzed` | 持 CFN 更新链但 `guard == "protected"`（或 `unknown`）⇒ 受保护资源那条直路被挡住，**模板层路径未分析** | ❌ 单列 |

**`*-unanalyzed` 两个标签沿用 `sign:fixture-issuer` 的既有机制**（`is_surface_label()` 返回 False）：
出现在 per-label 计数与**逐 principal 的集合比较**里（新增即红），但**不进** headline 并集。
理由：stack policy 挡住的是**受保护资源的直接更新路径**，不等于关闭了全部 CFN 提权路径——
service role 权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰那四个受保护资源。
所以 `guard == "protected"` **不得**被读成"该 principal 已完全退出冒充面"，也不得据此算确定收益。
这是**待核实的路径分析，不是本账号的利用成功实测**。

### 4.3 guard 的三值判定（与 `policy_problems()` 刻意分开的第二个谓词）

`router/infrastructure/stack_policy.py` 的 `policy_problems(actual, expected)` 判的是
**线上策略是否与本项目规定的形态等价**（`verify_deployed_edge.sh` ⑤ 用它）。它**不能**用来判 guard：

- 它的 `covered` 只收"Deny 且 Action ⊇ `DENIED_ACTIONS`"的语句里**字面**的 Resource 串；
  一份更严格的 `Deny Update:* on "*"` 会让 `want - covered` 非空（`want` 是精确的
  `LogicalResourceId/<id>`），于是报"没有 Deny 语句覆盖 X"，并另报"Resource 含通配"。
- ⇒ **`policy_problems() != [] 推不出 guard == "open"`。**

闸门用一个**目的单一的语义谓词**：这份 stack policy 是否对**这些逻辑 ID**拒绝 Update。
判为拒绝需要同时满足：`Effect` 为 `Deny`；`Action` 含 `Update:*` 或覆盖 `DENIED_ACTIONS` 全集；
`Principal` 为 `*`；`Resource` 逐字命中 `LogicalResourceId/<id>`，或是能覆盖它的通配
（`*`、`LogicalResourceId/*`、`LogicalResourceId/<前缀>*`）；且该语句没有 Condition。
三值：

| 观测 | guard |
|---|---|
| 无 stack policy | `open` |
| 能解析且判定"这些逻辑 ID 的 Update 被拒" | `protected` |
| 能解析且判定"未被拒" | `open` |
| 解析不出（未识别的语法、带 Condition、`GetStackPolicy` 失败/被拒） | `unknown` |

`unknown` 的处理：**该栈的确定标签一律不发**，改发对应的 `*-unanalyzed`，并在报告里打印原始策略摘要。
两个谓词各自的职责写进两处代码注释，互相点名，防止后来者"统一"掉。

## 5. 闸门改动

### 5.1 grant 词表（schema 7）

| 旧 | 新 | 说明 |
|---|---|---|
| `replace-platform-code:<fn>` | `update-fn-code:<fn>` | 只说动作事实（"能改 `$LATEST` 的代码"），不再声称"已能替换正在执行的版本" |
| — | `update-fn-config:<fn>` | 新 |
| — | `publish-fn-version:<fn>` | 新 |
| — | `create-fn:<候选类>` | 新 |
| — | `update-distribution` | 新 |
| — | `cfn-update-stack:<label>` | 新，label ∈ {router, deployer} |
| — | `cfn-create-change-set:<label>` / `cfn-execute-change-set:<label>` | **分开两条 grant**：`all()` 组合属于能力层，grant 层只记授权 |
| — | `cfn-set-stack-policy:<label>` | 新 |
| — | `pass-role:<角色类>` | 新（edge role、各栈 service role） |

`invoke-platform` / `invoke-site` / `kms-sign` / `kms-self-authorize` / `read-login-flow-secret` 不变。
**grant 串里只出现逻辑标签与函数名，不出现 StackId / 账号 ID / 分发 ID。**

### 5.2 能力层

每个 principal 的观测记录新增 `capabilities: [<标签>…]`（`classify()` 的输出，排序）。
比较口径与 grant 层**逐字相同**（刻意的不对称继续）：

- `platform` 类：**集合等值**，任一方向差异都红；
- 其它类别（含 `platform-overbroad`）：新增红、缩小是改善。

headline（`can_sign` / `can_replace_edge_verifier` / 并集 / 单列计数）**只打印，不参与红绿**——
它们由逐 principal 的集合派生，红绿在那一层已经判过了。**不得**只比总人数或一个布尔。

`--new-key` / `--retire-key` **不作用于能力层**：`sign:kms-direct` 等标签是"任一把 key 成立即算"的
口径，加一把或退一把 CMK 不改变标签集合（改变的是 `kms-sign:<kid>` 那些 grant 与 `kms` 分节）。
⇒ 轮转期能力层若出现变化，那**不是**轮转的副作用，必须有人看。

### 5.3 `model_inputs` 分节（新）

落 per-stack 的 `{label, guard, service_role_fp, controls}`、Edge association 的 entry 类型、
每个平台函数的 `entry` 与 `layers_supported`。**任一变化都红，不判方向。**

理由：guard 翻转在"当前无人持 `UpdateStack`"的账号里对能力层完全不可见，而它是实打实的
latent risk；反过来，能力层变化时这一节是"为什么变"的唯一可对账依据。
StackId / service role ARN 只落指纹（含账号 ID）。

### 5.4 采集与裁剪

按**模型实际消费的 (动作, 资源) 对**裁剪，不做笛卡尔积；**既有 grant 覆盖面不缩小**：

| 腿 | 动作 | 资源 |
|---|---|---|
| 函数腿（既有，扩） | `InvokeFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration` | 全部函数资源（平台 + 站点 + alias + 版本），与今天一致 |
| 发布腿（新，小） | `PublishVersion`, `CreateFunction` | Edge 两函数 + **两个**新建候选 ARN |
| CFN/CF/PassRole 腿（新，小） | `UpdateStack`, `CreateChangeSet`, `ExecuteChangeSet`, `SetStackPolicy`, `cloudfront:UpdateDistribution`, `iam:PassRole` | 两个 StackId、分发 ARN、edge role、各栈 service role |
| KMS 腿（既有） | 不变（含 RAW/DIGEST 两腿与合同值上下文） | 不变 |

- **两个**新建候选 ARN（一个中性名、一个与平台栈同前缀的名）是为了减小"按名字前缀授权"的盲区；
  即便如此，`CreateFunction` 的判定**只能**代表这两个 ARN，**不能**代表任意新函数名（§9 盲区）。
- 新动作/新资源类同时进 `coverage` 的资源类词表（`stack:router` / `stack:deployer` /
  `distribution` / `role:edge` / `role:cfn-service` / `fn:new-candidate`），
  新分节进 `BUNDLE_SHAPE`（递归默认拒绝，缺层即拒）。
- **耗时先量测再谈优化。** 不得通过取消分页、吞掉超时、减少 KMS 上下文腿来换速度。

### 5.5 正向控制

既有四条（edge / deployer / auth / panel 的 `REQUIRED_GRANT_PREFIXES`）不变。
grant 重命名不触及它们（它们锁 `invoke-*` 与 `kms-sign:` 前缀）。

## 6. probe 改动

同步换成共享模型；删掉源码里"router 栈无 stack policy"那句过期注释；guard 与 service role
改为观测输入（`GetStackPolicy` / `DescribeStacks`，只读）；覆盖 deployer 栈。
`--self-test` 继续存在，但用例集合与共享模块共用同一份（§7）。
`docs/security/3c-impersonation-surface.json` 是 gitignored 的单账号计数 ⇒ 重跑探针重生成，不在本轮断言数字。

## 7. 测试

新建 `site-builder/deployer/tests/test_impersonation_model.py`（模型的反例集真源），
`probe --self-test` 与闸门单测都引用同一份用例数据。

**既有 23 条反例原样迁移**（含"只有 `UpdateFunctionCode(Edge)` ⇒ 空集"这条正向控制、资源维度不许折叠那两条）。

**本轮新增反例**（每条只命中它要证明的那一点）：

| # | 输入 | 期望 |
|---|---|---|
| 1 | `UpdateFunctionConfiguration(EDGE)` + `UpdateDistribution` | **∅**（今天错判为 `edge:code(Publish=True)+associate`） |
| 2 | `UpdateFunctionCode(EDGE)` + `UpdateDistribution` | `edge:code(Publish=True)+associate`（正向控制，不许被 1 顺手修坏） |
| 3 | `UpdateFunctionConfiguration(AUTH)`（`layers_supported=True`） | `sign:hijack-auth-signer` |
| 4 | `UpdateStack(router)`，`guard="protected"` | 无 `edge:cfn-update-stack`，有 `edge:cfn-template-unanalyzed` |
| 5 | 同 4 + `SetStackPolicy(router)` | `edge:cfn-update-stack` |
| 6 | `UpdateStack(router)`，`guard="open"` | `edge:cfn-update-stack` |
| 7 | `UpdateStack(router)`，`guard="unknown"` | 无确定标签，有 `edge:cfn-template-unanalyzed` |
| 8 | `CreateChangeSet(router)` 单独 / `Create`+`Execute`，各配 `guard="protected"` 与 `"open"` | 单独恒 ∅；成对时按 guard 判 |
| 9 | `UpdateStack(deployer)`，`controls ∋ session-key`，`guard="open"`，`premises_verified=True` | `sign:cfn-session-key-stack` |
| 10 | 同 9 但 `premises_verified=False` | `sign:cfn-session-key-stack-unanalyzed`，**不进**冒充面并集 |
| 11 | `CreateFunction(候选) + PublishVersion(候选) + UpdateDistribution`，无 `PassRole` | ∅（既有反例，原样保留） |
| 12 | `CreateFunction(候选) + PassRole(edge role) + UpdateDistribution`，**无** `PublishVersion` | `edge:new-function+associate`（今天错判为 ∅；`CreateFunction` 自带 `Publish`） |
| 13 | `entry="unknown"` 的平台函数 + `UpdateFunctionCode` | 不发 `sign:hijack-*`（不得默认成 `$LATEST`） |

**闸门侧用例**：

- **能力标签集合完全不变，但 grant 扩到另一个受保护资源 ⇒ 仍然报红**（Codex 点名要求；证明能力层没有
  吃掉 grant 层的灵敏度）。
- `platform` 类丢一条 grant / 丢一条能力标签 ⇒ 红。
- `--carry-categories` 之后，`platform` 丢一条 grant **仍然红**（证明等值约束真的恢复了，见 §8）。
- 基线里出现已退役的 `replace-platform-code:` 前缀 ⇒ 读入即拒（防手改出半真半假的混合基线）。
- `BUNDLE_SHAPE`：新分节缺失 / 截断即拒（沿用既有递归合同的用例形状）。

**变形核验**（去掉守卫必须能复现缺陷）：

1. 把 `UpdateFunctionConfiguration` 并回代码类 ⇒ 用例 1 失败；
2. 去掉 guard 条件 ⇒ 用例 4/7 失败；
3. 把 `*-unanalyzed` 并进 `is_surface_label()` ⇒ 并集计数用例失败；
4. 把 `cfn-create/execute-change-set` 合成一条 grant ⇒ 用例 8 的"单独恒 ∅"失败；
5. 把 `PublishVersion` 加回"新建函数"那条路的前提 ⇒ 用例 12 失败。

## 8. 基线迁移（schema 6 → 7）

`BASELINE_SCHEMA = 7`；读到 6 **硬失败**（沿用既有先例，不做自动迁移通道）。
**资产里不加任何双模型/过渡代码**（`CLAUDE.md`：验证环境的中间迁移步骤不进版本库）。

### 8.1 `--carry-categories <FILE>`（进资产的通用能力）

**为什么必要（已核验）**：`write_baseline` 只从"这一轮读进来的基线 dict"沿用 `category`
（`old.get(fp, {}).get("category", "unclassified")`），而 schema 不匹配的既有提示是"删掉这个文件重生成"
⇒ 一次 schema 跳变会把**全部** `platform` 标注变成 `unclassified`，`platform` 的**集合等值**约束
静默降级成"只看新增"，而 `unclassified` 只是绿色报告里的一个字段。
（既有的 `--classify` 按**角色名**映射，能部分顶替，但它依赖一份仓库外文件存在且角色名没变过
——所以它是补充，不是替代。）

边界（都要有用例）：

- **只与 `--update-baseline` 同用**；单独给出即报错退出；
- 只读 `principals[*].category`，**不读** grants / capabilities / coverage / kms / 豁免 / 任何其它状态；
- 只导入**能按本轮观测的 principal 指纹匹配上**的条目，且值必须在既有 `categories` 白名单内；
  匹配不上或值非法的**逐条报出、不导入**；
- 结构必须合法（`{指纹: {"category": str}}`，指纹按 `_PFP_RE` 校验）——"支持旧 schema"
  **不等于**接受任意结构或任意指纹算法；
- 与 `--classify` 对同一 principal 给出**不同**分类时**报明并退出**，不静默覆盖。

### 8.2 见证流程（`.scratch/`，不进资产）

1. **旧 commit 跑完整闸门，必须绿**。`--dump-observed` 退出 0 **不算**闸门绿——必须真的做过比较。
   保存：旧代码版本号、schema 6 基线副本、旧 dump、比较报告。
2. **一次扫描、两版判定**：`.scratch` 里的一次性 runner 用**新的采集范围**包住 `gate.simulate` 记录
   原始 `decisions`，调用**一次** `gate.measure()`，同时得到 (a) 新模型的完整 bundle 与 (b) 原始
   decisions。用 (b) 分别喂旧、新判定 ⇒ 差异**只含模型影响**，不含环境变化。
   （闸门今天 `decisions` 用完即弃、dump 里只有算好的 grants ⇒ 换模型无法从旧 dump 回放，这是本步存在的原因。）
3. **schema 7 基线从同一份已审阅的 (a) 写**：`--from-dump <a> --update-baseline --carry-categories <旧基线备份>`。
   **不得**见证结束后重新扫描并无条件吸收另一份观测。
4. 旧基线**先移到备份位置**，再生成新基线；随后用新基线**复核一次必须绿**。
5. 逐项核对：重命名 / 采集扩展 / 新能力标签 / `model_inputs` 初值；**任何未解释的残余阻断签字**。

> 同输入双模型只隔离模型差异，**不意味着整个 AWS 观测窗口是原子的**：窗口一致性仍只由闸门既有的
> 枚举两端复查覆盖（它只覆盖 principal 层、只证明两端相等，三个盲区照旧）。

## 9. 明确记录的未分析范围（进 `docs/security/account-trust-boundary.md`）

1. **CFN 模板层路径**：`guard == "protected"` 只关掉"直接更新那四个受保护资源"这一条链。
   service role 权限足够高时，改模板新增 IAM 授权类资源等路径未必需要碰受保护资源。
   ⇒ 不得据 guard 宣称某 principal 退出冒充面，也不得算确定收益（ADR 0007 已有同样要求）。
2. **`CreateFunction` 的名字空间**：只对两个候选 ARN 有判定，按名字前缀授权的策略可能在别的名字上成立。
3. 既有三个盲区（`SimulatePrincipalPolicy` 的 Condition 下界、动作等价类不穷尽、临时角色）不变。

## 10. 需要同步的真源

| 文件 | 改什么 |
|---|---|
| `docs/security/account-trust-boundary.md` | headline 与集合关系标"**待真机重测**"；补 §9 的两块未分析范围；grant 名称变更 |
| `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 3g | 记"模型已对齐、待真机重测"，**不打完成勾**；订正"站点函数也过度声称"那半句（§1 表） |
| `docs/adr/0008-*.md`（新） | stack policy 的**两个谓词**（部署形态一致性 vs 闸门的语义 guard）与 guard 的三值；防后来者统一 |
| `CLAUDE.md` 跨组件改动矩阵 | 加一行：改共享模型 ⇒ probe + 闸门 + 两处用例集 + 基线 schema |
| `site-builder/DEPLOY.md` | schema 7 与 `--carry-categories` 进闸门说明；见证流程只写"在仓库外做"，不写本环境的中间步骤 |

## 11. 交付边界与证据分级

- **本机可做**（本轮交付）：共享模型 + 闸门/probe 改动 + 全部单测与变形核验。
  证据等级：**纯函数 / fake 层**（模型用例、闸门比较器用例），**静态**（botocore 服务模型、AWS 文档、ADR 核验）。
- **需要真机**（留给有真实 AWS + 完整 config 的环境）：闸门首跑、schema 7 基线生成、probe 重量测、
  `account-trust-boundary.md` 的数字、新增腿的耗时量测。证据等级：**production**。
- 本机 `site-builder/config.ini` 是精简+脱敏态（只有 `[Platform] account_id` 与 `[SessionKeys]` 两类段）
  ⇒ 模块级读完整 config 的 deploy 类测试在本机 `SystemExit`，**那不是本轮引入的缺陷**。

## 12. 裁定记录

| # | 裁定 | 理由 |
|---|---|---|
| 1 | 抽共享纯模块，**先修模型再共享** | probe 现状有两处失真（§1.1），"复制 probe 即正确"会把缺陷固化 |
| 2 | 保留 grant 层 + 新增派生能力层 | 压平成布尔的错误犯过三次；两层职责不同 |
| 3 | 纳入 deployer 栈，probe 同步扩展 | 不为维持旧 probe 范围而保留已知漏项；两边共用扩展后的模型仍是 parity |
| 4 | 按模型消费面裁剪模拟 | 避免与全部 alias/版本做笛卡尔积；既有 grant 覆盖面不缩小 |
| 5 | guard 三值 + 与 `policy_problems()` 分开的第二个谓词 | 已核验：更严格的 Deny-all 会让 `policy_problems()` 非空 ⇒ 它推不出 `open` |
| 6 | `--carry-categories` 进资产 | 已核验的静默约束丢失；通用能力而非本环境过渡 |
| 7 | schema 7 硬失败、无自动迁移通道 | 沿用先例；基线含单账号实测、不随资产分发 |
| 8 | 同输入双模型做见证，用同一份 dump 写基线 | 隔离"模型差异"与"环境差异"；不重新扫描吸收第二份观测 |
| 9 | 不主张任何"收益 −N" | ADR 0007 已要求；模板层路径未分析 |

**被否决**：① 闸门 import probe（成环）；② 能力层取代 grant 层（false-green 形状）；
③ 资产内置一次性双模型迁移路径（验证环境的中间步骤不进版本库）；
④ 用 `policy_problems()` 判 guard（语义不符）；⑤ 本轮同时做 3e（独立排期，且 idle 色历史存在性缺口不闭合）。
