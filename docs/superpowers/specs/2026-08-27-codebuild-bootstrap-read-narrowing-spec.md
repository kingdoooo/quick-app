# M09 真修复①：收窄 CodeBuild 对 CDK bootstrap 桶的读权限

> **状态：✅ 2026-08-27 已实施并部署生产，基线与文档已同步。** 这是
> `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 的 **3b**。风险模型的真源是
> `docs/security/account-trust-boundary.md`，本文不重复它，只写这一条改动。
> **下一条是 3c（非对称签名），建议先 spike。**
>
> **接手这一条时的读法**：正文（设计与守卫）+ 末尾的「实施记录与验收证据」一节就是全部
> 状态；实施计划在 `docs/superpowers/plans/2026-08-27-codebuild-bootstrap-read-narrowing.md`
> （Task 1/2 已完成、Task 3 的探针**已裁决移出关键路径**、Task 4/5 已执行）。

## 一句话

跑不可信站点依赖安装的 CodeBuild 项目（`site-package`）现在对整个 CDK bootstrap
asset 桶有读权限，而那个桶里有 9 个仍带**明文会话签名密钥**的 Edge asset。这条权限
**唯一的用途是取它自己那 25 行 buildspec**。把 buildspec 内联进 CloudFormation 模板，
这条权限就整条消失——不是收窄，是没有了。

## 现状（实测，只读）

部署出来的项目：

```
source.type = NO_SOURCE
buildspec   = arn:aws:s3:::cdk-hnb659fds-assets-<acct>-us-east-1/ba965c02….yml
serviceRole = SiteDeployerStack-PackageProjectRole…
```

该角色的 inline policy（`PackageProjectRoleDefaultPolicy…`）有五条语句，其中第一条是
本次要消掉的：

| # | 动作 | 资源 | 处置 |
|---|---|---|---|
| 1 | `s3:GetObject*`, `s3:GetBucket*`, `s3:List*` | `cdk-hnb659fds-assets-<acct>-us-east-1` **与 `/*`** | **本次删除** |
| 2 | `logs:*`（三个） | 该项目自己的 log group | 不动 |
| 3 | `codebuild:*Report*`（五个） | `report-group/site-package-*` | 不动 |
| 4 | `s3:GetObject` | `site-artifacts-<acct>/validated/*` | 不动，验收要确认还在 |
| 5 | `s3:PutObject` | `site-artifacts-<acct>/artifacts/*` | 不动，验收要确认还在 |

第 1 条是 `cb.BuildSpec.from_asset()` 让 CDK 自动加的：`Asset.grantRead()` 授的是
**整桶**，不是那一个对象。第 4、5 条是 `app.py` 里手写的精确授权。

**buildspec 自己从头到尾只碰 `$ARTIFACTS_BUCKET`**（第 13 行读 `validated/*`、
第 25 行写 `artifacts/*`），一次也没碰 bootstrap 桶。所以第 1 条与构建逻辑无关。

### 这个洞为什么活到今天（不是没人看，是守卫只看见了一半）

`test_validate.py::test_package_project_only_touches_validated_and_artifacts` 已经在
守这个角色了，而且它的**主语写得很准**——"构建容器那个角色能碰哪些前缀"，还刻意用 AST
定位而不是全文子串（因为 validate 自己的窄角色合法地持有 `uploads/*`）。它断言那个
角色的资源集合**恰好**是 `{validated/*, artifacts/*}`，"多一项就是给不可信构建多开一个
前缀"。

它照样漏了。原因：`_package_project_resources()` 遍历的是 AST 里
`package_project.add_to_role_policy(...)` 这些调用——也就是**手写的那一半**。
CDK 从 `from_asset()` 自动加进 `PackageProjectRoleDefaultPolicy` 的那条整桶读
不经过这个调用点，于是对这条守卫**结构上不可见**。

这正是 `syntax-guards-cannot-prove-semantics` 那条教训的又一次现身：**守卫的主语是
"这个角色的全部权限"，而它的证据只是"源码里手写的那部分权限"**——两者之差就是这个洞。
所以本次改动的守卫必须有一层断言在**合成后的模板**上（那才是角色策略的全貌），
不能只加第二条 AST 断言。

### 为什么这条比"账号内暴露"更要紧

`site-package` 是整个平台里**唯一**以站点作者可控的输入（`package.json` 与
`dependencies`）驱动、且在容器内执行第三方代码安装流程的地方。这条链一旦通，就从
「账号内部暴露」变成**「不可信站点作者可窃取平台签名密钥」**——而后者正是整套设计
声称要防的威胁。

**先纠正一个在本仓库多处流传的说法。** `CLAUDE.md`、
`docs/security/account-trust-boundary.md` 与 merged review 都写着「当前唯一的隔断是
`buildspec-package.yml` 里的 `npm install --ignore-scripts`」。**那句话不准确**，
按实测的控制点分布应该是：

| 攻击路径 | 控制点 |
|---|---|
| 站点**自己的** `package.json` 里写 `preinstall`/`postinstall` 等 | **两道**：合同校验器在 CodeBuild **之前**就拒（`contract/redlines.py` 的 `NPM_LIFECYCLE_KEYS`，`_scan_package_json` 对 `backend/` 下**任何** `package.json` 生效）＋ `--ignore-scripts` |
| 站点**自己的** `backend/.npmrc` | **两道**：合同校验器直接拒（`redlines.py:326`）＋ buildspec 的 `find /tmp/site -name .npmrc -delete` |
| **依赖**（transitive）里的生命周期脚本 | **只有 `--ignore-scripts` 一道** |

第三行是要紧的那一行，而它恰好是原说法唯一说对的部分。理由：`_scan_package_json`
**只看站点自己的 `scripts` 段，从不检查 `dependencies`**——registry、版本范围、
`git+`、`file:` 规格一概不限；而扫描器只读 `TEXT_EXT` 里的后缀，**`.tgz` 根本不被打开**。
实测（本机 npm 10.9.8 / node 22）：把一个带 `preinstall` 的包 `npm pack` 成本地 `.tgz`、
以 `"file:./dep.tgz"` 作依赖，`npm install` **会执行**那个 `preinstall`，而加上
`--ignore-scripts` **不会**。也就是说，对"依赖投毒"这条最现实的路径，那条 flag 确实
是唯一的控制点，且它对合同校验器完全不可见。

所以这条改动的理由不是"flag 可能被误删"，而是**平台不该把一条 flag 放在
「不可信第三方代码」与「平台签名密钥」之间**。改完之后 flag 仍然必须留着——它挡的
不只是这条路（构建容器里任意代码执行仍能读 `validated/*`、写 `artifacts/*`）。

> 上表的三处文档措辞不在本 spec 的改动范围之外：它们与守卫同属"声称与证据"这一件事，
> 由计划的 Task 1 一并改正（纯文档，不碰生产）。

## 这条改动买到什么、买不到什么

**买到**：把上面那条跨越威胁边界的路掐断，且不依赖 `--ignore-scripts` 这一条 flag。

**数字上只动 1 个 principal**：

| 项 | 现在 | 改后 |
|---|---|---|
| A 组总数 | 62 | **61** |
| 其中能取得会话签名密钥的 | 57 | **56** |
| `platform-overbroad` 类 | 1 | **0** |

**不是 21 个。** 那 21 个是"只能经 asset 这条路读到密钥"的其它角色，它们要退出暴露面
的前提是 **asset 里不再有活密钥**，那是下一条真修复（非对称签名）。§9 的 3b 已经纠正
过这个流传的数字，这里再钉一次。

**买不到**：`read-edge-code`（`lambda:GetFunction` 下载 Edge 产物）与 `read-jwt-param`
（四个 `ssm:GetParameter*` 动作）两条路一寸也没动。本改动不改变
`docs/security/account-trust-boundary.md` 的总体结论。

## 方案：把 buildspec 逐字节内联

CDK 没有 `BuildSpec.from_string`，只有 `from_object` / `from_object_to_yaml`
（都要先有 dict）、`from_asset`、`from_source_filename`（要有 source，而这里是
NO_SOURCE）。而 `infra/.venv` 里**没有 YAML 解析器**。三种候选都 synth 实测过：

| 写法 | 部署出的 `Source.BuildSpec` | 与文件逐字节相同 | 策略里还有 bootstrap 桶 |
|---|---|---|---|
| 现状 `from_asset` | S3 ARN | — | **有** |
| `from_object` 占位 + `add_property_override` | 文件原文 | 是 | 没有 |
| **自定义 `BuildSpec` 子类**（采用） | 文件原文 | 是 | 没有 |

采用自定义子类：

```python
class _InlineBuildSpec(cb.BuildSpec):
    """把仓库里的 buildspec 原文**逐字节**内联进 CodeBuild Project。

    **为什么不用 `BuildSpec.from_asset()`**：CDK 会给项目角色授**整桶**读
    （`Asset.grantRead()`），而同一个 bootstrap 桶里有 9 个带明文会话签名密钥的
    Edge asset——而本项目跑的正是不可信站点的依赖安装。那条权限的唯一用途是取
    这份 buildspec 自己。

    **为什么不先解析成 dict**（`from_object` / `from_object_to_yaml`）：那会把文件
    重新序列化，注释全丢——而 `--ignore-scripts` 为什么必需、`.npmrc` 为什么要先删，
    理由就写在注释里。重新序列化还会让 `version: 0.2`（YAML float）往返一次，
    等价性只能靠真跑一次构建来证明。一条纯收权的改动不该承担这个风险。

    `is_immediate` 与 `to_build_spec()` 都是 `BuildSpec` 的**公开** abstract 成员
    （aws-cdk-lib 2.262.1 实测），不是私有接口。
    """

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    @property
    def is_immediate(self) -> bool:
        return True

    def to_build_spec(self, scope=None) -> str:
        return self._text
```

调用处：

```python
BUILDSPEC_PATH = Path(__file__).parents[1] / "buildspec-package.yml"
...
package_project = cb.Project(
    self, "PackageProject", project_name="site-package",
    build_spec=_InlineBuildSpec(BUILDSPEC_PATH.read_bytes().decode("utf-8")),
    environment=…, timeout=…)
```

用 `read_bytes().decode("utf-8")` 而不是 `read_text()`：后者走文本模式，会做换行
归一化。**实测这个文件今天是纯 LF（1721 字节 / 25 个 `\n` / 0 个 `\r\n`），
两种读法结果逐字节相同**——所以这不是在修一个现存的 bug，只是让"模板里的字符串
重新编码后等于文件原始字节"这条断言在任何平台上都成立。

**唯一真源仍是仓库里的 `buildspec-package.yml`**，子类只是透明搬运。这是不选
"占位 + property override" 的理由：那个写法会让 `app.py` 里同时存在一个假的 L2 输入
和一个真的 L1 override，读代码、重构或升级 CDK 时容易只改一处——正是这个仓库反复
被咬的双真源形态。

### 不选的两条

- **保留 asset、只把自动生成的那条语句收窄到精确对象 key**：要在 CDK 生成
  `PackageProjectRoleDefaultPolicy` 之后找到并改写它，依赖 CDK 内部命名与生成顺序，
  是版本相关的手术；而且收窄后仍然是"在装着 9 个带活密钥 asset 的桶里有一条读权限"，
  只是范围小了。对象 key 是内容哈希，每次改 buildspec 都变。
- **给 router 栈换一个 bootstrap qualifier**，让 Edge asset 落到另一个桶：要重新
  bootstrap、改 router 配置，且旧桶里那 9 个对象仍然存在。blast radius 大得多，
  收益与本条相同。

## 守卫：三个结构化检查器 + 一个真机行为探针

**总原则：每个守卫都是「吃结构化输入、吐违规列表」的纯函数，反例一律在内存里注入。**
不改工作树、不需要另一个 harness、跑在默认套件里。上一版把这件事做成"文本子串黑名单
＋人工把 app.py 改回去跑一次"，那既证明不了语义、又违反了它自己给出的理由。

**为什么必须是精确 allowlist 而不是黑名单**：本 spec 前面那节「守卫只看见了一半」讲的
是同一件事的另一半。黑名单守卫的主语总是比证据宽——「策略里没出现 bootstrap 桶」不等于
「这个角色只能读 validated/、只能写 artifacts/」。实测过一份策略：两条精确授权都在、
另加 `s3:GetObject` + `s3:ListBucket` on `*`，上一版的两条模板断言**都通过**。

### 检查器 ①：buildspec 的命令合同（不是 YAML 解释器）

`build_container_interlock_violations(src) -> list[str]`，基于
`_buildspec_commands(src)`：定位唯一的 `commands:` 段、跳过 YAML 注释、拒绝 block
scalar / 行尾续行 / 无法 `shlex` 分词的条目（**fail-closed，不猜**），再按
`&&` `||` `;` `|` 切成逐条命令的 token 列表。`shlex.split(..., comments=True)` 同时
解决 shell 注释与引号。

判据是**整条命令序列与 `EXPECTED_COMMANDS` 等值**（12 条固定命令），另外给两条隔断
单独的报文（`npm install` 的 token 精确列表、删 `.npmrc` 的精确命令、以及它必须**严格
早于** install）——单独那几条只是为了报文能点名坏的是哪条隔断，检测靠整体等值。

**为什么必须整体等值，而不是"除 install 外不许有别的 npm 子命令"**：那条判据只看首
token 是不是 `npm`，实测 `env npm rebuild`、`sh -c 'npm rebuild'`、`/usr/bin/npm rebuild`
**全部放行**。而 wrapper 是枚举不完的（还有 `npx`、`node -e`、`bash -lc`…）——枚举它们
就是打地鼠。既然这份 buildspec 只有 12 条固定命令，把整条序列设成 allowlist 才是与
IAM 那层同一个形状：**任何**新增/改写/换序都红，合法改动必须显式更新安全合同并重新
过一次 review。

精确比对的代价是往命令上加任何合法 flag 都会红一次，逼一次自觉更新——与基线纪律同
一个取舍。

### 检查器 ②：IAM 的精确 allowlist（不是 IAM evaluator）

`package_project_s3_violations(template) -> list[str]`。三步，全部不求值：

1. 从 `AWS::CodeBuild::Project`（`Name == "site-package"`）的 `ServiceRole` **反查**
   角色逻辑 ID（要求是 `Fn::GetAtt` 形态，否则拒绝猜）——不靠 logical-ID 前缀；
2. 收集该角色的**全部**模板内权限来源：inline `Policies`、`AWS::IAM::Policy`、
   `AWS::IAM::ManagedPolicy`（两者按 `Roles` 含 `{"Ref": lid}` 匹配）、非空的
   `ManagedPolicyArns` 直接判违规，**以及 `AWS::S3::BucketPolicy`**——只收 identity
   policy 时，一条把 `s3:GetObject`+`s3:ListBucket` on `*` 授给本角色的桶策略能让整个
   断言照样绿（实测）。桶策略按 Principal 匹配：只把授给**本角色或 `*`** 的语句纳入，
   不认识的 Principal 形态按最坏情况处理并报违规。（本 stack 里今天就有一条
   `ArtifactsPolicy`，Principal 是 auto-delete 自定义资源的角色 ⇒ 正确地被跳过；
   把"任何桶策略"都算进来会立刻误红。）
3. 把 `Effect=Allow` 的 S3 `(action, resource)` 规范化成集合，与精确期望比**等值**：

```
s3:GetObject → <GetAtt:{artifacts 桶逻辑 ID}.Arn>/validated/*
s3:PutObject → <GetAtt:{artifacts 桶逻辑 ID}.Arn>/artifacts/*
```

比较逻辑抽成**共享纯函数** `s3_permission_violations(docs, expected, where=…)`，
被三处调用：手写模板 fixture、真 synth 模板、**以及部署后的真机验收**（那时 Resource 是
已解析的 ARN 字符串，同一个 `render_token` 原样返回）。三处共用是刻意的：上一版的部署后
确认自己拼了一套字符串 grep，而那套判据正是被"两条精确授权都在 + `s3:GetObject` on `*`"
绕过的那种——模板层变强而真机侧复制一套弱逻辑等于白改。

**不覆盖**：本 stack 之外的 resource policy，尤其是 **CDK bootstrap 桶自己的桶策略**
（不在这份模板里）。那条通道由 `verify_account_trust_boundary.py` 的 bucket-policy 快照
负责，检查器的 docstring 里写明了这条边界。

artifacts 桶的逻辑 ID 由"`BucketName` 以 `site-artifacts-` 开头的那个 `AWS::S3::Bucket`"
解析出来，**不硬编码 CDK 的哈希后缀**。以下形态**直接判违规、不求值**：
`NotAction` / `NotResource`、`Resource: "*"`、任何带 `*` 的 S3 动作（含 `s3:*`、
`s3:GetObject*`、`s3:List*`、裸 `*`）、任何 managed policy attachment、
以及 `render_token()` 不认识的 CloudFormation 形态（`Fn::ImportValue` 之类）。

### 检查器 ③：BuildSpec 的交付形态

`buildspec_template_violations(template, want_bytes) -> list[str]`：
`Source.Type == "NO_SOURCE"`；`Source.BuildSpec` 必须是 `str`（`Fn::Join` 形态即说明
它又变回了 asset 的 S3 ARN）；`.encode("utf-8")` 必须等于仓库文件的 `read_bytes()`；
且串里不许出现 `arn:` / `cdk-hnb659fds-assets` / `AssetParameters`。

### 三个检查器住在哪、由谁跑

放一个**只依赖标准库**（`json` + `shlex`）的模块
`site-builder/deployer/tests/security_contracts.py`，于是：

- **always-on**（默认 `deployer` 套件，**不需要 aws_cdk、不需要 Docker**）：
  `tests/test_security_contracts.py` 用真实 buildspec 文件与一份**手写的最小模板
  fixture**做正向输入，把全部反例在内存里注入做负向输入。手写 fixture 的形态是对着
  **已部署的 processed 模板**核过的（`Action` 可为 str 或 list、`Resource` 为
  `Fn::Join` + `Ref: AWS::Partition` / `Fn::GetAtt`），账号 ID 用 `000000000000`。
- **opt-in**（`SB_CDK_TESTS=1` + PYTHONPATH 桥接，**需要 Docker**）：
  `tests/test_infra_tables.py` 把**同样三个检查器**跑在真正 synth 出来的模板上。
  手写 fixture 会不会与现实漂移，就由这一层兜住。

`import app` 无副作用这条由一个**独立的纯函数**
`module_toplevel_side_effect_violations(src)` 守：遍历模块顶层、跳过
`if __name__ == "__main__":` 子树与函数/类体，拒绝任何 `App(...)` / `SiteDeployerStack(...)`
/ `*.synth()` 调用。**只找 `app.synth()` 是不够的**——把建栈两行放回顶层、只把 `synth()`
留在守卫里，import 一样会建栈而旧判据 `bad=[]`（实测）。负向控制用**改动前的完整三行**，
不是只放回 `synth()` 那一行。

**上一版那句"只 import app.py 不实例化栈、所以不需要 Docker"是错的**：`app.py`
第 905-908 行在**模块顶层**就 `App()` / `SiteDeployerStack(...)` / `app.synth()`，
`import app` 本身就 synth 整个栈并触发 Lambda bundling。所以本改动**顺带把那三行挪进
`if __name__ == "__main__":`**——`cdk.json` 是 `{"app": "python3 app.py"}`，加守卫对
`cdk` 完全无影响，而 `import app` 从此无副作用（现有 `test_infra_tables.py` 的 fixture
目前是 import 时 synth 一次、自己再建 App synth 一次，这一步也顺手消掉那次重复）。

### 第四层：真机闸门

`verify_account_trust_boundary.py`（约 9±1 分钟）。它才是这条安全属性的真回归守卫：
权限回来了就是"既有 principal 新增 grant" ⇒ 红。不是单测，跑一次要真凭证。

### 反例的有效性标准（这一轮最贵的教训）

上一版我声称"计划里的代码块机械验证过 16 项全过"。那 16 项是**我自己挑的退化**，而我
挑的正好是我的正则能抓住的那些；外部复审另挑四个，**全部绿**。所以：

> **自己写反例验自己的守卫，证明的是守卫对得上作者的想象力，不是对得上威胁。**

因此本 spec 规定，新增或修改任何安全守卫时，反例集合必须满足五条：

1. **tracked**（进仓库，不是一次性 /tmp 脚本）；
2. **可重复执行**（默认套件里就跑）；
3. **oracle 不由同一条实现路径产生**——至少包含一组**由复审方提出**的反例，逐字纳入；
4. 每条反例都确认命中**目标控制点**（报文点名的是那一条，不是别的）；
5. 失败不能由更早的检查顺带造成（构造反例时其余部分必须保持合格）。

本轮纳入的反例（③④⑤ 全部来自外部复审，已逐条实测会红）：

| 层 | 反例 |
|---|---|
| buildspec | `--ignore-scripts=false`；flag 只留在 shell 注释里；删 `.npmrc` 挪到 install 之后；删错目录；install 后追加 `npm rebuild`；`--no-ignore-scripts`；**`env npm rebuild`**；**`sh -c 'npm rebuild'`**；**`/usr/bin/npm rebuild`**；多一条 `node -e`；两条命令换序 |
| IAM | `s3:GetObject` on `*`；`s3:ListBucket`；另一个桶；`s3:GetObject*` 通配动作；`NotResource`；`Fn::ImportValue` 之类不认识的 token；挂 `AmazonS3ReadOnlyAccess`；角色自身 `Policies` 里的宽语句；经 `AWS::IAM::ManagedPolicy.Roles`；桶策略把 `s3:*` on `*` 授给本角色；桶策略 Principal 是 `*`；桶策略 Principal 形态不认识；**账号 root + `ArnEquals: aws:PrincipalArn` 指向本角色**；**账号 root 且无条件**；**账号 root + `ArnLike` 通配**；**`StringEqualsIgnoreCase` 大小写不同但指向本角色**；**条件值是 `${aws:PrincipalArn}`** |
| BuildSpec 形态 | S3-ARN 的 `Fn::Join` 形态；字节被改动一个字符 |
| StartBuild（真机） | `codebuild:*` on `*`；裸 `*` on `*`；`codebuild:Start*` 通配；`Allow`+`NotAction`；换成别的项目 ARN；**`CODEBUILD:*`**；**`CodeBuild:StartBuild`**；**`codebuild:startbuild`** |
| 桶策略读取（真机） | `AccessDenied` / `Throttling` / `InternalError` / `PermanentRedirect` 都必须**原样抛**，只有 `NoSuchBucketPolicy` 才算"没有策略" |
| `import` 无副作用 | 改动前的完整三行；只把 `synth()` 挪进守卫、建栈留在顶层；顶层裸 `App()`；顶层 `SiteDeployerStack(...)`；`@App()` decorator；`def f(x=SiteDeployerStack(...))` 默认值；`class C(App())` 基类；**`class C: App()`（类体会执行）**；**`class C: s = SiteDeployerStack(...)`**；**参数 annotation `def f(x: App())`**；**返回 annotation** |

正向控制（同样必须有，否则守卫可能"因为把一切都判红"而通过）：真实 buildspec 合格；
"改完之后"的模板合格；**授给别的身份的桶策略不该误红**；**账号 root + 条件明确指向别的
角色也不该误红**；**与该动作无关的 `Resource: "*"` 语句（如 logs）不该误报**；
**函数体/类体里的调用不该被判成顶层副作用**；守卫之内的三行必须放行；
以及"改动之前"的模板形态**必须红**。

**账号级 principal 的处理是 fail-closed 的**：`Principal: {"AWS": "<acct>:root"}` 加
`Condition: {ArnEquals: {aws:PrincipalArn: <role>}}` 是常见写法，只比对 `Principal.AWS`
是否字面等于角色 ARN 会整条漏掉。所以账号级 principal 一律去看 `aws:PrincipalArn`
条件，并**按算子各自的语义比**：`ArnEquals`/`StringEquals` 精确比、
`StringEqualsIgnoreCase` 双方 `casefold()` 后比（AWS 那边就是大小写不敏感的——只留取值、
统一用精确比会把 `ARN:AWS:IAM::…:ROLE/MYROLE` 当成"指向其它身份"而跳过，实测是一条
false-green）、`ArnLike`/`StringLike` 无通配时精确比。
指向本角色 ⇒ 计入；**没有条件、用 Not\* 或不认识的算子、Like 算子带通配、值里含
policy variable（`${…}`）、或形态不认识 ⇒ 按最坏情况计入并报违规**；
只有条件明确指向别的身份才跳过。

**两条容易写错的语义，都由反例钉住**：

- **IAM 动作大小写不敏感**（AWS 合同：`iam:ListAccessKeys` == `IAM:listaccesskeys`）。
  `fnmatchcase` 会把 `CODEBUILD:*` / `CodeBuild:StartBuild` / `codebuild:startbuild`
  整条漏掉（实测三条都返回零违规），所以匹配前统一小写、报文里保留原始大小写。
- **类的体在 import 时会执行**，函数的体不会；而 `app.py` 没有
  `from __future__ import annotations`，3.12 下 annotation 是**立即求值**的（实测：
  定义 `def f(x: probe())` 就会调用 `probe()`）。所以 import-time 遍历器要覆盖
  函数的 decorator/默认值/**全部 annotation**（含返回）、类的 decorator/基类/keywords/
  **整个类体**，而 lambda 的**体不遍历**（创建时不求值，遍历它会误红）。
  早先注释里"类的体不在 import 时执行"是**错的事实**，已改。

**真机侧的两个共享纯函数也在这份反例矩阵里**（它们住在 `security_contracts.py` 而不是
只写在计划的 shell heredoc 里，就是为了能被单测钉住）：`bucket_policy_statements()`
——**不许**用 `except s3.exceptions.from_code("NoSuchBucketPolicy")`，boto3 没建模这个异常、
`from_code` 实测返回的就是通用 `ClientError`，那条 except 会把 `AccessDenied`/限流全部
静默解释成"桶没有策略"；`action_resource_violations()` —— 按 **glob 判覆盖**而不是"Action
列表里字面含这个字符串"，否则 `codebuild:*` / 裸 `*` / `NotAction` 三种形态里的危险授权
根本不会进入被比较的集合。

### 真机行为探针（opt-in、tracked、默认不跑）

静态检查器证明**结构**，探针证明**真实 npm/CodeBuild 行为**。只跑一次然后把结论写成文字
会退回"不可复跑的证据等于没有证据"，所以它是一件**制品**而不是一次操作：

- 由 `RUN_CODEBUILD_SECURITY_PROBE=1` 单独开启，日常七包不跑；
- fixture 在 `tmp_path` **动态生成**，不进 `fixtures/`；
- 只在实施本改动时、以及构建镜像/npm 大版本变更时跑。

**观察对象**：站点的 `backend/` 带一个本地 `.tgz` 依赖，该依赖的 `preinstall` 往
自己目录里写一个唯一 sentinel 文件名。生产路径必须满足：构建**成功**，且产出的
`backend.zip` 里**搜不到那个 sentinel 文件名**。

用 `.tgz` 而不是普通子目录是必须的：合同校验器会扫 `backend/` 下**任何** `package.json`
并拒绝生命周期脚本，普通子目录形态的 fixture 在 validate 就被拦下、根本到不了 CodeBuild；
而 `.tgz` 不在 `TEXT_EXT` 里、不会被打开。**这同时就是上面那张表第三行的可执行证据。**

**正向控制是必需的**（否则"sentinel 不存在"可能只是探针根本没走到 `npm install`）：
用同一个 CodeBuild 项目、同一份输入，`StartBuild` 时带 `buildspecOverride` —— 只把
`--ignore-scripts` 去掉 —— sentinel **必须**出现。此时角色已经收权（只能读 `validated/*`、
写 `artifacts/*`），所以 override 的风险面很小。

**探针不证明什么**（写下来，别让它冒充更大的结论）：它**不覆盖 `.npmrc` 那条**。
把 registry 改成一个可观察目标需要么引入外部 registry、么依赖 npm 某个配置项的行为
细节，两者都会造出一个不稳定的 E2E。`.npmrc` 那条以检查器 ① 的精确结构与顺序判据为
权威，本 spec 明确接受这个边界。

## 实施与验收顺序

**所有 shell 块一律 `set -euo pipefail`。** 这不是排版习惯：本环境的 shell 是 **zsh**，
而 zsh 里 `${PIPESTATUS[0]}` 展开成**空字符串**（zsh 用 `$pipestatus`，还是 1-indexed），
且不带 `pipefail` 时 `cmd | tee` 的退出码是 **tee 的 0**。上一版用
`… | tee … ; echo "退出码: ${PIPESTATUS[0]}"` 读闸门结果——实测那会打印一个空退出码，
于是闸门真发现扩权（退出 1）时流程照样往下走进 `--update-baseline`，把真实漂移吸进基线。
**任何"跑一个命令然后判它成败"的步骤都必须让非零退出直接终止，而不是打印出来给人看。**

### A. 部署前（不碰生产）

1. always-on 全量（含三个检查器的正反用例）＋ opt-in 模板断言（PYTHONPATH 桥接、需 Docker）。
2. `cd site-builder/deployer/infra && rm -rf cdk.out && cdk diff`。
   **预期有两类变化，不是一类**：
   - `AWS::CodeBuild::Project` 的 `Source.BuildSpec`：`Fn::Join` 出的 S3 ARN → 内联字符串；
   - `AWS::IAM::Policy`（PackageProject 角色）：删掉 bootstrap 整桶读那一条。

   把预期写成"diff 只少一条 IAM 语句"是错的——属性本身也必须变。
3. 明确确认 diff 里**没有**：CodeBuild Project replacement；Role replacement；
   logical ID 变化；其它 IAM 变化；`site-artifacts` 精确权限的任何变化。
   （少一个 CDK asset 是预期的，那是 buildspec 不再上传。）

### B. 部署窗口：**操作员承诺的独占窗口**，不是技术上关掉了入口

CloudFormation **不保证** `Project` 的属性更新与 `IAM::Policy` 更新的先后。若策略先掉而
项目属性后切，那几十秒内**启动的**构建会取不到 buildspec 而失败（干净失败：部署 job 进
FAILED、可重试）。

**措辞要准**：本仓库没有维护开关，也没有能暂停 MCP/panel 写入口的机制。所以这一步的
真实内容是**单人环境下操作员承诺独占**：改动窗口内不自己发起部署，并在部署前确认此刻
没有在途工作。检查脚本的要求：

- 四个枚举（`list_builds_for_project`、`batch_get_builds`、`list_role_policies`、
  `list_attached_role_policies`）与 `site-deploy-jobs` 的 `scan` **全部用 paginator**；
  `batch_get_builds` 按 API 上限分批。实测该项目已有 **102** 个历史构建，取前 20 个
  必然漏掉更早仍在跑的那种；`scan` 的 `FilterExpression` 是每页 1MB 扫完才应用，
  只读第一页会漏掉后续分页里的 RUNNING job。
- 发现任何在途项就 **`raise SystemExit`**，不是打印 `True/False` 让人看——
  "打印了但没人拦"与"没有在途项"在自动执行下一模一样。
- **部署前立刻再查一次**（第一次查完到 CFN 开始更新之间仍可能进新任务）。
- 多用户环境下这一节不成立，需要真实的维护开关或暂停写入口——本 spec 明确只覆盖单人环境。

不为这个干净失败窗口设计两阶段迁移（"先内联并临时保留读权限、再单独删权限"）——
收益不值得那个复杂度。

### C. 部署后静态确认（只读，**用 assert 不用 print**）

1. **账号锚定**：`sts:GetCallerIdentity` 的账号必须等于 `config.ini` 里的账号
   （闸门脚本自己就这么做；这里少了它就可能对着另一个账号断言"已经收权了"）。
2. `codebuild batch-get-projects`：`source.type == "NO_SOURCE"`，且 `source.buildspec`
   **逐字节等于**仓库文件（**不是** S3 ARN）。
3. 沿该项目的 `serviceRole`、用 paginator 读 inline + attached policy，断言：
   bootstrap 桶 ARN **完全消失**；`validated/*` 的 `GetObject` 与 `artifacts/*` 的
   `PutObject` **仍在**；没有任何残留的 `s3:List*` / `s3:GetObject*`。
4. 三条全部 `assert`，任何一条不成立即终止。

### D. 行为确认

5. 跑当前完整 E2E 文件：

   ```bash
   set -euo pipefail
   cd "$(git rev-parse --show-toplevel)"
   RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
     site-builder/deployer/tests/test_e2e_fixtures.py -q
   ```

   **机械核实过：这个文件现在收集 10 条**（不是 4 条 fixture）。多条用例会重复部署
   `nosql-notes`，所以 `package_backend → CodeBuild` 会被**多次**经过。它覆盖到的与本
   改动相关的四件事：首次构建证明内联 buildspec 能被 CodeBuild 取用；更新构建证明不是
   只在创建时有效；失败恢复路径证明构建失败后项目仍可继续使用；NoSQL 与 DSQL 两类后端
   证明打包输出没有意外变化。**`约 6 分钟` 这个旧数字不要再引用**——按实测重新记。

6. 跑一次 opt-in 的真机行为探针（`RUN_CODEBUILD_SECURITY_PROBE=1`），含正向控制。

7. **不跑** `smoke_router.sh`：本改动不碰 CloudFront / Edge / route 注册 / 会话鉴权 /
   Function URL，而完整 E2E 本身已经通过公网路由访问生成的站点。

### E. 闸门与基线：**一次观测，三次使用**

上一版让 Task 3 实时跑一次闸门给人核对、Task 4 再实时跑一次 `--update-baseline`。那是
**TOCTOU**：两次观测各约 9.5 分钟，其间或第二次运行期间的任何 IAM 变化都会进新基线，
而人批准的并不是最终写进去的那一份。改成只观测一次、重复使用同一份字节
（`--from-dump` 与 `--update-baseline` 可同用，已核过 `main()` 的分支）：

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# ① 唯一一次 AWS 观测（约 9.5 分钟）。产物含真实角色名，**只许留在 /tmp，不得提交**。
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --dump-observed /tmp/m09-3b-observed.json
# ② 用同一份字节与旧基线比较，出闸门结论（不发 AWS 调用）
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --from-dump /tmp/m09-3b-observed.json
# ③ 人工核对 ② 的 delta 之后，从**同一份字节**写基线
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --from-dump /tmp/m09-3b-observed.json --update-baseline
```

② 的预期：退出码 0；只有**一条** improvement（那个 fp「不再具备任何敏感授权
（原 platform-overbroad）」）；A 62 → 61；可读密钥 57 → 56；`platform-overbroad` 1 → 0；
而 **B、resource policy、coverage、asset facts 全都不变**
（`edge_assets_carrying_live_key` 仍 9、`edge_code_targets_carrying_live_key` 仍 10、
`undecided_items` 774 → 774）。任何一项不符先查清原因再往下走。

③ 之后的基线 delta 必须用**结构化比较**硬断言，不许用 `git diff | grep | head -40`
那种**带截断的**读法（"不在前 40 行"不等于"不存在"）：把 `HEAD` 里的旧基线与工作树
里的新基线都 `json.load`，逐项断言 —— `principals` 恰好少一个**预期指纹**、被删条目的
`category`/`grants` 精确匹配、`facts` / `coverage` / `iam_write_statements` /
`permissions_boundaries` / `managed_policy_versions` / `resource_policies` / `schema`
**逐字节相同**、其余 61 条的 category 一个都没动。

最后：基线 JSON、文档里那 14 个带标记的数字、`account-trust-boundary.md` 的
「平台侧唯一的过宽授权」一节（改成"已收窄"并保留历史结论）必须进**同一个提交**——
文档数字测试会强制这个耦合，分开提交必红。收尾跑
`metamorphic_trust_boundary.py` 全量与七个包的全量测试。

## 回滚

revert `app.py` 那处改动并重新部署 deployer 栈。bootstrap 桶里那个孤儿 buildspec
asset 对象留着无害（它本来也不会被删）。若已经走到写基线那一步，则**一并 revert 基线与
文档那个提交**——否则闸门会把"权限回来了"报成红，而那正是它该做的；不要为了让闸门变绿
而保留新基线。**没有迁移、没有回填、没有补偿、没有状态**。

## 不变量（改完必须仍然成立）

- `site-package` 角色的 **S3 权限全集**精确等于两条：`s3:GetObject` on
  `site-artifacts-<acct>/validated/*`、`s3:PutObject` on
  `site-artifacts-<acct>/artifacts/*`。没有 `ListBucket`、没有 `DeleteObject`、
  没有通配动作、没有 `Resource: "*"`、没有任何 managed policy attachment
  （`app.py` 现有注释里的理由不变：`aws s3 cp --recursive` 需要 `ListObjectsV2`
  = `ListBucket` = 让构建容器能枚举所有 job）。**这条现在由检查器 ② 按等值断言**，
  不再是"没出现某个已知坏值"。
- buildspec 的**唯一真源**是 `site-builder/deployer/buildspec-package.yml`；
  部署出去的内容与它**逐字节**相同（含注释）。
- `npm install` 的 token 精确等于预期列表（含 `--ignore-scripts`），删 `.npmrc` 的命令
  精确存在且**严格早于**它，且除该 install 外没有其它 npm 子命令。由检查器 ① 断言。
- `test_validate.py` 现有的那条 AST 断言（`package_project` 手写资源集恰好是
  `{validated/*, artifacts/*}`）继续成立且**不放宽**——它仍然有价值（它守的是"源码里
  别手写多余前缀"），只是它证明不了角色权限的全貌，那由检查器 ② 补上。
- `import app` **无副作用**（`App()/synth()` 在 `__main__` 守卫之下）。

## 与下一条真修复的关系

本条**不**减少 `read-edge-code` / `read-jwt-param` 两条路上的任何 principal，也**不**
减少带活密钥的 asset 数（仍是 9）。下一条是**非对称签名**（KMS `kms:Sign` + Edge 只放
公钥），它才会让"只能经 asset 读到密钥"的那批（约 21 个）整个退出暴露面。顺序不能反：
先把跨越威胁边界的这条掐断（改动小、可回滚、不动签名链），再动签名链本身。

---

## 实施记录与验收证据（2026-08-27）

**这一节是这条改动的状态真源**，写在 spec 里而不是另建 handover 文件——本仓库的
`docs/design/` HANDOFF 都是 gitignored 的，CLAUDE.md 明确说那类文件不能当状态真源。

### 提交链

| 提交 | 内容 |
|---|---|
| `c15eef9` | 三个结构化检查器 + 外部反例；改正「唯一的隔断是 `--ignore-scripts`」这个说法 |
| `4fdec89` | **生产代码**：buildspec 逐字节内联，删掉整桶读；`__main__` 守卫；opt-in 模板断言 |
| `6760179` / `867e867` / `2eb6944` | 把实跑发现写回计划；探针前提改成实测；探针移出关键路径 |
| `79bf1e4` / `efd244d` / `a118db4` / `ed2d1ee` | 四轮外部复审的守卫修复（共 14 条，形态见下） |
| `34b87c5` / `8365a9c` | secret scan 的两处修复（假阳性 + 预处理 fail-open）＋ 它第一套回归测试 |
| `d3167d6` | **原子提交**：基线 + 14 个 marker 数字 + 风险文档 + CLAUDE.md |
| `18c01fa` | §9 的 3b 标成完成 |

### 落地数字（都由基线断言）

**A 62 → 61、可读密钥 57 → 56、`platform-overbroad` 1 → 0。**
**没有变的**：带活密钥的 asset 仍 **9**、Edge 代码目标仍 **10**、
`undecided_items` **774 → 774**、B 的 **22 holder / 43 语句**一字未动、
`resource_policies.platform` 与 bootstrap 桶策略不变。

写基线**之前**逐条核过 17 项条件（恰好 1 个 principal 退出、0 新增、被删条目的
`category`/`grants` 精确匹配、其余 61 条未动、facts/coverage/B/resource policies 全等），
写完再做一次结构化 delta 断言——**不用带截断的文本 diff**（"不在前 40 行"不等于"不存在"）。

### 验收证据（分层，别把一层当另一层）

| 层 | 证据 |
|---|---|
| 静态（部署前） | `cdk diff` 只引入 3 处资源变更，`IAM Statement Changes` 恰好一条删除、零新增；13 个 Lambda 的 `Code.S3Key` churn 是**既有现象**（把 `app.py` 换回上一版再 diff 一次，13 个照样变） |
| 静态（不触发替换） | CFN 资源 schema 的 `createOnlyProperties` 只有 `/properties/Name` ⇒ 改 `Source` 不替换；部署后项目 `created` 仍是 7-29，实测确认 |
| 单测 / opt-in | 检查器 92 passed；deployer 1091 passed / 52 skipped；opt-in 真 synth 模板 35 passed；七包 **2372 passed**；变形 **37/37 全红** |
| **部署前的真机预演** | 那段部署后验收代码在**部署之前**就对着生产只读跑过一次，红绿与"尚未部署"逐项吻合（两红一绿）——这证明验收脚本能识别旧状态，而不是"无论部署前后都绿" |
| 部署后静态 | `source.type=NO_SOURCE`、buildspec 与仓库文件**逐字节相同**、S3 权限全集精确等于两条（无 managed attachment、桶策略授给它 0 条）、`site-deployer-exec-role` 的 `codebuild:StartBuild` 资源仍精确等于那一个项目 ARN |
| **行为** | 完整 E2E **10 passed，实测 37 分 21 秒**；**当天 20 次 `site-package` 构建（13:30–14:17，截至 14:17）全部 SUCCEEDED，20/20 都是 `NO_SOURCE` + 内联 buildspec**（1721 字节，与仓库文件逐字节相同；`sha256[:12]=50bad5712a17`）——这才是"CodeBuild 真的接受并执行了它"的证据，模板层字节相等只证明结构。**别按"4 次"记**：那是 13:36 前的计数，写进提交信息时（14:53）已经过时，外部复审按生产实况纠正为 20 次 |

### 三条实施期的坑（都花过时间）

1. **完整 E2E 现在要 37 分 21 秒**，超过很多工具的单次超时上限。被 SIGTERM 掉时 autouse
   的清理 fixture 跑不完 ⇒ 留下真站点。要后台跑。
2. **"按残留 Lambda 找泄漏"会漏掉 static 站点**——static 没有后端 Lambda，只有路由表条目、
   前端 S3 前缀与 sites 行。第一轮清理就漏了一个。查泄漏要同时看
   `site-sites` 里 `status != DELETED` 的行。清理一律走平台自己的 undeploy 路径
   （`purge_data=True` + 强一致读回确认 `DELETED`），别手工删资源。
3. **信任边界闸门有一个约 10 分钟的 TOCTOU**（枚举 → 逐个模拟），而
   **它不只是可用性问题——这里原先的定性是错的**。`NoSuchEntity` 硬失败只覆盖
   "模拟时角色已经不在了"这一种 churn；同名重建（ARN 不变、RoleId 变）、窗口内改策略、
   T1 之后新建 principal 这三类都会**静默**产出混了两个时刻的快照。
   **实测**：写下当前基线的那次运行本身窗口内就有两条 `PutRolePolicy`（CloudTrail），
   只是恰好落在既不进 A 也不进 B 的角色上 ⇒ 值没错，"一个时刻的快照"这句话是假的。
   已修：模拟后再枚举一次并逐个比对 `uid`/boundary/全部语句，任一类漂移即作废本轮
   （`enumeration_drift` + 10 条用例 + 5 个变异验证）。详见
   `account-trust-boundary.md` 的闸门 caveat 一节。

### 这条改动被外部复审抓出 14 次同一个错误

全部形如**「枚举范围比声称的主语窄」**：只看源码手写的语句（漏 CDK 自动加的）；只看"含某个
子串"（漏 `--ignore-scripts=false`）；只看首 token 是 `npm` 的命令（漏 `env npm rebuild`）；
只看 identity policy（漏 `AWS::S3::BucketPolicy`）；桶策略只比 `Principal.AWS` 字面量
（漏账号 root + `aws:PrincipalArn` 条件）；Action 用 `fnmatchcase`（IAM 动作**不区分大小写**）；
import-time 遍历跳过类体与 annotation（**类的体在 import 时会执行**）；
`StringEqualsIgnoreCase` 写进了支持列表却没实现它的语义。

**统一解法**：把完整集合与精确期望比**等值**，而不是逐个排除已知坏形态；判据抽成纯函数让
**所有调用点共用**（包括真机验收——否则真机侧必然长出一套更弱的字符串 grep）；
每组反例必须**含一批由复审方提出、逐字纳入的**，并且配正向控制（否则"把一切都判红"也能
让反例全过）。
