# M09 真修复①：收窄 CodeBuild 对 CDK bootstrap 桶的读权限

> **状态：设计已定稿，未实施。** 这是 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`
> §9 的 **3b**。风险模型的真源是 `docs/security/account-trust-boundary.md`，本文不重复它，
> 只写这一条改动。**它是一次生产 IAM 改动**，实施前需要人工放行。

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

`site-package` 是整个平台里**唯一**以站点作者可控的输入（`package.json`）驱动、
且在容器内执行第三方代码安装流程的地方。今天唯一的隔断是 buildspec 第 22 行的
`npm install --ignore-scripts`（外加第 18 行先删站点自带的 `.npmrc`）。那条 flag
一旦被去掉、或将来支持 Python 后端而用 `pip install` 装 sdist，这条链就从
「账号内部暴露」变成**「不可信站点作者可窃取平台签名密钥」**——而后者正是整套设计
声称要防的威胁。

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

## 守卫：三层，各自能证明什么

`deployer/.venv` **没有 `aws_cdk`**（实测 `ModuleNotFoundError`）。所以"断言
`is_immediate is True` / `to_build_spec()` 与文件字节相等"这类**语义**断言进不了默认
测试套件——它们必须 import 生产代码。三层如下，各层的承诺**不许互相冒充**：

**第一层：always-on 文本/AST 守卫**（默认 `deployer` 套件，不需要 aws_cdk）

- `app.py` 里不许出现 `BuildSpec.from_asset`（AST 或整份文本断言，二者都可——
  这是一条纯文本事实，文本守卫能证明它）；
- `app.py` 里 buildspec 必须经 `read_bytes().decode(` 读取，不许退回 `read_text(`；
- **顺带补两条本来就该有的**：buildspec 里必须出现 `--ignore-scripts`，且必须有
  删除 `.npmrc` 的那一步。实测**今天没有任何测试断言这两行**——`--ignore-scripts`
  只在 `contract/redlines.py` 的一句注释里被提到，而 `.npmrc` 那条红线是**合同校验器
  拒绝站点自带 `backend/.npmrc`**（另一个控制点，不是 buildspec 这一步）。
  本 spec 的「不变量」一节声称这两行仍在，而无守卫的声称在这个仓库里等于没有声称。
  这两条与本改动同文件同威胁，属直接相邻面，不算扩范围。

**这一层证明不了 `Source.BuildSpec` 等于文件字节**——那是语义。见
`syntax-guards-cannot-prove-semantics` 那条教训，以及上面「守卫只看见了一半」那节：
语法/AST 黑名单挡不住语义倒退，也看不见 CDK 自动生成的那半边策略。
所以它只承担"`from_asset` 别回来 / 读法别退化 / 两条隔断别消失"这三件纯文本的事。

**第二层：opt-in synth/模板断言**（`SB_CDK_TESTS=1` + PYTHONPATH 桥接）

按仓库既有形态（缺 `aws_cdk` 时**报错而非静默 skip**）：

- 直接 import `app.py` 拿 `_InlineBuildSpec`（只 import 不实例化栈 ⇒ **不需要
  Docker**）：`is_immediate is True`；`to_build_spec().encode("utf-8")` 等于
  `buildspec-package.yml` 的 `read_bytes()`；
- 对整个 `SiteDeployerStack` synth（**需要 Docker**，Lambda bundling）后断言：
  - `Source.Type == "NO_SOURCE"`；
  - `Source.BuildSpec.encode("utf-8") == BUILDSPEC_PATH.read_bytes()`，且它**不是**
    `Fn::Join` / 不含 `arn:` / 不含 `cdk-hnb659fds-assets`；
  - `PackageProject` 角色的策略里**不出现任何 bootstrap 桶 ARN**；
  - 该角色**仍保留** `validated/*` 的精确 `s3:GetObject` 与 `artifacts/*` 的精确
    `s3:PutObject`（正向控制：证明这条断言不是因为整个策略都没了才通过的）。

**第三层：真机闸门**（`verify_account_trust_boundary.py`，约 9±1 分钟）

这才是这条安全属性的真回归守卫：权限回来了就是"既有 principal 新增 grant" ⇒ **红**。
它不是单测，跑一次要真凭证。

**反向验证**：上面每条新守卫都要在 `metamorphic_trust_boundary.py` 里配一条变形
（把 `_InlineBuildSpec` 换回 `from_asset`、把 `read_bytes().decode(` 换回
`read_text(`、把模板断言的资源集合放宽），并过那四关（变形前基准全绿且选中≥1 条 /
变形后可编译导入 / rc==1 / 末行有实际 `N failed`）。

## 实施与验收顺序

### A. 部署前（不碰生产）

1. 第一层守卫 + `deployer` 全量；第二层 opt-in CDK 测试（带 PYTHONPATH 桥接）。
2. `cd site-builder/deployer/infra && rm -rf cdk.out && cdk diff`。
   **预期有两类变化，不是一类**：
   - `AWS::CodeBuild::Project` 的 `Source.BuildSpec`：S3 ARN → 内联 YAML 字符串；
   - `AWS::IAM::Policy`（PackageProject 角色）：删掉 bootstrap 整桶读那一条。

   把预期写成"diff 只少一条 IAM 语句"是错的——属性本身也必须变。
3. 明确确认 diff 里**没有**：CodeBuild Project replacement；Role replacement；
   logical ID 变化；其它 IAM 变化；`site-artifacts` 精确权限的任何变化。
   （少一个 CDK asset 是预期的，那是 buildspec 不再上传。）

### B. 部署窗口

CloudFormation **不保证** `Project` 的属性更新与 `IAM::Policy` 更新的先后。若策略先
掉而项目属性后切，那几十秒内**启动的构建会取不到 buildspec 而失败**。失败是干净的
（部署 job 进 FAILED，重试即可），所以：

1. 暂停新的站点 deploy / confirm 入口；
2. 确认 `site-package` 没有 `IN_PROGRESS` 的 build；
3. 确认没有 RUNNING 的站点部署 job；
4. 等 CloudFormation 到 `UPDATE_COMPLETE` 再恢复入口。

这是个人测试/开发环境，**不为这个干净失败窗口设计两阶段迁移**。若将来要求零失败窗口，
才考虑"先内联并临时保留显式读权限、再单独删权限"两次部署——此处收益不值得那个复杂度。

### C. 部署后静态确认（只读）

1. `codebuild batch-get-projects`：`source.type == NO_SOURCE`，且
   `source.buildspec` 与仓库文件原文逐字节相同（**不是** S3 ARN）；
2. 沿该项目的 `serviceRole` 读 inline + attached policy：bootstrap 桶 ARN
   **完全消失**；`validated/*` 的 `GetObject` 与 `artifacts/*` 的 `PutObject`
   **仍在**；
3. 确认没有任何残留的 `s3:List*` / `s3:GetObject*` 指向 bootstrap 桶。

### D. 行为确认

4. 跑当前完整 E2E 文件：

   ```bash
   RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
     site-builder/deployer/tests/test_e2e_fixtures.py -q
   ```

   **机械核实过：这个文件现在收集 10 条**（不是 4 条 fixture）。多条用例会重复部署
   `nosql-notes`，所以 `package_backend → CodeBuild` 会被**多次**经过，而不是只在
   首次创建时验证一次。它覆盖到的与本改动相关的四件事：首次构建证明内联 buildspec
   能被 CodeBuild 取用；更新构建证明不是只在创建时有效；失败恢复路径证明构建失败后
   项目仍可继续使用；NoSQL 与 DSQL 两类后端证明打包输出没有意外变化。
   **`约 6 分钟` 这个旧数字不要再引用**——条数已经变了，耗时按实测重新记。

5. **不跑** `smoke_router.sh`：本改动不碰 CloudFront / Edge / route 注册 / 会话鉴权 /
   Function URL，而完整 E2E 本身已经通过公网路由访问生成的站点。多出来的时间买不到
   与本改动相关的信号。

### E. 闸门与基线（**先不更新基线**）

6. 跑 `python3 site-builder/scripts/verify_account_trust_boundary.py`，预期：
   - 退出码 0；
   - 只有预期的 improvement（那个 fp「不再具备任何敏感授权（原 platform-overbroad）」）；
   - A 62 → 61；可读密钥 57 → 56；`platform-overbroad` 1 → 0；
   - **B、resource policy、coverage、asset facts 都不应变化**（`edge_assets_carrying_live_key`
     仍是 9、`edge_code_targets_carrying_live_key` 仍是 10、`undecided_items` 774→774）。
     任何一项动了都要先查清原因再往下走。
7. **人工核对上述 delta**，确认与预期逐项一致，再 `--update-baseline`。
8. **一个原子提交**里同时更新：基线 JSON、文档里那 14 个带标记的数字、
   `account-trust-boundary.md` 里「平台侧唯一的过宽授权」那一节（改成"已收窄"并保留
   历史结论）、以及新增/调整的守卫。
   文档数字测试会强制这个同提交耦合——分开提交必红。
9. 最后跑 `metamorphic_trust_boundary.py` 全量与七个包的全量测试。

## 回滚

revert `app.py` 那处改动并重新部署 deployer 栈。bootstrap 桶里那个孤儿 buildspec
asset 对象留着无害（它本来也不会被删）。**没有迁移、没有回填、没有补偿、没有状态**——
这是一条属性 + 一条 IAM 语句的改动，回滚就是反向的同一次部署。

## 不变量（改完必须仍然成立）

- `site-package` 的构建容器**只能**读 `site-artifacts-<acct>/validated/*`、
  **只能**写 `site-artifacts-<acct>/artifacts/*`，且没有 `ListBucket`、没有
  `DeleteObject`（`app.py` 现有注释里的理由不变：`aws s3 cp --recursive` 需要
  `ListObjectsV2` = `ListBucket` = 让构建容器能枚举所有 job）。
- buildspec 的**唯一真源**是 `site-builder/deployer/buildspec-package.yml`；
  部署出去的内容与它逐字节相同（含注释）。
- `--ignore-scripts` 与"先删 `.npmrc`"两条仍在。**注意：今天这两行没有任何测试守着**
  （`test_validate.py` 断言的是 `validated_key($JOB_ID)` 在、`uploads/$JOB_ID` 不在，
  以及 app.py 里那个角色手写的资源集合），所以本改动顺带给它们补上第一层文本守卫。
- `test_validate.py` 现有的那条 AST 断言（`package_project` 手写资源集恰好是
  `{validated/*, artifacts/*}`）继续成立且**不放宽**；本改动只是在它旁边补上一层
  看合成后模板的断言，因为那条 AST 断言结构上看不见 CDK 自动生成的语句。

## 与下一条真修复的关系

本条**不**减少 `read-edge-code` / `read-jwt-param` 两条路上的任何 principal，也**不**
减少带活密钥的 asset 数（仍是 9）。下一条是**非对称签名**（KMS `kms:Sign` + Edge 只放
公钥），它才会让"只能经 asset 读到密钥"的那批（约 21 个）整个退出暴露面。顺序不能反：
先把跨越威胁边界的这条掐断（改动小、可回滚、不动签名链），再动签名链本身。
