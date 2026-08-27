# 收窄 CodeBuild 对 CDK bootstrap 桶的读权限 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让跑不可信站点依赖安装的 CodeBuild 项目（`site-package`）不再对整个 CDK bootstrap asset 桶有读权限——那个桶里有 9 个仍带明文会话签名密钥的 Edge asset。

**Architecture:** 那条权限是 `cb.BuildSpec.from_asset()` 让 CDK 自动加的（`Asset.grantRead()` 授整桶），唯一用途是取项目自己那 25 行 buildspec。用一个自定义 `cb.BuildSpec` 子类把 buildspec 原文**逐字节**内联进 CloudFormation 模板，这条权限整条消失（不是收窄）。守卫分三层，各层只承担自己能证明的事：always-on 文本守卫管"源码里那句话别回来"，opt-in 模板断言管"部署出去的东西真是内联的、且角色策略里没有 bootstrap 桶"，真机闸门管"权限别再长回来"。

**Tech Stack:** Python 3.12 / aws-cdk-lib 2.262.1（`infra/.venv`）/ pytest（`deployer/.venv`，**不含 aws_cdk**）/ CloudFormation / CodeBuild / IAM

**Spec:** `docs/superpowers/specs/2026-08-27-codebuild-bootstrap-read-narrowing-spec.md`

## Global Constraints

- **us-east-1 是硬约束**（Lambda@Edge 与 CloudFront 的 ACM 证书），本计划不涉及换区。
- **不得把真实账号 ID / 内部角色原名写进任何被跟踪的文件。** 提交前 `bash site-builder/scripts/scan_staged_secrets.sh` 必须 clean。
- **`verify_*` 脚本一律用系统 `python3` 跑**，不要用 `site-builder/deployer/.venv/bin/python3`：那个解释器的 CA 信任库是空的，每次 HTTPS 都 `CERTIFICATE_VERIFY_FAILED`（症状像网络故障，其实不是）。
- **每个提交都必须是绿的、可运行的 checkout。** 不许提交红着的测试（上一轮刚为此重排过历史）。
- **`deployer/.venv` 没有 `aws_cdk`**（实测 `ModuleNotFoundError`）。任何需要 import `infra/app.py` 的测试都必须走 PYTHONPATH 桥接并 opt-in，且缺依赖时**报错而非静默 skip**。
- **测试命令照抄，别猜**：默认套件是 `cd site-builder/deployer && .venv/bin/pytest tests -q`（**必须带 `tests/`**，裸 `pytest` 会误收集 `infra/cdk.out` 里的 asset 副本）。
- **改了 `infra/app.py` 的 bundling 段要跑 auth 那套才会红**（守卫住在 `auth/tests/test_requirements_locked.py`）。本计划不碰 bundling 段，但 Task 2 的收尾仍跑一次 auth 以证明没碰到。
- **Task 3 与 Task 4 是生产改动，必须单独获得人工放行才能开始。** Task 1 / Task 2 不碰生产。

### 与 spec 的一处**有意偏离**（已同步回 spec）

spec 的「反向验证」一节原写"每条新守卫在 `metamorphic_trust_boundary.py` 里配一条变形"。本计划改为**在测试文件内做负向 meta-test**（把源码文本读进来、在内存里造出退化、断言守卫函数会报违规），理由有两条：

1. 那个 harness 会**临时改工作树里的文件再还原**。它现在的目标文件只有闸门脚本与闸门测试；把 `infra/app.py`（生产 CDK 源码）和 `buildspec-package.yml`（安全隔断所在处）加进去，意味着进程被 SIGKILL 时工作树里会留下一份被改坏的生产基础设施源码。
2. 守卫本身就是"对一段文本求违规列表"的纯函数，负向 meta-test 能给出**同样强度**的证据（守卫真的会红），却完全不碰工作树，而且跑在**默认套件**里而不是一个要手工跑的脚本里。

`metamorphic_trust_boundary.py` 在本计划中**不改**。

---

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/deployer/infra/app.py` | deployer 栈定义。新增 `BUILDSPEC_PATH` 常量与 `_InlineBuildSpec` 子类；`cb.Project` 的 `build_spec` 换掉 | Modify（Task 2） |
| `site-builder/deployer/tests/test_validate.py` | 已有"构建容器那个角色能碰哪些前缀"的 AST 守卫。新增两组**文本**守卫函数 + 各自的负向 meta-test | Modify（Task 1、Task 2） |
| `site-builder/deployer/tests/test_infra_tables.py` | 仓库里唯一的 CDK 模板断言文件（opt-in，`SB_CDK_TESTS=1`）。新增 buildspec 内联与角色策略的模板断言 | Modify（Task 2） |
| `site-builder/scripts/account_trust_baseline.json` | 信任边界闸门的基线 | Modify（Task 4） |
| `docs/security/account-trust-boundary.md` | M09 结论真源，含 14 个由基线断言的数字 | Modify（Task 4） |

**为什么模板断言加在 `test_infra_tables.py` 而不是新建文件**：那个文件的 `template` fixture synth **整个** stack（Lambda bundling 要起 Docker）。新建文件就要么复制那段 fixture（重复的测试脚手架，且会 synth 两次 = 两次 Docker），要么把 fixture 提到 `conftest.py`（改动一个正绿的共享文件）。加在原文件里只需改它的 docstring，且"一条命令跑完所有需要 Docker 的断言"这个属性得以保留。Task 2 的 Step 1 会把 docstring 从"二期新增的表与索引"改成覆盖面更准的说法。

---

## Task 1: 补上构建容器两条隔断的文本守卫

**为什么先做这个**：`--ignore-scripts` 与"先删 `.npmrc`"是今天**唯一**挡在「不可信站点作者」与「平台签名密钥」之间的东西，而实测**没有任何测试断言这两行**（`--ignore-scripts` 只在 `contract/redlines.py` 的一句注释里出现；`.npmrc` 那条红线是合同校验器拒绝站点自带 `backend/.npmrc`，是另一个控制点，不是 buildspec 里那步 `find -delete`）。Task 2 之前它们仍然承重，所以先钉住。本任务**不改生产代码**。

**Files:**
- Modify: `site-builder/deployer/tests/test_validate.py`（在 `test_buildspec_and_iam_name_the_validated_prefix_only`，约 334-358 行之后追加）

**Interfaces:**
- Produces: `_build_container_interlock_violations(spec_src: str) -> list[str]` —— Task 2 不使用它，但同文件后续守卫沿用同一形态（**纯函数吃源码文本、吐违规说明列表**），因为这个形态才能写负向 meta-test。

- [ ] **Step 1: 写失败的测试**

**先补 import**（核过了：`test_validate.py` 的模块级 import 只有 `io / json / warnings / zipfile / boto3 / pytest`——**既没有 `re` 也没有 `Path`**，照抄下面的代码会 `NameError`）。把第 1-4 行的 stdlib 块改成：

```python
import io
import json
import re
import warnings
import zipfile
```

`Path` **不加到模块级**，而是在每个新测试函数体内 `from pathlib import Path`——邻居那条
`test_buildspec_and_iam_name_the_validated_prefix_only` 就是这么写的，跟着它的形态走。

然后在 `test_buildspec_and_iam_name_the_validated_prefix_only` 之后追加：

```python
# ── 构建容器的两条隔断 ──────────────────────────────────────────────────
# 这两行是「不可信站点作者」与「平台签名密钥」之间当前唯一的东西，而在本任务之前
# **没有任何测试断言它们**（`--ignore-scripts` 只出现在 contract/redlines.py 的一句
# 注释里；`.npmrc` 那条红线是合同校验器拒绝站点自带 backend/.npmrc —— 另一个控制点，
# 不是 buildspec 里这步 find -delete）。无守卫的声称等于没有声称。
#
# 守卫写成**纯函数吃文本、吐违规列表**，是为了能写负向 meta-test：这两条断言在写下的
# 那一刻就是绿的（pass-now），不证明它们会红的话，等于什么都没加。
def _build_container_interlock_violations(spec_src: str) -> list[str]:
    """`buildspec-package.yml` 里两条隔断是否还在。空列表 = 合格。

    **两条都钉在命令行上，不是"文件里出现过这个字符串"**：buildspec 的注释里也写着
    `--ignore-scripts`（那段解释它为什么必需），所以子串检查在"只删命令、留注释"时会
    照样绿——那正是本轮反复出现的那个错误：守卫的主语（"装依赖时带没带这个 flag"）
    比它的证据（"文件里有没有这几个字"）宽。
    """
    out = []
    if not re.search(r"^\s*-\s*npm install[^\n]*--ignore-scripts", spec_src, re.M):
        out.append(
            "npm install 那条命令上没有 --ignore-scripts —— 站点 package.json 由 AI "
            "生成、owner 可任意改，preinstall/postinstall 会在构建容器内以构建角色"
            "凭证任意执行（注释里提到它不算，要在命令上）")
    if not re.search(r"^\s*-\s*find\b[^\n]*-name\s+\.npmrc\b[^\n]*-delete", spec_src,
                     re.M):
        out.append(
            "没有删 .npmrc 的那条命令 —— 站点自带 .npmrc 能改 registry 拉入恶意包，"
            "而 CLI 上的 --ignore-scripts 盖不住 registry")
    return out


def test_buildspec_keeps_both_untrusted_build_interlocks():
    from pathlib import Path
    root = Path(__file__).parent.parent
    spec = (root / "buildspec-package.yml").read_text(encoding="utf-8")
    assert _build_container_interlock_violations(spec) == []


def test_the_interlock_guard_can_actually_fail():
    """pass-now 守卫必须证明它会红。逐条造一次退化，**不碰工作树**。"""
    from pathlib import Path
    root = Path(__file__).parent.parent
    good = (root / "buildspec-package.yml").read_text(encoding="utf-8")
    assert _build_container_interlock_violations(good) == [], "正向控制失效"

    # **只从命令上摘掉 flag、注释原样留着** —— 这才是有区分力的那次退化：
    # 子串式守卫在这里会绿，而钉在命令行上的守卫必须红。
    no_flag = re.sub(r"(^\s*-\s*npm install[^\n]*?) --ignore-scripts", r"\1", good,
                     flags=re.M)
    assert no_flag != good, "锚点没找到：npm install 那条命令的写法变了"
    assert "--ignore-scripts" in no_flag, \
        "前提：注释里那处必须留着，否则这条退化退化成了'整个文件都没这几个字'"
    assert any("ignore-scripts" in v
               for v in _build_container_interlock_violations(no_flag))

    no_npmrc = re.sub(r"^\s*-\s*find\b[^\n]*-name\s+\.npmrc\b[^\n]*-delete.*$", "",
                      good, flags=re.M)
    assert no_npmrc != good, "锚点没找到：删 .npmrc 那条命令的写法变了"
    assert any(".npmrc" in v
               for v in _build_container_interlock_violations(no_npmrc))
```

- [ ] **Step 2: 跑测试确认它们的状态**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_validate.py -k "interlock" -q
```

预期：**2 passed**。这两条本来就绿（那两行现在真的在），所以本步不是"看红"——**看红的责任在 `test_the_interlock_guard_can_actually_fail`**，它在内存里造出退化并要求守卫报违规。若它没通过，说明守卫的正则/子串与文件实际写法不匹配，先修守卫。

- [ ] **Step 3: 跑默认全量确认没有回归**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
```

预期：`1001 passed, 50 skipped`（改动前是 999 passed；本任务加 2 条）。若基数不是 999，以当次实测为准、不要照抄本数字。

- [ ] **Step 4: 提交**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/tests/test_validate.py
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
test(M09): 给构建容器的两条隔断补守卫（--ignore-scripts / 删 .npmrc）

实测这两行今天**没有任何测试守着**：`--ignore-scripts` 只出现在
contract/redlines.py 的一句注释里；`.npmrc` 那条红线是合同校验器拒绝站点自带
backend/.npmrc —— 另一个控制点，不是 buildspec 里这步 find -delete。
而它们是「不可信站点作者」与「平台签名密钥」之间当前唯一的东西。

守卫写成纯函数吃文本、吐违规列表，另配一条负向 meta-test 在内存里逐条造退化
并要求守卫报违规——这两条断言写下时就是绿的，不证明它们会红等于什么都没加。
不走 metamorphic harness 是刻意的：那个 harness 会临时改工作树里的文件，
把 buildspec 加进去意味着进程被杀时工作树里留下一份被改坏的安全隔断。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Task 2: 把 buildspec 逐字节内联，删掉整桶读

**Files:**
- Modify: `site-builder/deployer/infra/app.py`（常量区约 78 行 `VALIDATED_PREFIX` 附近加 `BUILDSPEC_PATH`；`cb.Project` 在 311-318 行）
- Modify: `site-builder/deployer/tests/test_validate.py`（追加交付方式的文本守卫 + 负向 meta-test）
- Modify: `site-builder/deployer/tests/test_infra_tables.py`（追加模板断言；改 docstring）

**Interfaces:**
- Consumes: 无（Task 1 的产物不被本任务使用）
- Produces:
  - `app.BUILDSPEC_PATH: pathlib.Path` —— 指向 `site-builder/deployer/buildspec-package.yml`
  - `app._InlineBuildSpec(text: str)` —— `is_immediate -> bool`（恒 True）、`to_build_spec(scope=None) -> str`（原样返回构造时那段文本）
  - `test_validate._buildspec_delivery_violations(app_src: str) -> list[str]`
  - `test_infra_tables._package_project_role_policies(tpl: dict) -> list[dict]`

- [ ] **Step 1: 写失败的 always-on 文本守卫**

在 `site-builder/deployer/tests/test_validate.py` 里 Task 1 那段之后追加：

```python
# ── buildspec 的交付方式 ────────────────────────────────────────────────
# 主语是"源码文本里有没有某句话"，所以文本断言是**恰好**够用的证据。
# 它证明不了"部署出去的 Source.BuildSpec 等于文件字节"——那是语义，住在
# tests/test_infra_tables.py 的模板断言里（opt-in）。
# 把语义 claim 挂在文本守卫上，正是 `_package_project_resources` 那条守卫漏掉整桶读
# 的同一个错误：主语是"这个角色的全部权限"，证据只是"源码里手写的那部分权限"。
#
# 注意 needle 用 `BuildSpec.from_asset` 而不是 `from_asset`：app.py 里
# `lam_.Code.from_asset(...)` 是合法且必需的，两者不能混为一谈。
def _buildspec_delivery_violations(app_src: str) -> list[str]:
    """`infra/app.py` 交付 buildspec 的方式是否退化。空列表 = 合格。"""
    out = []
    if "BuildSpec.from_asset" in app_src:
        out.append(
            "app.py 出现 BuildSpec.from_asset —— CDK 会给项目角色授**整桶** "
            "bootstrap 读（Asset.grantRead），而那个桶里有带明文会话签名密钥的 "
            "Edge asset，本项目跑的正是不可信站点的依赖安装")
    if 'BUILDSPEC_PATH.read_bytes().decode("utf-8")' not in app_src:
        out.append(
            "buildspec 不再用 read_bytes().decode(\"utf-8\") 读 —— 文本模式会做换行"
            "归一化，模板里那段字符串就不再与文件原始字节相等")
    if "build_spec=_InlineBuildSpec(" not in app_src:
        out.append("cb.Project 的 build_spec 不再是 _InlineBuildSpec(...)")
    return out


def test_buildspec_is_inlined_not_delivered_through_the_bootstrap_bucket():
    from pathlib import Path
    root = Path(__file__).parent.parent
    app = (root / "infra" / "app.py").read_text(encoding="utf-8")
    assert _buildspec_delivery_violations(app) == []


def test_the_buildspec_delivery_guard_can_actually_fail():
    """三条各造一次退化，**不碰工作树**。"""
    from pathlib import Path
    root = Path(__file__).parent.parent
    good = (root / "infra" / "app.py").read_text(encoding="utf-8")
    assert _buildspec_delivery_violations(good) == [], "正向控制失效"

    back_to_asset = good.replace(
        'build_spec=_InlineBuildSpec(BUILDSPEC_PATH.read_bytes().decode("utf-8"))',
        "build_spec=cb.BuildSpec.from_asset(str(BUILDSPEC_PATH))")
    assert back_to_asset != good, "锚点没找到——实现变了，守卫要同步更新"
    assert any("整桶" in v for v in _buildspec_delivery_violations(back_to_asset))

    text_mode = good.replace('BUILDSPEC_PATH.read_bytes().decode("utf-8")',
                             'BUILDSPEC_PATH.read_text(encoding="utf-8")')
    assert text_mode != good, "锚点没找到——读法的写法变了"
    assert any("read_bytes" in v for v in _buildspec_delivery_violations(text_mode))

    unwired = good.replace("build_spec=_InlineBuildSpec(",
                           "build_spec=cb.BuildSpec.from_object(")
    assert unwired != good, "锚点没找到——build_spec 的接线写法变了"
    assert any("_InlineBuildSpec" in v for v in _buildspec_delivery_violations(unwired))
```

- [ ] **Step 2: 跑它们，确认前两条真的红**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_validate.py -k "buildspec_delivery or buildspec_is_inlined" -q
```

预期：**2 failed**。`test_buildspec_is_inlined_not_delivered_through_the_bootstrap_bucket` 报三条违规（`from_asset` 在、`read_bytes` 不在、`_InlineBuildSpec` 不在）；`test_the_buildspec_delivery_guard_can_actually_fail` 在第一句正向控制上就断言失败。**这一步必须真的看到红**——看不到红说明守卫的 needle 写错了，不是代码已经改好了。

- [ ] **Step 3: 改 `infra/app.py`（常量）**

在 `VALIDATED_PREFIX = _validate_const("VALIDATED_PREFIX")` 那一行之后追加：

```python
# CodeBuild 的 buildspec：**逐字节内联**进模板，不走 CDK asset。
# `read_bytes().decode("utf-8")` 而不是 `read_text()`：后者走文本模式会做换行归一化，
# 那样"模板里的字符串重新编码后等于文件原始字节"这条断言就不再在任何平台上成立。
# （实测本文件今天是纯 LF，两种读法结果相同——这是稳健性措施，不是在修现存 bug。）
BUILDSPEC_PATH = Path(__file__).parents[1] / "buildspec-package.yml"
```

- [ ] **Step 4: 改 `infra/app.py`（子类）**

在模块级、`class SiteDeployerStack(Stack):` 之前追加：

```python
class _InlineBuildSpec(cb.BuildSpec):
    """把仓库里的 buildspec 原文**逐字节**内联进 CodeBuild Project。

    **为什么不用 `cb.BuildSpec.from_asset()`**：CDK 会给项目角色授**整桶**读
    （`Asset.grantRead()` 授的是桶，不是那一个对象），而同一个 CDK bootstrap 桶里有
    9 个仍带明文会话签名密钥的 Edge asset —— 而本项目跑的正是不可信站点的依赖安装。
    那条权限的唯一用途是取这份 buildspec 自己，内联之后它整条消失。

    **为什么不先解析成 dict**（`from_object` / `from_object_to_yaml`）：那会把文件
    重新序列化，注释全丢 —— 而 `--ignore-scripts` 为什么必需、`.npmrc` 为什么要先删，
    理由就写在注释里。重新序列化还让 `version: 0.2`（YAML float）往返一次，等价性
    只能靠真跑一次构建来证明；一条纯收权的改动不该承担那个风险。

    `is_immediate` 与 `to_build_spec()` 都是 `BuildSpec` 的**公开** abstract 成员
    （aws-cdk-lib 2.262.1 实测），不是私有接口。`is_immediate` 必须为 True，
    否则 CDK 不会把它渲染成内联字符串。
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

- [ ] **Step 5: 改 `infra/app.py`（接线）**

把 311-318 行的

```python
        package_project = cb.Project(
            self, "PackageProject", project_name="site-package",
            build_spec=cb.BuildSpec.from_asset(
                str(Path(__file__).parents[1] / "buildspec-package.yml")),
```

改成

```python
        package_project = cb.Project(
            self, "PackageProject", project_name="site-package",
            build_spec=_InlineBuildSpec(BUILDSPEC_PATH.read_bytes().decode("utf-8")),
```

其余参数（`environment`、`timeout`）与紧随其后的两条 `add_to_role_policy`（`validated/*` 读、`artifacts/*` 写）**一个字都不改**。

- [ ] **Step 6: 跑 always-on 守卫，确认转绿**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_validate.py -q
```

预期：全绿。特别确认 `test_buildspec_and_iam_name_the_validated_prefix_only`（那条既有的 AST 断言）**仍然通过且没被放宽**——它断言 `package_project` 手写的资源集合恰好是 `{validated/*, artifacts/*}`。

- [ ] **Step 7: 写 opt-in 模板断言**

先把 `site-builder/deployer/tests/test_infra_tables.py` 的 docstring 第一行从

```
"""CDK 模板断言：二期新增的表与索引必须存在，且 step Lambda 拿到 ADMINS_TABLE。
```

改成

```
"""CDK 模板断言：二期新增的表与索引、以及 CodeBuild buildspec 的交付方式与
PackageProject 角色的**全部** IAM 语句。

**本文件是仓库里唯一看"合成后模板"的地方**，所以凡是"源码 AST 看不见"的断言都归这里
（CDK 自动生成的 IAM 语句就属于这一类，见 `_package_project_role_policies` 的说明）。
```

然后在文件顶部常量区（`CONFIG = ...` 之后）追加：

```python
BUILDSPEC = Path(__file__).parents[1] / "buildspec-package.yml"
```

在文件末尾追加：

```python
def _package_project_role_policies(tpl: dict) -> list[dict]:
    """模板里挂在 PackageProject 角色上的**全部** `AWS::IAM::Policy`。

    **为什么必须看模板，而不是像 `test_validate.py` 那样看 app.py 的 AST**：
    那条 AST 断言遍历 `package_project.add_to_role_policy(...)`，也就是**手写的那一半**；
    CDK 从 `BuildSpec.from_asset()` 自动加进 `PackageProjectRoleDefaultPolicy` 的整桶读
    对它**结构上不可见**。于是那个洞在一条主语完全正确的守卫（"多一项就是给不可信构建
    多开一个前缀"）底下活了下来。模板才是角色策略的全貌。
    """
    roles = [lid for lid, r in tpl["Resources"].items()
             if r["Type"] == "AWS::IAM::Role"
             and lid.startswith("PackageProjectRole")]
    assert len(roles) == 1, f"PackageProject 角色没唯一定位到：{roles}——构造被改名了？"
    ref = roles[0]
    out = [r for r in tpl["Resources"].values()
           if r["Type"] == "AWS::IAM::Policy"
           and any(x.get("Ref") == ref for x in r["Properties"].get("Roles", []))]
    assert out, "没找到挂在 PackageProject 角色上的 IAM::Policy——定位逻辑失效了"
    return out


def _package_project_source(tpl: dict) -> dict:
    projects = [r["Properties"]["Source"] for r in tpl["Resources"].values()
                if r["Type"] == "AWS::CodeBuild::Project"
                and r["Properties"].get("Name") == "site-package"]
    assert len(projects) == 1, f"site-package 项目没唯一定位到：{len(projects)} 个"
    return projects[0]


def test_package_project_buildspec_is_inlined_byte_for_byte(template):
    """部署出去的 buildspec 必须是文件原文，不是指向 bootstrap 桶的 S3 ARN。"""
    src = _package_project_source(template.to_json())
    assert src.get("Type") == "NO_SOURCE"
    bs = src.get("BuildSpec")
    assert isinstance(bs, str), (
        f"BuildSpec 不是内联字符串而是 {type(bs).__name__}：{str(bs)[:120]}"
        "——Fn::Join 形态说明它又变成了 asset 的 S3 ARN")
    assert bs.encode("utf-8") == BUILDSPEC.read_bytes(), \
        "内联进模板的 buildspec 与仓库文件不逐字节相同"
    for bad in ("arn:", "cdk-hnb659fds-assets", "AssetParameters"):
        assert bad not in bs, f"BuildSpec 里出现 {bad!r}"


def test_package_project_role_cannot_read_the_bootstrap_bucket(template):
    """角色策略的**全貌**里不许出现任何 bootstrap 桶 ARN。

    正向控制在下一条：证明本条不是因为"整个策略都没了"才通过的。
    """
    blob = json.dumps([p["PolicyDocument"]
                       for p in _package_project_role_policies(template.to_json())])
    for bad in ("cdk-hnb659fds-assets", "AssetParameters"):
        assert bad not in blob, (
            f"PackageProject 角色的策略里出现 {bad!r}——跑不可信站点依赖安装的容器"
            "又能读到带明文会话密钥的 Edge asset 了")


def test_package_project_role_still_has_its_two_exact_artifact_grants(template):
    """正向控制：那两条精确授权必须还在，否则上一条断言毫无意义。"""
    docs = [p["PolicyDocument"]
            for p in _package_project_role_policies(template.to_json())]
    blob = json.dumps(docs)
    assert "/validated/*" in blob and "s3:GetObject" in blob, "少了读 validated/ 的授权"
    assert "/artifacts/*" in blob and "s3:PutObject" in blob, "少了写 artifacts/ 的授权"


def test_inline_buildspec_is_a_transparent_carrier():
    """**不需要 Docker**：只 import app.py，不实例化栈（不触发 Lambda bundling）。

    钉住两件让内联成立的事：`is_immediate` 为 True（否则 CDK 不渲染成内联字符串），
    以及 `to_build_spec()` 原样返回——子类只搬运，不加工。
    """
    try:
        import aws_cdk  # noqa: F401
    except ImportError:
        pytest.fail("SB_CDK_TESTS=1 但 aws_cdk 不可用——用 docstring 里的 "
                    "PYTHONPATH 桥接命令跑，否则这次运行什么都没验证")
    sys.path.insert(0, str(INFRA))
    import importlib
    mod = importlib.import_module("app")
    assert mod.BUILDSPEC_PATH == BUILDSPEC, "app.py 的 BUILDSPEC_PATH 指到别处了"
    text = BUILDSPEC.read_bytes().decode("utf-8")
    spec = mod._InlineBuildSpec(text)
    assert spec.is_immediate is True
    assert spec.to_build_spec() == text
    assert spec.to_build_spec().encode("utf-8") == BUILDSPEC.read_bytes()
```

- [ ] **Step 8: 跑 opt-in 模板断言（需 PYTHONPATH 桥接；前三条需 Docker）**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```

预期：全绿（含既有的表/索引断言）。Docker 必须在跑——synth 阶段会起容器装 psycopg。

如果只想跑不需要 Docker 的那一条：

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -k transparent_carrier -q
```

- [ ] **Step 9: 证明模板断言真的能红（一次性手工核对，不入仓）**

把 `app.py` 的 `build_spec=` 临时改回 `cb.BuildSpec.from_asset(str(BUILDSPEC_PATH))`，重跑 Step 8，**必须看到 `test_package_project_buildspec_is_inlined_byte_for_byte` 与 `test_package_project_role_cannot_read_the_bootstrap_bucket` 两条红**，然后改回来。

这一步是手工的、不留在仓库里：Step 7 那几条断言在写下时就是绿的（实现已在 Step 3-5 落地），不看它们红一次就等于没有证据。改回来之后**必须** `git diff site-builder/deployer/infra/app.py` 确认工作树干净，再进 Step 10。

- [ ] **Step 10: 跑默认全量 + auth（证明没碰到 bundling 段）**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer" && .venv/bin/pytest tests -q
cd "$(git rev-parse --show-toplevel)/site-builder/auth" && ../contract/.venv/bin/pytest tests -q
```

预期：deployer **`1003 passed, 54 skipped`**。算法：Task 1 之后是 `1001 passed, 50 skipped`；本任务新增 6 条，其中 2 条 always-on（进 passed）、4 条在 `test_infra_tables.py` 里因 `SB_CDK_TESTS` 未设而 skip（进 skipped）⇒ 1001+2、50+4。auth 预期 161 passed。

**基数以当次实测为准**，不要拿本行数字当断言——照抄一个过时基数正是这轮反复踩的坑。

- [ ] **Step 11: `cdk diff`（只看，不部署）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer/infra"
rm -rf cdk.out
PATH=.venv/bin:$PATH npx -y aws-cdk@latest diff 2>&1 | tee /tmp/m09-3b-cdkdiff.txt
```

预期**两类**变化，不是一类：

1. `AWS::CodeBuild::Project`（`PackageProjectC43E863E`）的 `Source.BuildSpec`：`Fn::Join` 出的 S3 ARN → 内联 YAML 字符串；
2. `AWS::IAM::Policy`（`PackageProjectRoleDefaultPolicy79E436B4`）：删掉 `s3:GetObject*`/`GetBucket*`/`List*` on bootstrap 桶那一条。

**把预期写成"diff 只少一条 IAM 语句"是错的**——属性本身也必须变。

逐项确认 diff 里**没有**：CodeBuild Project replacement、Role replacement、logical ID 变化、其它 IAM 变化、`site-artifacts` 精确权限的任何变化。（少一个 CDK asset 是预期的，那是 buildspec 不再上传。）

- [ ] **Step 12: 提交**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/infra/app.py \
        site-builder/deployer/tests/test_validate.py \
        site-builder/deployer/tests/test_infra_tables.py
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
fix(M09): buildspec 逐字节内联——删掉 CodeBuild 对 bootstrap 桶的整桶读

`site-package` 那条 `s3:GetObject*/GetBucket*/List*` on **整个** CDK bootstrap 桶
是 `BuildSpec.from_asset()` 让 CDK 自动加的（`Asset.grantRead()` 授桶不授对象），
而它的**唯一用途是取自己那 25 行 buildspec** —— buildspec 从头到尾只碰
`$ARTIFACTS_BUCKET`。同一个桶里有 9 个仍带明文会话签名密钥的 Edge asset，
而这个项目跑的正是不可信站点的依赖安装：今天唯一的隔断是一条
`npm install --ignore-scripts`。内联之后那条权限整条消失，不是收窄。

用自定义 `cb.BuildSpec` 子类而不是先解析成 dict：`from_object` 会把文件重新
序列化，注释全丢（`--ignore-scripts` 为什么必需就写在注释里），还让
`version: 0.2`（YAML float）往返一次。子类是透明搬运，部署出去的 buildspec 与
仓库文件**逐字节相同**。`is_immediate` / `to_build_spec()` 都是公开 abstract 成员。

**守卫分三层，各层只承担自己能证明的事**：always-on 文本守卫管"`BuildSpec.from_asset`
别回来 / 读法别退化 / 接线别断"（配负向 meta-test 证明会红）；opt-in 模板断言管
"部署出去的真是内联的、角色策略**全貌**里没有 bootstrap 桶"，另有正向控制证明
那两条精确授权还在；真机闸门管"权限别再长回来"。

模板那层是**必须**的，不是加分项：`test_validate.py` 早就在守这个角色，主语写得很准
（"多一项就是给不可信构建多开一个前缀"）、还刻意用 AST 而非全文子串，但
`_package_project_resources()` 遍历的是 `add_to_role_policy(...)` 这些调用——
**手写的那一半**；CDK 自动加进 DefaultPolicy 的那条对它结构上不可见。守卫的主语是
"这个角色的全部权限"、证据只是"源码里手写的那部分"，两者之差就是这个洞。

未部署。生产部署与基线/文档更新按计划的 Task 3/4 单独放行。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Task 3: 部署与真机验收

> **STOP —— 这一步动生产，必须先拿到人工放行。** 前置：Task 2 已提交、`cdk diff` 已人工过目、Docker 在跑、AWS 凭证有效且指向部署账号。

**Files:** 不改任何文件（纯部署 + 只读验证）

- [ ] **Step 1: 关部署入口并确认没有在途构建**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import boto3
cb = boto3.client("codebuild", region_name="us-east-1")
ids = cb.list_builds_for_project(projectName="site-package")["ids"][:20]
if ids:
    running = [b["id"] for b in cb.batch_get_builds(ids=ids)["builds"]
               if b["buildStatus"] == "IN_PROGRESS"]
    print("IN_PROGRESS 构建:", running or "无")
else:
    print("该项目还没有任何构建")
ddb = boto3.client("dynamodb", region_name="us-east-1")
# 表名 site-deploy-jobs（**不是** site-jobs）——真源是 infra/app.py 的
# `ddb.Table(self, "Jobs", table_name="site-deploy-jobs", …)`，运行时代码通过
# 环境变量 JOBS_TABLE 拿它。租约判"持有者还在跑吗"看的就是 status == "RUNNING"
# （见 common.py 的 plan_deploy_lease），所以这里筛 RUNNING 而不是"非终态"。
jobs = ddb.scan(TableName="site-deploy-jobs",
                FilterExpression="#s = :r",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":r": {"S": "RUNNING"}},
                ProjectionExpression="job_id")["Items"]
print("RUNNING 的部署 job:", [i["job_id"]["S"] for i in jobs] or "无")
PY
```

**两项都必须是"无"才继续。** CloudFormation 不保证 `Project` 属性更新与 `IAM::Policy` 更新的先后：若策略先掉而属性后切，那几十秒内**启动的**构建会取不到 buildspec 而失败（失败是干净的——部署 job 进 FAILED、可重试，但没必要制造它）。

- [ ] **Step 2: 部署 deployer 栈**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer/infra"
rm -rf cdk.out
PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

预期：`UPDATE_COMPLETE`。（`rm -rf cdk.out` 是必须的——改过 config.ini 或 asset 时不清会用陈旧 asset。）

- [ ] **Step 3: 静态确认（只读）**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import boto3, json
from pathlib import Path
BS = Path("site-builder/deployer/buildspec-package.yml").read_bytes()
cb = boto3.client("codebuild", region_name="us-east-1")
iam = boto3.client("iam", region_name="us-east-1")

p = cb.batch_get_projects(names=["site-package"])["projects"][0]
src = p["source"]
print("source.type =", src["type"])
inline = src.get("buildspec", "")
print("buildspec 是内联文本 =", not inline.startswith("arn:"))
print("与仓库文件逐字节相同 =", inline.encode("utf-8") == BS)

role = p["serviceRole"].rsplit("/", 1)[-1]
blob = []
for name in iam.list_role_policies(RoleName=role)["PolicyNames"]:
    blob.append(json.dumps(iam.get_role_policy(
        RoleName=role, PolicyName=name)["PolicyDocument"]))
for att in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
    v = iam.get_policy(PolicyArn=att["PolicyArn"])["Policy"]["DefaultVersionId"]
    blob.append(json.dumps(iam.get_policy_version(
        PolicyArn=att["PolicyArn"], VersionId=v)["PolicyVersion"]["Document"]))
all_pol = "\n".join(blob)
print("策略里还有 bootstrap 桶 =", "cdk-hnb659fds-assets" in all_pol)
print("validated/ 读权限仍在 =", "/validated/*" in all_pol)
print("artifacts/ 写权限仍在 =", "/artifacts/*" in all_pol)
print("还有 s3:List* =", "s3:List" in all_pol)
PY
```

预期逐行：`NO_SOURCE` / `True` / `True` / **`False`** / `True` / `True` / `False`。

- [ ] **Step 4: 恢复部署入口，跑完整 E2E**

```bash
cd "$(git rev-parse --show-toplevel)"
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_e2e_fixtures.py -q
```

**这个文件现在收集 10 条**（机械核实过，不是 4 条 fixture；`约 6 分钟` 那个旧数字不要再引用，按当次实测记）。多条用例会重复部署 `nosql-notes`，所以 `package_backend → CodeBuild` 会被**多次**经过。它覆盖到与本改动相关的四件事：首次构建证明内联 buildspec 能被 CodeBuild 取用；更新构建证明不是只在创建时有效；失败恢复路径证明构建失败后项目仍可继续使用；NoSQL 与 DSQL 两类后端证明打包输出没有意外变化。

**不跑** `smoke_router.sh`：本改动不碰 CloudFront / Edge / route 注册 / 会话鉴权 / Function URL，而完整 E2E 本身已经通过公网路由访问生成的站点。

- [ ] **Step 5: 跑信任边界闸门，但**不**更新基线**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_account_trust_boundary.py 2>&1 | tee /tmp/m09-3b-gate.txt
echo "退出码: ${PIPESTATUS[0]}"
```

预期（用系统 `python3`，不要用 `deployer/.venv` 的——那个的 CA 信任库是空的）：

- 退出码 0；
- 只有**一条** improvement：那个指纹「不再具备任何敏感授权（原 platform-overbroad：`['read-edge-asset']`）」；
- 「具备至少一项敏感授权的 principal」从 62 变 **61**；
- `edge_assets_carrying_live_key` 仍是 **9**、`edge_code_targets_carrying_live_key` 仍是 **10**、`undecided_items` **774 → 774（+0）**；
- B（`iam_write_drift` / `boundary_drift`）、resource policy、bucket policy **零变化**。

**任何一项与上面不符就停下查清原因，不要往 Task 4 走。** 尤其：如果 A 掉的不止 1 个，或掉的是别的 principal，说明这次部署改到了预期之外的东西。

---

## Task 4: 基线与文档的原子提交

> **STOP —— 需要人工核对 Task 3 Step 5 的 delta 之后才能开始。**

**Files:**
- Modify: `site-builder/scripts/account_trust_baseline.json`（由脚本重写，不手改）
- Modify: `docs/security/account-trust-boundary.md`

**不需要**改 `tests/test_verify_account_trust_boundary.py`：核过了——`platform-overbroad`
在那个文件里只出现两处，一处是 `test_doc_counts_come_from_the_baseline` 里的
`category_slugs` 映射（它从基线**算**计数，算出 0 就要求文档里出现 `…=0`，映射本身不用改），
另一处在一条用合成基线的用例里（与仓库基线无关）。

- [ ] **Step 1: 重写基线**

```bash
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_account_trust_boundary.py --update-baseline
```

- [ ] **Step 2: 看基线的 diff 是不是恰好那一条**

```bash
cd "$(git rev-parse --show-toplevel)"
git diff --stat site-builder/scripts/account_trust_baseline.json
git diff site-builder/scripts/account_trust_baseline.json | grep -E '^[-+]' | head -40
```

预期：只少一个 principal 条目（`category: platform-overbroad`、`grants: ["read-edge-asset"]`），其余 61 个条目、`coverage`、`iam_write_*`、`resource_policies` 一字不动。**多出别的变化就停下**——基线是这道闸门的全部记忆，一次糊涂的重写会把真实漂移一起吸收掉。

- [ ] **Step 3: 跑闸门测试，看文档数字守卫红在哪**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_verify_account_trust_boundary.py -q
```

预期：`test_doc_counts_come_from_the_baseline`（第 639 行，按 `<!-- baseline:… -->` 标记整串比对的那条）**红**，报文点出 `A总数` 期望 61、`可读密钥` 期望 56、`类别_platform_overbroad` 期望 0。这条红是**设计好的**：它强制基线与文档同提交。

- [ ] **Step 4: 改文档的数字**

在 `docs/security/account-trust-boundary.md` 里，把这三处标记连同它们前面的数字一起改（**数字与标记里的值必须一致**，守卫按 `f"{n} <!-- baseline:{label}={n} -->"` 整串匹配）：

- `62 <!-- baseline:A总数=62 -->` → `61 <!-- baseline:A总数=61 -->`
- `57 <!-- baseline:可读密钥=57 -->` → `56 <!-- baseline:可读密钥=56 -->`
- `1 <!-- baseline:类别_platform_overbroad=1 -->` → `0 <!-- baseline:类别_platform_overbroad=0 -->`

**那一行表格不能删。** `test_doc_counts_come_from_the_baseline` 对 `category_slugs` 里的
**每个**类别都要求文档中出现对应标记，删掉整行会让它红在"找不到 `…=0`"上。

同时把「合计 62 = A 组总数」那句里的 62 改成 61，以及开头「一句话」一节与「A + B 的并集是 66」那句里受影响的算术**逐一核对**（66 = 62 + 4 ⇒ 改为 65 = 61 + 4）。改完靠 Step 6 的守卫兜。

- [ ] **Step 5: 改「平台侧唯一的过宽授权」那一节**

把该节从"现状描述"改成"已收窄 + 历史结论保留"。要保留的三件事：这条权限**曾经**存在且是 CDK 自动授的；它跨越「不可信站点输入 → 平台签名密钥」这条威胁边界；以及**它得出的结论仍然成立**——"别把可签名的对称密钥物化进部署资产"。要新增的两句：现在 buildspec 逐字节内联、该角色对 bootstrap 桶零权限；以及**`--ignore-scripts` 仍然必须保留**（它挡的不只是这一条路，构建容器里任意代码执行仍能读 `validated/*`、写 `artifacts/*`）。

同时把该节标题里的"唯一"处理掉——`platform-overbroad` 现在是 0 个，留着"唯一"会读成"还有一个"。

- [ ] **Step 6: 跑测试直到全绿**

```bash
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
cd "$(git rev-parse --show-toplevel)/site-builder/auth" && ../contract/.venv/bin/pytest tests -q
```

预期：两者全绿。文档数字守卫与文档措辞守卫（`test_delivery_docs_current.py`）都必须过。

- [ ] **Step 7: 一个原子提交**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/scripts/account_trust_baseline.json \
        docs/security/account-trust-boundary.md \
        site-builder/deployer/tests/test_verify_account_trust_boundary.py
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
feat(M09): 收窄生效后重写基线 + 同步文档数字（A 62→61、可读密钥 57→56）

CodeBuild 那条整桶读已从生产移除并过完真机验收，所以基线要吸收这一条改善：
`platform-overbroad` 那个 principal 只有 `read-edge-asset` 一条 grant，
移除后它整条退出 A 组。

基线与文档**必须同提交**（`test_documented_numbers_match_baseline` 按
`<!-- baseline:… -->` 标记整串比对，分开提交必红）——那条耦合就是为了防止
"两处各说一套"。

「平台侧唯一的过宽授权」一节改成"已收窄 + 历史结论保留"：结论
（别把可签名的对称密钥物化进部署资产）仍然成立，而 `--ignore-scripts` 仍然
必须留着——它挡的不只是这一条路，构建容器里任意代码执行仍能读 validated/、
写 artifacts/。

**没有变的**：带活密钥的 asset 仍是 9、Edge 代码目标仍是 10、undecided 774→774、
B 的 22 holder/43 语句一字未动。`read-edge-code` 与 `read-jwt-param` 两条路
一寸也没动——那要等非对称签名（真修复②）。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

- [ ] **Step 8: 收尾全量**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/metamorphic_trust_boundary.py
(cd site-builder/contract && .venv/bin/pytest tests -q)
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/mcp && python3 -m pytest tests -q)
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```

预期：变形全红（37/37，本计划没动那个 harness，条数应不变）；七包全绿。**把各包的实测通过数记下来**——那是这一轮的签字数字，不要引用上一轮的。

- [ ] **Step 9: 更新 §9 与 memory**

在 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 里把 **3b** 标成已完成，并写明它**只**动了 1 个 principal、下一条是 3c（非对称签名）。这一步单独一个 `docs(M09):` 提交即可。

---

## 回滚

revert Task 2 的提交（`site-builder/deployer/infra/app.py` 那处），重新部署 deployer 栈。bootstrap 桶里那个孤儿 buildspec asset 对象留着无害（它本来也不会被删）。若已经走完 Task 4，则一并 revert 基线与文档那个提交，否则闸门会把"权限回来了"报成红——**那正是它该做的**，别为了让闸门变绿而保留新基线。

**没有迁移、没有回填、没有补偿、没有状态。** 这是一条属性 + 一条 IAM 语句的改动，回滚就是反向的同一次部署。

## 不变量（改完必须仍然成立）

- `site-package` 的构建容器**只能**读 `site-artifacts-<acct>/validated/*`、**只能**写 `site-artifacts-<acct>/artifacts/*`，且没有 `ListBucket`、没有 `DeleteObject`。
- buildspec 的**唯一真源**是 `site-builder/deployer/buildspec-package.yml`；部署出去的内容与它**逐字节**相同（含注释）。
- `--ignore-scripts` 与"先删 `.npmrc`"两条仍在（Task 1 起有守卫）。
- `test_validate.py` 那条既有 AST 断言（`package_project` 手写资源集恰好是 `{validated/*, artifacts/*}`）继续成立且**不放宽**。
- 每个提交都是绿的、可运行的 checkout。
