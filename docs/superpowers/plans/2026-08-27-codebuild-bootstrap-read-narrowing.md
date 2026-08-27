# 收窄 CodeBuild 对 CDK bootstrap 桶的读权限 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让跑不可信站点依赖安装的 CodeBuild 项目（`site-package`）不再对整个 CDK bootstrap asset 桶有读权限——那个桶里有 9 个仍带明文会话签名密钥的 Edge asset。

**Architecture:** 那条权限是 `cb.BuildSpec.from_asset()` 让 CDK 自动加的（`Asset.grantRead()` 授整桶），唯一用途是取项目自己那 25 行 buildspec。用一个自定义 `cb.BuildSpec` 子类把 buildspec 原文**逐字节**内联进 CloudFormation 模板，这条权限整条消失。守卫是三个**只依赖标准库的纯函数检查器**（buildspec 命令合同 / IAM 精确 allowlist / BuildSpec 交付形态），反例一律在内存里注入；另有一个 opt-in 的真机行为探针证明 npm 的真实行为。

**Tech Stack:** Python 3.12 / aws-cdk-lib 2.262.1（`infra/.venv`）/ pytest（`deployer/.venv`，**不含 aws_cdk**）/ CloudFormation / CodeBuild / IAM

**Spec:** `docs/superpowers/specs/2026-08-27-codebuild-bootstrap-read-narrowing-spec.md`

## Global Constraints

- **每个 shell 块开头都要 `set -euo pipefail`。** 本环境的 shell 是 **zsh**：实测
  `${PIPESTATUS[0]}` 在 zsh 里展开成**空字符串**（zsh 用 `$pipestatus`，还是 1-indexed），
  且不带 `pipefail` 时 `cmd | tee` 的退出码是 **tee 的 0**。所以**不许**用
  `… | tee … ; echo "退出码: ${PIPESTATUS[0]}"` 判命令成败——非零退出必须直接终止步骤。
- **us-east-1 是硬约束**（Lambda@Edge 与 CloudFront 的 ACM 证书）。
- **不得把真实账号 ID / 内部角色原名写进任何被跟踪的文件**；手写 fixture 一律用
  `000000000000`。提交前 `bash site-builder/scripts/scan_staged_secrets.sh`
  （Co-Authored-By 那类既有命中确认后可 `--allow-hits`）。
- **`verify_*` 脚本一律用系统 `python3`**，不要用 `site-builder/deployer/.venv/bin/python3`：
  那个解释器的 CA 信任库是空的，每次 HTTPS 都 `CERTIFICATE_VERIFY_FAILED`。
- **每个提交都必须是绿的、可运行的 checkout。** 不许提交红着的测试。
- **`deployer/.venv` 没有 `aws_cdk`**（实测 `ModuleNotFoundError`），且 `import app` 会
  synth 整个栈（`app.py` 顶层就 `App()/synth()`）⇒ 需要 Docker。因此所有**语义反例**都
  跑在手写模板 fixture 上（always-on、无 Docker），真模板只在 opt-in 层跑一次。
- **测试命令照抄**：默认套件 `cd site-builder/deployer && .venv/bin/pytest tests -q`
  （**必须带 `tests/`**，裸 `pytest` 会误收集 `infra/cdk.out` 里的 asset 副本）。
- **不更新 memory。** memory 是控制侧的东西、不是仓库产物，不进本计划的任何任务。
- **Task 4 与 Task 5 动生产，必须单独获得人工放行。** Task 1-3 不碰生产。

### 反例的有效性标准（本轮最贵的教训，spec 里有完整版）

上一版声称"计划里的代码块机械验证过 16 项全过"，而那 16 项是**作者自己挑的退化**；
外部复审另挑四个 buildspec 反例与一个 IAM 反例，**全部绿**。所以本计划里每个检查器的
反例集合都必须：① tracked；② 默认套件就跑；③ **含一组由复审方提出的反例，逐字纳入**；
④ 每条反例的报文点名的是目标控制点；⑤ 构造反例时其余部分保持合格，失败不能由更早的
检查顺带造成。

**本计划的全部代码块都在最终目录形态下跑过**（`deployer/tests/` 布局，21 passed），
不是"看着能跑"。

---

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/deployer/tests/security_contracts.py` | 三个检查器，**只依赖标准库**（`json` + `shlex`），被 always-on 与 opt-in 两套测试共用 | Create（Task 1） |
| `site-builder/deployer/tests/test_security_contracts.py` | always-on：真实 buildspec + 手写模板 fixture 做正向；全部外部反例内存注入做负向 | Create（Task 1） |
| `CLAUDE.md` / `docs/security/account-trust-boundary.md` | 改正「唯一的隔断是 `--ignore-scripts`」这个不准确的说法 | Modify（Task 1） |
| `site-builder/deployer/infra/app.py` | `BUILDSPEC_PATH` + `_InlineBuildSpec` + 接线 + `__main__` 守卫 | Modify（Task 2） |
| `site-builder/deployer/tests/test_infra_tables.py` | opt-in：把同样三个检查器跑在**真 synth 出来的**模板上 | Modify（Task 2） |
| `site-builder/deployer/tests/test_codebuild_security_probe.py` | opt-in 真机行为探针（`RUN_CODEBUILD_SECURITY_PROBE=1`） | Create（Task 3） |
| `site-builder/scripts/account_trust_baseline.json` | 信任边界闸门基线 | Modify（Task 5） |

**为什么模板断言加在 `test_infra_tables.py`**：那个文件的 `template` fixture synth 整个
stack（需 Docker）。新建文件要么复制那段 fixture（会 synth 两次），要么把它提到
`conftest.py`（改一个正绿的共享文件）。加在原文件里只需改 docstring，且"一条命令跑完所有
需要 Docker 的断言"这个属性保留。

---

## Task 1: 三个结构化检查器 + 全部外部反例 + 改正文档措辞

**不碰生产代码。** 先做这个，因为：① 它产出的检查器是 Task 2 的验收工具；② 它把
`--ignore-scripts` 与删 `.npmrc` 两条隔断钉住，而在 Task 2 落地之前那两条仍然承重；
③ 检查器的负向控制（"改动前的模板形态必须红"）在这里就建立好，Task 2 因此**不需要**
把 `app.py` 手工改回去跑一次。

**Files:**
- Create: `site-builder/deployer/tests/security_contracts.py`
- Create: `site-builder/deployer/tests/test_security_contracts.py`
- Modify: `CLAUDE.md`（第 40 行附近）
- Modify: `docs/security/account-trust-boundary.md`（`platform-overbroad` 那一节）

**Interfaces（Task 2 会用到）:**
- `security_contracts.build_container_interlock_violations(src: str) -> list[str]`
- `security_contracts.package_project_s3_violations(template: dict) -> list[str]`
- `security_contracts.buildspec_template_violations(template: dict, want: bytes) -> list[str]`
- 三者都是"空列表 = 合格"。

- [ ] **Step 1: 建检查器模块**

创建 `site-builder/deployer/tests/security_contracts.py`，内容如下（**逐字**，这份代码
已在最终目录形态下验证过）：

```python
"""安全合同的结构化检查器——**只依赖标准库**，被 always-on 与 opt-in 两套测试共用。

每个检查器都是「吃结构化输入、吐违规列表」的纯函数，于是反例可以在**内存里**注入：
不改工作树、不需要另一个 harness、跑在默认套件里。

为什么是**精确 allowlist** 而不是"没出现某个已知坏值"：黑名单守卫的主语总比它的证据
宽。实测过一份策略——两条精确授权都在、另加 `s3:GetObject` + `s3:ListBucket` on `*`
——而"策略里没有 bootstrap 桶"那种断言照样通过。这与 `_package_project_resources()`
只看见"手写的那一半"是同一个错误。
"""
import json
import shlex

# ── buildspec：命令合同 ────────────────────────────────────────────────────
_SEPARATORS = ("&&", "||", ";", "|")
# **精确 token 列表**，不是"含某个子串"：加一个 `--ignore-scripts=false` 或
# `--no-ignore-scripts` 都能把语义翻过来，而"含 --ignore-scripts"照样绿。
EXPECT_NPM_INSTALL = ["npm", "install", "--omit=dev", "--no-audit", "--no-fund",
                      "--ignore-scripts"]
EXPECT_NPMRC_DELETE = ["find", "/tmp/site", "-name", ".npmrc", "-delete"]


def _buildspec_commands(src: str) -> tuple[list[list[str]], list[str]]:
    """buildspec 的 `commands:` → 逐条 shell 命令的 token 列表。

    **fail-closed**：block scalar、行尾续行、shlex 分词失败、`commands:` 不唯一，
    一律报违规而不猜——猜错的方向永远是"看起来合格"。
    """
    lines = src.splitlines()
    heads = [i for i, l in enumerate(lines) if l.strip() == "commands:"]
    if len(heads) != 1:
        return [], [f"buildspec 里有 {len(heads)} 个 `commands:` 段（守卫只支持 1 个，"
                    f"形态变了就必须同步更新守卫，不许猜哪一段是构建命令）"]
    head = heads[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    entries: list[str] = []
    for raw in lines[head + 1:]:
        if not raw.strip():
            continue
        pad = len(raw) - len(raw.lstrip())
        if pad <= indent:
            break
        s = raw.strip()
        if s.startswith("#"):
            continue
        if not s.startswith("- "):
            return [], [f"commands 段里出现非 `- ` 条目：{s[:40]!r}"
                        f"（block scalar/多行命令不支持，守卫拒绝解析）"]
        body = s[2:].strip()
        if body.endswith("\\") or body in ("|", ">", "|-", ">-"):
            return [], [f"命令用了续行或 block scalar：{body[:40]!r}——守卫拒绝解析"]
        entries.append(body)
    if not entries:
        return [], ["commands 段是空的"]
    cmds: list[list[str]] = []
    for body in entries:
        try:
            toks = shlex.split(body, comments=True)
        except ValueError as exc:
            return [], [f"命令无法 shlex 分词（{exc}）：{body[:40]!r}"]
        cur: list[str] = []
        for t in toks:
            if t in _SEPARATORS:
                if cur:
                    cmds.append(cur)
                cur = []
            else:
                cur.append(t)
        if cur:
            cmds.append(cur)
    return cmds, []


def build_container_interlock_violations(src: str) -> list[str]:
    """构建容器的两条隔断：`--ignore-scripts` 与"装依赖前删掉 .npmrc"。"""
    cmds, out = _buildspec_commands(src)
    if out:
        return out
    npm = [(i, c) for i, c in enumerate(cmds) if c[0] == "npm"]
    installs = [(i, c) for i, c in npm if len(c) > 1 and c[1] == "install"]
    if len(installs) != 1:
        return [f"buildspec 里有 {len(installs)} 条 `npm install`（必须恰好 1 条）"]
    i_npm, install = installs[0]
    others = [c for i, c in npm if i != i_npm]
    if others:
        out.append(f"除 `npm install` 外还有 npm 子命令 {[c[:2] for c in others]}"
                   f"——`npm rebuild` / `npm run` 会重新执行生命周期脚本")
    if install != EXPECT_NPM_INSTALL:
        out.append(f"`npm install` 的 token 不是预期的精确列表。\n"
                   f"      期望: {EXPECT_NPM_INSTALL}\n      实际: {install}\n"
                   f"      （精确比对是刻意的：`--ignore-scripts=false` 与 "
                   f"`--no-ignore-scripts` 都能把语义翻过来，而「含这个子串」照样绿）")
    finds = [i for i, c in enumerate(cmds) if c == EXPECT_NPMRC_DELETE]
    if not finds:
        got = [c for c in cmds if c and c[0] == "find" and ".npmrc" in c]
        out.append(f"找不到精确的删 .npmrc 命令 {EXPECT_NPMRC_DELETE}"
                   f"（近似的有 {got or '无'}——删错目录等于没删）")
    elif min(finds) > i_npm:
        out.append(f"删 .npmrc 发生在 `npm install` **之后**（第 {min(finds)} 条 vs "
                   f"第 {i_npm} 条）——装依赖时 registry 已经被它改过了")
    return out


# ── IAM：精确 allowlist ───────────────────────────────────────────────────
class Unrenderable(Exception):
    pass


def render_token(node) -> str:
    """CloudFormation 标量 → 规范字符串。**不认识的形态抛异常**，不求值。"""
    if isinstance(node, str):
        return node
    if isinstance(node, dict) and len(node) == 1:
        k, v = next(iter(node.items()))
        if k == "Ref":
            return f"<Ref:{v}>"
        if k == "Fn::GetAtt":
            parts = v.split(".", 1) if isinstance(v, str) else list(v)
            return f"<GetAtt:{parts[0]}.{parts[1]}>"
        if k == "Fn::Join":
            delim, items = v
            return delim.join(render_token(x) for x in items)
    raise Unrenderable(json.dumps(node, ensure_ascii=False)[:80])


def _as_list(v):
    return v if isinstance(v, list) else [v]


def package_project_s3_violations(tpl: dict) -> list[str]:
    """`site-package` 角色的 **S3 权限全集**必须精确等于两条。

    覆盖角色的**全部**模板内权限来源（inline `Policies`、`AWS::IAM::Policy`、
    `AWS::IAM::ManagedPolicy`、`ManagedPolicyArns`）——只收其中一种，就是
    `_package_project_resources()` 那个"只看见手写一半"的错误换到模板层重演。
    """
    res = tpl["Resources"]
    projs = [(lid, r) for lid, r in res.items()
             if r["Type"] == "AWS::CodeBuild::Project"
             and r["Properties"].get("Name") == "site-package"]
    if len(projs) != 1:
        return [f"site-package 项目没唯一定位到（{len(projs)} 个）"]
    sr = projs[0][1]["Properties"].get("ServiceRole")
    if not (isinstance(sr, dict) and list(sr) == ["Fn::GetAtt"]):
        return [f"ServiceRole 不是 Fn::GetAtt 形态：{json.dumps(sr)[:80]}"
                f"——守卫拒绝猜角色是谁"]
    lid = (sr["Fn::GetAtt"].split(".", 1) if isinstance(sr["Fn::GetAtt"], str)
           else list(sr["Fn::GetAtt"]))[0]
    role = res.get(lid)
    if not role or role["Type"] != "AWS::IAM::Role":
        return [f"ServiceRole 指向的 {lid} 不是 AWS::IAM::Role"]

    out: list[str] = []
    docs: list[dict] = []
    if role["Properties"].get("ManagedPolicyArns"):
        out.append(f"角色挂了 managed policy {role['Properties']['ManagedPolicyArns']}"
                   f"——本角色不该有任何 managed policy attachment")
    for p in role["Properties"].get("Policies", []) or []:
        docs.append(p["PolicyDocument"])
    ref = {"Ref": lid}
    for r in res.values():
        if r["Type"] in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy") \
                and ref in (r["Properties"].get("Roles") or []):
            docs.append(r["Properties"]["PolicyDocument"])
    if not docs:
        return out + ["没找到该角色的任何策略文档——定位逻辑失效了"]

    buckets = [b for b, r in res.items()
               if r["Type"] == "AWS::S3::Bucket"
               and isinstance(r["Properties"].get("BucketName"), str)
               and r["Properties"]["BucketName"].startswith("site-artifacts-")]
    if len(buckets) != 1:
        return out + [f"site-artifacts 桶没唯一定位到（{buckets}）"]
    art = buckets[0]
    expected = {("s3:GetObject", f"<GetAtt:{art}.Arn>/validated/*"),
                ("s3:PutObject", f"<GetAtt:{art}.Arn>/artifacts/*")}

    got: set[tuple[str, str]] = set()
    for doc in docs:
        for st in doc["Statement"]:
            if "NotAction" in st or "NotResource" in st:
                out.append(f"语句用了 NotAction/NotResource（守卫不做集合求补）："
                           f"{json.dumps(st, ensure_ascii=False)[:90]}")
                continue
            if st.get("Effect") != "Allow":
                continue
            acts = [a for a in _as_list(st.get("Action") or [])]
            s3 = [a for a in acts if isinstance(a, str)
                  and (a == "*" or a.lower().startswith("s3:"))]
            if not s3:
                continue
            wild = [a for a in s3 if "*" in a]
            if wild:
                out.append(f"S3 动作里有通配 {wild}——精确 allowlist 不接受通配动作")
            try:
                rs = [render_token(x) for x in _as_list(st.get("Resource"))]
            except Unrenderable as exc:
                out.append(f"Resource 里有不认识的 CloudFormation 形态：{exc}")
                continue
            if any(r == "*" for r in rs):
                out.append(f"S3 语句的 Resource 是 `*`（动作 {s3}）")
            for a in s3:
                for r in rs:
                    got.add((a, r))
    if got != expected:
        extra, missing = sorted(got - expected), sorted(expected - got)
        out.append(f"S3 权限全集与精确 allowlist 不符。\n      多出: {extra}\n"
                   f"      缺少: {missing}")
    return out


# ── BuildSpec 交付形态 ────────────────────────────────────────────────────
def buildspec_template_violations(tpl: dict, want: bytes) -> list[str]:
    res = tpl["Resources"]
    projs = [r for r in res.values() if r["Type"] == "AWS::CodeBuild::Project"
             and r["Properties"].get("Name") == "site-package"]
    if len(projs) != 1:
        return [f"site-package 项目没唯一定位到（{len(projs)} 个）"]
    src = projs[0]["Properties"].get("Source") or {}
    out = []
    if src.get("Type") != "NO_SOURCE":
        out.append(f"Source.Type 是 {src.get('Type')!r}，期望 NO_SOURCE")
    bs = src.get("BuildSpec")
    if not isinstance(bs, str):
        return out + [f"BuildSpec 不是内联字符串而是 "
                      f"{type(bs).__name__}：{json.dumps(bs, ensure_ascii=False)[:90]}"
                      f"——Fn::Join 形态说明它又变回了 asset 的 S3 ARN"]
    if bs.encode("utf-8") != want:
        out.append("内联进模板的 buildspec 与仓库文件不逐字节相同")
    for bad in ("arn:", "cdk-hnb659fds-assets", "AssetParameters"):
        if bad in bs:
            out.append(f"BuildSpec 里出现 {bad!r}")
    return out
```

- [ ] **Step 2: 建 always-on 测试（正向 + 全部外部反例）**

创建 `site-builder/deployer/tests/test_security_contracts.py`：

```python
"""always-on：三个检查器的正向输入 + 全部外部反例（内存注入，不碰工作树）。"""
import copy
import json
import shlex
from pathlib import Path

import pytest

from security_contracts import (build_container_interlock_violations,
                                buildspec_template_violations,
                                package_project_s3_violations)

BUILDSPEC = Path(__file__).parents[1] / "buildspec-package.yml"

ROLE, POL, PRJ, ART = ("PackageProjectRoleB21CC0C9",
                       "PackageProjectRoleDefaultPolicy79E436B4",
                       "PackageProjectC43E863E", "Artifacts82DD59A1")
ACCT = "000000000000"          # **不是真实账号**：手写 fixture 一律用它


def _template(*, inlined: bool) -> dict:
    """最小模板 fixture。形态对着**已部署的 processed 模板**核过：
    `Action` 可为 str 或 list、`Resource` 为 `Fn::Join` + `Ref: AWS::Partition`
    / `Fn::GetAtt`。`inlined=False` 复现改动**之前**的形态（含整桶读 + S3-ARN buildspec），
    它必须让检查器红——那是这份 fixture 的负向控制。
    """
    art = {"Fn::GetAtt": [ART, "Arn"]}
    join = lambda *p: {"Fn::Join": ["", list(p)]}
    stmts = [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [join("arn:", {"Ref": "AWS::Partition"},
                           f":logs:us-east-1:{ACCT}:log-group:/aws/codebuild/",
                           {"Ref": PRJ})]},
        {"Effect": "Allow", "Action": ["codebuild:CreateReport"],
         "Resource": join("arn:", {"Ref": "AWS::Partition"},
                          f":codebuild:us-east-1:{ACCT}:report-group/", {"Ref": PRJ}, "-*")},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": join(art, "/validated/*")},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": join(art, "/artifacts/*")},
    ]
    if not inlined:
        stmts.insert(0, {
            "Effect": "Allow",
            "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
            "Resource": [join("arn:", {"Ref": "AWS::Partition"},
                              f":s3:::cdk-hnb659fds-assets-{ACCT}-us-east-1"),
                         join("arn:", {"Ref": "AWS::Partition"},
                              f":s3:::cdk-hnb659fds-assets-{ACCT}-us-east-1/*")]})
    source = ({"Type": "NO_SOURCE", "BuildSpec": BUILDSPEC.read_bytes().decode("utf-8")}
              if inlined else
              {"Type": "NO_SOURCE",
               "BuildSpec": join("arn:", {"Ref": "AWS::Partition"},
                                 f":s3:::cdk-hnb659fds-assets-{ACCT}-us-east-1/abc.yml")})
    return {"Resources": {
        ART: {"Type": "AWS::S3::Bucket",
              "Properties": {"BucketName": f"site-artifacts-{ACCT}"}},
        ROLE: {"Type": "AWS::IAM::Role", "Properties": {}},
        POL: {"Type": "AWS::IAM::Policy",
              "Properties": {"Roles": [{"Ref": ROLE}],
                             "PolicyDocument": {"Statement": stmts}}},
        PRJ: {"Type": "AWS::CodeBuild::Project",
              "Properties": {"Name": "site-package", "Source": source,
                             "ServiceRole": {"Fn::GetAtt": [ROLE, "Arn"]}}},
    }}


# ── 检查器 ①：buildspec 命令合同 ──────────────────────────────────────────
def test_real_buildspec_satisfies_the_command_contract():
    assert build_container_interlock_violations(
        BUILDSPEC.read_text(encoding="utf-8")) == []


def _npm_line(src):
    return next(l for l in src.splitlines()
                if "npm install" in l and l.strip().startswith("-"))


def _find_line(src):
    return next(l for l in src.splitlines() if ".npmrc" in l and "-delete" in l)


def _buildspec_counterexamples() -> dict[str, str]:
    """**外部复审提出的**反例（前五条）+ 本轮补的一条。逐字保留，别精简。"""
    good = BUILDSPEC.read_text(encoding="utf-8")
    npm, fnd = _npm_line(good), _find_line(good)
    lines = good.splitlines()
    i_f, i_n = lines.index(fnd), lines.index(npm)
    moved = lines[:i_f] + lines[i_f + 1:]
    j = next(k for k, l in enumerate(moved)
             if "npm install" in l and l.strip().startswith("-"))
    return {
        "flag 写成 --ignore-scripts=false": good.replace(
            "--ignore-scripts", "--ignore-scripts=false"),
        "flag 只留在 shell 注释里": good.replace(
            npm, npm.replace(" --ignore-scripts", "  # --ignore-scripts")),
        "删 .npmrc 挪到 install 之后":
            "\n".join(moved[:j + 1] + [fnd] + moved[j + 1:]) + "\n",
        "删的是别的目录": good.replace("find /tmp/site -name",
                                       "find /tmp/not-the-site -name"),
        "install 后追加 npm rebuild":
            "\n".join(lines[:i_n + 1] + ["      - npm rebuild"] + lines[i_n + 1:]) + "\n",
        "追加 --no-ignore-scripts 反转语义": good.replace(
            "--ignore-scripts", "--ignore-scripts --no-ignore-scripts"),
    }


@pytest.mark.parametrize("label", list(_buildspec_counterexamples()))
def test_command_contract_rejects_each_counterexample(label):
    good = BUILDSPEC.read_text(encoding="utf-8")
    mutated = _buildspec_counterexamples()[label]
    assert mutated != good, f"锚点没找到（buildspec 写法变了）：{label}"
    assert build_container_interlock_violations(mutated), f"**没红**：{label}"


# ── 检查器 ②：IAM 精确 allowlist ──────────────────────────────────────────
def test_inlined_template_has_exactly_two_s3_permissions():
    assert package_project_s3_violations(_template(inlined=True)) == []


def test_pre_change_template_is_rejected():
    """负向控制：改动**之前**的形态必须红（否则 fixture 与现实无关）。"""
    v = package_project_s3_violations(_template(inlined=False))
    assert v and any("通配" in x for x in v), v


def _iam_counterexamples() -> dict[str, dict]:
    art = {"Fn::GetAtt": [ART, "Arn"]}

    def with_stmt(st):
        t = _template(inlined=True)
        t["Resources"][POL]["Properties"]["PolicyDocument"]["Statement"].append(st)
        return t

    def role_prop(k, v):
        t = _template(inlined=True)
        t["Resources"][ROLE]["Properties"][k] = v
        return t

    mp = _template(inlined=True)
    mp["Resources"]["EvilMP"] = {
        "Type": "AWS::IAM::ManagedPolicy",
        "Properties": {"Roles": [{"Ref": ROLE}], "PolicyDocument": {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}}
    return {
        "s3:GetObject on *": with_stmt(
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}),
        "s3:ListBucket": with_stmt(
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": art}),
        "另一个桶": with_stmt({"Effect": "Allow", "Action": "s3:GetObject",
                               "Resource": "arn:aws:s3:::other-bucket/*"}),
        "通配动作 s3:GetObject*": with_stmt(
            {"Effect": "Allow", "Action": "s3:GetObject*", "Resource": art}),
        "NotResource": with_stmt({"Effect": "Allow", "Action": "s3:GetObject",
                                  "NotResource": "arn:aws:s3:::x/*"}),
        "不认识的 CloudFormation token": with_stmt(
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": {"Fn::ImportValue": "whatever"}}),
        "挂 AmazonS3ReadOnlyAccess": role_prop(
            "ManagedPolicyArns", ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]),
        "角色自身 Policies 里的宽语句": role_prop("Policies", [
            {"PolicyName": "extra", "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]),
        "经 AWS::IAM::ManagedPolicy.Roles": mp,
    }


@pytest.mark.parametrize("label", list(_iam_counterexamples()))
def test_iam_allowlist_rejects_each_counterexample(label):
    assert package_project_s3_violations(_iam_counterexamples()[label]), \
        f"**没红**：{label}"


# ── 检查器 ③：BuildSpec 交付形态 ──────────────────────────────────────────
def test_inlined_buildspec_template_is_clean():
    assert buildspec_template_violations(
        _template(inlined=True), BUILDSPEC.read_bytes()) == []


@pytest.mark.parametrize("label", ["S3-ARN 的 Fn::Join 形态", "字节被改动一个字符"])
def test_buildspec_template_rejects_each_counterexample(label):
    want = BUILDSPEC.read_bytes()
    if label == "S3-ARN 的 Fn::Join 形态":
        t = _template(inlined=False)
    else:
        t = _template(inlined=True)
        t["Resources"][PRJ]["Properties"]["Source"]["BuildSpec"] = \
            want.decode("utf-8")[:-1]
    assert buildspec_template_violations(t, want), f"**没红**：{label}"
```

- [ ] **Step 3: 跑它，确认正反两向都成立**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_security_contracts.py -q
```

预期 **21 passed**。其中三条是**这一整套的地基**，红了就别往下走：

- `test_real_buildspec_satisfies_the_command_contract`——真实文件合格（正向）；
- `test_inlined_template_has_exactly_two_s3_permissions`——"改完之后"的形态合格（正向）；
- `test_pre_change_template_is_rejected`——**"改动之前"的形态必须红**。这条是手写 fixture
  与现实有关联的唯一证据；它绿了说明 fixture 抄错了形态，整套反例都失去意义。

- [ ] **Step 4: 跑默认全量**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
```

预期 `1020 passed, 50 skipped`（改动前实测 999 passed / 50 skipped，本任务加 21 条）。
**基数以当次实测为准**，不要拿本行数字当断言。

- [ ] **Step 5: 改正 `CLAUDE.md` 里那句不准确的话**

把（约第 40 行）

```
> 当前唯一的隔断是 `buildspec-package.yml` 里的 `npm install --ignore-scripts`。
```

改成

```
> 当前的隔断分两层，**别把它记成"只有一条 flag"**：站点**自己的** package.json
> 生命周期脚本与 `backend/.npmrc` 由合同校验器在 CodeBuild 之前就拒
> （`contract/redlines.py` 的 `NPM_LIFECYCLE_KEYS`）；而**依赖里**的生命周期脚本
> **只有** `buildspec-package.yml` 的 `npm install --ignore-scripts` 一道——
> `_scan_package_json` 从不检查 `dependencies`，且 `.tgz` 依赖根本不被打开。
```

- [ ] **Step 6: 改正 `docs/security/account-trust-boundary.md` 的同一处说法**

在「平台侧唯一的过宽授权（`platform-overbroad`）」一节里，把「它今天**不可达**，隔断只有
一条：`buildspec-package.yml` 里 `npm install --ignore-scripts`（外加先删掉站点自带的
`.npmrc`）」改写成按攻击路径分层的说法，并写清那条实测：合同校验器只看站点自己的
`scripts` 段、不看 `dependencies`，而 `.tgz` 依赖不在扫描后缀里 ⇒ 对"依赖投毒"这条路，
`--ignore-scripts` 确实是唯一控制点。**保留原有结论**（"别把可签名的对称密钥物化进部署
资产"）与那 14 个带 `<!-- baseline:… -->` 标记的数字，本任务一个都不动。

- [ ] **Step 7: 跑文档守卫与秘密扫描**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py tests/test_verify_account_trust_boundary.py -q)
git add site-builder/deployer/tests/security_contracts.py \
        site-builder/deployer/tests/test_security_contracts.py \
        CLAUDE.md docs/security/account-trust-boundary.md
bash site-builder/scripts/scan_staged_secrets.sh
```

文档数字守卫（`test_doc_counts_come_from_the_baseline`）必须仍绿——本任务没动任何数字。

- [ ] **Step 8: 提交**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git commit -m "$(cat <<'MSG'
test(M09): 三个结构化安全检查器 + 外部反例；并改正「唯一隔断」这个说法

守卫全部写成「吃结构化输入、吐违规列表」的纯函数，反例在**内存里**注入：不改工作树、
不需要另一个 harness、跑在默认套件里。三个检查器：

- buildspec 的**命令合同**（不是 YAML 解释器）：定位唯一 commands 段、跳过 YAML 注释、
  拒绝 block scalar/续行/无法 shlex 分词（fail-closed），再按 && || ; | 切成逐条命令；
  判据是**精确 token 列表** + 顺序 + "除这条 install 外不许有别的 npm 子命令"。
- IAM 的**精确 allowlist**（不是 IAM evaluator）：从 Project.ServiceRole 反查角色、
  收集**全部**权限来源（inline Policies / IAM::Policy / IAM::ManagedPolicy /
  ManagedPolicyArns）、把 Allow 的 S3 (action, resource) 规范化后与两条精确期望比**等值**；
  NotAction/NotResource、Resource:*、通配动作、managed attachment、不认识的 CFN token
  一律判违规而不求值。
- BuildSpec 的交付形态：NO_SOURCE + 内联字符串 + 与仓库文件逐字节相等。

**为什么必须是精确 allowlist**：上一版是"没出现某个已知坏值 + 期望值存在"。实测一份
策略——两条精确授权都在、另加 s3:GetObject + s3:ListBucket on *——两条断言**都通过**。
这与 `_package_project_resources()` 只看见"手写的那一半"是同一个错误。

**反例集合含一组由复审方提出的反例，逐字纳入**（前一版我自验 16 项全过，而复审另挑的
四个 buildspec 退化——`--ignore-scripts=false`、flag 只留在注释里、删 .npmrc 挪到 install
之后、删错目录——全部绿）。自己写反例验自己的守卫，证明的是守卫对得上作者的想象力。

**顺带改正一个多处流传的说法**：「唯一的隔断是 --ignore-scripts」不准确。站点**自己的**
package.json 生命周期脚本与 backend/.npmrc 有合同校验器在 CodeBuild 之前拦（两道）；
但**依赖里**的生命周期脚本只有那条 flag——`_scan_package_json` 从不看 `dependencies`，
且 `.tgz` 不在扫描后缀里。实测（npm 10.9.8）：带 preinstall 的包 npm pack 成本地 .tgz
作依赖，npm install **会执行**它，加上 --ignore-scripts **不会**。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Task 2: 内联 buildspec + 删整桶读 + `__main__` 守卫 + opt-in 模板断言

**Files:**
- Modify: `site-builder/deployer/infra/app.py`（常量区 `VALIDATED_PREFIX` 之后；
  `class SiteDeployerStack` 之前；`cb.Project` 在 311-318 行；文件末尾 905-908 行）
- Modify: `site-builder/deployer/tests/test_infra_tables.py`

**Interfaces:**
- Consumes: Task 1 的三个检查器
- Produces: `app.BUILDSPEC_PATH: Path`、`app._InlineBuildSpec(text)`（`is_immediate -> True`、
  `to_build_spec(scope=None) -> str` 原样返回）

- [ ] **Step 1: 加常量**

在 `VALIDATED_PREFIX = _validate_const("VALIDATED_PREFIX")` 之后追加：

```python
# CodeBuild 的 buildspec：**逐字节内联**进模板，不走 CDK asset（理由见 _InlineBuildSpec）。
# `read_bytes().decode("utf-8")` 而不是 `read_text()`：后者走文本模式会做换行归一化，
# 那样"模板里的字符串重新编码后等于文件原始字节"这条断言就不再在任何平台成立。
# （实测本文件今天是纯 LF，两种读法结果相同——这是稳健性措施，不是在修现存 bug。）
BUILDSPEC_PATH = Path(__file__).parents[1] / "buildspec-package.yml"
```

- [ ] **Step 2: 加子类**

在 `class SiteDeployerStack(Stack):` **之前**追加：

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

- [ ] **Step 3: 换接线**

把 311-314 行的

```python
            build_spec=cb.BuildSpec.from_asset(
                str(Path(__file__).parents[1] / "buildspec-package.yml")),
```

改成

```python
            build_spec=_InlineBuildSpec(BUILDSPEC_PATH.read_bytes().decode("utf-8")),
```

`environment`、`timeout` 与紧随其后的两条 `add_to_role_policy`（`validated/*` 读、
`artifacts/*` 写）**一个字都不改**。

- [ ] **Step 4: 给顶层 synth 加 `__main__` 守卫**

把文件末尾（905-908 行）的

```python
app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
```

改成

```python
# **必须在 `__main__` 守卫之下**：不加时 `import app` 就 synth 整个栈并触发 Lambda
# bundling（要起 Docker），于是任何想 import 本模块做单测的地方都被迫依赖 Docker，
# 而 `test_infra_tables.py` 的 fixture 更是 import 时 synth 一次、自己再建 App synth
# 一次。`cdk.json` 是 `{"app": "python3 app.py"}`，所以对 `cdk` 完全无影响。
if __name__ == "__main__":
    app = App()
    SiteDeployerStack(app, "SiteDeployerStack",
                      env=Environment(account=ACCOUNT, region=REGION))
    app.synth()
```

- [ ] **Step 5: 跑默认全量，确认既有守卫没被放宽**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
```

预期仍是 `1020 passed, 50 skipped`。特别确认
`test_validate.py::test_buildspec_and_iam_name_the_validated_prefix_only` 仍绿——它断言
`package_project` **手写的**资源集合恰好是 `{validated/*, artifacts/*}`，本改动不该动它。

- [ ] **Step 6: 加 opt-in 模板断言**

先把 `tests/test_infra_tables.py` 的 docstring 第一行

```
"""CDK 模板断言：二期新增的表与索引必须存在，且 step Lambda 拿到 ADMINS_TABLE。
```

改成

```
"""CDK 模板断言：二期新增的表与索引、以及 CodeBuild buildspec 的交付方式与
PackageProject 角色的**全部** IAM 语句。

**本文件是仓库里唯一看"真 synth 出来的模板"的地方**，所以凡是"源码 AST 看不见"的断言都
归这里（CDK 自动生成的 IAM 语句就属于这一类）。语义反例不在这里——它们跑在
`test_security_contracts.py` 的手写 fixture 上（always-on、无 Docker）；本文件的职责是
证明**真模板**也满足同样那三个检查器，也就是替手写 fixture 兜住"与现实漂移"。
```

然后在文件顶部常量区（`CONFIG = …` 之后）追加：

```python
BUILDSPEC = Path(__file__).parents[1] / "buildspec-package.yml"
```

并在文件末尾追加（**注意这三条不再自己写判据**，直接复用 Task 1 的检查器）：

```python
def test_real_template_package_project_s3_is_exactly_two_permissions(template):
    from security_contracts import package_project_s3_violations
    assert package_project_s3_violations(template.to_json()) == []


def test_real_template_buildspec_is_inlined_byte_for_byte(template):
    from security_contracts import buildspec_template_violations
    assert buildspec_template_violations(
        template.to_json(), BUILDSPEC.read_bytes()) == []


def test_importing_app_does_not_synth(template):
    """`app.py` 顶层的 `App()/synth()` 必须在 `__main__` 守卫之下。

    这条守的是"import 无副作用"这个前提本身：没有它，任何想 import 本模块的单测都被迫
    依赖 Docker，而本文件的 fixture 会 synth 两次。判据取 AST——`import app` 已经由
    fixture 做过了，这里要断言的是**源码结构**。
    """
    import ast
    src = (INFRA / "app.py").read_text(encoding="utf-8")
    tops = [n for n in ast.parse(src).body
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
    bad = [n for n in tops
           if getattr(getattr(n.value.func, "value", None), "id", None) == "app"]
    assert not bad, f"app.py 顶层仍有 app.<...>() 调用（第 {[n.lineno for n in bad]} 行）"
```

- [ ] **Step 7: 跑 opt-in 断言（需 PYTHONPATH 桥接 + Docker）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
PYTHONPATH="$PWD/infra/.venv/lib/python3.12/site-packages" SB_CDK_TESTS=1 \
  .venv/bin/pytest tests/test_infra_tables.py -q
```

预期全绿（含既有的表/索引断言）。**不需要**把 `app.py` 手工改回 `from_asset` 跑一次：
这三个检查器"能红"已经由 Task 1 的 `test_pre_change_template_is_rejected` 与那 17 条
反例在内存里证明过了。上一版要求手工改工作树里的生产 CDK 文件，那既不可复跑、又违反了
"不改工作树"这条自己给出的理由。

- [ ] **Step 8: `cdk diff`（只看，不部署）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer/infra"
rm -rf cdk.out
PATH=.venv/bin:$PATH npx -y aws-cdk@latest diff | tee /tmp/m09-3b-cdkdiff.txt
```

预期**两类**变化，不是一类：

1. `AWS::CodeBuild::Project`（`PackageProjectC43E863E`）的 `Source.BuildSpec`：
   `Fn::Join` 出的 S3 ARN → 内联 YAML 字符串；
2. `AWS::IAM::Policy`（`PackageProjectRoleDefaultPolicy79E436B4`）：删掉
   `s3:GetObject*`/`GetBucket*`/`List*` on bootstrap 桶那一条。

逐项确认 diff 里**没有**：CodeBuild Project replacement、Role replacement、
logical ID 变化、其它 IAM 变化、`site-artifacts` 精确权限的任何变化。
（少一个 CDK asset 是预期的。）

- [ ] **Step 9: 跑 auth（证明没碰 bundling 段）并提交**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
git add site-builder/deployer/infra/app.py site-builder/deployer/tests/test_infra_tables.py
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
fix(M09): buildspec 逐字节内联——删掉 CodeBuild 对 bootstrap 桶的整桶读

`site-package` 那条 `s3:GetObject*/GetBucket*/List*` on **整个** CDK bootstrap 桶是
`BuildSpec.from_asset()` 让 CDK 自动加的（`Asset.grantRead()` 授桶不授对象），而它的
**唯一用途是取自己那 25 行 buildspec** —— buildspec 从头到尾只碰 `$ARTIFACTS_BUCKET`。
同一个桶里有 9 个仍带明文会话签名密钥的 Edge asset，而这个项目跑的正是不可信站点的
依赖安装。内联之后那条权限整条消失，不是收窄。

用自定义 `cb.BuildSpec` 子类而不是先解析成 dict：`from_object` 会把文件重新序列化、
注释全丢（`--ignore-scripts` 为什么必需就写在注释里），还让 `version: 0.2`（YAML float）
往返一次。子类是透明搬运，部署出去的 buildspec 与仓库文件**逐字节相同**。

顺带把顶层 `App()/synth()` 挪进 `if __name__ == "__main__":`：不加守卫时 `import app`
就 synth 整个栈并触发 Lambda bundling，于是任何 import 本模块的单测都被迫依赖 Docker，
而 `test_infra_tables.py` 的 fixture 更是 import 时 synth 一次、自己再建 App synth 一次。
`cdk.json` 是 `{"app": "python3 app.py"}`，对 `cdk` 无影响。

模板层验收**复用 Task 1 的三个检查器**，不再自己写判据：真模板必须满足与手写 fixture
同样那三条。也不再需要"手工把 app.py 改回 from_asset 跑一次"——检查器能红已经由内存
反例证明，而手工改工作树里的生产 CDK 文件既不可复跑、又违反了"不改工作树"这条理由。

未部署。生产部署与基线/文档更新按 Task 4/5 单独放行。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Task 3: opt-in 真机行为探针（tracked，默认不跑）

静态检查器证明**结构**，探针证明**真实 npm/CodeBuild 行为**。做成制品而不是一次操作，
否则又回到"不可复跑的证据等于没有证据"。**本任务只创建它（默认 skip ⇒ 提交是绿的）**，
真正跑它在 Task 4。

**Files:** Create `site-builder/deployer/tests/test_codebuild_security_probe.py`

- [ ] **Step 1: 写探针**

要求（每一条都已核过对应接口）：

- `pytestmark = pytest.mark.skipif(os.environ.get("RUN_CODEBUILD_SECURITY_PROBE") != "1", …)`，
  日常七包不跑；
- fixture 在 `tmp_path` **动态生成**，不进 `fixtures/`。站点内容照 `fixtures/nosql-notes`
  的形状（`site.json` + `backend/` + `frontend/`），**唯一的差别**是 `backend/` 下多一个
  本地 `.tgz` 依赖：
  - 先在 `tmp_path` 里造一个小包，`package.json` 的 `scripts.preinstall` 用
    `node -e` 往**自己目录**里写一个唯一 sentinel 文件名（例如 `PROBE-<随机 hex>`）；
  - `npm pack` 成 `.tgz` 放进 `backend/`；
  - `backend/package.json` 的 `dependencies` 写 `{"probe-dep": "file:./<tgz 名>"}`。
  - **必须用 `.tgz`，不能用普通子目录**：合同校验器会扫 `backend/` 下**任何**
    `package.json` 并拒绝生命周期脚本（`redlines.py` 的 `_scan_package_json`），
    普通子目录形态在 validate 就被拦下、根本到不了 CodeBuild；而 `.tgz` 不在 `TEXT_EXT`
    里、不会被打开。**这同时就是"依赖这条路只有 flag 一道"的可执行证据。**
- 用 `site-builder/scripts/deploy_fixture.py <dir> --site-id <probe-id>` 部署
  （与 E2E 同一条路径，别另写一套提交逻辑）；
- **清理必须复用 `tests/test_e2e_fixtures.py` 里那套 undeploy/清理 helper**，不许写一份
  简化副本（仓库纪律：测试里用真实生产 helper）；清理未完成要硬失败。
- 断言三条，**缺一条这个探针就可能在自欺**：
  1. 部署成功（`deploy_fixture.py` 退出码 0 且拿到 URL）；
  2. `lambda:GetFunction` 下载 `site-<probe-id>` 的代码包（函数名约定见
     `deploy_lambda_site.py:161` 的 `f"site-{event['site_id']}"`），zip 里**存在**
     `node_modules/probe-dep/package.json` —— 这是**正向控制**：证明 `npm install` 真的
     跑了并处理了我们这个依赖，而不是探针根本没走到装依赖这一步；
  3. 同一个 zip 里**搜不到那个 sentinel 文件名** —— 生命周期脚本没有被执行。

  第 2 条的必要性有实测支撑：本机 npm 10.9.8 下，`npm install --omit=dev --no-audit
  --no-fund --ignore-scripts` 之后 `node_modules/probe-dep/package.json` **在**、
  sentinel **不在**；去掉 flag 则 sentinel 出现。所以"存在 node_modules 且无 sentinel"
  恰好区分开"flag 生效"与"根本没装"。

- **可选的更深一层正向控制**（不作为本任务的必需项）：拿这次构建的
  `validated/<job>/backend-src.zip` 作输入，`StartBuild` 时带 `buildspecOverride`
  ——只把 `--ignore-scripts` 去掉——sentinel 必须出现。它更直接，但要多一次直调
  CodeBuild；此时角色已收权（只能读 `validated/*`、写 `artifacts/*`），风险面很小。
  要做就写进探针并同样 opt-in；不做则在 docstring 里写明"本探针的正向控制是第 2 条"。

- 探针的 docstring 必须写明**它不证明什么**：不覆盖 `.npmrc` 那条（把 registry 改成可
  观察目标需要引入外部 registry 或依赖 npm 某个配置项的行为细节，两者都会造出不稳定的
  E2E）。`.npmrc` 以检查器 ① 的精确结构与顺序判据为权威。

- [ ] **Step 2: 确认默认套件里它是 skip 的**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests -q
```

预期 passed 数不变、skipped 增加。**不要**在本任务里跑探针——它需要 Task 4 部署完成后的
生产状态；在此之前跑它只会证明"改动前 flag 也在生效"，那不是本改动的验收。

- [ ] **Step 3: 提交**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git add site-builder/deployer/tests/test_codebuild_security_probe.py
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
test(M09): opt-in 真机行为探针——证明依赖的生命周期脚本真的不被执行

静态检查器证明结构，探针证明真实 npm/CodeBuild 行为。做成 tracked、默认 skip 的制品
（`RUN_CODEBUILD_SECURITY_PROBE=1`），而不是"跑一次把结论写成文字"——那等于没有证据。

fixture 在 tmp_path 动态生成，`backend/` 里放一个本地 `.tgz` 依赖，其 preinstall 往自己
目录写一个唯一 sentinel。**必须用 .tgz**：合同校验器会扫 backend/ 下任何 package.json
并拒绝生命周期脚本，普通子目录形态在 validate 就被拦下、到不了 CodeBuild；而 .tgz 不在
扫描后缀里。这同时就是"依赖这条路只有 --ignore-scripts 一道"的可执行证据。

断言三条：部署成功；产出包里**存在** node_modules/probe-dep/package.json（正向控制——
证明 npm install 真的处理了这个依赖，而不是探针没走到装依赖那一步）；同一个包里**搜不到**
sentinel。只断言"sentinel 不存在"是不够的，那与"根本没装"无法区分。

不证明什么：不覆盖 .npmrc 那条（要把 registry 变成可观察目标就得引入外部 registry 或
依赖 npm 配置项的行为细节，两者都会造出不稳定的 E2E）。.npmrc 以命令合同检查器为权威。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Task 4: 部署与真机验收

> **STOP —— 动生产，必须先拿到人工放行。** 前置：Task 1-3 已提交、`cdk diff` 已人工过目、
> Docker 在跑、AWS 凭证有效且指向部署账号。

**Files:** 不改文件（部署 + 只读验证 + 跑探针）

- [ ] **Step 1: 确认独占窗口（操作员承诺，不是技术上关了入口）**

本仓库**没有**维护开关，也没有能暂停 MCP/panel 写入口的机制。所以这一步的真实内容是：
单人环境下操作员承诺窗口内不自己发起部署，并在部署前确认此刻没有在途工作。

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import boto3
REGION = "us-east-1"
s = boto3.Session(region_name=REGION)
# **账号锚定**：别对着另一个账号断言"没有在途工作"
import configparser
from pathlib import Path
cfg = configparser.ConfigParser()
cfg.read(Path("site-builder/config.ini"))
want = cfg["Platform"]["account_id"]
got = s.client("sts").get_caller_identity()["Account"]
assert got == want, f"凭证在 {got}，config.ini 是 {want}"

cb = s.client("codebuild")
ids = []
for page in cb.get_paginator("list_builds_for_project").paginate(
        projectName="site-package"):
    ids += page["ids"]
running = []
for i in range(0, len(ids), 100):            # batch_get_builds 上限 100
    running += [b["id"] for b in cb.batch_get_builds(ids=ids[i:i + 100])["builds"]
                if b["buildStatus"] == "IN_PROGRESS"]
# 表名 site-deploy-jobs（**不是** site-jobs）；租约判"还在跑吗"看的就是 RUNNING
jobs = []
for page in s.client("dynamodb").get_paginator("scan").paginate(
        TableName="site-deploy-jobs", FilterExpression="#s = :r",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":r": {"S": "RUNNING"}},
        ProjectionExpression="job_id"):
    jobs += [i["job_id"]["S"] for i in page["Items"]]
if running or jobs:
    raise SystemExit(f"有在途工作，先等它们结束：builds={running} jobs={jobs}")
print(f"独占窗口 OK（历史构建 {len(ids)} 个，全部已结束；无 RUNNING job）")
PY
```

**必须 `raise SystemExit` 而不是打印 `True/False`**：在自动执行下，"打印了但没人拦"
与"没有在途项"一模一样。分页也是必须的——实测该项目已有 **102** 个历史构建，取前 20 个
会漏掉更早仍在跑的那种；`scan` 的 `FilterExpression` 是每页 1MB 扫完才应用。

- [ ] **Step 2: 部署 deployer 栈**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer/infra"
rm -rf cdk.out
PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never
```

- [ ] **Step 3: 部署后静态确认（只读，全部 `assert`）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import boto3, configparser, json
from pathlib import Path
REGION = "us-east-1"
s = boto3.Session(region_name=REGION)
cfg = configparser.ConfigParser(); cfg.read(Path("site-builder/config.ini"))
want = cfg["Platform"]["account_id"]
assert s.client("sts").get_caller_identity()["Account"] == want, "账号不匹配"

BS = Path("site-builder/deployer/buildspec-package.yml").read_bytes()
p = s.client("codebuild").batch_get_projects(names=["site-package"])["projects"][0]
src = p["source"]
assert src["type"] == "NO_SOURCE", src["type"]
inline = src.get("buildspec", "")
assert not inline.startswith("arn:"), "buildspec 还是 S3 ARN"
assert inline.encode("utf-8") == BS, "内联的 buildspec 与仓库文件不逐字节相同"

iam = s.client("iam")
role = p["serviceRole"].rsplit("/", 1)[-1]
blob = []
for page in iam.get_paginator("list_role_policies").paginate(RoleName=role):
    for name in page["PolicyNames"]:
        blob.append(json.dumps(iam.get_role_policy(
            RoleName=role, PolicyName=name)["PolicyDocument"]))
for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role):
    for att in page["AttachedPolicies"]:
        v = iam.get_policy(PolicyArn=att["PolicyArn"])["Policy"]["DefaultVersionId"]
        blob.append(json.dumps(iam.get_policy_version(
            PolicyArn=att["PolicyArn"], VersionId=v)["PolicyVersion"]["Document"]))
allp = "\n".join(blob)
assert "cdk-hnb659fds-assets" not in allp, "bootstrap 桶权限还在"
assert "/validated/*" in allp and "/artifacts/*" in allp, "两条精确授权丢了"
assert "s3:List" not in allp, "还有 s3:List*"
print("部署后静态确认全部通过")
PY
```

- [ ] **Step 4: 行为确认**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
RUN_E2E=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_e2e_fixtures.py -q
RUN_CODEBUILD_SECURITY_PROBE=1 site-builder/deployer/.venv/bin/pytest \
  site-builder/deployer/tests/test_codebuild_security_probe.py -q
```

E2E 文件**机械核实过是 10 条**（不是 4 条 fixture；`约 6 分钟` 那个旧数字别再引用，
按实测重新记）。多条用例会重复部署 `nosql-notes`，所以 `package_backend → CodeBuild`
会被多次经过：首次构建证明内联 buildspec 能被取用、更新构建证明不是只在创建时有效、
失败恢复路径证明构建失败后项目仍可用、NoSQL 与 DSQL 两类后端证明打包输出没有意外变化。

**不跑** `smoke_router.sh`：本改动不碰 CloudFront / Edge / route / 会话鉴权 /
Function URL，而完整 E2E 本身已经通过公网路由访问生成的站点。

- [ ] **Step 5: 一次观测，三次使用**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# ① 唯一一次 AWS 观测（约 9.5 分钟）。产物含真实角色名，**只许留在 /tmp，不得提交**。
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --dump-observed /tmp/m09-3b-observed.json
# ② 用同一份字节与旧基线比较、出闸门结论（不发 AWS 调用）
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --from-dump /tmp/m09-3b-observed.json
```

`set -e` 会让 ② 的非零退出直接终止——**不要**用 `| tee` + `${PIPESTATUS[0]}` 判它。

② 的预期：只有**一条** improvement（那个 fp「不再具备任何敏感授权（原
platform-overbroad）」）；A 62 → 61；可读密钥 57 → 56；`platform-overbroad` 1 → 0；
而 **B、resource policy、coverage、asset facts 全都不变**
（`edge_assets_carrying_live_key` 仍 9、`edge_code_targets_carrying_live_key` 仍 10、
`undecided_items` 774 → 774）。任何一项不符先查清原因，**不要**进 Task 5。

---

## Task 5: 基线与文档的原子提交

> **STOP —— 需要人工核对 Task 4 Step 5 ② 的 delta 之后才能开始。**
> 必须复用 Task 4 产出的**同一份** `/tmp/m09-3b-observed.json`：重新实时观测一次就是
> TOCTOU——人批准的与写进去的不是同一份字节。

**Files:**
- Modify: `site-builder/scripts/account_trust_baseline.json`（由脚本从 dump 写，不手改）
- Modify: `docs/security/account-trust-boundary.md`

**不需要**改 `tests/test_verify_account_trust_boundary.py`：核过了——`platform-overbroad`
在那里只出现两处，一处是从基线**算**计数的 `category_slugs` 映射（算出 0 就要求文档里
出现 `…=0`，映射本身不用动），另一处用的是合成基线。

- [ ] **Step 1: 从同一份 dump 写基线**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 site-builder/scripts/verify_account_trust_boundary.py \
  --from-dump /tmp/m09-3b-observed.json --update-baseline
```

- [ ] **Step 2: 结构化断言基线 delta（不许用带截断的文本 diff）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import json, subprocess
P = "site-builder/scripts/account_trust_baseline.json"
old = json.loads(subprocess.run(["git", "show", f"HEAD:{P}"],
                                capture_output=True, text=True, check=True).stdout)
new = json.loads(open(P, encoding="utf-8").read())
gone = set(old["principals"]) - set(new["principals"])
added = set(new["principals"]) - set(old["principals"])
assert not added, f"新基线多出 principal：{added}"
assert len(gone) == 1, f"应当恰好少 1 个 principal，实际少了 {len(gone)}：{gone}"
fp = gone.pop()
e = old["principals"][fp]
assert e.get("category") == "platform-overbroad", e.get("category")
assert e.get("grants") == ["read-edge-asset"], e.get("grants")
for k in ("facts", "coverage", "iam_write_statements", "permissions_boundaries",
          "managed_policy_versions", "resource_policies", "schema"):
    assert old.get(k) == new.get(k), f"{k} 变了——本改动不该动它"
for k, v in new["principals"].items():
    assert v == old["principals"][k], f"{k} 的条目被改了"
print(f"基线 delta 恰好是预期的那一条（{fp}），其余 {len(new['principals'])} 条一字未动")
PY
```

**为什么不能用 `git diff | grep | head -40`**：那是**带截断的存在性判断**——"不在前 40 行"
不等于"不存在"，而基线接近千行。

- [ ] **Step 3: 跑闸门测试，看文档数字守卫红在哪**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/site-builder/deployer"
.venv/bin/pytest tests/test_verify_account_trust_boundary.py -q || true
```

预期 `test_doc_counts_come_from_the_baseline`（第 639 行，按 `<!-- baseline:… -->` 标记
**整串**比对）**红**，报文点出 `A总数` 期望 61、`可读密钥` 期望 56、
`类别_platform_overbroad` 期望 0。这条红是设计好的：它强制基线与文档同提交。
（这一步刻意加 `|| true`，因为"看它红"就是本步的目的。）

- [ ] **Step 4: 改文档的数字**

守卫按 `f"{n} <!-- baseline:{label}={n} -->"` **整串**匹配，所以数字与标记里的值
必须一致：

- `62 <!-- baseline:A总数=62 -->` → `61 <!-- baseline:A总数=61 -->`
- `57 <!-- baseline:可读密钥=57 -->` → `56 <!-- baseline:可读密钥=56 -->`
- `1 <!-- baseline:类别_platform_overbroad=1 -->` → `0 <!-- baseline:类别_platform_overbroad=0 -->`

**那一行表格不能删**：守卫对 `category_slugs` 里的每个类别都要求文档中出现对应标记，
删掉整行会红在"找不到 `…=0`"上。

同时把「合计 62 = A 组总数」改成 61，并逐一核对开头「一句话」一节与「A + B 的并集是 66」
那句的算术（66 = 62 + 4 ⇒ 65 = 61 + 4）。

- [ ] **Step 5: 改「平台侧唯一的过宽授权」那一节**

改成"已收窄 + 历史结论保留"。要保留：这条权限**曾经**存在且是 CDK 自动授的；它跨越
「不可信站点输入 → 平台签名密钥」这条威胁边界；**结论仍然成立**——"别把可签名的对称
密钥物化进部署资产"。要新增：现在 buildspec 逐字节内联、该角色对 bootstrap 桶零权限、
且这条不变量由检查器按**等值**断言；以及 **`--ignore-scripts` 仍然必须保留**（构建容器
里任意代码执行仍能读 `validated/*`、写 `artifacts/*`）。
标题里的"唯一"要去掉——`platform-overbroad` 现在是 0 个，留着会读成"还有一个"。

- [ ] **Step 6: 跑到全绿并提交**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
git add site-builder/scripts/account_trust_baseline.json \
        docs/security/account-trust-boundary.md
bash site-builder/scripts/scan_staged_secrets.sh
git commit -m "$(cat <<'MSG'
feat(M09): 收窄生效后重写基线 + 同步文档数字（A 62→61、可读密钥 57→56）

CodeBuild 那条整桶读已从生产移除并过完真机验收，所以基线吸收这一条改善：
`platform-overbroad` 那个 principal 只有 `read-edge-asset` 一条 grant，移除后它整条
退出 A 组。基线由 `--from-dump` 从**人工核对过的那一份** dump 写入——不是重新实时观测
一次（那样人批准的与写进去的不是同一份字节）。delta 用结构化断言核过：恰好少那一个
指纹、其余 61 条与 facts/coverage/iam_write/resource_policies/schema 一字未动。

基线与文档**必须同提交**（`test_doc_counts_come_from_the_baseline` 按标记整串比对，
分开提交必红）。「平台侧唯一的过宽授权」一节改成"已收窄 + 历史结论保留"，并写明
`--ignore-scripts` 仍然必须留着。

**没有变的**：带活密钥的 asset 仍 9、Edge 代码目标仍 10、undecided 774→774、
B 的 22 holder/43 语句一字未动。`read-edge-code` 与 `read-jwt-param` 两条路一寸没动
——那要等非对称签名（真修复②）。

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

- [ ] **Step 7: 收尾全量**

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

变形全红（本计划没动那个 harness，37 条应不变）；七包全绿。**把各包实测通过数记下来**
——那是这一轮的签字数字，不要引用上一轮的。

- [ ] **Step 8: 更新 §9**

在 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9 里把 **3b** 标成已完成，
写明它**只**动了 1 个 principal、下一条是 3c（非对称签名）。单独一个 `docs(M09):` 提交。

---

## 回滚

revert Task 2 的提交，重新部署 deployer 栈。bootstrap 桶里那个孤儿 buildspec asset
对象留着无害。若已走完 Task 5，**一并 revert 基线与文档那个提交**——否则闸门会把
"权限回来了"报成红，而那正是它该做的；不要为了让闸门变绿而保留新基线。
**没有迁移、没有回填、没有补偿、没有状态。**

## 不变量（改完必须仍然成立）

- `site-package` 角色的 **S3 权限全集**精确等于两条：`s3:GetObject` on
  `…/validated/*`、`s3:PutObject` on `…/artifacts/*`。没有 `ListBucket`、没有
  `DeleteObject`、没有通配动作、没有 `Resource: "*"`、没有任何 managed policy
  attachment。**由检查器 ② 按等值断言**，不是"没出现某个已知坏值"。
- buildspec 的**唯一真源**是 `site-builder/deployer/buildspec-package.yml`；部署出去的
  内容与它**逐字节**相同（含注释）。
- `npm install` 的 token 精确等于预期列表（含 `--ignore-scripts`），删 `.npmrc` 的命令
  精确存在且**严格早于**它，且除该 install 外没有其它 npm 子命令。由检查器 ① 断言。
- `test_validate.py::test_buildspec_and_iam_name_the_validated_prefix_only` 继续成立且
  **不放宽**。
- `import app` **无副作用**（`App()/synth()` 在 `__main__` 守卫之下）。
- 每个提交都是绿的、可运行的 checkout。
