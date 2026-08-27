"""always-on：三个检查器的正向输入 + 全部外部反例（内存注入，不碰工作树）。"""
import copy
import json
import shlex
from pathlib import Path

import pytest

from security_contracts import (build_container_interlock_violations,
                                buildspec_template_violations,
                                module_toplevel_side_effect_violations,
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


def _swap_lines(src: str, needle_a: str, needle_b: str) -> str:
    """按**内容**定位两行并交换（不按行号偏移——那样容易换到注释上）。"""
    lines = src.splitlines()
    ia = next(i for i, l in enumerate(lines) if needle_a in l and l.strip().startswith("-"))
    ib = next(i for i, l in enumerate(lines) if needle_b in l and l.strip().startswith("-"))
    lines[ia], lines[ib] = lines[ib], lines[ia]
    return "\n".join(lines) + "\n"


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
        # 下面三条是**外部复审提出的**：首 token 不是 `npm`，旧判据全部放行
        "env npm rebuild（wrapper）":
            "\n".join(lines[:i_n + 1] + ["      - env npm rebuild"] + lines[i_n + 1:]) + "\n",
        "sh -c 'npm rebuild'（wrapper）":
            "\n".join(lines[:i_n + 1] + ["      - sh -c 'npm rebuild'"] + lines[i_n + 1:]) + "\n",
        "/usr/bin/npm rebuild（绝对路径）":
            "\n".join(lines[:i_n + 1] + ["      - /usr/bin/npm rebuild"] + lines[i_n + 1:]) + "\n",
        # 整体等值顺带盖住的两类：多一条无关命令、把两条命令换序
        "多一条无关命令（node -e）":
            "\n".join(lines[:i_n + 1] + ['      - node -e "1"'] + lines[i_n + 1:]) + "\n",
        # **按内容定位**换序，不按行号偏移：第一版按 i_n-2/i_n-3 换，结果换到了两行
        # **注释**上、命令序列没变，于是检查器正确地没红——反例自己写错了。
        "删 .npmrc 与 cd backend 换序": _swap_lines(
            good, "-name .npmrc -delete", "cd /tmp/site/backend"),
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
        # 下面三条是**外部复审提出的**：只收 identity policy 时全部放行
        "桶策略把 s3:* on * 授给本角色": _bucket_policy(
            {"AWS": {"Fn::GetAtt": [ROLE, "Arn"]}},
            ["s3:GetObject", "s3:ListBucket"], "*"),
        "桶策略 Principal 是 *": _bucket_policy(
            "*", ["s3:GetObject"], "*"),
        "桶策略 Principal 形态不认识（fail-closed）": _bucket_policy(
            {"Weird": "x"}, ["s3:GetObject"], "*"),
    }


def _bucket_policy(principal, actions, resource) -> dict:
    t = _template(inlined=True)
    t["Resources"]["InjectedBucketPolicy"] = {
        "Type": "AWS::S3::BucketPolicy",
        "Properties": {"Bucket": {"Ref": ART}, "PolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": principal,
             "Action": actions, "Resource": resource}]}}}
    return t


def test_bucket_policy_for_another_principal_is_not_counted():
    """正向控制：授给**别的**身份的桶策略不该误红。

    真模板里就有一条 `ArtifactsPolicy`，Principal 是 auto-delete 自定义资源的角色；
    把"任何桶策略"都算进本角色的权限集合会让 opt-in 那层立刻误红。
    """
    t = _bucket_policy({"AWS": {"Fn::GetAtt": ["SomeOtherRoleABC123", "Arn"]}},
                       ["s3:PutBucketPolicy", "s3:GetBucket*"], "*")
    assert package_project_s3_violations(t) == []


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


# ── `app.py` 的 import 必须无副作用 ──────────────────────────────────────
# **放在 always-on 这边而不是 opt-in 那边**：它是纯 AST 判据、不需要 aws_cdk 也不需要
# Docker，写成要 `template` fixture 的用例会为一条不需要 synth 的断言白起一次 synth。
PRE_CHANGE_TOPLEVEL = """
app = App()
SiteDeployerStack(app, "SiteDeployerStack",
                  env=Environment(account=ACCOUNT, region=REGION))
app.synth()
"""

# 只把 `synth()` 挪进守卫、把建栈留在顶层——旧判据（只找 `app.synth()`）对它 bad=[]，
# 而 import 一样会建栈。这条是外部复审提出的反例。
SYNTH_ONLY_GUARDED = """
app = App()
SiteDeployerStack(app, "SiteDeployerStack")
if __name__ == "__main__":
    app.synth()
"""


def test_real_app_py_has_no_toplevel_side_effects():
    src = (Path(__file__).parents[1] / "infra" / "app.py").read_text(encoding="utf-8")
    assert module_toplevel_side_effect_violations(src) == []


@pytest.mark.parametrize("label,src", [
    ("改动前的完整三行", PRE_CHANGE_TOPLEVEL),
    ("只把 synth 挪进守卫、建栈留在顶层", SYNTH_ONLY_GUARDED),
    ("顶层只有一个裸 App()", "app = App()\n"),
    ("顶层只有一个 SiteDeployerStack(...)", 'SiteDeployerStack(app, "S")\n'),
])
def test_toplevel_side_effect_guard_rejects_each_counterexample(label, src):
    assert module_toplevel_side_effect_violations(src), f"**没红**：{label}"


def test_guard_allows_everything_inside_the_main_guard():
    """正向控制：守卫之内的同样三行必须放行，否则这条守卫会把正确写法也判红。"""
    ok = ('if __name__ == "__main__":\n'
          "    app = App()\n"
          '    SiteDeployerStack(app, "S")\n'
          "    app.synth()\n")
    assert module_toplevel_side_effect_violations(ok) == []
