"""always-on：三个检查器的正向输入 + 全部外部反例（内存注入，不碰工作树）。"""
import copy
import json
import shlex
from pathlib import Path

import pytest

from security_contracts import (action_resource_violations,
                                bucket_policy_statements,
                                grants_to_principal,
                                build_container_interlock_violations,
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
        # 下面三条是**外部复审提出的**：账号级 principal + aws:PrincipalArn 条件是常见
        # 写法，只比对 Principal.AWS 是否等于角色 ARN 会整条漏掉
        "账号 root + ArnEquals 指向本角色": _bucket_policy(
            {"AWS": f"arn:aws:iam::{ACCT}:root"}, ["s3:GetObject"], "*",
            condition={"ArnEquals": {"aws:PrincipalArn": {"Fn::GetAtt": [ROLE, "Arn"]}}}),
        "账号 root 且没有任何条件（fail-closed）": _bucket_policy(
            {"AWS": f"arn:aws:iam::{ACCT}:root"}, ["s3:GetObject"], "*"),
        "账号 root + ArnLike 通配（无法判定，fail-closed）": _bucket_policy(
            {"AWS": ACCT}, ["s3:GetObject"], "*",
            condition={"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{ACCT}:role/*"}}),
    }


def _bucket_policy(principal, actions, resource, *, condition=None) -> dict:
    t = _template(inlined=True)
    st = {"Effect": "Allow", "Principal": principal,
          "Action": actions, "Resource": resource}
    if condition is not None:
        st["Condition"] = condition
    t["Resources"]["InjectedBucketPolicy"] = {
        "Type": "AWS::S3::BucketPolicy",
        "Properties": {"Bucket": {"Ref": ART}, "PolicyDocument": {"Statement": [st]}}}
    return t


def test_account_root_condition_pointing_at_another_role_is_not_counted():
    """正向控制：账号级 principal + 条件**明确指向别的角色** ⇒ 不算授给本角色。

    没有这条，上面那三条反例可以由"把所有账号级 principal 都判红"来满足——那会让任何
    带 `aws:PrincipalArn` 收窄的正常桶策略都误红。
    """
    t = _bucket_policy(
        {"AWS": f"arn:aws:iam::{ACCT}:root"}, ["s3:GetObject"], "*",
        condition={"ArnEquals": {"aws:PrincipalArn":
                                 f"arn:aws:iam::{ACCT}:role/SomeoneElse"}})
    assert package_project_s3_violations(t) == []


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
    # 下面三条是**外部复审提出的**：这些都在 import 时求值，而上一版对
    # FunctionDef/ClassDef 整体跳过，于是全部放行
    ("decorator 里建栈", "@App()\ndef f():\n    pass\n"),
    ("默认参数里建栈", 'def f(x=SiteDeployerStack(None, "S")):\n    pass\n'),
    ("基类里建栈", "class C(App()):\n    pass\n"),
    # 下面四条是**外部复审提出的**：上一版把"类的体不在 import 时执行"写进了注释，
    # 那是**错的事实**；而 app.py 没有 `from __future__ import annotations`，3.12 下
    # annotation 是立即求值的（实测：定义 `def f(x: probe())` 就会调用 probe()）
    ("class body 里直接建栈", "class C:\n    App()\n"),
    ("class body 里赋值建栈", 'class C:\n    s = SiteDeployerStack(None, "S")\n'),
    ("参数 annotation 里建栈", "def f(x: App()):\n    pass\n"),
    ("返回 annotation 里建栈", 'def f() -> SiteDeployerStack(None, "S"):\n    pass\n'),
])
def test_toplevel_side_effect_guard_rejects_each_counterexample(label, src):
    assert module_toplevel_side_effect_violations(src), f"**没红**：{label}"


def test_guard_still_allows_normal_functions_and_classes():
    """正向控制：函数**体**与类**体**里的调用不在 import 时执行，不该被判红。

    没有这条，"把 FunctionDef/ClassDef 整体都walk一遍"这种过度收紧也能让上面那三条
    反例全过——而它会把 app.py 里 `SiteDeployerStack.__init__` 内部的每个
    `cb.Project(...)` 都报成顶层副作用。
    """
    src = ("class SiteDeployerStack:\n"
           "    def __init__(self):\n"
           "        self.p = App()\n"
           "        App().synth()\n"
           "def g():\n"
           "    return SiteDeployerStack()\n")
    assert module_toplevel_side_effect_violations(src) == []


def test_guard_allows_lambda_bodies():
    """正向控制：lambda 的**体**在创建时不求值，不该被判红。

    （它的默认值/annotation 会求值，那部分按函数规则查——见反例清单。）
    """
    assert module_toplevel_side_effect_violations("factory = lambda: App()\n") == []


def test_guard_allows_everything_inside_the_main_guard():
    """正向控制：守卫之内的同样三行必须放行，否则这条守卫会把正确写法也判红。"""
    ok = ('if __name__ == "__main__":\n'
          "    app = App()\n"
          '    SiteDeployerStack(app, "S")\n'
          "    app.synth()\n")
    assert module_toplevel_side_effect_violations(ok) == []


# ── 部署后真机验收共用的两个纯函数 ────────────────────────────────────────
# 它们住在 security_contracts.py（而不是只写在计划的 shell heredoc 里），就是为了能在
# 这里被单测钉住。上一版那两处判据只存在于计划正文，于是"boto3 没建模
# NoSuchBucketPolicy"与"字面比对 Action"这两个 fail-open 一直没人测到。
class _FakeS3:
    def __init__(self, *, policy=None, error_code=None):
        self._policy, self._code = policy, error_code

    def get_bucket_policy(self, Bucket):                    # noqa: N803
        if self._code:
            exc = Exception(f"boom {self._code}")
            exc.response = {"Error": {"Code": self._code}}
            raise exc
        return {"Policy": json.dumps(self._policy)}


def test_bucket_policy_absent_means_empty_statements():
    c = _FakeS3(error_code="NoSuchBucketPolicy")
    assert bucket_policy_statements(c, "b") == []


@pytest.mark.parametrize("code", ["AccessDenied", "Throttling", "InternalError",
                                  "PermanentRedirect"])
def test_bucket_policy_other_errors_are_raised_not_swallowed(code):
    """**这是本轮的一个实测 fail-open**：`s3.exceptions.from_code("NoSuchBucketPolicy")`

    在当前 boto3 里返回的就是通用 `ClientError`，于是那种 except 会把 AccessDenied、
    限流等全部解释成"桶没有策略"，验收继续绿。
    """
    c = _FakeS3(error_code=code)
    with pytest.raises(Exception) as ei:
        bucket_policy_statements(c, "b")
    assert code in str(ei.value)


def test_bucket_policy_returns_statements():
    c = _FakeS3(policy={"Statement": [{"Effect": "Allow"}]})
    assert bucket_policy_statements(c, "b") == [{"Effect": "Allow"}]


PROJECT_ARN = f"arn:aws:codebuild:us-east-1:{ACCT}:project/site-package"
_EXACT = {"Statement": [{"Effect": "Allow",
                         "Action": ["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                         "Resource": PROJECT_ARN}]}


def test_action_resource_exact_set_passes():
    assert action_resource_violations([_EXACT], "codebuild:StartBuild",
                                      {PROJECT_ARN}) == []


def test_unrelated_wildcard_resource_statement_is_not_flagged():
    """正向控制：与该动作无关的 `Resource: "*"` 语句（例如 logs）不该被误报。"""
    docs = [_EXACT, {"Statement": [{"Effect": "Allow", "Action": "logs:PutLogEvents",
                                    "Resource": "*"}]}]
    assert action_resource_violations(docs, "codebuild:StartBuild", {PROJECT_ARN}) == []


@pytest.mark.parametrize("label,st", [
    ("codebuild:* on *", {"Effect": "Allow", "Action": "codebuild:*", "Resource": "*"}),
    ("裸 * on *", {"Effect": "Allow", "Action": "*", "Resource": "*"}),
    ("codebuild:Start* 通配", {"Effect": "Allow", "Action": "codebuild:Start*",
                               "Resource": PROJECT_ARN}),
    ("Allow + NotAction", {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}),
    ("换成别的项目 ARN", {"Effect": "Allow", "Action": "codebuild:StartBuild",
                          "Resource": "arn:aws:codebuild:us-east-1:1:project/other"}),
    # 下面三条是**外部复审提出的**：AWS 的 IAM 合同规定服务前缀与动作名都**不区分
    # 大小写**（`iam:ListAccessKeys` == `IAM:listaccesskeys`），而 `fnmatchcase`
    # 会把它们整条漏掉
    ("CODEBUILD:* 全大写前缀", {"Effect": "Allow", "Action": "CODEBUILD:*",
                                "Resource": "*"}),
    ("CodeBuild:StartBuild 驼峰前缀", {"Effect": "Allow",
                                       "Action": "CodeBuild:StartBuild",
                                       "Resource": "*"}),
    ("codebuild:startbuild 全小写", {"Effect": "Allow",
                                     "Action": "codebuild:startbuild",
                                     "Resource": "*"}),
])
def test_action_resource_rejects_each_counterexample(label, st):
    """外部复审提出的三条（`codebuild:*` / 裸 `*` / `NotAction`）逐字纳入。

    字面比对 Action 时它们全部漏掉——因为危险授权根本没进入被比较的集合。
    """
    docs = [_EXACT, {"Statement": [st]}]
    assert action_resource_violations(docs, "codebuild:StartBuild",
                                      {PROJECT_ARN}), f"**没红**：{label}"


# ── `aws:PrincipalArn` 条件要按**算子各自的语义**比 ──────────────────────
# 外部复审的最后一条：把算子丢掉、统一用 `v in principal_ids` 比，就是大小写敏感的，
# 而 AWS 的 `StringEqualsIgnoreCase` 不敏感 ⇒ `ARN:AWS:IAM::…:ROLE/MYROLE` 明明命中
# 本角色却被当成"明确指向其它身份"跳过（实测 hit=False，一条 false-green）。
# 同一分支还有 policy variable：`${aws:PrincipalArn}` 既不含通配也不等于角色 ARN，
# 于是也被当成"明确不匹配"——任何 `${…}` 都必须 fail-closed。
_ME = "arn:aws:iam::000000000000:role/MyRole"


def _cond_stmt(op: str, val: str) -> dict:
    return {"Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
            "Action": "s3:GetObject", "Resource": "*",
            "Condition": {op: {"aws:PrincipalArn": val}}}


@pytest.mark.parametrize("label,op,val,want_hit,want_note", [
    # 外部复审点名的四条
    ("IgnoreCase 大小写不同但指向本角色", "StringEqualsIgnoreCase",
     "ARN:AWS:IAM::000000000000:ROLE/MYROLE", True, False),
    ("IgnoreCase 明确指向别的角色（不该误红）", "StringEqualsIgnoreCase",
     "arn:aws:iam::000000000000:role/OTHER", False, False),
    ("policy variable 必须 fail-closed", "StringEquals",
     "${aws:PrincipalArn}", True, True),
    ("ArnEquals 精确指向本角色（回归）", "ArnEquals", _ME, True, False),
    # 顺带钉住其余算子分支
    ("ArnEquals 指向别的角色", "ArnEquals",
     "arn:aws:iam::000000000000:role/Other", False, False),
    ("ArnLike 带通配 → fail-closed", "ArnLike",
     "arn:aws:iam::000000000000:role/*", True, True),
    ("ArnLike 无通配指向本角色 → 精确比", "ArnLike", _ME, True, False),
])
def test_principal_arn_condition_is_compared_per_operator(label, op, val,
                                                          want_hit, want_note):
    hit, notes = grants_to_principal(_cond_stmt(op, val), {_ME})
    assert hit is want_hit, f"{label}: hit={hit}，期望 {want_hit}"
    assert bool(notes) is want_note, f"{label}: notes={notes}，期望有 note={want_note}"
