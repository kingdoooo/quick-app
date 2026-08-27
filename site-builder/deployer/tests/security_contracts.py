"""安全合同的结构化检查器——**只依赖标准库**，被 always-on、opt-in 与部署后验收共用。

每个检查器都是「吃结构化输入、吐违规列表」的纯函数，于是反例可以在**内存里**注入：
不改工作树、不需要另一个 harness、跑在默认套件里。

为什么是**精确 allowlist** 而不是"没出现某个已知坏值"：黑名单守卫的主语总比它的证据
宽。实测过一份策略——两条精确授权都在、另加 `s3:GetObject` + `s3:ListBucket` on `*`
——而"策略里没有 bootstrap 桶"那种断言照样通过。这与 `_package_project_resources()`
只看见"手写的那一半"是同一个错误。

**这个错误在本轮被外部复审抓到过三轮，每轮都是"枚举范围比声称的主语窄"**：
① 只看源码手写的语句，漏 CDK 自动加的；② 只看"含某个子串"，漏 `--ignore-scripts=false`
之类语义翻转；③ 只看首 token 是 `npm` 的命令，漏 `env npm rebuild` / `sh -c '…'`；
④ 只看 identity policy，漏 `AWS::S3::BucketPolicy`。所以现在的写法一律是
**把完整集合与精确期望比等值**，而不是逐个排除已知坏形态。
"""
import fnmatch
import json
import re
import shlex

# ── buildspec：命令合同 ────────────────────────────────────────────────────
_SEPARATORS = ("&&", "||", ";", "|")
# **精确 token 列表**，不是"含某个子串"：加一个 `--ignore-scripts=false` 或
# `--no-ignore-scripts` 都能把语义翻过来，而"含 --ignore-scripts"照样绿。
EXPECT_NPM_INSTALL = ["npm", "install", "--omit=dev", "--no-audit", "--no-fund",
                      "--ignore-scripts"]
EXPECT_NPMRC_DELETE = ["find", "/tmp/site", "-name", ".npmrc", "-delete"]

# **整条命令序列的 allowlist。** 只判"有没有别的 npm 子命令"是不够的——实测
# `env npm rebuild`、`sh -c 'npm rebuild'`、`/usr/bin/npm rebuild` 三种写法的首 token
# 都不是 `npm`，于是那条判据全部放行。枚举 wrapper 是打地鼠（还有 `npx`、`node -e`、
# `bash -lc`…），所以改成整体等值：buildspec 只有 12 条固定命令，任何新增/改写/换序
# 都必须显式更新本清单并重新过一次 review。
#
# 两条隔断（`EXPECT_NPMRC_DELETE` 在 `EXPECT_NPM_INSTALL` **之前**）由这份清单的
# 顺序本身保证；单独那几条判据留着只是为了报文能点名是哪条隔断坏了。
EXPECTED_COMMANDS: list[list[str]] = [
    ["aws", "s3", "cp",
     "s3://$ARTIFACTS_BUCKET/validated/$JOB_ID/backend-src.zip", "/tmp/site.zip"],
    ["mkdir", "-p", "/tmp/site"],
    ["cd", "/tmp/site"],
    ["unzip", "-q", "/tmp/site.zip"],
    ["test", "-f", "/tmp/site/run.sh"],
    EXPECT_NPMRC_DELETE,
    ["cd", "/tmp/site/backend"],
    EXPECT_NPM_INSTALL,
    ["cp", "/tmp/site/run.sh", "./run.sh"],
    ["chmod", "+x", "./run.sh"],
    ["zip", "-qr", "/tmp/backend.zip", "."],
    ["aws", "s3", "cp", "/tmp/backend.zip",
     "s3://$ARTIFACTS_BUCKET/artifacts/$JOB_ID/backend.zip"],
]


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
    """构建容器的两条隔断 + **整条命令序列**必须与 `EXPECTED_COMMANDS` 等值。"""
    cmds, out = _buildspec_commands(src)
    if out:
        return out
    # ① 先给两条隔断单独的报文（整体等值也能抓到，但报文说不出坏的是哪条隔断）
    installs = [(i, c) for i, c in enumerate(cmds)
                if c[:2] == ["npm", "install"]]
    if len(installs) != 1:
        out.append(f"buildspec 里有 {len(installs)} 条 `npm install`（必须恰好 1 条）")
    else:
        i_npm, install = installs[0]
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
    # ② 整体等值：任何新增命令（含 `env npm rebuild` / `sh -c '…'` / `npx` / `node -e`
    #    这类绕过首 token 判据的 wrapper）都在这里红
    if cmds != EXPECTED_COMMANDS:
        extra = [c for c in cmds if c not in EXPECTED_COMMANDS]
        missing = [c for c in EXPECTED_COMMANDS if c not in cmds]
        out.append(f"命令序列与安全合同不等值（共 {len(cmds)} 条，期望 "
                   f"{len(EXPECTED_COMMANDS)} 条）。\n      多出: {extra}\n"
                   f"      缺少: {missing}\n"
                   f"      （整体等值是刻意的：只判「有没有别的 npm 子命令」时，"
                   f"`env npm rebuild` / `sh -c 'npm rebuild'` / `/usr/bin/npm rebuild` "
                   f"全部放行——枚举 wrapper 是打地鼠。合法改动请显式更新 "
                   f"EXPECTED_COMMANDS 并重新过 review。）")
    return out


# ── `app.py` 的 import 必须无副作用 ───────────────────────────────────────
# 只找 `app.synth()` 是不够的：把 `app = App()` 与 `SiteDeployerStack(...)` 放回顶层、
# 只把 `synth()` 留在守卫里，import 一样会建栈（实测那种写法下旧判据 bad=[]）。
_FORBIDDEN_TOPLEVEL_CALLS = ("App", "SiteDeployerStack", "synth")


def _is_main_guard(node) -> bool:
    import ast
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    left, ops, comps = node.test.left, node.test.ops, node.test.comparators
    return (isinstance(left, ast.Name) and left.id == "__name__"
            and len(ops) == 1 and isinstance(ops[0], ast.Eq)
            and isinstance(comps[0], ast.Constant) and comps[0].value == "__main__")


def module_toplevel_side_effect_violations(src: str) -> list[str]:
    """模块顶层（`if __name__ == "__main__":` 之外）不许建栈或 synth。

    没有这条守卫时 `import app` 就 synth 整个栈并触发 Lambda bundling，于是任何想
    import 该模块的单测都被迫依赖 Docker。判据取**源码结构**——真去 import 一次反而
    会把这条守卫本身变成需要 Docker 的用例。
    """
    import ast
    out = []
    for node in ast.parse(src).body:
        if _is_main_guard(node):
            continue                       # 守卫之内是允许的
        # 函数/类的**体**不在 import 时执行，但 decorator、默认值、基类**会**。
        # 上一版对 FunctionDef/ClassDef 整体 `continue`，于是 `@App()`、
        # `def f(x=SiteDeployerStack(...))`、`class C(App())` 全部放行——又是一次
        # "主语（import 时会不会建栈）比枚举范围宽"（外部复审第四条）。
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            roots = (list(node.decorator_list) + list(node.args.defaults)
                     + [d for d in node.args.kw_defaults if d is not None])
        elif isinstance(node, ast.ClassDef):
            roots = (list(node.decorator_list) + list(node.bases)
                     + [k.value for k in node.keywords])
        else:
            roots = [node]
        for root in roots:
            for sub in ast.walk(root):
                if not isinstance(sub, ast.Call):
                    continue
                name = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
                if name in _FORBIDDEN_TOPLEVEL_CALLS:
                    out.append(f"模块顶层第 {sub.lineno} 行（import 时求值）调用了 "
                               f"{name}(...)——会建栈/synth，必须挪进 "
                               f'`if __name__ == "__main__":`')
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


def s3_permission_violations(docs: list[dict], expected: set[tuple[str, str]], *,
                            where: str = "策略") -> list[str]:
    """一组策略文档里 `Effect=Allow` 的 S3 `(action, resource)` 全集必须**等于** `expected`。

    **共享给三个调用点**：手写模板 fixture、真 synth 模板、以及部署后的真机文档
    （后者的 Resource 是已解析的 ARN 字符串，`render_token` 原样返回）。三处用同一个
    规范化与比较逻辑，是因为上一版的部署后确认自己拼了一套字符串 grep，而那套判据
    已经被"两条精确授权都在 + `s3:GetObject` on `*`"证明可绕过。

    以下形态**直接判违规、不求值**：`NotAction`/`NotResource`、`Resource:"*"`、
    任何带 `*` 的 S3 动作（含 `s3:*` / `s3:GetObject*` / 裸 `*`）、`render_token`
    不认识的 CloudFormation 形态。
    """
    out: list[str] = []
    got: set[tuple[str, str]] = set()
    for doc in docs:
        for st in doc.get("Statement") or []:
            if "NotAction" in st or "NotResource" in st:
                out.append(f"{where}里有语句用了 NotAction/NotResource（不做集合求补）："
                           f"{json.dumps(st, ensure_ascii=False)[:90]}")
                continue
            if st.get("Effect") != "Allow":
                continue
            acts = [a for a in _as_list(st.get("Action") or []) if isinstance(a, str)]
            s3 = [a for a in acts if a == "*" or a.lower().startswith("s3:")]
            if not s3:
                continue
            wild = [a for a in s3 if "*" in a]
            if wild:
                out.append(f"{where}里 S3 动作有通配 {wild}——精确 allowlist 不接受通配动作")
            try:
                rs = [render_token(x) for x in _as_list(st.get("Resource"))]
            except Unrenderable as exc:
                out.append(f"{where}里 Resource 有不认识的 CloudFormation 形态：{exc}")
                continue
            if any(r == "*" for r in rs):
                out.append(f"{where}里有 S3 语句的 Resource 是 `*`（动作 {s3}）")
            for a in s3:
                for r in rs:
                    got.add((a, r))
    if got != expected:
        out.append(f"{where}的 S3 权限全集与精确 allowlist 不符。\n"
                   f"      多出: {sorted(got - expected)}\n"
                   f"      缺少: {sorted(expected - got)}")
    return out


# 账号级 principal（裸账号 ID 或 `…:root`）**不等于"与本角色无关"**：常见写法是
# `Principal: {"AWS": "<acct>:root"}` + `Condition: {ArnEquals: {aws:PrincipalArn: <role>}}`,
# 它实际就指向那个角色。只比对 Principal.AWS 是否字面等于角色 ARN 会整条漏掉。
_ACCOUNT_ROOT_RE = re.compile(r"^(?:\d{12}|arn:aws[\w-]*:iam::\d{12}:root)$")
# 只有这些**正向**算子能把账号级 principal 收窄到具体身份；Not* 与不认识的算子一律
# fail-closed（当成可能授给本角色并报违规）。
_PRINCIPAL_ARN_OPS = ("ArnEquals", "ArnLike", "StringEquals", "StringLike",
                      "StringEqualsIgnoreCase")


def _principal_arn_condition(st: dict) -> tuple[list[str] | None, list[str]]:
    """从 Condition 里取 `aws:PrincipalArn` 的取值集合。

    返回 `(值列表 或 None, 说明)`。`None` = 没有可用于收窄的条件（调用方按最坏情况处理）。
    """
    cond = st.get("Condition")
    if not isinstance(cond, dict):
        return None, []
    notes: list[str] = []
    vals: list[str] = []
    for op, kv in cond.items():
        if not isinstance(kv, dict):
            return None, [f"Condition 的 {op} 不是对象，无法判定"]
        for key, raw in kv.items():
            if key.lower() != "aws:principalarn":
                continue
            if op not in _PRINCIPAL_ARN_OPS:
                return None, [f"aws:PrincipalArn 用了 {op}（Not* 或不认识的算子），"
                              f"守卫不求值，按最坏情况处理"]
            for x in _as_list(raw):
                try:
                    vals.append(render_token(x))
                except Unrenderable as exc:
                    return None, [f"aws:PrincipalArn 的值形态不认识：{exc}"]
    return (vals or None), notes


def grants_to_principal(st: dict, principal_ids: set[str]) -> tuple[bool, list[str]]:
    """这条 resource-policy 语句是否授给了 `principal_ids` 里的某个身份（或所有人）。

    **公开**（不带下划线）是因为部署后的真机验收也要用它：那时 `principal_ids` 传的是
    已解析的角色 ARN，而模板检查器传的是 `<GetAtt:…>` / `<Ref:…>` 形态。两处共用同一个
    判据，才不会像上一版那样在真机侧又长出一套更弱的字符串 grep。

    **不认识的 Principal 形态 fail-closed**（当成"授给了"并报违规）：猜错的方向
    永远是"看起来合格"。
    """
    p = st.get("Principal")
    if p == "*":
        return True, []
    if not isinstance(p, dict):
        return True, [f"Principal 形态不认识（{json.dumps(p, ensure_ascii=False)[:60]}），"
                      f"守卫按最坏情况当成授给了本角色"]
    unknown = sorted(set(p) - {"AWS", "Service", "Federated", "CanonicalUser"})
    if unknown:
        return True, [f"Principal 里有不认识的键 {unknown}，按最坏情况处理"]
    account_level = False
    for raw in _as_list(p.get("AWS") or []):
        if raw == "*":
            return True, []
        try:
            rendered = render_token(raw)
        except Unrenderable as exc:
            return True, [f"Principal.AWS 里有不认识的形态：{exc}，按最坏情况处理"]
        if rendered in principal_ids:
            return True, []
        if _ACCOUNT_ROOT_RE.match(rendered):
            account_level = True
    if not account_level:
        return False, []
    # 账号级 principal：由 `aws:PrincipalArn` 条件决定它实际指向谁
    vals, notes = _principal_arn_condition(st)
    if vals is None:
        return True, notes or ["Principal 是账号级（裸账号 ID / `:root`）且没有可判定的 "
                               "`aws:PrincipalArn` 条件——按最坏情况当成授给了本角色"]
    if any(("*" in v or "?" in v) for v in vals):
        return True, notes + [f"`aws:PrincipalArn` 条件含通配 {vals}，无法判定是否命中"
                              f"本角色——按最坏情况处理"]
    return (any(v in principal_ids for v in vals)), notes


def package_project_s3_violations(tpl: dict) -> list[str]:
    """`site-package` 角色的 **S3 权限全集**必须精确等于两条。

    覆盖角色的**全部**模板内权限来源：inline `Policies`、`AWS::IAM::Policy`、
    `AWS::IAM::ManagedPolicy`、`ManagedPolicyArns`，**以及 `AWS::S3::BucketPolicy`**
    ——只收 identity policy 时，一条把 `s3:*` on `*` 授给本角色的桶策略能让整个断言
    照样绿（实测）。这与 `_package_project_resources()` 只看见"手写的那一半"同源。

    **不覆盖**：本 stack 之外的 resource policy，尤其是 **CDK bootstrap 桶自己的桶策略**
    （它不在这份模板里）。那条通道由 `verify_account_trust_boundary.py` 的
    bucket-policy 快照负责——本检查器不假装覆盖它。
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
        return out + ["没找到该角色的任何 identity policy——定位逻辑失效了"]

    # 桶策略：只把**授给本角色（或所有人）**的语句纳入权限集合。
    # 本 stack 里今天有一条 `ArtifactsPolicy`，Principal 是 auto-delete 自定义资源的
    # 角色 ⇒ 与本角色无关、正确地被跳过（若把"任何桶策略"都算进来会立刻误红）。
    me = {f"<GetAtt:{lid}.Arn>", f"<Ref:{lid}>"}
    for r in res.values():
        if r["Type"] != "AWS::S3::BucketPolicy":
            continue
        for st in r["Properties"]["PolicyDocument"].get("Statement") or []:
            if st.get("Effect") != "Allow":
                continue
            hit, notes = grants_to_principal(st, me)
            out += notes
            if hit:
                docs.append({"Statement": [st]})

    buckets = [b for b, r in res.items()
               if r["Type"] == "AWS::S3::Bucket"
               and isinstance(r["Properties"].get("BucketName"), str)
               and r["Properties"]["BucketName"].startswith("site-artifacts-")]
    if len(buckets) != 1:
        return out + [f"site-artifacts 桶没唯一定位到（{buckets}）"]
    art = buckets[0]
    expected = {("s3:GetObject", f"<GetAtt:{art}.Arn>/validated/*"),
                ("s3:PutObject", f"<GetAtt:{art}.Arn>/artifacts/*")}
    return out + s3_permission_violations(docs, expected, where="PackageProject 角色")


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


# ── 部署后真机验收共用的两个纯函数 ────────────────────────────────────────
def bucket_policy_statements(s3_client, bucket: str) -> list[dict]:
    """读桶策略。**只有 `NoSuchBucketPolicy` 才算"没有策略"**，其它错误原样抛。

    **不要写 `except s3.exceptions.from_code("NoSuchBucketPolicy")`**：boto3 的 S3
    service model 没有建模这个异常，`from_code` 实测返回的就是通用
    `botocore.exceptions.ClientError` ⇒ 那条 except 会把 `AccessDenied`、限流、
    错账号等**全部**静默解释成"桶没有策略"，验收随后继续绿。这是 fail-open。

    这里刻意不 import botocore：按 `response["Error"]["Code"]` 判，任何形态不符的异常
    都往外抛（fail-closed）。
    """
    try:
        return json.loads(s3_client.get_bucket_policy(Bucket=bucket)["Policy"]) \
            .get("Statement") or []
    except Exception as exc:                                        # noqa: BLE001
        code = getattr(exc, "response", None)
        code = (code or {}).get("Error", {}).get("Code") if isinstance(code, dict) else None
        if code == "NoSuchBucketPolicy":
            return []
        raise


def action_resource_violations(docs: list[dict], action: str,
                              expected_resources: set[str], *,
                              where: str = "策略") -> list[str]:
    """"能对 `action` 做事的资源集合"必须精确等于 `expected_resources`。

    **按 glob 判覆盖**（`fnmatch`），不是"Action 列表里字面含这个字符串"：
    `codebuild:*`、裸 `*`、`codebuild:Start*` 都覆盖 `codebuild:StartBuild`，而字面
    比对会把它们整条漏掉——那正是上一版这条真机断言的缺陷。`NotAction` 与
    `Resource: "*"` 一律判违规而不求值。

    只看**覆盖该动作**的语句，所以角色上与该动作无关的 `Resource: "*"` 语句
    （例如 logs）不会被误报。
    """
    out: list[str] = []
    got: set[str] = set()
    for doc in docs:
        for st in doc.get("Statement") or []:
            if st.get("Effect") != "Allow":
                continue
            if "NotAction" in st:
                out.append(f"{where}里有 Allow + NotAction 语句（守卫不做集合求补）："
                           f"{json.dumps(st, ensure_ascii=False)[:90]}")
                continue
            acts = [a for a in _as_list(st.get("Action") or []) if isinstance(a, str)]
            if not any(fnmatch.fnmatchcase(action, a) for a in acts):
                continue
            wild = [a for a in acts if "*" in a and fnmatch.fnmatchcase(action, a)]
            if wild:
                out.append(f"{where}里用通配动作 {wild} 覆盖了 {action}"
                           f"——精确 allowlist 不接受通配动作")
            try:
                rs = [render_token(x) for x in _as_list(st.get("Resource"))]
            except Unrenderable as exc:
                out.append(f"{where}里 Resource 形态不认识：{exc}")
                continue
            if any(r == "*" for r in rs):
                out.append(f"{where}里覆盖 {action} 的语句 Resource 是 `*`")
            got |= set(rs)
    if got != expected_resources:
        out.append(f"{where}里能做 {action} 的资源集合不符。\n"
                   f"      多出: {sorted(got - expected_resources)}\n"
                   f"      缺少: {sorted(expected_resources - got)}")
    return out
