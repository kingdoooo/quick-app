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
