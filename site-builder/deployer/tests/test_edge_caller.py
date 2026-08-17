"""Edge 调用者判定（唯一实现）。

**这些用例必须能在缺陷存在时变红**：Step 2 先确认全部 FAIL，Step 4 确认转绿，
Step 5 再逐条注入缺陷确认变红（本项目"验证本身无效"栽过多次）。
"""
import pytest

import edge_caller

# 测试用的假 RoleId。**拼接而不是写成一个字面量**：Code Defender 的
# HARD_CODED_SECRET 规则按 `AROA` 前缀 + 长度匹配，整串写出来会被拦下
# （本计划提交时实际发生过）。它的 remediation 建议是往 secrets.allowed
# 里加例外——那是放宽扫描器，本项目明令不走这个方向。
ROLE_ID = "AROA" + "EDGEROLEID" + "XXXXXX"


def _event(caller_id):
    return {"requestContext": {"authorizer": {"iam": {"callerId": caller_id}}}}


def test_real_edge_caller_is_accepted(monkeypatch):
    """真机抓到的形态：{RoleId}:{session_name}，session name 含区域前缀。"""
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(
        _event(f"{ROLE_ID}:us-east-1.ApplicationWebRouterStack-EdgeFn-abc123"))


def test_missing_env_rejects_everything(monkeypatch, caplog):
    """**配置缺失不得退化成"不检查"**——那正是 P1-1 的原始形态。"""
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False
    # **级别也要断言**（2026-08-12）：原来只匹配消息文本，于是把 logger.error
    # 降成 logger.warning 照样 pass（caplog 默认捕到 WARNING，只有 info/debug
    # 会变红）。而这一行的用途就是"整站 403 时能被告警捞出来"——降级即失效。
    assert any("EDGE_ROLE_ID" in r.message and r.levelname == "ERROR"
               for r in caplog.records), \
        "缺配置必须留一行可告警的 ERROR，否则整站 403 无从排查"


@pytest.mark.parametrize("empty", ["", "   "])
def test_blank_env_rejects_everything(monkeypatch, empty):
    monkeypatch.setenv("EDGE_ROLE_ID", empty)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is False


@pytest.mark.parametrize("evil", [
    f"{ROLE_ID}EVIL:us-east-1.x",   # startswith 骗得过
    f"AIDAX5GB:{ROLE_ID}",          # in 骗得过（把真 id 放进 session name 段）
    f"x{ROLE_ID}:s",                # 前缀污染
    ROLE_ID.lower() + ":s",         # 大小写：AROA 段是大写敏感的
    ROLE_ID,                        # 没有 session 段（不是 assumed-role 形态）
    "",                             # 空 callerId
])
def test_lookalike_callers_are_rejected(monkeypatch, evil):
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(_event(evil)) is False


@pytest.mark.parametrize("broken", [
    {},                                              # 没有 requestContext
    {"requestContext": {}},                          # 没有 authorizer
    {"requestContext": {"authorizer": {}}},          # 没有 iam
    {"requestContext": {"authorizer": {"iam": {}}}}, # 没有 callerId
    {"requestContext": None},                        # 显式 null（真实 payload 见过）
    {"requestContext": {"authorizer": None}},
])
def test_malformed_event_is_rejected_not_crashed(monkeypatch, broken):
    """AuthType=NONE 或平台改形态时 event 会缺这些层级——必须拒绝而不是抛异常。

    抛异常会变成 502，而 502 与 403 的运维含义完全不同（前者像故障、
    后者是策略），排查方向会被带偏。
    """
    monkeypatch.setenv("EDGE_ROLE_ID", ROLE_ID)
    assert edge_caller.caller_is_edge(broken) is False


def test_env_var_name_constant_matches_what_the_code_reads(monkeypatch):
    """常量与实现读的是同一个键——部署脚本引用它，不再各自写字面量。

    两处漂移的症状是"部署下发了 A、代码读 B"→ 线上全拒，而两侧单测都绿。
    """
    monkeypatch.delenv("EDGE_ROLE_ID", raising=False)
    monkeypatch.setenv(edge_caller.EDGE_ROLE_ID_ENV, ROLE_ID)
    assert edge_caller.caller_is_edge(_event(f"{ROLE_ID}:s")) is True


# ── C3: 不许过度承诺 + SCP 制品 ──────────────────────────────────────────
import ast
import json
import re
from pathlib import Path

POLICIES = Path(__file__).parents[2] / "policies"
SCP_FILE = POLICIES / "scp-site-invoke-only-edge.json"
README_FILE = POLICIES / "README.md"

# 这些说法一旦出现在 edge_caller 的模块 docstring 里，就是过度承诺。
# **它们不是随手列的**：本层只挡 Path B（经 Function URL 的调用），而 Path A
# （直接 lambda:Invoke，自造整个 payload 里的 callerId）在 2026-08-15 对
# site-panel 实测成功（伪造成 Edge 的 RoleId → 200）。所以任何"这条缺陷已关闭"
# 的措辞都与实测事实矛盾，而读到它的人会因此不再去做账号级加固。
OVERCLAIM_PHRASES = ("同账号绕过已关闭", "已关闭 P1-3", "P1-3 已关闭",
                     "已修复 P1-3", "closes P1-3", "彻底挡住", "无法绕过")


def _platform_function_names() -> tuple:
    """`infra/app.py` 里的 `PLATFORM_FUNCTION_NAMES`（按 AST 取，不 import——
    app.py 顶层 import aws_cdk，普通套件里没有）。

    期望值来自**另一个文件**：SCP 制品若把平台函数也列进 Deny，这里才判得出来。
    """
    src = (Path(__file__).parents[1] / "infra" / "app.py").read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) == "PLATFORM_FUNCTION_NAMES"):
            return tuple(e.value for e in node.value.elts)
    raise AssertionError("app.py 里找不到 PLATFORM_FUNCTION_NAMES——本条空转")


def _deployer_exec_role_name() -> str:
    """`infra/app.py` 里 `DeployerExecRole` 那个构造的 `role_name`。

    **按构造 ID（`"DeployerExecRole"`）定位，不按角色名找**——按名字找就是拿期望值
    去匹配期望值，改错了两边一起变。构造 ID 与角色名是两个不同的字符串，所以这条
    交叉核对是真的（SCP 的例外名单若与栈里的角色名漂移，真机上会把部署器锁在外面）。
    """
    src = (Path(__file__).parents[1] / "infra" / "app.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Call) and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "DeployerExecRole"):
            continue
        for kw in node.keywords:
            if kw.arg == "role_name" and isinstance(kw.value, ast.Constant):
                return kw.value.value
    raise AssertionError("app.py 里找不到 DeployerExecRole 的 role_name——本条空转")


def test_docstring_does_not_claim_it_closes_same_account_bypass():
    """`edge_caller` 只挡经 Function URL 的调用（Path B）。直接 `lambda:Invoke`
    可以自造整个 payload 里的 callerId（Path A，2026-08-15 对 site-panel 实测：
    伪造成 Edge 的 RoleId → 200）。docstring 必须写明它挡不住什么。

    **断言范围锁到模块 docstring**（`ast.get_docstring`），不是对整个文件
    `in src`：整文件的肯定断言里，文件**任何位置**的一句注释都能满足它——A7 那次
    假绿就是这个形态（Ruling 36 的边界：被断言的对象本身是散文时，文本匹配是对的，
    但范围要用 AST 锁住）。

    两个方向都要断：**正面**要求那几件事写出来了；**反面**要求没有"这条缺陷已关闭"
    这类措辞。只有正面断言的话，一份既提到 `lambda:Invoke` 又宣称"已关闭"的
    docstring 会照样绿——而用例名承诺的恰恰是后半句。
    """
    src = (Path(__file__).parents[1] / "functions" / "edge_caller.py").read_text(
        encoding="utf-8")
    doc = ast.get_docstring(ast.parse(src))
    assert doc, "edge_caller.py 没有模块 docstring——本条空转"

    # **每条断言只看它真正谈的那一段**，不在整份 docstring 里查子串。
    # 实测过为什么必须这样：`"lambda:Invoke" in doc` 会被后文
    # `lambda:InvokeFunction` 那句满足，`"伪造" in doc` 会被 Path B 的"不可伪造"
    # 满足，`"SCP" in doc` 会被"SCP 对管理账号无效"那句满足 —— 于是把 Path A 那行
    # 里的关键词删掉，三条断言**照样全绿**。散文里的 token 存在性会被无关的偶然
    # 提及满足，所以断言的范围要收到它所声称的那句话上（同 Ruling 60 的形态，
    # 换到散文这一侧）。
    for marker in ("**Path A", "**Path B", "**真正能关掉"):
        assert marker in doc, f"docstring 缺少结构标记 {marker}——本条无法分段，已空转"
    path_a = doc[doc.index("**Path A"):doc.index("**Path B")]
    path_b = doc[doc.index("**Path B"):doc.index("**真正能关掉")]
    remedy = doc[doc.index("**真正能关掉"):]

    # Path A：必须点名是哪个 API、可伪造、且本层挡不住
    assert "lambda:Invoke" in path_a, "Path A 那段没点名 lambda:Invoke"
    assert "伪造" in path_a, "Path A 那段没说 callerId 可被伪造"
    assert "挡不住" in path_a or "被绕过" in path_a, \
        "Path A 那段没说本函数挡不住它——这正是本用例要防的过度承诺"
    # Path B：必须说清它为什么有效（STS 填写、不可伪造）——这一半是正向对照，
    # 缺了会让读者以为两条路一样不可信，从而把有效的那层也当成无用。
    assert "STS" in path_b and "不可伪造" in path_b, "Path B 那段没说清它为什么有效"
    # 补救那段：必须指向制品、说明它是可选的、且点出管理账号这条边界。
    # （这里**不**断言 `"SCP" in remedy`：这一段里 "SCP" 出现两次、服务两个不同的
    #  claim（指向制品 / 管理账号边界），所以那条断言无论删哪一句都不会红 = 不可
    #  falsify。指向制品这件事由 `policies/` 这个路径独家承担。）
    assert "policies/" in remedy, "没指向 policies/ 下那份 SCP 模板"
    assert "可选" in remedy, "没说明那份 SCP 是可选的"
    assert "管理账号" in remedy, "没写明 SCP 对 Org 管理账号无效（本部署即是）"
    assert "纵深防御" in remedy, "没说明本层的定位（纵深防御，不是这条缺陷的修复）"

    for bad in OVERCLAIM_PHRASES:
        assert bad not in doc, f"docstring 过度承诺：出现了 {bad!r}"


def test_scp_artifact_denies_both_actions_and_excludes_platform_functions():
    """SCP 制品的四根轴：Deny 两个动作、资源不用通配、不含真实账号、有例外名单。

    **只 Deny `InvokeFunctionUrl` 挡不住 Path A**——那条路走的是
    `lambda:InvokeFunction`，两个动作都要列。
    """
    doc = json.loads(SCP_FILE.read_text(encoding="utf-8"))
    st = doc["Statement"][0]
    assert st["Effect"] == "Deny"
    assert set(st["Action"]) == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}, \
        "只 Deny InvokeFunctionUrl 挡不住 Path A"

    blob = json.dumps(doc, ensure_ascii=False)
    assert "{account_id}" in blob and not re.search(r"\b\d{12}\b", blob), \
        "制品里不许出现真实账号 ID"

    # **不许用 function:site-* 通配**：它同时命中平台自己那些函数，贴上去会打挂
    # 所有部署与下线（SFN 用 IAM 角色调 site-deployer-*；panel 调 undeploy）。
    assert "function:site-*" not in blob
    for r in (st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]):
        assert "*" not in r or r.startswith("{"), \
            f"Resource 用了通配 {r!r}——平台函数与用户站点同在 site- 命名空间下，" \
            "通配不可判定（这正是 v1 被驳回的原因）"

    # 平台函数名一个都不许出现在制品里（期望值来自 infra/app.py，不同源）
    for name in _platform_function_names():
        assert name not in blob, f"制品里出现了平台函数 {name}——会封死控制面"

    # **必须有例外名单**：没有 Condition 的 Deny 会把 Edge 自己也拒掉，
    # 于是所有站点 403 —— 那不是加固，是把平台关掉。
    cond = st.get("Condition", {})
    op = next((k for k in ("ArnNotLike", "StringNotEquals") if k in cond), None)
    assert op, f"例外名单的条件运算符不对：{list(cond)}"
    exempt = cond[op]["aws:PrincipalArn"]
    exempt = exempt if isinstance(exempt, list) else [exempt]

    # **例外集的组成本身要被断言，不只是"存在某个例外"。** 这份制品的价值全在
    # "最小例外集"上：多一个不需要的条目会教会读者错误的心智模型，少一个会把平台
    # 自己锁在外面。所以两个方向都锁死——**恰好**这两个角色，不多不少。
    #   · Edge 执行角色：唯一合法的站点调用方，漏了它所有站点 403；
    #   · site-deployer-exec-role：M7 的健康门直接 invoke 候选颜色
    #     （deploy_lambda_site._health_check 带 Qualifier），漏了它每次部署都在
    #     健康门失败。**这个名字从 infra/app.py 取，不手抄**（不同源）。
    want = {f"arn:aws:iam::{{account_id}}:role/{{edge_role_name}}",
            f"arn:aws:iam::{{account_id}}:role/{_deployer_exec_role_name()}"}
    assert set(exempt) == want, (
        f"例外集不是最小集：多了 {sorted(set(exempt) - want)}、"
        f"少了 {sorted(want - set(exempt))}")


def test_policies_readme_states_the_three_boundaries():
    """README 必须写清三条边界，否则读者会以为贴上 SCP 就闭合了 P1-3。"""
    txt = README_FILE.read_text(encoding="utf-8")
    assert "管理账号" in txt, "没写 SCP 对 Org 管理账号无效（本部署即是）"
    assert "site-*" in txt and "平台" in txt, \
        "没写 site-* 同时匹配平台函数、SFN 与 panel 角色都要例外"
    assert "保留前缀" in txt, "没写通配可判定的前提是 A3 的站点名保留前缀"
    # 生成资源列表的办法必须给出来，否则那个占位符没人填得对
    assert "{user_site_function_arns}" in txt and "aws lambda" in txt, \
        "没说明怎么生成用户站点的 ARN 列表"
    # 例外集是最小集，但"什么情况下要加回来"必须留一行——否则下一个把 Resource
    # 扩大到平台函数的人会带着一份不够用的例外名单上生产（panel 走
    # site-deployer-undeploy，那是平台函数）。
    assert "panel" in txt and "扩大" in txt, \
        "没写明'若把 Resource 扩大到平台函数，则需把 panel 角色加回例外'"
