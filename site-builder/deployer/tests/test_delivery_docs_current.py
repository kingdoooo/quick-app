"""交付文档的**时效**守卫：面向新账号/新读者的那几份文档不许留过时口径。

守的是采用者会照着做的那几份：`README.md` / `CLAUDE.md` / `CONTEXT.md` /
`site-builder/DEPLOY.md` / `site-builder/docs/client-setup.md` / 建站 Skill 的
`SKILL.md` 与两份 references / `site-builder/scripts/gen_onboarding.py`
—— 它们是"换个人/换个账号照着做"的唯一入口，过时的一行在这里的代价是对方按错的
顺序部署、或按不存在的路径执行。

**另一半方向相反**：`docs/superpowers/` / `docs/reviews/` / `docs/security/` 下的决策
记录**保留**单账号实测数据（那是它们的价值），改为在文件头自报"不是操作指引"
——见本文件末尾 `test_decision_records_declare_their_nature`。ADR 两边都不进
（日期是那个文体固有的）。

**为什么放在 deployer 包里**：仓库根没有 `tests/` 也没有 pytest 配置或 venv，新建一个
根级 `tests/` 会得到一份"没有任何标准命令会跑到"的守卫——那比没有守卫更糟（它占着
"已覆盖"的名分）。deployer 包的调用方式在 CLAUDE.md 的测试命令小节里，而且这里已经有
读 `DEPLOY.md` 的既有用例（`test_infra_tables.py`），路径先例一致。

**断言范围的纪律**（Ruling 70 的两半，方向相反，别搞混）：
  · **肯定断言必须切片到"真正谈这件事的那一节"**。对整份 markdown 做
    `"xxx" in text` 会被文件里任何位置的一句话满足——我在 C3 里踩过三次
    （`"伪造" in doc` 被反义句"不可伪造"满足）。
  · **否定断言反而应该覆盖整个文件**。"全文都不许出现这个过时数字"比"某一节里不许
    出现"更强，切片只会给它留下藏身之处。
"""
import ast
import re

import pytest
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[3]
README = ROOT / "README.md"
CLAUDE_MD = ROOT / "CLAUDE.md"
CONTEXT_MD = ROOT / "CONTEXT.md"
DEPLOY = ROOT / "site-builder" / "DEPLOY.md"
GEN_ONBOARDING = ROOT / "site-builder" / "scripts" / "gen_onboarding.py"
# 采用者会读的另外几份（工单 12 把它们一并纳入状态守卫）
CLIENT_SETUP = ROOT / "site-builder" / "docs" / "client-setup.md"
_SKILL_DIR = ROOT / "site-builder" / "skills" / "site-builder"
SKILL_MD = _SKILL_DIR / "SKILL.md"
SKILL_CONTRACT = _SKILL_DIR / "references" / "contract.md"
SKILL_REDLINES = _SKILL_DIR / "references" / "redlines.md"


def _read(p: Path) -> str:
    assert p.exists(), f"{p} 不存在——本条空转"
    return p.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """从 `heading` 那一行起，到**下一个同级或更高级**标题之前。

    找不到标题就让调用处红：标题被改名时本条会**自报空转**，而不是静默把覆盖面
    缩到零（同 `test_platform_function_name_list_...` 的处理）。

    **必须跟踪围栏代码块**：纯文本上，```bash 块里第 0 列的 `# 注释` 与 markdown
    的 H1 标题长得一模一样，不跟踪围栏就会把前者当成标题、在那里把小节切断。
    实测形态（CLAUDE.md 的「测试命令」那一节把每条命令的解释写成 shell 注释）：
    小节缩到只剩第一条命令，`test_claude_md_test_commands_carry_the_two_measured_traps`
    的四条断言**全部假红**——而文档一个字都没写错。
    替代方案"别在文档的代码块里写 # 注释"是对文档作者的约束，而本文件的存在
    理由正是文档会变；所以修的是解析器。围栏状态先整篇算一次，
    **两个循环都用它**：找标题的那一层同样不能在围栏里认标题。
    """
    lines = text.splitlines()
    fenced, inside = [], False
    for ln in lines:
        if ln.lstrip().startswith("```"):
            fenced.append(True)      # 围栏标记行本身：它不可能是标题
            inside = not inside
        else:
            fenced.append(inside)
    for i, ln in enumerate(lines):
        if fenced[i] or ln.strip() != heading:
            continue
        level = len(ln) - len(ln.lstrip("#"))
        for j in range(i + 1, len(lines)):
            nxt = lines[j]
            if (not fenced[j] and nxt.startswith("#")
                    and (len(nxt) - len(nxt.lstrip("#"))) <= level):
                return "\n".join(lines[i:j])
        return "\n".join(lines[i:])
    raise AssertionError(f"找不到小节 {heading!r}——本条空转（标题被改过？）")


def _blockquote(text: str, marker: str) -> str:
    """从含 `marker` 的那一行起，把连续的 `>` 引用块取完。"""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if marker in ln:
            j = i
            while j < len(lines) and lines[j].lstrip().startswith(">"):
                j += 1
            return "\n".join(lines[i:j])
    raise AssertionError(f"找不到含 {marker!r} 的引用块——本条空转")


def _window(text: str, needle: str, after: int = 6) -> str:
    """含 `needle` 的那一行 + 随后 `after` 行。

    多行的注记（一段解释跨 4-5 行）用单行切片会把理由切掉，于是"有没有写明原因"
    这类断言会假红。窗口是这类散文的正确结构单元。
    """
    lines = text.splitlines()
    hits = [i for i, ln in enumerate(lines) if needle in ln]
    assert hits, f"找不到含 {needle!r} 的行——本条空转"
    i = hits[0]
    return "\n".join(lines[i:i + 1 + after])


def _onboarding_template(src: str) -> str:
    """`gen_onboarding.py` 里**真正写进产物**的那段模板文本（按 AST 取）。

    只取 `OUT.write_text(...)` 的实参，所以源码里的注释一句都进不来——"用户读到的
    东西"与"我在旁边解释这件事的注释"必须分开，否则后者会替前者满足断言。
    """
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "write_text" and node.args):
            continue
        arg = node.args[0]
        if isinstance(arg, ast.JoinedStr):
            return "".join(v.value for v in arg.values
                           if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    raise AssertionError("gen_onboarding.py 里找不到 OUT.write_text(模板)——本条空转")


def _row(text: str, needle: str) -> str:
    """表格里含 `needle` 的那一行（唯一命中，否则红）。"""
    hits = [ln for ln in text.splitlines() if needle in ln]
    assert len(hits) == 1, f"{needle!r} 命中 {len(hits)} 行，无法定位——本条空转"
    return hits[0]


# ── 切片器自身的守卫 ──────────────────────────────────────────────────────

def test_section_does_not_end_at_a_comment_inside_a_fenced_block():
    """`_section` 的**反向验证**：围栏里的 `#` 注释不许被当成标题。

    这条缺陷的危险之处是它**只会假绿或假红，不会报错**：把小节静默缩到第一条
    命令为止，于是这一整套"文档还准不准"的断言要么全部空转、要么在文档完全正确
    时集体变红。两个方向都测——第一行注释不许截断（跟踪围栏），围栏**之后**的
    真标题必须仍然截断（别为了修前者把后者一起关掉）。
    """
    doc = "\n".join([
        "## 目标小节",
        "```bash",
        "# 这是 shell 注释，不是 H1",
        "pytest -q   # 第二条命令",
        "```",
        "尾部散文。",
        "## 下一节",
        "不该被收进来。"])
    sec = _section(doc, "## 目标小节")
    assert "第二条命令" in sec, f"围栏里的 # 注释把小节截断了：{sec!r}"
    assert "尾部散文" in sec, f"围栏闭合后的正文丢了：{sec!r}"
    assert "不该被收进来" not in sec, f"围栏之后的真标题没有截断小节：{sec!r}"


# ── 过时口径：否定断言，覆盖整个文件 ─────────────────────────────────────

def test_readme_status_has_no_stale_numbers_or_date():
    """README 的状态段不许写会过时的数字与日期。

    `154 个单元测试` 与 `2026-07-29` 是一期收尾时的快照；此后每一轮都会让它变假，
    而 README 是外部读者看到的第一段话。数字的正确去处是"跑一遍测试命令"。
    """
    txt = _read(README)
    for stale in ("154 个单元测试", "2026-07-29", "4 个 E2E fixture"):
        assert stale not in txt, f"README 里还留着过时口径 {stale!r}"
    # 目录导览那张表里也曾逐包写死测试数（67/11/30/23…）。它们漂得最厉害——
    # 实测时 deployer 那格写 30 而真实数字是三位数。按**形态**禁掉，不是逐个数字
    # 拉黑：写死一个数字这件事本身就是缺陷，换个数字不该让守卫变绿。
    counts = re.findall(r"（\d+\s*测试）", txt)
    assert not counts, f"README 里还有写死的逐包测试数：{counts}"

    # 肯定断言切到「开发与测试」那一节：它必须给出**可自查**的去处，而不是一个数字。
    # （README 重写为面向公开读者之前，这条切的是 `**资产范围**` 引用块；判据不变——
    # 一个数字换不来自查路径。）
    tests_sec = _section(txt, "## 开发与测试")
    assert "CLAUDE.md" in tests_sec, "「开发与测试」没指向 CLAUDE.md 的测试命令（读者无法自查）"
    # 否定断言覆盖整个文件：README 面向新 clone 的读者，**根本不提** gitignored 的过程
    # 记录。这比旧版"状态段须声明 docs/design 不随仓库分发"更强——旧版允许提、只要求
    # 标注；现在连提都不许，指针类的回归另由 test_delivery_docs_mark_every_undistributed_doc_pointer 兜住。
    for gone in ("docs/design", "HANDOFF"):
        assert gone not in txt, (
            f"README 提到了 {gone!r}，它是 gitignored 的过程记录 ⇒ 新 clone 里不存在")


def test_no_delivery_doc_still_says_phase2_m1_m3():
    """`二期 M1-M3` 是 M4-M7 之前的口径，三份文档里都不许再出现。"""
    for p in (README, CLAUDE_MD, DEPLOY):
        assert "二期 M1-M3" not in _read(p), f"{p.name} 里还写着「二期 M1-M3」"


def test_gen_onboarding_does_not_emit_machine_absolute_paths():
    """产物里不许出现本机绝对路径。

    `auth.js` 那条命令原来用 `{proxy_dir}` 插值出**生成这份文档的那台机器**的绝对
    路径，换台机器照抄就找不到文件。改成仓库相对路径 + "从仓库根执行"；
    `claude mcp add` 那条确实需要绝对路径，所以保留但换成占位符
    （与同文件 Quick Desktop 段既有写法统一）。
    """
    src = _read(GEN_ONBOARDING)
    # 否定断言覆盖整个文件（更强）
    assert "{proxy_dir}/auth.js" not in src, "auth.js 仍在插值本机绝对路径"

    # **肯定断言只看写进产物的那段模板**，不看整份源码。实测过为什么必须这样：
    # 我在 `proxy_rel` 上方的注释里也写了"从仓库根执行"这几个字，于是把**产物里**
    # 那句指引删掉之后，`"从仓库根" in src` 仍被那条注释满足 —— 用户读到的东西没了，
    # 断言却还是绿的。这是"注释满足断言"那一族（假绿总表第 4 行）。
    tpl = _onboarding_template(src)
    assert "<仓库绝对路径>" in tpl, (
        "产物里 claude mcp add 那条没有用 <仓库绝对路径> 占位符")
    assert "从仓库根" in tpl, "产物里没写明 auth.js 要从仓库根执行"

    # **每一处代理路径都必须是完整的**（相对仓库根或占位符 + 完整子路径）。
    # 原来 Quick Desktop 段写的是 `/绝对路径/quick-desktop-proxy/index.js`，
    # **漏了 `site-builder/clients/` 这一段** ⇒ 用户照抄得到的是一个不存在的路径。
    # 占位符省掉的应该只有"仓库在哪"，不该省掉仓库**内部**的结构。
    bad = [ln.strip() for ln in src.splitlines()
           if "quick-desktop-proxy" in ln
           and "site-builder/clients/quick-desktop-proxy" not in ln
           and not ln.strip().startswith("#")
           and "proxy_rel" not in ln]
    assert not bad, (
        "这些行里的代理路径不完整（缺 site-builder/clients/）：" + "; ".join(bad))


# ── C1 实测出来的过时口径：肯定断言，切片到对应小节 ──────────────────────

def test_deploy_md_codebuild_row_says_validated_not_uploads():
    """A2 之后 CodeBuild 角色读的是 `validated/*`（validate 产出的不可变工件），
    不再是 `uploads/*`。

    **同时正向核对没有改过头**：MCP 预签名上传那处仍然应该说 `uploads/*`——
    那是 owner 上传的落点，本来就正确。一次"全局替换 uploads→validated"会把它弄错，
    所以两边都断言。
    """
    txt = _read(DEPLOY)
    cb = _row(txt, "CodeBuild 角色收窄")
    assert "validated/*" in cb, f"CodeBuild 那行仍写着旧前缀：{cb.strip()[:120]}"
    assert "uploads/*" not in cb, f"CodeBuild 那行还留着 uploads/*：{cb.strip()[:120]}"
    presign = _row(txt, "presign")
    assert "uploads/*" in presign, (
        "MCP 预签名那处被改坏了——owner 的上传落点本来就是 uploads/*")


def test_deploy_md_documents_that_mcp_deploys_before_the_deployer_stack():
    """F1 之后 `validate` 缺 `upload_etag` 一律 fail-closed，而旧 MCP 不写这个属性
    ⇒ **存量重部时 MCP 必须先于 deployer 栈**，顺序错了的症状是"所有部署都在第一步
    挂"，与代码缺陷难分辨。

    要求写清三件事：顺序、为什么与首次 bootstrap 的顺序相反、以及排障锚点原文。
    """
    sec = _section(_read(DEPLOY), "## 部署顺序总览")
    assert "upload_etag" in sec, "没写 fail-closed 的那个字段名（排障时无从下手）"
    assert re.search(r"MCP.{0,40}(先|早)于.{0,20}(deployer|执行器)", sec), \
        "部署顺序总览里没写「MCP 先于 deployer 栈」"
    assert "bootstrap" in sec or "首次" in sec, \
        "没解释为什么与手册原有顺序相反（首次 bootstrap vs 存量重部）"
    assert "confirm_upload" in sec, "没给排障锚点（顺序错时会看到的报错原文）"


def test_cdk_out_note_says_mounted_inputs_are_hashed_not_cleared():
    """CDK 默认 asset hash **不含挂载卷的内容**（锁定清单、contract/）。原来的处方是"改了就
    `rm -rf cdk.out`"——实测**不成立**：重打的包是新字节，但 S3Key 不变，`cdk deploy` 照样跳过
    上传与更新。修法是 `infra/bundle_hash.py` 把挂载内容算进 hash。

    ⇒ 文档要写清：机理（挂载卷）、为什么清 cdk.out 没用、核对办法（`cdk diff` 看 Code 变化）；
    并且**不许**再有任何一行把 `rm -rf cdk.out` 当成清单 / 合同改动的处方。
    """
    txt = _read(DEPLOY)
    bad = [ln for ln in txt.splitlines()
           if "必须 `rm -rf cdk.out`" in ln and ("清单" in ln or "contract" in ln)]
    assert not bad, f"还有把 rm -rf cdk.out 当成清单/合同改动处方的旧说法：{bad}"
    win = _window(txt, "改依赖清单（`bundling-requirements.txt`）或 `site-builder/contract/`",
                  after=10)
    assert "挂载卷" in win, "没说明机理（挂载卷不进默认 asset hash）"
    assert "救不了" in win, "没说清 rm -rf cdk.out 为什么没用——下一个人会照旧处方做"
    assert "bundle_hash" in win and "cdk diff" in win, "没给修法与核对办法"


def test_deploy_md_says_bundling_copies_the_contract_package():
    """F2：bundling 不再 `pip install` 合同包，改 `cp` 包目录。

    理由必须写出来，否则下一个人"顺手改回 pip"：PEP 517 项目会在默认 build
    isolation 下**联网下载并执行**一个未锁版本、未锁 hash 的 setuptools，
    而它的输出进的是全部 site-deployer-* 产物。
    """
    txt = _read(DEPLOY)
    win = _window(txt, "bundling 用 Docker", after=4)
    assert "cp" in win, f"没写明合同包是 cp 进去的：{win[:160]}"
    assert "pip" in win and ("不走 pip" in win or "不走pip" in win), \
        "没明确说合同包**不走** pip（只说 cp 的话，下一个人会顺手改回去）"
    assert "PEP 517" in win and "setuptools" in win, \
        "没在同一处解释原因（PEP 517 会联网装未锁的 setuptools）"


def test_claude_md_test_commands_carry_the_two_measured_traps():
    """CLAUDE.md 的测试命令小节要带两条本轮实测的坑，否则下一个人会白花时间：

    · 改 `deployer/infra/app.py` 的 **bundling 段**要跑 **auth** 套件才会红
      （F2 的守卫住在 `auth/tests/test_requirements_locked.py`，AST 解析器在那边）；
    · **E2E 的 CA 陷阱**：`deployer/.venv` 的默认 SSL 上下文 CA 为空，而 E2E 会在
      进程内调用发起 HTTPS 的生产代码；只设 `SSL_CERT_FILE` 不够。
    """
    sec = _section(_read(CLAUDE_MD), "## 测试命令（有坑，别猜）")
    assert "test_requirements_locked" in sec or "auth" in sec, \
        "没写「改 bundling 段要跑 auth 套件」"
    assert "bundling" in sec, "没点出是 app.py 的 bundling 段"
    assert re.search(r"(CA|证书|SSL)", sec), "没写 E2E 的 CA/SSL 陷阱"
    assert "SSL_CERT_FILE" in sec, \
        "没写明「只设 SSL_CERT_FILE 不够」——这条不写就会有人按环境变量绕"


S1_SECTION = "## S1 加固（M01/M02/M05/M06）：存量环境的升级、闸门与回滚"


def test_deploy_md_s1_section_carries_the_facts_that_cost_most_to_lose():
    """S1 升级那一节里，这几条**丢了就会造成真实损失**，逐条钉住。

    这一节是给"没读过 spec、正在压力下照做"的人写的，所以判据只挑那些
    "写漏了会让操作者做错事"的事实，不管措辞：

    · 闸门命令是 `--check`，裸跑不是闸门（裸跑对"policy 与期望不一致"退 0
      ——把它接进发布检查就得到一条恒绿的假闸门）；
    · automation 只看退出码与计数、不 grep 输出文本（那段文案来自运行时
      `permissions.py`，本轮又改过一次，两次真机跑就因此输出不同）；
    · panel **不带** `--skip-frontend`（S1 改了 panel 前端，带上就是"代码对、
      线上没换"）；
    · 三个产物都要重部 + `verify_deployed_components.py`（漏一个的症状是
      产物陈旧而部署脚本全程正常，那个脚本是唯一能发现它的闸门）；
    · "0 个不合格角色"**不是**完整证明（不看信任策略、不看 boundary 还挂着没有）；
    · 回滚时 `null` 条目要 `delete_role_policy` 而不是 `put_role_policy`
      ——这一条写错，回滚会在 IAM 上抛错并停在半途；
    · 三波重登（spec 只写了两波）。

    **这一节内的代码块里有第 0 列的 `#` 注释**，所以本条同时是 `_section`
    围栏跟踪的真文档回归：解析器一退化，这里立刻红。
    """
    sec = _section(_read(DEPLOY), S1_SECTION)
    assert "--check" in sec and "裸跑不是闸门" in sec, \
        "没写清闸门命令是 --check、裸跑不是闸门"
    assert "退出码" in sec and ("grep" in sec or "计数" in sec), \
        "没写「automation 只看退出码与计数，别 grep 输出文本」"
    assert re.search(r"不许加\s*--skip-frontend|不[许准要]?加?\s*--skip-frontend", sec), \
        "没写明 panel 不能带 --skip-frontend"
    for needed in ("deploy_panel.py", "deploy_key_proxy.py", "deploy_agentcore.py",
                   "verify_deployed_components.py"):
        assert needed in sec, f"重部/验证清单里少了 {needed}"
    assert "不看信任策略" in sec and "boundary" in sec, \
        "没写明闸门不覆盖信任策略与 boundary 是否还挂着"
    assert "delete_role_policy" in sec and "put_role_policy" in sec, \
        "回滚段没写清两种条目对应两种动作（null ⇒ delete_role_policy）"
    assert sec.count("重新登录") or "重登" in sec, "没写强制重登"
    for wave in ("panel 部署完成", "auth 部署完成", "CloudFront 传播完成"):
        assert wave in sec, f"三波重登里少了「{wave}」那一波"


def test_deploy_md_calls_the_scp_template_unverified():
    """SCP 那份制品**未经真机验证**（`aws:PrincipalArn` 对 assumed-role 会话的取值
    没实测过），文档不许把它描述成"已验证的配置"。

    可以写成已验证的是 README 里那条生成 ARN 列表的命令——控制器在 C1 真机跑过。
    """
    sec = _section(_read(DEPLOY), "### 账号级加固（可选，**不是部署步骤**）")
    assert "policies/README.md" in sec, "没指向 policies/README.md"
    assert re.search(r"(simulator|空 OU|未经.{0,6}验证)", sec), \
        "没写明这是未经真机验证的模板、贴之前要先验"
    for bad in ("已验证的配置", "已验证配置"):
        assert bad not in sec, f"把 SCP 模板描述成了 {bad!r}"


# ── C4: 「延后项」清单里不许留已交付的东西 ─────────────────────────────────
#
# 这一类过时最误导：读者据此判断"这个能力还没有"，于是重复造或误报缺口。
# 判定各项是否已交付都有代码/目录证据（见每条断言的注释），不是凭印象。

# 已交付能力的**全部**称呼：改写前文档用的旧称 + 改写后 README / DEPLOY.md 的现行称呼。
# 判定按称呼命中——文档换了叫法而词表没跟上，判定分支就永远进不去、守卫空转成绿
# （R1 复审实测：README 改叫「API Key 交换层 / 控制台 / 协作者」后，旧词表一个都命中不了，
# 往「当前限制」里写"API Key 交换层、控制台和协作者支持均暂不提供"照样绿）。
# 改文档里的称呼时同步这张表；`test_limits_guard_fires_on_every_capability_alias` 逐个验。
_DELIVERED_CAPABILITIES = {
    # site-builder/key-proxy/（可选组件，mcp.{base_domain}）
    "API Key": ("MCP API-Key", "API-Key", "API Key", "key-proxy", "交换层"),
    # site-builder/panel/（console.{base_domain}）
    "控制台": ("管理面板", "控制台", "console."),
    # panel 与 MCP 的 collaborators 接口（manage_collaborators）
    "协作者": ("站点协作者", "协作者"),
    # auth/login_handler.py 的 PKCE_COOKIE + S256 + nonce 校验
    "PKCE/nonce": ("PKCE", "nonce"),
}
# 标记词必须是**否定句造不出来的**那个：`"交付" in sentence` 会被"仍未**交付**"满足，
# `已交付` / `已在二期交付` / `已支持` 都不可能由否定句产生。
_DELIVERED_MARKERS = ("已交付", "已在二期交付", "已支持")


def _section_lead(sec: str) -> str:
    """`_section` 的结果里，首个子标题之前的那部分（围栏里的 `#` 注释不算标题）。"""
    lines = sec.splitlines()
    mask = _fenced_mask(lines)
    for i in range(1, len(lines)):
        if not mask[i] and lines[i].startswith("#"):
            return "\n".join(lines[:i])
    return sec


def _limits_listing_delivered(sec: str) -> list:
    """「限制」类小节里提到已交付能力、却没说它已交付的句子（按句号与换行切句）。

    **不能简单断言"这些名字不出现"**：这类小节合理地可能提到它们，只是要说清"已交付"。
    正确的形态是：**凡提到它们的那句话，必须同时带已交付的标记**。
    """
    bad = []
    # 按语义单元拼回软折行、去掉排版记号与空白再比——"API\n  Key"、"**API** Key" 这类只改格式的
    # 旧句照样命中（R7 复审：按换行切句时软折行把称呼切成两半，强调符把称呼隔断）。
    for unit in _prose_units(sec):
        for sentence in re.split(r"[。；]", unit):
            flat = _squash(sentence)
            for cap, aliases in _DELIVERED_CAPABILITIES.items():
                if any(_squash(a) in flat for a in aliases) and not any(
                        m in flat for m in _DELIVERED_MARKERS):
                    bad.append(f"{cap}: {sentence.strip()[:90]}")
                    break
    return bad


def _squash(s: str) -> str:
    """`_plain` 之后再去掉全部空白：中文正文软折行拼回时英文词之间的空格不可靠。"""
    return re.sub(r"\s+", "", _plain(s))


def test_readme_future_candidates_do_not_list_delivered_capabilities():
    """README「当前限制」里不许列已交付的能力（原先守的是「如何继续」的候选清单，
    README 重写后那一节换成了只陈述当前事实的「当前限制」，判据不变）。

    实测各项现状：MCP API-Key = 已交付（`site-builder/key-proxy/`，二期 M4）；
    站点协作者 = 已交付（panel 的 collaborators 接口，M3）；管理面板 = 已交付
    （`site-builder/panel/`，console.{base_domain}，M3）；PKCE/nonce = 已交付
    （`auth/login_handler.py` 的 `PKCE_COOKIE` + S256 + nonce 校验）。
    仍未交付的只有 Python 站点 runtime 与精细缓存。
    """
    sec = _section(_read(README), "## 当前限制")
    bad = _limits_listing_delivered(sec)
    assert not bad, f"README「当前限制」把已交付的能力写成了限制：{bad}"
    # 正向：真实存在的那两项限制应当还在（否则这条断言退化成"把整段删掉就绿"）
    assert "Node.js" in sec and "Python" in sec and "缓存" in sec, \
        "「只支持 Node.js 后端」/「全站不缓存」这两条真实限制被一起删掉了——那是另一种失真"


def test_deploy_md_known_limits_do_not_list_delivered_capabilities():
    """DEPLOY.md 的「已知限制（向使用方说明）」是**对使用方**的口径，
    把已交付的 API Key fallback 写成"延后"比 README 那处更严重。
    （这一节原名「已知限制与延后项（向客户声明）」；资产只陈述当前事实、不列延后项，所以改了名，判据不变。）"""
    sec = _section(_read(DEPLOY), "## 已知限制（向使用方说明）")
    # 称呼判定只看**限制清单本身**（首个子标题之前）：后面几个 `###` 子节讲机制与信任边界，
    # 合理地提到控制台 / key-proxy 的设计（"已按独立 IAM 角色设计"），不是在列限制。
    bad = _limits_listing_delivered(_section_lead(sec))
    assert not bad, f"DEPLOY.md「已知限制」把已交付的能力写成了限制：{bad}"
    # 旧口径的原句仍对**整节**（含子节）断言——收窄到清单不能让它在子节里复活。
    assert _squash("API Key fallback 延后") not in _squash(sec), \
        "向使用方的说明里还写着 API Key fallback 延后，而 key-proxy 已交付"
    assert "Node.js" in _section_lead(sec), "仍未交付的「仅 Node.js 后端」被删掉了"


_ALL_CAPABILITY_ALIASES = [(cap, alias) for cap, aliases in _DELIVERED_CAPABILITIES.items()
                           for alias in aliases]


@pytest.mark.parametrize("cap,alias", _ALL_CAPABILITY_ALIASES)
def test_limits_guard_fires_on_every_capability_alias(cap, alias):
    """元用例：词表里**每一个**称呼都要真的进得了判定分支。

    反例用的正是 R1 复审实测漏过的那种句子（"……暂不提供"）；正对照是如实说明已交付
    的句子与真实存在的限制——它们不许被误伤，否则"全红"也能让反例那半边通过。
    """
    assert _limits_listing_delivered(f"- {alias} 暂不提供。\n"), (
        f"{cap} 的称呼 {alias!r} 写成'暂不提供'时守卫没红——这个称呼进不了判定分支")
    assert not _limits_listing_delivered(f"- {alias} 已交付，见部署手册。\n")
    assert not _limits_listing_delivered(
        "- 站点后端只支持 Node.js，不支持 Python。\n- CloudFront 全站不缓存。\n")


def test_limits_guard_fires_on_format_only_edits_of_the_historical_item():
    """R7 复审实测：旧 DEPLOY 限制清单原句只把 "API Key" 软折行或加强调就漏报。"""
    old = "- PoC 仅 Node.js 后端（Python 3.13 延后）；MCP 仅 OAuth（API Key fallback 延后）\n"
    for edited in (old, old.replace("API Key", "API\n  Key"), old.replace("API Key", "**API** Key")):
        assert _limits_listing_delivered(edited), f"没拦住：{edited!r}"
        assert _squash("API Key fallback 延后") in _squash(edited)
    assert not _limits_listing_delivered("- API\n  Key 组件已交付，见 ⑤c。\n")


def test_section_lead_stops_at_the_first_subheading_but_not_at_a_fenced_comment():
    sec = ("## 已知限制\n\n- API Key 暂不提供。\n```bash\n# 注释不是标题\n```\n- 尾项\n"
           "### 机制\n控制台已按独立角色设计\n")
    lead = _section_lead(sec)
    assert "尾项" in lead and "机制" not in lead
    assert _limits_listing_delivered(lead), "清单里的反例必须仍被抓到"


def test_readme_marks_the_phase_one_docs_as_snapshots():
    """README 不许把设计记录当成当前架构的有效入口：它们是**历史快照**
    （CLAUDE.md 的文档地图写着"已实现快照，勿改"）。新读者照一期 spec/plan 理解当前架构
    会错——二期的控制台/API Key/统计/blue-green 都不在里面。

    README 重写后，目录导览只列 `docs/superpowers/` 这一整个目录、不再逐个点名一期那两份；
    判据相应改成：**凡是**提到 `docs/superpowers` 或那两份文件名的行，都必须标明是快照。
    """
    txt = _read(README)
    sec = _section(txt, "## 目录导览")
    # 正对照：目录导览里确实有这一行（否则"没有任何一行"会让下面的循环空转成绿）
    assert _row(sec, "docs/superpowers"), "目录导览里没有 docs/superpowers 那一行——本条空转"
    needles = ("docs/superpowers", "2026-07-21-quick-site-builder-design.md",
               "2026-07-21-quick-site-builder.md")
    for ln in txt.splitlines():
        if any(n in ln for n in needles):
            assert "快照" in ln or "勿改" in ln, (
                f"这一行提到了设计记录却没标明是快照：{ln.strip()[:110]}")


# ── 活动文档不许再教「已被删除的实现」（Codex 复审 F1）────────────────────────
#
# S1 的候选条数上限已经删掉（任何有限值都会按路径深度让 M06 复活），spec 与代码都
# 改了，但**实施计划的 Task 9 仍在逐行规定** `MAX_SESSION_COOKIE_CANDIDATES = 8` 与
# 切片式截断，而 CLAUDE.md 的文档地图把那份 plan 与 spec 并列标为「S1 的设计与实施」。
# 也就是说新接手的人按文档地图进去，读到的是一份**会把漏洞重新实现出来**的可执行
# 指令。这条守卫要求：这类"已被取代的实现"只能出现在明确标了 superseded 的段落里。

# 已被取代、不许在无标记的活动段落里出现的实现符号。**每条都要写清它为什么被删**
# ——否则下一个人只知道"不许提"，不知道"提了会怎样"，于是会把标记加上了事。
_SUPERSEDED_SYMBOLS = {
    # 候选条数上限：可遮蔽条数上界 4n−2、n（路径段数）无界 ⇒ 不存在够大的有限值。
    # 8 在 4 段路径上被打满，64 在 17 段上被打满，M06 在那些路径上原样复活。
    "MAX_SESSION_COOKIE_CANDIDATES": "候选条数上限已删除（spec §4.4）",
}

# 认可的"这段已经不算指令了"标记
_SUPERSEDED_MARKERS = ("superseded", "已被取代", "已废弃", "历史记录")


def _fenced_mask(lines: list) -> list:
    """逐行「这一行在围栏代码块里吗」。与 `_section` 里那份同法。"""
    mask, inside = [], False
    for ln in lines:
        if ln.lstrip().startswith("```"):
            mask.append(True)        # 围栏标记行本身不可能是标题
            inside = not inside
        else:
            mask.append(inside)
    return mask


def _enclosing_section(lines: list, idx: int) -> str:
    """含第 idx 行的那个 markdown 小节（往上找最近的标题，往下到下一个同级或更高级）。

    **必须跟踪围栏**，理由与本文件 `_section` 的 docstring 同一条：围栏里第 0 列的
    `# 注释` 与 H1 标题在纯文本上长得一模一样。我第一版没跟踪，于是 plan 里那段
    Python 代码块的注释 `# 约 8KB 限制…` 被当成标题，小节从它开始算 ⇒ 上面那条
    superseded 横幅被切在小节外 ⇒ 守卫在文档**已经标好**的情况下假红。
    （同一个坑本文件警告过一次，我还是踩了；所以这里把解析器修对，而不是去改文档。）
    """
    fenced = _fenced_mask(lines)

    def is_heading(i: int) -> bool:
        return lines[i].startswith("#") and not fenced[i]

    start, level = 0, 99
    for i in range(idx, -1, -1):
        if is_heading(i):
            start = i
            level = len(lines[i]) - len(lines[i].lstrip("#"))
            break
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if is_heading(j) and (len(lines[j]) - len(lines[j].lstrip("#"))) <= level:
            end = j
            break
    return "\n".join(lines[start:end])


def test_no_tracked_doc_prescribes_a_superseded_implementation():
    """任何**被跟踪**的 .md 里，已被取代的实现符号只能出现在标了 superseded 的小节里。

    Codex 复审 F1：代码与 spec 都改成"不设条数上限"之后，plan 的 Task 9 仍在规定
    `MAX_SESSION_COOKIE_CANDIDATES = 8` + 切片截断，而 CLAUDE.md 把那份 plan 标为
    「S1 的设计与实施」——活动的实施真源在教人把已修掉的漏洞重新写回来。

    扫**全部 tracked .md**而不是一张文档清单：换个文件名、把内容搬进另一份文档，
    这条都还在。
    """
    import subprocess

    r = subprocess.run(["git", "ls-files", "-z", "*.md"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"git ls-files 失败（本条空转）：{r.stderr.strip()}"
    docs = [d for d in r.stdout.split("\0") if d]
    assert len(docs) > 5, f"只找到 {len(docs)} 份 tracked .md——本条空转"

    checked, offenders = 0, []
    for rel in docs:
        lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
        for sym, why in _SUPERSEDED_SYMBOLS.items():
            for i, line in enumerate(lines):
                if sym not in line:
                    continue
                checked += 1
                sec = _enclosing_section(lines, i)
                if not any(m in sec for m in _SUPERSEDED_MARKERS):
                    offenders.append(f"{rel}:{i + 1} [{sym}] {why}")

    assert not offenders, (
        "这些位置在**没有 superseded 标记**的小节里规定了已被取代的实现：\n  "
        + "\n  ".join(offenders)
        + "\n要么改成最终实现，要么在该小节开头加一段"
        f"{_SUPERSEDED_MARKERS[1]!r} 横幅并指向真源。")

    # 正对照：plan 的 Task 9 现在确实还留着那些字样（在 superseded 横幅之下）。
    # 归零意味着判据或文档结构变了，此时这条在空转。
    assert checked >= 4, (
        f"只在 tracked .md 里找到 {checked} 处已取代符号——判据多半跟不上文档了"
        "（符号被改名／文档被移出跟踪？），本条正在空转")


# ── 不许把"新 clone 里没有的文档"当真源（类级守卫）───────────────────────────
#
# README 早有一条同向的守卫（`test_readme_status_has_no_stale_numbers_or_date` 末尾
# 那三行：状态段必须说明 `docs/design` 不随仓库分发、且不许以 HANDOFF 为真源），
# **CLAUDE.md 一直没有**——S1 那次"文档地图/状态段把 gitignored 的 HANDOFF 写成状态
# 真源"就是从这个缺口漂回来的。
#
# 这里刻意**不**照抄那种逐个点名的写法（`"HANDOFF" not in ...`）：那是打地鼠，换个
# 文件名就绿。判据改成从 **git 自己**问"新 clone 里到底有没有这个文件"，于是新加一份
# gitignored 的过程记录、或把某份文档移出跟踪，守卫都会自己发现。


def _tracked_paths() -> set:
    """仓库里**被跟踪**的全部路径。「这是不是新 clone 里有的东西」的唯一判据。

    用 `git ls-files` 而不是 `git check-ignore`：真正要问的是"新 clone 里有没有"，
    而"没被 .gitignore 匹配"并不等于"被跟踪"（未跟踪且未忽略的文件同样不在 clone 里）。
    结果为空一定是环境问题（不在 git 仓库里／没有 git），**必须红而不是静默放过**——
    否则每个指针都会被判成"非分发"，这条会以假红的形式空转。
    """
    import subprocess

    r = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"git ls-files 失败（本条空转）：{r.stderr.strip()}"
    paths = {p for p in r.stdout.split("\0") if p}
    assert len(paths) > 100, f"git ls-files 只返回 {len(paths)} 条——本条空转"
    return paths


def _is_doc_pointer(tok: str) -> bool:
    """这个反引号内容是不是「指向一份文档」的路径。

    范围刻意收窄到**文档**：本守卫管的是"别拿一份新 clone 里没有的文档当真源"，
    不管 venv、config.ini、URL 路径。放宽到"所有路径"实测会咬出一堆
    `deployer/.venv`、`/api/keys/revoke`、`f"/{static_prefix}{path}"` 这类噪音——
    而假阳性的下一步是有人给守卫加目录级豁免，那才是真把洞开出来。
    """
    if tok.startswith(("/", "http", ".venv")) or any(c in tok for c in ' ":()=$'):
        return False
    if "/" not in tok and not tok.endswith(".md"):
        return False
    return tok.endswith(".md") or tok.startswith(("docs/", ".superpowers/"))


def _distributed(path: str, tracked: set, doc: Path) -> bool:
    """新 clone 里有没有它。

    **先按"相对这份文档所在目录"解析，再按仓库根**——这不是为了少报几条，而是
    读者就是这样解析的：`DEPLOY.md` 住在 `site-builder/`，它写的
    `docs/client-setup.md` 指的是 `site-builder/docs/client-setup.md`（实测该文件
    确实只存在于那里）。只按仓库根解析会把 DEPLOY.md 里 5 处**完全正常**的
    包内相对路径报成违规，而带着 5 条假阳性的守卫活不过下一轮。
    对 README/CLAUDE.md 两者等价（它们就在仓库根）。

    目录形态与 `<占位符>`／`{a,b}` 形态按字面前缀判。
    """
    rel = doc.parent.relative_to(ROOT).as_posix()
    for cand in ([f"{rel}/{path}", path] if rel != "." else [path]):
        if cand in tracked:
            return True
        prefix = re.split(r"[{<*]", cand)[0]
        if not prefix:
            return True                  # 整体是占位符，判不出，不当违规
        if any(t.startswith(prefix) for t in tracked):
            return True
    return False


def _doc_blocks(text: str) -> list:
    """`(行号, 块文本)`。**表格行自成一块，散文按空行分段。**

    granularity 是这条守卫的关键，两个极端都试过、都不对：
      · 按**小节**切太松——「文档地图」那张表只要任意一行写过 gitignored，新加的
        那一行就免检了，而新加的那一行正是会漂的那一行；
      · 按**单行**切会假红——引用块里的散文是折行的，指针在一行、`gitignored`
        在下一行（实测 CLAUDE.md 那段引用块就是这样）。
    表格行是读者单独消费的单元，散文段落才是。围栏代码块在调用处已剥掉：
    那里是命令（`.venv/bin/pytest` 之类），不是指向文档的真源指针。
    """
    out, buf, start = [], [], 0
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith("|"):
            if buf:
                out.append((start, "\n".join(buf)))
                buf = []
            out.append((i, ln))
        elif not ln.strip():
            if buf:
                out.append((start, "\n".join(buf)))
                buf = []
        else:
            if not buf:
                start = i
            buf.append(ln)
    if buf:
        out.append((start, "\n".join(buf)))
    return out


# 认可的「这东西不在你的 clone 里」标记。给三种写法而不是只认一个词：只认
# `gitignored` 会让"**不随仓库分发**"这种同义表述假红，而这三个都是三份文档已在用的
# 措辞。**不要往里加"仅本地"之类含糊的词**——标记的作用是让读者当场知道照这个路径
# 找不到文件。
NOT_DISTRIBUTED_MARKERS = ("gitignored", "不随仓库分发", "新 clone 里不存在")


def _pointers_in(block: str) -> set:
    """一块文本里所有「像是指向文档」的引用。

    反引号路径 **+ Markdown 链接目标**（`[文字](路径)`）。只取反引号会漏掉链接
    形态——Codex 复审指出的同一类失明（提取规则决定守卫的射程，而它当时只认一种
    写法）。裸文档名那一类由 `test_..._by_bare_name` 单独管，不在这里。
    """
    toks = set(re.findall(r"`([^`\n]+)`", block))
    toks |= set(re.findall(r"\]\(([^)\s]+)\)", block))
    return {t.strip() for t in toks if _is_doc_pointer(t.strip())}


def _bare_name_stems(prose: str, doc, tracked: set) -> set:
    """从这份文档**自己标出的**非分发指针里推出「文档词干」。

    自推导，不是硬编码黑名单：文档里出现 `docs/design/HANDOFF-2026-08-07.md`
    就得到词干 `HANDOFF`，于是同一份文档里任何**裸写** HANDOFF 的地方都要按
    同一标准要求标记。这样新加一份 gitignored 的 `docs/design/XXXX-2027.md`
    会自动带出词干 `XXXX`，不用有人回来补名单。

    只取长度 ≥5 的**全大写**片段：这是本仓库过程记录的命名习惯
    （HANDOFF / FINDINGS / SPIKE / SPEC），而全大写足以避开普通散文词。
    """
    stems = set()
    for tok in _pointers_in(prose):
        if _distributed(tok, tracked, doc):
            continue
        base = tok.rstrip("/").split("/")[-1]
        for part in re.split(r"[-_.{}0-9,/]+", base):
            if len(part) >= 5 and part.isupper():
                stems.add(part)
    return stems


def test_delivery_docs_do_not_reference_undistributed_docs_by_bare_name():
    """裸写的文档名（不加反引号、不写路径）也要标明它不随仓库分发。

    这是 Codex 复审抓到的一处**当前 HEAD 的直接矛盾**，不是未来的假想：
    CLAUDE.md 一边写"HANDOFF / FINDINGS 是 gitignored、不要当状态真源"，一边在
    E2E 那一节写"数量与最新结果**见 HANDOFF 的最新一节**"——新 clone 的读者照它
    去找一个不存在的文件。上一条守卫看不见它，因为它只从反引号里提路径，而
    `见 HANDOFF 的最新一节` 既没有反引号也没有路径。

    词干是**从三份文档共同推导的一个全局集合**（见 `_bare_name_stems`），不是
    "HANDOFF 黑名单"，所以新增一份过程记录会自动进入射程。

    **必须全局推、不能每份文档各推一份**（Codex 第三轮实测）：按单份推时
    DEPLOY.md 自己一条完整的非分发路径都没有 ⇒ 它的词干集合是空的 ⇒
    `DEPLOY.md:1979` 那句裸写的 `M5-FINDINGS §4.26` 压根不在射程内。
    也就是说"新增一份过程记录会自动进入射程"这个说法在单份推导下是**假的**——
    只有当同一份文档里还留着一条完整且已标记的路径时才成立。
    """
    tracked = _tracked_paths()
    # 先合并出全局词干集合，再逐份扫描
    stems = set()
    for doc in (README, CLAUDE_MD, DEPLOY):
        prose = re.sub(r"```.*?```", "", _read(doc), flags=re.S)
        stems |= _bare_name_stems(prose, doc, tracked)

    checked, offenders = len(stems), []
    for doc in (README, CLAUDE_MD, DEPLOY):
        prose = re.sub(r"```.*?```", "", _read(doc), flags=re.S)
        # **先把反引号跨度整段抹掉再找裸出现**：`docs/design/M{3,4,5}-FINDINGS.md`
        # 里面也含 FINDINGS，不抹掉就会把"规范写法"当成"裸写"报出来。
        masked = re.sub(r"`[^`\n]*`", " ", prose)
        raw = prose.splitlines()
        for i, line in enumerate(masked.splitlines(), 1):
            for stem in sorted(stems):
                if stem in line and not any(m in line
                                            for m in NOT_DISTRIBUTED_MARKERS):
                    offenders.append(f"{doc.name}:L{i} 裸写 {stem}：{raw[i - 1].strip()[:70]}")

    # 正对照：全局集合现在确实含 HANDOFF / FINDINGS / SPIKE
    assert checked >= 3, (
        f"只推出 {checked} 个文档词干——`_bare_name_stems` 多半跟不上文档写法了，"
        "本条正在空转。先修它，不要放宽这个数字。")
    assert {"HANDOFF", "FINDINGS"} <= stems, (
        f"全局词干集合少了 HANDOFF/FINDINGS：{sorted(stems)}——"
        "推导规则失效了，本条正在空转")
    assert not offenders, (
        "这些地方**裸写**了一份新 clone 里没有的文档名：\n  "
        + "\n  ".join(sorted(set(offenders)))
        + "\n同一行里标明它不随仓库分发，或者改成一条可执行命令／一份被跟踪的文档。")


def test_delivery_docs_mark_every_undistributed_doc_pointer():
    """三份交付文档里每一处指向「新 clone 里没有的文档」的指针，都必须当场标明。

    S1 那次漂移的形状：文档地图把 gitignored 的 `docs/design/HANDOFF-*.md` 列成
    "接手时读哪里"，于是新 clone 的接手人按图去找一个不存在的文件，并且**以为自己
    读到的是状态真源**。这三份是"换个人／换个账号照着做"的入口，这一行的代价是对方
    拿着缺失的口径去判断生产现在是什么样。

    判据不是一张文件名黑名单，而是 `git ls-files`：**新加一份 gitignored 的过程记录、
    或把某份文档移出跟踪，这条都会自己发现。**
    """
    tracked = _tracked_paths()
    scanned, offenders = 0, []
    for doc in (README, CLAUDE_MD, DEPLOY):
        # 围栏里是命令不是指针，先剥掉（`_section` 那套按标题切，这里要的是全文）
        prose = re.sub(r"```.*?```", "", _read(doc), flags=re.S)
        for line_no, block in _doc_blocks(prose):
            undistributed = sorted(p for p in _pointers_in(block)
                                   if _is_doc_pointer(p)
                                   and not _distributed(p, tracked, doc))
            scanned += len(undistributed)
            if undistributed and not any(m in block
                                         for m in NOT_DISTRIBUTED_MARKERS):
                offenders.append(f"{doc.name}:L{line_no} {undistributed}")

    # **正对照：本条不许空转。** 提取规则收窄过（只认文档路径），写错一个字符就会一个
    # 指针都扫不到，而那时它照样是绿的——守卫失效却无人知道。三份文档现在确实引用着
    # gitignored 的 `docs/design/` 与 `.superpowers/`，所以这个数必须远大于 0。
    assert scanned >= 8, (
        f"只扫到 {scanned} 处非分发文档指针——提取规则多半已经跟不上文档的写法，"
        "本条正在空转。先修 _is_doc_pointer/_doc_blocks，不要放宽这个数字。")

    assert not offenders, (
        "这些位置指向了**新 clone 里没有**的文档，却没标明：\n  "
        + "\n  ".join(offenders)
        + f"\n在同一块里加上 {NOT_DISTRIBUTED_MARKERS[0]!r} 之类的标记，或者改指一份"
        "被跟踪的文档。gitignored 的过程记录**不能**充当状态真源。")


# CommonMark 的行内链接目标：`<…>` 形态，或不含空白的裸目标（允许一层**平衡括号**，
# 如 `missing(1).md`），后面可跟一个 title（`"…"` / `'…'` / `(…)`，可以换行）。
# R2 复审：只认裸目标时 `[x](LICENSE "t")` 整条漏掉、`[x](<LICENSE>)` 误报；
# R3 复审：平衡括号目标与跨行 title 漏掉。
_MD_DEST = r"(?:<([^<>\n]*)>|((?:[^\s()<>]|\([^\s()<>]*\))+))"
_MD_TITLE = r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?"
_MD_INLINE_LINK_RE = re.compile(r"\]\(\s*" + _MD_DEST + _MD_TITLE + r"\s*\)")
# 引用式链接的定义行：`[label]: target "title"`
_MD_REF_DEF_RE = re.compile(r"^ {0,3}\[[^\]\n]+\]:\s*(?:<([^<>\n]*)>|(\S+))", re.M)
# 围栏代码块（``` 与 ~~~ 两种，闭合围栏至少与开头同长同符号）与行内代码里的 `[a](b)` 是示例，不是链接
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1[`~]*[ \t]*$", re.M | re.S)
_CODE_SPAN_RE = re.compile(r"(`+)(?!`).+?(?<!`)\1(?!`)", re.S)


def _strip_code(text: str) -> str:
    """剥掉围栏代码块与行内代码。行内代码**不跨段落**（空行即边界），`\\`` 是字面反引号——
    R4 复审：跨全文配对反引号会让一个落单的反引号吞掉两段之间的真实链接。"""
    out = []
    for block in re.split(r"(\n[ \t]*\n)", _FENCE_RE.sub("", text)):
        block = block.replace("\\`", "\0")          # 转义的反引号不参与配对
        out.append(_CODE_SPAN_RE.sub("", block).replace("\0", "\\`"))
    return "".join(out)


def _md_link_targets(text: str) -> list:
    """一份 markdown 里全部链接目标（行内 + 引用式定义）；围栏代码块与行内代码先剥掉。"""
    prose = _strip_code(text)
    return [a or b for rx in (_MD_INLINE_LINK_RE, _MD_REF_DEF_RE)
            for a, b in rx.findall(prose)]


def _broken_relative_links(text: str, tracked: set, base: str = "") -> list:
    """Markdown 链接 `[文字](目标)` 里的**相对**目标中，新 clone 里不存在的那些。

    去掉 `#锚点` 后按「相对文档所在目录」解析；目标是被跟踪的文件、或被跟踪文件的目录，
    才算存在。外链（`scheme:`）与页内锚点（`#…`）不归本条管。围栏代码块先剥掉。
    上面那条指针守卫看不见这一类：它只认以 `.md` 结尾或带 `/` 的 token，
    `CONTRIBUTING.md#security-issue-notifications` 两样都不沾（R1 复审：README 的
    Security / License 两节指向仓库里从没有过的 CONTRIBUTING.md 与 LICENSE）。
    """
    import posixpath

    bad = []
    for tgt in _md_link_targets(text):
        if re.match(r"^[a-z][a-z0-9+.-]*:", tgt, re.I) or tgt.startswith("#"):
            continue
        path = posixpath.normpath(posixpath.join(base, tgt.split("#", 1)[0]))
        if path not in tracked and not any(t.startswith(path + "/") for t in tracked):
            bad.append(tgt)
    return bad


# 公开读者会点的那几份。CONTRIBUTING.md 是 README 的 Security 一节指过去的。
_LINK_CHECKED_DOCS = (README, ROOT / "CONTRIBUTING.md", CLAUDE_MD, DEPLOY, CLIENT_SETUP,
                      ROOT / "site-builder" / "clients" / "quick-desktop-proxy" / "README.md")


def test_delivery_docs_relative_links_resolve_to_tracked_files():
    tracked = _tracked_paths()
    offenders = []
    for doc in _LINK_CHECKED_DOCS:
        base = doc.parent.relative_to(ROOT).as_posix()
        base = "" if base == "." else base
        offenders += [f"{doc.relative_to(ROOT)} → {t}"
                      for t in _broken_relative_links(_read(doc), tracked, base)]
    # 正对照：README 里确实有相对链接（否则提取规则写错时本条空转成绿）
    assert [t for t in _md_link_targets(_read(README))
            if not re.match(r"^[a-z][a-z0-9+.-]*:", t, re.I) and not t.startswith("#")], \
        "README 里一条相对链接都没扫到——本条空转"
    assert not offenders, "这些相对链接指向新 clone 里不存在的文件：\n  " + "\n  ".join(offenders)


def test_relative_link_guard_fires_on_a_missing_target_and_ignores_external_links():
    tracked = {"README.md", "LICENSE", "docs/security/x.md", "site-builder/docs/y.md"}
    assert _broken_relative_links("[a](CONTRIBUTING.md#security-issue-notifications)", tracked) \
        == ["CONTRIBUTING.md#security-issue-notifications"]
    assert _broken_relative_links("[b](docs/y.md)", tracked) == ["docs/y.md"], "应按文档目录解析"
    assert not _broken_relative_links("[b](docs/y.md)", tracked, base="site-builder")
    assert not _broken_relative_links(
        "[a](LICENSE) [b](docs/security/x.md#s) [c](https://e.com/x.md) [d](#top) "
        "[e](docs/security/) [f](mailto:a@b.c)\n```\n[g](missing.md)\n```", tracked)
    # title 与尖括号目标（R2 复审实测：旧提取规则对前者漏报、对后者误报）
    assert _broken_relative_links('[a](LICENSE-missing "Documentation")', tracked) \
        == ["LICENSE-missing"]
    assert _broken_relative_links("[a](CONTRIBUTING-missing.md#s 'T')", tracked) \
        == ["CONTRIBUTING-missing.md#s"]
    assert _broken_relative_links("[a](<no such.md> (T))", tracked) == ["no such.md"]
    assert not _broken_relative_links('[a](<LICENSE>) [b](LICENSE "t") [c]( LICENSE )', tracked)
    # 引用式定义
    assert _broken_relative_links("[x]: CONTRIBUTING.md#s \"t\"\n", tracked) == ["CONTRIBUTING.md#s"]
    assert not _broken_relative_links("[x]: <LICENSE>\n[y]: https://e.com\n", tracked)
    # 平衡括号目标与跨行 title（R3 复审实测漏报）
    assert _broken_relative_links("[a](missing(1).md)", tracked) == ["missing(1).md"]
    assert _broken_relative_links('[a](gone.md\n  "a title")', tracked) == ["gone.md"]
    assert not _broken_relative_links('[a](LICENSE\n  "a title") [b](docs/security/x.md#s(1))',
                                      tracked)
    # 行内代码与 ~~~ 围栏里的 `[a](b)` 是示例（R3 复审实测误报）
    assert not _broken_relative_links("写法示例：`[a](missing.md)`，或 ``[b](gone.md)``。", tracked)
    assert not _broken_relative_links("~~~markdown\n[a](missing.md)\n~~~\n", tracked)
    assert _broken_relative_links("~~~\n[a](x)\n~~~\n[b](missing.md)", tracked) == ["missing.md"]
    # 转义反引号与跨段落的落单反引号不构成代码（R4 复审实测：旧正则把中间的真实链接吞掉）
    assert _broken_relative_links("字面 \\` 号，[说明](missing.md)，再一个 \\` 号。", tracked) == ["missing.md"]
    assert _broken_relative_links("一段里落单的 ` 号。\n\n[说明](missing.md)\n\n另一段落单的 ` 号。",
                                  tracked) == ["missing.md"]
    assert not _broken_relative_links("同段跨行的 `[a](missing.md)\n仍是代码` 示例。", tracked)
    assert not _broken_relative_links("字面 \\` 号旁边的 [正常](LICENSE) 链接。", tracked)


# ── 措辞类守卫的合同（resource 口径 / 控制台可选 / 限制清单里的已交付能力）────────
#
# 它们是**词法绊线**，钉的是**历史上真实出现过的那几句错误口径**，在**只改格式**的编辑下
# 仍然要红：加引号 / 强调、软折行、改写成标题、列表、表格（含省略首尾竖线的 GFM 表格）、
# 引导句加粗等——这些都是整理文档时会顺手做的事，六轮复审逐一实测过。
# **不承诺拦住换了说法的意译**（例如把旧结论改写成新的句式、换一套同义词）：任何词法规则
# 都关不上意译，追下去只会把守卫变成一个不可维护的自然语言分类器。意译的防线是评审本身。
# 改这几条守卫时：旧句的格式变形必须仍红（各自的 *_fires_on_* 元用例），当前文档必须仍绿。

# 「Claude Code 直连为什么失败」的口径：单账号实测到的是"带 resource 时换 token 报
# invalid_grant"，**不是**"Cognito 不支持 resource"——Cognito 文档写明授权端点支持
# resource binding（R1 复审，coordinator 读 docs.aws.amazon.com 核实）。旧口径曾同时住在
# client-setup.md、代理 README 与 gen_onboarding 的生成模板里，只改前两处时第三处照样把
# 绝对结论发给组织用户（R2 复审）。这里按**旧口径的具体句式**拦，不做通用措辞识别：
# 否定引用（"别把这条读成'Cognito 不支持 resource'"）不在拦截范围内。
_RESOURCE_CLAIM_DOCS = (README, CLAUDE_MD, DEPLOY, CLIENT_SETUP, GEN_ONBOARDING,
                        ROOT / "site-builder" / "clients" / "quick-desktop-proxy" / "README.md")
# 前两种句式要与 resource 同句才算（"Cognito 不支持 dynamic client registration" 是真的）；
# 后两种是旧口径特有的**结论句式**（"任何用 Cognito…都会遇到"的泛化、"绕不开"的断言）。
# 引号里的是引用——"别把这条读成『Cognito 不支持 resource』"这类否定引用放行（R3 复审）。
# 这两组正则都跑在 `_plain()` 之后：强调符、反引号、引号已经去掉——**只改格式**的变形
# （"**Cognito** 不支持""Cognito **不支持**""**`resource`** 参数问题绕不开"）一次性归一，
# 不再逐个补字符类（R7 复审）。否定引用在归一之前由 `_drop_negated_quotes` 先剔掉。
_OVERCLAIM_WITH_RESOURCE_RE = re.compile(r"[而，,]\s*Cognito\s*不支持|Cognito\s*不认")
_OVERCLAIM_STANDALONE_RE = re.compile(
    r"任何用\s*Cognito[^。]*?都会遇到|resource\s*参数问题绕不开")
_FORMAT_CHARS_RE = re.compile(r"[*_`~“”\"「」『』‘’']")


def _plain(s: str) -> str:
    """去掉只影响排版的记号（强调、行内代码、删除线、各种引号），用于措辞匹配。"""
    return _FORMAT_CHARS_RE.sub("", s)
_QUOTED_RE = re.compile(r"[“\"「『][^“”\"「」『』]{0,160}[”\"」』]")
# 引号前面紧挨着这些词才算**否定引用**（"别把这条读成『…』"）；肯定的引号结论照常参与检测
# ——R4 复审：一律删掉引号内容会让"结论：『resource 参数问题绕不开』"这种旧口径加个引号就回归。
# "读成 / 写成"本身不是否定（"结论应写成『…』"是肯定句，R5 复审），要有前面那几个否定词才算。
_NEGATION_BEFORE_QUOTE_RE = re.compile(r"(?:别把|不要|不能|不是|并非|别再|不再|不应|不该)[^，。；]{0,24}$")
# GFM 表格的分隔行（首尾竖线可省略）：| --- | :-: | 或 --- | ---
_TABLE_DELIM_RE = re.compile(r"^\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$|^\|\s*:?-{3,}:?\s*\|$")


# 否定只管到它自己那一截：上一个引号之后、最后一个转折词之后才是这个引号的"引导语"
# ——R6 复审："不是 scope 问题而是「…」""不能写成「…」而应写成「…」"里的否定管不到后一个引号。
# 前面紧挨"不"的（不应 / 不应该）不是转折。
_CONTRAST_RE = re.compile(r"(?<!不)(?:而是|而应|而|但是|但|却|应当|应该|应)")


def _drop_negated_quotes(sentence: str) -> str:
    out, pos = [], 0
    for m in _QUOTED_RE.finditer(sentence):
        lead_in = _CONTRAST_RE.split(sentence[pos:m.start()])[-1]
        if _NEGATION_BEFORE_QUOTE_RE.search(lead_in):
            out.append(sentence[pos:m.start()])
        else:
            out.append(sentence[pos:m.end()])
        pos = m.end()
    out.append(sentence[pos:])
    return "".join(out)


def _prose_units(text: str, with_indent: bool = False) -> list:
    """把 markdown 切成语义单元：**表格行、列表项、标题、段落各自成块**，块内折行拼回一行；
    围栏代码块先剥掉，引用块的 `>` 前缀去掉。`with_indent=True` 时返回 `(缩进, 单元)`，
    缩进取单元首行（嵌套列表的层级靠它，R8 复审）。

    先前两条守卫把全文的换行一次删光再按句号切——一整张表或相邻列表项会并成"一句"，
    于是表里另一行的"验收"能豁免这一行的"可选"，相邻两项又会互相误伤（R3 复审实测）。
    表格按 GFM 的**分隔行**识别（首尾竖线可省略，R4 复审）：分隔行的上一行是表头，
    之后到空行为止每行一条。
    """
    raws = _FENCE_RE.sub("", text).splitlines()
    lines = [re.sub(r"^(?:>\s?)+", "", raw.strip()).strip() for raw in raws]
    # 缩进在去掉引用块前缀（`> `）**之后**再量——引用块里的嵌套列表层级在 `>` 后面（R9 复审）
    quote_prefix = re.compile(r"^[ \t]*(?:>[ \t]?)+")
    rests = [raw[m.end():] if (m := quote_prefix.match(raw)) else raw for raw in raws]
    indents = [len(r) - len(r.lstrip()) for r in rests]
    in_table = [False] * len(lines)
    for i, ln in enumerate(lines):
        if i and "|" in lines[i - 1] and _TABLE_DELIM_RE.match(ln):
            j = i - 1
            while j < len(lines) and lines[j]:
                in_table[j] = True
                j += 1
    units, buf = [], []
    start = [0]

    def emit(indent, unit):
        units.append((indent, unit) if with_indent else unit)

    def flush():
        if buf:
            emit(start[0], "".join(buf))
            buf.clear()

    for ln, table_row, ind in zip(lines, in_table, indents):
        if buf and not table_row and re.fullmatch(r"=+|-+", ln):
            # Setext 标题（段落下一行全是 = 或 -）：那一段就是标题
            emit(start[0], "# " + "".join(buf))
            buf.clear()
            continue
        if not ln:
            flush()
        elif table_row or ln.startswith(("|", "#")):
            flush()
            emit(ind, ln)
        else:
            if re.match(r"^(?:[-*+]|\d+[.)])\s", ln):
                flush()
            if not buf:
                start[0] = ind
            buf.append(ln)
    flush()
    return units


def _resource_overclaims(text: str) -> list:
    hits = []
    for unit in _prose_units(text):
        for sent in unit.split("。"):
            sent = _plain(_drop_negated_quotes(sent))
            if _OVERCLAIM_STANDALONE_RE.search(sent) or (
                    "resource" in sent and _OVERCLAIM_WITH_RESOURCE_RE.search(sent)):
                hits.append(sent.strip()[:90])
    return hits


def test_no_adopter_doc_says_cognito_does_not_support_resource():
    offenders = [f"{p.relative_to(ROOT)}: {h}" for p in _RESOURCE_CLAIM_DOCS
                 for h in _resource_overclaims(_read(p))]
    assert not offenders, "这些位置仍把单账号实测写成了 Cognito 的产品能力缺失：\n  " + \
        "\n  ".join(offenders)
    # 正对照：实测本身必须还在（不许"把整段删掉就绿"）
    assert "invalid_grant" in _read(CLIENT_SETUP) and "resource" in _read(GEN_ONBOARDING)


def test_resource_overclaim_guard_fires_on_each_old_phrasing():
    for old in ("Claude Code 带 RFC 8707 的 `resource`\n参数，而 **Cognito 不支持它**——换 token 失败。",
                "它发的 `resource` 参数 Cognito 不认，见上面。",
                "`resource` 才是。这与本平台的配置无关，任何用 Cognito 当 authorization server 的都会遇到。",
                "| 免代理方案 | 无（`resource` 参数问题绕不开） |",
                "它在 OAuth 请求里带 RFC 8707 的 `resource` 参数，Cognito 不支持，\n换 token 时报错。"):
        assert _resource_overclaims(old), f"旧口径没被拦住：{old[:60]}"
    assert not _resource_overclaims(
        "所以别把这条读成\"Cognito 不支持 resource\"，也别把任何 invalid_grant 都归到它头上。")
    assert not _resource_overclaims("Cognito 不支持 dynamic client registration。")
    # 明确否定的引用（R3 复审实测假红）与段落边界
    assert not _resource_overclaims("不能断言『任何用 Cognito 当 authorization server 的都会遇到』。")
    assert not _resource_overclaims("不要再写「resource 参数问题绕不开」。")
    assert not _resource_overclaims("任何用 Cognito 的部署都要先建 user pool。")
    assert not _resource_overclaims("带 `resource` 时失败。\n\n另一段：Cognito 不认这个 app client。")
    # R4 复审：肯定的引号结论照常抓；同一个否定引用软折行后照常放行
    assert _resource_overclaims("结论：“resource 参数问题绕不开”。")
    # R5 复审：旧句只加引号、以及"应写成『…』"这类肯定句，照样要抓
    assert _resource_overclaims("它在 OAuth 请求里带 RFC 8707 的 `resource` 参数，“Cognito 不支持”，换 token 时报错。")
    assert _resource_overclaims("它带 `resource` 参数，「Cognito 不支持」。")
    assert _resource_overclaims("结论应写成「resource 参数问题绕不开」。")
    assert not _resource_overclaims("别把这条读成「resource 参数问题绕不开」。")
    assert _resource_overclaims("结论应说成「resource 参数问题绕不开」。")
    assert _resource_overclaims("应读成「resource 参数问题绕不开」。")
    assert not _resource_overclaims("不能写成「resource 参数问题绕不开」。")
    assert not _resource_overclaims("不要说成「resource 参数问题绕不开」。")
    assert not _resource_overclaims("不应该写成「resource 参数问题绕不开」。")
    # 局部强调 / 引号（R7 复审）
    for fmt in ("带 `resource` 参数，**Cognito** 不支持，换 token 失败。",
                "带 `resource` 参数，Cognito **不支持**，换 token 失败。",
                "| 免代理方案 | 无（**`resource`** 参数问题绕不开） |",
                "它发的 `resource` 参数 *Cognito* 不认。"):
        assert _resource_overclaims(fmt), f"只改格式的旧句没被拦住：{fmt}"
    # 否定管不过转折（R6 复审）
    assert _resource_overclaims("不是 scope 问题而是「resource 参数问题绕不开」。")
    assert _resource_overclaims("不能写成「scope 缺失」而应写成「resource 参数问题绕不开」。")
    assert _resource_overclaims("结论：“任何用 Cognito 当 authorization server 的都会遇到”。")
    assert not _resource_overclaims("不能断言『任何用 Cognito 当 authorization server 的\n都会遇到』。")


# ── 仍然成立的限制不能随过程记录一起删掉（R2 复审）────────────────────────

def test_deploy_md_says_the_cdk_toolchain_is_unpinned_while_it_is():
    """README 重写时删掉了"源码不固定 CDK 工具链"那段（连同单账号的版本表），而事实没变。

    判据跟着事实走：只要还在用 `aws-cdk@latest`、或 deployer 的 `aws-cdk-lib` 不是精确钉死，
    DEPLOY.md 的「本机工具链」与「已知限制」就必须说。全部钉死之后这条自动放行。
    """
    deploy = _read(DEPLOY)
    req = _read(ROOT / "site-builder" / "deployer" / "infra" / "requirements.txt")
    unpinned = "aws-cdk@latest" in deploy or not re.search(r"^aws-cdk-lib==", req, re.M)
    if not unpinned:
        return
    assert "不随源码固定" in _section(deploy, "### 本机工具链"), \
        "「本机工具链」没说 CDK CLI / aws-cdk-lib 的版本不随源码固定"
    assert "CDK 工具链" in _section_lead(_section(deploy, "## 已知限制（向使用方说明）")), \
        "「已知限制」清单里没有 CDK 工具链不固定这一条"


def _console_called_optional(text: str) -> list:
    """把控制台说成「可选」、却没在**同一语义单元的同一句**里交代验收要求它的句子。

    以冒号结尾的引导句（"两个可选组件："）管到紧跟其后的每个列表项——那是 R2 修掉的
    原句形态，逐单元判时引导句与列表项各不沾边，必须拼起来看。
    """
    out, lead, parents = [], "", []      # parents：[(缩进, 以冒号结尾的父列表项)]
    headings = []                         # [(级别, 标题)]：子标题继承上级标题（R10 复审）
    for indent, raw in _prose_units(text, with_indent=True):
        unit = _plain(raw)      # 强调 / 引号只是排版（R7 复审："「两个可选组件：」"）
        if unit.startswith("#"):
            level = len(unit) - len(unit.lstrip("#"))
            headings = [(lv, h) for lv, h in headings if lv < level]
            own = unit
            title = unit.lstrip("#").strip().rstrip("：:").strip()   # "### 控制台（…）：" 这种标签式标题
            # 只让**组件名式的子标题**继承上级标题（"## 两个可选组件" 下的 "### 控制台"）：短、不成句。
            # 正文段落与成句的子标题不继承——DEPLOY「⑤c API Key 组件（可选）」一节里的
            # "### 首次部署后开关是关的，要去控制台开一次"说的是控制台这个**地方**，不是把它列进可选组。
            if len(title) <= 40 and not re.search(r"[，。；：,;]", title):
                unit = "".join(h for _, h in headings) + unit
            headings.append((level, own))
        if re.match(r"^(?:[-*+]|\d+[.)])\s", raw):
            # 以冒号结尾的**父列表项**（"- 两个可选组件："）只管到它自己的子项：同级或更外层的
            # 下一项出现时出栈（R8 复审）
            parents = [(i, p) for i, p in parents if i < indent]
            ends_with_colon = unit.rstrip().endswith(("：", ":"))
            own = unit
            unit = lead + "".join(p for _, p in parents) + unit
            if ends_with_colon:
                parents.append((indent, own))
        elif "|" in unit:
            # 引导句同样管到紧随的**表格行**（R6 复审：旧清单改写成"组件 | 说明"表格即漏报）；
            # 挂在父列表项下面的表格也一样（R9 复审）；可选组之外的外层表格退出父作用域
            parents = [(i, p) for i, p in parents if i < indent]
            unit = lead + "".join(p for _, p in parents) + unit
        else:
            parents = []
            # 引导句加了强调、引号或写成标题（"### 两个可选组件"）——都管到紧随的列表项
            # （R5 复审：只认"以冒号结尾"时这些改写都漏掉）
            lead = unit if unit.rstrip().endswith(("：", ":")) or unit.startswith("#") else ""
        out += [x.strip()[:90] for x in re.split(r"[。；]", unit)
                if ("控制台" in x or "⑤b" in x) and "可选" in x and "验收" not in x]
    return out


def test_docs_do_not_call_the_console_optional_while_acceptance_needs_it():
    """验收集要求控制台在（`verify_deployed_components.py` 无条件查 panel、`verify_console_e2e.py`
    整条打它），而改写后的 README / DEPLOY.md 把它标成了「可选组件」——照着跳过它的采用者
    过不了同一本手册定义的完成条件（R2 复审）。验收集不再要求它时，这条自动放行。"""
    accept = _section(_read(DEPLOY), "## ⑦ 部署后验收")
    if "verify_console_e2e.py" not in accept:
        return
    offenders = [f"{p.name}: {x}" for p in (README, DEPLOY) for x in _console_called_optional(_read(p))]
    assert not offenders, "这些句子把控制台说成可选，却没说验收要求它：\n  " + "\n  ".join(offenders)


def test_console_optional_guard_fires_on_the_old_wording():
    assert _console_called_optional("两个可选组件：\n\n- **控制台**（`console.x`）：在网页上看站点。")
    # 引导句加粗 / 写成标题（R5 复审）
    assert _console_called_optional("**两个可选组件：**\n\n- **控制台**（`console.x`）：在网页上看站点。")
    assert _console_called_optional("### 两个可选组件\n\n- **控制台**（`console.x`）：在网页上看站点。")
    for lead in ("「两个可选组件：」", "“两个可选组件：”", "*两个可选组件：*", "__两个可选组件：__",
                 "两个可选组件\n======", "两个可选组件\n------"):
        assert _console_called_optional(lead + "\n\n- **控制台**：在网页上看站点。"), lead
        assert not _console_called_optional(
            lead.replace("两个可选组件", "另外两个组件") + "\n\n- **控制台**：在网页上看站点。"), lead
    # 父列表项作引导句、原两项缩进成子列表（R8 复审），三种列表标记
    for mark in ("-", "*", "1."):
        nested = f"{mark} 两个可选组件：\n  - **控制台**：在网页上看站点。\n  - **API Key**：默认不部署。\n"
        assert _console_called_optional(nested), mark
        assert not _console_called_optional(nested.replace("两个可选组件", "另外两个组件")), mark
        # 引用块里的父子列表（R9 复审：缩进要在 `>` 之后量）
        assert _console_called_optional("".join("> " + ln + "\n" for ln in nested.splitlines())), mark
        # 父列表项下面的表格（有 / 无首尾竖线）
        for tbl in ("  | 组件 | 说明 |\n  |---|---|\n  | 控制台 | 网页管理 |\n",
                    "  组件 | 说明\n  --- | ---\n  控制台 | 网页管理\n"):
            assert _console_called_optional(f"{mark} 两个可选组件：\n\n" + tbl), mark
            assert not _console_called_optional(f"{mark} 另外两个组件：\n\n" + tbl), mark
        assert _console_called_optional("".join(">> " + ln + "\n" for ln in nested.splitlines())), mark
        # 可选组结束后的外层表格不受父项引导句影响
        assert not _console_called_optional(
            f"{mark} 两个可选组件：\n  - **API Key**：默认不部署。\n\n| 组件 | 说明 |\n|---|---|\n| 控制台 | 标准部署 |\n"), mark
        # 可选组之外的同级项不受父项引导句影响
        assert not _console_called_optional(
            f"{mark} 两个可选组件：\n  - **API Key**：默认不部署。\n{mark} 控制台：标准部署。\n"), mark
    assert not _console_called_optional("### 另外两个组件\n\n- **控制台**：标准部署。\n- **API Key**（可选）。")
    # 引导句 + 表格（R6 复审），有 / 无首尾竖线
    for tbl in ("| 组件 | 说明 |\n|---|---|\n| 控制台 | 网页管理 |\n",
                "组件 | 说明\n--- | ---\n控制台 | 网页管理\n"):
        assert _console_called_optional("两个可选组件：\n\n" + tbl)
        assert not _console_called_optional("另外两个组件：\n\n" + tbl)
    assert _console_called_optional("## ⑤b 自助管理控制台 — panel（**可选**）\n正文。")
    assert _console_called_optional("控制台（⑤b）与\nAPI Key 组件（⑤c）是可选的。")
    assert not _console_called_optional("API Key 组件（⑤c）是可选的；控制台（⑤b）照常部署。")
    assert not _console_called_optional("控制台（⑤b）不是必需的，但「⑦ 部署后验收」要求它。")
    assert not _console_called_optional("```\n 控制台 console · 可选的 API Key\n```")
    # 表格行与列表项各自成单元（R3 复审实测：合并后同表另一行的"验收"豁免了本行的"可选"）
    assert _console_called_optional(
        "| `site-builder/DEPLOY.md` | 部署手册：部署后验收 |\n| `site-builder/panel/` | 控制台（可选） |")
    assert not _console_called_optional("- 控制台：标准部署\n- API Key：可选\n")
    # 引导句写成 H2/H3、两项名称写成下一级标题（R10 复审）
    for top in ("##", "###"):
        sub = top + "#"
        doc = (f"{top} 两个可选组件：\n\n{sub} **控制台**（`console.{{你的域名}}`）：\n\n在网页上看站点。\n\n"
               f"{sub} API Key\n\n默认不部署。\n")
        assert _console_called_optional(doc), top
        assert not _console_called_optional(doc.replace("两个可选组件", "另外两个组件")), top
        # 成句的子标题说的是"去控制台做某事"，不是把控制台列进可选组
        assert not _console_called_optional(f"{top} API Key 组件（可选）\n\n{sub} 首次部署后开关是关的，要去控制台开一次\n")
        # 同级 / 上级标题退出可选组
        assert not _console_called_optional(
            f"{top} 两个可选组件\n\n{sub} API Key\n\n默认不部署。\n\n{top} 控制台\n\n标准部署。\n"), top
    # GFM 表格可省略首尾竖线（R4 复审）：照样逐行判
    no_edge = "路径 | 内容\n--- | ---\n`site-builder/DEPLOY.md` | 部署后验收\n`site-builder/panel/` | 控制台（可选）\n"
    assert _console_called_optional(no_edge)
    assert not _console_called_optional(no_edge.replace("控制台（可选）", "控制台"))
    assert not _console_called_optional(
        "另外两个组件：\n\n- **控制台**：标准部署包含它，验收要求它。\n- **API Key**（可选）：默认不部署。")


def test_claude_md_status_section_points_at_a_tracked_truth_source():
    """CLAUDE.md 状态段必须把「还剩什么」指向一份**被跟踪**的文档。

    上一条只保证"非分发的指针都标了"，它**不**保证真源本身是分发的——把状态段整段
    改成"见 HANDOFF（gitignored）"能同时满足上一条。这条补的正是那个方向，也是 S1
    漂移的实际形状。
    """
    tracked = _tracked_paths()
    status = _section(_read(CLAUDE_MD), "## 项目是什么")

    assert any(m in status for m in NOT_DISTRIBUTED_MARKERS), (
        "状态段没说明 docs/design 那批过程记录不随仓库分发")
    assert "不要把它们当状态真源" in status, (
        "状态段少了「不要把它们当状态真源」这句——这是 S1 漂移的直接成因")

    # 「还剩什么」的真源必须是被跟踪的文件。**按被跟踪判定，不写死文件名**：
    # 换一份 review 文档时这条应该继续成立，而不是要跟着改。
    #
    # **绑到那一**句**，不是那一段**（Codex 复审指出"段里随便找到一个 tracked .md
    # 就算过"太松；我第一次只收紧到"块"，仍然不够——实测把这句改指 HANDOFF 之后
    # 守卫照样全绿，因为同一段里还有 `docs/phase2-requirements.md` 这些被跟踪的
    # 指针替它满足了断言）。判据必须是"**这句话**指向的那份文档被跟踪"。
    assert status.count("**待办与优先级**") == 1, (
        "状态段里「**待办与优先级**」不是恰好一处，定位不了那句声明"
        "——本条空转（措辞被改过？）")
    tail = status.split("**待办与优先级**", 1)[1]
    sentence = tail.split("。", 1)[0]          # 到第一个句号为止
    cited = sorted(_pointers_in(sentence))
    truth = [p for p in cited
             if p.endswith(".md") and _distributed(p, tracked, CLAUDE_MD)]
    assert truth, (
        "「待办与优先级」**这一句**指向的不是一份被跟踪的文档——读者拿不到一份新 "
        f"clone 里真的存在的「还剩什么」清单。这句引用的是：{cited}")


def test_deploy_md_lists_every_production_session_verifier():
    """DEPLOY.md 必须点名**每一个**生产验签点，未知组件也要红。

    这条是 3c spike 抓出来的：DEPLOY.md 从前把 `verify_session_jwt()` 说成只有测试会
    调用它、生产验签只在 Edge。M3/M05 之后 auth 的 `/console-session` 与 panel 的每个写
    请求都成了生产消费方，而注记没跟上。害处很具体——按"只改 Edge 一处"去估非对称化
    （§9 的 3c）的改动范围，会漏掉两个生产验签点。

    **判据两层**：便宜那层禁旧断言的原话；承重那层从源码派生调用点。

    承重那层被绕过一次，两处都修了（Codex 第十三轮）：
      ① 原先用**逐行子串** `"verify_session_jwt(" in line` 找调用 ⇒ 注释、字符串、
         `def` 行都可能混进来。现在走 **AST**，只认真正的 `Call` 节点。
      ② 原先有一张手写的 `owners` 前缀表，落在表外的路径 `continue` **跳过** ⇒
         实测在 `site-builder/mcp/` 放一个被 git 跟踪的新验签点，守卫照样 1 passed。
         **手写前缀表就是手写名单的另一种形态，必然滞后。** 现在**没有豁免**：
         派生出来的每一个调用点，其仓库相对路径都必须出现在 DEPLOY.md 里；
         新组件出现就红，逼一次自觉更新文档，而不是静默漏掉。
    """
    doc = _read(DEPLOY)
    assert "只有测试在用" not in doc, (
        "DEPLOY.md 又出现了「verify_session_jwt 只有测试在用」——"
        "实测有两个生产调用方")

    # 两个名字都算：auth / panel 调的是 `session.verify_token`，Edge 里那份叫
    # `_verify_session_jwt`（Lambda@Edge 不能 import auth 包，所以它是内嵌的另一份实现）。
    # 3c-final 起只剩这两个：`verify_session_jwt` / `verify_with_legacy`（HS 时代的「2 + 1」入口）
    # 已随 legacy 入口一起删除，写在这里只会让派生集合永远差一个空名字。
    wanted = {"verify_token", "_verify_session_jwt"}
    tracked = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
    callers: set[str] = set()
    for rel in tracked:
        path = ROOT / rel
        if "/tests/" in rel or path.name.startswith("test_") or "cdk.out" in rel:
            continue
        if not path.exists():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = (fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute) else None)
            if name in wanted:
                callers.add(rel)
                break

    # 下限：派生集合空了（git ls-files 没跑起来 / AST 判据写错）不能变成空循环的绿
    assert len(callers) >= 3, (
        f"只找到 {sorted(callers)} —— 判据失效？实测应有 Edge、auth、panel 三处")

    for rel in sorted(callers):
        assert rel in doc, (
            f"{rel} 里有生产验签调用，但 DEPLOY.md 没点到它——"
            f"按文档估改动范围会漏掉这个组件。新组件出现就要更新那张表，没有豁免")


# --------------------------------------------------------------------------
# asset-v1 ticket 15：采用者文档不承载验证环境的状态（ADR 0005）
# --------------------------------------------------------------------------
#
# **采用者会读的每一份都在这里**（工单 12 逐份清理后加进来的；加进来的那一刻本条就
# 接管它，所以清理时先加再改）。
#
# **谁不在这里，以及为什么**：
#   · ADR（`docs/adr/*.md`）——日期是这个文体固有的（frontmatter 的 `date:`、
#     "出处：<日期> 定稿"）。清掉等于损坏 ADR，而它本身就是决策记录、不是过程记录。
#   · 决策记录（spec / plan / review / `docs/security/`）——它们**确实**含单账号实测
#     数据与迁移过程，那是它们的价值。它们走另一条路：文件头一句声明说清"不是操作
#     指引"（工单 12 的第 2 条），由 test_decision_records_declare_their_nature 守。
_STATUS_FREE_DOCS = (CLAUDE_MD, README, CONTEXT_MD, DEPLOY, CLIENT_SETUP,
                     SKILL_MD, SKILL_CONTRACT, SKILL_REDLINES)

# 每条一句"为什么它是状态"。命中就是红，判断交给人——这是启发式，不是语义分析；
# 所以模式要窄到不误伤协议说明（"尚未更新的边缘节点"是轮转顺序的解释，不是进度）。
_STATUS_PATTERNS = (
    (r"已部署|已上线|已落地|已实施|已完成部署", "部署完成态是验证环境的事实，资产没有'已部署'"),
    (r"尚未(获|开始|部署|实施|实现|排期|做)", "进度句；'尚未更新的边缘节点'这类协议说明不在射程内"),
    (r"待做|还没做|还剩[^。\n]{0,8}(件|条|个|项)[^。\n]{0,4}没做", "待办只在 §9 与工单里；'还剩什么没做'这个固定短语是文档地图的行名，不在射程内"),
    (r"已修并|已修（|✅", "闭合标记属于 review 表"),
    (r"已于", "'X 已于 <日期>' 是时间线的引导词"),
    (r"首次执行|本机现在|本机做了|本机当前|本机这", "'本机'的环境记录；'本机制'/'本机工具链'不在射程内"),
    (r"ticket \d+ 起|3c-[0-9A-Za-z-]+ 起", "'某票起'是过程标记，采用者没有这些票"),
    (r"下一个包", "顺序与进度住在 spec §6.1 / §11.9 与工单；'下一步是不可逆的删参数'是协议说明，所以不收'下一步'"),
)
_DATE_RE = re.compile(r"(?<!\d)20\d\d-\d\d-\d\d(?!\d)")        # 不用 \b：CJK 与 'T' 都是 \w
_SHA_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{7,40}(?![0-9A-Za-z])")
_PATH_SPAN_RE = re.compile(r"`([\w./@{}*,+:=<>-]+)`")                # 无空格、像路径/标识符的 inline code


def _status_scan_text(txt: str) -> str:
    """围栏**里的内容保留**（命令注释里的'某票起'同样是状态），只去掉围栏标记行本身；
    inline code 只抹掉**像路径的**那种（`docs/superpowers/specs/2026-08-28-…` 里的日期不是状态），
    带空格的 inline code 原样保留——否则反引号就成了写状态的逃生口。"""
    lines = [l for l in txt.splitlines() if not l.lstrip().startswith("```")]
    body = "\n".join(lines)
    return _PATH_SPAN_RE.sub(lambda m: " " if "/" in m.group(1) or m.group(1).endswith(".md") else m.group(0), body)


def _status_violations(txt: str) -> list:
    out = []
    for no, line in enumerate(_status_scan_text(txt).splitlines(), 1):
        for d in _DATE_RE.findall(line):
            out.append((no, "日期", d))
        for h in _SHA_RE.findall(line):
            if re.search(r"[a-f]", h) and re.search(r"\d", h):
                out.append((no, "SHA", h))
        for pat, _why in _STATUS_PATTERNS:
            for m in re.finditer(pat, line):
                out.append((no, "状态词", m.group(0)))
    return out


@pytest.mark.parametrize("doc", _STATUS_FREE_DOCS, ids=lambda p: p.name)
def test_status_free_docs_carry_no_environment_status(doc):
    """CLAUDE.md 是采用者的 Agent 第一个读的文件（ADR 0005）。验证环境的"现在到哪了"——部署日期、
    commit SHA、"已部署 / 尚未 / 待做"——写在这里会牵着后续每个 session 的判断走，而对在自己账号
    部署资产的采用者毫无意义。状态只住 gitignored 的接手点文件与 spec 的状态列。"""
    bad = _status_violations(_read(doc))
    assert not bad, f"{doc.name} 里还有验证环境的状态（行号按去掉围栏标记行后的正文计）：\n  " + \
        "\n  ".join(f"L{no} {kind}: {hit}" for no, kind, hit in bad)


def test_status_guard_matchers_fire_on_each_violation_class():
    """**正对照**：三类匹配器各自能红。日期紧贴中文、ISO 时间戳、8/40 位 SHA、每个状态词、围栏里的
    状态、带空格的 inline code 里的状态——`\\b` 版本对前两类全部漏过，反引号整段抹掉会放过最后一类。"""
    sample = "\n".join([
        "于2026-09-06起生效；T0 = 2026-09-03T13:51:18Z。",
        "见提交 8ee96b4a 与 05797af372f2577fafa5e8fd1ae54a3343d475be。",
        "```bash", "# 3c-1B ticket 18 起还有两个旗标", "```",
        "真源：`2026-09-05 已部署 auth+panel`，见接手点。",
    ] + [f"句子里有{re.sub(r'[|()\\\\dw+\[\]^$?.*{}-]', '', p.split('|')[0])}"
         for p, _ in _STATUS_PATTERNS if not p.startswith("ticket")])
    kinds = {(k, h) for _, k, h in _status_violations(sample)}
    assert ("日期", "2026-09-06") in kinds and ("日期", "2026-09-03") in kinds, kinds
    assert ("SHA", "8ee96b4a") in kinds and any(k == "SHA" and len(h) == 40 for k, h in kinds), kinds
    assert ("状态词", "ticket 18 起") in kinds, "围栏里的状态没被扫到"
    assert ("日期", "2026-09-05") in kinds and ("状态词", "已部署") in kinds, "inline code 成了逃生口"
    for pat, why in _STATUS_PATTERNS:
        if not pat.startswith("ticket"):
            assert any(k == "状态词" and re.fullmatch(pat, h) for k, h in kinds), f"模式没在正对照里触发：{pat}（{why}）"


def test_status_guard_ignores_protocol_prose_and_paths():
    """**负对照**：协议说明与路径不能误红——否则改对的文档会被逼着换措辞。"""
    clean = "\n".join([
        "新签发的 cookie 在尚未更新的边缘节点验签失败——所以 verifier 先行。",
        "本机制分两层；### 本机工具链；给 Claude Code 等本机客户端的 OAuth 用。",
        "见 `docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.9。",
        "`site-builder/scripts/verify_*` 是真机闸门；DSQL endpoint 自拼 `{id}.dsql.{region}.on.aws`。",
        "**待办与优先级**见 §9；还剩什么没做读那张表；而下一步是不可逆的删参数。",
    ])
    assert _status_violations(clean) == [], _status_violations(clean)


# --------------------------------------------------------------------------
# asset-v1 ticket 02：router 栈的 stack policy——每个 router 部署点都要 open → deploy → apply
# --------------------------------------------------------------------------
_CDK_DEPLOY_RE = re.compile(r"aws-cdk@latest deploy")
_ROUTER_CWD_RE = re.compile(r"cd router/infrastructure\b")
_DEPLOYER_CWD_RE = re.compile(r"cd site-builder/deployer/infra\b")


def _fenced_blocks(text: str):
    """(开围栏的行号, 围栏内的行列表)。"""
    lines, inside, start, buf = text.splitlines(), False, 0, []
    for no, ln in enumerate(lines, 1):
        if ln.lstrip().startswith("```"):
            if inside:
                yield start, buf
            inside, start, buf = not inside, no, []
        elif inside:
            buf.append(ln)


def _router_deploy_sites(block: list) -> list:
    """围栏块里哪些行是 **router** 的 `cdk deploy`：同一行或之前最近一次 `cd` 指向 router/infrastructure。
    `(cd … )` 子 shell 闭合后 cwd 归零（一行式当场闭合；带 `\\` 续行的等到以 `)` 结尾的那行）。"""
    sites, cwd, subshell = [], None, False
    for i, ln in enumerate(block):
        s = ln.strip()
        if _ROUTER_CWD_RE.search(ln):
            cwd = "router"
        elif _DEPLOYER_CWD_RE.search(ln):
            cwd = "deployer"
        if _CDK_DEPLOY_RE.search(ln) and cwd == "router":
            sites.append(i)
        if "(cd " in ln and s.endswith(")"):
            cwd = None
        elif "(cd " in ln:
            subshell = True
        elif subshell and s.endswith(")"):
            subshell, cwd = False, None
    return sites


def _unwrapped_router_deploys(text: str, name: str = "doc") -> tuple[int, list]:
    """(找到的 router 部署点数, 违规描述列表)。判定与 test_… 分离，好让合成文本做变形对照。"""
    seen, problems = 0, []
    for start, block in _fenced_blocks(text):
        for i in _router_deploy_sites(block):
            seen += 1
            before, after = "\n".join(block[:i]), "\n".join(block[i + 1:])
            if "router_stack_policy.py open" not in before:
                problems.append(f"{name} L{start + 1 + i}：router 的 cdk deploy 之前没有 open")
            if "router_stack_policy.py apply" not in after:
                problems.append(f"{name} L{start + 1 + i}：router 的 cdk deploy 之后没有 apply")
    fenced = {no for start, block in _fenced_blocks(text) for no in range(start, start + len(block) + 2)}
    for no, ln in enumerate(text.splitlines(), 1):
        if no not in fenced and _ROUTER_CWD_RE.search(ln) and _CDK_DEPLOY_RE.search(ln):
            problems.append(f"{name} L{no}：围栏外（表格）写了 router 的部署命令——改成引用 ② 节")
    return seen, problems


def test_every_router_deploy_site_is_wrapped_by_stack_policy_open_and_apply():
    """stack policy 拒 `Update:*` ⇒ 不先 open 的 router 部署会在 ExecuteChangeSet 阶段失败回滚；
    部署后不 apply 则保护一直开着、只有 verify_deployed_edge.sh ⑤ 会点出来。所以文档里**每一处**
    router 的 `cdk deploy` 都必须在同一个围栏块里前有 open、后有 apply；表格单元格里不许再写
    router 的部署命令（那里放不下三步，改成引用 ② 那一节）。"""
    seen = 0
    for doc in (CLAUDE_MD, DEPLOY):
        n, problems = _unwrapped_router_deploys(_read(doc), doc.name)
        assert problems == [], "\n".join(problems)
        seen += n
    assert seen >= 4, f"只找到 {seen} 处 router 部署点——判据失效？CLAUDE.md 1 处 + DEPLOY.md 至少 3 处"


_WRAPPED_SITE = """intro
```bash
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
(cd site-builder/deployer/infra && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
```
"""


def test_router_deploy_guard_can_fail_on_synthetic_docs():
    """**变形对照**：合成一段合规文本（router 三步 + 紧跟的 deployer 部署不被误认为 router 的），
    再分别去掉 open、去掉 apply、把 router 部署写进表格——每种都必须红，且 deployer 那一行永不计入。"""
    seen, problems = _unwrapped_router_deploys(_WRAPPED_SITE, "synthetic")
    assert (seen, problems) == (1, []), (seen, problems)
    no_open = _WRAPPED_SITE.replace("python3 site-builder/scripts/router_stack_policy.py open\n", "")
    assert any("没有 open" in p for p in _unwrapped_router_deploys(no_open, "synthetic")[1])
    no_apply = _WRAPPED_SITE.replace("python3 site-builder/scripts/router_stack_policy.py apply\n", "")
    assert any("没有 apply" in p for p in _unwrapped_router_deploys(no_apply, "synthetic")[1])
    table = _WRAPPED_SITE + "| ② | 路由层 | `cd router/infrastructure && npx -y aws-cdk@latest deploy` |\n"
    assert any("围栏外" in p for p in _unwrapped_router_deploys(table, "synthetic")[1])
    # 多行子 shell：`(cd router/infrastructure && \` 续行后以 `)` 收尾，收尾后的 deployer 部署不算 router 的
    multiline = """```bash
python3 site-builder/scripts/router_stack_policy.py open
(cd router/infrastructure && rm -rf cdk.out && \\
   PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
python3 site-builder/scripts/router_stack_policy.py apply
(cd site-builder/deployer/infra && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy)
```
"""
    assert _unwrapped_router_deploys(multiline, "synthetic") == (1, [])


# --------------------------------------------------------------------------
# asset-v1 工单 08：HS256 时代的词汇只许留在决策记录里
# --------------------------------------------------------------------------
#
# 会话签名改成 KMS RS256 之后，最贵的一类残留不是"少写了一句新话"，而是"旧话还在"：
# 采用者照着 `ensure_session_keys.py` / `jwt-secret` / `signer = legacy` 去做，得到的是
# **不存在的脚本、不存在的参数、加载器会硬拒的配置组合**——而每一条读起来都像正确的指令。
# 所以这条守卫扫全仓，不扫一张文档清单。
_HS_ERA_TOKENS = ("HS256", "jwt-secret", "JWT_SECRET", "SESSION_SIGNER", "LEGACY_ENTRY", "legacy_param",
                  "mint_session_jwt", "verify_with_legacy", "ensure_session_keys", "migrate_sites_to_blue_green",
                  "--drain-gate legacy", "signer = legacy", "signer = current")
# 决策记录允许出现（文件头声明性质）；采用者文档不许
_HS_ALLOWED_PREFIXES = ("docs/superpowers/", "docs/reviews/", "docs/adr/", "docs/security/3c-", ".scratch/")

# **逐路径**例外：这些文件带禁用词是因为它们**拒绝**这些名字（反向断言、否定用例、
# 已删符号清单）。删掉否定用例、或为了躲开 grep 去混淆代码，都比留下这份清单更糟。
# 每条一句"它为什么必须提到旧名字"。
_HS_EXEMPT_PATHS = {
    "site-builder/auth/session_keys.py":
        "`REMOVED_KEYS` 要点名 legacy_param / signer 才能对写着旧键的 config 报出可读的错",
    "site-builder/auth/tests/test_session_keys.py":
        "否定用例把已删的键注进 config，断言加载器硬拒",
    "site-builder/auth/tests/test_deploy_auth_sequence.py":
        "反向断言：HS 时代那三个 env 键必须从 lambda_env 里彻底消失",
    "site-builder/auth/tests/test_secret_loading.py":
        "反向断言：三个已删 env 键不许出现在 auth 的 lambda_env / 源码里",
    "site-builder/auth/tests/test_pkce.py":
        "变形用例把 login-flow 的取值改回会话密钥名，证明守卫会咬",
    "site-builder/auth/tests/test_signer_guard.py":
        "`FORBIDDEN_NAMES` 是已删签发/验签函数名的清单，AST 守卫按它咬",
    "site-builder/auth/tests/test_verifier_allowlist.py":
        "否定参数：allowlist 必须拒 HS256 等非 RS256 alg",
    "router/infrastructure/lambda/test_edge_kid_allowlist.py":
        "自带禁用词清单，断言 Edge 源码里不再出现它们",
    "router/infrastructure/lambda/test_stack_static.py":
        "反向断言两个注入点已消失 + 否定参数 bad_alg=HS256",
    "site-builder/scripts/verify_deployed_components.py":
        "真机反向断言：线上产物里出现这些名字即判「部的是 3c-final 之前的代码」",
    "site-builder/scripts/verify_deployed_edge.sh":
        "同上，Edge 产物那一半",
    "site-builder/deployer/tests/test_verify_deployed_components.py":
        "上面那条闸门的用例，正负两侧都要拿旧名字造样本",
    "site-builder/deployer/tests/test_verify_deployed_edge_static.py":
        "同上，Edge 那一半",
    "site-builder/deployer/tests/test_verify_account_trust_boundary.py":
        "`test_hs_era_symbols_are_gone` 点名已删符号 + 解析用例里的样例 SSM ARN",
    "site-builder/deployer/tests/test_session_verify_counts.py":
        "反向断言：`--drain-gate legacy` 这个旗标与 accepted_legacy 列都必须不存在",
    "site-builder/panel/tests/test_console_session.py":
        "反向断言：三个 HS 时代 env 键不许出现在 panel 的环境里",
    "site-builder/panel/tests/test_deploy_panel_contract.py":
        "反向断言：3c-final 删掉的三个 env 键靠等值清单挡回来",
    "site-builder/panel/tests/test_handler.py":
        "反向断言：panel 源码里不许再有本地签发函数",
    "site-builder/deployer/tests/test_delivery_docs_current.py":
        "本文件——`_HS_ERA_TOKENS` 自己就是那张清单",
    "docs/security/account-trust-boundary.md":
        "威胁模型真源：HS 形态那一节是显式标了「历史记录」的对照，"
        "另由 test_threat_model_marks_the_hs_era_section_historical 守着标记还在",
}


def _hs_era_hits(paths) -> list:
    hits = []
    for rel in paths:
        if rel.startswith(_HS_ALLOWED_PREFIXES) or rel in _HS_EXEMPT_PATHS:
            continue
        if not rel.endswith((".md", ".py", ".sh", ".ini", ".example", ".txt", ".yaml", ".yml")):
            continue
        path = ROOT / rel
        if not path.exists():          # 已删但索引里还在（rename 中途）
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for tok in _HS_ERA_TOKENS:
            if tok in text:
                hits.append(f"{rel}: {tok}")
    return hits


def _tracked_files() -> list:
    return subprocess.run(["git", "ls-files"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.split()


def test_adopter_docs_and_code_carry_no_hs_era_vocabulary():
    """3c-final 之后 HS256 / legacy 入口 / signer 开关只存在于决策记录里（spec / review / ADR）。

    采用者文档（CLAUDE.md、README、DEPLOY.md、client-setup、skills、CONTEXT.md）与全部源码 /
    测试都不许再提——例外只有 `_HS_EXEMPT_PATHS` 里那些"因为要拒绝旧名字所以必须写出它"的文件。
    """
    tracked = _tracked_files()
    assert len(tracked) > 50, f"git ls-files 只给了 {len(tracked)} 个文件——本条空转"
    hits = _hs_era_hits(tracked)
    assert not hits, "HS/legacy 词汇残留（要么删掉，要么它属于决策记录并搬到允许的目录）：\n  " + \
        "\n  ".join(hits)


def test_hs_era_exemption_list_cannot_go_stale():
    """例外清单只许列**真的存在、且真的还带禁用词**的文件。

    没有这一条，清单会变成"曾经需要例外"的墓地：文件改干净了、甚至被删了，条目还留着，
    于是下一次真的有人往那个文件里写回 `jwt-secret`，守卫默默放过。
    """
    tracked = set(_tracked_files())
    stale = []
    for rel, why in _HS_EXEMPT_PATHS.items():
        assert why.strip(), f"{rel} 的例外没写理由"
        if rel not in tracked:
            stale.append(f"{rel}: 不在 git 索引里（删了/改名了？把条目一起删）")
            continue
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        if not any(tok in text for tok in _HS_ERA_TOKENS):
            stale.append(f"{rel}: 已经不含任何禁用词了 —— 例外条目该删（否则它成了永久豁免）")
    assert not stale, "例外清单过期：\n  " + "\n  ".join(stale)


def test_hs_era_guard_bites_a_synthetic_leftover():
    """**变形对照**：给一个既不在允许前缀、也不在例外清单里的路径塞一个禁用词，必须命中；
    允许前缀与例外清单必须仍然放过。证明上面那条不是靠空集合过的。"""
    real = "site-builder/DEPLOY.md"
    assert real in set(_tracked_files()), "锚点文件不在索引里——本条空转"
    assert _hs_era_hits([real]) == [], "DEPLOY.md 现在应当是干净的——本条前提不成立"
    assert _hs_era_hits(["docs/superpowers/specs/whatever.md"]) == [], "允许前缀被误伤"
    exempt = next(iter(_HS_EXEMPT_PATHS))
    assert _hs_era_hits([exempt]) == [], "例外清单没生效"
    # 真正的变形：把禁用词写进一个**不受豁免**的路径
    victim = ROOT / "site-builder" / "DEPLOY.md"
    original = victim.read_text(encoding="utf-8")
    try:
        victim.write_text(original + "\n照着 ensure_session_keys.py 建 jwt-secret。\n", encoding="utf-8")
        hits = _hs_era_hits([real])
        assert any("jwt-secret" in h for h in hits) and any("ensure_session_keys" in h for h in hits), hits
    finally:
        victim.write_text(original, encoding="utf-8")


def test_threat_model_marks_the_hs_era_section_historical():
    """威胁模型文档在例外清单里，所以那份文档的 HS 形态段落**必须自带「已被取代」标记**——
    否则例外就等于让一整份文档回到无人看管的状态，而它恰好是"平台防谁"的真源。"""
    doc = _read(ROOT / "docs" / "security" / "account-trust-boundary.md")
    sec = _section(doc, "## 密钥有三条路能拿到，三条都实测可用")
    assert any(m in sec for m in _SUPERSEDED_MARKERS), (
        "「密钥有三条路能拿到」这一节没有 superseded / 历史记录 标记——"
        f"读者会把 HS 形态当成现状。认可的标记：{_SUPERSEDED_MARKERS}")
    assert "HS256" in sec, "标记在，但这一节已经不谈 HS 形态了——标记该跟着走"


# ---- 配置键与就绪清单的对账（merged review M22）-------------------------------------------

def test_deploy_md_readiness_lists_the_alert_recipient():
    """`[Alerting] email` 为空时 `deploy_auth.py` 响亮失败（`alarm_pipeline` 抛 ValueError），
    而 §0 的就绪清单从前没列它：采用者按 §0 备齐一切、到 ① 才被一个没听说过的键拦下。
    两处都要有：§0 正文（讲清"要有人能收信并点 SNS 确认链接"与 `SB_ALERT_EMAIL` 这条覆盖路径）
    与「部署顺序总览」末尾那份 checklist。"""
    doc = _read(DEPLOY)
    sec0 = _section(doc, "## 0. 前置要求（全部备齐才开始）")
    assert "[Alerting]" in sec0 and "SB_ALERT_EMAIL" in sec0, "§0 没提告警收件人"
    assert "确认" in sec0 and "deploy_auth.py" in sec0, "§0 要讲清订阅须手工确认、缺它 deploy_auth.py 会失败"
    overview = _section(doc, "## 部署顺序总览")
    checklist = overview[overview.index("开始前的就绪清单"):]
    assert "[Alerting]" in checklist, "「开始前的就绪清单」没列 [Alerting] email"


def test_deploy_md_does_not_document_config_keys_that_nothing_reads():
    """M22 的三个死键（`[Panel] ops_log_table` / `session_codes_table`、`[ApiKey] keys_table`）从
    `.example` 删了：表名由 deployer 栈按字面量建、部署脚本按同一字面量下发，不是配置项。
    文档若还把它们列成"要回填的字段"，采用者会去填一个不存在的键。否定断言覆盖整个文件。"""
    doc = _read(DEPLOY)
    for key in ("ops_log_table", "session_codes_table"):
        assert key not in doc, f"DEPLOY.md 还在提已删除的配置键 {key}"
    assert not re.search(r"(?<![_a-z])keys_table\b", doc), "DEPLOY.md 还在提已删除的配置键 keys_table"



# --------------------------------------------------------------------------
# asset-v1 ticket 13：验收打包（spec §11.9 第 2、8 条）——采用者部署完"怎么知道它对"
# --------------------------------------------------------------------------
#
# DEPLOY.md 的最后一步是**分发的验收集**：`verify_deployed_*` + `smoke_router` + 四个 `verify_*`。
# E2E 是开发者回归、账号信任边界闸门与冒充面探针是可选自检——三者都不在验收集里，但各有自己的
# 小节（读者要能找到它们，只是不该把它们当成"部署对不对"的判据）。
ACCEPTANCE_HEADING = "## ⑦ 部署后验收"
ACCEPTANCE_SET_HEADING = "### 验收集（按这个顺序跑）"
DEVELOPER_REGRESSION_HEADING = "### 开发者回归（不在验收集里）"
TRUST_BOUNDARY_HEADING = "### 可选：账号信任边界自检"

# spec §11.9 第 2 条的原话展开；"四个 verify_*" 的成员以「夹具站点与验收前置」一节点名的为准。
DISTRIBUTED_GATES = (
    "verify_deployed_components.py", "verify_deployed_edge.sh", "smoke_router.sh",
    "verify_console_e2e.py", "verify_analytics_e2e.py", "verify_api_key_e2e.py",
    "verify_session_token_semantics.py",
)
# 在验收集的**围栏块**里出现即红（散文里提一句"E2E 见开发者回归"是允许的，那是指针不是清单项）。
NOT_IN_ACCEPTANCE_SET = (
    "RUN_E2E", "test_e2e_fixtures.py",
    "verify_account_trust_boundary.py", "probe_impersonation_surface.py",
    "verify_kid_entry_live.py", "session_verify_counts.py",
)
_FULL_E2E_RE = re.compile(r"test_e2e_fixtures\.py\s+-q")   # 全量 E2E；④ 的单条冒烟带 `::test_…`，不算


def _fenced_text(text: str) -> str:
    """只取围栏代码块里的内容——验收集"只列这些"的判据看命令，不看散文。"""
    return "\n".join("\n".join(block) for _, block in _fenced_blocks(text))


def _acceptance_set_violations(doc: str) -> list:
    """判定与 test_… 分离，好让合成文本做正负对照。

    **"不多不少"要两侧都有断言**：白名单在场 + 黑名单缺席只证明了"不少"——往围栏里加一条
    `verify_permission_matrix.py` / `verify_site_table_integrity.py` 照样全绿，而采用者会把
    多出来的那条当成必过项。所以按围栏里出现的 `site-builder/scripts/<名字>` 抽出**实际集合**
    与清单做等值比较（`origin_request.py`、`site-builder/config.ini` 都不在 `scripts/` 前缀下，
    不会误入）。
    """
    cmds = _fenced_text(_section(doc, ACCEPTANCE_SET_HEADING))
    names = set(re.findall(r"site-builder/scripts/([\w.-]+)", cmds))
    out = [f"验收集里没列 {g}" for g in sorted(set(DISTRIBUTED_GATES) - names)]
    out += [f"验收集里混进了 {t}" for t in NOT_IN_ACCEPTANCE_SET if t in cmds]
    out += [f"验收集里多出 {n}（不在七条分发闸门里）" for n in sorted(names - set(DISTRIBUTED_GATES))]
    # **每条都要无条件执行**：包在 `if …; then` 里的命令不跑时 bash 仍退 0，"七条全绿"就成了"六条 + 一条没跑"。
    # 组件缺席由脚本自己表达（verify_api_key_e2e 无 [ApiKey] 段 ⇒ PASS 组件缺席、退 0），不由外层条件表达。
    for line in cmds.splitlines():
        if re.match(r"\s*(if|elif|case)\b", line) or re.match(r"\s+(python3|bash) site-builder/scripts/", line):
            out.append(f"验收集里有条件执行 / 缩进的命令：{line.strip()!r}——每条闸门必须顶格无条件执行")
    for g in DISTRIBUTED_GATES:
        if not re.search(rf"^(python3|bash) site-builder/scripts/{re.escape(g)}( |$)", cmds, re.M):
            out.append(f"{g} 在验收集里不是顶格无条件的一条命令")
    return out


def test_deploy_md_acceptance_set_lists_exactly_the_distributed_gates():
    """采用者部署完最需要的一句话是"怎么知道它对"——答案是一个围栏块，七条命令，不多不少。
    多一条（E2E、信任边界闸门）会让采用者把开发者工具当成必过项；少一条则漏验一层。"""
    doc = _read(DEPLOY)
    _section(doc, ACCEPTANCE_HEADING)          # 标题被改名时在这里自报空转
    assert _acceptance_set_violations(doc) == [], _acceptance_set_violations(doc)
    # fail-fast 是这个围栏块的语义前提：第一条红了还继续跑，采用者会拿着半套结果当"验收通过"。
    cmds = _fenced_text(_section(doc, ACCEPTANCE_SET_HEADING))
    assert cmds.strip().splitlines()[0].strip() == "set -euo pipefail", \
        f"验收集围栏的第一行不是 set -euo pipefail，而是 {cmds.strip().splitlines()[0]!r}"
    assert "|| true" not in cmds, "验收集里有 `|| true`——它把失败吞成绿"


def test_acceptance_set_guard_fires_on_missing_and_on_smuggled_entries():
    """**正负对照**：漏一条要红、围栏里混进开发者工具要红、散文里提到不算混进。"""
    good = "\n".join(
        [ACCEPTANCE_HEADING, "", ACCEPTANCE_SET_HEADING, "",
         "E2E（RUN_E2E）不在这里，见开发者回归。", "", "```bash"]
        + [f"python3 site-builder/scripts/{g}" for g in DISTRIBUTED_GATES]
        + ["```", "", DEVELOPER_REGRESSION_HEADING, "", "```bash",
           "RUN_E2E=1 pytest test_e2e_fixtures.py -q", "```"])
    assert _acceptance_set_violations(good) == [], _acceptance_set_violations(good)
    missing = good.replace("python3 site-builder/scripts/smoke_router.sh\n", "")
    assert any("smoke_router.sh" in v for v in _acceptance_set_violations(missing))
    smuggled = good.replace("```\n\n" + DEVELOPER_REGRESSION_HEADING,
                            "RUN_E2E=1 pytest test_e2e_fixtures.py -q\n```\n\n" + DEVELOPER_REGRESSION_HEADING, 1)
    hits = _acceptance_set_violations(smuggled)
    assert any("RUN_E2E" in v for v in hits) and any("test_e2e_fixtures.py" in v for v in hits), hits
    # **多列一条**（黑名单之外的真实闸门）同样要红——否则"不多不少"只有一半有断言。
    extra = good.replace("```\n\n" + DEVELOPER_REGRESSION_HEADING,
                         "python3 site-builder/scripts/verify_permission_matrix.py\n```\n\n"
                         + DEVELOPER_REGRESSION_HEADING, 1)
    assert any("verify_permission_matrix.py" in v for v in _acceptance_set_violations(extra)), \
        _acceptance_set_violations(extra)
    # **条件执行**同样要红：包进 `if grep …; then … fi` 的那条不跑时 bash 仍退 0（Codex review P2）。
    guarded = good.replace("python3 site-builder/scripts/verify_api_key_e2e.py",
                           "if grep -q '^\\[ApiKey\\]' site-builder/config.ini; then\n"
                           "  python3 site-builder/scripts/verify_api_key_e2e.py\nfi", 1)
    hits = _acceptance_set_violations(guarded)
    assert any("条件执行" in v for v in hits) and any("verify_api_key_e2e.py" in v and "顶格" in v for v in hits), hits


def test_deploy_md_acceptance_section_gives_an_acquisition_path_for_every_prerequisite():
    """全新账号里每个分发脚本的前置条件都要有**获取路径**（工单 13 的第二句）：
    登录态 → `[Verification]`（本机凭据列进 verifier_trusted_principals，改完重跑 deploy_auth.py）
    + `ensure_fixture_site.py`；用户 OAuth token → `quick-desktop-proxy/auth.js`；
    可选组件 → `[ApiKey]` 决定 verify_api_key_e2e.py 跑不跑。缺任一项，采用者会把"前置没备齐"
    读成"部署坏了"。"""
    sec = _section(_read(DEPLOY), ACCEPTANCE_HEADING)
    for needle, why in (
        ("[Verification]", "夹具签发器的开关"),
        ("verifier_trusted_principals", "本机凭据要列进信任名单，否则 assume 不了 verifier 角色"),
        ("ensure_fixture_site.py", "常驻夹具站点"),
        ("deploy_auth.py", "改了 [Verification] 要重部 auth 才生效"),
        ("quick-desktop-proxy/auth.js", "verify_analytics_e2e.py 的 MCP 段要真实用户 OAuth token"),
        ("[ApiKey]", "可选组件缺席时 verify_api_key_e2e.py 无对象"),
    ):
        assert needle in sec, f"部署后验收一节没写 {needle}（{why}）"


def test_deploy_md_full_e2e_lives_only_in_developer_regression():
    """E2E 移到「开发者回归」，且全量 E2E 命令**只**在那里出现（否定断言覆盖整份文档）。
    ④ 里手工触发一条 `::test_static_site_public_200` 当执行器冒烟不算全量。"""
    doc = _read(DEPLOY)
    dev = _section(doc, DEVELOPER_REGRESSION_HEADING)
    assert "RUN_E2E=1" in dev and _FULL_E2E_RE.search(dev), "开发者回归一节没有全量 E2E 命令"
    assert len(_FULL_E2E_RE.findall(doc)) == len(_FULL_E2E_RE.findall(dev)), \
        "全量 E2E 命令还出现在「开发者回归」之外"
    assert re.search(r"端到端彩排|⑦\s*彩排", doc) is None, \
        "旧的 ⑦ 叫法还在（含「⑦ 彩排」这种带空格、无「端到端」的写法）——总览箭头图或正文没同步"


def test_deploy_md_trust_boundary_self_check_is_optional_and_says_first_run_and_duration():
    """账号信任边界闸门与冒充面探针是**可选**自检（§11.9 第 8 条）：小节要写明首跑只能
    `--update-baseline` 生成基线、不出结论（基线不随资产分发），以及耗时——不写耗时，
    采用者会在第 3 分钟把它当成挂死杀掉。"""
    sec = _section(_read(DEPLOY), TRUST_BOUNDARY_HEADING)
    for needle in ("verify_account_trust_boundary.py", "probe_impersonation_surface.py",
                   "--update-baseline", "分钟", "--dump-observed"):
        assert needle in sec, f"可选自检一节没写 {needle}"
    assert re.search(r"首跑|第一次跑", sec), "没写明首跑的语义（只能生成基线，不能出结论）"
    assert re.search(r"不出结论|不能出结论", sec), "没写明首跑不出结论"


def test_deploy_md_acceptance_section_is_status_free():
    """DEPLOY.md 整体进 `_STATUS_FREE_DOCS` 归工单 12；新写的验收一节从第一天起就按那条守——
    它是采用者部署完读的最后一节，日期 / SHA / "已部署" 在这里比在别处更误导。"""
    bad = _status_violations(_section(_read(DEPLOY), ACCEPTANCE_HEADING))
    assert not bad, "部署后验收一节里有验证环境的状态：\n  " + \
        "\n  ".join(f"L{no} {kind}: {hit}" for no, kind, hit in bad)


def test_deploy_md_overview_arrow_ends_at_acceptance():
    """总览箭头图的最后一格是 ⑦ 部署后验收（不再是 E2E 彩排）——采用者照箭头走到最后一格
    就该得到"对不对"的答案。"""
    sec = _section(_read(DEPLOY), "## 部署顺序总览")
    assert "⑦部署后验收" in sec, "箭头图最后一格不是 ⑦部署后验收"


# ── 工单 07：ADR 0006 的实现机理措辞（决策没变，只修机理 ⇒ 不 supersede）──────

ADR_0006 = ROOT / "docs" / "adr" / "0006-built-in-cognito-admin-created-users-idp-mode.md"


def test_adr_0006_names_the_real_email_immutability_mechanism():
    """ADR 0006 原文写的"应用客户端对 `email` 只读"**按字面做不出来**（工单 06 Q3
    实测）：显式给出的 WriteAttributes 必须包含全部 Required=True 属性，
    `["name"]` 被 InvalidParameterException 拒，而 `["email","name"]` 反而被接受。
    真正的实现点是用户池 schema 的 `Mutable=False`。

    ADR 是 accepted 状态的 tracked 决策文档，读它的人会照着实现 ⇒ 机理写错的代价
    是有人去配 WriteAttributes 并以为拿到了一条边界。**决策没变，所以不 supersede。**
    """
    doc = _read(ADR_0006)
    assert "Mutable" in doc, "ADR 0006 没点名 schema 的 Mutable=False（真实实现点）"
    assert "邮箱属性对应用客户端不可写" not in doc, \
        "ADR 0006 还留着按字面做不出来的那句措辞"
    # 提到 WriteAttributes 时必须是"它不是防线"的意思
    for i, line in enumerate(doc.splitlines()):
        if "WriteAttributes" in line:
            assert "不是" in line, f"ADR 0006:{i + 1} 把 WriteAttributes 说成了防线"


def test_adr_0006_no_longer_says_the_mode_is_unimplemented():
    """模式已落地 ⇒ "待实现"是过时口径（否定断言覆盖整份文件）。"""
    doc = _read(ADR_0006)
    for stale in ("待实现", "07 实现"):
        assert stale not in doc, f"ADR 0006 还写着 {stale!r}"


# ── 工单 07：DEPLOY.md 第 3 条路（内置 Cognito）已脚本化 ─────────────────────

BUILT_IN_COGNITO_HEADING = "### 【内置 Cognito】第二个池的确切形态"


def test_deploy_md_built_in_cognito_path_is_scripted_not_manual():
    """第 3 条路的门槛就是这一节：它必须给出**配置 + 一条命令**，而不是一串
    aws cognito-idp create-* 让采用者手工建池。"""
    doc = _read(DEPLOY)
    sec = _section(doc, BUILT_IN_COGNITO_HEADING)      # 标题改名时自报空转
    assert "mode = cognito-admin" in sec
    assert "cognito_user_pool_name" in sec and "cognito_domain_prefix" in sec
    assert "deploy_pool.py" in sec, "这一节没告诉读者是哪个脚本建的"
    # 三个派生字段不许再出现在"要填的 [IdP]"清单里
    for derived in ("issuer =", "client_id ="):
        assert f"{derived} <" not in sec, \
            f"这一节还在让采用者填 {derived}——内置模式下它由部署过程派生"
    # 否定断言覆盖整份文件：占位口径不许残留在任何地方
    for stale in ("目前依赖工单 07", "尚未落地", "在那之前按本节手工建"):
        assert stale not in doc, f"DEPLOY.md 还留着占位口径 {stale!r}"


def test_deploy_md_keeps_the_two_admin_create_user_commands():
    """建户不进脚本（裁定 3）⇒ 手册必须留这两条，且必须带 --permanent
    与 email_verified=true——少第二条用户停在 FORCE_CHANGE_PASSWORD，
    少 email_verified 则 require_email_verified 把他挡在 /callback。"""
    sec = _section(_read(DEPLOY), BUILT_IN_COGNITO_HEADING)
    assert "admin-create-user" in sec
    assert "admin-set-user-password" in sec and "--permanent" in sec
    assert "email_verified,Value=true" in sec
    assert "SUPPRESS" in sec


def test_deploy_md_readiness_for_built_in_cognito_is_config_only():
    """就绪清单是**开始部署前**的检查。内置模式下"第二个池"是 ① 建出来的产物，
    所以这一条的前置只能是配置 + 前缀可用，不能要求池已存在
    （旧文案要求"第二个池 + 托管域名 + app client 已建"，那是手工时代的口径）。"""
    doc = _read(DEPLOY)
    overview = _section(doc, "## 部署顺序总览")
    checklist = overview[overview.index("开始前的就绪清单"):]
    assert "【内置 Cognito】" in checklist, "就绪清单里没有【内置 Cognito】那一条（本条空转）"
    assert "mode = cognito-admin" in checklist
    assert "第二个池 + 托管域名 + app client 已建" not in checklist, \
        "就绪清单还在要求采用者先手工建好池"


# ── 工单 12 第 2 条：决策记录必须自报"不是操作指引" ──────────────────────────
#
# 采用者拿到的仓库里，`docs/superpowers/`、`docs/reviews/`、`docs/security/` 下的
# tracked 文档**确实**含单账号实测数据与当时的迁移过程——那是它们的价值，不该清掉
# （这与 _STATUS_FREE_DOCS 那条方向相反，别混）。风险是采用者把其中某一段当成
# 操作步骤照做：那些步骤是对**当时那个环境**说的。所以每一份自己在文件头声明。
_DECISION_RECORD_GLOBS = ("docs/superpowers/specs/*.md", "docs/superpowers/plans/*.md",
                          "docs/reviews/*.md", "docs/security/*.md")
_DECISION_BANNER = "决策记录，不是操作指引"


def _decision_records() -> list:
    """**按 git 问**，不按硬编码清单：新加一份 spec/plan/review 自动进射程。"""
    import subprocess
    r = subprocess.run(["git", "ls-files", "-z", *_DECISION_RECORD_GLOBS],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"git ls-files 失败（本条空转）：{r.stderr.strip()}"
    out = [f for f in r.stdout.split("\0") if f]
    assert len(out) > 10, f"只找到 {len(out)} 份决策记录——本条空转（glob 写错？）"
    return out


def test_decision_records_declare_their_nature():
    """每一份 tracked 决策记录的**开头**都要有那句声明。

    "开头"是判据的一部分：写在第 300 行的免责声明救不了一个从中间读起的人，而
    采用者读这类文档时几乎总是被别处的链接直接带到某一节。
    """
    offenders = []
    for rel in _decision_records():
        head = "".join((ROOT / rel).read_text(encoding="utf-8").splitlines(True)[:8])
        if _DECISION_BANNER not in head:
            offenders.append(rel)
    assert not offenders, (
        "这些决策记录的前 8 行里没有那句声明（新加的 spec/plan/review 也要加）：\n  "
        + "\n  ".join(offenders))


def test_decision_record_banner_points_at_the_operational_truth_source():
    """声明本身要给出去处，否则它只是免责而不指路。"""
    for rel in _decision_records():
        head = "".join((ROOT / rel).read_text(encoding="utf-8").splitlines(True)[:8])
        assert "site-builder/DEPLOY.md" in head, f"{rel} 的声明没指向操作真源"


def test_status_free_docs_and_decision_records_do_not_overlap():
    """两条纪律方向相反，同一份文档不能同时进两边——那会要求它既保留实测数据
    又清掉实测数据。ADR 两边都不进（日期是那个文体固有的），这条也把它钉住。"""
    free = {p.relative_to(ROOT).as_posix() for p in _STATUS_FREE_DOCS}
    records = set(_decision_records())
    assert not (free & records), f"同时进了两条纪律：{sorted(free & records)}"
    adrs = {f for f in records if f.startswith("docs/adr/")}
    assert not adrs, f"ADR 不该进决策记录声明（日期是文体固有的）：{sorted(adrs)}"


# ── 工单 12 第 3 条：不许把「新 clone 里没有的文件」标成 tracked ──────────────
#
# 既有的 test_delivery_docs_mark_every_undistributed_doc_pointer 是**块级启发式**：
# 同一段里出现 "gitignored" 就算标注过。实测它会漏掉这一类——把
# `docs/security/3c-impersonation-surface.json` untrack 之后，CLAUDE.md 那一格仍写着
# 「（**tracked**，…名字只进 gitignored dump）」，块里那个"gitignored"说的是**另一个**
# 文件，于是错标堂堂正正地过了守卫。
#
# 所以这条按**相邻**判：`**tracked**` 这个标签紧挨着的那个路径，必须真的被跟踪。
# 方向是"标签欺骗"，与上面那条"指针缺标注"互补。
_TRACKED_LABEL_RE = re.compile(
    r"`([\w./@{}*,+:=<>-]+)`\s*（\s*\*\*tracked\*\*|\*\*tracked\*\*[^）]{0,20}`([\w./@{}*,+:=<>-]+)`")


def test_no_doc_labels_an_untracked_path_as_tracked():
    """`**tracked**` 是个承诺：读者会据此认为 clone 下来就有这个文件。

    扫**全部 tracked .md**（不是三份入口文档）：这个标签在 spec / review / ADR 里
    同样是承诺，而那几份恰恰最爱标它。
    """
    import subprocess
    r = subprocess.run(["git", "ls-files", "-z", "*.md"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"git ls-files 失败（本条空转）：{r.stderr.strip()}"
    docs = [d for d in r.stdout.split("\0") if d]
    assert len(docs) > 5, f"只找到 {len(docs)} 份 tracked .md——本条空转"
    tracked = _tracked_paths()

    checked, offenders = 0, []
    for rel in docs:
        for no, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            for m in _TRACKED_LABEL_RE.finditer(line):
                path = m.group(1) or m.group(2)
                if not _is_doc_pointer(path):
                    continue
                checked += 1
                if not _distributed(path, tracked, ROOT / rel):
                    offenders.append(f"{rel}:{no} 把 {path} 标成 tracked，但它没被跟踪")
    assert not offenders, "\n  ".join(["标签与事实不符："] + offenders)
    assert checked >= 3, (
        f"只找到 {checked} 处 `**tracked**` 标签——判据多半跟不上文档了，本条正在空转")


def test_tracked_label_guard_catches_a_synthetic_lie(tmp_path):
    """**正对照**：合成一行"把不存在的文件标成 tracked"，判据必须认出来。
    没有这条，上面那条在正则写错时会静默全绿。"""
    line = "| 证据 | `docs/security/does-not-exist.json`（**tracked**，只读） |"
    hits = [m.group(1) or m.group(2) for m in _TRACKED_LABEL_RE.finditer(line)]
    assert hits == ["docs/security/does-not-exist.json"], hits
    assert _is_doc_pointer(hits[0])
    assert not _distributed(hits[0], {"docs/security/other.json"}, README)


# ── 工单 12 的两件新增内容 ─────────────────────────────────────────────────

def test_deploy_md_recommends_a_dedicated_account_and_says_why():
    """§9 的 3d 把「迁独立成员账号」从工程项降为**手册建议**（ADR 0005）。
    降级的前提是手册真的写了它并说清理由——否则那一行裁定等于把事情丢掉了。

    判据切到 §0 的账号一节：必须同时有"建议专用账号"、"为什么"（那三条能力）、
    以及"共享账号也站得住"（不然读者会以为这是硬前置而卡在这里）。
    """
    sec = _section(_read(DEPLOY), "#### 建议：部署到一个**专用**账号（是建议，不是硬要求）")
    assert "kms:Sign" in sec, "没说清「能签会话」是哪条能力"
    assert "ReadOnlyAccess" in sec, "没说清只读权限不够（这是刻意做到的那一半）"
    assert "共享账号" in sec, "没说清共享账号里资产仍然站得住 ⇒ 读者会当成硬前置"
    assert "account-trust-boundary.md" in sec, "没指向完整口径"
    assert "verify_account_trust_boundary.py" in sec, "没说清漂移闸门在共享账号里会变噪音"


# 采用者文档里不许出现的**具体主张**（工单 12）。判据是这些"把身份等同于飞书"的
# 说法，**不是"出现飞书"**——后者做不成守卫：手册里有整节【飞书】步骤、有逐路枚举
# org 边界的表、有"这个 secret 不是飞书 App Secret"这类澄清，全是正当的。
# 试过按行 + 短语白名单，四轮下来白名单越长、判据越弱，最后会放行一切。
_FEISHU_BINDING_CLAIMS = (
    "绑定飞书账号", "绑飞书账号", "都绑飞书", "需飞书登录", "必须飞书登录",
    "全组织飞书用户", "访问者需飞书", "飞书或标准 IdP", "携带飞书身份",
    "跳飞书登录", "你的飞书邮箱", "能飞书登录",
)


def _feishu_binding_offenders(text: str, name: str) -> list:
    """→ 违规行清单。守卫与正/负对照**共用**它（判定只有一处）。"""
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        for claim in _FEISHU_BINDING_CLAIMS:
            if claim in line:
                out.append(f"{name}:{no} [{claim}] {line.strip()[:80]}")
    return out


def test_adopter_docs_do_not_bind_identity_to_feishu():
    """飞书是**一种参考适配器**，不是身份模型的一部分（ADR 0006 / 工单 12）。

    "访问者需飞书登录 / 绑定飞书账号 / 全组织飞书用户"会让没有飞书的人以为这个平台
    用不了——而三条身份路径里有两条与飞书无关。**否定断言覆盖整份文件**（连
    【飞书】那一节也一样：那一节该说的是"走这条路时…"，不是无条件的"都绑飞书"）。
    """
    offenders = []
    for doc in (README, CLAUDE_MD, CONTEXT_MD, DEPLOY, CLIENT_SETUP,
                SKILL_MD, SKILL_CONTRACT, SKILL_REDLINES):
        offenders += _feishu_binding_offenders(_read(doc), doc.name)
    assert not offenders, (
        "这些位置把身份绑在飞书上（它只是一种参考适配器）：\n  " + "\n  ".join(offenders))


def test_feishu_binding_guard_fires_on_each_claim():
    """**正对照**：每条主张都必须真的被**同一个判定函数**认出来。

    上一版这条是同义反复（自己造一行含 claim 的文本，再断言 claim 在里面），
    那种正对照在判定逻辑写错时照样绿。现在走 `_feishu_binding_offenders`。
    """
    for claim in _FEISHU_BINDING_CLAIMS:
        hits = _feishu_binding_offenders(f"前缀：{claim}，其余照旧。", "probe.md")
        assert len(hits) == 1 and claim in hits[0], (claim, hits)
    # 负对照：正当的谈法不许被认成违规
    for clean in ("飞书是一种参考适配器，走 OIDC 适配器接进来。",
                  "> **飞书** —— org = 创建企业自建应用的那个租户。",
                  "**不是飞书 App Secret**。看 describe-identity-provider 就明白。",
                  "走这条路时，站点登录与部署权限绑的就是飞书账号。"):
        assert _feishu_binding_offenders(clean, "probe.md") == [], clean
