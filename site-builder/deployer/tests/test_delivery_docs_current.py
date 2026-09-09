"""交付文档的**时效**守卫：面向新账号/新读者的那几份文档不许留过时口径。

守的是 `README.md` / `CLAUDE.md` / `site-builder/DEPLOY.md` /
`site-builder/scripts/gen_onboarding.py` —— 它们是"换个人/换个账号照着做"的唯一入口，
过时的一行在这里的代价是对方按错的顺序部署、或按不存在的路径执行。

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
DEPLOY = ROOT / "site-builder" / "DEPLOY.md"
GEN_ONBOARDING = ROOT / "site-builder" / "scripts" / "gen_onboarding.py"


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

    # 肯定断言切到状态段：它必须给出**可自查**的去处，而不是一个数字
    status = _blockquote(txt, "**当前状态**")
    assert "CLAUDE.md" in status, "状态段没指向 CLAUDE.md 的测试命令（读者无法自查）"
    assert "docs/design" in status and "不随仓库分发" in status, (
        "状态段没说明 docs/design 不随仓库分发——新 clone 会指向不存在的文件")
    assert "HANDOFF" not in status, (
        "状态段仍以 HANDOFF 为真源，而它是 gitignored ⇒ 新 clone 里不存在")


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


def test_cdk_out_note_also_covers_dependency_manifest_changes():
    """CDK 的 asset hash **不含挂载卷里的清单内容**（实测：两份不同 lockfile 算出
    同一个 asset），所以"只改 `bundling-requirements.txt` 不改 `app.py`"时真机会复用
    旧产物、新清单当次不生效。现有那句 `rm -rf cdk.out` 只提了 config.ini，
    覆盖到这一条是巧合不是设计 ⇒ 要写成显式条件。
    """
    txt = _read(DEPLOY)
    hits = [ln for ln in txt.splitlines()
            if "rm -rf cdk.out" in ln and ("清单" in ln or "requirements" in ln)]
    assert hits, "没有任何一处把「改依赖清单」列进必须 rm -rf cdk.out 的条件"
    win = _window(txt, hits[0].strip()[:40], after=6)
    assert "asset" in win, "没说明原因（asset hash 不含挂载卷内容）"
    assert "挂载卷" in win or "asset-input" in win, "原因写得不足以让人判断适用范围"


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

def test_readme_future_candidates_do_not_list_delivered_capabilities():
    """README「如何继续」的二期候选清单里，已交付的能力必须去掉。

    实测各项现状：MCP API-Key = 已交付（`site-builder/key-proxy/`，二期 M4）；
    站点协作者 = 已交付（panel 的 collaborators 接口，M3）；管理面板 = 已交付
    （`site-builder/panel/`，console.{base_domain}，M3）；PKCE/nonce = 已交付
    （`auth/login_handler.py` 的 `PKCE_COOKIE` + S256 + nonce 校验）。
    仍未交付的只有 Python 站点 runtime 与精细缓存。
    """
    sec = _section(_read(README), "## 如何继续")
    # **不能简单断言"这些名字不出现"**：这一段合理地需要提到它们，只是要说清"已交付"
    # ——我第一版就是那么写的，于是被我自己那句"…都已在二期交付"判红了。
    # 正确的形态是：**凡提到它们的那句话，必须同时说它已交付**。
    # 这样"把它挪回候选清单"会红（那句话里没有"交付"），而如实说明不会。
    # 标记词必须是**否定句造不出来的**那个。第一版我查的是 `"交付" in sentence`，
    # 而候选那句写着"仍未**交付**的候选" ⇒ 断言被**否定句**满足，把 MCP API-Key 挪回
    # 候选清单时它照样绿。这正是本轮假绿总表第 11 行（散文里的 token 会被无关的偶然
    # 提及、甚至被反义句满足）——**在记录这条判据的用例里又踩了一次**。
    # `已交付` / `已在二期交付` 都不可能由"仍未交付"产生。
    for delivered in ("MCP API-Key", "站点协作者", "管理面板", "PKCE/nonce"):
        for sentence in sec.split("。"):
            if delivered in sentence:
                assert "已交付" in sentence or "已在二期交付" in sentence, (
                    f"提到 {delivered!r} 的这句话没说明它**已**交付，读者会以为它还没有："
                    f"{sentence.strip()[:90]}")
    # 正向：仍未交付的那两项应当还在（否则这条断言退化成"把整段删掉就绿"）
    assert "Python" in sec and "缓存" in sec, \
        "仍未交付的 Python runtime / 精细缓存被一起删掉了——那是另一种失真"


def test_deploy_md_known_limits_do_not_list_delivered_capabilities():
    """DEPLOY.md 的「已知限制与延后项（向客户声明）」是**对客户**的口径，
    把已交付的 API Key fallback 写成"延后"比 README 那处更严重。"""
    sec = _section(_read(DEPLOY), "## 已知限制与延后项（向客户声明）")
    assert "API Key fallback 延后" not in sec, \
        "向客户声明里还写着 API Key fallback 延后，而 M4 已交付 key-proxy"
    assert "Node.js" in sec, "仍未交付的「仅 Node.js 后端」被删掉了"


def test_readme_marks_the_phase_one_docs_as_snapshots():
    """README 目录导览把一期的 spec/plan 当成有效入口，而它们是**一期快照**
    （CLAUDE.md 的文档地图写着"已实现快照，勿改"）。新读者照它们理解当前架构会错
    ——二期的控制台/API Key/统计/blue-green 都不在里面。
    """
    sec = _section(_read(README), "## 目录导览")
    for row_needle in ("specs/2026-07-21-quick-site-builder-design.md",
                       "plans/2026-07-21-quick-site-builder.md"):
        row = _row(sec, row_needle)
        assert "一期" in row and ("快照" in row or "勿改" in row), (
            f"这一行没标明是一期快照：{row.strip()[:110]}")


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
# 目前只对 CLAUDE.md 生效；README / DEPLOY.md / client-setup 还带着大量时间线与"已部署"，
# 由工单 12 清理后逐份加进 _STATUS_FREE_DOCS。**加进来的那一刻本条就会守住它**，所以清理时
# 先加再改。
_STATUS_FREE_DOCS = (CLAUDE_MD,)

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

