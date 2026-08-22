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


def test_migrate_script_has_an_entry_in_both_deploy_and_claude():
    """`migrate_sites_to_blue_green.py` 是存量环境升到 blue/green 的必经一步，
    两份文档里都必须有入口，且写清四件事：默认 dry-run、`--apply` 才写、
    `--site-id` 可单点重跑、**static 站点会被报成 skipped**（它们没有后端 Lambda，
    那不是失败）。
    """
    for p in (DEPLOY, CLAUDE_MD):
        txt = _read(p)
        assert "migrate_sites_to_blue_green" in txt, f"{p.name} 里没有迁移脚本入口"
    # **切到迁移那一节再断言**：`static` 与 `skipped` 这两个词在 DEPLOY.md 别处也有
    # （tier 名、别的小节），全文匹配会被它们满足 —— 实测把这一节里那条 static 说明
    # 整句删掉之后，全文版本的断言仍然是绿的。
    sec = _section(_read(DEPLOY),
                   "### 存量站点迁移到 blue/green（M7；**只有存量环境需要**）")
    assert "--apply" in sec and "dry-run" in sec, \
        "迁移那一节没写清默认 dry-run / --apply 才真写"
    assert "--site-id" in sec, "迁移那一节没写 --site-id 单点重跑"
    assert "static" in sec and "skipped" in sec, \
        "迁移那一节没写 static 站点会被报成 skipped（会被误读成失败）"
    assert "拒绝" in sec or "人工" in sec, \
        "没写「共用旧 URL 的站点会被拒并要求人工处理」"


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
