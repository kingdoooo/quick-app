"""文档里的 MCP 工具面必须对着**实时注册表**校验，不能手抄。

背景（二期 M6）：`get_site_analytics` 上线、真机闸门全绿之后，被跟踪的文件里
仍有六处说工具是 4 / 5 / 8 个——`docs/client-setup.md` 的排查表甚至把 5 当成
**预期值**，照它排查的人会去查一个不存在的故障。三份文件同时错的根因不是粗心，
而是**没有任何东西从真源推导出文档里的清单**（本仓库记过的「别打地鼠，修那一类」）。

做法：文档里每一处工具面声明都用标记圈出来，由本文件对着
`server.mcp.list_tools()` 校验。真源取**实时注册表**而不是
`test_agentcore_contract.EXPECTED_TOOLS`（那份是并列的镜像，由那边的
`test_all_tools_registered` / `test_no_unexpected_tools_registered` 钉住）——
加了工具却两处都不改时，"文档陈旧"这一格必须自己会红。

两种区域，各管一件事：

  · `tool-count` —— 区域里那个数字必须等于工具总数；
  · `tool-list`  —— 区域里的工具名集合必须**恰好**等于注册表。
    少一个 = 新工具没写进文档（Agent 不会去用它）；
    多一个 = 改名/删掉的工具还留在文档里（读者照着调，报"工具不存在"）。

**为什么判据不是"每个工具名在文件里出现过"**（M5-FINDINGS §4.8 的那一类）：
那种存在性检查满足于任何一处顺带提及——`undeploy_site` 只要在 `purge_data`
的警告里出现就够了，`get_site_analytics` 在别处被提到一次也够了——而它对
"数字写错了"和"旧名字还留着"这两个**真实发生过的**缺陷永远不会变红。
所以判据是**逐区域的集合相等**，且区域里除工具名外不放别的 snake_case 标识符
（文件路径、测试名一律放到区域外，否则会被当成"文档里多出来的工具"）。

反向验证（2026-08-15，两次都真造过缺陷）：给注册表加第 10 个工具 →
`test_tool_list_regions_match_registry` 与 `test_tool_count_regions_match_registry`
在全部登记文件上变红；把 SKILL.md 里 `get_site_analytics` 那行删掉 → 只有
list 那条红，且报出"文档缺失"的那个名字。
"""
import re
from pathlib import Path

import pytest

MCP_DIR = Path(__file__).parents[1]
ROOT = MCP_DIR.parents[1]

# 文件（相对仓库根）→ 它必须至少各有一个的区域类型。
# **新增声明工具面的文档时在这里登记**；登记了却没写标记时
# test_every_registered_doc_declares_its_regions 会红（标记被删/改名不能静默放过）。
DOC_REGIONS = {
    "README.md": {"list"},
    "site-builder/DEPLOY.md": {"count", "list"},
    "site-builder/docs/client-setup.md": {"count", "list"},
    "site-builder/skills/site-builder/SKILL.md": {"list"},
    "site-builder/scripts/gen_onboarding.py": {"count", "list"},
    # 部署脚本打印的冒烟清单也是一处"预期值"声明（Task 17 手工改对过一次，
    # 但没有任何东西钉住它）。
    "site-builder/mcp/deploy_agentcore.py": {"count"},
}

# CLAUDE.md **刻意不用标记**：它每个会话都被原样注入上下文，架构图里插一段
# HTML 注释的噪音要按会话数付费。改用锚定断言——耦合写在下面那条用例里，
# 失败信息直接点出是哪一行。
CLAUDE_MD_ANCHOR = "② 部署 MCP (site-builder/mcp/)"

# 工具名的形态：小写 + 至少一个下划线（九个工具全是这个形状）。
TOOL_TOKEN = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")


def _registry() -> set[str]:
    """实时注册表 = 真源（装饰器注册的那份，不是任何一份手抄清单）。"""
    import asyncio

    import server
    return {t.name for t in asyncio.run(server.mcp.list_tools())}


def _regions(text: str, kind: str) -> list[str]:
    """所有 `tool-<kind>` 区域的正文。

    **起始标记自己那一截说明文字不算正文**：markdown 形态切到它的 `-->`
    （说明可以跨行），Python 注释形态切到行尾。不切的话，标记里写的
    `test_doc_tool_surface.py` 自己就会被当成"文档里多出来的工具"——
    第一版就是这么绿不了的。
    区域正文里剩下的注释符（结束标记的 `<!--`、Python 的行首 `#`）一并剥掉，
    于是"标记怎么写"不影响判据，两种文件用同一套规则。
    """
    out = []
    for raw in re.findall(rf"tool-{kind}:begin(.*?)tool-{kind}:end", text, re.S):
        head = raw.find("-->")
        cut = head + 3 if head >= 0 else raw.find("\n") + 1
        out.append(re.sub(r"<!--|-->|^[ \t]*#", " ", raw[cut:], flags=re.M))
    return out


@pytest.mark.parametrize("rel", sorted(DOC_REGIONS))
def test_every_registered_doc_declares_its_regions(rel):
    """守卫的守卫：标记不在了，下面两条会静默变成"零个区域全部通过"。"""
    text = (ROOT / rel).read_text()
    for kind in sorted(DOC_REGIONS[rel]):
        assert _regions(text, kind), (
            f"{rel} 里找不到 tool-{kind} 区域——标记被删掉或改名了。"
            f"要么补回 `tool-{kind}:begin` / `tool-{kind}:end`，"
            f"要么把该文件从 DOC_REGIONS 里摘掉（显式的取舍，不要静默）")


@pytest.mark.parametrize("rel", sorted(r for r, k in DOC_REGIONS.items()
                                       if "count" in k))
def test_tool_count_regions_match_registry(rel):
    expected = len(_registry())
    for region in _regions((ROOT / rel).read_text(), "count"):
        nums = re.findall(r"\d+", region)
        assert len(nums) == 1, (
            f"{rel} 的 tool-count 区域里有 {len(nums)} 个数字（{nums}）——"
            "区域里只放工具总数那一个数字，别的挪到区域外")
        assert int(nums[0]) == expected, (
            f"{rel} 说 MCP 有 {nums[0]} 个工具，实际注册了 {expected} 个。"
            "工具面变了就同步这里（照它排查的人会去查一个不存在的故障）")


@pytest.mark.parametrize("rel", sorted(r for r, k in DOC_REGIONS.items()
                                       if "list" in k))
def test_tool_list_regions_match_registry(rel):
    registry = _registry()
    for region in _regions((ROOT / rel).read_text(), "list"):
        named = set(TOOL_TOKEN.findall(region))
        assert not named - registry, (
            f"{rel} 的 tool-list 区域里有注册表没有的名字: "
            f"{sorted(named - registry)}——工具被改名/删掉后文档没跟上，"
            "读者照它调会拿到「工具不存在」；若那是别的标识符（文件名/测试名），"
            "把它挪到区域外")
        assert not registry - named, (
            f"{rel} 的 tool-list 区域漏了工具: {sorted(registry - named)}"
            "——文档里没有的工具，Agent/用户不会主动去用它（M5 的 "
            "get_site_analytics 就是这么部署上去又没人知道的）")


def test_claude_md_architecture_line_states_the_real_tool_count():
    """CLAUDE.md 架构图那一行的工具数（该文件里唯一的工具面声明）。"""
    expected = len(_registry())
    lines = [l for l in (ROOT / "CLAUDE.md").read_text().splitlines()
             if CLAUDE_MD_ANCHOR in l]
    assert len(lines) == 1, (
        f"CLAUDE.md 里 {CLAUDE_MD_ANCHOR!r} 出现 {len(lines)} 次——"
        "本用例靠它定位工具数那一行，锚点漂了就等于没有这道闸门")
    assert f"{expected} 工具" in lines[0], (
        f"CLAUDE.md 架构图第 ② 层写的工具数与注册表（{expected} 个）不一致:\n"
        f"  {lines[0].strip()}")
