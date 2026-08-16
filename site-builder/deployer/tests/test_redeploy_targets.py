"""反向索引：改了哪个文件该重部哪些目标。

同形态漏过两次：permissions.py 漏 key-proxy、access_rollup.py 漏 panel
（本轮 verify_deployed_components 红成 71/72）。

**期望值一律硬编码**。v1 的 copied_files_not_in_map() 用同三个解析器同时生成
"实际"与"期望"，差集恒为空——解析器漏一个文件两边同时漏，守卫永远不红（§4.28）。
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

REPO = Path(__file__).parents[3]

# 硬编码的真源快照（2026-08-16 逐个读三份清单核对过：
#   panel     deploy_panel.COPY_FILES
#   key-proxy deploy_key_proxy.COPY_FILES = api_key_config/common/edge_caller/
#             keygen/keystore/ops_log/permissions
#   mcp       Dockerfile:26 = server/common/permissions/ops_log/analytics/access_rollup
# ）。改部署脚本的复制清单时**要手工同步这里**——这正是本守卫的价值：
# 两边不一致就红，而不是两边一起错（v1 那版两边同源 ⇒ 差集恒空）。
EXPECTED = {
    "access_rollup.py": {"panel", "mcp", "deployer"},
    "analytics.py": {"panel", "mcp", "deployer"},
    "permissions.py": {"panel", "key-proxy", "mcp", "deployer"},
    "edge_caller.py": {"panel", "key-proxy", "deployer"},
    "keystore.py": {"panel", "key-proxy", "deployer"},
    "ops_log.py": {"panel", "key-proxy", "mcp", "deployer"},
    "common.py": {"panel", "key-proxy", "mcp", "deployer"},
}


def test_vendor_map_matches_the_hardcoded_snapshot():
    import which_targets_to_redeploy as w
    m = w.vendor_map()
    for f, comps in EXPECTED.items():
        assert m.get(f, set()) >= comps, \
            f"{f} 的重部目标少了 {comps - m.get(f, set())}"


def test_directory_rules_use_path_parts_not_substring():
    """v1 判 `"/router/" in p`，而 git diff 输出 `router/...` 无前导斜杠 ⇒ 永不匹配。"""
    import which_targets_to_redeploy as w
    assert "router" in w.targets_for(["router/infrastructure/lambda/origin_request.py"])
    assert "panel" in w.targets_for(["site-builder/panel/api.py"])
    assert "mcp" in w.targets_for(["site-builder/mcp/server.py"])
    assert "auth" in w.targets_for(["site-builder/auth/session.py"])
    assert "deployer" in w.targets_for(["site-builder/deployer/infra/app.py"])


def test_vendored_module_maps_beyond_its_own_directory():
    """functions/access_rollup.py 在 deployer 目录下，但 panel 也打包了它。"""
    import which_targets_to_redeploy as w
    got = w.targets_for(["site-builder/deployer/functions/access_rollup.py"])
    assert {"deployer", "panel"} <= got


def test_vendored_lookup_is_scoped_to_the_real_source_dirs():
    """vendored 映射只对真正的复制源目录生效，不对"路径里带 functions 段"生效。

    按文件名套映射的代价是同名文件会误报：某天谁在别处建个 functions/ 目录放个
    同名文件，"改它要重部 panel/mcp" 就是假的。判定必须锚定在部署脚本实际
    复制的那两个目录上（deployer/functions 与 auth），而不是 `"functions" in parts`。
    """
    import which_targets_to_redeploy as w
    assert w.targets_for(["site-builder/mcp/functions/access_rollup.py"]) == {"mcp"}
    # 子目录也不算：复制清单做的是 `fn_dir / name`，不递归。
    assert w.targets_for(
        ["site-builder/deployer/functions/sub/permissions.py"]) == {"deployer"}


def test_auth_sourced_module_maps_to_panel():
    """session.py 的源文件在 auth/，panel 把它复制进自己的 zip。

    两个部署脚本的 `_build_zip` 都是 `deployer/functions` → `auth` 顺序查找，
    所以 auth/ 里的文件同样是 vendored 的；漏掉它就是"改了 session.py 只重部 auth"，
    正是 permissions.py / access_rollup.py 那两次的同形态漏。
    """
    import which_targets_to_redeploy as w
    assert {"auth", "panel"} <= w.targets_for(["site-builder/auth/session.py"])
    # 反面：auth 自己的文件没进任何复制清单，不该牵连 panel。
    assert "panel" not in w.targets_for(["site-builder/auth/pre_token_email.py"])


def test_hand_asserted_coupling_pulls_in_the_edge():
    """session.py 改了也要重部 router——这条边推不出来，只能手写。

    `auth/session.py` 与 `router/infrastructure/lambda/origin_request.py` 是**两份独立
    实现靠人手同步**同一套 HS256 会话验签（CLAUDE.md:145「两处必须字节级同步」、
    origin_request.py:453 同款注释），不是文件复制，任何复制清单里都没有它。
    答成 `auth, panel` 而漏掉 router 的后果是**全平台会话验签失败**——这个工具存在
    的意义就是不在这类事上安静地答错。

    手写的边要能与推导出来的边**分开**（`coupled_targets`）：读者得看出哪条有真源、
    哪条需要人维护。
    """
    import which_targets_to_redeploy as w
    assert {"auth", "panel", "router"} <= w.targets_for(["site-builder/auth/session.py"])
    assert w.coupled_targets(["site-builder/auth/session.py"]) == {"router"}
    # 反面两条：别的 auth 文件没有这条耦合；推导层不该凭空多出手写的目标。
    assert "router" not in w.targets_for(["site-builder/auth/pre_token_email.py"])
    assert w.coupled_targets(["site-builder/deployer/functions/permissions.py"]) == set()


def test_partially_parseable_copy_list_raises_instead_of_returning_short_list(tmp_path):
    """清单解析不动时必须抛，不能返回"部分清单"。

    少解析出一个文件名，输出里与"这个文件确实不用重部"完全一样——那是本工具唯一
    真正危险的失效方式（漏报），所以宁可吵到没法用。
    """
    import which_targets_to_redeploy as w
    m = tmp_path / "fake_deploy.py"
    m.write_text('EXTRA = "b.py"\nCOPY_FILES = ("a.py", EXTRA)\n')
    try:
        got = w._list_const(m, "COPY_FILES")
    except RuntimeError:
        return
    raise AssertionError(f"应当抛 RuntimeError，却返回了 {got}")


def test_absolute_paths_are_normalized_to_repo_relative():
    """操作者手里的路径通常是绝对的；锚定前缀对绝对路径全不匹配 ⇒ 会静默报"无"。"""
    import which_targets_to_redeploy as w
    got = w.targets_for([str(REPO / "site-builder" / "deployer" / "functions"
                             / "permissions.py")])
    assert {"deployer", "panel", "key-proxy", "mcp"} <= got


def _fake_git(tracked, untracked):
    """假造两条 git 命令的输出。

    **按 argv 里有没有 `-z` 决定分隔符**，像真 git 那样：把 `-z` 去掉这个退化在这里
    就是真的退化，而不是被 fake 悄悄补上。不在仓库里真建文件——那会污染工作树。
    """
    def run(argv, *a, **kw):
        if "ls-files" in argv:
            names = untracked
        elif "diff" in argv:
            names = tracked
        else:
            raise AssertionError(f"意料之外的 git 命令：{argv}")
        sep = "\0" if "-z" in argv else "\n"
        return subprocess.CompletedProcess(
            argv, 0, stdout="".join(n + sep for n in names))
    return run


def test_default_mode_sees_untracked_files(monkeypatch):
    """无参模式漏 untracked = 在最需要提示的场景静默漏报：新写一个共享模块时
    `git diff` 看不见它（Codex 复审 P2-f 实测：未跟踪的 panel 文件 → "没有改动的文件"）。
    """
    import which_targets_to_redeploy as w
    new = "site-builder/panel/new_shared_thing.py"
    monkeypatch.setattr(w.subprocess, "run", _fake_git([], [new]))
    paths = w._changed_paths()
    assert new in paths, f"未跟踪的新文件没被收进来：{paths}"
    assert "panel" in w.targets_for(paths), f"收进来了却没算出 panel：{paths}"


def test_paths_with_spaces_survive_parsing(monkeypatch):
    """按空白切会把一个含空格的路径拆成两条：既进不了任何目录规则（被算作"未归类"），
    又可能凭空造出不存在的路径。所以两条 git 命令都用 -z。
    """
    import which_targets_to_redeploy as w
    weird = "site-builder/panel/my new file.py"
    monkeypatch.setattr(w.subprocess, "run",
                        _fake_git(["site-builder/panel/a.py"], [weird]))
    paths = w._changed_paths()
    assert weird in paths, f"含空格的路径没有整条保留：{paths}"
    # 拆坏的形态不只是"少了一条"，还会凭空多出几条不存在的路径
    assert not ({"site-builder/panel/my", "new", "file.py"} & set(paths)), paths
