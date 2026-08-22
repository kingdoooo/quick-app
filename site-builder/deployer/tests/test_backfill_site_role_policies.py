"""backfill 的单测。

闸门的判据是「实际 policy == 从当前 sites 行推导的期望 policy」，
所以这里的重点用例是那些**不含通配却依然不可用**的形态
（错账号、漏表、孤儿角色）——只查 `*` 的闸门会放过它们。
"""
import json
import os
import pathlib
import stat
import sys

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "scripts"))
import backfill_site_role_policies as bf  # noqa: E402


class _FakeIam:
    """只实现 backfill 用到的调用。

    get_role_policy 缺失时抛真形态的 NoSuchEntity ClientError——
    `_actual_policy` 只把这一种判为"policy 不存在"，其他错误原样抛出。
    """

    def __init__(self, policies, extra_inline=None, attached=None,
                 roles_without_policy=None):
        self._policies = policies                  # {role_name: site-scope 文档}
        self._extra_inline = extra_inline or {}    # {role_name: [policy 名…]}
        self._attached = attached or {}            # {role_name: [policy ARN…]}
        # 存在、但没有 site-scope 的角色：get_role 认识它，
        # get_role_policy 对它抛 NoSuchEntity（TOCTOU 用例需要这个态）
        self._roles_without_policy = set(roles_without_policy or ())

    def _known_roles(self):
        return list(self._policies) + sorted(self._roles_without_policy)

    def get_role(self, RoleName):
        if RoleName in self._known_roles():
            return {"Role": {"RoleName": RoleName}}
        raise ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
            "GetRole")

    def get_paginator(self, name):
        if name == "list_roles":
            pages = [{"Roles": [{"RoleName": r} for r in self._known_roles()]}]
            return type("P", (), {"paginate": lambda _s, **_k: pages})()
        if name == "list_role_policies":
            def _pg(_s, *, RoleName, **_k):
                names = ["site-scope"] if RoleName in self._policies else []
                return [{"PolicyNames":
                         names + self._extra_inline.get(RoleName, [])}]
            return type("P", (), {"paginate": _pg})()
        if name == "list_attached_role_policies":
            def _pg(_s, *, RoleName, **_k):
                return [{"AttachedPolicies": [
                    {"PolicyArn": a}
                    for a in self._attached.get(RoleName, [])]}]
            return type("P", (), {"paginate": _pg})()
        raise AssertionError(f"_FakeIam 不认识 paginator {name}")

    def get_role_policy(self, RoleName, PolicyName):
        if RoleName not in self._policies:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
                "GetRolePolicy")
        return {"PolicyDocument": self._policies[RoleName]}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # 反向存在性检查默认打空桩——check_roles 的每条用例只关心手上那个角色，
    # 不该顺带去扫真实 sites 表。要测反向缺失的用例自己覆盖它。
    monkeypatch.setattr(bf, "active_fullstack_site_ids", lambda: [])
    return monkeypatch


def _nosql_site(*tables):
    return {"tier": "fullstack-nosql", "data_tables": list(tables)}


def test_norm_is_insensitive_to_iam_normalization():
    """IAM 会把单元素列表回成字符串、也不保证语句顺序 ⇒ 不能比 JSON 字符串。"""
    a = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:1"},
                       {"Effect": "Allow", "Action": ["logs:Put"],
                        "Resource": ["arn:2", "arn:3"]}]}
    b = {"Statement": [{"Effect": "Allow", "Action": ["logs:Put"],
                        "Resource": ["arn:3", "arn:2"]},
                       {"Effect": "Allow", "Action": ["s3:GetObject"],
                        "Resource": ["arn:1"]}]}
    assert bf._norm(a) == bf._norm(b)


def test_norm_keeps_condition_and_other_statement_fields():
    """「精确 ARN + 额外 Condition」不能被判成合格（Codex 指出）。

    v2 的 `_norm` 只比 (Effect, Action, Resource) 三元组——Condition /
    NotAction / NotResource 被静默丢弃。带限区 Condition 的角色文本上
    "逐项相等"，于是不进 targets、不跑功能模拟，--check 绿而站点不可用。
    """
    base = {"Statement": [{"Effect": "Allow",
                           "Action": ["dynamodb:GetItem"],
                           "Resource": ["arn:aws:dynamodb:r:1:table/x"]}]}
    conditioned = {"Statement": [{
        **base["Statement"][0],
        "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}]}
    assert bf._norm(base) != bf._norm(conditioned)


def test_check_roles_passes_when_actual_equals_expected(env):
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    assert bf.check_roles(_FakeIam({"site-rt-a-abc123": good})) == []


def test_check_roles_flags_a_wrong_account_policy_that_has_no_wildcard(env):
    """**闸门判的是"等于期望"，不是"没有 `*`"。**

    这条构造一个**除了账号号码全对、且没有任何通配**的 policy——它正是 v2 那版
    只查 `*` 的闸门会放过、而站点访问自己的表会全部 AccessDenied 的形态
    （Codex 复核指出）。错 region、漏表同理。
    """
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    env.setenv("ACCOUNT_ID", "999999999999")            # 先用错账号造"实际"
    actual = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    env.setenv("ACCOUNT_ID", "111111111111")            # 期望按正确账号算
    # 前提断言**只看 DynamoDB 表 ARN**：日志资源按设计带 stream 层通配
    # `log-group:…:*`，那不是 M01 的危险表前缀——对整文档查 `*` 会让这条
    # 用例在 policy 形态完全正确时也必然失败（Codex 指出的确定性 Blocker：
    # v4 就是整文档断言，Step 4 永远不能全绿）。
    ddb_resources = [
        r for stmt in actual["Statement"]
        if any(str(a).startswith("dynamodb:") for a in
               (stmt["Action"] if isinstance(stmt["Action"], list)
                else [stmt["Action"]]))
        for r in (stmt["Resource"] if isinstance(stmt["Resource"], list)
                  else [stmt["Resource"]])]
    assert ddb_resources and all("*" not in r for r in ddb_resources), \
        "这条用例的前提：DynamoDB 表 ARN 精确、不含通配"
    bad = bf.check_roles(_FakeIam({"site-rt-a-abc123": actual}))
    assert len(bad) == 1 and "不一致" in bad[0][1]


def test_check_roles_flags_a_missing_table(env):
    """漏表同样不合格——新加的表会 AccessDenied，而 policy 里没有通配。"""
    import common
    env.setattr(common, "get_site_consistent",
                lambda sid: _nosql_site("notes", "tags"))
    stale = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam({"site-rt-a-abc123": stale}))
    assert len(bad) == 1


def test_check_roles_flags_an_extra_inline_policy(env):
    """site-scope 完全等于期望、但角色上还挂着第二条 inline ⇒ 不合格且需人工。

    boundary 对全部 DynamoDB 数据动作放行整个 site-data-*（infra/app.py 的
    SiteRuntimeBoundary），残留的"PutItem on site-data-*"调试 policy 与它
    取交集就是有效跨租户写权限——只比 site-scope 的闸门对它失明，只模拟
    GetItem 的功能验收也测不出（Codex 指出的 P1）。
    """
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam(
        {"site-rt-a-abc123": good},
        extra_inline={"site-rt-a-abc123": ["debug-put"]}))
    assert len(bad) == 1 and bad[0][1].startswith(bf.EXTRA_POLICY_REASON)


def test_check_roles_flags_an_attached_managed_policy(env):
    """attached managed policy 同理——角色上只许有 site-scope 这一条。"""
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    bad = bf.check_roles(_FakeIam(
        {"site-rt-a-abc123": good},
        attached={"site-rt-a-abc123":
                  ["arn:aws:iam::111111111111:policy/debug"]}))
    assert len(bad) == 1 and bad[0][1].startswith(bf.EXTRA_POLICY_REASON)


def test_check_roles_flags_an_orphan_role(env):
    """sites 表里没有对应行的角色（下线清理失败留下的）也要报出来。"""
    import common
    env.setattr(common, "get_site_consistent", lambda sid: None)
    iam = _FakeIam({"site-rt-gone-abc123": {"Statement": []}})
    bad = bf.check_roles(iam)
    assert len(bad) == 1 and "孤儿" in bad[0][1]


def test_check_roles_flags_an_active_site_whose_role_is_missing(env):
    """反向也要查：ACTIVE fullstack 站点的角色**不存在**同样不合格。

    v2 只从现存 site-rt-* 角色出发反查 sites 行——"角色整个缺失"
    （误删/清理脚本写错）完全不可见，IAM 里一个角色都没有时闸门反而
    全绿（Codex 指出）。理由必须是 MISSING_ROLE_REASON 原文——main 按
    这个前缀把它分流到需人工（不自动重建：异常要先查根因，且这保证了
    备份里 null 不会混入"角色本身不存在"态，见 _persist_backup docstring）。
    """
    env.setattr(bf, "active_fullstack_site_ids", lambda: ["a-abc123"])
    bad = bf.check_roles(_FakeIam({}))
    assert bad == [("site-rt-a-abc123", bf.MISSING_ROLE_REASON)]


def _min_config(tmp_path, account="111111111111"):
    """最小可用 config。**不读真实 config.ini**：它是 gitignored 的，干净
    clone / CI 里不存在——依赖它的测试会以"读不到 config"失败，与被测行为
    无关（Codex 指出，与上一轮 parents[3] 同型的"本机能过、clone 必挂"）。"""
    p = tmp_path / "config.ini"
    p.write_text(f"[Platform]\naccount_id = {account}\nregion = us-east-1\n"
                 "[Deployer]\nsites_table = sb-sites-test\n")
    return p


def test_load_env_refuses_a_mismatched_account(monkeypatch, tmp_path):
    """**凭证账号 ≠ config 目标账号 ⇒ 拒绝执行。**

    不核对的话：凭证指向别的账号 ⇒ 那里没有 site-rt-* ⇒ 闸门看到"0 个不合格"
    ⇒ dry-run/--apply/--check 全退 0，而目标账号里的旧通配角色一个都没动，
    发布记录却显示 M01 已闭环（Codex 复核指出的 P1）。
    """
    class _Sts:
        def get_caller_identity(self):
            return {"Account": "999999999999"}
    monkeypatch.setattr(bf.boto3, "client", lambda name, **kw: _Sts())
    with pytest.raises(SystemExit, match="拒绝执行"):
        bf._load_env(_min_config(tmp_path))


def test_load_env_overrides_stale_shell_values(monkeypatch, tmp_path):
    """config 值必须**直接覆盖**，不能让 shell 残留胜出（不用 setdefault）。

    仓库既有的两个迁移脚本 docstring 都明写了这条理由。
    """
    class _Sts:
        def get_caller_identity(self):
            return {"Account": "111111111111"}
    monkeypatch.setattr(bf.boto3, "client", lambda name, **kw: _Sts())
    monkeypatch.setenv("SITES_TABLE", "wrong-sites-table")
    bf._load_env(_min_config(tmp_path))
    assert os.environ["SITES_TABLE"] == "sb-sites-test"


def test_no_iam_mutation_happens_if_the_backup_cannot_be_persisted(env, tmp_path):
    """**先留档，后动生产**：备份写失败 ⇒ `ensure_site_role` 一次都没调。

    v2 把备份攒在内存字典、循环结束才写文件——第 2 个角色写入抛异常
    （IAM 限流最常见）时，第 1 个已被改而备份文件不存在，spec §7.3 承诺的
    回滚材料落空（Codex 用窄复现证实过）。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role",
                lambda *a, **k: calls.append((a, k)))
    env.setattr(bf, "BACKUP_PATH", tmp_path / "no-such-dir" / "backup.json")
    iam = _FakeIam({"site-rt-a-abc123": {"Statement": []}})
    with pytest.raises(FileNotFoundError):
        bf.apply_plans(iam, [("site-rt-a-abc123", "a-abc123",
                              "dynamodb", ["notes"])])
    assert calls == []


def _backup_doc(roles, account="111111111111", region="us-east-1"):
    return {"schema_version": 1, "account_id": account,
            "region": region, "roles": roles}


def test_backup_never_overwrites_an_existing_snapshot(env, tmp_path):
    """重跑合并、绝不覆盖：已收敛的角色不再是 target，无条件覆盖备份文件会
    丢掉它们的原始通配 policy——回滚要的恰是**第一份**快照（Codex 指出）。"""
    path = tmp_path / "backup.json"
    path.write_text(json.dumps(_backup_doc({"site-rt-done-abc123": {"orig": 1},
                                            "site-rt-a-abc123": {"orig": 1}})))
    env.setattr(bf, "BACKUP_PATH", path)
    bf._persist_backup(_FakeIam({"site-rt-a-abc123": {"now": 2}}),
                       ["site-rt-a-abc123"])
    roles = json.loads(path.read_text())["roles"]
    assert roles["site-rt-done-abc123"] == {"orig": 1}   # 不在本次 targets，不丢
    assert roles["site-rt-a-abc123"] == {"orig": 1}      # 在本次 targets，不覆盖


def test_backup_refuses_to_merge_a_snapshot_from_another_account(env, tmp_path):
    """备份带账号元数据，合并前核对：A 账号的旧快照不能被"绝不覆盖"保留成
    B 账号同名 role 的回滚材料——回滚时会把 A 的资源 ARN 写进 B
    （Codex 指出）。不一致就拒绝执行，绝不静默合并。"""
    path = tmp_path / "backup.json"
    path.write_text(json.dumps(_backup_doc(
        {"site-rt-a-abc123": {"orig": 1}}, account="999999999999")))
    env.setattr(bf, "BACKUP_PATH", path)
    with pytest.raises(SystemExit, match="拒绝合并"):
        bf._persist_backup(_FakeIam({"site-rt-a-abc123": {"now": 2}}),
                           ["site-rt-a-abc123"])
    # 文件必须原封不动
    assert json.loads(path.read_text())["account_id"] == "999999999999"


def test_a_transient_read_error_during_backup_stops_before_any_mutation(env, tmp_path):
    """备份阶段读 policy 限流 ⇒ 原样抛出且零 IAM 写入。

    v3 的 `_actual_policy` 裸吞一切异常返回 None，`_persist_backup` 把它
    落盘成"原本没有 policy"且永不覆盖——一次限流就把回滚材料**永久**记成
    null（Codex 复现过）。只有 NoSuchEntity 才是"不存在"。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role", lambda *a, **k: calls.append(a))
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")

    class _ThrottledIam(_FakeIam):
        def get_role_policy(self, RoleName, PolicyName):
            raise ClientError(
                {"Error": {"Code": "Throttling", "Message": "rate exceeded"}},
                "GetRolePolicy")

    with pytest.raises(ClientError):
        bf.apply_plans(_ThrottledIam({"site-rt-a-abc123": {}}),
                       [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert calls == []
    assert not (tmp_path / "backup.json").exists()


def test_a_role_that_vanishes_after_enumeration_aborts_before_any_write(env, tmp_path):
    """TOCTOU 兜底：枚举时在、备份前被带外删除的角色 ⇒ 中止且零 IAM 写入。

    GetRolePolicy 的 NoSuchEntity 分不出"角色没了"和"角色在、只缺
    site-scope"——不复核 GetRole 的话，消失的角色会被备份成 null、再被
    ensure_site_role 整建，回滚歧义（删整个角色还是只删 policy）原样回来。
    「缺失角色分流需人工」只保证枚举时刻的缺失；这条守卫把「null ⇒ 角色
    存在」从运维假设变成技术保证（Codex 签核附带项）。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role", lambda *a, **k: calls.append(a))
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")
    with pytest.raises(SystemExit, match="枚举后消失"):
        bf.apply_plans(_FakeIam({}),
                       [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert calls == []
    assert not (tmp_path / "backup.json").exists()


def test_backup_null_requires_the_role_to_still_exist(env, tmp_path):
    """null 只允许在「角色在、site-scope 不在」时落盘（GetRole 复核通过）。"""
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")
    iam = _FakeIam({}, roles_without_policy={"site-rt-a-abc123"})
    bf._persist_backup(iam, ["site-rt-a-abc123"])
    saved = json.loads((tmp_path / "backup.json").read_text())
    assert saved["roles"] == {"site-rt-a-abc123": None}


def test_engine_and_tables_come_from_the_site_row():
    site = {"tier": "fullstack-nosql", "data_tables": ["notes", "tags"]}
    assert bf.plan_for("a-abc123", site) == ("dynamodb", ["notes", "tags"])
    assert bf.plan_for("b-abc123", {"tier": "fullstack-sql"}) == ("dsql", [])


def test_dynamodb_site_without_data_tables_is_skipped_not_guessed():
    """缺 data_tables 而 engine 是 dynamodb ⇒ 需人工，不猜表清单。"""
    with pytest.raises(bf.NeedsManualReview, match="data_tables"):
        bf.plan_for("a-abc123", {"tier": "fullstack-nosql"})


def test_unknown_tier_is_skipped_not_guessed():
    with pytest.raises(bf.NeedsManualReview, match="tier"):
        bf.plan_for("a-abc123", {"tier": "fullstack-graph"})


# ---------------------------------------------------------------------------
# fix round 1：复核提的四项 Important
# ---------------------------------------------------------------------------


def test_backup_is_fsynced_before_and_after_the_atomic_replace(env, tmp_path):
    """`os.replace` 只给**文件系统层面的原子性**，不给持久性。

    replace 返回后目标内容仍可能只在 page cache 里。要命的窗口：replace 成功 →
    7 个 put_role_policy 成功 → 机器掉电 → 生产 IAM 已改而回滚文件是 0 字节。
    两次 fsync 都必需且顺序固定：先 fsync 临时文件的 fd（让**内容**落盘），
    replace 之后再 fsync **父目录**的 fd（让**改名**本身落盘）。
    """
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def _spy_fsync(fd):
        kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        events.append(("fsync", kind))
        return real_fsync(fd)

    def _spy_replace(src, dst):
        events.append(("replace", None))
        return real_replace(src, dst)

    env.setattr(os, "fsync", _spy_fsync)
    env.setattr(os, "replace", _spy_replace)
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")
    bf._persist_backup(_FakeIam({"site-rt-a-abc123": {"orig": 1}}),
                       ["site-rt-a-abc123"])
    assert events == [("fsync", "file"), ("replace", None), ("fsync", "dir")]
    assert json.loads((tmp_path / "backup.json").read_text())["roles"] == {
        "site-rt-a-abc123": {"orig": 1}}


def test_a_leftover_temp_file_aborts_before_any_iam_mutation(env, tmp_path):
    """**只测"残留锁文件"这一条**：崩在写窗口里的上一次跑留下 .tmp ⇒ 下一次跑
    在任何 IAM 写入之前中止，且**不自动删**那个文件（要人工确认内容后再删）。

    并发互相覆盖那条不变量由
    `test_a_concurrent_run_cannot_clobber_another_runs_snapshot` 覆盖——它需要
    真正把另一次跑交错进来才测得到，本用例只预置一个文件，测不出那件事
    （这条 docstring 原先声称测的是并发，名不副实，复核指出）。
    """
    import common
    calls = []
    env.setattr(common, "ensure_site_role", lambda *a, **k: calls.append(a))
    # 写后复核也打桩：这条用例唯一该失败的理由是"没有中止"，
    # 不该被后续步骤缺环境变量的 KeyError 顶掉。
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    env.setattr(bf, "verify_access", lambda *a, **k: [])
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")
    leftover = tmp_path / "backup.json.tmp"
    leftover.write_text('{"half": ')          # 上一次崩溃留下的半个 JSON
    with pytest.raises(SystemExit, match="另一个 backfill"):
        bf.apply_plans(_FakeIam({"site-rt-a-abc123": {"orig": 1}}),
                       [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert calls == []                        # 零 IAM 写入
    assert leftover.read_text() == '{"half": '  # 残留原封不动，等人工处理
    assert not (tmp_path / "backup.json").exists()


def test_a_concurrent_run_cannot_clobber_another_runs_snapshot(env, tmp_path):
    """锁必须罩住**读-改-写全程**，不是只罩住写盘那一瞬。

    第一版把 O_EXCL 放在读-改-写**之后**，而 `os.replace` 会 unlink 掉 tmp、
    即**释放**它——于是锁只存在微秒级，既没盖住别人的读阶段也没盖住自己的
    写 IAM 阶段。复核用单线程 + fake 确定性地复现了原缺陷：让 A 的整个
    `_persist_backup` 在 B 的逐角色读循环中间跑完，A 的原始 policy 就从回滚
    文件里消失了，而 A 的 O_EXCL 从未撞上——此时 A 已经在 put_role_policy 循环里。

    本用例把那个交错固定下来：B 持锁期间 A 必须**中止**（而不是悄悄写出一份
    只含自己的快照再被 B 覆盖）；A 事后重跑时读到的是已合并的文件，
    于是两份原始 policy 都在——「谁都不丢」。
    """
    path = tmp_path / "backup.json"
    env.setattr(bf, "BACKUP_PATH", path)
    iam = _FakeIam({"site-rt-a-abc123": {"orig": "A"},
                    "site-rt-b-abc123": {"orig": "B"}})
    real_actual = bf._actual_policy
    run_a = {"started": False, "error": None}

    def _actual_with_run_a_interleaved(iam_, role_name):
        # 此刻 B 已经读过 BACKUP_PATH（不存在）、正在逐角色读 policy——
        # 正是原缺陷需要的那个时刻。让 A 完整跑一遍。
        if not run_a["started"]:
            run_a["started"] = True
            try:
                bf._persist_backup(iam_, ["site-rt-a-abc123"])
            except SystemExit as exc:
                run_a["error"] = str(exc)
        return real_actual(iam_, role_name)

    env.setattr(bf, "_actual_policy", _actual_with_run_a_interleaved)
    bf._persist_backup(iam, ["site-rt-b-abc123"])          # 这一次是 B
    assert run_a["started"], "交错没发生，这条用例什么都没测到"
    assert run_a["error"] and "另一个 backfill" in run_a["error"], \
        "B 持锁期间 A 必须中止；A 跑完就意味着它的快照会被 B 覆盖掉"
    assert json.loads(path.read_text())["roles"] == {
        "site-rt-b-abc123": {"orig": "B"}}

    # A 事后重跑（操作者看到"另一个 backfill 正在运行"后该做的事）：
    # 读到 B 已合并的文件并在其上合并，两份原始都在 ⇒ 谁都没丢。
    bf._persist_backup(iam, ["site-rt-a-abc123"])
    assert json.loads(path.read_text())["roles"] == {
        "site-rt-a-abc123": {"orig": "A"},
        "site-rt-b-abc123": {"orig": "B"}}


def test_a_transient_read_failure_leaves_no_lock_file_behind(env, tmp_path):
    """限流是**瞬时、自愈**的故障，绝不能因此留下锁文件。

    把 O_EXCL 移到读-改-写之前会带来这个陷阱：循环里既有的两个中止出口
    （`_actual_policy` 的非 NoSuchEntity 重抛、以及"枚举后消失"的 SystemExit）
    会把锁文件留在原地 ⇒ **一次 IAM 限流就让之后每一次重跑都被挡住**，
    直到人工删文件——把临时故障变成阻塞运维的故障。

    既有的 `test_a_transient_read_error_during_backup_stops_before_any_mutation`
    只断言 `backup.json` 不存在、对 `.tmp` 一字未提，所以锁泄漏时它照样绿
    （复核指出）。这条专门盯 `.tmp`，并验证限流过去后重跑能正常成功。
    """
    path = tmp_path / "backup.json"
    env.setattr(bf, "BACKUP_PATH", path)

    class _ThrottledOnce(_FakeIam):
        def __init__(self, policies):
            super().__init__(policies)
            self.throttling = True

        def get_role_policy(self, RoleName, PolicyName):
            if self.throttling:
                raise ClientError(
                    {"Error": {"Code": "Throttling", "Message": "rate exceeded"}},
                    "GetRolePolicy")
            return super().get_role_policy(RoleName, PolicyName)

    iam = _ThrottledOnce({"site-rt-a-abc123": {"orig": "A"}})
    with pytest.raises(ClientError):
        bf._persist_backup(iam, ["site-rt-a-abc123"])
    assert not (tmp_path / "backup.json.tmp").exists(), \
        "限流留下了锁文件——下一次重跑会被自己上一次的残留挡住"
    assert not path.exists()

    # 限流过去，重跑必须正常成功（而不是报"另一个 backfill 正在运行"）
    iam.throttling = False
    bf._persist_backup(iam, ["site-rt-a-abc123"])
    assert json.loads(path.read_text())["roles"] == {
        "site-rt-a-abc123": {"orig": "A"}}


# ---------------------------------------------------------------------------
# 闸门第 4 层（`verify_access`：IAM 策略模拟器）的正反两向
#
# 这一层是四层判据里**唯一反映真实 IAM 判定**而不是文本比较的一层，也是唯一能
# 证明 M01 的**写**侧被关掉的一层（spec §4.2.1：只模拟 GetItem 验不出"邻居表
# 可写"）。此前它在每一条用例里都被打桩（`_laggy_setup` 与残留锁那条各一处，
# 它们要证的是别的事，故意保留），于是**从未执行过**——第一次执行会发生在
# `--apply` 对生产 IAM 的那一刻，而那是不可逆动作的闸门。
# 「没被证明会咬的守卫等于没有守卫」是这一整轮的方法，这里把它补齐。
#
# 用 fake 模拟"策略模拟器"能证的只有两件事，但恰好就是要证的两件：
#   ① 判定被正确解读（allowed 的邻居 ⇒ 报泄漏；被拒的自己表 ⇒ 报不可用）；
#   ② **发给模拟器的动作清单是全部六个数据动作**，不是只有 GetItem。
# 它证不了 AWS 的判定本身对不对——那由真机 `--check` 覆盖。

# 期望 policy 里的六个 DynamoDB 数据动作（`common.site_policy`）。
# **在测试里写成字面量是有意的第二份**：从被测代码现取会让"只模拟 GetItem"
# 这一缺陷自证为对（它同样"等于自己推导的清单"）。
_ALL_DDB_ACTIONS = {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"}


class _SimIam(_FakeIam):
    """带策略模拟器的 fake。`decide(action, resource) -> 判定字符串`。

    返回形态照 IAM 的 `SimulatePrincipalPolicy`：每个动作一条
    `EvaluationResults`，资源级判定在 `ResourceSpecificResults[0]`
    的 `EvalResourceDecision` 里——被测代码读的正是这两层。
    """

    def __init__(self, decide, policies=None):
        super().__init__(policies or {})
        self._decide = decide
        self.calls = []          # [(PolicySourceArn, (动作…), 资源 ARN)]

    def simulate_principal_policy(self, *, PolicySourceArn, ActionNames,
                                  ResourceArns):
        assert len(ResourceArns) == 1, \
            f"被测代码一次只该模拟一个资源，实际 {ResourceArns}"
        res = ResourceArns[0]
        self.calls.append((PolicySourceArn, tuple(ActionNames), res))
        return {"EvaluationResults": [
            {"EvalActionName": a,
             "ResourceSpecificResults": [
                 {"EvalResourceName": res,
                  "EvalResourceDecision": self._decide(a, res)}]}
            for a in ActionNames]}


def test_verify_access_reports_a_still_reachable_nested_neighbour(env):
    """邻居表**任何一个动作** allowed ⇒ 必须报泄漏，且报出是哪些动作。

    这正是 M01 的形态：邻居的 site_id 以本站点的 site_id 为前缀，旧通配
    `table/site-data-{A}-*` 会把它一并放进去。这里让写动作 allowed、读动作被拒，
    因为"只模拟 GetItem 时残留的写权限照样闸门绿"是加这一层的**全部**理由——
    所以文案必须点出**多于一个**动作，否则报出来的东西不足以判断泄漏范围。
    """
    def decide(action, resource):
        if "probe" in resource:                     # 嵌套邻居
            return "allowed" if action in ("dynamodb:PutItem",
                                           "dynamodb:DeleteItem") else "implicitDeny"
        return "allowed"                            # 自己的表：全通
    iam = _SimIam(decide)
    problems = bf.verify_access(iam, "a-abc123", ["notes"])
    assert len(problems) == 1, problems
    assert "仍能访问嵌套邻居的表" in problems[0], problems[0]
    # 邻居必须真的是"以本 site_id 为前缀"的那种表名，否则这一层测的不是 M01
    assert "site-data-a-abc123-probe" in problems[0], problems[0]
    named = [a for a in _ALL_DDB_ACTIONS if a in problems[0]]
    assert len(named) > 1, (
        f"只报出 {named}——只点一个动作时，操作者无法判断泄漏是读还是写: "
        f"{problems[0]}")


def test_verify_access_reports_its_own_table_being_denied(env):
    """反方向：自己的表被拒 ⇒ 必须报出来（backfill 把 policy 写窄了/写错了）。

    没有这一向，一次把 policy 写成"什么都不许"的 backfill 会通过第 4 层：
    邻居确实访问不了了，而站点自己也访问不了——文本等值那一层若同时被
    同一个错误的 `site_policy` 满足（它与自己相等），这就是最后一道判据。
    """
    iam = _SimIam(lambda action, resource: "implicitDeny")
    problems = bf.verify_access(iam, "a-abc123", ["notes"])
    assert len(problems) == 1, problems
    assert "访问自己的表 notes 被拒" in problems[0], problems[0]
    assert "backfill 写坏了" in problems[0], problems[0]


def test_verify_access_simulates_every_data_action_not_just_reads(env):
    """动作清单必须是**六个数据动作全部**，且每个资源都按全部动作模拟一次。

    这是这一层被加进来的确切原因（Codex 指出的 P1）：只模拟 `GetItem` 时，
    角色上残留的一条"PutItem on site-data-*"调试 policy 在读模拟下同样"被拒"，
    闸门绿而跨租户**写**仍然可行——M01 的修复等于只验了读。

    **清单相等而不是包含**：多出一个动作也要有人看一眼（`site_policy` 加动作
    时先确认模拟这一层也跟着覆盖了它，再更新这里的字面量）；少一个动作就是
    上面那个缺陷回来了。
    """
    import common
    iam = _SimIam(lambda action, resource:
                  "implicitDeny" if "probe" in resource else "allowed")
    assert bf.verify_access(iam, "a-abc123", ["notes", "tags"]) == []
    assert iam.calls, "一次模拟都没发生——这条用例什么都没测到"
    for source, actions, res in iam.calls:
        assert source == common.site_role_arn("a-abc123"), source
        assert set(actions) == _ALL_DDB_ACTIONS, (
            f"模拟 {res} 时的动作清单是 {sorted(actions)}，"
            f"期望 {sorted(_ALL_DDB_ACTIONS)}")
    # 覆盖面：每张自己的表各一次 + 嵌套邻居一次
    assert [res.rsplit("/", 1)[1] for _s, _a, res in iam.calls] == [
        "site-data-a-abc123-notes", "site-data-a-abc123-tags",
        "site-data-a-abc123-probe-abc123-notes"]


def _run_main(env, argv, iam):
    """跑 main()：`_load_env` 与 `boto3.client` 都打桩，不碰真实 config / AWS。"""
    env.setattr(sys, "argv", ["backfill"] + argv)
    env.setattr(bf, "_load_env", lambda *a, **k: None)
    env.setattr(bf.boto3, "client", lambda name, **kw: iam)
    return bf.main()


def test_only_the_dry_run_warns_that_it_is_not_the_gate(env, capsys):
    """裸跑必须自己声明"我不是闸门"，`--check` 不该带这句。

    裸跑打印计划、退 0，于是把这条最顺手的命令接进发布检查就得到一条恒绿的
    假闸门——正是整个 S1 要消灭的形态。退出码不能改（理由见下一条），所以用
    一行显式警告顶上。
    """
    import common
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    iam = _FakeIam({"site-rt-a-abc123": good})

    assert _run_main(env, [], iam) == 0
    assert bf.DRY_RUN_NOT_A_GATE in capsys.readouterr().out

    assert _run_main(env, ["--check"], iam) == 0
    assert bf.DRY_RUN_NOT_A_GATE not in capsys.readouterr().out

    # `--apply` 也不该带这句：它结尾自己跑一遍闸门并按结果定退出码，
    # 那时"这不是闸门"是错的。（这里 targets 为空 ⇒ 不写任何东西。）
    assert _run_main(env, ["--apply"], iam) == 0
    assert bf.DRY_RUN_NOT_A_GATE not in capsys.readouterr().out


def test_dry_run_still_exits_zero_with_targets_so_apply_can_be_chained(env, capsys):
    """**退出码不能改成非 0。** Task 10 Step 3 在 `set -euo pipefail` 块里先跑
    裸 dry-run 再 `--apply`，而 backfill 之前 targets 必然非空（那正是要跑它的
    理由）——dry-run 退非 0 会让那个块每次都在 `--apply` 之前中止，部署序列
    根本不可跑。所以"待收敛 N 个"不计入退出码，只靠警告行提示。
    """
    import common
    env.setattr(common, "get_site_consistent",
                lambda sid: _nosql_site("notes", "tags"))
    stale = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    assert _run_main(env, [], _FakeIam({"site-rt-a-abc123": stale})) == 0
    out = capsys.readouterr().out
    assert "待收敛的角色：1" in out and bf.DRY_RUN_NOT_A_GATE in out


class _LaggyIam(_FakeIam):
    """读回时先给 `stale_reads` 次旧文档，之后给正确的——模拟 IAM 传播滞后。

    第 1 次读是 `_persist_backup` 的备份读，所以计数从它开始。
    """

    def __init__(self, doc, *, stale_doc, stale_reads):
        super().__init__({"site-rt-a-abc123": doc})
        self._stale_doc, self._stale_reads, self.reads = stale_doc, stale_reads, 0

    def get_role_policy(self, RoleName, PolicyName):
        self.reads += 1
        doc = (self._stale_doc if self.reads <= self._stale_reads
               else self._policies[RoleName])
        return {"PolicyDocument": doc}


def _laggy_setup(env, tmp_path, stale_reads):
    """共享夹具：IAM 写入打桩、sleep 打桩、verify_access 恒绿。

    `verify_access` 打桩是有意的：它靠 IAM 策略模拟器，用 fake 去模拟模拟器只能
    测出"我怎么调它"。这里要证的是**读回滞后被重试**，所以把模拟段固定成绿。
    """
    import common
    slept, wrote = [], []
    env.setattr(bf.time, "sleep", lambda s: slept.append(s))
    env.setattr(common, "ensure_site_role", lambda *a, **k: wrote.append(a))
    env.setattr(common, "get_site_consistent", lambda sid: _nosql_site("notes"))
    env.setattr(bf, "verify_access", lambda *a, **k: [])
    env.setattr(bf, "BACKUP_PATH", tmp_path / "backup.json")
    good = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["notes"]))
    stale = json.loads(common.site_policy("a-abc123", "dynamodb", tables=["old"]))
    iam = _LaggyIam(good, stale_doc=stale, stale_reads=stale_reads)
    return iam, slept, wrote


def test_a_lagging_iam_read_is_retried_instead_of_reported_as_failure(env, tmp_path):
    """IAM 是最终一致的，策略模拟器尤其会滞后一次写入若干秒。

    不重试的话，一次**完全正确**的 --apply 会把传播延迟记成"落地的 policy 与
    期望不一致"并退 1——操作者会合理地读成"迁移把生产 IAM 改坏了"。
    重试只包读侧：`put_role_policy` 幂等，重发它只会搅浑画面，所以断言
    `ensure_site_role` **恰好被调一次**。
    """
    # 备份读(1) + 读回第 1、2 次滞后(2,3)，第 3 次(4) 才对
    iam, slept, wrote = _laggy_setup(env, tmp_path, stale_reads=3)
    failed = bf.apply_plans(
        iam, [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert failed == []
    assert len(wrote) == 1          # 写只发生一次，重试不重发 put_role_policy
    assert slept == [2, 4]          # 只睡到成功为止，没有把预算用完


def test_the_verify_retry_is_bounded_and_keeps_the_original_failure_message(
        env, tmp_path):
    """重试有硬上限：一直不一致 ⇒ 用完 2/4/8 秒退避后仍按**原文**记失败。

    上限是硬要求（不做无限等待），而失败文案必须与加重试之前逐字一致，
    这样真正的不一致仍然以同样的方式报出来。
    """
    iam, slept, wrote = _laggy_setup(env, tmp_path, stale_reads=99)
    failed = bf.apply_plans(
        iam, [("site-rt-a-abc123", "a-abc123", "dynamodb", ["notes"])])
    assert failed == ["a-abc123: 落地的 policy 与期望不一致"]
    assert slept == [2, 4, 8]       # 有界：退避序列用完就停
    assert len(wrote) == 1
