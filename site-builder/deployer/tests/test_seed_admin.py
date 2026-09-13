"""admin_seed → site-admins 表的注入脚本。

为什么这个脚本必须存在：CDK 只建表，`permissions.add_admin` 在二期之前
生产路径无人调用——表部署出来是空的，谁都不是 admin。而"添加管理员"本身
需要 admin 权限，所以第一个管理员无法从 UI 添加（死锁），只能部署时注入。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))


def test_dry_run_does_not_write(aws):
    import permissions
    import seed_admin

    out = seed_admin.seed("admin@example.com", dry_run=True)
    assert out["written"] is False
    assert permissions.list_admins() == []      # 确实没写


def test_apply_adds_admin(aws):
    import permissions
    import seed_admin

    out = seed_admin.seed("admin@example.com", dry_run=False)
    assert out["written"] is True
    assert permissions.is_admin("admin@example.com")
    assert permissions.list_admins() == ["admin@example.com"]


def test_rerun_is_idempotent_and_keeps_count_accurate(aws):
    """重跑不得让 __count__ 虚高——计数虚高会让"最后一个管理员不可删"的
    保护失效（n > 1 通过 → 表被删空）。"""
    import permissions
    import seed_admin

    seed_admin.seed("admin@example.com", dry_run=False)
    out = seed_admin.seed("admin@example.com", dry_run=False)
    assert out["already_admin"] is True
    assert out["written"] is False
    assert permissions.list_admins() == ["admin@example.com"]
    # __count__ 必须仍是 1（add_admin 的条件写保证；这里锁住重跑不破坏它）
    assert permissions.rebuild_admin_count() == 1


def test_empty_seed_fails_loudly(aws):
    """空值必须报错而不是静默跳过：静默跳过 = 部署完没有任何管理员，
    而这个状态从外部看不出来（表存在、脚本 exit 0）。"""
    import seed_admin

    with pytest.raises(SystemExit) as e:
        seed_admin.seed("", dry_run=False)
    assert "admin_seed" in str(e.value)


# --- _load_config 必须把 permissions/ops_log 需要的**全部**环境变量备齐（工单 14 实测） ---
# 上面那些用例直接调 seed(),从不经过 _load_config(),而 conftest 的 `aws` fixture
# 白送了一整套 ENV(含 OPS_LOG_TABLE) ⇒ **缺环境变量这类缺陷在这套测试里结构性看不见**。
# 真机上的后果:`add_admin` 里的 ops-log 写入是 best-effort(异常被吞、只打 traceback、
# 退 0),于是"第一个管理员"这次授予**成功但没有审计行**,而操作者看到一条 KeyError
# traceback,读起来像失败。下面两条专门盯这道缝:一律先把变量从 env 里**删掉**,
# 逼 _load_config 自己造出来。

_CONFIG_INI = """\
[Platform]
base_domain = example.com
account_id = 000000000000
region = us-east-1
admin_seed = admin@example.com

[Deployer]
jobs_table = site-deploy-jobs
sites_table = site-sites
admins_table = site-admins
"""


@pytest.fixture
def seed_admin_with_config(tmp_path, monkeypatch):
    """让 _load_config() 读一份临时 config.ini,并清掉它该负责设置的环境变量。"""
    import seed_admin

    (tmp_path / "config.ini").write_text(_CONFIG_INI, encoding="utf-8")
    # _load_config 读的是 HERE.parent / "config.ini"
    monkeypatch.setattr(seed_admin, "HERE", tmp_path / "scripts")
    for var in ("OPS_LOG_TABLE", "ADMINS_TABLE", "SITES_TABLE"):
        monkeypatch.delenv(var, raising=False)
    return seed_admin


def test_load_config_sets_every_env_var_its_callees_read(aws, seed_admin_with_config):
    """`_load_config` 是这个脚本唯一的环境变量装配点——漏一个就是一条静默缺陷。"""
    cfg = seed_admin_with_config._load_config()
    import os
    assert os.environ["ADMINS_TABLE"] == "site-admins"
    assert os.environ["SITES_TABLE"] == "site-sites"
    assert os.environ["AWS_DEFAULT_REGION"] == "us-east-1"
    # 审计表**不是配置项**(deployer 栈与 deploy_panel 都按同一字面量),但仍然必须被设上
    assert os.environ["OPS_LOG_TABLE"] == "site-ops-log"
    assert cfg["Platform"]["admin_seed"] == "admin@example.com"


def test_apply_after_load_config_writes_an_audit_row(aws, seed_admin_with_config):
    """端到端那半句:第一个管理员必须留下审计行。
    这是平台上权限最大的一次授予,没有审计行等于它从未发生过。"""
    import boto3

    seed_admin_with_config._load_config()
    out = seed_admin_with_config.seed("admin@example.com", dry_run=False)
    assert out["written"] is True

    rows = boto3.resource("dynamodb", region_name="us-east-1") \
        .Table("site-ops-log").scan()["Items"]
    actions = [r.get("action") for r in rows]
    assert "add_admin" in actions, f"没有 add_admin 审计行: {rows}"


def _fail_audit(monkeypatch):
    """让审计写入抛异常——模拟表不存在 / AccessDenied / 限流那一整类静默失败。"""
    import ops_log
    monkeypatch.setattr(ops_log, "_put",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))


def test_apply_reports_audit_gap_when_the_row_did_not_land(aws, seed_admin_with_config,
                                                          monkeypatch):
    """Codex 复审 P2：缺 `OPS_LOG_TABLE` 只是审计失败的**一个**原因。
    `ops_log.record` 吞掉一切异常，所以"没抛异常"不等于"审计落了"。
    授权必须仍然成立，但**缺失要响亮**。"""
    import permissions

    sa = seed_admin_with_config
    sa._load_config()
    _fail_audit(monkeypatch)
    out = sa.seed("admin@example.com", dry_run=False)
    assert out["written"] is True
    assert permissions.is_admin("admin@example.com"), "授权不该因为审计失败而回退"
    assert out["audited"] is False, "审计没落，报告里必须说出来"


def test_apply_reports_audited_true_on_the_happy_path(aws, seed_admin_with_config):
    """正对照：审计表健康时 audited 必须是 True。
    少了它，上面那条用"永远 False"实现也能绿。"""
    sa = seed_admin_with_config
    sa._load_config()
    assert sa.seed("admin@example.com", dry_run=False)["audited"] is True


def test_a_historical_add_admin_row_must_not_count_as_this_ones(aws, seed_admin_with_config,
                                                               monkeypatch):
    """**Codex 复审 P1 的复现**：同一邮箱历史上被加过又删过时，那条旧的 `add_admin`
    审计行不能冒充本次。

    序列：① 正常加 A（留下审计行）→ ② 加 B 并删掉 A（remove_admin 不许删最后一个，
    所以必须先有 B）→ ③ 注入审计写失败 → ④ 再加 A。
    旧实现在 ④ 返回 audited=True（它只问"这个邮箱有没有 add_admin 行"），
    而本次审计其实没写。正确答案是 False。
    """
    import permissions

    sa = seed_admin_with_config
    sa._load_config()
    sa.seed("admin@example.com", dry_run=False)                 # ①
    permissions.add_admin("second@example.com", added_by="test")  # ②
    permissions.remove_admin("admin@example.com", removed_by="test")
    assert not permissions.is_admin("admin@example.com")
    _fail_audit(monkeypatch)                                    # ③
    out = sa.seed("admin@example.com", dry_run=False)            # ④
    assert out["written"] is True
    assert out["audited"] is False, (
        "历史上的 add_admin 审计行被当成了本次的——写前/写后差集没起作用")


def test_an_unrelated_row_landing_in_the_window_does_not_count(aws, seed_admin_with_config,
                                                              monkeypatch):
    """写前/写后差集**非空**还不够——差出来的那一行必须真的是本次的 `add_admin`。

    这条隔离的是 action/actor 过滤那半边（`new_keys` 非空检查覆盖不到它）：
    模拟"本次 add_admin 的审计写失败了，但同一窗口里落了一条别的审计行"
    （并发的 remove_admin、或别的 actor 在动同一个名单）。
    只看差集非空会把那条无关行当成本次的证据。
    """
    import ops_log

    sa = seed_admin_with_config
    sa._load_config()
    real_put = ops_log._put

    def put_something_else(**kw):
        # 本次这条 add_admin 不写，改写一条别的 action —— 差集非空但不是本次的证据
        if kw.get("action") == "add_admin":
            kw = {**kw, "action": "remove_admin", "actor": "someone-else"}
        return real_put(**kw)

    monkeypatch.setattr(ops_log, "_put", put_something_else)
    out = sa.seed("admin@example.com", dry_run=False)
    assert out["written"] is True
    assert out["audited"] is False, (
        "差集里只有一条无关的审计行，却被当成本次 add_admin 的证据"
        "——action/actor 过滤没起作用")


def test_a_noop_audit_row_must_not_count_as_this_ones(aws, seed_admin_with_config,
                                                     monkeypatch):
    """**Codex 复审 P1 的第二个复现**：`add_admin` 的幂等分支写的是
    `action=add_admin, actor=seed_admin.py, result=noop` —— 同 action、同 actor，
    只有 `result` 不同。那条行的含义是"这个邮箱本来就已经是管理员"，
    **不是**"本次授予留下了审计"。

    真机上够得着这条：`is_admin()` 与 `add_admin()` 之间有窗口，
    别人抢先加同一个邮箱就会走到幂等分支。
    """
    import ops_log

    sa = seed_admin_with_config
    sa._load_config()
    real_put = ops_log._put

    def put_as_noop(**kw):
        if kw.get("action") == "add_admin":
            kw = {**kw, "result": "noop"}      # action / actor 都不动，只改 result
        return real_put(**kw)

    monkeypatch.setattr(ops_log, "_put", put_as_noop)
    out = sa.seed("admin@example.com", dry_run=False)
    assert out["written"] is True
    assert out["audited"] is False, (
        "result=noop 的审计行被当成了本次授予的证据——没有检查 result == 'ok'")


def test_unreadable_audit_table_is_reported_as_not_audited(aws, seed_admin_with_config,
                                                           monkeypatch):
    """读不出来（None）必须当成"没有"，不能当成"新写了一行"。
    判不了就报缺失，方向是保守的。"""
    sa = seed_admin_with_config
    sa._load_config()
    monkeypatch.setattr(sa, "_audit_keys", lambda email: None)
    assert sa.seed("admin@example.com", dry_run=False)["audited"] is False


def test_main_prints_an_actionable_warning_when_audit_is_missing(aws, seed_admin_with_config,
                                                                monkeypatch, capsys):
    """**这一条才真的调 main() 并读输出。**
    上一版的用例在 docstring 里声称"main() 打出告警"却从没调用过 main()、capsys 也没用
    ⇒ 把整个告警块删掉测试仍全绿（Codex 复审 P2）。

    同时钉住告警**不许**再教人「删掉再加回来」：第一个管理员通常是唯一管理员，
    而 `remove_admin` 明确拒绝删除最后一个 ⇒ 那个处置步骤执行不了。
    """
    sa = seed_admin_with_config
    monkeypatch.setattr(sys, "argv", ["seed_admin.py", "--apply"])
    _fail_audit(monkeypatch)
    assert sa.main() == 0, "审计缺失不该让脚本失败——管理员确实写进去了"
    out = capsys.readouterr().out
    assert "读不到**本次**的 add_admin 审计行" in out, out
    assert "dynamodb:PutItem" in out, "没告诉操作者最可能的原因"
    assert "再加一个" in out, "没给出能执行的处置"
    # 不是"别提这个短语"，而是"提到它时必须是**否定**的"：第一个管理员通常是唯一管理员，
    # 而 remove_admin 拒绝删除最后一个 ⇒ 把它当处置步骤是执行不了的。
    assert "**不能**靠「删掉再加回来」" in out, (
        f"没有明确否掉「删掉再加回来」这条走不通的处置：\n{out}")
    assert "remove_admin 明确拒绝删除最后一个" in out, "没说清为什么走不通"


def test_main_stays_quiet_when_audit_landed(aws, seed_admin_with_config, monkeypatch, capsys):
    """正对照：审计正常时不该打那条告警（否则它就是噪音，会被训练成无脑忽略）。"""
    sa = seed_admin_with_config
    monkeypatch.setattr(sys, "argv", ["seed_admin.py", "--apply"])
    assert sa.main() == 0
    assert "⚠️" not in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "@x.com", "a b@x.com"])
def test_malformed_email_rejected_before_write(aws, bad):
    """dry-run 也要校验——否则拼错的邮箱要到 --apply 才暴露。"""
    import permissions
    import seed_admin

    with pytest.raises(SystemExit):
        seed_admin.seed(bad, dry_run=True)
    assert permissions.list_admins() == []
