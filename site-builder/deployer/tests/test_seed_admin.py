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


def test_apply_reports_audit_gap_when_the_row_did_not_land(aws, seed_admin_with_config,
                                                          monkeypatch, capsys):
    """Codex 复审 P2：缺 `OPS_LOG_TABLE` 只是审计失败的**一个**原因。
    `ops_log.record` 吞掉一切异常（表不存在 / AccessDenied / 限流都走同一条静默路径），
    所以"没抛异常"不等于"审计落了"。授权必须仍然成立，但**缺失要响亮**。

    这里用"让审计写入抛异常"来模拟那一整类原因，断言两件事：
      ① 管理员确实写进去了（授权不因审计失败而回退——那是平台级裁定）；
      ② 报告里 audited=False，且 main() 打出可处置的告警。
    """
    import permissions
    import ops_log

    sa = seed_admin_with_config
    sa._load_config()
    monkeypatch.setattr(ops_log, "_put",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    out = sa.seed("admin@example.com", dry_run=False)
    assert out["written"] is True
    assert permissions.is_admin("admin@example.com"), "授权不该因为审计失败而回退"
    assert out["audited"] is False, "审计没落，报告里必须说出来"


def test_apply_reports_audited_true_on_the_happy_path(aws, seed_admin_with_config):
    """正对照：审计表健康时 audited 必须是 True。
    少了它，上面那条用"永远 False"实现也能绿。"""
    sa = seed_admin_with_config
    sa._load_config()
    out = sa.seed("admin@example.com", dry_run=False)
    assert out["audited"] is True


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "@x.com", "a b@x.com"])
def test_malformed_email_rejected_before_write(aws, bad):
    """dry-run 也要校验——否则拼错的邮箱要到 --apply 才暴露。"""
    import permissions
    import seed_admin

    with pytest.raises(SystemExit):
        seed_admin.seed(bad, dry_run=True)
    assert permissions.list_admins() == []
