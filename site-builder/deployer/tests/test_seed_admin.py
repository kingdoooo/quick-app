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


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "@x.com", "a b@x.com"])
def test_malformed_email_rejected_before_write(aws, bad):
    """dry-run 也要校验——否则拼错的邮箱要到 --apply 才暴露。"""
    import permissions
    import seed_admin

    with pytest.raises(SystemExit):
        seed_admin.seed(bad, dry_run=True)
    assert permissions.list_admins() == []
