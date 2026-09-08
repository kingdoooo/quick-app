"""`scripts/ensure_fixture_site.py`：幂等创建常驻夹具站点（spec §11.7 / ADR 0002）。

三种起点都要覆盖：不存在 / DELETED 墓碑 ⇒ 部署；存在但权限漂了 ⇒ 只收敛权限；存在但 owner
不是夹具域 ⇒ 拒绝（不覆盖别人的站点）。

**配置文本自己造**：真的 `site-builder/config.ini` 是 gitignored 的，读它会让整个文件在干净
clone 里报错而不是通过（deploy_fixture 的用例为同一条理由造假 config）。
"""
import sys
import textwrap
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "deployer/functions"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import ensure_fixture_site as efs  # noqa: E402

CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.com
    routing_table = routing

    [Deployer]
    sites_table = site-sites
    admins_table = site-admins

    [Panel]
    ops_log_table = site-ops-log
""")


def _cfg(tmp_path, text=CFG):
    p = tmp_path / "config.ini"; p.write_text(text); return p


def _site(ddb, **over):
    item = {"site_id": {"S": efs.FIXTURE_SITE_ID}, "owner": {"S": efs.PROBE_EMAIL}, "status": {"S": "ACTIVE"},
            "tier": {"S": "static"}, "require_login": {"BOOL": True},
            "allowed_users": {"L": [{"S": efs.PROBE_EMAIL}]}, "collaborators": {"L": []}, "permissions_rev": {"N": "1"}}
    item.update(over)
    ddb.put_item(TableName="site-sites", Item=item)


def test_deploys_when_the_site_is_absent_and_then_converges_permissions(aws, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy",
                        lambda site_id, **kw: calls.append(("perm", site_id, kw)) or {"require_login": True, "allowed_users": [efs.PROBE_EMAIL]})
    out = efs.ensure(_cfg(tmp_path),
                     deploy=lambda fixture, owner, *, site_id=None, marker=None: calls.append(("deploy", fixture, owner, site_id)))
    assert calls[0] == ("deploy", "static-hello", efs.PROBE_EMAIL, efs.FIXTURE_SITE_ID)
    assert calls[1][1] == efs.FIXTURE_SITE_ID and calls[1][2] == {"actor": efs.PROBE_EMAIL, "require_login": True,
                                                                  "allowed_users": [efs.PROBE_EMAIL]}
    assert out == {"deployed": True, "permissions_changed": True}


def test_is_a_no_op_when_the_resident_site_is_already_correct(aws, tmp_path, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: pytest.fail("不该改权限"))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out == {"deployed": False, "permissions_changed": False}


def test_converges_permissions_without_redeploying_when_only_policy_drifted(aws, tmp_path, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, require_login={"BOOL": False}, allowed_users={"S": "org"})
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda site_id, **kw: calls.append(kw) or {})
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert calls == [{"actor": efs.PROBE_EMAIL, "require_login": True, "allowed_users": [efs.PROBE_EMAIL]}]
    assert out["permissions_changed"] and not out["deployed"]


def test_an_extra_allowed_user_is_converged_away(aws, tmp_path, monkeypatch):
    """名单多一个人也是漂移：夹具站点只许 `probe@e2e.invalid` 进，否则那条"只有它能进"的断言是空话。"""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, allowed_users={"L": [{"S": efs.PROBE_EMAIL}, {"S": "someone@example.com"}]})
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda site_id, **kw: calls.append(kw) or {})
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert calls and calls[0]["allowed_users"] == [efs.PROBE_EMAIL]
    assert out == {"deployed": False, "permissions_changed": True}


def test_refuses_when_the_site_id_is_held_by_a_non_fixture_owner(aws, tmp_path):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, owner={"S": "someone@example.test"})
    with pytest.raises(SystemExit, match="e2e.invalid"):
        efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该覆盖别人的站点"))


def test_deleted_tombstone_is_treated_as_absent(aws, tmp_path, monkeypatch):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    _site(ddb, status={"S": "DELETED"})
    calls = []
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: {})
    efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: calls.append(a))
    assert calls, "墓碑行不是活站点，应当重新部署"


def test_an_empty_config_is_fatal(aws, tmp_path):
    """configparser 对缺失文件是静默的——不硬失败就会拿空表名往下打（KeyError 读起来像代码坏了）。"""
    with pytest.raises(SystemExit, match="读空了"):
        efs.ensure(tmp_path / "missing.ini", deploy=lambda *a, **k: pytest.fail("不该走到部署"))


def test_the_two_literals_come_from_the_mint_module(aws):
    """`e2e-probe` / `probe@e2e.invalid` 只有一个定义处——闸门与本脚本必须指同一个站点。"""
    sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
    import _session_mint as sm
    assert (efs.FIXTURE_SITE_ID, efs.PROBE_EMAIL) == (sm.FIXTURE_SITE_ID, sm.PROBE_EMAIL)
