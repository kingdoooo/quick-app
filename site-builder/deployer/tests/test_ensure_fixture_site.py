"""`scripts/ensure_fixture_site.py`：幂等创建常驻夹具站点（spec §11.7 / ADR 0002）。

覆盖四种起点（sites 行缺失 / 墓碑 / **路由行缺失** / 权限漂移）、owner 被占用时的拒绝、
"收敛完读回核对"那道闸，以及**取值只认 config.ini**（环境变量不许覆盖）。

**配置文本自己造**：真的 `site-builder/config.ini` 是 gitignored 的，读它会让整个文件在干净
clone 里报错而不是通过（deploy_fixture 的用例为同一条理由造假 config）。
"""
import os
import sys
import textwrap
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[3]
for d in ("scripts", "deployer/functions"):
    sys.path.insert(0, str(ROOT / "site-builder" / d))
import ensure_fixture_site as efs  # noqa: E402

# 表名/区域与 conftest 的 `aws` 夹具（moto）一致——现在它们是从**这份配置**读的，
# 不再是从环境变量兜底来的，所以对不上就会真的读错表。
CFG = textwrap.dedent("""
    [Platform]
    region = us-east-1
    base_domain = example.com
    routing_table = routing

    [Deployer]
    sites_table = site-sites
    admins_table = site-admins
""")
SUB = f"app-{efs.FIXTURE_SITE_ID}"


def _cfg(tmp_path, text=CFG):
    p = tmp_path / "config.ini"; p.write_text(text); return p


def _ddb():
    return boto3.client("dynamodb", region_name="us-east-1")


def _site(ddb, **over):
    item = {"site_id": {"S": efs.FIXTURE_SITE_ID}, "owner": {"S": efs.PROBE_EMAIL}, "status": {"S": "ACTIVE"},
            "tier": {"S": "static"}, "require_login": {"BOOL": True},
            "allowed_users": {"L": [{"S": efs.PROBE_EMAIL}]}, "collaborators": {"L": []}, "permissions_rev": {"N": "1"}}
    item.update(over)
    ddb.put_item(TableName="site-sites", Item=item)


def _route(ddb, **over):
    """部署路径写出来的那条路由行（`register_route` 是整条 put_item）。"""
    item = {"subdomain": {"S": SUB}, "owner": {"S": efs.PROBE_EMAIL},
            "require_auth": {"BOOL": True}, "allowed_users": {"L": [{"S": efs.PROBE_EMAIL}]},
            "collaborators": {"L": []}, "permissions_rev": {"N": "1"},
            "api_target": {"S": "https://placeholder.invalid"},
            "static_prefix": {"S": f"sites/{efs.FIXTURE_SITE_ID}/v1"}}
    item.update(over)
    ddb.put_item(TableName="routing", Item=item)


def _fake_deploy(ddb, calls):
    """假部署：写出 static fixture **刚部完**的两行形态（公开站点 + org 名单）。

    真部署会写这两行（`common.upsert_site` / `register_route`），所以假部署也必须写——
    不写的话"收敛完读回核对"那道闸会在每条用例里以路由行缺失失败，而那不是被测行为。
    """
    def deploy(fixture, owner, *, site_id=None, marker=None):
        calls.append(("deploy", fixture, owner, site_id))
        _site(ddb, require_login={"BOOL": False}, allowed_users={"S": "org"})
        _route(ddb, require_auth={"BOOL": False}, allowed_users={"S": "org"})
    return deploy


def _fake_perm(ddb, calls):
    """假 `set_access_policy`：记下参数，并按**真实**投影字段写路由行（require_auth/allowed_users/owner）。

    只记参数不写投影的话，读回核对同样会红——而那道闸正是本轮要加的东西。
    """
    def set_access_policy(site_id, **kw):
        calls.append(("perm", site_id, kw))
        _site(ddb)
        _route(ddb)
        return {"require_login": True, "allowed_users": [efs.PROBE_EMAIL]}
    return set_access_policy


def test_deploys_when_the_site_is_absent_and_then_converges_permissions(aws, tmp_path, monkeypatch):
    ddb, calls = _ddb(), []
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=_fake_deploy(ddb, calls))
    assert calls[0] == ("deploy", "static-hello", efs.PROBE_EMAIL, efs.FIXTURE_SITE_ID)
    assert calls[1][1] == efs.FIXTURE_SITE_ID and calls[1][2] == {"actor": efs.PROBE_EMAIL, "require_login": True,
                                                                  "allowed_users": [efs.PROBE_EMAIL]}
    assert out == {"deployed": True, "permissions_changed": True}


def test_is_a_no_op_when_the_resident_site_is_already_correct(aws, tmp_path, monkeypatch):
    ddb = _ddb()
    _site(ddb); _route(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: pytest.fail("不该改权限"))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out == {"deployed": False, "permissions_changed": False}


def test_converges_permissions_without_redeploying_when_only_policy_drifted(aws, tmp_path, monkeypatch):
    ddb, calls = _ddb(), []
    _site(ddb, require_login={"BOOL": False}, allowed_users={"S": "org"}); _route(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert [c[2] for c in calls] == [{"actor": efs.PROBE_EMAIL, "require_login": True,
                                      "allowed_users": [efs.PROBE_EMAIL]}]
    assert out == {"deployed": False, "permissions_changed": True}


def test_an_extra_allowed_user_is_converged_away(aws, tmp_path, monkeypatch):
    """名单多一个人也是漂移：夹具站点只许 `probe@e2e.invalid` 进，否则那条"只有它能进"的断言是空话。"""
    ddb, calls = _ddb(), []
    _site(ddb, allowed_users={"L": [{"S": efs.PROBE_EMAIL}, {"S": "someone@example.com"}]}); _route(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert calls and calls[0][2]["allowed_users"] == [efs.PROBE_EMAIL]
    assert out == {"deployed": False, "permissions_changed": True}


def test_a_missing_route_row_is_treated_as_not_deployed(aws, tmp_path, monkeypatch):
    """sites 行完好但路由行不在：只有部署路径会建路由行（权限投影带 `attribute_exists(subdomain)`），
    所以这必须走部署，而不是打印"一切正常"让闸门继续以"先跑 ensure_fixture_site.py"失败。"""
    ddb, calls = _ddb(), []
    _site(ddb)
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=_fake_deploy(ddb, calls))
    assert calls[0][0] == "deploy" and out["deployed"] is True


def test_a_route_row_that_the_gate_would_not_find_is_converged_without_redeploying(aws, tmp_path, monkeypatch):
    """路由行存在但 `require_auth` 不是 True（Edge 会当公开站点放行、`live_target` 也挑不到它）：
    权限收敛能修投影（事务里那半 update 就是写它），所以不必重新部署。"""
    ddb, calls = _ddb(), []
    _site(ddb); _route(ddb, require_auth={"BOOL": False})
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out == {"deployed": False, "permissions_changed": True}
    assert efs._route_row(ddb)["require_auth"]["BOOL"] is True


def test_a_route_owner_that_drifted_off_the_fixture_domain_is_converged(aws, tmp_path, monkeypatch):
    """路由行的 owner 漂成别的域：Edge 的夹具分支按 **route owner** 判夹具站点 ⇒ 夹具会话会被 302。
    真源仍是夹具域，所以这是投影漂移，收敛即可。"""
    ddb, calls = _ddb(), []
    _site(ddb); _route(ddb, owner={"S": "someone@example.com"})
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out["permissions_changed"] and efs._route_row(ddb)["owner"]["S"] == efs.PROBE_EMAIL


def test_it_refuses_to_report_success_when_the_route_still_would_not_gate(aws, tmp_path, monkeypatch):
    """收敛"成功"但投影那一半没写成（事务返回 `route_synced=False` 就是这种）⇒ 必须响亮失败。

    这是本轮要关掉的最坏形态：脚本打印"一切正常"，而闸门继续以"先跑 ensure_fixture_site.py"失败。
    """
    ddb = _ddb()
    _site(ddb); _route(ddb, require_auth={"BOOL": False})
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: {})   # 只写真源、投影没写
    with pytest.raises(SystemExit, match="route_synced|require_auth"):
        efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))


def test_refuses_when_the_site_id_is_held_by_a_non_fixture_owner(aws, tmp_path):
    ddb = _ddb()
    _site(ddb, owner={"S": "someone@example.test"})
    with pytest.raises(SystemExit, match="e2e.invalid"):
        efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该覆盖别人的站点"))


def test_deleted_tombstone_is_treated_as_absent(aws, tmp_path, monkeypatch):
    ddb, calls = _ddb(), []
    _site(ddb, status={"S": "DELETED"})
    monkeypatch.setattr(efs.permissions, "set_access_policy", _fake_perm(ddb, calls))
    efs.ensure(_cfg(tmp_path), deploy=_fake_deploy(ddb, calls))
    assert calls[0][0] == "deploy", "墓碑行不是活站点，应当重新部署"


def test_an_empty_config_is_fatal(aws, tmp_path):
    """configparser 对缺失文件是静默的——不硬失败就会拿空表名往下打（KeyError 读起来像代码坏了）。"""
    with pytest.raises(SystemExit, match="读空了"):
        efs.ensure(tmp_path / "missing.ini", deploy=lambda *a, **k: pytest.fail("不该走到部署"))


def test_an_unfilled_required_value_is_fatal(aws, tmp_path):
    """`routing_table` / `base_domain` 空着 = config 没回填。**不许**用环境变量兜底顶上去。"""
    text = CFG.replace("routing_table = routing", "routing_table =")
    with pytest.raises(SystemExit, match="ROUTING_TABLE"):
        efs.ensure(_cfg(tmp_path, text), deploy=lambda *a, **k: pytest.fail("不该走到部署"))


# ---- 取值来源：config.ini 是唯一真源（复审 Important 1）------------------------------------

def test_config_wins_over_a_conflicting_environment_and_the_environment_is_restored(aws, tmp_path, monkeypatch):
    """六个键被环境变量预先设成**错的**值时，本函数必须仍按 config 取值，跑完还原环境。

    最现实的形态是陈旧的 `AWS_DEFAULT_REGION` export：`setdefault` 会让本脚本去另一个区读 sites 表
    （那里什么都没有）⇒ 每次都判成"不存在"并重新部署，幂等性没了；权限也会写去错的区。
    这里 moto 只在 us-east-1 建了表，所以"读错区"= 读不到那一行，用例会以"重新部署了"失败。
    """
    ddb = _ddb()
    _site(ddb); _route(ddb)
    wrong = {"AWS_DEFAULT_REGION": "eu-west-1", "SITES_TABLE": "wrong-sites",
             "ROUTING_TABLE": "wrong-routing", "BASE_DOMAIN": "wrong.example",
             "ADMINS_TABLE": "wrong-admins", "OPS_LOG_TABLE": "wrong-ops"}
    for k, v in wrong.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(efs.permissions, "set_access_policy", lambda *a, **k: pytest.fail("不该改权限"))
    out = efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署（说明读的不是 config 里那张表）"))
    assert out == {"deployed": False, "permissions_changed": False}
    # 跑完还原：留下六个进程级副作用会让同进程里别的调用方去错的表读数
    assert {k: os.environ.get(k) for k in wrong} == wrong


def test_the_config_values_are_what_permissions_sees_during_the_call(aws, tmp_path, monkeypatch):
    """`permissions.py` 从环境变量找表，所以"config 赢"必须体现在**调用期间**的环境里。"""
    ddb = _ddb()
    _site(ddb, require_login={"BOOL": False}); _route(ddb)
    monkeypatch.setenv("SITES_TABLE", "wrong-sites")
    seen = {}

    def set_access_policy(site_id, **kw):
        seen.update({k: os.environ[k] for k in ("SITES_TABLE", "ROUTING_TABLE", "BASE_DOMAIN",
                                                "AWS_DEFAULT_REGION", "ADMINS_TABLE", "OPS_LOG_TABLE")})
        _site(ddb); _route(ddb)
        return {}

    monkeypatch.setattr(efs.permissions, "set_access_policy", set_access_policy)
    efs.ensure(_cfg(tmp_path), deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert seen == {"SITES_TABLE": "site-sites", "ROUTING_TABLE": "routing", "BASE_DOMAIN": "example.com",
                    "AWS_DEFAULT_REGION": "us-east-1", "ADMINS_TABLE": "site-admins",
                    "OPS_LOG_TABLE": "site-ops-log"}


def test_ops_log_table_is_the_platform_literal_not_a_config_key(aws, tmp_path, monkeypatch):
    """`OPS_LOG_TABLE` 不是配置项（merged review M22）：deployer 栈按字面量建 `site-ops-log`、
    `deploy_panel` 按同一字面量下发给 panel。本脚本若从 config 读它，采用者填个别的值就会让夹具脚本
    与 panel 写两张**不同**的审计表——比"改了不生效"更糟。所以 config 里写了别的值也不生效、
    没有 `[Panel]` 段也不算缺值，环境里的陈旧值同样被覆盖。"""
    monkeypatch.setenv("OPS_LOG_TABLE", "stale-from-env")
    with_other = CFG + "\n[Panel]\nops_log_table = somebody-elses-table\n"
    with efs._config_env(_cfg(tmp_path, with_other)) as want:
        assert want["OPS_LOG_TABLE"] == "site-ops-log"
        assert os.environ["OPS_LOG_TABLE"] == "site-ops-log"
    with efs._config_env(_cfg(tmp_path)) as want:          # 没有 [Panel] 段也不算缺值
        assert want["OPS_LOG_TABLE"] == "site-ops-log"
    assert os.environ["OPS_LOG_TABLE"] == "stale-from-env", "退出时要还原环境"


# ---- 与真源模块、与闸门的对账 ----------------------------------------------------------------

def test_the_real_permissions_module_converges_both_rows_and_then_the_gate_finds_the_target(aws, tmp_path):
    """**不打桩**：用生产的 `permissions.set_access_policy` 走一遍真源 + 投影的原子写，
    然后用生产的 `_session_mint.live_target` 去找目标——两侧的判据必须真的对得上。

    这条是上面那些假 `set_access_policy` 用例的正对照：假的按我以为的形态写投影，
    这条证明**真实**投影写出来的形态就是闸门找得到的那一种。
    """
    sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
    import _session_mint as sm
    ddb = _ddb()
    _site(ddb, require_login={"BOOL": False}, allowed_users={"S": "org"})
    _route(ddb, require_auth={"BOOL": False}, allowed_users={"S": "org"})
    cfg = _cfg(tmp_path)
    out = efs.ensure(cfg, deploy=lambda *a, **k: pytest.fail("不该重新部署"))
    assert out == {"deployed": False, "permissions_changed": True}
    route = efs._route_row(ddb)
    assert route["require_auth"]["BOOL"] is True
    assert [x["S"] for x in route["allowed_users"]["L"]] == [efs.PROBE_EMAIL]
    assert route["api_target"]["S"] == "https://placeholder.invalid", "投影不许踩掉 api_target"
    target = sm.live_target(cfg, ddb=boto3.resource("dynamodb", region_name="us-east-1"))
    assert (target.subdomain, target.owner) == (SUB, efs.PROBE_EMAIL)
    # 幂等：紧接着再跑一次必须什么都不做
    assert efs.ensure(cfg, deploy=lambda *a, **k: pytest.fail("不该重新部署")) == {
        "deployed": False, "permissions_changed": False}


def test_the_two_literals_come_from_the_mint_module(aws):
    """`e2e-probe` / `probe@e2e.invalid` 只有一个定义处——闸门与本脚本必须指同一个站点。"""
    sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
    import _session_mint as sm
    assert (efs.FIXTURE_SITE_ID, efs.PROBE_EMAIL) == (sm.FIXTURE_SITE_ID, sm.PROBE_EMAIL)


def test_the_read_back_uses_the_gates_own_lookup_not_a_second_copy_of_the_criteria(aws, tmp_path):
    """读回核对必须**调闸门那段查找**，不是在本脚本里复述一份同义条件。

    复述的后果就是本轮在修的死循环："脚本说完成、闸门说先跑脚本"。这里逐个造出三种不合格的
    路由行形态，断言 `_gate_target` 与 `live_target` 给出同一个结论（都找不到）。
    """
    sys.path.insert(0, str(ROOT / "site-builder" / "scripts"))
    import _session_mint as sm
    assert efs._gate_target.__doc__ and efs.live_target is sm.live_target, "读回不该有第二份判据"
    ddb, cfg = _ddb(), _cfg(tmp_path)
    for bad in ({"require_auth": {"BOOL": False}}, {"owner": {"S": "x@example.com"}},
                {"require_auth": {"S": "true"}}):
        _route(ddb, **bad)
        assert efs._gate_target(cfg) is None, bad
    _route(ddb)
    assert efs._gate_target(cfg).subdomain == SUB


def test_the_ops_log_literal_is_pinned_to_the_cdk_table_and_the_panel_env():
    """`_ENV_LITERALS["OPS_LOG_TABLE"]` 是第三份手抄的 `site-ops-log`：唯一创建者是 `deployer/infra/app.py`
    的 CDK 表定义，panel 的 `deploy_panel.py` 按同一字面量下发。漂移的症状不是报错而是写进一张不存在的表
    （`ops_log` 的 PutItem 被吞），所以三份必须由这一条钉在一起——与 key-proxy 的
    `test_api_keys_table_name_matches_the_cdk_table` 同款。"""
    name = efs._ENV_LITERALS["OPS_LOG_TABLE"]
    app_src = (ROOT / "site-builder" / "deployer" / "infra" / "app.py").read_text(encoding="utf-8")
    panel_src = (ROOT / "site-builder" / "panel" / "deploy_panel.py").read_text(encoding="utf-8")
    assert f'table_name="{name}"' in app_src, f"CDK 不再按 {name!r} 建 ops-log 表了？先改 app.py 再改这里"
    assert f'"OPS_LOG_TABLE": "{name}"' in panel_src, f"deploy_panel 下发的 OPS_LOG_TABLE 不再是 {name!r}"
