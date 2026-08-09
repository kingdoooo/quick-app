"""真实 AWS 端到端：RUN_E2E=1 .venv/bin/pytest tests/test_e2e_fixtures.py -q
断言真实 HTTP 行为，不只看部署退出码。登录态用平台 JWT_SECRET 直接 mint
测试会话 cookie（SSM 读密钥）——无需人工飞书扫码即可自动化验证 CRUD。"""
import configparser
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

import boto3
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("RUN_E2E"),
                                reason="需要 RUN_E2E=1 与真实 AWS 凭证")
ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / "site-builder/auth"))


@pytest.fixture(scope="module")
def cfg():
    c = configparser.ConfigParser()
    c.read(ROOT / "site-builder/config.ini")
    return c


# ---- fixture 自动清理（spec §11-pre.3）----
#
# **本次运行创建的 site_id 逐个记账**，清理只碰这些。绝不按 owner 批量删：
# 试点环境里有长期存在的真站点，它们的 owner 恰好也是跑测试的这个人，
# 按 owner 清理会把它们一起下线（purge_data 更是不可恢复）。
#
# **清理失败 = 测试失败**：静默泄漏比红更糟——没人会去看"绿了但留下 7 个
# 站点"，而残留会干扰下一轮（本项目的 verify 脚本已因残留探针自我否定过一次）。
_created_site_ids: list[str] = []


def _record_created(url: str) -> str:
    """从站点 URL 记账 site_id，返回它。"""
    site_id = url.split("//app-")[1].split(".")[0]
    if site_id not in _created_site_ids:
        _created_site_ids.append(site_id)
    return site_id


@pytest.fixture(scope="module", autouse=True)
def _cleanup_created_sites():
    """module 级 autouse：跑完把本次部署的站点全部下线 + 清数据。

    autouse 是有意的——靠每个用例记得调用清理一定会漏（而漏掉的那次正好是
    失败退出的那次）。
    """
    yield
    if os.environ.get("SB_KEEP_FIXTURES"):
        print(f"\nSB_KEEP_FIXTURES：保留 {_created_site_ids}")
        return
    import common
    import permissions        # noqa: F401  确保表名环境变量一致的依赖已就位
    leaked, errors = [], []
    for site_id in list(_created_site_ids):
        try:
            job_id = f"job-e2e-cleanup-{site_id[-6:]}"
            common._table("JOBS_TABLE").put_item(Item={
                "job_id": job_id, "site_id": site_id, "owner": "e2e@cleanup",
                "status": "PENDING", "phase": "submitted", "error": "", "url": "",
                "created_at": common._now(), "updated_at": common._now()})
            # purge_data=True：留下 DynamoDB 表 / DSQL schema 会持续计费，
            # 也会让下一轮的同名探针数据串味
            boto3.client("lambda", region_name="us-east-1").invoke(
                FunctionName="site-deployer-undeploy",
                Payload=json.dumps({"job_id": job_id, "site_id": site_id,
                                    "purge_data": True}).encode())
            # 强一致读回：invoke 返回 200 不等于站点真的下线了
            site = common.get_site_consistent(site_id)
            if site and site.get("status") != "DELETED":
                leaked.append(site_id)
        except Exception as e:      # noqa: BLE001  汇总后统一失败，不吞
            errors.append(f"{site_id}: {type(e).__name__}: {e}")
    if errors or leaked:
        raise AssertionError(
            "fixture 清理未完成——**资源已泄漏，必须手工处理**。\n"
            f"  未确认删除: {leaked}\n  清理报错: {errors}\n"
            "（要保留现场排查请设 SB_KEEP_FIXTURES=1 重跑）")


@pytest.fixture(scope="module")
def session_cookie(cfg):
    """合成一个**能通过 Edge 全部检查**的会话 cookie。

    必须带 idp 与 auth_via：Edge 开了 `require_idp_claim=true` 之后，缺这两个
    claim 的会话会被 302 到登录页，于是后面所有 CRUD 断言都在"根本没到站点"
    的前提下通过/失败，验的不是它们声称的东西（Codex 审查 2026-08-06 P2）。
    这两个值必须与 Edge 的 TRUSTED_IDPS / TRUSTED_AUTH_SOURCES 逐字符一致——
    真机实测过 Cognito 签出的就是 `Feishu` 与 `TokenGeneration_HostedAuth`。
    idp 从 router/config.ini 读，避免这里和部署配置漂移。
    """
    from session import mint_session_jwt
    secret = boto3.client("ssm", region_name="us-east-1").get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    import configparser
    rc = configparser.ConfigParser(interpolation=None)
    rc.read(ROOT / "router/config.ini")
    trusted = rc["SiteBuilder"].get("trusted_idps", "").split("#")[0].strip()
    idp = trusted.split(",")[0].strip()
    assert idp, ("router/config.ini 的 trusted_idps 为空——Edge 开关为 true 时"
                 "任何会话都会被拦，E2E 必然失败")
    return "sb_session=" + mint_session_jwt(
        "e2e@test.com", "E2E Bot", secret,
        idp=idp, auth_via="TokenGeneration_HostedAuth")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _ssl_context():
    """显式用 certifi 的 CA bundle。

    macOS 上系统 Python 的默认信任库常为空（get_ca_certs() 返回 0 条），
    urllib 会以 CERTIFICATE_VERIFY_FAILED 失败，而同一 URL curl 正常——
    那是本机环境问题，不该表现为 E2E 失败。
    """
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _req(url, method="GET", cookie=None, body=None, extra_headers=None):
    opener = urllib.request.build_opener(
        NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context()))
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    # extra_headers 用于"伪造用户头必须被剥除"这类断言——没有它，那条用例
    # 只是在验"无 cookie 会 302"，与它声称的东西无关（Codex 审查 2026-08-06 P2）
    headers.update(extra_headers or {})
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body else None)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _deploy(fixture: str) -> str:
    """部署 fixture，返回站点 URL。

    deploy_fixture.py 先打印若干进度行（`  [RUNNING] validate`），最后打印
    json.dumps(job, indent=2) —— 是多行的，最后一行只是 `}`。所以只能从
    第一个 `{` 起整块解析，不能取最后一行。
    """
    r = subprocess.run([sys.executable,
                        str(ROOT / "site-builder/scripts/deploy_fixture.py"),
                        str(ROOT / f"site-builder/fixtures/{fixture}")],
                       capture_output=True, text=True, timeout=1200)
    assert r.returncode == 0, r.stdout + r.stderr
    start = r.stdout.find("{")
    assert start != -1, f"未找到 job JSON:\n{r.stdout}"
    job = json.loads(r.stdout[start:])
    url = job.get("url")
    assert url, f"job 无 url 字段: {job}"
    # **记账在 return 之前**：任何后续断言失败时清理仍能找到这个站点。
    # 放在调用方记账会漏掉"部署成功但第一条断言就失败"的那条路径。
    _record_created(url)
    return url


def test_static_site_public_200():
    url = _deploy("static-hello")
    code, _, body = _req(url + "/")
    assert code == 200 and b"Site Builder" in body


def test_notes_site_auth_and_crud(session_cookie, cfg):
    url = _deploy("nosql-notes")
    base = cfg["Platform"]["base_domain"]
    # 1. 未登录 → 302 到登录端点（不跟随）
    code, headers, _ = _req(url + "/")
    assert code == 302
    assert headers["Location"].startswith(f"https://auth.{base}/login")
    # 2. 带会话 cookie：完整 CRUD（真实 body 走 CloudFront→Edge SigV4→Function URL）
    code, _, body = _req(url + "/api/notes", "POST", session_cookie,
                         {"text": "e2e note"})
    assert code == 201, body
    created = json.loads(body)
    assert created["author"] == "e2e@test.com"  # x-user-email 注入生效
    code, _, body = _req(url + "/api/notes", cookie=session_cookie)
    assert code == 200
    assert any(n["id"] == created["id"] for n in json.loads(body))  # read-back
    code, _, _ = _req(f"{url}/api/notes/{created['id']}", "DELETE",
                      session_cookie)
    assert code == 204
    # 3a. 伪造用户头 + 无 cookie → 仍 302（假头不能替代会话）
    fake = {"x-user-email": "attacker@evil.com", "x-user-name": "Attacker"}
    code, _, _ = _req(url + "/api/notes", extra_headers=fake)
    assert code == 302, "带伪造用户头竟然被放行"
    # 3b. 伪造用户头 + **合法 cookie** → 请求成立，但站点看到的必须是 cookie 里
    #     的身份，不是假头里的。这才是"Edge 无条件剥除客户端头"的真正验证：
    #     只测 3a 的话，Edge 即使完全不剥头也照样通过（无 cookie 本就 302）。
    code, _, body = _req(url + "/api/notes", "POST", session_cookie,
                         {"text": "header-strip probe"}, extra_headers=fake)
    assert code == 201, body
    probe = json.loads(body)
    assert probe["author"] == "e2e@test.com", \
        f"伪造的 x-user-email 未被剥除，站点看到了 {probe['author']}"
    _req(f"{url}/api/notes/{probe['id']}", "DELETE", session_cookie)


def test_expenses_site_dsql_crud(session_cookie):
    url = _deploy("sql-expenses")
    code, _, body = _req(url + "/api/expenses", "POST", session_cookie,
                         {"title": "e2e-coffee", "amount": 9.9})
    assert code == 201, body
    code, _, body = _req(url + "/api/expenses", cookie=session_cookie)
    assert code == 200
    assert any(e["title"] == "e2e-coffee" for e in json.loads(body))


def test_update_visible_and_undeploy_404(cfg):
    # 部署新实例后 undeploy，验证 404。
    # （deploy_fixture.py **没有** --site-id 参数——site_id 由它随机生成，
    #   所以"同 site_id 二次部署"这条路径不在本用例覆盖范围内。）
    url = _deploy("static-hello")
    site_id = url.split("//app-")[1].split(".")[0]
    fn = boto3.client("lambda", region_name="us-east-1")
    boto3.client("lambda", region_name="us-east-1")  # noqa
    # 直调 undeploy Lambda（模拟 MCP 工具路径）
    jobs = boto3.resource("dynamodb", region_name="us-east-1").Table(
        cfg["Deployer"]["jobs_table"])
    from datetime import datetime, timezone
    jid = f"job-e2e-un-{site_id[-6:]}"
    now = datetime.now(timezone.utc).isoformat()
    jobs.put_item(Item={"job_id": jid, "site_id": site_id, "owner": "fixture@test",
                        "status": "PENDING", "phase": "submitted", "error": "",
                        "url": "", "created_at": now, "updated_at": now})
    fn.invoke(FunctionName="site-deployer-undeploy",
              Payload=json.dumps({"job_id": jid, "site_id": site_id}))
    import time
    time.sleep(70)  # Edge 路由缓存过期
    code, _, _ = _req(url + "/")
    assert code == 404
