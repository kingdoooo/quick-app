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
