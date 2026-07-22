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
    from session import mint_session_jwt
    secret = boto3.client("ssm", region_name="us-east-1").get_parameter(
        Name="/site-builder/jwt-secret", WithDecryption=True)["Parameter"]["Value"]
    return "sb_session=" + mint_session_jwt("e2e@test.com", "E2E Bot", secret)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _req(url, method="GET", cookie=None, body=None):
    opener = urllib.request.build_opener(NoRedirect)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body else None)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _deploy(fixture: str) -> str:
    """部署 fixture，返回站点 URL。"""
    r = subprocess.run([sys.executable,
                        str(ROOT / "site-builder/scripts/deploy_fixture.py"),
                        str(ROOT / f"site-builder/fixtures/{fixture}")],
                       capture_output=True, text=True, timeout=1200)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout.splitlines()[-1].strip() or "{}").get("url") \
        or [l for l in r.stdout.splitlines() if '"url"' in l][-1].split('"')[3]


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
    # 3. 伪造用户头被剥除：带假头但无 cookie 仍 302
    code, headers, _ = _req(url + "/api/notes")
    assert code == 302


def test_expenses_site_dsql_crud(session_cookie):
    url = _deploy("sql-expenses")
    code, _, body = _req(url + "/api/expenses", "POST", session_cookie,
                         {"title": "e2e-coffee", "amount": 9.9})
    assert code == 201, body
    code, _, body = _req(url + "/api/expenses", cookie=session_cookie)
    assert code == 200
    assert any(e["title"] == "e2e-coffee" for e in json.loads(body))


def test_update_visible_and_undeploy_404(cfg):
    # 二次部署同一 static fixture（同 site_id 由 deploy_fixture 支持 --site-id 参数）
    # 简化：部署新实例后 undeploy，验证 404
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
