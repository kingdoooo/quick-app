"""真实 AWS 端到端：RUN_E2E=1 .venv/bin/pytest tests/test_e2e_fixtures.py -q
断言真实 HTTP 行为，不只看部署退出码。登录态用平台 JWT_SECRET 直接 mint
测试会话 cookie（SSM 读密钥）——无需人工飞书扫码即可自动化验证 CRUD。

**M7 的五条（spec §5）在本文件的后半段**。它们与前面几条的区别在于：前面几条验
"部署一次能用"，后面五条验**更新的原子性**——同一个 site_id 连着部两次、每次带
不同的 marker，然后按"公网 /api/health 的响应体里是哪个 marker"判断到底是哪份
字节在服务。只断言 HTTP 200 的话，"第二次部署被整个忽略"同样是绿的（v1 的三条
E2E 就是这样被驳回的）。
"""
import configparser
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import boto3
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("RUN_E2E"),
                                reason="需要 RUN_E2E=1 与真实 AWS 凭证")
ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / "site-builder/auth"))
FIXTURES = ROOT / "site-builder/fixtures"

# Edge 的路由缓存 TTL 是 60s（router/.../origin_request.py 的 ROUTE_CACHE_TTL）。
# 切完路由要等它过期，公网看到的才是新 api_target。等不够的症状是"新代码没上线"，
# 而实际上只是缓存还没过期——最容易被误判成产品缺陷的一种红。
ROUTE_CACHE_WAIT = 70

# blue/green 的颜色词表在这里**故意再写一遍**，不从 deploy_lambda_site import：
# 断言的期望值不许与被测代码同源推导。这两个名字是 spec §4.1 定死的对外契约
# （固定 alias blue/green，各带一个固定 Function URL），所以这份重述的真源是 spec。
# 真机上的颜色也只能从"路由的 api_target 等于哪个 alias 的 Function URL"反推——
# 下面 _live_color 是按这条契约独立实现的一份，不是被测函数的引用。
COLORS = ("blue", "green")


@pytest.fixture(scope="module")
def cfg():
    c = configparser.ConfigParser()
    c.read(ROOT / "site-builder/config.ini")
    return c


# ---- 默认 SSL 上下文的 CA 信任库 ----
#
# 本文件有**两类** HTTPS 请求，过去只管了第一类：
#   ① 测试自己发的 —— 走下面的 `_ssl_context()`，显式用 certifi，一直是好的；
#   ② **在进程内被调用的生产代码**发的 —— 走 Python 的**默认**上下文。
#      `migrate_sites_to_blue_green._public_check` → `smoke_test._head` → `urlopen()`
#      就是这一类（spec §5.4 那条用例在进程内直接调 `migrate_one`）。
#
# `deployer/.venv/bin/python3` 的默认上下文**一个 CA 都没有**（实测
# `cert_store_stats()` 全 0，CLAUDE.md 记过这个坑），于是第二类请求以
# CERTIFICATE_VERIFY_FAILED 失败——症状读起来像网络/证书故障，其实是本机解释器的
# 信任库是空的。真机第一次跑就栽在这里（21 分钟之后才炸）。
#
# **生产上没有这个问题**：`smoke_test` 在 Lambda 里跑，迁移脚本按 CLAUDE.md 用系统
# `python3`（走 pip 注入的 truststore，读 macOS keychain）。所以要修的是本 harness，
# **不是** `smoke_test.py` 或迁移脚本——改那两个文件等于为了 harness 的缺陷去动生产码。

def _ctx_trust_ok(ctx) -> bool:
    """这个 SSL 上下文能不能验证证书。

    两种都算可用：
      · `cert_store_stats()["x509_ca"] > 0` —— 静态信任库里有 CA；
      · `cert_store_stats()` 抛 `NotImplementedError` —— pip 注入的 truststore
        （`pip._vendor.truststore._api.SSLContext`），校验委托给操作系统钥匙串，
        它本来就没有静态计数。
    **把第二种当失败**会让这条判定在系统 `python3` 上恒假，于是守卫只在 venv 上成立。
    """
    try:
        return ctx.cert_store_stats()["x509_ca"] > 0
    except NotImplementedError:
        return True


def _default_trust_ok() -> bool:
    return _ctx_trust_ok(ssl.create_default_context())


# vendored 依赖住在仓库里（`.venv` 在仓库根下），所以"我们自己的源码"不能只判仓库前缀。
_VENDORED_DIRS = (".venv", "site-packages", "node_modules", "cdk.out")


def _is_our_source(path) -> bool:
    parts = Path(path).parts
    return str(path).startswith(str(ROOT)) and not any(v in parts
                                                       for v in _VENDORED_DIRS)


def _frozen_https_contexts() -> list:
    """本仓库**已被 import** 的模块里，那些在模块级建好的 opener 已经定格的
    HTTPS 上下文。

    为什么会有"定格"：`urllib.request.HTTPSHandler.__init__` 在**构造时**就调
    `http.client._create_https_context()` 把上下文存进 `self._context`
    （CPython 3.12 实测）。`smoke_test` 在模块级 `build_opener(...)`，所以它的信任库
    在 **import 那一刻**就定了——之后再改 `SSL_CERT_FILE` 对它无效。
    真机第一次跑就是这样：我先设了环境变量也救不了一个已经 import 过的 smoke_test。

    不写死模块名：按"文件是**我们自己的**源码 + 属性是 OpenerDirector"扫，将来任何
    一个照同样写法建 opener 的模块都会被自动罩住。

    **必须排除 vendored 目录**：`.venv` 就在仓库根下面，只判 `startswith(ROOT)` 会把
    三百多个三方模块一起扫进来（实测 336 个），于是对它们的每个属性做 getattr、还可能
    去改它们的上下文。改动本身仍是安全的（下面只换**一个 CA 都没有**的上下文，被刻意
    钉到私有 CA 的上下文有 CA、会被跳过），但那个范围不是本函数的意图。
    """
    out = []
    for mod in list(sys.modules.values()):
        path = getattr(mod, "__file__", None)
        if not path or not _is_our_source(path):
            continue
        for name in dir(mod):
            try:
                obj = getattr(mod, name)
            except Exception:       # noqa: BLE001  属性可能是会抛的 property
                continue
            if isinstance(obj, urllib.request.OpenerDirector):
                out += [(mod.__name__, name, h) for h in obj.handlers
                        if isinstance(h, urllib.request.HTTPSHandler)]
    return out


def _ensure_default_ssl_trust() -> str:
    """把**默认** SSL 上下文（以及已经定格的 opener）的信任库修好。

    返回一行说明，打进 E2E 日志便于排查。

    `SSL_CERT_FILE` 是 OpenSSL 每次建上下文都会重读的（实测：设了→121 个 CA，
    删了→回到 0），所以进程跑起来之后再设对**之后**建的上下文有效；已经定格的那些
    要单独换掉，见 `_frozen_https_contexts`。

    外部显式设过 `SSL_CERT_FILE` 就不覆盖（可能指向企业 CA 包）。
    """
    notes = []
    if _default_trust_ok():
        notes.append("默认上下文本来就可用")
    elif os.environ.get("SSL_CERT_FILE"):
        # 外部设了却仍然不可用 —— 覆盖它反而会掩盖配置错误，如实报出来
        raise RuntimeError(
            f"SSL_CERT_FILE={os.environ['SSL_CERT_FILE']} 已设置，但默认 SSL "
            "上下文仍然没有 CA——请先确认那个文件是有效的 CA bundle")
    else:
        import certifi   # 缺它就没得修：让 ImportError 直接上抛，别静默继续
        os.environ["SSL_CERT_FILE"] = certifi.where()
        notes.append(f"已设 SSL_CERT_FILE={certifi.where()}")
        if not _default_trust_ok():
            raise RuntimeError(
                f"设了 SSL_CERT_FILE={os.environ['SSL_CERT_FILE']} 之后默认 SSL "
                "上下文仍然没有 CA——进程内调用的生产代码会以 "
                "CERTIFICATE_VERIFY_FAILED 失败，而那读起来像证书/网络故障")

    # 已经定格的 opener：换掉那个上下文本身。用 create_default_context() 重建而不是
    # reload 整个模块——reload 会重定义 SmokeFailure 之类的异常类，持有旧引用的
    # `except` 就捕不到了。
    repaired = []
    for mod_name, attr, handler in _frozen_https_contexts():
        if _ctx_trust_ok(handler._context):
            continue
        handler._context = ssl.create_default_context()
        if not _ctx_trust_ok(handler._context):
            raise RuntimeError(
                f"{mod_name}.{attr} 的 HTTPS 上下文换过之后仍然没有 CA——"
                "进程内那条 urlopen 会以 CERTIFICATE_VERIFY_FAILED 失败")
        repaired.append(f"{mod_name}.{attr}")
    notes.append(f"已修定格 opener: {repaired}" if repaired else "无定格 opener 待修")
    return "；".join(notes)


# ---- fixture 自动清理（spec §11-pre.3）----
#
# **本次运行创建的 site_id 逐个记账**，清理只碰这些。绝不按 owner 批量删：
# 试点环境里有长期存在的真站点，它们的 owner 恰好也是跑测试的这个人，
# 按 owner 清理会把它们一起下线（purge_data 更是不可恢复）。
#
# **清理失败 = 测试失败**：静默泄漏比红更糟——没人会去看"绿了但留下 7 个
# 站点"，而残留会干扰下一轮（本项目的 verify 脚本已因残留探针自我否定过一次）。
_created_site_ids: list[str] = []


def _record_site_id(site_id: str) -> str:
    """记账一个 site_id（幂等），返回它。"""
    if site_id not in _created_site_ids:
        _created_site_ids.append(site_id)
    return site_id


def _record_created(url: str) -> str:
    """从站点 URL 记账 site_id，返回它。"""
    return _record_site_id(url.split("//app-")[1].split(".")[0])


@pytest.fixture(scope="module", autouse=True)
def _platform_env(cfg):
    """把 config.ini 的表名/域名/角色导成环境变量，并修好默认 SSL 信任库。

    清理路径 `import common` 后走 `common._table("JOBS_TABLE")`，迁移脚本走
    `os.environ["ROUTING_TABLE"]`，健康门合成事件要 `BASE_DOMAIN`——都从环境变量取。
    不设的话 module 级清理以 KeyError 收场，读起来像"清理逻辑坏了"，其实是缺配置
    （而清理失败会被报成"资源已泄漏"，把人引到完全错的方向）。

    SSL 那一项见 `_ensure_default_ssl_trust` 上面那段：本文件会在进程内直接调生产
    代码，而那些代码用**默认** SSL 上下文，venv 里它是空的。

    跑完还原（含 `SSL_CERT_FILE`）：这是进程级副作用，留着会污染同一次 pytest 里的
    其它文件。
    """
    want = {"JOBS_TABLE": cfg["Deployer"]["jobs_table"],
            "SITES_TABLE": cfg["Deployer"]["sites_table"],
            "ROUTING_TABLE": cfg["Platform"]["routing_table"],
            "BASE_DOMAIN": cfg["Platform"]["base_domain"],
            "EDGE_ROLE_ARN": cfg["Deployer"]["edge_role_arn"],
            "AWS_DEFAULT_REGION": cfg["Platform"]["region"]}
    # SSL_CERT_FILE 由 _ensure_default_ssl_trust 决定要不要设，但**还原名单里必须有它**
    saved = {k: os.environ.get(k) for k in list(want) + ["SSL_CERT_FILE"]}
    os.environ.update(want)
    print(f"\n默认 SSL 信任库：{_ensure_default_ssl_trust()}")
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture(scope="module", autouse=True)
def _cleanup_created_sites(_platform_env):
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


def _fixture_cmd(fixture, site_id: str | None = None,
                 marker: str | None = None) -> list:
    """deploy_fixture.py 的命令行。`fixture` 可以是 fixtures/ 下的名字，也可以是
    绝对路径——M7 的几条用例要在 tmpdir 里造"坏后端"这类变体。"""
    path = str(fixture) if os.path.isabs(str(fixture)) else \
        str(FIXTURES / str(fixture))
    cmd = [sys.executable, str(ROOT / "site-builder/scripts/deploy_fixture.py"),
           path]
    if site_id:
        cmd += ["--site-id", site_id]
    if marker:
        cmd += ["--marker", marker]
    return cmd


def _job_json(stdout: str) -> dict:
    """deploy_fixture.py 先打印若干进度行（`  [RUNNING] validate`），最后打印
    json.dumps(job, indent=2) —— 是多行的，最后一行只是 `}`。所以只能从
    第一个 `{` 起整块解析，不能取最后一行。"""
    start = stdout.find("{")
    assert start != -1, f"未找到 job JSON:\n{stdout}"
    return json.loads(stdout[start:])


def _deploy(fixture, site_id: str | None = None,
            marker: str | None = None) -> str:
    """部署 fixture，返回站点 URL。"""
    r = subprocess.run(_fixture_cmd(fixture, site_id, marker),
                       capture_output=True, text=True, timeout=1800)
    assert r.returncode == 0, r.stdout + r.stderr
    job = _job_json(r.stdout)
    url = job.get("url")
    assert url, f"job 无 url 字段: {job}"
    # **记账在 return 之前**：任何后续断言失败时清理仍能找到这个站点。
    # 放在调用方记账会漏掉"部署成功但第一条断言就失败"的那条路径。
    _record_created(url)
    return url


def _deploy_expected_to_fail(fixture, site_id: str) -> dict:
    """部署一个**预期失败**的版本，返回失败的 job 记录。

    `_deploy` 断言 `returncode == 0`，所以失败路径必须另开一个入口——在 `_deploy`
    里加个 `expect_fail` 开关会让"忘了传"静默变成"断言反了"。

    **必须传 site_id**：这条路径的全部意义是"对一个已经在线的站点做一次会失败的
    更新"，随机 site_id 验的是首次部署失败，那是另一件事。
    """
    assert site_id, "失败路径必须指定 site_id（否则验的是首次部署，不是更新）"
    _record_site_id(site_id)
    r = subprocess.run(_fixture_cmd(fixture, site_id), capture_output=True,
                       text=True, timeout=1800)
    assert r.returncode != 0, f"预期失败的版本竟然部署成功了：\n{r.stdout}"
    job = _job_json(r.stdout)
    assert job["status"] == "FAILED", job
    return job


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
    # （"同 site_id 二次部署"那条路径由后面 M7 的五条覆盖，那里用 --site-id
    #   把两次部署钉在同一个站点上。）
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
    time.sleep(ROUTE_CACHE_WAIT)  # Edge 路由缓存过期
    code, _, _ = _req(url + "/")
    assert code == 404


# ════════════════════════════════════════════════════════════════════════
# M7 spec §5：blue/green 原子更新的五条
#
# 共同的判据是**公网 /api/health 的响应体里是哪个 marker**。marker 由
# deploy_fixture.py 的 `--marker` 写进那个响应（见它的 inject_marker），每次部署
# 换一个随机串——所以"第二次部署被整个忽略"与"第二次部署真的换上了新字节"在断言
# 层面可区分。这正是 v1 那三条只断言 HTTP 200 的 E2E 被驳回的原因。
# ════════════════════════════════════════════════════════════════════════


def _lam():
    return boto3.client("lambda", region_name="us-east-1")


def _ddb():
    return boto3.client("dynamodb", region_name="us-east-1")


def _site_row(site_id: str) -> dict | None:
    """sites 表里这个 site_id 的行（强一致）。不存在返回 None。"""
    import common
    return common.get_site_consistent(site_id)


def _assert_site_id_is_free(site_id: str) -> None:
    """这个 site_id 在 sites 表里**必须不存在**，否则拒绝使用。

    这条是 fail-closed 的闸门，不是洁癖。真机跑完清点资源时发现：试点环境里有一个
    **真站点**的 site_id 形如 `notes-<6 位十六进制>`（真人 owner，permissions_rev 已经
    十几），而本函数从前生成的**正是同一个形状**。撞上之后：

      ① `--site-id` 让部署覆盖那个站点的 Lambda 与路由，并把 owner 改成 fixture@test；
      ② 紧接着 module 级清理按 `purge_data=True` 下线它 ⇒ 连 DynamoDB 数据表一起删。

    也就是**不可恢复地毁掉一个真用户的站点**。单次概率 1/16^6，但代价不可逆，所以
    按闸门处理而不是赌概率。已 DELETED 的旧行同样拒绝：复用那种 id 会让本次清理去动
    一段别人的历史记录。

    本文件原有的注释只防住了"按 owner 批量删"这一种误伤，没防住 site_id 撞车。
    """
    row = _site_row(site_id)
    assert row is None, (
        f"site_id {site_id} 在 sites 表里**已存在**"
        f"（status={row.get('status')!r}, owner={row.get('owner')!r}）——"
        "拒绝使用：E2E 会用 --site-id 覆盖它、再按 purge_data=True 清理掉它，"
        "那对真站点是不可恢复的。请重跑（会换一个新的随机 id）")


def _new_site_id(name: str = "notes") -> str:
    """本次运行专用的 site_id。

    **必须自己生成**：M7 的用例要在两次部署之间复用同一个 id，那是"更新"路径的
    唯一入口。**生成时就记账**——第一次部署之后的任何一步失败都还要能清理掉它。

    形态是 `{name}-e2e{4 位十六进制}`：那个 `e2e` 段是给**人**看的——在控制台里
    一眼能判断"这是测试造的"，而纯随机后缀与真站点无法区分（既有的 `e2ekey*` 测试
    站点用的是同一个约定）。真正的闸门是 `_assert_site_id_is_free`。
    """
    site_id = f"{name}-e2e{secrets.token_hex(2)}"
    _assert_site_id_is_free(site_id)
    return _record_site_id(site_id)


def _marker(tag: str) -> str:
    """每次部署一个新随机串。

    **不能复用同一个串**：marker 相同 ⇒ 上传字节相同 ⇒ 构建产物相同 ⇒
    `publish_version` 对"代码与配置都没变"不发新版本（AWS 官方行为），于是
    "版本号变了""CodeSha256 不同"这两条断言会在代码完全正确时也红。
    """
    return f"m7-{tag}-{secrets.token_hex(4)}"


def _route_item(cfg, site_id: str) -> dict | None:
    """路由表里这个站点的**整条** item（强一致）。不存在返回 None。

    整条读是有意的：spec §5.5 要断言"失败恢复写回的是切换前的整值"，挑字段比较
    会漏掉恰好没挑的那个（require_auth / allowed_users / permissions_rev …）。
    """
    return _ddb().get_item(TableName=cfg["Platform"]["routing_table"],
                           Key={"subdomain": {"S": f"app-{site_id}"}},
                           ConsistentRead=True).get("Item")


def _color_url(site_id: str, color: str) -> str | None:
    """这一色**已存在**的 Function URL（不存在返回 None）。"""
    lam = _lam()
    try:
        return lam.get_function_url_config(
            FunctionName=f"site-{site_id}",
            Qualifier=color)["FunctionUrl"].rstrip("/")
    except lam.exceptions.ResourceNotFoundException:
        return None


def _live_color(cfg, site_id: str) -> str | None:
    """路由的 api_target 指着哪个颜色。认不出返回 None（旧式/未迁移）。

    按 spec §4.1 的契约独立实现：颜色不另存一份状态，只能从"api_target 等于哪个
    alias 的 Function URL"反推。
    """
    item = _route_item(cfg, site_id) or {}
    target = item.get("api_target", {}).get("S", "").rstrip("/")
    if not target:
        return None
    for c in COLORS:
        if _color_url(site_id, c) == target:
            return c
    return None


def _other(color: str) -> str:
    return COLORS[1] if color == COLORS[0] else COLORS[0]


def _alias_version(site_id: str, color: str) -> str:
    return _lam().get_alias(FunctionName=f"site-{site_id}",
                            Name=color)["FunctionVersion"]


def _code_sha(site_id: str, version: str) -> str:
    return _lam().get_function_configuration(
        FunctionName=f"site-{site_id}", Qualifier=version)["CodeSha256"]


def _health_body(url: str, cookie: str | None = None) -> str:
    """公网 GET /api/health 的响应体（要求 200）。marker 断言全走这里。"""
    code, _, body = _req(url + "/api/health", cookie=cookie)
    assert code == 200, f"{url}/api/health 返回 {code}：{body[:300]!r}"
    return body.decode(errors="replace")


# ---- tmpdir 里的 fixture 变体（坏后端 / 公开站点）----
#
# 造在 tmpdir 而不是加进 site-builder/fixtures/：这些变体是**故意坏的**，留在仓库里
# 迟早会被别的用例或人当成正常样例部署出去。

# 合同要求后端必须有 GET /api/health（contract/redlines.py 会在部署前拦），所以路由
# 要在；但进程在 listen 之前就抛 ⇒ Lambda init 失败 ⇒ 健康门拿到 FunctionError。
_BAD_BOOT_SERVER = """\
const express = require("express");
const app = express();
app.get("/api/health", (req, res) => res.json({ ok: true }));
throw new Error("m7-e2e: intentional boot failure");
"""

# 健康门与冒烟打的是同一个 /api/health，但走两条路：健康门**直调 alias**并带
# `user-agent: site-builder-deploy-healthcheck`（deploy_lambda_site._health_event），
# 冒烟走公网。要造出"提交点之后才失败"，唯一不动平台代码的办法就是让站点自己按这个
# UA 区分两者。UA 若哪天与平台漂移，这个后端会连健康门都过不去 ⇒ 失败原因变成
# BackendUnhealthy ⇒ 用例里那条 `SmokeFailure` 断言当场红，不会静默变成别的东西。
_SMOKE_POISON_SERVER = """\
const express = require("express");
const app = express();
const DEPLOY_UA = "site-builder-deploy-healthcheck";
app.get("/api/health", (req, res) => {
  if ((req.headers["user-agent"] || "") === DEPLOY_UA) {
    return res.json({ ok: true, gate: "passed" });
  }
  res.status(500).json({ ok: false, why: "m7-e2e: poisoned for public smoke" });
});
app.listen(process.env.PORT || 8080);
"""


def _variant(dest: Path, *, server_js: str | None = None,
             require_login: bool | None = None,
             base: str = "nosql-notes") -> Path:
    """在 dest 下造一个 fixture 变体，返回它的目录（绝对路径）。

    `run.sh` 复制到 **dest 本身**（= 变体目录的父目录）：deploy_fixture.py 从
    fixture 的父目录取它，与仓库里 fixtures/run.sh 的位置一致。漏掉它现在会被
    deploy_fixture 当场拒掉（而不是打出一个没有 Handler 的包）。
    """
    tree = dest / base
    shutil.copytree(FIXTURES / base, tree)
    shutil.copy2(FIXTURES / "run.sh", dest / "run.sh")
    if server_js is not None:
        (tree / "backend/server.js").write_text(server_js, encoding="utf-8")
    if require_login is not None:
        manifest = json.loads((tree / "site.json").read_text())
        manifest["auth"]["require_login"] = require_login
        (tree / "site.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tree


def test_same_site_update_swaps_color_and_serves_the_new_bytes(session_cookie, cfg):
    """spec §5.1 同站更新成功。

    红的条件：第二次部署被忽略（旧 marker 仍在服务）、颜色没换（还部在 live 色上）、
    版本号没变、或两个版本的 CodeSha256 相同。M7 之前的代码在这里必红——那时没有
    blue/green alias，api_target 是函数级 URL，`_live_color` 认不出任何颜色。
    """
    site_id = _new_site_id()
    m_a, m_b = _marker("a"), _marker("b")

    url = _deploy("nosql-notes", site_id=site_id, marker=m_a)
    live_a = _live_color(cfg, site_id)
    # 首次部署落在 COLORS[0]（spec §4.1：live 为 None 时用第一个颜色）
    assert live_a == COLORS[0], f"首次部署没落在 {COLORS[0]}：{live_a}"
    ver_a = _alias_version(site_id, live_a)
    sha_a = _code_sha(site_id, ver_a)
    route_a = _route_item(cfg, site_id)
    assert m_a in _health_body(url, session_cookie), "v1 自己都没在服务"

    url_b = _deploy("nosql-notes", site_id=site_id, marker=m_b)
    assert url_b == url, f"同一个 site_id 的 URL 变了：{url} → {url_b}"

    live_b = _live_color(cfg, site_id)
    assert live_b == _other(live_a), \
        f"路由没切到空闲色（{live_a} → {live_b}）——更新打在了正在服务的那一色上"
    ver_b = _alias_version(site_id, live_b)
    assert ver_b != ver_a, f"两色 alias 指着同一个版本 {ver_a}"
    assert _code_sha(site_id, ver_b) != sha_a, \
        "两个版本的 CodeSha256 相同——新字节根本没进去"
    # 提交点是**一次** put_item，同时切 api_target 与 static_prefix（spec §4.1）
    route_b = _route_item(cfg, site_id)
    assert route_b["static_prefix"]["S"] != route_a["static_prefix"]["S"], \
        "静态前缀没跟着切——前后端不是同一次提交切换的"

    time.sleep(ROUTE_CACHE_WAIT)
    body = _health_body(url, session_cookie)
    assert m_b in body, f"公网仍不是新字节：{body[:300]}"
    assert m_a not in body, f"公网还在服务旧字节：{body[:300]}"


def test_failed_update_leaves_live_intact_and_then_recovers(
        session_cookie, cfg, tmp_path):
    """spec §5.2 + §5.3，**同一个 site_id、同一个序列**。

    §5.2 红的条件：坏更新竟然部成功（returncode 0）、失败原因不是空闲色上的健康门、
    线上颜色/版本/路由被动过、或公网已经不是 v1 的 marker。M7 之前必红：那时新字节
    直接推到挂着 Function URL 的 `$LATEST`，坏后端当场上线，公网 /api/health 是 5xx。

    §5.3 红的条件：坏更新之后这个站点再也部不上去（比如空闲色的 alias 卡在坏版本上、
    或颜色判定被上一次失败带歪）。**必须与 §5.2 同序列**——v1 那条"好→好"里根本没有
    失败部署，验的东西与它声称的无关。
    """
    site_id = _new_site_id()
    m_a, m_c = _marker("a"), _marker("c")

    url = _deploy("nosql-notes", site_id=site_id, marker=m_a)
    live = _live_color(cfg, site_id)
    assert live in COLORS, f"部完了却认不出颜色：{live}"
    ver_live = _alias_version(site_id, live)
    route_before = _route_item(cfg, site_id)
    idle = _other(live)

    job = _deploy_expected_to_fail(
        _variant(tmp_path / "bad", server_js=_BAD_BOOT_SERVER), site_id)
    err = job.get("error", "")
    # **失败身份是断言的一部分**：只断言 FAILED 的话，validate 阶段挂掉、CodeBuild
    # 超时、权限不足都同样绿，而那些根本没走到健康门。`site-{id}:{idle}` 这个片段只
    # 出现在 _health_check 抛的消息里，且在消息最前面——job.error 被截到 500 字符，
    # 靠后的 errorType 可能被切掉，所以身份判据要用最前面那一段。
    assert f"site-{site_id}:{idle}" in err, \
        f"失败不是发生在空闲色 {idle} 的健康门上：{err}"
    assert any(s in err for s in ("BackendUnhealthy", "FunctionError=")), \
        f"失败原因看不出是健康门拦下的：{err}"

    # 线上零影响：颜色、版本、路由整条、公网返回的字节，四样都没变
    assert _live_color(cfg, site_id) == live, "线上颜色被换掉了"
    assert _alias_version(site_id, live) == ver_live, "线上那一色的版本被动了"
    assert _route_item(cfg, site_id) == route_before, "路由被动了（提交点之前）"
    assert m_a in _health_body(url, session_cookie), "公网已经不是 v1 的字节了"

    # §5.3：失败之后仍然能正常更新上去
    assert _deploy("nosql-notes", site_id=site_id, marker=m_c) == url
    time.sleep(ROUTE_CACHE_WAIT)
    body = _health_body(url, session_cookie)
    assert m_c in body, f"失败之后的恢复部署没上线：{body[:300]}"
    assert m_a not in body, f"公网还在服务 v1：{body[:300]}"


def test_legacy_site_migrates_to_blue_green_and_then_survives_a_bad_update(
        session_cookie, cfg, tmp_path):
    """spec §5.4 存量迁移。

    先把一个刚部好的站点**退化**成迁移前的形态（函数级 FURL + 路由指它 + 没有
    alias），这样"存量站点"是真的存量形态而不是描述。

    红的条件：退化后的站点更新竟然没有 fail-closed（那正是 §4.3 不允许的隐式半迁移）、
    迁移脚本没把路由切到 blue、迁移后公网不通、或迁移后的坏更新又打到了线上。
    """
    site_id = _new_site_id()
    m = _marker("legacy")
    url = _deploy("nosql-notes", site_id=site_id, marker=m)
    old_url = _degrade_to_legacy(cfg, site_id)
    time.sleep(ROUTE_CACHE_WAIT)
    assert m in _health_body(url, session_cookie), "退化成旧式形态后站点就不通了"
    assert _live_color(cfg, site_id) is None, "退化没做干净，还认得出颜色"

    # ① 未迁移的站点更新必须 fail-closed（spec §4.3：不做隐式半迁移）
    job = _deploy_expected_to_fail(
        _variant(tmp_path / "bad1", server_js=_BAD_BOOT_SERVER), site_id)
    assert "UnmigratedSite" in job.get("error", ""), \
        f"未迁移站点没有 fail-closed，而是走到了别的失败：{job.get('error', '')}"
    assert m in _health_body(url, session_cookie), "被拒的部署仍然动了线上"

    # ② 跑迁移。**按 site_id 单点调 migrate_one，不跑 CLI 的全表扫描**：
    #    这是真账号，全表扫会把所有真实站点一起迁掉。
    sys.path.insert(0, str(ROOT / "site-builder/scripts"))
    import migrate_sites_to_blue_green as mig
    mig._load_config()
    assert mig.migrate_one(_lam(), _ddb(), site_id, dry_run=False) == "migrated"

    blue = _color_url(site_id, COLORS[0])
    assert blue, f"迁移后 {COLORS[0]} 没有 Function URL"
    item = _route_item(cfg, site_id)
    assert item["api_target"]["S"].rstrip("/") == blue, \
        f"路由没指向 {COLORS[0]}：{item['api_target']['S']} != {blue}"
    assert _live_color(cfg, site_id) == COLORS[0]
    assert old_url != blue, "迁移前后是同一个端点，等于什么都没迁"
    assert m in _health_body(url, session_cookie), "迁移后公网不通"

    # ③ 迁移之后，坏更新同样打不到线上——而且必须是**健康门**在空闲色上拦下的，
    #    不是又一次 UnmigratedSite（那说明迁移其实没被部署路径认出来）
    job = _deploy_expected_to_fail(
        _variant(tmp_path / "bad2", server_js=_BAD_BOOT_SERVER), site_id)
    err = job.get("error", "")
    assert f"site-{site_id}:{_other(COLORS[0])}" in err, \
        f"迁移后的坏更新不是被空闲色的健康门拦下的：{err}"
    assert _live_color(cfg, site_id) == COLORS[0], "坏更新把颜色换了"
    assert m in _health_body(url, session_cookie), "坏更新打到了线上"


def _degrade_to_legacy(cfg, site_id: str) -> str:
    """把一个 blue/green 站点退回迁移前形态，返回那个函数级（无 qualifier）URL。

    **顺序不能反**：先建旧 URL 并把路由指过去，再删颜色的 URL 与 alias。反过来会有
    一段时间路由指着一个已经不存在的端点——那不是"存量站点"的形态，是一次故障。
    """
    lam, fn = _lam(), f"site-{site_id}"
    try:
        old = lam.create_function_url_config(
            FunctionName=fn, AuthType="AWS_IAM")["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        old = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
    # 2025-10 起 Edge 调用需要 InvokeFunctionUrl + InvokeFunction 两条语句，缺一即
    # 403。这里**不带 Qualifier**——存量站点的授权就是授在函数上的。
    for sid, action, extra in (
            ("edge-invoke", "lambda:InvokeFunctionUrl",
             {"FunctionUrlAuthType": "AWS_IAM"}),
            ("edge-invoke-function", "lambda:InvokeFunction",
             {"InvokedViaFunctionUrl": True})):
        try:
            lam.add_permission(FunctionName=fn, StatementId=sid, Action=action,
                               Principal=cfg["Deployer"]["edge_role_arn"], **extra)
        except lam.exceptions.ResourceConflictException:
            pass
    _ddb().update_item(TableName=cfg["Platform"]["routing_table"],
                       Key={"subdomain": {"S": f"app-{site_id}"}},
                       UpdateExpression="SET api_target = :t",
                       ExpressionAttributeValues={":t": {"S": old.rstrip("/")}})
    for c in COLORS:
        for call, kw in ((lam.delete_function_url_config,
                          {"FunctionName": fn, "Qualifier": c}),
                         (lam.delete_alias, {"FunctionName": fn, "Name": c})):
            try:
                call(**kw)
            except lam.exceptions.ResourceNotFoundException:
                pass
    return old.rstrip("/")


def test_smoke_failure_after_the_commit_point_restores_the_whole_route_item(
        cfg, tmp_path):
    """spec §5.5 提交点之后失败会恢复路由。

    站点是**公开**的（require_login=false）：require_auth 站点的冒烟判据是"302 到
    登录端点"，请求根本到不了站点代码，无论后端怎么坏都不会让冒烟失败。

    红的条件：失败原因不是 SmokeFailure（说明没走到提交点之后，验的不是恢复路径）、
    路由没被写回、写回的不是**整值**（少一个字段就不相等）、或公网已经不是 v1 的字节。
    没有恢复逻辑时必红：路由会停在指向那个 500 后端的新色上。
    """
    site_id = _new_site_id()
    m1 = _marker("e1")
    url = _deploy(_variant(tmp_path / "pub", require_login=False),
                  site_id=site_id, marker=m1)
    route_before = _route_item(cfg, site_id)
    assert route_before, "首次部署后路由表里没有这条路由"
    assert route_before.get("require_auth", {}).get("BOOL") is False, \
        "变体没生效——站点仍要求登录，那样冒烟根本到不了站点代码"
    live = _live_color(cfg, site_id)

    job = _deploy_expected_to_fail(
        _variant(tmp_path / "poison", server_js=_SMOKE_POISON_SERVER,
                 require_login=False), site_id)
    err = job.get("error", "")
    # SmokeFailure 只可能发生在**提交点之后**（register_route 已经 put_item 了），
    # 所以这条断言同时确立了"路由确实切过"这个前提——否则下面验的只是"路由没动过"。
    assert "SmokeFailure" in err, f"失败不是冒烟阶段的，验不到恢复路径：{err}"
    after = _route_item(cfg, site_id)
    assert after == route_before, (
        "路由没被整值恢复到切换前——\n"
        f"  切换前: {route_before}\n  失败后: {after}")
    assert _live_color(cfg, site_id) == live, "恢复后线上颜色不是原来那一色"

    time.sleep(ROUTE_CACHE_WAIT)
    body = _health_body(url)
    assert m1 in body, f"恢复后公网不是 v1 的字节：{body[:300]}"
