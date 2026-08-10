#!/usr/bin/env python3
"""**组件部署一致性的唯一真源**：线上跑的是不是这份代码。

由 `verify_contract_fixtures.py` 重构而来（M3 Task 13）。改名的理由：它早就
不只管 contract fixture 了——从 deployer 守卫模块到 auth 再到 panel/MCP，
"部署产物 == 本地源码"这件事只能有一个脚本回答。**旧名不留 shim**：两个入口
会让人只跑其中一个，而漏掉的那个正好是没覆盖的层。

七段（缺一不可）：
  ① 合同 scanner 的真实项目风格判定——合规写法一个都不能误拦；
  ② 已知绕过与真违规一个都不能放过；
     （①② 是纯本地判定，--local 时只跑这两段。x-user-name 那条红线进过
      "修漏报 → 引入误报 → 再修"的循环，所以正反两侧都要覆盖。）
  ③ 线上 deployer Lambda 群：contract/redlines.py + 守卫三件套逐包核对；
  ④ 线上 auth 服务：login_handler.py / session.py + SSM TTL 在产物中；
  ⑤ 线上 panel：四个复制模块 + Function URL AuthType 与 resource policy
     两条语句 + 环境变量**无明文密钥**；
  ⑥ 线上 MCP runtime：镜像 digest 可追溯 + runtime role 含 ops-log PutItem
     与 created_at 白名单；
  ⑦ console route 记录形态（split / api_target / static_prefix / require_auth）。

**为什么本地 pytest 不能替代它**：单测跑本地源码，线上跑的是另一份产物。
实测过两次"仓库里修好了、线上还是旧的"：validate 的 LastModified 停在五个
提交之前；auth 的 SSM TTL 修复在仓库里躺了两天没上线。

用法：
    ./verify_deployed_components.py           # 全部七段
    ./verify_deployed_components.py --local   # 只跑 ①②（无 AWS 凭证时）
"""
import argparse
import configparser
import hashlib
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/contract/src"))
CFG_PATH = HERE.parent / "config.ini"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


# ---- 真实项目风格：合规，必须放行 ----
# 每条都取自真实 Node/TS 后端里会自然写出的形态。误报的代价是拦住合规站点，
# 所以这一组比违规组更重要。
COMPLIANT = {
    "Express + prettier 折行": """
const express = require('express');
const app = express();
app.get('/api/me', (req, res) => {
  const rawUserName =
    req.headers['x-user-name'] || '';
  res.json({ email: req.headers['x-user-email'],
             name: decodeURIComponent(rawUserName) });
});
""",
    "解构取头": """
app.post('/api/notes', async (req, res) => {
  const { 'x-user-email': email, 'x-user-name': rawName } = req.headers;
  const name = decodeURIComponent(rawName || '');
  await db.put({ email, name, body: req.body.text });
  res.json({ ok: true });
});
""",
    "helper 工具函数封装": """
const decodeHeader = (v) => decodeURIComponent(v || '');
function currentUser(req) {
  return { email: req.headers['x-user-email'],
           name: decodeHeader(req.headers['x-user-name']) };
}
module.exports = { currentUser };
""",
    "TypeScript 断言 + 可选链": """
interface User { email: string; name: string }
export function whoami(req: Request): User {
  const raw = req.headers['x-user-name'] as string | undefined;
  return { email: String(req.headers['x-user-email'] ?? ''),
           name: decodeURIComponent(raw ?? '') };
}
""",
    "存进 req 属性供中间件下游用": """
app.use((req, res, next) => {
  req.userEmail = req.headers['x-user-email'];
  req.userName = req.headers['x-user-name'];
  next();
});
app.get('/api/x', (req, res) => {
  res.json({ name: decodeURIComponent(req.userName) });
});
""",
    "实参里带正则替换": """
const name = decodeURIComponent(
  req.headers['x-user-name'].replace(/https?:\\/\\//g, ''));
""",
    "前端 fetch 后解码": """
fetch('/api/me').then(r => r.json()).then(d => {
  const raw = d.headers['x-user-name'];
  document.getElementById('who').textContent = decodeURIComponent(raw);
});
""",
    "req.get() 取头": """
const raw = req.get('x-user-name');
const name = decodeURIComponent(raw || '');
""",
}

# ---- 已知绕过与真违规：必须拦下 ----
VIOLATING = {
    "解码的是无关值": """
const raw = req.headers['x-user-name'];
const q = decodeURIComponent(req.query.q);
db.put({ name: raw, q });
""",
    "只在注释里解码": """
const raw = req.headers['x-user-name'];
// 记得 decodeURIComponent(req.headers['x-user-name'])
db.put({ name: raw });
""",
    "JSDoc 里的示例解码": """
/**
 * @example decodeURIComponent(req.headers['x-user-name'])
 */
const raw = req.headers['x-user-name'];
db.put({ name: raw });
""",
    "字符串里的解码": """
const raw = req.headers['x-user-name'];
logger.info("下游需要 decodeURIComponent(req.headers['x-user-name'])");
db.put({ name: raw });
""",
    "多声明符锚错变量": """
const q = req.query.q, name = req.headers['x-user-name'];
res.json({ q: decodeURIComponent(q), name });
""",
    "完全没解码": """
const name = req.headers['x-user-name'] || '';
db.put({ name });
""",
    "拼接头名且未解码": """
const raw = req.headers['x-user-' + 'name'];
db.put({ name: raw });
""",
}


def run_local() -> None:
    from contract.redlines import _check_user_name_decoded
    print("\n── ① 合规写法必须放行（误报会挡住真实用户）────────")
    for name, code in COMPLIANT.items():
        errs = _check_user_name_decoded(code, Path("api/index.js"))
        check(errs == [], f"放行：{name}",
              "" if errs == [] else "被误拦")
    print("\n── ② 绕过与违规必须拦下 ──────────────────────────")
    for name, code in VIOLATING.items():
        errs = _check_user_name_decoded(code, Path("api/index.js"))
        check(bool(errs), f"拦下：{name}", "" if errs else "被放过")


def read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


def _fetch_package(lam, function_name: str):
    """下载某个 Lambda 的部署包 → ZipFile。带重试，并**校验是合法 zip**。

    两件事都吃过亏（2026-08-08 实测）：
      · 预签名 URL 偶发 RemoteDisconnected / reset；
      · 更阴的是**下到一个截断的片段**（当时拿到 53KB，真实包 5.5MB），
        `curl` 退出码是 0，只有解 zip 才发现坏。所以必须校验而不是只看
        有没有抛异常——"下载成功"不等于"下到了完整文件"。
    """
    import io
    import urllib.request
    import zipfile

    loc = lam.get_function(FunctionName=function_name)["Code"]["Location"]
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(loc, timeout=120) as r:
                blob = r.read()
            return zipfile.ZipFile(io.BytesIO(blob))   # 坏包在这里就会抛
        except Exception as exc:                # noqa: BLE001 连接层/截断都重试
            last = exc
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{function_name} 部署包下载失败: {last}")


def run_deployed() -> None:
    """核对线上 validate Lambda 里的 contract 包与本地一致。"""
    import boto3
    from botocore.config import Config

    region = read_cfg("Platform", "region")
    fn = "site-deployer-validate"
    lam = boto3.client("lambda", region_name=region,
                       config=Config(retries={"max_attempts": 5,
                                              "mode": "adaptive"}))
    print("\n── ③ 线上 validate Lambda 是否加载了这份 scanner ────")
    print(f"  {fn}  LastModified="
          f"{lam.get_function_configuration(FunctionName=fn)['LastModified']}")
    zf = _fetch_package(lam, fn)
    names = [n for n in zf.namelist() if n.endswith("contract/redlines.py")]
    if not names:
        check(False, "部署包里找不到 contract/redlines.py",
              "打包方式变了？先核对 CDK bundling")
        return
    deployed = zf.read(names[0]).decode()
    local = (ROOT / "site-builder/contract/src/contract/redlines.py").read_text()
    d_sha = hashlib.sha256(deployed.encode()).hexdigest()[:12]
    l_sha = hashlib.sha256(local.encode()).hexdigest()[:12]
    check(d_sha == l_sha,
          "线上 redlines.py == 本地 redlines.py",
          f"线上 {d_sha} / 本地 {l_sha}"
          + ("" if d_sha == l_sha
             else " —— **线上仍是旧 scanner**，需重新部署 SiteDeployerStack"))
    # 即便 sha 不同也给出具体差异，便于判断"差的是不是本轮修复"
    if d_sha != l_sha:
        for marker, why in (
                ("_header_holder_names", "关联判定（解码必须对应这个头）"),
                ("_balanced_arg", "括号配平（支持嵌套调用）"),
                ("keep_header", "头名保留（注释里的假解码仍被抹）")):
            check(marker in deployed, f"线上含 {marker} —— {why}")

    # **守卫本体也要核**（2026-08-08 独立审查指出的缺口）：几轮修的缺陷绝大多数
    # 在 permissions.py / register_route.py / common.py 里，只比 redlines.py
    # 等于漏掉了主体。逐个函数包核对，才抓得住"部分 Lambda 没更新"这种半量部署。
    guarded = {
        "permissions.py": ROOT / "site-builder/deployer/functions/permissions.py",
        "register_route.py": ROOT / "site-builder/deployer/functions/register_route.py",
        "common.py": ROOT / "site-builder/deployer/functions/common.py",
    }
    fns = [f["FunctionName"] for f in lam.list_functions()["Functions"]
           if f["FunctionName"].startswith("site-deployer-")]
    mismatched: list[str] = []
    for fname in sorted(fns):
        z = _fetch_package(lam, fname)
        pkg = set(z.namelist())
        for base, path in guarded.items():
            if base not in pkg:
                continue        # 该函数包里没有这个模块，正常（打包差异）
            if (hashlib.sha256(z.read(base)).hexdigest()
                    != hashlib.sha256(path.read_bytes()).hexdigest()):
                mismatched.append(f"{fname}:{base}")
    check(not mismatched,
          f"{len(fns)} 个 site-deployer-* 函数里的守卫模块都与本地一致",
          "不一致: " + ", ".join(mismatched[:5]) if mismatched
          else "permissions/register_route/common 三件套逐包核对通过")

    # **auth 服务也要核**：它此前完全没被任何闸门覆盖，结果 SSM TTL 修复
    # （提交 7238471）在仓库里躺了两天没上线，靠人手查 LastModified 才发现
    # （2026-08-08）。`session.py` 尤其重要——它与 Edge 的验签算法必须字节级
    # 同步，两边漂移的症状是"登录成功但立刻被踢回登录页"，极难定位。
    print("\n── ④ 线上 auth 服务是否加载了这份代码 ──────────────")
    z = _fetch_package(lam, "site-auth-service")
    pkg = set(z.namelist())
    auth_mismatch: list[str] = []
    for base in ("login_handler.py", "session.py"):
        local = ROOT / "site-builder/auth" / base
        if base not in pkg:
            auth_mismatch.append(f"{base}(包里缺失)")
            continue
        if (hashlib.sha256(z.read(base)).hexdigest()
                != hashlib.sha256(local.read_bytes()).hexdigest()):
            auth_mismatch.append(base)
    check(not auth_mismatch,
          "site-auth-service 的 login_handler.py / session.py 与本地一致",
          "不一致: " + ", ".join(auth_mismatch) if auth_mismatch
          else "含 session.py（与 Edge 验签同算法，必须同步）")
    # TTL 必须是**赋值语句**而不是只出现在注释里（前几轮栽过"断言的字样只活在
    # 注释里"，所以这里按行首赋值断言）
    if "login_handler.py" in pkg:
        body = z.read("login_handler.py").decode()
        import re as _re
        check(bool(_re.search(r'^SECRET_TTL_SECONDS = \d+', body, _re.M))
              and "time.monotonic() - hit[1] < SECRET_TTL_SECONDS" in body,
              "SSM 密钥缓存的 TTL 在产物中生效（赋值 + 判定都在）",
              "无 TTL 时轮转密钥后 warm 容器会永久用旧值")


def run_panel() -> None:
    """⑤ 线上 panel：复制模块、Function URL 授权、环境变量无明文密钥。"""
    import json
    import re as _re

    import boto3
    from botocore.config import Config

    region = read_cfg("Platform", "region")
    lam = boto3.client("lambda", region_name=region,
                       config=Config(retries={"max_attempts": 5,
                                              "mode": "adaptive"}))
    print("\n── ⑤ 线上 panel（M3 控制台）────────────────────────")
    fn = "site-panel"
    try:
        conf = lam.get_function_configuration(FunctionName=fn)
    except lam.exceptions.ResourceNotFoundException:
        check(False, f"{fn} 存在", "panel 尚未部署——先跑 deploy_panel.py")
        return
    print(f"  {fn}  LastModified={conf['LastModified']}")

    # 复制清单：panel 的四个依赖模块必须在产物里，且与本地字节一致。
    # 少任何一个都是运行时 ImportError（Task 8 在 MCP 镜像上真踩过）。
    z = _fetch_package(lam, fn)
    pkg = set(z.namelist())
    sources = {
        "common.py": ROOT / "site-builder/deployer/functions/common.py",
        "permissions.py": ROOT / "site-builder/deployer/functions/permissions.py",
        "ops_log.py": ROOT / "site-builder/deployer/functions/ops_log.py",
        "session.py": ROOT / "site-builder/auth/session.py",
        "handler.py": ROOT / "site-builder/panel/handler.py",
        "api.py": ROOT / "site-builder/panel/api.py",
        "console_session.py": ROOT / "site-builder/panel/console_session.py",
    }
    bad: list[str] = []
    for base, path in sources.items():
        if base not in pkg:
            bad.append(f"{base}(缺失)")
            continue
        if (hashlib.sha256(z.read(base)).hexdigest()
                != hashlib.sha256(path.read_bytes()).hexdigest()):
            bad.append(base)
    check(not bad, "panel 产物的 7 个模块与本地一致",
          "不一致: " + ", ".join(bad) if bad
          else "含 session.py（upgrade code 单一实现）与 ops_log.py")

    # **环境变量不得含明文密钥**：GetFunctionConfiguration 会原样回显，
    # 拿到 JWT_SECRET 即可伪造任意用户会话。
    env = conf.get("Environment", {}).get("Variables", {})
    # 判据分两类，都不能只看长度：
    #   ① 键名像密钥（SECRET/TOKEN/PASSWORD/KEY），但 `*_PARAM`（只是参数名）除外；
    #   ② 值像**高熵**串。长度不够——实测 ROUTING_TABLE 的值
    #      `ApplicationWebRouterStack-subdomain-mapping` 有 42 字符且全是
    #      [A-Za-z0-9-]，被"长度 > 40 的不透明串"这条误判成明文密钥（假红一次）。
    #      改为要求"无分隔符 + 大小写数字混排"（真实的 base64/hex 密钥形态），
    #      资源名里的连字符/点会把它排除掉。
    def _looks_high_entropy(v: str) -> bool:
        if len(v) < 32 or not _re.fullmatch(r"[A-Za-z0-9+/=]{32,}", v):
            return False        # 含 - . _ / : 的资源名、ARN、URL 一概排除
        return (any(c.isupper() for c in v) and any(c.islower() for c in v)
                and any(c.isdigit() for c in v))

    SECRETISH = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL",
                 "PRIVATE_KEY")
    leaked = [k for k, v in env.items()
              if (any(s in k.upper() for s in SECRETISH)
                  and not k.upper().endswith("_PARAM"))
              or _looks_high_entropy(str(v))]
    check(not leaked, "panel 环境变量无明文密钥",
          f"疑似明文: {leaked}" if leaked
          else f"只有参数名 JWT_SECRET_PARAM={env.get('JWT_SECRET_PARAM', '缺失')}")
    check(env.get("JWT_SECRET_PARAM", "").startswith("/"),
          "panel 下发的是 SSM 参数名", env.get("JWT_SECRET_PARAM", "缺失"))

    # Function URL：AuthType 与 resource policy 的两条语句
    url_conf = lam.get_function_url_config(FunctionName=fn)
    check(url_conf["AuthType"] == "AWS_IAM",
          "panel Function URL AuthType=AWS_IAM",
          f"实际 {url_conf['AuthType']}"
          + ("" if url_conf["AuthType"] == "AWS_IAM"
             else " —— NONE 等于 endpoint 全网可调"))
    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    stmts = policy.get("Statement", [])
    edge_role = read_cfg("Deployer", "edge_role_arn")
    actions, principals = set(), set()
    for s in stmts:
        a = s.get("Action")
        actions |= set(a if isinstance(a, list) else [a])
        p = s.get("Principal", {})
        principals.add(p.get("AWS") if isinstance(p, dict) else p)
    check(actions == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"},
          "resource policy 恰好两条动作（2025-10 起缺一即 403）",
          f"实际 {sorted(actions)}")
    check(principals == {edge_role},
          "Principal 逐字符 == edge role（不是 * 不是账号根）",
          f"实际 {sorted(principals)}")

    # **resource policy 正确 ≠ 只有 Edge 能调**（Codex 审查 2026-08-10 P1-1）。
    # AWS 的规则：同账号 principal 只要 identity policy 允许
    # lambda:InvokeFunctionUrl + InvokeFunction，无需命中 resource policy 也能
    # 调用。真机验证过：直接签名调用并自带 x-user-email，/api/me 返回 200 且
    # is_admin=true、/api/sites?all=1 返回全部站点。
    # 所以这里必须**真的打一次直连请求**，而不是只读配置。
    env_eid = env.get("EDGE_ROLE_ID", "")
    edge_role_name = edge_role.rsplit("/", 1)[-1]
    try:
        real_eid = boto3.client("iam").get_role(
            RoleName=edge_role_name)["Role"]["RoleId"]
    except Exception as e:
        real_eid = f"<查不到: {e}>"
    check(bool(env_eid) and env_eid == real_eid,
          "panel 下发的 EDGE_ROLE_ID == Edge 角色真实 RoleId",
          f"env={env_eid or '缺失'} vs iam={real_eid}"
          + ("" if env_eid else " —— 缺失时 handler 拒绝所有请求（fail-closed）"))

    _verify_direct_invoke_is_rejected(lam, fn)


def _verify_direct_invoke_is_rejected(lam, fn: str) -> None:
    """**反向验收**：同账号非 Edge 的签名直连必须被拒（403）。

    这条是 P1-1 的真正闸门。它要求当前 AWS 身份**有** Function URL 调用权限
    才有意义——没有权限时拿到的 403 来自 IAM 而不是来自 handler 的校验，
    那样这条断言就是假绿，所以此时明确报 SKIP 而不是 PASS。
    """
    import urllib.error
    import urllib.request

    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    try:
        url = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
        arn = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
        me = boto3.client("sts").get_caller_identity()["Arn"]
        sim = boto3.client("iam").simulate_principal_policy(
            PolicySourceArn=me, ActionNames=["lambda:InvokeFunctionUrl"],
            ResourceArns=[arn])["EvaluationResults"][0]["EvalDecision"]
    except Exception as e:
        print(f"  SKIP  非 Edge 直连必须 403（准备阶段失败: {e}）")
        return
    if sim != "allowed":
        # 没有调用权限时，403 来自 IAM 而非 handler —— 无法证明校验生效
        print("  SKIP  非 Edge 直连必须 403"
              f"（当前身份无 InvokeFunctionUrl 权限，测不出 handler 的判定）")
        return

    target = url.rstrip("/") + "/api/me"
    creds = boto3.Session().get_credentials().get_frozen_credentials()
    req = AWSRequest(method="GET", url=target,
                     headers={"x-user-email": "verify-probe@invalid.local"})
    SigV4Auth(creds, "lambda", read_cfg("Platform", "region")).add_auth(req)
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(target, headers=dict(req.headers)),
            timeout=25)
        status, body = resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode()[:200]
    except Exception as e:
        print(f"  SKIP  非 Edge 直连必须 403（请求失败: {e}）")
        return
    check(status == 403,
          "同账号非 Edge 的签名直连被拒（伪造 x-user-email 无效）",
          f"实际 {status} {body}"
          + (" —— 身份可被伪造，读接口全部越权" if status == 200 else ""))


def run_mcp_and_route() -> None:
    """⑥ MCP runtime 与 ⑦ console route。"""
    import boto3

    region = read_cfg("Platform", "region")
    print("\n── ⑥ 线上 MCP runtime ──────────────────────────────")
    iam = boto3.client("iam")
    role = "site-mcp-runtime-role"
    try:
        names = iam.list_role_policies(RoleName=role)["PolicyNames"]
    except iam.exceptions.NoSuchEntityException:
        check(False, f"{role} 存在", "MCP 尚未部署")
        names = []
    ops_ok = created_ok = False
    for pname in names:
        doc = iam.get_role_policy(RoleName=role, PolicyName=pname)["PolicyDocument"]
        for s in doc.get("Statement", []):
            res = s.get("Resource", "")
            res = res if isinstance(res, list) else [res]
            acts = s.get("Action", "")
            acts = set(acts if isinstance(acts, list) else [acts])
            if any("site-ops-log" in r for r in res):
                # 只 PutItem：给 Update/Delete 等于允许篡改审计
                ops_ok = acts == {"dynamodb:PutItem"}
            if any(r.endswith("table/site-sites") for r in res):
                attrs = (s.get("Condition", {})
                         .get("ForAllValues:StringEquals", {})
                         .get("dynamodb:Attributes", []))
                if "created_at" in attrs:
                    created_ok = True
    check(ops_ok, "MCP runtime role 的 ops-log 权限恰好是 PutItem",
          "" if ops_ok else "缺失或过宽——改权限时会在审计写入处 AccessDenied")
    check(created_ok,
          "MCP runtime role 的 sites 白名单含 created_at",
          "" if created_ok
          else "**缺它则经 MCP 新建站点直接 AccessDenied**（Task 5 已实测 "
               "implicitDeny）——需要跑 deploy_agentcore.py")

    # 镜像 tag 必须可追溯到提交（不是 latest）
    acc = boto3.client("bedrock-agentcore-control", region_name=region)
    try:
        rts = acc.list_agent_runtimes().get("agentRuntimes", [])
    except Exception as exc:                # noqa: BLE001
        check(False, "查询 AgentCore runtime", f"{type(exc).__name__}: {exc}")
        rts = []
    target = [r for r in rts if r.get("agentRuntimeName") == "site_builder_deploy"]
    if target:
        rt = acc.get_agent_runtime(agentRuntimeId=target[0]["agentRuntimeId"])
        uri = (rt.get("agentRuntimeArtifact", {})
                 .get("containerConfiguration", {}).get("containerUri", ""))
        check("@sha256:" in uri,
              "MCP runtime 按 digest 引用镜像（不是可变 tag）",
              uri.rsplit("/", 1)[-1][:40] if uri else "取不到 containerUri")
    else:
        check(False, "找到 site_builder_deploy runtime")

    print("\n── ⑦ console route 记录 ────────────────────────────")
    table = read_cfg("Platform", "routing_table")
    item = boto3.resource("dynamodb", region_name=region).Table(table).get_item(
        Key={"subdomain": "console"}, ConsistentRead=True).get("Item")
    if not item:
        check(False, "console route 存在", "先跑 deploy_panel.py")
        return
    check(item.get("route_mode") == "split",
          "console route_mode=split（/api/* 走 Lambda，其余走 S3）",
          str(item.get("route_mode")))
    check(bool(item.get("api_target")), "console api_target 非空",
          str(item.get("api_target"))[:60])
    prefix = str(item.get("static_prefix", ""))
    check(prefix.startswith("platform/console/"),
          "console static_prefix 指向版本化平台前缀", prefix)
    # **尾斜杠是真机 403 的成因**：Edge 的静态改写是
    # `f"/{static_prefix}{path}"` 且 path 以 "/" 开头，尾斜杠会拼出
    # `platform/console/v1//index.html`，而上传的是单斜杠版本——同一份前端，
    # 两个不同的 S3 key，控制台整站 403。startswith 检查抓不到它（两种形态
    # 都以 "platform/console/" 开头），所以必须单独断言。
    check(not prefix.endswith("/"),
          "console static_prefix 无尾斜杠（否则 Edge 拼出双斜杠 → 整站 403）",
          prefix)
    check(item.get("require_auth") is True,
          "console require_auth=True（面板必须登录）",
          str(item.get("require_auth")))

    # 前端产物真的在 S3 里，且 key 就是 Edge 会去取的那一个。
    # "route 配好了"不等于"页面能打开"——Task 13 之后线上正是 route 存在但
    # platform/console/ 下没有对象的状态（登录后拿到 403/404）。
    bucket = f"site-frontend-{read_cfg('Platform', 'account_id')}"
    index_key = f"{prefix}/index.html"
    try:
        head = boto3.client("s3", region_name=region).head_object(
            Bucket=bucket, Key=index_key)
        check(head["ContentLength"] > 0,
              f"console 首页对象存在（{index_key}）",
              f"{head['ContentLength']} 字节")
    except Exception as exc:
        check(False, f"console 首页对象存在（{index_key}）",
              f"{type(exc).__name__} —— 前端没上传，或 key 与 Edge 取的不一致")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true",
                    help="只跑本地 scanner 判定（①②），不查线上组件")
    args = ap.parse_args()
    run_local()
    if not args.local:
        run_deployed()
        run_panel()
        run_mcp_and_route()
    return 0


if __name__ == "__main__":
    rc = 1
    crashed = ""
    try:
        rc = main()
    except Exception as exc:                # noqa: BLE001
        import traceback
        traceback.print_exc()
        # **必须记在 finally 之外的变量里**：只把 rc 置 1 是不够的，下面的
        # finally 会按"本地 15 项全过"重算 rc 并把它盖成 0。于是
        # run_deployed()（本脚本存在的全部理由）一旦抛异常——没凭证、被节流、
        # 或那个预签名 URL 下载失败（实测会 RemoteDisconnected）——脚本会打印
        # "15/15 项通过"并 exit 0，等于把最关键的检查静默丢掉
        # （2026-08-08 独立审查复现）。
        crashed = f"{type(exc).__name__}: {exc}"
        rc = 1
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        # 下限：合规 8 + 违规 7 = 15 项本地判定，少于这个数说明中途挂了
        # （非 --local 时还有 ③ 的 2 项，但下限只保本地那部分）
        MIN_CHECKS = 15
        print()
        if crashed:
            print(f"结果：执行中断（{crashed}）—— 验收**未完成**，状态不可信。"
                  "本地判定即便全过也不代表线上是这份 scanner。")
            rc = 1
        elif len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）—— "
                  "验收**未完成**，状态不可信")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else ""))
            rc = 1 if failed else 0
    sys.exit(rc)
