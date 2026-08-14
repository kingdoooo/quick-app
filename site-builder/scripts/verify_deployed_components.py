#!/usr/bin/env python3
"""**组件部署一致性的唯一真源**：线上跑的是不是这份代码。

由 `verify_contract_fixtures.py` 重构而来（M3 Task 13）。改名的理由：它早就
不只管 contract fixture 了——从 deployer 守卫模块到 auth 再到 panel/MCP，
"部署产物 == 本地源码"这件事只能有一个脚本回答。**旧名不留 shim**：两个入口
会让人只跑其中一个，而漏掉的那个正好是没覆盖的层。

九段（缺一不可）：
  ① 合同 scanner 的真实项目风格判定——合规写法一个都不能误拦；
  ② 已知绕过与真违规一个都不能放过；
     （①② 是纯本地判定，--local 时只跑这两段。x-user-name 那条红线进过
      "修漏报 → 引入误报 → 再修"的循环，所以正反两侧都要覆盖。）
  ③ 线上 deployer Lambda 群：contract/redlines.py + 守卫三件套逐包核对；
  ④ 线上 auth 服务：login_handler.py / session.py + SSM TTL 在产物中；
  ⑤ 线上 panel：**进包清单从 `deploy_panel.COPY_FILES` 推导**后逐字节核对
     + Function URL AuthType 与 resource policy 两条语句 + 环境变量**无明文
     密钥** + 非 Edge 的签名直连必须 403；
  ⑥ 线上 MCP runtime：镜像 digest 可追溯 + runtime role 含 ops-log PutItem
     与 created_at 白名单；
  ⑦ console route 记录形态（split / api_target / static_prefix / require_auth）；
  ⑧ 线上 key-proxy（二期 M4 的 API Key 交换层，**仅在 config.ini 有 `[ApiKey]`
     段时才跑**——没有该段 = 平台只允许 OAuth 一条认证路径，组件本就不存在）：
     进包清单从 `deploy_key_proxy.COPY_FILES` 推导后逐字节核对 + Function URL
     授权三条 + 环境变量无明文密钥且整体 == 本地 `lambda_environment()` 推导值
     + 非 Edge 直连 403 + `mcp` route 形态 + **`mcp` 不在 Edge 产物的
     `PLATFORM_SUBDOMAINS` 里** + 网关 allowedClients/allowlist 与容器
     `MACHINE_CLIENT_ID` **同开同关** + 哨兵行的 `enabled` 是**布尔**
     + role 对凭证表没有 `PutItem`/`DeleteItem`/`Scan`。
  ⑨ 线上 M5 统计管道：明细表的**真实副本区集合 == `router/config.ini` 的清单**
     + 每个副本 ACTIVE + 聚合表开着 deletion protection + Edge 角色对明细表
     **有且只有 PutItem 且资源逐字覆盖每个副本区** + 无写扩权 + rollup 规则
     ENABLED / cron / target 是 rollup 函数。

**⑨ 为什么只能在真机上验**：副本清单有三条腿，而它们分处两个包——router 栈
给 edge_role 的 PutItem 资源集合与 Edge 代码的 `ACCESS_REPLICA_REGIONS` 都从
`router/config.ini` 推导，而 deployer 栈 `TableV2` 的 replicas 被
`deployer/tests/test_infra_tables.py` 钉在一份**字面量**上，它看不见
`router/config.ini`。往清单里加一个区，**两个包的单测都还是绿的**，而 Edge 在
往一个不存在的副本写——埋点的写失败是**有意吞掉**的，那个区于是静默零数据。
`describe_table` 读回的真实 `Replicas` 是这件事的唯一闸门。

**⑤⑧ 的进包清单为什么必须"推导"而不是手抄**（Task 1 审查的 Minor 2）：
两段各自硬编码一份模块名清单时，每加一个共享模块就多漏一个——`edge_caller.py`
与 `keystore.py` 曾经进了 panel 的部署包却**从不做真机字节比对**，而 panel 的
复制闭包单测与这道闸门当时**同时是绿的**。手抄的清单本身就是下一个漂移源
（M3-FINDINGS §2.18）。

**为什么本地 pytest 不能替代它**：单测跑本地源码，线上跑的是另一份产物。
实测过两次"仓库里修好了、线上还是旧的"：validate 的 LastModified 停在五个
提交之前；auth 的 SSM TTL 修复在仓库里躺了两天没上线。

用法：
    ./verify_deployed_components.py           # 全部九段
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
# Lambda@Edge 的产物在 router 那一侧（⑧ 要读它的 PLATFORM_SUBDOMAINS）
ROUTER_CFG_PATH = ROOT / "router" / "config.ini"

results: list[tuple[bool, str, str]] = []

# ---- 检查数下限（Global Constraints）----
# "少于下限就是没跑完"这条下限只在**数得准**时有意义，所以按段分开记，且
# **只数不可 SKIP 的项**：非 Edge 直连那条在当前身份无 InvokeFunctionUrl 权限时
# 合法地 SKIP（那时的 403 来自 IAM 而不是 handler，算 PASS 就是假绿）。
MIN_LOCAL_CHECKS = 15       # ① 合规 8 + ② 违规 7
MIN_DEPLOYED_CHECKS = 20    # ③ 2 + ④ 2 + ⑤ 7 + ⑥ 3 + ⑦ 6
# ⑧ 只在 [ApiKey] 段存在（组件启用）时计入：产物 1 + 环境变量 2 + scope 1 +
# Function URL 3 + EDGE_ROLE_ID 1 + 环境变量整体 1 + route 6 + Edge 白名单 1 +
# runtime 3 + 哨兵行 2 + role 2 = 23
MIN_KEY_PROXY_CHECKS = 23
# 无 [ApiKey] 段时改跑 absence 断言（Codex P1-3）：Lambda / route / 开关 /
# allowedClients / allowlist 五条。**不是 SKIP**——见 _verify_component_is_absent。
MIN_KEY_PROXY_ABSENT_CHECKS = 5
# ⑨ M5 统计管道：清单 1 + 明细表 3（存在/副本集合/副本 ACTIVE）+ 聚合表 1 +
# Edge 角色 4（读到策略/只有 PutItem/资源逐字/无扩权）+ rollup 规则 3
# （ENABLED/cron/target）= 12。**无条件计入**——M5 不是可选组件。
MIN_ANALYTICS_CHECKS = 12
# 实际下限由 main() 按"这次真跑了哪几段"累加，finally 里读它。初值是本地那部分
# ——main() 之前就崩掉时走的是 crashed 分支，不靠这个值。
min_expected = MIN_LOCAL_CHECKS


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


def _parsed_cfg(path: Path) -> configparser.ConfigParser:
    """读一份 config.ini，**并断言它真的读到了**。

    `ConfigParser.read()` 对不存在的路径是**静默返回空**的（不抛异常）。于是
    "cwd 漂了 / 路径错了"与"文件里真没这一段"在下游是同一个症状，而后者的判定
    （`has_section` / `KeyError`）会给出一个**看起来言之有理的错误结论**。
    2026-08-13 实测栽过：在 `deployer/infra/` 下用相对路径读 `site-builder/
    config.ini`，`has_section('IdP')` 全 False，据此推出了一条根本不存在的
    生产隐患。本函数是那条教训的落点——路径读不到就当场炸，绝不返回空配置。
    """
    c = configparser.ConfigParser(interpolation=None)
    c.read(path)
    if not c.sections():
        raise RuntimeError(
            f"{path} 读不到任何段——configparser 对缺失文件是静默的，"
            "此时任何 has_section/取值判断都会得出假结论。请从仓库根用绝对路径跑。")
    return c


def read_cfg(section: str, key: str) -> str:
    return _parsed_cfg(CFG_PATH)[section][key].split("#")[0].split(";")[0].strip()


def _load_deploy_module(name: str, path: Path):
    """按文件路径加载一个部署脚本，只为取它的 `COPY_FILES` 等**真源常量**。

    为什么是 import 而不是正则/AST 抠那个字面量：清单的唯一定义就在那个模块里，
    import 拿到的是**它真正会用的值**；扒源码等于在这里再造一个解析器，而它对
    "清单改成计算出来的"这类变化会静默给出旧答案。

    两个脚本 import 时都只有 `configparser.read()` 这一类副作用（不发 AWS 调用）。
    `deploy_key_proxy` 会自己 `sys.path.insert` 它依赖的两个目录，所以这里**不做
    任何 sys.path 干预**——干预反而会让 `import handler` 命中 panel 的同名文件。
    """
    import importlib.util
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"加载不了 {path}——它还在原地吗？")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _expected_package_modules(deploy_mod, own_dir: Path) -> dict[str, Path]:
    """部署包里**应该**出现的每个模块名 → 它的本地源文件。

    从部署脚本的 `COPY_FILES` 推导，查找顺序与两个 `_build_zip` 一致
    （`deployer/functions` → `auth`），外加该组件自己的顶层 `*.py`
    （`_build_zip` 打的就是 `HERE.glob("*.py")`，排除部署脚本本身）。

    **不在这里手抄第二份清单**：见模块 docstring 里 ⑤⑧ 那段。清单漂移的症状是
    "新模块进了部署包却永远不被真机比对"，而两侧单测都是绿的。
    """
    fn_dir = ROOT / "site-builder/deployer/functions"
    auth_dir = ROOT / "site-builder/auth"
    out: dict[str, Path] = {}
    for name in deploy_mod.COPY_FILES:
        src = fn_dir / name
        if not src.exists():
            src = auth_dir / name
        if not src.exists():
            raise RuntimeError(
                f"{deploy_mod.__name__}.COPY_FILES 里的 {name} 在本地找不到源文件"
                f"（找过 {fn_dir} 与 {auth_dir}）——部署脚本自己也会在这里中止")
        out[name] = src
    script = Path(deploy_mod.__file__).name
    for py in sorted(own_dir.glob("*.py")):
        if py.name == script:
            continue
        out[py.name] = py
    return out


def _check_package_modules(z, label: str, expected: dict[str, Path]) -> None:
    """产物里的每个模块与本地逐字节一致。少一个就是运行时 ImportError。"""
    pkg = set(z.namelist())
    bad: list[str] = []
    for base, path in sorted(expected.items()):
        if base not in pkg:
            bad.append(f"{base}(缺失)")
            continue
        if (hashlib.sha256(z.read(base)).hexdigest()
                != hashlib.sha256(path.read_bytes()).hexdigest()):
            bad.append(base)
    check(not bad, f"{label} 产物的 {len(expected)} 个模块与本地一致",
          "不一致: " + ", ".join(bad) if bad
          else "清单由 COPY_FILES 推导（加了共享模块会自动纳入比对）")


# ---- 环境变量里不得出现明文密钥：判据两类，⑤⑧ 共用 ----
# 都不能只看长度——实测 ROUTING_TABLE 的值
# `ApplicationWebRouterStack-subdomain-mapping` 有 42 字符且全是 [A-Za-z0-9-]，
# 被"长度 > 40 的不透明串"这条误判成明文密钥（假红一次）。改为要求"无分隔符 +
# 大小写数字混排"（真实的 base64/hex 密钥形态），资源名里的连字符/点会把它排除。
SECRETISH = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY")


def _looks_high_entropy(v: str) -> bool:
    import re as _re
    if len(v) < 32 or not _re.fullmatch(r"[A-Za-z0-9+/=]{32,}", v):
        return False        # 含 - . _ / : 的资源名、ARN、URL 一概排除
    return (any(c.isupper() for c in v) and any(c.islower() for c in v)
            and any(c.isdigit() for c in v))


def _check_env_has_no_plaintext_secret(env: dict, label: str,
                                       param_key: str) -> None:
    """① 键名像密钥（`*_PARAM` 除外——那只是参数名）；② 值像高熵串。

    `lambda:GetFunctionConfiguration` 会**原样回显**环境变量，而它是个常见的
    只读权限：拿到 JWT_SECRET 即可伪造任意用户会话，拿到 machine client secret
    即可自己换机器 token。
    """
    leaked = [k for k, v in env.items()
              if (any(s in k.upper() for s in SECRETISH)
                  and not k.upper().endswith("_PARAM"))
              or _looks_high_entropy(str(v))]
    check(not leaked, f"{label} 环境变量无明文密钥",
          f"疑似明文: {leaked}" if leaked
          else f"只有参数名 {param_key}={env.get(param_key, '缺失')}")
    check(env.get(param_key, "").startswith("/"),
          f"{label} 下发的是 SSM 参数名（不是 secret 本体）",
          env.get(param_key, "缺失"))


def _check_function_url_authz(lam, fn: str, label: str, edge_role: str) -> None:
    """Function URL 的 AuthType + resource policy 恰好两条动作 + Principal 逐字符。

    2025-10 起需要 `InvokeFunctionUrl` + `InvokeFunction`(InvokedViaFunctionUrl)
    两条，缺一即 403；`AuthType=NONE` + `Principal:*` 会被安全扫描自动处置
    （实测删光整个 resource policy）。
    """
    import json

    url_conf = lam.get_function_url_config(FunctionName=fn)
    check(url_conf["AuthType"] == "AWS_IAM",
          f"{label} Function URL AuthType=AWS_IAM",
          f"实际 {url_conf['AuthType']}"
          + ("" if url_conf["AuthType"] == "AWS_IAM"
             else " —— NONE 等于 endpoint 全网可调"))
    policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    actions, principals = set(), set()
    for s in policy.get("Statement", []):
        a = s.get("Action")
        actions |= set(a if isinstance(a, list) else [a])
        p = s.get("Principal", {})
        principals.add(p.get("AWS") if isinstance(p, dict) else p)
    check(actions == {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"},
          f"{label} resource policy 恰好两条动作（2025-10 起缺一即 403）",
          f"实际 {sorted(actions)}")
    check(principals == {edge_role},
          f"{label} Principal 逐字符 == edge role（不是 * 不是账号根）",
          f"实际 {sorted(principals)}")


def _check_edge_role_id_env(env: dict, edge_role: str, label: str) -> str:
    """`EDGE_ROLE_ID` == IAM **现查**的真实 RoleId。返回现查到的值。

    现查而不是让人往 config 里再抄一遍：手抄的第二份真源会漂移。缺这个值时
    `edge_caller.caller_is_edge` 刻意 fail-closed（拒绝所有请求）——所以它既是
    正确性断言也是可用性断言。
    """
    import boto3

    env_eid = env.get("EDGE_ROLE_ID", "")
    try:
        real_eid = boto3.client("iam").get_role(
            RoleName=edge_role.rsplit("/", 1)[-1])["Role"]["RoleId"]
    except Exception as e:                  # noqa: BLE001 查不到也要给出结论
        real_eid = f"<查不到: {e}>"
    check(bool(env_eid) and env_eid == real_eid,
          f"{label} 下发的 EDGE_ROLE_ID == Edge 角色真实 RoleId",
          f"env={env_eid or '缺失'} vs iam={real_eid}"
          + ("" if env_eid else " —— 缺失时 handler 拒绝所有请求（fail-closed）"))
    return real_eid


def _fetch_package(lam, function_name: str, qualifier: str = ""):
    """下载某个 Lambda 的部署包 → ZipFile。带重试，并**校验是合法 zip**。

    `qualifier` 给版本化的函数用（Lambda@Edge 只能按版本取，`$LATEST` 不是
    CloudFront 实际执行的那份）。

    两件事都吃过亏（2026-08-08 实测）：
      · 预签名 URL 偶发 RemoteDisconnected / reset；
      · 更阴的是**下到一个截断的片段**（当时拿到 53KB，真实包 5.5MB），
        `curl` 退出码是 0，只有解 zip 才发现坏。所以必须校验而不是只看
        有没有抛异常——"下载成功"不等于"下到了完整文件"。
    """
    import io
    import urllib.request
    import zipfile

    kw = {"Qualifier": qualifier} if qualifier else {}
    loc = lam.get_function(FunctionName=function_name, **kw)["Code"]["Location"]
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
    """⑤ 线上 panel：进包模块、Function URL 授权、环境变量无明文密钥。"""
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

    # 进包清单：**从 deploy_panel.COPY_FILES 推导**，不在这里手抄第二份
    # （见模块 docstring 的 ⑤⑧ 那段）。少任何一个模块都是运行时 ImportError
    # （Task 8 在 MCP 镜像上真踩过）。
    dp = _load_deploy_module("deploy_panel",
                             ROOT / "site-builder/panel/deploy_panel.py")
    _check_package_modules(_fetch_package(lam, fn), "panel",
                           _expected_package_modules(
                               dp, ROOT / "site-builder/panel"))

    env = conf.get("Environment", {}).get("Variables", {})
    _check_env_has_no_plaintext_secret(env, "panel", "JWT_SECRET_PARAM")

    edge_role = read_cfg("Deployer", "edge_role_arn")
    _check_function_url_authz(lam, fn, "panel", edge_role)
    _check_edge_role_id_env(env, edge_role, "panel")

    # **resource policy 正确 ≠ 只有 Edge 能调**（Codex 审查 2026-08-10 P1-1）。
    # AWS 的规则：同账号 principal 只要 identity policy 允许
    # lambda:InvokeFunctionUrl + InvokeFunction，无需命中 resource policy 也能
    # 调用。真机验证过：直接签名调用并自带 x-user-email，/api/me 返回 200 且
    # is_admin=true、/api/sites?all=1 返回全部站点。
    # 所以这里必须**真的打一次直连请求**，而不是只读配置。
    _verify_direct_invoke_is_rejected(
        lam, fn, "/api/me", "同账号非 Edge 的签名直连被拒（伪造 x-user-email 无效）",
        headers={"x-user-email": "verify-probe@invalid.local"},
        on_200="身份可被伪造，读接口全部越权")


def _verify_direct_invoke_is_rejected(lam, fn: str, path: str, name: str,
                                      headers: dict | None = None,
                                      method: str = "GET",
                                      on_200: str = "") -> None:
    """**反向验收**：同账号非 Edge 的签名直连必须被 handler 拒掉（403）。

    这条是 P1-1 的真正闸门。它要求当前 AWS 身份**有** Function URL 调用权限
    才有意义——没有权限时拿到的 403 来自 IAM 而不是来自 handler 的校验，
    那样这条断言就是假绿，所以此时明确报 SKIP 而不是 PASS。

    **状态码之外还看响应体**：403 有两个来源，而它们要区分开。IAM 拒的响应体是
    `{"Message":"Forbidden"}`，handler 拒的是 `{"error":"禁止访问"}`
    （panel 与 key-proxy 的 ⓪ 步共用 `edge_caller`，两边同一份文案）。只断言
    状态码时，"IAM 恰好也拒了"会让这条闸门在 handler 的校验被删掉之后仍然绿——
    而 simulate_principal_policy 那道 SKIP 前置只挡得住"稳定无权限"的环境，挡不住
    "策略刚好在这一刻不允许"。所以判据是**响应体里有我们自己的 `error` 键**。
    """
    import json
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
        print(f"  SKIP  {name}（准备阶段失败: {e}）")
        return
    if sim != "allowed":
        # 没有调用权限时，403 来自 IAM 而非 handler —— 无法证明校验生效
        print(f"  SKIP  {name}"
              "（当前身份无 InvokeFunctionUrl 权限，测不出 handler 的判定）")
        return

    target = url.rstrip("/") + path
    creds = boto3.Session().get_credentials().get_frozen_credentials()
    req = AWSRequest(method=method, url=target, headers=dict(headers or {}))
    SigV4Auth(creds, "lambda", read_cfg("Platform", "region")).add_auth(req)
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(target, headers=dict(req.headers),
                                   method=method), timeout=25)
        status, body = resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode()[:200]
    except Exception as e:
        print(f"  SKIP  {name}（请求失败: {e}）")
        return
    try:
        from_handler = isinstance(json.loads(body), dict) and \
            "error" in json.loads(body)
    except ValueError:
        from_handler = False
    check(status == 403 and from_handler, name,
          f"实际 {status} {body}"
          + (f" —— {on_200}" if status == 200 and on_200 else "")
          + ("" if from_handler
             else " —— 响应体不是 handler 的 {\"error\":…}，这个 403 来自 IAM，"
                  "证明不了 handler 的校验还在"))


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


def _edge_deployed_source() -> str:
    """CloudFront **当前关联的那个版本**的 Edge 产物 → `index.py` 文本。

    版本选择规则与 `verify_deployed_edge.sh` ① 段一致，**不按"版本号最大/时间
    最新"挑**：Lambda@Edge 的旧版本要等全球副本排空才能删，CDK 期间会出现多次
    `DELETE_FAILED (skipped)`，实测**旧版本的 LastModified 比新版本更晚**。

    这里与那个 shell 脚本有一段重复的定位逻辑。之所以可以接受：本段只问一个
    问题——`mcp` 有没有进 `PLATFORM_SUBDOMAINS`——而这个答案对"读到哪个版本"
    不敏感（`mcp` 从来没进过任何版本；真有人把它加进去并部署了，$LATEST 与
    关联版本都会带上它）。也就是说这份重复**不可能让两个脚本给出相反的结论**。
    """
    import boto3

    region = "us-east-1"        # Lambda@Edge / ACM 的硬约束区域
    rcfg = _parsed_cfg(ROUTER_CFG_PATH)
    stack = rcfg["CDK"]["stack_name"].split("#")[0].strip()
    short = rcfg["LambdaEdge"]["origin_request_function_name"] \
        .split("#")[0].strip()
    outs = boto3.client("cloudformation", region_name=region).describe_stacks(
        StackName=stack)["Stacks"][0].get("Outputs", [])
    dist = next((o["OutputValue"] for o in outs
                 if o["OutputKey"] == "DistributionId"), "")
    if not dist:
        raise RuntimeError(f"栈 {stack} 没有 CfnOutput DistributionId")
    assoc = (boto3.client("cloudfront").get_distribution_config(Id=dist)
             ["DistributionConfig"]["DefaultCacheBehavior"]
             .get("LambdaFunctionAssociations", {}).get("Items", []))
    arns = [a["LambdaFunctionARN"] for a in assoc
            if a.get("EventType") == "origin-request"]
    if len(arns) != 1:
        raise RuntimeError(f"origin-request 关联的 Lambda 不是恰好一个: {arns}")
    qualifier = arns[0].rsplit(":", 1)[-1]
    if not qualifier.isdigit():
        raise RuntimeError(f"分发关联的不是一个具体版本: {arns[0]}")
    z = _fetch_package(boto3.client("lambda", region_name=region),
                       f"{stack}-{short}", qualifier)
    if "index.py" not in set(z.namelist()):
        raise RuntimeError("Edge 产物里没有 index.py——打包方式变了？")
    return z.read("index.py").decode()


def _check_mcp_is_not_a_platform_subdomain(sub: str) -> None:
    """决定 9 的闸门：`{mcp_subdomain}` **不得**进 Edge 的 `PLATFORM_SUBDOMAINS`。

    key-proxy 只认 `X-API-Key`，不需要平台 cookie；进了这个白名单只会让一个
    公网组件白拿一个顶域会话 JWT（Edge 会把保留 cookie 转发给它）。

    **按赋值整行断言再解析元组**，不用裸 `grep`：`PLATFORM_SUBDOMAINS` 这个名字
    在源码注释里也出现，裸匹配时"改了常量但留着注释"照样过——这正是前几轮栽过的
    "断言的字样只活在注释里"。
    """
    import ast

    name = f"{sub} 不在 Edge 产物的 PLATFORM_SUBDOMAINS 里（决定 9）"
    try:
        src = _edge_deployed_source()
    except Exception as exc:            # noqa: BLE001 读不到就是没验成
        check(False, name,
              f"读不到 Edge 产物（{type(exc).__name__}: {exc}）——这条未验成，"
              "不能当通过")
        return
    line = next((ln for ln in src.splitlines()
                 if ln.startswith("PLATFORM_SUBDOMAINS = ")), "")
    if not line:
        check(False, name, "产物里找不到 PLATFORM_SUBDOMAINS 的赋值行")
        return
    try:
        subs = ast.literal_eval(line.split("=", 1)[1].strip())
    except (SyntaxError, ValueError) as exc:
        check(False, name, f"赋值行解析不了（{exc}）: {line[:80]}")
        return
    check(sub not in tuple(subs), name,
          f"产物里是 {tuple(subs)}"
          + (f" —— 含 {sub}，交换层会拿到平台会话 cookie" if sub in tuple(subs)
             else ""))


def _check_key_proxy_role_is_narrow(dkp, cfg) -> None:
    """key-proxy 执行角色：对凭证表**没有** `PutItem`/`DeleteItem`/`Scan`。

    发 Key 是控制台（panel）的事；吊销是置 `revoked` 而不是删行（删了就没有
    审计痕迹）；`Scan` 等于能读全表凭证行。包里带着 `keystore.create` 是有意
    接受的——**代码在但权限不在**是纵深。

    **inline 与 attached 两类策略都要扫**：只扫 inline 时，任何人挂一个
    `AmazonDynamoDBFullAccess` 上去，这道闸门照样绿。
    """
    import boto3

    iam = boto3.client("iam")
    role = dkp.ROLE_NAME
    docs = []
    try:
        for pname in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            docs.append((f"inline:{pname}",
                         iam.get_role_policy(RoleName=role,
                                             PolicyName=pname)["PolicyDocument"]))
        for att in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
            pol = iam.get_policy(PolicyArn=att["PolicyArn"])["Policy"]
            doc = iam.get_policy_version(
                PolicyArn=att["PolicyArn"],
                VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
            docs.append((f"attached:{att['PolicyName']}", doc))
    except iam.exceptions.NoSuchEntityException:
        check(False, f"{role} 存在", "key-proxy 尚未部署")
        return

    FORBIDDEN = ("dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Scan",
                 "dynamodb:BatchWriteItem", "dynamodb:*", "*")
    table = dkp.API_KEYS_TABLE
    granted: list[str] = []
    for src, doc in docs:
        for s in doc.get("Statement", []):
            if s.get("Effect") != "Allow":
                continue
            res = s.get("Resource", "")
            res = res if isinstance(res, list) else [res]
            # `*` 与 `…:table/*` 也覆盖这张表——不能只匹配表名字面量
            if not any(r == "*" or table in r or r.endswith(":table/*")
                       for r in res):
                continue
            acts = s.get("Action", "")
            acts = acts if isinstance(acts, list) else [acts]
            granted += [f"{src}:{a}" for a in acts if a in FORBIDDEN]
    check(not granted,
          f"key-proxy role 对 {table} 无 PutItem/DeleteItem/Scan（含通配）",
          f"被授予了: {granted}" if granted
          else f"扫了 {len(docs)} 份策略（inline + attached）")

    # 更强的一条：inline 策略**逐条等于**本地 role_statements() 推导的结果。
    # 上面那条挡的是已知的坏动作，这条挡的是"多了一条谁也没注意的语句"。
    want = dkp.role_statements(cfg)
    got = next((d for n, d in docs if n == "inline:key-proxy-access"), None)
    same = got is not None and got.get("Statement") == want
    check(same, "key-proxy role 的 inline 策略 == 本地 role_statements() 推导值",
          "线上与本地不一致（Sid 或语句集漂了）——线上跑的不是这份权限模型"
          if not same else f"{len(want)} 条语句逐条相同")


def _verify_component_is_absent(cfg, api_key_config) -> int:
    """无 `[ApiKey]` 段时：断言线上**真的**没有这条凭证通道（Codex P1-3）。

    spec §5.1.1 承诺的是"整段不配 = 平台只允许 OAuth 一条认证路径"。但那只对
    **首次部署**成立——组件已经启用过再把配置段删掉，`deploy_key_proxy.py` 会
    报告"跳过"并返回 0，而线上的 Lambda / route / 已开的哨兵行**一个都不会被拆**
    （凭证表是 RemovalPolicy.RETAIN）。于是配置与线上成了两个真源，而这正是本项目
    反复栽过的那一类（`config.ini` 里那个 `enabled` 键就是同一个陷阱）。

    子域名从 `DEFAULT_MCP_SUBDOMAIN` 取：配置段没了，`mcp_subdomain(cfg)` 返回
    空串，但线上那条 route 用的是**当初**的名字。默认值是绝大多数部署的实际取值；
    若当初自定义过，本段查不到它——所以退化时的文案要说清这一点，别让人以为
    "查过了没有"。
    """
    import boto3

    region = read_cfg("Platform", "region")
    sub = api_key_config.DEFAULT_MCP_SUBDOMAIN
    print("  config.ini 无 [ApiKey] 段 → 断言线上这条通道**真的不存在**"
          f"（子域按默认名 {sub!r} 探测）")

    lam = boto3.client("lambda", region_name=region)
    try:
        lam.get_function_configuration(FunctionName="site-key-proxy")
        gone = False
    except lam.exceptions.ResourceNotFoundException:
        gone = True
    check(gone, "site-key-proxy 已不存在",
          "**仍在线**——删配置段不会拆组件，见 DEPLOY.md ⑤c 的下线步骤"
          if not gone else "")

    route = boto3.resource("dynamodb", region_name=region).Table(
        read_cfg("Platform", "routing_table")).get_item(
            Key={"subdomain": sub}, ConsistentRead=True).get("Item")
    check(route is None, f"{sub} route 已不存在",
          f"**route 仍在**，指向 {str(route.get('api_target'))[:40]}…"
          if route else "")

    # 哨兵行在 RETAIN 表里，删配置段不会动它。**开着的哨兵行 + 活着的 Key
    # = 通道仍然通**，所以这里断言"要么没这行，要么它是关的"。
    try:
        row = boto3.resource("dynamodb", region_name=region).Table(
            "site-api-keys").get_item(Key={"key_hash": "__switch__"},
                                      ConsistentRead=True).get("Item")
    except Exception:                       # noqa: BLE001 表可能已经不在
        row = None
    off = row is None or row.get("enabled") is not True
    check(off, "总开关不是「开」（凭证表是 RETAIN，删配置段不会关它）",
          "**哨兵行 enabled=true**——只要还有未吊销的 Key，通道就是通的"
          if not off else ("哨兵行不存在" if row is None else "已关"))

    # 网关侧的两道门禁：machine client 与 on-behalf 头都不该还在
    try:
        acc = boto3.client("bedrock-agentcore-control", region_name=region)
        rts = acc.list_agent_runtimes().get("agentRuntimes", [])
        t = [r for r in rts if r.get("agentRuntimeName") == "site_builder_deploy"]
        rt = acc.get_agent_runtime(agentRuntimeId=t[0]["agentRuntimeId"]) if t else {}
        allowed = list((rt.get("authorizerConfiguration", {})
                        .get("customJWTAuthorizer", {}).get("allowedClients") or []))
        allowlist = list((rt.get("requestHeaderConfiguration", {})
                          .get("requestHeaderAllowlist") or []))
    except Exception as exc:                # noqa: BLE001
        check(False, "读到 AgentCore runtime 配置", f"{type(exc).__name__}: {exc}")
        return MIN_KEY_PROXY_ABSENT_CHECKS
    check(len(allowed) <= 1,
          "allowedClients 里没有多出来的 machine client",
          f"有 {len(allowed)} 个 client——多出来的那个还能换机器 token"
          if len(allowed) > 1 else "只有 mcp client")
    check(api_key_config.ON_BEHALF_HEADER not in allowlist,
          f"requestHeaderAllowlist 里没有 {api_key_config.ON_BEHALF_HEADER}",
          f"**头仍在白名单里**: {allowlist}"
          if api_key_config.ON_BEHALF_HEADER in allowlist else str(allowlist))
    return MIN_KEY_PROXY_ABSENT_CHECKS


def run_key_proxy() -> int:
    """⑧ 线上 key-proxy（M4 API Key 交换层）。

    返回**这一段承诺的最小检查数**（`MIN_KEY_PROXY_CHECKS` 或 0），由 main()
    累加进下限。组件未启用、或组件根本没部署时返回 0——前者是合法默认状态，
    后者已经落了一条 FAIL，不需要再靠下限报第二次。
    """
    import boto3
    from botocore.config import Config

    cfg = _parsed_cfg(CFG_PATH)
    dkp = _load_deploy_module(
        "deploy_key_proxy", ROOT / "site-builder/key-proxy/deploy_key_proxy.py")
    # 门禁判定走**唯一真源**（`deployer/functions/api_key_config`），本脚本不再
    # 写一次 `has_section("ApiKey")`：多一个判定点就多一处漂移，而漂移的结果是
    # "部分部署"——网关放行、容器拒绝，症状是 HTTP 200 加一句业务错误文案。
    # 这个 import 能成立是因为 deploy_key_proxy 已经把 functions/ 铺进了 sys.path。
    import api_key_config

    print("\n── ⑧ 线上 key-proxy（M4 API Key 交换层）─────────────")
    if not api_key_config.api_key_enabled(cfg):
        # **不 SKIP，而是断言组件真的不存在**（Codex 审查 2026-08-13 P1-3）。
        # 原来这里直接 SKIP，于是"配置显示 OAuth-only 而线上凭证通道仍然活着"
        # 这个状态**没有任何闸门查得出来**——而 spec §5.1.1 承诺的正是"无
        # [ApiKey] 段 = 平台只允许 OAuth 一条认证路径"。
        # 组件门禁只对**首次部署**成立：`deploy_key_proxy.py` 看到无该段就返回 0、
        # 一次 AWS 调用都不发，所以它**不会拆除**已经存在的 Lambda / route /
        # 已开的哨兵行（凭证表还是 RETAIN 的）。把 SKIP 换成 absence 断言，
        # 是让"我以为关了"与"真的关了"这两件事不再靠人的记忆区分。
        return _verify_component_is_absent(cfg, api_key_config)

    region = read_cfg("Platform", "region")
    lam = boto3.client("lambda", region_name=region,
                       config=Config(retries={"max_attempts": 5,
                                              "mode": "adaptive"}))
    fn = dkp.FN_NAME
    try:
        conf = lam.get_function_configuration(FunctionName=fn)
    except lam.exceptions.ResourceNotFoundException:
        check(False, f"{fn} 存在",
              "config.ini 有 [ApiKey] 段但组件没部署——"
              "先跑 key-proxy/deploy_key_proxy.py")
        return 0
    print(f"  {fn}  LastModified={conf['LastModified']}")

    # 进包清单**从 deploy_key_proxy.COPY_FILES 推导**（+ key-proxy 自己的 *.py）
    _check_package_modules(_fetch_package(lam, fn), "key-proxy",
                           _expected_package_modules(
                               dkp, ROOT / "site-builder/key-proxy"))

    env = conf.get("Environment", {}).get("Variables", {})
    _check_env_has_no_plaintext_secret(env, "key-proxy", "MACHINE_SECRET_PARAM")

    # MACHINE_SCOPE 必须是 **config 派生**值（Codex 审查 2026-08-11 P1-2a）：
    # 硬编码 `site-builder-mcp/invoke` 绕开了"config.ini 是唯一取值来源"，而
    # 两处各拼一次会出现"建的 scope 与换 token 用的 scope 不是同一个"——
    # Cognito 报 `invalid_scope`，报错文案把排查方向带向 client 配置。
    want_scope = api_key_config.machine_scope(cfg)
    check(bool(want_scope) and env.get("MACHINE_SCOPE") == want_scope,
          "key-proxy 的 MACHINE_SCOPE == config 派生的 {resource_server}/{scope}",
          f"env={env.get('MACHINE_SCOPE', '缺失')} vs 派生={want_scope}")

    edge_role = read_cfg("Deployer", "edge_role_arn")
    _check_function_url_authz(lam, fn, "key-proxy", edge_role)
    real_eid = _check_edge_role_id_env(env, edge_role, "key-proxy")

    # 环境变量**整体**与本地 `lambda_environment()` 的推导值一致。上面几条是有
    # 专门诊断文案的重点项，这条兜住其余键（表名 / AgentCore 端点 / Cognito 域 /
    # machine client id）的漂移：任一处漂了都是"部署成功而组件全挂"。
    # **只报差异的键名、不报值**：值里有端点 URL 与 client id，没必要打出来。
    try:
        want_env = dkp.lambda_environment(real_eid, cfg)
    except SystemExit as exc:       # 本地推导自己就中止了（配置缺项）
        check(False, "key-proxy 环境变量 == 本地 lambda_environment() 推导值",
              f"本地推导即中止: {exc}")
    else:
        diff = sorted(k for k in set(want_env) | set(env)
                      if env.get(k) != want_env.get(k))
        check(not diff, "key-proxy 环境变量 == 本地 lambda_environment() 推导值",
              f"这些键与本地不一致: {diff}" if diff
              else f"{len(want_env)} 个键逐一相同")

    # 非 Edge 直连必须被 handler 的 ⓪ 步拒掉。对 key-proxy 而言绕过 Edge 不等于
    # 绕过认证（还得有一把有效 Key），但 **Edge 是限流与可观测性的唯一位置**。
    _verify_direct_invoke_is_rejected(
        lam, fn, "/", "非 Edge 的签名直连被 key-proxy 拒（handler 的 ⓪ 步）",
        on_200="绕过 Edge 可直连交换层，Key 的暴力尝试不留任何可告警痕迹")

    # ---- route 形态 ----
    sub = api_key_config.mcp_subdomain(cfg)
    route = boto3.resource("dynamodb", region_name=region).Table(
        read_cfg("Platform", "routing_table")).get_item(
            Key={"subdomain": sub}, ConsistentRead=True).get("Item")
    if not route:
        check(False, f"{sub} route 存在", "先跑 deploy_key_proxy.py")
    else:
        check(route.get("route_mode") == "api-only",
              f"{sub} route_mode=api-only（单端点 POST，没有静态资源）",
              str(route.get("route_mode")))
        # **布尔不是字符串**：Edge 的判定是 `require_auth is False`，字符串会落进
        # "按需要登录处理"→ 302 到登录页，而调用方是只会发 MCP 的客户端，
        # 它拿到的是一坨 HTML。
        check(route.get("require_auth") is False,
              f"{sub} require_auth 是布尔 False（不是字符串）",
              f"{route.get('require_auth')!r}")
        check(route.get("owner") == "platform",
              f"{sub} owner=platform（记录用；Edge 判平台身份只认 host 白名单）",
              str(route.get("owner")))
        target = str(route.get("api_target", ""))
        live = lam.get_function_url_config(
            FunctionName=fn)["FunctionUrl"].rstrip("/")
        check(target == live,
              f"{sub} api_target == 线上 Function URL",
              "route 指向的不是当前 Function URL——改过函数/重建过 URL 后没重跑部署"
              if target != live else target[:44] + "…")
        # 尾斜杠单独断言：Edge 拼接会得到双斜杠，与实际路径不是同一个
        # （M3 实测整站 403）。上面那条等值断言已经隐含它，但这条的症状太特殊，
        # 值得有一句自己的错误文案。
        check(bool(target) and not target.endswith("/"),
              f"{sub} api_target 无尾斜杠（否则 Edge 拼出双斜杠）", target[-24:])
        check(str(route.get("static_prefix", "")) == "",
              f"{sub} static_prefix 为空串（api-only 没有静态前缀）",
              f"{route.get('static_prefix')!r}")

    _check_mcp_is_not_a_platform_subdomain(sub)

    # ---- 网关与容器的三道门禁"同开同关"----
    # allowedClients 在网关配置里、MACHINE_CLIENT_ID 在容器环境里，**分处两地
    # 分别写就会漂移**，而漂移的那一半正好是最难排查的"网关放行、容器拒绝"
    # （HTTP 200 加一句业务错误文案，Codex 审查 2026-08-11 P1-2b）。
    # 期望值取自 deploy_agentcore 的**同一个派生点**，不在这里手抄。
    da = _load_deploy_module("deploy_agentcore",
                            ROOT / "site-builder/mcp/deploy_agentcore.py")
    machine_id = dkp.machine_client_id(cfg)
    accc = boto3.client("bedrock-agentcore-control", region_name=region)
    rts = accc.list_agent_runtimes().get("agentRuntimes", [])
    target_rt = [r for r in rts
                 if r.get("agentRuntimeName") == da.RUNTIME_NAME]
    if not target_rt:
        check(False, f"找到 {da.RUNTIME_NAME} runtime", "MCP 尚未部署")
    else:
        rt = accc.get_agent_runtime(
            agentRuntimeId=target_rt[0]["agentRuntimeId"])
        allowed = list((rt.get("authorizerConfiguration", {})
                        .get("customJWTAuthorizer", {})
                        .get("allowedClients") or []))
        allowlist = list((rt.get("requestHeaderConfiguration", {})
                          .get("requestHeaderAllowlist") or []))
        rt_env = rt.get("environmentVariables") or {}
        check(sorted(allowed) == sorted(da.allowed_clients(cfg)),
              "AgentCore allowedClients == 本地 allowed_clients() 推导值"
              "（含 machine client）",
              f"线上 {len(allowed)} 个 / 本地 {len(da.allowed_clients(cfg))} 个"
              + ("" if machine_id in allowed
                 else " —— machine client 不在名单里，机器 token 在网关层就被拒"))
        check(sorted(allowlist) == sorted(da.request_header_allowlist(cfg)),
              f"requestHeaderAllowlist == 本地推导值（含 "
              f"{api_key_config.ON_BEHALF_HEADER}）", str(allowlist))
        # **当且仅当**：网关名单里有 machine client ⟺ 容器拿到了同一个 id。
        in_gateway = machine_id in allowed
        container_id = (rt_env.get(da.MACHINE_CLIENT_ID_ENV) or "").strip()
        check(in_gateway == bool(container_id)
              and (not container_id or container_id == machine_id),
              f"网关 allowedClients 与容器 {da.MACHINE_CLIENT_ID_ENV} 同开同关"
              "且是同一个 client id",
              f"网关含={in_gateway} 容器有值={bool(container_id)} "
              f"两者相同={container_id == machine_id}")

    # ---- 哨兵行 ----
    # `enabled` 必须是 DynamoDB **BOOL**：`keystore.lookup` 的判定是
    # `enabled is not True`，字符串 `"true"` 同样被拒，症状是"控制台显示开着但
    # 所有 Key 都 401"（两侧单测各自都绿）。**不断言它是开还是关**——关闸是
    # 管理员的合法状态，这里只报告它。
    # 主键取 `keygen.SWITCH_PK`（deploy_key_proxy 从那里 import 的同一个值），
    # 不在这里写 `"__switch__"` 字面量：手抄的主键漂了就会读到一行不存在的记录，
    # 而"读不到"与"没有这一行"在这里是同一个症状。
    row = boto3.resource("dynamodb", region_name=region).Table(
        dkp.API_KEYS_TABLE).get_item(
            Key={"key_hash": dkp.SWITCH_PK}, ConsistentRead=True).get("Item")
    check(row is not None and "enabled" in row,
          f"{dkp.API_KEYS_TABLE} 的哨兵行存在且有 enabled 字段",
          "哨兵行缺失——keystore.lookup 会把所有 Key 都拒掉" if not row
          else f"updated_by={row.get('updated_by', '?')}")
    check(isinstance((row or {}).get("enabled"), bool),
          "哨兵行的 enabled 是布尔（字符串 \"true\" 会让所有 Key 401）",
          f"{(row or {}).get('enabled')!r}（当前总开关："
          f"{'开' if (row or {}).get('enabled') is True else '关'}）")

    _check_key_proxy_role_is_narrow(dkp, cfg)
    return MIN_KEY_PROXY_CHECKS


def _describe_table_or_none(ddb, table: str):
    """`describe_table`，表不存在时返回 None **而不是把异常抛出去**。

    ⑨ 段里最能抓东西的是 Edge 角色那几条（本仓唯一看得见跨包副本漂移的地方），
    而它们排在这几个 describe 之后。任何一个 describe 抛出去都会中断整段——于是
    "deployer 栈还没部署这一版 / 正在分步部署"这种**部分部署**中间态下，真正要看
    的那几条一条也不跑，而部分部署恰好是 DEPLOY.md 那套分步流程的正常中间态。
    表不存在时照样落 FAIL，段内检查数不变（下限还数得准）。
    """
    try:
        return ddb.describe_table(TableName=table)["Table"]
    except ddb.exceptions.ResourceNotFoundException:
        return None


def _mask_account(text: str) -> str:
    """把 12 位账号 ID 换成 `<acct>`。

    ⑨ 段的失败文案里带 ARN，而这些输出会被贴进 findings / 交接文档 / 审查报告。
    账号 ID 不该跟着走——git 历史已经清洗过一次真实账号值。
    """
    import re as _re
    return _re.sub(r"\d{12}", "<acct>", text)


def run_analytics() -> int:
    """⑨ M5 统计管道的线上形态。返回本段承诺的最小检查数。

    **别拿 CFN 的 StackStatus 当结论**（M4-FINDINGS §3.13）——直接
    `describe_table` 读回 `Replicas` / `DeletionProtectionEnabled`，那才是被改的
    那个属性。栈状态 UPDATE_COMPLETE 只说明"上一次部署的模板收敛了"。

    这一段扛的是模块 docstring 里 ⑨ 那段说的事：副本清单的三条腿分处两个包，
    加一个区时两个包的单测都还是绿的，而 Edge 往不存在的副本写、失败被埋点吞掉。
    """
    import boto3

    print("\n── ⑨ 线上 M5 统计管道 ──────────────────────────────")
    region = read_cfg("Platform", "region")
    # `_parsed_cfg` 读不到任何段就当场炸，不返回空配置（M4-FINDINGS §3.10）：
    # 否则"cwd 漂了"与"配置里真没这一段"在下游是同一个症状。
    rcfg = _parsed_cfg(ROUTER_CFG_PATH)
    # **清单从 router/config.ini 推导，不在这里手抄第二份**：手抄的清单每加一个
    # 区就漏一个，而漏掉的那个区正是静默零数据的那个（M4-FINDINGS §3.9）。
    # 顺带把行内注释切掉（configparser 默认保留它）——`stack.py` 拼 ARN 时只
    # `.strip()`，所以配置里真带了注释时线上 ARN 会**带着注释**，与这里推导出的
    # 干净值不等 ⇒ 下面那条逐字断言会响亮地红，而不是两边一起被污染后假绿。
    table = rcfg["SiteBuilder"]["access_table"].split("#")[0].split(";")[0].strip()
    regions = [r.strip() for r in
               rcfg["SiteBuilder"]["access_replica_regions"]
               .split("#")[0].split(";")[0].split(",") if r.strip()]
    check(len(regions) >= 2, f"副本清单至少主区+1（{len(regions)} 个）", str(regions))

    d = boto3.client("dynamodb", region_name=region)
    desc = _describe_table_or_none(d, table)
    check(desc is not None and desc["TableStatus"] == "ACTIVE",
          f"{table} 存在且 ACTIVE",
          "**表不存在**——deployer 栈还没部署这一版" if desc is None
          else desc["TableStatus"])
    # 用**并集**写法：`Replicas` 里是否包含被查询的那个区取决于 API 行为，
    # CFN 模板里它**是包含主区的**（2026-08-14 synth 实测
    # ['ap-southeast-1','ap-northeast-1','us-east-1']），而 DescribeTable 的
    # 运行时行为本轮未实测——并集对两种行为都成立。主区补 ACTIVE 的依据是
    # describe 本身在主区成功返回了。
    live = {r["RegionName"]: r.get("ReplicaStatus", "?")
            for r in (desc or {}).get("Replicas", [])}
    if desc is not None:
        live.setdefault(region, "ACTIVE")
    missing, unexpected = set(regions) - set(live), set(live) - set(regions)
    check(bool(live) and not missing and not unexpected,
          f"副本区集合 == 清单（{sorted(regions)}）",
          f"线上 {sorted(live)}"
          + (f"；清单有而线上无 {sorted(missing)} —— Edge 会往不存在的副本写，"
             "AccessDenied 被埋点吞掉 = 该区静默零数据" if missing else "")
          + (f"；线上有而清单无 {sorted(unexpected)} —— Edge 不会写它，"
             "白付跨区复制的钱" if unexpected else ""))
    # `all()` 对空集合是真——先断言读到了副本（M5-FINDINGS §4.5）
    check(bool(live) and all(v == "ACTIVE" for v in live.values()),
          "每个副本都是 ACTIVE", str(live) if live else "一个副本都读不到")

    # 聚合表名在本仓各处都是字面量（deployer 栈 / deploy_panel / deploy_agentcore
    # 都写死它），没有 config 键可推导——这里跟着写字面量。
    daily = _describe_table_or_none(d, "site-access-daily")
    check((daily or {}).get("DeletionProtectionEnabled") is True,
          "site-access-daily 开着 deletion protection",
          "**表不存在**——deployer 栈还没部署这一版" if daily is None
          else f"{daily.get('DeletionProtectionEnabled')!r}"
               + ("" if daily.get("DeletionProtectionEnabled") is True
                  else " —— 400 天趋势一旦删掉不可重建（明细只活 90 天）"))

    # Edge 角色：有且只有明细表的 PutItem，**且资源逐字覆盖每个副本区**。
    # 只累计 action 的写法恰好漏掉它声称要防的东西：只给 us-east-1 一个 ARN 时
    # action 仍然是 PutItem、闸门绿灯，而两个亚洲区写入 AccessDenied 后被
    # `_record_access` 吞掉 ⇒ 按实测流量分布 **96.1% 的数据静默缺失**。
    # 也**必须读 attached policies**：只读 inline 时，把语句搬进托管策略即绕过。
    #
    # 角色名取自 site-builder/config.ini 的 `[Deployer] edge_role_arn`——与
    # `_check_edge_role_id_env` 和 ⑤⑧ 的 Principal 断言同一个来源。
    # **不用 router/config.ini 的 `[Lambda] execution_role_name`**：那个键与线上
    # Edge 角色无关（角色由 CDK 生成名字，实测线上叫
    # `ApplicationWebRouterStack-EdgeFunctionRole…`），拿它去 list_role_policies
    # 得到的是 NoSuchEntity——闸门会红，但红的理由是假的。
    iam = boto3.client("iam")
    edge_role = read_cfg("Deployer", "edge_role_arn").rsplit("/", 1)[-1]
    # 账号取 router 的 `[AWS] account_id`：`stack.py` 拼这几个 ARN 用的就是它
    # （见那里 Codex P2-4 的注释），拿别处的值比等于比一个不同的真源。
    account = rcfg["AWS"]["account_id"].split("#")[0].split(";")[0].strip()
    docs, n_attached = [], 0
    try:
        for name in iam.list_role_policies(RoleName=edge_role)["PolicyNames"]:
            docs.append(iam.get_role_policy(RoleName=edge_role,
                                            PolicyName=name)["PolicyDocument"])
        attached = iam.list_attached_role_policies(
            RoleName=edge_role)["AttachedPolicies"]
        n_attached = len(attached)
        for pol in attached:
            meta = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
            docs.append(iam.get_policy_version(
                PolicyArn=pol["PolicyArn"],
                VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"])
    except iam.exceptions.NoSuchEntityException as exc:
        print(f"  （Edge 角色 {edge_role} 的策略读到一半就没了: {exc}）")
    check(bool(docs), "读到了 Edge 角色的策略（inline + attached）",
          f"inline={len(docs) - n_attached} attached={n_attached}")

    # 出现在**任何资源**上都算扩权的动作。PutItem 不在这里——它在那三个明细表
    # ARN 上正是期望值，只有落在宽资源（`*` / `…:table/*`）上才算扩权。
    BROAD_WRITE = {"dynamodb:UpdateItem", "dynamodb:DeleteItem",
                   "dynamodb:BatchWriteItem", "dynamodb:*", "*"}
    put_arns, acts_on_table, extra = set(), set(), set()
    for doc in docs:
        stmts = doc.get("Statement", [])
        for st in (stmts if isinstance(stmts, list) else [stmts]):
            # 只数 Allow。**这一段查不出显式 Deny**（真机上 Deny 掉明细表的
            # PutItem 会让埋点全挂而这里照样绿）——那件事由 Task 14 的
            # verify_analytics_e2e.py 真写一行来兜。
            if st.get("Effect") != "Allow":
                continue
            acts = st.get("Action", [])
            acts = {str(a) for a in (acts if isinstance(acts, list) else [acts])}
            # `*` 也要进来：挂一个 AdministratorAccess 上去时 action 是 `*`，
            # 不是 `dynamodb:` 前缀，只按前缀过滤会把它整条跳过。
            if not any(a.startswith("dynamodb:") or a == "*" for a in acts):
                continue
            res = st.get("Resource", [])
            res = [str(r) for r in (res if isinstance(res, list) else [res])]
            hit = {r for r in res if f"table/{table}" in r}
            if hit:
                acts_on_table |= acts
                if "dynamodb:PutItem" in acts:
                    put_arns |= hit
            extra |= acts & BROAD_WRITE
            if any(r == "*" or r.endswith(":table/*") for r in res):
                extra |= acts & {"dynamodb:PutItem"}
    check(acts_on_table == {"dynamodb:PutItem"},
          "Edge 角色对明细表**有且只有** PutItem",
          str(sorted(acts_on_table))
          + (" —— 一条都没有：Edge 的埋点全部 AccessDenied 后被吞掉"
             if not acts_on_table else ""))
    expected_arns = {f"arn:aws:dynamodb:{rg}:{account}:table/{table}"
                     for rg in regions}
    check(put_arns == expected_arns,
          f"PutItem 资源**逐字**覆盖全部 {len(regions)} 个副本区",
          _mask_account(f"缺 {sorted(expected_arns - put_arns)} / "
                        f"多 {sorted(put_arns - expected_arns)}"))
    check(not extra, "Edge 角色没有任何 DynamoDB 写扩权动作", str(sorted(extra)))

    ev = boto3.client("events", region_name=region)
    rule_name = "site-access-rollup-daily"
    try:
        rule = ev.describe_rule(Name=rule_name)
        targets = ev.list_targets_by_rule(Rule=rule_name)["Targets"]
    except ev.exceptions.ResourceNotFoundException:
        rule, targets = {}, []
    check(rule.get("State") == "ENABLED", f"{rule_name} 规则 ENABLED",
          rule.get("State", "**规则不存在**——deployer 栈还没部署这一版"))
    check(rule.get("ScheduleExpression") == "cron(20 0 * * ? *)",
          "rollup 每日 00:20 UTC",
          str(rule.get("ScheduleExpression", "规则不存在")))
    # **ENABLED + cron 正确 + 零个 target 是个完全合法的 EventBridge 规则**：
    # 它每天准点触发、什么也不做。聚合表于是停在最后一次成功那天，而控制台只会
    # 显示一条越来越旧的趋势线——没有报错、没有告警、`describe_rule` 全绿。
    lam = boto3.client("lambda", region_name=region)
    try:
        rollup_arn = lam.get_function_configuration(
            FunctionName="site-access-rollup")["FunctionArn"]
    except lam.exceptions.ResourceNotFoundException:
        rollup_arn = ""
    got = {str(t.get("Arn", "")) for t in targets}
    check(bool(rollup_arn) and got == {rollup_arn},
          f"{rule_name} 的 target 恰好是 site-access-rollup 函数",
          "**site-access-rollup 函数不存在**" if not rollup_arn
          else _mask_account(f"target={sorted(got)}"))
    return MIN_ANALYTICS_CHECKS


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true",
                    help="只跑本地 scanner 判定（①②），不查线上组件")
    args = ap.parse_args()
    global min_expected
    run_local()
    min_expected = MIN_LOCAL_CHECKS
    if not args.local:
        run_deployed()
        run_panel()
        run_mcp_and_route()
        min_expected += MIN_DEPLOYED_CHECKS
        # ⑧ 只在组件启用时计入下限（返回值就是它承诺的最小项数）
        min_expected += run_key_proxy()
        # ⑨ 无条件计入：M5 统计管道不是可选组件
        min_expected += run_analytics()
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
        # 下限由 main() 按"这次真跑了哪几段"累加（见 MIN_* 常量）。旧版只保本地
        # 那 15 项，于是任何线上段整段静默跳过都不会被下限抓到。
        MIN_CHECKS = min_expected
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
