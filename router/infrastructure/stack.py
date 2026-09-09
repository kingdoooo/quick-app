#!/usr/bin/env python3
"""
Application Web Router Stack
CloudFront-based dynamic subdomain routing system using Lambda@Edge and DynamoDB
"""
import os
import configparser
import json
import re
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from aws_cdk import (
    App,
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Environment,
    Tags,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    aws_cloudfront as cloudfront,
    aws_certificatemanager as acm,
    aws_cloudfront_origins as origins,
)
from constructs import Construct

from stack_policy import assert_protected_constructs


class ConfigLoader:
    """Configuration loader supporting config.ini and environment variables"""
    def __init__(self):
        config_file = Path(__file__).parent.parent / "config.ini"
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
    
    def get(self, section: str, key: str, env_var: str = None) -> str:
        """Get config value, prioritize environment variable"""
        if env_var and os.getenv(env_var):
            return os.getenv(env_var)
        return self.config.get(section, key)
    
    def get_int(self, section: str, key: str, env_var: str = None) -> int:
        """Get integer config value"""
        return int(self.get(section, key, env_var))
    
    def get_tags(self) -> dict:
        """Get all tags from config"""
        if self.config.has_section("Tags"):
            return dict(self.config.items("Tags"))
        return {}


def _synth_offline() -> bool:
    """3c-1B ticket 19（merged review M12）：**取不到公钥**时是否允许退化成 SYNTH 占位 allowlist。

    **默认不允许**——`cdk deploy` 一定带凭据，走到这里的失败（`[SessionKeys]` 读不动、
    cryptography 闭包缺失、DescribeKey / GetPublicKey 被拒 / 限流 / 网络）都是该让部署失败的事，
    而不是"打一行 WARNING 然后 exit 0 把一个 kid 永不匹配的 allowlist 全球复制出去"。离线 synth
    （无凭据的 CI、本地看模板）显式设 `APP_SYNTH_OFFLINE=1` 才走占位符路径，且产物仍带 SYNTH-ONLY
    标记（verify_deployed_edge.sh 会抓，纵深保留）。
    配置错误（非 RS256 行、KMS 里的 key 与 `spki_sha256` 不符）在任何模式下都抛：那不是"读不到"，
    是写错了。

    **它只回答"可不可以退化"这一个问题。** 产物里要不要装 Edge 依赖**不看它**，看注进去的 allowlist
    带不带 SYNTH-ONLY 标记（`_asset_is_synth_only`）——理由见 `WebRouterStack.__init__` 那一段。
    """
    return os.getenv("APP_SYNTH_OFFLINE") == "1"


def _edge_placeholder_re():
    """取 `lambda/edge_substitutions.py` 里那条正则（唯一定义），**不污染 `sys.path`**。

    3c-1B-G A5：原先是无条件 `sys.path.insert(0, …/lambda)`。它有两个后果——每次调用都
    多一条重复项；更要紧的是那个目录会**永久**排在 `sys.path[0]`，于是 synth 进程里后续
    任何裸 `import session` / `import origin_request` 都可能解析到 Edge 那边的同名模块。
    用 `spec_from_file_location` 按路径加载，作用域只在本函数内。
    """
    import importlib.util
    path = Path(__file__).resolve().parent / "lambda" / "edge_substitutions.py"
    spec = importlib.util.spec_from_file_location("_edge_substitutions_for_synth", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.PLACEHOLDER_RE


def assert_edge_source_fully_injected(src: str) -> str:
    """注入完成的 Edge 源码里**不许剩任何 `{{…}}`**，剩了就让 synth 失败（3c-1B ticket 21）。

    要防的不是"值读不到"（ticket 19 已经让那条在 synth 失败），而是**替换表漏项**：给
    `origin_request.py` 加一个注入点却忘了往下面那条 replace 链里补一行，产物就会带着字面量
    占位符部署出去，且没有任何一步会拦——`cdk deploy` 照常 exit 0。

    运行期的惰性解析（同一张票的另一半）把这种产物的后果从"整个分发 502"降成"带 cookie 的
    私有请求 500"，但**坏产物本来就不该被生成**：Edge 改一次要 10-20 分钟全球复制才能回滚。

    正则**从 lambda/edge_substitutions.py 取，不在这里抄第二份**：那个模块只用标准库，
    取它与 `_session_keys_on_path` 取 session_keys 是同一个做法（另有三个包的测试也这样
    import 它）。抄一份的代价已经真实发生过：ticket 22 给 helper 的正则补上了数字，而
    verify_deployed_edge.sh 里那份一直停在 `[A-Z_]`、漏掉 `ACCESS_TABLE_V2` 这类名字，
    直到 ticket 21 才发现。**唯一还剩的手抄副本就是那个 shell 闸门**（bash 的 grep 没法
    import），改这条正则时必须连它一起改。
    """
    left = sorted(set(_edge_placeholder_re().findall(src)))
    if left:
        raise ValueError(
            f"Edge 源码注入后仍有未替换的占位符 {left}——`origin_request.py` 新增了注入点，"
            "但 stack.py 的替换链没跟上。synth 拒绝生成模板（带占位符的产物部署出去会让"
            "私有站点的已登录请求 500，而 Edge 回滚要 10-20 分钟全球复制）。"
            "补一行 replace，并同步 lambda/edge_substitutions.py 的 DEFAULTS。")
    return src


def _session_keys_on_path() -> Path:
    """把 `site-builder/auth` 放进 `sys.path` 并返回仓库根。

    **单独一个函数、被每个 `from session_keys import …` 的地方各自调用**：早先它藏在
    `_session_keys()` 里，于是"传了 keys 就不走 `_session_keys()`"的那条路会在 import
    时炸（latent ImportError，只因为调用顺序恰好对才没现形）。
    """
    root = Path(__file__).resolve().parents[2]
    # **幂等**（3c-1B-G A5）：原先每次调用都插一条，一次 synth 下来 `sys.path` 里有 3-4 份重复。
    # 位置仍是 0，**刻意不改成 append**：那会改变解析顺序，而这是 synth 的关键路径。
    # 已知且**未改变**的残留性质：`site-builder/auth` 会留在 `sys.path[0]`，所以本进程后续
    # 任何裸 `import session` / `import verifier_env` 会解析到那边。彻底修法是像
    # `_edge_placeholder_re` 那样按路径加载，但这条路径有三处 `from session_keys import …`
    # 依赖它，改动面比收益大——先只去重。
    target = str(root / "site-builder" / "auth")
    if target not in sys.path:
        sys.path.insert(0, target)
    return root


def _session_keys():
    """`[SessionKeys]` 的唯一定义在 site-builder/auth/session_keys.py（不在本文件复制一份）。"""
    root = _session_keys_on_path()
    from session_keys import load_session_keys
    return load_session_keys(root / "site-builder" / "config.ini")


def load_site_allowlist(keys, *, kms=None) -> str:
    """3c-final：Edge 只认 site family 的 RS256 公钥 allowlist（spec §4.1 / §11.6）。

    → JSON 文本 `kid -> {"alg": "RS256", "spki_b64": <base64 DER SPKI>, "role"}`。每把 key 在这里过 spec §11.6
    第 1 层的四项校验（DescribeKey 三项 + 指纹 == config；session_kms.fetch_verified_public_key_der），任一不符
    **任何模式都抛**——那不是"读不到"，是配置指错了 key。**只取 site family，console 的公钥不进 Edge**
    （公钥不是秘密，但"接受哪些 key"本身就是授权边界）。

    `keys` 可以是已加载的 `SessionKeys`，也可以是**取值函数**（controller R17）：`WebRouterStack` 传的是后者，
    因为"只想看模板"的两条路——显式覆盖与显式离线——必须在 `[SessionKeys]` **根本加载不动**时仍然走得通
    （切换窗口里 site-builder/config.ini 还是旧形态）。急加载会让 `SessionKeysError` 在进本函数之前就抛出来。

    三类失败，三种处置（`_degrade` 是唯一的退化点）：
    1. **配置写错**——非 RS256 行、或 KMS 里的 key 与配置声明的不是同一把（`KeyMaterialMismatch`）：
       **任何模式都抛**，绝不注占位。那不是"读不到"，是指错了 key。
    2. **配置读不动 / 依赖装不上 / KMS 调不通**：默认让 synth 失败（什么都不部署）；只有显式
       `APP_SYNTH_OFFLINE=1` 才注入带 SYNTH-ONLY 标记的占位 allowlist 并在 stderr 警告，
       该模板**绝不能部署**（verify_deployed_edge.sh 会抓到标记）。
    3. `APP_SITE_ALLOWLIST_JSON` 在场 ⇒ 用它，**根本不加载配置、不碰 KMS**（离线 synth / 测试）。

    `import session_kms` **刻意放在取公钥那一步里、不在函数顶部**：它拖着 cryptography 闭包，而离线 synth
    的解释器（router/infrastructure/.venv）里没有那个包——放顶部会让"只想看模板"这条路死在 import 上，
    而那正是 R17 要保住的路。
    """
    _session_keys_on_path()
    from session_keys import SYNTH_PLACEHOLDER_ALLOWLIST_JSON, SessionKeysError

    def _degrade(reason_cn: str, reason_en: str, exc: Exception, fix: str = "",
                 *, as_config_error: bool = False) -> str:
        """**唯一**的退化点：默认让 synth 失败，显式离线才注占位。

        `as_config_error` 给配置本身读不动的那一路：**类型仍是 `SessionKeysError`**（调用方与闸门
        按它判"这是配置错，不是环境故障"），原消息一字不改地留在最前面（它已经指名道姓缺哪个键、
        哪个小节），后面补上与 KMS 那条同样的出路提示——原消息缺的只是"我现在只想看模板怎么办"。
        """
        way_out = ("离线只看模板请显式设 APP_SYNTH_OFFLINE=1（产物带 SYNTH-ONLY 标记、且不含 "
                   "cryptography/，不可部署）或用 APP_SITE_ALLOWLIST_JSON 覆盖。")
        if not _synth_offline():
            if as_config_error:
                raise SessionKeysError(
                    f"{exc}——synth 拒绝生成模板，什么都不会部署。{way_out}") from exc
            raise RuntimeError(
                f"{reason_cn}（{type(exc).__name__}: {exc}）——synth 拒绝生成模板，什么都不会部署。{fix}"
                + way_out) from exc
        print(f"WARNING: {reason_en} ({exc}); APP_SYNTH_OFFLINE=1 ⇒ injecting the SYNTH-ONLY "
              "placeholder allowlist. DO NOT deploy this template.", file=sys.stderr)
        return SYNTH_PLACEHOLDER_ALLOWLIST_JSON

    override = os.getenv("APP_SITE_ALLOWLIST_JSON")   # 显式覆盖（离线 synth / 测试）
    if override:
        text = override
    else:
        try:
            site_refs = list((keys() if callable(keys) else keys).allowlist("site"))
        except SessionKeysError as exc:
            text = _degrade("读 [SessionKeys] 失败", "could not load [SessionKeys]", exc,
                            as_config_error=True)
            site_refs = None
        if site_refs is not None:
            for ref in site_refs:      # 已加载成功的行：非 RS256 是配置错，在 try 之外 ⇒ 任何模式都抛
                if ref.alg != "RS256":
                    raise ValueError(f"{ref.kid}: Edge 只支持 RS256 行（3c-final）")
            try:
                import boto3
                import session_kms
            except ImportError as exc:
                text = _degrade("synth 取公钥要 boto3 与 cryptography（session_kms 的闭包）",
                                "boto3/cryptography missing in the synth interpreter", exc,
                                "先给 router/infrastructure/.venv 装 requirements.txt（bootstrap_venvs.sh "
                                "--only router/infrastructure）；")
            else:
                try:
                    kms = kms or boto3.client("kms", region_name="us-east-1")
                    allow = {ref.kid: {"alg": ref.alg,
                                       "spki_b64": session_kms.spki_b64(
                                           session_kms.fetch_verified_public_key_der(kms, ref)),
                                       "role": ref.role} for ref in site_refs}
                    text = json.dumps(allow, separators=(",", ":"))
                except session_kms.KeyMaterialMismatch:
                    raise          # 配置指错 key（或 key 被换过）：任何模式都不注占位
                except Exception as exc:  # noqa: BLE001
                    text = _degrade("按 [SessionKeys] 从 KMS 取 site 公钥失败",
                                    "could not fetch site public keys from KMS", exc,
                                    "这是 cdk deploy 路径：先确认 deployer 栈已建 CMK、凭据有 "
                                    "kms:DescribeKey / GetPublicKey；")
    if "\'\'\'" in text or "\\" in text:
        raise ValueError("allowlist JSON 含三引号或反斜杠，注进三引号字符串会破坏 Edge 源码")
    # 注入前保证是合法 JSON。ticket 21 之后 Edge 侧是惰性解析（不合法只让"带 cookie 的私有
    # 请求"500，不再是 import 期整个分发 502），但这条**仍然是最该拦住它的地方**：
    # 坏值根本不该进产物，Edge 回滚要 10-20 分钟全球复制。
    json.loads(text)
    return text


SYNTH_ONLY_SENTINEL = "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY.txt"


def _synth_only_marker() -> str:
    """SYNTH-ONLY 标记的**唯一来源**：占位 allowlist 的那个 kid（定义在 session_keys.py）。

    **不在这里抄第二份字面量**——抄一份就会与占位常量、与 verify_deployed_edge.sh 的 grep 各自漂，
    而这三处必须是同一个字符串才谈得上"标记 ⇔ 不可部署"。
    """
    _session_keys_on_path()
    from session_keys import SYNTH_PLACEHOLDER_ALLOWLIST_JSON
    return next(iter(json.loads(SYNTH_PLACEHOLDER_ALLOWLIST_JSON)))


def _asset_is_synth_only(site_allowlist_json: str) -> bool:
    """这份产物是不是"看得出不可部署"的那种：**注进去的** allowlist 带 SYNTH-ONLY 标记。

    判据刻意是**产物内容**而不是 `_synth_offline()` 那个旗标（见 `__init__` 里的理由）。用包含而不是
    与占位常量等值比：显式 `APP_SITE_ALLOWLIST_JSON` 里带上这个标记同样算"我知道这份不可部署"，
    那是离线看模板的正当出路。
    """
    return _synth_only_marker() in site_allowlist_json


def _write_synth_only_sentinel(target_dir: str) -> Path:
    """跳过 vendoring 时往 asset 里放一个带标记的哨兵文件，让"缺依赖"这件事在产物里看得见。

    没有它，"asset 里没有 cryptography/"只能靠数目录发现；有了它，任何按标记做的核对
    （verify_deployed_edge.sh、人眼 `ls`）都会命中。Lambda 产物多一个文本文件无副作用。
    """
    path = Path(target_dir) / SYNTH_ONLY_SENTINEL
    path.write_text(
        f"{_synth_only_marker()}\n\n"
        "这份 Edge 产物是 synth 的占位形态：注入的 allowlist 是 SYNTH-ONLY 占位（kid 永不匹配），\n"
        "且**没有**交叉安装 cryptography 闭包，所以 Lambda@Edge 冷启动会 import 失败。\n"
        "不要部署它。要真产物：让 [SessionKeys] 可加载、凭据能 kms:DescribeKey / GetPublicKey，\n"
        "然后不带 APP_SYNTH_OFFLINE / APP_SITE_ALLOWLIST_JSON 重新 synth。\n",
        encoding="utf-8")
    return path


EDGE_REQUIREMENTS = Path(__file__).parent / "lambda" / "requirements-edge.txt"


def vendor_edge_dependencies(target_dir: str) -> None:
    """把 Edge 的锁定依赖（cryptography 闭包）按 hash 交叉装进 asset 目录（ADR 0003 / spec §11.1）。

    与 deploy_auth.build_zip / deploy_panel._build_zip 同一套开关，目标换成 Lambda@Edge 的
    python3.11 / x86_64（**不是本机**：宿主 wheel 装出来的 cryptography 在 Edge 运行时 import
    失败，而那是全站 502）。`--require-hashes` 是全量语义，清单里任何一个包缺 hash 都会让这条
    install 直接失败——守卫在 auth/tests/test_requirements_locked.py（清单 + 本函数的 argv）。
    """
    subprocess.run([sys.executable, "-m", "pip", "install", "--require-hashes",
                    "-r", str(EDGE_REQUIREMENTS), "--target", target_dir, "-q",
                    "--platform", "manylinux2014_x86_64", "--only-binary", ":all:",
                    "--python-version", "3.11", "--implementation", "cp"], check=True)


ACCOUNT_ID_PLACEHOLDER = "{account_id}"
# 约定名（裁定 D-I10-1）。资产里有**四个生产方**把它写死，所以它不是可自由配置的键：
#   ① deployer/infra/app.py  —— 执行器角色的 IAM 资源 ARN（`arn:aws:s3:::site-frontend-<acct>[/*]`）
#   ② deployer/infra/app.py  —— 六个 step Lambda 的 `FRONTEND_BUCKET` 环境变量
#   ③ panel/deploy_panel.py  —— 控制台前端上传的目标桶
#   ④ scripts/verify_deployed_components.py —— 真机核对（含"桶上不许有 sites/ 过期规则"那条）
# ②的消费方是 upload / undeploy / mark_job 三个 step。改桶名要同时改这四处，改这一个键不够。
FRONTEND_BUCKET_CONVENTION = "site-frontend-" + ACCOUNT_ID_PLACEHOLDER
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
# S3 通用桶名的字符集与长度（3-63、小写字母/数字/`.`/`-`、首尾必须是字母或数字）。
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_IPV4_LIKE_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")


def normalize_account_id(raw: str) -> str:
    """`[AWS] account_id` 的**唯一**归一化点（工单 10 item 8）：→ 正好 12 位数字，否则抛。

    本栈有三个消费方——前端桶名、埋点明细表的 DynamoDB 资源 ARN、栈的 `Environment`。此前三处各自
    `config.get(...)`，而只有桶名那条会因为空值/垃圾**响亮**失败。埋点那条是**静默**的：账号为空时
    ARN 渲染成 `arn:aws:dynamodb:{region}::table/…`，Edge 的 PutItem 全部 AccessDenied，
    而埋点异常一律吞掉（统计不是安全控制）⇒ 那个区静默零数据，没有任何人会知道。

    **只剥空白，行内注释一律拒**——与 `frontend_bucket`、`require_idp_claim`、`trusted_idps`
    三个兄弟键同法。`ConfigLoader` 用裸 `ConfigParser`（`inline_comment_prefixes` 默认关），所以
    `account_id = 000000000000  # 你的账号` 读出来带着那句注释。剥掉它等于替采用者猜意图，而
    「猜对了」与「猜错了」在 synth 输出里长得一模一样；拒掉的话操作者看到的是一句"注释另起一行"。
    """
    account = (raw or "").strip()
    if not account:
        raise ValueError(
            "[AWS] account_id 为空——它要拼进前端桶名、edge role 的 DynamoDB 资源 ARN 与栈的 "
            "Environment。空值在桶名那条会响亮失败，但在埋点 ARN 上是**静默**的（PutItem 全部 "
            "AccessDenied，而埋点异常一律吞掉 ⇒ 该区静默零数据）。先填 router/config.ini 的 "
            "[AWS] account_id（12 位数字）。")
    if "#" in account or ";" in account:
        raise ValueError(
            f"[AWS] account_id 含注释字符（当前 {account!r}）——configparser 会把行内注释并进值，"
            "而账号里不会有 `#` 或 `;`。值里只放 12 位数字，注释另起一行。")
    if not _ACCOUNT_ID_RE.fullmatch(account):
        raise ValueError(
            f"[AWS] account_id 必须是 12 位数字（剥掉两端空白后得到 {account!r}）——"
            "它要拼进前端桶名与 IAM 资源 ARN，写错的后果一半响亮一半静默（见本函数 docstring）。")
    return account


def resolve_frontend_bucket(raw: str, account_id: str) -> str:
    """`[SiteBuilder] frontend_bucket` → 真实桶名（merged review M17；裁定 D-I10-1）。

    契约：**已归一化的 account 进、桶名出**（`account_id` 必须正好 12 位数字，归一化在
    `normalize_account_id` 那一处做）。`{account_id}` 按它插值，与 site-builder 侧同一约定
    （`[Deployer] frontend_bucket`，由 `smoke_router.sh` / `verify_analytics_e2e.py` 同法插值）
    ⇒ 采用者在两份 config.ini 里都不必手填账号。

    **插值后必须等于约定名 `site-frontend-<account_id>`**：与约定相同的字面量放行（已手填账号的
    存量 config.ini 不用改），**其它字面量一律拒**。理由不是洁癖：桶名由上面 `FRONTEND_BUCKET_CONVENTION`
    注释里的四个生产方写死，只改这一个键的结果是 Edge 去读一个**没人写过**的桶 ⇒ 每个静态资源 403，
    而私有桶上"没权限"与"没这个对象"都是 403 ⇒ 最难诊断的那一类。

    行内注释**按拒绝处理、不按剥离处理**——与 `normalize_account_id` 以及下面
    `require_idp_claim` / `trusted_idps` 两个兄弟键同法（这三个键 + 本键显式拒注释；其余读取点没有注释处置）：
    `ConfigLoader` 用裸 `ConfigParser`（`inline_comment_prefixes` 默认关），所以
    `frontend_bucket = site-frontend-{account_id}  # 别改` 读出来的值里带着那句注释。剥掉它等于替
    采用者猜意图；共享键本来就不许带注释（`deployer/tests/test_example_config_consistency.py` 有一条
    专门的断言）。

    每条拒绝都在 **synth 期**抛、什么都不部署：这个值同时进 `arn:aws:s3:::{bucket}/sites/*`（edge role
    的读权限）与 Edge 源码里的 `FRONTEND_BUCKET_DOMAIN`，而 Edge 改一次要 10-20 分钟全球复制才能回滚。
    """
    bucket = (raw or "").strip()
    account = account_id or ""
    if not bucket:
        raise ValueError(
            "[SiteBuilder] frontend_bucket 为空——插出来的 `site-frontend-` 是个合法但不存在的桶名，"
            "IAM 资源 ARN 与 Edge 的 FRONTEND_BUCKET_DOMAIN 照样渲染得出来（症状是每个静态资源 403）。"
            f"填成 {FRONTEND_BUCKET_CONVENTION!r} 即可。")
    if "#" in bucket or ";" in bucket:
        raise ValueError(
            f"frontend_bucket 含注释字符（当前 {bucket!r}）——configparser 会把行内注释并进值，"
            "而桶名里不会有 `#` 或 `;`。值里只放桶名，注释另起一行。")
    if not _ACCOUNT_ID_RE.fullmatch(account):
        raise ValueError(
            f"account_id 必须是已归一化的 12 位数字（当前 {account!r}）——本函数的契约是"
            "「已归一化的 account 进、桶名出」，归一化只在 `normalize_account_id` 一处做，"
            "这里**刻意不再洗一遍**（洗第二遍等于开第二条路径，两条会漂）。"
            "调用方漏了归一化，或者 router/config.ini 的 [AWS] account_id 还没填。")
    bucket = bucket.replace(ACCOUNT_ID_PLACEHOLDER, account)
    if "{" in bucket or "}" in bucket:
        raise ValueError(
            f"frontend_bucket 插值后仍含占位符（当前 {bucket!r}）——只认 {ACCOUNT_ID_PLACEHOLDER}。"
            "残留的占位符会原样进 `arn:aws:s3:::…/sites/*` 与 Edge 源码，那是把花括号部署出去。")
    if not _BUCKET_NAME_RE.fullmatch(bucket):
        raise ValueError(
            f"frontend_bucket 不是合法的 S3 桶名（当前 {bucket!r}）——只允许小写字母、数字、`.`、`-`，"
            "长度 3-63，首尾必须是字母或数字。引号/空格/换行/反斜杠/斜杠都不合法。")
    if ".." in bucket:
        raise ValueError(f"frontend_bucket 含连续的点（当前 {bucket!r}）——S3 桶名不允许 `..`。")
    if _IPV4_LIKE_RE.fullmatch(bucket):
        raise ValueError(f"frontend_bucket 像 IP 地址（当前 {bucket!r}）——S3 桶名不允许 IPv4 形态。")
    expected = FRONTEND_BUCKET_CONVENTION.replace(ACCOUNT_ID_PLACEHOLDER, account)
    if bucket != expected:
        raise ValueError(
            f"frontend_bucket 必须解析成 {expected!r}（当前 {bucket!r}）——桶名在本资产里是**约定**，"
            "不是可自由配置的键：四个生产方把它写死了（deployer/infra/app.py 的 IAM 资源 ARN 与 "
            "FRONTEND_BUCKET 环境变量、panel/deploy_panel.py 的前端上传、经那个环境变量取值的 "
            "upload/undeploy/mark_job、scripts/verify_deployed_components.py 的核对）。**改桶名不是改"
            "这一个键**，要同时改那四处；只改这里的结果是 Edge 去读一个没人写过的桶 ⇒ 每个静态资源 403。"
            f"保持 {FRONTEND_BUCKET_CONVENTION!r} 模板不动即可。")
    return bucket


def assert_frontend_bucket_matches_site_builder(resolved: str, *, config_path=None):
    """两份 config.ini 必须指同一个前端桶（裁定 D-I10-2）。→ 对账用的 site-builder 侧值（跳过时 None）。

    抓两类事故：**错账号**（`AWS_PROFILE` / 手填指到另一个账号，两份文件各说各话）与**手抄漂移**
    （一侧被改成写死的字面量）。此前没有任何运行期交叉校验：本栈只读 router 侧，
    `verify_deployed_components.py` 只读 site-builder 侧，两边各自都"能用"。

    退化只在「离线」那一条与 `load_site_allowlist` 的 `_degrade` 同款（controller R17）；「读不到」那一条**刻意 fail-open**（首装顺序里 site-builder/config.ini 可能还没回填），这与 R17 的部署模式硬失败不同：
    · 显式离线（`APP_SYNTH_OFFLINE=1`）⇒ 连读都不读，stderr 警告后跳过。"只想看模板"这条路必须在
      site-builder/config.ini 还没回填时也走得通。
    · **读不到**（文件不存在 / 缺段 / 缺键 / 解析不了）⇒ stderr 警告后跳过，**刻意不失败**：
      首装顺序里 site-builder/config.ini 可能还没回填到这一段，而 router 侧自己那份已经够渲染出
      正确的桶名（四个生产方也不读这个键）。
    · **写错了**（值本身不合约定）⇒ 抛。那不是"读不到"，与 `_degrade` 里"配置写错任何模式都抛"同一条纪律。
    · 两侧解析出**不同的桶** ⇒ 抛，什么都不部署。
    """
    if _synth_offline():
        print("WARNING: APP_SYNTH_OFFLINE=1; skipping the frontend_bucket cross-config reconciliation "
              "with site-builder/config.ini (template-only synth).", file=sys.stderr)
        return None
    path = Path(config_path) if config_path else \
        Path(__file__).resolve().parents[2] / "site-builder" / "config.ini"
    cfg = configparser.ConfigParser()
    try:
        if not cfg.read(path):
            raise FileNotFoundError(str(path))
        raw = cfg.get("Deployer", "frontend_bucket")
        account = cfg.get("Platform", "account_id")
    except (OSError, configparser.Error) as exc:
        print(f"WARNING: could not read [Deployer] frontend_bucket / [Platform] account_id from {path} "
              f"({type(exc).__name__}: {exc}); skipping the frontend_bucket cross-config reconciliation.",
              file=sys.stderr)
        return None
    try:
        # site-builder 侧的账号走**同一个**归一化点：同样的行内注释在两份文件里必须有同样的待遇。
        other = resolve_frontend_bucket(raw, normalize_account_id(account))
    except ValueError as exc:
        raise ValueError(
            f"site-builder/config.ini 的 [Deployer] frontend_bucket / [Platform] account_id 本身写错了：{exc}"
        ) from exc
    if other != resolved:
        raise ValueError(
            f"两份 config.ini 指向不同的前端桶：router/config.ini 解析出 {resolved!r}，"
            f"{path} 解析出 {other!r}。两份文件描述的是**同一个**账号里的**同一个**桶，"
            "写成两个名字的症状是每个静态资源 403（私有桶上「没权限」与「没这个对象」都是 403，"
            "极难诊断）。先让两侧的 account_id 相等，并把两个 frontend_bucket 都保持成 "
            f"{FRONTEND_BUCKET_CONVENTION!r} 模板。")
    return other


class WebRouterStack(Stack):
    """CloudFront dynamic subdomain routing Stack"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        config = ConfigLoader()
        stack_name = construct_id

        # `[AWS] account_id` 只在这里读一次、归一化一次（工单 10 item 8）。三个消费方共用它：
        # 前端桶名、埋点明细表的 DynamoDB 资源 ARN、栈的 Environment（模块底部那处也走同一个
        # 归一化函数）。各读一次的旧形态里只有桶名那条对空值/垃圾响亮，埋点那条是静默的
        # （理由见 normalize_account_id 的 docstring）。
        account_id = normalize_account_id(config.get("AWS", "account_id", "APP_ACCOUNT_ID"))

        # Apply tags to all resources in this stack
        tags = config.get_tags()
        for key, value in tags.items():
            Tags.of(self).add(key, value)
        
        # DynamoDB table
        mapping_table = dynamodb.Table(
            self,
            "SubdomainMappingTable",
            table_name=f"{stack_name}-{config.get('DynamoDB', 'table_name', 'APP_DYNAMODB_TABLE')}",
            partition_key=dynamodb.Attribute(
                name="subdomain",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )
        
        # Lambda@Edge IAM role
        edge_role = iam.Role(
            self,
            "EdgeFunctionRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lambda.amazonaws.com"),
                iam.ServicePrincipal("edgelambda.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )
        mapping_table.grant_read_data(edge_role)
        # Since October 2025 new function URLs require BOTH lambda:InvokeFunctionUrl
        # and lambda:InvokeFunction; granting only the former yields 403 at the edge.
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"],
            resources=["*"]
        ))

        # Site-builder: shared frontend bucket (private; edge function reads
        # static assets via SigV4-signed GET)
        # `{account_id}` 模板按 [AWS] account_id 插值——与 site-builder/config.ini 同一约定（M17）。
        frontend_bucket = resolve_frontend_bucket(
            config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET"), account_id)
        # 裁定 D-I10-2：再与 site-builder/config.ini 对账（错账号 / 手抄漂移）。
        # 离线或读不到时只警告并跳过；两侧不一致或那边写错了则抛，什么都不部署。
        assert_frontend_bucket_matches_site_builder(frontend_bucket)
        base_domain = config.get("SiteBuilder", "base_domain", "APP_BASE_DOMAIN")
        # 站点前端在 sites/ 下；M3 控制台前端在 platform/console/{version}/ 下。
        # **两个前缀都要给、且只给这两个**：
        #   · 缺 platform/* → route_mode=split 的 console 静态请求全部
        #     AccessDenied（控制台白屏，而 /api/* 正常，症状很误导）；
        #   · 给整桶 /* → 站点前缀与平台前缀的隔离失效。
        # 由 test_stack_edge_iam.py 断言资源集合恰好是这两个。
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["s3:GetObject"],
            resources=[f"arn:aws:s3:::{frontend_bucket}/sites/*",
                       f"arn:aws:s3:::{frontend_bucket}/platform/*"]
        ))

        # M5 埋点：只给明细表的 PutItem，且**每个副本区一条资源**。
        # 副本清单是 config.ini 里的唯一真源（deployer 栈的 TableV2 replicas 与
        # Edge 代码的 ACCESS_REPLICA_REGIONS 用同一份），由
        # test_stack_edge_iam.py 从它推导断言。
        # 只给 PutItem：Edge 是公网请求路径上的组件，只该能"追加一行"，
        # 不该能改写或删除访问历史。
        # **账号取自 config，不用 `self.account`**（Codex 审查 2026-08-14 P2-4）：
        # 实测 `self.account` 在无显式 env 的栈里渲染成
        # {"Fn::Join": ["", ["arn:...:", {"Ref": "AWS::AccountId"}, ":table/..."]]}
        # ——一个 **dict**，模板断言没法按字符串比。用 config 的字面量则渲染成
        # 普通字符串，断言可以逐字比。这也更符合 CLAUDE.md 的「config.ini 是
        # 账号/域名的唯一取值来源」。
        # 值来自 __init__ 顶部那**唯一**的归一化点（工单 10 item 8）——这条 ARN 上的空账号
        # 是静默失败，所以它必须和桶名那条同源、共享同一道校验。
        access_account = account_id
        access_table = config.get("SiteBuilder", "access_table",
                                  "APP_ACCESS_TABLE").strip()
        access_regions = [r.strip() for r in
                          config.get("SiteBuilder", "access_replica_regions",
                                     "APP_ACCESS_REPLICA_REGIONS").split(",")
                          if r.strip()]
        if len(access_regions) < 2:
            raise ValueError(
                f"access_replica_regions 至少要有主区+1 个副本（当前 {access_regions}）"
                "——只有一个区时应该直接去掉副本设计，而不是配一个残缺清单")
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["dynamodb:PutItem"],
            resources=[f"arn:aws:dynamodb:{rg}:{access_account}:table/{access_table}"
                       for rg in access_regions]))

        # Read Lambda code and inject configuration
        lambda_code_path = Path(__file__).parent / "lambda" / "origin_request.py"
        with open(lambda_code_path, 'r') as f:
            lambda_code = f.read()
        
        lambda_code = lambda_code.replace(
            '{{DYNAMODB_TABLE_NAME}}',
            f"{stack_name}-{config.get('DynamoDB', 'table_name', 'APP_DYNAMODB_TABLE')}"
        ).replace(
            '{{DYNAMODB_REGION}}',
            config.get("DynamoDB", "region", "APP_DYNAMODB_REGION")
        )

        # Site-builder placeholders (Task 6/7). The frontend bucket lives in us-east-1
        # (Lambda@Edge SigV4 in origin_request.py signs for us-east-1).
        # 3c-final 起 Edge 拿到的是 site family 的 **RS256 公钥** allowlist：公钥在 synth 时按
        # [SessionKeys] 的 key_arn 从 KMS 取、过四项校验（load_site_allowlist）——Edge 手里再没有
        # 任何能签发的材料。
        # 传的是**取值函数**而不是取好的值（controller R17）：显式覆盖与显式离线这两条"只想看
        # 模板"的路必须在 `[SessionKeys]` 根本加载不动时仍然走得通，急加载会先炸在这一行。
        session_keys = _session_keys
        site_allowlist_json = load_site_allowlist(session_keys)
        # 两个值都要在 synth 时验证——它们控制的是 org 语义在请求路径上的
        # 唯一执行点，配错的代价不对称：
        # ① configparser 默认**保留行内注释**（inline_comment_prefixes=()）：
        #    `require_idp_claim = true   # 按 Task 15 翻开` 读出来的值是
        #    'true   # 按 Task 15 翻开' → lower() != "true" → **防线静默关闭**，
        #    部署成功、无警告。翻开关时顺手加注释是完全现实的操作。
        #    同理 yes/1/on 这些 configparser.getboolean 接受的值这里都算 False。
        # ② require_idp_claim=true 而 trusted_idps 为空 → 所有人被 302 →
        #    全站锁死，而 Edge 重部署要 10-20 分钟全球复制才能恢复。
        # ③ 两个键都是必填：缺键时 ConfigLoader.get 抛 NoOptionError（响亮失败），
        #    不要给它们加默认值——留占位符字面量同样是"防线静默关闭"。
        require_idp_claim = config.get("SiteBuilder", "require_idp_claim",
                                       "APP_REQUIRE_IDP_CLAIM").strip()
        trusted_idps = config.get("SiteBuilder", "trusted_idps",
                                  "APP_TRUSTED_IDPS").strip()
        if require_idp_claim not in ("true", "false"):
            raise ValueError(
                f"require_idp_claim 必须是 true/false（当前 {require_idp_claim!r}）"
                "——行内注释会被并进值里，yes/1/on 也不行（会被当成 false，"
                "防线静默关闭）")
        if require_idp_claim == "true" and not trusted_idps:
            raise ValueError(
                "require_idp_claim=true 但 trusted_idps 为空——部署出去所有"
                "用户都会被 302 锁死（Edge 回滚要 10-20 分钟全球复制）。"
                "先在 [SiteBuilder] 填 trusted_idps。")
        # trusted_idps 同样吃行内注释的亏：`Feishu   # 飞书` 会整串进白名单，
        # idp="Feishu" 匹配不上任何项 → 开关为 true 时同样是全站锁死。
        # provider 名不可能含 #，见到即为注释被并进值。
        if "#" in trusted_idps or ";" in trusted_idps:
            raise ValueError(
                f"trusted_idps 含注释字符（当前 {trusted_idps!r}）——configparser "
                "会把行内注释并进值，白名单被污染后没有任何 idp 能匹配上"
                "（require_idp_claim=true 时 = 全站锁死）。值里只放 provider 名。")
        lambda_code = (lambda_code
            .replace("{{FRONTEND_BUCKET_DOMAIN}}",
                     f"{frontend_bucket}.s3.us-east-1.amazonaws.com")
            .replace("{{SITE_ALLOWLIST_JSON}}", site_allowlist_json)
            .replace("{{BASE_DOMAIN}}", base_domain)
            .replace("{{REQUIRE_IDP_CLAIM}}", require_idp_claim)
            .replace("{{TRUSTED_IDPS}}", trusted_idps)
            .replace("{{ACCESS_TABLE}}", access_table)
            .replace("{{ACCESS_REPLICA_REGIONS}}", ",".join(access_regions)))
        # 全部替换完成之后、写产物之前：漏项即 synth 失败（ticket 21，见函数 docstring）
        lambda_code = assert_edge_source_fully_injected(lambda_code)

        # Write to temporary file
        temp_dir = tempfile.mkdtemp()
        with open(os.path.join(temp_dir, 'index.py'), 'w') as f:
            f.write(lambda_code)

        # Edge 内嵌 verifier 现在 import cryptography（RS256 验签），而 Lambda@Edge 既没有层
        # 也不能带环境变量 ⇒ 依赖必须在这里按 hash 交叉装进 asset 目录（ADR 0003 / spec §11.1）。
        #
        # **判据是注进产物的 allowlist 带不带 SYNTH-ONLY 标记，不是 `_synth_offline()` 那个旗标。**
        # 按旗标判会开出第四种组合：旗标还留在 shell / CI 环境里（陈旧变量），而 config 已是 RS 形态、
        # KMS 可达、四项校验通过 ⇒ 注进去的是**真** allowlist（产物没有标记、看起来完全正常），
        # 却跳过了 vendoring ⇒ asset 里没有 cryptography/ ⇒ **每次** Edge 冷启动 import 失败
        # = 所有子域 502，而 Edge 回滚要 10-20 分钟全球复制。资产的安全叙事是
        # 「标记 ⇔ 不可部署」，这里按**构造**维持它：跳过 vendoring 的那一支一定写标记哨兵，
        # 没有标记的那一支一定装依赖。第三种结局是**响亮失败**——带真 allowlist 而 pip 装不动
        # （无网）时 `check=True` 让 synth 失败，那正确：这种产物既没有标记又缺依赖。
        if _asset_is_synth_only(site_allowlist_json):
            _write_synth_only_sentinel(temp_dir)
        else:
            vendor_edge_dependencies(temp_dir)

        # Lambda@Edge function
        edge_function = lambda_.Function(
            self,
            "OriginRequestFunction",
            function_name=f"{stack_name}-{config.get('LambdaEdge', 'origin_request_function_name', 'APP_ORIGIN_REQUEST_FUNCTION_NAME')}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            code=lambda_.Code.from_asset(temp_dir),
            role=edge_role,
            memory_size=config.get_int("Lambda", "memory_size", "APP_LAMBDA_MEMORY_SIZE"),
            timeout=Duration.seconds(config.get_int("Lambda", "timeout_seconds", "APP_LAMBDA_TIMEOUT_SECONDS")),
        )
        shutil.rmtree(temp_dir)

        # Origin-response function: strips platform-reserved Set-Cookie coming
        # back from untrusted site origins, so a site cannot overwrite the
        # top-domain session cookie (session fixation / forced logout).
        response_dir = tempfile.mkdtemp()
        shutil.copyfile(
            Path(__file__).parent / "lambda" / "origin_response.py",
            os.path.join(response_dir, "index.py"),
        )
        origin_response_function = lambda_.Function(
            self,
            "OriginResponseFunction",
            function_name=f"{stack_name}-origin-response",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            code=lambda_.Code.from_asset(response_dir),
            role=edge_role,
            memory_size=128,
            timeout=Duration.seconds(5),
        )
        shutil.rmtree(response_dir)
        
        # CloudFront Distribution
        certificate = acm.Certificate.from_certificate_arn(
            self,
            "Certificate",
            certificate_arn=config.get("CloudFront", "certificate_arn", "APP_CERTIFICATE_ARN")
        )
        
        # Create new OriginRequestPolicy
        origin_request_policy = cloudfront.OriginRequestPolicy(
            self,
            "OriginRequestPolicy",
            origin_request_policy_name=config.get("CloudFront", "origin_request_policy_name", "APP_ORIGIN_REQUEST_POLICY_NAME"),
            header_behavior=cloudfront.OriginRequestHeaderBehavior.all(),
            cookie_behavior=cloudfront.OriginRequestCookieBehavior.all(),
            query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.all(),
        )
        
        # Caching MUST stay disabled: the origin-request Lambda only runs on
        # cache misses, so any caching would let authenticated responses be
        # served to unauthenticated users and leak content across subdomains
        # under the wildcard domain. CACHING_DISABLED also removes the cache
        # propagation delay for routing-table updates/removals.
        # include_body=True is required so the request body participates in
        # the SigV4 signature computed by the edge function.
        distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(
                    config.get("CloudFront", "default_origin", "APP_DEFAULT_ORIGIN"),
                    protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=origin_request_policy,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                compress=True,
                edge_lambdas=[
                    cloudfront.EdgeLambda(
                        function_version=edge_function.current_version,
                        event_type=cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
                        include_body=True,
                    ),
                    cloudfront.EdgeLambda(
                        function_version=origin_response_function.current_version,
                        event_type=cloudfront.LambdaEdgeEventType.ORIGIN_RESPONSE,
                    ),
                ]
            ),
            domain_names=[config.get("CloudFront", "domain_name", "APP_DOMAIN_NAME")],
            certificate=certificate,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            enable_ipv6=True,
        )

        # stack policy 的声明必须与栈一致（construct ID / L1 类型 / 逻辑 ID 形态），
        # 否则 synth 失败——不让 router_stack_policy.py 在 20 分钟的 Edge 部署之后才发现推不出 ID。
        assert_protected_constructs(self)

        # Outputs
        CfnOutput(self, "DynamoDBTableName", value=mapping_table.table_name)
        CfnOutput(self, "EdgeFunctionArn", value=edge_function.current_version.function_arn)
        CfnOutput(self, "EdgeRoleArn", value=edge_role.role_arn)
        CfnOutput(self, "DistributionDomainName", value=distribution.distribution_domain_name)
        CfnOutput(self, "DistributionId", value=distribution.distribution_id)


# CDK App
app = App()

# Load config for app-level settings
config = ConfigLoader()

WebRouterStack(
    app,
    config.get("CDK", "stack_name", "APP_STACK_NAME"),
    env=Environment(
        account=normalize_account_id(config.get("AWS", "account_id", "APP_ACCOUNT_ID")),
        region=config.get("AWS", "region", "APP_REGION")
    ),
    description=config.get("CDK", "stack_description", "APP_STACK_DESCRIPTION")
)

app.synth()
