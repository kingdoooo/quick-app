"""面板会话：一次性 code 消费 → __Host-sb_console cookie，以及 CSRF 前置。

**本模块不实现 code 的编解码**——单一实现在 auth/session.py，deploy_panel.py
打包时复制过来（同 common.py / permissions.py 模式）。这里只做三件事：
① 验升级码（RS256）后**原子消费 jti**（条件写 session-codes）；
② 构造/校验 __Host-sb_console（TTL 4h；线格式见 console_cookie）；
③ CSRF 校验，且必须**前置于**一切业务副作用（spec §5.4，顺序在 handler.py）。

密钥：会话签名 key 在 KMS（非对称 CMK，spec §11.2 / ADR 0001）；环境变量只有
kid / key_arn / spki_sha256，公钥运行时取、指纹核对后才用（session_kms.public_key_loader）。
签发经 `session_kms.KmsSigner`——私钥永不离开 KMS，所以"账号内任何只读身份读到密钥即可
伪造任意用户会话"这条路不存在了（docs/security/account-trust-boundary.md 是那条路的原文）。
**panel 只碰 console family**（spec §4.3）：拿到 site 的 key 等于 panel 被攻破时能伪造站点会话。
"""
import os
import time
from datetime import datetime, timezone

import boto3

import session
import session_kms
import verifier_env

CONSOLE_COOKIE = "__Host-sb_console"
CONSOLE_TTL_SECONDS = 4 * 3600
# 消费标记留存时长：code 本身 60 秒过期，但标记要留得久一点才能挡住
# "过期后重放"的探测，也便于排查。TTL 到点由 DynamoDB 自动清。
CONSUMED_TTL_SECONDS = 3600
WRITE_METHODS = ("PUT", "POST", "DELETE")

_kms_client = None
_public_key = None        # session_kms.public_key_loader(_kms())（容器复用：每把公钥只取一次）
_SIGNER = None            # console current 的 KmsSigner（容器复用：自检只做一次）


class UpgradeRejected(Exception):
    """code/cookie 不可信。handler 转 401 + {"need": "console-session"}。"""


class CsrfRejected(Exception):
    """前置校验未过。handler 转 403，且**此时尚未发生任何副作用**。"""


def _kms():
    global _kms_client
    if _kms_client is None:
        _kms_client = boto3.client("kms", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    return _kms_client


def _reset_signing() -> None:
    """测试钩子：换掉 _kms() 后清掉缓存的公钥加载器与 signer。"""
    global _public_key, _SIGNER
    _public_key = None
    _SIGNER = None


def _get_public_key(key_arn: str, spki_sha256: str):
    global _public_key
    if _public_key is None:
        _public_key = session_kms.public_key_loader(_kms())
    return _public_key(key_arn, spki_sha256)


def _console_allowlist() -> dict:
    """panel 自己那份 allowlist：**只有 console family**（spec §4.3）。公钥按 key_arn 取、与 spki_sha256 核对。

    装配逻辑在 verifier_env（auth 拥有、构建时复制进包），SESSION_KEYS_JSON 里出现别的 family
    就直接拒——panel 是公网可达组件，拿到 site 的 key 等于能伪造站点会话。
    """
    return verifier_env.load_allowlist(os.environ.get("SESSION_KEYS_JSON"), "console", _get_public_key,
                                       allowed_families=("console",))


def _signer() -> tuple:
    """→ (kid, sign)：console family 的 current。**panel 只签面板会话，只碰 console family。**

    与 auth 同形（`auth/tests/test_signer_guard.py` 的 AST 守卫按路径读本文件，锁死"每次
    mint_token 的 kid/sign 都是本函数同一次调用绑定出来的"）。这是一条有意的跨包耦合——
    守卫要同时看住两个组件的签发点才有意义——但方向容易反着猜，所以写在这里：
    **改本函数或 `console_cookie` 会让 auth 的套件变红，不是 panel 的。**

    KmsSigner 按 key_arn 缓存：首次调用做一次 GetPublicKey 指纹自检（spec §11.6 第 2 层）。
    """
    global _SIGNER
    kid, key_arn, spki = verifier_env.signing_ref(os.environ.get("SESSION_KEYS_JSON"), "console",
                                                  allowed_families=("console",))
    if _SIGNER is None or _SIGNER.key_arn != key_arn:
        _SIGNER = session_kms.KmsSigner(_kms(), key_arn, spki)
    return kid, _SIGNER


def _log_verify(outcome: str) -> None:
    verifier_env.log_verify("panel", outcome)


def _codes_table():
    return boto3.resource("dynamodb", region_name=os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1")).Table(
            os.environ["SESSION_CODES_TABLE"])


def consume_code(code: str, *, expected_email: str) -> str:
    """验 code 并**原子消费** jti → email。任何不可信情形抛 UpgradeRejected。

    条件写而不是"先查再写"：并发重放下后者两边都会看到"没用过"，两个请求
    都能换到面板会话。

    **三步顺序不可调换**（每一步都在挡一类攻击）：
      ① 验签 —— 否则伪造的 code 也能往表里写一行（垃圾数据 + 探测 jti 空间）；
      ② 比对 expected_email —— **必须在消费之前**（Codex 审查 2026-08-10
         P2-3）。原来是"先消费再由 handler 比对"，于是拿别人的 code 提交一次
         （得到 401）就把它作废了，合法持有者随后只会看到"升级码已被使用"。
         实测复现过。这一步放在条件写之前，错身份就不会留下任何痕迹；
      ③ 原子消费 jti。

    `expected_email` 是**必填关键字参数**：给默认值等于允许调用方忘记传，
    而"忘记传"恰好退化成原来那个缺陷。
    """
    import botocore.exceptions
    claims, outcome = session.verify_token(code or "", allowlist=_console_allowlist(),
                                           token_use="console-upgrade")
    _log_verify(outcome)
    if not claims:
        raise UpgradeRejected("升级码无效或已过期")
    # **空值不得视为相等**（同 verify_console_cookie 的理由）：两边都空时
    # `==` 成立，等于放行一个无身份的请求。
    if not expected_email or claims.get("email") != expected_email:
        raise UpgradeRejected("升级码与当前身份不符")
    try:
        _codes_table().put_item(
            Item={"jti": claims["jti"], "email": claims["email"],
                  "consumed_at": datetime.now(timezone.utc).isoformat(),
                  "expires_at": int(time.time()) + CONSUMED_TTL_SECONDS},
            ConditionExpression="attribute_not_exists(jti)")
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise UpgradeRejected("升级码已被使用") from e
        raise
    return claims["email"]


def ensure_signing_material() -> None:
    """签发前把材料取一遍（3i）：解析 SESSION_KEYS_JSON、构造 signer、做一次 GetPublicKey 自检。**不签发**。

    `handler` 的 `/api/session-callback` 必须在 `consume_code()` **之前**调它：那一步是
    DynamoDB 条件写，**不可逆**地作废那枚一次性升级码。原先取材料发生在 `console_cookie()`
    里、也就是消费之后 ⇒ `SESSION_KEYS_JSON` 缺失/非 JSON/family 缺 current、`kms:GetPublicKey`
    AccessDenied、公钥指纹与配置不符任一发生，用户就丢掉一枚码并拿到 500，必须重走
    auth→console 的升级跳转。与 ticket 20 给 `/callback` 做的是同一件事，只是轻一档
    （那边重来一次要整个 Cognito 往返）。

    **它不签发**，只把材料解析与自检跑通——`console_cookie` 仍是 panel 唯一的签发点
    （signer 的 AST 守卫要求 `handler.py` 里一次 mint 都不能有）。自检结果在 KmsSigner 里
    记住了，所以 `console_cookie` 随后那次不再多打一次 GetPublicKey。
    """
    _signer()[1].self_check()


def console_cookie(email: str, name: str) -> str:
    """__Host-sb_console 的 Set-Cookie 值。

    __Host- 前缀是浏览器强制的：必须 Secure、必须 Path=/、**必须无 Domain**。
    不要给本函数加 domain 参数——任何 Domain= 都会让浏览器整条丢弃 cookie，
    表现为"登录成功但面板一直 401"（auth 的 PKCE cookie 有同样的注释）。

    线格式（spec §11.4 的面板会话表）：console family 的 current kid + RS256 签名，
    claim 恰好是 token_use / aud / email / name / exp / iat——**没有 typ，也没有 scope**。
    """
    kid, sign = _signer()
    token = session.mint_token(kid=kid, sign=sign, token_use="console-session",
                               email=email, ttl_seconds=CONSOLE_TTL_SECONDS, name=name)
    return (f"{CONSOLE_COOKIE}={token}; Secure; HttpOnly; "
            f"SameSite=Lax; Path=/; Max-Age={CONSOLE_TTL_SECONDS}")


def verify_console_cookie(cookie_header: str, *, x_user_email: str) -> str:
    """→ email。验签 + 未过期 + token_use/aud 是面板会话 + **与 Edge 身份一致**。

    最后一条不能省：换人登录后浏览器里可能还留着前一个人的
    __Host-sb_console（4h TTL），而 x-user-email 是 Edge 刚验过的真身份。
    不一致就必须重新升级，否则 B 拿着 A 的面板会话操作 A 的站点。
    """
    token = ""
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == CONSOLE_COOKIE:
            token = v
            break
    if not token:
        raise UpgradeRejected("缺少面板会话")
    # token_use=console-session + aud=console-panel 由 verify_token 一起判，这里不再手查 scope
    claims, outcome = session.verify_token(token, allowlist=_console_allowlist(),
                                           token_use="console-session")
    _log_verify(outcome)
    if not claims:
        raise UpgradeRejected("面板会话无效或已过期")
    # **空值不得视为相等**：两边都空时 `==` 成立，等于放行一个无身份请求
    if not x_user_email or claims.get("email") != x_user_email:
        raise UpgradeRejected("面板会话与当前登录身份不一致")
    return claims["email"]


def check_csrf(method: str, headers: dict) -> None:
    """spec §5.4 的方法白名单 / Origin / Content-Type 三项。

    **缺 Origin 直接拒绝，不回退 Referer**：Referer 会被代理与隐私设置改写，
    拿它当同源证据就是一条绕过路径。

    Origin 用**逐字符相等**而不是 startswith/endswith：
    `https://console.example.com.evil.com` 与 `https://evil.console.example.com`
    都能骗过前缀/后缀匹配。
    """
    if (method or "").upper() not in WRITE_METHODS:
        raise CsrfRejected(f"方法 {method!r} 不允许用于写操作")
    expected = f"https://{os.environ['CONSOLE_HOST']}"
    origin = (headers or {}).get("origin", "")
    if not origin:
        raise CsrfRejected("缺少 Origin 头")
    if origin != expected:
        raise CsrfRejected("Origin 不匹配")
    ctype = (headers or {}).get("content-type", "")
    # 浏览器常发 application/json;charset=UTF-8——按前缀判断 media type
    if not ctype.split(";")[0].strip().lower() == "application/json":
        raise CsrfRejected("Content-Type 必须是 application/json")
