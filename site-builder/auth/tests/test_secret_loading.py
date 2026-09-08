"""密钥不得以明文躺在 Lambda 环境变量里。

部署时实测（2026-08-05）：`aws lambda get-function-configuration` 直接回显
CLIENT_SECRET 与 JWT_SECRET 的明文——任何持 lambda:GetFunctionConfiguration
的主体（一个很常见的只读权限）都能读到。

JWT_SECRET 的后果比 client secret 更重：Edge 只验 HS256 签名，拿到它即可
伪造任意用户的会话 cookie，等于绕过平台全部鉴权（owner/allowed_users/
collaborators 全部失效）。而两个值本来就以 SSM SecureString 为真源
（deploy_auth.ensure_secret 写入），复制进环境变量纯属多余的暴露面。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

import login_handler as lh


def test_secrets_are_read_from_ssm_not_env(monkeypatch):
    """_secret() 必须走 SSM，且环境变量里没有明文时也能工作。"""
    calls = []

    def fake_get_parameter(Name, WithDecryption=False):
        calls.append((Name, WithDecryption))
        return {"Parameter": {"Value": f"value-of-{Name.rsplit('/', 1)[-1]}"}}

    class _SSM:
        get_parameter = staticmethod(fake_get_parameter)

    lh._secret_cache.clear()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.setenv("JWT_SECRET_PARAM", "/site-builder/jwt-secret")
    monkeypatch.setenv("CLIENT_SECRET_PARAM", "/site-builder/site-client-secret")

    assert lh._secret("JWT_SECRET") == "value-of-jwt-secret"
    assert lh._secret("CLIENT_SECRET") == "value-of-site-client-secret"
    assert all(w is True for _, w in calls), "SecureString 必须 WithDecryption"


def test_secret_is_cached_across_calls(monkeypatch):
    """Lambda 容器内只读一次：每次调用都打 SSM 会加延迟并撞节流。"""
    n = []

    class _SSM:
        @staticmethod
        def get_parameter(Name, WithDecryption=False):
            n.append(Name)
            return {"Parameter": {"Value": "v"}}

    lh._secret_cache.clear()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("JWT_SECRET_PARAM", "/p/jwt")

    for _ in range(5):
        assert lh._secret("JWT_SECRET") == "v"
    assert len(n) == 1, f"应只读一次 SSM，实际 {len(n)} 次"


def test_cache_expires_after_ttl(monkeypatch):
    """缓存必须有 TTL，否则密钥轮转后 warm 容器永久用旧值。

    Codex 审查 2026-08-06 P2。失败场景：轮转 Cognito client secret + SSM 参数
    但不改 Lambda 配置 → 已有 warm environment 永久用旧 CLIENT_SECRET、新
    environment 用新值 → 登录请求随机落到两类容器，一部分成功一部分
    invalid_client，而且**没有任何配置变更能触发刷新**。
    AWS 说明 Lambda 执行环境可复用数小时，官方 Parameter Store 缓存方案都提供
    可配置 TTL 正是为此。
    """
    n = []

    class _SSM:
        @staticmethod
        def get_parameter(Name, WithDecryption=False):
            n.append(Name)
            return {"Parameter": {"Value": f"v{len(n)}"}}

    fake_now = [1000.0]
    lh._secret_cache.clear()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    monkeypatch.setattr(lh.time, "monotonic", lambda: fake_now[0])
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.setenv("CLIENT_SECRET_PARAM", "/p/cs")

    assert lh._secret("CLIENT_SECRET") == "v1"
    fake_now[0] += lh.SECRET_TTL_SECONDS - 1      # TTL 内：仍用缓存
    assert lh._secret("CLIENT_SECRET") == "v1"
    assert len(n) == 1, "TTL 内不该重读 SSM"
    fake_now[0] += 2                               # 越过 TTL：重读
    assert lh._secret("CLIENT_SECRET") == "v2"
    assert len(n) == 2, "TTL 到期后应重读 SSM"


def test_ttl_is_bounded_and_documented():
    """TTL 要在合理区间：太长等于没有，太短等于每次调用都打 SSM（延迟+节流）。"""
    assert 60 <= lh.SECRET_TTL_SECONDS <= 900, lh.SECRET_TTL_SECONDS


def test_session_key_rotation_protocol_is_documented_where_the_secret_is_read():
    """会话密钥的轮转**不能靠就地改值、也不能只靠 TTL**，`_secret` 附近必须写明现在的做法。

    Edge 那份是 CDK 部署时字符串替换注入的（Lambda@Edge 不支持环境变量），改一次要 10-20
    分钟全球复制。auth 侧即使 TTL 到期读到新值，Edge 仍在用旧值验签 → 新签发的会话全部
    验签失败（症状是部分用户登录后立刻被踢回登录页，极难定位到密钥版本不一致）。

    **3c-1B 起这条提醒的内容变了**（本票之前写的是"不在当前实现范围内"）：机制已经存在——
    `kid` + verifier 双接受 + 先 verifier 后 signer，新 key 经 `previous` 槽位随 Edge 复制
    就位后才互换。所以提醒必须指向那套 runbook，而不是继续说"做不到"；写着"做不到"会让下一
    个人真的去就地改值。本条锁的就是这三样一直在：Edge 的复制延迟、`kid`/槽位机制、
    DEPLOY.md 的 runbook 指针。
    """
    src = (Path(__file__).parents[1] / "login_handler.py").read_text()
    seg = src[src.index("def _secret"):src.index("def _get_jwks_client")]
    assert "Edge" in seg and "轮转" in seg, "_secret 附近必须写明会话密钥轮转需与 Edge 协调"
    assert "kid" in seg and "previous" in seg, "必须写明现在靠 kid + previous 槽位轮转"
    assert "DEPLOY.md" in seg, "必须留下指向十步 runbook 的指针"
    assert "不在当前实现范围内" not in seg, "3c-1A/1B 之后这句已经不成立，留着会误导下一个人"


def test_env_plaintext_still_honored_for_local_tests(monkeypatch):
    """环境变量直给值时仍可用——单测与本地调试依赖它，且不打 SSM。

    生产部署不设这两个变量（deploy_auth 只下发 *_PARAM），所以这条兼容
    路径不会让明文回到线上配置里。
    """
    class _SSM:
        @staticmethod
        def get_parameter(**kw):
            raise AssertionError("有环境变量时不该打 SSM")

    lh._secret_cache.clear()
    monkeypatch.setattr(lh, "_ssm", lambda: _SSM())
    monkeypatch.setenv("JWT_SECRET", "local-dev-secret")
    assert lh._secret("JWT_SECRET") == "local-dev-secret"


def test_missing_both_sources_fails_loudly(monkeypatch):
    """两个来源都没有时必须抛错，不能静默用空串签 JWT。

    空密钥签出的 HS256 是**任何人都能伪造**的——静默降级在这里等于关掉鉴权。
    """
    lh._secret_cache.clear()
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("JWT_SECRET_PARAM", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        lh._secret("JWT_SECRET")


def test_lambda_role_grants_ssm_read_on_every_run():
    """角色必须有 ssm:GetParameter + kms:Decrypt，且**已存在时也要补**。

    原实现对已有角色 early-return，只在创建时附策略——那样线上这个角色
    永远拿不到新权限，运行时读 SSM 会 AccessDenied，症状是所有登录 500。
    这与 deploy_pool 里"幂等重跑不能把线上加固打回默认"是同一类要求：
    幂等脚本必须每次都收敛到目标状态，而不是只在首次生效。
    """
    # 读源码文本而非 import：deploy_auth 依赖 boto3，而 auth 借用的 contract
    # venv 里没有它（见 CLAUDE.md 的测试命令表）——import 会以 ModuleNotFound
    # 失败，看起来像实现的错。
    whole = (Path(__file__).parents[1] / "deploy_auth.py").read_text()
    src = whole[whole.index("def ensure_lambda_role"):whole.index("def json_trust")]
    assert "ssm:GetParameter" in src, "缺 SSM 读权限，运行时读密钥会 AccessDenied"
    assert "kms:Decrypt" in src, "SecureString 解密需要 kms:Decrypt"
    # 3c-final：会话签名不再是 SSM 里的 HMAC 秘密，而是两把 KMS 非对称 CMK。签发要 kms:Sign
    # （带算法与 MessageType 两个条件——少任何一个都等于把这把 key 的其余用法一并交出去），
    # verifier 冷启动装 allowlist 要 kms:GetPublicKey。缺哪条的症状都是"部署 exit 0 而登录全 500"。
    assert "kms:Sign" in src and "kms:GetPublicKey" in src and "RSASSA_PKCS1_V1_5_SHA_256" in src \
        and '"kms:MessageType": "RAW"' in src
    # early-return 会让已有角色永远补不上权限
    body = src[src.index("try:"):]
    assert "return iam.get_role" not in body.split("except")[0], \
        "已存在的角色也必须走补策略的路径，不能直接 return"
    assert "put_role_policy" in src


def test_deploy_auth_does_not_ship_plaintext_secrets():
    """部署脚本的环境变量里不得再出现 secret 明文，只下发参数名。"""
    src = (Path(__file__).parents[1] / "deploy_auth.py").read_text()
    env_block = src[src.index("def lambda_env"):src.index("def main()")]
    assert '"JWT_SECRET":' not in env_block, "JWT_SECRET 明文不得进环境变量"
    assert '"CLIENT_SECRET":' not in env_block, "CLIENT_SECRET 明文不得进环境变量"
    assert "CLIENT_SECRET_PARAM" in src and "JWT_SECRET_PARAM" not in src


# ---- 3c-1A：auth 的 SSM 权限收成精确清单；环境变量多两项（都不是明文）----

def test_deploy_auth_ssm_resources_are_exact_not_prefixed():
    """前缀 `parameter/site-builder/*` 会把 session-keys 下未来的一切一并交出去。"""
    src = (Path(__file__).parents[1] / "deploy_auth.py").read_text()
    assert ":parameter/site-builder/*" not in src, "auth role 仍在用 SSM 前缀通配"
    assert "load_session_keys" in src, "SSM 资源清单必须从 [SessionKeys] 推导，不手抄"


def test_deploy_auth_ships_session_keys_json_and_fixture_switch_without_values():
    """env 里只有 RS 行的清单与夹具签发器开关；HS 时代那三个键必须彻底消失。

    留着任何一个的后果都不是"多个没用的变量"：`LEGACY_ENTRY` / `SESSION_SIGNER` 在 3c-final 的
    handler 里没有读取点，留在配置里会让下一个人以为还能靠改它们回滚（真正的回滚是换 kid）；
    `JWT_SECRET_PARAM` 则指向一个即将被删的 SSM 参数。
    """
    src = (Path(__file__).parents[1] / "deploy_auth.py").read_text()
    env_block = src[src.index("def lambda_env"):src.index("def main()")]
    assert '"SESSION_KEYS_JSON"' in env_block and '"FIXTURE_ISSUER"' in env_block
    for gone in ('"LEGACY_ENTRY"', '"SESSION_SIGNER"', '"JWT_SECRET_PARAM"'):
        assert gone not in env_block, gone
    assert '"secret"' not in env_block and "token_hex" not in env_block, "环境变量里只能有参数名"
