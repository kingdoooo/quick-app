# 3c-1A · verifier 认 kid allowlist（HS256，signer 不动）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让全部五个验签点（Edge、auth `/console-session`、panel 面板会话、panel 升级码、auth legacy）按 spec §5 的合同验 token：`kid → {family, alg, key}` 固定 allowlist、每 family `current` + `previous`、legacy 第三入口（状态机 **L1**）。**signer 一行不改**：本包结束时线上所有 token 仍是今天的形态，verifier 只是**多了**两条入口。

**Architecture:** 不新增组件。新增两个「唯一定义」：`session_keys.py`（`[SessionKeys]` 的加载与校验，auth 拥有、panel 复制、router 栈 synth 时 import）与 `session.verify_token`（allowlist 验签核心，Edge 内嵌字节等价的副本）。既有的 `verify_session_jwt` / `verify_upgrade_code` 退化成 **legacy 入口的实现**，只在 header 没有 `kid` 时被调用。两把新 HS secret（`site-hs-v1` / `console-hs-v1`）在本包**创建并被 verifier 加载**，但**没有任何 signer 用它们签**（那是 3c-1B）。

**Tech Stack:** Python 3.12/3.13、boto3、pytest、moto（panel / deployer 测试）、AWS SSM SecureString、Lambda@Edge、CDK

**Spec:** `docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md`，本包对应 §6.1 的 **3c-1A** 行；合同 §4.3/§4.4/§5，状态机 §6.2「3c-1 的 legacy 状态机」，反例 §9，裁定 §11.4（字面量与 claim 表）、§11.6（`[SessionKeys]` schema），观测 §8。术语按根 `CONTEXT.md`（key family / verifier allowlist / legacy 入口 / token_use）。

**实施授权**：spec 头部写明它不构成 3c-1 的实施授权。**本计划被批准即是 3c-1A 的授权**，范围以本文件为限；3c-1B（signer 切 kid）另立计划。

## Global Constraints

- **每条守卫先写会红的用例**，实际跑红再写实现。§9 的每一条反例都要有对应用例，且要有**正向控制**（一个合法 token 能过），否则负向用例全绿证明不了任何东西。
- **测试命令按包照抄，不要猜 venv**（三个借用关系都验证过）：
  - `(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)`
  - `(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)`
  - `(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)`
  - `(cd site-builder/deployer && .venv/bin/pytest tests -q)`（**必须带 `tests/`**）
  - 改了 `deployer/infra/app.py` 或 `router/infrastructure/stack.py` 的 pip/bundling 段要跑 auth 那套（AST 守卫在 `auth/tests/test_requirements_locked.py`）。本包不碰 pip 段。
- **最终闸门不要并行跑七套**：`contract/tests/test_redlines.py` 有墙钟哨兵，争用下假红（CLAUDE.md）。
- **signer 不动是本包的定义，不是建议。** `login_handler.py` 与 `console_session.py` 里 mint 的调用点保持调用 `mint_session_jwt` / `mint_upgrade_code`，签出来的 header 仍是 `{"alg":"HS256","typ":"JWT"}`（无 `kid`）。Task 2 有一条 AST 守卫锁死"1A 里没有 handler 调用 `mint_token`"，3c-1B 再放开。
- **L1 的接受路径是「2 + 1」**：每 family 只有 `current`（`previous` 为空）加一条 legacy 入口。**有 `kid` 但不在 allowlist ⇒ 直接拒，不回落 legacy**（状态机第 5 条）。legacy 入口的进入条件是 header **根本没有 `kid` 键**。
- **legacy 入口按旧合同验，且只在 legacy 入口里这么验**：site = `typ=session` 且**无 `scope`**；console-session = `typ=session` + `scope=console`；upgrade = `typ=console-upgrade` + `jti`。新入口**只**认 `token_use` + `aud`，不接受 `typ`/`scope`。
- **`session.py` 与 `origin_request.py` 的验签实现必须字节等价**（CLAUDE.md 不变量）。改一处必须同步另一处；跨组件正向向量（`test_edge_auth.py::test_a_real_auth_token_verifies_at_the_edge`）**按新模型重写，不许删**。
- **`kid` 是攻击者控制的输入**：不得用它拼 SSM path / 文件名 / ARN；`alg` 只用来与 allowlist 里的绑定值**比对**，不用来分派实现（spec §4.4）。
- **`[SessionKeys]` 按 spec §11.6 的 schema 落地**，本包只有 HS 行，`previous` 留空；RS 行的键名（`key_arn` / `spki_sha256`）**现在就进 schema 校验器**（值缺省允许），避免 3c-2B 再改 schema。
- **两把新 SSM secret 在本包创建**（`/site-builder/session-keys/site-hs-v1`、`/site-builder/session-keys/console-hs-v1`），由 `scripts/ensure_session_keys.py` 幂等创建（`deploy_auth.py` 的 `ensure_secret` 同一套实现）。**它们必须先于闸门与任何 verifier 部署存在**（Task 7 的顺序）。
- **闸门先行**（spec §6.1 进入条件）：`verify_account_trust_boundary.py` 认识两个 HS key family 与 legacy/current/previous 之后，才允许部署第一个 verifier。基线 schema 3 → 4 做**精确迁移**，不是重置（spec §6.2 3c-3 一节的理由同样适用于这里）。
- **部署顺序**：ensure_session_keys → 闸门（新代码，出 schema 4 基线）→ auth → panel → router（Edge）→ **等 CloudFront `Status == Deployed`** → `verify_deployed_edge.sh` → 真机验收 → 闸门复跑（精确 delta）。等待在 router **之后**（S1 计划的教训：真正触发 Lambda@Edge 传播的是 router 部署本身）。
- **回滚**：本包 signer 不变 ⇒ 任何 verifier 单独回滚到上一版都安全（旧代码只认 legacy，而线上 token 全是 legacy）。回滚顺序不重要，这是 verifier-first 的全部意义；**但 SSM 里新建的两把 secret 不删**（删了再建会换值，1B 之前没有消费者，留着无害）。
- **观测不记 token**（spec §8）：只记固定低基数词表 `accepted_current / accepted_previous / accepted_legacy / unknown_kid / alg_mismatch / wrong_audience / wrong_token_use / bad_signature / expired`。埋点异常一律吞掉。
- **不把真实账号 ID / 域名 / site_id / 邮箱写进任何被跟踪的文件。** 测试固定用十二个 1 的假账号、`example.test`、`test-secret` 这类占位值。
- `router/infrastructure/lambda/_*_testable.py` 是测试期现生成的副本（gitignored），**不要手工编辑**。
- **secret scan 三条硬要求**（同 S1 计划）：新文件 `git add` 之前 `bash site-builder/scripts/scan_staged_secrets.sh --files <新文件…> || exit 1`；`git add` 之后 `bash site-builder/scripts/scan_staged_secrets.sh || exit 1`；两处都带 `|| exit 1`。命中不自动清洗。
- **命令块里不写绝对主机路径**；回仓库根用 `cd "$(git rev-parse --show-toplevel)"`；多条 `cd` 各自套子 shell；**所有多命令 bash 块以 `set -euo pipefail` 开头**。
- **证据分级**：每个 Task 的验收写明是 static / fake-unit / integration / sandbox / production 哪一级，不许把单测写成"真机验过"。进度与证据链写到 `.superpowers/sdd/2026-09-02-3c-1a-verifier-kid-allowlist/progress.md`（gitignored）。

---

### Task 0：`[SessionKeys]` 的唯一定义 `session_keys.py`

**目标**：一个加载器、一个校验器，被 auth / panel / router 栈 / 闸门 / 脚本共用。**它不读 SSM**，只把 config 变成结构；取 secret 是调用方的事。

**Files:**
- 新建 `site-builder/auth/session_keys.py`
- 新建 `site-builder/auth/tests/test_session_keys.py`
- 修改 `site-builder/config.ini.example`（新增 `[SessionKeys]` + 两个 `[SessionKey:<kid>]` 小节）
- 修改 `site-builder/panel/deploy_panel.py`（`COPY_FILES` 加 `session_keys.py`；`test_copy_files_covers_every_local_module_panel_imports` 会先红）

**Step 1：先写红的用例** `auth/tests/test_session_keys.py`

覆盖：合法最小配置（两 family 各一 `current`、无 `previous`）；`kid` 格式必须匹配 `^(site|console)-(hs|rs)-v\d+$` 且 family 前缀与所属 family 一致（`console-hs-v1` 出现在 `site_current` 必拒）；`alg` 只允许 `HS256` / `RS256`；HS 行必须有 `ssm_param`（以 `/site-builder/session-keys/` 开头）、不得有 `key_arn`；RS 行必须有 `key_arn`（带 `:key/` 的完整 ARN，**拒 alias**）与 64 位十六进制 `spki_sha256`；同一 `kid` 不得同时出现在两个 family；`current` 与 `previous` 不得相同；`legacy_param` 必填（本包就是 `/site-builder/jwt-secret`）；缺段或缺键 ⇒ 抛 `SessionKeysError`（响亮），**不给默认值**（CLAUDE.md：configparser 对缺失是静默的，"读不到就硬失败"是本仓库的既定做法）。

**Step 2：实现**（候选实现，落盘前按 Step 1 的用例跑绿）

```python
"""[SessionKeys] 的唯一定义：加载 + 校验，不读 SSM。auth 拥有；panel 复制；router 栈 synth 时 import。"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass
from pathlib import Path

KID_RE = re.compile(r"^(site|console)-(hs|rs)-v(\d+)$")
HS_PARAM_PREFIX = "/site-builder/session-keys/"
ALGS = {"hs": "HS256", "rs": "RS256"}
FAMILIES = ("site", "console")


class SessionKeysError(ValueError):
    """配置缺失或自相矛盾。调用方不得捕获后回落默认值。"""


@dataclass(frozen=True)
class KeyRef:
    kid: str
    family: str
    alg: str
    role: str                     # "current" | "previous"
    ssm_param: str | None = None  # HS
    key_arn: str | None = None    # RS（3c-2B 起）
    spki_sha256: str | None = None


@dataclass(frozen=True)
class SessionKeys:
    families: dict            # family -> {"current": KeyRef, "previous": KeyRef | None}
    legacy_param: str

    def allowlist(self, family: str) -> tuple[KeyRef, ...]:
        fam = self.families[family]
        return tuple(k for k in (fam["current"], fam["previous"]) if k is not None)


def _strip(v: str) -> str:
    return v.split("#")[0].strip()


def _key_ref(cfg: configparser.ConfigParser, kid: str, family: str, role: str) -> KeyRef:
    m = KID_RE.match(kid)
    if not m or m.group(1) != family:
        raise SessionKeysError(f"{family}_{role}={kid!r} 不是本 family 的合法 kid")
    sect = f"SessionKey:{kid}"
    if not cfg.has_section(sect):
        raise SessionKeysError(f"缺 [{sect}] 小节")
    alg = _strip(cfg.get(sect, "alg", fallback=""))
    if alg != ALGS[m.group(2)]:
        raise SessionKeysError(f"[{sect}] alg={alg!r} 与 kid 里的算法段不一致")
    ssm_param = _strip(cfg.get(sect, "ssm_param", fallback=""))
    key_arn = _strip(cfg.get(sect, "key_arn", fallback=""))
    spki = _strip(cfg.get(sect, "spki_sha256", fallback=""))
    if alg == "HS256":
        if not ssm_param.startswith(HS_PARAM_PREFIX) or key_arn or spki:
            raise SessionKeysError(f"[{sect}] HS 行必须只有 ssm_param（{HS_PARAM_PREFIX}…）")
        return KeyRef(kid, family, alg, role, ssm_param=ssm_param)
    if ":key/" not in key_arn or not re.fullmatch(r"[0-9a-f]{64}", spki) or ssm_param:
        raise SessionKeysError(f"[{sect}] RS 行必须有带 :key/ 的 key_arn 与 64 位 hex spki_sha256")
    return KeyRef(kid, family, alg, role, key_arn=key_arn, spki_sha256=spki)


def load_session_keys(config_path: Path) -> SessionKeys:
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(config_path) or not cfg.has_section("SessionKeys"):
        raise SessionKeysError(f"{config_path} 缺 [SessionKeys] 段")
    families: dict = {}
    seen: set[str] = set()
    for fam in FAMILIES:
        cur = _strip(cfg.get("SessionKeys", f"{fam}_current", fallback=""))
        prev = _strip(cfg.get("SessionKeys", f"{fam}_previous", fallback=""))
        if not cur:
            raise SessionKeysError(f"[SessionKeys] 缺 {fam}_current")
        if prev == cur:
            raise SessionKeysError(f"[SessionKeys] {fam}_previous 与 current 相同")
        refs = {"current": _key_ref(cfg, cur, fam, "current"),
                "previous": _key_ref(cfg, prev, fam, "previous") if prev else None}
        for r in refs.values():
            if r is not None:
                if r.kid in seen:
                    raise SessionKeysError(f"kid {r.kid} 出现在两个 family")
                seen.add(r.kid)
        families[fam] = refs
    legacy = _strip(cfg.get("SessionKeys", "legacy_param", fallback=""))
    if not legacy:
        raise SessionKeysError("[SessionKeys] 缺 legacy_param（3c-3 之前必填）")
    return SessionKeys(families=families, legacy_param=legacy)
```

**Step 3：`config.ini.example` 新增段**（占位值；注释写清 RS 行是 3c-2B 起才填）

```ini
[SessionKeys]
# 3c-1A：每 family 一把 current（HS256），previous 留空；legacy_param 是拆 family 之前的共享密钥，
# 3c-3 删 legacy 入口时一并删。RS 行（key_arn / spki_sha256）3c-2B 起才出现。
site_current = site-hs-v1
site_previous =
console_current = console-hs-v1
console_previous =
legacy_param = /site-builder/jwt-secret

[SessionKey:site-hs-v1]
alg = HS256
ssm_param = /site-builder/session-keys/site-hs-v1

[SessionKey:console-hs-v1]
alg = HS256
ssm_param = /site-builder/session-keys/console-hs-v1
```

**Step 4：验收**（fake-unit）：auth 套件全绿；panel 的 `test_copy_files_covers_every_local_module_panel_imports` 从红到绿。

---

### Task 1：`ensure_session_keys.py` 建两把 HS secret（幂等）

**Files:**
- 新建 `site-builder/scripts/ensure_session_keys.py`
- 新建 `site-builder/deployer/tests/test_ensure_session_keys.py`（moto SSM）

**Step 1：先写红的用例**：不存在则以 `secrets.token_hex(32)` 创建 SecureString；存在则**不覆盖、不打印值**；两把值必须不同；只按 `load_session_keys` 里 HS 行的 `ssm_param` 建，**不接受命令行传路径**（路径来自 config，不来自参数，否则等于让人随手建第三把）；`legacy_param` 不在它的职责内（那把已经存在，属于 `deploy_auth.py`）。

**Step 2：实现**：复用 `deploy_auth.py` 的 `ensure_secret`（把它提到 `auth/secrets_util.py` 或直接 import `deploy_auth.ensure_secret`；选前者，`deploy_auth.py` 顶层有副作用性的 config 读取）。脚本用 `python3` 跑（≥3.10，boto3 + pip-system-certs，CLAUDE.md）。

**Step 3：验收**（fake-unit）：deployer 套件绿。**真机执行放到 Task 7 第 ① 步。**

---

### Task 2：`session.py` 的 allowlist 验签核心 + 新 mint（handler 不接）

**Files:**
- 修改 `site-builder/auth/session.py`（新增 `mint_token` / `verify_token` / `verify_with_legacy`；既有四个函数不改签名）
- 新建 `site-builder/auth/tests/test_verifier_allowlist.py`
- 修改 `site-builder/auth/tests/test_upgrade_code.py`、`test_session.py`（补 legacy 入口的边界）
- 修改 `site-builder/panel/tests/upgrade_code_vectors.py`（向量表加带 `kid` 的一组，两侧共跑）
- 新建 `site-builder/auth/tests/test_signer_untouched_in_1a.py`（AST 守卫）

**Step 1：先写红的用例** `test_verifier_allowlist.py`。按 spec §9 逐条，**每条一个用例名**：

| 反例 | 期望 outcome |
|---|---|
| 未知 `kid` | `unknown_kid`，**且 legacy 开着也不回落** |
| 缺 `kid`、legacy 关 | `unknown_kid` |
| header JSON 里**重复** `kid` 键 | `bad_signature`（解析期拒） |
| `kid` 对、`alg` 错（`HS512` / `RS256` / `none` / `None` / `NONE`） | `alg_mismatch` |
| site 的 `kid` 投给 console allowlist | `unknown_kid` |
| console 的 `kid` 投给 site allowlist（= Edge） | `unknown_kid` |
| allowlist 之外的第三把 key 签的（kid 冒用 current） | `bad_signature` |
| legacy 入口关闭后递 legacy token | `unknown_kid` |
| `token_use` 不匹配（升级码当面板会话、面板会话当站点会话，M05 完整矩阵） | `wrong_token_use` |
| `aud` 不匹配；`aud` 是数组 `["site-edge"]` | `wrong_audience` |
| 过期 | `expired` |
| `email` 缺或空 | `bad_signature`（身份字段合同） |
| **正向控制**：合法 current token | `accepted_current`，claims 完整 |
| **正向控制**：合法 previous token | `accepted_previous` |
| **正向控制**：legacy token、legacy 开 | `accepted_legacy` |

外加 `mint_token` 的合同：三类 token 的 claim 集合**等于** §11.4 的表（升级码含 `jti`，其余不含）；`name` 截到 256；signing input > 4096 字节 ⇒ 抛 `ValueError`（**不签**）；header 恰好是 `{"alg":"HS256","typ":"JWT","kid":...}`。

**Step 2：实现**（候选实现；解析顺序按 spec §5：先验签，再信 payload）

```python
# 追加到 site-builder/auth/session.py（既有函数不动）
TOKEN_USES = {"site-session": "site-edge",
              "console-upgrade": "console-exchange",
              "console-session": "console-panel"}
OUTCOMES = ("accepted_current", "accepted_previous", "accepted_legacy",
            "unknown_kid", "alg_mismatch", "wrong_audience",
            "wrong_token_use", "bad_signature", "expired")
NAME_MAX = 256
SIGNING_INPUT_MAX = 4096


def _strict_json(raw: bytes) -> dict:
    """拒绝重复键：Python 默认取最后一个，攻击者可放两个 kid 让不同实现看到不同值。"""
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d
    obj = json.loads(raw, object_pairs_hook=no_dupes)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def mint_token(*, kid: str, secret: str, token_use: str, email: str,
               ttl_seconds: int, name: str = "", idp: str = "",
               auth_via: str = "", now: int | None = None) -> str:
    """3c-1B 起由 handler 调用；1A 只在测试与跨组件向量里用。claim 集合按 spec §11.4。"""
    aud = TOKEN_USES[token_use]
    t = int(time.time()) if now is None else now
    claims = {"token_use": token_use, "aud": aud, "email": email,
              "exp": t + int(ttl_seconds), "iat": t}
    if token_use == "site-session":
        claims.update(name=name[:NAME_MAX], idp=idp, auth_via=auth_via)
    elif token_use == "console-upgrade":
        claims["jti"] = _b64url(secrets.token_bytes(16))
        claims["exp"] = t + min(int(ttl_seconds), UPGRADE_MAX_TTL)
    else:
        claims["name"] = name[:NAME_MAX]
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid},
                                separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    if len(signing_input) > SIGNING_INPUT_MAX:
        raise ValueError("signing input 超过 4096 字节，拒签")   # §11.5 的长度闸
    return f"{header}.{payload}.{_sign(signing_input, secret)}"


def verify_token(token: str, *, allowlist: dict, token_use: str,
                 now: int | None = None) -> tuple[dict | None, str]:
    """allowlist: kid -> {"alg": "HS256", "secret": str, "role": "current"|"previous"}。
    返回 (claims 或 None, outcome)。顺序：kid ∈ allowlist → alg 精确一致 → 验签 →
    token_use → aud → exp → email。**先验签再信 payload。**"""
    try:
        header_b64, payload_b64, sig = token.split(".")
        header = _strict_json(_b64url_decode(header_b64))
    except Exception:
        return None, "bad_signature"
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in allowlist:
        return None, "unknown_kid"
    entry = allowlist[kid]
    if header.get("alg") != entry["alg"]:
        return None, "alg_mismatch"
    try:
        expected = _sign(f"{header_b64}.{payload_b64}".encode(), entry["secret"])
        if not hmac.compare_digest(sig, expected):
            return None, "bad_signature"
        claims = _strict_json(_b64url_decode(payload_b64))
    except Exception:
        return None, "bad_signature"
    if claims.get("token_use") != token_use:
        return None, "wrong_token_use"
    if claims.get("aud") != TOKEN_USES[token_use]:          # 字符串精确相等，数组必拒
        return None, "wrong_audience"
    t = int(time.time()) if now is None else now
    try:
        if int(claims.get("exp", 0)) <= t:
            return None, "expired"
    except Exception:
        return None, "bad_signature"
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        return None, "bad_signature"
    if token_use == "console-upgrade" and not claims.get("jti"):
        return None, "bad_signature"
    return claims, f"accepted_{entry['role']}"


def verify_with_legacy(token: str, *, allowlist: dict, token_use: str,
                       legacy_secret: str | None, now: int | None = None
                       ) -> tuple[dict | None, str]:
    """L1/L2 的「2 + 1」入口。legacy 的进入条件是 header **没有 kid 键**；
    有 kid 但不在 allowlist ⇒ unknown_kid，**不回落**。legacy_secret=None 表示 L3（入口已删）。"""
    try:
        header = _strict_json(_b64url_decode(token.split(".")[0]))
    except Exception:
        return None, "bad_signature"
    if "kid" in header or legacy_secret is None:
        return verify_token(token, allowlist=allowlist, token_use=token_use, now=now)
    if token_use == "console-upgrade":
        claims = verify_upgrade_code(token, legacy_secret, now)
    else:
        claims = verify_session_jwt(token, legacy_secret, now, expected_typ=SESSION_TYP)
        if claims is not None:
            scope = claims.get("scope")
            if (token_use == "console-session") != (scope == "console"):
                claims = None                 # 旧合同：site 无 scope；console-session 有
    return (claims, "accepted_legacy") if claims else (None, "bad_signature")
```

**Step 3：AST 守卫** `test_signer_untouched_in_1a.py`：解析 `login_handler.py` 与 `panel/console_session.py`，断言没有任何 `mint_token(` 调用；并断言 `mint_session_jwt` 的 header 仍无 `kid`（跑一次 mint 解 header）。**3c-1B 的第一步就是删掉这条守卫**，它的 docstring 要写明这一点。

**Step 4：变形（meta）测试**：`test_verifier_allowlist.py` 里加一条 `test_mutation_aud_list_would_pass_if_compare_were_membership`：用 `monkeypatch` 把 `TOKEN_USES[token_use]` 比对换成 `in` 语义的桩，断言 `aud=["site-edge"]` 那条用例**会转绿**，证明那条反例真在盯这一行。同理一条：把 `verify_with_legacy` 的 `"kid" in header` 改成 `header.get("kid") in allowlist` 时，"未知 kid 不回落"必须转红。

**Step 5：验收**（fake-unit）：auth 与 panel 套件绿；`upgrade_code_vectors.py` 新增的带 `kid` 向量在两侧都跑。

---

### Task 3：Edge 内嵌 verifier 认 site family 的 allowlist + legacy 入口开关

**Files:**
- 修改 `router/infrastructure/lambda/origin_request.py`（`_verify_session_jwt` 重写为 `verify_with_legacy` 的字节等价副本，只覆盖 site family）
- 修改 `router/infrastructure/stack.py`（读 `site-builder/config.ini` 的 `[SessionKeys]`，取 site family 各 kid 的 SSM 值，注入 `{{SITE_ALLOWLIST_JSON}}` 与 `{{LEGACY_ENTRY}}`；`{{JWT_SECRET}}` 保留为 legacy secret）
- 修改 `router/infrastructure/lambda/test_edge_auth.py`（占位符表；新用例；跨组件向量重写）、`test_origin_request.py`、`test_edge_access_log.py`（占位符表）
- 修改 `site-builder/scripts/verify_deployed_edge.sh`（`typ` 那条 grep 换成三条：allowlist 常量存在且 kid 集合 == config；legacy 开关值 == config；`_verify_session_jwt` 里有 `unknown_kid` 分支）

**Step 1：先写红的用例**（`test_edge_auth.py`）
- 占位符表加 `"{{SITE_ALLOWLIST_JSON}}": json.dumps({"site-hs-v1": {"alg": "HS256", "secret": "test-secret-v1", "role": "current"}})` 与 `"{{LEGACY_ENTRY}}": "on"`；另生成一份 `_edge_legacy_off_testable.py`（`"off"`）。
- 新用例：带 `kid=site-hs-v1` 的 `mint_token(token_use="site-session")` 被放行；`kid=console-hs-v1`（即使秘钥对）被 302；未知 kid 不回落 legacy；`aud` 数组被拒；legacy token 在 `on` 放行、在 `off` 302；**legacy 入口下 console 会话（`scope=console`）投给 Edge 被 302**（这是相对今天的收紧，spec §2 指出今天 Edge 不查 scope）。
- 跨组件正向向量改成**两条**：`mint_token(kid="site-hs-v1", ...)` 过新入口；`mint_session_jwt(...)` 过 legacy 入口。两条都从 `auth/session.py` import 真实 mint。
- **一条守卫**：Edge 源码里 `SITE_ALLOWLIST_JSON` 只被 `json.loads` 一次且结果不被 `kid` 以外的输入索引（防"用 kid 拼资源"）。

**Step 2：实现要点**
- `origin_request.py`：新增常量 `SITE_ALLOWLIST_JSON = "{{SITE_ALLOWLIST_JSON}}"`、`LEGACY_ENTRY = "{{LEGACY_ENTRY}}"`，模块顶层 `_SITE_ALLOWLIST = json.loads(SITE_ALLOWLIST_JSON)`；`_verify_session_jwt(token)` 返回 claims 或 None **不变签名**（`_check_auth` 不动），内部照抄 `verify_with_legacy` 的逻辑（site family、`token_use="site-session"`、legacy 走原来的 `typ=="session"` 检查**加**"无 `scope`"），并用 `logger.info(json.dumps({"event": "session_verify", "outcome": ...}))` 记 outcome，**不记 token**。
- `stack.py`：`sys.path` 加 `site-builder/auth`，`load_session_keys(ROOT / "site-builder" / "config.ini")`；对 site family 的每个 `KeyRef` 取 SSM 值组 allowlist；SSM 读失败沿用今天的 synth-only 占位符路径（`SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY`，stderr WARNING）。`{{LEGACY_ENTRY}}` 来自 `[SessionKeys] legacy_param` 是否非空（非空 = `on`；3c-3 清空即 `off`）。
- `verify_deployed_edge.sh`：下载产物后断言 `SITE_ALLOWLIST_JSON` 里的 kid 集合等于 `read_cfg`（改为读 `site-builder/config.ini`）的 site family；断言 `LEGACY_ENTRY = "on"`；**不打印 secret**（grep 时只取 kid）。

**Step 3：验收**（fake-unit）：router 套件绿，含两条跨组件向量。`verify_deployed_edge.sh` 的改动在 Task 7 真机验。

---

### Task 4：auth 与 panel 的验签点切到 `verify_with_legacy`

**Files:**
- 修改 `site-builder/auth/login_handler.py`（`/console-session` 的候选 cookie 逐个验：`verify_with_legacy(..., token_use="site-session")`；`_secret()` 泛化出 `_secret_by_param(param)`；allowlist 由环境变量 `SESSION_KEYS_JSON` 描述（kid/alg/role/ssm_param，**无值**），值按 param 经 `_secret_by_param` 取，TTL 缓存照旧）
- 修改 `site-builder/auth/deploy_auth.py`（`lambda_env()` 加 `SESSION_KEYS_JSON` 与 `LEGACY_ENTRY`；role 的 SSM 资源加两把新 param 的精确 ARN）
- 修改 `site-builder/panel/console_session.py`（`verify_console_cookie` → `token_use="console-session"`；`consume_code` → `token_use="console-upgrade"`；legacy 走原来的两条函数）
- 修改 `site-builder/panel/deploy_panel.py`（env 加 `SESSION_KEYS_JSON`（只含 console family）与 `LEGACY_ENTRY`；`ReadJwtSecretOnly` 语句资源改为**精确 ARN 列表**：legacy + console-hs-v1；`COPY_FILES` 已在 Task 0 加了 `session_keys.py`）
- 修改 `site-builder/panel/tests/test_deploy_panel_contract.py`（`test_panel_role_ssm_resource_is_exact_jwt_secret_arn` 泛化为"每个资源都是配置里 console family 或 legacy 的精确 ARN，无通配，**且不含 site family**"）
- 修改 `site-builder/auth/tests/test_login_handler.py`、`test_secret_loading.py`、`site-builder/panel/tests/test_console_session.py`、`test_handler.py`

**Step 1：先写红的用例**
- auth：`/console-session` 对 `kid=site-hs-v1` 会话换出升级码；对 legacy 会话同样换出；对 `kid=console-hs-v1` 会话 302 去登录；对未知 kid 302；同名遮蔽 cookie 排在前面仍换出（M06 不退化）。
- panel：面板会话 `kid=console-hs-v1` 与 legacy（`scope=console`）都能过；站点会话（无论新旧形态）被拒；升级码 `kid` 形态与 legacy 形态都能被原子消费，`jti` 缺失被拒；`SESSION_KEYS_JSON` 里若出现 site family ⇒ panel 启动即拒（**panel 不得持 site 的 allowlist**，spec §4.3）。
- 合同：panel role 的 SSM 资源集合 == {legacy, console-hs-v1} 的精确 ARN；auth role == {legacy, site-hs-v1, console-hs-v1, site-client-secret}（auth 今天用前缀 `parameter/site-builder/*`，**本包顺手收成精确列表**，`test_secret_loading.py` 加断言）。

**Step 2：实现**：环境变量只下发**参数名**，不下发值（`verify_deployed_components.py` 的"环境变量无明文密钥"检查覆盖；`SESSION_KEYS_JSON` 含分隔符不会被"长不透明串"启发式误判）。`SESSION_KEYS_JSON` 由部署脚本用 `load_session_keys` 推导，格式 `{"site": [{"kid":..., "alg":..., "role":..., "ssm_param":...}], "console": [...]}`，panel 只有 `console` 键。

**Step 3：验收**（fake-unit）：auth、panel 套件绿。

---

### Task 5：观测词表与 `verify_deployed_components.py`

**Files:**
- 修改 `login_handler.py` / `console_session.py`：验签 outcome 经既有的固定词表日志（auth 是 `_log_event`，panel 照它加一个）打 `session_verify`；
- 修改 `site-builder/scripts/verify_deployed_components.py`：⑤⑧ 的"环境变量整体 == 本地推导值"覆盖新增的两个 env；
- 新建 `site-builder/scripts/session_verify_counts.py`：CloudWatch Logs Insights 查 Edge / auth / panel 三个日志组最近 N 小时各 outcome 计数（只读），**这是 L2 → L3 退役判据的读数工具**，本包先把它建好并在 Task 7 用它证明 `accepted_legacy > 0 且总量 > 0`（埋点在工作）。
- 测试：`auth/tests/test_login_handler.py` 断言日志行 outcome ∈ `OUTCOMES`、且行里不含 token 任一段；Edge 同理（`test_edge_auth.py` 用 caplog）。

**验收**（fake-unit + Task 7 的 production 读数）。

---

### Task 6：闸门认识两个 key family（基线 schema 3 → 4，精确迁移）

**这是 spec §6.1 写明的进入条件，Task 7 部署前必须完成并跑过一次。**

**Files:**
- 修改 `site-builder/scripts/verify_account_trust_boundary.py`
- 修改 `site-builder/deployer/tests/test_verify_account_trust_boundary.py`
- 修改 `site-builder/scripts/account_trust_baseline.json`（由脚本迁移写出，**不手编**）
- 修改 `docs/security/account-trust-boundary.md`（数字由基线断言，改口径说明）

**Step 1：先写红的用例**
- `JWT_PARAM_NAME` 单值 → `session_key_params()`：从 `load_session_keys` 得到 `{legacy, site-hs-v1, console-hs-v1}` 三个 param；grant 词表 `read-jwt-secret` 变成 `read-session-key:<kid|legacy>`（每把一条，**不合并**，否则"谁能读 site 的 key"与"谁能读 console 的 key"分不开，而 spec §4.1 的整个论点就是这两者要分开）。
- Edge 产物定位：`_SECRET_ASSIGN_RE` 保留（找 legacy），新增在 zip 内查每把 HS 值（`secret_in_zip_bytes(blob, value)` 逐把）；facts 变成 `edge_code_targets_carrying_key:<kid|legacy>`、`edge_assets_carrying_key:<kid|legacy>`。**Edge 产物里不得出现 console family 的值**（新增一条硬断言：出现即 FAIL，这是 spec §4.1 "Edge 的 allowlist 里不出现 console 公钥/密钥"的闸门形态）。
- 基线 schema 4；`load_baseline(migrate_from=3)` 只接受 3 → 4（CLI 形态沿用现有的 `--update-baseline --migrate-from-schema 3`，今天它只认 2 → 3）：旧 `read-jwt-secret` grant 精确改名为 `read-session-key:legacy`，旧 `edge_*_carrying_live_key` facts 改名为 `…:legacy`，新 kid 的 grant/facts 以**首次观测**进入并在报告里单列"本轮新增（迁移）"；**其它任何差异照样红**。`test_migration_only_accepts_schema_2_to_3` 改成 3 → 4 并保留 2 → 3 拒绝。
- 正对照：`test_known_principal_gaining_secret_read_is_a_failure` 对新 kid 同样成立。

**Step 2：实现**：按用例。`--dump` 模式不要求现有基线 schema 一致（既有用例 `test_dump_mode_does_not_require_an_existing_current_schema_baseline` 保持绿）。

**Step 3：验收**（fake-unit）：deployer 套件绿。真机跑在 Task 7 第 ② 步。

---

### Task 7：全量回归、按序部署、真机验收、闸门 delta

**Step 1：全量单测（串行，不并行）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(cd site-builder/contract && .venv/bin/pytest tests -q)
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```

（MCP 那套本包不碰；`test_redlines.py` 的墙钟哨兵红了先单独重跑一次再判断。）

**Step 2：回填 `site-builder/config.ini` 的 `[SessionKeys]`**（照 `config.ini.example`，值就是那两条固定 param 路径；不进 git）。

**Step 3：按序部署与验收**（每一步都是硬停止点）

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# ① 两把 HS secret 先存在（幂等；只创建，不打印值）
python3 site-builder/scripts/ensure_session_keys.py
# ② 闸门先行：新代码 + schema 3→4 迁移。此刻 verifier 未部署，所以 site-hs-v1 /
#    console-hs-v1 的读取者只应是 {操作者身份} 且 Edge 产物里还没有它们。
#    任何与迁移无关的漂移 ⇒ 红 ⇒ 停。约 11 分钟。
python3 site-builder/scripts/verify_account_trust_boundary.py --update-baseline --migrate-from-schema 3
# ③ verifier-first：auth → panel（两者都是 $LATEST，秒级生效；signer 未变）
(cd site-builder/auth && python3 deploy_auth.py)
(cd site-builder/panel && python3 deploy_panel.py --skip-frontend)
python3 site-builder/scripts/verify_deployed_components.py
# ④ Edge：rm -rf cdk.out 是必须的（config 变了）
(cd router/infrastructure && rm -rf cdk.out && PATH=.venv/bin:$PATH npx -y aws-cdk@latest deploy --require-approval never)
# ⑤ 独立证据证明 Edge 全球部署完成，不是"CDK 说好了"
#    distribution id 不在 config.ini 里（那份只放输入不放产出），与 verify_deployed_edge.sh
#    同一来源：router 栈的 CfnOutput DistributionId。栈名取 router/config.ini [CDK]。
python3 - <<'PY'
import configparser, sys, time, boto3
c = configparser.ConfigParser(interpolation=None); c.read("router/config.ini")
stack = c["CDK"]["stack_name"].split("#")[0].strip()
outs = boto3.client("cloudformation", region_name="us-east-1").describe_stacks(
    StackName=stack)["Stacks"][0]["Outputs"]
dist = next(o["OutputValue"] for o in outs if o["OutputKey"] == "DistributionId")
cf = boto3.client("cloudfront")
for _ in range(60):
    if cf.get_distribution(Id=dist)["Distribution"]["Status"] == "Deployed":
        sys.exit(0)
    time.sleep(30)
sys.exit("CloudFront 30 分钟仍未 Deployed")
PY
bash site-builder/scripts/verify_deployed_edge.sh
# ⑥ 真机验收：今天的 verify 脚本仍用 legacy secret 本地 mint ⇒ 它们走的是 legacy 入口，
#    这正是 L1 要证明的事（旧 token 在新 verifier 上全部仍然放行）
python3 site-builder/scripts/verify_session_token_semantics.py
python3 site-builder/scripts/verify_console_e2e.py
bash site-builder/scripts/smoke_router.sh
# ⑦ 新入口的真机正向证据：用 site-hs-v1 本地 mint 一枚（读 SSM，操作者身份）打夹具站点，
#    必须放行；用 console-hs-v1 mint 的同形态 token 打 Edge，必须 302。
python3 site-builder/scripts/verify_kid_entry_live.py      # 本包新增，只发 GET
# ⑧ 观测在工作：三处日志里 accepted_legacy > 0 且总量 > 0；unknown_kid 只应来自 ⑦ 的负例
python3 site-builder/scripts/session_verify_counts.py --hours 1
# ⑨ 闸门复跑：相对 ② 的精确 delta 只允许——auth role 新增读 site-hs-v1/console-hs-v1、
#    panel role 新增读 console-hs-v1、Edge 产物新增携带 site-hs-v1（**不得**携带 console-hs-v1）。
python3 site-builder/scripts/verify_account_trust_boundary.py
```

**Step 4：E2E**（可选但推荐，37 分钟，后台跑或调大超时）：`RUN_E2E=1 site-builder/deployer/.venv/bin/pytest site-builder/deployer/tests/test_e2e_fixtures.py -q`。它走 legacy 入口，绿 = L1 对存量形态零影响。

**Step 5：文档**（都是状态真源）：
- `site-builder/DEPLOY.md`「轮转 jwt-secret」一节：从"当前实现不支持安全轮转"改成"verifier 已支持 `current`+`previous`+legacy（3c-1A）；**签发端仍未切**，真正的轮转协议在 3c-1B"，并写入 Task 7 的部署顺序与"verifier 单独回滚安全"这条性质；
- `CLAUDE.md`：不变量"auth/session 与 Edge verifier 是同一契约"补一句"含 `[SessionKeys]` 的 allowlist"；文档地图加本计划；测试命令段不变；
- spec §6.1 3c-1A 行状态标注"已实施（commit SHA）"；
- `docs/security/account-trust-boundary.md`：基线口径从单密钥改为按 kid 分列，数字由基线断言。

**Step 6：commit**（`scan_staged_secrets.sh` 两次，`|| exit 1`），最终签字用 commit SHA + 干净工作树。

**回滚**：任一步失败 ⇒ 只回滚失败的那个 verifier（Edge：CDK 回到上一版本并等 Deployed；auth/panel：上一版 zip）。**不动 SSM 里的新 secret**。signer 全程未变，回滚不产生任何用户可见影响。

---

### 3c-1A 的退出条件（= 3c-1B 的进入条件）

按 spec §6.1：**Edge 全球关联版本已确认生效**（Step 3 ⑤），且四个 `verify_*` 与 E2E 的登录态工具能 mint **带新 `kid` 的 HS token**。后者是 3c-1B 的进入条件而不是本包的交付物，但本包的 `mint_token` 与 `verify_kid_entry_live.py` 已经把它需要的原语放好了。

## 附：本计划覆盖 spec 的对照

| spec | 本计划 |
|---|---|
| §4.1 两个 key family、Edge 不含 console key | Task 0 schema；Task 3 只注入 site family；Task 6 闸门硬断言 Edge 产物不含 console 值 |
| §4.3 每个 verifier 自己的 allowlist | Task 3（Edge = site）、Task 4（auth = site；panel = console，且 panel 见到 site 即拒） |
| §4.4 禁止项四条 | Task 2 用例（kid 不拼资源、alg 只比对）、Task 3 守卫、Task 0（无全局 registry，按 family 切片下发） |
| §5 验签合同六步 | Task 2 `verify_token` 顺序 + 用例 |
| §6.2 状态机 L1 六条定义 | Global Constraints 的「2 + 1」「不回落」「按入口二分」；Task 2 `verify_with_legacy` |
| §8 观测词表 | Task 2 `OUTCOMES`、Task 5 |
| §9 反例全表 | Task 2 用例表、Task 3 Edge 用例、Task 4 M05 矩阵 |
| §10 表里归 3c-1A 的行 | `verify_account_trust_boundary.py`（Task 6）、`verify_deployed_edge.sh`（Task 3）、Edge 三个测试文件（Task 3）、auth/panel 测试（Task 4）、`config.ini.example`（Task 0） |
| §11.4 字面量与三类 claim 表 | Task 2 `TOKEN_USES` / `mint_token` |
| §11.6 `[SessionKeys]` schema | Task 0 |
| §6.1 进入条件（闸门先认两个 family） | Task 6 + Task 7 ②，部署前硬停止点 |
| §7 verifier-first、独立证据、回滚只回 signer | Task 7 ③④⑤ 与回滚段（本包无 signer 变化，故任何 verifier 可单独回滚） |

**明确不在本包**：signer 发 `kid`（1B）、login-flow secret（1B）、轮转演练 R1/R2（1B，且状态机要求 L3 之后）、KMS 任何东西（2A/2B）、`/fixture-session`（2A）、删 legacy 入口（3c-3）。

## 实施记录与偏差（2026-09-02，实施后 /code-review 两轴复审已吸收）

- **未按计划改名 `read-jwt-param → read-session-key:legacy`**（Task 6）。理由：28 个 principal 的 grant、文档标记与历史用例都挂着旧名，改名是一次纯结构性 churn；`is_secret_grant()` 已把 legacy 三条路与每 kid 一条统一成"可读密钥"判据。迁移桶按计划落地为 `--new-kid`（已声明的新 kid 在此前已能读密钥的 principal 上单列为迁移、不算扩权；未声明或此前不能读密钥仍红）。首跑（observed-1）是在该功能之前用人工审查 + `--update-baseline` 放行的，审查记录在 progress。
- **新增 `--migrate-baseline-only`**（零 AWS 调用的结构迁移）：为了在"脚本已是 schema 4、真机观测还没跑"的窗口里让 `test_baseline_schema_is_current` 保持有意义，而不是把测试放宽。
- **`APP_SITE_ALLOWLIST_JSON` 覆盖**：与既有 `APP_JWT_SECRET` 同款的离线 synth 开关；SSM 读失败注入的是带 `SYNTH-ONLY` 标记的占位 allowlist（不是空 `{}`），`verify_deployed_edge.sh` 的既有断言会抓。
- **`verify_kid_entry_live.py` 冒充目标站点的真实 owner**（与 `verify_session_token_semantics.py` 相同做法），是 3c-2A 常驻夹具站点（ADR-0002）就位前的过渡；放行断言是 `== 200`，`--self-test` 不碰 AWS。
- **COPY_FILES 加的是 `verifier_env.py`**（allowlist 装配 / legacy 开关 / 观测日志，auth 拥有、panel 复制），不是 `session_keys.py`（panel 运行时不读 config，只读环境变量）。
- 回滚锚点：部署前给 auth/panel `publish_version` 会让闸门多出 19 条 `@version` invoke grant（版本 ARN 是资源等价类成员）；验收后已删，**下次别用 publish_version 做锚点**，用 git 重部。
