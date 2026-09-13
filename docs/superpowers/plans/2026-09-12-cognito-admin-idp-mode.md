# 内置 Cognito 管理员建户 IdP 模式（asset-v1 工单 07）Implementation Plan

> **决策记录，不是操作指引。** 本文含单账号实测数据与当时的取舍过程，按写下的那一刻为准；
> 采用者要的操作步骤真源是 `site-builder/DEPLOY.md`，还剩什么没做看 `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` §9。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 `deploy_pool.py` 加一个 `[IdP] mode = cognito-admin` 模式：同一次运行里再建**第二个** Cognito 用户池充当 OIDC IdP（LITE 档、只许管理员建户、`email` 在 schema 层不可变），平台池照常以 OIDC 联邦接它——让"还没有任何 IdP"的采用者零外部依赖完成首次部署。

**Architecture:** 三层。① **纯本地 preflight**（模式解析、模式所需键、两套字段混填、`provider_name` 保留名、隔离旗标）——在任何 AWS 调用之前失败；② **只读 AWS preflight**（按池名与按域名前缀各查一次 IdP 池，不一致即 fail closed）——在第一次 AWS **写**之前失败；③ **收敛**——`main()` 在平台池托管域名（②）之后插入一步 ②b：建 IdP 池 → 托管域名（classic hosted UI，**不传** `ManagedLoginVersion`）→ 联邦 app client → 读回复验边界，然后把派生出的 `issuer` / `client_id` / `client_secret` 喂给既有的 `_ensure_oidc_idp`。`external-oidc`（默认，键缺失时的回落）那条代码路径**行为不变**。

**Tech Stack:** Python 3.12、boto3/botocore（`cognito-idp`）、pytest + botocore `Stubber`、configparser（裸解析，行内注释留在值里）。

**Spec:**
- `docs/adr/0006-built-in-cognito-admin-created-users-idp-mode.md`（tracked，决策真源；本计划 Task 9 修正它的实现机理措辞）
- `.scratch/asset-v1/issues/07-cognito-admin-created-users-idp-mode.md`（**gitignored**，工单正文 + 2026-09-11 那条完整实现输入）
- `.scratch/asset-v1/issues/06-idp-spike-google-and-second-cognito-pool.md`（**gitignored**，五个 Q 的实测答案与两条更正 = 本计划全部数字的证据来源）
- `.scratch/asset-v1/idp-spike/provision_idp_pool.py`（**gitignored**，06 留下的可跑参照实现；**只照抄 API 序列，不要照搬 `record()` / `Q1_*` / `Q2_*` / `Q5_*` 那套探针逻辑**——那是 spike 用来回答问题的，不属于生产脚本）

## Global Constraints

- **证据强度**：本计划引用的每个 Cognito 行为都是工单 06 在**单账号真机**上量过的，不是推断。列在下面「06 的实测结论」里；**不要重新推导，也不要相信与之矛盾的旧文档**。
- **真实账号 ID / 域名 / secret 只进 gitignored 的 `config.ini` 与 `.scratch/`**。提交前跑 `site-builder/scripts/scan_staged_secrets.sh`（**要先 `git add`**，空 stage 它什么都不看）。
- 脚本一律用**不带路径的 `python3`**（≥3.10，Homebrew python@3.12）；`config.ini` 是唯一取值来源，不硬编码账号 / 域名。
- **`.example` 的注释必须写成独立注释行**，不是行内注释：生产是裸 `ConfigParser`，`#` 会被并进值（`test_example_config_consistency.py` 专门禁共享键上的行内注释）。
- **生产池 `site-builder-users` 不许改**。真机验证只在隔离池上做：`deploy_pool.py --pool-name <spike> --domain-prefix <spike>`（三层隔离：池名、pre-token 函数名、SSM 前缀），本计划再加两个旗标把 IdP 池也隔离掉。
- 七套件跑法照抄 CLAUDE.md「测试命令」（本计划只动 `deployer` 与文档 ⇒ 最少要跑 `deployer`；最终闸门跑全部七套，**别并行**，`contract` 里那条墙钟哨兵对机器争用敏感）。
- **`us-east-1` 是硬约束**（Lambda@Edge + CloudFront ACM）。
- 不用 em dash（`—` 破折号在中文正文里照本仓库既有风格用，但 AWS 资源名与描述里只用连字符）。

## 06 的实测结论（本计划的输入，全部真机量过）

| # | 结论 | 落在本计划哪里 |
|---|---|---|
| 1 | IdP 池 **`UserPoolTier: LITE` 就够**（平台池要 ESSENTIALS 是为了 pre-token V2）；LITE **拒**managed login v2（`FeatureUnavailableInTierException`）⇒ 只有 classic hosted UI，**不需要** `create_managed_login_branding`，`/login` 照样 200 且带密码表单 | Task 3 `idp_pool_config`、Task 5 `_ensure_domain(managed_login_version=None)`、**不调** `_ensure_branding` |
| 2 | IdP 池**不需要** pre-token 触发器（平台池自己那个就够；access token 里 `email`/`idp`/`auth_via` 都在） | Task 7：②b 不碰 `deploy_auth.ensure_pre_token_trigger` |
| 3 | **"邮箱不可写"的唯一实现点是 schema `email` 的 `Mutable: False`**，不是 `WriteAttributes`：显式 `WriteAttributes` **必须包含全部 `Required=True` 属性**（`["name"]` 被 `InvalidParameterException: Invalid write attributes specified while creating a client` 拒，而 `["email","name"]` 反而**被接受**）⇒ 它不是防线。**正解是整个键不传**。复验：`Mutable=False` 下 `admin-update-user-attributes` 改 email 报 `user.email: Attribute cannot be updated.`——**连管理员都改不了** | Task 3（`idp_client_config` 不含该键 + 用例钉死）、Task 5（读回复验 `Mutable is False`）、Task 9（ADR 措辞） |
| 4 | **`ExplicitAuthFlows` 必须显式给 `["ALLOW_REFRESH_TOKEN_AUTH"]`，写 `[]` 是真缺陷**：空数组被当成"未指定"，默认值含 `ALLOW_USER_SRP_AUTH` + `ALLOW_CUSTOM_AUTH` ⇒ 身份源池上 SRP 密码认证全开、可绕过 hosted UI 直接用 API 认证（实测 `USER_SRP_AUTH` 调 `InitiateAuth` **成功返回挑战**）。显式给值后三个 flow 全 `not enabled`，且 hosted UI 仍 200 | Task 2（两道闸门收严到"必须显式非空"+ machine client 同步修）、Task 3、Task 5（读回复验覆盖 IdP 池那个 client） |
| 5 | **`provider_name` 保留名（逐个实测，区分大小写）**：被拒的**只有四个社交类型名** `Google` / `Facebook` / `LoginWithAmazon` / `SignInWithApple`（报 `Provider X cannot be of type OIDC`）；`SAML` 与 `COGNITO` **API 接受**，但 `COGNITO` 与 `SupportedIdentityProviders` 的字面量撞义、**不许用**；`google` 小写也接受（别依赖） | Task 1（本地保留名校验前移，零 API 调用） |
| 6 | **IdP 池必须有托管域名**：issuer 的 discovery 文档里 `authorization_endpoint` / `token_endpoint` / `userinfo_endpoint` 全指向托管域名。`claims_supported` 是 `null`（Cognito 不宣告），对本平台无影响 | Task 5 |
| 7 | 管理员建户**两条命令**，少第二条用户停在 `FORCE_CHANGE_PASSWORD`（首登多一屏强制改密）：`admin-create-user`（带 `email_verified=true`、`MessageAction=SUPPRESS`）+ `admin-set-user-password --permanent` | Task 7（脚本末尾打印这两条）、Task 10（DEPLOY.md） |
| 8 | 平台池里联邦用户 username 形如 `{ProviderName}_{sub}`；平台池 `UsernameAttributes=["email"]` ⇒ 同一邮箱跨 provider 在**同一个池**里会在登录期别名冲突（换池验证不受影响） | Task 10（已在 DEPLOY.md §0 第 3 条硬约束里，不重复写） |
| 9 | **回调 URL 必须用平台池托管域名的真实现值，不能用配置前缀拼**：`_ensure_domain` 在池已有域名时**沿用现值、忽略配置前缀**，拼错的症状是最后一跳 `redirect_uri_mismatch` | Task 7（②b 用 `_ensure_domain` 的返回值，不用 `args.domain_prefix`） |
| 10 | `client_secret` **不必持久化**：`create_user_pool_client` / `update_user_pool_client` 都回传 `ClientSecret`，幂等重跑能重取 | Task 5（返回值直接用；**不写 SSM**） |
| 11 | 部署顺序上 IdP 池与平台池互为前置，但平台池托管域名前缀是**配置给定的**（不由 AWS 分配）⇒ **可以一趟做完**，别让它变成"要跑两次" | Task 7（②b 插在 ② 之后、③ 之前） |

## 三条裁定（Kent，2026-09-12，写进 plan 以免执行期再问）

1. **`external-oidc` 下 `[IdP]` 段存在但 `provider_name` 为空 ⇒ 保持现状：打印告警并跳过联邦。** `provider_name` 只在 `cognito-admin` 下强制必填（那时必定要建 provider）。理由：`.example` 出厂就是空值，"先建池、后接 IdP"是支持的首次部署路径；external-oidc 是**生产在用的代码路径**，本票最大的风险面就是它的回归。保留名校验对**两种模式的非空值**都生效。
2. **加 `--idp-pool-name` / `--idp-domain-prefix` 两个旗标，隔离运行时必须显式给。** `--pool-name != site-builder-users` 时缺任一即在任何 AWS 写之前退出。理由：IdP 池的名字来自 config，而 `--pool-name` 的三层隔离覆盖不到它——"隔离平台池 + 生产 IdP 池"会对**生产 IdP 池的 app client** 做 read-modify-write。另外 IdP 池 client 的 `CallbackURLs` 按**并集**收敛（沿用本仓库既有的"多一个已登记 URL 无害、少一个会报错"先例），即使误跑也不会摘掉线上回调。
3. **管理员建户不进脚本**，手册保留那两条 `aws cognito-idp` 命令。理由：建户是持续性运维动作（加人就做一次），不属于幂等部署脚本的语义；且脚本里处理初始密码交付会引入"明文进 shell 历史 / transcript"的新设计面。脚本**打印**这两条命令（含真实 pool id），把门槛降到复制粘贴。

## File Structure

| 文件 | 责任 | 动作 |
|---|---|---|
| `site-builder/scripts/deploy_pool.py` | 平台池 + （新）内置 IdP 池的唯一收敛入口 | 修改：+ ~9 个函数、`main()` 插入 ⓿/②b、两个新旗标 |
| `site-builder/config.ini.example` | 采用者复制的起点 | 修改：`[IdP]` + 三个新键（说明写成独立注释行） |
| `site-builder/deployer/tests/test_deploy_pool.py` | `deploy_pool.py` 的行为守卫 | 修改：+ ~30 条用例；改写 1 条（machine client 的 `[]` 前提） |
| `site-builder/deployer/tests/test_delivery_docs_current.py` | 交付文档时效守卫 | 修改：+ 2 条（DEPLOY.md 第 3 条路已脚本化、ADR 0006 措辞） |
| `site-builder/DEPLOY.md` | 部署手册 | 修改：§0 第 3 条路（去掉"依赖工单 07"占位）、【内置 Cognito】小节改写、就绪清单第 3 条、① 步骤 1 加分支 |
| `docs/adr/0006-*.md` | ADR（accepted，决策不变、只修实现机理措辞） | 修改：正文一句 + Consequences 两条 |
| `.scratch/asset-v1/issues/07-*.md` | 工单（gitignored） | 修改：正文措辞 + Comments 记裁定与实测 |
| `.scratch/asset-v1/NEXT.md` | 接手点（gitignored） | 修改：顶部 |
| `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md` | §9 待办真源（tracked） | 修改：第 11 行划掉"模式仍待实现" |

**不新建文件。** 全部改动落在 `deploy_pool.py` 与它既有的那两份测试里——模式开关是这个脚本的一个分支，不是一个新组件。

---

### Task 1: `[IdP] mode` 解析 + 保留名校验前移（纯本地 preflight，零 AWS 调用）

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（在 `_truthy` 之后、`pool_config` 之前插入）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Produces:
  - `IDP_MODE_EXTERNAL: str = "external-oidc"`、`IDP_MODE_COGNITO: str = "cognito-admin"`、`IDP_MODES: tuple[str, str]`
  - `RESERVED_PROVIDER_NAMES: dict[str, str]`（名字 → 为什么不许用）
  - `_clean(value: str) -> str`（切掉行内注释 + strip，**不改大小写**）
  - `idp_mode(idp: dict) -> str`
  - `assert_provider_name_allowed(name: str) -> None`
  - `check_idp_section(idp: dict, mode: str) -> None`
  - `resolve_idp_pool_names(*, pool_name: str, idp_pool_name: str | None, idp_domain_prefix: str | None, idp: dict) -> tuple[str, str]`
- Consumes: 无（本任务是纯函数层）

- [ ] **Step 1: 写失败的用例（模式解析 + 保留名 + 三类配置错误 + 隔离守卫）**

追加到 `site-builder/deployer/tests/test_deploy_pool.py` 末尾：

```python
# ---------------------------------------------------------------------------
# 工单 07：[IdP] mode —— 纯本地 preflight（零 AWS 调用）
# ---------------------------------------------------------------------------
#
# **为什么这些用例必须存在**：`test_config_example_keys_are_read.py` 把"整段读取"
# （`dict(cfg["IdP"])`，deploy_pool 正是这样读的）算成"读了该段每个键"，所以往
# `[IdP]` 里加任何键，那个守卫都恒真——它证明不了新键影响行为。本节是新键的
# **唯一**行为证据。

def _idp_cognito(**over) -> dict:
    """cognito-admin 模式的最小合法 [IdP]（issuer/client_id/client_secret 必须缺席）。"""
    base = {"mode": "cognito-admin", "provider_name": "CognitoSource",
            "cognito_user_pool_name": "site-builder-idp",
            "cognito_domain_prefix": "acme-idp-2026"}
    base.update(over)
    return base


def test_idp_mode_defaults_to_external_when_key_absent():
    """键缺失 ⇒ external-oidc。这是向后兼容的支点：存量 config.ini 里没有 mode。"""
    assert dp.idp_mode({}) == dp.IDP_MODE_EXTERNAL
    assert dp.idp_mode({"provider_name": "Feishu"}) == dp.IDP_MODE_EXTERNAL
    assert dp.idp_mode({"mode": ""}) == dp.IDP_MODE_EXTERNAL


def test_idp_mode_tolerates_inline_comments():
    """裸 ConfigParser 会把行内注释并进值。mode 是本脚本自己判分支用的，
    所以它必须先切掉 `#` / `;`——否则 `mode = cognito-admin  # 内置` 会被判成未知模式。"""
    assert dp.idp_mode({"mode": "cognito-admin  # 内置池"}) == dp.IDP_MODE_COGNITO
    assert dp.idp_mode({"mode": "external-oidc ; 已有 IdP"}) == dp.IDP_MODE_EXTERNAL


def test_idp_mode_rejects_unknown_value():
    """未知模式必须响亮失败：静默回落成 external-oidc 会让写错模式名的采用者
    建出一个"没有 IdP 池、client 只列 COGNITO"的池，而输出看起来一切正常。"""
    with pytest.raises(SystemExit, match="cognito-admin"):
        dp.idp_mode({"mode": "cognito-managed"})     # ADR 早期用过的名字，不是最终值


@pytest.mark.parametrize("name", ["Google", "Facebook", "LoginWithAmazon",
                                  "SignInWithApple", "COGNITO"])
def test_reserved_provider_names_are_rejected_locally(name):
    """保留名校验必须**在任何 AWS 调用之前**：Cognito 要到 create_identity_provider
    才报 `Provider Google cannot be of type OIDC`，而那时池与托管域名都已建好，
    脚本停在中途（工单 06 腿 1 实测踩过）。前四个是 Cognito 拒的社交类型名；
    COGNITO 是本仓库自己的规则——API 接受它，但 app client 的
    SupportedIdentityProviders 用这个字面量表示"池内建用户目录"，同名无法分辨。"""
    with pytest.raises(SystemExit) as e:
        dp.assert_provider_name_allowed(name)
    assert name in str(e.value)


@pytest.mark.parametrize("name", ["GoogleOIDC", "SAML", "google", "CognitoSource",
                                  "Feishu"])
def test_non_reserved_provider_names_are_accepted(name):
    """校验**区分大小写且只拒实测被拒的那些**，不许自己发明规则。

    逐个实测过：`SAML` 与 `google`（小写）Cognito 都接受。多拒一个名字的代价是
    采用者被一条不存在的限制挡住，而错误文案会告诉他"Cognito 保留了这个名字"
    ——一句假话。`google` 能用但不该依赖（大小写差一个字母就变成被拒的那个），
    这条提醒写在 config.ini.example 的注释里，不写成硬失败。
    """
    dp.assert_provider_name_allowed(name)      # 不得抛


def test_reserved_name_check_sees_through_inline_comments():
    """`provider_name = Google  # 我们的 IdP` 同样要被拦住。"""
    with pytest.raises(SystemExit, match="Google"):
        dp.check_idp_section({"provider_name": "Google  # 我们的 IdP"},
                             dp.IDP_MODE_EXTERNAL)


def test_external_mode_with_empty_provider_name_is_not_an_error():
    """**回归钉子（裁定 1）**：`[IdP]` 段存在但全空 ⇒ 不报错。

    `.example` 出厂就是空值，而 main() 对这种情形的既有行为是打印告警并跳过联邦
    （"首次部署、联邦还没接"那条路）。把它改成硬失败会改掉生产在用的那条代码路径。
    """
    dp.check_idp_section({}, dp.IDP_MODE_EXTERNAL)                       # 不得抛
    dp.check_idp_section({"provider_name": "", "issuer": ""},
                         dp.IDP_MODE_EXTERNAL)                            # 不得抛


def test_cognito_mode_requires_provider_name():
    """cognito-admin 下必定要建 provider ⇒ 名字必填，且它还要逐字符进 router 的
    trusted_idps（那一对没有任何自动闸门）。"""
    with pytest.raises(SystemExit, match="provider_name"):
        dp.check_idp_section(_idp_cognito(provider_name=""), dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("missing", ["cognito_user_pool_name", "cognito_domain_prefix"])
def test_cognito_mode_requires_both_of_its_own_keys(missing):
    """两个键缺一不可：少了池名就无法幂等找回那个池，少了域名前缀就没有
    authorization/token/userinfo 端点（issuer 的 discovery 全指向托管域名）。"""
    idp = _idp_cognito(**{missing: ""})
    with pytest.raises(SystemExit, match=missing):
        dp.check_idp_section(idp, dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("field", ["issuer", "client_id", "client_secret"])
def test_cognito_mode_rejects_externally_supplied_federation_fields(field):
    """三个字段在内置模式下由部署过程从新建的池派生 ⇒ **非空即报冲突**，不静默忽略。

    静默忽略的症状最难查：采用者以为自己指定了 issuer，实际生效的是另一个池的
    issuer，而两者的 discovery 文档都合法、登录页都能开，只有 claim 里的 `idp`
    与预期不同。
    """
    with pytest.raises(SystemExit, match=field):
        dp.check_idp_section(_idp_cognito(**{field: "x"}), dp.IDP_MODE_COGNITO)


@pytest.mark.parametrize("field", ["cognito_user_pool_name", "cognito_domain_prefix"])
def test_external_mode_rejects_cognito_mode_keys(field):
    """反向混填同样拒：填了内置模式的键却没切模式 ⇒ 采用者以为会建第二个池，
    而实际什么都没建（.example 出厂两键为空，所以只有"填了"才触发）。"""
    idp = {"provider_name": "Okta", "issuer": "https://okta.example/",
           "client_id": "c", "client_secret": "s", field: "acme-idp"}
    with pytest.raises(SystemExit, match=field):
        dp.check_idp_section(idp, dp.IDP_MODE_EXTERNAL)


def test_cognito_mode_minimal_config_passes():
    dp.check_idp_section(_idp_cognito(), dp.IDP_MODE_COGNITO)      # 不得抛


def test_idp_pool_names_prefer_flags_over_config():
    assert dp.resolve_idp_pool_names(
        pool_name=dp.POOL_NAME, idp_pool_name=None, idp_domain_prefix=None,
        idp=_idp_cognito()) == ("site-builder-idp", "acme-idp-2026")
    assert dp.resolve_idp_pool_names(
        pool_name=dp.POOL_NAME, idp_pool_name="spike-idp",
        idp_domain_prefix="spike-idp-2026",
        idp=_idp_cognito()) == ("spike-idp", "spike-idp-2026")


@pytest.mark.parametrize("flags", [(None, None), ("spike-idp", None),
                                   (None, "spike-idp-2026")])
def test_isolated_platform_pool_requires_both_idp_isolation_flags(flags):
    """**裁定 2**：`--pool-name` 的三层隔离（池名 / pre-token 函数名 / SSM 前缀）
    **覆盖不到 IdP 池**——它的名字来自 config。所以"隔离平台池 + 生产 IdP 池"
    这个组合会对**生产 IdP 池的 app client** 做 read-modify-write
    （`SupportedIdentityProviders` / `ExplicitAuthFlows` / `CallbackURLs`）。
    在任何 AWS 写之前拒掉它，而不是靠人记得同时改 config。
    """
    name, prefix = flags
    with pytest.raises(SystemExit, match="--idp-pool-name"):
        dp.resolve_idp_pool_names(pool_name="sb-idp-spike", idp_pool_name=name,
                                  idp_domain_prefix=prefix, idp=_idp_cognito())
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "idp_mode or reserved or cognito_mode or external_mode or idp_pool_names or isolation_flags"`
Expected: FAIL，`AttributeError: module 'deploy_pool' has no attribute 'idp_mode'`（等）

- [ ] **Step 3: 实现**

在 `deploy_pool.py` 里，把 `_truthy` 改成复用新的 `_clean`，并在它后面插入本任务的函数：

```python
def _clean(value: str) -> str:
    """config.ini 的取值清洗：切掉行内注释再 strip，**不改大小写**。

    裸 ConfigParser 不剥行内注释（本仓库刻意保持这个语义，见
    test_example_config_consistency.py），所以每个自己判分支的键都要先过这里。
    大小写必须原样保留——Cognito 的 provider 名校验区分大小写（实测：`Google`
    被拒而 `google` 接受）。
    """
    return str(value).split("#")[0].split(";")[0].strip()


def _truthy(value: str) -> bool:
    """config.ini 的布尔解析。

    只认明确的真值词；写错（yes/1/on 之外的拼写）一律当 False，与
    router/stack.py 对 require_idp_claim 的严格态度一致。
    """
    return _clean(value).lower() in ("true", "yes", "1", "on")


# ---- [IdP] 模式（ADR 0006 / 工单 07）-------------------------------------
#
# external-oidc：采用者已有 OIDC IdP（Okta / Entra / Google / 飞书适配器…），
#                issuer / client_id / client_secret 由他给出。**默认值**，
#                也是 mode 键缺失时的回落——存量 config.ini 里没有这个键。
# cognito-admin：资产自己再建第二个 Cognito 池当 OIDC IdP（LITE、只许管理员
#                建户、email 在 schema 层 Mutable=False），三个联邦字段由部署
#                过程派生。决策见 docs/adr/0006-*.md。
#
# **名字不叫 cognito-managed**（ADR 早期用过）：LITE 档恰恰**不支持** managed
# login v2，那个名字会把读者引到反面。
IDP_MODE_EXTERNAL = "external-oidc"
IDP_MODE_COGNITO = "cognito-admin"
IDP_MODES = (IDP_MODE_EXTERNAL, IDP_MODE_COGNITO)

# cognito-admin 独有的键（缺一不可：少了池名无法幂等找回那个池，少了域名前缀
# 就没有 authorization/token/userinfo 端点）
_COGNITO_MODE_KEYS = ("cognito_user_pool_name", "cognito_domain_prefix")
# external-oidc 独有的键；cognito-admin 下由部署过程派生，**非空即冲突**
_EXTERNAL_MODE_KEYS = ("issuer", "client_id", "client_secret")

# provider_name 的保留名（**逐个实测，区分大小写**，工单 06 腿 1）。
# 只有四个**社交类型名**会被 Cognito 拒（`Provider X cannot be of type OIDC`）；
# `SAML` 与小写 `google` 都被接受，所以不许往这张表里凭印象加名字——多拒一个
# 就是用一句假话挡住采用者。`COGNITO` 是本仓库自己的规则，理由见值。
RESERVED_PROVIDER_NAMES = {
    "Google": "Cognito 把它保留给原生 social provider 类型（ProviderType=Google），"
              "与本平台一律走的 ProviderType=OIDC 冲突。接 Google 用 GoogleOIDC。",
    "Facebook": "同上（原生 social provider 类型名）。",
    "LoginWithAmazon": "同上（原生 social provider 类型名）。",
    "SignInWithApple": "同上（原生 social provider 类型名）。",
    "COGNITO": "Cognito 的 API 接受它，但 app client 的 SupportedIdentityProviders "
               "用这个字面量表示「池内建用户目录」——同名会让配置语义无法分辨。",
}


def idp_mode(idp: dict) -> str:
    """[IdP] mode 的唯一解析点。键缺失 / 为空 → external-oidc（向后兼容）。

    未知值**响亮失败**：静默回落会让写错模式名的采用者建出一个"没有 IdP 池、
    client 只列 COGNITO"的平台池，而脚本输出看起来一切正常。
    """
    raw = _clean(idp.get("mode", ""))
    if not raw:
        return IDP_MODE_EXTERNAL
    if raw not in IDP_MODES:
        raise SystemExit(
            f"[IdP] mode = {raw!r} 不认识。只能是 {IDP_MODE_EXTERNAL}（已有 OIDC "
            f"IdP，默认）或 {IDP_MODE_COGNITO}（资产内置第二个 Cognito 池当 IdP）。"
            "键缺失时按 external-oidc。")
    return raw


def assert_provider_name_allowed(name: str) -> None:
    """provider_name 的保留名校验。**纯本地、零 API 调用，前移到任何 AWS 写之前。**

    不前移的代价实测过（工单 06 腿 1）：Cognito 要到 create_identity_provider
    才报 `Provider Google cannot be of type OIDC`，而那一步在建池与建托管域名
    **之后**，脚本停在中途。文档挡不住手滑。
    """
    why = RESERVED_PROVIDER_NAMES.get(name)
    if why:
        raise SystemExit(f"[IdP] provider_name = {name!r} 不能用：{why}")


def check_idp_section(idp: dict, mode: str) -> None:
    """[IdP] 段的本地一致性校验（零 AWS 调用）。

    三类判据：
      ① provider_name 非空时不许是保留名（两种模式都查）；
      ② 模式所需键齐备（cognito-admin 才有必填项——external-oidc 下"全空 =
         跳过联邦"是支持的首次部署状态，见 main() ③ 的告警分支）；
      ③ 两套模式的字段不许混填（静默忽略比报错难查得多：采用者以为自己指定了
         issuer，实际生效的是另一个池的）。
    """
    name = _clean(idp.get("provider_name", ""))
    if name:
        assert_provider_name_allowed(name)

    cognito_filled = [k for k in _COGNITO_MODE_KEYS if _clean(idp.get(k, ""))]
    # client_secret 不过 _clean：secret 里的 `#` 不是注释（Cognito 的 secret 是
    # [\w+]+，但别让清洗逻辑成为一条能改写凭证的路径）
    external_filled = [k for k in _EXTERNAL_MODE_KEYS if str(idp.get(k, "")).strip()]

    if mode == IDP_MODE_COGNITO:
        if not name:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 必须给 provider_name（Cognito 里那个"
                " provider 名，自取）。同一个值还要逐字符写进 router/config.ini 的"
                " [SiteBuilder] trusted_idps，否则 require_idp_claim=true 下这个 IdP"
                "的用户全部被 Edge 302——那一对没有任何自动闸门。")
        missing = [k for k in _COGNITO_MODE_KEYS if k not in cognito_filled]
        if missing:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 缺 {', '.join(missing)}。"
                "这两个键与 mode 是一组、缺一不可：没有池名就无法幂等找回那个 IdP 池，"
                "没有托管域名前缀就没有 authorize/token/userinfo 端点"
                "（issuer 的 discovery 文档全指向托管域名）。")
        if external_filled:
            raise SystemExit(
                f"[IdP] mode = {IDP_MODE_COGNITO} 下 {', '.join(external_filled)} 必须留空"
                "——它们由本次部署从新建的 IdP 池派生。填了值说明这份 config 混了两套"
                "模式的字段，静默忽略会让你以为生效的是自己填的那个 issuer。")
    elif cognito_filled:
        raise SystemExit(
            f"[IdP] mode = {IDP_MODE_EXTERNAL}（或未给 mode）时 {', '.join(cognito_filled)}"
            f" 必须留空——那是 {IDP_MODE_COGNITO} 模式的键。要用内置 IdP 池请显式写"
            f" mode = {IDP_MODE_COGNITO}。")


def resolve_idp_pool_names(*, pool_name: str, idp_pool_name: str | None,
                           idp_domain_prefix: str | None,
                           idp: dict) -> tuple[str, str]:
    """内置 IdP 池的池名与托管域名前缀：命令行旗标优先于 config。

    **隔离守卫**：`--pool-name` 不是生产池时，两个旗标必须都显式给出。
    `--pool-name` 只隔离了三样东西（平台池名、pre-token 函数名、SSM 前缀），
    **IdP 池的名字来自 config** ⇒ "隔离平台池 + 生产 IdP 池"这个组合会对生产
    IdP 池的 app client 做 read-modify-write（改 SupportedIdentityProviders /
    ExplicitAuthFlows / CallbackURLs）。这里在任何 AWS 写之前拒掉它。
    """
    if pool_name != POOL_NAME and not (idp_pool_name and idp_domain_prefix):
        raise SystemExit(
            f"--pool-name {pool_name!r} 不是生产池，但没有同时给 --idp-pool-name 与"
            " --idp-domain-prefix。内置 IdP 池的名字来自 config.ini，`--pool-name`"
            "隔离不到它——照这样跑会对**生产 IdP 池**的 app client 做写操作。"
            "两个旗标都显式给出后再跑。")
    return (idp_pool_name or _clean(idp.get("cognito_user_pool_name", "")),
            idp_domain_prefix or _clean(idp.get("cognito_domain_prefix", "")))
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS（全文件；`_truthy` 的既有 6 条参数化用例必须仍绿——它现在走 `_clean`）

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): [IdP] mode 解析 + provider_name 保留名校验前移（纯本地 preflight）"
```

---

### Task 2: 两道 flow 闸门收严到"必须显式非空"+ machine client 同步修

> **这一条可以被单独否决**（其余任务不依赖它）。它修的是**既有生产代码**里与工单 07 同类的一个缺陷，且要改写一条**刻意锁死了反向前提**的既有用例。理由与代价写在下面；不做的话请在工单 07 的 Comments 里记一句"已知、暂不修"。

**为什么**：工单 06 实测出 `ExplicitAuthFlows: []` 被 Cognito 当成**未指定**，默认值是
`ALLOW_REFRESH_TOKEN_AUTH` + `ALLOW_USER_SRP_AUTH` + `ALLOW_CUSTOM_AUTH`。而
`deploy_pool.client_configs` 里的 **machine client 正是 `"ExplicitAuthFlows": []`**
（`client_credentials`，key-proxy 用，`[ApiKey]` 段存在时才建）。两道闸门判的是
"有没有开原生 flow"（与 `NATIVE_AUTH_FLOWS` 求交集），空集合自然过——于是
`_assert_no_native_flows` 与 `_verify_no_native_flows` **一起瞎掉**，正是这个文件
自己的注释警告过的形态（"漏项的后果不是少拦一种，而是两道闸门一起瞎掉"）。
既有用例 `test_machine_client_passes_both_native_flow_gates` 把"`[]` 必须放行"
锁死了，它的 docstring 说"将来若有人把判定收严…那个改动看起来像是加固"——
**那条判断建立在"空 = 什么都没开"这个前提上，而 06 量出前提是错的**。

**代价**（要 Kent 知情）：改完之后下一次在**生产池**上跑 `deploy_pool.py` 会更新
machine client 的 `ExplicitAuthFlows`（`[]` → `["ALLOW_REFRESH_TOKEN_AUTH"]`）。
`client_credentials` 与 `ExplicitAuthFlows` 是两个正交维度，收紧它不影响
key-proxy 换 token；但"Cognito 接受 client_credentials client 带
ALLOW_REFRESH_TOKEN_AUTH"这一点**只有 shape 层校验**，真机确认放在 Task 12
（隔离池的 `[ApiKey]` 段会建出 machine client，那一步就是证据）。

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（`client_configs` 的 machine 分支、`_assert_no_native_flows`、`_verify_no_native_flows`）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`（改写 1 条 + 新增 3 条）

**Interfaces:**
- Consumes: `NATIVE_AUTH_DISABLED`、`NATIVE_AUTH_FLOWS`（既有）
- Produces: 两道闸门的新判据（非空 + 无交集）；`client_configs()["machine"]["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]`

- [ ] **Step 1: 改写既有用例 + 写新用例**

把 `test_machine_client_passes_both_native_flow_gates`（约 line 886）整条替换成：

```python
def test_machine_client_explicitly_disables_native_flows_not_empty_list():
    """machine client 的 ExplicitAuthFlows 必须是**显式的** ["ALLOW_REFRESH_TOKEN_AUTH"]。

    **这条用例取代了原先那条锁死"`[]` 必须放行"的用例**，因为它的前提被实测推翻了
    （工单 06）：Cognito 把空数组当成**未指定**，而未指定的默认值是
    ALLOW_REFRESH_TOKEN_AUTH + **ALLOW_USER_SRP_AUTH** + **ALLOW_CUSTOM_AUTH**。
    实测（对一个 ExplicitAuthFlows=[] 的 client 带正确 SECRET_HASH 调 InitiateAuth）：
    `USER_SRP_AUTH` **成功返回挑战**，`CUSTOM_AUTH` 只因没配 lambda 而失败 ⇒ 两个
    flow 都是开的。改成显式那一项后三者全部 `not enabled`。

    所以"读回来是空"与"能力面是空"是两件事，中间差一次**行为**验证——这也是
    NATIVE_AUTH_DISABLED 一开始就写成 ["ALLOW_REFRESH_TOKEN_AUTH"] 而不是 [] 的原因。
    """
    machine = dp.client_configs("example.com", [], idp_name="Okta",
                                include_machine=True,
                                machine_scopes=("site-builder-mcp/invoke",))["machine"]
    assert machine["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    dp._assert_no_native_flows("machine", machine)          # 不得抛

    from botocore.stub import Stubber
    cog = _resource_server_cog()
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ExplicitAuthFlows":
                                              ["ALLOW_REFRESH_TOKEN_AUTH"]}},
                          {"UserPoolId": "us-east-1_x", "ClientId": "m1"})
        dp._verify_no_native_flows(cog, "us-east-1_x", {"machine": "m1"})


@pytest.mark.parametrize("flows", [[], None])
def test_assert_no_native_flows_rejects_unspecified(flows):
    """空 / 缺席同样要被拦：它等于"未指定" ⇒ Cognito 的默认值把 SRP 与 CUSTOM 打开。

    这条判据不能只写在 machine client 的用例里——闸门本身必须会红，否则下一个
    手抄一份 client 参数的人照样能把 `[]` 递进去。
    """
    params = {} if flows is None else {"ExplicitAuthFlows": flows}
    with pytest.raises(SystemExit, match="未指定|显式"):
        dp._assert_no_native_flows("probe", params)


@pytest.mark.parametrize("flows", [[], None])
def test_verify_no_native_flows_rejects_unspecified_readback(flows):
    """读回复验同样要拦空值：线上读回 [] / None 时能力面是**开着**的
    （SRP + CUSTOM），而旧判据会把它当成"边界成立"打印一行 ✓。"""
    import boto3
    from botocore.stub import Stubber
    live = {} if flows is None else {"ExplicitAuthFlows": flows}
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool_client", {"UserPoolClient": live},
                          {"UserPoolId": "us-east-1_test", "ClientId": "c1"})
        with pytest.raises(SystemExit, match="未指定|显式"):
            dp._verify_no_native_flows(cog, "us-east-1_test", {"site": "c1"})
```

同时把 `test_machine_client_with_scopes_is_client_credentials_only`（约 line 201）里
`assert machine["ExplicitAuthFlows"] == []` 改成 `== ["ALLOW_REFRESH_TOKEN_AUTH"]`。

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "native_flows or client_credentials_only"`
Expected: FAIL（machine 仍是 `[]`；两道闸门仍放行空值）

- [ ] **Step 3: 实现**

`client_configs` 的 machine 分支：

```python
            # 不开任何原生认证 flow（与 site/mcp 同一条边界）。
            # **必须是显式的 ["ALLOW_REFRESH_TOKEN_AUTH"]，不能是 []**：空数组被
            # Cognito 当成"未指定"，而未指定的默认值含 ALLOW_USER_SRP_AUTH +
            # ALLOW_CUSTOM_AUTH（工单 06 实测：[] 时 USER_SRP_AUTH 调 InitiateAuth
            # 成功返回挑战）。client_credentials 与 ExplicitAuthFlows 正交，
            # 收紧它不影响 key-proxy 换 token。
            "ExplicitAuthFlows": list(NATIVE_AUTH_DISABLED),
```

两道闸门各加一段（放在求交集**之前**）：

```python
def _assert_no_native_flows(key: str, params: dict) -> None:
    """边界自检：client 参数里不得出现任何原生认证 flow（spec §3.5 第 4 条）。

    放在下发之前——配置漂移（有人为了调试加回 USER_PASSWORD_AUTH）会让
    allowed_users="org" 的边界失效，而 claim 校验拦不住"原生认证 → refresh
    洗白"这条路径。

    **空 / 缺席同样是缺陷**（工单 06 实测）：Cognito 把它当成"未指定"，默认值是
    ALLOW_REFRESH_TOKEN_AUTH + ALLOW_USER_SRP_AUTH + ALLOW_CUSTOM_AUTH ⇒ 能力面
    是开着的，而与 NATIVE_AUTH_FLOWS 求交集恰好为空 ⇒ 两道闸门一起瞎掉。
    """
    flows = set(params.get("ExplicitAuthFlows") or [])
    if not flows:
        raise SystemExit(
            f"client {key} 的 ExplicitAuthFlows 为空 / 未给——Cognito 会把它当成"
            "「未指定」并套用默认值（含 ALLOW_USER_SRP_AUTH + ALLOW_CUSTOM_AUTH），"
            f"等于原生认证全开。必须显式给 {NATIVE_AUTH_DISABLED}。")
    bad = flows & set(NATIVE_AUTH_FLOWS)
    ...  # 既有逻辑不变


def _verify_no_native_flows(cog, pool_id: str, clients: dict) -> None:
    """下发后读回复验：update_user_pool_client 是整体替换，漏传即被清空/改写。

    **读回 [] / None 也要红**：那是"未指定" ⇒ 线上能力面含 SRP + CUSTOM
    （工单 06 实测），而旧判据会为它打印一行 ✓。
    """
    for key, client_id in clients.items():
        desc = cog.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
        flows = set(desc.get("ExplicitAuthFlows") or [])
        if not flows:
            raise SystemExit(
                f"client {key}({client_id}) 线上的 ExplicitAuthFlows 是空 / 未设——"
                "Cognito 按「未指定」套默认值（含 SRP + CUSTOM），原生认证实际开着，"
                f"中止。期望恰好是 {NATIVE_AUTH_DISABLED}（spec §3.5 第 4 条）")
        bad = flows & set(NATIVE_AUTH_FLOWS)
        ...  # 既有逻辑不变
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS。若 `test_client_configs_pass_botocore_param_validation` 红，说明 machine 的
参数组合被 shape 校验拒了——那属于真实缺陷，回到 Step 3 而不是放宽用例。

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "fix(asset-v1/07): ExplicitAuthFlows 空数组 = 未指定（SRP/CUSTOM 默认开）——两道闸门收严 + machine client 显式 refresh-only"
```

---

### Task 3: 内置 IdP 池的参数生成（纯函数）

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（紧跟 `client_configs` 之后）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Consumes: `NATIVE_AUTH_DISABLED`（Task 2 之后仍是同一个值）
- Produces:
  - `IDP_CLIENT_NAME: str = "platform-federation"`
  - `idp_pool_config(pool_name: str) -> dict`（`CreateUserPool` 参数）
  - `idp_client_config(platform_idpresponse: str) -> dict`（`CreateUserPoolClient` 参数）

- [ ] **Step 1: 写失败的用例**

```python
def test_idp_pool_is_lite_tier():
    """LITE 够用：平台池要 ESSENTIALS 是为了 pre-token V2，而这个池不挂任何触发器
    （实测 access token 里 email/idp/auth_via 都由**平台池**那个触发器注入）。
    LITE 还明确拒 managed login v2 ⇒ 只有 classic hosted UI，也不需要 branding。
    采用者的月成本因此只加 LITE 一档。"""
    assert dp.idp_pool_config("acme-idp")["UserPoolTier"] == "LITE"


def test_idp_pool_email_is_required_and_immutable():
    """**这是"邮箱由身份源控制"的唯一实现点。**

    实测复验：Mutable=False 下 admin_update_user_attributes 改 email 报
    `InvalidParameterException: user.email: Attribute cannot be updated.`
    ——连管理员都改不了。代价是建错邮箱只能删号重建（写进 DEPLOY.md）。
    """
    schema = dp.idp_pool_config("acme-idp")["Schema"]
    email = [a for a in schema if a["Name"] == "email"]
    assert email == [{"Name": "email", "AttributeDataType": "String",
                      "Required": True, "Mutable": False}]


def test_idp_pool_disables_self_signup():
    """开着自注册 = 任何人都能自己造一个邮箱身份，整条路的地基就没了
    （也是 palisade.udd.cognito.pool.open 扫的那一条）。"""
    cfg = dp.idp_pool_config("acme-idp")
    assert cfg["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert cfg["PoolName"] == "acme-idp"
    assert cfg["UsernameAttributes"] == ["email"]
    assert cfg["AutoVerifiedAttributes"] == ["email"]


def test_idp_client_omits_write_attributes_entirely():
    """**WriteAttributes 这个键必须整个不给**，而不是给一份不含 email 的名单。

    实测（工单 06 Q3）：显式给出的 WriteAttributes 必须包含全部 Required=True 属性
    ——`["name"]` 被 `InvalidParameterException: Invalid write attributes specified
    while creating a client` 拒，而 `["email","name"]` 反而**被接受**（哪怕 email 是
    Mutable=False）。所以它**不是防线**；不给这个键时读回是 None，语义是"全部
    **可变**标准属性可写"，而 email 在 schema 层不可变 ⇒ 自动被排除。
    """
    assert "WriteAttributes" not in dp.idp_client_config("https://x/oauth2/idpresponse")


def test_idp_client_reads_the_three_mapping_targets():
    """ReadAttributes 缺 email 而请求了 email scope ⇒ token 端点 invalid_grant。"""
    cfg = dp.idp_client_config("https://x/oauth2/idpresponse")
    assert set(cfg["ReadAttributes"]) == {"email", "email_verified", "name"}


def test_idp_client_is_confidential_code_flow_with_platform_callback():
    cfg = dp.idp_client_config("https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse")
    assert cfg["GenerateSecret"] is True        # Cognito 作 OIDC RP 时要 client_secret
    assert cfg["AllowedOAuthFlows"] == ["code"]
    assert cfg["AllowedOAuthFlowsUserPoolClient"] is True
    assert set(cfg["AllowedOAuthScopes"]) == {"openid", "email", "profile"}
    assert cfg["CallbackURLs"] == [
        "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"]
    # IdP 池自己就是身份源：它的 client 只列 COGNITO（与平台池刻意不列 COGNITO 相反）
    assert cfg["SupportedIdentityProviders"] == ["COGNITO"]
    assert cfg["ClientName"] == dp.IDP_CLIENT_NAME


def test_idp_client_passes_the_native_flow_gate():
    """身份源池上原生认证全开 = 可以绕过 hosted UI 直接用 API 认证
    （工单 06 的 Q4 更正）。这个池今天没有 CDK / 控制台替它复验，闸门就是这条。"""
    cfg = dp.idp_client_config("https://x/oauth2/idpresponse")
    assert cfg["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    dp._assert_no_native_flows("idp-federation", cfg)      # 不得抛


def test_idp_pool_and_client_pass_botocore_param_validation():
    """参数形态按 service model 校验：拼错键名 / 类型的症状否则是真机上
    ParamValidationError，而那时平台池已经建好了。"""
    import botocore.session
    from botocore.validate import validate_parameters
    model = botocore.session.get_session().get_service_model("cognito-idp")
    validate_parameters(dp.idp_pool_config("acme-idp"),
                        model.operation_model("CreateUserPool").input_shape)
    params = dict(dp.idp_client_config("https://x/oauth2/idpresponse"),
                  UserPoolId="us-east-1_abc")
    validate_parameters(params,
                        model.operation_model("CreateUserPoolClient").input_shape)
```

> `test_client_configs_pass_botocore_param_validation`（约 line 320）里已有 `validate_parameters` 的用法，照它的 import 形态写。

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "idp_pool or idp_client"`
Expected: FAIL（`AttributeError: idp_pool_config`）

- [ ] **Step 3: 实现**

```python
# ---- 内置 IdP 池（[IdP] mode = cognito-admin，ADR 0006）------------------
#
# 平台池 vs 这个池的分工：平台池是**RP**（联邦到某个 IdP、发平台自己的 token），
# 这个池是**IdP**（真正存用户与密码，只许管理员建户）。两者的配置刻意不同：
#   · tier：平台池 ESSENTIALS（pre-token V2），这个池 LITE（不挂触发器）；
#   · 托管登录：平台池 managed login v2 + 必须套 branding，这个池 classic
#     hosted UI + **不需要** branding（LITE 拒 v2）；
#   · SupportedIdentityProviders：平台池刻意**不**列 COGNITO（否则暴露本地登录
#     入口，击穿 allowed_users="org"），这个池**只**列 COGNITO（它就是目录本身）。
# 每一项都在工单 06 的隔离池上实测过。
IDP_CLIENT_NAME = "platform-federation"


def idp_pool_config(pool_name: str) -> dict:
    """内置 IdP 池的 CreateUserPool 参数。

    `email` 的 `Required=True, Mutable=False` 是**"邮箱由身份源控制"的唯一实现点**
    ——app client 的 WriteAttributes 不是防线（显式给出时必须包含全部 Required
    属性，`["name"]` 被拒而 `["email","name"]` 反而被接受）。实测复验：
    Mutable=False 下连 admin_update_user_attributes 都报
    `user.email: Attribute cannot be updated.`。
    **代价**：建错邮箱只能删号重建，没有改的路（写进 DEPLOY.md）。

    schema 建后不可改 ⇒ 一个 email 可变的既有池**修不回来**，`_ensure_idp_pool`
    的读回复验会明说要删池重建。
    """
    return {
        "PoolName": pool_name,
        # LITE 够用：平台池要 ESSENTIALS 是为了 pre-token V2，这个池不挂触发器。
        # LITE 拒 managed login v2（FeatureUnavailableInTierException）⇒ 只有
        # classic hosted UI，实测 /login 直接 200 且带密码表单、无注册入口。
        "UserPoolTier": "LITE",
        "AutoVerifiedAttributes": ["email"],
        "UsernameAttributes": ["email"],
        "Schema": [{"Name": "email", "AttributeDataType": "String",
                    "Required": True, "Mutable": False}],
        # 与平台池同一条硬要求：只许管理员建户。
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "UserPoolTags": {"project": "site-builder", "managed_by": "deploy_pool.py",
                         "role": "idp-source"},
    }


def idp_client_config(platform_idpresponse: str) -> dict:
    """IdP 池里"给平台池联邦用"的 app client。

    platform_idpresponse 必须是**平台池托管域名的真实现值**拼出来的
    `/oauth2/idpresponse`，不是按配置前缀拼的——`_ensure_domain` 在池已有域名时
    沿用现值、忽略配置前缀，拼错的症状是最后一跳 `redirect_uri_mismatch`。

    **WriteAttributes 整个键不给**（见 idp_pool_config 的 docstring）。
    **ExplicitAuthFlows 必须显式给**：[] 被当成未指定 ⇒ SRP + CUSTOM 默认开着，
    可绕过 hosted UI 直接用 API 认证（工单 06 实测）。
    """
    return {
        "ClientName": IDP_CLIENT_NAME,
        "GenerateSecret": True,          # Cognito 作 OIDC RP 时要 client_secret
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": [platform_idpresponse],
        "SupportedIdentityProviders": ["COGNITO"],   # 这个池自己就是身份源
        "ReadAttributes": ["email", "email_verified", "name"],
        "ExplicitAuthFlows": list(NATIVE_AUTH_DISABLED),
    }
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): 内置 IdP 池与联邦 client 的参数生成（LITE / email 不可变 / 不给 WriteAttributes）"
```

---

### Task 4: 只读 AWS preflight（第 4/5 条分叉 fail closed）

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（紧跟 `_find_pool` 之后）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Consumes: `_find_pool(cog, name) -> str | None`（既有）
- Produces:
  - `_pool_id_for_domain(cog, prefix: str) -> str | None`
  - `preflight_idp_pool(cog, pool_name: str, domain_prefix: str) -> str | None`（返回已存在的 IdP 池 id，没有则 None）

- [ ] **Step 1: 写失败的用例**

```python
class _ReadOnlyCog:
    """只实现 preflight 需要的三个**读** API 的假 client。

    "preflight 不写"因此是**结构性**的：任何 create_* / update_* 调用会
    AttributeError，而不是靠人读代码确认。比 Stubber 更强的一点是它记录调用顺序，
    可以断言"读了哪几个、没读别的"。
    """

    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self, pools: dict, domains: dict):
        self._pools = pools            # {pool_name: {"Id":…, "Domain":…}}
        self._domains = domains        # {domain_prefix: pool_id}
        self.calls: list = []

    def list_user_pools(self, **kw):
        self.calls.append(("list_user_pools", kw))
        return {"UserPools": [{"Id": p["Id"], "Name": n}
                              for n, p in self._pools.items()]}

    def describe_user_pool(self, UserPoolId):
        self.calls.append(("describe_user_pool", UserPoolId))
        for p in self._pools.values():
            if p["Id"] == UserPoolId:
                return {"UserPool": dict(p)}
        raise self.exceptions.ResourceNotFoundException(UserPoolId)

    def describe_user_pool_domain(self, Domain):
        self.calls.append(("describe_user_pool_domain", Domain))
        pool_id = self._domains.get(Domain)
        # **实测形态**：不存在的前缀返回空的 DomainDescription，不抛异常
        return {"DomainDescription": {"UserPoolId": pool_id} if pool_id else {}}


def test_preflight_returns_none_when_nothing_exists_and_only_reads():
    cog = _ReadOnlyCog(pools={}, domains={})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") is None
    assert {c[0] for c in cog.calls} <= {"list_user_pools", "describe_user_pool",
                                         "describe_user_pool_domain"}


def test_preflight_returns_existing_pool_when_name_and_domain_agree():
    cog = _ReadOnlyCog(pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "acme-idp-2026"}},
                       domains={"acme-idp-2026": "us-east-1_a"})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") == "us-east-1_a"


def test_preflight_fails_closed_when_domain_belongs_to_another_pool():
    """判据 4：按名字与按域名前缀找到的**不是同一个池** ⇒ 停。

    继续往下跑的后果是把这个域名前缀当成"还没建"，于是 create_user_pool_domain
    对着别的池的前缀失败（或更糟：那个池是另一个环境的 IdP 池，而我们正准备把
    平台池的回调写到它的 client 上）。
    """
    cog = _ReadOnlyCog(pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "other-prefix"}},
                       domains={"acme-idp-2026": "us-east-1_b", "other-prefix": "us-east-1_a"})
    with pytest.raises(SystemExit, match="us-east-1_b"):
        dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026")


def test_preflight_fails_closed_when_named_pool_has_a_different_domain():
    """判据 5：按名字找到的池存在，但它的托管域名 ≠ 配置里的前缀 ⇒ 停。

    `_ensure_domain` 在池已有域名时**沿用现值、忽略配置前缀**，所以放它过去会得到
    "config 说 A、线上用 B"的静默漂移，而最后一跳的症状是 redirect_uri_mismatch
    （工单 06 的第 4 条 code-review 结论）。
    """
    cog = _ReadOnlyCog(pools={"acme-idp": {"Id": "us-east-1_a", "Domain": "legacy-prefix"}},
                       domains={"legacy-prefix": "us-east-1_a"})
    with pytest.raises(SystemExit, match="legacy-prefix"):
        dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026")


def test_preflight_allows_existing_pool_without_a_domain_yet():
    """池建好了但域名没建（上一次跑到一半中断）⇒ 这是可收敛的状态，不该拒。"""
    cog = _ReadOnlyCog(pools={"acme-idp": {"Id": "us-east-1_a"}}, domains={})
    assert dp.preflight_idp_pool(cog, "acme-idp", "acme-idp-2026") == "us-east-1_a"


def test_domain_lookup_treats_missing_and_not_found_alike():
    """两种"没有"都要当成 None：空 DomainDescription（实测形态）与
    ResourceNotFoundException（防御性，AWS 若改行为不至于把 preflight 打成崩溃）。"""
    cog = _ReadOnlyCog(pools={}, domains={})
    assert dp._pool_id_for_domain(cog, "nope") is None

    class _Raising(_ReadOnlyCog):
        def describe_user_pool_domain(self, Domain):
            raise self.exceptions.ResourceNotFoundException(Domain)

    assert dp._pool_id_for_domain(_Raising(pools={}, domains={}), "nope") is None
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "preflight or domain_lookup"`
Expected: FAIL（`AttributeError: preflight_idp_pool`）

- [ ] **Step 3: 实现**

```python
def _pool_id_for_domain(cog, prefix: str) -> str | None:
    """按托管域名前缀反查 pool id；查不到返回 None。

    **实测形态**：不存在的前缀不抛异常，而是返回**空的** DomainDescription。
    ResourceNotFoundException 也一并当成 None（防御性——若 AWS 改行为，preflight
    应当退化成"没查到"，而不是把整个部署打成崩溃）。

    注意效力边界：前缀是**跨账号全局唯一**的，被**别的账号**占用时这里同样返回
    None（我们看不见别人的池）。那种情形留给 create_user_pool_domain 报错——
    它的文案已经足够清楚，而 preflight 无法区分"没人用"与"别人在用"。
    """
    try:
        desc = cog.describe_user_pool_domain(Domain=prefix)
    except cog.exceptions.ResourceNotFoundException:
        return None
    return (desc.get("DomainDescription") or {}).get("UserPoolId") or None


def preflight_idp_pool(cog, pool_name: str, domain_prefix: str) -> str | None:
    """内置 IdP 池的**只读** preflight；返回已存在的池 id（没有则 None）。

    两条判据都 fail closed，且都在第一次 AWS **写**之前（工单 06 那个坑正是
    "池和域名都建好之后才炸"）：
      ④ 按名字与按域名前缀找到的不是同一个池 ⇒ 停。放它过去意味着我们要么对着
         别人的前缀建域名，要么把平台池的回调写进另一个环境的 IdP client。
      ⑤ 按名字找到的池已有托管域名但 ≠ 配置前缀 ⇒ 停。`_ensure_domain` 会沿用
         现值、忽略配置前缀，于是得到"config 说 A、线上用 B"的静默漂移，症状是
         登录最后一跳 redirect_uri_mismatch。
    """
    by_name = _find_pool(cog, pool_name)
    by_domain = _pool_id_for_domain(cog, domain_prefix)
    if by_domain and by_domain != by_name:
        raise SystemExit(
            f"[IdP] cognito_domain_prefix = {domain_prefix!r} 已被 pool {by_domain} 占用，"
            f"而按 cognito_user_pool_name = {pool_name!r} 找到的是 "
            f"{by_name or '（不存在）'}——两者不是同一个池，中止。"
            "两个键必须指向同一个 IdP 池（改配置，或先清理那个池的托管域名）。")
    if by_name:
        live = (cog.describe_user_pool(UserPoolId=by_name)["UserPool"] or {}).get("Domain")
        if live and live != domain_prefix:
            raise SystemExit(
                f"IdP pool {by_name}（{pool_name}）的托管域名是 {live!r}，而 config 写的是"
                f" {domain_prefix!r}，中止。托管域名建好后本脚本会沿用现值、忽略配置前缀"
                "，放行只会得到「config 说一个、线上用另一个」的静默漂移——症状是登录"
                "最后一跳 redirect_uri_mismatch。把 config 改成线上现值，或删掉那个域名。")
    return by_name
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): IdP 池的只读 preflight（池名与域名前缀不一致即 fail closed）"
```

---

### Task 5: IdP 池收敛（建池 → 托管域名 → 联邦 client → 读回复验）

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（`_ensure_domain` 加参数；`_ensure_pool` 之后插入三个函数）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Consumes: `idp_pool_config` / `idp_client_config`（Task 3）、`pool_update_params`、`_client_update_params`、`_assert_no_native_flows`、`_verify_no_native_flows`（既有）
- Produces:
  - `_ensure_domain(cog, pool_id, prefix, *, managed_login_version: int | None = MANAGED_LOGIN_V2) -> str`（**签名变化**，默认值保持既有行为）
  - `_ensure_idp_pool(cog, pool_name: str, existing: str | None) -> str`
  - `_verify_idp_pool_boundaries(cog, pool_id: str) -> None`
  - `_ensure_idp_pool_client(cog, idp_pool_id: str, platform_idpresponse: str) -> tuple[str, str]`（`(client_id, client_secret)`）

- [ ] **Step 1: 写失败的用例**

```python
def test_idp_domain_is_created_without_managed_login_version():
    """LITE 池只有 classic hosted UI：传 ManagedLoginVersion=2 会
    `FeatureUnavailableInTierException`（实测）。所以内置 IdP 池这条路必须
    **不带**这个参数——Stubber 按精确参数匹配，多传一个键就不匹配。"""
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": {"Id": "us-east-1_a"}},
                          {"UserPoolId": "us-east-1_a"})
        stub.add_response("create_user_pool_domain", {},
                          {"Domain": "acme-idp-2026", "UserPoolId": "us-east-1_a"})
        assert dp._ensure_domain(cog, "us-east-1_a", "acme-idp-2026",
                                 managed_login_version=None) == "acme-idp-2026"
        stub.assert_no_pending_responses()


def test_platform_domain_still_requests_managed_login_v2_by_default():
    """回归钉子：平台池那条路（默认参数）**必须**仍然传 v2。
    平台池是 managed login v2 + 必须套 branding，混成一条就是登录页不可用。"""
    import inspect
    sig = inspect.signature(dp._ensure_domain)
    assert sig.parameters["managed_login_version"].default == dp.MANAGED_LOGIN_V2


def test_ensure_idp_pool_creates_and_verifies_both_boundaries():
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("create_user_pool", {"UserPool": {"Id": "us-east-1_new"}},
                          dp.idp_pool_config("acme-idp"))
        stub.add_response("describe_user_pool", {"UserPool": {
            "Id": "us-east-1_new",
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            "SchemaAttributes": [{"Name": "email", "Mutable": False},
                                 {"Name": "name", "Mutable": True}]}},
                          {"UserPoolId": "us-east-1_new"})
        assert dp._ensure_idp_pool(cog, "acme-idp", None) == "us-east-1_new"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("live,match", [
    ({"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
      "SchemaAttributes": [{"Name": "email", "Mutable": False}]}, "自注册"),
    ({"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
      "SchemaAttributes": [{"Name": "email", "Mutable": True}]}, "重建"),
])
def test_idp_pool_boundaries_fail_closed(live, match):
    """两条边界各自都要红。

    email 可变那条**不可自愈**（schema 建后不能改），所以文案必须说"删池重建"
    ——否则采用者会以为幂等重跑能修好它，反复跑一个永远不满足前提的部署。
    """
    import boto3
    from botocore.stub import Stubber
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("describe_user_pool", {"UserPool": dict(live, Id="us-east-1_a")},
                          {"UserPoolId": "us-east-1_a"})
        with pytest.raises(SystemExit, match=match):
            dp._verify_idp_pool_boundaries(cog, "us-east-1_a")


def test_ensure_idp_pool_client_creates_with_secret():
    import boto3
    from botocore.stub import Stubber
    fake_secret = "FAKEidpclientsecretFAKEidpcs1"
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    idpresponse = "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients", {"UserPoolClients": []},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("create_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientSecret": fake_secret}},
                          dict(dp.idp_client_config(idpresponse),
                               UserPoolId="us-east-1_a"))
        assert dp._ensure_idp_pool_client(cog, "us-east-1_a", idpresponse) == \
            ("idpc1", fake_secret)
        stub.assert_no_pending_responses()


def test_ensure_idp_pool_client_unions_callbacks_on_update():
    """**回调取并集，绝不替换**（裁定 2 的第二半）。

    UpdateUserPoolClient 是整体替换，直接下发我们这一条会摘掉线上已登记的回调
    ——若那是另一个平台池的 idpresponse，那个环境的登录当场全断。沿用本仓库
    既有的先例（LogoutURLs 的注释：多一个已登记 URL 无害，少一个会报错）。
    """
    import boto3
    from botocore.stub import Stubber
    fake_secret = "FAKEidpclientsecretFAKEidpcs1"
    other = "https://other.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    mine = "https://plat.auth.us-east-1.amazoncognito.com/oauth2/idpresponse"
    cog = boto3.client("cognito-idp", region_name="us-east-1",
                       aws_access_key_id="t", aws_secret_access_key="t")
    with Stubber(cog) as stub:
        stub.add_response("list_user_pool_clients",
                          {"UserPoolClients": [{"ClientName": dp.IDP_CLIENT_NAME,
                                                "ClientId": "idpc1"}]},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientName": dp.IDP_CLIENT_NAME,
                                              "CallbackURLs": [other],
                                              "ExplicitAuthFlows":
                                                  ["ALLOW_REFRESH_TOKEN_AUTH"]}},
                          {"UserPoolId": "us-east-1_a", "ClientId": "idpc1"})
        stub.add_client_error("update_user_pool_client", service_error_code="X")
        with pytest.raises(Exception):
            dp._ensure_idp_pool_client(cog, "us-east-1_a", mine)
        # 断言点是**发出去的参数**：Stubber 记下了最后一次请求
        sent = stub.client.meta.events        # 占位；下一行才是真正的断言方式
    # 用捕获而不是 Stubber 的错误路径来读参数（_capture_update_params 是本文件既有的工具）
    cog2 = boto3.client("cognito-idp", region_name="us-east-1",
                        aws_access_key_id="t", aws_secret_access_key="t")
    captured = _capture_update_params(cog2)
    with Stubber(cog2) as stub:
        stub.add_response("list_user_pool_clients",
                          {"UserPoolClients": [{"ClientName": dp.IDP_CLIENT_NAME,
                                                "ClientId": "idpc1"}]},
                          {"UserPoolId": "us-east-1_a", "MaxResults": 60})
        stub.add_response("describe_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientName": dp.IDP_CLIENT_NAME,
                                              "CallbackURLs": [other],
                                              "ExplicitAuthFlows":
                                                  ["ALLOW_REFRESH_TOKEN_AUTH"]}},
                          {"UserPoolId": "us-east-1_a", "ClientId": "idpc1"})
        stub.add_response("update_user_pool_client",
                          {"UserPoolClient": {"ClientId": "idpc1",
                                              "ClientSecret": fake_secret}}, None)
        assert dp._ensure_idp_pool_client(cog2, "us-east-1_a", mine) == \
            ("idpc1", fake_secret)
    assert sorted(captured[0]["CallbackURLs"]) == sorted([other, mine])
```

> `_capture_update_params(cog)` 是本文件既有的工具（约 line 1057）——它挂 `before-parameter-build` 事件把参数抄下来。**先读它的实现再用**；上面那条用例的第一段（`add_client_error` 那几行）只是说明"不能靠错误路径读参数"，实现时**删掉它**，只留第二段。

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "idp_domain or idp_pool_client or idp_pool_boundaries or ensure_idp_pool"`
Expected: FAIL

- [ ] **Step 3: 实现**

`_ensure_domain` 加参数（只在两处分支上加判断，其余不动）：

```python
def _ensure_domain(cog, pool_id: str, prefix: str, *,
                   managed_login_version: int | None = MANAGED_LOGIN_V2) -> str:
    """建/纠正托管域名。

    **`ManagedLoginVersion` 属于 domain API，不是 client API**（既有注释保留）。

    `managed_login_version=None` 是**内置 IdP 池**那条路：LITE 档只有 classic
    hosted UI，传 2 会 `FeatureUnavailableInTierException`（实测），而 classic
    hosted UI **不需要** CreateManagedLoginBranding（实测 /login 200 且带密码表单）。
    平台池仍走默认值 v2 —— 那边"不套 branding 则登录页不可用"依然成立，
    两条别混。
    """
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    existing = pool.get("Domain")
    if not existing:
        kw = ({"ManagedLoginVersion": managed_login_version}
              if managed_login_version is not None else {})
        cog.create_user_pool_domain(Domain=prefix, UserPoolId=pool_id, **kw)
        print(f"  域名前缀 {prefix}"
              + (f"（managed login v{managed_login_version}）"
                 if managed_login_version is not None else "（classic hosted UI）"))
        return prefix

    desc = cog.describe_user_pool_domain(Domain=existing)
    version = desc.get("DomainDescription", {}).get("ManagedLoginVersion")
    if managed_login_version is None:
        print(f"  域名 {existing}（classic hosted UI，v{version}）")
        return existing
    if version != managed_login_version:
        ...   # 既有升级分支不变
```

三个新函数（放在 `_ensure_pool` 之后、`MANAGED_LOGIN_V2` 之前的位置无所谓，但要在 `_ensure_domain` 之后才被调用）：

```python
def _verify_idp_pool_boundaries(cog, pool_id: str) -> None:
    """读回复验内置 IdP 池的两条边界。

    这个池今天没有别的闸门替采用者复验（平台池那套 CDK 与 verify_* 都不覆盖它），
    所以两条都在这里硬断言：
      · AllowAdminCreateUserOnly —— 开着自注册 = 任何人自己造一个邮箱身份；
      · email 的 Mutable=False —— "邮箱由身份源控制"的唯一实现点。
    第二条**不可自愈**（schema 建后不能改），所以文案必须说删池重建。
    """
    pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    only_admin = pool.get("AdminCreateUserConfig", {}).get("AllowAdminCreateUserOnly")
    if only_admin is not True:
        raise SystemExit(
            f"IdP pool {pool_id} 的 AllowAdminCreateUserOnly={only_admin!r}——"
            "自注册未关闭，任何人都能自助注册出一个邮箱身份，"
            "「邮箱由身份源控制」不成立，中止")
    mutable = [a.get("Mutable") for a in pool.get("SchemaAttributes", [])
               if a.get("Name") == "email"]
    if mutable != [False]:
        raise SystemExit(
            f"IdP pool {pool_id} 的 email 属性 Mutable={mutable}，必须是 [False]。"
            "这是「邮箱不可自改」的唯一实现点，而 schema 在建池后**不能修改**"
            "——只能删掉这个池重建（改 [IdP] cognito_user_pool_name 换个名字也行）。中止")
    print("  ✓ 自注册已关闭、email 不可变（连管理员都改不了）")


def _ensure_idp_pool(cog, pool_name: str, existing: str | None) -> str:
    """幂等建/纠正内置 IdP 池；existing 由 preflight_idp_pool 给出。

    已存在时只纠正 AdminCreateUserConfig（唯一可自愈的那条边界），其余字段靠
    pool_update_params 原样回填——update_user_pool 是整体替换，手抄白名单会
    静默关掉威胁防护、短信配置与 tags（见那个函数的 docstring）。
    tier 不在这里纠正：LITE 与 ESSENTIALS 都能工作，它不是边界，只是成本。
    """
    if not existing:
        pool_id = cog.create_user_pool(**idp_pool_config(pool_name))["UserPool"]["Id"]
        print(f"  新建 IdP pool {pool_id}（LITE，只许管理员建户，email 不可变）")
    else:
        pool_id = existing
        print(f"  已存在 IdP pool {pool_id}，核对关键配置")
        pool = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        kwargs = pool_update_params(cog, pool)
        kwargs["AdminCreateUserConfig"] = \
            idp_pool_config(pool_name)["AdminCreateUserConfig"]
        cog.update_user_pool(UserPoolId=pool_id, **kwargs)
    _verify_idp_pool_boundaries(cog, pool_id)
    return pool_id


def _ensure_idp_pool_client(cog, idp_pool_id: str,
                            platform_idpresponse: str) -> tuple[str, str]:
    """幂等建/更新联邦用 app client；返回 (client_id, client_secret)。

    **secret 不持久化**：create / update 都回传 ClientSecret，幂等重跑能重取，
    所以它既不进 SSM 也不进 config.ini（少一份长期副本就少一处泄漏面）。

    **CallbackURLs 取并集，不替换**：UpdateUserPoolClient 是整体替换，直接下发
    我们这一条会摘掉线上已登记的回调——若那是另一个平台池的 idpresponse，
    那个环境的登录当场全断。多一个已登记 URL 无害（同 site client 的 LogoutURLs）。
    """
    existing = {}
    token = None
    while True:
        kw = {"NextToken": token} if token else {}
        resp = cog.list_user_pool_clients(UserPoolId=idp_pool_id, MaxResults=60, **kw)
        for c in resp.get("UserPoolClients", []):
            existing[c["ClientName"]] = c["ClientId"]
        token = resp.get("NextToken")
        if not token:
            break

    params = idp_client_config(platform_idpresponse)
    _assert_no_native_flows("idp-federation", params)
    client_id = existing.get(IDP_CLIENT_NAME)
    if client_id is None:
        desc = cog.create_user_pool_client(UserPoolId=idp_pool_id,
                                          **params)["UserPoolClient"]
        print(f"  新建 IdP client {desc['ClientId']}（{IDP_CLIENT_NAME}）")
    else:
        # CallbackURLs 交给下面并集处理，所以先不声明它
        desired = {k: v for k, v in params.items() if k != "CallbackURLs"}
        update = _client_update_params(cog, idp_pool_id, client_id, desired)
        update["CallbackURLs"] = sorted(
            set(update.get("CallbackURLs") or []) | set(params["CallbackURLs"]))
        desc = cog.update_user_pool_client(UserPoolId=idp_pool_id, ClientId=client_id,
                                          **update)["UserPoolClient"]
        print(f"  更新 IdP client {client_id}，回调 {update['CallbackURLs']}")
    secret = desc.get("ClientSecret", "")
    if not secret:
        raise SystemExit(
            f"IdP client {desc['ClientId']} 没有 client_secret——Cognito 作 OIDC RP "
            "必须有它，否则 provider 会在**用户登录时**才报 invalid_client。"
            f"删掉那个 client（{IDP_CLIENT_NAME}）让本脚本重建。")
    return desc["ClientId"], secret
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS（`test_domain_creation_requests_managed_login_v2` / `test_existing_domain_with_v1_is_upgraded` 两条既有用例必须仍绿）

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): IdP 池收敛（classic hosted UI 域名、联邦 client、两条边界读回复验、回调取并集）"
```

---

### Task 6: `_ensure_oidc_idp` 模式感知

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（`_ensure_oidc_idp`）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Produces:
  - `_ensure_oidc_idp(cog, pool_id, idp, *, mode: str = IDP_MODE_EXTERNAL) -> None`（**签名变化**，默认值保持既有行为）
  - `cognito_mode_idp(idp: dict, *, region: str, idp_pool_id: str, client_id: str, client_secret: str) -> dict`

- [ ] **Step 1: 写失败的用例**

```python
def test_cognito_mode_idp_derives_issuer_from_the_new_pool():
    """issuer 是池的 discovery 地址（不是托管域名）——托管域名只出现在 discovery
    文档里的三个端点上。写错这一条的症状是 create_identity_provider 就失败。"""
    out = dp.cognito_mode_idp(_idp_cognito(), region="us-east-1",
                              idp_pool_id="us-east-1_abc", client_id="c1",
                              client_secret="s1")
    assert out["issuer"] == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc"
    assert out["client_id"] == "c1"
    assert out["client_secret"] == "s1"
    assert out["provider_name"] == "CognitoSource"     # config 的值原样带过
    assert _idp_cognito().get("issuer") is None        # 不得改动入参


def test_cognito_mode_ignores_sb_idp_client_secret_env(monkeypatch):
    """**环境变量不许覆盖派生出来的 secret。**

    `SB_IDP_CLIENT_SECRET` 是 external-oidc 那条路的注入通道（让明文只活在子进程
    里）。内置模式下 secret 是本次运行刚从新建的 client 上读到的，如果环境里恰好
    留着上一条路的值，覆盖的后果是 provider 带着一个错的 secret 建成功、
    **到用户登录换 token 那一刻才报 invalid_client**。
    """
    monkeypatch.setenv("SB_IDP_CLIENT_SECRET", "STALEsecretfromanotherIdP0001")
    idp = dp.cognito_mode_idp(_idp_cognito(), region="us-east-1",
                              idp_pool_id="us-east-1_abc", client_id="c1",
                              client_secret="DERIVEDsecretFROMnewPOOL0001")
    captured = _captured_mapping_and_details(idp, mode=dp.IDP_MODE_COGNITO)
    assert captured["details"]["client_secret"] == "DERIVEDsecretFROMnewPOOL0001"


def test_external_mode_still_prefers_the_env_secret(monkeypatch):
    """回归钉子：external-oidc 那条路的注入通道不能被改坏
    （既有用例 test_idp_client_secret_can_come_from_env 也覆盖，这条锁"模式参数
    不影响它"）。"""
    monkeypatch.setenv("SB_IDP_CLIENT_SECRET", "ENVsecret0001")
    captured = _captured_mapping_and_details(_idp(client_secret="cfg"),
                                            mode=dp.IDP_MODE_EXTERNAL)
    assert captured["details"]["client_secret"] == "ENVsecret0001"


def test_cognito_mode_still_maps_email_verified():
    """内置池发 email_verified（建户时置 true），映射必须照常配上——
    平台侧 require_email_verified 默认 true，缺映射时该池所有登录都会被拒。"""
    idp = dp.cognito_mode_idp(_idp_cognito(), region="us-east-1",
                              idp_pool_id="us-east-1_abc", client_id="c1",
                              client_secret="s1")
    captured = _captured_mapping_and_details(idp, mode=dp.IDP_MODE_COGNITO)
    assert captured["mapping"] == {"email": "email", "name": "name",
                                   "email_verified": "email_verified"}
```

新增一个测试工具（放在既有的 `_captured_mapping` 旁边，并让既有的 `_captured_mapping`
复用它，避免两份 Stubber 样板）：

```python
def _captured_mapping_and_details(idp: dict, *, mode: str) -> dict:
    """跑一次 _ensure_oidc_idp 的 create 路径，抄下 ProviderDetails 与 AttributeMapping。

    照既有 `_captured_mapping` 的形态写（Stubber + ResourceNotFoundException 触发
    create 分支），只是把 details 也返回，并透传 mode。
    """
    ...
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "cognito_mode_idp or cognito_mode_ignores or external_mode_still_prefers or cognito_mode_still_maps"`
Expected: FAIL

- [ ] **Step 3: 实现**

```python
def cognito_mode_idp(idp: dict, *, region: str, idp_pool_id: str,
                     client_id: str, client_secret: str) -> dict:
    """把刚建好的内置 IdP 池派生成 `_ensure_oidc_idp` 认的那份 idp dict。

    issuer 是**池的 discovery 地址**（`https://cognito-idp.{region}.amazonaws.com/
    {poolId}`），不是托管域名——托管域名只出现在 discovery 文档里的
    authorize / token / userinfo 三个端点上（所以域名仍是必需的，见 _ensure_domain）。

    返回新 dict，不改入参（调用方还要用 config 的原值打印回填提示）。
    """
    return {**idp,
            "issuer": f"https://cognito-idp.{region}.amazonaws.com/{idp_pool_id}",
            "client_id": client_id,
            "client_secret": client_secret}
```

`_ensure_oidc_idp` 的 secret 取值段改成模式感知（其余一字不动）：

```python
def _ensure_oidc_idp(cog, pool_id: str, idp: dict, *,
                     mode: str = IDP_MODE_EXTERNAL) -> None:
    """联邦一个 OIDC IdP。飞书适配器、标准 IdP（Okta 等）与**内置 Cognito 池**
    走同一条路径。

    （既有的 email_verified 映射长注释保留，一字不改。）

    **secret 的来源随模式不同**：
      · external-oidc：环境变量 SB_IDP_CLIENT_SECRET 优先，其次 config
        （明文只活在子进程里；两者都缺时**部署期**退出——空 secret 建出的
        provider 只在用户登录换 token 那一刻才报 invalid_client）。
      · cognito-admin：secret 是本次运行刚从新建的 IdP client 上读到的，
        **绝不读环境变量**——环境里若留着另一条路的值，覆盖后果同样是
        "provider 建成功、登录才失败"。
    """
    name = idp["provider_name"]
    if mode == IDP_MODE_COGNITO:
        secret = str(idp.get("client_secret", "")).strip()
        if not secret:
            raise SystemExit(
                "内部不变量被破坏：cognito-admin 模式下 client_secret 应由 "
                "_ensure_idp_pool_client 派生。这不是配置问题，请检查 main() 的接线。")
    else:
        secret = os.environ.get("SB_IDP_CLIENT_SECRET", "").strip() \
            or idp.get("client_secret", "").strip()
        if not secret:
            sys.exit(...)      # 既有文案一字不改
    ...                        # details / mapping / create-or-update 分支不变
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS（既有的 6 条 `test_idp_*` 用例全绿——它们走默认 mode）

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): _ensure_oidc_idp 模式感知（内置模式的 secret 由本次派生，不读环境变量）"
```

---

### Task 7: `main()` 接线（⓿ preflight / ②b IdP 池 / 两个旗标 / 输出）+ 顺序守卫

**Files:**
- Modify: `site-builder/scripts/deploy_pool.py`（`main()`）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Consumes: Task 1/3/4/5/6 的全部产物
- Produces: `main()` 的新次序与两个新旗标（`--idp-pool-name` / `--idp-domain-prefix`）

- [ ] **Step 1: 写失败的用例（AST 顺序守卫 + 旗标存在性）**

```python
def test_main_runs_local_preflight_before_the_first_aws_write():
    """**次序是这条路的全部安全性所在**：本地 preflight → 只读 preflight → 第一次写。

    工单 06 那个坑正是"池和域名都建好之后才炸"（provider_name 填了保留名）。
    用 AST 抄出 main() 里的调用顺序，而不是 `in source` ——后者对"函数被调用了"
    成立，对"在写之前被调用"无话可说。
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(dp.main))
    called = [n.func.id if isinstance(n.func, ast.Name) else
              getattr(n.func, "attr", "") for n in ast.walk(tree)
              if isinstance(n, ast.Call)]
    order = {name: called.index(name) for name in
             ("idp_mode", "check_idp_section", "resolve_idp_pool_names",
              "preflight_idp_pool", "_ensure_pool") if name in called}
    for name in ("idp_mode", "check_idp_section", "resolve_idp_pool_names",
                 "preflight_idp_pool"):
        assert name in order, f"main() 没调用 {name}"
    assert "_ensure_pool" in order, "main() 没调用 _ensure_pool（本条空转）"
    for name in ("idp_mode", "check_idp_section", "resolve_idp_pool_names",
                 "preflight_idp_pool"):
        assert order[name] < order["_ensure_pool"], \
            f"{name} 排在 _ensure_pool（第一次 AWS 写）之后——preflight 失去意义"


def test_main_creates_the_idp_pool_after_the_platform_domain():
    """②b 必须在 ②（平台池托管域名）之后：IdP client 的回调要平台池托管域名的
    **真实现值**，而 _ensure_domain 在池已有域名时沿用现值、忽略配置前缀
    （拼错的症状是最后一跳 redirect_uri_mismatch）。
    同时它必须在 ③（建 provider）之前：provider 要 IdP 池的 issuer + secret。"""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(dp.main))
    called = [getattr(n.func, "id", getattr(n.func, "attr", ""))
              for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert called.index("_ensure_domain") < called.index("_ensure_idp_pool")
    assert called.index("_ensure_idp_pool") < called.index("_ensure_oidc_idp")
    assert called.index("_ensure_idp_pool_client") < called.index("_ensure_oidc_idp")


def test_main_has_the_two_idp_isolation_flags():
    """隔离旗标必须在 CLI 上（裁定 2）。默认 None ⇒ 生产运行时取 config 值。"""
    import ast
    import inspect
    src = inspect.getsource(dp.main)
    for flag in ("--idp-pool-name", "--idp-domain-prefix"):
        assert flag in src, f"main() 缺旗标 {flag}"
    assert ast.parse(src)          # 语法自检


def test_main_prints_the_two_admin_create_user_commands():
    """内置模式下脚本必须把建户那两条命令打出来（含真实 pool id）。

    少第二条（admin-set-user-password --permanent）的后果实测过：用户停在
    FORCE_CHANGE_PASSWORD，hosted UI 首登多一屏强制改密。裁定 3 决定建户不进
    脚本，那么"把命令递到手上"就是这条路唯一的降门槛手段。
    """
    import inspect
    src = inspect.getsource(dp.main)
    assert "admin-create-user" in src
    assert "admin-set-user-password" in src and "--permanent" in src
    assert "email_verified,Value=true" in src        # require_email_verified 的前提
    assert "SUPPRESS" in src
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "main_runs_local_preflight or main_creates_the_idp_pool or main_has_the_two or main_prints_the_two"`
Expected: FAIL

- [ ] **Step 3: 实现**

`main()` 的改动（其余段落一字不动）：

```python
    ap.add_argument("--pool-name", default=POOL_NAME,
                    help=f"user pool 名（默认 {POOL_NAME}；仅隔离 spike 时改）")
    # 内置 IdP 池的隔离旗标：默认取 config 的两个键。**--pool-name 隔离不到 IdP 池**
    # （它的名字来自 config），所以隔离运行时这两个必须显式给——否则会对生产 IdP
    # 池的 app client 做写操作，见 resolve_idp_pool_names。
    ap.add_argument("--idp-pool-name", default=None,
                    help="内置 IdP 池名（默认取 [IdP] cognito_user_pool_name）")
    ap.add_argument("--idp-domain-prefix", default=None,
                    help="内置 IdP 池的托管域名前缀（默认取 [IdP] cognito_domain_prefix）")
    args = ap.parse_args()

    import boto3
    cfg = _cfg()
    region = cfg["Platform"]["region"]
    base_domain = cfg["Platform"]["base_domain"]

    # ⓿ preflight。**纯本地判断放在建 boto3 client 之前**：工单 06 那个坑是
    # "池和托管域名都建好之后才炸"（provider_name 填了保留名），停在中途最难收拾。
    idp = dict(cfg["IdP"]) if cfg.has_section("IdP") else {}
    mode = idp_mode(idp)
    check_idp_section(idp, mode)
    idp_pool_name = idp_domain_prefix = ""
    if mode == IDP_MODE_COGNITO:
        idp_pool_name, idp_domain_prefix = resolve_idp_pool_names(
            pool_name=args.pool_name, idp_pool_name=args.idp_pool_name,
            idp_domain_prefix=args.idp_domain_prefix, idp=idp)
    print(f"⓿ preflight 通过（[IdP] mode = {mode}）")

    cog = boto3.client("cognito-idp", region_name=region)

    # 只读 preflight：仍在第一次写之前
    idp_pool_existing = None
    if mode == IDP_MODE_COGNITO:
        idp_pool_existing = preflight_idp_pool(cog, idp_pool_name, idp_domain_prefix)

    print(f"① user pool（禁自注册）: {args.pool_name}")
    pool_id = _ensure_pool(cog, base_domain, args.pool_name)

    print("② 托管域名")
    domain_prefix = _ensure_domain(cog, pool_id, args.domain_prefix)

    # ②b 内置 IdP 池。**必须在 ② 之后**：它的 client 要登记平台池托管域名的
    # /oauth2/idpresponse，而 ② 在池已有域名时沿用现值、忽略配置前缀。
    # **也必须在 ③ 之前**：provider 要这个池的 issuer + client secret。
    # 两个方向合起来 = 一趟做完，不需要跑两次（工单 06 第 11 条）。
    idp_pool_id = None
    if mode == IDP_MODE_COGNITO:
        print(f"②b 内置 IdP 池（mode = {IDP_MODE_COGNITO}）: {idp_pool_name}")
        platform_idpresponse = (
            f"https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse")
        idp_pool_id = _ensure_idp_pool(cog, idp_pool_name, idp_pool_existing)
        _ensure_domain(cog, idp_pool_id, idp_domain_prefix,
                       managed_login_version=None)
        idp_client_id, idp_client_secret = _ensure_idp_pool_client(
            cog, idp_pool_id, platform_idpresponse)
        # 这个池是本脚本建的，所以它也要过那道读回复验——手工建的池没有它，
        # 而"读回值看起来对、能力面其实是开的"正是最容易骗过人的地方（工单 06 Q4）。
        _verify_no_native_flows(cog, idp_pool_id,
                                {"idp-federation": idp_client_id})
        idp = cognito_mode_idp(idp, region=region, idp_pool_id=idp_pool_id,
                               client_id=idp_client_id,
                               client_secret=idp_client_secret)

    # ③ IdP 必须先建：client 的 SupportedIdentityProviders 要引用它的名字（既有注释保留）
    idp_name = None
    if _clean(idp.get("provider_name", "")):
        print("③ OIDC IdP 联邦")
        _ensure_oidc_idp(cog, pool_id, idp, mode=mode)
        idp_name = idp["provider_name"]
    else:
        print("③ 跳过 IdP 联邦（config.ini 无 [IdP] 段或 provider_name 为空）")
        ...     # 既有四行告警一字不动
```

> **注意**：③ 的判定从 `cfg.has_section("IdP") and cfg["IdP"].get("provider_name")` 换成
> `_clean(idp.get("provider_name", ""))`。两者对既有配置**同真值**（`has_section` 为假时
> `idp` 是空 dict），差别只有两点：`idp` 现在可能是派生过的（内置模式）；以及
> `provider_name = Feishu  # 生产` 这种带行内注释的值不再被当成"有值却建出一个名字里带
> 注释的 provider"——那本来就会被 Cognito 拒。

末尾输出（在既有的"回填 site-builder/config.ini"块之后）：

```python
    if mode == IDP_MODE_COGNITO:
        print(f"\n【内置 Cognito 模式】IdP 池 {idp_pool_id}")
        print("  issuer / client_id / client_secret 由本次部署派生，"
              "**不要**回填 config.ini（非空即报冲突）")
        print(f"  IdP 侧回调已自动登记：{platform_idpresponse}")
        print("\n  给第一个用户建号（两条都要——少第二条用户会停在 "
              "FORCE_CHANGE_PASSWORD，首登多一屏强制改密）：")
        print(f"    aws cognito-idp admin-create-user --region {region} \\")
        print(f"      --user-pool-id {idp_pool_id} --username <email> \\")
        print("      --user-attributes Name=email,Value=<email> "
              "Name=email_verified,Value=true Name=name,Value=<显示名> \\")
        print("      --message-action SUPPRESS")
        print(f"    aws cognito-idp admin-set-user-password --region {region} \\")
        print(f"      --user-pool-id {idp_pool_id} --username <email> \\")
        print("      --password '<初始密码>' --permanent")
        print("  email_verified=true 是平台侧 require_email_verified 能过的前提；"
              "SUPPRESS 表示不发邮件 ⇒ 初始密码要你自己交给用户。")
        print("  ⚠️  email 在 schema 层不可变 ⇒ **建错邮箱只能删号重建**，没有改的路。")
    elif idp_name:
        print(f"\n在 IdP（{idp_name}）侧把这个回调加进白名单：")
        print(f"  https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/idpresponse")
```

- [ ] **Step 4: 跑用例，确认通过**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q`
Expected: PASS。另跑一次编译自检：`python3 -m py_compile site-builder/scripts/deploy_pool.py`

- [ ] **Step 5: 提交**

```bash
git add site-builder/scripts/deploy_pool.py site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): main() 接线——⓿ preflight、②b 内置 IdP 池、两个隔离旗标、建户命令输出"
```

---

### Task 8: `config.ini.example` 的三个新键 + 模板自证 preflight

**Files:**
- Modify: `site-builder/config.ini.example`（`[IdP]` 段开头）
- Test: `site-builder/deployer/tests/test_deploy_pool.py`

**Interfaces:**
- Consumes: `idp_mode` / `check_idp_section`（Task 1）
- Produces: `.example` 的 `[IdP] mode` / `cognito_user_pool_name` / `cognito_domain_prefix`

- [ ] **Step 1: 写失败的用例**

```python
def _example_idp() -> dict:
    """出厂 `.example` 的 [IdP] 段，**裸 ConfigParser**（与生产同款：行内注释留在值里）。"""
    import configparser
    from pathlib import Path
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).resolve().parents[3] / "site-builder" / "config.ini.example")
    assert cfg.sections(), ".example 读空了——本条空转"
    return dict(cfg["IdP"])


def test_shipped_example_declares_the_three_mode_keys():
    idp = _example_idp()
    for key in ("mode", "cognito_user_pool_name", "cognito_domain_prefix"):
        assert key in idp, f".example 的 [IdP] 缺 {key}"


def test_shipped_example_passes_its_own_preflight():
    """**出厂模板必须过自己的 preflight。**

    这条比它看起来重要：`cognito_user_pool_name` 若出厂就带一个推荐值
    （`site-builder-idp`），而 mode 是 external-oidc ⇒ 判据③（两套字段混填）当场
    把每个采用者的第一次部署打红。所以两个 cognito_* 键出厂**必须为空**，
    推荐值只写在注释里。
    """
    idp = _example_idp()
    mode = dp.idp_mode(idp)
    assert mode == dp.IDP_MODE_EXTERNAL, ".example 的出厂模式必须是 external-oidc"
    dp.check_idp_section(idp, mode)          # 不得抛


def test_example_switched_to_cognito_admin_passes_preflight():
    """采用者按注释填完之后也必须过：把 mode 换成 cognito-admin、补两个键、
    清空三个派生字段——这就是 DEPLOY.md 第 3 条路要他做的全部编辑。"""
    idp = dict(_example_idp(), mode="cognito-admin", provider_name="CognitoSource",
               cognito_user_pool_name="site-builder-idp",
               cognito_domain_prefix="acme-idp-2026",
               issuer="", client_id="", client_secret="")
    assert dp.idp_mode(idp) == dp.IDP_MODE_COGNITO
    dp.check_idp_section(idp, dp.IDP_MODE_COGNITO)      # 不得抛


def test_example_mode_keys_have_no_inline_comments():
    """行内注释会被裸 ConfigParser 并进值 ⇒ `mode = cognito-admin  # 内置` 虽然被
    `_clean` 兜住了，但 cognito_user_pool_name 带注释就会拼出一个带空格与井号的
    池名。注释一律写在**上一行**（与 test_example_config_consistency 同一条纪律）。"""
    idp = _example_idp()
    for key in ("mode", "cognito_user_pool_name", "cognito_domain_prefix"):
        assert "#" not in idp[key] and ";" not in idp[key], f"{key} = {idp[key]!r}"
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py -q -k "example"`
Expected: FAIL（`.example 的 [IdP] 缺 mode`）

- [ ] **Step 3: 实现**

在 `site-builder/config.ini.example` 的 `[IdP]` 段**最前面**（`provider_name` 的注释块之前）插入：

```ini
[IdP]
# 身份源模式。两种取值，**键缺失时按 external-oidc**（存量 config.ini 无此键）：
#   external-oidc —— 你已有 OIDC IdP（Okta / Entra ID / Google / 飞书适配器…）。
#                    下面的 issuer / client_id / client_secret 由你填。
#   cognito-admin —— 让资产自己再建**第二个** Cognito 用户池充当 OIDC IdP：
#                    只许管理员建户、email 在 schema 层不可变（连管理员都改不了）。
#                    适用于「还没有任何 IdP」，零外部依赖。此模式下
#                    issuer / client_id / client_secret **必须留空**——它们由部署
#                    过程从新建的池派生，**非空即报冲突**（不会被静默忽略）。
#                    决策见 docs/adr/0006-*.md，操作见 DEPLOY.md §0 第 3 条路。
mode = external-oidc
# 下面两个键**只在 mode = cognito-admin 时填，且缺一不可**：
#   cognito_user_pool_name —— 那个 IdP 池的名字（建议 site-builder-idp）。
#                             幂等重跑靠它找回池，改名等于建一个新池。
#   cognito_domain_prefix  —— 它的托管域名前缀，**跨账号全局唯一**，可能被占用。
#                             必须建：issuer 的 discovery 文档里 authorize / token /
#                             userinfo 三个端点全部指向托管域名。
# 出厂留空是刻意的：external-oidc 下填了它们会被判成「两套模式混填」而拒。
cognito_user_pool_name =
cognito_domain_prefix =
```

（原有的 `provider_name` 注释块与其余键**一字不动**，只是排在这三个键之后。）

- [ ] **Step 4: 跑用例，确认通过**

Run:
```bash
cd site-builder/deployer && .venv/bin/pytest tests/test_deploy_pool.py tests/test_config_example_keys_are_read.py tests/test_example_config_consistency.py -q
```
Expected: PASS（`test_every_example_key_is_read_by_some_code` 靠 `dict(cfg["IdP"])` 的整段读取覆盖新键；`provider_name` 那条共享键配对不受影响）

- [ ] **Step 5: 提交**

```bash
git add site-builder/config.ini.example site-builder/deployer/tests/test_deploy_pool.py
git commit -m "feat(asset-v1/07): config.ini.example 的 [IdP] mode 与两个内置池键（出厂空值，注释独立成行）"
```

---

### Task 9: ADR 0006 与工单 07 的措辞订正 + 文档守卫

**Files:**
- Modify: `docs/adr/0006-built-in-cognito-admin-created-users-idp-mode.md`
- Modify: `.scratch/asset-v1/issues/07-cognito-admin-created-users-idp-mode.md`（gitignored，不进提交）
- Test: `site-builder/deployer/tests/test_delivery_docs_current.py`

**Interfaces:** 无代码接口。**决策没变，只修正实现机理 ⇒ 不需要 supersede，不开新 ADR。**

- [ ] **Step 1: 写失败的用例**

追加到 `site-builder/deployer/tests/test_delivery_docs_current.py`：

```python
ADR_0006 = ROOT / "docs" / "adr" / "0006-built-in-cognito-admin-created-users-idp-mode.md"


def test_adr_0006_names_the_real_email_immutability_mechanism():
    """ADR 0006 原文写的"应用客户端对 `email` 只读"**按字面做不出来**（工单 06 Q3
    实测）：显式给出的 WriteAttributes 必须包含全部 Required=True 属性，
    `["name"]` 被 InvalidParameterException 拒，而 `["email","name"]` 反而被接受。
    真正的实现点是用户池 schema 的 `Mutable=False`。

    ADR 是 accepted 状态的 tracked 决策文档，读它的人会照着实现 ⇒ 机理写错的代价
    是有人去配 WriteAttributes 并以为拿到了一条边界。**决策没变，所以不 supersede。**
    """
    doc = _read(ADR_0006)
    assert "Mutable" in doc, "ADR 0006 没点名 schema 的 Mutable=False（真实实现点）"
    assert "邮箱属性对应用客户端不可写" not in doc, \
        "ADR 0006 还留着按字面做不出来的那句措辞"
    # 提到 WriteAttributes 时必须是"它不是防线"的意思
    for i, line in enumerate(doc.splitlines()):
        if "WriteAttributes" in line:
            assert "不是" in line, f"ADR 0006:{i + 1} 把 WriteAttributes 说成了防线"


def test_adr_0006_no_longer_says_the_mode_is_unimplemented():
    """模式已落地 ⇒ "待实现"是过时口径（否定断言覆盖整份文件）。"""
    doc = _read(ADR_0006)
    for stale in ("待实现", "07 实现"):
        assert stale not in doc, f"ADR 0006 还写着 {stale!r}"
```

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q -k adr_0006`
Expected: FAIL（`ADR 0006 还留着按字面做不出来的那句措辞`）

- [ ] **Step 3: 改 ADR 0006**

正文第 9-11 行改成（`（**待实现**，工单 06 探路、07 实现）` 整段删掉）：

```markdown
IdP 客户端"是首次部署最大的门槛。决定：`deploy_pool.py` 增加一个可选模式
（`[IdP] mode = cognito-admin`），再建**第二个** Cognito 用户池充当 OIDC IdP
——只允许管理员建户，并在该用户池的 **schema 层**把 `email` 设为必填且不可变
（`Required=True, Mutable=False`）——平台池照常以 OIDC 联邦接入它。平台代码零改动，
"邮箱由身份源控制"的硬要求由第二个池的配置满足，而不是放松平台池。
```

在 `## Consequences` 里追加三条：

```markdown
- **app client 的 `WriteAttributes` 不是邮箱不可变性的安全边界**：显式给出该字段时
  Cognito 要求它包含全部 `Required=True` 属性（排除 `email` 会被
  `InvalidParameterException` 拒，显式列出 `email` 反而被接受）。边界由用户池 schema 的
  `Mutable=False` 提供——实测连 `admin-update-user-attributes` 都报
  `user.email: Attribute cannot be updated.`。代价是**邮箱建错或需变更时只能删号重建**。
- schema 在建池后不可修改 ⇒ 一个 `email` 可变的既有池修不回来，`deploy_pool.py` 的读回
  复验会明说要换池名或删池重建。
- 内置模式还有一条原先没写出来的理由：`ProviderType=OIDC` + issuer
  `https://accounts.google.com` 在**协议层**就是社交登录，Amazon 内部（Isengard 注册的）
  账号里会触发 CloudSecurity 的 "Cognito Must Not Use Social Identity Providers"
  检查（按用途判，改 provider 名不能绕过）。三条身份路径里只有 Google 那条有这个问题。
```

- [ ] **Step 4: 改工单 07 正文（gitignored，不进提交）**

把 `**What to build:**` 那段里的「应用客户端对 `email` 只读」改成：

```
在该用户池的 schema 层把 `email` 设为 `Required=True, Mutable=False`
（app client 的 `WriteAttributes` **不是**防线——实现上整个键不传）
```

并把 `[IdP] mode = cognito-managed 之类` 改成 `[IdP] mode = cognito-admin`。

- [ ] **Step 5: 跑用例，确认通过 + 提交**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q`
Expected: PASS

```bash
git add docs/adr/0006-built-in-cognito-admin-created-users-idp-mode.md \
        site-builder/deployer/tests/test_delivery_docs_current.py
git commit -m "docs(asset-v1/07): ADR 0006 订正邮箱不可变性的实现机理（schema Mutable=False，非 WriteAttributes）"
```

---

### Task 10: DEPLOY.md —— 第 3 条路从"手工建"改成"脚本建"

**Files:**
- Modify: `site-builder/DEPLOY.md`（四处：§0 的提示块、【内置 Cognito】小节、就绪清单第 3 条、① 步骤 1）
- Test: `site-builder/deployer/tests/test_delivery_docs_current.py`

**Interfaces:** 无代码接口。**新增散文必须 status-free**（不写日期 / 进度 / "现在到哪了"——`test_status_free_docs_carry_no_environment_status` 覆盖 DEPLOY.md）。

- [ ] **Step 1: 写失败的用例**

```python
BUILT_IN_COGNITO_HEADING = "### 【内置 Cognito】第二个池的确切形态"


def test_deploy_md_built_in_cognito_path_is_scripted_not_manual():
    """第 3 条路的门槛就是这一节：它必须给出**配置 + 一条命令**，而不是一串
    aws cognito-idp create-* 让采用者手工建池。"""
    doc = _read(DEPLOY)
    sec = _section(doc, BUILT_IN_COGNITO_HEADING)      # 标题改名时自报空转
    assert "mode = cognito-admin" in sec
    assert "cognito_user_pool_name" in sec and "cognito_domain_prefix" in sec
    assert "deploy_pool.py" in sec, "这一节没告诉读者是哪个脚本建的"
    # 三个派生字段不许再出现在"要填的 [IdP]"清单里
    for derived in ("issuer =", "client_id ="):
        assert f"{derived} <" not in sec, \
            f"这一节还在让采用者填 {derived}——内置模式下它由部署过程派生"
    # 否定断言覆盖整份文件：占位口径不许残留在任何地方
    for stale in ("目前依赖工单 07", "尚未落地", "在那之前按本节手工建"):
        assert stale not in doc, f"DEPLOY.md 还留着占位口径 {stale!r}"


def test_deploy_md_keeps_the_two_admin_create_user_commands():
    """建户不进脚本（裁定 3）⇒ 手册必须留这两条，且必须带 --permanent
    与 email_verified=true——少第二条用户停在 FORCE_CHANGE_PASSWORD，
    少 email_verified 则 require_email_verified 把他挡在 /callback。"""
    sec = _section(_read(DEPLOY), BUILT_IN_COGNITO_HEADING)
    assert "admin-create-user" in sec
    assert "admin-set-user-password" in sec and "--permanent" in sec
    assert "email_verified,Value=true" in sec
    assert "SUPPRESS" in sec


def test_deploy_md_readiness_for_built_in_cognito_is_config_only():
    """就绪清单是**开始部署前**的检查。内置模式下"第二个池"是 ① 建出来的产物，
    所以这一条的前置只能是配置 + 前缀可用，不能要求池已存在
    （旧文案要求"第二个池 + 托管域名 + app client 已建"，那是手工时代的口径）。"""
    doc = _read(DEPLOY)
    sec = _section(doc, "开始前的就绪清单（详见上面 §0）")
    line = [ln for ln in sec.splitlines() if "【内置 Cognito】" in ln]
    assert line, "就绪清单里没有【内置 Cognito】那一条（本条空转）"
    joined = "\n".join(sec.splitlines())
    assert "mode = cognito-admin" in joined
    assert "第二个池 + 托管域名 + app client 已建" not in joined
```

> `_section(doc, "开始前的就绪清单（详见上面 §0）")` 的第二个参数必须与文档里那一行**逐字符相同**；那一行不是 markdown 标题，所以实现时改用 `doc` 的切片方式（照 `test_deploy_md_readiness_lists_the_alert_recipient` 的既有写法）。

- [ ] **Step 2: 跑用例，确认失败**

Run: `cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q -k "built_in_cognito or admin_create_user or readiness_for_built_in"`
Expected: FAIL

- [ ] **Step 3: 改 DEPLOY.md**

**(a) §0 的提示块**（现在的"> **第 3 条路（内置 Cognito）目前依赖工单 07**…"整块）替换成：

```markdown
> **第 3 条路只需要三行配置 + 那条 `deploy_pool.py`**：填 `[IdP] mode = cognito-admin`
> 与 `cognito_user_pool_name` / `cognito_domain_prefix`，① 阶段的 `deploy_pool.py`
> 会在**同一次运行**里把第二个池、它的托管域名与联邦 app client 一起建出来，并把
> 平台池的 `/oauth2/idpresponse` 自动登记为回调（IdP 侧不用你手工填任何东西）。
> 池建好后用两条 `aws cognito-idp` 命令建第一个用户，见下面「【内置 Cognito】」一节。
> 可行性与每一项配置的理由都在那一节里；决策见 `docs/adr/0006-*.md`。
```

**(b)【内置 Cognito】小节**：把开头那句 `> deploy_pool.py 的模式开关属于工单 07，尚未落地。在那之前按本节手工建。` 换成：

```markdown
**怎么做**：填三行配置，跑 ① 的 `deploy_pool.py`。

```ini
# site-builder/config.ini
[IdP]
mode = cognito-admin
provider_name = CognitoSource          # 自取；同一个值要加进 router 的 trusted_idps
cognito_user_pool_name = site-builder-idp
cognito_domain_prefix = <全局唯一前缀>
# issuer / client_id / client_secret **留空**——由部署过程从新建的池派生，非空即报冲突
scopes = openid email profile
map_email_verified = true
require_email_verified = true
```

```bash
python3 site-builder/scripts/deploy_pool.py     # ①；②b 那一步就是这个池
```

脚本在**第一次 AWS 写之前**会拒掉这些配置错误：未知 `mode`、两套模式字段混填、
`provider_name` 是四个社交保留名之一、按池名与按域名前缀找到的不是同一个池、
按池名找到的池已有一个**不同**的托管域名。建完还会读回复验两条边界
（自注册已关、`email` 不可变）与那个 client 的 `ExplicitAuthFlows`。

下面这张表是脚本建出来的形态；列在这里是为了让你知道每条边界靠什么成立，
**以及在别处看到一个手工建的池时怎么核对它**。
```

表格与其后的读回核对命令、`ExplicitAuthFlows` 陷阱、`WriteAttributes` 那段
**全部保留**（它们现在的角色是"核对与理由"，不是"操作步骤"），但把
「**建完池就读回核对这两项**（手工建的池没有脚本替你复验…）」的括号改成
「（脚本已经复验过；这两条命令给你自己核对，或核对别人手工建的池用）」，
把 `ExplicitAuthFlows` 那段的「**建完必须读回核对**（这个池是手工建的，没有脚本替你复验）」
同样改成「脚本已复验；下面这条命令供你自己核对」。

「**回填平台池的 `[IdP]` 段**」那个 ini 块换成上面 (b) 的那份（三个派生字段留空）。

**(c) 就绪清单第 3 条**（`/ **3【内置 Cognito】** …` 那三行）替换成：

```markdown
      / **3【内置 Cognito】** `[IdP] mode = cognito-admin` + `cognito_user_pool_name`
      / `cognito_domain_prefix` 已填，且那个域名前缀（跨账号全局唯一）没被占用
      ——池本身由 ① 的 `deploy_pool.py` 建；建完再用两条 `aws cognito-idp`
      命令建第一个用户（见 §0）
```

**(d) ① 步骤 1**（`1. **身份层用脚本建，不要手工建 pool**` 那段）在既有 `client_secret` 注入
说明之后插入一段：

```markdown
   **【内置 Cognito】** `[IdP] mode = cognito-admin` 时**不需要** `client_secret`
   （也不需要 `issuer` / `client_id`）：同一次运行的 ②b 步会建出第二个池、它的
   托管域名（classic hosted UI，LITE 档不支持 managed login v2，也不需要 branding）
   与联邦 app client，然后从那个 client 上取 secret 直接建 provider。
   secret **不落任何地方**（不进 SSM、不进 config.ini）——幂等重跑会重新取。
   跑完照脚本末尾打印的那两条 `aws cognito-idp` 命令建第一个用户。
```

- [ ] **Step 4: 跑用例，确认通过**

Run:
```bash
cd site-builder/deployer && .venv/bin/pytest tests/test_delivery_docs_current.py -q
```
Expected: PASS。特别注意这几条既有守卫必须仍绿：`test_status_free_docs_carry_no_environment_status`、
`test_deploy_md_does_not_document_config_keys_that_nothing_reads`、
`test_delivery_docs_mark_every_undistributed_doc_pointer`、
`test_deploy_md_acceptance_set_lists_exactly_the_distributed_gates`。

- [ ] **Step 5: 提交**

```bash
git add site-builder/DEPLOY.md site-builder/deployer/tests/test_delivery_docs_current.py
git commit -m "docs(asset-v1/07): DEPLOY.md 第 3 条路改成脚本化（三行配置 + deploy_pool.py），保留手工核对命令"
```

---

### Task 11: 七套件 + `external-oidc` 回归（单测层）

**Files:** 无改动（只跑）。发现红就回到对应任务。

- [ ] **Step 1: 顺序跑七套件（别并行）**

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

(cd site-builder/contract && .venv/bin/pytest tests -q)
(cd site-builder/auth && ../contract/.venv/bin/pytest tests -q)
(cd router/infrastructure/lambda && ../../../site-builder/deployer/.venv/bin/pytest . -q)
(cd site-builder/deployer && .venv/bin/pytest tests -q)
(cd site-builder/mcp && python3 -m pytest tests -q)
(cd site-builder/panel && ../deployer/.venv/bin/pytest tests -q)
(cd site-builder/key-proxy && ../deployer/.venv/bin/pytest tests -q)
```

Expected: 七套全绿。两条已知假红先重跑再判断：`contract` 的墙钟哨兵（3000 组 decode
必须 10 秒内，重负载下实测被拖到 13.6 秒）；`mcp` 那条在宿主没装 pytest 时报
`No module named pytest`（改用 `site-builder/mcp/run_locked_tests.sh`）。

- [ ] **Step 2: `external-oidc` 回归的逐项核对（读代码 + 用例，不连 AWS）**

**本票最大的风险面是它，不是新模式**——改的是生产在用的那条代码路径。逐项确认，
每条都指向一个具体的用例或 diff 位置：

| # | 不变量 | 证据 |
|---|---|---|
| 1 | 无 `[IdP]` 段 ⇒ 跳过联邦 + 四行告警，已存在的 client 保留线上 provider 名单 | `test_clients_fall_back_to_cognito_only_without_idp`、`test_update_without_idp_config_preserves_live_federation`、`test_update_path_omits_provider_key_entirely_without_idp` |
| 2 | `[IdP]` 段存在但 `provider_name` 为空 ⇒ 同上（**不报错**） | `test_external_mode_with_empty_provider_name_is_not_an_error` + `main()` ③ 分支的 diff |
| 3 | `provider_name` 有值 ⇒ site/mcp 只列该 IdP，不含 COGNITO | `test_production_clients_exclude_local_cognito_users`、`test_create_with_idp_config_lists_only_that_idp` |
| 4 | `ProviderDetails` 五个键与 `AttributeMapping` 三个键不变 | `test_idp_maps_email_verified_by_default`、`test_idp_email_verified_mapping_can_be_disabled`、`test_idp_mapping_applies_on_update_path_too` |
| 5 | `SB_IDP_CLIENT_SECRET` 优先于 config；两者都缺时**部署期**退出 | `test_idp_client_secret_can_come_from_env`、`test_idp_missing_client_secret_fails_loudly`、`test_external_mode_still_prefers_the_env_secret` |
| 6 | 平台池 tier / 自注册 / 域名 v2 / branding 四项不变 | `test_pool_config_requires_essentials_tier`、`test_pool_config_disables_self_signup`、`test_domain_creation_requests_managed_login_v2`、`test_platform_domain_still_requests_managed_login_v2_by_default` |
| 7 | site/mcp 的四个 TTL、`ExplicitAuthFlows`、`EnableTokenRevocation` / `PreventUserExistenceErrors` 的 read-modify-write 保留 | `test_refresh_token_validity_is_capped`、`test_access_token_validity_is_capped`、`test_clients_disable_all_native_auth_flows`、`test_client_update_preserves_unmanaged_hardening` |
| 8 | `--pool-name` 的三层隔离（池名 / 触发器函数名 / SSM 前缀）不变 | `test_spike_pool_secrets_go_to_isolated_ssm_prefix`、`test_spike_pool_does_not_overwrite_production_pre_token_lambda`、`test_default_pool_name_is_production_pool` |
| 9 | ⑧ 不写 IdP client 的 secret 到 SSM | `_store_client_secrets` 的调用点未变（`git diff` 里 ⑧ 那段零改动） |
| 10 | machine client 只有 `ExplicitAuthFlows` 一个字段变（Task 2；若 Task 2 被否决则**零变化**） | `git diff site-builder/scripts/deploy_pool.py` 的 machine 段 |

```bash
git diff --stat HEAD~<本票提交数> -- site-builder/scripts/deploy_pool.py
git diff HEAD~<本票提交数> -- site-builder/scripts/deploy_pool.py | grep -n '^-' | grep -v '^-\{3\}'
# ↑ 逐行看**删掉**了什么。external-oidc 的回归风险全在删除与改写行上，新增行不改变旧路径。
```

- [ ] **Step 3: 记录结果，不提交**（本任务无产物；红就回到对应任务）

---

### Task 12: 隔离池真机验证（两条腿 + 清理）

**Files:** 无仓库改动。过程文件一律落 `.scratch/asset-v1/07/`（gitignored，含真实值的一律 `chmod 600`）。

**前提**：`aws sts get-caller-identity` 指向验证账号 / `us-east-1`；`python3` ≥ 3.10 且装了
`boto3` / `pip-system-certs`。**生产池 `site-builder-users` 全程零改动**——两条腿都用
`--pool-name` + 两个 `--idp-*` 旗标隔离，且 `[IdP]` 的临时改动由 `.scratch/` 下的一次性
runner 以 try/finally 备份 → 打补丁 → 跑 → 还原并**核对字节相等**（照抄
`.scratch/asset-v1/idp-spike/run_deploy_pool.py`）。

- [ ] **Step 1: 腿 A —— `external-oidc` 回归（真机）**

用工单 06 留下的 Google OAuth client（`.scratch/asset-v1/idp-spike/idp-google.ini`，
GCP 侧按 Kent 的决定保留着，**两条 redirect URI 都还登记着**）。
**平台隔离池的托管域名前缀仍用 `sb-idp-spike-2026`** ⇒ GCP 侧一个字都不用改。

```bash
cd "$(git rev-parse --show-toplevel)"
# runner 从 .scratch/asset-v1/idp-spike/run_deploy_pool.py 复制过来改，改动只有两处：
#   ① 补丁源换成 idp-google.ini（external-oidc 形态，mode 键**故意不写**——顺带
#      验证"键缺失 ⇒ external-oidc"这条回落；
#   ② 命令加 --pool-name sb-idp-spike --domain-prefix sb-idp-spike-2026
python3 .scratch/asset-v1/07/run_deploy_pool_external.py
```

逐项核对（判据是**读回来的线上值**，不是脚本输出）：

```bash
POOL=<隔离池 id>
aws cognito-idp describe-identity-provider --region us-east-1 \
  --user-pool-id "$POOL" --provider-name GoogleOIDC \
  --query '{details: IdentityProvider.ProviderDetails, mapping: IdentityProvider.AttributeMapping}'
# 期望 details 五个键（client_id / client_secret / attributes_request_method=GET /
#      oidc_issuer / authorize_scopes）、mapping 三个键（email / name / email_verified）
for C in <site_client_id> <mcp_client_id>; do
  aws cognito-idp describe-user-pool-client --region us-east-1 \
    --user-pool-id "$POOL" --client-id "$C" \
    --query 'UserPoolClient.{idps: SupportedIdentityProviders, flows: ExplicitAuthFlows,
             at: AccessTokenValidity, it: IdTokenValidity, rt: RefreshTokenValidity,
             rev: EnableTokenRevocation, pue: PreventUserExistenceErrors}'
done
# 期望 idps == ["GoogleOIDC"]（不含 COGNITO）、flows == ["ALLOW_REFRESH_TOKEN_AUTH"]、
#      15 / 15 / 1、rev == true、pue == ENABLED
```

`[ApiKey]` 段存在 ⇒ 这一趟同时会建出 machine client。**这就是 Task 2 的真机证据**：

```bash
aws cognito-idp describe-user-pool-client --region us-east-1 \
  --user-pool-id "$POOL" --client-id <machine_client_id> \
  --query 'UserPoolClient.{flows: ExplicitAuthFlows, oauth: AllowedOAuthFlows}'
# 期望 flows == ["ALLOW_REFRESH_TOKEN_AUTH"]、oauth == ["client_credentials"]
# ⇒ 证明 Cognito 接受 client_credentials client 带 ALLOW_REFRESH_TOKEN_AUTH
```

- [ ] **Step 2: 腿 B —— `cognito-admin` 全链路（真机）**

```bash
python3 .scratch/asset-v1/07/run_deploy_pool_builtin.py
#   补丁：mode = cognito-admin / provider_name = SbIdpSource /
#         cognito_user_pool_name、cognito_domain_prefix 留空（**靠旗标给**，
#         顺带验证"旗标优先于 config"与"隔离运行必须给旗标"）
#   命令：deploy_pool.py --pool-name sb-idp-spike --domain-prefix sb-idp-spike-2026 \
#           --idp-pool-name sb-idp-source --idp-domain-prefix sb-idp-source-2026
```

负向先做（**都不该产生任何 AWS 写**，逐条确认退出码非 0 且没建出资源）：

```bash
# ① 少一个旗标
python3 site-builder/scripts/deploy_pool.py --pool-name sb-idp-spike \
  --domain-prefix sb-idp-spike-2026 --idp-pool-name sb-idp-source ; echo "exit=$?"
# ② 保留名（临时把 provider_name 改成 Google）
# ③ 混填（临时给 issuer 一个值）
# ④ 域名前缀指向另一个池（临时把 --idp-domain-prefix 改成平台隔离池的前缀）
```

正向做完后核对：

```bash
IDP=<IdP 池 id>
aws cognito-idp describe-user-pool --region us-east-1 --user-pool-id "$IDP" \
  --query '{tier: UserPool.UserPoolTier,
            selfSignupClosed: UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly,
            emailImmutable: UserPool.SchemaAttributes[?Name==`email`].Mutable | [0],
            domain: UserPool.Domain}'
# 期望 {"tier":"LITE","selfSignupClosed":true,"emailImmutable":false,"domain":"sb-idp-source-2026"}
aws cognito-idp describe-user-pool-client --region us-east-1 --user-pool-id "$IDP" \
  --client-id <idp_client_id> \
  --query 'UserPoolClient.{flows: ExplicitAuthFlows, cb: CallbackURLs,
           read: ReadAttributes, write: WriteAttributes}'
# 期望 flows == ["ALLOW_REFRESH_TOKEN_AUTH"]、cb 只含平台隔离池的 /oauth2/idpresponse、
#      write 是 null（**整个键没给**）
curl -s "https://cognito-idp.us-east-1.amazonaws.com/$IDP/.well-known/openid-configuration" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["issuer"]); \
                print({k:d[k] for k in ("authorization_endpoint","token_endpoint","userinfo_endpoint")})'
# 期望三个端点都指向 sb-idp-source-2026.auth.us-east-1.amazoncognito.com
```

**幂等复跑一次同一条命令**：期望零新建、输出全是"已存在 / 更新"，且上面每项读回值不变。

管理员建户（用脚本末尾打印的那两条命令，邮箱用一个不在生产池里的地址）：

```bash
aws cognito-idp admin-create-user ...   # 见脚本输出
aws cognito-idp admin-set-user-password ... --permanent
# 复验 email 不可变（**期望失败**）：
aws cognito-idp admin-update-user-attributes --region us-east-1 --user-pool-id "$IDP" \
  --username <email> --user-attributes Name=email,Value=attacker@example.invalid
# 期望 InvalidParameterException: user.email: Attribute cannot be updated.
```

浏览器登录 + **真实生产函数**验 claim（照 `.scratch/asset-v1/idp-spike/probe_login.py` 的手法；
它顶部那四个常量 `POOL_ID` / `SITE_CLIENT_ID` / `COGNITO_DOMAIN` / `SECRET_PARAM` 要换成
这次隔离池的值）：

```bash
cp .scratch/asset-v1/idp-spike/probe_login.py .scratch/asset-v1/07/probe_login.py
# 改四个常量 → 打印 authorize URL → 浏览器登录（用刚建的用户与初始密码）
python3 .scratch/asset-v1/07/probe_login.py url
python3 .scratch/asset-v1/07/probe_login.py exchange --code <浏览器地址栏里的 code>
```

**判据**：`login_handler._exchange_code`（`REQUIRE_EMAIL_VERIFIED=True`）返回的 dict 里
`email` 是刚建的那个地址、`idp == "SbIdpSource"`、`auth_via == "TokenGeneration_HostedAuth"`、
`name` 是建户时给的显示名。**首登不应出现强制改密屏**（`--permanent` 生效的证据）。

- [ ] **Step 3: 清理并复核**

```bash
# 顺序：先删 IdP 池的托管域名与池，再删平台隔离池（provider 随池消失）
aws cognito-idp delete-user-pool-domain --region us-east-1 --user-pool-id "$IDP" --domain sb-idp-source-2026
aws cognito-idp delete-user-pool --region us-east-1 --user-pool-id "$IDP"
aws cognito-idp delete-user-pool-domain --region us-east-1 --user-pool-id "$POOL" --domain sb-idp-spike-2026
aws cognito-idp delete-user-pool --region us-east-1 --user-pool-id "$POOL"
aws lambda delete-function --region us-east-1 --function-name site-auth-pre-token-spike-sb-idp-spike
aws ssm delete-parameters --region us-east-1 \
  --names /site-builder-spike/sb-idp-spike/site-client-secret \
          /site-builder-spike/sb-idp-spike/machine-client-secret

# 复核：spike 零残留，生产三样都在
aws cognito-idp list-user-pools --region us-east-1 --max-results 60 \
  --query 'UserPools[?contains(Name, `sb-idp`)].[Name,Id]'            # 期望 []
aws cognito-idp list-user-pools --region us-east-1 --max-results 60 \
  --query 'UserPools[?Name==`site-builder-users`].[Name,Id]'          # 期望 1 条
aws lambda get-function --region us-east-1 --function-name site-auth-pre-token \
  --query 'Configuration.FunctionName'                                # 期望存在
aws ssm get-parameter --region us-east-1 --name /site-builder/site-client-secret \
  --query 'Parameter.Name'                                            # 期望存在（不取值）
# config.ini 与动手前**字节相等**（runner 的 finally 已还原，这里是复核）
git status --porcelain site-builder/config.ini router/config.ini       # 期望空（两份都 gitignored，本行只防误改被跟踪文件）
python3 - <<'EOF'
import hashlib, pathlib
for p in ("site-builder/config.ini", "router/config.ini"):
    print(p, hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()[:12])
EOF
# ↑ 与动手前 runner 记下的同一个前缀比对
```

> **不需要**为这次隔离池实验给 `verify_account_trust_boundary.py` 做任何声明：那个闸门的
> principal 来自 `GetAccountAuthorizationDetails`，而这次不新建 IAM principal（spike 的
> pre-token Lambda 复用现成的 `site-auth-service-role`），它模拟的资源清单也是按 config
> 固定的（工单 06 已核实过这一点）。

- [ ] **Step 4: 把实测结果写进工单 07 的 Comments**（gitignored；含真实池 id 的部分只留在那里）

---

### Task 13: 收尾（状态、§9、扫密、code-review）

**Files:**
- Modify: `docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md`（§9 第 11 行）
- Modify: `.scratch/asset-v1/issues/07-*.md`、`.scratch/asset-v1/NEXT.md`（gitignored，不进提交）

- [ ] **Step 1: §9 第 11 行**

把 `+ 内置"Cognito 管理员建户"**模式仍待实现**（工单 07）` 与行末的
`**剩下的是 \`deploy_pool.py\` 的模式开关**（工单 07，含前移保留名校验）` 改成划掉/完成态，
补一句实现要点（**不写日期以外的环境状态**）：

```markdown
| 11 | ~~**IdP 通用性验证**~~（**✅ 已完成**，asset-v1 工单 06）+ ~~内置"Cognito 管理员建户"模式~~（**✅ 已完成**，工单 07） | …（既有正文保留）… **模式已落地**：`[IdP] mode = cognito-admin` 在同一次 `deploy_pool.py` 运行里建出第二个池（LITE、只许管理员建户、`email` schema 层 `Mutable=False`）、它的 classic hosted UI 托管域名与联邦 app client，并把平台池的 `/oauth2/idpresponse` 自动登记为回调；`provider_name` 保留名校验与"两套模式字段混填""池名与域名前缀不一致"三类判据都在**第一次 AWS 写之前**失败。建户仍是手工两条 `aws cognito-idp` 命令（脚本打印）。 |
```

- [ ] **Step 2: 工单 07 Status + Comments**

Status 改 `done`；Comments 追加一条 `2026-09-12`：三条裁定、`external-oidc` 回归的
10 项核对结果、两条腿的真机证据（含 `_exchange_code` 返回的 claim dict）、Task 2 的
决定（做了/否决）、以及"IdP 池 client secret 不持久化"这个刻意的设计。

- [ ] **Step 3: NEXT.md 顶部**

改成"工单 07 完成"，写清：改了 `deploy_pool.py` / `.example` / DEPLOY.md / ADR 0006 /
§9；**没有重部任何生产组件**（生产池零改动；下一次在生产池跑 `deploy_pool.py` 会把
machine client 的 `ExplicitAuthFlows` 收紧——若 Task 2 做了）；下一张票是 12（等 07 的
那部分现在解锁了）。

- [ ] **Step 4: 扫密 + 提交**

```bash
cd "$(git rev-parse --show-toplevel)"
git add site-builder/scripts/deploy_pool.py site-builder/config.ini.example \
        site-builder/DEPLOY.md docs/adr/0006-*.md \
        docs/reviews/MERGED-ADVERSARIAL-REVIEW-2026-08-21.md \
        site-builder/deployer/tests/test_deploy_pool.py \
        site-builder/deployer/tests/test_delivery_docs_current.py
bash site-builder/scripts/scan_staged_secrets.sh      # **必须先 git add**，空 stage 它什么都不看
git status --porcelain            # 确认 .scratch/ 与两份 config.ini 都不在里面
git commit -m "docs(asset-v1/07): §9 第 11 行收口——内置 Cognito 管理员建户模式已落地"
```

- [ ] **Step 5: `/code-review` 并处理findings**

Run: `/code-review`（本票的完整 diff）。用 `superpowers:receiving-code-review` 处理结论；
接受的每条都要有对应用例，拒绝的每条在工单 Comments 里写理由。

- [ ] **Step 6: 最终闸门（七套件顺序跑一遍）**

Run: Task 11 Step 1 的那段。Expected: 七套全绿。

---

## Self-Review

**1. Spec 覆盖**（工单 07 的产物清单 + 五条 preflight + 另外四条 + 两处措辞订正）

| 要求 | 落在 |
|---|---|
| `deploy_pool.py` 的模式实现 | Task 3 / 5 / 6 / 7 |
| preflight 1（无 mode ⇒ external-oidc） | Task 1 `idp_mode` + `test_idp_mode_defaults_to_external_when_key_absent` |
| preflight 2（未知 mode / 所需键缺失 / 混填） | Task 1 `check_idp_section` + 5 条用例 |
| preflight 3（`provider_name` 保留名，本地） | Task 1 `assert_provider_name_allowed`（裁定 1 收窄了"必填"那半，理由写在裁定里） |
| preflight 4 / 5（池名与域名前缀分叉 fail closed） | Task 4 `preflight_idp_pool` |
| 回调要平台池托管域名的**真实现值** | Task 7 `main()`（用 `_ensure_domain` 的返回值）+ `test_main_creates_the_idp_pool_after_the_platform_domain` |
| `client_secret` 不持久化 + `_ensure_oidc_idp` 模式感知（external 那侧的检查绝不能少） | Task 5 / Task 6 + `test_cognito_mode_ignores_sb_idp_client_secret_env`、`test_idp_missing_client_secret_fails_loudly`（既有） |
| `_verify_no_native_flows` 覆盖 IdP 池那个 client | Task 7 `main()` ②b 末尾 + Task 3 的 `test_idp_client_passes_the_native_flow_gate` |
| 一趟做完，不要变成"跑两次" | Task 7 的 ②b 位置 + 两条 AST 顺序守卫 |
| `.example` 三个新键（注释独立成行） | Task 8 |
| DEPLOY.md §0 第 3 条路 + ① 步骤 1 + 就绪清单 | Task 10 |
| ADR 0006 + 工单 07 措辞订正 | Task 9 |
| 工单 Comments / NEXT.md / §9 第 11 行 | Task 13 |
| 真实行为测试（至少四组：external 默认 / cognito 正常 / 所需键缺失 / 混填）+ 保留名 + preflight 零写 + 4/5 条分叉 | Task 1（9 组）+ Task 4（6 条，含结构性"零写"）+ Task 8（4 条模板自证） |
| 完成判据：七套件 / 隔离池真机 / external-oidc 回归 / 删隔离池 / `/code-review` | Task 11 / 12 / 13 |

**2. Placeholder 扫描**：Task 5 Step 1 里那条 union 用例的第一段是**刻意保留的反例说明**
（"不能靠错误路径读参数"），实现时删掉——已在紧随其后的引用块里写明。Task 6 的
`_captured_mapping_and_details` 只给了 docstring 与"照既有 `_captured_mapping` 写"的指引，
因为那份既有工具的 Stubber 样板必须先读再复用（照抄一份就是第二处样板）。其余每一步都有
可执行的代码或命令。

**3. 类型一致性**：`idp_mode(idp) -> str`、`check_idp_section(idp, mode) -> None`、
`resolve_idp_pool_names(...) -> tuple[str, str]`、`preflight_idp_pool(...) -> str | None`、
`_ensure_idp_pool(cog, pool_name, existing) -> str`、`_ensure_idp_pool_client(...) -> tuple[str, str]`、
`cognito_mode_idp(...) -> dict`、`_ensure_domain(..., managed_login_version: int | None)`、
`_ensure_oidc_idp(..., mode: str)`——在 Task 7 的 `main()` 里逐个按这些签名调用，名字与
Task 1/3/4/5/6 的 Interfaces 块一致。`_clean` 与 `_truthy` 的关系（后者复用前者）在
Task 1 Step 3 里给了完整实现，避免两处切注释。

## 两个必须让 Kent 知情的点

1. **Task 2 改的是既有生产代码**，并且要改写一条**刻意锁死了反向前提**的既有用例
（`test_machine_client_passes_both_native_flow_gates`）。它可以被单独否决而不影响其余任务。
2. **裁定 1 收窄了工单里"`provider_name` 两模式都必填"那半句**：`external-oidc` 下空值仍
只是告警 + 跳过联邦。理由是 `.example` 出厂即空值、而 external-oidc 是生产在用的路径。
