"""API Key 组件的门禁判定——**全平台唯一真源**（二期 M4，spec §5.1.1）。

API Key 是**可选组件**：`config.ini` 整段不配 `[ApiKey]` = 平台只允许 OAuth
一条认证路径（推荐的默认）。"配没配"这个判定必须只有一处——三个部署脚本
（`scripts/deploy_pool.py`、`mcp/deploy_agentcore.py`、
`key-proxy/deploy_key_proxy.py`）各写一次 `cfg.has_section("ApiKey")` 就是三个
判定点，漏改一处得到的是**部分部署**，而部分部署恰好是最危险的状态：

  · 网关 allowlist 放了 `X-SB-On-Behalf-Of` 头，但 machine client 没进
    `allowedClients` → 机器 token 在网关层被拒（白部署，症状明显）；
  · 反过来 machine client 进了 `allowedClients`，而容器的 `MACHINE_CLIENT_ID`
    是空 → 请求过网关、`_caller_email()` fail-closed 拒掉，症状是 HTTP 200
    加一句业务错误文案，是最难排查的那一半。

**落点是 `deployer/functions/`，不是 `scripts/`**（Codex 审查 2026-08-11 P1-3，
已实测复现）：三个脚本分别从 `site-builder/`、`site-builder/mcp/`、
`site-builder/key-proxy/` 执行，后两个目录看不到 `scripts/`
——`import deploy_pool` 会在任何 AWS 调用**之前** ModuleNotFoundError。放
`functions/` 后三者都能用同一个相对路径 `sys.path.insert`
（`deploy_pool.py` 现成的 `HERE.parent / "auth"` 就是这个形态），且它天然进
Lambda/容器打包，key-proxy 运行时也能用同一份判定。

本模块**不 import boto3、不读环境变量**：只从传入的 ConfigParser 派生，纯函数。
"""

API_KEY_SECTION = "ApiKey"

# 交换层告诉 MCP server「以谁的身份行事」的头。**这里是它的唯一定义**：
# 同一个名字要在三处一致——网关的 requestHeaderAllowlist（不放行则头到不了
# 容器）、key-proxy 出站时加的头、MCP server 读的头。三处漂移的症状分别是
# "所有 Key 调用被拒""上游收不到身份""身份识别不了"，都不指向名字本身。
# server.py 因为容器只 COPY 三个模块而留了一份小写镜像，由
# mcp/tests/test_component_gate.py 的 real-value 断言绑定（漂了当场红）。
ON_BEHALF_HEADER = "X-SB-On-Behalf-Of"

# 默认值与 config.ini.example 的 [ApiKey] 注释一致。给默认值而不是必填：
# resource server / scope / 子域都是"能改但基本不改"的名字，缺省让最小配置
# （只写一行 `[ApiKey]`）就是一套可用的完整组件。
DEFAULT_RESOURCE_SERVER_ID = "site-builder-mcp"
DEFAULT_SCOPE = "invoke"
DEFAULT_MCP_SUBDOMAIN = "mcp"


def _value(cfg, key: str, default: str) -> str:
    """取 `[ApiKey]` 的一个键，切掉 configparser 保留的行内注释。

    ConfigParser 默认 `inline_comment_prefixes=None`，所以
    `scope = invoke  # 用不着改` 的值里**带着注释文本**。直接拼进 Cognito
    scope 会得到一个不存在的 scope，而 token 端点的报错文案指向 client 配置
    ——排查方向被带偏（machine_token 的既有教训）。与
    `deploy_pool._truthy` / `deploy_panel._cfg` 同一口径。
    """
    raw = cfg[API_KEY_SECTION].get(key, "") or ""
    head = raw.split("#")[0].split(";")[0].strip()
    return head or default


def api_key_enabled(cfg) -> bool:
    """有没有 `[ApiKey]` 段 = API Key 组件是否启用。**唯一判定点。**

    判"段存在"而不是段里的某个 `enabled` 键（2026-08-11 定，此前有过那个键）：
    应急关闸开关是 `site-api-keys` 表里的哨兵行（管理员在控制台开关，即时生效、
    有审计）。配置文件里再放一个开关就是两个真源，比没有开关更危险——写了
    `enabled = false` 而实现只读哨兵行，结果是 Key 全部继续有效而现场以为已经
    关了；反过来部署脚本"把配置收敛到线上"的语义又会把管理员的关闸静默覆盖成开。
    完整说明见 `config.ini.example` 的 `[ApiKey]` 段。
    """
    return cfg.has_section(API_KEY_SECTION)


def resource_server_id(cfg) -> str:
    """Cognito resource server 的 identifier。**未启用组件时返回 ""。**"""
    if not api_key_enabled(cfg):
        return ""
    return _value(cfg, "resource_server_id", DEFAULT_RESOURCE_SERVER_ID)


def scope_name(cfg) -> str:
    """machine client 唯一被授予的 custom scope 名。未启用时返回 ""。"""
    if not api_key_enabled(cfg):
        return ""
    return _value(cfg, "scope", DEFAULT_SCOPE)


def machine_scope(cfg) -> str:
    """`{identifier}/{scope}` —— 这个拼接**全仓库只在这里做一次**。

    key-proxy 换 machine token 时要带完整 scope 串，deploy_pool 建 resource
    server 时要用同样的两个分量。两处各拼一次的话，改了 config 里任一分量就会
    出现"建的 scope 与换 token 用的 scope 不是同一个"，而 Cognito 的报错是
    `invalid_scope`，指向 client 配置。

    未启用组件时返回 ""——调用方必须把空值当"不可用"，**不得拿空 scope 去换
    token**（Cognito 会拒，且错误文案同样把排查方向带向 client 配置）。
    """
    identifier, scope = resource_server_id(cfg), scope_name(cfg)
    return f"{identifier}/{scope}" if identifier and scope else ""


def mcp_subdomain(cfg) -> str:
    """交换层的子域名（`route_mode=api-only`、`require_auth=False`）。

    **它不进 Edge 的 `PLATFORM_SUBDOMAINS`**：key-proxy 只认 `X-API-Key`，
    不需要平台 cookie；进白名单只会让一个公网组件白拿一个顶域会话 JWT。
    未启用组件时返回 ""（= 不注册这个子域的路由）。
    """
    if not api_key_enabled(cfg):
        return ""
    return _value(cfg, "mcp_subdomain", DEFAULT_MCP_SUBDOMAIN)
