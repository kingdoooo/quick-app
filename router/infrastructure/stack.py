#!/usr/bin/env python3
"""
Application Web Router Stack
CloudFront-based dynamic subdomain routing system using Lambda@Edge and DynamoDB
"""
import os
import configparser
import json
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


def load_jwt_secret(legacy_param: str) -> str:
    """Deploy-time **legacy-entry** secret injection for the edge function.

    3c-1B（spec §11.8.1）：参数路径来自 `[SessionKeys] legacy_param`（唯一真源），
    **不再硬编码** `/site-builder/jwt-secret`——硬编码与真源分叉时，闸门盯着一把密钥而
    Edge 注入的是另一把，两边都不报错。**路径必须由调用方传入**（不给默认值，也不在这里
    自己读一次 config）：调用方已经加载过 `SessionKeys`，多一条"自己读"的路就多一份可能
    与它不一致的取值，而"两个注入值来自同一份解析"正是这次要保证的性质。

    Resolution order:
    1. `legacy_param` 为**空**（L3：legacy 入口已关闭）→ 空串，且**不打警告**。
       空串**不是** SYNTH 占位符：`verify_deployed_edge.sh` 的两条占位符断言看的是
       `SYNTH-ONLY-PLACEHOLDER` 字样与未替换的 `{{…}}`，空替换不会误报。
       Edge 在 `LEGACY_ENTRY=off` 下根本不读这个常量（1A 已按开关分支）。
    2. `APP_JWT_SECRET` environment variable (explicit override)
    3. SSM SecureString parameter at `legacy_param` (us-east-1)
    4. Synth-only placeholder (SSM unreachable / parameter missing /
       boto3 not installed) — allows `cdk synth` to run offline, but the
       resulting template MUST NOT be deployed: with a wrong secret every
       legacy session token fails verification (fail-closed, endless login
       redirect). Real deployments must have the SSM parameter in place
       (aws ssm put-parameter --name <legacy_param>
        --type SecureString --value <secret> --region us-east-1).

    **第 1 条与第 4 条必须分得开**：两者都让 Edge 拒绝 legacy token，但一个是刻意的
    （入口已关闭，无 legacy token 还在流通），另一个是故障（SSM 读不到，线上现存的
    legacy cookie 全部失效）。把"刻意为空"也走占位符路径会让 L3 的每次部署都被
    产物核对判红，而真故障反而被当成日常。
    """
    if not legacy_param:
        return ""
    env_secret = os.getenv("APP_JWT_SECRET")
    if env_secret:
        return env_secret
    try:
        import boto3
        ssm = boto3.client("ssm", region_name="us-east-1")
        return ssm.get_parameter(
            Name=legacy_param, WithDecryption=True
        )["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001 - deliberate synth-time fallback
        import sys
        print(
            f"WARNING: could not read SSM {legacy_param} ({exc}); "
            "using a synth-only placeholder. DO NOT deploy this template.",
            file=sys.stderr,
        )
        return "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"


def _session_keys_on_path() -> Path:
    """把 `site-builder/auth` 放进 `sys.path` 并返回仓库根。

    **单独一个函数、被每个 `from session_keys import …` 的地方各自调用**：早先它藏在
    `_session_keys()` 里，于是"传了 keys 就不走 `_session_keys()`"的那条路会在 import
    时炸（latent ImportError，只因为调用顺序恰好对才没现形）。
    """
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "site-builder" / "auth"))
    return root


def _session_keys():
    """`[SessionKeys]` 的唯一定义在 site-builder/auth/session_keys.py（不在本文件复制一份）。"""
    root = _session_keys_on_path()
    from session_keys import load_session_keys
    return load_session_keys(root / "site-builder" / "config.ini")


def load_site_allowlist(keys) -> tuple:
    """3c-1A：Edge 只认 site family 的 kid allowlist（spec §4.1 / §11.6）。

    `keys` 是**必填**的已加载 `SessionKeys`（由调用方与 `load_jwt_secret` 共用同一份，
    见 `WebRouterStack.__init__`）——本函数不自己再读一次 config。

    → (allowlist_json, legacy_entry)。kid 清单来自 `site-builder/config.ini` 的 [SessionKeys]
    （唯一取值来源，经 site-builder/auth/session_keys.py 校验，缺段/写错即 synth 失败），
    secret 值按每行的 ssm_param 从 SSM 取；**只取 site family，console 的 key 不进 Edge**。
    legacy 开关：legacy_param 非空即 "on"，为空即 "off"（清空它 = 3c-1B 的 L3，关闭入口）。

    SSM 读失败沿用 load_jwt_secret 的 synth-only 语义：注入带 SYNTH-ONLY 标记的占位 allowlist 并在
    stderr 警告，这样 `cdk synth` 离线能跑，但该模板**绝不能部署**（verify_deployed_edge.sh 会抓到标记）。
    """
    _session_keys_on_path()          # 无条件放路径：不依赖调用方是否先调过 _session_keys()
    from session_keys import SYNTH_PLACEHOLDER_ALLOWLIST_JSON, legacy_entry
    override = os.getenv("APP_SITE_ALLOWLIST_JSON")   # 与 APP_JWT_SECRET 同款的显式覆盖（离线 synth / 测试）
    if override:
        text = override
    else:
        try:
            import boto3
            ssm = boto3.client("ssm", region_name="us-east-1")
            allow = {}
            for ref in keys.allowlist("site"):
                if ref.alg != "HS256":
                    raise ValueError(f"{ref.kid}: 3c-1A 的 Edge 只支持 HS256 行（RS 行是 3c-2B）")
                val = ssm.get_parameter(Name=ref.ssm_param, WithDecryption=True)["Parameter"]["Value"]
                allow[ref.kid] = {"alg": ref.alg, "secret": val, "role": ref.role}
            text = json.dumps(allow, separators=(",", ":"))
        except Exception as exc:  # noqa: BLE001 - deliberate synth-time fallback
            print(f"WARNING: could not build the site allowlist from SSM ({exc}); "
                  "injecting the SYNTH-ONLY placeholder allowlist. DO NOT deploy this template.",
                  file=sys.stderr)
            text = SYNTH_PLACEHOLDER_ALLOWLIST_JSON   # 合法 JSON、带标记、kid 永不匹配（session_keys 里有说明）
    if "\'\'\'" in text or "\\" in text:
        raise ValueError("allowlist JSON 含三引号或反斜杠，注进三引号字符串会破坏 Edge 源码")
    json.loads(text)   # 注入前保证是合法 JSON，否则 Edge 在 import 时就炸
    return text, legacy_entry(keys)


class WebRouterStack(Stack):
    """CloudFront dynamic subdomain routing Stack"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        config = ConfigLoader()
        stack_name = construct_id
        
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
        frontend_bucket = config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET")
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
        access_account = config.get("AWS", "account_id", "APP_ACCOUNT_ID").strip()
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

        # Site-builder placeholders (Task 6/7). JWT secret comes from SSM at
        # deploy time (see load_jwt_secret); the bucket lives in us-east-1
        # (Lambda@Edge SigV4 in origin_request.py signs for us-east-1).
        # `[SessionKeys]` 只解析一遍，两个注入值都从同一份取——分开各读一次的话，
        # 中途改 config 会让 Edge 拿到自相矛盾的 (allowlist, legacy secret) 组合。
        session_keys = _session_keys()
        jwt_secret = load_jwt_secret(session_keys.legacy_param)
        site_allowlist_json, legacy_entry = load_site_allowlist(session_keys)
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
            .replace("{{JWT_SECRET}}", jwt_secret)
            .replace("{{SITE_ALLOWLIST_JSON}}", site_allowlist_json)
            .replace("{{LEGACY_ENTRY}}", legacy_entry)
            .replace("{{BASE_DOMAIN}}", base_domain)
            .replace("{{REQUIRE_IDP_CLAIM}}", require_idp_claim)
            .replace("{{TRUSTED_IDPS}}", trusted_idps)
            .replace("{{ACCESS_TABLE}}", access_table)
            .replace("{{ACCESS_REPLICA_REGIONS}}", ",".join(access_regions)))
        
        # Write to temporary file
        temp_dir = tempfile.mkdtemp()
        with open(os.path.join(temp_dir, 'index.py'), 'w') as f:
            f.write(lambda_code)

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
        account=config.get("AWS", "account_id", "APP_ACCOUNT_ID"),
        region=config.get("AWS", "region", "APP_REGION")
    ),
    description=config.get("CDK", "stack_description", "APP_STACK_DESCRIPTION")
)

app.synth()
