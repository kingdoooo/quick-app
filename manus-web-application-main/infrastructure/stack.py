#!/usr/bin/env python3
"""
Application Web Router Stack
CloudFront-based dynamic subdomain routing system using Lambda@Edge and DynamoDB
"""
import os
import configparser
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


def load_jwt_secret() -> str:
    """Deploy-time JWT secret injection for the edge function.

    Resolution order:
    1. APP_JWT_SECRET environment variable (explicit override)
    2. SSM SecureString parameter /site-builder/jwt-secret (us-east-1)
    3. Synth-only placeholder (SSM unreachable / parameter missing /
       boto3 not installed) — allows `cdk synth` to run offline, but the
       resulting template MUST NOT be deployed: with a wrong secret every
       session token fails verification (fail-closed, endless login
       redirect). Real deployments must have the SSM parameter in place
       (aws ssm put-parameter --name /site-builder/jwt-secret
        --type SecureString --value <secret> --region us-east-1).
    """
    env_secret = os.getenv("APP_JWT_SECRET")
    if env_secret:
        return env_secret
    try:
        import boto3
        ssm = boto3.client("ssm", region_name="us-east-1")
        return ssm.get_parameter(
            Name="/site-builder/jwt-secret", WithDecryption=True
        )["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001 - deliberate synth-time fallback
        import sys
        print(
            f"WARNING: could not read SSM /site-builder/jwt-secret ({exc}); "
            "using a synth-only placeholder. DO NOT deploy this template.",
            file=sys.stderr,
        )
        return "SYNTH-ONLY-PLACEHOLDER-DO-NOT-DEPLOY"


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
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["lambda:InvokeFunctionUrl"],
            resources=["*"]
        ))

        # Site-builder: shared frontend bucket (private; edge function reads
        # static assets via SigV4-signed GET)
        frontend_bucket = config.get("SiteBuilder", "frontend_bucket", "APP_FRONTEND_BUCKET")
        base_domain = config.get("SiteBuilder", "base_domain", "APP_BASE_DOMAIN")
        edge_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["s3:GetObject"],
            resources=[f"arn:aws:s3:::{frontend_bucket}/sites/*"]
        ))
        
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
        jwt_secret = load_jwt_secret()
        lambda_code = (lambda_code
            .replace("{{FRONTEND_BUCKET_DOMAIN}}",
                     f"{frontend_bucket}.s3.us-east-1.amazonaws.com")
            .replace("{{JWT_SECRET}}", jwt_secret)
            .replace("{{BASE_DOMAIN}}", base_domain))
        
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
                    )
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
