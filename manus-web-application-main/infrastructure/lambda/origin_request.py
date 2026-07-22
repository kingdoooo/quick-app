"""
Lambda@Edge Origin Request处理器

根据DynamoDB中存储的subdomain映射关系，动态将CloudFront请求路由到不同的后端服务
支持 AWS_IAM 认证的 Lambda Function URL
"""
import json
import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib.parse


# 配置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 配置常量（Lambda@Edge不支持环境变量，由CDK部署时注入）
DYNAMODB_TABLE_NAME = "{{DYNAMODB_TABLE_NAME}}"
DYNAMODB_REGION = "{{DYNAMODB_REGION}}"
DEFAULT_PROTOCOL = "https"
DEFAULT_PORT = 443
DEFAULT_SSL_PROTOCOLS = ["TLSv1.2"]
DEFAULT_READ_TIMEOUT = 30
DEFAULT_KEEPALIVE_TIMEOUT = 5

# 初始化DynamoDB客户端
dynamodb = boto3.client("dynamodb", region_name=DYNAMODB_REGION)

# 初始化 boto3 session 用于签名
session = boto3.Session()
credentials = session.get_credentials()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda@Edge处理器，用于origin request阶段的动态路由
    
    参数:
        event: CloudFront origin request事件
        context: Lambda上下文对象
        
    返回:
        修改后的CloudFront请求，包含动态设置的源站
    """
    try:
        request = event["Records"][0]["cf"]["request"]
        
        # 从自定义header中提取原始host
        original_host = _get_original_host(request)
        if not original_host:
            logger.warning("未找到X-Original-Host header，使用默认源站")
            return request
        
        logger.info(f"处理请求，host: {original_host}")
        
        # 提取subdomain
        subdomain = _extract_subdomain(original_host)
        logger.info(f"提取的subdomain: {subdomain}")
        
        # 保留原始URI和query string，处理特殊字符
        original_uri = request.get("uri", "/")
        original_querystring = request.get("querystring", "")
        
        # 从DynamoDB查询目标后端
        target_url = _lookup_target_url(subdomain)
        
        if target_url:
            # 处理查询字符串中的特殊字符（如Base64的等号）
            fixed_querystring = original_querystring
            if original_querystring:
                fixed_querystring = _fix_querystring_encoding(original_querystring)
            
            # 修改请求，路由到目标后端（传入修复后的查询字符串用于签名）
            _modify_request_origin(request, target_url, original_uri, fixed_querystring)
            
            # 保留原始URI和修复后的query string
            request["uri"] = original_uri
            request["querystring"] = fixed_querystring
            
            logger.info(
                f"路由 {subdomain} 到 {target_url} "
                f"(URI: {original_uri}, QS: {original_querystring})"
            )
            return request
        else:
            logger.warning(f"未找到subdomain的映射: {subdomain}")
            # 返回404错误
            return {
                'status': '404',
                'statusDescription': 'Not Found',
                'headers': {
                    'content-type': [{
                        'key': 'Content-Type',
                        'value': 'text/html'
                    }]
                },
                'body': f'<html><body><h1>404 Not Found</h1><p>Subdomain "{subdomain}" not configured.</p></body></html>'
            }
        
    except Exception as e:
        logger.error(f"处理请求时出错: {str(e)}", exc_info=True)
        # 出错时返回原始请求，避免中断请求流程
        return event["Records"][0]["cf"]["request"]


def _fix_querystring_encoding(querystring: str) -> str:
    """
    修复查询字符串中的编码问题，特别是Base64字符串中的等号
    
    参数:
        querystring: 原始查询字符串
        
    返回:
        修复后的查询字符串
    """
    if not querystring:
        return querystring
    
    try:
        # 解析查询参数
        params = urllib.parse.parse_qs(querystring, keep_blank_values=True)
        
        # 重新构建查询字符串，确保正确编码
        fixed_params = []
        for key, values in params.items():
            for value in values:
                # 对参数值进行URL编码，特别处理Base64字符串
                encoded_value = urllib.parse.quote(value, safe='')
                fixed_params.append(f"{key}={encoded_value}")
        
        result = "&".join(fixed_params)
        logger.info(f"Fixed querystring: {querystring} -> {result}")
        return result
        
    except Exception as e:
        logger.warning(f"Failed to fix querystring encoding: {e}")
        return querystring


def _get_original_host(request: Dict[str, Any]) -> Optional[str]:
    """
    从 Host 或 X-Original-Host header 中提取原始 host
    
    参数:
        request: CloudFront请求对象
        
    返回:
        原始host值，如果不存在则返回None
    """
    headers = request.get("headers", {})
    
    # 优先使用 Host header
    if "host" in headers:
        host = headers["host"][0]["value"]
        logger.info(f"Found Host header: {host}")
        return host
    
    # 回退到 X-Original-Host
    if "x-original-host" in headers:
        host = headers["x-original-host"][0]["value"]
        logger.info(f"Found X-Original-Host header: {host}")
        return host
    
    logger.warning("No Host or X-Original-Host header found")
    return None


def _extract_subdomain(host: str) -> str:
    """
    从hostname中提取subdomain
    
    参数:
        host: 完整的hostname（例如："api.example.com"）
        
    返回:
        subdomain（例如："api"）
    """
    return host.split(".")[0]


def _lookup_target_url(subdomain: str) -> Optional[str]:
    """
    从DynamoDB查询目标后端URL
    
    参数:
        subdomain: 要查询的subdomain
        
    返回:
        目标URL，如果未找到则返回None
    """
    try:
        response = dynamodb.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={"subdomain": {"S": subdomain}},
            ProjectionExpression="target_url",
            ConsistentRead=False,  # 使用最终一致性读取以获得更好的性能
        )
        
        if "Item" in response and "target_url" in response["Item"]:
            return response["Item"]["target_url"]["S"]
        
        return None
        
    except ClientError as e:
        logger.error(f"DynamoDB错误: {e.response['Error']['Message']}")
        return None


def _modify_request_origin(request: Dict[str, Any], target_url: str, uri: str = "/", querystring: str = "") -> None:
    """
    修改请求以路由到目标后端，支持 AWS_IAM 认证
    
    参数:
        request: CloudFront请求对象（原地修改）
        target_url: 目标后端URL
        uri: 请求URI
        querystring: 查询字符串（已修复编码）
    """
    # 解析目标URL以提取域名和路径
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc
    
    # 检查是否是 Lambda Function URL (需要 IAM 签名)
    is_lambda_url = ".lambda-url." in domain and ".on.aws" in domain
    
    if is_lambda_url:
        # 为 Lambda Function URL 添加 SigV4 签名（使用修复后的查询字符串）
        _add_sigv4_auth(request, domain, uri, querystring)
    
    # 更新源站配置
    request["origin"] = {
        "custom": {
            "domainName": domain,
            "port": DEFAULT_PORT,
            "protocol": DEFAULT_PROTOCOL,
            "path": "",
            "sslProtocols": DEFAULT_SSL_PROTOCOLS,
            "readTimeout": DEFAULT_READ_TIMEOUT,
            "keepaliveTimeout": DEFAULT_KEEPALIVE_TIMEOUT,
            "customHeaders": {},
        }
    }
    
    # 更新Host header以匹配新的源站
    request["headers"]["host"] = [{"key": "Host", "value": domain}]


def _add_sigv4_auth(request: Dict[str, Any], domain: str, uri: str = "/", querystring: str = "") -> None:
    """
    为请求添加 AWS Signature Version 4 认证头
    
    参数:
        request: CloudFront请求对象
        domain: Lambda Function URL 域名
        uri: 请求URI
        querystring: 查询字符串（已修复编码）
    """
    # 提取区域
    region = domain.split(".lambda-url.")[1].split(".")[0]
    
    # 构建请求 URL（使用修复后的查询字符串）
    url = f"https://{domain}{uri}"
    if querystring:
        url += f"?{querystring}"
    
    # 获取请求方法和 body
    method = request.get("method", "GET")
    body = request.get("body", {}).get("data", "")
    
    # 创建 AWS 请求对象
    aws_request = AWSRequest(method=method, url=url, data=body)
    
    # 添加签名
    SigV4Auth(credentials, "lambda", region).add_auth(aws_request)
    
    # 将签名头添加到 CloudFront 请求
    for header_name, header_value in aws_request.headers.items():
        if header_name.lower() in ['authorization', 'x-amz-date', 'x-amz-security-token']:
            request["headers"][header_name.lower()] = [{
                "key": header_name,
                "value": header_value
            }]
    
    logger.info(f"Added SigV4 auth for Lambda URL in region {region} with querystring: {querystring}")
