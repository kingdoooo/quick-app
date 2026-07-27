#!/usr/bin/env python3
import boto3
import time
import random
import string
import argparse

# 解析命令行参数
parser = argparse.ArgumentParser(description='Deploy Lambda function with custom image')
parser.add_argument('--image', required=True, help='ECR image URI to deploy')
parser.add_argument('--name', help='Custom function name prefix')
args = parser.parse_args()

# ============================================================================
# 配置设置 (直接在代码中配置)
# ============================================================================
ACCOUNT_ID = "{account_id}"
REGION = "us-east-1"
FUNCTION_PREFIX = args.name if args.name else "test-lambda"
ROLE_NAME = "lambda-execution-role"
DYNAMODB_TABLE = "ApplicationWebRouterStack-subdomain-mapping"
DOMAIN_NAME = "jendencrazy.win"

# 资源标签
TAGS = {
    "project": "site-builder",
    "environment": "test",
    "managed_by": "script"
}

# 生成随机后缀
RANDOM_SUFFIX = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
FUNCTION_NAME = f"{FUNCTION_PREFIX}-{RANDOM_SUFFIX}"
IMAGE_URI = args.image  # 使用命令行参数指定的镜像
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}"

lambda_client = boto3.client('lambda', region_name=REGION)
dynamodb_client = boto3.client('dynamodb', region_name=REGION)
iam_client = boto3.client('iam')

print("=" * 50)
print("🚀 部署 Lambda 函数（带耗时统计）")
print("=" * 50)
print()

start_time = time.time()

# 0. 检查并创建 IAM 角色
print("🔍 检查 IAM 角色...")
role_check_start = time.time()
try:
    iam_client.get_role(RoleName=ROLE_NAME)
    print(f"✅ 角色 {ROLE_NAME} 已存在 ({time.time() - role_check_start:.2f}s)")
except iam_client.exceptions.NoSuchEntityException:
    print(f"⚠️  角色 {ROLE_NAME} 不存在，正在创建...")
    
    # 创建角色
    iam_client.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}',
        Description="Lambda execution role for test functions"
    )
    
    # 附加基本执行策略
    iam_client.attach_role_policy(
        RoleName=ROLE_NAME,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    
    print(f"✅ 角色 {ROLE_NAME} 已创建 ({time.time() - role_check_start:.2f}s)")
print()

# 1. 创建 Lambda 函数
print("⚡ 创建 Lambda 函数...")
create_start = time.time()
response = lambda_client.create_function(
    FunctionName=FUNCTION_NAME,
    PackageType='Image',
    Code={'ImageUri': IMAGE_URI},
    Role=ROLE_ARN,
    Timeout=30,
    MemorySize=512,
    Description='Express.js Demo with Lambda Web Adapter',
    Tags=TAGS
)
print(f"✅ 函数已创建 ({time.time() - create_start:.2f}s)")
print()

# 2. 等待函数就绪
print("⏳ 等待函数就绪...")
wait_start = time.time()
waiter = lambda_client.get_waiter('function_active')
waiter.wait(FunctionName=FUNCTION_NAME)
print(f"✅ 函数已就绪 ({time.time() - wait_start:.2f}s)")
print()

# 3. 创建 Function URL
print("🌐 创建 Function URL (AWS_IAM)...")
url_start = time.time()
url_response = lambda_client.create_function_url_config(
    FunctionName=FUNCTION_NAME,
    AuthType='AWS_IAM'
)
function_url = url_response['FunctionUrl']
print(f"✅ Function URL 已创建 ({time.time() - url_start:.2f}s)")
print()

# 4. 添加到 DynamoDB (如果表存在)
print("💾 检查 DynamoDB 表...")
ddb_start = time.time()
subdomain = FUNCTION_NAME  # 定义在 try 块外部
try:
    dynamodb_client.describe_table(TableName=DYNAMODB_TABLE)
    print(f"✅ DynamoDB 表存在，添加映射...")
    
    dynamodb_client.put_item(
        TableName=DYNAMODB_TABLE,
        Item={
            'subdomain': {'S': subdomain},
            'target_url': {'S': function_url.rstrip('/')}
        }
    )
    print(f"✅ DynamoDB 映射已添加 ({time.time() - ddb_start:.2f}s)")
    access_url = f"https://{subdomain}.{DOMAIN_NAME}/"
except dynamodb_client.exceptions.ResourceNotFoundException:
    print(f"⚠️  DynamoDB 表 {DYNAMODB_TABLE} 不存在，跳过映射 ({time.time() - ddb_start:.2f}s)")
    access_url = "N/A (需要先部署 CDK 堆栈)"
print()

total_time = time.time() - start_time

print("=" * 50)
print("✅ 部署完成！")
print("=" * 50)
print()
print(f"📊 耗时统计:")
print(f"  总耗时: {total_time:.2f}s")
print()
print(f"📋 部署信息:")
print(f"  函数名称: {FUNCTION_NAME}")
print(f"  Subdomain: {subdomain}")
print(f"  Function URL: {function_url}")
print(f"  访问地址: {access_url}")
print(f"  认证方式: AWS_IAM")
print()
