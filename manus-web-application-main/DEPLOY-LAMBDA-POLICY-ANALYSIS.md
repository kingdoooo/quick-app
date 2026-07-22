# Deploy Lambda 脚本权限分析

本文档分析 `deploy_lambda.py` 脚本执行所需的最小权限。

## 脚本功能概述

`deploy_lambda.py` 脚本执行以下操作：
1. 检查并创建 IAM 执行角色
2. 创建 Lambda 函数（使用容器镜像）
3. 等待函数就绪
4. 创建 Function URL
5. 添加 DynamoDB 子域名映射

## 权限需求分析

### 1. IAM 角色管理权限

```json
{
  "Sid": "IAMRoleManagement",
  "Action": [
    "iam:GetRole",
    "iam:CreateRole", 
    "iam:AttachRolePolicy",
    "iam:PassRole"
  ],
  "Resource": [
    "arn:aws:iam::*:role/lambda-execution-role*"
  ]
}
```

**脚本操作**:
```python
# 检查角色是否存在
iam_client.get_role(RoleName=ROLE_NAME)

# 创建角色（如果不存在）
iam_client.create_role(
    RoleName=ROLE_NAME,
    AssumeRolePolicyDocument='...',
    Description="Lambda execution role for test functions"
)

# 附加基本执行策略
iam_client.attach_role_policy(
    RoleName=ROLE_NAME,
    PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)
```

**权限说明**:
- `iam:GetRole`: 检查角色是否已存在
- `iam:CreateRole`: 创建新的 Lambda 执行角色
- `iam:AttachRolePolicy`: 附加 AWS 托管的基本执行策略
- `iam:PassRole`: 将角色传递给 Lambda 服务

**资源限制**: 仅限 `lambda-execution-role*` 模式的角色

### 2. IAM 策略附加权限

```json
{
  "Sid": "IAMPolicyAccess",
  "Action": [
    "iam:AttachRolePolicy"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    }
  }
}
```

**安全限制**: 仅允许附加 AWS 托管的 Lambda 基本执行策略，防止权限提升

### 3. Lambda 函数管理权限

```json
{
  "Sid": "LambdaFunctionManagement",
  "Action": [
    "lambda:CreateFunction",
    "lambda:GetFunction",
    "lambda:CreateFunctionUrlConfig",
    "lambda:TagResource"
  ],
  "Resource": [
    "arn:aws:lambda:us-east-1:*:function:*"
  ]
}
```

**脚本操作**:
```python
# 创建 Lambda 函数
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

# 等待函数就绪
waiter = lambda_client.get_waiter('function_active')
waiter.wait(FunctionName=FUNCTION_NAME)

# 创建 Function URL
url_response = lambda_client.create_function_url_config(
    FunctionName=FUNCTION_NAME,
    AuthType='AWS_IAM'
)
```

**权限说明**:
- `lambda:CreateFunction`: 创建新的 Lambda 函数
- `lambda:GetFunction`: 检查函数状态（waiter 内部使用）
- `lambda:CreateFunctionUrlConfig`: 创建 Function URL
- `lambda:TagResource`: 为函数添加标签

**资源限制**: 限制在 us-east-1 区域的所有函数

### 4. DynamoDB 访问权限

```json
{
  "Sid": "DynamoDBAccess",
  "Action": [
    "dynamodb:DescribeTable",
    "dynamodb:PutItem"
  ],
  "Resource": [
    "arn:aws:dynamodb:us-east-1:*:table/*WebRouterStack*"
  ]
}
```

**脚本操作**:
```python
# 检查表是否存在
dynamodb_client.describe_table(TableName=DYNAMODB_TABLE)

# 添加子域名映射
dynamodb_client.put_item(
    TableName=DYNAMODB_TABLE,
    Item={
        'subdomain': {'S': subdomain},
        'target_url': {'S': function_url.rstrip('/')}
    }
)
```

**权限说明**:
- `dynamodb:DescribeTable`: 检查 DynamoDB 表是否存在
- `dynamodb:PutItem`: 添加子域名到 Function URL 的映射

**资源限制**: 仅限包含 `WebRouterStack` 的表

### 5. ECR 镜像访问权限

```json
{
  "Sid": "ECRImageAccess",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability", 
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage"
  ],
  "Resource": "*"
}
```

**脚本操作**:
```python
# Lambda 创建时需要拉取容器镜像
Code={'ImageUri': IMAGE_URI}
```

**权限说明**:
- `ecr:GetAuthorizationToken`: 获取 ECR 认证令牌
- `ecr:BatchCheckLayerAvailability`: 检查镜像层可用性
- `ecr:GetDownloadUrlForLayer`: 获取镜像层下载 URL
- `ecr:BatchGetImage`: 批量获取镜像信息

**为什么需要 `*`**: ECR 认证和镜像拉取是全局操作

## 安全特性

### 1. 资源限制
- IAM 角色限制到特定命名模式
- Lambda 函数限制到特定区域
- DynamoDB 限制到项目相关表

### 2. 条件限制
- IAM 策略附加限制到特定的 AWS 托管策略
- 防止附加过度权限的策略

### 3. 最小权限原则
- 仅包含脚本执行必需的权限
- 不包含删除或修改现有资源的权限

## 使用方法

### 1. 创建策略
```bash
aws iam create-policy \
  --policy-name DeployLambdaPolicy \
  --policy-document file://deploy-lambda-policy.json
```

### 2. 附加到用户
```bash
aws iam attach-user-policy \
  --user-name deploy-user \
  --policy-arn arn:aws:iam::ACCOUNT:policy/DeployLambdaPolicy
```

### 3. 执行脚本
```bash
python3 scripts/deploy_lambda.py \
  --image {account_id}.dkr.ecr.us-east-1.amazonaws.com/expressjs-demo:x86_64 \
  --name my-function
```

## 权限对比

| 操作 | CDK 策略 | Deploy Lambda 策略 |
|------|----------|-------------------|
| IAM 角色管理 | ✅ 完整权限 | ✅ 基本权限 |
| Lambda 函数 | ✅ 完整生命周期 | ✅ 创建和配置 |
| DynamoDB | ✅ 表管理 | ✅ 数据操作 |
| CloudFormation | ✅ 需要 | ❌ 不需要 |
| CloudFront | ✅ 需要 | ❌ 不需要 |
| S3 | ✅ 需要 | ❌ 不需要 |

## 故障排除

### 常见错误
1. **ECR 权限不足**: 确保有 ECR 镜像拉取权限
2. **IAM 角色创建失败**: 检查角色命名是否符合策略限制
3. **DynamoDB 表不存在**: 脚本会跳过映射，不会报错

### 权限验证
```bash
# 测试 IAM 权限
aws iam get-role --role-name lambda-execution-role

# 测试 Lambda 权限  
aws lambda list-functions --region us-east-1

# 测试 DynamoDB 权限
aws dynamodb describe-table --table-name ApplicationWebRouterStack-subdomain-mapping
```

## 最佳实践

1. **环境隔离**: 不同环境使用不同的策略
2. **定期清理**: 定期删除测试函数和角色
3. **监控使用**: 使用 CloudTrail 监控权限使用
4. **版本控制**: 将策略文件纳入版本控制

---
**文档版本**: v1.0  
**最后更新**: 2026-01-06  
**适用脚本**: deploy_lambda.py
