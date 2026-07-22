# CDK 最小化权限策略详细说明

本文档详细分析 `cdk-minimal-policy.json` 中每个权限的作用和必要性。

## 策略概述

该策略专为 CDK 部署设计，采用最小权限原则，仅授予完成 Web Router Stack 部署所需的最低权限。

## 权限详细分析

### 1. CloudFormation Stack 访问权限

```json
{
  "Sid": "CloudFormationStackAccess",
  "Resource": [
    "arn:aws:cloudformation:us-east-1:*:stack/*WebRouterStack*/*",
    "arn:aws:cloudformation:us-east-1:*:stack/CDKToolkit/*"
  ]
}
```

**作用**: CDK 部署的核心权限
- `CreateStack/UpdateStack/DeleteStack`: 创建、更新、删除 CloudFormation 堆栈
- `DescribeStacks/DescribeStackEvents/DescribeStackResources`: 查看堆栈状态和资源
- `CreateChangeSet/ExecuteChangeSet`: CDK 使用 ChangeSet 进行安全部署
- `ContinueUpdateRollback`: 处理部署失败时的回滚操作

**资源限制**: 仅限包含 `WebRouterStack` 的堆栈和 CDK 工具包堆栈

### 2. CloudFormation 全局访问权限

```json
{
  "Sid": "CloudFormationGlobalAccess",
  "Resource": "*"
}
```

**作用**: CDK 运行时必需的全局操作
- `ListStacks`: CDK 需要列出现有堆栈以避免命名冲突
- `ValidateTemplate`: 部署前验证 CloudFormation 模板语法

**为什么需要 `*`**: 这些操作不针对特定堆栈，必须使用全局权限

### 3. S3 CDK 资产存储权限

```json
{
  "Sid": "S3CDKAssets",
  "Resource": [
    "arn:aws:s3:::cdk-*",
    "arn:aws:s3:::cdk-*/*"
  ]
}
```

**作用**: CDK 资产管理
- `CreateBucket`: CDK 首次运行时创建资产存储桶
- `PutObject/GetObject`: 上传和下载 Lambda 代码、CloudFormation 模板等资产
- `PutBucketPolicy/PutBucketVersioning`: 配置存储桶安全策略
- `PutBucketPublicAccessBlock`: 确保存储桶不会意外公开

**资源限制**: 仅限 CDK 创建的存储桶（`cdk-` 前缀）

### 4. Lambda 函数访问权限

```json
{
  "Sid": "LambdaFunctionAccess",
  "Resource": [
    "arn:aws:lambda:us-east-1:*:function:*WebRouterStack*",
    "arn:aws:lambda:*:*:function:*WebRouterStack*"
  ]
}
```

**作用**: Lambda@Edge 函数管理
- `CreateFunction/UpdateFunctionCode`: 创建和更新 Lambda 函数
- `PublishVersion`: Lambda@Edge 需要发布版本才能与 CloudFront 关联
- `EnableReplication`: Lambda@Edge 特有权限，允许函数复制到边缘位置
- `AddPermission/RemovePermission`: 管理函数的资源策略

**资源限制**: 仅限项目相关的 Lambda 函数
**跨区域**: `*:*` 允许 Lambda@Edge 在所有区域操作

### 5. Lambda 全局访问权限

```json
{
  "Sid": "LambdaGlobalAccess",
  "Resource": "*"
}
```

**作用**: CDK 需要列出现有函数以避免命名冲突
**为什么需要 `*`**: `ListFunctions` 是全局操作，无法限制到特定资源

### 6. IAM 角色访问权限

```json
{
  "Sid": "IAMRoleAccess",
  "Resource": [
    "arn:aws:iam::*:role/*WebRouterStack*",
    "arn:aws:iam::*:role/cdk-*"
  ]
}
```

**作用**: 创建和管理 Lambda 执行角色
- `CreateRole/DeleteRole`: 创建 Lambda@Edge 执行角色
- `AttachRolePolicy/DetachRolePolicy`: 附加 AWS 托管策略
- `PutRolePolicy/DeleteRolePolicy`: 管理内联策略（如 DynamoDB 访问权限）

**资源限制**: 仅限项目角色和 CDK 相关角色

### 7. IAM PassRole 权限

```json
{
  "Sid": "IAMPassRole",
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": [
        "lambda.amazonaws.com",
        "edgelambda.amazonaws.com",
        "cloudformation.amazonaws.com"
      ]
    }
  }
}
```

**作用**: 允许将角色传递给 AWS 服务
**安全条件**: 仅允许传递给指定的 AWS 服务，防止权限提升攻击

### 8. DynamoDB 表访问权限

```json
{
  "Sid": "DynamoDBTableAccess",
  "Resource": [
    "arn:aws:dynamodb:us-east-1:*:table/*WebRouterStack*"
  ]
}
```

**作用**: 子域名映射表管理
- `CreateTable/DeleteTable`: 创建和删除 DynamoDB 表
- `DescribeTable/UpdateTable`: 查看和修改表配置
- `TagResource/UntagResource`: 管理表标签

**资源限制**: 仅限项目相关的 DynamoDB 表

### 9. CloudFront 分发访问权限

```json
{
  "Sid": "CloudFrontDistributionAccess",
  "Resource": "*"
}
```

**作用**: CloudFront 分发管理
- `CreateDistribution/UpdateDistribution/DeleteDistribution`: 分发生命周期管理
- `GetDistribution/GetDistributionConfig`: 查看分发配置

**为什么需要 `*`**: CloudFront 分发 ARN 在创建前未知，且 AWS 不支持基于名称的资源限制

### 10. CloudFront 策略访问权限

```json
{
  "Sid": "CloudFrontPolicyAccess",
  "Resource": "*"
}
```

**作用**: 缓存策略和源请求策略管理
- `CreateCachePolicy/CreateOriginRequestPolicy`: 创建自定义策略
- `UpdateCachePolicy/UpdateOriginRequestPolicy`: 更新策略配置

**为什么需要 `*`**: 策略 ARN 在创建前未知

### 11. CloudFront 全局访问权限

```json
{
  "Sid": "CloudFrontGlobalAccess",
  "Resource": "*"
}
```

**作用**: CDK 需要列出现有资源以避免冲突
**为什么需要 `*`**: 列表操作是全局的，无法限制到特定资源

### 12. ACM 证书访问权限

```json
{
  "Sid": "ACMCertificateAccess",
  "Resource": "*"
}
```

**作用**: SSL/TLS 证书管理
- `DescribeCertificate`: 验证证书状态和配置
- `ListCertificates`: 查找可用证书

**为什么需要 `*`**: CDK 需要查找现有证书，证书 ARN 通常通过配置提供

### 13. SSM 参数访问权限

```json
{
  "Sid": "SSMParameterAccess",
  "Resource": "arn:aws:ssm:us-east-1:*:parameter/cdk-bootstrap/*"
}
```

**作用**: CDK Bootstrap 配置访问
- `GetParameter/GetParameters`: 读取 CDK bootstrap 过程中创建的配置参数

**资源限制**: 仅限 CDK bootstrap 参数

### 14. ECR 访问权限

```json
{
  "Sid": "ECRAccess",
  "Resource": "*"
}
```

**作用**: 容器镜像访问（用于 Lambda 容器镜像）
- `GetAuthorizationToken`: 获取 ECR 登录令牌
- `BatchCheckLayerAvailability/GetDownloadUrlForLayer/BatchGetImage`: 下载镜像层

**为什么需要 `*`**: ECR 认证令牌是全局的，镜像拉取操作需要访问多个 ECR 仓库

## 安全特性

### 1. 资源限制
- 使用 `*WebRouterStack*` 模式匹配，限制操作范围
- CDK 相关资源使用 `cdk-*` 前缀限制

### 2. 条件限制
- IAM PassRole 使用服务条件，防止权限提升

### 3. 区域限制
- 大部分资源限制在 `us-east-1`（Lambda@Edge 要求）
- Lambda@Edge 允许跨区域复制

### 4. 最小权限原则
- 仅包含 CDK 部署必需的权限
- 避免使用过于宽泛的权限

## 使用建议

1. **命名规范**: 确保 stack 名称包含 `WebRouterStack` 字符串
2. **定期审计**: 定期检查权限使用情况
3. **环境隔离**: 不同环境使用不同的策略实例
4. **监控告警**: 设置 CloudTrail 监控权限使用

## 故障排除

### 常见权限错误
- **Stack 名称不匹配**: 确保包含 `WebRouterStack`
- **区域错误**: Lambda@Edge 必须在 us-east-1 部署
- **证书问题**: ACM 证书必须在 us-east-1 区域

### 权限验证
```bash
# 测试权限是否足够
AWS_PROFILE=cdk-deploy cdk diff
AWS_PROFILE=cdk-deploy cdk deploy --dry-run
```