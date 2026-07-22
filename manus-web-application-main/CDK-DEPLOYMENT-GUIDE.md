# CDK 部署最小化权限用户指南

## 概述

本指南提供了为 CDK 部署创建最小化权限用户的完整流程，确保安全性的同时满足部署需求。

## 已创建的资源

### IAM 用户
- **用户名**: `cdk-deploy-user`
- **ARN**: `arn:aws:iam::{account_id}:user/cdk-deploy-user`
- **用途**: 专门用于 CDK 部署的最小权限用户

### IAM 策略
- **策略名**: `CDKMinimalDeployPolicy`
- **ARN**: `arn:aws:iam::{account_id}:policy/CDKMinimalDeployPolicy`
- **文件**: `cdk-minimal-policy.json`

### 访问密钥
- **Access Key ID**: `<YOUR_ACCESS_KEY_ID>`
- **Secret Access Key**: `<YOUR_SECRET_ACCESS_KEY>`

## 权限范围

该策略包含以下最小化权限：

### 核心服务
- **CloudFormation**: 限制到 `ApplicationWebRouterStack*` 和 `CDKToolkit` 堆栈
- **S3**: 仅 CDK 资产存储桶 (`cdk-*`)
- **Lambda**: 限制到项目函数 (`ApplicationWebRouterStack*`)
- **IAM**: 限制到项目角色，带 PassRole 条件

### 应用服务
- **DynamoDB**: 限制到项目表 (`ApplicationWebRouterStack*`)
- **CloudFront**: 分发和策略管理权限
- **ACM**: 证书查看权限
- **ECR**: 镜像拉取权限

### 支持服务
- **SSM**: CDK bootstrap 参数访问权限

## 本地配置

### AWS CLI 配置文件
```bash
# 配置文件名: cdk-deploy
aws configure set aws_access_key_id <YOUR_ACCESS_KEY_ID> --profile cdk-deploy
aws configure set aws_secret_access_key <YOUR_SECRET_ACCESS_KEY> --profile cdk-deploy
aws configure set region us-east-1 --profile cdk-deploy
aws configure set output json --profile cdk-deploy
```

### 使用方法
```bash
# 验证身份
aws sts get-caller-identity --profile cdk-deploy

# CDK Bootstrap
AWS_PROFILE=cdk-deploy cdk bootstrap aws://ACCOUNT_ID/us-east-1

# CDK 部署
AWS_PROFILE=cdk-deploy cdk deploy --require-approval never

# CDK 销毁
AWS_PROFILE=cdk-deploy cdk destroy
```

## 部署验证

### 成功部署的资源
- ✅ CloudFormation 堆栈: `ApplicationWebRouterStackV2`
- ✅ Lambda@Edge 函数: `ApplicationWebRouterStackV2-application-web-router`
- ✅ DynamoDB 表: `ApplicationWebRouterStackV2-subdomain-mapping`
- ✅ CloudFront 分发: `E26PBD1NHVPUW`
- ✅ 分发域名: `d23gw984x70vq1.cloudfront.net`

### 验证命令
```bash
# 查看堆栈状态
AWS_PROFILE=cdk-deploy aws cloudformation describe-stacks --stack-name ApplicationWebRouterStackV2 --region us-east-1

# 查看 Lambda 函数
AWS_PROFILE=cdk-deploy aws lambda get-function --function-name ApplicationWebRouterStackV2-application-web-router --region us-east-1

# 查看 DynamoDB 表
AWS_PROFILE=cdk-deploy aws dynamodb describe-table --table-name ApplicationWebRouterStackV2-subdomain-mapping --region us-east-1

# 查看 CloudFront 分发
AWS_PROFILE=cdk-deploy aws cloudfront get-distribution --id E26PBD1NHVPUW
```

## 安全建议

### 访问密钥管理
1. **定期轮换**: 建议每 90 天轮换一次访问密钥
2. **安全存储**: 使用 AWS Secrets Manager 或其他密钥管理服务
3. **最小权限**: 仅在需要时使用，部署完成后可暂时禁用

### 权限审计
```bash
# 查看用户附加的策略
AWS_PROFILE=cdk-deploy aws iam list-attached-user-policies --user-name cdk-deploy-user

# 查看策略详情
AWS_PROFILE=cdk-deploy aws iam get-policy --policy-arn arn:aws:iam::{account_id}:policy/CDKMinimalDeployPolicy
```

## 清理资源

### 删除部署资源
```bash
# 删除 CDK 堆栈
AWS_PROFILE=cdk-deploy cdk destroy

# 删除 CDK Bootstrap 资源（可选）
AWS_PROFILE=cdk-deploy aws cloudformation delete-stack --stack-name CDKToolkit --region us-east-1
```

### 删除 IAM 资源
```bash
# 删除访问密钥
aws iam delete-access-key --user-name cdk-deploy-user --access-key-id <YOUR_ACCESS_KEY_ID>

# 分离策略
aws iam detach-user-policy --user-name cdk-deploy-user --policy-arn arn:aws:iam::{account_id}:policy/CDKMinimalDeployPolicy

# 删除用户
aws iam delete-user --user-name cdk-deploy-user

# 删除策略
aws iam delete-policy --policy-arn arn:aws:iam::{account_id}:policy/CDKMinimalDeployPolicy
```

## 故障排除

### 常见问题
1. **权限不足**: 检查策略是否正确附加到用户
2. **区域错误**: 确保使用 us-east-1 区域（Lambda@Edge 要求）
3. **证书问题**: 确保 ACM 证书在 us-east-1 区域且状态为已颁发

### 日志查看
```bash
# CloudFormation 事件
AWS_PROFILE=cdk-deploy aws cloudformation describe-stack-events --stack-name ApplicationWebRouterStackV2 --region us-east-1

# Lambda@Edge 日志（需要在执行区域查看）
AWS_PROFILE=cdk-deploy aws logs describe-log-groups --log-group-name-prefix /aws/lambda/us-east-1.ApplicationWebRouterStackV2 --region us-east-1
```

## 联系信息

如有问题，请联系系统管理员或查看 AWS 文档。

---
**创建时间**: 2026-01-05  
**测试状态**: ✅ 已验证  
**适用版本**: CDK v2.x  
**策略版本**: v4 (通用版本，无硬编码账户ID)
