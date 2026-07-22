# Application Web Router

A CloudFront-based dynamic subdomain routing system that uses Lambda@Edge and DynamoDB to route requests to different backend services based on subdomain.

## 🏗️ Architecture

```
User Request (api.example.com)
    ↓
CloudFront Distribution
    ↓
[Origin Request] Lambda@Edge
    └─ Query DynamoDB for subdomain mapping
    └─ Dynamically route to target backend
    ↓
Backend Service (Lambda URL / API Gateway / ALB)
```

## ✨ Features

- ✅ **Dynamic Routing**: Route requests based on subdomain without code changes
- ✅ **Full HTTP Support**: All HTTP methods (GET, POST, PUT, DELETE, etc.)
- ✅ **Transparent Routing**: URL in browser remains unchanged
- ✅ **SSL/TLS**: Automatic HTTPS with custom domain
- ✅ **Query String Preservation**: Complete URI and query string forwarding
- ✅ **DynamoDB Backend**: Flexible subdomain-to-backend mappings
- ✅ **Cost Optimized**: CloudFront Function for viewer-request (cheaper than Lambda@Edge)

## 📁 Project Structure

```
.
├── README.md
├── config.ini                          # Global configuration
├── config.ini.example                  # Configuration template
│
├── infrastructure/                     # CDK Infrastructure as Code
│   ├── stack.py                       # All-in-one CDK stack
│   ├── cdk.json                       # CDK configuration
│   ├── requirements.txt               # Python dependencies
│   │
│   └── lambda/                        # Lambda functions
│       └── origin_request.py         # Dynamic routing logic
│
├── scripts/                           # Deployment scripts
│   └── deploy_lambda.py              # Lambda deployment script
│
└── examples/                          # Example applications
    └── expressjs-demo/               # Express.js demo app
```

## 🚀 Quick Start

### Prerequisites

- AWS CLI configured with appropriate credentials
- Node.js 20+ and AWS CDK CLI installed
- Python 3.11+
- ACM certificate in `us-east-1` for your domain

### Installation

1. **Clone and navigate to project**
   ```bash
   cd manus-web-application
   ```

2. **Install Python dependencies**
   ```bash
   cd infrastructure
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure settings**
   
   Copy and edit the configuration file:
   ```bash
   cp config.ini.example config.ini
   # Edit config.ini with your AWS account details
   ```

   Key settings to update in `config.ini`:
   ```ini
   [AWS]
   account_id = YOUR_ACCOUNT_ID
   region = us-east-1

   [CloudFront]
   domain_name = *.your-domain.com
   certificate_arn = arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT_ID
   ```

   You can also override settings using environment variables:
   ```bash
   export APP_DOMAIN_NAME="*.your-domain.com"
   export APP_CERTIFICATE_ARN="arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT_ID"
   ```

4. **Bootstrap CDK** (first time only)
   ```bash
   cdk bootstrap aws://ACCOUNT_ID/us-east-1
   ```

5. **Deploy**
   ```bash
   cdk deploy
   ```

### Post-Deployment Setup

1. **Configure DNS**
   
   Add CNAME record in your DNS provider:
   ```
   *.your-domain.com → d1234abcd.cloudfront.net
   ```

2. **Add subdomain mappings**
   ```bash
   aws dynamodb put-item \
     --table-name subdomain-mapping \
     --region us-east-1 \
     --item '{
       "subdomain": {"S": "api"},
       "target_url": {"S": "https://api-backend.lambda-url.us-east-1.on.aws"}
     }'
   ```

## 📖 Usage Examples

### Add Subdomain Mapping

```bash
# Map 'app' subdomain to Lambda Function URL
aws dynamodb put-item \
  --table-name subdomain-mapping \
  --region us-east-1 \
  --item '{
    "subdomain": {"S": "app"},
    "target_url": {"S": "https://xyz123.lambda-url.us-east-1.on.aws"}
  }'

# Map 'api' subdomain to API Gateway
aws dynamodb put-item \
  --table-name subdomain-mapping \
  --region us-east-1 \
  --item '{
    "subdomain": {"S": "api"},
    "target_url": {"S": "https://api.execute-api.us-east-1.amazonaws.com"}
  }'
```

### Test Routing

```bash
# GET request
curl https://api.your-domain.com/users

# POST request with JSON body
curl -X POST https://api.your-domain.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com"}'

# Request with query parameters
curl https://api.your-domain.com/users?page=2&limit=10
```

### Update Mapping

```bash
aws dynamodb update-item \
  --table-name subdomain-mapping \
  --region us-east-1 \
  --key '{"subdomain": {"S": "api"}}' \
  --update-expression "SET target_url = :url" \
  --expression-attribute-values '{":url": {"S": "https://new-backend.com"}}'
```

### Delete Mapping

```bash
aws dynamodb delete-item \
  --table-name subdomain-mapping \
  --region us-east-1 \
  --key '{"subdomain": {"S": "api"}}'
```

## 🔍 How It Works

### 1. Viewer Request Stage (CloudFront Function)
- Executes at CloudFront edge locations
- Preserves original `Host` header as `X-Original-Host`
- Extremely fast and cost-effective

### 2. Origin Request Stage (Lambda@Edge)
- Reads `X-Original-Host` header
- Extracts subdomain (e.g., "api" from "api.example.com")
- Queries DynamoDB for target backend URL
- Dynamically modifies request origin
- Preserves original URI and query strings

### 3. CloudFront Distribution
- Fetches content from dynamic origin
- Returns response to user
- Browser URL remains unchanged

## 🛠️ Configuration

### Environment Variables

All configuration can be overridden using environment variables:

```bash
# Domain and SSL
export APP_DOMAIN_NAME="*.example.com"
export APP_CERTIFICATE_ARN="arn:aws:acm:us-east-1:123456789012:certificate/abc-123"

# DynamoDB
export APP_DYNAMODB_TABLE="my-subdomain-mappings"
export APP_DYNAMODB_REGION="us-east-1"

# Lambda@Edge
export APP_ORIGIN_REQUEST_FUNCTION_NAME="my-router-function"
export APP_LAMBDA_MEMORY_SIZE="256"
export APP_LAMBDA_TIMEOUT_SECONDS="10"

# CloudFront Function
export APP_VIEWER_REQUEST_FUNCTION_NAME="my-viewer-function"

# CloudFront
export APP_DEFAULT_ORIGIN="default.example.com"
export APP_ORIGIN_REQUEST_POLICY_NAME="MyCustomPolicy"

cdk deploy
```

### ⚠️ Stack Naming Important Notice

When modifying the stack name in `config.ini`, ensure the new name contains **"WebRouterStack"** string:

```ini
# ✅ Valid names (will work with minimal permissions)
stack_name = ApplicationWebRouterStack
stack_name = MyWebRouterStackV2
stack_name = ProdWebRouterStack2024

# ❌ Invalid names (will cause permission errors)
stack_name = MyAppStack
stack_name = RouterApplication
```

**Reason**: The minimal IAM policy uses `*WebRouterStack*` pattern matching for security. Names not containing this string will be denied access.

### ⚠️ Stack Naming Important Notice

When modifying the stack name in `config.ini`, ensure the new name contains **"WebRouterStack"** string:

```ini
# ✅ Valid names (will work with minimal permissions)
stack_name = ApplicationWebRouterStack
stack_name = MyWebRouterStackV2
stack_name = ProdWebRouterStack2024

# ❌ Invalid names (will cause permission errors)
stack_name = MyAppStack
stack_name = RouterApplication
```

**Reason**: The minimal IAM policy uses `*WebRouterStack*` pattern matching for security. Names not containing this string will be denied access.

### CDK Context

```bash
cdk deploy -c environment=staging
```

## 📊 Monitoring and Troubleshooting

### View Lambda@Edge Logs

Lambda@Edge logs are created in the region closest to where the function executed:

```bash
# Check logs in specific region
aws logs tail /aws/lambda/us-east-1.application-web-router \
  --region us-west-2 \
  --since 30m \
  --follow

# Find all log groups
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/us-east-1.application-web-router \
  --region us-east-1
```

### CloudFront Cache Invalidation

```bash
aws cloudfront create-invalidation \
  --distribution-id E1234ABCD5678 \
  --paths "/*"
```

### Common Issues

| Issue | Solution |
|-------|----------|
| 403 Forbidden | Check CloudFront allowed methods configuration |
| 404 Not Found | Verify subdomain mapping exists in DynamoDB |
| 502 Bad Gateway | Ensure target backend is accessible and healthy |
| Stale routing | Create CloudFront cache invalidation |

## 🔒 Security Best Practices

- ✅ Use HTTPS only (enforced by default)
- ✅ Minimum TLS 1.2 protocol
- ✅ IAM roles with least privilege
- ✅ DynamoDB encryption at rest (default)
- ✅ CloudFront access logs (optional, configure in stack)

## 💰 Cost Considerations

- **CloudFront**: Pay per request and data transfer
- **Lambda@Edge**: Pay per request and execution time
- **CloudFront Function**: ~1/6th the cost of Lambda@Edge
- **DynamoDB**: Pay per read (on-demand pricing)

Estimated cost for 1M requests/month: ~$1-5 USD

## 🧪 Testing

### Unit Test Lambda Function

```bash
cd infrastructure/lambda
python3 -m pytest test_origin_request.py
```

### Integration Test

```bash
# Test with curl
curl -v -H "Host: test.example.com" https://d1234abcd.cloudfront.net/

# Check response headers
curl -I https://test.example.com/api/health
```

### Lambda Web Adapter Testing Results

**⚠️ Known Issue**: Lambda Web Adapter (LWA) has systematic compatibility issues in the current Lambda environment.

#### Test Summary (December 2025)

We tested multiple official AWS Lambda Web Adapter examples with consistent failures:

| Example | Architecture | Result | Error Type |
|---------|-------------|---------|------------|
| Flask | x86_64 | ❌ Failed | `exec format error` |
| Nginx | x86_64 | ❌ Failed | Filesystem constraints |
| Express.js | x86_64 | ❌ Failed | `exec format error` |
| Gin (Go) | x86_64 | ❌ Failed | `exec format error` |

#### Common Issues

1. **Architecture Compatibility**: Even with `--platform linux/amd64`, LWA extension fails with:
   ```
   fork/exec /opt/extensions/lambda-adapter: exec format error
   ```

2. **Filesystem Constraints**: When LWA starts successfully, applications fail due to Lambda's read-only filesystem:
   ```
   nginx: [emerg] open() '/run/nginx.pid' failed (30: Read-only file system)
   ```

#### Build Commands Tested

```bash
# All failed with same errors
docker build --platform linux/amd64 -f Dockerfile.lambda -t test-image .
```

#### Alternative Solutions

For Express.js applications, use `@vendia/serverless-express` instead:

```dockerfile
FROM public.ecr.aws/lambda/nodejs:18
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
CMD ["lambda.handler"]
```

#### Deploy Lambda Script Usage

Use the `scripts/deploy_lambda.py` script to deploy Lambda functions with custom images:

```bash
# Deploy with custom image
python3 scripts/deploy_lambda.py --image ECR_IMAGE_URI --name FUNCTION_PREFIX

# Example: Deploy nginx demo
python3 scripts/deploy_lambda.py \
  --image {account_id}.dkr.ecr.us-east-1.amazonaws.com/expressjs-demo:nginx-demo-x86_64 \
  --name nginx-demo

# Example: Deploy expressjs demo  
python3 scripts/deploy_lambda.py \
  --image {account_id}.dkr.ecr.us-east-1.amazonaws.com/expressjs-demo:x86_64 \
  --name expressjs-test
```

**Parameters:**
- `--image` (required): ECR image URI to deploy
- `--name` (optional): Custom function name prefix (defaults to config value)

**What it does:**
1. Creates Lambda function with specified image
2. Creates Function URL with AWS_IAM authentication
3. Adds subdomain mapping to DynamoDB
4. Provides access URL via CloudFront distribution

## 🚧 Limitations

- Lambda@Edge must be deployed in `us-east-1`
- Lambda@Edge doesn't support environment variables
- Origin-request timeout: 30 seconds max
- Lambda@Edge code size: 1MB compressed, 50MB uncompressed
- Propagation time: 15-30 minutes for Lambda@Edge updates

## 🗑️ Cleanup

```bash
# Delete stack
cdk destroy

# Note: Lambda@Edge functions may take hours to fully delete
# due to CloudFront replication
```

## 📚 Additional Resources

- [AWS Lambda@Edge Documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-edge.html)
- [CloudFront Functions vs Lambda@Edge](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/edge-functions.html)
- [CDK Best Practices](https://docs.aws.amazon.com/cdk/latest/guide/best-practices.html)

## 📝 License

MIT

## 👥 Contributing

Contributions welcome! Please open an issue or submit a pull request.

---

**Built with ❤️ using AWS CDK**
