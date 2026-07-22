#!/usr/bin/env bash
# 路由层冒烟：无 auth 静态路由 / 有 auth 302 / 未知子域 404
set -euo pipefail
BASE_DOMAIN=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['base_domain'])")
TABLE=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Platform']['routing_table'])")
BUCKET=$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('site-builder/config.ini');print(c['Deployer']['frontend_bucket'].replace('{account_id}',c['Platform']['account_id']))")

echo "hello-router" > /tmp/index.html
echo "hello-other" > /tmp/index2.html
aws s3 cp /tmp/index.html "s3://${BUCKET}/sites/smoke/job-smoke1/index.html"
aws s3 cp /tmp/index2.html "s3://${BUCKET}/sites/smoke2/job-smoke2/index.html"
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smoke"},"site_id":{"S":"smoke"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke/job-smoke1"},"api_target":{"S":""},
  "require_auth":{"BOOL":false},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smoke2"},"site_id":{"S":"smoke2"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke2/job-smoke2"},"api_target":{"S":""},
  "require_auth":{"BOOL":false},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
aws dynamodb put-item --table-name "$TABLE" --item '{
  "subdomain":{"S":"app-smokeauth"},"site_id":{"S":"smoke"},"route_mode":{"S":"split"},
  "static_prefix":{"S":"sites/smoke/job-smoke1"},"api_target":{"S":""},
  "require_auth":{"BOOL":true},"allowed_users":{"S":"org"},"owner":{"S":"smoke@test"}}'
sleep 65  # 等 Edge 路由缓存过期

test "$(curl -s https://app-smoke.${BASE_DOMAIN}/)" = "hello-router" && echo "PASS: static route"
# 不同子域同路径内容不串（缓存已禁用的行为验证）
test "$(curl -s https://app-smoke2.${BASE_DOMAIN}/)" = "hello-other" && echo "PASS: no cross-site cache"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' https://app-smokeauth.${BASE_DOMAIN}/)
[[ "$LOC" == https://auth.${BASE_DOMAIN}/login* ]] && echo "PASS: auth 302"
# auth 子域全路径路由到认证 Lambda（api-only 模式，从公网地址验证而非 Function URL 直连）
ALOC=$(curl -s -o /dev/null -w '%{redirect_url}' "https://auth.${BASE_DOMAIN}/login?redirect=https://app-smoke.${BASE_DOMAIN}/")
[[ "$ALOC" == *"/oauth2/authorize"* ]] && echo "PASS: auth subdomain api-only routing"
CODE=$(curl -s -o /dev/null -w '%{http_code}' https://app-nonexistent.${BASE_DOMAIN}/)
[[ "$CODE" == "404" ]] && echo "PASS: unknown 404"
# 路由更新即时生效（无缓存）：切 static_prefix 后 65 秒内可见新内容
aws dynamodb update-item --table-name "$TABLE" \
  --key '{"subdomain":{"S":"app-smoke"}}' \
  --update-expression "SET static_prefix = :p" \
  --expression-attribute-values '{":p":{"S":"sites/smoke2/job-smoke2"}}'
sleep 65
test "$(curl -s https://app-smoke.${BASE_DOMAIN}/)" = "hello-other" && echo "PASS: route update visible"
