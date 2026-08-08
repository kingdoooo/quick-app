#!/usr/bin/env bash
# 核对**已部署的 Edge 产物**是否就是本地这份源码构建出来的。
#
# 为什么必须查产物而不是本地源码：Lambda@Edge 不支持环境变量，配置（表名、
# JWT 密钥、开关）由 CDK 在部署时**字符串替换**注入。于是有三类事故本地完全
# 看不出来：
#   ① SSM 读取失败 → 注入的是 SYNTH-ONLY-PLACEHOLDER → 线上所有会话验签失败；
#   ② 用了陈旧 cdk.out → 部署出去的是上一版代码，而 git 显示已修复；
#   ③ CloudFront 仍指向旧 Lambda 版本 → 新版本存在但没有流量走它。
# 「测试全绿 + git 已提交」对这三类一点保护都没有——只有下载产物逐行比对才行。
#
# 用法：
#   ./verify_deployed_edge.sh            # 核对 CloudFront 当前实际关联的版本
#   ./verify_deployed_edge.sh 5          # 核对指定版本号
#
# ⚠️ **不要按"版本号最大/时间最新"去挑版本，用默认的分发关联版本**。
# Lambda@Edge 的旧版本要等全球副本排空才能删，CDK 期间会出现多次
# `DELETE_FAILED (skipped)`，**旧版本的 LastModified 可能因此比新版本更晚**
# （2026-08-08 实测：v4 的时间戳晚于 v5，而 CloudFront 关联的是 v5）。
# 拿旧版本号当参数跑本脚本会得到一个**正确的** FAIL——那是旧代码，不是回归。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/router/infrastructure/lambda/origin_request.py"
CFG="$ROOT/router/config.ini"
REGION="us-east-1"      # Lambda@Edge 硬约束
FAILURES=0
fail() { echo "FAIL  $1"; FAILURES=$((FAILURES + 1)); }

[ -f "$SRC" ] || { echo "找不到源码 $SRC"; exit 1; }

# **键缺失必须硬失败**，不能返回空串让调用方回落硬编码值：本项目的规则是
# config.ini 是唯一取值来源，而"回落到刚好等于本环境的字面量"会让脚本在这里
# 一直"能用"、换个账号就悄悄验错对象（2026-08-08 独立审查指出：原实现读的
# `[Stack]` 段根本不存在——真实段名是 `[CDK]`——却因回落而无人发现）。
read_cfg() {  # $1=section $2=key
  python3 - "$CFG" "$1" "$2" <<'PY'
import configparser, sys
c = configparser.ConfigParser(interpolation=None)
c.read(sys.argv[1])
try:
    print(c[sys.argv[2]][sys.argv[3]].split("#")[0].split(";")[0].strip())
except KeyError:
    sys.exit(f"config.ini 缺少 [{sys.argv[2]}] {sys.argv[3]}")
PY
}

FN="$(read_cfg LambdaEdge origin_request_function_name)"
STACK="$(read_cfg CDK stack_name)"     # 段名是 [CDK]，不是 [Stack]
FUNCTION="$STACK-$FN"
# distribution id 不在 config.ini 里（那份只放输入，不放产出），从栈的
# CfnOutput 取——这也顺带保证我们查的是**这个栈**当前的分发，而不是手抄的旧值。
DIST_ID="$(aws cloudformation describe-stacks --stack-name "$STACK" \
            --region "$REGION" \
            --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue | [0]" \
            --output text 2>/dev/null || echo "")"
[ "$DIST_ID" = "None" ] && DIST_ID=""

echo "── ① 定位要核对的版本 ────────────────────────────"
QUALIFIER="${1:-}"
if [ -z "$QUALIFIER" ]; then
  # **默认核对 CloudFront 真正关联的那个版本**，不是 $LATEST：
  # 部署成功但分发仍指向旧版本时，只查最新版本会得出"已生效"的错误结论。
  if [ -z "$DIST_ID" ]; then
    # 别把操作者指向一个不存在的配置键：id 是从栈的 CfnOutput DistributionId
    # 取的（见上），取不到通常是栈名不对、凭证不对或栈还没建好。
    echo "取不到栈 $STACK 的 CfnOutput DistributionId —— 无法确认分发关联的版本"
    echo "  · 确认栈名与 router/config.ini 的 [CDK] stack_name 一致、凭证可用"
    echo "  · 或显式传版本号（注意：那样就不校验分发是否真的指向它）：$0 <version>"
    exit 1
  fi
  ARN="$(aws cloudfront get-distribution-config --id "$DIST_ID" \
          --query "DistributionConfig.DefaultCacheBehavior.LambdaFunctionAssociations.Items[?EventType=='origin-request'].LambdaFunctionARN | [0]" \
          --output text 2>/dev/null || echo "")"
  case "$ARN" in
    *:[0-9]*) QUALIFIER="${ARN##*:}" ;;
    *) echo "取不到 origin-request 关联的 Lambda ARN（得到 '$ARN'）"; exit 1 ;;
  esac
  echo "  CloudFront $DIST_ID 的 origin-request 关联版本 = $QUALIFIER"
else
  echo "  按参数核对版本 = ${QUALIFIER}（注意：可能不是分发实际使用的版本）"
fi

echo "── ② 下载该版本的部署产物 ────────────────────────"
TMP="$(mktemp -d -t edgecheck.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
LOC="$(aws lambda get-function --function-name "$FUNCTION" \
        --qualifier "$QUALIFIER" --region "$REGION" \
        --query 'Code.Location' --output text)"
# 预签名 URL 偶发 reset，重试几次（--retry 只对部分错误生效，故加 --retry-all-errors）
curl -sSL --retry 3 --retry-all-errors -o "$TMP/code.zip" "$LOC"
unzip -o -q "$TMP/code.zip" -d "$TMP"
[ -f "$TMP/index.py" ] || { echo "产物里没有 index.py"; exit 1; }
# 变量后紧跟全角括号时**必须加花括号**：bash 把 `（` 当成变量名的一部分，
# 报 `QUALIFIER（: unbound variable`（set -u 下直接中断）。中文注释/输出里
# 这个坑很容易踩。
echo "  已取到 ${FUNCTION}:${QUALIFIER}（$(wc -c <"$TMP/code.zip") 字节）"

echo "── ③ 逐行比对：产物必须 == 源码经占位符替换 ───────"
# 只允许差异出现在**含占位符的行**上。行数不同、或出现非占位符差异，都说明
# 部署出去的不是这份源码（陈旧 cdk.out / 手改过线上代码 / 版本搞错）。
if ! python3 - "$SRC" "$TMP/index.py" <<'PY'
import re, sys
src = open(sys.argv[1]).read().splitlines()
dep = open(sys.argv[2]).read().splitlines()
if len(src) != len(dep):
    sys.exit(f"FAIL  行数不一致：源码 {len(src)} / 产物 {len(dep)}"
             " —— 产物不是这份源码构建的（多半用了陈旧 cdk.out）")
ph_re = re.compile(r"\{\{[A-Z_]+\}\}")
other = [(i + 1, a, b) for i, (a, b) in enumerate(zip(src, dep))
         if a != b and not ph_re.search(a)]
if other:
    for n, a, b in other[:10]:
        print(f"FAIL  L{n} 非占位符差异\n      源码={a.strip()[:70]!r}\n      产物={b.strip()[:70]!r}")
    sys.exit(1)
n_ph = sum(1 for a, b in zip(src, dep) if a != b)
print(f"PASS  产物 == 源码（{len(src)} 行，{n_ph} 处差异全部是占位符替换）")
PY
then FAILURES=$((FAILURES + 1)); fi

echo "── ④ 注入值与安全开关 ───────────────────────────"
if grep -q "SYNTH-ONLY-PLACEHOLDER" "$TMP/index.py"; then
  fail "产物含 SYNTH-ONLY-PLACEHOLDER —— SSM 读取失败，线上所有会话验签都会失败"
else
  echo "PASS  无 SYNTH-ONLY-PLACEHOLDER"
fi
# 占位符一个都不该残留（不只 SYNTH 那个）
LEFT="$(grep -o '{{[A-Z_]*}}' "$TMP/index.py" | sort -u | tr '\n' ' ' || true)"
if [ -n "$LEFT" ]; then
  fail "产物里仍有未替换的占位符: $LEFT"
else
  echo "PASS  占位符全部已替换"
fi
# 安全开关必须是收紧值。**按整行断言**，避免注释里的同名字样蒙混过关。
if grep -qE '^REQUIRE_IDP_CLAIM = "true"' "$TMP/index.py"; then
  echo "PASS  REQUIRE_IDP_CLAIM = \"true\""
else
  fail "REQUIRE_IDP_CLAIM 不是 \"true\"：$(grep -E '^REQUIRE_IDP_CLAIM' "$TMP/index.py" || echo '未找到')"
fi
# **必须锚在被替换的那个字面量上**。`.*"[^"]+"` 是不够的：源码行是
#   TRUSTED_IDPS = tuple(x.strip() for x in "{{TRUSTED_IDPS}}".split(",") …)
# 空替换后变成 `for x in "".split(",")`，而 `"[^"]+"` 会匹配到后面那个 `","`
# 字面量 —— 于是"白名单为空"这个**全站锁死**的配置被判成 PASS
# （2026-08-08 独立审查发现并实测）。
if grep -qE '^TRUSTED_IDPS = tuple\(x\.strip\(\) for x in "[^"]+"\.split' "$TMP/index.py"; then
  echo "PASS  $(grep -E '^TRUSTED_IDPS = ' "$TMP/index.py")"
else
  fail "TRUSTED_IDPS 为空 —— REQUIRE_IDP_CLAIM=true 且白名单为空 = 全站锁死"
fi
# fail-closed 哨兵：本轮修复的核心，必须真在产物里。
# **按赋值语句与实际使用点断言，不用裸 grep**：`_UNKNOWN` 在源码里也出现在
# 注释与 docstring 中（origin_request.py 有 3 处，其中 2 处是说明文字），
# 裸 grep 时"回滚了代码但留着解释性注释"照样 PASS——这正是前几轮栽过的
# "断言的字样只活在注释里"那个坑。
if grep -qE '^_UNKNOWN = _Unknown\(\)' "$TMP/index.py" \
   && grep -qE 'out\[k\] = _UNKNOWN' "$TMP/index.py"; then
  echo "PASS  _deser 的 _UNKNOWN fail-closed 哨兵在产物中（赋值与使用点都在）"
else
  fail "产物里没有 _UNKNOWN 的赋值或使用点 —— 部署的是 fail-open 的旧代码"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
  echo "结果：$FAILURES 项未达预期 —— 线上 Edge 与预期不一致，先排查再继续"
  exit 1
fi
echo "结果：已部署的 Edge（版本 ${QUALIFIER}）与本地源码一致，安全开关到位"
