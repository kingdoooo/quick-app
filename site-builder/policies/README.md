# 账号级加固（可选）——`scp-site-invoke-only-edge.json`

这个目录里的东西**不是部署的一部分**，也**不是任何缺陷的修复**。它是一份给运维照抄的
SCP 模板，用来收窄"同账号 principal 直接调用站点 Lambda"这条路。贴不贴都能正常运行。

## 它想解决什么，以及它解决不了什么

站点的鉴权全在边缘：Edge 验会话 cookie、按 `allowed_users` 放行、注入
`x-user-email`，站点代码零 auth 逻辑。这条链的前提是"带着 `x-user-email` 进来的请求
必然来自 Edge"。而 AWS 的规则是：**同账号 principal 只要自己的 identity policy 允许
`lambda:InvokeFunctionUrl` + `lambda:InvokeFunction`，就无需命中 resource policy 也能
调用**。于是同账号里任何拿到这两个动作的身份都能绕过 Edge。

有两条绕过路径，**代码只挡得住第二条**：

| | 路径 | 攻击者控制什么 | 代码能挡吗 |
|---|---|---|---|
| **Path A** | 直接 `lambda:Invoke`（不经 Function URL） | **整个 payload**，包括 `requestContext.authorizer.iam.callerId` | **挡不住** |
| **Path B** | 经 Function URL 调用（SigV4 签名） | 请求头与 body；`callerId` 由 **STS** 填写，调用方不可伪造 | 挡得住（`functions/edge_caller.py`） |

Path A 在 2026-08-15 对 `site-panel` 实测过：手工构造整个事件、把 `callerId` 伪造成
Edge 角色的 RoleId，`/api/me` 返回 200 且被识别成管理员。**这不是理论风险。**
`edge_caller.py` 读的就是 payload 里的那个字段，所以它在 Path A 下天然被绕过——它的
价值只在 Path B（那里 `callerId` 由 STS 填、伪造不了）。

**真正能关掉 Path A 的只有账号级 IAM 收窄**：让同账号里除 Edge / 部署器 / 面板之外
的身份根本没有 `lambda:InvokeFunction` on 站点函数。SCP 是实现它的一种办法。

## 三条边界（贴之前必须读）

### ① SCP 对 Organizations **管理账号无效**

这是 AWS 的硬规则：SCP 不作用于管理账号里的任何身份，**包括 root**。
**本部署所在的账号就是管理账号**，所以在这里贴上这份 SCP，对本账号里的 IAM 身份
**一点约束都没有**。想让它真的生效，得先把工作负载搬到成员账号（OU 下），或者改用
别的手段（per-identity policy boundary、把站点函数搬到独立账号）。

**所以：贴了这份 SCP 不等于 Path A 被关闭。** 这一条是本文件存在的首要理由。

### ② `site-*` 通配会把控制面一起封死

平台自己的函数与用户站点**共用 `site-` 命名空间**：`site-panel`、`site-auth-service`、
`site-key-proxy`、`site-access-rollup`，以及 `site-deployer-*` 那一批。一个
`Resource: "arn:aws:lambda:*:*:function:site-*"` 的 Deny 会同时命中它们，后果是
**所有部署与下线立刻失效**（Step Functions 用 IAM 角色调 `site-deployer-*`；panel 调
`site-deployer-undeploy`）。**plan v1 就是因为这个范围被驳回的。**

所以模板里的 `Resource` 是一个**显式列表占位符** `{user_site_function_arns}`，不是通配。
生成办法（**排除平台函数**，只留用户站点）：

```bash
# 平台函数名的真源是 site-builder/deployer/infra/app.py 的 PLATFORM_FUNCTION_NAMES
PLATFORM=$(python3 - <<'PY'
import ast, pathlib
src = pathlib.Path("site-builder/deployer/infra/app.py").read_text()
for n in ast.parse(src).body:
    if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PLATFORM_FUNCTION_NAMES":
        print("|".join(e.value for e in n.value.elts)); break
PY
)
aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `site-`)].FunctionArn' \
  --output text | tr '\t' '\n' | grep -Ev ":function:($PLATFORM)$"
```

把输出贴进 `Resource`（JSON 数组）。**每次新建站点都要重新生成并更新 SCP** —— 这是
显式列表的代价，也是它可判定的原因。（宁可维护一张列表，也不要一个会封死控制面的通配。）

### ③ 通配"可判定"的前提是站点名保留前缀（Task A3）

`RESERVED_SITE_NAME_PREFIXES`（`deployer/functions/common.py`）禁止用户把站点命名成
`panel` / `auth` / `key-proxy` / `access` / `deployer` / `runtime` / `rt` 或以它们加连字符
开头。没有这条，用户可以建一个叫 `panel` 的站点产出 `site-panel-x1y2z3`，于是"按前缀
区分平台与用户"这件事本身不成立。A3 之后前缀才是可判定的——**但即便可判定，本模板
仍然用显式列表**，因为可判定只保证"能写对通配"，不保证"写对了"。

## 例外名单里那三个角色，各自为什么必须在

| 角色 | 为什么 |
|---|---|
| `{edge_role_name}`（Lambda@Edge 执行角色） | 它是唯一合法的站点调用方。漏了它 = 所有站点 403。 |
| `site-deployer-exec-role` | **M7 的健康门会直接 invoke 候选颜色**（`deploy_lambda_site._health_check` 带 `Qualifier`）。漏了它 = 每次部署都在健康门失败。 |
| `{panel_role_name}` | 防御性列入：panel 触发下线走的是 `site-deployer-undeploy`（平台函数，本来就不在 `Resource` 里）。若你把资源列表扩大到包含平台函数（**不推荐**，见边界②），它必须在例外里。 |

**`aws:PrincipalArn` 的形态要在目标账号里先验一次再贴。** 对 assumed-role 会话，这个
键的取值（角色 ARN 还是 `assumed-role/.../session`）取决于调用形态；模板用
`ArnNotLike` 是为了容忍两种写法，但**写错的后果是把平台自己锁在外面**。贴之前用
IAM policy simulator 或先挂到一个空 OU 上试，别直接上生产 OU。

## 结论

- 这份模板是**纵深防御**，不是 Path A 的修复；
- 在**管理账号**里它不生效，而本部署就在管理账号；
- 资源必须是显式列表；用 `site-*` 通配会封死控制面。

`functions/edge_caller.py` 的模块 docstring 里有同一组结论的简版，两处说法应一致。
