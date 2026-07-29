"""从 config.ini 渲染「组织内用户接入指引」ONBOARDING.md。

产物含真实 endpoint/client_id/账号相关值，故 gitignored——部署者跑本脚本
生成后自行分发（发飞书群/内部 wiki 均可）。指引面向两类读者：
人（照抄命令），以及被人要求"帮我接入建站平台"的 Agent（可直接执行）。
"""
import configparser
from pathlib import Path

ROOT = Path(__file__).parents[1]
# interpolation=None：endpoint_url 是 URL-encoded ARN，含 % 字符
CFG = configparser.ConfigParser(interpolation=None)
CFG.read(ROOT / "config.ini")

base = CFG["Platform"]["base_domain"]
endpoint = CFG["MCP"]["endpoint_url"]
client_id = CFG["Cognito"]["mcp_client_id"]
pool = CFG["Cognito"]["user_pool_id"]
region = CFG["Platform"]["region"]

assert endpoint and client_id, "config.ini [MCP]/[Cognito] 未回填——先完成 DEPLOY.md ①⑤"

OUT = ROOT / "ONBOARDING.md"
OUT.write_text(f"""# Site Builder 接入指引（组织内用户）

> 本文件由 `scripts/gen_onboarding.py` 从当前部署配置生成，含真实 endpoint。
> 面向两类读者：**人**（复制命令照做）与 **Agent**（可直接按步骤执行）。
> 接入后你可以在 Claude Code / Quick Desktop 里用自然语言建站并部署，
> 得到 `https://app-xxx.{base}` 的可分享 URL。

## 你需要具备

- 组织飞书账号，且**通讯录里已填邮箱**（设置→账号→邮箱可自查；没有邮箱
  无法识别站点归属，接入会失败）。
- 使用 Claude Code 接入时：本机已安装 Claude Code CLI。

## Claude Code 接入（推荐，全命令行）

在仓库根目录（或任何拿到 `site-builder/skills/` 目录拷贝的位置）执行：

```bash
# 1) 安装建站 Skill
mkdir -p ~/.claude/skills
cp -r site-builder/skills/site-builder ~/.claude/skills/

# 2) 注册部署 MCP（一字不改，直接复制）
claude mcp add --transport http site-builder-deploy \\
  "{endpoint}" \\
  --client-id {client_id} --callback-port 18765
```

3) 完成 OAuth：任意 Claude Code 会话里输入 `/mcp` → 选 `site-builder-deploy`
   → `Authenticate` → 浏览器弹出飞书登录，登录即完成。
   `claude mcp list` 显示 ✓ connected 即就绪。

4) 验证：新会话说一句
   > 用 site-builder 技能列出我部署的站点
   应返回列表（首次为空数组）。

## Quick Desktop 接入

Quick Desktop 的 Remote MCP 不支持 OAuth，需用仓库自带的本地 stdio 代理
（`site-builder/clients/quick-desktop-proxy/`，纯 Node 18+ 内置模块，免 install）：

1. 导入 Skill：把 `site-builder/skills/site-builder/` 整个目录复制到你的
   Quick profile 的 skills 目录（如 `~/.quickwork/profiles/{{profile}}/skills/`）。
2. 首次 OAuth（浏览器飞书登录，token 落盘后代理自动续期）：
   ```bash
   cd site-builder/clients/quick-desktop-proxy
   node auth.js "{endpoint}" "{client_id}"
   ```
3. 添加 MCP：Settings → Capabilities → MCP → Add，
   Connection type=**Local**，Command=`node`，Args（**不要加引号**——UI 字段
   不是 shell，引号会成为参数的一部分；URL 无空格，不需要引号）：
   ```
   /绝对路径/quick-desktop-proxy/index.js {endpoint} {client_id}
   ```
   若 Quick 的 Args 字段不接受多参数，改用环境变量（代理两种都认）：
   Args 只填脚本路径，Env 加 `SITE_BUILDER_MCP_ENDPOINT={endpoint}`
   与 `SITE_BUILDER_MCP_CLIENT_ID={client_id}`。

## 开始使用

对 Agent 说需求即可，例如：

> 用 site-builder 技能给我做一个团队值日表站点，能登记和换班，全组织可看，做完部署

Agent 会走完：需求澄清 → 生成代码 → 本地预览 → 部署 → 返回站点 URL。
站点访问权限在部署时声明（全组织可见 / 指定邮箱名单 / 完全公开）。

## 权限模型（你能做什么）

- 任何完成接入的人都能创建站点；站点归属（owner）自动绑定你的飞书邮箱。
- 你只能查看/更新/下线**自己**的站点；他人站点对你不可见。
- 下线默认保留数据；连数据一起删需要显式确认（不可恢复）。

## 常见错误对照

| 症状 | 原因与处置 |
|---|---|
| `claude mcp add` 报 "Incompatible auth server: does not support dynamic client registration" | 漏了 `--client-id`/`--callback-port` 参数，用上面的完整命令 |
| OAuth 回调页报 "port 8765 already in use" | 你改了 callback-port——必须用 18765（8765/8766 被 Quick Desktop 常驻占用） |
| 飞书授权走完，回调报 `invalid_request: Feishu Error - 500 internal_error` | 你的飞书账号在通讯录里没有邮箱：设置→账号→绑定邮箱后重试 |
| 工具调用报 "无法识别调用者身份" | 重新走一遍 `/mcp` Authenticate（token 过期或首次未授权） |
| PUT 上传 site.zip 报 403 SignatureDoesNotMatch | 上传命令带了 `Content-Type` 头；用 `curl -X PUT -T site.zip "<upload_url>"` 裸传 |

## 管理员参考（非用户操作）

- user pool：`{pool}`（{region}）；MCP client：`{client_id}`
- 用户侧问题排查入口：`site-builder/DEPLOY.md` ①（飞书邮箱/权限）、
  `site-builder/docs/client-setup.md`（逐客户端冒烟清单）
""", encoding="utf-8")
print(f"已生成 {OUT}（gitignored，自行分发）")
