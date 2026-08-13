"""从 config.ini 渲染「组织内用户接入指引」ONBOARDING.md。

产物含真实 endpoint/client_id/账号相关值，故 gitignored——部署者跑本脚本
生成后自行分发（发飞书群/内部 wiki 均可）。指引面向两类读者：
人（照抄命令），以及被人要求"帮我接入建站平台"的 Agent（可直接执行）。
"""
import configparser
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
# 组件启用判定走**唯一真源**（三个部署脚本用的是同一个函数）——在这里再写一次
# `has_section("ApiKey")` 就是第四个判定点
sys.path.insert(0, str(ROOT / "deployer" / "functions"))
import api_key_config                                    # noqa: E402
# interpolation=None：endpoint_url 是 URL-encoded ARN，含 % 字符
CFG = configparser.ConfigParser(interpolation=None)
CFG.read(ROOT / "config.ini")

base = CFG["Platform"]["base_domain"]
endpoint = CFG["MCP"]["endpoint_url"]
client_id = CFG["Cognito"]["mcp_client_id"]
pool = CFG["Cognito"]["user_pool_id"]
region = CFG["Platform"]["region"]
# 两条客户端通道都走这个 stdio 代理（Claude Code 直连会因 RFC 8707 resource
# 参数被 Cognito 拒，Quick Desktop 的 Remote MCP 不支持 OAuth）。
# 用绝对路径：用户可能从任意目录跑生成出的命令。
proxy_dir = ROOT / "clients/quick-desktop-proxy"

assert endpoint and client_id, "config.ini [MCP]/[Cognito] 未回填——先完成 DEPLOY.md ①⑤"

# API Key 章节只在组件启用时出现。**不启用时一个字都不提**：写"本平台未启用"
# 只会让读者去问"那怎么启用"，而那是部署者的决定，不是用户能做的事。
if api_key_config.api_key_enabled(CFG):
    _mcp_host = f"{api_key_config.mcp_subdomain(CFG)}.{base}"
    api_key_section = f"""## Quick Desktop 免代理接入（Remote MCP + API Key）

本平台启用了 API Key，所以 Quick Desktop 可以**不用**上面那个 stdio 代理：

1. 打开 `https://console.{base}/` 的 **API Key** 页面，点"创建"。
   **明文只显示这一次**——服务端不保存明文，抄漏了只能吊销重发。
2. Settings → Capabilities → MCP → Add，Connection type = **Remote**：
   - URL：`https://{_mcp_host}/`
   - Headers：`X-API-Key: 你刚创建的那把`
3. 不需要 Node、不需要 `auth.js`、不需要本机进程常驻。

两条路径的身份语义完全一致：Key 绑定创建它的人的邮箱，经它部署的站点 owner
就是你。别人拿到你的 Key 就等于拿到你的身份——**像密码一样保管**，可疑时立刻
去同一个页面吊销（立即生效）。

"""
else:
    api_key_section = ""

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

**MCP 走本地 stdio 代理，不要用 HTTP transport 直连**：Claude Code 会在 OAuth
请求里带 RFC 8707 的 `resource` 参数，而 Cognito 不支持——授权页能走完但换
token 报 `invalid_grant`，状态卡在 `! Needs authentication`（2026-08-06 实测）。

```bash
# 1) 安装建站 Skill
mkdir -p ~/.claude/skills
cp -r site-builder/skills/site-builder ~/.claude/skills/

# 2) 授权一次（浏览器飞书登录，token 落盘 ~/.site-builder-deploy-token.json）
node {proxy_dir}/auth.js \\
  "{endpoint}" \\
  "{client_id}"

# 3) 注册部署 MCP（stdio 形态；URL 与 client_id 必须是两个独立参数）
claude mcp add site-builder-deploy -- \\
  node {proxy_dir}/index.js \\
  "{endpoint}" \\
  "{client_id}"
```

4) **重启 Claude Code**（stdio server 在启动时加载），然后 `/mcp` 应显示 8 个
   工具、不再要求授权。若显示需要认证，检查配置里存的是 **3 个** args
   （脚本路径 / endpoint / client_id）——shell 引号有时会把后两个粘成一个。

5) 验证：新会话说一句
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
3. 添加 MCP（两种方式，推荐直接编辑配置文件——零歧义）：

   **方式 a：编辑 `~/.quickwork/profiles/{{profile}}/mcp_config.json`**，
   在 `mcpServers` 下加一项后重启 Quick Desktop（args 是 JSON 数组，
   每个元素精确对应一个 argv）：
   ```json
   "site-builder-deploy": {{
     "command": "node",
     "args": ["/绝对路径/quick-desktop-proxy/index.js",
              "{endpoint}",
              "{client_id}"]
   }}
   ```

   **方式 b：UI 表单**（Settings → Capabilities → MCP → Add）：
   Connection type=**Local**，Command=`node`，Args 一行填：
   ```
   /绝对路径/quick-desktop-proxy/index.js {endpoint} {client_id}
   ```
   Args 字段按类 shell 规则解析（空格拆分、引号剥除）——URL 无空格，
   带不带引号都可以。UI 也有 env 区域，等价写法：Args 只填脚本路径，
   env 设 `SITE_BUILDER_MCP_ENDPOINT` / `SITE_BUILDER_MCP_CLIENT_ID`
   （代理 argv 与环境变量两种都认）。

{api_key_section}## 开始使用

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
