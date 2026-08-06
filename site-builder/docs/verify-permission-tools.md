# 权限三件套真机验证清单

`update_site_permissions` / `manage_collaborators` / `get_site_permissions`
已部署上线但**从未真机调用过**（M1/M2 的收尾缺口，计划里属 Task 12 的后半）。
`verify_mcp_iam_scope.sh` 验的是 runtime 角色的 IAM 边界，不是工具行为。

**为什么必须真机**：这三个工具的写入是 sites 表（真源）+ 路由表（Edge 读的投影）
的原子双写，还带 `permissions_rev` 并发条件与 admin 代管路径。moto 不执行 IAM
授权、Stubber 只校验请求形态，所以单测全绿不代表线上对。而失败形态往往是
「工具返回成功、投影没跟上」——只看工具返回值发现不了。

## 准备

**扮演真实用户**：只用 Skill/MCP/URL，不去翻平台源码找答案。回答不了的就是
产品缺口，记下来。

服务端核对用（只读，不写数据）：

```bash
./site-builder/scripts/check_permissions_state.sh <site_id>
./site-builder/scripts/check_permissions_state.sh <site_id> --watch   # 观察投影生效
```

它打印两张表的权限字段并判定一致性，**区分「影响鉴权的字段」与
「仅信息性的 permissions_rev」**——后者在刚迁移过的存量站点上必然缺失
（`migrate_permissions.py` 只写 sites 侧），不是缺陷。

**用一个新建的 fixture 站点做实验，不要拿现有站点**。现有站点里
`team-kudos-wall-1d5lpc` 等是验证过的一期产物，改坏了要重部署。

```bash
# --owner 必须填**你的登录邮箱**：默认的 fixture@test 会让 role_of() 判你不是
# owner，所有权限工具都拒绝，症状看起来像"工具坏了"
python3 site-builder/scripts/deploy_fixture.py \
  site-builder/fixtures/nosql-notes --owner <你的飞书邮箱>
```

约 90 秒出 `https://app-<site_id>.<base_domain>`。验完用 `undeploy_site`
下线（带 `purge_data=true` 才会删数据表/schema）。

需要第二个身份才能验完整（协作者视角、越权路径）。没有第二个飞书账号时，
标 🔸 的项只能验一半——把验不了的记为待办，不要假装通过。

## 验证项

### 1. get_site_permissions —— 读路径与角色判定

对自己的站点调用。

- [ ] 返回含 `owner` / `collaborators` / `require_login` / `allowed_users` / `my_role`
- [ ] `owner` == 你的飞书邮箱，`my_role` == `owner`
- [ ] 对**别人的站点**调用 → 被拒（`site-sites` 里有别人 owner 的站点时）
- [ ] 对不存在的 site_id 调用 → 可读的错误，不是 500

判读：`my_role` 是 `role_of()` 的输出。若显示 `none` 但你确实是 owner，
说明 email claim 与表里 owner 不一致（大小写、别名邮箱）。

### 2. update_site_permissions —— 访问策略双写

- [ ] `require_login=false` → 脚本显示两表 `require_login`/`require_auth` 都变 false
- [ ] **无痕浏览器（未登录）访问站点 URL → 直接进,不再 302**
      （这一步才证明 Edge 真按新策略执行；只看表里的值不算）
- [ ] 改回 `require_login=true` → 未登录访问恢复 302
- [ ] `allowed_users=["你的邮箱"]` → 你仍能访问
- [x] `allowed_users=["别人的邮箱"]`（不含你）→ **你仍能访问，这是正确的**：
      `origin_request.py` 里 owner 与 collaborator **隐式在名单内**
      （注释原文：他们能改这个名单，要求他们把自己也写进去只会制造"把自己锁在
      门外"的工单）。所以这一项验的是**免锁例外生效**，不是名单拦截。
- [ ] 🔸 名单拦截本身**必须用第三方身份验**（既非 owner 也非协作者）——
      owner 自己永远进得去，用自己测名单等于没测。无第二账号时此项无法验证。
- [ ] `permissions_rev` 每次写入递增，`permissions_updated_by` == 你的邮箱
- [ ] 两表 `allowed_users` 一致（脚本判定「鉴权字段两表一致」）

判读：边缘生效有延迟（工具返回里写「最多 1 分钟」）。用 `--watch` 看表已变、
但浏览器还没变时，等一分钟再试，别急着判失败。

### 3. manage_collaborators —— 协作者与所有权

- [ ] `add=["someone@example.com"]` → 两表 `collaborators` 都出现该邮箱
- [ ] 重复 add 同一人 → 不产生重复项（幂等）
- [ ] `remove` 该邮箱 → 两表都移除
- [ ] **`add` 与 `transfer_owner` 同时传 → 报错「互斥」，且什么都没写**
      （这条是刻意的：静默半执行比报错难查。验完用脚本确认 add 的人**没有**被加上）
- [ ] 三个参数都不传 → 报错「需要指定 add / remove / transfer_owner 之一」
- [ ] 🔸 `transfer_owner=<第二个账号>` → `owner` 变成对方，**你自动降级为协作者**
      （防转错人失去访问）。转移后你应仍能调 `update_site_permissions`
      但**不能**再调 `manage_collaborators`（仅 owner 可）
- [ ] 🔸 以协作者身份调 `manage_collaborators` → 被拒
- [ ] 🔸 以协作者身份调 `undeploy_site` → 被拒（协作者不能下线站点）

### 4. admin 代管路径

你已是平台管理员（`site-admins` 表里有你）。

- [ ] 🔸 对**别人 owner 的站点**调 `get_site_permissions` → 成功，`my_role` == `admin`
- [ ] 🔸 对别人的站点调 `update_site_permissions` → 成功
      （代管入口就是为「owner 离职/误撤自己权限」准备的）
- [ ] 从 `site-admins` 表临时删掉自己 → 上面两项应立刻变成被拒
      （验完记得用 `seed_admin.py --apply` 加回来）

### 5. 并发冲突（可选，需要两个终端）

- [ ] 两个终端几乎同时对同一站点调 `update_site_permissions` →
      其中一个报「站点权限已被其他人修改，请刷新后重试」（409 语义），
      **不是** 500，也不是两个都成功后互相覆盖

## 记录

每项写下实际返回与两表状态。**验不了的项标明原因**（如「无第二账号」），
不要留空或标成通过——这份清单的价值在于下次能看出哪些是真验过的。

发现的产品缺口（错误信息看不懂、需要翻源码才知道怎么用、Agent 会误用的
参数语义）也记在这里，那些是二期 M3 控制台要解决的输入。

---

## 验证结果（2026-08-06，站点 notes-01d147，身份 owner + 平台管理员）

通道：**Claude Code 走 stdio 代理**（`clients/quick-desktop-proxy`）。直连 HTTP
transport 走不通——Claude Code 按 MCP 新版规范发 RFC 8707 的 `resource` 参数，
Cognito 不支持，token 交换返回 `invalid_grant`（客户端日志是
`Error during auth completion`）。三次对照实验定位：带 scope 无 resource → 成功；
无 scope 无 resource → 成功；带 resource → 失败。**scope 缺失不是根因**。

### 通过的项

| 项 | 实测 |
|---|---|
| `get_site_permissions` 字段与角色 | 五字段齐全，`my_role=owner` |
| `update_site_permissions` 双写 | `require_login` 改动两表同步，`permissions_rev` 每次递增（1→8），`permissions_updated_by` 正确 |
| **Edge 真按新策略执行** | `require_login=false` → 未登录 200（约 10 秒生效）；改回 `true` → 恢复 302（约 40 秒）。两个方向都验过 |
| owner/collaborator 免锁例外 | `allowed_users` 设成不含自己的名单后仍能访问（`origin_request.py` 显式设计） |
| `add`+`transfer_owner` 互斥 | 报错且**零副作用**：collaborators 空、owner 未变、rev 未推进 |
| 三参数全空 | 报错「需要指定 add / remove / transfer_owner 之一」 |
| `add` / `remove` 双写 | 两表同步；重复 add 幂等（名单不重复） |
| `transfer_owner` 自动降级 | 转出后原 owner 进 collaborators（防转错人失去访问）；转回同样正确 |
| admin 优先于 collaborator | 转出后 `my_role=admin` 而非 `collaborator`——印证 `role_of` 注释里的排序理由 |
| admin 代管 | 非 owner 身份仍可改权限、可转移所有权 |
| **admin 撤销立刻生效** | 从 admins 表删掉自己后，同一调用立刻被拒（强一致读，无缓存窗口） |
| `list_my_sites` 走 GSI | 10 个站点全返回，`role` 正确，含新建站点 |

### 未验证（需要第二个飞书账号）

- **名单拦截本身**：owner 与 collaborator 隐式在名单内，用自己测等于没测。
- 协作者视角的越权：以协作者身份调 `manage_collaborators` / `undeploy_site` 应被拒。
- 并发冲突（409）：需要两个身份或两个终端同时写。

### 发现的产品缺口

1. **不存在的 site_id 报「你无权访问」**。这是刻意的（`role_of` 对 `site=None`
   返回 `ROLE_NONE`，避免枚举探测），但打错一个字符时提示会让人以为是权限问题
   而去找 owner 加名单。控制台（M3）应能区分这两种情况。
2. **重复 add 同一协作者也推进 `permissions_rev`**（4→6）。不影响正确性
   （rev 只用于并发条件），但"无实际变更也算一次修改"会让审计日志有噪声。
3. `deploy_fixture.py` 曾不写 sites 记录（已修）：它绕过 MCP 直接起状态机，而
   `do_deploy_site` 才调 `upsert_site` 写 owner。缺 owner 时站点**能正常访问**
   （Edge 只读路由表，owner 由 register_route 从 job 兜底写入），但所有权限
   工具都判你不是 owner——症状看起来像"工具坏了"。

