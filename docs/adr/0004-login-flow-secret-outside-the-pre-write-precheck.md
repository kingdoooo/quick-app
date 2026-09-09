---
status: accepted
date: 2026-09-03
---
# login-flow secret 不进 auth 的写前参数核对清单

spec §11.8.12 的裁定写的是"两个部署脚本在第一次写之前对各自 family 集合里的每个 HS
`ssm_param`（**auth 另加 login-flow** 与非空的 legacy）做一次 `GetParameter`，任一缺失即拒绝
部署"。同一份 spec 的 §11.8.6 又要求"`deploy_auth.py` 的 `ensure_secret` 保留为兜底"。
**这两条不能同时成立**：核对发生在任何写之前，所以把 login-flow 列进清单就等于让那条缺省补建
永远走不到——首次部署必然被自己拒掉，而它存在的唯一理由正是首次部署。3c-1A 已经为 legacy 参数
做过同一个取舍——当时 legacy 那把共享密钥同样由 auth 的部署路径缺省补建，因此也不在清单里
（那把密钥与 legacy 入口已随 3c-final 删除，这里只是记录先例），当时没有把理由写下来。

**裁定：login-flow 与 legacy 一样归 `owned`，不进核对清单；`ensure_secret` 保留。**

判据是"核对到底在防什么"。precheck 防的是**多个消费方必须就同一个值达成一致**，所以这个值不能
由部署脚本随手造一把：会话密钥被 Edge 与 panel 各自持有，auth 自己生成一把新的就会让两侧验签
不上，症状是全部登录 500 而脚本 exit 0。login-flow secret 只有 auth **一个**消费方（panel 与
Edge 永不持有它，见 §11.3），auth 自己造一把随机值是完全正确的行为，那个失败模式在它身上不存在。
§11.8.12 自己给的动机（"忘了先建参数就会撞上"）说的也是轮转期新增的会话密钥，而 login-flow
只创建一次、不参与轮转。

**创建方只剩 `deploy_auth.ensure_secret` 一处**（那个专门建密钥的脚本随 3c-final 删除，plan 08 D5），
所以这把密钥的生命周期完全落在 auth 自己的部署路径里，与本裁定同源。

放弃掉的是"忘了先建参数时得到一次响亮拒绝"，代价范围仅限这一把单消费方、可随时重造的密钥。

## Consequences

- `session_keys.ssm_parameter_names/ssm_parameter_arns` 的 `login_flow` 开关**默认关**，只有
  `deploy_auth` 传 `True`。默认取安全的那一侧：漏传的后果是 auth 运行时 AccessDenied（响亮），
  误传的后果是把一把密钥交给不需要它的组件（静默扩权）。
- 那条缺省补建必须有正对照，否则它是死代码而本 ADR 的前提失效：
  `auth/tests/test_deploy_auth_sequence.py::test_main_creates_the_login_flow_secret_when_it_is_absent`
  加同文件的"不覆盖既有值"一条。
- panel 侧有三条负向断言锁住"它永不持有这把密钥"
  （`panel/tests/test_deploy_panel_contract.py`，含一条禁止 `deploy_panel` 出现 `login_flow` 的
  结构守卫）。
- **`ensure_secret` 在创建分支打一行（只有参数名）。** 这是本裁定的直接代价：既然缺参不再被
  拒绝，"参数被删了、脚本默默重造一把"就没有任何信号，事后只看到一轮失败的登录。判据是
  `auth/tests/test_deploy_auth_sequence.py` 的两条：创建时必须出现参数名且**不得**出现值，
  参数已存在时必须完全安静（幂等重跑是常态，每次刷一行会把"创建"这个信号淹掉）。
- **`legacy_param` 走同一条排除，但那一条并不安全——这是一个已知缺口，非本 ADR 引入。**
  3c-1A 就把它归入 `owned`（本脚本首次部署时生成它）。区别在消费方数量：legacy 的 `jwt-secret`
  有**第二个**消费方，Edge 那份是 CDK 部署时字符串替换注入的。成熟部署上它若被删，auth 造一把新的
  而 Edge 仍拿着旧的 ⇒ 正是 precheck 本要防的全员登录循环。今天唯一的现场信号就是上面那行创建声明；
  真正的修复要能区分"首次部署"与"这个参数不该不存在"，那是独立的设计面（1B 不做）。
  **所以本 ADR 的"安全"结论只覆盖 login-flow 一把，不要把它读成对 legacy 的背书。**
- **§11.8.12 的字面清单已按本 ADR 修订**（3c-1B ticket 08 的文档票）：那一节的正文不再写
  "auth 另加 login-flow 与非空的 legacy"，并附了一段引本 ADR 的注记，其中单独重申了下面那条
  "只覆盖 login-flow 一把"的边界。两处若再分叉，**本 ADR 仍是这一条的裁定真源**。
  照修订前的原话把 login-flow 加回核对清单会让首次部署失败。
- 3c-2B 在同一个 `precheck()` 钩子里加四项 KMS 校验时，这条归属划分不受影响：RS key 由外部
  provision，属于"多消费方必须一致"那一类，该进清单。

出处：`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.3、§11.8.6、
§11.8.12；实现见 `site-builder/auth/deploy_auth.py` 的 `required_parameters()`。
