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
做过同一个取舍（它也由本脚本创建，因此也不在清单里），当时没有把理由写下来。

**裁定：login-flow 与 legacy 一样归 `owned`，不进核对清单；`ensure_secret` 保留。**

判据是"核对到底在防什么"。precheck 防的是**多个消费方必须就同一个值达成一致**，所以这个值不能
由部署脚本随手造一把：会话密钥被 Edge 与 panel 各自持有，auth 自己生成一把新的就会让两侧验签
不上，症状是全部登录 500 而脚本 exit 0。login-flow secret 只有 auth **一个**消费方（panel 与
Edge 永不持有它，见 §11.3），auth 自己造一把随机值是完全正确的行为，那个失败模式在它身上不存在。
§11.8.12 自己给的动机（"⑥ 若忘跑 `ensure_session_keys.py` 就会撞上"）说的也是轮转期新增的会话
密钥，而 login-flow 在 1B 里只创建一次、不参与轮转演练。

放弃掉的是"忘跑 ensure 脚本时得到一次响亮拒绝"，代价范围仅限这一把单消费方、可随时重造的密钥。

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
- **读 §11.8.12 的人会看到与代码不一致的清单。** 那一节的字面清单在 spec 里尚未修订
  （tracked spec 的改动归 3c-1B ticket 08 的文档票）；在修订之前，本 ADR 是这一条的裁定真源。
  照 §11.8.12 原话把 login-flow 加回核对清单会让首次部署失败。
- 3c-2B 在同一个 `precheck()` 钩子里加四项 KMS 校验时，这条归属划分不受影响：RS key 由外部
  provision，属于"多消费方必须一致"那一类，该进清单。

出处：`docs/superpowers/specs/2026-08-28-asymmetric-session-signing-spec.md` §11.3、§11.8.6、
§11.8.12；实现见 `site-builder/auth/deploy_auth.py` 的 `required_parameters()`。
