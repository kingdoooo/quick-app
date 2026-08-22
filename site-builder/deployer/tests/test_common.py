import re
import common


def test_job_lifecycle(aws):
    jid = common.create_job("a@x.com", "demo-abc123")
    job = common.get_job(jid)
    assert job["status"] == "PENDING" and job["owner"] == "a@x.com"
    common.update_job(jid, status="RUNNING", phase="validate")
    assert common.get_job(jid)["phase"] == "validate"
    common.update_job(jid, status="FAILED", error="boom")
    j = common.get_job(jid)
    assert j["status"] == "FAILED" and j["error"] == "boom"


def test_update_job_with_no_fields_only_touches_updated_at(aws):
    jid = common.create_job("a@x.com", "demo-abc123")
    before = common.get_job(jid)
    common.update_job(jid)  # 不传任何可选字段：不应崩溃
    after = common.get_job(jid)
    assert after["status"] == "PENDING"
    assert after["updated_at"] >= before["updated_at"]


def test_list_jobs_by_owner(aws):
    a = common.create_job("a@x.com", "s1")
    common.create_job("b@x.com", "s2")
    mine = common.list_jobs_by_owner("a@x.com")
    assert [j["job_id"] for j in mine] == [a]


def test_site_upsert_and_get(aws):
    common.upsert_site("demo-abc123", owner="a@x.com", tier="static",
                       subdomain="app-demo-abc123", status="ACTIVE")
    s = common.get_site("demo-abc123")
    assert s["tier"] == "static"
    common.upsert_site("demo-abc123", status="DELETED")
    assert common.get_site("demo-abc123")["status"] == "DELETED"
    assert common.get_site("demo-abc123")["owner"] == "a@x.com"  # 未覆盖字段保留


def test_id_helpers():
    # 合同允许最长 30 字符；site_id 取前 20 字符 + 6 位随机后缀
    sid = common.new_site_id("my-long-project-name-abcdefg")
    assert re.match(r"^[a-z][a-z0-9-]{0,19}-[a-z0-9]{6}$", sid)
    assert common.subdomain_for("x-1a2b3c") == "app-x-1a2b3c"
    assert common.dsql_schema_for("x-1a2b3c") == "site_x1a2b3c"


def test_site_name_rejects_sql_and_resource_name_hazards():
    """site_name 会成为 DSQL 标识符与 IAM/Lambda 资源名，必须在入口拦下。"""
    import pytest
    for bad in ['x" ; CREATE ROLE attacker WITH LOGIN SUPERUSER; --',
                "MySite With Spaces!", "UPPER", "-lead", "has_underscore",
                "a", "x" * 31, "", "sql'inject"]:
        with pytest.raises(common.InvalidSiteName):
            common.new_site_id(bad)
    # 合法名照常通过
    for good in ("expense-tracker", "notes", "a1", "x" * 30):
        assert common.new_site_id(good)


def test_list_sites_by_owner_uses_gsi(aws):
    import common
    common.upsert_site("s-1", owner="o@x.com", name="one")
    common.upsert_site("s-2", owner="o@x.com", name="two")
    common.upsert_site("s-3", owner="other@x.com", name="three")
    got = {s["site_id"] for s in common.list_sites_by_owner("o@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_by_owner_empty(aws):
    import common
    assert common.list_sites_by_owner("nobody@x.com") == []


def test_list_sites_for_user_includes_collaborations(aws):
    import common
    common.upsert_site("s-1", owner="me@x.com", collaborators=[])
    common.upsert_site("s-2", owner="other@x.com", collaborators=["me@x.com"])
    common.upsert_site("s-3", owner="other@x.com", collaborators=["nope@x.com"])
    got = {s["site_id"] for s in common.list_sites_for_user("me@x.com")}
    assert got == {"s-1", "s-2"}


def test_list_sites_for_user_dedups(aws):
    import common
    # 理论上 owner 不该同时在 collaborators 里（permissions 层会拦），
    # 但历史数据可能有——不能返回重复项
    common.upsert_site("s-1", owner="me@x.com", collaborators=["me@x.com"])
    got = [s["site_id"] for s in common.list_sites_for_user("me@x.com")]
    assert got == ["s-1"]


def test_list_jobs_by_site_returns_newest_first(aws):
    for jid, ts in [("job-1", "2026-06-01T00:00:00+00:00"),
                    ("job-2", "2026-07-01T00:00:00+00:00"),
                    ("job-3", "2026-05-01T00:00:00+00:00")]:
        common._table("JOBS_TABLE").put_item(Item={
            "job_id": jid, "site_id": "sx", "owner": "u@x.com",
            "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
            "created_at": ts, "updated_at": ts})
    # 另一个站点的 job 不得混入
    common._table("JOBS_TABLE").put_item(Item={
        "job_id": "job-other", "site_id": "sy", "owner": "u@x.com",
        "status": "SUCCEEDED", "phase": "smoke-test", "error": "", "url": "",
        "created_at": "2026-08-01T00:00:00+00:00",
        "updated_at": "2026-08-01T00:00:00+00:00"})
    jobs = common.list_jobs_by_site("sx")
    assert [j["job_id"] for j in jobs] == ["job-2", "job-1", "job-3"]


def test_create_site_record_collision_raises_and_writes_nothing(aws):
    """碰撞必须抛 SiteIdCollision，且已有站点的**每个字段**原样不动。"""
    import pytest
    common._table("SITES_TABLE").put_item(Item={
        "site_id": "victim-abc123", "owner": "victim@x.com",
        "name": "victim", "status": "ACTIVE",
        "created_at": "2026-01-01T00:00:00+00:00"})
    with pytest.raises(common.SiteIdCollision):
        common.create_site_record("victim-abc123",
                                  owner="attacker@x.com", name="attacker")
    site = common.get_site("victim-abc123")
    assert site["owner"] == "victim@x.com"      # 不只 created_at——
    assert site["name"] == "victim"             # owner/name/status 全部
    assert site["status"] == "ACTIVE"           # 必须原样（假绿教训）
    assert site["created_at"] == "2026-01-01T00:00:00+00:00"


def test_create_site_record_writes_full_record_once(aws):
    common.create_site_record("s-new", owner="u@x.com", name="fresh")
    site = common.get_site("s-new")
    assert site["owner"] == "u@x.com" and site["status"] == "DEPLOYING"
    assert site["created_at"]


def test_reserved_prefixes_rejected_so_platform_wildcards_stay_decidable():
    """平台与用户站点共用 `site-` 命名空间：站点名 `auth-tool` ⇒ 函数
    `site-auth-tool-x1y2z3`，会匹配 `site-auth-*` 通配。任何按前缀通配平台函数的
    策略（IAM Deny / SCP）都因此不可判定——所以在入口就把这些前缀留出来。"""
    import common, pytest
    for bad in ("auth", "panel", "deployer", "key-proxy", "access", "rt",
                "auth-tool", "panel-v2", "deployer-x", "rt-foo"):
        with pytest.raises(common.InvalidSiteName):
            common.validate_site_name(bad)
    for ok in ("notes", "voc-dashboard", "authors", "paneling", "accessible"):
        assert common.validate_site_name(ok) == ok   # 只拦"整词或 name- 起头"


def test_reserved_prefixes_are_documented_in_the_agent_facing_contract():
    """入口拒绝了、而给生成方 Agent 的正式合同里查不到 ⇒ Agent 只能靠报错文案自解释。

    期望值**遍历代码里的真源**（`common.RESERVED_SITE_NAME_PREFIXES`），所以往元组里
    加一项而忘了改文档时这条会红——反过来抄一份前缀清单到测试里就没有这个性质。

    判定落在**那一节之内、按反引号字面量**，不是全文 substring：全文 substring 下
    七项里有三项凭空变绿——`rt` 被 `backend.port` 的两个字母满足、`auth` 被 site.json
    的 auth 字段满足、`runtime` 被 `backend.runtime` 满足（实测：全文判时只报缺 4 项）。
    "守卫被无关文本满足"正是本轮反复栽的那一类。
    """
    from pathlib import Path
    doc = (Path(__file__).parents[2] / "skills" / "site-builder" / "references"
           / "contract.md").read_text(encoding="utf-8")
    anchor = "## 站点名的保留前缀"
    assert anchor in doc, f"合同里找不到 {anchor!r} 这一节——本条已空转"
    section = doc.split(anchor, 1)[1].split("\n## ", 1)[0]
    missing = [p for p in common.RESERVED_SITE_NAME_PREFIXES
               if f"`{p}`" not in section]
    assert not missing, f"这些保留前缀没写进给 Agent 的合同：{missing}"


def test_existing_site_names_still_valid():
    """现有 6 个站点无一冲突——加这条校验不需要数据迁移。"""
    import common
    for n in ("notes", "promo-roi-tracker", "return-analysis",
              "returns-dashboard", "team-kudos-wall", "voc-dashboard"):
        assert common.validate_site_name(n) == n


def test_get_job_consistent_read_is_opt_in(aws):
    """`consistent=True` 必须真的把 `ConsistentRead=True` 传到 `get_item`，
    默认调用必须**不**带它。

    断言的是**传下去的 kwargs**而不是"读到的值"：moto 与真机的最终一致窗口都测不出来
    （moto 的读恒为强一致），所以"读对了"这种断言在任何实现下都会绿——包括把参数
    整个丢掉的实现。默认那半边同样要锁：把默认改成 True 会让每一次 job 读都变成
    强一致读（成本翻倍且与既有调用方的语义不符），那也是退化。
    """
    seen = []
    real_table = common._table

    class _Spy:
        def __init__(self, inner):
            self._inner = inner

        def get_item(self, **kw):
            seen.append(kw)
            return self._inner.get_item(**kw)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    jid = common.create_job("a@x.com", "demo-abc123")
    common._table = lambda env: _Spy(real_table(env))
    try:
        assert common.get_job(jid)["job_id"] == jid
        assert common.get_job(jid, consistent=True)["job_id"] == jid
    finally:
        common._table = real_table

    assert len(seen) == 2, seen
    assert "ConsistentRead" not in seen[0], f"默认调用带上了强一致读：{seen[0]}"
    assert seen[1].get("ConsistentRead") is True, (
        f"consistent=True 没有传到 get_item：{seen[1]}")


def test_static_prefix_format_has_a_single_definition():
    """前端版本前缀 `sites/{site_id}/{job_id}` 的格式**只允许在 common.py 里出现**。

    这个不变量被四方共同依赖，而它们各自的失败模式互不相同、都很难从症状反推：

      · `register_route` 写进路由表的 `static_prefix` —— Edge 按它改写 URI；
        **尾斜杠多一个就整站 403**（拼出双斜杠，与上传的 key 不是同一个对象），
        而两侧单测各自都会绿（CLAUDE.md 记的实测坑）；
      · `upload_frontend` 按它拼 S3 key —— 与上面不一致就是"上传到了没人读的位置"；
      · `mark_job._cleanup_old_versions` 按它决定保留谁 —— 不一致就是**删掉线上
        正在服务的前端**；
      · `mark_job._restore_route` 按它做补偿的条件 —— 不一致就是恢复静默停摆
        （条件永远不成立）。

    曾经这四处各手写一份 f-string，没有任何东西保证它们同义。本用例按源码钉死。
    """
    import ast
    import re
    from pathlib import Path
    root = Path(__file__).parents[3]
    canonical = (root / "site-builder" / "deployer" / "functions"
                 / "common.py").resolve()
    # `sites/` 后面紧跟一个 f-string 占位 = 在手搓这个 S3 键前缀。
    #
    # 两类**不算**，各有理由，所以判据不能只是 `sites/\{`：
    #   · 裸字面量 `"sites/"`（不带占位）—— CDK 的 IAM 资源 ARN 里有
    #     `.../sites/*`，那是同一段路径的**授权**表达，不是键的构造；
    #   · 前面紧贴斜杠的 `/api/sites/{site_id}/...` —— panel 的 HTTP 路由与
    #     verify 脚本调的接口路径，与 S3 键毫无关系。所以要求 `sites` 前面**不是**
    #     路径分隔符或标识符字符，即它必须是字符串的开头那一段。
    handmade = re.compile(r"(?<![\w/])sites/\{")
    offenders = []
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        if py.resolve() == canonical:
            continue
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        # 只看代码，不看注释与 docstring：解释这个格式为什么危险是允许的，
        # 也是必要的。ast.unparse 已经把注释全部丢掉，再清掉 docstring 即可。
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                body = node.body
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    body[0].value.value = ""
        if handmade.search(ast.unparse(tree)):
            offenders.append(str(py.relative_to(root)))
    assert not offenders, (
        "这些文件手写了前端版本前缀的格式，必须改用 common.static_prefix_for / "
        f"common.site_prefix_for：{offenders}")


def test_static_prefix_carries_no_trailing_slash():
    """路由表里的 `static_prefix` **不带**尾斜杠——Edge 的改写是
    `f"/{static_prefix}{path}"` 且 `path` 已以 `/` 开头。"""
    import common
    assert common.static_prefix_for("s-1", "job-9") == "sites/s-1/job-9"
    assert common.site_prefix_for("s-1") == "sites/s-1/"


def test_route_api_target_reads_strongly_consistent(aws, monkeypatch):
    """`route_api_target` 必须强一致读（Codex 2026-08-17 P1-4）。

    它的返回值不是拿来展示的：`deploy_lambda_site` 用它推导 live color，进而决定
    **哪个 alias 可以安全地改**。读到上一次切换之前的旧副本 ⇒ 把正在服务的那一色
    当成空闲色 ⇒ `update_alias` 直接把未经健康门的新版本推到线上流量上。

    按**发出去的参数**断言，不按返回值：最终一致读在 moto 上同样返回最新值，
    只看返回值的用例对这个缺陷完全不敏感。
    """
    import boto3
    import botocore.client
    import common
    seen = []
    real = botocore.client.BaseClient._make_api_call

    def _spy(self, op, params):
        if op == "GetItem" and params.get("TableName") == "routing":
            seen.append(params.get("ConsistentRead"))
        return real(self, op, params)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _spy)
    boto3.client("dynamodb").put_item(TableName="routing", Item={
        "subdomain": {"S": "app-s-1"},
        "api_target": {"S": "https://g.lambda-url.us-east-1.on.aws"}})
    common.route_api_target("s-1")
    assert seen == [True], \
        f"live color 的真源读不是强一致（ConsistentRead={seen}）"


def test_no_literal_index_into_cancellation_reasons():
    """事务取消原因列表**不许用整数字面量下标**——下标必须由构造处算出。

    这一类已经出过三次同型写法（mcp.do_confirm_upload / mcp.do_undeploy /
    register_route），前两处改成 `zip(labels, reasons)` 后第三处仍留着 `reasons[2]`
    ——正是"修实例不修类"的形态。往 TransactItems 中间插一项时，写死的下标把
    文案对到错误的原因上；在 register_route 那一处更糟：把"这是重放"误读成
    "权限被并发修改"，一次**已经提交**的部署被报成 FAILED。

    判据：任何名为 `reasons` 的变量不得被整数字面量下标（`reasons[0]` 这种）。
    合法写法是 `zip(labels, reasons)` 或 `reasons[computed_idx]`。
    """
    import ast
    from pathlib import Path
    root = Path(__file__).parents[3]
    offenders = []
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "reasons"
                    and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, int)):
                offenders.append(f"{py.relative_to(root)}:{node.lineno}")
    assert not offenders, (
        f"这些位置用整数字面量下标读 CancellationReasons：{offenders}——"
        "改成 zip(labels, reasons) 或由构造处算出的下标")


def test_table_name_format_has_a_single_definition():
    """站点数据表名 `site-data-{site_id}-{logical}` 的格式**只允许在 common.py 里出现**。

    为什么值得一条守卫：M01 的修复要求建表 / 授权 / 删表三处对同一格式达成一致，
    而它曾被手抄三份（provision_dynamodb 建、common.site_policy 授权、undeploy 删）。
    它们各自的失败模式互不相同、都很难从症状反推：

      · 建表与授权不一致 —— 表建出来了但站点角色没有它的权限，站点运行时
        AccessDeniedException；
      · 授权与删表不一致 —— 下线时漏删，遗留表继续计费，且**下一个同名站点可能
        直接读到上一个站点的残留数据**；
      · 三者都用通配前缀 —— 因为分隔符是 `-` 而 site_id 自身可含 `-`，
        `site-data-foo-k3d9x1-*` 会命中 site_id 为 `foo-k3d9x1-…` 的**另一个站点**的表。
        这正是 M01 要求逐表枚举精确 ARN 的原因。

    **扫描范围是整个 `site-builder` 而不只是 deployer/functions**：panel、mcp、
    key-proxy 各自把 deployer 的共享模块打进自己的产物，第四份手抄同样可能出现在
    那些目录里；只看一个目录的守卫不能保证"这类缺陷不会再回来"。
    与 `test_static_prefix_format_has_a_single_definition` 同一套判据结构。
    """
    import ast
    import re
    from pathlib import Path
    root = Path(__file__).parents[3]
    canonical = (root / "site-builder" / "deployer" / "functions"
                 / "common.py").resolve()
    # `site-data-` 后面紧跟一个 f-string 占位 = 在手搓**某一个站点**的表名。
    #
    # 要求这个占位，是为了把"构造表名"与"授权整类表名"分开——后者**不算**违规：
    #   · `deployer/infra/app.py` 的 `f"...table/site-data-*"` 是执行器角色对
    #     全部站点表的账号级授权，它没有 site_id 可传（也 import 不到本模块），
    #     必须保持原样。它的下一个字符是 `*` 而非 `{`，因此天然被排除，
    #     不需要按文件名特例。
    # 与 sibling 守卫里"CDK 的 ARN vs S3 的键"是同一个区分。
    handmade = re.compile(r"site-data-\{")
    offenders = []
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        if py.resolve() == canonical:
            continue
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        # 只看代码，不看注释与 docstring：解释这个格式为什么危险是允许的，
        # 也是必要的（undeploy.py 的模块与函数 docstring 都提到它）。
        # ast.unparse 已经把注释全部丢掉，再清掉 docstring 即可。
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                body = node.body
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    body[0].value.value = ""
        if handmade.search(ast.unparse(tree)):
            offenders.append(str(py.relative_to(root)))
    assert not offenders, (
        "这些文件手写了站点数据表名的格式，必须改用 common.site_table_name："
        f"{offenders}")


def test_site_table_name_is_the_canonical_format():
    """钉死唯一定义**自己**的产出。

    上面那条守卫排除了 canonical 文件，因此它只能说"别处没有手写"，
    不能说"这里还写着"——把定义删掉或搬走，它照样绿。这条补上另一半。
    """
    import common
    assert common.site_table_name("foo-k3d9x1", "notes") == "site-data-foo-k3d9x1-notes"
