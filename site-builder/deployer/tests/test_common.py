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
    from conftest import is_transient_deploy_copy
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        if py.resolve() == canonical:
            continue
        # 部署窗口里的逐字节副本不算手抄（按内容豁免，理由在那个 helper 上方）
        if is_transient_deploy_copy(py):
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
    from conftest import is_transient_deploy_copy
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "tests")):
            continue
        if py.resolve() == canonical:
            continue
        # 部署窗口里的逐字节副本不算手抄（按内容豁免，理由在那个 helper 上方）
        if is_transient_deploy_copy(py):
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


def test_the_deploy_copy_exemption_only_covers_byte_identical_files(tmp_path):
    """"按内容豁免"的**反向验证**，常驻（探针一律在 tmp_path）。

    上面几条守卫扫的是整个 `site-builder/`，而 panel / mcp / key-proxy 的部署
    脚本会把这些共享模块复制进自己的包目录、打完包在 finally 删掉（MCP 那一次的
    窗口覆盖整个 buildx+push，分钟级）。不豁免就会在部署期变成假红，而假红的
    下一步是有人给守卫加一条**路径**豁免——那会把一份真的手抄一起放过，等于把
    洞开在守卫自己身上。所以三个方向都钉死：
    逐字节相同 ⇒ 豁免；改过一个字节 ⇒ 仍被咬住；真源自己 ⇒ 不由这条豁免负责
    （"唯一定义在哪"必须由各守卫按路径点名）。
    """
    from conftest import is_transient_deploy_copy
    src_dir, pkg = tmp_path / "functions", tmp_path / "panel"
    src_dir.mkdir()
    pkg.mkdir()
    (src_dir / "common.py").write_text("A = 1\n")
    copy = pkg / "common.py"
    copy.write_text("A = 1\n")
    assert is_transient_deploy_copy(copy, sources=(src_dir,)) is True
    copy.write_text("A = 1\nB = 2   # 手抄之后改了它\n")
    assert is_transient_deploy_copy(copy, sources=(src_dir,)) is False
    assert is_transient_deploy_copy(src_dir / "common.py",
                                    sources=(src_dir,)) is False
    (pkg / "only_here.py").write_text("A = 1\n")      # 真源里没有同名文件
    assert is_transient_deploy_copy(pkg / "only_here.py",
                                    sources=(src_dir,)) is False


def test_site_policy_never_matches_a_nested_sites_tables(monkeypatch):
    """A 的策略绝不能匹配 B 的表——即使 B 的 site_id 以 A 的 site_id 开头。

    这一对是关键（Codex 复审给出的绕过变体，已实测）：B 的**名字**
    `foo-k3d9x1-longname` 是合法站点名、且**不** fullmatch SITE_ID_RE，
    所以"拒绝像 site_id 的名字"那类修法拦不住它——只有精确 ARN 能。
    用这一对而不是 `foo-k3d9x1-ab12cd`，正是为了证明修的是 ARN 本身。
    """
    import fnmatch
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    a, b = "foo-k3d9x1", "foo-k3d9x1-longname-abc123"
    doc = json.loads(common.site_policy(a, "dynamodb", tables=["notes"]))
    resources = []
    for stmt in doc["Statement"]:
        res = stmt["Resource"]
        resources += res if isinstance(res, list) else [res]
    b_table = ("arn:aws:dynamodb:us-east-1:111111111111:table/"
               + common.site_table_name(b, "notes"))
    assert not any(fnmatch.fnmatchcase(b_table, r) for r in resources), (
        f"站点 {a} 的策略匹配到了站点 {b} 的表；资源集合: {resources}")


def test_dynamodb_resources_are_exactly_this_sites_tables(monkeypatch):
    """正向钉死：dynamodb 资源逐表精确枚举，等值、不多不少。

    上面那条负向用例只断言"匹配不到 B 的表"，它**拦不住两类回归**：

    · **更窄的通配**——写成 `table/{site_table_name(site_id, t)}*` 时，A 的
      `…-foo-k3d9x1-notes*` 并不 fnmatch B 的 `…-foo-k3d9x1-longname-abc123-notes`，
      负向用例照绿；可它按**同一机制**放开了 id 以 `foo-k3d9x1-notes-` 开头的
      任何站点的全部表。负向用例只对"被删掉的那一种通配形态"会红，不覆盖这一类。
    · **过窄**——整段 dynamodb 语句删掉、或只发第一张表，负向用例同样照绿
      （在此之前，全套测试没有任何一条断言"站点必须拿到自己的表"）。

    所以这里断言**等值**（与日志组那条同一形状），且用**两张**表——一张分不出
    "逐表枚举"和"只发第一张"。期望值写成字面量而不是调 `site_table_name`：
    钉的是产物，不能从被测的同一个 helper 推导出来。
    """
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    doc = json.loads(common.site_policy("foo-k3d9x1", "dynamodb",
                                        tables=["notes", "tags"]))
    ddb = [s for s in doc["Statement"]
           if any(a.startswith("dynamodb:") for a in s["Action"])]
    assert len(ddb) == 1
    assert ddb[0]["Resource"] == [
        "arn:aws:dynamodb:us-east-1:111111111111:table/site-data-foo-k3d9x1-notes",
        "arn:aws:dynamodb:us-east-1:111111111111:table/site-data-foo-k3d9x1-tags"]
    # 非 logs 语句里一律不许出现通配。**这条只对 dynamodb 引擎的产物成立**，
    # 别顺手推广：logs 的 stream 层那条 `…:*` 是必须的（见 sibling 用例），
    # dsql 的 `Resource: "*"` 也另有理由（隔离由 per-site PG role 保证）。
    for stmt in doc["Statement"]:
        if any(a.startswith("logs:") for a in stmt["Action"]):
            continue
        res = stmt["Resource"]
        for r in (res if isinstance(res, list) else [res]):
            assert "*" not in r, f"dynamodb 站点的资源里出现通配: {r}"


def test_log_group_resources_are_exact_not_a_bare_prefix(monkeypatch):
    """日志组资源必须是精确名 + stream 层两条，不多不少。

    裸前缀 `/aws/lambda/site-{site_id}*` 同样会匹配到 site_id 以本站点为前缀的
    其他站点的日志组（可写别人的日志流 = 审计伪造）。给两条是因为
    CreateLogStream / PutLogEvents 作用在 stream 层，只给 group ARN 会 403。
    """
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    doc = json.loads(common.site_policy("s-1", "none", tables=[]))
    logs = [s for s in doc["Statement"]
            if any(a.startswith("logs:") for a in s["Action"])]
    assert len(logs) == 1
    assert logs[0]["Resource"] == [
        "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/site-s-1",
        "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/site-s-1:*"]


def test_dynamodb_engine_without_tables_is_rejected(monkeypatch):
    """engine=dynamodb 但没声明表 ⇒ 抛错，不许退回通配。

    空 Resource 列表本身是非法 IAM，而合同要求 dynamodb 站点至少一张表。
    """
    import pytest
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with pytest.raises(ValueError, match="没有声明表"):
        common.site_policy("s-1", "dynamodb", tables=[])


def test_no_gsi_support_yet_so_index_arns_are_not_needed():
    """GSI 触发器：当前站点表没有 GSI，所以 policy 不含 index ARN。

    **这条是真的触发器，不是"精确 ARN 断言顺带覆盖"**（v1 的覆盖表那么写是错的
    ——那三条断言压根不看索引 ARN，将来加了 GSI 它们仍会全绿，而运行时访问索引
    会因缺 `table/.../index/*` 而 403）。谁将来给站点表加 GSI 支持，这条会红，
    强制他同步 `site_policy`。
    """
    import pathlib
    root = pathlib.Path(__file__).parents[1]
    provisioner = (root / "functions" / "provision_dynamodb.py").read_text()
    assert "GlobalSecondaryIndex" not in provisioner, (
        "provision_dynamodb 开始建 GSI 了 —— site_policy 必须同步加 "
        "table/<name>/index/* 资源，否则站点访问索引会 403")
    schema = (root.parents[0] / "contract" / "src" / "contract" / "schema.py").read_text()
    assert "index" not in schema.lower(), (
        "contract schema 开始接受索引声明了 —— 同上，site_policy 要同步")


def test_dsql_policy_is_exactly_dbconnect_plus_the_two_log_groups(monkeypatch):
    """dsql 分支的产物整份钉死——全套用例此前**一次都没调过它**。

    为什么它值得单独一条：`site_policy` 的每一处调用都传 dynamodb 或 none，
    于是 M01 刚重写过的 dsql 分支从没被执行过，而它管的是存量站点里的多数
    （7 个里有 5 个是 DSQL）。Task 3c 的 backfill 闸门也兜不住这里的错——
    它的 check_roles 把实际策略与 `site_policy` 的输出比，**两侧同源**，
    错的文档与自己相等照样绿；它的 IAM 模拟器功能检查只对
    engine == "dynamodb" 跑。

    期望值是写死的整份文档，不调 `site_table_name`、也不从返回值反推：
    从被测对象推出来的期望只是同义反复。
    """
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    doc = json.loads(common.site_policy("foo-k3d9x1", "dsql", tables=[]))
    assert doc == {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                    "logs:PutLogEvents"],
         "Resource": [
             "arn:aws:logs:us-east-1:111111111111:log-group:"
             "/aws/lambda/site-foo-k3d9x1",
             "arn:aws:logs:us-east-1:111111111111:log-group:"
             "/aws/lambda/site-foo-k3d9x1:*"]},
        # 隔离由 per-site PG role 保证，所以这里的 `*` 是有意的（见 site_policy）。
        {"Effect": "Allow", "Action": "dsql:DbConnect", "Resource": "*"}]}


def test_dsql_ignores_tables_and_never_grants_dynamodb(monkeypatch):
    """dsql 站点即使被传入非空 tables，也不许长出 dynamodb 语句。

    `site_policy` 的 docstring 写着"engine 为 dsql / none 时忽略它"，但没有
    任何用例钉住这句话。会红的形态很具体：把 `if engine == "dynamodb"` 写成
    `if tables:`（"有表就授权"读起来很顺）⇒ DSQL 站点白拿一批 DynamoDB 表的
    读写权。上面那条传 tables=[] 的用例对这个形态照绿，所以两条都要有。
    """
    import json
    monkeypatch.setenv("ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    raw = common.site_policy("foo-k3d9x1", "dsql", tables=["notes", "tags"])
    assert "dynamodb" not in raw, f"dsql 站点的策略里出现了 dynamodb 授权：{raw}"
    assert "site-data-" not in raw, f"dsql 站点的策略里出现了站点数据表 ARN：{raw}"
    doc = json.loads(raw)
    assert {"Effect": "Allow", "Action": "dsql:DbConnect",
            "Resource": "*"} in doc["Statement"]
    assert len(doc["Statement"]) == 2, "dsql 站点应当只有日志组与 DbConnect 两条"


def test_tier_engine_agrees_with_the_contract():
    """`common.tier_engine` 必须与 contract 的 TIER_ENGINE 逐项一致。

    真源是合同（tier→engine 是合同语义），deployer 侧只能有一个派生实现。
    两处漂移的症状：backfill 给 DSQL 站点算出 engine="dynamodb"，
    于是重写 policy 时丢掉 `dsql:DbConnect` —— **站点当场连不上库**。
    """
    from contract.schema import TIER_ENGINE
    for tier, engine in TIER_ENGINE.items():
        assert common.tier_engine(tier) == engine, tier
    # 反向也要锁：上面那个循环只走合同里的 tier，deployer 侧**多**一个键它照绿
    # （sibling 用例只否掉 "fullstack-graph" 这一个具体值）。多出来的键意味着
    # deployer 接受一个合同会拒的 tier，"唯一派生实现"就名不副实了。
    assert set(common._TIER_ENGINE) == set(TIER_ENGINE), (
        "deployer 侧的 tier 集合与合同不一致："
        f"{sorted(set(common._TIER_ENGINE) ^ set(TIER_ENGINE))}")


def test_tier_engine_rejects_an_unknown_tier():
    """未知 tier 必须抛错，不许猜。

    backfill 会因此跳过该角色并计入"需人工"，而不是给它算出一个可能错的 engine。
    """
    import pytest
    with pytest.raises(ValueError, match="未知 tier"):
        common.tier_engine("fullstack-graph")
    # 空串与 None 也必须被拒：undeploy 把"值不可用"的稀疏行直接交给本函数
    # （`site.get("tier") or ""`）来判定，靠的就是这两个都走抛错出口。
    # 谁将来给 _TIER_ENGINE 加个假值键、或让本函数对空值宽容，这条会红。
    for falsy in ("", None):
        with pytest.raises(ValueError, match="未知 tier"):
            common.tier_engine(falsy)


def test_no_module_hand_rolls_the_tier_engine_mapping():
    """tier→engine 不许在**任何**模块里再内联一份。

    （原名 `test_undeploy_does_not_hand_roll_the_tier_mapping`，只读
    `functions/undeploy.py` 一个文件——而那正是 `mcp/server.py:594` 的第三份手抄
    能在它眼皮底下活下来的原因：那份还是生产上真正说话的那一份，它把 engine 塞进
    undeploy 的 payload，短路掉 undeploy 自己的派生。所以判据连同扫描范围一起换掉，
    沿用 Task 2 表名守卫的结构：扫整个 `site-builder/`。）

    **判据是"同一个表达式里同时出现 tier 名与引擎名"，不是"提到了 fullstack-sql"。**
    为什么必须这么窄——裸字面量扫描会把三类完全正当的写法误判成违规：
      · `contract/src/contract/redlines.py` 的错误文案
        （"backend/schema.sql: fullstack-sql 必须提供建表 SQL"）；
      · 合同自己的校验分支 `if tier == "fullstack-sql" and db.get("tables")`
        ——它按 tier 分流，但并**不**产出 engine，不是这个映射；
      · 满地的测试夹具 `tier="fullstack-sql"`。
    而真正的手抄一定把两侧写进**一个**表达式：
    `"dsql" if tier == "fullstack-sql" else "dynamodb"`（IfExp）、
    `{"fullstack-sql": "dsql", ...}`（Dict）、或 Compare 兜住的变体。
    豁免两个文件：真源 `contract.schema`（那份 Dict 就是定义）与唯一派生
    `deployer/functions/common.py`。
    """
    import ast
    from pathlib import Path
    root = Path(__file__).parents[3]
    exempt = {
        # 真源：tier→engine 是合同语义，这份 Dict 就是定义本身
        (root / "site-builder/contract/src/contract/schema.py").resolve(),
        # deployer 侧的唯一派生实现（一致性由 sibling 用例与合同对齐）
        (root / "site-builder/deployer/functions/common.py").resolve()}
    offenders = []
    from conftest import is_transient_deploy_copy
    for py in (root / "site-builder").rglob("*.py"):
        if any(part in py.parts for part in
               (".venv", "cdk.out", "__pycache__", "build", "node_modules",
                "tests")):
            continue
        if py.resolve() in exempt:
            continue
        # 部署窗口里的逐字节副本不算手抄（按内容豁免，理由在那个 helper 上方）
        if is_transient_deploy_copy(py):
            continue
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.IfExp, ast.Compare, ast.Dict)):
                continue
            src = ast.unparse(node)
            if "fullstack-sql" in src and ("dsql" in src or "dynamodb" in src):
                offenders.append(f"{py.relative_to(root)}:{node.lineno}")
    assert not offenders, (
        f"这些表达式内联了 tier→engine，必须改调 common.tier_engine：{offenders}")


# ── 物理表名对 logical 必须单射（M01 的残留半边）─────────────────────────────
#
# 去掉通配之后，那个"精确 ARN"仍然是**拼**出来的，而 logical 由 manifest 提供、
# 攻击者可控。logical 也允许 `-` 时：
#   A（id `aa-en3d3a`）声明 `b-rd8fhn-notes`  ⎫ 拼出同一张表
#   B（id `aa-en3d3a-b-rd8fhn`）声明 `notes`  ⎭ site-data-aa-en3d3a-b-rd8fhn-notes
# ⇒ A 的精确 ARN 就是 B 的数据表，且 A 的 data_tables 也会记下它 ⇒ 对 A 执行
# purge_data 会删掉 B 的表。已端到端复现。
#
# **断言形式要注意**：修好之后 `site_table_name(A, "b-rd8fhn-notes")` 应该**抛错**，
# 而不是"返回一个与 B 不同的名字"。所以下面拆成四条，不把"两个名字不相等"当唯一
# 判据——那种写法在 runtime guard 被删、只剩 validator 时仍会绿。

_COLLIDE_A = "aa-en3d3a"
_COLLIDE_B = "aa-en3d3a-b-rd8fhn"
_COLLIDE_LOGICAL = "b-rd8fhn-notes"      # A 声明它就会指到 B 的表


def test_site_table_name_refuses_a_logical_name_with_a_hyphen():
    """判据一：唯一定义处 fail-closed。"""
    import common
    import pytest
    with pytest.raises(common.InvalidTableName, match="连字符"):
        common.site_table_name(_COLLIDE_A, _COLLIDE_LOGICAL)


def test_site_table_name_refuses_malformed_logical_names():
    import common
    import pytest
    for bad in (None, "", 123, []):
        with pytest.raises(common.InvalidTableName):
            common.site_table_name(_COLLIDE_A, bad)
    for bad_site in (None, "", 123):
        with pytest.raises(common.InvalidTableName):
            common.site_table_name(bad_site, "notes")


def test_site_policy_cannot_be_made_to_point_at_another_site_table(monkeypatch):
    """判据三：`site_policy` 压根生成不出 B 的表 ARN。

    这条比"policy 里没有 B 的 ARN"强：它证明的是**造不出来**，而不是"这次恰好
    没造出来"。当年 merged review 要求的回归用例只覆盖 A 老实声明自己表名的场景。
    """
    import common
    import pytest
    monkeypatch.setenv("ACCOUNT_ID", "111122223333")
    with pytest.raises(common.InvalidTableName):
        common.site_policy(_COLLIDE_A, "dynamodb", tables=[_COLLIDE_LOGICAL])


def test_site_policy_still_grants_exact_arns_for_legal_names(monkeypatch):
    """判据四：**正对照**——合法 logical 名下仍是逐表精确 ARN、无通配。

    没有这一条，把 site_policy 改成"永远抛错"也能让上面几条绿；而"表名不再含
    连字符"更不能变成重新引入 `site-data-{id}-*` 通配的理由（那就是 M01 本身）。
    """
    import json

    import common
    monkeypatch.setenv("ACCOUNT_ID", "111122223333")
    pol = json.loads(common.site_policy("notes-01d147", "dynamodb",
                                        tables=["notes", "books"]))
    ddb_res = [r for st in pol["Statement"]
               for r in (st["Resource"] if isinstance(st["Resource"], list)
                         else [st["Resource"]])
               if ":table/" in r]
    assert len(ddb_res) == 2, f"应逐表枚举，得到 {ddb_res}"
    assert not any("*" in r for r in ddb_res), f"出现通配：{ddb_res}"
    assert {r.split(":table/")[-1] for r in ddb_res} == {
        "site-data-notes-01d147-notes", "site-data-notes-01d147-books"}


def test_runtime_guard_matches_the_contract_table_name_rule():
    """runtime 的拒绝条件必须与合同的 `TABLE_NAME_RE` 对齐——**两边都不许单独放宽**。

    `common.py` 刻意**不** import `contract.schema`：它被复制进 deployer / MCP /
    panel / key-proxy 四个产物，而只有 deployer 的 step Lambda 带 contract 包，为
    "唯一定义"引入 ImportError 会是一次与安全无关的部署回归。代价是两处判据可能
    漂移，所以由这条测试把它们绑起来（测试环境两个包都在）。

    只断言**安全性质**的那一半（含 `-` 必拒 / 合法名必过），不要求 runtime 复制完整
    字符集——完整校验是 validator 的职责。
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parents[3] / "site-builder/contract/src"))
    from contract.schema import TABLE_NAME_RE

    import common
    import pytest

    # 合同放行的名字，runtime 必须都能拼
    for good in ("notes", "my_notes", "n", "t0"):
        assert TABLE_NAME_RE.fullmatch(good), f"样例 {good!r} 选错了"
        assert common.site_table_name("s-abc123", good) == f"site-data-s-abc123-{good}"

    # 合同因**连字符**而拒的名字，runtime 也必须拒（这是单射所需的那一半）
    for bad in ("my-notes", _COLLIDE_LOGICAL, "-notes", "notes-"):
        assert TABLE_NAME_RE.fullmatch(bad) is None, f"样例 {bad!r} 选错了"
        with pytest.raises(common.InvalidTableName):
            common.site_table_name("s-abc123", bad)


# ── 归属核验（tag 从只写变成会回读）───────────────────────────────────────

def _mk_table(ddb, site_id, logical, *, tags=True, owner=None, pk="id"):
    import common
    name = common.site_table_name(site_id, logical)
    kw = dict(TableName=name,
              KeySchema=[{"AttributeName": pk, "KeyType": "HASH"}],
              AttributeDefinitions=[{"AttributeName": pk, "AttributeType": "S"}],
              BillingMode="PAY_PER_REQUEST")
    if tags:
        kw["Tags"] = [{"Key": "project", "Value": "site-builder"},
                      {"Key": "site_id", "Value": owner or site_id}]
    ddb.create_table(**kw)
    return name


def test_assert_table_owned_by_site_accepts_our_own_table(aws):
    import boto3
    import common
    ddb = boto3.client("dynamodb")
    _mk_table(ddb, "notes-01d147", "notes")
    arn = common.assert_table_owned_by_site(
        ddb, "notes-01d147", "notes",
        expect_key_schema=[{"AttributeName": "id", "KeyType": "HASH"}],
        expect_attribute_definitions=[{"AttributeName": "id",
                                       "AttributeType": "S"}])
    assert arn.endswith("table/site-data-notes-01d147-notes")


def test_assert_table_owned_by_site_rejects_a_foreign_site_tag(aws):
    """tag 说它属于别的站点 ⇒ 拒。这是碰撞被利用时的最后一道门。"""
    import boto3
    import common
    import pytest
    ddb = boto3.client("dynamodb")
    # 表名算作 A 的，但 tag 上写着 B —— 正是碰撞落地后的形态
    _mk_table(ddb, "aa-en3d3a", "notes", owner="somebody-else-x1")
    with pytest.raises(common.TableOwnershipUnconfirmed, match="另一个站点"):
        common.assert_table_owned_by_site(ddb, "aa-en3d3a", "notes",
                                          read_attempts=1)


def test_assert_table_owned_by_site_rejects_a_table_without_tags(aws):
    """没有 tag ⇒ 归属未确认 ⇒ 拒。**不许降级成"那就当它是我的"**。"""
    import boto3
    import common
    import pytest
    ddb = boto3.client("dynamodb")
    _mk_table(ddb, "notes-01d147", "notes", tags=False)
    with pytest.raises(common.TableOwnershipUnconfirmed, match="归属未确认"):
        common.assert_table_owned_by_site(ddb, "notes-01d147", "notes",
                                          read_attempts=1)


def test_assert_table_owned_by_site_rejects_our_own_table_with_a_different_schema(aws):
    """是本站的表、但 schema 与本次声明不符 ⇒ 也要拒。

    否则会被静默当成一次成功的幂等重试，而站点代码按新 schema 读写一张旧结构的表。
    """
    import boto3
    import common
    import pytest
    ddb = boto3.client("dynamodb")
    _mk_table(ddb, "notes-01d147", "notes", pk="id")
    with pytest.raises(common.TableOwnershipUnconfirmed, match="KeySchema"):
        common.assert_table_owned_by_site(
            ddb, "notes-01d147", "notes",
            expect_key_schema=[{"AttributeName": "note_id", "KeyType": "HASH"}])


def test_assert_table_owned_by_site_rejects_a_missing_table(aws):
    """默认（allow_absent=False）"表不存在"仍是失败——这是 provision 的语义：
    预检点看到过的表在 assert 时消失 = 并发删除，必须 fail-closed。"""
    import boto3
    import common
    import pytest
    ddb = boto3.client("dynamodb")
    with pytest.raises(common.TableOwnershipUnconfirmed, match="describe_table"):
        common.assert_table_owned_by_site(ddb, "notes-01d147", "nosuch")


def test_allow_absent_returns_none_for_a_missing_table(aws):
    """purge 的幂等重试靠它：表已删/从未建成 = 该表清理已完成 ⇒ 返回 None。"""
    import boto3
    import common
    ddb = boto3.client("dynamodb")
    assert common.assert_table_owned_by_site(
        ddb, "notes-01d147", "nosuch", read_attempts=1, allow_absent=True) is None


def test_allow_absent_only_covers_resource_not_found(aws):
    """describe 抛的**不是** NotFound（限流/权限）⇒ allow_absent 下仍 fail-closed。

    放宽这条，"跳过"就成了新的静默放行：一次可注入的读失败会让 purge 把
    "没能确认"当成"已经删完"，残留数据无人知晓。
    """
    import common
    import pytest

    class _Broken:
        class exceptions:
            ResourceNotFoundException = type("NF", (Exception,), {})

        def describe_table(self, **kw):
            raise RuntimeError("throttled")

    with pytest.raises(common.TableOwnershipUnconfirmed, match="describe_table"):
        common.assert_table_owned_by_site(_Broken(), "notes-01d147", "notes",
                                          read_attempts=1, allow_absent=True)


def test_allow_absent_does_not_relax_the_ownership_check_itself(aws):
    """表**存在**但 tag 属外站 ⇒ allow_absent=True 也必须拒。"""
    import boto3
    import common
    import pytest
    ddb = boto3.client("dynamodb")
    _mk_table(ddb, "aa-en3d3a", "notes", owner="somebody-else-x1")
    with pytest.raises(common.TableOwnershipUnconfirmed, match="另一个站点"):
        common.assert_table_owned_by_site(ddb, "aa-en3d3a", "notes",
                                          read_attempts=1, allow_absent=True)


def test_table_tags_paginates(aws, monkeypatch):
    """`ListTagsOfResource` 带 NextToken，不分页会读到不完整的 tag 集合。

    不完整与"缺 site_id tag"在调用方那里是同一个结论 ⇒ 会把自家表误判成外站表。
    这里用一个分两页的假客户端锁住分页行为（moto 每页 10 条，真实 tag 只有 2 个，
    所以行为差异在真机上要等 tag 变多才暴露——那时就太晚了）。
    """
    import common

    class _Paged:
        def __init__(self):
            self.calls = []

        def list_tags_of_resource(self, **kw):
            self.calls.append(kw.get("NextToken"))
            if not kw.get("NextToken"):
                return {"Tags": [{"Key": "project", "Value": "site-builder"}],
                        "NextToken": "page2"}
            return {"Tags": [{"Key": "site_id", "Value": "notes-01d147"}]}

    fake = _Paged()
    tags = common.table_tags(fake, "arn:aws:dynamodb:us-east-1:1:table/x")
    assert tags == {"project": "site-builder", "site_id": "notes-01d147"}, \
        f"没把两页合起来：{tags}"
    assert fake.calls == [None, "page2"], f"分页调用序列不对：{fake.calls}"
