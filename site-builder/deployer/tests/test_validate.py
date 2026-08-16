import io
import json
import warnings
import zipfile

import boto3
import pytest


def _pin(job_id: str, etag: str, length: int):
    """模拟 confirm_upload：把 HEAD 到的 ETag 钉进 job 记录。

    真实流程里 validate 之前必然经过 confirm_upload，助手如实建出那个状态才对
    ——`pin=False` 就是"模拟老 MCP / 绕过 confirm"。
    """
    boto3.client("dynamodb").update_item(
        TableName="site-deploy-jobs", Key={"job_id": {"S": job_id}},
        UpdateExpression="SET upload_etag = :e, upload_bytes = :n",
        ExpressionAttributeValues={":e": {"S": etag}, ":n": {"N": str(length)}})


def _upload_site_zip(job_id: str, manifest: dict, files: dict,
                     *, pin: bool = True) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("site.json", json.dumps(manifest))
        for path, content in files.items():
            z.writestr(path, content)
    body = buf.getvalue()
    r = boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                      Key=f"uploads/{job_id}.zip", Body=body)
    if pin:
        _pin(job_id, r["ETag"], len(body))
    return r["ETag"]


def _s3_keys(prefix: str) -> list[str]:
    return sorted(o["Key"] for o in boto3.client("s3").list_objects_v2(
        Bucket="site-artifacts-1", Prefix=prefix).get("Contents", []))


GOOD_MANIFEST = {"name": "hello", "tier": "static",
                 "database": {"engine": "none"},
                 "auth": {"require_login": False, "allowed_users": "org"}}

# 需要"打包结果非空"的用例都用它：static 树没有 run.sh/backend/，打出来是空包
# 而空包根本不写对象，于是"validated/ 下没有对象"在 static 上恒成立——拿 static
# 去断言"失败不写工件"会与那条跳过逻辑同谋成恒真。
FULLSTACK_MANIFEST = {"name": "fullstack", "tier": "fullstack-nosql",
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "t", "pk": "id"}]},
                      "backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node app.js", "port": 8080},
                      "auth": {"require_login": False, "allowed_users": "org"}}
GOOD_BACKEND = {"run.sh": "#!/bin/sh\nnode app.js\n",
                "backend/app.js": "// GET /api/health\nok()"}


def test_valid_static_site_passes(aws):
    import validate, common
    jid = common.create_job("a@x.com", "hello-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"})
    out = validate.handler({"job_id": jid, "site_id": "hello-x1"}, None)
    assert out["manifest"]["tier"] == "static"
    # 解包结果已回写
    keys = [o["Key"] for o in boto3.client("s3").list_objects_v2(
        Bucket="site-artifacts-1", Prefix=f"extracted/{jid}/")["Contents"]]
    assert f"extracted/{jid}/frontend/index.html" in keys


def test_bad_manifest_raises(aws):
    import validate, common
    jid = common.create_job("a@x.com", "bad-x1")
    _upload_site_zip(jid, {"name": "bad!", "tier": "nope"}, {})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "bad-x1"}, None)
    assert "tier" in str(ei.value)


def test_redline_violation_raises(aws):
    import validate, common
    jid = common.create_job("a@x.com", "red-x1")
    _upload_site_zip(jid, GOOD_MANIFEST,
                     {"frontend/index.html": "<script>fetch('http://localhost:8080/api/x')</script>"})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "red-x1"}, None)
    assert "localhost" in str(ei.value)


def test_zip_bomb_rejected(aws):
    import validate, common
    jid = common.create_job("a@x.com", "bomb-x1")
    # 高压缩比：4MB 全零 → zip 后 ~4KB，比率 >100:1
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/big.js": "\0" * (4 * 1024 * 1024)})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "bomb-x1"}, None)
    assert "压缩比" in str(ei.value)


def test_too_many_files_rejected(aws):
    import validate, common
    jid = common.create_job("a@x.com", "many-x1")
    files = {f"frontend/f{i}.txt": "x" for i in range(2001)}
    _upload_site_zip(jid, GOOD_MANIFEST, files)
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "many-x1"}, None)
    assert "文件数" in str(ei.value)


def test_duplicate_zip_entries_rejected(aws):
    """重名 ⇒ zipfile（扫描方）与 unzip（构建方）对它的处置不必然一致。"""
    import validate, common
    jid = common.create_job("a@x.com", "dup-x1")
    buf = io.BytesIO()
    # 重名正是本例要造的畸形，zipfile 自己那句 Duplicate name 警告是噪声——
    # 让它冒到套件输出里，等于用一条恒响的警告把别的警告淹掉。
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("site.json", json.dumps(GOOD_MANIFEST))
            z.writestr("frontend/index.html", "<h1>good</h1>")
            z.writestr("frontend/index.html", "<h1>evil</h1>")
    # 手工造包也要走 confirm_upload 那一步，否则先撞上"缺 upload_etag"那条守卫，
    # 测的就不是重名了（本文件里 _upload_site_zip 帮不上忙的两处之一）。
    body = buf.getvalue()
    r = boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                      Key=f"uploads/{jid}.zip", Body=body)
    _pin(jid, r["ETag"], len(body))
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "dup-x1"}, None)
    assert "重名" in str(ei.value)


def test_codebuild_input_is_immune_to_upload_swap(aws):
    """预签名 PUT 有效期内可重复使用并覆盖同 key。校验通过后把 uploads/ 换成
    违规内容，CodeBuild 读的那个 key 必须仍是被校验过的字节。"""
    import io, zipfile, boto3, validate, common
    s3 = boto3.client("s3")
    jid = common.create_job("a@x.com", "swap-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST,
                     {**GOOD_BACKEND, "frontend/index.html": "<h1>hi</h1>"})
    validate.handler({"job_id": jid, "site_id": "swap-x1"}, None)
    key = validate.validated_key(jid)
    before = s3.get_object(Bucket="site-artifacts-1", Key=key)["Body"].read()

    # 换包之后**必须真的再跑一次 handler**：只在换包前后各读一次，两次之间没有任何
    # 写入者，`after == before` 恒成立——那样这条断言在任何实现下都不会红。让失败的
    # 那一次运行真的发生，它才咬得住"校验失败不许动已有工件"。
    _upload_site_zip(jid, FULLSTACK_MANIFEST,
                     {**GOOD_BACKEND,
                      "backend/app.js": "res.cookie('s', x)  // GET /api/health"})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "swap-x1"}, None)
    # 换上去的那份确实**是**红线违规（res.cookie ⇒ 站点自带 auth），不是随便一个错：
    # 否则"第二次跑失败了"可能只是因为包坏了，证不到本例想证的东西。
    assert "auth 逻辑" in str(ei.value)

    after = s3.get_object(Bucket="site-artifacts-1", Key=key)["Body"].read()
    assert after == before, "校验失败的那次运行覆盖了已有的 validated/ 工件"
    with zipfile.ZipFile(io.BytesIO(after)) as z:
        assert "res.cookie" not in z.read("backend/app.js").decode()
        assert sorted(z.namelist()) == ["backend/app.js", "run.sh"]  # 前端不进构建容器


def test_successful_run_reads_the_upload_exactly_once(aws, monkeypatch):
    """打包只能来自已解包并扫描过的那棵树。哪天改回"在 put 时重新 get 一遍上传
    key"（P1-1 最可能的复发形态），get_object 就会变成两次——按次数锁死。"""
    import boto3, validate, common
    jid = common.create_job("a@x.com", "once-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST, GOOD_BACKEND)
    reads, real_client = [], boto3.client

    class _Spy:
        """只拦 get_object 记 key，其余一律透传给真客户端。"""

        def __init__(self, inner):
            self._inner = inner

        def get_object(self, **kw):
            reads.append(kw["Key"])
            return self._inner.get_object(**kw)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def _client(svc, *a, **kw):
        c = real_client(svc, *a, **kw)
        return _Spy(c) if svc == "s3" else c   # common 走 boto3.resource，不受影响

    monkeypatch.setattr(validate.boto3, "client", _client)
    validate.handler({"job_id": jid, "site_id": "once-x1"}, None)
    assert reads == [f"uploads/{jid}.zip"]


def test_validation_failure_writes_no_build_artifact(aws):
    """工件必须在**全部**校验通过之后才写：把 put_object 提到 scan_redlines 之前，
    整个套件仍会绿（既有违规用例只断 raises，不看 validated/）——本例补上那一刀。

    用 fullstack 树是必需的：static 打出来是空包、本就不写对象，拿它断言"失败不写"
    会与那条跳过逻辑同谋成恒真。"""
    import botocore.exceptions, boto3, validate, common
    jid = common.create_job("a@x.com", "nowrite-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST, {
        **GOOD_BACKEND,
        "frontend/index.html": "<script>fetch('http://localhost:8080/api/x')</script>"})
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "nowrite-x1"}, None)
    assert "localhost" in str(ei.value)
    with pytest.raises(botocore.exceptions.ClientError) as err:
        boto3.client("s3").get_object(Bucket="site-artifacts-1",
                                      Key=validate.validated_key(jid))
    assert err.value.response["Error"]["Code"] == "NoSuchKey"


def test_static_site_writes_no_build_artifact(aws):
    """static 没有 run.sh/backend/ ⇒ 没有构建输入，不该产出工件。

    空 zip 也是**合法** zip（22 字节 EOCD），照写会让"validated/ 下有对象"不再
    等价于"有东西要构建"，上面那条失败用例也就失去信号。"""
    import botocore.exceptions, boto3, validate, common
    jid = common.create_job("a@x.com", "staticnb-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"})
    validate.handler({"job_id": jid, "site_id": "staticnb-x1"}, None)
    with pytest.raises(botocore.exceptions.ClientError) as err:
        boto3.client("s3").get_object(Bucket="site-artifacts-1",
                                      Key=validate.validated_key(jid))
    assert err.value.response["Error"]["Code"] == "NoSuchKey"


def test_build_artifact_streams_from_disk_instead_of_memory(aws, monkeypatch):
    """重新打包出来的工件必须**落到 /tmp 再流式上传**，不许整份常驻内存。

    A2 引入这份重新打包时它是 `io.BytesIO`：峰值内存于是同时有下载下来的上传包
    **与**这个 zip 两份全尺寸副本（M7 之前只有前者），而 validate 的 memory_size
    是 512MB。磁盘那侧已经由 CDK 断言按解包上界定过尺寸
    （`VALIDATE_EPHEMERAL_MB`），所以正确的落点是磁盘而不是内存。

    断言的是**机制**不是"内存用了多少"：后者在单测里量不出来，而机制退化
    （`Body=` 又变回 bytes / BytesIO）恰好就是复发形态。`.name` 指向一个当场
    存在的真文件，是"落盘"与"BytesIO 冒充流"的分水岭。
    """
    import boto3, validate, common
    from pathlib import Path
    jid = common.create_job("a@x.com", "stream-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST, GOOD_BACKEND)
    key = validate.validated_key(jid)
    seen, real_client = {}, boto3.client

    class _Spy:
        """只在写工件那一次记下 Body 的形态，其余一律透传。"""

        def __init__(self, inner):
            self._inner = inner

        def put_object(self, **kw):
            if kw.get("Key") == key:
                body = kw["Body"]
                name = getattr(body, "name", None)
                seen.update(type_=type(body), readable=hasattr(body, "read"),
                            name=name,
                            on_disk=bool(name) and Path(name).is_file())
            return self._inner.put_object(**kw)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def _client(svc, *a, **kw):
        c = real_client(svc, *a, **kw)
        return _Spy(c) if svc == "s3" else c

    monkeypatch.setattr(validate.boto3, "client", _client)
    validate.handler({"job_id": jid, "site_id": "stream-x1"}, None)

    assert seen, f"没有任何一次 put_object 写到 {key}——本条空转"
    assert not issubclass(seen["type_"], (bytes, bytearray, io.BytesIO)), (
        f"工件是整份内存副本（Body={seen['type_'].__name__}）——要的是落盘后的文件流")
    assert seen["readable"], seen
    assert seen["on_disk"], (
        f"Body 不是磁盘上的文件（name={seen['name']!r}）——BytesIO 也有 read()，"
        "只有 .name 指向真文件才证明这份 zip 没在内存里")
    # 落盘之后内容仍要对：流式上传最容易的错法是传了个没 seek 回 0 的句柄 ⇒ 空对象
    got = boto3.client("s3").get_object(Bucket="site-artifacts-1", Key=key)["Body"].read()
    with zipfile.ZipFile(io.BytesIO(got)) as z:
        assert sorted(z.namelist()) == ["backend/app.js", "run.sh"], z.namelist()


def test_buildspec_and_iam_name_the_validated_prefix_only():
    """三处命名同一前缀（validate.py / buildspec / CDK IAM），按真源核对。

    buildspec 那侧比**整个 key**而不只是前缀：只比前缀会让对象名
    （backend-src.zip）两侧脱钩——改掉它，两边单测照绿，而真机每次构建都死在
    第一条 `aws s3 cp` 上（404）。IAM 那侧仍按前缀比，因为它授的就是前缀。
    纯文本核对，不碰 AWS，所以不取 moto 夹具。"""
    from pathlib import Path
    import validate
    root = Path(__file__).parent.parent
    spec = (root / "buildspec-package.yml").read_text()
    assert validate.validated_key("$JOB_ID") in spec and "uploads/$JOB_ID" not in spec
    app = (root / "infra" / "app.py").read_text()
    assert f"/{validate.VALIDATED_PREFIX}/*" in app and "/uploads/*" not in app


def test_extraction_path_collision_rejected(aws):
    """`./a` 与 `a//b` 在 namelist 里各自独立，extractall 却把它们折叠成同一个
    落盘路径、只保留最后一份字节——按原名去重看不见这种撞车。"""
    import validate, common
    jid = common.create_job("a@x.com", "coll-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"backend/app.js": "FIRST",
                                          "./backend/app.js": "SECOND",
                                          "backend//app.js": "THIRD"})
    raw = boto3.client("s3").get_object(
        Bucket="site-artifacts-1", Key=f"uploads/{jid}.zip")["Body"].read()
    names = zipfile.ZipFile(io.BytesIO(raw)).namelist()
    assert len(names) == len(set(names)), "前提：不能有精确重名，否则测的是上一条守卫"

    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "coll-x1"}, None)
    assert "重名" in str(ei.value)


def test_entry_cap_precedes_dup_check(aws):
    """条目数上限必须留在重名检查**之上**：重名检查里的 count() 是 O(n²)，
    没有上限先兜住就是个 CPU 放大面。既超量又重名 ⇒ 必须报「文件数」。"""
    import validate, common
    jid = common.create_job("a@x.com", "order-x1")
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("site.json", json.dumps(GOOD_MANIFEST))
            for i in range(validate.MAX_ZIP_ENTRIES):
                z.writestr(f"frontend/f{i}.txt", "x")
            z.writestr("frontend/f0.txt", "dup")  # 精确重名，且总数已超上限
    body = buf.getvalue()
    r = boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                      Key=f"uploads/{jid}.zip", Body=body)
    _pin(jid, r["ETag"], len(body))
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "order-x1"}, None)
    assert "文件数" in str(ei.value)
    assert "重名" not in str(ei.value)


def test_upload_is_pinned_to_the_bytes_confirm_upload_checked(aws):
    """同一个 job 的上传 key 在不同时刻可以是不同字节：SFN 对每个 LambdaInvoke 都有
    MaxAttempts:6 的 service-exception 重试（实测合成模板），而预签名 PUT URL 还活
    900s。两次 attempt 读到不同包时，发布出去的前端是两棵树的并集、被删掉的 migration
    仍会执行、manifest 与代码可能来自不同 attempt——三者都不是"字节没校验"，而是
    "这个组合没被一起校验过"。钉住 confirm 当时那份字节后，重试要么同字节要么 412。"""
    import validate, common
    jid = common.create_job("a@x.com", "pin-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST, GOOD_BACKEND)          # attempt 1，已钉
    _upload_site_zip(jid, FULLSTACK_MANIFEST,                        # owner 用仍有效的
                     {**GOOD_BACKEND, "backend/app.js": "// GET /api/health\nok2()"},
                     pin=False)                                      # 预签名 URL 覆盖
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "pin-x1"}, None)
    assert "确认" in str(ei.value) and "重新上传" in str(ei.value)
    assert _s3_keys(f"validated/{jid}/") == []      # 也不许留下构建工件


def test_missing_upload_etag_fails_closed(aws):
    """缺 etag 一律拒，**不做"那就不钉了直接读"的兜底**——那等于把这条守卫做成可选的
    （本仓库记过的"假值兜底"形态）。代价是一条部署顺序约束：MCP 必须先于 deployer 栈
    部署，否则窗口内旧 MCP 建的 job 全在第一步失败（已进 ledger Ruling 30 与 C1）。"""
    import validate, common
    jid = common.create_job("a@x.com", "noetag-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"},
                     pin=False)
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "noetag-x1"}, None)
    assert "upload_etag" in str(ei.value)


def test_oversized_upload_rejected_before_reading_the_body(aws, monkeypatch):
    """confirm 的 50MB 只对 HEAD 当时那个对象成立（HEAD→GET TOCTOU）。**Body.read 一被
    调用就炸**，所以这条锁的是"顺序"，不只是"有个检查"——把大小检查写在 read 之后
    同样能让"太大就拒"的断言变绿，而内存已经炸了。"""
    import validate, common
    jid = common.create_job("a@x.com", "huge-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"})

    class _Boom:
        def read(self, *a, **k):
            raise AssertionError("不许在大小检查之前读 Body")

    orig = boto3.client
    real_s3 = orig("s3")

    class _FakeS3:
        exceptions = real_s3.exceptions

        def get_object(self, **kw):
            return {"ContentLength": 5 * 1024 ** 3, "Body": _Boom()}

        def __getattr__(self, n):
            return getattr(real_s3, n)

    monkeypatch.setattr(validate.boto3, "client",
                        lambda name, *a, **kw: _FakeS3() if name == "s3"
                        else orig(name, *a, **kw))
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "huge-x1"}, None)
    assert "上限" in str(ei.value)


def test_retry_with_the_pinned_bytes_still_succeeds(aws):
    """钉住字节**不许**把合法重试变成失败：service-exception 重试是对真实瞬时故障有用
    的机制，本项不砍它（Ruling 29）。同一份字节重跑必须仍然成功、结果一致、
    extracted/ 集合不变（= 没有陈旧并集）。"""
    import validate, common
    jid = common.create_job("a@x.com", "retry-x1")
    _upload_site_zip(jid, FULLSTACK_MANIFEST, GOOD_BACKEND)
    first = validate.handler({"job_id": jid, "site_id": "retry-x1"}, None)
    before = _s3_keys(f"extracted/{jid}/")
    second = validate.handler({"job_id": jid, "site_id": "retry-x1"}, None)
    assert second == first
    assert _s3_keys(f"extracted/{jid}/") == before


def test_upload_cap_matches_the_50mb_check_at_the_mcp_entrance(aws):
    """期望值**从 MCP 的源码 AST 里取**，不抄字面量：两处不一致时，MCP 放宽而这边没跟
    的症状是"合法上传在部署第一步被拒"，反向则是这条硬上限失去意义。"""
    import ast
    from pathlib import Path
    import validate
    src = (Path(__file__).parents[2] / "mcp" / "server.py").read_text(encoding="utf-8")
    found = [n.value for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == "MAX_ZIP_BYTES"]
    assert found, "mcp/server.py 里找不到 MAX_ZIP_BYTES 的赋值——本条已空转"
    expected = eval(compile(ast.Expression(found[0]), "<mcp>", "eval"))
    assert validate.MAX_UPLOAD_BYTES == expected


def test_validate_reads_the_job_record_with_a_consistent_read(aws, monkeypatch):
    """`upload_etag` 是 confirm_upload 几百毫秒前刚写的，这里必须**强一致**读。

    最终一致读读到旧副本时不会自愈：`ContractViolation` 是**函数错误**，而 SFN 对本
    步骤的 Retry 只列了四条 Lambda **服务**异常（实测合成模板的 `ErrorEquals`）⇒ 不
    重试，直接走 `States.ALL` 的 catch 到 MarkFailed。于是部署硬失败，且报的是"请重新
    调用 confirm_upload"——而此刻 job 已是 RUNNING，用户根本没法再 confirm。

    断言的是**传给 common.get_job 的参数**：moto 的读恒为强一致，"读到了正确的值"
    在最终一致实现下同样会绿（本条真正要防的那个 bug 在单测里没有可观测的后果）。
    """
    import validate, common
    jid = common.create_job("a@x.com", "cons-x1")
    _upload_site_zip(jid, GOOD_MANIFEST, {"frontend/index.html": "<h1>hi</h1>"})
    calls, real = [], common.get_job

    def _spy(job_id, **kw):
        calls.append((job_id, kw))
        return real(job_id, **kw)

    monkeypatch.setattr(validate.common, "get_job", _spy)
    validate.handler({"job_id": jid, "site_id": "cons-x1"}, None)
    assert calls, "validate 没有读 job 记录——本条已空转"
    assert all(kw.get("consistent") is True for _, kw in calls), (
        f"validate 用最终一致读取 upload_etag：{calls}")


def test_scripts_that_bypass_mcp_to_create_jobs_pin_the_upload_etag():
    """绕过 MCP 自己建 job 并起状态机的脚本，必须自己补上 confirm_upload 那一步。

    **这条守卫的全部价值在于把一个只有真机才暴露的断路提前到单测。**
    `scripts/deploy_fixture.py` 完全绕过 MCP（自己 put_object 到 uploads/、自己
    put_item 建 job、自己 start_execution），而 validate 现在缺 `upload_etag` 就
    fail-closed ⇒ 它建的每个 job 都会在第一步失败。它断的是本计划的主闸门：
    `tests/test_e2e_fixtures.py` 用 subprocess 调它，而那是 P1-1/P1-2 唯一的真机证据。
    真机跑一次要 6 分钟且需要 AWS 凭证——所以这条必须是静态的、免费的。

    按**类**锁而不是只钉 deploy_fixture.py 一个文件名：判据是"既往 uploads/ 写东西、
    又起状态机"，将来任何新的 bypass 脚本都会被这条自动罩住。`deploy_fixture.py`
    本身写成硬性下界，防的是判据哪天失效后集合悄悄变空、这条断言恒真
    （本仓库记过的"空集合上 all() 恒真"形态）。

    两侧的松紧**故意不对称**：
      · **选谁来查**用纯文本，宁可多选——多选一个脚本只是多要求它写 etag（安全方向），
        漏选才是致命的；
      · **判它写了没有**必须走 AST 的字符串字面量。这条是实测教训不是洁癖：我第一版
        用文本搜 `upload_etag`，而我给 deploy_fixture.py 补的**注释里就有这个词**
        ⇒ 删掉真正那行赋值之后守卫照样绿（注释自己满足了自己的断言，与上一个提交
        修掉的 A7 同型）。注释不在 AST 里，docstring 显式剔除。
    """
    import ast
    from pathlib import Path

    def _code_strings(src: str) -> list[str]:
        """源码里**代码位置**的字符串字面量：注释天然不进 AST，docstring 剔掉。"""
        tree = ast.parse(src)
        docs = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)) and body:
                first = body[0]
                if (isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    docs.add(id(first.value))
        return [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in docs]

    scripts = sorted((Path(__file__).parents[2] / "scripts").rglob("*.py"))
    assert scripts, "找不到 site-builder/scripts/——本条已空转"
    sources = {p: p.read_text(encoding="utf-8") for p in scripts}
    bypass = {p: s for p, s in sources.items()
              if "uploads/" in s and "start_execution" in s}
    assert "deploy_fixture.py" in {p.name for p in bypass}, (
        "判据没能选出 deploy_fixture.py——它是已知的 bypass 脚本，选不中说明这条"
        f"守卫已经空转（当前选中：{sorted(p.name for p in bypass)}）")
    missing = sorted(p.name for p, s in bypass.items()
                     if not any("upload_etag" in lit for lit in _code_strings(s)))
    assert not missing, (
        f"{missing} 绕过 MCP 建 job 但没写 upload_etag——它建的每个 job 都会在 "
        "validate 第一步以「任务记录里没有 upload_etag」失败（E2E 闸门全红）")
