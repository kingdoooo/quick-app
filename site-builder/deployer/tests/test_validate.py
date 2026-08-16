import io
import json
import warnings
import zipfile

import boto3
import pytest


def _upload_site_zip(job_id: str, manifest: dict, files: dict):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("site.json", json.dumps(manifest))
        for path, content in files.items():
            z.writestr(path, content)
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{job_id}.zip", Body=buf.getvalue())


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
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=buf.getvalue())
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
    boto3.client("s3").put_object(Bucket="site-artifacts-1",
                                  Key=f"uploads/{jid}.zip", Body=buf.getvalue())
    with pytest.raises(validate.ContractViolation) as ei:
        validate.handler({"job_id": jid, "site_id": "order-x1"}, None)
    assert "文件数" in str(ei.value)
    assert "重名" not in str(ei.value)
