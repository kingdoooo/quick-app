import io
import json
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
    import io, json, warnings, zipfile, boto3, validate, common
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
    good = {"name": "swap", "tier": "fullstack-nosql",
            "database": {"engine": "dynamodb", "tables": [{"name": "t", "pk": "id"}]},
            "backend": {"runtime": "nodejs22.x", "entrypoint": "node app.js", "port": 8080},
            "auth": {"require_login": False, "allowed_users": "org"}}
    _upload_site_zip(jid, good, {"run.sh": "#!/bin/sh\nnode app.js\n",
                                 "backend/app.js": "// GET /api/health\nok()",
                                 "frontend/index.html": "<h1>hi</h1>"})
    validate.handler({"job_id": jid, "site_id": "swap-x1"}, None)
    key = validate.validated_key(jid)
    before = s3.get_object(Bucket="site-artifacts-1", Key=key)["Body"].read()

    _upload_site_zip(jid, good, {"run.sh": "#!/bin/sh\nnode app.js\n",
                                 "backend/app.js": "res.cookie('s', x)  // GET /api/health"})
    after = s3.get_object(Bucket="site-artifacts-1", Key=key)["Body"].read()
    assert after == before, "validated/ 工件被上传覆盖影响了"
    with zipfile.ZipFile(io.BytesIO(after)) as z:
        assert "res.cookie" not in z.read("backend/app.js").decode()
        assert sorted(z.namelist()) == ["backend/app.js", "run.sh"]  # 前端不进构建容器


def test_buildspec_and_iam_name_the_validated_prefix_only(aws):
    """三处命名同一前缀（validate.py / buildspec / CDK IAM），按真源核对。"""
    from pathlib import Path
    import validate
    prefix = validate.VALIDATED_PREFIX
    root = Path(__file__).parent.parent
    spec = (root / "buildspec-package.yml").read_text()
    assert f"{prefix}/$JOB_ID/" in spec and "uploads/$JOB_ID" not in spec
    app = (root / "infra" / "app.py").read_text()
    assert f"/{prefix}/*" in app and "/uploads/*" not in app
