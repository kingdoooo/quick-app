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
