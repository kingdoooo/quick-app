from unittest.mock import MagicMock, patch
import pytest


EVENT = {"job_id": "job-1", "site_id": "s-1",
         "manifest": {"backend": {"runtime": "nodejs22.x"}}, "env_vars": {}}


def _cb_mock(statuses):
    cb = MagicMock()
    cb.start_build.return_value = {"build": {"id": "site-package:abc"}}
    cb.batch_get_builds.side_effect = [
        {"builds": [{"buildStatus": s, "logs": {"deepLink": "http://log"}}]}
        for s in statuses]
    return cb


def test_success_returns_zip_key(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    with patch.object(package_backend, "_codebuild", return_value=_cb_mock(
            ["IN_PROGRESS", "SUCCEEDED"])), \
         patch.object(package_backend.time, "sleep"):
        out = package_backend.handler(dict(EVENT), None)
    assert out["backend_zip_key"] == "artifacts/job-1/backend.zip"


def test_failure_raises(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    with patch.object(package_backend, "_codebuild", return_value=_cb_mock(
            ["FAILED"])), \
         patch.object(package_backend.time, "sleep"):
        with pytest.raises(package_backend.PackageError):
            package_backend.handler(dict(EVENT), None)


def test_start_build_env_overrides(aws):
    import package_backend, common
    common.create_job("a@x.com", "s-1")
    cb = _cb_mock(["SUCCEEDED"])
    with patch.object(package_backend, "_codebuild", return_value=cb), \
         patch.object(package_backend.time, "sleep"):
        package_backend.handler(dict(EVENT), None)
    env = {e["name"]: e["value"]
           for e in cb.start_build.call_args.kwargs["environmentVariablesOverride"]}
    assert env == {"JOB_ID": "job-1", "ARTIFACTS_BUCKET": "site-artifacts-1"}
