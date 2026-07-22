import boto3


EVENT = {"job_id": "job-1", "site_id": "notes-a1b2c3",
         "manifest": {"name": "notes", "tier": "fullstack-nosql",
                      "database": {"engine": "dynamodb",
                                   "tables": [{"name": "notes", "pk": "id"}]},
                      "backend": {"runtime": "nodejs22.x",
                                  "entrypoint": "node server.js", "port": 8080},
                      "auth": {"require_login": True, "allowed_users": "org"}}}


def test_creates_table_and_env(aws):
    import provision_dynamodb, common
    common.create_job("a@x.com", "notes-a1b2c3")
    out = provision_dynamodb.handler(dict(EVENT), None)
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"
    desc = boto3.client("dynamodb").describe_table(
        TableName="site-data-notes-a1b2c3-notes")
    assert desc["Table"]["KeySchema"][0]["AttributeName"] == "id"


def test_idempotent_rerun(aws):
    import provision_dynamodb
    provision_dynamodb.handler(dict(EVENT), None)
    out = provision_dynamodb.handler(dict(EVENT), None)  # 不抛 ResourceInUse
    assert out["env_vars"]["TABLE_NOTES"] == "site-data-notes-a1b2c3-notes"
