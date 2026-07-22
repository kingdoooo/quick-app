"""site.json（部署清单）结构校验——部署合同的机器可执行定义。"""
import re

TIERS = {"static", "fullstack-nosql", "fullstack-sql"}
RUNTIMES = {"nodejs22.x"}  # Python 3.13 记为二期（需 db.py 模板/fixture/E2E 支撑）
TIER_ENGINE = {"static": "none", "fullstack-nosql": "dynamodb", "fullstack-sql": "dsql"}
NAME_RE = re.compile(r"[a-z][a-z0-9-]{1,29}")
TABLE_RE = re.compile(r"[a-z][a-z0-9_-]{0,29}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []

    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        errors.append("name: 必须为小写字母开头、仅含 [a-z0-9-]、长度 2-30")

    tier = manifest.get("tier")
    if tier not in TIERS:
        errors.append(f"tier: 必须是 {sorted(TIERS)} 之一")
        return errors  # tier 非法时后续规则无意义

    db = manifest.get("database")
    if db is None:
        db = {}
    elif not isinstance(db, dict):
        errors.append(f"database: 必须为对象，得到 {db!r}")
        db = {}
    engine = db.get("engine")
    if engine != TIER_ENGINE[tier]:
        errors.append(f"database.engine: tier={tier} 时必须为 {TIER_ENGINE[tier]!r}，得到 {engine!r}")

    backend = manifest.get("backend")
    if tier == "static":
        if backend is not None:
            errors.append("backend: tier=static 时不允许出现")
    else:
        if not isinstance(backend, dict):
            errors.append("backend: fullstack tier 必须提供")
        else:
            if backend.get("runtime") not in RUNTIMES:
                errors.append(f"backend.runtime: 必须是 {sorted(RUNTIMES)} 之一")
            if not isinstance(backend.get("entrypoint"), str) or not backend.get("entrypoint"):
                errors.append("backend.entrypoint: 必须为非空字符串")
            if backend.get("port") != 8080:
                errors.append("backend.port: 必须为 8080（LWA 约定）")

    if tier == "fullstack-nosql":
        tables = db.get("tables") or []
        if not isinstance(tables, list):
            errors.append(f"database.tables: 必须为数组，得到 {tables!r}")
        elif not tables:
            errors.append("database.tables: dynamodb 引擎必须声明至少一张表")
        elif len(tables) > 10:
            errors.append("database.tables: 至多 10 张表")
        else:
            names = []
            for t in tables:
                if not isinstance(t, dict):
                    errors.append(f"database.tables: 每项必须为对象: {t!r}")
                    continue
                tname, tpk = t.get("name"), t.get("pk")
                if (not isinstance(tname, str) or not TABLE_RE.fullmatch(tname)
                        or not isinstance(tpk, str) or not TABLE_RE.fullmatch(tpk)):
                    errors.append(f"database.tables: 表名/主键须匹配 {TABLE_RE.pattern}: {t}")
                else:
                    names.append(tname)
            if len(names) != len(set(names)):
                errors.append("database.tables: 表名不得重复")

    if tier == "fullstack-sql" and db.get("tables"):
        errors.append("database.tables: dsql 引擎不使用 tables（schema 写在 backend/schema.sql）")

    auth = manifest.get("auth")
    if not isinstance(auth, dict) or not isinstance(auth.get("require_login"), bool):
        errors.append("auth.require_login: 必须为布尔值")
    else:
        au = auth.get("allowed_users")
        if au != "org":
            if not isinstance(au, list) or not au or not all(
                isinstance(e, str) and EMAIL_RE.fullmatch(e) for e in au
            ):
                errors.append('auth.allowed_users: 必须为 "org" 或非空邮箱数组')

    return errors
