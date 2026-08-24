"""site.json（部署清单）结构校验——部署合同的机器可执行定义。"""
import re

TIERS = {"static", "fullstack-nosql", "fullstack-sql"}
RUNTIMES = {"nodejs22.x"}  # Python 3.13 记为二期（需 db.py 模板/fixture/E2E 支撑）
TIER_ENGINE = {"static": "none", "fullstack-nosql": "dynamodb", "fullstack-sql": "dsql"}
# 合同侧只管字符集。站点名还有一条**保留前缀**规则（平台自己的 Lambda 也叫
# site-*，见 M7-SPEC §2.1），它由入口的 `common.validate_site_name` 单点拦下——
# 不在这里复制一份：规则抄成两处就迟早对不上。
NAME_RE = re.compile(r"[a-z][a-z0-9-]{1,29}")
# **表名与属性名的字符集刻意不同，不要再合成一条。**
#
# 表名会成为物理资源名的一段：`site-data-{site_id}-{表名}`
# （`common.site_table_name`，那里是该格式的唯一定义）。而 site_id 自身可含 `-`，
# 所以只要表名也允许 `-`，两个**不同**站点就能拼出同一个物理表名——站点 A
# （id `aa-en3d3a`）声明表名 `b-rd8fhn-notes`，与站点 B（id `aa-en3d3a-b-rd8fhn`）
# 声明表名 `notes` 得到同一张表，于是 A 的 per-site IAM 精确 ARN 就是 B 的数据表。
#
# 禁掉表名里的 `-` 是**构造性**消除，不是缓解：若 `A + "-" + la == B + "-" + lb`
# 且 A≠B，不妨 |A|<|B|，则该串在下标 |A| 与 |B| 处都是 `-`，而 |B| ≥ |A|+1 意味着
# 下标 |B| 落在 `la` 内部 ⇒ `la` 必含 `-`。所以表名无 `-` ⇒ 碰撞不可能
# （证明只用到表名的字符集，与 site_id 的字符集无关）。
#
# 表名还会变成 Lambda 环境变量名 `TABLE_<NAME>`（`provision_dynamodb`），而 Lambda
# 的键不接受 `-`——从前那种表名会一路走到部署后段才失败。
#
# 属性名（pk）**不参与**任何资源名，DynamoDB 本身也接受 `-`，所以不跟着收紧：
# 那属于与本条安全性质无关的合同收窄。
TABLE_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,29}")
ATTRIBUTE_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,29}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []

    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        errors.append("name: 必须为小写字母开头、仅含 [a-z0-9-]、长度 2-30"
                      "（另有保留前缀，由部署入口校验）")

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
                # **两个字段各出一条信息**：合成一条时，一个误伤 pk 的回归会与"表名
                # 不合法"长得一模一样，用例也分辨不出来（原来就是合成的）。
                bad = []
                if not isinstance(tname, str) or not TABLE_NAME_RE.fullmatch(tname):
                    bad.append(
                        f"表名须匹配 {TABLE_NAME_RE.pattern}"
                        "——**不得含连字符 `-`**（表名会成为物理表名与环境变量名"
                        " TABLE_<NAME> 的一段），请改用下划线 `_`")
                if not isinstance(tpk, str) or not ATTRIBUTE_NAME_RE.fullmatch(tpk):
                    bad.append(f"主键属性名须匹配 {ATTRIBUTE_NAME_RE.pattern}"
                               "（属性名允许 `-`）")
                if bad:
                    errors.append(f"database.tables: {'；'.join(bad)}: {t}")
                else:
                    names.append(tname)
            if len(names) != len(set(names)):
                errors.append("database.tables: 表名不得重复")

    if tier == "fullstack-sql" and db.get("tables"):
        errors.append("database.tables: dsql 引擎不使用 tables（schema 写在 backend/schema.sql）")

    # auth 段只在首次部署时被 register_route 落进 sites 表作为初始值；
    # 之后访问策略的真源是 sites 表（控制台/MCP 在线修改，见二期 spec §3）。
    # 这里仍做完整校验——首次部署要靠它把住格式。
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
