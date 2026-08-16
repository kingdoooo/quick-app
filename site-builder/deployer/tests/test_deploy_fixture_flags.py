"""`scripts/deploy_fixture.py` 的 `--site-id` / `--marker`（M7 spec §5 的前置）。

这五件事**不需要 AWS 就能证**，而不证的话它们只会在一次二十分钟的真机 E2E 里以
另一种形态失败——"marker 没进去"读起来和"新代码没上线"一模一样，而后者正是那
几条 E2E 要判的东西：

  · marker 真的落进后端 `/api/health` 的响应对象，且改完的 JS 仍然合法（用 `node`
    真解析那个字面量，不是文本匹配自己的正则）；
  · 注入只在临时副本上做，**仓库里的 fixture 一个字节都不变**；
  · marker 路径换了打包的源目录，`run.sh` 最容易在这里被丢掉（它取自原 fixture 的
    父目录，不在副本里）；
  · `--site-id` 给了就逐字用、不给就随机；CLI 的两个开关真的接到 `main` 上；
  · 建 job 时仍然写 `upload_etag`（F1 之后缺它一律 fail-closed，漏写 = E2E 全红）。
"""
import configparser
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))

import deploy_fixture as df        # noqa: E402

FIXTURES = Path(__file__).parents[2] / "fixtures"
NOSQL = FIXTURES / "nosql-notes"
STATIC = FIXTURES / "static-hello"


# ---- 假 AWS / 假 config：让这些用例在干净 clone（无 config.ini）里也能跑 ----
#
# config.ini 是 gitignored 的，读真的那份会让整个文件在干净树里报错而不是通过
# （F4 修过同型问题）。这里的账号号是占位符。
def _fake_cfg() -> configparser.ConfigParser:
    c = configparser.ConfigParser()
    c.read_dict({
        "Platform": {"account_id": "000000000000"},
        "Deployer": {
            "sites_table": "site-sites", "jobs_table": "site-deploy-jobs",
            "state_machine_arn":
                "arn:aws:states:us-east-1:000000000000:stateMachine:site-deploy"}})
    return c


class _FakeAWS:
    """`deploy_fixture` 用到的四个 boto3 入口，按名字分开好断言各自收到了什么。"""

    def __init__(self, etag: str = '"etag-abc"', status: str = "SUCCEEDED"):
        self.s3 = MagicMock()
        self.s3.put_object.return_value = {"ETag": etag}
        self.table = MagicMock()
        # 第一次轮询就是终态：否则 main 会 sleep(10) 死循环
        self.table.get_item.return_value = {"Item": {"status": status,
                                                     "phase": "done"}}
        self.ddb = MagicMock()
        self.ddb.Table.return_value = self.table
        self.sfn = MagicMock()
        self.boto3 = MagicMock()
        self.boto3.client.side_effect = lambda name, **kw: {
            "s3": self.s3, "stepfunctions": self.sfn}[name]
        self.boto3.resource.side_effect = lambda name, **kw: self.ddb

    # ---- 断言用的取值口 ----
    def zip_bytes(self) -> bytes:
        return self.s3.put_object.call_args.kwargs["Body"]

    def job_item(self) -> dict:
        return self.table.put_item.call_args.kwargs["Item"]

    def sites_key(self) -> dict:
        return self.table.update_item.call_args.kwargs["Key"]

    def sfn_input(self) -> dict:
        return json.loads(self.sfn.start_execution.call_args.kwargs["input"])


@pytest.fixture
def aws(monkeypatch):
    fake = _FakeAWS()
    monkeypatch.setattr(df, "boto3", fake.boto3)
    monkeypatch.setattr(df, "_CFG", _fake_cfg())
    return fake


def _run(fixture_dir, **kw):
    """跑一次 main，吃掉它的终态 sys.exit（成功是 0）。"""
    with pytest.raises(SystemExit) as e:
        df.main(str(fixture_dir), **kw)
    assert e.value.code == 0, f"main 以 {e.value.code} 退出"


def _copy_fixture(dest: Path, src: Path = NOSQL) -> Path:
    """把 fixture 复制到 dest 下（连 `run.sh` 一起——它在 fixture 的**父目录**）。"""
    tree = dest / src.name
    shutil.copytree(src, tree)
    shutil.copy2(FIXTURES / "run.sh", dest / "run.sh")
    return tree


def _health_line(text: str) -> str:
    """后端里带 `/api/health` 的那一行。

    **不用 deploy_fixture 自己的正则**定位——那样断言的期望值就与被测代码同源了。
    """
    lines = [ln for ln in text.splitlines() if "/api/health" in ln]
    assert len(lines) == 1, f"期望恰好一行 /api/health，得到 {lines}"
    return lines[0]


def _res_json_arg(line: str) -> str:
    """`res.json(` 到配对 `)` 之间的实参文本（括号配平，允许嵌套调用）。"""
    start = line.index("res.json(") + len("res.json(") - 1
    depth = 0
    for i in range(start, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[start + 1:i]
    raise AssertionError(f"括号不配平: {line}")


def _tree_digest(root: Path) -> dict:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------- marker

def test_marker_lands_in_the_health_response_object(tmp_path):
    """marker 必须出现在 `/api/health` 的响应实参里，而不是文件的随便某处。

    写进注释、写进另一个路由、或者只是追加在文件末尾，都能让"文件里有这个串"成立
    ——而 E2E 断言的是**HTTP 响应体**里有它。所以这里只看那一行的 `res.json(` 实参。
    """
    tree = _copy_fixture(tmp_path)
    df.inject_marker(tree, "m7-probe-a1b2")
    arg = _res_json_arg(_health_line((tree / "backend/server.js").read_text()))
    assert "m7-probe-a1b2" in arg, f"marker 不在 /api/health 的响应实参里: {arg}"


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 来真解析 JS 字面量")
def test_patched_health_literal_really_parses_as_the_expected_object(tmp_path):
    """让 **node** 求值那个对象字面量：语法合法、marker 是它的一个字段值、
    原有字段没被吃掉。

    这条是本文件里唯一"真运行被改过的代码"的证据。纯文本断言无法区分
    `{ "sb_marker": "x", ok: true }`（对的）与 `{ "sb_marker": "x" ok: true }`
    （少个逗号，语法错，站点起不来）——两者都包含 marker 子串。
    """
    tree = _copy_fixture(tmp_path)
    df.inject_marker(tree, "m7-probe-c3d4")
    arg = _res_json_arg(_health_line((tree / "backend/server.js").read_text()))
    out = subprocess.run(
        ["node", "-e", f"process.stdout.write(JSON.stringify({arg}))"],
        capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, f"注入后的字面量 node 解析不了：{out.stderr}"
    obj = json.loads(out.stdout)
    assert obj[df.MARKER_FIELD] == "m7-probe-c3d4", obj
    assert obj["ok"] is True, f"注入把原有字段挤掉了: {obj}"


# ---- 用 stub 过的 express 真跑一遍被改过的 /api/health 处理函数 ----
#
# 比上面两条都强：它执行的是**注入之后的那个文件**，拿到的是那个路由真正交给
# `res.json` 的对象。文本断言分不出"marker 落在 /api/health 上"与"marker 落在同一行
# 的注释里 / 落在另一个路由上"；这里分得出。
_EXPRESS_STUB = """\
module.exports = function express() {
  const routes = {};
  const app = {
    get: (p, h) => { routes[p] = h; },
    post: () => {}, put: () => {}, delete: () => {}, patch: () => {},
    use: () => {}, listen: () => {}, __routes: routes,
  };
  global.__app = app;
  return app;
};
module.exports.json = () => (req, res, next) => { if (next) next(); };
module.exports.urlencoded = module.exports.json;
module.exports.static = () => (req, res, next) => { if (next) next(); };
"""
_AWS_SDK_STUB = """\
const noop = new Proxy(function () {}, {
  get: () => noop, apply: () => noop, construct: () => noop,
});
module.exports = new Proxy({}, { get: () => noop });
"""
_DRIVER = """\
require(process.argv[2]);
const app = global.__app;
if (!app) { console.error("server.js 没有创建 express app"); process.exit(2); }
const h = app.__routes["/api/health"];
if (!h) {
  console.error("没有注册 /api/health 路由；已注册: " +
                Object.keys(app.__routes).join(","));
  process.exit(3);
}
const res = {
  json: (o) => process.stdout.write(JSON.stringify(o)),
  status: (c) => ({ json: (o) => process.stdout.write(
      JSON.stringify(Object.assign({ __status: c }, o))), end: () => {} }),
};
h({ headers: {}, body: {}, params: {}, query: {} }, res);
"""


def _stub_node_modules(tree: Path) -> None:
    """给 backend/ 装上假的 express 与 @aws-sdk（node 从 require 者所在目录往上找）。"""
    mods = tree / "backend/node_modules"
    (mods / "express").mkdir(parents=True)
    (mods / "express/index.js").write_text(_EXPRESS_STUB)
    for pkg in ("@aws-sdk/client-dynamodb", "@aws-sdk/lib-dynamodb"):
        d = mods / pkg
        d.mkdir(parents=True)
        (d / "index.js").write_text(_AWS_SDK_STUB)
        (d / "package.json").write_text('{"main": "index.js"}')


def _run_health_route(tree: Path) -> dict:
    """真跑 backend/server.js 的 `/api/health` 处理函数，返回它交给 res 的对象。"""
    _stub_node_modules(tree)
    driver = tree / "backend/_probe.js"
    driver.write_text(_DRIVER)
    out = subprocess.run(["node", str(driver), str(tree / "backend/server.js")],
                         capture_output=True, text=True, timeout=30,
                         cwd=str(tree / "backend"))
    assert out.returncode == 0, f"跑 /api/health 失败：{out.stderr}"
    return json.loads(out.stdout)


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 真跑被改过的后端")
def test_running_the_patched_health_route_returns_the_marker(tmp_path):
    """注入后：`/api/health` 真正返回的对象里有 marker，`ok` 还在，状态码没被改。"""
    tree = _copy_fixture(tmp_path)
    df.inject_marker(tree, "m7-probe-run1")
    body = _run_health_route(tree)
    assert body.get(df.MARKER_FIELD) == "m7-probe-run1", body
    assert body.get("ok") is True, f"注入改变了原有响应: {body}"
    assert "__status" not in body, f"注入把响应改成了非 200: {body}"


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 真跑未改过的后端")
def test_unpatched_health_route_has_no_marker_field(tmp_path):
    """对照组：不注入时同一条路由**没有**这个字段。

    没有这条的话，上面那条在"fixture 本来就带 marker 字段"时也绿——断言的期望值
    就变成了从被测产物反推。
    """
    body = _run_health_route(_copy_fixture(tmp_path))
    assert df.MARKER_FIELD not in body, body
    assert body.get("ok") is True, body


def test_marker_injection_fails_loudly_when_there_is_no_backend(tmp_path):
    """反向注入①：static fixture 根本没有后端 ⇒ 必须抛，不能静默成功。

    静默的话 E2E 的 marker 断言会去验一个不存在的东西，而部署照样绿。
    """
    tree = tmp_path / "static-hello"
    shutil.copytree(STATIC, tree)
    with pytest.raises(SystemExit) as e:
        df.inject_marker(tree, "m7-probe")
    # **判据必须是这一分支独有的片段**：两条 fail-closed 的消息里都含 "backend" 与
    # "/api/health"（实测），按它们断言的话去掉目录检查这条也照样绿——异常类型相同
    # 时分支身份才是断言的真正内容。
    assert "没有 backend/ 目录" in str(e.value), e.value


def test_marker_injection_fails_loudly_when_health_route_is_missing(tmp_path):
    """反向注入②：有后端、但 `/api/health` 那条路由被拿掉 ⇒ 必须抛。

    与①是两根不同的自由度（"没有 backend 目录"和"有目录但找不到注入点"），
    只测其中一根的话另一根可以静默回落。
    """
    tree = _copy_fixture(tmp_path)
    server = tree / "backend/server.js"
    text = server.read_text()
    server.write_text("\n".join(ln for ln in text.splitlines()
                                if "/api/health" not in ln))
    with pytest.raises(SystemExit) as e:
        df.inject_marker(tree, "m7-probe")
    assert "里找不到" in str(e.value), e.value       # 这一分支独有（见上一条注释）


def test_marker_rejects_values_that_would_break_the_js_literal(tmp_path):
    """marker 被写进一个 JS 字符串字面量 ⇒ 带引号/换行的值必须先被拒。

    放过去的后果不是"注入攻击"（值由跑测试的人给），而是**站点起不来**，
    然后一次真机 E2E 里表现为莫名的 BackendUnhealthy。
    """
    tree = _copy_fixture(tmp_path)
    for bad in ('a"; process.exit(1);//', "a'b", "a\nb", "a b", ""):
        with pytest.raises(SystemExit):
            df.inject_marker(tree, bad)


def test_marker_build_leaves_the_repo_fixture_byte_identical(tmp_path, aws):
    """注入只在临时副本上做：跑完仓库里的 fixtures/ 逐文件哈希不变。

    直接改仓库 fixture 的话，第一条 E2E 会"通过"，而 git 工作树被污染、
    后面每一次部署都带着上一次的 marker。
    """
    before = _tree_digest(FIXTURES)
    _run(NOSQL, marker="m7-probe-e5f6")
    assert _tree_digest(FIXTURES) == before, "仓库 fixture 被改动了"
    # 同时确认这次 build 真的注入了（否则上面那条在"什么都没做"时也绿）
    with zipfile.ZipFile(io.BytesIO(aws.zip_bytes())) as z:
        assert "m7-probe-e5f6" in z.read("backend/server.js").decode()


def test_marker_build_still_ships_run_sh(tmp_path, aws):
    """marker 路径换了打包的源目录，而 `run.sh` 取自**原 fixture 的父目录**。

    丢掉它的症状是 Lambda 的 Handler `run.sh` 不存在——真机上表现为
    BackendUnhealthy，离这里的根因隔了整条流水线。
    """
    _run(NOSQL, marker="m7-probe-0011")
    with zipfile.ZipFile(io.BytesIO(aws.zip_bytes())) as z:
        names = set(z.namelist())
    assert "run.sh" in names, f"zip 里没有 run.sh: {sorted(names)}"
    assert "site.json" in names and "backend/server.js" in names, sorted(names)


def test_build_without_marker_ships_the_fixture_verbatim(aws):
    """不给 marker 时，zip 里的后端与仓库文件**逐字节相同**（行为逐字不变）。"""
    _run(NOSQL)
    with zipfile.ZipFile(io.BytesIO(aws.zip_bytes())) as z:
        assert z.read("backend/server.js") == (NOSQL / "backend/server.js").read_bytes()
        assert df.MARKER_FIELD not in z.read("backend/server.js").decode()


def test_non_static_fixture_without_run_sh_fails_instead_of_shipping_a_broken_zip(
        tmp_path, aws):
    """`run.sh` 缺失 ⇒ 立刻报错。

    原来的代码是 `if run_sh.exists()` 静默跳过，打出一个没有 Handler 的 zip：
    部署会走完 validate、CodeBuild、建函数，最后在健康门以
    "BackendUnhealthy" 失败——根因离症状隔了整条流水线。
    """
    tree = tmp_path / "nosql-notes"
    shutil.copytree(NOSQL, tree)          # 故意不复制 run.sh
    with pytest.raises(SystemExit) as e:
        df.main(str(tree))
    assert "run.sh" in str(e.value), e.value


# ---------------------------------------------------------------- site-id

def test_site_id_is_used_verbatim_everywhere_it_is_written(aws):
    """`--site-id` 必须同时进 sites 表的 Key、job 记录和状态机输入。

    只进一处的后果是两表/状态机不一致——`register_route` 会因为 sites 行不存在
    直接拒绝写路由（那条错误文案说的是"站点不存在"，排查会往完全别的方向去）。
    """
    _run(NOSQL, site_id="notes-zzz999")
    assert aws.sites_key() == {"site_id": "notes-zzz999"}
    assert aws.job_item()["site_id"] == "notes-zzz999"
    assert aws.sfn_input()["site_id"] == "notes-zzz999"


def test_site_id_defaults_to_a_fresh_random_id(monkeypatch):
    """不给 `--site-id` 时行为逐字不变：按 site.json 的 name + 随机后缀，每次不同。

    期望的形状取自 fixture 的 `name` 与既有约定（name + 6 位十六进制），
    不从 deploy_fixture 的代码反推。
    """
    seen = []
    for _ in range(2):
        fake = _FakeAWS()
        monkeypatch.setattr(df, "boto3", fake.boto3)
        monkeypatch.setattr(df, "_CFG", _fake_cfg())
        _run(NOSQL)
        seen.append(fake.sfn_input()["site_id"])
    assert all(re.fullmatch(r"notes-[0-9a-f]{6}", s) for s in seen), seen
    assert seen[0] != seen[1], f"两次生成了同一个 site_id: {seen}"


def test_cli_wires_both_new_flags_into_main():
    """CLI 层单独一条：`main` 支持这两个参数、而 argparse 没接上，是最容易漏的缝。

    E2E 是按 `--site-id` / `--marker` 这两个**命令行**开关调它的。
    """
    with patch.object(df, "main") as m:
        df.cli(["/tmp/fx", "--site-id", "notes-abc123", "--marker", "m7-b",
                "--owner", "someone@example.com"])
    assert m.call_args.kwargs["site_id"] == "notes-abc123"
    assert m.call_args.kwargs["marker"] == "m7-b"
    # 既有开关不许被改坏
    assert "someone@example.com" in m.call_args.args + tuple(
        m.call_args.kwargs.values())


def test_cli_defaults_keep_both_flags_absent():
    with patch.object(df, "main") as m:
        df.cli(["/tmp/fx"])
    assert m.call_args.kwargs["site_id"] is None
    assert m.call_args.kwargs["marker"] is None


# ------------------------------------------- E2E 那几个 fixture 变体的离线证据
#
# `tests/test_e2e_fixtures.py` 里的 M7 用例要在 tmpdir 里造两个**故意坏的**后端。
# 它们如果在 `validate` 阶段就被合同拦下，真机上的表现是"部署失败了但原因不对"——
# 而那几条用例断言的正是失败原因（BackendUnhealthy / SmokeFailure）。等一次二十分钟
# 的真机跑来发现这件事太贵，所以在这里离线证：
#   ① 变体的 site.json + 代码都过合同（会走到健康门，不会被提前拦）；
#   ② 冒烟毒药后端的 UA 分流真的成立（那是 spec §5.5 唯一的注入手段）；
#   ③ 那个 UA 与平台健康门实际发的 UA 逐字相同（跨文件耦合，漂了就静默失效）。
#
# 这里 import 一个测试模块是有意的：那两段后端源码的归属地是 E2E 文件，抄第二份
# 就会各自漂移。**在函数体内 import**，让它坏掉时表现为用例失败而不是收集错误。

def _contract_errors(tree: Path) -> list:
    sys.path.insert(0, str(Path(__file__).parents[3] / "site-builder/contract/src"))
    from contract.redlines import scan_redlines
    from contract.schema import validate_manifest
    manifest = json.loads((tree / "site.json").read_text())
    return validate_manifest(manifest) + scan_redlines(tree, manifest)


def test_e2e_bad_boot_backend_passes_the_contract(tmp_path):
    """坏后端必须**过**合同校验：它要坏在运行时（健康门），不是坏在 validate。

    被合同拦下的话 job 的 error 里是红线文案，`assert BackendUnhealthy` 当场红——
    但那要等一次真机部署才知道。
    """
    import test_e2e_fixtures as e2e
    tree = e2e._variant(tmp_path / "bad", server_js=e2e._BAD_BOOT_SERVER)
    assert _contract_errors(tree) == [], "坏后端被合同拦下了，走不到健康门"
    assert (tmp_path / "bad/run.sh").is_file(), \
        "_variant 没把 run.sh 放到 fixture 的父目录——deploy_fixture 会当场拒绝"


def test_e2e_smoke_poison_backend_passes_the_contract_and_flips_to_public(tmp_path):
    """冒烟毒药后端过合同，且 require_login 真的被翻成 false。

    没翻成 false 的话冒烟判据是"302 到登录端点"，请求根本到不了站点代码 ⇒
    无论后端多坏冒烟都会通过 ⇒ 那条用例的 `_deploy_expected_to_fail` 直接红。
    """
    import test_e2e_fixtures as e2e
    tree = e2e._variant(tmp_path / "poison", server_js=e2e._SMOKE_POISON_SERVER,
                        require_login=False)
    assert _contract_errors(tree) == []
    assert json.loads((tree / "site.json").read_text())["auth"]["require_login"] \
        is False


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node 真跑毒药后端")
def test_e2e_smoke_poison_backend_passes_the_gate_but_fails_public(tmp_path):
    """毒药后端的 UA 分流：健康门的 UA 拿到 200，其它 UA 拿到 500。

    这是 spec §5.5 全部机制所在——"提交点之后才失败"没有别的注入手段。分流不成立
    时两条路会一起 200（部署成功，用例红）或一起 500（健康门就挂了，失败原因不是
    SmokeFailure，用例也红），所以它至少不会静默假绿；但那两种都要真机才看得见。
    """
    import test_e2e_fixtures as e2e
    tree = e2e._variant(tmp_path / "poison", server_js=e2e._SMOKE_POISON_SERVER)
    _stub_node_modules(tree)
    (tree / "backend/_probe.js").write_text(_DRIVER_WITH_UA)
    got = {}
    for label, ua in (("gate", "site-builder-deploy-healthcheck"),
                      ("public", "Mozilla/5.0"), ("empty", "")):
        out = subprocess.run(
            ["node", str(tree / "backend/_probe.js"),
             str(tree / "backend/server.js"), ua],
            capture_output=True, text=True, timeout=30,
            cwd=str(tree / "backend"))
        assert out.returncode == 0, f"{label}: {out.stderr}"
        got[label] = json.loads(out.stdout)
    assert got["gate"] == {"ok": True, "gate": "passed"}, got["gate"]
    assert got["public"].get("__status") == 500, got["public"]
    assert got["empty"].get("__status") == 500, got["empty"]


def test_e2e_poison_user_agent_matches_the_real_health_gate(monkeypatch):
    """毒药后端认的那个 UA 必须与 `deploy_lambda_site._health_event()` 发的**逐字**相同。

    这是一处跨文件耦合：平台改了健康门的 UA，毒药后端就会连健康门都过不去，spec §5.5
    那条用例的失败原因变成 BackendUnhealthy。它仍会红（不是假绿），但要等真机——
    所以在这里把两边钉在一起。
    """
    import test_e2e_fixtures as e2e
    monkeypatch.setenv("BASE_DOMAIN", "example.com")
    import deploy_lambda_site
    real_ua = deploy_lambda_site._health_event()["headers"]["user-agent"]
    assert f'"{real_ua}"' in e2e._SMOKE_POISON_SERVER, (
        f"健康门实际发的 UA 是 {real_ua!r}，毒药后端里没有这个字面量——"
        "spec §5.5 的注入手段已经失效")


# 与 _DRIVER 的差别只有一个：UA 从命令行取，用来验毒药后端的分流。
_DRIVER_WITH_UA = """\
require(process.argv[2]);
const app = global.__app;
const h = app && app.__routes["/api/health"];
if (!h) { console.error("没有注册 /api/health 路由"); process.exit(3); }
const res = {
  json: (o) => process.stdout.write(JSON.stringify(o)),
  status: (c) => ({ json: (o) => process.stdout.write(
      JSON.stringify(Object.assign({ __status: c }, o))), end: () => {} }),
};
h({ headers: { "user-agent": process.argv[3] }, body: {}, params: {}, query: {} },
  res);
"""


# ---------------------------------------------------------------- F1 约束

def test_job_record_pins_the_upload_etag_from_the_same_put(aws):
    """建 job 时必须写 `upload_etag`，且取的是**这一次 put_object 的返回**。

    F1 之后 validate 缺这个属性一律 fail-closed ⇒ 漏写的话这个脚本建的每个 job
    都在第一步失败，E2E 全红。`tests/test_validate.py` 有一条 AST 静态守卫按
    "类"锁这件事；这里是同一条约束的**行为**版本：静态守卫只能证"源码里写了这个
    字符串"，证不了它写进了 job 记录、也证不了写的是哪个 ETag。
    """
    _run(NOSQL)
    assert aws.job_item()["upload_etag"] == aws.s3.put_object.return_value["ETag"]
    assert aws.job_item()["upload_bytes"] == len(aws.zip_bytes())
