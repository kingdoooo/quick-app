#!/usr/bin/env python3
"""合同 scanner 的真实项目风格验收 + **线上 validate Lambda 是否真的加载了新版**。

两件事，缺一不可：

① 用真实项目风格的代码验 scanner（不只是合成片段）。
   x-user-name 那条红线已经进过一轮"修漏报 → 引入误报 → 再修"的循环，所以
   正反两侧都要覆盖：合规写法**一个都不能误拦**（误报会挡住真实用户的部署、
   并逼人绕过规则），已知绕过一个都不能放过。

② 确认**部署出去的那份**真的是这份代码。
   scanner 跑在 site-deployer-validate 里，contract 包是 CDK bundling 时
   `pip install` 进去的。本地源码修好、CDK 没重部署时：git 显示已修，线上仍是
   旧 scanner。本地 pytest 对这种情况零保护——这正是本脚本存在的理由。
   实测过：写完修复时线上 validate 的 LastModified 还停在五个提交之前。

用法：
    ./verify_contract_fixtures.py             # ①+②
    ./verify_contract_fixtures.py --local     # 只跑 ①（无 AWS 凭证时）
"""
import argparse
import configparser
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "site-builder/contract/src"))
CFG_PATH = HERE.parent / "config.ini"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


# ---- 真实项目风格：合规，必须放行 ----
# 每条都取自真实 Node/TS 后端里会自然写出的形态。误报的代价是拦住合规站点，
# 所以这一组比违规组更重要。
COMPLIANT = {
    "Express + prettier 折行": """
const express = require('express');
const app = express();
app.get('/api/me', (req, res) => {
  const rawUserName =
    req.headers['x-user-name'] || '';
  res.json({ email: req.headers['x-user-email'],
             name: decodeURIComponent(rawUserName) });
});
""",
    "解构取头": """
app.post('/api/notes', async (req, res) => {
  const { 'x-user-email': email, 'x-user-name': rawName } = req.headers;
  const name = decodeURIComponent(rawName || '');
  await db.put({ email, name, body: req.body.text });
  res.json({ ok: true });
});
""",
    "helper 工具函数封装": """
const decodeHeader = (v) => decodeURIComponent(v || '');
function currentUser(req) {
  return { email: req.headers['x-user-email'],
           name: decodeHeader(req.headers['x-user-name']) };
}
module.exports = { currentUser };
""",
    "TypeScript 断言 + 可选链": """
interface User { email: string; name: string }
export function whoami(req: Request): User {
  const raw = req.headers['x-user-name'] as string | undefined;
  return { email: String(req.headers['x-user-email'] ?? ''),
           name: decodeURIComponent(raw ?? '') };
}
""",
    "存进 req 属性供中间件下游用": """
app.use((req, res, next) => {
  req.userEmail = req.headers['x-user-email'];
  req.userName = req.headers['x-user-name'];
  next();
});
app.get('/api/x', (req, res) => {
  res.json({ name: decodeURIComponent(req.userName) });
});
""",
    "实参里带正则替换": """
const name = decodeURIComponent(
  req.headers['x-user-name'].replace(/https?:\\/\\//g, ''));
""",
    "前端 fetch 后解码": """
fetch('/api/me').then(r => r.json()).then(d => {
  const raw = d.headers['x-user-name'];
  document.getElementById('who').textContent = decodeURIComponent(raw);
});
""",
    "req.get() 取头": """
const raw = req.get('x-user-name');
const name = decodeURIComponent(raw || '');
""",
}

# ---- 已知绕过与真违规：必须拦下 ----
VIOLATING = {
    "解码的是无关值": """
const raw = req.headers['x-user-name'];
const q = decodeURIComponent(req.query.q);
db.put({ name: raw, q });
""",
    "只在注释里解码": """
const raw = req.headers['x-user-name'];
// 记得 decodeURIComponent(req.headers['x-user-name'])
db.put({ name: raw });
""",
    "JSDoc 里的示例解码": """
/**
 * @example decodeURIComponent(req.headers['x-user-name'])
 */
const raw = req.headers['x-user-name'];
db.put({ name: raw });
""",
    "字符串里的解码": """
const raw = req.headers['x-user-name'];
logger.info("下游需要 decodeURIComponent(req.headers['x-user-name'])");
db.put({ name: raw });
""",
    "多声明符锚错变量": """
const q = req.query.q, name = req.headers['x-user-name'];
res.json({ q: decodeURIComponent(q), name });
""",
    "完全没解码": """
const name = req.headers['x-user-name'] || '';
db.put({ name });
""",
    "拼接头名且未解码": """
const raw = req.headers['x-user-' + 'name'];
db.put({ name: raw });
""",
}


def run_local() -> None:
    from contract.redlines import _check_user_name_decoded
    print("\n── ① 合规写法必须放行（误报会挡住真实用户）────────")
    for name, code in COMPLIANT.items():
        errs = _check_user_name_decoded(code, Path("api/index.js"))
        check(errs == [], f"放行：{name}",
              "" if errs == [] else "被误拦")
    print("\n── ② 绕过与违规必须拦下 ──────────────────────────")
    for name, code in VIOLATING.items():
        errs = _check_user_name_decoded(code, Path("api/index.js"))
        check(bool(errs), f"拦下：{name}", "" if errs else "被放过")


def read_cfg(section: str, key: str) -> str:
    c = configparser.ConfigParser(interpolation=None)
    c.read(CFG_PATH)
    return c[section][key].split("#")[0].split(";")[0].strip()


def run_deployed() -> None:
    """核对线上 validate Lambda 里的 contract 包与本地一致。"""
    import boto3
    from botocore.config import Config
    import urllib.request
    import io
    import zipfile

    region = read_cfg("Platform", "region")
    fn = "site-deployer-validate"
    lam = boto3.client("lambda", region_name=region,
                       config=Config(retries={"max_attempts": 5,
                                              "mode": "adaptive"}))
    print("\n── ③ 线上 validate Lambda 是否加载了这份 scanner ────")
    meta = lam.get_function(FunctionName=fn)
    cfgm = meta["Configuration"]
    print(f"  {fn}  LastModified={cfgm['LastModified']}")
    with urllib.request.urlopen(meta["Code"]["Location"], timeout=120) as r:
        blob = r.read()
    zf = zipfile.ZipFile(io.BytesIO(blob))
    names = [n for n in zf.namelist() if n.endswith("contract/redlines.py")]
    if not names:
        check(False, "部署包里找不到 contract/redlines.py",
              "打包方式变了？先核对 CDK bundling")
        return
    deployed = zf.read(names[0]).decode()
    local = (ROOT / "site-builder/contract/src/contract/redlines.py").read_text()
    d_sha = hashlib.sha256(deployed.encode()).hexdigest()[:12]
    l_sha = hashlib.sha256(local.encode()).hexdigest()[:12]
    check(d_sha == l_sha,
          "线上 redlines.py == 本地 redlines.py",
          f"线上 {d_sha} / 本地 {l_sha}"
          + ("" if d_sha == l_sha
             else " —— **线上仍是旧 scanner**，需重新部署 SiteDeployerStack"))
    # 即便 sha 不同也给出具体差异，便于判断"差的是不是本轮修复"
    if d_sha != l_sha:
        for marker, why in (
                ("_header_holder_names", "关联判定（解码必须对应这个头）"),
                ("_balanced_arg", "括号配平（支持嵌套调用）"),
                ("keep_header", "头名保留（注释里的假解码仍被抹）")):
            check(marker in deployed, f"线上含 {marker} —— {why}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true",
                    help="只跑本地 scanner 判定，不查线上 Lambda")
    args = ap.parse_args()
    run_local()
    if not args.local:
        run_deployed()
    return 0


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    except Exception:                       # noqa: BLE001
        import traceback
        traceback.print_exc()
        rc = 1
    finally:
        failed = sum(1 for ok, _, _ in results if not ok)
        # 下限：合规 8 + 违规 7 = 15 项本地判定，少于这个数说明中途挂了
        MIN_CHECKS = 15
        print()
        if len(results) < MIN_CHECKS:
            print(f"结果：只跑了 {len(results)} 项（预期 ≥{MIN_CHECKS}）—— "
                  "验收**未完成**，状态不可信")
            rc = 1
        else:
            print(f"结果：{len(results) - failed}/{len(results)} 项通过"
                  + (f"，{failed} 项未达预期" if failed else ""))
            rc = 1 if failed else 0
    sys.exit(rc)
