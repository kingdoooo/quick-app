"""权限矩阵真机闸门（`scripts/verify_permission_matrix.py`）的可单测部分。

那个脚本的主体只能在真实 AWS 上跑，但它的**下限常量**必须锁在单测里：
G（坏数据拒绝投影）/ H（审计落库）两节是 8f8b0c6 新加的，加完后实际检查项从
21 升到 26，而 `MIN_CHECKS` 若还停在 20，把 G/H 整段误删后旧的 21 项照样
`>= 20`——闸门重新报绿（Codex 复审 8f8b0c6 的 P3-1）。

脚本模块顶层无 AWS/config 副作用（read_cfg 只在 main/__main__ 里被调），
可以安全 import。
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT = (Path(__file__).parents[2] / "scripts"
           / "verify_permission_matrix.py")


def _gate():
    spec = importlib.util.spec_from_file_location("_vpm", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_vpm"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_min_checks_floor_covers_the_audit_sections():
    """下限必须把 G/H 两节算进去：低于 26 就锁不住"审计段被整段删掉仍全绿"。"""
    assert _gate().MIN_CHECKS >= 26, \
        "MIN_CHECKS 低于当前实际检查项数（26）——G/H 段被删掉时闸门不会红"
