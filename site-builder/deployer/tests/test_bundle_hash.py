"""deployer bundling 的 asset hash 必须覆盖**全部**进包输入（infra/bundle_hash.py）。

缺陷原形（2026-09-27 实测）：CDK 的默认 SOURCE hash 只看 `/asset-input`（functions/）与
bundling 选项的字符串，**挂载卷的内容不进 hash**。只改 contract/ 或锁定清单 ⇒ S3Key 不变 ⇒
`cdk diff` 零差异、`cdk deploy` 什么都不部——`rm -rf cdk.out` 也救不了（重打的包里是新字节，
但同名 key 已在 bootstrap 桶里，上传与更新都被跳过）。
"""
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "infra"))
import bundle_hash as bh  # noqa: E402


def _tree(root: Path) -> dict:
    (root / "functions").mkdir(parents=True)
    (root / "functions" / "validate.py").write_text("def handler(e, c): pass\n")
    (root / "contract").mkdir()
    (root / "contract" / "redlines.py").write_text("RULES = 1\n")
    (root / "locks").mkdir()
    (root / "locks" / "bundling-requirements.txt").write_text("sqlparse==0.6.0\n")
    return {
        "source": root / "functions",
        "bundling": {"image": "img:3.13", "platform": "linux/amd64",
                     "command": ["bash", "-c", "cp -r /asset-input/. /asset-output/"],
                     "volumes": [{"hostPath": str(root / "contract"), "containerPath": "/asset-contract"},
                                 {"hostPath": str(root / "locks"), "containerPath": "/asset-locks"}]},
        "reads": {"/asset-contract": [root / "contract"],
                  "/asset-locks": [root / "locks" / "bundling-requirements.txt"]},
    }


def _h(t: dict) -> str:
    return bh.bundle_asset_hash(t["source"], t["bundling"], reads=t["reads"])


def test_same_inputs_same_hash_even_at_a_different_absolute_path(tmp_path):
    """确定性：同样的内容换个 checkout 位置（另一台机器 / worktree）hash 不变。"""
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    assert _h(a) == _h(a) == _h(b)


@pytest.mark.parametrize("mutate", [
    lambda r, t: (r / "functions" / "validate.py").write_text("def handler(e, c): return 1\n"),
    lambda r, t: (r / "contract" / "redlines.py").write_text("RULES = 2\n"),       # 缺陷原形
    lambda r, t: (r / "locks" / "bundling-requirements.txt").write_text("sqlparse==0.6.1\n"),
    lambda r, t: (r / "contract" / "new_rule.py").write_text(""),
    lambda r, t: (r / "contract" / "redlines.py").rename(r / "contract" / "rules.py"),
    lambda r, t: t["bundling"]["command"].append("--extra"),
    lambda r, t: t["bundling"].update(platform="linux/arm64"),
    lambda r, t: t["bundling"].update(image="img:3.14"),
], ids=["source", "contract", "lockfile", "contract-new-file", "rename", "command",
        "platform", "image"])
def test_every_bundle_input_moves_the_hash(tmp_path, mutate):
    root = tmp_path / "r"
    t = _tree(root)
    before = _h(t)
    mutate(root, t)
    assert _h(t) != before


@pytest.mark.parametrize("junk", ["__pycache__/validate.cpython-312.pyc", "stale.pyc", ".DS_Store"])
def test_host_only_junk_does_not_move_the_hash(tmp_path, junk):
    """宿主机上跑测试留下的 pyc、Finder 的 .DS_Store 不能让同一份源码换 hash。"""
    root = tmp_path / "r"
    t = _tree(root)
    before = _h(t)
    for base in (root / "functions", root / "contract"):
        (base / junk).parent.mkdir(parents=True, exist_ok=True)
        (base / junk).write_bytes(b"\x00junk")
    assert _h(t) == before


def test_an_undeclared_mount_fails_synth(tmp_path):
    """新加一个挂载卷却没声明它读了什么 ⇒ 同一个洞会以另一个名字回来，所以直接拒。"""
    t = _tree(tmp_path / "r")
    del t["reads"]["/asset-locks"]
    with pytest.raises(ValueError, match="/asset-locks"):
        _h(t)


def test_a_declared_read_that_is_not_mounted_fails_synth(tmp_path):
    t = _tree(tmp_path / "r")
    t["reads"]["/asset-ghost"] = [tmp_path / "r" / "contract"]
    with pytest.raises(ValueError, match="/asset-ghost"):
        _h(t)


def test_a_declared_read_outside_its_mount_fails_synth(tmp_path):
    """声明的读取路径必须在对应挂载的 hostPath 之下——否则 hash 的是别的东西。"""
    t = _tree(tmp_path / "r")
    t["reads"]["/asset-locks"] = [tmp_path / "r" / "contract" / "redlines.py"]
    with pytest.raises(ValueError, match="/asset-locks"):
        _h(t)


def test_a_missing_input_fails_synth(tmp_path):
    t = _tree(tmp_path / "r")
    (tmp_path / "r" / "locks" / "bundling-requirements.txt").unlink()
    with pytest.raises(FileNotFoundError):
        _h(t)


def test_app_py_step_fn_uses_it():
    """接线：app.py 的 step_fn bundling 必须把这个 hash 传给 CDK（否则回到默认 SOURCE hash）。"""
    src = (Path(__file__).parents[1] / "infra" / "app.py").read_text()
    assert "asset_hash=bundle_asset_hash(" in src
    assert "from bundle_hash import bundle_asset_hash" in src
