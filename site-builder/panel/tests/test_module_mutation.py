"""共享变形助手自己的守卫（3c-1B）。

`mutate_module_segment` 是两处变形测试的地基。它一旦静默失效（锚点没命中、改到了验签那一处、
或者段落切错），依赖它的变形测试就从"证明正向断言会红"退化成空转，而**空转是绿的**。
所以它的三条失败路径各要一条用例——这是"守卫的守卫"，与
`test_deploy_panel_contract.test_shipped_env_scan_is_not_vacuous` 同一个理由。
"""
import pytest

from module_mutation import mutate_module_segment

SRC = '''VALUE = "untouched"


def sign():
    return "target"


def verify():
    return "target"
'''


@pytest.fixture
def src_file(tmp_path):
    p = tmp_path / "subject.py"
    p.write_text(SRC)
    return p


def test_replaces_only_inside_the_region(src_file, tmp_path):
    """段外的同一个字面量必须**不动**——这正是"改到验签那一处"要防的形状。"""
    mod = mutate_module_segment(src_file, region=("def sign", "def verify"),
                                old='"target"', new='"mutated"',
                                tmp_path=tmp_path, module_name="_subject_mutant_ok")
    assert mod.sign() == "mutated"
    assert mod.verify() == "target", "段外也被替换了——切段没起作用"
    assert mod.VALUE == "untouched"
    assert src_file.read_text() == SRC, "改到了源文件上——必须只动临时副本"


def test_ambiguous_anchor_fails_loudly_instead_of_guessing(tmp_path):
    """段**内**出现两次：必须失败。静默改第一处会让变形测试测的是随机一处。"""
    dup = tmp_path / "dup.py"
    dup.write_text('def sign():\n    x = "target"\n    return "target" + x\n\n\ndef verify():\n    pass\n')
    with pytest.raises(AssertionError, match="恰好 1 次"):
        mutate_module_segment(dup, region=("def sign", "def verify"),
                              old='"target"', new='"mutated"',
                              tmp_path=tmp_path, module_name="_subject_mutant_dup")


def test_absent_anchor_fails_loudly(src_file, tmp_path):
    """锚点一次都没命中：同样必须失败（否则副本 == 原件，变形测试恒绿）。"""
    with pytest.raises(AssertionError, match="恰好 1 次"):
        mutate_module_segment(src_file, region=("def sign", "def verify"),
                              old='"no-such-literal"', new='"mutated"',
                              tmp_path=tmp_path, module_name="_subject_mutant_absent")


def test_reversed_region_fails_loudly(src_file, tmp_path):
    with pytest.raises(AssertionError, match="锚点顺序反了"):
        mutate_module_segment(src_file, region=("def verify", "def sign"),
                              old='"target"', new='"mutated"',
                              tmp_path=tmp_path, module_name="_subject_mutant_rev")


def test_missing_region_anchor_is_an_error_not_a_no_op(src_file, tmp_path):
    with pytest.raises(ValueError):      # str.index 的 substring not found
        mutate_module_segment(src_file, region=("def nope", "def verify"),
                              old='"target"', new='"mutated"',
                              tmp_path=tmp_path, module_name="_subject_mutant_noregion")
