import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relopin import honey  # noqa: E402
from relopin.seed import SplitMix64, derive_subseed  # noqa: E402


def test_smali_trap_method_string():
    code = honey.smali_trap_method("getFakeKey", "SECRET-123", "string")
    assert 'const-string v0, "SECRET-123"' in code
    assert "return-object v0" in code


def test_smali_trap_method_int_uses_return_type():
    """إصلاح الثغرة #10: return_type كان حقلاً مُتجاهَلاً تمامًا — الآن يُنتج توقيع/تعليمات مختلفة فعليًا."""
    code = honey.smali_trap_method("getFakeCode", "42", "int")
    assert "()I" in code
    assert "const v0, 0x2a" in code
    assert "return v0" in code
    assert "return-object" not in code


def test_smali_trap_method_unsupported_type_raises():
    with pytest.raises(ValueError):
        honey.smali_trap_method("x", "y", "float")


def test_load_honey_config_example():
    traps = honey.load_honey_config(Path(__file__).resolve().parent.parent / "honeytraps.example.json")
    assert len(traps) == 3
    assert all(t.fake_value for t in traps)


def test_derive_subseed_deterministic_and_distinct():
    a1 = derive_subseed(999, "naming")
    a2 = derive_subseed(999, "naming")
    b = derive_subseed(999, "honey")
    assert a1 == a2  # نفس المدخل => نفس المخرج دائمًا
    assert a1 != b  # تسميات مختلفة => قيم مستقلة


def test_splitmix64_reproducible_sequence():
    r1 = SplitMix64(42)
    r2 = SplitMix64(42)
    seq1 = [r1.next_u64() for _ in range(10)]
    seq2 = [r2.next_u64() for _ in range(10)]
    assert seq1 == seq2
